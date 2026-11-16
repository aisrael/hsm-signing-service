//! The command line interface and the code that runs each command.

use std::io::Read;
use std::io::Write;
use std::sync::Arc;

use base64::Engine;
use clap::Parser;
use clap::Subcommand;
use clap::crate_version;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::signal::unix::SignalKind;
#[cfg(unix)]
use tokio::signal::unix::signal;
use tokio::sync::oneshot;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::algorithm::Algorithm;
use crate::api;
use crate::api::BASE64;
use crate::app_state::AppState;
use crate::config::Config;
use crate::hsm_backend;
use crate::hsm_backend::HsmBackend;
use crate::metrics::Metrics;
use crate::telemetry;
use crate::telemetry::TelemetryGuard;

const CRATE_VERSION: &str = crate_version!();

/// Command line arguments
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The command to run. The default is `server`.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the HTTP signing service.
    Server,
    /// Encrypt STDIN with AES-GCM inside the HSM. Print the result to STDOUT
    /// as base64 of `iv || ciphertext || tag`.
    Encrypt {
        /// The label of the AES key in the token.
        #[arg(long)]
        key_id: String,
    },
    /// Decrypt the base64 output of `encrypt` (read from STDIN) inside the
    /// HSM. Write the plaintext bytes to STDOUT.
    Decrypt {
        /// The label of the AES key in the token.
        #[arg(long)]
        key_id: String,
    },
    /// Verify a signature of the payload (read from STDIN as raw bytes) with
    /// the EC public key inside the HSM. Print `valid` and exit with code 0 if
    /// the signature matches. Otherwise exit with code 1.
    Verify {
        /// The label of the EC key pair that made the signature.
        #[arg(long)]
        key_id: String,
        /// The signature as base64 of the DER form, as the API returns it.
        #[arg(long)]
        signature: String,
    },
    /// Wrap an EC private key with an AES key inside the HSM. Print the
    /// wrapped key to STDOUT as base64.
    Wrap {
        /// The label of the AES key that wraps the other key.
        #[arg(long)]
        key_id: String,
        /// The label of the EC private key to wrap. It must be extractable.
        #[arg(long)]
        target_key_id: String,
    },
}

/// Parse the command line arguments and run the command.
pub async fn run() {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Server) {
        Command::Server => run_server().await,
        Command::Encrypt { key_id } => do_encrypt(&key_id),
        Command::Decrypt { key_id } => do_decrypt(&key_id),
        Command::Verify { key_id, signature } => do_verify(&key_id, &signature),
        Command::Wrap {
            key_id,
            target_key_id,
        } => do_wrap(&key_id, &target_key_id),
    }
}

/// Read STDIN as the payload and verify the base64 DER `signature` with the EC
/// public key `key_id`. Print `valid` to STDOUT if it matches. Otherwise print
/// an error to STDERR and exit with code 1.
fn do_verify(key_id: &str, signature: &str) {
    let config = Config::try_from_env().unwrap_or_else(|err| {
        eprintln!("Error loading configuration: {err}");
        std::process::exit(1);
    });

    let signature = BASE64.decode(signature.trim()).unwrap_or_else(|err| {
        eprintln!("Error: the signature is not valid base64: {err}");
        std::process::exit(1);
    });

    let mut payload = Vec::new();
    if let Err(err) = std::io::stdin().read_to_end(&mut payload) {
        eprintln!("Error reading STDIN: {err}");
        std::process::exit(1);
    }

    let hsm_backend = hsm_backend::CryptokiBackend::try_new(&config).unwrap_or_else(|err| {
        eprintln!("Error initializing HSM backend: {err}");
        std::process::exit(1);
    });

    let valid = hsm_backend
        .verify(key_id, Algorithm::EcdsaP256Sha256, &payload, &signature)
        .unwrap_or_else(|err| {
            eprintln!("Error verifying the signature: {err}");
            std::process::exit(1);
        });

    if !valid {
        eprintln!("Error: the signature is not valid");
        std::process::exit(1);
    }
    println!("valid");
}

/// Wrap the EC private key `target_key_id` with the AES key `key_id` and print
/// the wrapped key to STDOUT as base64. Errors go to STDERR and the process
/// exits with code 1.
fn do_wrap(key_id: &str, target_key_id: &str) {
    let config = Config::try_from_env().unwrap_or_else(|err| {
        eprintln!("Error loading configuration: {err}");
        std::process::exit(1);
    });

    let hsm_backend = hsm_backend::CryptokiBackend::try_new(&config).unwrap_or_else(|err| {
        eprintln!("Error initializing HSM backend: {err}");
        std::process::exit(1);
    });

    let wrapped = hsm_backend
        .wrap(key_id, target_key_id)
        .unwrap_or_else(|err| {
            eprintln!("Error wrapping the key: {err}");
            std::process::exit(1);
        });

    println!("{}", BASE64.encode(wrapped));
}

/// Read STDIN, base64-decode it, decrypt it with the AES key `key_id` and write
/// the plaintext bytes to STDOUT. Surrounding whitespace in the input is
/// ignored. Errors go to STDERR and the process exits with code 1.
fn do_decrypt(key_id: &str) {
    let config = Config::try_from_env().unwrap_or_else(|err| {
        eprintln!("Error loading configuration: {err}");
        std::process::exit(1);
    });

    let mut input = Vec::new();
    if let Err(err) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("Error reading STDIN: {err}");
        std::process::exit(1);
    }
    let encrypted = BASE64.decode(input.trim_ascii()).unwrap_or_else(|err| {
        eprintln!("Error: STDIN is not valid base64: {err}");
        std::process::exit(1);
    });

    let hsm_backend = hsm_backend::CryptokiBackend::try_new(&config).unwrap_or_else(|err| {
        eprintln!("Error initializing HSM backend: {err}");
        std::process::exit(1);
    });

    let plaintext = hsm_backend
        .decrypt(key_id, &encrypted)
        .unwrap_or_else(|err| {
            eprintln!("Error decrypting: {err}");
            std::process::exit(1);
        });

    let mut stdout = std::io::stdout().lock();
    if let Err(err) = stdout.write_all(&plaintext).and_then(|()| stdout.flush()) {
        eprintln!("Error writing STDOUT: {err}");
        std::process::exit(1);
    }
}

/// Read STDIN, encrypt it with the AES key `key_id` and print base64 to STDOUT.
/// Errors go to STDERR and the process exits with code 1.
fn do_encrypt(key_id: &str) {
    let config = Config::try_from_env().unwrap_or_else(|err| {
        eprintln!("Error loading configuration: {err}");
        std::process::exit(1);
    });

    let mut plaintext = Vec::new();
    if let Err(err) = std::io::stdin().read_to_end(&mut plaintext) {
        eprintln!("Error reading STDIN: {err}");
        std::process::exit(1);
    }

    let hsm_backend = hsm_backend::CryptokiBackend::try_new(&config).unwrap_or_else(|err| {
        eprintln!("Error initializing HSM backend: {err}");
        std::process::exit(1);
    });

    let encrypted = hsm_backend
        .encrypt(key_id, &plaintext)
        .unwrap_or_else(|err| {
            eprintln!("Error encrypting: {err}");
            std::process::exit(1);
        });

    println!("{}", BASE64.encode(encrypted));
}

/// Install the log subscriber. The level comes from `RUST_LOG` (default `info`).
///
/// If `OTEL_EXPORTER_OTLP_ENDPOINT` is set, the spans also go to the OTLP
/// collector. The caller must call `shutdown` on the returned guard before the
/// process ends. A failure to set up the exporter is printed, and the service
/// runs without telemetry: signing must not stop because of it.
fn init_tracing() -> Option<TelemetryGuard> {
    let (guard, otel_layer) = match telemetry::init() {
        Ok(Some((guard, tracer))) => (
            Some(guard),
            Some(tracing_opentelemetry::layer().with_tracer(tracer)),
        ),
        Ok(None) => (None, None),
        Err(err) => {
            eprintln!("Error setting up telemetry, continuing without it: {err}");
            (None, None)
        }
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::CLOSE))
        .with(otel_layer)
        .init();

    if guard.is_some() {
        tracing::info!("sending traces to the OTLP collector");
    }
    guard
}

/// Run the HTTP signing service until the process stops.
async fn run_server() {
    println!("hsm-signing-service version {CRATE_VERSION} starting...");

    let config = Config::try_from_env().unwrap_or_else(|err| {
        eprintln!("Error loading configuration: {err}");
        std::process::exit(1);
    });

    // Start logging before the backend, so its start-up messages are written.
    let telemetry = init_tracing();
    // Real instruments if telemetry is on. Otherwise they record nothing.
    let metrics = telemetry
        .as_ref()
        .map_or_else(Metrics::noop, |telemetry| Metrics::new(&telemetry.meter()));

    // With a session pool size, the service uses a pool of sessions. Without
    // one, it uses a single session.
    match config.session_pool_size() {
        Some(pool_size) => {
            let hsm_backend =
                hsm_backend::CryptokiBackendWithSessionPool::try_new(&config, pool_size)
                    .unwrap_or_else(|err| {
                        eprintln!("Error initializing HSM backend: {err}");
                        std::process::exit(1);
                    })
                    .with_metrics(&metrics);
            serve(config, hsm_backend, telemetry, metrics).await
        }
        None => {
            let hsm_backend =
                hsm_backend::CryptokiBackend::try_new(&config).unwrap_or_else(|err| {
                    eprintln!("Error initializing HSM backend: {err}");
                    std::process::exit(1);
                });
            serve(config, hsm_backend, telemetry, metrics).await
        }
    }
}

/// Serve the API with the given HSM backend until the process stops. Then send
/// the spans that are still in the queue of the exporter.
async fn serve<B>(
    config: Config,
    hsm_backend: B,
    telemetry: Option<TelemetryGuard>,
    metrics: Metrics,
) where
    B: HsmBackend,
{
    let app_state = AppState::try_new(&config, hsm_backend)
        .unwrap_or_else(|err| {
            eprintln!("Error initializing application state: {err}");
            std::process::exit(1);
        })
        .with_metrics(metrics);

    let state = Arc::new(app_state);

    let app = api::router(&config, state);

    let addr = config.addr();
    let listener = TcpListener::bind(&addr).await.expect("failed to bind");
    tracing::info!("listening on {addr}");

    // The server stops on a shutdown signal and waits for running requests.
    // The channel tells the drain timer when the signal arrived.
    let (signal_tx, signal_rx) = oneshot::channel::<()>();
    let server = async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_signal().await;
                tracing::info!("shutdown signal received, waiting for running requests");
                let _ = signal_tx.send(());
            })
            .await
    };
    let drain_timeout = config.shutdown_timeout();
    let drain_timer = async move {
        // Without a signal the channel closes, and the timer must never fire.
        if signal_rx.await.is_ok() {
            tokio::time::sleep(drain_timeout).await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    tokio::select! {
        result = server => {
            result.expect("server error");
            tracing::info!("shut down");
            if let Some(telemetry) = telemetry {
                telemetry.shutdown();
            }
        }
        () = drain_timer => {
            tracing::warn!(
                "requests still running after {} seconds, exiting",
                drain_timeout.as_secs()
            );
            // Keep the spans of the slow requests: they are the interesting ones.
            if let Some(telemetry) = telemetry {
                telemetry.shutdown();
            }
            std::process::exit(1);
        }
    }
}

/// Wait for Ctrl+C or, on Unix, for SIGTERM (the signal that Docker and
/// Kubernetes send to stop a container).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install the Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal(SignalKind::terminate())
            .expect("failed to install the SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
