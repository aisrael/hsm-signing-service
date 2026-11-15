//! The command line interface and the code that runs each command.

use std::io::Read;
use std::io::Write;
use std::sync::Arc;

use base64::Engine;
use clap::Parser;
use clap::Subcommand;
use clap::crate_version;
use tokio::net::TcpListener;
use tracing_subscriber::fmt::format::FmtSpan;

use crate::api;
use crate::api::BASE64;
use crate::app_state::AppState;
use crate::config::Config;
use crate::hsm_backend;
use crate::hsm_backend::HsmBackend;

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
        Command::Wrap {
            key_id,
            target_key_id,
        } => do_wrap(&key_id, &target_key_id),
    }
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

/// Run the HTTP signing service until the process stops.
async fn run_server() {
    println!("hsm-signing-service version {CRATE_VERSION} starting...");

    let config = Config::try_from_env().unwrap_or_else(|err| {
        eprintln!("Error loading configuration: {err}");
        std::process::exit(1);
    });

    let hsm_backend = hsm_backend::CryptokiBackend::try_new(&config).unwrap_or_else(|err| {
        eprintln!("Error initializing HSM backend: {err}");
        std::process::exit(1);
    });

    let app_state = AppState::try_new(&config, hsm_backend).unwrap_or_else(|err| {
        eprintln!("Error initializing application state: {err}");
        std::process::exit(1);
    });

    let state = Arc::new(app_state);

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let app = api::router(state);

    let addr = config.addr();
    let listener = TcpListener::bind(&addr).await.expect("failed to bind");
    tracing::info!("listening on {addr}");

    axum::serve(listener, app).await.expect("server error");
}
