//! A simple HTTP service that signs payloads using a hardware security module (HSM).

use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use base64::Engine;
use base64::engine::GeneralPurpose;
use clap::Parser;
use clap::Subcommand;
use clap::crate_version;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::instrument;
use tracing::trace;
use tracing_subscriber::fmt::format::FmtSpan;

mod app_state;
mod config;
mod errors;
mod hsm_backend;

use app_state::AppState;
use config::Config;

use crate::hsm_backend::HsmBackend;
use crate::hsm_backend::HsmBackendError;

const CRATE_VERSION: &str = crate_version!();

/// The algorithm to use for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "ECDSA_P256_SHA256")]
    EcdsaP256Sha256,
}

/// The request body for the POST /v1/sign endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub key_id: String,
    pub algorithm: Algorithm,
    pub payload: String,
}

/// The response body for the POST /v1/sign endpoint.
#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub key_id: String,
    pub algorithm: Algorithm,
    pub signature: String,
    pub duration_ms: u64,
}

/// The body of every error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Errors that the API returns to the client.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The `payload` field is not valid base64.
    #[error("Unable to base64 decode payload: {0}")]
    PayloadBase64DecodingError(#[from] base64::DecodeError),
    /// No private key has the label `key_id`. The label is not echoed back.
    #[error("Key not found")]
    KeyNotFound,
    /// Something failed inside the service. The cause is logged, not sent.
    #[error("Internal error")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            ApiError::PayloadBase64DecodingError(_) => StatusCode::BAD_REQUEST,
            ApiError::KeyNotFound => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::Internal(cause) => {
                tracing::error!("internal error: {cause}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let error_body = ErrorResponse {
            error: self.to_string(),
        };
        (status, Json(error_body)).into_response()
    }
}

/// Just an alias for the base64 engine we use to decode the payload.
const BASE64: GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[instrument(skip(state, request))]
async fn handle_post_sign<B>(
    State(state): State<Arc<AppState<B>>>,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError>
where
    B: HsmBackend,
{
    trace!("POST /v1/sign");
    let start = Instant::now();
    let decoded_payload = BASE64.decode(&request.payload)?;

    // `spawn_blocking` needs a `'static` closure, so it gets its own copies.
    let backend_state = Arc::clone(&state);
    let key_id = request.key_id.clone();
    let signature = tokio::task::spawn_blocking(move || {
        let backend = &backend_state.hsm_backend;
        // The key can still disappear before `sign` runs. Then `sign` returns
        // `KeyNotFound` and the client gets the same error.
        if !backend
            .key_exists(&key_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
        {
            return Err(ApiError::KeyNotFound);
        }
        backend
            .sign(&key_id, &decoded_payload)
            .map_err(|e| match e {
                // The key was removed after `key_exists` found it.
                HsmBackendError::KeyNotFound(_) => ApiError::KeyNotFound,
                e => ApiError::Internal(e.to_string()),
            })
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))??;

    let response = SignResponse {
        key_id: request.key_id,
        algorithm: request.algorithm,
        signature: BASE64.encode(signature),
        duration_ms: start.elapsed().as_millis() as u64,
    };
    Ok(Json(response))
}

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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Server) {
        Command::Server => run_server().await,
        Command::Encrypt { key_id } => run_encrypt(&key_id),
        Command::Decrypt { key_id } => run_decrypt(&key_id),
        // Not implemented yet. The command only parses its arguments.
        Command::Wrap { .. } => {}
    }
}

/// Read STDIN, base64-decode it, decrypt it with the AES key `key_id` and write
/// the plaintext bytes to STDOUT. Surrounding whitespace in the input is
/// ignored. Errors go to STDERR and the process exits with code 1.
fn run_decrypt(key_id: &str) {
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
fn run_encrypt(key_id: &str) {
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

    let app = Router::new()
        .route("/v1/sign", post(handle_post_sign))
        .with_state(state);

    let addr = config.addr();
    let listener = TcpListener::bind(&addr).await.expect("failed to bind");
    tracing::info!("listening on {addr}");

    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm_backend::MockHsmBackend;

    fn state_with(backend: MockHsmBackend) -> State<Arc<AppState<MockHsmBackend>>> {
        let config = Config::for_test("example", "0000");
        let app_state = AppState::try_new(&config, backend).expect("unable to build the state");
        State(Arc::new(app_state))
    }

    #[tokio::test]
    async fn handle_post_sign_echoes_the_payload() {
        let request = SignRequest {
            key_id: "example".to_string(),
            algorithm: Algorithm::EcdsaP256Sha256,
            payload: "aGVsbG8gd29ybGQ=".to_string(), // "hello world"
        };

        let mut backend = MockHsmBackend::new();
        backend
            .expect_key_exists()
            .withf(|key_id| key_id == "example")
            .times(1)
            .returning(|_| Ok(true));
        backend
            .expect_sign()
            .withf(|key_id, payload| key_id == "example" && payload == b"hello world")
            .times(1)
            .returning(|_, payload| Ok(payload.to_vec()));

        let Json(response) = handle_post_sign(state_with(backend), Json(request))
            .await
            .expect("Expected Ok(Json(SignResponse))");

        assert_eq!(response.key_id, "example");
        assert_eq!(response.algorithm, Algorithm::EcdsaP256Sha256);
        // The mock returns the payload as the signature.
        assert_eq!(response.signature, "aGVsbG8gd29ybGQ=");
    }

    #[tokio::test]
    async fn handle_post_sign_invalid_base64_payload() {
        let request = SignRequest {
            key_id: "example".to_string(),
            algorithm: Algorithm::EcdsaP256Sha256,
            payload: "invalid_base64".to_string(),
        };

        // The payload is rejected before the backend is called.
        let mut backend = MockHsmBackend::new();
        backend.expect_key_exists().never();
        backend.expect_sign().never();

        let result = handle_post_sign(state_with(backend), Json(request)).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ApiError::PayloadBase64DecodingError(_)),
            "Expected PayloadBase64DecodingError, got {err:?}"
        );
    }

    fn request(key_id: &str) -> Json<SignRequest> {
        Json(SignRequest {
            key_id: key_id.to_string(),
            algorithm: Algorithm::EcdsaP256Sha256,
            payload: "aGVsbG8gd29ybGQ=".to_string(), // "hello world"
        })
    }

    #[tokio::test]
    async fn handle_post_sign_unknown_key() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_key_exists()
            .times(1)
            .returning(|_| Ok(false));
        backend.expect_sign().never();

        let err = handle_post_sign(state_with(backend), request("no-such-key"))
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::KeyNotFound), "got {err:?}");
        assert_eq!(
            err.into_response().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn handle_post_sign_key_lookup_fails() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_key_exists()
            .times(1)
            .returning(|_| Err(HsmBackendError::TokenNotFound("secret-detail".into())));
        backend.expect_sign().never();

        let err = handle_post_sign(state_with(backend), request("example"))
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::Internal(_)), "got {err:?}");
        // The client message must not carry the cause.
        assert_eq!(err.to_string(), "Internal error");
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn handle_post_sign_key_removed_before_signing() {
        let mut backend = MockHsmBackend::new();
        backend.expect_key_exists().times(1).returning(|_| Ok(true));
        backend
            .expect_sign()
            .times(1)
            .returning(|key_id, _| Err(HsmBackendError::KeyNotFound(key_id.to_string())));

        let err = handle_post_sign(state_with(backend), request("example"))
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::KeyNotFound), "got {err:?}");
        assert_eq!(
            err.into_response().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn handle_post_sign_sign_fails() {
        let mut backend = MockHsmBackend::new();
        backend.expect_key_exists().times(1).returning(|_| Ok(true));
        backend
            .expect_sign()
            .times(1)
            .returning(|_, _| Err(HsmBackendError::AmbiguousKey("secret-detail".into())));

        let err = handle_post_sign(state_with(backend), request("example"))
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::Internal(_)), "got {err:?}");
        assert_eq!(err.to_string(), "Internal error");
    }
}
