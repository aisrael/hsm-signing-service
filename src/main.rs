//! A simple HTTP service that signs payloads using a hardware security module (HSM).

use std::fmt::Write;

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use base64::Engine;
use base64::engine::GeneralPurpose;
use clap::crate_version;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::instrument;
use tracing::trace;
use tracing_subscriber::fmt::format::FmtSpan;

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
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let error_body = ErrorResponse {
            error: self.to_string(),
        };
        (StatusCode::BAD_REQUEST, Json(error_body)).into_response()
    }
}

/// Just an alias for the base64 engine we use to decode the payload.
const BASE64: GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

#[instrument(skip(request))]
async fn handle_post_sign(
    Json(request): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    trace!("POST /v1/sign");
    // Validate that the payload is valid base64.
    let decoded_payload = BASE64.decode(&request.payload)?;
    // For now, we just return the payload in hex as the signature.
    let signature = encode_hex(&decoded_payload);
    let response = SignResponse {
        key_id: request.key_id,
        algorithm: request.algorithm,
        signature: signature,
        duration_ms: 1,
    };
    Ok(Json(response))
}

#[tokio::main]
async fn main() {
    let hsm_signing_service_host =
        std::env::var("HSM_SIGNING_SERVICE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let hsm_signing_service_port =
        std::env::var("HSM_SIGNING_SERVICE_PORT").unwrap_or_else(|_| "8080".into());

    println!("hsm-signing-service version {CRATE_VERSION} starting...");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let app = Router::new().route("/v1/sign", post(handle_post_sign));

    let addr = format!("{hsm_signing_service_host}:{hsm_signing_service_port}");
    let listener = TcpListener::bind(&addr).await.expect("failed to bind");
    tracing::info!("listening on {addr}");

    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handle_post_sign_echoes_the_payload() {
        let request = SignRequest {
            key_id: "example".to_string(),
            algorithm: Algorithm::EcdsaP256Sha256,
            payload: "aGVsbG8gd29ybGQ=".to_string(), // "hello world"
        };

        let Json(response) = handle_post_sign(Json(request))
            .await
            .expect("Expected Ok(Json(SignResponse))");

        assert_eq!(response.key_id, "example");
        assert_eq!(response.algorithm, Algorithm::EcdsaP256Sha256);
        // For now, the handler echoes the payload as the signature.
        assert_eq!(response.signature, "68656c6c6f20776f726c64");
    }

    #[tokio::test]
    async fn handle_post_sign_invalid_base64_payload() {
        let request = SignRequest {
            key_id: "example".to_string(),
            algorithm: Algorithm::EcdsaP256Sha256,
            payload: "invalid_base64".to_string(),
        };

        let result = handle_post_sign(Json(request)).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ApiError::PayloadBase64DecodingError(_)),
            "Expected PayloadBase64DecodingError, got {err:?}"
        );
    }
}
