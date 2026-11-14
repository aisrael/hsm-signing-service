use axum::Json;
use axum::Router;
use axum::routing::post;
use clap::crate_version;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;

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

async fn handle_post_sign(Json(request): Json<SignRequest>) -> Json<SignResponse> {
    Json(SignResponse {
        key_id: request.key_id,
        algorithm: request.algorithm,
        signature: request.payload, // For now, just echo the payload as the signature.
        duration_ms: 1,
    })
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
        .init();

    let app = Router::new().route("/v1/sign", post(handle_post_sign));

    let addr = format!("{hsm_signing_service_host}:{hsm_signing_service_port}");
    let listener = TcpListener::bind(&addr).await.expect("failed to bind");
    tracing::info!("listening on {addr}");

    axum::serve(listener, app).await.expect("server error");
}
