use axum::Router;
use axum::routing::post;
use clap::crate_version;
use tokio::net::TcpListener;

const CRATE_VERSION: &str = crate_version!();

async fn handle_post_sign() {
    tracing::trace!("POST /v1/sign");
}

#[tokio::main]
async fn main() {
    println!("hsm-signing-service version {CRATE_VERSION} starting...");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let app = Router::new().route("/v1/sign", post(handle_post_sign));

    let addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(addr).await.expect("failed to bind");
    tracing::info!("listening on {addr}");

    axum::serve(listener, app).await.expect("server error");
}
