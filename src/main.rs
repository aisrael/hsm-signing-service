use clap::crate_version;

const CRATE_VERSION: &str = crate_version!();

#[tokio::main]
async fn main() {
    println!("hsm-signing-service version {CRATE_VERSION} starting...");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
}
