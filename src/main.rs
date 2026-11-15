//! A simple HTTP service that signs payloads using a hardware security module (HSM).

mod api;
mod app_state;
mod cli;
mod config;
mod errors;
mod hsm_backend;

#[tokio::main]
async fn main() {
    cli::run().await
}
