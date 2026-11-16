//! A simple HTTP service that signs payloads using a hardware security module (HSM).

mod algorithm;
mod api;
mod app_state;
mod cli;
mod config;
mod errors;
mod hsm_backend;
mod utils;

#[tokio::main]
async fn main() {
    cli::run().await
}
