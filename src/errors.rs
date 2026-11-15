//! Application errors

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unable to initialize HSM backend: {0}")]
    HsmBackendInitializationError(String),
}
