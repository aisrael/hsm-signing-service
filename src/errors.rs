//! Application errors

use crate::hsm_backend::HsmBackendError;

/// Application errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HSM backend error: {0}")]
    BackendError(#[from] HsmBackendError),
}
