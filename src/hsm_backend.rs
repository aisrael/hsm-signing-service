//! The HSM backend trait and its implementation for SoftHSM2.

use crate::config::Config;
use crate::errors::Error;

pub trait HsmBackend {
    /// Sign the given payload using the specified key.
    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct SoftHsm2Backend;

impl SoftHsm2Backend {
    pub fn try_new(config: &Config) -> Result<Self, Error> {
        Ok(SoftHsm2Backend)
    }
}

impl HsmBackend for SoftHsm2Backend {
    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        // Here you would implement the actual signing logic using SoftHSM2.
        // For now, we just return the payload as the "signature".
        Ok(payload.to_vec())
    }
}
