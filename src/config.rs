//! The configuration for the HSM signing service.

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The HSM_SIGNING_SERVICE_PORT is not a valid u16
    #[error("HSM_SIGNING_SERVICE_PORT is not a valid u16: {0}")]
    InvalidHsmSigningServicePort(String),
    /// The PKCS11_MODULE variable points to a non-existent file
    #[error("PKCS11_MODULE points to a non-existent file: {0}")]
    Pkcs11ModuleNotFound(String),
    /// The TOKEN_LABEL variable is not set
    #[error("KEY_LABEL is not set")]
    KeyLabelNotSet,
    /// The HSM_PIN variable is not set
    #[error("HSM_PIN is not set")]
    HsmPinNotSet,
}

pub struct Config {
    /// The host and port to bind the service to.
    host: String,
    /// The port to bind the service to.
    port: u16,
    /// The path to the HSM PKCS#11 library
    pkcs11_module: String,
    /// The token label
    key_label: String,
    /// The PIN for the token
    hsm_pin: String,
}

/// The default host and port for the HSM signing service
const DEFAULT_HSM_SIGNING_SERVICE_HOST: &str = "127.0.0.1";
/// The default port for the HSM signing service
const DEFAULT_HSM_SIGNING_SERVICE_PORT: &str = "8080";
/// The default path to the HSM PKCS#11 library
const DEFAULT_PKCS11_MODULE: &str = "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so";

impl Config {
    pub fn try_from_env() -> Result<Self, ConfigError> {
        let host = std::env::var("HSM_SIGNING_SERVICE_HOST")
            .unwrap_or_else(|_| DEFAULT_HSM_SIGNING_SERVICE_HOST.into());
        let raw_port = std::env::var("HSM_SIGNING_SERVICE_PORT")
            .unwrap_or_else(|_| DEFAULT_HSM_SIGNING_SERVICE_PORT.into());
        let port = raw_port
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidHsmSigningServicePort(raw_port))?;
        let pkcs11_module = std::env::var("PKCS11_MODULE").unwrap_or(DEFAULT_PKCS11_MODULE.into());
        let key_label = std::env::var("KEY_LABEL").map_err(|_| ConfigError::KeyLabelNotSet)?;
        let hsm_pin = std::env::var("HSM_PIN").map_err(|_| ConfigError::HsmPinNotSet)?;

        Ok(Config {
            host,
            port,
            pkcs11_module,
            key_label,
            hsm_pin,
        })
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn pkcs11_module(&self) -> &str {
        &self.pkcs11_module
    }

    pub fn key_label(&self) -> &str {
        &self.key_label
    }

    pub fn hsm_pin(&self) -> &str {
        &self.hsm_pin
    }
}
