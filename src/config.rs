//! The configuration for the HSM signing service.

use std::{env::VarError, fs::File};

use secrecy::SecretString;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The environment variable is not set
    #[error("Environment variable {0} is not set")]
    EnvVarNotSet(&'static str),
    /// The environment variable is set, but its value is not valid unicode
    #[error("Environment variable {0} is not valid unicode")]
    EnvVarNotUnicode(&'static str),
    /// The environment variable is set, but its value is empty
    #[error("Environment variable {0} is empty")]
    EnvVarEmpty(&'static str),
    /// The HSM_SIGNING_SERVICE_PORT is not a valid u16
    #[error("HSM_SIGNING_SERVICE_PORT is not a valid u16: {0}")]
    InvalidHsmSigningServicePort(String),
    /// The PKCS11_MODULE variable points to a file that does not exist or is not readable
    #[error("PKCS11_MODULE file not found or not readable: {0}")]
    Pkcs11ModuleNotFound(String),
}

#[derive(Debug)]
pub struct Config {
    /// The host (address) to bind the service to.
    host: String,
    /// The port to bind the service to.
    port: u16,
    /// The path to the HSM PKCS#11 library
    pkcs11_module: String,
    /// The label of the token. `setup.sh` uses the same label for the key.
    key_label: String,
    /// The PIN for the token
    hsm_pin: SecretString,
}

/// The default host for the HSM signing service
const DEFAULT_HSM_SIGNING_SERVICE_HOST: &str = "127.0.0.1";
/// The default port for the HSM signing service
const DEFAULT_HSM_SIGNING_SERVICE_PORT: &str = "8080";
/// The default path to the HSM PKCS#11 library
const DEFAULT_PKCS11_MODULE: &str = "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so";

/// Check if a file exists and is readable
fn file_is_readable(path: &str) -> bool {
    File::open(path).is_ok()
}

/// Read a required environment variable.
///
/// Fails if the variable is not set, is not valid unicode, or is empty.
fn try_read_from_env(name: &'static str) -> Result<String, ConfigError> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Err(ConfigError::EnvVarEmpty(name)),
        Ok(value) => Ok(value),
        Err(VarError::NotPresent) => Err(ConfigError::EnvVarNotSet(name)),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::EnvVarNotUnicode(name)),
    }
}

/// Read an optional environment variable.
///
/// Returns `default` if the variable is not set. A variable that is set must
/// still be valid unicode and not empty, so a mistake is never hidden by the
/// default.
fn try_read_from_env_with_default(
    name: &'static str,
    default: &str,
) -> Result<String, ConfigError> {
    match try_read_from_env(name) {
        Err(ConfigError::EnvVarNotSet(_)) => Ok(default.to_owned()),
        result => result,
    }
}

impl Config {
    pub fn try_from_env() -> Result<Self, ConfigError> {
        let host = try_read_from_env_with_default(
            "HSM_SIGNING_SERVICE_HOST",
            DEFAULT_HSM_SIGNING_SERVICE_HOST,
        )?;
        let raw_port = try_read_from_env_with_default(
            "HSM_SIGNING_SERVICE_PORT",
            DEFAULT_HSM_SIGNING_SERVICE_PORT,
        )?;
        let port = raw_port
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidHsmSigningServicePort(raw_port))?;
        let pkcs11_module = try_read_from_env_with_default("PKCS11_MODULE", DEFAULT_PKCS11_MODULE)?;

        if !file_is_readable(&pkcs11_module) {
            return Err(ConfigError::Pkcs11ModuleNotFound(pkcs11_module));
        }

        let key_label = try_read_from_env("KEY_LABEL")?;
        let hsm_pin = SecretString::from(try_read_from_env("HSM_PIN")?);

        Ok(Config {
            host,
            port,
            pkcs11_module,
            key_label,
            hsm_pin,
        })
    }

    /// A `Config` for tests that need a token. The PKCS#11 module comes from
    /// `PKCS11_MODULE` or the default, like in `try_from_env`.
    #[cfg(test)]
    pub fn for_test(key_label: &str, hsm_pin: &str) -> Self {
        Config {
            host: DEFAULT_HSM_SIGNING_SERVICE_HOST.into(),
            port: DEFAULT_HSM_SIGNING_SERVICE_PORT
                .parse()
                .expect("the default port is valid"),
            pkcs11_module: try_read_from_env_with_default("PKCS11_MODULE", DEFAULT_PKCS11_MODULE)
                .expect("PKCS11_MODULE is valid"),
            key_label: key_label.into(),
            hsm_pin: SecretString::from(hsm_pin),
        }
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

    /// The PIN. Call `expose_secret()` only where the PIN is really needed.
    pub fn hsm_pin(&self) -> &SecretString {
        &self.hsm_pin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests change the process environment, which is shared by all
    // tests that run in parallel. Each test uses its own variable name, and
    // no other code reads these names.
    //
    // SAFETY (for every `set_var` call below): no other thread reads or
    // writes these variables while the test runs.
    fn set(name: &str, value: &str) {
        unsafe { std::env::set_var(name, value) };
    }

    #[test]
    fn read_returns_the_value() {
        set("CONFIG_TEST_READ_VALUE", "value");
        assert_eq!(
            try_read_from_env("CONFIG_TEST_READ_VALUE").unwrap(),
            "value"
        );
    }

    #[test]
    fn read_fails_when_not_set() {
        let result = try_read_from_env("CONFIG_TEST_READ_NOT_SET");
        assert!(matches!(
            result,
            Err(ConfigError::EnvVarNotSet("CONFIG_TEST_READ_NOT_SET"))
        ));
    }

    #[test]
    fn read_fails_when_empty() {
        set("CONFIG_TEST_READ_EMPTY", "");
        let result = try_read_from_env("CONFIG_TEST_READ_EMPTY");
        assert!(matches!(
            result,
            Err(ConfigError::EnvVarEmpty("CONFIG_TEST_READ_EMPTY"))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn read_fails_when_not_unicode() {
        use std::os::unix::ffi::OsStrExt;
        let value = std::ffi::OsStr::from_bytes(&[0xff, 0xfe]);
        unsafe { std::env::set_var("CONFIG_TEST_READ_NOT_UNICODE", value) };
        let result = try_read_from_env("CONFIG_TEST_READ_NOT_UNICODE");
        assert!(matches!(
            result,
            Err(ConfigError::EnvVarNotUnicode(
                "CONFIG_TEST_READ_NOT_UNICODE"
            ))
        ));
    }

    #[test]
    fn with_default_returns_the_value_when_set() {
        set("CONFIG_TEST_DEFAULT_VALUE", "value");
        let result = try_read_from_env_with_default("CONFIG_TEST_DEFAULT_VALUE", "default");
        assert_eq!(result.unwrap(), "value");
    }

    #[test]
    fn with_default_returns_the_default_when_not_set() {
        let result = try_read_from_env_with_default("CONFIG_TEST_DEFAULT_NOT_SET", "default");
        assert_eq!(result.unwrap(), "default");
    }

    #[test]
    fn with_default_fails_when_empty() {
        set("CONFIG_TEST_DEFAULT_EMPTY", "");
        let result = try_read_from_env_with_default("CONFIG_TEST_DEFAULT_EMPTY", "default");
        assert!(matches!(
            result,
            Err(ConfigError::EnvVarEmpty("CONFIG_TEST_DEFAULT_EMPTY"))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn with_default_fails_when_not_unicode() {
        use std::os::unix::ffi::OsStrExt;
        let value = std::ffi::OsStr::from_bytes(&[0xff, 0xfe]);
        unsafe { std::env::set_var("CONFIG_TEST_DEFAULT_NOT_UNICODE", value) };
        let result = try_read_from_env_with_default("CONFIG_TEST_DEFAULT_NOT_UNICODE", "default");
        assert!(matches!(
            result,
            Err(ConfigError::EnvVarNotUnicode(
                "CONFIG_TEST_DEFAULT_NOT_UNICODE"
            ))
        ));
    }

    #[test]
    fn debug_output_does_not_show_the_pin() {
        let pin = "pin-that-must-stay-secret";
        let config = Config::for_test("example", pin);

        // The compact and the pretty-printed form both use `Debug`.
        for output in [format!("{config:?}"), format!("{config:#?}")] {
            assert!(!output.contains(pin), "Debug shows the PIN: {output}");
            assert!(output.contains("REDACTED"), "unexpected: {output}");
            // The other fields are still visible, so the output is useful.
            assert!(output.contains("example"), "unexpected: {output}");
        }
    }
}
