//! The configuration for the HSM signing service.

use std::time::Duration;
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
    /// The HSM_SIGNING_SERVICE_SHUTDOWN_TIMEOUT_SECS is not a whole number of 1 or more
    #[error(
        "HSM_SIGNING_SERVICE_SHUTDOWN_TIMEOUT_SECS must be a whole number of seconds, 1 or more: {0}"
    )]
    InvalidShutdownTimeout(String),
    /// The HSM_SIGNING_SERVICE_SESSION_POOL_SIZE is not a whole number of 1 or more
    #[error(
        "HSM_SIGNING_SERVICE_SESSION_POOL_SIZE must be a whole number of 1 or more, or not set: {0}"
    )]
    InvalidSessionPoolSize(String),
    /// The HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS is not a whole number of 1 or more
    #[error(
        "HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS must be a whole number of milliseconds, 1 or more: {0}"
    )]
    InvalidPoolConnectionTimeout(String),
    /// The HSM_SIGNING_SERVICE_MAX_QUEUE is not a whole number of 0 or more
    #[error("HSM_SIGNING_SERVICE_MAX_QUEUE must be a whole number of 0 or more: {0}")]
    InvalidMaxQueue(String),
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
    /// How long the server waits for running requests after a shutdown signal.
    shutdown_timeout: Duration,
    /// The number of HSM sessions in the session pool. `None` means no pool:
    /// the service uses a single session.
    session_pool_size: Option<u32>,
    /// How long a request waits for a free session of the session pool. The
    /// pool also uses it to open its sessions at start.
    pool_connection_timeout: Duration,
    /// How many requests can wait for a free session, in addition to the
    /// requests that use a session. The service rejects more requests with
    /// 503.
    max_queue: u32,
    /// The path to the HSM PKCS#11 library
    pkcs11_module: String,
    /// The label of the token. `setup.sh` uses the same label for the key.
    token_label: String,
    /// The PIN for the token
    hsm_pin: SecretString,
}

/// The default host for the HSM signing service
const DEFAULT_HSM_SIGNING_SERVICE_HOST: &str = "127.0.0.1";
/// The default port for the HSM signing service
const DEFAULT_HSM_SIGNING_SERVICE_PORT: &str = "8080";
/// The default number of seconds to wait for running requests on shutdown
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: &str = "30";
/// The default number of milliseconds to wait for a free session of the pool
const DEFAULT_POOL_CONNECTION_TIMEOUT_MS: &str = "500";
/// The default number of requests that can wait for a free session
const DEFAULT_MAX_QUEUE: &str = "20";
/// The default path to the HSM PKCS#11 library
const DEFAULT_PKCS11_MODULE: &str = "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so";

/// Parse the shutdown timeout: a whole number of seconds, 1 or more. Zero is
/// not valid, because it would end all running requests at once.
fn parse_shutdown_timeout(raw: String) -> Result<Duration, ConfigError> {
    match raw.parse::<u64>() {
        Ok(secs) if secs >= 1 => Ok(Duration::from_secs(secs)),
        _ => Err(ConfigError::InvalidShutdownTimeout(raw)),
    }
}

/// Parse the session pool size: a whole number of 1 or more. Zero is not
/// valid, because a pool without sessions cannot sign.
fn parse_session_pool_size(raw: String) -> Result<u32, ConfigError> {
    match raw.parse::<u32>() {
        Ok(size) if size >= 1 => Ok(size),
        _ => Err(ConfigError::InvalidSessionPoolSize(raw)),
    }
}

/// Parse the pool connection timeout: a whole number of milliseconds, 1 or
/// more. Zero is not valid, because a request would fail at once when all
/// sessions are in use.
fn parse_pool_connection_timeout(raw: String) -> Result<Duration, ConfigError> {
    match raw.parse::<u64>() {
        Ok(millis) if millis >= 1 => Ok(Duration::from_millis(millis)),
        _ => Err(ConfigError::InvalidPoolConnectionTimeout(raw)),
    }
}

/// Parse the maximum queue length: a whole number of 0 or more. Zero is valid:
/// then no request waits, and the service rejects a request when all sessions
/// are in use.
fn parse_max_queue(raw: String) -> Result<u32, ConfigError> {
    raw.parse::<u32>()
        .map_err(|_| ConfigError::InvalidMaxQueue(raw))
}

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

/// Read an optional environment variable that has no default.
///
/// Returns `None` if the variable is not set. A variable that is set must
/// still be valid unicode and not empty, so a mistake is never hidden.
fn try_read_optional_from_env(name: &'static str) -> Result<Option<String>, ConfigError> {
    match try_read_from_env(name) {
        Err(ConfigError::EnvVarNotSet(_)) => Ok(None),
        result => result.map(Some),
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
        let shutdown_timeout = parse_shutdown_timeout(try_read_from_env_with_default(
            "HSM_SIGNING_SERVICE_SHUTDOWN_TIMEOUT_SECS",
            DEFAULT_SHUTDOWN_TIMEOUT_SECS,
        )?)?;
        let session_pool_size =
            try_read_optional_from_env("HSM_SIGNING_SERVICE_SESSION_POOL_SIZE")?
                .map(parse_session_pool_size)
                .transpose()?;
        let pool_connection_timeout =
            parse_pool_connection_timeout(try_read_from_env_with_default(
                "HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS",
                DEFAULT_POOL_CONNECTION_TIMEOUT_MS,
            )?)?;
        let max_queue = parse_max_queue(try_read_from_env_with_default(
            "HSM_SIGNING_SERVICE_MAX_QUEUE",
            DEFAULT_MAX_QUEUE,
        )?)?;
        let pkcs11_module = try_read_from_env_with_default("PKCS11_MODULE", DEFAULT_PKCS11_MODULE)?;

        if !file_is_readable(&pkcs11_module) {
            return Err(ConfigError::Pkcs11ModuleNotFound(pkcs11_module));
        }

        let token_label = try_read_from_env("HSM_TOKEN_LABEL")?;
        let hsm_pin = SecretString::from(try_read_from_env("HSM_PIN")?);

        Ok(Config {
            host,
            port,
            shutdown_timeout,
            session_pool_size,
            pool_connection_timeout,
            max_queue,
            pkcs11_module,
            token_label,
            hsm_pin,
        })
    }

    /// A `Config` for tests that need a token. The PKCS#11 module comes from
    /// `PKCS11_MODULE` or the default, like in `try_from_env`.
    #[cfg(test)]
    pub fn for_test(token_label: &str, hsm_pin: &str) -> Self {
        Config {
            host: DEFAULT_HSM_SIGNING_SERVICE_HOST.into(),
            port: DEFAULT_HSM_SIGNING_SERVICE_PORT
                .parse()
                .expect("the default port is valid"),
            shutdown_timeout: parse_shutdown_timeout(DEFAULT_SHUTDOWN_TIMEOUT_SECS.into())
                .expect("the default shutdown timeout is valid"),
            session_pool_size: None,
            pool_connection_timeout: parse_pool_connection_timeout(
                DEFAULT_POOL_CONNECTION_TIMEOUT_MS.into(),
            )
            .expect("the default pool connection timeout is valid"),
            max_queue: parse_max_queue(DEFAULT_MAX_QUEUE.into())
                .expect("the default maximum queue length is valid"),
            pkcs11_module: try_read_from_env_with_default("PKCS11_MODULE", DEFAULT_PKCS11_MODULE)
                .expect("PKCS11_MODULE is valid"),
            token_label: token_label.into(),
            hsm_pin: SecretString::from(hsm_pin),
        }
    }

    /// The same `Config`, with another queue length. For tests that need a
    /// small limit for the requests.
    #[cfg(test)]
    pub fn with_max_queue(mut self, max_queue: u32) -> Self {
        self.max_queue = max_queue;
        self
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// How long to wait for running requests after a shutdown signal.
    pub fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// The number of sessions in the session pool, or `None` for no pool (a
    /// single session).
    pub fn session_pool_size(&self) -> Option<u32> {
        self.session_pool_size
    }

    /// How long a request waits for a free session of the session pool.
    pub fn pool_connection_timeout(&self) -> Duration {
        self.pool_connection_timeout
    }

    /// How many requests can be in the service at the same time: the sessions
    /// (one without a pool) plus the queue. The service answers more requests
    /// with 503.
    pub fn max_concurrent_requests(&self) -> usize {
        let sessions = self.session_pool_size.unwrap_or(1) as usize;
        sessions + self.max_queue as usize
    }

    pub fn pkcs11_module(&self) -> &str {
        &self.pkcs11_module
    }

    pub fn token_label(&self) -> &str {
        &self.token_label
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
    fn shutdown_timeout_accepts_a_whole_number_of_seconds() {
        assert_eq!(
            parse_shutdown_timeout("30".into()).unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_shutdown_timeout("1".into()).unwrap(),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn shutdown_timeout_rejects_other_values() {
        for raw in ["0", "abc", "-5", "1.5", "18446744073709551616", " 5"] {
            let result = parse_shutdown_timeout(raw.into());
            assert!(
                matches!(&result, Err(ConfigError::InvalidShutdownTimeout(value)) if value == raw),
                "{raw:?}: unexpected {result:?}"
            );
        }
    }

    #[test]
    fn default_shutdown_timeout_is_valid() {
        let config = Config::for_test("example", "test-pin");
        assert_eq!(config.shutdown_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn optional_read_returns_the_value_when_set() {
        set("CONFIG_TEST_OPTIONAL_VALUE", "value");
        let result = try_read_optional_from_env("CONFIG_TEST_OPTIONAL_VALUE");
        assert_eq!(result.unwrap().as_deref(), Some("value"));
    }

    #[test]
    fn optional_read_returns_none_when_not_set() {
        let result = try_read_optional_from_env("CONFIG_TEST_OPTIONAL_NOT_SET");
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn optional_read_fails_when_empty() {
        set("CONFIG_TEST_OPTIONAL_EMPTY", "");
        let result = try_read_optional_from_env("CONFIG_TEST_OPTIONAL_EMPTY");
        assert!(matches!(
            result,
            Err(ConfigError::EnvVarEmpty("CONFIG_TEST_OPTIONAL_EMPTY"))
        ));
    }

    #[test]
    fn session_pool_size_accepts_a_whole_number_of_1_or_more() {
        assert_eq!(parse_session_pool_size("1".into()).unwrap(), 1);
        assert_eq!(parse_session_pool_size("10".into()).unwrap(), 10);
    }

    #[test]
    fn session_pool_size_rejects_other_values() {
        for raw in ["0", "abc", "-5", "1.5", "4294967296", " 5"] {
            let result = parse_session_pool_size(raw.into());
            assert!(
                matches!(&result, Err(ConfigError::InvalidSessionPoolSize(value)) if value == raw),
                "{raw:?}: unexpected {result:?}"
            );
        }
    }

    #[test]
    fn there_is_no_session_pool_by_default() {
        let config = Config::for_test("example", "test-pin");
        assert_eq!(config.session_pool_size(), None);
    }

    #[test]
    fn pool_connection_timeout_accepts_a_whole_number_of_milliseconds() {
        assert_eq!(
            parse_pool_connection_timeout("500".into()).unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(
            parse_pool_connection_timeout("1".into()).unwrap(),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn pool_connection_timeout_rejects_other_values() {
        for raw in ["0", "abc", "-5", "1.5", "18446744073709551616", " 5"] {
            let result = parse_pool_connection_timeout(raw.into());
            assert!(
                matches!(&result, Err(ConfigError::InvalidPoolConnectionTimeout(value)) if value == raw),
                "{raw:?}: unexpected {result:?}"
            );
        }
    }

    #[test]
    fn default_pool_connection_timeout_is_500_milliseconds() {
        let config = Config::for_test("example", "test-pin");
        assert_eq!(config.pool_connection_timeout(), Duration::from_millis(500));
    }

    #[test]
    fn max_queue_accepts_a_whole_number_of_0_or_more() {
        assert_eq!(parse_max_queue("0".into()).unwrap(), 0);
        assert_eq!(parse_max_queue("20".into()).unwrap(), 20);
    }

    #[test]
    fn max_queue_rejects_other_values() {
        for raw in ["abc", "-1", "1.5", "4294967296", " 5"] {
            let result = parse_max_queue(raw.into());
            assert!(
                matches!(&result, Err(ConfigError::InvalidMaxQueue(value)) if value == raw),
                "{raw:?}: unexpected {result:?}"
            );
        }
    }

    #[test]
    fn without_a_pool_the_service_takes_one_session_plus_the_queue() {
        let config = Config::for_test("example", "test-pin");
        // 1 session + 20 in the queue
        assert_eq!(config.max_concurrent_requests(), 21);
    }

    #[test]
    fn with_a_pool_the_service_takes_the_pool_size_plus_the_queue() {
        let mut config = Config::for_test("example", "test-pin");
        config.session_pool_size = Some(10);
        config.max_queue = 5;
        assert_eq!(config.max_concurrent_requests(), 15);
    }

    #[test]
    fn with_no_queue_the_service_takes_only_the_sessions() {
        let mut config = Config::for_test("example", "test-pin");
        config.session_pool_size = Some(4);
        config.max_queue = 0;
        assert_eq!(config.max_concurrent_requests(), 4);
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
