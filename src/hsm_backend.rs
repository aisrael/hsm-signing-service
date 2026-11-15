//! The HSM backend trait and its implementation for SoftHSM2.

use std::sync::Mutex;
use std::sync::OnceLock;

use cryptoki::context::CInitializeArgs;
use cryptoki::context::CInitializeFlags;
use cryptoki::context::Pkcs11;
use cryptoki::error::Error as CryptokiError;
use cryptoki::session::Session;
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::config::Config;

/// Errors from the HSM backend. No message may contain the PIN.
#[derive(Debug, thiserror::Error)]
pub enum HsmBackendError {
    #[error("unable to load the PKCS#11 module: {0}")]
    LoadModule(#[source] CryptokiError),
    #[error("unable to initialize the PKCS#11 module: {0}")]
    InitializeModule(#[source] CryptokiError),
    #[error("unable to list the slots: {0}")]
    ListSlots(#[source] CryptokiError),
    #[error("no token with the label {0:?} was found")]
    TokenNotFound(String),
    #[error("unable to open a session: {0}")]
    OpenSession(#[source] CryptokiError),
    #[error("unable to log in to the token: {0}")]
    Login(#[source] CryptokiError),
}

pub trait HsmBackend {
    /// Sign the given payload using the specified key.
    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, String>;
}

/// Find the slot of the token that has the given label.
fn find_token_by_label(pkcs11: &Pkcs11, label: &str) -> Result<Slot, HsmBackendError> {
    let slots = pkcs11
        .get_slots_with_token()
        .map_err(HsmBackendError::ListSlots)?;
    slots
        .into_iter()
        .find(|slot| {
            pkcs11
                .get_token_info(*slot)
                .is_ok_and(|info| info.label() == label)
        })
        .ok_or_else(|| HsmBackendError::TokenNotFound(label.to_string()))
}

/// The PKCS#11 module. It is loaded and initialized once for the whole process.
///
/// It is never dropped, on purpose. Dropping it finalizes the module and
/// unloads the library, and SoftHSM2 then crashes (SIGSEGV) when the process
/// exits. A second `C_Initialize` in the same process also fails.
static PKCS11: OnceLock<Pkcs11> = OnceLock::new();

/// Load and initialize the PKCS#11 module on the first call. Later calls
/// return the same module and ignore the path in `config`.
fn load_pkcs11(config: &Config) -> Result<&'static Pkcs11, HsmBackendError> {
    if let Some(pkcs11) = PKCS11.get() {
        return Ok(pkcs11);
    }
    let pkcs11 = Pkcs11::new(config.pkcs11_module()).map_err(HsmBackendError::LoadModule)?;
    if let Err(e) = pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        // Dropping a module that is not initialized would also crash at exit.
        std::mem::forget(pkcs11);
        return Err(HsmBackendError::InitializeModule(e));
    }
    Ok(PKCS11.get_or_init(|| pkcs11))
}

/// Open a read-only session on the given slot and log in as the normal user.
fn open_logged_in_session(
    pkcs11: &Pkcs11,
    slot: Slot,
    config: &Config,
) -> Result<Session, HsmBackendError> {
    let session = pkcs11
        .open_ro_session(slot)
        .map_err(HsmBackendError::OpenSession)?;
    session
        .login(UserType::User, Some(&AuthPin::new(config.hsm_pin().into())))
        .map_err(HsmBackendError::Login)?;
    Ok(session)
}

/// A connection to a SoftHSM2 token through the PKCS#11 (Cryptoki) interface.
pub struct CryptokiBackend {
    /// A logged-in session. `Session` is not `Sync`, so it sits behind a `Mutex`.
    #[allow(dead_code)]
    session: Mutex<Session>,
}

impl CryptokiBackend {
    /// Load the PKCS#11 module, find the token by its label, open a session
    /// and log in as the normal user.
    pub fn try_new(config: &Config) -> Result<Self, HsmBackendError> {
        let pkcs11 = load_pkcs11(config)?;

        let token_label = config.key_label();
        let slot = find_token_by_label(pkcs11, token_label)?;

        let session = open_logged_in_session(pkcs11, slot, config)?;

        tracing::info!("connected to the HSM token {token_label:?}");
        Ok(CryptokiBackend {
            session: Mutex::new(session),
        })
    }
}

impl HsmBackend for CryptokiBackend {
    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        // Here you would implement the actual signing logic using SoftHSM2.
        // For now, we just return the payload as the "signature".
        Ok(payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::OnceLock;

    use super::*;

    const TOKEN_LABEL: &str = "example-test";
    const SO_PIN: &str = "0000test";
    const PIN: &str = "1234test";

    // The tests share one PKCS#11 module and one token. They run one at a
    // time, so a wrong-PIN test cannot affect the others.
    static PKCS11_LOCK: Mutex<()> = Mutex::new(());
    static TOKEN: OnceLock<()> = OnceLock::new();

    /// Create a SoftHSM2 token in a private directory below `target/`, once
    /// for the whole test run. The user's own SoftHSM2 tokens stay untouched.
    fn with_test_token() -> MutexGuard<'static, ()> {
        let guard = PKCS11_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        TOKEN.get_or_init(|| {
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-softhsm");
            let _ = std::fs::remove_dir_all(&dir);
            let tokens = dir.join("tokens");
            std::fs::create_dir_all(&tokens).expect("unable to create the token directory");

            let conf = dir.join("softhsm2.conf");
            std::fs::write(
                &conf,
                format!(
                    "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                    tokens.display()
                ),
            )
            .expect("unable to write softhsm2.conf");

            let output = Command::new("softhsm2-util")
                .env("SOFTHSM2_CONF", &conf)
                .args(["--init-token", "--free", "--label", TOKEN_LABEL])
                .args(["--so-pin", SO_PIN, "--pin", PIN])
                .output()
                .expect("unable to run softhsm2-util (is SoftHSM2 installed?)");
            assert!(
                output.status.success(),
                "softhsm2-util failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            // SAFETY: this runs once, before any test starts the PKCS#11
            // module. The tests that read the environment use other names.
            unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };
        });
        guard
    }

    #[test]
    fn connects_to_the_token() {
        let _lock = with_test_token();
        let config = Config::for_test(TOKEN_LABEL, PIN);

        let result = CryptokiBackend::try_new(&config);

        assert!(
            result.is_ok(),
            "expected to connect, got {:?}",
            result.err()
        );
    }

    #[test]
    fn fails_with_a_wrong_pin() {
        let _lock = with_test_token();
        let config = Config::for_test(TOKEN_LABEL, "wrong-pin");

        let error = CryptokiBackend::try_new(&config)
            .err()
            .expect("expected an error");

        let message = error.to_string();
        assert!(
            message.contains("unable to log in"),
            "unexpected: {message}"
        );
        assert!(!message.contains("wrong-pin"), "the error shows the PIN");
    }

    #[test]
    fn fails_when_no_token_has_the_label() {
        let _lock = with_test_token();
        let config = Config::for_test("no-such-token", PIN);

        let error = CryptokiBackend::try_new(&config)
            .err()
            .expect("expected an error");

        assert!(
            error.to_string().contains("no token with the label"),
            "unexpected: {error}"
        );
    }
}
