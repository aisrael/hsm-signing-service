//! The HSM backend trait and its implementation for SoftHSM2.

use std::ops::Deref;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::OnceLock;

use cryptoki::context::CInitializeArgs;
use cryptoki::context::CInitializeFlags;
use cryptoki::context::Pkcs11;
use cryptoki::error::Error as CryptokiError;
use cryptoki::error::RvError;
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::object::Attribute;
use cryptoki::object::KeyType;
use cryptoki::object::ObjectClass;
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use r2d2_cryptoki::Pool;
use r2d2_cryptoki::PooledSession;
use r2d2_cryptoki::SessionAuth;
use r2d2_cryptoki::SessionManager;
use r2d2_cryptoki::r2d2;
use secrecy::ExposeSecret;

use crate::algorithm::Algorithm;
use crate::config::Config;
use crate::metrics::GaugeGuard;
use crate::metrics::Metrics;
use crate::utils::der_to_raw_signature;
use crate::utils::raw_to_der_signature;

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
    #[error("unable to open the session pool: {0}")]
    BuildPool(#[source] r2d2::Error),
    #[error("unable to get a session from the pool: {0}")]
    Checkout(#[source] r2d2::Error),
    #[error("unable to search for the key: {0}")]
    FindKey(#[source] CryptokiError),
    #[error("no key with the label {0:?} was found")]
    KeyNotFound(String),
    #[error("more than one key has the label {0:?}")]
    AmbiguousKey(String),
    #[error("the HSM failed to sign: {0}")]
    Sign(#[source] CryptokiError),
    #[error("the HSM returned an invalid signature: {0}")]
    InvalidSignature(&'static str),
    #[error("the HSM failed to verify the signature: {0}")]
    Verify(#[source] CryptokiError),
    #[error("the signature has the wrong encoding: {0}")]
    InvalidSignatureEncoding(&'static str),
    #[error("the HSM failed to generate a random IV: {0}")]
    GenerateIv(#[source] CryptokiError),
    #[error("the HSM failed to encrypt: {0}")]
    Encrypt(#[source] CryptokiError),
    #[error("the encrypted data is too short")]
    InvalidCiphertext,
    #[error("the HSM failed to decrypt (wrong key or changed data): {0}")]
    Decrypt(#[source] CryptokiError),
    #[error("the HSM failed to wrap the key (is it extractable?): {0}")]
    Wrap(#[source] CryptokiError),
}

/// The length of the AES-GCM IV in bytes. 12 bytes (96 bits) is the usual size.
const GCM_IV_LEN: u32 = 12;
/// The length of the AES-GCM authentication tag in bits.
const GCM_TAG_BITS: u64 = 128;
/// The shortest valid encrypted data: the IV and the tag, with an empty ciphertext.
const GCM_MIN_LEN: usize = GCM_IV_LEN as usize + (GCM_TAG_BITS / 8) as usize;

#[cfg_attr(test, mockall::automock)]
pub trait HsmBackend: Send + Sync + 'static {
    /// Sign the given payload with the private key that has the label `key_id`,
    /// using the mechanism of `algorithm` inside the HSM. The HSM hashes the
    /// payload. The result is DER for ECDSA and the raw bytes for RSA.
    ///
    /// It fails with `KeyNotFound` if no key has the label and fits the
    /// algorithm (the key type, and for ECDSA the curve). This method blocks.
    fn sign(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmBackendError>;

    /// Verify a signature of `payload` (in the form that `sign` returns) with
    /// the public key that has the label `key_id`, using the mechanism of
    /// `algorithm` inside the HSM.
    ///
    /// Return `Ok(false)` if the signature does not match. Return an error if
    /// the key does not exist or does not fit the algorithm, if an ECDSA
    /// `signature` is not valid DER, or if the HSM fails. This method blocks.
    fn verify(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, HsmBackendError>;

    /// Encrypt the plaintext with the AES key that has the label `key_id`,
    /// using AES-GCM inside the HSM.
    ///
    /// The result is `iv || ciphertext || tag`. The IV has 12 bytes and the
    /// tag has 16 bytes. The HSM generates a new random IV for every call, so
    /// the caller cannot choose it. This method blocks.
    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmBackendError>;

    /// Decrypt data from `encrypt` with the AES key that has the label
    /// `key_id`. The input is `iv || ciphertext || tag`.
    ///
    /// It fails if the key is wrong or if the data changed, because AES-GCM
    /// checks the tag. This method blocks.
    fn decrypt(&self, key_id: &str, encrypted: &[u8]) -> Result<Vec<u8>, HsmBackendError>;

    /// Wrap the EC private key `target_key_id` with the AES key `key_id`,
    /// using AES key wrap with padding inside the HSM.
    ///
    /// The result is the target key (PKCS#8) encrypted with the AES key. The
    /// plain key never leaves the HSM. It fails if the target key is not
    /// extractable. This method blocks.
    fn wrap(&self, key_id: &str, target_key_id: &str) -> Result<Vec<u8>, HsmBackendError>;
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
        .login(
            UserType::User,
            Some(&AuthPin::new(config.hsm_pin().expose_secret().into())),
        )
        .map_err(HsmBackendError::Login)?;
    Ok(session)
}

/// A connection to a SoftHSM2 token through the PKCS#11 (Cryptoki) interface.
#[derive(Debug)]
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

        let token_label = config.token_label();
        let slot = find_token_by_label(pkcs11, token_label)?;

        let session = open_logged_in_session(pkcs11, slot, config)?;

        tracing::info!("connected to the HSM token {token_label:?}");
        Ok(CryptokiBackend {
            session: Mutex::new(session),
        })
    }

    /// Lock the session.
    ///
    /// A poisoned lock only means that another request panicked. The session
    /// itself is still usable.
    fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Find the EC private keys that have the label `key_id`. The label is
/// matched as exact bytes.
fn find_private_keys(session: &Session, key_id: &str) -> Result<Vec<ObjectHandle>, CryptokiError> {
    let template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Label(key_id.as_bytes().to_vec()),
    ];
    session.find_objects(&template)
}

/// Find the keys of the class `class` that have the label `key_id` and fit
/// `algorithm`: the key type, and for ECDSA the curve. The label is matched as
/// exact bytes.
fn find_keys_for(
    session: &Session,
    key_id: &str,
    algorithm: Algorithm,
    class: ObjectClass,
) -> Result<Vec<ObjectHandle>, CryptokiError> {
    let mut template = vec![
        Attribute::Class(class),
        Attribute::KeyType(algorithm.key_type()),
        Attribute::Label(key_id.as_bytes().to_vec()),
    ];
    if let Some(ec_params) = algorithm.ec_params() {
        template.push(Attribute::EcParams(ec_params.to_vec()));
    }
    session.find_objects(&template)
}

/// Find the AES secret keys that have the label `key_id`. The label is
/// matched as exact bytes.
fn find_aes_keys(session: &Session, key_id: &str) -> Result<Vec<ObjectHandle>, CryptokiError> {
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Label(key_id.as_bytes().to_vec()),
    ];
    session.find_objects(&template)
}

/// Return the handle if the search found exactly one key.
fn exactly_one(handles: Vec<ObjectHandle>, key_id: &str) -> Result<ObjectHandle, HsmBackendError> {
    match handles.as_slice() {
        [key] => Ok(*key),
        [] => Err(HsmBackendError::KeyNotFound(key_id.to_string())),
        _ => Err(HsmBackendError::AmbiguousKey(key_id.to_string())),
    }
}

/// Find the one AES key that has the label `key_id`.
fn find_aes_key(session: &Session, key_id: &str) -> Result<ObjectHandle, HsmBackendError> {
    let handles = find_aes_keys(session, key_id).map_err(HsmBackendError::FindKey)?;
    exactly_one(handles, key_id)
}

/// Find the one EC private key that has the label `key_id`.
fn find_private_key(session: &Session, key_id: &str) -> Result<ObjectHandle, HsmBackendError> {
    let handles = find_private_keys(session, key_id).map_err(HsmBackendError::FindKey)?;
    exactly_one(handles, key_id)
}

/// Find the one key of the class `class` that fits `algorithm`. One search
/// only: a key with the label but the wrong type or curve is `KeyNotFound`.
fn find_key_for(
    session: &Session,
    key_id: &str,
    algorithm: Algorithm,
    class: ObjectClass,
) -> Result<ObjectHandle, HsmBackendError> {
    let handles =
        find_keys_for(session, key_id, algorithm, class).map_err(HsmBackendError::FindKey)?;
    exactly_one(handles, key_id)
}

/// Convert a signature in the form of `sign` (DER for ECDSA, raw for RSA) to
/// the form of the HSM.
fn signature_for_hsm(algorithm: Algorithm, signature: &[u8]) -> Result<Vec<u8>, HsmBackendError> {
    match algorithm.ecdsa_component_len() {
        Some(component_len) => der_to_raw_signature(signature, component_len),
        None => Ok(signature.to_vec()),
    }
}

/// Sign with the mechanism of `algorithm`. The HSM hashes the payload. For
/// ECDSA the result is in DER form (the HSM returns the raw `r || s`). For RSA
/// it is the raw signature.
fn sign_with(
    session: &Session,
    key_id: &str,
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<Vec<u8>, HsmBackendError> {
    let key = find_key_for(session, key_id, algorithm, ObjectClass::PRIVATE_KEY)?;

    // Only the PKCS#11 call is inside the span: this is the time of the HSM,
    // without the key lookup.
    let raw = tracing::info_span!("hsm_sign", algorithm = algorithm.name()).in_scope(|| {
        session
            .sign(&algorithm.mechanism(), key, payload)
            .map_err(HsmBackendError::Sign)
    })?;
    match algorithm.ecdsa_component_len() {
        Some(component_len) => raw_to_der_signature(&raw, component_len),
        None => Ok(raw),
    }
}

/// Verify with the mechanism of `algorithm`. The HSM hashes the payload.
/// `hsm_signature` is in the form of the HSM (raw `r || s` for ECDSA).
fn verify_with(
    session: &Session,
    key_id: &str,
    algorithm: Algorithm,
    payload: &[u8],
    hsm_signature: &[u8],
) -> Result<bool, HsmBackendError> {
    let key = find_key_for(session, key_id, algorithm, ObjectClass::PUBLIC_KEY)?;

    match session.verify(&algorithm.mechanism(), key, payload, hsm_signature) {
        Ok(()) => Ok(true),
        Err(CryptokiError::Pkcs11(RvError::SignatureInvalid | RvError::SignatureLenRange, _)) => {
            Ok(false)
        }
        Err(e) => Err(HsmBackendError::Verify(e)),
    }
}

/// Encrypt with `CKM_AES_GCM`. The IV comes from the HSM random number
/// generator. The key never leaves the token.
fn encrypt_with(
    session: &Session,
    key_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, HsmBackendError> {
    let key = find_aes_key(session, key_id)?;

    let mut iv = session
        .generate_random_vec(GCM_IV_LEN)
        .map_err(HsmBackendError::GenerateIv)?;
    // The IV is not secret. Keep a copy, because the parameters borrow `iv`.
    let iv_copy = iv.clone();
    let params =
        GcmParams::new(&mut iv, &[], GCM_TAG_BITS.into()).map_err(HsmBackendError::Encrypt)?;
    let encrypted = session
        .encrypt(&Mechanism::AesGcm(params), key, plaintext)
        .map_err(HsmBackendError::Encrypt)?;

    let mut output = iv_copy;
    output.extend_from_slice(&encrypted);
    Ok(output)
}

/// Split `iv || ciphertext || tag` into the IV and the rest. Do this before a
/// session is in use, because it needs no HSM.
fn split_encrypted(encrypted: &[u8]) -> Result<(&[u8], &[u8]), HsmBackendError> {
    if encrypted.len() < GCM_MIN_LEN {
        return Err(HsmBackendError::InvalidCiphertext);
    }
    Ok(encrypted.split_at(GCM_IV_LEN as usize))
}

/// Decrypt with `CKM_AES_GCM`. The HSM checks the tag.
fn decrypt_with(
    session: &Session,
    key_id: &str,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, HsmBackendError> {
    let key = find_aes_key(session, key_id)?;

    let mut iv = iv.to_vec();
    let params =
        GcmParams::new(&mut iv, &[], GCM_TAG_BITS.into()).map_err(HsmBackendError::Decrypt)?;
    session
        .decrypt(&Mechanism::AesGcm(params), key, ciphertext)
        .map_err(HsmBackendError::Decrypt)
}

/// Wrap with `CKM_AES_KEY_WRAP_PAD`. The HSM exports the target key
/// encrypted. The plain key never leaves the token.
fn wrap_with(
    session: &Session,
    key_id: &str,
    target_key_id: &str,
) -> Result<Vec<u8>, HsmBackendError> {
    let wrapping_key = find_aes_key(session, key_id)?;
    let target_key = find_private_key(session, target_key_id)?;

    session
        .wrap_key(&Mechanism::AesKeyWrapPad, wrapping_key, target_key)
        .map_err(HsmBackendError::Wrap)
}

impl HsmBackend for CryptokiBackend {
    fn sign(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmBackendError> {
        sign_with(&self.session(), key_id, algorithm, payload)
    }

    fn verify(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, HsmBackendError> {
        let hsm_signature = signature_for_hsm(algorithm, signature)?;
        verify_with(&self.session(), key_id, algorithm, payload, &hsm_signature)
    }

    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmBackendError> {
        encrypt_with(&self.session(), key_id, plaintext)
    }

    fn decrypt(&self, key_id: &str, encrypted: &[u8]) -> Result<Vec<u8>, HsmBackendError> {
        let (iv, ciphertext) = split_encrypted(encrypted)?;
        decrypt_with(&self.session(), key_id, iv, ciphertext)
    }

    fn wrap(&self, key_id: &str, target_key_id: &str) -> Result<Vec<u8>, HsmBackendError> {
        wrap_with(&self.session(), key_id, target_key_id)
    }
}

/// A connection to a SoftHSM2 token with a pool of sessions (from `r2d2`), so
/// that several operations can run at the same time.
///
/// The login happens once, in `try_new`, before the pool exists. PKCS#11 login
/// belongs to the token, so every session of the pool is logged in after that.
/// The pool itself never logs in: a wrong PIN would make it try again and
/// again, and every failed login counts toward the lockout of the token.
#[derive(Debug)]
pub struct CryptokiBackendWithSessionPool {
    pool: Pool,
    /// The session that logged in. It stays open for the life of the process,
    /// so the token stays logged in even if the pool closes its sessions. It
    /// is not used for operations. `Session` is not `Sync`, so it sits behind
    /// a `Mutex`.
    _login_session: Mutex<Session>,
    /// The instruments. They record nothing until `with_metrics` sets them.
    metrics: Metrics,
}

/// A session that is taken from the pool. It derefs to the `Session`. While it
/// lives, the gauge `pool.sessions_in_use` counts it.
struct HeldSession {
    // The session goes back to the pool first, then the gauge goes down. For a
    // moment the gauge shows a session in use that is already free, never the
    // other way round.
    session: PooledSession,
    _in_use: GaugeGuard,
}

impl Deref for HeldSession {
    type Target = Session;

    fn deref(&self) -> &Session {
        &self.session
    }
}

impl CryptokiBackendWithSessionPool {
    /// Report the pool size and the sessions in use with these instruments.
    pub fn with_metrics(mut self, metrics: &Metrics) -> Self {
        metrics.set_pool_size(self.pool.max_size());
        self.metrics = metrics.clone();
        self
    }

    /// Load the PKCS#11 module, find the token by its label, log in as the
    /// normal user (once), and open `pool_size` sessions. It fails at once if
    /// the login fails or if the pool cannot open all of its sessions.
    pub fn try_new(config: &Config, pool_size: u32) -> Result<Self, HsmBackendError> {
        let pkcs11 = load_pkcs11(config)?;

        let token_label = config.token_label();
        let slot = find_token_by_label(pkcs11, token_label)?;

        let login_session = open_logged_in_session(pkcs11, slot, config)?;

        // The manager only opens sessions. The pool has no connection
        // customizer, so it never logs in. `SessionAuth::RoUser` makes the
        // pool open read-only sessions and expect the state "logged in".
        // `Pkcs11` is a shared handle, and the static in `load_pkcs11` keeps
        // the module loaded, so this clone cannot finalize the module.
        let auth = SessionAuth::RoUser(AuthPin::new(config.hsm_pin().expose_secret().into()));
        let manager = SessionManager::new(pkcs11.clone(), slot, &auth);

        // `build` waits until all sessions are open. The pool never closes a
        // session because of its age or because it is idle.
        let pool = Pool::builder()
            .max_size(pool_size)
            .min_idle(Some(pool_size))
            .idle_timeout(None)
            .max_lifetime(None)
            .connection_timeout(config.pool_connection_timeout())
            .build(manager)
            .map_err(HsmBackendError::BuildPool)?;

        tracing::info!("connected to the HSM token {token_label:?}");
        tracing::info!("opened {pool_size} HSM sessions");
        Ok(CryptokiBackendWithSessionPool {
            pool,
            _login_session: Mutex::new(login_session),
            metrics: Metrics::noop(),
        })
    }

    /// Take a session from the pool. It goes back to the pool when it is
    /// dropped. This blocks until a session is free, for at most
    /// the pool connection timeout from the `Config`.
    fn session(&self) -> Result<HeldSession, HsmBackendError> {
        // The span is the time that the request waits for a free session.
        let session = tracing::info_span!("pool_checkout")
            .in_scope(|| self.pool.get().map_err(HsmBackendError::Checkout))?;
        // Count the session only after the checkout worked.
        Ok(HeldSession {
            session,
            _in_use: self.metrics.session_in_use(),
        })
    }
}

impl HsmBackend for CryptokiBackendWithSessionPool {
    fn sign(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmBackendError> {
        let session = self.session()?;
        sign_with(&session, key_id, algorithm, payload)
    }

    fn verify(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, HsmBackendError> {
        let hsm_signature = signature_for_hsm(algorithm, signature)?;
        let session = self.session()?;
        verify_with(&session, key_id, algorithm, payload, &hsm_signature)
    }

    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmBackendError> {
        let session = self.session()?;
        encrypt_with(&session, key_id, plaintext)
    }

    fn decrypt(&self, key_id: &str, encrypted: &[u8]) -> Result<Vec<u8>, HsmBackendError> {
        let (iv, ciphertext) = split_encrypted(encrypted)?;
        let session = self.session()?;
        decrypt_with(&session, key_id, iv, ciphertext)
    }

    fn wrap(&self, key_id: &str, target_key_id: &str) -> Result<Vec<u8>, HsmBackendError> {
        let session = self.session()?;
        wrap_with(&session, key_id, target_key_id)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::OnceLock;
    use std::time::Duration;

    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::AttributeType;
    use p256::ecdsa::Signature;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

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

        let error = CryptokiBackend::try_new(&config).expect_err("expected an error");

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

        let error = CryptokiBackend::try_new(&config).expect_err("expected an error");

        assert!(
            error.to_string().contains("no token with the label"),
            "unexpected: {error}"
        );
    }

    /// Generate an EC P-256 key pair inside the test token. The private key is
    /// not extractable. Run once per label.
    fn generate_key_pair(label: &str) {
        generate_ec_key_pair(label, false);
    }

    /// Generate an EC P-256 key pair whose private key is extractable (and
    /// sensitive), so that it can be wrapped. Run once per label.
    fn generate_exportable_key_pair(label: &str) {
        generate_ec_key_pair(label, true);
    }

    fn generate_ec_key_pair(label: &str, extractable: bool) {
        generate_ec_key_pair_on(label, Algorithm::EcdsaP256Sha256, extractable);
    }

    /// Open a read-write session on the test token, logged in.
    fn test_session() -> Session {
        let config = Config::for_test(TOKEN_LABEL, PIN);
        let pkcs11 = load_pkcs11(&config).expect("unable to load the module");
        let slot = find_token_by_label(pkcs11, TOKEN_LABEL).expect("token not found");
        let session = pkcs11
            .open_rw_session(slot)
            .expect("unable to open a session");
        // The login state belongs to the token. Another session may have logged in already.
        let _ = session.login(UserType::User, Some(&AuthPin::new(PIN.into())));
        session
    }

    /// Generate an EC key pair on the curve of `algorithm` inside the test token.
    fn generate_ec_key_pair_on(label: &str, algorithm: Algorithm, extractable: bool) {
        let session = test_session();
        let ec_params = algorithm.ec_params().expect("not an EC algorithm").to_vec();
        let public = [
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::EcParams(ec_params),
            Attribute::Token(true),
            Attribute::Verify(true),
        ];
        let private = [
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(extractable),
            Attribute::Sign(true),
        ];
        session
            .generate_key_pair(&Mechanism::EccKeyPairGen, &public, &private)
            .expect("unable to generate the key pair");
    }

    /// Generate a 2048-bit RSA key pair inside the test token. The private key
    /// is not extractable.
    fn generate_rsa_key_pair(label: &str) {
        let session = test_session();
        let public = [
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::Token(true),
            Attribute::Verify(true),
        ];
        let private = [
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
        ];
        session
            .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public, &private)
            .expect("unable to generate the key pair");
    }

    #[test]
    fn sign_needs_an_exact_label_match() {
        let _lock = with_test_token();
        generate_key_pair("example-exact");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        for label in ["example-exac", "EXAMPLE-EXACT", "example-exact "] {
            let result = backend.sign(label, Algorithm::EcdsaP256Sha256, b"hello world");
            assert!(
                matches!(result, Err(HsmBackendError::KeyNotFound(_))),
                "label {label:?}: unexpected: {result:?}"
            );
        }
    }

    /// Read the public key of the pair with the given label from the test token.
    fn public_key(label: &str) -> VerifyingKey {
        let config = Config::for_test(TOKEN_LABEL, PIN);
        let pkcs11 = load_pkcs11(&config).expect("unable to load the module");
        let slot = find_token_by_label(pkcs11, TOKEN_LABEL).expect("token not found");
        let session = pkcs11
            .open_ro_session(slot)
            .expect("unable to open a session");
        let template = [
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let handle = session
            .find_objects(&template)
            .expect("unable to search for the public key")
            .into_iter()
            .next()
            .expect("the public key does not exist");
        let attributes = session
            .get_attributes(handle, &[AttributeType::EcPoint])
            .expect("unable to read the EC point");
        let Some(Attribute::EcPoint(point)) = attributes.into_iter().next() else {
            panic!("the public key has no EC point");
        };
        // CKA_EC_POINT is a DER OCTET STRING (2 bytes of header) around the SEC1 point.
        VerifyingKey::from_sec1_bytes(&point[2..]).expect("the EC point is not valid")
    }

    #[test]
    fn sign_returns_a_valid_der_signature_for_an_existing_key() {
        let _lock = with_test_token();
        generate_key_pair("example-sign");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let payload = b"hello world";

        let der = backend
            .sign("example-sign", Algorithm::EcdsaP256Sha256, payload)
            .expect("expected a signature");

        let signature = Signature::from_der(&der).expect("the signature is not valid DER");
        public_key("example-sign")
            .verify(payload, &signature)
            .expect("the signature does not verify");
    }

    #[test]
    fn verify_accepts_a_signature_from_sign() {
        let _lock = with_test_token();
        generate_key_pair("example-verify");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let der = backend
            .sign("example-verify", Algorithm::EcdsaP256Sha256, b"hello world")
            .unwrap();

        let result = backend.verify(
            "example-verify",
            Algorithm::EcdsaP256Sha256,
            b"hello world",
            &der,
        );

        assert!(matches!(result, Ok(true)), "unexpected: {result:?}");
    }

    #[test]
    fn verify_rejects_another_payload() {
        let _lock = with_test_token();
        generate_key_pair("example-verify-payload");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let der = backend
            .sign(
                "example-verify-payload",
                Algorithm::EcdsaP256Sha256,
                b"hello world",
            )
            .unwrap();

        let result = backend.verify(
            "example-verify-payload",
            Algorithm::EcdsaP256Sha256,
            b"hello World",
            &der,
        );

        assert!(matches!(result, Ok(false)), "unexpected: {result:?}");
    }

    #[test]
    fn verify_rejects_a_changed_signature() {
        let _lock = with_test_token();
        generate_key_pair("example-verify-changed");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let der = backend
            .sign(
                "example-verify-changed",
                Algorithm::EcdsaP256Sha256,
                b"hello world",
            )
            .unwrap();
        // Change one bit inside `r`, then encode the signature as DER again.
        let mut raw = Signature::from_der(&der).unwrap().to_bytes();
        raw[5] ^= 0x01;
        let changed = Signature::from_slice(&raw).unwrap().to_der();

        let result = backend.verify(
            "example-verify-changed",
            Algorithm::EcdsaP256Sha256,
            b"hello world",
            changed.as_bytes(),
        );

        assert!(matches!(result, Ok(false)), "unexpected: {result:?}");
    }

    #[test]
    fn verify_rejects_a_signature_from_another_key() {
        let _lock = with_test_token();
        generate_key_pair("example-verify-key-a");
        generate_key_pair("example-verify-key-b");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let der = backend
            .sign(
                "example-verify-key-a",
                Algorithm::EcdsaP256Sha256,
                b"hello world",
            )
            .unwrap();

        let result = backend.verify(
            "example-verify-key-b",
            Algorithm::EcdsaP256Sha256,
            b"hello world",
            &der,
        );

        assert!(matches!(result, Ok(false)), "unexpected: {result:?}");
    }

    #[test]
    fn verify_fails_when_the_signature_is_not_der() {
        let _lock = with_test_token();
        generate_key_pair("example-verify-garbage");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let result = backend.verify(
            "example-verify-garbage",
            Algorithm::EcdsaP256Sha256,
            b"hello world",
            b"not a signature",
        );

        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignatureEncoding(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn verify_fails_for_an_unknown_label() {
        let _lock = with_test_token();
        generate_key_pair("example-verify-known");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let der = backend
            .sign(
                "example-verify-known",
                Algorithm::EcdsaP256Sha256,
                b"hello world",
            )
            .unwrap();

        let result = backend.verify(
            "no-such-key",
            Algorithm::EcdsaP256Sha256,
            b"hello world",
            &der,
        );

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn verify_fails_for_an_aes_key_label() {
        let _lock = with_test_token();
        generate_key_pair("example-verify-sig");
        generate_aes_key("example-verify-aes");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let der = backend
            .sign(
                "example-verify-sig",
                Algorithm::EcdsaP256Sha256,
                b"hello world",
            )
            .unwrap();

        let result = backend.verify(
            "example-verify-aes",
            Algorithm::EcdsaP256Sha256,
            b"hello world",
            &der,
        );

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(_))),
            "unexpected: {result:?}"
        );
    }

    /// Generate a non-extractable AES-256 key inside the test token.
    fn generate_aes_key(label: &str) {
        let config = Config::for_test(TOKEN_LABEL, PIN);
        let pkcs11 = load_pkcs11(&config).expect("unable to load the module");
        let slot = find_token_by_label(pkcs11, TOKEN_LABEL).expect("token not found");
        let session = pkcs11
            .open_rw_session(slot)
            .expect("unable to open a session");
        let _ = session.login(UserType::User, Some(&AuthPin::new(PIN.into())));

        let template = [
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::ValueLen(32.into()),
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ];
        session
            .generate_key(&Mechanism::AesKeyGen, &template)
            .expect("unable to generate the AES key");
    }

    #[test]
    fn encrypt_output_decrypts_to_the_plaintext() {
        let _lock = with_test_token();
        generate_aes_key("example-aes-round-trip");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let plaintext = b"hello world";

        let encrypted = backend
            .encrypt("example-aes-round-trip", plaintext)
            .expect("expected ciphertext");

        // 12 bytes of IV, the ciphertext (same length as the plaintext), 16 bytes of tag.
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);
        let decrypted = backend
            .decrypt("example-aes-round-trip", &encrypted)
            .expect("expected to decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_uses_a_new_iv_every_time() {
        let _lock = with_test_token();
        generate_aes_key("example-aes-iv");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let first = backend.encrypt("example-aes-iv", b"same").unwrap();
        let second = backend.encrypt("example-aes-iv", b"same").unwrap();

        assert_ne!(first[..12], second[..12], "the IV repeated");
        assert_ne!(first, second);
    }

    #[test]
    fn encrypt_output_fails_to_decrypt_after_a_change() {
        let _lock = with_test_token();
        generate_aes_key("example-aes-tamper");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let mut encrypted = backend
            .encrypt("example-aes-tamper", b"hello world")
            .unwrap();

        // Change one bit of the ciphertext.
        encrypted[12] ^= 0x01;

        let result = backend.decrypt("example-aes-tamper", &encrypted);

        assert!(
            matches!(result, Err(HsmBackendError::Decrypt(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn decrypt_fails_with_another_key() {
        let _lock = with_test_token();
        generate_aes_key("example-aes-key-a");
        generate_aes_key("example-aes-key-b");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let encrypted = backend
            .encrypt("example-aes-key-a", b"hello world")
            .unwrap();

        let result = backend.decrypt("example-aes-key-b", &encrypted);

        assert!(
            matches!(result, Err(HsmBackendError::Decrypt(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn decrypt_fails_when_the_data_is_too_short() {
        let _lock = with_test_token();
        generate_aes_key("example-aes-short");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        // One byte less than an IV and a tag.
        let result = backend.decrypt("example-aes-short", &[0u8; 27]);

        assert!(
            matches!(result, Err(HsmBackendError::InvalidCiphertext)),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn decrypt_fails_for_a_key_that_does_not_exist() {
        let _lock = with_test_token();
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let result = backend.decrypt("no-such-key", &[0u8; 28]);

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(ref id)) if id == "no-such-key"),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn encrypt_accepts_an_empty_plaintext() {
        let _lock = with_test_token();
        generate_aes_key("example-aes-empty");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let encrypted = backend.encrypt("example-aes-empty", b"").unwrap();

        assert_eq!(encrypted.len(), 12 + 16);
        let decrypted = backend.decrypt("example-aes-empty", &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_fails_for_a_key_that_does_not_exist() {
        let _lock = with_test_token();
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let result = backend.encrypt("no-such-key", b"hello world");

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(ref id)) if id == "no-such-key"),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn encrypt_does_not_use_an_ec_key() {
        let _lock = with_test_token();
        generate_key_pair("example-not-aes");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let result = backend.encrypt("example-not-aes", b"hello world");

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn wrap_returns_the_target_key_in_a_form_the_hsm_can_unwrap() {
        let _lock = with_test_token();
        generate_aes_key("example-wrap-kek");
        generate_exportable_key_pair("example-wrap-target");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let payload = b"hello world";

        let wrapped = backend
            .wrap("example-wrap-kek", "example-wrap-target")
            .expect("expected a wrapped key");

        // Unwrap the blob into a temporary key. If it holds the original key,
        // a signature from it verifies with the public key of the original.
        let session = backend.session();
        let kek = find_aes_key(&session, "example-wrap-kek").unwrap();
        let template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Label(b"example-wrap-unwrapped".to_vec()),
            Attribute::Token(false),
            Attribute::Sign(true),
        ];
        let unwrapped = session
            .unwrap_key(&Mechanism::AesKeyWrapPad, kek, &wrapped, &template)
            .expect("the HSM could not unwrap the key");
        let raw = session
            .sign(&Mechanism::EcdsaSha256, unwrapped, payload)
            .expect("unable to sign with the unwrapped key");
        let signature = Signature::from_slice(&raw).unwrap();
        public_key("example-wrap-target")
            .verify(payload, &signature)
            .expect("the unwrapped key is not the original key");
    }

    #[test]
    fn wrap_fails_for_a_key_that_is_not_extractable() {
        let _lock = with_test_token();
        generate_aes_key("example-wrap-kek-fixed");
        generate_key_pair("example-wrap-fixed");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let result = backend.wrap("example-wrap-kek-fixed", "example-wrap-fixed");

        assert!(
            matches!(result, Err(HsmBackendError::Wrap(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn wrap_fails_for_an_unknown_wrapping_key() {
        let _lock = with_test_token();
        generate_exportable_key_pair("example-wrap-target-2");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let result = backend.wrap("no-such-key", "example-wrap-target-2");

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(ref id)) if id == "no-such-key"),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn wrap_fails_for_an_unknown_target_key() {
        let _lock = with_test_token();
        generate_aes_key("example-wrap-kek-3");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let result = backend.wrap("example-wrap-kek-3", "no-such-key");

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(ref id)) if id == "no-such-key"),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn wrap_does_not_accept_an_aes_key_as_the_target() {
        let _lock = with_test_token();
        generate_aes_key("example-wrap-kek-4");
        generate_aes_key("example-wrap-aes-target");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let result = backend.wrap("example-wrap-kek-4", "example-wrap-aes-target");

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn sign_fails_for_a_key_that_does_not_exist() {
        let _lock = with_test_token();
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let result = backend.sign("no-such-key", Algorithm::EcdsaP256Sha256, b"hello world");

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(ref id)) if id == "no-such-key"),
            "unexpected: {result:?}"
        );
    }
    // The backend with a session pool.

    #[test]
    fn pool_connects_to_the_token() {
        let _lock = with_test_token();
        let config = Config::for_test(TOKEN_LABEL, PIN);

        let result = CryptokiBackendWithSessionPool::try_new(&config, 3);

        let backend = result.expect("expected to connect");
        assert_eq!(backend.pool.state().connections, 3);
    }

    #[test]
    fn pool_fails_with_a_wrong_pin() {
        let _lock = with_test_token();
        let config = Config::for_test(TOKEN_LABEL, "wrong-pin");

        let error =
            CryptokiBackendWithSessionPool::try_new(&config, 3).expect_err("expected an error");

        // The login happens before the pool, so the error is a login error.
        let message = error.to_string();
        assert!(
            matches!(error, HsmBackendError::Login(_)),
            "unexpected: {message}"
        );
        assert!(!message.contains("wrong-pin"), "the error shows the PIN");
    }

    #[test]
    fn pool_fails_when_no_token_has_the_label() {
        let _lock = with_test_token();
        let config = Config::for_test("no-such-token", PIN);

        let error =
            CryptokiBackendWithSessionPool::try_new(&config, 3).expect_err("expected an error");

        assert!(
            matches!(error, HsmBackendError::TokenNotFound(_)),
            "unexpected: {error}"
        );
    }

    #[test]
    fn every_session_of_the_pool_can_sign() {
        let _lock = with_test_token();
        generate_key_pair("example-pool-sessions");
        let backend =
            CryptokiBackendWithSessionPool::try_new(&Config::for_test(TOKEN_LABEL, PIN), 3)
                .unwrap();
        let payload = b"hello world";

        // Hold all three sessions at the same time, so each one is used.
        let sessions: Vec<_> = (0..3)
            .map(|_| backend.session().expect("expected a session"))
            .collect();
        for session in &sessions {
            let der = sign_with(
                session,
                "example-pool-sessions",
                Algorithm::EcdsaP256Sha256,
                payload,
            )
            .expect("a session of the pool cannot sign");
            let signature = Signature::from_der(&der).expect("the signature is not valid DER");
            public_key("example-pool-sessions")
                .verify(payload, &signature)
                .expect("the signature does not verify");
        }
    }

    #[test]
    fn sign_makes_a_span_for_the_checkout_and_one_for_the_hsm_call() {
        use opentelemetry::trace::TraceContextExt;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        use crate::telemetry::testing;

        let _lock = with_test_token();
        testing::exporter();
        generate_key_pair("example-span-key");
        let backend =
            CryptokiBackendWithSessionPool::try_new(&Config::for_test(TOKEN_LABEL, PIN), 1)
                .unwrap();

        // The test span is the parent. It has a unique name, because the
        // exporter is shared with other tests.
        let root = tracing::info_span!("backend_spans_test_root");
        let root_id = root.in_scope(|| {
            backend
                .sign("example-span-key", Algorithm::EcdsaP256Sha256, b"hello")
                .expect("expected a signature");
            tracing::Span::current()
                .context()
                .span()
                .span_context()
                .span_id()
        });
        drop(root);

        let spans = testing::finished_spans();
        let children: Vec<_> = spans
            .iter()
            .filter(|span| span.parent_span_id == root_id)
            .collect();
        let checkout = children
            .iter()
            .find(|span| span.name == "pool_checkout")
            .expect("no pool_checkout span");
        let sign = children
            .iter()
            .find(|span| span.name == "hsm_sign")
            .expect("no hsm_sign span");
        assert_eq!(
            testing::attribute(sign, "algorithm").unwrap(),
            "ECDSA_P256_SHA256"
        );
        // The wait for the session is over before the HSM call starts.
        assert!(checkout.end_time <= sign.start_time);
    }

    #[test]
    fn the_pool_reports_its_size_and_the_sessions_in_use() {
        use crate::metrics::testing::TestMetrics;

        let _lock = with_test_token();
        generate_key_pair("example-gauge-key");
        let test = TestMetrics::new();
        let backend =
            CryptokiBackendWithSessionPool::try_new(&Config::for_test(TOKEN_LABEL, PIN), 3)
                .unwrap()
                .with_metrics(&test.metrics);
        assert_eq!(test.value("hsm_signing.pool.size"), Some(3));
        assert_eq!(test.value("hsm_signing.pool.sessions_in_use"), None);

        let first = backend.session().unwrap();
        let second = backend.session().unwrap();
        assert_eq!(test.value("hsm_signing.pool.sessions_in_use"), Some(2));
        drop(first);
        assert_eq!(test.value("hsm_signing.pool.sessions_in_use"), Some(1));
        drop(second);
        assert_eq!(test.value("hsm_signing.pool.sessions_in_use"), Some(0));

        // `sign` takes a session and gives it back, with success and with an error.
        backend
            .sign("example-gauge-key", Algorithm::EcdsaP256Sha256, b"hello")
            .expect("expected a signature");
        backend
            .sign("no-such-key", Algorithm::EcdsaP256Sha256, b"hello")
            .expect_err("expected an error");
        assert_eq!(test.value("hsm_signing.pool.sessions_in_use"), Some(0));
    }

    #[test]
    fn a_failed_checkout_is_not_counted_as_a_session_in_use() {
        use crate::metrics::testing::TestMetrics;

        let _lock = with_test_token();
        let test = TestMetrics::new();
        // The wait for a session ends after the pool connection timeout.
        let backend =
            CryptokiBackendWithSessionPool::try_new(&Config::for_test(TOKEN_LABEL, PIN), 1)
                .unwrap()
                .with_metrics(&test.metrics);

        let _only = backend.session().unwrap();
        assert!(backend.session().is_err());

        assert_eq!(test.value("hsm_signing.pool.sessions_in_use"), Some(1));
    }

    #[test]
    fn pool_has_no_more_sessions_than_its_size() {
        let _lock = with_test_token();
        let backend =
            CryptokiBackendWithSessionPool::try_new(&Config::for_test(TOKEN_LABEL, PIN), 2)
                .unwrap();

        let _first = backend.session().unwrap();
        let _second = backend.session().unwrap();

        let third = backend.pool.get_timeout(Duration::from_millis(100));
        assert!(third.is_err(), "the pool gave out a third session");
    }

    #[test]
    fn a_session_goes_back_to_the_pool() {
        let _lock = with_test_token();
        let backend =
            CryptokiBackendWithSessionPool::try_new(&Config::for_test(TOKEN_LABEL, PIN), 1)
                .unwrap();

        drop(backend.session().unwrap());

        let again = backend.pool.get_timeout(Duration::from_millis(100));
        assert!(again.is_ok(), "the session did not come back");
    }

    #[test]
    fn pool_signs_from_many_threads_at_once() {
        let _lock = with_test_token();
        generate_key_pair("example-pool-threads");
        let backend =
            CryptokiBackendWithSessionPool::try_new(&Config::for_test(TOKEN_LABEL, PIN), 3)
                .unwrap();
        let verifying_key = public_key("example-pool-threads");

        std::thread::scope(|scope| {
            for thread in 0..8 {
                let backend = &backend;
                let verifying_key = &verifying_key;
                scope.spawn(move || {
                    for call in 0..5 {
                        let payload = format!("payload {thread}-{call}");
                        let der = backend
                            .sign(
                                "example-pool-threads",
                                Algorithm::EcdsaP256Sha256,
                                payload.as_bytes(),
                            )
                            .expect("expected a signature");
                        let signature =
                            Signature::from_der(&der).expect("the signature is not valid DER");
                        verifying_key
                            .verify(payload.as_bytes(), &signature)
                            .expect("the signature does not verify");
                    }
                });
            }
        });
    }

    #[test]
    fn pool_signs_and_verifies_with_one_session() {
        let _lock = with_test_token();
        generate_key_pair("example-pool-one");
        let backend =
            CryptokiBackendWithSessionPool::try_new(&Config::for_test(TOKEN_LABEL, PIN), 1)
                .unwrap();

        for _ in 0..3 {
            let der = backend
                .sign(
                    "example-pool-one",
                    Algorithm::EcdsaP256Sha256,
                    b"hello world",
                )
                .unwrap();
            let result = backend.verify(
                "example-pool-one",
                Algorithm::EcdsaP256Sha256,
                b"hello world",
                &der,
            );
            assert!(matches!(result, Ok(true)), "unexpected: {result:?}");
        }
    }

    #[test]
    fn pool_sign_fails_for_a_key_that_does_not_exist() {
        let _lock = with_test_token();
        let backend =
            CryptokiBackendWithSessionPool::try_new(&Config::for_test(TOKEN_LABEL, PIN), 2)
                .unwrap();

        let result = backend.sign("no-such-key", Algorithm::EcdsaP256Sha256, b"hello world");

        assert!(
            matches!(result, Err(HsmBackendError::KeyNotFound(ref id)) if id == "no-such-key"),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn every_ecdsa_algorithm_signs_and_verifies() {
        let _lock = with_test_token();
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let cases = [
            (Algorithm::EcdsaP256Sha256, "example-algo-p256"),
            (Algorithm::EcdsaP384Sha384, "example-algo-p384"),
            (Algorithm::EcdsaP521Sha512, "example-algo-p521"),
        ];
        for (algorithm, label) in cases {
            generate_ec_key_pair_on(label, algorithm, false);

            let der = backend.sign(label, algorithm, b"hello world").unwrap();

            let raw = der_to_raw_signature(&der, algorithm.ecdsa_component_len().unwrap())
                .unwrap_or_else(|e| panic!("{algorithm:?}: {e}"));
            assert_eq!(raw.len(), 2 * algorithm.ecdsa_component_len().unwrap());
            let valid = backend.verify(label, algorithm, b"hello world", &der);
            assert!(matches!(valid, Ok(true)), "{algorithm:?}: {valid:?}");
            let other = backend.verify(label, algorithm, b"hello World", &der);
            assert!(matches!(other, Ok(false)), "{algorithm:?}: {other:?}");
        }
    }

    #[test]
    fn rsa_signs_and_verifies() {
        let _lock = with_test_token();
        generate_rsa_key_pair("example-algo-rsa");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        let signature = backend
            .sign(
                "example-algo-rsa",
                Algorithm::RsaPkcs1Sha256,
                b"hello world",
            )
            .expect("expected a signature");

        // RSA 2048: the signature has the length of the modulus.
        assert_eq!(signature.len(), 256);
        let valid = backend.verify(
            "example-algo-rsa",
            Algorithm::RsaPkcs1Sha256,
            b"hello world",
            &signature,
        );
        assert!(matches!(valid, Ok(true)), "unexpected: {valid:?}");
        let other = backend.verify(
            "example-algo-rsa",
            Algorithm::RsaPkcs1Sha256,
            b"hello World",
            &signature,
        );
        assert!(matches!(other, Ok(false)), "unexpected: {other:?}");
    }

    #[test]
    fn sign_reports_key_not_found_when_the_key_does_not_fit_the_algorithm() {
        let _lock = with_test_token();
        generate_ec_key_pair_on("example-mismatch-p256", Algorithm::EcdsaP256Sha256, false);
        generate_ec_key_pair_on("example-mismatch-p384", Algorithm::EcdsaP384Sha384, false);
        generate_rsa_key_pair("example-mismatch-rsa");
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();
        let cases = [
            ("example-mismatch-p256", Algorithm::RsaPkcs1Sha256),
            ("example-mismatch-rsa", Algorithm::EcdsaP256Sha256),
            // The key type is right, but the curve is wrong, in both directions.
            ("example-mismatch-p256", Algorithm::EcdsaP384Sha384),
            ("example-mismatch-p384", Algorithm::EcdsaP256Sha256),
            ("example-mismatch-p384", Algorithm::EcdsaP521Sha512),
        ];
        for (label, algorithm) in cases {
            let result = backend.sign(label, algorithm, b"hello world");
            assert!(
                matches!(result, Err(HsmBackendError::KeyNotFound(_))),
                "{label} with {algorithm:?}: unexpected: {result:?}"
            );
        }
    }

    #[test]
    fn sign_still_reports_an_unknown_label_for_every_algorithm() {
        let _lock = with_test_token();
        let backend = CryptokiBackend::try_new(&Config::for_test(TOKEN_LABEL, PIN)).unwrap();

        for algorithm in [
            Algorithm::EcdsaP256Sha256,
            Algorithm::EcdsaP384Sha384,
            Algorithm::EcdsaP521Sha512,
            Algorithm::RsaPkcs1Sha256,
        ] {
            let result = backend.sign("no-such-key-anywhere", algorithm, b"hello world");
            assert!(
                matches!(result, Err(HsmBackendError::KeyNotFound(_))),
                "{algorithm:?}: unexpected: {result:?}"
            );
        }
    }
}
