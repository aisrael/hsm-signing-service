//! Black-box tests for the `encrypt` and `decrypt` commands.
//!
//! The tests run the compiled program as a child process. They use no types
//! or functions from the service code.
//!
//! The tests use the real environment: the token, the keys and the settings
//! come from the environment variables of the developer (see `.envrc.example`).
//! Run `setup.sh` once before you run the tests, so that the token and the AES
//! key exist.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::assert_failed;
use common::assert_succeeded;
use common::env_var;
use common::run;

/// The label of the AES key. `setup.sh` creates the key with this label.
fn key_id() -> String {
    env_var("AES_KEY_LABEL")
}

/// Encrypt with the AES key. The test fails if the command fails.
fn encrypt(plaintext: &[u8]) -> String {
    let output = run(&["encrypt", "--key-id", &key_id()], plaintext);
    assert_succeeded(&output);
    String::from_utf8(output.stdout).expect("the output is not UTF-8")
}

/// Decrypt with the AES key. The test fails if the command fails.
fn decrypt(encrypted: &str) -> Vec<u8> {
    let output = run(&["decrypt", "--key-id", &key_id()], encrypted.as_bytes());
    assert_succeeded(&output);
    output.stdout
}

#[test]
fn decrypt_returns_the_text_that_encrypt_received() {
    let encrypted = encrypt(b"hello world");

    assert_eq!(decrypt(&encrypted), b"hello world");
}

#[test]
fn the_round_trip_keeps_every_byte_value() {
    // All 256 byte values, repeated. This includes NUL and bytes that are not UTF-8.
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(4096).collect();

    let encrypted = encrypt(&plaintext);

    assert_eq!(decrypt(&encrypted), plaintext);
}

#[test]
fn the_round_trip_keeps_a_trailing_newline_and_empty_input() {
    assert_eq!(decrypt(&encrypt(b"hello\n")), b"hello\n");
    assert_eq!(decrypt(&encrypt(b"")), b"");
}

#[test]
fn encrypt_prints_base64_of_iv_ciphertext_and_tag() {
    let plaintext = b"hello world";

    let encrypted = encrypt(plaintext);

    assert!(encrypted.ends_with('\n'), "no newline at the end");
    let bytes = BASE64
        .decode(encrypted.trim_end())
        .expect("the output is not valid base64");
    // 12 bytes of IV, the ciphertext (same length as the plaintext), 16 bytes of tag.
    assert_eq!(bytes.len(), 12 + plaintext.len() + 16);
    assert!(
        !bytes.windows(plaintext.len()).any(|w| w == plaintext),
        "the plaintext is visible in the output"
    );
}

#[test]
fn encrypt_gives_a_different_result_each_time() {
    let first = encrypt(b"same input");
    let second = encrypt(b"same input");

    assert_ne!(first, second);
    assert_eq!(decrypt(&first), decrypt(&second));
}

#[test]
fn decrypt_accepts_spaces_around_the_input() {
    let encrypted = encrypt(b"hello world");

    assert_eq!(
        decrypt(&format!("\n  {}\n\n", encrypted.trim_end())),
        b"hello world"
    );
}

#[test]
fn decrypt_fails_when_the_data_changed() {
    let encrypted = encrypt(b"hello world");
    let mut bytes = BASE64.decode(encrypted.trim_end()).unwrap();
    // Change one bit of the ciphertext (after the 12 bytes of IV).
    bytes[12] ^= 0x01;

    let output = run(
        &["decrypt", "--key-id", &key_id()],
        BASE64.encode(bytes).as_bytes(),
    );

    assert_failed(&output);
}

#[test]
fn decrypt_fails_when_the_input_is_not_base64() {
    let output = run(&["decrypt", "--key-id", &key_id()], b"not base64!");

    assert_failed(&output);
}

#[test]
fn decrypt_fails_when_the_input_is_too_short() {
    // Valid base64 of 2 bytes. An IV and a tag need 28 bytes.
    let output = run(&["decrypt", "--key-id", &key_id()], b"aGk=");

    assert_failed(&output);
}

#[test]
fn both_commands_fail_for_an_unknown_key() {
    let encrypted = encrypt(b"hello world");

    assert_failed(&run(&["encrypt", "--key-id", "no-such-key"], b"hello"));
    assert_failed(&run(
        &["decrypt", "--key-id", "no-such-key"],
        encrypted.as_bytes(),
    ));
}

#[test]
fn encrypt_fails_for_the_ec_key() {
    // The token label is also the label of the EC key pair. It is not an AES key.
    let ec_key = env_var("HSM_TOKEN_LABEL");

    assert_failed(&run(&["encrypt", "--key-id", &ec_key], b"hello"));
}

#[test]
fn both_commands_need_a_key_id() {
    for command in ["encrypt", "decrypt"] {
        let output = run(&[command], b"");

        // Clap exits with code 2 for a usage error.
        assert_eq!(output.status.code(), Some(2), "{command}: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--key-id"));
    }
}
