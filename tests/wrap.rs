//! Black-box tests for the `wrap` command.
//!
//! The tests run the compiled program as a child process. They use no types
//! or functions from the service code.
//!
//! The tests use the real environment: the token, the keys and the settings
//! come from the environment variables of the developer (see `.envrc.example`).
//! Run `setup.sh` once before you run the tests, so that the token and the
//! keys exist.

mod common;

use std::process::Output;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::assert_failed;
use common::assert_succeeded;
use common::env_var;
use common::run;

/// The AES key that wraps the other key.
fn aes_key() -> String {
    env_var("AES_KEY_LABEL")
}

/// The EC private key that `setup.sh` makes extractable, so it can be wrapped.
fn exportable_key() -> String {
    env_var("EXPORTABLE_KEY_LABEL")
}

/// Run `wrap` with the given arguments.
fn run_wrap(args: &[&str]) -> Output {
    run(&[&["wrap"][..], args].concat(), b"")
}

/// Wrap the exportable key with the AES key. The test fails if the command fails.
fn wrap_exportable_key() -> String {
    let output = run_wrap(&["--key-id", &aes_key(), "--target-key-id", &exportable_key()]);
    assert_succeeded(&output);
    assert!(
        output.stderr.is_empty(),
        "unexpected STDERR: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("the output is not UTF-8")
}

#[test]
fn wrap_prints_the_wrapped_key_as_base64() {
    let output = wrap_exportable_key();

    assert!(output.ends_with('\n'), "no newline at the end");
    assert_eq!(output.trim_end().lines().count(), 1, "more than one line");
    let bytes = BASE64
        .decode(output.trim_end())
        .expect("the output is not valid base64");
    // AES key wrap output has a multiple of 8 bytes. It is longer than a
    // 32-byte key, because it has an 8-byte header and the encoded key.
    assert_eq!(bytes.len() % 8, 0, "unexpected length: {}", bytes.len());
    assert!(bytes.len() > 40, "unexpected length: {}", bytes.len());
}

#[test]
fn wrap_gives_the_same_result_each_time() {
    // AES key wrap has no IV, so the same key and target give the same output.
    assert_eq!(wrap_exportable_key(), wrap_exportable_key());
}

#[test]
fn wrap_fails_for_a_key_that_is_not_extractable() {
    // The token label is also the label of the signing key. It is not extractable.
    let output = run_wrap(&[
        "--key-id",
        &aes_key(),
        "--target-key-id",
        &env_var("HSM_TOKEN_LABEL"),
    ]);

    let stderr = assert_failed(&output);

    assert!(
        stderr.contains("extractable"),
        "the message does not say why: {stderr}"
    );
}

#[test]
fn wrap_fails_when_the_target_is_not_an_ec_private_key() {
    // The AES key is a secret key, so it is not a valid target.
    let output = run_wrap(&["--key-id", &aes_key(), "--target-key-id", &aes_key()]);

    assert_failed(&output);
}

#[test]
fn wrap_fails_when_the_wrapping_key_is_not_an_aes_key() {
    // The exportable key is an EC key, so it cannot wrap another key.
    let output = run_wrap(&[
        "--key-id",
        &exportable_key(),
        "--target-key-id",
        &exportable_key(),
    ]);

    assert_failed(&output);
}

#[test]
fn wrap_fails_for_an_unknown_target_key() {
    let output = run_wrap(&["--key-id", &aes_key(), "--target-key-id", "no-such-key"]);

    let stderr = assert_failed(&output);

    assert!(stderr.contains("no-such-key"), "unexpected: {stderr}");
}

#[test]
fn wrap_fails_for_an_unknown_wrapping_key() {
    let output = run_wrap(&[
        "--key-id",
        "no-such-key",
        "--target-key-id",
        &exportable_key(),
    ]);

    let stderr = assert_failed(&output);

    assert!(stderr.contains("no-such-key"), "unexpected: {stderr}");
}

#[test]
fn wrap_needs_both_key_options() {
    // Clap exits with code 2 for a usage error.
    for (args, missing) in [
        (vec!["--key-id", "a"], "--target-key-id"),
        (vec!["--target-key-id", "b"], "--key-id"),
        (vec![], "--key-id"),
    ] {
        let output = run_wrap(&args);

        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(missing),
            "{args:?}: the message does not name {missing}"
        );
    }
}
