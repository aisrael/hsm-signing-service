//! Black-box tests for the `verify` command.
//!
//! The tests start the compiled service, sign a payload over HTTP, and run the
//! compiled program with `verify`. They use no types or functions from the
//! service code. They need the token and the key `example` (see `setup.sh`).

mod common;

use common::Service;
use common::assert_failed;
use common::assert_succeeded;
use common::run;
use serde_json::Value;
use serde_json::json;

const PAYLOAD: &[u8] = b"hello world";
const PAYLOAD_BASE64: &str = "aGVsbG8gd29ybGQ="; // "hello world"

/// Sign `PAYLOAD` with the key `example` through the API. Return the
/// `signature` field of the response.
fn sign_through_the_api() -> String {
    let service = Service::start();
    let request = json!({
        "key_id": "example",
        "algorithm": "ECDSA_P256_SHA256",
        "payload": PAYLOAD_BASE64,
    });
    let body: Value = ureq::post(service.url("/v1/sign"))
        .send_json(&request)
        .expect("the request failed")
        .body_mut()
        .read_json()
        .expect("the response body is not valid JSON");
    body["signature"]
        .as_str()
        .expect("signature is not a string")
        .to_string()
}

#[test]
fn verify_accepts_a_signature_from_the_api() {
    let signature = sign_through_the_api();

    let output = run(
        &["verify", "--key-id", "example", "--signature", &signature],
        PAYLOAD,
    );

    assert_succeeded(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "valid");
}

#[test]
fn verify_rejects_another_payload() {
    let signature = sign_through_the_api();

    let output = run(
        &["verify", "--key-id", "example", "--signature", &signature],
        b"hello World",
    );

    let message = assert_failed(&output);
    assert!(
        message.contains("the signature is not valid"),
        "unexpected: {message}"
    );
}

#[test]
fn verify_rejects_a_signature_that_is_not_base64() {
    let output = run(
        &[
            "verify",
            "--key-id",
            "example",
            "--signature",
            "not base64!",
        ],
        PAYLOAD,
    );

    let message = assert_failed(&output);
    assert!(message.contains("base64"), "unexpected: {message}");
}

#[test]
fn verify_rejects_a_signature_that_is_not_der() {
    // Valid base64, but the bytes are not a DER signature.
    let output = run(
        &["verify", "--key-id", "example", "--signature", "aGVsbG8="],
        PAYLOAD,
    );

    let message = assert_failed(&output);
    assert!(message.contains("DER"), "unexpected: {message}");
}

#[test]
fn verify_fails_for_an_unknown_key() {
    let signature = sign_through_the_api();

    let output = run(
        &[
            "verify",
            "--key-id",
            "no-such-key",
            "--signature",
            &signature,
        ],
        PAYLOAD,
    );

    let message = assert_failed(&output);
    assert!(message.contains("no-such-key"), "unexpected: {message}");
}

#[test]
fn verify_needs_both_arguments() {
    for args in [
        &["verify", "--signature", "aGVsbG8="][..],
        &["verify", "--key-id", "example"][..],
    ] {
        let output = run(args, PAYLOAD);

        assert_eq!(output.status.code(), Some(2), "unexpected: {output:?}");
        assert!(output.stdout.is_empty(), "STDOUT is not empty");
    }
}
