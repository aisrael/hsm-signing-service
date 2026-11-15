//! Black-box tests for `POST /v1/sign`.
//!
//! The tests start the compiled service as a child process and talk to it
//! over HTTP only. They use no types or functions from the service code.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::Service;
use p256::ecdsa::Signature;
use serde_json::Value;
use serde_json::json;

#[test]
fn post_sign_returns_a_der_signature() {
    let service = Service::start();

    let request = json!({
        "key_id": "example",
        "algorithm": "ECDSA_P256_SHA256",
        "payload": "aGVsbG8gd29ybGQ=", // "hello world"
    });

    let mut response = ureq::post(service.url("/v1/sign"))
        .send_json(&request)
        .expect("the request failed");

    assert_eq!(response.status(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("the response has no content-type header")
        .to_str()
        .unwrap();
    assert!(
        content_type.starts_with("application/json"),
        "unexpected content-type: {content_type}"
    );

    let body: Value = response
        .body_mut()
        .read_json()
        .expect("the response body is not valid JSON");

    assert_eq!(body["key_id"], "example");
    assert_eq!(body["algorithm"], "ECDSA_P256_SHA256");
    // The signature is base64 of a DER-encoded ECDSA signature.
    let der = BASE64
        .decode(
            body["signature"]
                .as_str()
                .expect("signature is not a string"),
        )
        .expect("the signature is not valid base64");
    Signature::from_der(&der).expect("the signature is not valid DER");
    // The HSM accepts the signature for the same payload and the public key.
    let signature = body["signature"].as_str().unwrap();
    let output = common::run(
        &["verify", "--key-id", "example", "--signature", signature],
        b"hello world",
    );
    common::assert_succeeded(&output);
    assert!(
        body["duration_ms"].is_u64(),
        "duration_ms is not a non-negative integer: {}",
        body["duration_ms"]
    );
}
