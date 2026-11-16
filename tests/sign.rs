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

/// Send `POST /v1/sign` and return the status and the JSON body. A 4xx or 5xx
/// answer is not an error here.
fn post_sign(service: &Service, key_id: &str, algorithm: &str) -> (u16, Value) {
    let request = json!({
        "key_id": key_id,
        "algorithm": algorithm,
        "payload": "aGVsbG8gd29ybGQ=", // "hello world"
    });
    let mut response = ureq::post(service.url("/v1/sign"))
        .config()
        .http_status_as_error(false)
        .build()
        .send_json(&request)
        .expect("the request failed");
    let status = response.status().as_u16();
    let body: Value = response
        .body_mut()
        .read_json()
        .expect("the response body is not valid JSON");
    (status, body)
}

#[test]
fn post_sign_signs_with_every_algorithm() {
    let service = Service::start();
    // The DER signature of an ECDSA algorithm has at most this many bytes
    // (the sequence header, and two integers with a leading zero). RSA 2048
    // gives 256 bytes.
    let cases = [
        ("P384_KEY_LABEL", "ECDSA_P384_SHA384", 104),
        ("P521_KEY_LABEL", "ECDSA_P521_SHA512", 139),
        ("RSA_KEY_LABEL", "RSA_PKCS1_SHA256", 256),
    ];
    for (label_variable, algorithm, max_len) in cases {
        let key_id = common::env_var(label_variable);

        let (status, body) = post_sign(&service, &key_id, algorithm);

        assert_eq!(status, 200, "{algorithm}: {body}");
        assert_eq!(body["algorithm"], algorithm);
        let signature = BASE64
            .decode(body["signature"].as_str().expect("no signature"))
            .expect("the signature is not valid base64");
        assert!(
            signature.len() > 8 && signature.len() <= max_len,
            "{algorithm}: unexpected signature length {}",
            signature.len()
        );
        if algorithm == "RSA_PKCS1_SHA256" {
            assert_eq!(signature.len(), 256);
        } else {
            assert_eq!(signature[0], 0x30, "{algorithm}: not a DER sequence");
        }
    }
}

#[test]
fn post_sign_answers_422_when_the_key_does_not_fit_the_algorithm() {
    let service = Service::start();
    let rsa_key = common::env_var("RSA_KEY_LABEL");
    let p384_key = common::env_var("P384_KEY_LABEL");

    for (key_id, algorithm) in [
        ("example", "RSA_PKCS1_SHA256"),
        (rsa_key.as_str(), "ECDSA_P256_SHA256"),
        // The key type is right, but the curve is wrong.
        ("example", "ECDSA_P384_SHA384"),
        (p384_key.as_str(), "ECDSA_P256_SHA256"),
    ] {
        let (status, body) = post_sign(&service, key_id, algorithm);

        assert_eq!(status, 422, "{key_id} with {algorithm}: {body}");
        assert_eq!(body["error"], "Key not found");
    }
}
