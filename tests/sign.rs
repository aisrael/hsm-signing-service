//! Black-box tests for `POST /v1/sign`.
//!
//! The tests start the compiled service as a child process and talk to it
//! over HTTP only. They use no types or functions from the service code.

use std::net::TcpListener;
use std::net::TcpStream;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;

use serde_json::Value;
use serde_json::json;

const ADDR: &str = "127.0.0.1";

/// Ask the operating system for a port that no process uses now.
fn free_port() -> u16 {
    TcpListener::bind((ADDR, 0))
        .expect("failed to find a free port")
        .local_addr()
        .unwrap()
        .port()
}

/// A running service. The process stops when this value is dropped.
struct Service {
    child: Child,
    addr: String,
}

impl Service {
    fn start() -> Self {
        let port = free_port();
        let addr = format!("{ADDR}:{port}");

        // Set both variables, so values from the developer's shell (for
        // example, from `.envrc`) cannot change the address.
        let child = Command::new(env!("CARGO_BIN_EXE_hsm-signing-service"))
            .env("HSM_SIGNING_SERVICE_HOST", ADDR)
            .env("HSM_SIGNING_SERVICE_PORT", port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start the service");
        let service = Service { child, addr };

        // Wait until the service accepts connections.
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(&service.addr).is_err() {
            assert!(
                Instant::now() < deadline,
                "the service did not start within 10 seconds"
            );
            sleep(Duration::from_millis(50));
        }
        service
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn post_sign_echoes_the_payload() {
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
    // For now, the service echoes the payload as the signature.
    assert_eq!(body["signature"], "aGVsbG8gd29ybGQ=");
    assert!(
        body["duration_ms"].is_u64(),
        "duration_ms is not a non-negative integer: {}",
        body["duration_ms"]
    );
}
