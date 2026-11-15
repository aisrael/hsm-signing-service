//! Helpers shared by the integration tests.
//!
//! The tests run the compiled program as a child process. They use the real
//! environment: the token, the keys and the settings come from the environment
//! variables of the developer (see `.envrc.example`). Run `setup.sh` once
//! before you run the tests, so that the token and the keys exist.

// Each test file is a separate crate and uses only some of these helpers.
#![allow(dead_code)]

use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;

const ADDR: &str = "127.0.0.1";

/// Read a required environment variable.
pub fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} is not set. Set it in your environment (or copy `.envrc.example` \
             to `.envrc` and use `direnv allow`), then run `sh ./setup.sh`"
        )
    })
}

/// Run the program with the given arguments. `stdin` is the input. The program
/// inherits the environment of the test, which holds the token and PIN.
pub fn run(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hsm-signing-service"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start the program");
    // The program reads all of STDIN before it writes, so this cannot block.
    // It may exit before it reads (for example, on a usage error). Then the
    // write fails, and the test checks the exit status instead.
    let _ = child.stdin.take().expect("no STDIN").write_all(stdin);
    child.wait_with_output().expect("failed to wait")
}

/// Check that the command succeeded.
pub fn assert_succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "the command failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Check that the command failed with exit code 1, wrote nothing to STDOUT
/// and gave an error message that does not show the PIN. Return the message.
pub fn assert_failed(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(1), "unexpected: {output:?}");
    assert!(output.stdout.is_empty(), "STDOUT is not empty");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!stderr.is_empty(), "no error message");
    assert!(
        !stderr.contains(&env_var("HSM_PIN")),
        "the error message shows the PIN"
    );
    stderr
}

/// Ask the operating system for a port that no process uses now.
fn free_port() -> u16 {
    TcpListener::bind((ADDR, 0))
        .expect("failed to find a free port")
        .local_addr()
        .unwrap()
        .port()
}

/// A running service. The process stops when this value is dropped.
pub struct Service {
    pub child: Child,
    addr: String,
}

impl Service {
    /// Start the service on a free port and wait until it accepts connections.
    pub fn start() -> Self {
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

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
