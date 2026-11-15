//! Black-box test for the shutdown of the service.
//!
//! The test starts the compiled service as a child process, sends it a
//! signal and checks the exit status. It uses no types or functions from the
//! service code. It needs the `kill` command, so it runs on Unix only.
#![cfg(unix)]

mod common;

use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;

use common::Service;

#[test]
fn the_service_exits_with_code_0_after_sigterm() {
    let mut service = Service::start();

    let pid = service.child.id().to_string();
    let status = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("failed to run `kill`");
    assert!(status.success(), "`kill` failed: {status}");

    // The service has no running requests, so it must stop at once.
    let deadline = Instant::now() + Duration::from_secs(10);
    let exit_status = loop {
        if let Some(status) = service.child.try_wait().expect("failed to wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the service did not exit within 10 seconds after SIGTERM"
        );
        sleep(Duration::from_millis(50));
    };

    assert_eq!(exit_status.code(), Some(0), "unexpected: {exit_status}");
}
