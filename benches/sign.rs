//! A benchmark for `POST /v1/sign`.
//!
//! The benchmark starts the compiled service as a child process. It uses the
//! environment variables of the developer (see `.envrc.example`) and needs the
//! token and the key `example` (see `setup.sh`).
//!
//! For now, the benchmark only starts the service and stops it again.

#[path = "../tests/common/mod.rs"]
mod common;

use common::Service;

fn main() {
    let service = Service::start();
    println!("the service is running at {}", service.url(""));

    // The service stops when `service` is dropped.
}
