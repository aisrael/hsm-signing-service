//! A benchmark for `POST /v1/sign`.
//!
//! The benchmark starts the compiled service as a child process. It uses the
//! environment variables of the developer (see `.envrc.example`) and needs the
//! token and the key `example` (see `setup.sh`).
//!
//! One caller sends requests one after another. First a warm-up phase runs,
//! and its results are thrown away. Then the measured phase runs. The report
//! shows the latency percentiles and the error rate.
//!
//! ```sh
//! cargo bench --bench sign -- --warmup-secs 5 --duration-secs 30
//! ```

#[path = "../tests/common/mod.rs"]
mod common;

use std::time::Duration;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Parser;
use common::Service;
use serde_json::Value;
use serde_json::json;

/// The payload of every request, for now.
const PAYLOAD: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
                       sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

#[derive(Debug, Parser)]
struct Args {
    /// How long the warm-up phase runs, in seconds.
    #[arg(long, default_value_t = 5)]
    warmup_secs: u64,
    /// How long the measured phase runs, in seconds.
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,
    /// Cargo passes this flag to every benchmark. The benchmark ignores it.
    #[arg(long, hide = true)]
    bench: bool,
}

/// The results of one phase.
struct PhaseResults {
    /// The latencies of the successful requests.
    latencies: Vec<Duration>,
    total_requests: u64,
    failed_requests: u64,
    /// How long the phase took.
    elapsed: Duration,
}

impl PhaseResults {
    /// The latencies of the successful requests in milliseconds, from the
    /// smallest to the largest.
    fn latencies_ms(&self) -> Vec<f64> {
        let mut latencies_ms: Vec<f64> = self
            .latencies
            .iter()
            .map(|latency| latency.as_secs_f64() * 1000.0)
            .collect();
        latencies_ms.sort_by(f64::total_cmp);
        latencies_ms
    }
}

/// Send one sign request. Return its latency, or `None` if the request
/// failed: the call failed, the status is not 200, or the response has no
/// signature.
fn sign_once(agent: &ureq::Agent, url: &str, request: &Value) -> Option<Duration> {
    let start = Instant::now();
    let body = agent
        .post(url)
        .send_json(request)
        .ok()?
        .body_mut()
        .read_json::<Value>()
        .ok()?;
    body["signature"].is_string().then(|| start.elapsed())
}

/// Send requests one after another until `duration` has passed.
fn run_phase(agent: &ureq::Agent, url: &str, request: &Value, duration: Duration) -> PhaseResults {
    let start = Instant::now();
    let mut latencies = Vec::new();
    let mut total_requests = 0;
    let mut failed_requests = 0;
    while start.elapsed() < duration {
        total_requests += 1;
        match sign_once(agent, url, request) {
            Some(latency) => latencies.push(latency),
            None => failed_requests += 1,
        }
    }
    PhaseResults {
        latencies,
        total_requests,
        failed_requests,
        elapsed: start.elapsed(),
    }
}

/// The percentile `p` (0 to 100) of the sorted values, by the nearest-rank
/// method. The values must not be empty.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Print the report for the measured phase.
fn report(phase: &PhaseResults) {
    let PhaseResults {
        total_requests,
        failed_requests,
        elapsed,
        ..
    } = phase;
    let latencies_ms = phase.latencies_ms();
    let ok = latencies_ms.len();

    println!("requests: {total_requests} (ok {ok}, errors {failed_requests})");
    if *total_requests > 0 {
        let error_rate = *failed_requests as f64 / *total_requests as f64 * 100.0;
        println!("error rate: {error_rate:.2}%");
    }
    if ok == 0 {
        println!("no successful requests, so there are no latencies");
        return;
    }
    println!("throughput: {:.1} req/s", ok as f64 / elapsed.as_secs_f64());
    println!(
        "latency ms: min {:.2}  p50 {:.2}  p95 {:.2}  p99 {:.2}  max {:.2}",
        latencies_ms[0],
        percentile(&latencies_ms, 50.0),
        percentile(&latencies_ms, 95.0),
        percentile(&latencies_ms, 99.0),
        latencies_ms[ok - 1],
    );
}

fn main() {
    let args = Args::parse();

    let service = Service::start();
    let url = service.url("/v1/sign");
    let agent = ureq::Agent::new_with_defaults();
    let request = json!({
        "key_id": "example",
        "algorithm": "ECDSA_P256_SHA256",
        "payload": BASE64.encode(PAYLOAD),
    });

    println!("warm-up: {} s", args.warmup_secs);
    run_phase(
        &agent,
        &url,
        &request,
        Duration::from_secs(args.warmup_secs),
    );

    println!("measuring: {} s", args.duration_secs);
    let phase = run_phase(
        &agent,
        &url,
        &request,
        Duration::from_secs(args.duration_secs),
    );
    report(&phase);

    // The service stops when `service` is dropped.
}
