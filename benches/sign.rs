//! A benchmark for `POST /v1/sign`.
//!
//! The benchmark starts the compiled service as a child process. It uses the
//! environment variables of the developer (see `.envrc.example`) and needs the
//! token and the signing key (see `setup.sh`). The signing key has the same
//! label as the token, so the benchmark takes the `key_id` from
//! `HSM_TOKEN_LABEL`.
//!
//! One caller sends requests one after another. Each request has a payload
//! of random words (3 to 20 words, from the `fake` crate). The `--seed`
//! option seeds the random number generator, so a run can use the same
//! sequence of payloads again. First a warm-up phase runs,
//! and its results are thrown away. Then the measured phase runs. The report
//! shows the latency percentiles and the error rate.
//!
//! ```sh
//! cargo bench --bench sign -- --warmup-secs 5 --duration-secs 30 --seed 42
//! ```

#[path = "../tests/common/mod.rs"]
mod common;

use std::time::Duration;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Parser;
use common::Service;
use fake::Fake;
use fake::faker::lorem::en::Sentence;
use fake::rand::SeedableRng;
use fake::rand::make_rng;
use fake::rand::rngs::StdRng;
use serde_json::Value;
use serde_json::json;

/// The number of words in a payload: from 3 up to (not including) 21, so a
/// payload has 3 to 10 words.
const WORDS: std::ops::Range<usize> = 3..11;

#[derive(Debug, Parser)]
struct Args {
    /// How long the warm-up phase runs, in seconds.
    #[arg(long, default_value_t = 5)]
    warmup_secs: u64,
    /// How long the measured phase runs, in seconds.
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,
    /// Seed for the random number generator that makes the payloads. Without
    /// a seed, every run uses different payloads.
    #[arg(long)]
    seed: Option<u64>,
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

/// The report for one phase. The latencies are those of the successful
/// requests, in milliseconds. They are `None` if no request succeeded. The
/// error rate is a percentage. It is `None` if there were no requests.
struct Report {
    total_requests: u64,
    failed_requests: u64,
    /// How long the phase took.
    elapsed: Duration,
    error_rate: Option<f64>,
    min: Option<f64>,
    p50: Option<f64>,
    p95: Option<f64>,
    p99: Option<f64>,
    max: Option<f64>,
}

impl From<PhaseResults> for Report {
    /// Sort the latencies, convert them to milliseconds and compute the
    /// percentiles and the error rate.
    fn from(results: PhaseResults) -> Self {
        let mut latencies = results.latencies;
        latencies.sort();
        let sorted: Vec<f64> = latencies
            .iter()
            .map(|latency| latency.as_secs_f64() * 1000.0)
            .collect();
        Report {
            total_requests: results.total_requests,
            failed_requests: results.failed_requests,
            elapsed: results.elapsed,
            error_rate: (results.total_requests > 0)
                .then(|| results.failed_requests as f64 / results.total_requests as f64 * 100.0),
            min: sorted.first().copied(),
            p50: Report::percentile(&sorted, 50.0),
            p95: Report::percentile(&sorted, 95.0),
            p99: Report::percentile(&sorted, 99.0),
            max: sorted.last().copied(),
        }
    }
}

impl Report {
    /// The percentile `p` (0 to 100) of the sorted values, by the nearest-rank
    /// method. Return `None` if there are no values.
    fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
        let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
        sorted.get(rank.max(1) - 1).copied()
    }
}

/// Make a sign request with a random payload: a sentence, as base64.
fn random_request(key_id: &str, rng: &mut StdRng) -> Value {
    let sentence: String = Sentence(WORDS).fake_with_rng(rng);
    json!({
        "key_id": key_id,
        "algorithm": "ECDSA_P256_SHA256",
        "payload": BASE64.encode(sentence),
    })
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

/// Send requests one after another until `duration` has passed. Make each
/// payload before the request starts, so that it does not count in the latency.
fn run_phase(
    agent: &ureq::Agent,
    url: &str,
    key_id: &str,
    rng: &mut StdRng,
    duration: Duration,
) -> PhaseResults {
    let start = Instant::now();
    let mut latencies = Vec::new();
    let mut total_requests = 0;
    let mut failed_requests = 0;
    while start.elapsed() < duration {
        let request = random_request(key_id, rng);
        total_requests += 1;
        match sign_once(agent, url, &request) {
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

/// Print the report for the measured phase.
fn print_report(report: &Report) {
    let Report {
        total_requests,
        failed_requests,
        elapsed,
        ..
    } = report;
    let ok = total_requests - failed_requests;

    println!("requests: {total_requests} (ok {ok}, errors {failed_requests})");
    if let Some(error_rate) = report.error_rate {
        println!("error rate: {error_rate:.2}%");
    }
    let (Some(min), Some(p50), Some(p95), Some(p99), Some(max)) =
        (report.min, report.p50, report.p95, report.p99, report.max)
    else {
        println!("no successful requests, so there are no latencies");
        return;
    };
    println!("throughput: {:.1} req/s", ok as f64 / elapsed.as_secs_f64());
    println!(
        "latency ms: min {:.2}  p50 {:.2}  p95 {:.2}  p99 {:.2}  max {:.2}",
        min, p50, p95, p99, max,
    );
}

fn main() {
    let args = Args::parse();

    let service = Service::start();
    let url = service.url("/v1/sign");
    let key_id = common::env_var("HSM_TOKEN_LABEL");
    let agent = ureq::Agent::new_with_defaults();
    let mut rng = match args.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => make_rng(),
    };

    println!("warm-up: {} s", args.warmup_secs);
    run_phase(
        &agent,
        &url,
        &key_id,
        &mut rng,
        Duration::from_secs(args.warmup_secs),
    );

    println!("measuring: {} s", args.duration_secs);
    let report = Report::from(run_phase(
        &agent,
        &url,
        &key_id,
        &mut rng,
        Duration::from_secs(args.duration_secs),
    ));
    print_report(&report);

    // The service stops when `service` is dropped.
}
