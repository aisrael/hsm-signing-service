//! A `criterion` benchmark for `POST /v1/sign`, to find regressions.
//!
//! The benchmark starts the compiled service as a child process and sends real
//! HTTP requests with one caller, as the `custom_benchmark` benchmark does with
//! one caller. Each request has a payload of random words (3 to 10 words). The
//! payloads come from a fixed seed, so every run sends the same sequence.
//! Compare a run with a saved baseline to find a slowdown:
//!
//! ```sh
//! cargo bench --bench criterion_benchmark -- --save-baseline before
//! cargo bench --bench criterion_benchmark -- --baseline before
//! ```
//!
//! The benchmark needs the token and the key (see `setup.sh`) and the
//! environment variables of the service. A request that fails stops the
//! benchmark, because a time without a signature has no meaning. For
//! percentiles, error rates and many callers, use `custom_benchmark`.

#[path = "../tests/common/mod.rs"]
mod common;

use std::hint::black_box;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::Service;
use criterion::BatchSize;
use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use fake::Fake;
use fake::faker::lorem::en::Sentence;
use fake::rand::SeedableRng;
use fake::rand::rngs::StdRng;
use serde_json::Value;
use serde_json::json;

/// The number of words in a payload: from 3 up to (not including) 11, so a
/// payload has 3 to 10 words.
const WORDS: std::ops::Range<usize> = 3..11;

/// The seed of the random number generator that makes the payloads.
const SEED: u64 = 42;

/// Make a sign request with a random payload: a sentence, as base64.
fn random_request(key_id: &str, rng: &mut StdRng) -> Value {
    let sentence: String = Sentence(WORDS).fake_with_rng(rng);
    json!({
        "key_id": key_id,
        "algorithm": "ECDSA_P256_SHA256",
        "payload": BASE64.encode(sentence),
    })
}

/// Send one sign request. Return the `signature` field of the response.
fn sign_once(agent: &ureq::Agent, url: &str, request: &Value) -> String {
    let body = agent
        .post(url)
        .send_json(request)
        .expect("the request failed")
        .body_mut()
        .read_json::<Value>()
        .expect("the response body is not valid JSON");
    body["signature"]
        .as_str()
        .expect("the response has no signature")
        .to_string()
}

fn bench_sign(c: &mut Criterion) {
    let service = Service::start();
    let url = service.url("/v1/sign");
    let key_id = common::env_var("HSM_TOKEN_LABEL");
    let agent = ureq::Agent::new_with_defaults();
    let mut rng = StdRng::seed_from_u64(SEED);

    c.bench_function("post_v1_sign", |b| {
        // Make the request in the setup step, so it does not count in the time.
        b.iter_batched(
            || random_request(&key_id, &mut rng),
            |request| black_box(sign_once(&agent, &url, &request)),
            BatchSize::SmallInput,
        );
    });

    // The service stops when `service` is dropped.
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .sample_size(1000);
    targets = bench_sign
}
criterion_main!(benches);
