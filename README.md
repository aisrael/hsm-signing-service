hsm-signing-service
====

An exercise demonstrating how to interface with an HSM service (SoftHSM) and serve signing requests over an API, written in Rust.

## Introduction

This project is a REST service that signs data with a key that stays inside a hardware security module (HSM). A client sends `POST /v1/sign` with a key label and a payload. The HSM signs the payload with the requested algorithm, and the service returns the signature.

### Architecture

A request goes through three layers:

```mermaid
flowchart LR
    client([Client]) --> axum["axum handler<br/>and middleware"]
    axum --> backend["HsmBackend"]
    backend --> softhsm[("SoftHSM")]
```

- **axum and middleware:** They own the HTTP endpoints. A middleware does the admission control. An HSM session is a scarce resource, so when too many requests are running or waiting, the middleware rejects new requests at once with `503`. The handlers do not talk to the HSM directly. They use the `HsmBackend` trait.
- **`HsmBackend`:** This trait is the only way to reach the HSM. It has two implementations. One uses a single session. The other uses a pool of sessions, and it is used when you configure a pool size. A request that waits too long for a session gets `504`. The handler tests use a mock backend, so they need no HSM.
- **SoftHSM:** It holds the token and the keys. It does the signing, so the private key never leaves it. A real HSM can replace it, because both use the PKCS#11 interface.

For the component diagram and the sequence diagrams, see [docs/call_flow.md](docs/call_flow.md). For the decision about the limits, see [docs/adrs/001-implemented-max-concurrent-requests.md](docs/adrs/001-implemented-max-concurrent-requests.md). For the load tests, see [Benchmarks](#benchmarks). To run the service in a container, see [Container image](#container-image).

### Concurrency and admission control

An HSM session is a scarce resource, and an HSM call is slow compared to the rest of a request. Two features control how the service uses sessions:

- **Session pool:** Without a pool, the service uses one session, so signing requests are done one at a time. With a pool several requests can be signed at the same time. A bigger pool can raise throughput only if the HSM can do the work in parallel. SoftHSM may not, so measure before you choose a size (see [Benchmarks](#benchmarks)). If all sessions are in use, a request waits for a free one for a short time. After that, it gets `504`.
- **Admission control:** The service accepts only a fixed number of requests at the same time. The limit is the number of sessions plus the queue size. A request over the limit gets `503` with a `Retry-After` header at once, and it never reaches the HSM. With a queue size of `0`, no request waits.

The effect is that the service does not slow down for everyone when the load is too high. Accepted requests wait only a short, bounded time. The excess load is rejected early and cheaply, and the client can try again.

For the details of the decision, see [docs/adrs/001-implemented-max-concurrent-requests.md](docs/adrs/001-implemented-max-concurrent-requests.md).

### Security Approaches

- **Key management:** The HSM makes and keeps every key. `setup.sh` generates the keys inside the token, and we never import a key. The signing key and the AES key are not extractable, so a key never leaves the HSM in plain form. The only export is a demo key that `wrap` outputs encrypted under the AES key. The service finds a key by its label. It has no key rotation, backup or per-key access control (see the limitations).
- **Secrets:** The service reads the PIN from an environment variable. The code does not log it, and the repository does not hold it.
- **Access:** The endpoint has no authentication. Anyone who can reach it can sign with the keys in the token. The service listens on `127.0.0.1` by default. Keep it on a trusted network.

## Setup

Required tools:

- Homebrew ([https://brew.sh/](https://brew.sh/))
- softhsm2-util ([`brew install softhsm`](https://formulae.brew.sh/formula/softhsm))
- pkcs11-tool ([`brew install opensc`](https://formulae.brew.sh/formula/opensc))

**SoftHSM version:** Use SoftHSM 2.7.0 or later. The `server` and `verify` commands sign and verify with the mechanism `CKM_ECDSA_SHA256`, which SoftHSM supports from 2.7.0 (the release notes say "Added support for ECDSA with hashing"). With an older version, such as 2.6.1 (the version in the Ubuntu package), signing fails with `MechanismInvalid`. To check your version, run `softhsm2-util --version`.

### Environment variables

The setup script and the application itself require certain environment variables to be set.

[direnv](https://direnv.net/) provides a convenient way to manage environment variables per-folder. After installing `direnv`, copy `.envrc.example ` to `.envrc`, then run `direnv allow`.

### `setup.sh`

After installing the required tools and ensuring the environment variables are set, run the provided setup script to create the token and keys:

```sh
sh ./setup.sh
```

## Usage

The program has five commands: `server`, `encrypt`, `decrypt`, `verify` and `wrap`. If you give no command, the program runs `server`.

```sh
cargo run -- --help
```

All commands read their settings from environment variables.

| Command | What it does |
| --- | --- |
| `server` | Starts the HTTP service. It has the endpoint `POST /v1/sign`. |
| `encrypt` | Encrypts data from STDIN with an AES-256-GCM key inside the HSM. |
| `decrypt` | Decrypts the output of `encrypt` inside the HSM. |
| `verify` | Checks an ECDSA signature inside the HSM. |
| `wrap` | Encrypts an EC private key with an AES key inside the HSM. |

For the arguments, the output, the error responses and the exit codes of each command, see [docs/commands.md](docs/commands.md).

```sh
cargo run -- server
curl -X POST http://127.0.0.1:8080/v1/sign \
  -H 'Content-Type: application/json' \
  -d '{"key_id": "example", "algorithm": "ECDSA_P256_SHA256", "payload": "aGVsbG8gd29ybGQ="}'
```

**Warning:** The endpoint has no authentication. Anyone who can reach it can sign data with the keys in the token. Keep the default address (`127.0.0.1`) unless you add access control.

### Environment variables reference

| Variable | Required | Description |
| --- | --- | --- |
| `HSM_TOKEN_LABEL` | Yes | The label of the SoftHSM token. |
| `HSM_PIN` | Yes | The user PIN of the token. |
| `PKCS11_MODULE` | No | The path to the PKCS#11 library. The default is the Homebrew SoftHSM library. |
| `HSM_SIGNING_SERVICE_HOST` | No | The address to listen on. The default is `127.0.0.1`. |
| `HSM_SIGNING_SERVICE_PORT` | No | The port to listen on. The default is `8080`. |
| `HSM_SIGNING_SERVICE_SHUTDOWN_TIMEOUT_SECS` | No | How many seconds the server waits for running requests after a shutdown signal. Use a whole number of 1 or more. The default is `30`. |
| `HSM_SIGNING_SERVICE_SESSION_POOL_SIZE` | No | How many HSM sessions the server keeps in its session pool. Use a whole number of 1 or more. If you do not set it, the server uses one session and no pool. |
| `HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS` | No | How many milliseconds a request waits for a free session of the pool. After this time, the server answers `504`. The pool also uses this time to open its sessions at start. Use a whole number of 1 or more. The value `0` is not valid: the server does not start. The default is `500`. Only used with a session pool. |
| `HSM_SIGNING_SERVICE_MAX_QUEUE` | No | How many requests can wait for a free session, in addition to the requests that use a session. The server answers more requests at once with `503` and a `Retry-After` header. Use a whole number of 0 or more. With `0`, no request waits. The default is `20`. |
| `AES_KEY_LABEL` | Setup only | The label of the AES-256 key. `setup.sh` creates it. |
| `EXPORTABLE_KEY_LABEL` | Setup only | The label of the EC P-256 key pair that `wrap` wraps. `setup.sh` creates it. |

## Container image

The `Dockerfile` builds the service with SoftHSM 2.7.0 (built from source, because the Debian package is 2.6.1 and cannot sign with `CKM_ECDSA_SHA256`). The commands work with `docker` and with `podman`.

The image has two targets:

| Target | Content | Use |
| --- | --- | --- |
| `runtime` (default) | The service and the SoftHSM library. It runs as user `app` (UID 10001). | Run the service. |
| `setup` | The runtime image, `softhsm2-util`, `pkcs11-tool` and `setup.sh`. | Create the token and keys, once. |

The image holds no token, key or PIN. The token lives in the volume `/var/lib/softhsm/tokens`. You create it with the `setup` image, then the service uses the same volume.

Build both images:

```sh
docker build -t example-hsm-signing-service .
docker build --target setup -t example-hsm-signing-service-setup .
```

Create the token and keys in a named volume. The commands use the environment variables from `.envrc` (see [Environment variables](#environment-variables)). `-e NAME` passes the value from your shell and does not put it on the command line:

```sh
docker volume create example-hsm-tokens
docker run --rm -v example-hsm-tokens:/var/lib/softhsm/tokens \
  -e HSM_TOKEN_LABEL -e AES_KEY_LABEL -e EXPORTABLE_KEY_LABEL -e HSM_SO_PIN -e HSM_PIN \
  example-hsm-signing-service-setup
```

Run the service on the same volume:

```sh
docker run --rm -p 127.0.0.1:8080:8080 -v example-hsm-tokens:/var/lib/softhsm/tokens \
  -e HSM_TOKEN_LABEL -e HSM_PIN \
  example-hsm-signing-service
```

Then send the request from the [`server`](docs/commands.md#server) section to `http://127.0.0.1:8080/v1/sign`. You can set the other variables of the table above with more `-e` options. The `docker stop` command sends SIGTERM, and the service shuts down gracefully.

Notes:

- The image sets `HSM_SIGNING_SERVICE_HOST=0.0.0.0`, so the port is reachable from outside the container. The endpoint has no authentication. Publish the port only on a trusted interface (`127.0.0.1:` in the command above).
- In a real deployment, give `HSM_PIN` to the container from a secret store (for example a Kubernetes `Secret`), not from a file in the repository. A real HSM replaces the volume: set `PKCS11_MODULE` to the library of the vendor.
- The `setup` image runs `setup.sh`. It stops with an error if a key has wrong settings. It is safe to run again.
- The service has a liveness endpoint, `GET /healthz`, which replies with `HTTP 200` and an empty body when the process serves HTTP. It does not call the HSM, so it does not show that signing works (the service does not replace a session that the HSM closes). It is not limited by `HSM_SIGNING_SERVICE_MAX_QUEUE`, so a busy service still answers it.

## Benchmarks

There are two benchmarks. Both start the compiled service as a child process on a free port. Then they send real `POST /v1/sign` requests over HTTP, with a random payload of 3 to 10 words. They sign with the real SoftHSM token, so they need the token, the key and the environment variables (see [Setup](#setup)). Cargo builds the service with the bench profile (optimized).

Load the environment variables first. If you use `direnv`, they are already set. If not, load `.envrc` in a subshell, so the variables do not stay in your shell:

```sh
(set -a; . ./.envrc; set +a; cargo bench --bench custom_benchmark)
```

### `custom_benchmark`

Measures throughput and latency for a number of concurrent callers. Each caller is a thread. It sends requests one after another on its own connection. For each level, a warm-up phase runs first, and its results are thrown away. Then the measured phase runs. The report shows the number of requests, the error rate, the throughput (successful requests per second) and the latency (minimum, p50, p95, p99 and maximum, in milliseconds).

```sh
cargo bench --bench custom_benchmark -- --warmup-secs 5 --duration-secs 30 --seed 42 -C 1 -C 10 -C 100 -C 500
```

| Option | Default | Description |
| --- | --- | --- |
| `--warmup-secs <N>` | `5` | How long the warm-up phase runs, in seconds. |
| `--duration-secs <N>` | `30` | How long the measured phase runs, in seconds. |
| `-C`, `--concurrency <N>` | `1` | The number of concurrent callers, from 1 to 1000. Repeat the option or separate the values with commas to run several levels one after another. `-C 1 -C 10` is the same as `--concurrency 1,10`. |
| `--seed <N>` | none | Seeds the random number generators, so a run can send the same payloads again. Without a seed, every run uses different payloads. |

Notes:

- Each caller sends its next request after the last one ends (a closed loop). When the service is slow, the callers wait, and this hides part of the queueing delay.
- The client and the service run on one machine and share the CPU. SoftHSM is software, so its signing time is not the time of a real HSM.
- Each caller needs a socket, and so does the service. For hundreds of callers, check the limit of open files in your shell (`ulimit -n`). If it is low (the macOS default is often 256), connection errors can look like service errors. Raise the limit before you run the benchmark, for example `ulimit -n 4096`.

### `criterion_benchmark`

Finds regressions. It sends the same requests with one caller and uses [criterion](https://crates.io/crates/criterion) to measure the time of one request and to compare it with an earlier run. The payloads come from a fixed seed, so every run sends the same sequence. A request that fails stops the benchmark.

Save a baseline, change the code, then compare:

```sh
cargo bench --bench criterion_benchmark -- --save-baseline before
cargo bench --bench criterion_benchmark -- --baseline before
```

`criterion` prints the time for each run and tells you if the time changed. It saves the results and an HTML report in `target/criterion`.
