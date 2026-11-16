hsm-signing-service
====

An exercise demonstrating how to interface with an HSM service (SoftHSM) and serve signing requests over an API, written in Rust.

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

### `server`

Starts the HTTP service.

```sh
cargo run -- server
```

The service has one API endpoint: `POST /v1/sign`. The `key_id` field is the label of an EC P-256 private key in the token. The HSM hashes the payload with SHA-256 and signs it with ECDSA. The private key never leaves the HSM.

```sh
curl -X POST http://127.0.0.1:8080/v1/sign \
  -H 'Content-Type: application/json' \
  -d '{"key_id": "example", "algorithm": "ECDSA_P256_SHA256", "payload": "aGVsbG8gd29ybGQ="}'
```

The response has the signature as base64 of a DER-encoded ECDSA signature:

```json
{
  "key_id": "example",
  "algorithm": "ECDSA_P256_SHA256",
  "signature": "MEUCIQ...",
  "duration_ms": 8
}
```

Error responses have the body `{"error": "..."}`:

| Status | Cause |
| --- | --- |
| 400 | The `payload` field is not valid base64. |
| 422 | The token has no private key with the label `key_id`. |
| 500 | An internal error. The response does not show the cause. The service writes it to the log. |
| 503 | The queue limit is reached: all sessions are in use and `HSM_SIGNING_SERVICE_MAX_QUEUE` requests are already waiting. The response has a `Retry-After: 1` header. The request did not reach the HSM, so the client can try again. |
| 504 | No session was free after `HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS` milliseconds. Only happens with a session pool. |

The server stops when it gets SIGINT (Ctrl+C) or SIGTERM (the signal that Docker and Kubernetes send). It stops accepting new connections and waits for the requests that are running. Then it exits with code 0. If requests are still running after `HSM_SIGNING_SERVICE_SHUTDOWN_TIMEOUT_SECS` seconds, the server logs a warning and exits with code 1.

**Warning:** The endpoint has no authentication. Anyone who can reach it can sign data with the keys in the token. Keep the default address (`127.0.0.1`) unless you add access control.

### `encrypt`

Encrypts data with AES-256-GCM inside the HSM. The command reads the plaintext from STDIN and prints the result to STDOUT as base64.

The `--key-id` argument is required. It is the label of an AES key in the token.

```sh
printf 'hello world' | cargo run -- encrypt --key-id example-aes
```

The command encrypts the input exactly as it is. `echo` adds a newline at the end, so use `printf` or `echo -n` if you do not want the newline.

The output is base64 of `iv || ciphertext || tag`:

- `iv`: 12 bytes. The HSM makes a new random IV for each call. You cannot set it.
- `ciphertext`: the same length as the plaintext.
- `tag`: 16 bytes. It authenticates the data.

If the command fails, it prints an error to STDERR and exits with code 1. STDOUT stays empty.

### `decrypt`

Decrypts the output of `encrypt` inside the HSM. The command reads the base64 text from STDIN and writes the plaintext to STDOUT.

The `--key-id` argument is required. It must be the label of the AES key that `encrypt` used.

```sh
printf 'hello world' | cargo run -- encrypt --key-id example-aes | cargo run -- decrypt --key-id example-aes
```

The command ignores spaces and newlines around the input. It writes the plaintext bytes exactly as they were. It does not add a newline.

AES-GCM checks the tag. The command fails if you use the wrong key or if someone changed the data. It also fails if the input is not valid base64 or is shorter than 28 bytes (the IV and the tag).

If the command fails, it prints an error to STDERR and exits with code 1. STDOUT stays empty.

### `verify`

Checks an ECDSA signature inside the HSM (`CKM_ECDSA_SHA256`). The command reads the payload from STDIN and uses the EC public key of the key pair.

The following arguments are required:

- `--key-id`: the label of the EC key pair that made the signature. The public key must have the same label as the private key.
- `--signature`: the signature as base64 of the DER form. This is the `signature` field of the API response.

```sh
printf 'hello world' | cargo run -- verify --key-id example --signature MEUCIQ...
```

This example signs through the API and then verifies the result (it needs `jq`):

```sh
printf 'hello world' > payload.txt
signature=$(curl -s -X POST http://127.0.0.1:8080/v1/sign \
  -H 'Content-Type: application/json' \
  -d "{\"key_id\": \"example\", \"algorithm\": \"ECDSA_P256_SHA256\", \"payload\": \"$(base64 < payload.txt)\"}" \
  | jq -r .signature)
cargo run -- verify --key-id example --signature "$signature" < payload.txt
```

The API takes the payload as base64, but `verify` takes the raw bytes on STDIN. The command uses the input exactly as it is, so a newline at the end changes the result. Use `printf` or `echo -n`.

| Exit code | Meaning |
| --- | --- |
| 0 | The signature matches. The command prints `valid` to STDOUT. |
| 1 | The signature does not match, or an error happened (for example, the key does not exist or the signature is not valid base64 or DER). The command prints a message to STDERR. STDOUT stays empty. |
| 2 | An argument is missing or wrong. |

### `wrap`

Encrypts an EC private key with an AES key inside the HSM (AES key wrap with padding, `CKM_AES_KEY_WRAP_PAD`). The command prints the encrypted key to STDOUT as base64.

The following arguments are required:

- `--key-id`: the label of the AES key that wraps. `setup.sh` creates the key `example-aes`.
- `--target-key-id`: the label of the EC private key to wrap. `setup.sh` creates the key `example-exportable` for this purpose.

```sh
cargo run -- wrap --key-id example-aes --target-key-id example-exportable
```

The output is the private key (PKCS#8) encrypted under the AES key. It is safe to store, because only an HSM that has the same AES key can decrypt it. The AES key and the plain private key never leave the HSM. The command gives the same output each time, because AES key wrap uses no IV.

The HSM wraps only a key that is extractable. `setup.sh` makes only `example-exportable` extractable (and sensitive), and it fails if any other key in the token is extractable. The signing key stays non-extractable, so `wrap` fails for it. This is on purpose. `example-exportable` exists to demonstrate the command.

`wrap` supports EC private keys only. The program has no `unwrap` command.

If the command fails, it prints an error to STDERR and exits with code 1. STDOUT stays empty.

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

Then send the request from the [`server`](#server) section to `http://127.0.0.1:8080/v1/sign`. You can set the other variables of the table above with more `-e` options. The `docker stop` command sends SIGTERM, and the service shuts down gracefully.

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
