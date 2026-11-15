hsm-signing-service
====

An exercise demonstrating how to interface with an HSM service (SoftHSM) and serve signing requests over an API, written in Rust.

## Setup

Required tools:

- Homebrew ([https://brew.sh/](https://brew.sh/))
- softhsm2-util ([`brew install softhsm`](https://formulae.brew.sh/formula/softhsm))
- pkcs11-tool ([`brew install opensc`](https://formulae.brew.sh/formula/opensc))

### Environment variables

The setup script and the application itself require certain environment variables to be set.

[direnv](https://direnv.net/) provides a convenient way to manage environment variables per-folder. After installing `direnv`, copy `.envrc.example ` to `.envrc`, then run `direnv allow`.

### `setup.sh`

After installing the required tools and ensuring the environment variables are set, run the provided setup script to create the token and keys:

```sh
sh ./setup.sh
```

## Usage

The program has four commands: `server`, `encrypt`, `decrypt` and `wrap`. If you give no command, the program runs `server`.

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
| `AES_KEY_LABEL` | Setup only | The label of the AES-256 key. `setup.sh` creates it. |
| `EXPORTABLE_KEY_LABEL` | Setup only | The label of the EC P-256 key pair that `wrap` wraps. `setup.sh` creates it. |

### `server`

Starts the HTTP service.

```sh
cargo run -- server
```

The service has one endpoint: `POST /v1/sign`. The `key_id` field is the label of an EC P-256 private key in the token. The HSM hashes the payload with SHA-256 and signs it with ECDSA. The private key never leaves the HSM.

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
