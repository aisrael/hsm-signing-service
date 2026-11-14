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
