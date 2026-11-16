# Call flow

This document shows how the parts of the service work together and how the service handles a `POST /v1/sign` request.

## Components

`main` starts the Tokio runtime and calls `cli::run`. For the `server` command, `cli::run_server` loads the configuration, connects to the HSM, builds the router and starts `axum`. The handler uses the `HsmBackend` trait and does not know the implementation. In production, the implementation is `CryptokiBackend`. In unit tests, it is `MockHsmBackend`.

```mermaid
flowchart TB
    client([HTTP client])

    subgraph process["hsm-signing-service process"]
        main["main<br/>#[tokio::main]"]
        cli["cli::run / run_server<br/>config, startup, shutdown"]
        axum["axum<br/>axum::serve + Router"]
        handler["api::handle_post_sign"]
        state["AppState&lt;B&gt;<br/>Arc, shared by all requests"]
        trait{{"trait HsmBackend<br/>sign, verify, encrypt, ..."}}
        cryptoki["CryptokiBackend<br/>Mutex&lt;Session&gt;"]
        mock["MockHsmBackend<br/>unit tests only"]
        module["cryptoki crate<br/>PKCS#11 module, loaded once"]
    end

    softhsm[("SoftHSM2<br/>libsofthsm2 + token")]

    client -->|"POST /v1/sign"| axum
    main --> cli
    cli -->|"builds and serves"| axum
    cli -->|"CryptokiBackend::try_new"| cryptoki
    cli -->|"AppState::try_new"| state
    axum -->|"routes /v1/sign"| handler
    handler -->|"reads hsm_backend"| state
    state -->|"owns"| trait
    trait -.->|"implemented by"| cryptoki
    trait -.->|"implemented by"| mock
    cryptoki --> module
    module -->|"C_Sign, C_FindObjects, ..."| softhsm
```

## Sign request

The HSM calls are blocking, so the handler runs them with `tokio::task::spawn_blocking`. This keeps the async worker threads free. `CryptokiBackend` has one logged-in session behind a `Mutex`, so the HSM calls of concurrent requests run one at a time.

The private key never leaves the HSM. The HSM hashes the payload with SHA-256 and signs it (`CKM_ECDSA_SHA256`). It returns the signature as raw `r || s`. `CryptokiBackend` converts it to DER form.

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Axum as axum (Router)
    participant Handler as handle_post_sign
    participant Pool as Tokio blocking pool<br/>(spawn_blocking)
    participant Backend as CryptokiBackend<br/>(HsmBackend)
    participant Cryptoki as cryptoki Session
    participant HSM as SoftHSM2 token

    Client->>Axum: POST /v1/sign<br/>{key_id, algorithm, payload (base64)}
    Axum->>Axum: Route to the handler and parse the JSON body<br/>into SignRequest
    alt the body is not valid JSON, or has an unknown field or algorithm
        Axum-->>Client: 4xx rejection from the Json extractor
    end
    Axum->>Handler: handle_post_sign(State, Json(SignRequest))
    Handler->>Handler: Decode the base64 payload
    alt the payload is not valid base64
        Handler-->>Client: 400 {"error": "Unable to base64 decode payload: ..."}
    end
    Handler->>Pool: spawn_blocking(closure)
    Pool->>Backend: sign(key_id, payload)
    Backend->>Backend: Lock the session Mutex
    Backend->>Cryptoki: find_objects(private key, EC, label = key_id)
    Cryptoki->>HSM: C_FindObjects
    HSM-->>Cryptoki: object handles
    Cryptoki-->>Backend: handles
    alt no private key has this label
        Backend-->>Pool: Err(KeyNotFound)
        Pool-->>Handler: Err(ApiError::KeyNotFound)
        Handler-->>Client: 422 {"error": "Key not found"}
    end
    Backend->>Cryptoki: sign(CKM_ECDSA_SHA256, key, payload)
    Cryptoki->>HSM: C_SignInit + C_Sign
    HSM->>HSM: Hash the payload with SHA-256<br/>and sign it with the private key
    HSM-->>Cryptoki: raw signature (r || s)
    Cryptoki-->>Backend: raw signature
    Backend->>Backend: Convert r || s to a DER signature
    Backend-->>Pool: Ok(DER signature bytes)
    alt the HSM fails, or the key label is not unique
        Pool-->>Handler: Err(Internal)
        Handler-->>Client: 500 {"error": "Internal error"}<br/>(the cause goes to the log only)
    end
    Pool-->>Handler: Ok(signature)
    Handler->>Handler: Encode the signature as base64<br/>and set duration_ms
    Handler-->>Axum: Json(SignResponse)
    Axum-->>Client: 200 {key_id, algorithm, signature, duration_ms}
```

## Startup and shutdown

- `run_server` stops with exit code 1 if the configuration is not valid, if the HSM token is not found, or if the login fails. Because of this, the service never starts without a working HSM connection.
- On SIGINT or SIGTERM, `axum` stops accepting new connections and waits for the running requests. If they are still running after `HSM_SIGNING_SERVICE_SHUTDOWN_TIMEOUT_SECS` seconds, the process exits with code 1.
