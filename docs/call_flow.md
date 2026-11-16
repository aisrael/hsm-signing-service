# Call flow

This document shows how the parts of the service work together and how the service handles a `POST /v1/sign` request.

## Components

`main` starts the Tokio runtime and calls `cli::run`. For the `server` command, `cli::run_server` loads the configuration, connects to the HSM, builds the router and starts `axum`. The handler uses the `HsmBackend` trait and does not know the implementation. In production, there are two implementations. `run_server` chooses one at startup:

- `CryptokiBackendWithSessionPool` is used when `HSM_SIGNING_SERVICE_SESSION_POOL_SIZE` is set. It has a pool of sessions (from `r2d2`), so several HSM calls can run at the same time.
- `CryptokiBackend` is used when that variable is not set. It has one session behind a `Mutex`.

In unit tests, the implementation is `MockHsmBackend`.

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
        cryptoki["CryptokiBackend<br/>Mutex&lt;Session&gt;<br/>(no pool size)"]
        pooled["CryptokiBackendWithSessionPool<br/>r2d2 pool of sessions<br/>(pool size set)"]
        mock["MockHsmBackend<br/>unit tests only"]
        module["cryptoki crate<br/>PKCS#11 module, loaded once"]
    end

    softhsm[("SoftHSM2<br/>libsofthsm2 + token")]

    client -->|"POST /v1/sign"| axum
    main --> cli
    cli -->|"builds and serves"| axum
    cli -->|"CryptokiBackend::try_new"| cryptoki
    cli -->|"CryptokiBackendWithSessionPool::try_new"| pooled
    cli -->|"AppState::try_new"| state
    axum -->|"routes /v1/sign"| handler
    handler -->|"reads hsm_backend"| state
    state -->|"owns"| trait
    trait -.->|"implemented by"| cryptoki
    trait -.->|"implemented by"| pooled
    trait -.->|"implemented by"| mock
    cryptoki --> module
    pooled --> module
    module -->|"C_Sign, C_FindObjects, ..."| softhsm
```

## Sign request

The HSM calls are blocking, so the handler runs them with `tokio::task::spawn_blocking`. This keeps the async worker threads free. The number of HSM calls that run at the same time depends on the backend:

- `CryptokiBackend` has one logged-in session behind a `Mutex`, so the HSM calls of concurrent requests run one at a time.
- `CryptokiBackendWithSessionPool` takes a session from the pool for each call and gives it back when the call ends. Up to `HSM_SIGNING_SERVICE_SESSION_POOL_SIZE` calls run at the same time. If all sessions are in use, the call waits for a free session for up to `HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS` milliseconds (the default is 500). After that, it fails with a checkout error.

The diagram shows `CryptokiBackend`. `CryptokiBackendWithSessionPool` follows the same steps. The only difference is how it gets a session (see the note after the diagram).

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
    alt the HSM fails, the key label is not unique, or (pool only) no session is free in time
        Pool-->>Handler: Err(Internal)
        Handler-->>Client: 500 {"error": "Internal error"}<br/>(the cause goes to the log only)
    end
    Pool-->>Handler: Ok(signature)
    Handler->>Handler: Encode the signature as base64<br/>and set duration_ms
    Handler-->>Axum: Json(SignResponse)
    Axum-->>Client: 200 {key_id, algorithm, signature, duration_ms}
```

### Session handling with `CryptokiBackendWithSessionPool`

In the diagram, step "Lock the session Mutex" is replaced by "take a session from the pool". The other steps are the same.

```mermaid
sequenceDiagram
    participant Pool as Tokio blocking pool
    participant Backend as CryptokiBackendWithSessionPool
    participant R2d2 as r2d2 Pool
    participant HSM as SoftHSM2 token

    Pool->>Backend: sign(key_id, payload)
    Backend->>R2d2: get()
    alt no session is free after 5 seconds
        R2d2-->>Backend: Err
        Backend-->>Pool: Err(Checkout)
    end
    R2d2-->>Backend: PooledSession
    Backend->>HSM: find the key, then sign (as in the diagram above)
    HSM-->>Backend: signature
    Backend->>R2d2: drop PooledSession (the session goes back to the pool)
    Backend-->>Pool: Ok(DER signature bytes)
```

A checkout error is not a `KeyNotFound` error, so the handler returns `500 {"error": "Internal error"}`.

## Startup and shutdown

- `run_server` stops with exit code 1 if the configuration is not valid, if the HSM token is not found, or if the login fails. Because of this, the service never starts without a working HSM connection.
- With `CryptokiBackendWithSessionPool`, `try_new` logs in once, with one session that stays open for the life of the process. PKCS#11 login belongs to the token, so every session of the pool is then logged in. The pool never logs in itself, because a wrong PIN would be tried again and again, and each failed login counts toward the lockout of the token. Then `try_new` opens all the sessions of the pool (read-only). It fails, and the process exits with code 1, if the pool cannot open all of them. The pool never closes a session because of its age or because it is idle.
- On SIGINT or SIGTERM, `axum` stops accepting new connections and waits for the running requests. If they are still running after `HSM_SIGNING_SERVICE_SHUTDOWN_TIMEOUT_SECS` seconds, the process exits with code 1.
