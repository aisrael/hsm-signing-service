# ADR 001: Implemented max concurrent requests

- Status: Accepted
- Date: 2026-11-16

## Context

The service signs with a pool of HSM sessions (`HSM_SIGNING_SERVICE_SESSION_POOL_SIZE`). Without a pool, it has one session. The number of HSM calls that can run at the same time is therefore small, and each call takes about 200 µs.

Before this change, all the other requests waited for a session. A request waited for up to `HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS` and then failed. With many callers (the benchmark uses up to 500), a lot of work piled up in the service, and a client could not tell "the service is full" from a real error.

We need a limit for the number of requests that are in the service at the same time. A request over the limit must fail at once with `503` and a `Retry-After` header, so the client can try again. The limit must be:

- the number of sessions (1 without a pool) plus a queue length that the operator sets with `HSM_SIGNING_SERVICE_MAX_QUEUE` (the default is 20);
- checked before the service does work for the request;
- easy to test without an HSM.

## Decision

We use an axum middleware, `api::limit_requests`.

- `api::router(&config, state)` builds a Tokio `Semaphore` with `config.max_concurrent_requests()` places and adds the middleware with `middleware::from_fn_with_state`. The router takes `&Config` as its first argument, so it can read more settings later.
- For each request, the middleware calls `Semaphore::try_acquire`. It never waits.
- If no place is free, the middleware returns `ApiError::Busy`: `503` with `Retry-After: 1` and the body `{"error": "Service busy, try again later"}`. The request does not reach the handler, so the service does not parse its body.
- If a place is free, the middleware keeps it until the response is ready, for a success and for an error.
- `HSM_SIGNING_SERVICE_MAX_QUEUE=0` is valid. It means that no request waits: the service rejects a request when all sessions are in use.
- A different case stays separate: if a request gets to the backend and no session is free before the pool connection timeout, the handler returns `504`.

## Options that we rejected

### A semaphore directly in the handler

`AppState` would own the semaphore, and `handle_post_sign` would take a place at its start. We built this first.

- The handler runs after axum has parsed the JSON body. A rejected request still costs the parse.
- The handler mixes two jobs: signing and admission control. Each new constraint would add more code to the handler.
- `AppState` would need to know the limit, and tests of the handler would need to fill the semaphore by hand.

### The limit in an `HsmBackend` wrapper

`HsmBackendWithQueue<B: HsmBackend>` would wrap the inner backend. `run_server` would use the inner backend directly when the queue length is 0.

- The check would run inside `spawn_blocking`. Every request would take a blocking thread, and would do the base64 decode and the task switch, before the check. When many requests arrive at once, the queue of the blocking pool (up to 512 threads) is not limited by this check.
- Admission control is an HTTP concern, and the backend is an HSM concern. The wrapper would also have to pass `verify`, `encrypt`, `decrypt` and `wrap` through without a limit.
- Using the backend directly for `0` would mean "no limit". We want `0` to mean "no request waits", so the wrapper would need a second switch for "no limit".
- The good side: no extra cost when the wrapper is off, and easy tests with `MockHsmBackend`.

### Tower layers

`ConcurrencyLimitLayer`, `LoadShedLayer` and `HandleErrorLayer` from `tower` would do the same job. We built this second and it worked, with tests.

- It needs all three layers for one job. `ConcurrencyLimitLayer` alone makes extra requests wait. `LoadShedLayer` turns "no place" into an error. axum accepts only services that never fail, so `HandleErrorLayer` must turn that error into the `503` response.
- It adds the `tower` crate as a dependency, with `tokio-util` and `futures-sink`.
- The path from "limit reached" to the `503` response is indirect, and it is harder to read than a short function.
- The good side: it is a common pattern and the code is not ours to maintain.

## Consequences

- The limit is about 10 lines of our own code. We maintain it, and a change in axum can affect it.
- The middleware is the place for other checks that must run before the handler (for example, authentication or a rate limit).
- A place counts a request in the service, not an HSM call. If a client disconnects, axum drops the handler and the place is free, but the blocking thread can still hold its session until the HSM call ends. Under a very slow HSM, the service can briefly run more calls than it has places.
- Taking and freeing a place costs an atomic operation, about tens of nanoseconds when no other request competes for the same counter. We did not measure it. A sign call takes about 200 µs.
- Benchmarks that must not see `503` need a queue length at least as large as the number of callers. For example, 500 callers need `HSM_SIGNING_SERVICE_MAX_QUEUE=500`.
- We tested the limit with unit tests of the router. A router test holds one request in the backend and checks that the next request gets `503` with `Retry-After` and that the backend is called once. Two more tests check that a place is free again after a success and after an error. No test has sent concurrent requests to a running server.
