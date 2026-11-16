//! The HTTP API: request and response types, errors and the handlers.

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::Router;
use axum::extract::Request;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::RETRY_AFTER;
use axum::middleware;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use base64::Engine;
use base64::engine::GeneralPurpose;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::Semaphore;
use tracing::Instrument;
use tracing::Span;
use tracing::instrument;
use tracing::trace;

use crate::algorithm::Algorithm;
use crate::app_state::AppState;
use crate::config::Config;
use crate::hsm_backend::HsmBackend;
use crate::hsm_backend::HsmBackendError;
use crate::metrics::Metrics;
use crate::telemetry;

/// The request body for the POST /v1/sign endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub key_id: String,
    pub algorithm: Algorithm,
    pub payload: String,
}

/// The response body for the POST /v1/sign endpoint.
#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub key_id: String,
    pub algorithm: Algorithm,
    pub signature: String,
    pub duration_ms: u64,
}

/// The body of every error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Errors that the API returns to the client.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The `payload` field is not valid base64.
    #[error("Unable to base64 decode payload: {0}")]
    PayloadBase64DecodingError(#[from] base64::DecodeError),
    /// No private key has the label `key_id`. The label is not echoed back.
    #[error("Key not found")]
    KeyNotFound,
    /// Something failed inside the service. The cause is logged, not sent.
    #[error("Internal error")]
    Internal(String),
    /// The service has too many requests: all sessions are in use and the queue
    /// is full. The client can try again. The `limit_requests` middleware gives this
    /// error.
    #[error("Service busy, try again later")]
    Busy,
    /// No session was free before the pool connection timeout.
    #[error("Request timed out")]
    Timeout,
}

impl ApiError {
    /// A short, fixed name of the error. It is the `outcome` attribute of the
    /// request spans, so it must stay a small set of values.
    fn outcome(&self) -> &'static str {
        match self {
            ApiError::PayloadBase64DecodingError(_) => "bad_request",
            ApiError::KeyNotFound => "key_not_found",
            ApiError::Internal(_) => "internal",
            ApiError::Busy => "busy",
            ApiError::Timeout => "timeout",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let mut headers = HeaderMap::new();
        let status = match &self {
            ApiError::PayloadBase64DecodingError(_) => StatusCode::BAD_REQUEST,
            ApiError::KeyNotFound => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::Internal(cause) => {
                tracing::error!("internal error: {cause}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ApiError::Busy => {
                headers.insert(RETRY_AFTER, HeaderValue::from_static("1"));
                StatusCode::SERVICE_UNAVAILABLE
            }
            ApiError::Timeout => {
                tracing::warn!("no HSM session was free before the pool timeout");
                StatusCode::GATEWAY_TIMEOUT
            }
        };
        let error_body = ErrorResponse {
            error: self.to_string(),
        };
        (status, headers, Json(error_body)).into_response()
    }
}

/// Just an alias for the base64 engine we use to decode the payload.
pub(crate) const BASE64: GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Middleware that limits how many requests are in the service. It takes one
/// place of the semaphore for each request and gives it back when the response
/// is ready. A request over the limit does not wait: it gets `503` at once,
/// before the service reads its body.
///
/// This is the place for other checks that must run before the handler.
async fn limit_requests(State(limit): State<Limit>, request: Request, next: Next) -> Response {
    let Ok(_place) = limit.places.try_acquire() else {
        tracing::warn!("too many requests in the service, answering 503");
        Span::current().record("rejected", true);
        return ApiError::Busy.into_response();
    };
    // Counted only after the place is taken: a rejected request is not in the
    // service. The guard drops with the place, when the response is ready.
    let _in_flight = limit.metrics.request_in_flight();
    next.run(request).await
}

/// The state of `limit_requests`: the places and the gauge that counts them.
#[derive(Clone)]
struct Limit {
    places: Arc<Semaphore>,
    metrics: Metrics,
}

/// The route of the signing endpoint. Also the `http.route` of its spans.
const SIGN_ROUTE: &str = "/v1/sign";

/// Middleware that makes the server span of a request. The span joins the
/// trace in the `traceparent` header, if the client sends one. It is the
/// outermost layer, so it also covers the requests that `limit_requests`
/// rejects.
async fn trace_request(request: Request, next: Next) -> Response {
    let span = tracing::info_span!(
        "http_request",
        otel.name = format!("{} {SIGN_ROUTE}", request.method()),
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        http.request.method = %request.method(),
        http.route = SIGN_ROUTE,
        http.response.status_code = tracing::field::Empty,
        rejected = tracing::field::Empty,
    );
    telemetry::set_parent_from_headers(&span, request.headers());

    let response = next.run(request).instrument(span.clone()).await;

    let status = response.status();
    span.record("http.response.status_code", status.as_u16());
    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
    }
    response
}

/// Build the router with all the routes of the API.
///
/// At most `config.max_concurrent_requests()` requests are in the service at
/// the same time (see `limit_requests`).
pub fn router<B>(config: &Config, state: Arc<AppState<B>>) -> Router
where
    B: HsmBackend,
{
    let limit = Limit {
        places: Arc::new(Semaphore::new(config.max_concurrent_requests())),
        metrics: state.metrics.clone(),
    };
    Router::new()
        .route(SIGN_ROUTE, post(handle_post_sign))
        .layer(middleware::from_fn_with_state(limit, limit_requests))
        // After the limit layer, so it is outside of it.
        .layer(middleware::from_fn(trace_request))
        // Added after the layer on purpose: the limit does not apply to the
        // health check, so a busy service still answers it.
        .route("/healthz", get(handle_get_healthz))
        .with_state(state)
}

/// The liveness check. It answers `200` with an empty body when the process
/// serves HTTP. It does not call the HSM, so it does not show that signing
/// works.
async fn handle_get_healthz() -> StatusCode {
    StatusCode::OK
}

/// Sign the payload on a blocking thread, because the HSM backend is
/// synchronous. Maps the backend errors to API errors. It fails with
/// `ApiError::Timeout` if no session is free before the pool connection
/// timeout.
///
/// The blocking thread has no current span, so the closure enters the span of
/// this function. Without that, the spans of the backend would start new traces.
#[instrument(skip(state, payload, algorithm), fields(algorithm = algorithm.name()))]
async fn sign_blocking<B>(
    state: &Arc<AppState<B>>,
    key_id: String,
    algorithm: Algorithm,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ApiError>
where
    B: HsmBackend,
{
    let state = Arc::clone(state);
    let span = Span::current();
    tokio::task::spawn_blocking(move || {
        span.in_scope(|| {
            state
                .hsm_backend
                .sign(&key_id, algorithm, &payload)
                .map_err(|e| match e {
                    HsmBackendError::KeyNotFound(_) => ApiError::KeyNotFound,
                    HsmBackendError::Checkout(_) => ApiError::Timeout,
                    e => ApiError::Internal(e.to_string()),
                })
        })
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
}

/// Handle `POST /v1/sign`. The span records the `outcome` of the request.
#[instrument(
    skip(state, request),
    fields(outcome = tracing::field::Empty, otel.status_code = tracing::field::Empty)
)]
async fn handle_post_sign<B>(
    State(state): State<Arc<AppState<B>>>,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError>
where
    B: HsmBackend,
{
    trace!("POST /v1/sign");
    let result = sign_request(&state, request).await;
    // A field can be recorded only once, so each path records `outcome` once.
    let span = Span::current();
    match &result {
        Ok(_) => span.record("outcome", "ok"),
        Err(err) => {
            if matches!(err, ApiError::Internal(_) | ApiError::Timeout) {
                span.record("otel.status_code", "ERROR");
            }
            span.record("outcome", err.outcome())
        }
    };
    result
}

/// Decode the payload, sign it and build the response.
async fn sign_request<B>(
    state: &Arc<AppState<B>>,
    request: SignRequest,
) -> Result<Json<SignResponse>, ApiError>
where
    B: HsmBackend,
{
    let start = Instant::now();
    let decoded_payload = BASE64.decode(&request.payload)?;

    let signature = sign_blocking(
        state,
        request.key_id.clone(),
        request.algorithm,
        decoded_payload,
    )
    .await?;

    let response = SignResponse {
        key_id: request.key_id,
        algorithm: request.algorithm,
        signature: BASE64.encode(signature),
        duration_ms: start.elapsed().as_millis() as u64,
    };
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use r2d2_cryptoki::r2d2;
    use r2d2_cryptoki::r2d2::ManageConnection;
    use tower::ServiceExt;

    use super::*;
    use crate::hsm_backend::MockHsmBackend;

    fn state_with(backend: MockHsmBackend) -> State<Arc<AppState<MockHsmBackend>>> {
        let config = Config::for_test("example", "test-pin");
        let app_state = AppState::try_new(&config, backend).expect("unable to build the state");
        State(Arc::new(app_state))
    }

    #[tokio::test]
    async fn sign_blocking_returns_the_signature() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .withf(|key_id, _, payload| key_id == "example" && payload == b"hello")
            .times(1)
            .returning(|_, _, _| Ok(vec![1, 2, 3]));
        let state = state_with(backend).0;

        let signature = sign_blocking(
            &state,
            "example".into(),
            Algorithm::EcdsaP256Sha256,
            b"hello".to_vec(),
        )
        .await
        .expect("expected a signature");

        assert_eq!(signature, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn sign_blocking_maps_key_not_found() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .times(1)
            .returning(|key_id, _, _| Err(HsmBackendError::KeyNotFound(key_id.to_string())));
        let state = state_with(backend).0;

        let err = sign_blocking(
            &state,
            "no-such-key".into(),
            Algorithm::EcdsaP256Sha256,
            vec![],
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ApiError::KeyNotFound), "got {err:?}");
    }

    #[tokio::test]
    async fn sign_blocking_maps_other_backend_errors_to_internal() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .times(1)
            .returning(|_, _, _| Err(HsmBackendError::AmbiguousKey("secret-detail".into())));
        let state = state_with(backend).0;

        let err = sign_blocking(&state, "example".into(), Algorithm::EcdsaP256Sha256, vec![])
            .await
            .unwrap_err();

        // The cause is kept for the log. The client message does not show it.
        assert!(
            matches!(&err, ApiError::Internal(cause) if cause.contains("secret-detail")),
            "got {err:?}"
        );
        assert_eq!(err.to_string(), "Internal error");
    }

    #[tokio::test]
    async fn sign_blocking_maps_a_panic_in_the_backend_to_internal() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .times(1)
            .returning(|_, _, _| panic!("the backend panicked"));
        let state = state_with(backend).0;

        let err = sign_blocking(&state, "example".into(), Algorithm::EcdsaP256Sha256, vec![])
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::Internal(_)), "got {err:?}");
    }

    /// A connection manager that never opens a connection.
    struct NeverConnects;

    impl ManageConnection for NeverConnects {
        type Connection = ();
        type Error = std::io::Error;

        fn connect(&self) -> Result<(), std::io::Error> {
            Err(std::io::Error::other("no connection"))
        }

        fn is_valid(&self, _: &mut ()) -> Result<(), std::io::Error> {
            Ok(())
        }

        fn has_broken(&self, _: &mut ()) -> bool {
            false
        }
    }

    /// The error of a pool that has no free session when the wait ends. It is
    /// the real error that `r2d2` gives, because `r2d2::Error` has no
    /// constructor.
    fn checkout_error() -> r2d2::Error {
        let pool = r2d2::Pool::builder()
            .min_idle(Some(0))
            .build_unchecked(NeverConnects);
        pool.get_timeout(std::time::Duration::from_millis(10))
            .map(|_| ())
            .expect_err("the pool has no connection")
    }

    #[tokio::test]
    async fn sign_blocking_fails_with_a_timeout_when_no_session_is_free() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .times(1)
            .returning(|_, _, _| Err(HsmBackendError::Checkout(checkout_error())));
        let state = state_with(backend).0;

        let err = sign_blocking(&state, "example".into(), Algorithm::EcdsaP256Sha256, vec![])
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::Timeout), "got {err:?}");
    }

    #[tokio::test]
    async fn handle_post_sign_answers_504_when_no_session_is_free() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .times(1)
            .returning(|_, _, _| Err(HsmBackendError::Checkout(checkout_error())));

        let err = handle_post_sign(state_with(backend), request("example"))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "Request timed out");
        assert_eq!(err.into_response().status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn handle_post_sign_echoes_the_payload() {
        let request = SignRequest {
            key_id: "example".to_string(),
            algorithm: Algorithm::EcdsaP256Sha256,
            payload: "aGVsbG8gd29ybGQ=".to_string(), // "hello world"
        };

        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .withf(|key_id, _, payload| key_id == "example" && payload == b"hello world")
            .times(1)
            .returning(|_, _, payload| Ok(payload.to_vec()));

        let Json(response) = handle_post_sign(state_with(backend), Json(request))
            .await
            .expect("Expected Ok(Json(SignResponse))");

        assert_eq!(response.key_id, "example");
        assert_eq!(response.algorithm, Algorithm::EcdsaP256Sha256);
        // The mock returns the payload as the signature.
        assert_eq!(response.signature, "aGVsbG8gd29ybGQ=");
    }

    #[tokio::test]
    async fn handle_post_sign_gives_the_requested_algorithm_to_the_backend() {
        let cases = [
            (Algorithm::EcdsaP256Sha256, "ECDSA_P256_SHA256"),
            (Algorithm::EcdsaP384Sha384, "ECDSA_P384_SHA384"),
            (Algorithm::EcdsaP521Sha512, "ECDSA_P521_SHA512"),
            (Algorithm::RsaPkcs1Sha256, "RSA_PKCS1_SHA256"),
        ];
        for (expected, name) in cases {
            let request: SignRequest = serde_json::from_str(&format!(
                r#"{{"key_id": "example", "algorithm": "{name}", "payload": "aGVsbG8="}}"#
            ))
            .expect("the request is valid");
            let mut backend = MockHsmBackend::new();
            backend
                .expect_sign()
                .withf(move |_, algorithm, _| *algorithm == expected)
                .times(1)
                .returning(|_, _, _| Ok(vec![1]));

            let Json(response) = handle_post_sign(state_with(backend), Json(request))
                .await
                .expect("Expected Ok(Json(SignResponse))");

            assert_eq!(response.algorithm, expected);
        }
    }

    #[tokio::test]
    async fn handle_post_sign_invalid_base64_payload() {
        let request = SignRequest {
            key_id: "example".to_string(),
            algorithm: Algorithm::EcdsaP256Sha256,
            payload: "invalid_base64".to_string(),
        };

        // The payload is rejected before the backend is called.
        let mut backend = MockHsmBackend::new();
        backend.expect_sign().never();

        let result = handle_post_sign(state_with(backend), Json(request)).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ApiError::PayloadBase64DecodingError(_)),
            "Expected PayloadBase64DecodingError, got {err:?}"
        );
    }

    fn request(key_id: &str) -> Json<SignRequest> {
        Json(SignRequest {
            key_id: key_id.to_string(),
            algorithm: Algorithm::EcdsaP256Sha256,
            payload: "aGVsbG8gd29ybGQ=".to_string(), // "hello world"
        })
    }

    #[tokio::test]
    async fn handle_post_sign_unknown_key() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .withf(|key_id, _, _| key_id == "no-such-key")
            .times(1)
            .returning(|key_id, _, _| Err(HsmBackendError::KeyNotFound(key_id.to_string())));

        let err = handle_post_sign(state_with(backend), request("no-such-key"))
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::KeyNotFound), "got {err:?}");
        assert_eq!(
            err.into_response().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    /// A router that has one place: no session pool and no queue.
    fn router_with_one_place(backend: MockHsmBackend) -> Router {
        let config = Config::for_test("example", "test-pin").with_max_queue(0);
        assert_eq!(config.max_concurrent_requests(), 1);
        router(&config, state_with(backend).0)
    }

    /// A `POST /v1/sign` request for the router, as HTTP.
    fn http_request() -> Request<Body> {
        Request::post("/v1/sign")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"key_id":"example","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}"#,
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn healthz_answers_200_and_does_not_call_the_backend() {
        // A mock without expectations fails the test if the backend is called.
        let app = router_with_one_place(MockHsmBackend::new());

        let response = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty(), "the body is not empty");
    }

    #[tokio::test]
    async fn healthz_answers_200_when_the_limit_is_reached() {
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let mut backend = MockHsmBackend::new();
        backend.expect_sign().times(1).returning(move |_, _, _| {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(vec![1])
        });
        let app = router_with_one_place(backend);
        let first = tokio::spawn(app.clone().oneshot(http_request()));
        tokio::task::spawn_blocking(move || started_rx.recv())
            .await
            .unwrap()
            .expect("the first request must reach the backend");

        // The only place is in use: a sign request gets 503, the health check 200.
        let sign = app.clone().oneshot(http_request()).await.unwrap();
        let health = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(sign.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(health.status(), StatusCode::OK);

        release_tx.send(()).unwrap();
        first.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn router_answers_503_when_the_limit_is_reached() {
        // The first request stays in the backend until the test lets it go.
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let mut backend = MockHsmBackend::new();
        // Only the first request reaches the backend. A second call fails the
        // test.
        backend.expect_sign().times(1).returning(move |_, _, _| {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(vec![1])
        });
        let app = router_with_one_place(backend);

        let first = tokio::spawn(app.clone().oneshot(http_request()));
        tokio::task::spawn_blocking(move || started_rx.recv())
            .await
            .unwrap()
            .expect("the first request must reach the backend");

        let second = app.clone().oneshot(http_request()).await.unwrap();

        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(second.headers().get(RETRY_AFTER).unwrap(), "1");
        let body = axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"Service busy, try again later"}"#
        );

        release_tx.send(()).unwrap();
        let first = first.await.unwrap().unwrap();
        assert_eq!(first.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_gives_the_place_back_when_a_request_ends() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .times(30)
            .returning(|_, _, _| Ok(vec![1, 2, 3]));
        // Only one place. More requests than places, one after another. Each
        // request must free its place, or a request would get 503.
        let app = router_with_one_place(backend);

        for _ in 0..30 {
            let response = app.clone().oneshot(http_request()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn router_gives_the_place_back_when_a_request_fails() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .times(5)
            .returning(|key_id, _, _| Err(HsmBackendError::KeyNotFound(key_id.to_string())));
        let app = router_with_one_place(backend);

        for _ in 0..5 {
            let response = app.clone().oneshot(http_request()).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    #[tokio::test]
    async fn handle_post_sign_sign_fails() {
        let mut backend = MockHsmBackend::new();
        backend
            .expect_sign()
            .times(1)
            .returning(|_, _, _| Err(HsmBackendError::AmbiguousKey("secret-detail".into())));

        let err = handle_post_sign(state_with(backend), request("example"))
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::Internal(_)), "got {err:?}");
        // The client message must not carry the cause.
        assert_eq!(err.to_string(), "Internal error");
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    mod gauges {
        use super::*;
        use crate::metrics::testing::TestMetrics;

        /// A router with one place, that records its metrics in `metrics`.
        fn router_with_metrics(backend: MockHsmBackend, metrics: &Metrics) -> Router {
            let config = Config::for_test("example", "test-pin").with_max_queue(0);
            let state = AppState::try_new(&config, backend)
                .expect("unable to build the state")
                .with_metrics(metrics.clone());
            router(&config, Arc::new(state))
        }

        #[tokio::test]
        async fn in_flight_counts_the_requests_in_the_service_and_not_the_rejected_ones() {
            let test = TestMetrics::new();
            let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let mut backend = MockHsmBackend::new();
            backend.expect_sign().times(1).returning(move |_, _, _| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(vec![1])
            });
            let app = router_with_metrics(backend, &test.metrics);
            assert_eq!(test.value("hsm_signing.requests.in_flight"), None);

            let first = tokio::spawn(app.clone().oneshot(http_request()));
            tokio::task::spawn_blocking(move || started_rx.recv())
                .await
                .unwrap()
                .expect("the first request must reach the backend");
            assert_eq!(test.value("hsm_signing.requests.in_flight"), Some(1));

            // The only place is taken: this request gets 503 and is not counted.
            let second = app.clone().oneshot(http_request()).await.unwrap();
            assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(test.value("hsm_signing.requests.in_flight"), Some(1));

            release_tx.send(()).unwrap();
            first.await.unwrap().unwrap();
            assert_eq!(test.value("hsm_signing.requests.in_flight"), Some(0));
        }

        #[tokio::test]
        async fn in_flight_goes_back_to_zero_after_a_failed_request() {
            let test = TestMetrics::new();
            let mut backend = MockHsmBackend::new();
            backend
                .expect_sign()
                .times(1)
                .returning(|_, _, _| Err(HsmBackendError::AmbiguousKey("a".into())));
            let app = router_with_metrics(backend, &test.metrics);

            let response = app.oneshot(http_request()).await.unwrap();

            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(test.value("hsm_signing.requests.in_flight"), Some(0));
        }
    }

    mod spans {
        //! The spans that a request makes. They share one global in-memory
        //! exporter, so each test sends its own `traceparent` with a unique
        //! trace id and reads only the spans of that trace.

        use opentelemetry::trace::Status;
        use opentelemetry_sdk::trace::SpanData;

        use super::*;
        use crate::telemetry::testing;

        /// A `POST /v1/sign` request with a `traceparent` header. The trace id
        /// is the `trace_id` and the parent span id is always `PARENT_SPAN_ID`.
        fn traced_request(key_id: &str, trace_id: &str) -> Request<Body> {
            Request::post("/v1/sign")
                .header("content-type", "application/json")
                .header("traceparent", format!("00-{trace_id}-{PARENT_SPAN_ID}-01"))
                .body(Body::from(format!(
                    r#"{{"key_id":"{key_id}","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}}"#
                )))
                .unwrap()
        }

        const PARENT_SPAN_ID: &str = "00f067aa0ba902b7";

        /// The finished spans of one trace.
        fn spans_of(trace_id: &str) -> Vec<SpanData> {
            testing::finished_spans()
                .into_iter()
                .filter(|span| span.span_context.trace_id().to_string() == trace_id)
                .collect()
        }

        /// The one span with this name.
        fn span_named<'a>(spans: &'a [SpanData], name: &str) -> &'a SpanData {
            let mut found = spans.iter().filter(|span| span.name == name);
            let span = found
                .next()
                .unwrap_or_else(|| panic!("no span named {name:?} in {spans:#?}"));
            assert!(found.next().is_none(), "more than one span named {name:?}");
            span
        }

        fn is_error(span: &SpanData) -> bool {
            matches!(span.status, Status::Error { .. })
        }

        #[tokio::test]
        async fn a_request_makes_a_tree_of_spans_in_the_trace_of_the_caller() {
            testing::exporter();
            let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
            let mut backend = MockHsmBackend::new();
            // The backend runs on a blocking thread. Its span must still be a
            // child of `sign_blocking`.
            backend.expect_sign().times(1).returning(|_, _, _| {
                tracing::info_span!("mock_backend").in_scope(|| Ok(vec![1, 2, 3]))
            });
            let app = router_with_one_place(backend);

            let response = app
                .oneshot(traced_request("span-tree-key", trace_id))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let spans = spans_of(trace_id);
            let http = span_named(&spans, "POST /v1/sign");
            let handler = span_named(&spans, "handle_post_sign");
            let blocking = span_named(&spans, "sign_blocking");
            let backend = span_named(&spans, "mock_backend");

            // The server span joins the trace of the caller.
            assert_eq!(http.parent_span_id.to_string(), PARENT_SPAN_ID);
            assert_eq!(handler.parent_span_id, http.span_context.span_id());
            assert_eq!(blocking.parent_span_id, handler.span_context.span_id());
            assert_eq!(backend.parent_span_id, blocking.span_context.span_id());

            assert_eq!(testing::attribute(http, "http.route").unwrap(), "/v1/sign");
            assert_eq!(
                testing::attribute(http, "http.response.status_code").unwrap(),
                "200"
            );
            assert_eq!(testing::attribute(handler, "outcome").unwrap(), "ok");
            assert_eq!(
                testing::attribute(blocking, "algorithm").unwrap(),
                "ECDSA_P256_SHA256"
            );
            assert!(
                testing::attribute(blocking, "key_id")
                    .unwrap()
                    .contains("span-tree-key")
            );
            assert!(!is_error(http) && !is_error(handler));
        }

        #[tokio::test]
        async fn an_unknown_key_is_an_outcome_but_not_a_span_error() {
            testing::exporter();
            let trace_id = "4bf92f3577b34da6a3ce929d0e0e4737";
            let mut backend = MockHsmBackend::new();
            backend
                .expect_sign()
                .times(1)
                .returning(|key_id, _, _| Err(HsmBackendError::KeyNotFound(key_id.to_string())));
            let app = router_with_one_place(backend);

            let response = app
                .oneshot(traced_request("no-such-key", trace_id))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

            let spans = spans_of(trace_id);
            let handler = span_named(&spans, "handle_post_sign");
            assert_eq!(
                testing::attribute(handler, "outcome").unwrap(),
                "key_not_found"
            );
            assert!(!is_error(handler));
        }

        #[tokio::test]
        async fn a_checkout_timeout_is_an_error_span_with_the_outcome_timeout() {
            testing::exporter();
            let trace_id = "4bf92f3577b34da6a3ce929d0e0e4738";
            let mut backend = MockHsmBackend::new();
            backend
                .expect_sign()
                .times(1)
                .returning(|_, _, _| Err(HsmBackendError::Checkout(checkout_error())));
            let app = router_with_one_place(backend);

            let response = app
                .oneshot(traced_request("timeout-key", trace_id))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);

            let spans = spans_of(trace_id);
            let http = span_named(&spans, "POST /v1/sign");
            let handler = span_named(&spans, "handle_post_sign");
            assert_eq!(testing::attribute(handler, "outcome").unwrap(), "timeout");
            assert!(is_error(handler));
            assert!(is_error(http));
        }

        #[tokio::test]
        async fn a_bad_payload_is_a_bad_request_outcome() {
            testing::exporter();
            let trace_id = "4bf92f3577b34da6a3ce929d0e0e4739";
            let backend = MockHsmBackend::new();
            let app = router_with_one_place(backend);
            let request = Request::post("/v1/sign")
                .header("content-type", "application/json")
                .header("traceparent", format!("00-{trace_id}-{PARENT_SPAN_ID}-01"))
                .body(Body::from(
                    r#"{"key_id":"example","algorithm":"ECDSA_P256_SHA256","payload":"***"}"#,
                ))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            let spans = spans_of(trace_id);
            let handler = span_named(&spans, "handle_post_sign");
            assert_eq!(
                testing::attribute(handler, "outcome").unwrap(),
                "bad_request"
            );
            // The backend was not called, so there is no `sign_blocking` span.
            assert!(spans.iter().all(|span| span.name != "sign_blocking"));
        }

        #[tokio::test]
        async fn a_rejected_request_has_a_span_marked_rejected() {
            testing::exporter();
            let trace_id = "4bf92f3577b34da6a3ce929d0e0e4740";
            let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let mut backend = MockHsmBackend::new();
            backend.expect_sign().times(1).returning(move |_, _, _| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(vec![1])
            });
            let app = router_with_one_place(backend);

            let first = tokio::spawn(app.clone().oneshot(http_request()));
            tokio::task::spawn_blocking(move || started_rx.recv())
                .await
                .unwrap()
                .expect("the first request must reach the backend");

            let second = app
                .clone()
                .oneshot(traced_request("rejected-key", trace_id))
                .await
                .unwrap();
            assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);

            let spans = spans_of(trace_id);
            let http = span_named(&spans, "POST /v1/sign");
            assert_eq!(testing::attribute(http, "rejected").unwrap(), "true");
            assert_eq!(
                testing::attribute(http, "http.response.status_code").unwrap(),
                "503"
            );
            assert!(is_error(http));
            // The handler never ran.
            assert!(spans.iter().all(|span| span.name != "handle_post_sign"));

            release_tx.send(()).unwrap();
            first.await.unwrap().unwrap();
        }
    }
}
