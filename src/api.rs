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
use axum::routing::post;
use base64::Engine;
use base64::engine::GeneralPurpose;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::Semaphore;
use tracing::instrument;
use tracing::trace;

use crate::app_state::AppState;
use crate::config::Config;
use crate::hsm_backend::HsmBackend;
use crate::hsm_backend::HsmBackendError;

/// The algorithm to use for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "ECDSA_P256_SHA256")]
    EcdsaP256Sha256,
}

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
            ApiError::Timeout => StatusCode::GATEWAY_TIMEOUT,
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
async fn limit_requests(
    State(places): State<Arc<Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(_place) = places.try_acquire() else {
        return ApiError::Busy.into_response();
    };
    next.run(request).await
}

/// Build the router with all the routes of the API.
///
/// At most `config.max_concurrent_requests()` requests are in the service at
/// the same time (see `limit_requests`).
pub fn router<B>(config: &Config, state: Arc<AppState<B>>) -> Router
where
    B: HsmBackend,
{
    let places = Arc::new(Semaphore::new(config.max_concurrent_requests()));
    Router::new()
        .route("/v1/sign", post(handle_post_sign))
        .layer(middleware::from_fn_with_state(places, limit_requests))
        .with_state(state)
}

/// Sign the payload on a blocking thread, because the HSM backend is
/// synchronous. Maps the backend errors to API errors. It fails with
/// `ApiError::Timeout` if no session is free before the pool connection
/// timeout.
#[instrument(skip(state, payload))]
async fn sign_blocking<B>(
    state: &Arc<AppState<B>>,
    key_id: String,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ApiError>
where
    B: HsmBackend,
{
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || {
        state
            .hsm_backend
            .sign(&key_id, &payload)
            .map_err(|e| match e {
                HsmBackendError::KeyNotFound(_) => ApiError::KeyNotFound,
                HsmBackendError::Checkout(_) => ApiError::Timeout,
                e => ApiError::Internal(e.to_string()),
            })
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
}

#[instrument(skip(state, request))]
async fn handle_post_sign<B>(
    State(state): State<Arc<AppState<B>>>,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError>
where
    B: HsmBackend,
{
    trace!("POST /v1/sign");
    let start = Instant::now();
    let decoded_payload = BASE64.decode(&request.payload)?;

    let signature = sign_blocking(&state, request.key_id.clone(), decoded_payload).await?;

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
            .withf(|key_id, payload| key_id == "example" && payload == b"hello")
            .times(1)
            .returning(|_, _| Ok(vec![1, 2, 3]));
        let state = state_with(backend).0;

        let signature = sign_blocking(&state, "example".into(), b"hello".to_vec())
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
            .returning(|key_id, _| Err(HsmBackendError::KeyNotFound(key_id.to_string())));
        let state = state_with(backend).0;

        let err = sign_blocking(&state, "no-such-key".into(), vec![])
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
            .returning(|_, _| Err(HsmBackendError::AmbiguousKey("secret-detail".into())));
        let state = state_with(backend).0;

        let err = sign_blocking(&state, "example".into(), vec![])
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
            .returning(|_, _| panic!("the backend panicked"));
        let state = state_with(backend).0;

        let err = sign_blocking(&state, "example".into(), vec![])
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
            .returning(|_, _| Err(HsmBackendError::Checkout(checkout_error())));
        let state = state_with(backend).0;

        let err = sign_blocking(&state, "example".into(), vec![])
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
            .returning(|_, _| Err(HsmBackendError::Checkout(checkout_error())));

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
            .withf(|key_id, payload| key_id == "example" && payload == b"hello world")
            .times(1)
            .returning(|_, payload| Ok(payload.to_vec()));

        let Json(response) = handle_post_sign(state_with(backend), Json(request))
            .await
            .expect("Expected Ok(Json(SignResponse))");

        assert_eq!(response.key_id, "example");
        assert_eq!(response.algorithm, Algorithm::EcdsaP256Sha256);
        // The mock returns the payload as the signature.
        assert_eq!(response.signature, "aGVsbG8gd29ybGQ=");
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
            .withf(|key_id, _| key_id == "no-such-key")
            .times(1)
            .returning(|key_id, _| Err(HsmBackendError::KeyNotFound(key_id.to_string())));

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
    async fn router_answers_503_when_the_limit_is_reached() {
        // The first request stays in the backend until the test lets it go.
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let mut backend = MockHsmBackend::new();
        // Only the first request reaches the backend. A second call fails the
        // test.
        backend.expect_sign().times(1).returning(move |_, _| {
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
            .returning(|_, _| Ok(vec![1, 2, 3]));
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
            .returning(|key_id, _| Err(HsmBackendError::KeyNotFound(key_id.to_string())));
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
            .returning(|_, _| Err(HsmBackendError::AmbiguousKey("secret-detail".into())));

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
}
