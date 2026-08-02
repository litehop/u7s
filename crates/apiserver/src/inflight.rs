// inflight.rs — Tower middleware for concurrent request limiting.
//
// Enforces two limits:
//   - MAX_INFLIGHT (50): total concurrent requests across all methods.
//   - MAX_MUTATING (20): concurrent requests for mutating methods
//     (POST, PUT, PATCH, DELETE).
//
// When a limit is exceeded the request is rejected immediately with
// HTTP 429 and a Kubernetes-style Status JSON body.  No queuing.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{header, Method, Request, Response, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::Layer;
use tower_service::Service;

use crate::status::Status;

const MAX_INFLIGHT: usize = 200;
const MAX_MUTATING: usize = 100;

// ---------------------------------------------------------------------------
// InflightLayer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct InflightLayer {
    inflight: Arc<Semaphore>,
    mutating: Arc<Semaphore>,
}

impl InflightLayer {
    pub fn new() -> Self {
        InflightLayer {
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            mutating: Arc::new(Semaphore::new(MAX_MUTATING)),
        }
    }
}

impl<S> Layer<S> for InflightLayer {
    type Service = InflightService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InflightService {
            inner,
            inflight: Arc::clone(&self.inflight),
            mutating: Arc::clone(&self.mutating),
        }
    }
}

// ---------------------------------------------------------------------------
// InflightService
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct InflightService<S> {
    inner: S,
    inflight: Arc<Semaphore>,
    mutating: Arc<Semaphore>,
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn too_many_requests_response(req: &Request<Body>, limit_kind: &str) -> Response<Body> {
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // No other log line ever sees this request — InflightLayer runs before
    // ContentTypeLayer's access log, so a rejected request would otherwise
    // vanish from apiserver.log entirely.
    tracing::warn!(
        method = %req.method(),
        uri = %req.uri(),
        limit_kind,
        user_agent,
        "inflight limit reached, returning 429",
    );
    let status = Status {
        kind: "Status",
        api_version: "v1",
        status: "Failure",
        message: "Too many requests".to_owned(),
        reason: "TooManyRequests",
        code: 429,
        metadata: None,
        details: None,
    };
    let body = serde_json::to_vec(&status).unwrap_or_default();
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S> Service<Request<Body>> for InflightService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mutating = is_mutating(req.method());

        // Try to acquire the total inflight permit (non-blocking).
        let inflight_permit = match Arc::clone(&self.inflight).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let resp = too_many_requests_response(&req, "inflight");
                return Box::pin(async move { Ok(resp) });
            }
        };

        // Try to acquire the mutating permit if applicable.
        let mutating_permit: Option<OwnedSemaphorePermit> = if mutating {
            match Arc::clone(&self.mutating).try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => {
                    // Release inflight permit before returning.
                    drop(inflight_permit);
                    let resp = too_many_requests_response(&req, "mutating");
                    return Box::pin(async move { Ok(resp) });
                }
            }
        } else {
            None
        };

        let mut inner = self.inner.clone();
        Box::pin(async move {
            // Permits are held for the duration of the inner call and dropped
            // when this future completes, automatically releasing the semaphore.
            let _inflight = inflight_permit;
            let _mutating = mutating_permit;
            inner.call(req).await
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, Response, StatusCode};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tower::Layer;
    use tower_service::Service;

    // A minimal no-op inner service that always returns 200.
    #[derive(Clone)]
    struct OkService;

    impl Service<Request<Body>> for OkService {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            Box::pin(async { Ok(Response::builder().status(200).body(Body::empty()).unwrap()) })
        }
    }

    fn make_request(method: Method) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri("/api/v1/namespaces")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_inflight_limit_returns_429() {
        // When all 50 inflight slots are consumed, the 51st request must get 429.
        // This validates that the total concurrency cap is enforced — without it,
        // an unbounded server could OOM under load.
        let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
        let mutating = Arc::new(Semaphore::new(MAX_MUTATING));

        // Exhaust all inflight permits.
        let _permits: Vec<OwnedSemaphorePermit> = (0..MAX_INFLIGHT)
            .map(|_| Arc::clone(&inflight).try_acquire_owned().unwrap())
            .collect();

        let layer = InflightLayer {
            inflight: Arc::clone(&inflight),
            mutating: Arc::clone(&mutating),
        };
        let mut svc = layer.layer(OkService);

        let req = make_request(Method::GET);
        let resp = svc.call(req).await.unwrap();
        // Must be 429 — the inflight limit is hit.
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "must return 429 when inflight limit is exhausted"
        );
    }

    #[tokio::test]
    async fn test_mutating_limit_returns_429() {
        // When all 20 mutating slots are consumed, the 21st mutating request
        // must get 429.  This validates that write concurrency is bounded — without
        // it, 20 concurrent writes could exceed SQLite lock contention budget.
        let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
        let mutating = Arc::new(Semaphore::new(MAX_MUTATING));

        // Exhaust only mutating permits; inflight still has headroom.
        let _permits: Vec<OwnedSemaphorePermit> = (0..MAX_MUTATING)
            .map(|_| Arc::clone(&mutating).try_acquire_owned().unwrap())
            .collect();

        let layer = InflightLayer {
            inflight: Arc::clone(&inflight),
            mutating: Arc::clone(&mutating),
        };
        let mut svc = layer.layer(OkService);

        let req = make_request(Method::POST);
        let resp = svc.call(req).await.unwrap();
        // Must be 429 — the mutating limit is hit even though inflight has room.
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "must return 429 when mutating limit is exhausted"
        );
    }

    #[tokio::test]
    async fn test_read_bypasses_mutating_limit() {
        // GET requests must not consume mutating permits.  A full mutating pool
        // must not block read traffic — reads are never write-limited.
        let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
        let mutating = Arc::new(Semaphore::new(MAX_MUTATING));

        // Exhaust mutating permits.
        let _permits: Vec<OwnedSemaphorePermit> = (0..MAX_MUTATING)
            .map(|_| Arc::clone(&mutating).try_acquire_owned().unwrap())
            .collect();

        let layer = InflightLayer {
            inflight: Arc::clone(&inflight),
            mutating: Arc::clone(&mutating),
        };
        let mut svc = layer.layer(OkService);

        let req = make_request(Method::GET);
        let resp = svc.call(req).await.unwrap();
        // Must succeed — read traffic is not blocked by a full mutating pool.
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET must succeed even when mutating pool is full"
        );
    }

    #[tokio::test]
    async fn test_permits_released_on_completion() {
        // After a request completes, the semaphore permit must be released so
        // subsequent requests are not erroneously rejected.
        let layer = InflightLayer::new();
        let mut svc = layer.layer(OkService);

        // Fill all inflight slots by making and completing requests serially.
        for _ in 0..MAX_INFLIGHT + 5 {
            let req = make_request(Method::GET);
            let resp = svc.call(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "serial requests must all succeed as permits are released"
            );
        }
    }

    #[tokio::test]
    async fn test_429_response_is_kubernetes_status_json() {
        // The 429 body must be a valid Kubernetes Status object.
        // kubectl and controllers parse this body — wrong format breaks tooling.
        let inflight = Arc::new(Semaphore::new(0)); // immediately exhausted
        let mutating = Arc::new(Semaphore::new(MAX_MUTATING));

        let layer = InflightLayer {
            inflight: Arc::clone(&inflight),
            mutating: Arc::clone(&mutating),
        };
        let mut svc = layer.layer(OkService);

        let req = make_request(Method::GET);
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("body must be valid JSON");

        assert_eq!(json["apiVersion"], "v1");
        assert_eq!(json["kind"], "Status");
        assert_eq!(json["status"], "Failure");
        assert_eq!(json["reason"], "TooManyRequests");
        assert_eq!(json["code"], 429);
    }

    // In-memory sink for tracing-subscriber's fmt layer, so the 429 log test can assert
    // on the rendered field set without adding a tracing-test dependency.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'w> tracing_subscriber::fmt::MakeWriter<'w> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'w self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn test_429_rejection_is_logged_with_method_uri_and_limit_kind() {
        // Before this test existed, an InflightLayer 429 was invisible in apiserver.log:
        // InflightLayer runs before ContentTypeLayer's access log, so a rejected request
        // never reached the only other log line that recorded method/uri/status. Without
        // this warn!, diagnosing rate-limit pressure required forensic reconstruction from
        // request-density timing instead of a grep. If the log call is ever dropped, this
        // test must fail.
        let buf = SharedBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let inflight = Arc::new(Semaphore::new(0)); // immediately exhausted
        let mutating = Arc::new(Semaphore::new(MAX_MUTATING));

        let layer = InflightLayer {
            inflight: Arc::clone(&inflight),
            mutating: Arc::clone(&mutating),
        };
        let mut svc = layer.layer(OkService);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/namespaces")
            .header("user-agent", "e2e.test/v1.34.0")
            .body(Body::empty())
            .unwrap();
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("POST") && log.contains("/api/v1/namespaces"),
            "429 rejection log must record method and uri so operators can identify which \
             request was rejected without cross-referencing response bodies; log was: {log}"
        );
        assert!(
            log.contains("limit_kind") && log.contains("inflight"),
            "429 rejection log must record which cap tripped (inflight vs mutating) — \
             the caller already knows this from which semaphore failed to acquire, and \
             discarding it forces guesswork about which limit needs raising; log was: {log}"
        );
        assert!(
            log.contains("e2e.test/v1.34.0"),
            "429 rejection log must record the user-agent so operators can tell which \
             client (e2e.test vs kube-controller-manager vs kubelet) is generating the \
             rejected load; log was: {log}"
        );
    }
}
