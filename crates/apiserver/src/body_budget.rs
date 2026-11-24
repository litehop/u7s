// body_budget.rs — Tower middleware bounding request-body memory.
//
// Every buffered body is expanded into a serde_json tree, cloned for admission and
// patching, and mirrored into the watch ring, so the memory a request costs scales with
// its body size, not with the request count the inflight pools bound. This layer:
//   - rejects a declared Content-Length above MAX_BODY_BYTES with 413 before any body
//     byte is read;
//   - reserves the declared length (MAX_BODY_BYTES when the length is unknown) from a
//     shared byte budget for the life of the request, and answers 429 + Retry-After
//     when the budget is exhausted;
//   - turns the bare-text 413 that axum's body extractors (and several handlers) emit
//     into the Status object kubectl and client-go expect.
//
// Long-running requests (proxy, exec, attach, log, portforward, watch) carry streamed
// bodies that outlive the handler's buffering, so they are not reserved.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::body::HttpBody as _;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use axum::response::IntoResponse as _;
use tokio::sync::Semaphore;
use tower::Layer;
use tower_service::Service;

use crate::auth::is_long_running_request;
use crate::status::Status;

/// Bytes of request body that may be buffered across all in-flight requests: two
/// maximum-size bodies. Measured on a 3 MiB ConfigMap of 225k one-byte values, each
/// concurrent create grew the apiserver by roughly 200 MiB (~70x the body), so two bound
/// the worst case near 400 MiB on a 1 GiB host. Ordinary bodies (kubelet status patches,
/// pod creates) cost a few KiB each and never notice the budget.
const BODY_BUDGET_BYTES: usize = 6 * 1024 * 1024;

#[derive(Clone)]
pub struct BodyBudgetLayer {
    budget: Arc<Semaphore>,
}

impl BodyBudgetLayer {
    pub fn new() -> Self {
        BodyBudgetLayer {
            budget: Arc::new(Semaphore::new(BODY_BUDGET_BYTES)),
        }
    }
}

impl<S> Layer<S> for BodyBudgetLayer {
    type Service = BodyBudgetService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyBudgetService {
            inner,
            budget: Arc::clone(&self.budget),
        }
    }
}

#[derive(Clone)]
pub struct BodyBudgetService<S> {
    inner: S,
    budget: Arc<Semaphore>,
}

fn declared_length(req: &Request<Body>) -> Option<usize> {
    req.headers()
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Bytes this request may buffer: the declared length, MAX_BODY_BYTES when a body is
/// coming with no declared length (chunked), zero when there is no body.
fn reservation(req: &Request<Body>) -> usize {
    if is_long_running_request(req.method(), req.uri().path(), req.uri().query()) {
        return 0;
    }
    match declared_length(req) {
        Some(n) => n,
        None if req.body().is_end_stream() => 0,
        None => crate::MAX_BODY_BYTES,
    }
}

fn too_large(limit: usize) -> Response<Body> {
    Status::request_entity_too_large(format!("Request entity too large: limit is {limit} bytes"))
        .into_response()
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S> Service<Request<Body>> for BodyBudgetService<S>
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
        let mut inner = self.inner.clone();

        if declared_length(&req).is_some_and(|n| n > crate::MAX_BODY_BYTES) {
            let resp = too_large(crate::MAX_BODY_BYTES);
            return Box::pin(async move { Ok(resp) });
        }

        let want = reservation(&req);
        let permit = if want == 0 {
            None
        } else {
            match Arc::clone(&self.budget).try_acquire_many_owned(want as u32) {
                Ok(p) => Some(p),
                Err(_) => {
                    crate::metrics::INFLIGHT_REJECTED_TOTAL
                        .with_label_values(&["body_bytes"])
                        .inc();
                    let resp =
                        Status::too_many_requests_retry_after("Too many requests".to_owned(), 1)
                            .into_response();
                    return Box::pin(async move { Ok(resp) });
                }
            }
        };

        Box::pin(async move {
            let _permit = permit;
            let mut resp = inner.call(req).await?;
            if resp.status() == StatusCode::PAYLOAD_TOO_LARGE
                && resp.headers().get(header::CONTENT_TYPE)
                    != Some(&HeaderValue::from_static("application/json"))
            {
                resp = too_large(crate::MAX_BODY_BYTES);
            }
            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::DefaultBodyLimit;
    use axum::http::Method;
    use axum::routing::post;
    use axum::Router;
    use bytes::Bytes;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tower::ServiceExt as _;

    async fn echo_len(body: Bytes) -> String {
        body.len().to_string()
    }

    fn app() -> (Router, BodyBudgetLayer) {
        let layer = BodyBudgetLayer::new();
        let router = Router::new()
            .route("/api/v1/namespaces/default/configmaps", post(echo_len))
            .layer(layer.clone())
            .layer(DefaultBodyLimit::max(crate::MAX_BODY_BYTES));
        (router, layer)
    }

    fn post_req(body: Body, content_length: Option<usize>) -> Request<Body> {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/namespaces/default/configmaps");
        if let Some(n) = content_length {
            b = b.header(header::CONTENT_LENGTH, n);
        }
        b.body(body).unwrap()
    }

    async fn status_body(resp: Response<Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).expect("413 body must be a Status object, not text")
    }

    /// A declared oversize body must be refused from the headers alone: if the server
    /// read it first, one request would still pin the whole body in memory.
    #[tokio::test]
    async fn oversize_content_length_gets_413_without_reading_the_body() {
        let polled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&polled);
        let body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
            flag.store(true, Ordering::SeqCst);
            Poll::Ready(Some(Ok::<_, std::io::Error>(Bytes::from_static(b"x"))))
        }));
        let (router, _) = app();
        let resp = router
            .oneshot(post_req(body, Some(crate::MAX_BODY_BYTES + 1)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            !polled.load(Ordering::SeqCst),
            "the oversize body was read before being rejected"
        );
        let status = status_body(resp).await;
        assert_eq!(status["reason"], "RequestEntityTooLarge");
        assert_eq!(status["code"], 413);
    }

    /// A client that omits Content-Length (chunked) must not get past the limit; kubectl
    /// would otherwise see a 200 for a body that the limit says is invalid, or the server
    /// would buffer without bound.
    #[tokio::test]
    async fn oversize_chunked_body_gets_413_status_object() {
        let chunk = Bytes::from(vec![b'a'; 1024 * 1024]);
        let stream = futures_util::stream::iter(
            (0..=crate::MAX_BODY_BYTES / chunk.len())
                .map(move |_| Ok::<_, std::io::Error>(chunk.clone())),
        );
        let (router, _) = app();
        let resp = router
            .oneshot(post_req(Body::from_stream(stream), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let status = status_body(resp).await;
        assert_eq!(status["reason"], "RequestEntityTooLarge");
    }

    /// Writes beyond the shared byte budget are shed with a retryable 429 instead of
    /// being buffered, and the bytes return to the budget when the holder finishes;
    /// otherwise a few large concurrent creates would exhaust a small host's memory.
    #[tokio::test]
    async fn concurrent_large_bodies_over_budget_get_429_and_budget_is_returned() {
        let (router, layer) = app();
        let held = Arc::clone(&layer.budget)
            .try_acquire_many_owned((BODY_BUDGET_BYTES - 100) as u32)
            .unwrap();

        let resp = router
            .clone()
            .oneshot(post_req(Body::from(vec![b'a'; 200]), Some(200)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));

        let small = router
            .clone()
            .oneshot(post_req(Body::from(vec![b'a'; 50]), Some(50)))
            .await
            .unwrap();
        assert_eq!(
            small.status(),
            StatusCode::OK,
            "bytes inside the budget must pass"
        );

        drop(held);
        let resp = router
            .oneshot(post_req(Body::from(vec![b'a'; 200]), Some(200)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "budget must be returned on drop"
        );
        assert_eq!(layer.budget.available_permits(), BODY_BUDGET_BYTES);
    }

    /// A body exactly at the limit is what kubectl may legitimately send for a large
    /// ConfigMap or custom resource; rejecting it would break objects etcd accepts.
    #[tokio::test]
    async fn body_exactly_at_the_limit_is_accepted() {
        let (router, _) = app();
        let n = crate::MAX_BODY_BYTES;
        let resp = router
            .oneshot(post_req(Body::from(vec![b'a'; n]), Some(n)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
