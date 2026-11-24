// body_budget.rs — Tower middleware bounding request-body memory.
//
// Every buffered body is expanded into a serde_json tree, cloned for admission and
// patching, and mirrored into the watch ring, so the memory a request costs scales with
// its body size, not with the request count the inflight pools bound. This layer:
//   - rejects a declared Content-Length above MAX_BODY_BYTES with 413 before any body
//     byte is read;
//   - reserves body bytes from a shared budget incrementally, as each chunk arrives, and
//     holds them for the life of the request; a slow client therefore holds only what it
//     has sent. When the budget is exhausted mid-body the request is answered 429 +
//     Retry-After;
//     Accepted: three concurrent maximum-size bodies can each take 2 MiB and all end in
//     429; clients retry, and the budget bounds memory rather than guaranteeing admission;
//   - answers 504 Timeout when the body read deadline (see inflight.rs) fired, whatever
//     the handler made of the failed read;
//   - turns the bare-text 413 that axum's body extractors (and several handlers) emit
//     into the Status object kubectl and client-go expect.
//
// Streamed bodies (exec, attach, log, portforward, watch) are not metered. Proxy
// requests are: their handlers buffer the whole body before dialling upstream.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use axum::response::IntoResponse as _;
use futures_util::StreamExt as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::Layer;
use tower_service::Service;

use crate::auth::{is_long_running_request, is_proxy_request};
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

fn is_metered(req: &Request<Body>) -> bool {
    !is_long_running_request(req.method(), req.uri().path(), req.uri().query())
        || is_proxy_request(req.uri().path())
}

fn too_large(limit: usize) -> Response<Body> {
    Status::request_entity_too_large(format!("Request entity too large: limit is {limit} bytes"))
        .into_response()
}

/// Budget bytes one request has taken so far. Shared by the body stream (which adds to it)
/// and the request future (which outlives the stream's last read), so the bytes return to
/// the budget only when both are gone: handler finished, timed out, or client disconnected.
struct Held {
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    exhausted: AtomicBool,
    timed_out: AtomicBool,
}

fn meter(body: Body, budget: Arc<Semaphore>, held: Arc<Held>) -> Body {
    let frames = futures_util::stream::unfold(
        (body.into_data_stream(), budget, held),
        |(mut s, budget, held)| async move {
            let item = s.next().await?;
            if let Err(e) = &item {
                if crate::inflight::is_body_timeout(e) {
                    held.timed_out.store(true, Ordering::SeqCst);
                }
            }
            let item = item.and_then(|chunk| {
                let Ok(p) = Arc::clone(&budget).try_acquire_many_owned(chunk.len() as u32) else {
                    held.exhausted.store(true, Ordering::SeqCst);
                    return Err(axum::Error::new(std::io::Error::other(
                        "request body budget exhausted",
                    )));
                };
                let mut slot = held.permit.lock().unwrap();
                match slot.as_mut() {
                    Some(have) => have.merge(p),
                    None => *slot = Some(p),
                }
                Ok(chunk)
            });
            Some((item.map_err(axum::BoxError::from), (s, budget, held)))
        },
    );
    Body::from_stream(frames)
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

        let held = Arc::new(Held {
            permit: Mutex::new(None),
            exhausted: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
        });
        let req = if is_metered(&req) {
            let budget = Arc::clone(&self.budget);
            let held = Arc::clone(&held);
            req.map(|b| meter(b, budget, held))
        } else {
            req
        };

        Box::pin(async move {
            let mut resp = inner.call(req).await;
            if held.exhausted.load(Ordering::SeqCst) {
                crate::metrics::INFLIGHT_REJECTED_TOTAL
                    .with_label_values(&["body_bytes"])
                    .inc();
                return Ok(Status::too_many_requests_retry_after(
                    "Too many requests".to_owned(),
                    1,
                )
                .into_response());
            }
            if held.timed_out.load(Ordering::SeqCst) {
                return Ok(Status::gateway_timeout(
                    "Timeout: request did not complete within the allotted timeout".to_owned(),
                )
                .into_response());
            }
            if let Ok(r) = resp.as_mut() {
                if r.status() == StatusCode::PAYLOAD_TOO_LARGE
                    && r.headers().get(header::CONTENT_TYPE)
                        != Some(&HeaderValue::from_static("application/json"))
                {
                    *r = too_large(crate::MAX_BODY_BYTES);
                }
            }
            resp
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
        const MIB: usize = 1024 * 1024;
        let (router, layer) = app();
        let mut senders = Vec::new();
        let mut pending = Vec::new();
        for _ in 0..2 {
            let (req, tx) = trickle_req(CM, 3 * MIB);
            tx.send(Ok(Bytes::from(vec![b'a'; 2 * MIB]))).await.unwrap();
            pending.push(tokio::spawn(router.clone().oneshot(req)));
            senders.push(tx);
        }
        // Mid-body each holds what it has sent (2 MiB), not the 3 MiB it declared.
        settle_until(&layer, 4 * MIB).await;

        let resp = router
            .clone()
            .oneshot(post_req(Body::from(vec![b'a'; MIB]), Some(MIB)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a write that fits in the unsent remainder of the budget was shed"
        );

        for tx in &senders {
            tx.send(Ok(Bytes::from(vec![b'a'; MIB]))).await.unwrap();
        }
        settle_until(&layer, 6 * MIB).await;
        let resp = router
            .clone()
            .oneshot(post_req(Body::from(vec![b'a'; 200]), Some(200)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));

        drop(senders);
        for p in pending {
            assert_eq!(p.await.unwrap().unwrap().status(), StatusCode::OK);
        }
        assert_eq!(
            layer.budget.available_permits(),
            BODY_BUDGET_BYTES,
            "budget must be returned when the holders finish"
        );
        let resp = router
            .oneshot(post_req(Body::from(vec![b'a'; 200]), Some(200)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The limit and budget are sized together (two max-size bodies). Reverting the limit
    /// to the old 4 MiB would let a body past what upstream accepts and shrink the
    /// budget's worth to 1.5 bodies.
    #[test]
    fn body_limit_and_budget_are_pinned() {
        assert_eq!(
            crate::MAX_BODY_BYTES,
            3_145_728,
            "upstream MaxRequestBodyBytes"
        );
        assert_eq!(BODY_BUDGET_BYTES, 2 * crate::MAX_BODY_BYTES);
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

    type Trickle = tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>;

    /// A request whose body arrives only as the returned sender feeds it, as a slow client
    /// would, claiming `declared` bytes up front.
    fn trickle_req(uri: &str, declared: usize) -> (Request<Body>, Trickle) {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let body = Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|c| (c, rx))
        }));
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_LENGTH, declared)
            .body(body)
            .unwrap();
        (req, tx)
    }

    const CM: &str = "/api/v1/namespaces/default/configmaps";

    async fn settle_until(layer: &BodyBudgetLayer, held: usize) {
        for _ in 0..200 {
            if layer.budget.available_permits() == BODY_BUDGET_BYTES - held {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "budget never reached {held} held bytes (available {})",
            layer.budget.available_permits()
        );
    }

    /// Two clients that each declare a maximum-size body but have sent only a KiB must
    /// hold a KiB each. If the declared length were reserved up front, two slow-loris
    /// connections would pin the whole budget and every honest write would get 429.
    #[tokio::test]
    async fn slow_clients_hold_only_the_bytes_they_have_sent() {
        let (router, layer) = app();
        let mut senders = Vec::new();
        let mut pending = Vec::new();
        for _ in 0..2 {
            let (req, tx) = trickle_req(CM, crate::MAX_BODY_BYTES);
            tx.send(Ok(Bytes::from(vec![b'a'; 1024]))).await.unwrap();
            pending.push(tokio::spawn(router.clone().oneshot(req)));
            senders.push(tx);
        }
        settle_until(&layer, 2048).await;

        let n = 1024 * 1024;
        let resp = router
            .clone()
            .oneshot(post_req(Body::from(vec![b'a'; n]), Some(n)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a normal write was shed while slow clients had sent only 2 KiB"
        );
        drop(senders);
        for p in pending {
            let _ = p.await;
        }
    }

    /// A client that vanishes mid-body (connection reset) drops the request future; the
    /// bytes it had sent must return to the budget or disconnects would leak it dry.
    #[tokio::test]
    async fn client_disconnect_mid_body_releases_its_reservation() {
        let (router, layer) = app();
        let (req, tx) = trickle_req(CM, crate::MAX_BODY_BYTES);
        tx.send(Ok(Bytes::from(vec![b'a'; 2048]))).await.unwrap();
        let task = tokio::spawn(router.oneshot(req));
        // Held mid-body is exactly the bytes sent, not the declared length.
        settle_until(&layer, 2048).await;

        task.abort();
        let _ = task.await;
        assert_eq!(
            layer.budget.available_permits(),
            BODY_BUDGET_BYTES,
            "disconnected client kept its body bytes reserved"
        );
        drop(tx);
    }

    async fn stalled_body_is_cut_with_504(uri: &str) {
        let layer = BodyBudgetLayer::new();
        let router = Router::new()
            .fallback(echo_len)
            .layer(layer.clone())
            .layer(crate::inflight::InflightLayer::new());
        let (req, tx) = trickle_req(uri, crate::MAX_BODY_BYTES);
        tx.send(Ok(Bytes::from(vec![b'a'; 1024]))).await.unwrap();
        let task = tokio::spawn(router.clone().oneshot(req));
        settle_until(&layer, 1024).await;

        let n = 1024 * 1024;
        let resp = router
            .oneshot(post_req(Body::from(vec![b'a'; n]), Some(n)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a stalled body must not stop other writes"
        );

        tokio::time::advance(
            crate::inflight::MUTATING_BODY_TIMEOUT + std::time::Duration::from_secs(1),
        )
        .await;
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("stalled body read never ended")
            .unwrap()
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::GATEWAY_TIMEOUT,
            "a stalled body is a timeout, not a size problem"
        );
        let status = status_body(resp).await;
        assert_eq!(status["reason"], "Timeout");
        assert_eq!(status["code"], 504);
        assert_eq!(
            layer.budget.available_permits(),
            BODY_BUDGET_BYTES,
            "timed-out body kept its bytes reserved"
        );
        drop(tx);
    }

    /// A body that stalls past the body deadline must fail the request with 504 and give
    /// its bytes back; otherwise a client that sends a little and goes quiet pins budget
    /// and an inflight seat indefinitely.
    #[tokio::test(start_paused = true)]
    async fn stalled_body_times_out_with_504_and_releases_its_budget() {
        stalled_body_is_cut_with_504(CM).await;
    }

    /// Proxy is exempt from inflight seats but its buffered body draws on the budget, so a
    /// trickling proxy POST must be cut too, or one principal pins the budget indefinitely.
    #[tokio::test(start_paused = true)]
    async fn stalled_proxy_body_times_out_with_504_and_releases_its_budget() {
        stalled_body_is_cut_with_504("/api/v1/namespaces/default/pods/p/proxy/x").await;
    }

    /// Proxy handlers buffer the request body up to the limit, so it must draw on the same
    /// budget; if proxy were exempt, concurrent proxied POSTs would bypass the cap entirely.
    #[tokio::test]
    async fn proxy_bodies_are_metered_and_shed_with_429() {
        let layer = BodyBudgetLayer::new();
        let router = Router::new()
            .fallback(echo_len)
            .layer(layer.clone())
            .layer(DefaultBodyLimit::max(crate::MAX_BODY_BYTES));
        let _held = Arc::clone(&layer.budget)
            .try_acquire_many_owned((BODY_BUDGET_BYTES - 100) as u32)
            .unwrap();

        let mut req = post_req(Body::from(vec![b'a'; 200]), Some(200));
        *req.uri_mut() = "/api/v1/namespaces/default/pods/p/proxy/x".parse().unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
