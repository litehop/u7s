// inflight.rs — Tower middleware for concurrent request limiting.
//
// Enforces two limits:
//   - MAX_INFLIGHT (200): total concurrent requests across all methods.
//     Rejected immediately (HTTP 429) when exhausted — reads must fail
//     fast, not queue, so a mutating storm can't stall health checks/watches.
//   - MAX_MUTATING (100): concurrent requests for mutating methods
//     (POST, PUT, PATCH, DELETE). Overflow WAITS for a free permit up to
//     MUTATING_WAIT_TIMEOUT before returning 429 — see that constant's
//     doc comment for why queuing, not instant-reject, is correct here.
//
// The mutating queue is a DELIBERATE minimal subset of Kubernetes' API
// Priority & Fairness (APF): it gives overflow a bounded wait instead of
// an instant reject, but skips APF's FlowSchema/PriorityLevel request
// classification and per-flow shuffle-sharded fairness entirely. u7s is
// single-tenant at its current scale, so the fairness problem APF exists
// to solve — one tenant's burst starving another's — doesn't apply yet.
// Any future ask to add priority levels, multiple queues, or per-flow
// fairness here must first cost-analyze extending this file vs adopting
// upstream APF; skipping that analysis is how this accretes into a worse,
// hand-rolled APF one feature at a time.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, Response, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::Layer;
use tower_service::Service;

use crate::status::Status;

const MAX_INFLIGHT: usize = 200;
const MAX_MUTATING: usize = 100;

/// Max time a mutating request waits for a free permit before 429ing.
///
/// The storm this exists for is exactly 300 concurrent DELETEs (a
/// controller bulk-deleting objects, or a test spec doing the same with
/// no client-side throttling). Measured directly against a live VM
/// stack with 300 genuinely-concurrent DELETEs (curl `--parallel`, not a
/// forked-process loop — those don't actually overlap enough to matter):
/// the burst drained through the 100-permit semaphore in 0.18-0.28s over
/// three runs. 30s leaves ~100x headroom above that so a legitimate burst
/// never 429s, while still bounding how long a request waits against a
/// genuinely stuck or overloaded backend.
const MUTATING_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Max number of mutating requests allowed to queue for a permit at once.
///
/// tokio's `Semaphore` waiter list is unbounded FIFO — without this cap,
/// a flood arriving faster than permits free up could pile up arbitrarily
/// many waiting requests (each holding an open connection for up to
/// MUTATING_WAIT_TIMEOUT) before ever rejecting anything, trading the old
/// cheap instant-429 for a slow memory-DoS. 512 clears the known 300-DELETE
/// storm with headroom while staying small enough to bound worst-case
/// memory use.
const MAX_MUTATING_QUEUE_DEPTH: usize = 512;

// ---------------------------------------------------------------------------
// InflightLayer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct InflightLayer {
    inflight: Arc<Semaphore>,
    mutating: Arc<Semaphore>,
    mutating_waiters: Arc<AtomicUsize>,
}

impl InflightLayer {
    pub fn new() -> Self {
        InflightLayer {
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            mutating: Arc::new(Semaphore::new(MAX_MUTATING)),
            mutating_waiters: Arc::new(AtomicUsize::new(0)),
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
            mutating_waiters: Arc::clone(&self.mutating_waiters),
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
    mutating_waiters: Arc<AtomicUsize>,
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// RAII counter for a request queued on the mutating semaphore.
///
/// Must decrement on every exit path — permit acquired, timeout elapsed,
/// or the holding future dropped outright (client disconnects while
/// queued). A bare fetch_add/fetch_sub pair without Drop would leak the
/// count whenever a future is cancelled instead of polled to completion,
/// letting MAX_MUTATING_QUEUE_DEPTH's guard ratchet towards permanently
/// rejecting everything after enough disconnects.
struct WaiterGuard(Arc<AtomicUsize>);

impl WaiterGuard {
    fn new(waiters: Arc<AtomicUsize>) -> Self {
        waiters.fetch_add(1, Ordering::SeqCst);
        WaiterGuard(waiters)
    }
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Acquire a mutating permit, waiting up to MUTATING_WAIT_TIMEOUT if the
/// semaphore is momentarily exhausted rather than rejecting on the spot.
/// Returns `Err` if the queue-depth guard trips (fail fast, no wait) or
/// the wait times out (permits stayed exhausted the whole time).
async fn acquire_mutating_permit(
    semaphore: Arc<Semaphore>,
    waiters: Arc<AtomicUsize>,
) -> Result<OwnedSemaphorePermit, ()> {
    // Fast path: a permit is free right now, no need to join the queue.
    if let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() {
        return Ok(permit);
    }

    // Queue-depth guard: tokio's Semaphore waiter list is unbounded FIFO,
    // so admission into the wait itself must be bounded rather than
    // trusting the timeout alone to cap memory (see MAX_MUTATING_QUEUE_DEPTH
    // doc comment).
    if waiters.load(Ordering::SeqCst) >= MAX_MUTATING_QUEUE_DEPTH {
        return Err(());
    }
    let _waiter_guard = WaiterGuard::new(Arc::clone(&waiters));

    match tokio::time::timeout(MUTATING_WAIT_TIMEOUT, semaphore.acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) | Err(_) => Err(()),
    }
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
        let mut inner = self.inner.clone();

        if !is_mutating(req.method()) {
            // Reads: single instant-reject check against the total inflight
            // cap, unchanged — see the module doc comment for why.
            let inflight_permit = match Arc::clone(&self.inflight).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    let resp = too_many_requests_response(&req, "inflight");
                    return Box::pin(async move { Ok(resp) });
                }
            };
            return Box::pin(async move {
                let _inflight = inflight_permit;
                inner.call(req).await
            });
        }

        // Mutating: acquire the (possibly-waited) mutating permit FIRST,
        // then the inflight permit. A queued-but-not-yet-admitted mutating
        // request must NOT hold an inflight permit while it waits — inflight
        // permits are held for up to MUTATING_WAIT_TIMEOUT once acquired
        // this way, and grabbing one before the mutating wait resolves would
        // let a 300-request mutating burst alone exhaust MAX_INFLIGHT (200)
        // purely from requests parked in the mutating queue, instant-429ing
        // read traffic (and any mutation past #200) on a cap this fix
        // deliberately does not touch. Acquiring in mutating-then-inflight
        // order means only requests actually admitted through the 100-permit
        // mutating gate ever compete for inflight capacity, exactly as if
        // they were ordinary reads.
        let mutating_sem = Arc::clone(&self.mutating);
        let mutating_waiters = Arc::clone(&self.mutating_waiters);
        let inflight_sem = Arc::clone(&self.inflight);

        Box::pin(async move {
            let mutating_permit =
                match acquire_mutating_permit(mutating_sem, mutating_waiters).await {
                    Ok(p) => p,
                    Err(()) => {
                        let resp = too_many_requests_response(&req, "mutating");
                        return Ok(resp);
                    }
                };

            let inflight_permit = match inflight_sem.try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    drop(mutating_permit);
                    let resp = too_many_requests_response(&req, "inflight");
                    return Ok(resp);
                }
            };

            // Permits are held for the duration of the inner call and dropped
            // when this future completes, automatically releasing the semaphore.
            let _mutating = mutating_permit;
            let _inflight = inflight_permit;
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
        // When all 200 inflight slots are consumed, the 201st request must get 429.
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
            mutating_waiters: Arc::new(AtomicUsize::new(0)),
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

    #[tokio::test(start_paused = true)]
    async fn test_mutating_overflow_waits_then_429_after_deadline() {
        // Before this fix, the 101st mutating request while all 100 permits
        // were held got an INSTANT 429 (try_acquire_owned, no queue). That is
        // exactly what turns a routine bulk operation (e.g. a controller
        // deleting 300 objects at once) into a guaranteed 429 storm — see
        // acquire_mutating_permit's doc comment. The new contract: it must
        // WAIT for a permit, and only 429 once MUTATING_WAIT_TIMEOUT elapses
        // with no permit freed. Time is paused so this proves the wait
        // happened (virtual time) without the test taking 30 real seconds.
        let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
        let mutating = Arc::new(Semaphore::new(MAX_MUTATING));

        // Exhaust all mutating permits and never release them — nothing will
        // free up, so the request under test must ride out the full deadline.
        let _permits: Vec<OwnedSemaphorePermit> = (0..MAX_MUTATING)
            .map(|_| Arc::clone(&mutating).try_acquire_owned().unwrap())
            .collect();

        let layer = InflightLayer {
            inflight: Arc::clone(&inflight),
            mutating: Arc::clone(&mutating),
            mutating_waiters: Arc::new(AtomicUsize::new(0)),
        };
        let mut svc = layer.layer(OkService);

        let req = make_request(Method::POST);
        let start = tokio::time::Instant::now();
        let resp = svc.call(req).await.unwrap();

        assert!(
            start.elapsed() >= MUTATING_WAIT_TIMEOUT,
            "overflow must wait out the full deadline instead of instant-429ing \
             — a request that 429s before the deadline elapsed didn't queue at all"
        );
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "must still 429 once the deadline elapses with no permit ever freed"
        );
    }

    #[tokio::test]
    async fn test_mutating_burst_of_300_all_queue_and_succeed() {
        // THE regression this fix exists for: csi-hostpath's
        // pvc-deletion-performance spec fires exactly 300 concurrent DELETEs
        // with no client-side throttling. Before this fix, request #101 got
        // an instant 429; the upstream delete goroutine has no panic
        // recovery, so a single 429 crashed the whole test process. A burst
        // this size must all queue behind the 100-permit cap and succeed —
        // zero 429s — or the same crash reproduces.
        let layer = InflightLayer::new();

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..300 {
            let mut svc = layer.layer(OkService);
            tasks.spawn(async move { svc.call(make_request(Method::DELETE)).await.unwrap() });
        }

        let mut rejected = 0;
        let mut succeeded = 0;
        while let Some(res) = tasks.join_next().await {
            let resp = res.expect("request task must not panic");
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                rejected += 1;
            } else {
                succeeded += 1;
            }
        }

        assert_eq!(
            rejected, 0,
            "a burst of 300 concurrent mutating requests must all queue behind \
             the 100-permit cap, not 429 — the whole point of bounded-wait \
             backpressure is that overflow waits instead of failing outright"
        );
        assert_eq!(
            succeeded, 300,
            "every queued request must eventually succeed"
        );
    }

    #[tokio::test]
    async fn test_mutating_queue_depth_guard_rejects_instantly_when_full() {
        // tokio's Semaphore waiter list is unbounded FIFO by default — without
        // this guard, a flood arriving faster than permits free up could pile
        // up arbitrarily many waiting requests (each holding an open
        // connection for up to MUTATING_WAIT_TIMEOUT) before ever rejecting
        // anything, trading the old cheap instant-429 for a memory-DoS. This
        // is the guard that bounds that: once the waiter count already hits
        // MAX_MUTATING_QUEUE_DEPTH, the next request must reject INSTANTLY,
        // not join the queue and wait out the deadline.
        let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
        let mutating = Arc::new(Semaphore::new(MAX_MUTATING));
        let mutating_waiters = Arc::new(AtomicUsize::new(0));

        // Saturate the permits...
        let _permits: Vec<OwnedSemaphorePermit> = (0..MAX_MUTATING)
            .map(|_| Arc::clone(&mutating).try_acquire_owned().unwrap())
            .collect();
        // ...and simulate the waiter queue already being at capacity.
        mutating_waiters.store(MAX_MUTATING_QUEUE_DEPTH, Ordering::SeqCst);

        let layer = InflightLayer {
            inflight: Arc::clone(&inflight),
            mutating: Arc::clone(&mutating),
            mutating_waiters: Arc::clone(&mutating_waiters),
        };
        let mut svc = layer.layer(OkService);

        let req = make_request(Method::POST);
        let start = tokio::time::Instant::now();
        let resp = svc.call(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "must 429 once the waiter queue is already at MAX_MUTATING_QUEUE_DEPTH"
        );
        assert!(
            start.elapsed() < MUTATING_WAIT_TIMEOUT,
            "the queue-depth guard must reject instantly, not wait out the \
             deadline — this is the memory-DoS guard: waiting here is exactly \
             the unbounded growth it exists to prevent"
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
            mutating_waiters: Arc::new(AtomicUsize::new(0)),
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
            mutating_waiters: Arc::new(AtomicUsize::new(0)),
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

    #[tokio::test]
    async fn test_429_rejection_is_logged_with_method_uri_and_limit_kind() {
        // Before this test existed, an InflightLayer 429 was invisible in apiserver.log:
        // InflightLayer runs before ContentTypeLayer's access log, so a rejected request
        // never reached the only other log line that recorded method/uri/status. Without
        // this warn!, diagnosing rate-limit pressure required forensic reconstruction from
        // request-density timing instead of a grep. If the log call is ever dropped, this
        // test must fail.
        crate::test_utils::tracing_capture::install_global_test_subscriber();
        let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = crate::test_utils::tracing_capture::TestBufferGuard::new(buf.clone());

        let inflight = Arc::new(Semaphore::new(0)); // immediately exhausted
        let mutating = Arc::new(Semaphore::new(MAX_MUTATING));

        let layer = InflightLayer {
            inflight: Arc::clone(&inflight),
            mutating: Arc::clone(&mutating),
            mutating_waiters: Arc::new(AtomicUsize::new(0)),
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

        let log = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
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
