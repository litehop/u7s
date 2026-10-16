// inflight.rs — Tower middleware for concurrent request limiting.
//
// Runs after authentication (the caller's identity decides which seats it may take) and
// enforces two pools:
//   - MAX_INFLIGHT (200): total concurrent requests across all methods.
//     Rejected immediately (HTTP 429) when exhausted — reads must fail
//     fast, not queue, so a mutating storm can't stall health checks/watches.
//   - MAX_MUTATING (100): concurrent requests for mutating methods
//     (POST, PUT, PATCH, DELETE). Overflow WAITS for a free permit up to
//     MUTATING_WAIT_TIMEOUT before returning 429 — see that constant's
//     doc comment for why queuing, not instant-reject, is correct here.
//
// Each pool keeps a reserved fraction that only control-plane identities
// (`state::is_system_priority_username`) may use, and caps any single other
// user at a share of the pool, so one tenant can neither starve kubelets and
// controllers nor take every seat. Long-running requests (watch, proxy,
// exec/attach/portforward, log) and health probes bypass the pools entirely,
// as upstream's LongRunningFunc and exempt priority level do.
//
// This is a DELIBERATE minimal subset of Kubernetes' API Priority & Fairness
// (APF): two classes (system / everyone else), a per-user cap, and a bounded
// wait for mutations, with no FlowSchema classification or shuffle-sharded
// fair queuing. Any future ask to add priority levels, multiple queues, or
// per-flow fairness here must first cost-analyze extending this file vs
// adopting upstream APF; skipping that analysis is how this accretes into a
// worse, hand-rolled APF one feature at a time.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, Response};
use axum::response::IntoResponse as _;
use futures_util::StreamExt as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::Layer;
use tower_service::Service;

use crate::auth::{is_long_running_request, UserInfo};
use crate::state::is_system_priority_username;
use crate::status::Status;

const MAX_INFLIGHT: usize = 200;
const MAX_MUTATING: usize = 100;

/// Seats only control-plane identities may take: 20% of each pool. Kubelet lease and
/// status writes, controller updates and the scheduler's bindings are a few dozen
/// concurrent requests on a single-node-to-small cluster, so 40 read / 20 mutating seats
/// cover them with headroom while leaving 80% of the pool to everyone else.
const RESERVED_INFLIGHT: usize = MAX_INFLIGHT / 5;
const RESERVED_MUTATING: usize = MAX_MUTATING / 5;

/// Most seats one non-system user may hold: 25% of each pool. Four distinct users are
/// needed to fill the shared remainder, so a single runaway client or one leaked token is
/// contained, while a legitimate tenant still gets 50 concurrent reads / 25 concurrent
/// writes — well above what kubectl or a controller sustains.
const USER_SHARE_INFLIGHT: usize = MAX_INFLIGHT / 4;
const USER_SHARE_MUTATING: usize = MAX_MUTATING / 4;

/// Per-user semaphore map size past which idle entries are dropped, bounding memory
/// against minted ServiceAccount names. Live entries never exceed the pool size plus the
/// queue depth, so pruning at this size only ever removes idle ones.
const USER_MAP_PRUNE_AT: usize = 1024;

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

/// Max time a non-long-running mutating request may take to deliver its body once
/// admitted. Matches kube-apiserver's default 60s request timeout, which bounds every
/// non-long-running request (and so releases its max-in-flight seat). Only the body read
/// is bounded here, not the handler.
const MUTATING_BODY_TIMEOUT: Duration = Duration::from_secs(60);

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
// Pool
// ---------------------------------------------------------------------------

enum Caller {
    System,
    Other(String),
}

impl Caller {
    fn of(req: &Request<Body>) -> Self {
        match req.extensions().get::<UserInfo>() {
            Some(u) if is_system_priority_username(&u.username) => Caller::System,
            Some(u) => Caller::Other(u.username.clone()),
            None => Caller::Other(String::new()),
        }
    }
}

/// Held for the life of a request; dropping it returns every seat.
struct Seat {
    _user: Option<OwnedSemaphorePermit>,
    _shared: Option<OwnedSemaphorePermit>,
    _all: OwnedSemaphorePermit,
}

/// A seat pool: `all` is the hard capacity, `shared` is the part non-system callers may
/// use (capacity minus the reserved seats), and each non-system user is further limited
/// by its own semaphore. System callers take only from `all`, so while non-system holders
/// are bounded by `shared` the reserved seats are always free for them.
struct Pool {
    all: Arc<Semaphore>,
    shared: Arc<Semaphore>,
    user_share: usize,
    users: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl Pool {
    fn new(capacity: usize, reserved: usize, user_share: usize) -> Arc<Self> {
        Arc::new(Pool {
            all: Arc::new(Semaphore::new(capacity)),
            shared: Arc::new(Semaphore::new(capacity.saturating_sub(reserved))),
            user_share,
            users: Mutex::new(HashMap::new()),
        })
    }

    fn user_semaphore(&self, user: &str) -> Arc<Semaphore> {
        let mut users = self.users.lock().unwrap();
        if users.len() >= USER_MAP_PRUNE_AT {
            // An Arc held elsewhere is a live permit or a queued waiter.
            users.retain(|_, s| Arc::strong_count(s) > 1);
        }
        Arc::clone(
            users
                .entry(user.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(self.user_share))),
        )
    }

    fn try_acquire(&self, caller: &Caller) -> Option<Seat> {
        let (user, shared) = match caller {
            Caller::System => (None, None),
            Caller::Other(name) => (
                Some(self.user_semaphore(name).try_acquire_owned().ok()?),
                Some(Arc::clone(&self.shared).try_acquire_owned().ok()?),
            ),
        };
        let all = Arc::clone(&self.all).try_acquire_owned().ok()?;
        Some(Seat {
            _user: user,
            _shared: shared,
            _all: all,
        })
    }

    /// Like `try_acquire`, but a miss waits up to MUTATING_WAIT_TIMEOUT instead of
    /// rejecting on the spot. Returns `None` if the queue-depth guard trips (fail fast, no
    /// wait) or the wait times out.
    async fn acquire_waiting(&self, caller: &Caller, waiters: &Arc<AtomicUsize>) -> Option<Seat> {
        // Fast path: a seat is free right now, no need to join the queue.
        if let Some(seat) = self.try_acquire(caller) {
            return Some(seat);
        }

        // tokio's Semaphore waiter list is unbounded FIFO, so admission into the wait
        // itself must be bounded (see MAX_MUTATING_QUEUE_DEPTH).
        let _waiter = WaiterGuard::try_new(Arc::clone(waiters))?;

        let wait = async {
            let (user, shared) = match caller {
                Caller::System => (None, None),
                Caller::Other(name) => (
                    Some(self.user_semaphore(name).acquire_owned().await.ok()?),
                    Some(Arc::clone(&self.shared).acquire_owned().await.ok()?),
                ),
            };
            let all = Arc::clone(&self.all).acquire_owned().await.ok()?;
            Some(Seat {
                _user: user,
                _shared: shared,
                _all: all,
            })
        };
        tokio::time::timeout(MUTATING_WAIT_TIMEOUT, wait)
            .await
            .ok()
            .flatten()
    }
}

// ---------------------------------------------------------------------------
// InflightLayer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct InflightLayer {
    inflight: Arc<Pool>,
    mutating: Arc<Pool>,
    mutating_waiters: Arc<AtomicUsize>,
}

impl InflightLayer {
    pub fn new() -> Self {
        InflightLayer {
            inflight: Pool::new(MAX_INFLIGHT, RESERVED_INFLIGHT, USER_SHARE_INFLIGHT),
            mutating: Pool::new(MAX_MUTATING, RESERVED_MUTATING, USER_SHARE_MUTATING),
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
    inflight: Arc<Pool>,
    mutating: Arc<Pool>,
    mutating_waiters: Arc<AtomicUsize>,
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// `/healthz`, `/livez`, `/readyz` and their sub-checks: probes must answer even when
/// every seat is taken, or the kubelet restarts a merely busy apiserver.
fn is_health_probe(path: &str) -> bool {
    ["/healthz", "/livez", "/readyz"].iter().any(|probe| {
        path.strip_prefix(probe)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// RAII counter for a request queued on the mutating pool.
///
/// Must decrement on every exit path — permit acquired, timeout elapsed,
/// or the holding future dropped outright (client disconnects while
/// queued). A bare fetch_add/fetch_sub pair without Drop would leak the
/// count whenever a future is cancelled instead of polled to completion,
/// letting MAX_MUTATING_QUEUE_DEPTH's guard ratchet towards permanently
/// rejecting everything after enough disconnects.
struct WaiterGuard(Arc<AtomicUsize>);

impl WaiterGuard {
    /// Atomically reserve a waiter slot and enforce MAX_MUTATING_QUEUE_DEPTH
    /// as a hard cap. `fetch_add` returns the count as of BEFORE this
    /// reservation, so checking that returned value (instead of a separate
    /// `load` followed by its own `fetch_add`) closes the race where two
    /// concurrent callers both observe the count one below the cap and both
    /// proceed to increment, transiently pushing it past the cap. If the
    /// reservation overshoots, roll it back with `fetch_sub` before
    /// rejecting so the failed attempt itself doesn't count as a waiter.
    fn try_new(waiters: Arc<AtomicUsize>) -> Option<Self> {
        let prior = waiters.fetch_add(1, Ordering::SeqCst);
        if prior >= MAX_MUTATING_QUEUE_DEPTH {
            waiters.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(WaiterGuard(waiters))
    }
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Rewrap the request body so the whole read must finish within
/// MUTATING_BODY_TIMEOUT of permit admission; on expiry the body yields a
/// TimedOut error, the handler fails, and the permits drop.
fn with_body_deadline(req: Request<Body>) -> Request<Body> {
    let deadline = tokio::time::Instant::now() + MUTATING_BODY_TIMEOUT;
    req.map(|body| {
        let frames =
            futures_util::stream::unfold(body.into_data_stream(), move |mut s| async move {
                match tokio::time::timeout_at(deadline, s.next()).await {
                    Ok(Some(item)) => Some((item.map_err(axum::BoxError::from), s)),
                    Ok(None) => None,
                    Err(_) => Some((
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "request body read timed out",
                        )
                        .into()),
                        s,
                    )),
                }
            });
        Body::from_stream(frames)
    })
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
    // Retry-After/retryAfterSeconds make client-go back off instead of retrying hot.
    Status::too_many_requests_retry_after("Too many requests".to_owned(), 1).into_response()
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

        if is_health_probe(req.uri().path())
            || is_long_running_request(req.method(), req.uri().path(), req.uri().query())
        {
            return Box::pin(async move { inner.call(req).await });
        }

        let caller = Caller::of(&req);

        if !is_mutating(req.method()) {
            // Reads: single instant-reject check against the total inflight
            // cap — see the module doc comment for why.
            let seat = match self.inflight.try_acquire(&caller) {
                Some(seat) => seat,
                None => {
                    let resp = too_many_requests_response(&req, "inflight");
                    return Box::pin(async move { Ok(resp) });
                }
            };
            return Box::pin(async move {
                let _seat = seat;
                inner.call(req).await
            });
        }

        // Mutating: acquire the (possibly-waited) mutating seat FIRST,
        // then the inflight seat. A queued-but-not-yet-admitted mutating
        // request must NOT hold an inflight seat while it waits — inflight
        // seats are held for up to MUTATING_WAIT_TIMEOUT once acquired
        // this way, and grabbing one before the mutating wait resolves would
        // let a 300-request mutating burst alone exhaust MAX_INFLIGHT (200)
        // purely from requests parked in the mutating queue, instant-429ing
        // read traffic (and any mutation past #200). Acquiring in
        // mutating-then-inflight order means only requests actually admitted
        // through the 100-seat mutating gate ever compete for inflight
        // capacity, exactly as if they were ordinary reads.
        let mutating = Arc::clone(&self.mutating);
        let inflight = Arc::clone(&self.inflight);
        let waiters = Arc::clone(&self.mutating_waiters);

        Box::pin(async move {
            let Some(mutating_seat) = mutating.acquire_waiting(&caller, &waiters).await else {
                return Ok(too_many_requests_response(&req, "mutating"));
            };
            let Some(inflight_seat) = inflight.try_acquire(&caller) else {
                return Ok(too_many_requests_response(&req, "inflight"));
            };

            // Seats are held for the duration of the inner call and dropped
            // when this future completes, automatically releasing the semaphores.
            let _mutating = mutating_seat;
            let _inflight = inflight_seat;
            inner.call(with_body_deadline(req)).await
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

    fn request_as(method: Method, uri: &str, username: &str) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(UserInfo {
            username: username.to_owned(),
            ..Default::default()
        });
        req
    }

    /// Take every seat in the pool, as a stuck workload would.
    fn exhaust(pool: &Pool) -> OwnedSemaphorePermit {
        let n = pool.all.available_permits() as u32;
        Arc::clone(&pool.all).try_acquire_many_owned(n).unwrap()
    }

    #[tokio::test]
    async fn test_inflight_limit_returns_429() {
        // When all 200 inflight slots are consumed, the 201st request must get 429.
        // This validates that the total concurrency cap is enforced — without it,
        // an unbounded server could OOM under load.
        let layer = InflightLayer::new();
        let _permits = exhaust(&layer.inflight);
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
        // Exhaust all mutating permits and never release them — nothing will
        // free up, so the request under test must ride out the full deadline.
        let layer = InflightLayer::new();
        let _permits = exhaust(&layer.mutating);
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
        let layer = InflightLayer::new();
        // Saturate the permits...
        let _permits = exhaust(&layer.mutating);
        // ...and simulate the waiter queue already being at capacity.
        layer
            .mutating_waiters
            .store(MAX_MUTATING_QUEUE_DEPTH, Ordering::SeqCst);
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

    #[test]
    fn test_waiter_guard_cap_never_exceeded_under_contention() {
        // Regression for a check-then-increment TOCTOU: the old guard did
        // `if waiters.load() >= MAX { reject }` followed by a separate
        // `waiters.fetch_add(1)` as two ops, so two racers could both load
        // a value one below the cap, both pass the check, and both
        // increment — transiently exceeding the cap. That overshoot defeats
        // the memory bound the guard exists to enforce (see
        // MAX_MUTATING_QUEUE_DEPTH's doc comment). WaiterGuard::try_new is
        // plain sync code (no .await between its load and its increment),
        // so the only way this races is genuine OS-thread parallelism —
        // real std::thread::spawn racers hammering the same atomic, holding
        // every granted guard until every racer has finished, is what
        // actually exercises that hardware race (a tokio task flood with a
        // cooperative yield point never reliably reproduced it: the
        // scheduling overhead between spawned tasks dwarfs the nanosecond
        // window of the two racing atomic ops). This asserts the total
        // number of guards ever granted across all racers never exceeds the
        // cap, no matter how many threads race for the last slots. A single
        // race is a probabilistic hardware race (not every run hits the
        // exact nanosecond-scale interleaving), so this repeats the race
        // many times — any single round overshooting the cap is a failure.
        const RACERS: usize = 32;
        const ATTEMPTS_PER_RACER: usize = 64; // RACERS * ATTEMPTS_PER_RACER >> cap
        const ROUNDS: usize = 40;

        for round in 0..ROUNDS {
            let waiters = Arc::new(AtomicUsize::new(0));
            let handles: Vec<_> = (0..RACERS)
                .map(|_| {
                    let waiters = Arc::clone(&waiters);
                    std::thread::spawn(move || {
                        // Hold every granted guard (don't drop) until the
                        // whole race is over, so releases never relieve the
                        // pressure other racers put on the boundary while
                        // it's crossed. Returning the Vec itself (not just
                        // its length) is what keeps the guards alive past
                        // this thread finishing its own attempts — a racer
                        // that returns early must not free slots while
                        // slower racers are still contending.
                        let mut granted = Vec::new();
                        for _ in 0..ATTEMPTS_PER_RACER {
                            if let Some(guard) = WaiterGuard::try_new(Arc::clone(&waiters)) {
                                granted.push(guard);
                            }
                        }
                        granted
                    })
                })
                .collect();

            let all_granted: Vec<Vec<WaiterGuard>> =
                handles.into_iter().map(|h| h.join().unwrap()).collect();
            let total_granted: usize = all_granted.iter().map(Vec::len).sum();

            assert!(
                total_granted <= MAX_MUTATING_QUEUE_DEPTH,
                "round {round}: granted {total_granted} waiter guards total, \
                 exceeding MAX_MUTATING_QUEUE_DEPTH ({MAX_MUTATING_QUEUE_DEPTH}) \
                 — a transient overshoot here means the guard failed to \
                 enforce the hard memory bound it exists for"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_waiter_guard_no_spurious_rejection_under_cap() {
        // The atomic reservation must not reject when there is actually
        // headroom under the cap — a fix that closes the overshoot race by
        // over-rejecting would trade one bug (transient overshoot) for
        // another (legitimate requests 429ing early). Half the cap's worth
        // of concurrent acquires, none of which should ever be rejected.
        let waiters = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..(MAX_MUTATING_QUEUE_DEPTH / 2) {
            let waiters = Arc::clone(&waiters);
            let rejected = Arc::clone(&rejected);
            tasks.spawn(async move {
                match WaiterGuard::try_new(waiters) {
                    Some(guard) => {
                        tokio::task::yield_now().await;
                        drop(guard);
                    }
                    None => {
                        rejected.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
        }
        while tasks.join_next().await.is_some() {}

        assert_eq!(
            rejected.load(Ordering::SeqCst),
            0,
            "acquiring at half the queue-depth cap concurrently must never \
             be rejected — rejecting here would 429 requests that had real \
             headroom under MAX_MUTATING_QUEUE_DEPTH"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_waiter_guard_count_returns_to_zero_after_drop() {
        // The Drop impl on WaiterGuard is what prevents the ratchet the
        // module comment warns about: every acquired guard, once dropped,
        // must give its slot back. If a leak crept back in (e.g. a bare
        // fetch_add/fetch_sub without RAII), the waiter count would drift
        // upward across requests until MAX_MUTATING_QUEUE_DEPTH permanently
        // rejects everything even with zero real waiters outstanding.
        let waiters = Arc::new(AtomicUsize::new(0));

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..(MAX_MUTATING_QUEUE_DEPTH * 2) {
            let waiters = Arc::clone(&waiters);
            tasks.spawn(async move {
                if let Some(guard) = WaiterGuard::try_new(waiters) {
                    tokio::task::yield_now().await;
                    drop(guard);
                }
                // Attempts that were rejected must also leave no trace —
                // try_new rolls back its own reservation on rejection.
            });
        }
        while tasks.join_next().await.is_some() {}

        assert_eq!(
            waiters.load(Ordering::SeqCst),
            0,
            "waiter count must return to exactly 0 once every guard — \
             granted or rejected — has been dropped/rolled back; a nonzero \
             residual here is the permanent-rejection ratchet the Drop \
             impl exists to prevent"
        );
    }

    #[tokio::test]
    async fn test_read_bypasses_mutating_limit() {
        // GET requests must not consume mutating permits.  A full mutating pool
        // must not block read traffic — reads are never write-limited.
        let layer = InflightLayer::new();
        let _permits = exhaust(&layer.mutating);
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
        let layer = InflightLayer::new();
        let _permits = exhaust(&layer.inflight);
        let mut svc = layer.layer(OkService);

        let req = make_request(Method::GET);
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get(header::RETRY_AFTER).unwrap(),
            "1",
            "without Retry-After client-go retries immediately and keeps the pool saturated"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("body must be valid JSON");
        assert_eq!(json["details"]["retryAfterSeconds"], 1);

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

        let layer = InflightLayer::new();
        let _permits = exhaust(&layer.inflight);
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

    // Inner service that drains the whole body like a real extractor: 200 on
    // success, 408 when the body read errors.
    #[derive(Clone)]
    struct ReadBodyService;

    impl Service<Request<Body>> for ReadBodyService {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            Box::pin(async move {
                let status = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
                    Ok(_) => StatusCode::OK,
                    Err(_) => StatusCode::REQUEST_TIMEOUT,
                };
                Ok(Response::builder()
                    .status(status)
                    .body(Body::empty())
                    .unwrap())
            })
        }
    }

    fn channel_body() -> (tokio::sync::mpsc::Sender<Vec<u8>>, Body) {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let stream = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv()
                .await
                .map(|chunk| (Ok::<_, std::convert::Infallible>(chunk), rx))
        });
        (tx, Body::from_stream(stream))
    }

    #[tokio::test(start_paused = true)]
    async fn slowloris_body_exhausts_the_mutating_pool_unless_the_read_times_out() {
        // 100 authenticated clients that open a POST and never finish the
        // body used to pin every mutating permit forever, so kubelet lease
        // writes and controller updates queued then 429ed cluster-wide. The
        // body deadline must fail those reads and give the permits back.
        let layer = InflightLayer::new();
        let mutating = Arc::clone(&layer.mutating);
        let inflight = Arc::clone(&layer.inflight);

        let mut senders = Vec::new();
        let mut tasks = tokio::task::JoinSet::new();
        // Four tenants fill everything non-system callers may use.
        for i in 0..MAX_MUTATING - RESERVED_MUTATING {
            let (tx, body) = channel_body();
            tx.send(b"{".to_vec()).await.unwrap();
            senders.push(tx);
            let mut svc = layer.layer(ReadBodyService);
            let mut req = request_as(Method::POST, "/x", &format!("tenant-{}", i % 4));
            *req.body_mut() = body;
            tasks.spawn(async move { svc.call(req).await.unwrap().status() });
        }

        // Join late enough that its queue wait outlives the body deadline.
        tokio::time::sleep(Duration::from_secs(40)).await;
        assert_eq!(
            mutating.shared.available_permits(),
            0,
            "setup: pool must be pinned"
        );

        // A legitimate write now has to queue behind the stuck bodies.
        let mut other = layer.layer(ReadBodyService);
        let healthy = tokio::spawn(async move {
            other
                .call(make_request(Method::POST))
                .await
                .unwrap()
                .status()
        });

        tokio::time::sleep(MUTATING_BODY_TIMEOUT).await;

        let drained = tokio::time::timeout(Duration::from_secs(5), async {
            let mut out = Vec::new();
            while let Some(res) = tasks.join_next().await {
                out.push(res.unwrap());
            }
            out
        })
        .await
        .expect("stuck bodies still hold their permits after the deadline");
        for res in drained {
            assert_eq!(
                res,
                StatusCode::REQUEST_TIMEOUT,
                "a body that never completes must fail its read"
            );
        }
        assert_eq!(
            healthy.await.unwrap(),
            StatusCode::OK,
            "other writes must get a permit once stuck bodies time out"
        );
        assert_eq!(
            mutating.all.available_permits(),
            MAX_MUTATING,
            "mutating permits leaked"
        );
        assert_eq!(
            inflight.all.available_permits(),
            MAX_INFLIGHT,
            "inflight permits leaked"
        );
        drop(senders);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_but_finishing_body_within_deadline_is_not_cut_off() {
        // The deadline must not break clients that are merely slow: a body
        // that completes before it expires still reaches the handler intact.
        let layer = InflightLayer::new();
        let mut svc = layer.layer(ReadBodyService);
        let (tx, body) = channel_body();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/x")
            .body(body)
            .unwrap();
        let call = tokio::spawn(async move { svc.call(req).await.unwrap().status() });

        for _ in 0..3 {
            tokio::time::sleep(MUTATING_BODY_TIMEOUT / 4).await;
            tx.send(b"chunk".to_vec()).await.unwrap();
        }
        drop(tx);

        assert_eq!(call.await.unwrap(), StatusCode::OK);
    }

    // Inner service that holds its seat until the gate opens.
    #[derive(Clone)]
    struct GateService(tokio::sync::watch::Receiver<bool>);

    impl Service<Request<Body>> for GateService {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            let mut rx = self.0.clone();
            Box::pin(async move {
                let _ = rx.wait_for(|open| *open).await;
                Ok(Response::builder().status(200).body(Body::empty()).unwrap())
            })
        }
    }

    /// Start `n` requests from `user` that keep their seats until `gate` opens.
    async fn hold_seats(
        layer: &InflightLayer,
        gate: &tokio::sync::watch::Receiver<bool>,
        method: Method,
        uri: &str,
        user: &str,
        n: usize,
    ) -> tokio::task::JoinSet<StatusCode> {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..n {
            let mut svc = layer.layer(GateService(gate.clone()));
            let req = request_as(method.clone(), uri, user);
            tasks.spawn(async move { svc.call(req).await.unwrap().status() });
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
        tasks
    }

    async fn status_of(layer: &InflightLayer, req: Request<Body>) -> StatusCode {
        layer.layer(OkService).call(req).await.unwrap().status()
    }

    #[tokio::test(start_paused = true)]
    async fn one_user_cannot_hold_every_read_seat_and_starve_other_users() {
        // Without a per-user cap a single leaked token or runaway controller takes all
        // 200 read seats and every other client gets 429.
        let layer = InflightLayer::new();
        let (open, gate) = tokio::sync::watch::channel(false);
        let _held = hold_seats(
            &layer,
            &gate,
            Method::GET,
            "/api/v1/pods",
            "tenant",
            USER_SHARE_INFLIGHT,
        )
        .await;

        assert_eq!(
            status_of(&layer, request_as(Method::GET, "/api/v1/pods", "tenant")).await,
            StatusCode::TOO_MANY_REQUESTS,
            "a user past its share must be rejected"
        );
        assert_eq!(
            status_of(&layer, request_as(Method::GET, "/api/v1/pods", "other")).await,
            StatusCode::OK,
            "another user must still get a seat while one user is at its cap"
        );
        open.send(true).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn one_user_cannot_hold_every_write_seat_and_starve_other_users() {
        // Same starvation on the mutating pool, where overflow queues: the over-share
        // request must wait out its deadline for the user's own seats, not be admitted,
        // and must not block anyone else while it waits.
        let layer = InflightLayer::new();
        let (open, gate) = tokio::sync::watch::channel(false);
        let _held = hold_seats(
            &layer,
            &gate,
            Method::POST,
            "/api/v1/namespaces",
            "tenant",
            USER_SHARE_MUTATING,
        )
        .await;

        let over = {
            let layer = layer.clone();
            tokio::spawn(async move {
                status_of(
                    &layer,
                    request_as(Method::POST, "/api/v1/namespaces", "tenant"),
                )
                .await
            })
        };
        assert_eq!(
            status_of(
                &layer,
                request_as(Method::POST, "/api/v1/namespaces", "other")
            )
            .await,
            StatusCode::OK,
            "another user's write must be admitted while one user is at its cap"
        );
        tokio::time::sleep(MUTATING_WAIT_TIMEOUT + Duration::from_secs(1)).await;
        assert_eq!(
            over.await.unwrap(),
            StatusCode::TOO_MANY_REQUESTS,
            "a user past its write share must not be admitted"
        );
        open.send(true).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn kubelet_still_gets_a_seat_when_tenants_exhaust_the_read_pool() {
        // Tenants filling the shared part of the pool must not lock out node heartbeats:
        // a kubelet that cannot report status gets its node marked NotReady.
        let layer = InflightLayer::new();
        let (open, gate) = tokio::sync::watch::channel(false);
        let shared = MAX_INFLIGHT - RESERVED_INFLIGHT;
        let mut held = Vec::new();
        for t in 0..shared.div_ceil(USER_SHARE_INFLIGHT) {
            let n = USER_SHARE_INFLIGHT.min(shared - t * USER_SHARE_INFLIGHT);
            held.push(
                hold_seats(
                    &layer,
                    &gate,
                    Method::GET,
                    "/api/v1/pods",
                    &format!("tenant-{t}"),
                    n,
                )
                .await,
            );
        }

        assert_eq!(
            status_of(&layer, request_as(Method::GET, "/api/v1/pods", "late")).await,
            StatusCode::TOO_MANY_REQUESTS,
            "setup: the shared part of the pool must be full"
        );
        for system in ["system:node:n1", "admin", "system:kube-scheduler"] {
            assert_eq!(
                status_of(&layer, request_as(Method::GET, "/api/v1/nodes", system)).await,
                StatusCode::OK,
                "{system} must use the reserved seats while tenants hold the pool"
            );
        }
        open.send(true).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn kubelet_still_gets_a_seat_when_tenants_exhaust_the_write_pool() {
        let layer = InflightLayer::new();
        let (open, gate) = tokio::sync::watch::channel(false);
        let shared = MAX_MUTATING - RESERVED_MUTATING;
        let mut held = Vec::new();
        for t in 0..shared.div_ceil(USER_SHARE_MUTATING) {
            let n = USER_SHARE_MUTATING.min(shared - t * USER_SHARE_MUTATING);
            held.push(
                hold_seats(
                    &layer,
                    &gate,
                    Method::PUT,
                    "/api/v1/namespaces/a/configmaps/c",
                    &format!("tenant-{t}"),
                    n,
                )
                .await,
            );
        }

        let start = tokio::time::Instant::now();
        assert_eq!(
            status_of(
                &layer,
                request_as(
                    Method::PUT,
                    "/apis/coordination.k8s.io/v1/leases/n1",
                    "system:node:n1"
                )
            )
            .await,
            StatusCode::OK,
            "a kubelet lease write must be admitted while tenants hold the pool"
        );
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "the reserved seat must be free immediately, not after queueing"
        );
        open.send(true).unwrap();
    }

    #[tokio::test]
    async fn health_probes_pass_when_every_seat_is_taken() {
        // A kubelet that gets 429 from /livez restarts a merely busy apiserver.
        let layer = InflightLayer::new();
        let _all = exhaust(&layer.inflight);
        let _mut = exhaust(&layer.mutating);

        assert_eq!(
            status_of(&layer, make_request(Method::GET)).await,
            StatusCode::TOO_MANY_REQUESTS,
            "setup: ordinary requests must be rejected"
        );
        for path in [
            "/healthz",
            "/livez",
            "/readyz",
            "/readyz/etcd",
            "/healthz/ping",
        ] {
            let req = Request::builder().uri(path).body(Body::empty()).unwrap();
            assert_eq!(
                status_of(&layer, req).await,
                StatusCode::OK,
                "{path} must bypass the pools"
            );
        }
        let req = Request::builder()
            .uri("/healthzzz")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            status_of(&layer, req).await,
            StatusCode::TOO_MANY_REQUESTS,
            "only the probe paths are exempt, not any path sharing the prefix"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn watches_do_not_consume_a_seat_and_pass_when_the_pool_is_full() {
        // Long-lived watches pinning seats would drain the pool within minutes (hundreds of
        // informers), 429ing every ordinary request; watches have their own caps.
        let layer = InflightLayer::new();
        let (open, gate) = tokio::sync::watch::channel(false);
        let held = hold_seats(
            &layer,
            &gate,
            Method::GET,
            "/api/v1/pods?watch=true",
            "tenant",
            USER_SHARE_INFLIGHT * 2,
        )
        .await;
        assert_eq!(
            held.len(),
            USER_SHARE_INFLIGHT * 2,
            "setup: watches running"
        );
        assert_eq!(
            layer.inflight.all.available_permits(),
            MAX_INFLIGHT,
            "open watches must not hold in-flight seats"
        );

        let _all = exhaust(&layer.inflight);
        assert_eq!(
            status_of(
                &layer,
                request_as(Method::GET, "/api/v1/pods?watch=true", "tenant")
            )
            .await,
            StatusCode::OK,
            "a watch must be admitted even when the pool is exhausted"
        );
        open.send(true).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn proxied_upload_longer_than_the_body_deadline_is_not_cut() {
        // Proxy is long-running upstream: a pods/proxy POST whose body takes minutes (an
        // upload through the apiserver) must not be failed by the 60s body deadline.
        let layer = InflightLayer::new();
        let (tx, body) = channel_body();
        let mut svc = layer.layer(ReadBodyService);
        let mut req = request_as(
            Method::POST,
            "/api/v1/namespaces/a/pods/p/proxy/upload",
            "tenant",
        );
        *req.body_mut() = body;
        let call = tokio::spawn(async move { svc.call(req).await.unwrap().status() });

        tx.send(b"part1".to_vec()).await.unwrap();
        tokio::time::sleep(MUTATING_BODY_TIMEOUT * 2).await;
        tx.send(b"part2".to_vec()).await.unwrap();
        drop(tx);

        assert_eq!(
            call.await.unwrap(),
            StatusCode::OK,
            "a proxy body taking longer than the deadline must still be delivered"
        );
        assert_eq!(
            layer.mutating.all.available_permits(),
            MAX_MUTATING,
            "proxy must not hold a mutating seat"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn non_proxy_body_stalling_past_the_deadline_is_still_cut() {
        // Guards the exemption's scope: only long-running requests escape the deadline,
        // an ordinary POST that stalls must still free its seat.
        let layer = InflightLayer::new();
        let (tx, body) = channel_body();
        let mut svc = layer.layer(ReadBodyService);
        let mut req = request_as(Method::POST, "/api/v1/namespaces/a/configmaps", "tenant");
        *req.body_mut() = body;
        let call = tokio::spawn(async move { svc.call(req).await.unwrap().status() });

        tx.send(b"part1".to_vec()).await.unwrap();
        tokio::time::sleep(MUTATING_BODY_TIMEOUT * 2).await;

        assert_eq!(call.await.unwrap(), StatusCode::REQUEST_TIMEOUT);
        drop(tx);
    }

    #[test]
    fn long_running_classifier_matches_upstream_exemptions() {
        let cases = [
            (Method::GET, "/api/v1/pods", Some("watch=true"), true),
            (
                Method::GET,
                "/api/v1/namespaces/a/pods",
                Some("watch=1"),
                true,
            ),
            (Method::GET, "/api/v1/pods", Some("watch=false"), false),
            (Method::GET, "/api/v1/pods", None, false),
            (Method::GET, "/api/v1/namespaces/a/pods/p", None, false),
            (Method::GET, "/api/v1/namespaces/a/pods/p/log", None, true),
            (Method::POST, "/api/v1/namespaces/a/pods/p/exec", None, true),
            (
                Method::POST,
                "/api/v1/namespaces/a/pods/p/attach",
                None,
                true,
            ),
            (
                Method::POST,
                "/api/v1/namespaces/a/pods/p/portforward",
                None,
                true,
            ),
            (
                Method::POST,
                "/api/v1/namespaces/a/services/s/proxy/x",
                None,
                true,
            ),
            (Method::PUT, "/api/v1/nodes/n/proxy/x", None, true),
            (Method::POST, "/api/v1/namespaces/a/pods", None, false),
            (
                Method::PATCH,
                "/api/v1/namespaces/a/pods/p/status",
                None,
                false,
            ),
            (Method::GET, "/version", None, false),
            (Method::GET, "/healthz", Some("watch=true"), false),
        ];
        for (method, path, query, want) in cases {
            assert_eq!(
                is_long_running_request(&method, path, query),
                want,
                "{method} {path}?{query:?}"
            );
        }
    }

    #[test]
    fn per_user_semaphore_map_stays_bounded_under_minted_identities() {
        // ServiceAccount names are attacker-mintable; an entry per name forever is a slow
        // memory leak.
        let pool = Pool::new(MAX_INFLIGHT, RESERVED_INFLIGHT, USER_SHARE_INFLIGHT);
        for i in 0..USER_MAP_PRUNE_AT * 3 {
            let seat = pool.try_acquire(&Caller::Other(format!("sa-{i}")));
            assert!(seat.is_some());
        }
        assert!(
            pool.users.lock().unwrap().len() <= USER_MAP_PRUNE_AT,
            "idle per-user entries must be pruned"
        );
    }
}
