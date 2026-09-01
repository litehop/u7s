Bead: mayor-4q3m2

# InflightLayer instant-429 vs queued backpressure — options for the operator

## Verdict

Recommend **(c) bounded-wait backpressure on the mutating semaphore only**
(`acquire_owned().await` under a `tokio::time::timeout`, plus a small
max-queue-depth guard), not (b) raising `MAX_MUTATING`. Raising the cap only
moves the same crash to a bigger burst (any fixed ceiling still instant-
rejects a big-enough storm — this test's is 300 PVCs, exactly the gap the
bead's own DESIGN note already flags) and directly weakens the SQLite-lock-
contention protection the cap exists for. (c) preserves the "≤100 concurrent
SQLite writers" invariant exactly (the Semaphore's permit count is unchanged
by the acquisition method) while turning a deliberate, resource-preserving
burst into a queued wait instead of an instant panic-inducing 429. It needs
exactly one test rewritten (`test_mutating_limit_returns_429`) and a queue-
depth cap to avoid an unbounded-waiter DoS surface. (a) excluding the spec is
the fastest unblock and is fully reversible, but ships a real behavior gap
vs upstream APF unfixed. (d) full APF is correctly out of scope for u7s's
scale.

## 1. Storm size + the threshold

Fetched `test/e2e/storage/testsuites/pvcdeletionperf.go` and
`test/e2e/storage/drivers/csi.go` at `release-1.36` into
`temp/research/` in this worktree.

**Storm size: exactly 300 concurrent DELETE calls**, not a lower bound picked
by the test itself but by the csi-hostpath driver's fixed config
(`test/e2e/storage/drivers/csi.go:129-140`, `initHostPathCSIDriver`):

```go
PerformanceTestOptions: &storageframework.PerformanceTestOptions{
    ProvisioningOptions: &storageframework.PerformanceTestProvisioningOptions{
        VolumeSize: "1Mi",
        Count:      300,
        ...
```

The AfterEach in `pvcdeletionperf.go:142-161` spawns exactly `len(l.pvcs)`
(=300) goroutines with **no concurrency limiter of any kind** — each
goroutine calls `e2epv.DeletePersistentVolumeClaim` immediately:

```go
wg.Add(len(l.pvcs))
for _, pvc := range l.pvcs {
    go func(pvc *v1.PersistentVolumeClaim) { // Start a goroutine for each PVC
        defer wg.Done() // Decrement the counter when the goroutine finishes
        ...
        err := e2epv.DeletePersistentVolumeClaim(ctx, l.cs, pvc.Name, pvc.Namespace)
        framework.ExpectNoError(err)
        ...
```

The framework is configured with `ClientQPS: 500, ClientBurst: 1000`
(`pvcdeletionperf.go:100-104`) specifically "to avoid client-side throttling
from the test itself" — so client-go's own rate limiter does not smooth this
burst at all; all 300 DELETEs land on the apiserver essentially at once.

**Performance constraint asserted: 30 minutes, on PVC *creation* (Bound),
not deletion.** The doc comment says the suite is a metrics-recording tool,
not an SLA gate, for the deletion phase itself
(`pvcdeletionperf.go:48-49`):

> "The main goal is to record the duration for the PVC/PV deletion process
> for each run, and so the test doesn't set explicit expectations to match
> against."

The one real pass/fail assertion in the spec is the creation-side timeout
(`pvcdeletionperf.go:45`, `240-245`):

```go
const pvcDeletionTestTimeout = 30 * time.Minute
...
select {
case l.pvcs = <-waitForProvisionCh:
    framework.Logf("All PVCs in Bound state")
case <-time.After(pvcDeletionTestTimeout):
    ginkgo.Fail(fmt.Sprintf("expected all PVCs to be in Bound state within %v", pvcDeletionTestTimeout.Round(time.Second)))
}
```

There is no equivalent `ginkgo.Fail` on deletion latency — deletion just
calls `framework.ExpectNoError` on each `DeletePersistentVolumeClaim` /
`WaitForPersistentVolumeDeleted` call, so **the crash is not "too slow," it
is the *first* DELETE past #100 getting an instant 429 that a bare `go
func(){...}()` (no `GinkgoRecover`) cannot survive.**

**`GinkgoRecover()` confirmed missing on the PVC loop, present on the pod
loop 17 lines above:**

- Pod-delete loop, `pvcdeletionperf.go:125-128`:
  ```go
  go func(pod *v1.Pod) {
      defer ginkgo.GinkgoRecover()
      defer wg.Done()
  ```
- PVC-delete loop, `pvcdeletionperf.go:144-145` (17 lines below the pod
  loop's `GinkgoRecover`, 18 below its `go func`):
  ```go
  go func(pvc *v1.PersistentVolumeClaim) { // Start a goroutine for each PVC
      defer wg.Done() // Decrement the counter when the goroutine finishes
  ```
  No `defer ginkgo.GinkgoRecover()` anywhere in this closure. A panic here
  (from `framework.ExpectNoError` on the 429) is unrecovered and takes down
  the whole ginkgo worker process — matching mayor-4t2c9's observed "Exit
  result of proc 1: exit status 2".

## 2. Our current mechanics — `crates/apiserver/src/inflight.rs`

Read the file end-to-end (169 lines of implementation + 220 lines of tests,
6 tests total — see correction below on the bead's "5 tests" framing).

**Semaphore type and enforcement.** Two independent `Arc<tokio::sync::
Semaphore>`, constructed once in `InflightLayer::new()` (`inflight.rs:37-44`):

```rust
const MAX_INFLIGHT: usize = 200;
const MAX_MUTATING: usize = 100;
...
inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
mutating: Arc::new(Semaphore::new(MAX_MUTATING)),
```

Every request goes through `InflightService::call` (`inflight.rs:126-151`),
which tries the total-inflight permit first, then — only for POST/PUT/PATCH/
DELETE (`is_mutating`, `inflight.rs:69-74`) — the mutating permit:

```rust
let inflight_permit = match Arc::clone(&self.inflight).try_acquire_owned() {
    Ok(p) => p,
    Err(_) => { /* 429 "inflight" */ }
};
let mutating_permit: Option<OwnedSemaphorePermit> = if mutating {
    match Arc::clone(&self.mutating).try_acquire_owned() {
        Ok(p) => Some(p),
        Err(_) => { /* release inflight permit, 429 "mutating" */ }
    }
} else { None };
```

`try_acquire_owned` is the instant-reject: it returns `Err` synchronously if
no permit is free rather than waiting, which is exactly what makes this an
immediate 429 with zero queuing.

**Cap scope: per-process global, not per-connection/per-namespace/per-
client.** `InflightLayer::new()` is called exactly once per production
apiserver process, when the axum router is built
(`crates/apiserver/src/lib.rs:610`, inside the same `.layer()` chain the
in-file comment documents as "body_limit → inflight → auth → content_type →
handler"). The `Layer::layer(&self, inner)` impl (`inflight.rs:46-56`) only
`Arc::clone`s the two semaphores into every `InflightService` instance — it
never constructs a new `Semaphore`. So all connections and all clients
served by one apiserver process share the same 100-permit mutating budget;
the only other call site (`crates/apiserver/src/bootstrap_apply.rs:900`) is
a test-only `TestApiserver` helper, not a second production instance.

**The 5-vs-6-tests correction (Rule 7 — flagging, not blending).** The bead
text says "5 unit tests assert this... citing SQLite lock-contention
protection." The file actually has **6** `#[tokio::test]`s. Only **one**
comment cites SQLite explicitly. Precise breakdown:

| Test | What it asserts | Cites SQLite? |
|---|---|---|
| `test_inflight_limit_returns_429` | 201st request instant-429s once 200 inflight permits are held | No — cites OOM: "without it, an unbounded server could OOM under load" |
| `test_mutating_limit_returns_429` | 101st mutating request instant-429s once 100 mutating permits are held | **Yes** — quoted below |
| `test_read_bypasses_mutating_limit` | GET never touches the mutating semaphore | No |
| `test_permits_released_on_completion` | permits release after each request so serial traffic never false-rejects | No |
| `test_429_response_is_kubernetes_status_json` | 429 body is valid k8s `Status` JSON | No |
| `test_429_rejection_is_logged_with_method_uri_and_limit_kind` | rejected requests are still logged (InflightLayer runs before the access-log layer) | No |

The one SQLite-citing comment, verbatim (`inflight.rs:236-237`):

> "When all 100 mutating slots are consumed, the 101st mutating request
> must get 429. This validates that write concurrency is bounded — without
> it, 100 concurrent writes could exceed SQLite lock contention budget."

So: 5 of the 6 tests are about the instant-reject/permit-accounting design
itself (the 6th is purely about the log line, added later per its own
comment about requests "vanishing" from `apiserver.log`); of those 5, only
the mutating-limit test states the SQLite rationale in-comment. The other
4 state OOM protection, read/write fairness, permit hygiene, and response
shape as their respective reasons — real reasons, just not "SQLite" reasons.

## 3. Options matrix

### (a) Exclude the non-Conformance spec

Skip `pvc-deletion-performance [Slow][Serial]` (it is not `[Conformance]`-
tagged) from whichever suite selection mechanism u7s's e2e runner uses
(ginkgo `--skip` regex or an exclude list). **Change:** zero product code
touched; the crash simply never runs. **Reversible:** yes, trivially — it's
a config-only exclusion, drop the skip once a real fix lands. **Tradeoff:**
does not fix the underlying reject-vs-queue gap vs real kube-apiserver; any
other spec (present or future) that fires >100 truly-concurrent mutations
without its own `GinkgoRecover` reproduces the identical class of crash.

### (b) Raise `MAX_MUTATING`

**Value that clears *this* storm: >= 300**, matching the csi-hostpath
driver's fixed `Count: 300` (section 1) — this is a bare lower bound for an
isolated single-test burst, not an engineered safety margin (a real cluster
also has kubelet heartbeats/controller reconciles landing concurrently, so
an operationally "safe" raise would need to sit meaningfully above 300).

**Does a higher fixed ceiling still instant-reject a bigger burst? Yes, by
construction.** `try_acquire_owned` fails synchronously whenever the permit
count is exhausted regardless of what that count is set to — raising
`MAX_MUTATING` to any finite C only moves the failure point to the (C+1)-th
concurrent mutation. This is exactly the qualitative gap the bead's own
DESIGN note calls out: "any fixed ceiling still instant-rejects a big-enough
burst; the qualitative reject-vs-queue gap is the real issue." A future test
with `Count: 500` (or simply a busier live cluster) reproduces the identical
crash at a higher watermark.

**Does it weaken the SQLite-lock protection the tests cite? Yes, directly.**
The cap's entire purpose per `test_mutating_limit_returns_429`'s own comment
is to keep concurrent SQLite writers under a budget; tripling it from 100 to
>=300 triples the number of concurrent SQLite writers the apiserver will
now allow, cutting directly into whatever margin the current 100 was chosen
against (the codebase's git history for this file does not show a load-test
number derivation — see below — so 100 itself is not provably "the" safe
number either, but going 3x higher without evidence is directly counter to
the stated protection, not incidental to it).

*(Note on provenance: `git log --diff-filter=A -- crates/apiserver/src/
inflight.rs` resolves to a single large squash-style commit with no design
discussion attached, so the historical derivation of "100" specifically is
not recoverable from this repo's history; the in-file test comments are the
only documented rationale and are treated as authoritative for this doc.)*

### (c) tokio Semaphore backpressure (wait-then-timeout) — the operator's instinct

Concretely: on the mutating path only, replace
`Arc::clone(&self.mutating).try_acquire_owned()` with
`tokio::time::timeout(D, Arc::clone(&self.mutating).acquire_owned()).await`,
429 only if the timeout elapses. (Scoped to the mutating semaphore, not the
total-inflight one — see (iii) below for why.)

**(i) Does it preserve the SQLite concurrency bound? Confirmed from the
actual code: yes.** `Semaphore::new(MAX_MUTATING)` (`inflight.rs:41`) fixes
the *permit count*, not the acquisition method — a `tokio::sync::Semaphore`
never has more than `MAX_MUTATING` permits outstanding at once regardless of
whether callers use `try_acquire_owned` (fails on empty) or `acquire_owned()`
(waits on empty, is woken when a permit is released). Swapping the
acquisition method changes only what happens to the (101st, 102nd, ...)
caller while the 100 permits are held — it waits instead of failing — it
does not change the "≤100 permits held at once" invariant the SQLite
protection actually depends on. This directly answers the operator's
instinct: yes, it is safe on this axis.

**(ii) Unbounded FIFO waiter queue — DoS/queue-depth risk: real, needs a
separate cap.** `tokio::sync::Semaphore`'s internal waiter list has no built-
in bound; any number of tasks may be parked in `.acquire()` simultaneously.
For *this* test's burst (a closed, self-limiting 300-goroutine storm that
resolves itself as permits free up) that is fine — worst case ~200 requests
wait briefly. It is not fine as a general-purpose mechanism: without an
explicit max-queue-depth guard, an actual flood (malicious or a much larger
future test) would let unboundedly many requests pile up waiting, each
holding an open connection for up to the timeout duration, before ever
being rejected — trading an instant, cheap 429 for a slow-building resource
hold. Recommend gating admission into the wait itself (e.g., an
`AtomicUsize` queue-depth counter checked before calling `acquire_owned`,
instant-429 once queued-waiters exceeds a second, smaller constant) rather
than relying on the timeout alone to bound exposure.

**(iii) Test impact — scoped correctly (mutating semaphore only), only 1 of
6 tests changes:**

- `test_mutating_limit_returns_429` — **must change.** It holds all 100
  mutating permits for the test's entire scope and currently asserts an
  immediate 429 on the 101st POST. Under wait-then-timeout the same POST
  would now block for up to the timeout before 429ing; the test must switch
  from "instant 429" to "eventually 429 after waiting up to timeout"
  (using a short test-scoped timeout constant, or `tokio::time::pause()`,
  to keep the test fast).
- `test_inflight_limit_returns_429`, `test_read_bypasses_mutating_limit`,
  `test_permits_released_on_completion`, `test_429_response_is_kubernetes_
  status_json`, `test_429_rejection_is_logged_with_method_uri_and_limit_
  kind` — **unaffected**, because none of them exhaust the *mutating*
  semaphore and then send a *mutating* request while it stays exhausted for
  the whole call. `test_read_bypasses_mutating_limit` sends a GET (never
  touches the mutating semaphore at all); the other three that exhaust a
  semaphore do so on the *inflight* one, not mutating, and it is
  deliberately left on `try_acquire_owned` in this scoped design.

  *(If the same wait-then-timeout treatment were also applied to the total
  `inflight` semaphore — a broader reading of the operator's ask — those
  three inflight-exhaustion tests would additionally need a short
  test-scoped timeout to stay fast, though not a semantic rewrite, since
  they only assert 429/body/log content, not instant timing. Recommend
  against that broader scope: the total-inflight cap also gates plain GETs,
  and making cheap reads wait during overload — rather than fast-failing —
  is a worse tradeoff for cluster health checks/watches than what this bead
  is actually about.)*

### (d) Full APF (FlowSchema + PriorityLevelConfiguration + shuffle-sharding)

Real kube-apiserver's API Priority and Fairness is a full admission-control
subsystem: request classification into `FlowSchema`s, per-`PriorityLevel
Configuration` concurrency shares, shuffle-sharded fair queuing so one noisy
client/namespace can't starve others, and its own configurable queue-length/
wait-time limits — designed for genuinely multi-tenant clusters with many
independent, mutually-distrusting clients competing for apiserver capacity.
u7s is single-tenant at its current scale (one or a handful of trusted
controllers/kubelets/kubectl users per cluster, not hundreds of tenants);
the fairness problem APF solves — preventing tenant A's burst from starving
tenant B — does not exist yet. Building full APF now would be adding a
large, genuinely complex admission-control subsystem to solve a fairness
problem u7s doesn't have, in service of a bug that a much smaller bounded-
queue mechanism (option c) already resolves correctly. Worth knowing what
the "real" fix looks like so a future genuine multi-tenant requirement isn't
mistaken for "just raise the semaphore again," but not proportionate here.

## 4. Recommendation

Ship (c), scoped to the mutating semaphore only: swap `try_acquire_owned`
for `acquire_owned().await` under a bounded `tokio::time::timeout`, add an
explicit max-queue-depth guard ahead of the wait so an actual flood still
fast-429s instead of piling up unboundedly, and rewrite exactly
`test_mutating_limit_returns_429` for the new wait-then-timeout semantics
(the other 5 tests are unaffected under this scope). This is correctness-
first: it is the only option that both (1) fixes the crash for the actual
storm size in this test (300, confirmed above) *and any larger future one*
— unlike (b), which just moves the same instant-reject cliff to a higher,
still-finite watermark — and (2) provably preserves the SQLite concurrency
bound the existing test suite protects, confirmed directly against the
`Semaphore::new(MAX_MUTATING)` construction rather than assumed. (a) is a
reasonable *immediate* unblock (fully reversible, zero risk) while (c) is
implemented and reviewed, but should not be treated as the final answer
since it leaves a real behavior gap vs upstream APF in place indefinitely.
(d) is correctly out of scope for u7s's current single-tenant scale.
