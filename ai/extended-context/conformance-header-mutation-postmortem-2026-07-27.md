# Postmortem: `content_type.rs` header-mutation conformance regression

**Status:** Resolved. **Duration:** 2026-07-25 → 2026-07-27 (~3 days elapsed, several hours
of active investigation across 8 scout dispatches + operator-driven bisection).
**Confirmed stable** across two independent post-fix runs (2026-07-27, 2026-07-28).
**Severity:** P1 — full conformance suite went from 446/446 stable to failing 3-5 specs
per run, with ~50-70 minute wall-clock ballooning, for every run across three days.
**Root cause:** PR #895 (`040855f1`, `feat(apiserver): structured access log with
user_agent/latency/request_id`) unconditionally mutated response headers
(`resp.headers_mut().insert("x-request-id", ...)`) on every response, including
long-lived `Transfer-Encoding: chunked` watch streams — the one response class the
same file already exempted from post-hoc mutation for a documented reason.
**Fix:** PR #907 — skip the header insertion for chunked responses, matching the
existing `is_chunked` exemption the file already applies to body re-encoding.

## Impact

Three consecutive days of full conformance runs (each a 2-3 hour commitment) failed
with a shifting set of 3-5 random spec failures out of 446, plus 50-70 minutes of
wall-clock ballooning versus the ~1h50m baseline. Because the failing specs were
**different on every run** (never the same 3-5 tests twice), the regression was
initially indistinguishable from flakiness, and the true cause was hidden behind two
misleading-but-real secondary phenomena (image-pull queue contention, and an apparent
kubelet PLEG stall) that consumed most of the investigation time before the actual
defect was found.

## Timeline

| Date (JST) | Event |
|---|---|
| 2026-07-24 10:13 | Full suite passes 446/446 against `c944b97d`, 1h50m. Last known-good baseline. |
| 2026-07-24 10:52 | PR #895 merged (`040855f1`) — the regression, unrecognized at merge time. |
| 2026-07-24 (later) | Several more perf/observability PRs land (#896-#905): cef5 F3/F8/F10, jdeon `prepare_live_event`, jwt v11 bump, `/metrics` endpoint. |
| 2026-07-25 11:40 | First failing run (`0725-1140`): 442/446, 3h00m. Initially triaged as **environmental** (image-pull latency spike coincided with the failures). |
| 2026-07-25 17:00 | Operator reruns on an idle host to test the environmental theory: still fails, 441/446, 2h59m, **environmental theory falsified**. |
| 2026-07-25 (evening) | Scout traces jdeon's `prepare_live_event` watch-emission code path in full — cleared, byte-correct, no stale-reference bug. |
| 2026-07-26 03:03 | New diagnostic tooling (PR #906, `--verbose` → cri-o + kubelet `--v=5` logging) lands, merged specifically to unblock this investigation. Third failing run with the new logs: 443/446, 2h40m. |
| 2026-07-26 (with new logs) | Scout finds kubelet goes silent for 9-10 minutes between "sandbox ready" and "app container created," and attributes it to a `SerializeImagePulls` queue-starvation dynamic from concurrent 100-pod GC-cascading-deletion test bursts. Real and reproducible, but not sufficient on its own to explain the regression, since the same GC specs exist in the passing baseline too. |
| 2026-07-27 03:31 & 10:43 | Operator manually bisects: passing-baseline binary (`c944b97d`) + only the harness commit **still fails** (441/446, 2h59m) — proving the originally-suspected perf/watch commits (cef5 F3/F8/F10, jdeon, jwt v11) were **not** the cause. |
| 2026-07-27 (mid-day) | Operator corrects the mayor's misreading of the bisect branch composition — it also carried PR #895's access-log commit. This reframes the whole investigation. |
| 2026-07-27 14:05 | Operator builds `bisect-access` = passing baseline + harness **only** (access-log commit dropped). Run `0727-1405`: **446/446, 1h45m** — faster than the original baseline. Root cause isolated to PR #895. |
| 2026-07-27 (fix) | PR #907 merged: skip the header mutation for chunked responses. |
| 2026-07-27 19:27 | Confirmation run on `main` with the fix: **446/446, 1h43m21s** — fastest run of the whole investigation. `retrywatcher context canceled` count: 0 (down from 300 in the last failing run). |
| 2026-07-28 01:27 | Second confirmation run on `main` (now also carrying an unrelated SA-token safety-net change, `mayor-504t7`/PR #910): **446/446, 1h46m41s**, `retrywatcher context canceled` count: 0. Fix holds stably across two independent runs. |

## Root cause

`crates/apiserver/src/content_type.rs` is a Tower middleware that runs on every
response. Before PR #895, it already had a documented invariant: **a watch/streaming
response's body must never be touched**, because by the time this middleware runs, the
body is a live `Body` stream already wired to a `tokio::sync::broadcast::Receiver`
subscribed inside the store's `watch()` call — it is an in-progress operation, not a
finished value. The file's existing `is_chunked` check exists specifically to skip
body re-encoding for exactly this reason (skipping it would deadlock the response, since
the stream never ends while the connection is open).

PR #895 added a new, unconditional operation to every response in this same middleware:

```rust
if let Ok(value) = HeaderValue::from_str(&request_id_str) {
    resp.headers_mut()
        .insert(HeaderName::from_static("x-request-id"), value);
}
```

This runs on **every** response, with no `is_chunked` exemption — the one class of
response the file already knew was special was the one operation that didn't inherit
the existing safety rule.

**Corroborating evidence:** `grep -c 'retrywatcher.*context canceled'` across every run
in the investigation returned exactly 0 for every run on a binary without PR #895's
commit, and up to 300 (in a tight ~1-2s poll-then-retry loop) for every run with it.

**Honest caveat on mechanism:** the exact runtime pathway by which mutating headers on
an already-streaming `Response<Body>` causes client-go's watch clients to see
`context canceled` was **never proven with a minimal repro or a stack trace** — no
scout or the fix's implementing worker isolated the precise axum/hyper-level
interaction. What we have is: (a) a real, provable structural asymmetry in the code
(this is the only response class not exempted from post-hoc mutation), (b) a very
strong statistical correlation (0 vs up to 300 cancellations, present in every run on
either side of the bisection), and (c) full resolution confirmed across four
independent live runs after the fix landed (two of which beat the original passing
baseline's wall-clock time, including a fourth confirmation run on 2026-07-28 that also
checked for and found no recurrence of an unrelated, separately-shortened SA-token
safety-net window). This is a structurally-sound, high-confidence fix validated
empirically, not a fix proven via a first-principles trace of the failure mechanism.

The gap is more than "nobody got around to it" — a first-principles read of the code
makes the mechanism genuinely puzzling, not just unconfirmed. `resp.headers_mut()`
mutates the `HeaderMap` inside `http::Response`'s `Parts` *before* the `Response` is
returned up through the Tower/hyper stack — nothing has been written to the wire yet at
that point, and `Parts`/`Body` are separate fields with no unsafe pinning coupling in
the `http`/`axum` crates. Under ordinary safe-Rust semantics this operation shouldn't
affect the stream's behavior once hyper starts polling it. Compounding the puzzle: the
fix left the `tracing::info!` repositioning and the `reencode_proto_response`
extraction untouched — only the header insert was made conditional — so the header
insert is empirically the single differentiating operation between the confirmed-broken
and confirmed-fixed binaries, per the fix diff itself. We know *that* it's causal; we
do not know *why*.

**Tracked as a separate, optional follow-up**: `mayor-mo96q` (P3, non-blocking,
best-effort) — a minimal standalone axum/tokio repro (ideally driven by a real
client-go watch client rather than a naive HTTP client, since the cancellation
behavior is client-go's own internal machinery) to either isolate the mechanism or
establish that it requires a precondition only present in the full system. Explicitly
allowed to come back inconclusive. If a mechanism is found, the finding will be folded
back into this document as an addendum rather than filed as a separate writeup.

## Why the failures looked so different from what they were

The single defect produced a wide, seemingly-unrelated fan of symptoms, which is the
main reason this took three days instead of one:

1. **Pervasive watch instability.** Every long-lived watch connection in the cluster —
   kubelet's own informers, kube-controller-manager's informers, the e2e test
   framework's own watch helpers — got its `X-Request-Id` header mutated mid-stream on
   an unknown cadence, which (per the correlation above) caused those connections to be
   cancelled and re-established via client-go's poll-then-retry fallback path. Every
   such cancellation costs time: a full relist, an informer resync, a burst of catch-up
   requests. This is consistent with a **pervasive, system-wide slowdown** that doesn't
   show up as elevated *per-request* latency (individual PATCH/GET/POST calls measured
   healthy at 0-2ms throughout every stall) because the cost lives in the
   watch/streaming channel, not the request-response path.

2. **This slowdown widened a pre-existing, usually-harmless timing window.** The
   conformance suite includes three `sig-api-machinery` garbage-collector specs that
   each spin up ~100-pod ReplicationControllers. kubelet's `SerializeImagePulls=true`
   default processes one image pull at a time system-wide; any unrelated pod created
   while one of these 100-pod bursts is draining sits behind the whole queue. This is a
   real, independently-reproducible kubelet architectural quirk that exists in *every*
   run, pass or fail — but it only crosses the conformance framework's ~5-minute
   timeout into an actual test failure when the *overall system* is already running
   slow enough to widen the odds of an unlucky overlap. The header-mutation bug's
   system-wide slowdown was that push. This also explains why a **different** 3-5
   specs failed on every run: ginkgo randomizes spec order per run, so which pod
   happened to land inside a GC burst's queue-starvation window varied run to run.

3. **The CRD-conversion-webhook fragility** (present in 5 of 6 failing runs) has its
   own internal race — the test asserts `Endpoints` object exists, then immediately
   calls the webhook, racing against the webhook pod's own TLS listener actually being
   ready. That race is normally narrow enough to not matter; under the pervasive
   slowdown described above it widened enough to fail intermittently.

None of these three symptom classes are wrong observations — they're all real,
independently-verifiable mechanisms. The investigation's difficulty was that each looked
like a plausible **root cause** in isolation, when each was actually a **downstream
amplifier** of the same single upstream defect.

## Investigation: dead ends and why they were plausible at the time

- **"It's environmental" (image-pull/registry latency).** The first failing run showed
  genuine 9-10 minute image pulls for images that took sub-second in the baseline —
  a real, measurable anomaly. It took a second run on an idle host, which still failed,
  to falsify this. *Lesson: a striking anomaly in the data is not proof it's the cause
  — confirm it reproduces the failure, not just correlates with it.*
- **"It's the jdeon watch-fanout rework" (`prepare_live_event`, PR #903).** The most
  recently-merged commit touching the exact subsystem (watch delivery) implicated by
  the symptoms. A full code-review scout traced every code path and found it
  byte-correct with no stale-reference bugs — later fully exonerated by the bisection
  (a binary *with* jdeon's commit but *without* PR #895 passed clean, twice).
- **"It's a kubelet PLEG relist-miss."** The first symptom directly observed (kubelet
  goes silent for 9+ minutes) pattern-matched a known upstream kubelet bug class. It
  took `--v=5` kubelet logging (newly added specifically to test this) to show CRI-O
  and PLEG were actually both fast once invoked — the silence was upstream of CRI-O
  entirely, ruling this out.
- **"It's `SerializeImagePulls` queue starvation, full stop."** The most concrete,
  fully-reproducible mechanism found — a specific pod's exact 9m28s stall was traced to
  the precise second against a concurrent 100-pod GC burst. This was correct as a
  *mechanism* but incomplete as an *explanation*, since the same GC specs exist in the
  passing baseline. It's the amplified symptom, not the cause (see above).
- **"There's no way to prove or disprove a per-op latency regression."** A targeted
  scout discovered the passing baseline had zero `latency_ms` instrumentation (that
  field was *itself* added by the culprit commit) — genuinely blocking a clean
  before/after comparison from existing data. This is what motivated rebuilding a
  passing-baseline binary with the new logging tooling attached, which led directly to
  the operator's bisection.

## How it was actually found

Five rounds of code-review-focused scouting (reading `prepare_live_event`, admission
chain, scheduler event handling, per-op latency estimates) all correctly cleared their
targets but could not produce a positive identification, because the actual defect was
in a commit nobody had flagged as high-risk — an access-log/observability change,
which "obviously" doesn't touch business logic. The investigation only converged once
the operator switched from code review to **incremental bisection**: build the known
passing baseline, cherry-pick one candidate commit at a time, run the *full* suite
(not a narrow `--focus`, which is statistically unreliable for a failure with this low
and variable an incidence rate) after each addition. This isolated the true culprit in
two bisection rounds once applied.

**Process lesson:** when a regression's suspect window contains several "obviously
risky" commits (perf rewrites, hot-path changes) that all get cleared by careful code
review, don't conclude the regression is external/environmental — systematically
bisect *every* commit in the window, including the "boring" ones. A commit that adds a
few lines to a middleware shared by every request has the same blast-radius potential
as a hot-path rewrite, regardless of how safe it looks.

## The fix

`crates/apiserver/src/content_type.rs`, `ContentTypeService::call`: the `X-Request-Id`
header insertion now checks `Transfer-Encoding: chunked` first and skips the mutation
entirely for streaming responses, matching the file's pre-existing `is_chunked`
exemption for body re-encoding. All other response classes (the overwhelming majority
of traffic) keep the full structured-logging behavior from PR #895 unchanged. Shipped
with a regression test (`chunked_watch_response_headers_are_not_mutated_by_access_log`)
verified to fail on revert.

## Lessons learned / process changes

1. **Observability/logging commits are not automatically low-risk.** They're excluded
   from "hot path" suspicion by habit, but any middleware touching every request has
   full blast radius regardless of what it's nominally *for*. Audit other shared
   middleware for the same header/body-mutation-on-streaming-response class of bug —
   this is now banked as a standing review note (`ai/dashboard.md` stance section).
2. **A regression that produces different failing specs on every run is a strong
   signal of a system-wide slowdown or race, not N independent flaky tests.** Don't
   triage each failing spec as an isolated bug before checking whether they share a
   common amplifying condition (as the GC-burst/SerializeImagePulls dynamic and the
   CRD-webhook race both turned out to be downstream of the same root cause here).
3. **Diagnostic tooling investment pays for itself mid-investigation.** PR #906
   (extending `--verbose` to cri-o + kubelet `--v=5` logging) was merged specifically
   to unblock this investigation and was essential — none of the later scouts could
   have distinguished PLEG-relist-miss from CRI-O slowness from kubelet-internal
   stalls without it.
4. **`--focus` sonobuoy runs are unreliable gates for low-and-variable-incidence
   regressions.** A 1%-incidence bug can pass a narrow `--focus` run by chance. The
   full suite, run multiple times, was the only reliable signal throughout this
   investigation.
5. **Bisect the "boring" commits too, not just the obviously risky ones**, once
   code-review-based scouting has stalled on the high-suspicion candidates. This is the
   single technique that actually cracked the case after five inconclusive code-review
   rounds.
6. **Verify instrumentation exists on BOTH sides of a comparison before trusting it.**
   Several early scouts asserted "the apiserver's channel is healthy" by measuring
   `latency_ms` — a field that, unbeknownst to them, didn't exist on the passing
   baseline at all (it was added by the same commit under suspicion). A fair
   before/after comparison requires the same instrumentation on both binaries.
7. **Watch the mayor's own working-directory branch state when the operator is
   sharing the checkout for manual bisection.** Mid-investigation, the mayor
   misread which commits were on the operator's `bisect` branch (assumed it was
   pure baseline + harness, when it also carried the culprit commit) — an easy
   mistake when a shared checkout's branch can change between reads. Always
   `git branch --show-current` before reasoning about "current" file contents in a
   shared checkout.

## Cross-references

- Bead: `mayor-ido0r` (closed 2026-07-27).
- Fix PR: [#907](https://github.com/valerauko/u7s/pull/907).
- Enabling tooling PR: [#906](https://github.com/valerauko/u7s/pull/906) (`mayor-tfggx`).
- Regressing PR: #895 (`040855f1`, `feat(apiserver): structured access log with
  user_agent/latency/request_id`).
- **Open follow-up**: `mayor-mo96q` (P3, optional, non-blocking) — root-cause the exact
  mechanism via a minimal standalone repro. See the "Honest caveat on mechanism" section
  above.
- bd memories: `content-type-header-mutation-breaks-watch-streams`,
  `bisection-incremental-cherry-pick-technique`.

## Addendum 2026-07-28: mechanism investigation inconclusive

`mayor-mo96q` attempted to close the "honest caveat on mechanism" gap above. Result:
the hypothesized coupling was **ruled out** at two independent levels, which narrows
the remaining hypothesis space but does not identify a positive mechanism — filed as
inconclusive per the bead's own explicit allowance.

**Tier 1 (source-level read).** Confirmed the exact versions in `Cargo.lock`: axum
0.8.9, axum-core 0.5.6, hyper 1.11.0, http 1.4.0, http-body 1.0.1, tower 0.5.3. Read
`http::Response<T>` (`response.rs`): it is a plain `{ head: Parts, body: T }` struct —
`headers_mut()` returns `&mut self.head.headers`, a direct field borrow with no
interior mutability, no `RefCell`/`Mutex`, and no unsafe pinning between `Parts` and
`T`. Read `axum_core::body::Body` (`body.rs`): it is `pub struct Body(BoxBody)` where
`BoxBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Error>` — a self-contained
boxed stream with zero references to any `HeaderMap`. There is no code path by which
`HeaderMap::insert` (a plain multimap mutation) can reach into or affect `Body` polling.
This confirms the mayor's a-priori reasoning was correct at the type level: mechanically,
this specific mutation cannot touch the stream.

**Tier 2 (minimal repro, real client-go client).** Built a standalone axum/tokio crate
(`temp/mo96q-repro/`, gitignored) reproducing the exact shape: a Tower middleware with a
`broken` mode (unconditional `resp.headers_mut().insert("x-request-id", ...)`, mirroring
pre-#907) and a `fixed` mode (skips the insert when `Transfer-Encoding: chunked`,
mirroring the shipped fix), in front of an axum handler streaming NDJSON `ADDED` events
every 300ms via `Body::from_stream`. Drove it with a **real** `k8s.io/client-go@v0.36.2`
program (`temp/mo96q-repro/goclient/`) using the actual `tools/watch.RetryWatcher` against
a `rest.RESTClientFor`-built client — the same machinery kubelet/KCM informers use, per
the postmortem's own suspicion that a naive HTTP client might not trigger whatever
client-go's internals react to. Ran both modes for 8s each: `broken` mode delivered 23
continuous `ADDED` events with the header actually inserted on every chunked response
(`is_streaming=true inserted=true` confirmed in server logs); `fixed` mode delivered 26
events with no insertion. **Neither mode produced a single `context canceled`, watch
error, or `ResultChan` closure** — `RetryWatcher` behaved identically in both. The one
hypothesis this doesn't test is "a naive/non-client-go client wouldn't trigger it," which
was also checked with a raw-TCP client (same result: no disruption in `broken` mode).

**Tier 3: not attempted.** Given Tier 1 and Tier 2 converged on the same negative result
using the real client machinery the postmortem specifically flagged as suspect, and this
is a time-boxed P3 investigation, VM-based precondition-narrowing (bringing up the full
u7s stack and subtracting components) was judged not to be a good use of the remaining
budget without a positive Tier 2 signal to chase.

**Verdict:** mechanism narrowed, not proven — inconclusive. Both plausible failure levels
(the `http`/`axum-core` type system, and a real client-go `RetryWatcher` against a
single long-lived watch) show no coupling. The bisection's finding that the header insert
is empirically the single differentiating operation is not in doubt (it was proven by the
operator's own commit-level bisection and confirmed stable across four live runs); what
remains unexplained is why. The two most likely untested preconditions, in order of
suspicion: (1) **TLS layering** — the real apiserver serves over `tokio-rustls`; this
repro used plain HTTP, and TLS record buffering/flushing timing sits exactly at the
boundary between "headers committed" and "bytes on the wire" that this investigation
otherwise ruled out at the safe-Rust level; (2) **concurrent watch load** — the
conformance run has dozens of simultaneous long-lived watches sharing the same
`ContentTypeService` and store `Arc`, and this repro tested one connection at a time. A
future attempt should add TLS and concurrent watch load to the same repro harness (both
are additive to what's already built in `temp/mo96q-repro/`) before concluding the
mechanism is unreachable by direct experiment.

## Addendum 2026-07-30: TLS and concurrent-load preconditions also ruled out

`mayor-e25ge` extended the mo96q repro (`temp/e25ge-repro/`, gitignored) with the two
untested preconditions the previous addendum flagged: TLS layering (tokio-rustls 0.26.4
+ a real self-signed cert via rcgen 0.14.8, mirroring
`crates/apiserver/src/lib.rs::serve_tls`'s exact
`TcpListener`→`TlsAcceptor`→`hyper_util::TokioIo`→`hyper::service_fn` wiring) and
concurrent watch load (N=1/25/50 simultaneous real `client-go@v0.36.2` `RetryWatcher`
clients sharing one server process). Ran the full cross product (TLS-only,
concurrent-only, TLS+concurrent) × (broken/fixed mode) for 15-20s each, up to N=50:
**zero cancellations, restarts, or anomalous log signals in every cell**, cross-validated
via both klog output and a direct resourceVersion-reset detector. Neither hypothesis
reproduces, alone or combined. All three levels this investigation has now checked
(type-level source read, single-connection real client, TLS+concurrent-load real client
at conformance-scale N) show no coupling.

**Verdict: mechanism investigation closed as unproven-but-fixed.** The fix (PR #907)
remains validated by commit-level bisection and four independent stable live runs;
further first-principles pursuit of *why* is not a good use of effort against an
already-resolved, stable issue.
