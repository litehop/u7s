# Dashboard
2026-07-02T22:39Z — **7 fixes merged. ROOT CAUSE of u3fa PROVEN (physical log evidence) + FIX IN FLIGHT: batch namespace-delete stamped all objects ONE rv → watch dedup silently dropped all-but-one DELETE event → controllers wedged in a permanent 409-loop. NOT a SQLite stale read; NOT #646. Operator chose Fix A (unique rv per object, etcd-like). Mayor on main `d806ee4e` = origin. 0 open PRs. 1 worker (u3fa fix).**

Resume: `bd prime`

## What needs the operator now
- **Nothing blocking.** u3fa fix worker running (Fix A, live-verified via --stack-only + --focus EndpointSlice gate). I'll verify its diff + VM evidence and bring the PR when it lands.
- **After u3fa merges: re-scope mayor-7lrp** against fresh data (it's a SEPARATE, transient bookmark-latency issue — the batch-delete fix may reduce its errors too; measure before deciding if it needs its own fix). u3fa is blocked-by 7lrp in bd but they're distinct bugs — will unlink/re-scope post-merge.

## ✅ PROVEN ROOT CAUSE (u3fa) — batch-delete watch event loss
Physical evidence (preserved: ai/findings/u3fa-7lrp-evidence/{apiserver-a731152e.log, consistency-scout-verdict.md}), VERIFIED by mayor against log + code:
- `delete_namespace_sync` (sqlite.rs:384) deletes all ns objects in one txn, bumps the global revision counter ONCE → every deleted object stamped the SAME rv (596 in capture).
- `push_event` fires N DELETE events all at rv=596; watch dedup (sqlite.rs:995 `event.revision <= last_replayed`) yields the first, then **permanently drops the rest** (log line 2806: `dedup skip .../endpoints/.../example-named-port rv=596 last_replayed=596`).
- endpoints-controller never sees the DELETE → keeps stale informer cache → PUTs old rv → correct 409 (RevisionMismatch{expected:N,current:0}, object is gone) → retries from the never-updated cache → **infinite 409-loop** (16 PUTs over 40+s) → EndpointSlice test FAILS.
- **Refuted:** #646 scope (it's a 409, not a 403); first 7lrp scout's "WAL stale read / watch latency" (guards ARE fine; this is permanent event loss, not timing).
- **Fix (in flight):** per-object rv increment in delete_namespace_sync (sole multi-object mutation path — confirmed) so every DELETE gets a distinct watch event. Atomicity preserved (still one BEGIN IMMEDIATE/COMMIT).

## In-flight
| Worker | Bead | Surface | State |
|---|---|---|---|
| fix (a906b74f) | mayor-u3fa (P1) | crates/store/src/sqlite.rs + live VM lima-node-smoke:6444 | ⏳ Fix A (unique rv per deleted object). Regression test (fails-on-revert) + live verify: no dedup-skip/409-loop after fix, --focus EndpointSlice test PASSES. |

## 🔬 P1 (mayor-7lrp) re-investigation — the framing is suspect
First scout (findings: ai/findings/7lrp-wal-stale-read-scout-2026-07-02.md) claimed the get()/list() guards are correct and pivoted to "watch-delivery latency" as the cause of the 598 "read version N not as new as written version M" errors — but NEVER physically proved a stale read occurs, and never examined how rv is computed/stamped/served. Operator flagged this as the SAME hand-wave shape that cost 2 days on PDB (where the real bug was our apiserver dropping `spec` on proto decode). Prior: SQLite is ACID + benchmarked orders of magnitude above our load; a read regressing after a newer read is unthinkable unless OUR code is wrong.
**Suspect zone (mayor's read):** single GLOBAL revision counter in `meta` (sqlite.rs:276), objects stamped with global value (stamp_resource_version :209-219 @ :289), last_written_revision global AtomicU64 (:37,:311). Hypotheses for 2nd scout: (1) HTTP response returns rv=M but stored/served object carries a different rv (PDB-class mis-serve); (2) kcm's GLOBAL-rv ConsistencyStore trips because a per-resource LIST snapshot rv < global M (another resource advanced the global counter); (3) counter advanced before COMMIT durable; (4) content_type re-encode alters rv.

## In-flight
None. (EndpointSlice scout a731152e STALLED at watchdog before writing its doc; partial captured + apiserver.log preserved. Next: one merged u3fa+7lrp consistency scout — awaiting operator go on scope.)

## ✅ Tooling fix landed: --stack-only (#651, mayor-inox)
run-all.sh now has --stack-only (steps 1-5, skip sonobuoy — stack left up for kubectl/DB) + vm-operations.md documents it + a bare-run=~6h warning. This closes the runaway that killed the first 7lrp scout. Mayor-side follow-ups DONE: dispatch-prompt-template.md Lima block now mandates --focus/--stack-only + warns against bare run-all.sh (uncommitted — fold into next push); bd memory worker-run-all-verbatim updated with flag discipline.

## Queued next
- **mayor-u3fa (P1)** — EndpointSlice regression (scout IN FLIGHT above). If #646 is the cause, the fix likely reverts/narrows the matches_rule scope logic — will surface to operator (touches admission we just shipped).
- **mayor-7lrp (P1)** — WAL stale-read, PAUSED. RE-DISPATCH the adversarial scout (now with --stack-only, no sonobuoy needed) AFTER u3fa, since u3fa may share a root cause (both could be admission/CAS write-path regressions). Mandate: physically prove a SQLite stale read OR pin our rv compute/stamp/serve bug. First scout doc (hypotheses to falsify): ai/findings/7lrp-wal-stale-read-scout-2026-07-02.md.

## Recently shipped this session (all merged, mayor-verified)
#650 Job proto decode (successPolicy/podFailurePolicy + zero per-index limits, 2w29) · #649 beads-sync · #648 rmcp 2.1.0 · #647 PATCH CAS + JSON-Patch /status isolation (egmm/o419) · #646 CEL checked-arithmetic + matches_rule scope (wucf/gzm3) · #645 Deployment/RS status proto decode (0mth). Plus 3 audits closed (perf/quality/security).

## This session's shipped work (all merged 2026-07-02 ~15:02Z, all diffs mayor-verified)
- **#647** (egmm P1 + o419 P2) — PATCH subresource CAS: scale/approval/status PATCH handlers now source the CAS token from the incoming patch body (was: stored RV = unconditional writes; #643 fixed the PUT siblings, these were missed). HPA-critical (scale is PATCH-only). + JSON-Patch /status path-isolation (422 if a JSON Patch on /status targets /spec — was a priv-esc). 1816 tests.
- **#646** (wucf P1 + gzm3 P2) — admission: CEL i64 arithmetic now checked_* (was panic-DoS via crafted VAP/MAP, incl i64::MIN/-1). + matches_rule now enforces rule `scope` (Namespaced/Cluster) — the correct use of the previously-discarded `namespace` param (namespaceSelector labels were already done by callers). SECURITY PR, reviewed. 1812 tests.
- **#645** (0mth P1) — proto: Deployment.status + ReplicaSet.status now decoded (were dropped; new instances of proto-decode-drop pattern). Added 4 prost structs + status fields at tag 3; all field numbers verified vs upstream apps/v1. 1806 tests.

## Audit outcome (3 audits closed w/ verdicts+cross-refs; docs in ai/findings/audit-2026-07-02/)
Auth/RBAC/JWT core verdict = SOLID (no bypasses). 24 raw findings synthesized. 5 HIGH all now shipped. Systemic themes found: (1) PATCH subresource handlers lagged the PUT-CAS fix (#643); (2) proto-decode-drop recurrence. Full findings: perf.md / quality.md / security.md.

## Open beads (20)
- **mayor-cef5 (P3)** — deferred audit findings tracker. Strongest promote candidates: perf F1 (admission does 5 SQLite LISTs per write for near-static configs → cache in AppState; biggest write-latency lever) and quality F-05 (delete_collection swallows non-NotFound errors → silent partial delete + quota drift).
- **mayor-7lrp (P1)** — WAL stale read (see top; next up).
- **~17 symptom-framed P2 conformance beads** — 2w29 (Job proto decode: successPolicy/podFailurePolicy — ANOTHER proto-decode-drop instance), qrip (STS rolling update after patch), on07 (volume defaultMode), frxo (SA token credential-id), a83z (Lease nil renewTime), kxht (VAP wrong outcomes+panic — DISTINCT from wucf's arithmetic panic), rsei (scheduler preemption), dfly (DRA PATCH missing kind), uam0 (CRD not in /openapi/v2), f5p5 (resourcequota/status 404), lp6i (pod resize 405), pu5i (pod log 500), n124 (pod proxy konnectivity CONNECT tunnel), 2av8 (dryRun+RuntimeClass), y832 (sonobuoy progress dropped), f60a (webhook timeout error type). Infra: zc9l (smoke coverage), vehd (k8s patch-version check).

## Durable patterns banked (ai/extended-context/apiserver-code-gotchas.md)
proto-decode field drops (now +2: Deployment/RS status) & ObjectMeta ownerReferences round-trip drops. bd memory: dispatch-proto-decode-drop-check. mayor-2w29 (Job) is the next known instance to fix.

## Stance (unchanged, confirmed this session)
Pre-alpha Kubernetes apiserver in Rust. Correctness > conformance breadth. Workers in isolated worktrees (ALWAYS isolation="worktree"); mayor orchestrates, doesn't code (4-condition gate). Merge-on-green WITH verification. No back-compat shims. Never --admin. Flag security/API/architecture PRs. Mayor: confirm branch=main + pwd before bead/dashboard ops.

## VM slots
| Slot | VM | Port | Kubelet | Konnectivity | Status |
|---|---|---|---|---|---|
| mayor | lima-node | 6443 | 10250 | 8135 | operator stack |
| worker-1 | lima-node-smoke | 6444 | 10251 | 8235 | free (stopped) |
| worker-2 | lima-node-2 | 6445 | 10252 | 8335 | free (running) |
Konnectivity auto-derives from port: 8135 + (port − 6443) × 100.

## Session loops (session-only, auto-expire 7d)
:07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard
