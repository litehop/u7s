# Dashboard
2026-07-02T23:05Z — **u3fa FIXED + MERGED (#653): batch namespace-delete now assigns a distinct rv per object (etcd-like), so watchers no longer dedup-drop DELETE events → the permanent Endpoints 409-loop is gone. 9 PRs merged this session. Mayor on main `266f7897` = origin. 0 open PRs. 0 workers. Board: 19 ready.**

Resume: `bd prime`

## What needs the operator now
- **Nothing blocking.** The u3fa consistency bug (proven root cause, live-verified fix) is landed.
- **mayor-7lrp is now the clean residual (re-scoped, OPEN).** Post-#653 the EndpointSlice --focus test STILL fails but PURELY for the 7lrp reason: "EndpointSlice informer cache is out of date" (endpointslice controller's informer lags its own write — bookmark-delivery latency). The first 7lrp scout's "get()/list() guards are correct" now looks RIGHT; the real 7lrp is watch/informer-consistency latency, which the 0702-watch-consistency-audit flagged as HARD / maybe-not-fully-fixable without forking KCM. RECOMMEND: re-measure on a fresh run, then a design decision on whether/how to fix — surface to operator before committing to an approach. Evidence: ai/findings/u3fa-7lrp-evidence/.

## Uncommitted (fold into next push): .beads/ (7lrp re-scope note).

## ✅ PROVEN ROOT CAUSE (u3fa) — batch-delete watch event loss
Physical evidence (preserved: ai/findings/u3fa-7lrp-evidence/{apiserver-a731152e.log, consistency-scout-verdict.md}), VERIFIED by mayor against log + code:
- `delete_namespace_sync` (sqlite.rs:384) deletes all ns objects in one txn, bumps the global revision counter ONCE → every deleted object stamped the SAME rv (596 in capture).
- `push_event` fires N DELETE events all at rv=596; watch dedup (sqlite.rs:995 `event.revision <= last_replayed`) yields the first, then **permanently drops the rest** (log line 2806: `dedup skip .../endpoints/.../example-named-port rv=596 last_replayed=596`).
- endpoints-controller never sees the DELETE → keeps stale informer cache → PUTs old rv → correct 409 (RevisionMismatch{expected:N,current:0}, object is gone) → retries from the never-updated cache → **infinite 409-loop** (16 PUTs over 40+s) → EndpointSlice test FAILS.
- **Refuted:** #646 scope (it's a 409, not a 403); first 7lrp scout's "WAL stale read / watch latency" (guards ARE fine; this is permanent event loss, not timing).
- **Fix (in flight):** per-object rv increment in delete_namespace_sync (sole multi-object mutation path — confirmed) so every DELETE gets a distinct watch event. Atomicity preserved (still one BEGIN IMMEDIATE/COMMIT).

## ✅ #654 MERGED (6c8a5bde) — proto cluster + generic PATCH TypeMeta
on07 (Volume defaultMode), a83z (Lease MicroTime NANOS — not a missing field), dfly (GENERIC do_patch TypeMeta bug — NOT DRA-specific; fixes kind-less PATCH responses for ALL resources). 3 beads closed. Follow-up filed: measure which other PATCH conformance tests now pass on next full run.

## ✅ #655 MERGED (58ca5aa9) — GET /pods/<name>/resize (was 405). lp6i closed.
Caveat noted: --focus couldn't fully validate (conformance pod stayed Unschedulable in the VM — infra, unrelated; 405→200 proven via kubectl). FLAG for next full run: unschedulable-pod may affect other --focus gates (possible node-saturation/scheduler env issue).

## ✅ #656 MERGED (86127e5a) — f5p5 DONE. Both terminating-scope conformance sub-tests PASS (:803 + scopeSelector :1567). Root cause was 2 MORE proto-drops (activeDeadlineSeconds field 5 + scopeSelector field 3). f5p5 closed.

## (history) PR #656 (f5p5) — the debugging saga
DEBUG SCOUT af7f2d1d cracked it: BOTH failures were proto-drops (again!):
1. **activeDeadlineSeconds (PodSpec field 5) was "skipped"** in the decoder (proto.rs:930) → pod_is_terminating saw Null for EVERY pod → Terminating quota never counted the terminating pod. Debug log proof: `pod_is_terminating: ... activeDeadlineSeconds=Null result=false`.
2. **spec.scopeSelector (ResourceQuotaSpec field 3) never decoded** ("skipped" proto.rs:2750) → scopeSelector-variant quota looked scope-less, counted all pods.
FIX (mayor-VERIFIED uncommitted diff, correct field numbers vs upstream, debug logging stripped, live-verified used=0/1): added activeDeadlineSeconds field 5 + ScopeSelector/ScopedResourceSelectorRequirement structs + scopeSelector eval (Exists/DoesNotExist) in quota.rs. Regression test present. 1839 tests pass.
NOW: scout resumed to commit+push to the f5p5 branch (updates #656) + run the --focus gate in FOREGROUND. Merge #656 once it confirms both sub-tests (:803 + :1567) PASS.
ALL prior 5 commits confirmed correct+needed. This bead = 4 proto-drops total (scope logic was fine, it had no data).

**🔑 THIS IS THE STRONGEST DATA POINT FOR THE TYPING RESEARCH (a3e16361):** f5p5 alone was TWO more silent proto-field-drops. The "skipped" comments in proto.rs are a systematic landmine — every hand-skipped field is a latent conformance bug. Feed this to the operator's typing decision.

LESSONS THIS BEAD: (a) forking-early + long-running workers go STALE vs mid-session merges → check branch base before merging. (b) "still building" backgrounded runs stalled workers 2× → briefs mandate FOREGROUND run-all.sh. (c) always read the e2e.txt PASS/FAIL yourself. (d) a correct scope FIX with dropped input DATA still fails — trace the data, not just the logic.

Both routing beads were MIS-FRAMED — scout af69fee4 caught that lp6i's "route missing" was actually a missing GET method, f5p5's "404" was actually a Terminating-scope accounting bug (/status works fine). Root-cause-first avoided 2 bad fixes (one would've regressed conformance). Scout doc: ai/findings/f5p5-lp6i-routing-scout-2026-07-02.md.

## 🔬 PROTO TYPING INITIATIVE (in progress — operator-driven strategic thread)
**Churn research (a3e16361) DONE** (doc: ai/findings/k8s-proto-schema-churn-1.34-1.36-2026-07-03.md). Verdict: upstream GA proto is addition-dominated, ~0 breaking changes over 1.34→1.36 (55 field adds, 1 alpha-field edge case). CRUCIAL REFRAME: our .proto FILES are already complete/current at v1.36; the bug source is **proto.rs = 17.6k lines of hand-written PARTIAL prost structs (224 of 643 msgs)**. "Type everything" = complete the structs, not track schema. Bloat negligible (~225KB). Kills the proto-drop bug class by construction.
**Operator decision:** pursue it as an EPIC. But first raised the SOURCE-OF-TRUTH question: should our TYPES be source of truth (author Rust → derive proto, check vs upstream) [Direction B, operator's lean] rather than codegen types FROM upstream proto [Direction A]? Rationale: upstream Go structs are the real source; proto+OpenAPI are DERIVED from them — so deriving from upstream's derived-proto is backwards.
**NOW: spike a65027ab** — evaluates Direction B concretely (Rust-types→proto toolchain viability, field-number pinning mechanism, compat-checker design, 3-way cost/readability) + a throwaway Lease PoC. THEN file the EPIC with a decided direction. Note: proto.rs TODAY is already hand-authored Rust w/ #[prost(tag=N)] — Direction B may = "what we do now but COMPLETE + a compat-checker". Doc: ai/findings/proto-source-of-truth-spike-2026-07-03.md.
Downstream: connects to deferred OpenAPI-v2 bead mayor-52wo (complete typing is a necessary-not-sufficient prereq).

## Next candidates (bd ready ~13 remaining)
- **mayor-7lrp (P1)** — watch/informer-consistency latency (re-scoped, see above) — needs a design decision, not a blind fix.
- **~16 symptom-framed P2 conformance beads** — root-cause-verify each (--stack-only kubectl repro) before a fix worker. Known proto-decode-drop instance still open: none this session (2w29 shipped). Others: qrip (STS rolling update), on07 (volume defaultMode), frxo (SA token credential-id), a83z (Lease nil renewTime), kxht (VAP outcomes+panic), rsei (scheduler preemption), dfly (DRA PATCH kind), uam0 (CRD /openapi/v2), f5p5 (resourcequota/status 404), lp6i (pod resize 405), pu5i (pod log 500), n124 (pod proxy CONNECT tunnel), 2av8 (dryRun+RuntimeClass), y832 (sonobuoy progress), f60a (webhook timeout type). Infra: zc9l, vehd.
- **mayor-cef5 (P3)** — deferred audit findings (perf F1 admission-config-cache; delete_collection error-swallow F-05).

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
