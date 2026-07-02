# Dashboard
2026-07-02T15:03Z — **Audit→fix cycle COMPLETE. 3 audits ran → 6 beads filed → 5 HIGH/MED fixes shipped in 3 PRs (#645/#646/#647), all merged green. Mayor on main level with origin. 0 workers, 0 open PRs. Board: 20 ready.**

Resume: `bd prime`

## What needs the operator now
- **Nothing blocking.** This session's wave (audits-first, your call) is fully landed and verified. Ready for the next move.
- **Recommended next: the P1 (mayor-7lrp) — SQLite WAL stale-read** wedging kcm controllers (598 "not as new as written version" in one run; widest blast radius on run stability). Well-root-caused, dispatch-ready. NOTE before dispatch: the w8tj bead history + `ai/findings/0702-watch-consistency-audit.md` both flag the global BOOKMARK-per-write (sqlite.rs:166-172) as a watch-consistency concern — likely adjacent to this bug. A scout should read both before the fix worker starts.
- **Then: ~17 symptom-framed P2 conformance beads.** Root-cause-verify each (scout/kubectl repro) before dispatching a fix — per verify-bead-framing-before-dispatch, symptom-filed beads are often wrong about cause.

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
