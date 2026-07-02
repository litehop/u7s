# Dashboard
2026-07-01T00:47Z — **P1 crash RESOLVED (#633 merged — CRD tombstone 410 no longer hot-loops sendInitialEvents watches). Full conformance run now UNBLOCKED. Mayor on main `ea501a1e` = origin. 0 workers, 0 open PRs (2 external Renovate). Branch protection ON. Loops CANCELLED.**

Resume: `bd prime`

## What needs the operator now
- **FULL CONFORMANCE RUN — now truly unblocked.** The P1 that killed the last run (#633) is fixed; resizePolicy + the whole since-#617 batch are in. Your lima-node stack is fresh (--reset'd). This is the recommended next step: re-baseline off a real full run instead of the stale 0627 partial. Loops stay OFF during it; I triage e2e.txt when it lands.
- **2 external Renovate PRs** (cheap, whenever): #632 (rust-toolchain digest bump), and note #628 rmcp-v2 already merged. #632 may just need CI to pass; check before merge.

## 🔴→✅ The P1 crash (RESOLVED) — CRD sendInitialEvents 410-storm
A full conformance run DIED: u7s returned bare 410 for `watch+sendInitialEvents` on a TOMBSTONED (deleted) CRD group → the webhook test's informer couldn't recover (its re-LIST also 410'd, no resumable RV) → hot-loop ~6000/s → apiserver self-saturated (unreachable inside+outside cluster) → run died, zero results.
- **Root cause:** find_crd returns the (correct-for-deleted) tombstone 410 as the FIRST op in list_cr, BEFORE the watch branch — so it wrongly applied to watch+sendInitialEvents, which loops instead of stopping.
- **Fix #633 (mayor-jiap, merged):** narrow guard — tombstoned group + watch + sendInitialEvents → serve empty watch stream (200+BOOKMARK) so the informer parks; non-watch + plain-watch 410 preserved (+ tests). Clear tombstone on replace_crd PUT. Live-verified controlled (no flood), CI 17/17.
- **Diagnosis took 3 scouts** (1 stalled+salvaged) + operator's kill-apiserver/check-cri-o-logs steer to pin the live client. Evidence archived: `temp/research/crash-0630/`.
- **Recovery lesson:** apiserver restart / sonobuoy delete / pod-kill all FAILED to stop the live storm (client reconnects; saturation deadlocks graceful cleanup); only killing the apiserver + full --reset cleared it.

## Open beads — 4, all P3 (post-full-run priority; the run will re-rank them)
- **mayor-ma3q** — resize status.resize acknowledgment: bulk resize specs time out 300s. SPIKE-FIRST (revisits the wjon "conditional gaps not needed" conclusion for the broader set).
- **mayor-u8w7** — reject invalid resize patches with 422 ('apply invalid resize patch requests' specs).
- **mayor-w8tj** — PDB disruptedPods reconcile-race (watch-semantics; flaky; hard — needs a watch-delivery-to-KCM-informer investigation).
- **mayor-kxsk** — Foreground deletion propagation (feature; foregroundDeletion finalizer loop).

## Deferred (3)
mayor-52wo (embed upstream OpenAPI v2 — #621 laid the gnostic-proto prereq; this greens kubectl --validate specs) · mayor-j7to (Argo CD RBAC seed) · mayor-rvkq (CRD CEL validation).

## Durable patterns banked (ai/extended-context/apiserver-code-gotchas.md — committed 2f74743b)
Two ⚠️ PATTERN sections for future workers: (1) **proto-decode field drops** (~8 instances: enableServiceLinks/runtimeClassName/Service.status/EndpointSlice/PVC-status/PDB-status/ownerRefs/resizePolicy) — missing field in the prost struct silently dropped on decode; add w/ correct upstream field number + round-trip test + AUDIT siblings; a systematic proto-vs-upstream audit would surface the rest in one sweep. (2) **ObjectMeta round-trip drops ownerReferences** (3 sites). Operational half in bd memory `dispatch-proto-decode-drop-check`.

## Recently merged (this session, newest first)
#633 CRD tombstone-410 hot-loop fix (P1, jiap) · #631 resizePolicy proto decode (op18; resize 4→16) · #630 resize generation+subresource-discovery (21gi/usz6) · #628 rmcp v2 (3ki4) · #629 CR cascading deletion (0qqs) · #627 PDB status decode+generation (2z1k, partial→w8tj) · #626 CronJob cascade + ownerRefs decode/create (2f5a) · #625 RC no-policy→Orphan (wo9t) · #624 dead default_pod + scale-handler dedup (9xb5/trb0) · #623 OIDC discovery endpoints (p8qh) · #620 RBAC escalate-verb (a31j) · #619 default ServiceCIDR seed (zief). (Earlier: #614 KCM-killer, #615 RC scale, #617 GC cascade+Orphan, + the scheduler/konnectivity infra fix.)

## Stance
Pre-alpha Kubernetes apiserver in Rust. Correctness > conformance breadth. Workers in isolated worktrees (ALWAYS isolation="worktree"); mayor orchestrates, doesn't code (except trivial 4-condition externally-verified edits). Merge-on-green WITH verification (incl. conformance --focus for spec-targeting beads; repeat for races). No back-compat shims. Never --admin. Mayor: confirm branch=main + pwd before bead/dashboard ops.

## VM slots
| Slot | VM | Port | Kubelet | Konnectivity | Status |
|---|---|---|---|---|---|
| mayor | lima-node | 6443 | 10250 | 8135 | operator stack (fresh --reset) |
| worker-1 | lima-node-smoke | 6444 | 10251 | 8235 | free |
| worker-2 | lima-node-2 | 6445 | 10252 | 8335 | free |
Konnectivity auto-derives from port (mayor-evnb fix): 8135 + (port − 6443) × 100.

## Session loops
CANCELLED. Re-create on resume: :07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard
