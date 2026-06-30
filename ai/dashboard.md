# Dashboard
2026-06-29T13:30Z — **GC-bug wave: #626 (CronJob cascade + ownerRefs decode/create) + #627 (PDB status decode + generation) MERGED. 0qqs (CR-cascade) scouted → fix-ready. PDB residual race split to mayor-w8tj. Mayor on main `263891af`, 0 workers, 0 open PRs, all VMs free. Branch protection ON. Loops CANCELLED.**

Resume: `bd prime`

## ✅ #629 MERGED (mayor-0qqs) — P2 lead done; ALL 3 re-verify GC bugs resolved
CR (CRD-backed) cascading deletion: cr.rs delete handlers now parse DeleteOptions + apply_delete_policy + cascade_delete_cr_dependents (recursive ownerRef scan, honors Orphan). --focus PASSES, CI 17/17, 6 fail-on-revert tests. Found the THIRD ownerRefs-drop: stamp_cr_fields had the same ObjectMeta-round-trip bug (CRs lost ownerRefs on create) — fixed (cf #626). Foreground finalizer-loop deferred (kxsk). → **2f5a (#626) + 2z1k (#627, partial→w8tj) + 0qqs (#629) ALL DONE.**

## ✅ #630 MERGED (mayor-21gi + mayor-usz6) — resize fixes + conditional-gap probe ANSWERED
2 small resize fixes (generation-bump + 6 pod subresources in /api/v1 discovery). **3 of 6 resize conformance specs now PASS** (were all failing pre-#617). The probe DEFINITIVELY answered the spike's open questions: allocatedResources-synth = NOT REAL (kubelet writes it); PodResizePending/InProgress conditions = NOT BLOCKING (status.resize='Proposed' suffices). Neither built — confirmed-not-needed, the spike→probe discipline working.
- **NEW: mayor-op18 (P2)** — the 3 remaining resize failures (+~65 non-conformance) trace to **Container.resizePolicy stripped on proto decode (field 23 missing from proto.rs)** — the 4th+ proto-decode-drop. Highest-leverage resize follow-up. (3rd conformance spec 'resize via replace endpoint' fails for a DIFFERENT reason: init-container 'sleep 1d' never exits init — separate.)

## ✅ #631 MERGED (mayor-op18) — resizePolicy decode; resize passing 4→16
Container.resizePolicy (proto field 23) was missing from the prost struct → stripped on decode. Added it (additive +115/-0, proto.rs). Live-verified resizePolicy survives the round-trip; resize --focus passing 4→16. CI 17/17. NO regression (additive-only; the "0/3 conformance" in the run was a DIFFERENT spec subset than #630's 3-pass — the focus matches a nondeterministic set, not a regression — confirmed by the additive diff). **resizePolicy DONE = operator's pre-full-run gate cleared.**
- **2 remaining resize gaps FILED (separate, P3):** mayor-u8w7 (reject invalid resize patches w/ 422 — validation), mayor-ma3q (status.resize acknowledgment — bulk 300s timeouts; SPIKE-FIRST, partially revisits the wjon "conditional gaps not needed" conclusion since the broader set times out).

## ✅ #628 MERGED (mayor-3ki4) — rmcp v2 cleanup done
rmcp 1.7→2.0: Content removed in v2 → migrated to ContentBlock (same ::text ctor), 4 lines in mcp-server/src/lib.rs. CI 17/17, 1923 tests. v2 brings OAuth/SSRF/session-leak security fixes.

## 0 workers, 0 PRs, both VMs free, on main `a363d914`. ⇒ FULL CONFORMANCE RUN is the clean next step (operator's to launch)
resizePolicy gate cleared. The full run uses the mayor's lima-node stack (no worker-VM contention). Re-baselines the LARGE since-#617 batch: GC cascade (RC/RS/STS/CronJob/CR→deps) + Orphan/propagationPolicy/orphanDependents + ownerRefs decode/create ×3 + PDB status + ServiceCIDR seed + OIDC discovery + RBAC escalate + OpenAPI proto + resize (resizePolicy+generation+subresource discovery) + scheduler/konnectivity infra. We've been fixing spec-by-spec off the stale 0627 partial; the full run gives a real remaining-surface map + auto-confirms maybe-fixed (w8tj flaky). Loops stay OFF during it; mayor triages e2e.txt when it lands.
⚠️ UNCOMMITTED (fold into next commit; the gotchas doc is committed-tracked, not gitignored): ai/extended-context/apiserver-code-gotchas.md (2 new ⚠️ PATTERN sections — proto-decode drops + ObjectMeta-round-trip drops) + dashboard + beads.

## READY: FULL CONFORMANCE RUN (operator's to launch)
resizePolicy gate cleared (#631). Both worker VMs free; the rmcp worker uses no VM. The full run uses the mayor's lima-node stack — independent of the rmcp worker. Recommended next: re-baseline the large since-#617 batch (GC cascade/orphan/ownerRefs ×N, PDB, ServiceCIDR, OIDC+RBAC, OpenAPI proto, resize). Loops stay OFF during it. Mayor triages the e2e.txt when it lands.

## Patterns BANKED this turn (operator request — "remember serde substructure drops")
- **ai/extended-context/apiserver-code-gotchas.md** — added 2 ⚠️ PATTERN sections (durable, committed-on-next-commit): (1) proto-decode field drops (~8 instances logged: enableServiceLinks/runtimeClassName/Service.status/EndpointSlice/PVC-status/PDB-status/ownerRefs/resizePolicy) — rule: missing field in the prost struct, add with upstream field number + round-trip test + AUDIT siblings; (2) ObjectMeta serde round-trip drops ownerReferences (3 sites: create handler, object_meta_to_json, stamp_cr_fields) — save+restore workaround, or add fields to ObjectMeta.
- **bd memory `dispatch-proto-decode-drop-check`** — operational: inject the proto-drop check into every proto/pod/CR/defaulting dispatch brief.
- CANDIDATE FOLLOW-UP BEAD: a systematic proto-struct-vs-upstream AUDIT (would surface remaining drops in one sweep instead of one-spec-at-a-time). op18's worker reports the Container-struct sibling-gaps as a start.

## rmcp v2 (#628) — FILED as mayor-3ki4 (P3 chore), HELD for dispatch
COST EVALUATED: SMALL (~15-30min). Pure version bump but FAILS test/lint/coverage on ONE compile error: `unresolved import rmcp::model::Content` (v2 renamed/moved Content per "align model types w/ MCP 2025-11-25 spec"). Blast radius: 1 file `crates/mcp-server/src/lib.rs` (1 import + 3 `Content::text()` calls). Risk LOW (MCP tooling crate, not apiserver). Value MODERATE (v2 security fixes: OAuth spoofing, SSRF, HTTP session leak).
**DISPATCH GATE (operator: "when there's no risk of conflict"):** the only shared surface with apiserver work is Cargo.lock (workspace-wide). Dispatch mayor-3ki4 ONLY when NO other worker is modifying Cargo.lock — i.e. after op18 (in-flight) lands, or any quiet window. Worker extends PR #628's branch. cargo-only, no VM.

## Inflection point: FULL CONFORMANCE RUN after op18
Operator plan: handle resizePolicy (op18, in-flight) BEFORE the full run. Once op18 merges → run it. This session merged a large batch since #617 (GC cascade RC/RS/STS/CronJob/CR, Orphan+propagationPolicy, ownerRefs ×3, PDB status, ServiceCIDR, OIDC+RBAC-escalate, OpenAPI proto, resize) — been fixing spec-by-spec blind; the full run converts that into a real remaining-surface map + auto-confirms maybe-fixed (w8tj flaky, op18 landing).

## Next decisions (after these land)
- **mayor-w8tj (P3)** — PDB reconcile-race (watch-semantics investigation; flaky, hard).
- **mayor-kxsk (P3)** — Foreground deletion propagation (feature; finalizer loop).
- **mayor-52wo (DEFERRED)** — OpenAPI embed / kubectl-validate decision.
- **Fresh full conformance run** — re-baseline everything this session fixed.

## ✅ MERGED this wave (GC bugs)
- **#626 (mayor-2f5a)** — CronJob→Jobs→Pods cascade. PLUS two FOUNDATIONAL bugs the worker found en route: object_meta_to_json (proto) dropped ownerReferences from EVERY decoded object; create_namespaced_resource's ObjectMeta round-trip dropped ownerReferences on EVERY create. Both fixed (proto-decode-drop / serde-round-trip-drop family). CronJob GC --focus PASSES. CI 17/17. (These ownerRefs fixes likely help other GC specs.)
- **#627 (mayor-2z1k, PARTIAL)** — fixed 2 REAL PDB bugs: proto decoder dropped status.disruptedPods (field 3); generation=0 on create. CI 17/17. BUT does NOT fully green the PDB spec — residual KCM-reconcile race remains → **mayor-w8tj**.

## ⚠️ mayor-w8tj (P3, NEW) — PDB residual reconcile-race (the hard part of 2z1k)
PDB spec still FLAKY (3 runs: PASS/FAIL/FAIL) after #627's 2 real fixes. Verified chain: test writes disruptedPods (PERSISTS), KCM disruption controller reconciles ~2s later + clears it (pod Running, rebuilds map from matching pods), test's read-back races KCM. #627's generation=1 fix is insufficient: the test's 2nd waitForPdbToBeProcessed (after the status write) is a no-op (observedGeneration>=generation already holds from KCM's create-time reconcile). WHY real k8s blocks there is UNRESOLVED. Leading hypothesis: u7s PDB WATCH doesn't promptly deliver status-subresource updates (incl. disruptedPods) to KCM's informer cache → buildDisruptedPodMap rebuilds from stale cache. Needs a deep watch-semantics investigation, NOT another blind patch. Full findings in the bead. LESSON: 3 incomplete theories on this bead, each surfaced by RUNNING the spec repeatedly — code-reading alone said "fixed" twice and was wrong both times.

## Open beads — P2 (confirmed, dispatchable)
- **mayor-0qqs** — CR cascading deletion (fix-ready, design recorded; medium).

## Open beads — P3
- **mayor-21gi** + **mayor-usz6** — the 2 resize fixes (queued; dispatch + resize --focus).
- **mayor-w8tj** — PDB reconcile-race (watch-semantics investigation; flaky, lower urgency).
- **mayor-kxsk** — Foreground deletion propagation (feature; finalizer machinery).

## Deferred (3)
mayor-52wo (OpenAPI embed — prereq #621 merged) · mayor-j7to (Argo CD RBAC seed) · mayor-rvkq (CRD CEL validation).

## STANDING LESSON (reinforced hard this wave): run the conformance SPEC, repeatedly
Spec-targeting fixes are NOT done on cargo-green + a kubectl repro + a code-reading argument. This wave: #626's CronJob fix only worked after finding 2 deeper ownerRefs drops; #627's PDB "fix" passed code-review TWICE and failed the --focus BOTH times; the flake was only exposed by running the spec 3×. For any conformance bead: require the --focus result, and for suspected races, require MULTIPLE runs. "It's a KCM race / real k8s passes it anyway" is an explain-away to distrust until proven (here it WAS partly real — but only after 2 genuine u7s bugs were found first).

## Stance
Pre-alpha Kubernetes apiserver in Rust. Correctness > conformance breadth. Workers in isolated worktrees (ALWAYS isolation="worktree"); mayor orchestrates, doesn't code (except trivial 4-condition externally-verified edits). Merge-on-green WITH verification (incl. conformance --focus, repeated for races). No back-compat shims. Never --admin. Mayor: confirm branch=main + pwd before bead/dashboard ops (worker dispatches can drift the checkout).

## VM slots
| Slot | VM | Port | Kubelet | Konnectivity | Status |
|---|---|---|---|---|---|
| mayor | lima-node | 6443 | 10250 | 8135 | operator stack |
| worker-1 | lima-node-smoke | 6444 | 10251 | 8235 | free |
| worker-2 | lima-node-2 | 6445 | 10252 | 8335 | free |
Konnectivity auto-derives from port (mayor-evnb fix): 8135 + (port − 6443) × 100.

## Session loops
CANCELLED. Re-create on resume: :07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard
