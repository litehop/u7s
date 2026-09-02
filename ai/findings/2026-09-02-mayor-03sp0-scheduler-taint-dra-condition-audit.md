# Scheduler placement audit: taints, node conditions, DRA

Bead: mayor-03sp0
Date: 2026-09-02
Scope: `crates/scheduler/src/lib.rs` scheduling-decision path only (RBAC grants like the `5o3cc` NodeRules cluster are necessary but not sufficient — this checks whether the scheduler actually acts on the resulting state).

## VERDICT

Taints/tolerations: **HONORED**. Node conditions: **HONORED indirectly** (via the same taint mechanism, live-verified for DiskPressure only). DRA: **NOT HONORED** — placement is entirely device-unaware (already tracked as an open epic, mayor-8qcaw).

## 1. Taints / tolerations — HONORED

The scheduler excludes a `NoSchedule`- or `NoExecute`-tainted node the pod does not tolerate, on the real decision path, not just as a referenced type:

- `node_taints_tolerated` (`crates/scheduler/src/lib.rs:2706-2715`) filters the node's taints to `NoSchedule`/`NoExecute` and requires every one to be tolerated:
  ```
  taints.iter().filter(|t| t.effect == "NoSchedule" || t.effect == "NoExecute")
        .all(|t| tolerations.iter().any(|tol| toleration_matches_taint(tol, t)))
  ```
- `toleration_matches_taint` (`lib.rs:2684-2698`) implements full key/operator(`Exists`/`Equal`)/value/effect matching, including the wildcard (`key: None`, `operator: Exists`) case.
- This predicate is wired into `node_qualifies_for_pod` (`lib.rs:1723-1757`, call at `lib.rs:1730`), which is the single gating function called from both scheduling paths:
  - `select_node_with_capacity` (direct scheduling), call at `lib.rs:1907`.
  - `find_preemption_plan` (preemption candidate search), call at `lib.rs:3061`.
  - `select_node_with_capacity` is reached from `pick_node` (`lib.rs:2810-2824`), the public entry point `main.rs` calls per pending pod.
- End-to-end unit tests exercise this at the `select_node_with_capacity` level, not just the pure predicate: `select_node_with_capacity_skips_untolerated_tainted_node` (`lib.rs:6406`) and `select_node_with_capacity_selects_tainted_node_with_matching_toleration` (`lib.rs:6424`).
- `spec.unschedulable=true` (cordon) is folded into the same predicate (`lib.rs:1736-1746`) via a synthetic `node.kubernetes.io/unschedulable` `NoSchedule` taint, mirroring upstream's always-on `NodeUnschedulable` filter.

Gaps that do **not** change the verdict:
- `Toleration` (`lib.rs:453-462`) has no `tolerationSeconds` field. This only governs the timing of NoExecute-taint-based *eviction* of an already-running pod — that's KCM+kubelet territory (confirmed stock upstream Go, not u7s code; see bd memory `u7s-rust-owns-only-apiserver-scheduler-store`), out of scope for this scheduling-time audit per the bead's own framing.
- `PreferNoSchedule` is intentionally excluded from the blocking filter (`lib.rs:2709`) because this scheduler does no scoring pass (documented at `lib.rs:991-994`) — upstream only ever treats `PreferNoSchedule` as a soft scoring signal, never a hard filter, so this is not a divergence.

## 2. Node conditions (NotReady / MemoryPressure / DiskPressure / PIDPressure) — HONORED, indirectly

The scheduler's own `NodeStatus` struct (`lib.rs:1003-1009`) carries only `allocatable`/`capacity` — **no `conditions` field at all**. A repo-wide grep of `crates/scheduler/src/lib.rs` for `MemoryPressure`, `DiskPressure`, `PIDPressure`, `NotReady`, `node_ready` returns **zero hits**. Taken alone, that would look like a gap.

It is not, because upstream Kubernetes itself does not filter placement via a direct node-condition predicate either — since `TaintNodesByCondition` went GA (~1.12), that exclusion is implemented *exclusively* via taints: kube-controller-manager's `NodeLifecycleController` converts `Ready=False`/`MemoryPressure`/`DiskPressure`/`PIDPressure` conditions into the corresponding `node.kubernetes.io/{not-ready,memory-pressure,disk-pressure,pid-pressure}` taints, and the scheduler's ordinary `TaintToleration` filter does the rest. In u7s, KCM is a real, unmodified, stock upstream Go binary (bd memory `u7s-rust-owns-only-apiserver-scheduler-store`: "kube-controller-manager (KCM) [is a] stock upstream Go binar[y]... via scripts/conformance/04-start-kcm.sh from dl.k8s.io"), so that condition-to-taint conversion is off-the-shelf, and the taint-enforcement half is the same code already verified honored in §1.

This full pipeline (condition → KCM taint → u7s scheduler exclusion) is **live-verified for DiskPressure** by the closed audit mayor-w44wg (2026-08-18, stack-only run on lima-node-3), quoted verbatim from its close reason:

> "Live-verified on HEAD (lima-node-3, stack-only) that u7s's own plumbing (Node status.conditions merge-by-type patch, real kcm's condition-to-taint reconciliation, u7s scheduler's taint enforcement) works correctly end-to-end: a held DiskPressure=True condition produces the disk-pressure NoSchedule taint and the scheduler correctly leaves a replacement pod Pending instead of re-binding it."

`NotReady`/`MemoryPressure`/`PIDPressure` were **not independently re-verified live in this audit** (source-only, no VM per the bead's Shape-3 scope). They go through the identical generic `NodeLifecycleController` condition→taint reconciliation code path inside the same stock KCM binary — there is no scheduler-side, condition-specific code that could diverge between the four conditions, so no additional u7s-specific gap is expected. Filed a low-severity confirmation follow-on rather than treating this as an unverified assumption (Rule 12).

## 3. DRA (dynamic resource allocation) — NOT HONORED

`crates/scheduler/src/lib.rs` has **zero references** to `ResourceClaim`, `ResourceSlice`, `DeviceClass`, `resourceclaim`, or any DRA-related type or field (verified by direct grep across the whole file — no `file:line` to cite because there is nothing there). `crates/apiserver` registers `ResourceClaim`/`ResourceClaimTemplate`/`DeviceClass`/`ResourceSlice` purely as generic CRUD resources with protobuf-decode adapters — no allocation logic anywhere in the request path. A pod with `spec.resourceClaims` referencing an unallocated claim schedules today with total disregard for device availability: no PreFilter/Reserve/PreBind-equivalent wiring exists, `status.allocation` is never computed, and `status.reservedFor` is never populated by anything.

This exact gap is **already tracked** as an open epic, `mayor-8qcaw` ("implement DRA structured-parameter allocation (dynamicresources scheduler plugin equivalent)"), whose own description independently confirms the same zero-hit grep result across both `crates/scheduler` and `crates/controller-manager`, and scopes the missing subsystem (device-slice indexing, CEL selector evaluation, allocation algorithm, scheduler bind-cycle wiring, deallocation controller). It is operator-deferred (2026-08-11) pending backlog drain, not abandoned. No duplicate bead filed here — see cross-reference below instead.

## Follow-on beads

- New: confirmation-only, P3 — live-repro NotReady/MemoryPressure/PIDPressure condition→taint→Pending-placement for the two condition types not covered by mayor-w44wg's DiskPressure repro (severity: low, this is expected-to-pass confirmation of a generic, already-proven-for-one-condition-type mechanism, not a known break).
- Cross-reference (no new bead): `mayor-8qcaw` — DRA scheduler placement gap, already fully scoped as its own epic.
