---
name: roadmap
description: u7s phase roadmap — goals, milestones, exit criteria, and deferred items per phase. The authoritative place to track what's done, what's in flight, and what's explicitly waiting on a trigger.
metadata:
  type: project
---

# u7s Roadmap

**North star:** Run a real Argo CD GitOps setup on u7s. That requires a kubectl-compatible
API surface, working workload controllers, CRD support, and RBAC — all idle under 128 MB RAM.

**Project stance:** Pre-alpha/greenfield. No backward compat. Break freely.

---

## Phase 1 — Core API server ✓ COMPLETE

**Goal:** A Kubernetes-compatible REST API server in Rust that kubectl can talk to.

### Completed
- Rust API server from scratch (axum, rustls/rcgen, serde_json::Value-based objects)
- SQLite WAL state store (rusqlite bundled; watch fan-out via in-memory broadcast channel)
- CRUD for: Pod, Deployment, ReplicaSet, StatefulSet, ConfigMap, Secret, ServiceAccount,
  Role, ClusterRole, RoleBinding, ClusterRoleBinding, Namespace, Node, CRD + custom resources
- Token auth (bearer token CSV), x509 client cert auth, SA JWT minting + verification
- RBAC enforcement (is_allowed, escalation prevention, system:masters bypass)
- CRI-O + crun container runtime integration
- Kubelet registration: CSR signing, Node object management, watch/list
- Proto negotiation (protobuf response encoding for kubelet 1.36+)
- Discovery endpoints (/api, /apis, /api/v1, /apis/GROUP/VERSION)
- Strategic Merge Patch (SMP) including nested list merge-key handling
- Server-Side Apply stub (remaps to merge patch; managedFields echo)

### Key decisions recorded
- `docs/decisions/rust-api-server-from-scratch.md`
- `docs/decisions/sqlite-over-lmdb.md`
- `docs/decisions/crio-over-containerd.md`

---

## Phase 2 — Controller manager + kubelet hardening ✓ COMPLETE

**Goal:** Run kube-controller-manager against u7s; kubelet joins and stays healthy.

### Completed
- resourceVersion semantics: LIST rv=0 → current snapshot (no read cache)
- ADDED vs MODIFIED event encoding via is_create:bool in InternalEvent
- Full two-phase soft-delete for all resources (deletionTimestamp + finalizers)
- KCM running: controllers = csrapproving, csrsigning, garbagecollector, deployment, replicaset
- ClusterRole aggregation controller (system:masters + aggregated roles for Argo CD)
- system:authenticated group added to all auth paths
- boon CRD schema validator (full openAPIV3Schema: enum, pattern, min/max, format)
- Typed fields policy: type what apiserver reasons about; serde_json::Value for pass-through
- SMP nested list merge-key fix + regression tests
- Service ports SMP merge key (port, not name)
- Typed structs: PodSpec, PodStatus, CSRSpec/Status, NamespaceStatus

### Explicitly deferred out of Phase 2 (now Phase 3/4 work)
- DB-04: scheduler — external kube-scheduler binary acceptable for compat testing.
  **Trigger: needed for sonobuoy conformance run (Pods stay Pending without it).**
- DB-05: controller-manager SA token provisioning — KCM still uses system:masters admin
  cert. JWT minting works. Real SA-based kubeconfig for KCM not yet wired.
  **Trigger: conformance or Argo CD install exposes auth gap.**

### Key decisions recorded
- `docs/decisions/boon-for-crd-schema-validation.md`

---

## Phase 3 — Conformance (CURRENT)

**Goal:** Pass sonobuoy non-disruptive-conformance subset. Close the gap to a
point where Argo CD can be installed and operated.

**Method:** Audit-first → file beads → cluster + dispatch fixes → sonobuoy run → triage.

### Completed this phase
- Conformance orchestration scripts: `scripts/conformance/01-05-*.sh` + `run-all.sh`
- OpenAPI v2/v3 stub endpoints (prerequisite for sonobuoy API discovery)
- /openapi/v2 static blob embedding (mayor-52wo) — **DEFERRED** (see below)
- Argo CD gap audit (8 gaps identified, 6 resolved in PRs #200–#203)
- RBAC: nonResourceURLs enforcement — **NOT YET IMPLEMENTED** (see below)
- SA projected volume auto-injection — **DEFERRED** (see below)
- Phase 3 audit: 5 HIGH + 9 MED conformance gaps; most resolved

### Conformance stack: COMPLETE (as of 2026-05-24)
`scripts/conformance/run-all.sh` runs: build → apiserver → lima VM + kubelet → kcm →
kube-scheduler (on Mac host) → sonobuoy. `reset.sh` + `--reset` flag added for clean
restarts. **Stack is feature-complete and ready to run.**

### Phase 3 deferred items (explicit triggers — do not let these rot)

| Bead | Title | Trigger to activate |
|------|-------|---------------------|
| mayor-52wo (P2, DEFERRED) | Embed full OpenAPI v2 spec as static blob | sonobuoy API conformance check fails on stub |
| mayor-j7to (P2, DEFERRED) | Seed minimal Argo CD RBAC at startup | Argo CD install attempt fails on RBAC gap |
| DB-05 (PARTIAL) | KCM SA token provisioning (real kubeconfig, not system:masters) | conformance or Argo CD install hits auth gap |
| — (NOT STARTED) | RBAC nonResourceURLs enforcement | Argo CD SA needs `/version` non-resource grant |
| — (DEFERRED) | SA projected volume auto-injection into every pod | pod fails to mount implicit token |

### Phase 3 exit criteria
1. ✓ `scripts/conformance/run-all.sh` completes without a scheduler-less Pending failure
2. Sonobuoy non-disruptive-conformance run produces a results report
3. All HIGH-severity sonobuoy failures have filed beads (or are fixed)

---

## Phase 4 — Argo CD milestone (PLANNED)

**Goal:** `argocd install` succeeds against u7s and can manage a simple Application.

### Prerequisites (must land before or during Phase 4)
- Scheduler running in conformance stack (Phase 3 blocker above)
- SA token provisioning for KCM (DB-05)
- RBAC nonResourceURLs support
- Pod /exec stub (currently 501) — Argo CD's `argocd exec` needs this
- SA projected volume injection OR Argo CD pods explicitly mounting token Secret

### Known gaps to address
- **Pod exec/attach:** WebSocket proxy apiserver→kubelet. Decision logged in memory
  (`networking-websocket-decision-2026-05-22`): WebSocket-only, no SPDY.
  Proxy-through decision is still open (operator to decide full proxy vs stub-first).
- **Namespace controller:** finalizer-based deletion for proper namespace GC
  (Argo CD garbage collection relies on it).
- **Argo CD RBAC seeding** (mayor-j7to): seed argocd-application-controller SA +
  ClusterRole + ClusterRoleBinding at startup if install keeps failing.

### Phase 4 exit criteria
1. `argocd install` applies all manifests without error
2. An Application pointing at a simple Helm chart reconciles to Synced/Healthy
3. RSS of full control plane (apiserver + kcm + scheduler) idles under 128 MB

---

## Perpetually deferred (revisit only on explicit trigger)

| Bead | Title | Condition to undefer |
|------|-------|----------------------|
| mayor-rvkq (P3, DEFERRED) | CRD CEL validation (x-kubernetes-validations) | Future workload uses CEL; Argo CD audit found zero hits |
| mayor-6w76 (P3, OPEN) | Pod proto decoder native impl | Real proto decode failure observed in the wild |
| mayor-j7to (P2, DEFERRED) | Argo CD RBAC seeding | Argo CD install fails specifically on this gap |
| — | crates/scheduler full custom impl | External kube-scheduler binary covers conformance; custom impl is Phase 4+ |

---

## Architecture summary (for reference)

| Component | Decision | Doc |
|-----------|----------|-----|
| API server | From scratch in Rust (axum) | `docs/decisions/rust-api-server-from-scratch.md` |
| State store | SQLite WAL (rusqlite bundled) | `docs/decisions/sqlite-over-lmdb.md` |
| Container runtime | CRI-O + crun | `docs/decisions/crio-over-containerd.md` |
| Scheduler | External kube-scheduler (Phase 3/4); custom bin-spread planned (Phase 4+) | `docs/decisions/custom-bin-spread-scheduler.md` |
| CRD validation | boon crate (full openAPIV3Schema) | `docs/decisions/boon-for-crd-schema-validation.md` |
| Networking | WebSocket-only exec/attach/portforward (no SPDY) | memory: networking-websocket-decision-2026-05-22 |
| TLS | aws-lc-rs (P-256 ECDSA) — known arm64/Lima compat issue; workaround: use CI | memory: local-lima-arm64-environment |
