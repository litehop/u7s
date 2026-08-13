---
name: project-context
description: Core technical context for u7s — goals, constraints, design decisions, and open questions established in the founding session.
metadata:
  type: project
---

## What u7s is

A Kubernetes-compatible control plane implementation in Rust, targeting severely resource-constrained environments where k3s and k0s are too heavy.

**North star milestone:** Sufficient Kubernetes API compatibility to run an Argo CD GitOps setup on the cluster.

## Target environment

- **Hardware:** Minimal VPS — 1 GB RAM total, 1 shared vCPU
- **Constraint:** All control plane components must idle under **128 MB RAM combined**
- **Implication:** etcd is off the table. SQLite or LMDB only.

## Topology

- **Control plane:** Single node (no HA). One control plane, multiple data plane nodes.
- **Networking:** CNI plugin model — user brings their own (Flannel, Calico, etc.)

## Implementation language

**Rust.** Chosen for minimal footprint, no GC pauses, no runtime overhead.

## Kubernetes API surface (required for Argo CD milestone)

- Core workload APIs: Pod, Deployment, ReplicaSet, StatefulSet
- Config/secret APIs: ConfigMap, Secret
- RBAC: ServiceAccount, Role, ClusterRole, RoleBinding, ClusterRoleBinding
- CRD + custom resource support (Argo CD ships its own CRDs: Application, AppProject, etc.)

## Design decisions (all settled)

- **API server:** Implemented from scratch in Rust (axum). No upstream binary wrapping.
- **State store:** SQLite WAL (rusqlite bundled). See `docs/decisions/sqlite-over-lmdb.md`.
- **Container runtime:** CRI-O + crun. See `docs/decisions/crio-over-containerd.md`.
- **Scheduler:** Custom Rust scheduler (`crates/scheduler`). See `roadmap.md`'s Architecture summary table and `docs/decisions/custom-bin-spread-scheduler.md`.
- **Networking:** CNI plugin model (no built-in overlay). WebSocket-only exec/attach/portforward (no SPDY).
- **CRD validation:** boon crate (full openAPIV3Schema). See `docs/decisions/boon-for-crd-schema-validation.md`.

## Current phase

Phase 3 — Conformance. Stack complete as of 2026-05-24. Ready for first sonobuoy run.
See `roadmap.md` for full detail.

## Worker preamble addendum (append to the common preamble in docs/the-mayor-method/dispatch-prompt-template.md)

```
Domain: Kubernetes-compatible control plane in Rust.
Target: 1 GB VPS, 1 vCPU. Control plane idle budget: <128 MB RAM total.
Topology: single control plane node, multiple data plane nodes.
API compat target: Argo CD GitOps milestone (workloads, config/secret, RBAC, CRDs).
API server: implemented from scratch in Rust (no upstream kube-apiserver).
Networking: CNI plugin model.
State store: SQLite or LMDB (TBD).
```
