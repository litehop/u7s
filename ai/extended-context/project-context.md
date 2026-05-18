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

## Key open decisions (need operator input before spec is written)

- **State store:** SQLite vs LMDB. Operator noted "need to think more." Both are embedded; SQLite is simpler (SQL queries, tooling), LMDB is faster and has zero-copy reads but a lower-level API.
- **Container runtime:** Not decided. Options: containerd, CRI-O, direct runc/crun.
- **Scheduler design:** Operator wants to understand the domain better before committing to custom vs upstream kube-scheduler.

## Design decisions already made

- **API server:** Implement the Kubernetes REST API from scratch in Rust. No wrapping of upstream kube-apiserver binary.
- **Networking:** CNI plugin model (no built-in overlay).

## Session goals

- Write specifications and implementation prompts (`/ai/prompts/`)
- Architecture overview first, then drill into individual components

## Worker preamble addendum (append to project-stance.md preamble)

```
Domain: Kubernetes-compatible control plane in Rust.
Target: 1 GB VPS, 1 vCPU. Control plane idle budget: <128 MB RAM total.
Topology: single control plane node, multiple data plane nodes.
API compat target: Argo CD GitOps milestone (workloads, config/secret, RBAC, CRDs).
API server: implemented from scratch in Rust (no upstream kube-apiserver).
Networking: CNI plugin model.
State store: SQLite or LMDB (TBD).
```
