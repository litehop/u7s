---
name: project-context
description: Core technical context for u7s — goals, constraints, design decisions, and open questions established in the founding session.
metadata:
  type: project
---

## What u7s is

A Kubernetes-compatible control plane implementation in Rust, targeting severely resource-constrained environments where k3s and k0s are too heavy.

**North star:** see `north-star.md` — durable why-u7s-exists, decision framework, and guiding principles (operator sign-off required to change). Do not restate it here.

**Current phase / status:** see `roadmap.md` — component matrix, gates, and priorities (changes often; treat any number here as dated the moment a new measurement lands).

## Target environment

- **Hardware:** Minimal VPS — 1 GB RAM total, 1 shared vCPU
- **Constraint:** All control plane components must idle under **128 MiB RAM combined** (u7s's own processes — apiserver, scheduler, and whichever upstream components the matrix in `roadmap.md` still runs; excludes in-cluster workload footprint)
- **Implication:** etcd is off the table.

## Topology

- **Control plane:** Single node (no HA). One control plane, multiple data plane nodes.
- **Networking:** CNI plugin model — user brings their own (Flannel, Calico, etc.)

## Implementation language

**Rust.** Chosen for minimal footprint, no GC pauses, no runtime overhead.

## Design decisions

Settled component decisions (state store, container runtime, scheduler, CRD validation, networking, TLS) live in `roadmap.md`'s Architecture summary table, each linking to its own doc under `docs/decisions/`. Not duplicated here — see that table for the current list and rationale.

## Worker preamble addendum (append to the common preamble in docs/the-mayor-method/dispatch-prompt-template.md)

```
Domain: Kubernetes-compatible control plane in Rust.
Target: 1 GB VPS, 1 vCPU. Control plane idle budget: <128 MiB RAM total (u7s's own processes).
Topology: single control plane node, multiple data plane nodes.
API compat: conform to upstream Kubernetes API surface; Argo CD is used as a correctness probe, not a milestone (see north-star.md).
API server: implemented from scratch in Rust (no upstream kube-apiserver).
Networking: CNI plugin model.
State store: SQLite WAL (rusqlite bundled) — see docs/decisions/sqlite-over-lmdb.md.
```
