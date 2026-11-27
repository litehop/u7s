---
name: project-context
description: Core technical context for u7s — goals, constraints, design decisions, and open questions established in the founding session.
metadata:
  type: project
as_of: 2026-08-13
kind: project-state
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

## Worker preamble addendum (append to the common preamble in ai/prompts/mayor-dispatch-template.md)

```
Domain: Kubernetes-compatible control plane in Rust.
Target: 1 GB VPS, 1 vCPU. Control plane idle budget: <128 MiB RAM total (u7s's own processes).
Topology: single control plane node, multiple data plane nodes.
API compat: conform to upstream Kubernetes API surface; Argo CD is used as a correctness probe, not a milestone (see north-star.md).
API server: implemented from scratch in Rust (no upstream kube-apiserver).
Networking: CNI plugin model.
State store: SQLite WAL (rusqlite bundled) — see docs/decisions/sqlite-over-lmdb.md.
```

## Divergence decisions (operator-approved 2026-11-27)

- **UID preconditions:** the scheduler binds and preempts with UID
  preconditions (#2295, #2311). Upstream `DeletePod` sends none. A deliberate
  tightening; behaviour differs only in the delete-and-recreate race.
- **CRD `pattern` compile budget (#2289):** 8 MiB per CRD and 1 MiB per
  pattern, with a 4 KiB per-pattern floor (so at most 2048 patterns per CRD),
  compiled off the async runtime. Upstream has only a per-pattern Go limit
  (Go `regexp/syntax/parse.go`: `maxSize = 128 << 20 / instSize`, `instSize =
  5 * 8`, so about 128 MiB of instructions, plus `maxHeight = 1000`). Real CRDs measured at most 357 KB summed and 81 KB for a
  single pattern.
- **Security fixes** are not backported or advised while there are zero users.
