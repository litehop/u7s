---
name: roadmap
description: u7s roadmap — current state and priorities via a per-component decision matrix and horizontal gates. Not a phase list. Durable north star, decision framework, and guiding principles live in north-star.md; this file changes often and links back rather than restating them.
metadata:
  type: project
as_of: 2026-10-14
kind: roadmap
---

# u7s Roadmap

See [north-star.md](north-star.md) for why u7s exists, how component
decisions get made, and what "done" means in principle (changes rarely,
needs operator sign-off). This file is current state and priorities.
Figures are snapshots — check `ai/findings/` or `dashboard.md` for the
latest.

---

## Component matrix

State: **NATIVE** (u7s Rust) · **UPSTREAM** (real binary) · **HYBRID**
(upstream binary, u7s-run). Decision: **KEEP** (settled) · **MEASURED**
(data exists, open) · **UNMEASURED** (blocks decision) · **DEFERRED**
(parked, has a trigger).

| Component | State | Measured? | Decision | Notes / next action |
|---|---|---|---|---|
| **API server** | NATIVE | Yes | KEEP | Smallest of u7s's own components. Decode-correctness fixes ongoing. |
| **Scheduler** | NATIVE | Yes | KEEP | Bin-spread scheduler, custom preemption. |
| **Store** | NATIVE (in apiserver) | Yes | KEEP | SQLite WAL + sharded watch fan-out + per-shard compaction horizon. |
| **KCM** | UPSTREAM | Yes | MEASURED | `--controllers='*,-cloud-*'`. Second-largest component by a wide margin. |
| **Kubelet** | UPSTREAM | Yes | MEASURED | Single largest component (over 2x KCM). Config tuning landed; behavior-changing levers (`--max-pods`, change-detection strategy) stay deferred. Native rewrite off the table until kubelet+CRI-O+kube-proxy Gate-4 math resolves (`mayor-v9jk0`). |
| **CRI-O + crun** | UPSTREAM | Yes | KEEP | No rewrite plan. |
| **kube-proxy** | UPSTREAM | Yes | MEASURED | East-west `ClusterIP`/`NodePort` only; `LoadBalancer` is ServiceLB. Native rewrite of remaining scope open, data-first. |
| **ServiceLB (eBPF)** | NATIVE | Yes | KEEP | Per-node eBPF (`aya`) north-south LB, Geneve cross-node. Lives in `litehop/beep` since 2026-09-08; Phase 4 real-fleet go/no-go gates open there. |
| **konnectivity-server** | HYBRID | Yes | KEEP-as-dev-tool, skipped in production | Bridges apiserver↔kubelet across Lima's NAT; same-network production dials `kubelet:10250` directly. |
| **CoreDNS** | UPSTREAM | Yes | KEEP | No rewrite plan. |
| **metrics-server** | UPSTREAM | Yes | KEEP | No rewrite plan. |
| **Sentinel / sentinel-derive** | NATIVE (test infra) | n/a | KEEP | Proto-descriptor oracle; closed the silent-decode-drop bug class. |

**k3s comparison:** resolved — real k3s, same harness and accounting.
Methodology: `ai/perf/mayor-5x0kh-k3s-matched-comparison-2026-08-20.md`.

---

## Gates (horizontal cuts across the matrix)

Not a linear sequence; some run in parallel.

### Gate 1 — Conformance floor ✓ CLEARED, with known blind spots
Full sonobuoy Conformance passes: single-node first green 2026-07-24;
two-node 446/0/0/7133 2026-08-10. Current (1.37.1, two-node, iptables
kube-proxy): 460/460 + 2/2 disruptive on 2026-10-14. Counts come from
e2e.txt; script totals before #1771 also counted ginkgo suite nodes.

Green is necessary, not sufficient. (1) Single-node bias: the scheduler once
shipped zero taint/toleration handling (Gate 5 keeps catching this class).
(2) No security surface: the red-team audit's findings were not
conformance-visible; fix wave closed under `mayor-s851y`. Open: audit-log
subsystem (`mayor-0qjgc`, P3).

Any regression preempts perf work (correctness-first).

### Gate 2 — Measurement baseline — DONE
Per-process RSS for every matrix component under a full 2-node conformance
run (`mayor-jnk90`), plus real k3s measured the same way (`mayor-5x0kh`).
Re-measure u7s after every non-trivial component-level perf change.

### Gate 3 — Correctness infrastructure ✓ SUBSTANTIALLY DONE
- Proto-descriptor oracle; filter-is-empty bug class audited and fixed
  (`present_nonempty`/`present_any` adoption opportunistic); observability
  EPIC (access log, `/metrics`, ring gauges, run-time sampling).
- InflightLayer bounded-wait backpressure (`crates/apiserver/src/inflight.rs`)
  replaces instant-429. Deliberate minimal APF subset — guardrail: bd memory
  `u7s-inflight-backpressure-is-deliberate-minimal-apf-subset`.

### Gate 4 — Perf (ACTIVE since 2026-07-24)
Method: audit → file bead → measure before/after → land; correctness gaps
preempt. Wins landed are in `dashboard.md` and `ai/findings/`.

Follow-ons: protobuf watch-stream framing, wider decode-parity coverage.

**Target:** control-plane processes (apiserver, scheduler, every native
component) under **128 MiB combined**, idle (`project-context.md`);
excludes in-cluster workload footprint.

### Gate 5 — Correctness beyond Conformance (ongoing, opportunistic)
Representative workloads (WordPress+MariaDB, GPU-request workload, Argo CD
as a probe not a milestone) and non-Conformance upstream e2e subsets
(multi-node, CSI). Candidate fix if Argo CD fails on an RBAC gap: `mayor-j7to`
(seed minimal RBAC), deferred until observed.

### Gate 6 — Packaging & distribution (local-install MVP shipped 2026-08-21)
End-game: k3s-style one-shell-script install. Install UX, component shipping,
systemd contract, and hosting are settled in ADRs (`docs/decisions/`).
Needs-data: tarball size; multi-node CA-trust/rotation (join-token settled).

MVP: `scripts/install.sh` — zero-argument single-node install from a
pre-built tarball path to working `kubectl get nodes`/`logs`/`exec`, CoreDNS
and kube-proxy running. Still open (no beads yet; blocked on
correctness/perf stabilizing): distribution origin, multi-node join,
CA-trust/rotation, metrics-server, agent-facing install.

### Gate 7 — Migration story (future, NOT STARTED)
Migrating an existing k3s/k0s user onto u7s: (1) control-plane migration,
likely API-level export/import (trades resourceVersion/UID history for no
k3s-internals coupling; PV data separate); (2) data-plane node conversion —
real kubelet makes this close to a normal re-join.

Not a bead yet; fires after Gate 6 settles install/topology shape.

---

## Standing initiatives (bd EPICs)

| EPIC | Priority | Status | Trigger / un-defer condition (DEFERRED) or scope (OPEN) |
|---|---|---|---|
| `mayor-u6ju` | P3 | DEFERRED | Gate 5 probes demonstrate a real Server-Side Apply requirement |
| `mayor-8qcaw` | P2 | OPEN | DRA claim allocation: CEL selector evaluation, allocation algorithm, deallocation controller (scouts complete, verdict B) |

## Deferred / opportunistic follow-ons

| Bead | Priority | Note |
|---|---|---|
| `mayor-9xsn3` | P3 | DRA v1alpha3 registration. Deferred to 1.37 upstream bump |

Open minor P4 follow-ons to shipped CRD CEL enforcement: `mayor-90qvg`,
`mayor-1y0h6`.

---

## Architecture summary

| Component | Decision | Doc (under `docs/decisions/` unless noted) |
|---|---|---|
| API server | Rust from scratch (axum) | `rust-api-server-from-scratch.md` |
| State store | SQLite WAL (rusqlite), sharded watch fan-out | `sqlite-over-lmdb.md` |
| Container runtime | CRI-O + crun | `crio-over-containerd.md` |
| Scheduler | Custom (`crates/scheduler`) | `custom-bin-spread-scheduler.md` |
| CRD validation | boon crate | `boon-for-crd-schema-validation.md` |
| Networking | WebSocket-only exec/attach/portforward (no SPDY) | operator confirmed 2026-05-28 |
| TLS | aws-lc-rs (P-256 ECDSA) — arm64/Lima compat issue, use CI | memory: `local-lima-arm64-environment` |
| Service LoadBalancer | Per-node eBPF (aya) + Geneve | `litehop/beep` (`docs/decisions/`) |
