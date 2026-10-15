---
name: roadmap
description: u7s roadmap — current state and priorities via a per-component decision matrix and horizontal gates. Not a phase list. Durable north star, decision framework, and guiding principles live in north-star.md; this file changes often and links back rather than restating them.
metadata:
  type: project
as_of: 2026-10-15
kind: roadmap
---

# u7s Roadmap

See [north-star.md](north-star.md) for why u7s exists, how component
decisions get made, and what "done" means in principle (changes rarely,
needs operator sign-off). This file is current state and priorities.
Figures: see `dashboard.md`.

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
| **KCM** | UPSTREAM | Yes | MEASURED | `--controllers='*,-cloud-*'`. Second-largest component. Rewrite go/no-go: `mayor-vc844` Phase 2, pending `mayor-w898x`. |
| **Kubelet** | UPSTREAM | Yes | MEASURED | Largest component (over 2x KCM). Config tuning landed; behavior-changing levers (`--max-pods`, change-detection strategy) deferred. Rewrite: same pending decision as KCM. |
| **CRI-O + crun** | UPSTREAM | Yes | KEEP | No rewrite plan. |
| **kube-proxy** | UPSTREAM | Yes | KEEP | East-west `ClusterIP`/`NodePort` only. Replacement is out of u7s scope (beep repo, post-v1.0). |
| **ServiceLB** | UPSTREAM (beep) | Yes | KEEP | Not shipped (no LB provider in `install.sh`). Planned: `litehop/beep` as klipper-lb role (`mayor-jlm8z`), pending v0.5.0 evaluation (`mayor-da224`). |
| **konnectivity-server** | HYBRID | Yes | KEEP-as-dev-tool | Rig-only, bridges apiserver↔kubelet across Lima's NAT. Shipped webhook/aggregation reach Services by `ClusterIP` (PR #1799); production dials `kubelet:10250` directly. |
| **CoreDNS** | UPSTREAM | Yes | KEEP | No rewrite plan. |
| **metrics-server** | not shipped | n/a | KEEP | Not shipped; documented as user-applied (Gate 6 C4). |
| **Sentinel / sentinel-derive** | NATIVE (test infra) | n/a | KEEP | Proto-descriptor oracle; closed the silent-decode-drop bug class. |

The kubeconfig crate is gone; politeia replaced it.

**k3s comparison:** resolved — real k3s, same harness and accounting.
Methodology: `ai/perf/mayor-5x0kh-k3s-matched-comparison-2026-08-20.md`.

---

## Gates (horizontal cuts across the matrix)

Not linear; some run in parallel.

### Gate 1 — Conformance floor ✓ CLEARED, with known blind spots
Full sonobuoy Conformance passes: single-node first green 2026-07-24;
two-node 446/0/0/7133 2026-08-10. Current (1.37.1, two-node, iptables
kube-proxy): 460/460 + 2/2 disruptive on 2026-10-14. Counts come from
e2e.txt.

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
preempt. Wins landed are in `dashboard.md`.

Follow-ons: protobuf watch-stream framing, wider decode-parity coverage.

**Aspiration, blocks nothing:** host-level control-plane processes (apiserver,
scheduler, KCM, kubelet, CRI-O, kube-proxy; pods excluded) under 128 MiB.
Release-gate run 2026-10-15, peak PSS: kubelet 82-114 MiB, KCM 76-81, CRI-O
75-84, apiserver 27-31; idle MemAvailable ~430 MiB on a 947 MiB VM.

### Release gate — FAILING (first verdict 2026-10-15)
Every release must pass the 1 GiB / 1 vCPU burst test (no swap):
WordPress+MariaDB, then 20- and 80-pod bursts. No separate alpha milestone;
the first release is the first to clear it. Runs on a local Lima VM; ask the
operator ahead for a quiet host window. Harness: `scripts/release-gate/`
(PR #1807, hardening `mayor-6uez9`).

First verdict FAIL: page-cache refault memory thrash in the 80-pod burst
causes lease and CRI timeouts, node NotReady, then immediate eviction because
`DefaultTolerationSeconds` admission is missing (`mayor-7afq6`, P1). Lever:
control-plane memory protection (`mayor-i4bvb`).

### Gate 5 — Correctness beyond Conformance (ongoing, opportunistic)
Representative workloads (WordPress+MariaDB, GPU-request workload, Argo CD
as a probe not a milestone) and non-Conformance upstream e2e subsets
(multi-node, CSI). Candidate fix if Argo CD fails on an RBAC gap: `mayor-j7to`
(seed minimal RBAC), deferred until observed.

### Gate 6 — Packaging & distribution (local-install MVP shipped 2026-08-21)
End-game: k3s-style one-shell-script install. Install UX, component shipping,
systemd contract, and hosting are settled in ADRs (`docs/decisions/`).

MVP: `scripts/install.sh` — zero-argument single-node install from a
pre-built tarball to working `kubectl get nodes`/`logs`/`exec`, CoreDNS and
kube-proxy running. Decided (audit `mayor-3kp5u`):
- C1: releases are prereleases until the release gate passes; the unpinned
  install URL 404s intentionally.
- C3 goal: transparent pre-expiry rotation; compromise means manual cutover;
  kubectl Warning headers plus Node Events.
- C4: metrics-server not shipped, documented.
- C5: agent-friendly install (`mayor-yxe9t`).
- C6: networking flags (`mayor-rv1aw`).

Pending operator confirmation:
- C2 mechanism (`mayor-u251u`; direction set: per-node minting, no apiserver
  restart, no private key in cmdline). Proposed: serverTLSBootstrap CSR plus
  approver; Secret-backed bootstrap tokens with TTL.
- C3 PKI design P1-P7 (`mayor-xdw6u`). Control-plane kubelet's admin
  credentials: `mayor-zboqh`.

### Gate 7 — Migration story (STARTED)
MVP epic `mayor-te4sn`: single-node k3s → u7s via `u7s migrate`, API-based
export/import (UID/resourceVersion loss accepted and reported, PVs reused in
place). Decisions A2-A10 are on `mayor-ffgal`. The off-ramp (u7s → k3s) is
not in the MVP. Data-plane node conversion is close to a normal re-join.

---

## Standing initiatives (bd EPICs)

| EPIC | Priority | Status | Trigger / un-defer condition (DEFERRED) or scope (OPEN) |
|---|---|---|---|
| `mayor-u6ju` | P3 | DEFERRED | Gate 5 probes demonstrate a real Server-Side Apply requirement |
| `mayor-8qcaw` | P2 | OPEN | DRA claim allocation: CEL selector evaluation, allocation algorithm, deallocation controller (scouts complete, verdict B) |

## Follow-ons

`mayor-9xsn3` (P3): DRA v1alpha3 registration; its trigger, the 1.37 bump
(landed 2026-09-30), has fired, so it is now actionable. Minor P4 follow-ons
to shipped CRD CEL enforcement: `mayor-90qvg`, `mayor-1y0h6`.

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
| Service LoadBalancer | beep (per-node eBPF + Geneve) | `litehop/beep` (`docs/decisions/`) |
