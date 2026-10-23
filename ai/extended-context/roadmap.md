---
name: roadmap
description: u7s roadmap — current state and priorities via a per-component decision matrix and horizontal gates. Not a phase list. Durable north star, decision framework, and guiding principles live in north-star.md; this file changes often and links back rather than restating them.
metadata:
  type: project
as_of: 2026-10-23
kind: roadmap
---

# u7s Roadmap

See [north-star.md](north-star.md) for why u7s exists, how component
decisions get made, and what "done" means in principle (changes rarely,
needs operator sign-off). This file is current state and priorities.
Figures: see `dashboard.md`.

Priority: correctness (Conformance first) > security > perf > features. Target: Kubernetes 1.37.1.

---

## Component matrix

State: **NATIVE** (u7s Rust) · **UPSTREAM** (real binary) · **HYBRID**
(upstream binary, u7s-run). Decision: **KEEP** (settled) · **MEASURED**
(data exists, open) · **UNMEASURED** (blocks decision) · **DEFERRED**
(parked, has a trigger).

| Component | State | Measured? | Decision | Notes / next action |
|---|---|---|---|---|
| **API server** | NATIVE | Yes | KEEP | Decode-correctness and security-audit fixes ongoing. |
| **Scheduler** | NATIVE | Yes | KEEP | Bin-spread, custom preemption. No DRA allocation. |
| **Store** | NATIVE (in apiserver) | Yes | KEEP | SQLite WAL + sharded watch fan-out + per-shard compaction horizon. |
| **KCM** | UPSTREAM | Yes | MEASURED | `--controllers='*,-cloud-*'`. Second-largest component. Rewrite go/no-go is the operator's open decision: `mayor-vc844`. |
| **Kubelet** | UPSTREAM | Yes | MEASURED | Largest component. Same decision. |
| **CRI-O + crun** | UPSTREAM | Yes | KEEP | No rewrite plan. |
| **kube-proxy** | UPSTREAM | Yes | KEEP | East-west only. Replacement is out of scope (beep repo, post-v1.0). |
| **ServiceLB** | UPSTREAM (beep) | Yes | KEEP | Not shipped. Planned: `litehop/beep` (`mayor-jlm8z`), pending v0.5.0 evaluation (`mayor-da224`). |
| **konnectivity-server** | HYBRID | Yes | KEEP-as-dev-tool | Rig-only, bridges apiserver↔kubelet across Lima's NAT; production dials `kubelet:10250` directly. |
| **CoreDNS** | UPSTREAM | Yes | KEEP | No rewrite plan. |
| **metrics-server** | not shipped | n/a | KEEP | Documented as user-applied (Gate 6 C4). |
| **Sentinel / sentinel-derive** | NATIVE (test infra) | n/a | KEEP | Proto-descriptor oracle; closed the silent-decode-drop bug class. |

**Rewrite decision (`mayor-vc844`):** open, operator's call. No clean flag
lever remains; rewrite-only residual (2026-10-21, loaded 1 GiB node):
~10-22 MB KCM, ~19-24 MB kubelet.

---

## Gates (horizontal cuts across the matrix)

### Gate 1 — Conformance floor ✓ CLEARED, with known blind spots
Full sonobuoy Conformance passes: single-node first green 2026-07-24;
two-node 446/0/0/7133 2026-08-10. Latest recorded (1.37.1, two-node,
iptables kube-proxy): 460/460 + 2/2 disruptive on 2026-10-14. These
counts predate the 2026-10-23 merges; a re-run is pending.

Green is necessary, not sufficient: single-node bias (Gate 5) and security
surface (Gate 8) are not conformance-visible. Any regression preempts perf.

### Gate 2 — Measurement baseline — DONE
Per-process RSS for every component under a 2-node conformance run
(`mayor-jnk90`), plus real k3s (`mayor-5x0kh`). Re-measure after every
non-trivial perf change.

### Gate 3 — Correctness infrastructure ✓ SUBSTANTIALLY DONE
Proto-descriptor oracle, filter-is-empty bug class fixed, observability EPIC.
InflightLayer bounded-wait backpressure is a deliberate minimal APF subset —
guardrail: bd memory `u7s-inflight-backpressure-is-deliberate-minimal-apf-subset`.

### Gate 4 — Perf (ACTIVE since 2026-07-24)
Method: audit → bead → measure before/after → land. Wins: `dashboard.md`.

**Aspiration, blocks nothing:** host-level control-plane processes (pods
excluded) under 128 MiB. Release-gate run 2026-10-15, peak PSS: kubelet
82-114 MiB, KCM 76-81, CRI-O 75-84, apiserver 27-31.

### Release gate — no PASS recorded (first verdict FAIL, 2026-10-15)
Minor releases must pass the 1 GiB / 1 vCPU no-swap burst test: WordPress +
MariaDB, then 20- and N-pod bursts. N = largest of 50, 40 passing 3/3 on a
quiet host (`burst-gate.sh --confirm`; patch releases not gated).
Harness: `scripts/release-gate/` (`mayor-6uez9`); noisy hosts yield an
INVALID verdict that `--confirm` re-runs.

Decided (operator 2026-10-23): the authoritative gate runs on a real 1-vCPU
VPS (GCP e2-micro, x86_64 tarball); Mac Lima is an optional pre-check. Not
built: `mayor-p3ktl` is open and `mayor-6uez9` is open-partial, depending on
it. Operator 2026-10-23: no rush to cut a release. Operator 2026-10-20:
cert rotation (`mayor-xdw6u.11`) blocks a release; lifting that is not yet
confirmed.

### Gate 5 — Correctness beyond Conformance (ongoing, opportunistic)
Representative workloads (WordPress+MariaDB, GPU-request, Argo CD) and
non-Conformance upstream e2e subsets (multi-node, CSI).

### Gate 6 — Packaging & distribution (local-install MVP shipped 2026-08-21)
End-game: k3s-style one-shell-script install. Install UX, component shipping,
systemd contract, and hosting are settled in ADRs (`docs/decisions/`).

MVP: `scripts/install.sh` — zero-argument single-node install from a
pre-built tarball to working `kubectl get nodes`/`logs`/`exec`. Decided
(audit `mayor-3kp5u`):
- C1: releases are prereleases until the release gate passes; the unpinned
  install URL 404s intentionally.
- C3: transparent pre-expiry rotation, tracked in `mayor-xdw6u`.
- C4: metrics-server not shipped, documented.
- C5: agent-friendly install (`mayor-yxe9t`). C6: networking flags
  (`mayor-rv1aw`).

Release authenticity (`mayor-pfykw`, closed, PR #1952): the tarball,
`.sha256` and `install.sh` are Ed25519-signed, and `install.sh` verifies.
Open: operator-side Release Environment settings (`mayor-1gfa6`), follow-ups
`mayor-b4guu`. C2 (`mayor-u251u`) still awaits operator confirmation.

### Gate 7 — Migration story (STARTED)
MVP epic `mayor-te4sn`: single-node k3s → u7s via `u7s migrate`, API-based
export/import (UID/resourceVersion loss accepted, PVs reused in place).
Export dry-run landed. Decisions on `mayor-ffgal`.

### Gate 8 — Security (ACTIVE)
Epic `mayor-qap3i`: audit run-1 (30 confirmed findings, 4 leads), filed
2026-10-22. All four P1s landed (JSON Patch depth, mirror-pod references,
encoded-route bypass, RoleBinding escalation) plus several P2s (`.5` closed). Open P2s as of 2026-10-23, in progress:
`.43` (CEL absent-key fail-open), `.23`, `.15`, `.25`, `.4`, `mayor-fg6oo`
(Service externalIPs), `mayor-d07ct` (KCM wildcard identity). Open, partial
via #1963: `.19` (CEL gate metering). `.35` is claimed, `.40` unstarted.

---

## Standing initiatives (bd EPICs)

| EPIC | Priority | Status | Trigger / un-defer condition (DEFERRED) or scope (OPEN) |
|---|---|---|---|
| `mayor-qap3i` | P1 | OPEN | Security audit run-1 fixes; P1s done, P2s in flight |
| `mayor-xdw6u` | P2 | OPEN | PKI rotation. Release-gating work left: `.11` e2e. `.8` two-tier and `.9` root succession do not gate a release |
| `mayor-te4sn` | P2 | OPEN | Migration MVP: import, cutover, docs (`.3`-`.5`) |
| `mayor-17nj7` | P2 | OPEN | Memory audit; 5 of 42 children open, all P4 |
| `mayor-8qcaw` | P2 | OPEN | DRA claim allocation. Starts only after security and perf drain (operator 2026-10-23); not Conformance-gating. Blocks `mayor-57p8x`: follow upstream feature gates (DeviceTaintRule eviction) |
| `mayor-u6ju` | P3 | DEFERRED | Gate 5 probes demonstrate a real Server-Side Apply requirement |

## Follow-ons

`mayor-9xsn3` (P3): DRA v1alpha3 registration, actionable since the 1.37
bump (2026-09-30). Decided: stop serving `certificates.k8s.io/v1beta1`
(`mayor-72l3k`, #1956). P4 CRD CEL follow-ons: `mayor-90qvg`, `mayor-1y0h6`.

---

## Architecture summary

| Component | Decision | Doc (under `docs/decisions/` unless noted) |
|---|---|---|
| API server | Rust from scratch (axum) | `rust-api-server-from-scratch.md` |
| State store | SQLite WAL (rusqlite), sharded watch fan-out | `sqlite-over-lmdb.md` |
| Container runtime | CRI-O + crun | `crio-over-containerd.md` |
| Scheduler | Custom (`crates/scheduler`) | `custom-bin-spread-scheduler.md` |
| CRD validation | boon crate | `boon-for-crd-schema-validation.md` |
| Streaming | WebSocket-only exec/attach/portforward | operator 2026-05-28 |
| TLS | aws-lc-rs (P-256 ECDSA); arm64/Lima issue, use CI | memory: `local-lima-arm64-environment` |
| Service LoadBalancer | beep (per-node eBPF + Geneve) | `litehop/beep` (`docs/decisions/`) |
