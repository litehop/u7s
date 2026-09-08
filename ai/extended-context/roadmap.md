---
name: roadmap
description: u7s roadmap — current state and priorities via a per-component decision matrix and horizontal gates. Not a phase list. Durable north star, decision framework, and guiding principles live in north-star.md; this file changes often and links back rather than restating them.
metadata:
  type: project
as_of: 2026-09-08
kind: roadmap
---

# u7s Roadmap

See [north-star.md](north-star.md) for why u7s exists, how component
decisions get made, and what "done" means in principle — that document
changes rarely and needs explicit operator sign-off. This file is the
opposite: current state, measurements, and priorities, expected to change
often. Specific figures here are snapshots — check `ai/findings/` or
`dashboard.md` for the latest before relying on a number quoted below.

---

## Component matrix

State: **NATIVE** (u7s Rust) · **UPSTREAM** (real binary) · **HYBRID**
(upstream binary, u7s-run). Decision: **KEEP** (settled) · **MEASURED**
(data exists, open) · **UNMEASURED** (blocks decision) · **DEFERRED**
(parked, has a trigger).

| Component | State | Measured? | Decision | Notes / next action |
|---|---|---|---|---|
| **API server** | NATIVE | Yes | KEEP | Smallest of u7s's own components. Ring-resize + fat LTO landed; protobuf LIST encoder; decode-correctness fixes ongoing. |
| **Scheduler** | NATIVE | Yes | KEEP | Bin-spread scheduler, custom preemption, DB-04 resolved. Confirmed small relative to the stack. |
| **Store** | NATIVE (part of apiserver) | Yes | KEEP | SQLite WAL + sharded watch fan-out + per-shard compaction horizon. |
| **KCM (kube-controller-manager)** | UPSTREAM | Yes | MEASURED | Runs with `--controllers='*,-cloud-*'`. Confirmed **second-largest** component by a wide margin. |
| **Kubelet** | UPSTREAM | Yes | MEASURED | Runs on every node. Confirmed the **single largest** component — more than double KCM. Round-2 config-tuning (feature-gate audit + cAdvisor trim) landed (`mayor-9dk3n`, PR #1456); remaining behavior-changing levers (`--max-pods`, change-detection strategy) stay deferred. Native rewrite stays off the table until kubelet+CRI-O+kube-proxy Gate-4 math resolves (`mayor-v9jk0`). |
| **CRI-O + crun** | UPSTREAM | Yes | KEEP | Container runtime. No plan to rewrite; measured for completeness only. |
| **kube-proxy** | UPSTREAM | Yes | MEASURED | East-west `ClusterIP`/`NodePort` only — north-south `LoadBalancer` split off to eBPF ServiceLB (next row). Native rewrite of remaining scope still open, data-first. |
| **ServiceLB (eBPF dataplane)** | NATIVE | Yes | KEEP | Per-node eBPF (tc-bpf, `aya`) LB for north-south `type=LoadBalancer`: consistent-hash to a backend, Geneve-encapsulate cross-node, symmetric return — chosen over klipper-lb-alike and other options (ADRs below). Migrated to its own repo (`litehop/beep`) 2026-09-08 with full history; retained here as an architecture-of-record entry only. Still pre-production, Phase 4 real-fleet go/no-go gates open — tracked in beep. |
| **konnectivity-server** | HYBRID | Yes | KEEP-as-dev-tool, skipped in production | Bridges apiserver↔kubelet across Lima's NAT boundary — a dev-topology artifact. Same-network production dials `kubelet:10250` directly, no tunnel. |
| **CoreDNS** | UPSTREAM | Yes | KEEP | In-cluster DNS. No plan to rewrite. |
| **metrics-server** | UPSTREAM | Yes | KEEP | Standard component; no rewrite plan. |
| **Sentinel / sentinel-derive** | NATIVE (test infra) | n/a | KEEP | Proto-descriptor oracle framework, closed the silent-decode-drop bug class. |

**k3s/k0s comparison:** resolved — real k3s (v1.36.3+k3s1, native
containerd), same sonobuoy harness, same component-boundary accounting.
Methodology: `ai/perf/mayor-5x0kh-k3s-matched-comparison-2026-08-20.md`.

---

## Gates (horizontal cuts across the matrix)

Not a linear sequence — some gates run in parallel. But each has a fireable
un-defer trigger.

### Gate 1 — Conformance floor ✓ CLEARED, with known blind spots
Full 446-spec sonobuoy Conformance passes: single-node 446/446 first green
2026-07-24; two-node 446/0/0/7133 in 25m11s 2026-08-10.

**Caveat:** green is necessary, not sufficient — two demonstrated blind
spots. (1) Single-node bias: the scheduler once shipped zero
taint/toleration handling, since fixed (Gate 5 keeps catching this class).
(2) No security surface: a red-team audit's 4 Phase-1 deep-dives found 1
CRITICAL + 7 HIGH + 4 MED + 3 LOW findings, none conformance-visible — fix
wave complete, all 15 closed under `mayor-s851y`; one lower-priority item
remains open outside that count, an audit-log subsystem (`mayor-0qjgc`,
P3).

Any regression preempts perf work (north-star.md's correctness-first
principle).

### Gate 2 — Measurement baseline — DONE, k3s comparison resolved
`mayor-jnk90` (closed 2026-08-12): full 2-node conformance run with the
`mayor-zpvp2` sampler, per-process RSS for every matrix component.
`mayor-5x0kh` (closed 2026-08-20): real k3s measured the same way — see the
matrix's k3s-comparison note above. Re-measure u7s's own side after every
non-trivial component-level perf change.

### Gate 3 — Correctness infrastructure ✓ SUBSTANTIALLY DONE
- Proto-descriptor oracle (sentinel-completeness lists from
  `FileDescriptorSet`, not hand lists) closed a bug class worth ~10
  silent-decode-drop bugs pre-landing; filter-is-empty three-state
  pointer-string bug class audited and fixed (refactor banked,
  `present_nonempty`/`present_any`, opportunistic); observability EPIC
  (structured access log + `/metrics` + ring gauges) extended into
  automated run-time sampling.
- InflightLayer bounded-wait backpressure (`crates/apiserver/src/inflight.rs`):
  fixed (`mayor-4q3m2`, PR #1510) — tokio bounded-wait timeout replaces the
  instant-429 that crashed csi-hostpath under bulk-mutating bursts.
  Deliberate minimal APF subset — guardrail: bd memory
  `u7s-inflight-backpressure-is-deliberate-minimal-apf-subset`.

### Gate 4 — Perf (ACTIVE since 2026-07-24)
Method: audit → file bead → measure before/after → land; correctness gaps
preempt in-progress perf work at conformance-regression priority.

Wins landed: watch-ring sharding/sizing, discovery-path caching, protobuf
LIST encoding, per-version CR conversion caching, typed-fields migration,
`prepare_cached`/batched-fetch/borrow-deserialize across store + apiserver
handlers, build/profiling fixes. Full list: `dashboard.md`, `ai/findings/`.

Follow-ons: protobuf watch-stream framing, wider decode-parity coverage,
opportunistic `present_nonempty`/`present_any` adoption.

**Target:** control-plane processes (apiserver, scheduler, every native
component above) under **128 MiB combined**, idle (`project-context.md`);
excludes in-cluster workload footprint, far below the illustrative k3s
figure.

### Gate 5 — Correctness baseline beyond Conformance (ongoing, opportunistic)
Conformance is necessary but not sufficient (Gate 1's caveat). Two
complementary approaches keep finding what it misses: representative
workloads (WordPress+MariaDB stateful app, GPU-request workload, Argo CD
as a correctness probe not a milestone — north-star.md), and
non-Conformance-tagged upstream e2e subsets covering what single-node bias
misses (multi-node, CSI, etc.).

Not urgent, built incrementally. Candidate fix if the Argo CD probe fails
on an RBAC gap: `mayor-j7to` (seeds minimal RBAC), deferred until that
failure is actually observed.

### Gate 6 — Packaging & distribution (local-install MVP shipped 2026-08-21)
End-game: k3s-style one-shell-script install (north-star.md's packaging
philosophy — default everything, minimal configurable surface). Settled
via ADR (`docs/decisions/`): install UX, upstream-component shipping
shape, systemd install contract, distribution hosting. Needs-data: tarball
size (one tarball, kube-proxy excluded as a DaemonSet); multi-node
CA-trust/rotation (join-token settled, shared-token k3s-style; recommended
k0s-style CA-in-token + kubeadm's runbook).

**MVP shipped 2026-08-21** (`mayor-wl8kl`/PR #1332, `mayor-1uunh`/PR #1340):
`scripts/install.sh` — zero-argument single-node install, clean Ubuntu box
to `kubectl get nodes`/`logs`/`exec` working, CoreDNS + kube-proxy running
(kubelet cert cluster-CA-signed, `mayor-h0cyv`/PR #1343). Still open:
distribution origin, multi-node join, CA-trust/rotation, metrics-server,
agent-facing install (none yet beads — blocked on correctness/perf
stabilizing and Gate 2 settling what's packaged). MVP takes a pre-built
tarball as a path argument, decoupling install logic from tarball
build/hosting.

### Gate 7 — Migration story (future consideration, NOT STARTED)
Gate 6 solves a fresh install, not migrating an existing k3s/k0s user onto
u7s — harder, later, two parts: (1) control-plane migration without data
loss, likely API-level export/import rather than a byte-level store
migration (trades resourceVersion/UID history for avoiding k3s-internals
coupling; PersistentVolume *data* migration is separate); (2) data-plane
node conversion — reusing real kubelet unmodified makes this closer to a
normal re-join (repoint kubeconfig + CA trust, restart) than a rewrite.

Not a bead yet — blocked on Gate 6 settling install/topology shape; fires
after, informed by whichever real distro (k3s most likely) the first
migration-seeking user is running.

---

## Standing initiatives (bd EPICs)

Long-running arcs tracked in bd, not tied to a single gate.

| EPIC | Priority | Status | Trigger / un-defer condition |
|---|---|---|---|
| `mayor-u6ju` | P3 | DEFERRED | Gate 5 probes demonstrate a real Server-Side Apply requirement — not pursued speculatively given SSA's scope |
| `mayor-8qcaw` | P4 | DEFERRED | Backlog otherwise clears OR DRA conformance failure traces to claim allocation |

Closed: `mayor-axi12` (superseded), `mayor-0bd14` (all children closed).

---

## Deferred / opportunistic follow-ons

| Bead | Priority | Note |
|---|---|---|
| `mayor-9xsn3` | P3 | DRA v1alpha3 registration. Deferred to 1.37 upstream bump (schema growing there) |

Closed: `mayor-jtlnx` (self-heals, no fix needed); `mayor-rvkq`/`mayor-fbxcy`
(CRD CEL enforcement shipped, `mayor-olvm0`/PR #1372, no longer deferred —
minor P4 follow-ons `mayor-90qvg`/`mayor-1y0h6` still open).

---

## Architecture summary (for reference)

| Component | Decision | Doc (under `docs/decisions/` unless noted) |
|---|---|---|
| API server | Rust from scratch (axum) | `rust-api-server-from-scratch.md` |
| State store | SQLite WAL (rusqlite), sharded watch fan-out by resource-type | `sqlite-over-lmdb.md` |
| Container runtime | CRI-O + crun | `crio-over-containerd.md` |
| Scheduler | Custom (`crates/scheduler`) — NodeTally, preemption, periodic re-sync | `custom-bin-spread-scheduler.md` |
| CRD validation | boon crate (full openAPIV3Schema) | `boon-for-crd-schema-validation.md` |
| Networking | WebSocket-only exec/attach/portforward (no SPDY) | operator confirmed 2026-05-28; k8s 1.34+ dropped SPDY |
| TLS | aws-lc-rs (P-256 ECDSA) — arm64/Lima compat issue, use CI | memory: `local-lima-arm64-environment` |
| Service LoadBalancer | Per-node eBPF (aya) + Geneve | `litehop/beep` (`docs/decisions/`) |

(`project-context.md` used to duplicate this table; `mayor-sks59` linked
it here instead, 2026-08-13.)
