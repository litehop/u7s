---
name: roadmap
description: u7s roadmap — current state and priorities via a per-component decision matrix and horizontal gates. Not a phase list. Durable north star, decision framework, and guiding principles live in north-star.md; this file changes often and links back rather than restating them.
metadata:
  type: project
---

# u7s Roadmap

See [north-star.md](north-star.md) for why u7s exists, how component
decisions get made, and what "done" means in principle — that document
changes rarely and needs explicit operator sign-off. This file is the
opposite: current state, measurements, and priorities, expected to change
often as work lands. Specific figures here are snapshots — treat anything
numeric as dated the moment a new measurement lands, and check
`ai/findings/` or `dashboard.md` for the latest before relying on a number
quoted below.

---

## Component matrix

State legend: **NATIVE** (u7s-owned Rust) · **UPSTREAM** (real upstream
binary runs against u7s) · **HYBRID** (upstream binary, run and configured
by u7s).

Decision legend: **KEEP** (decision made, no revisit expected) · **MEASURED**
(data exists, decision open) · **UNMEASURED** (blocks decision) · **DEFERRED**
(decision explicitly parked with un-defer trigger).

| Component | State | Measured? | Decision | Notes / next action |
|---|---|---|---|---|
| **API server** | NATIVE | Yes | KEEP | Smallest of u7s's own components. Ring-resize + fat LTO landed; protobuf response encoder for hot-path LIST; decode-correctness fixes ongoing. Current figures change with nearly every perf PR — see `ai/findings/` and `dashboard.md`, not restated here. |
| **Scheduler** | NATIVE | Yes | KEEP | Bin-spread scheduler, custom preemption, DB-04 resolved. Confirmed small relative to the rest of the stack. |
| **Store** | NATIVE (part of apiserver) | Yes | KEEP | SQLite WAL + sharded watch fan-out + per-shard compaction horizon. |
| **KCM (kube-controller-manager)** | UPSTREAM | Yes | MEASURED | Runs with `--controllers='*,-cloud-*'`. Confirmed the **second-largest** component in the stack by a wide margin. Native reimplementation attempted then deleted (`mayor-20325`); SA-token provisioning tracked separately as EPIC `mayor-axi12` (deferred). Same evidence-gated process applies to the full component, not just the SA-token sub-issue — an upstream config-tuning audit comes before any rewrite cost-benefit estimate. |
| **Kubelet** | UPSTREAM | Yes | MEASURED | Runs on every node. Confirmed the **single largest** component by a wide margin — more than double KCM. "Gargantuan" (scope, complexity, footprint) is a real, multi-dimensional description, not a disqualifier: necessity is obvious (skipped), cost is measured, an upstream config-tuning audit is next, native rewrite is only considered after that. Packaging shape (Gate 6) may also factor in eventually. |
| **CRI-O + crun** | UPSTREAM | Yes | KEEP | Container runtime. No plan to rewrite; measurement was for completeness only. |
| **kube-proxy** | UPSTREAM | Yes | MEASURED | Low-level networking; native rewrite is high-effort. No presumption either way — same necessity-then-cost-then-tuning-then-rewrite evaluation as everything else, data-first. |
| **konnectivity-server** | HYBRID | Yes | MEASURED, necessity in question | Its current job (routing admission-webhook calls to pod IPs) is tied to *today's dev topology* — the host apiserver can't otherwise reach the VM's pod network (`docs/decisions/webhook-tls-via-konnectivity.md`). Whether u7s's real target deployment shape needs an apiserver↔kubelet tunnel *at all* is open — e.g. a WireGuard-meshed cluster would likely put the control-plane node on the same mesh as everything else, removing the need. The necessity question comes before any build-vs-delegate call here. |
| **CoreDNS** | UPSTREAM | Yes | KEEP | In-cluster DNS. No plan to rewrite. |
| **metrics-server** | UPSTREAM | Yes | KEEP | Standard component; no rewrite plan. |
| **Sentinel / sentinel-derive** | NATIVE (test infra) | n/a | KEEP | Proto-descriptor oracle framework, closed the silent-decode-drop bug class. |

**On the k3s/k0s comparison:** the north star cites k3s's control-plane/agent
RSS as illustrative scale, not a verified target (see north-star.md). u7s's
own absolute per-component numbers above are real and measured
(`mayor-jnk90`, 2026-08-12 — see
`ai/findings/upstream-component-rss-cpu-baseline-2026-08-12.md`). The
*ratio* between u7s and k3s is **not** trustworthy yet: k3s's figure covers
only the `k3s`/`k3s-agent` binary itself, while u7s's figure sums every
control-plane and data-plane process (including crio and CoreDNS, which have
no confirmed counterpart inside the k3s number). Two concrete follow-ons,
independent of each other:
1. A matched-methodology comparison — verify what's actually inside the
   k3s/k3s-agent binaries against k3s source, then measure both sides at the
   same scope.
2. An upstream configuration/tuning audit for kubelet and KCM specifically
   (the two dominant components) — cheap to check, and must happen before
   any rewrite cost-benefit estimate, per north-star.md's decision process.

---

## Gates (horizontal cuts across the matrix)

Not a linear sequence — some gates run in parallel. But each has a fireable
un-defer trigger.

### Gate 1 — Conformance floor ✓ CLEARED, with known blind spots
- Full 446-spec sonobuoy non-disruptive-Conformance passes.
- Single-node 446/446 first green: 2026-07-24.
- Two-node 446/0/0/7133 in 25m11s: 2026-08-10.
- **Caveat, not a footnote:** a green suite is necessary but not sufficient
  evidence of correctness. Its heavy single-node bias is a real, demonstrated
  blind spot — the scheduler shipped with zero taint/toleration handling for
  a period without the suite ever catching it, because taint enforcement is
  overwhelmingly a multi-node concern (since fixed —
  `node_taints_tolerated`/`toleration_matches_taint` in `crates/scheduler`).
  This is exactly what Gate 5 below exists to keep catching.
- Any test regression triggers immediate correctness work (higher priority
  than perf work) — see north-star.md's correctness-first principle.

### Gate 2 — Measurement baseline — first pass complete, comparison unresolved
- `mayor-jnk90` closed 2026-08-12: one full 2-node conformance run with the
  `mayor-zpvp2` sampler, producing per-process RSS for every component in the
  matrix above. See the matrix's "On the k3s/k0s comparison" note for what
  this does and doesn't establish yet.
- Follow-ons filed from that run: no CPU trajectory data yet (`mayor-aozrt`,
  only RSS was captured), a CoreDNS RSS anomaly (`mayor-b1gz2`), and a
  monitoring-artifact gap in `run-all.sh` (`mayor-xzkqw`).
- Re-measure after every non-trivial component-level perf change, and once
  the matched k3s-comparison methodology exists.

### Gate 3 — Correctness infrastructure ✓ SUBSTANTIALLY DONE
- Proto-descriptor oracle: sentinel-completeness expected-key lists derived
  from `FileDescriptorSet` instead of hand lists. Closed a bug class that
  had produced ~10 silent-decode-drop bugs in the month before it landed.
- Filter-is-empty three-state pointer-string bug class: audited, concrete
  fixes shipped, refactor recommendation banked (`present_nonempty` /
  `present_any` helper pair, opportunistic adoption).
- Observability EPIC: structured access log + `/metrics` + ring gauges,
  extended into automated run-time sampling.

### Gate 4 — Perf (ACTIVE since 2026-07-24)
Method: audit → file bead → measured before/after → land. No perf PR without
a measured delta. Correctness gaps found through any means — conformance, a
non-conformance-tagged e2e subset, or a representative workload — preempt
in-progress perf work, same priority as a conformance regression.

Kinds of wins landed so far: watch-ring sharding and sizing, discovery-path
caching, protobuf response encoding for hot-path LIST types, per-version CR
conversion caching, typed-fields migration, and build/profiling tooling
fixes that prevented a misattributed regression. Full list with PR
references: `dashboard.md` and `ai/findings/`.

Known follow-ons: protobuf response encoding for watch-stream framing;
wider field coverage toward decode parity; opportunistic adoption of the
`present_nonempty`/`present_any` helper pair.

**Target:** u7s's own control-plane processes (apiserver + scheduler + every
component the matrix above still runs) under **128 MiB combined**, idle — a
founding-session target (`project-context.md`), independently reaffirmed
this session. Explicitly excludes any in-cluster workload's own footprint
(Argo CD, test workloads, anything running as a pod) — u7s controls its own
processes, not what users deploy on top. This target doesn't depend on the
unresolved k3s-ratio question above: it's far enough below even the
illustrative k3s figure that hitting it settles the comparison on any
reasonable accounting.

### Gate 5 — Correctness baseline beyond Conformance (ongoing, opportunistic)
Conformance is necessary but not sufficient (Gate 1's caveat). This gate
exists to keep finding what it misses, using two complementary approaches:
- Representative workloads exercising realistic usage patterns — candidates
  include a WordPress+MariaDB-style stateful app, a workload with GPU
  requests, and Argo CD. Argo CD's role here is as a correctness probe, not
  a milestone to reach for its own sake (see north-star.md).
- Subsets of upstream e2e tests that aren't Conformance-tagged but exercise
  real behavior Conformance's single-node bias misses (multi-node scenarios,
  CSI, etc.).

Not urgent — built incrementally alongside other work, not a dedicated push.
Known candidate fix if the Argo CD probe specifically fails on an RBAC gap:
`mayor-j7to` (seeds minimal Argo CD RBAC), deliberately left deferred until
that failure is actually observed rather than pre-emptively applied —
pre-seeding before attempting the install would mask whatever the real gap
turns out to be.

### Gate 6 — Packaging & distribution (NOT STARTED)
End-game: k3s-style one-shell-script install. See north-star.md's packaging
philosophy for the settled direction (default everything, minimal
configurable surface — node identity and network-interface selection only —
motivated by concrete k3s/k0s failure modes). Still open:
- Binary distribution shape: single static binary? per-component binaries?
- How upstream KCM/kubelet/CRI-O ship alongside u7s (download at first-run
  vs. bundled vs. dependency).
- Fresh-VM install contract (systemd unit? podman? bare processes?).
- Multi-node scale-out shape.

Not a bead yet. Fires when correctness + perf are both stable enough that a
packaging story would not need to be re-litigated within weeks, and once
Gate 2's component decisions are far enough along to know what's actually
being packaged.

---

## Standing initiatives (bd EPICs)

Long-running arcs tracked in bd, not tied to a single gate.

| EPIC | Priority | Status | Trigger / un-defer condition |
|---|---|---|---|
| `mayor-axi12` | P3 | DEFERRED | Conformance or Argo CD install exposes SA-token auth gap (Gate 5) |
| `mayor-u6ju` | P3 | DEFERRED | Gate 5's representative-workload probes (Argo CD or otherwise) demonstrate a real Server-Side Apply requirement — deliberately not pursued speculatively, given SSA's scope |
| `mayor-8qcaw` | P4 | DEFERRED | Backlog otherwise clears OR DRA conformance failure traces to claim allocation |
| `mayor-0bd14` | P2 | OPEN (all 10 children CLOSED) | bd-hygiene: mark EPIC closed; no work remaining |

---

## Deferred / opportunistic follow-ons

| Bead | Priority | Note |
|---|---|---|
| `mayor-rvkq` | P3 | CRD CEL validation (`x-kubernetes-validations`). A CEL evaluator already exists for `ValidatingAdmissionPolicy` — this would wire it into CR schema validation, not build one from scratch. Trigger: real workload uses CEL in a CRD schema |
| `mayor-jtlnx` | P3 | Verify `mayor-9sd51`/PR #1134 eliminates 100% of KCM 410 fatal errors. Opportunistic on next conformance run |
| `mayor-9xsn3` | P3 | DRA v1alpha3 registration. Deferred to 1.37 upstream bump (schema growing there) |
| `mayor-t1h49` | P3 | `ai/prompts/` refresh — stale `controller-manager` references |

---

## Architecture summary (for reference)

| Component | Decision | Doc |
|---|---|---|
| API server | From scratch in Rust (axum) | `docs/decisions/rust-api-server-from-scratch.md` |
| State store | SQLite WAL (rusqlite bundled), sharded watch fan-out by resource-type prefix | `docs/decisions/sqlite-over-lmdb.md` |
| Container runtime | CRI-O + crun | `docs/decisions/crio-over-containerd.md` |
| Scheduler | Custom Rust scheduler (`crates/scheduler`) — in-memory NodeTally, preemption, periodic re-sync | `docs/decisions/custom-bin-spread-scheduler.md` |
| CRD validation | boon crate (full openAPIV3Schema) | `docs/decisions/boon-for-crd-schema-validation.md` |
| Networking | WebSocket-only exec/attach/portforward (no SPDY) | operator confirmed 2026-05-28; k8s 1.34+ dropped SPDY |
| TLS | aws-lc-rs (P-256 ECDSA) — known arm64/Lima compat issue; workaround: use CI | memory: `local-lima-arm64-environment` |

(This table duplicates `project-context.md`'s "Design decisions" section —
known, tracked as part of `mayor-sks59`'s broader cleanup, not resolved
here.)

---

## What this roadmap is not

- Not a timeline. Timelines assume predictable engineering-effort estimates on a
  novel codebase; we don't have those. Every gate has a fireable trigger; that's
  what schedules the next work.
- Not a phase list. Component decisions are per-component, not per-phase. The
  matrix above is the primary structure; gates are horizontal cuts, not linear
  phases.
- Not an aspiration doc. Every row cites either a shipped decision, a filed
  bead, or a pointer to where the current data lives. Aspiration lives in
  north-star.md; everything below it is tracked work.
