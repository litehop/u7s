---
name: roadmap
description: u7s roadmap — current state and priorities via a per-component decision matrix and horizontal gates. Not a phase list. Durable north star, decision framework, and guiding principles live in north-star.md; this file changes often and links back rather than restating them.
metadata:
  type: project
as_of: 2026-08-18
kind: roadmap
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
| **KCM (kube-controller-manager)** | UPSTREAM | Yes | MEASURED | Runs with `--controllers='*,-cloud-*'`. Confirmed the **second-largest** component in the stack by a wide margin. Native reimplementation attempted then deleted (`mayor-20325`). Least-privilege auth gap (was tracked as EPIC `mayor-axi12`) resolved 2026-08-13: dedicated x509 identities replace the `system:masters` admin-cert shim for both KCM (`mayor-c6rml`) and the scheduler (`mayor-c0b1u`, same gap found via the axi12 audit). Same evidence-gated process applies to the full component — an upstream config-tuning audit comes before any rewrite cost-benefit estimate. |
| **Kubelet** | UPSTREAM | Yes | MEASURED | Runs on every node. Confirmed the **single largest** component by a wide margin — more than double KCM. "Gargantuan" (scope, complexity, footprint) is a real, multi-dimensional description, not a disqualifier: necessity is obvious (skipped), cost is measured, an upstream config-tuning audit is next, native rewrite is only considered after that. Packaging shape (Gate 6) may also factor in eventually. |
| **CRI-O + crun** | UPSTREAM | Yes | KEEP | Container runtime. No plan to rewrite; measurement was for completeness only. |
| **kube-proxy** | UPSTREAM | Yes | MEASURED | Low-level networking; native rewrite is high-effort. No presumption either way — same necessity-then-cost-then-tuning-then-rewrite evaluation as everything else, data-first. |
| **konnectivity-server** | HYBRID | Yes | KEEP-as-dev-tool, skipped in production | Bridges apiserver (host) → kubelet (VM subnet) across Lima's NAT boundary — a dev-topology artifact, not a runtime requirement. Same-network production deployments (k3s-style packaging target) dial `kubelet:10250` directly; no tunnel needed. User-provided VPN/WireGuard mesh covers any cross-network case transparently. Product-shape re-open trigger: if u7s ever targets hosted-control-plane (users bring nodes over public internet), tunnel requirements return and this row should be re-evaluated. Decision settled 2026-08-19 (see `mayor-yi29j` close reason). |
| **CoreDNS** | UPSTREAM | Yes | KEEP | In-cluster DNS. No plan to rewrite. |
| **metrics-server** | UPSTREAM | Yes | KEEP | Standard component; no rewrite plan. |
| **Sentinel / sentinel-derive** | NATIVE (test infra) | n/a | KEEP | Proto-descriptor oracle framework, closed the silent-decode-drop bug class. |

**On the k3s/k0s comparison:** resolved — real k3s (v1.36.3+k3s1, native
containerd) was installed, run through the same sonobuoy harness, and
measured with the same component-boundary accounting u7s uses on itself.
Single-node idle matched-boundary total: **~813 MB**, ~8-11x the old
illustrative "~70-100MB" bare-binary estimate, and ~6.1x above u7s's own
128 MiB Gate-4 target (a conservative floor against the target, not u7s's
current actual total). This doesn't change Gate 4's target or urgency; it
replaces a hand-wavy caveat with a real number, though the container
runtime's (CRI-O vs containerd) behavior under real load remains only
partially resolved. Full methodology, deviations, and per-process tables:
`ai/perf/mayor-5x0kh-k3s-matched-comparison-2026-08-20.md`. The separate
upstream configuration/tuning audit for kubelet and KCM remains open and
untouched by this work.

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

### Gate 2 — Measurement baseline — u7s-side pass complete, k3s comparison resolved
- `mayor-jnk90` closed 2026-08-12: one full 2-node conformance run with the
  `mayor-zpvp2` sampler, producing per-process RSS for every component in the
  matrix above.
- `mayor-5x0kh` closed 2026-08-20: real k3s measured with the same harness
  and the same component-boundary accounting, replacing the old illustrative
  k3s figure. See the matrix's "On the k3s/k0s comparison" note for the
  result and its remaining open sub-question (container-runtime behavior
  under real load).
- Follow-ons filed from the `mayor-jnk90` run, all since resolved: CPU
  trajectory instrumentation added (`mayor-aozrt`), the CoreDNS RSS anomaly
  root-caused and fixed (`mayor-b1gz2`), and the `run-all.sh`
  monitoring-artifact gap fixed 2026-08-14 (`mayor-xzkqw`, PR #1158).
- Re-measure u7s's own side after every non-trivial component-level perf
  change.

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

**Post-tuning baseline, verified (`mayor-3a0et`, 2026-08-20):** this session
landed a cluster of memory/correctness fixes (kubelet + KCM Go-runtime
tuning, codegen migration, protobuf-decode fixes, Lima network partition)
with no full Conformance run verifying their combined effect until now —
prior Gate-4 checks this session used a stale pre-tuning run. A fresh
2-node run (`lima-node-2`+`lima-node-4`, full `--reset`, 483/483 passed,
same primary-node-only accounting as the pre-tuning baseline) gives:
**idle 358,456 KB (350.1 MiB, 2.74x target) vs pre-tuning 350,036 KB (2.67x)
— +2.4%, entirely attributable to CRI-O's idle footprint (+22.0%), not any
of this session's fixes; peak 460,468 KB (449.7 MiB, 3.51x target) vs
pre-tuning 492,124 KB (3.76x) — a real -6.4% improvement, driven mostly by
KCM (-17.7% peak) and the apiserver (-10.4% peak).** This baseline
deliberately excludes two still-open PRs (`mayor-zbkq1` protobuf fix,
`mayor-pjtkz` KCM tuning) — neither expected to move these numbers
materially, but this is not a complete-fixes baseline. A depth-20 dhat
profile of the same 2-node topology ran immediately after; see
`ai/findings/mayor-3a0et-post-tuning-baseline-and-depth20-profile-2026-08-20.md`
for the full per-process table, the 2nd-node cost (not previously reported),
and the profiling depth/overhead data point.

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

### Gate 7 — Migration story (future consideration, NOT STARTED)
Operator observation (2026-08-14): a fresh-install story (Gate 6) answers
"how does a new user get a u7s cluster," not "how does an existing k3s/k0s
user — frustrated with their current distro — move to u7s." Both matter for
adoption; migration is the harder, later problem. Two distinct sub-problems,
not one:

- **Control-plane migration without data loss.** Moving the cluster's actual
  API-object state (Deployments, Services, Secrets, etc.) from the old
  control plane's backing store into u7s's SQLite store. The likely shape is
  API-level export/import (list every resource from the old cluster, apply
  into u7s) rather than a byte-level store migration — that avoids coupling
  u7s to k3s's embedded-etcd or dqlite internals, at the cost of not
  preserving resourceVersion/UID history (probably an acceptable trade for a
  one-time cutover). PersistentVolume *data* (not the API object, the actual
  bytes on disk) is a separate concern from API-object migration and needs
  its own story (e.g. rsync-style volume migration) — conflating the two
  would understate the problem.
- **Data-plane node conversion.** Because u7s deliberately reuses real
  upstream kubelet unmodified (see north-star.md's conformance principle),
  this is structurally simpler than it would be for a distro with a bundled
  node agent: kubelet is control-plane-agnostic, so converting a node is
  closer to a normal node re-join (stop the old agent, point kubelet's
  kubeconfig + CA trust at u7s's apiserver, restart) than a from-scratch
  rewrite. This is a genuine structural advantage of the
  reuse-real-components decision, not a proposal to build agent-swap
  tooling now — worth remembering when Gate 6/7 design work actually starts.

Not a bead yet — no actionable next step exists until Gate 6 (packaging)
settles the target install/topology shape; you can't design a migration
*into* a shape that isn't decided yet. Fires after Gate 6, opportunistically
informed by whichever real distro (k3s most likely, given the north star's
comparison) the first migration-seeking user is actually running.

---

## Standing initiatives (bd EPICs)

Long-running arcs tracked in bd, not tied to a single gate.

| EPIC | Priority | Status | Trigger / un-defer condition |
|---|---|---|---|
| `mayor-u6ju` | P3 | DEFERRED | Gate 5's representative-workload probes (Argo CD or otherwise) demonstrate a real Server-Side Apply requirement — deliberately not pursued speculatively, given SSA's scope |
| `mayor-8qcaw` | P4 | DEFERRED | Backlog otherwise clears OR DRA conformance failure traces to claim allocation |

Closed since last revision: `mayor-axi12` (superseded 2026-08-13 by `mayor-c6rml`/`mayor-c0b1u`, both closed — see KCM matrix row) and `mayor-0bd14` (100% of 10 children closed, no work remaining — closed 2026-08-14).

---

## Deferred / opportunistic follow-ons

| Bead | Priority | Note |
|---|---|---|
| `mayor-rvkq` | P3 | CRD CEL validation (`x-kubernetes-validations`). A CEL evaluator already exists for `ValidatingAdmissionPolicy` — this would wire it into CR schema validation, not build one from scratch. Trigger: real workload uses CEL in a CRD schema |
| `mayor-9xsn3` | P3 | DRA v1alpha3 registration. Deferred to 1.37 upstream bump (schema growing there) |

Closed since last revision: `mayor-jtlnx` (CLOSED 2026-08-14, no-fix-warranted) —
verified against two fresh full-conformance runs that `mayor-9sd51`/PR #1134's fix
eliminates 100% of the original fatal `deleteCollection` signature. A different,
non-fatal error still surfaces ~once per 446-spec run via `deleteAllContent`'s
unscoped `listCollection` sweep, but it self-heals via KCM's own retry in
single-digit milliseconds and does not block conformance. Extending verb-scoping
to that LIST path was investigated and explicitly rejected: it risks reintroducing
the informer-relist-hangs-forever bug `mayor-9sd51` fixed, since there's no safe
way to distinguish a namespace-deleter sweep LIST from an informer relist LIST at
the handler level. No PR opened; see bead close reason for full evidence.

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

(`project-context.md`'s "Design decisions" section previously duplicated
this table; `mayor-sks59` resolved that 2026-08-13 — it now links here
instead of restating the list.)

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
