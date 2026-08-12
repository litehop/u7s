---
name: roadmap
description: u7s roadmap — north star, decision framework, per-component state matrix, and horizontal gates. The authoritative place to track what's done, what's in flight, and what's waiting on a trigger. Not a phase list; a component matrix with measurement-gated decisions.
metadata:
  type: project
---

# u7s Roadmap

**North star.** A Kubernetes distro for environments where even k3s and k0s
(both Go, both ~430 MiB control-plane + ~60 MiB agent) are too heavy. The
end-game is `curl … | sh` install parity with k3s at a fraction of the
resources. A running Argo CD GitOps setup was a mid-milestone, not the point.

**Decision metric (single, load-bearing).**
> Can we stay conformant with less resources? If yes, build/optimize it in u7s.
> If no (correctness would slip, or the engineering-vs-savings ratio is bad),
> keep the upstream component.

**Conformance is the floor, not the goal.** We cannot claim "a Kubernetes distro on
a fraction of the resources" if it is not a conformant Kubernetes distro. Conformance
is what makes every "u7s vs upstream" resource comparison meaningful. Correctness
regressions are always higher priority than perf work.

**Guiding principles (operator, load-bearing for every dispatch).**
1. **Conform, don't reinvent — especially at the API level.** Kubernetes'
   architecture is proven; u7s optimizes *on* it, it does not fork it. This is
   what lets us run REAL upstream KCM/kubelet/kube-scheduler against u7s as
   conformance oracles. Diverging at the API boundary would forfeit that.
2. **Correctness first, performance second.** Perf work on incorrect code
   optimizes the wrong thing.
3. **Every component decision is gated by measurement.** No "we should rewrite
   kubelet" or "kube-proxy is fine as upstream" without RSS/CPU data for both
   sides. `mayor-jnk90` fills in this table; until it lands, cells are `TBD`.

**Project stance.** Pre-alpha/greenfield. No backward compat. Break freely.

---

## Component matrix

State legend: **NATIVE** (u7s-owned Rust) · **UPSTREAM** (real upstream binary
runs against u7s) · **UNKNOWN** (no measurement, no decision yet).

Decision legend: **KEEP** (decision made, no revisit expected) · **MEASURED**
(data exists, decision open) · **UNMEASURED** (blocks decision) · **DEFERRED**
(decision explicitly parked with un-defer trigger).

| Component | State | RSS (peak) | RSS (idle) | Decision | Notes / next action |
|---|---|---|---|---|---|
| **API server** | NATIVE | 82 MiB | ≤ 25 MiB | KEEP | Ring-resize + fat LTO landed (PR #1128); protobuf response encoder for hot-path LIST (PR #1130); many decode-correctness fixes in flight |
| **Scheduler** | NATIVE | TBD (mayor-jnk90) | TBD | KEEP | Bin-spread scheduler, custom preemption, DB-04 resolved. Never resource-measured against upstream `kube-scheduler` |
| **Store** | NATIVE (part of apiserver) | included above | included above | KEEP | SQLite WAL + sharded watch fan-out (mayor-drs2a) + per-shard horizon (mayor-f8ziu) |
| **KCM (kube-controller-manager)** | UPSTREAM | TBD (mayor-jnk90) | TBD | UNMEASURED | Runs with `--controllers='*,-cloud-*'`. Native reimplementation attempted then deleted (mayor-20325); SA-token provisioning tracked as EPIC `mayor-axi12` (deferred). Reconsider native subset only if measurement + roadmap justify |
| **Kubelet** | UPSTREAM | TBD (mayor-jnk90) | TBD | UNMEASURED | Runs on every VM. Native kubelet would be gargantuan; decision blocked on measurement AND on packaging shape (see Gates below) |
| **CRI-O + crun** | UPSTREAM | TBD (mayor-jnk90) | TBD | KEEP | Container runtime. No plan to rewrite; measurement is for completeness only |
| **kube-proxy** | UPSTREAM | TBD (mayor-jnk90) | TBD | UNMEASURED | Low-level networking; native rewrite is high-effort. Operator: leaning delegation but wants data first |
| **konnectivity-server** | HYBRID (upstream binary run by u7s) | TBD (mayor-jnk90) | TBD | UNMEASURED | Same shape as kube-proxy: low-level, native rewrite unattractive. Data-first |
| **CoreDNS** | UPSTREAM | TBD (mayor-jnk90) | TBD | KEEP | In-cluster DNS. No plan to rewrite |
| **metrics-server** | UPSTREAM | TBD (mayor-jnk90) | TBD | KEEP | Standard component; no rewrite plan |
| **Sentinel / sentinel-derive** | NATIVE (test infra) | n/a | n/a | KEEP | Proto-descriptor oracle framework (mayor-j430l → mayor-66qj6), closed the silent-decode-drop bug class |

Aggregate targets to beat (operator reference, from a live k3s toy cluster):
- **k3s control-plane node**: 430 MiB
- **k3s-agent data-plane node**: 60 MiB

u7s equivalents are TBD pending mayor-jnk90. That measurement is what turns
every UNMEASURED row into MEASURED and enables the per-component decisions.

---

## Gates (horizontal cuts across the matrix)

Not a linear sequence — some gates run in parallel. But each has a fireable
un-defer trigger.

### Gate 1 — Conformance floor ✓ CLEARED
- Full 446-spec sonobuoy non-disruptive-Conformance passes.
- Single-node 446/446 first green: 2026-07-24.
- Two-node 446/0/0/7133 in 25m11s: 2026-08-10.
- Any test regression triggers immediate correctness work (higher priority than perf).

### Gate 2 — Measurement baseline (IN FLIGHT: mayor-jnk90)
- One full 2-node conformance run with the mayor-zpvp2 sampler active (PR #1131).
- Deliverable: per-process RSS + CPU trajectories for every component in the matrix.
- Aggregate control-plane and data-plane numbers directly comparable to k3s 430/60 MiB.
- Un-blocks: every UNMEASURED → MEASURED transition, i.e. every "should we rewrite X?" question.
- Follow-on: re-measure after every non-trivial component-level perf change.

### Gate 3 — Correctness infrastructure ✓ SUBSTANTIALLY DONE
- Proto-descriptor oracle: sentinel-completeness expected-key lists derived from `FileDescriptorSet` instead of hand lists. Closed a bug class that had produced ~10 silent-decode-drop bugs in the month before it landed. `mayor-j430l` → `mayor-66qj6`, PRs #1104-#1115.
- Filter-is-empty three-state pointer-string bug class: audited (`mayor-i2068`), 3 concrete fixes shipped (`mayor-mb9ed` PR #1121, `mayor-6xld9` PR #1132, `mayor-mqyg1` PR #1133), refactor recommendation banked (`present_nonempty` / `present_any` helper pair, opportunistic adoption).
- Observability EPIC: structured access log + `/metrics` (6-metric set) + ring gauges (`mayor-atemy`, closed 2026-07-31; extended by `mayor-zpvp2` PR #1131 into automated run-time sampling).

### Gate 4 — Perf (ACTIVE since 2026-07-24)
Method: audit → file bead → measured before/after → land. No perf PR without a measured delta.

Landed:
- Ring-shard by resource-type prefix (`mayor-drs2a` PR #1090)
- Per-shard compaction horizon (`mayor-f8ziu` PR #1125)
- Ring capacity 10,000 → 512 + fat LTO + `codegen-units=1` → **137 MiB → 82 MiB apiserver peak** (`mayor-eupeb` in #1128; sizing evidence from `mayor-4wsmv` / `mayor-pi684`)
- Discovery bytes-cache (3-order wall-clock speedup, `mayor-a9kc1` PR #1116)
- Decoder HashMap dispatch (62/64 arms, `mayor-77b49` PR #1117)
- Protobuf response encoder LIST-only hot-path (1.8-1.9x wire-size reduction, `mayor-re0a5` PR #1130)
- Per-version CR conversion cache EPIC (`mayor-zw0ou`, closed 2026-07-30)
- Global-bookmark broadcast fanout reduction (`mayor-dd9fp`/`mayor-38png` PR #1091)
- Typed-fields migration EPIC (`mayor-0bd14`, 10/10 children CLOSED; EPIC still marked OPEN in bd — hygiene fix pending)
- Build provenance + dhat-depth env-var + `debug=line-tables-only` (`mayor-xivpx`/`mayor-zjiqo`/`mayor-eupeb` cluster PR #1135) — methodology tooling that prevents mis-attributed regressions

Known follow-ons:
- Protobuf response encoder for watch-stream (4-byte length-delimited framing, deferred from mayor-re0a5)
- Widen protobuf response encoder field coverage toward decode parity (Pod affinity/topologySpread, Node daemonEndpoints/etc.)
- `mayor-i2068` audit's `present_nonempty`/`present_any` helper adoption (opportunistic, not blocking)

New target (replacing "beat existing distros ~1 GiB"): TBD pending mayor-jnk90.
Candidate target shape: aggregate control-plane RSS at conformance-suite peak
under N MiB. N picked after we see the number.

### Gate 5 — Argo CD milestone (partial, un-attempted end-to-end)
Implementation prerequisites: all done or superseded.
- Pod exec via WebSocket: SHIPPED (`mayor-mixv` PR #342)
- Namespace-controller finalizer ownership: SHIPPED (`mayor-bpmz9` PR #860)
- SA projected volume auto-injection: SHIPPED (`mayor-dlrr` PR #226)
- RBAC nonResourceURLs: SHIPPED (`mayor-9sil` PR #202)
- DB-05 KCM SA-token provisioning: DEFERRED as EPIC `mayor-axi12` — trigger unchanged (conformance/Argo CD install exposes auth gap; native scaffolding deleted 2026-08-12 per operator directive, reimplementation informed by pre-deletion git blame)

Un-attempted: `argocd install` against u7s has never been run. `mayor-j7to` (Argo CD RBAC seeding, deferred) fires only if the install attempt itself fails on that specific gap. This gate advances when someone runs `argocd install` and reports what breaks.

### Gate 6 — Packaging & distribution (NOT STARTED)
End-game: k3s-style one-shell-script install. Shape completely open. Questions to answer when we get here:
- Binary distribution: single static binary? per-component binaries? Homebrew tap? apt repo?
- Which configuration knobs to expose vs. lock behind sensible defaults?
- How is upstream KCM/kubelet/CRI-O packaged with u7s (download at first-run vs. bundled vs. dependency)?
- What's the fresh-VM install contract (systemd unit? podman? bare processes?)
- Multi-node scale-out shape (does the k3s `k3sup`-style paradigm fit u7s?)

Not a bead yet. Fires when correctness + perf are both stable enough that a packaging story would not need to be re-litigated within weeks.

---

## Standing initiatives (bd EPICs)

Long-running arcs tracked in bd, not tied to a single gate.

| EPIC | Priority | Status | Trigger / un-defer condition |
|---|---|---|---|
| `mayor-axi12` | P3 | DEFERRED | Conformance or Argo CD install exposes SA-token auth gap (Gate 5) |
| `mayor-u6ju` | P3 | DEFERRED | Research shows Helm/Argo/Flux requires Server-Side Apply |
| `mayor-8qcaw` | P4 | DEFERRED | Backlog otherwise clears OR DRA conformance failure traces to claim allocation |
| `mayor-0bd14` | P2 | OPEN (all 10 children CLOSED) | bd-hygiene: mark EPIC closed; no work remaining |

---

## Deferred / opportunistic follow-ons

| Bead | Priority | Note |
|---|---|---|
| `mayor-52wo` | P2 | OpenAPI v2 static-blob embedding. Trigger: sonobuoy API conformance check fails on stub |
| `mayor-j7to` | P2 | Argo CD RBAC seeding. Trigger: Argo CD install specifically fails on RBAC gap |
| `mayor-rvkq` | P3 | CRD CEL validation. Trigger: real workload uses CEL |
| `mayor-jtlnx` | P3 | Verify `mayor-9sd51`/PR #1134 eliminates 100% of kcm 410 fatal errors. Opportunistic on next conformance run |
| `mayor-9xsn3` | P3 | DRA v1alpha3 registration. Deferred to 1.37 upstream bump (schema growing there) |
| `mayor-t1h49` | P3 | `ai/prompts/` refresh — stale `controller-manager` references |
| `mayor-vy44t` | P2 | This roadmap rewrite itself |

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

---

## What this roadmap is not

- Not a timeline. Timelines assume predictable engineering-effort estimates on a
  novel codebase; we don't have those. Every gate has a fireable trigger; that's
  what schedules the next work.
- Not a phase list. Component decisions are per-component, not per-phase. The
  matrix above is the primary structure; gates are horizontal cuts, not linear
  phases.
- Not an aspiration doc. Every row cites either a shipped PR, a filed bead, or
  a TBD-until-<bead>. Aspiration lives in the north star; everything below it
  is tracked work.
