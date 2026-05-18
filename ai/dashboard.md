# Dashboard

2026-05-19 UTC+2
Resume: open Claude Code at /Users/balint.erdos/u7s (new mayor session)
Open beads: 0

## What needs the operator now

**DECISION PHASE — backlog is cold.** No open beads, no open PRs, no workers. Mayor is idle until Phase 3 scope is defined.

To resume: file Phase 3 beads, or say "run a Phase 3 audit" and the mayor will dispatch a read-only audit worker to surface gaps.

Known Phase 3 candidates (from architectural decisions):
- `crates/scheduler` skeleton (DB-04 deferred)
- Controller-manager SA token provisioning (DB-05 deferred)
- Conformance testing (sonobuoy / kube-bench) — API surface may now be ready
- kubectl end-to-end smoke tests against a live cluster

## Forward-looking

Nothing is in flight. Dispatch resumes as soon as beads exist. The push phase is over; this is the natural pause between phases.

## Recent progress

Phase 2 fully complete — 12 PRs merged, 29/29 beads closed, all worktrees removed.

| Wave | PRs | Highlights |
|------|-----|------------|
| Wave 1 | #4–#7 | Store watch, generic handler, merge patch, RBAC index |
| Wave 2 | #8–#12 | Field selector, pod watch, namespace CRUD, generic cluster, auth middleware |
| Wave 3 | #13–#15 | Core resources, SSRR/SSAR, SA TokenRequest JWT |

Main is clean at `68a3020`. No stale branches, no stale worktrees.

## Stance (reasserted)

Pre-alpha/greenfield: break freely, no backward compat, delete dead code. Correctness first, then performance (hard RSS/latency targets). kubectl-compatible API surface. Minimal dependencies — resist adding crates. Mayor merges on green CI; flags security/API surface/architecture PRs for operator review first.
