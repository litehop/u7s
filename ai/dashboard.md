# Dashboard
2026-05-23 10:15 UTC
Session: new session — mayor restarted
Open beads: 2 (2×P3)

## What needs the operator now

**Decision: sonobuoy run (`mayor-2ni`)**
Ready to run a sonobuoy non-disruptive conformance pass? Needs: u7s running on Mac host + lima VM. Operator must kick this off manually (or say yes and mayor dispatches the audit worker). CNCF certification path confirmed: sonobuoy results are what matters (not APISnoop).

**Nothing else blocking.** `mayor-h2fk` (RSS bench) will be dispatched automatically once you confirm it's safe — see below.

## Forward-looking focus

- **`mayor-h2fk`** — RSS bench with Deployment reconciliation loop. Safe to dispatch now: PR #203 (namespace controller + kcm expansion) just merged. Will dispatch this session.
- **`mayor-2ni`** — sonobuoy audit. Operator-time task; mayor can dispatch the audit worker once operator confirms the local cluster is up.
- After those two: backlog is empty. File new beads or wait for sonobuoy results to drive next wave.

## In-flight / open PRs

None — all clean.

## Recent progress

This session (2026-05-23):
- **5 PRs merged**: #200 (system:authenticated), #201 (SSA managedFields), #202 (RBAC aggregation + nonResourceURLs), #203 (namespace lifecycle + kcm controllers), bead sync commit
- **6 beads closed**: mayor-hcen, mayor-oydz, mayor-5u0r, mayor-9sil, mayor-rlou, mayor-hfmg
- **Pre-push hook wired**: `core.hooksPath = .githooks` + `chmod +x` — enforces fmt+test+clippy on every push
- **APISnoop research**: not needed for CNCF cert (sonobuoy is the gate); APISnoop deferred/dropped
- 313 beads closed total, 2 remain

## Stance
Pre-alpha/greenfield: break freely, no backward compat, correctness first, performance-critical (RSS/latency hard targets), kubectl-compatible API surface, minimal crate deps. Mayor merges on green CI (missing checks = merge conflict to investigate). Flags security/API/architecture PRs for operator review first.
