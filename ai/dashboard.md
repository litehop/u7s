# Dashboard
2026-05-23 11:45 UTC
Resume: open Claude Code in /Users/balint.erdos/u7s and say "I am the Mayor now"
Open beads: 2 (1×P2, 1×P3)

## What needs the operator now

**Decision: sonobuoy run (`mayor-2ni`)**
Ready to run a sonobuoy non-disruptive conformance pass? Needs u7s on Mac host + lima VM. Operator must initiate.

**Decision: OpenAPI/protobuf research (`mayor-w2il`)**
Research bead filed this session. Safe to dispatch a research agent any time — no code changes, findings doc only.

## Open beads

| Bead | Priority | Description |
|------|----------|-------------|
| mayor-w2il | P2 | Research: effort estimate for proper OpenAPI spec + protobuf encoding |
| mayor-2ni | P3 | Sonobuoy non-disruptive conformance audit |

## In-flight / open PRs

None — all clean.

## Recent progress (this session)

- **6 PRs merged**: #200 (system:authenticated), #201 (SSA managedFields), #202 (RBAC aggregation + nonResourceURLs), #203 (namespace lifecycle + kcm controllers), #204 closed (wrong scope), #205 (bench-rss-deploy — Deployment reconciliation RSS bench)
- **7 beads closed**: mayor-hcen, mayor-oydz, mayor-5u0r, mayor-9sil, mayor-rlou, mayor-hfmg, mayor-h2fk
- **Pre-push hook wired**: `core.hooksPath = .githooks` + `chmod +x` enforced on every push
- **APISnoop research**: not needed for CNCF cert (sonobuoy is the gate)
- **314 beads closed total**, 2 remain

## Stance
Pre-alpha/greenfield: break freely, no backward compat, correctness first, performance-critical (RSS/latency hard targets), kubectl-compatible API surface, minimal crate deps. Mayor merges on green CI (missing checks = merge conflict to investigate). Flags security/API/architecture PRs for operator review first.
