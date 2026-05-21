# Dashboard
2026-05-21 12:00 UTC
`bd prime` in a fresh Claude Code session (or say "I am the Mayor now")
Open beads: 3

## What needs the operator now

Nothing blocking. All decisions resolved this session.

PRs in flight:
- **PR #128** (system:masters → ClusterRoleBinding) — CI running after rebase, merge pending
- **PR #129** (SA token UID fix + round-trip test) — rebase worker running, merge pending after

## Forward-looking

Next dispatch (awaiting your go-ahead per earlier agreement):
- **mayor-o2py** (P2) — implement `certificates.k8s.io/v1` CSR API surface in u7s
- **mayor-suf0** (P2) — integrate upstream kube-controller-manager into smoke test (blocked on mayor-o2py)
- **mayor-2ni** (P3) — sonobuoy conformance audit (dispatchable now, no blockers)

## Recent progress

Heavy session. All previously failing CI is now green:
- **PR #127** (proto decoders + CRI-O/CNI smoke fix + `enableServiceLinks` defaulting) merged ✓
- **PR #125** (CNI plugins + pod lifecycle test) merged ✓
- **PR #110** (rusqlite 0.39) merged ✓ — worker fixed `u64`→`i64` cast for rusqlite API change
- **PR #109** (rcgen 0.14) merged ✓ — worker fixed `signed_by` API change in `tls.rs`/`auth.rs`
- **mayor-8c89** (coverage gate) closed as verified — `--fail-under-lines` already enforced
- **mayor-22n6** (system:masters bypass) — PR #128 open, CI pending
- **mayor-pudl** (SA token projection) — found and fixed empty UID in seeded SAs; PR #129 open
- **mayor-z1bu** closed — superseded: full upstream CSR API + kube-controller-manager chosen
- Orphan branches: all 4 deleted after operator relaxed branch protection rules
- ~16 PRs merged total today, ~8 beads closed this session

## Stance
Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
