# Dashboard
2026-05-21 11:15 UTC
`bd prime` in a fresh Claude Code session (or say "I am the Mayor now")
Open beads: 5

## What needs the operator now

- **CSR bootstrap decision (mayor-z1bu, P3):** Option B (k3s-style direct signing, ~5–10 MB, simple) vs Option C (upstream CSR API compatible, ~10–20 MB). Worker cannot be dispatched until you decide.
- **Remote orphan branches** — 4 worker branches on origin cannot be deleted due to branch protection rules: `worker/agent-a527be169434048f8`, `worker/agent-a9860d883980034a1`, `worker/agent-a30178a0715196ad9`, `worker/ci-node-ready-mayor-2dc`. All are from merged/closed PRs. Operator needs to delete these manually or relax the protection rule for `worker/*`.
- **Renovate PRs #109 (rcgen) and #110 (rusqlite)** — still failing CI, need a rebase onto main to pick up smoke test fixes.

## Forward-looking

All P2 beads are dispatchable now. Next dispatch round:
- **mayor-22n6** — replace system:masters hardcoded bypass with seeded ClusterRoleBinding
- **mayor-8c89** — enforce coverage threshold as hard CI gate
- **mayor-pudl** — verify SA token projection end-to-end
- **mayor-2ni** (P3) — sonobuoy conformance audit (smoke test now green, this is unblocked)
- Renovate PRs #109/#110 rebase workers

## Recent progress

Smoke test is now fully green across all 3 kubelet matrix versions (1.34.8, 1.35.5, 1.36.1). Two root causes fixed:
1. CRI-O runtime: forced `crun` v1.4.5 rejected OCI spec 1.2.x from CRI-O 1.34+ — removed the pin, simplified CNI to cniVersion 0.4.0 bridge-only.
2. `spec.enableServiceLinks` defaulting — kubelet raised `CreateContainerConfigError` when field absent — fixed with `apply_pod_create_defaults()` in `pods.rs`.

PRs merged this session: **#125** (CNI + pod lifecycle test), **#127** (proto decoders + smoke fixes), **#126** (system:nodes RBAC), **#124** (jsonwebtoken), **#123** (CodeQL). ~10 PRs total today, ~12 beads closed.

Hygiene: 3 idle local worktrees removed, stale tracking refs pruned.

## Stance
Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
