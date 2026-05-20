# Dashboard

2026-05-20T14:48 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**PR #80 CI pending** — metadata.uid fix (kubelet pod lifecycle blocker). Will auto-merge on green.

**Stance check** — current stance: pre-alpha/greenfield, break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; security/API/arch PRs flagged for operator review. Confirm still correct or adjust.

**Pod lifecycle retest** — after PR #80 merges, the e2e test should proceed past `ContainerCreating`. Two remaining unknowns until we rerun: (1) image pull succeeds inside lima VM, (2) no further apiserver gaps surface. Ready to retest on your signal.

**Nothing else blocked on you.**

## Forward-looking

1. PR #80 merges → rerun pod lifecycle test on lima-node
2. If pod reaches Succeeded: add CI smoke job (create pod, assert Succeeded within 60s)
3. mayor-xy2 (CR schema validation, P3) — deferred until Argo CD milestone

## Recent progress

Pod lifecycle e2e test run today — reached `ContainerCreating`, uncovered two bugs:
- **mayor-xt2 (fixed, PR #80)**: `metadata.uid` was null; cri-o needs uid to name sandbox
- **mayor-3ua (already done)**: system namespaces were already seeded in main.rs; bead closed as false alarm
- **mayor-0hu (merged PR #78)**: pods/status PATCH — kubelet status writes working (conditions appeared correctly during test)

Session totals: PRs #73–80 merged or open; test count 219 → 255 this session.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
