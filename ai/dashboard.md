# Dashboard

2026-05-20T13:41 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**Stance check** — current stance is: pre-alpha/greenfield, break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI automatically; flag security/API/architecture PRs for operator review first. Confirm this is still correct or adjust.

**pods/status subresource** — kubelet cannot report pod phase (PATCHes `pods/{name}/status`) without this. Blocking pod lifecycle e2e. Ready to file a bead and dispatch if you want to move on it.

**Nothing else blocked on you.**

## Forward-looking

1. **pods/status subresource fix** — file bead, dispatch worker; unblocks hello-world pod reaching Succeeded on lima-node
2. **CI smoke job** — once pods/status works, add a job that creates a pod, waits for Succeeded, fails CI if not reached within 60s
3. **mayor-xy2** (CR schema validation, P3) — deferred until Argo CD milestone

## Recent progress

Major quality sprint closed. All merged today:
- **PR #73** — RBAC soft-delete index fix + json-patch add + watch 410 + field-selector dedup (operator-reviewed)
- **PR #74** — regression tests for strategic-merge-patch and host.lima.internal SAN
- **PR #75** — RBAC edge-case tests: namespace mismatch, resourceNames, ClusterRoleBinding scope
- **PR #76** — patch.rs strategic-merge edge-case tests + parse_resource_version deduplication
- **PR #77** — CR/CRD panic fixes (7 `.unwrap()` → proper 500 returns) + pure-function extraction + discovery tests

Test count grew from 219 → 224+ across this sprint. Worktrees and remote branches fully pruned; repo clean.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
