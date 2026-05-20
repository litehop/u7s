# Dashboard

2026-05-20T13:42 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**Decision: pods/status subresource** — kubelet cannot report pod phase without it. Fix is ~100-150 LoC in pods.rs (add PATCH route for status, merge only .status field, emit watch event). Ready to file bead and dispatch on your go-ahead.

**Decision: stance check** — current stance: pre-alpha/greenfield, break freely, merge on green CI, security/API/arch PRs need operator review. Confirm still correct, or adjust milestone focus (pod lifecycle? Argo CD? sonobuoy conformance?).

## Forward-looking

1. pods/status fix → enables hello-world pod reaching Succeeded on lima-node
2. CI smoke job → create pod, assert Succeeded within 60s
3. mayor-xy2 (CR schema validation, P3) — deferred until Argo CD milestone

## Recent progress

Quality sprint complete. 5 PRs merged today (#73–77):
- RBAC soft-delete index fix, json-patch `add`, watch 410, field-selector dedup
- Regression tests for strategic-merge-patch, SAN inclusion, RBAC edge cases
- 7 `serde_json::to_vec().unwrap()` panics fixed in CR/CRD handlers
- `parse_resource_version` deduplicated across 5 files
- Test count: ~170 → 224+ this sprint

Repo clean: 0 open PRs, 0 worktrees, 0 remote worker branches.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
