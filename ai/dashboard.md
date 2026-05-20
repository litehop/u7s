# Dashboard

2026-05-20T13:03 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**Review PR #73 before merge — RBAC security surface:**
- mayor-oyn: RBAC index now evicted on soft-delete (ClusterRoleBinding/RoleBinding)
- Test `rbac_index_evicted_on_soft_delete_of_clusterrolebinding` verifies alice loses access immediately on DELETE, not after finalizers clear
- CI pending; do not merge without your review

**Review PR #74 before merge — regression tests only (no logic changes):**
- mayor-adg: adds `accepts_patch_content_type()` and `build_server_sans()` pure functions with unit tests
- Tests fail if strategic-merge-patch fix or host.lima.internal SAN hardcoding is reverted
- 219 tests passing, clippy clean — lower risk, but review if you wish before merge

**Nothing else blocked on you.**

## In-flight

- **PR #73** — 4-bead cluster (RBAC soft-delete, json-patch add, watch 410, field-selector dedup). CI pending. **Flagged for operator review.**
- **PR #74** — regression tests for PRs #67-68 fixes. 219 tests. CI pending. Operator review optional.

## Recent progress

- Closed mayor-adg: PR #74 open with 4 new regression tests (accepts_patch_content_type, build_server_sans x2; sendInitialEvents already had test).
- Merged PRs #69 (proto varint test), #70 (TLS partial CA fix), #71 (RBAC seed metadata + key parsing).
- Policy update committed: Rule 14 — every bug fix ships with a regression test; testing policy added to worker preamble.
- 226 tests total in PR #73 branch, 219 in PR #74 branch (PR #74 is based on main at 472ade0).

## Forward-looking

1. **PR #73** — merge after operator review (RBAC security surface)
2. **PR #74** — merge after CI green (or operator review if desired)
3. **Pod lifecycle** — once both PRs merged, verify pod reaches Succeeded on lima-node, add CI smoke job
4. **mayor-xy2** (CR schema validation, P3) — deferred until Argo CD milestone

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
