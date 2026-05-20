# Dashboard

2026-05-20T13:04 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**Review PR #73 — RBAC security surface (CI green, awaiting your approval):**
- RBAC index evicted immediately on soft-delete (ClusterRoleBinding/RoleBinding) — `rbac_index_evicted_on_soft_delete_of_clusterrolebinding` test verifies alice loses access on DELETE, not after finalizers drain
- Also includes: json-patch `add` on missing path, watch 410 uses compaction horizon, field-selector dedup
- 226 tests, all green. **Do not merge without your review.**

**PR #74 — regression tests only, CI green:**
- `accepts_patch_content_type()` and `build_server_sans()` extracted as pure functions with unit tests
- Tests fail if strategic-merge-patch fix or `host.lima.internal` SAN hardcoding is reverted
- No logic changes. Safe to merge; review optional.

## Forward-looking

1. Merge PR #73 (operator review) + PR #74 (CI green / optional review)
2. Once merged: verify pod reaches Succeeded on lima-node, add CI smoke job
3. **mayor-xy2** (CR schema validation, P3) — deferred until Argo CD milestone; only open bead

## Recent progress

- All P1/P2 beads closed: mayor-oyn, mayor-ofi, mayor-iek, mayor-lyc, mayor-adg
- Merged: PRs #69-71 (proto varint test, TLS partial CA, RBAC seed + key parsing)
- Rule 14 (regression tests for every bug fix) codified in CLAUDE.md and worker preamble
- 226 tests in PR #73 branch; 219 in PR #74 branch (10 + 4 new regression tests this sprint)

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
