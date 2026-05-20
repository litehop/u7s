# Dashboard

2026-05-20T10:45 UTC
`bd prime` in a fresh Claude Code session
Open beads: 2 (mayor-adg P1, mayor-xy2 P3)

## What needs the operator now

**Review PR #73 before merge — RBAC security surface:**
- mayor-oyn: RBAC index now evicted on soft-delete (ClusterRoleBinding/RoleBinding)
- Test `rbac_index_evicted_on_soft_delete_of_clusterrolebinding` verifies alice loses access immediately on DELETE, not after finalizers clear
- CI pending; do not merge without your review

**Nothing else blocked on you.**

## In-flight

- **PR #73** — 4-bead cluster (RBAC soft-delete, json-patch add, watch 410, field-selector dedup). CI pending. **Flagged for operator review.**
- **mayor-adg (P1)** — retroactive regression tests for PRs #67-68 (sendInitialEvents annotation, strategic-merge-patch, SAN inclusion). Ready to dispatch.

## Recent progress

- Merged PRs #69 (proto varint test), #70 (TLS partial CA fix), #71 (RBAC seed metadata + key parsing).
- Policy update committed: Rule 14 — every bug fix ships with a regression test; testing policy added to worker preamble.
- Closed: mayor-oyn, mayor-ofi, mayor-iek, mayor-lyc, mayor-032, mayor-9zd, mayor-cst, mayor-1cy.
- Caught and closed PR #72 (first cluster-a attempt): worker deleted sendInitialEvents implementation. Redone directly with all 3 strings verified present (20 hits in generic.rs, 5 in pods.rs).
- 226 tests total, 10 new regression tests added in PR #73.

## Forward-looking

1. **mayor-adg** — dispatch worker to add regression tests for PRs #67-68 (sendInitialEvents BOOKMARK annotation, strategic-merge-patch, SAN inclusion).
2. **Pod lifecycle** — no remaining known kubelet blockers. Once PR #73 merged, verify pod reaches Succeeded on lima-node, then add CI smoke job.
3. **mayor-xy2** (CR schema validation, P3) — deferred until Argo CD milestone.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
