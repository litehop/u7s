# Dashboard

2026-05-20T09:15 UTC
`bd prime` in a fresh Claude Code session
Open beads: 5 (cluster-a worker in-flight)

## What needs the operator now

**Review before merge — PR #72 (cluster-a-generic, RBAC security surface):** When the cluster-a worker finishes, its PR touches the RBAC index (soft-delete security gap, mayor-oyn P1). Flag for your review before merging per merge policy.

**Nothing else blocked on you.** PRs #69–71 merge automatically on green CI.

## In-flight

- **worker/cluster-a-generic** — mayor-oyn (P1 RBAC soft-delete), mayor-ofi (json-patch add), mayor-iek (watch 410 rv), mayor-lyc (field-selector dedup). Still running, no PR yet.
- **PR #69** — proto varint test (mayor-1cy). CI pending. Merges on green.
- **PR #70** — TLS partial CA fix (mayor-cst). CI pending. Merges on green.
- **PR #71** — RBAC seed metadata + key parsing (mayor-032/9zd). CI pending. Merges on green.

## Recent progress (this session)

- Merged PR #67: kubelet compat — TLS SAN, sendInitialEvents BOOKMARK, strategic-merge-patch, RBAC subresources.
- Merged PR #68: CSINode watch BOOKMARK test + RuntimeClass stub (runtimeclasses in registry → 200 instead of 404).
- Filed 8 review beads (code quality audit), dispatched 4 workers to resolve them.
- Closed: mayor-032, mayor-9zd, mayor-cst, mayor-1cy, mayor-c5i, mayor-9jc.
- Worktree hygiene: agent-a7fad47c5a89d7887 removed, origin pruned.

## Forward-looking

1. **Pod lifecycle** — once cluster-a lands, no known remaining kubelet blockers. Next: verify pod reaches Succeeded on lima-node, then add CI smoke job to `.github/workflows/smoke.yaml`.
2. **Sonobuoy** — after pod lifecycle end-to-end.
3. **mayor-xy2** (CR schema validation, P3) — deferred until Argo CD milestone.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
