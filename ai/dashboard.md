# Dashboard

2026-05-20T13:56 UTC
`bd prime` in a fresh Claude Code session
Open beads: 3 (mayor-eet P2, mayor-br6 P2, mayor-xy2 P3 deferred)

## What needs the operator now

**Nothing blocked on you.**

In-flight: worker/cluster-net dispatched for mayor-eet (IngressClass registration) + mayor-br6 (CR status subresource / Gateway API CRD path). CI pending on the PR when it lands.

## Forward-looking

1. **cluster-net PR** — IngressClass one-liner + CR status subresource test (Gateway API sanity check)
2. **Pod lifecycle e2e** — pods/status fix landed (PR #78, 250 tests). Next: manual test on lima-node, then add CI smoke job
3. **mayor-xy2** (CR schema validation, P3) — deferred until Argo CD milestone

## Recent progress

- **PR #78 merged** — `PATCH /api/v1/namespaces/{ns}/pods/{name}/status` implemented; `apply_status_patch()` extracted with 4 unit tests; 250 tests total (up from 224)
- Quality sprint complete: PRs #73-77 merged (RBAC fix, regression tests, CR panic fixes, patch edge cases, parse_resource_version dedup)
- Networking audit: Ingress status already works; IngressClass missing (mayor-eet); Gateway API CRDs need status subresource test (mayor-br6)
- Repo clean: 0 open PRs (cluster-net in flight), 1 active worktree

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
