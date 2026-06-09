# Dashboard
2026-06-10T16:20Z — #503 and #504 merged; queue empty; ready for VAP rerun.

## Operator attention needed
- **Rerun VAP** — three fixes now on main (#502, #503, #504). Run sonobuoy to verify hang is resolved.

## Open PRs
None.

## In-flight workers
None.

## Ready beads
None — queue empty.

## Deferred
mayor-52wo (OpenAPI blob) · mayor-j7to (Argo CD RBAC) · mayor-rvkq (CRD CEL validation)

## Recent merges
- #504 fix(watch): sendInitialEvents field selector filtering (mayor-ezur)
- #503 fix(status): preserve /status patch response (mayor-k7t4)
- #502 fix(admission): VAP denial returns 422 Invalid instead of 403 (mayor-6phz)
- #501 test(admission): store round-trip regression for VAP spec.replicas (mayor-tj0j)
- #500 fix(namespace): delete namespace-scoped CRDs on namespace deletion (mayor-k0tn)
- #499 chore(deps): uuid v1.23.3

## Worktree hygiene
Stale: mayor-k7t4 worktree. Clean after confirming PR merged.

## Main at
a46ef78 — fix(watch): apply field/label selector to sendInitialEvents snapshot (#504)
