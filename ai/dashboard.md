# Dashboard
2026-06-10T02:10Z — #506 merged; ready for VAP rerun.

## Operator attention needed
- **Rerun VAP** — five fixes now on main (#502–#506). Focus: "should type check validation expressions" and "should type check a CRD".

## Open PRs
None.

## In-flight workers
None.

## Ready beads
None — queue empty.

## Deferred
mayor-52wo (OpenAPI blob) · mayor-j7to (Argo CD RBAC) · mayor-rvkq (CRD CEL validation)

## Recent merges
- #506 fix(discovery): serve CRD groups in OpenAPI v3 paths index (mayor-urzz)
- #505 fix(admission): populate status.typeChecking on VAP write (mayor-zdpo)
- #504 fix(watch): sendInitialEvents field selector filtering (mayor-ezur)
- #503 fix(status): preserve /status patch response (mayor-k7t4)
- #502 fix(admission): VAP denial returns 422 Invalid instead of 403 (mayor-6phz)

## Worktree hygiene
Stale: mayor-k7t4, vap-typecheck-mayor-zdpo, openapi-v3-crd-mayor-urzz worktrees. Clean after confirming PRs merged.

## Main at
ec9ecc24 — fix(discovery): serve CRD groups in OpenAPI v3 paths index (#506)
