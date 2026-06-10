# Dashboard
2026-06-10T01:40Z — #505 merged; ready for VAP rerun.

## Operator attention needed
- **Rerun VAP** — four fixes now on main (#502, #503, #504, #505). Focus: "should type check validation expressions" and "should type check a CRD".

## Open PRs
None.

## In-flight workers
None.

## Ready beads
None — queue empty.

## Deferred
mayor-52wo (OpenAPI blob) · mayor-j7to (Argo CD RBAC) · mayor-rvkq (CRD CEL validation)

## Recent merges
- #505 fix(admission): populate status.typeChecking on VAP write (mayor-zdpo)
- #504 fix(watch): sendInitialEvents field selector filtering (mayor-ezur)
- #503 fix(status): preserve /status patch response (mayor-k7t4)
- #502 fix(admission): VAP denial returns 422 Invalid instead of 403 (mayor-6phz)
- #501 test(admission): store round-trip regression for VAP spec.replicas (mayor-tj0j)
- #500 fix(namespace): delete namespace-scoped CRDs on namespace deletion (mayor-k0tn)

## Worktree hygiene
Stale: mayor-k7t4, vap-typecheck-mayor-zdpo worktrees. Clean after confirming PRs merged.

## Main at
58d9eff2 — fix(admission): populate status.typeChecking on VAP write (#505)
