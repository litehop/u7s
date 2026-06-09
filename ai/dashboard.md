# Dashboard
2026-06-10T16:10Z — #503 and #504 in CI; sendInitialEvents hang root cause confirmed and fixed.

## Operator attention needed
- **#503 in CI** — fix(status): PATCH /status no longer overwritten by write_vap_status. Merge once green.
- **#504 in CI** — fix(watch): sendInitialEvents initial snapshot now filtered by field/label selector. Root cause of VAP BeforeEach hang. Merge once green.

## Open PRs
- #503 fix(status): preserve /status patch response (mayor-k7t4) — CI in progress
- #504 fix(watch): sendInitialEvents field selector filtering (mayor-ezur) — CI in progress

## In-flight workers
None.

## Ready beads
None — queue empty.

## Deferred
mayor-52wo (OpenAPI blob) · mayor-j7to (Argo CD RBAC) · mayor-rvkq (CRD CEL validation)

## Recent merges
- #502 fix(admission): VAP denial returns 422 Invalid instead of 403 (mayor-6phz)
- #501 test(admission): store round-trip regression for VAP spec.replicas (mayor-tj0j)
- #500 fix(namespace): delete namespace-scoped CRDs on namespace deletion (mayor-k0tn)
- #499 chore(deps): uuid v1.23.3
- #498 fix(auth): sa.key in PKCS#1 PEM for KCM (mayor-at5v)
- #497 fix(admission): write_vap_status on PATCH /status (mayor-r381)

## Worktree hygiene
Stale: mayor-k7t4 worktree (PR #503 submitted). Clean after merge.

## Main at
2b2d412 — fix(admission): VAP denial returns 422 Invalid instead of 403 Forbidden (#502)
