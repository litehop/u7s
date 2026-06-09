# Dashboard
2026-06-09T14:02Z — queue empty; all known VAP fixes landed; ready for next run.

## Operator attention needed
- **Next action: run VAP focus** — all 5 fixes merged (#496–#501). Run to verify spec.replicas×2, PATCH /status, SA token all pass cleanly.
- **SA token race** — KCM may not issue token within ~2s of pod start. If it still fails after clean run, file a bead to investigate token issuance latency.

## Open PRs
None.

## In-flight workers
None.

## Ready beads
None — queue empty.

## Deferred
mayor-52wo (OpenAPI blob) · mayor-j7to (Argo CD RBAC) · mayor-rvkq (CRD CEL validation)

## Recent merges
- #501 test(admission): store round-trip regression for VAP spec.replicas (mayor-tj0j)
- #500 fix(namespace): delete namespace-scoped CRDs on namespace deletion (mayor-k0tn)
- #499 chore(deps): uuid v1.23.3
- #498 fix(auth): sa.key in PKCS#1 PEM for KCM (mayor-at5v)
- #497 fix(admission): write_vap_status on PATCH /status (mayor-r381)
- #496 fix(admission): preserve spec.replicas in proto decoders (mayor-fmqw)

## Worktree hygiene
Clean — no active worktrees.

## Main at
c546d8f — test(admission): store round-trip regression for VAP spec.replicas (#501)
