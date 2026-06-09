# Dashboard
2026-06-09T09:10Z — Two PRs in CI. Queue empty pending merge.

## Operator attention needed
- **#495 and #496 CI** — all checks null (queued). Merge loop will fire when green.

## Open PRs
- **#495** fix(admission): VAP/VAPB proto decode (mayor-2lot) — 17 checks queued
- **#496** fix(admission): proto replicas field + CEL eval (mayor-fmqw) — 8 checks queued

## In-flight workers
None (both completed, PRs open).

## Active worktrees
- `ai/worktrees/vap-400-mayor-2lot` — branch `worker/vap-400-mayor-2lot` (awaiting merge)
- `ai/worktrees/cel-replicas-mayor-fmqw` — branch `worker/cel-replicas-mayor-fmqw` (awaiting merge)

## Recent merges (this session)
- #494 fix(admission): set VAP/VAPB status.observedGeneration on write (mayor-xw6c)
- 7aa3ccd fix(scripts): guard empty TARGET_DIR_ARGS bash 3.2 array (direct push)
- #493 fix(discovery): return 406 for proto-only Accept on /openapi/v2 (mayor-bp6k)
- #492 fix(admission): thread authenticated UserInfo into AdmissionContext (mayor-bgpu)
- #491 fix(admission): request.userInfo support in VAP CEL evaluator (mayor-gfpm)
- #490 fix(apiserver): JSON Status 404 fallback for unmatched routes (mayor-upqy)

## Bead queue
Ready: none (queue drained).
Deferred: mayor-52wo · mayor-j7to · mayor-rvkq

## Worktree hygiene
Two active worktrees (pending PR merge). All else clean.

## Main at
c92c55c — docs(prompts): add vm-operations.md manual stack guide for workers
