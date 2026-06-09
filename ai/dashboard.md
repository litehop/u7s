# Dashboard
2026-06-09T08:25Z — Dispatch paused: documenting manual VM verification steps before dispatch.

## Operator attention needed
- **Dispatch template gap** — Lima VM protocol block describes `run-all.sh` only; workers
  cannot run scripts directly (not in allowlist). Manual step-by-step equivalent needed
  for steps 3 (lima-start) and 5 (sonobuoy + result retrieval) before dispatching
  mayor-fmqw and mayor-2lot. Mayor asked operator: write the section?

## Open PRs
None.

## In-flight workers
None. Two worktrees pre-created, workers not yet dispatched:
- `ai/worktrees/cel-replicas-mayor-fmqw` — branch `worker/cel-replicas-mayor-fmqw`
- `ai/worktrees/vap-400-mayor-2lot` — branch `worker/vap-400-mayor-2lot`

## Recent merges (this session)
- #494 fix(admission): set VAP/VAPB status.observedGeneration on write (mayor-xw6c)
- 7aa3ccd fix(scripts): guard empty TARGET_DIR_ARGS bash 3.2 array (direct push)
- #493 fix(discovery): return 406 for proto-only Accept on /openapi/v2 (mayor-bp6k)
- #492 fix(admission): thread authenticated UserInfo into AdmissionContext (mayor-bgpu)
- #491 fix(admission): request.userInfo support in VAP CEL evaluator (mayor-gfpm)
- #490 fix(apiserver): JSON Status 404 fallback for unmatched routes (mayor-upqy)

## Bead queue
- mayor-fmqw — VAP marker denied by own policy / replicas CEL eval (P2) — worktree ready
- mayor-2lot — VAP/VAPB create returns 400 invalid JSON (P2) — worktree ready
- Deferred: mayor-52wo · mayor-j7to · mayor-rvkq

## Worktree hygiene
Two pre-created worktrees. No dispatched workers.

## Main at
9611f16 — fix(admission): set VAP/VAPB status.observedGeneration on write (#494)
