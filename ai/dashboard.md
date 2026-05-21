# Dashboard
2026-05-22 (session active — coverage drive)
`bd prime` in a fresh Claude Code session (or say "I am the Mayor now")
Open beads: 13 (12 coverage tasks + 1 investigation)

## What needs the operator now

Nothing blocking. Merge policy: auto on green CI.

**Note for next mayor:** Workers using `isolation: worktree` get a worktree created but must explicitly `cd` into it. Always include the absolute worktree path in worker prompts and tell them to `cd` there as step 0. The session CWD stays at the mayor checkout even with `isolation: worktree`.

## Wave 1 — in flight (6 background agents)

| Bead | File | Before | Worker |
|------|------|--------|--------|
| mayor-7v1m | handlers/scale.rs | 36%L/35%F | running (re-dispatched with explicit worktree cd) |
| mayor-ditd | handlers/pods.rs | 51%L/42%F | running |
| mayor-s6kt | client-util/src/lib.rs | 28%L/57%F | running |
| mayor-o813+c8w4 | keys.rs + types.rs | 55%/69%L | running (cluster) |
| mayor-y3i8 | handlers/mod.rs + serializer.rs | investigation | running (read-only) |

## Wave 2 — queued (dispatch after wave 1 PRs land)

| Bead | File | Before |
|------|------|--------|
| mayor-ykrv | handlers/authorization.rs | 73%L/60%F |
| mayor-8o8f | handlers/generic.rs | 68%L/55%F |
| mayor-5jnt | handlers/namespaces.rs | 73%L/62%F |
| mayor-yo8x | handlers/tokens.rs | 79%L/68%F |

## Wave 3 — queued (binary crate lib-extraction, structural)

| Bead | Crate | Before |
|------|-------|--------|
| mayor-dbl7 | controller-manager | 9%L/12%F |
| mayor-y70u | scheduler | 21%L/22%F |
| mayor-izua | mcp-server | 0%/0% |

## Coverage goals

- Non-main.rs: ≥70% line, ≥95% function
- main.rs: extract logic → lib.rs, test that; wiring exempt
- Baseline: 74.58% line / 67.99% fn workspace total

## Recent progress

- 2026-05-22: 13 coverage beads filed. Wave 1 (5+1 workers) dispatched.
  Testing conventions documented in `ai/prompts/rust-testing-conventions.md`.
- Previous session: PRs #128 (RBAC seeded ClusterRoleBinding) and #129 (SA token projection) merged.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
