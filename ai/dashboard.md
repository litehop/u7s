# Dashboard

2026-05-21T16:05 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**e2e retest decision** — three apiserver bugs fixed (PRs #80–82). The pod lifecycle test is ready to rerun. The remaining unknown is cri-o: `container create failed: unknown version specified` (CNI config issue in the lima VM). Options:
1. Rerun the test now to confirm apiserver fixes unblock kubelet initialization
2. Investigate the lima VM CNI config first
3. File a bead and move on to next milestone

Recommendation: rerun first, confirm the node reaches Ready, then decide on cri-o.

**Nothing else blocked on you.**

## Forward-looking

1. Pod lifecycle e2e retest → if node reaches Ready, cri-o CNI is the last gap → file bead
2. If pod reaches Succeeded: add CI smoke job (create pod, assert Succeeded within 60s)
3. mayor-xy2 (CR schema validation, P3) — deferred until Argo CD milestone

## Recent progress

Session closed out cleanly:
- **PRs #80–82 merged**: uid stamping, apply-patch+yaml acceptance, SSA upsert — kubelet CSINode + Lease init now unblocked
- **Worktree hygiene**: 5 stale worktrees + 1 orphan remote branch removed
- **Policy update**: Rule 15 added — prefer `--merge` for PRs, `--squash` only for noisy CI branches, never `--rebase`
- Test count: 255 → 260

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI with `--merge` (regular merge commit); flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
