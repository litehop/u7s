# Dashboard

2026-05-20T11:30 UTC
`bd prime` in a fresh Claude Code session
Open beads: 2 (mayor-xy2 P3 deferred; mayor-cd2 P3 in_progress)

## What needs the operator now

**Watch CI on 44897f5** — kubelet-smoke now runs 3 matrix legs (1.34.8 / 1.35.5 / 1.36.1) with cri-o+crun. First run in progress; triage if any leg fails.

**No other operator decisions pending.**

`mayor-xy2` (CR schema validation / openAPIV3Schema enforcement) intentionally deferred — permissive CR validation is safe for the Argo CD milestone.

## Forward-looking

1. **Triage kubelet-smoke matrix CI** — watch 44897f5 run; fix any per-version failure
2. **Code quality review results** (mayor-cd2) — reviewer agent running in background; will produce findings as follow-up beads
3. **Sonobuoy conformance** — enumerate API conformance gaps once kubelet CI is stable

## Recent progress

This session closed 4 beads (2 this batch):

| Commit | What | Beads |
|--------|------|-------|
| 5debd14 | aqua lockfile (kubectl v1.31.14), docs/dev-setup.md | mayor-7gz |
| 01bbe5f | kubelet-smoke.yaml (Linux CI), lima/kubelet.yaml, scripts/lima-start.sh | mayor-hov, mayor-lf3 |
| e4cc3fb + 44897f5 | cri-o+crun, 3-version matrix (1.34/1.35/1.36), fix gpg --batch, crun drop-in | mayor-p19, mayor-pua |

Also: fixed two CI regressions (aqua SLSA bug → kubectl via apt; gpg --tty → --batch).

99 total beads closed across project lifetime. No open PRs. Single worktree (main only).

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
