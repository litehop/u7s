# Dashboard

2026-05-20T12:00 UTC
`bd prime` in a fresh Claude Code session
Open beads: 6 (mayor-xy2 P3 deferred; mayor-4r7, mayor-67m, mayor-abq, mayor-59u P3 code quality; mayor-p19/mayor-pua closed)

## What needs the operator now

**kubelet-smoke CI in progress (run 26137189337)** — fixing two failures found in the matrix:
1. `apt` rejects downgrade for 1.34/1.35 (runner has newer kubectl) — fixed with `--allow-downgrades`
2. kubelet 1.36 removed `--node-name` CLI flag — migrated all flags to `KubeletConfiguration` file

Watch for green. If another failure, mayor will triage.

**No operator decisions pending.** All 4 code quality beads (mayor-4r7, mayor-67m, mayor-abq, mayor-59u) are P3 backlog — no urgency.

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **Confirm kubelet-smoke matrix green** — run 26137189337 in progress
2. **Code quality P3 backlog** — 4 beads ready: merge_patch dedup, proto ObjectMeta dedup, method_to_verb HEAD, rbac dead_code cleanup
3. **Sonobuoy conformance** — enumerate API conformance gaps once kubelet CI is stable

## Recent progress

This session closed 6 beads:

| Commit | What | Beads |
|--------|------|-------|
| 5debd14 | aqua lockfile (kubectl v1.31.14), docs/dev-setup.md | mayor-7gz |
| 01bbe5f | kubelet-smoke.yaml (Linux CI), lima/kubelet.yaml, scripts/lima-start.sh | mayor-hov, mayor-lf3 |
| e4cc3fb+44897f5 | cri-o+crun, 3-version matrix, gpg --batch, crun drop-in | mayor-p19, mayor-pua |
| mayor-cd2 | Code quality audit complete, 4 follow-up beads filed | mayor-cd2 |

Also fixed 4 CI regressions in sequence: aqua SLSA, gpg /dev/tty, apt downgrade, --node-name removal.

99 total beads closed. No open PRs. Single worktree (main only).

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
