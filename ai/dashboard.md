# Dashboard

2026-05-20T11:10 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2, P3, intentionally deferred)

## What needs the operator now

**Kubelet smoke CI is broken — fix just pushed, watching for green.**

Root cause: aqua's SLSA self-update verification fails in CI (`unexpected tlog entry type: expected intoto:0.0.2, got dsse:0.0.1`) — upstream aqua bug. Fix: removed the aqua steps from `kubelet-smoke.yaml` and installed kubectl 1.31 directly from the same `pkgs.k8s.io` apt repo already added for kubelet. Commit `709d730` pushed to main; CI run in progress.

**No other operator decisions pending.**

`mayor-xy2` (CR schema validation / openAPIV3Schema enforcement) intentionally deferred — permissive CR validation is safe for the Argo CD milestone.

## Forward-looking

1. **Confirm kubelet-smoke CI green** — watch run triggered by 709d730; triage if any new failure
2. **Sonobuoy conformance** — enumerate API conformance gaps systematically once kubelet CI is stable
3. **Code quality audit** — dispatch a reviewer against recent commits (proto, handlers, inflight, watch, e2e scripts)

## Recent progress

This session closed 4 beads and fixed a CI regression:

| Commit | What |
|--------|------|
| 5debd14 | aqua lockfile (kubectl v1.31.14), docs/dev-setup.md (mayor-7gz) |
| 01bbe5f | kubelet-smoke.yaml (Linux CI), lima/kubelet.yaml, scripts/lima-start.sh (mayor-hov, mayor-lf3) |
| 709d730 | fix kubelet-smoke CI: replace aqua with direct kubectl apt install |

97 total beads closed across project lifetime. No open PRs. Single worktree (main only — stale agent-a23685e5e788423b9 cleaned up this session).

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
