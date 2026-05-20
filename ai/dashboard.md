# Dashboard

2026-05-20T14:00 UTC
`bd prime` in a fresh Claude Code session
Open beads: 3 (mayor-w8x P2 in_progress, mayor-qah P2 blocked on w8x, mayor-xy2 P3 deferred)

## What needs the operator now

**Worker running** — mayor-w8x (storage/node discovery stubs) dispatched to background worker. Will open a PR; review and merge when CI green.

`mayor-xy2` (CR schema validation / openAPIV3Schema enforcement) remains intentionally deferred — permissive validation is safe for the Argo CD milestone.

**Kubelet implementation** — operator raised; recommendation is to close API conformance gaps first. No bead filed, awaiting direction.

## Forward-looking

1. **mayor-w8x** — worker building storage.k8s.io/v1 + node.k8s.io/v1 discovery stubs; merge when green
2. **mayor-qah (Sonobuoy conformance run)** — blocked on w8x landing; once merged, dispatch a worker to run sonobuoy against local u7s and triage failures into beads
3. **mayor-xy2 (CR schema validation)** — deferred; re-evaluate at Argo CD milestone
4. **Kubelet implementation** — longer-term; awaiting operator direction

## Recent progress

Operator activated two new initiatives (storage/node stubs + sonobuoy). Beads filed: mayor-w8x (P2), mayor-qah (P2, blocked on w8x). Worker dispatched for w8x.

Prior session closed 11 beads and merged 2 PRs:

| PR | What | Beads |
|----|------|-------|
| #56 (e45a703) | fieldSelector wired to store + list pagination (+16 tests) | mayor-yx5, mayor-ynx |
| #57 (dd531fa) | merge_patch dedup, proto dedup, HEAD verb, rbac cleanup (−114 lines) | mayor-4r7, mayor-67m, mayor-abq, mayor-59u |

Also fixed 5 kubelet-smoke CI regressions; 3-version matrix (1.34.8/1.35.5/1.36.1, cri-o+crun) green.

105 total beads closed across project lifetime. 0 open PRs. Single worktree (main only). CI green.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
