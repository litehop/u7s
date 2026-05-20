# Dashboard

2026-05-20T13:00 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2, P3, intentionally deferred)

## What needs the operator now

**Backlog is empty.** No decisions pending, no blockers.

`mayor-xy2` (CR schema validation / openAPIV3Schema enforcement) intentionally deferred.

**Roadmap question raised** — see Forward-looking.

## Forward-looking

Backlog drained this session. Next initiative candidates (operator input welcome):

1. **kubelet implementation** — operator raised this; see roadmap discussion below
2. **Sonobuoy conformance** — enumerate remaining API gaps systematically; fieldSelector + pagination now landed which unblocks more conformance tests
3. **More code quality passes** — reviewer identified patterns to continue (e.g. watch-path refactor, handler error type unification)
4. **mayor-xy2 (CR schema validation)** — deferred; re-evaluate when Argo CD milestone closer

## Recent progress

This session closed 11 beads and merged 2 PRs, all on green CI:

| PR | What | Beads |
|----|------|-------|
| #56 (e45a703) | fieldSelector wired to store + list pagination with limit/continue cursor tokens (+16 tests) | mayor-yx5, mayor-ynx |
| #57 (dd531fa) | merge_patch dedup (4→1), proto ObjectMeta dedup (3→1), HEAD verb mapping, rbac dead_code cleanup (−114 lines net) | mayor-4r7, mayor-67m, mayor-abq, mayor-59u |

Also: kubelet-smoke matrix finally green — all three legs (1.34.8, 1.35.5, 1.36.1) pass with cri-o+crun. Fixed 5 successive CI regressions to get there (aqua SLSA, gpg --batch, apt downgrade, --node-name removal, nodeName-in-KubeletConfiguration).

107 total beads closed across project lifetime. 0 open PRs. Single worktree (main only). CI fully green.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
