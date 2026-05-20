# Dashboard

2026-05-20T15:15 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**HOLD — backlog empty, CI green, no open PRs, no worktrees.**

Sonobuoy infrastructure is ready. Run it whenever you're ready to enumerate conformance gaps:
```sh
export KUBECONFIG=...
scripts/lima-start.sh       # start lima VM + kubelet (if not running)
scripts/sonobuoy-run.sh     # ~5–15 min; use --focus for targeted runs
```
Mayor will triage results into beads and dispatch workers.

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **Run sonobuoy** (operator-driven) → triage failures → new beads → dispatch workers
2. **mayor-xy2 (CR schema validation)** — deferred; re-evaluate at Argo CD milestone
3. **Kubelet implementation** — longer-term; awaiting operator direction

## Recent progress

| PR | What | Beads |
|----|------|-------|
| #59 (16774c4) | sonobuoy v0.57.3 in lima VM + sonobuoy-run.sh + docs | mayor-qah |
| #58 (d2a5b49) | storage.k8s.io/v1 + node.k8s.io/v1 discovery registration (+4 tests) | mayor-w8x |
| #56 (e45a703) | fieldSelector wiring + list pagination (+16 tests) | mayor-yx5, mayor-ynx |
| #57 (dd531fa) | merge_patch dedup, proto dedup, HEAD verb, rbac cleanup (−114 lines) | mayor-4r7, mayor-67m, mayor-abq, mayor-59u |

107 total beads closed across project lifetime. 0 open PRs. Single worktree (main only). All CI green.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
