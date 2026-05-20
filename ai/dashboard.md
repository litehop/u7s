# Dashboard

2026-05-20T14:30 UTC
`bd prime` in a fresh Claude Code session
Open beads: 2 (mayor-qah P2 needs operator, mayor-xy2 P3 deferred)

## What needs the operator now

**HOLD — no dispatchable candidates.**

`mayor-qah` (Sonobuoy conformance run) is unblocked but requires operator action: sonobuoy needs a live u7s + registered kubelet node to run against. Options:
  1. Run locally: `cargo build --release`, start u7s, start kubelet via lima, then `sonobuoy run --mode=quick` against it
  2. Or: say the word and mayor will build a CI workflow for it (adds a long-running CI job ~30–60 min)

`mayor-xy2` (CR schema validation) remains intentionally deferred.

## Forward-looking

1. **mayor-qah (Sonobuoy)** — operator decides: run locally or build CI workflow; mayor will triage results into new beads
2. **mayor-xy2 (CR schema validation)** — deferred; re-evaluate at Argo CD milestone
3. **Kubelet implementation** — longer-term; awaiting operator direction

## Recent progress

PR #58 (d2a5b49) merged green — `storage.k8s.io/v1` and `node.k8s.io/v1` registered in discovery (csidrivers, csinodes, storageclasses, volumeattachments, runtimeclasses). Closes mayor-w8x.

| PR | What | Beads |
|----|------|-------|
| #58 (d2a5b49) | storage.k8s.io/v1 + node.k8s.io/v1 discovery registration (+4 tests) | mayor-w8x |
| #56 (e45a703) | fieldSelector wiring + list pagination (+16 tests) | mayor-yx5, mayor-ynx |
| #57 (dd531fa) | merge_patch dedup, proto dedup, HEAD verb, rbac cleanup (−114 lines) | mayor-4r7, mayor-67m, mayor-abq, mayor-59u |

106 total beads closed across project lifetime. 0 open PRs. Single worktree (main only). All CI green.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
