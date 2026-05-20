# Dashboard

2026-05-20T15:30 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**ACTION REQUIRED — sonobuoy run.**

To enumerate conformance gaps, start u7s and kick off sonobuoy:

```sh
# Terminal 1 — start u7s apiserver
cargo run -p u7s-apiserver -- \
  --db /tmp/u7s-dev.db \
  --kubeconfig /tmp/u7s-dev.kubeconfig \
  --sa-key /tmp/u7s-sa.key \
  --sa-pub /tmp/u7s-sa.pub \
  --advertise-address https://host.lima.internal:6443

# Terminal 2 — run sonobuoy (~5–15 min)
export KUBECONFIG=/tmp/u7s-dev.kubeconfig
scripts/lima-start.sh
scripts/sonobuoy-run.sh
```

Paste the failure output to mayor. Mayor will triage into beads and dispatch workers immediately.

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **Sonobuoy triage** — operator runs sonobuoy → paste failures → mayor files conformance-gap beads → dispatch workers
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
