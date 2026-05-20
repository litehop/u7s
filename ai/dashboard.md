# Dashboard

2026-05-20T05:04 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**ACTION REQUIRED — restart u7s and re-run sonobuoy.**

Three fixes landed this session. Restart u7s to pick them all up:

```sh
# Kill running process, then:
cargo run -p u7s-apiserver -- \
  --db /tmp/u7s-dev.db \
  --kubeconfig /tmp/u7s-dev.kubeconfig \
  --sa-key /tmp/u7s-sa.key \
  --sa-pub /tmp/u7s-sa.pub \
  --advertise-address https://host.lima.internal:6443

# Then refresh CA in VM and run sonobuoy:
export KUBECONFIG=/tmp/u7s-dev.kubeconfig
scripts/lima-start.sh
scripts/sonobuoy-run.sh
```

Paste sonobuoy failure output to mayor — will triage into conformance-gap beads immediately.

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **Sonobuoy triage** — operator restarts u7s → runs sonobuoy → pastes failures → mayor files conformance-gap beads → dispatch workers
2. **CA persistence** — CA regenerates on every restart, breaking kubelet trust; P2 candidate
3. **mayor-xy2** — deferred; re-evaluate at Argo CD milestone

## Recent progress

| PR | What | Bead |
|----|------|------|
| #60 (075fa8f) | feat(bootstrap): seed default + kube-system namespaces on startup | mayor-0hc |
| 26aae71 | feat(version): GET /version — fixes sonobuoy "couldn't retrieve server version" | mayor-mr2 |
| 2f339ed + 8c80901 | fix(tls): advertise-address SAN + kubeconfig server URL | mayor-iko |
| b95141d | fix(lima): conmon in cri-o install | — |

111 total beads closed. 0 open PRs. Single worktree (main only). 202 tests passing.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
