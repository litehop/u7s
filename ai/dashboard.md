# Dashboard

2026-05-20T04:55 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**ACTION REQUIRED — restart u7s and re-run sonobuoy.**

Two bugs fixed this session; u7s must be restarted to pick them up:

```sh
# Kill running process, then:
cargo run -p u7s-apiserver -- \
  --db /tmp/u7s-dev.db \
  --kubeconfig /tmp/u7s-dev.kubeconfig \
  --sa-key /tmp/u7s-sa.key \
  --sa-pub /tmp/u7s-sa.pub \
  --advertise-address https://host.lima.internal:6443

# Then re-run lima-start.sh to push fresh CA into VM:
export KUBECONFIG=/tmp/u7s-dev.kubeconfig
scripts/lima-start.sh
scripts/sonobuoy-run.sh
```

Paste sonobuoy failure output to mayor — will triage into conformance-gap beads immediately.

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **Sonobuoy triage** — operator restarts u7s → runs sonobuoy → pastes failures → mayor files conformance-gap beads → dispatch workers
2. **CA persistence** — CA is regenerated on every restart, breaking kubelet trust. Worth filing a bead to persist it like SA keys.
3. **mayor-xy2 (CR schema validation)** — deferred; re-evaluate at Argo CD milestone

## Recent progress

| Commit | What | Bead |
|--------|------|------|
| 26aae71 | feat(version): GET /version endpoint — fixes sonobuoy startup failure | mayor-mr2 |
| 8c80901 | fix(tls): kubeconfig always writes 127.0.0.1; SANs cover advertise-address | — |
| 2f339ed | fix(tls): advertise-address hostname added to server cert SANs | mayor-iko |
| b95141d | fix(lima): add conmon to cri-o install (crio crash-loop fix) | — |

110 total beads closed. 0 open PRs. Single worktree (main only). 200 tests passing.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
