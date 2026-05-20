# Dashboard

2026-05-20T04:45 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**ACTION REQUIRED — restart u7s and retry kubelet registration.**

The TLS SAN bug is fixed (commit 2f339ed). Kill the running apiserver and restart with `RUST_LOG=info` so the new cert is generated:

```sh
# Kill the old process (no --advertise-address SAN), restart with logging
cargo run -p u7s-apiserver -- \
  --db /tmp/u7s-dev.db \
  --kubeconfig /tmp/u7s-dev.kubeconfig \
  --sa-key /tmp/u7s-sa.key \
  --sa-pub /tmp/u7s-sa.pub \
  --advertise-address https://host.lima.internal:6443
```

Then in the lima VM:
```sh
export KUBECONFIG=/tmp/u7s-dev.kubeconfig
scripts/lima-start.sh   # if kubelet isn't running
scripts/sonobuoy-run.sh
```

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **Sonobuoy triage** — operator restarts u7s → node registers → run sonobuoy → paste failures → mayor files conformance-gap beads
2. **mayor-xy2 (CR schema validation)** — deferred; re-evaluate at Argo CD milestone
3. **Kubelet implementation** — longer-term; awaiting operator direction

## Recent progress

| PR | What | Beads |
|----|------|-------|
| 2f339ed | fix(tls): advertise-address hostname added to cert SANs + kubeconfig server URL | mayor-iko |
| b95141d | fix(lima): add conmon to cri-o install (crio crash-loop fix) | — |
| #59 (16774c4) | sonobuoy v0.57.3 in lima VM + sonobuoy-run.sh + docs | mayor-qah |
| #58 (d2a5b49) | storage.k8s.io/v1 + node.k8s.io/v1 discovery registration (+4 tests) | mayor-w8x |

108 total beads closed across project lifetime. 0 open PRs. Single worktree (main only). 199 tests passing.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
