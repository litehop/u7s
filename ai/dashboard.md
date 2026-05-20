# Dashboard

2026-05-20T04:46 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**ACTION REQUIRED — restart u7s apiserver.**

TLS SAN bug is fixed (commit 2f339ed). The running process has the old cert. Kill it and restart:

```sh
cargo run -p u7s-apiserver -- \
  --db /tmp/u7s-dev.db \
  --kubeconfig /tmp/u7s-dev.kubeconfig \
  --sa-key /tmp/u7s-sa.key \
  --sa-pub /tmp/u7s-sa.pub \
  --advertise-address https://host.lima.internal:6443
```

New cert will include `host.lima.internal` as a SAN. Kubelet should register within ~30s.

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **Node registration** — once u7s restarts, verify `kubectl get nodes` shows `lima-node`
2. **Sonobuoy run** — once node registers, run `scripts/sonobuoy-run.sh` → paste failures → mayor triages into beads
3. **mayor-xy2 (CR schema validation)** — deferred; re-evaluate at Argo CD milestone

## Recent progress

| Commit/PR | What | Bead |
|-----------|------|------|
| 2f339ed | fix(tls): advertise-address hostname added to cert SANs; kubeconfig uses advertise-address as server URL | mayor-iko |
| b95141d | fix(lima): add conmon to cri-o install (crio crash-loop on fresh VM) | — |
| #59 (16774c4) | sonobuoy v0.57.3 in lima VM + sonobuoy-run.sh + docs | mayor-qah |
| #58 (d2a5b49) | storage.k8s.io/v1 + node.k8s.io/v1 discovery registration (+4 tests) | mayor-w8x |

108 total beads closed. 0 open PRs. Single worktree (main only). 199 tests passing.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
