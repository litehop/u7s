# Dashboard

2026-05-20T05:02 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred) + PR #60 in CI

## What needs the operator now

**WAITING — PR #60 in CI, then restart u7s and re-run sonobuoy.**

Once #60 merges, restart u7s (to pick up /version + namespace seeding) then re-run:

```sh
export KUBECONFIG=/tmp/u7s-dev.kubeconfig
scripts/lima-start.sh   # refreshes CA in VM
scripts/sonobuoy-run.sh
```

Paste sonobuoy failure output to mayor — will triage into conformance-gap beads immediately.

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **Merge PR #60** (CI pending) — namespace seeding fixes sonobuoy preflight
2. **Sonobuoy triage** — operator runs sonobuoy → pastes failures → mayor files conformance-gap beads → dispatch workers
3. **CA persistence** — CA regenerates on every restart, breaking kubelet trust; worth a P2 bead
4. **mayor-xy2** — deferred; re-evaluate at Argo CD milestone

## Recent progress

| Commit/PR | What | Bead |
|-----------|------|------|
| PR #60 (CI) | feat(bootstrap): seed default + kube-system namespaces on startup | mayor-0hc |
| 26aae71 | feat(version): GET /version — fixes sonobuoy "couldn't retrieve server version" | mayor-mr2 |
| 8c80901 | fix(tls): kubeconfig writes 127.0.0.1; SANs cover advertise-address | — |
| 2f339ed | fix(tls): advertise-address hostname added to server cert SANs | mayor-iko |
| b95141d | fix(lima): conmon added to cri-o install (crio crash-loop fix) | — |

110 total beads closed. 1 PR in CI. 202 tests passing.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
