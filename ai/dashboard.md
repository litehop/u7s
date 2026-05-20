# Dashboard

2026-05-20T05:22 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**WAITING — lima MCP wiring in progress.**

Once `.claude/settings.json` is saved with the lima MCP config and Claude Code reloads it, mayor can drive sonobuoy autonomously. Keep u7s running on the host — do not stop it.

If restarting u7s to pick up latest commits (namespace seeding + /version), use:

```sh
cargo run -p u7s-apiserver -- \
  --db /tmp/u7s-dev.db \
  --kubeconfig /tmp/u7s-dev.kubeconfig \
  --sa-key /tmp/u7s-sa.key \
  --sa-pub /tmp/u7s-sa.pub \
  --advertise-address https://host.lima.internal:6443
```

Then re-run `scripts/lima-start.sh` to push fresh CA into VM before sonobuoy.

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **lima MCP** — once active, mayor runs sonobuoy autonomously and triages failures into beads
2. **Sonobuoy aggregator pod** — needs kubelet picking up the pod via crio; kubelet/crio runtime regression to diagnose
3. **CA persistence** — CA regenerates on every u7s restart, breaking kubelet trust; P2 bead candidate
4. **Sonobuoy triage** — failures → conformance-gap beads → worker dispatch
5. **mayor-xy2** — deferred; re-evaluate at Argo CD milestone

## Recent progress

| Commit/PR | What | Bead |
|-----------|------|------|
| 553bb2b | fix(sonobuoy): --skip-preflight=dnscheck | — |
| #60 (075fa8f) | feat(bootstrap): seed default + kube-system namespaces on startup | mayor-0hc |
| 26aae71 | feat(version): GET /version — fixes sonobuoy server version check | mayor-mr2 |
| 2f339ed + 8c80901 | fix(tls): advertise-address SAN + kubeconfig server URL | mayor-iko |
| b95141d | fix(lima): conmon added to cri-o install | — |

111 total beads closed. 0 open PRs. Single worktree (main only). 202 tests passing.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
