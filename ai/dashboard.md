# Dashboard

2026-05-20T05:16 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**TWO ACTIONS — lima MCP config + kubelet runtime fix.**

### 1. Add lima MCP to Claude Code settings

Add to `.claude/settings.json` (or `~/.claude.json` for global):

```json
{
  "mcpServers": {
    "lima-node": {
      "command": "limactl",
      "args": ["mcp", "serve", "lima-node"]
    }
  }
}
```

This lets mayor/workers run commands inside the lima VM directly — no manual log relaying needed.

### 2. Kubelet using containerd instead of crio after restart

After a kubelet restart, `--container-runtime-endpoint` reverts to `containerd.sock` instead of `crio.sock`. The kubelet config override in `/etc/systemd/system/kubelet.service.d/u7s.conf` is not being applied. Re-run `scripts/lima-start.sh` to reprovision, then check:

```sh
limactl shell lima-node sudo journalctl -u kubelet --no-pager -n 5
```

Sonobuoy aggregator pod is stuck because the pod scheduling loop isn't completing (kubelet → cri-o → container running → status PATCH back to u7s).

`mayor-xy2` (CR schema validation) intentionally deferred.

## Forward-looking

1. **lima MCP setup** — once configured, mayor can iterate on sonobuoy failures autonomously
2. **Sonobuoy aggregator pod stuck** — kubelet must pick up the sonobuoy pod and run it; likely needs crio fix + possibly pod scheduling gaps in u7s
3. **CA persistence** — CA regenerates on every u7s restart, breaking kubelet trust; P2 candidate bead
4. **Sonobuoy triage** — once aggregator runs, paste failures → mayor files conformance-gap beads
5. **mayor-xy2** — deferred; re-evaluate at Argo CD milestone

## Recent progress

| Commit/PR | What | Bead |
|-----------|------|------|
| 553bb2b | fix(sonobuoy): skip dns preflight (--skip-preflight=dnscheck) | — |
| #60 (075fa8f) | feat(bootstrap): seed default + kube-system namespaces on startup | mayor-0hc |
| 26aae71 | feat(version): GET /version — fixes sonobuoy server version check | mayor-mr2 |
| 2f339ed + 8c80901 | fix(tls): advertise-address SAN + kubeconfig server URL | mayor-iko |
| b95141d | fix(lima): conmon added to cri-o install | — |

111 total beads closed. 0 open PRs. Single worktree (main only). 202 tests passing.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
