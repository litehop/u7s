# Dashboard

2026-05-20T06:35 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**Backlog is cold.** No blocking decisions.

**Next step: test that kubelet registers a node.** Build u7s, start it, check kubelet logs. The three fixes landed this session should unblock node registration:
- CA key persists across restarts → kubelet's trusted CA stays valid
- system:node RBAC seeded at startup → kubelet credentials work without system:masters bypass
- NodeSpec decoded from proto → stored nodes have valid podCIDR/providerID

Once node registers: run sonobuoy, triage failures into new beads.

## Forward-looking

1. **Kubelet node registration smoke test** — `cargo build && ./u7s-apiserver`, check kubelet logs in lima
2. **Sonobuoy** — once node registers, restart with `--mode=non-disruptive-conformance`
3. **Triage sonobuoy failures** → new beads → worker dispatch
4. **mayor-xy2** (CR schema validation, P3) — only open bead, low priority

## Recent progress — this session

| PR | What | Status |
|----|------|--------|
| #63 | decode NodeSpec fields (podCIDR/providerID) from kubelet proto | merged |
| #64 | seed system:node ClusterRole+ClusterRoleBinding at startup | merged |
| #66 | persist CA key+cert across restarts (--ca-key/--ca-cert) | merged |

114 total beads closed. 0 open PRs. 0 worktrees. Kubelet smoke tests (1.34.8, 1.35.5, 1.36.1) passed CI for all PRs.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
