# Dashboard

2026-05-20T06:45 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**Backlog cold. No decisions needed.**

**Your next action:** Verify kubelet registers a node against the new build. Start u7s (`cargo run --bin u7s-apiserver`) and check kubelet logs in the lima VM. This is the acceptance gate for the 3 PRs merged this session.

If node registers → run sonobuoy → triage failures into new beads → mayor dispatches workers.
If node still fails → investigate logs, file new beads with root cause.

## Forward-looking

1. **Kubelet node registration** — manual acceptance test (operator action)
2. **Sonobuoy triage** — once node registers, restart sonobuoy; failures become new beads
3. **mayor-xy2** (CR schema validation, P3) — only open bead, intentionally deferred; revisit at Argo CD milestone

## Recent progress

This session merged 5 PRs (all kubelet-registration blockers):

| PR | What |
|----|------|
| #61 | seed kube-node-lease + kube-public namespaces |
| #62 | storage.k8s.io/v1 resources in build_registry |
| #63 | decode NodeSpec fields (podCIDR/providerID) from kubelet proto |
| #64 | seed system:node ClusterRole+ClusterRoleBinding at startup |
| #66 | persist CA key+cert across restarts (--ca-key/--ca-cert) |

114 total beads closed. 0 open PRs. 0 worktrees. All kubelet smoke tests (1.34.8 / 1.35.5 / 1.36.1) green.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
