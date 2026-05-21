# Dashboard
2026-05-21 06:58 UTC
Resume: open Claude Code in /Users/balint.erdos/u7s, say "I am the Mayor now"
Open beads: 5 (3 in_progress, 2 open)

## What needs the operator now
- **PRs #97 and #103** both still failing kubelet smoke (pod stuck ContainerCreating, Events: <none>). Worker dispatched to investigate root cause — may surface a decision if the fix is architectural.
- **Renovate PRs #109 (rcgen) and #110 (rusqlite)** are failing — not yet dispatched. Will handle after current batch.

## Forward-looking
3 workers running in parallel:
1. **CodeQL fix** (mayor-47hf) — `auth.rs:66` split inline to locals; `tls.rs` test suppressions. Pure cleanup.
2. **Kubelet smoke fix** (mayor-l90x) — pod stuck ContainerCreating. Investigating missing PATCH /pods/{name}/status endpoint or strategic-merge-patch gap. Will use CI artifact logs + lima-node locally.
3. **jsonwebtoken v10 compat** (mayor-zxu4) — 5 test panics in auth.rs from missing CryptoProvider init. Enables Renovate PR #117 to merge.

After these land: revisit Renovate PRs #109 and #110 (rcgen and rusqlite). Then sonobuoy gap audit (mayor-2ni) and protobuf bindings (mayor-pgdr).

## Recent progress
- PR #121 (schemars v1) merged ✓
- PR #122 (thiserror v2) merged ✓
- PR #120 (CSINode round-trip test) merged ✓
- PRs #97 and #103 open — kubelet smoke failing on new pod lifecycle assertion step
- Previous session: ~120 PRs total merged; security sprint, CI hardening, feature work complete

## Stance
Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Mayor merges on green CI; flags security/API/architecture PRs for operator review first.
