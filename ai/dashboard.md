# Dashboard

2026-05-21T15:30 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**Pod lifecycle e2e still blocked** — Two bugs fixed and merged (PR #80: uid stamping, PR #81: accept apply-patch+yaml as strategic-merge-patch), but CSINode init still fails. Root cause identified: `PATCH /apis/storage.k8s.io/v1/csinodes/lima-node` with `apply-patch+yaml` returns 404 when the resource doesn't exist — SSA should upsert. This is the next fix needed before the pod can proceed past kubelet initialization. Ready to dispatch on your signal.

**Operator question:** Should I dispatch the SSA upsert fix (apply-patch+yaml creates if not found) as a P1 worker now? It's a targeted change in `patch_resource()` in generic.rs, ~20 LoC.

**Nothing else blocked on you.**

## Forward-looking

1. Fix SSA upsert (apply-patch+yaml PATCH creates resource if absent) → kubelet CSINode and Lease init unblocked
2. Rerun pod lifecycle test once kubelet reaches Ready → pod should progress past ContainerCreating  
3. The cri-o sandbox failure (`unknown version specified`) may be a separate CNI/cri-o config issue in the lima VM — unrelated to apiserver
4. CI smoke job (create pod, assert Succeeded in 60s) — after manual e2e succeeds
5. mayor-xy2 (CR schema validation, P3) — deferred until Argo CD milestone

## Recent progress

Two bugs fixed this session from the pod lifecycle e2e test run:
- **PR #80 merged**: `metadata.uid` now assigned at create time — kubelet can name cri-o sandbox
- **PR #81 merged**: `application/apply-patch+yaml` accepted as strategic-merge-patch — kubelet can send SSA requests
- **e2e test status**: node registers, pod gets uid, kubelet tries to initialize CSINode and Lease via SSA PATCH → hits upsert gap (404 on non-existent CSINode)
- Test count: 255 → 257

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
