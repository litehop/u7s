# Dashboard

2026-05-21T15:50 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**Stance confirmation** — current stance below; confirm or adjust before next dispatch cycle.

**Pod lifecycle e2e — retest ready.** Three bugs fixed and merged this session (PRs #80, #81, #82). Kubelet should now be able to: (1) assign uid to pods, (2) send SSA PATCHes, (3) create CSINode + Lease via SSA upsert. The cri-o sandbox failure (`unknown version specified`) seen during the last test run is a CNI config issue in the lima VM — unrelated to u7s. Needs investigation or workaround before the pod can progress past ContainerCreating. Ready to retest on your signal.

**Nothing else blocked on you.**

## Forward-looking

1. Rerun pod lifecycle test — if cri-o sandbox still fails, investigate CNI config in lima VM (not an apiserver bug)
2. If pod reaches Succeeded: add CI smoke job (create pod, assert Succeeded within 60s)
3. mayor-xy2 (CR schema validation, P3) — deferred until Argo CD milestone

## Recent progress

Three P1 correctness fixes merged this session — all driven by live kubelet e2e testing:
- **PR #80**: `metadata.uid` stamped at create time — kubelet can name cri-o sandboxes
- **PR #81**: `application/apply-patch+yaml` accepted as strategic-merge-patch — kubelet SSA requests no longer 415
- **PR #82**: SSA PATCH upserts (creates if absent) — kubelet CSINode + Lease init unblocked; reviewed by code-review agent (no issues found)

Worktree hygiene: 5 stale worktrees removed, 1 orphan remote branch deleted.

Session test count: 255 → 260.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
