# Dashboard

2026-05-20T15:00 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred) + PR #59 in CI

## What needs the operator now

**PR #59 in CI** — sonobuoy lima setup (lima/kubelet.yaml + scripts/sonobuoy-run.sh + docs). Will auto-merge when green. After merge, operator can run sonobuoy locally:
```sh
export KUBECONFIG=...
scripts/lima-start.sh
scripts/sonobuoy-run.sh
```

`mayor-xy2` (CR schema validation) intentionally deferred — safe for Argo CD milestone.

**HOLD on bead dispatch** — only deferred bead remains. Backlog is empty pending sonobuoy results, which will spawn new conformance-gap beads.

## Forward-looking

1. **Merge PR #59** (CI pending) — sonobuoy VM setup
2. **Run sonobuoy** (operator-driven, ~5–15 min) → results triage → new conformance-gap beads → dispatch workers
3. **mayor-xy2 (CR schema validation)** — deferred; re-evaluate at Argo CD milestone
4. **Kubelet implementation** — longer-term; awaiting operator direction

## Recent progress

| PR | What | Beads |
|----|------|-------|
| #59 (pending) | sonobuoy v0.57.3 in lima VM + sonobuoy-run.sh + docs | mayor-qah |
| #58 (d2a5b49) | storage.k8s.io/v1 + node.k8s.io/v1 discovery registration (+4 tests) | mayor-w8x |
| #56 (e45a703) | fieldSelector wiring + list pagination (+16 tests) | mayor-yx5, mayor-ynx |
| #57 (dd531fa) | merge_patch dedup, proto dedup, HEAD verb, rbac cleanup (−114 lines) | mayor-4r7, mayor-67m, mayor-abq, mayor-59u |

106 total beads closed across project lifetime. 1 open PR (#59 in CI). All CI green.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
