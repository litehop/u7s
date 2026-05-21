# Dashboard

2026-05-21 — session active
`bd prime` in a fresh Claude Code session
Open beads: 6 (2 workers in flight)

## What needs the operator now

Nothing blocking — no decisions queued.

**Workers in flight:**
- **proto encoder fix** (`mayor-cux`, worker `a5ae2b40566e07637`) — diagnosing wireType 6 in `proto.rs`; will push fix to PR #84 branch to re-trigger CI
- **scheduler namespace-aware** (`mayor-chl`, worker `a8d6e55c0c72edca9`) — changing watch URL to cluster-wide `/api/v1/pods`

**PRs pending CI:**
- **PR #84** (`worker/agent-a5fbeadb79a66a443`) — protobuf response negotiation. Still failing `kubectl` with wireType 6. Fix in-flight above.
- **PR #86** (`worker/seed-services-mayor-lmz`) — seeds `default/kubernetes` + `kube-system/kube-dns` Services. Lint ✓, rest pending.

## Forward-looking

1. **mayor-cux** (in-flight) → PR #84 goes green → merge → kubelet smoke unblocked
2. **mayor-chl** (in-flight) → new PR → scheduler watches all namespaces
3. **mayor-2dc** (P1) — CI: assert node reaches Ready. Dispatch after PR #84 merges.
4. **mayor-v43** (P1) — CI: pod lifecycle smoke. Blocked on mayor-2dc.
5. **mayor-6m3** (P2) — seed CoreDNS deployment. Blocked on PR #86 merge (mayor-lmz).
6. **mayor-2ni** (P3) — sonobuoy audit. Blocked on pod lifecycle.
7. **mayor-xy2** (P3) — CR schema validation. Deferred.

## Recent progress

- **PR #86 opened**: seeds `kubernetes` + `kube-dns` Services at startup (mayor-lmz). +2 tests, 262 total.
- **6 roadmap beads filed** this session: mayor-2dc, mayor-v43, mayor-lmz, mayor-chl, mayor-6m3, mayor-2ni.
- Full prior backlog drained: 50+ beads closed before this session.
- Mayor switched to `main` branch (was on `fix/proto-content-length`).

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI with `--merge`; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).
