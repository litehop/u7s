# Dashboard

2026-05-20T08:00 UTC
`bd prime` in a fresh Claude Code session
Open beads: 3 (mayor-886 P2, mayor-a1a P2, mayor-xy2 P3 deferred)

## What needs the operator now

Nothing blocking. Two PRs in CI (#54 Lease tests, #55 Node proto decoder) — will merge automatically when green.

`mayor-xy2` (P3, CR schema validation) remains intentionally deferred.

## Forward-looking

After #54 and #55 merge, all P1/P2 beads will be closed. Backlog near-zero.

Next candidates (no beads filed yet — awaiting operator direction):
- Attempt a real kubelet join against u7s (would surface remaining gaps organically)
- Conformance testing via sonobuoy
- Code quality / performance audit pass against recent commits

## Recent progress (this session)

Major push on testing and kubelet surface:
- **PR #49 merged** — smoke test proto decode fix (empty contentType bug)
- **PR #50 merged** — 5 wire-level integration tests (exercise exact kubectl wire bytes)
- **PR #51 merged** — watch stream smoke test (curl-based NDJSON; server was already correct)
- **PR #52 merged** — inflight limiter (50/20 limits, 429 on exhaustion) + load RSS bench (3 MB delta)
- **PR #53 merged** — fieldSelector=spec.nodeName for pod list/watch (P1 kubelet correctness)
- **PR #54** (Lease integration tests) — in CI
- **PR #55** (Node proto decoder) — in CI
- Beads closed today: mayor-fp3, mayor-pjp, mayor-7ft, mayor-ajt, mayor-4m9, mayor-m7u (6 closed)
- 92 total beads closed across project lifetime

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
