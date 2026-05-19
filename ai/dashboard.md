# Dashboard

2026-05-20T10:00 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2, P3, intentionally deferred)

## What needs the operator now

**One design decision pending** — how to set up end-to-end testing infrastructure.

Operator raised two open questions:
1. **Virtualization approach**: lima VMs (real kubelet + CRI, better fidelity, slower CI) vs KinD containers (faster, but topology differs and some kubelet behaviors won't surface). Mayor recommendation: lima. Operator has not decided yet.
2. **kubectl version matrix**: aqua (per-project lockfile, zero pollution to system kubectl) is the proposed approach. Needs operator sign-off before filing beads.

`mayor-xy2` (CR schema validation / openAPIV3Schema enforcement) remains intentionally deferred — permissive CR validation is safe for the Argo CD milestone.

## Forward-looking

Once operator decides on virtualization + kubectl versioning approach, mayor will:
1. File beads for e2e test infrastructure (lima setup scripts, aqua lockfile, kubelet join smoke test)
2. Dispatch workers to implement in sequence (infra first, then kubelet join test)
3. After kubelet join is green, revisit sonobuoy conformance as the next conformance milestone

No current in-flight workers. All loops running.

## Recent progress

This session (continuing from prior context) closed 8 beads and merged 7 PRs:

| PR | What | Beads |
|----|------|-------|
| #49 | Proto decode fix (empty contentType) | mayor-fp3 |
| #50 | Wire-level kubectl integration tests (5 tests) | mayor-pjp |
| #51 | Watch stream smoke test (curl-based NDJSON) | mayor-ajt |
| #52 | Inflight limiter (50/20 limits) + load RSS bench | mayor-7ft |
| #53 | fieldSelector=spec.nodeName for pod list/watch | mayor-4m9 |
| #54 | Lease PUT OCC integration tests (3 tests) | mayor-886 |
| #55 | Node proto decoder for kubelet PUT path | mayor-a1a |

93 total beads closed across project lifetime. No open PRs. All worktrees cleaned.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
