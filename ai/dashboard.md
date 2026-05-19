# Dashboard

2026-05-19T05:30 UTC
Session: 96473ee9-26b3-4236-b9dc-1d311e5cee69
Open beads: 4 (2 in flight)

## What needs the operator now

Nothing urgent. Both active workers are non-security work.

## In flight

| Worker | Bead | Surface | Status |
|--------|------|---------|--------|
| acf8a0bcd89019101 | mayor-qde | namespace/CRD/CR watch handlers | Running |
| a41cc68f6aa51a2b1 | mayor-cw9 | Argo CD gap analysis → bead filing | Running |

## Open beads

| Priority | Bead | Title | Notes |
|----------|------|-------|-------|
| P2 | mayor-qde | Watch implementation | Worker in flight |
| P3 | mayor-mti | Sonobuoy baseline | Blocked on mayor-qde |
| P3 | mayor-cw9 | Argo CD gap analysis | Worker in flight |
| P3 | mayor-xy2 | CR schema validation | Deferred |

## Forward-looking

Watch (mayor-qde) is the critical path: ~15-20% of conformance tests require it. The store+generic infrastructure is complete; the gap is wiring namespace/CRD/CR list handlers to call watch_generic.

Argo CD gap analysis (mayor-cw9) will produce a set of new beads — expect RBAC resources, Deployment/StatefulSet handlers, and possibly networking resources as gaps.

After watch lands: unblock sonobuoy baseline (mayor-mti), dispatch schema validation (mayor-xy2).

## Recent progress

All major Phase 3 deliverables landed:
- PR #31: smoke CI fixes (TLS, PEM, token auth)
- PR #32: resourceVersion monotonic ordering test
- PR #33: x509 client cert auth (operator approved)
- PR #34: protobuf request decoding (zero new deps)

Smoke CI: green end-to-end with pure kubectl. Mayor on main, 1 worktree.

**Session totals:** 54 beads closed, PRs #21–34 merged.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal deps. Merge on green CI; flag security/API surface/architecture PRs for operator review first.
