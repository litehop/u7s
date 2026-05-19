# Dashboard

2026-05-19T05:45 UTC
Session: 96473ee9-26b3-4236-b9dc-1d311e5cee69
Open beads: 10 (5 in flight)

## What needs the operator now

Nothing urgent. All 4 active workers are on non-security, disjoint surfaces.

## In flight

| Worker | Bead(s) | Surface | Status |
|--------|---------|---------|--------|
| acf8a0bcd89019101 | mayor-qde, mayor-5l4 | namespace/CRD/CR watch handlers | Running |
| aa0f42dee5ed4114e | mayor-bph, mayor-5d9, mayor-9xr, mayor-9za | state.rs + discovery.rs (4 API groups) | Running |
| a88cd0d281e19661d | mayor-cn8 | authorization.rs (SubjectAccessReview + TokenReview) | Running |
| a3563486e8a752bd0 | mayor-7ak | generic.rs (strategic merge patch) | Running |

## Open beads

| Priority | Bead | Title | Notes |
|----------|------|-------|-------|
| P2 | mayor-qde | Watch implementation | Worker in flight |
| P2 | mayor-bph | networking.k8s.io/v1 missing | Worker in flight (cluster) |
| P2 | mayor-5d9 | admissionregistration.k8s.io/v1 missing | Worker in flight (cluster) |
| P2 | mayor-9xr | coordination.k8s.io/v1 missing | Worker in flight (cluster) |
| P2 | mayor-7ak | Strategic merge patch rejected | Worker in flight |
| P2 | mayor-5l4 | Watch on core/v1 Namespaces missing | Covered by watch worker |
| P2 | mayor-cn8 | SubjectAccessReview/TokenReview missing | Worker in flight |
| P2 | mayor-uca | CR status subresource write path | Hold — overlaps cr.rs with watch worker |
| P3 | mayor-mti | Sonobuoy baseline | Blocked on mayor-qde |
| P3 | mayor-xy2 | CR schema validation | Deferred |

## Forward-looking

Once in-flight batches land:
1. All 4 missing API groups (networking, admissionregistration, coordination, policy) will be served
2. Watch works for namespaces, CRDs, CR instances
3. `kubectl apply` re-apply works (SMP enabled)
4. SubjectAccessReview + TokenReview unblock Argo CD SSO/RBAC UI

Remaining: mayor-uca (CR status subresource), then dispatch sonobuoy baseline.

## Recent progress

Argo CD gap analysis complete: 8 gaps identified, 8 beads filed (mayor-cw9 closed).
PRs #33 (x509) and #34 (protobuf) merged. Smoke CI green with pure kubectl.

**Session totals:** 54 beads closed, PRs #21–34 merged.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal deps. Merge on green CI; flag security/API surface/architecture PRs for operator review first.
