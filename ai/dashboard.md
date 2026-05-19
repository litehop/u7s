# Dashboard

2026-05-19T06:30 UTC
Session: 96473ee9-26b3-4236-b9dc-1d311e5cee69
Open beads: 1

## What needs the operator now

Nothing urgent. Board is cold — only one deferred P3 bead remains.

**Audit in flight:** Independent review of PRs #23–25 (CRD implementation) running now. Expect follow-on beads when it completes.

## Open beads

| Priority | Bead | Title | Notes |
|----------|------|-------|-------|
| P3 | mayor-xy2 | CR instance schema validation (openAPIV3Schema enforcement) | Deferred intentionally — Argo CD does not require this in Phase 3 |

## Forward-looking

**Next natural work:** Await audit results from the CRD review. If the audit surfaces correctness gaps or missing API surface, those become P1/P2 beads and the dispatch loop picks them up. If clean, the project is ready for Argo CD integration testing.

**Argo CD milestone path:**
1. CRD support ✓ (PRs #23–25)
2. Argo CD install smoke test — not yet started; needs a running cluster
3. Any gaps surfaced by Argo CD installation become new beads

**Standing deferred:** mayor-xy2 (CR schema validation) — implement when Argo CD integration reveals a concrete need, not speculatively.

## Recent progress

**This session (2026-05-19):**

| PR | Title | Beads |
|----|-------|-------|
| #23 | feat(crd): CRD storage and CRUD handlers | mayor-6h1 |
| #24 | feat(discovery): dynamic /apis — CRD groups appear without restart | mayor-f1h |
| #25 | feat(cr): serve CR instance CRUD for installed CRDs | mayor-4fy |

Also merged earlier:
- PR #22 — scale subresource (mayor-d01)
- Direct commit — controller-manager SA token provisioning (mayor-2hu)
- Direct commit — SA JWT inbound verification (mayor-n9a)

51 beads closed total. 52 filed this phase.

## Stance (reasserted each session)

Pre-alpha/greenfield: break freely, no backward compat, delete dead code. Correctness first. kubectl-compatible API surface. Minimal dependencies (resist adding crates). **Merge on green CI automatically**; flag security/API surface/architecture PRs for operator review first.
