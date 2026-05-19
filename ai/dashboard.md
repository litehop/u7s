# Dashboard

2026-05-19T06:15 UTC
Session: 96473ee9-26b3-4236-b9dc-1d311e5cee69
Open beads: 13 (1 in flight, PR pending)

## What needs the operator now

Nothing urgent. One profiling worker running; PR #40 awaiting CI.

## In flight / pending

| Item | Bead | Surface | Status |
|------|------|---------|--------|
| PR #40 | mayor-uca | CR status subresource fallback in generic.rs | CI running (rebased) |
| Worker a3c495fbe98f583ec | mayor-pga | scripts/bench-rss.sh + perf CI job | Running |

## Open beads

| Priority | Bead | Title | Notes |
|----------|------|-------|-------|
| P2 | mayor-uca | CR status subresource write path | PR #40 pending CI |
| P2 | mayor-pga | Profiling workflow: RSS + latency bench | Worker in flight |
| P2 | mayor-yx5 | fieldSelector support | Ready to dispatch |
| P2 | mayor-l8f | generateName support | Ready to dispatch |
| P2 | mayor-jf3 | JSON Patch RFC 6902 | Ready to dispatch |
| P2 | mayor-c3v | Namespace Terminating phase lifecycle | Ready to dispatch |
| P2 | mayor-ynx | List pagination (limit/continue) | Ready to dispatch |
| P2 | mayor-b4g | Pod status subresource (pods/status) | Ready to dispatch |
| P2 | mayor-qnc | DELETE response body + finalizer soft-delete | Ready to dispatch |
| P2 | mayor-ik3 | resourceVersion in watch ADDED events | Ready to verify first |
| P3 | mayor-xy2 | CR schema validation | Deferred |

## Forward-looking

Conformance analysis complete: ~40-50% of API-level tests passable now.
Top blocker cluster for conformance: fieldSelector (mayor-yx5), generateName (mayor-l8f), JSON Patch (mayor-jf3), Pod status subresource (mayor-b4g). These 4 alone unlock another ~15-20% of conformance tests.

Profiling workflow (mayor-pga) establishes the RSS gate: 64 MB threshold for apiserver, enforced in CI on main push.

Next dispatch round: cluster mayor-yx5 + mayor-l8f + mayor-b4g as they all touch query/handler plumbing; mayor-jf3 + mayor-c3v into patch.rs/namespaces.rs; mayor-qnc into delete handlers.

## Recent progress

This session: PRs #36–40, ~20 beads closed. Conformance gap analysis: 8 beads filed. Profiling bead filed.

Smoke CI green end-to-end with pure kubectl.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal deps. Merge on green CI; flag security/API surface/architecture PRs for operator review first.
