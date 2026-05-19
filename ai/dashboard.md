# Dashboard

2026-05-19T07:00 UTC
Session: 96473ee9-26b3-4236-b9dc-1d311e5cee69
Open beads: 9 (0 in flight)

## What needs the operator now

Nothing urgent. Operator paused after profiling workflow merged. 9 P2/P3 beads ready for next session.

## In flight / pending

Nothing in flight.

## Open beads

| Priority | Bead | Title | Notes |
|----------|------|-------|-------|
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

Profiling workflow (mayor-pga) merged (PR #41): bench-rss.sh asserts ≤64 MB idle RSS; perf CI job runs on every main push. RSS gate: 65536 kB threshold, sampled via `ps -o rss=`.

Next dispatch round: cluster mayor-yx5 + mayor-l8f + mayor-b4g as they all touch query/handler plumbing; mayor-jf3 + mayor-c3v into patch.rs/namespaces.rs; mayor-qnc into delete handlers.

## Recent progress

This session: PRs #33–41, ~25 beads closed. Conformance gap analysis: 8 beads filed. Profiling workflow filed and merged. Argo CD gap analysis filed.

Smoke CI green end-to-end with pure kubectl. perf CI job active on main push.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal deps. Merge on green CI; flag security/API surface/architecture PRs for operator review first.
