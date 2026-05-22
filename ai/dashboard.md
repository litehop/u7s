# Dashboard
2026-05-22T (new session)
Session: c7f5c957-9e8f-44b1-946e-9ddac1927010
Open beads: 10 (4 in-flight)

## What the operator needs to do now

Nothing blocking. All open decisions resolved:
- Proxy-through: (A) full proxy-through confirmed — WebSocket both directions, transport abstracted for HTTP/3+QUIC swap-in
- Worker dispatch: resolved (confirmed by operator)

## In-flight work

| Bead | Worktree | Status |
|------|----------|--------|
| mayor-xas3 P2 | ai/worktrees/admission-xas3 | Dispatched — admission webhook pipeline |
| mayor-15hu P3 | ai/worktrees/client-util-15hu | Dispatched — HyperApiClient dedup |
| mayor-2d7p P2 | ai/worktrees/portforward-2d7p | Dispatched — portforward WebSocket full proxy |
| mayor-l7a9 P3 | ai/worktrees/attach-l7a9 | Dispatched — attach WebSocket full proxy |

No open PRs yet (workers are building).

## Waiting for (next dispatch round)

| ID | P | Summary | Blocker |
|----|---|---------|---------|
| mayor-pva9 | P3 | CRD conversion webhooks | Depends on mayor-xas3 |
| mayor-lghq | P3 | rustls post-quantum ML-KEM | Ready — unblocked by PR #174 |
| mayor-2ni | P3 | sonobuoy conformance audit | Ready |
| mayor-rvkq | P3 | CRD CEL validation | Ready |
| mayor-u7ij | P3 | ResourceQuota enforcement | Ready |
| mayor-x9b5 | P3 | LimitRange enforcement | Ready |

## Recent progress

**This session:**
- Proxy-through decision resolved: (A) full proxy-through, WebSocket both ways, transport abstracted
- 4 workers dispatched: admission webhooks, HyperApiClient dedup, portforward, attach
- 5 loops started: 10m dashboard, 15m dispatch, 30m cluster review, 30m PR merge, 60m hygiene

**Previous session (2026-05-22):**
- PR #174 merged: reqwest native-tls → rustls (mayor-knyy ✓)
- WebSocket transport decision: WebSocket only, no SPDY at any layer

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, performance-critical (RSS/latency hard targets), kubectl-compatible API surface, minimal crate deps. Merge on green CI automatically; flag security/API/architecture PRs for operator review first.
