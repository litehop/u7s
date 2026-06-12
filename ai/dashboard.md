# Dashboard
2026-06-12T04:11Z — #522 #523 #524 merged. No workers in-flight. Queue: 5 open beads.

Resume: `bd prime`

## Operator attention needed

None.

## In-flight workers

None.

## Open PRs

None.

## Recent merges
- #524 fix(apiserver): increment generation and add GET on ephemeralcontainers (mayor-d74k)
- #523 fix(proto): regression test for GRPC probe decode (mayor-ephx)
- #522 fix(apiserver): DNS pod exec 404 routing fix (mayor-7cjk + mayor-pbwj)
- #521 fix(watch): suppress store BOOKMARK events when allowWatchBookmarks=false (mayor-4oqo)
- #520 fix(apiserver): include CRD schemas in /openapi/v2 definitions (mayor-slc2)

## VM port assignment
| Slot | VM | Port | Who |
|---|---|---|---|
| mayor | lima-node | 6443 | Mayor |
| worker-1 | lima-node-smoke | 6444 | free (running) |
| worker-2 | lima-node-2 | 6445 | free (running) |
| worker-3 | — | 6446 | free |
| worker-4 | — | 6447 | free |
| worker-5 | — | 6448 | free |

## Queued
- mayor-352r (P2) — namespace TTL watchdog (scripts)
- mayor-ewnt (P2) — scheduling predicates (VM required)
- mayor-rzmf (P2) — webhooks (large missing feature)
- mayor-2zo1 (P2) — ResourceQuota admission (large missing feature)
- mayor-zhr6 (P3) — projected volumes
- mayor-l5hs (P3) — sonobuoy stall detector (blocked on mayor-352r)

## Loops running (session-only, expire 7 days)
- :07 hourly — posture reread (2ea6d18f)
- :11 hourly — worktree hygiene (ff60a583)
- :17 every 2h — cluster review (a4d9857a)
- :23 every 2h — merge pass (28f6d4ef)
- :43 hourly — bead dispatch pass (53ca77a8)
- :53 hourly — dashboard refresh (c5b70796)
