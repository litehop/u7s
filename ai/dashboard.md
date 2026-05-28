# Dashboard
2026-05-28T(session-open)
Resume: `bd ready` → 3 beads; serial worker dispatch in progress

## What needs the operator now

Nothing blocking. Serial worker chain running — see In-flight below.

## In-flight

| Worker | Bead | What | Status |
|--------|------|------|--------|
| a142e257 | mayor-uvcp | DaemonSet pods fail — focused e2e + fix or close-as-fixed | running |

Queue (dispatching serially — shared cluster):
1. mayor-2cwk — projected ConfigMap volume updates
2. mayor-4ath — liveness probe restarts

## Open PRs

None.

## Deferred

| Bead | What | Priority |
|------|------|----------|
| mayor-xxds | PodScheduled condition missing | P2 |
| mayor-b72p | Worker isolation infra | P2 |
| mayor-1rt1 | lima-start.sh KCM docs | P1 (deferred) |
| mayor-52wo | Embed upstream OpenAPI v2 spec | P2 |
| mayor-j7to | Argo CD RBAC seed | P2 |
| mayor-rvkq | CRD CEL validation | P3 |

## Recent merges (this session)

| PR | What | Beads |
|----|------|-------|
| #306 ✓ | perf(store): composite (ns, obj_name) index replacing separate indexes | mayor-ohuz |
| #305 ✓ | perf(store): ns/obj_name columns + SQL index pushdown | mayor-2soq |
| #304 ✓ | Always set metadata.uid on create | mayor-1oa9 |
| #303 ✓ | deletecollection verb in discovery + RBAC | mayor-b7jq |
| #302 ✓ | Stale-read floor via write-connection retry | mayor-mnnt |
| #301 ✓ | SSA PATCH returns full object + managedFields | mayor-jy6p |
| #300 ✓ | 409 Conflict returns existing object | mayor-d5tr |
| #299 ✓ | metadata.name field selector fast-path | mayor-my1f |
| #298 ✓ | hmac 0.13 / sha2 0.11 fix | mayor-ao32 |
| #297 ✓ | Register 9 missing API resources | mayor-g9m9 + 8 |
| #296 ✓ | Remove empty flowcontrol group; add tokenreviews | mayor-4wdh, mayor-2ptq |

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first. Mayor merges on green CI immediately (CLEAN = merge, no branch manipulation).
