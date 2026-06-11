# Dashboard
2026-06-11T14:19Z — #513 merged. Bead backlog empty. No in-flight workers.

Resume: `bd prime`

## Operator attention needed

Bead backlog empty — ready for next run or new beads from a fresh sonobuoy pass.

## In-flight workers

None.

## Open PRs

None.

## Recent merges
- #513 fix(apiserver): StatefulSet conformance — collection PATCH, canary partition, rollback revision (eywo+w2x6+j8w8)
- #512 fix(proto): decode StatefulSet status.conditions from protobuf body (mayor-hdaz)
- #511 fix(proto): decode ContainerPort from pod proto; add eviction handler (mayor-27ix)
- #510 fix(scripts): --port flag for apiserver port isolation (mayor-fuwy)
- #509 fix(proto): spec.replicas unconditional in workload decoders (mayor-b7y4)
- #508 fix(watch): full object body in DELETED tombstone (mayor-eajn)

## VM port assignment
| Slot | Port | Who |
|---|---|---|
| mayor | 6443 | Mayor (lima-node) |
| worker-1 | 6444 | free (lima-node-smoke, running) |
| worker-2 | 6445 | free (lima-node-2, stopped) |

## Loops running (session-only, expire 7 days)
- :07 hourly — posture reread
- :11 hourly — worktree hygiene
- :17 every 2h — cluster review
- :23 every 2h — merge pass
- :43 hourly — bead dispatch pass
- :53 hourly — dashboard refresh

## Deferred
mayor-52wo · mayor-j7to · mayor-rvkq
