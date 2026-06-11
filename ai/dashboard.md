# Dashboard
2026-06-12T — #514 merged. Label selector bug fixed. Svc-latency hang resolved.

Resume: `bd prime`

## Operator attention needed

Run focused conformance to verify svc-latency hang is gone:
`scripts/conformance/run-all.sh --focus "Service endpoints latency should not be very high"`

## In-flight workers

None.

## Open PRs

None.

## Recent merges
- #514 fix(watch): implement DoesNotExist/Exists/NotEquals label selector operators (mayor-p97u)
- #513 fix(apiserver): StatefulSet conformance — collection PATCH, canary partition, rollback revision (eywo+w2x6+j8w8)
- #512 fix(proto): decode StatefulSet status.conditions from protobuf body (mayor-hdaz)
- #511 fix(proto): decode ContainerPort from pod proto; add eviction handler (mayor-27ix)
- #510 fix(scripts): --port flag for apiserver port isolation (mayor-fuwy)
- #509 fix(proto): spec.replicas unconditional in workload decoders (mayor-b7y4)

## VM port assignment
| Slot | Port | Who |
|---|---|---|
| mayor | 6443 | Mayor (lima-node) |
| worker-1 | 6444 | free (lima-node-smoke, running) |
| worker-2 | 6445 | free (lima-node-2, stopped) |

## Loops running (session-only, expire 7 days)
- :07 hourly — posture reread (2c38f451)
- :11 hourly — worktree hygiene (0e661092)
- :17 every 2h — cluster review (6b504dfd)
- :23 every 2h — merge pass (ea2ece0d)
- :43 hourly — bead dispatch pass (96a4b06d)
- :53 hourly — dashboard refresh (2169b806)

## Deferred
mayor-52wo · mayor-j7to · mayor-rvkq
