# Dashboard
2026-05-28T03:10
Resume: `bd ready` → 21 beads open; 5 P1 claimed, awaiting dispatch

## What needs the operator now

Nothing — ready to dispatch P1 workers. Previous kubelet decision resolved (no bead filed).

## In-flight

5 P1 beads claimed, workers not yet dispatched (prior attempt used `isolation="worktree"` — fixed in dispatch-prompt-template.md commit 20ac195; must pre-create worktrees manually):

| Bead | What |
|------|------|
| mayor-f93h | ConfigMap POST returns 409 instead of 201 |
| mayor-bdsj | GET returns resourceVersion=0 for stored objects |
| mayor-guqc | Watch streams close prematurely (~1s) |
| mayor-2fja | Missing selector defaulting for Deployment/RS/StatefulSet |
| mayor-0hxr | POST returns empty body on 400 |

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
| #307 ✓ | test(watch): ConfigMap PATCH emits MODIFIED watch event | mayor-2cwk |
| #306 ✓ | perf(store): composite (ns, obj_name) index | mayor-ohuz |
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

## Closed this session

| Bead | Resolution |
|------|-----------|
| mayor-uvcp | Already fixed by #297 (controllerrevisions registration) |
| mayor-2cwk | Bug in upstream kubelet volume syncer, not apiserver. Test in #307. |
| mayor-4ath | Bug in upstream kubelet probe runner, not apiserver. Tests in #308. |

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first. Mayor merges on green CI immediately.
