# Dashboard
2026-05-29T00:30 — PR #330 CI re-running after /apis regression fix; 3 ready beads; 2 operator decisions pending

Resume: merge #330 on green → dispatch dacc; decide pzkt + mixv

## What needs the operator now

| Bead | Decision needed | Mayor recommendation |
|------|----------------|---------------------|
| **mayor-pzkt** | ClusterIP allocator: real dual-stack CIDR manager vs incrementing stub? | **Real allocator** — u7s is natively dual-stack (IPv4+IPv6 pools required) |
| **mayor-mixv** | WebSocket exec/attach: operator confirmed WebSocket-only. Dispatch worker? | **Yes — dispatch now** |

## In-flight PRs

| PR | Bead | What | CI |
|----|------|------|----|
| #330 | mayor-pv8p | fix: AggregatedDiscovery /discovery/v2 + /apis regression fix | 8 checks pending |

## Open worktrees
- mayor-pv8p (PR #330 open — merge watcher active)

## Ready to dispatch

| Bead | What | Blocked on |
|------|------|-----------|
| mayor-dacc | Remove --validate=false from smoke/perf CI | PR #330 merge first |
| mayor-mixv | Pod exec/attach WebSocket proxy apiserver→kubelet | Operator go-ahead |
| mayor-pzkt | Service ClusterIP dual-stack allocator | Operator decision on real vs stub |

## Deferred

| Bead | What | Priority |
|------|------|----------|
| mayor-b72p | Worker isolation infra (operator decision: option 3 recommended) | P2 |
| mayor-52wo | Embed upstream OpenAPI v2 spec | P2 |
| mayor-j7to | Argo CD RBAC seed (depends on SA token projection) | P2 |
| mayor-rvkq | CRD CEL validation | P3 |

## Recent merges (this session)

| PR | What | Bead |
|----|------|------|
| #336 ✓ | fix: LimitRange panic (is_object guards + proto spec decode) | mayor-1dhj |
| #335 ✓ | fix: fieldValidation=Strict returns 422 Status body | mayor-7exg |
| #334 ✓ | fix: PodScheduled=False on create, True on bind | mayor-xxds |
| #333 ✓ | fix: lima-start.sh starts KCM alongside kubelet | mayor-1rt1 |
| #332 ✓ | fix: AdmissionWebhook bootstrap deadlock prevention | mayor-d1fb |
| #331 ✓ | fix: EndpointSlice + EndpointSliceMirroring controllers in KCM | mayor-do5i |
| #329 ✓ | fix: openapi_v2 dynamic CRD definitions; CRD status conditions | mayor-8ssu |
| #328 ✓ | fix: pod resize subresource PATCH+PUT | mayor-sor9 |
| #327 ✓ | fix: register DRA resource.k8s.io/v1 types | mayor-ixyf |
| #326 ✓ | fix: Pod metadata.generation initialized and incremented | mayor-0zki |
| #325 ✓ | fix: Event PATCH normalizes series.lastObservedTime | mayor-quqc |

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first. Mayor merges on green CI immediately.

## Protocol notes
- Use `subagent_type="worker"` in every editing Agent dispatch — default lacks permissionMode:auto
- Include permission line in every prompt: "You have full permission to use all tools…"
- Step 0: `git -C <worktree>` not `cd <worktree>` (cd not in Bash allowlist)
- Pre-create worktrees manually; never use `isolation: "worktree"` in Agent dispatches
- Worker must test against a running server (not just cargo test) for any HTTP-level behavior change
