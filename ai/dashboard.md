# Dashboard
2026-05-22T (session wind-down)
Session: c7f5c957-9e8f-44b1-946e-9ddac1927010
Open beads: 9 (2 workers still running in background)

## What the operator needs to do next

**Nothing urgent.** Two workers are still running in the background — their PRs will appear on GitHub when done. Next session: review and merge those PRs, then dispatch the blocked wave.

**PRs to watch:**
- PR #177 (admission webhooks, mayor-xas3) — CI running, expect green shortly
- PR from worker/deployment-smoke-9o59 — Deployment + ConfigMap smoke test (mayor-9o59)
- PR from worker/postquantum-lghq — ML-KEM hybrid TLS (mayor-lghq)

## Blocked wave (dispatch next session after PR #177 merges)

| ID | P | Summary | Blocker |
|----|---|---------|---------|
| mayor-pva9 | P3 | CRD conversion webhooks | Depends on mayor-xas3 (#177) |
| mayor-5hyh | P3 | Admission namespaceSelector evaluation | Depends on mayor-xas3 (#177) |
| mayor-6l4h | P3 | Admission service-based clientConfig | Depends on mayor-xas3 (#177) |
| mayor-u7ij | P3 | ResourceQuota enforcement | Wait for #177 (resource.rs hot zone) |
| mayor-x9b5 | P3 | LimitRange enforcement | Wait for #177 (resource.rs hot zone) |
| mayor-h2fk | P3 | RSS stress test bench | Depends on mayor-9o59 |
| mayor-2ni | P3 | sonobuoy conformance audit | Ready — needs live setup |

## In-flight worktrees

| Worktree | Branch | Status |
|----------|--------|--------|
| ai/worktrees/admission-xas3 | worker/admission-xas3 | PR #177 in CI |
| ai/worktrees/deployment-smoke-9o59 | worker/deployment-smoke-9o59 | Worker running |
| ai/worktrees/postquantum-lghq | worker/postquantum-lghq | Worker running |

## Session summary (2026-05-22)

**Decisions made:**
- Proxy-through: (A) full WebSocket both directions, transport abstracted for HTTP/3+QUIC
- CEL (mayor-rvkq): deferred indefinitely — Argo CD has zero x-kubernetes-validations
- ResourceQuota/LimitRange: will go inside admission pipeline as built-in plugins

**PRs merged:** #175 (client-util dedup), #176 (pod /attach), #178 (pod /portforward)
**Beads closed:** mayor-15hu, mayor-l7a9, mayor-2d7p
**Beads filed:** mayor-9o59, mayor-h2fk, mayor-5hyh, mayor-6l4h

**Key learnings recorded in memory:**
- CI not running = check mergeability first (conflict blocks CI)
- jq over python3 for shell JSON parsing

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, performance-critical (RSS/latency hard targets), kubectl-compatible API surface, minimal crate deps. Merge on green CI automatically; flag security/API/architecture PRs for operator review first.
