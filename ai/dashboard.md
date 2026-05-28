# Dashboard
2026-05-27T18:30 (session active)
Session: active — `claude --continue` in /Users/balint.erdos/u7s

## What needs the operator now

Sonobuoy run in progress. Awaiting results.

## In-flight

- Sonobuoy conformance run (operator-initiated)

## Open PRs

None.

## Open beads

None — all beads from this session closed.

## Recent merges (this session)

| PR | What | Beads |
|----|------|-------|
| #282 ✓ | Continue token expiry → 410 Gone | mayor-sg53 |
| #283 ✓ | Register 5 missing API groups (scheduling, events, storage, networking, admissionregistration) | mayor-yjt3, mayor-8tij, mayor-d7uo, mayor-zcx7, mayor-r2q5 |
| #284 ✓ | Service Type defaulting, NodePort allocation, ExternalName ClusterIP | mayor-51ji, mayor-bdum |
| #285 ✓ | Event timestamps → microsecond precision | mayor-y2zv |
| #286 ✓ | too-many-arguments refactor | mayor-6miy |
| #287 ✓ | sonobuoy retrieve: fix WebSocket splice mutex deadlock (EOF root cause) | mayor-m41q |
| #288 ✓ | Correct PodSpec proto field numbers (root cause of ~175 pod failures) | mayor-fsb6, mayor-2ym1 |
| #289 ✓ | Kind consistency in proto JSON fallback; bounded splice channels; token TTL 60s; EventSeries.lastObservedTime precision | mayor-ep6w, mayor-bklb, mayor-0hw8, mayor-ojvd |
| #290 ✓ | Proto envelope 16 MiB size limit (OOM protection) | mayor-g6wq |
| #291 ✓ | Remove unwrap() panics from codec/handler paths | mayor-5arq |
| #292 ✓ | HMAC-SHA256 signing for continue tokens | mayor-73s6 |
| direct ✓ | Auto-build u7s-scheduler if binary not found | — |

## Deferred beads

| Bead | What | Priority |
|------|------|----------|
| mayor-xxds | PodScheduled condition missing | P2 |
| mayor-b72p | Worker isolation infra | P2 |
| mayor-1rt1 | lima-start.sh KCM documentation | P1 (deferred) |
| mayor-52wo | embed upstream OpenAPI v2 spec | P2 |
| mayor-j7to | Argo CD RBAC seed | P2 |
| mayor-rvkq | CRD CEL validation | P3 |

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first, kubectl-compatible API, minimal deps. Mayor merges on green CI automatically.
