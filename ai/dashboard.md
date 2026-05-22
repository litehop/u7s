# Dashboard
2026-05-22 (session active — holding on feature dispatch per operator)
`bd prime` in a fresh Claude Code session (or say "I am the Mayor now")
Open beads: 3

## What needs the operator now

**Holding on feature work per operator instruction.**
- **mayor-o2py (P2)** — CSR API (`certificates.k8s.io/v1`) CRUD + status write-back. New API surface — requires operator review before dispatch.
- **mayor-suf0 (P2)** — kube-controller-manager smoke test. Blocked on mayor-o2py.
- **mayor-2ni (P3)** — sonobuoy conformance audit (read-only). Operator has asked to hold on dispatch.

Say the word when ready to proceed with any of the above.

## In-flight

Nothing running. No open PRs.

## Recent progress (this session)

Coverage drive complete. 14 PRs merged (#131, #133, #135–#148), 13 beads closed.

Key wins:
- All apiserver handlers covered (authorization, namespaces, scale, generic, tokens, pods, cr)
- Binary crates extracted to lib.rs: scheduler, controller-manager, mcp-server
- CI/hook quality gates tightened: fmt check + clippy --tests added
- Dead serializer.rs removed
- scheduler/src/lib.rs: pure helpers extracted (parse_uri_parts, drain_watch_buffer, select_first_node), 25 tests
- handlers/cr.rs: 27 tests added, 67%→78%F coverage
- Overall workspace: 83.9%L / 79.9%F

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
