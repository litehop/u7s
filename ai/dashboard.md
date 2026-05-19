# Dashboard

2026-05-19T08:55 UTC
Session: 96473ee9-26b3-4236-b9dc-1d311e5cee69
Open beads: 8 (4 in flight)

## What needs the operator now

Nothing urgent. All active work is in background workers.

## In flight

| Worker | Bead | Surface | Status |
|--------|------|---------|--------|
| aed6dc2b371a7d508 | mayor-mzf | ci.yml smoke job | Running |
| a5260701c9c04b637 | mayor-1qa | auth.rs + tls.rs | Running |
| a9c0cc1816fe48d9a | mayor-xld | crates/store | Running |
| a9e1dc8c1adffdad9 | mayor-837 | proto.rs + handlers | Running |

## Open beads

| Priority | Bead | Title | Notes |
|----------|------|-------|-------|
| P2 | mayor-mzf | Smoke job: curl for writes, kubeconfig heredoc fix | Worker in flight |
| P2 | mayor-1qa | x509 client cert auth | Worker in flight |
| P2 | mayor-xld | Global monotonic resourceVersion | Worker in flight |
| P2 | mayor-837 | Protobuf request bodies | Worker in flight |
| P2 | mayor-qde | Watch implementation | Unblocked but large — needs design before dispatch |
| P3 | mayor-mti | Sonobuoy baseline | Blocked on mayor-qde + mayor-xld |
| P3 | mayor-cw9 | Argo CD integration | Blocked on mayor-mzf |
| P3 | mayor-xy2 | CR schema validation | Deferred |

## Forward-looking

Once the 4 in-flight PRs land:
1. Smoke CI will be green end-to-end
2. kubectl will work with client cert credentials (x509 auth)
3. kubectl writes (create/apply) will work without workarounds (protobuf)
4. resourceVersion ordering conformance guaranteed
5. Next dispatch: **mayor-qde (watch)** — the single largest conformance gate. Needs a design pass before dispatching.

## Recent progress

Smoke CI job revealed 3 pre-existing bugs fixed this session:
- Axum route syntax `:param` → `{param}` (server couldn't start — mayor-7bw)
- kubeconfig certs encoded as DER not PEM (TLS verification failed — mayor-rcn)
- CA cert not in server TLS chain (clients couldn't verify server — tls.rs fix)
- x509 client cert auth missing (kubectl auth failed — mayor-1qa in flight)
- kubectl sends protobuf, server only speaks JSON (mayor-837 in flight)

Origin hygiene: 10 merged orphan branches deleted.

**Session totals:** 58+ beads closed, PRs #22–30 merged.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal deps. Merge on green CI automatically; flag security/API surface/architecture PRs for operator review first.
