# Dashboard

2026-05-19T05:20 UTC
Session: 96473ee9-26b3-4236-b9dc-1d311e5cee69
Open beads: 4 (0 in flight)

## What needs the operator now

**PR #33 (x509 auth)** — merged per operator approval. Smoke CI on main will run shortly; result unknown.

## In flight

None — all workers complete.

## Open beads

| Priority | Bead | Title | Notes |
|----------|------|-------|-------|
| P2 | mayor-qde | Watch implementation | Needs design before dispatch — largest conformance gate |
| P3 | mayor-mti | Sonobuoy baseline | Blocked on mayor-qde (watch) |
| P3 | mayor-cw9 | Argo CD integration | Unblocked now that smoke CI is stable |
| P3 | mayor-xy2 | CR schema validation | Deferred |

## Forward-looking

With the 4 in-flight PRs all merged:
1. **Smoke CI**: green end-to-end with pure kubectl (no curl workaround)
2. **x509 auth**: kubectl works with client cert credentials from generated kubeconfig
3. **Protobuf**: kubectl writes (create/apply) work natively
4. **resourceVersion**: global monotonic ordering confirmed
5. **Next dispatch**: **mayor-qde (watch)** — design pass first, then dispatch

## Recent progress (this session)

All previously in-flight PRs landed:
- PR #31: smoke CI fixes (TLS cert chain, kubeconfig PEM encoding, token auth)
- PR #32: global monotonic resourceVersion test (store already correct)
- PR #33: x509 client cert auth — CN→username, O→groups, mTLS optional
- PR #34: protobuf request decoding — magic bytes + Unknown envelope, zero new deps

Smoke CI: first green run end-to-end (test + smoke both passing on main push).

Worktree/branch hygiene: 1 branch, 1 worktree (main only). All orphans cleaned.

ci.yml: reverted curl workaround — now uses kubectl throughout since protobuf is implemented.

**Session totals:** 54 beads closed across sessions, PRs #21–34 merged.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal deps. Merge on green CI automatically; flag security/API surface/architecture PRs for operator review first.
