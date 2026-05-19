# Dashboard

2026-05-19T06:00 UTC
Session: agent-a41cc68f6aa51a2b1
Open beads: 12 (0 in flight)

## What needs the operator now

Nothing urgent. Argo CD gap analysis complete — 8 beads filed. See `ai/argocd-gap-analysis.md` for full detail and priority order.

## In flight

None.

## Open beads

| Priority | Bead | Title | Notes |
|----------|------|-------|-------|
| P2 | mayor-qde | Watch implementation | Needs design before dispatch — largest conformance gate |
| P2 | mayor-bph | networking.k8s.io/v1 missing | NetworkPolicy/Ingress; blocks Argo CD install |
| P2 | mayor-5d9 | admissionregistration.k8s.io/v1 missing | Webhooks; blocks Argo CD install |
| P2 | mayor-9xr | coordination.k8s.io/v1 missing | Leases/leader election; blocks Argo CD controllers |
| P2 | mayor-7ak | Strategic merge patch rejected | kubectl apply re-apply fails for all resources |
| P2 | mayor-5l4 | Watch on core/v1 Namespaces missing | Argo CD namespace discovery |
| P2 | mayor-cn8 | SubjectAccessReview/TokenReview missing | Argo CD SSO and per-user RBAC |
| P2 | mayor-uca | CRD /status subresource for CR instances | Argo CD application-controller status reporting |
| P3 | mayor-mti | Sonobuoy baseline | Blocked on mayor-qde (watch) |
| P3 | mayor-cw9 | Argo CD integration gap analysis | DONE — closing |
| P3 | mayor-9za | policy/v1 PDB missing | Lower priority; only affects HA Argo CD profile |
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
