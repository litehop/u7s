# Dashboard
2026-05-27 00:00 UTC
Session: active — resume with `claude --continue` in /Users/balint.erdos/u7s
Open PRs: 1 (#269 CI running) | In-progress beads: 0 | Deferred: 5

## What needs the operator now

**e2e still 0/444 — but different reason now.**

Latest run was `--reset`, so apiserver generated a fresh CA. Kubelet holds old CA certs → `BadCertificate` storm → e2e pod TLS fails before any test runs. This is expected after `--reset`. The CA stability code in `tls.rs` is correct — it persists across non-reset restarts.

**Next step to get e2e running:** run sonobuoy WITHOUT `--reset` (reuse existing `temp/u7s/`). The CA will be stable, kubelet will reconnect with valid certs, and the e2e pod should succeed. Alternatively: after `--reset`, wait ~60s after `lima-start.sh` before running sonobuoy so kubelet can re-establish.

Also pending: #269 (EndpointSlices) — CI running, merge on green.

## Deferred
mayor-1rt1 (P1), mayor-52wo (P2), mayor-j7to (P2), mayor-6w76 (P3), mayor-rvkq (P3)

## Cluster review: no clusters.

## Deferred beads (not blocking)

| Bead | What | Priority |
|------|------|----------|
| mayor-1rt1 | lima-start.sh KCM documentation | P1 (deferred — may not be a real problem) |
| mayor-52wo | embed upstream OpenAPI v2 spec | P2 |
| mayor-j7to | Argo CD RBAC seed | P2 |
| mayor-6w76 | Pod proto decoder | P3 |
| mayor-rvkq | CRD CEL validation | P3 |

## Recent progress this session

| PR | What | Bead | Status |
|----|------|------|--------|
| #265 ✓ | TokenRequest spec.expirationSeconds | mayor-o30k | merged |
| #264 ✓ | spec.dnsPolicy defaults to ClusterFirst | mayor-grmb | merged |
| #263 ✓ | PUT /namespaces/{name}/finalize | mayor-trbl | merged |
| mayor-hgfr ✓ | prost proto decoders (already merged prior session) | — | closed/verified |

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first, performance-critical, kubectl-compatible API, minimal deps. Mayor merges on green CI automatically; flags security/API/architecture decisions first.
