# Dashboard
2026-05-27 09:00 UTC
Session: active — resume with `claude --continue` in /Users/balint.erdos/u7s
Open PRs: 1 (#270 CI running) | In-progress beads: 0 | Deferred: 5

## What needs the operator now

**e2e 0/444 root cause identified and fix in CI.**

The chunking e2e test (`apimachinery/chunking.go:68`) creates ~400 PodTemplates in parallel via the Go client using `Content-Type: application/vnd.kubernetes.protobuf`. We had no PodTemplate proto decoder → 400 response → `Failf()` in goroutine without `defer GinkgoRecover()` → **panic kills entire Ginkgo process** → 0/444.

Fix is in PR #270 (PodTemplate proto decoder). Merge on green.

**Second known e2e issue (after panic is fixed):** `batch/v1.CronJob` POST from e2e pod returns 400 — same root cause (no batch proto decoder). See bead mayor-50f3. These will be individual test failures, not panics.

**To re-run e2e:** sonobuoy delete + re-run (can use `--reset` since that was never the problem). The `BadCertificate` entries in apiserver.log are from kubelet, not the e2e pod — the e2e pod CAN reach the apiserver fine.

## Deferred
mayor-1rt1 (P1 deferred), mayor-52wo (P2), mayor-j7to (P2), mayor-6w76 (P3), mayor-rvkq (P3)

## Open beads

| Bead | What | Priority |
|------|------|----------|
| mayor-50f3 | batch/v1 proto body decoding (CronJob POST → 400) | P2 |

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
| #270 | PodTemplate proto decoder (fixes e2e chunking panic) | mayor-edov | CI running |
| #269 ✓ | discovery.k8s.io/v1 EndpointSlices | — | merged |
| #268 ✓ | creationTimestamp stamping on namespace create | — | merged |
| #267 ✓ | Remove ANSI escape codes from apiserver log | — | merged |
| #265 ✓ | TokenRequest spec.expirationSeconds | mayor-o30k | merged |
| #264 ✓ | spec.dnsPolicy defaults to ClusterFirst | mayor-grmb | merged |
| #263 ✓ | PUT /namespaces/{name}/finalize | mayor-trbl | merged |

## Mayor process note
Investigation done directly this session (justified — needed diagnosis before dispatch). Implementation dispatched to worker for #270. Next session: dispatch workers immediately after diagnosis; don't stay in investigator mode past the point where the fix is clear.

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first, performance-critical, kubectl-compatible API, minimal deps. Mayor merges on green CI automatically; flags security/API/architecture decisions first.
