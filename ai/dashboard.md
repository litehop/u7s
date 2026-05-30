# Dashboard
2026-05-30T~22:15 — No open PRs; no workers; dispatch queue empty; rebuild needed

Resume: rebuild → sonobuoy → triage new failures → dispatch

## What needs the operator now

**Rebuild + sonobuoy.** All pending fixes are on main (ae34275). The dispatch queue is exhausted for apiserver work — remaining beads are all node/KCM-side and won't yield new fixes without sonobuoy data.

```bash
cargo build --release -p u7s-apiserver
scripts/u7s-start.sh --background
```

Then run focus groups:
1. `SONOBUOY_FOCUS='should support remote command execution over websockets'` — exec (#360+#363)
2. `SONOBUOY_FOCUS='FlowSchema'` — APF defaults (#362)
3. `SONOBUOY_FOCUS='AdmissionWebhook.*deny pod and configmap'` — Secret proto (#361)
4. `SONOBUOY_FOCUS='SubjectReview.*SubjectReview API operations'` — RBAC (#358)

## In-flight workers

_None._

## Open PRs

_None. Main at ae34275._

## Fixes on main since last rebuild (ae34275)

| PR | What |
|----|------|
| #365 | chore: 9 upstream proto files added |
| #364 | fix: Container/ServiceSpec/PVSpec proto field tags corrected |
| #363 | fix: exec/attach use connect_async_tls_with_config (kubelet 400 fixed) |
| #362 | feat: seed default FlowSchemas + PriorityLevelConfigurations |
| #361 | fix: Secret type/stringData proto tags swapped |
| #360 | fix: with_upgrades() — exec/attach/portforward now actually run |

## Ready beads (all node/KCM-side — need sonobuoy to scope next work)

| Bead | What |
|------|------|
| mayor-dss4 | ResourceQuota not enforcing (KCM) |
| mayor-wqom | PreStop hook (kubelet) |
| mayor-7ppb | readiness probe delay (kubelet) |
| mayor-ve9f | DaemonSet scheduling (kubelet) |
| mayor-3y8r | ClusterDNS not configured (kubelet) |

## Stance
Pre-alpha/greenfield — break freely, correctness first. Mayor merges on green CI immediately.
