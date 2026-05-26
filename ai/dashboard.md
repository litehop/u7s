# Dashboard
2026-05-26 06:21 UTC
Session: 77df47c6-8519-40b9-ab7b-8df161b2a86d
Open beads: 4 (2×P1, 2×P2)

## What I need to do next

**Run sonobuoy** — conditions merge fix is on main. This is the gate for mayor-gtue (0 tests run). The root cause was confirmed: kubelet heartbeat patches were replacing the whole conditions array last-write-wins, dropping `status:"True"` from the Ready condition. BeforeSuite saw zero schedulable nodes and aborted. Fix is landed.

```bash
scripts/conformance/run-all.sh --reset
```

**mayor-gtue** should auto-close once sonobuoy shows tests actually executing. If it still shows 0 tests, the conditions fix didn't take — restart the apiserver first so it picks up the new binary.

**mayor-f44c + mayor-jz57** — pod log 500 and kubelet client cert 401 — both touch the log proxy and kubelet auth surface. Related. Flag before dispatching (auth surface).

**mayor-ahrc** — sonobuoy retrieve timing fix. Low urgency until sonobuoy is running end-to-end; then dispatch.

No operator decisions pending.

## Forward-looking

After sonobuoy confirms tests are executing: triage actual failures → file beads → next dispatch wave.

Expected failure surface based on what we know:
- Pod log proxy (mayor-f44c / mayor-jz57) — retrieve and `kubectl logs` both broken
- Any conformance tests that exercise exec/attach (same proxy path)
- Unknown failures from the test run itself

mayor-f44c and mayor-jz57 share the log proxy surface — candidate for a cluster dispatch once sonobuoy gives us the full failure list.

## Recent progress

**This session: 8 PRs merged, 6 P2 beads closed, 1 P1 bead closed (mayor-2wi0).**

| PR | What landed | Beads |
|----|-------------|-------|
| #251/#255 | rusqlite 0.40 (renovate, twice due to bad revert cycle) | — |
| #252 | Node proxy subresource | — |
| #253 | SelfSubjectAccessReview 415 fix | mayor-2duz |
| #254 | Table response for `kubectl get` | mayor-1wjo |
| #256 | Watch stream defaults + namespaced collection DELETE | mayor-s2i6, mayor-k2g6 |
| main | conditions merge key (`type`) for strategic-merge-patch | mayor-2wi0 (P1) |
| main | Remove unused PodStatus struct | — |

**Root cause of 0 tests in sonobuoy diagnosed and fixed:** kubelet sends heartbeat-only status patches every 10s that omit `status`/`reason`/`message` for stable conditions. Without `type` as the SMP merge key, the whole conditions array was replaced last-write-wins on each heartbeat. Ready condition lost `status:"True"`. e2e BeforeSuite saw 0 schedulable nodes → 444 tests skipped in 100ms.

Also: local Rust upgraded to 1.95.0 (unblocking future pushes).

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first, performance-critical (RSS/latency hard targets), kubectl-compatible API surface, minimal deps. Mayor merges on green CI automatically; flags security/API/architecture decisions first.
