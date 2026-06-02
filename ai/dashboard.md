# Dashboard
2026-06-02T~17:00 — Phase 3 PR #395 in CI (6 checks pending); ready to merge when green

## Konnectivity sub-project status

| Bead | Title | Status |
|------|-------|--------|
| mayor-s1bs | Binary download script | ✅ merged #393 |
| mayor-0iwa | Mac-side server startup | ✅ merged #394 |
| mayor-0yoa | Lima VM agent startup | ⏳ PR #395 — 6 CI checks pending |
| mayor-6m1q | 20/20 confirm + debug log strip | 🔜 waiting on #395 |

## PR #395 — waiting for CI
- `feat(konnectivity): start konnectivity-agent in lima VM`
- MCP-verified: agent process confirmed running in VM, dialing `host.lima.internal:8132`
- Agent retrying (expected — server side was not yet up when tested)
- 6 checks still pending; no failures

## Sonobuoy scorecard

| Group | Result |
|-------|--------|
| AggregatedDiscovery | ✅ 4/4 |
| LimitRange | ✅ 2/2 |
| Exec WebSocket | ✅ 1/1 |
| SubjectAccessReview | ✅ 20/20 |
| ResourceQuota | ❌ needs retest |
| AdmissionWebhook | 🟡 19/20 — konnectivity fix in progress |
| FlowSchema | ❌ APF gap |

## Open PRs
- #395 — konnectivity agent in VM — ⏳ CI pending (0 failures)

## Next action
Merge #395 when green → dispatch mayor-6m1q (sonobuoy 20/20 + strip debug logs)

## Main at
`4281260` — feat(konnectivity): start server on Mac side (#394)
