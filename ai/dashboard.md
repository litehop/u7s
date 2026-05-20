# Dashboard

2026-05-20T05:35 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 blocked)

## What needs the operator now

**WAITING — lima MCP wiring.** The previous session was blocked waiting for `.claude/settings.json` to be saved with the lima MCP config so Claude Code reloads it. Once that's done, mayor can drive sonobuoy autonomously.

Key facts about current state:
- The revert of the dns-preflight skip (1a5e527) means sonobuoy will fail on DNS check again — this was intentional if the fix was wrong, but needs follow-up
- Kubelet/crio runtime regression still undiagnosed (sonobuoy aggregator pod not starting)
- CA regenerates on every u7s restart, breaking kubelet trust — P2 bead candidate not yet filed

**Operator decisions needed:**
1. Is the dns-preflight revert intentional? If so, file a bead for an alternative approach.
2. Ready to file CA-persistence bead (P2)?

## Forward-looking

1. **lima MCP** — once active, mayor runs sonobuoy autonomously and triages failures into beads
2. **Sonobuoy aggregator pod** — kubelet/crio runtime regression to diagnose (needs lima MCP or manual triage)
3. **CA persistence** — CA regenerates on every u7s restart, breaking kubelet trust; needs a bead
4. **Sonobuoy triage** — failures → conformance-gap beads → worker dispatch
5. **mayor-xy2** — CR schema validation, deferred; re-evaluate at Argo CD milestone

With only 1 open bead (deferred/blocked), the backlog is cold. Mayor will HOLD on dispatch until operator resolves blockers above or files new beads.

## Recent progress

| Commit | What | Status |
|--------|------|--------|
| 1a5e527 | Revert sonobuoy dns-preflight skip | Just landed |
| 257912f | Dashboard: waiting on lima MCP | Previous session |
| 279ef31 | Add lima MCP server config | Previous session |
| 553bb2b | fix(sonobuoy): skip dns preflight | Reverted |

111 total beads closed. 0 open PRs. 202 tests passing.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
