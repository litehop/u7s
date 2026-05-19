# Dashboard

2026-05-19T11:30 UTC+9
Session: mayor-phase3-start — resume by opening Claude Code at /Users/balint.erdos/u7s
Open beads: 18 (17 Phase 3 + 1 tooling bug)

## What needs the operator now

**Worktree settings.json issue** (see below) — needs a decision on fix approach before the next worker dispatch.

No other operator decisions needed. The 15m dispatch loop will start firing workers against the new bead backlog.

## Worktree issue — what happened and what to do

**What happened:** Two consecutive background agents were dispatched for the Phase 3 audit. Both failed, getting hijacked by the `fewer-permission-prompts` skill. Root cause: background agents (Agent tool) run in a sub-session that does NOT inherit `.claude/settings.local.json`. The project's allowlist (`bd *`, `find *`, etc.) is in `settings.local.json`. When the agent hit a permission prompt for `bd` or `find`, the skill intercepted and tried to scan `~/.claude/projects/` instead of doing the audit.

**How it was resolved:** Audit was run in-session (mayor read all files directly). No worker worktree was needed.

**How to automate this away:** Two options:
1. Move the allow entries from `settings.local.json` into `settings.json` — this file IS shared with sub-sessions. Risk: `settings.json` is checked into git; the allow list becomes visible to anyone who clones the repo.
2. Keep `settings.local.json` but add a preamble to every worker dispatch that explicitly grants the needed permissions via the worker's own tool-call pattern (less clean).

**Bead filed:** mayor-srk — tracks this with the root cause documented.

**Recommendation:** Move the allow list to `settings.json`. This is a dev-tooling repo with no secrets in the allow list. The tradeoff (visibility in git) is acceptable.

## Phase 3 bead backlog (18 open)

| Priority | Bead | Title |
|----------|------|-------|
| P1 | mayor-srk | Worker agents don't inherit settings.local.json permissions |
| P1 | mayor-4z5 | Watch not implemented for generic resources |
| P1 | mayor-vgr | RBAC index not populated from store on startup |
| P1 | mayor-f28 | RBAC index not updated when roles/bindings written via API |
| P1 | mayor-n9a | SA JWTs minted but never validated on inbound requests |
| P2 | mayor-6wk | Discovery serverAddress hardcoded to 127.0.0.1:6443 |
| P2 | mayor-8sb | watch verb missing from all discovery resource lists |
| P2 | mayor-5nv | Cross-namespace pod list (GET /api/v1/pods) returns 404 |
| P2 | mayor-weh | authorization.k8s.io and authentication.k8s.io missing from /apis |
| P2 | mayor-d01 | Scale subresource missing for Deployments/ReplicaSets/StatefulSets |
| P2 | mayor-j55 | namespaces missing from /api/v1 discovery resource list |
| P2 | mayor-u9f | CRD support — required for Argo CD milestone |
| P3 | mayor-0fb | Deduplicate RFC3339 time formatting (3 copies) |
| P3 | mayor-bfu | pods.rs duplicates resource version parsing |
| P3 | mayor-aqv | Remove dead key_prefix() stub from store |
| P3 | mayor-2ae | Add max watch duration |
| P3 | mayor-3w7 | Scaffold crates/scheduler (DB-04) |
| P3 | mayor-2hu | Controller manager SA token provisioning (DB-05) |

## Forward-looking

**Next dispatch wave:** The 15m loop will pick up the P1 beads. Likely first cluster:
- mayor-vgr + mayor-f28 (same surface: state.rs + generic.rs RBAC wiring) — dispatch together
- mayor-n9a (auth.rs — solo, security-adjacent, should flag for review)
- mayor-4z5 (generic.rs watch — large feature, solo dispatch)

**Worktree fix first:** Resolve mayor-srk before dispatching workers, otherwise agents will fail again.

## Active loops

| Job ID   | Cadence | Purpose                              |
|----------|---------|--------------------------------------|
| 793b83d0 | 60m     | Re-read bootstrap + stance reminder  |
| b2799068 | 15m     | Dispatch ready beads                 |
| 6b5804b9 | 30m     | Cluster same-surface beads           |
| e62ccb63 | 60m     | Worktree hygiene sweep               |
| 6c144cb1 | 30m     | Merge green PRs                      |
| b614e568 | 10m     | Update this dashboard                |

## Recent progress

Phase 3 audit complete — 18 beads filed from in-session read of all 17 .rs files. Findings: 5 HIGH (correctness/security), 8 MED (missing features), 5 LOW (cleanup). Key surprises: RBAC index is never populated from store on restart (open cluster after every restart) and SA JWTs are minted but never verified.
