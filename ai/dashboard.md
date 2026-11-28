---
updated: 2026-11-28T14:30 JST
---
# Dashboard — session 2026-11-28 closed, main `7a597847`
**Stance:** alpha (no compat); correctness > security > perf > features; upstream **1.37.3**; merge queue on green, never `--admin`; security PRs drafted for operator; no advisories while zero users.
**Resume:** paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons; `bd show mayor-gnceb`.

## 🎯 Next session, operator first
- **#2325** (`gnceb`, security, DRAFT, re-review GO): boon → `jsonschema` 0.63, Ecma262 syntax (operator: no hand-rolled regex rewriting; option C was not viable). Un-draft? On merge, close #2317 (`nq194`) as moot.
- **#2328** (`rz95x`, node-authz, DRAFT, LGTM): nodes GET their own ResourceSlices. Un-draft?

## ⏭ Ready follow-ups
- From today: `k48qg` PUT 409 upstream text · `2o546` #2328 router test · `c0wwu` pods/status op tests · `nxiev` STEP J size gate.
- Older: `xdw6u.13` PKI worker CA refresh (2-node) · `f6r49` `39838` `u73e2` `03nx2` · KCM Phase 1 · `cpebd` `yl4c1`.

## ✅ merged 2026-11-28 (10 PRs)
- **apiserver:** #2322 immutable-metadata 422/409 at the shared pin · #2326 its test tightening · #2329 JSON patch on pods/status.
- **node-authz:** #2321 nodes write only their own ResourceSlices.
- **KCM:** #2324 50-pod burst stage; Phase 0 PASS on all 3 stages; projection cap 35.99 MiB, WordPress-scoped (operator).
- **Tooling:** #2320 #2330 premise-check (bounded, explained, no false "already landed") · #2323 #2327 hygiene STEP J bd GC.
- **Deps:** #2319 Rust 1.100.1. **Ops:** bd store GC 1.3G → 523M, reads ~10× faster (`11t3x`).

<!-- BEGIN AUTO: open-prs -->
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->
