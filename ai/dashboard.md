---
updated: 2026-11-27T16:43Z
---
# Dashboard — session 2026-11-27 closed, main `c02dcffb`
**Stance:** alpha (no compat); correctness > security > perf > features; upstream **1.37.3**; merge queue on green, never `--admin`; security PRs drafted for operator; no advisories while zero users.
**Resume:** paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons; read `ai/extended-context/conformance-vm-state-automation.md`; `bd show mayor-gnceb`.

## 🎯 Next session, operator first
- **`gnceb` (security, P2):** boon's ECMA pattern rewrite is quadratic and runs before the #2289 budget (8 KiB `\s` = 18 s; est. ~7 min CPU per CRD write). Pick a fix: own linear rewrite (recommended) / shorthand budget / per-CRD source cap.
- **#2317** (DRAFT, `nq194`): raises the pattern source cap to 2048 for a real Cilium CRD. Parked behind `gnceb`.
- Optional: re-baseline the KCM Phase 0 projection cap (33.4 → 35.99 on the 10-controller trim).

## ⏭ Ready follow-ups
- apiserver parity: `n3q2s` `f6r49` `zeghf` `39838` `u73e2` `03nx2`. KCM: `84rmv` burst stage, then Phase 1. Tooling: `cpebd` `yl4c1`.

## ✅ merged this session (27 PRs)
- **Security:** #2302 CR patch→delete RBAC bypass · #2289 CRD pattern budget · #2284 reserved pools.
- **Scheduler UID-safety:** #2295 #2304 #2306 #2309 #2311 #2315.
- **apiserver parity:** #2297 #2298 #2305 #2308 #2313 #2316 #2301.
- **Rig:** #2296 #2307 #2310 (VM state converts automatically) #2299 #2291 #2293.
- **KCM:** #2300 Phase 0 PASS (8.12 / 9.14 MiB). **Tooling/docs:** #2303 #2312 #2314 #2294.

<!-- BEGIN AUTO: open-prs -->
- #2317 fix(apiserver): stop rejecting real CRD patterns over 1 KiB; compiled-size budget is the bound (mayor-nq194) (`worker/agent-aa3198b3d75aec45b`, CLEAN)
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-aa3198b3d75aec45b` (`worker/agent-aa3198b3d75aec45b`)
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
As of 2026-11-27T16:42:32Z (last tick) — Branch `main` @ `c02dcffb`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->
