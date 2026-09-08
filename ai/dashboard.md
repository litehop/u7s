# Dashboard
**2026-09-08T09:50Z — SESSION WRAPPED. Board fully clean: 0 PRs / 0 workers / 0 worktrees; local+remote = `main` only @ `33960fb5`. 7 PRs merged (#1622-27, #1629). Next mayor: re-bootstrap (recreates session-only crons), then pick from the non-eBPF backlog (the eBPF LB migrated to `litehop/beep`).** Resume: `bd prime` → this file.

## 🎯 Operator: nothing needs a decision right now
**eBPF ServiceLB migrated to `litehop/beep`** (2026-09-08, full history) — the `ebpf-build` required-check task (was `mayor-mmnr2`) and the whole `aie31` epic now live there; no eBPF item is a u7s operator task anymore. Branch backlog cleaned this session (33 remote → 1; 12 local → 1) — recurring remote-orphan sweep filed for hygiene (crashed-worker/closed-PR branches the merge-queue never deletes).

**Stance:** pre-alpha/greenfield, correctness > security > perf > features; merge-on-green via native queue, `--admin` never; plan-first.
**Crons:** tick `1a85cbfe` (15m) · reread `d0a587e3` (60m) · hygiene `3903f848` (60m) — session-only; tick+hygiene gather `ListAgents` → pass `--live-agents` (aq6ah). Hygiene fail-safes (exit 2) with zero workers by design; zero-worker orphan-reap gap tracked (bead).

## ✅ Merged this (mayor) session (7)
**#1629** roadmap refresh (2505→1490w; kubelet audit done, gate statuses, eBPF/perf — mayor-8qcaw P4→P2 follow-on in flight). **#1627** servicelb CI/hooks (7uyqb: path-conditional hooks + ebpf-build cargo-test; 1 fix round). **#1626** apiserver memory (17nj7.12: 111-site clone→borrow; −95% kubectl-get Table). **#1625** store (w871h caching; 17nj7.36 batched-fetch LIST). **#1624** servicelb P1 (aie31.14 POD_TARGETS gate, aie31.9 REV_FLOW-miss drop; 1 fix round). **#1622** store (0fg4q; 4fkee won't-do). **#1623** cleanup (89t1u + tbdwj). #1628 (d9o3d) CLOSED unmerged → aie31.17.
Pre-handoff WAVE 2 (#1614–1621, 7 PRs): core-ops liveness #1620, store LIST-bound #1621, quota-admission #1618, servicelb #1619, CR-quota #1617, store clone/cache #1616, eBPF docs #1614.

## 🧵 eBPF ServiceLB — migrated to `litehop/beep`
The eBPF load balancer (epic `aie31` + `f3ru5`/`9gr0n`/`lrbvo`/`tavxy`/affinity and the rest) moved to its own repo `litehop/beep` on 2026-09-08 with full git history; all eBPF work — critical path, gates, perf beads — is tracked there now, not here.

## ▶ IN PROGRESS
None — board clean, session wrapped.

## 🧷 Handoff loose ends (all tracked in bd)
- **mayor-8qcaw roadmap row** still shows P4/DEFERRED (should be P2/OPEN) — #1630 fix closed DIRTY on a stale base; new P4 bead filed to redo it cleanly from current main (trivial haiku).
- New hygiene/infra beads: remote-orphan branch sweep, `j70mp` (reset.sh reap gap), `211lc` (v1beta1 Table conformance).

## ⏭ Next candidates (plan-first)
Non-eBPF backlog (the eBPF LB now lives in `litehop/beep`): m10di, sm91b.6; v1.x: 17nj7.35.

## ✅ Merged last session (2026-09-07, 11 PRs #1603–#1613)
Cross-field defaulting, streaming LIST, eBPF #1611/1605/1609, store/quota #1610/1613. Prior (2026-09-06): #1594–#1601.

## 🔁 Cron loops
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
## Repo state
<!-- BEGIN AUTO: repo-state -->
As of 2026-09-08T09:42:08Z (last tick) — Branch `main` @ `b6acfb3e`, dirty, 0 ahead / 3 behind origin/main.
<!-- END AUTO: repo-state -->
## 🔎 Open PRs
<!-- BEGIN AUTO: open-prs -->
None open.
<!-- END AUTO: open-prs -->
## 📋 Review queue
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->
## 🌲 Worktrees / hygiene
<!-- BEGIN AUTO: worktrees -->
- `/Users/balint.erdos/u7s/ai/worktrees/agent-a9e8cdeabc88e04e8` (`worker/agent-a9e8cdeabc88e04e8`)
<!-- END AUTO: worktrees -->
