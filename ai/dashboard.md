---
updated: 2026-11-17T15:10Z
---
# Dashboard — hand-off after 2026-11-17 (main `e074a92d`) — v0.4.5 out; next v0.4.6
**Stance:** alpha (no compat promise); correctness > security > perf > features; upstream 1.37.1 except secure crypto; queue merge on green, never `--admin`; security PRs drafted for operator.
**Resume:** paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons; `bd recall release-plan-v0-4-6`.

## 🎯 Waiting on you
1. (Optional) post the cri-o issue drafted in `temp/cri-o-issue-apparmor-stacked-peer.md`.

## ⏭ Next session → v0.4.6 once all three are on main and audit is green
- **`mayor-bekfa` (P1) cargo audit red on main**: chrono + chrono-tz newly "unmaintained" (RUSTSEC-2026-0543/0555), via u7s-apiserver and cel 0.16
- `mayor-1diau` pod MTU = NIC − 74/94 (beep Geneve); then notify beep mayor (earlier notice undelivered)
- `mayor-u015m` download_mirror status-branch tests, overall time cap, temp-file trap
- `mayor-na818` flannel from docker.io/flannel, digest-pinned
- then snapshot → `--confirm` 3/3 on pd-balanced → release

## ⏭ Later
`mayor-lwwze` AppArmor detector (design approved; doc on `worker/agent-a8ffaf53174ff3c38` @ `6c03cb34`) · `mayor-kyhhp` DNS on generic-kernel real installs · `mayor-6ftew` DRA delete · `mayor-06ha8` 2-node rig · epic `mayor-c12qi` watchdog · `mayor-ie064` Renovate pins · `mayor-g06uz` CRI-O 1.37.4 · `mayor-qnix7` · `mayor-xqog5` reviewer posting · #2068 mariadb.

## ✅ Session 2026-11-17
**v0.4.5 released** (`92562be8`, gate 3/3) · beep run 1 PASS · Conformance 452/462 · #2158 #2161 #2165 #2166 #2168 #2170 #2171 install/gate/rig fixes · #2169 relay hardening (deployed) · #2156 README alpha. Decisions in bead notes.

<!-- BEGIN AUTO: open-prs -->
- #2068 examples(mariadb): drop CPU limit, small InnoDB args (partial: first init still ~50% on e2-micro) (`worker/agent-a60ed75eb02f26db1`, CLEAN)
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a60ed75eb02f26db1` (`worker/agent-a60ed75eb02f26db1`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a8ffaf53174ff3c38` (`worker/agent-a8ffaf53174ff3c38`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/beep-903-run1` (`beep/903-run1`)
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
As of 2026-11-17T15:10Z — Branch `main` @ `e074a92d`.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->
