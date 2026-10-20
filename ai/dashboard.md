---
updated: 2026-10-20T03:12Z
---
# Dashboard — session 2026-10-20 (main `1b5a0399`)
**Stance:** pre-alpha; correctness (Conformance first) > security > perf > features; queue merge on green, never `--admin`. No GCP account/project in git.
**Resume:** `ai/prompts/mayor-bootstrap.md`; `bd prime`; crons: tick 15m, posture 60m, hygiene 60m.

## 🎯 Waiting on you
- **Pick:** `xdw6u.6.2` kubelet-serving IP-SAN tightening option (#1866 baseline accepted 2026-10-19)
- Classifier denies mayor `limactl stop`: stop idle VMs when flagged.

## ▶ In progress (wave 1, 02:35Z)
- `zkchq` PR #1905 REQUEST_CHANGES (system:monitoring lacks /healthz/* etc.) → fix round on lima-node-2
- `xojac` PR #1903 in merge queue; existing clusters keep the verbs until `tcewr`; drift `oua2n`
- `4xypz` #1902 · `ufcno` #1904: LGTM, CI re-running → queue on green; follow-ons `itfmm`, `7ahpf`
- ✅ `qgyz4` merged #1901 (`1b5a0399`); follow-on `2o37f`
- Bookkeeping PR (end of wave): delete stale finding `ai/findings/2026-10-15-mayor-3kp5u-…` (bead closed)
- Next: `d72sq` authz path decode (operator-approved 2026-10-19; then `60d7s`) · `rfet5` (snapshot.1 is out) · install.sh hardening (zboqh, fkj56, d07ct…) · PKI xdw6u.1→.7→.10 · admission (fg6oo, o985u…)

## Open PRs
<!-- BEGIN AUTO: open-prs -->
- #1905 apiserver(health): named checks with ?verbose, ?exclude and per-check paths (mayor-zkchq) (`worker/agent-a85432a06ca74aa88`, BLOCKED)
- #1904 apiserver(node-authz): scope node access to own csinodes, leases, resourceslices (mayor-ufcno) (`worker/agent-a3153efd2c080c0a4`, BLOCKED)
- #1903 apiserver(rbac): drop bind/escalate from seeded admin ClusterRole (mayor-xojac) (`worker/agent-ab723b3fbb707eabb`, CLEAN)
- #1902 apiserver(patch): strip SMP directives from new list elements and map values (mayor-4xypz) (`worker/agent-a3275223d520b8da9`, BLOCKED)
<!-- END AUTO: open-prs -->
## ✅ Merged since last dashboard (#1891–#1900)
#1893 aggregation guard kept strict + outbound_url tests · #1894 beep v0.6.0 default LB · #1895 Rust toolchain pinned to 1.99.1 · #1896/#1899 cloud-two-node.sh live-run fixes · #1897 KCM waits for CA on fresh install · #1898 kubelet webhook authz on install.sh clusters (SAR gate honours Node authorizer) · #1891/#1900 libc/tokio bumps.

## 🌲 Worktrees / hygiene
<!-- BEGIN AUTO: worktrees -->
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a3153efd2c080c0a4` (`worker/agent-a3153efd2c080c0a4`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a3275223d520b8da9` (`worker/agent-a3275223d520b8da9`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a81cfb6d11ef53025` (`fix2-1902`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a85432a06ca74aa88` (`worker/agent-a85432a06ca74aa88`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-aa7df380e9e0e3eed` (`worker/agent-aa7df380e9e0e3eed`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-ab723b3fbb707eabb` (`worker/agent-ab723b3fbb707eabb`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-af84b141d06f9c3c4` (`fix-1902`)
- `/Users/balint.erdos/litehop/u7s/temp/review-scratch/dash-beep` (`chore/dashboard-beep-rc`)
<!-- END AUTO: worktrees -->
## 🔁 Cron loops
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
## Repo state
<!-- BEGIN AUTO: repo-state -->
As of 2026-10-20T03:10:51Z (last tick) — Branch `main` @ `1b5a0399`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->
## 📋 Review queue
<!-- BEGIN AUTO: review-queue -->
1 pending review-queue entries.
<!-- END AUTO: review-queue -->
