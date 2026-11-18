---
updated: 2026-11-18T13:35Z
---
# Dashboard — session 2026-11-18 closed (main `6f8b7d37`) — v0.4.7 released
**Stance:** alpha (no compat promise); correctness > security > perf > features; upstream 1.37.1 except secure crypto; queue merge on green, never `--admin`; security PRs drafted for operator; every release gated (agent runs burst + upgrade gates, operator pushes tags + approves publish).
**Resume:** paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons; `bd recall release-plan-v0-4-7`; `bd recall upgrade-policy-prev-release-only-until-prod`.

## 🎯 Waiting on you
1. (Optional) post the cri-o issue in `temp/cri-o-issue-apparmor-stacked-peer.md`.

## ⏭ Next — update story (migration `te4sn.5` after)
- `docs/upgrading.md` against the decided policy (Vale's first real use)
- `mayor-ur8p9` P2 SIGPIPE-prone pipes in ~30 non-test scripts (install.sh first) · `umkeu` P2 flannel restart on MTU change
- Then top-10 triage of the ~100 ready beads

## ⏭ Later
`oisst` version truncation · `umkeu` flannel MTU restart · `oisst` version truncation · `3l1se` · `wvd1p` · `ccwwb` · `uv9ga` · `5mqdd` · hygiene `gpud5`/`qh7ko` · later: `te4sn.5`, `8leyz` (12-17), `lwwze`, `kyhhp`, `6ftew`, `06ha8`, `c12qi`, `ie064`, `g06uz`

## ✅ 2026-11-18
**v0.4.7 released** 13:29Z (`d9e45502`; burst 3/3 + upgrade 10/10, `mayor-nhpl9`) · **v0.4.6 released** (`dec6f6e3`) · #2189 CI CNI plugins from pinned GitHub release, cached by digest (`6f8b7d37`) · #2181 advisory Vale lint (`d9e45502`) · #2186 SIGPIPE-safe test greps + guard · #2187/#2188 v0.4.7 changelog (`6d008d78` = snapshot commit) · #2183 upgrade check Lima+GCP (`6fab1015`) · #2185 CI eth0 → default-route NIC (`430a9d97`) · #2184 StatefulSet churn fix (`7aa44e32`) · #2182 store `user_version` (`b8789597`) · audits `4genk`, `fqktu` (archive tags) · #2180 #2176 #2177 #2175 #2174 #2173 · memories 380→326.

<!-- BEGIN AUTO: open-prs -->
None open.
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
None (no active worker worktrees).
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
As of 2026-11-18T13:19:42Z (last tick) — Branch `main` @ `6f8b7d37`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->
