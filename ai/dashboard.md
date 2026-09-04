# Dashboard
**2026-09-04 04:37Z — ⏸ WRAPPING (operator switching networks — API calls may drop).** main @ `ecab3a48` (#1555 queued). Resume: `bd prime` → this file.

**⚠️ WRAP DIRECTIVE (until operator says otherwise):** do NOT dispatch new workers. Let the 3 in-flight workers land; for each PR: review → merge if LGTM, or reopen-the-bead-and-record on needs-changes (do NOT start a fix round — that leaves a worker at risk during the network switch). Wrap is done when: no active workers, git state clean/pushed, dashboard current. Then it's safe to switch.

**Stance:** pre-alpha/greenfield, break freely, correctness > security > perf > features, merge-on-green via native queue, `--admin` never.

⚠️ **lima-node MCP failed** this session (`-32000`); workers use `limactl shell` fallback. VMs: node-4=6dj51.5 fix, node-2=17nj7.4 fix; free node-3/5/smoke.

## 🔎 Needs next session
- **#1556** (17nj7.4, DRAFT) — ⚠️ **3rd rejection; REOPENED, NOT re-dispatched (wrap).** The childless-root fix reintroduced UNBOUNDED growth (fold-target insert at sqlite.rs:308-331 has no cap re-check → map never shrinks). Needs a **design rethink**, not another patch — full root-cause in bead notes. Branch durable on origin.
- Review follow-up beads filed: **d5skc** (6dj51.5/#1555 nits), + one for 17nj7.3/#1560 (delete_namespace_scoped_crds evict gap).

## ▶ IN PROGRESS (1 perf) — LAST of the wrap set
- **17nj7.5** (a0284, node-3) — incremental ResourceQuota counter, end per-admission O(n²) namespace rescan. quota.rs + resource.rs.
- **swg4h** — operator-owned: reruns Conformance + csi-hostpath e2e at session wrap.
- Held (NOT dispatched, wrapping): **17nj7.8** (find_crd), pa0ze, scheduler .6/.18, etc.

## ✅ Merged this session (6)
- **#1560** 17nj7.3 CrConversionCache leak+bound · **#1555** 6dj51.5 scheduler CSI race · **#1557** g7jh2 eBPF Phase 2 (unblocks pa0ze) · **#1558** 17nj7.2 RBAC ns-purge (sec) · **#1559** 17nj7.1 metric-DoS (sec) · **#1554** cleanup.

## 📋 Next up (opportunistic, once main advances / VMs free)
- **perf 17nj7** (opportunistic backlog per operator): clean+ready now → `.5` (quota recount, quota.rs), `.8` (find_crd, crd handler). After #1558 → `.3` (CrConversionCache, ns cascade). After #1555 → scheduler `.6`/`.18`. `.7` folded into 6dj51.5. `.12` (94 clone sites) solo in a quiet window.
- **eBPF L3** after #1557 merges (unblocks Phase 3): pa0ze; also g3lag, bguco.
- standalone: **2t1g1**, **xiovg**. **dq1gf** (VM rename) P3 no-auto-dispatch.

## 🟢 Deferred / gated
- decision-gated: sm91b.6, 0qjgc, 90qvg. epics: aie31 (Ph1-2 landing), sm91b, 8qcaw, s82zr. release-coupled (1.37): 1n9eu, 9xsn3. held: ujqtt, tnzdi, bhih0, 1y0h6, 44jyu, hm02b, t8ucq, r871h. elmno DEFERRED.

## 📌 Standing decisions
- **17nj7 = opportunistic backlog, NOT deferred** (operator) — dispatch by priority + scope + conflict-risk.
- Merge via native queue only (bare `gh pr merge`); never `--admin`.
- Phase 4 (lrbvo) deploys eBPF via the MANUAL Phase-1 loader, NOT the Phase-5 DaemonSet (clarified in lrbvo/aie31 notes).

## 🔁 Cron loops
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
## Repo state
<!-- BEGIN AUTO: repo-state -->
As of 2026-09-04T08:35:41Z (last tick) — Branch `main` @ `02ea37d6`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->
## 🔎 Open PRs
<!-- BEGIN AUTO: open-prs -->
- #1561 perf(apiserver): incremental ResourceQuota usage counter to end the per-admission O(n) namespace rescan (mayor-17nj7.5) (`worker/agent-a0284015530e21610`, BLOCKED)
- #1556 fix(store): bound reclaimed_horizons and de-linearize watch-open horizon lookup without horizon-eviction regression (mayor-17nj7.4) (`worker/agent-a2f40b04fb9d1c092`, BLOCKED)
<!-- END AUTO: open-prs -->
## 📋 Review queue
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->

## 🌲 Worktrees / hygiene
<!-- BEGIN AUTO: worktrees -->
- `/Users/balint.erdos/u7s/ai/worktrees/agent-a0284015530e21610` (`worker/agent-a0284015530e21610`)
- `/Users/balint.erdos/u7s/ai/worktrees/agent-a2f40b04fb9d1c092` (`worker/agent-a2f40b04fb9d1c092`)
<!-- END AUTO: worktrees -->
