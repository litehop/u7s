# Dashboard
2026-08-14T09:24Z — Mayor session active (Claude CLI). Resume: `bd prime` → this file.

Stance: resource-optimized k8s, correctness → obs → perf, pre-alpha, merge-on-green.

## ▶ IN PROGRESS
- **mayor-j7wwq** on `lima-node-4`/6446 — Path A final verification: sonobuoy `--focus` CoreDNS + metrics-server. Verification-only, no code. Verdict either declares Path A complete end-to-end or surfaces a regression.

## 🟢 CI running (3 PRs, 0 failures)
- **#1166** (mayor-o1w23) — `do_patch` strategic-merge composite-key fix + CRD list-map-keys fix. UNSTABLE: 9 SUCCESS, 7 IN_PROGRESS (bench-rss × 3 + kubectl/kubelet/kcm version checks).
- **#1167** (mayor-6in12) — VM-ownership doc correction.
- **#1168** (mayor-t79kb) — mandatory inline-sync pattern, landed in `bootstrap.md` (correct home per worker's judgment).

## ✅ Merged this session (11 PRs — Path A COMPLETE)
- **#1155-1165** — P0 conformance regression firefight (24 fixes), observability (`odsv6`, `ukbhp` histogram), pinpoint-focus-gate doc (`5dxup`), Path A [3/3] CoreDNS (`60zfu`).

## Extended-context updates
- **`ai/extended-context/roadmap.md`** — Gate 7 (Migration story) added (operator-prompted): k3s→u7s control-plane migration + data-plane node conversion. Fires after Gate 6.

## Loop findings this cycle (09:22Z six-loop batch)
- Posture: fine.
- Hygiene: 0 orphans (host processes are legacy pre-session). 0 refs to prune (all 3 origin worker refs correspond to open PRs).
- PR merge: 3 open, all with CI still running, 0 failures. Merge next :43 or on-notification whichever comes first.
- Cluster review: no new beads.
- Bead dispatch: fired j7wwq (Path A verification, unblocked by #1165 merge). 88h1w / jtlnx / 0xbre held for next cycles.

## Standing loops
Confirmed reliable on Claude CLI (was broken in VS Code extension per anthropics/claude-code#86015). Posture :07, hygiene :23, cluster review :17,47, PR merge :13,43, bead dispatch :08,23,38,53, dashboard :04,19,34,49.

## Next after CI green + j7wwq returns
1. Merge #1166, #1167, #1168 on green.
2. Absorb j7wwq verdict — if green, Path A initiative can be declared verified end-to-end.
3. **`mayor-88h1w`** — reclaim watch-ring shards for deleted CRDs (design work; prerequisites landed).
4. **`mayor-jtlnx`** — verify `9sd51` fix eliminates 100% of KCM 410s.
5. **`mayor-0xbre`** — schema-driven encoder generation.

## bd memories banked this session (10)
`mayor-dashboard-timestamp-must-use-date-u`, `content-type-dispatch-must-key-on-apiversion-plus-kind`, `worker-brief-hypothesis-may-be-wrong-encourage-independent-diagnosis` (5×), `worker-must-not-end-turn-waiting-for-inner-background-task`, `evacuate-worker-run-artifacts-before-worktree-removal`, `u7s-global-revision-counter-not-per-object`, `sonobuoy-progress-reporting-is-inherently-lagged-by-design`, `claude-code-cron-loops-blocked-by-background-workers-in-stream-json-transport`, `operator-owns-no-vms-all-lima-slots-dispatchable`, `mayor-do-not-remove-worktree-until-worker-fully-terminated`.

## Repo state
- Branch: `main` at `bd1c238c`. Worktrees: 1 (mayor) + 1 (j7wwq). Open PRs: 3.
- VMs (all 6 dispatch-assignable): `lima-node` (6443, legacy processes bound), `lima-node-3` (6445, idle), `lima-node-4` (6446, j7wwq), `lima-node-5` (6447, idle), `lima-node-2` (6444, idle post-o1w23-reap). `lima-node-smoke` (6448) not provisioned.

## Live docs
- [`project-context.md`](ai/extended-context/project-context.md) · [`north-star.md`](ai/extended-context/north-star.md) · [`roadmap.md`](ai/extended-context/roadmap.md)
