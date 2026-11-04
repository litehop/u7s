---
updated: 2026-11-04T19:40Z
---
# Dashboard — session 2026-11-04 WRAPPED (main `46fdc109`, snapshot `v0.4.3-snapshot.4`)
**Stance:** pre-alpha, no users; conformance correctness > security > perf > features; match upstream 1.37.1 except secure crypto defaults; queue merge on green, never `--admin`. CI wall-clock is a ratchet.
**Resume:** `claude --settings .claude/settings.json`; paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons. Read `ai/extended-context/cert-rotation-and-release-gate-state.md` (#2109). No workers or VMs running.

## 🎯 Waiting on you
- **Burst-cliff mitigation** (`hjwdo`; gates the next snapshot). 1 GiB / 1 vCPU node wedges on a 40–50-pod burst (gate `n1-custom-1-1024`: 0/3 @50, 0/3 @40, `ltido`). Cause: page-cache thrash of control-plane file pages (`kutwm`). #2039 memory protection measured **worse** than main (`9ygmh`); no idle-memory regression across releases (`adwea`). Remaining levers: kubelet eviction thresholds, an observer-light knee measurement, smaller control-plane RSS (`vc844`); zram ruled out (10-16). Also: close #2039?
- `cosign` was installed on your Mac via Homebrew by a worker without asking — keep or `brew uninstall cosign`.
- Then cut the next snapshot (#2107's first full build + fresh-install check). Open calls: `vc844`, `yfca9`, `feature-tests`, `b6c59.1`.

## ⏭ Next
`hxuqo` (gate keeps evidence when a run wedges) · `wi3yg` (README prerequisites) · `vs7af` (rig/CI off pkgs.k8s.io before 12-29) · dual-stack `sy83n`, `5f4ey`, `l5wmt`.

## ✅ Done 2026-11-04
Conformance 460/460 + 2/2 · gate VM `n1-custom-1-1024` (#2105) · kubectl+CNI in tarball (#2107) · single→dual upgrade (#2100) · README verified live (#2106) · harness #2096 #2098 #2099 #2101–#2104 #2108 · `kutwm`, `adwea`, `9ygmh` measurements · state doc #2109.

## 📝 Decided 2026-11-04
Dual-stack > install > docs; IPv6-only → P4 epic `8w6at.10` · no backward compatibility; installer only adds its own files · GCP resources deleted when unneeded.

<!-- BEGIN AUTO: open-prs -->
- #2109 docs(extended-context): release-gate state as of 2026-11-04 (mayor-ydj1s) (`worker/agent-a6d13e8931fe4a4bf`, BLOCKED)
- #2068 examples(mariadb): drop CPU limit, small InnoDB args (partial: first init still ~50% on e2-micro) (`worker/agent-a60ed75eb02f26db1`, CLEAN)
- #2039 feat(install): protect control-plane memory (systemd slice MemoryLow + kubelet reserved/allocatable) (mayor-i4bvb) (`worker/agent-a7c2b61ba4bb75df8`, CLEAN)
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a60ed75eb02f26db1` (`worker/agent-a60ed75eb02f26db1`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a6d13e8931fe4a4bf` (`worker/agent-a6d13e8931fe4a4bf`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a7c2b61ba4bb75df8` (`worker/agent-a7c2b61ba4bb75df8`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/beep-903-run1` (`beep/903-run1`)
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
none (cancelled at hand-off 2026-11-04)
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
As of 2026-11-04T19:26:34Z (last tick) — Branch `main` @ `46fdc109`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->
