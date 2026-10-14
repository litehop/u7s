---
updated: 2026-10-13T09:41Z
---
# Dashboard — SESSION WRAPPED (2026-10-13 18:41 JST, main `65ceb945`)
**Stance:** pre-alpha/greenfield; correctness (esp. Conformance) > security > perf > features; merge-on-green via queue, never `--admin`.
**Resume:** `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register 3 crons (pass BARE hex ids to `--live-agents`); `git restore --staged --worktree .beads/issues.jsonl` if it blocks, then `git pull --ff-only origin main`.

## ▶ First thing next session
1. Confirm **#1749** landed (cascades → KCM GC + namespace finalizers on all 5 create paths; conflict with #1752 resolved, 61/61 GC/Namespaces/Watchers; auto-merge armed at wrap, CI re-running). Pull; reap its worktree `agent-a2bf025b16f9598ea`.
2. **Full 1.37.1 conformance on main** (everything from today in: #1741, #1748, #1749, #1752…). Last full: 490/497 on #1749's pre-#1748 build — the 7 CTB fails are explained by #1748; baseline 461/462.
3. `cr.rs`/admission wave: `mxjh5` (P2, CR validation before mutating webhooks) · `r3ax1` (P2, NamespaceLifecycle admission) · `nore3` (P2, CRD delete may orphan CRs) · `mvkgo` (P3, CR create keeps client status).
4. 1 GiB VM session on a quiet host: `w898x` (KCM/kubelet memory buckets → unblocks `vc844`) + `5icnm` (why CoreDNS requests made the 80-pod burst 0/3; capacity math first).
5. Small/no-VM: `lgb33` (tick exits 1 when bead JSONL blocks pull) · `ncrw4` (flaky apiserver lib test) · `bdd4r` · `gzr5h` · `z2hw2` · `tzrzt` · `yw312`.

## 🎯 NEEDS OPERATOR
- None. `vc844` waits on `w898x`.

## ✅ Landed this session (24 PRs + #1749 pending)
- **Conformance/correctness:** #1748 mTLS regression (WATCH ignored `spec.signerName`) · #1752 one per-kind field-selector table for LIST+WATCH, 400 on unsupported labels · #1741 CRD rule fidelity (3 rounds) · #1740 path segments + generation on update · #1745 CR status after webhooks · #1744 PCR proof-of-possession (security) · #1737 CEL int binding · #1736 KCM storage-version-migrator.
- **Tooling/docs:** #1753 install.sh heredoc fixes (silent empty `rm -rf`) + 1 GiB docs · #1754 tick git ops → REPO_ROOT · #1750 kubelet-port drift fail-loud · #1751 tick tests fail-on-revert · #1746 retired-findings facts · #1743/#1738 git-guard · #1742 resolvConf fail-loud · #1739 `--live-agents` prefixes · deps #1731–#1735, #1747 · #1755 bead snapshot.
- **No PR:** beep v0.4.0 = ship-candidate (`re973`; next-release re-eval `da224`; klipper-lb rejected) · `p2k2s` audit (tag `archive/mayor-p2k2s-findings`) · `xiovg` closed (173 legacy findings retired).

## 🧠 Banked / lessons
`memories-for-operational-guidelines-not-point-in-time-facts` · `reevaluate-owned-dependencies-each-release` · `lima-mcp-connects-only-after-its-vm-starts` · profiling memory updated. Process: hold a PR as DRAFT when its review LGTMs but a fix round is still needed (the tick auto-queues approved PRs) · overlapping-surface PRs collide in the merge queue — merge main into the second after the first lands.

## 🔎 Open PRs
<!-- BEGIN AUTO: open-prs -->
#1749 (auto-merge armed; CI re-running on the merge commit)
<!-- END AUTO: open-prs -->
## 🔁 Cron loops
<!-- BEGIN AUTO: cron-loops -->
CANCELLED at wrap (session-only). Re-register on resume.
<!-- END AUTO: cron-loops -->
## Repo state
<!-- BEGIN AUTO: repo-state -->
2026-10-13T09:41Z — `main` @ `65ceb945`. Local `.beads/issues.jsonl` re-exported after the snapshot (discard before pull). VMs: lima-node-2/3/5/smoke running, lima-node-4 re-provisioned; no host stacks.
<!-- END AUTO: repo-state -->

## 📋 Review queue
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->

## 🌲 Worktrees / hygiene
<!-- BEGIN AUTO: worktrees -->
`agent-a2bf025b16f9598ea` (#1749 branch holder) — reap after merge.
<!-- END AUTO: worktrees -->
