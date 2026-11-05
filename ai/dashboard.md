---
updated: 2026-11-05T09:52Z
---
# Dashboard — session 2026-11-05 WRAPPED (main `abce1d43`)
**Stance:** pre-alpha, no users; conformance correctness > security > perf > features; match upstream 1.37.1 except secure crypto defaults; queue merge on green, never `--admin`.
**Resume:** paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons. Context: `bd show mayor-hjwdo` notes; `ai/extended-context/memory-management-state.md` (#2118). No workers or VMs running.

## 🎯 Waiting on you
- Gate burst size: 2026-10-15 decision says 80 pods; script and confirmation pass use 50 (else 40). Which?

## ⏭ Next
1. `f3yoo` (P1): the quiet-host check flags the gate VM's own thrash as contention — today's Lima "INVALID" runs were self-induced, not host load. Also corrects #2118's doc.
   `st8o2` (P1): probe timeouts make recovery unobservable on a starved node.
2. `pzhtd` (P1) experiment E on GCP: cap `kubepods.slice` via `enforceNodeAllocatable` (#2039's allocatable half) under the killable overload.
3. Overload/recovery gate criterion, targets from E. Follow-ons `y7xy9`, `xseef`, `pj20g`.

## 📝 Decided 2026-11-05
- #2039 stays open as draft. MGLRU `min_ttl_ms` and MemoryMin + early eviction did not help (weak evidence); systemd-oomd is the fallback.
- cosign stays a host prerequisite for gate builds from main.

## ✅ This session
#2113 contention INVALID regardless of outcome · #2114/#2115 evidence on wedge, stall abort, Lima VM trimmed to GCP parity · #2116 control-plane `OOMScoreAdjust=-997` · #2117 anon/file sampler + killable overload repro + recovery metric · findings tags for `18a8g`, `e5idl`, `g28ic`, `65y7s`, `j1ao0`.

<!-- BEGIN AUTO: open-prs -->
- #2118 extended-context refresh (auto-merge set) · #2068 mariadb example (partial) · #2039 control-plane memory protection (draft)
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
- Finished findings worktrees (tagged `archive/mayor-<bead>-findings`, safe to remove): 18a8g, e5idl, g28ic, 65y7s, j1ao0.
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
none (cancelled at hand-off 2026-11-05)
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
As of 2026-11-05T09:52Z — `main` @ `abce1d43`.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->
