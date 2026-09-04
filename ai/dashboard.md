# Dashboard
**2026-09-05 — ✅ SESSION WRAPPED.** main @ `db3c7ba7` (+3 servicelb PRs). #1567 (pa0ze Phase-3 keying, 4 review rounds) + #1568 (tk4ku memory sampler) MERGED; **#1569** (tk4ku ceiling recalibration 1→4 MiB) QUEUED — first action next session: confirm #1569 merged + close `mayor-tk4ku`. Resume: `bd prime` → this file.

**Stance:** pre-alpha/greenfield, break freely, correctness > security > perf > features, merge-on-green via native queue, `--admin` never.

## ✅ Merged this session
- **#1567** pa0ze eBPF Phase-3 conntrack keying (4 review rounds; occupant identity = `(front, client_port)`, sufficient because REV_FLOW key pins client_ip) · **#1568** tk4ku eBPF map-memory + loader-RSS sampler + CI gate. **#1569** ceiling 1→4 MiB queued.
- Prev sessions: #1561/#1566/#1563/#1565/#1564 (+ #1560/#1555/#1557/#1558/#1559/#1554).

## ⏭ Next / follow-ups
- **#1569** (tk4ku ceiling 1→4 MiB) QUEUED — confirm merged, then `bd close mayor-tk4ku`.
- **`de18e` now URGENT (bump from P3):** `ebpf-memory-smoke`/`ebpf-build` are NOT required checks — the queue merged #1568 with `ebpf-memory-smoke` RED (stale ceiling on real Phase-3 numbers). #1569 turns it green; de18e must make it *gating* so a red eBPF gate can't merge again.
- **`d9o3d`** (P3, from #1567 review): backend src-port remap re-derives every packet → LRU-eviction mid-connection port reassignment; deferred to Phase-4/`lrbvo` churn testing.
- **`j43cj`** (P3): pre-commit hook misses nested `crates/servicelb` fmt (root cause of the pa0ze round-2→3 red).
- **aie31.5** (L2-header) + **aie31.7** (tier-1 WireGuard) — downstream of #1567 (now merged), dispatchable. **aie31.3** doc-fix (map type + footprint → ~1.82 MiB).
- Bugs: `reset.sh --host-only` over-kills shared Lima net daemon (P2, `fbfi9`); #1561 RQ-scope-change no recount (P3); 17nj7 quota follow-ups (P3).

## 🚧 Operator decisions pending — eBPF Phase-4 (lrbvo)
- Tier-1 (2-Lima-over-WireGuard, local, `aie31.7`) is now dev work, NOT op-blocked. Only **tier 2/3 (real public-IP / IPv6-only fleet)** need provisioning. IPv6-only DESCOPED from MVP.
- Registry for the Phase-5 DaemonSet (`9gr0n`): GHCR OUT (IPv4-only); verify Docker Hub's IPv6-pull or self-host `zot`.

## 📋 Backlog (apiserver perf 17nj7)
- .9 (matching_shards), .10/.11 (watch), .12 (94 clone sites); hmv26 (ns-cascade). Keep disjoint from quota.rs/store.

## 📌 Standing decisions
- 17nj7 = opportunistic backlog (operator). Merge via native queue only; never `--admin`.
- eBPF CI = FULL-feasible on GH Actions (spike; de18e can gate the full harness). conntrack maps = LRU_HASH (shared, NOT PERCPU); **real Phase-3 per-node footprint ~1.82 MiB** (preallocated for 8192-entry FWD/REV_FLOW; the old ~21.5 KiB was the Phase-2 fixture).
- Phase 4 (lrbvo) deploys via the MANUAL Phase-1 loader, not the Phase-5 DaemonSet.

## 🔁 Cron loops
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
## Repo state
<!-- BEGIN AUTO: repo-state -->
As of 2026-09-04T15:35:14Z (last tick) — Branch `main` @ `6f1900e6`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->
## 🔎 Open PRs
<!-- BEGIN AUTO: open-prs -->
- #1567 feat(servicelb): Phase 3 conntrack full-tuple keying + backend src-port remap on conflict (mayor-pa0ze) (`worker/agent-accf25c8d059bab89`, UNSTABLE)
<!-- END AUTO: open-prs -->
## 📋 Review queue
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->

## 🌲 Worktrees / hygiene
<!-- BEGIN AUTO: worktrees -->
- `/Users/balint.erdos/u7s/ai/worktrees/agent-a4c1c8c1e57f056b2` (`worker/agent-a4c1c8c1e57f056b2`)
- `/Users/balint.erdos/u7s/ai/worktrees/agent-a69ad9d12880b2d17` (`worker/agent-a69ad9d12880b2d17`)
- `/Users/balint.erdos/u7s/ai/worktrees/agent-accf25c8d059bab89` (`worker/agent-accf25c8d059bab89`)
- `/Users/balint.erdos/u7s/ai/worktrees/agent-ae39ad21ff54d555c` (`worker/agent-ae39ad21ff54d555c`)
<!-- END AUTO: worktrees -->
