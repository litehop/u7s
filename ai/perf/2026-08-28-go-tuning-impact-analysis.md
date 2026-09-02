Bead: mayor-2z1no

# Go-Runtime Tuning Impact Analysis (Round-1 vs pre-tuning baseline)

## Verdict

Round-1 tuning (GOMEMLIMIT=200MiB/GOGC=50/GOMAXPROCS=2) reduced peak RSS on
all three components under a real full-conformance load, scaled roughly to
each component's heap size: kubelet -42% (huge), KCM -15% (moderate),
kube-proxy -7% (small but real, not a wash as mayor-kujf3 worried). No
component regressed. No sonobuoy test flipped pass->fail; no OOM/eviction
signal in any log.

## Data reconciliation note

Commit merge timestamps are **not** reliable tuning-cutover markers — dirty
worktrees ran the tuned tuple on live VMs before each PR merged (confirmed:
`0819-0255-conformance` and `0820-0510-conformance` already show tuned
kubelet/KCM despite predating the 0179712d/073a5974 merge commits). Ground
truth used instead: each run's `host-logs/{kubelet,kcm,kube-proxy-*}.log`
"Golang settings" line (`GOGC=`/`GOMAXPROCS=` populated or blank).

- **True pre-tuning baseline** (all three blank): `0813-1502-conformance`,
  `0814-0434-conformance`, `0818-1112-conformance` — same `rss.csv` schema
  as the fresh run. Used `0818-1112` (closest to Round-1 start) as primary,
  other two as range-check.
- **Post-tuning, all three applied**: `0828-1013-conformance` (fresh run,
  confirmed via grep — kubelet/KCM/both kube-proxy units all show
  `GOGC="50" GOMAXPROCS="2"`).
- **Intermediate checkpoint**: `0827-1443-conformance` (kubelet+KCM tuned,
  kube-proxy still untuned) — exactly reproduces the bead-cited figures
  (kubelet 125.7MB, KCM 109.2MB, kube-proxy 53.3MB), confirming that's where
  those numbers came from.

## Per-component numbers

| Component | Pre-tuning peak RSS | Post-tuning peak RSS | Delta | Source |
|---|---|---|---|---|
| kubelet | 204.3MB (`0818-1112`); range 204–222MB across 3 pre runs | 118.0MB (`0828-1013` fresh) | **-86MB (-42%)** | `monitoring/rss.csv`, comm=kubelet, max(rss_kb) |
| KCM (kube-controller) | 132.3MB (`0818-1112`); range 130–137MB | 112.8MB (`0828-1013` fresh, one transient tick); 109.2MB (`0827-1443` checkpoint) | **-19.5MB (-15%)** | `monitoring/rss.csv`, comm=kube-controller |
| kube-proxy | 52.7MB (`0818-1112`); range 51–53MB; 53.3MB in the kube-proxy-still-untuned `0827-1443` checkpoint | 48.9MB (`0828-1013` fresh, both nodes tuned) | **-3.8MB (-7.2%)** | `monitoring/rss.csv`, comm=kube-proxy, max across both node scopes |

GC/pressure signal: none. No OOM, no eviction-manager trigger, no crash in
any host-log across the fresh run. KCM's peak (115.48MB at 10:02:39Z) is a
single-tick spike back to ~110–111MB immediately after — the same GC-lag
signature already documented in mayor-iefj5/mayor-kagyg, not new behavior.

Sonobuoy: fresh run and `0827-1443` both 0 failures / 7616 tests (483
non-disabled specs). The true pre-tuning baseline `0818-1112` had 2
failures — pre-dates tuning entirely, so not tuning-caused; if anything,
post-tuning is cleaner, not worse.

Wall-clock: fresh ginkgo suite time 1497.9s (~25.0min) vs pre-tuning
`0818-1112` 1449.9s (~24.2min) vs intermediate `0827-1443` 1699.1s
(~28.3min). No monotonic trend — spread exceeds anything attributable to
GOMAXPROCS=2; treat as noise, not a tuning-caused slowdown.

**Round-2 KCM 128MiB target (mayor-xpxj5):** the pre-tuning 109MB citation
undersells the real peak slightly — two tuned full-conformance samples show
109.2MB and 112.8MB (transient 115.48MB), a ~3–6MB run-to-run spread. 128MiB
(134.2MB) still clears the observed transient peak by ~19–25MB, so the
target looks reasonable but is based on only 2 full-run samples — not
"stable" in the sense of many repeats, just consistently under threshold so
far.

**kube-proxy 53.3MB baseline (mayor-kujf3):** confirmed accurate — it's the
pre-kube-proxy-tuning peak from `0827-1443`. Post-tuning fresh run shows
48.9MB, a real (not noise-level) 7.2% drop. The tuple is not miscalibrated
or wasted on kube-proxy's smaller heap; it's just proportionally smaller,
as expected.

## Follow-on beads to file

- Before locking Round-2 KCM GOMEMLIMIT=128MiB (mayor-xpxj5), run 1-2 more
  full-conformance repeats to firm up the peak estimate beyond n=2 samples.
- mayor-kujf3 should stay open for its own acceptance criteria
  (EndpointSlice sync-latency / IPVS correctness) — this pass only confirms
  RSS improved, not kube-proxy's functional correctness under the tuple.
- Bank a bd memory with these 5 runs' tuned/untuned peak RSS figures
  (full-conformance-scale, not just 31-pod-cycle) so future tuning rounds
  don't have to re-derive the pre/post baseline from scratch.
- `monitoring/kcm-metrics-*.prom` scrapes in the fresh run contain no
  `process_resident_memory_bytes` or `go_memstats_*` series (grep came back
  empty) — worth checking the scrape config/port if Round-2 wants
  Prometheus-native memory data instead of ps-based rss.csv.

## Confidence

Medium-high. Based on 5 full-conformance runs with identical `rss.csv`
schema and per-run log-verified tuned/untuned state (not inferred from
commit dates). Would raise confidence: more tuned-KCM full-run samples (n=2
today) before finalizing 128MiB, and an actual EndpointSlice-sync-latency
measurement for kube-proxy rather than RSS alone.
