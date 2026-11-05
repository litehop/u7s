---
as_of: 2026-11-05
kind: initiative-state
---

# Memory management state

**AS OF 2026-11-05** (see `ai/extended-context/README.md` for the refresh
cycle).

## 1 GiB burst gate (mayor-hjwdo)

**A 1 GiB / 1 vCPU node wedges under a 40-50 pod burst. The leading,
supported explanation is a headroom cliff: with no swap only file pages are
reclaimable, so pressure evicts control-plane code and the node
refault-thrashes. Which mitigation ships is undecided.**

Caveats: evidence is n=1 per run, every 2026-11-05 Lima run was INVALID for
host contention, and the mechanism is unconfirmed on GCP.

Evidence for the mechanism (mayor-kutwm, mayor-6bw98/36soz via #2117):
- A killable 30x25 MiB BestEffort overload shows the `MemAvailable` drop is the
  overload's own anon, paid for by evicting file cache. Control-plane
  anon/slab/pagetables stay ~flat; control-plane `Pss_File` -> 0, then
  refaults (Lima, n=1).
- In the Lima #2039 A/B, pre-burst `MemAvailable` predicted the knee
  regardless of arm. A trimmed Lima VM (-60-70 MiB idle) passed a 50-pod
  burst that wedged before (#2115); knees were 20 observed / 40-50
  unobserved.
- Symptom differs by platform: GCP pd-standard showed ~95% iowait in the
  gate wedge (ltido); Lima shows ~100% sys CPU with iowait ~0 (#2114 live
  run). The GCP overload run G1 did not recover (PSI full 61%, iowait 54%).
- The kernel OOM killer does fire, ordered by `oom_score_adj`: pods die
  first, killed BestEffort pods restart-loop and the node never recovers
  (L2: 26 kills). One Lima run froze ~380 s with no kill (L1).
- Recovery therefore appears to need an earlier pressure-driven kill/evict
  trigger and back-pressure against restart/replacement.

Disproven (do not re-investigate):

| Claim | Evidence |
|---|---|
| ~5 MiB/pod burst cost | settled <~1 MiB/pod (Lima 0.4-0.5); transient not captured (mayor-e5idl) |
| u7s idle regression | none; the ~100 MiB was observer load (mayor-adwea) |
| Lima-specific u7s bloat | Lima +75 MiB is guest daemons, trimmed by #2115 (mayor-18a8g) |
| concurrent control-plane growth in bursts | control-plane anon/slab/pagetables ~flat (Lima, n=1, mayor-6bw98) |
| MemoryLow-only (#2039) | knee 20 on both arms in observer-matched runs; secondary metrics (MemAvailable min, mem PSI) worse on the PR (mayor-9ygmh, corrected in PR body) |

Tried, did not help (weak evidence):
- MGLRU `min_ttl_ms=1000` made the wedge worse (killed apiserver/KCM), but
  only on the tmpfs `--mem-hog-mib` repro, which is not representative
  (mayor-65y7s).
- MemoryMin + early kubelet eviction: kubelet starved, 0 evictions, no
  taint. n=1, INVALID for contention, and its recovery metric was broken
  (mayor-j1ao0, mayor-st8o2).

Hypothesis (untested): userspace responders cannot act once the node is
starved, so containment must be kernel cgroup limits.

Landed:
- #2113 contention makes a run INVALID regardless of outcome; truthful ramp
  knee summary (mayor-a0e9q).
- #2114 evidence survives a wedged/dead guest; wedge abort (mayor-hxuqo).
- #2115 Lima trim to GCP parity; stall wedge past the 300 s cap; evidence on
  host kill (mayor-3fvb7, mayor-nqkjp).
- #2116 `OOMScoreAdjust=-997` on u7s-apiserver and u7s-kcm (mayor-5ljmf).
- #2117 sampler with anon/file split, per-cgroup refault/PSI, OOM victims;
  killable overload repro; recovery metric (mayor-6bw98, mayor-36soz).

Open / next:
- mayor-st8o2: probe timeouts make the recovery metric unable to observe
  recovery.
- mayor-pzhtd: experiment E, `kubepods.slice` `memory.max` via
  `enforceNodeAllocatable` (#2039's other half), on GCP.
- mayor-pj20g (limit concurrent sandbox creation), mayor-y7xy9 (GCP wedge
  calibration), mayor-xseef (VM reuse, CPU calibration).
- Operator decision: add an overload/recovery criterion to the release gate
  after the experiments, with targets set from what they show achievable.
  Gate size (50 vs 80 pods) is open with the operator. #2039 stays open as a
  draft.

Methodology rules:
- In-VM sampler only; off-VM observers cost ~79 MiB and skew A/B.
- n=1, time-boxed runs; one Lima VM at a time.
- Lima runs need an operator-granted quiet window; every 2026-11-05 Lima
  run was INVALID for host contention.
- GCP is release-authoritative.
- Workers TERM their own burst-gate PID.
- Gate builds from main need `cosign` on the host; build at a tag to run an
  old release.

## 1 GiB VPS fit (measured 2026-10-01, mayor-g0qp7)

The shipped install fits a 1 GiB VM at idle and with one small app. Lima
aarch64, 947 MiB, no swap, k8s 1.36.4, node Ready in 57 s.

Idle PSS (MB): KCM 62, kubelet 61, cri-o 34, kube-proxy 23, CoreDNS 22,
flanneld 21, u7s apiserver+scheduler 17; stack 240. `MemAvailable` idle
462 MiB; 80-pod burst 187; minimum 103. Below ~150-200 MiB the vCPU
re-faults code pages and BestEffort pods incl. CoreDNS are OOM-killed.

Levers: swapfile (`failSwapOn: false` set); CoreDNS memory requests; OS
baseline trim (mayor-elrly). A KCM/kubelet Rust rewrite saves ~17-50 MB
each and does not fix the burst failure; mayor-vc844 Phase 2 awaits the
operator (mayor recommends no-go). CoreDNS ~145 MiB was a self-forward loop,
fixed in #1706. Single run; aarch64 only (mayor-ed4dv). Write-up: `git show
archive/mayor-g0qp7-findings:ai/findings/2026-10-01-mayor-g0qp7-1gib-vps-fit.md`

## Go-runtime tuning (kubelet / KCM / kube-proxy)

`GOMEMLIMIT=200MiB GOGC=50 GOMAXPROCS=2` (systemd env in
`scripts/conformance/lima-start.sh`), verified 2026-08-28 against full
conformance, 0/7616 sonobuoy failures, no OOM:
- kubelet peak RSS 204 -> 118 MB; KCM 132 -> 113 MB (128MiB Round-2 target);
  kube-proxy 53 -> 49 MB.
- kube-proxy `syncProxyRules` latency not degraded (tuned p95 86.5 ms vs
  untuned 70-87 ms; n=1 tuned run).

## Apiserver RSS (2026-08-12)

Peak RSS 137 -> 82 MB from Fat LTO + `codegen-units=1` (~20 MB) and
`RING_CAPACITY` 10_000 -> 512 (a full conformance run needed 25 replayed
events; zero 410s or `Lagged`). An undersized ring is not a correctness
risk: stale clients get 410 and re-LIST. Remaining ~82 MB: ~16 MB SQLite page
cache, ~16 MB `__TEXT`, rest heap.

dhat figures are churn totals (bytes ever allocated) under profiling that
inflates RSS 52-88%; for footprint use live-byte counters or measure
un-profiled. The 08-06 baseline was dominated by `serde_json::Value`
trees; typed-struct migration is complete.

## Memory subsystems that matter

- **SqliteStore** ring/`deletion_log`/compaction are sharded per resource
  type (~73 shards in conformance; lazily created, never reclaimed). The
  broadcast channel is deliberately unsharded, so a busy type can lag a quiet
  watcher. `RING_CAPACITY` 512 per shard, `BROADCAST_CAPACITY` 1024.
- **Typing**: reasoned-about fields must be typed structs, not raw `Value`
  (`memory:typing-guideline-no-raw-json-for-reasoned-fields`); watch for
  regressions.
- **Protobuf adapters**: decode every generated field or fail a completeness
  test.
- **Observability**: `u7s_watch_ring_occupancy`, `u7s_watch_ring_span_seconds`,
  `u7s_watch_replay_depth`, `apiserver_request_total`.
- **Caches**: discovery bytes-cache (18 us -> 15 ns) and JWT signature cache.
- dhat measures heap churn, not host RSS; do not conflate.

## Known issues (unfixed)

Recapturing dhat at backtrace depth 50 to de-anonymize the ~4.46 GB
"depth-truncated recursion" bucket is deferred by the operator; on the full
suite it costs +82% wall-clock and +318% RSS and still truncates 60% of
stacks. Do not run it until a concrete hotspot needs it.

## Diagnostic playbook

dmesg first, never kubelet's OOM log
(`memory:dmesg-first-for-oom-investigation`). The OOM victim is often not the
hog; check cgroup totals first
(`memory:oom-victim-is-not-necessarily-the-memory-hog`). dhat `eb==mb` is not
automatically a leak
(`memory:dhat-eb-equals-mb-not-necessarily-a-leak`). Grep-verify any
statistic at citation time
(`memory:statistics-from-findings-docs-must-be-grep-verified-never-recited`).
Regression bench: saturate at max-inflight=50/max-mutating=20, hold 30 s,
sample RSS delta
(`memory:memory-bench-scenario-saturate-server-at-max-inflight`). PSS
includes file pages and falls under eviction: split anon/file before
concluding a component did not grow.
