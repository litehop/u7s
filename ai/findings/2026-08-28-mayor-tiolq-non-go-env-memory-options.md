Bead: mayor-tiolq
Date: 2026-08-28
Scope: non-Go-env memory options for kubelet/KCM/kube-proxy/CRI-O, post-Round-2

# Non-Go-env memory options: audit

## Recommendation

Try **per-unit cgroup v2 `MemoryHigh=`** first — still config-only, never
OOM-kills — but retargeted against the CURRENT post-Round-1 baseline, not a
stale one. Kubelet's peak is now **118.0MB**, not the pre-tuning 204.3MB
(235MB untuned sawtooth already fixed by `GOMEMLIMIT=200MiB` — see
`memory-management-state.md:22`). The honest remaining leverage is squeezing
the ~82MB of slack GOMEMLIMIT still leaves unused, not clipping a peak that's
already gone — weaker than a first pass, order 0-15MB. The
other three mechanisms remain near-zero leverage (overcommit, CRI-O metrics)
or reopen the Go-env lane Round-1/2 already owns (`GODEBUG=madvdontneed`).

## Per-mechanism

**1. cgroup `memory.max`/`memory.high`.** Cgroup v2: `memory.max` hard-caps
and OOM-kills if unreclaimable; `memory.high` throttles + forces reclaim
without OOM-killing (kernel.org `cgroup-v2.rst`). systemd maps both 1:1 to
`MemoryMax=`/`MemoryHigh=` in the same drop-in already used for
`Environment=GOMEMLIMIT`. Orthogonal to GOMEMLIMIT: GOMEMLIMIT is the Go GC
pacer's internal soft target, invisible to the kernel; `memory.high` is
external and kernel-enforced. Post-Round-1, kubelet's measured peak is
**118.0MB — 82MB below its own 200MiB GOMEMLIMIT** (`memory-management-state.md:22`;
Round-1 already fixed the pre-tuning 204.3MB/235MB sawtooth via GOMEMLIMIT
itself). A `MemoryHigh` above 200MiB would never engage. The real lever is
`MemoryHigh` *below* GOMEMLIMIT, inside that 82MB of slack (e.g. ~150MiB).
Correction: the Go GC guide's 5-10%-headroom advice sizes GOMEMLIMIT *below*
a pre-existing hard limit, not an external ceiling *above* an already-chosen
GOMEMLIMIT — that direction doesn't apply here, so ~150MiB is our own
extrapolation, not a guide citation. Magnitude: modest, order 0-15MB. Cost:
config-only. Risk: real — 150MiB leaves only ~27% margin over a peak from a
single tuned run with no re-run planned; start conservative.

**2. `/proc/sys/vm/overcommit_memory`.** Modes: 0 (heuristic, default), 1
(always allow), 2 (never overcommit, bounded by `overcommit_ratio` +
swap) (kernel.org `vm.rst`). Global, non-cgroup-scoped: it changes *failure
mode* (upfront ENOMEM vs. later OOM-kill), not RSS. Our aggregate footprint
(~209MB) is far from any Lima VM's physical-memory edge, so there's no edge
to move. Mode 2 also risks breaking Go's own large virtual-address-space
reservations (which are virtual, not resident, but still count against a
strict commit limit), a documented gotcha for Go workloads. Magnitude: ~0MB.
Cost: one sysctl line. Risk: real (spurious ENOMEM for Go processes) for no
measured gain.

**3. CRI-O runtime options.** Read `crio.conf.5.md`: `enable_metrics`
defaults `false` and our install scripts never turn it on, so
`metrics_collectors` trimming (the RING_CAPACITY-style lever we already used
for apiserver) is inert for us — there's nothing enabled to trim.
`container_min_memory` (12MiB default) floors *workload* container
requests, not CRI-O's own daemon RSS. CRI-O exposes no in-daemon
image/layer-cache-size knob (image storage is backed by the overlay
filesystem via containers/storage, not an in-process LRU). The one live
lever is `runtime_type="pod"` (conmon-rs, one monitor per pod instead of
per-container) — but sonobuoy's e2e suite is dominated by single-container
pods, so consolidation saves nothing there. CRI-O's own Go runtime is
untouched by Round-1/2 — a Go-env gap, not this audit's frontier (see
follow-on #5). Magnitude: low (order 0-15MB, mostly image-pull bursts).
Cost: config-only. Risk: low.

**4. `MADV_DONTNEED`/`MADV_FREE`.** Confirmed in Go runtime source
(`runtime/mem_linux.go`): Linux default is `MADV_FREE` (lazy — freed pages
stay resident, counted in RSS, until the kernel reclaims under pressure);
`GODEBUG=madvdontneed=1` forces `MADV_DONTNEED` (immediate return, RSS drops
at once, but next touch costs a fresh page fault). This complements
GOMEMLIMIT (which decides *when* to scavenge) by changing *how visibly* that
scavenging shows up as measured RSS — plausibly explains slop between a
GOMEMLIMIT target and observed peak RSS. Caveat: `GODEBUG` is still a Go env
var — a different axis (page-return timing, not GC pacing) than Round-1/2's
tuple, flagged honestly rather than smuggled in as "non-Go-env." Magnitude:
order 5-20MB, mostly visible right after churn, not at idle. Cost:
one env var. Risk: CPU/latency cost on page re-fault — needs the same
syncProxyRules-latency re-verification Round-1 already did for the base
tuple.

## What experiments to run (priority order)

1. **cgroup `MemoryHigh`** — add `MemoryHigh=150M` to kubelet.service
   drop-in (below the 200MiB GOMEMLIMIT, ~27% above the current 118MB peak);
   rerun the 31-pod churn cycle; measure peak RSS before/after. Expect order
   0-15MB further reduction; watch for throttling/latency regression given
   the tight margin.
2. **CRI-O baseline gap-fill** — CRI-O's own peak RSS during a full
   conformance run is missing from the measured set; sample it once before
   proposing further CRI-O changes.
3. **`GODEBUG=madvdontneed=1`** on kubelet.service; rerun churn cycle,
   measure peak RSS and PLEG/sync-loop latency. Expect 5-20MB RSS drop, watch
   for CPU regression.
4. **overcommit validation only** — `cat /proc/meminfo | grep Commit` before
   and after a full run to confirm we're nowhere near the overcommit edge;
   do not change the sysctl.

## What does NOT help

- `overcommit_memory` retuning: no RSS reduction, real risk to Go's virtual
  reservations, and we're nowhere near the ceiling it governs.
- CRI-O `metrics_collectors` trimming: already inert — `enable_metrics` is
  `false` in our config, so there's nothing to trim.

## Follow-on beads to file (mayor files, not this worker)

1. Experiment: `MemoryHigh=150M` cgroup drop-in on kubelet.service (below GOMEMLIMIT), measure RSS/latency delta.
2. Baseline: measure CRI-O daemon's own peak RSS during a full conformance run.
3. Experiment: `GODEBUG=madvdontneed=1` on kubelet.service + kube-proxy.service, with latency re-verification.
4. Experiment: `MemoryHigh=` for kube-proxy + KCM once Round-2 lands (after xpxj5/9dk3n merge).
5. Experiment (Go-env lane, not this bead's scope): Round-1-style GOMEMLIMIT/GOGC/GOMAXPROCS tuning for the CRI-O daemon itself — untouched by Round-1/2, unlike kubelet/KCM/kube-proxy.
