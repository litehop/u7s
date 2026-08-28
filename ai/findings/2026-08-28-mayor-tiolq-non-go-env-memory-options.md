Bead: mayor-tiolq
Date: 2026-08-28
Scope: non-Go-env memory options for kubelet/KCM/kube-proxy/CRI-O, post-Round-2

# Non-Go-env memory options: audit

## Recommendation

Try **per-unit cgroup v2 `MemoryHigh=`** (systemd drop-in, same `[Service]`
block already used for `Environment=GOMEMLIMIT=...`) first. It is
config-only, never OOM-kills, and directly targets the one *measured* failure
mode in our own data — kubelet's documented sawtooth peak to 235MB — rather
than a theoretical one. The other three mechanisms are either near-zero
leverage for us today (overcommit, CRI-O metrics) or reopen the Go-env lane
Round-1/2 already owns (`GODEBUG=madvdontneed`).

## Per-mechanism

**1. cgroup `memory.max`/`memory.high`.** Cgroup v2 exposes both: `memory.max`
is a hard cap that invokes the OOM killer if unreclaimable; `memory.high` is a
throttle-and-reclaim boundary that never OOM-kills (kernel.org
`cgroup-v2.rst`). systemd maps these 1:1 to `MemoryMax=`/`MemoryHigh=` in a
unit drop-in — the exact mechanism already used for `Environment=GOMEMLIMIT`.
Interaction with GOMEMLIMIT is orthogonal, not redundant: GOMEMLIMIT governs
the Go GC pacer's *internal* heap target; the kernel has no visibility into
it. `memory.high` instead forces the kernel to reclaim resident-but-freed
(MADV_FREE) pages under its own pressure, sooner than idle global reclaim
would. Go's own GC guide recommends 5-10% headroom above a Go program's
memory target when a hard container limit exists — sizing `MemoryHigh` at
~220-230MiB (over the 200MiB GOMEMLIMIT) follows that guidance. Magnitude:
likely near-zero delta to *steady-state* RSS (already well-behaved per
Round-1) but real leverage clipping the documented transient peak — order
10-40MB off worst-case, not mean. Cost: config-only, per-unit drop-in, zero
code change. Risk: `MemoryMax` (not `MemoryHigh`) without headroom risks an
abrupt OOM-kill worse than the sawtooth it replaces — start with `MemoryHigh`
only.

**2. `/proc/sys/vm/overcommit_memory`.** Modes: 0 (heuristic, default), 1
(always allow), 2 (never overcommit, bounded by `overcommit_ratio` +
swap) (kernel.org `vm.rst`). This is a global, non-cgroup-scoped policy
that changes *failure mode* (upfront ENOMEM vs. later OOM-kill) at the
memory ceiling — it does not shrink anyone's RSS. Our aggregate footprint
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
untouched by Round-1/2 (no GOMEMLIMIT anywhere in `crio.service`), but that's
squarely the Go-env lane, not this audit's frontier — flagging as a gap for
a future Round-3 bead, not a pick here. Magnitude: low (order 0-15MB, mostly
during image-pull bursts). Cost: config-only. Risk: low.

**4. `MADV_DONTNEED`/`MADV_FREE`.** Confirmed in Go runtime source
(`runtime/mem_linux.go`): Linux default is `MADV_FREE` (lazy — freed pages
stay resident, counted in RSS, until the kernel reclaims under pressure);
`GODEBUG=madvdontneed=1` forces `MADV_DONTNEED` (immediate return, RSS drops
at once, but next touch costs a fresh page fault). This complements
GOMEMLIMIT (which decides *when* to scavenge) by changing *how visibly* that
scavenging shows up as measured RSS — plausibly explains slop between a
GOMEMLIMIT target and observed peak RSS. Caveat: this is technically still a
`GODEBUG` **Go env var**, just a different axis (page-return timing, not GC
pacing) than Round-1/2's GOMEMLIMIT/GOGC/GOMAXPROCS tuple — flagging the
classification honestly rather than smuggling it in as "non-Go-env."
Magnitude: order 5-20MB, mostly visible right after churn, not at idle. Cost:
one env var. Risk: CPU/latency cost on page re-fault — needs the same
syncProxyRules-latency re-verification Round-1 already did for the base
tuple.

## What experiments to run (priority order)

1. **cgroup `MemoryHigh`** — add `MemoryHigh=220M` to kubelet.service drop-in;
   rerun the existing 31-pod churn cycle; measure peak RSS before/after.
   Expect ~0 delta to steady state, order 10-40MB clipped off any recurring
   transient peak.
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

1. Experiment: `MemoryHigh=` cgroup drop-in on kubelet.service, measure peak-RSS clipping.
2. Baseline: measure CRI-O daemon's own peak RSS during a full conformance run.
3. Experiment: `GODEBUG=madvdontneed=1` on kubelet.service + kube-proxy.service, with latency re-verification.
4. Experiment: `MemoryHigh=` for kube-proxy + KCM once Round-2 lands (after xpxj5/9dk3n merge).
