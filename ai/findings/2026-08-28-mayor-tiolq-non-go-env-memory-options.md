Bead: mayor-tiolq
Date: 2026-08-28
Scope: non-Go-env memory options for kubelet/KCM/kube-proxy/CRI-O, post-Round-2

# Non-Go-env memory options: audit

## Recommendation

**Non-Go-env mechanisms offer bounded leverage post-Round-1.** Kubelet's peak
is already 118.0MB — 41% under its own 200MiB GOMEMLIMIT ceiling (Round-1:
204.3MB→118.0MB via GOMEMLIMIT; `memory-management-state.md:22`). None of the
four found genuine current-state squeeze room: the workload isn't above any
ceiling for cgroup/overcommit/CRI-O knobs to reclaim from. The one mechanism
with plausible non-zero leverage today (`MADV_DONTNEED` page-return timing)
is itself Go-env-adjacent, not purely non-Go-env. **Reserve all four as
tools, not a to-do list**: revisit if Round-2 lands a footprint still large
relative to target; don't spend implementation effort now. This
bounded-leverage finding is itself the answer to the operator's north-star
question — Round-2 is approaching the ceiling of what tuning, Go-env or
otherwise, can add.

## Per-mechanism

**1. cgroup `memory.max`/`memory.high`.** Cgroup v2: `memory.max` hard-caps
and OOM-kills if unreclaimable; `memory.high` throttles + forces reclaim only
once usage **exceeds** the boundary — it does nothing below it (kernel.org
`cgroup-v2.rst`). systemd maps both 1:1 to `MemoryMax=`/`MemoryHigh=` in the
drop-in already used for `Environment=GOMEMLIMIT`. Post-Round-1, kubelet's
peak (118.0MB) sits 82MB below its 200MiB GOMEMLIMIT — that gap isn't
reclaimable slack, it's headroom Go's GC already keeps for burst safety, so a
`MemoryHigh` anywhere in that range never engages and squeezes nothing. Its
only honest use is as a **safety ceiling**: set just above the observed peak
(~130MiB, ~10% margin) so it engages only if the workload tries to exceed
today's baseline.
Magnitude: **zero measured leverage today** — purely defensive, not a
reduction tool. Cost: config-only. Risk: real if set too tight — 130MiB is
thin margin over a single-run peak; re-verify before treating as a gate.

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
lever, `runtime_type="pod"` (conmon-rs, shared monitor per pod), saves
nothing since sonobuoy's e2e suite is dominated by single-container pods.
CRI-O's own Go runtime is untouched by Round-1/2 — a Go-env gap, not this
audit's frontier (see follow-on #5). Magnitude: low (order 0-15MB, mostly image-pull bursts).
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

1. **cgroup `MemoryHigh` as a safety ceiling** — add `MemoryHigh=130M` to
   kubelet.service (~10% above the 118MB peak); rerun the 31-pod churn cycle;
   confirm it does NOT engage under normal load (expect 0 RSS delta) and DOES
   throttle under an injected burst above 130MB. Validates a regression
   alarm, not a reduction.
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

1. Experiment: `MemoryHigh=130M` safety-ceiling drop-in on kubelet.service (regression alarm, not a reduction); confirm engage/no-engage behavior.
2. Baseline: measure CRI-O daemon's own peak RSS during a full conformance run.
3. Experiment: `GODEBUG=madvdontneed=1` on kubelet.service + kube-proxy.service, with latency re-verification.
4. Experiment: `MemoryHigh=` for kube-proxy + KCM once Round-2 lands (after xpxj5/9dk3n merge).
5. Experiment (Go-env lane, not this bead's scope): Round-1-style GOMEMLIMIT/GOGC/GOMAXPROCS tuning for the CRI-O daemon itself — untouched by Round-1/2, unlike kubelet/KCM/kube-proxy.
