Bead: mayor-lulpm

# Conformance run memory audit: 0827-1443-conformance

## Verdict

No leaks found. The apiserver's staged RSS growth (31MB -> 96MB over the
28-minute run) tracks a real, identified, already-bounded-but-uncompacted
data structure — the per-shard deletion-tombstone log — not an unbounded
leak. The single largest memory event in the whole run belongs to coredns
(an addon u7s vendors and configures, not apiserver/scheduler/konnectivity
code): a 14x RSS spike (62MB -> 888MB) with ~1s of cumulative CPU across the
whole run, i.e. a burst allocation with no proportional work, then a return
to baseline. VM headroom was never a concern (min free 11.7%/28.8%, 0 ticks
under threshold). Ring-age data confirms the watch ring is working exactly
as designed (bounded, idle-shard GC active) — a dead end for "leak", useful
confirmation that the design holds under real conformance load.

Severity: 1 MED (apiserver deletion-log), 1 LOW (coredns GOMEMLIMIT), 1 LOW
(informational — footprint-gap is binary-wide, not a fix target), 1 DEFER
(ring/shard system — confirmed working, no action).

## Data source

`/Users/balint.erdos/u7s/temp/e2e/0827-1443-conformance/monitoring/`
(rss.csv 1849 rows, ring-age.csv 3795 rows, vm-free.csv 113 rows, 3
`metrics-*.prom` snapshots). Cross-referenced `manifests/coredns.yaml`,
`crates/store/src/sqlite.rs`, `podlogs/kube-system/coredns-*/logs/coredns.txt`.
Run window: 2026-08-27T14:14:30Z -> 14:43:23Z (~28m53s), via
`scripts/conformance/aggregate-run-metrics.sh` plus direct `awk` queries
against the raw CSVs (that script's own output is quoted verbatim in
"Peak RSS" below; the rest of this doc goes past its summary level).

## 1. Peak RSS per component

| Component | Peak RSS | Peak footprint | Samples |
|---|---:|---:|---:|
| u7s-apiserver | 93.4 MB (95.7MB at final tick) | 56.0 MB | 56 |
| u7s-scheduler | 14.5 MB (14.9MB at final tick) | 8.1 MB | 56 |
| konnectivity-server | 43.1 MB (44.2MB at final tick) | 24.0 MB | 56 |
| kubelet (lima-node-2) | 125.7 MB | -- | 102 |
| kube-proxy | 53.3 MB | -- | 102 |
| kube-controller-manager | 109.2 MB | -- | 56 |
| cri-o | 115.8 MB | -- | 102 |
| **coredns** | **867.4 MB** (35886, same PID throughout) | -- | -- |
| e2e.test (sonobuoy) | 275.7 MB | -- | -- |
| lima-guestagent | 115.0 MB | -- | -- |

coredns's peak (867.4 MB, at 2026-08-27T14:20:16Z) dwarfs every u7s-owned
process combined (93.4+14.5+43.1+125.7 = 276.7MB). `plugins/e2e/` in this
run only has `definition.json`/`sonobuoy_results.yaml` (no per-test
timestamps), so the exact triggering subtest can't be pinned down further;
the coredns pod's own log (`podlogs/kube-system/coredns-*/logs/coredns.txt`,
5 lines total, no errors/restarts) rules out a crash-restart as the
explanation — see dimension 4.

## 2. Growth pattern

**apiserver**: staged growth, not monotonic creep. 31MB (14:14:30) -> flat
plateau at 72.7MB for 7 minutes (14:20:16-14:27:06, zero movement) -> steps
to 91.7MB by 14:29:43 -> flat again for 10 minutes -> final bump to 95.7MB
at the very last tick. Each step correlates with new test-namespace/CRD
churn (see dimension 7); each plateau is genuinely flat (not a slowed
climb), which is the signature of "cache grew to fit newly-created live
objects" (normal), not "something grows every tick forever" (leak).

**konnectivity-server**: fastest to plateau — 37.7MB -> 44.1MB by 14:19:13,
then **completely flat** (44112-44144 KB) for the remaining ~24 minutes and
~74 samples. This is the cleanest process in the run.

**scheduler**: same staged shape as apiserver, at 5x smaller absolute scale
(7.4MB -> 14.9MB).

**kubelet (lima-node-2)**: 96.7MB -> flat ~105-107MB for 13 minutes -> steps
to ~116-118MB at 14:27:37 and holds there for the remaining 16 minutes. The
step lines up with the same conformance-test-load-increase window as
apiserver's second step (14:27:06-14:29:43) — consistent with "kubelet's
per-pod RSS scales with concurrently-running-pod count," not an independent
leak; kubelet's own growth stops when apiserver's does.

## 3. Footprint gap (rss_kb vs footprint_kb, host processes only)

| Component | RSS (final) | Footprint (final) | Gap | Gap as % of RSS |
|---|---:|---:|---:|---:|
| apiserver | 95,680 KB | 57,344 KB | 38,336 KB (37.4MB) | 40.1% |
| konnectivity-server | 44,160 KB | 24,576 KB | 19,584 KB (19.1MB) | 44.4% |
| scheduler | 14,864 KB | 6,864 KB | 8,000 KB (7.8MB) | 53.8% |

apiserver has the widest **absolute** gap (37.4MB); scheduler has the
widest **relative** gap (53.8%) — but all three cluster in the same 40-54%
band. That uniformity across three different binaries built from the same
toolchain is itself the finding: this looks like a property of the Rust
build + macOS `ps`-vs-`footprint` measurement gap (evictable/shared pages
counted by `ps` but not by `footprint`), not a per-component allocator-
retention bug. **Dead end for a per-component fix** — chasing "why does
apiserver retain 37MB of non-live pages" would likely just rediscover "the
binary's own resident text + shared libc/libSystem pages," the same
explanation the sampler script's own header comment already gives for why
`footprint` exists. Not filing a bead for this.

## 4. CPU-per-byte-of-RSS

| Component | Peak/final RSS | Cumulative CPU (run end) | Wall time | CPU utilization |
|---|---:|---:|---:|---:|
| apiserver | 95.7 MB | 69.8s | 1733s | ~4.0% |
| kubelet | 116.9 MB | 61.0s | ~1733s | ~3.5% |
| kube-controller-manager | 110.9 MB | 38.0s | ~1733s | ~2.2% |
| cri-o | 74.7-115.8 MB | 34.0s | ~1733s | ~2.0% |
| konnectivity-server | 44.2 MB | 6.7s | 1733s | ~0.4% |
| scheduler | 14.9 MB | 2.9s | 1733s | ~0.2% |
| **coredns** | **867.4 MB (peak)** | **~1.0s** | 1733s | **~0.06%** |

coredns is the standout cheap-fix-shaped signature in the entire run: it
spent essentially zero CPU (1 second, cumulative, over 29 minutes) while
briefly holding 867MB RSS — i.e. this is not proportional-to-work memory,
it is a burst allocation the Go runtime hadn't yet given back to the OS.
Every u7s-owned host process (apiserver, scheduler, konnectivity-server) is
firmly in the "small memory doing real, proportional work" quadrant — none
of them show the "large RSS, no CPU" shape that would mark them as a cheap
fix.

## 5. VM ceiling headroom

`vm-free.csv`: lima-node-2 min free = 2276MB of 7912MB total (28.8%);
lima-node-3 min free = 924MB of 7912MB (11.7%). Both nodes stayed
comfortably above the 100MB/5% joint threshold for all 56 ticks each (0
ticks crossed, confirmed via `aggregate-run-metrics.sh`'s own OOM-proximity
section). lima-node-3 (running the second worker's kubelet/crio plus
overlapping sonobuoy/coredns/kubelet growth) has the thinner margin of the
two but is not close to swap/OOM in this run. **No VM-ceiling risk found in
this run** — worth re-checking only if a future run adds node count or a
denser workload without a proportional VM memory bump.

## 6. Ring-age signal

Top-occupancy shards (`/registry/apps/replicasets/`, `/registry/configmaps/`,
`/registry/discovery.k8s.io/endpointslices/`, `/registry/endpoints/`,
`/registry/events/`) all sit at exactly 512 events — `RING_CAPACITY` in
`crates/store/src/sqlite.rs:14`. This is occupancy *at cap*, i.e. the ring
is full and staying full (by design: a write only evicts the oldest entry
once the ring exceeds capacity, `sqlite.rs:490`), not a ring that keeps
growing past its bound. `u7s_watch_ring_shard_evictions_total` in the
pre-teardown snapshot shows real idle-shard reaping happened during the run
(`/registry/cr/`: 10, `/registry/events/`: 10, `/registry/apiextensions.k8s.io/`:
3, `/registry/service-ips/`: 4) — `RING_SHARD_IDLE_GRACE` (120s,
`sqlite.rs:34`) is confirmed live and working against the ~12 ephemeral
per-CRD shards this run's `crd-publish-openapi`/`crd-webhook`/
`crd-selectable-fields` conformance tests create. **This dimension is a
dead end for "leak" as originally hypothesised** — the watch-ring/shard
lifecycle is doing exactly what its own design comments say it should. The
real memory signal in this run is not the ring; it's the deletion log
(dimension 7), which the ring-eviction and shard-GC paths do not touch.

## 7. Prometheus deltas (startup -> post-run -> pre-teardown)

- **`u7s_deletion_log_len`** (sum across shards): **2 -> 4133 -> 4133**.
  All growth happened during the active test run; zero growth between
  post-run and pre-teardown (the two snapshots are numerically identical),
  confirming the count tracks live test churn, not an ongoing background
  leak. Top shards at pre-teardown: `/registry/pods/` 867,
  `/registry/podtemplates/` 805, `/registry/serviceaccounts/` 490,
  `/registry/namespaces/` 482, `/registry/discovery.k8s.io/endpointslices/`
  290. Per `crates/store/src/sqlite.rs:561-590`, each entry in this map is a
  full `Arc<InternalEvent>` — the complete last-known object body of a
  deleted resource, kept so a reconnecting watcher gets a correct DELETE
  event — capped per-shard at `2*RING_CAPACITY` = 1024
  (`sqlite.rs:566-567`). None of the active shards hit that cap in this
  28-minute run (867/1024 and 805/1024 are the closest); a longer or
  higher-churn run (more Job/CronJob/HPA-driven pod cycling) would. This is
  the most concrete apiserver memory-optimization candidate from this
  audit: bounded-but-not-yet-compacted growth that scales with delete
  churn, holding full object bodies rather than just enough to synthesize
  a DELETE event.
- **`u7s_watch_broadcast_receivers`**: 97 -> 105 (peak-of-the-two 105) —
  modest, tracks long-running watch/informer connections, not concerning.
- **`u7s_sa_sig_cache_size`**: 5 -> 17 — trivial, bounded by distinct SA
  identities used in the run.
- **`u7s_watch_closed_total{reason="compacted"}`**: 0 for the whole run —
  confirms no watcher was ever forced to resync because the ring outran it;
  further evidence dimension 6 is a dead end for "leak."
- No jemalloc/allocator-arena counters, no storage-engine row-count gauges
  beyond `u7s_deletion_log_len`, and no connection-table gauges are exposed
  in `/metrics` today (checked via `grep '^# HELP'` across all three
  snapshots) — this audit's dimension-3/4 reasoning had to rely on
  `rss_kb`/`footprint_kb`/`cpu_seconds_cumulative` from the sampler CSV
  instead of allocator-level counters, because none exist to query.

## Prioritized components

1. **apiserver deletion-log tombstone retention** — MED. Evidence:
   `u7s_deletion_log_len` 2->4133 over the run, `sqlite.rs:561-590` (full
   object body per tombstone, capped at 1024/shard). Hypothesis: either
   store a lighter tombstone (key+revision+kind, not the full last object)
   if watch semantics allow it, or lower the per-shard cap / add a
   time-based eviction so churny clusters don't hold the maximum body-size
   x 1024 x N-busy-shards ceiling indefinitely. Estimated impact: order of
   10s of MB in this run's shape; scales with sustained delete-churn in
   longer-lived clusters (CronJobs, HPA-driven scale-down, Job cleanup).
   Risk: MEDIUM — touches watch-replay correctness (`deletion_log_evicts_
   tombstone_on_recreate`/`deletion_log_retains_tombstone_for_deleted_key_
   not_recreated` tests in `sqlite.rs` already encode the correctness
   contract that any change here must preserve).
2. **coredns memory ceiling (867MB burst, ~1s CPU)** — LOW. Evidence:
   dimensions 1 and 4. `manifests/coredns.yaml:7-9` already documents a
   *rejected* `resources.limits.memory` (found flaky with the prometheus
   plugin — a hard cgroup limit risks an OOM-kill mid-burst). A softer
   alternative not yet tried: set `GOMEMLIMIT` via the container's env,
   which caps Go's own heap target and triggers extra GC rather than an
   OOM-kill, so it doesn't reintroduce the flakiness the existing comment
   describes. Estimated impact: caps an 867MB transient down to a
   configured ceiling (order of 100s of MB avoided at burst time). Risk:
   LOW (env-var only, no manifest resources.* field, reversible).
3. **Footprint-gap uniformity across host binaries** — LOW/informational,
   no bead. Evidence: dimension 3 (40-54% gap on all three host processes,
   same magnitude regardless of process size). Not a per-component defect;
   flagged so a future audit doesn't re-spend time rediscovering the same
   binary-wide characteristic.
4. **Watch-ring / shard-lifecycle** — DEFER, no bead. Evidence: dimension
   6 (occupancy at-cap by design, real idle-shard eviction counters firing,
   zero forced-compaction disconnects). Confirmed working as designed under
   real conformance load; nothing to fix.

## Non-goals confirmed clean

- VM OOM/swap risk (dimension 5): clean, both nodes >10% free throughout.
- apiserver/scheduler/konnectivity growth shape (dimension 2): all
  plateau-then-step, no monotonic leak signature.
