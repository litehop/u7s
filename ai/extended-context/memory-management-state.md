---
as_of: 2026-08-28
kind: initiative-state
---

# Memory management state

**AS OF 2026-08-28** — refreshed by a dispatched worker after Round-1 Go-runtime
tuning verification landed (see `ai/extended-context/README.md` for how this
doc's audit/refresh cycle works). Prior refresh: 2026-08-17.

## Go-runtime tuning (kubelet / KCM / kube-proxy)

Round-1 tuple `GOMEMLIMIT=200MiB GOGC=50 GOMAXPROCS=2` (set via each unit's
systemd env in `scripts/conformance/lima-start.sh`) was verified 2026-08-28
against a real full-conformance load: 5 untuned runs vs. one fresh run with
all three components tuned, ground-truthed per-run from each component's own
"Golang settings" log line (not commit dates — dirty worktrees ran tuned
tuples on live VMs before some tuning PRs merged).

Peak RSS improved on all three, no correctness regression:
- kubelet: 204.3MB → 118.0MB (-42%)
- KCM: 132.3MB → 112.8MB, one transient tick to 115.48MB (-15%); steady-state
  112.8MB across n=2 tuned runs supports a 128MiB Round-2 retune target
- kube-proxy: 52.7MB → 48.9MB (-7.2%) — real but small; the tuple isn't
  miscalibrated for kube-proxy's smaller heap, the effect is just
  proportionally smaller

No OOM/eviction signal in any host log; sonobuoy 0/7616 failures in both the
tuned checkpoint and the fresh fully-tuned run.

**EndpointSlice sync-latency (kube-proxy's own risk):** no degradation found.
`syncProxyRules complete elapsed=` log-line percentiles across the same runs
(~1100-1150 events/run): pre-tuning median 52-55ms / p95 70-87ms / p99
97-138ms across 5 runs; the one tuned run measured median 57.7ms / p95
86.5ms / p99 119.7ms — inside, or barely above, the pre-tuning spread, with
p99 mid-pack (below 2 of the 5 untuned samples). Matches the previously
measured idle-stack per-event cost of 45-70ms
(`memory:clusterip-session-affinity-race-is-kube-proxy-syncproxyrules-cost`):
full-suite churn runs the sync loop more often, not more expensively per
event. Caveat: only one tuned run exists; no further re-runs are planned
(Go-component memory is already established as run-to-run consistent, so no
more stability sampling).

## Headline: peak apiserver RSS 137 MB → 82 MB (2026-08-12 measurement)

Two measured changes: **Fat LTO + `codegen-units=1`** (`[profile.release]`,
commit `617fc0dd`, ~20MB — the workspace previously had no `[profile.*]` at
all), and **`RING_CAPACITY` 10_000 → 512** (commit `62070e12`), sized from the
`u7s_watch_replay_depth` histogram: a full conformance run's worst-case
client only ever needed 25 replayed events, and old 10_000 was ~400× that.
Retained events dropped 30,550 → 8,037. Verified at 512: zero failures, zero
revision-expiry 410s, zero `Lagged` recoveries.

Ring undersizing is *not* a correctness risk — a client whose resourceVersion
aged out gets 410 and re-LISTs (the protocol's designed recovery path).
Sizing the ring is a memory-vs-relist-load trade, not a safety threshold.
Remaining ~82MB: ~16MB SQLite page cache (C-side malloc, invisible to dhat),
~16MB resident `__TEXT`, rest live heap/allocator arenas.

## Executive summary

The 08-06 dhat baseline (17.0GB/60.5min churn) was dominated by
`serde_json::Value` tree construction (44.2% of bytes). Fixes against that
baseline dropped serde_json's share 10.65pp and num_bigint_dig+jsonwebtoken's
5.18pp; the freed budget was absorbed by SqliteStore's global-bookmark
broadcast fan-out, addressed by the sharding work below. The
typed-struct-migration effort is fully complete (raw `Value` no longer backs
reasoned-about fields in the audited surface).

**Caveat on every dhat figure in this doc:** these are *churn* totals (bytes
ever allocated), not retained memory, captured under profiling that itself
perturbs the run (RSS under dhat was 52-88% instrumentation overhead) — for
actual footprint use dhat's live-byte counters or measure un-profiled
(`memory:conformance-suite-wall-clock-budget`).

## Memory subsystems that matter

**SqliteStore ring/broadcast/deletion_log.** The ring, `deletion_log`, and
compaction horizon are **sharded per resource type** (`SqliteStore::shards`,
~73 shards in a conformance run) — `find_shard` bounds each scan to one
shard. The broadcast `tx` channel is deliberately *un*sharded: every watch
subscribes to one channel and filters to its own prefix, so a busy resource
type can still lag a quiet watcher. `RING_CAPACITY` is 512 (per shard);
`BROADCAST_CAPACITY` is 1024. Shards are created lazily on first write and
never reclaimed (accepted trade-off, not an open bug).

**`serde_json::Value` in handler logic.** Reasoned-about fields must be typed
structs, not raw `Value`
(`memory:typing-guideline-no-raw-json-for-reasoned-fields`) — this guideline
has been forgotten and rediscovered more than once; watch for new
Value-wrangling creeping back into reasoned fields.

**Protobuf decode adapters.** Sentinel-completeness (decode every
generated-struct field or fail a completeness test) is the standing
convention for new adapters.

**Watch observability.** `u7s_watch_ring_occupancy`, `u7s_watch_ring_span_seconds`,
and `u7s_watch_replay_depth` are live; `apiserver_request_total` is recorded
on both watch and non-watch paths.

**Discovery cache & JWT sig-cache.** Both live: a bytes-cache for discovery
(3-order speedup, 18μs→15ns steady-state) and cached JWT signature
verification.

**glibc arena / RSS-vs-heap gap.** dhat measures heap churn only, not host
RSS — do not conflate the two when citing a coverage percentage.

## Known issues (unfixed)

The only item in this doc's tracked surface that is not closed: recapturing
dhat at backtrace depth 50 to de-anonymize the ~4.46GB "depth-truncated
recursion" bucket from the 08-06 profile. A full-suite run at depth 50 costs
+82% wall-clock and +318% RSS, causes cascading watchdog reaps, and still
leaves 60% of stacks truncated. Deferred by the operator until a concrete
memory hotspot needs sub-depth-10 attribution — do not run depth-50 against
the full conformance suite in the meantime.

## Diagnostic playbook

dmesg first, never kubelet's own OOM log
(`memory:dmesg-first-for-oom-investigation`). The OOM victim is often not the
actual hog — check cgroup-level totals first
(`memory:oom-victim-is-not-necessarily-the-memory-hog`). A dhat `eb==mb`
program point is not automatically a leak; confirm the retention structure is
actually unbounded before filing a bead
(`memory:dhat-eb-equals-mb-not-necessarily-a-leak`). Any statistic cited into
a new bead must be grep-verified at the moment of citation, never recited
from memory
(`memory:statistics-from-findings-docs-must-be-grep-verified-never-recited`).
Regression bench scenario: saturate at max-inflight=50/max-mutating=20, hold
30s, sample RSS delta
(`memory:memory-bench-scenario-saturate-server-at-max-inflight`).
