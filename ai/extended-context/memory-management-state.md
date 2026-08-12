# Memory management state

**AS OF 2026-08-12 — next refresh: weekly, via mayor-rr177's cron (registered as `c6250b1c`, Sundays 19:37 local). If this banner is more than ~10 days stale, treat every number below as a starting hypothesis, not a fact.** The 2026-08-12 refresh was manual, after an audit found five separate false claims in the 08-10 version — the cron either is not running or is not catching structural changes, worth checking.

## Headline: peak apiserver RSS 137 MB → 82 MB (2026-08-12)

Two changes, both measured rather than assumed:

- **Fat LTO + `codegen-units = 1`** (`[profile.release]`, commit `617fc0dd`). The workspace previously had no `[profile.*]` at all. ~20 MB.
- **`RING_CAPACITY` 10_000 → 512** (commit `62070e12`), sized from the new `u7s_watch_replay_depth` histogram: across a full conformance run, 2,359 watch opens replayed **266 events in total** (mean 0.10), and the deepest any single client ever needed was **25**. The old 10_000 was ~400× the observed worst case. Retained events dropped 30,550 → 8,037.

Verified at 512: zero failures, zero revision-expiry 410s, zero compacted closes, zero `Lagged` recoveries.

**The framing that unlocked this, and that supersedes earlier docs:** ring undersizing is *not* a correctness risk. A client whose resourceVersion has aged out gets 410 and re-LISTs — the protocol's designed recovery path, complete and correct. The cost is one LIST. Sizing the ring is a memory-versus-relist-load trade on a smooth curve, tuned by watching the 410 rate — not a safety threshold defended with a large constant. Earlier justifications for a big ring reasoned from LIST-to-watch gaps "measured in minutes", which described the era of retry storms they were written in, not the current apiserver.

**Where the remaining ~82 MB sits:** ~16 MB SQLite page cache (`cache_size = -8000` × 2 connections — C-side malloc, so *structurally invisible to dhat* at any backtrace depth), ~16 MB resident `__TEXT`, the rest live heap and allocator arenas. The ring is no longer the dominant term.

## Executive summary

The 0810-0107 conformance run's dhat profile (40.67 min) totaled ~11.95 GB of allocation bytes, with `SqliteStore::push_event_locked`'s unconditional global-bookmark broadcast now the single largest site at 5.80% of total bytes (bd:drs2a). The 08-06 baseline (17.0 GB / 60.5 min) was dominated by `serde_json::Value` tree construction — 44.2% of bytes, 52.6% of events (bd:7e8jf). The three fixes shipped against that baseline (bd:g7g2m, bd:e555b, bd:6sbvc) measurably worked — serde_json's share dropped 10.65pp, num_bigint_dig+jsonwebtoken dropped 5.18pp — but the freed budget was absorbed by watch-broadcast fan-out, not eliminated (bd:ddcyx verdict). Over the last month a typed-struct-migration EPIC was scoped into 9 children (bd:0bd14, 1/10 complete); as of this writing bd:0bd14.2 and bd:4yct9 are in flight in parallel worktrees. Still open: bd:noub6 (P2, kubelet eviction gap), bd:c6s2o (audit in flight, protobuf encoding).

**Caveat on every dhat figure in this paragraph:** these are *churn* totals (bytes ever allocated), not retained memory, and they were captured under profiling that itself perturbs the run. For "how much memory does the process hold", use dhat's `gb`/`eb` (live bytes, backtrace-depth-independent) or measure un-profiled — RSS under dhat was 52–88% instrumentation. See bd memory `conformance-suite-wall-clock-budget`.

## Memory subsystems that matter

**SqliteStore ring/broadcast/deletion_log.** The ring, `deletion_log` and compaction horizon are **sharded per resource type** — `SqliteStore::shards`, ~73 shards in a conformance run, each an independent `RingShard`. Stage-2 sharding (bd:drs2a) **landed 2026-08-10**, commit `94fc1828`/PR#1090, and the per-shard compaction horizon (bd:f8ziu) landed 2026-08-12, PR#1125. That fixed the O(total-occupancy) watch-open scan behind bd:nlkyd's 61× measurement: `find_shard` now bounds each scan to one shard.

**Do not conflate the ring with the broadcast.** The `tx` broadcast channel is still deliberately *un*sharded — every watch subscribes to that one channel and filters to its own prefix — so a busy resource type can still lag a quiet one's watcher. `RING_CAPACITY` is 512 (per shard); `BROADCAST_CAPACITY` is 1024. Both now carry their justifying measurement in their doc comments.

Shards are created lazily on first write and **never reclaimed** (bd:88h1w, P3). `compaction_horizon_for` returns 0 when no shard matches — correct only while "no shard" means "never written"; reclamation must preserve a reclaimed shard's floor or it will silently serve empty replays as complete history.

**`serde_json::Value` in handler logic.** 94.5% of JSON allocation bytes trace to `Object.body = Value` construction, types.rs:639-642 (bd:7e8jf) — a standing violation of `memory:typing-guideline-no-raw-json-for-reasoned-fields`. Grep-corrected actionable surface: ~1,534 occurrences across 34 files, after excluding generated adapter code (bd:0bd14 notes). bd:0bd14.1's scout grouped this into 9 children; 6 remain queued P3.

**Protobuf decode adapters.** The sentinel-completeness pattern (decode every generated-struct field or fail a completeness test) shipped three merged fixes this week: bd:a2ysh (PR #1072, VolumeMount), bd:ifrs4 (PR #1074, PVCSpec), bd:ovni7 (PR #1077, PVCStatus). bd:c6s2o is auditing the remaining response-encoding exclusions and KCM/kubelet protobuf-flip readiness; no verdict yet.

**Watch replay** is served from the per-shard ring (see above), not a per-resource re-list. A long-idle object can still age out under that shard's own churn — and now only its own, not the whole store's. bd:4yct9 is migrating the stamping/projection call sites (~297.3 MB / 3.68M blocks, dhat 0810-0107).

**Watch observability** (new 2026-08-12): `u7s_watch_ring_occupancy` (count), `u7s_watch_ring_span_seconds` (history depth in seconds — note bd:ukbhp, a polled gauge cannot report its own minimum, so treat low readings as real and high readings as unproven), and `u7s_watch_replay_depth` (what clients actually asked for — the requirement side of sizing). `apiserver_request_total` is wired at the watch handler only, so log-410s and metric-410s legitimately disagree (bd:2ay2a).

**Discovery cache** (bd:k3pxp, P2) and **JWT sig-cache scout** (bd:32uy1, P2) are both queued, not dispatched.

**glibc arena / RSS-vs-heap gap.** dhat measures heap churn only, not host RSS. This doc's brief asked to cite a "55.6%→37.3% coverage drop" from bd:ddcyx — that figure does not appear anywhere in bd:ddcyx's close reason, notes, or any bd memory. **Unverifiable, omitted per Rule 12.**

## Known issues (unfixed)

- ~~bd:drs2a~~ — CLOSED, landed 2026-08-10 (PR#1090). Its leftover, the store-wide compaction horizon, is also closed (bd:f8ziu, PR#1125).
- ~~bd:u6rec~~ — CLOSED. The depth 10→50 bump landed, but **it cost +82% wall-clock and +318% RSS and still truncated 60% of stacks**. Its follow-on bd:eegsu (recapture at depth 50) now carries a warning: do not run depth-50 profiling against the full suite.
- bd:noub6 (P2) — kubelet eviction manager has no soft threshold; ~10s poll cadence can't preempt sub-60s OOM bursts.
- bd:0bd14.3–.9 (P3) — 7 queued typed-migration children.
- bd:k3pxp, bd:32uy1 (P2) — discovery cache and JWT-verify cache, scoped but not dispatched.

## Low-hanging fruit

Per bd:0bd14.1's ranking: bd:0bd14.5 (table row builders, ~200-250 LoC, read-only per-kind structs, no round-trip risk) and bd:0bd14.7 (namespace finalizer, ~60-100 LoC — most of the file is already typed) are the cheapest remaining wins.

## Cross-cutting problems

`ObjectMeta` declares no `ownerReferences` field at all (bd:0bd14.2) — three separate handlers have had to manually save/restore the raw `Value` around every `ObjectMeta` round-trip to avoid silently dropping it (documented pre-existing pattern, `ai/extended-context/apiserver-code-gotchas.md`); bd:0bd14.2 is fixing this at the type level now, not yet landed. The `Value`-in-handlers pattern is a recurring, not one-off, violation of the typing guideline. bd:c6s2o's proto-encoding exclusion audit is in flight; no verdict yet.

## Highest-leverage changes (ranked)

1. ~~bd:drs2a~~ — done. The ring is no longer the leading memory term at all: 8,037 retained events after the 512 resize. Further ring work (bd:7l5p6 pre-allocation, now ~300 KB; bd:88h1w reclamation) has been downgraded accordingly — their justifications were written against a 10_000-entry ring.
2. bd:4yct9 (P1, in flight) — watch stamping, ~297.3 MB / 3.68M blocks.
3. bd:0bd14.2 (P1, in flight) — ownerReferences + GC + LIST envelope, ~210.9 MB / 3.60M blocks.
4. bd:0bd14.3–.9 (P3) — remaining typed-migration children, per bd:0bd14.1's order (.4/.3 next, .6 after .2 lands, .7 standalone, .5/.8/.9 last).

## Diagnostic playbook

dmesg first, never kubelet's own OOM log (`memory:dmesg-first-for-oom-investigation`). The OOM victim is often not the actual hog — check cgroup-level totals first (`memory:oom-victim-is-not-necessarily-the-memory-hog`). A dhat `eb==mb` program point is not automatically a leak; confirm the retention structure is actually unbounded before filing a bead (`memory:dhat-eb-equals-mb-not-necessarily-a-leak`). Any statistic cited into a new bead must be grep-verified at the moment of citation, never recited from memory (`memory:statistics-from-findings-docs-must-be-grep-verified-never-recited`). Regression bench scenario: saturate at max-inflight=50/max-mutating=20, hold 30s, sample RSS delta (`memory:memory-bench-scenario-saturate-server-at-max-inflight`).
