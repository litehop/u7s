# Memory management state

**AS OF 2026-08-10 / HEAD `1dea152f` — next refresh: weekly, via mayor-rr177's cron (registered as `c6250b1c`, Sundays 19:37 local). If this banner is more than ~10 days stale, treat every number below as a starting hypothesis, not a fact.**

## Executive summary

The 0810-0107 conformance run's dhat profile (40.67 min) totaled ~11.95 GB of allocation bytes, with `SqliteStore::push_event_locked`'s unconditional global-bookmark broadcast now the single largest site at 5.80% of total bytes (bd:drs2a). The 08-06 baseline (17.0 GB / 60.5 min) was dominated by `serde_json::Value` tree construction — 44.2% of bytes, 52.6% of events (bd:7e8jf). The three fixes shipped against that baseline (bd:g7g2m, bd:e555b, bd:6sbvc) measurably worked — serde_json's share dropped 10.65pp, num_bigint_dig+jsonwebtoken dropped 5.18pp — but the freed budget was absorbed by watch-broadcast fan-out, not eliminated (bd:ddcyx verdict). Over the last month a typed-struct-migration EPIC was scoped into 9 children (bd:0bd14, 1/10 complete); as of this writing bd:0bd14.2 and bd:4yct9 are in flight in parallel worktrees. Still open: bd:drs2a (P1, store sharding), bd:u6rec (P2, unattributed dhat residual), bd:noub6 (P2, kubelet eviction gap), bd:c6s2o (audit in flight, protobuf encoding).

## Memory subsystems that matter

**SqliteStore ring/broadcast/deletion_log.** One global `SqliteStore` (lib.rs:202) backs every resource type; its ring, `deletion_log.by_key`, and broadcast channel share one write path. `RING_CAPACITY` went 1_000 → 100_000 (bd:jzlon, PR#978) → 10_000 (bd:h3zlt, PR#1037; confirmed live in current code by grep). Full-ring linear scans on watch-open/Lagged-recovery measured 61x latency scaling from 1k to 100k occupancy (bd:nlkyd). Stage-2 sharding by resource-type prefix (bd:drs2a, P1, ~300-500 LoC across the Store trait + ~48 handler call sites) is scoped but not started.

**`serde_json::Value` in handler logic.** 94.5% of JSON allocation bytes trace to `Object.body = Value` construction, types.rs:639-642 (bd:7e8jf) — a standing violation of `memory:typing-guideline-no-raw-json-for-reasoned-fields`. Grep-corrected actionable surface: ~1,534 occurrences across 34 files, after excluding generated adapter code (bd:0bd14 notes). bd:0bd14.1's scout grouped this into 9 children; 6 remain queued P3.

**Protobuf decode adapters.** The sentinel-completeness pattern (decode every generated-struct field or fail a completeness test) shipped three merged fixes this week: bd:a2ysh (PR #1072, VolumeMount), bd:ifrs4 (PR #1074, PVCSpec), bd:ovni7 (PR #1077, PVCStatus). bd:c6s2o is auditing the remaining response-encoding exclusions and KCM/kubelet protobuf-flip readiness; no verdict yet.

**Watch replay** is one global ring, not a per-resource re-list (`memory:watch-replay-is-global-ring-buffer-not-per-resource-relist`) — a long-idle object can still age out under sustained churn. bd:4yct9 is migrating the stamping/projection call sites (~297.3 MB / 3.68M blocks, dhat 0810-0107).

**Discovery cache** (bd:k3pxp, P2) and **JWT sig-cache scout** (bd:32uy1, P2) are both queued, not dispatched.

**glibc arena / RSS-vs-heap gap.** dhat measures heap churn only, not host RSS. This doc's brief asked to cite a "55.6%→37.3% coverage drop" from bd:ddcyx — that figure does not appear anywhere in bd:ddcyx's close reason, notes, or any bd memory. **Unverifiable, omitted per Rule 12.**

## Known issues (unfixed)

- bd:drs2a (P1) — O(ring-size) watch scans + global bookmark fan-out, the #1 allocation site.
- bd:u6rec (P2) — 6.6% (~1.12 GB) of dhat churn unattributed past the default 12-frame stack depth.
- bd:noub6 (P2) — kubelet eviction manager has no soft threshold; ~10s poll cadence can't preempt sub-60s OOM bursts.
- bd:0bd14.3–.9 (P3) — 7 queued typed-migration children.
- bd:k3pxp, bd:32uy1 (P2) — discovery cache and JWT-verify cache, scoped but not dispatched.

## Low-hanging fruit

Per bd:0bd14.1's ranking: bd:0bd14.5 (table row builders, ~200-250 LoC, read-only per-kind structs, no round-trip risk) and bd:0bd14.7 (namespace finalizer, ~60-100 LoC — most of the file is already typed) are the cheapest remaining wins.

## Cross-cutting problems

`ObjectMeta` declares no `ownerReferences` field at all (bd:0bd14.2) — three separate handlers have had to manually save/restore the raw `Value` around every `ObjectMeta` round-trip to avoid silently dropping it (documented pre-existing pattern, `ai/extended-context/apiserver-code-gotchas.md`); bd:0bd14.2 is fixing this at the type level now, not yet landed. The `Value`-in-handlers pattern is a recurring, not one-off, violation of the typing guideline. bd:c6s2o's proto-encoding exclusion audit is in flight; no verdict yet.

## Highest-leverage changes (ranked)

1. bd:drs2a (P1) — store sharding; fixes the #1 allocation site and the O(ring) latency bug together.
2. bd:4yct9 (P1, in flight) — watch stamping, ~297.3 MB / 3.68M blocks.
3. bd:0bd14.2 (P1, in flight) — ownerReferences + GC + LIST envelope, ~210.9 MB / 3.60M blocks.
4. bd:0bd14.3–.9 (P3) — remaining typed-migration children, per bd:0bd14.1's order (.4/.3 next, .6 after .2 lands, .7 standalone, .5/.8/.9 last).

## Diagnostic playbook

dmesg first, never kubelet's own OOM log (`memory:dmesg-first-for-oom-investigation`). The OOM victim is often not the actual hog — check cgroup-level totals first (`memory:oom-victim-is-not-necessarily-the-memory-hog`). A dhat `eb==mb` program point is not automatically a leak; confirm the retention structure is actually unbounded before filing a bead (`memory:dhat-eb-equals-mb-not-necessarily-a-leak`). Any statistic cited into a new bead must be grep-verified at the moment of citation, never recited from memory (`memory:statistics-from-findings-docs-must-be-grep-verified-never-recited`). Regression bench scenario: saturate at max-inflight=50/max-mutating=20, hold 30s, sample RSS delta (`memory:memory-bench-scenario-saturate-server-at-max-inflight`).
