---
as_of: 2026-08-17
kind: initiative-state
---

# Memory management state

**AS OF 2026-08-17 — full refresh by mayor-pks56 (NOT mayor-rr177's cron: that cron is audit-only, it files P3 drift beads against this doc but never edits it — see the corrected description in `ai/extended-context/README.md`, mayor-ir84r).** Every bead ID cited below was re-verified via `bd show` on 2026-08-17. Nothing mechanically refreshes this doc's content after the beads it cites close — the next refresh happens whenever mayor-rr177's audit next flags drift here, picked up manually or by a dispatched worker.

## Headline: peak apiserver RSS 137 MB → 82 MB (AS OF 2026-08-12 measurement; not re-measured 2026-08-17)

Two changes, both measured rather than assumed at the time:

- **Fat LTO + `codegen-units = 1`** (`[profile.release]`, commit `617fc0dd`). The workspace previously had no `[profile.*]` at all. ~20 MB.
- **`RING_CAPACITY` 10_000 → 512** (commit `62070e12`), sized from the new `u7s_watch_replay_depth` histogram: across a full conformance run, 2,359 watch opens replayed **266 events in total** (mean 0.10), and the deepest any single client ever needed was **25**. The old 10_000 was ~400× the observed worst case. Retained events dropped 30,550 → 8,037.

Verified at 512: zero failures, zero revision-expiry 410s, zero compacted closes, zero `Lagged` recoveries.

**The framing that unlocked this, and that supersedes earlier docs:** ring undersizing is *not* a correctness risk. A client whose resourceVersion has aged out gets 410 and re-LISTs — the protocol's designed recovery path, complete and correct. The cost is one LIST. Sizing the ring is a memory-versus-relist-load trade on a smooth curve, tuned by watching the 410 rate — not a safety threshold defended with a large constant. Earlier justifications for a big ring reasoned from LIST-to-watch gaps "measured in minutes", which described the era of retry storms they were written in, not the current apiserver.

**Where the remaining ~82 MB sits:** ~16 MB SQLite page cache (`cache_size = -8000` × 2 connections — C-side malloc, so *structurally invisible to dhat* at any backtrace depth), ~16 MB resident `__TEXT`, the rest live heap and allocator arenas. The ring is no longer the dominant term.

## Executive summary

The 08-06 baseline (17.0 GB / 60.5 min dhat churn) was dominated by `serde_json::Value` tree construction — 44.2% of bytes, 52.6% of events (bd:7e8jf, CLOSED). Three quick fixes against that baseline all closed and shipped (bd:g7g2m PR #1036, bd:e555b PR #1038, bd:6sbvc PR #1034): serde_json's share dropped 10.65pp, num_bigint_dig+jsonwebtoken dropped 5.18pp (bd:ddcyx verdict, CLOSED). The freed budget was absorbed by the SqliteStore global-bookmark broadcast fan-out (5.80% of the 0810-0107 run's ~11.95 GB), which the sharding work below then addressed. The typed-struct-migration EPIC (bd:0bd14, scoped into 9 children by bd:0bd14.1) is now **100% closed** (10/10, closed 2026-08-14 — see roadmap.md). bd:noub6 (kubelet eviction gap) closed 2026-08-11 as an operator verdict of "not a u7s bug" (upstream Go kubelet behavior, not something u7s can fix). bd:c6s2o (protobuf response-encoding + KCM/kubelet flip-readiness audit) closed 2026-08-10: the response re-encoder it was scoped to check doesn't exist on current main (already killed by an earlier revert, 51d54dec), the 4 stale content-type guards it found were removed via bd:7txak (CLOSED), and the KCM protobuf flip was live-verified SAFE for the tested field set. **As of this 2026-08-17 check, every bead this doc has ever cited as open/in-flight/queued is CLOSED except bd:eegsu** (see Known issues below).

**Caveat on every dhat figure in this doc:** these are *churn* totals (bytes ever allocated), not retained memory, and they were captured under profiling that itself perturbs the run. For "how much memory does the process hold", use dhat's `gb`/`eb` (live bytes, backtrace-depth-independent) or measure un-profiled — RSS under dhat was 52–88% instrumentation. See bd memory `conformance-suite-wall-clock-budget`.

## Memory subsystems that matter

**SqliteStore ring/broadcast/deletion_log.** The ring, `deletion_log` and compaction horizon are **sharded per resource type** — `SqliteStore::shards`, ~73 shards in a conformance run, each an independent `RingShard`. Sharding (bd:drs2a, PR #1090) and the per-shard compaction horizon (bd:f8ziu, PR #1125) both landed and fixed the O(total-occupancy) watch-open scan behind bd:nlkyd's 61× measurement: `find_shard` now bounds each scan to one shard.

**Do not conflate the ring with the broadcast.** The `tx` broadcast channel is still deliberately *un*sharded — every watch subscribes to that one channel and filters to its own prefix — so a busy resource type can still lag a quiet one's watcher. `RING_CAPACITY` is 512 (per shard); `BROADCAST_CAPACITY` is 1024.

**Shard lifecycle.** Shards are created lazily on first write. The "never reclaimed" gap (bd:88h1w) got a design scout (CLOSED) and 3 follow-ons, all CLOSED: bd:hdgju (reclaimed-vs-never-written discriminator), bd:41qj2 (CRD-delete eager teardown), bd:m5gjv (live-watch-stream severance investigation).

**`serde_json::Value` in handler logic.** 94.5% of JSON allocation bytes traced to `Object.body = Value` construction, types.rs:639-642 (bd:7e8jf) — a standing violation of `memory:typing-guideline-no-raw-json-for-reasoned-fields`. bd:0bd14.1's scout grouped the actionable surface into 9 child beads; **all 9 are now closed** (see Highest-leverage below). The lesson, not just the ticket, matters: this guideline has been forgotten and rediscovered more than once — watch for new Value-wrangling creeping back into reasoned-about fields.

**Protobuf decode adapters.** The sentinel-completeness pattern (decode every generated-struct field or fail a completeness test) shipped three fixes: bd:a2ysh (PR #1072, VolumeMount), bd:ifrs4 (PR #1074, PVCSpec), bd:ovni7 (PR #1077, PVCStatus) — all CLOSED. bd:c6s2o's follow-on audit (above) closed with no new decode gaps found.

**Watch stamping/projection.** bd:4yct9 (CLOSED, PR #1080) migrated watch event stamping and PartialObjectMetadata projection to typed structs.

**Watch observability.** `u7s_watch_ring_occupancy`, `u7s_watch_ring_span_seconds`, and `u7s_watch_replay_depth` are all live. bd:ukbhp (polled gauge couldn't report its own minimum) fixed via PR #1164 (switched to a histogram). bd:2ay2a (apiserver_request_total wired at the watch handler only) closed via PR #1174 — the non-watch path had actually been recording since PR #932/#933; only a stale doc comment needed fixing.

**Discovery cache & JWT sig-cache.** Both CLOSED. bd:k3pxp shipped a bytes-cache for discovery (bd:a9kc1, PR #1116, 3-order speedup: 18μs→15ns steady-state). bd:32uy1 found JWT signature-verify caching already shipped via bd:6sbvc/PR #1034 — no gap remained.

**glibc arena / RSS-vs-heap gap.** dhat measures heap churn only, not host RSS. A "55.6%→37.3% coverage drop" figure once drafted into this doc does not appear anywhere in bd:ddcyx's close reason, notes, or any bd memory — **unverifiable, omitted per Rule 12.**

## Known issues (unfixed)

As of 2026-08-17, the only item in this doc's tracked surface that is not CLOSED:

- **bd:eegsu (P2, DEFERRED 2026-08-13)** — recapture dhat at backtrace depth 50 to de-anonymize the ~4.46 GB "depth-truncated recursion" bucket from the 08-06 profile. Its parent (bd:u6rec, the depth 10→50 bump itself) is CLOSED and landed, but a full-suite run at depth 50 costs +82% wall-clock and +318% RSS, causes cascading watchdog reaps, and still leaves 60% of stacks truncated. Deferred by the operator until a concrete memory hotspot needs sub-depth-10 attribution — do not run depth-50 against the full conformance suite in the meantime.

## Highest-leverage changes (ranked, historical — all CLOSED)

1. bd:drs2a / bd:f8ziu — sharded ring + per-shard compaction horizon. The ring is no longer the leading memory term: 8,037 retained events after the 512 resize (down from 30,550). Follow-on ring work (bd:7l5p6 pre-allocation removal, PR #1179; bd:88h1w reclamation design) is also CLOSED — both were scoped down once written against the smaller ring.
2. bd:4yct9 — watch stamping/projection type migration, ~297.3 MB / 3.68M blocks of churn in the 0810-0107 profile.
3. bd:0bd14.2 — ownerReferences typed field + GC cascade-delete + LIST envelope, ~210.9 MB / 3.60M blocks. Unblocked bd:0bd14.6 (CR envelope stamping), which had been waiting on it.
4. bd:0bd14.5 / bd:0bd14.7 — table row builders and namespace finalizer, the cheapest remaining EPIC children at the time; both shipped (PR #1094, PR #1092).

## Cross-cutting problems

`ObjectMeta` used to declare no `ownerReferences` field, forcing three separate handlers to manually save/restore the raw `Value` around every `ObjectMeta` round-trip (see `ai/extended-context/apiserver-code-gotchas.md`'s ObjectMeta PATTERN section, now marked historical). **Fixed at the type level** by bd:0bd14.2 (PR #1079, `owner_references` field added); all 3 workarounds removed by PR #1081. The broader lesson stands independent of this specific fix: ad hoc `Value`-in-handlers workarounds are a recurring pattern, not a one-off — the type-level fix is almost always better than papering over a round-trip.

## Diagnostic playbook

dmesg first, never kubelet's own OOM log (`memory:dmesg-first-for-oom-investigation`). The OOM victim is often not the actual hog — check cgroup-level totals first (`memory:oom-victim-is-not-necessarily-the-memory-hog`). A dhat `eb==mb` program point is not automatically a leak; confirm the retention structure is actually unbounded before filing a bead (`memory:dhat-eb-equals-mb-not-necessarily-a-leak`). Any statistic cited into a new bead must be grep-verified at the moment of citation, never recited from memory (`memory:statistics-from-findings-docs-must-be-grep-verified-never-recited`). Regression bench scenario: saturate at max-inflight=50/max-mutating=20, hold 30s, sample RSS delta (`memory:memory-bench-scenario-saturate-server-at-max-inflight`).
