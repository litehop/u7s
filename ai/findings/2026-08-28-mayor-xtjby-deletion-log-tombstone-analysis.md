Bead: mayor-xtjby

# Deletion-log tombstone retention: lighter representation + eviction policy

## Verdict

A two-tier deletion_log (full-body for recent deletes, stripped
revision-only for aged-out ones) is VIABLE and is the concrete
recommendation. A flat switch to always-stripped tombstones is NOT VIABLE
(breaks selector-filtered watch correctness). Pure time-based eviction
(replacing the count cap with a wall-clock cutoff) is NOT preferred over a
count-based tier switch — same memory outcome, more code, a clock read on
every push. Upstream kube-apiserver does not strip delete-event bodies
either; it bounds history by a ~75s time window instead of downgrading
fidelity, which is the same "bound the window, not the body" idea the
two-tier design applies here. Severity: 1 MED (implement two-tier
deletion_log), 1 LOW (instrument body-size/selector-usage to tune the
tier caps with real data instead of estimates).

## 1. DELETE-event semantics (client-go)

`temp/research/{reflector,delta_fifo,shared_informer}.go` @ release-1.36.
`reflector.go:1049-1057`: on `watch.Deleted`, the reflector calls
`store.Delete(event.Object)` — the object it just decoded off the wire,
full body included, not a stripped key. `delta_fifo.go:408-439`
(`DeltaFIFO.Delete`) passes that object straight into the queue; consumers'
`OnDelete(obj)` handlers get the full last-known object. Real controllers
rely on this: ReplicaSet's expectations tracking reads owner refs, endpoint
controllers read Pod IP/readiness, GC reads ownerReferences — all only
available on `OnDelete` if the full body is there. `DeletedFinalStateUnknown`
(`delta_fifo.go:793-800`) is a *client-side* fallback for relist-detected
deletions (`Replace()`, lines 642-664) where the client substitutes its own
locally-cached copy — it is not evidence that the server may send less.

u7s's own code already reaches the same conclusion independently:
`crates/store/src/lib.rs:238-240` documents `WatchEvent::Deleted.body` as
existing so "informers can do label-selector matching on the deleted
object," and `crates/apiserver/src/handlers/watch.rs:1157-1235` uses it to
evaluate `label_selector`/`field_selector` against the pre-deletion object
before deciding whether to emit a synthetic DELETED at all. **Verdict:
NOT VIABLE to unconditionally strip — a selector-scoped watch needs the
body to decide inclusion, matching upstream's own DELETE-carries-full-object
design.**

## 2. Upstream storage layer comparison

`temp/research/watch_cache.go` @ release-1.36, `staging/.../storage/cacher/`.
`watchCacheEvent` (line 71-82) carries both `Object` and `PrevObject` in
full — upstream does not strip delete bodies either. Capacity is instead
bounded by time: `resizeCacheLocked` (line 374) grows/shrinks the cache so
it holds `eventFreshDuration` worth of history (2x/0.5x steps), and
`DefaultEventFreshDuration = defaultBookmarkFrequency + 15s = 75s`
(`cacher.go:70-77`, fetched separately). Upstream's answer to "how much
delete history to keep" is a **time window**, not a lighter body — the
input this audit's dimension 4 hypothesis (time-based eviction) already
anticipated. **This is direct precedent for time as the bounding signal,
but not for stripping body content**, which sharpens dimension 1's verdict.

## 3. Per-shard cap arithmetic

Current: `DELETION_LOG_CAP = 2*RING_CAPACITY = 1024` full
`Arc<InternalEvent>` bodies per shard (`sqlite.rs:566-567`). No in-repo
measurement of average object size exists (checked, none found) — the
range below is an estimate, flagged needs-data in the LOW follow-on.
Assume 1-6KB/object (bare ServiceAccount/Namespace at the low end, Pod
with full container statuses at the high end) and N=10 shards capable of
sustained delete churn (Pods, PodTemplates, ServiceAccounts, Namespaces,
EndpointSlices, ReplicaSets, Jobs, Events, ConfigMaps, Endpoints):

- Observed in the 28-min run (mayor-lulpm doc, dimension 7): top-5 shards
  summed to 2,934/1024-cap tombstones, ~8-15MB at 3-5KB avg — consistent
  with that doc's own "order of 10s of MB" estimate.
- Theoretical worst case, all N=10 shards saturated at the 1024 cap:
  10 * 1024 * 3-5KB = **30-50MB**, held indefinitely in a long-running,
  high-churn cluster (the scenario this bead worries about — CronJob/Job
  cleanup, HPA-driven cycling — never reached in a 28-minute run).

## 4. Time-based eviction viability

Read `deletion_log_evicts_tombstone_on_recreate` and
`deletion_log_retains_tombstone_for_deleted_key_not_recreated`
(`sqlite.rs:2938-3035`) in full. Neither test exercises wall-clock time —
both run in milliseconds. A time-based (or count-tier) eviction threshold
set to anything realistic (minutes, not milliseconds) cannot trip either
test; they remain valid as written.

The deeper question — does evicting a tombstone before a legitimate
reconnect break correctness — is already answered by the existing
cap-based eviction's own accepted tradeoff (`sqlite.rs:555-559`: tombstones
evicted past the cap are "for keys deleted more than 2000 writes ago,
which any active watcher has already processed"). Tracing the actual
failure mode (`sqlite.rs:1971-2004`, connect-time replay): a watcher whose
`from_revision < horizon` gets every tombstone the log still holds, THEN
`WatchEvent::Compacted`. A client-go reflector treats `Compacted`/410 as
"stop, relist" — and relist's own deletion-detection path
(`delta_fifo.go:642-664`, `Replace()`) synthesizes a
`DeletedFinalStateUnknown` from the *client's own* cached copy for any key
that vanished without a delivered DELETE. So a missing tombstone during a
Compacted reconnect degrades to the same, already-standard,
already-handled client-go code path as any other watch gap — it does not
silently drop the delete. **Verdict: a stricter eviction (time- or
count-tier-based) is viable; it does not introduce a new failure mode,
only makes the existing accepted one (forced relist after prolonged
disconnect) trigger somewhat sooner for pathologically-late reconnects.**

## 5. Real-world reconnect windows

`temp/research/reflector.go:62-67`: reflector reconnect backoff is
`defaultBackoffInit = 800ms`, `defaultBackoffMax = 30s`, jittered
exponential, reset after 2 minutes of healthy operation — confirming the
bead's own premise. u7s's own measured data is more specific still: the
`RING_CAPACITY` doc comment (`sqlite.rs:10-13`) reports a full conformance
run's deepest actual replay need was 25 events (mean 0.10, 2,359 watch
opens) — i.e., in real traffic, reconnects are so prompt that almost none
ever needed more than the live ring, let alone the deletion_log's full
1024-deep tail. **Verdict: any reasonable full-fidelity window (hundreds
of events, single-digit minutes) has enormous headroom over observed
reconnect behavior.**

## Recommendation: two-tier deletion_log

```rust
/// - Full: complete last-known body, needed so a selector-scoped watch can
///   correctly decide whether the deleted object still matches (see
///   watch.rs's WatchEvent::Deleted handling) before emitting a synthetic
///   DELETE.
/// - Stripped: revision only. Replay degrades to `body: None`, which
///   watch.rs's encode_watch_event already handles today via
///   build_tombstone_object's "no body available, send unconditionally"
///   fallback (`watch.rs:295-298`) — no new wire-format code needed.
enum DeletionLogEntry {
    Full(Arc<InternalEvent>),
    Stripped { revision: u64 },
}
```

`by_revision: BTreeMap<u64, String>` is unchanged and still the eviction
index for both tiers. Policy: once a shard's Full-tier count exceeds
`RING_CAPACITY` (512, matching the ring's own sizing rationale), downgrade
(not remove) the lowest-revision Full entry to Stripped — same key, same
`by_revision` entry, no correctness-affecting resize of the log. Once
total `by_key.len()` exceeds a larger `STRIPPED_TIER_CAP` (e.g.
`8*RING_CAPACITY` = 4096), evict outright via the existing `pop_first()`
path.

Net effect for a saturated shard: ~512 full bodies (~1.5-2.5MB at 3-5KB
avg) + ~3584 stripped entries (~24-byte key + 8-byte revision + tag,
~100-150KB) ≈ 2-2.6MB, vs today's worst case of ~1024 full bodies
(3-5MB) — roughly half the memory while covering 4x more delete-history
depth for late reconnects (falling back to the already-safe "conservative
send" path once past the full-fidelity window). Evict-on-recreate
(`sqlite.rs:583-585`) is unaffected: it removes by String key regardless
of tier.

## Non-goals confirmed

Neither guarding test's correctness contract (retain-until-recreated) is
weakened — a Stripped tombstone still answers "was this key deleted,"
just without the body a selector-scoped watch needs for filtering, which
degrades to today's already-implemented conservative-send fallback rather
than to silence.
