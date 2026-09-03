# Memory audit: apiserver, store, scheduler (2026-09-03)

Bead: mayor-17nj7 (source-of-record for the memory/perf epic)

Status: audit findings, no code changed. Scope: whole workspace, biased toward
the apiserver and JSON handling.

Baseline, measured from the run's own sampler
(`temp/e2e/0903-1111-csi-hostpath/monitoring/rss.csv`, 128 apiserver samples):
**119.5 MiB peak, 86.1 MiB mean.** RSS climbs to a ~100 MiB plateau, makes one
transient excursion to 119.5 MiB at 10:30:40, then settles to 78 MiB and is
still declining (72.1 MiB) at end of run — no accretion signature in this run.
The largest collection in that cluster is 87 KiB (15 CRDs), so **findings are
ranked by growth order, not by absolute bytes**; any figure quoted at a
hypothetical pod count is labelled as a projection.

**Answer: the dominant memory cost is holding many `serde_json::Value` objects
alive simultaneously, and almost every fix for it is also a CPU win — the audit
found no significant memory-vs-CPU trade.** The one exception is the SQLite page
cache (11.7 MiB recoverable, genuinely traded against IO). Separately, four
unbounded-growth defects exist, one of which is an unauthenticated remote
memory-exhaustion vector.

Method: `serde_json` figures are measured with a counting global allocator
against a real 5,624-byte Pod (harness was `temp/memaudit/`, gitignored, not
committed). Everything else is static reading with arithmetic shown. Nothing was
run against a live cluster; no before/after RSS was measured.

---

## 0. Root cause, measured

A 5,624-byte Pod parses into **55,816 bytes of heap — 9.9x**.

| allocation size | count | bytes | share |
| --- | --- | --- | --- |
| 512-1023 B | 78 | 49,488 | **88%** |
| all others | 391 | 6,448 | 12% |

The 78 are std `BTreeMap` leaf nodes (~634 B: 11 key slots + 11 value slots).
K8s JSON objects average **2.1 keys**, so ~81% of every node is uninitialized
padding. Real string payload is 7% of the total.

Two consequences that drive the whole ranking:

1. Holding N objects as `Value` costs ~10x their byte size.
2. `Value::clone()` and `serde_json::to_value()` on anything already containing
   `Value`s are deep copies at that rate. `to_value` has no `Value` fast path
   (`serde_json/src/value/ser.rs`), so `json!({"k": some_value})` deep-clones.

`preserve_order` (IndexMap) was tested as a remedy and **rejected**: 9.9x -> 9.5x,
and `size_of::<Value>()` grows 32 -> 72 bytes.

The project already knew `serde_json::Value` construction was 44.2% of
allocation *churn* (`memory-management-state.md:63`). New here: the mechanism,
the *peak* figures, and the specific sites.

---

## 1. Unbounded growth (rank separately — these have no steady state)

### U1. Unauthenticated remote memory exhaustion via metric cardinality
`auth.rs:866-919`, `auth.rs:1472-1479`, `auth.rs:1515-1522`, `metrics.rs:68-82`

`parse_path` copies URL segments verbatim into the `group`/`version`/`resource`
labels of `apiserver_request_total`. A request with no credential is
`Identified("system:anonymous")` (`auth.rs:279-286`), so the `BadToken` 401
shortcut that correctly records empty labels (`auth.rs:1187`) is bypassed; the
403 path records the raw values. No `remove_label_values` or `.reset()` exists
anywhere in the apiserver.

`curl -k https://apiserver/apis/$RANDOM/$RANDOM/$RANDOM` — no token, no client
cert — mints a permanent ~1.03 KiB series. At 1,000 req/s that is **1.06 MB/s,
1 GB in ~16 minutes**. A `/metrics` scrape at 1M series transiently allocates a
further ~700 MB.

Fix: validate the three labels against `AppState::resource_registry` + the CRD
set, else `"other"`. Costs one hash lookup on the auth path. The store crate
already solves exactly this with `prefix_bucket` (`store/src/metrics.rs:335-346`).

Benign cardinality is bounded at ~5.8K series (~6 MB), so this is a security
fix, not a steady-state saving. **Verified end to end.**

### U2. Namespace deletion never purges `RbacIndex` — stale authorization + leak
`namespaces.rs:906-949` (esp. `:933`), `rbac.rs:69-74`

The namespace cascade hard-deletes objects from the store and purges
`node_graph` (`:947`) but never calls `rbac_index.remove_object`. Single-object
delete, finalizer drain and both deletecollection paths all purge correctly
(`resource.rs:990,1023,1100,1092,4073-4075,4261-4263`) — the cascade is the only
gap.

~859 B leaked per namespace/RBAC/delete cycle; ~1 MB per conformance run.
Worst case a 4 MiB Role leaks 2-3 MB per cycle.

**The memory is the lesser problem: a RoleBinding deleted by namespace teardown
still grants its permissions until restart, and re-applies if the namespace name
is recreated** (`rbac.rs:172-182` matches on `binding.namespace`). CI reuses
namespace names constantly. `enumerate_rules` also linear-scans both binding
vectors per authorization decision, so the leak slows every request.

### U3. `CrConversionCache` unbounded, and missed by the namespace cascade
`state.rs:478-489, 511-513, 541-548`; `cr.rs:539-546`

`HashMap<(rv, targetApiVersion), Arc<serde_json::Value>>` with no capacity, TTL
or LRU. Bounded only by live CR count x target versions, at the full 10x `Value`
cost. 10,000 CRs x 10 KB x 2 versions ~ **2.0 GB**, vs ~200 MB as pre-serialized
bytes (~90% saving, and it removes the `Value::clone()` on every hit).

Genuine leak on top: `namespaces.rs:933` never calls
`evict_cr_conversion_cache`, so CRs destroyed by a namespace delete leave their
converted `Value` resident forever. Zero cost on clusters with no webhook-
conversion CRD.

### U4. `ever_matched` grows unbounded, and is populated where it can never be read
`watch.rs:922, 949-952, 1021-1024, 1119`

`HashSet<(String, String)>` per watch stream, one entry per object ever seen.
The `sendInitialEvents` loop at `:949` inserts unconditionally, *before* the
fast-path/slow-path split at `:1021` — and the fast path (no selectors) never
reads the set, as its own comment says. So a no-selector `sendInitialEvents`
watch fills ~640 KB it cannot use, held for the stream's 30-minute life. 50 such
informers = **~32 MB of pure dead weight**. Fix is a one-line gate on the insert.

On selector-filtered watches the set is legitimate but still unbounded in object
count. Separately `:1149-1151` allocates four `String`s per *non-matching* event.

### U5. `reclaimed_horizons` grows monotonically
`sqlite.rs:243-248, 266-284, 809-813`

One entry per shard key torn down and never recreated under the identical key.
Namespace-scoped watch prefixes are by construction never reused. ~111 B per
abandoned prefix (5.5 MB at 50,000). The sharper cost is CPU:
`find_reclaimed_horizon` (`:932-938`) is an O(n) `starts_with` scan on the
watch-open path.

The `shards` map itself does **not** leak — `schedule_idle_gc` removes under the
same write lock as its idle check, with a correct `Arc::ptr_eq` guard.

---

## 2. Ranked by growth order

Absolute bytes at today's scale are misleading — the measured baseline is
119.5 MiB peak / 86.1 MiB mean (`temp/e2e/0903-1111-csi-hostpath/monitoring/rss.csv`,
128 samples), and the largest collection in that cluster is 87 KiB / 15 CRDs.
What decides when u7s stops fitting on a cheap VPS is the *order*, so that is
the sort key. Dimensions: `P` pods, `N` nodes, `NS` namespaces, `W` concurrent
watchers, `C` CRDs, `R` custom resources, `K` objects in the listed collection,
`S` ring shards, `D` distinct URL paths, `Q` in-flight requests (capped 200),
`t` uptime.

Measured coefficients: one 5,624 B pod = 55.8 KB as `Value` (9.9x); a LIST peaks
at 19.6x stored bytes; a POM LIST at 16.5x.

### Class A — unbounded in time. No steady state; scale is irrelevant.

| Finding | Order | Coefficient |
| --- | --- | --- |
| U1 metric cardinality, unauthenticated | **O(D)**, D attacker-chosen -> O(t) | ~1.03 KiB/path |
| U2 RBAC index never purged on ns delete | **O(t)** in ns-delete count | ~859 B/cycle (+ stale authz) |
| U3 `CrConversionCache` no cap + missed eviction | **O(R x versions) + O(t)** | ~10x CR size/entry |
| U5 `reclaimed_horizons` | **O(t)** in abandoned prefixes | ~111 B each |

These are the only findings that get worse while the cluster stays still.

### Class B — super-linear. These are the walls.

| Finding | Order | Note |
| --- | --- | --- |
| Quota recount on create (`quota.rs:640`, `resource.rs:2738`+`:2863`) | **O(P_ns)/create -> O(P_ns^2)** to fill a namespace | x2 per create; gated on a ResourceQuota existing |
| Preemption `pods_on` per candidate node (`lib.rs:3060`) | **O(N x P)** per plan, x5 attempts | + N mutex acquisitions |
| Scheduler node re-LIST x unbounded spawn (`lib.rs:2816`, `run.rs:547`) | **O(P_pending x N)** co-resident | no node cache, no semaphore |
| `find_crd` per CR request (`cr.rs:224`) | **O(C)/request -> O(C x R)** per reconcile sweep, xQ | uncached list + parse + schema clone |
| `matching_shards` on every write (`sqlite.rs:862`) | **O(S)** per write | CPU, on the hottest path |
| Watch fan-out re-parse (`watch.rs:1041`) | **O(W)** parse+serialize per write | CPU; 941 µs/write @ W=50 |

### Class C — linear in a cluster dimension, times the ~10x `Value` tax.

| Finding | Order | Why it stings |
| --- | --- | --- |
| Store LIST ignores `limit` (`sqlite.rs:1514-1556`) | **O(K_prefix)** even when the client asked for O(limit) | defeats the client's own bound |
| `fetch_initial_events` (`watch.rs:377`) | **O(K) x 9.9**, x2 on a cold shard | no selector pushdown, no paging |
| LIST double-materialization (`generic.rs:674`) | **O(K) x 19.6** | one function, 6 call sites |
| POM LIST (`resource.rs:188`) | **O(K) x 16.5** | costs more than the full object it shrinks |
| Scheduler resync (`run.rs:818`, `lib.rs:952`) | **O(P) x 19.8 every 30 s** | unconditional, on a timer |
| `ever_matched` (`watch.rs:949`) | **O(K x W)** | dead weight on no-selector watches |
| `replayed` (`sqlite.rs:2131`) | **O(min(512, backlog) x W)** | one-character fix |
| Ring shards (`sqlite.rs:104`) | **O(S x 512 x objSize)** | no global budget |
| Namespace cascade delete (`sqlite.rs:1304`) | **O(K_ns)** held in one transaction | |

### Class D — constant. Only these are material at today's scale.

| Finding | Size | Note |
| --- | --- | --- |
| SQLite page cache | **15.6 MiB (11.7 recoverable)** | **~14% of the 86 MiB mean** |
| glibc arenas, no `MALLOC_ARENA_MAX` | 5-15 MB est. | O(threads), threads bounded |
| `max_blocking_threads` unset | ~2.8 MB resident / 260 MiB virtual | |
| Broadcast channel | ~2.1 MiB | half wasted on bookmarks |
| Duplicate deps | ~0.3-1 MB text | |
| Per-request copies (SMP patch, webhooks, defaults, `from_value` clones) | **O(objSize) x Q**, Q<=200 | bounded by inflight; churn, not ceiling |

**Reading this for prioritisation:** Class D is what your 86 MiB is made of
*today*. Class A degrades with uptime alone. Class B decides the ceiling. Class C
is a constant-factor tax on every dimension at once — and it is the cheapest to
fix, because the ~10x is pure waste rather than a space/time trade.

## 3. Detail, previously ranked by absolute gain

Units differ and must not be summed: *per-request peak*, *already-paid
resident*, and *churn* are three different things. Column 3 says which.

| # | Finding | Kind | Memory gain | CPU / other cost |
| --- | --- | --- | --- | --- |
| 1 | Scheduler resync LISTs all pods every 30s, then deep-clones each into a wrapper before filtering | per-tick peak + churn | 11 MB (100 pods) / 56 MB (500) / 558 MB (5k) -> ~0 | **none — strictly faster** |
| 2 | Scheduler re-LISTs all nodes per scheduling decision, unbounded concurrency | transient peak | 1.2 GB worst case (500 pending pods) -> 200 KB cached | staleness; a 2nd watch stream |
| 3 | `fetch_initial_events` materializes the whole collection as `Value`s — no selector pushdown, no paging; a cold shard lists it *twice* | per-request peak | 272 MB -> ~28 MB @ 5k pods (**-90%**) | one SQL round trip per page |
| 4 | LIST materializes all N items, then `to_value` deep-clones the whole list | per-request peak | 53.9 MB -> 3.1 MB per 500-pod page (**-94%**) | **none — 1.6x faster** |
| 4b | POM LIST holds full items + cloned metadata; POM peak is **1.44x the full object** it is meant to shrink | per-request peak | 45.3 MB -> 2.8 MB (**-94%**); 113 MB on a 5k LIST | **none** |
| 5 | Store LIST paths ignore `limit`; `watch()` backfill unlimited | per-request peak | ~38 MB per request, client-triggerable | borrowck friction; new `ListOptions` field |
| 6 | Ring subsystem: per-shard caps, no global budget | resident | 4.75 MiB x shards (347 MB @ 73; ~32 MB observed) | O(\|shards\|) scan already on write path |
| 7 | `find_crd` re-lists + re-parses every CRD per CR request, then deep-clones the schema | per-request peak | ~2 MB held/request; ~100 MB @ 50 concurrent | one RwLock read; invalidation hook (exists) |
| 8 | SQLite page cache 2 x 8 MB | **already-paid resident** | **11.7 MiB certain** | **real IO trade — benchmark first** |
| 9 | Scheduler deep-copies whole pod cache per decision, even for affinity-free pods | churn | 3.2 MB/decision; 1.6 GB per 500-pod burst | lock hold time (fix *reduces* it) |
| 10 | `replayed` ring snapshot pinned for the whole watch stream lifetime | resident | 20 MB @ measured depth; 392 MB worst case | **none — one-character fix** |
| 11 | `strategic_merge_patch` holds 4 simultaneous copies of every merge-keyed array, recursively | per-request peak | ~144 KB per PATCH (2.6x the object) | none — removes work |
| 12 | Broadcast channel: 1024 slots, half wasted on bookmarks | resident | ~1.04 MiB | more `Lagged` -> O(ring) recovery |
| 13 | `apply_defaults` round-trips each spec `clone -> typed -> to_value` | per-request peak | ~87 KB per workload write | none (`.take()` is a drop-in) |
| 14 | Mutating webhooks deep-clone the object once per webhook, including non-matching ones | churn | 168 KB @ 3 webhooks; ~112 MB/s @ 200 w/s x5 | none — one `match` |
| 15 | `do_patch` pre-patch snapshots clone whole bodies (Node, StorageClass) | per-request peak | 210 KB of a 510 KB node-patch peak (41%) | lazy re-parse on the rare reject path |
| 16 | `apply_json_patch` clones the entire object for atomicity, twice on the webhook path | per-request peak | 56 KB; 3V -> 1V with #14 | one extra read-only tree walk |
| 17 | 94 production sites of `from_value(x.clone())` | churn | small peak | **-95% time, -99% allocs** on table render |
| 18 | Protobuf writes parsed twice via a discarded intermediate `Value` | churn | ~112 KB + 2x parse per write | handler signature churn, ~15 sites |
| 19 | No global allocator; no `MALLOC_ARENA_MAX` | resident | 5-15 MB (est.) | malloc lock contention |
| 20 | `max_blocking_threads` unset; ~200 threads park on 2 SQLite connections | resident + virtual | ~2.8 MB resident, 260 MiB virtual | `spawn_blocking` queue depth |
| 21 | Shard-key metric labels bypass `prefix_bucket` | resident | 20-30 MB @ high namespace churn | loses per-namespace observability |
| 22 | Quota re-counts the namespace twice per create | churn | 2.2 MB per create in a 200-pod ns | needs an incremental counter |
| 23 | Duplicate deps: `ring` + `aws-lc-rs`, 2x tungstenite, 2x RustCrypto | resident text | ~0.3-1 MB | upgrade friction |
| 24 | `put_sync` builds two `Value` trees per update | transient | ~46 KB/pod; 18 MB @ 1.5 MB object | one memcmp on the miss path |
| 25 | No-op write path clones the whole body then discards it (`sqlite.rs:1087`) | churn | 1.14 MB/s @ 3k pods | none |
| 26 | `splice()` buffers 256 frames/direction, no websocket size cap | per-session peak | 8 MiB/session (4 GiB theoretical) | backpressure instead of buffering |
| 27 | `pod_matches_field_selector` deep-clones the whole spec to read `nodeName` (`pods.rs:115`) | churn | 17 KB/pod transient | **none — one line** |

### CPU-dominant findings (little memory gain, large CPU gain)

These matter because the audit's premise was memory, but they are where the
compute actually goes.

| Finding | Cost now | After |
| --- | --- | --- |
| Watch fan-out re-parses + re-serializes **per watcher** (`watch.rs:1041`) | 941 µs/write @ M=50 | ~19 µs (**-98%**) |
| Selectors evaluated *after* the full parse (`watch.rs:1062-1099`) | 31% of a core @ 1% selectivity, 99% wasted | ~1% of that |
| `from_value(x.clone())` — 94 production sites | 155,500 allocs / 4.31 ms per `kubectl get pods` | 2,000 allocs / 0.20 ms |

**The zero-parse watch path is already built and unreachable.**
`ndjson_event_raw` (`watch.rs:24`) is documented, unit-tested
(`watch.rs:1883`) and benchmarked (`benches/watch_fanout.rs`), but its only
production references are the ADDED/MODIFIED arms of `encode_watch_event`
(`:251`, `:268`) — and `watch_generic_impl` handles every Added/Modified in the
`if` at `watch.rs:1018`, so the `encode_watch_event` call at `:1280` sits in the
`else` branch and only ever sees Bookmark/Deleted. `prepare_live_event`'s doc
already promises the `Bytes` are shareable "across callers (same event, multiple
watchers)"; nothing shares them. **Verified by reading the branch structure.**

Note on framing: per-watcher re-encoding is a CPU and allocator-churn problem,
**not** an M-fold resident-memory one. Each `Value` lives and dies inside one
poll, so transient peak is bounded by tokio worker count (~580 KB on 10 cores),
not by watcher count.

Beyond the table, and legitimate more often than it looks: for resource types
where `apply_defaults` is a no-op — **Pods, ConfigMaps, Nodes, Secrets and all
CRs are absent from its allowlist** (`defaults.rs:16-113`) — a LIST can splice
stored bytes straight into the response without parsing at all: **53.9 MB ->
2.75 MB and 313x faster**. Precondition: no defaults, no POM/Table/protobuf
transform, and label selectors handled by a byte prefilter.

### Measured LIST strategies (500 pods, 2,746 KiB stored)

| strategy | peak | vs raw | CPU |
| --- | --- | --- | --- |
| current (parse + `to_value` envelope + `to_vec`) | 53,915 KiB | 19.6x | 19.59 ms |
| envelope by move (drop the `to_value` clone) | 31,366 KiB | 11.4x | 11.58 ms (1.7x) |
| streaming parse (one `Value` alive at a time) | 3,143 KiB | 1.1x | 11.98 ms (1.6x) |
| pass-through (no parse) | 2,750 KiB | 1.0x | 0.06 ms (313x) |

`build_list_response` (`generic.rs:645-675`) is the highest-leverage single
change in the audit: ~6 lines, and all six non-test LIST endpoints route through
it (`resource.rs:206,2544`, `cr.rs:2193,3163,12925`, `core.rs:207`, `csr.rs:221`).

---

## 4. Verified negatives (checked, cost nothing — do not re-audit)

- **The 1.01 MB protobuf descriptor is not in the release binary.**
  `proto_descriptor` is `#[cfg(test)]` (`lib.rs:28-29`); confirmed by `grep -a`
  on the built artifact — 0 hits.
- No discovery or OpenAPI document is cached as `Value`; a regression test at
  `discovery.rs:5825` enforces this. The discovery cache is ~40-60 KB of typed
  structs.
- The generated adapters contain **zero** non-test statics, consts or lazy maps.
  `core_gen_adapter.rs` (11,417 lines) has none of any kind.
- The scheduler's pod cache is already a typed projection (`TalliedPod`, 176 B),
  not `Value` — ~4 MB for 5,000 pods vs 277 MB if it held `Value`s. Already won.
- `SigCache` is hard-capped at 512 (~57 KB). `WatchLimitState` is swept.
  `QuotaAdmissionLocks` is evicted. `inflight.rs` is fully bounded.
- `Bytes::from(Vec<u8>)` never memcpys in bytes 1.12.1 — only the explicit
  `.clone()` at `sqlite.rs:1087` copies.
- The `shards` HashMap does not leak (see U4).
- Request bodies are capped at 4 MiB and the limit is applied outermost, before
  auth (`lib.rs:70,611`). Mutating queue depth is capped at 512. This is done well.
- `chrono-tz`'s 18 MB rlib is pruned by fat LTO to 2 retained symbols. Not bloat.
- `panic = "abort"` would cut 2.25 MiB of unwind tables but those pages stay
  cold — ~0 RSS — and it would break the deliberate panic-isolation boundaries at
  `lib.rs:712-721` and `:735-745`. **Rejected on correctness grounds.**
- `strip`/`debug` settings affect file size and page cache, not heap. ~0 RSS.
- **`proxy.rs` has no unbounded response buffering.** Every streaming path
  streams (`:331`, `:270-277`, `:2019`, `:2774`); every buffering path is capped
  at `MAX_BODY_BYTES` (`:2628-2642`, `:2513`) or hard-fails at 64 KiB
  (`:1680-1694`). One behavioural note, not a memory one: the konnectivity leg
  (`:2513`) cannot stream at all, so a >4 MiB pod-proxy response *fails* there
  while the direct-dial leg streams it.

## 5. Corrections to existing project docs

- `memory-management-state.md:85-86` — "Shards are created lazily on first write
  and never reclaimed" is wrong on both halves: shards are created on first
  *watch* (`sqlite.rs:1973-1978`), and idle-GC does reclaim them (`:217-249`).
- `ai/findings/legacy/0818-1303-conformance-memory-audit-2026-08-18.md:45` cites
  `DELETION_LOG_CAP = 1024`, superseded by the 512-full / 4096-total two-tier
  scheme (`sqlite.rs:644,662`).
- `[profile.dist]` is dead configuration: `scripts/build-release-tarball.sh:46`
  builds `--release`, never `--profile dist`, so the `opt-level = "s"` override
  for `u7s-proto-generated` never applies to a shipped artifact.

## 6. Suggested order

1. **U1** — unauthenticated OOM. Security, not perf.
2. **U2** — stale authorization after namespace delete. Correctness, not perf.
3. `build_list_response` envelope-by-move — 6 lines, -42% LIST peak, 1.7x faster.
4. `sqlite.rs:2131` `&replayed` -> `replayed.drain(..)` — one character, tens of MB.
5. `pods.rs:115` — delete the `clone()`+`from_value`, read `nodeName` by index
   like the six lines directly below it already do.
6. `watch.rs:949` — gate the `ever_matched` insert on a selector being set.
7. Scheduler resync `fieldSelector` + map/filter order — two one-liners.
8. `MALLOC_ARENA_MAX=2` in `scripts/install.sh` — one line, no code, measurable
   with the existing saturate-at-max-inflight bench.
9. Wire up `ndjson_event_raw` for builtin no-selector watches — the largest CPU
   win, and the scaffolding already exists.

Items 3-6 are all strictly-faster-too. The `serde_json::Value` representation
itself (a Vec-backed map would cut 634 B/node to ~112 B for a 2-key map) is the
larger prize but needs a `Map` replacement, not a local change.
