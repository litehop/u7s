# apiserver hot-path audit (2026-11-24)

Bead: mayor-f7ym1

**Verdict: apiserver request CPU is dominated by JSON that is parsed into
`serde_json::Value`, defaulted and re-serialized for every LIST item, by every
open watch being woken for every store write, and by the protobuf/Table LIST
paths that materialize the whole collection. GET and single-object writes are
cheap (0.15 ms and 0.9-1.5 ms CPU). Each hotspot has a measured baseline and a
target in its bead.**

Scope: LIST/WATCH/GET of ConfigMaps, Secrets, Pods, Deployments and the write
path on the host apiserver of the lima-node-smoke rig (release build,
`lto=fat`, macOS arm64, SQLite store, in-process scheduler). Out of scope: TLS
cost (rustls/chacha is 10-26% of on-CPU samples, set by the client's connection
pattern), kubelet/KCM behaviour.

## Workload (repeatable)

`scripts/bench/apiserver-hot-paths.sh --kubeconfig temp/u7s/kubeconfig --pid <apiserver pid>`
(`lsof -nP -iTCP:<port> -sTCP:LISTEN` gives the pid; defaults are the numbers
below, `--skip-seed` reuses a seeded store).

- Seed: 10 namespaces x 50 each of ConfigMap (~600 B data), Secret,
  Deployment (replicas 0), Pod (2 containers). Pods bind to a fake node
  `bench-node` and tolerate everything, so scheduler, kubelet and node
  lifecycle leave them alone. Served totals: 523 ConfigMaps / 1.08 MB, 502
  Secrets / 0.85 MB, 509 Pods / 2.84 MB, 503 Deployments / 1.53 MB (kubectl
  apply adds managedFields and last-applied, ~2 KB per object).
- Phase 1: 2000 GETs per kind. Phase 2: 100 LISTs per variant (namespaced,
  all-namespaces, labelSelector, `limit=100`, protobuf Accept). Phase 2b: 200
  sequential POST/PUT/PATCH/DELETE per kind. Phase 2c: 500 PUTs with 0 and then
  100 idle non-matching watchers. Apiserver CPU is attributed per label in the
  sequential phases (ps `cputime`, 10 ms resolution; sequential, so
  attribution is clean).
- Phase 3 (30 s): 20 informer-like LIST+WATCH clients, 4 readers (GET/LIST
  loops), 1 writer.
- Client is curl, batched per process (connection reused within a batch);
  latency is for same-machine before/after comparison, not absolute.

Run D below is the canonical baseline; run C (same code, same seed) agreed
within ~10% on every row. Raw output is in the worktree's `temp/` only;
numbers are copied here.

## Baseline (run D)

Sequential apiserver CPU per request (whole process, includes ~2.5 ms/s of
background scheduler/KCM/kubelet traffic):

| request | ms CPU/req | p50 / p99 client ms |
| --- | --- | --- |
| GET configmaps / secrets / deployments / pods | 0.16 / 0.125 / 0.15 / 0.17 | 0.13-0.17 / 0.3-0.6 |
| GET pods, Accept protobuf | 0.215 | 0.24 / 2.4 |
| LIST ns (50 items) configmaps / secrets / pods / deployments | 0.6 / 0.5 / 1.5 / 1.2 | 0.7 / 0.7 / 1.8 / 1.4 |
| LIST all-ns configmaps / secrets (~510 items, ~1 MB) | 4.4 / 3.9 | 5.5 / 4.7 |
| LIST all-ns pods (509, 2.8 MB) | **13.8** | 15.8 / 17.1 |
| LIST all-ns deployments (503, 1.5 MB) | 10.1 | 11.6 / 16.2 |
| LIST all-ns pods, labelSelector (20% match) | 9.9 (72%) | 10.4 / 15.3 |
| LIST all-ns pods, Accept protobuf | **20.0** | 21.5 / 28.1 |
| LIST all-ns pods `limit=100` | 3.3 | 3.8 / 7.9 |
| POST / PUT / PATCH / DELETE configmaps | 0.90 / 0.85 / 0.85 / 0.85 | 0.4 each |
| POST / PATCH / DELETE pods | 1.40 / 1.50 / 1.20 | 0.9 / 1.0 / 0.7 |
| POST / DELETE secrets | 0.90 / 0.95 | 1.3 / 0.5 |
| PATCH deployments | 1.15 | 0.8 |
| PUT configmap, 0 extra watchers | 0.78 | 0.43 / 2.9 |
| PUT configmap, 100 non-matching watchers | **1.52** | 0.54 / 3.9 |

Mixed phase (30 s, 20 watchers + 4 readers + writer): 41.7 CPU-s (1.4 cores)
for 39,891 timed requests and 81,645 watch lines delivered. GET p50 0.4-0.5 ms
but p99 4.8-6.4 ms (10x); LIST all-ns configmaps p50 8.5 / p99 20 ms; writes
p50 0.9-1.9 / p99 4.7-10.4 ms. RSS: 34 MiB on a fresh stack, 138 MiB after
seeding, 191 MiB peak (and at end) of phase 3.

A first pair of runs used `schedulerName: bench-idle` pods; the in-process
scheduler bound and ran them (bead mayor-c3uvm, a correctness bug), which
inflated POST pods to 5.3 ms, LIST pods to 16.4 ms and RSS to 333 MiB. Those
figures are discarded; POST pod is not a hotspot (1.4 ms, 1.6x a ConfigMap).

## On-CPU profile

macOS `sample` (1 ms) attached to the apiserver during the mixed phase and
isolated loops; leaf self-time attributed to the nearest `u7s_*` frame
(`file:line` from the release build's line tables). `sample` under-counts
absolute CPU ~4x (60+ threads); use shares, not counts.

- Mixed phase leaf shares: syscalls/IO (socket `writev`, sqlite `pread`) 28%,
  malloc/free 16%, TLS/crypto 10-26%, JSON parse 7%, JSON serialize 3%,
  memcpy 6%.
- Isolated LIST all-ns configmaps loop: `writev` 15%, ChaCha20 13%, serde_json
  string serialize 8%, string parse/utf8 9%, memmove 7%, malloc/free 10%,
  sqlite `pread` 8%. Excluding TLS and socket IO, parse+serialize+malloc/drop
  is roughly half.
- Under every watch stream, tokio broadcast `recv_ref` ->
  `parking_lot RawMutex::lock_slow` (`sqlite.rs:2630`): all receivers contend
  on the channel's single tail mutex.

## Allocation profile (dhat, depth 30, partial bench)

`run-all.sh --profile --dhat-depth 30` run with the pre-correction seed
(scheduled pods) through seeding, GETs and part of phase 2; attribution is by
frame match over `dhat-heap.json`. Totals: 12.0 GB in 103 M blocks.

- `stream_list_json` stacks: 1.35 GB / 7.52 M blocks over roughly 74 k listed
  items (derived from the apiserver log's LIST counts x item counts, +-30%):
  ~18 KB and ~100 allocations per item for a ~2 KB object, consistent with the
  9.9x `Value` inflation in `ai/findings/2026-09-03-memory-audit-apiserver-store-scheduler.md`.
- `create_pod` stacks: 119 MB / 1.36 M blocks over 500 pod creates:
  ~238 KB and ~2,700 allocations per POST pod (lower bound; frames beyond
  depth 30 are cut).
- Heap at peak (t-gmax) 124 MB; 108 MB of it in stacks through
  `u7s_scheduler`, 65 MB in serde_json `Value` trees. Taken with scheduled pods
  running, so it needs re-taking before acting (see the RSS bead).

## Fan-out measurement

Phase 2c of the script: 500 PUTs of one ConfigMap, apiserver CPU per write:
0.78 ms with only the rig's own watchers, 1.52 ms with 100 additional idle
watchers on a prefix the write never matches (+7.4 us per watcher per write,
all wasted). A hand run with 50 *matching* watchers measured +12 us per
watcher-write on top of the 1.0 ms base.

## Ranked hotspots

| # | cost | where | bead |
| --- | --- | --- | --- |
| 1 | LIST parses to `Value`, defaults and re-serializes every item (pods 13.8 ms/LIST, 27 us/pod) | `crates/apiserver/src/handlers/resource.rs:139-158` (`stream_list_json`), callers `resource.rs:308`, `handlers/core.rs:172` | mayor-f3aaa |
| 2 | Every watch woken for every store write (+7.4 us/watcher/write wasted); shared tail mutex; GET p99 10x p50 under load | `crates/store/src/sqlite.rs:2630-2667`, `crates/apiserver/src/handlers/watch.rs:1271` | mayor-nrm0f |
| 3 | protobuf/Table/PartialObjectMetadata LIST materializes `Vec<Value>` (pods 20.0 vs 13.8 ms) | `resource.rs:330-381`, `core.rs:194-247` | mayor-z37qr |
| 4 | labelSelector LIST parses everything first (72% of unfiltered at 20% selectivity) | `resource.rs:140-146`, `resource.rs:338`, `core.rs:201` | mayor-tfd0f |
| 5 | RSS 34 -> 138 MiB after seeding 2000 objects, 191 MiB peak; heap peak attributed to scheduler pod-cache Values | `crates/scheduler/src/run.rs:489-510`, `core.rs:84-104` | mayor-7s8gr |

Related correctness bug found while profiling: mayor-c3uvm (scheduler ignores
`spec.schedulerName`).

Not hotspots: GET (0.125-0.17 ms CPU, p99 under 0.7 ms), namespaced LIST of 50
objects (0.5-1.5 ms), single-object writes (0.85-1.5 ms, mostly SQLite commit
and watch fan-out). The scheduler running in-process is 5-10% of on-CPU
samples during pod writes. Every watch event is followed by a BOOKMARK
(`sqlite.rs:2667`, required by KCM's consistency check), which doubles frames
per watcher event; left alone because it is load-bearing.

## Method for after-measurements

Same script, same seed, fresh `run-all.sh --stack-only` stack, release build.
A bead is done when its row meets the target in two consecutive runs and the
touched kind passes its conformance focus.
