# SQLite as the u7s state store

**Status:** Accepted  
**Date:** 2026-05-18

## Context

u7s needs an embedded state store for Kubernetes object persistence. The two viable candidates for a memory-constrained Rust project are SQLite and LMDB.

## Decision

Use SQLite in WAL mode via `rusqlite` (bundled feature).

## Rationale

The target workload peaks at ~17 writes/second (100 Argo CD Applications × 10 syncs/minute). SQLite WAL sustains >1,000 writes/second with p99 latency well under 10 ms — two orders of magnitude of headroom. The decisive advantage is operational: `sqlite3 state.db` is sufficient for live debugging and disaster recovery without additional tooling. LMDB's binary format requires custom cursor code to inspect.

LMDB's advantages (higher read throughput, zero-copy reads) are irrelevant at this scale. The `lmdb-rkv` crate is effectively dormant, and `MDB_MAP_FULL` (requires process restart to resize the mmap) is a real operational risk on a pre-alpha system.

## Watch notification

All writes go through a single in-process code path. Watch fan-out uses an in-memory broadcast channel fired after `COMMIT`. Watch resumption uses an in-memory ring buffer (`VecDeque<Arc<InternalEvent>>`, capacity 1000) — no `events` table, no DB query on reconnect. This eliminates one write per mutation and the serde round-trip on the watch path. `resourceVersion` is persisted in `objects.revision` and a `meta` table.

## Consequences

- WAL mode still required for reader concurrency (GET/LIST do not block on writes).
- Ring buffer horizon triggers 410 Gone → relist, which is the defined Kubernetes recovery path.
- If write throughput ever exceeds the 10 ms p99 threshold under load, re-evaluate LMDB. See `state-store.md` §6 for the benchmark spec.
