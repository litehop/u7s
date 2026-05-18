# u7s State Store — Trade-off Analysis and Implementation Spec

**Status:** RFC-grade implementation prompt. Last updated: 2026-05-18.
**Audience:** A senior Rust engineer building this component from scratch.
**Read first:** `architecture.md` §6 (storage interface), §9.1 (SQLite vs LMDB decision). This document assumes familiarity with that material and expands it into a full spec.

---

## 1. Decision Summary

**Recommendation: SQLite (WAL mode).**

SQLite is the right default for u7s because the target workload — a Kubernetes control plane for Argo CD GitOps on a 1 GB VPS — will never exceed SQLite's write throughput ceiling in normal operation. The simulated peak load is ~1,000 object writes/minute (~17/second). SQLite WAL can sustain >1,000 writes/second with p99 latency well under 10 ms on commodity SSDs, giving two orders of magnitude of headroom. The decisive advantage is operational: `sqlite3 state.db` is sufficient for live debugging, disaster recovery, and schema inspection without any additional tooling. LMDB's binary format requires custom cursor code to inspect. In a pre-alpha system where correctness and debuggability matter more than raw throughput, that gap is material.

**Resolution trigger:** Benchmark both backends under the simulated Argo CD load (see §6). If SQLite p99 write latency exceeds **10 ms** sustained over a 5-minute run, switch to LMDB. If SQLite RSS with the chosen `cache_size` exceeds **20 MB** under load, reduce cache and retest. Only if both thresholds are violated simultaneously — and the reduced cache causes unacceptable read latency — is LMDB warranted.

---

## 2. Kubernetes Storage Semantics

What the state store must do, concretely. No approximations.

### 2.1 Object Storage

Every Kubernetes object is stored as serialized bytes (JSON in Phase 1; MessagePack is a deferred option) under a deterministic string key:

```
/registry/pods/<namespace>/<name>
/registry/namespaces/<name>
/registry/apps/deployments/<namespace>/<name>
/registry/rbac.authorization.k8s.io/clusterroles/<name>
/registry/<group>/<plural>/<namespace>/<name>   # custom resources
```

Key derivation is defined in api-server.md §5. The store does not interpret key structure — it exposes prefix-scan operations, and the API server constructs keys.

### 2.2 Resource Versions

The store maintains a **single global monotonic counter** — the **revision**. Every successful write (put or delete) atomically increments this counter and stamps the affected object with the new value. The counter is persisted with the data; it never resets across restarts.

A Kubernetes `metadata.resourceVersion` is the decimal string of this `u64`: `"42"`.

Rules:
- `PUT` with `metadata.resourceVersion: "42"` → the store must verify the stored object is currently at revision 42 before overwriting. Mismatch → 409 Conflict.
- `PUT` with `metadata.resourceVersion: "0"` → the object must not exist. Exists → 409 AlreadyExists.
- `PUT` with no `resourceVersion` → unconditional write (used internally by controllers for non-contested updates).
- `DELETE` follows the same optimistic concurrency rules.

### 2.3 Watch Resumption

A watch request carries `?resourceVersion=N`. The store must replay all events with revision > N, in revision order, then switch to live events.

If N is older than the compaction horizon: the store signals 410 Gone. The client must re-list.

If N == 0: do not replay history. Start from the current revision and deliver only future events. (The client should have done a list first to populate its cache.)

The implementation mechanism differs between SQLite and LMDB (see §3 and §4), but the semantics are identical.

### 2.4 List Consistency

A `Store::list(prefix, ...)` call must return a snapshot — all objects as they existed at a single revision. No object should appear at a stale version while another appears at a newer version in the same list response.

The list response carries a `resourceVersion` field at the list level reflecting the snapshot revision. Clients use this as the starting point for a subsequent watch.

SQLite achieves this with a `BEGIN DEFERRED` transaction. LMDB achieves it inherently via MVCC read transactions.

### 2.5 Optimistic Concurrency

The `Store::put` method takes `expected_revision: Option<u64>`:

- `None` → unconditional write.
- `Some(0)` → create-only: the key must not exist.
- `Some(rv)` → update-only: the stored object's revision must match `rv` exactly.

On mismatch, the store returns `Err(StoreError::RevisionMismatch { current: u64 })`. The API server translates this to an HTTP 409 response.

This is the mechanism that prevents two controllers from concurrently overwriting each other's changes — the second writer will lose and must re-read before retrying.

---

## 3. SQLite Design

### 3.1 Schema

```sql
-- One row per live Kubernetes object.
-- 'key' is the full /registry/... path.
-- 'value' is the serialized object bytes (JSON or MsgPack).
-- 'revision' is the global revision at which this version was written.
CREATE TABLE IF NOT EXISTS objects (
    key      TEXT    NOT NULL PRIMARY KEY,
    value    BLOB    NOT NULL,
    revision INTEGER NOT NULL
) WITHOUT ROWID;

-- Append-only event log. Each write (put or delete) appends one row.
-- 'revision' is the primary key — it IS the global monotonic counter.
-- 'key' identifies which object changed.
-- 'value' is NULL for deletes (tombstone).
-- 'is_delete' avoids ambiguity when value could legitimately be empty.
CREATE TABLE IF NOT EXISTS events (
    revision INTEGER NOT NULL PRIMARY KEY,   -- autoincrement gives global order
    key      TEXT    NOT NULL,
    value    BLOB,                           -- NULL on delete
    is_delete INTEGER NOT NULL DEFAULT 0    -- 1 = delete tombstone
);

-- Single-row table holding the current revision.
-- Updated atomically in the same transaction as every write.
-- Redundant with MAX(revision) FROM events, but avoids a full-table scan
-- on startup and on every read that needs the current revision.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);
-- Seed: INSERT OR IGNORE INTO meta VALUES ('revision', '0');

-- Optional: field index for spec.nodeName (Pods).
-- Enables O(log n) field selector queries for the node agent watch.
-- Add in Phase 3 when node agent watch performance matters.
CREATE INDEX IF NOT EXISTS idx_pods_nodename
    ON objects (json_extract(value, '$.spec.nodeName'))
    WHERE key LIKE '/registry/pods/%';
```

**Why `WITHOUT ROWID` on objects:** The `key` column is a text primary key. `WITHOUT ROWID` stores rows in a B-tree keyed directly by `key`, making prefix scans (`LIKE '/registry/pods/%'`) and exact lookups O(log n) without a secondary index. The downside is that updates require a full row replacement, which is acceptable — objects are small (typically 1–10 KB).

**Why a separate `events` table:** The event log is append-only. SQLite's autoincrement rowid on `events` provides the global monotonic counter without a separate sequence object. The current revision is always `MAX(revision)` from `events`, which SQLite can serve from the index root in O(1). The `meta` table caches this to avoid even that cost on the write path's read of the current revision.

**Subtle point:** `events` is the source of truth for revision ordering. `objects.revision` is a denormalized cache of "the revision at which this object was last written." Do not read `objects.revision` to determine ordering — use `events.revision`.

### 3.2 WAL Mode Configuration

Apply these pragmas immediately after opening each connection:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA cache_size   = -8000;    -- 8 MB page cache (negative = kibibytes)
PRAGMA busy_timeout = 5000;     -- 5 s; prevents instant SQLITE_BUSY on write contention
PRAGMA wal_autocheckpoint = 1000; -- Checkpoint after 1000 WAL pages (~4 MB default page size)
```

**Why WAL:** WAL (Write-Ahead Log) allows N concurrent readers and 1 writer simultaneously without blocking. The alternative (rollback journal) serializes all readers during a write. For u7s, readers (GET, LIST, watch replay) outnumber writers by a large margin. WAL is mandatory.

**Why `synchronous=NORMAL`:** `FULL` calls `fsync` after every transaction commit. `NORMAL` calls `fsync` only at WAL checkpoints, reducing write latency by 2–10x on typical SSDs. The risk is losing the last committed transaction if the OS crashes between the WAL write and the checkpoint. This is acceptable for a control plane that can re-create state from a Kubernetes reconciliation cycle. Do NOT use `OFF` — that risks corruption.

**Why `cache_size=-8000`:** 8 MB page cache. The default (~2 MB) is too small for any real workload and causes excessive disk reads. 8 MB covers ~2,000 4 KB pages — enough to keep the hot objects table in cache on a small cluster. Stay under 16 MB to respect the memory budget (architecture.md §2).

**Why `busy_timeout=5000`:** SQLite allows only one writer at a time. Without a timeout, a second writer gets `SQLITE_BUSY` immediately and the Rust code must implement retry logic. With a 5 s timeout, SQLite spins internally. Set this on every connection — reader connections can also time out waiting for a checkpoint.

**Why `wal_autocheckpoint=1000`:** Prevents the WAL file from growing unbounded. At 4 KB per page, 1000 pages = 4 MB WAL cap before auto-checkpoint. Checkpoint runs on the writer connection; it does not block readers. If a reader holds a read transaction open across the checkpoint window (e.g., a slow watch replay), the WAL cannot be fully reset — bound read transaction lifetimes (see §3.6 compaction notes).

### 3.3 Resource Version Implementation

The global revision counter is the `events.revision` column, which is an `INTEGER PRIMARY KEY` (SQLite autoincrement alias). SQLite guarantees that each `INSERT INTO events` gets a revision strictly greater than all previous rows, even across restarts (SQLite persists the max rowid).

Write procedure (single transaction):

```sql
BEGIN IMMEDIATE;

-- 1. Read current stored revision for optimistic concurrency check.
SELECT revision FROM objects WHERE key = ?1;

-- 2. If expected_revision check fails: ROLLBACK; return RevisionMismatch.

-- 3. Write the object.
INSERT INTO objects (key, value, revision) VALUES (?1, ?2, 0)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, revision = excluded.revision;
-- revision is set after the events insert; see step 5.

-- 4. Append to the event log. The autoincrement gives us the new revision.
INSERT INTO events (key, value, is_delete) VALUES (?1, ?2, 0);

-- 5. Update the object's revision to match the event's revision.
UPDATE objects SET revision = last_insert_rowid() WHERE key = ?1;

-- 6. Update meta table.
UPDATE meta SET value = CAST(last_insert_rowid() AS TEXT) WHERE key = 'revision';

COMMIT;
```

**Subtle point:** Steps 4 and 5 must happen in this order. The `last_insert_rowid()` call is connection-scoped; it returns the rowid from the most recent INSERT on this connection. This is safe within a single transaction.

**BEGIN IMMEDIATE:** Acquires a write lock immediately rather than upgrading from a read lock (which can deadlock in WAL mode). Always use `BEGIN IMMEDIATE` for write transactions.

### 3.4 Watch Resumption Query

Watch resumption is a query against the `events` table:

```sql
SELECT revision, key, value, is_delete
FROM events
WHERE revision > ?1
ORDER BY revision ASC;
```

This query is covered by the primary key index on `events.revision` — it is an O(log n + k) B-tree scan where k is the number of events since the requested revision.

**Polling vs. notification:** SQLite has no built-in pub/sub. The watch mechanism works as follows:

1. The write path holds a `tokio::sync::broadcast::Sender<InternalEvent>` per store instance.
2. After committing a write transaction, the writer sends to the broadcast channel (in-memory, no disk I/O).
3. Watch subscribers hold a `Receiver`. On receiving a broadcast event, they filter by prefix and forward to the HTTP response stream.
4. For watch resumption (catching up from an old revision), the subscriber first replays from the `events` table (SQL query above), then switches to the broadcast channel.

The replay-then-live-feed transition requires care to avoid missing events or delivering duplicates. See §8 for the full mechanism.

**SQLite update hook alternative:** SQLite provides a C-level update hook (`sqlite3_update_hook`). `rusqlite` exposes this. The hook fires synchronously in the writer thread after each row change. This could be used to notify watch subscribers without polling. However, it fires before `COMMIT`, which means the change is not yet visible to readers. Using the broadcast channel after `COMMIT` is simpler and correct. Skip the update hook.

### 3.5 List Consistency

```sql
BEGIN DEFERRED;
SELECT key, value, revision
FROM objects
WHERE key >= ?1 AND key < ?2   -- prefix scan using lex bounds
ORDER BY key ASC;
-- Also read the current revision for the list-level resourceVersion.
SELECT value FROM meta WHERE key = 'revision';
COMMIT;
```

**Why `BEGIN DEFERRED`:** A deferred transaction starts as a read transaction. SQLite WAL gives it a snapshot of the database as of the moment it first reads a page. All rows returned within this transaction reflect the same snapshot. The list-level `resourceVersion` is read in the same transaction, guaranteeing it matches the snapshot.

**Prefix scan bounds:** For a prefix `/registry/pods/default/`, the lower bound is the prefix itself and the upper bound is the prefix with the last character incremented by one: `/registry/pods/default0` (ASCII `0` = `\x30` = `\x2f` + 1 where `\x2f` is `/`). More robustly, use the next lexicographic string:

```rust
fn prefix_end(prefix: &str) -> String {
    let mut bytes = prefix.as_bytes().to_vec();
    // Increment the last byte; if it overflows, pop and carry.
    // For ASCII keys this is always safe.
    for b in bytes.iter_mut().rev() {
        if *b < 0xFF {
            *b += 1;
            return String::from_utf8(bytes).unwrap();
        }
        *b = 0x00;
    }
    // All bytes were 0xFF — no upper bound needed.
    String::new()  // signal: no upper bound
}
```

Use `WHERE key >= ?1 AND key < ?2` when `prefix_end` returns a non-empty string. Use `WHERE key >= ?1` when the prefix covers the entire remaining keyspace (pathological case, unlikely with `/registry/` prefix structure).

**Subtle point:** Do not use `LIKE '/registry/pods/%'` for large scans. `LIKE` forces a full table scan unless the prefix does not contain wildcard characters and the column is the primary key. The range-bound approach above uses the B-tree index directly.

### 3.6 Optimistic Concurrency

The check is inside the write transaction (step 1 in §3.3):

```sql
SELECT revision FROM objects WHERE key = ?1;
```

Logic in Rust:

```rust
match (stored_revision, expected_revision) {
    // Unconditional write: no check.
    (_, None) => {},
    // Create-only: key must not exist.
    (None, Some(0)) => {},
    (Some(_), Some(0)) => return Err(StoreError::AlreadyExists),
    // Update-only: revision must match.
    (None, Some(_)) => return Err(StoreError::RevisionMismatch { current: 0 }),
    (Some(stored), Some(expected)) if stored == expected => {},
    (Some(stored), Some(_)) => return Err(StoreError::RevisionMismatch { current: stored }),
}
```

**Subtle point:** The read of `objects.revision` and the subsequent write must be in the same `BEGIN IMMEDIATE` transaction. If you read outside a transaction and then open a write transaction, another writer can slip in between — the stored revision may have changed. `BEGIN IMMEDIATE` acquires the write lock before the read, preventing this race.

The `RETURNING` clause can collapse the select + update into one statement, but only for updates (not inserts). For a combined upsert with a CAS check, the two-step approach above is clearer and correct.

### 3.7 Rust Crates and Connection Pool Strategy

```toml
[dependencies]
rusqlite  = { version = "0.32", features = ["bundled"] }
r2d2      = "0.8"
r2d2_sqlite = "0.24"   # r2d2 pool adapter for rusqlite
```

**Why `bundled`:** Compiles SQLite from source as part of the Rust build. No dependency on the system `libsqlite3`. This ensures the exact SQLite version (3.45+) and compile-time flags (WAL, JSON1 extension for `json_extract`) are available everywhere.

**Why r2d2 over deadpool-sqlite:** r2d2 is synchronous, which matches `rusqlite` (which is also synchronous). The write path runs in a `tokio::task::spawn_blocking` call — the blocking pool handles the thread. r2d2 is simpler and better tested for this pattern. `deadpool-sqlite` wraps the same `spawn_blocking` internally; adding both crates has no benefit.

**Pool sizing strategy:**

SQLite WAL allows **one writer and N readers concurrently**. The pool must reflect this:

```rust
// Writer pool: size 1. Only one connection ever writes.
// This eliminates writer contention entirely.
let write_pool = r2d2::Pool::builder()
    .max_size(1)
    .connection_timeout(Duration::from_secs(10))
    .build(r2d2_sqlite::SqliteConnectionManager::file(&db_path))?;

// Reader pool: size proportional to expected concurrent reads.
// On a 1 vCPU target, 4–8 readers is more than sufficient.
// tokio's blocking thread pool will not exceed this count anyway.
let read_pool = r2d2::Pool::builder()
    .max_size(8)
    .connection_timeout(Duration::from_secs(5))
    .build(r2d2_sqlite::SqliteConnectionManager::file(&db_path))?;
```

Apply WAL pragmas in the connection initializer so every connection in both pools is configured:

```rust
impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for WalCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous  = NORMAL;
            PRAGMA cache_size   = -8000;
            PRAGMA busy_timeout = 5000;
        ")?;
        Ok(())
    }
}
```

**Blocking threads:** `tokio::task::spawn_blocking` draws from a separate thread pool (default: up to 512 threads, but effectively limited by `max_size` on the connection pools). Each read or write acquires a connection from the pool, runs synchronously, and releases. The tokio task awaits the `JoinHandle`. This is the correct pattern for synchronous I/O in async code.

### 3.8 Memory Footprint

| Component | RSS impact |
|---|---|
| Page cache (`cache_size=-8000`) | 8 MB maximum; starts near 0 and grows as pages are read |
| WAL file in memory (OS page cache) | Shared with disk; not private RSS unless pages are dirty |
| Connection pool (1 writer + 8 readers) | ~9 connections × ~100 KB per SQLite connection = ~900 KB |
| `events` table working set | Depends on event log size; with compaction at 1000 rows, negligible |
| **Total estimate** | **5–12 MB RSS** (matches architecture.md §2 estimate) |

The page cache is the dominant cost. With `cache_size=-8000`, SQLite will not use more than 8 MB for page caching. Physical pages are only allocated as reads occur — a cold start uses near-zero cache.

### 3.9 Compaction and Housekeeping

**WAL checkpoint:** The WAL file grows with every write until checkpointed. With `wal_autocheckpoint=1000`, SQLite checkpoints automatically in the writer after 1000 pages. This is passive — it runs inline in the write path, briefly. For control:

```rust
// Explicit checkpoint (run periodically or on clean shutdown):
conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
// TRUNCATE mode: full checkpoint + truncates the WAL file to zero.
// PASSIVE: does not block readers. FULL: waits for readers. TRUNCATE: same as FULL then truncates.
// Use PASSIVE for background jobs; TRUNCATE on clean shutdown.
```

**Stalled checkpoint risk:** If a reader holds a read transaction open (e.g., a slow watch replay scanning thousands of events), the WAL cannot be checkpointed past the snapshot that reader started on. The WAL file will grow until the reader finishes. Mitigate:
- Bound watch replay read transactions: read events in chunks of 100, committing between chunks.
- Set a hard timeout on watch replay read transactions (close and send 410 Gone if replay takes > 10 s).

**Event log compaction (implementing 410 Gone):**

Keep the `events` table bounded. A background task runs every 60 seconds:

```sql
DELETE FROM events
WHERE revision < (
    SELECT MAX(revision) FROM events
) - 1000;    -- keep last 1000 events
```

The `1000` is configurable. After deletion, the oldest revision in `events` defines the compaction horizon. When `Store::watch(prefix, from_revision)` is called with `from_revision` below this horizon, the store returns a stream whose first event is `WatchEvent::Bookmark { revision: current }` — signaling to the API server to send 410 Gone to the client.

**Implementation of the horizon check:**

```rust
async fn get_compaction_horizon(&self) -> Result<u64> {
    // Returns the smallest revision still in the events table.
    // If 0, no compaction has occurred.
    spawn_blocking(|| {
        let conn = self.read_pool.get()?;
        let horizon: Option<u64> = conn.query_row(
            "SELECT MIN(revision) FROM events",
            [],
            |r| r.get(0),
        ).optional()?;
        Ok(horizon.unwrap_or(0))
    }).await?
}
```

**VACUUM:** `VACUUM` rewrites the entire database file to reclaim space from deleted rows. Do not run it automatically — it locks the database. Run it manually during maintenance windows, or use `VACUUM INTO 'new.db'` for an online vacuum that writes to a new file without blocking.

---

## 4. LMDB Design

### 4.1 Database (DBI) Layout

LMDB organizes data into named databases (DBIs) within a single memory-mapped environment. Use three DBIs:

```
env/
├── objects          # TEXT key → BLOB value
│                    # Key: /registry/... (same key schema as SQLite)
│                    # Value: length-prefixed struct { revision: u64, data: [u8] }
│                    #        (8 bytes revision, then the JSON bytes)
│
├── events           # Composite key → BLOB value
│                    # Key: big-endian u64 revision (8 bytes, fixed-width)
│                    # Value: length-prefixed struct { key_len: u32, key: [u8], data: [u8] }
│                    #        NULL data = delete tombstone
│                    # Fixed-width key → natural sort order → efficient cursor range scan
│
└── meta             # TEXT key → TEXT value
                     # Key: "revision" → current revision as big-endian u64
```

**Why embed revision in the object value:** LMDB has no secondary index concept. Embedding the revision in the value bytes allows reading the object's revision without a separate lookup. The layout `[revision: u64 big-endian][json bytes]` requires a custom serializer but avoids a DBI join.

**Why big-endian u64 as the events DBI key:** LMDB sorts keys by raw byte comparison. Big-endian encoding ensures numeric sort order — revision 1 sorts before revision 2 as expected. A cursor scan `from_revision > N` becomes a cursor seek to `N+1` followed by a forward iteration.

**Alternative layout — separate objects/events approach (recommended):** The layout above with `objects` and `events` as two DBIs mirrors the SQLite schema and makes the implementation more symmetric. An alternative is to store all history inline under `{revision_prefix}/{key}` but this makes point lookups O(log n) per key with prefix scan instead of O(log n) direct. The two-DBI layout is preferable.

### 4.2 Resource Version: LMDB Transaction ID vs. Custom Counter

**Option A: LMDB's internal transaction ID (`MDB_TXN_ID`).**
Every LMDB write transaction has a monotonically increasing ID accessible via `mdb_txn_id()`. This could serve as the revision counter without any extra storage.

**Rejected:** `mdb_txn_id` is not exposed in the `heed` safe API and accessing it requires unsafe. More critically, the value is not guaranteed to be sequential with no gaps — LMDB may skip transaction IDs internally. K8s resource version semantics require a counter that a client can compare with `>` to determine ordering, but gaps are not themselves a problem. However, relying on an internal LMDB detail creates fragility. Use a custom counter.

**Option B: Custom counter in the `meta` DBI (recommended).**
Store the current revision as a big-endian u64 under the key `"revision"` in the `meta` DBI. Each write transaction:
1. Reads `meta["revision"]`.
2. Increments by 1.
3. Writes the new value back.
4. Writes to `objects` and `events` DBIs using the new revision.
5. Commits.

All four operations are atomic within the LMDB write transaction. If the process crashes mid-transaction, LMDB rolls back automatically.

### 4.3 Watch Resumption

LMDB has no change notification mechanism. Watch resumption works like the SQLite approach but with a cursor scan instead of a SQL query:

1. Open a read transaction.
2. Open a cursor on the `events` DBI.
3. Seek to the first key greater than `from_revision` (big-endian encoded).
4. Iterate forward, yielding events.
5. Close the read transaction.
6. Switch to the in-memory broadcast channel for live events.

```rust
// Pseudo-code for LMDB event replay:
fn replay_events(env: &Env, from_revision: u64) -> Vec<InternalEvent> {
    let rtxn = env.read_txn()?;
    let db: Database<OwnedType<U64<BigEndian>>, ByteSlice> = env.open_db(Some("events"))?;
    let mut cursor = db.iter_from(&rtxn, &(from_revision + 1))?;
    let mut events = Vec::new();
    while let Some(Ok((revision, value))) = cursor.next() {
        events.push(decode_event(revision, value));
    }
    rtxn.commit()?;
    events
}
```

**Subtle point (LMDB long-read-transaction stall):** A read transaction holds a snapshot of the entire LMDB environment. While the read transaction is open, LMDB cannot reclaim pages that were freed after the transaction's snapshot. If watch replay scans thousands of events in a single read transaction, it holds the snapshot for the duration. Under heavy write load, this can cause the LMDB data file to grow significantly. Mitigate by reading in chunks of 100–500 events and committing/reopening the read transaction between chunks, similar to the SQLite compaction note.

### 4.4 List Consistency

LMDB MVCC gives snapshot semantics for free. A read transaction opened at any point sees a consistent snapshot of the database:

```rust
fn list_objects(env: &Env, prefix: &str) -> Result<(Vec<StoreObject>, u64)> {
    let rtxn = env.read_txn()?;
    let objects_db = env.open_db(Some("objects"))?;
    let meta_db = env.open_db(Some("meta"))?;

    // Read current revision in the same snapshot.
    let revision: u64 = read_revision(&rtxn, &meta_db)?;

    // Cursor scan with prefix bounds.
    let mut cursor = objects_db.range(&rtxn, prefix..&prefix_end(prefix))?;
    let mut results = Vec::new();
    while let Some(Ok((key, value))) = cursor.next() {
        results.push(decode_object(key, value)?);
    }
    rtxn.commit()?;
    Ok((results, revision))
}
```

No `BEGIN`/`COMMIT` equivalent needed — the read transaction IS the snapshot boundary.

### 4.5 Optimistic Concurrency

LMDB has no built-in CAS (compare-and-swap) on values. The check must be done explicitly within the write transaction:

```rust
fn put_object(write_txn: &mut RwTxn, objects_db: &Database, key: &str, new_value: &[u8], expected_revision: Option<u64>) -> Result<u64> {
    let stored = objects_db.get(write_txn, key)?;
    let stored_revision = stored.map(|v| read_revision_from_value(v)).unwrap_or(0);

    match (stored, expected_revision) {
        (_, None) => {},                                                          // unconditional
        (None, Some(0)) => {},                                                    // create-only, key absent: OK
        (Some(_), Some(0)) => return Err(StoreError::AlreadyExists),             // create-only, key exists: fail
        (None, Some(_)) => return Err(StoreError::RevisionMismatch { current: 0 }),
        (Some(_), Some(exp)) if stored_revision == exp => {},                     // match: OK
        (Some(_), Some(_)) => return Err(StoreError::RevisionMismatch { current: stored_revision }),
    }

    // Increment revision, write object and event.
    let new_revision = stored_revision.max(read_global_revision(write_txn)?) + 1;
    // ... write new_revision into value, into events DBI, into meta DBI ...
    Ok(new_revision)
}
```

**Critical: the read (`objects_db.get`) and the write must be in the same write transaction.** LMDB write transactions are exclusive (one at a time), so there is no race between the check and the write. This is simpler than the SQLite case.

### 4.6 Rust Crates

**Recommendation: `heed` (version 0.20+).**

```toml
[dependencies]
heed = { version = "0.20", features = ["read-txn-no-tls"] }
```

**Why `heed` over `lmdb-rkv`:**
- `heed` is actively maintained (2024–2025 releases); `lmdb-rkv` has been dormant since 2022.
- `heed` provides typed database handles with serde integration (optional) and a cleaner cursor API.
- The `read-txn-no-tls` feature allows read transactions to be created and closed on different threads — required for use with tokio's `spawn_blocking`.
- `heed` wraps the LMDB C library (via `lmdb-sys`) but exposes a fully safe Rust API for the operations u7s needs.

**Do NOT use `heed` from async code directly.** All LMDB operations are synchronous. Wrap in `tokio::task::spawn_blocking` just like the SQLite path:

```rust
pub struct LmdbStore {
    env: Arc<Env>,   // heed::Env; Send + Sync
    broadcast_tx: broadcast::Sender<InternalEvent>,
    // ...
}
```

### 4.7 Memory Footprint

LMDB's memory model is unusual:

- **Virtual address space:** LMDB memory-maps the entire database file. The virtual address reservation is set at `env.open()` time as the `map_size`. This can be set to 1 GB with no physical cost.
- **Physical RSS:** Only pages that have been accessed are resident. An empty or small-data environment might use 3–5 MB RSS.
- **mmap overhead:** Each LMDB read transaction holds a reference to the memory-mapped region. Many simultaneous read transactions do not multiply physical memory — they all reference the same mmap pages.

```
Virtual: 1 GB declared (map_size)
Physical: 3–10 MB (resident pages, matches architecture.md §2 estimate)
```

**The virtual vs. physical confusion is the most common LMDB operational mistake.** Document it prominently in ops runbooks.

### 4.8 Map Size Declaration Strategy

```rust
let env = EnvOpenOptions::new()
    .map_size(1 * 1024 * 1024 * 1024)  // 1 GB virtual — declare large
    .max_dbs(8)
    .open(db_path)?;
```

**Why 1 GB:** Physical cost is near-zero. Declaring it large avoids `MDB_MAP_FULL` errors on fast-growing clusters. On a 32-bit OS this would fail (32-bit address space is 4 GB total); on a 64-bit Linux system, 1 GB of virtual address reservation is trivial.

**`MDB_MAP_FULL` handling:** If the actual data exceeds `map_size`, every write transaction returns `MDB_MAP_FULL`. The environment must be closed and reopened with a larger `map_size`. There is no online resize without a brief outage. Mitigate:
1. Set `map_size` to 1 GB initially. For a small-cluster control plane, this will never be hit.
2. Monitor `env.info().last_pgno` and alert when the data file exceeds 50% of `map_size`.
3. If resizing is needed: stop writes, close env, reopen with `2 * current_map_size`, resume. This is a configuration change, not data migration.

Handling `MDB_MAP_FULL` gracefully in production requires the store to detect the error and signal a need for restart. Log it loudly; do not silently discard writes.

---

## 5. Head-to-Head Comparison

| Dimension | SQLite (WAL) | LMDB (heed) |
|---|---|---|
| **Write throughput** | ~1,000–5,000 TPS small writes (WAL, synchronous=NORMAL). Sufficient for Argo CD target (~17 writes/s). | ~10,000–50,000 TPS small writes. 2–10x faster than SQLite for write-heavy workloads. Overkill for the target. |
| **Read throughput** | B-tree lookup, page-cached. Fast for hot data. Degraded on cold cache (disk I/O). | Zero-copy mmap reads. No deserialization of stored pages. Faster than SQLite for reads; pages are memory-mapped. |
| **Memory footprint (idle)** | 5–12 MB RSS (page cache + connections). Cache size is tunable. | 3–10 MB RSS (resident mmap pages only). Virtual space large; physical is minimal. |
| **Watch resumption complexity** | Medium. SQL query on `events` table; covered by primary key index. Event replay logic in Rust is straightforward. | Medium. Cursor scan of `events` DBI; big-endian key encoding required. Equivalent complexity. |
| **Tooling / debuggability** | Excellent. `sqlite3 state.db` enables ad-hoc queries, schema inspection, manual edits. DB Browser for SQLite provides a GUI. | Poor. Binary mmap format. Must write custom cursor code to inspect contents. `mdb_dump`/`mdb_load` utilities exist but are not interactive. |
| **Rust ecosystem maturity** | Excellent. `rusqlite` is battle-tested, widely used, actively maintained. `bundled` feature eliminates system dependency. | Good. `heed` is actively maintained; `lmdb-rkv` is dormant. LMDB itself (C library) is mature and stable. Fewer Rust examples in the wild. |
| **Operational risk** | WAL growth if checkpoints stall. `busy_timeout` misconfiguration causes spurious failures. Both are well-documented. | `MDB_MAP_FULL` requires process restart. Long read transactions stall page reclaim silently (hard to detect without monitoring). Less familiar failure mode. |
| **Correctness complexity** | CAS via `BEGIN IMMEDIATE` + row-level check. Well-understood SQLite locking semantics. | CAS via write-transaction isolation (simpler in theory). mmap semantics require careful bounds on read transaction lifetime. |
| **Schema evolution** | `ALTER TABLE` or data migration scripts. SQL DDL is the migration story. | No schema; binary layout changes require custom migration code. More fragile. |
| **Phase 1 implementation speed** | Faster. SQL DDL is the schema; queries are the logic. `rusqlite` API is straightforward. | Slower. Must implement typed DBI encoding/decoding, cursor-based scans, big-endian key layout by hand. |

**Summary:** For u7s at the target workload, SQLite is better on every dimension except raw write throughput, which is irrelevant at 17 writes/second. LMDB's advantages materialize at write rates 10x–100x higher than the Argo CD target.

---

## 6. Resolution Trigger

### Benchmark Specification

**Simulated workload:** Argo CD with 100 Applications, 10 syncs/minute per Application = ~1,000 object writes/minute = ~17 writes/second sustained, with occasional bursts to 5× (~85 writes/second) during concurrent sync storms.

**Test scenario:**
1. Pre-populate the store with 500 objects (~5 MB total: Deployments, Pods, ConfigMaps, Secrets).
2. Run a write driver: 17 writes/second to random keys for 5 minutes (steady state).
3. Run a concurrent read driver: 50 reads/second (GET + LIST) during the same window.
4. Run 3 concurrent watch subscribers, each watching a different resource prefix.
5. After 2 minutes, spike writes to 85/second for 30 seconds, then return to 17/second.

**Metrics to collect:**
- p50, p95, p99, p99.9 write latency (measured from `put()` call to `put()` return).
- p50, p95, p99 read latency (measured from `get()` or `list()` call to return).
- Watch event delivery latency (from write commit to broadcast receiver delivery).
- RSS of the API server process at steady state and during the spike.
- WAL file size at steady state and during the spike (SQLite only).

**Decision thresholds:**

| Metric | SQLite stays | Switch to LMDB |
|---|---|---|
| p99 write latency (steady state) | < 10 ms | > 10 ms sustained |
| p99 write latency (spike) | < 25 ms | > 25 ms sustained |
| RSS at steady state | < 20 MB (store only) | N/A (LMDB is not better) |
| Watch delivery latency | < 5 ms | > 5 ms |

**Switch condition:** SQLite p99 write latency exceeds 10 ms under steady-state load AND exceeds 25 ms during the spike. Both thresholds must be violated. A single threshold violation alone is not sufficient — the headroom is large enough that a single threshold may be a measurement artifact.

**Measurement methodology:**
- Instrument `SqliteStore::put` with `tokio::time::Instant::now()` + `elapsed()`. Collect as a `hdrhistogram::Histogram`.
- Run on the target VPS hardware (1 shared vCPU, SSD). Do not benchmark on developer machines with NVMe.
- Run the benchmark binary separately from the API server to isolate storage from network/serialization.
- Run three trials; take the worst.

**Expected result:** SQLite will meet all thresholds with headroom. The benchmark is a safeguard, not an expectation of switching.

---

## 7. Storage Trait Implementation

The `Store` trait from architecture.md §6:

```rust
pub trait Store: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<StoreObject>>;
    async fn list(&self, prefix: &str, revision_out: &mut u64) -> Result<Vec<StoreObject>>;
    async fn put(&self, key: &str, value: Bytes, expected_revision: Option<u64>) -> Result<u64>;
    async fn delete(&self, key: &str, expected_revision: Option<u64>) -> Result<u64>;
    async fn watch(&self, prefix: &str, from_revision: u64) -> Result<impl Stream<Item = WatchEvent> + Send>;
}
```

### 7.1 SqliteStore

```rust
pub struct SqliteStore {
    /// Single-connection write pool (max_size=1).
    write_pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    /// Multi-connection read pool (max_size=8).
    read_pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    /// Broadcast channel for live watch events.
    /// Capacity: 1024 events. Lagging receivers get RecvError::Lagged → 410 Gone.
    broadcast_tx: broadcast::Sender<Arc<InternalEvent>>,
    /// Compaction horizon: revision below which events have been deleted.
    /// Updated by the background compaction task.
    compaction_horizon: Arc<AtomicU64>,
}

/// An event sent over the broadcast channel and used for watch replay.
pub struct InternalEvent {
    pub prefix: String,       // e.g. "/registry/pods/default/"
    pub key: String,          // full key
    pub revision: u64,
    pub value: Option<Bytes>, // None = delete tombstone
}
```

**Trivial methods:**
- `get`: `spawn_blocking` → `SELECT key, value, revision FROM objects WHERE key = ?`.
- `list`: `spawn_blocking` → `BEGIN DEFERRED` + range scan + `SELECT meta.value` for revision + `COMMIT`.

**Subtle methods:**
- `put`: `spawn_blocking` → `BEGIN IMMEDIATE` + CAS check + upsert into `objects` + insert into `events` + update `meta` + `COMMIT`. After commit, send `Arc<InternalEvent>` to `broadcast_tx`. **The broadcast send must happen after `COMMIT`, not before.** Sending before commit means watchers see an event for a revision that is not yet visible to readers — a subtle consistency bug.
- `delete`: Same as `put` but with `NULL` value and `is_delete=1` in events.
- `watch`: Checks `from_revision` against `compaction_horizon`. If compacted: return a stream that immediately yields `WatchEvent::Bookmark { revision: current }`. Otherwise: spawn a task that (a) replays from `events` table, then (b) subscribes to `broadcast_rx` and filters by prefix. Returns the stream.

**The watch implementation is the most subtle part.** The transition from replay-mode to live-mode must be race-free. See §8 for the full mechanism.

### 7.2 LmdbStore

```rust
pub struct LmdbStore {
    env: Arc<heed::Env>,
    /// Named DBIs opened at startup.
    objects_db: heed::Database<Str, ByteSlice>,
    events_db: heed::Database<OwnedType<U64<BigEndian>>, ByteSlice>,
    meta_db: heed::Database<Str, ByteSlice>,
    broadcast_tx: broadcast::Sender<Arc<InternalEvent>>,
    compaction_horizon: Arc<AtomicU64>,
}
```

**Trivial methods:**
- `get`: `spawn_blocking` → read transaction → `objects_db.get(key)` → decode value.
- `list`: `spawn_blocking` → read transaction → cursor range scan → read revision from `meta_db` → commit.

**Subtle methods:**
- `put`: `spawn_blocking` → write transaction (exclusive, one at a time) → read current object from `objects_db` → CAS check → increment revision → write to `objects_db`, `events_db`, `meta_db` → commit → send to `broadcast_tx`. The write transaction exclusivity eliminates most of the CAS subtlety that SQLite requires.
- `delete`: Same as `put` with a tombstone value in `events_db` and deletion from `objects_db`.
- `watch`: Same as `SqliteStore::watch` but uses cursor scan of `events_db` for replay.

**`LmdbStore` differences from `SqliteStore`:**
- No connection pooling needed — `heed::Env` is `Send + Sync` and handles multiple read transactions internally.
- Write transactions are serialized by LMDB itself — no need for the single-writer pool hack.
- `MDB_MAP_FULL` must be caught and converted to a `StoreError::StoreFull` so the API server can log and halt writes gracefully.
- The `read-txn-no-tls` feature must be enabled in `heed` to allow read transactions to span `spawn_blocking` thread transitions.

---

## 8. Watch Notification Mechanism

Neither SQLite nor LMDB has native change notification. Watch fan-out is an in-memory mechanism above the store layer.

### 8.1 Architecture

```
Write path:
  caller → store.put(key, value, expected_rv)
         → [DB write: SQLite COMMIT or LMDB write txn commit]
         → broadcast_tx.send(Arc<InternalEvent>)
         → return new_revision

Watch subscriber:
  store.watch(prefix, from_rv)
    ├── [Phase 1: replay] DB cursor scan events WHERE revision > from_rv
    │     yields buffered WatchEvent items
    └── [Phase 2: live]  broadcast_rx.recv() → filter by prefix → yield WatchEvent
```

### 8.2 Broadcast Channel

```rust
use tokio::sync::broadcast;

// Created once at store initialization.
// Capacity: 1024 events.
// Rationale: at 100 writes/second burst, 1024 capacity gives ~10 seconds of buffer
// before the slowest subscriber lags. A subscriber that lags beyond 1024 events
// receives RecvError::Lagged — the store sends WatchEvent::Bookmark to signal 410 Gone.
let (broadcast_tx, _) = broadcast::channel::<Arc<InternalEvent>>(1024);
```

Each call to `store.watch(prefix, from_rv)` creates a new `broadcast_rx` subscriber:

```rust
async fn watch(&self, prefix: &str, from_rv: u64) -> Result<impl Stream<Item = WatchEvent> + Send> {
    let horizon = self.compaction_horizon.load(Ordering::Relaxed);
    if from_rv < horizon && from_rv != 0 {
        // Already compacted. Signal 410 Gone.
        let current = self.current_revision().await?;
        return Ok(stream::once(async move {
            WatchEvent::Bookmark { revision: current }
        }).boxed());
    }

    // Subscribe BEFORE replaying. This ensures no events are missed between
    // the replay completing and the live subscription starting.
    let mut rx = self.broadcast_tx.subscribe();
    let prefix_owned = prefix.to_string();

    // Replay historical events.
    let historical = self.replay_events(prefix, from_rv).await?;

    // Build a stream: historical events, then live events from broadcast.
    let live = async_stream::stream! {
        for event in historical {
            yield event;
        }
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if ev.key.starts_with(&prefix_owned) {
                        yield decode_watch_event(&ev);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Receiver fell behind by n events. Signal 410 Gone.
                    let revision = ev_or_current_revision();
                    yield WatchEvent::Bookmark { revision };
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Ok(live.boxed())
}
```

**Critical ordering invariant:** Subscribe to the broadcast channel BEFORE reading the historical events from the DB. If done in the opposite order, a write that commits between the DB read completing and the broadcast subscription starting will be missed — an invisible event. Subscribing first and then replaying from the DB means the broadcast may deliver events that the DB replay also delivers (duplicates), but duplicates are safe to filter by revision (skip events with revision <= last_replayed_revision).

```rust
// In the live stream section, after historical replay:
let mut last_replayed_rv = from_rv;
for event in historical {
    last_replayed_rv = event.revision;
    yield event;
}
// In the broadcast loop:
Ok(ev) => {
    if ev.revision <= last_replayed_rv {
        continue;  // Duplicate from the replay window; skip.
    }
    if ev.key.starts_with(&prefix_owned) {
        yield decode_watch_event(&ev);
    }
}
```

This is the correct and necessary deduplication.

### 8.3 Channel Capacity Sizing

**Too small:** Slow watchers fall behind. `RecvError::Lagged` fires. The watcher receives 410 Gone and must relist. With a burst of 100 writes/second and capacity 100, a watcher that stalls for 1 second will lag.

**Too large:** Each slot in a `tokio::sync::broadcast` channel holds an `Arc<InternalEvent>` pointer (8 bytes on 64-bit). 1024 slots × 8 bytes = 8 KB overhead per channel — negligible. The actual event data is ref-counted and shared across all subscribers.

**Recommendation:** 1024 capacity. At the target workload of 17 writes/second sustained and 85/second burst, this gives >10 seconds of buffer for a stalled subscriber before it lags. A subscriber stalled for 10 seconds on a healthy cluster indicates a client-side problem; drop it.

### 8.4 Lagging Receiver Handling

When a receiver gets `RecvError::Lagged(n)`:

1. The `store.watch()` stream yields `WatchEvent::Bookmark { revision: current }`.
2. The API server's watch handler (api-server.md §6) detects a `WatchEvent::Bookmark` as the 410 Gone signal.
3. The handler sends the 410 ERROR event to the client and closes the chunked response.
4. The tokio task driving the watch exits, releasing the broadcast receiver.

The client (kubectl, Argo CD, controller) receives the 410 and relists. This is the defined Kubernetes behavior for expired watch streams — not an error, a normal operational flow.

**Do NOT silently discard lagged events or attempt to recover.** The 410 → relist cycle is the designed recovery mechanism.

---

## 9. Phased Delivery

### Phase 1: Single Pod, No Watch (Minimum Viable)

**What is needed:**
- `Store::get` and `Store::put` (unconditional, `expected_revision=None`).
- `Store::list` with prefix scan and snapshot revision.
- `Store::delete` (unconditional).
- Schema: `objects` table only. No `events` table, no broadcast channel.
- No optimistic concurrency (omit `expected_revision` checks — accept all writes).
- No watch.

**What to skip:** Event log, compaction, broadcast channel, watch replay, optimistic concurrency enforcement.

**Acceptance:** `kubectl get pods` returns an empty list. `kubectl create pod` with `spec.nodeName` set stores the pod. `kubectl get pod foo` retrieves it.

**Implementation time estimate:** 1–2 days. This is 60 lines of Rust + the DDL.

### Phase 2: Watch (Controllers Need Watch)

**Add:**
- `events` table and `meta` table.
- Global revision counter: every write increments and stamps the object.
- Broadcast channel and `InternalEvent`.
- `Store::watch` with replay-then-live mechanism.
- Optimistic concurrency: `expected_revision` enforcement.
- `Store::delete` with tombstone event.
- Event log compaction background task (last 1000 events).

**Acceptance:** A watch subscriber receives `ADDED`/`MODIFIED`/`DELETED` events in order. Reconnecting with the last `resourceVersion` replays missed events. A stale `resourceVersion` triggers 410 Gone.

**Implementation time estimate:** 3–5 days. The replay/live transition and deduplication are the hard parts.

### Phase 3: RBAC, ServiceAccount Tokens

**Add:**
- Field selector index for `spec.nodeName` on Pods (SQLite: partial index with `json_extract`; LMDB: no built-in, filter in Rust after prefix scan).
- Pagination: `continue` token cursor in `Store::list` (add `limit` and `start_after_key` parameters).
- Watch ring buffer: the in-memory buffer described in architecture.md §4.2. Complement the DB-backed event log with an in-memory `VecDeque<Arc<InternalEvent>>` bounded at 1000 events. Serve watch resumption from the ring buffer when possible (faster than DB); fall back to DB when the ring buffer doesn't cover the requested revision.

**What does NOT need to change in the store:** RBAC objects are stored exactly like any other object. The RBAC index (api-server.md §7) is an in-memory structure built from watch events — the store just delivers those events.

**Acceptance:** The RBAC index is populated on startup from a `Store::list` of Role/ClusterRole/Binding objects. Subsequent changes arrive via `Store::watch`. The node agent field-selector watch (`spec.nodeName=<node>`) returns only pods for that node without scanning all pods.

---

## Appendix: Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("key not found: {key}")]
    NotFound { key: String },

    #[error("revision mismatch: expected {expected}, current {current}")]
    RevisionMismatch { expected: u64, current: u64 },

    #[error("key already exists: {key}")]
    AlreadyExists { key: String },

    #[error("watch history compacted: requested revision {requested} is below horizon {horizon}")]
    Compacted { requested: u64, horizon: u64 },

    /// LMDB only. Signals the process must restart with a larger map_size.
    #[error("storage map full: increase map_size and restart")]
    StoreFull,

    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("lmdb error: {0}")]
    Lmdb(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;
```

The API server maps `StoreError` variants to HTTP status codes:
- `RevisionMismatch` → 409 Conflict
- `AlreadyExists` → 409 Conflict
- `NotFound` → 404
- `Compacted` → triggers 410 Gone watch event (not a direct HTTP response)
- `StoreFull` → 500 + alert; stop accepting writes
