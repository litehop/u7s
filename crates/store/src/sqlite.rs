use super::*;

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::{broadcast, Mutex};

const RING_CAPACITY: usize = 1000;
const BROADCAST_CAPACITY: usize = 2048;

pub struct SqliteStore {
    /// Single write connection. Mutex ensures serial access across spawn_blocking calls.
    /// ALL rusqlite calls must go through spawn_blocking — rusqlite is synchronous.
    write_conn: Arc<Mutex<Connection>>,
    /// Read connection (WAL allows concurrent readers).
    /// For Phase 1 with one vCPU, a single read connection is sufficient.
    /// For :memory: databases, this is the same connection as write_conn.
    read_conn: Arc<Mutex<Connection>>,
    /// Broadcast channel for live events after writes.
    tx: broadcast::Sender<Arc<InternalEvent>>,
    /// Ring buffer of recent events for replay.
    /// std::sync::RwLock so push_event can write synchronously from async context.
    ring: Arc<RwLock<VecDeque<Arc<InternalEvent>>>>,
    /// Deletion-only log that persists tombstones independently of the main ring buffer.
    /// When the main ring compacts (evicts old events), deletion events may be lost, causing
    /// reconnecting watchers to miss DELETED events for objects deleted before the compaction.
    /// Keyed by store key: each key maps to its latest DELETED event. This means tombstones
    /// are never evicted by unrelated writes — a namespace deleted early in a long conformance
    /// run will still deliver its DELETED event even after 10 000+ subsequent writes.
    deletion_log: Arc<RwLock<HashMap<String, Arc<InternalEvent>>>>,
    /// Lowest revision still in the ring buffer (revision of oldest entry + 1).
    compaction_horizon: Arc<AtomicU64>,
    /// Revision of the most recently committed write. List reads are compared against
    /// this: if the read snapshot is older, the list is retried via the write connection
    /// to guarantee the returned resourceVersion never regresses after a write.
    last_written_revision: Arc<AtomicU64>,
}

impl SqliteStore {
    pub fn new(db_path: &str) -> Result<Self> {
        let write_conn = open_conn(db_path)?;

        // Run migrations on the write connection.
        write_conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS objects (
                key      TEXT    NOT NULL PRIMARY KEY,
                value    BLOB    NOT NULL,
                revision INTEGER NOT NULL,
                ns       TEXT,
                obj_name TEXT
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');

            CREATE INDEX IF NOT EXISTS idx_pods_nodename
            ON objects (json_extract(value, '$.spec.nodeName'))
            WHERE key LIKE '/registry/pods/%';

            CREATE INDEX IF NOT EXISTS idx_ns_name ON objects(ns, obj_name) WHERE ns IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_name ON objects(obj_name);
        ",
        )?;

        let write_conn = Arc::new(Mutex::new(write_conn));

        // For :memory: databases (tests), share the write connection for reads.
        // Separate in-memory connections are always distinct databases.
        // For file databases, open a second connection for concurrent reads under WAL.
        let read_conn = if db_path == ":memory:" {
            Arc::clone(&write_conn)
        } else {
            Arc::new(Mutex::new(open_conn(db_path)?))
        };

        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        let ring = Arc::new(RwLock::new(VecDeque::with_capacity(RING_CAPACITY + 1)));
        let deletion_log = Arc::new(RwLock::new(HashMap::new()));
        let compaction_horizon = Arc::new(AtomicU64::new(0));
        let last_written_revision = Arc::new(AtomicU64::new(0));

        Ok(Self {
            write_conn,
            read_conn,
            tx,
            ring,
            deletion_log,
            compaction_horizon,
            last_written_revision,
        })
    }

    fn push_event(&self, event: Arc<InternalEvent>) {
        // Write to ring buffer synchronously using std::sync::RwLock.
        // This avoids a spawned task race between write and watch replay.
        {
            let mut guard = self.ring.write().expect("ring poisoned");
            guard.push_back(Arc::clone(&event));
            if guard.len() > RING_CAPACITY {
                guard.pop_front();
                // Update compaction horizon to the revision of the oldest remaining entry.
                if let Some(oldest) = guard.front() {
                    self.compaction_horizon
                        .store(oldest.revision, Ordering::Relaxed);
                }
            }
        }
        // Maintain the deletion_log: persist tombstones so watchers that reconnect after ring
        // compaction can still receive DELETED events for objects deleted before compaction.
        //
        // Eviction policy (two-pronged to bound memory without dropping needed tombstones):
        //
        // 1. Evict-on-recreate: when a PUT event arrives for a key that has a tombstone in
        //    deletion_log, remove it. The tombstone is stale — the key now exists again, so
        //    any watcher reconnecting will see the live object in a fresh list response. Keeping
        //    a DELETED tombstone for a live key would cause a watcher to emit a spurious DELETED
        //    event for the current incarnation.
        //
        // 2. Cap at 2×RING_CAPACITY: after inserting a new tombstone, if the map exceeds the
        //    cap, evict the entry with the lowest revision. The cap is generous enough (2×1000)
        //    to cover any watcher within the ring window; tombstones evicted by this path are
        //    for keys deleted more than 2000 writes ago, which any active watcher has already
        //    processed via the broadcast channel.
        {
            let mut guard = self.deletion_log.write().expect("deletion_log poisoned");
            if event.value.is_none() {
                // Deletion: insert tombstone then cap the map.
                guard.insert(event.key.clone(), Arc::clone(&event));
                const DELETION_LOG_CAP: usize = 2 * RING_CAPACITY;
                if guard.len() > DELETION_LOG_CAP {
                    // Find and remove the entry with the smallest revision.
                    if let Some(oldest_key) = guard
                        .iter()
                        .min_by_key(|(_, e)| e.revision)
                        .map(|(k, _)| k.clone())
                    {
                        guard.remove(&oldest_key);
                    }
                }
            } else {
                // Creation/update: evict any stale tombstone for this key.
                guard.remove(&event.key);
            }
        }
        // Best-effort broadcast of the specific event.
        let event_revision = event.revision;
        let _ = self.tx.send(event);
        // Broadcast a global bookmark (key="") to advance all informers' sync RVs.
        // KCM's ConsistencyStore.EnsureReady() checks each informer's
        // LastStoreSyncResourceVersion against the RV of writes the controller made.
        // A StatefulSet watch only sees StatefulSet events — without a global bookmark,
        // its sync RV lags pod write RVs and EnsureReady requeues indefinitely.
        //
        // Use this event's own revision (not last_written_revision) so that concurrent
        // writes cannot inject a higher RV into this event's bookmark.  If write-B
        // commits and bumps last_written_revision to N+1 before write-A calls
        // last_written_revision.load(), write-A's bookmark would carry rv=N+1, advancing
        // watchers' last_replayed to N+1 before write-B's event(rv=N+1) is broadcast —
        // causing write-B's event to be dedup-skipped and silently dropped.
        let _ = self.tx.send(Arc::new(InternalEvent {
            key: String::new(),
            revision: event_revision,
            value: None,
            is_create: false,
            deleted_body: None,
        }));
    }

    /// Return the current compaction horizon: the lowest revision no longer in the ring.
    /// If `from_revision > 0 && from_revision < compaction_horizon()`, the revision is expired.
    pub fn compaction_horizon(&self) -> u64 {
        self.compaction_horizon.load(Ordering::Relaxed)
    }

    /// Directly set the compaction horizon. Intended for tests that simulate compaction
    /// without needing to overflow the ring buffer (which requires 1000+ writes).
    pub fn set_compaction_horizon_for_test(&self, horizon: u64) {
        self.compaction_horizon.store(horizon, Ordering::Relaxed);
    }
}

fn open_conn(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous  = NORMAL;
        PRAGMA cache_size   = -8000;
        PRAGMA busy_timeout = 5000;
        -- Keep the WAL file small so read connections do not fall far behind write connections.
        -- At 1000 (the SQLite default), the WAL can hold 1000 pages before checkpointing.
        -- Under high write bursts (conformance runs), the read connection lags and the
        -- stale-read guard in get()/list() must retry via the write connection repeatedly,
        -- causing KCM's RS controller to log 'read version N is not as new as written version M'
        -- and requeue in a tight loop for up to 15 minutes.  At 100, checkpoints are more
        -- frequent so the read connection stays within ~100 pages of the write head.
        PRAGMA wal_autocheckpoint = 100;
    ",
    )?;
    Ok(conn)
}

/// Stamps metadata.resourceVersion into the stored JSON.
/// Parses the JSON, sets the field, re-serializes.
/// Also extracts ns and obj_name from the single parse to avoid a second deserialization.
fn stamp_resource_version(
    value: &Bytes,
    revision: u64,
) -> Result<(Bytes, Option<String>, Option<String>)> {
    let mut obj: serde_json::Value = serde_json::from_slice(value)?;
    let ns = obj["metadata"]["namespace"].as_str().map(str::to_owned);
    let obj_name = obj["metadata"]["name"].as_str().map(str::to_owned);
    obj["metadata"]["resourceVersion"] = serde_json::Value::String(revision.to_string());
    Ok((Bytes::from(serde_json::to_vec(&obj)?), ns, obj_name))
}

// Full write procedure — runs inside spawn_blocking.
// Returns (new_revision, stamped_value, is_create).
fn put_sync(
    conn: &Connection,
    key: &str,
    value: Bytes,
    expected_revision: Option<u64>,
    last_written: &AtomicU64,
) -> Result<(u64, Bytes, bool)> {
    // 1. Begin exclusive write transaction.
    conn.execute_batch("BEGIN IMMEDIATE")?;

    // 2. Read current stored revision for optimistic concurrency check.
    // SQLite stores integers as i64; cast to u64 (revisions fit in i63 range).
    let stored: Option<u64> = conn
        .query_row(
            "SELECT revision FROM objects WHERE key = ?1",
            params![key],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        )
        .optional()?;

    let is_create = stored.is_none();

    // 3. Optimistic concurrency check.
    match (stored, expected_revision) {
        (_, None) => {}       // unconditional
        (None, Some(0)) => {} // create-only, absent: OK
        (Some(_), Some(0)) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::AlreadyExists {
                key: key.to_string(),
            });
        }
        (None, Some(exp)) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::RevisionMismatch {
                expected: exp,
                current: 0,
            });
        }
        (Some(stored_rv), Some(exp)) if stored_rv == exp => {} // match: OK
        (Some(stored_rv), Some(exp)) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::RevisionMismatch {
                expected: exp,
                current: stored_rv,
            });
        }
    }

    // 4. Increment global revision counter.
    conn.execute(
        "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'revision'",
        [],
    )?;

    // 5. Read the new revision.
    let new_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )?;

    // 6. Stamp metadata.resourceVersion in the JSON value and extract indexed columns
    //    from the single parse, avoiding a second deserialization of the stamped bytes.
    let (stamped_value, ns, obj_name) = stamp_resource_version(&value, new_revision)?;

    // 7. Upsert the object.
    conn.execute(
        "INSERT INTO objects (key, value, revision, ns, obj_name) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, revision = excluded.revision,
         ns = excluded.ns, obj_name = excluded.obj_name",
        params![
            key,
            stamped_value.as_ref(),
            new_revision as i64,
            ns,
            obj_name
        ],
    )?;

    conn.execute_batch("COMMIT")?;
    // Update last_written_revision immediately after COMMIT on this blocking thread.
    // Doing this here (rather than in the async caller) eliminates the scheduling window
    // where a concurrent list on the read connection could see the new WAL data but
    // load a stale last_written_revision from the async task queue — causing the list
    // guard to miss the stale-read and return an older resourceVersion to the reflector.
    last_written.fetch_max(new_revision, Ordering::Release);
    Ok((new_revision, stamped_value, is_create))
}

fn delete_sync(
    conn: &Connection,
    key: &str,
    expected_revision: Option<u64>,
    last_written: &AtomicU64,
) -> Result<(u64, Bytes)> {
    conn.execute_batch("BEGIN IMMEDIATE")?;

    let stored: Option<(u64, Vec<u8>)> = conn
        .query_row(
            "SELECT revision, value FROM objects WHERE key = ?1",
            params![key],
            |r| {
                Ok((
                    r.get::<_, i64>(0).map(|v| v as u64)?,
                    r.get::<_, Vec<u8>>(1)?,
                ))
            },
        )
        .optional()?;

    // Optimistic concurrency check (same logic as put).
    match stored.as_ref().map(|(rv, _)| *rv) {
        None => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::NotFound {
                key: key.to_string(),
            });
        }
        Some(_) if expected_revision.is_none() => {}
        Some(_) if expected_revision == Some(0) => {}
        Some(stored_rv) => {
            if let Some(exp) = expected_revision {
                if stored_rv != exp {
                    conn.execute_batch("ROLLBACK")?;
                    return Err(StoreError::RevisionMismatch {
                        expected: exp,
                        current: stored_rv,
                    });
                }
            }
        }
    }

    let last_value = Bytes::from(stored.unwrap().1);

    conn.execute(
        "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'revision'",
        [],
    )?;
    let new_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )?;

    conn.execute("DELETE FROM objects WHERE key = ?1", params![key])?;
    conn.execute_batch("COMMIT")?;
    // Same rationale as put_sync: update last_written_revision on the blocking thread
    // immediately after COMMIT so the list guard sees it before any reader can observe
    // the new WAL state from a concurrent read connection.
    last_written.fetch_max(new_revision, Ordering::Release);
    Ok((new_revision, last_value))
}

/// Delete all objects in a namespace atomically.
///
/// Returns the keys that were deleted (may be empty) and the new revision
/// (only meaningful when at least one object was deleted).
fn delete_namespace_sync(
    conn: &Connection,
    namespace: &str,
    last_written: &AtomicU64,
) -> Result<(u64, Vec<String>)> {
    conn.execute_batch("BEGIN IMMEDIATE")?;

    // Collect all keys in the namespace.
    let mut stmt = conn.prepare("SELECT key FROM objects WHERE ns = ?1")?;
    let keys: Vec<String> = stmt
        .query_map(params![namespace], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();

    if keys.is_empty() {
        conn.execute_batch("ROLLBACK")?;
        // Return current revision without incrementing (nothing was deleted).
        let rev: u64 = conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
                [],
                |r| r.get::<_, i64>(0).map(|v| v as u64),
            )
            .unwrap_or(0);
        return Ok((rev, vec![]));
    }

    // Increment global revision once for the batch.
    conn.execute(
        "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'revision'",
        [],
    )?;
    let new_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )?;

    // Delete all objects in the namespace.
    conn.execute("DELETE FROM objects WHERE ns = ?1", params![namespace])?;
    conn.execute_batch("COMMIT")?;
    // Same rationale as put_sync: update immediately after COMMIT on the blocking thread.
    last_written.fetch_max(new_revision, Ordering::Release);
    Ok((new_revision, keys))
}

fn get_sync(conn: &Connection, key: &str) -> Result<Option<StoreObject>> {
    let result = conn
        .query_row(
            "SELECT key, value, revision FROM objects WHERE key = ?1",
            params![key],
            |r| {
                Ok(StoreObject {
                    key: r.get::<_, String>(0)?,
                    value: Bytes::from(r.get::<_, Vec<u8>>(1)?),
                    revision: r.get::<_, i64>(2).map(|v| v as u64)?,
                })
            },
        )
        .optional()?;
    Ok(result)
}

/// Compute the exclusive upper bound for a prefix range scan.
/// Increments the last byte of the prefix that is not 0xFF.
/// Returns empty string if no upper bound is possible (all 0xFF — pathological).
fn prefix_upper_bound(prefix: &str) -> String {
    let mut bytes = prefix.as_bytes().to_vec();
    for b in bytes.iter_mut().rev() {
        if *b < 0xFF {
            *b += 1;
            return String::from_utf8(bytes).unwrap();
        }
        *b = 0x00;
    }
    String::new() // no upper bound needed
}

fn query_all(conn: &Connection, sql: &str, p: &[&dyn rusqlite::ToSql]) -> Result<Vec<StoreObject>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt
        .query_map(p, |r| {
            Ok(StoreObject {
                key: r.get(0)?,
                value: Bytes::from(r.get::<_, Vec<u8>>(1)?),
                revision: r.get::<_, i64>(2).map(|v| v as u64)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn list_sync(conn: &Connection, prefix: &str, opts: &ListOptions) -> Result<ListResponse> {
    conn.execute_batch("BEGIN DEFERRED")?;

    let upper = prefix_upper_bound(prefix);
    let ck = opts.continue_key.as_deref().unwrap_or("");

    // When limit is set with no field selector, use SQL-level pagination (fetch limit+1).
    // When a field selector is present, collect all matching rows then paginate in memory,
    // because in-memory filtering may discard rows between the cursor and the limit boundary.
    let (items, continue_key) = match &opts.field_selector {
        // SQL index fast-path: metadata.name=<value> — uses idx_name index.
        Some(FieldSelector {
            field,
            value,
            negated: false,
        }) if field == "metadata.name" => {
            let raw = if upper.is_empty() {
                if ck.is_empty() {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects \
                         WHERE key >= ?1 AND obj_name = ?2 ORDER BY key ASC",
                        &[&prefix, value as &dyn rusqlite::ToSql],
                    )?
                } else {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects \
                         WHERE key >= ?1 AND obj_name = ?2 AND key > ?3 ORDER BY key ASC",
                        &[&prefix, value as &dyn rusqlite::ToSql, &ck],
                    )?
                }
            } else if ck.is_empty() {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key >= ?1 AND key < ?2 AND obj_name = ?3 ORDER BY key ASC",
                    &[&prefix, &upper, value as &dyn rusqlite::ToSql],
                )?
            } else {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key >= ?1 AND key < ?2 AND obj_name = ?3 AND key > ?4 ORDER BY key ASC",
                    &[&prefix, &upper, value as &dyn rusqlite::ToSql, &ck],
                )?
            };
            paginate_in_memory(raw, opts.limit)
        }

        // SQL index fast-path: metadata.namespace=<value> — uses idx_ns index.
        Some(FieldSelector {
            field,
            value,
            negated: false,
        }) if field == "metadata.namespace" => {
            let raw = if upper.is_empty() {
                if ck.is_empty() {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects \
                         WHERE key >= ?1 AND ns = ?2 ORDER BY key ASC",
                        &[&prefix, value as &dyn rusqlite::ToSql],
                    )?
                } else {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects \
                         WHERE key >= ?1 AND ns = ?2 AND key > ?3 ORDER BY key ASC",
                        &[&prefix, value as &dyn rusqlite::ToSql, &ck],
                    )?
                }
            } else if ck.is_empty() {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key >= ?1 AND key < ?2 AND ns = ?3 ORDER BY key ASC",
                    &[&prefix, &upper, value as &dyn rusqlite::ToSql],
                )?
            } else {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key >= ?1 AND key < ?2 AND ns = ?3 AND key > ?4 ORDER BY key ASC",
                    &[&prefix, &upper, value as &dyn rusqlite::ToSql, &ck],
                )?
            };
            paginate_in_memory(raw, opts.limit)
        }

        // Indexed fast-path: spec.nodeName on pods — uses the partial index.
        Some(FieldSelector {
            field,
            value,
            negated: false,
        }) if field == "spec.nodeName" && prefix.starts_with("/registry/pods/") => {
            let like_prefix = format!("{}%", prefix);
            let raw = if ck.is_empty() {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key LIKE ?1 AND json_extract(value, '$.spec.nodeName') = ?2 \
                     ORDER BY key ASC",
                    &[&like_prefix, value as &dyn rusqlite::ToSql],
                )?
            } else {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key LIKE ?1 AND json_extract(value, '$.spec.nodeName') = ?2 \
                     AND key > ?3 ORDER BY key ASC",
                    &[&like_prefix, value as &dyn rusqlite::ToSql, &ck],
                )?
            };
            paginate_in_memory(raw, opts.limit)
        }

        // Generic field selector: full scan + in-memory filter + in-memory pagination.
        Some(FieldSelector {
            field,
            value,
            negated,
        }) => {
            let raw = if upper.is_empty() {
                if ck.is_empty() {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 ORDER BY key ASC",
                        &[&prefix],
                    )?
                } else {
                    query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key > ?2 ORDER BY key ASC",
                        &[&prefix, &ck],
                    )?
                }
            } else if ck.is_empty() {
                query_all(conn,
                    "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 ORDER BY key ASC",
                    &[&prefix, &upper],
                )?
            } else {
                query_all(conn,
                    "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 AND key > ?3 ORDER BY key ASC",
                    &[&prefix, &upper, &ck],
                )?
            };

            // Walk the dot-separated path in the parsed JSON and compare to expected value.
            let path_parts: Vec<&str> = field.split('.').collect();
            let filtered: Vec<StoreObject> = raw
                .into_iter()
                .filter(|obj| {
                    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.value) else {
                        return false;
                    };
                    let mut cur = &parsed;
                    let mut absent = false;
                    for part in &path_parts {
                        match cur.get(part) {
                            Some(next) => cur = next,
                            None => {
                                absent = true;
                                break;
                            }
                        }
                    }
                    // Absent fields are treated as the zero value: "" for strings,
                    // false for bools. Both compare equal to "false" or "".
                    let matches = if absent {
                        value.is_empty() || value == "false"
                    } else {
                        match cur {
                            serde_json::Value::String(s) => s == value,
                            serde_json::Value::Bool(b) => {
                                value == if *b { "true" } else { "false" }
                            }
                            serde_json::Value::Null => value.is_empty(),
                            serde_json::Value::Number(n) => value.as_str() == n.to_string(),
                            _ => false,
                        }
                    };
                    if *negated {
                        !matches
                    } else {
                        matches
                    }
                })
                .collect();
            paginate_in_memory(filtered, opts.limit)
        }

        // No field selector: SQL-level pagination when limit is set (fetch limit+1 rows).
        None => {
            let fetch_limit = opts.limit.map(|l| (l + 1) as i64);
            let raw = if upper.is_empty() {
                match (ck.is_empty(), fetch_limit) {
                    (true, None)       => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 ORDER BY key ASC",
                        &[&prefix])?,
                    (true, Some(lim))  => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 ORDER BY key ASC LIMIT ?2",
                        &[&prefix, &lim])?,
                    (false, None)      => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key > ?2 ORDER BY key ASC",
                        &[&prefix, &ck])?,
                    (false, Some(lim)) => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key > ?2 ORDER BY key ASC LIMIT ?3",
                        &[&prefix, &ck, &lim])?,
                }
            } else {
                match (ck.is_empty(), fetch_limit) {
                    (true, None)       => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 ORDER BY key ASC",
                        &[&prefix, &upper])?,
                    (true, Some(lim))  => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 ORDER BY key ASC LIMIT ?3",
                        &[&prefix, &upper, &lim])?,
                    (false, None)      => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 AND key > ?3 ORDER BY key ASC",
                        &[&prefix, &upper, &ck])?,
                    (false, Some(lim)) => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 AND key > ?3 ORDER BY key ASC LIMIT ?4",
                        &[&prefix, &upper, &ck, &lim])?,
                }
            };
            // If we fetched limit+1 rows, there are more items. Discard the extra row
            // and use the last returned item's key as the cursor for the next page.
            if let Some(limit) = opts.limit.map(|l| l as usize) {
                if raw.len() > limit {
                    let mut items = raw;
                    items.pop(); // discard the probe row; it belongs to the next page
                    let ck = items.last().map(|o| o.key.clone());
                    (items, ck)
                } else {
                    (raw, None)
                }
            } else {
                (raw, None)
            }
        }
    };

    let snapshot_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )?;

    // When there are more pages, count the remaining items so callers can populate
    // metadata.remainingItemCount in list responses (required by chunking conformance).
    let remaining_count = match &continue_key {
        None => None,
        Some(cursor) => {
            let upper = prefix_upper_bound(prefix);
            let count: u64 = if upper.is_empty() {
                conn.query_row(
                    "SELECT COUNT(*) FROM objects WHERE key >= ?1 AND key > ?2",
                    params![prefix, cursor],
                    |r| r.get::<_, i64>(0).map(|v| v as u64),
                )?
            } else {
                conn.query_row(
                    "SELECT COUNT(*) FROM objects WHERE key >= ?1 AND key < ?2 AND key > ?3",
                    params![prefix, &upper, cursor],
                    |r| r.get::<_, i64>(0).map(|v| v as u64),
                )?
            };
            Some(count)
        }
    };

    conn.execute_batch("COMMIT")?;

    Ok(ListResponse {
        items,
        revision: snapshot_revision,
        continue_key,
        remaining_count,
    })
}

/// Apply in-memory pagination: if limit is set, return at most limit items and
/// set continue_key to the last item's key if more remain.
fn paginate_in_memory(
    mut items: Vec<StoreObject>,
    limit: Option<u64>,
) -> (Vec<StoreObject>, Option<String>) {
    if let Some(limit) = limit {
        let limit = limit as usize;
        if items.len() > limit {
            items.truncate(limit);
            let ck = items.last().map(|o| o.key.clone());
            (items, ck)
        } else {
            (items, None)
        }
    } else {
        (items, None)
    }
}

impl Store for SqliteStore {
    async fn get(&self, key: &str) -> Result<Option<StoreObject>> {
        let conn = self.read_conn.clone();
        let key_str = key.to_string();
        let obj = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            get_sync(&conn, &key_str)
        })
        .await??;

        // Guard: if the returned object's revision is older than the most recently committed
        // write, the WAL read connection returned a stale view. Retry via the write connection
        // to ensure read-after-write consistency — a GET immediately after a PUT must never
        // return an older resourceVersion than what the PUT returned.
        let min_rev = self.last_written_revision.load(Ordering::Acquire);
        if obj.as_ref().is_some_and(|o| o.revision < min_rev) || (obj.is_none() && min_rev > 0) {
            let write_conn = self.write_conn.clone();
            let key_str2 = key.to_string();
            return tokio::task::spawn_blocking(move || {
                let conn = write_conn.blocking_lock();
                get_sync(&conn, &key_str2)
            })
            .await?;
        }

        Ok(obj)
    }

    async fn list(&self, prefix: &str, opts: ListOptions) -> Result<ListResponse> {
        let read_conn = self.read_conn.clone();
        let prefix = prefix.to_string();
        let prefix2 = prefix.clone();
        let opts2 = opts.clone();
        let resp = tokio::task::spawn_blocking(move || {
            let conn = read_conn.blocking_lock();
            list_sync(&conn, &prefix, &opts2)
        })
        .await??;

        // Guard: if the read snapshot is older than the most recently committed write,
        // the WAL read connection returned a stale view. Retry via the write connection,
        // which always reflects the latest committed state. This prevents the KCM informer
        // from seeing a list resourceVersion that regresses below a revision it already
        // observed from a watch event.
        let min_rev = self.last_written_revision.load(Ordering::Acquire);
        if resp.revision < min_rev {
            let write_conn = self.write_conn.clone();
            return tokio::task::spawn_blocking(move || {
                let conn = write_conn.blocking_lock();
                list_sync(&conn, &prefix2, &opts)
            })
            .await?;
        }

        Ok(resp)
    }

    async fn put(&self, key: &str, value: Bytes, expected_revision: Option<u64>) -> Result<u64> {
        let conn = self.write_conn.clone();
        let key_str = key.to_string();
        let last_written = Arc::clone(&self.last_written_revision);
        let (revision, stamped_value, is_create) = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            put_sync(&conn, &key_str, value, expected_revision, &last_written)
        })
        .await??;

        self.push_event(Arc::new(InternalEvent {
            key: key.to_string(),
            revision,
            value: Some(stamped_value),
            is_create,
            deleted_body: None,
        }));

        Ok(revision)
    }

    async fn delete(&self, key: &str, expected_revision: Option<u64>) -> Result<(u64, Bytes)> {
        let conn = self.write_conn.clone();
        let key_str = key.to_string();
        let last_written = Arc::clone(&self.last_written_revision);
        let (revision, last_value) = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            delete_sync(&conn, &key_str, expected_revision, &last_written)
        })
        .await??;

        self.push_event(Arc::new(InternalEvent {
            key: key.to_string(),
            revision,
            value: None,
            is_create: false,
            deleted_body: Some(last_value.clone()),
        }));

        Ok((revision, last_value))
    }

    async fn delete_namespace_resources(&self, namespace: &str) -> Result<Vec<String>> {
        let conn = self.write_conn.clone();
        let ns = namespace.to_string();
        let last_written = Arc::clone(&self.last_written_revision);
        let (revision, keys) = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            delete_namespace_sync(&conn, &ns, &last_written)
        })
        .await??;

        if !keys.is_empty() {
            for key in &keys {
                self.push_event(Arc::new(InternalEvent {
                    key: key.clone(),
                    revision,
                    value: None,
                    is_create: false,
                    deleted_body: None,
                }));
            }
        }

        Ok(keys)
    }

    async fn watch(
        &self,
        prefix: &str,
        from_revision: u64,
    ) -> Result<impl futures_core::Stream<Item = WatchEvent> + Send + 'static> {
        // Subscribe FIRST to avoid missing events between replay and live.
        let mut rx = self.tx.subscribe();

        let horizon = self.compaction_horizon.load(Ordering::Relaxed);

        // Collect ring buffer snapshot while holding read lock (std::sync::RwLock — synchronous).
        let replayed: Vec<Arc<InternalEvent>> = {
            let guard = self.ring.read().expect("ring poisoned");
            guard
                .iter()
                .filter(|e| e.key.starts_with(prefix) && e.revision > from_revision)
                .cloned()
                .collect()
        };

        let prefix_owned = prefix.to_string();
        let compaction_horizon_arc = Arc::clone(&self.compaction_horizon);
        // Captured for lag recovery: allows re-subscribing and re-scanning ring buffer
        // without terminating the stream when the broadcast channel lags transiently.
        let tx_clone = self.tx.clone();
        let ring_arc = Arc::clone(&self.ring);
        // Captured to replay deletion tombstones that survived compaction of the main ring.
        let deletion_log_arc = Arc::clone(&self.deletion_log);

        let stream = async_stream::stream! {
            // Yield compacted event if from_revision is before the horizon.
            // Before yielding Compacted, emit any deletion tombstones from the deletion_log
            // that the client missed (revision > from_revision). These are deletions that were
            // compacted out of the main ring buffer — without replaying them here, the client
            // would reconnect after a relist and never see the DELETED events, deadlocking any
            // watcher that waits for a DELETED event for an object deleted in the compaction window.
            if from_revision > 0 && from_revision < horizon {
                let tombstones: Vec<Arc<InternalEvent>> = {
                    let guard = deletion_log_arc.read().expect("deletion_log poisoned");
                    guard
                        .values()
                        .filter(|e| e.key.starts_with(&prefix_owned) && e.revision > from_revision)
                        .cloned()
                        .collect()
                };
                for tombstone in &tombstones {
                    yield internal_to_watch(tombstone);
                }
                yield WatchEvent::Compacted { requested: from_revision, horizon };
                return;
            }

            // Replay historical events from ring buffer.
            let mut last_replayed = from_revision;
            for event in &replayed {
                last_replayed = last_replayed.max(event.revision);
                yield internal_to_watch(event);
            }

            // Tracks the highest revision seen from global bookmarks. Used only for emitting
            // BOOKMARK events to clients; deliberately separate from last_replayed so that a
            // global bookmark from a *different* resource's write cannot advance last_replayed
            // and cause a later out-of-order event on this prefix to be dedup-skipped.
            let mut bookmark_rv: u64 = from_revision;

            // Forward live broadcast events, skipping already-replayed revisions.
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        // A global bookmark (key == "") is delivered to all watches
                        // regardless of prefix — it advances the informer's sync RV
                        // without carrying an object (KCM ConsistencyStore relies on this).
                        //
                        // Do NOT update last_replayed here: a global bookmark may arrive from
                        // a concurrent write on a completely different prefix, with a revision
                        // higher than a pending event on this watcher's prefix. Advancing
                        // last_replayed from a cross-prefix bookmark would cause that pending
                        // event to be dedup-skipped and silently dropped.
                        if event.key.is_empty() {
                            if event.revision > bookmark_rv {
                                bookmark_rv = event.revision;
                                // Emit BOOKMARK at the highest observed RV across both specific
                                // events and bookmarks, so clients still see advancing bookmarks.
                                yield WatchEvent::Bookmark { revision: bookmark_rv.max(last_replayed) };
                            }
                            continue;
                        }
                        if !event.key.starts_with(&prefix_owned) {
                            continue;
                        }
                        // Deduplicate: skip if already covered by replay or a previous live event.
                        if event.revision <= last_replayed {
                            tracing::debug!(
                                prefix = %prefix_owned,
                                key = %event.key,
                                rv = event.revision,
                                last_replayed,
                                "watch: dedup skip"
                            );
                            continue;
                        }
                        tracing::debug!(
                            prefix = %prefix_owned,
                            key = %event.key,
                            rv = event.revision,
                            "watch: yielding live event"
                        );
                        last_replayed = event.revision;
                        yield internal_to_watch(&event);
                        // Immediately follow every event with a BOOKMARK at the same RV.
                        // client-go only advances LastStoreSyncResourceVersion on BOOKMARK events.
                        // KCM ConsistencyStore checks the pod informer's LastStoreSyncResourceVersion
                        // immediately after writing a pod — without a trailing BOOKMARK the check
                        // always sees a stale RV and requeues indefinitely.
                        yield WatchEvent::Bookmark { revision: last_replayed };
                    }
                    Err(broadcast::error::RecvError::Lagged(_n)) => {
                        // The broadcast channel dropped messages because this receiver was too slow.
                        // Attempt recovery: re-subscribe (to capture all future events) then
                        // re-scan the ring buffer for events missed during the lag.  This avoids
                        // terminating the stream with a 410 error for a transient slow-consumer
                        // scenario — which forces the client to relist and re-watch, wasting
                        // another full round-trip and potentially lagging again.
                        //
                        // If the ring buffer has also been compacted past last_replayed, we
                        // fall back to yielding Compacted so the client can relist from a valid
                        // revision rather than silently skipping events.
                        rx = tx_clone.subscribe();
                        let catchup: Vec<Arc<InternalEvent>> = {
                            let guard = ring_arc.read().expect("ring poisoned");
                            guard
                                .iter()
                                .filter(|e| {
                                    e.key.starts_with(&prefix_owned) && e.revision > last_replayed
                                })
                                .cloned()
                                .collect()
                        };
                        for event in &catchup {
                            last_replayed = last_replayed.max(event.revision);
                            yield internal_to_watch(event);
                        }
                        // If the ring buffer was also compacted past last_replayed (events lost
                        // from both broadcast and ring buffer), signal the gap to the consumer.
                        // Before signalling Compacted, replay any deletion tombstones from the
                        // deletion_log that are not already covered by the ring buffer catchup.
                        // Without this, a namespace deleted during the lag+compaction window
                        // would never deliver its DELETED event: the client would reconnect after
                        // a relist, open a new Watch at the current revision, and wait forever.
                        let current_horizon = compaction_horizon_arc.load(Ordering::Relaxed);
                        if current_horizon > last_replayed {
                            // Use from_revision (the watcher's original start) rather than
                            // last_replayed as the lower bound for deletion_log replay.
                            //
                            // Why: after ring catchup, last_replayed is advanced by non-prefix
                            // events (e.g. pod writes advancing the ring), so last_replayed may
                            // now be GREATER than the tombstone's revision even though the
                            // tombstone was never delivered. A deletion at revision D and
                            // last_replayed at D+500 would be silently skipped with
                            // `> last_replayed`, causing sonobuoy delete --wait to deadlock.
                            //
                            // Using from_revision ensures every deletion since the watcher
                            // started is delivered before Compacted. The client relists after
                            // Compacted anyway, so a pre-Compacted duplicate DELETED is harmless.
                            let tombstones: Vec<Arc<InternalEvent>> = {
                                let guard = deletion_log_arc.read().expect("deletion_log poisoned");
                                guard
                                    .values()
                                    .filter(|e| {
                                        e.key.starts_with(&prefix_owned)
                                            && e.revision > from_revision
                                    })
                                    .cloned()
                                    .collect()
                            };
                            for tombstone in &tombstones {
                                last_replayed = last_replayed.max(tombstone.revision);
                                yield internal_to_watch(tombstone);
                            }
                            yield WatchEvent::Compacted {
                                requested: last_replayed,
                                horizon: current_horizon,
                            };
                            return;
                        }
                        // Ring buffer covered the gap; continue watching from last_replayed.
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Sender dropped; stop stream.
                        return;
                    }
                }
            }
        };

        Ok(stream)
    }

    fn compaction_horizon(&self) -> u64 {
        self.compaction_horizon.load(Ordering::Relaxed)
    }

    fn current_revision(&self) -> u64 {
        self.last_written_revision.load(Ordering::Acquire)
    }
}

pub(crate) fn internal_to_watch(event: &InternalEvent) -> WatchEvent {
    match &event.value {
        Some(value) => {
            let obj = StoreObject {
                key: event.key.clone(),
                value: value.clone(),
                revision: event.revision,
            };
            if event.is_create {
                WatchEvent::Added(obj)
            } else {
                WatchEvent::Modified(obj)
            }
        }
        None => WatchEvent::Deleted {
            key: event.key.clone(),
            revision: event.revision,
            body: event.deleted_body.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::time::Duration;

    fn svc_value(name: &str, rv: u64) -> Bytes {
        Bytes::from(format!(
            r#"{{"apiVersion":"v1","kind":"Service","metadata":{{"name":"{name}","namespace":"default","resourceVersion":"{rv}"}}}}"#,
            name = name,
            rv = rv
        ))
    }

    /// Verify that a global bookmark carrying a higher revision (from a concurrent write that
    /// already committed and bumped `last_written_revision`) does NOT cause a subsequent
    /// specific event at that same revision to be dedup-skipped.
    ///
    /// Why it matters: before the fix, push_event read last_written_revision AFTER the commit,
    /// so if write-B (rv=2) committed between write-A's commit and write-A's push_event call,
    /// write-A's bookmark would carry rv=2.  A watcher receiving event(svc-a,rv=1) then
    /// bookmark(rv=2) then event(svc-b,rv=2) would skip svc-b (rv=2 <= last_replayed=2).
    /// The controller watching services would never see svc-b — it disappears silently.
    ///
    /// The fix: use the event's own revision for the global bookmark so concurrent writes
    /// cannot contaminate each other's bookmarks.
    #[tokio::test]
    async fn watch_bookmark_race_loses_event_without_fix() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // Subscribe the watcher before any writes so it enters the live-event loop.
        let stream = store
            .watch("/registry/services/", 0)
            .await
            .expect("watch failed");
        futures_util::pin_mut!(stream);

        // Simulate the race: write-B (rv=2) has already committed and bumped
        // last_written_revision to 2 before write-A calls push_event for rv=1.
        // With the bug, push_event reads last_written_revision=2 and broadcasts
        // bookmark(rv=2) — a revision higher than write-A's own event.
        store.last_written_revision.store(2, Ordering::Release);

        // push_event for svc-a (rv=1).
        // BUG:   broadcasts event(svc-a,rv=1) + bookmark(rv=2)  [reads last_written_revision=2]
        // FIX:   broadcasts event(svc-a,rv=1) + bookmark(rv=1)  [uses event.revision]
        store.push_event(Arc::new(InternalEvent {
            key: "/registry/services/default/svc-a".into(),
            revision: 1,
            value: Some(svc_value("svc-a", 1)),
            is_create: true,
            deleted_body: None,
        }));

        // push_event for svc-b (rv=2) — the concurrent write.
        // Broadcasts event(svc-b,rv=2) + bookmark(rv=2).
        store.push_event(Arc::new(InternalEvent {
            key: "/registry/services/default/svc-b".into(),
            revision: 2,
            value: Some(svc_value("svc-b", 2)),
            is_create: true,
            deleted_body: None,
        }));

        // Collect Added events for a short window.
        // With BUG:  watcher sees event(svc-a,rv=1)→Added, bookmark(rv=2)→last_replayed=2,
        //            event(svc-b,rv=2)→rv<=last_replayed→SKIP.  svc-b is never delivered.
        // With FIX:  watcher sees event(svc-a,rv=1)→Added, bookmark(rv=1), then
        //            event(svc-b,rv=2)→rv>last_replayed=1→Added.  Both delivered.
        let mut added_keys: Vec<String> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Added(obj))) => {
                    added_keys.push(obj.key.clone());
                }
                Ok(Some(WatchEvent::Bookmark { .. })) => {}
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break, // timeout
            }
        }

        assert!(
            added_keys.contains(&"/registry/services/default/svc-a".to_string()),
            "svc-a must be delivered as Added; without this a watcher misses the service entirely"
        );
        assert!(
            added_keys.contains(&"/registry/services/default/svc-b".to_string()),
            "svc-b must be delivered as Added; push_event must use event.revision for the global \
             bookmark, not last_written_revision — otherwise a concurrent write that commits first \
             causes the bookmark to carry a future rv, advancing last_replayed and dedup-skipping \
             svc-b's event so controllers never see it"
        );
    }

    /// Verify that a global bookmark from a *different* resource's write does not advance
    /// `last_replayed` on a watcher for a different prefix, causing a subsequent lower-rv
    /// event on that prefix to be dedup-skipped.
    ///
    /// Why it matters: an Endpoints write at rv=365 fires a global bookmark(rv=365). A Services
    /// watcher receives that bookmark BEFORE the service event at rv=364 (delayed by scheduling).
    /// If the bookmark advances `last_replayed=365`, the service event(rv=364) is dedup-skipped
    /// and controllers (KCM) never see the service — no EndpointSlice is ever created.
    ///
    /// The fix: global bookmarks must NOT advance `last_replayed` used for dedup. Track bookmark
    /// progress separately (`bookmark_rv`); use `max(last_replayed, bookmark_rv)` only for
    /// emitting BOOKMARK events to clients.
    #[tokio::test]
    async fn watch_cross_resource_bookmark_skips_event() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // Subscribe to /registry/services/ from rv=0.
        let stream = store
            .watch("/registry/services/", 0)
            .await
            .expect("watch failed");
        futures_util::pin_mut!(stream);

        let tx = store.tx.clone();

        // 1. Global bookmark at rv=365 (from a concurrent Endpoints write on a different prefix).
        //    This arrives BEFORE the service event at rv=364 due to scheduling jitter.
        tx.send(Arc::new(InternalEvent {
            key: String::new(),
            revision: 365,
            value: None,
            is_create: false,
            deleted_body: None,
        }))
        .expect("send bookmark");

        // 2. Service event at rv=364 (arrived late due to scheduling).
        tx.send(Arc::new(InternalEvent {
            key: "/registry/services/default/svc-a".into(),
            revision: 364,
            value: Some(Bytes::from(
                r#"{"apiVersion":"v1","kind":"Service","metadata":{"name":"svc-a","namespace":"default","resourceVersion":"364"}}"#,
            )),
            is_create: true,
            deleted_body: None,
        }))
        .expect("send svc-a event");

        // Collect Added events for a short window.
        // With BUG:  watcher receives bookmark(rv=365)→last_replayed=365, then
        //            svc-a(rv=364)→rv<=last_replayed→SKIP.  svc-a is never delivered.
        // With FIX:  bookmark only updates bookmark_rv, last_replayed stays at 0;
        //            svc-a(rv=364)→rv>last_replayed=0→Added.  svc-a is delivered.
        let mut added_keys: Vec<String> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Added(obj))) => {
                    added_keys.push(obj.key.clone());
                }
                Ok(Some(WatchEvent::Bookmark { .. })) => {}
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break, // timeout
            }
        }

        assert!(
            added_keys.contains(&"/registry/services/default/svc-a".to_string()),
            "svc-a must be delivered as Added even when a global bookmark with a higher rv \
             (from a different resource's write) arrives before the service event; \
             if global bookmarks advance last_replayed, the service event is dedup-skipped \
             and controllers like KCM never create EndpointSlices for the service"
        );
    }

    /// GET after PUT must return a revision >= the revision returned by PUT.
    ///
    /// KCM tracks the last revision it wrote and rejects reads whose resourceVersion is lower
    /// ("read version N is not as new as written version M"). Without the stale-read guard on
    /// get(), the WAL read connection can return an older object revision, triggering repeated
    /// optimistic concurrency failures in the controller reconcile loop.
    ///
    /// The guard fires when obj.revision < last_written_revision, retrying via the write
    /// connection. This test verifies the invariant holds: get after put returns the written rv.
    #[tokio::test]
    async fn get_after_put_returns_at_least_written_revision() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/apps/replicasets/default/rs-a";
        let value = Bytes::from(
            r#"{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"name":"rs-a","namespace":"default"}}"#,
        );

        let written_rv = store.put(key, value, None).await.expect("put must succeed");

        // Simulate a concurrent write that bumped last_written_revision above written_rv.
        // On a file-backed WAL store, the read connection may not have replayed the latest
        // WAL frame yet, causing get() to return an object with revision < last_written_revision.
        // The guard must detect this and retry via the write connection.
        store
            .last_written_revision
            .store(written_rv + 1, Ordering::Release);

        let obj = store
            .get(key)
            .await
            .expect("get must not error")
            .expect("object must exist after put");

        assert!(
            obj.revision >= written_rv,
            "get must return revision >= the revision returned by put ({written_rv}); \
             returning a lower revision causes KCM optimistic concurrency failures: \
             'read version {} is not as new as written version {written_rv}'",
            obj.revision
        );
    }

    /// GET for an existing pod must not return None when the WAL read snapshot predates the
    /// pod's creation.
    ///
    /// Without this fix, a GET that 404s an existing pod makes the kubelet tear down and
    /// recreate the sandbox ~1/sec, so Job pods never hold Running and every Job conformance
    /// test times out. The apiserver logged 105,684 pod-GET 404s in 5 min for only 6 pods.
    ///
    /// The stale-read guard must cover the None case (obj is None AND min_rev > 0), not just
    /// the Some(stale) case (obj.revision < min_rev).
    ///
    /// This test constructs a SqliteStore with a stale read_conn (empty in-memory DB that
    /// has no rows) and a write_conn that has the pod committed. last_written_revision is set
    /// to 1, signalling that writes have occurred that the read snapshot cannot see.
    /// With the fix: get() detects None + min_rev > 0 and retries via write_conn → Some.
    /// Without the fix: get() returns None directly → assertion fails → test fails on revert.
    #[tokio::test(flavor = "multi_thread")]
    async fn get_returns_some_when_stale_read_snapshot_misses_creation() {
        use std::collections::{HashMap, VecDeque};
        use std::sync::RwLock;
        use tokio::sync::broadcast;

        let key = "/registry/core/pods/job-ns/foo-d1a7f";
        let pod_value = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"foo-d1a7f","namespace":"job-ns"}}"#,
        );

        // Build a write connection with the full schema and the pod committed.
        let write_raw = Connection::open_in_memory().expect("write conn");
        write_raw
            .execute_batch(
                "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
                 revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
                 CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL); \
                 INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');",
            )
            .expect("schema");
        let last_written = Arc::new(AtomicU64::new(0));
        let written_rv = {
            put_sync(&write_raw, key, pod_value, None, &last_written)
                .expect("put_sync")
                .0
        };
        let write_conn = Arc::new(Mutex::new(write_raw));

        // Build a STALE read connection: a separate in-memory DB with the schema but NO rows.
        // This simulates the WAL read connection whose snapshot predates the pod's creation.
        let stale_raw = Connection::open_in_memory().expect("stale read conn");
        stale_raw
            .execute_batch(
                "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
                 revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
                 CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL); \
                 INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');",
            )
            .expect("stale schema");
        let read_conn = Arc::new(Mutex::new(stale_raw));

        // Confirm the stale read returns None — this is the production symptom.
        let stale_result =
            tokio::task::block_in_place(|| get_sync(&read_conn.blocking_lock(), key))
                .expect("get_sync on stale conn must not error");
        assert!(
            stale_result.is_none(),
            "stale read connection must return None (no rows) — test setup broken"
        );

        // Assemble the store with the stale read_conn and write_conn that has the pod.
        let (tx, _) = broadcast::channel(16);
        let store = SqliteStore {
            write_conn,
            read_conn,
            tx,
            ring: Arc::new(RwLock::new(VecDeque::new())),
            deletion_log: Arc::new(RwLock::new(HashMap::new())),
            compaction_horizon: Arc::new(AtomicU64::new(0)),
            last_written_revision: last_written,
        };

        // last_written_revision is already written_rv (set by put_sync).
        // get() must detect: obj == None AND min_rev == written_rv > 0 → retry via write_conn.
        let obj = store.get(key).await.expect("get must not error");

        assert!(
            obj.is_some(),
            "get must return Some for an existing pod (written at rv={written_rv}), not None; \
             a None response causes the kubelet to 404 the pod and tear down the sandbox ~1/sec, \
             so Job pods never hold Running and Job conformance tests time out"
        );
    }

    /// LIST after PUT must return a snapshot revision >= the revision returned by PUT.
    ///
    /// Under high write bursts with a large WAL (wal_autocheckpoint=1000), the read connection
    /// lags behind the write connection and list() returns a stale snapshot revision.
    /// KCM's RS controller compares the list resourceVersion against its last written revision
    /// and requeues in a tight loop for up to 15 minutes when the list RV is lower.
    ///
    /// The stale-read guard in list() detects this (resp.revision < last_written_revision)
    /// and retries via the write connection which always reflects the latest committed state.
    /// This test verifies the guard fires and the returned revision is current.
    #[tokio::test]
    async fn list_after_put_returns_at_least_written_revision() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/apps/replicasets/";
        let key = "/registry/apps/replicasets/default/rs-a";
        let value = Bytes::from(
            r#"{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"name":"rs-a","namespace":"default"}}"#,
        );

        let written_rv = store.put(key, value, None).await.expect("put must succeed");

        // Simulate WAL lag: bump last_written_revision above written_rv, as if a concurrent write
        // committed but the read connection's WAL snapshot has not yet replayed those frames.
        // On a file-backed WAL store under high write bursts, wal_autocheckpoint=1000 means the
        // read connection can trail the write connection by up to 1000 pages.
        store
            .last_written_revision
            .store(written_rv + 1, Ordering::Release);

        let resp = store
            .list(prefix, ListOptions::default())
            .await
            .expect("list must not error");

        assert!(
            resp.revision >= written_rv,
            "list must return snapshot revision >= the revision returned by put ({written_rv}); \
             a lower revision causes KCM's RS controller to log \
             'read version {} is not as new as written version {written_rv}' \
             and requeue in a tight loop for up to 15 minutes",
            resp.revision
        );
    }

    /// Repeated list() calls must return consistent results — verifies prepare_cached does not
    /// corrupt query state across calls.
    ///
    /// Why it matters: prepare_cached reuses the cached statement handle; if the handle is
    /// left in a bad state (rows not consumed, reset not called), a subsequent list on the same
    /// connection returns wrong results or errors, breaking any controller that lists repeatedly.
    #[tokio::test]
    async fn repeated_list_returns_consistent_results() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/core/configmaps/";

        for i in 0..5u32 {
            let key = format!("/registry/core/configmaps/default/cm-{i}");
            let val = Bytes::from(format!(
                r#"{{"apiVersion":"v1","kind":"ConfigMap","metadata":{{"name":"cm-{i}","namespace":"default"}}}}"#
            ));
            store.put(&key, val, None).await.expect("put must succeed");
        }

        let first = store
            .list(prefix, ListOptions::default())
            .await
            .expect("first list");
        let second = store
            .list(prefix, ListOptions::default())
            .await
            .expect("second list");

        assert_eq!(
            first.items.len(),
            second.items.len(),
            "repeated list() must return the same item count; a mismatch means prepare_cached \
             left the statement in a corrupted state, causing controllers to see inconsistent \
             object counts across reflector resyncs"
        );
        assert_eq!(
            first.items.len(),
            5,
            "list must return all 5 inserted configmaps; returning fewer breaks reflector \
             initial list completeness"
        );
    }

    /// PUT followed by GET must return the correctly stamped resourceVersion and the identical
    /// ns/obj_name that were in the original value — verifying that extracting indexed columns
    /// from the pre-stamp parse yields the same result as extracting from the stamped bytes.
    ///
    /// Why it matters: if the single-parse optimization extracts ns/obj_name from the wrong
    /// JSON document (e.g. before namespace is set, or from a stale value), the indexed columns
    /// in SQLite diverge from the stored object, breaking field-selector queries by namespace
    /// or name — controllers that list pods by nodeName or services by namespace never find
    /// their objects and reconcile loops stall indefinitely.
    #[tokio::test]
    async fn put_stamps_rv_and_preserves_ns_obj_name() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/core/pods/prod/web-abc";
        let raw = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web-abc","namespace":"prod"}}"#,
        );

        let rv = store.put(key, raw, None).await.expect("put must succeed");

        let obj = store
            .get(key)
            .await
            .expect("get must not error")
            .expect("object must exist after put");

        let parsed: serde_json::Value =
            serde_json::from_slice(&obj.value).expect("stored value must be valid JSON");

        assert_eq!(
            parsed["metadata"]["resourceVersion"].as_str(),
            Some(rv.to_string().as_str()),
            "stored object must have resourceVersion stamped to the revision returned by put; \
             a mismatch means the stamp did not propagate to the stored bytes"
        );
        assert_eq!(
            parsed["metadata"]["namespace"].as_str(),
            Some("prod"),
            "namespace must survive the single-parse stamp path; if extraction reads from the \
             wrong parse result the indexed ns column is wrong and namespace-scoped list queries \
             return empty results"
        );
        assert_eq!(
            parsed["metadata"]["name"].as_str(),
            Some("web-abc"),
            "name must survive the single-parse stamp path; if extraction reads from the wrong \
             parse result the indexed obj_name column is wrong and name field-selector queries \
             return empty results"
        );

        // Verify the indexed columns are queryable via field selector (proves SQLite columns match).
        let by_ns = store
            .list(
                "/registry/core/pods/",
                ListOptions {
                    field_selector: Some(FieldSelector {
                        field: "metadata.namespace".to_string(),
                        value: "prod".to_string(),
                        negated: false,
                    }),
                    ..Default::default()
                },
            )
            .await
            .expect("list by namespace");

        assert_eq!(
            by_ns.items.len(),
            1,
            "field-selector list by namespace=prod must return 1 pod; returning 0 means the \
             ns indexed column was not correctly populated by the single-parse put path, \
             breaking all namespace-scoped list queries"
        );
    }

    /// deletion_log must NOT retain a tombstone after the deleted key is re-created via PUT.
    ///
    /// Why it matters: keeping a DELETED tombstone for a live key causes a watcher reconnecting
    /// after compaction to receive a spurious DELETED event for the current (live) incarnation
    /// of the key, making controllers believe the object was deleted and stop reconciling —
    /// an unbounded deletion_log also leaks one Arc<InternalEvent> (full object body) per
    /// ever-deleted key, growing without bound on a long-running server.
    #[tokio::test]
    async fn deletion_log_evicts_tombstone_on_recreate() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/core/namespaces/ns-a";
        let val =
            Bytes::from(r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-a"}}"#);

        // Create, then delete the key — tombstone enters deletion_log.
        store
            .put(key, val.clone(), None)
            .await
            .expect("put must succeed");
        store.delete(key, None).await.expect("delete must succeed");

        {
            let guard = store.deletion_log.read().expect("deletion_log poisoned");
            assert!(
                guard.contains_key(key),
                "deletion_log must contain tombstone for deleted key; test setup broken"
            );
        }

        // Re-create the key via PUT — tombstone must be evicted.
        store
            .put(key, val, None)
            .await
            .expect("recreate must succeed");

        {
            let guard = store.deletion_log.read().expect("deletion_log poisoned");
            assert!(
                !guard.contains_key(key),
                "deletion_log must NOT retain tombstone after key is re-created; retaining it \
                 causes watchers reconnecting after compaction to receive a spurious DELETED event \
                 for the live object, making controllers stop reconciling the re-created resource"
            );
        }
    }

    /// deletion_log must retain tombstones for recently-deleted keys that have not been
    /// re-created, so a watcher reconnecting after compaction still receives DELETED events.
    ///
    /// Why it matters: evicting too aggressively drops DELETED events a watcher needs —
    /// a watcher that reconnects after the ring is compacted relies on deletion_log to
    /// receive tombstones for objects deleted during the compaction window; without them
    /// the watcher deadlocks waiting for a DELETED event that never arrives.
    #[tokio::test]
    async fn deletion_log_retains_tombstone_for_deleted_key_not_recreated() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // Delete several keys without re-creating them — all tombstones must survive.
        for i in 0..5u32 {
            let key = format!("/registry/core/namespaces/ns-{i}");
            let val = Bytes::from(format!(
                r#"{{"apiVersion":"v1","kind":"Namespace","metadata":{{"name":"ns-{i}"}}}}"#
            ));
            store.put(&key, val, None).await.expect("put must succeed");
            store.delete(&key, None).await.expect("delete must succeed");
        }

        // Perform additional writes (non-deletions) that do NOT touch the deleted keys.
        for i in 0..10u32 {
            let key = format!("/registry/core/configmaps/default/cm-{i}");
            let val = Bytes::from(format!(
                r#"{{"apiVersion":"v1","kind":"ConfigMap","metadata":{{"name":"cm-{i}","namespace":"default"}}}}"#
            ));
            store.put(&key, val, None).await.expect("put must succeed");
        }

        let guard = store.deletion_log.read().expect("deletion_log poisoned");
        for i in 0..5u32 {
            let key = format!("/registry/core/namespaces/ns-{i}");
            assert!(
                guard.contains_key(&key),
                "deletion_log must retain tombstone for ns-{i} (not re-created); evicting it \
                 would cause a reconnecting watcher to miss the DELETED event, deadlocking any \
                 controller waiting for the namespace deletion to complete"
            );
        }
    }
}
