use bytes::Bytes;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tokio::sync::{broadcast, Mutex};

/// A single stored Kubernetes object.
#[derive(Debug, Clone)]
pub struct StoreObject {
    /// Full /registry/... key.
    pub key: String,
    /// Serialized JSON bytes.
    pub value: Bytes,
    /// Global revision at which this version was written.
    pub revision: u64,
}

/// Identifies a single object.
#[derive(Debug, Clone)]
pub struct ObjectKey {
    pub key: String,
}

impl ObjectKey {
    /// Derives the store key for a namespace-scoped core resource.
    /// Example: namespace="default", resource="pods", name="nginx"
    /// → "/registry/pods/default/nginx"
    pub fn namespaced(resource: &str, namespace: &str, name: &str) -> Self {
        Self {
            key: format!("/registry/{}/{}/{}", resource, namespace, name),
        }
    }
}

/// Filters a list to objects where a dot-separated JSON field matches a value.
#[derive(Debug, Clone)]
pub struct FieldSelector {
    /// Dot-separated JSON path, e.g. "spec.nodeName".
    pub field: String,
    /// Expected value, e.g. "node-01".
    pub value: String,
    /// When true, include objects where the field does NOT equal value (!=).
    /// When false, include objects where the field equals value (=).
    pub negated: bool,
}

/// Options for a list operation.
#[derive(Debug, Default, Clone)]
pub struct ListOptions {
    /// If set, filter results to objects where the named field equals the given value.
    pub field_selector: Option<FieldSelector>,
    /// Maximum number of items to return. None means no limit.
    pub limit: Option<u64>,
    /// Opaque cursor: the store key to start from (exclusive lower bound).
    /// Clients obtain this from `ListResponse::continue_key` (base64-encoded).
    pub continue_key: Option<String>,
}

/// Result of a list operation.
#[derive(Debug)]
pub struct ListResponse {
    pub items: Vec<StoreObject>,
    /// Global revision of the snapshot at which this list was consistent.
    pub revision: u64,
    /// Set when more items remain after this page. Clients pass this back as `continue_key`
    /// (after base64-encoding) to get the next page.
    pub continue_key: Option<String>,
    /// Number of items remaining after this page (i.e. not returned in items).
    /// Set only when continue_key is Some; None when all items fit in this page.
    pub remaining_count: Option<u64>,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("key not found: {key}")]
    NotFound { key: String },

    #[error("revision mismatch: expected {expected}, current {current}")]
    RevisionMismatch { expected: u64, current: u64 },

    #[error("key already exists: {key}")]
    AlreadyExists { key: String },

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error("compacted: requested revision {requested} is below compaction horizon {horizon}")]
    Compacted { requested: u64, horizon: u64 },

    #[error("json serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Internal event broadcast after every write.
#[derive(Debug)]
pub struct InternalEvent {
    pub key: String,
    pub revision: u64,
    pub value: Option<Bytes>, // None = deleted
    pub is_create: bool,      // true if key did not exist before this put
}

/// Public watch event for consumers.
#[derive(Debug, Clone)]
pub enum WatchEvent {
    Added(StoreObject),
    Modified(StoreObject),
    Deleted { key: String, revision: u64 },
    Bookmark { revision: u64 },
    Compacted { requested: u64, horizon: u64 },
}

pub trait Store: Send + Sync + 'static {
    /// Get a single object by exact key. Returns None if not found.
    fn get(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Option<StoreObject>>> + Send;

    /// List all objects whose keys share the given prefix.
    /// Returns a consistent snapshot and the revision of that snapshot.
    fn list(
        &self,
        prefix: &str,
        opts: ListOptions,
    ) -> impl std::future::Future<Output = Result<ListResponse>> + Send;

    /// Write an object with optimistic concurrency control.
    ///
    /// `expected_revision` semantics:
    ///   None       → unconditional write (create or overwrite)
    ///   Some(0)    → create-only: key must not exist → AlreadyExists if it does
    ///   Some(rv)   → update-only: stored revision must equal rv → RevisionMismatch if not
    ///
    /// Returns the new global revision on success.
    /// The store stamps `metadata.resourceVersion` in the stored value before persisting.
    fn put(
        &self,
        key: &str,
        value: Bytes,
        expected_revision: Option<u64>,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;

    /// Delete an object. Same optimistic concurrency semantics as put.
    /// Returns the new global revision on success (the deletion revision).
    fn delete(
        &self,
        key: &str,
        expected_revision: Option<u64>,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;

    /// Watch objects under prefix starting from (exclusive) from_revision.
    /// Yields historical events from the ring buffer then live broadcast events.
    fn watch(
        &self,
        prefix: &str,
        from_revision: u64,
    ) -> impl std::future::Future<
        Output = Result<impl futures_core::Stream<Item = WatchEvent> + Send + 'static>,
    > + Send;

    /// Delete all objects belonging to the given namespace.
    ///
    /// Atomically removes every stored object whose `metadata.namespace` matches
    /// `namespace`. Returns the list of deleted store keys.
    ///
    /// Used by the namespace hard-delete path to prevent orphaned resources from
    /// causing false 409 AlreadyExists errors when the same namespace name is
    /// later re-created.
    fn delete_namespace_resources(
        &self,
        namespace: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;

    /// Return the current compaction horizon.
    /// Any revision below this value has been compacted out of the ring buffer.
    /// Returns 0 when no compaction has occurred.
    fn compaction_horizon(&self) -> u64;
}

const RING_CAPACITY: usize = 1000;
const BROADCAST_CAPACITY: usize = 512;

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
        let compaction_horizon = Arc::new(AtomicU64::new(0));
        let last_written_revision = Arc::new(AtomicU64::new(0));

        Ok(Self {
            write_conn,
            read_conn,
            tx,
            ring,
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
        // Best-effort broadcast; lagging receivers are dropped automatically.
        let _ = self.tx.send(event);
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
        PRAGMA wal_autocheckpoint = 1000;
    ",
    )?;
    Ok(conn)
}

/// Stamps metadata.resourceVersion into the stored JSON.
/// Parses the JSON, sets the field, re-serializes.
fn stamp_resource_version(value: &Bytes, revision: u64) -> Result<Bytes> {
    let mut obj: serde_json::Value = serde_json::from_slice(value)?;
    obj["metadata"]["resourceVersion"] = serde_json::Value::String(revision.to_string());
    Ok(Bytes::from(serde_json::to_vec(&obj)?))
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

    // 6. Stamp metadata.resourceVersion in the JSON value.
    let stamped_value = stamp_resource_version(&value, new_revision)?;

    // 7. Extract ns and obj_name for indexed columns.
    let (ns, obj_name) = {
        let obj: serde_json::Value = serde_json::from_slice(&stamped_value)?;
        let ns = obj["metadata"]["namespace"].as_str().map(str::to_owned);
        let obj_name = obj["metadata"]["name"].as_str().map(str::to_owned);
        (ns, obj_name)
    };

    // 8. Upsert the object.
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
) -> Result<u64> {
    conn.execute_batch("BEGIN IMMEDIATE")?;

    let stored: Option<u64> = conn
        .query_row(
            "SELECT revision FROM objects WHERE key = ?1",
            params![key],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        )
        .optional()?;

    // Optimistic concurrency check (same logic as put).
    match (stored, expected_revision) {
        (None, _) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::NotFound {
                key: key.to_string(),
            });
        }
        (Some(_), None) => {}
        (Some(_), Some(0)) => {} // 0 means "must exist" for delete (unconditional)
        (Some(stored_rv), Some(exp)) if stored_rv == exp => {}
        (Some(stored_rv), Some(exp)) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::RevisionMismatch {
                expected: exp,
                current: stored_rv,
            });
        }
    }

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
    Ok(new_revision)
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
    let mut stmt = conn.prepare(sql)?;
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
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            get_sync(&conn, &key)
        })
        .await?
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
        }));

        Ok(revision)
    }

    async fn delete(&self, key: &str, expected_revision: Option<u64>) -> Result<u64> {
        let conn = self.write_conn.clone();
        let key_str = key.to_string();
        let last_written = Arc::clone(&self.last_written_revision);
        let revision = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            delete_sync(&conn, &key_str, expected_revision, &last_written)
        })
        .await??;

        self.push_event(Arc::new(InternalEvent {
            key: key.to_string(),
            revision,
            value: None,
            is_create: false,
        }));

        Ok(revision)
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

        let stream = async_stream::stream! {
            // Yield compacted event if from_revision is before the horizon.
            if from_revision > 0 && from_revision < horizon {
                yield WatchEvent::Compacted { requested: from_revision, horizon };
                return;
            }

            // Replay historical events from ring buffer.
            let mut last_replayed = from_revision;
            for event in &replayed {
                last_replayed = last_replayed.max(event.revision);
                yield internal_to_watch(event);
            }

            // Forward live broadcast events, skipping already-replayed revisions.
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if !event.key.starts_with(&prefix_owned) {
                            continue;
                        }
                        // Deduplicate: skip if already covered by replay or a previous live event.
                        if event.revision <= last_replayed {
                            continue;
                        }
                        last_replayed = event.revision;
                        yield internal_to_watch(&event);
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
                        let current_horizon = compaction_horizon_arc.load(Ordering::Relaxed);
                        if current_horizon > last_replayed {
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
}

fn internal_to_watch(event: &InternalEvent) -> WatchEvent {
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
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_core::Stream;
    use std::pin::Pin;

    fn make_store() -> SqliteStore {
        SqliteStore::new(":memory:").expect("open in-memory db")
    }

    fn pod_json(name: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": name,
                    "namespace": "default"
                },
                "spec": {
                    "nodeName": "test-node",
                    "containers": [{"name": "nginx", "image": "nginx:latest"}]
                }
            })
            .to_string(),
        )
    }

    fn pod_json_with_node(name: &str, node: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": name,
                    "namespace": "default"
                },
                "spec": {
                    "nodeName": node,
                    "containers": [{"name": "nginx", "image": "nginx:latest"}]
                }
            })
            .to_string(),
        )
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let store = make_store();
        let key = "/registry/pods/default/nginx";
        let value = pod_json("nginx");

        let rv = store
            .put(key, value.clone(), Some(0))
            .await
            .expect("create");
        assert!(rv > 0, "revision should be positive after create");

        let obj = store.get(key).await.expect("get").expect("should exist");
        assert_eq!(obj.key, key);
        assert_eq!(obj.revision, rv);

        // resourceVersion should be stamped in the stored JSON
        let parsed: serde_json::Value = serde_json::from_slice(&obj.value).unwrap();
        assert_eq!(
            parsed["metadata"]["resourceVersion"].as_str().unwrap(),
            rv.to_string()
        );
    }

    #[tokio::test]
    async fn test_create_already_exists() {
        let store = make_store();
        let key = "/registry/pods/default/nginx";
        let value = pod_json("nginx");

        store
            .put(key, value.clone(), Some(0))
            .await
            .expect("first create");

        let err = store
            .put(key, value, Some(0))
            .await
            .expect_err("should fail");
        assert!(matches!(err, StoreError::AlreadyExists { .. }));
    }

    #[tokio::test]
    async fn test_optimistic_concurrency_mismatch() {
        let store = make_store();
        let key = "/registry/pods/default/nginx";
        let value = pod_json("nginx");

        let rv1 = store
            .put(key, value.clone(), Some(0))
            .await
            .expect("create");

        // Advance the revision by doing a replace
        let rv2 = store
            .put(key, value.clone(), Some(rv1))
            .await
            .expect("first replace");
        assert!(rv2 > rv1);

        // Now try to replace with the stale rv1
        let err = store
            .put(key, value, Some(rv1))
            .await
            .expect_err("should conflict");
        assert!(
            matches!(err, StoreError::RevisionMismatch { expected, current } if expected == rv1 && current == rv2)
        );
    }

    #[tokio::test]
    async fn test_delete() {
        let store = make_store();
        let key = "/registry/pods/default/nginx";
        let value = pod_json("nginx");

        store.put(key, value, Some(0)).await.expect("create");

        let _del_rv = store.delete(key, None).await.expect("delete");

        let result = store.get(key).await.expect("get after delete");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let store = make_store();
        let key = "/registry/pods/default/missing";

        let err = store.delete(key, None).await.expect_err("should fail");
        assert!(matches!(err, StoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn test_list() {
        let store = make_store();

        store
            .put("/registry/pods/default/alpha", pod_json("alpha"), Some(0))
            .await
            .expect("create alpha");
        store
            .put("/registry/pods/default/beta", pod_json("beta"), Some(0))
            .await
            .expect("create beta");
        store
            .put("/registry/pods/other/gamma", pod_json("gamma"), Some(0))
            .await
            .expect("create gamma");

        let resp = store
            .list("/registry/pods/default/", ListOptions::default())
            .await
            .expect("list");
        assert_eq!(resp.items.len(), 2);

        let keys: Vec<&str> = resp.items.iter().map(|o| o.key.as_str()).collect();
        assert!(keys.contains(&"/registry/pods/default/alpha"));
        assert!(keys.contains(&"/registry/pods/default/beta"));

        // Snapshot revision should be >= last written revision
        assert!(resp.revision >= 3);
    }

    #[tokio::test]
    async fn test_list_empty() {
        let store = make_store();
        let resp = store
            .list("/registry/pods/default/", ListOptions::default())
            .await
            .expect("list");
        assert_eq!(resp.items.len(), 0);
        assert_eq!(resp.revision, 0);
    }

    #[tokio::test]
    async fn test_unconditional_put() {
        let store = make_store();
        let key = "/registry/pods/default/nginx";
        let value = pod_json("nginx");

        // Unconditional create
        let rv1 = store
            .put(key, value.clone(), None)
            .await
            .expect("unconditional create");
        assert!(rv1 > 0);

        // Unconditional overwrite
        let rv2 = store
            .put(key, value, None)
            .await
            .expect("unconditional overwrite");
        assert!(rv2 > rv1);
    }

    // Helper: pull next event from a pinned stream with a timeout.
    async fn next_event(
        stream: &mut Pin<Box<dyn Stream<Item = WatchEvent> + Send>>,
    ) -> Option<WatchEvent> {
        use std::future::poll_fn;
        use tokio::time::{timeout, Duration};
        timeout(
            Duration::from_secs(2),
            poll_fn(|cx| stream.as_mut().poll_next(cx)),
        )
        .await
        .ok()
        .flatten()
    }

    #[tokio::test]
    async fn watch_added_event() {
        // Put an object, subscribe watch from revision 0, verify ADDED event.
        let store = make_store();
        let key = "/registry/pods/default/nginx";

        let rv = store
            .put(key, pod_json("nginx"), Some(0))
            .await
            .expect("create");

        // Watch from before the put; ring buffer should have the event.
        let stream = store
            .watch("/registry/pods/default/", 0)
            .await
            .expect("watch");
        let mut stream: Pin<Box<dyn Stream<Item = WatchEvent> + Send>> = Box::pin(stream);

        let event = next_event(&mut stream).await.expect("should get event");
        assert!(
            matches!(&event, WatchEvent::Added(obj) if obj.key == key && obj.revision == rv),
            "expected Added, got {:?}",
            event
        );
    }

    #[tokio::test]
    async fn watch_deleted_event() {
        // Put then delete; watch from revision 0 should yield Added then Deleted.
        let store = make_store();
        let key = "/registry/pods/default/nginx";

        let _rv1 = store
            .put(key, pod_json("nginx"), Some(0))
            .await
            .expect("create");
        let rv2 = store.delete(key, None).await.expect("delete");

        let stream = store
            .watch("/registry/pods/default/", 0)
            .await
            .expect("watch");
        let mut stream: Pin<Box<dyn Stream<Item = WatchEvent> + Send>> = Box::pin(stream);

        // First event is Added from the put.
        let ev1 = next_event(&mut stream).await.expect("added event");
        assert!(
            matches!(ev1, WatchEvent::Added(_)),
            "expected Added, got {:?}",
            ev1
        );

        // Second event is Deleted from the delete.
        let ev2 = next_event(&mut stream).await.expect("deleted event");
        assert!(
            matches!(&ev2, WatchEvent::Deleted { key: k, revision: r } if k == key && *r == rv2),
            "expected Deleted, got {:?}",
            ev2
        );
    }

    #[tokio::test]
    async fn watch_compacted() {
        // Watch with a very old (non-zero) revision should yield a Compacted event
        // when from_revision < compaction_horizon.
        let store = make_store();

        // Manually advance the compaction horizon by simulating a full ring.
        // We set compaction_horizon directly to simulate compaction having occurred.
        store.compaction_horizon.store(50, Ordering::Relaxed);

        // Request from revision 10, which is below horizon 50.
        let stream = store.watch("/registry/pods/", 10).await.expect("watch");
        let mut stream: Pin<Box<dyn Stream<Item = WatchEvent> + Send>> = Box::pin(stream);

        let event = next_event(&mut stream)
            .await
            .expect("should get compacted event");
        assert!(
            matches!(
                event,
                WatchEvent::Compacted {
                    requested: 10,
                    horizon: 50
                }
            ),
            "expected Compacted, got {:?}",
            event
        );
    }

    #[tokio::test]
    async fn watch_lagged_emits_compaction_horizon_not_message_count() {
        // RecvError::Lagged(n) gives n = count of dropped messages, NOT a revision number.
        // The Compacted event horizon field must be the store's compaction horizon (a revision),
        // not the dropped-message count. If a consumer retries from horizon=3 (dropped count)
        // when the real horizon is 50_000, it gets 410 Gone or replays compacted history.
        //
        // This test will FAIL if the fix is reverted to `let current_horizon = n`.
        use tokio::sync::broadcast;

        // Build a store with a tiny broadcast capacity so lag is easy to trigger.
        let write_conn = {
            use rusqlite::Connection;
            let conn = Connection::open(":memory:").unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID;
                 CREATE TABLE IF NOT EXISTS meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);
                 INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');
                 CREATE INDEX IF NOT EXISTS idx_pods_nodename ON objects (json_extract(value, '$.spec.nodeName')) WHERE key LIKE '/registry/pods/%';
                 CREATE INDEX IF NOT EXISTS idx_ns_name ON objects(ns, obj_name) WHERE ns IS NOT NULL;
                 CREATE INDEX IF NOT EXISTS idx_name ON objects(obj_name);",
            ).unwrap();
            conn
        };
        let write_conn = Arc::new(tokio::sync::Mutex::new(write_conn));
        let read_conn = Arc::clone(&write_conn);

        // Use broadcast capacity = 4 so writing 6 events lags a slow subscriber.
        let (tx, _) = broadcast::channel::<Arc<InternalEvent>>(4);
        let ring = Arc::new(RwLock::new(std::collections::VecDeque::with_capacity(
            RING_CAPACITY + 1,
        )));
        let compaction_horizon = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let store = SqliteStore {
            write_conn,
            read_conn,
            tx,
            ring,
            compaction_horizon,
            last_written_revision: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };

        // Set a known compaction horizon — this is what the Compacted event must report.
        let known_horizon: u64 = 50_000;
        store.set_compaction_horizon_for_test(known_horizon);

        // Subscribe a watcher BEFORE writing, so it lags when we flood the channel.
        let stream = store.watch("/registry/pods/", 0).await.expect("watch");
        let mut stream: Pin<Box<dyn futures_core::Stream<Item = WatchEvent> + Send>> =
            Box::pin(stream);

        // Write enough events to overflow the broadcast channel (capacity=4) without consuming.
        // We write 6 objects: 6 > 4, so the slow subscriber lags by 2 messages.
        for i in 0..6u64 {
            let key = format!("/registry/pods/default/pod-{i}");
            store
                .put(&key, pod_json(&format!("pod-{i}")), Some(0))
                .await
                .expect("put");
        }

        // Drain replayed ring-buffer events (up to 6), then expect a Compacted event
        // from the broadcast lag. We allow up to 10 events to find it.
        let mut compacted_event = None;
        for _ in 0..10 {
            match next_event(&mut stream).await {
                Some(WatchEvent::Compacted { requested, horizon }) => {
                    compacted_event = Some((requested, horizon));
                    break;
                }
                Some(_) => continue, // replayed ring-buffer event; keep going
                None => break,       // timeout — stream ended
            }
        }

        let (_, horizon) = compacted_event
            .expect("watch stream must emit a Compacted event when the broadcast channel lags");

        // The horizon must be the store's compaction horizon (known_horizon = 50_000),
        // not the dropped-message count (which would be 2 — far smaller).
        assert_eq!(
            horizon, known_horizon,
            "Compacted horizon must be the store's compaction horizon ({known_horizon}), \
             not the dropped-message count (got {horizon})"
        );
    }

    /// Regression test for mayor-v7qi: when the broadcast channel lags (slow consumer),
    /// the watch stream must NOT terminate with a Compacted error when the ring buffer
    /// still holds the missed events. Instead it must recover, replay the ring buffer
    /// catchup, and continue delivering subsequent LIVE broadcast events.
    ///
    /// Without the fix: Lagged → Compacted → stream closes → 410 error sent to client →
    /// client relists and re-watches → may lag again → test stalls for 300s.
    ///
    /// With the fix: Lagged → recover via ring buffer → ADDED/MODIFIED events from
    /// subsequent live writes also arrive → test does not stall.
    ///
    /// This test FAILS if the fix is reverted (i.e., if RecvError::Lagged immediately
    /// yields WatchEvent::Compacted without attempting ring-buffer recovery): the stream
    /// closes before the live "recovery-pod" event can arrive.
    #[tokio::test]
    async fn watch_lagged_recovers_and_delivers_subsequent_live_events() {
        use std::sync::Arc;
        use tokio::sync::broadcast;
        use tokio::time::Duration;

        // Build a store with a tiny broadcast capacity so lag is easy to trigger.
        let write_conn = {
            use rusqlite::Connection;
            let conn = Connection::open(":memory:").unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID;
                 CREATE TABLE IF NOT EXISTS meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);
                 INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');
                 CREATE INDEX IF NOT EXISTS idx_pods_nodename ON objects (json_extract(value, '$.spec.nodeName')) WHERE key LIKE '/registry/pods/%';
                 CREATE INDEX IF NOT EXISTS idx_ns_name ON objects(ns, obj_name) WHERE ns IS NOT NULL;
                 CREATE INDEX IF NOT EXISTS idx_name ON objects(obj_name);",
            ).unwrap();
            conn
        };
        let write_conn = Arc::new(tokio::sync::Mutex::new(write_conn));
        let read_conn = Arc::clone(&write_conn);

        // Tiny broadcast capacity: 4 messages. Writing 6 objects causes the subscriber to lag.
        let (tx, _) = broadcast::channel::<Arc<InternalEvent>>(4);
        let ring = Arc::new(RwLock::new(std::collections::VecDeque::with_capacity(
            RING_CAPACITY + 1,
        )));
        let compaction_horizon = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let store = Arc::new(SqliteStore {
            write_conn,
            read_conn,
            tx,
            ring,
            compaction_horizon,
            last_written_revision: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });

        // Compaction horizon is 0: ring buffer has NOT been compacted.
        // All written events are available in the ring buffer for recovery.

        // Subscribe a watcher BEFORE writing, so it lags when we flood the channel.
        let stream = store
            .watch("/registry/pods/default/", 0)
            .await
            .expect("watch");
        let mut stream: Pin<Box<dyn futures_core::Stream<Item = WatchEvent> + Send>> =
            Box::pin(stream);

        // Write 6 objects — overflows broadcast channel (capacity=4), causes lag.
        // All 6 events are also stored in the ring buffer (capacity=1000).
        for i in 0..6u64 {
            let key = format!("/registry/pods/default/pod-{i}");
            store
                .put(&key, pod_json(&format!("pod-{i}")), Some(0))
                .await
                .expect("put");
        }

        // Spawn a task that writes a "live" pod after a short delay.
        // This pod arrives via the broadcast channel AFTER the Lagged recovery,
        // not from the ring buffer (ring buffer is read during recovery, before this write).
        // Without the recovery fix, the stream terminates before this event can arrive.
        let store2 = Arc::clone(&store);
        let live_key = "/registry/pods/default/recovery-pod";
        tokio::spawn(async move {
            // Allow time for the stream to process the 6 ring-buffer events and hit the
            // Lagged error in the broadcast loop before writing the live event.
            tokio::time::sleep(Duration::from_millis(20)).await;
            store2
                .put(live_key, pod_json("recovery-pod"), Some(0))
                .await
                .expect("put recovery pod");
        });

        // Consume the stream. With the fix:
        //   1. 6 ADDED events from ring buffer replay (before Lagged hits)
        //   2. Lagged hits → recover: re-subscribe + re-scan ring buffer (already delivered, catchup empty)
        //   3. "recovery-pod" arrives via live broadcast → stream delivers it
        //
        // Without the fix:
        //   1. 6 ADDED events from ring buffer replay
        //   2. Lagged hits → WatchEvent::Compacted emitted → stream closes
        //   3. "recovery-pod" never arrives → test panics or fails assertion
        let mut found_live = false;
        let mut got_compacted = false;
        for _ in 0..20 {
            match next_event(&mut stream).await {
                Some(WatchEvent::Added(obj)) => {
                    if obj.key == live_key {
                        found_live = true;
                        break;
                    }
                }
                Some(WatchEvent::Compacted { .. }) => {
                    got_compacted = true;
                    break;
                }
                Some(_) => {}
                None => break,
            }
        }

        assert!(
            !got_compacted,
            "watch stream must NOT emit Compacted when ring buffer covers the lag gap; \
             without the mayor-v7qi fix, RecvError::Lagged immediately yields Compacted, \
             forcing the client to relist and re-watch (and likely lag again) — \
             causing conformance tests to stall for 300s waiting for MODIFIED events"
        );
        assert!(
            found_live,
            "watch stream must deliver the live 'recovery-pod' event after lag recovery; \
             without the fix the stream closes before this event arrives (mayor-v7qi)"
        );
    }

    #[tokio::test]
    async fn watch_is_create_flag() {
        // First put → is_create=true (Added); second put (same key) → is_create=false (Modified).
        let store = make_store();
        let key = "/registry/pods/default/nginx";

        let rv1 = store
            .put(key, pod_json("nginx"), Some(0))
            .await
            .expect("create");
        let rv2 = store
            .put(key, pod_json("nginx-v2"), Some(rv1))
            .await
            .expect("update");

        let stream = store
            .watch("/registry/pods/default/", 0)
            .await
            .expect("watch");
        let mut stream: Pin<Box<dyn Stream<Item = WatchEvent> + Send>> = Box::pin(stream);

        let ev1 = next_event(&mut stream).await.expect("first event");
        assert!(
            matches!(&ev1, WatchEvent::Added(obj) if obj.revision == rv1),
            "expected Added for create, got {:?}",
            ev1
        );

        let ev2 = next_event(&mut stream).await.expect("second event");
        assert!(
            matches!(&ev2, WatchEvent::Modified(obj) if obj.revision == rv2),
            "expected Modified for update, got {:?}",
            ev2
        );
    }

    // --- Field selector tests ---

    #[tokio::test]
    async fn test_field_selector_nodename() {
        // Verifies that the indexed fast-path (spec.nodeName on pods) returns only
        // pods assigned to the requested node, exercising the partial SQLite index.
        let store = make_store();

        store
            .put(
                "/registry/pods/default/pod-a",
                pod_json_with_node("pod-a", "node-1"),
                Some(0),
            )
            .await
            .expect("create pod-a");
        store
            .put(
                "/registry/pods/default/pod-b",
                pod_json_with_node("pod-b", "node-2"),
                Some(0),
            )
            .await
            .expect("create pod-b");
        store
            .put(
                "/registry/pods/default/pod-c",
                pod_json_with_node("pod-c", "node-1"),
                Some(0),
            )
            .await
            .expect("create pod-c");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "spec.nodeName".to_string(),
                value: "node-1".to_string(),
                negated: false,
            }),
            ..Default::default()
        };
        let resp = store.list("/registry/pods/", opts).await.expect("list");

        assert_eq!(
            resp.items.len(),
            2,
            "should return exactly the 2 pods on node-1"
        );
        let keys: Vec<&str> = resp.items.iter().map(|o| o.key.as_str()).collect();
        assert!(keys.contains(&"/registry/pods/default/pod-a"));
        assert!(keys.contains(&"/registry/pods/default/pod-c"));
        assert!(
            !keys.contains(&"/registry/pods/default/pod-b"),
            "pod-b is on node-2, must be excluded"
        );
    }

    #[tokio::test]
    async fn test_field_selector_fallback() {
        // Verifies that metadata.namespace field selector returns only objects in that namespace.
        // metadata.namespace now uses the SQL idx_ns index fast-path.
        let store = make_store();

        store
            .put(
                "/registry/pods/default/pod-a",
                pod_json_with_node("pod-a", "node-1"),
                Some(0),
            )
            .await
            .expect("create pod-a");
        store
            .put(
                "/registry/pods/other/pod-b",
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": { "name": "pod-b", "namespace": "other" },
                        "spec": { "nodeName": "node-2", "containers": [] }
                    })
                    .to_string(),
                ),
                Some(0),
            )
            .await
            .expect("create pod-b");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "metadata.namespace".to_string(),
                value: "default".to_string(),
                negated: false,
            }),
            ..Default::default()
        };
        let resp = store.list("/registry/pods/", opts).await.expect("list");

        assert_eq!(resp.items.len(), 1, "only pod-a is in namespace default");
        assert_eq!(resp.items[0].key, "/registry/pods/default/pod-a");
    }

    #[tokio::test]
    async fn test_field_selector_none() {
        // Verifies that field_selector: None preserves the existing list behavior exactly.
        let store = make_store();

        store
            .put("/registry/pods/default/alpha", pod_json("alpha"), Some(0))
            .await
            .expect("create alpha");
        store
            .put("/registry/pods/default/beta", pod_json("beta"), Some(0))
            .await
            .expect("create beta");
        store
            .put("/registry/pods/other/gamma", pod_json("gamma"), Some(0))
            .await
            .expect("create gamma");

        let resp = store
            .list("/registry/pods/default/", ListOptions::default())
            .await
            .expect("list");
        assert_eq!(
            resp.items.len(),
            2,
            "default() must behave identically to before this change"
        );
        let keys: Vec<&str> = resp.items.iter().map(|o| o.key.as_str()).collect();
        assert!(keys.contains(&"/registry/pods/default/alpha"));
        assert!(keys.contains(&"/registry/pods/default/beta"));
    }

    #[tokio::test]
    async fn test_field_selector_metadata_name_namespaced_returns_exact_object() {
        // fieldSelector=metadata.name=<value> on a namespaced resource must return only
        // the object with that name, without scanning all objects in the prefix.
        // If the fast-path is removed and replaced with a generic full-scan filter, the
        // correctness is unchanged but the key insight (direct key lookup) is lost.
        // This test verifies: (a) the matching object is returned, (b) non-matching objects
        // in the same prefix are excluded, (c) objects in other namespaces are excluded.
        let store = make_store();

        store
            .put("/registry/pods/default/target", pod_json("target"), Some(0))
            .await
            .expect("create target pod");
        store
            .put("/registry/pods/default/other", pod_json("other"), Some(0))
            .await
            .expect("create other pod in same namespace");
        store
            .put(
                "/registry/pods/kube-system/target",
                pod_json("target"),
                Some(0),
            )
            .await
            .expect("create target pod in different namespace");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "metadata.name".to_string(),
                value: "target".to_string(),
                negated: false,
            }),
            ..Default::default()
        };
        let resp = store
            .list("/registry/pods/default/", opts)
            .await
            .expect("list");

        assert_eq!(
            resp.items.len(),
            1,
            "metadata.name selector must return exactly one object for the matching name; \
             a full scan would include 'other' pod if the fast-path were broken"
        );
        assert_eq!(
            resp.items[0].key, "/registry/pods/default/target",
            "the returned object must be the one with the matching name in the specified prefix"
        );
    }

    #[tokio::test]
    async fn test_field_selector_metadata_name_cluster_scoped_returns_exact_object() {
        // fieldSelector=metadata.name=<value> on a cluster-scoped resource (prefix ends at
        // the resource level) must return only the matching object.
        // Kubernetes clients use this to fetch a single node by name via list, not get.
        let store = make_store();

        store
            .put(
                "/registry/nodes/node-a",
                node_json("node-a", false),
                Some(0),
            )
            .await
            .expect("create node-a");
        store
            .put(
                "/registry/nodes/node-b",
                node_json("node-b", false),
                Some(0),
            )
            .await
            .expect("create node-b");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "metadata.name".to_string(),
                value: "node-a".to_string(),
                negated: false,
            }),
            ..Default::default()
        };
        let resp = store.list("/registry/nodes/", opts).await.expect("list");

        assert_eq!(
            resp.items.len(),
            1,
            "metadata.name selector on cluster-scoped resource must return exactly one object; \
             a scan would return all nodes if the key prefix computation were wrong"
        );
        assert_eq!(
            resp.items[0].key, "/registry/nodes/node-a",
            "only node-a must be returned, not node-b"
        );
    }

    #[tokio::test]
    async fn test_field_selector_metadata_name_absent_returns_empty() {
        // metadata.name=<nonexistent> must return an empty list, not an error.
        // Kubernetes clients rely on empty lists from get-by-name selectors when
        // an object doesn't exist (e.g., checking if a resource was deleted).
        let store = make_store();

        store
            .put("/registry/pods/default/alpha", pod_json("alpha"), Some(0))
            .await
            .expect("create alpha");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "metadata.name".to_string(),
                value: "nonexistent".to_string(),
                negated: false,
            }),
            ..Default::default()
        };
        let resp = store
            .list("/registry/pods/default/", opts)
            .await
            .expect("list");

        assert_eq!(
            resp.items.len(),
            0,
            "metadata.name selector for a non-existent name must return empty list, not an error"
        );
    }

    fn node_json(name: &str, unschedulable: bool) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Node",
                "metadata": { "name": name },
                "spec": { "unschedulable": unschedulable }
            })
            .to_string(),
        )
    }

    fn node_json_no_unschedulable(name: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Node",
                "metadata": { "name": name },
                "spec": {}
            })
            .to_string(),
        )
    }

    #[tokio::test]
    async fn test_field_selector_neq_bool_excludes_matching_nodes() {
        // GetReadySchedulableNodes uses fieldSelector=spec.unschedulable!=true.
        // A schedulable node (spec.unschedulable=false) must be INCLUDED.
        // An unschedulable node (spec.unschedulable=true) must be EXCLUDED.
        // Before the fix, the '!' was included in the field name, so json_extract
        // looked for "$.spec.unschedulable!" which finds nothing — returning 0 results.
        let store = make_store();

        store
            .put(
                "/registry/nodes/schedulable",
                node_json("schedulable", false),
                Some(0),
            )
            .await
            .expect("create schedulable node");
        store
            .put(
                "/registry/nodes/unschedulable",
                node_json("unschedulable", true),
                Some(0),
            )
            .await
            .expect("create unschedulable node");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "spec.unschedulable".to_string(),
                value: "true".to_string(),
                negated: true,
            }),
            ..Default::default()
        };
        let resp = store.list("/registry/nodes/", opts).await.expect("list");

        assert_eq!(
            resp.items.len(),
            1,
            "only the schedulable node must be returned when filtering spec.unschedulable!=true"
        );
        assert_eq!(
            resp.items[0].key, "/registry/nodes/schedulable",
            "the schedulable node (spec.unschedulable=false) must be included; \
             the unschedulable node must be excluded"
        );
    }

    #[tokio::test]
    async fn test_field_selector_eq_bool_includes_only_matching() {
        // fieldSelector=spec.unschedulable=true must return ONLY unschedulable nodes.
        // This tests that bool JSON values are compared correctly via string "true"/"false".
        let store = make_store();

        store
            .put(
                "/registry/nodes/schedulable",
                node_json("schedulable", false),
                Some(0),
            )
            .await
            .expect("create schedulable node");
        store
            .put(
                "/registry/nodes/unschedulable",
                node_json("unschedulable", true),
                Some(0),
            )
            .await
            .expect("create unschedulable node");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "spec.unschedulable".to_string(),
                value: "true".to_string(),
                negated: false,
            }),
            ..Default::default()
        };
        let resp = store.list("/registry/nodes/", opts).await.expect("list");

        assert_eq!(
            resp.items.len(),
            1,
            "only the unschedulable node must be returned when filtering spec.unschedulable=true"
        );
        assert_eq!(
            resp.items[0].key, "/registry/nodes/unschedulable",
            "the unschedulable node (spec.unschedulable=true) must match the = selector"
        );
    }

    #[tokio::test]
    async fn test_field_selector_neq_absent_field_included() {
        // When spec.unschedulable is absent (field not in JSON), the node is schedulable
        // by default in Kubernetes. A != selector must include objects where the field
        // is absent, not silently exclude them.
        let store = make_store();

        store
            .put(
                "/registry/nodes/no-field",
                node_json_no_unschedulable("no-field"),
                Some(0),
            )
            .await
            .expect("create node without unschedulable field");
        store
            .put(
                "/registry/nodes/unschedulable",
                node_json("unschedulable", true),
                Some(0),
            )
            .await
            .expect("create unschedulable node");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "spec.unschedulable".to_string(),
                value: "true".to_string(),
                negated: true,
            }),
            ..Default::default()
        };
        let resp = store.list("/registry/nodes/", opts).await.expect("list");

        assert_eq!(
            resp.items.len(),
            1,
            "node with absent spec.unschedulable must be included by != selector"
        );
        assert_eq!(
            resp.items[0].key, "/registry/nodes/no-field",
            "absent field is not equal to 'true', so != selector must include it"
        );
    }

    #[tokio::test]
    async fn test_field_selector_eq_false_matches_absent_field() {
        // e2e BeforeSuite queries spec.unschedulable=false. A node with no
        // spec.unschedulable field must be included because absent == zero value == false.
        let store = make_store();

        store
            .put(
                "/registry/nodes/no-field",
                node_json_no_unschedulable("no-field"),
                Some(0),
            )
            .await
            .expect("create node without unschedulable field");
        store
            .put(
                "/registry/nodes/unschedulable",
                node_json("unschedulable", true),
                Some(0),
            )
            .await
            .expect("create unschedulable node");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "spec.unschedulable".to_string(),
                value: "false".to_string(),
                negated: false,
            }),
            ..Default::default()
        };
        let resp = store.list("/registry/nodes/", opts).await.expect("list");

        assert_eq!(
            resp.items.len(),
            1,
            "node with absent spec.unschedulable must match spec.unschedulable=false"
        );
        assert_eq!(
            resp.items[0].key, "/registry/nodes/no-field",
            "only the schedulable node (absent field) must be returned"
        );
    }

    #[tokio::test]
    async fn test_global_monotonic_resource_version() {
        // Kubernetes conformance requires resourceVersion to be a strictly increasing
        // integer across ALL resource types, not per-resource. A watch started at rv=N
        // must receive only events with rv > N regardless of kind.
        //
        // This test writes 5 objects of 3 different resource kinds and verifies:
        //   1. Each returned revision is strictly greater than the previous.
        //   2. The revision stored in metadata.resourceVersion is an integer string
        //      (no decimals, no non-numeric characters).
        let store = make_store();

        let pod_value = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": { "name": "p1", "namespace": "default" },
                "spec": { "containers": [] }
            })
            .to_string(),
        );

        let ns_value = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1", "kind": "Namespace",
                "metadata": { "name": "staging" }
            })
            .to_string(),
        );

        let cm_value = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": { "name": "cfg", "namespace": "default" },
                "data": {}
            })
            .to_string(),
        );

        let rv1 = store
            .put("/registry/pods/default/p1", pod_value.clone(), Some(0))
            .await
            .expect("create pod");
        let rv2 = store
            .put("/registry/namespaces/staging", ns_value.clone(), Some(0))
            .await
            .expect("create namespace");
        let rv3 = store
            .put(
                "/registry/configmaps/default/cfg",
                cm_value.clone(),
                Some(0),
            )
            .await
            .expect("create configmap");
        let rv4 = store
            .put("/registry/pods/default/p2", pod_value.clone(), Some(0))
            .await
            .expect("create pod 2");
        let rv5 = store
            .put("/registry/namespaces/production", ns_value.clone(), Some(0))
            .await
            .expect("create namespace 2");

        let revisions = [rv1, rv2, rv3, rv4, rv5];

        // Strictly increasing: each write must advance the global counter by at least 1.
        for window in revisions.windows(2) {
            assert!(
                window[1] > window[0],
                "resourceVersion must be strictly increasing across resource kinds: {} → {}",
                window[0],
                window[1]
            );
        }

        // The revision stamped into metadata.resourceVersion must be an integer string.
        // Kubernetes clients parse it with strconv.ParseInt — any decimal or non-numeric
        // character would cause conformance failures.
        for (key, expected_rv) in [
            ("/registry/pods/default/p1", rv1),
            ("/registry/namespaces/staging", rv2),
            ("/registry/configmaps/default/cfg", rv3),
        ] {
            let obj = store.get(key).await.expect("get").expect("should exist");
            let parsed: serde_json::Value = serde_json::from_slice(&obj.value).unwrap();
            let rv_str = parsed["metadata"]["resourceVersion"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!("metadata.resourceVersion must be a string for key {key}")
                });

            // Must parse as u64 (integer, no decimal point).
            let rv_int: u64 = rv_str.parse().unwrap_or_else(|_| {
                panic!("metadata.resourceVersion '{rv_str}' is not a valid integer string for key {key}")
            });
            assert_eq!(
                rv_int, expected_rv,
                "stamped resourceVersion must match returned revision for key {key}"
            );
        }
    }

    // --- Pagination tests ---

    #[tokio::test]
    async fn test_list_limit_returns_continue_key() {
        // A page smaller than the total must return a continue_key so clients know more items remain.
        // Without this, a client that gets fewer items than expected has no way to tell
        // whether it's the last page or pagination is simply broken.
        let store = make_store();

        store
            .put("/registry/pods/default/aaa", pod_json("aaa"), Some(0))
            .await
            .expect("create aaa");
        store
            .put("/registry/pods/default/bbb", pod_json("bbb"), Some(0))
            .await
            .expect("create bbb");
        store
            .put("/registry/pods/default/ccc", pod_json("ccc"), Some(0))
            .await
            .expect("create ccc");

        let resp = store
            .list(
                "/registry/pods/default/",
                ListOptions {
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .expect("list page 1");

        assert_eq!(
            resp.items.len(),
            2,
            "page 1 must return exactly limit items"
        );
        assert!(
            resp.continue_key.is_some(),
            "more items remain; continue_key must be set"
        );
    }

    #[tokio::test]
    async fn test_list_continue_returns_next_page() {
        // Using the continue_key from page 1 must return the next page starting after
        // the last item of page 1. If continue_key is ignored, the client gets duplicates.
        let store = make_store();

        store
            .put("/registry/pods/default/aaa", pod_json("aaa"), Some(0))
            .await
            .expect("create aaa");
        store
            .put("/registry/pods/default/bbb", pod_json("bbb"), Some(0))
            .await
            .expect("create bbb");
        store
            .put("/registry/pods/default/ccc", pod_json("ccc"), Some(0))
            .await
            .expect("create ccc");

        let page1 = store
            .list(
                "/registry/pods/default/",
                ListOptions {
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .expect("page 1");
        let ck = page1
            .continue_key
            .clone()
            .expect("must have continue_key after page 1");

        let page2 = store
            .list(
                "/registry/pods/default/",
                ListOptions {
                    limit: Some(2),
                    continue_key: Some(ck),
                    ..Default::default()
                },
            )
            .await
            .expect("page 2");

        assert_eq!(
            page2.items.len(),
            1,
            "page 2 must return the remaining 1 item"
        );
        assert!(
            page2.continue_key.is_none(),
            "no more items; last page must not have continue_key"
        );

        // Verify no overlap: page 2 must not contain any item from page 1.
        let page1_keys: std::collections::HashSet<&str> =
            page1.items.iter().map(|o| o.key.as_str()).collect();
        for item in &page2.items {
            assert!(
                !page1_keys.contains(item.key.as_str()),
                "page 2 must not repeat items from page 1"
            );
        }
    }

    #[tokio::test]
    async fn test_list_last_page_no_continue_key() {
        // When a single page covers all items exactly, continue_key must be absent.
        // If it were set, the next request would return an empty page, which some clients
        // treat as an error rather than end-of-list.
        let store = make_store();

        store
            .put("/registry/pods/default/aaa", pod_json("aaa"), Some(0))
            .await
            .expect("create aaa");
        store
            .put("/registry/pods/default/bbb", pod_json("bbb"), Some(0))
            .await
            .expect("create bbb");

        let resp = store
            .list(
                "/registry/pods/default/",
                ListOptions {
                    limit: Some(10),
                    ..Default::default()
                },
            )
            .await
            .expect("list with limit > total");

        assert_eq!(resp.items.len(), 2);
        assert!(
            resp.continue_key.is_none(),
            "all items fit in one page; continue_key must be absent"
        );
    }

    #[test]
    fn stamp_resource_version_returns_err_on_invalid_json() {
        // Regression test for mayor-n37: stamp_resource_version must return Err rather than
        // panicking when the stored value is not valid JSON. Before the fix this called
        // `.unwrap()` on serde_json::to_vec, but the real risk was the from_slice unwrap path
        // (the to_vec call on a serde_json::Value is infallible in practice). The test
        // covers the from_slice error path — if the fix is reverted, the function returns
        // an unwrap panic on a Result::Err rather than propagating StoreError::Serialization.
        let bad_bytes = Bytes::from_static(b"not valid json {{{");
        let result = stamp_resource_version(&bad_bytes, 42);
        assert!(
            result.is_err(),
            "stamp_resource_version must return Err on invalid JSON, not panic"
        );
        assert!(
            matches!(result.unwrap_err(), StoreError::Serialization(_)),
            "error variant must be StoreError::Serialization"
        );
    }

    // --- Watch fan-out and conditional delete tests (mayor-1lj2) ---

    #[tokio::test]
    async fn watch_fan_out_two_concurrent_watchers_both_receive_added() {
        // Two concurrent watchers on the same prefix must BOTH receive the ADDED event
        // when an object is written. Fan-out via the broadcast channel means each subscriber
        // gets its own copy. If the implementation is a single-consumer channel, the second
        // watcher silently misses events — a correctness bug for multi-controller deployments.
        use futures_core::Stream;
        use std::pin::Pin;

        let store = Arc::new(make_store());
        let key = "/registry/pods/default/fan-out-pod";

        // Subscribe both watchers BEFORE writing, so the event goes into the broadcast channel.
        let stream_a = store
            .watch("/registry/pods/default/", 0)
            .await
            .expect("watch A");
        let stream_b = store
            .watch("/registry/pods/default/", 0)
            .await
            .expect("watch B");
        let mut stream_a: Pin<Box<dyn Stream<Item = WatchEvent> + Send>> = Box::pin(stream_a);
        let mut stream_b: Pin<Box<dyn Stream<Item = WatchEvent> + Send>> = Box::pin(stream_b);

        let rv = store
            .put(key, pod_json("fan-out-pod"), Some(0))
            .await
            .expect("create");

        // Both streams must independently receive an ADDED event for the same revision.
        let ev_a = next_event(&mut stream_a)
            .await
            .expect("stream A must get event");
        assert!(
            matches!(&ev_a, WatchEvent::Added(obj) if obj.key == key && obj.revision == rv),
            "watcher A must receive ADDED for the written object, got {:?}",
            ev_a
        );

        let ev_b = next_event(&mut stream_b)
            .await
            .expect("stream B must get event");
        assert!(
            matches!(&ev_b, WatchEvent::Added(obj) if obj.key == key && obj.revision == rv),
            "watcher B must receive ADDED independently — fan-out failed, got {:?}",
            ev_b
        );
    }

    #[tokio::test]
    async fn conditional_delete_stale_rv_returns_revision_mismatch() {
        // delete(key, Some(stale_rv)) must return RevisionMismatch when the stored
        // revision has advanced past stale_rv. Without this check, any concurrent
        // controller could delete a newer version of an object, losing mutations.
        let store = make_store();
        let key = "/registry/pods/default/cond-del-pod";

        let rv1 = store
            .put(key, pod_json("cond-del-pod"), Some(0))
            .await
            .expect("create");

        // Advance the revision by updating the object so rv1 is now stale.
        let rv2 = store
            .put(key, pod_json("cond-del-pod"), Some(rv1))
            .await
            .expect("update");
        assert!(rv2 > rv1, "revision must advance after update");

        // Attempt to delete with the stale rv1 — must be rejected.
        let err = store
            .delete(key, Some(rv1))
            .await
            .expect_err("delete with stale rv must fail");
        assert!(
            matches!(
                err,
                StoreError::RevisionMismatch {
                    expected,
                    current
                } if expected == rv1 && current == rv2
            ),
            "expected RevisionMismatch {{expected: {rv1}, current: {rv2}}}, got {err:?}"
        );
    }

    #[tokio::test]
    async fn conditional_delete_correct_rv_succeeds() {
        // delete(key, Some(rv)) with the current revision must succeed and remove the object.
        // This verifies the happy path of optimistic concurrency for delete.
        let store = make_store();
        let key = "/registry/pods/default/cond-del-ok-pod";

        let rv = store
            .put(key, pod_json("cond-del-ok-pod"), Some(0))
            .await
            .expect("create");

        store
            .delete(key, Some(rv))
            .await
            .expect("delete with correct rv must succeed");

        // Object must be gone.
        let result = store.get(key).await.expect("get after delete");
        assert!(
            result.is_none(),
            "object must be absent after conditional delete"
        );
    }

    #[tokio::test]
    async fn list_revision_never_regresses_below_last_written() {
        // After a write at revision N, any subsequent list must return
        // metadata.resourceVersion >= N. The KCM informer cache records the highest
        // revision it has seen from watch events; if a relist returns a lower revision,
        // client-go aborts with "read version is not as new as written version".
        //
        // The guard: last_written_revision tracks the highest committed write revision.
        // If list_sync returns an older snapshot, list retries via the write connection.
        // Reverting the guard (removing the retry branch) would make this test pass
        // trivially for :memory: (shared conn), so the test also directly verifies
        // that last_written_revision is set on put/delete.
        let store = make_store();
        let key = "/registry/apps/replicasets/default/my-rs";

        let rs_json = Bytes::from(
            serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "metadata": { "name": "my-rs", "namespace": "default" }
            })
            .to_string(),
        );

        let rv = store
            .put(key, rs_json.clone(), Some(0))
            .await
            .expect("create ReplicaSet");

        // last_written_revision must be updated after put.
        let recorded = store.last_written_revision.load(Ordering::Acquire);
        assert_eq!(
            recorded, rv,
            "last_written_revision must equal the revision returned by put; \
             if last_written_revision is not updated, the stale-read guard cannot trigger"
        );

        // list must return revision >= rv.
        let resp = store
            .list("/registry/apps/replicasets/", ListOptions::default())
            .await
            .expect("list");
        assert!(
            resp.revision >= rv,
            "list must return resourceVersion >= last write revision ({rv}); \
             a regression here means the KCM informer cache would receive a stale \
             resourceVersion and abort with 'read version is not as new as written version'"
        );

        // Simulate the stale-WAL scenario: set last_written_revision higher than
        // what the read snapshot currently has, then verify list falls back to the
        // write connection (which returns the current state, so revision >= rv).
        let future_rv = rv + 9999;
        store
            .last_written_revision
            .store(future_rv, Ordering::Release);
        let resp2 = store
            .list("/registry/apps/replicasets/", ListOptions::default())
            .await
            .expect("list after simulated stale-WAL");
        // The write connection will return the actual latest revision (rv, not future_rv),
        // but it must be >= rv (the actual committed state).
        assert!(
            resp2.revision >= rv,
            "after stale-WAL simulation, list via write connection must return revision >= {rv}; \
             got {}",
            resp2.revision
        );
    }

    #[tokio::test]
    async fn list_by_namespace_uses_index() {
        // metadata.namespace field selector must return only objects in the requested namespace.
        // The query is pushed down to SQL using the idx_ns index on the ns column, avoiding
        // full-table scans and per-object JSON deserialization. If the SQL path is removed
        // and reverted to in-memory filtering, this test still passes for correctness but
        // the performance contract is broken.
        let store = make_store();

        store
            .put(
                "/registry/pods/ns-a/pod-1",
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": { "name": "pod-1", "namespace": "ns-a" },
                        "spec": { "containers": [] }
                    })
                    .to_string(),
                ),
                Some(0),
            )
            .await
            .expect("create pod-1 in ns-a");
        store
            .put(
                "/registry/pods/ns-a/pod-2",
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": { "name": "pod-2", "namespace": "ns-a" },
                        "spec": { "containers": [] }
                    })
                    .to_string(),
                ),
                Some(0),
            )
            .await
            .expect("create pod-2 in ns-a");
        store
            .put(
                "/registry/pods/ns-b/pod-3",
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": { "name": "pod-3", "namespace": "ns-b" },
                        "spec": { "containers": [] }
                    })
                    .to_string(),
                ),
                Some(0),
            )
            .await
            .expect("create pod-3 in ns-b");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "metadata.namespace".to_string(),
                value: "ns-a".to_string(),
                negated: false,
            }),
            ..Default::default()
        };
        let resp = store.list("/registry/pods/", opts).await.expect("list");

        assert_eq!(
            resp.items.len(),
            2,
            "metadata.namespace selector must return exactly the 2 pods in ns-a; \
             pod-3 in ns-b must be excluded"
        );
        let keys: Vec<&str> = resp.items.iter().map(|o| o.key.as_str()).collect();
        assert!(
            keys.contains(&"/registry/pods/ns-a/pod-1"),
            "pod-1 in ns-a must be included"
        );
        assert!(
            keys.contains(&"/registry/pods/ns-a/pod-2"),
            "pod-2 in ns-a must be included"
        );
        assert!(
            !keys.contains(&"/registry/pods/ns-b/pod-3"),
            "pod-3 in ns-b must be excluded by the namespace selector"
        );
    }

    #[tokio::test]
    async fn list_by_name_uses_index() {
        // metadata.name field selector must return only the object(s) with the matching name.
        // The query is pushed down to SQL using the idx_name index on the obj_name column.
        // Without the SQL index path, a full range scan + per-object JSON parse is required,
        // which is O(n) in the number of objects rather than O(log n).
        let store = make_store();

        store
            .put(
                "/registry/configmaps/default/alpha",
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": { "name": "alpha", "namespace": "default" },
                        "data": {}
                    })
                    .to_string(),
                ),
                Some(0),
            )
            .await
            .expect("create alpha configmap");
        store
            .put(
                "/registry/configmaps/default/beta",
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": { "name": "beta", "namespace": "default" },
                        "data": {}
                    })
                    .to_string(),
                ),
                Some(0),
            )
            .await
            .expect("create beta configmap");
        store
            .put(
                "/registry/configmaps/other/alpha",
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": { "name": "alpha", "namespace": "other" },
                        "data": {}
                    })
                    .to_string(),
                ),
                Some(0),
            )
            .await
            .expect("create alpha configmap in other namespace");

        let opts = ListOptions {
            field_selector: Some(FieldSelector {
                field: "metadata.name".to_string(),
                value: "alpha".to_string(),
                negated: false,
            }),
            ..Default::default()
        };
        let resp = store
            .list("/registry/configmaps/default/", opts)
            .await
            .expect("list");

        assert_eq!(
            resp.items.len(),
            1,
            "metadata.name selector scoped to /default/ prefix must return exactly 1 object; \
             beta and alpha-in-other-ns must be excluded"
        );
        assert_eq!(
            resp.items[0].key, "/registry/configmaps/default/alpha",
            "only the alpha configmap in the default namespace must be returned"
        );
    }

    #[test]
    fn explain_query_plan_shows_index_for_ns_and_name() {
        // Verifies that SQLite uses the composite idx_ns_name index for ns+name queries and
        // idx_name for name-only queries — neither must fall back to a full table scan.
        // SQLite uses at most one index per table per query; the composite index covers both
        // ns-only and ns+name cases. If idx_ns_name is replaced with separate indexes,
        // the ns+name query would use only one of them and lose selectivity.
        // This test fails if the indexes are dropped or the composite is split back into two.
        let store = SqliteStore::new(":memory:").expect("open in-memory db");
        let conn = store.write_conn.blocking_lock();

        // ns + obj_name query: must use the composite idx_ns_name index.
        let plan_ns_name: Vec<String> = {
            let mut stmt = conn
                .prepare(
                    "EXPLAIN QUERY PLAN \
                     SELECT key, value, revision FROM objects \
                     WHERE key >= '/registry/pods/' AND key < '/registry/pods0' \
                     AND ns = 'default' AND obj_name = 'nginx' \
                     ORDER BY key ASC",
                )
                .expect("prepare ns+name plan");
            stmt.query_map([], |r| r.get::<_, String>(3))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect()
        };

        let plan_ns_name_str = plan_ns_name.join(" ");
        assert!(
            plan_ns_name_str.to_lowercase().contains("idx_ns_name"),
            "EXPLAIN QUERY PLAN for ns+name must use idx_ns_name (composite index), got: {plan_ns_name_str}"
        );

        // name-only query (cluster-scoped): must use the idx_name index.
        let plan_name: Vec<String> = {
            let mut stmt = conn
                .prepare(
                    "EXPLAIN QUERY PLAN \
                     SELECT key, value, revision FROM objects \
                     WHERE key >= '/registry/pods/' AND key < '/registry/pods0' AND obj_name = 'nginx' \
                     ORDER BY key ASC",
                )
                .expect("prepare name plan");
            stmt.query_map([], |r| r.get::<_, String>(3))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect()
        };

        let plan_name_str = plan_name.join(" ");
        assert!(
            plan_name_str.to_lowercase().contains("search"),
            "EXPLAIN QUERY PLAN for obj_name= must show SEARCH (index usage), got: {plan_name_str}"
        );
    }

    #[tokio::test]
    async fn last_written_revision_updated_on_delete() {
        // delete must also update last_written_revision so that a list following
        // a delete never returns a revision below the delete's revision.
        let store = make_store();
        let key = "/registry/apps/replicasets/default/del-rs";

        let rs_json = Bytes::from(
            serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "metadata": { "name": "del-rs", "namespace": "default" }
            })
            .to_string(),
        );

        let put_rv = store.put(key, rs_json, Some(0)).await.expect("create");

        let del_rv = store.delete(key, Some(put_rv)).await.expect("delete");
        assert!(del_rv > put_rv, "delete must advance revision");

        let recorded = store.last_written_revision.load(Ordering::Acquire);
        assert_eq!(
            recorded, del_rv,
            "last_written_revision must be updated to the delete revision; \
             without this, a list after a delete could return a stale revision"
        );
    }

    /// Regression test for mayor-mwgk: last_written_revision must be updated inside the blocking
    /// thread (put_sync), not in the async caller, so it is visible before spawn_blocking resolves.
    ///
    /// Without this fix there was a multi-threaded race: put_sync could commit rv=N+1 to the WAL
    /// (making it visible to new read transactions) while a concurrent list on the read connection
    /// saw the new WAL data but the async caller had not yet executed fetch_max. The list guard
    /// would then read last_written_revision=N and conclude no retry was needed, returning the
    /// stale revision to the KCM reflector. The reflector logged
    /// "read version N is not as new as written version N+1" and waited up to 60s before
    /// retrying — long enough to cause conformance test timeouts.
    ///
    /// This test cannot reproduce the race itself (that requires a specific thread interleaving),
    /// but it verifies the structural property that makes the race impossible: after put() awaits,
    /// last_written_revision already equals the returned revision. With the old code the update
    /// happened AFTER the await returned (in the async frame), so a concurrent list could see
    /// the stale value. With the new code the update is inside spawn_blocking and therefore
    /// sequenced before the future resolves.
    #[tokio::test]
    async fn last_written_revision_set_before_put_await_returns() {
        let store = make_store();
        let key = "/registry/apps/replicasets/default/race-rs";

        let rs_json = Bytes::from(
            serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "metadata": { "name": "race-rs", "namespace": "default" }
            })
            .to_string(),
        );

        let rv = store.put(key, rs_json, Some(0)).await.expect("create");

        // last_written_revision must already equal rv at this point, not merely "eventually".
        // If fetch_max ran in async context (after await), a concurrent list executing its guard
        // check between the spawn_blocking completing and fetch_max running would see stale value.
        let recorded = store.last_written_revision.load(Ordering::Acquire);
        assert_eq!(
            recorded, rv,
            "last_written_revision must equal the put revision before put() returns — \
             if it lags behind (updated after spawn_blocking resolves in async context), \
             a concurrent list on the read connection can observe the new WAL data but \
             load a stale last_written_revision, bypassing the stale-read guard and \
             returning an older resourceVersion that causes the KCM reflector to log \
             'read version is not as new as written version'"
        );
    }

    /// Regression test for mayor-mwgk: last_written_revision must be set inside delete_sync.
    #[tokio::test]
    async fn last_written_revision_set_before_delete_await_returns() {
        let store = make_store();
        let key = "/registry/apps/replicasets/default/race-del-rs";

        let rs_json = Bytes::from(
            serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "metadata": { "name": "race-del-rs", "namespace": "default" }
            })
            .to_string(),
        );

        let put_rv = store.put(key, rs_json, Some(0)).await.expect("create");
        let del_rv = store.delete(key, Some(put_rv)).await.expect("delete");

        let recorded = store.last_written_revision.load(Ordering::Acquire);
        assert_eq!(
            recorded, del_rv,
            "last_written_revision must equal the delete revision before delete() returns; \
             same race risk as put: a concurrent list could bypass the stale-read guard"
        );
    }

    /// Regression test for mayor-bg80: a watch opened at rv=N must NOT replay the ADDED event
    /// for an object that was created at exactly revision N.
    ///
    /// The Kubernetes conformance test "should observe add, update, and delete watch notifications
    /// on configmaps" lists first (getting rv=N) then opens a watch at rv=N. If an object was
    /// created at rv=N and the watch replays it as ADDED, the test fails with
    /// "Unexpected watch notification observed: {ADDED &ConfigMap{...}}".
    ///
    /// This test FAILS if the ring buffer filter changes from `e.revision > from_revision`
    /// to `e.revision >= from_revision` — a "≥" would replay the create at revision N even
    /// though the watcher opened at rv=N (meaning "I already know about events up to N").
    #[tokio::test]
    async fn watch_from_rv_n_does_not_replay_object_created_at_rv_n() {
        let store = make_store();
        let prefix = "/registry/configmaps/default/";
        let key = "/registry/configmaps/default/kube-root-ca.crt";

        // Create the object. Its ADDED event goes into the ring buffer at revision N.
        let create_rv = store
            .put(key, pod_json("kube-root-ca.crt"), Some(0))
            .await
            .expect("create");

        // Open a watch at rv=create_rv. The Kubernetes protocol says:
        // "watch from after revision N — I already know about events up to N".
        // The ring buffer must NOT replay the ADDED event for the object just created.
        let stream = store
            .watch(prefix, create_rv)
            .await
            .expect("watch from create_rv");
        let mut stream: Pin<Box<dyn Stream<Item = WatchEvent> + Send>> = Box::pin(stream);

        // The stream must block waiting for new events — no immediate ADDED for the
        // pre-existing object. We use a short timeout; any event that arrives is a bug.
        let spurious = next_event(&mut stream).await;
        assert!(
            spurious.is_none(),
            "watch at rv=N must not replay the ADDED event for an object created at rv=N; \
             received spurious event: {:?}. \
             This breaks the conformance test 'should observe add, update, and delete watch \
             notifications on configmaps' which lists at rv=N then opens a watch at rv=N and \
             expects ONLY new events (mayor-bg80)",
            spurious
        );
    }

    /// Complementary to the above: an object created BEFORE the watch rv is correctly excluded,
    /// while a new object created AFTER the watch rv is correctly included as ADDED.
    ///
    /// This test verifies the boundary condition: the filter `e.revision > from_revision` is
    /// strict (>) not inclusive (>=), so from_revision=N excludes events at revision N.
    #[tokio::test]
    async fn watch_from_rv_n_sees_new_objects_created_after_rv_n() {
        let store = make_store();
        let prefix = "/registry/configmaps/default/";
        let pre_key = "/registry/configmaps/default/pre-existing";
        let new_key = "/registry/configmaps/default/new-object";

        // Create pre-existing object at rv=N.
        let create_rv = store
            .put(pre_key, pod_json("pre-existing"), Some(0))
            .await
            .expect("create pre-existing");

        // Open watch at rv=create_rv. Pre-existing object must NOT appear.
        let stream = store
            .watch(prefix, create_rv)
            .await
            .expect("watch from create_rv");
        let mut stream: Pin<Box<dyn Stream<Item = WatchEvent> + Send>> = Box::pin(stream);

        // Create a new object AFTER the watch is open.
        let new_rv = store
            .put(new_key, pod_json("new-object"), Some(0))
            .await
            .expect("create new object");

        // Only the new object's ADDED event (revision > create_rv) must appear.
        let ev = next_event(&mut stream)
            .await
            .expect("new object must emit ADDED");
        assert!(
            matches!(&ev, WatchEvent::Added(obj) if obj.key == new_key && obj.revision == new_rv),
            "watch at rv=N must receive ADDED for new object (rv={new_rv} > from_rv={create_rv}); \
             got: {:?}",
            ev
        );

        // No further events — pre-existing object's ADDED must not appear.
        let extra = next_event(&mut stream).await;
        assert!(
            extra.is_none(),
            "no extra events expected; pre-existing object ADDED must be filtered out; \
             got: {:?}",
            extra
        );
    }
}
