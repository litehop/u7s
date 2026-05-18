use bytes::Bytes;
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

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
        Self { key: format!("/registry/{}/{}/{}", resource, namespace, name) }
    }
}

/// Options for a list operation. Phase 1: only prefix is used.
#[derive(Debug, Default)]
pub struct ListOptions {
    // Reserved for Phase 2+ (label selectors, pagination).
}

/// Result of a list operation.
#[derive(Debug)]
pub struct ListResponse {
    pub items: Vec<StoreObject>,
    /// Global revision of the snapshot at which this list was consistent.
    pub revision: u64,
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
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub trait Store: Send + Sync + 'static {
    /// Get a single object by exact key. Returns None if not found.
    fn get(&self, key: &str) -> impl std::future::Future<Output = Result<Option<StoreObject>>> + Send;

    /// List all objects whose keys share the given prefix.
    /// Returns a consistent snapshot and the revision of that snapshot.
    fn list(&self, prefix: &str, opts: ListOptions) -> impl std::future::Future<Output = Result<ListResponse>> + Send;

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
    fn delete(&self, key: &str, expected_revision: Option<u64>) -> impl std::future::Future<Output = Result<u64>> + Send;
}

pub struct SqliteStore {
    /// Single write connection. Mutex ensures serial access across spawn_blocking calls.
    /// ALL rusqlite calls must go through spawn_blocking — rusqlite is synchronous.
    write_conn: Arc<Mutex<Connection>>,
    /// Read connection (WAL allows concurrent readers).
    /// For Phase 1 with one vCPU, a single read connection is sufficient.
    /// For :memory: databases, this is the same connection as write_conn.
    read_conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub fn new(db_path: &str) -> Result<Self> {
        let write_conn = open_conn(db_path)?;

        // Run migrations on the write connection.
        write_conn.execute_batch("
            CREATE TABLE IF NOT EXISTS objects (
                key      TEXT    NOT NULL PRIMARY KEY,
                value    BLOB    NOT NULL,
                revision INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');
        ")?;

        let write_conn = Arc::new(Mutex::new(write_conn));

        // For :memory: databases (tests), share the write connection for reads.
        // Separate in-memory connections are always distinct databases.
        // For file databases, open a second connection for concurrent reads under WAL.
        let read_conn = if db_path == ":memory:" {
            Arc::clone(&write_conn)
        } else {
            Arc::new(Mutex::new(open_conn(db_path)?))
        };

        Ok(Self {
            write_conn,
            read_conn,
        })
    }
}

fn open_conn(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous  = NORMAL;
        PRAGMA cache_size   = -8000;
        PRAGMA busy_timeout = 5000;
        PRAGMA wal_autocheckpoint = 1000;
    ")?;
    Ok(conn)
}

/// Stamps metadata.resourceVersion into the stored JSON.
/// Parses the JSON, sets the field, re-serializes.
fn stamp_resource_version(value: &Bytes, revision: u64) -> Result<Bytes> {
    let mut obj: serde_json::Value = serde_json::from_slice(value)
        .map_err(|e| StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))))?;
    obj["metadata"]["resourceVersion"] = serde_json::Value::String(revision.to_string());
    Ok(Bytes::from(serde_json::to_vec(&obj).unwrap()))
}

// Full write procedure — runs inside spawn_blocking.
fn put_sync(
    conn: &Connection,
    key: &str,
    value: Bytes,
    expected_revision: Option<u64>,
) -> Result<(u64, Bytes)> {
    // 1. Begin exclusive write transaction.
    conn.execute_batch("BEGIN IMMEDIATE")?;

    // 2. Read current stored revision for optimistic concurrency check.
    let stored: Option<u64> = conn.query_row(
        "SELECT revision FROM objects WHERE key = ?1",
        params![key],
        |r| r.get(0),
    ).optional()?;

    // 3. Optimistic concurrency check.
    match (stored, expected_revision) {
        (_, None) => {}                                                 // unconditional
        (None, Some(0)) => {}                                          // create-only, absent: OK
        (Some(_), Some(0)) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::AlreadyExists { key: key.to_string() });
        }
        (None, Some(exp)) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::RevisionMismatch { expected: exp, current: 0 });
        }
        (Some(stored_rv), Some(exp)) if stored_rv == exp => {}        // match: OK
        (Some(stored_rv), Some(exp)) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::RevisionMismatch { expected: exp, current: stored_rv });
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
        |r| r.get(0),
    )?;

    // 6. Stamp metadata.resourceVersion in the JSON value.
    let stamped_value = stamp_resource_version(&value, new_revision)?;

    // 7. Upsert the object.
    conn.execute(
        "INSERT INTO objects (key, value, revision) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, revision = excluded.revision",
        params![key, stamped_value.as_ref(), new_revision],
    )?;

    conn.execute_batch("COMMIT")?;
    Ok((new_revision, stamped_value))
}

fn delete_sync(
    conn: &Connection,
    key: &str,
    expected_revision: Option<u64>,
) -> Result<u64> {
    conn.execute_batch("BEGIN IMMEDIATE")?;

    let stored: Option<u64> = conn.query_row(
        "SELECT revision FROM objects WHERE key = ?1",
        params![key],
        |r| r.get(0),
    ).optional()?;

    // Optimistic concurrency check (same logic as put).
    match (stored, expected_revision) {
        (None, _) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::NotFound { key: key.to_string() });
        }
        (Some(_), None) => {}
        (Some(_), Some(0)) => {} // 0 means "must exist" for delete (unconditional)
        (Some(stored_rv), Some(exp)) if stored_rv == exp => {}
        (Some(stored_rv), Some(exp)) => {
            conn.execute_batch("ROLLBACK")?;
            return Err(StoreError::RevisionMismatch { expected: exp, current: stored_rv });
        }
    }

    conn.execute(
        "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'revision'",
        [],
    )?;
    let new_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get(0),
    )?;

    conn.execute("DELETE FROM objects WHERE key = ?1", params![key])?;
    conn.execute_batch("COMMIT")?;
    Ok(new_revision)
}

fn get_sync(conn: &Connection, key: &str) -> Result<Option<StoreObject>> {
    let result = conn.query_row(
        "SELECT key, value, revision FROM objects WHERE key = ?1",
        params![key],
        |r| {
            Ok(StoreObject {
                key:      r.get::<_, String>(0)?,
                value:    Bytes::from(r.get::<_, Vec<u8>>(1)?),
                revision: r.get::<_, u64>(2)?,
            })
        },
    ).optional()?;
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

fn list_sync(conn: &Connection, prefix: &str) -> Result<ListResponse> {
    conn.execute_batch("BEGIN DEFERRED")?;

    let upper = prefix_upper_bound(prefix);

    let items: Vec<StoreObject> = if upper.is_empty() {
        let mut stmt = conn.prepare("SELECT key, value, revision FROM objects WHERE key >= ?1 ORDER BY key ASC")?;
        let rows = stmt.query_map(params![prefix], |r| {
            Ok(StoreObject {
                key:      r.get(0)?,
                value:    Bytes::from(r.get::<_, Vec<u8>>(1)?),
                revision: r.get(2)?,
            })
        })?.collect::<rusqlite::Result<_>>()?;
        rows
    } else {
        let mut stmt = conn.prepare("SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 ORDER BY key ASC")?;
        let rows = stmt.query_map(params![prefix, upper], |r| {
            Ok(StoreObject {
                key:      r.get(0)?,
                value:    Bytes::from(r.get::<_, Vec<u8>>(1)?),
                revision: r.get(2)?,
            })
        })?.collect::<rusqlite::Result<_>>()?;
        rows
    };

    let snapshot_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get(0),
    )?;

    conn.execute_batch("COMMIT")?;

    Ok(ListResponse { items, revision: snapshot_revision })
}

impl Store for SqliteStore {
    async fn get(&self, key: &str) -> Result<Option<StoreObject>> {
        let conn = self.read_conn.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            get_sync(&conn, &key)
        }).await?
    }

    async fn list(&self, prefix: &str, _opts: ListOptions) -> Result<ListResponse> {
        let conn = self.read_conn.clone();
        let prefix = prefix.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            list_sync(&conn, &prefix)
        }).await?
    }

    async fn put(&self, key: &str, value: Bytes, expected_revision: Option<u64>) -> Result<u64> {
        let conn = self.write_conn.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let (revision, _stamped) = put_sync(&conn, &key, value, expected_revision)?;
            Ok::<_, StoreError>(revision)
        }).await?
    }

    async fn delete(&self, key: &str, expected_revision: Option<u64>) -> Result<u64> {
        let conn = self.write_conn.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            delete_sync(&conn, &key, expected_revision)
        }).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> SqliteStore {
        SqliteStore::new(":memory:").expect("open in-memory db")
    }

    fn pod_json(name: &str) -> Bytes {
        Bytes::from(serde_json::json!({
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
        }).to_string())
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let store = make_store();
        let key = "/registry/pods/default/nginx";
        let value = pod_json("nginx");

        let rv = store.put(key, value.clone(), Some(0)).await.expect("create");
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

        store.put(key, value.clone(), Some(0)).await.expect("first create");

        let err = store.put(key, value, Some(0)).await.expect_err("should fail");
        assert!(matches!(err, StoreError::AlreadyExists { .. }));
    }

    #[tokio::test]
    async fn test_optimistic_concurrency_mismatch() {
        let store = make_store();
        let key = "/registry/pods/default/nginx";
        let value = pod_json("nginx");

        let rv1 = store.put(key, value.clone(), Some(0)).await.expect("create");

        // Advance the revision by doing a replace
        let rv2 = store.put(key, value.clone(), Some(rv1)).await.expect("first replace");
        assert!(rv2 > rv1);

        // Now try to replace with the stale rv1
        let err = store.put(key, value, Some(rv1)).await.expect_err("should conflict");
        assert!(matches!(err, StoreError::RevisionMismatch { expected, current } if expected == rv1 && current == rv2));
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

        store.put("/registry/pods/default/alpha", pod_json("alpha"), Some(0)).await.expect("create alpha");
        store.put("/registry/pods/default/beta", pod_json("beta"), Some(0)).await.expect("create beta");
        store.put("/registry/pods/other/gamma", pod_json("gamma"), Some(0)).await.expect("create gamma");

        let resp = store.list("/registry/pods/default/", ListOptions::default()).await.expect("list");
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
        let resp = store.list("/registry/pods/default/", ListOptions::default()).await.expect("list");
        assert_eq!(resp.items.len(), 0);
        assert_eq!(resp.revision, 0);
    }

    #[tokio::test]
    async fn test_unconditional_put() {
        let store = make_store();
        let key = "/registry/pods/default/nginx";
        let value = pod_json("nginx");

        // Unconditional create
        let rv1 = store.put(key, value.clone(), None).await.expect("unconditional create");
        assert!(rv1 > 0);

        // Unconditional overwrite
        let rv2 = store.put(key, value, None).await.expect("unconditional overwrite");
        assert!(rv2 > rv1);
    }
}
