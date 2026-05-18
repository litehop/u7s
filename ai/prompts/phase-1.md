# Phase 1 Implementation Prompt — u7s

**Status:** Implementation-ready. Last updated: 2026-05-18.
**Audience:** A senior Rust engineer building Phase 1 from scratch. This document is self-contained — you do not need to read any other spec to implement Phase 1.

---

## 1. What Phase 1 Delivers

At the end of Phase 1, a human operator can run `kubectl get pods` (returns an empty list), `kubectl create -f pod.yaml` (stores the pod and returns it with a `resourceVersion`), `kubectl get pod <name>` (retrieves it), and `kubectl delete pod <name>` (removes it). Pods must have `spec.nodeName` set explicitly in the manifest — there is no scheduler in Phase 1. The operator can also use `kubectl replace` to update a stored pod. **`kubectl apply` does not work in Phase 1**: `apply` uses strategic merge patch, which is not implemented until Phase 3; the server will return a 415 or 400 for that content type. There is no watch support, no controllers, no scheduler, no RBAC enforcement (all requests are accepted), no CRDs, and no admission. Only the `default` namespace is supported — namespace as a first-class resource, service accounts, and cross-namespace operations are out of scope. The idle RSS target is under 30 MB.

---

## 2. Cargo Workspace Layout

```
u7s/
  Cargo.toml          (workspace manifest)
  crates/
    store/            (lib crate: Store trait + SqliteStore)
    apiserver/        (bin crate: axum HTTPS server)
```

### Root `Cargo.toml`

```toml
[workspace]
members = ["crates/store", "crates/apiserver"]
resolver = "2"
```

### `crates/store/Cargo.toml`

```toml
[package]
name    = "u7s-store"
version = "0.1.0"
edition = "2021"

[dependencies]
rusqlite        = { version = "0.32", features = ["bundled"] }
tokio           = { version = "1", features = ["full"] }
bytes           = "1"
serde           = { version = "1", features = ["derive"] }
serde_json      = "1"
thiserror       = "1"
tracing         = "0.1"
```

### `crates/apiserver/Cargo.toml`

```toml
[package]
name    = "u7s-apiserver"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "u7s-apiserver"
path = "src/main.rs"

[dependencies]
u7s-store       = { path = "../store" }
axum            = "0.8"
tower           = "0.5"
hyper           = { version = "1", features = ["http1"] }
tokio           = { version = "1", features = ["full"] }
rustls          = "0.23"
tokio-rustls    = "0.26"
rcgen           = "0.13"
rustls-pemfile  = "2"
serde           = { version = "1", features = ["derive"] }
serde_json      = "1"
bytes           = "1"
thiserror       = "1"
tracing         = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
base64          = "0.22"
```

---

## 3. Store Crate

### 3.1 Public Types

```rust
// crates/store/src/lib.rs

use bytes::Bytes;
use thiserror::Error;

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
```

### 3.2 Store Trait

Phase 1 includes only these four methods. `watch` is Phase 2+.

```rust
pub trait Store: Send + Sync + 'static {
    /// Get a single object by exact key. Returns None if not found.
    async fn get(&self, key: &str) -> Result<Option<StoreObject>>;

    /// List all objects whose keys share the given prefix.
    /// Returns a consistent snapshot and the revision of that snapshot.
    async fn list(&self, prefix: &str, opts: ListOptions) -> Result<ListResponse>;

    /// Write an object with optimistic concurrency control.
    ///
    /// `expected_revision` semantics:
    ///   None       → unconditional write (create or overwrite)
    ///   Some(0)    → create-only: key must not exist → AlreadyExists if it does
    ///   Some(rv)   → update-only: stored revision must equal rv → RevisionMismatch if not
    ///
    /// Returns the new global revision on success.
    /// The store stamps `metadata.resourceVersion` in the stored value before persisting.
    async fn put(
        &self,
        key: &str,
        value: Bytes,
        expected_revision: Option<u64>,
    ) -> Result<u64>;

    /// Delete an object. Same optimistic concurrency semantics as put.
    /// Returns the new global revision on success (the deletion revision).
    async fn delete(&self, key: &str, expected_revision: Option<u64>) -> Result<u64>;
}
```

### 3.3 SqliteStore

#### Schema DDL

```sql
-- Live objects. Key is the full /registry/... path.
-- WITHOUT ROWID: stores rows in a B-tree keyed directly by `key`.
-- Enables O(log n) prefix scans without a secondary index.
-- FOOTGUN: WITHOUT ROWID tables do not support last_insert_rowid().
--   The revision counter MUST come from the `meta` table, not autoincrement.
CREATE TABLE IF NOT EXISTS objects (
    key      TEXT    NOT NULL PRIMARY KEY,
    value    BLOB    NOT NULL,
    revision INTEGER NOT NULL
) WITHOUT ROWID;

-- Single-row table holding the global revision counter.
-- Seeded to 0 on first open.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');
```

#### WAL Pragmas

Apply immediately after opening every connection:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA cache_size   = -8000;
PRAGMA busy_timeout = 5000;
PRAGMA wal_autocheckpoint = 1000;
```

`journal_mode=WAL` allows N concurrent readers and 1 writer without blocking. `synchronous=NORMAL` skips per-commit fsync (fsync only at checkpoint), reducing write latency 2–10x with acceptable durability. `cache_size=-8000` sets an 8 MB page cache (negative value = kibibytes). `busy_timeout=5000` makes SQLite spin for up to 5 s before returning SQLITE_BUSY — eliminates manual retry loops. `wal_autocheckpoint=1000` caps WAL growth at ~4 MB before auto-checkpoint.

#### SqliteStore Struct and Constructor

```rust
use rusqlite::{Connection, params};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct SqliteStore {
    /// Single write connection. Mutex ensures serial access across spawn_blocking calls.
    /// ALL rusqlite calls must go through spawn_blocking — rusqlite is synchronous.
    write_conn: Arc<Mutex<Connection>>,
    /// Read connection (WAL allows concurrent readers).
    /// For Phase 1 with one vCPU, a single read connection is sufficient.
    read_conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub fn new(db_path: &str) -> Result<Self> {
        let write_conn = open_conn(db_path)?;
        let read_conn  = open_conn(db_path)?;

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

        Ok(Self {
            write_conn: Arc::new(Mutex::new(write_conn)),
            read_conn:  Arc::new(Mutex::new(read_conn)),
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
```

#### spawn_blocking Boundary

**Every rusqlite call must be wrapped in `tokio::task::spawn_blocking`.** rusqlite is synchronous blocking I/O. Calling it directly from an async context will stall the tokio executor. The pattern:

```rust
let conn = self.write_conn.clone();
let result = tokio::task::spawn_blocking(move || {
    let conn = conn.blocking_lock();
    // ... rusqlite operations ...
    Ok::<_, StoreError>(value)
}).await??;
```

Note the double `?` — the outer one unwraps `JoinError`, the inner one unwraps `StoreError`.

#### put Implementation

The `put` method stamps `metadata.resourceVersion` into the JSON before storing it. This means callers receive a `StoreObject` (or the new revision) and can reconstruct the stamped object.

```rust
// Full write procedure — runs inside spawn_blocking.
fn put_sync(
    conn: &Connection,
    key: &str,
    mut value: Bytes,
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

/// Stamps metadata.resourceVersion into the stored JSON.
/// Parses the JSON, sets the field, re-serializes.
fn stamp_resource_version(value: &Bytes, revision: u64) -> Result<Bytes> {
    let mut obj: serde_json::Value = serde_json::from_slice(value)
        .map_err(|e| StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))))?;
    obj["metadata"]["resourceVersion"] = serde_json::Value::String(revision.to_string());
    Ok(Bytes::from(serde_json::to_vec(&obj).unwrap()))
}
```

**Why `BEGIN IMMEDIATE`:** Acquires the write lock before reading. Prevents a TOCTOU race where another writer increments the revision between the CAS read and the write — even though SQLite allows only one writer at a time in WAL mode, `BEGIN DEFERRED` could upgrade from read to write and deadlock. `IMMEDIATE` avoids this.

#### delete Implementation

```rust
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
```

#### get Implementation

```rust
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
```

#### list Implementation

The list uses a range scan (not `LIKE`) to leverage the B-tree index on the `WITHOUT ROWID` table. The snapshot revision is read in the same transaction.

```rust
fn list_sync(conn: &Connection, prefix: &str) -> Result<ListResponse> {
    conn.execute_batch("BEGIN DEFERRED")?;

    let upper = prefix_upper_bound(prefix);

    let mut stmt = if upper.is_empty() {
        conn.prepare("SELECT key, value, revision FROM objects WHERE key >= ?1 ORDER BY key ASC")?
    } else {
        conn.prepare("SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 ORDER BY key ASC")?
    };

    let items: Vec<StoreObject> = if upper.is_empty() {
        stmt.query_map(params![prefix], |r| {
            Ok(StoreObject {
                key:      r.get(0)?,
                value:    Bytes::from(r.get::<_, Vec<u8>>(1)?),
                revision: r.get(2)?,
            })
        })?.collect::<rusqlite::Result<_>>()?
    } else {
        stmt.query_map(params![prefix, upper], |r| {
            Ok(StoreObject {
                key:      r.get(0)?,
                value:    Bytes::from(r.get::<_, Vec<u8>>(1)?),
                revision: r.get(2)?,
            })
        })?.collect::<rusqlite::Result<_>>()?
    };

    let snapshot_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get(0),
    )?;

    conn.execute_batch("COMMIT")?;

    Ok(ListResponse { items, revision: snapshot_revision })
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
```

**Why range bounds instead of LIKE:** `LIKE '/registry/pods/%'` forces a full table scan. The range `key >= ?1 AND key < ?2` uses the B-tree primary key directly (O(log n) seek + forward scan) — correct for a `WITHOUT ROWID` table.

---

## 4. API Server Crate

### 4.1 main.rs — Startup Sequence

```rust
// crates/apiserver/src/main.rs

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    // 1. Parse CLI args.
    let args = Args::parse();
    //    --db <path>           SQLite database path (default: ./state.db)
    //    --listen <addr>       Listen address (default: 0.0.0.0:6443)
    //    --kubeconfig <path>   Where to write the kubeconfig (default: ./kubeconfig.yaml)

    // 2. Init tracing.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // 3. Open store.
    let store = Arc::new(SqliteStore::new(&args.db)?);

    // 4. Generate TLS certs (writes nothing if certs already exist at --data-dir).
    let tls_material = generate_tls(&args)?;

    // 5. Write kubeconfig.
    write_kubeconfig(&args.kubeconfig, &tls_material)?;

    // 6. Build axum router.
    let app = build_router(Arc::clone(&store));

    // 7. Bind TLS listener and serve.
    let listener = TcpListener::bind(&args.listen).await?;
    serve_tls(listener, app, tls_material.server_config).await?;
    Ok(())
}
```

**Argument struct (using `clap`):**

```rust
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "./state.db")]
    db: String,

    #[arg(long, default_value = "0.0.0.0:6443")]
    listen: String,

    #[arg(long, default_value = "./kubeconfig.yaml")]
    kubeconfig: String,
}
```

Add `clap = { version = "4", features = ["derive"] }` to apiserver dependencies.

### 4.2 TLS Setup

Generate a self-signed CA and a server cert signed by that CA using `rcgen`. This runs once on startup; if the certs are already present (embedded in the TlsMaterial struct for simplicity in Phase 1 — no disk persistence required), they are regenerated fresh on each start. Fresh-each-start is fine for Phase 1 because there is only one admin user and the kubeconfig is rewritten on each start.

```rust
use rcgen::{CertificateParams, DistinguishedName, IsCa, BasicConstraints, KeyPair, SanType};
use rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer}};
use tokio_rustls::TlsAcceptor;

pub struct TlsMaterial {
    /// DER-encoded CA certificate (written into kubeconfig).
    pub ca_cert_der: Vec<u8>,
    /// DER-encoded admin client certificate (written into kubeconfig).
    pub admin_cert_der: Vec<u8>,
    /// PEM-encoded admin private key (written into kubeconfig).
    pub admin_key_pem: Vec<u8>,
    /// Configured rustls ServerConfig for the axum server.
    pub server_config: Arc<ServerConfig>,
}

pub fn generate_tls(args: &Args) -> anyhow::Result<TlsMaterial> {
    // --- CA ---
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName, "u7s-ca",
    );
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // --- Server cert ---
    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::default();
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];
    server_params.distinguished_name.push(
        rcgen::DnType::CommonName, "u7s-apiserver",
    );
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    // --- Admin client cert ---
    let admin_key = KeyPair::generate()?;
    let mut admin_params = CertificateParams::default();
    admin_params.distinguished_name.push(rcgen::DnType::CommonName, "admin");
    // O=system:masters bypasses RBAC (Phase 3+). Harmless in Phase 1 (no RBAC).
    admin_params.distinguished_name.push(rcgen::DnType::OrganizationName, "system:masters");
    let admin_cert = admin_params.signed_by(&admin_key, &ca_cert, &ca_key)?;

    // --- Build rustls ServerConfig ---
    let server_cert_chain = vec![CertificateDer::from(server_cert.der().to_vec())];
    let server_key_der = PrivateKeyDer::try_from(server_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("key error: {e}"))?;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(server_cert_chain, server_key_der)?;

    Ok(TlsMaterial {
        ca_cert_der:    ca_cert.der().to_vec(),
        admin_cert_der: admin_cert.der().to_vec(),
        admin_key_pem:  admin_key.serialize_pem().into_bytes(),
        server_config:  Arc::new(server_config),
    })
}
```

### 4.3 Kubeconfig Structure

```rust
pub fn write_kubeconfig(path: &str, tls: &TlsMaterial) -> anyhow::Result<()> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let ca_data    = b64.encode(&tls.ca_cert_der);
    let cert_data  = b64.encode(&tls.admin_cert_der);
    let key_data   = b64.encode(&tls.admin_key_pem);

    let kubeconfig = format!(r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: {ca_data}
  name: u7s
contexts:
- context:
    cluster: u7s
    user: admin
  name: u7s
current-context: u7s
users:
- name: admin
  user:
    client-certificate-data: {cert_data}
    client-key-data: {key_data}
"#);

    std::fs::write(path, kubeconfig)?;
    tracing::info!("kubeconfig written to {path}");
    Ok(())
}
```

### 4.4 TLS Listener

```rust
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use axum::Router;

pub async fn serve_tls(
    listener: TcpListener,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    tracing::info!("listening on {}", listener.local_addr()?);

    loop {
        let (tcp_stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => { tracing::warn!("TLS accept error: {e}"); return; }
            };
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(move |req| {
                let app = app.clone();
                async move { Ok::<_, std::convert::Infallible>(app.call(req).await.unwrap()) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!("connection error: {e}");
            }
        });
    }
}
```

Add `hyper-util = "0.1"` to apiserver dependencies.

### 4.5 AppState

```rust
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<SqliteStore>,
}
```

### 4.6 Router — Exact Route Table

Phase 1 serves pods only. All routes are hardcoded (no dynamic dispatch needed). `?watch=true` returns 400.

```rust
use axum::{Router, routing::{get, post, put, delete, patch}};

pub fn build_router(store: Arc<SqliteStore>) -> Router {
    let state = AppState { store };

    Router::new()
        // Discovery
        .route("/api",                                              get(handlers::discovery::api_versions))
        .route("/api/v1",                                          get(handlers::discovery::api_v1_resources))

        // Pods — collection
        .route("/api/v1/namespaces/:ns/pods",
            get(handlers::pods::list_pods)
            .post(handlers::pods::create_pod))

        // Pods — named resource
        .route("/api/v1/namespaces/:ns/pods/:name",
            get(handlers::pods::get_pod)
            .put(handlers::pods::replace_pod)
            .delete(handlers::pods::delete_pod)
            .patch(handlers::pods::patch_pod))

        .with_state(state)
}
```

### 4.7 Object Type

```rust
// crates/apiserver/src/types.rs

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every Kubernetes object in memory.
/// Body is kept as a serde_json::Value for cheap pass-through.
/// Accessors parse individual fields on demand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    #[serde(flatten)]
    pub body: Value,
}

impl Object {
    pub fn name(&self) -> Option<&str> {
        self.body["metadata"]["name"].as_str()
    }

    pub fn namespace(&self) -> Option<&str> {
        self.body["metadata"]["namespace"].as_str()
    }

    pub fn resource_version(&self) -> Option<&str> {
        self.body["metadata"]["resourceVersion"].as_str()
    }

    pub fn resource_version_u64(&self) -> Option<u64> {
        self.resource_version()?.parse().ok()
    }

    pub fn set_resource_version(&mut self, rv: u64) {
        self.body["metadata"]["resourceVersion"] = Value::String(rv.to_string());
    }

    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(serde_json::to_vec(&self.body).unwrap())
    }

    pub fn from_bytes(bytes: &Bytes) -> Result<Self, serde_json::Error> {
        let body: Value = serde_json::from_slice(bytes)?;
        Ok(Self { body })
    }
}
```

### 4.8 ObjectKey Derivation

```rust
// crates/apiserver/src/keys.rs

/// Derives the store key for a namespace-scoped resource.
/// group="" for core/v1.
pub fn object_key(resource: &str, namespace: &str, name: &str) -> String {
    format!("/registry/{}/{}/{}", resource, namespace, name)
}

/// Derives the list prefix for a namespace-scoped resource.
pub fn list_prefix(resource: &str, namespace: &str) -> String {
    format!("/registry/{}/{}/", resource, namespace)
}
```

Phase 1 hardcodes `resource="pods"` and validates that `namespace="default"` (return 400 for other namespaces — hardcoding `default` is the explicit Phase 1 limitation).

### 4.9 Status Error Type

```rust
// crates/apiserver/src/status.rs

use axum::{http::StatusCode, response::{IntoResponse, Response}};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub kind:        &'static str,
    pub api_version: &'static str,
    pub status:      &'static str,
    pub message:     String,
    pub reason:      &'static str,
    pub code:        u16,
}

pub struct StatusError(pub StatusCode, pub Status);

impl IntoResponse for StatusError {
    fn into_response(self) -> Response {
        (self.0, axum::Json(self.1)).into_response()
    }
}

impl Status {
    pub fn not_found(name: &str, kind: &str) -> StatusError {
        StatusError(
            StatusCode::NOT_FOUND,
            Status {
                kind: "Status", api_version: "v1", status: "Failure",
                message: format!("{kind} \"{name}\" not found"),
                reason: "NotFound", code: 404,
            },
        )
    }

    pub fn already_exists(name: &str, kind: &str) -> StatusError {
        StatusError(
            StatusCode::CONFLICT,
            Status {
                kind: "Status", api_version: "v1", status: "Failure",
                message: format!("{kind} \"{name}\" already exists"),
                reason: "AlreadyExists", code: 409,
            },
        )
    }

    pub fn conflict(message: String) -> StatusError {
        StatusError(
            StatusCode::CONFLICT,
            Status {
                kind: "Status", api_version: "v1", status: "Failure",
                message,
                reason: "Conflict", code: 409,
            },
        )
    }

    pub fn bad_request(message: String) -> StatusError {
        StatusError(
            StatusCode::BAD_REQUEST,
            Status {
                kind: "Status", api_version: "v1", status: "Failure",
                message,
                reason: "BadRequest", code: 400,
            },
        )
    }

    pub fn internal(message: String) -> StatusError {
        StatusError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Status {
                kind: "Status", api_version: "v1", status: "Failure",
                message,
                reason: "InternalError", code: 500,
            },
        )
    }
}
```

### 4.10 Handler Specs

All handlers have signature:

```rust
async fn handler_name(
    State(state): State<AppState>,
    Path(params): Path<Params>,
    // Query / Json extractor as needed
) -> Result<impl IntoResponse, StatusError>
```

#### Watch Guard

Every GET handler on a collection must reject watch requests:

```rust
#[derive(Deserialize)]
pub struct CollectionQuery {
    pub watch: Option<bool>,
}

// At the top of list_pods:
if query.watch == Some(true) {
    return Err(Status::bad_request("watch is not supported in Phase 1".into()));
}
```

#### `GET /api/v1/namespaces/:ns/pods` — List Pods

1. Reject `?watch=true` → 400.
2. Validate `ns == "default"` → 400 otherwise.
3. Call `store.list("/registry/pods/default/", ListOptions::default())`.
4. Deserialize each `StoreObject.value` as `Object`.
5. Return a `PodList`:

```json
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": { "resourceVersion": "<snapshot_revision>" },
  "items": [ ... ]
}
```

The `metadata.resourceVersion` on the list is the snapshot revision from `ListResponse.revision`.

#### `POST /api/v1/namespaces/:ns/pods` — Create Pod

1. Validate `ns == "default"` → 400.
2. Parse body as `Object`.
3. Validate `obj.name()` is present and non-empty → 400.
4. Validate `obj.namespace()` matches `:ns` (or set it if absent).
5. Ensure `metadata.namespace` is set to `"default"` in the stored object.
6. Call `store.put(key, obj.to_bytes(), Some(0))` (create-only).
   - `AlreadyExists` → 409 via `Status::already_exists`.
7. Retrieve the stored object (the store stamped `resourceVersion` into it).
8. Return 201 with the stored object body.

The store's `put` stamps `resourceVersion` into the JSON before persisting. The API server must re-read the stored bytes (or reconstruct the object with the returned revision) to serve the correct `resourceVersion` in the response.

Simple approach: after `store.put` returns `new_revision`, call `obj.set_resource_version(new_revision)` and return `obj`.

#### `GET /api/v1/namespaces/:ns/pods/:name` — Get Pod

1. Validate `ns == "default"` → 400.
2. Call `store.get(&object_key("pods", ns, name))`.
3. `None` → 404 via `Status::not_found`.
4. Return 200 with the stored `value` bytes as the response body (already has `resourceVersion` stamped).

**Performance note:** Serve `value` bytes directly without deserialization when possible. Use `axum::response::Response::builder()` with `Content-Type: application/json`.

#### `PUT /api/v1/namespaces/:ns/pods/:name` — Replace Pod

1. Validate `ns == "default"` → 400.
2. Parse body as `Object`.
3. Validate `obj.name()` == `:name` → 400 if mismatch.
4. Extract `expected_revision`:
   - If `obj.resource_version()` is `None` or `""` → `None` (unconditional — not recommended but allowed).
   - If `"0"` → `Some(0)`.
   - Otherwise parse as `u64` → `Some(rv)`.
5. Call `store.put(key, obj.to_bytes(), expected_revision)`.
   - `RevisionMismatch` → 409 via `Status::conflict`.
   - `AlreadyExists` → 409 via `Status::already_exists`.
6. Set `resourceVersion` on returned object to the new revision.
7. Return 200 with the updated object.

#### `DELETE /api/v1/namespaces/:ns/pods/:name` — Delete Pod

1. Validate `ns == "default"` → 400.
2. Optionally: parse body for `resourceVersion` (kubectl delete does not send one; treat as unconditional).
3. Call `store.delete(&object_key("pods", ns, name), None)`.
   - `NotFound` → 404 via `Status::not_found`.
4. Return 200 with a Status object:

```json
{
  "kind": "Status",
  "apiVersion": "v1",
  "status": "Success",
  "code": 200
}
```

#### `PATCH /api/v1/namespaces/:ns/pods/:name` — JSON Merge Patch

Phase 1 supports **JSON merge patch only** (`Content-Type: application/merge-patch+json`).

1. Check `Content-Type` header:
   - `application/merge-patch+json` → proceed.
   - `application/strategic-merge-patch+json` → 400 with message "strategic merge patch not supported in Phase 1; use kubectl replace instead of kubectl apply".
   - Anything else → 415 Unsupported Media Type.
2. Validate `ns == "default"` → 400.
3. Load the current stored object via `store.get`.
   - `None` → 404.
4. Parse body as `serde_json::Value` (the patch).
5. Apply JSON merge patch to the current object body:

```rust
fn json_merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (Some(t), Some(p)) = (target.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            if v.is_null() {
                t.remove(k);
            } else if v.is_object() {
                let entry = t.entry(k).or_insert(serde_json::Value::Object(Default::default()));
                json_merge_patch(entry, v);
            } else {
                t.insert(k.clone(), v.clone());
            }
        }
    } else {
        *target = patch.clone();
    }
}
```

6. Extract `expected_revision` from the patched object's `metadata.resourceVersion` (optimistic concurrency — same logic as PUT).
7. Store the patched object with `store.put(key, patched_bytes, expected_revision)`.
   - `RevisionMismatch` → 409.
8. Return 200 with the stored object.

### 4.11 Discovery Handlers

These return hardcoded JSON. Phase 1 serves only pods.

#### `GET /api` — APIVersions

```rust
pub async fn api_versions() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "kind": "APIVersions",
        "apiVersion": "v1",
        "versions": ["v1"],
        "serverAddressByClientCIDRs": [
            { "clientCIDR": "0.0.0.0/0", "serverAddress": "https://127.0.0.1:6443" }
        ]
    }))
}
```

#### `GET /api/v1` — APIResourceList

```rust
pub async fn api_v1_resources() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "v1",
        "resources": [
            {
                "name": "pods",
                "singularName": "pod",
                "namespaced": true,
                "kind": "Pod",
                "verbs": ["create", "delete", "get", "list", "patch", "update"],
                "shortNames": ["po"]
            }
        ]
    }))
}
```

kubectl reads `GET /api` to discover that `v1` exists, then `GET /api/v1` to find pod endpoints. These two responses are sufficient for `kubectl get pods` and `kubectl create/get/delete pod` to work.

---

## 5. Resource Version in API Responses

### Flow

**On create (POST):**
1. Handler calls `store.put(key, value_bytes, Some(0))`.
2. Inside `put_sync`, the store increments the global counter and stamps `metadata.resourceVersion = new_revision` into the JSON before persisting.
3. Handler receives `new_revision` from `store.put`.
4. Handler calls `obj.set_resource_version(new_revision)` and returns the object.
5. The returned object has `metadata.resourceVersion` set. kubectl sees it.

**On replace (PUT):**
- Same as create. The handler passes the client's `resourceVersion` as `expected_revision`. If it matches the stored revision, the write proceeds and a new revision is stamped.

**On get (GET single):**
- The stored bytes already have `metadata.resourceVersion` stamped from the last write. Serve them directly.

**On list (GET collection):**
- Each item in `items[]` already has `metadata.resourceVersion` from its last write.
- The list's `metadata.resourceVersion` is the snapshot revision from `ListResponse.revision`. This is the revision clients should use as the starting point for a watch (Phase 2+).

**On patch (PATCH):**
- The handler loads the current object (already has `resourceVersion`), applies the merge patch, then calls `store.put`. A new revision is stamped.

---

## 6. Running and Testing

### Build and Start

```bash
cd /path/to/u7s
cargo build

./target/debug/u7s-apiserver \
    --db ./state.db \
    --kubeconfig ./kubeconfig.yaml \
    --listen 0.0.0.0:6443
```

The server writes `kubeconfig.yaml` on startup. On the first run, `state.db` is created and seeded.

### Kubectl Operations

```bash
export KUBECONFIG=./kubeconfig.yaml

# List pods — should return empty list.
kubectl get pods

# Create a pod with nodeName set explicitly (no scheduler in Phase 1).
# kubectl apply will NOT work — it uses strategic merge patch.
# Use kubectl create with a manifest file.
cat > pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  namespace: default
spec:
  nodeName: test-node
  containers:
  - name: nginx
    image: nginx:latest
EOF
kubectl create -f pod.yaml

# Or use kubectl run with overrides to set nodeName:
kubectl run nginx --image=nginx \
  --overrides='{"spec":{"nodeName":"test-node"}}'

# Retrieve the pod.
kubectl get pod nginx

# Replace the pod (kubectl replace works — it uses PUT).
kubectl replace -f pod.yaml

# Delete the pod.
kubectl delete pod nginx

# Confirm deletion.
kubectl get pod nginx  # should return 404 / "not found"
```

### Why `kubectl apply` Does Not Work

`kubectl apply` sends a `PATCH` request with `Content-Type: application/strategic-merge-patch+json`. Phase 1 only implements JSON merge patch (`application/merge-patch+json`). The server returns a 400 error for strategic merge patch requests. Use `kubectl create` for first creation and `kubectl replace` for updates.

---

## 7. Acceptance Criteria

Phase 1 is done when **all** of the following hold:

1. **`cargo build` succeeds with no warnings** (use `RUSTFLAGS="-D warnings"` to verify).

2. **`kubectl get pods` returns an empty list** — response is HTTP 200 with body:
   ```json
   {"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"0"},"items":[]}
   ```
   (or `resourceVersion` may be any valid string — just must not error).

3. **`kubectl create -f pod.yaml` stores the pod** — response is HTTP 201 with the pod body including a non-empty `metadata.resourceVersion`.

4. **`kubectl get pod nginx` retrieves the stored pod** — HTTP 200, body matches the created pod, `metadata.resourceVersion` is present.

5. **`kubectl delete pod nginx` removes the pod** — HTTP 200 with Success status. Subsequent `kubectl get pod nginx` returns HTTP 404.

6. **Concurrent `kubectl replace` with a stale `resourceVersion` returns 409** — simulate with:
   ```bash
   # Get current rv.
   RV=$(kubectl get pod nginx -o jsonpath='{.metadata.resourceVersion}')
   # Replace once to advance rv.
   kubectl replace -f pod.yaml
   # Replace again with the stale rv — should fail.
   kubectl replace --force=false -f <(kubectl get pod nginx -o json | \
     jq --arg rv "$RV" '.metadata.resourceVersion = $rv')
   # Expected: error from server (Conflict)
   ```

7. **Server idles under 30 MB RSS** — check with `ps -o rss= -p <pid>` after `kubectl get pods` completes and the server is idle.

---

## Appendix: Known Footguns

### WITHOUT ROWID and last_insert_rowid()

The `objects` table is declared `WITHOUT ROWID`. SQLite's `last_insert_rowid()` does not work for `WITHOUT ROWID` tables — it returns 0 or an unrelated value. **Do not use `last_insert_rowid()` anywhere in the store.** The revision counter lives in the `meta` table and must be read back explicitly after incrementing.

### spawn_blocking is not optional

Every `rusqlite::Connection` call blocks the thread. Calling rusqlite from an async context without `spawn_blocking` will stall the tokio worker thread, causing the entire server to stop accepting connections. This is not a performance concern — it is a correctness concern.

### TLS cert regeneration on restart

In Phase 1, TLS certs are generated fresh on each server start. The kubeconfig is also rewritten. If you start the server and then restart it, kubectl will need to pick up the new kubeconfig (it will, as long as `KUBECONFIG` points to the same file path). State in the SQLite database persists across restarts; certs do not. This is a known Phase 1 simplification — Phase 2+ should persist certs to disk.

### kubectl apply limitation

`kubectl apply` is the primary workflow for most Kubernetes users. It does not work in Phase 1. This must be clearly communicated to anyone testing Phase 1. The workaround: `kubectl create` (for new resources) and `kubectl replace` (for updates). These use POST and PUT respectively — both are fully implemented.

### BEGIN IMMEDIATE is required for all writes

Using `BEGIN DEFERRED` for write transactions in SQLite WAL mode can cause `SQLITE_BUSY` or, worse, silent upgrade races if a read transaction is open on the same connection. Always use `BEGIN IMMEDIATE` for any transaction that will write. `BEGIN DEFERRED` is correct only for read-only transactions.
