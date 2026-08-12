use bytes::Bytes;
use thiserror::Error;

pub mod metrics;
pub mod sqlite;

pub use sqlite::SqliteStore;

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

/// Resolve a dot-separated JSON path (e.g. "spec.nodeName") against `value` and test
/// equality with `expected`.
///
/// A field missing anywhere along the path compares as its zero value ("" for strings,
/// "false" for bools) rather than never matching — this mirrors Kubernetes' `fields.Set`
/// semantics, where an absent key's `Get()` returns "". Without that fallback, a field
/// selector like `spec.nodeName=` (matching un-scheduled pods) could never match anything,
/// since newly-created pods have no `spec.nodeName` key at all yet.
///
/// Shared by the generic (non-indexed) field-selector scan in `sqlite.rs` and by CR field
/// selectors (arbitrary CRD-declared JSON paths in apiserver), so both resolve values
/// identically instead of drifting apart.
pub fn json_path_equals(value: &serde_json::Value, field: &str, expected: &str) -> bool {
    let mut cur = value;
    for part in field.split('.') {
        match cur.get(part) {
            Some(next) => cur = next,
            None => return expected.is_empty() || expected == "false",
        }
    }
    match cur {
        serde_json::Value::String(s) => s == expected,
        serde_json::Value::Bool(b) => expected == if *b { "true" } else { "false" },
        serde_json::Value::Null => expected.is_empty(),
        serde_json::Value::Number(n) => expected == n.to_string(),
        _ => false,
    }
}

#[cfg(test)]
mod json_path_equals_tests {
    use super::json_path_equals;
    use serde_json::json;

    // WHY: this function backs BOTH the store's own generic field-selector scan and every CR
    // field selector (arbitrary CRD-declared JSON paths) — a regression here silently breaks
    // field-selector filtering for every CRD author who declares `selectableFields`.

    #[test]
    fn matches_top_level_string_field() {
        let obj = json!({"host": "host1"});
        assert!(
            json_path_equals(&obj, "host", "host1"),
            "a single-segment path must resolve against the object root, since CRD selectable \
             fields are commonly declared without a `spec` wrapper (e.g. `.host`)"
        );
        assert!(!json_path_equals(&obj, "host", "host2"));
    }

    #[test]
    fn matches_nested_dot_path() {
        let obj = json!({"spec": {"nodeName": "node-01"}});
        assert!(
            json_path_equals(&obj, "spec.nodeName", "node-01"),
            "multi-segment paths must walk each dot-separated component from the root"
        );
    }

    #[test]
    fn absent_field_matches_only_empty_expectation() {
        let obj = json!({"host": "host1"});
        assert!(
            json_path_equals(&obj, "port", ""),
            "a field selector for an unset field (e.g. `port=` for a CR with no port key) must \
             match the zero value, mirroring Kubernetes' fields.Set.Get() returning \"\" for a \
             missing key — otherwise clients could never select 'field is unset'"
        );
        assert!(
            !json_path_equals(&obj, "port", "80"),
            "an absent field must never satisfy a non-empty expectation — a CR without a port \
             key is not the same as one whose port equals 80"
        );
    }

    #[test]
    fn absent_intermediate_segment_is_treated_as_absent() {
        let obj = json!({"host": "host1"});
        assert!(
            !json_path_equals(&obj, "spec.host", "host1"),
            "when an intermediate path segment (spec) is missing entirely, the whole path must \
             resolve as absent rather than panicking or matching by coincidence"
        );
    }

    #[test]
    fn matches_bool_and_number_by_string_representation() {
        let obj = json!({"ready": true, "count": 3});
        assert!(json_path_equals(&obj, "ready", "true"));
        assert!(!json_path_equals(&obj, "ready", "false"));
        assert!(json_path_equals(&obj, "count", "3"));
    }
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

/// Error from `Store::create_if_namespace_active`.
#[derive(Debug, Error)]
pub enum CreateNamespacedError {
    /// The namespace at the checked key has `status.phase == "Terminating"`. The insert was
    /// never attempted — real kube-apiserver rejects the create outright rather than letting
    /// it land in a namespace that is mid-deletion.
    #[error("namespace is being terminated")]
    NamespaceTerminating,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<rusqlite::Error> for CreateNamespacedError {
    fn from(e: rusqlite::Error) -> Self {
        CreateNamespacedError::Store(StoreError::from(e))
    }
}

impl From<tokio::task::JoinError> for CreateNamespacedError {
    fn from(e: tokio::task::JoinError) -> Self {
        CreateNamespacedError::Store(StoreError::from(e))
    }
}

/// Internal event broadcast after every write.
#[derive(Debug)]
pub struct InternalEvent {
    pub key: String,
    pub revision: u64,
    pub value: Option<Bytes>, // None = deleted
    pub is_create: bool,      // true if key did not exist before this put
    /// For deletions: the object bytes as they existed immediately before deletion.
    /// None for non-deletion events.
    pub deleted_body: Option<Bytes>,
}

/// Public watch event for consumers.
#[derive(Debug, Clone)]
pub enum WatchEvent {
    Added(StoreObject),
    Modified(StoreObject),
    Deleted {
        key: String,
        revision: u64,
        /// Last-known object body before deletion. Used to emit full tombstone objects
        /// in watch streams so informers can do label-selector matching on the deleted object.
        body: Option<Bytes>,
    },
    Bookmark {
        revision: u64,
    },
    Compacted {
        requested: u64,
        horizon: u64,
    },
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
    ///
    /// No-op suppression: if a precondition above is satisfied AND the key already has a
    /// stored value AND the new value is semantically identical to it (ignoring
    /// `metadata.resourceVersion`), the store does not write, does not bump the revision, and
    /// does not emit a watch event — it returns the existing revision as if the write
    /// succeeded. This mirrors real kube-apiserver's etcd3 `GuaranteedUpdate` byte-equality
    /// short-circuit and exists so routine, unchanged re-writes (e.g. kubelet's periodic
    /// status re-PATCH of a steady pod) don't flood every watcher with phantom MODIFIED
    /// events. A precondition violation is still reported as `RevisionMismatch` even when the
    /// content would have been unchanged — the CAS check runs first.
    fn put(
        &self,
        key: &str,
        value: Bytes,
        expected_revision: Option<u64>,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;

    /// Create-only write, gated on a namespace's `status.phase` not being `"Terminating"`.
    ///
    /// `ns_key`, when `Some`, is the full store key of the parent namespace object (e.g.
    /// `/registry/namespaces/foo`) — the phase read and the create at `key` happen inside one
    /// transaction, so no concurrent write to `ns_key` (e.g. a namespace delete flipping its
    /// phase to `Terminating`) can land in the gap between the check and the insert. Pass
    /// `None` for cluster-scoped creates, which skip the namespace check entirely and behave
    /// exactly like `put(key, value, Some(0))`.
    ///
    /// A namespace that does not exist at `ns_key` is treated as active (not Terminating):
    /// namespace-existence enforcement, where a caller wants it, is the caller's own job (see
    /// e.g. pods.rs's `parse_namespace`), not this method's — it exists solely to close the
    /// create-vs-delete phase-flip race, not to add a new validation rule.
    ///
    /// The default implementation (`get` the namespace, then `put`) is NOT atomic — it exists
    /// so callers that don't need real atomicity (test doubles wrapping another `Store`) don't
    /// have to implement this method. `SqliteStore` overrides it with a single
    /// `BEGIN IMMEDIATE … COMMIT` transaction; that override is the one path production code
    /// actually depends on for correctness.
    fn create_if_namespace_active(
        &self,
        ns_key: Option<&str>,
        key: &str,
        value: Bytes,
    ) -> impl std::future::Future<Output = std::result::Result<u64, CreateNamespacedError>> + Send
    {
        async move {
            if let Some(ns_key) = ns_key {
                if let Some(stored) = self
                    .get(ns_key)
                    .await
                    .map_err(CreateNamespacedError::Store)?
                {
                    if let Ok(ns_obj) = serde_json::from_slice::<serde_json::Value>(&stored.value) {
                        if ns_obj["status"]["phase"].as_str() == Some("Terminating") {
                            return Err(CreateNamespacedError::NamespaceTerminating);
                        }
                    }
                }
            }
            self.put(key, value, Some(0))
                .await
                .map_err(CreateNamespacedError::Store)
        }
    }

    /// Delete an object. Same optimistic concurrency semantics as put.
    /// Returns the new global revision and the last-known object bytes on success.
    fn delete(
        &self,
        key: &str,
        expected_revision: Option<u64>,
    ) -> impl std::future::Future<Output = Result<(u64, Bytes)>> + Send;

    /// Watch objects under prefix starting from (exclusive) from_revision.
    /// Yields historical events from the ring buffer then live broadcast events.
    fn watch(
        &self,
        prefix: &str,
        from_revision: u64,
    ) -> impl std::future::Future<
        Output = Result<impl futures_core::Stream<Item = WatchEvent> + Send + 'static>,
    > + Send;

    /// List all objects belonging to the given namespace with their bodies.
    ///
    /// Returns every stored object whose `metadata.namespace` matches `namespace`.
    /// Unlike `delete_namespace_resources` this does not remove the objects; it is
    /// used by the namespace cascade path to inspect each object's finalizers before
    /// deciding whether to hard-delete or soft-delete (set deletionTimestamp).
    fn list_namespace_objects(
        &self,
        namespace: &str,
    ) -> impl std::future::Future<Output = Result<Vec<StoreObject>>> + Send;

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
    ///
    /// For an implementation that shards its ring by resource type this is a cross-shard
    /// MAXIMUM, so do not decide watch expiry with it — use `compaction_horizon_for`.
    fn compaction_horizon(&self) -> u64;

    /// Return the compaction horizon that governs watches on `prefix` specifically: the revision
    /// below which THIS resource type's history has been discarded.
    ///
    /// This, not `compaction_horizon`, is what an expiry check must consult. On a sharded store
    /// the two differ sharply: the store-wide value tracks whichever resource type churns
    /// hardest, so expiring against it rejects watches on quiet resource types whose own ring
    /// still holds every event they ever saw — a spurious 410 that forces the client into a
    /// needless relist, and under sustained churn can prevent it from ever re-establishing.
    ///
    /// Defaults to `compaction_horizon()` so unsharded implementations (and test doubles) need
    /// not override it — for a single global ring the two are the same value.
    fn compaction_horizon_for(&self, _prefix: &str) -> u64 {
        self.compaction_horizon()
    }

    /// Return the global revision of the most recently committed write.
    /// Used by watch BOOKMARK heartbeats to advance informer sync RVs across
    /// resource types (KCM ConsistencyStore checks informer RV >= last written RV).
    fn current_revision(&self) -> u64;

    /// Return the number of currently active subscribers on the shared watch broadcast
    /// channel — i.e. how many watch streams are open right now, across every resource type.
    /// Backs the `u7s_watch_broadcast_receivers` gauge; read on demand at scrape time since
    /// `tokio::sync::broadcast::Sender::receiver_count` already tracks this lock-free with no
    /// extra bookkeeping needed here.
    fn watch_receiver_count(&self) -> usize;
}
