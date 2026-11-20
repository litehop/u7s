//! Shared test-only helpers for handler unit tests.
//!
//! `fn make_state() -> AppState { ... }` (a minimal in-memory `AppState` with
//! no CIDR config, no SA signing key, and an empty group index) was copied
//! byte-for-byte into ~13 handler test modules. A handful of admission/status
//! test modules need a variant that takes a caller-owned `Arc<SqliteStore>`
//! so they can seed data before the `AppState` is built. Both live here so a
//! future change to `AppState::new`'s signature or defaults is a one-file
//! edit instead of a ~18-file mechanical edit.

use std::sync::Arc;

use u7s_store::SqliteStore;

use crate::state::AppState;

/// Assert a create was refused as 422 Invalid with a FieldValueInvalid cause on `field`.
pub(crate) fn assert_invalid_name_field(err: &crate::status::StatusError, field: &str) {
    let body = serde_json::to_value(&err.1).unwrap();
    assert_eq!(
        err.0,
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "{body}"
    );
    assert_eq!(body["reason"], "Invalid", "{body}");
    assert_eq!(body["details"]["causes"][0]["field"], field, "{body}");
    assert_eq!(
        body["details"]["causes"][0]["reason"], "FieldValueInvalid",
        "{body}"
    );
    for k in ["name", "kind"] {
        assert!(
            body["details"][k].as_str().is_some_and(|v| !v.is_empty()),
            "details.{k} must be set like upstream: {body}"
        );
    }
    assert!(body["details"]["group"].is_string(), "{body}");
}

/// One PATCH per patch type (merge, strategic-merge, JSON Patch, server-side apply) that
/// tries to rewrite `metadata.name` (`field == "name"`) or `metadata.namespace`
/// (`field == "namespace"`) to `value`: `(label, content-type, body)`. `api_version`/`kind`
/// fill the apply body's type meta.
pub(crate) fn identity_rewrite_patches(
    field: &str,
    value: &str,
    api_version: &str,
    kind: &str,
) -> Vec<(&'static str, &'static str, bytes::Bytes)> {
    let obj = |v: serde_json::Value| bytes::Bytes::from(v.to_string());
    vec![
        (
            "merge",
            "application/merge-patch+json",
            obj(serde_json::json!({"metadata": {field: value}})),
        ),
        (
            "strategic-merge",
            "application/strategic-merge-patch+json",
            obj(serde_json::json!({"metadata": {field: value}})),
        ),
        (
            "json-patch",
            "application/json-patch+json",
            obj(serde_json::json!([
                {"op": "add", "path": format!("/metadata/{field}"), "value": value}
            ])),
        ),
        (
            "apply",
            "application/apply-patch+yaml",
            obj(serde_json::json!({
                "apiVersion": api_version, "kind": kind, "metadata": {field: value}
            })),
        ),
    ]
}

pub(crate) fn content_type_headers(ct: &'static str) -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(ct),
    );
    h
}

/// Assert a patch was refused as upstream's 400 BadRequest identity mismatch.
pub(crate) fn assert_identity_mismatch(err: &crate::status::StatusError, label: &str, field: &str) {
    assert_eq!(
        err.0,
        axum::http::StatusCode::BAD_REQUEST,
        "{label}: {}",
        err.1.message
    );
    let want = if field == "name" {
        "does not match the name on the URL"
    } else {
        "namespace of the provided object does not match the namespace sent on the request"
    };
    assert!(
        err.1.message.contains(want),
        "{label}: message {:?} must contain {want:?}",
        err.1.message
    );
}

/// Create an Active Namespace so namespaced creates into it pass NamespaceLifecycle.
/// Idempotent: an existing namespace is left untouched.
pub(crate) async fn seed_namespace(state: &AppState, name: &str) {
    seed_namespace_in(&*state.store, name).await;
}

/// [`seed_namespace`] against a bare store, for tests that wrap the store before building state.
pub(crate) async fn seed_namespace_in<S: u7s_store::Store>(store: &S, name: &str) {
    let body = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": name},
        "status": {"phase": "Active"}
    });
    match store
        .put(
            &crate::keys::cluster_object_key("namespaces", name),
            bytes::Bytes::from(body.to_string()),
            Some(0),
        )
        .await
    {
        Ok(_) | Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => panic!("seed namespace {name}: {e}"),
    }
}

/// Build a minimal in-memory `AppState` backed by a fresh `SqliteStore`.
pub(crate) fn make_state() -> AppState {
    make_state_with_store(Arc::new(
        SqliteStore::new(":memory:").expect("in-memory store"),
    ))
}

/// Same as [`make_state`], but takes a caller-provided store so tests can
/// seed data into it before the `AppState` that will serve it is built.
pub(crate) fn make_state_with_store(store: Arc<SqliteStore>) -> AppState {
    let state = AppState::new(
        store,
        None,
        std::collections::HashMap::new(),
        "https://localhost:6443".into(),
    );
    grant_create_everywhere(&state.rbac_index);
    state
}

/// Grant user `admin` and the `system:masters`/`system:nodes` groups the `create` verb on everything, so handler
/// tests that PUT/apply-create objects clear the create-on-update authorization without gaining
/// any other verb (sign/bind/escalate tests must still see a real denial).
pub(crate) fn grant_create_everywhere(rbac: &crate::rbac::RbacIndex) {
    grant_create_to(
        rbac,
        "test-creator",
        &serde_json::json!([
            {"kind": "User", "name": "admin"},
            {"kind": "Group", "name": "system:masters"},
            {"kind": "Group", "name": "system:nodes"}
        ]),
    );
}

/// Grant a single user the `create` verb on everything (see [`grant_create_everywhere`]).
pub(crate) fn grant_create_to_user(rbac: &crate::rbac::RbacIndex, username: &str) {
    grant_create_to(
        rbac,
        &format!("test-creator-{username}"),
        &serde_json::json!([{"kind": "User", "name": username}]),
    );
}

fn grant_create_to(rbac: &crate::rbac::RbacIndex, binding: &str, subjects: &serde_json::Value) {
    rbac.apply_object(
        "/apis/rbac.authorization.k8s.io/v1/clusterroles/test-creator",
        &serde_json::json!({"rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["create"]}]}),
    );
    rbac.apply_object(
        &format!("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{binding}"),
        &serde_json::json!({
            "subjects": subjects,
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "test-creator"}
        }),
    );
}

/// Install a minimal single-version (storage) namespaced CRD so CR requests resolve
/// through `find_crd` the way they do against a live cluster.
pub(crate) async fn install_namespaced_crd(
    state: &AppState,
    group: &str,
    version: &str,
    plural: &str,
    kind: &str,
) {
    let crd = serde_json::json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": { "name": format!("{plural}.{group}") },
        "spec": {
            "group": group,
            "names": {
                "plural": plural,
                "singular": plural,
                "kind": kind,
                "listKind": format!("{kind}List")
            },
            "scope": "Namespaced",
            "versions": [{
                "name": version, "served": true, "storage": true,
                "schema": { "openAPIV3Schema": {
                    "type": "object", "x-kubernetes-preserve-unknown-fields": true
                } }
            }]
        }
    });
    crate::handlers::crd::create_crd(
        axum::extract::State(state.clone()),
        axum::Extension(crate::auth::UserInfo {
            username: "test-user".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        }),
        axum::http::HeaderMap::new(),
        bytes::Bytes::from(crd.to_string()),
    )
    .await
    .expect("install CRD");
}

/// Grant `username` `verb` on `certificates.k8s.io/signers` named `signer_resource_name`
/// (a signer name, or `<domain>/*`) through the same RBAC index the real authorizer reads.
pub(crate) fn grant_signer_verb<S: u7s_store::Store>(
    state: &AppState<S>,
    username: &str,
    verb: &str,
    signer_resource_name: &str,
) {
    let id = format!("{username}-{verb}");
    state.rbac_index.apply_object(
        &format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{id}"),
        &serde_json::json!({"rules": [{
            "apiGroups": ["certificates.k8s.io"],
            "resources": ["signers"],
            "resourceNames": [signer_resource_name],
            "verbs": [verb]
        }]}),
    );
    state.rbac_index.apply_object(
        &format!("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{id}"),
        &serde_json::json!({
            "subjects": [{"kind": "User", "name": username}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": id
            }
        }),
    );
}

/// Headers of a server-side apply by `manager`, as `resolve_field_manager` forwards them.
pub(crate) fn apply_headers(manager: &str, force: bool) -> axum::http::HeaderMap {
    let mut h = content_type_headers("application/apply-patch+yaml");
    h.insert(
        "x-u7s-field-manager",
        axum::http::HeaderValue::from_str(manager).unwrap(),
    );
    if force {
        h.insert("x-u7s-force", axum::http::HeaderValue::from_static("true"));
    }
    h
}

/// A `managedFields` entry for an Update by `manager` owning `fields_v1`.
pub(crate) fn update_entry(
    manager: &str,
    api_version: &str,
    subresource: Option<&str>,
    fields_v1: serde_json::Value,
) -> serde_json::Value {
    let mut e = serde_json::json!({
        "manager": manager, "operation": "Update", "apiVersion": api_version,
        "time": "2026-01-01T00:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": fields_v1
    });
    if let Some(s) = subresource {
        e["subresource"] = s.into();
    }
    e
}

/// The `managedFields` entry of `manager` for `operation` scoped to `subresource`.
pub(crate) fn managed_entry<'a>(
    obj: &'a serde_json::Value,
    manager: &str,
    operation: &str,
    subresource: Option<&str>,
) -> Option<&'a serde_json::Value> {
    obj["metadata"]["managedFields"]
        .as_array()?
        .iter()
        .find(|e| {
            e["manager"] == manager
                && e["operation"] == operation
                && e["subresource"].as_str() == subresource
        })
}

pub(crate) async fn response_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

type ApplyResult = Result<serde_json::Value, crate::status::StatusError>;

/// A status apply must record `{manager, Apply, subresource: status}` owning what it named
/// and a later apply that drops a field must remove it. Without the scoped entry, applied
/// status is owned as an Update, so `kubectl apply --server-side --subresource=status`
/// can never delete fields it stops sending. Returns the object after each apply.
pub(crate) async fn assert_status_apply_is_scoped_and_prunes<F, Fut>(
    apply: F,
    first_yaml: &str,
    second_yaml: &str,
) -> (serde_json::Value, serde_json::Value)
where
    F: Fn(&'static str, bool, String) -> Fut,
    Fut: std::future::Future<Output = ApplyResult>,
{
    let first = apply("ctrl", false, first_yaml.to_owned())
        .await
        .unwrap_or_else(|e| panic!("first status apply must succeed: {e:?}"));
    let entry = managed_entry(&first, "ctrl", "Apply", Some("status")).unwrap_or_else(|| {
        panic!(
            "a status apply must record an Apply manager scoped to status: {}",
            first["metadata"]["managedFields"]
        )
    });
    assert!(
        entry["fieldsV1"]["f:status"].is_object(),
        "the status-scoped manager must own the status it applied: {entry}"
    );
    assert!(
        managed_entry(&first, "ctrl", "Apply", None).is_none(),
        "a status apply must not create a main-resource Apply entry"
    );
    let second = apply("ctrl", false, second_yaml.to_owned())
        .await
        .unwrap_or_else(|e| panic!("second status apply must succeed: {e:?}"));
    (first, second)
}

/// A status apply over a field an Update manager owns with a different value must be 409
/// without force (as upstream) and take ownership with force. `owned_status_key` is the
/// `status` member the seeded object's Update entry owns and `conflict_yaml` changes.
pub(crate) async fn assert_status_apply_conflicts_without_force<F, Fut>(
    apply: F,
    conflict_yaml: &str,
    owned_status_key: &str,
) where
    F: Fn(&'static str, bool, String) -> Fut,
    Fut: std::future::Future<Output = ApplyResult>,
{
    let err = apply("ctrl", false, conflict_yaml.to_owned())
        .await
        .expect_err("a status apply over another manager's field must conflict without force");
    assert_eq!(
        err.0,
        axum::http::StatusCode::CONFLICT,
        "conflict must be 409 as upstream: {}",
        err.1.message
    );
    let forced = apply("ctrl", true, conflict_yaml.to_owned())
        .await
        .unwrap_or_else(|e| panic!("force must override the conflict: {e:?}"));
    let key = format!("f:{owned_status_key}");
    assert!(
        managed_entry(&forced, "ctrl", "Apply", Some("status")).unwrap()["fieldsV1"]["f:status"]
            .get(&key)
            .is_some(),
        "force must give the applier the field: {}",
        forced["metadata"]["managedFields"]
    );
    let loser = forced["metadata"]["managedFields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["operation"] == "Update");
    assert!(
        loser.is_none_or(|l| l["fieldsV1"]["f:status"].get(&key).is_none()),
        "the forced field must leave the previous owner: {loser:?}"
    );
}
// ---------------------------------------------------------------------------
// MockStore — injects RevisionMismatch on the first put() after arm() is called.
//
// Using Arc<SqliteStore> for inner so we can clone the handle into the async
// block without borrowing self (SqliteStore is not Clone).
// ---------------------------------------------------------------------------

pub(crate) struct MockStore {
    pub(crate) inner: Arc<SqliteStore>,
    inject_next: std::sync::atomic::AtomicBool,
    delete_before_next_put: std::sync::Mutex<Option<String>>,
    write_before_next_put: std::sync::Mutex<Option<(String, bytes::Bytes)>>,
    write_before_next_delete: std::sync::Mutex<Option<(String, bytes::Bytes)>>,
    churn_before_every_delete: std::sync::Mutex<Option<String>>,
    churns: std::sync::atomic::AtomicU64,
    delete_before_next_delete: std::sync::Mutex<Option<String>>,
}

impl MockStore {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(SqliteStore::new(":memory:").unwrap()),
            inject_next: std::sync::atomic::AtomicBool::new(false),
            delete_before_next_put: std::sync::Mutex::new(None),
            write_before_next_put: std::sync::Mutex::new(None),
            write_before_next_delete: std::sync::Mutex::new(None),
            churn_before_every_delete: std::sync::Mutex::new(None),
            churns: std::sync::atomic::AtomicU64::new(0),
            delete_before_next_delete: std::sync::Mutex::new(None),
        }
    }

    /// Deletes `key` right before the next put, i.e. after the handler's read.
    pub(crate) fn arm_delete_before_put(&self, key: &str) {
        *self.delete_before_next_put.lock().unwrap() = Some(key.to_string());
    }

    /// Overwrites `key` with `body` right before the next put: a concurrent writer that
    /// lands after the handler's read.
    pub(crate) fn arm_write_before_put(&self, key: &str, body: bytes::Bytes) {
        *self.write_before_next_put.lock().unwrap() = Some((key.to_string(), body));
    }

    /// Overwrites `key` with `body` right before the next delete: a concurrent writer that
    /// lands after the handler's read.
    pub(crate) fn arm_write_before_delete(&self, key: &str, body: bytes::Bytes) {
        *self.write_before_next_delete.lock().unwrap() = Some((key.to_string(), body));
    }

    /// Deletes `key` right before the next delete: someone else's delete that lands first.
    pub(crate) fn arm_delete_before_delete(&self, key: &str) {
        *self.delete_before_next_delete.lock().unwrap() = Some(key.to_string());
    }

    /// Rewrites `key` right before every delete: a writer that wins every race. Each lost
    /// race advances the paused tokio clock by 20s, so only for `start_paused` tests.
    pub(crate) fn arm_churn_before_every_delete(&self, key: &str) {
        *self.churn_before_every_delete.lock().unwrap() = Some(key.to_string());
    }

    pub(crate) fn arm(&self) {
        self.inject_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl u7s_store::Store for MockStore {
    fn get(
        &self,
        key: impl Into<String> + Send,
    ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
    {
        let inner = self.inner.clone();
        let key: String = key.into();
        async move { inner.get(&key).await }
    }

    fn list(
        &self,
        prefix: impl Into<String> + Send,
        opts: u7s_store::ListOptions,
    ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send {
        let inner = self.inner.clone();
        let prefix: String = prefix.into();
        async move { inner.list(&prefix, opts).await }
    }

    fn put(
        &self,
        key: impl Into<String> + Send,
        value: bytes::Bytes,
        expected_revision: Option<u64>,
    ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
        let inject = self
            .inject_next
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        let delete_first = self.delete_before_next_put.lock().unwrap().take();
        let write_first = self.write_before_next_put.lock().unwrap().take();
        let inner = self.inner.clone();
        let key: String = key.into();
        async move {
            if let Some(k) = delete_first {
                inner.delete(&k, None).await.unwrap();
            }
            if let Some((k, body)) = write_first {
                inner.put(&k, body, None).await.unwrap();
            }
            if inject {
                Err(u7s_store::StoreError::RevisionMismatch {
                    expected: 1,
                    current: 99,
                })
            } else {
                inner.put(&key, value, expected_revision).await
            }
        }
    }

    fn delete(
        &self,
        key: impl Into<String> + Send,
        expected_revision: Option<u64>,
    ) -> impl std::future::Future<Output = u7s_store::Result<(u64, bytes::Bytes)>> + Send {
        let write_first = self.write_before_next_delete.lock().unwrap().take();
        let delete_first = self.delete_before_next_delete.lock().unwrap().take();
        let churn = self.churn_before_every_delete.lock().unwrap().clone();
        let n = self
            .churns
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let inner = self.inner.clone();
        let key: String = key.into();
        async move {
            if let Some((k, body)) = write_first {
                inner.put(&k, body, None).await.unwrap();
            }
            if let Some(k) = delete_first {
                inner.delete(&k, None).await.unwrap();
            }
            if let Some(k) = churn {
                // Needs a paused tokio clock: each lost race costs 20s of request time.
                assert!(
                    n < 50,
                    "the delete never gave up on a writer that always wins"
                );
                tokio::time::advance(std::time::Duration::from_secs(20)).await;
                if let Some(cur) = inner.get(&k).await.unwrap() {
                    let mut body: serde_json::Value = serde_json::from_slice(&cur.value).unwrap();
                    body["metadata"]["annotations"] = serde_json::json!({"churn": n.to_string()});
                    inner
                        .put(&k, bytes::Bytes::from(body.to_string()), None)
                        .await
                        .unwrap();
                }
            }
            inner.delete(&key, expected_revision).await
        }
    }

    fn list_namespace_objects(
        &self,
        namespace: &str,
    ) -> impl std::future::Future<Output = u7s_store::Result<Vec<u7s_store::StoreObject>>> + Send
    {
        let inner = self.inner.clone();
        let ns = namespace.to_string();
        async move { inner.list_namespace_objects(&ns).await }
    }

    fn delete_namespace_resources(
        &self,
        namespace: &str,
    ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
        let inner = self.inner.clone();
        let ns = namespace.to_string();
        async move { inner.delete_namespace_resources(&ns).await }
    }

    fn watch(
        &self,
        _prefix: &str,
        _from_revision: u64,
    ) -> impl std::future::Future<
        Output = u7s_store::Result<
            impl futures_core::Stream<Item = u7s_store::WatchEvent> + Send + 'static,
        >,
    > + Send {
        // MockStore::watch is not called by the OCC tests (they only test put).
        // Return an empty stream so MockStore compiles as a Store impl.
        // Delegating to inner.watch() is not possible because SqliteStore::watch
        // is async fn taking &self — the desugared future captures &self for its
        // full lifetime, creating a borrow-across-await that the borrow checker
        // rejects inside async move blocks.
        std::future::ready(Ok(futures_util::stream::empty()))
    }

    fn compaction_horizon(&self) -> u64 {
        self.inner.compaction_horizon()
    }

    fn current_revision(&self) -> u64 {
        self.inner.current_revision()
    }

    fn watch_receiver_count(&self) -> usize {
        self.inner.watch_receiver_count()
    }
}
