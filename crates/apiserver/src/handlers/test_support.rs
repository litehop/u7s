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
    AppState::new(
        store,
        None,
        None,
        std::collections::HashMap::new(),
        "https://localhost:6443".into(),
    )
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
pub(crate) fn grant_signer_verb(
    state: &AppState,
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
