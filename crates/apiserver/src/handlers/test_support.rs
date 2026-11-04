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
