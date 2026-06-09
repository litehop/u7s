use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use u7s_store::Store;

use crate::{
    keys::group_object_key,
    state::AppState,
    status::Status,
    types::Object,
    util::{content_type, extract_body, parse_resource_version},
};

use super::generic::{lookup, store_err, validate_name};
use super::json_patch::{apply_json_patch, detect_patch_type, PatchType};
use super::resource::{get_namespaced_resource, get_resource};

// -- cluster-scoped --

pub async fn get_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    // Same as get_resource; status is embedded in the object.
    get_resource(State(state), Path((group, version, plural, name))).await
}

pub async fn put_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("name", &name)?;
    let meta = lookup(&state, &group, &version, &plural)?.clone();
    let body = extract_body(&body, content_type(&headers));
    let incoming =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = group_object_key(&group, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // Replace only the status field; leave spec and metadata (except resourceVersion) untouched.
    match &incoming.body["status"] {
        serde_json::Value::Null => {
            current.body.as_object_mut().map(|m| m.remove("status"));
        }
        v => {
            current.body["status"] = v.clone();
        }
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

pub async fn patch_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("name", &name)?;
    let meta = lookup(&state, &group, &version, &plural)?.clone();
    let patch_type = detect_patch_type(&headers)?;

    let key = group_object_key(&group, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    match patch_type {
        PatchType::Json => {
            // JSON Patch addresses the full document; operations include the /status prefix.
            apply_json_patch(&mut current.body, &patch)?;
        }
        _ => {
            // Merge and strategic merge: only patch the status portion.
            if let Some(status_patch) = patch.get("status") {
                let entry = current.body.as_object_mut().map(|m| {
                    m.entry("status")
                        .or_insert(serde_json::Value::Object(Default::default()))
                });
                if let Some(entry) = entry {
                    match patch_type {
                        PatchType::Merge => crate::patch::merge_patch(entry, status_patch),
                        PatchType::StrategicMerge => {
                            crate::patch::strategic_merge_patch(entry, status_patch)
                                .map_err(|e| Status::bad_request(e.to_string()))?;
                        }
                        PatchType::Json => unreachable!(),
                    }
                }
            }
        }
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

// -- namespaced --

pub async fn get_namespaced_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    // Same as get_namespaced_resource; status is embedded in the object.
    get_namespaced_resource(State(state), Path((group, version, ns, plural, name))).await
}

pub async fn put_namespaced_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    validate_name("name", &name)?;
    let body = extract_body(&body, content_type(&headers));
    let incoming =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // CR fallback: if the resource is not in the registry (e.g. Gateway API CRDs), fall back
    // to the CR storage key. This allows Gateway/GatewayClass controllers to PUT status on
    // their custom resources using the same /status route as built-in types.
    let (key, kind_fallback) = match lookup(&state, &group, &version, &plural) {
        Ok(meta) => (
            group_object_key(&group, &plural, Some(&ns), &name),
            meta.kind.clone(),
        ),
        Err(_) => {
            // CR fallback: CRs are stored under /registry/cr/<group>/<version>/<plural>/<ns>/<name>
            let cr_key = format!("/registry/cr/{group}/{version}/{plural}/{ns}/{name}");
            (cr_key, plural.clone())
        }
    };

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &kind_fallback))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let kind = current.body["kind"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or(kind_fallback);

    match &incoming.body["status"] {
        serde_json::Value::Null => {
            current.body.as_object_mut().map(|m| m.remove("status"));
        }
        v => {
            current.body["status"] = v.clone();
        }
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &kind))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

pub async fn patch_namespaced_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    validate_name("name", &name)?;
    let patch_type = detect_patch_type(&headers)?;

    let key = match lookup(&state, &group, &version, &plural) {
        Ok(_) => group_object_key(&group, &plural, Some(&ns), &name),
        Err(_) => {
            // CR fallback: CRs are stored under /registry/cr/<group>/<version>/<plural>/<ns>/<name>
            format!("/registry/cr/{group}/{version}/{plural}/{ns}/{name}")
        }
    };

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &plural))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let kind = current.body["kind"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| plural.clone());

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    match patch_type {
        PatchType::Json => {
            // JSON Patch addresses the full document; operations include the /status prefix.
            apply_json_patch(&mut current.body, &patch)?;
        }
        _ => {
            // Merge and strategic merge: only patch the status portion.
            if let Some(status_patch) = patch.get("status") {
                let entry = current.body.as_object_mut().map(|m| {
                    m.entry("status")
                        .or_insert(serde_json::Value::Object(Default::default()))
                });
                if let Some(entry) = entry {
                    match patch_type {
                        PatchType::Merge => crate::patch::merge_patch(entry, status_patch),
                        PatchType::StrategicMerge => {
                            crate::patch::strategic_merge_patch(entry, status_patch)
                                .map_err(|e| Status::bad_request(e.to_string()))?;
                        }
                        PatchType::Json => unreachable!(),
                    }
                }
            }
        }
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &kind))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use u7s_store::SqliteStore;

    fn json_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    }

    fn merge_patch_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        h
    }

    fn make_state() -> crate::state::AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    /// get_resource_status returns 404 when the cluster-scoped object does not exist.
    /// Status reads delegate to get_resource; a missing object must never return 200.
    #[tokio::test]
    async fn get_resource_status_returns_404_for_missing() {
        let state = make_state();
        let result = get_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "nonexistent".into(),
            )),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// get_resource_status returns the stored object (same as get_resource) when it exists.
    /// Controllers read status via this path; returning the full object is correct.
    #[tokio::test]
    async fn get_resource_status_returns_stored_object() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1" },
            "spec": { "drivers": [] },
            "status": { "ready": true }
        });
        store
            .put(
                "/registry/storage.k8s.io/csinodes/worker-1",
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let result = get_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-1".into(),
            )),
        )
        .await;
        let resp = match result {
            Ok(r) => r,
            Err(_) => panic!("get_resource_status must succeed when object exists"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    /// put_resource_status returns 404 when the cluster-scoped object does not exist.
    /// Controllers must not create objects via the status subresource.
    #[tokio::test]
    async fn put_resource_status_returns_404_for_missing_resource() {
        let state = make_state();
        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "nonexistent" },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "nonexistent".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// put_resource_status with a null status body removes the status field.
    /// When a controller explicitly sets status=null, the field must be removed
    /// rather than set to null — Kubernetes serializes absent and null fields differently.
    #[tokio::test]
    async fn put_resource_status_null_status_removes_field() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-3" },
            "spec": { "drivers": [] },
            "status": { "ready": true }
        });
        let key = "/registry/storage.k8s.io/csinodes/worker-3";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // PUT body with explicit null status (JSON: "status": null)
        let null_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-3" },
            "status": null
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-3".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&null_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "put with null status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v.get("status").is_none(),
            "null status in PUT body must remove the status field from the stored object"
        );
    }

    /// patch_resource_status returns 404 when cluster-scoped object does not exist.
    /// Controllers must receive an unambiguous error so they know the resource is gone.
    #[tokio::test]
    async fn patch_resource_status_returns_404_for_missing_resource() {
        let state = make_state();
        let patch = serde_json::json!({"status": {"phase": "Failed"}});
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "nonexistent".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// get_namespaced_resource_status returns the stored object when it exists.
    /// Namespaced controllers (e.g. Deployment controller) read status via this path.
    #[tokio::test]
    async fn get_namespaced_resource_status_returns_stored_object() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-x", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "node-x" }
        });
        store
            .put(
                "/registry/coordination.k8s.io/leases/kube-node-lease/node-x",
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let result = get_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "node-x".into(),
            )),
        )
        .await;
        let resp = match result {
            Ok(r) => r,
            Err(_) => panic!("get_namespaced_resource_status must succeed when object exists"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    /// get_namespaced_resource_status returns 404 when the object does not exist.
    #[tokio::test]
    async fn get_namespaced_resource_status_returns_404_for_missing() {
        let state = make_state();
        let result = get_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "nonexistent".into(),
            )),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// put_namespaced_resource_status updates only the status field for a registered resource.
    /// The spec must remain unchanged — status isolation is critical for controllers.
    #[tokio::test]
    async fn put_namespaced_resource_status_updates_status() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-y", "namespace": "kube-node-lease", "resourceVersion": "1" },
            "spec": { "holderIdentity": "node-y", "leaseDurationSeconds": 40 }
        });
        store
            .put(
                "/registry/coordination.k8s.io/leases/kube-node-lease/node-y",
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let put_body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-y", "namespace": "kube-node-lease" },
            "status": { "phase": "Active" }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "node-y".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "put_namespaced_resource_status must succeed"
        );
        let stored = store
            .get("/registry/coordination.k8s.io/leases/kube-node-lease/node-y")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Active");
        assert_eq!(v["spec"]["holderIdentity"], "node-y");
    }

    /// put_namespaced_resource_status returns 404 when the object does not exist.
    #[tokio::test]
    async fn put_namespaced_resource_status_returns_404_for_missing() {
        let state = make_state();
        let body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "missing", "namespace": "kube-node-lease" },
            "status": { "phase": "Active" }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "missing".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// put_namespaced_resource_status with null status removes the status field.
    /// Same semantics as the cluster-scoped variant — controllers can clear status.
    #[tokio::test]
    async fn put_namespaced_resource_status_null_status_removes_field() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-z", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "node-z" },
            "status": { "phase": "Active" }
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/node-z";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let null_body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-z", "namespace": "kube-node-lease" },
            "status": null
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "node-z".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&null_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "put with null status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v.get("status").is_none(),
            "null status in PUT body must remove the status field"
        );
    }

    /// patch_namespaced_resource_status with merge-patch updates the status field.
    /// This is the primary path used by namespaced controllers to report status.
    #[tokio::test]
    async fn patch_namespaced_resource_status_with_merge_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-w", "namespace": "kube-node-lease", "resourceVersion": "1" },
            "spec": { "holderIdentity": "node-w" },
            "status": {}
        });
        store
            .put(
                "/registry/coordination.k8s.io/leases/kube-node-lease/node-w",
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let patch = serde_json::json!({"status": {"phase": "Bound"}});
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "node-w".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "patch_namespaced_resource_status must succeed"
        );
        let stored = store
            .get("/registry/coordination.k8s.io/leases/kube-node-lease/node-w")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Bound");
        assert_eq!(v["spec"]["holderIdentity"], "node-w");
    }

    /// patch_resource_status with strategic-merge-patch applies the status portion only.
    #[tokio::test]
    async fn patch_resource_status_with_strategic_merge_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "smp-node" },
            "spec": { "drivers": [] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/smp-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut smp_headers = axum::http::HeaderMap::new();
        smp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        let patch =
            serde_json::json!({"status": {"conditions": [{"type": "Ready", "status": "True"}]}});

        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "smp-node".into(),
            )),
            smp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "strategic-merge-patch on status must succeed"
        );
    }

    /// patch_namespaced_resource_status with strategic-merge-patch.
    #[tokio::test]
    async fn patch_namespaced_resource_status_with_strategic_merge_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "smp-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "smp-lease" },
            "status": {}
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/smp-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut smp_headers = axum::http::HeaderMap::new();
        smp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        let patch = serde_json::json!({"status": {"conditions": [{"type": "Available", "status": "True"}]}});

        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "smp-lease".into(),
            )),
            smp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "strategic-merge-patch on namespaced status must succeed"
        );
    }

    /// patch_namespaced_resource_status returns 404 when the object does not exist.
    #[tokio::test]
    async fn patch_namespaced_resource_status_returns_404_for_missing() {
        let state = make_state();
        let patch = serde_json::json!({"status": {"phase": "Failed"}});
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "nonexistent".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// put_resource_status replaces only the status field, leaving spec untouched.
    /// Status subresource isolation is required so that controllers cannot accidentally
    /// overwrite spec data when updating status (and vice versa).
    #[tokio::test]
    async fn put_resource_status_replaces_status_only() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a CSINode in the store.
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1", "resourceVersion": "1" },
            "spec": { "drivers": [{"name": "csi.io", "nodeID": "worker-1"}] }
        });
        let key = "/registry/storage.k8s.io/csinodes/worker-1";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        let put_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1" },
            "status": { "allocatable": {"count": 10} }
        });

        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-1".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        assert!(result.is_ok(), "put_resource_status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["allocatable"]["count"], 10);
        assert_eq!(v["spec"]["drivers"][0]["name"], "csi.io");
    }

    /// patch_resource_status with merge-patch updates only the status sub-field.
    #[tokio::test]
    async fn patch_resource_status_merge_patch_updates_status() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-2", "resourceVersion": "1" },
            "spec": { "drivers": [{"name": "csi.io", "nodeID": "worker-2"}] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/worker-2";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        let patch = serde_json::json!({"status": {"phase": "Ready"}});
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-2".into(),
            )),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        assert!(result.is_ok(), "patch_resource_status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Ready");
        assert_eq!(v["spec"]["drivers"][0]["name"], "csi.io");
    }

    /// patch_resource_status with JSON Patch (`application/json-patch+json`) applies operations
    /// on the full document. JSON Patch addresses the /status prefix explicitly.
    #[tokio::test]
    async fn patch_resource_status_with_json_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "jp-node" },
            "spec": { "drivers": [] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/jp-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut jp_headers = axum::http::HeaderMap::new();
        jp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );
        let patch = serde_json::json!([
            {"op": "add", "path": "/status/ready", "value": true}
        ]);

        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "jp-node".into(),
            )),
            jp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "JSON patch on status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["ready"], true);
    }

    /// patch_namespaced_resource_status with JSON Patch applies operations on the full document.
    #[tokio::test]
    async fn patch_namespaced_resource_status_with_json_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "jp-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "jp-lease" },
            "status": {}
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/jp-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut jp_headers = axum::http::HeaderMap::new();
        jp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );
        let patch = serde_json::json!([
            {"op": "add", "path": "/status/phase", "value": "Bound"}
        ]);

        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "jp-lease".into(),
            )),
            jp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "JSON patch on namespaced status must succeed"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Bound");
    }

    // OCC is enforced by SqliteStore::put's CAS; tested in crates/store/src/lib.rs.

    /// Gateway API controllers PATCH status on namespaced Gateways via the /status route.
    /// gateway.networking.k8s.io/v1 is in the static resource registry, so
    /// patch_namespaced_resource_status must use the registry store key (not the CR fallback key).
    #[tokio::test]
    async fn gateway_cr_status_merge_patch_updates_status_only() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let group = "gateway.networking.k8s.io";
        let version = "v1";
        let plural = "gateways";
        let ns = "default";
        let name = "my-gateway";
        // Gateway is in the registry, so the handler uses the registry key.
        let registry_key = crate::keys::group_object_key(group, plural, Some(ns), name);

        let initial = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": name, "namespace": ns, "resourceVersion": "1" },
            "spec": {
                "gatewayClassName": "nginx",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            },
            "status": {}
        });
        let initial_bytes = bytes::Bytes::from(serde_json::to_vec(&initial).unwrap());
        store
            .put(&registry_key, initial_bytes, None)
            .await
            .expect("seed Gateway");

        let patch =
            serde_json::json!({"status": {"conditions": [{"type": "Ready", "status": "True"}]}});
        let patch_bytes = bytes::Bytes::from(serde_json::to_vec(&patch).unwrap());

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
                name.to_string(),
            )),
            headers,
            patch_bytes,
        )
        .await;

        assert!(
            result.is_ok(),
            "Gateway status PATCH must succeed via registry path"
        );

        let stored = store
            .get(&registry_key)
            .await
            .expect("store get")
            .expect("Gateway must exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let conds = v["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be an array");
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0]["type"], "Ready");
        assert_eq!(conds[0]["status"], "True");

        assert_eq!(v["spec"]["gatewayClassName"], "nginx");
        assert_eq!(v["spec"]["listeners"][0]["port"], 80);
    }

    /// put_namespaced_resource_status uses the CR fallback key when the group is not
    /// in the static resource registry. This allows CRD-backed controllers (e.g. cert-manager)
    /// to update status on their custom resources via the same /status route as built-in types.
    #[tokio::test]
    async fn put_namespaced_resource_status_uses_cr_fallback_key_for_unknown_group() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        // Store a CR under the CR fallback key path.
        // "certificates.cert-manager.io" is not in the static registry, so the handler
        // must fall back to /registry/cr/<group>/<version>/<plural>/<ns>/<name>.
        let cert = serde_json::json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": { "name": "my-cert", "namespace": "default" },
            "spec": { "secretName": "my-tls" }
        });
        let cr_key = "/registry/cr/cert-manager.io/v1/certificates/default/my-cert";
        store
            .put(
                cr_key,
                bytes::Bytes::from(serde_json::to_vec(&cert).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let put_body = serde_json::json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": { "name": "my-cert", "namespace": "default" },
            "status": { "conditions": [{"type": "Ready", "status": "True"}] }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "cert-manager.io".into(),
                "v1".into(),
                "default".into(),
                "certificates".into(),
                "my-cert".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "put_namespaced_resource_status must succeed via CR fallback key for unknown group"
        );

        let stored = store.get(cr_key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["conditions"][0]["type"], "Ready",
            "status must be updated via CR fallback key"
        );
        // spec must be unchanged — status subresource isolation applies to CRs too
        assert_eq!(
            v["spec"]["secretName"], "my-tls",
            "spec must not be modified"
        );
    }

    /// patch_namespaced_resource_status uses the CR fallback key when the group is not
    /// in the static resource registry. Controllers that manage custom resources must be
    /// able to patch status via the same /status route used for built-in resources.
    #[tokio::test]
    async fn patch_namespaced_resource_status_uses_cr_fallback_key_for_unknown_group() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let cert = serde_json::json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": { "name": "patch-cert", "namespace": "default" },
            "spec": { "secretName": "patch-tls" },
            "status": {}
        });
        let cr_key = "/registry/cr/cert-manager.io/v1/certificates/default/patch-cert";
        store
            .put(
                cr_key,
                bytes::Bytes::from(serde_json::to_vec(&cert).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let patch =
            serde_json::json!({"status": {"conditions": [{"type": "Issued", "status": "True"}]}});
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "cert-manager.io".into(),
                "v1".into(),
                "default".into(),
                "certificates".into(),
                "patch-cert".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "patch_namespaced_resource_status must succeed via CR fallback key for unknown group"
        );

        let stored = store.get(cr_key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["conditions"][0]["type"], "Issued",
            "status must be patched via CR fallback key"
        );
        assert_eq!(
            v["spec"]["secretName"], "patch-tls",
            "spec must not be modified by status patch"
        );
    }

    /// put_resource_status returns 400 when the name parameter is empty.
    /// validate_name runs before any store access, so an empty name is rejected
    /// before touching the database — this prevents path-traversal store key attacks.
    #[tokio::test]
    async fn put_resource_status_rejects_empty_name() {
        let state = make_state();
        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "" },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "".into(), // empty name
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 400 for empty name"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::BAD_REQUEST,
            "empty name must return 400, not reach the store"
        );
    }

    /// Regression test for mayor-fvkg: PATCH resourcequotas/status updates status.used
    /// but must not touch spec.hard.
    ///
    /// The KCM's resourcequota controller patches this endpoint to record how many objects
    /// have been created against each quota. If the patch clobbers spec.hard, the quota's
    /// hard limits are lost and subsequent enforcement checks will allow unlimited creates.
    #[tokio::test]
    async fn patch_resourcequota_status_updates_used_not_spec() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "compute-quota", "namespace": "default", "resourceVersion": "1" },
            "spec": { "hard": { "pods": "10", "services": "5" } },
            "status": { "hard": { "pods": "10", "services": "5" }, "used": { "pods": "0", "services": "0" } }
        });
        let key = "/registry/resourcequotas/default/compute-quota";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // KCM quota controller patches status.used after a pod is created.
        let patch = serde_json::json!({
            "status": {
                "hard": { "pods": "10", "services": "5" },
                "used": { "pods": "1", "services": "0" }
            }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "resourcequotas".into(),
                "compute-quota".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PATCH resourcequotas/status must succeed so KCM quota controller can update used counts"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["status"]["used"]["pods"], "1",
            "status.used.pods must be updated to 1 after KCM patches it — \
             if not, kubectl describe quota shows stale counts and conformance polls forever"
        );
        assert_eq!(
            v["spec"]["hard"]["pods"], "10",
            "spec.hard must not be modified by a PATCH to /status — \
             status subresource isolation prevents controllers from accidentally overwriting limits"
        );
        assert_eq!(
            v["spec"]["hard"]["services"], "5",
            "spec.hard.services must survive a PATCH to /status"
        );
    }

    // ---------------------------------------------------------------------------
    // MockStore — injects RevisionMismatch on the first put() after arm() is called.
    //
    // Using Arc<SqliteStore> for inner so we can clone the handle into the async
    // block without borrowing self (SqliteStore is not Clone).
    // ---------------------------------------------------------------------------

    struct MockStore {
        inner: Arc<SqliteStore>,
        inject_next: std::sync::atomic::AtomicBool,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(SqliteStore::new(":memory:").unwrap()),
                inject_next: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn arm(&self) {
            self.inject_next
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl u7s_store::Store for MockStore {
        fn get(
            &self,
            key: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.get(&key).await }
        }

        fn list(
            &self,
            prefix: &str,
            opts: u7s_store::ListOptions,
        ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send
        {
            let inner = self.inner.clone();
            let prefix = prefix.to_string();
            async move { inner.list(&prefix, opts).await }
        }

        fn put(
            &self,
            key: &str,
            value: bytes::Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inject = self
                .inject_next
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            async move {
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
            key: &str,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.delete(&key, expected_revision).await }
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
    }

    /// put_resource_status returns 409 Conflict when the store rejects the write
    /// with RevisionMismatch (OCC: another writer updated the object concurrently).
    ///
    /// The handler must propagate RevisionMismatch as 409, not 500.  Without this
    /// guarantee, controllers that retry on 409 would instead see 500 and stop
    /// retrying, leaving the status field permanently stale.
    #[tokio::test]
    async fn put_resource_status_returns_409_on_revision_mismatch() {
        let mock = Arc::new(MockStore::new());
        // Seed a CSINode via the inner store (bypasses the inject flag).
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "node-occ" },
            "spec": { "drivers": [] }
        });
        mock.inner
            .put(
                "/registry/storage.k8s.io/csinodes/node-occ",
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Arm the mock so the next put() injects RevisionMismatch.
        mock.arm();

        let state = crate::state::AppState::new(
            mock,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "node-occ" },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "node-occ".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 409 but handler returned Ok"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "RevisionMismatch must produce 409 Conflict so controllers can retry"
        );
    }

    /// put_namespaced_resource_status returns 409 Conflict when the store rejects
    /// the write with RevisionMismatch.
    ///
    /// Same OCC contract as the cluster-scoped variant above, but exercising the
    /// namespaced code path which has its own lookup and put call.
    #[tokio::test]
    async fn put_namespaced_resource_status_returns_409_on_revision_mismatch() {
        let mock = Arc::new(MockStore::new());
        // Seed a Deployment via the inner store.
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "myapp", "namespace": "default" },
            "spec": { "replicas": 1, "selector": {"matchLabels": {"app": "myapp"}}, "template": {} }
        });
        mock.inner
            .put(
                "/registry/apps/deployments/default/myapp",
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Arm the mock so the next put() injects RevisionMismatch.
        mock.arm();

        let state = crate::state::AppState::new(
            mock,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "myapp", "namespace": "default" },
            "status": { "readyReplicas": 1 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "myapp".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 409 but handler returned Ok"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "RevisionMismatch must produce 409 Conflict so controllers can retry"
        );
    }

    /// Regression test for mayor-k7t4: PATCH /status on a ValidatingAdmissionPolicy must return
    /// exactly what the client sent in the patch, not a hardcoded Ready condition injected by
    /// write_vap_status.
    ///
    /// The conformance test at validatingadmissionpolicy.go:601 PATCHes status.conditions with a
    /// custom condition (PatchStatusFailed) and immediately reads the response body. If
    /// write_vap_status overwrites status after the store write, the client sees Ready instead of
    /// PatchStatusFailed and the conformance test fails.
    #[tokio::test]
    async fn vap_patch_status_preserves_client_conditions_not_overwritten_by_write_vap_status() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let vap = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {
                "name": "test-vap",
                "generation": 1
            },
            "spec": {
                "validations": [{"expression": "true"}]
            },
            "status": {}
        });
        let key = "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/test-vap";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&vap).unwrap()),
                None,
            )
            .await
            .unwrap();

        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Patch with a custom condition — exactly what the conformance test does.
        let patch = serde_json::json!({
            "status": {
                "conditions": [{"type": "PatchStatusFailed", "status": "False", "reason": "Test"}]
            }
        });
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "admissionregistration.k8s.io".into(),
                "v1".into(),
                "validatingadmissionpolicies".into(),
                "test-vap".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let resp = match result {
            Ok(r) => r.into_response(),
            Err(e) => panic!("PATCH /status on VAP must succeed, got: {e:?}"),
        };
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let conditions = v["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be an array in the response");
        assert_eq!(
            conditions.len(), 1,
            "conformance test polls for a custom status condition after PATCH /status; \
             if write_vap_status overwrites it the test sees Ready instead of PatchStatusFailed and fails"
        );
        assert_eq!(
            conditions[0]["type"], "PatchStatusFailed",
            "conformance test polls for a custom status condition after PATCH /status; \
             if write_vap_status overwrites it the test sees Ready instead of PatchStatusFailed and fails"
        );
    }
}
