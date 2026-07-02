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

/// Merge incoming metadata onto the current object's metadata, preserving fields that
/// must never change via a status subresource write.
///
/// Protected fields: identity fields (name, namespace, uid, creationTimestamp,
/// resourceVersion, generation) AND lifecycle-control fields (finalizers,
/// deletionTimestamp). A status write that changes finalizers can restore a finalizer
/// a peer controller just removed, causing livelock where the object stays Terminating
/// forever.
///
/// Restore semantics: if the field was absent (null) in the stored object, the field is
/// removed after merge even if the incoming body added it. If it was present, it is
/// restored to its stored value unconditionally.
pub(crate) fn merge_incoming_metadata(
    current: &mut serde_json::Value,
    incoming: &serde_json::Value,
) {
    let incoming_meta = &incoming["metadata"];
    if !incoming_meta.is_object() {
        return;
    }
    const PROTECTED: &[&str] = &[
        "name",
        "namespace",
        "uid",
        "creationTimestamp",
        "resourceVersion",
        "generation",
        "finalizers",
        "deletionTimestamp",
    ];
    let saved: Vec<(&str, serde_json::Value)> = PROTECTED
        .iter()
        .map(|&k| (k, current["metadata"][k].clone()))
        .collect();

    crate::patch::merge_patch(&mut current["metadata"], incoming_meta);

    for (k, v) in saved {
        if v.is_null() {
            if let Some(meta_obj) = current["metadata"].as_object_mut() {
                meta_obj.remove(k);
            }
        } else {
            current["metadata"][k] = v;
        }
    }
}

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

    // Replace status and merge metadata; leave spec and identity fields untouched.
    match &incoming.body["status"] {
        serde_json::Value::Null => {
            current.body.as_object_mut().map(|m| m.remove("status"));
        }
        v => {
            current.body["status"] = v.clone();
        }
    }
    merge_incoming_metadata(&mut current.body, &incoming.body);

    let expected_rv = parse_resource_version(incoming.resource_version())?;
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
            // Merge and strategic merge: apply status and metadata from the patch body.
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
            merge_incoming_metadata(&mut current.body, &patch);
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
    merge_incoming_metadata(&mut current.body, &incoming.body);

    let expected_rv = parse_resource_version(incoming.resource_version())?;
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
            // Merge and strategic merge: apply status and metadata from the patch body.
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
            merge_incoming_metadata(&mut current.body, &patch);
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

    /// Regression test for mayor-2z1k: PATCH/PUT poddisruptionbudgets/status must persist
    /// status.disruptedPods so the DisruptionController conformance test passes.
    ///
    /// The spec '[sig-apps] DisruptionController should update/patch PodDisruptionBudget status'
    /// writes status.disruptedPods['pod-0'] via the PDB /status subresource and reads back the
    /// key. If the handler wipes status (because the incoming proto-decoded body had null status),
    /// the read-back returns an empty map and the conformance test fails with:
    ///   `<map[string]v1.Time | len:0>: nil, expected key 'pod-0'`
    ///
    /// This test operates at the JSON level (the proto-decode layer is tested in proto.rs).
    /// It fails if put_namespaced_resource_status removes status when incoming status is non-null.
    #[tokio::test]
    async fn put_pdb_status_persists_disrupted_pods() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {
                "name": "my-pdb",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": { "minAvailable": 1 }
        });
        let key = "/registry/policy/poddisruptionbudgets/default/my-pdb";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb).unwrap()),
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

        // DisruptionController PUT /status body with disruptedPods set.
        let put_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "my-pdb", "namespace": "default" },
            "status": {
                "disruptedPods": { "pod-0": "2024-01-01T00:00:00Z" },
                "disruptionsAllowed": 0,
                "currentHealthy": 1,
                "desiredHealthy": 1,
                "expectedPods": 1
            }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "policy".into(),
                "v1".into(),
                "default".into(),
                "poddisruptionbudgets".into(),
                "my-pdb".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PUT poddisruptionbudgets/status must succeed — DisruptionController calls this \
             to record disrupted pods"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let disrupted_pods = v["status"]["disruptedPods"].as_object().expect(
            "status.disruptedPods must be present after PUT /status — \
             the conformance test reads it back and expects key 'pod-0'; \
             if missing the test fails with `<map[string]v1.Time | len:0>: nil`",
        );
        assert!(
            disrupted_pods.contains_key("pod-0"),
            "pod-0 must be in status.disruptedPods after PUT /status — \
             the DisruptionController conformance test fails if this key is absent"
        );

        // spec must be unchanged — status subresource isolation applies to PDB too
        assert_eq!(
            v["spec"]["minAvailable"], 1,
            "spec.minAvailable must not be modified by a PUT to /status"
        );
    }

    /// Regression test: PATCH poddisruptionbudgets/status with merge-patch must persist
    /// status.disruptedPods. The DisruptionController may use PATCH instead of PUT.
    ///
    /// This test fails if patch_namespaced_resource_status drops the status field when
    /// applying a merge-patch that includes status.disruptedPods.
    #[tokio::test]
    async fn patch_pdb_status_persists_disrupted_pods() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {
                "name": "patch-pdb",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": { "minAvailable": 2 },
            "status": {}
        });
        let key = "/registry/policy/poddisruptionbudgets/default/patch-pdb";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb).unwrap()),
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

        let patch = serde_json::json!({
            "status": {
                "disruptedPods": { "pod-0": "2024-01-01T00:00:00Z" },
                "disruptionsAllowed": 1,
                "currentHealthy": 2,
                "desiredHealthy": 2,
                "expectedPods": 2
            }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "policy".into(),
                "v1".into(),
                "default".into(),
                "poddisruptionbudgets".into(),
                "patch-pdb".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PATCH poddisruptionbudgets/status must succeed"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let disrupted_pods = v["status"]["disruptedPods"].as_object().expect(
            "status.disruptedPods must survive PATCH /status — \
             the DisruptionController conformance test fails if this field is absent after patch",
        );
        assert!(
            disrupted_pods.contains_key("pod-0"),
            "pod-0 must be in status.disruptedPods after PATCH /status"
        );
        assert_eq!(
            v["spec"]["minAvailable"], 2,
            "spec.minAvailable must not be changed by PATCH /status"
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
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, bytes::Bytes)>> + Send
        {
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

        fn current_revision(&self) -> u64 {
            self.inner.current_revision()
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

    /// PUT /status with metadata.annotations must persist the annotation.
    /// Controllers (e.g. CronJob) set annotations via /status; dropping them causes
    /// the CronJob conformance test to fail because it asserts the annotation is present
    /// after the PUT returns 200.
    #[tokio::test]
    async fn put_namespaced_status_persists_metadata_annotations() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let cronjob = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {
                "name": "test-cj",
                "namespace": "default",
                "uid": "abc-123",
                "resourceVersion": "1"
            },
            "spec": { "schedule": "* * * * *" },
            "status": {}
        });
        let key = "/registry/batch/cronjobs/default/test-cj";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&cronjob).unwrap()),
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
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {
                "name": "test-cj",
                "namespace": "default",
                "annotations": { "patchedstatus": "true" }
            },
            "status": { "active": [] }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "batch".into(),
                "v1".into(),
                "default".into(),
                "cronjobs".into(),
                "test-cj".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["annotations"]["patchedstatus"], "true",
            "annotation set via PUT /status must be stored; \
             dropping it breaks CronJob conformance which sets annotations this way"
        );
        assert_eq!(
            v["status"]["active"],
            serde_json::json!([]),
            "status must be updated"
        );
        assert_eq!(
            v["spec"]["schedule"], "* * * * *",
            "spec must not be modified by /status PUT"
        );
        assert_eq!(
            v["metadata"]["uid"], "abc-123",
            "uid must not change via /status PUT"
        );
    }

    /// PATCH /status (merge-patch) with metadata.annotations must persist the annotation.
    /// Same contract as PUT; this is the path taken by kubectl patch --subresource=status.
    #[tokio::test]
    async fn patch_namespaced_status_persists_metadata_annotations() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let cronjob = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {
                "name": "ann-cj",
                "namespace": "default",
                "uid": "def-456",
                "resourceVersion": "1"
            },
            "spec": { "schedule": "*/5 * * * *" },
            "status": {}
        });
        let key = "/registry/batch/cronjobs/default/ann-cj";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&cronjob).unwrap()),
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

        let patch = serde_json::json!({
            "metadata": { "annotations": { "xzmpcheck": "ok" } },
            "status": { "lastScheduleTime": "2024-01-01T00:00:00Z" }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "batch".into(),
                "v1".into(),
                "default".into(),
                "cronjobs".into(),
                "ann-cj".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PATCH /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["annotations"]["xzmpcheck"], "ok",
            "annotation set via PATCH /status must be stored; \
             dropping it breaks kubectl patch --subresource=status and CronJob conformance"
        );
        assert_eq!(
            v["status"]["lastScheduleTime"], "2024-01-01T00:00:00Z",
            "status must also be updated alongside metadata"
        );
        assert_eq!(
            v["spec"]["schedule"], "*/5 * * * *",
            "spec must not change from /status PATCH"
        );
        assert_eq!(
            v["metadata"]["uid"], "def-456",
            "uid must not change via /status PATCH"
        );
    }

    /// PATCH /status must NOT apply spec even if the body contains a spec field.
    /// A controller that accidentally includes spec in its /status PATCH must not
    /// corrupt the stored spec — spec isolation is what makes the status subresource safe.
    #[tokio::test]
    async fn patch_namespaced_status_ignores_spec_in_body() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "safe-deploy", "namespace": "default", "resourceVersion": "1" },
            "spec": { "replicas": 3 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/safe-deploy";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
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

        let patch = serde_json::json!({
            "spec": { "replicas": 99 },
            "status": { "readyReplicas": 3 }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "safe-deploy".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PATCH /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["replicas"], 3,
            "spec must be unchanged after PATCH /status even when spec is in the patch body; \
             status subresource isolation prevents controllers from corrupting spec"
        );
        assert_eq!(v["status"]["readyReplicas"], 3, "status must be updated");
    }

    /// PUT /status must NOT apply spec from the incoming body.
    /// The stored spec must survive — status subresource writes only touch status+metadata.
    #[tokio::test]
    async fn put_resource_status_ignores_spec_in_body() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "specguard-node", "resourceVersion": "1" },
            "spec": { "drivers": [{"name": "csi.io"}] }
        });
        let key = "/registry/storage.k8s.io/csinodes/specguard-node";
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

        let put_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "specguard-node", "annotations": { "x": "y" } },
            "spec": { "drivers": [] },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "specguard-node".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["drivers"][0]["name"], "csi.io",
            "spec from the stored object must survive a PUT /status that contains a different spec"
        );
        assert_eq!(
            v["metadata"]["annotations"]["x"], "y",
            "annotation from PUT body must be applied"
        );
        assert_eq!(v["status"]["ready"], true, "status must be updated");
    }

    /// PUT /status must not let a status write overwrite immutable identity (uid).
    /// If uid could be changed via /status, a compromised controller could silently
    /// re-point a resource to a different object identity, breaking GC and admission.
    #[tokio::test]
    async fn put_namespaced_status_does_not_overwrite_uid() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "uid-guard", "namespace": "default", "uid": "real-uid-1", "resourceVersion": "1" },
            "spec": { "replicas": 1 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/uid-guard";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
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
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "uid-guard", "namespace": "default", "uid": "attacker-uid", "annotations": { "safe": "yes" } },
            "status": { "readyReplicas": 1 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "uid-guard".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["uid"], "real-uid-1",
            "uid must not be overwritten by a status write; \
             allowing uid changes via /status would break GC and object identity guarantees"
        );
        assert_eq!(
            v["metadata"]["annotations"]["safe"], "yes",
            "non-identity annotations must still land"
        );
    }

    /// PUT /status on a cluster-scoped resource must not overwrite finalizers or deletionTimestamp.
    /// A status PUT that clears finalizers can race with a peer controller that just removed a
    /// finalizer, restoring it and causing the object to be stuck Terminating forever (livelock).
    #[tokio::test]
    async fn put_resource_status_preserves_finalizers_and_deletion_timestamp() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "fin-node",
                "resourceVersion": "1",
                "finalizers": ["storage.kubernetes.io/csinode-protection"],
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/fin-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
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
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "fin-node",
                "finalizers": [],
                "deletionTimestamp": "2099-12-31T00:00:00Z"
            },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "fin-node".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["finalizers"][0], "storage.kubernetes.io/csinode-protection",
            "finalizers must survive PUT /status — a status PUT that clears finalizers can \
             restore a just-removed finalizer causing the object to be stuck Terminating forever (livelock)"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2024-01-01T00:00:00Z",
            "deletionTimestamp must survive PUT /status — changing it via status would allow \
             a controller to bypass the graceful deletion lifecycle"
        );
    }

    /// PUT /status on a namespaced resource must not overwrite finalizers or deletionTimestamp.
    /// Same livelock risk as the cluster-scoped path: if a controller PUT /status and the body
    /// reflects an older version of the object that still has a finalizer a peer just removed,
    /// the finalizer is restored and the object is stuck Terminating forever.
    #[tokio::test]
    async fn put_namespaced_resource_status_preserves_finalizers_and_deletion_timestamp() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "fin-deploy",
                "namespace": "default",
                "resourceVersion": "1",
                "finalizers": ["foregroundDeletion"],
                "deletionTimestamp": "2024-06-01T00:00:00Z"
            },
            "spec": { "replicas": 1 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/fin-deploy";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
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
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "fin-deploy",
                "namespace": "default",
                "finalizers": [],
                "deletionTimestamp": "2099-01-01T00:00:00Z"
            },
            "status": { "readyReplicas": 1 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "fin-deploy".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["finalizers"][0], "foregroundDeletion",
            "finalizers must survive PUT /namespaced/status — a status PUT that clears finalizers \
             can restore a just-removed finalizer causing the object to be stuck Terminating forever (livelock)"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2024-06-01T00:00:00Z",
            "deletionTimestamp must survive PUT /namespaced/status"
        );
    }

    // ---------------------------------------------------------------------------
    // PVC status.conditions must be persisted via /status subresource (mayor-r83x)
    // ---------------------------------------------------------------------------

    /// PATCH /pvc/status with conditions must persist the conditions so they are
    /// present on subsequent GET.
    ///
    /// The conformance spec '[sig-storage] PersistentVolumes CSI Conformance should
    /// apply changes to a pv/pvc status [Conformance]' (storage/persistent_volumes.go:789)
    /// patches PVC /status with a condition {type: "StatusUpdated"} and then reads it
    /// back.  If the condition is not persisted, the test fails with
    /// "got conditions=nil, expected StatusUpdated".
    ///
    /// This test fails if the merge_patch path in patch_namespaced_resource_status
    /// does not propagate status.conditions to the stored object.
    #[tokio::test]
    async fn pvc_status_conditions_persisted_via_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed a PVC with initial status.phase=Pending (as apply_defaults would set).
        let pvc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": "my-pvc",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "1Gi" } }
            },
            "status": { "phase": "Pending" }
        });
        let key = "/registry/persistentvolumeclaims/default/my-pvc";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pvc).unwrap()),
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

        // PATCH /pvc/status with a CSI condition.
        let patch = serde_json::json!({
            "status": {
                "conditions": [
                    {
                        "type": "StatusUpdated",
                        "status": "True",
                        "reason": "CSITest",
                        "message": "applied by conformance test"
                    }
                ]
            }
        });

        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
                "my-pvc".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PATCH /pvc/status must succeed — got: {:?}",
            result.err()
        );

        // Verify the conditions are now stored.
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let conditions = v["status"]["conditions"].as_array().expect(
            "status.conditions must be an array after PATCH /pvc/status — \
                 the conformance test '[sig-storage] PersistentVolumes CSI Conformance should \
                 apply changes to a pv/pvc status' checks conditions != nil after the patch; \
                 nil conditions means the PATCH did not persist",
        );
        assert_eq!(
            conditions.len(),
            1,
            "exactly one condition must be stored after PATCH"
        );
        assert_eq!(
            conditions[0]["type"], "StatusUpdated",
            "condition type must be StatusUpdated — if this fails, patch_namespaced_resource_status \
             is not merging status.conditions into the stored PVC object"
        );

        // The original phase must still be present (merge-patch preserves existing keys).
        assert_eq!(
            v["status"]["phase"], "Pending",
            "status.phase must survive the PATCH — merge-patch must not wipe existing status keys"
        );

        // Spec must be untouched.
        assert_eq!(
            v["spec"]["accessModes"][0], "ReadWriteOnce",
            "spec must be unchanged after PATCH /pvc/status"
        );
    }

    /// PUT /pvc/status with conditions replaces status and conditions are readable.
    ///
    /// The CSI provisioner may use PUT instead of PATCH to set PVC status conditions.
    /// If PUT /pvc/status doesn't persist conditions, CSI provisioning status is invisible.
    ///
    /// This test fails if put_namespaced_resource_status does not replace the status
    /// field with the incoming value when that value contains conditions.
    #[tokio::test]
    async fn pvc_status_conditions_persisted_via_put() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let pvc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": "put-pvc",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "2Gi" } }
            },
            "status": { "phase": "Pending" }
        });
        let key = "/registry/persistentvolumeclaims/default/put-pvc";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pvc).unwrap()),
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

        // PUT /pvc/status with phase=Bound and conditions.
        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "put-pvc", "namespace": "default" },
            "status": {
                "phase": "Bound",
                "conditions": [
                    { "type": "StatusUpdated", "status": "True" }
                ]
            }
        });

        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
                "put-pvc".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PUT /pvc/status must succeed — got: {:?}",
            result.err()
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["status"]["phase"], "Bound",
            "status.phase must be Bound after PUT /pvc/status"
        );
        let conditions = v["status"]["conditions"].as_array().expect(
            "status.conditions must be present after PUT /pvc/status — \
             if nil, the PUT did not replace status with the incoming value",
        );
        assert_eq!(
            conditions[0]["type"], "StatusUpdated",
            "condition type must be StatusUpdated after PUT /pvc/status"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests for mayor-8phw: subresource PUT CAS must use the INCOMING
    // body's resourceVersion, not the stored object's.  Without this fix, a writer
    // holding a stale RV can overwrite a newer write (concurrent clobber) instead
    // of receiving 409 Conflict and retrying from a fresh GET.
    // ---------------------------------------------------------------------------

    /// put_resource_status with a stale resourceVersion in the body must return 409 Conflict.
    ///
    /// Without this fix the handler used the stored object's RV as the CAS token, making
    /// every PUT unconditional — a controller holding stale state would silently overwrite
    /// a peer's concurrent write instead of receiving 409 and retrying from a fresh GET.
    #[tokio::test]
    async fn put_resource_status_stale_rv_returns_409_else_concurrent_writers_clobber() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "rv-test-node" },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/rv-test-node";
        // First write gives rv=1.
        let rv1 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                None,
            )
            .await
            .unwrap();
        // Second write advances to rv=2 (simulates a concurrent writer).
        let mut obj2 = obj.clone();
        obj2["metadata"]["resourceVersion"] = serde_json::json!(rv1.to_string());
        let rv2 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance after second write");

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // PUT body carries the now-stale rv1 — must be rejected with 409.
        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "rv-test-node", "resourceVersion": rv1.to_string() },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "rv-test-node".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "stale-rv PUT to put_resource_status must return 409 — \
                 without this check concurrent controllers silently clobber each other"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "stale resourceVersion in PUT /status body must produce 409 Conflict, \
             not 200 — controllers must retry from a fresh GET when they lose the CAS race"
        );
    }

    /// put_resource_status with an absent resourceVersion in the body succeeds unconditionally.
    ///
    /// Clients that legitimately omit resourceVersion (e.g. single-writer bootstrapping)
    /// must not be broken by the stale-RV fix.  parse_resource_version returns None for
    /// absent/empty rv, and the store treats None as unconditional.
    #[tokio::test]
    async fn put_resource_status_absent_rv_is_unconditional_write() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "no-rv-node" },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/no-rv-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
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

        // Body has no resourceVersion — must succeed (unconditional write).
        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "no-rv-node" },
            "status": { "ready": false }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "no-rv-node".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "absent resourceVersion in PUT /status body must succeed (unconditional write) — \
             single-writer bootstrap clients must not be broken by the stale-RV fix"
        );
    }

    /// put_namespaced_resource_status with a stale resourceVersion in the body must return 409.
    ///
    /// This is the PDB conformance scenario: the DisruptionController holds a snapshot at rv=R0,
    /// the test's UpdateStatus advances the store to R1, then the controller's stale PUT (still
    /// body rv=R0) must get 409 so it retries with a fresh GET and preserves disruptedPods.
    /// Without this fix the controller's write was accepted unconditionally, wiping disruptedPods.
    #[tokio::test]
    async fn put_namespaced_resource_status_stale_rv_returns_409_else_concurrent_writers_clobber() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "cas-pdb", "namespace": "default" },
            "spec": { "minAvailable": 1 }
        });
        let key = "/registry/policy/poddisruptionbudgets/default/cas-pdb";
        let rv1 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();
        // Advance the store to rv2 (peer writer succeeded).
        let mut pdb2 = pdb.clone();
        pdb2["metadata"]["resourceVersion"] = serde_json::json!(rv1.to_string());
        let rv2 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance after second write");

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // PUT body carries the now-stale rv1 — must be rejected with 409.
        let body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "cas-pdb", "namespace": "default", "resourceVersion": rv1.to_string() },
            "status": { "disruptedPods": {}, "disruptionsAllowed": 1 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "policy".into(),
                "v1".into(),
                "default".into(),
                "poddisruptionbudgets".into(),
                "cas-pdb".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "stale-rv PUT to put_namespaced_resource_status must return 409 — \
                 the PDB conformance test fails when the DisruptionController's stale write \
                 is accepted unconditionally and wipes disruptedPods"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "stale resourceVersion in namespaced PUT /status body must produce 409 — \
             controllers must retry from fresh GET, not silently clobber concurrent writes"
        );
    }

    /// put_namespaced_resource_status with an absent resourceVersion in the body succeeds.
    ///
    /// Upstream k8s allows omitting resourceVersion in a subresource PUT, treating it as
    /// an unconditional write.  The fix must not break this.
    #[tokio::test]
    async fn put_namespaced_resource_status_absent_rv_is_unconditional_write() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "norev-pdb", "namespace": "default" },
            "spec": { "minAvailable": 1 }
        });
        let key = "/registry/policy/poddisruptionbudgets/default/norev-pdb";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb).unwrap()),
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

        // No resourceVersion in body — must succeed unconditionally.
        let body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "norev-pdb", "namespace": "default" },
            "status": { "disruptionsAllowed": 2 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "policy".into(),
                "v1".into(),
                "default".into(),
                "poddisruptionbudgets".into(),
                "norev-pdb".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "absent resourceVersion in namespaced PUT /status body must succeed (unconditional) — \
             clients that omit rv must not be broken by the stale-RV CAS fix"
        );
    }
}
