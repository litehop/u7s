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

pub async fn get_resource_status(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    // Same as get_resource; status is embedded in the object.
    get_resource(State(state), Path((group, version, plural, name))).await
}

pub async fn put_resource_status(
    State(state): State<AppState>,
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

pub async fn patch_resource_status(
    State(state): State<AppState>,
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

pub async fn get_namespaced_resource_status(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    // Same as get_namespaced_resource; status is embedded in the object.
    get_namespaced_resource(State(state), Path((group, version, ns, plural, name))).await
}

pub async fn put_namespaced_resource_status(
    State(state): State<AppState>,
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

pub async fn patch_namespaced_resource_status(
    State(state): State<AppState>,
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

    /// Gateway API controllers PATCH status on namespaced Gateway CRs via /status route.
    /// The group is not in the static resource registry, so patch_namespaced_resource_status
    /// must fall back to the CR store key.
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
        let cr_key = format!("/registry/cr/{group}/{version}/{plural}/{ns}/{name}");

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
            .put(&cr_key, initial_bytes, None)
            .await
            .expect("seed Gateway CR");

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
            "Gateway CR status PATCH must succeed via CR fallback"
        );

        let stored = store
            .get(&cr_key)
            .await
            .expect("store get")
            .expect("CR must exist");
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
}
