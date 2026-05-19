use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store, StoreError};

use crate::{
    keys::{cluster_list_prefix, cluster_object_key},
    state::AppState,
    status::Status,
    types::Object,
    util::{extract_body, utc_now_rfc3339},
};

/// Validate a namespace name: lowercase alphanumeric + hyphens, 1–63 chars.
/// Returns Err with 422 if invalid.
fn validate_namespace_name(name: &str) -> Result<(), crate::status::StatusError> {
    if name.is_empty() || name.len() > 63 {
        return Err(Status::unprocessable_entity(format!(
            "invalid namespace name '{name}': must be 1–63 characters"
        )));
    }
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(Status::unprocessable_entity(format!(
            "invalid namespace name '{name}': must match [a-z0-9-]+"
        )));
    }
    Ok(())
}

fn store_err_to_status(err: StoreError, name: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, "Namespace"),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, "Namespace"),
        StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "Namespace \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => Status::internal(other.to_string()),
    }
}

fn parse_resource_version(rv: Option<&str>) -> Result<Option<u64>, crate::status::StatusError> {
    match rv {
        None | Some("") => Ok(None),
        Some("0") => Ok(Some(0)),
        Some(s) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|_| Status::bad_request(format!("invalid resourceVersion: {s}"))),
    }
}

fn merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (Some(t), Some(p)) = (target.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            if v.is_null() {
                t.remove(k);
            } else if v.is_object() {
                let entry = t
                    .entry(k)
                    .or_insert(serde_json::Value::Object(Default::default()));
                merge_patch(entry, v);
            } else {
                t.insert(k.clone(), v.clone());
            }
        }
    } else {
        *target = patch.clone();
    }
}

pub async fn list_namespaces(
    State(state): State<AppState>,
    Query(query): Query<super::generic::CollectionQuery>,
) -> Result<Response, crate::status::StatusError> {
    let prefix = cluster_list_prefix("namespaces");

    if query.watch == Some(true) {
        return super::generic::watch_generic(
            state,
            prefix,
            "v1".to_string(),
            "Namespace".to_string(),
            query.resource_version.unwrap_or(0),
        )
        .await;
    }

    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut items = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(v);
    }

    let body = serde_json::json!({
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items
    });

    Ok(Json(body).into_response())
}

pub async fn create_namespace(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = obj
        .name()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Status::bad_request("metadata.name is required".into()))?
        .to_string();

    validate_namespace_name(&name)?;

    // Ensure kind/apiVersion and status are set
    if obj.body.get("kind").is_none() {
        obj.body["kind"] = serde_json::Value::String("Namespace".into());
    }
    if obj.body.get("apiVersion").is_none() {
        obj.body["apiVersion"] = serde_json::Value::String("v1".into());
    }
    if obj.body["status"].is_null() || obj.body.get("status").is_none() {
        obj.body["status"] = serde_json::json!({ "phase": "Active" });
    }

    let key = cluster_object_key("namespaces", &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), Some(0))
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok((StatusCode::CREATED, Json(obj.body)))
}

pub async fn get_namespace(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Response, crate::status::StatusError> {
    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn replace_namespace(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj.name().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let expected_revision = parse_resource_version(obj.resource_version())?;

    let key = cluster_object_key("namespaces", &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok(Json(obj.body))
}

pub async fn patch_namespace(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("application/merge-patch+json") {
        return Err(Status::unsupported_media_type(format!(
            "unsupported media type '{content_type}'; use application/merge-patch+json"
        )));
    }

    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    merge_patch(&mut current.body, &patch);

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current.set_resource_version(new_rv);

    Ok(Json(current.body))
}

pub async fn delete_namespace(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let key = cluster_object_key("namespaces", &name);

    // Fetch current to get finalizers and to return the Terminating state.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // Stamp Terminating phase and deletionTimestamp (emits MODIFIED watch event on write-back).
    obj.body["status"]["phase"] = serde_json::Value::String("Terminating".into());
    obj.body["metadata"]["deletionTimestamp"] = serde_json::Value::String(utc_now_rfc3339());

    let expected_rv = parse_resource_version(obj.resource_version())?;
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;
    obj.set_resource_version(new_rv);

    // If no finalizers, hard-delete immediately (emits DELETED watch event).
    let has_finalizers = obj.body["metadata"]["finalizers"]
        .as_array()
        .map(|arr| !arr.is_empty())
        .unwrap_or(false);

    if !has_finalizers {
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
    }

    Ok(Json(obj.body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_namespace_names() {
        assert!(validate_namespace_name("default").is_ok());
        assert!(validate_namespace_name("kube-system").is_ok());
        assert!(validate_namespace_name("a").is_ok());
        assert!(validate_namespace_name(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn invalid_namespace_names() {
        // empty
        assert!(validate_namespace_name("").is_err());
        // too long
        assert!(validate_namespace_name(&"a".repeat(64)).is_err());
        // uppercase rejected
        assert!(validate_namespace_name("Default").is_err());
        // underscore rejected
        assert!(validate_namespace_name("my_ns").is_err());
        // dot rejected
        assert!(validate_namespace_name("my.ns").is_err());
    }

    #[test]
    fn invalid_returns_422() {
        let err = validate_namespace_name("Bad_Name").unwrap_err();
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // -- delete_namespace --

    async fn make_state() -> (crate::state::AppState, std::sync::Arc<u7s_store::SqliteStore>) {
        let store = std::sync::Arc::new(u7s_store::SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(store.clone(), None, None, std::collections::HashMap::new(), "https://localhost:6443".into());
        (state, store)
    }

    /// delete_namespace on a non-existent namespace must return 404.
    #[tokio::test]
    async fn delete_namespace_not_found_returns_404() {
        use axum::extract::{Path, State};
        let (state, _store) = make_state().await;
        let result = delete_namespace(State(state), Path("missing-ns".to_string())).await;
        match result {
            Err(e) => assert_eq!(e.0, StatusCode::NOT_FOUND),
            Ok(_) => panic!("expected 404"),
        }
    }

    /// delete_namespace on an existing namespace (no finalizers) must:
    /// - return 200 with the namespace body in Terminating phase,
    /// - remove the namespace from the store (hard-delete after Terminating stamp).
    #[tokio::test]
    async fn delete_namespace_returns_terminating_body_and_removes_from_store() {
        use axum::extract::{Path, State};
        let (state, store) = make_state().await;

        let key = "/registry/namespaces/my-ns";
        let ns_obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "my-ns" },
            "status": { "phase": "Active" }
        });
        store.put(key, bytes::Bytes::from(serde_json::to_vec(&ns_obj).unwrap()), None).await.unwrap();

        let result = delete_namespace(State(state), Path("my-ns".to_string())).await;
        assert!(result.is_ok(), "delete_namespace must succeed for existing namespace");

        // Namespace must be gone (no finalizers → hard-deleted after Terminating stamp)
        let still_there = store.get(key).await.unwrap();
        assert!(still_there.is_none(), "namespace with no finalizers must be removed after delete");
    }

    /// delete_namespace on a namespace with finalizers must soft-delete:
    /// write Terminating state back but NOT remove from store.
    #[tokio::test]
    async fn delete_namespace_with_finalizers_stays_in_store_as_terminating() {
        use axum::extract::{Path, State};
        let (state, store) = make_state().await;

        let key = "/registry/namespaces/finalized-ns";
        let ns_obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "finalized-ns",
                "finalizers": ["kubernetes"]
            },
            "status": { "phase": "Active" }
        });
        store.put(key, bytes::Bytes::from(serde_json::to_vec(&ns_obj).unwrap()), None).await.unwrap();

        let result = delete_namespace(State(state), Path("finalized-ns".to_string())).await;
        assert!(result.is_ok(), "delete_namespace must succeed with finalizers present");

        // Namespace must still be in the store
        let stored = store.get(key).await.unwrap().expect("namespace must persist when finalizers present");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["phase"],
            "Terminating",
            "status.phase must be Terminating after delete with finalizers"
        );
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must be set"
        );
    }

    // When ?watch=true, list_namespaces must route to the watch stream (chunked transfer)
    // rather than returning a normal NamespaceList JSON. This ensures clients that open
    // a watch on /api/v1/namespaces actually receive a streaming response.
    #[tokio::test]
    async fn list_namespaces_watch_returns_chunked_stream() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;
        use crate::state::AppState;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(store, None, None, std::collections::HashMap::new(), "https://localhost:6443".into());

        let query = crate::handlers::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
        };

        let resp = match list_namespaces(State(state), Query(query)).await {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        // watch_generic always sets transfer-encoding: chunked
        assert_eq!(
            resp.headers().get("transfer-encoding").and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "watch response must use chunked transfer encoding"
        );
    }
}
