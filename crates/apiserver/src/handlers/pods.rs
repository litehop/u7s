use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde::Deserialize;
use u7s_store::{ListOptions, Store, StoreError};

use crate::{
    keys::{list_prefix, object_key},
    state::AppState,
    status::Status,
    types::Object,
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    pub watch: Option<bool>,
}

#[derive(Deserialize)]
pub struct NsParams {
    pub ns: String,
}

#[derive(Deserialize)]
pub struct NsNameParams {
    pub ns: String,
    pub name: String,
}

fn validate_namespace(ns: &str) -> Result<(), crate::status::StatusError> {
    if ns != "default" {
        return Err(Status::bad_request(format!(
            "only the 'default' namespace is supported in Phase 1; got '{ns}'"
        )));
    }
    Ok(())
}

fn store_err_to_status(err: StoreError, name: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, "Pod"),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, "Pod"),
        StoreError::RevisionMismatch { expected, current } => {
            Status::conflict(format!(
                "Pod \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
            ))
        }
        other => Status::internal(other.to_string()),
    }
}

pub async fn list_pods(
    State(state): State<AppState>,
    Path(NsParams { ns }): Path<NsParams>,
    Query(query): Query<CollectionQuery>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    if query.watch == Some(true) {
        return Err(Status::bad_request("watch is not supported in Phase 1".into()));
    }
    validate_namespace(&ns)?;

    let prefix = list_prefix("pods", &ns);
    let resp = state.store.list(&prefix, ListOptions::default()).await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut items = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let parsed: serde_json::Value = serde_json::from_slice(&obj.value)
            .map_err(|e| Status::internal(e.to_string()))?;
        items.push(parsed);
    }

    let body = serde_json::json!({
        "kind": "PodList",
        "apiVersion": "v1",
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items
    });

    Ok(Json(body))
}

pub async fn create_pod(
    State(state): State<AppState>,
    Path(NsParams { ns }): Path<NsParams>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_namespace(&ns)?;

    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = obj.name()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Status::bad_request("metadata.name is required".into()))?
        .to_string();

    // Ensure namespace is set in the stored object
    obj.body["metadata"]["namespace"] = serde_json::Value::String("default".to_string());

    let key = object_key("pods", "default", &name);
    let new_rv = state.store.put(&key, obj.to_bytes(), Some(0)).await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok((StatusCode::CREATED, Json(obj.body)))
}

pub async fn get_pod(
    State(state): State<AppState>,
    Path(NsNameParams { ns, name }): Path<NsNameParams>,
) -> Result<Response, crate::status::StatusError> {
    validate_namespace(&ns)?;

    let key = object_key("pods", "default", &name);
    let stored = state.store.get(&key).await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    ).into_response())
}

pub async fn replace_pod(
    State(state): State<AppState>,
    Path(NsNameParams { ns, name }): Path<NsNameParams>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_namespace(&ns)?;

    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj.name().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let expected_revision = match obj.resource_version() {
        None | Some("") => None,
        Some("0") => Some(0),
        Some(rv) => {
            let parsed = rv.parse::<u64>().map_err(|_| {
                Status::bad_request(format!("invalid resourceVersion: {rv}"))
            })?;
            Some(parsed)
        }
    };

    let key = object_key("pods", "default", &name);
    let new_rv = state.store.put(&key, obj.to_bytes(), expected_revision).await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok(Json(obj.body))
}

pub async fn delete_pod(
    State(state): State<AppState>,
    Path(NsNameParams { ns, name }): Path<NsNameParams>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_namespace(&ns)?;

    let key = object_key("pods", "default", &name);
    state.store.delete(&key, None).await
        .map_err(|e| store_err_to_status(e, &name))?;

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

pub async fn patch_pod(
    State(state): State<AppState>,
    Path(NsNameParams { ns, name }): Path<NsNameParams>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Check Content-Type
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/strategic-merge-patch+json") {
        return Err(Status::bad_request(
            "strategic merge patch not supported in Phase 1; use kubectl replace instead of kubectl apply".into()
        ));
    }

    if !content_type.contains("application/merge-patch+json") {
        return Err(Status::unsupported_media_type(
            format!("unsupported media type '{content_type}'; use application/merge-patch+json")
        ));
    }

    validate_namespace(&ns)?;

    let key = object_key("pods", "default", &name);
    let stored = state.store.get(&key).await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut current_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    json_merge_patch(&mut current_obj.body, &patch);

    // Extract expected revision from current object (after patch may have changed it)
    let expected_revision = match current_obj.resource_version() {
        None | Some("") => None,
        Some("0") => Some(0),
        Some(rv) => {
            let parsed = rv.parse::<u64>().map_err(|_| {
                Status::bad_request(format!("invalid resourceVersion in patched object: {rv}"))
            })?;
            Some(parsed)
        }
    };

    let new_rv = state.store.put(&key, current_obj.to_bytes(), expected_revision).await
        .map_err(|e| store_err_to_status(e, &name))?;

    current_obj.set_resource_version(new_rv);

    Ok(Json(current_obj.body))
}

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
