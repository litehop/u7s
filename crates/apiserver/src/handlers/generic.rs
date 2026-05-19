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
    keys::{group_list_prefix, group_object_key},
    state::AppState,
    status::Status,
    types::{Object, ResourceKey},
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    pub watch: Option<bool>,
    pub label_selector: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn lookup<'a>(
    state: &'a AppState,
    group: &str,
    version: &str,
    plural: &str,
) -> Result<&'a crate::types::ResourceMeta, crate::status::StatusError> {
    let key = ResourceKey {
        group: group.to_string(),
        version: version.to_string(),
        plural: plural.to_string(),
    };
    state
        .resource_registry
        .get(&key)
        .ok_or_else(|| {
            Status::not_found(
                &format!("{}/{}/{}", group, version, plural),
                "Resource",
            )
        })
}

fn store_err(err: StoreError, name: &str, kind: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, kind),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, kind),
        StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "{kind} \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => Status::internal(other.to_string()),
    }
}

fn check_watch(query: &CollectionQuery) -> Result<(), crate::status::StatusError> {
    if query.watch == Some(true) {
        return Err(Status::bad_request("watch is not supported in Phase 1".into()));
    }
    Ok(())
}

/// Parse a label selector string of the form `key=value,key2=value2` into key-value pairs.
/// Only simple equality selectors are supported. Returns an error on malformed input.
fn parse_label_selector(selector: &str) -> Result<Vec<(&str, &str)>, crate::status::StatusError> {
    let mut pairs = Vec::new();
    for part in selector.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut it = part.splitn(2, '=');
        let key = it.next().unwrap_or("").trim();
        let val = it.next().ok_or_else(|| {
            Status::bad_request(format!("invalid label selector '{part}': expected key=value"))
        })?.trim();
        if key.is_empty() {
            return Err(Status::bad_request(format!("invalid label selector '{part}': empty key")));
        }
        pairs.push((key, val));
    }
    Ok(pairs)
}

/// Filter `items` by label selector pairs. Keeps only items where all key=value pairs match
/// the object's `metadata.labels` map.
fn apply_label_selector(
    items: Vec<serde_json::Value>,
    pairs: &[(&str, &str)],
) -> Vec<serde_json::Value> {
    if pairs.is_empty() {
        return items;
    }
    items
        .into_iter()
        .filter(|item| {
            let labels = &item["metadata"]["labels"];
            pairs.iter().all(|(k, v)| {
                labels.get(*k).and_then(|lv| lv.as_str()) == Some(*v)
            })
        })
        .collect()
}

pub fn parse_resource_version(rv: Option<&str>) -> Result<Option<u64>, crate::status::StatusError> {
    match rv {
        None | Some("") => Ok(None),
        Some("0") => Ok(Some(0)),
        Some(s) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|_| Status::bad_request(format!("invalid resourceVersion: {s}"))),
    }
}

fn build_list_response(
    kind: &str,
    group: &str,
    version: &str,
    revision: u64,
    items: Vec<serde_json::Value>,
) -> serde_json::Value {
    let api_version = if group.is_empty() {
        version.to_string()
    } else {
        format!("{}/{}", group, version)
    };
    serde_json::json!({
        "kind": format!("{}List", kind),
        "apiVersion": api_version,
        "metadata": { "resourceVersion": revision.to_string() },
        "items": items
    })
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

/// Check finalizers for delete: if non-empty, set deletionTimestamp and return modified object.
/// Returns `None` if hard-delete should proceed, `Some(obj)` if soft-delete was applied.
fn apply_delete_policy(obj: &mut Object) -> Option<serde_json::Value> {
    let has_finalizers = obj.body["metadata"]["finalizers"]
        .as_array()
        .map(|arr| !arr.is_empty())
        .unwrap_or(false);

    if has_finalizers {
        // Soft delete: stamp deletionTimestamp.
        let now = utc_now_rfc3339();
        obj.body["metadata"]["deletionTimestamp"] = serde_json::Value::String(now);
        Some(obj.body.clone())
    } else {
        None
    }
}

use crate::util::utc_now_rfc3339;

const RBAC_GROUP: &str = "rbac.authorization.k8s.io";

/// Build the RBAC index key for a cluster-scoped object.
fn rbac_cluster_key(group: &str, version: &str, plural: &str, name: &str) -> String {
    format!("/apis/{group}/{version}/{plural}/{name}")
}

/// Build the RBAC index key for a namespaced object.
fn rbac_namespaced_key(group: &str, version: &str, ns: &str, plural: &str, name: &str) -> String {
    format!("/apis/{group}/{version}/namespaces/{ns}/{plural}/{name}")
}

// ---------------------------------------------------------------------------
// Cluster-scoped handlers  (group/version/resource)
// ---------------------------------------------------------------------------

pub async fn list_resource(
    State(state): State<AppState>,
    Path((group, version, plural)): Path<(String, String, String)>,
    Query(query): Query<CollectionQuery>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    check_watch(&query)?;
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let prefix = group_list_prefix(&group, &plural, None);
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

    let items = if let Some(ref sel) = query.label_selector {
        let pairs = parse_label_selector(sel)?;
        apply_label_selector(items, &pairs)
    } else {
        items
    };

    let body = build_list_response(&meta.kind, &group, &version, resp.revision, items);
    Ok(Json(body))
}

pub async fn get_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let key = group_object_key(&group, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn create_resource(
    State(state): State<AppState>,
    Path((group, version, plural)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = obj
        .name()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Status::bad_request("metadata.name is required".into()))?
        .to_string();

    let key = group_object_key(&group, &plural, None, &name);
    let result = state.store.put(&key, obj.to_bytes(), Some(0)).await;
    let new_rv = match result {
        Ok(rv) => rv,
        Err(StoreError::AlreadyExists { .. }) if meta.create_or_update => {
            // createOrUpdate: replace existing object unconditionally.
            state
                .store
                .put(&key, obj.to_bytes(), None)
                .await
                .map_err(|e| store_err(e, &name, &meta.kind))?
        }
        Err(e) => return Err(store_err(e, &name, &meta.kind)),
    };

    obj.set_resource_version(new_rv);
    if group == RBAC_GROUP {
        let rbac_key = rbac_cluster_key(&group, &version, &plural, &name);
        state.rbac_index.apply_object(&rbac_key, &obj.body);
    }
    Ok((StatusCode::CREATED, Json(obj.body)))
}

pub async fn replace_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj.name().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    // Strip status from the incoming body on the main endpoint when the resource
    // has a dedicated status subresource (clients must use /status for that).
    if meta.has_status_subresource {
        if let Some(map) = obj.body.as_object_mut() {
            map.remove("status");
        }
    }

    let expected_revision = parse_resource_version(obj.resource_version())?;

    let key = group_object_key(&group, &plural, None, &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    obj.set_resource_version(new_rv);
    if group == RBAC_GROUP {
        let rbac_key = rbac_cluster_key(&group, &version, &plural, &name);
        state.rbac_index.apply_object(&rbac_key, &obj.body);
    }
    Ok(Json(obj.body))
}

pub async fn delete_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let key = group_object_key(&group, &plural, None, &name);

    // Fetch current to check finalizers.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    if let Some(soft) = apply_delete_policy(&mut obj) {
        // Soft-delete: persist modified object, return it.
        let expected_rv = parse_resource_version(obj.resource_version())?;
        let new_rv = state
            .store
            .put(&key, obj.to_bytes(), expected_rv)
            .await
            .map_err(|e| store_err(e, &name, &meta.kind))?;
        let mut body = soft;
        body["metadata"]["resourceVersion"] = serde_json::Value::String(new_rv.to_string());
        return Ok(Json(body));
    }

    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    if group == RBAC_GROUP {
        let rbac_key = rbac_cluster_key(&group, &version, &plural, &name);
        state.rbac_index.remove_object(&rbac_key);
    }
    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

pub async fn patch_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();
    validate_patch_content_type(&headers)?;

    let key = group_object_key(&group, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let mut patch: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // Strip status from the patch on the main endpoint for resources with a status subresource.
    if meta.has_status_subresource {
        if let Some(map) = patch.as_object_mut() {
            map.remove("status");
        }
    }

    merge_patch(&mut current.body, &patch);

    // Post-patch: if deletionTimestamp is set and finalizers are now empty, hard-delete.
    let deletion_ts_set = current.body["metadata"]["deletionTimestamp"].is_string();
    let finalizers_empty = current.body["metadata"]["finalizers"]
        .as_array()
        .map(|arr| arr.is_empty())
        .unwrap_or(true);

    if deletion_ts_set && finalizers_empty {
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err(e, &name, &meta.kind))?;
        if group == RBAC_GROUP {
            let rbac_key = rbac_cluster_key(&group, &version, &plural, &name);
            state.rbac_index.remove_object(&rbac_key);
        }
        return Ok(Json(current.body));
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    current.set_resource_version(new_rv);
    if group == RBAC_GROUP {
        let rbac_key = rbac_cluster_key(&group, &version, &plural, &name);
        state.rbac_index.apply_object(&rbac_key, &current.body);
    }
    Ok(Json(current.body))
}

// ---------------------------------------------------------------------------
// Namespaced handlers  (group/version/namespaces/:ns/resource)
// ---------------------------------------------------------------------------

pub async fn list_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    Query(query): Query<CollectionQuery>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    check_watch(&query)?;
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let prefix = group_list_prefix(&group, &plural, Some(&ns));
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

    let items = if let Some(ref sel) = query.label_selector {
        let pairs = parse_label_selector(sel)?;
        apply_label_selector(items, &pairs)
    } else {
        items
    };

    let body = build_list_response(&meta.kind, &group, &version, resp.revision, items);
    Ok(Json(body))
}

pub async fn get_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let key = group_object_key(&group, &plural, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn create_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = obj
        .name()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Status::bad_request("metadata.name is required".into()))?
        .to_string();

    obj.body["metadata"]["namespace"] = serde_json::Value::String(ns.clone());

    let key = group_object_key(&group, &plural, Some(&ns), &name);
    let result = state.store.put(&key, obj.to_bytes(), Some(0)).await;
    let new_rv = match result {
        Ok(rv) => rv,
        Err(StoreError::AlreadyExists { .. }) if meta.create_or_update => {
            // createOrUpdate: replace existing object unconditionally.
            state
                .store
                .put(&key, obj.to_bytes(), None)
                .await
                .map_err(|e| store_err(e, &name, &meta.kind))?
        }
        Err(e) => return Err(store_err(e, &name, &meta.kind)),
    };

    obj.set_resource_version(new_rv);
    if group == RBAC_GROUP {
        let rbac_key = rbac_namespaced_key(&group, &version, &ns, &plural, &name);
        state.rbac_index.apply_object(&rbac_key, &obj.body);
    }
    Ok((StatusCode::CREATED, Json(obj.body)))
}

pub async fn replace_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj.name().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    // Strip status from the incoming body on the main endpoint when the resource
    // has a dedicated status subresource.
    if meta.has_status_subresource {
        if let Some(map) = obj.body.as_object_mut() {
            map.remove("status");
        }
    }

    let expected_revision = parse_resource_version(obj.resource_version())?;

    let key = group_object_key(&group, &plural, Some(&ns), &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    obj.set_resource_version(new_rv);
    if group == RBAC_GROUP {
        let rbac_key = rbac_namespaced_key(&group, &version, &ns, &plural, &name);
        state.rbac_index.apply_object(&rbac_key, &obj.body);
    }
    Ok(Json(obj.body))
}

pub async fn delete_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let key = group_object_key(&group, &plural, Some(&ns), &name);

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    if let Some(soft) = apply_delete_policy(&mut obj) {
        let expected_rv = parse_resource_version(obj.resource_version())?;
        let new_rv = state
            .store
            .put(&key, obj.to_bytes(), expected_rv)
            .await
            .map_err(|e| store_err(e, &name, &meta.kind))?;
        let mut body = soft;
        body["metadata"]["resourceVersion"] = serde_json::Value::String(new_rv.to_string());
        return Ok(Json(body));
    }

    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    if group == RBAC_GROUP {
        let rbac_key = rbac_namespaced_key(&group, &version, &ns, &plural, &name);
        state.rbac_index.remove_object(&rbac_key);
    }
    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

pub async fn patch_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();
    validate_patch_content_type(&headers)?;

    let key = group_object_key(&group, &plural, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let mut patch: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // Strip status from the patch on the main endpoint for resources with a status subresource.
    if meta.has_status_subresource {
        if let Some(map) = patch.as_object_mut() {
            map.remove("status");
        }
    }

    merge_patch(&mut current.body, &patch);

    // Post-patch: if deletionTimestamp is set and finalizers are now empty, hard-delete.
    let deletion_ts_set = current.body["metadata"]["deletionTimestamp"].is_string();
    let finalizers_empty = current.body["metadata"]["finalizers"]
        .as_array()
        .map(|arr| arr.is_empty())
        .unwrap_or(true);

    if deletion_ts_set && finalizers_empty {
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err(e, &name, &meta.kind))?;
        if group == RBAC_GROUP {
            let rbac_key = rbac_namespaced_key(&group, &version, &ns, &plural, &name);
            state.rbac_index.remove_object(&rbac_key);
        }
        return Ok(Json(current.body));
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    current.set_resource_version(new_rv);
    if group == RBAC_GROUP {
        let rbac_key = rbac_namespaced_key(&group, &version, &ns, &plural, &name);
        state.rbac_index.apply_object(&rbac_key, &current.body);
    }
    Ok(Json(current.body))
}

// ---------------------------------------------------------------------------
// Status subresource handlers
// ---------------------------------------------------------------------------
//
// GET    /apis/:group/:version/:resource/:name/status
// PUT    /apis/:group/:version/:resource/:name/status
// PATCH  /apis/:group/:version/:resource/:name/status
//
// GET    /apis/:group/:version/namespaces/:ns/:resource/:name/status
// PUT    /apis/:group/:version/namespaces/:ns/:resource/:name/status
// PATCH  /apis/:group/:version/namespaces/:ns/:resource/:name/status
//
// TODO: register in main.rs — see PR for worker/p2-generic-cluster

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
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let incoming = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

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
        serde_json::Value::Null => { current.body.as_object_mut().map(|m| m.remove("status")); }
        v => { current.body["status"] = v.clone(); }
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
    let meta = lookup(&state, &group, &version, &plural)?.clone();
    validate_patch_content_type(&headers)?;

    let key = group_object_key(&group, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // Only merge the status portion of the patch.
    if let Some(status_patch) = patch.get("status") {
        let entry = current
            .body
            .as_object_mut()
            .map(|m| m.entry("status").or_insert(serde_json::Value::Object(Default::default())));
        if let Some(entry) = entry {
            merge_patch(entry, status_patch);
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
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();

    let incoming = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = group_object_key(&group, &plural, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    match &incoming.body["status"] {
        serde_json::Value::Null => { current.body.as_object_mut().map(|m| m.remove("status")); }
        v => { current.body["status"] = v.clone(); }
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

pub async fn patch_namespaced_resource_status(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();
    validate_patch_content_type(&headers)?;

    let key = group_object_key(&group, &plural, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    if let Some(status_patch) = patch.get("status") {
        let entry = current
            .body
            .as_object_mut()
            .map(|m| m.entry("status").or_insert(serde_json::Value::Object(Default::default())));
        if let Some(entry) = entry {
            merge_patch(entry, status_patch);
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

// ---------------------------------------------------------------------------
// Core group (group="", version="v1") handler wrappers for /api/v1/... routes
// ---------------------------------------------------------------------------
//
// These inject the fixed (group, version) = ("", "v1") into the generic handlers
// so the router can use simpler path patterns like /api/v1/:resource.

pub async fn core_list_resource(
    State(state): State<AppState>,
    Path(plural): Path<String>,
    Query(query): Query<CollectionQuery>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    list_resource(
        State(state),
        Path(("".into(), "v1".into(), plural)),
        Query(query),
    )
    .await
}

pub async fn core_get_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_resource(State(state), Path(("".into(), "v1".into(), plural, name))).await
}

pub async fn core_create_resource(
    State(state): State<AppState>,
    Path(plural): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    create_resource(State(state), Path(("".into(), "v1".into(), plural)), body).await
}

pub async fn core_replace_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    replace_resource(State(state), Path(("".into(), "v1".into(), plural, name)), body).await
}

pub async fn core_delete_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    delete_resource(State(state), Path(("".into(), "v1".into(), plural, name))).await
}

pub async fn core_patch_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_resource(State(state), Path(("".into(), "v1".into(), plural, name)), headers, body).await
}

pub async fn core_get_resource_status(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_resource_status(State(state), Path(("".into(), "v1".into(), plural, name))).await
}

pub async fn core_put_resource_status(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    put_resource_status(State(state), Path(("".into(), "v1".into(), plural, name)), body).await
}

pub async fn core_patch_resource_status(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_resource_status(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        headers,
        body,
    )
    .await
}

pub async fn core_list_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural)): Path<(String, String)>,
    Query(query): Query<CollectionQuery>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    list_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural)),
        Query(query),
    )
    .await
}

pub async fn core_get_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_namespaced_resource(State(state), Path(("".into(), "v1".into(), ns, plural, name))).await
}

pub async fn core_create_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural)): Path<(String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    create_namespaced_resource(State(state), Path(("".into(), "v1".into(), ns, plural)), body).await
}

pub async fn core_replace_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    replace_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        body,
    )
    .await
}

pub async fn core_delete_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    delete_namespaced_resource(State(state), Path(("".into(), "v1".into(), ns, plural, name))).await
}

pub async fn core_patch_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
        body,
    )
    .await
}

pub async fn core_get_namespaced_resource_status(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
    )
    .await
}

pub async fn core_put_namespaced_resource_status(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    put_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        body,
    )
    .await
}

pub async fn core_patch_namespaced_resource_status(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
        body,
    )
    .await
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

fn validate_patch_content_type(headers: &HeaderMap) -> Result<(), crate::status::StatusError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/strategic-merge-patch+json") {
        return Err(Status::bad_request(
            "strategic merge patch not supported in Phase 1; use application/merge-patch+json".into(),
        ));
    }

    if !content_type.contains("application/merge-patch+json") {
        return Err(Status::unsupported_media_type(format!(
            "unsupported media type '{content_type}'; use application/merge-patch+json"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item_with_labels(labels: &[(&str, &str)]) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (k, v) in labels {
            map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
        serde_json::json!({ "metadata": { "labels": map } })
    }

    /// Unwrap a Result whose Err type doesn't impl Debug.
    fn ok<T>(r: Result<T, crate::status::StatusError>) -> T {
        match r {
            Ok(v) => v,
            Err(_) => panic!("expected Ok but got Err"),
        }
    }

    // -- parse_label_selector --

    #[test]
    fn parse_single_pair() {
        let pairs = ok(parse_label_selector("app=frontend"));
        assert_eq!(pairs, vec![("app", "frontend")]);
    }

    #[test]
    fn parse_multiple_pairs() {
        let pairs = ok(parse_label_selector("app=frontend,env=prod"));
        assert_eq!(pairs, vec![("app", "frontend"), ("env", "prod")]);
    }

    #[test]
    fn parse_empty_selector_returns_empty() {
        let pairs = ok(parse_label_selector(""));
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_missing_equals_is_error() {
        // no '=' present — must fail because label selectors require key=value
        assert!(parse_label_selector("app").is_err());
    }

    #[test]
    fn parse_empty_key_is_error() {
        assert!(parse_label_selector("=val").is_err());
    }

    #[test]
    fn parse_value_may_be_empty() {
        // key= is valid — value is empty string
        let pairs = ok(parse_label_selector("app="));
        assert_eq!(pairs, vec![("app", "")]);
    }

    // -- apply_label_selector --

    #[test]
    fn filter_matches_all_present_labels() {
        let items = vec![
            item_with_labels(&[("app", "frontend"), ("env", "prod")]),
            item_with_labels(&[("app", "backend"), ("env", "prod")]),
        ];
        let pairs = vec![("app", "frontend"), ("env", "prod")];
        let result = apply_label_selector(items, &pairs);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["metadata"]["labels"]["app"], "frontend");
    }

    #[test]
    fn filter_removes_items_missing_label() {
        let items = vec![
            item_with_labels(&[("app", "frontend")]),
            item_with_labels(&[]),
        ];
        let pairs = vec![("app", "frontend")];
        let result = apply_label_selector(items, &pairs);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_empty_pairs_returns_all() {
        let items = vec![
            item_with_labels(&[("a", "1")]),
            item_with_labels(&[("b", "2")]),
        ];
        let result = apply_label_selector(items, &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn filter_no_match_returns_empty() {
        let items = vec![item_with_labels(&[("app", "backend")])];
        let pairs = vec![("app", "frontend")];
        let result = apply_label_selector(items, &pairs);
        assert!(result.is_empty());
    }

    // -- build_list_response --

    #[test]
    fn core_group_api_version_is_version_only() {
        // For core group (group=""), apiVersion should be just "v1", not "/v1".
        let body = build_list_response("Node", "", "v1", 0, vec![]);
        assert_eq!(body["apiVersion"], "v1");
        assert_eq!(body["kind"], "NodeList");
    }

    #[test]
    fn non_core_group_api_version_includes_group() {
        let body = build_list_response("Deployment", "apps", "v1", 0, vec![]);
        assert_eq!(body["apiVersion"], "apps/v1");
    }
}
