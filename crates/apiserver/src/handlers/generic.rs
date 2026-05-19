use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde::Deserialize;
use u7s_store::{ListOptions, Store, StoreError, WatchEvent};

use crate::{
    keys::{group_list_prefix, group_object_key},
    state::AppState,
    status::Status,
    types::{Object, ResourceKey},
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    pub watch: Option<bool>,
    pub resource_version: Option<u64>,
    pub label_selector: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

pub(crate) fn generate_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    let c = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut n = t ^ c.wrapping_mul(0x9e3779b97f4a7c15);
    const CHARS: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";
    let mut out = [0u8; 5];
    for b in out.iter_mut() {
        *b = CHARS[(n % CHARS.len() as u64) as usize];
        n = n.wrapping_div(CHARS.len() as u64);
    }
    String::from_utf8(out.to_vec()).unwrap()
}

fn resolve_name(obj: &mut Object) -> Result<String, crate::status::StatusError> {
    match obj.name().filter(|n| !n.is_empty()) {
        Some(n) => Ok(n.to_string()),
        None => {
            let gen = obj.body["metadata"]["generateName"].as_str().unwrap_or("");
            if gen.is_empty() {
                return Err(Status::bad_request("metadata.name or metadata.generateName is required".into()));
            }
            let name = format!("{}{}", gen, generate_suffix());
            obj.body["metadata"]["name"] = serde_json::Value::String(name.clone());
            Ok(name)
        }
    }
}

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

/// Serialise a single watch event to NDJSON bytes (including trailing newline).
/// Returns None on Compacted — the caller should close the stream.
fn encode_watch_event(event: &WatchEvent, api_version: &str, kind: &str) -> Option<Bytes> {
    let line = match event {
        WatchEvent::Added(obj) => {
            let object: serde_json::Value =
                serde_json::from_slice(&obj.value).unwrap_or(serde_json::Value::Null);
            format!(
                "{{\"type\":\"ADDED\",\"object\":{}}}\n",
                serde_json::to_string(&object).unwrap_or_default()
            )
        }
        WatchEvent::Modified(obj) => {
            let object: serde_json::Value =
                serde_json::from_slice(&obj.value).unwrap_or(serde_json::Value::Null);
            format!(
                "{{\"type\":\"MODIFIED\",\"object\":{}}}\n",
                serde_json::to_string(&object).unwrap_or_default()
            )
        }
        WatchEvent::Deleted { key, revision } => {
            // Reconstruct a minimal tombstone object from the store key.
            let (name, namespace) = parse_key_name_ns(key);
            let object = if namespace.is_empty() {
                serde_json::json!({
                    "apiVersion": api_version,
                    "kind": kind,
                    "metadata": { "name": name, "resourceVersion": revision.to_string() }
                })
            } else {
                serde_json::json!({
                    "apiVersion": api_version,
                    "kind": kind,
                    "metadata": {
                        "name": name,
                        "namespace": namespace,
                        "resourceVersion": revision.to_string()
                    }
                })
            };
            format!(
                "{{\"type\":\"DELETED\",\"object\":{}}}\n",
                serde_json::to_string(&object).unwrap_or_default()
            )
        }
        WatchEvent::Bookmark { revision } => {
            format!(
                "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{revision}\"}}}}}}\n"
            )
        }
        WatchEvent::Compacted { .. } => return None,
    };
    Some(Bytes::from(line))
}

/// Parse the last two path segments of a store key as (name, namespace).
/// Key format: /registry/<resource>/<namespace>/<name>  (namespaced)
///         or: /registry/<group>/<plural>/<name>        (cluster-scoped)
/// We only need the final segment as name; second-to-last as namespace (may be empty).
fn parse_key_name_ns(key: &str) -> (&str, &str) {
    let parts: Vec<&str> = key.rsplitn(3, '/').collect();
    match parts.as_slice() {
        [name, namespace, ..] => (name, namespace),
        [name] => (name, ""),
        _ => ("", ""),
    }
}

/// Stream watch events for a given store prefix in NDJSON format.
/// Mirrors watch_pods in pods.rs with a 60s bookmark heartbeat and 5min max duration.
pub(crate) async fn watch_generic(
    state: AppState,
    prefix: String,
    api_version: String,
    kind: String,
    from_revision: u64,
) -> Result<Response, crate::status::StatusError> {
    let event_stream = state
        .store
        .watch(&prefix, from_revision)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let chunk_stream = async_stream::stream! {
        use futures_core::Stream;
        use std::pin::pin;
        use tokio::time::{Duration, interval, sleep};

        let mut event_stream = pin!(event_stream);
        let mut bookmark_tick = interval(Duration::from_secs(60));
        bookmark_tick.tick().await; // skip initial immediate tick

        let mut max_duration = pin!(sleep(Duration::from_secs(5 * 60)));
        let mut last_rv: u64 = from_revision;

        loop {
            tokio::select! {
                biased;

                maybe_event = {
                    use std::future::poll_fn;
                    poll_fn(|cx| {
                        use std::task::Poll;
                        match event_stream.as_mut().poll_next(cx) {
                            Poll::Ready(v) => Poll::Ready(v),
                            Poll::Pending => Poll::Pending,
                        }
                    })
                } => {
                    match maybe_event {
                        None => break,
                        Some(event) => {
                            match &event {
                                WatchEvent::Added(obj) | WatchEvent::Modified(obj) => {
                                    last_rv = last_rv.max(obj.revision);
                                }
                                WatchEvent::Deleted { revision, .. } => {
                                    last_rv = last_rv.max(*revision);
                                }
                                WatchEvent::Bookmark { revision } => {
                                    last_rv = last_rv.max(*revision);
                                }
                                WatchEvent::Compacted { .. } => {}
                            }

                            bookmark_tick.reset();

                            if matches!(event, WatchEvent::Compacted { .. }) {
                                let error_line = Bytes::from(
                                    "{\"type\":\"ERROR\",\"object\":{\"apiVersion\":\"v1\",\"kind\":\"Status\",\"code\":410,\"message\":\"too old resource version\",\"reason\":\"Expired\"}}\n"
                                );
                                yield Ok::<Bytes, axum::BoxError>(error_line);
                                break;
                            }

                            if let Some(chunk) = encode_watch_event(&event, &api_version, &kind) {
                                yield Ok::<Bytes, axum::BoxError>(chunk);
                            }
                        }
                    }
                }

                _ = bookmark_tick.tick() => {
                    let bookmark = format!(
                        "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\"}}}}}}\n"
                    );
                    yield Ok::<Bytes, axum::BoxError>(Bytes::from(bookmark));
                }

                _ = &mut max_duration => {
                    let bookmark = format!(
                        "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\"}}}}}}\n"
                    );
                    yield Ok::<Bytes, axum::BoxError>(Bytes::from(bookmark));
                    break;
                }
            }
        }
    };

    let body = Body::from_stream(chunk_stream);
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::TRANSFER_ENCODING, "chunked")
        .body(body)
        .expect("response builder never fails with these headers");

    Ok(resp)
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

use crate::util::{extract_body, utc_now_rfc3339};

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
) -> Result<Response, crate::status::StatusError> {
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::list_cr(
                State(state),
                Path((group, version, plural)),
                query,
            )
            .await;
        }
    };
    let prefix = group_list_prefix(&group, &plural, None);

    if query.watch == Some(true) {
        let api_version = if group.is_empty() {
            version.clone()
        } else {
            format!("{}/{}", group, version)
        };
        return watch_generic(
            state,
            prefix,
            api_version,
            meta.kind.clone(),
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

    let items = if let Some(ref sel) = query.label_selector {
        let pairs = parse_label_selector(sel)?;
        apply_label_selector(items, &pairs)
    } else {
        items
    };

    let body = build_list_response(&meta.kind, &group, &version, resp.revision, items);
    Ok(Json(body).into_response())
}

pub async fn get_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::get_cr(
                State(state),
                Path((group, version, plural, name)),
            )
            .await;
        }
    };

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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::create_cr(
                State(state),
                Path((group, version, plural)),
                headers,
                body,
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = resolve_name(&mut obj)?;

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
    Ok((StatusCode::CREATED, Json(obj.body)).into_response())
}

pub async fn replace_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::replace_cr(
                State(state),
                Path((group, version, plural, name)),
                headers,
                body,
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

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
    Ok(Json(obj.body).into_response())
}

pub async fn delete_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::delete_cr(
                State(state),
                Path((group, version, plural, name)),
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

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
        return Ok(Json(body).into_response());
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
    })).into_response())
}

pub async fn patch_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = detect_patch_type(&headers)?;
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::patch_cr(
                State(state),
                Path((group, version, plural, name)),
                headers,
                body,
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

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

    match patch_type {
        PatchType::Merge => merge_patch(&mut current.body, &patch),
        PatchType::StrategicMerge => {
            crate::patch::strategic_merge_patch(&mut current.body, &patch)
                .map_err(|e| Status::bad_request(e.to_string()))?;
        }
        PatchType::Json => {
            apply_json_patch(&mut current.body, &patch)?;
        }
    }

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
        return Ok(Json(current.body).into_response());
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
    Ok(Json(current.body).into_response())
}

// ---------------------------------------------------------------------------
// Namespaced handlers  (group/version/namespaces/:ns/resource)
// ---------------------------------------------------------------------------

pub async fn list_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    Query(query): Query<CollectionQuery>,
) -> Result<Response, crate::status::StatusError> {
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::list_cr_namespaced(
                State(state),
                Path((group, version, ns, plural)),
                query,
            )
            .await;
        }
    };
    let prefix = group_list_prefix(&group, &plural, Some(&ns));

    if query.watch == Some(true) {
        let api_version = if group.is_empty() {
            version.clone()
        } else {
            format!("{}/{}", group, version)
        };
        return watch_generic(
            state,
            prefix,
            api_version,
            meta.kind.clone(),
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

    let items = if let Some(ref sel) = query.label_selector {
        let pairs = parse_label_selector(sel)?;
        apply_label_selector(items, &pairs)
    } else {
        items
    };

    let body = build_list_response(&meta.kind, &group, &version, resp.revision, items);
    Ok(Json(body).into_response())
}

pub async fn get_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::get_cr_namespaced(
                State(state),
                Path((group, version, ns, plural, name)),
            )
            .await;
        }
    };

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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::create_cr_namespaced(
                State(state),
                Path((group, version, ns, plural)),
                headers,
                body,
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = resolve_name(&mut obj)?;

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
    Ok((StatusCode::CREATED, Json(obj.body)).into_response())
}

pub async fn replace_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::replace_cr_namespaced(
                State(state),
                Path((group, version, ns, plural, name)),
                headers,
                body,
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

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
    Ok(Json(obj.body).into_response())
}

pub async fn delete_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::delete_cr_namespaced(
                State(state),
                Path((group, version, ns, plural, name)),
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

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
        return Ok(Json(body).into_response());
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
    })).into_response())
}

pub async fn patch_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = detect_patch_type(&headers)?;
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::patch_cr_namespaced(
                State(state),
                Path((group, version, ns, plural, name)),
                headers,
                body,
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

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

    match patch_type {
        PatchType::Merge => merge_patch(&mut current.body, &patch),
        PatchType::StrategicMerge => {
            crate::patch::strategic_merge_patch(&mut current.body, &patch)
                .map_err(|e| Status::bad_request(e.to_string()))?;
        }
        PatchType::Json => {
            apply_json_patch(&mut current.body, &patch)?;
        }
    }

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
        return Ok(Json(current.body).into_response());
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
    Ok(Json(current.body).into_response())
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let meta = lookup(&state, &group, &version, &plural)?.clone();
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
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

    let patch: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    match patch_type {
        PatchType::Json => {
            // JSON Patch addresses the full document; operations include the /status prefix.
            apply_json_patch(&mut current.body, &patch)?;
        }
        _ => {
            // Merge and strategic merge: only patch the status portion.
            if let Some(status_patch) = patch.get("status") {
                let entry = current
                    .body
                    .as_object_mut()
                    .map(|m| m.entry("status").or_insert(serde_json::Value::Object(Default::default())));
                if let Some(entry) = entry {
                    match patch_type {
                        PatchType::Merge => merge_patch(entry, status_patch),
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
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let incoming = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let (key, kind_fallback) = match lookup(&state, &group, &version, &plural) {
        Ok(meta) => (group_object_key(&group, &plural, Some(&ns), &name), meta.kind.clone()),
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

    let kind = current.body["kind"].as_str().map(str::to_owned).unwrap_or(kind_fallback);

    match &incoming.body["status"] {
        serde_json::Value::Null => { current.body.as_object_mut().map(|m| m.remove("status")); }
        v => { current.body["status"] = v.clone(); }
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

    let kind = current.body["kind"].as_str().map(str::to_owned).unwrap_or_else(|| plural.clone());

    let patch: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    match patch_type {
        PatchType::Json => {
            // JSON Patch addresses the full document; operations include the /status prefix.
            apply_json_patch(&mut current.body, &patch)?;
        }
        _ => {
            // Merge and strategic merge: only patch the status portion.
            if let Some(status_patch) = patch.get("status") {
                let entry = current
                    .body
                    .as_object_mut()
                    .map(|m| m.entry("status").or_insert(serde_json::Value::Object(Default::default())));
                if let Some(entry) = entry {
                    match patch_type {
                        PatchType::Merge => merge_patch(entry, status_patch),
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
    // Pods are namespaced; the registry has no cluster-scoped "pods" entry.
    // Handle GET /api/v1/pods by scanning across all namespaces.
    if plural == "pods" {
        let prefix = crate::keys::cluster_list_prefix("pods");
        if query.watch == Some(true) {
            return watch_generic(
                state,
                prefix,
                "v1".into(),
                "Pod".into(),
                query.resource_version.unwrap_or(0),
            )
            .await
            .map(IntoResponse::into_response);
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
        let items = if let Some(ref sel) = query.label_selector {
            let pairs = parse_label_selector(sel)?;
            apply_label_selector(items, &pairs)
        } else {
            items
        };
        let body = build_list_response("Pod", "", "v1", resp.revision, items);
        return Ok(Json(body).into_response());
    }

    list_resource(
        State(state),
        Path(("".into(), "v1".into(), plural)),
        Query(query),
    )
    .await
    .map(IntoResponse::into_response)
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    create_resource(State(state), Path(("".into(), "v1".into(), plural)), headers, body).await
}

pub async fn core_replace_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    replace_resource(State(state), Path(("".into(), "v1".into(), plural, name)), headers, body).await
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    put_resource_status(State(state), Path(("".into(), "v1".into(), plural, name)), headers, body).await
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    create_namespaced_resource(State(state), Path(("".into(), "v1".into(), ns, plural)), headers, body).await
}

pub async fn core_replace_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    replace_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    put_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
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

#[derive(Debug)]
enum PatchType {
    Merge,
    StrategicMerge,
    Json,
}

fn detect_patch_type(headers: &HeaderMap) -> Result<PatchType, crate::status::StatusError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type.contains("application/strategic-merge-patch+json") {
        return Ok(PatchType::StrategicMerge);
    }
    if content_type.contains("application/merge-patch+json") {
        return Ok(PatchType::Merge);
    }
    if content_type.contains("application/json-patch+json") {
        return Ok(PatchType::Json);
    }
    Err(Status::unsupported_media_type(format!(
        "unsupported media type '{content_type}'; use application/merge-patch+json, application/strategic-merge-patch+json, or application/json-patch+json"
    )))
}

/// Apply a JSON Patch (RFC 6902) to `obj`.
/// Supports `add`, `remove`, and `replace` operations.
/// Returns Err(422) for unsupported operations or invalid paths.
fn apply_json_patch(
    obj: &mut serde_json::Value,
    patch: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let ops = patch.as_array().ok_or_else(|| {
        Status::unprocessable_entity("JSON patch must be an array of operations".into())
    })?;

    for op in ops {
        let op_str = op["op"].as_str().ok_or_else(|| {
            Status::unprocessable_entity("each JSON patch operation must have an 'op' field".into())
        })?;
        let path = op["path"].as_str().ok_or_else(|| {
            Status::unprocessable_entity("each JSON patch operation must have a 'path' field".into())
        })?;

        match op_str {
            "add" | "replace" => {
                let value = op.get("value").ok_or_else(|| {
                    Status::unprocessable_entity(format!("'{op_str}' operation requires a 'value' field"))
                })?.clone();
                json_patch_set(obj, path, value)?;
            }
            "remove" => {
                json_patch_remove(obj, path)?;
            }
            other => {
                return Err(Status::unprocessable_entity(format!(
                    "unsupported JSON patch operation '{other}'; supported: add, remove, replace"
                )));
            }
        }
    }
    Ok(())
}

/// Parse a JSON Pointer (RFC 6901) into path segments.
fn json_pointer_segments(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return vec![];
    }
    // Leading '/' is required for non-empty pointers; skip it.
    let stripped = pointer.strip_prefix('/').unwrap_or(pointer);
    stripped
        .split('/')
        .map(|seg| seg.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// Navigate to the parent of the target, returning a mutable ref to the parent and the final key.
fn json_patch_navigate_mut<'a>(
    obj: &'a mut serde_json::Value,
    segments: &[String],
) -> Result<(&'a mut serde_json::Value, String), crate::status::StatusError> {
    if segments.is_empty() {
        return Err(Status::unprocessable_entity("cannot operate on root document".into()));
    }
    let (parents, last) = segments.split_at(segments.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = json_navigate_one(cur, seg)?;
    }
    Ok((cur, last[0].clone()))
}

fn json_navigate_one<'a>(
    node: &'a mut serde_json::Value,
    seg: &str,
) -> Result<&'a mut serde_json::Value, crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => {
            map.get_mut(seg).ok_or_else(|| {
                Status::unprocessable_entity(format!("path segment '{seg}' not found"))
            })
        }
        serde_json::Value::Array(arr) => {
            let idx: usize = seg.parse().map_err(|_| {
                Status::unprocessable_entity(format!("path segment '{seg}' is not a valid array index"))
            })?;
            arr.get_mut(idx).ok_or_else(|| {
                Status::unprocessable_entity(format!("array index {idx} out of bounds"))
            })
        }
        _ => Err(Status::unprocessable_entity(format!(
            "cannot traverse into non-object/array at segment '{seg}'"
        ))),
    }
}

fn json_patch_set(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parent, key) = json_patch_navigate_mut(obj, &segs)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.insert(key, value);
        }
        serde_json::Value::Array(arr) => {
            if key == "-" {
                arr.push(value);
            } else {
                let idx: usize = key.parse().map_err(|_| {
                    Status::unprocessable_entity(format!("invalid array index '{key}'"))
                })?;
                if idx <= arr.len() {
                    arr.insert(idx, value);
                } else {
                    return Err(Status::unprocessable_entity(format!(
                        "array index {idx} out of bounds (len {})",
                        arr.len()
                    )));
                }
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot set value on non-object/array".into(),
            ));
        }
    }
    Ok(())
}

fn json_patch_remove(
    obj: &mut serde_json::Value,
    pointer: &str,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    let (parent, key) = json_patch_navigate_mut(obj, &segs)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.remove(&key).ok_or_else(|| {
                Status::unprocessable_entity(format!("path '{pointer}' not found"))
            })?;
        }
        serde_json::Value::Array(arr) => {
            let idx: usize = key.parse().map_err(|_| {
                Status::unprocessable_entity(format!("invalid array index '{key}'"))
            })?;
            if idx < arr.len() {
                arr.remove(idx);
            } else {
                return Err(Status::unprocessable_entity(format!(
                    "array index {idx} out of bounds"
                )));
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot remove from non-object/array".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    // -- encode_watch_event: resourceVersion in ADDED events --

    /// Conformance: watch ADDED event payloads must include a non-empty
    /// metadata.resourceVersion. Kubernetes clients use this to track progress
    /// through the watch stream and to issue subsequent watches from a known point.
    /// A missing or empty resourceVersion causes clients to re-list indefinitely.
    #[test]
    fn encode_watch_event_added_includes_resource_version() {
        // Simulate the object as stored by store.put(): bytes already have
        // metadata.resourceVersion stamped by stamp_resource_version().
        let obj_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "my-cm",
                "namespace": "default",
                "resourceVersion": "42"
            }
        });
        let value = bytes::Bytes::from(serde_json::to_vec(&obj_json).unwrap());
        let event = WatchEvent::Added(u7s_store::StoreObject {
            key: "/registry/configmaps/default/my-cm".into(),
            value,
            revision: 42,
        });

        let chunk = encode_watch_event(&event, "v1", "ConfigMap")
            .expect("ADDED event must produce a chunk");

        let line = std::str::from_utf8(&chunk).unwrap().trim_end();
        let decoded: serde_json::Value = serde_json::from_str(line)
            .expect("chunk must be valid JSON");

        assert_eq!(decoded["type"], "ADDED", "event type must be ADDED");

        let rv = decoded["object"]["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("");
        assert!(
            !rv.is_empty(),
            "object.metadata.resourceVersion must be non-empty in ADDED event; \
             Kubernetes watch clients cannot track progress without it"
        );
        assert_eq!(rv, "42", "resourceVersion must match the value stamped by store.put()");
    }

    /// Mirror of the ADDED test for MODIFIED events: same conformance requirement.
    #[test]
    fn encode_watch_event_modified_includes_resource_version() {
        let obj_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "my-cm",
                "namespace": "default",
                "resourceVersion": "99"
            }
        });
        let value = bytes::Bytes::from(serde_json::to_vec(&obj_json).unwrap());
        let event = WatchEvent::Modified(u7s_store::StoreObject {
            key: "/registry/configmaps/default/my-cm".into(),
            value,
            revision: 99,
        });

        let chunk = encode_watch_event(&event, "v1", "ConfigMap")
            .expect("MODIFIED event must produce a chunk");

        let decoded: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim_end()).unwrap();

        assert_eq!(decoded["type"], "MODIFIED");
        let rv = decoded["object"]["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("");
        assert!(
            !rv.is_empty(),
            "object.metadata.resourceVersion must be non-empty in MODIFIED event"
        );
        assert_eq!(rv, "99");
    }

    /// Regression guard: if encode_watch_event ever strips metadata.resourceVersion
    /// (e.g. by rebuilding the object from scratch), this test must fail.
    #[test]
    fn encode_watch_event_added_without_resource_version_in_blob_yields_empty() {
        // Object stored WITHOUT resourceVersion (should not happen in practice,
        // but verifies the test is sensitive to presence/absence of the field).
        let obj_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "bare" }
        });
        let value = bytes::Bytes::from(serde_json::to_vec(&obj_json).unwrap());
        let event = WatchEvent::Added(u7s_store::StoreObject {
            key: "/registry/configmaps/default/bare".into(),
            value,
            revision: 7,
        });

        let chunk = encode_watch_event(&event, "v1", "ConfigMap").unwrap();
        let decoded: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim_end()).unwrap();

        // This asserts the negative: if stamp_resource_version is NOT called, the field is absent.
        // The fact that the two tests above pass (with rv="42"/"99") proves encode_watch_event
        // does NOT inject the field itself — it relies entirely on store.put() to stamp it.
        let rv = decoded["object"]["metadata"]["resourceVersion"].as_str().unwrap_or("");
        assert!(
            rv.is_empty(),
            "without stamping, resourceVersion must be absent — \
             encode_watch_event must not synthesize it from StoreObject.revision"
        );
    }

    // -- detect_patch_type --

    fn headers_with_content_type(ct: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            ct.parse().unwrap(),
        );
        h
    }

    #[test]
    fn detect_patch_type_accepts_merge_patch() {
        // kubectl uses application/merge-patch+json — must be accepted
        let h = headers_with_content_type("application/merge-patch+json");
        assert!(matches!(
            detect_patch_type(&h),
            Ok(PatchType::Merge)
        ));
    }

    #[test]
    fn detect_patch_type_accepts_strategic_merge_patch() {
        // kubectl apply uses application/strategic-merge-patch+json — must be accepted
        // (this was previously rejected with HTTP 400)
        let h = headers_with_content_type("application/strategic-merge-patch+json");
        assert!(matches!(
            detect_patch_type(&h),
            Ok(PatchType::StrategicMerge)
        ));
    }

    #[test]
    fn detect_patch_type_rejects_unknown_content_type() {
        // An arbitrary content type must be rejected with 415
        let h = headers_with_content_type("application/json");
        let err = detect_patch_type(&h).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn detect_patch_type_rejects_missing_content_type() {
        // No Content-Type header at all must also be rejected
        let h = HeaderMap::new();
        let err = detect_patch_type(&h).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn strategic_merge_patch_applied_correctly_via_handler_logic() {
        // Verify that when SMP is dispatched, it merges arrays by name key (not replaces),
        // which is the whole reason SMP exists — merge_patch would have replaced the array.
        let mut body = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "app", "image": "nginx:1.0"}
                ]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "sidecar", "image": "sidecar:latest"}
                ]
            }
        });
        crate::patch::strategic_merge_patch(&mut body, &patch).unwrap();
        let containers = body["spec"]["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 2, "SMP must merge containers by name, not replace the array");
    }

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

    // -- apply_json_patch (RFC 6902) --

    #[test]
    fn json_patch_add_op_sets_field() {
        // add must create a new field; used by conformance tests to set spec fields atomically
        let mut obj = serde_json::json!({"metadata": {"name": "x"}});
        let patch = serde_json::json!([{"op": "add", "path": "/metadata/label", "value": "v1"}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj["metadata"]["label"], "v1");
    }

    #[test]
    fn json_patch_remove_op_deletes_field() {
        // remove must delete an existing field
        let mut obj = serde_json::json!({"metadata": {"name": "x", "extra": "gone"}});
        let patch = serde_json::json!([{"op": "remove", "path": "/metadata/extra"}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert!(obj["metadata"]["extra"].is_null(), "field must be absent after remove");
    }

    #[test]
    fn json_patch_replace_op_updates_field() {
        // replace must overwrite an existing field value
        let mut obj = serde_json::json!({"spec": {"replicas": 1}});
        let patch = serde_json::json!([{"op": "replace", "path": "/spec/replicas", "value": 3}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj["spec"]["replicas"], 3);
    }

    #[test]
    fn json_patch_empty_array_is_noop() {
        // An empty patch array must leave the document unchanged
        let mut obj = serde_json::json!({"metadata": {"name": "x"}});
        let before = obj.clone();
        ok(apply_json_patch(&mut obj, &serde_json::json!([])));
        assert_eq!(obj, before);
    }

    #[test]
    fn json_patch_invalid_op_returns_422() {
        // Unsupported operations like 'copy' must return 422 (not 415 or 400)
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "copy", "from": "/a", "path": "/b"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn json_patch_invalid_path_returns_422() {
        // Removing a non-existent path must return 422
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "remove", "path": "/nonexistent"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn json_patch_pointer_unescaping() {
        // RFC 6901: ~1 decodes to '/', ~0 decodes to '~'
        let mut obj = serde_json::json!({"a/b": {"c~d": 0}});
        let patch = serde_json::json!([{"op": "replace", "path": "/a~1b/c~0d", "value": 42}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj["a/b"]["c~d"], 42);
    }

    #[test]
    fn detect_patch_type_accepts_json_patch() {
        // application/json-patch+json must now be accepted instead of 415
        let h = headers_with_content_type("application/json-patch+json");
        assert!(matches!(detect_patch_type(&h), Ok(PatchType::Json)));
    }

    // -- generate_suffix + resolve_name --

    #[test]
    fn generate_suffix_produces_5_chars_from_allowed_charset() {
        // The suffix is used as a unique name component; must be 5 chars from the safe charset.
        const ALLOWED: &str = "bcdfghjklmnpqrstvwxz2456789";
        let suffix = generate_suffix();
        assert_eq!(suffix.len(), 5, "suffix must be exactly 5 characters");
        for c in suffix.chars() {
            assert!(ALLOWED.contains(c), "suffix char '{c}' not in allowed set");
        }
    }

    #[test]
    fn generate_suffix_produces_different_values() {
        // Two calls must produce different values (collision would cause a store conflict).
        let a = generate_suffix();
        let b = generate_suffix();
        assert_ne!(a, b, "consecutive suffixes must differ");
    }

    #[test]
    fn resolve_name_uses_existing_name() {
        // When metadata.name is already set, generateName is ignored and the existing name wins.
        let mut obj = Object::from_bytes(
            &bytes::Bytes::from(serde_json::json!({
                "metadata": { "name": "my-pod", "generateName": "ignored-" }
            }).to_string())
        ).unwrap();
        let name = ok(resolve_name(&mut obj));
        assert_eq!(name, "my-pod");
        assert_eq!(obj.body["metadata"]["name"], "my-pod");
    }

    #[test]
    fn resolve_name_generates_from_generate_name() {
        // When metadata.name is absent but generateName is set, a name with the prefix is generated.
        let mut obj = Object::from_bytes(
            &bytes::Bytes::from(serde_json::json!({
                "metadata": { "generateName": "test-" }
            }).to_string())
        ).unwrap();
        let name = ok(resolve_name(&mut obj));
        assert!(name.starts_with("test-"), "generated name must start with generateName prefix");
        assert_eq!(name.len(), "test-".len() + 5, "generated name must be prefix + 5 char suffix");
        // The name must be written back into the object body.
        assert_eq!(obj.body["metadata"]["name"].as_str(), Some(name.as_str()));
    }

    #[test]
    fn resolve_name_returns_400_when_neither_set() {
        // Neither name nor generateName → must return 400 (not a panic, not 500).
        let mut obj = Object::from_bytes(
            &bytes::Bytes::from(serde_json::json!({ "metadata": {} }).to_string())
        ).unwrap();
        let err = resolve_name(&mut obj).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    // -- CR status PUT fallback --

    // Verify that put_namespaced_resource_status works for CRD-backed resources whose group
    // is not in the static resource registry (e.g. argoproj.io/Application).
    // The handler must use the CR store key (/registry/cr/<group>/<version>/<plural>/<ns>/<name>)
    // and write the incoming status field onto the stored object.
    #[tokio::test]
    async fn cr_status_put_updates_status_field() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(store.clone(), None, None, std::collections::HashMap::new(), "https://localhost:6443".into());

        // Seed a CR object using the CR store key format (matches cr.rs cr_store_key).
        let group = "argoproj.io";
        let version = "v1alpha1";
        let plural = "applications";
        let ns = "argocd";
        let name = "my-app";
        let cr_key = format!("/registry/cr/{group}/{version}/{plural}/{ns}/{name}");

        let initial = serde_json::json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": {
                "name": name,
                "namespace": ns,
                "resourceVersion": "0"
            },
            "spec": { "project": "default" }
        });
        let initial_bytes = bytes::Bytes::from(serde_json::to_vec(&initial).unwrap());
        store.put(&cr_key, initial_bytes, None).await.expect("seed CR");

        // Issue a status PUT — group is not in static registry so the CR fallback fires.
        let put_body = serde_json::json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": { "name": name, "namespace": ns },
            "status": { "health": { "status": "Healthy" }, "sync": { "status": "Synced" } }
        });
        let body_bytes = bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap());

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
                name.to_string(),
            )),
            headers,
            body_bytes,
        )
        .await;

        assert!(result.is_ok(), "CR status PUT must succeed for unregistered group");

        // Verify the status was persisted in the store.
        let stored = store.get(&cr_key).await.expect("store get").expect("object must exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["health"]["status"],
            "Healthy",
            "status.health.status must be persisted after CR status PUT"
        );
        assert_eq!(
            v["status"]["sync"]["status"],
            "Synced",
            "status.sync.status must be persisted after CR status PUT"
        );
        // spec must be preserved — PUT replaces only status, not the whole object
        assert_eq!(
            v["spec"]["project"],
            "default",
            "spec must be unchanged after status PUT"
        );
    }

    // -- Lease PUT: kubelet liveness signal --
    //
    // The kubelet keeps a node alive by PUTing a Lease object to
    // /apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/{nodeName}.
    // Three cases must work correctly:
    //   1. First PUT (no resourceVersion) → unconditional create → 200
    //   2. Second PUT (matching resourceVersion) → conditional update → 200
    //   3. PUT with stale resourceVersion → 409 Conflict
    //
    // These tests exercise `replace_namespaced_resource` end-to-end with an
    // in-memory store so that regression in the OCC path fails immediately.

    fn make_lease_body(resource_version: Option<&str>) -> bytes::Bytes {
        let mut meta = serde_json::json!({
            "name": "worker-node-1",
            "namespace": "kube-node-lease"
        });
        if let Some(rv) = resource_version {
            meta["resourceVersion"] = serde_json::Value::String(rv.to_string());
        }
        let body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": meta,
            "spec": {
                "acquireTime": "2026-05-20T00:00:00Z",
                "holderIdentity": "worker-node-1",
                "leaseDurationSeconds": 40,
                "renewTime": "2026-05-20T00:00:00Z"
            }
        });
        bytes::Bytes::from(serde_json::to_vec(&body).unwrap())
    }

    fn json_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    }

    /// Kubelet first PUT: no resourceVersion → unconditional write → must succeed.
    ///
    /// A kubelet bootstrapping a new node issues a PUT with no resourceVersion.
    /// parse_resource_version maps this to None → store.put(None) → unconditional
    /// upsert. If this fails, the kubelet cannot register its liveness signal and
    /// the node will never become Ready.
    #[tokio::test]
    async fn lease_put_without_resource_version_creates_lease() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = replace_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "worker-node-1".to_string(),
            )),
            json_headers(),
            make_lease_body(None),
        )
        .await;

        assert!(
            result.is_ok(),
            "first Lease PUT (no resourceVersion) must succeed — kubelet cannot \
             become Ready if creation fails"
        );
    }

    /// Kubelet renewal PUT: use resourceVersion returned from creation → must succeed.
    ///
    /// After the first PUT, the kubelet stores the returned resourceVersion and
    /// sends it on every subsequent renewal. The store OCC check must pass when
    /// the version matches. If this fails, lease renewal is broken and the node
    /// will appear NotReady after the lease duration (40 s by default).
    #[tokio::test]
    async fn lease_put_with_matching_resource_version_updates_lease() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // First PUT: create the lease (no resourceVersion).
        let create_response = replace_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "worker-node-1".to_string(),
            )),
            json_headers(),
            make_lease_body(None),
        )
        .await
        .unwrap_or_else(|_| panic!("first Lease PUT must succeed"))
        .into_response();

        // Extract resourceVersion from the response body.
        let body_bytes = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let rv = body["metadata"]["resourceVersion"]
            .as_str()
            .expect("response must include metadata.resourceVersion")
            .to_string();

        // Second PUT: renew the lease with the returned resourceVersion.
        let renew_result = replace_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "worker-node-1".to_string(),
            )),
            json_headers(),
            make_lease_body(Some(&rv)),
        )
        .await;

        assert!(
            renew_result.is_ok(),
            "Lease renewal PUT with matching resourceVersion must succeed — \
             mismatched OCC would break kubelet liveness"
        );
    }

    /// Stale resourceVersion → 409 Conflict.
    ///
    /// If two kubelets (or a buggy kubelet) try to renew the same lease
    /// concurrently, the one with the stale resourceVersion must be rejected
    /// with 409 Conflict. Without this check the last writer silently wins
    /// and the true holder's timestamp is lost, causing false NotReady.
    #[tokio::test]
    async fn lease_put_with_stale_resource_version_returns_conflict() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Create the lease.
        let create_result = replace_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "worker-node-1".to_string(),
            )),
            json_headers(),
            make_lease_body(None),
        )
        .await;
        assert!(create_result.is_ok(), "first Lease PUT must succeed");

        // PUT with a stale (known-wrong) resourceVersion — "999" is higher than
        // any real revision from a fresh in-memory store.
        let stale_result = replace_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "worker-node-1".to_string(),
            )),
            json_headers(),
            make_lease_body(Some("999")),
        )
        .await;

        match stale_result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::CONFLICT,
                "stale Lease PUT must return 409 Conflict — without OCC check, \
                 concurrent writers silently corrupt the lease"
            ),
            Ok(_) => panic!(
                "stale Lease PUT must be rejected with 409 Conflict, not succeed"
            ),
        }
    }
}
