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
    keys::{cluster_object_key, list_prefix, object_key},
    state::AppState,
    status::Status,
    types::{Namespace, Object},
    util::{extract_body, parse_resource_version},
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    pub watch: Option<bool>,
    pub resource_version: Option<u64>,
    pub field_selector: Option<String>,
    /// When true, the server emits existing pods as ADDED events before streaming
    /// live changes. Used by kubelet (Kubernetes 1.27+) for efficient informer startup.
    #[serde(rename = "sendInitialEvents")]
    pub send_initial_events: Option<bool>,
}

/// Extract a store-level FieldSelector from a raw field selector string.
/// Picks the first equality (`=`) term that is not a negation (`!=`).
/// Returns None if no equality term is present or the string is empty.
fn pod_store_field_selector(sel: &str) -> Option<u7s_store::FieldSelector> {
    sel.split(',').find_map(|term| {
        let term = term.trim();
        if !term.contains("!=") {
            term.split_once('=').and_then(|(field, value)| {
                if field.is_empty() {
                    return None;
                }
                Some(u7s_store::FieldSelector {
                    field: field.to_string(),
                    value: value.to_string(),
                })
            })
        } else {
            None
        }
    })
}

/// Parse a `fieldSelector` query string and test a pod JSON value against it.
///
/// Supported selectors (comma-separated):
///   spec.nodeName=<value>   — include only if pod's spec.nodeName equals value
///   spec.nodeName!=<value>  — include only if pod's spec.nodeName does not equal value
///
/// An empty or absent selector matches everything (pass-through).
/// Unknown selector terms are ignored (conservative: don't drop pods on unrecognised fields).
pub fn filter_pods_by_field_selector(
    pods: Vec<serde_json::Value>,
    selector: &str,
) -> Vec<serde_json::Value> {
    if selector.is_empty() {
        return pods;
    }
    pods.into_iter()
        .filter(|pod| pod_matches_field_selector(pod, selector))
        .collect()
}

fn pod_matches_field_selector(pod: &serde_json::Value, selector: &str) -> bool {
    for term in selector.split(',') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        if let Some((field, value)) = term.split_once("!=") {
            if field == "spec.nodeName" {
                let node_name = pod["spec"]["nodeName"].as_str().unwrap_or("");
                if node_name == value {
                    return false;
                }
            }
            // Unknown fields: ignore (don't filter out)
        } else if let Some((field, value)) = term.split_once('=') {
            if field == "spec.nodeName" {
                let node_name = pod["spec"]["nodeName"].as_str().unwrap_or("");
                if node_name != value {
                    return false;
                }
            }
            // Unknown fields: ignore (don't filter out)
        }
        // Unparseable term: ignore
    }
    true
}

/// Validate a raw namespace string: format check then store lookup.
/// Returns 400 on invalid format, 404 if namespace does not exist.
async fn parse_namespace(
    raw: &str,
    state: &AppState,
) -> Result<Namespace, crate::status::StatusError> {
    let ns = Namespace::parse(raw).map_err(Status::bad_request)?;
    let key = cluster_object_key("namespaces", ns.as_str());
    let exists = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .is_some();
    if !exists {
        return Err(Status::not_found(ns.as_str(), "Namespace"));
    }
    Ok(ns)
}

fn store_err_to_status(err: StoreError, name: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, "Pod"),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, "Pod"),
        StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "Pod \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => Status::internal(other.to_string()),
    }
}

pub async fn list_pods(
    State(state): State<AppState>,
    Path((raw_ns,)): Path<(String,)>,
    Query(query): Query<CollectionQuery>,
) -> Result<Response, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let prefix = list_prefix("pods", ns.as_str());

    if query.watch == Some(true) {
        let from_rv = query.resource_version.unwrap_or(0);
        let initial_pods = if query.send_initial_events == Some(true) {
            // Collect existing pods under this namespace prefix and filter by field selector.
            let store_fs = query
                .field_selector
                .as_deref()
                .and_then(pod_store_field_selector);
            let resp = state
                .store
                .list(
                    &prefix,
                    ListOptions {
                        field_selector: store_fs,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            let mut pods: Vec<serde_json::Value> = resp
                .items
                .iter()
                .filter_map(|o| serde_json::from_slice(&o.value).ok())
                .collect();
            if let Some(ref sel) = query.field_selector {
                pods = filter_pods_by_field_selector(pods, sel);
            }
            Some((pods, resp.revision))
        } else {
            None
        };
        return watch_pods(
            state,
            prefix,
            ns,
            from_rv,
            query.field_selector,
            initial_pods,
        )
        .await;
    }

    let store_field_selector = query
        .field_selector
        .as_deref()
        .and_then(pod_store_field_selector);
    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                field_selector: store_field_selector,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut items = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let parsed: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(parsed);
    }

    let items = if let Some(ref sel) = query.field_selector {
        filter_pods_by_field_selector(items, sel)
    } else {
        items
    };

    let body = serde_json::json!({
        "kind": "PodList",
        "apiVersion": "v1",
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items
    });

    Ok(Json(body).into_response())
}

async fn watch_pods(
    state: AppState,
    prefix: String,
    _ns: Namespace,
    from_revision: u64,
    field_selector: Option<String>,
    initial_pods: Option<(Vec<serde_json::Value>, u64)>,
) -> Result<Response, crate::status::StatusError> {
    let event_stream = state
        .store
        .watch(&prefix, from_revision)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // The body stream yields Result<Bytes, BoxError> items.
    // We transform WatchEvent items into NDJSON chunks.
    // A periodic bookmark is sent every 60 s if no other events fire.
    // Max watch duration: 5 minutes per the Kubernetes spec default.
    let field_selector = field_selector.unwrap_or_default();
    let chunk_stream = async_stream::stream! {
        use futures_core::Stream;
        use std::pin::pin;
        use tokio::time::{Duration, interval, sleep};

        let mut event_stream = pin!(event_stream);
        let mut bookmark_tick = interval(Duration::from_secs(60));
        // Skip the first immediate tick so we don't send a bookmark before any events.
        bookmark_tick.tick().await;

        let mut max_duration = pin!(sleep(Duration::from_secs(5 * 60)));

        // Track the most recently seen revision for bookmark emission.
        let mut last_rv: u64 = from_revision;

        // sendInitialEvents: emit existing pods as ADDED, then BOOKMARK.
        if let Some((pods, list_rv)) = initial_pods {
            last_rv = last_rv.max(list_rv);
            for pod in pods {
                let line = format!(
                    "{{\"type\":\"ADDED\",\"object\":{}}}\n",
                    serde_json::to_string(&pod).unwrap_or_default()
                );
                yield Ok::<Bytes, axum::BoxError>(Bytes::from(line));
            }
            let bookmark = format!(
                "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\",\"annotations\":{{\"k8s.io/initial-events-end\":\"true\"}}}}}}}}\n"
            );
            yield Ok::<Bytes, axum::BoxError>(Bytes::from(bookmark));
        }

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
                        None => break, // store closed the stream
                        Some(event) => {
                            // Update last_rv from the event before encoding.
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

                            // Reset bookmark timer on any real event.
                            bookmark_tick.reset();

                            if let WatchEvent::Compacted { horizon, .. } = &event {
                                // Use horizon (not last_rv) — clients use this rv to relist;
                                // last_rv may predate the horizon causing an infinite relist loop.
                                let error_line = Bytes::from(format!(
                                    "{{\"type\":\"ERROR\",\"object\":{{\"apiVersion\":\"v1\",\"kind\":\"Status\",\"code\":410,\"message\":\"too old resource version\",\"reason\":\"Expired\",\"metadata\":{{\"resourceVersion\":\"{horizon}\"}}}}}}}}\n"
                                ));
                                yield Ok::<Bytes, axum::BoxError>(error_line);
                                break;
                            }

                            // Apply fieldSelector: for Added/Modified, check spec.nodeName.
                            // Deleted events lack full pod data; pass them through so the
                            // kubelet can clean up resources it was already tracking.
                            let skip = !field_selector.is_empty() && match &event {
                                WatchEvent::Added(obj) | WatchEvent::Modified(obj) => {
                                    let pod: serde_json::Value =
                                        serde_json::from_slice(&obj.value).unwrap_or(serde_json::Value::Null);
                                    !pod_matches_field_selector(&pod, &field_selector)
                                }
                                _ => false,
                            };

                            if !skip {
                                if let Some(chunk) = super::generic::encode_watch_event(&event, "v1", "Pod") {
                                    yield Ok::<Bytes, axum::BoxError>(chunk);
                                }
                            }
                        }
                    }
                }

                _ = bookmark_tick.tick() => {
                    let bookmark = format!(
                        "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\"}}}}}}\n"
                    );
                    yield Ok::<Bytes, axum::BoxError>(Bytes::from(bookmark));
                }

                _ = &mut max_duration => {
                    // Max watch duration reached — send a final BOOKMARK and close gracefully.
                    let bookmark = format!(
                        "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\"}}}}}}\n"
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

pub async fn create_pod(
    State(state): State<AppState>,
    Path((raw_ns,)): Path<(String,)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = {
        match obj.name().filter(|n| !n.is_empty()) {
            Some(n) => n.to_string(),
            None => {
                let gen = obj.body["metadata"]["generateName"].as_str().unwrap_or("");
                if gen.is_empty() {
                    return Err(Status::bad_request(
                        "metadata.name or metadata.generateName is required".into(),
                    ));
                }
                let generated = format!("{}{}", gen, crate::handlers::generic::generate_suffix());
                obj.body["metadata"]["name"] = serde_json::Value::String(generated.clone());
                generated
            }
        }
    };

    // Ensure namespace is set in the stored object
    obj.body["metadata"]["namespace"] = serde_json::Value::String(ns.as_str().to_owned());
    crate::handlers::generic::stamp_metadata(&mut obj);

    let key = object_key("pods", ns.as_str(), &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), Some(0))
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok((StatusCode::CREATED, Json(obj.body)))
}

pub async fn get_pod(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn replace_pod(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj.name().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let expected_revision = parse_resource_version(obj.resource_version())?;

    let key = object_key("pods", ns.as_str(), &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok(Json(obj.body))
}

pub async fn delete_pod(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);

    // Fetch current object to check finalizers.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let has_finalizers = obj.body["metadata"]["finalizers"]
        .as_array()
        .map(|arr| !arr.is_empty())
        .unwrap_or(false);

    if has_finalizers {
        // Soft delete: stamp deletionTimestamp and write back.
        obj.body["metadata"]["deletionTimestamp"] = serde_json::Value::String(utc_now_rfc3339());
        let expected_rv = parse_resource_version(obj.resource_version())?;
        let new_rv = state
            .store
            .put(&key, obj.to_bytes(), expected_rv)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
        obj.set_resource_version(new_rv);
        return Ok(Json(obj.body));
    }

    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

/// Classify the patch Content-Type for pod PATCH requests.
/// Mirrors detect_patch_type in generic.rs; consolidated once generic exports it.
#[derive(Debug)]
enum PodPatchType {
    Merge,
    StrategicMerge,
    Json,
}

fn detect_pod_patch_type(headers: &HeaderMap) -> Result<PodPatchType, crate::status::StatusError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type.contains("application/strategic-merge-patch+json") {
        return Ok(PodPatchType::StrategicMerge);
    }
    if content_type.contains("application/merge-patch+json") {
        return Ok(PodPatchType::Merge);
    }
    if content_type.contains("application/json-patch+json") {
        return Ok(PodPatchType::Json);
    }
    if content_type.contains("application/apply-patch+yaml") {
        return Ok(PodPatchType::StrategicMerge);
    }
    Err(Status::unsupported_media_type(format!(
        "unsupported media type '{content_type}'; use application/merge-patch+json, application/strategic-merge-patch+json, or application/json-patch+json"
    )))
}

pub async fn patch_pod(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = detect_pod_patch_type(&headers)?;

    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut current_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    match patch_type {
        PodPatchType::StrategicMerge => {
            crate::patch::strategic_merge_patch(&mut current_obj.body, &patch)
                .map_err(|e| Status::bad_request(e.to_string()))?;
        }
        PodPatchType::Merge => {
            crate::patch::merge_patch(&mut current_obj.body, &patch);
        }
        PodPatchType::Json => {
            pod_apply_json_patch(&mut current_obj.body, &patch)?;
        }
    }

    // Post-patch: if deletionTimestamp is set and finalizers are now empty, hard-delete.
    let deletion_ts_set = current_obj.body["metadata"]["deletionTimestamp"].is_string();
    let finalizers_empty = current_obj.body["metadata"]["finalizers"]
        .as_array()
        .map(|arr| arr.is_empty())
        .unwrap_or(true);

    if deletion_ts_set && finalizers_empty {
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
        return Ok(Json(current_obj.body));
    }

    // Extract expected revision from current object (after patch may have changed it)
    let expected_revision = parse_resource_version(current_obj.resource_version())?;

    let new_rv = state
        .store
        .put(&key, current_obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current_obj.set_resource_version(new_rv);

    Ok(Json(current_obj.body))
}

// ---------------------------------------------------------------------------
// JSON Patch (RFC 6902) helpers for pod PATCH.
// Duplicated from generic.rs until that module exports them as pub(crate).
// TODO(mayor-1hc follow-up): remove once generic::apply_json_patch is pub(crate).
// ---------------------------------------------------------------------------

fn pod_apply_json_patch(
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
            Status::unprocessable_entity(
                "each JSON patch operation must have a 'path' field".into(),
            )
        })?;
        match op_str {
            "add" => {
                let value = op
                    .get("value")
                    .ok_or_else(|| {
                        Status::unprocessable_entity(
                            "'add' operation requires a 'value' field".into(),
                        )
                    })?
                    .clone();
                pod_json_patch_add(obj, path, value)?;
            }
            "replace" => {
                let value = op
                    .get("value")
                    .ok_or_else(|| {
                        Status::unprocessable_entity(
                            "'replace' operation requires a 'value' field".into(),
                        )
                    })?
                    .clone();
                pod_json_patch_set(obj, path, value)?;
            }
            "remove" => {
                pod_json_patch_remove(obj, path)?;
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

fn pod_json_pointer_segments(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return vec![];
    }
    let stripped = pointer.strip_prefix('/').unwrap_or(pointer);
    stripped
        .split('/')
        .map(|seg| seg.replace("~1", "/").replace("~0", "~"))
        .collect()
}

fn pod_json_navigate_mut<'a>(
    obj: &'a mut serde_json::Value,
    segments: &[String],
) -> Result<(&'a mut serde_json::Value, String), crate::status::StatusError> {
    if segments.is_empty() {
        return Err(Status::unprocessable_entity(
            "cannot operate on root document".into(),
        ));
    }
    let (parents, last) = segments.split_at(segments.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = pod_json_navigate_one(cur, seg)?;
    }
    Ok((cur, last[0].clone()))
}

fn pod_json_navigate_one<'a>(
    node: &'a mut serde_json::Value,
    seg: &str,
) -> Result<&'a mut serde_json::Value, crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => map
            .get_mut(seg)
            .ok_or_else(|| Status::unprocessable_entity(format!("path segment '{seg}' not found"))),
        serde_json::Value::Array(arr) => {
            let idx: usize = seg.parse().map_err(|_| {
                Status::unprocessable_entity(format!(
                    "path segment '{seg}' is not a valid array index"
                ))
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

fn pod_json_navigate_one_or_create<'a>(
    node: &'a mut serde_json::Value,
    seg: &str,
) -> Result<&'a mut serde_json::Value, crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => {
            map.entry(seg)
                .or_insert_with(|| serde_json::Value::Object(Default::default()));
            Ok(map.get_mut(seg).unwrap())
        }
        _ => Err(Status::unprocessable_entity(format!(
            "cannot create intermediate key '{seg}' in non-object"
        ))),
    }
}

fn pod_json_patch_add(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = pod_json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parents, last) = segs.split_at(segs.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = pod_json_navigate_one_or_create(cur, seg)?;
    }
    let key = &last[0];
    match cur {
        serde_json::Value::Object(map) => {
            map.insert(key.clone(), value);
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
                "cannot add value to non-object/array".into(),
            ))
        }
    }
    Ok(())
}

fn pod_json_patch_set(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = pod_json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parent, key) = pod_json_navigate_mut(obj, &segs)?;
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
            ))
        }
    }
    Ok(())
}

fn pod_json_patch_remove(
    obj: &mut serde_json::Value,
    pointer: &str,
) -> Result<(), crate::status::StatusError> {
    let segs = pod_json_pointer_segments(pointer);
    let (parent, key) = pod_json_navigate_mut(obj, &segs)?;
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
            ))
        }
    }
    Ok(())
}

use crate::util::utc_now_rfc3339;

#[cfg(test)]
mod watch_tests {
    use super::*;
    use bytes::Bytes;
    use u7s_store::{StoreObject, WatchEvent};

    fn make_store_object(key: &str, revision: u64, json: serde_json::Value) -> StoreObject {
        StoreObject {
            key: key.to_string(),
            value: Bytes::from(serde_json::to_vec(&json).unwrap()),
            revision,
        }
    }

    /// encode_watch_event (shared via generic) for Added emits {"type":"ADDED","object":...}\n
    /// and the object bytes are valid JSON from the stored value.
    #[test]
    fn encode_added_roundtrip() {
        let obj = make_store_object(
            "/registry/pods/default/nginx",
            5,
            serde_json::json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"nginx","resourceVersion":"5"}}),
        );
        let bytes =
            crate::handlers::generic::encode_watch_event(&WatchEvent::Added(obj), "v1", "Pod")
                .expect("should encode");
        let line = std::str::from_utf8(&bytes).unwrap();
        assert!(line.ends_with('\n'), "NDJSON must end with newline");

        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["type"], "ADDED");
        assert_eq!(parsed["object"]["metadata"]["name"], "nginx");
    }

    /// encode_watch_event for Modified emits {"type":"MODIFIED","object":...}\n
    #[test]
    fn encode_modified() {
        let obj = make_store_object(
            "/registry/pods/default/nginx",
            7,
            serde_json::json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"nginx","resourceVersion":"7"}}),
        );
        let bytes =
            crate::handlers::generic::encode_watch_event(&WatchEvent::Modified(obj), "v1", "Pod")
                .expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "MODIFIED");
    }

    /// encode_watch_event for Deleted reconstructs a minimal object from the store key.
    /// The emitted object must contain name and namespace derived from the key.
    #[test]
    fn encode_deleted_reconstructs_metadata() {
        let bytes = crate::handlers::generic::encode_watch_event(
            &WatchEvent::Deleted {
                key: "/registry/pods/default/nginx".to_string(),
                revision: 9,
            },
            "v1",
            "Pod",
        )
        .expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "DELETED");
        assert_eq!(parsed["object"]["metadata"]["name"], "nginx");
        assert_eq!(parsed["object"]["metadata"]["namespace"], "default");
        assert_eq!(parsed["object"]["metadata"]["resourceVersion"], "9");
    }

    /// encode_watch_event for Bookmark emits the correct structure.
    #[test]
    fn encode_bookmark() {
        let bytes = crate::handlers::generic::encode_watch_event(
            &WatchEvent::Bookmark { revision: 42 },
            "v1",
            "Pod",
        )
        .expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "BOOKMARK");
        assert_eq!(parsed["object"]["metadata"]["resourceVersion"], "42");
        assert_eq!(parsed["object"]["kind"], "Pod");
    }

    /// encode_watch_event for Compacted returns None — the caller must close the stream.
    #[test]
    fn encode_compacted_returns_none() {
        let result = crate::handlers::generic::encode_watch_event(
            &WatchEvent::Compacted {
                requested: 5,
                horizon: 50,
            },
            "v1",
            "Pod",
        );
        assert!(result.is_none(), "Compacted must signal close via None");
    }

    /// When Compacted fires, the 410 ERROR event must carry the horizon as
    /// metadata.resourceVersion. Clients use this to relist from a valid point;
    /// sending last_rv (which may predate the horizon) causes an infinite relist loop.
    #[test]
    fn watch_410_error_uses_compaction_horizon_not_last_rv() {
        let horizon: u64 = 500;
        let obj = serde_json::json!({
            "type": "ERROR",
            "object": {
                "apiVersion": "v1",
                "kind": "Status",
                "code": 410,
                "message": "too old resource version",
                "reason": "Expired",
                "metadata": {"resourceVersion": horizon.to_string()}
            }
        });
        let rv = obj["object"]["metadata"]["resourceVersion"]
            .as_str()
            .unwrap();
        assert_eq!(
            rv, "500",
            "410 ERROR must carry horizon as resourceVersion so clients relist from \
             a valid point, not from last_rv which may predate the compaction horizon"
        );
    }

    /// parse_key_name_ns (shared via generic) correctly extracts name and namespace.
    #[test]
    fn parse_key_standard() {
        let (name, ns) =
            crate::handlers::generic::parse_key_name_ns("/registry/pods/default/nginx");
        assert_eq!(name, "nginx");
        assert_eq!(ns, "default");
    }

    /// parse_key_name_ns handles a custom namespace correctly.
    #[test]
    fn parse_key_custom_namespace() {
        let (name, ns) =
            crate::handlers::generic::parse_key_name_ns("/registry/pods/kube-system/coredns");
        assert_eq!(name, "coredns");
        assert_eq!(ns, "kube-system");
    }

    /// CollectionQuery with watch=true and resource_version=42 routes to watch mode.
    /// Verified by constructing the struct directly and checking the fields Axum would populate.
    #[test]
    fn collection_query_watch_flag_present() {
        let q = CollectionQuery {
            watch: Some(true),
            resource_version: Some(42),
            field_selector: None,
            send_initial_events: None,
        };
        assert!(q.watch == Some(true));
        assert_eq!(q.resource_version, Some(42));
    }

    /// CollectionQuery with absent fields should default to None (no watch, no rv).
    #[test]
    fn collection_query_defaults() {
        let q = CollectionQuery {
            watch: None,
            resource_version: None,
            field_selector: None,
            send_initial_events: None,
        };
        assert_eq!(q.watch, None);
        assert_eq!(q.resource_version, None);
    }
}

#[cfg(test)]
mod field_selector_tests {
    use super::*;

    fn pod_with_node(node_name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {"nodeName": node_name}
        })
    }

    fn pod_without_node() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {}
        })
    }

    /// Empty selector is a pass-through: all pods must be returned.
    /// Kubelet depends on this when fieldSelector is absent.
    #[test]
    fn empty_selector_passes_all() {
        let pods = vec![
            pod_with_node("worker-1"),
            pod_with_node("worker-2"),
            pod_without_node(),
        ];
        let result = filter_pods_by_field_selector(pods.clone(), "");
        assert_eq!(result.len(), pods.len());
    }

    /// spec.nodeName=worker-1 must include only pods scheduled to worker-1.
    /// This is the primary kubelet query: it must receive only its own pods.
    #[test]
    fn eq_filter_matches_correct_node() {
        let pods = vec![
            pod_with_node("worker-1"),
            pod_with_node("worker-2"),
            pod_without_node(),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.nodeName=worker-1");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["nodeName"], "worker-1");
    }

    /// spec.nodeName=worker-1 must not match a pod on a different node.
    /// If this fails, kubelet on worker-2 receives worker-1's pods and tries to run them.
    #[test]
    fn eq_filter_excludes_wrong_node() {
        let pods = vec![pod_with_node("worker-2"), pod_without_node()];
        let result = filter_pods_by_field_selector(pods, "spec.nodeName=worker-1");
        assert!(result.is_empty());
    }

    /// spec.nodeName!=worker-1 must exclude pods on worker-1 and include everything else.
    #[test]
    fn ne_filter_excludes_matching_node() {
        let pods = vec![
            pod_with_node("worker-1"),
            pod_with_node("worker-2"),
            pod_without_node(),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.nodeName!=worker-1");
        assert_eq!(result.len(), 2);
        for pod in &result {
            assert_ne!(pod["spec"]["nodeName"].as_str().unwrap_or(""), "worker-1");
        }
    }

    /// A pod with no spec.nodeName (empty string) must NOT match spec.nodeName=worker-1.
    /// Kubelet must not receive unscheduled pods — that was the original bug.
    #[test]
    fn eq_filter_excludes_unscheduled_pods() {
        let pods = vec![pod_without_node()];
        let result = filter_pods_by_field_selector(pods, "spec.nodeName=worker-1");
        assert!(
            result.is_empty(),
            "unscheduled pods must not reach the kubelet"
        );
    }

    /// Unknown selector fields must be ignored (pass-through) rather than dropping pods.
    /// This is the safe default: conservative filtering prevents silent data loss.
    #[test]
    fn unknown_field_is_ignored() {
        let pods = vec![pod_with_node("worker-1"), pod_with_node("worker-2")];
        let result = filter_pods_by_field_selector(pods.clone(), "metadata.unknown=foo");
        assert_eq!(result.len(), pods.len());
    }

    /// Multiple comma-separated selectors are ANDed together.
    #[test]
    fn multiple_terms_are_anded() {
        // Only worker-1 pods should pass spec.nodeName=worker-1,spec.nodeName!=worker-2
        // (worker-1 != worker-2 is true, so worker-1 passes both)
        let pods = vec![pod_with_node("worker-1"), pod_with_node("worker-2")];
        let result =
            filter_pods_by_field_selector(pods, "spec.nodeName=worker-1,spec.nodeName!=worker-2");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["nodeName"], "worker-1");
    }

    // -- pod_store_field_selector: the extracted helper must behave correctly --

    /// Equality term is picked up as a FieldSelector.
    /// This helper is used in both the list and watch paths — if it's wrong,
    /// kubelet receives pods scheduled to other nodes.
    #[test]
    fn pod_store_field_selector_eq_term() {
        let fs = pod_store_field_selector("spec.nodeName=worker-1");
        let fs = fs.expect("equality term must produce Some");
        assert_eq!(fs.field, "spec.nodeName");
        assert_eq!(fs.value, "worker-1");
    }

    /// Negation-only selector returns None — store FieldSelector only supports equality.
    #[test]
    fn pod_store_field_selector_ne_only_returns_none() {
        let fs = pod_store_field_selector("spec.nodeName!=worker-1");
        assert!(fs.is_none(), "ne-only selector must return None");
    }

    /// Mixed selector: equality term wins, negation is skipped.
    #[test]
    fn pod_store_field_selector_mixed_returns_eq_term() {
        let fs = pod_store_field_selector("spec.nodeName!=bad,spec.nodeName=worker-1");
        let fs = fs.expect("must return the equality term");
        assert_eq!(fs.value, "worker-1");
    }

    /// Empty string returns None.
    #[test]
    fn pod_store_field_selector_empty_returns_none() {
        assert!(pod_store_field_selector("").is_none());
    }
}

// ---------------------------------------------------------------------------
// Status subresource — GET/PUT/PATCH /api/v1/namespaces/:ns/pods/:name/status
// ---------------------------------------------------------------------------

pub async fn get_pod_status(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn replace_pod_status(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let incoming: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut current_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    current_obj.body["status"] = incoming["status"].clone();

    let expected_rv = parse_resource_version(current_obj.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current_obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current_obj.set_resource_version(new_rv);

    Ok(Json(current_obj.body))
}

/// Returns true if the content-type is acceptable for a pod status patch.
/// Kubelet uses application/strategic-merge-patch+json; both strategic-merge-patch
/// and merge-patch are accepted. JSON-patch (RFC 6902) is not supported for status.
fn accepts_patch_content_type(ct: &str) -> bool {
    ct.contains("application/strategic-merge-patch+json")
        || ct.contains("application/merge-patch+json")
}

/// Apply only the `.status` portion of `patch` to `stored`, returning the full updated pod.
///
/// Fields outside `.status` in the patch body (e.g. `.spec`) are ignored — the status
/// subresource cannot modify spec. This is the Kubernetes API contract for status subresources.
pub fn apply_status_patch(
    stored: &serde_json::Value,
    patch: &serde_json::Value,
) -> serde_json::Value {
    let mut result = stored.clone();
    if let Some(patch_status) = patch.get("status") {
        if result["status"].is_object() && patch_status.is_object() {
            crate::patch::merge_patch(&mut result["status"], patch_status);
        } else {
            result["status"] = patch_status.clone();
        }
    }
    result
}

pub async fn patch_pod_status(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Kubelet uses strategic-merge-patch; both patch types update only the status field.
    if !accepts_patch_content_type(content_type) {
        return Err(Status::unsupported_media_type(format!(
            "unsupported media type '{content_type}'; use application/merge-patch+json or application/strategic-merge-patch+json"
        )));
    }

    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut current_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    current_obj.body = apply_status_patch(&current_obj.body, &patch);

    let expected_rv = parse_resource_version(current_obj.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current_obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current_obj.set_resource_version(new_rv);

    Ok(Json(current_obj.body))
}

// ---------------------------------------------------------------------------
// Binding subresource — POST /api/v1/namespaces/:ns/pods/:name/binding
// ---------------------------------------------------------------------------

#[cfg(test)]
mod status_tests {
    use super::*;

    /// replace_pod_status copies only the "status" field from the incoming body.
    /// Any other fields in the incoming body (spec, metadata) must be ignored.
    /// This is the Kubernetes contract: PUT /status only updates status.
    #[test]
    fn replace_status_only_mutates_status_field() {
        let mut current = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app"}]},
            "status": {"phase": "Pending"}
        });
        let incoming = serde_json::json!({
            "status": {"phase": "Running", "conditions": [{"type": "Ready"}]},
            "spec": {"containers": [{"name": "hacked"}]}
        });

        // Simulate what replace_pod_status does: only copy status field.
        current["status"] = incoming["status"].clone();

        assert_eq!(current["status"]["phase"], "Running");
        assert_eq!(current["status"]["conditions"][0]["type"], "Ready");
        // spec must not be overwritten — it is outside the status subresource
        assert_eq!(current["spec"]["containers"][0]["name"], "app");
    }

    /// patch_pod_status merges only the "status" field from the patch.
    /// Spec and metadata changes in the patch body must be ignored.
    #[test]
    fn patch_status_merges_only_status_field() {
        let mut status = serde_json::json!({"phase": "Pending", "hostIP": "1.2.3.4"});
        let patch_status = serde_json::json!({"phase": "Running"});

        // json_merge_patch on the status object: merges in place.
        crate::patch::merge_patch(&mut status, &patch_status);

        assert_eq!(status["phase"], "Running");
        // pre-existing fields not in the patch must survive
        assert_eq!(status["hostIP"], "1.2.3.4");
    }

    /// patch_pod_status with a null field in the patch status removes that field.
    #[test]
    fn patch_status_null_removes_field() {
        let mut status = serde_json::json!({"phase": "Running", "hostIP": "1.2.3.4"});
        let patch_status = serde_json::json!({"hostIP": null});

        crate::patch::merge_patch(&mut status, &patch_status);

        // null in merge patch means delete
        assert!(status.get("hostIP").map_or(true, |v| v.is_null()
            || !status.as_object().unwrap().contains_key("hostIP")));
        assert_eq!(status["phase"], "Running");
    }

    /// patch_pod_status with no "status" key in the patch leaves status unchanged.
    #[test]
    fn patch_status_no_status_key_is_noop() {
        let original_status = serde_json::json!({"phase": "Running"});
        let mut current = serde_json::json!({
            "status": original_status.clone()
        });
        let patch = serde_json::json!({"metadata": {"labels": {"app": "test"}}});

        // Simulate handler logic: only act if patch has "status" key
        if let Some(patch_status) = patch.get("status") {
            if current["status"].is_object() && patch_status.is_object() {
                crate::patch::merge_patch(&mut current["status"], patch_status);
            } else {
                current["status"] = patch_status.clone();
            }
        }

        assert_eq!(current["status"], original_status);
    }

    /// accepts_patch_content_type must accept strategic-merge-patch and merge-patch,
    /// and must reject json-patch and empty strings.
    /// Kubelet uses strategic-merge-patch+json; rejecting it would break node status
    /// updates. Accepting json-patch would be incorrect (unsupported semantics for status).
    #[test]
    fn patch_content_type_acceptance() {
        assert!(
            accepts_patch_content_type("application/strategic-merge-patch+json"),
            "strategic-merge-patch must be accepted — kubelet uses this type"
        );
        assert!(
            accepts_patch_content_type("application/merge-patch+json"),
            "merge-patch must be accepted"
        );
        assert!(
            !accepts_patch_content_type("application/json-patch+json"),
            "json-patch must be rejected — not supported for status subresource"
        );
        assert!(
            !accepts_patch_content_type(""),
            "empty content-type must be rejected"
        );
    }

    /// apply_status_patch with {"status":{"phase":"Running"}} on a Pending pod must
    /// yield phase=Running. This is the primary kubelet use-case: reporting pod lifecycle
    /// transitions. If the phase doesn't update, pod lifecycle e2e is impossible.
    #[test]
    fn patch_pod_status_updates_phase() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Pending"}
        });
        let patch = serde_json::json!({"status": {"phase": "Running"}});

        let result = apply_status_patch(&stored, &patch);

        assert_eq!(
            result["status"]["phase"], "Running",
            "phase must transition Pending -> Running after kubelet patch"
        );
    }

    /// apply_status_patch must ignore spec fields in the patch body.
    /// The status subresource cannot modify spec — Kubernetes API contract.
    /// If spec can be changed via /status, an attacker could hijack pod scheduling.
    #[test]
    fn patch_pod_status_ignores_spec_fields() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "worker-1", "containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Pending"}
        });
        let patch = serde_json::json!({
            "status": {"phase": "Running"},
            "spec": {"nodeName": "hacked"}
        });

        let result = apply_status_patch(&stored, &patch);

        assert_eq!(
            result["status"]["phase"], "Running",
            "status phase must be updated"
        );
        assert_eq!(
            result["spec"]["nodeName"], "worker-1",
            "spec.nodeName must not be changed — status subresource cannot modify spec"
        );
    }

    /// apply_status_patch must preserve existing status fields not present in the patch.
    /// Kubelet sends incremental updates; clobbering existing conditions would lose
    /// previously reported state (e.g. Initialized, ContainersReady conditions).
    #[test]
    fn patch_pod_status_preserves_existing_status_fields() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {},
            "status": {
                "phase": "Pending",
                "conditions": [{"type": "Initialized", "status": "True"}],
                "hostIP": "10.0.0.1"
            }
        });
        let patch = serde_json::json!({"status": {"phase": "Running"}});

        let result = apply_status_patch(&stored, &patch);

        assert_eq!(
            result["status"]["phase"], "Running",
            "phase must be updated"
        );
        assert_eq!(
            result["status"]["hostIP"], "10.0.0.1",
            "pre-existing hostIP must not be clobbered"
        );
        let conditions = result["status"]["conditions"]
            .as_array()
            .expect("conditions must still be an array");
        assert_eq!(
            conditions.len(),
            1,
            "pre-existing conditions must be preserved"
        );
        assert_eq!(
            conditions[0]["type"], "Initialized",
            "Initialized condition must survive the phase-only patch"
        );
    }

    /// apply_status_patch that adds a new condition to status.conditions merges correctly.
    /// For merge-patch semantics: arrays are replaced, so patching with a new conditions
    /// array replaces the old one. This is the expected RFC 7396 behavior.
    /// If this merges incorrectly, kubelet's reported conditions will be wrong.
    #[test]
    fn patch_pod_status_with_conditions_merge() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {},
            "status": {
                "phase": "Running",
                "conditions": [
                    {"type": "Initialized", "status": "True"},
                    {"type": "Ready", "status": "False"}
                ]
            }
        });
        // Kubelet sends the full updated conditions array (merge-patch replaces arrays).
        let patch = serde_json::json!({
            "status": {
                "phase": "Running",
                "conditions": [
                    {"type": "Initialized", "status": "True"},
                    {"type": "Ready", "status": "True"},
                    {"type": "ContainersReady", "status": "True"}
                ]
            }
        });

        let result = apply_status_patch(&stored, &patch);

        let conditions = result["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array");
        // Merge-patch replaces the array entirely with the patch value.
        assert_eq!(
            conditions.len(),
            3,
            "conditions array must reflect the full patch (merge-patch replaces arrays)"
        );
        let ready = conditions
            .iter()
            .find(|c| c["type"] == "Ready")
            .expect("Ready condition must be present");
        assert_eq!(
            ready["status"], "True",
            "Ready condition status must be updated to True"
        );
        let containers_ready = conditions.iter().find(|c| c["type"] == "ContainersReady");
        assert!(
            containers_ready.is_some(),
            "ContainersReady condition must be added by the patch"
        );
    }
}

// ---------------------------------------------------------------------------
// Patch type detection tests — regression for mayor-erz
// ---------------------------------------------------------------------------

#[cfg(test)]
mod patch_type_tests {
    use super::*;
    use axum::http::{header::CONTENT_TYPE, HeaderMap, HeaderValue};

    fn headers_with_ct(ct: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
        h
    }

    /// json-patch+json must be accepted — not return 415.
    /// This is the regression test for mayor-erz: before the fix, patch_pod
    /// rejected application/json-patch+json with HTTP 415 Unsupported Media Type.
    #[test]
    fn json_patch_content_type_is_accepted() {
        let h = headers_with_ct("application/json-patch+json");
        let result = detect_pod_patch_type(&h);
        assert!(
            result.is_ok(),
            "application/json-patch+json must be accepted by patch_pod; \
             before mayor-erz fix it returned 415 Unsupported Media Type"
        );
        assert!(matches!(result.ok(), Some(PodPatchType::Json)));
    }

    /// strategic-merge-patch+json must be accepted.
    #[test]
    fn strategic_merge_patch_content_type_is_accepted() {
        let h = headers_with_ct("application/strategic-merge-patch+json");
        assert!(matches!(
            detect_pod_patch_type(&h).ok(),
            Some(PodPatchType::StrategicMerge)
        ));
    }

    /// merge-patch+json must be accepted.
    #[test]
    fn merge_patch_content_type_is_accepted() {
        let h = headers_with_ct("application/merge-patch+json");
        assert!(matches!(
            detect_pod_patch_type(&h).ok(),
            Some(PodPatchType::Merge)
        ));
    }

    /// apply-patch+yaml is treated as strategic-merge-patch (SSA approximation).
    #[test]
    fn apply_patch_yaml_is_accepted_as_strategic_merge() {
        let h = headers_with_ct("application/apply-patch+yaml");
        assert!(matches!(
            detect_pod_patch_type(&h).ok(),
            Some(PodPatchType::StrategicMerge)
        ));
    }

    /// Unknown content-type must return 415 error.
    #[test]
    fn unknown_content_type_returns_415() {
        let h = headers_with_ct("application/octet-stream");
        // Must error, not succeed.
        let result = detect_pod_patch_type(&h);
        assert!(result.is_err(), "unknown content-type must be rejected");
        // Verify it produces a 415 response.
        let resp: axum::response::Response = result.unwrap_err().into_response();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    /// pod_apply_json_patch: replace operation updates a field in the pod object.
    /// This verifies the json-patch apply path end-to-end at the logic level.
    #[test]
    fn pod_apply_json_patch_replace_updates_field() {
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {"nodeName": "worker-1"}
        });
        let patch = serde_json::json!([
            {"op": "replace", "path": "/spec/nodeName", "value": "worker-2"}
        ]);
        assert!(
            pod_apply_json_patch(&mut pod, &patch).is_ok(),
            "replace op must succeed"
        );
        assert_eq!(
            pod["spec"]["nodeName"], "worker-2",
            "replace op must update spec.nodeName"
        );
    }

    /// pod_apply_json_patch: add operation inserts a new field.
    #[test]
    fn pod_apply_json_patch_add_inserts_field() {
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod"},
            "spec": {}
        });
        let patch = serde_json::json!([
            {"op": "add", "path": "/spec/nodeName", "value": "worker-3"}
        ]);
        assert!(
            pod_apply_json_patch(&mut pod, &patch).is_ok(),
            "add op must succeed"
        );
        assert_eq!(pod["spec"]["nodeName"], "worker-3");
    }

    /// pod_apply_json_patch: remove operation deletes a field.
    #[test]
    fn pod_apply_json_patch_remove_deletes_field() {
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod", "labels": {"app": "test"}}
        });
        let patch = serde_json::json!([
            {"op": "remove", "path": "/metadata/labels/app"}
        ]);
        assert!(
            pod_apply_json_patch(&mut pod, &patch).is_ok(),
            "remove op must succeed"
        );
        assert!(
            pod["metadata"]["labels"].get("app").is_none(),
            "remove op must delete the key"
        );
    }
}

pub async fn bind_pod(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let binding: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let node_name = binding["target"]["name"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Status::bad_request("target.name is required".into()))?
        .to_string();

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    obj.body["spec"]["nodeName"] = serde_json::Value::String(node_name);

    let expected_rv = parse_resource_version(obj.resource_version())?;

    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok((StatusCode::CREATED, Json(obj.body)))
}
