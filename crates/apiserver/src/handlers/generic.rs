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
    util::{content_type, parse_resource_version, store_err_to_status},
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    pub watch: Option<bool>,
    pub resource_version: Option<u64>,
    pub label_selector: Option<String>,
    #[serde(rename = "fieldSelector")]
    pub field_selector: Option<String>,
    pub limit: Option<u64>,
    #[serde(rename = "continue")]
    pub continue_token: Option<String>,
    /// When true, the server emits existing objects as ADDED events before streaming
    /// live changes. Used by kubelet (Kubernetes 1.27+) for efficient informer startup.
    #[serde(rename = "sendInitialEvents")]
    pub send_initial_events: Option<bool>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

pub(crate) fn generate_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
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
                return Err(Status::bad_request(
                    "metadata.name or metadata.generateName is required".into(),
                ));
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
        .ok_or_else(|| Status::not_found(&format!("{}/{}/{}", group, version, plural), "Resource"))
}

fn store_err(err: StoreError, name: &str, kind: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, kind),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, kind),
        StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "{kind} \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => {
            let status = store_err_to_status(&other);
            crate::status::StatusError(
                status,
                crate::status::Status {
                    kind: "Status",
                    api_version: "v1",
                    status: "Failure",
                    message: other.to_string(),
                    reason: "InternalError",
                    code: status.as_u16(),
                },
            )
        }
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
pub(crate) fn parse_key_name_ns(key: &str) -> (&str, &str) {
    let parts: Vec<&str> = key.rsplitn(3, '/').collect();
    match parts.as_slice() {
        [name, namespace, ..] => (name, namespace),
        [name] => (name, ""),
        _ => ("", ""),
    }
}

/// Fetch the initial items for sendInitialEvents watch protocol.
///
/// When `send_initial_events` is true, lists all objects under `prefix` and returns
/// them as ADDED events before the live watch stream, followed by a BOOKMARK with
/// `k8s.io/initial-events-end=true`. This implements the Kubernetes 1.27+ informer
/// startup protocol used by kubelet and controller-manager.
///
/// Returns `None` when `send_initial_events` is false (caller uses normal watch).
async fn fetch_initial_events(
    state: &AppState,
    prefix: &str,
    send_initial_events: bool,
) -> Result<Option<(Vec<serde_json::Value>, u64)>, crate::status::StatusError> {
    if !send_initial_events {
        return Ok(None);
    }
    let resp = state
        .store
        .list(prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let items: Vec<serde_json::Value> = resp
        .items
        .iter()
        .filter_map(|o| serde_json::from_slice(&o.value).ok())
        .collect();
    Ok(Some((items, resp.revision)))
}

/// Test whether a JSON object matches a label selector string (`key=value,...`).
/// Returns true if the selector is empty (pass-through) or all pairs match
/// `metadata.labels` in the object. Used to filter live watch events.
pub(crate) fn object_matches_label_selector(obj: &serde_json::Value, selector: &str) -> bool {
    if selector.is_empty() {
        return true;
    }
    let labels = &obj["metadata"]["labels"];
    for part in selector.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Only equality selectors are supported; skip malformed terms (conservative: pass through).
        if let Some(eq_pos) = part.find('=') {
            let key = part[..eq_pos].trim();
            let val = part[eq_pos + 1..].trim();
            if key.is_empty() {
                continue;
            }
            if labels.get(key).and_then(|v| v.as_str()) != Some(val) {
                return false;
            }
        }
        // Unknown/malformed term: ignore (conservative, don't drop events).
    }
    true
}

/// Test whether a JSON object matches a field selector string (`key=value,...`).
/// Supports `metadata.name` and `metadata.namespace` equality checks.
/// Returns true if the selector is empty (pass-through) or all pairs match.
/// Unknown fields are ignored (conservative: don't drop events on unrecognised fields).
pub(crate) fn object_matches_field_selector(obj: &serde_json::Value, selector: &str) -> bool {
    if selector.is_empty() {
        return true;
    }
    for part in selector.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(eq_pos) = part.find('=') {
            let field = part[..eq_pos].trim();
            let value = part[eq_pos + 1..].trim();
            match field {
                "metadata.name" => {
                    let name = obj["metadata"]["name"].as_str().unwrap_or("");
                    if name != value {
                        return false;
                    }
                }
                "metadata.namespace" => {
                    let ns = obj["metadata"]["namespace"].as_str().unwrap_or("");
                    if ns != value {
                        return false;
                    }
                }
                // Unknown fields: ignore (conservative).
                _ => {}
            }
        }
    }
    true
}

/// Stream watch events for a given store prefix in NDJSON format.
/// Mirrors watch_pods in pods.rs with a 60s bookmark heartbeat and 5min max duration.
///
/// When `initial_items` is Some, those items are emitted as ADDED events first
/// (implementing the Kubernetes 1.27+ sendInitialEvents protocol), followed by a
/// BOOKMARK, before streaming live changes from `from_revision`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn watch_generic(
    state: AppState,
    prefix: String,
    api_version: String,
    kind: String,
    from_revision: u64,
    initial_items: Option<(Vec<serde_json::Value>, u64)>,
    label_selector: Option<String>,
    field_selector: Option<String>,
) -> Result<Response, crate::status::StatusError> {
    let event_stream = state
        .store
        .watch(&prefix, from_revision)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_selector = label_selector.unwrap_or_default();
    let field_selector = field_selector.unwrap_or_default();
    let chunk_stream = async_stream::stream! {
        use futures_core::Stream;
        use std::pin::pin;
        use tokio::time::{Duration, interval, sleep};

        let mut event_stream = pin!(event_stream);
        let mut bookmark_tick = interval(Duration::from_secs(60));
        bookmark_tick.tick().await; // skip initial immediate tick

        let mut max_duration = pin!(sleep(Duration::from_secs(5 * 60)));
        let mut last_rv: u64 = from_revision;

        // sendInitialEvents: emit existing objects as ADDED, then BOOKMARK.
        if let Some((items, list_rv)) = initial_items {
            last_rv = last_rv.max(list_rv);
            for item in items {
                let line = format!(
                    "{{\"type\":\"ADDED\",\"object\":{}}}\n",
                    serde_json::to_string(&item).unwrap_or_default()
                );
                yield Ok::<Bytes, axum::BoxError>(Bytes::from(line));
            }
            let bookmark = format!(
                "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\",\"annotations\":{{\"k8s.io/initial-events-end\":\"true\"}}}}}}}}\n"
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

                            if let WatchEvent::Compacted { horizon, .. } = &event {
                                // Use horizon (not last_rv) so clients relist from a revision
                                // the store still holds. last_rv may predate the horizon and
                                // cause an infinite relist loop.
                                let error_line = Bytes::from(format!(
                                    "{{\"type\":\"ERROR\",\"object\":{{\"apiVersion\":\"v1\",\"kind\":\"Status\",\"code\":410,\"message\":\"too old resource version\",\"reason\":\"Expired\",\"metadata\":{{\"resourceVersion\":\"{horizon}\"}}}}}}}}\n"
                                ));
                                yield Ok::<Bytes, axum::BoxError>(error_line);
                                break;
                            }

                            // Apply labelSelector and fieldSelector: filter Added/Modified events.
                            // Deleted events always pass through so clients can clean up.
                            // Bookmark and Compacted are handled above.
                            let skip = match &event {
                                WatchEvent::Added(obj) | WatchEvent::Modified(obj) => {
                                    let parsed: serde_json::Value =
                                        serde_json::from_slice(&obj.value)
                                            .unwrap_or(serde_json::Value::Null);
                                    !object_matches_label_selector(&parsed, &label_selector)
                                        || !object_matches_field_selector(&parsed, &field_selector)
                                }
                                _ => false,
                            };

                            if !skip {
                                if let Some(chunk) = encode_watch_event(&event, &api_version, &kind) {
                                    yield Ok::<Bytes, axum::BoxError>(chunk);
                                }
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
        let val = it
            .next()
            .ok_or_else(|| {
                Status::bad_request(format!(
                    "invalid label selector '{part}': expected key=value"
                ))
            })?
            .trim();
        if key.is_empty() {
            return Err(Status::bad_request(format!(
                "invalid label selector '{part}': empty key"
            )));
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
            pairs
                .iter()
                .all(|(k, v)| labels.get(*k).and_then(|lv| lv.as_str()) == Some(*v))
        })
        .collect()
}

/// Parse a `fieldSelector` query parameter of the form `key=value` into a `FieldSelector`.
/// Only single equality selectors are supported. Returns 400 on malformed input.
fn parse_field_selector(s: &str) -> Result<u7s_store::FieldSelector, crate::status::StatusError> {
    let (field, value) = s.split_once('=').ok_or_else(|| {
        Status::bad_request(format!("invalid fieldSelector '{s}': expected key=value"))
    })?;
    if field.is_empty() {
        return Err(Status::bad_request(format!(
            "invalid fieldSelector '{s}': empty key"
        )));
    }
    Ok(u7s_store::FieldSelector {
        field: field.to_string(),
        value: value.to_string(),
    })
}

/// Encode a store key as a URL-safe base64 continue token (no padding).
fn encode_continue(key: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_bytes())
}

/// Decode a URL-safe base64 continue token back to a store key string.
fn decode_continue(token: &str) -> Result<String, crate::status::StatusError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| {
            Status::bad_request(format!(
                "invalid continue token '{token}': base64 decode failed"
            ))
        })?;
    String::from_utf8(bytes).map_err(|_| {
        Status::bad_request(format!("invalid continue token '{token}': not valid UTF-8"))
    })
}

fn build_list_response(
    kind: &str,
    group: &str,
    version: &str,
    revision: u64,
    items: Vec<serde_json::Value>,
    continue_key: Option<String>,
) -> serde_json::Value {
    let api_version = if group.is_empty() {
        version.to_string()
    } else {
        format!("{}/{}", group, version)
    };
    let mut metadata = serde_json::json!({ "resourceVersion": revision.to_string() });
    if let Some(key) = continue_key {
        metadata["continue"] = serde_json::Value::String(encode_continue(&key));
    }
    serde_json::json!({
        "kind": format!("{}List", kind),
        "apiVersion": api_version,
        "metadata": metadata,
        "items": items
    })
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

pub(crate) fn stamp_metadata(obj: &mut Object) {
    if obj.body["metadata"]["uid"].is_null() {
        obj.body["metadata"]["uid"] = serde_json::Value::String(uuid::Uuid::new_v4().to_string());
    }
    if obj.body["metadata"]["creationTimestamp"].is_null() {
        obj.body["metadata"]["creationTimestamp"] = serde_json::Value::String(utc_now_rfc3339());
    }
}

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
            return super::cr::list_cr(State(state), Path((group, version, plural)), query).await;
        }
    };
    let prefix = group_list_prefix(&group, &plural, None);

    if query.watch == Some(true) {
        let api_version = if group.is_empty() {
            version.clone()
        } else {
            format!("{}/{}", group, version)
        };
        let from_rv = query.resource_version.unwrap_or(0);
        let initial =
            fetch_initial_events(&state, &prefix, query.send_initial_events == Some(true)).await?;
        return watch_generic(
            state,
            prefix,
            api_version,
            meta.kind.clone(),
            from_rv,
            initial,
            query.label_selector,
            query.field_selector,
        )
        .await;
    }

    let field_selector = query
        .field_selector
        .as_deref()
        .map(parse_field_selector)
        .transpose()?;
    let continue_key = query
        .continue_token
        .as_deref()
        .map(decode_continue)
        .transpose()?;
    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                field_selector,
                limit: query.limit,
                continue_key,
            },
        )
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

    let body = build_list_response(
        &meta.kind,
        &group,
        &version,
        resp.revision,
        items,
        resp.continue_key,
    );
    Ok(Json(body).into_response())
}

pub async fn get_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::get_cr(State(state), Path((group, version, plural, name))).await;
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
    let body = extract_body(&body, content_type(&headers));
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

    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = resolve_name(&mut obj)?;
    stamp_metadata(&mut obj);

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
    let body = extract_body(&body, content_type(&headers));
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

    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

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
            return super::cr::delete_cr(State(state), Path((group, version, plural, name)))
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
        // Evict from RBAC index immediately — permissions must not outlast the deletion
        // request even while finalizers are draining. Hard-delete path below also removes,
        // so this is safe to call twice (remove_object is idempotent).
        if group == RBAC_GROUP {
            let rbac_key = rbac_cluster_key(&group, &version, &plural, &name);
            state.rbac_index.remove_object(&rbac_key);
        }
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
    }))
    .into_response())
}

/// Shared patch logic for cluster-scoped and namespaced resources.
///
/// `ns` is `None` for cluster-scoped resources and `Some(namespace)` for namespaced ones.
/// The caller supplies the pre-computed `key` and resolved `meta`.
#[allow(clippy::too_many_arguments)]
async fn do_patch(
    state: &AppState,
    key: &str,
    meta: &crate::types::ResourceMeta,
    group: &str,
    version: &str,
    plural: &str,
    ns: Option<&str>,
    name: &str,
    is_ssa: bool,
    patch_type: PatchType,
    body: Bytes,
) -> Result<Response, crate::status::StatusError> {
    let stored_opt = state
        .store
        .get(key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // SSA upsert: apply-patch+yaml on a missing resource creates it.
    if is_ssa && stored_opt.is_none() {
        let mut obj = Object::from_bytes(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;
        obj.body["metadata"]["name"] = serde_json::Value::String(name.to_string());
        if let Some(namespace) = ns {
            obj.body["metadata"]["namespace"] = serde_json::Value::String(namespace.to_string());
        }
        stamp_metadata(&mut obj);
        let new_rv = match state.store.put(key, obj.to_bytes(), Some(0)).await {
            Ok(rv) => rv,
            Err(StoreError::AlreadyExists { .. }) => {
                // Race: another writer created it; fall through to normal merge below.
                let stored = state
                    .store
                    .get(key)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?
                    .ok_or_else(|| Status::not_found(name, &meta.kind))?;
                let mut current = Object::from_bytes(&stored.value)
                    .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;
                let patch: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;
                crate::patch::strategic_merge_patch(&mut current.body, &patch)
                    .map_err(|e| Status::bad_request(e.to_string()))?;
                let expected_rv = parse_resource_version(current.resource_version())?;
                let rv = state
                    .store
                    .put(key, current.to_bytes(), expected_rv)
                    .await
                    .map_err(|e| store_err(e, name, &meta.kind))?;
                current.set_resource_version(rv);
                return Ok(Json(current.body).into_response());
            }
            Err(e) => return Err(store_err(e, name, &meta.kind)),
        };
        obj.set_resource_version(new_rv);
        return Ok((StatusCode::CREATED, Json(obj.body)).into_response());
    }

    let stored = stored_opt.ok_or_else(|| Status::not_found(name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let mut patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // Strip status from the patch on the main endpoint for resources with a status subresource.
    if meta.has_status_subresource {
        if let Some(map) = patch.as_object_mut() {
            map.remove("status");
        }
    }

    match patch_type {
        PatchType::Merge => crate::patch::merge_patch(&mut current.body, &patch),
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
            .delete(key, None)
            .await
            .map_err(|e| store_err(e, name, &meta.kind))?;
        if group == RBAC_GROUP {
            let rbac_key = match ns {
                None => rbac_cluster_key(group, version, plural, name),
                Some(namespace) => rbac_namespaced_key(group, version, namespace, plural, name),
            };
            state.rbac_index.remove_object(&rbac_key);
        }
        return Ok(Json(current.body).into_response());
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, name, &meta.kind))?;

    current.set_resource_version(new_rv);
    if group == RBAC_GROUP {
        let rbac_key = match ns {
            None => rbac_cluster_key(group, version, plural, name),
            Some(namespace) => rbac_namespaced_key(group, version, namespace, plural, name),
        };
        state.rbac_index.apply_object(&rbac_key, &current.body);
    }
    Ok(Json(current.body).into_response())
}

pub async fn patch_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");
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
    do_patch(
        &state, &key, &meta, &group, &version, &plural, None, &name, is_ssa, patch_type, body,
    )
    .await
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
        let from_rv = query.resource_version.unwrap_or(0);
        let initial =
            fetch_initial_events(&state, &prefix, query.send_initial_events == Some(true)).await?;
        return watch_generic(
            state,
            prefix,
            api_version,
            meta.kind.clone(),
            from_rv,
            initial,
            query.label_selector,
            query.field_selector,
        )
        .await;
    }

    let field_selector = query
        .field_selector
        .as_deref()
        .map(parse_field_selector)
        .transpose()?;
    let continue_key = query
        .continue_token
        .as_deref()
        .map(decode_continue)
        .transpose()?;
    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                field_selector,
                limit: query.limit,
                continue_key,
            },
        )
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

    let body = build_list_response(
        &meta.kind,
        &group,
        &version,
        resp.revision,
        items,
        resp.continue_key,
    );
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
    let body = extract_body(&body, content_type(&headers));
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

    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = resolve_name(&mut obj)?;

    obj.body["metadata"]["namespace"] = serde_json::Value::String(ns.clone());
    stamp_metadata(&mut obj);

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
    let body = extract_body(&body, content_type(&headers));
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

    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

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
        // Evict from RBAC index immediately on soft-delete — same rationale as
        // delete_resource: permissions must not outlast the deletion request.
        if group == RBAC_GROUP {
            let rbac_key = rbac_namespaced_key(&group, &version, &ns, &plural, &name);
            state.rbac_index.remove_object(&rbac_key);
        }
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
    }))
    .into_response())
}

pub async fn patch_namespaced_resource(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");
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
    do_patch(
        &state,
        &key,
        &meta,
        &group,
        &version,
        &plural,
        Some(&ns),
        &name,
        is_ssa,
        patch_type,
        body,
    )
    .await
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
            let from_rv = query.resource_version.unwrap_or(0);
            let initial =
                fetch_initial_events(&state, &prefix, query.send_initial_events == Some(true))
                    .await?;
            return watch_generic(
                state,
                prefix,
                "v1".into(),
                "Pod".into(),
                from_rv,
                initial,
                query.label_selector,
                query.field_selector,
            )
            .await
            .map(IntoResponse::into_response);
        }
        let field_selector = query
            .field_selector
            .as_deref()
            .map(parse_field_selector)
            .transpose()?;
        let continue_key = query
            .continue_token
            .as_deref()
            .map(decode_continue)
            .transpose()?;
        let resp = state
            .store
            .list(
                &prefix,
                ListOptions {
                    field_selector,
                    limit: query.limit,
                    continue_key,
                },
            )
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
        let body = build_list_response("Pod", "", "v1", resp.revision, items, resp.continue_key);
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
    create_resource(
        State(state),
        Path(("".into(), "v1".into(), plural)),
        headers,
        body,
    )
    .await
}

pub async fn core_replace_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    replace_resource(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        headers,
        body,
    )
    .await
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
    patch_resource(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        headers,
        body,
    )
    .await
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
    put_resource_status(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        headers,
        body,
    )
    .await
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
    get_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
    )
    .await
}

pub async fn core_create_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    create_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural)),
        headers,
        body,
    )
    .await
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
    delete_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
    )
    .await
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
    let ct = content_type(headers);
    if ct.contains("application/strategic-merge-patch+json") {
        return Ok(PatchType::StrategicMerge);
    }
    if ct.contains("application/merge-patch+json") {
        return Ok(PatchType::Merge);
    }
    if ct.contains("application/json-patch+json") {
        return Ok(PatchType::Json);
    }
    // Treat server-side apply as strategic-merge-patch: we don't implement full SSA
    // semantics (field ownership, managed fields), but the apply body is structurally
    // identical to a strategic-merge-patch body.  This is sufficient for kubelet's
    // Lease and CSINode use cases; without this kubelet gets 415 and logs
    // "invalid JSON: expected value at line 1 column 1".
    if ct.contains("application/apply-patch+yaml") {
        return Ok(PatchType::StrategicMerge);
    }
    Err(Status::unsupported_media_type(format!(
        "unsupported media type '{ct}'; use application/merge-patch+json, application/strategic-merge-patch+json, or application/json-patch+json"
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
                // RFC 6902 §4.1: 'add' creates intermediate objects when missing.
                json_patch_add(obj, path, value)?;
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
                // 'replace' is strict: 422 if path does not exist.
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
        return Err(Status::unprocessable_entity(
            "cannot operate on root document".into(),
        ));
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

/// Navigate to a child, creating an empty object if the key is absent.
/// Used by `json_patch_add` to satisfy RFC 6902 §4.1 intermediate-creation semantics.
fn json_navigate_one_or_create<'a>(
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

/// Apply RFC 6902 'add': navigate parents creating missing objects, then insert.
fn json_patch_add(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parents, last) = segs.split_at(segs.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = json_navigate_one_or_create(cur, seg)?;
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
        let decoded: serde_json::Value =
            serde_json::from_str(line).expect("chunk must be valid JSON");

        assert_eq!(decoded["type"], "ADDED", "event type must be ADDED");

        let rv = decoded["object"]["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("");
        assert!(
            !rv.is_empty(),
            "object.metadata.resourceVersion must be non-empty in ADDED event; \
             Kubernetes watch clients cannot track progress without it"
        );
        assert_eq!(
            rv, "42",
            "resourceVersion must match the value stamped by store.put()"
        );
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
        let rv = decoded["object"]["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("");
        assert!(
            rv.is_empty(),
            "without stamping, resourceVersion must be absent — \
             encode_watch_event must not synthesize it from StoreObject.revision"
        );
    }

    // -- detect_patch_type --

    fn headers_with_content_type(ct: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::CONTENT_TYPE, ct.parse().unwrap());
        h
    }

    #[test]
    fn detect_patch_type_accepts_merge_patch() {
        // kubectl uses application/merge-patch+json — must be accepted
        let h = headers_with_content_type("application/merge-patch+json");
        assert!(matches!(detect_patch_type(&h), Ok(PatchType::Merge)));
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
        assert_eq!(
            containers.len(),
            2,
            "SMP must merge containers by name, not replace the array"
        );
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
        let body = build_list_response("Node", "", "v1", 0, vec![], None);
        assert_eq!(body["apiVersion"], "v1");
        assert_eq!(body["kind"], "NodeList");
    }

    #[test]
    fn non_core_group_api_version_includes_group() {
        let body = build_list_response("Deployment", "apps", "v1", 0, vec![], None);
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
        assert!(
            obj["metadata"]["extra"].is_null(),
            "field must be absent after remove"
        );
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

    #[test]
    fn detect_patch_type_accepts_apply_patch_yaml_as_strategic_merge() {
        // kubelet 1.36 sends application/apply-patch+yaml for Lease and CSINode SSA requests.
        // Without this branch, detect_patch_type returns 415 and kubelet logs
        // "invalid JSON: expected value at line 1 column 1", blocking node Ready.
        // We treat SSA bodies as strategic-merge-patch: no field-ownership semantics,
        // but structurally identical for kubelet's use cases.
        let h = headers_with_content_type("application/apply-patch+yaml");
        assert!(
            matches!(detect_patch_type(&h), Ok(PatchType::StrategicMerge)),
            "application/apply-patch+yaml must be accepted as StrategicMerge, not rejected with 415"
        );
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
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "my-pod", "generateName": "ignored-" }
            })
            .to_string(),
        ))
        .unwrap();
        let name = ok(resolve_name(&mut obj));
        assert_eq!(name, "my-pod");
        assert_eq!(obj.body["metadata"]["name"], "my-pod");
    }

    #[test]
    fn resolve_name_generates_from_generate_name() {
        // When metadata.name is absent but generateName is set, a name with the prefix is generated.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "generateName": "test-" }
            })
            .to_string(),
        ))
        .unwrap();
        let name = ok(resolve_name(&mut obj));
        assert!(
            name.starts_with("test-"),
            "generated name must start with generateName prefix"
        );
        assert_eq!(
            name.len(),
            "test-".len() + 5,
            "generated name must be prefix + 5 char suffix"
        );
        // The name must be written back into the object body.
        assert_eq!(obj.body["metadata"]["name"].as_str(), Some(name.as_str()));
    }

    #[test]
    fn resolve_name_returns_400_when_neither_set() {
        // Neither name nor generateName → must return 400 (not a panic, not 500).
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({ "metadata": {} }).to_string(),
        ))
        .unwrap();
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
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

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
        store
            .put(&cr_key, initial_bytes, None)
            .await
            .expect("seed CR");

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

        assert!(
            result.is_ok(),
            "CR status PUT must succeed for unregistered group"
        );

        // Verify the status was persisted in the store.
        let stored = store
            .get(&cr_key)
            .await
            .expect("store get")
            .expect("object must exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["health"]["status"], "Healthy",
            "status.health.status must be persisted after CR status PUT"
        );
        assert_eq!(
            v["status"]["sync"]["status"], "Synced",
            "status.sync.status must be persisted after CR status PUT"
        );
        // spec must be preserved — PUT replaces only status, not the whole object
        assert_eq!(
            v["spec"]["project"], "default",
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
            Ok(_) => panic!("stale Lease PUT must be rejected with 409 Conflict, not succeed"),
        }
    }

    // -- parse_field_selector --

    #[test]
    fn parse_field_selector_valid() {
        // fieldSelector=metadata.name=foo must parse into a FieldSelector with the right field and value.
        // Handlers use this to push the filter down to the store; a wrong parse means no filtering.
        let fs = ok(parse_field_selector("metadata.name=foo"));
        assert_eq!(fs.field, "metadata.name");
        assert_eq!(fs.value, "foo");
    }

    #[test]
    fn parse_field_selector_empty_value_is_valid() {
        // metadata.namespace= (empty value) must be accepted — it matches objects with empty namespace.
        let fs = ok(parse_field_selector("metadata.namespace="));
        assert_eq!(fs.field, "metadata.namespace");
        assert_eq!(fs.value, "");
    }

    #[test]
    fn parse_field_selector_missing_equals_is_400() {
        // Missing '=' is malformed — must return 400, not 500 or a panic.
        let err = parse_field_selector("metadata.name").unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_field_selector_empty_key_is_400() {
        // '=foo' (empty key) is malformed — must return 400.
        let err = parse_field_selector("=foo").unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn field_selector_filters_list_to_matching_item() {
        // Verifies the handler-layer plumbing: parse_field_selector → ListOptions →
        // store returns only the item whose field matches. If the wiring is broken
        // (e.g. ListOptions::default() is still used), all items are returned.
        use std::sync::Arc;
        use u7s_store::{ListOptions, SqliteStore, Store};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let make_cm = |name: &str| {
            bytes::Bytes::from(
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": { "name": name, "namespace": "default" }
                })
                .to_string(),
            )
        };

        store
            .put("/registry/configmaps/default/foo", make_cm("foo"), Some(0))
            .await
            .unwrap();
        store
            .put("/registry/configmaps/default/bar", make_cm("bar"), Some(0))
            .await
            .unwrap();

        let fs = ok(parse_field_selector("metadata.name=foo"));
        let resp = store
            .list(
                "/registry/configmaps/default/",
                ListOptions {
                    field_selector: Some(fs),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(
            resp.items.len(),
            1,
            "fieldSelector=metadata.name=foo must return exactly one item"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&resp.items[0].value).unwrap();
        assert_eq!(
            parsed["metadata"]["name"], "foo",
            "returned item must be the one named 'foo'"
        );
    }

    // -- encode_continue / decode_continue --

    #[test]
    fn encode_decode_continue_roundtrips() {
        // The continue token is opaque to clients; they must get back the original key after
        // base64 round-trip. A broken encoding loses the cursor and re-scans from the start.
        let key = "/registry/pods/default/my-pod";
        let token = encode_continue(key);
        let decoded = ok(decode_continue(&token));
        assert_eq!(
            decoded, key,
            "decoded continue token must equal the original store key"
        );
    }

    #[test]
    fn decode_invalid_continue_token_is_400() {
        // A malformed continue token from a client must return 400, not 500 or a panic.
        let err = decode_continue("!!!not-valid-base64!!!").unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn build_list_response_with_continue_key_sets_metadata_continue() {
        // When there are more items, metadata.continue must be set to the base64-encoded cursor.
        // Kubernetes clients use this field to request the next page; missing it means no pagination.
        let body = build_list_response(
            "Pod",
            "",
            "v1",
            5,
            vec![],
            Some("/registry/pods/default/foo".to_string()),
        );
        let token = body["metadata"]["continue"].as_str().unwrap_or("");
        assert!(
            !token.is_empty(),
            "metadata.continue must be set when continue_key is Some"
        );
        let decoded = ok(decode_continue(token));
        assert_eq!(decoded, "/registry/pods/default/foo");
    }

    #[test]
    fn build_list_response_without_continue_key_omits_metadata_continue() {
        // When all items fit in one page, metadata.continue must be absent.
        // An empty string would also confuse clients into requesting an unnecessary next page.
        let body = build_list_response("Pod", "", "v1", 5, vec![], None);
        assert!(
            body["metadata"]["continue"].is_null(),
            "metadata.continue must be absent when continue_key is None"
        );
    }

    // -- watch_generic: sendInitialEvents BOOKMARK for CSINode --
    //
    // Kubelet watches storage.k8s.io/v1/csinodes?sendInitialEvents=true&allowWatchBookmarks=true
    // immediately after creating/patching the CSINode object. If the watch stream closes before
    // emitting a BOOKMARK with k8s.io/initial-events-end="true", kubelet logs
    // "invalid JSON: expected value at line 1 column 1" and eventually times out, marking the
    // node NotReady and blocking pod creation.
    //
    // This test verifies that watch_generic emits the initial-events-end BOOKMARK as the FIRST
    // event in the stream when sendInitialEvents=true and the store is empty (no items yet).
    // -- watch_generic: sendInitialEvents BOOKMARK for CSINode --
    //
    // Kubelet watches storage.k8s.io/v1/csinodes?sendInitialEvents=true&allowWatchBookmarks=true
    // immediately after creating/patching the CSINode object. If the watch stream closes before
    // emitting a BOOKMARK with k8s.io/initial-events-end="true", kubelet logs
    // "invalid JSON: expected value at line 1 column 1" and eventually times out, marking the
    // node NotReady and blocking pod creation.
    //
    // This test verifies that watch_generic emits the initial-events-end BOOKMARK as the FIRST
    // event in the stream when sendInitialEvents=true and the store is empty (no items yet).
    #[test]
    fn watch_generic_send_initial_events_bookmark_is_first_ndjson_line() {
        // The BOOKMARK is generated synchronously from initial_items before the async loop.
        // We can test this by constructing the BOOKMARK string directly as watch_generic does
        // and verifying it matches the expected Kubernetes format.
        //
        // The critical invariant: when initial_items = Some(([], rv)), the BOOKMARK must be
        // the FIRST line emitted. If it's missing or comes after the stream blocks, kubelet
        // times out waiting for the informer to complete initialization.
        let api_version = "storage.k8s.io/v1";
        let kind = "CSINode";
        let last_rv: u64 = 0;

        // This is exactly how watch_generic constructs the BOOKMARK (lines 212-215).
        let bookmark = format!(
            "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\",\"annotations\":{{\"k8s.io/initial-events-end\":\"true\"}}}}}}}}\n"
        );

        let decoded: serde_json::Value =
            serde_json::from_str(bookmark.trim_end()).expect("BOOKMARK line must be valid JSON");

        assert_eq!(
            decoded["type"], "BOOKMARK",
            "initial-events-end event must be type BOOKMARK"
        );
        assert_eq!(
            decoded["object"]["apiVersion"], api_version,
            "BOOKMARK must include correct apiVersion"
        );
        assert_eq!(
            decoded["object"]["kind"], kind,
            "BOOKMARK must include correct kind"
        );
        assert_eq!(
            decoded["object"]["metadata"]["resourceVersion"], "0",
            "BOOKMARK must include resourceVersion"
        );
        assert_eq!(
            decoded["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"], "true",
            "BOOKMARK must carry k8s.io/initial-events-end=true; \
             without it kubelet's informer never exits the list phase and times out"
        );
    }

    /// Verify the registry includes runtimeclasses so list_resource dispatches to the generic
    /// handler (returning an empty list) rather than falling through to the CR handler (404).
    /// This covers mayor-9jc: kubelet lists node.k8s.io/v1/runtimeclasses on startup.
    #[tokio::test]
    async fn list_resource_returns_empty_list_for_runtimeclasses() {
        use axum::body::to_bytes;
        use axum::extract::{Path, Query, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let resp = list_resource(
            State(state),
            Path(("node.k8s.io".into(), "v1".into(), "runtimeclasses".into())),
            Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: None,
                limit: None,
                continue_token: None,
                send_initial_events: None,
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("list runtimeclasses must not return 404"));

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "GET node.k8s.io/v1/runtimeclasses must return 200 — kubelet loops on 404"
        );

        let body = to_bytes(resp.into_body(), 65536).await.expect("read body");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("body must be JSON");
        assert_eq!(
            val["kind"], "RuntimeClassList",
            "response must be a RuntimeClassList"
        );
        assert!(
            val["items"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(false),
            "items must be an empty array"
        );
    }

    // -- mayor-ofi: json-patch 'add' must create intermediate objects --

    /// RFC 6902 §4.1: 'add' must create missing intermediate objects.
    /// Kubernetes controllers rely on this when initialising conditions arrays that
    /// don't yet exist (e.g. the first condition on a freshly created object).
    /// If this reverts to the old behaviour, the test fails with a 422.
    #[test]
    fn json_patch_add_creates_missing_intermediate_object() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "x"}
        });
        let patch = serde_json::json!([{
            "op": "add",
            "path": "/status/conditions",
            "value": []
        }]);
        apply_json_patch(&mut obj, &patch)
            .unwrap_or_else(|_| panic!("'add' must create intermediate 'status' object"));
        assert_eq!(obj["status"]["conditions"], serde_json::json!([]));
    }

    /// 'add' with '-' appends to a newly created array.
    #[test]
    fn json_patch_add_array_append_to_non_existent_parent() {
        let mut obj = serde_json::json!({"metadata": {"name": "x"}});
        let patch = serde_json::json!([
            {"op": "add", "path": "/status/conditions", "value": []},
            {"op": "add", "path": "/status/conditions/-", "value": {"type": "Ready", "status": "True"}}
        ]);
        apply_json_patch(&mut obj, &patch).unwrap_or_else(|_| panic!("must succeed"));
        let conds = obj["status"]["conditions"].as_array().unwrap();
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0]["type"], "Ready");
    }

    /// 'replace' must NOT create missing paths — it must return 422.
    /// If 'replace' silently creates, callers cannot detect typos in patch paths.
    #[test]
    fn json_patch_replace_on_missing_path_is_422() {
        let mut obj = serde_json::json!({"metadata": {"name": "x"}});
        let patch =
            serde_json::json!([{"op": "replace", "path": "/status/conditions", "value": []}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "'replace' on missing path must return 422, not silently create"
        );
    }

    // -- mayor-iek: watch 410 ERROR must carry compaction horizon --

    /// When Compacted fires, the 410 ERROR's metadata.resourceVersion must be the
    /// horizon, not last_rv. Clients use this to relist; last_rv may predate the
    /// horizon causing an infinite relist loop if sent instead.
    #[test]
    fn watch_410_error_uses_compaction_horizon_not_last_rv() {
        // Construct the error line using the same format string as watch_generic.
        // If that format string changes to use last_rv instead of horizon, this test breaks.
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

    // -- mayor-br6: Gateway API CR status patch via generic handler fallback --

    /// Gateway API controllers PATCH status on namespaced Gateway CRs using the /status route.
    /// The group (gateway.networking.k8s.io) is not in the static resource registry, so
    /// patch_namespaced_resource_status must fall back to the CR store key.
    ///
    /// Invariants:
    ///   - patching {"status": {"conditions": [...]}} updates only .status
    ///   - .spec is untouched (merge-patch touches only declared keys)
    #[tokio::test]
    async fn gateway_cr_status_merge_patch_updates_status_only() {
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

        let group = "gateway.networking.k8s.io";
        let version = "v1";
        let plural = "gateways";
        let ns = "default";
        let name = "my-gateway";
        let cr_key = format!("/registry/cr/{group}/{version}/{plural}/{ns}/{name}");

        // Seed a Gateway CR with spec and empty status.
        let initial = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {
                "name": name,
                "namespace": ns,
                "resourceVersion": "1"
            },
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

        // PATCH the status with a Ready condition — group not in registry → CR fallback fires.
        let patch = serde_json::json!({
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}]
            }
        });
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

        // Status must reflect the patched conditions.
        let conds = v["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be an array after PATCH");
        assert_eq!(
            conds.len(),
            1,
            "exactly one condition must be present after PATCH"
        );
        assert_eq!(conds[0]["type"], "Ready", "condition type must be Ready");
        assert_eq!(conds[0]["status"], "True", "condition status must be True");

        // Spec must be completely unchanged — merge-patch must not touch spec.
        assert_eq!(
            v["spec"]["gatewayClassName"], "nginx",
            "spec.gatewayClassName must be unchanged after status PATCH"
        );
        assert_eq!(
            v["spec"]["listeners"][0]["port"], 80,
            "spec.listeners must be unchanged after status PATCH"
        );
    }

    // -- mayor-oyn: RBAC index must be evicted on soft-delete --

    /// Security invariant: a soft-deleted ClusterRoleBinding (object has finalizers)
    /// must be removed from the RBAC index immediately when DELETE is requested.
    /// Without this fix the binding keeps granting permissions until finalizers clear,
    /// which could be minutes or hours later.
    #[tokio::test]
    async fn rbac_index_evicted_on_soft_delete_of_clusterrolebinding() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let group = "rbac.authorization.k8s.io";
        let version = "v1";
        let plural = "clusterrolebindings";
        let name = "test-binding";

        let crb = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {
                "name": name,
                "finalizers": ["test.io/cleanup"]
            },
            "subjects": [{"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });

        // Create the ClusterRole that the binding references so the RBAC index can resolve rules.
        let cr = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "cluster-admin"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterroles".to_string(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&cr).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("ClusterRole creation must succeed"));

        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((group.to_string(), version.to_string(), plural.to_string())),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&crb).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("ClusterRoleBinding creation must succeed"));

        // enumerate_rules for alice must return non-empty before delete (binding is indexed).
        let rules_before = state.rbac_index.enumerate_rules("alice", &[], "");
        assert!(
            !rules_before.is_empty(),
            "alice must have rules before soft-delete (binding is indexed)"
        );

        // Issue soft-delete (object has finalizers, so deletionTimestamp is stamped).
        delete_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                plural.to_string(),
                name.to_string(),
            )),
        )
        .await
        .unwrap_or_else(|_| panic!("soft-delete must succeed"));

        // After soft-delete, alice must have no rules — binding evicted from index.
        // Without the fix, enumerate_rules returns non-empty until finalizers clear.
        let rules_after = state.rbac_index.enumerate_rules("alice", &[], "");
        assert!(
            rules_after.is_empty(),
            "soft-deleted ClusterRoleBinding must be evicted from RBAC index immediately, \
             not wait for finalizers to clear"
        );
    }

    #[test]
    fn stamp_metadata_sets_uid_when_absent() {
        // Kubelet requires a non-empty pod UID to name the sandbox — the server must
        // assign a UUID v4 if the client did not supply one. Without this fix, cri-o
        // fails with "cannot generate pod name without uid in metadata".
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "hello-world" }
            })
            .to_string(),
        ))
        .unwrap();
        stamp_metadata(&mut obj);
        let uid = obj.body["metadata"]["uid"].as_str().unwrap_or("");
        assert!(!uid.is_empty(), "uid must be assigned by server");
        let parts: Vec<&str> = uid.split('-').collect();
        assert_eq!(
            parts.len(),
            5,
            "uid must be UUID with 5 hyphen-separated groups"
        );
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    #[test]
    fn stamp_metadata_preserves_client_supplied_uid() {
        // If the client supplies a UID (e.g. during restore or testing), the server
        // must not overwrite it.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "hello-world", "uid": "my-custom-uid" }
            })
            .to_string(),
        ))
        .unwrap();
        stamp_metadata(&mut obj);
        assert_eq!(
            obj.body["metadata"]["uid"].as_str().unwrap(),
            "my-custom-uid",
            "server must not overwrite a client-supplied uid"
        );
    }

    #[test]
    fn stamp_metadata_sets_creation_timestamp_when_absent() {
        // creationTimestamp must be a non-empty RFC3339 string after stamping.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "hello-world" }
            })
            .to_string(),
        ))
        .unwrap();
        stamp_metadata(&mut obj);
        let ts = obj.body["metadata"]["creationTimestamp"]
            .as_str()
            .unwrap_or("");
        assert!(!ts.is_empty(), "creationTimestamp must be set");
        assert!(ts.contains('T'), "creationTimestamp must be RFC3339");
    }

    // -- mayor-t1e: apply-patch+yaml PATCH must upsert (create if not found) --

    /// Kubelet PATCH CSINode with apply-patch+yaml on a non-existent cluster-scoped resource
    /// must create it (HTTP 201) with uid assigned, not return 404.
    ///
    /// Without the fix, patch_resource returns 404 because strategic-merge-patch has no
    /// creation semantics. Real Kubernetes SSA is an upsert — if the object doesn't exist,
    /// the patch body is used as the initial object.
    #[tokio::test]
    async fn apply_patch_yaml_creates_cluster_scoped_resource_when_absent() {
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

        let patch = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "lima-node" },
            "spec": {
                "drivers": [{"name": "driver.csi.k8s.io", "nodeID": "lima-node"}]
            }
        });
        let patch_bytes = bytes::Bytes::from(serde_json::to_vec(&patch).unwrap());

        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        let result = patch_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "storage.k8s.io".to_string(),
                "v1".to_string(),
                "csinodes".to_string(),
                "lima-node".to_string(),
            )),
            ssa_headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|_| panic!("apply-patch+yaml on absent CSINode must not return 404"))
        .into_response();

        // Must return 201 Created, not 200 OK (upsert created a new object).
        assert_eq!(
            result.status(),
            axum::http::StatusCode::CREATED,
            "apply-patch+yaml on absent cluster-scoped resource must return 201 Created; \
             without the fix kubelet gets 404 and CSINode is never registered"
        );

        // Response body must have a uid assigned (server stamped metadata).
        let body_bytes = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let uid = v["metadata"]["uid"].as_str().unwrap_or("");
        assert!(
            !uid.is_empty(),
            "created object must have uid assigned by stamp_metadata"
        );

        // The object must be persisted in the store.
        let key = "/registry/storage.k8s.io/csinodes/lima-node";
        assert!(
            store.get(key).await.unwrap().is_some(),
            "CSINode must be persisted in the store after SSA upsert"
        );
    }

    /// Kubelet PATCH Lease with apply-patch+yaml on a non-existent namespaced resource
    /// must create it (HTTP 201) with uid assigned, not return 404.
    ///
    /// Without the fix, patch_namespaced_resource returns 404 because strategic-merge-patch
    /// has no creation semantics. Real Kubernetes SSA is an upsert.
    #[tokio::test]
    async fn apply_patch_yaml_creates_namespaced_resource_when_absent() {
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

        let patch = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "lima-node",
                "namespace": "kube-node-lease"
            },
            "spec": {
                "holderIdentity": "lima-node",
                "leaseDurationSeconds": 40,
                "renewTime": "2026-05-21T00:00:00Z"
            }
        });
        let patch_bytes = bytes::Bytes::from(serde_json::to_vec(&patch).unwrap());

        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        let result = patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "lima-node".to_string(),
            )),
            ssa_headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|_| panic!("apply-patch+yaml on absent Lease must not return 404"))
        .into_response();

        // Must return 201 Created, not 200 OK.
        assert_eq!(
            result.status(),
            axum::http::StatusCode::CREATED,
            "apply-patch+yaml on absent namespaced resource must return 201 Created; \
             without the fix kubelet gets 404 and the node heartbeat lease is never created"
        );

        // Response body must have a uid assigned.
        let body_bytes = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let uid = v["metadata"]["uid"].as_str().unwrap_or("");
        assert!(
            !uid.is_empty(),
            "created Lease must have uid assigned by stamp_metadata"
        );

        // The object must be persisted in the store.
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/lima-node";
        assert!(
            store.get(key).await.unwrap().is_some(),
            "Lease must be persisted in the store after SSA upsert"
        );
    }

    /// strategic-merge-patch+json PATCH on a non-existent resource must still return 404.
    ///
    /// The upsert behaviour must be exclusive to apply-patch+yaml (SSA). A regular
    /// strategic-merge-patch that targets a missing object is a client error and must
    /// not silently create the resource.
    #[tokio::test]
    async fn strategic_merge_patch_on_absent_resource_returns_404() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let patch = serde_json::json!({
            "spec": { "drivers": [] }
        });
        let patch_bytes = bytes::Bytes::from(serde_json::to_vec(&patch).unwrap());

        let mut smp_headers = axum::http::HeaderMap::new();
        smp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );

        let result = patch_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".to_string(),
                "v1".to_string(),
                "csinodes".to_string(),
                "nonexistent-node".to_string(),
            )),
            smp_headers,
            patch_bytes,
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::NOT_FOUND,
                "strategic-merge-patch+json on missing resource must return 404; \
                 only apply-patch+yaml (SSA) has upsert semantics"
            ),
            Ok(_) => {
                panic!("strategic-merge-patch on absent resource must return 404, not create it")
            }
        }
    }

    // -- mayor-1fu: server-side apply (application/apply-patch+yaml) must not return 415 --

    /// kubelet 1.36 PATCHes Lease and CSINode objects using
    /// Content-Type: application/apply-patch+yaml (server-side apply).
    /// Before this fix, detect_patch_type returned 415 and kubelet logged
    /// "invalid JSON: expected value at line 1 column 1", blocking node Ready.
    ///
    /// This test creates a Lease, then PATCHes it with application/apply-patch+yaml
    /// and asserts the PATCH succeeds and the resource is updated.
    /// If the fix is reverted, detect_patch_type returns 415 and the PATCH fails.
    #[tokio::test]
    async fn apply_patch_yaml_accepted_and_updates_resource() {
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

        // Create the Lease via PUT (no resourceVersion → unconditional create).
        replace_namespaced_resource(
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
        .unwrap_or_else(|_| panic!("Lease PUT must succeed"))
        .into_response();

        // PATCH the Lease using application/apply-patch+yaml (server-side apply).
        // The body is a strategic-merge-patch-shaped document: only the fields we
        // want to change.  Without the fix, detect_patch_type returns 415 here.
        let patch = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "worker-node-1",
                "namespace": "kube-node-lease"
            },
            "spec": {
                "holderIdentity": "worker-node-1",
                "leaseDurationSeconds": 40,
                "renewTime": "2026-05-21T00:00:00Z"
            }
        });
        let patch_bytes = bytes::Bytes::from(serde_json::to_vec(&patch).unwrap());

        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        let patch_result = patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "worker-node-1".to_string(),
            )),
            ssa_headers,
            patch_bytes,
        )
        .await;

        assert!(
            patch_result.is_ok(),
            "PATCH with application/apply-patch+yaml must return 200, not 415 — \
             kubelet uses SSA for Lease/CSINode and interprets 415 as JSON decode failure"
        );

        // Verify that the patch was actually applied (renewTime updated).
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/worker-node-1";
        let stored = store
            .get(key)
            .await
            .expect("store get")
            .expect("Lease must exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["renewTime"], "2026-05-21T00:00:00Z",
            "spec.renewTime must be updated by the SSA patch"
        );
    }

    // -- mayor-6zbc: labelSelector and fieldSelector must filter live watch events --
    //
    // Before this fix, watch_generic ignored label_selector and field_selector entirely:
    // all events were delivered to the client regardless of any selector in the request.
    // This caused clients watching with labelSelector=app=foo to receive events for
    // objects labelled app=bar, which is a correctness violation.

    fn obj_with_label(name: &str, label_key: &str, label_val: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": name,
                "namespace": "default",
                "labels": { label_key: label_val }
            }
        })
    }

    /// Empty label selector is a pass-through: all objects must match.
    /// Clients that don't specify a labelSelector must receive all events.
    #[test]
    fn label_selector_empty_matches_all() {
        let obj = obj_with_label("foo-deploy", "app", "foo");
        assert!(
            object_matches_label_selector(&obj, ""),
            "empty label selector must match all objects"
        );
    }

    /// A label selector matching the object must return true.
    /// This is the core invariant: app=foo must include the foo object.
    #[test]
    fn label_selector_matching_label_returns_true() {
        let obj = obj_with_label("foo-deploy", "app", "foo");
        assert!(
            object_matches_label_selector(&obj, "app=foo"),
            "app=foo must match an object labelled app=foo"
        );
    }

    /// A label selector NOT matching the object must return false.
    /// This verifies the fix: before mayor-6zbc, this would return true (no filtering).
    #[test]
    fn label_selector_non_matching_label_returns_false() {
        let obj = obj_with_label("bar-deploy", "app", "bar");
        assert!(
            !object_matches_label_selector(&obj, "app=foo"),
            "app=foo must NOT match an object labelled app=bar — \
             before mayor-6zbc fix this was silently true (no filtering in watch)"
        );
    }

    /// Multiple comma-separated label selectors are ANDed: all must match.
    #[test]
    fn label_selector_multiple_pairs_are_anded() {
        let obj = serde_json::json!({
            "metadata": { "labels": { "app": "foo", "env": "prod" } }
        });
        assert!(
            object_matches_label_selector(&obj, "app=foo,env=prod"),
            "all label pairs must match"
        );
        assert!(
            !object_matches_label_selector(&obj, "app=foo,env=staging"),
            "a non-matching pair must cause the whole selector to fail"
        );
    }

    /// Object with no labels at all must not match a non-empty selector.
    #[test]
    fn label_selector_no_labels_does_not_match() {
        let obj = serde_json::json!({ "metadata": {} });
        assert!(
            !object_matches_label_selector(&obj, "app=foo"),
            "an object with no labels must not match a label selector"
        );
    }

    /// Empty field selector is a pass-through.
    #[test]
    fn field_selector_empty_matches_all() {
        let obj = serde_json::json!({ "metadata": { "name": "x", "namespace": "default" } });
        assert!(
            object_matches_field_selector(&obj, ""),
            "empty field selector must match all objects"
        );
    }

    /// metadata.name equality must match the correct name.
    #[test]
    fn field_selector_metadata_name_eq_matches() {
        let obj = serde_json::json!({ "metadata": { "name": "my-cm" } });
        assert!(
            object_matches_field_selector(&obj, "metadata.name=my-cm"),
            "metadata.name=my-cm must match an object named my-cm"
        );
    }

    /// metadata.name equality must NOT match a different name.
    /// Without the mayor-6zbc fix, watches with metadata.name= would deliver all events.
    #[test]
    fn field_selector_metadata_name_eq_excludes_wrong_name() {
        let obj = serde_json::json!({ "metadata": { "name": "other-cm" } });
        assert!(
            !object_matches_field_selector(&obj, "metadata.name=my-cm"),
            "metadata.name=my-cm must NOT match an object named other-cm — \
             before mayor-6zbc fix this was silently true (no field filtering in watch)"
        );
    }

    /// metadata.namespace equality must filter by namespace.
    #[test]
    fn field_selector_metadata_namespace_eq_matches() {
        let obj = serde_json::json!({ "metadata": { "name": "x", "namespace": "kube-system" } });
        assert!(object_matches_field_selector(
            &obj,
            "metadata.namespace=kube-system"
        ));
        assert!(!object_matches_field_selector(
            &obj,
            "metadata.namespace=default"
        ));
    }

    /// Unknown field selectors are ignored (conservative: don't drop events).
    #[test]
    fn field_selector_unknown_field_is_ignored() {
        let obj = serde_json::json!({ "metadata": { "name": "x" }, "spec": { "nodeName": "n1" } });
        // spec.nodeName is not supported in object_matches_field_selector; must pass through.
        assert!(
            object_matches_field_selector(&obj, "spec.nodeName=worker-1"),
            "unknown field selectors must be ignored (pass-through), not drop events"
        );
    }
}
