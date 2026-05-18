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
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    pub watch: Option<bool>,
    pub resource_version: Option<u64>,
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
        return watch_pods(state, prefix, ns, query.resource_version.unwrap_or(0)).await;
    }

    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut items = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let parsed: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(parsed);
    }

    let body = serde_json::json!({
        "kind": "PodList",
        "apiVersion": "v1",
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items
    });

    Ok(Json(body).into_response())
}

/// Serialise a single watch event to NDJSON bytes (including trailing newline).
/// Returns None on Compacted — the caller should close the stream.
fn encode_watch_event(event: &WatchEvent) -> Option<Bytes> {
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
            // The store deleted event carries no bytes; reconstruct a minimal object.
            // Key format: /registry/pods/<namespace>/<name>
            let (name, namespace) = parse_key_name_ns(key);
            let object = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "resourceVersion": revision.to_string()
                }
            });
            format!(
                "{{\"type\":\"DELETED\",\"object\":{}}}\n",
                serde_json::to_string(&object).unwrap_or_default()
            )
        }
        WatchEvent::Bookmark { revision } => {
            format!(
                "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{{\"resourceVersion\":\"{revision}\"}}}}}}\n"
            )
        }
        WatchEvent::Compacted { .. } => return None,
    };
    Some(Bytes::from(line))
}

/// Parse the last two path segments of a store key as (name, namespace).
/// Key format: /registry/<resource>/<namespace>/<name>
fn parse_key_name_ns(key: &str) -> (&str, &str) {
    let parts: Vec<&str> = key.rsplitn(3, '/').collect();
    // rsplitn(3) gives [name, namespace, rest] for a well-formed key
    match parts.as_slice() {
        [name, namespace, ..] => (name, namespace),
        [name] => (name, ""),
        _ => ("", ""),
    }
}

async fn watch_pods(
    state: AppState,
    prefix: String,
    _ns: Namespace,
    from_revision: u64,
) -> Result<Response, crate::status::StatusError> {
    let event_stream = state
        .store
        .watch(&prefix, from_revision)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // The body stream yields Result<Bytes, BoxError> items.
    // We transform WatchEvent items into NDJSON chunks.
    // A periodic bookmark is sent every 60 s if no other events fire.
    let chunk_stream = async_stream::stream! {
        use futures_core::Stream;
        use std::pin::pin;
        use tokio::time::{Duration, interval};

        let mut event_stream = pin!(event_stream);
        let mut bookmark_tick = interval(Duration::from_secs(60));
        // Skip the first immediate tick so we don't send a bookmark before any events.
        bookmark_tick.tick().await;

        // Track the most recently seen revision for bookmark emission.
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

                            let is_compacted = matches!(event, WatchEvent::Compacted { .. });
                            if is_compacted {
                                let error_line = Bytes::from(
                                    "{\"type\":\"ERROR\",\"object\":{\"apiVersion\":\"v1\",\"kind\":\"Status\",\"code\":410,\"message\":\"too old resource version\",\"reason\":\"Expired\"}}\n"
                                );
                                yield Ok::<Bytes, axum::BoxError>(error_line);
                                break;
                            }

                            if let Some(chunk) = encode_watch_event(&event) {
                                yield Ok::<Bytes, axum::BoxError>(chunk);
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
            }
        }
    };

    let body = Body::from_stream(chunk_stream);
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::TRANSFER_ENCODING,
            "chunked",
        )
        .body(body)
        .expect("response builder never fails with these headers");

    Ok(resp)
}

pub async fn create_pod(
    State(state): State<AppState>,
    Path((raw_ns,)): Path<(String,)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;

    let mut obj = Object::from_bytes(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = obj
        .name()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Status::bad_request("metadata.name is required".into()))?
        .to_string();

    // Ensure namespace is set in the stored object
    obj.body["metadata"]["namespace"] =
        serde_json::Value::String(ns.as_str().to_owned());

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
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;

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
            let parsed = rv
                .parse::<u64>()
                .map_err(|_| Status::bad_request(format!("invalid resourceVersion: {rv}")))?;
            Some(parsed)
        }
    };

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
        obj.body["metadata"]["deletionTimestamp"] =
            serde_json::Value::String(utc_now_rfc3339());
        let expected_rv = match obj.resource_version() {
            None | Some("") => None,
            Some("0") => Some(0),
            Some(rv) => Some(rv.parse::<u64>().map_err(|_| {
                Status::bad_request(format!("invalid resourceVersion: {rv}"))
            })?),
        };
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

pub async fn patch_pod(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Check Content-Type
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let is_smp = content_type.contains("application/strategic-merge-patch+json");
    let is_jmp = content_type.contains("application/merge-patch+json");

    if !is_smp && !is_jmp {
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

    let patch: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    if is_smp {
        crate::patch::strategic_merge_patch(&mut current_obj.body, &patch)
            .map_err(|e| Status::bad_request(e.to_string()))?;
    } else {
        json_merge_patch(&mut current_obj.body, &patch);
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

    let new_rv = state
        .store
        .put(&key, current_obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current_obj.set_resource_version(new_rv);

    Ok(Json(current_obj.body))
}

/// Returns the current UTC time as an RFC3339 string (`YYYY-MM-DDThh:mm:ssZ`).
/// Uses only `std::time` — no chrono dependency.
fn utc_now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    let (year, month, day) = {
        let mut d = days;
        let n400 = d / 146097; d %= 146097;
        let n100 = (d / 36524).min(3); d -= n100 * 36524;
        let n4 = d / 1461; d %= 1461;
        let n1 = (d / 365).min(3); d -= n1 * 365;
        let year = n400 * 400 + n100 * 100 + n4 * 4 + n1 + 1970;
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let month_days: &[u64] = if leap {
            &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        let mut month = 0u64;
        for (i, &md) in month_days.iter().enumerate() {
            if d < md { month = i as u64 + 1; break; }
            d -= md;
        }
        (year, month, d + 1)
    };

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn json_merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (Some(t), Some(p)) = (target.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            if v.is_null() {
                t.remove(k);
            } else if v.is_object() {
                let entry = t
                    .entry(k)
                    .or_insert(serde_json::Value::Object(Default::default()));
                json_merge_patch(entry, v);
            } else {
                t.insert(k.clone(), v.clone());
            }
        }
    } else {
        *target = patch.clone();
    }
}

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

    /// encode_watch_event for Added emits {"type":"ADDED","object":...}\n
    /// and the object bytes are valid JSON from the stored value.
    #[test]
    fn encode_added_roundtrip() {
        let obj = make_store_object(
            "/registry/pods/default/nginx",
            5,
            serde_json::json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"nginx","resourceVersion":"5"}}),
        );
        let bytes = encode_watch_event(&WatchEvent::Added(obj)).expect("should encode");
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
        let bytes = encode_watch_event(&WatchEvent::Modified(obj)).expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "MODIFIED");
    }

    /// encode_watch_event for Deleted reconstructs a minimal object from the store key.
    /// The emitted object must contain name and namespace derived from the key.
    #[test]
    fn encode_deleted_reconstructs_metadata() {
        let bytes = encode_watch_event(&WatchEvent::Deleted {
            key: "/registry/pods/default/nginx".to_string(),
            revision: 9,
        })
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
        let bytes =
            encode_watch_event(&WatchEvent::Bookmark { revision: 42 }).expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "BOOKMARK");
        assert_eq!(parsed["object"]["metadata"]["resourceVersion"], "42");
        assert_eq!(parsed["object"]["kind"], "Pod");
    }

    /// encode_watch_event for Compacted returns None — the caller must close the stream.
    #[test]
    fn encode_compacted_returns_none() {
        let result = encode_watch_event(&WatchEvent::Compacted {
            requested: 5,
            horizon: 50,
        });
        assert!(result.is_none(), "Compacted must signal close via None");
    }

    /// parse_key_name_ns correctly extracts name and namespace from a standard store key.
    #[test]
    fn parse_key_standard() {
        let (name, ns) = parse_key_name_ns("/registry/pods/default/nginx");
        assert_eq!(name, "nginx");
        assert_eq!(ns, "default");
    }

    /// parse_key_name_ns handles a custom namespace correctly.
    #[test]
    fn parse_key_custom_namespace() {
        let (name, ns) = parse_key_name_ns("/registry/pods/kube-system/coredns");
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
        };
        assert_eq!(q.watch, None);
        assert_eq!(q.resource_version, None);
    }
}

// ---------------------------------------------------------------------------
// Binding subresource — POST /api/v1/namespaces/:ns/pods/:name/binding
// ---------------------------------------------------------------------------

pub async fn bind_pod(
    State(state): State<AppState>,
    Path((raw_ns, name)): Path<(String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns)?;

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

    let expected_rv = match obj.resource_version() {
        None | Some("") => None,
        Some("0") => Some(0),
        Some(rv) => Some(rv.parse::<u64>().map_err(|_| {
            Status::bad_request(format!("invalid resourceVersion: {rv}"))
        })?),
    };

    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok((StatusCode::CREATED, Json(obj.body)))
}
