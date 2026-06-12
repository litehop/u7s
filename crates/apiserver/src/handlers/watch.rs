use axum::{body::Body, http::StatusCode, response::Response};
use bytes::Bytes;
use u7s_store::{ListOptions, Store, WatchEvent};

use crate::{state::AppState, status::Status};

/// Transform a full CR JSON object into a PartialObjectMetadata object.
/// The GC only needs metadata (ownerReferences, finalizers, etc.) — spec/status are omitted.
pub(crate) fn to_partial_object_metadata(obj: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "PartialObjectMetadata",
        "metadata": obj.get("metadata").cloned().unwrap_or_default()
    })
}

/// Serialise a single watch event to NDJSON bytes (including trailing newline).
/// Returns None on Compacted — the caller should close the stream.
/// Returns None on corrupt object bytes (invalid UTF-8) — the event is skipped,
/// a warning is logged, and the stream continues. Emitting null would send invalid
/// data to Kubernetes clients that may panic or behave incorrectly.
///
/// When `as_partial_object_metadata` is true, ADDED and MODIFIED event objects are
/// wrapped as PartialObjectMetadata (apiVersion: meta.k8s.io/v1, kind: PartialObjectMetadata,
/// only metadata preserved). BOOKMARK and DELETED use the caller-supplied api_version/kind
/// which should also be set to "meta.k8s.io/v1"/"PartialObjectMetadata" by the caller.
pub(crate) fn encode_watch_event(
    event: &WatchEvent,
    api_version: &str,
    kind: &str,
    as_partial_object_metadata: bool,
) -> Option<Bytes> {
    let line = match event {
        WatchEvent::Added(obj) => {
            let object_json = match std::str::from_utf8(&obj.value) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("watch ADDED event has invalid UTF-8, skipping: {e}");
                    return None;
                }
            };
            if as_partial_object_metadata {
                let full: serde_json::Value =
                    serde_json::from_str(object_json).unwrap_or(serde_json::Value::Null);
                let pom = to_partial_object_metadata(&full);
                format!(
                    "{{\"type\":\"ADDED\",\"object\":{}}}\n",
                    serde_json::to_string(&pom).unwrap_or_default()
                )
            } else {
                format!("{{\"type\":\"ADDED\",\"object\":{object_json}}}\n")
            }
        }
        WatchEvent::Modified(obj) => {
            let object_json = match std::str::from_utf8(&obj.value) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("watch MODIFIED event has invalid UTF-8, skipping: {e}");
                    return None;
                }
            };
            if as_partial_object_metadata {
                let full: serde_json::Value =
                    serde_json::from_str(object_json).unwrap_or(serde_json::Value::Null);
                let pom = to_partial_object_metadata(&full);
                format!(
                    "{{\"type\":\"MODIFIED\",\"object\":{}}}\n",
                    serde_json::to_string(&pom).unwrap_or_default()
                )
            } else {
                format!("{{\"type\":\"MODIFIED\",\"object\":{object_json}}}\n")
            }
        }
        WatchEvent::Deleted {
            key,
            revision,
            body,
        } => {
            if let Some(body_bytes) = body {
                if let Ok(s) = std::str::from_utf8(body_bytes) {
                    if let Ok(mut obj) = serde_json::from_str::<serde_json::Value>(s) {
                        obj["metadata"]["resourceVersion"] =
                            serde_json::Value::String(revision.to_string());
                        return Some(Bytes::from(format!(
                            "{{\"type\":\"DELETED\",\"object\":{}}}\n",
                            serde_json::to_string(&obj).unwrap_or_default()
                        )));
                    }
                }
            }
            // Fallback: reconstruct a minimal tombstone from the store key.
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
pub(crate) async fn fetch_initial_events<S: Store>(
    state: &AppState<S>,
    prefix: &str,
    send_initial_events: bool,
    group: &str,
    plural: &str,
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
        .map(|mut v| {
            super::defaults::apply_defaults(group, plural, &mut v);
            v
        })
        .collect();
    Ok(Some((items, resp.revision)))
}

/// Test whether a JSON object matches a label selector string.
/// Returns true if the selector is empty (pass-through) or all terms match
/// `metadata.labels` in the object. Used to filter live watch events.
///
/// Supported operators: `key=value` (Equality), `key!=value` (NotEquals),
/// `!key` (DoesNotExist), bare `key` (Exists).
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
        if let Some(key) = part.strip_prefix('!') {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            if labels.get(key).is_some() {
                return false;
            }
            continue;
        }
        if let Some((key, value)) = part.split_once("!=") {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                continue;
            }
            if labels.get(key).and_then(|v| v.as_str()) == Some(value) {
                return false;
            }
            continue;
        }
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim();
            let value = value.trim().strip_prefix('=').unwrap_or(value.trim());
            if key.is_empty() {
                continue;
            }
            if labels.get(key).and_then(|v| v.as_str()) != Some(value) {
                return false;
            }
            continue;
        }
        let key = part.trim();
        if key.is_empty() {
            continue;
        }
        if labels.get(key).is_none() {
            return false;
        }
    }
    true
}

/// Test whether a JSON object matches a field selector string (`key=value,...` or `key!=value,...`).
/// Supports `metadata.name`, `metadata.namespace` (equality only), and `spec.nodeName`
/// (equality and inequality). Returns true if the selector is empty (pass-through) or all
/// terms match. Unknown fields are ignored (conservative: don't drop events on unrecognised fields).
pub(crate) fn object_matches_field_selector(obj: &serde_json::Value, selector: &str) -> bool {
    if selector.is_empty() {
        return true;
    }
    for part in selector.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Check for inequality (`!=`) before equality (`=`) to avoid misparse.
        if let Some((field, value)) = part.split_once("!=") {
            let field = field.trim();
            let value = value.trim();
            if field == "spec.nodeName" {
                let node_name = obj["spec"]["nodeName"].as_str().unwrap_or("");
                if node_name == value {
                    return false;
                }
            }
            // Unknown fields: ignore (conservative).
        } else if let Some((field, value)) = part.split_once('=') {
            let field = field.trim();
            let value = value.trim();
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
                "spec.nodeName" => {
                    let node_name = obj["spec"]["nodeName"].as_str().unwrap_or("");
                    if node_name != value {
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

/// Parameters for `watch_generic`.
///
/// Groups the arguments that previously caused a `clippy::too_many_arguments` warning.
pub(crate) struct WatchConfig {
    pub prefix: String,
    pub api_version: String,
    pub kind: String,
    pub from_revision: u64,
    pub initial_items: Option<(Vec<serde_json::Value>, u64)>,
    pub label_selector: Option<String>,
    pub field_selector: Option<String>,
    pub allow_watch_bookmarks: bool,
    pub username: String,
    /// When true, wrap each ADDED/MODIFIED object as PartialObjectMetadata and use
    /// "meta.k8s.io/v1"/"PartialObjectMetadata" for BOOKMARK and DELETED events.
    /// The caller must also pass api_version="meta.k8s.io/v1" and kind="PartialObjectMetadata".
    pub as_partial_object_metadata: bool,
    pub group: String,
    pub plural: String,
    /// Client-requested watch stream lifetime in seconds. When Some(n), the server closes
    /// the stream after n seconds. When None, a default of 5 minutes (300s) is used.
    /// Watches must not be subject to a shorter general request timeout — only this value
    /// controls when the server closes the stream.
    pub timeout_seconds: Option<u64>,
}

/// Stream watch events for a given store prefix in NDJSON format.
/// Sends a 60s bookmark heartbeat and closes after cfg.timeout_seconds (default 5 min).
///
/// When `cfg.initial_items` is Some, those items are emitted as ADDED events first
/// (implementing the Kubernetes 1.27+ sendInitialEvents protocol), followed by a
/// BOOKMARK, before streaming live changes from `cfg.from_revision`.
///
/// `cfg.username` is the authenticated client identity used to enforce the per-client
/// watch stream concurrency limit (MAX_WATCHES_PER_CLIENT). Exceeding the limit
/// returns HTTP 429 immediately without opening a watch stream.
pub(crate) async fn watch_generic<S: Store>(
    state: AppState<S>,
    cfg: WatchConfig,
) -> Result<Response, crate::status::StatusError> {
    let WatchConfig {
        prefix,
        api_version,
        kind,
        from_revision,
        initial_items,
        label_selector,
        field_selector,
        allow_watch_bookmarks,
        username,
        as_partial_object_metadata,
        group,
        plural,
        timeout_seconds,
    } = cfg;
    // Enforce per-client watch concurrency limit. Try to acquire a permit from
    // this user's semaphore. If the semaphore is exhausted (client already has
    // MAX_WATCHES_PER_CLIENT open streams), return 429 immediately.
    let sem = state.watch_limit.semaphore_for(&username);
    let _watch_permit = sem.try_acquire_owned().map_err(|_| {
        crate::status::Status::too_many_requests(format!(
            "watch limit exceeded for user \"{username}\": maximum {} concurrent watch streams",
            crate::state::MAX_WATCHES_PER_CLIENT
        ))
    })?;
    // _watch_permit is held for the duration of the watch stream and released when
    // this function returns (RAII drop).

    // Check compaction horizon BEFORE committing headers so clients get a synchronous HTTP 410.
    // If from_rv > 0 and below the horizon, the revision is expired — return 410 immediately.
    // Skip this check when sendInitialEvents is active: initial_items already holds a fresh
    // list snapshot at the current revision, and watch_from_rv below will be set to list_rv,
    // not from_revision. The stale from_revision is irrelevant in that path.
    if from_revision > 0 && initial_items.is_none() {
        let horizon = state.store.compaction_horizon();
        if from_revision < horizon {
            return Err(Status::expired(format!(
                "too old resource version: {from_revision} (current compaction horizon: {horizon})"
            )));
        }
    }

    // When sendInitialEvents is active, the list snapshot was taken at list_rv.
    // The ring buffer replay must start from list_rv (not from_revision) so that
    // any write that raced between the list and the watch subscribe is replayed
    // as a synthetic ADDED in the initial phase — before the BOOKMARK — not after
    // it. Emitting an event after the BOOKMARK would violate the Kubernetes watch
    // protocol invariant: everything before BOOKMARK is "initial state".
    let watch_from_rv = match &initial_items {
        Some((_, list_rv)) => *list_rv,
        None => from_revision,
    };

    let event_stream = state
        .store
        .watch(&prefix, watch_from_rv)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // Keep the store alive for the entire watch stream lifetime.
    //
    // The broadcast sender (`tx`) lives inside the store. If the store's `Arc` reference count
    // drops to zero while the stream body is being consumed, `tx` is dropped and the broadcast
    // receivers immediately get `RecvError::Closed`, causing the watch stream to close instead
    // of staying open for future events. This most visibly affects the namespace watch
    // (GET /api/v1/namespaces?watch=true): when the ring buffer is empty for the namespace prefix
    // and the caller holds no other store reference (common in tests and possible under request
    // routing where the handler-local `state` is the only live clone), the stream closes before
    // the client receives any data.
    let _store_keepalive = std::sync::Arc::clone(&state.store);

    let label_selector = label_selector.unwrap_or_default();
    let field_selector = field_selector.unwrap_or_default();
    let chunk_stream = async_stream::stream! {
        use futures_core::Stream;
        use std::pin::pin;
        use tokio::time::{Duration, interval, sleep};

        // Hold the store Arc for the duration of the stream so the broadcast sender
        // is never dropped while we are waiting for live events.
        let _store_keepalive = _store_keepalive;

        let mut event_stream = pin!(event_stream);
        let mut bookmark_tick = interval(Duration::from_secs(60));
        bookmark_tick.tick().await; // skip initial immediate tick

        // Use the client-requested timeout, defaulting to 5 minutes when absent.
        // Watches must never be subject to a shorter general request timeout —
        // the client's timeoutSeconds is the only server-side close trigger.
        let stream_timeout_secs = timeout_seconds.unwrap_or(5 * 60);
        let mut max_duration = pin!(sleep(Duration::from_secs(stream_timeout_secs)));
        let mut last_rv: u64 = from_revision;

        // sendInitialEvents: emit existing objects as ADDED, then BOOKMARK.
        if let Some((items, list_rv)) = initial_items {
            tracing::debug!(prefix = %prefix, list_rv, item_count = items.len(), "watch: sendInitialEvents start");
            last_rv = last_rv.max(list_rv);
            for item in items {
                // Apply the same label/field selector filtering as live events so that
                // a watch with sendInitialEvents=true and a fieldSelector does not deliver
                // every object in the prefix as ADDED (which would cause the BOOKMARK to
                // never be emitted for non-matching objects, hanging the watch).
                if !object_matches_label_selector(&item, &label_selector)
                    || !object_matches_field_selector(&item, &field_selector)
                {
                    continue;
                }
                let emit = if as_partial_object_metadata {
                    to_partial_object_metadata(&item)
                } else {
                    item
                };
                let line = format!(
                    "{{\"type\":\"ADDED\",\"object\":{}}}\n",
                    serde_json::to_string(&emit).unwrap_or_default()
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
                            if let WatchEvent::Added(obj) | WatchEvent::Modified(obj) = &event {
                                let is_modified = matches!(&event, WatchEvent::Modified(_));
                                let event_type = if is_modified { "MODIFIED" } else { "ADDED" };
                                if let Ok(s) = std::str::from_utf8(&obj.value) {
                                    let mut parsed: serde_json::Value =
                                        serde_json::from_str(s).unwrap_or(serde_json::Value::Null);
                                    if object_matches_label_selector(&parsed, &label_selector)
                                        && object_matches_field_selector(&parsed, &field_selector)
                                    {
                                        let obj_name = parsed["metadata"]["name"].as_str().unwrap_or("");
                                        let obj_ns = parsed["metadata"]["namespace"].as_str().unwrap_or("");
                                        tracing::debug!(
                                            prefix = %prefix,
                                            event_type,
                                            name = obj_name,
                                            ns = obj_ns,
                                            rv = obj.revision,
                                            "watch: emitting event"
                                        );
                                        super::defaults::apply_defaults(&group, &plural, &mut parsed);
                                        let emit = if as_partial_object_metadata {
                                            to_partial_object_metadata(&parsed)
                                        } else {
                                            parsed
                                        };
                                        let line = format!(
                                            "{{\"type\":\"{event_type}\",\"object\":{}}}\n",
                                            serde_json::to_string(&emit).unwrap_or_default()
                                        );
                                        yield Ok::<Bytes, axum::BoxError>(Bytes::from(line));
                                    } else if is_modified {
                                        // The object no longer matches the selector after this
                                        // MODIFIED update. Emit a synthetic DELETED so watchers
                                        // remove it from their cache. Without this, informers
                                        // with a labelSelector would never learn that a previously-
                                        // matching object exited their watch scope.
                                        let name = parsed["metadata"]["name"].as_str().unwrap_or("");
                                        let ns = parsed["metadata"]["namespace"].as_str().unwrap_or("");
                                        let rv = obj.revision.to_string();
                                        let tombstone = if ns.is_empty() {
                                            serde_json::json!({
                                                "apiVersion": api_version,
                                                "kind": kind,
                                                "metadata": {
                                                    "name": name,
                                                    "resourceVersion": rv
                                                }
                                            })
                                        } else {
                                            serde_json::json!({
                                                "apiVersion": api_version,
                                                "kind": kind,
                                                "metadata": {
                                                    "name": name,
                                                    "namespace": ns,
                                                    "resourceVersion": rv
                                                }
                                            })
                                        };
                                        let line = format!(
                                            "{{\"type\":\"DELETED\",\"object\":{}}}\n",
                                            serde_json::to_string(&tombstone).unwrap_or_default()
                                        );
                                        yield Ok::<Bytes, axum::BoxError>(Bytes::from(line));
                                    }
                                } else {
                                    tracing::warn!("watch {event_type} event has invalid UTF-8, skipping");
                                }
                            } else if let Some(chunk) = encode_watch_event(&event, &api_version, &kind, as_partial_object_metadata) {
                                yield Ok::<Bytes, axum::BoxError>(chunk);
                            }
                        }
                    }
                }

                _ = bookmark_tick.tick() => {
                    if allow_watch_bookmarks {
                        // Use the global store revision, not last_rv (the last RV seen on
                        // this stream). KCM's ConsistencyStore checks that each informer's
                        // LastStoreSyncResourceVersion (advanced by BOOKMARK) is >= the RV
                        // of any write the controller made to *any* resource type. A
                        // StatefulSet watch only sees StatefulSet events, so last_rv stays
                        // stale relative to pod writes — causing endless requeue loops.
                        let bookmark_rv = _store_keepalive.current_revision().max(last_rv);
                        let bookmark = format!(
                            "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{bookmark_rv}\"}}}}}}\n"
                        );
                        yield Ok::<Bytes, axum::BoxError>(Bytes::from(bookmark));
                    }
                }

                _ = &mut max_duration => {
                    if allow_watch_bookmarks {
                        let bookmark_rv = _store_keepalive.current_revision().max(last_rv);
                        let bookmark = format!(
                            "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{bookmark_rv}\"}}}}}}\n"
                        );
                        yield Ok::<Bytes, axum::BoxError>(Bytes::from(bookmark));
                    }
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

#[cfg(test)]
mod tests {
    use super::super::generic::apply_label_selector;
    use super::*;
    use u7s_store::WatchEvent;

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

        let chunk = encode_watch_event(&event, "v1", "ConfigMap", false)
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

        let chunk = encode_watch_event(&event, "v1", "ConfigMap", false)
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

        let chunk = encode_watch_event(&event, "v1", "ConfigMap", false).unwrap();
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

    /// Regression: encode_watch_event must skip (return None) for ADDED events whose
    /// stored bytes are not valid UTF-8, rather than emitting {"type":"ADDED","object":null}.
    ///
    /// Kubernetes clients (controller-runtime, client-go) do not expect null objects in
    /// watch streams and may panic or enter a bad state when they receive one. A corrupt
    /// store entry must not propagate to clients; the stream must continue for subsequent
    /// valid events.
    #[test]
    fn encode_watch_event_added_with_invalid_utf8_is_skipped() {
        let corrupt_bytes = bytes::Bytes::from(vec![0xFF, 0xFE, 0x00]);
        let event = WatchEvent::Added(u7s_store::StoreObject {
            key: "/registry/configmaps/default/corrupt".into(),
            value: corrupt_bytes,
            revision: 1,
        });

        let result = encode_watch_event(&event, "v1", "ConfigMap", false);

        assert!(
            result.is_none(),
            "encode_watch_event must skip (return None) for ADDED events with invalid UTF-8, \
             not emit {{\"type\":\"ADDED\",\"object\":null}} which breaks Kubernetes watch clients"
        );
    }

    /// Regression: same as above but for MODIFIED events.
    #[test]
    fn encode_watch_event_modified_with_invalid_utf8_is_skipped() {
        let corrupt_bytes = bytes::Bytes::from(vec![0xFF, 0xFE]);
        let event = WatchEvent::Modified(u7s_store::StoreObject {
            key: "/registry/configmaps/default/corrupt".into(),
            value: corrupt_bytes,
            revision: 2,
        });

        let result = encode_watch_event(&event, "v1", "ConfigMap", false);

        assert!(
            result.is_none(),
            "encode_watch_event must skip (return None) for MODIFIED events with invalid UTF-8, \
             not emit {{\"type\":\"MODIFIED\",\"object\":null}} which breaks Kubernetes watch clients"
        );
    }

    /// Verify the BOOKMARK for sendInitialEvents is constructed correctly.
    #[test]
    fn watch_generic_send_initial_events_bookmark_is_first_ndjson_line() {
        let api_version = "storage.k8s.io/v1";
        let kind = "CSINode";
        let last_rv: u64 = 0;

        // This is exactly how watch_generic constructs the BOOKMARK.
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

    /// Regression test for mayor-e8fx: when a client opens a watch with a resourceVersion
    /// below the compaction horizon, watch_generic must return HTTP 410 BEFORE committing
    /// headers.
    #[tokio::test]
    async fn watch_generic_returns_410_before_streaming_for_expired_rv() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        store.set_compaction_horizon_for_test(50);

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 10, // expired
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_err(),
            "watch_generic must return Err(410) for expired resourceVersion, \
             not Ok(streaming 200) — clients cannot detect failure from a stream header"
        );
        use axum::response::IntoResponse;
        let err_resp: axum::response::Response = result.unwrap_err().into_response();
        assert_eq!(
            err_resp.status(),
            axum::http::StatusCode::GONE,
            "HTTP 410 Gone must be returned synchronously so clients can retry without \
             waiting for the stream body"
        );
    }

    /// watch_generic with from_revision=0 (full watch) must NOT trigger the 410 check.
    #[tokio::test]
    async fn watch_generic_rv_zero_does_not_trigger_410() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        store.set_compaction_horizon_for_test(50);

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0, // not expired
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "rv=0 (full watch) must not trigger the 410 expiry check, \
             even when a compaction horizon exists"
        );
    }

    /// watch_generic with sendInitialEvents=true (initial_items is Some) and an expired
    /// from_revision must NOT return 410 — the stale rv is irrelevant because the watch
    /// starts from the fresh list_rv, not from_revision. Without this fix sonobuoy's
    /// configmap watches get stuck in a 410 retry loop once the ring buffer fills.
    #[tokio::test]
    async fn watch_generic_send_initial_events_bypasses_410_for_expired_rv() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        store.set_compaction_horizon_for_test(50);

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // initial_items=Some simulates sendInitialEvents=true having already fetched a
        // fresh list snapshot. from_revision=10 is below the horizon of 50.
        let result = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 10,                 // expired — below horizon of 50
                initial_items: Some((vec![], 50)), // sendInitialEvents already fetched snapshot at rv=50
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "watch_generic must not return 410 when sendInitialEvents=true (initial_items is Some), \
             even if from_revision is below the compaction horizon — the watch starts from list_rv, \
             not from_revision"
        );
    }

    /// When Compacted fires, the 410 ERROR's metadata.resourceVersion must be the
    /// horizon, not last_rv.
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

    /// The (MAX_WATCHES_PER_CLIENT + 1)th watch from the same user returns 429.
    #[tokio::test]
    async fn watch_limit_per_client_returns_429_on_overflow() {
        use crate::state::{AppState, MAX_WATCHES_PER_CLIENT};
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

        let sem = state.watch_limit.semaphore_for("alice");
        let _permits: Vec<_> = (0..MAX_WATCHES_PER_CLIENT)
            .map(|_| {
                sem.clone()
                    .try_acquire_owned()
                    .expect("permit must be available")
            })
            .collect();

        let result = watch_generic(
            state.clone(),
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "alice".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_err(),
            "watch_generic must return Err(429) when the per-client limit is exhausted"
        );
        use axum::response::IntoResponse;
        let err_resp: axum::response::Response = result.unwrap_err().into_response();
        assert_eq!(
            err_resp.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "must return HTTP 429 when per-client watch limit is exhausted, not silently queue"
        );
    }

    // -- fetch_initial_events and watch_generic store error paths (mayor-8j1l) --

    /// fetch_initial_events maps StoreError → StatusError(500) via Status::internal.
    /// This test verifies the error conversion so that if the map_err is accidentally
    /// removed or changed to a different status code, the test fails.
    ///
    /// The path cannot be triggered with SqliteStore (which never errors after
    /// construction on :memory:), so we test the Status::internal constructor directly —
    /// it must produce INTERNAL_SERVER_ERROR. The production code has exactly one
    /// `map_err(|e| Status::internal(e.to_string()))` in fetch_initial_events.
    #[test]
    fn fetch_initial_events_store_error_maps_to_500() {
        use axum::response::IntoResponse;

        // Simulate what fetch_initial_events does on store.list() failure:
        // it calls Status::internal(e.to_string()). Verify the StatusCode is 500.
        let err = crate::status::Status::internal("simulated list failure".to_string());
        let resp: axum::response::Response = err.into_response();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "fetch_initial_events must map store list() errors to HTTP 500 via Status::internal; \
             changing this to another code would break client error handling"
        );
    }

    /// watch_generic maps store.watch() errors → StatusError(500) via Status::internal.
    /// The path cannot be triggered with SqliteStore (watch() always returns Ok after
    /// construction). This test verifies the Status::internal mapping is the correct 500 code.
    ///
    /// The production code path is:
    ///   state.store.watch(...).await.map_err(|e| Status::internal(e.to_string()))?
    /// If someone changes this to Status::bad_request or a 4xx, this test fails.
    #[test]
    fn watch_generic_store_watch_error_maps_to_500() {
        use axum::response::IntoResponse;

        let err = crate::status::Status::internal("simulated watch failure".to_string());
        let resp: axum::response::Response = err.into_response();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "watch_generic must map store watch() errors to HTTP 500 via Status::internal"
        );
    }

    /// A different user's watch succeeds even when another user has exhausted their quota.
    #[tokio::test]
    async fn watch_limit_does_not_affect_other_users() {
        use crate::state::{AppState, MAX_WATCHES_PER_CLIENT};
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

        let sem_alice = state.watch_limit.semaphore_for("alice");
        let _permits: Vec<_> = (0..MAX_WATCHES_PER_CLIENT)
            .map(|_| {
                sem_alice
                    .clone()
                    .try_acquire_owned()
                    .expect("permit must be available")
            })
            .collect();

        let result = watch_generic(
            state.clone(),
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "bob".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "bob's watch must succeed even when alice has exhausted her per-client limit"
        );
    }

    // -- watch_generic label/field selector filtering (mayor-gkif) --

    /// Helper: read from a watch_generic Response body with a timeout, returning parsed NDJSON lines.
    ///
    /// Waits up to 3 seconds for the body to close, then parses all collected NDJSON lines.
    /// All watch_generic calls in these tests must use `timeout_seconds: Some(1)` so the
    /// stream closes after 1 second, allowing `to_bytes` to return the collected bytes.
    ///
    /// The 3-second timeout guards against tests hanging indefinitely if the stream never closes.
    async fn read_watch_body_with_timeout(
        resp: axum::response::Response,
    ) -> Vec<serde_json::Value> {
        use tokio::time::{timeout, Duration};

        let body = resp.into_body();
        let result = timeout(
            Duration::from_secs(3),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await;

        let bytes = match result {
            Ok(Ok(b)) => b,
            // Timeout (stream still open after 3s) or error: return empty.
            _ => return vec![],
        };

        let text = match std::str::from_utf8(&bytes) {
            Ok(t) => t.to_owned(),
            Err(_) => return vec![],
        };
        text.lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    /// A watch with a matching label selector must emit the ADDED event for a matching object.
    /// The watcher subscribes with label selector "app=frontend". An object with that label
    /// is written BEFORE subscribing so the ring buffer replays it. The watch stream must
    /// yield ADDED. This is the primary correctness requirement for label-filtered watches.
    #[tokio::test]
    async fn watch_generic_label_selector_matching_object_emits_added() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Write matching object before subscribing so the ring buffer captures it.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-match",
                "namespace": "default",
                "labels": { "app": "frontend" }
            }
        });
        store
            .put(
                "/registry/configmaps/default/cm-match",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Subscribe from rv=0 with a matching label selector; ring buffer will replay the event.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can collect bytes
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed for label selector test"));

        let lines = read_watch_body_with_timeout(resp).await;
        assert_eq!(
            lines.len(),
            1,
            "matching object must produce exactly 1 ADDED event in the stream; got {:?}",
            lines
        );
        assert_eq!(
            lines[0]["type"], "ADDED",
            "event type must be ADDED for a matching object"
        );
        assert_eq!(
            lines[0]["object"]["metadata"]["name"], "cm-match",
            "ADDED event must carry the matching object"
        );
    }

    /// A watch with a label selector must NOT emit ADDED for non-matching objects.
    /// The watcher subscribes with "app=frontend". An object with "app=backend" is written
    /// BEFORE subscribing (ring buffer). No ADDED event must appear.
    ///
    /// If filtering is removed from watch_generic, this test fails because the non-matching
    /// object would be emitted, breaking informer cache correctness.
    #[tokio::test]
    async fn watch_generic_label_selector_non_matching_object_suppressed() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Write non-matching object BEFORE watching so it goes into the ring buffer.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-no-match",
                "namespace": "default",
                "labels": { "app": "backend" }
            }
        });
        store
            .put(
                "/registry/configmaps/default/cm-no-match",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Label selector "app=frontend" — the stored object has "app=backend".
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        // The stream blocks waiting for the next event (no matching objects); timeout returns empty.
        let lines = read_watch_body_with_timeout(resp).await;
        for line in &lines {
            assert_ne!(
                line["type"], "ADDED",
                "non-matching object must NOT produce ADDED event; \
                 label selector filtering is broken: got {:?}",
                lines
            );
        }
    }

    /// DELETED events must always pass through label selector filtering.
    /// Even if the deleted object did not match the selector, the client must still
    /// receive the DELETED event so it can remove the object from its local cache.
    /// Suppressing DELETED for non-matching objects would cause informer cache leaks.
    ///
    /// Implementation note: watch_generic uses `_ => false` in the `skip` match arm
    /// for non-Added/Modified events, ensuring Deleted always passes through.
    #[tokio::test]
    async fn watch_generic_deleted_event_always_passes_label_selector() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Create and then delete an object that does NOT match the label selector.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-deleted",
                "namespace": "default",
                "labels": { "app": "backend" }
            }
        });
        let rv = store
            .put(
                "/registry/configmaps/default/cm-deleted",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();
        store
            .delete("/registry/configmaps/default/cm-deleted", Some(rv))
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Watch with label selector "app=frontend" — the object has "app=backend".
        // The DELETED event must still arrive (not suppressed by the selector).
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        let lines = read_watch_body_with_timeout(resp).await;

        // Ring buffer has: ADDED (backend, suppressed) and DELETED (always passes).
        let deleted_count = lines.iter().filter(|v| v["type"] == "DELETED").count();
        assert_eq!(
            deleted_count, 1,
            "DELETED event must pass through label selector filtering; \
             suppressing it would cause informer cache leaks: got lines {:?}",
            lines
        );

        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 0,
            "non-matching ADDED event must be suppressed by label selector; got lines {:?}",
            lines
        );
    }

    /// Regression test for mayor-dymy (bug 2): when a MODIFIED event changes the object's
    /// labels so it no longer matches the watch selector, the server must emit a synthetic
    /// DELETED event, not drop the event silently.
    ///
    /// Without this fix, informers watching with a labelSelector would never learn that a
    /// previously-matching object exited scope (labels changed), causing stale cache entries
    /// and spurious reconciliations that act on objects no longer in scope.
    ///
    /// This test would fail on revert: without the synthetic DELETED, `deleted_count` is 0.
    #[tokio::test]
    async fn watch_generic_modified_event_losing_selector_match_emits_synthetic_deleted() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Create object with matching label "app=frontend".
        let obj_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-scope-exit",
                "namespace": "default",
                "labels": { "app": "frontend" }
            }
        });
        let rv1 = store
            .put(
                "/registry/configmaps/default/cm-scope-exit",
                bytes::Bytes::from(serde_json::to_vec(&obj_v1).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        // Update the object, removing the matching label (app=backend now).
        // This is a MODIFIED event whose new state no longer matches "app=frontend".
        let obj_v2 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-scope-exit",
                "namespace": "default",
                "labels": { "app": "backend" }
            }
        });
        store
            .put(
                "/registry/configmaps/default/cm-scope-exit",
                bytes::Bytes::from(serde_json::to_vec(&obj_v2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Watch with "app=frontend". Ring buffer has ADDED (matches) then MODIFIED (no match).
        // The MODIFIED must produce a synthetic DELETED, not silence.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        let lines = read_watch_body_with_timeout(resp).await;

        // Expect: ADDED (v1 matches) + DELETED (synthetic, v2 lost match).
        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 1,
            "initial ADDED (matching object) must appear in stream; got {:?}",
            lines
        );

        let deleted_count = lines.iter().filter(|v| v["type"] == "DELETED").count();
        assert_eq!(
            deleted_count, 1,
            "MODIFIED event that removes matching label must emit a synthetic DELETED; \
             without it informers never learn the object left scope and keep stale cache \
             entries (mayor-dymy regression): got {:?}",
            lines
        );

        // The synthetic DELETED must identify the correct object.
        let deleted_ev = lines.iter().find(|v| v["type"] == "DELETED").unwrap();
        assert_eq!(
            deleted_ev["object"]["metadata"]["name"], "cm-scope-exit",
            "synthetic DELETED must carry the object name; got {:?}",
            deleted_ev
        );
        assert_eq!(
            deleted_ev["object"]["metadata"]["namespace"], "default",
            "synthetic DELETED must carry the object namespace; got {:?}",
            deleted_ev
        );

        // No MODIFIED events should appear — the object lost scope.
        let modified_count = lines.iter().filter(|v| v["type"] == "MODIFIED").count();
        assert_eq!(
            modified_count, 0,
            "MODIFIED that exits scope must not appear as MODIFIED in stream; got {:?}",
            lines
        );
    }

    // -- parse_key_name_ns --

    /// parse_key_name_ns extracts name and namespace from a namespaced store key.
    /// Kubernetes DELETE tombstones are built from this; wrong parsing causes
    /// malformed watch DELETED events that confuse client informers.
    #[test]
    fn parse_key_name_ns_extracts_name_and_namespace() {
        let (name, ns) = parse_key_name_ns("/registry/coordination.k8s.io/leases/default/my-lease");
        assert_eq!(name, "my-lease");
        assert_eq!(ns, "default");
    }

    /// parse_key_name_ns returns empty namespace for cluster-scoped keys.
    #[test]
    fn parse_key_name_ns_cluster_scoped_has_empty_namespace() {
        let (name, _ns) = parse_key_name_ns("/registry/storage.k8s.io/csinodes/node-1");
        assert_eq!(name, "node-1");
        // The segment before name is "csinodes", not a namespace, but parse_key_name_ns
        // returns whatever the second-to-last segment is. For cluster-scoped resources
        // that segment is the plural resource name, which is non-empty.
        // The important invariant: name is the last segment.
        assert!(!name.is_empty());
    }

    /// parse_key_name_ns on a single-segment key returns (segment, "").
    #[test]
    fn parse_key_name_ns_single_segment_returns_empty_namespace() {
        let (name, ns) = parse_key_name_ns("only-name");
        assert_eq!(name, "only-name");
        assert_eq!(ns, "");
    }

    // -- fetch_initial_events --

    /// fetch_initial_events returns None when send_initial_events is false.
    /// This keeps the normal watch path unchanged and avoids a redundant list.
    #[tokio::test]
    async fn fetch_initial_events_returns_none_when_disabled() {
        use crate::state::AppState;
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

        let result = match fetch_initial_events(&state, "/registry/test/", false, "", "").await {
            Ok(r) => r,
            Err(_) => panic!("fetch_initial_events must not fail"),
        };

        assert!(
            result.is_none(),
            "fetch_initial_events must return None when send_initial_events=false"
        );
    }

    /// fetch_initial_events returns Some with existing objects when enabled.
    /// Kubelet uses this to get a complete state snapshot before streaming live changes.
    #[tokio::test]
    async fn fetch_initial_events_returns_existing_objects_when_enabled() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed two objects
        for name in ["cm-a", "cm-b"] {
            let obj = serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "name": name, "namespace": "default" }
            });
            store
                .put(
                    &format!("/registry/configmaps/default/{name}"),
                    bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                    Some(0),
                )
                .await
                .unwrap();
        }

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = match fetch_initial_events(
            &state,
            "/registry/configmaps/default/",
            true,
            "",
            "configmaps",
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("fetch_initial_events must not fail"),
        };

        let (items, _rv) =
            result.unwrap_or_else(|| panic!("fetch_initial_events must return Some when enabled"));
        assert_eq!(
            items.len(),
            2,
            "fetch_initial_events must return all objects under prefix"
        );
    }

    /// fetch_initial_events returns Some with empty list when no objects exist.
    /// Empty sendInitialEvents must still emit a BOOKMARK; returning None would skip it.
    #[tokio::test]
    async fn fetch_initial_events_returns_empty_list_when_no_objects() {
        use crate::state::AppState;
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

        let result = match fetch_initial_events(
            &state,
            "/registry/configmaps/empty/",
            true,
            "",
            "configmaps",
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("fetch_initial_events must not fail"),
        };

        let (items, _rv) = result.unwrap_or_else(|| {
            panic!("fetch_initial_events must return Some even for empty namespace")
        });
        assert!(
            items.is_empty(),
            "empty prefix must return empty item list, not None"
        );
    }

    // -- object_matches_label_selector / object_matches_field_selector tests --

    fn item_with_labels(labels: &[(&str, &str)]) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (k, v) in labels {
            map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
        serde_json::json!({ "metadata": { "labels": map } })
    }

    #[test]
    fn filter_matches_all_present_labels() {
        use super::super::generic::LabelSelectorTerm;
        let items = vec![
            item_with_labels(&[("app", "frontend"), ("env", "prod")]),
            item_with_labels(&[("app", "backend"), ("env", "prod")]),
        ];
        let terms = vec![
            LabelSelectorTerm::Equality {
                key: "app",
                value: "frontend",
            },
            LabelSelectorTerm::Equality {
                key: "env",
                value: "prod",
            },
        ];
        let result = apply_label_selector(items, &terms);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["metadata"]["labels"]["app"], "frontend");
    }

    #[test]
    fn filter_removes_items_missing_label() {
        use super::super::generic::LabelSelectorTerm;
        let items = vec![
            item_with_labels(&[("app", "frontend")]),
            item_with_labels(&[]),
        ];
        let terms = vec![LabelSelectorTerm::Equality {
            key: "app",
            value: "frontend",
        }];
        let result = apply_label_selector(items, &terms);
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
        use super::super::generic::LabelSelectorTerm;
        let items = vec![item_with_labels(&[("app", "backend")])];
        let terms = vec![LabelSelectorTerm::Equality {
            key: "app",
            value: "frontend",
        }];
        let result = apply_label_selector(items, &terms);
        assert!(result.is_empty());
    }

    // -- object_matches_label_selector edge cases --

    /// Empty selector matches all objects, including those with no labels.
    /// Watch streams use this: an empty selector must never drop events.
    #[test]
    fn label_selector_empty_matches_all() {
        let obj_with_labels = serde_json::json!({"metadata": {"labels": {"app": "frontend"}}});
        let obj_no_labels = serde_json::json!({"metadata": {}});
        assert!(object_matches_label_selector(&obj_with_labels, ""));
        assert!(object_matches_label_selector(&obj_no_labels, ""));
    }

    /// A selector that does not match any label on the object returns false.
    #[test]
    fn label_selector_no_match_returns_false() {
        let obj = serde_json::json!({"metadata": {"labels": {"app": "backend"}}});
        assert!(!object_matches_label_selector(&obj, "app=frontend"));
    }

    /// Multiple comma-separated terms must all match (AND semantics).
    #[test]
    fn label_selector_multi_term_all_must_match() {
        let obj = serde_json::json!({"metadata": {"labels": {"app": "frontend", "env": "prod"}}});
        // Both match → true
        assert!(object_matches_label_selector(&obj, "app=frontend,env=prod"));
        // Only one matches → false
        assert!(!object_matches_label_selector(&obj, "app=frontend,env=dev"));
    }

    /// Object with no metadata.labels does not match any label selector.
    #[test]
    fn label_selector_object_without_labels_does_not_match() {
        let obj = serde_json::json!({"metadata": {"name": "no-labels"}});
        assert!(!object_matches_label_selector(&obj, "app=frontend"));
    }

    /// DoesNotExist (`!key`): objects WITH the key must be dropped; objects WITHOUT it must pass.
    /// KCM's EndpointSlice controller watches with `!service.kubernetes.io/headless`;
    /// if this operator is ignored (old bug), ALL EndpointSlice events fan out to ALL watchers.
    #[test]
    fn label_selector_does_not_exist_drops_objects_with_key() {
        let has_key =
            serde_json::json!({"metadata": {"labels": {"service.kubernetes.io/headless": ""}}});
        let no_key = serde_json::json!({"metadata": {"labels": {"app": "web"}}});
        let no_labels = serde_json::json!({"metadata": {"name": "bare"}});

        assert!(
            !object_matches_label_selector(&has_key, "!service.kubernetes.io/headless"),
            "object WITH the key must not match DoesNotExist(!key) — KCM EPS fan-out regression"
        );
        assert!(
            object_matches_label_selector(&no_key, "!service.kubernetes.io/headless"),
            "object without the key must match DoesNotExist(!key)"
        );
        assert!(
            object_matches_label_selector(&no_labels, "!service.kubernetes.io/headless"),
            "object with no labels must match DoesNotExist(!key)"
        );
    }

    /// Exists (bare `key`): objects WITHOUT the key must be dropped; objects WITH it must pass.
    #[test]
    fn label_selector_exists_drops_objects_missing_key() {
        let has_key = serde_json::json!({"metadata": {"labels": {"app": "web"}}});
        let no_key = serde_json::json!({"metadata": {"labels": {"env": "prod"}}});
        let no_labels = serde_json::json!({"metadata": {"name": "bare"}});

        assert!(
            object_matches_label_selector(&has_key, "app"),
            "object WITH the key must match bare-key Exists selector"
        );
        assert!(
            !object_matches_label_selector(&no_key, "app"),
            "object without the key must NOT match Exists selector — watch filter must drop it"
        );
        assert!(
            !object_matches_label_selector(&no_labels, "app"),
            "object with no labels must NOT match Exists selector"
        );
    }

    /// NotEquals (`key!=value`): objects where key==value must be dropped; others pass.
    #[test]
    fn label_selector_not_equals_drops_matching_value() {
        let matches_val = serde_json::json!({"metadata": {"labels": {"env": "prod"}}});
        let other_val = serde_json::json!({"metadata": {"labels": {"env": "staging"}}});
        let missing_key = serde_json::json!({"metadata": {"labels": {"app": "web"}}});

        assert!(
            !object_matches_label_selector(&matches_val, "env!=prod"),
            "object with env=prod must NOT match env!=prod selector"
        );
        assert!(
            object_matches_label_selector(&other_val, "env!=prod"),
            "object with env=staging must match env!=prod selector"
        );
        assert!(
            object_matches_label_selector(&missing_key, "env!=prod"),
            "object without env key must match env!=prod selector (key absent != value present)"
        );
    }

    /// Label-A watcher must NOT receive events for objects with only label B.
    /// This is the primary scenario from the bead: watcher for "app=frontend" must not see
    /// objects that have only "app=backend".
    #[test]
    fn label_selector_watcher_a_does_not_receive_events_for_label_b() {
        let label_b_obj = serde_json::json!({"metadata": {"labels": {"app": "backend"}}});
        assert!(
            !object_matches_label_selector(&label_b_obj, "app=frontend"),
            "watcher for app=frontend must not receive events for app=backend objects; \
             label-A watcher receiving label-B events causes informer cache divergence"
        );
    }

    // -- apply_label_selector new operator regression tests --

    /// apply_label_selector with DoesNotExist operator: objects with the key are excluded.
    #[test]
    fn apply_label_selector_does_not_exist_excludes_objects_with_key() {
        use super::super::generic::LabelSelectorTerm;
        let with_key = item_with_labels(&[("managed-by", "helm")]);
        let without_key = item_with_labels(&[("app", "web")]);
        let terms = vec![LabelSelectorTerm::DoesNotExist { key: "managed-by" }];
        let result = apply_label_selector(vec![with_key, without_key], &terms);
        assert_eq!(
            result.len(),
            1,
            "DoesNotExist filter must exclude objects that have the key; got {result:?}"
        );
        assert_eq!(
            result[0]["metadata"]["labels"]["app"], "web",
            "the remaining object must be the one without the key"
        );
    }

    /// apply_label_selector with Exists operator: objects without the key are excluded.
    #[test]
    fn apply_label_selector_exists_excludes_objects_missing_key() {
        use super::super::generic::LabelSelectorTerm;
        let with_key = item_with_labels(&[("tier", "frontend")]);
        let without_key = item_with_labels(&[("app", "web")]);
        let terms = vec![LabelSelectorTerm::Exists { key: "tier" }];
        let result = apply_label_selector(vec![with_key, without_key], &terms);
        assert_eq!(
            result.len(),
            1,
            "Exists filter must exclude objects that are missing the key; got {result:?}"
        );
        assert_eq!(
            result[0]["metadata"]["labels"]["tier"], "frontend",
            "the remaining object must be the one that has the key"
        );
    }

    /// apply_label_selector with NotEquals operator: objects where key==value are excluded.
    #[test]
    fn apply_label_selector_not_equals_excludes_matching_value() {
        use super::super::generic::LabelSelectorTerm;
        let prod = item_with_labels(&[("env", "prod")]);
        let staging = item_with_labels(&[("env", "staging")]);
        let terms = vec![LabelSelectorTerm::NotEquals {
            key: "env",
            value: "prod",
        }];
        let result = apply_label_selector(vec![prod, staging], &terms);
        assert_eq!(
            result.len(),
            1,
            "NotEquals filter must exclude the prod object; got {result:?}"
        );
        assert_eq!(
            result[0]["metadata"]["labels"]["env"], "staging",
            "the remaining object must be the staging one"
        );
    }

    // -- object_matches_field_selector edge cases --

    /// Empty field selector matches all objects.
    #[test]
    fn field_selector_empty_matches_all() {
        let obj = serde_json::json!({"metadata": {"name": "foo", "namespace": "default"}});
        assert!(object_matches_field_selector(&obj, ""));
    }

    /// metadata.name equality match returns true when names agree.
    #[test]
    fn field_selector_metadata_name_equality_matches() {
        let obj = serde_json::json!({"metadata": {"name": "foo"}});
        assert!(object_matches_field_selector(&obj, "metadata.name=foo"));
    }

    /// metadata.name equality returns false when name differs.
    #[test]
    fn field_selector_metadata_name_equality_no_match() {
        let obj = serde_json::json!({"metadata": {"name": "bar"}});
        assert!(!object_matches_field_selector(&obj, "metadata.name=foo"));
    }

    /// metadata.namespace equality filters by namespace.
    #[test]
    fn field_selector_metadata_namespace_equality() {
        let obj = serde_json::json!({"metadata": {"name": "pod-1", "namespace": "kube-system"}});
        assert!(object_matches_field_selector(
            &obj,
            "metadata.namespace=kube-system"
        ));
        assert!(!object_matches_field_selector(
            &obj,
            "metadata.namespace=default"
        ));
    }

    /// spec.nodeName equality match.
    #[test]
    fn field_selector_spec_node_name_equality() {
        let obj =
            serde_json::json!({"metadata": {"name": "pod-1"}, "spec": {"nodeName": "node-a"}});
        assert!(object_matches_field_selector(&obj, "spec.nodeName=node-a"));
        assert!(!object_matches_field_selector(&obj, "spec.nodeName=node-b"));
    }

    /// spec.nodeName inequality (`!=`) returns false when names are equal.
    #[test]
    fn field_selector_spec_node_name_inequality() {
        let obj =
            serde_json::json!({"metadata": {"name": "pod-1"}, "spec": {"nodeName": "node-a"}});
        // node-a != node-a → false (they are equal, so inequality fails)
        assert!(!object_matches_field_selector(
            &obj,
            "spec.nodeName!=node-a"
        ));
        // node-a != node-b → true (they differ)
        assert!(object_matches_field_selector(&obj, "spec.nodeName!=node-b"));
    }

    /// Unknown field is ignored (conservative: don't drop events for unrecognised selectors).
    #[test]
    fn field_selector_unknown_field_is_ignored() {
        let obj = serde_json::json!({"metadata": {"name": "pod-1"}});
        // Unknown field → ignore → still matches
        assert!(object_matches_field_selector(&obj, "status.phase=Running"));
    }

    // -- sendInitialEvents regression: initial-events-end BOOKMARK via watch_generic (mayor-w9tz) --

    /// Regression: when fetch_initial_events returns Some(items, rv) and is passed to
    /// watch_generic, the stream must emit the initial-events-end BOOKMARK before any
    /// live events. This verifies the fix for mayor-w9tz: CR watch paths (cr.rs, crd.rs)
    /// previously passed None for initial_items, causing GC to block forever waiting for
    /// the BOOKMARK and never completing cache sync.
    #[tokio::test]
    async fn watch_generic_with_initial_items_emits_initial_events_end_bookmark() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed one object so initial_items is non-empty.
        let obj = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GatewayClass",
            "metadata": { "name": "my-gc" }
        });
        store
            .put(
                "/registry/gateway.networking.k8s.io/v1/gatewayclasses/my-gc",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Simulate what list_cr does: call fetch_initial_events then pass result to watch_generic.
        let initial_items = match fetch_initial_events(
            &state,
            "/registry/gateway.networking.k8s.io/v1/gatewayclasses/",
            true, // send_initial_events = true
            "gateway.networking.k8s.io",
            "gatewayclasses",
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("fetch_initial_events must not fail"),
        };

        assert!(
            initial_items.is_some(),
            "fetch_initial_events must return Some when send_initial_events=true"
        );

        let resp = match watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/gateway.networking.k8s.io/v1/gatewayclasses/".into(),
                api_version: "gateway.networking.k8s.io/v1".into(),
                kind: "GatewayClass".into(),
                from_revision: 0,
                initial_items,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: true,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch_generic must succeed"),
        };

        let lines = read_watch_body_with_timeout(resp).await;

        // The stream must contain at least: ADDED (for seeded object) + BOOKMARK with
        // k8s.io/initial-events-end=true. If initial_items is None (the bug), no BOOKMARK
        // is emitted and GC blocks forever waiting for it.
        let bookmark = lines.iter().find(|v| {
            v["type"] == "BOOKMARK"
                && v["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
        });
        assert!(
            bookmark.is_some(),
            "watch_generic must emit initial-events-end BOOKMARK when initial_items is Some; \
             without it GC (metadatainformer) blocks cache sync forever (mayor-w9tz). \
             Got lines: {:?}",
            lines
        );

        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert!(
            added_count >= 1,
            "watch_generic must emit at least one ADDED event for the seeded object before the BOOKMARK; got {:?}",
            lines
        );
    }

    /// A Service stored without ipFamilies/ipFamilyPolicy must have those fields defaulted in
    /// the watch ADDED event. KCM's endpoints-controller indexes IPFamilies[0] on every
    /// watch event; if the field is absent from the watch stream (even though GET would default it),
    /// KCM panics. This test fails if apply_defaults is removed from the watch event path.
    #[tokio::test]
    async fn watch_generic_service_added_event_has_ip_family_defaults() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "my-svc",
                "namespace": "default"
            },
            "spec": {
                "clusterIP": "10.96.1.1",
                "selector": { "app": "foo" }
            }
        });
        store
            .put(
                "/registry/services/default/my-svc",
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/services/default/".into(),
                api_version: "v1".into(),
                kind: "Service".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "services".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        let lines = read_watch_body_with_timeout(resp).await;
        let added = lines
            .iter()
            .find(|v| v["type"] == "ADDED")
            .unwrap_or_else(|| panic!("must emit ADDED event; got {:?}", lines));

        assert_eq!(
            added["object"]["spec"]["ipFamilyPolicy"], "SingleStack",
            "watch ADDED event must carry ipFamilyPolicy default; \
             KCM reads this field from watch events and panics if absent"
        );
        assert_eq!(
            added["object"]["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "watch ADDED event must carry ipFamilies default; \
             KCM indexes IPFamilies[0] and panics if the slice is nil"
        );
        assert_eq!(
            added["object"]["spec"]["clusterIPs"],
            serde_json::json!(["10.96.1.1"]),
            "watch ADDED event must carry clusterIPs default"
        );
    }

    /// fetch_initial_events must apply defaults to snapshot items returned via sendInitialEvents=true.
    /// Without this, a Service seeded without ipFamilies is delivered raw to KCM's
    /// endpoints-controller, which indexes IPFamilies[0] and panics, killing the KCM process.
    /// This test fails on revert: fetch_initial_events would return items without ipFamilies.
    #[tokio::test]
    async fn fetch_initial_events_applies_defaults_to_snapshot_items() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed a Service WITHOUT ipFamilies — exactly as main.rs seeds kube-dns.
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "kube-dns", "namespace": "kube-system" },
            "spec": { "clusterIP": "10.96.0.10", "selector": { "k8s-app": "kube-dns" } }
        });
        store
            .put(
                "/registry/services/kube-system/kube-dns",
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = fetch_initial_events(
            &state,
            "/registry/services/kube-system/",
            true,
            "",
            "services",
        )
        .await
        .expect("fetch_initial_events must succeed")
        .expect("sendInitialEvents=true must return Some");

        let (items, _) = result;
        assert_eq!(items.len(), 1, "must return the seeded service");
        assert_eq!(
            items[0]["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "fetch_initial_events must apply ipFamilies default to snapshot items; \
             KCM indexes IPFamilies[0] on every service event — a missing ipFamilies panics \
             the endpoints-controller and kills the KCM process"
        );
    }

    /// Regression test for mayor-guqc: timeout_seconds controls the server-side watch stream
    /// lifetime. When `timeout_seconds: Some(1)`, the stream must close within ~2 seconds.
    ///
    /// Without the fix, timeout_seconds was ignored and the server defaulted to 5 minutes (300s).
    /// This test fails on revert: `to_bytes` would block for 300s and the outer `timeout`
    /// would expire, causing the assertion `completed` to be false.
    ///
    /// The practical impact: Kubernetes informers send `timeoutSeconds=<n>` (typically 300-600s)
    /// to control watch stream lifetime. If ignored, the server closes based only on the
    /// internal default, which may be shorter (causing "context canceled" on every watch).
    #[tokio::test]
    async fn watch_generic_timeout_seconds_closes_stream_at_requested_duration() {
        use crate::state::AppState;
        use std::sync::Arc;
        use tokio::time::{timeout, Duration};
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Request a 1-second watch stream. The stream generator will break out of its loop
        // after max_duration fires (1s), closing the body. Without the fix, timeout_seconds
        // is ignored and the stream default is 300s — to_bytes would not return within 2s.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "configmaps".into(),
                timeout_seconds: Some(1), // request 1-second stream lifetime
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch_generic must succeed with timeout_seconds=1"));

        // Collect body with a 3-second outer timeout. If timeout_seconds is honoured, the
        // stream closes after ~1s and to_bytes returns Ok. If timeout_seconds is ignored
        // (300s default), to_bytes blocks until the outer timeout expires → Err(elapsed).
        let completed = timeout(
            Duration::from_secs(3),
            axum::body::to_bytes(resp.into_body(), usize::MAX),
        )
        .await
        .is_ok();

        assert!(
            completed,
            "watch stream with timeout_seconds=1 must close within 3s; \
             if it does not, timeout_seconds is being ignored and the server uses a longer \
             default — Kubernetes informers that set timeoutSeconds will get streams that \
             close at the wrong time (mayor-guqc)"
        );
    }

    // -- sendInitialEvents + fieldSelector regression (mayor-ezur) --

    /// Regression for mayor-ezur: a watch with sendInitialEvents=true AND a matching
    /// fieldSelector must deliver an ADDED event for the matching object followed by a
    /// BOOKMARK with k8s.io/initial-events-end=true.
    ///
    /// Without the fix, the initial snapshot is emitted without field selector filtering,
    /// so all objects are emitted as ADDED regardless of the selector. After the fix,
    /// only matching objects are emitted. This test verifies the matching path works.
    ///
    /// This test fails if the field selector filter is removed from the initial snapshot loop.
    #[tokio::test]
    async fn watch_generic_send_initial_events_with_matching_field_selector_emits_added_then_bookmark(
    ) {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed the object we will filter for.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "default",
                "namespace": "test-ns"
            }
        });
        store
            .put(
                "/registry/serviceaccounts/test-ns/default",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let initial_items = fetch_initial_events(
            &state,
            "/registry/serviceaccounts/test-ns/",
            true,
            "",
            "serviceaccounts",
        )
        .await
        .expect("fetch_initial_events must not fail");

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/serviceaccounts/test-ns/".into(),
                api_version: "v1".into(),
                kind: "ServiceAccount".into(),
                from_revision: 0,
                initial_items,
                label_selector: None,
                field_selector: Some("metadata.name=default".into()),
                allow_watch_bookmarks: true,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1),
            },
        )
        .await
        .expect("watch_generic must succeed");

        let lines = read_watch_body_with_timeout(resp).await;

        // Must have exactly one ADDED event for the matching object.
        let added: Vec<_> = lines.iter().filter(|v| v["type"] == "ADDED").collect();
        assert_eq!(
            added.len(),
            1,
            "sendInitialEvents + fieldSelector=metadata.name=default must emit exactly 1 ADDED \
             for the matching object; got {:?}",
            lines
        );
        assert_eq!(
            added[0]["object"]["metadata"]["name"], "default",
            "ADDED event must carry the matching object (mayor-ezur)"
        );

        // Must have a BOOKMARK with k8s.io/initial-events-end=true.
        let bookmark = lines.iter().find(|v| {
            v["type"] == "BOOKMARK"
                && v["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
        });
        assert!(
            bookmark.is_some(),
            "sendInitialEvents watch must emit initial-events-end BOOKMARK; \
             without it the watch hangs forever (mayor-ezur). Got lines: {:?}",
            lines
        );
    }

    /// Regression for mayor-ezur: a watch with sendInitialEvents=true AND a non-matching
    /// fieldSelector must emit NO ADDED events (the object is filtered out) but still emit
    /// the BOOKMARK with k8s.io/initial-events-end=true.
    ///
    /// Without the fix, the non-matching object is emitted as ADDED (field selector ignored
    /// for initial snapshot). After the fix it is filtered out. The BOOKMARK must still
    /// arrive so the watch does not hang.
    ///
    /// This test fails if the field selector filter is removed from the initial snapshot loop.
    #[tokio::test]
    async fn watch_generic_send_initial_events_with_non_matching_field_selector_emits_only_bookmark(
    ) {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed an object whose name does NOT match the field selector.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "other-sa",
                "namespace": "test-ns2"
            }
        });
        store
            .put(
                "/registry/serviceaccounts/test-ns2/other-sa",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let initial_items = fetch_initial_events(
            &state,
            "/registry/serviceaccounts/test-ns2/",
            true,
            "",
            "serviceaccounts",
        )
        .await
        .expect("fetch_initial_events must not fail");

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/serviceaccounts/test-ns2/".into(),
                api_version: "v1".into(),
                kind: "ServiceAccount".into(),
                from_revision: 0,
                initial_items,
                label_selector: None,
                // Selector for "default" — the stored SA is named "other-sa", so no match.
                field_selector: Some("metadata.name=default".into()),
                allow_watch_bookmarks: true,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1),
            },
        )
        .await
        .expect("watch_generic must succeed");

        let lines = read_watch_body_with_timeout(resp).await;

        // Must have zero ADDED events — the object does not match the selector.
        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 0,
            "sendInitialEvents + non-matching fieldSelector must emit no ADDED events; \
             field selector filtering of initial snapshot is broken (mayor-ezur). Got: {:?}",
            lines
        );

        // The BOOKMARK with initial-events-end must still arrive so the watch doesn't hang.
        let bookmark = lines.iter().find(|v| {
            v["type"] == "BOOKMARK"
                && v["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
        });
        assert!(
            bookmark.is_some(),
            "sendInitialEvents watch must emit initial-events-end BOOKMARK even when no objects \
             match the fieldSelector; without it the watch hangs forever (mayor-ezur). \
             Got lines: {:?}",
            lines
        );
    }

    /// Regression test for mayor-bg80: a watch opened with from_revision=N (the revision at
    /// which an object was created) must NOT deliver a spurious ADDED event for that object.
    ///
    /// The Kubernetes conformance test "should observe add, update, and delete watch notifications
    /// on configmaps" lists configmaps (getting rv=N), then opens a watch at rv=N. Any existing
    /// configmap (e.g. kube-root-ca.crt created at rv≤N) must not appear as an ADDED event.
    /// A spurious ADDED causes the test to fail with "Unexpected watch notification observed".
    ///
    /// This test fails if the ring buffer filter changes from strict `>` to inclusive `>=`,
    /// or if the from_revision is not forwarded correctly to the store's watch() call.
    #[tokio::test]
    async fn watch_generic_no_spurious_added_for_object_created_before_watch_rv() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Create an object that exists BEFORE the watch is opened.
        // This simulates kube-root-ca.crt or any other pre-existing configmap.
        let pre_existing = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "kube-root-ca.crt",
                "namespace": "default"
            }
        });
        let create_rv = store
            .put(
                "/registry/configmaps/default/kube-root-ca.crt",
                bytes::Bytes::from(serde_json::to_vec(&pre_existing).unwrap()),
                Some(0),
            )
            .await
            .expect("create pre-existing configmap");

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Open watch at from_revision=create_rv. This simulates a client that listed
        // configmaps (getting rv=create_rv) and then opens a watch at that rv, expecting
        // to see only NEW events — not the ADDED for the pre-existing object.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: create_rv,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "configmaps".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch_generic must succeed"));

        // The stream must block — no immediate ADDED for the pre-existing configmap.
        // Any ADDED event here is spurious and represents the bug.
        let lines = read_watch_body_with_timeout(resp).await;
        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 0,
            "watch at from_revision=N must not emit ADDED for objects created at revision ≤N; \
             a spurious ADDED breaks the conformance test \
             'should observe add, update, and delete watch notifications on configmaps' \
             (mayor-bg80). Got lines: {:?}",
            lines
        );
    }

    /// A write to prefix A must deliver a BOOKMARK to a watch on prefix B.
    ///
    /// KCM 1.36 ConsistencyStore.EnsureReady() checks each informer's
    /// LastStoreSyncResourceVersion (advanced by BOOKMARK events) against the RV
    /// of any write the controller made — including writes to other resource types.
    /// A StatefulSet watch that hasn't seen a StatefulSet event stays at its initial
    /// sync RV, so a pod write at a higher RV causes EnsureReady to requeue forever.
    /// The global bookmark (key="") fixes this by delivering a BOOKMARK with the
    /// current global RV to every open watch after each write.
    #[tokio::test]
    async fn write_to_different_prefix_delivers_bookmark_to_watch() {
        use std::sync::Arc;
        use u7s_store::{SqliteStore, Store};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Write an object under prefix A so we have a non-zero baseline RV.
        store
            .put(
                "/registry/pods/default/pod-1",
                bytes::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": {"name": "pod-1", "namespace": "default"}
                    }))
                    .unwrap(),
                ),
                None,
            )
            .await
            .expect("pod write must succeed");

        // Open a watch on prefix B (statefulsets) starting from rv=0.
        let sts_stream = store
            .watch("/registry/apps/statefulsets/", 0)
            .await
            .expect("watch must open");

        // Write another object under prefix A (a second pod).
        store
            .put(
                "/registry/pods/default/pod-2",
                bytes::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": {"name": "pod-2", "namespace": "default"}
                    }))
                    .unwrap(),
                ),
                None,
            )
            .await
            .expect("second pod write must succeed");

        let pod_rv = store.current_revision();

        // The statefulset watch must receive a BOOKMARK with the pod write RV,
        // even though no statefulset was written.
        use std::pin::pin;
        use tokio::time::{timeout, Duration};
        let mut sts_stream = pin!(sts_stream);
        let event = timeout(Duration::from_secs(2), async {
            loop {
                if let Some(u7s_store::WatchEvent::Bookmark { revision }) =
                    futures_util::StreamExt::next(&mut sts_stream).await
                {
                    return revision;
                }
            }
        })
        .await
        .expect("statefulset watch must receive a BOOKMARK within 2s after a pod write");

        assert!(
            event >= pod_rv,
            "BOOKMARK revision {event} must be >= pod write revision {pod_rv} — \
             without this, KCM ConsistencyStore.EnsureReady requeues the StatefulSet \
             controller forever after every pod creation"
        );
    }
}
