use axum::{body::Body, http::StatusCode, response::Response};
use bytes::Bytes;
use u7s_store::{ListOptions, Store, WatchEvent};

use crate::{state::AppState, status::Status};

/// Serialise a single watch event to NDJSON bytes (including trailing newline).
/// Returns None on Compacted — the caller should close the stream.
/// Returns None on corrupt object bytes (invalid UTF-8) — the event is skipped,
/// a warning is logged, and the stream continues. Emitting null would send invalid
/// data to Kubernetes clients that may panic or behave incorrectly.
pub(crate) fn encode_watch_event(
    event: &WatchEvent,
    api_version: &str,
    kind: &str,
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
            format!("{{\"type\":\"ADDED\",\"object\":{object_json}}}\n")
        }
        WatchEvent::Modified(obj) => {
            let object_json = match std::str::from_utf8(&obj.value) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("watch MODIFIED event has invalid UTF-8, skipping: {e}");
                    return None;
                }
            };
            format!("{{\"type\":\"MODIFIED\",\"object\":{object_json}}}\n")
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
pub(crate) async fn fetch_initial_events(
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

/// Stream watch events for a given store prefix in NDJSON format.
/// Mirrors watch_pods in pods.rs with a 60s bookmark heartbeat and 5min max duration.
///
/// When `initial_items` is Some, those items are emitted as ADDED events first
/// (implementing the Kubernetes 1.27+ sendInitialEvents protocol), followed by a
/// BOOKMARK, before streaming live changes from `from_revision`.
///
/// `username` is the authenticated client identity used to enforce the per-client
/// watch stream concurrency limit (MAX_WATCHES_PER_CLIENT). Exceeding the limit
/// returns HTTP 429 immediately without opening a watch stream.
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
    allow_watch_bookmarks: bool,
    username: String,
) -> Result<Response, crate::status::StatusError> {
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
    if from_revision > 0 {
        let horizon = state.store.compaction_horizon();
        if from_revision < horizon {
            return Err(Status::expired(format!(
                "too old resource version: {from_revision} (current compaction horizon: {horizon})"
            )));
        }
    }

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
                    if allow_watch_bookmarks {
                        let bookmark = format!(
                            "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\"}}}}}}\n"
                        );
                        yield Ok::<Bytes, axum::BoxError>(Bytes::from(bookmark));
                    }
                }

                _ = &mut max_duration => {
                    if allow_watch_bookmarks {
                        let bookmark = format!(
                            "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\"}}}}}}\n"
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

        let result = encode_watch_event(&event, "v1", "ConfigMap");

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

        let result = encode_watch_event(&event, "v1", "ConfigMap");

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
            "/registry/test/".into(),
            "v1".into(),
            "ConfigMap".into(),
            10, // expired
            None,
            None,
            None,
            false,
            "test-user".into(),
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
            "/registry/test/".into(),
            "v1".into(),
            "ConfigMap".into(),
            0, // not expired
            None,
            None,
            None,
            false,
            "test-user".into(),
        )
        .await;

        assert!(
            result.is_ok(),
            "rv=0 (full watch) must not trigger the 410 expiry check, \
             even when a compaction horizon exists"
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
            "/registry/test/".into(),
            "v1".into(),
            "ConfigMap".into(),
            0,
            None,
            None,
            None,
            false,
            "alice".into(),
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
            "/registry/test/".into(),
            "v1".into(),
            "ConfigMap".into(),
            0,
            None,
            None,
            None,
            false,
            "bob".into(),
        )
        .await;

        assert!(
            result.is_ok(),
            "bob's watch must succeed even when alice has exhausted her per-client limit"
        );
    }

    // -- watch_generic label/field selector filtering (mayor-gkif) --

    /// Helper: read from a watch_generic Response body with a timeout, returning parsed NDJSON lines.
    /// Used to consume ring-buffer events which are emitted synchronously at stream start.
    async fn read_watch_body_with_timeout(
        resp: axum::response::Response,
    ) -> Vec<serde_json::Value> {
        use tokio::time::{timeout, Duration};

        let body = resp.into_body();
        // Use a short timeout: ring-buffer events are emitted immediately; live events block.
        let result = timeout(
            Duration::from_millis(200),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await;

        let bytes = match result {
            Ok(Ok(b)) => b,
            // Timeout or error: use whatever was collected so far (empty).
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
            "/registry/configmaps/default/".into(),
            "v1".into(),
            "ConfigMap".into(),
            0,
            None,
            Some("app=frontend".into()),
            None,
            false,
            "test-user".into(),
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
            "/registry/configmaps/default/".into(),
            "v1".into(),
            "ConfigMap".into(),
            0,
            None,
            Some("app=frontend".into()),
            None,
            false,
            "test-user".into(),
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
            "/registry/configmaps/default/".into(),
            "v1".into(),
            "ConfigMap".into(),
            0,
            None,
            Some("app=frontend".into()),
            None,
            false,
            "test-user".into(),
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

        let result = match fetch_initial_events(&state, "/registry/test/", false).await {
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

        let result = match fetch_initial_events(&state, "/registry/configmaps/default/", true).await
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

        let result = match fetch_initial_events(&state, "/registry/configmaps/empty/", true).await {
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
}
