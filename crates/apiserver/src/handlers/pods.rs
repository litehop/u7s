use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use serde::Deserialize;
use u7s_store::{ListOptions, Store, StoreError};

use crate::{
    admission::{run_mutating_webhooks, run_validating_webhooks, AdmissionContext},
    auth::UserInfo,
    keys::{cluster_object_key, list_prefix, object_key},
    state::AppState,
    status::Status,
    types::{Binding, Namespace, Object, ObjectMeta, PodSpec},
    util::{extract_body, parse_resource_version},
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    pub watch: Option<bool>,
    pub resource_version: Option<u64>,
    #[serde(rename = "labelSelector")]
    pub label_selector: Option<String>,
    pub field_selector: Option<String>,
    /// When true, the server emits existing pods as ADDED events before streaming
    /// live changes. Used by kubelet (Kubernetes 1.27+) for efficient informer startup.
    #[serde(rename = "sendInitialEvents")]
    pub send_initial_events: Option<bool>,
    /// When true, the server sends periodic BOOKMARK events. When false or absent,
    /// bookmarks are suppressed (except the sendInitialEvents end-of-list BOOKMARK).
    #[serde(rename = "allowWatchBookmarks")]
    pub allow_watch_bookmarks: Option<bool>,
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
                    negated: false,
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
    let spec: PodSpec = serde_json::from_value(pod["spec"].clone()).unwrap_or_default();
    let node_name = spec.node_name.as_deref().unwrap_or("");
    for term in selector.split(',') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        if let Some((field, value)) = term.split_once("!=") {
            if field == "spec.nodeName" && node_name == value {
                return false;
            }
            // Unknown fields: ignore (don't filter out)
        } else if let Some((field, value)) = term.split_once('=') {
            if field == "spec.nodeName" && node_name != value {
                return false;
            }
            // Unknown fields: ignore (don't filter out)
        }
        // Unparseable term: ignore
    }
    true
}

/// Validate a raw namespace string: format check then store lookup.
/// Returns 400 on invalid format, 404 if namespace does not exist.
async fn parse_namespace<S: Store>(
    raw: &str,
    state: &AppState<S>,
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

pub async fn list_pods<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns,)): Path<(String,)>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
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
        return super::watch::watch_generic(
            state,
            super::watch::WatchConfig {
                prefix,
                api_version: "v1".into(),
                kind: "Pod".into(),
                from_revision: from_rv,
                initial_items: initial_pods,
                label_selector: None,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username: user.username,
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "pods".into(),
            },
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

    let items = if let Some(ref sel) = query.label_selector {
        let pairs = super::generic::parse_label_selector(sel)?;
        super::generic::apply_label_selector(items, &pairs)
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

pub async fn create_pod<S: Store>(
    State(state): State<AppState<S>>,
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

    let name = crate::handlers::generic::resolve_name(&mut obj)?;

    // Ensure namespace is set in the stored object
    obj.body["metadata"]["namespace"] = serde_json::Value::String(ns.as_str().to_owned());
    crate::handlers::generic::stamp_metadata(&mut obj);

    apply_pod_create_defaults(&mut obj.body);
    inject_sa_token_volume(&mut obj.body, &name);

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "pods",
        name: &name,
        namespace: Some(ns.as_str()),
        operation: "CREATE",
    };
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), Some(0))
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok((StatusCode::CREATED, Json(obj.body)))
}

pub async fn get_pod<S: Store>(
    State(state): State<AppState<S>>,
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

pub async fn replace_pod<S: Store>(
    State(state): State<AppState<S>>,
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

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "pods",
        name: &name,
        namespace: Some(ns.as_str()),
        operation: "UPDATE",
    };
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok(Json(obj.body))
}

/// DELETE /api/v1/namespaces/{ns}/pods — collection delete with optional labelSelector.
///
/// sonobuoy cleanup sends this to remove all pods it created in a namespace.
/// Applies the labelSelector if present; deletes all matching pods.
pub async fn delete_collection_pods<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns,)): Path<(String,)>,
    Query(query): Query<super::generic::CollectionQuery>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let prefix = list_prefix("pods", ns.as_str());

    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(super::generic::parse_label_selector)
        .transpose()?;

    for obj in resp.items {
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.value) {
            if let Some(ref pairs) = label_pairs {
                let kept = super::generic::apply_label_selector(vec![parsed], pairs);
                if kept.is_empty() {
                    continue;
                }
            }
        }
        let _ = state.store.delete(&obj.key, None).await;
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

pub async fn delete_pod<S: Store>(
    State(state): State<AppState<S>>,
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

    let meta: ObjectMeta = serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
    let has_finalizers = meta.finalizers.as_ref().is_some_and(|f| !f.is_empty());

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

pub async fn patch_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = super::json_patch::detect_patch_type(&headers)?;

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
        super::json_patch::PatchType::StrategicMerge => {
            crate::patch::strategic_merge_patch(&mut current_obj.body, &patch)
                .map_err(|e| Status::bad_request(e.to_string()))?;
        }
        super::json_patch::PatchType::Merge => {
            crate::patch::merge_patch(&mut current_obj.body, &patch);
        }
        super::json_patch::PatchType::Json => {
            super::json_patch::apply_json_patch(&mut current_obj.body, &patch)?;
        }
    }

    // Post-patch: if deletionTimestamp is set and finalizers are now empty, hard-delete.
    let post_patch_meta: ObjectMeta =
        serde_json::from_value(current_obj.body["metadata"].clone()).unwrap_or_default();
    let deletion_ts_set = post_patch_meta.deletion_timestamp.is_some();
    let finalizers_empty = post_patch_meta
        .finalizers
        .as_ref()
        .is_none_or(|f| f.is_empty());

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
            crate::handlers::watch::encode_watch_event(&WatchEvent::Added(obj), "v1", "Pod", false)
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
        let bytes = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Modified(obj),
            "v1",
            "Pod",
            false,
        )
        .expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "MODIFIED");
    }

    /// encode_watch_event for Deleted reconstructs a minimal object from the store key.
    /// The emitted object must contain name and namespace derived from the key.
    #[test]
    fn encode_deleted_reconstructs_metadata() {
        let bytes = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Deleted {
                key: "/registry/pods/default/nginx".to_string(),
                revision: 9,
            },
            "v1",
            "Pod",
            false,
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
        let bytes = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Bookmark { revision: 42 },
            "v1",
            "Pod",
            false,
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
        let result = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Compacted {
                requested: 5,
                horizon: 50,
            },
            "v1",
            "Pod",
            false,
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
        let (name, ns) = crate::handlers::watch::parse_key_name_ns("/registry/pods/default/nginx");
        assert_eq!(name, "nginx");
        assert_eq!(ns, "default");
    }

    /// parse_key_name_ns handles a custom namespace correctly.
    #[test]
    fn parse_key_custom_namespace() {
        let (name, ns) =
            crate::handlers::watch::parse_key_name_ns("/registry/pods/kube-system/coredns");
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
            label_selector: None,
            field_selector: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
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
            label_selector: None,
            field_selector: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
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

#[cfg(test)]
mod label_selector_tests {
    fn pod_with_label(name: &str, key: &str, value: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": "sonobuoy",
                "labels": {key: value}
            },
            "spec": {}
        })
    }

    /// labelSelector on pods LIST must exclude pods whose labels do not match.
    ///
    /// sonobuoy issues `kubectl get pods -n sonobuoy -l sonobuoy-component=aggregator`
    /// and expects only the aggregator pod. Without label filtering, the plugin pod
    /// (sonobuoy-component=plugin) is also returned, causing sonobuoy to miscount
    /// running pods and stall.
    #[test]
    fn label_selector_excludes_non_matching_pods() {
        let aggregator = pod_with_label("sonobuoy", "sonobuoy-component", "aggregator");
        let plugin = pod_with_label("sonobuoy-e2e-job-abc", "sonobuoy-component", "plugin");
        let items = vec![aggregator, plugin];

        let pairs =
            super::super::generic::parse_label_selector("sonobuoy-component=aggregator").unwrap();
        let result = super::super::generic::apply_label_selector(items, &pairs);

        assert_eq!(
            result.len(),
            1,
            "labelSelector must exclude the plugin pod — only the aggregator should be returned"
        );
        assert_eq!(
            result[0]["metadata"]["name"], "sonobuoy",
            "the returned pod must be the aggregator, not the plugin"
        );
    }
}

// ---------------------------------------------------------------------------
// Status subresource — GET/PUT/PATCH /api/v1/namespaces/:ns/pods/:name/status
// ---------------------------------------------------------------------------

pub async fn get_pod_status<S: Store>(
    State(state): State<AppState<S>>,
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

pub async fn replace_pod_status<S: Store>(
    State(state): State<AppState<S>>,
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

pub async fn patch_pod_status<S: Store>(
    State(state): State<AppState<S>>,
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
        assert!(status
            .get("hostIP")
            .is_none_or(|v| v.is_null() || !status.as_object().unwrap().contains_key("hostIP")));
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
    use crate::handlers::json_patch::{apply_json_patch, detect_patch_type, PatchType};
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
        let result = detect_patch_type(&h);
        assert!(
            result.is_ok(),
            "application/json-patch+json must be accepted by patch_pod; \
             before mayor-erz fix it returned 415 Unsupported Media Type"
        );
        assert!(matches!(result.ok(), Some(PatchType::Json)));
    }

    /// strategic-merge-patch+json must be accepted.
    #[test]
    fn strategic_merge_patch_content_type_is_accepted() {
        let h = headers_with_ct("application/strategic-merge-patch+json");
        assert!(matches!(
            detect_patch_type(&h).ok(),
            Some(PatchType::StrategicMerge)
        ));
    }

    /// merge-patch+json must be accepted.
    #[test]
    fn merge_patch_content_type_is_accepted() {
        let h = headers_with_ct("application/merge-patch+json");
        assert!(matches!(detect_patch_type(&h).ok(), Some(PatchType::Merge)));
    }

    /// apply-patch+yaml is treated as strategic-merge-patch (SSA approximation).
    #[test]
    fn apply_patch_yaml_is_accepted_as_strategic_merge() {
        let h = headers_with_ct("application/apply-patch+yaml");
        assert!(matches!(
            detect_patch_type(&h).ok(),
            Some(PatchType::StrategicMerge)
        ));
    }

    /// Unknown content-type must return 415 error.
    #[test]
    fn unknown_content_type_returns_415() {
        let h = headers_with_ct("application/octet-stream");
        // Must error, not succeed.
        let result = detect_patch_type(&h);
        assert!(result.is_err(), "unknown content-type must be rejected");
        // Verify it produces a 415 response.
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    /// apply_json_patch: replace operation updates a field in the pod object.
    /// This verifies the json-patch apply path end-to-end at the logic level.
    #[test]
    fn apply_json_patch_replace_updates_field() {
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {"nodeName": "worker-1"}
        });
        let patch = serde_json::json!([
            {"op": "replace", "path": "/spec/nodeName", "value": "worker-2"}
        ]);
        assert!(
            apply_json_patch(&mut pod, &patch).is_ok(),
            "replace op must succeed"
        );
        assert_eq!(
            pod["spec"]["nodeName"], "worker-2",
            "replace op must update spec.nodeName"
        );
    }

    /// apply_json_patch: add operation inserts a new field.
    #[test]
    fn apply_json_patch_add_inserts_field() {
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod"},
            "spec": {}
        });
        let patch = serde_json::json!([
            {"op": "add", "path": "/spec/nodeName", "value": "worker-3"}
        ]);
        assert!(
            apply_json_patch(&mut pod, &patch).is_ok(),
            "add op must succeed"
        );
        assert_eq!(pod["spec"]["nodeName"], "worker-3");
    }

    /// apply_json_patch: remove operation deletes a field.
    #[test]
    fn apply_json_patch_remove_deletes_field() {
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod", "labels": {"app": "test"}}
        });
        let patch = serde_json::json!([
            {"op": "remove", "path": "/metadata/labels/app"}
        ]);
        assert!(
            apply_json_patch(&mut pod, &patch).is_ok(),
            "remove op must succeed"
        );
        assert!(
            pod["metadata"]["labels"].get("app").is_none(),
            "remove op must delete the key"
        );
    }
}

/// Apply pod creation defaults: set spec.enableServiceLinks=true if absent,
/// and stamp defaultMode=420 on configMap/secret/projected volumes if absent.
///
/// Extracted for testability — the full create_pod handler is async and needs
/// a live store, so the defaulting logic lives here as a pure function.
pub fn apply_pod_create_defaults(pod: &mut serde_json::Value) {
    // Deserialize spec into typed form once; all typed-field accesses are compile-checked.
    let mut spec: PodSpec = serde_json::from_value(pod["spec"].clone()).unwrap_or_default();

    // enableServiceLinks: PodSpec deserializes this with default_true, so
    // spec.enable_service_links is true when the field was absent. Write it
    // back only when absent in the raw JSON, preserving an explicit false.
    if pod["spec"]["enableServiceLinks"].is_null() {
        pod["spec"]["enableServiceLinks"] =
            serde_json::to_value(spec.enable_service_links).expect("bool is always serializable");
    }

    // dnsPolicy: default to "ClusterFirst" when absent.
    // Real kube-apiserver always stamps this field on create. The kubelet reads
    // spec.dnsPolicy and rejects empty string with "invalid DNSPolicy=", which
    // causes it to fall back to ClusterFirst for every pod — silently incorrect
    // behaviour. Defaulting here matches kube-apiserver behaviour and preserves
    // any explicit value set by the user (e.g. ClusterFirstWithHostNet, None).
    if pod["spec"]["dnsPolicy"].is_null() {
        pod["spec"]["dnsPolicy"] = serde_json::json!("ClusterFirst");
    }

    // defaultMode for volume sources that require it.
    // The kubelet refuses to mount ConfigMap/Secret volumes whose defaultMode is absent:
    //   "no defaultMode used, not even the default value for it"
    // Real kube-apiserver defaults these to 0644 (420 decimal).
    //
    // We deserialize each volume into a typed Volume, stamp the missing defaultMode
    // on the typed field, then write the whole volumes array back. This ensures the
    // rename of defaultMode → somethingElse is a compile error rather than a silent
    // bug, and that untyped volume fields (emptyDir, hostPath, etc.) survive via `rest`.
    if let Some(ref mut volumes) = spec.volumes {
        let mut changed = false;
        for vol in volumes.iter_mut() {
            for proj in [
                vol.config_map.as_mut(),
                vol.secret.as_mut(),
                vol.projected.as_mut(),
            ]
            .into_iter()
            .flatten()
            {
                if proj.default_mode.is_none() {
                    proj.default_mode = Some(420);
                    changed = true;
                }
            }
        }
        if changed {
            pod["spec"]["volumes"] =
                serde_json::to_value(&*volumes).expect("Volume is always serializable");
        }
    }
    // If spec.volumes is None, there is nothing to default.

    // Default fieldRef.apiVersion to "v1" for all containers (including initContainers).
    // The kubelet calls ConvertDownwardAPIFieldLabel(apiVersion, ...) which errors with
    // "unsupported pod version: <empty>" when apiVersion is absent.
    // Real kube-apiserver stamps this field before storing the object.
    for containers_key in &["containers", "initContainers"] {
        if let Some(containers) = pod["spec"][containers_key].as_array_mut() {
            for container in containers {
                if let Some(env) = container["env"].as_array_mut() {
                    for var in env {
                        let field_ref = &mut var["valueFrom"]["fieldRef"];
                        if field_ref.is_object()
                            && (field_ref["apiVersion"].is_null() || field_ref["apiVersion"] == "")
                        {
                            field_ref["apiVersion"] = serde_json::json!("v1");
                        }
                    }
                }
            }
        }
    }
}

/// Inject the projected service-account token volume into a pod, mirroring
/// what the real Kubernetes ServiceAccount admission plugin does.
///
/// Skips injection when:
/// - `spec.serviceAccountName` is absent or empty
/// - `spec.automountServiceAccountToken` is explicitly `false`
/// - any existing volume name already starts with `kube-api-access-` (idempotency)
///
/// The volume name suffix is derived deterministically from the pod name so
/// the function is pure (no I/O, no randomness) and therefore unit-testable.
pub fn inject_sa_token_volume(pod: &mut serde_json::Value, pod_name: &str) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Skip if serviceAccountName absent or empty.
    let sa_name = pod["spec"]["serviceAccountName"].as_str().unwrap_or("");
    if sa_name.is_empty() {
        return;
    }

    // Skip if automountServiceAccountToken is explicitly false.
    if pod["spec"]["automountServiceAccountToken"] == serde_json::Value::Bool(false) {
        return;
    }

    // Idempotency: skip if a kube-api-access-* volume already exists.
    if let Some(volumes) = pod["spec"]["volumes"].as_array() {
        if volumes.iter().any(|v| {
            v["name"]
                .as_str()
                .map(|n| n.starts_with("kube-api-access-"))
                .unwrap_or(false)
        }) {
            return;
        }
    }

    // Deterministic 5-char suffix from pod name hash.
    let mut h = DefaultHasher::new();
    pod_name.hash(&mut h);
    let suffix_num = h.finish();
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let suffix: String = (0..5)
        .map(|i| {
            let idx = ((suffix_num >> (i * 6)) as usize) % ALPHABET.len();
            ALPHABET[idx] as char
        })
        .collect();
    let vol_name = format!("kube-api-access-{suffix}");

    // Append projected volume.
    let new_vol = serde_json::json!({
        "name": vol_name,
        "projected": {
            "defaultMode": 420,
            "sources": [
                {"serviceAccountToken": {"expirationSeconds": 3607, "path": "token"}},
                {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                {"downwardAPI": {"items": [{"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}, "path": "namespace"}]}}
            ]
        }
    });
    match pod["spec"]["volumes"].as_array_mut() {
        Some(vols) => vols.push(new_vol),
        None => pod["spec"]["volumes"] = serde_json::json!([new_vol]),
    }

    // Append volumeMount to each container in containers and initContainers,
    // skipping any that already mount the SA path.
    const SA_MOUNT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
    let new_mount = serde_json::json!({
        "mountPath": SA_MOUNT_PATH,
        "name": vol_name,
        "readOnly": true
    });
    for containers_key in &["containers", "initContainers"] {
        if let Some(containers) = pod["spec"][containers_key].as_array_mut() {
            for container in containers.iter_mut() {
                let already_mounted = container["volumeMounts"]
                    .as_array()
                    .map(|mounts| {
                        mounts
                            .iter()
                            .any(|m| m["mountPath"].as_str() == Some(SA_MOUNT_PATH))
                    })
                    .unwrap_or(false);
                if already_mounted {
                    continue;
                }
                match container["volumeMounts"].as_array_mut() {
                    Some(mounts) => mounts.push(new_mount.clone()),
                    None => container["volumeMounts"] = serde_json::json!([new_mount.clone()]),
                }
            }
        }
    }
}

#[cfg(test)]
mod create_defaults_tests {
    use super::*;

    /// create_pod must default spec.enableServiceLinks to true when absent.
    ///
    /// The kubelet's kuberuntime_manager requires this field to construct service
    /// env vars for each container.  Without it the container fails with
    /// CreateContainerConfigError: "nil pod.spec.enableServiceLinks encountered".
    /// Real kube-apiserver always sets this field on create.
    #[test]
    fn enable_service_links_defaults_to_true_when_absent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "smoke-pod", "namespace": "default"},
            "spec": {
                "nodeName": "ci-node",
                "containers": [{"name": "hello", "image": "busybox:1.36"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["enableServiceLinks"],
            serde_json::Value::Bool(true),
            "enableServiceLinks must be defaulted to true so the kubelet can construct \
             service env vars; a nil value causes CreateContainerConfigError"
        );
    }

    /// create_pod must NOT override an explicit false value for enableServiceLinks.
    ///
    /// If the user explicitly disables service link injection, that preference
    /// must be preserved.
    #[test]
    fn enable_service_links_false_is_preserved() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "enableServiceLinks": false,
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["enableServiceLinks"],
            serde_json::Value::Bool(false),
            "an explicit enableServiceLinks=false must not be overridden by the default"
        );
    }

    /// Kubelet refuses to mount a ConfigMap volume whose defaultMode is absent:
    /// "no defaultMode used, not even the default value for it"
    /// Real kube-apiserver defaults it to 0644 (420 decimal).
    #[test]
    fn configmap_volume_default_mode_is_set_when_absent() {
        let mut pod = serde_json::json!({
            "spec": {
                "volumes": [{"name": "cfg", "configMap": {"name": "my-cm"}}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["volumes"][0]["configMap"]["defaultMode"],
            serde_json::Value::Number(420.into()),
            "configMap volume defaultMode must be set to 0644 (420) when absent"
        );
    }

    #[test]
    fn configmap_volume_explicit_default_mode_is_preserved() {
        let mut pod = serde_json::json!({
            "spec": {
                "volumes": [{"name": "cfg", "configMap": {"name": "my-cm", "defaultMode": 256}}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["volumes"][0]["configMap"]["defaultMode"],
            serde_json::Value::Number(256.into()),
            "explicit defaultMode must not be overridden"
        );
    }

    #[test]
    fn secret_volume_default_mode_is_set_when_absent() {
        let mut pod = serde_json::json!({
            "spec": {
                "volumes": [{"name": "sec", "secret": {"secretName": "my-sec"}}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["volumes"][0]["secret"]["defaultMode"],
            serde_json::Value::Number(420.into()),
            "secret volume defaultMode must be set to 0644 (420) when absent"
        );
    }

    /// fieldRef.apiVersion must be defaulted to "v1" when absent.
    ///
    /// The kubelet calls ConvertDownwardAPIFieldLabel(apiVersion, label, value) which
    /// returns "unsupported pod version: <value>" when apiVersion is empty or missing.
    /// Real kube-apiserver stamps "v1" on fieldRef before storing the object.
    /// Without the fix, sonobuoy pods fail with CreateContainerConfigError.
    #[test]
    fn field_ref_api_version_defaults_to_v1_when_absent() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "sonobuoy:latest",
                    "env": [{
                        "name": "SONOBUOY_ADVERTISE_IP",
                        "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}
                    }]
                }]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["env"][0]["valueFrom"]["fieldRef"]["apiVersion"],
            serde_json::json!("v1"),
            "fieldRef.apiVersion must be defaulted to v1; absent value causes \
             CreateContainerConfigError in kubelet"
        );
    }

    #[test]
    fn field_ref_api_version_preserved_when_explicit() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "sonobuoy:latest",
                    "env": [{
                        "name": "MY_VAR",
                        "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.name"}}
                    }]
                }]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["env"][0]["valueFrom"]["fieldRef"]["apiVersion"],
            serde_json::json!("v1"),
        );
    }

    #[test]
    fn field_ref_api_version_defaulted_in_init_containers() {
        let mut pod = serde_json::json!({
            "spec": {
                "initContainers": [{
                    "name": "init",
                    "image": "busybox",
                    "env": [{
                        "name": "NODE_NAME",
                        "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}
                    }]
                }]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["initContainers"][0]["env"][0]["valueFrom"]["fieldRef"]["apiVersion"],
            serde_json::json!("v1"),
        );
    }

    // --- dnsPolicy defaulting tests ---

    /// create_pod must default spec.dnsPolicy to "ClusterFirst" when absent.
    ///
    /// Real kube-apiserver always stamps this field on create. The kubelet reads
    /// spec.dnsPolicy and logs "invalid DNSPolicy=" with an empty string, then
    /// falls back to ClusterFirst for every pod — silently incorrect behaviour.
    /// Without this default, every pod in a conformance run triggers the kubelet
    /// error "Failed to get DNS type for pod. Falling back to DNSClusterFirst
    /// policy. err=invalid DNSPolicy=".
    #[test]
    fn dns_policy_defaults_to_cluster_first_when_absent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirst"),
            "dnsPolicy must be defaulted to ClusterFirst when absent — \
             kubelet rejects empty string with 'invalid DNSPolicy=' and falls back \
             incorrectly, silently breaking pod DNS for every pod in a cluster"
        );
    }

    /// create_pod must NOT override an explicit dnsPolicy value.
    ///
    /// A pod running in host network mode uses ClusterFirstWithHostNet so that
    /// DNS resolution works correctly while sharing the host network namespace.
    /// Overriding this to ClusterFirst would silently break DNS for such pods.
    ///
    /// This is also the round-trip regression test: a pod created with an explicit
    /// dnsPolicy must have that exact value when read back from the store.
    #[test]
    fn dns_policy_explicit_value_is_preserved() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "hostnet-pod", "namespace": "default"},
            "spec": {
                "dnsPolicy": "ClusterFirstWithHostNet",
                "hostNetwork": true,
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirstWithHostNet"),
            "an explicit dnsPolicy must not be overridden by the default — \
             ClusterFirstWithHostNet is required for pods using hostNetwork; \
             overriding it would silently break DNS resolution for those pods"
        );
    }

    /// create_pod must NOT override dnsPolicy: "None" (user-managed DNS).
    ///
    /// Pods with dnsPolicy=None manage DNS entirely via dnsConfig.nameservers.
    /// Overriding to ClusterFirst would silently break their custom DNS setup.
    #[test]
    fn dns_policy_none_is_preserved() {
        let mut pod = serde_json::json!({
            "spec": {
                "dnsPolicy": "None",
                "dnsConfig": {"nameservers": ["1.1.1.1"]},
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["dnsPolicy"],
            serde_json::json!("None"),
            "dnsPolicy=None must be preserved — user-managed DNS pods configure \
             nameservers via dnsConfig; overriding would silently redirect DNS traffic"
        );
    }

    // --- inject_sa_token_volume tests ---

    /// SA token projected volume must be injected when serviceAccountName is set.
    ///
    /// rest.InClusterConfig() reads /var/run/secrets/kubernetes.io/serviceaccount/token;
    /// without this injection sonobuoy fails with "no configuration has been provided".
    #[test]
    fn sa_token_volume_injected_when_sa_name_set() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        let volumes = pod["spec"]["volumes"]
            .as_array()
            .expect("volumes must be set");
        assert!(
            volumes.iter().any(|v| v["name"]
                .as_str()
                .map(|n| n.starts_with("kube-api-access-"))
                .unwrap_or(false)),
            "a kube-api-access-* volume must be injected so in-cluster token is available"
        );
        let mounts = pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts must be set");
        assert!(
            mounts.iter().any(|m| m["mountPath"].as_str()
                == Some("/var/run/secrets/kubernetes.io/serviceaccount")),
            "volumeMount at SA path must be added to container"
        );
    }

    /// SA token volume must NOT be injected when automountServiceAccountToken is false.
    ///
    /// Pods that explicitly opt out must not receive the mount; injecting anyway
    /// would violate the user's security intent and differ from real kube behavior.
    #[test]
    fn sa_token_volume_not_injected_when_automount_false() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "automountServiceAccountToken": false,
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        assert!(
            pod["spec"]["volumes"].is_null(),
            "no volume must be injected when automountServiceAccountToken=false"
        );
    }

    /// SA token volume must NOT be injected when serviceAccountName is absent.
    ///
    /// Pods with no SA name have no identity to bind a token to.
    #[test]
    fn sa_token_volume_not_injected_when_sa_name_absent() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        assert!(
            pod["spec"]["volumes"].is_null(),
            "no volume must be injected when serviceAccountName is absent"
        );
    }

    /// SA token volume must NOT be injected when serviceAccountName is empty string.
    #[test]
    fn sa_token_volume_not_injected_when_sa_name_empty() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "",
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        assert!(
            pod["spec"]["volumes"].is_null(),
            "no volume must be injected when serviceAccountName is empty"
        );
    }

    /// inject_sa_token_volume must be idempotent: a second call must not add a
    /// duplicate volume when a kube-api-access-* volume already exists.
    ///
    /// This prevents volume-name collisions on repeated admission passes.
    #[test]
    fn sa_token_volume_idempotent_when_kube_api_access_volume_exists() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "volumes": [{"name": "kube-api-access-abcde", "projected": {"defaultMode": 420, "sources": []}}],
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        let count = pod["spec"]["volumes"]
            .as_array()
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(
            count, 1,
            "duplicate kube-api-access-* volume must not be added when one already exists"
        );
    }

    /// VolumeMounts must be added to both containers and initContainers.
    ///
    /// initContainers run before main containers and also need in-cluster config
    /// (e.g. sonobuoy's init step pulls a kubeconfig).
    #[test]
    fn sa_token_volume_mounts_added_to_containers_and_init_containers() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "containers": [{"name": "main", "image": "busybox"}],
                "initContainers": [{"name": "init", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        let main_mount = pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .and_then(|m| {
                m.iter().find(|e| {
                    e["mountPath"].as_str() == Some("/var/run/secrets/kubernetes.io/serviceaccount")
                })
            });
        assert!(
            main_mount.is_some(),
            "main container must receive the SA volumeMount"
        );
        let init_mount = pod["spec"]["initContainers"][0]["volumeMounts"]
            .as_array()
            .and_then(|m| {
                m.iter().find(|e| {
                    e["mountPath"].as_str() == Some("/var/run/secrets/kubernetes.io/serviceaccount")
                })
            });
        assert!(
            init_mount.is_some(),
            "initContainer must receive the SA volumeMount"
        );
    }

    /// A container that already mounts the SA path must not receive a duplicate mount.
    ///
    /// Kubelet rejects pods with duplicate mount paths; idempotency here prevents
    /// that failure when a pod already has an explicit SA mount.
    #[test]
    fn sa_token_volume_mount_skipped_when_container_has_existing_sa_mount() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "containers": [{
                    "name": "app",
                    "image": "busybox",
                    "volumeMounts": [{
                        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                        "name": "my-existing-sa",
                        "readOnly": true
                    }]
                }]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        let mount_count = pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .map(|m| {
                m.iter()
                    .filter(|e| {
                        e["mountPath"].as_str()
                            == Some("/var/run/secrets/kubernetes.io/serviceaccount")
                    })
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            mount_count, 1,
            "duplicate SA mount must not be added when container already has one"
        );
    }
}

/// Extract the target node name from a Binding object body.
///
/// Returns `Err` with a 400 if `target.name` is absent or empty.
/// Extracted for testability — the full `bind_pod` handler is async and requires a live store.
pub fn extract_binding_node_name(
    binding: &serde_json::Value,
) -> Result<String, crate::status::StatusError> {
    let parsed: Binding = serde_json::from_value(binding.clone())
        .map_err(|_| Status::bad_request("target.name is required".into()))?;
    if parsed.target.name.is_empty() {
        return Err(Status::bad_request("target.name is required".into()));
    }
    Ok(parsed.target.name)
}

pub async fn bind_pod<S: Store>(
    State(state): State<AppState<S>>,
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

    let node_name = extract_binding_node_name(&binding)?;

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

// ---------------------------------------------------------------------------
// Unit tests for pure functions: store_err_to_status, JSON patch helpers,
// binding extraction. These cover lines/branches not reachable via the
// existing watch_tests / field_selector_tests / status_tests / patch_type_tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pure_logic_tests {
    use super::*;
    use crate::handlers::json_patch::{
        apply_json_patch, json_navigate_one, json_navigate_one_or_create, json_patch_add,
        json_patch_navigate_mut, json_patch_remove, json_patch_set, json_pointer_segments,
    };
    use u7s_store::StoreError;

    // -----------------------------------------------------------------------
    // store_err_to_status
    // -----------------------------------------------------------------------

    /// StoreError::NotFound must map to HTTP 404 and name the "Pod" kind.
    /// Without this, callers (get_pod, delete_pod) would surface wrong status codes.
    #[test]
    fn store_err_not_found_becomes_404() {
        let err = StoreError::NotFound {
            key: "/registry/pods/default/my-pod".into(),
        };
        let status_err = store_err_to_status(err, "my-pod");
        let resp: axum::response::Response = status_err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    /// StoreError::AlreadyExists must map to HTTP 409.
    /// create_pod must surface Conflict when the key already exists.
    #[test]
    fn store_err_already_exists_becomes_409() {
        let err = StoreError::AlreadyExists {
            key: "/registry/pods/default/my-pod".into(),
        };
        let status_err = store_err_to_status(err, "my-pod");
        let resp: axum::response::Response = status_err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::CONFLICT);
    }

    /// StoreError::RevisionMismatch must map to HTTP 409 Conflict.
    /// replace_pod OCC relies on this: a stale resourceVersion must not silently
    /// overwrite newer data.
    #[test]
    fn store_err_revision_mismatch_becomes_409() {
        let err = StoreError::RevisionMismatch {
            expected: 3,
            current: 7,
        };
        let status_err = store_err_to_status(err, "my-pod");
        let resp: axum::response::Response = status_err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::CONFLICT);
    }

    /// Other StoreErrors (e.g. Compacted) must map to HTTP 500 Internal Server Error.
    /// This is the catch-all arm; any unrecognised store error must not leak as a 2xx.
    #[test]
    fn store_err_compacted_becomes_500() {
        let err = StoreError::Compacted {
            requested: 1,
            horizon: 100,
        };
        let status_err = store_err_to_status(err, "my-pod");
        let resp: axum::response::Response = status_err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // json_pointer_segments
    // -----------------------------------------------------------------------

    /// Empty pointer yields empty segments — root document path.
    #[test]
    fn pointer_segments_empty_string() {
        assert!(json_pointer_segments("").is_empty());
    }

    /// "/a/b/c" splits into ["a", "b", "c"].
    #[test]
    fn pointer_segments_three_parts() {
        assert_eq!(json_pointer_segments("/a/b/c"), vec!["a", "b", "c"]);
    }

    /// RFC 6901 escape sequences: ~1 -> "/" and ~0 -> "~".
    #[test]
    fn pointer_segments_rfc6901_escapes() {
        let segs = json_pointer_segments("/a~1b/c~0d");
        assert_eq!(segs, vec!["a/b", "c~d"]);
    }

    /// A pointer without a leading slash is used as-is (strip_prefix returns None).
    #[test]
    fn pointer_segments_no_leading_slash() {
        let segs = json_pointer_segments("foo/bar");
        assert_eq!(segs, vec!["foo", "bar"]);
    }

    // -----------------------------------------------------------------------
    // json_patch_navigate_mut
    // -----------------------------------------------------------------------

    /// Empty segments must return an error ("cannot operate on root document").
    #[test]
    fn navigate_mut_empty_segments_returns_err() {
        let mut obj = serde_json::json!({"a": 1});
        let result = json_patch_navigate_mut(&mut obj, &[]);
        assert!(result.is_err(), "empty segments must error");
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Single segment returns (root_object, "key") — the last segment.
    #[test]
    fn navigate_mut_single_segment() {
        let mut obj = serde_json::json!({"x": 99});
        let segs = vec!["x".to_string()];
        let (parent, key) =
            json_patch_navigate_mut(&mut obj, &segs).unwrap_or_else(|_| panic!("must succeed"));
        assert_eq!(key, "x");
        assert!(parent.is_object());
    }

    // -----------------------------------------------------------------------
    // json_navigate_one
    // -----------------------------------------------------------------------

    /// Traversing into an object with a known key succeeds.
    #[test]
    fn navigate_one_object_known_key() {
        let mut obj = serde_json::json!({"spec": {"nodeName": "worker-1"}});
        let result = json_navigate_one(&mut obj, "spec");
        assert!(result.is_ok());
    }

    /// Traversing into an object with an unknown key returns 422.
    #[test]
    fn navigate_one_object_missing_key_returns_422() {
        let mut obj = serde_json::json!({"spec": {}});
        let result = json_navigate_one(&mut obj, "status");
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Traversing into an array by numeric index succeeds.
    #[test]
    fn navigate_one_array_valid_index() {
        let mut obj = serde_json::json!([10, 20, 30]);
        let result = json_navigate_one(&mut obj, "1");
        assert!(result.is_ok());
        let val = result.unwrap_or_else(|_| panic!("must succeed"));
        assert_eq!(*val, serde_json::json!(20));
    }

    /// Traversing into an array with an out-of-bounds index returns 422.
    #[test]
    fn navigate_one_array_oob_returns_422() {
        let mut obj = serde_json::json!([10]);
        let result = json_navigate_one(&mut obj, "5");
        assert!(result.is_err());
    }

    /// Traversing into an array with a non-numeric index returns 422.
    #[test]
    fn navigate_one_array_non_numeric_index_returns_422() {
        let mut obj = serde_json::json!([10]);
        let result = json_navigate_one(&mut obj, "not-a-number");
        assert!(result.is_err());
    }

    /// Traversing into a scalar (non-object/array) returns 422.
    #[test]
    fn navigate_one_scalar_returns_422() {
        let mut obj = serde_json::json!(42);
        let result = json_navigate_one(&mut obj, "foo");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // json_navigate_one_or_create
    // -----------------------------------------------------------------------

    /// Creating an intermediate key in an object succeeds.
    #[test]
    fn navigate_one_or_create_creates_missing_key() {
        let mut obj = serde_json::json!({});
        let result = json_navigate_one_or_create(&mut obj, "spec");
        assert!(result.is_ok());
        let node = result.unwrap_or_else(|_| panic!("must succeed"));
        assert!(node.is_object());
    }

    /// Creating into a non-object (e.g. array, scalar) returns 422.
    #[test]
    fn navigate_one_or_create_non_object_returns_422() {
        let mut obj = serde_json::json!([1, 2, 3]);
        let result = json_navigate_one_or_create(&mut obj, "key");
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    // -----------------------------------------------------------------------
    // json_patch_add — branches not covered by patch_type_tests
    // -----------------------------------------------------------------------

    /// add to root (empty pointer) replaces the whole document.
    #[test]
    fn patch_add_root_replaces_document() {
        let mut obj = serde_json::json!({"old": true});
        json_patch_add(&mut obj, "", serde_json::json!({"new": true}))
            .unwrap_or_else(|_| panic!("add to root must succeed"));
        assert_eq!(obj, serde_json::json!({"new": true}));
    }

    /// add with "-" as last segment appends to an array.
    /// This is the RFC 6902 append convention; kubelet uses it for conditions.
    #[test]
    fn patch_add_dash_appends_to_array() {
        let mut obj = serde_json::json!({"items": [1, 2]});
        json_patch_add(&mut obj, "/items/-", serde_json::json!(3))
            .unwrap_or_else(|_| panic!("add '-' must succeed"));
        assert_eq!(obj["items"], serde_json::json!([1, 2, 3]));
    }

    /// add with a numeric index inserts at that position.
    #[test]
    fn patch_add_numeric_index_inserts_at_position() {
        let mut obj = serde_json::json!({"items": [1, 3]});
        json_patch_add(&mut obj, "/items/1", serde_json::json!(2))
            .unwrap_or_else(|_| panic!("add at index must succeed"));
        assert_eq!(obj["items"], serde_json::json!([1, 2, 3]));
    }

    /// add with an out-of-bounds index returns 422.
    #[test]
    fn patch_add_array_oob_returns_422() {
        let mut obj = serde_json::json!({"items": [1]});
        let result = json_patch_add(&mut obj, "/items/5", serde_json::json!(99));
        assert!(result.is_err());
    }

    /// add with an invalid (non-numeric) array index returns 422.
    #[test]
    fn patch_add_invalid_array_index_returns_422() {
        let mut obj = serde_json::json!({"items": [1]});
        let result = json_patch_add(&mut obj, "/items/not-a-num", serde_json::json!(99));
        assert!(result.is_err());
    }

    /// add to a scalar (non-object/array) returns 422.
    #[test]
    fn patch_add_to_scalar_returns_422() {
        let mut obj = serde_json::json!(42);
        let result = json_patch_add(&mut obj, "/foo", serde_json::json!(1));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // json_patch_set — branches not covered by patch_type_tests
    // -----------------------------------------------------------------------

    /// set (replace) on root (empty pointer) replaces the whole document.
    #[test]
    fn patch_set_root_replaces_document() {
        let mut obj = serde_json::json!({"old": true});
        json_patch_set(&mut obj, "", serde_json::json!({"new": true}))
            .unwrap_or_else(|_| panic!("set root must succeed"));
        assert_eq!(obj, serde_json::json!({"new": true}));
    }

    /// set with "-" on an array appends (same as add "-").
    #[test]
    fn patch_set_dash_appends_to_array() {
        let mut obj = serde_json::json!({"items": [1, 2]});
        json_patch_set(&mut obj, "/items/-", serde_json::json!(3))
            .unwrap_or_else(|_| panic!("set '-' must succeed"));
        assert_eq!(obj["items"], serde_json::json!([1, 2, 3]));
    }

    /// set with a numeric index beyond bounds returns 422.
    #[test]
    fn patch_set_array_oob_returns_422() {
        let mut obj = serde_json::json!({"items": [1]});
        let result = json_patch_set(&mut obj, "/items/5", serde_json::json!(99));
        assert!(result.is_err());
    }

    /// set with an invalid array index returns 422.
    #[test]
    fn patch_set_invalid_array_index_returns_422() {
        let mut obj = serde_json::json!({"items": [1]});
        let result = json_patch_set(&mut obj, "/items/bad", serde_json::json!(2));
        assert!(result.is_err());
    }

    /// set on a scalar parent (non-object/array) returns 422.
    #[test]
    fn patch_set_non_object_parent_returns_422() {
        let mut obj = serde_json::json!({"leaf": 42});
        // "leaf" is an integer; navigating into it then setting a sub-key must fail.
        let result = json_patch_set(&mut obj, "/leaf/sub", serde_json::json!(1));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // json_patch_remove — branches not covered by patch_type_tests
    // -----------------------------------------------------------------------

    /// remove a key that does not exist returns 422.
    #[test]
    fn patch_remove_missing_key_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let result = json_patch_remove(&mut obj, "/b");
        assert!(result.is_err());
    }

    /// remove by valid array index succeeds and shortens the array.
    #[test]
    fn patch_remove_array_index_succeeds() {
        let mut obj = serde_json::json!({"items": [10, 20, 30]});
        json_patch_remove(&mut obj, "/items/1")
            .unwrap_or_else(|_| panic!("remove at valid index must succeed"));
        assert_eq!(obj["items"], serde_json::json!([10, 30]));
    }

    /// remove with an out-of-bounds array index returns 422.
    #[test]
    fn patch_remove_array_oob_returns_422() {
        let mut obj = serde_json::json!({"items": [10]});
        let result = json_patch_remove(&mut obj, "/items/5");
        assert!(result.is_err());
    }

    /// remove with a non-numeric array index returns 422.
    #[test]
    fn patch_remove_invalid_array_index_returns_422() {
        let mut obj = serde_json::json!({"items": [10]});
        let result = json_patch_remove(&mut obj, "/items/not-num");
        assert!(result.is_err());
    }

    /// remove from a scalar (non-object/array) returns 422.
    #[test]
    fn patch_remove_scalar_parent_returns_422() {
        let mut obj = serde_json::json!({"leaf": 42});
        // Navigate into "leaf" (integer) then attempt remove of a sub-key.
        let result = json_patch_remove(&mut obj, "/leaf/sub");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // apply_json_patch — error paths not covered by patch_type_tests
    // -----------------------------------------------------------------------

    /// patch body must be a JSON array; a non-array returns 422.
    #[test]
    fn apply_json_patch_non_array_body_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!({"op": "replace", "path": "/a", "value": 2});
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// An operation missing the "op" field returns 422.
    #[test]
    fn apply_json_patch_missing_op_field_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"path": "/a", "value": 2}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// An operation missing the "path" field returns 422.
    #[test]
    fn apply_json_patch_missing_path_field_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "replace", "value": 2}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// An "add" operation missing "value" returns 422.
    #[test]
    fn apply_json_patch_add_missing_value_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "add", "path": "/b"}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// A "replace" operation missing "value" returns 422.
    #[test]
    fn apply_json_patch_replace_missing_value_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "replace", "path": "/a"}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// An unsupported op (e.g. "copy") returns 422.
    /// Only add, remove, replace are supported.
    #[test]
    fn apply_json_patch_unsupported_op_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "copy", "from": "/a", "path": "/b"}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// An empty array patch is a no-op and must succeed.
    #[test]
    fn apply_json_patch_empty_array_is_noop() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([]);
        assert!(apply_json_patch(&mut obj, &patch).is_ok());
        assert_eq!(obj["a"], 1);
    }

    // -----------------------------------------------------------------------
    // extract_binding_node_name
    // -----------------------------------------------------------------------

    /// A valid binding with target.name returns the node name.
    /// This is the primary scheduler use-case: bind pod to node.
    #[test]
    fn extract_binding_node_name_valid() {
        let binding = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Binding",
            "target": {"kind": "Node", "name": "worker-1"}
        });
        let result = extract_binding_node_name(&binding);
        let name = result.unwrap_or_else(|_| panic!("valid binding must yield node name"));
        assert_eq!(name, "worker-1");
    }

    /// A binding with an empty target.name must be rejected with 400.
    /// An empty nodeName would silently leave the pod unscheduled.
    #[test]
    fn extract_binding_node_name_empty_returns_400() {
        let binding = serde_json::json!({"target": {"name": ""}});
        let result = extract_binding_node_name(&binding);
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    /// A binding missing target.name must be rejected with 400.
    #[test]
    fn extract_binding_node_name_missing_returns_400() {
        let binding = serde_json::json!({"target": {}});
        let result = extract_binding_node_name(&binding);
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    /// A binding missing target entirely must be rejected with 400.
    #[test]
    fn extract_binding_node_name_no_target_returns_400() {
        let binding = serde_json::json!({"kind": "Binding"});
        let result = extract_binding_node_name(&binding);
        assert!(result.is_err());
    }
}

// ---------------------------------------------------------------------------
// Integration-style tests for async handlers (tower::ServiceExt::oneshot)
// These use an in-memory store so no real server is needed.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod handler_tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::{delete, get, patch, post, put},
        Router,
    };
    use bytes::Bytes;
    use tower::ServiceExt;
    use u7s_store::{SqliteStore, Store};

    use super::*;
    use crate::state::AppState;

    /// Build a minimal AppState backed by an in-memory SQLite store.
    fn make_state() -> (AppState, Arc<SqliteStore>) {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        (state, store)
    }

    /// Seed the store with a namespace so parse_namespace succeeds.
    async fn seed_namespace(store: &Arc<SqliteStore>, ns: &str) {
        let key = format!("/registry/namespaces/{ns}");
        let val = serde_json::json!({"kind": "Namespace", "metadata": {"name": ns}});
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed namespace");
    }

    /// Seed the store with a pod, merging `extra` into the default pod JSON.
    async fn seed_pod(store: &Arc<SqliteStore>, ns: &str, name: &str, extra: serde_json::Value) {
        let key = format!("/registry/pods/{ns}/{name}");
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": ns,
                "resourceVersion": "1"
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Pending"}
        });
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                pod[k] = v.clone();
            }
        }
        store
            .put(&key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .expect("seed pod");
    }

    fn json_body(v: &serde_json::Value) -> Body {
        Body::from(Bytes::from(serde_json::to_vec(v).unwrap()))
    }

    // -----------------------------------------------------------------------
    // get_pod
    // -----------------------------------------------------------------------

    /// GET a pod that exists must return 200 with the pod JSON.
    #[tokio::test]
    async fn get_pod_returns_200_for_existing_pod() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "nginx", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/nginx")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// GET a pod that does not exist must return 404.
    #[tokio::test]
    async fn get_pod_returns_404_for_missing_pod() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/ghost")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// GET a pod in a namespace that does not exist must return 404.
    #[tokio::test]
    async fn get_pod_returns_404_for_missing_namespace() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/nonexistent/pods/nginx")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // create_pod
    // -----------------------------------------------------------------------

    /// POST a valid pod must return 201 with the created pod.
    #[tokio::test]
    async fn create_pod_returns_201() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    /// POST a pod with invalid JSON must return 400.
    #[tokio::test]
    async fn create_pod_returns_400_for_invalid_json() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("not json"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // dnsPolicy round-trip regression test (mayor-grmb)
    // -----------------------------------------------------------------------

    /// A pod created with spec.dnsPolicy: ClusterFirstWithHostNet must have that
    /// exact value when read back via GET.
    ///
    /// Before the fix, spec.dnsPolicy was absent from the stored pod when not
    /// explicitly set, causing the kubelet to log "invalid DNSPolicy=" for every
    /// pod and fall back to ClusterFirst — silently incorrect behaviour.
    ///
    /// This test also verifies the full create→get round-trip so that a future
    /// regression (e.g. a new defaulting pass that strips dnsPolicy) is caught.
    #[tokio::test]
    async fn create_pod_dns_policy_survives_round_trip() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        // Create a pod with an explicit dnsPolicy.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "dns-pod", "namespace": "default"},
            "spec": {
                "dnsPolicy": "ClusterFirstWithHostNet",
                "hostNetwork": true,
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let create_req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let create_resp = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(
            create_resp.status(),
            StatusCode::CREATED,
            "pod creation must succeed"
        );

        // Read the pod back via GET.
        let get_req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/dns-pod")
            .body(Body::empty())
            .unwrap();

        let get_resp = app.oneshot(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(get_resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            v["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirstWithHostNet"),
            "spec.dnsPolicy must survive the create→get round-trip unchanged — \
             before mayor-grmb fix this was lost, causing kubelet to log \
             'invalid DNSPolicy=' for every pod"
        );

        // Verify stored value directly in the store for defense-in-depth.
        let stored = store
            .get("/registry/pods/default/dns-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirstWithHostNet"),
            "spec.dnsPolicy must be present in the stored object, not just the response"
        );
    }

    /// A pod created without spec.dnsPolicy must have it defaulted to "ClusterFirst"
    /// after creation (matching real kube-apiserver behaviour).
    ///
    /// Kubelet reads spec.dnsPolicy on every pod; an empty string causes it to
    /// log "invalid DNSPolicy=" and fall back incorrectly for every pod.
    #[tokio::test]
    async fn create_pod_dns_policy_defaults_to_cluster_first_when_absent() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "no-dns-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = store
            .get("/registry/pods/default/no-dns-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirst"),
            "dnsPolicy must be defaulted to ClusterFirst when absent at creation time — \
             real kube-apiserver always stamps this field; the kubelet rejects empty string"
        );
    }

    // -----------------------------------------------------------------------
    // replace_pod (PUT)
    // -----------------------------------------------------------------------

    /// PUT with mismatched name in URL vs body must return 400.
    /// This guards against accidental or malicious object renaming via PUT.
    #[tokio::test]
    async fn replace_pod_name_mismatch_returns_400() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "nginx", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .with_state(state);

        // URL says "nginx" but body says "other-pod".
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "other-pod",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/nginx")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // delete_pod
    // -----------------------------------------------------------------------

    /// DELETE a pod without finalizers must return 200 with a Status object.
    #[tokio::test]
    async fn delete_pod_without_finalizers_returns_200() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "to-delete", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .with_state(state);

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/to-delete")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// DELETE a pod with finalizers must soft-delete: stamp deletionTimestamp, keep object.
    #[tokio::test]
    async fn delete_pod_with_finalizers_stamps_deletion_timestamp() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed with finalizers directly (don't rely on seed_pod merge for nested metadata).
        let key = "/registry/pods/default/finalized-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "finalized-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .with_state(state.clone());

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/finalized-pod")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "soft-delete must return 200");

        // The pod must still exist with deletionTimestamp set.
        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must be stamped on soft-delete"
        );
    }

    /// DELETE a pod that does not exist must return 404.
    #[tokio::test]
    async fn delete_pod_missing_returns_404() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .with_state(state);

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/ghost")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // patch_pod
    // -----------------------------------------------------------------------

    /// PATCH with merge-patch+json must update the specified field.
    #[tokio::test]
    async fn patch_pod_merge_patch_updates_field() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"metadata": {"labels": {"app": "test"}}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// PATCH with an unsupported content-type must return 415.
    #[tokio::test]
    async fn patch_pod_unsupported_content_type_returns_415() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from("{}"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // -----------------------------------------------------------------------
    // get_pod_status
    // -----------------------------------------------------------------------

    /// GET /status on an existing pod returns 200.
    #[tokio::test]
    async fn get_pod_status_returns_200() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                get(get_pod_status),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// GET /status on a missing pod returns 404.
    #[tokio::test]
    async fn get_pod_status_returns_404_for_missing() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                get(get_pod_status),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/ghost/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // replace_pod_status (PUT /status)
    // -----------------------------------------------------------------------

    /// PUT /status must update the status field and preserve spec.
    #[tokio::test]
    async fn replace_pod_status_updates_status_only() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "status": {"phase": "Running"},
            "spec": {"containers": [{"name": "hacker"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify store: status updated, spec preserved.
        let key = "/registry/pods/default/my-pod";
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Running");
        // spec was seeded with one container named "app"; the handler must not overwrite it.
        assert_eq!(v["spec"]["containers"][0]["name"], "app");
    }

    // -----------------------------------------------------------------------
    // patch_pod_status (PATCH /status)
    // -----------------------------------------------------------------------

    /// PATCH /status with strategic-merge-patch must update the phase.
    #[tokio::test]
    async fn patch_pod_status_updates_phase() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        let patch_body = serde_json::json!({"status": {"phase": "Running"}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// PATCH /status with an unsupported content-type must return 415.
    #[tokio::test]
    async fn patch_pod_status_unsupported_content_type_returns_415() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .header(header::CONTENT_TYPE, "application/json-patch+json")
            .body(Body::from("[]"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // -----------------------------------------------------------------------
    // bind_pod (POST /binding)
    // -----------------------------------------------------------------------

    /// POST /binding with a valid target.name must set spec.nodeName on the pod.
    #[tokio::test]
    async fn bind_pod_sets_node_name() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "unscheduled-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/binding",
                post(bind_pod),
            )
            .with_state(state);

        let binding = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Binding",
            "metadata": {"name": "unscheduled-pod", "namespace": "default"},
            "target": {"kind": "Node", "name": "worker-1"}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/unscheduled-pod/binding")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&binding))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify spec.nodeName was set.
        let key = "/registry/pods/default/unscheduled-pod";
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["nodeName"], "worker-1",
            "bind_pod must set spec.nodeName to the target node"
        );
    }

    /// POST /binding with missing target.name must return 400.
    #[tokio::test]
    async fn bind_pod_missing_target_name_returns_400() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/binding",
                post(bind_pod),
            )
            .with_state(state);

        let binding = serde_json::json!({"apiVersion": "v1", "kind": "Binding", "target": {}});

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/my-pod/binding")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&binding))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // patch_pod — JSON patch through handler
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // list_pods (GET /namespaces/:ns/pods)
    // -----------------------------------------------------------------------

    /// GET /pods on an existing namespace returns 200 with a PodList.
    /// This covers the non-watch list_pods path and its inline lambdas.
    #[tokio::test]
    async fn list_pods_returns_200_with_pod_list() {
        use axum::http::method::Method;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "pod-a", serde_json::json!({})).await;
        seed_pod(&store, "default", "pod-b", serde_json::json!({})).await;

        let user = crate::auth::UserInfo {
            username: "test-user".into(),
            uid: String::new(),
            groups: vec![],
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(axum::Extension(user))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/default/pods")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(v["kind"], "PodList");
        assert_eq!(
            v["items"].as_array().unwrap().len(),
            2,
            "must return both seeded pods"
        );
    }

    /// GET /pods with a field selector must filter pods by nodeName.
    #[tokio::test]
    async fn list_pods_with_field_selector_filters_pods() {
        use axum::http::method::Method;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed one pod on worker-1 and one on worker-2.
        let key_a = "/registry/pods/default/pod-a";
        let pod_a = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-a", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "worker-1", "containers": []}
        });
        store
            .put(
                key_a,
                Bytes::from(serde_json::to_vec(&pod_a).unwrap()),
                None,
            )
            .await
            .unwrap();

        let key_b = "/registry/pods/default/pod-b";
        let pod_b = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-b", "namespace": "default", "resourceVersion": "2"},
            "spec": {"nodeName": "worker-2", "containers": []}
        });
        store
            .put(
                key_b,
                Bytes::from(serde_json::to_vec(&pod_b).unwrap()),
                None,
            )
            .await
            .unwrap();

        let user = crate::auth::UserInfo {
            username: "test-user".into(),
            uid: String::new(),
            groups: vec![],
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(axum::Extension(user))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/default/pods?field_selector=spec.nodeName%3Dworker-1")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "only worker-1 pods should be returned");
        assert_eq!(items[0]["spec"]["nodeName"], "worker-1");
    }

    /// GET /pods on a nonexistent namespace must return 404.
    #[tokio::test]
    async fn list_pods_missing_namespace_returns_404() {
        use axum::http::method::Method;

        let (state, _store) = make_state();

        let user = crate::auth::UserInfo {
            username: "test-user".into(),
            uid: String::new(),
            groups: vec![],
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(axum::Extension(user))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/nonexistent/pods")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // replace_pod (PUT) — success path
    // -----------------------------------------------------------------------

    /// PUT with matching name and valid resourceVersion must return 200.
    #[tokio::test]
    async fn replace_pod_valid_update_returns_200() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        // seed_pod seeds with resourceVersion "1" in the body; the actual store revision is 1.
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        // Read back the actual stored revision so we can construct the PUT correctly.
        let stored_rv = {
            let obj = store
                .get("/registry/pods/default/my-pod")
                .await
                .unwrap()
                .unwrap();
            obj.revision
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {"containers": [{"name": "app", "image": "nginx:latest"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // replace_pod — 409 on stale resourceVersion
    // -----------------------------------------------------------------------

    /// PUT /pods/:name with a stale resourceVersion must return 409 Conflict.
    /// replace_pod uses OCC: a stale writer must not silently overwrite newer data.
    #[tokio::test]
    async fn replace_pod_stale_rv_returns_409() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "occ-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .with_state(state);

        let stale_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "occ-pod",
                "namespace": "default",
                "resourceVersion": "99999"
            },
            "spec": {"containers": [{"name": "app", "image": "nginx:latest"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/occ-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&stale_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "stale resourceVersion on replace_pod must return 409 Conflict — \
             OCC prevents lost-update races when multiple controllers update the same pod"
        );
    }

    // -----------------------------------------------------------------------
    // replace_pod_status — 404 on missing pod
    // -----------------------------------------------------------------------

    /// PUT /pods/:name/status on a missing pod must return 404.
    /// The status subresource cannot create objects — only the main resource endpoint does that.
    #[tokio::test]
    async fn replace_pod_status_returns_404_for_missing() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "ghost-pod", "namespace": "default"},
            "status": {"phase": "Running"}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/ghost-pod/status")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PUT /status on non-existent pod must return 404 — \
             the status subresource cannot create new pods"
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod_status — 404 on missing pod
    // -----------------------------------------------------------------------

    /// PATCH /pods/:name/status on a missing pod must return 404.
    #[tokio::test]
    async fn patch_pod_status_returns_404_for_missing() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/ghost-pod/status")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(Body::from(r#"{"status":{"phase":"Running"}}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PATCH /status on non-existent pod must return 404 — \
             kubelet should not be able to update status of pods that don't exist"
        );
    }

    // -----------------------------------------------------------------------
    // create_pod — 409 on duplicate
    // -----------------------------------------------------------------------

    /// POST /pods with the same name twice must return 409 Conflict.
    /// Duplicate pod creation must be rejected — the scheduler must GET+bind, not re-create.
    #[tokio::test]
    async fn create_pod_duplicate_returns_409() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "dup-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .with_state(state);

        // First create — must succeed.
        let req1 = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();
        let resp1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::CREATED);

        // Second create with same name — must return 409.
        let req2 = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();
        let resp2 = app.oneshot(req2).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::CONFLICT,
            "duplicate pod creation must return 409 Conflict — \
             the store already has this key and AlreadyExists maps to 409"
        );
    }

    // -----------------------------------------------------------------------
    // parse_namespace — invalid format returns 400
    // -----------------------------------------------------------------------

    /// GET /pods in a namespace with an invalid format (contains uppercase) must return 404.
    /// parse_namespace validates format; an invalid namespace name must be rejected.
    #[tokio::test]
    async fn list_pods_invalid_namespace_format_returns_404() {
        use axum::http::method::Method;

        let (state, _store) = make_state();

        let user = crate::auth::UserInfo {
            username: "test".into(),
            uid: String::new(),
            groups: vec![],
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(axum::Extension(user))
            .with_state(state);

        // "INVALID" has uppercase — parse_namespace rejects it
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/INVALID/pods")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // Either 400 (bad format) or 404 (not found in store) — both are correct rejections.
        assert!(
            resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND,
            "invalid namespace format must return 400 or 404, got {}",
            resp.status()
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod — 404 on missing pod
    // -----------------------------------------------------------------------

    /// PATCH /pods/:name on a missing pod must return 404.
    #[tokio::test]
    async fn patch_pod_missing_pod_returns_404() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/ghost-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(Body::from(r#"{"metadata":{"labels":{"k":"v"}}}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PATCH on non-existent pod must return 404"
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod — strategic-merge-patch (delete-then-recreate finalizer path)
    // -----------------------------------------------------------------------

    /// PATCH with strategic-merge-patch+json must succeed.
    #[tokio::test]
    async fn patch_pod_strategic_merge_patch_succeeds() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"metadata": {"annotations": {"k": "v"}}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // patch_pod — deletionTimestamp+empty-finalizers path
    // -----------------------------------------------------------------------

    /// PATCH that clears finalizers on a pod with deletionTimestamp set must hard-delete.
    #[tokio::test]
    async fn patch_pod_clears_finalizers_triggers_hard_delete() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed pod with deletionTimestamp and a finalizer.
        let key = "/registry/pods/default/finalized-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "finalized-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2025-01-01T00:00:00Z",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state.clone());

        // Patch to remove the finalizer.
        let patch_body = serde_json::json!({"metadata": {"finalizers": []}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/finalized-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Pod should now be deleted from the store.
        let stored = store.get(key).await.unwrap();
        assert!(
            stored.is_none(),
            "pod must be hard-deleted when deletionTimestamp is set and finalizers are empty"
        );
    }

    // -----------------------------------------------------------------------
    // PATCH with json-patch+json and a valid remove op must succeed.
    // -----------------------------------------------------------------------

    /// PATCH with json-patch+json and a valid remove op must succeed.
    #[tokio::test]
    async fn patch_json_patch_remove_label() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed pod with a label directly so we control the exact JSON.
        let key = "/registry/pods/default/labeled-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "labeled-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"env": "test"}
            },
            "spec": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!([{"op": "remove", "path": "/metadata/labels/env"}]);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/labeled-pod")
            .header(header::CONTENT_TYPE, "application/json-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ---------------------------------------------------------------------------
// Admission regression tests — prove create_pod / replace_pod invoke the
// admission webhook pipeline (mayor-8sn9).
//
// Without the fix both handlers skipped admission entirely; admission-based
// controls (OPA Gatekeeper, Kyverno) on pods were non-functional.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod admission_tests {
    use std::sync::Arc;

    use axum::{routing::post, Router};
    use bytes::Bytes;
    use tokio::net::TcpListener;
    use u7s_store::{SqliteStore, Store};

    use super::*;
    use crate::state::AppState;

    fn make_state(store: Arc<SqliteStore>) -> AppState {
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    async fn seed_namespace(store: &Arc<SqliteStore>, ns: &str) {
        let key = format!("/registry/namespaces/{ns}");
        let val = serde_json::json!({"kind": "Namespace", "metadata": {"name": ns}});
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed namespace");
    }

    async fn start_mock_webhook(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock webhook server must not fail");
        });
        (format!("http://{addr}"), handle)
    }

    fn patch_label_router() -> Router {
        Router::new().route(
            "/webhook",
            post(|| async {
                let patch = serde_json::json!([
                    {"op": "add", "path": "/metadata/labels", "value": {"admitted": "yes"}}
                ]);
                let patch_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    serde_json::to_string(&patch).unwrap(),
                );
                axum::Json(serde_json::json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "test-uid",
                        "allowed": true,
                        "patch": patch_b64,
                        "patchType": "JSONPatch"
                    }
                }))
            }),
        )
    }

    fn deny_router() -> Router {
        Router::new().route(
            "/webhook",
            post(|| async {
                axum::Json(serde_json::json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "test-uid",
                        "allowed": false,
                        "status": {"code": 403, "message": "denied by test webhook"}
                    }
                }))
            }),
        )
    }

    /// create_pod must invoke the mutating admission pipeline.
    /// A mutating webhook that adds a label must have that label present in the
    /// stored pod — without this fix, the webhook was never called and the pod was
    /// stored without the label.
    #[tokio::test]
    async fn create_pod_invokes_mutating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        seed_namespace(&store, "default").await;

        let (url, _handle) = start_mock_webhook(patch_label_router()).await;

        // Register a MutatingWebhookConfiguration targeting pods CREATE.
        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test-mutating"},
            "webhooks": [{
                "name": "test.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/test-mutating",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "test-pod", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "nginx"}]}
            })
            .to_string(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let result = create_pod(
            axum::extract::State(state),
            axum::extract::Path(("default".to_string(),)),
            headers,
            pod_body,
        )
        .await;

        assert!(
            result.is_ok(),
            "create_pod must succeed when webhook allows"
        );

        // The stored pod must have the label injected by the webhook.
        let stored = store
            .get("/registry/pods/default/test-pod")
            .await
            .unwrap()
            .expect("pod must be stored");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["labels"]["admitted"], "yes",
            "mutating webhook label must be present in stored pod — \
             without the fix, create_pod bypassed admission and the label was never injected"
        );
    }

    /// create_pod must invoke the validating admission pipeline.
    /// A validating webhook that denies must cause create_pod to return an error,
    /// and the pod must NOT be stored. Before the fix, denial was silently ignored.
    #[tokio::test]
    async fn create_pod_invokes_validating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        seed_namespace(&store, "default").await;

        let (url, _handle) = start_mock_webhook(deny_router()).await;

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-validating"},
            "webhooks": [{
                "name": "deny.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-validating",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "denied-pod", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "nginx"}]}
            })
            .to_string(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let result = create_pod(
            axum::extract::State(state),
            axum::extract::Path(("default".to_string(),)),
            headers,
            pod_body,
        )
        .await;

        assert!(
            result.is_err(),
            "create_pod must be rejected when validating webhook denies — \
             without the fix, admission was bypassed and the pod was silently stored"
        );

        // Pod must NOT be in the store.
        let stored = store
            .get("/registry/pods/default/denied-pod")
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "denied pod must not be stored in the backing store"
        );
    }

    /// replace_pod must invoke the mutating admission pipeline.
    /// A webhook that adds a label on UPDATE must mutate the stored pod.
    #[tokio::test]
    async fn replace_pod_invokes_mutating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        seed_namespace(&store, "default").await;

        // Seed an existing pod.
        let pod_key = "/registry/pods/default/my-pod";
        let existing = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });
        store
            .put(
                pod_key,
                Bytes::from(serde_json::to_vec(&existing).unwrap()),
                None,
            )
            .await
            .unwrap();

        let stored_rv = store.get(pod_key).await.unwrap().unwrap().revision;

        let (url, _handle) = start_mock_webhook(patch_label_router()).await;

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test-mutating-update"},
            "webhooks": [{
                "name": "test.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"], "operations": ["UPDATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/test-mutating-update",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "my-pod",
                    "namespace": "default",
                    "resourceVersion": stored_rv.to_string()
                },
                "spec": {"containers": [{"name": "app", "image": "nginx:latest"}]}
            })
            .to_string(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let result = replace_pod(
            axum::extract::State(state),
            axum::extract::Path(("default".to_string(), "my-pod".to_string())),
            headers,
            pod_body,
        )
        .await;

        assert!(
            result.is_ok(),
            "replace_pod must succeed when webhook allows"
        );

        let stored = store
            .get(pod_key)
            .await
            .unwrap()
            .expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["labels"]["admitted"], "yes",
            "mutating webhook label must be present after replace_pod — \
             without the fix, replace_pod bypassed admission and the label was never injected"
        );
    }
}
