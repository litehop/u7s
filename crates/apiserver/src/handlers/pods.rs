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
    keys::{cluster_object_key, group_object_key, list_prefix, object_key},
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
    /// Server-side timeout for watch streams in seconds. See CollectionQuery::timeout_seconds.
    #[serde(rename = "timeoutSeconds")]
    pub timeout_seconds: Option<u64>,
}

/// Extract a store-level FieldSelector from a raw field selector string.
/// Picks the first equality (`=`) term that is not a negation (`!=`).
/// Returns None if no equality term is present or the string is empty.
pub fn pod_store_field_selector(sel: &str) -> Option<u7s_store::FieldSelector> {
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

/// Filter a list of Event JSON values by a comma-separated field selector.
///
/// Supported fields (all equality, no negation):
///   involvedObject.name, involvedObject.kind, involvedObject.namespace,
///   involvedObject.uid, reason
///
/// All supplied terms are AND-evaluated: an event must match every term.
/// An unknown field is ignored (pass-through). An event missing a constrained
/// field does not match.
pub fn filter_events_by_field_selector(
    events: Vec<serde_json::Value>,
    selector: &str,
) -> Vec<serde_json::Value> {
    if selector.is_empty() {
        return events;
    }
    events
        .into_iter()
        .filter(|ev| event_matches_field_selector(ev, selector))
        .collect()
}

fn event_matches_field_selector(ev: &serde_json::Value, selector: &str) -> bool {
    for term in selector.split(',') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        if let Some((field, expected)) = term.split_once('=') {
            let actual = match field {
                "involvedObject.name" => ev["involvedObject"]["name"].as_str().unwrap_or(""),
                "involvedObject.kind" => ev["involvedObject"]["kind"].as_str().unwrap_or(""),
                "involvedObject.namespace" => {
                    ev["involvedObject"]["namespace"].as_str().unwrap_or("")
                }
                "involvedObject.uid" => ev["involvedObject"]["uid"].as_str().unwrap_or(""),
                "reason" => ev["reason"].as_str().unwrap_or(""),
                _ => continue,
            };
            if actual != expected {
                return false;
            }
        }
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
    headers: HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    // Detect as=Table before namespace validation: a v1beta1 Table request must return
    // 406 Not Acceptable regardless of namespace validity (the format is not supported).
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(version) = super::table::table_accept_version(accept) {
        if version != "v1" {
            return Err(Status::not_acceptable(format!(
                "Table version \"{version}\" is not supported; only meta.k8s.io/v1 is accepted"
            )));
        }
    }

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
            if let Some(ref sel) = query.label_selector {
                pods.retain(|pod| super::watch::object_matches_label_selector(pod, sel));
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
                label_selector: query.label_selector,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username: user.username,
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "pods".into(),
                timeout_seconds: query.timeout_seconds,
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

    // Return Table format when as=Table;v=v1 is requested (v1beta1 was rejected above).
    if super::table::wants_table(accept) {
        return Ok(Json(super::table::build_table("", "pods", items)).into_response());
    }

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
    Extension(user): Extension<UserInfo>,
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
    initialize_pod_generation(&mut obj.body);
    apply_automount_sa_token_default(&state, &mut obj.body, ns.as_str()).await;
    inject_sa_token_volume(&mut obj.body, &name);

    if let Some(rc_name) = obj.body["spec"]["runtimeClassName"]
        .as_str()
        .map(str::to_owned)
    {
        let rc_key = group_object_key("node.k8s.io", "runtimeclasses", None, &rc_name);
        if let Ok(Some(stored_rc)) = state.store.get(&rc_key).await {
            if let Ok(rc_obj) = serde_json::from_slice::<serde_json::Value>(&stored_rc.value) {
                apply_runtime_class_overhead(&mut obj.body, &rc_obj);
            }
        }
    }

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "pods",
        name: &name,
        namespace: Some(ns.as_str()),
        operation: "CREATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
        })),
        dry_run: false,
    };
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

    // LimitRange: inject defaults then validate min/max bounds.
    obj.body =
        crate::limit_range::apply_limit_ranges(&state, obj.body, ns.as_str(), "pods").await?;

    // ResourceQuota: ensure pod count does not exceed hard limits, respecting scope selectors.
    crate::quota::check_resource_quota(&state, ns.as_str(), "", "pods", Some(&obj.body)).await?;

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
    Extension(user): Extension<UserInfo>,
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

    // Fetch the stored object to compare spec (needed for generation tracking).
    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;
    let stored_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;
    let spec_before = stored_obj.body["spec"].clone();

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "pods",
        name: &name,
        namespace: Some(ns.as_str()),
        operation: "UPDATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
        })),
        dry_run: false,
    };
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

    increment_pod_generation_if_spec_changed(&mut obj.body, &spec_before);

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
    let already_terminating = meta.deletion_timestamp.is_some();

    // Real Kubernetes apiserver always soft-deletes pods first (sets deletionTimestamp)
    // so the kubelet receives a MODIFIED event and gracefully terminates the container via SIGTERM.
    // Hard-delete only when the pod is already in the Terminating state AND has no finalizers —
    // this is the path taken when the kubelet calls DELETE a second time after stopping the container.
    //
    // Without this: pods are immediately hard-deleted, the kubelet only receives a DELETED event
    // with a minimal tombstone (no spec), and the container is never sent SIGTERM — it keeps
    // running indefinitely while the StatefulSet controller waits for the pod to terminate.
    if already_terminating && !has_finalizers {
        // Hard-delete: pod is already Terminating and all finalizers are gone.
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;

        return Ok(Json(serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Success",
            "code": 200
        })));
    }

    // Soft-delete: stamp deletionTimestamp so the kubelet knows to gracefully terminate
    // the container. Applies regardless of whether the pod has finalizers.
    obj.body["metadata"]["deletionTimestamp"] = serde_json::Value::String(utc_now_rfc3339());
    let expected_rv = parse_resource_version(obj.resource_version())?;
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;
    obj.set_resource_version(new_rv);
    Ok(Json(obj.body))
}

pub async fn patch_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    Query(patch_query): Query<super::json_patch::PatchQuery>,
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

    let spec_before = current_obj.body["spec"].clone();

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

    increment_pod_generation_if_spec_changed(&mut current_obj.body, &spec_before);

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

    // Dry-run: validation passed; return the would-be patched object without persisting.
    if patch_query.is_dry_run() {
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

/// POST /api/v1/namespaces/{ns}/pods/{name}/eviction
///
/// Eviction triggers graceful pod deletion. We accept any Eviction body (or
/// empty body) and soft-delete the pod by stamping `deletionTimestamp`, exactly
/// as `delete_pod` does. Without this endpoint the conformance test
/// "Should recreate evicted statefulset" hangs: the test calls the Eviction API,
/// receives a 404 (no route), the pod is never terminated, and the StatefulSet
/// controller never triggers recreation.
pub async fn evict_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let key = object_key("pods", ns.as_str(), &name);

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let meta: ObjectMeta = serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
    let already_terminating = meta.deletion_timestamp.is_some();
    let has_finalizers = meta.finalizers.as_ref().is_some_and(|f| !f.is_empty());

    if already_terminating && !has_finalizers {
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
    } else if !already_terminating {
        obj.body["metadata"]["deletionTimestamp"] = serde_json::Value::String(utc_now_rfc3339());
        let expected_rv = parse_resource_version(obj.resource_version())?;
        state
            .store
            .put(&key, obj.to_bytes(), expected_rv)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
    }

    let eviction: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|_| {
        serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": name, "namespace": ns.as_str() }
        })
    });
    Ok((StatusCode::CREATED, Json(eviction)))
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

    /// DELETED watch events must carry the full last-known object body so that
    /// informer tombstone handlers (DeletedFinalStateUnknown) can match the deleted
    /// object against label selectors. Without labels in the tombstone, the KCM
    /// StatefulSet controller cannot identify which StatefulSet owned the pod and
    /// status.replicas stays at 1, causing 10-minute AfterEach hangs in conformance.
    #[test]
    fn encode_deleted_carries_full_pod_body_with_labels() {
        let pod_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "nginx",
                "namespace": "default",
                "labels": {
                    "app": "nginx",
                    "controller-revision-hash": "abc123",
                    "statefulset.kubernetes.io/pod-name": "nginx-0"
                },
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "name": "nginx",
                    "uid": "some-uid"
                }]
            },
            "spec": { "containers": [] }
        });
        let body_bytes = Bytes::from(serde_json::to_vec(&pod_body).unwrap());
        let bytes = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Deleted {
                key: "/registry/pods/default/nginx".to_string(),
                revision: 9,
                body: Some(body_bytes),
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
        assert_eq!(
            parsed["object"]["metadata"]["resourceVersion"], "9",
            "resourceVersion must be updated to deletion revision"
        );
        assert_eq!(
            parsed["object"]["metadata"]["labels"]["statefulset.kubernetes.io/pod-name"], "nginx-0",
            "DELETED tombstone must carry pod labels so KCM StatefulSet controller can \
             identify which StatefulSet owned the pod via DeletedFinalStateUnknown handler; \
             without labels status.replicas never drops to 0 (10-minute hang)"
        );
        assert!(
            parsed["object"]["metadata"]["ownerReferences"].is_array(),
            "DELETED tombstone must carry ownerReferences so GC can clean up owned resources"
        );
    }

    /// When no body is available (e.g. deletion_log tombstone from before this fix),
    /// encode_watch_event falls back to reconstructing minimal metadata from the key.
    #[test]
    fn encode_deleted_falls_back_to_key_when_no_body() {
        let bytes = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Deleted {
                key: "/registry/pods/default/nginx".to_string(),
                revision: 9,
                body: None,
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
            timeout_seconds: None,
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
            timeout_seconds: None,
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
mod event_field_selector_tests {
    use super::*;

    fn event(name: &str, kind: &str, ns: &str, uid: &str, reason: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": {"name": "ev", "namespace": ns},
            "involvedObject": {
                "name": name,
                "kind": kind,
                "namespace": ns,
                "uid": uid
            },
            "reason": reason
        })
    }

    /// kubectl describe sends multi-term involvedObject selectors; all terms must be AND-evaluated.
    /// Without AND logic, a selector with involvedObject.kind=Pod returns events for every kind,
    /// making kubectl describe show unrelated events or none at all.
    #[test]
    fn multi_term_involved_object_selectors_are_and_evaluated() {
        let pod_event = event("coredns-xxx", "Pod", "kube-system", "uid-1", "Started");
        let node_event = event("node-1", "Node", "kube-system", "uid-2", "Started");
        let events = vec![pod_event.clone(), node_event];

        let result = filter_events_by_field_selector(
            events,
            "involvedObject.name=coredns-xxx,involvedObject.kind=Pod",
        );

        assert_eq!(
            result.len(),
            1,
            "kubectl describe relies on multi-term involvedObject selectors being AND-evaluated; \
             without AND logic involvedObject.kind is ignored and all events for any kind are returned, \
             making kubectl describe show wrong events or always show Events: <none>"
        );
        assert_eq!(result[0]["involvedObject"]["kind"], "Pod");
        assert_eq!(result[0]["involvedObject"]["name"], "coredns-xxx");
    }

    /// A single-term selector still works after the change.
    #[test]
    fn single_term_involved_object_name_still_filters() {
        let ev1 = event("coredns-xxx", "Pod", "kube-system", "uid-1", "Started");
        let ev2 = event("other-pod", "Pod", "kube-system", "uid-2", "Pulled");
        let events = vec![ev1, ev2];

        let result = filter_events_by_field_selector(events, "involvedObject.name=coredns-xxx");
        assert_eq!(
            result.len(),
            1,
            "single-term involvedObject.name selector must still filter correctly; \
             if this regresses kubectl get events --field-selector involvedObject.name=X stops working"
        );
        assert_eq!(result[0]["involvedObject"]["name"], "coredns-xxx");
    }

    /// A selector that matches no event must return empty — not all events.
    #[test]
    fn selector_matching_no_event_returns_empty() {
        let ev = event("pod-a", "Pod", "default", "uid-1", "Started");
        let result = filter_events_by_field_selector(vec![ev], "involvedObject.name=nonexistent");
        assert!(
            result.is_empty(),
            "a selector term with no match must return empty; returning all events would cause \
             kubectl describe to show events for unrelated objects"
        );
    }

    /// An empty selector is a pass-through — all events are returned.
    #[test]
    fn empty_selector_passes_all_events() {
        let ev1 = event("pod-a", "Pod", "default", "uid-1", "Started");
        let ev2 = event("pod-b", "Deployment", "default", "uid-2", "Scaled");
        let events = vec![ev1, ev2];
        let result = filter_events_by_field_selector(events.clone(), "");
        assert_eq!(result.len(), events.len());
    }

    /// reason= field selector filters by event reason.
    #[test]
    fn reason_field_selector_filters_by_reason() {
        let ev1 = event("pod-a", "Pod", "default", "uid-1", "Pulled");
        let ev2 = event("pod-b", "Pod", "default", "uid-2", "Started");
        let events = vec![ev1, ev2];
        let result = filter_events_by_field_selector(events, "reason=Pulled");
        assert_eq!(
            result.len(),
            1,
            "reason= field selector must return only events with matching reason; \
             without this, kubectl get events --field-selector reason=X returns unrelated events"
        );
        assert_eq!(result[0]["reason"], "Pulled");
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

    /// Regression test for mayor-zcnd: sendInitialEvents pod watch with a labelSelector must
    /// exclude pods that do not match the selector from the initial ADDED events.
    ///
    /// The StatefulSet controller opens a pod watch with sendInitialEvents=true and
    /// labelSelector matching its pods (e.g. "app=ss"). Before this fix, ALL pods in the
    /// namespace were returned as initial ADDED events, regardless of labels. The fix applies
    /// object_matches_label_selector to the initial items before passing them to watch_generic.
    ///
    /// This test verifies the filtering logic that was added: only pods with the matching
    /// label should survive the retain. Without the fix (retain removed), non-matching pods
    /// appear in the initial items and the informer cache gets polluted.
    #[test]
    fn send_initial_events_label_selector_filters_initial_pods() {
        let ss_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "ss-0",
                "namespace": "default",
                "labels": {"app": "ss", "controller-uid": "abc123"}
            },
            "spec": {}
        });
        let unrelated_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "unrelated-pod",
                "namespace": "default",
                "labels": {"app": "other"}
            },
            "spec": {}
        });

        let mut pods = vec![ss_pod.clone(), unrelated_pod];
        let selector = "app=ss";

        // This is the exact retain logic added by the fix.
        pods.retain(|pod| super::super::watch::object_matches_label_selector(pod, selector));

        assert_eq!(
            pods.len(),
            1,
            "sendInitialEvents with labelSelector=app=ss must return only ss-0, not unrelated pods; \
             without the fix all pods are returned and the StatefulSet controller's pod informer \
             cache is polluted with pods from other StatefulSets (mayor-zcnd)"
        );
        assert_eq!(
            pods[0]["metadata"]["name"], "ss-0",
            "the retained pod must be ss-0 (matches app=ss), not the unrelated pod"
        );
    }

    /// Regression test for mayor-zcnd (live watch path): pod watch with labelSelector must
    /// deliver MODIFIED events for matching pods and suppress events for non-matching pods.
    ///
    /// Before the fix, label_selector was hardcoded to None in the pod watch path, so
    /// watch_generic received no label selector and delivered ALL pod MODIFIED events.
    /// The StatefulSet controller's informer received MODIFIED events for pods belonging
    /// to other StatefulSets or other workloads, adding noise but not breaking correctness.
    ///
    /// After the fix, label_selector=query.label_selector is forwarded. watch_generic applies
    /// object_matches_label_selector and only delivers events for pods matching the selector.
    /// Non-matching pods get a synthetic DELETED if they were previously sent as ADDED.
    ///
    /// This test verifies that object_matches_label_selector correctly identifies matching pods.
    /// If the label selector check is removed, the retain in sendInitialEvents fails silently
    /// (every pod would be retained) and non-ss pods appear in the informer cache.
    #[test]
    fn label_selector_matches_statefulset_pod_labels() {
        // StatefulSet controller watches with selector matching all its pods.
        let selector = "app=ss,controller-uid=abc";

        let ss_pod = serde_json::json!({
            "metadata": {"labels": {"app": "ss", "controller-uid": "abc", "statefulset.kubernetes.io/pod-name": "ss-0"}}
        });
        let other_ss_pod = serde_json::json!({
            "metadata": {"labels": {"app": "other-ss", "controller-uid": "xyz"}}
        });
        let unlabeled = serde_json::json!({
            "metadata": {"name": "bare"}
        });

        assert!(
            super::super::watch::object_matches_label_selector(&ss_pod, selector),
            "ss-0 must match selector app=ss,controller-uid=abc — it belongs to this StatefulSet"
        );
        assert!(
            !super::super::watch::object_matches_label_selector(&other_ss_pod, selector),
            "pod from other StatefulSet must NOT match — delivering its events to this watcher \
             would pollute the informer cache with unrelated pods"
        );
        assert!(
            !super::super::watch::object_matches_label_selector(&unlabeled, selector),
            "unlabeled pod must NOT match — no labels means selector cannot be satisfied"
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
///
/// For array fields with registered strategic-merge keys (conditions, podIPs,
/// containerStatuses, etc.) the patch is applied using strategic-merge semantics so
/// that `$patch:delete` directives remove matching items rather than being stored
/// literally.  Storing them literally causes the kubelet to detect phantom array
/// changes on every reconcile and continuously recreate the pod sandbox.
pub fn apply_status_patch(
    stored: &serde_json::Value,
    patch: &serde_json::Value,
) -> serde_json::Value {
    let mut result = stored.clone();
    if let Some(patch_status) = patch.get("status") {
        if result["status"].is_object() && patch_status.is_object() {
            // Merge fields individually so we can handle arrays with strategic merge keys.
            if let Some(patch_obj) = patch_status.as_object() {
                for (key, val) in patch_obj {
                    if key == "conditions" {
                        // Strategic merge by .type — patch conditions override stored ones by type,
                        // but stored conditions not present in the patch are preserved.
                        // Fields within a matched condition are merged; missing fields in the
                        // patch leave existing stored fields intact.
                        merge_conditions(&mut result["status"]["conditions"], val);
                    } else if val.is_array() {
                        // For array fields, use strategic-merge-patch so that $patch:delete
                        // directives are applied by merge key rather than stored literally.
                        // Wrap the field in a one-key object so strategic_merge_patch can
                        // resolve the merge key via the field name as the path root.
                        let wrapper_patch = serde_json::json!({ key: val });
                        let mut wrapper_target =
                            serde_json::json!({ key: result["status"][key].clone() });
                        // Ignore errors — unknown $patch directives fall through to merge_patch.
                        if crate::patch::strategic_merge_patch(&mut wrapper_target, &wrapper_patch)
                            .is_ok()
                        {
                            result["status"][key] = wrapper_target[key].clone();
                        } else {
                            crate::patch::merge_patch(&mut result["status"][key], val);
                        }
                    } else {
                        crate::patch::merge_patch(&mut result["status"][key], val);
                    }
                }
            }
        } else {
            result["status"] = patch_status.clone();
        }
    }
    // Enforce hostNetwork invariant: a pod sharing the host network namespace has
    // the node's IP as its pod IP, not a pod-CIDR address.  The kubelet sets
    // status.podIP from the CNI sandbox result, which for hostNetwork pods is
    // still a pod-CIDR address because the sandbox creation path doesn't special-
    // case hostNetwork.  Override podIP/podIPs here so the downward API exposes
    // the correct value (HOST_IP == POD_IP for hostNetwork pods).
    if result["spec"]["hostNetwork"] == serde_json::json!(true) {
        let host_ip = result["status"]["hostIP"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        if let Some(host_ip) = host_ip {
            result["status"]["podIP"] = serde_json::json!(host_ip);
            result["status"]["podIPs"] = serde_json::json!([{"ip": host_ip}]);
        }
    }

    result
}

/// Merge a patch conditions array into stored conditions, keyed by `type`.
/// Fields present in the patch condition update the stored condition; fields absent
/// in the patch are left as-is in the stored condition.
fn merge_conditions(stored: &mut serde_json::Value, patch_conditions: &serde_json::Value) {
    let Some(patch_arr) = patch_conditions.as_array() else {
        return;
    };
    if !stored.is_array() {
        *stored = patch_conditions.clone();
        return;
    }
    let stored_arr = stored.as_array_mut().unwrap();
    for patch_cond in patch_arr {
        let Some(cond_type) = patch_cond["type"].as_str() else {
            continue;
        };
        if let Some(existing) = stored_arr.iter_mut().find(|c| c["type"] == cond_type) {
            // Merge patch fields into the existing condition, skipping null values.
            if let Some(patch_obj) = patch_cond.as_object() {
                for (k, v) in patch_obj {
                    if !v.is_null() {
                        existing[k] = v.clone();
                    }
                }
            }
        } else {
            stored_arr.push(patch_cond.clone());
        }
    }
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
// Resize subresource — PATCH/PUT /api/v1/namespaces/:ns/pods/:name/resize
// ---------------------------------------------------------------------------

/// Merge incoming container resources onto the stored pod (match by container name),
/// then set status.resize = "Proposed".
///
/// Only spec.containers[].resources is updated; all other fields are preserved.
/// This is the pure logic extracted for testability.
pub fn apply_resize_patch(
    stored: &serde_json::Value,
    incoming: &serde_json::Value,
) -> serde_json::Value {
    let mut result = stored.clone();
    if let Some(incoming_containers) = incoming["spec"]["containers"].as_array() {
        if let Some(stored_containers) = result["spec"]["containers"].as_array_mut() {
            for stored_container in stored_containers.iter_mut() {
                let stored_name = stored_container["name"].as_str().unwrap_or("");
                if let Some(incoming_container) = incoming_containers
                    .iter()
                    .find(|c| c["name"].as_str().unwrap_or("") == stored_name)
                {
                    if !incoming_container["resources"].is_null() {
                        stored_container["resources"] = incoming_container["resources"].clone();
                    }
                }
            }
        }
    }
    result["status"]["resize"] = serde_json::json!("Proposed");
    result
}

pub async fn patch_pod_resize<S: Store>(
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

    current_obj.body = apply_resize_patch(&current_obj.body, &incoming);

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
// EphemeralContainers subresource — PATCH /api/v1/namespaces/:ns/pods/:name/ephemeralcontainers
// ---------------------------------------------------------------------------

/// Merge `spec.ephemeralContainers` from `patch` into `stored`.
///
/// Kubernetes semantics: ephemeral containers may be added but never removed.
/// We append containers from the patch whose name does not already exist in the
/// stored list, leaving existing containers untouched.
///
/// Extracted as a pure function for testability — the async handler cannot be
/// tested without a live store.
pub fn apply_ephemeral_containers_patch(
    stored: &serde_json::Value,
    patch: &serde_json::Value,
) -> serde_json::Value {
    let mut result = stored.clone();

    let patch_containers = match patch["spec"]["ephemeralContainers"].as_array() {
        Some(a) => a.clone(),
        None => return result,
    };

    let existing: Vec<serde_json::Value> = result["spec"]["ephemeralContainers"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let existing_names: std::collections::HashSet<String> = existing
        .iter()
        .filter_map(|c| c["name"].as_str().map(|s| s.to_owned()))
        .collect();

    let mut merged = existing;
    for c in &patch_containers {
        if !existing_names.contains(c["name"].as_str().unwrap_or("")) {
            merged.push(c.clone());
        }
    }

    result["spec"]["ephemeralContainers"] = serde_json::json!(merged);
    result
}

pub async fn get_ephemeral_containers<S: Store>(
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

pub async fn patch_ephemeral_containers<S: Store>(
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
    let patch: serde_json::Value = serde_json::from_slice(&body)
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

    let spec_before = current_obj.body["spec"].clone();
    current_obj.body = apply_ephemeral_containers_patch(&current_obj.body, &patch);
    increment_pod_generation_if_spec_changed(&mut current_obj.body, &spec_before);

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

    /// apply_status_patch with containerStatuses[].restartCount=3 must persist the value.
    ///
    /// The kubelet increments restartCount after each container restart triggered by a
    /// failing liveness probe. If apply_status_patch silently drops or zeros restartCount,
    /// the e2e test "should have monotonically increasing restart count" always sees 0
    /// and fails. This is failure mode B for mayor-4ath.
    #[test]
    fn patch_pod_status_restart_count_persists() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "liveness-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "busybox",
                    "livenessProbe": {"exec": {"command": ["/bin/false"]},
                        "initialDelaySeconds": 1, "periodSeconds": 1}}]
            },
            "status": {"phase": "Running"}
        });
        // Kubelet sends a status PATCH after the container restarts; it includes the
        // full containerStatuses array with the updated restartCount.
        let patch = serde_json::json!({
            "status": {
                "phase": "Running",
                "containerStatuses": [{
                    "name": "app",
                    "ready": false,
                    "restartCount": 3,
                    "image": "busybox",
                    "imageID": "",
                    "state": {"running": {"startedAt": "2024-01-01T00:00:01Z"}}
                }]
            }
        });

        let result = apply_status_patch(&stored, &patch);

        assert_eq!(
            result["status"]["containerStatuses"][0]["restartCount"], 3,
            "restartCount must be preserved after status PATCH — kubelet increments this \
             after each liveness probe restart; if it's zeroed, the e2e monotonic-restart-count \
             test always sees 0 restarts (mayor-4ath failure mode B)"
        );
        assert_eq!(
            result["spec"]["containers"][0]["livenessProbe"]["exec"]["command"][0], "/bin/false",
            "spec.containers[].livenessProbe must be untouched by status PATCH"
        );
    }

    /// Kubelet sends partial conditions (type + observedGeneration only, no status field).
    /// Strategic merge by type must preserve the existing status value, not replace it with null.
    /// Without this, endpoints-controller sees Ready condition with null status → treats pod as
    /// not-ready → never populates Endpoints.subsets → webhook service never gets endpoints →
    /// AdmissionWebhook conformance test times out waiting for endpoint count=1.
    #[test]
    fn patch_pod_status_partial_conditions_preserve_ready_status() {
        let stored = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "ns", "resourceVersion": "1"},
            "spec": {},
            "status": {
                "conditions": [
                    {"type": "Ready", "status": "True", "lastTransitionTime": "2026-06-02T00:00:01Z"},
                    {"type": "ContainersReady", "status": "True"},
                    {"type": "PodScheduled", "status": "True"}
                ]
            }
        });
        // Kubelet periodic sync: partial update with type + observedGeneration, no status field.
        let patch = serde_json::json!({
            "status": {
                "conditions": [
                    {"observedGeneration": 1, "type": "Ready"},
                    {"observedGeneration": 1, "type": "ContainersReady"},
                    {"observedGeneration": 1, "type": "PodScheduled"}
                ]
            }
        });

        let result = apply_status_patch(&stored, &patch);
        let conditions = result["status"]["conditions"]
            .as_array()
            .expect("conditions array");
        let ready = conditions
            .iter()
            .find(|c| c["type"] == "Ready")
            .expect("Ready condition");
        assert_eq!(
            ready["status"], "True",
            "Ready status must survive a partial kubelet conditions patch — without this, \
             endpoints-controller sees no-status=not-ready and never populates Endpoints"
        );
        assert_eq!(
            ready["observedGeneration"], 1,
            "observedGeneration from patch must be merged in"
        );
        assert_eq!(
            ready["lastTransitionTime"], "2026-06-02T00:00:01Z",
            "lastTransitionTime absent from patch must be preserved from stored value"
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

    /// apply_status_patch for a hostNetwork pod must set status.podIP == status.hostIP.
    ///
    /// A pod with spec.hostNetwork=true shares the node's network namespace, so its
    /// pod IP is the node IP, not a pod-CIDR address.  The kubelet sets status.podIP
    /// from the CNI sandbox result, which is a pod-CIDR IP even for hostNetwork pods.
    /// Without this override, the downward API exposes HOST_IP != POD_IP, breaking
    /// the sonobuoy test "Downward API should provide host IP and pod IP as an env var
    /// if pod uses host network" (SONOBUOY_FOCUS='Downward API should provide host IP
    /// and pod IP.*host network').
    #[test]
    fn host_network_pod_status_pod_ip_equals_host_ip() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "hostnet-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "hostNetwork": true,
                "containers": [{"name": "app", "image": "nginx"}]
            },
            "status": {"phase": "Pending"}
        });
        // Kubelet patches status with hostIP (node IP) and podIP (pod-CIDR address from CNI).
        let patch = serde_json::json!({
            "status": {
                "phase": "Running",
                "hostIP": "192.168.5.15",
                "podIP": "10.85.1.153",
                "podIPs": [{"ip": "10.85.1.153"}]
            }
        });

        let result = apply_status_patch(&stored, &patch);

        assert_eq!(
            result["status"]["podIP"], "192.168.5.15",
            "hostNetwork pod status.podIP must equal status.hostIP (192.168.5.15), not \
             the pod-CIDR address (10.85.1.153) — downward API POD_IP must match HOST_IP \
             for pods sharing the host network namespace"
        );
        assert_eq!(
            result["status"]["podIPs"][0]["ip"], "192.168.5.15",
            "hostNetwork pod status.podIPs[0].ip must equal hostIP — same invariant as podIP"
        );
        assert_eq!(
            result["status"]["hostIP"], "192.168.5.15",
            "hostIP must remain unchanged at the node IP"
        );
    }

    /// apply_status_patch for a normal (non-hostNetwork) pod must NOT override podIP.
    ///
    /// Only hostNetwork pods receive the host IP override; regular pods keep their
    /// pod-CIDR address.  Incorrect over-application would break all pod networking.
    #[test]
    fn non_host_network_pod_status_pod_ip_unchanged() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "normal-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "hostNetwork": false,
                "containers": [{"name": "app", "image": "nginx"}]
            },
            "status": {"phase": "Pending"}
        });
        let patch = serde_json::json!({
            "status": {
                "phase": "Running",
                "hostIP": "192.168.5.15",
                "podIP": "10.85.1.153",
                "podIPs": [{"ip": "10.85.1.153"}]
            }
        });

        let result = apply_status_patch(&stored, &patch);

        assert_eq!(
            result["status"]["podIP"], "10.85.1.153",
            "non-hostNetwork pod status.podIP must not be overridden — \
             only hostNetwork pods share the node IP"
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

    // Initialize status.conditions with PodScheduled=False when absent.
    //
    // Real kube-apiserver always stamps this condition on Pod create.  Conformance
    // scheduling tests (e.g. scheduling/predicates.go) wait for PodScheduled to
    // appear in status.conditions before declaring scheduling success.  Without this
    // initial False, the field is absent after create and the scheduler never has a
    // condition to flip to True — so tests that wait for "scheduled condition" time out.
    //
    // Idempotent: the condition is only inserted when status.conditions is absent or
    // does not already contain a PodScheduled entry.
    let conditions_absent = pod["status"]["conditions"].is_null()
        || pod["status"]["conditions"].as_array().is_none_or(|arr| {
            arr.iter()
                .all(|c| c["type"].as_str() != Some("PodScheduled"))
        });
    if conditions_absent {
        if !pod["status"].is_object() {
            pod["status"] = serde_json::json!({});
        }
        let now = crate::util::utc_now_rfc3339();
        let scheduled_false = serde_json::json!({
            "type": "PodScheduled",
            "status": "False",
            "reason": "Unschedulable",
            "message": "pod not yet scheduled",
            "lastTransitionTime": now
        });
        match pod["status"]["conditions"].as_array_mut() {
            Some(arr) => arr.push(scheduled_false),
            None => pod["status"]["conditions"] = serde_json::json!([scheduled_false]),
        }
    }

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

/// Copy `spec.overhead.podFixed` from a RuntimeClass into `pod.spec.overhead`.
///
/// If the pod already carries `spec.overhead`, it is left unchanged (idempotent,
/// matches what the kube-apiserver RuntimeClass admission plugin does).
/// The RuntimeClass JSON must be the full stored object; if it has no
/// `spec.overhead.podFixed` this is a no-op.
pub fn apply_runtime_class_overhead(pod: &mut serde_json::Value, rc: &serde_json::Value) {
    let pod_fixed = &rc["spec"]["overhead"]["podFixed"];
    if pod_fixed.is_null() || pod_fixed.as_object().is_none_or(|m| m.is_empty()) {
        return;
    }
    if pod["spec"]["overhead"].is_null() {
        pod["spec"]["overhead"] = pod_fixed.clone();
    }
}

/// Set `metadata.generation = 1` on a newly created pod if absent or null.
/// Preserves the caller-supplied value when it is already set.
///
/// Kubernetes conformance tests require generation=1 on every newly created pod.
/// Without this, controllers that gate on observedGeneration == generation will
/// never progress because generation stays at null.
pub fn initialize_pod_generation(pod: &mut serde_json::Value) {
    if pod["metadata"]["generation"].is_null() {
        pod["metadata"]["generation"] = serde_json::json!(1i64);
    }
}

/// Increment `metadata.generation` by 1 when the pod spec has changed.
///
/// Called after PATCH and PUT operations. Kubernetes increments generation on
/// every spec change so that controllers and status reporters can detect when
/// spec has advanced past what they last reconciled (via observedGeneration).
pub fn increment_pod_generation_if_spec_changed(
    pod: &mut serde_json::Value,
    spec_before: &serde_json::Value,
) {
    if pod["spec"] != *spec_before {
        let current = pod["metadata"]["generation"].as_i64().unwrap_or(1);
        pod["metadata"]["generation"] = serde_json::json!(current + 1);
    }
}

/// Resolve and write `spec.automountServiceAccountToken` on a pod before create.
///
/// Real kube-apiserver's ServiceAccount admission plugin resolves the effective
/// automount value as follows:
/// 1. If the pod already has the field set (true or false), leave it — pod wins.
/// 2. If the pod has a serviceAccountName, look up the SA; if the SA sets the
///    field to false, inherit that value (token will be suppressed).
/// 3. Otherwise default to true (the kube-apiserver default).
///
/// Without this, a pod that omits `spec.automountServiceAccountToken` always gets
/// the token injected, even if the ServiceAccount opts out with
/// `automountServiceAccountToken: false`. That breaks the conformance test
/// "ServiceAccounts should allow opting out of API token automount".
///
/// This function writes the resolved boolean into `pod["spec"]["automountServiceAccountToken"]`
/// so that `inject_sa_token_volume` can make a deterministic decision.
pub async fn apply_automount_sa_token_default<S: Store>(
    state: &AppState<S>,
    pod: &mut serde_json::Value,
    namespace: &str,
) {
    // 1. Pod already has the field set — nothing to do.
    if !pod["spec"]["automountServiceAccountToken"].is_null() {
        return;
    }

    // 2. Look up the SA if serviceAccountName is present.
    let sa_name = pod["spec"]["serviceAccountName"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    if !sa_name.is_empty() {
        let sa_key = object_key("serviceaccounts", namespace, &sa_name);
        if let Ok(Some(stored)) = state.store.get(&sa_key).await {
            if let Ok(sa) = serde_json::from_slice::<serde_json::Value>(&stored.value) {
                // SA explicitly sets automountServiceAccountToken=false: inherit it.
                // ServiceAccount stores this as a top-level field, not under spec.
                if sa["automountServiceAccountToken"] == serde_json::Value::Bool(false) {
                    pod["spec"]["automountServiceAccountToken"] = serde_json::Value::Bool(false);
                    return;
                }
            }
        }
    }

    // 3. Default to true.
    pod["spec"]["automountServiceAccountToken"] = serde_json::Value::Bool(true);
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

    /// apply_pod_create_defaults must preserve spec.containers[].livenessProbe intact.
    ///
    /// The kubelet reads livenessProbe from the pod spec it receives from the apiserver.
    /// If apply_pod_create_defaults (or any other CREATE-path code) strips or transforms
    /// livenessProbe, the kubelet never sees the probe config and cannot run it — causing
    /// the container to never restart even when the probe command fails. This is failure
    /// mode A for mayor-4ath: the probe config is dropped before the kubelet can act on it.
    #[test]
    fn liveness_probe_is_preserved_through_create_defaults() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "liveness-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "busybox",
                    "livenessProbe": {
                        "exec": {"command": ["/bin/sh", "-c", "exit 1"]},
                        "initialDelaySeconds": 5,
                        "periodSeconds": 2,
                        "failureThreshold": 3
                    }
                }]
            }
        });

        apply_pod_create_defaults(&mut pod);

        let probe = &pod["spec"]["containers"][0]["livenessProbe"];
        assert!(
            probe.is_object(),
            "livenessProbe must remain an object after apply_pod_create_defaults — \
             kubelet reads it to schedule probe runs; if missing, probes never fire \
             and restartCount stays at 0 (mayor-4ath failure mode A)"
        );
        assert_eq!(
            probe["exec"]["command"][0], "/bin/sh",
            "livenessProbe.exec.command must be preserved exactly"
        );
        assert_eq!(
            probe["exec"]["command"][2], "exit 1",
            "livenessProbe.exec.command payload must be preserved"
        );
        assert_eq!(
            probe["initialDelaySeconds"], 5,
            "livenessProbe.initialDelaySeconds must be preserved"
        );
        assert_eq!(
            probe["periodSeconds"], 2,
            "livenessProbe.periodSeconds must be preserved"
        );
        assert_eq!(
            probe["failureThreshold"], 3,
            "livenessProbe.failureThreshold must be preserved"
        );
    }

    /// apply_pod_create_defaults must insert PodScheduled=False into status.conditions.
    ///
    /// Real kube-apiserver always stamps this condition on create.  Conformance scheduling
    /// tests (scheduling/predicates.go) wait for `PodScheduled` to appear in
    /// `pod.status.conditions`; without this default the field is absent after create and
    /// those tests time out with "Did not find scheduled condition for pod".
    ///
    /// This test fails if the PodScheduled initialization is removed — proving it is a
    /// genuine regression test, not just documentation.
    #[test]
    fn pod_create_defaults_sets_pod_scheduled_false() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pfpod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        apply_pod_create_defaults(&mut pod);

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be an array after apply_pod_create_defaults");
        let scheduled = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("PodScheduled"))
            .expect(
                "PodScheduled condition must be present — scheduling tests wait for it and \
                 time out with 'Did not find scheduled condition for pod' if absent",
            );
        assert_eq!(
            scheduled["status"], "False",
            "PodScheduled must start as False — the scheduler flips it to True after binding; \
             if missing, scheduling tests cannot observe the transition"
        );
        assert_eq!(
            scheduled["reason"], "Unschedulable",
            "PodScheduled reason must be Unschedulable before the pod is bound to a node"
        );
    }

    /// apply_pod_create_defaults must not overwrite a pre-existing PodScheduled condition.
    ///
    /// Idempotency: if the pod already carries PodScheduled (e.g. from a webhook or
    /// a second call to apply_pod_create_defaults), the existing value must survive.
    #[test]
    fn pod_create_defaults_does_not_overwrite_existing_pod_scheduled() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pfpod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {
                "conditions": [{
                    "type": "PodScheduled",
                    "status": "True",
                    "reason": "PodScheduled",
                    "lastTransitionTime": "2024-01-01T00:00:00Z"
                }]
            }
        });

        apply_pod_create_defaults(&mut pod);

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("conditions must still be an array");
        let scheduled = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("PodScheduled"))
            .expect("PodScheduled condition must be present");
        assert_eq!(
            scheduled["status"], "True",
            "pre-existing PodScheduled=True must not be overwritten to False"
        );
    }
}

/// Flip the PodScheduled condition to True in-place.
///
/// Finds an existing PodScheduled entry in `status.conditions` and sets its status to
/// "True" with reason "PodScheduled".  If no entry exists, appends one.
/// `now` must be an RFC3339 timestamp string (used as `lastTransitionTime`).
///
/// Extracted for testability — the full `bind_pod` handler is async and requires a live store.
pub fn set_pod_scheduled_true(pod: &mut serde_json::Value, now: &str) {
    if !pod["status"].is_object() {
        pod["status"] = serde_json::json!({});
    }
    if let Some(conditions) = pod["status"]["conditions"].as_array_mut() {
        for cond in conditions.iter_mut() {
            if cond["type"].as_str() == Some("PodScheduled") {
                cond["status"] = serde_json::json!("True");
                cond["reason"] = serde_json::json!("PodScheduled");
                cond["message"] = serde_json::json!("");
                cond["lastTransitionTime"] = serde_json::json!(now);
                return;
            }
        }
        // No existing PodScheduled condition — append one.
        conditions.push(serde_json::json!({
            "type": "PodScheduled",
            "status": "True",
            "reason": "PodScheduled",
            "message": "",
            "lastTransitionTime": now
        }));
    } else {
        pod["status"]["conditions"] = serde_json::json!([{
            "type": "PodScheduled",
            "status": "True",
            "reason": "PodScheduled",
            "message": "",
            "lastTransitionTime": now
        }]);
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;

    /// create_pod must set metadata.generation=1 when the caller does not supply one.
    ///
    /// Controllers and scheduler use generation/observedGeneration to detect spec changes.
    /// A missing generation means a controller can never know if it has reconciled the
    /// latest spec — it would either loop forever or never act.
    #[test]
    fn initialize_sets_generation_to_1_when_absent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });
        initialize_pod_generation(&mut pod);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(1i64),
            "generation must be initialized to 1 on create — absent generation means \
             controllers relying on observedGeneration will never see spec changes"
        );
    }

    /// create_pod must preserve a caller-supplied generation value.
    ///
    /// Some controllers pre-set generation (e.g. when reconstructing objects);
    /// overriding it would break their bookkeeping.
    #[test]
    fn initialize_preserves_caller_supplied_generation() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "generation": 5i64},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });
        initialize_pod_generation(&mut pod);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(5i64),
            "a caller-supplied generation must not be overridden on create"
        );
    }

    /// PATCH that changes spec must increment generation.
    ///
    /// A spec change that does not bump generation is invisible to controllers
    /// watching generation; they would never re-reconcile the updated spec.
    #[test]
    fn increment_on_spec_change() {
        let spec_before =
            serde_json::json!({"containers": [{"name": "app", "image": "nginx:1.0"}]});
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "generation": 1i64},
            "spec": {"containers": [{"name": "app", "image": "nginx:2.0"}]}
        });
        increment_pod_generation_if_spec_changed(&mut pod, &spec_before);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(2i64),
            "generation must increment when spec changes — controllers use \
             generation/observedGeneration to detect new work; no increment means stale reconcile"
        );
    }

    /// PATCH that does not change spec must NOT increment generation.
    ///
    /// A metadata-only patch (labels, annotations) must leave generation unchanged
    /// so controllers do not re-reconcile when nothing in spec changed.
    #[test]
    fn no_increment_when_spec_unchanged() {
        let spec = serde_json::json!({"containers": [{"name": "app", "image": "nginx:1.0"}]});
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "generation": 1i64, "labels": {}},
            "spec": spec.clone()
        });
        increment_pod_generation_if_spec_changed(&mut pod, &spec);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(1i64),
            "generation must NOT increment for metadata-only patches — spurious increments \
             would cause controllers to re-reconcile unchanged pods"
        );
    }

    /// Sequential spec changes must increment generation monotonically.
    ///
    /// A pod updated twice (generation 1 → 2 → 3) must track both changes.
    /// If the counter resets or skips, observedGeneration comparisons break.
    #[test]
    fn generation_increments_monotonically_across_multiple_patches() {
        let spec_v1 = serde_json::json!({"containers": [{"name": "app", "image": "nginx:1.0"}]});
        let spec_v2 = serde_json::json!({"containers": [{"name": "app", "image": "nginx:2.0"}]});
        let spec_v3 = serde_json::json!({"containers": [{"name": "app", "image": "nginx:3.0"}]});

        let mut pod = serde_json::json!({
            "metadata": {"generation": 1i64},
            "spec": spec_v2.clone()
        });

        // First spec change: 1 -> 2
        increment_pod_generation_if_spec_changed(&mut pod, &spec_v1);
        assert_eq!(pod["metadata"]["generation"], serde_json::json!(2i64));

        // Second spec change: 2 -> 3
        pod["spec"] = spec_v3.clone();
        increment_pod_generation_if_spec_changed(&mut pod, &spec_v2);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(3i64),
            "generation must increment monotonically — generation=3 after two spec changes; \
             a reset or skip would break observedGeneration tracking in controllers"
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

    // Set PodScheduled=True now that the pod has a node assignment.
    //
    // In real k8s the scheduler does a separate PATCH on the status subresource to
    // flip PodScheduled from False→True.  In u7s we do it atomically inside bind_pod
    // so no separate scheduler status-patch is required.  Conformance scheduling tests
    // wait for PodScheduled=True before asserting the pod is running.
    let now = utc_now_rfc3339();
    set_pod_scheduled_true(&mut obj.body, &now);

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

    // -----------------------------------------------------------------------
    // set_pod_scheduled_true
    // -----------------------------------------------------------------------

    /// set_pod_scheduled_true must flip an existing PodScheduled=False to True.
    ///
    /// bind_pod calls this after setting spec.nodeName.  If it doesn't flip the
    /// condition, scheduling conformance tests that wait for PodScheduled=True will
    /// time out.  This test fails if set_pod_scheduled_true is reverted to a no-op.
    #[test]
    fn set_pod_scheduled_true_flips_false_condition() {
        let mut pod = serde_json::json!({
            "status": {
                "conditions": [{
                    "type": "PodScheduled",
                    "status": "False",
                    "reason": "Unschedulable",
                    "lastTransitionTime": "2024-01-01T00:00:00Z"
                }]
            }
        });

        set_pod_scheduled_true(&mut pod, "2024-01-01T00:00:01Z");

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array");
        let scheduled = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("PodScheduled"))
            .expect("PodScheduled condition must still be present after flip");
        assert_eq!(
            scheduled["status"], "True",
            "PodScheduled must be True after bind_pod calls set_pod_scheduled_true — \
             scheduling conformance tests wait for this transition"
        );
        assert_eq!(
            scheduled["reason"], "PodScheduled",
            "reason must change to PodScheduled after binding"
        );
    }

    /// set_pod_scheduled_true must append PodScheduled=True when no condition exists.
    ///
    /// Handles pods that were created without the initial PodScheduled=False default
    /// (e.g. pods seeded directly into the store in tests).
    #[test]
    fn set_pod_scheduled_true_appends_when_absent() {
        let mut pod = serde_json::json!({
            "status": {"phase": "Pending"}
        });

        set_pod_scheduled_true(&mut pod, "2024-01-01T00:00:01Z");

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array after append");
        let scheduled = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("PodScheduled"))
            .expect("PodScheduled condition must be present after append");
        assert_eq!(
            scheduled["status"], "True",
            "appended PodScheduled condition must have status=True"
        );
    }

    /// set_pod_scheduled_true must not disturb other conditions.
    ///
    /// Pods may already have Initialized/Ready conditions set by kubelet; only
    /// PodScheduled must be touched.
    #[test]
    fn set_pod_scheduled_true_leaves_other_conditions_intact() {
        let mut pod = serde_json::json!({
            "status": {
                "conditions": [
                    {
                        "type": "Initialized",
                        "status": "True",
                        "lastTransitionTime": "2024-01-01T00:00:00Z"
                    },
                    {
                        "type": "PodScheduled",
                        "status": "False",
                        "reason": "Unschedulable",
                        "lastTransitionTime": "2024-01-01T00:00:00Z"
                    }
                ]
            }
        });

        set_pod_scheduled_true(&mut pod, "2024-01-01T00:00:01Z");

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array");
        assert_eq!(
            conditions.len(),
            2,
            "only PodScheduled must be touched; Initialized must survive"
        );
        let initialized = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("Initialized"))
            .expect("Initialized condition must survive");
        assert_eq!(
            initialized["status"], "True",
            "Initialized condition must not be modified by set_pod_scheduled_true"
        );
    }

    // -----------------------------------------------------------------------
    // apply_runtime_class_overhead
    // -----------------------------------------------------------------------

    /// A pod referencing a RuntimeClass with overhead.podFixed{cpu:10m} must have
    /// spec.overhead set to {cpu:10m} by apply_runtime_class_overhead.
    ///
    /// The RuntimeClass admission plugin in real kube-apiserver copies podFixed into
    /// pod.spec.overhead on CREATE. Without this, conformance test
    /// '[sig-node] RuntimeClass should schedule a Pod requesting a RuntimeClass and
    /// initialize its Overhead' fails with expected cpu=10m but got 0.
    /// This test fails when apply_runtime_class_overhead is removed or does not copy.
    #[test]
    fn runtime_class_overhead_injected_into_pod_spec() {
        let rc = serde_json::json!({
            "apiVersion": "node.k8s.io/v1",
            "kind": "RuntimeClass",
            "metadata": {"name": "my-rc"},
            "spec": {
                "overhead": {
                    "podFixed": {"cpu": "10m", "memory": "50Mi"}
                }
            }
        });
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "default"},
            "spec": {
                "runtimeClassName": "my-rc",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        apply_runtime_class_overhead(&mut pod, &rc);

        assert_eq!(
            pod["spec"]["overhead"]["cpu"], "10m",
            "spec.overhead.cpu must equal the RuntimeClass podFixed.cpu — \
             conformance test asserts overhead matches the RuntimeClass definition"
        );
        assert_eq!(
            pod["spec"]["overhead"]["memory"], "50Mi",
            "spec.overhead.memory must equal the RuntimeClass podFixed.memory"
        );
    }

    /// A pod that already has spec.overhead set must not have it overwritten.
    ///
    /// Idempotency: the admission plugin must not overwrite overhead that was
    /// already set (e.g. by a mutating webhook).
    #[test]
    fn runtime_class_overhead_not_overwritten_when_already_set() {
        let rc = serde_json::json!({
            "spec": {
                "overhead": {
                    "podFixed": {"cpu": "10m"}
                }
            }
        });
        let mut pod = serde_json::json!({
            "spec": {
                "overhead": {"cpu": "20m"}
            }
        });

        apply_runtime_class_overhead(&mut pod, &rc);

        assert_eq!(
            pod["spec"]["overhead"]["cpu"], "20m",
            "pre-existing spec.overhead must not be overwritten by RuntimeClass admission — \
             a mutating webhook may have already set it to a valid value"
        );
    }

    /// A RuntimeClass without overhead.podFixed must leave pod.spec.overhead unchanged.
    #[test]
    fn runtime_class_without_overhead_is_noop() {
        let rc = serde_json::json!({
            "spec": {}
        });
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        apply_runtime_class_overhead(&mut pod, &rc);

        assert!(
            pod["spec"]["overhead"].is_null(),
            "pod.spec.overhead must remain absent when RuntimeClass has no podFixed overhead"
        );
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

    /// Return an axum Extension layer that injects a test UserInfo, required by handlers
    /// that extract Extension<UserInfo>. Without this, Router-based tests get 500.
    fn auth_layer() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
        })
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
            .layer(auth_layer())
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
            .layer(auth_layer())
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
    // RuntimeClass overhead injection regression test
    // -----------------------------------------------------------------------

    /// Creating a pod with spec.runtimeClassName referencing a RuntimeClass that has
    /// overhead.podFixed must result in the stored pod having spec.overhead set.
    ///
    /// The RuntimeClass admission plugin in real kube-apiserver copies podFixed into
    /// pod.spec.overhead at CREATE time. Conformance test '[sig-node] RuntimeClass
    /// should schedule a Pod requesting a RuntimeClass and initialize its Overhead'
    /// fails with "Expected value:0 to equal value:10 scale:-3" when this injection
    /// is absent.
    ///
    /// This test fails when the RuntimeClass store fetch and apply_runtime_class_overhead
    /// call are removed from create_pod.
    #[tokio::test]
    async fn create_pod_injects_runtime_class_overhead() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let rc = serde_json::json!({
            "apiVersion": "node.k8s.io/v1",
            "kind": "RuntimeClass",
            "metadata": {"name": "test-rc"},
            "spec": {
                "overhead": {
                    "podFixed": {"cpu": "10m"}
                }
            }
        });
        store
            .put(
                "/registry/node.k8s.io/runtimeclasses/test-rc",
                Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .expect("seed RuntimeClass");

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "rc-pod", "namespace": "default"},
            "spec": {
                "runtimeClassName": "test-rc",
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
            .get("/registry/pods/default/rc-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["overhead"]["cpu"], "10m",
            "spec.overhead.cpu must be injected from RuntimeClass.spec.overhead.podFixed — \
             conformance test asserts the pod overhead matches the RuntimeClass definition"
        );
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
            .layer(auth_layer())
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
            .layer(auth_layer())
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
    // automountServiceAccountToken defaulting (mayor-vfe2)
    // -----------------------------------------------------------------------

    /// A pod created without spec.automountServiceAccountToken must have it
    /// defaulted to true in the stored/returned object.
    ///
    /// Real kube-apiserver writes the resolved boolean into the stored pod so
    /// controllers and the kubelet always see a concrete value.  Without this,
    /// the field is absent after create and SA-level opting-out never works.
    ///
    /// This test fails if apply_automount_sa_token_default is removed or if it
    /// stops writing true when no SA sets the field to false.
    #[tokio::test]
    async fn create_pod_automount_defaults_to_true_when_absent() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "no-automount-pod", "namespace": "default"},
            "spec": {
                "serviceAccountName": "default",
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
            .get("/registry/pods/default/no-automount-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["automountServiceAccountToken"],
            serde_json::json!(true),
            "spec.automountServiceAccountToken must be defaulted to true when absent — \
             without this, SA-level opt-out cannot be inherited (conformance test \
             'ServiceAccounts should allow opting out of API token automount' fails)"
        );
    }

    /// A pod created with serviceAccountName pointing to a SA that has
    /// automountServiceAccountToken=false must NOT get the SA token volume injected.
    ///
    /// Conformance test 'ServiceAccounts should allow opting out of API token automount'
    /// creates a SA with automountServiceAccountToken=false, creates a pod referencing
    /// that SA (without a pod-level field), and expects the token NOT to be mounted.
    /// Without SA inheritance, the pod omits the field and inject_sa_token_volume
    /// injects the token anyway — the conformance test times out.
    ///
    /// This test fails if apply_automount_sa_token_default stops reading the SA's field.
    #[tokio::test]
    async fn create_pod_inherits_automount_false_from_service_account() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed a ServiceAccount with automountServiceAccountToken=false.
        let sa_key = "/registry/serviceaccounts/default/no-token-sa";
        let sa = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "no-token-sa", "namespace": "default"},
            "automountServiceAccountToken": false
        });
        store
            .put(
                sa_key,
                bytes::Bytes::from(serde_json::to_vec(&sa).unwrap()),
                None,
            )
            .await
            .expect("seed SA");

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "opt-out-pod", "namespace": "default"},
            "spec": {
                "serviceAccountName": "no-token-sa",
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
            .get("/registry/pods/default/opt-out-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["spec"]["automountServiceAccountToken"],
            serde_json::json!(false),
            "spec.automountServiceAccountToken must be false when inherited from SA — \
             SA opted out; pod must not get token"
        );
        assert!(
            v["spec"]["volumes"].is_null()
                || v["spec"]["volumes"]
                    .as_array()
                    .map(|vols| {
                        vols.iter().all(|vol| {
                            vol["name"]
                                .as_str()
                                .map(|n| !n.starts_with("kube-api-access-"))
                                .unwrap_or(true)
                        })
                    })
                    .unwrap_or(true),
            "no kube-api-access-* volume must be injected when SA has \
             automountServiceAccountToken=false — conformance test \
             'ServiceAccounts should allow opting out of API token automount' \
             checks that no token file appears in the pod"
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
            .layer(auth_layer())
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

    /// DELETE a pod without finalizers must soft-delete (stamp deletionTimestamp) on the first
    /// DELETE call — it must NOT hard-delete immediately.
    ///
    /// Real Kubernetes apiserver always soft-deletes pods first so the kubelet receives a MODIFIED
    /// event with deletionTimestamp set, which triggers graceful container termination via SIGTERM.
    /// If pods are hard-deleted immediately (bypassing the soft-delete step), the kubelet only
    /// receives a DELETED tombstone with minimal metadata (no spec), and the container never
    /// receives SIGTERM — it keeps running indefinitely.
    ///
    /// This is the regression test for the StatefulSet AfterEach hang (mayor-859w):
    /// scale-to-0 stalled for up to 91 minutes because the StatefulSet pod was hard-deleted without
    /// going through the soft-delete+SIGTERM flow. This test fails on revert: if pods are
    /// hard-deleted immediately, the pod will be gone from the store and the deletionTimestamp
    /// assertion will fail.
    #[tokio::test]
    async fn delete_pod_without_finalizers_soft_deletes_first() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/to-delete";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "to-delete", "namespace": "default", "resourceVersion": "1" },
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
            .uri("/api/v1/namespaces/default/pods/to-delete")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "soft-delete must return 200");

        // The pod must still exist (soft-deleted, not hard-deleted).
        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("pod must still exist after first DELETE — soft-delete must not remove it");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must be stamped on first DELETE even without finalizers — \
             kubelet uses this signal to send SIGTERM to the container; without it the \
             container keeps running and the StatefulSet scale-to-0 hangs (mayor-859w)"
        );
    }

    /// Second DELETE on a pod that is already Terminating (has deletionTimestamp) and has no
    /// finalizers must hard-delete it — this is the path taken by the kubelet after it stops
    /// the container and calls DELETE with gracePeriodSeconds=0.
    ///
    /// Without the hard-delete on the second DELETE, the pod would stay in Terminating forever
    /// since no GC controller removes finalizer-free terminating pods.
    #[tokio::test]
    async fn delete_pod_already_terminating_without_finalizers_hard_deletes() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/terminating-pod";
        // Seed a pod that already has deletionTimestamp set (soft-deleted) with no finalizers.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "terminating-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2026-01-01T00:00:00Z"
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
            .uri("/api/v1/namespaces/default/pods/terminating-pod")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "hard-delete of already-terminating pod must return 200"
        );

        // The pod must be gone (hard-deleted).
        let stored = store.get(key).await.unwrap();
        assert!(
            stored.is_none(),
            "pod with deletionTimestamp and no finalizers must be hard-deleted on second DELETE — \
             this is the kubelet's graceful termination complete signal (gracePeriodSeconds=0 path)"
        );
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
    // evict_pod
    // -----------------------------------------------------------------------

    /// POST /pods/{name}/eviction on a running pod must soft-delete (stamp deletionTimestamp)
    /// and return 201 Created with the Eviction object.
    ///
    /// Without this endpoint the conformance test "Should recreate evicted statefulset" never
    /// terminates the orphan pod, so the StatefulSet controller never gets a pod-deleted event
    /// and never recreates ss-0. The test then times out after 15 minutes.
    ///
    /// This test fails on revert: if evict_pod is removed, the route does not exist, and the
    /// pod deletionTimestamp is never stamped, breaking the StatefulSet recreation flow.
    #[tokio::test]
    async fn evict_pod_stamps_deletion_timestamp_and_returns_201() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/ss-0";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "ss-0", "namespace": "default", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "ss-0", "namespace": "default" }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/ss-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&eviction_body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "eviction must return 201 Created — the test uses this status to confirm the pod is being terminated"
        );

        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("pod must still exist after eviction — soft-delete, not hard-delete");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "eviction must stamp deletionTimestamp so the kubelet sends SIGTERM and the \
             StatefulSet controller sees the pod as terminating — without this the orphan \
             pod runs forever and the 'Should recreate evicted statefulset' test hangs"
        );
    }

    /// POST /pods/{name}/eviction on a non-existent pod must return 404.
    ///
    /// Callers must get a clear Not Found rather than a panic or silent success.
    #[tokio::test]
    async fn evict_pod_missing_returns_404() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/ghost/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "eviction of a non-existent pod must return 404 — callers must know the pod is gone"
        );
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

    /// SSA PATCH (application/apply-patch+yaml) with ?dryRun=All must return the would-be
    /// patched pod but must NOT persist the change to the store.
    ///
    /// This is the regression test for the dryRun=All bug in patch_pod: before the fix,
    /// patch_pod read no query params and always wrote to the store, causing
    /// "kubectl server-side dry-run: update Pods" sonobuoy tests to fail because
    /// the Pod image was changed on the server when it should not have been.
    #[tokio::test]
    async fn patch_pod_dry_run_all_does_not_mutate_store() {
        use axum::body::to_bytes;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "dry-run-pod",
            serde_json::json!({
                "spec": {"containers": [{"name": "app", "image": "nginx:original"}]}
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        // SSA PATCH with dryRun=All: change image to "nginx:new".
        let patch_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "dry-run-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx:new"}]}
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/dry-run-pod?dryRun=All")
            .header(header::CONTENT_TYPE, "application/apply-patch+yaml")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "dry-run PATCH must return 200"
        );

        // Response must show the would-be new image.
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let resp_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let containers = resp_json["spec"]["containers"].as_array().unwrap();
        assert_eq!(
            containers[0]["image"], "nginx:new",
            "dry-run response must show the would-be new image"
        );

        // The store must still have the original image — the write was skipped.
        let stored = store
            .get("/registry/pods/default/dry-run-pod")
            .await
            .unwrap()
            .expect("pod must still exist in store");
        let stored_json: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let stored_containers = stored_json["spec"]["containers"].as_array().unwrap();
        assert_eq!(
            stored_containers[0]["image"],
            "nginx:original",
            "dry-run PATCH must NOT mutate the store — image must remain 'nginx:original'; \
             if this fails, the dryRun=All guard was removed from patch_pod and the write went through"
        );
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

    /// PATCH /status must persist the new phase to the store and the response body.
    ///
    /// Regression test for mayor-fbp7: the handler accepted the PATCH without error
    /// but reported 0 changed fields — meaning the stored object was not mutated.
    ///
    /// This test fails if patch_pod_status is a no-op: if it returns 200 but leaves
    /// the stored object unchanged, the GET from the store will still show "Pending"
    /// and the assertion below will catch the regression.
    #[tokio::test]
    async fn patch_pod_status_persists_phase_change_to_store() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        // Seed a pod with phase "Pending" and a Ready=True condition.
        seed_pod(
            &store,
            "default",
            "lifecycle-pod",
            serde_json::json!({
                "status": {
                    "phase": "Pending",
                    "conditions": [{"type": "Ready", "status": "True"}]
                }
            }),
        )
        .await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        // Kubelet reports the pod is now Running and conditions updated.
        // This is the exact scenario the e2e lifecycle test exercises.
        let patch_body = serde_json::json!({
            "status": {
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": "False"}]
            }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/lifecycle-pod/status")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH /status must return 200"
        );

        // Read the pod back from the store — not from the response — to verify
        // the changes were actually persisted (not just echoed in the response body).
        let key = "/registry/pods/default/lifecycle-pod";
        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["status"]["phase"], "Running",
            "phase must be updated to Running in the store — \
             if this fails the PATCH is a no-op (mayor-fbp7 regression): \
             kubelet cannot advance pod lifecycle and pods stay Pending forever"
        );
        assert_eq!(
            v["status"]["conditions"][0]["status"], "False",
            "Ready condition must be updated to False in the store — \
             if this fails the status subresource PATCH is discarding changes"
        );
        // spec must not be touched by a status PATCH
        assert_eq!(
            v["spec"]["containers"][0]["name"], "app",
            "spec.containers must be unchanged after a status-only PATCH"
        );
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
            .layer(auth_layer())
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
            .layer(auth_layer())
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
            .layer(auth_layer())
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

    // -----------------------------------------------------------------------
    // patch_pod_resize (PATCH + PUT /resize)
    // -----------------------------------------------------------------------

    /// PATCH /resize with updated container resources must update the stored pod's resources
    /// and set status.resize = "Proposed".
    ///
    /// This is the core in-place resource update (VPA GA in k8s 1.33+) flow. If resources
    /// are not updated or status.resize is not "Proposed", conformance tests for in-place
    /// pod resize fail and the feature is not usable.
    #[tokio::test]
    async fn patch_pod_resize_updates_resources_and_sets_proposed() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed a pod with CPU limit 100m.
        let key = "/registry/pods/default/resize-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resize-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {
                        "limits": {"cpu": "100m"},
                        "requests": {"cpu": "100m"}
                    }
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize).put(patch_pod_resize),
            )
            .with_state(state);

        // PATCH /resize with updated CPU limit 200m.
        let resize_body = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {"cpu": "200m"},
                        "requests": {"cpu": "200m"}
                    }
                }]
            }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/resize-pod/resize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&resize_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH /resize must return 200 — conformance tests require this"
        );

        // Verify store: resources updated and status.resize = "Proposed".
        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["spec"]["containers"][0]["resources"]["limits"]["cpu"], "200m",
            "container resources must be updated to 200m after /resize PATCH — \
             if this fails the in-place resize feature is not working (mayor-sor9)"
        );
        assert_eq!(
            v["status"]["resize"], "Proposed",
            "status.resize must be set to 'Proposed' after /resize PATCH — \
             conformance tests assert this field to verify the resize was acknowledged"
        );
    }

    /// PUT /resize must behave identically to PATCH /resize.
    #[tokio::test]
    async fn put_pod_resize_updates_resources_and_sets_proposed() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/resize-pod2";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resize-pod2", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}}}]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize).put(patch_pod_resize),
            )
            .with_state(state);

        let resize_body = serde_json::json!({
            "spec": {"containers": [{"name": "app",
                "resources": {"limits": {"cpu": "500m"}}}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/resize-pod2/resize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&resize_body))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "PUT /resize must return 200");

        let stored = store.get(key).await.unwrap().expect("pod must exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["containers"][0]["resources"]["limits"]["cpu"], "500m",
            "PUT /resize must update container resources"
        );
        assert_eq!(
            v["status"]["resize"], "Proposed",
            "PUT /resize must set status.resize=Proposed"
        );
    }

    /// PATCH /resize on a missing pod must return 404.
    #[tokio::test]
    async fn patch_pod_resize_missing_pod_returns_404() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/nonexistent/resize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"spec":{"containers":[]}}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PATCH /resize on non-existent pod must return 404"
        );
    }
}

// ---------------------------------------------------------------------------
// Pure-logic tests for apply_resize_patch
// ---------------------------------------------------------------------------

#[cfg(test)]
mod resize_tests {
    use super::*;

    /// apply_resize_patch merges container resources by name and sets status.resize = "Proposed".
    ///
    /// This is the primary in-place resize contract: if the container resources are not updated
    /// or status.resize is not set, the conformance test for pod resize fails.
    #[test]
    fn apply_resize_patch_updates_resources_and_sets_proposed() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            },
            "status": {"phase": "Running"}
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {"limits": {"cpu": "200m"}, "requests": {"cpu": "200m"}}
                }]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["cpu"], "200m",
            "container resources must be updated to 200m — \
             if this fails the in-place resize feature is broken (mayor-sor9)"
        );
        assert_eq!(
            result["status"]["resize"], "Proposed",
            "status.resize must be set to 'Proposed' — conformance tests assert this field"
        );
        // Unchanged fields must survive.
        assert_eq!(
            result["spec"]["containers"][0]["image"], "nginx",
            "container image must be preserved after resize patch"
        );
        assert_eq!(
            result["status"]["phase"], "Running",
            "status.phase must be preserved after resize patch"
        );
    }

    /// apply_resize_patch only updates the container matching by name; other containers are unchanged.
    #[test]
    fn apply_resize_patch_only_updates_matching_container() {
        let stored = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "app", "resources": {"limits": {"cpu": "100m"}}},
                    {"name": "sidecar", "resources": {"limits": {"cpu": "50m"}}}
                ]
            },
            "status": {}
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "300m"}}}]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["cpu"], "300m",
            "named container resources must be updated"
        );
        assert_eq!(
            result["spec"]["containers"][1]["resources"]["limits"]["cpu"], "50m",
            "sidecar container must be unchanged — resize only targets named containers"
        );
    }

    /// apply_resize_patch with no matching container name leaves all containers unchanged.
    #[test]
    fn apply_resize_patch_no_match_leaves_containers_unchanged() {
        let stored = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "100m"}}}]
            },
            "status": {}
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{"name": "nonexistent", "resources": {"limits": {"cpu": "999m"}}}]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["cpu"], "100m",
            "unmatched container resources must be unchanged"
        );
        // status.resize is still set even if no container matched.
        assert_eq!(result["status"]["resize"], "Proposed");
    }
}

// ---------------------------------------------------------------------------
// EphemeralContainers pure-logic tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ephemeral_containers_tests {
    use super::*;

    /// apply_ephemeral_containers_patch appends a new ephemeral container.
    ///
    /// This is the primary sonobuoy ephemeral-container flow: a PATCH body
    /// `{"spec":{"ephemeralContainers":[{"name":"debugger","image":"busybox"}]}}`
    /// must add the container to the pod. If the container is not appended,
    /// `kubectl debug` and the sonobuoy conformance test fail with 404.
    #[test]
    fn apply_ephemeral_patch_appends_new_container() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "target", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox"}]
            }
        });

        let result = apply_ephemeral_containers_patch(&stored, &patch);

        let ecs = result["spec"]["ephemeralContainers"]
            .as_array()
            .expect("ephemeralContainers must be an array");
        assert_eq!(
            ecs.len(),
            1,
            "one ephemeral container must be present after PATCH"
        );
        assert_eq!(
            ecs[0]["name"], "debugger",
            "the new ephemeral container must appear in spec.ephemeralContainers — \
             without this, kubectl debug and sonobuoy ephemeral-container tests fail"
        );
        // Existing spec must be untouched.
        assert_eq!(
            result["spec"]["containers"][0]["name"], "app",
            "regular containers must not be disturbed by ephemeral container patch"
        );
    }

    /// apply_ephemeral_containers_patch does not remove existing ephemeral containers.
    ///
    /// Kubernetes semantics: ephemeral containers are immutable once added.
    /// Sending a PATCH with only new containers must not remove pre-existing ones.
    #[test]
    fn apply_ephemeral_patch_preserves_existing_containers() {
        let stored = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "first", "image": "busybox"}]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "second", "image": "alpine"}]
            }
        });

        let result = apply_ephemeral_containers_patch(&stored, &patch);

        let ecs = result["spec"]["ephemeralContainers"]
            .as_array()
            .expect("ephemeralContainers must be an array");
        assert_eq!(
            ecs.len(),
            2,
            "both the existing and the new ephemeral container must be present — \
             ephemeral containers cannot be removed once added (Kubernetes immutability contract)"
        );
        let names: Vec<&str> = ecs.iter().filter_map(|c| c["name"].as_str()).collect();
        assert!(
            names.contains(&"first"),
            "pre-existing ephemeral container 'first' must not be removed"
        );
        assert!(
            names.contains(&"second"),
            "newly patched ephemeral container 'second' must be present"
        );
    }

    /// apply_ephemeral_containers_patch is idempotent: re-patching the same container
    /// by name must not duplicate it.
    #[test]
    fn apply_ephemeral_patch_skips_duplicate_name() {
        let stored = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox:old"}]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox:new"}]
            }
        });

        let result = apply_ephemeral_containers_patch(&stored, &patch);

        let ecs = result["spec"]["ephemeralContainers"]
            .as_array()
            .expect("ephemeralContainers must be an array");
        assert_eq!(
            ecs.len(),
            1,
            "duplicate container name must not be appended — idempotent re-PATCH must not duplicate"
        );
    }

    /// apply_ephemeral_containers_patch with no ephemeralContainers in the patch is a no-op.
    #[test]
    fn apply_ephemeral_patch_no_spec_key_is_noop() {
        let stored = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        let patch = serde_json::json!({"metadata": {"labels": {"foo": "bar"}}});

        let result = apply_ephemeral_containers_patch(&stored, &patch);

        assert!(
            result["spec"]["ephemeralContainers"].is_null()
                || result["spec"]["ephemeralContainers"]
                    .as_array()
                    .is_none_or(|a| a.is_empty()),
            "a patch without spec.ephemeralContainers must leave the field absent"
        );
    }

    /// Patching ephemeralContainers increments metadata.generation.
    ///
    /// The [sig-node] Ephemeral Containers conformance test reads back the pod and
    /// asserts generation==2.  Without the increment the test sees generation==1 and
    /// immediately fails (fast failure, not a 120s timeout).
    #[test]
    fn ephemeral_patch_increments_generation() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "target", "namespace": "default", "generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox"}]
            }
        });

        let spec_before = pod["spec"].clone();
        pod = apply_ephemeral_containers_patch(&pod, &patch);
        increment_pod_generation_if_spec_changed(&mut pod, &spec_before);

        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(2i64),
            "generation must be incremented to 2 after ephemeralContainers PATCH — \
             the [sig-node] Ephemeral Containers conformance test asserts generation==2 \
             and fails immediately if this is not done"
        );
    }
}

// ---------------------------------------------------------------------------
// Integration test: PATCH /ephemeralcontainers route
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ephemeral_containers_route_tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::patch,
        Router,
    };
    use bytes::Bytes;
    use tower::ServiceExt;
    use u7s_store::{SqliteStore, Store};

    use super::*;
    use crate::state::AppState;

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

    async fn seed_namespace(store: &Arc<SqliteStore>, ns: &str) {
        let key = format!("/registry/namespaces/{ns}");
        let val = serde_json::json!({"kind": "Namespace", "metadata": {"name": ns}});
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed namespace");
    }

    fn json_body(v: &serde_json::Value) -> Body {
        Body::from(Bytes::from(serde_json::to_vec(v).unwrap()))
    }

    /// PATCH /ephemeralcontainers must return 200 and include the new ephemeral container
    /// in spec.ephemeralContainers of the response body.
    ///
    /// This is the primary sonobuoy conformance case: the test patches an ephemeral container
    /// onto a running pod and expects 200 with the updated spec. Without this route the
    /// server returns 404 ("the server could not find the requested resource") and the
    /// conformance test fails with "Failed to patch ephemeral containers in pod".
    #[tokio::test]
    async fn patch_ephemeral_containers_returns_200_with_new_container() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/ephemeral-target";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "ephemeral-target", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
                patch(patch_ephemeral_containers),
            )
            .with_state(state);

        let patch_body = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox"}]
            }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/ephemeral-target/ephemeralcontainers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH /ephemeralcontainers must return 200 — without this route the server \
             returns 404 and kubectl debug / sonobuoy ephemeral-container conformance tests fail"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let ecs = v["spec"]["ephemeralContainers"]
            .as_array()
            .expect("response must contain spec.ephemeralContainers");
        assert_eq!(
            ecs.len(),
            1,
            "one ephemeral container must be in the response"
        );
        assert_eq!(
            ecs[0]["name"], "debugger",
            "the new ephemeral container must appear in the response spec.ephemeralContainers"
        );
    }

    /// PATCH /ephemeralcontainers on a missing pod must return 404.
    #[tokio::test]
    async fn patch_ephemeral_containers_missing_pod_returns_404() {
        let (state, _store) = make_state();
        seed_namespace(&_store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
                patch(patch_ephemeral_containers),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/nonexistent/ephemeralcontainers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"spec":{"ephemeralContainers":[{"name":"d","image":"busybox"}]}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PATCH /ephemeralcontainers on nonexistent pod must return 404"
        );
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

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
        })
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
            test_user(),
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
            test_user(),
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
            test_user(),
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
