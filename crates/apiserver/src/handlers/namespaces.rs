use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store, StoreError};

use crate::{
    admission::{run_mutating_webhooks, run_validating_webhooks, AdmissionContext},
    auth::UserInfo,
    handlers::{
        generic::apply_delete_policy,
        json_patch::{apply_json_patch, detect_patch_type, PatchQuery, PatchType},
        resource::{do_patch, PatchConfig},
    },
    keys::{cluster_list_prefix, cluster_object_key},
    proto,
    state::AppState,
    status::Status,
    types::{NamespacePhase, NamespaceSpec, NamespaceStatus, Object, ObjectMeta, ResourceMeta},
    util::{content_type, extract_body, parse_resource_version, utc_now_rfc3339},
};

/// Validate a namespace name: lowercase alphanumeric + hyphens, 1–63 chars.
/// Returns Err with 422 if invalid.
fn validate_namespace_name(name: &str) -> Result<(), crate::status::StatusError> {
    if name.is_empty() || name.len() > 63 {
        return Err(Status::unprocessable_entity(format!(
            "invalid namespace name '{name}': must be 1–63 characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Status::unprocessable_entity(format!(
            "invalid namespace name '{name}': must match [a-z0-9-]+"
        )));
    }
    Ok(())
}

fn store_err_to_status(err: StoreError, name: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, "Namespace"),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, "Namespace"),
        StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "Namespace \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => Status::internal(other.to_string()),
    }
}

pub async fn list_namespaces<S: Store>(
    State(state): State<AppState<S>>,
    Query(query): Query<super::generic::CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    let prefix = cluster_list_prefix("namespaces");

    if query.watch == Some(true) {
        let initial = super::watch::fetch_initial_events(
            &state,
            &prefix,
            query.send_initial_events == Some(true),
        )
        .await?;
        return super::watch::watch_generic(
            state,
            super::watch::WatchConfig {
                prefix,
                api_version: "v1".to_string(),
                kind: "Namespace".to_string(),
                from_revision: query.resource_version.unwrap_or(0),
                initial_items: initial,
                label_selector: query.label_selector,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username: user.username,
                as_partial_object_metadata: false,
                group: "".to_string(),
                plural: "namespaces".to_string(),
                timeout_seconds: query.timeout_seconds,
            },
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

    let body = serde_json::json!({
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items
    });

    Ok(Json(body).into_response())
}

pub async fn create_namespace<S: Store>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Decode the request body. When kubectl sends Content-Type:
    // application/vnd.kubernetes.protobuf, the body is a k8s Unknown envelope. For core types
    // like Namespace, Unknown.raw is proto-encoded (contentType = protobuf), not JSON. We decode
    // the envelope to check the inner content-type and, if needed, decode the nested proto bytes
    // using the Namespace-specific decoder.
    let mut obj = if ct.starts_with("application/vnd.kubernetes.protobuf") {
        match proto::decode_k8s_proto_envelope(&body) {
            Some(env) if env.content_type == "application/json" => {
                // Inner bytes are explicitly JSON — parse normally.
                let b = bytes::Bytes::from(env.raw);
                Object::from_bytes(&b)
                    .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?
            }
            Some(env) => {
                // Inner bytes are proto-encoded. kubectl sends contentType="" (empty) with a
                // proto-encoded Namespace in Unknown.raw — not JSON. Decode using the
                // Namespace-specific proto decoder; fall back to JSON only if proto fails.
                match proto::decode_namespace_proto(&env.raw) {
                    Some(json_val) => Object { body: json_val },
                    None => Object::from_bytes(&bytes::Bytes::from(env.raw))
                        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?,
                }
            }
            None => {
                // Not a valid k8s proto envelope — fall back to raw JSON parse.
                Object::from_bytes(&body)
                    .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?
            }
        }
    } else {
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?
    };

    let name = {
        match obj.name().filter(|n| !n.is_empty()) {
            Some(n) => n.to_string(),
            None => {
                let meta: ObjectMeta =
                    serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
                let gen = meta.generate_name.as_deref().unwrap_or("");
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

    validate_namespace_name(&name)?;

    // Ensure kind/apiVersion and status are set
    if obj.body.get("kind").is_none() {
        obj.body["kind"] = serde_json::Value::String("Namespace".into());
    }
    if obj.body.get("apiVersion").is_none() {
        obj.body["apiVersion"] = serde_json::Value::String("v1".into());
    }
    if obj.body["status"].is_null() || obj.body.get("status").is_none() {
        obj.body["status"] = serde_json::to_value(NamespaceStatus {
            phase: Some(NamespacePhase::Active),
            rest: serde_json::Value::Object(Default::default()),
        })
        .map_err(|e| Status::internal(format!("failed to serialize NamespaceStatus: {e}")))?;
    }

    // Stamp the "kubernetes" finalizer into spec.finalizers at creation time.
    //
    // Kubernetes namespace finalizers live in spec.finalizers, not metadata.finalizers.
    // The upstream KCM namespace controller reads spec.finalizers to decide whether to
    // drain a namespace before hard-deleting it. Stamping at creation (rather than
    // relying on an async controller ADDED event) ensures every namespace always goes
    // through the drain lifecycle even if the controller is behind.
    {
        let mut spec: NamespaceSpec =
            serde_json::from_value(obj.body["spec"].clone()).unwrap_or_default();
        let has_k8s = spec
            .finalizers
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|f| f == "kubernetes");
        if !has_k8s {
            spec.finalizers
                .get_or_insert_with(Vec::new)
                .push("kubernetes".to_owned());
            obj.body["spec"] = serde_json::to_value(spec)
                .map_err(|e| Status::internal(format!("failed to serialize NamespaceSpec: {e}")))?;
        }
    }

    // Assign a UID if none provided — required for owner references and garbage collection.
    {
        let meta: ObjectMeta =
            serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
        if meta.uid.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
            obj.body["metadata"]["uid"] =
                serde_json::Value::String(uuid::Uuid::new_v4().to_string());
        }
    }

    {
        let meta: ObjectMeta =
            serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
        if meta.creation_timestamp.is_none() {
            obj.body["metadata"]["creationTimestamp"] =
                serde_json::Value::String(utc_now_rfc3339());
        }
    }

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "namespaces",
        name: &name,
        namespace: None,
        operation: "CREATE",
    };
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

    let key = cluster_object_key("namespaces", &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), Some(0))
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok((StatusCode::CREATED, Json(obj.body)))
}

pub async fn get_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
) -> Result<Response, crate::status::StatusError> {
    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn replace_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
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

    // Post-replace: if deletionTimestamp is set and spec.finalizers are empty, hard-delete.
    let replace_meta: ObjectMeta =
        serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
    let deletion_ts_set = replace_meta.deletion_timestamp.is_some();
    let replace_spec: NamespaceSpec =
        serde_json::from_value(obj.body["spec"].clone()).unwrap_or_default();
    let finalizers_empty = replace_spec
        .finalizers
        .as_deref()
        .map(|f| f.is_empty())
        .unwrap_or(true);

    let key = cluster_object_key("namespaces", &name);
    if deletion_ts_set && finalizers_empty {
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
        return Ok(Json(obj.body).into_response());
    }

    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok(Json(obj.body).into_response())
}

pub async fn patch_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    Query(patch_query): Query<PatchQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = content_type(&headers);

    if ct.contains("application/apply-patch+yaml") {
        let ns_meta = ResourceMeta {
            kind: "Namespace".to_string(),
            #[cfg(test)]
            namespaced: false,
            has_status_subresource: true,
            create_or_update: false,
        };
        let key = cluster_object_key("namespaces", &name);
        return do_patch(
            &state,
            PatchConfig {
                key: &key,
                meta: &ns_meta,
                group: "",
                version: "v1",
                plural: "namespaces",
                ns: None,
                name: &name,
                is_ssa: true,
                field_manager: patch_query.field_manager.as_deref(),
                patch_type: PatchType::StrategicMerge,
                body,
            },
        )
        .await;
    }

    if !ct.contains("application/merge-patch+json")
        && !ct.contains("application/strategic-merge-patch+json")
    {
        return Err(Status::unsupported_media_type(format!(
            "unsupported media type '{ct}'; use application/merge-patch+json"
        )));
    }

    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    crate::patch::merge_patch(&mut current.body, &patch);

    // Post-patch: if deletionTimestamp is set and spec.finalizers are empty, hard-delete.
    let current_meta: ObjectMeta =
        serde_json::from_value(current.body["metadata"].clone()).unwrap_or_default();
    let deletion_ts_set = current_meta.deletion_timestamp.is_some();
    let patch_spec: NamespaceSpec =
        serde_json::from_value(current.body["spec"].clone()).unwrap_or_default();
    let finalizers_empty = patch_spec
        .finalizers
        .as_deref()
        .map(|f| f.is_empty())
        .unwrap_or(true);

    if deletion_ts_set && finalizers_empty {
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
        return Ok(Json(current.body).into_response());
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current.set_resource_version(new_rv);

    Ok(Json(current.body).into_response())
}

/// PUT /api/v1/namespaces/{name}/finalize
///
/// Implements the Kubernetes namespace finalize subresource. The upstream
/// kube-controller-manager namespace controller calls this after draining all
/// resources from the namespace to remove the "kubernetes" finalizer. Unlike a
/// full PUT, this endpoint only updates spec.finalizers (stored as
/// metadata.finalizers). If deletionTimestamp is set and finalizers are now
/// empty, the namespace is hard-deleted.
pub async fn finalize_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Parse the finalizers from the request body.
    // KCM sends the finalizers in spec.finalizers. We also accept metadata.finalizers
    // as a fallback for clients that write the field in standard metadata position.
    let req: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // KCM writes spec.finalizers; fall back to metadata.finalizers.
    let new_finalizers =
        if !req["spec"]["finalizers"].is_null() && req["spec"].get("finalizers").is_some() {
            req["spec"]["finalizers"].clone()
        } else {
            req["metadata"]["finalizers"].clone()
        };

    // Fetch the current namespace from the store.
    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // Namespace finalizers live in spec.finalizers (not metadata.finalizers).
    // Ensure spec exists before writing.
    if current.body.get("spec").is_none() || current.body["spec"].is_null() {
        current.body["spec"] = serde_json::json!({});
    }
    current.body["spec"]["finalizers"] = new_finalizers;

    // Check: if deletionTimestamp is set and spec.finalizers are now empty → hard-delete.
    let current_meta: ObjectMeta =
        serde_json::from_value(current.body["metadata"].clone()).unwrap_or_default();
    let deletion_ts_set = current_meta.deletion_timestamp.is_some();
    let current_spec: NamespaceSpec =
        serde_json::from_value(current.body["spec"].clone()).unwrap_or_default();
    let finalizers_empty = current_spec
        .finalizers
        .as_deref()
        .map(|f| f.is_empty())
        .unwrap_or(true);

    if deletion_ts_set && finalizers_empty {
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
        return Ok(Json(current.body).into_response());
    }

    // Finalizers remain — persist the updated object and return it.
    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current.set_resource_version(new_rv);

    Ok(Json(current.body).into_response())
}

/// GET /api/v1/namespaces/{name}/status
///
/// Returns the full namespace object. Status is embedded, not a separate subresource store.
pub async fn get_namespace_status<S: Store>(
    state: State<AppState<S>>,
    Path(name): Path<String>,
) -> Result<Response, crate::status::StatusError> {
    get_namespace(state, Path(name)).await
}

/// PUT /api/v1/namespaces/{name}/status
///
/// Replaces only the status field of a namespace. The KCM namespace controller calls this
/// to set status.conditions (e.g. NamespaceDeletionContentFailure) during namespace deletion.
pub async fn put_namespace_status<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let incoming =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

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
        .map_err(|e| store_err_to_status(e, &name))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

/// PATCH /api/v1/namespaces/{name}/status
///
/// Patches only the status field of a namespace. Supports merge-patch, strategic-merge-patch,
/// and json-patch. The KCM namespace controller uses strategic-merge-patch to update conditions.
pub async fn patch_namespace_status<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = detect_patch_type(&headers)?;

    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    match patch_type {
        PatchType::Json => {
            apply_json_patch(&mut current.body, &patch)?;
        }
        _ => {
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
        .map_err(|e| store_err_to_status(e, &name))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

pub async fn delete_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let key = cluster_object_key("namespaces", &name);

    // Fetch current to check finalizers.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    if let Some(mut soft) = apply_delete_policy(&mut obj) {
        // Soft-delete: set phase=Terminating, persist, return the namespace object.
        soft["status"] = serde_json::to_value(NamespaceStatus {
            phase: Some(NamespacePhase::Terminating),
            rest: serde_json::Value::Object(Default::default()),
        })
        .map_err(|e| Status::internal(format!("failed to serialize NamespaceStatus: {e}")))?;
        obj.body = soft;
        let expected_rv = parse_resource_version(obj.resource_version())?;
        let new_rv = state
            .store
            .put(&key, obj.to_bytes(), expected_rv)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
        obj.set_resource_version(new_rv);
        return Ok(Json(obj.body).into_response());
    }

    // No finalizers — hard-delete immediately.
    // Cascade-delete all resources in the namespace first so that re-creating
    // a namespace with the same name does not inherit orphaned objects and
    // cause false 409 AlreadyExists errors on subsequent POSTs.
    if let Err(e) = state.store.delete_namespace_resources(&name).await {
        tracing::warn!("namespace {name}: cascade delete failed: {e}");
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
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_namespace_names() {
        assert!(validate_namespace_name("default").is_ok());
        assert!(validate_namespace_name("kube-system").is_ok());
        assert!(validate_namespace_name("a").is_ok());
        assert!(validate_namespace_name(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn invalid_namespace_names() {
        // empty
        assert!(validate_namespace_name("").is_err());
        // too long
        assert!(validate_namespace_name(&"a".repeat(64)).is_err());
        // uppercase rejected
        assert!(validate_namespace_name("Default").is_err());
        // underscore rejected
        assert!(validate_namespace_name("my_ns").is_err());
        // dot rejected
        assert!(validate_namespace_name("my.ns").is_err());
    }

    #[test]
    fn invalid_returns_422() {
        let result = validate_namespace_name("Bad_Name");
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // When ?watch=true, list_namespaces must route to the watch stream (chunked transfer)
    // rather than returning a normal NamespaceList JSON. This ensures clients that open
    // a watch on /api/v1/namespaces actually receive a streaming response.
    #[tokio::test]
    async fn list_namespaces_watch_returns_chunked_stream() {
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

        let query = crate::handlers::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        };

        let resp = match list_namespaces(
            State(state),
            Query(query),
            Extension(crate::auth::UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        // watch_generic always sets transfer-encoding: chunked
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "watch response must use chunked transfer encoding"
        );
    }

    fn make_state() -> AppState {
        use std::sync::Arc;
        use u7s_store::SqliteStore;
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    fn namespace_body(name: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": name }
            })
            .to_string(),
        )
    }

    // create_namespace must return 201 with the name set and a non-empty UID assigned.
    // A missing UID would break owner references and garbage collection.
    #[tokio::test]
    async fn create_namespace_returns_201_with_name_and_uid() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("my-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Verify the stored object has name and UID set
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "my-ns"))
            .await
            .expect("store get must not error")
            .expect("namespace must exist in store");
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored value must be valid JSON");
        assert_eq!(
            body["metadata"]["name"], "my-ns",
            "created namespace must have correct name"
        );
        assert!(
            body["metadata"]["uid"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "created namespace must have a non-empty UID"
        );
    }

    // create_namespace must stamp the "kubernetes" finalizer on every namespace,
    // even when the request body does not include finalizers.
    //
    // Without this stamp, the KCM must add the finalizer asynchronously after
    // watching the ADDED event. This creates a race: if the namespace is deleted
    // before the KCM processes the event (e.g. the ring buffer evicts it, or the
    // KCM is not running), the namespace hard-deletes without draining resources —
    // leaving serviceaccounts, configmaps, and other child objects as orphans.
    // Stamping the finalizer at creation time guarantees the drain lifecycle runs.
    #[tokio::test]
    async fn create_namespace_stamps_kubernetes_finalizer() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("finalizer-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "finalizer-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("namespace must exist in store");
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored value must be valid JSON");

        let finalizers = body["spec"]["finalizers"].as_array().expect(
            "spec.finalizers must be an array — namespace finalizers live in spec, not metadata",
        );
        assert!(
            finalizers.iter().any(|v| v.as_str() == Some("kubernetes")),
            "create_namespace must stamp spec.finalizers=[\"kubernetes\"] so that \
             delete_namespace soft-deletes instead of hard-deleting, ensuring the KCM \
             can drain child resources before the namespace is removed. \
             Without this, the namespace hard-deletes immediately, orphaning resources. \
             Got finalizers: {:?}",
            finalizers
        );
    }

    // create_namespace must stamp metadata.creationTimestamp so it is never null.
    //
    // Kubernetes clients and the e2e framework rely on creationTimestamp being a
    // non-null RFC3339 string. A null value causes JSON marshalling errors in
    // client-go and breaks conformance tests that inspect namespace metadata.
    // The KCM's namespace informer may also behave incorrectly on null timestamps.
    #[tokio::test]
    async fn create_namespace_stamps_creation_timestamp() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("ts-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "ts-ns"))
            .await
            .expect("store get must not error")
            .expect("namespace must exist in store");
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored value must be valid JSON");

        let ts = body["metadata"]["creationTimestamp"].as_str().unwrap_or("");
        assert!(
            !ts.is_empty(),
            "create_namespace must stamp metadata.creationTimestamp as a non-empty RFC3339 string; \
             a null value breaks client-go JSON marshalling and e2e framework namespace setup"
        );
        assert!(
            ts.contains('T'),
            "creationTimestamp must be RFC3339 (contains 'T'); got: {ts}"
        );
    }

    // replace_namespace must reflect updated labels in the response body.
    // This verifies that PUT applies the full replacement, not a partial update.
    #[tokio::test]
    async fn replace_namespace_reflects_updated_labels() {
        let state = make_state();

        // Create first
        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("label-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Fetch to get uid and resourceVersion
        let stored_entry = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "label-ns"))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored: serde_json::Value =
            serde_json::from_slice(&stored_entry.value).expect("parse stored");
        let rv = stored["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("1")
            .to_string();
        let uid = stored["metadata"]["uid"].as_str().unwrap_or("").to_string();

        // PUT with new labels, carrying back uid+rv
        let replace_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "label-ns",
                    "uid": uid,
                    "resourceVersion": rv,
                    "labels": { "env": "prod" }
                }
            })
            .to_string(),
        );

        // Verify stored state after replace reflects the label update
        assert!(
            replace_namespace(
                State(state.clone()),
                Path("label-ns".to_string()),
                axum::http::HeaderMap::new(),
                replace_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        let after = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "label-ns"))
            .await
            .expect("store get must not error")
            .expect("must still exist");
        let body: serde_json::Value = serde_json::from_slice(&after.value).expect("parse after");
        assert_eq!(
            body["metadata"]["labels"]["env"], "prod",
            "replace must persist the updated labels"
        );
    }

    // patch_namespace with merge-patch must return 200 and apply the patch.
    // This verifies the happy path: correct content-type, namespace exists, patch is valid JSON.
    #[tokio::test]
    async fn patch_namespace_applies_merge_patch() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("patch-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!({ "metadata": { "labels": { "patched": "yes" } } }).to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_namespace(
                State(state.clone()),
                Path("patch-ns".to_string()),
                axum::extract::Query(PatchQuery::default()),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "patch must succeed"
        );

        let after = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "patch-ns"))
            .await
            .expect("store get")
            .expect("must still exist");
        let body: serde_json::Value =
            serde_json::from_slice(&after.value).expect("parse after patch");
        assert_eq!(
            body["metadata"]["labels"]["patched"], "yes",
            "patch must apply the merge patch to the stored namespace"
        );
    }

    // delete_namespace on a namespace created via create_namespace must soft-delete:
    // set phase=Terminating + deletionTimestamp and keep the namespace in the store
    // until the KCM removes the "kubernetes" finalizer.
    //
    // create_namespace stamps the "kubernetes" finalizer at creation time so that
    // every namespace goes through the drain lifecycle. Without this, a race between
    // namespace creation and the KCM watching for ADDED events can cause the finalizer
    // to be absent, resulting in an immediate hard-delete that skips resource drain.
    #[tokio::test]
    async fn delete_namespace_soft_deletes_to_terminating() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("del-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        assert!(
            delete_namespace(State(state.clone()), Path("del-ns".to_string()))
                .await
                .is_ok(),
            "delete must succeed"
        );

        // The namespace must still exist in Terminating state.
        // Hard-delete only happens after the KCM removes the "kubernetes" finalizer.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "del-ns"))
            .await
            .expect("store get must not error")
            .expect("namespace must still exist after delete — waiting for KCM to drain");
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored namespace");
        assert_eq!(
            body["status"]["phase"], "Terminating",
            "namespace must be Terminating after delete while kubernetes finalizer is present"
        );
        assert!(
            body["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must be set after delete"
        );
    }

    // store_err_to_status must map each StoreError variant to the correct HTTP status code.
    // This mapping is what clients rely on to distinguish 404 from 409 from 500.
    #[test]
    fn store_err_to_status_not_found_maps_to_404() {
        let err = store_err_to_status(StoreError::NotFound { key: "k".into() }, "my-ns");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn store_err_to_status_already_exists_maps_to_409() {
        let err = store_err_to_status(StoreError::AlreadyExists { key: "k".into() }, "my-ns");
        assert_eq!(err.0, StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["reason"], "AlreadyExists");
    }

    #[test]
    fn store_err_to_status_revision_mismatch_maps_to_409_conflict() {
        let err = store_err_to_status(
            StoreError::RevisionMismatch {
                expected: 1,
                current: 2,
            },
            "my-ns",
        );
        assert_eq!(err.0, StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        // RevisionMismatch maps to Conflict reason, not AlreadyExists
        assert_eq!(json["reason"], "Conflict");
        assert!(
            json["message"].as_str().unwrap().contains("my-ns"),
            "conflict message must identify the namespace"
        );
    }

    #[test]
    fn store_err_to_status_other_maps_to_500() {
        // Compacted is a catch-all "other" arm — maps to internal server error.
        // This ensures unexpected store errors don't leak as 4xx to clients.
        let err = store_err_to_status(
            StoreError::Compacted {
                requested: 1,
                horizon: 5,
            },
            "any-ns",
        );
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["reason"], "InternalError");
    }

    // Regression test for the kcm-smoke-stack bug: when a client requests
    // ?watch=true&sendInitialEvents=true on /api/v1/namespaces, the server must
    // emit the initial-events-end BOOKMARK (k8s.io/initial-events-end=true).
    //
    // Without this BOOKMARK, the GC's metadata SharedInformerFactory (which watches
    // ALL resource types including namespaces) never reports "all synced", blocking
    // the GC's dependency graph builder. With an incomplete dependency graph the GC
    // cannot verify owner references and may garbage-collect newly created ReplicaSets,
    // causing the kcm deployment controller smoke test to fail.
    //
    // The bug was: list_namespaces passed None for initial_items to watch_generic.
    // watch_generic only emits the BOOKMARK when initial_items is Some(_).
    #[tokio::test]
    async fn list_namespaces_watch_with_send_initial_events_emits_bookmark() {
        use tokio::time::{timeout, Duration};

        let state = make_state();

        // Seed a namespace so the initial list is non-empty, making the ADDED + BOOKMARK
        // sequence unambiguous.
        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("bookmark-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let query = crate::handlers::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: Some(true),
            allow_watch_bookmarks: Some(true),
            timeout_seconds: Some(1), // stream closes after 1s so to_bytes can return with collected data
        };

        let resp = match list_namespaces(
            State(state),
            Query(query),
            Extension(crate::auth::UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);

        // Read until stream closes (timeout_seconds=1) or the 3-second guard fires.
        // The BOOKMARK must be in the initial burst before any live-event wait.
        let body = resp.into_body();
        let result = timeout(
            Duration::from_secs(3),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await;
        let bytes = match result {
            Ok(Ok(b)) => b,
            _ => bytes::Bytes::new(),
        };
        let text = std::str::from_utf8(&bytes).unwrap_or("");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        let has_initial_events_end_bookmark = lines.iter().any(|v| {
            v["type"] == "BOOKMARK"
                && v["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
        });
        assert!(
            has_initial_events_end_bookmark,
            "list_namespaces with sendInitialEvents=true must emit a BOOKMARK with \
             k8s.io/initial-events-end=true; without it the GC metadata informer factory \
             never completes cache sync and blocks the GC dependency graph builder. \
             Got lines: {:?}",
            lines
        );
    }

    // list_namespaces (non-watch) must return a NamespaceList with the created namespace.
    // This is the primary read path for `kubectl get namespaces`.
    #[tokio::test]
    async fn list_namespaces_returns_namespace_list() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("list-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match list_namespaces(
            State(state.clone()),
            Query(crate::handlers::generic::CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: None,
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            }),
            Extension(crate::auth::UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
    }

    // get_namespace must return 200 with the namespace body when it exists.
    #[tokio::test]
    async fn get_namespace_returns_200_for_existing() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("get-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match get_namespace(State(state.clone()), Path("get-ns".to_string())).await {
            Ok(r) => r,
            Err(_) => panic!("get must not error"),
        };

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "existing namespace must return 200"
        );
    }

    // get_namespace must return 404 when the namespace does not exist.
    // Clients depend on this to know a resource is absent.
    #[tokio::test]
    async fn get_namespace_returns_404_for_missing() {
        let state = make_state();

        let result = get_namespace(State(state.clone()), Path("no-such-ns".to_string())).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    // create_namespace must reject bodies with neither name nor generateName.
    // Without an identity, the object cannot be stored or referenced.
    #[tokio::test]
    async fn create_namespace_rejects_missing_name() {
        let state = make_state();
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {}
            })
            .to_string(),
        );

        let result =
            create_namespace(State(state.clone()), axum::http::HeaderMap::new(), body).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    // create_namespace must reject invalid namespace names with 422.
    // Kubernetes enforces strict DNS label rules on namespace names.
    #[tokio::test]
    async fn create_namespace_rejects_invalid_name() {
        let state = make_state();
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "INVALID_NAME" }
            })
            .to_string(),
        );

        let result =
            create_namespace(State(state.clone()), axum::http::HeaderMap::new(), body).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // create_namespace must reject a duplicate: second create for same name returns 409.
    // Kubernetes returns AlreadyExists (409) when a namespace already exists.
    #[tokio::test]
    async fn create_namespace_rejects_duplicate() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("dup-ns"),
            )
            .await
            .is_ok(),
            "first create must succeed"
        );

        let result = create_namespace(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            namespace_body("dup-ns"),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "second create of same namespace must return 409"
        );
    }

    // replace_namespace must reject a request where URL name != body name.
    // Kubernetes enforces name consistency to prevent accidental overwrites.
    #[tokio::test]
    async fn replace_namespace_rejects_name_mismatch() {
        let state = make_state();

        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "other-ns", "resourceVersion": "1" }
            })
            .to_string(),
        );

        let result = replace_namespace(
            State(state.clone()),
            Path("different-ns".to_string()),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::BAD_REQUEST,
            "name mismatch between URL and body must return 400"
        );
    }

    // patch_namespace must return 415 when Content-Type is not merge-patch+json.
    // Without the right content type, the patch semantics are undefined.
    #[tokio::test]
    async fn patch_namespace_rejects_wrong_content_type() {
        let state = make_state();

        let patch_body = Bytes::from(serde_json::json!({}).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let result = patch_namespace(
            State(state.clone()),
            Path("any-ns".to_string()),
            axum::extract::Query(PatchQuery::default()),
            headers,
            patch_body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "wrong content type must return 415"
        );
    }

    // patch_namespace must return 404 when the namespace does not exist.
    #[tokio::test]
    async fn patch_namespace_returns_404_for_missing() {
        let state = make_state();

        let patch_body = Bytes::from(serde_json::json!({}).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_namespace(
            State(state.clone()),
            Path("no-such-ns".to_string()),
            axum::extract::Query(PatchQuery::default()),
            headers,
            patch_body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::NOT_FOUND,
            "patch on non-existent namespace must return 404"
        );
    }

    // delete_namespace must return 404 when the namespace does not exist.
    #[tokio::test]
    async fn delete_namespace_returns_404_for_missing() {
        let state = make_state();

        let result = delete_namespace(State(state.clone()), Path("ghost-ns".to_string())).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::NOT_FOUND,
            "deleting non-existent namespace must return 404"
        );
    }

    fn namespace_body_with_finalizers(name: &str, finalizers: &[&str]) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": name },
                "spec": { "finalizers": finalizers }
            })
            .to_string(),
        )
    }

    // delete_namespace with finalizers present must NOT hard-delete — it must set
    // phase=Terminating + deletionTimestamp and return the namespace object.
    //
    // Real Kubernetes: a namespace with the "kubernetes" finalizer enters Terminating
    // and only hard-deletes after the namespace controller drains child resources.
    // Instant hard-delete breaks Argo CD's GC logic and causes stale object collisions.
    #[tokio::test]
    async fn delete_namespace_with_finalizers_transitions_to_terminating() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body_with_finalizers("fin-ns", &["kubernetes"]),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Delete should return the namespace in Terminating state, NOT a 404.
        assert!(
            delete_namespace(State(state.clone()), Path("fin-ns".to_string()))
                .await
                .is_ok(),
            "delete with finalizers must not error"
        );

        // The namespace must still exist in the store — it was not hard-deleted.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "fin-ns"))
            .await
            .expect("store get must not error")
            .expect("namespace must still exist after soft-delete");
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored namespace");

        assert_eq!(
            body["status"]["phase"], "Terminating",
            "phase must be Terminating after soft-delete with finalizers present"
        );
        assert!(
            body["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must be set after soft-delete"
        );
        assert!(
            body["spec"]["finalizers"]
                .as_array()
                .is_some_and(|f| !f.is_empty()),
            "spec.finalizers must remain present until the controller removes them — \
             namespace finalizers live in spec, not metadata"
        );
    }

    // delete_namespace on a namespace that was stored WITHOUT any finalizers must
    // hard-delete immediately. This covers the case where a namespace was seeded
    // or otherwise written directly to the store without the "kubernetes" finalizer
    // (e.g. a migration path or a test that bypasses create_namespace).
    //
    // Note: create_namespace now always stamps the "kubernetes" finalizer at creation
    // time. This test exercises the code path via a direct store write to verify that
    // the hard-delete path in delete_namespace still works for un-finalized namespaces.
    #[tokio::test]
    async fn delete_namespace_without_finalizers_hard_deletes() {
        use u7s_store::Store;
        let state = make_state();

        // Write a namespace directly to the store WITHOUT a finalizer,
        // simulating a namespace that predates the finalizer-stamping fix.
        let key = crate::keys::cluster_object_key("namespaces", "no-fin-ns");
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "no-fin-ns",
                "uid": "00000000-0000-0000-0000-000000000099",
                "resourceVersion": "1"
            },
            "status": { "phase": "Active" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("direct store write must succeed");

        assert!(
            delete_namespace(State(state.clone()), Path("no-fin-ns".to_string()))
                .await
                .is_ok(),
            "delete without finalizers must succeed"
        );

        // The namespace must be gone — no finalizers means immediate hard-delete.
        let stored = state
            .store
            .get(&key)
            .await
            .expect("store get must not error");
        assert!(
            stored.is_none(),
            "namespace without finalizers must be hard-deleted immediately — \
             this path applies to namespaces that predate the finalizer-stamping fix"
        );
    }

    // Cascade-delete removes namespace resources on hard-delete so re-creating a
    // namespace with the same name does not inherit stale objects.
    //
    // Without the cascade: if a configmap is created in namespace "recycled-ns" and
    // the namespace is then hard-deleted (no finalizers), the configmap remains in the
    // store. When the KCM root CA publisher later POSTs "kube-root-ca.crt" in the
    // re-created "recycled-ns", it gets 409 AlreadyExists because the stale configmap
    // is still there. This is the false-positive 409 reported in kcm.log.
    #[tokio::test]
    async fn delete_namespace_hard_delete_cascades_to_namespace_resources() {
        use crate::handlers::json_patch::CreateQuery;
        use crate::handlers::resource::create_namespaced_resource;
        use axum::extract::{Path, State};
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use u7s_store::Store;

        let state = make_state();

        // Write a namespace directly to the store WITHOUT a finalizer so
        // delete_namespace takes the hard-delete path (no soft-delete).
        let ns_key = crate::keys::cluster_object_key("namespaces", "recycled-ns");
        let ns_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "recycled-ns",
                "uid": "00000000-0000-0000-0000-000000000099",
                "resourceVersion": "1"
            },
            "status": { "phase": "Active" }
        });
        state
            .store
            .put(&ns_key, bytes::Bytes::from(ns_body.to_string()), Some(0))
            .await
            .expect("namespace write must succeed");

        // Seed a configmap in the namespace — simulates KCM creating kube-root-ca.crt.
        let cm_key = crate::keys::object_key("configmaps", "recycled-ns", "kube-root-ca.crt");
        let cm_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "kube-root-ca.crt",
                "namespace": "recycled-ns",
                "resourceVersion": "2"
            },
            "data": { "ca.crt": "CERT" }
        });
        state
            .store
            .put(&cm_key, bytes::Bytes::from(cm_body.to_string()), Some(0))
            .await
            .expect("configmap write must succeed");

        // Hard-delete the namespace (no finalizers → immediate delete).
        delete_namespace(State(state.clone()), Path("recycled-ns".to_string()))
            .await
            .expect("namespace delete must succeed");

        // The configmap must have been cascade-deleted along with the namespace.
        // If it still exists, re-creating the namespace will produce false 409s.
        let stored_cm = state
            .store
            .get(&cm_key)
            .await
            .expect("store get must not error");
        assert!(
            stored_cm.is_none(),
            "configmap must be cascade-deleted when its namespace is hard-deleted — \
             without cascade, re-creating the namespace causes false 409 AlreadyExists \
             errors when KCM tries to POST kube-root-ca.crt"
        );

        // Re-create the namespace.
        state
            .store
            .put(&ns_key, bytes::Bytes::from(ns_body.to_string()), Some(0))
            .await
            .expect("namespace re-create must succeed");

        // Now POST the same configmap name — must return 201 (not 409).
        let cm_post_body = bytes::Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "name": "kube-root-ca.crt", "namespace": "recycled-ns" },
                "data": { "ca.crt": "CERT" }
            })
            .to_string(),
        );
        let headers = {
            let mut h = axum::http::HeaderMap::new();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            );
            h
        };
        let resp = create_namespaced_resource(
            State(state.clone()),
            Path((
                "".into(),
                "v1".into(),
                "recycled-ns".into(),
                "configmaps".into(),
            )),
            axum::extract::Query(CreateQuery::default()),
            headers,
            cm_post_body,
        )
        .await
        .unwrap_or_else(|e| panic!("POST must not hard-error; got: {e:?}"))
        .into_response();

        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST configmap to re-created namespace must return 201 Created, not 409 — \
             false 409 occurs when namespace hard-delete leaves orphaned resources in the store"
        );
    }

    // patch_namespace must trigger hard-delete when deletionTimestamp is set and
    // finalizers become empty after the patch.
    //
    // This is the mechanism the namespace controller uses: it patches to remove the
    // finalizer, which causes the apiserver to hard-delete the namespace. Without this
    // the namespace stays in Terminating forever even after the controller removes
    // the finalizer.
    #[tokio::test]
    async fn patch_namespace_hard_deletes_when_finalizers_cleared_with_deletion_ts() {
        let state = make_state();

        // Create with finalizer.
        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body_with_finalizers("drain-ns", &["kubernetes"]),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Soft-delete to set deletionTimestamp.
        assert!(
            delete_namespace(State(state.clone()), Path("drain-ns".to_string()))
                .await
                .is_ok(),
            "soft-delete must succeed"
        );

        // Remove the finalizer via merge-patch — this must trigger a hard-delete.
        // Namespace finalizers live in spec.finalizers, not metadata.finalizers.
        let patch_body =
            Bytes::from(serde_json::json!({ "spec": { "finalizers": [] } }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_namespace(
                State(state.clone()),
                Path("drain-ns".to_string()),
                axum::extract::Query(PatchQuery::default()),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "patch to clear finalizers must succeed"
        );

        // The namespace must be gone — clearing the last finalizer triggers hard-delete.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "drain-ns"))
            .await
            .expect("store get must not error");
        assert!(
            stored.is_none(),
            "namespace must be hard-deleted when all finalizers are removed while \
             deletionTimestamp is set — without this the namespace stays Terminating forever"
        );
    }

    // replace_namespace with stale resourceVersion must return 409 Conflict.
    // OCC prevents concurrent updates from clobbering each other.
    // A stale PUT must be rejected rather than silently overwriting newer data.
    #[tokio::test]
    async fn replace_namespace_stale_resource_version_returns_409() {
        let state = make_state();

        // Create the namespace first.
        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("occ-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Try to replace with a known-stale resourceVersion.
        let stale_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "occ-ns",
                    "resourceVersion": "99999"
                }
            })
            .to_string(),
        );

        let result = replace_namespace(
            State(state.clone()),
            Path("occ-ns".to_string()),
            axum::http::HeaderMap::new(),
            stale_body,
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("stale replace must fail"),
        };
        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "stale resourceVersion on replace_namespace must return 409 Conflict — \
             OCC is the guard against lost-update races in concurrent namespace updates"
        );
    }

    // finalize_namespace (PUT /api/v1/namespaces/{name}/finalize) must hard-delete
    // the namespace when deletionTimestamp is set and spec.finalizers is empty.
    //
    // This is the exact call the KCM namespace controller makes after draining all
    // resources. Without this endpoint the namespace stays Terminating forever.
    #[tokio::test]
    async fn finalize_namespace_hard_deletes_when_spec_finalizers_empty_with_deletion_ts() {
        let state = make_state();

        // Create with the kubernetes finalizer.
        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body_with_finalizers("finalize-ns", &["kubernetes"]),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Soft-delete to set deletionTimestamp + phase=Terminating.
        assert!(
            delete_namespace(State(state.clone()), Path("finalize-ns".to_string()))
                .await
                .is_ok(),
            "soft-delete must succeed"
        );

        // The namespace must still be in the store (Terminating, not hard-deleted).
        assert!(
            state
                .store
                .get(&crate::keys::cluster_object_key(
                    "namespaces",
                    "finalize-ns"
                ))
                .await
                .unwrap()
                .is_some(),
            "namespace must still exist after soft-delete"
        );

        // KCM calls PUT /finalize with spec.finalizers: [] to remove the finalizer.
        // This must trigger a hard-delete.
        let finalize_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "finalize-ns" },
                "spec": { "finalizers": [] }
            })
            .to_string(),
        );

        assert!(
            finalize_namespace(
                State(state.clone()),
                Path("finalize-ns".to_string()),
                finalize_body,
            )
            .await
            .is_ok(),
            "finalize with empty spec.finalizers must succeed"
        );

        // The namespace must now be gone — hard-deleted by finalize_namespace.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "finalize-ns",
            ))
            .await
            .expect("store get must not error");
        assert!(
            stored.is_none(),
            "PUT /finalize with empty spec.finalizers while deletionTimestamp is set \
             must hard-delete the namespace — without this the namespace stays Terminating forever. \
             This is the critical path the KCM uses to complete namespace termination."
        );
    }

    // finalize_namespace must only update finalizers and persist (not hard-delete)
    // when spec.finalizers is non-empty after the PUT.
    //
    // The KCM may call finalize with some finalizers remaining if multiple controllers
    // registered finalizers. Only the last removal (empty finalizers) triggers hard-delete.
    #[tokio::test]
    async fn finalize_namespace_persists_when_spec_finalizers_non_empty() {
        let state = make_state();

        // Create with two finalizers.
        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body_with_finalizers("multi-fin-ns", &["kubernetes", "other"]),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Soft-delete to set deletionTimestamp.
        assert!(
            delete_namespace(State(state.clone()), Path("multi-fin-ns".to_string()))
                .await
                .is_ok(),
            "soft-delete must succeed"
        );

        // Call finalize with one finalizer remaining (kubernetes removed, other stays).
        let finalize_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "multi-fin-ns" },
                "spec": { "finalizers": ["other"] }
            })
            .to_string(),
        );

        assert!(
            finalize_namespace(
                State(state.clone()),
                Path("multi-fin-ns".to_string()),
                finalize_body,
            )
            .await
            .is_ok(),
            "finalize with non-empty spec.finalizers must succeed"
        );

        // The namespace must still exist — non-empty finalizers mean no hard-delete yet.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "multi-fin-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("namespace must still exist — finalizers remain, no hard-delete yet");
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored namespace");

        let finalizers = body["spec"]["finalizers"]
            .as_array()
            .expect("spec.finalizers must be an array — namespace finalizers live in spec");
        assert_eq!(
            finalizers.len(),
            1,
            "after finalize with spec.finalizers=[other], only one finalizer must remain"
        );
        assert_eq!(
            finalizers[0].as_str(),
            Some("other"),
            "the remaining finalizer must be 'other'"
        );
    }

    // finalize_namespace must return 404 when the namespace does not exist.
    // The KCM should not encounter this in practice, but the handler must be correct.
    #[tokio::test]
    async fn finalize_namespace_returns_404_for_missing() {
        let state = make_state();

        let finalize_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "no-such-ns" },
                "spec": { "finalizers": [] }
            })
            .to_string(),
        );

        let result = finalize_namespace(
            State(state.clone()),
            Path("no-such-ns".to_string()),
            finalize_body,
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 for missing namespace"),
        };
        assert_eq!(
            err.0,
            StatusCode::NOT_FOUND,
            "finalize on non-existent namespace must return 404"
        );
    }

    // replace_namespace must trigger hard-delete when deletionTimestamp is set and
    // finalizers become empty after the PUT.
    //
    // The u7s namespace controller uses GET + PUT to remove the "kubernetes" finalizer.
    // Without this hard-delete trigger, the namespace stays Terminating forever even
    // after the controller finishes draining resources.
    #[tokio::test]
    async fn replace_namespace_hard_deletes_when_finalizers_cleared_with_deletion_ts() {
        let state = make_state();

        // Create with finalizer.
        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body_with_finalizers("put-drain-ns", &["kubernetes"]),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Soft-delete to set deletionTimestamp.
        assert!(
            delete_namespace(State(state.clone()), Path("put-drain-ns".to_string()))
                .await
                .is_ok(),
            "soft-delete must succeed"
        );

        // Fetch the stored state so we have the right resourceVersion.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "put-drain-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let mut ns: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored");

        // Remove the finalizer from the body and PUT — this must trigger hard-delete.
        // Namespace finalizers live in spec.finalizers, not metadata.finalizers.
        ns["spec"]["finalizers"] = serde_json::json!([]);

        let replace_body = Bytes::from(ns.to_string());

        assert!(
            replace_namespace(
                State(state.clone()),
                Path("put-drain-ns".to_string()),
                axum::http::HeaderMap::new(),
                replace_body,
            )
            .await
            .is_ok(),
            "PUT with empty finalizers must succeed"
        );

        // The namespace must be gone.
        let after = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "put-drain-ns",
            ))
            .await
            .expect("store get must not error");
        assert!(
            after.is_none(),
            "namespace must be hard-deleted when all finalizers are removed via PUT while \
             deletionTimestamp is set"
        );
    }

    // get_namespace_status must return 200 with the full namespace body.
    // Status is embedded in the object, not a separate store entry.
    #[tokio::test]
    async fn get_namespace_status_returns_200() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("status-get-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = get_namespace_status(State(state.clone()), Path("status-get-ns".to_string()))
            .await
            .expect("get_namespace_status must not error");

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "GET /status must return 200 for existing namespace"
        );
    }

    // put_namespace_status must update status.conditions without touching metadata or spec.
    // The KCM namespace controller calls this to set NamespaceDeletionContentFailure
    // so the test can detect that namespace deletion is making progress.
    #[tokio::test]
    async fn put_namespace_status_updates_conditions() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("status-put-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored_before = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "status-put-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let before: serde_json::Value = serde_json::from_slice(&stored_before.value).unwrap();
        let rv = before["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("1");

        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "status-put-ns", "resourceVersion": rv },
                "status": {
                    "phase": "Terminating",
                    "conditions": [{
                        "type": "NamespaceDeletionContentFailure",
                        "status": "True",
                        "reason": "ContentDeletionFailed",
                        "message": "test-pod has a finalizer"
                    }]
                }
            })
            .to_string(),
        );

        assert!(
            put_namespace_status(
                State(state.clone()),
                Path("status-put-ns".to_string()),
                axum::http::HeaderMap::new(),
                status_body,
            )
            .await
            .is_ok(),
            "put_namespace_status must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "status-put-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            body["status"]["conditions"][0]["type"],
            "NamespaceDeletionContentFailure",
            "PUT /status must persist conditions; KCM uses this to signal namespace deletion progress. \
             Without this endpoint the test waits 5 minutes and times out."
        );
        assert_eq!(
            body["metadata"]["name"], "status-put-ns",
            "metadata must be unchanged after PUT /status"
        );
    }

    // put_namespace_status must return 404 for a namespace that does not exist.
    #[tokio::test]
    async fn put_namespace_status_returns_404_for_missing() {
        let state = make_state();

        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "ghost-status-ns" },
                "status": { "phase": "Terminating" }
            })
            .to_string(),
        );

        let result = put_namespace_status(
            State(state.clone()),
            Path("ghost-status-ns".to_string()),
            axum::http::HeaderMap::new(),
            status_body,
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 for missing namespace"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::NOT_FOUND,
            "PUT /status on non-existent namespace must return 404"
        );
    }

    // patch_namespace_status must update status via merge-patch without touching spec/metadata.
    // The KCM uses this to append conditions without replacing the entire status object.
    #[tokio::test]
    async fn patch_namespace_status_applies_merge_patch() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("status-patch-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!({
                "status": {
                    "conditions": [{
                        "type": "NamespaceDeletionContentFailure",
                        "status": "False"
                    }]
                }
            })
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_namespace_status(
                State(state.clone()),
                Path("status-patch-ns".to_string()),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "patch_namespace_status must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "status-patch-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            body["status"]["conditions"][0]["type"], "NamespaceDeletionContentFailure",
            "PATCH /status must persist the condition; KCM uses merge-patch to update conditions \
             without replacing the whole status. Without this the condition is never visible."
        );
        assert_eq!(
            body["metadata"]["name"], "status-patch-ns",
            "metadata must be unchanged after PATCH /status"
        );
    }

    // SSA PATCH on Namespace must return a non-empty JSON body with the full object.
    //
    // Before the fix, patch_namespace rejected apply-patch+yaml with 415 Unsupported
    // Media Type. The e2e test received an empty body and failed with
    // "invalid JSON: expected value at line 1 column 1".
    // This test would fail on revert: reverting the fix causes the handler to return
    // 415 rather than the updated object.
    #[tokio::test]
    async fn ssa_patch_namespace_returns_non_empty_json_body() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("ssa-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "ssa-ns",
                "finalizers": ["kubernetes"]
            }
        });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let result = patch_namespace(
            State(state.clone()),
            Path("ssa-ns".to_string()),
            axum::extract::Query(PatchQuery {
                field_manager: Some("e2e-test".to_string()),
                _field_validation: None,
            }),
            ssa_headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "SSA PATCH on Namespace must not return an error (got {:?}); \
                 before the fix this returned 415 Unsupported Media Type causing \
                 the e2e test to receive an empty body",
                e.0
            )
        })
        .into_response();

        assert_eq!(
            result.status(),
            StatusCode::OK,
            "SSA PATCH on existing Namespace must return 200"
        );

        let body_bytes = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        assert!(
            !body_bytes.is_empty(),
            "SSA PATCH response body must not be empty — an empty body causes \
             'invalid JSON: expected value at line 1 column 1' in e2e tests"
        );
        let v: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("SSA PATCH response must be valid JSON");
        assert_eq!(
            v["metadata"]["name"], "ssa-ns",
            "SSA PATCH response must contain the full Namespace object"
        );
    }

    // SSA PATCH on Namespace with ?fieldManager= must set metadata.managedFields.
    //
    // Before the fix, patch_namespace rejected apply-patch+yaml so managedFields
    // was never populated. The e2e test "apply changes to status" checks for
    // 'metadata.managedFields' in the response; without it the test fails with
    // "patched object should have the applied annotation".
    // This test would fail on revert: the handler returns 415 and managedFields
    // is absent from any response body.
    #[tokio::test]
    async fn ssa_patch_namespace_sets_managed_fields_for_field_manager() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("mf-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "mf-ns" }
        });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let result = patch_namespace(
            State(state.clone()),
            Path("mf-ns".to_string()),
            axum::extract::Query(PatchQuery {
                field_manager: Some("kubectl-apply".to_string()),
                _field_validation: None,
            }),
            ssa_headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|e| panic!("SSA PATCH must succeed, got {:?}", e.0))
        .into_response();

        let body_bytes = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let mf = &v["metadata"]["managedFields"];
        assert!(
            mf.is_array(),
            "SSA PATCH response must include metadata.managedFields; \
             the e2e test 'apply changes to status' checks for the applied annotation. \
             Without managedFields the test fails with \
             'patched object should have the applied annotation'"
        );
        assert_eq!(
            mf[0]["manager"], "kubectl-apply",
            "managedFields[0].manager must equal the ?fieldManager query parameter"
        );
        assert_eq!(
            mf[0]["operation"], "Apply",
            "managedFields[0].operation must be 'Apply' for SSA requests"
        );
    }

    /// Regression test for mayor-8tiu: `GET /api/v1/namespaces?watch=true` with no
    /// sendInitialEvents and an empty namespace store must stay open for the requested
    /// timeoutSeconds, not close immediately with 0 bytes.
    ///
    /// The bug: the broadcast sender (`tx`) inside SqliteStore is dropped when `state`
    /// (the handler-local AppState clone) drops at the end of `list_namespaces`. If
    /// `state` holds the only `Arc<S>` reference, the store is destroyed, `tx` is dropped,
    /// and the broadcast receiver immediately gets `RecvError::Closed`, causing the stream
    /// generator to `return` — yielding `Poll::Ready(None)` — which closes the watch body
    /// with 0 bytes before `timeoutSeconds` expires.
    ///
    /// The fix: `watch_generic` now captures `_store_keepalive = Arc::clone(&state.store)`
    /// inside the `chunk_stream` closure, keeping the store (and therefore `tx`) alive for
    /// the entire lifetime of the streaming response body.
    ///
    /// Without the fix: body completes in << 1 second (store drops → tx drops → Closed).
    /// With the fix: body completes after ~1 second (timeoutSeconds=1 fires correctly).
    ///
    /// This test fails if `_store_keepalive` is removed from `watch_generic`'s chunk_stream.
    #[tokio::test]
    async fn namespace_watch_rv0_no_send_initial_events_stays_open_for_timeout() {
        use tokio::time::{timeout, Duration, Instant};

        // make_state() creates the store internally — AppState holds the only Arc<S>.
        // When list_namespaces moves `state` in and drops it, no external reference
        // remains. Without _store_keepalive in chunk_stream, tx drops and the stream
        // closes immediately rather than waiting for timeoutSeconds.
        let state = make_state();

        let query = crate::handlers::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: Some(false), // no bookmarks — body will be empty
            timeout_seconds: Some(1),           // server closes after 1s
        };

        let resp = match list_namespaces(
            State(state),
            Query(query),
            Extension(crate::auth::UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        // `state` has been dropped inside list_namespaces. Without the fix, the store
        // (and tx) are now destroyed — the broadcast rx returns Closed immediately.
        // We measure how long it takes to drain the body: if the stream closed immediately
        // (bug), to_bytes returns in microseconds. If the stream respects timeoutSeconds=1
        // (fix), to_bytes returns after ~1 second.
        let t0 = Instant::now();
        let _ = timeout(
            Duration::from_secs(3), // outer guard so the test doesn't hang
            axum::body::to_bytes(resp.into_body(), usize::MAX),
        )
        .await;
        let elapsed = t0.elapsed();

        assert!(
            elapsed.as_millis() >= 900,
            "namespace watch with timeoutSeconds=1 must stay open for at least 900ms; \
             if it closes immediately ({}ms), the broadcast tx was dropped when the handler's \
             AppState was destroyed — the _store_keepalive fix in watch_generic is needed to \
             keep the store alive for the stream's lifetime (mayor-8tiu)",
            elapsed.as_millis()
        );
    }
}

// ---------------------------------------------------------------------------
// Admission regression tests — prove create_namespace invokes the
// admission webhook pipeline (mayor-8sn9).
//
// Without the fix, create_namespace bypassed admission entirely; admission-based
// controls on namespaces were non-functional.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod admission_tests {
    use std::sync::Arc;

    use axum::{routing::post, Router};
    use bytes::Bytes;
    use tokio::net::TcpListener;
    use u7s_store::{SqliteStore, Store};

    use super::*;

    fn make_state(store: Arc<SqliteStore>) -> crate::state::AppState {
        crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
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

    /// create_namespace must invoke the mutating admission pipeline.
    /// A mutating webhook that adds a label must have that label in the stored
    /// namespace. Without the fix, the webhook was never called.
    #[tokio::test]
    async fn create_namespace_invokes_mutating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        let patch_label_router = Router::new().route(
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
        );

        let (url, _handle) = start_mock_webhook(patch_label_router).await;

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test-mutating-ns"},
            "webhooks": [{
                "name": "test.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["namespaces"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/test-mutating-ns",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let ns_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": "test-ns"}
            })
            .to_string(),
        );

        let result = create_namespace(
            axum::extract::State(state),
            axum::http::HeaderMap::new(),
            ns_body,
        )
        .await;

        assert!(
            result.is_ok(),
            "create_namespace must succeed when webhook allows"
        );

        let stored = store
            .get(&crate::keys::cluster_object_key("namespaces", "test-ns"))
            .await
            .unwrap()
            .expect("namespace must be stored");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["labels"]["admitted"], "yes",
            "mutating webhook label must be present in stored namespace — \
             without the fix, create_namespace bypassed admission and the label was never injected"
        );
    }

    /// create_namespace must invoke the validating admission pipeline.
    /// A validating webhook that denies must cause create_namespace to return an error,
    /// and the namespace must NOT be stored.
    #[tokio::test]
    async fn create_namespace_invokes_validating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        let deny_router = Router::new().route(
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
        );

        let (url, _handle) = start_mock_webhook(deny_router).await;

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-validating-ns"},
            "webhooks": [{
                "name": "deny.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["namespaces"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-validating-ns",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let ns_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": "denied-ns"}
            })
            .to_string(),
        );

        let result = create_namespace(
            axum::extract::State(state),
            axum::http::HeaderMap::new(),
            ns_body,
        )
        .await;

        assert!(
            result.is_err(),
            "create_namespace must be rejected when validating webhook denies — \
             without the fix, admission was bypassed and the namespace was silently stored"
        );

        let stored = store
            .get(&crate::keys::cluster_object_key("namespaces", "denied-ns"))
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "denied namespace must not be stored in the backing store"
        );
    }
}
