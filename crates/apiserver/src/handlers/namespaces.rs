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
        json_patch::{
            apply_json_patch, detect_patch_type, ssa_body_to_json, PatchQuery, PatchType,
        },
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
            "",
            "namespaces",
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
    Extension(user): Extension<UserInfo>,
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
                // proto-encoded Namespace in Unknown.raw — not JSON. Decode via the dispatch
                // table; fall back to JSON only if proto fails.
                match proto::decode_proto_by_kind_and_version("Namespace", "", &env.raw) {
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

    // Inject the kubernetes.io/metadata.name label required for namespaceSelector evaluation.
    // Kubernetes stamps this label automatically on every namespace at creation time so that
    // admission webhook namespaceSelectors using matchExpressions on this label work correctly
    // (e.g. to exempt specific namespaces from a webhook). Without it, selectors like
    // `key: kubernetes.io/metadata.name, operator: NotIn, values: [kube-system]` would have
    // no label to match against and every namespace would appear to be in scope.
    {
        let labels = obj.body["metadata"]["labels"].clone();
        let mut labels_map = match labels {
            serde_json::Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        labels_map
            .entry("kubernetes.io/metadata.name")
            .or_insert_with(|| serde_json::Value::String(name.clone()));
        obj.body["metadata"]["labels"] = serde_json::Value::Object(labels_map);
    }

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "namespaces",
        name: &name,
        namespace: None,
        operation: "CREATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
        })),
        dry_run: false,
    };
    obj.body = run_mutating_webhooks(&state, obj.body, None, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;

    let key = cluster_object_key("namespaces", &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), Some(0))
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    // Seed kube-root-ca.crt synchronously so a pod admitted into this namespace
    // immediately after creation never races KCM's root-ca-cert-publisher for it.
    // Upstream, the publisher creates this ConfigMap asynchronously on its own
    // reconcile loop; a pod can be created (and its SA token volume admitted)
    // before that reconcile fires, and the kubelet then fails to mount the
    // projected volume with "configmap kube-root-ca.crt not found", hanging the
    // pod forever. KCM's publisher still POSTs its own copy later — that becomes
    // a 409 which the generic create-conflict path already handles.
    if let Some(ca_der) = state.cluster_ca_der.as_deref() {
        let cm_key = crate::keys::object_key("configmaps", &name, "kube-root-ca.crt");
        let ca_pem =
            String::from_utf8_lossy(&crate::tls::pem_encode("CERTIFICATE", ca_der)).into_owned();
        let cm_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "kube-root-ca.crt", "namespace": &name },
            "data": { "ca.crt": ca_pem }
        });
        match state
            .store
            .put(&cm_key, Bytes::from(cm_body.to_string()), Some(0))
            .await
        {
            Ok(_) => {}
            Err(StoreError::AlreadyExists { .. }) => {}
            Err(e) => tracing::warn!(
                "failed to seed kube-root-ca.crt in namespace {name}: {e} — \
                 pods created here may hang mounting their SA token volume until \
                 KCM's root-ca-cert-publisher creates it"
            ),
        }
    }

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
    Extension(user): Extension<UserInfo>,
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
                dry_run: patch_query.is_dry_run(),
                user_info: Some(serde_json::json!({
                    "username": user.username,
                    "uid": user.uid,
                    "groups": user.groups,
                })),
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = crate::util::extract_body(&body, ct);

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
    // CAS on the INCOMING request's resourceVersion, not the stored object's: /finalize is
    // a replace subresource, so a client holding a stale snapshot must get 409 and retry
    // rather than clobber a concurrent write. Absent rv stays unconditional (returns None).
    let incoming_meta: ObjectMeta =
        serde_json::from_value(req["metadata"].clone()).unwrap_or_default();
    let expected_rv = parse_resource_version(incoming_meta.resource_version.as_deref())?;
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

    crate::handlers::status::merge_incoming_metadata(&mut current.body, &incoming.body);

    let expected_rv = parse_resource_version(incoming.resource_version())?;
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
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");

    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // apply-patch+yaml bodies are genuine YAML (e.g. kubectl apply --server-side status);
    // every other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
    };

    match patch_type {
        PatchType::Json => {
            // /status is a separate RBAC subresource from the main Namespace endpoint —
            // for Namespace this also guards Pod Security Admission: a caller with only
            // `namespaces/status` must not be able to rewrite the enforce/warn/audit
            // labels under /metadata/labels via a JSON Patch on this endpoint.
            crate::handlers::status::validate_status_json_patch_paths(&patch)?;
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
            crate::handlers::status::merge_incoming_metadata(&mut current.body, &patch);
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

/// Cascade-delete all objects in a namespace, respecting `metadata.finalizers`.
///
/// Objects with non-empty `metadata.finalizers` are soft-deleted: `deletionTimestamp` is
/// stamped and the object is persisted so the owning controller can observe the deletion
/// signal and remove its finalizer. Objects without finalizers are hard-deleted immediately.
///
/// Returns `true` if any objects were soft-deleted (i.e. had finalizers and were not
/// immediately removed). The caller uses this to decide whether the namespace itself must
/// remain alive in Terminating state — the namespace cannot hard-delete until all contained
/// objects with finalizers are cleared, matching Kubernetes OrderedNamespaceDeletion semantics.
///
/// The fast path (no finalizers on any object) is unaffected: all objects hard-delete and
/// the function returns `false`, allowing the namespace to hard-delete immediately.
async fn cascade_delete_namespace_resources<S: Store>(
    state: &AppState<S>,
    namespace: &str,
) -> bool {
    let objects = match state.store.list_namespace_objects(namespace).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("namespace {namespace}: cascade list failed: {e}");
            return false;
        }
    };

    let now = utc_now_rfc3339();
    let mut any_soft_deleted = false;
    for obj_stored in objects {
        let mut val: serde_json::Value = match serde_json::from_slice(&obj_stored.value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let has_finalizers = val["metadata"]["finalizers"]
            .as_array()
            .is_some_and(|f| !f.is_empty());
        if has_finalizers {
            // Soft-delete: stamp deletionTimestamp so the controller observes deletion.
            // Use an unconditional put (None) — we just read this object; a race
            // that adds a finalizer between our read and this write is acceptable
            // because deletionTimestamp is monotonically stamped (never cleared).
            val["metadata"]["deletionTimestamp"] = serde_json::Value::String(now.clone());
            let updated = serde_json::to_vec(&val).unwrap_or_default();
            if let Err(e) = state
                .store
                .put(&obj_stored.key, bytes::Bytes::from(updated), None)
                .await
            {
                tracing::warn!(
                    "namespace {namespace}: soft-delete {} failed: {e}",
                    obj_stored.key
                );
            } else {
                any_soft_deleted = true;
            }
        } else {
            if let Err(e) = state.store.delete(&obj_stored.key, None).await {
                tracing::warn!(
                    "namespace {namespace}: hard-delete {} failed: {e}",
                    obj_stored.key
                );
            }
        }
    }
    any_soft_deleted
}

/// Cascade-delete a namespace's resources, re-verifying emptiness before letting the
/// caller hard-delete the namespace, retrying if a resource is still present.
///
/// `create_namespaced_resource` (and the CR equivalent) rejects writes into a namespace
/// whose `status.phase` is already `Terminating` — but that check reads the namespace,
/// then later writes the new object, a classic check-then-act window. A create that lands
/// in that window is invisible to a single `cascade_delete_namespace_resources` pass: its
/// own `list_namespace_objects` snapshot is taken before the racing write lands, so its
/// delete loop can't touch an object it doesn't know exists yet. If the caller trusts that
/// one pass and hard-deletes the namespace immediately after, the racily-created object is
/// orphaned forever: it has no namespace left to ever re-drain it, and — if it was still
/// Pending/unscheduled — it silently blocks anything that requires every pod cluster-wide
/// to be scheduled, e.g. the SchedulerPredicates/SchedulerPreemption conformance suite's
/// "wait for stable cluster" precondition (bd mayor-35zvy).
///
/// Returns `true` if the namespace must stay Terminating (a finalizer'd object needs its
/// controller to act, or resources kept reappearing after the retry budget ran out) and
/// `false` once a pass finds nothing left to soft-delete and a fresh list confirms empty.
async fn cascade_delete_namespace_resources_until_stable<S: Store>(
    state: &AppState<S>,
    namespace: &str,
) -> bool {
    const MAX_ATTEMPTS: u32 = 5;
    for _ in 0..MAX_ATTEMPTS {
        if cascade_delete_namespace_resources(state, namespace).await {
            // A finalizer'd object was soft-deleted — its controller owns finishing this,
            // not us. No amount of retrying here will make it disappear faster.
            return true;
        }
        match state.store.list_namespace_objects(namespace).await {
            Ok(remaining) if remaining.is_empty() => return false,
            Ok(_) => continue, // an object appeared after this pass's cascade — retry
            Err(_) => return false,
        }
    }
    // Objects kept reappearing across every retry — don't hard-delete out from under them.
    true
}

/// Check if a Terminating namespace can now be hard-deleted.
///
/// Called after an object in a namespace has its finalizers cleared and is hard-deleted.
/// If the namespace has `deletionTimestamp` set and `spec.finalizers` is empty, and no
/// remaining objects in the namespace have `metadata.finalizers`, the namespace is
/// hard-deleted (along with any remaining finalizer-free objects).
///
/// This is the completion trigger for the OrderedNamespaceDeletion flow:
///   1. delete_namespace soft-deletes finalizer'd objects + keeps namespace Terminating
///   2. controller removes finalizer from object → object is hard-deleted → this function runs
///   3. if no more finalizer'd objects remain → namespace hard-deletes
pub(crate) async fn maybe_finalize_terminating_namespace<S: Store>(
    state: &AppState<S>,
    namespace: &str,
) {
    let ns_key = cluster_object_key("namespaces", namespace);
    let ns_stored = match state.store.get(&ns_key).await {
        Ok(Some(v)) => v,
        _ => return,
    };
    let ns_val: serde_json::Value = match serde_json::from_slice(&ns_stored.value) {
        Ok(v) => v,
        Err(_) => return,
    };
    let ns_meta: ObjectMeta =
        serde_json::from_value(ns_val["metadata"].clone()).unwrap_or_default();
    if ns_meta.deletion_timestamp.is_none() {
        return;
    }
    let ns_spec: NamespaceSpec = serde_json::from_value(ns_val["spec"].clone()).unwrap_or_default();
    let spec_finalizers_empty = ns_spec
        .finalizers
        .as_deref()
        .map(|f| f.is_empty())
        .unwrap_or(true);
    if !spec_finalizers_empty {
        return;
    }
    // Check if any objects in the namespace still have metadata.finalizers.
    let objects = match state.store.list_namespace_objects(namespace).await {
        Ok(v) => v,
        Err(_) => return,
    };
    let any_remaining_finalizers = objects.iter().any(|obj| {
        serde_json::from_slice::<serde_json::Value>(&obj.value)
            .ok()
            .and_then(|v| {
                v["metadata"]["finalizers"]
                    .as_array()
                    .map(|f| !f.is_empty())
            })
            .unwrap_or(false)
    });
    if any_remaining_finalizers {
        return;
    }
    // No remaining finalizer'd objects — hard-delete remaining objects and the namespace.
    for obj in objects {
        let _ = state.store.delete(&obj.key, None).await;
    }
    delete_namespace_scoped_crds(state, namespace).await;
    let _ = state.store.delete(&ns_key, None).await;
}

/// Delete all CRDs whose `spec.group` contains `namespace_name` as a substring.
///
/// CRDs created by test frameworks (e.g. VAP conformance) embed the namespace name in their
/// group, e.g. `crontabs.stable.<namespace>.example.com`.  When the namespace is deleted,
/// KCM's GC/quota controller registers a cluster-wide watch on that group; as long as the
/// CRD exists, KCM re-queues the namespace drain forever and the namespace never finishes
/// terminating.  Deleting the CRD here (with its tombstone) breaks the cycle.  Errors are
/// non-fatal.
async fn delete_namespace_scoped_crds<S: Store>(state: &AppState<S>, namespace_name: &str) {
    let prefix = "/registry/apiextensions.k8s.io/customresourcedefinitions/";
    let resp = match state.store.list(prefix, ListOptions::default()).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("cascade-delete CRDs for namespace {namespace_name}: list failed: {e}");
            return;
        }
    };

    for item in resp.items {
        let crd: serde_json::Value = match serde_json::from_slice(&item.value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let group = match crd["spec"]["group"].as_str() {
            Some(g) => g,
            None => continue,
        };
        if !group.contains(namespace_name) {
            continue;
        }
        let crd_name = match crd["metadata"]["name"].as_str() {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };
        let key = format!("/registry/apiextensions.k8s.io/customresourcedefinitions/{crd_name}");
        if let Err(e) = state.store.delete(&key, None).await {
            tracing::warn!("cascade-delete CRD {crd_name} for namespace {namespace_name}: {e}");
            continue;
        }
        let tombstone_key = crate::handlers::crd::deleted_group_tombstone_key(group);
        let tombstone_val =
            serde_json::to_vec(&serde_json::json!({ "group": group })).unwrap_or_default();
        let _ = state
            .store
            .put(&tombstone_key, bytes::Bytes::from(tombstone_val), None)
            .await;
    }
}

pub async fn delete_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    Extension(user): Extension<UserInfo>,
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

    // Admission webhook pipeline (validating only — mutating webhooks do not apply to DELETE).
    // Run once here, before branching into soft-delete/finalizer logic below, matching every
    // other delete handler's single admission point.
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "namespaces",
        name: &name,
        namespace: None,
        operation: "DELETE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
        })),
        dry_run: false,
    };
    run_validating_webhooks(&state, &obj.body, Some(&obj.body), &admission_ctx).await?;

    if let Some(mut soft) = apply_delete_policy(&mut obj) {
        soft["status"] = serde_json::to_value(NamespaceStatus {
            phase: Some(NamespacePhase::Terminating),
            rest: serde_json::Value::Object(Default::default()),
        })
        .map_err(|e| Status::internal(format!("failed to serialize NamespaceStatus: {e}")))?;
        obj.body = soft;

        // spec.finalizers (including "kubernetes") is left untouched. deletionTimestamp +
        // "kubernetes" in spec.finalizers is the real KCM namespace-controller's ONLY watch
        // trigger for its v1.34+ ordered content-deletion sequence, which is what sets
        // status.conditions (NamespaceDeletionContentFailure etc.) that OrderedNamespaceDeletion
        // polls for. u7s used to self-clear "kubernetes" here, acting as its own namespace
        // controller — but that erased the trigger before the real controller could ever
        // observe it, so it never ran. The real controller now owns clearing spec.finalizers,
        // via PUT .../finalize (finalize_namespace), once its drain completes.

        // Persist status.phase=Terminating to the store. create_namespaced_resource's
        // Terminating gate reads this stored value, so a racing controller create is
        // rejected the instant this write lands — before the real namespace controller
        // (or anything else) does any further work (bd mayor-74j3.6).
        let expected_rv = parse_resource_version(obj.resource_version())?;
        let new_rv = state
            .store
            .put(&key, obj.to_bytes(), expected_rv)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
        obj.set_resource_version(new_rv);

        // Content deletion itself is deliberately NOT done here anymore: it is the real
        // KCM namespace-controller's job, and it runs its resource types in a specific
        // order (pods first, then everything else — KEP-5080). u7s previously ran its own
        // synchronous best-effort cascade in parallel, but that raced ahead of KCM and
        // deleted later-phase objects (e.g. a plain ConfigMap) essentially at the same
        // instant as the pod, collapsing the very ordering window
        // OrderedNamespaceDeletion asserts on (namespace.go:581-610 polls for the
        // ConfigMap to still exist while the pod already has deletionTimestamp set).
        // delete_namespace_scoped_crds still runs: it deletes CRDs whose group embeds this
        // namespace's name, a u7s-specific problem unrelated to ordinary namespace content
        // (CRDs are cluster-scoped and KCM's namespace-controller has no notion of them
        // belonging to this namespace) — without it KCM's discovery re-scan never settles.
        delete_namespace_scoped_crds(&state, &name).await;

        return Ok(Json(obj.body).into_response());
    }

    // No spec.finalizers — hard-delete immediately (namespace was not given a lifecycle
    // controller, e.g. seeded directly in tests). Cascade-delete all resources first so
    // that re-creating the namespace does not inherit stale objects (false 409).
    // Objects with metadata.finalizers are still soft-deleted for correctness but the
    // namespace itself is immediately gone (no Terminating state mechanism without
    // deletionTimestamp on the namespace).
    cascade_delete_namespace_resources_until_stable(&state, &name).await;
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
                extra: Default::default(),
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

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
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
                test_user(),
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

    // create_namespace must synchronously seed "kube-root-ca.crt" in the new namespace.
    //
    // A pod can be created in a brand-new namespace immediately after it is created —
    // before KCM's root-ca-cert-publisher has run its own async reconcile for that
    // namespace. The ServiceAccount admission auto-mounts a projected SA token volume
    // that references "kube-root-ca.crt" by name; if it doesn't exist yet, the kubelet
    // fails to mount the volume ("configmap kube-root-ca.crt not found") and the pod
    // hangs forever. This test fails if that seeding is removed or broken.
    #[tokio::test]
    async fn create_namespace_seeds_kube_root_ca_configmap() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let cert = rcgen::generate_simple_self_signed(vec!["10.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(ca_der.clone()),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            namespace_body("fresh-ns"),
        )
        .await
        .expect("create must succeed");

        let cm_key = crate::keys::object_key("configmaps", "fresh-ns", "kube-root-ca.crt");
        let stored = state
            .store
            .get(&cm_key)
            .await
            .expect("store get must not error")
            .unwrap_or_else(|| {
                panic!(
                    "kube-root-ca.crt must exist in a freshly created namespace — \
                     without it, the projected SA token volume the ServiceAccount \
                     admission injects into every pod fails to mount and the pod \
                     never reaches Running"
                )
            });
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored value must be valid JSON");
        assert_eq!(body["data"]["ca.crt"].as_str().unwrap_or(""), {
            let pem = crate::tls::pem_encode("CERTIFICATE", &ca_der);
            String::from_utf8(pem).unwrap()
        });
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
                test_user(),
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

    /// create_namespace must stamp kubernetes.io/metadata.name on every namespace.
    ///
    /// This label is required for admission webhook namespaceSelector evaluation. Webhooks
    /// use matchExpressions like `{key: kubernetes.io/metadata.name, operator: NotIn,
    /// values: ["kube-system"]}` to exclude specific namespaces. Without this label the
    /// expression has nothing to match — `has_key` is false, `NotIn` returns `true`, and
    /// the webhook fires for ALL namespaces regardless of their intended exemption.
    #[tokio::test]
    async fn create_namespace_stamps_kubernetes_metadata_name_label() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("label-test-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "label-test-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("namespace must exist in store");
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored value must be valid JSON");

        assert_eq!(
            body["metadata"]["labels"]["kubernetes.io/metadata.name"],
            serde_json::Value::String("label-test-ns".into()),
            "create_namespace must stamp kubernetes.io/metadata.name label so admission webhook \
             namespaceSelector matchExpressions (e.g. NotIn, DoesNotExist) can evaluate \
             correctly against this namespace; without it, exemption-based selectors fail"
        );
    }

    /// create_namespace must preserve user-supplied labels AND inject kubernetes.io/metadata.name.
    ///
    /// If the user supplies labels (e.g. a CI label or exemption marker), those must survive
    /// the metadata.name injection. A bug here would silently drop user labels or incorrectly
    /// overwrite them with just the metadata.name label, breaking namespace selectors that
    /// rely on user-supplied labels.
    #[tokio::test]
    async fn create_namespace_preserves_existing_labels_when_injecting_metadata_name() {
        let state = make_state();
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "labeled-ns",
                    "labels": {
                        "myapp": "true",
                        "env": "test"
                    }
                }
            })
            .to_string(),
        );

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                body,
            )
            .await
            .is_ok(),
            "create with existing labels must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "labeled-ns"))
            .await
            .expect("store get must not error")
            .expect("namespace must exist in store");
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored value must be valid JSON");

        assert_eq!(
            body["metadata"]["labels"]["kubernetes.io/metadata.name"],
            serde_json::Value::String("labeled-ns".into()),
            "kubernetes.io/metadata.name must be injected"
        );
        assert_eq!(
            body["metadata"]["labels"]["myapp"],
            serde_json::Value::String("true".into()),
            "user-supplied labels must be preserved when metadata.name is injected"
        );
        assert_eq!(
            body["metadata"]["labels"]["env"],
            serde_json::Value::String("test".into()),
            "all user-supplied labels must survive metadata.name injection"
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
                test_user(),
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
                test_user(),
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
                test_user(),
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
                test_user(),
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

    // delete_namespace must leave the "kubernetes" finalizer (and deletionTimestamp) in
    // place rather than self-clearing it. deletionTimestamp != nil && "kubernetes" in
    // spec.finalizers is the real KCM namespace-controller's ONLY watch trigger for its
    // ordered content-deletion sequence — the sequence that sets status.conditions like
    // NamespaceDeletionContentFailure, which OrderedNamespaceDeletion polls for. If
    // delete_namespace strips "kubernetes" itself (as it used to, acting as its own
    // namespace controller), that trigger vanishes before the real controller ever
    // observes it, so the controller — and the condition — never run.
    //
    // Fails on revert: reverting to the self-clear makes spec.finalizers empty and hard-deletes
    // the namespace immediately here, instead of leaving it Terminating with "kubernetes"
    // present for the real controller to finalize.
    #[tokio::test]
    async fn delete_namespace_leaves_kubernetes_finalizer_for_real_controller() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("del-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        assert!(
            delete_namespace(
                State(state.clone()),
                Path("del-ns".to_string()),
                test_user()
            )
            .await
            .is_ok(),
            "delete must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "del-ns"))
            .await
            .expect("store get must not error")
            .expect(
                "namespace must NOT be hard-deleted by delete_namespace — only the real \
                 namespace controller, via PUT /finalize, may remove the \"kubernetes\" \
                 finalizer and complete the deletion",
            );
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            body["status"]["phase"], "Terminating",
            "namespace must be Terminating, awaiting the real namespace controller's drain"
        );
        assert!(
            body["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must be set — together with the \"kubernetes\" finalizer this \
             is the real namespace controller's only watch trigger"
        );
        let finalizers = body["spec"]["finalizers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            finalizers,
            vec![Some("kubernetes")],
            "delete_namespace must leave the \"kubernetes\" finalizer in place — self-clearing \
             it erases the real namespace controller's watch trigger before it can ever \
             observe deletionTimestamp != nil && \"kubernetes\" in spec.finalizers, so the \
             controller (and its NamespaceDeletionContentFailure status condition) never runs"
        );
    }

    // delete_namespace must leave ALL spec.finalizers untouched, whether "kubernetes" or an
    // external controller's own. Completion is driven entirely by PUT /finalize: each owning
    // controller removes only its own finalizer once its own work is done, and the namespace
    // hard-deletes only once every finalizer is gone. This is the conformance test flow for
    // "should apply a finalizer to a namespace".
    #[tokio::test]
    async fn delete_namespace_with_external_finalizer_stays_terminating_until_cleared() {
        let state = make_state();

        // Create with kubernetes finalizer (stamped by create_namespace).
        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("ext-fin-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Simulate an external controller adding its own finalizer via PUT /finalize.
        let add_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "ext-fin-ns" },
                "spec": { "finalizers": ["kubernetes", "e2e.example.com"] }
            })
            .to_string(),
        );
        assert!(
            finalize_namespace(
                State(state.clone()),
                Path("ext-fin-ns".to_string()),
                axum::http::HeaderMap::new(),
                add_body,
            )
            .await
            .is_ok(),
            "adding e2e finalizer must succeed"
        );

        // Delete the namespace — BOTH finalizers must remain; only their owning controllers
        // may remove them, via PUT /finalize.
        assert!(
            delete_namespace(
                State(state.clone()),
                Path("ext-fin-ns".to_string()),
                test_user()
            )
            .await
            .is_ok(),
            "delete must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "ext-fin-ns"))
            .await
            .expect("store get must not error")
            .expect("namespace must still exist — its finalizers keep it alive");
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            body["status"]["phase"], "Terminating",
            "namespace must be Terminating while any finalizer is present"
        );
        let finalizers = body["spec"]["finalizers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            finalizers,
            vec![Some("kubernetes"), Some("e2e.example.com")],
            "delete_namespace must not remove \"kubernetes\" — only the real namespace \
             controller may, via PUT /finalize, once its own drain completes"
        );

        // External controller removes only its own finalizer via PUT /finalize; "kubernetes"
        // is left alone, so the namespace must still be alive.
        let remove_ext_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "ext-fin-ns" },
                "spec": { "finalizers": ["kubernetes"] }
            })
            .to_string(),
        );
        assert!(
            finalize_namespace(
                State(state.clone()),
                Path("ext-fin-ns".to_string()),
                axum::http::HeaderMap::new(),
                remove_ext_body,
            )
            .await
            .is_ok(),
            "removing external finalizer must succeed"
        );
        assert!(
            state
                .store
                .get(&crate::keys::cluster_object_key("namespaces", "ext-fin-ns"))
                .await
                .expect("store get must not error")
                .is_some(),
            "namespace must still exist — the \"kubernetes\" finalizer is still present"
        );

        // The real namespace controller (KCM) removes "kubernetes" once its own content
        // drain completes.
        let remove_k8s_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "ext-fin-ns" },
                "spec": { "finalizers": [] }
            })
            .to_string(),
        );
        assert!(
            finalize_namespace(
                State(state.clone()),
                Path("ext-fin-ns".to_string()),
                axum::http::HeaderMap::new(),
                remove_k8s_body,
            )
            .await
            .is_ok(),
            "removing kubernetes finalizer must succeed"
        );

        // Namespace must now be gone.
        let after = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "ext-fin-ns"))
            .await
            .expect("store get must not error");
        assert!(
            after.is_none(),
            "namespace must hard-delete once ALL finalizers are removed — \
             this is the conformance test flow: add external finalizer, delete namespace, \
             remove external finalizer, remove kubernetes finalizer, namespace disappears"
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
                test_user(),
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
                extra: Default::default(),
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
                test_user(),
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
                extra: Default::default(),
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
                test_user(),
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

        let result = create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
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

        let result = create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
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
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("dup-ns"),
            )
            .await
            .is_ok(),
            "first create must succeed"
        );

        let result = create_namespace(
            State(state.clone()),
            test_user(),
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
            test_user(),
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
            test_user(),
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

        let result = delete_namespace(
            State(state.clone()),
            Path("ghost-ns".to_string()),
            test_user(),
        )
        .await;
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

    // delete_namespace with an explicit "kubernetes" finalizer (set at creation time rather
    // than auto-stamped) must still leave it in place and keep the namespace Terminating —
    // only the real namespace controller, via PUT /finalize, may remove it.
    #[tokio::test]
    async fn delete_namespace_with_finalizers_stays_terminating() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body_with_finalizers("fin-ns", &["kubernetes"]),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        assert!(
            delete_namespace(
                State(state.clone()),
                Path("fin-ns".to_string()),
                test_user()
            )
            .await
            .is_ok(),
            "delete with finalizers must not error"
        );

        // The namespace must still exist, with "kubernetes" still in spec.finalizers — u7s
        // must not act as the namespace controller and clear it synchronously.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "fin-ns"))
            .await
            .expect("store get must not error")
            .expect(
                "namespace must NOT be hard-deleted when the kubernetes finalizer is present — \
                 only the real namespace controller, via PUT /finalize, may remove it",
            );
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let finalizers = body["spec"]["finalizers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            finalizers,
            vec![Some("kubernetes")],
            "delete_namespace must not self-clear the kubernetes finalizer, regardless of \
             whether it was auto-stamped or explicitly set at creation time"
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
            delete_namespace(
                State(state.clone()),
                Path("no-fin-ns".to_string()),
                test_user()
            )
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
        delete_namespace(
            State(state.clone()),
            Path("recycled-ns".to_string()),
            test_user(),
        )
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
            test_user(),
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
    // finalizers become empty after the patch. This covers the case where a namespace
    // was written directly to the store in Terminating state (e.g. migrated from an
    // older version) and a client clears the finalizer via PATCH.
    #[tokio::test]
    async fn patch_namespace_hard_deletes_when_finalizers_cleared_with_deletion_ts() {
        use u7s_store::Store;
        let state = make_state();

        // Write a namespace directly to the store with deletionTimestamp set and a
        // custom finalizer (not "kubernetes") to simulate a namespace that is already
        // Terminating and being drained by an external controller.
        let key = crate::keys::cluster_object_key("namespaces", "drain-ns");
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "drain-ns",
                "uid": "00000000-0000-0000-0000-000000000001",
                "resourceVersion": "1",
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "finalizers": ["other-controller"] },
            "status": { "phase": "Terminating" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(ns.to_string()), Some(0))
            .await
            .expect("direct store write must succeed");

        // Remove the finalizer via merge-patch — this must trigger a hard-delete.
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
                test_user(),
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
                test_user(),
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
    // This is the real completion path: delete_namespace no longer self-clears the
    // "kubernetes" finalizer, so the real KCM namespace-controller calls this endpoint to
    // remove it once its content-deletion sequence completes. The behavior must be correct
    // regardless of how the namespace entered the Terminating state.
    #[tokio::test]
    async fn finalize_namespace_hard_deletes_when_spec_finalizers_empty_with_deletion_ts() {
        use u7s_store::Store;
        let state = make_state();

        // Write a namespace directly to the store with deletionTimestamp already set
        // and a custom finalizer, simulating a namespace in Terminating state.
        let key = crate::keys::cluster_object_key("namespaces", "finalize-ns");
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "finalize-ns",
                "uid": "00000000-0000-0000-0000-000000000002",
                "resourceVersion": "1",
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "finalizers": ["other-controller"] },
            "status": { "phase": "Terminating" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(ns.to_string()), Some(0))
            .await
            .expect("direct store write must succeed");

        // PUT /finalize with spec.finalizers: [] to remove the finalizer.
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
                axum::http::HeaderMap::new(),
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
             must hard-delete the namespace — without this the namespace stays Terminating forever."
        );
    }

    // finalize_namespace must only update finalizers and persist (not hard-delete)
    // when spec.finalizers is non-empty after the PUT.
    //
    // Only the last removal (empty finalizers) triggers hard-delete.
    #[tokio::test]
    async fn finalize_namespace_persists_when_spec_finalizers_non_empty() {
        use u7s_store::Store;
        let state = make_state();

        // Write a namespace directly to the store with deletionTimestamp already set
        // and two custom finalizers, simulating a namespace with multiple controllers.
        let key = crate::keys::cluster_object_key("namespaces", "multi-fin-ns");
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "multi-fin-ns",
                "uid": "00000000-0000-0000-0000-000000000003",
                "resourceVersion": "1",
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "finalizers": ["controller-a", "controller-b"] },
            "status": { "phase": "Terminating" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(ns.to_string()), Some(0))
            .await
            .expect("direct store write must succeed");

        // Call finalize with one finalizer remaining (controller-a removed, controller-b stays).
        let finalize_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "multi-fin-ns" },
                "spec": { "finalizers": ["controller-b"] }
            })
            .to_string(),
        );

        assert!(
            finalize_namespace(
                State(state.clone()),
                Path("multi-fin-ns".to_string()),
                axum::http::HeaderMap::new(),
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
            "after finalize with spec.finalizers=[controller-b], only one finalizer must remain"
        );
        assert_eq!(
            finalizers[0].as_str(),
            Some("controller-b"),
            "the remaining finalizer must be 'controller-b'"
        );
    }

    // PUT /finalize with a stale resourceVersion must return 409 Conflict.
    // /finalize is a replace subresource: KCM's namespace controller reads the namespace,
    // removes a finalizer, and PUTs it back. If a concurrent write landed in between, the
    // stale PUT must be rejected so the controller retries from a fresh GET instead of
    // resurrecting stale finalizers (which would strand the namespace in Terminating).
    #[tokio::test]
    async fn finalize_namespace_stale_rv_returns_409() {
        use axum::response::IntoResponse;
        use u7s_store::Store;
        let state = make_state();

        let key = crate::keys::cluster_object_key("namespaces", "occ-fin-ns");
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "occ-fin-ns",
                "uid": "00000000-0000-0000-0000-000000000004",
                "resourceVersion": "1",
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "finalizers": ["controller-a", "controller-b"] },
            "status": { "phase": "Terminating" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(ns.to_string()), Some(0))
            .await
            .expect("direct store write must succeed");

        // Finalize with a STALE resourceVersion (store is at rv=1, not 99999) and finalizers
        // still non-empty (so it takes the persist path, not hard-delete).
        let finalize_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "occ-fin-ns", "resourceVersion": "99999" },
                "spec": { "finalizers": ["controller-b"] }
            })
            .to_string(),
        );

        let resp = finalize_namespace(
            State(state.clone()),
            Path("occ-fin-ns".to_string()),
            axum::http::HeaderMap::new(),
            finalize_body,
        )
        .await
        .into_response();

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::CONFLICT,
            "stale resourceVersion on PUT /finalize must return 409 Conflict — \
             otherwise the namespace controller resurrects stale finalizers over a concurrent \
             write and the namespace can stay stuck in Terminating"
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
            axum::http::HeaderMap::new(),
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
    // finalizers become empty after the PUT. This covers namespaces written directly
    // to the store in Terminating state (e.g. migrated from an older version).
    #[tokio::test]
    async fn replace_namespace_hard_deletes_when_finalizers_cleared_with_deletion_ts() {
        use u7s_store::Store;
        let state = make_state();

        // Write a namespace directly to the store with deletionTimestamp already set
        // and a custom finalizer, simulating a Terminating namespace.
        let key = crate::keys::cluster_object_key("namespaces", "put-drain-ns");
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "put-drain-ns",
                "uid": "00000000-0000-0000-0000-000000000004",
                "resourceVersion": "1",
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "finalizers": ["other-controller"] },
            "status": { "phase": "Terminating" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(ns.to_string()), Some(0))
            .await
            .expect("direct store write must succeed");

        // Remove the finalizer from the body and PUT — this must trigger hard-delete.
        let replace_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "put-drain-ns",
                    "uid": "00000000-0000-0000-0000-000000000004",
                    "resourceVersion": "1",
                    "deletionTimestamp": "2024-01-01T00:00:00Z"
                },
                "spec": { "finalizers": [] },
                "status": { "phase": "Terminating" }
            })
            .to_string(),
        );

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
             deletionTimestamp is set — without this, Terminating namespaces migrated from \
             older versions never complete deletion"
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
                test_user(),
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
                test_user(),
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
                test_user(),
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

    /// patch_namespace_status must accept a genuine multi-line YAML apply-patch+yaml body,
    /// not just a JSON body wearing the +yaml content-type.
    ///
    /// WHY this matters: this is the exact e2e ApplyStatus() gap that motivated this fix —
    /// "apply changes to a namespace status" calls ApplyStatus(), which sends real YAML
    /// block syntax to PATCH .../namespaces/{name}/status. Before this fix,
    /// patch_namespace_status had no is_ssa handling at all: detect_patch_type accepted the
    /// content type, but the body was still parsed with serde_json::from_slice, which
    /// rejects YAML outright with "invalid patch JSON" — ApplyStatus() 400'd and the e2e
    /// client panicked indexing an empty conditions slice.
    #[tokio::test]
    async fn patch_namespace_status_accepts_real_yaml_apply_patch_body() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("ssa-status-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Genuine YAML block syntax — NOT JSON serialized to bytes.
        let patch_body = Bytes::from_static(
            b"status:\n  conditions:\n  - type: NamespaceDeletionContentFailure\n    status: \"False\"\n",
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let result = patch_namespace_status(
            State(state.clone()),
            Path("ssa-status-ns".to_string()),
            headers,
            patch_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "apply-patch+yaml with a genuine YAML body on namespace /status must succeed, \
             not 400 'invalid patch JSON': {:?}",
            result.err()
        );
    }

    /// A JSON Patch targeting only /status must still be accepted on the /status endpoint.
    ///
    /// This is the companion happy-path to the rejection tests below: the path guard must
    /// not be so strict that it blocks legitimate status-only JSON Patches (e.g. KCM
    /// appending a condition via JSON Patch instead of merge-patch).
    #[tokio::test]
    async fn patch_namespace_status_json_patch_touching_only_status_succeeds() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("json-status-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!([
                { "op": "add", "path": "/status/phase", "value": "Active" }
            ])
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );

        assert!(
            patch_namespace_status(
                State(state.clone()),
                Path("json-status-ns".to_string()),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "a JSON Patch touching only /status must be accepted on the /status endpoint"
        );
    }

    /// A JSON Patch to .../namespaces/{ns}/status targeting /metadata/labels must be
    /// REJECTED — /status is a separate RBAC subresource from the main Namespace
    /// endpoint, and for Namespace this is a concrete Pod Security Admission bypass:
    /// a caller with only `namespaces/status` rights could otherwise rewrite the
    /// pod-security.kubernetes.io/enforce label to weaken or disable PSA for the
    /// namespace without ever touching the main PATCH/PUT endpoint.
    #[tokio::test]
    async fn patch_namespace_status_json_patch_rejects_metadata_labels() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("psa-bypass-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!([
                {
                    "op": "add",
                    "path": "/metadata/labels",
                    "value": { "pod-security.kubernetes.io/enforce": "privileged" }
                }
            ])
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );

        let err = match patch_namespace_status(
            State(state.clone()),
            Path("psa-bypass-ns".to_string()),
            headers,
            patch_body,
        )
        .await
        {
            Ok(_) => panic!(
                "a JSON Patch on /status targeting /metadata/labels must be rejected — \
                 otherwise a status-only grant lets a caller rewrite the PSA enforce \
                 label and bypass Pod Security Admission for the namespace"
            ),
            Err(e) => e,
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "rejection must be 422 Unprocessable Entity (same as status.rs's generic guard)"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "psa-bypass-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            body["metadata"]["labels"]["pod-security.kubernetes.io/enforce"].is_null(),
            "the PSA enforce label must NOT have been written by the rejected status patch"
        );
    }

    /// A JSON Patch to .../namespaces/{ns}/status targeting /spec must be REJECTED —
    /// same RBAC-isolation rule as /metadata, generalized: spec is never reachable via
    /// the status subresource, regardless of whether the resource even has a spec.
    #[tokio::test]
    async fn patch_namespace_status_json_patch_rejects_spec() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("spec-bypass-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!([
                { "op": "add", "path": "/spec/finalizers", "value": [] }
            ])
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );

        assert!(
            patch_namespace_status(
                State(state.clone()),
                Path("spec-bypass-ns".to_string()),
                headers,
                patch_body,
            )
            .await
            .is_err(),
            "a JSON Patch on /status targeting /spec must be rejected"
        );
    }

    /// A MERGE patch to .../namespaces/{ns}/status setting `metadata.labels` must not
    /// change the stored labels — same PSA-bypass class as #733's JSON-Patch fix, but a
    /// different content-type: merge-patch (and strategic-merge-patch) reach /status
    /// through `merge_incoming_metadata`, not `validate_status_json_patch_paths`, so
    /// closing only the JSON-Patch vector left this one open. A caller with only
    /// `namespaces/status` rights could otherwise rewrite
    /// `pod-security.kubernetes.io/enforce` via a plain merge-patch and bypass PSA.
    #[tokio::test]
    async fn patch_namespace_status_merge_patch_rejects_metadata_labels() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("psa-merge-bypass-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!({
                "metadata": {
                    "labels": { "pod-security.kubernetes.io/enforce": "privileged" }
                },
                "status": { "phase": "Active" }
            })
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_namespace_status(
            State(state.clone()),
            Path("psa-merge-bypass-ns".to_string()),
            headers,
            patch_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "a merge-patch to /status must still succeed — the label change is dropped, \
             not rejected, mirroring how finalizers/deletionTimestamp are already restored"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "psa-merge-bypass-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            body["metadata"]["labels"]["pod-security.kubernetes.io/enforce"].is_null(),
            "a merge-patch on /status must NOT be able to set the PSA enforce label — \
             otherwise a status-only grant can silently weaken Pod Security Admission"
        );
        assert_eq!(
            body["status"]["phase"], "Active",
            "the legitimate status change in the same patch must still apply"
        );
    }

    /// A merge-patch to .../namespaces/{ns}/status must ignore `/spec` even when the
    /// patch body includes it — spec is never read by the merge/strategic-merge branch
    /// of patch_namespace_status, but this locks that in as an explicit regression test
    /// rather than relying on it being an accidental side effect of what the handler reads.
    #[tokio::test]
    async fn patch_namespace_status_merge_patch_ignores_spec() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("spec-merge-bypass-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!({
                "spec": { "finalizers": ["attacker.io/blocker"] },
                "status": { "phase": "Active" }
            })
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_namespace_status(
            State(state.clone()),
            Path("spec-merge-bypass-ns".to_string()),
            headers,
            patch_body,
        )
        .await;
        assert!(result.is_ok(), "a merge-patch to /status must succeed");

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "spec-merge-bypass-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            body["spec"]["finalizers"]
                .as_array()
                .map(|a| !a.iter().any(|v| v == "attacker.io/blocker"))
                .unwrap_or(true),
            "spec must not be modified by a merge-patch to /status — \
             a status-only grant must not be able to add a spec.finalizer"
        );
    }

    // -----------------------------------------------------------------------
    // Regression: PUT /status with Content-Type: application/vnd.kubernetes.protobuf
    // must persist status.conditions (mayor-ftkl PANIC-1)
    // -----------------------------------------------------------------------

    /// Build a protobuf varint (LEB128) encoding of v.
    fn encode_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    /// Encode a length-delimited protobuf field (wire type 2).
    fn encode_ld(field: u64, payload: &[u8]) -> Vec<u8> {
        let tag = (field << 3) | 2;
        let mut out = encode_varint(tag);
        out.extend_from_slice(&encode_varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    /// Build a k8s proto envelope for a PUT `.../namespaces/{name}/status` body carrying
    /// two conditions — the exact shape client-go's typed clientset sends for
    /// `nsClient.UpdateStatus(...)` once the e2e "should apply changes to a namespace
    /// status" test has GET'd the namespace, appended a condition locally, and calls
    /// UpdateStatus. The upstream e2e framework defaults every typed clientset's REST
    /// ContentType to `application/vnd.kubernetes.protobuf`
    /// (test/e2e/framework/test_context.go's `--kube-api-content-type` flag) — a
    /// different client/process than this stack's kube-controller-manager, which we
    /// start with `--kube-api-content-type=application/json`.
    fn build_namespace_status_put_proto_envelope(name: &str) -> Vec<u8> {
        // NamespaceCondition{type:"StatusPatch", status:"True", reason:"E2E", message:"Patched by an e2e test"}
        let mut cond1 = encode_ld(1, b"StatusPatch");
        cond1.extend(encode_ld(2, b"True"));
        cond1.extend(encode_ld(5, b"E2E"));
        cond1.extend(encode_ld(6, b"Patched by an e2e test"));

        // NamespaceCondition{type:"StatusUpdate", status:"True", reason:"E2E", message:"Updated by an e2e test"}
        let mut cond2 = encode_ld(1, b"StatusUpdate");
        cond2.extend(encode_ld(2, b"True"));
        cond2.extend(encode_ld(5, b"E2E"));
        cond2.extend(encode_ld(6, b"Updated by an e2e test"));

        // NamespaceStatus{phase:"Active", conditions:[cond1, cond2]}  (field 1 = phase, field 2 = conditions)
        let mut status = encode_ld(1, b"Active");
        status.extend(encode_ld(2, &cond1));
        status.extend(encode_ld(2, &cond2));

        // ObjectMeta{name: name}  (field 1 = name)
        let obj_meta = encode_ld(1, name.as_bytes());

        // Namespace{metadata: field 1, status: field 3}
        let mut namespace_proto = encode_ld(1, &obj_meta);
        namespace_proto.extend(encode_ld(3, &status));

        // TypeMeta{apiVersion:"v1", kind:"Namespace"}
        let mut type_meta = encode_ld(1, b"v1");
        type_meta.extend(encode_ld(2, b"Namespace"));

        // Unknown{typeMeta: field 1, raw: field 2} — contentType (field 4) left empty,
        // matching what client-go sends for core types with a registered proto codec.
        let mut unknown = encode_ld(1, &type_meta);
        unknown.extend(encode_ld(2, &namespace_proto));

        let mut body = vec![0x6b, 0x38, 0x73, 0x00]; // k8s proto magic
        body.extend(unknown);
        body
    }

    // put_namespace_status must persist status.conditions sent with Content-Type:
    // application/vnd.kubernetes.protobuf, not just application/json.
    //
    // The existing put_namespace_status_updates_conditions test above only sends plain
    // JSON, so it never exercised proto decoding and could not have caught this. But the
    // real "should apply changes to a namespace status" e2e test's typed clientset
    // defaults to protobuf (see build_namespace_status_put_proto_envelope's doc comment),
    // so that is the content type the conformance run actually hits. Before mayor-oww6's
    // fix to decode_namespace_proto_gen, this decoder never read `ns.status` at all, so a
    // protobuf-encoded PUT /status silently stored an empty status; the e2e client then
    // read back an empty Conditions slice and panicked with "index out of range [-1]"
    // indexing `Conditions[len(Conditions)-1]` (namespace.go:365). Namespace status
    // conditions must persist through this exact apply-status sequence or that panic
    // reproduces. This test fails on revert: reverting the `if let Some(status) =
    // ns.status` block in decode_namespace_proto_gen makes the asserted conditions
    // vanish from both the response and the store.
    #[tokio::test]
    async fn put_namespace_status_persists_conditions_from_protobuf_content_type() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("status-put-proto-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let proto_body = Bytes::from(build_namespace_status_put_proto_envelope(
            "status-put-proto-ns",
        ));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/vnd.kubernetes.protobuf".parse().unwrap(),
        );

        let resp = put_namespace_status(
            State(state.clone()),
            Path("status-put-proto-ns".to_string()),
            headers,
            proto_body,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "put_namespace_status must accept a protobuf-encoded body (got {:?})",
                e.0
            )
        })
        .into_response();

        let body_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("response must be valid JSON");

        assert_eq!(
            body["status"]["conditions"].as_array().map(Vec::len),
            Some(2),
            "namespace status.conditions must persist through the apply-status sequence \
             or the conformance test panics on Conditions[-1]; got {:?}",
            body["status"]["conditions"]
        );
        assert_eq!(
            body["status"]["conditions"][1]["type"], "StatusUpdate",
            "the last condition must be the one the e2e client appended before calling \
             UpdateStatus — this is exactly \
             `statusUpdated.Status.Conditions[len(statusUpdated.Status.Conditions)-1].Type` \
             at namespace.go:365"
        );

        // Persisted, not just echoed back in the response.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "status-put-proto-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let stored_body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_body["status"]["conditions"].as_array().map(Vec::len),
            Some(2),
            "conditions must be durably persisted to the store, not merely echoed back \
             in the PUT response"
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
                test_user(),
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
                dry_run: None,
            }),
            test_user(),
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
                test_user(),
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
                dry_run: None,
            }),
            test_user(),
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
                extra: Default::default(),
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

    /// Regression: cascade_delete_namespace_resources_until_stable must respect object
    /// metadata.finalizers.
    ///
    /// An object with non-empty metadata.finalizers must NOT be hard-deleted immediately.
    /// Instead it must receive deletionTimestamp and remain in the store (Terminating) until
    /// its controller removes the finalizer. An object without finalizers must be
    /// hard-deleted immediately (fast path preserved).
    ///
    /// delete_namespace no longer calls this cascade for "kubernetes"-finalized namespaces —
    /// the real KCM namespace-controller owns draining those now, so that it (not u7s) can
    /// run its resource types in KEP-5080 order (pods first). This cascade still runs for
    /// namespaces that never received a "kubernetes" finalizer at all (e.g. direct store
    /// writes bypassing create_namespace), so this test exercises it directly.
    ///
    /// Without the fix (cascade uses raw delete_namespace_resources):
    ///   - the finalizer'd object vanishes immediately → controller never sees the signal
    ///
    /// Fails on revert: reverting to delete_namespace_resources causes the finalizer'd object
    /// to be absent from the store after the cascade instead of being in Terminating.
    #[tokio::test]
    async fn cascade_delete_respects_object_finalizers() {
        use crate::keys::object_key;
        use u7s_store::Store;

        let state = make_state();

        // Seed a Terminating namespace directly, with the "kubernetes" finalizer still
        // present — the state a namespace is in while KCM (or, here, the cascade called
        // directly) is still draining its content.
        let ns_key = crate::keys::cluster_object_key("namespaces", "fin-cascade-ns");
        let ns_seed = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "fin-cascade-ns",
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "finalizers": ["kubernetes"] },
            "status": { "phase": "Terminating" }
        });
        state
            .store
            .put(&ns_key, bytes::Bytes::from(ns_seed.to_string()), None)
            .await
            .expect("namespace seed must succeed");

        // Seed a pod WITH metadata.finalizers in the namespace.
        let pod_key = object_key("pods", "fin-cascade-ns", "protected-pod");
        let pod_with_finalizer = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "protected-pod",
                "namespace": "fin-cascade-ns",
                "finalizers": ["test.io/delete-me"]
            },
            "spec": { "containers": [] }
        });
        state
            .store
            .put(
                &pod_key,
                bytes::Bytes::from(pod_with_finalizer.to_string()),
                None,
            )
            .await
            .expect("pod-with-finalizer write must succeed");

        // Seed a pod WITHOUT finalizers in the namespace.
        let plain_pod_key = object_key("pods", "fin-cascade-ns", "plain-pod");
        let pod_no_finalizer = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "plain-pod",
                "namespace": "fin-cascade-ns"
            },
            "spec": { "containers": [] }
        });
        state
            .store
            .put(
                &plain_pod_key,
                bytes::Bytes::from(pod_no_finalizer.to_string()),
                None,
            )
            .await
            .expect("plain-pod write must succeed");

        // Run the cascade directly (this is what the "no kubernetes finalizer" branch of
        // delete_namespace still calls; for a "kubernetes"-finalized namespace, KCM would
        // reach the same objects via its own DeleteCollection calls instead).
        cascade_delete_namespace_resources_until_stable(&state, "fin-cascade-ns").await;

        // Pod WITH finalizer must still exist with deletionTimestamp set (Terminating).
        let stored_pod = state
            .store
            .get(&pod_key)
            .await
            .expect("store get must not error")
            .expect(
                "pod with metadata.finalizers must NOT be hard-deleted during the cascade — \
                 it must remain in Terminating (deletionTimestamp set) until its controller \
                 removes the finalizer; without the fix, delete_namespace_resources erases it \
                 immediately and OrderedNamespaceDeletion fails",
            );
        let pod_body: serde_json::Value =
            serde_json::from_slice(&stored_pod.value).expect("pod body must parse");
        assert!(
            pod_body["metadata"]["deletionTimestamp"].is_string(),
            "pod with finalizer must have deletionTimestamp set after the cascade — \
             the controller needs to observe this to trigger its cleanup logic"
        );

        // Pod WITHOUT finalizer must be hard-deleted (fast path preserved).
        let plain_stored = state
            .store
            .get(&plain_pod_key)
            .await
            .expect("store get must not error");
        assert!(
            plain_stored.is_none(),
            "pod without finalizers must be hard-deleted immediately by the cascade — \
             the finalizer-less fast path must not regress; objects without finalizers must still \
             be cleaned up promptly to avoid orphan accumulation"
        );

        // Now simulate the controller removing the pod's finalizer + hard-delete the pod.
        // We directly remove the pod (simulating the controller clearing the finalizer):
        state
            .store
            .delete(&pod_key, None)
            .await
            .expect("pod hard-delete must succeed");
        // Trigger namespace completion check.
        maybe_finalize_terminating_namespace(&state, "fin-cascade-ns").await;

        // The namespace must still exist: all contained objects are drained, but the
        // "kubernetes" finalizer is still present — maybe_finalize_terminating_namespace must
        // NOT treat "content is empty" as license to also clear spec.finalizers itself; only
        // the real namespace controller may do that, via PUT /finalize.
        assert!(
            state
                .store
                .get(&crate::keys::cluster_object_key(
                    "namespaces",
                    "fin-cascade-ns",
                ))
                .await
                .expect("store get must not error")
                .is_some(),
            "namespace must NOT hard-delete while spec.finalizers still contains \"kubernetes\", \
             even once every contained object is drained — clearing \"kubernetes\" is the real \
             namespace controller's job, not an automatic side effect of content being empty"
        );

        // The real namespace controller (KCM) finishes by calling PUT /finalize once its own
        // content-deletion sequence confirms nothing remains.
        let finalize_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "fin-cascade-ns" },
                "spec": { "finalizers": [] }
            })
            .to_string(),
        );
        assert!(
            finalize_namespace(
                State(state.clone()),
                Path("fin-cascade-ns".to_string()),
                axum::http::HeaderMap::new(),
                finalize_body,
            )
            .await
            .is_ok(),
            "KCM's finalize call must succeed"
        );

        // Namespace must now be gone — the real controller cleared "kubernetes" itself.
        let ns_after = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "fin-cascade-ns",
            ))
            .await
            .expect("store get must not error");
        assert!(
            ns_after.is_none(),
            "namespace must hard-delete once the real controller clears the \"kubernetes\" \
             finalizer via PUT /finalize"
        );
    }

    use std::sync::Arc;
    use u7s_store::SqliteStore;

    /// A store wrapper whose first `list_namespace_objects` call for a chosen namespace
    /// writes a plain (finalizer-less) racer pod into the inner store immediately AFTER
    /// taking its snapshot — simulating a controller's create landing strictly after
    /// `cascade_delete_namespace_resources`'s own LIST call already returned, but before the
    /// namespace-delete request finishes. Every other call, and every later
    /// `list_namespace_objects` call, delegates straight to the inner SqliteStore.
    struct RaceInjectStore {
        inner: Arc<SqliteStore>,
        target_ns: String,
        racer_key: String,
        injected: std::sync::atomic::AtomicBool,
    }

    impl u7s_store::Store for RaceInjectStore {
        fn get(
            &self,
            key: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.get(&key).await }
        }

        fn list(
            &self,
            prefix: &str,
            opts: u7s_store::ListOptions,
        ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send
        {
            let inner = self.inner.clone();
            let prefix = prefix.to_string();
            async move { inner.list(&prefix, opts).await }
        }

        fn put(
            &self,
            key: &str,
            value: Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.put(&key, value, expected_revision).await }
        }

        fn delete(
            &self,
            key: &str,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, Bytes)>> + Send {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.delete(&key, expected_revision).await }
        }

        fn watch(
            &self,
            _prefix: &str,
            _from_revision: u64,
        ) -> impl std::future::Future<
            Output = u7s_store::Result<
                impl futures_core::Stream<Item = u7s_store::WatchEvent> + Send + 'static,
            >,
        > + Send {
            std::future::ready(Ok(futures_util::stream::empty()))
        }

        fn list_namespace_objects(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            let should_inject_after = namespace == self.target_ns
                && !self
                    .injected
                    .swap(true, std::sync::atomic::Ordering::SeqCst);
            let racer_key = self.racer_key.clone();
            let target_ns = self.target_ns.clone();
            async move {
                let result = inner.list_namespace_objects(&ns).await;
                if should_inject_after {
                    let racer = serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": { "name": "racer-pod", "namespace": target_ns },
                        "spec": { "containers": [] }
                    });
                    inner
                        .put(&racer_key, Bytes::from(racer.to_string()), None)
                        .await
                        .expect("racer pod write must succeed");
                }
                result
            }
        }

        fn delete_namespace_resources(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.delete_namespace_resources(&ns).await }
        }

        fn compaction_horizon(&self) -> u64 {
            self.inner.compaction_horizon()
        }

        fn current_revision(&self) -> u64 {
            self.inner.current_revision()
        }

        fn watch_receiver_count(&self) -> usize {
            self.inner.watch_receiver_count()
        }
    }

    /// Regression: a pod created in the window between cascade_delete_namespace_resources's
    /// LIST snapshot and its caller hard-deleting the namespace must not be silently
    /// orphaned forever.
    ///
    /// `create_namespaced_resource` rejects writes once it observes the namespace as
    /// Terminating, but it checks-then-acts: a create already past that check can still
    /// land after `cascade_delete_namespace_resources` took its LIST snapshot. A single,
    /// un-retried cascade pass can't see that pod, and once the namespace hard-deletes there
    /// is nothing left to ever re-drain it — if it was never scheduled, it silently blocks
    /// anything that requires every pod cluster-wide to have a node (the mechanism behind
    /// the SchedulerPredicates/SchedulerPreemption conformance suite's "wait for stable
    /// cluster" timeout on leftover pods from unrelated namespaces; bd mayor-35zvy).
    ///
    /// delete_namespace no longer calls this cascade for "kubernetes"-finalized namespaces
    /// (the real KCM namespace-controller owns that drain now), but it still calls it — and
    /// is still exposed to this exact race — for namespaces with no finalizer at all, so
    /// this test exercises the cascade helper directly.
    ///
    /// Fails on revert: reverting cascade_delete_namespace_resources_until_stable to call
    /// cascade_delete_namespace_resources once (no retry-until-stable) makes this test fail —
    /// the racer pod survives because the one-shot cascade's snapshot predates it.
    #[tokio::test]
    async fn delete_namespace_catches_pod_created_during_cascade_race() {
        let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let racer_key = crate::keys::object_key("pods", "race-ns", "racer-pod");
        let race_store = Arc::new(RaceInjectStore {
            inner: Arc::clone(&inner),
            target_ns: "race-ns".to_string(),
            racer_key: racer_key.clone(),
            injected: std::sync::atomic::AtomicBool::new(false),
        });

        let state = crate::state::AppState::new(
            Arc::clone(&race_store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Run the cascade directly — the wrapped store injects a racer pod right after its
        // first LIST snapshot returns, simulating a concurrent create landing in the
        // check-then-act window.
        cascade_delete_namespace_resources_until_stable(&state, "race-ns").await;

        let racer_stored = inner
            .get(&racer_key)
            .await
            .expect("store get must not error");
        assert!(
            racer_stored.is_none(),
            "a pod created during the cascade race must still be reaped by a retry pass — \
             otherwise it is orphaned forever with no namespace left to ever re-drain it"
        );
    }
}

// ---------------------------------------------------------------------------
// Status subresource metadata-protection tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod status_tests {
    use super::*;
    use std::sync::Arc;
    use u7s_store::SqliteStore;

    fn make_state(store: Arc<SqliteStore>) -> crate::state::AppState {
        crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    fn json_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    }

    fn merge_patch_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        h
    }

    /// PUT /api/v1/namespaces/{name}/status must not overwrite finalizers or deletionTimestamp.
    /// Namespace finalizers live in spec.finalizers, but metadata.finalizers are also protected.
    /// A status PUT that restores a just-removed metadata finalizer causes livelock where the
    /// namespace stays Terminating forever — exactly the bug fixed by the 8-field helper.
    #[tokio::test]
    async fn put_namespace_status_preserves_finalizers_and_deletion_timestamp() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "fin-ns",
                "resourceVersion": "1",
                "finalizers": ["some-controller.io/protection"],
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "finalizers": ["kubernetes"] },
            "status": {}
        });
        let key = "/registry/namespaces/fin-ns";
        store
            .put(key, Bytes::from(serde_json::to_vec(&ns).unwrap()), None)
            .await
            .unwrap();
        let state = make_state(store.clone());

        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "fin-ns",
                "finalizers": [],
                "deletionTimestamp": "2099-01-01T00:00:00Z"
            },
            "status": { "phase": "Terminating" }
        });
        let result = put_namespace_status(
            State(state),
            Path("fin-ns".to_string()),
            json_headers(),
            Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /namespaces/status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["finalizers"][0], "some-controller.io/protection",
            "metadata.finalizers must survive PUT /namespaces/status — restoring a just-removed \
             finalizer via a status write causes the namespace to be stuck Terminating forever (livelock)"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2024-01-01T00:00:00Z",
            "deletionTimestamp must survive PUT /namespaces/status"
        );
    }

    /// PATCH /api/v1/namespaces/{name}/status must not overwrite finalizers or deletionTimestamp.
    /// Same livelock risk as PUT: a merge-patch status body carrying an older snapshot of the
    /// object restores a finalizer a peer controller just removed.
    #[tokio::test]
    async fn patch_namespace_status_preserves_finalizers_and_deletion_timestamp() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "fin-ns-patch",
                "resourceVersion": "1",
                "finalizers": ["some-controller.io/protection"],
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "finalizers": ["kubernetes"] },
            "status": {}
        });
        let key = "/registry/namespaces/fin-ns-patch";
        store
            .put(key, Bytes::from(serde_json::to_vec(&ns).unwrap()), None)
            .await
            .unwrap();
        let state = make_state(store.clone());

        let patch = serde_json::json!({
            "metadata": {
                "finalizers": [],
                "deletionTimestamp": "2099-01-01T00:00:00Z"
            },
            "status": { "phase": "Terminating" }
        });
        let result = patch_namespace_status(
            State(state),
            Path("fin-ns-patch".to_string()),
            merge_patch_headers(),
            Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PATCH /namespaces/status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["finalizers"][0], "some-controller.io/protection",
            "metadata.finalizers must survive PATCH /namespaces/status — restoring a just-removed \
             finalizer via a status patch causes the namespace to be stuck Terminating forever (livelock)"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2024-01-01T00:00:00Z",
            "deletionTimestamp must survive PATCH /namespaces/status"
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

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
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
            test_user(),
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
            test_user(),
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

    /// Deleting a namespace must cascade-delete CRDs whose spec.group contains the namespace name.
    ///
    /// VAP conformance tests create CRDs with groups like
    /// `crontabs.stable.<namespace>.example.com`.  KCM's GC/quota controller registers a
    /// cluster-wide watch on that group; as long as the CRD exists, KCM re-queues the namespace
    /// drain forever and the namespace never finishes terminating.  If this cascade is removed,
    /// the CRD will still be present after the namespace soft-delete and this test will fail.
    #[tokio::test]
    async fn delete_namespace_cascades_to_namespace_scoped_crds() {
        use std::sync::Arc;
        use u7s_store::{SqliteStore, Store as _};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let ns_name = "test-ns-crd-drain";

        // Create the namespace via the proper handler so spec.finalizers is stamped —
        // this ensures the soft-delete path is triggered (not hard-delete).
        let ns_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": ns_name }
            })
            .to_string(),
        );
        assert!(
            create_namespace(
                State(state.clone()),
                axum::Extension(crate::auth::UserInfo {
                    username: "admin".into(),
                    uid: String::new(),
                    groups: vec![],
                    extra: Default::default(),
                }),
                axum::http::HeaderMap::new(),
                ns_body,
            )
            .await
            .is_ok(),
            "namespace create must succeed"
        );

        // Seed a CRD whose spec.group embeds the namespace name.
        let crd_name = format!("crontabs.stable.{ns_name}.example.com");
        let crd_group = format!("stable.{ns_name}.example.com");
        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": &crd_name },
            "spec": {
                "group": &crd_group,
                "names": { "plural": "crontabs", "singular": "crontab", "kind": "CronTab" },
                "scope": "Namespaced",
                "versions": [{ "name": "v1", "served": true, "storage": true }]
            }
        });
        let crd_key =
            format!("/registry/apiextensions.k8s.io/customresourcedefinitions/{crd_name}");
        store
            .put(
                &crd_key,
                Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .expect("CRD seed must succeed");

        // Soft-delete the namespace.
        assert!(
            delete_namespace(State(state.clone()), Path(ns_name.to_string()), test_user())
                .await
                .is_ok(),
            "namespace soft-delete must succeed"
        );

        // The CRD must be gone — KCM's GC watch on this group must not survive the namespace delete.
        let crd_after = store.get(&crd_key).await.expect("store.get must not fail");
        assert!(
            crd_after.is_none(),
            "CRD with namespace-scoped group must be deleted when namespace is soft-deleted — \
             without this, KCM re-queues the namespace drain indefinitely and the namespace \
             never finishes terminating"
        );
    }
}

// ---------------------------------------------------------------------------
// Regression tests for mayor-8phw: put_namespace_status must CAS on the
// INCOMING body's resourceVersion, not the stored object's RV.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod namespace_status_cas_tests {
    use super::*;
    use std::sync::Arc;
    use u7s_store::{SqliteStore, Store};

    fn make_state(store: Arc<SqliteStore>) -> crate::state::AppState {
        crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    fn json_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    }

    /// put_namespace_status with a stale resourceVersion in the body must return 409 Conflict.
    ///
    /// Without this fix put_namespace_status used the stored object's RV as the CAS token,
    /// making every PUT unconditional — a controller with a stale snapshot of the Namespace
    /// would silently overwrite a peer's concurrent status write instead of receiving 409
    /// and retrying from a fresh GET.
    #[tokio::test]
    async fn put_namespace_status_stale_rv_returns_409_else_concurrent_writers_clobber() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "cas-ns" },
            "spec": { "finalizers": ["kubernetes"] },
            "status": {}
        });
        let key = "/registry/namespaces/cas-ns";
        let rv1 = store
            .put(key, Bytes::from(serde_json::to_vec(&ns).unwrap()), None)
            .await
            .unwrap();
        // Advance the store to rv2 (simulate a concurrent writer making a genuine change — the
        // store suppresses no-op writes, so status must actually differ from the first write).
        let mut ns2 = ns.clone();
        ns2["metadata"]["resourceVersion"] = serde_json::json!(rv1.to_string());
        ns2["status"] = serde_json::json!({"phase": "Active"});
        let rv2 = store
            .put(
                key,
                Bytes::from(serde_json::to_vec(&ns2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance after second write");

        let state = make_state(store);

        // PUT body carries the now-stale rv1 — must be rejected with 409.
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "cas-ns", "resourceVersion": rv1.to_string() },
            "status": { "phase": "Terminating" }
        });
        let result = put_namespace_status(
            State(state),
            Path("cas-ns".to_string()),
            json_headers(),
            Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "stale-rv PUT to put_namespace_status must return 409 — \
                 without this check concurrent controllers silently clobber namespace status writes"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "stale resourceVersion in PUT /namespaces/status body must return 409 — \
             controllers must retry from a fresh GET when they lose the CAS race"
        );
    }

    /// put_namespace_status with an absent resourceVersion in the body succeeds unconditionally.
    ///
    /// Upstream k8s allows omitting resourceVersion in a subresource PUT.  The fix must not
    /// break clients that legitimately omit rv.
    #[tokio::test]
    async fn put_namespace_status_absent_rv_is_unconditional_write() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "norev-ns" },
            "spec": { "finalizers": ["kubernetes"] },
            "status": {}
        });
        let key = "/registry/namespaces/norev-ns";
        store
            .put(key, Bytes::from(serde_json::to_vec(&ns).unwrap()), None)
            .await
            .unwrap();
        let state = make_state(store);

        // No resourceVersion in body — must succeed as unconditional write.
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "norev-ns" },
            "status": { "phase": "Active" }
        });
        let result = put_namespace_status(
            State(state),
            Path("norev-ns".to_string()),
            json_headers(),
            Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "absent resourceVersion in PUT /namespaces/status body must succeed (unconditional) — \
             single-writer clients that omit rv must not be broken by the stale-RV CAS fix"
        );
    }
}
