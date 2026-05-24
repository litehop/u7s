use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store, StoreError};

use crate::admission::{run_mutating_webhooks, run_validating_webhooks, AdmissionContext};
use crate::{limit_range, quota};

use crate::{
    auth::UserInfo,
    keys::{group_list_prefix, group_object_key},
    state::AppState,
    status::Status,
    types::{Object, ObjectMeta},
    util::{content_type, extract_body, parse_resource_version},
};

use super::generic::{
    apply_delete_policy, apply_label_selector, build_list_response, check_crb_escalation,
    decode_continue, lookup, parse_field_selector, parse_label_selector, resolve_name,
    stamp_metadata, store_err, validate_name, CollectionQuery, RBAC_GROUP,
};
use super::json_patch::{
    apply_json_patch, detect_patch_type, inject_managed_fields, strip_managed_fields, PatchQuery,
    PatchType,
};
use super::watch::{fetch_initial_events, watch_generic};

// ---------------------------------------------------------------------------
// Cluster-scoped handlers  (group/version/resource)
// ---------------------------------------------------------------------------

/// Detect whether the Accept header requests PartialObjectMetadata.
/// The kcm metadatainformer (GC) sends headers like:
///   application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,
///   application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json
fn wants_partial_object_metadata(accept: &str) -> bool {
    accept.contains("as=PartialObjectMetadata")
}

pub async fn list_resource(
    State(state): State<AppState>,
    Path((group, version, plural)): Path<(String, String, String)>,
    Query(query): Query<CollectionQuery>,
    headers: HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::list_cr(
                State(state),
                Path((group, version, plural)),
                headers,
                query,
                user.username,
            )
            .await;
        }
    };
    let prefix = group_list_prefix(&group, &plural, None);

    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pom = wants_partial_object_metadata(accept);

    if query.watch == Some(true) {
        let (watch_api_version, watch_kind) = if pom {
            (
                "meta.k8s.io/v1".to_string(),
                "PartialObjectMetadata".to_string(),
            )
        } else {
            let av = if group.is_empty() {
                version.clone()
            } else {
                format!("{}/{}", group, version)
            };
            (av, meta.kind.clone())
        };
        let from_rv = query.resource_version.unwrap_or(0);
        let initial =
            fetch_initial_events(&state, &prefix, query.send_initial_events == Some(true)).await?;
        return watch_generic(
            state,
            prefix,
            watch_api_version,
            watch_kind,
            from_rv,
            initial,
            query.label_selector,
            query.field_selector,
            query.allow_watch_bookmarks == Some(true),
            user.username,
            pom,
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

    if pom {
        let pom_items: Vec<serde_json::Value> = items
            .iter()
            .map(super::watch::to_partial_object_metadata)
            .collect();
        let body = serde_json::json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": resp.revision.to_string() },
            "items": pom_items
        });
        return Ok(Json(body).into_response());
    }

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
    validate_name("name", &name)?;
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
    Extension(user): Extension<UserInfo>,
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

    // Escalation prevention: before persisting a ClusterRoleBinding, verify the
    // caller already holds all rules of the referenced ClusterRole. This prevents
    // users from granting themselves permissions they don't currently have.
    check_crb_escalation(&plural, &group, &user, &obj.body, &state)?;

    let name = resolve_name(&mut obj)?;
    stamp_metadata(&mut obj);
    super::defaults::apply_defaults(&group, &plural, &mut obj.body);

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: None,
        operation: "CREATE",
    };
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

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
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("name", &name)?;
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

    // Escalation prevention: before updating a ClusterRoleBinding, verify the
    // caller already holds all rules of the referenced ClusterRole.
    check_crb_escalation(&plural, &group, &user, &obj.body, &state)?;

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

    super::defaults::apply_defaults(&group, &plural, &mut obj.body);

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: None,
        operation: "UPDATE",
    };
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

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
    validate_name("name", &name)?;
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
        let mut body = Object { body: soft };
        body.set_resource_version(new_rv);
        return Ok(Json(body.body).into_response());
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
/// `field_manager` is the value of the `?fieldManager=` query param; used only for SSA to
/// populate the synthetic `managedFields` echo in the response.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_patch(
    state: &AppState,
    key: &str,
    meta: &crate::types::ResourceMeta,
    group: &str,
    version: &str,
    plural: &str,
    ns: Option<&str>,
    name: &str,
    is_ssa: bool,
    field_manager: Option<&str>,
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
        // Strip any managedFields the client sent — we don't track field ownership.
        strip_managed_fields(&mut obj.body);
        let mut obj_meta: ObjectMeta =
            serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
        obj_meta.name = Some(name.to_string());
        if let Some(namespace) = ns {
            obj_meta.namespace = Some(namespace.to_string());
        }
        obj.body["metadata"] =
            serde_json::to_value(obj_meta).map_err(|e| Status::internal(e.to_string()))?;
        stamp_metadata(&mut obj);
        super::defaults::apply_defaults(group, plural, &mut obj.body);
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
                let mut patch: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;
                strip_managed_fields(&mut patch);
                crate::patch::strategic_merge_patch(&mut current.body, &patch)
                    .map_err(|e| Status::bad_request(e.to_string()))?;
                super::defaults::apply_defaults(group, plural, &mut current.body);
                if let Some(fm) = field_manager {
                    let api_ver = current.body["apiVersion"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let now = crate::util::utc_now_rfc3339();
                    inject_managed_fields(&mut current.body, fm, &api_ver, &now);
                }
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
        if let Some(fm) = field_manager {
            let api_ver = obj.body["apiVersion"].as_str().unwrap_or("").to_string();
            let now = crate::util::utc_now_rfc3339();
            inject_managed_fields(&mut obj.body, fm, &api_ver, &now);
        }
        return Ok((StatusCode::CREATED, Json(obj.body)).into_response());
    }

    let stored = stored_opt.ok_or_else(|| Status::not_found(name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let mut patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // Strip managedFields the client sent in the apply body — we don't track field ownership.
    if is_ssa {
        strip_managed_fields(&mut patch);
    }

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
    super::defaults::apply_defaults(group, plural, &mut current.body);

    // Post-patch: if deletionTimestamp is set and finalizers are now empty, hard-delete.
    let current_meta: ObjectMeta =
        serde_json::from_value(current.body["metadata"].clone()).unwrap_or_default();
    let deletion_ts_set = current_meta.deletion_timestamp.is_some();
    let finalizers_empty = current_meta
        .finalizers
        .as_deref()
        .map(|f| f.is_empty())
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

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group,
        version,
        resource: plural,
        name,
        namespace: ns,
        operation: "UPDATE",
    };
    current.body = run_mutating_webhooks(state, current.body, &admission_ctx).await?;
    run_validating_webhooks(state, &current.body, &admission_ctx).await?;

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
    // SSA: echo synthetic managedFields so clients (e.g. Argo CD) can track field ownership.
    if is_ssa {
        if let Some(fm) = field_manager {
            let api_ver = current.body["apiVersion"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let now = crate::util::utc_now_rfc3339();
            inject_managed_fields(&mut current.body, fm, &api_ver, &now);
        }
    }
    Ok(Json(current.body).into_response())
}

pub async fn patch_resource(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Query(patch_query): Query<PatchQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("name", &name)?;
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
        &state,
        &key,
        &meta,
        &group,
        &version,
        &plural,
        None,
        &name,
        is_ssa,
        patch_query.field_manager.as_deref(),
        patch_type,
        body,
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
    headers: HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::list_cr_namespaced(
                State(state),
                Path((group, version, ns, plural)),
                headers,
                query,
                user.username,
            )
            .await;
        }
    };
    let prefix = group_list_prefix(&group, &plural, Some(&ns));

    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pom = wants_partial_object_metadata(accept);

    if query.watch == Some(true) {
        let (watch_api_version, watch_kind) = if pom {
            (
                "meta.k8s.io/v1".to_string(),
                "PartialObjectMetadata".to_string(),
            )
        } else {
            let av = if group.is_empty() {
                version.clone()
            } else {
                format!("{}/{}", group, version)
            };
            (av, meta.kind.clone())
        };
        let from_rv = query.resource_version.unwrap_or(0);
        let initial =
            fetch_initial_events(&state, &prefix, query.send_initial_events == Some(true)).await?;
        return watch_generic(
            state,
            prefix,
            watch_api_version,
            watch_kind,
            from_rv,
            initial,
            query.label_selector,
            query.field_selector,
            query.allow_watch_bookmarks == Some(true),
            user.username,
            pom,
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

    if pom {
        let pom_items: Vec<serde_json::Value> = items
            .iter()
            .map(super::watch::to_partial_object_metadata)
            .collect();
        let body = serde_json::json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": resp.revision.to_string() },
            "items": pom_items
        });
        return Ok(Json(body).into_response());
    }

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
    validate_name("namespace", &ns)?;
    validate_name("name", &name)?;
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
    validate_name("namespace", &ns)?;
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

    let mut ns_meta: ObjectMeta =
        serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
    ns_meta.namespace = Some(ns.clone());
    obj.body["metadata"] =
        serde_json::to_value(ns_meta).map_err(|e| Status::internal(e.to_string()))?;
    stamp_metadata(&mut obj);
    super::defaults::apply_defaults(&group, &plural, &mut obj.body);

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: Some(&ns),
        operation: "CREATE",
    };
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

    // LimitRange: inject defaults then validate min/max bounds (pods only).
    obj.body = limit_range::apply_limit_ranges(&state, obj.body, &ns, &plural).await?;

    // ResourceQuota: ensure object count does not exceed hard limits.
    quota::check_resource_quota(&state, &ns, &group, &plural).await?;

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
    validate_name("namespace", &ns)?;
    validate_name("name", &name)?;
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

    super::defaults::apply_defaults(&group, &plural, &mut obj.body);

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: Some(&ns),
        operation: "UPDATE",
    };
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

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
    validate_name("namespace", &ns)?;
    validate_name("name", &name)?;
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
        let mut body = Object { body: soft };
        body.set_resource_version(new_rv);
        return Ok(Json(body.body).into_response());
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
    Query(patch_query): Query<PatchQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    validate_name("name", &name)?;
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
        patch_query.field_manager.as_deref(),
        patch_type,
        body,
    )
    .await
}

// ---------------------------------------------------------------------------
// Private helpers (duplicated from generic to avoid pub exposure)
// ---------------------------------------------------------------------------

fn rbac_cluster_key(group: &str, version: &str, plural: &str, name: &str) -> String {
    format!("/apis/{group}/{version}/{plural}/{name}")
}

fn rbac_namespaced_key(group: &str, version: &str, ns: &str, plural: &str, name: &str) -> String {
    format!("/apis/{group}/{version}/namespaces/{ns}/{plural}/{name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Extension;

    fn json_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    }

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

    fn make_state() -> crate::state::AppState {
        use std::sync::Arc;
        use u7s_store::SqliteStore;
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    // -- cr_status_put_updates_status_field --

    /// Verify that put_namespaced_resource_status works for CRD-backed resources whose group
    /// is not in the static resource registry (e.g. argoproj.io/Application).
    #[tokio::test]
    async fn cr_status_put_updates_status_field() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

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

        let put_body = serde_json::json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": { "name": name, "namespace": ns },
            "status": { "health": { "status": "Healthy" }, "sync": { "status": "Synced" } }
        });
        let body_bytes = bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap());

        let result = super::super::status::put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
                name.to_string(),
            )),
            json_headers(),
            body_bytes,
        )
        .await;

        assert!(
            result.is_ok(),
            "CR status PUT must succeed for unregistered group"
        );

        let stored = store
            .get(&cr_key)
            .await
            .expect("store get")
            .expect("object must exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["health"]["status"], "Healthy");
        assert_eq!(v["status"]["sync"]["status"], "Synced");
        assert_eq!(v["spec"]["project"], "default");
    }

    // -- Lease PUT: kubelet liveness signal --

    /// Kubelet first PUT: no resourceVersion → unconditional write → must succeed.
    #[tokio::test]
    async fn lease_put_without_resource_version_creates_lease() {
        let state = make_state();

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
    #[tokio::test]
    async fn lease_put_with_matching_resource_version_updates_lease() {
        use axum::response::IntoResponse;

        let state = make_state();

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

        let body_bytes = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let rv = body["metadata"]["resourceVersion"]
            .as_str()
            .expect("response must include metadata.resourceVersion")
            .to_string();

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
            "Lease renewal PUT with matching resourceVersion must succeed"
        );
    }

    /// Stale resourceVersion → 409 Conflict.
    #[tokio::test]
    async fn lease_put_with_stale_resource_version_returns_conflict() {
        let state = make_state();

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
                "stale Lease PUT must return 409 Conflict"
            ),
            Ok(_) => panic!("stale Lease PUT must be rejected with 409 Conflict, not succeed"),
        }
    }

    /// fieldSelector=metadata.name=foo must filter list to matching item.
    #[tokio::test]
    async fn field_selector_filters_list_to_matching_item() {
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

        let fs = parse_field_selector("metadata.name=foo")
            .unwrap_or_else(|_| panic!("valid field selector must parse"));
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

        assert_eq!(resp.items.len(), 1);
        let parsed: serde_json::Value = serde_json::from_slice(&resp.items[0].value).unwrap();
        assert_eq!(parsed["metadata"]["name"], "foo");
    }

    /// list_resource returns an empty RuntimeClassList (not 404) for runtimeclasses.
    #[tokio::test]
    async fn list_resource_returns_empty_list_for_runtimeclasses() {
        use axum::body::to_bytes;
        use axum::extract::{Path, Query, State};

        let state = make_state();

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
                allow_watch_bookmarks: None,
            }),
            axum::http::HeaderMap::new(),
            Extension(crate::auth::UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("list runtimeclasses must not return 404"));

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), 65536).await.expect("read body");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("body must be JSON");
        assert_eq!(val["kind"], "RuntimeClassList");
        assert!(val["items"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false));
    }

    /// strategic-merge-patch on absent resource returns 404.
    #[tokio::test]
    async fn strategic_merge_patch_on_absent_resource_returns_404() {
        let state = make_state();

        let patch = serde_json::json!({"spec": { "drivers": [] }});
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
            axum::extract::Query(PatchQuery::default()),
            smp_headers,
            patch_bytes,
        )
        .await;

        match result {
            Err(err) => assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND),
            Ok(_) => panic!("strategic-merge-patch on absent resource must return 404"),
        }
    }

    /// apply-patch+yaml creates cluster-scoped resource when absent (SSA upsert).
    #[tokio::test]
    async fn apply_patch_yaml_creates_cluster_scoped_resource_when_absent() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
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
            "spec": { "drivers": [{"name": "driver.csi.k8s.io", "nodeID": "lima-node"}] }
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
            axum::extract::Query(PatchQuery::default()),
            ssa_headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|_| panic!("apply-patch+yaml on absent CSINode must not return 404"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(!v["metadata"]["uid"].as_str().unwrap_or("").is_empty());

        let key = "/registry/storage.k8s.io/csinodes/lima-node";
        assert!(store.get(key).await.unwrap().is_some());
    }

    /// apply-patch+yaml creates namespaced resource when absent (SSA upsert).
    #[tokio::test]
    async fn apply_patch_yaml_creates_namespaced_resource_when_absent() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let patch = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "lima-node", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "lima-node", "leaseDurationSeconds": 40, "renewTime": "2026-05-21T00:00:00Z" }
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
            axum::extract::Query(PatchQuery::default()),
            ssa_headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|_| panic!("apply-patch+yaml on absent Lease must not return 404"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(!v["metadata"]["uid"].as_str().unwrap_or("").is_empty());

        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/lima-node";
        assert!(store.get(key).await.unwrap().is_some());
    }

    /// apply-patch+yaml PATCH must upsert (create if not found) and update if existing.
    #[tokio::test]
    async fn apply_patch_yaml_accepted_and_updates_resource() {
        use axum::response::IntoResponse;

        let state = make_state();

        // Create the Lease via PUT first.
        let _ = replace_namespaced_resource(
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

        let patch = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "worker-node-1", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "worker-node-1", "leaseDurationSeconds": 40, "renewTime": "2026-05-21T00:00:00Z" }
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
            axum::extract::Query(PatchQuery::default()),
            ssa_headers,
            patch_bytes,
        )
        .await;

        assert!(
            patch_result.is_ok(),
            "PATCH with application/apply-patch+yaml must succeed"
        );
    }

    /// apply-patch+yaml with ?fieldManager=argocd must return managedFields in the response.
    ///
    /// Argo CD reads managedFields from apply responses to determine field ownership.
    /// Without this, Argo CD reports every resource as OutOfSync and loops forever.
    /// This test covers both creation (object absent) and update (object exists) paths.
    #[tokio::test]
    async fn apply_patch_yaml_returns_managed_fields_for_field_manager() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
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
                "name": "argocd-lease",
                "namespace": "kube-node-lease",
                // Client sends managedFields in the body — we must strip it before storing.
                "managedFields": [{"manager": "old-manager", "operation": "Apply"}]
            },
            "spec": { "holderIdentity": "argocd", "leaseDurationSeconds": 15 }
        });
        let patch_bytes = bytes::Bytes::from(serde_json::to_vec(&patch).unwrap());

        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        // --- Creation path (object absent) ---
        let create_result = patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "argocd-lease".to_string(),
            )),
            axum::extract::Query(PatchQuery {
                field_manager: Some("argocd".to_string()),
            }),
            ssa_headers.clone(),
            patch_bytes.clone(),
        )
        .await
        .unwrap_or_else(|_| panic!("apply-patch+yaml creation must succeed"))
        .into_response();

        assert_eq!(create_result.status(), axum::http::StatusCode::CREATED);
        let body_bytes = to_bytes(create_result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Response must contain managedFields echoing the field manager.
        let mf = &v["metadata"]["managedFields"];
        assert!(mf.is_array(), "managedFields must be an array");
        let entry = &mf[0];
        assert_eq!(
            entry["manager"], "argocd",
            "managedFields[0].manager must be the ?fieldManager value"
        );
        assert_eq!(
            entry["operation"], "Apply",
            "managedFields[0].operation must be 'Apply'"
        );
        assert_eq!(
            entry["apiVersion"], "coordination.k8s.io/v1",
            "managedFields[0].apiVersion must match the object apiVersion"
        );
        assert!(
            entry["time"].is_string(),
            "managedFields[0].time must be a string timestamp"
        );

        // The client-supplied managedFields from the request body must NOT appear in the store.
        // We only store the synthetic entry; we never persist the client's old ownership data.
        let stored = store
            .get("/registry/coordination.k8s.io/leases/kube-node-lease/argocd-lease")
            .await
            .unwrap()
            .expect("object must exist");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        // The stored managedFields should not contain "old-manager" from the request body.
        if let Some(stored_mf) = stored_v["metadata"]["managedFields"].as_array() {
            for entry in stored_mf {
                assert_ne!(
                    entry["manager"], "old-manager",
                    "client-supplied managedFields must not be persisted in the store"
                );
            }
        }

        // --- Update path (object exists) ---
        let update_patch = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "argocd-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "argocd", "leaseDurationSeconds": 20 }
        });
        let update_bytes = bytes::Bytes::from(serde_json::to_vec(&update_patch).unwrap());

        let update_result = patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "argocd-lease".to_string(),
            )),
            axum::extract::Query(PatchQuery {
                field_manager: Some("argocd".to_string()),
            }),
            ssa_headers,
            update_bytes,
        )
        .await
        .unwrap_or_else(|_| panic!("apply-patch+yaml update must succeed"))
        .into_response();

        let update_body = to_bytes(update_result.into_body(), usize::MAX)
            .await
            .unwrap();
        let uv: serde_json::Value = serde_json::from_slice(&update_body).unwrap();

        let umf = &uv["metadata"]["managedFields"];
        assert!(
            umf.is_array(),
            "managedFields must be present in update response"
        );
        assert_eq!(
            umf[0]["manager"], "argocd",
            "update response managedFields[0].manager must be 'argocd'"
        );
        assert_eq!(
            umf[0]["operation"], "Apply",
            "update response managedFields[0].operation must be 'Apply'"
        );
    }

    /// get_resource returns 404 when the object does not exist in the store.
    #[tokio::test]
    async fn get_resource_returns_404_when_not_found() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = get_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "missing-node".into(),
            )),
        )
        .await;

        let err = result.expect_err("get on missing object must return error");
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// get_resource returns the stored object when it exists.
    #[tokio::test]
    async fn get_resource_returns_stored_object() {
        use axum::extract::{Path, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").unwrap());

        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1" }
        });
        store
            .put(
                "/registry/storage.k8s.io/csinodes/worker-1",
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = get_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-1".into(),
            )),
        )
        .await;

        let resp = result.unwrap_or_else(|_| panic!("get_resource must return 200"));
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    /// get_namespaced_resource returns 404 when the namespaced object does not exist.
    #[tokio::test]
    async fn get_namespaced_resource_returns_404_when_not_found() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = get_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "missing".into(),
            )),
        )
        .await;

        let err = result.expect_err("get on missing namespaced object must return error");
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// list_namespaced_resource returns an empty list when no objects exist.
    #[tokio::test]
    async fn list_namespaced_resource_returns_empty_list() {
        use axum::body::to_bytes;
        use axum::extract::{Path, Query, State};

        let state = make_state();

        let resp = list_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
            )),
            Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: None,
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
            }),
            axum::http::HeaderMap::new(),
            axum::Extension(crate::auth::UserInfo {
                username: "test".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("list must succeed"));

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), 65536).await.unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["kind"], "LeaseList");
        assert!(val["items"].as_array().unwrap().is_empty());
    }

    /// create_namespaced_resource must persist the object and return 201 Created.
    #[tokio::test]
    async fn create_namespaced_resource_creates_and_returns_201() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-a", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "node-a", "leaseDurationSeconds": 40 }
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("create_namespaced_resource must succeed"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::CREATED);

        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/node-a";
        assert!(store.get(key).await.unwrap().is_some());
    }

    /// delete_namespaced_resource must hard-delete objects without finalizers and return 200 Status.
    #[tokio::test]
    async fn delete_namespaced_resource_hard_deletes_and_returns_200() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-b", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "node-b" }
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/node-b";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "node-b".into(),
            )),
        )
        .await
        .unwrap_or_else(|_| panic!("delete must succeed"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::OK);
        assert!(store.get(key).await.unwrap().is_none());

        let body = to_bytes(result.into_body(), 4096).await.unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["kind"], "Status");
        assert_eq!(val["status"], "Success");
    }

    /// delete_namespaced_resource must return 404 when the object does not exist.
    #[tokio::test]
    async fn delete_namespaced_resource_returns_404_when_not_found() {
        let state = make_state();

        let result = delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "nonexistent".into(),
            )),
        )
        .await;

        match result {
            Err(err) => assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND),
            Ok(_) => panic!("delete of missing object must return 404 error"),
        }
    }

    /// Security invariant: a soft-deleted ClusterRoleBinding must be removed from the
    /// RBAC index immediately when DELETE is requested.
    #[tokio::test]
    async fn rbac_index_evicted_on_soft_delete_of_clusterrolebinding() {
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

        let cr = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "cluster-admin"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        // Pre-seed the rbac_index so system:masters can create ClusterRoleBindings
        // via RBAC (no hardcoded bypass exists).
        let masters_crb_seed = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "system-masters-cluster-admin"},
            "subjects": [{"kind": "Group", "name": "system:masters"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin",
            &cr,
        );
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system-masters-cluster-admin",
            &masters_crb_seed,
        );

        let admin_user = Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
        });
        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterroles".to_string(),
            )),
            admin_user.clone(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&cr).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("ClusterRole creation must succeed"));

        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((group.to_string(), version.to_string(), plural.to_string())),
            admin_user,
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&crb).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("ClusterRoleBinding creation must succeed"));

        let rules_before = state.rbac_index.enumerate_rules("alice", &[], "");
        assert!(!rules_before.is_empty());

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

        let rules_after = state.rbac_index.enumerate_rules("alice", &[], "");
        assert!(
            rules_after.is_empty(),
            "soft-deleted ClusterRoleBinding must be evicted from RBAC index immediately"
        );
    }

    /// delete_resource returns 404 when the cluster-scoped object does not exist.
    #[tokio::test]
    async fn delete_resource_returns_404_for_missing() {
        use axum::extract::{Path, State};

        let state = make_state();
        let result = delete_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "nonexistent".into(),
            )),
        )
        .await;

        match result {
            Err(err) => assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND),
            Ok(_) => panic!("delete of missing cluster-scoped object must return 404"),
        }
    }

    /// delete_resource with finalizers sets deletionTimestamp (soft-delete) and
    /// leaves the object in the store. The object must not be hard-deleted while
    /// finalizers are still present — controllers watch for deletionTimestamp to run cleanup.
    #[tokio::test]
    async fn delete_resource_with_finalizers_soft_deletes() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "finalizer-node",
                "finalizers": ["example.com/cleanup"]
            },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/finalizer-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        let del_result = delete_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "finalizer-node".into(),
            )),
        )
        .await;
        let result = match del_result {
            Ok(r) => r.into_response(),
            Err(_) => panic!("soft-delete must succeed"),
        };

        assert_eq!(result.status(), axum::http::StatusCode::OK);
        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "soft-deleted object must have deletionTimestamp set"
        );

        // Object must still exist in the store (not hard-deleted)
        assert!(
            store.get(key).await.unwrap().is_some(),
            "object with finalizers must remain in store after soft-delete"
        );
    }

    /// replace_resource (PUT) on a new object with no resourceVersion creates it.
    /// When no resourceVersion is given, this is an unconditional write (create-or-update).
    #[tokio::test]
    async fn replace_resource_creates_object_when_no_resource_version() {
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "replace-node" },
            "spec": { "drivers": [] }
        });

        let rr_result = replace_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "replace-node".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
        )
        .await;
        let result = match rr_result {
            Ok(r) => r.into_response(),
            Err(_) => panic!("replace_resource without rv must succeed"),
        };

        assert_eq!(result.status(), axum::http::StatusCode::OK);
    }

    /// replace_resource (PUT) with matching resourceVersion updates the object.
    #[tokio::test]
    async fn replace_resource_updates_object_with_matching_rv() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // First PUT — no rv → creates
        let v1 = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "rv-node" },
            "spec": { "drivers": [] }
        });
        let rr1 = replace_resource(
            State(state.clone()),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "rv-node".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&v1).unwrap()),
        )
        .await;
        let resp1 = match rr1 {
            Ok(r) => r.into_response(),
            Err(_) => panic!("first replace must succeed"),
        };

        let body = to_bytes(resp1.into_body(), usize::MAX).await.unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let rv = stored["metadata"]["resourceVersion"]
            .as_str()
            .unwrap()
            .to_string();

        // Second PUT with matching rv → update
        let v2 = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "rv-node", "resourceVersion": rv },
            "spec": { "drivers": [{"name": "new.csi.io", "nodeID": "rv-node"}] }
        });
        let result = replace_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "rv-node".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&v2).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "replace_resource with matching rv must succeed"
        );
    }

    /// replace_resource with stale resourceVersion must return 409 Conflict.
    /// This is the OCC guarantee: stale writers must be rejected.
    #[tokio::test]
    async fn replace_resource_returns_409_on_stale_rv() {
        use axum::extract::{Path, State};

        let state = make_state();

        // Create the object
        let v1 = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "stale-node" },
            "spec": { "drivers": [] }
        });
        match replace_resource(
            State(state.clone()),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "stale-node".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&v1).unwrap()),
        )
        .await
        {
            Ok(_) => {}
            Err(_) => panic!("first replace must succeed"),
        }

        // Try with a known-stale rv
        let stale = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "stale-node", "resourceVersion": "999" },
            "spec": { "drivers": [] }
        });
        let result = replace_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "stale-node".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&stale).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(err.0, axum::http::StatusCode::CONFLICT),
            Ok(_) => panic!("stale replace must return 409 Conflict"),
        }
    }

    /// patch_resource with JSON Patch (`application/json-patch+json`) applies the patch.
    /// This is the fine-grained mutation path used by kubectl patch --type=json.
    #[tokio::test]
    async fn patch_resource_with_json_patch_applies_changes() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "patch-node", "resourceVersion": "1" },
            "spec": { "drivers": [] }
        });
        store
            .put(
                "/registry/storage.k8s.io/csinodes/patch-node",
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        let mut jp_headers = axum::http::HeaderMap::new();
        jp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );

        let patch = serde_json::json!([
            {"op": "add", "path": "/metadata/labels", "value": {"env": "prod"}}
        ]);

        let patch_result = patch_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "patch-node".into(),
            )),
            axum::extract::Query(PatchQuery::default()),
            jp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        let result = match patch_result {
            Ok(r) => r.into_response(),
            Err(_) => panic!("json-patch on existing object must succeed"),
        };

        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["metadata"]["labels"]["env"], "prod");
    }

    /// patch_namespaced_resource with merge-patch updates the object.
    /// This is the primary mutation path used by controller-manager for namespaced resources.
    #[tokio::test]
    async fn patch_namespaced_resource_merge_patch_applies_changes() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "ns-patch-lease", "namespace": "kube-node-lease", "resourceVersion": "1" },
            "spec": { "holderIdentity": "original" }
        });
        store
            .put(
                "/registry/coordination.k8s.io/leases/kube-node-lease/ns-patch-lease",
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();

        let mut mp_headers = axum::http::HeaderMap::new();
        mp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let patch = serde_json::json!({"spec": {"holderIdentity": "updated"}});

        let mp_result = patch_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "ns-patch-lease".into(),
            )),
            axum::extract::Query(PatchQuery::default()),
            mp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        let result = match mp_result {
            Ok(r) => r.into_response(),
            Err(_) => panic!("merge-patch on existing namespaced object must succeed"),
        };

        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["spec"]["holderIdentity"], "updated");
    }

    /// create_resource returns 409 Conflict when creating the same name twice.
    /// Kubernetes rejects duplicate object creation — clients must GET first or use apply.
    /// Uses Node (cluster-scoped, create_or_update=false) to trigger 409.
    #[tokio::test]
    async fn create_resource_returns_409_on_duplicate() {
        use axum::extract::{Path, State};

        let state = make_state();

        // Node is registered with create_or_update=false, so duplicate create must 409.
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": { "name": "dup-node" }
        });
        let admin = Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
        });

        match create_resource(
            State(state.clone()),
            Path(("".into(), "v1".into(), "nodes".into())),
            admin.clone(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&node).unwrap()),
        )
        .await
        {
            Ok(_) => {}
            Err(_) => panic!("first create must succeed"),
        }

        let result = create_resource(
            State(state),
            Path(("".into(), "v1".into(), "nodes".into())),
            admin,
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&node).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(err.0, axum::http::StatusCode::CONFLICT),
            Ok(_) => panic!("duplicate create must return 409 Conflict"),
        }
    }

    /// list_resource with labelSelector filters to matching items only.
    /// Controllers and kubectl filter lists by label; incorrect filtering causes missing or extra items.
    #[tokio::test]
    async fn list_resource_with_label_selector_filters_results() {
        use axum::body::to_bytes;
        use axum::extract::{Path, Query, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed two CSINodes with different labels
        for (name, app) in [("node-foo", "foo"), ("node-bar", "bar")] {
            let obj = serde_json::json!({
                "apiVersion": "storage.k8s.io/v1",
                "kind": "CSINode",
                "metadata": {
                    "name": name,
                    "labels": { "app": app }
                },
                "spec": { "drivers": [] }
            });
            store
                .put(
                    &format!("/registry/storage.k8s.io/csinodes/{name}"),
                    bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                    Some(0),
                )
                .await
                .unwrap();
        }

        let list_result = list_resource(
            State(state),
            Path(("storage.k8s.io".into(), "v1".into(), "csinodes".into())),
            Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: Some("app=foo".into()),
                field_selector: None,
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
            }),
            axum::http::HeaderMap::new(),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
        )
        .await;
        let resp = match list_result {
            Ok(r) => r,
            Err(_) => panic!("list with label selector must not fail"),
        };

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = v["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            1,
            "label selector must filter to 1 matching item"
        );
        assert_eq!(items[0]["metadata"]["name"], "node-foo");
    }

    /// replace_namespaced_resource with stale resourceVersion returns 409 Conflict.
    #[tokio::test]
    async fn replace_namespaced_resource_returns_409_on_stale_rv() {
        use axum::extract::{Path, State};

        let state = make_state();

        // Create via replace (no rv)
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "stale-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "original" }
        });
        match replace_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "stale-lease".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
        )
        .await
        {
            Ok(_) => {}
            Err(_) => panic!("first replace must succeed"),
        }

        // Try with a known-stale rv
        let stale = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "stale-lease", "namespace": "kube-node-lease", "resourceVersion": "999" },
            "spec": { "holderIdentity": "updated" }
        });
        let result = replace_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "stale-lease".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&stale).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(err.0, axum::http::StatusCode::CONFLICT),
            Ok(_) => panic!("stale replace_namespaced must return 409 Conflict"),
        }
    }

    /// delete_namespaced_resource with finalizers soft-deletes: sets deletionTimestamp,
    /// leaves the object in the store. Finalizer-based cleanup cannot work if the object
    /// is hard-deleted immediately.
    #[tokio::test]
    async fn delete_namespaced_resource_with_finalizers_soft_deletes() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "finalizer-lease",
                "namespace": "kube-node-lease",
                "finalizers": ["example.com/cleanup"]
            },
            "spec": { "holderIdentity": "finalizer-lease" }
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/finalizer-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();

        let del_ns = delete_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "finalizer-lease".into(),
            )),
        )
        .await;
        let result = match del_ns {
            Ok(r) => r.into_response(),
            Err(_) => panic!("soft-delete must succeed"),
        };

        assert_eq!(result.status(), axum::http::StatusCode::OK);
        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "soft-deleted object must have deletionTimestamp"
        );

        assert!(
            store.get(key).await.unwrap().is_some(),
            "namespaced object with finalizers must remain in store after soft-delete"
        );
    }

    /// do_patch: when deletionTimestamp is set and patch removes all finalizers,
    /// the object must be hard-deleted from the store. This is the finalizer GC path:
    /// controllers remove themselves from finalizers, and once empty, the object is gone.
    #[tokio::test]
    async fn patch_resource_hard_deletes_when_finalizers_removed_after_soft_delete() {
        use axum::extract::{Path, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed an object that is already soft-deleted (has deletionTimestamp) with one finalizer.
        let obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "gc-node",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": ["example.com/cleanup"]
            },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/gc-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                None,
            )
            .await
            .unwrap();

        // PATCH to clear the finalizers list.
        let mut mp_headers = axum::http::HeaderMap::new();
        mp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        let patch = serde_json::json!({"metadata": {"finalizers": []}});

        let result = patch_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "gc-node".into(),
            )),
            axum::extract::Query(PatchQuery::default()),
            mp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "patch removing finalizers from soft-deleted object must succeed"
        );

        // After GC, the object must be hard-deleted from the store.
        assert!(
            store.get(key).await.unwrap().is_none(),
            "object with deletionTimestamp and empty finalizers must be hard-deleted after patch"
        );
    }

    /// get_resource follows the CR fallback path for unregistered groups.
    /// Custom resources not in the static registry must be served from the CR store.
    #[tokio::test]
    async fn get_resource_cr_fallback_returns_404_for_missing() {
        use axum::extract::{Path, State};

        let state = make_state();

        // Use an unregistered group to trigger CR fallback
        let result = get_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "widgets".into(),
                "my-widget".into(),
            )),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("missing CR must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// get_namespaced_resource follows the CR fallback path for unregistered groups.
    #[tokio::test]
    async fn get_namespaced_resource_cr_fallback_returns_404_for_missing() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = get_namespaced_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "default".into(),
                "widgets".into(),
                "missing-widget".into(),
            )),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("missing namespaced CR must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// delete_resource follows the CR fallback path for unregistered groups.
    #[tokio::test]
    async fn delete_resource_cr_fallback_returns_404_for_missing() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = delete_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "widgets".into(),
                "missing-widget".into(),
            )),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("delete of missing CR must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// delete_namespaced_resource follows the CR fallback path for unregistered groups.
    #[tokio::test]
    async fn delete_namespaced_resource_cr_fallback_returns_404_for_missing() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = delete_namespaced_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "default".into(),
                "widgets".into(),
                "missing-widget".into(),
            )),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("delete of missing namespaced CR must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// replace_resource CR fallback returns 404 when no CRD is registered.
    /// Without a CRD, the server cannot validate or accept CRs of that type.
    #[tokio::test]
    async fn replace_resource_cr_fallback_returns_404_without_crd() {
        use axum::extract::{Path, State};

        let state = make_state();

        let widget = serde_json::json!({
            "apiVersion": "custom.example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "my-widget" }
        });

        let result = replace_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "widgets".into(),
                "my-widget".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&widget).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("replace_resource without CRD must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// create_resource CR fallback returns 404 when no CRD is registered.
    #[tokio::test]
    async fn create_resource_cr_fallback_returns_404_without_crd() {
        use axum::extract::{Path, State};

        let state = make_state();

        let widget = serde_json::json!({
            "apiVersion": "custom.example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "my-widget" }
        });

        let result = create_resource(
            State(state),
            Path(("custom.example.com".into(), "v1".into(), "widgets".into())),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&widget).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("create_resource without CRD must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// patch_resource CR fallback for unregistered groups.
    #[tokio::test]
    async fn patch_resource_cr_fallback_returns_404_for_missing() {
        use axum::extract::{Path, State};

        let state = make_state();

        let mut mp_headers = axum::http::HeaderMap::new();
        mp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        let patch = serde_json::json!({"metadata": {"labels": {"env": "prod"}}});

        let result = patch_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "widgets".into(),
                "nonexistent".into(),
            )),
            axum::extract::Query(PatchQuery::default()),
            mp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("patch on missing CR must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// patch_namespaced_resource CR fallback for unregistered groups.
    #[tokio::test]
    async fn patch_namespaced_resource_cr_fallback_returns_404_for_missing() {
        use axum::extract::{Path, State};

        let state = make_state();

        let mut mp_headers = axum::http::HeaderMap::new();
        mp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        let patch = serde_json::json!({"metadata": {"labels": {"env": "prod"}}});

        let result = patch_namespaced_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "default".into(),
                "widgets".into(),
                "nonexistent".into(),
            )),
            axum::extract::Query(PatchQuery::default()),
            mp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("patch on missing namespaced CR must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// create_namespaced_resource CR fallback returns 404 when no CRD is registered.
    #[tokio::test]
    async fn create_namespaced_resource_cr_fallback_returns_404_without_crd() {
        use axum::extract::{Path, State};

        let state = make_state();

        let widget = serde_json::json!({
            "apiVersion": "custom.example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "ns-widget", "namespace": "default" }
        });

        let result = create_namespaced_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "default".into(),
                "widgets".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&widget).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("create_namespaced CR without CRD must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// replace_namespaced_resource CR fallback returns 404 when no CRD is registered.
    #[tokio::test]
    async fn replace_namespaced_resource_cr_fallback_returns_404_without_crd() {
        use axum::extract::{Path, State};

        let state = make_state();

        let widget = serde_json::json!({
            "apiVersion": "custom.example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "rns-widget", "namespace": "default" }
        });

        let result = replace_namespaced_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "default".into(),
                "widgets".into(),
                "rns-widget".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&widget).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("replace_namespaced CR without CRD must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    // -- resource.rs CRUD handler error mappings (mayor-96nx) --

    /// patch_resource with an unsupported content-type (e.g. application/json) must
    /// return 415 Unsupported Media Type. Clients that accidentally use the wrong
    /// content type header would otherwise get a cryptic error — 415 correctly
    /// signals that the content-type is the problem, not the request body.
    #[tokio::test]
    async fn patch_resource_with_bad_content_type_returns_415() {
        use axum::extract::{Path, State};

        let state = make_state();

        // application/json is not a supported patch content-type for patch_resource.
        // Valid types: merge-patch+json, strategic-merge-patch+json, json-patch+json,
        //              apply-patch+yaml. application/json alone must return 415.
        let mut bad_headers = axum::http::HeaderMap::new();
        bad_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let patch = serde_json::json!({"metadata": {"labels": {"env": "prod"}}});

        let result = patch_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "any-node".into(),
            )),
            axum::extract::Query(PatchQuery::default()),
            bad_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "application/json content-type must return 415 for patch_resource"
            ),
            Ok(_) => panic!("patch_resource with application/json must return 415"),
        }
    }

    /// patch_namespaced_resource with an unsupported content-type must return 415.
    /// Same invariant as the cluster-scoped case: content-type validation fires before
    /// any store access, so the error is fast and the reason is unambiguous.
    #[tokio::test]
    async fn patch_namespaced_resource_with_bad_content_type_returns_415() {
        use axum::extract::{Path, State};

        let state = make_state();

        let mut bad_headers = axum::http::HeaderMap::new();
        bad_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let patch = serde_json::json!({"metadata": {"labels": {"env": "prod"}}});

        let result = patch_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "any-lease".into(),
            )),
            axum::extract::Query(PatchQuery::default()),
            bad_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "application/json content-type must return 415 for patch_namespaced_resource"
            ),
            Ok(_) => panic!("patch_namespaced_resource with application/json must return 415"),
        }
    }

    /// create_namespaced_resource returns 409 Conflict when creating the same
    /// namespaced object twice. Duplicate creation with the same name and namespace
    /// must be rejected to prevent silent data corruption.
    #[tokio::test]
    async fn create_namespaced_resource_returns_409_on_duplicate() {
        use axum::extract::{Path, State};

        let state = make_state();

        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "dup-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "dup-lease" }
        });
        let body = bytes::Bytes::from(serde_json::to_vec(&lease).unwrap());

        match create_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
            )),
            json_headers(),
            body.clone(),
        )
        .await
        {
            Ok(_) => {}
            Err(_) => panic!("first create must succeed"),
        }

        let result = create_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
            )),
            json_headers(),
            body,
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::CONFLICT,
                "duplicate namespaced create must return 409 Conflict"
            ),
            Ok(_) => panic!("duplicate create_namespaced_resource must return 409"),
        }
    }

    /// strategic_merge_patch merges arrays by name key (not replaces).
    #[test]
    fn strategic_merge_patch_applied_correctly_via_handler_logic() {
        let mut body = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "nginx:1.0"}]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "containers": [{"name": "sidecar", "image": "sidecar:latest"}]
            }
        });
        crate::patch::strategic_merge_patch(&mut body, &patch).unwrap();
        let containers = body["spec"]["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 2, "SMP must merge containers by name");
    }

    // -- PartialObjectMetadata (POM) watch support for built-in resources (mayor-by0r) --
    //
    // The kube-controller-manager's garbage collector uses metadatainformer, which opens
    // watches on ALL resource types with Accept: ...as=PartialObjectMetadata... .
    // list_namespaced_resource and list_resource must detect this header and:
    //   1. Wrap ADDED/MODIFIED events as PartialObjectMetadata objects.
    //   2. Use apiVersion="meta.k8s.io/v1" and kind="PartialObjectMetadata" in all events.
    //   3. Send the initial-events-end BOOKMARK with the correct apiVersion/kind.
    // Without this fix the GC's informer receives events with the wrong apiVersion/kind
    // (e.g. "apps/v1"/"Deployment"), causing it to reject the BOOKMARK and never complete
    // cache sync — which blocks the GC from running and can prevent Deployment→RS creation.

    fn pom_accept_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static(
                "application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,\
                 application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json",
            ),
        );
        h
    }

    /// Regression: list_namespaced_resource with POM Accept must return PartialObjectMetadataList.
    /// The GC does a list before opening a watch. If the list returns a DeploymentList instead of
    /// PartialObjectMetadataList, the GC cannot parse the response and will fail to populate its
    /// dependency graph.
    #[tokio::test]
    async fn list_namespaced_resource_with_pom_accept_returns_partial_object_metadata_list() {
        use axum::body::to_bytes;
        use axum::extract::{Path, Query, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "my-deploy",
                "namespace": "default",
                "ownerReferences": []
            },
            "spec": { "replicas": 1 }
        });
        store
            .put(
                "/registry/apps/deployments/default/my-deploy",
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let resp = list_namespaced_resource(
            State(state),
            Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
            )),
            Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: None,
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
            }),
            pom_accept_headers(),
            axum::Extension(crate::auth::UserInfo {
                username: "test".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("list with POM Accept must succeed"));

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["apiVersion"], "meta.k8s.io/v1",
            "POM list must return apiVersion=meta.k8s.io/v1, not apps/v1; \
             GC cannot parse the dependency graph from a DeploymentList"
        );
        assert_eq!(
            v["kind"], "PartialObjectMetadataList",
            "POM list must return kind=PartialObjectMetadataList, not DeploymentList"
        );
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "must return 1 item");
        assert_eq!(
            items[0]["apiVersion"], "meta.k8s.io/v1",
            "each POM item must have apiVersion=meta.k8s.io/v1"
        );
        assert_eq!(
            items[0]["kind"], "PartialObjectMetadata",
            "each POM item must have kind=PartialObjectMetadata"
        );
        // spec must be stripped (only metadata is preserved in PartialObjectMetadata)
        assert!(
            items[0]["spec"].is_null() || items[0].get("spec").is_none(),
            "POM items must not include spec — only metadata is preserved"
        );
    }

    /// Regression: list_namespaced_resource with POM Accept + sendInitialEvents=true must send
    /// the initial-events-end BOOKMARK with apiVersion=meta.k8s.io/v1 and
    /// kind=PartialObjectMetadata. Without this fix, the GC's informer receives a BOOKMARK
    /// with apiVersion=apps/v1 and kind=Deployment, which it rejects, causing the informer to
    /// never complete cache sync and eventually log "event bookmark expired".
    #[tokio::test]
    async fn list_namespaced_resource_with_pom_accept_watch_emits_pom_bookmark() {
        use axum::extract::{Path, Query, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed a Deployment so sendInitialEvents emits at least one ADDED event.
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "gc-deploy", "namespace": "default" },
            "spec": { "replicas": 1 }
        });
        store
            .put(
                "/registry/apps/deployments/default/gc-deploy",
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let resp = list_namespaced_resource(
            State(state),
            Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
            )),
            Query(CollectionQuery {
                watch: Some(true),
                resource_version: Some(0),
                label_selector: None,
                field_selector: None,
                limit: None,
                continue_token: None,
                send_initial_events: Some(true),
                allow_watch_bookmarks: Some(true),
            }),
            pom_accept_headers(),
            axum::Extension(crate::auth::UserInfo {
                username: "gc-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("watch with POM Accept must succeed"));

        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // Read the stream with a short timeout — initial events are emitted synchronously.
        use tokio::time::{timeout, Duration};
        let body = resp.into_body();
        let bytes = timeout(
            Duration::from_millis(300),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await
        .unwrap_or(Ok(bytes::Bytes::new()))
        .unwrap_or_default();

        let text = std::str::from_utf8(&bytes).unwrap_or("");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        // The ADDED event must carry PartialObjectMetadata, not Deployment.
        let added = lines.iter().find(|v| v["type"] == "ADDED");
        assert!(
            added.is_some(),
            "watch with sendInitialEvents must emit at least one ADDED event for the seeded Deployment"
        );
        let added = added.unwrap();
        assert_eq!(
            added["object"]["apiVersion"], "meta.k8s.io/v1",
            "ADDED event must carry apiVersion=meta.k8s.io/v1 when POM is requested; \
             GC informer rejects ADDED events with wrong apiVersion"
        );
        assert_eq!(
            added["object"]["kind"], "PartialObjectMetadata",
            "ADDED event must carry kind=PartialObjectMetadata when POM is requested"
        );

        // The initial-events-end BOOKMARK must carry PartialObjectMetadata apiVersion/kind.
        // This is the key fix: without it the GC informer never completes cache sync.
        let bookmark = lines.iter().find(|v| {
            v["type"] == "BOOKMARK"
                && v["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
        });
        assert!(
            bookmark.is_some(),
            "watch with POM Accept + sendInitialEvents must emit initial-events-end BOOKMARK; \
             without it GC's metadatainformer blocks forever and logs 'event bookmark expired'. \
             Got lines: {:?}",
            lines
        );
        let bookmark = bookmark.unwrap();
        assert_eq!(
            bookmark["object"]["apiVersion"], "meta.k8s.io/v1",
            "initial-events-end BOOKMARK must carry apiVersion=meta.k8s.io/v1, not apps/v1; \
             GC informer validates the apiVersion in the BOOKMARK and rejects mismatches"
        );
        assert_eq!(
            bookmark["object"]["kind"], "PartialObjectMetadata",
            "initial-events-end BOOKMARK must carry kind=PartialObjectMetadata, not Deployment"
        );
    }

    /// create_resource with invalid JSON body must return 400 Bad Request.
    /// Clients that send malformed bodies (e.g. truncated JSON) must get a clear
    /// rejection rather than a 500 or silent data corruption.
    #[tokio::test]
    async fn create_resource_invalid_json_returns_400() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = create_resource(
            State(state),
            Path(("".into(), "v1".into(), "nodes".into())),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from("not valid json"),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::BAD_REQUEST,
                "invalid JSON body must return 400"
            ),
            Ok(_) => panic!("invalid JSON must be rejected with 400"),
        }
    }

    /// replace_namespaced_resource rejects a body whose name doesn't match the URL name.
    /// Prevents accidental cross-object overwrites via PUT.
    #[tokio::test]
    async fn replace_namespaced_resource_name_mismatch_returns_400() {
        use axum::extract::{Path, State};

        let state = make_state();

        let body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "other-lease", "namespace": "kube-node-lease" },
            "spec": {}
        });

        let result = replace_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "url-name".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::BAD_REQUEST,
                "name mismatch between URL and body must return 400"
            ),
            Ok(_) => panic!("name mismatch must be rejected with 400"),
        }
    }

    /// replace_resource rejects a body whose name doesn't match the URL name.
    #[tokio::test]
    async fn replace_resource_name_mismatch_returns_400() {
        use axum::extract::{Path, State};

        let state = make_state();

        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "actual-name" },
            "spec": { "drivers": [] }
        });

        let result = replace_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "url-name".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::BAD_REQUEST,
                "name mismatch must return 400"
            ),
            Ok(_) => panic!("name mismatch must be rejected with 400"),
        }
    }

    /// create_namespaced_resource with invalid JSON body must return 400.
    #[tokio::test]
    async fn create_namespaced_resource_invalid_json_returns_400() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = create_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
            )),
            json_headers(),
            bytes::Bytes::from("not json at all"),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::BAD_REQUEST,
                "invalid JSON in create_namespaced_resource must return 400"
            ),
            Ok(_) => panic!("invalid JSON body must return 400"),
        }
    }

    /// get_resource with an invalid name (contains '..') must return 400.
    /// Name validation guards against path traversal and invalid etcd keys.
    #[tokio::test]
    async fn get_resource_invalid_name_returns_400() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = get_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "..".into(),
            )),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("invalid name must return error"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::BAD_REQUEST,
            "double-dot name must be rejected with 400 — guards against path traversal"
        );
    }

    /// delete_resource with invalid name must return 400 (validate_name check).
    #[tokio::test]
    async fn delete_resource_invalid_name_returns_400() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = delete_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "..".into(),
            )),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("invalid name must return error"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::BAD_REQUEST,
            "invalid name must return 400 from delete_resource"
        );
    }

    /// replace_resource with invalid body JSON must return 400.
    #[tokio::test]
    async fn replace_resource_invalid_json_returns_400() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = replace_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "test-node".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from("invalid json"),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::BAD_REQUEST,
                "invalid JSON in replace_resource must return 400"
            ),
            Ok(_) => panic!("invalid JSON must return 400"),
        }
    }

    /// replace_namespaced_resource with invalid JSON body must return 400.
    #[tokio::test]
    async fn replace_namespaced_resource_invalid_json_returns_400() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = replace_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "my-lease".into(),
            )),
            json_headers(),
            bytes::Bytes::from("not json"),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::BAD_REQUEST,
                "invalid JSON in replace_namespaced_resource must return 400"
            ),
            Ok(_) => panic!("invalid JSON body must return 400"),
        }
    }

    /// rbac_cluster_key and rbac_namespaced_key produce the expected paths.
    /// These keys index ClusterRoles/ClusterRoleBindings for RBAC rule lookup.
    /// A wrong key format causes RBAC evaluation to fail silently.
    #[test]
    fn rbac_key_format_is_correct() {
        let ck = rbac_cluster_key("rbac.authorization.k8s.io", "v1", "clusterroles", "admin");
        assert_eq!(
            ck, "/apis/rbac.authorization.k8s.io/v1/clusterroles/admin",
            "cluster key format must match the RBAC index expected path"
        );

        let nk = rbac_namespaced_key(
            "rbac.authorization.k8s.io",
            "v1",
            "kube-system",
            "rolebindings",
            "view",
        );
        assert_eq!(
            nk, "/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/rolebindings/view",
            "namespaced key format must match the RBAC index expected path"
        );
    }

    /// wants_partial_object_metadata detects the GC's Accept header correctly.
    /// This is the predicate that gates POM mode — if it returns false for the GC's header,
    /// the GC gets wrong apiVersion/kind in all events and can never sync.
    #[test]
    fn wants_partial_object_metadata_detects_gc_accept_header() {
        // Real header sent by kube-controller-manager's metadatainformer.
        let gc_accept = "application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;\
                         g=meta.k8s.io;v=v1,application/json;as=PartialObjectMetadata;\
                         g=meta.k8s.io;v=v1,application/json";
        assert!(
            wants_partial_object_metadata(gc_accept),
            "GC's Accept header must be detected as POM; if not, GC informers get wrong \
             apiVersion/kind and can never sync (mayor-by0r)"
        );

        // Non-POM accept must return false.
        assert!(
            !wants_partial_object_metadata("application/json"),
            "plain JSON Accept must not be detected as POM"
        );
        assert!(
            !wants_partial_object_metadata(""),
            "empty Accept must not be detected as POM"
        );
    }
}
