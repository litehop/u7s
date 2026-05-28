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
use super::watch::{fetch_initial_events, watch_generic, WatchConfig};

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

pub async fn list_resource<S: Store>(
    State(state): State<AppState<S>>,
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
    let table = super::table::wants_table(accept);

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
            WatchConfig {
                prefix,
                api_version: watch_api_version,
                kind: watch_kind,
                from_revision: from_rv,
                initial_items: initial,
                label_selector: query.label_selector,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username: user.username,
                as_partial_object_metadata: pom,
                group: group.clone(),
                plural: plural.clone(),
                timeout_seconds: query.timeout_seconds,
            },
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
        .map(|t| decode_continue(t, &state.continue_token_key))
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
        let mut v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        super::defaults::apply_defaults(&group, &plural, &mut v);
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

    if table {
        return Ok(Json(super::table::build_table(&group, &plural, items)).into_response());
    }

    let body = build_list_response(
        &meta.kind,
        &group,
        &version,
        resp.revision,
        items,
        resp.continue_key,
        resp.remaining_count,
        &state.continue_token_key,
    );
    Ok(Json(body).into_response())
}

pub async fn get_resource<S: Store>(
    State(state): State<AppState<S>>,
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

    let mut obj: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;
    super::defaults::apply_defaults(&group, &plural, &mut obj);
    Ok(Json(obj).into_response())
}

pub async fn create_resource<S: Store>(
    State(state): State<AppState<S>>,
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
    super::defaults::validate_resource(&group, &plural, &obj.body).map_err(Status::bad_request)?;

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
        Err(StoreError::AlreadyExists { .. }) => {
            let stored = state
                .store
                .get(&key)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .ok_or_else(|| Status::not_found(&name, &meta.kind))?;
            let existing: serde_json::Value = serde_json::from_slice(&stored.value)
                .map_err(|e| Status::internal(e.to_string()))?;
            return Ok((StatusCode::CONFLICT, Json(existing)).into_response());
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

pub async fn replace_resource<S: Store>(
    State(state): State<AppState<S>>,
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
    super::defaults::validate_resource(&group, &plural, &obj.body).map_err(Status::bad_request)?;

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

pub async fn delete_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Guard first — before validate_name so colon-names in RBAC (e.g. system:node) don't fail
    // the DNS-label charset check. The collection-delete path has the same guard.
    if is_seeded_rbac_object(&group, &name) {
        return Err(Status::forbidden(format!(
            "cannot delete bootstrap RBAC object {name}"
        )));
    }
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

/// Parameters for `do_patch`.
///
/// Groups the arguments that previously caused a `clippy::too_many_arguments` warning.
pub(crate) struct PatchConfig<'a> {
    pub key: &'a str,
    pub meta: &'a crate::types::ResourceMeta,
    pub group: &'a str,
    pub version: &'a str,
    pub plural: &'a str,
    /// `None` for cluster-scoped resources, `Some(namespace)` for namespaced ones.
    pub ns: Option<&'a str>,
    pub name: &'a str,
    pub is_ssa: bool,
    /// Value of the `?fieldManager=` query param; used only for SSA to
    /// populate the synthetic `managedFields` echo in the response.
    pub field_manager: Option<&'a str>,
    pub patch_type: PatchType,
    pub body: Bytes,
}

/// Shared patch logic for cluster-scoped and namespaced resources.
///
/// `cfg.ns` is `None` for cluster-scoped resources and `Some(namespace)` for namespaced ones.
/// The caller supplies the pre-computed `cfg.key` and resolved `cfg.meta`.
/// `cfg.field_manager` is the value of the `?fieldManager=` query param; used only for SSA to
/// populate the synthetic `managedFields` echo in the response.
pub(crate) async fn do_patch<S: Store>(
    state: &AppState<S>,
    cfg: PatchConfig<'_>,
) -> Result<Response, crate::status::StatusError> {
    let PatchConfig {
        key,
        meta,
        group,
        version,
        plural,
        ns,
        name,
        is_ssa,
        field_manager,
        patch_type,
        body,
    } = cfg;
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
        super::defaults::validate_resource(group, plural, &obj.body)
            .map_err(Status::bad_request)?;
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
                super::defaults::validate_resource(group, plural, &current.body)
                    .map_err(Status::bad_request)?;
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
    super::defaults::validate_resource(group, plural, &current.body)
        .map_err(Status::bad_request)?;

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

pub async fn patch_resource<S: Store>(
    State(state): State<AppState<S>>,
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
        PatchConfig {
            key: &key,
            meta: &meta,
            group: &group,
            version: &version,
            plural: &plural,
            ns: None,
            name: &name,
            is_ssa,
            field_manager: patch_query.field_manager.as_deref(),
            patch_type,
            body,
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Namespaced handlers  (group/version/namespaces/:ns/resource)
// ---------------------------------------------------------------------------

pub async fn list_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
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
    let table = super::table::wants_table(accept);

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
            WatchConfig {
                prefix,
                api_version: watch_api_version,
                kind: watch_kind,
                from_revision: from_rv,
                initial_items: initial,
                label_selector: query.label_selector,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username: user.username,
                as_partial_object_metadata: pom,
                group: group.clone(),
                plural: plural.clone(),
                timeout_seconds: query.timeout_seconds,
            },
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
        .map(|t| decode_continue(t, &state.continue_token_key))
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
        let mut v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        super::defaults::apply_defaults(&group, &plural, &mut v);
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

    if table {
        return Ok(Json(super::table::build_table(&group, &plural, items)).into_response());
    }

    let body = build_list_response(
        &meta.kind,
        &group,
        &version,
        resp.revision,
        items,
        resp.continue_key,
        resp.remaining_count,
        &state.continue_token_key,
    );
    Ok(Json(body).into_response())
}

pub async fn get_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
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

    let mut obj: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;
    super::defaults::apply_defaults(&group, &plural, &mut obj);
    Ok(Json(obj).into_response())
}

pub async fn create_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
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

    // Auto-allocate clusterIP for Services that don't specify one.
    // Must run before apply_defaults so the allocated IP feeds into ipFamilies/clusterIPs.
    if group.is_empty() && plural == "services" {
        maybe_allocate_cluster_ip(&state, &ns, &name, &mut obj.body).await?;
    }

    super::defaults::apply_defaults(&group, &plural, &mut obj.body);
    super::defaults::validate_resource(&group, &plural, &obj.body).map_err(Status::bad_request)?;

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
        Err(StoreError::AlreadyExists { .. }) => {
            let stored = state
                .store
                .get(&key)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .ok_or_else(|| Status::not_found(&name, &meta.kind))?;
            let existing: serde_json::Value = serde_json::from_slice(&stored.value)
                .map_err(|e| Status::internal(e.to_string()))?;
            return Ok((StatusCode::CONFLICT, Json(existing)).into_response());
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

pub async fn replace_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
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
    super::defaults::validate_resource(&group, &plural, &obj.body).map_err(Status::bad_request)?;

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

pub async fn delete_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    // Guard before validate_name("name") so colon-names in RBAC don't fail the charset check.
    // Namespaced system: objects don't exist today but blocking them prevents future surprises.
    if is_seeded_rbac_object(&group, &name) {
        return Err(Status::forbidden(format!(
            "cannot delete bootstrap RBAC object {name}"
        )));
    }
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

    // Release the clusterIP sentinel so the IP can be re-allocated.
    if group.is_empty() && plural == "services" {
        let cluster_ip = obj.body["spec"]["clusterIP"]
            .as_str()
            .unwrap_or("")
            .to_string();
        state.release_service_ip(&cluster_ip).await;
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    }))
    .into_response())
}

pub async fn patch_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
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
        PatchConfig {
            key: &key,
            meta: &meta,
            group: &group,
            version: &version,
            plural: &plural,
            ns: Some(&ns),
            name: &name,
            is_ssa,
            field_manager: patch_query.field_manager.as_deref(),
            patch_type,
            body,
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Collection delete handlers  (DELETE on collection endpoint)
// ---------------------------------------------------------------------------

/// DELETE /apis/{group}/{version}/{resource}
///
/// Deletes all cluster-scoped objects of the given resource type.  Real
/// Kubernetes supports collection delete (kubectl delete clusterrolebinding --all,
/// sonobuoy delete --all).  Without this handler axum returns 405 because no
/// DELETE is registered on the collection route.
pub async fn delete_collection_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural)): Path<(String, String, String)>,
    Query(query): Query<CollectionQuery>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Verify the resource is known; return 404 for unknown resource types.
    let _meta = lookup(&state, &group, &version, &plural)
        .cloned()
        .map_err(|_| Status::not_found(&plural, &format!("{group}/{version}/{plural}")))?;

    let prefix = group_list_prefix(&group, &plural, None);
    let resp = state
        .store
        .list(&prefix, u7s_store::ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(parse_label_selector)
        .transpose()?;

    for obj in resp.items {
        // Extract name from the stored JSON for RBAC index eviction and protection.
        let mut cluster_ip_to_release: Option<String> = None;
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.value) {
            let name = parsed["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            // Honor labelSelector — only delete objects matching the requested labels.
            if let Some(ref pairs) = label_pairs {
                let kept = apply_label_selector(vec![parsed.clone()], pairs);
                if kept.is_empty() {
                    continue;
                }
            }
            // Skip bootstrap RBAC objects — deleting them would revoke cluster-admin
            // access for the admin cert user (system:masters → cluster-admin binding).
            if is_seeded_rbac_object(&group, &name) {
                continue;
            }
            if group == RBAC_GROUP && !name.is_empty() {
                let rbac_key = rbac_cluster_key(&group, &version, &plural, &name);
                state.rbac_index.remove_object(&rbac_key);
            }
            if group.is_empty() && plural == "services" {
                let ip = parsed["spec"]["clusterIP"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                if !ip.is_empty() {
                    cluster_ip_to_release = Some(ip);
                }
            }
        }
        // Ignore NotFound races (another writer may have deleted concurrently).
        let _ = state.store.delete(&obj.key, None).await;
        if let Some(ref ip) = cluster_ip_to_release {
            state.release_service_ip(ip).await;
        }
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    }))
    .into_response())
}

/// DELETE /apis/{group}/{version}/namespaces/{ns}/{resource}
///
/// Deletes all namespaced objects of the given resource type within the namespace.
pub async fn delete_collection_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    Query(query): Query<CollectionQuery>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    let _meta = lookup(&state, &group, &version, &plural)
        .cloned()
        .map_err(|_| Status::not_found(&plural, &format!("{group}/{version}/{plural}")))?;

    let prefix = group_list_prefix(&group, &plural, Some(&ns));
    let resp = state
        .store
        .list(&prefix, u7s_store::ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(parse_label_selector)
        .transpose()?;

    for obj in resp.items {
        let mut cluster_ip_to_release: Option<String> = None;
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.value) {
            let name = parsed["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            if group.is_empty() && plural == "services" {
                let ip = parsed["spec"]["clusterIP"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                if !ip.is_empty() {
                    cluster_ip_to_release = Some(ip);
                }
            }
            if let Some(ref pairs) = label_pairs {
                let kept = apply_label_selector(vec![parsed], pairs);
                if kept.is_empty() {
                    continue;
                }
            }
            if group == RBAC_GROUP && !name.is_empty() {
                let rbac_key = rbac_namespaced_key(&group, &version, &ns, &plural, &name);
                state.rbac_index.remove_object(&rbac_key);
            }
        }
        let _ = state.store.delete(&obj.key, None).await;
        if let Some(ref ip) = cluster_ip_to_release {
            state.release_service_ip(ip).await;
        }
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// Private helpers (duplicated from generic to avoid pub exposure)
// ---------------------------------------------------------------------------

/// Allocate a clusterIP for a Service if none is already set.
///
/// Called on Service CREATE only (not update/patch — you never reallocate).
/// Keeps `apply_defaults` pure (no async side effects).
///
/// Sets `spec.clusterIP` in `body` when allocation succeeds.
/// If `spec.clusterIP` is already set (non-empty string), does nothing.
/// ExternalName services are skipped entirely — they must not have a ClusterIP.
async fn maybe_allocate_cluster_ip<S: Store>(
    state: &AppState<S>,
    ns: &str,
    name: &str,
    body: &mut serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    // ExternalName services must not have a ClusterIP; skip allocation entirely.
    let svc_type = body["spec"]["type"].as_str().unwrap_or("");
    if svc_type == "ExternalName" {
        return Ok(());
    }

    // Only auto-allocate when clusterIP is absent or empty.
    let existing = body["spec"]["clusterIP"].as_str().unwrap_or("").to_string();
    if !existing.is_empty() {
        return Ok(());
    }

    // Detect the special `default/kubernetes` Service which reserves .1.
    let is_kubernetes_service = ns == "default" && name == "kubernetes";

    if let Some(ip) = state.allocate_service_ip(is_kubernetes_service).await? {
        body["spec"]["clusterIP"] = serde_json::Value::String(ip.to_string());
    }
    Ok(())
}

fn rbac_cluster_key(group: &str, version: &str, plural: &str, name: &str) -> String {
    format!("/apis/{group}/{version}/{plural}/{name}")
}

fn rbac_namespaced_key(group: &str, version: &str, ns: &str, plural: &str, name: &str) -> String {
    format!("/apis/{group}/{version}/namespaces/{ns}/{plural}/{name}")
}

/// Returns true if the named RBAC object was seeded at startup and must not be
/// bulk-deleted by collection DELETE (e.g. sonobuoy delete --all).
///
/// Any RBAC object whose name starts with "system:" is considered
/// bootstrap-protected and survives collection deletes.
///
/// This matters because sonobuoy delete --all now sends DELETE to the
/// collection endpoint (enabled in PR #230). Without protection, that request
/// wipes the system:masters ClusterRoleBinding from both the SQLite store and
/// the in-memory RBAC index, revoking cluster-admin access for the cert user.
fn is_seeded_rbac_object(group: &str, name: &str) -> bool {
    group == RBAC_GROUP && (name.starts_with("system:") || name == "cluster-admin")
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
                timeout_seconds: None,
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
                _field_validation: None,
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
                _field_validation: None,
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
                timeout_seconds: None,
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

    /// Regression test (mayor-3cgu): collection DELETE on RBAC resources must NOT remove
    /// bootstrap objects (system:masters, cluster-admin, system:node, etc.).
    ///
    /// sonobuoy delete --all issues DELETE /apis/rbac.authorization.k8s.io/v1/clusterrolebindings
    /// which (after PR #230) now calls delete_collection_resource.  Without protection that
    /// handler would wipe the system:masters ClusterRoleBinding from both the SQLite store and
    /// the in-memory RBAC index, causing the admin cert user to lose cluster-admin access
    /// immediately — even without a server restart.
    #[tokio::test]
    async fn delete_collection_skips_seeded_rbac_objects() {
        use axum::extract::{Path, State};
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

        let group = "rbac.authorization.k8s.io";
        let version = "v1";
        let plural = "clusterrolebindings";

        // Seed the system:masters ClusterRoleBinding as seed_rbac() does at startup.
        let crb_key = crate::keys::group_object_key(group, plural, None, "system:masters");
        let crb_val = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": "system:masters" },
            "subjects": [{ "kind": "Group", "name": "system:masters" }],
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" }
        });
        store
            .put(
                &crb_key,
                bytes::Bytes::from(serde_json::to_vec(&crb_val).unwrap()),
                None,
            )
            .await
            .expect("seed must succeed");
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system:masters",
            &crb_val,
        );

        // Also insert a non-system binding that sonobuoy might create.
        let user_crb_key =
            crate::keys::group_object_key(group, plural, None, "sonobuoy-clusteradmin");
        let user_crb_val = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": "sonobuoy-clusteradmin" },
            "subjects": [{ "kind": "ServiceAccount", "name": "sonobuoy", "namespace": "sonobuoy" }],
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" }
        });
        store
            .put(
                &user_crb_key,
                bytes::Bytes::from(serde_json::to_vec(&user_crb_val).unwrap()),
                None,
            )
            .await
            .expect("user binding seed must succeed");

        // Collection DELETE — simulates sonobuoy delete --all (no labelSelector)
        let result = delete_collection_resource(
            State(state.clone()),
            Path((group.to_string(), version.to_string(), plural.to_string())),
            Query(CollectionQuery {
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
        )
        .await;
        assert!(result.is_ok(), "collection delete must succeed");

        // system:masters must still be in the store.
        let still_there = store.get(&crb_key).await.expect("store.get must not fail");
        assert!(
            still_there.is_some(),
            "system:masters CRB must survive collection DELETE — \
             deleting it would revoke cluster-admin access for the admin cert user"
        );

        // sonobuoy-clusteradmin must be gone.
        let gone = store
            .get(&user_crb_key)
            .await
            .expect("store.get must not fail");
        assert!(
            gone.is_none(),
            "non-system CRB (sonobuoy-clusteradmin) must be deleted by collection DELETE"
        );
    }

    /// is_seeded_rbac_object protects names that start with "system:".
    /// Verifies the name-matching logic so we can't accidentally widen/narrow the guard.
    #[test]
    fn is_seeded_rbac_object_matches_protected_names() {
        let group = "rbac.authorization.k8s.io";
        // Protected names.
        assert!(
            is_seeded_rbac_object(group, "system:masters"),
            "system:masters must be protected"
        );
        assert!(
            is_seeded_rbac_object(group, "system:node"),
            "system:node must be protected"
        );
        assert!(
            is_seeded_rbac_object(group, "system:basic-user"),
            "system:basic-user must be protected"
        );
        // Unprotected names.
        assert!(
            !is_seeded_rbac_object(group, "sonobuoy-clusteradmin"),
            "sonobuoy bindings must not be protected"
        );
        assert!(
            !is_seeded_rbac_object(group, "my-custom-role"),
            "user-created roles must not be protected"
        );
        // Wrong group: must not protect even system: names.
        assert!(
            !is_seeded_rbac_object("apps", "system:masters"),
            "is_seeded_rbac_object must only protect rbac.authorization.k8s.io resources"
        );
    }

    /// delete_resource must reject a named DELETE of system:node ClusterRoleBinding with 403.
    ///
    /// This is the bug sonobuoy triggered: a named DELETE bypassed the is_seeded_rbac_object guard
    /// that the collection-delete path already had. Without this guard the bootstrap binding is
    /// erased and the admin cert user loses cluster-admin access. If this guard is removed, the
    /// test will return Ok(200) or Err(404) instead of Err(403).
    ///
    /// The guard fires before validate_name, so "system:node" (which contains a colon not in the
    /// DNS-label charset) never reaches the validator — the 403 is returned first.
    #[tokio::test]
    async fn delete_resource_rejects_named_delete_of_bootstrap_clusterrolebinding() {
        use axum::extract::{Path, State};

        let state = make_state();

        let result = delete_resource(
            State(state),
            Path((
                "rbac.authorization.k8s.io".into(),
                "v1".into(),
                "clusterrolebindings".into(),
                "system:node".into(),
            )),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::FORBIDDEN,
                "named DELETE of system:node ClusterRoleBinding must return 403 Forbidden — \
                 the guard must fire before validate_name so the colon in the name is irrelevant"
            ),
            Ok(_) => panic!(
                "named DELETE of bootstrap RBAC object must be rejected — \
                 if this fires the is_seeded_rbac_object guard was removed from delete_resource"
            ),
        }
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
        .await
        .unwrap_or_else(|e| panic!("duplicate create must not hard-error; got: {e:?}"))
        .into_response();

        assert_eq!(
            result.status(),
            axum::http::StatusCode::CONFLICT,
            "duplicate create must return 409 Conflict with existing object body"
        );
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
                timeout_seconds: None,
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
        .await
        .unwrap_or_else(|e| panic!("duplicate namespaced create must not hard-error; got: {e:?}"))
        .into_response();

        assert_eq!(
            result.status(),
            axum::http::StatusCode::CONFLICT,
            "duplicate namespaced create must return 409 Conflict with existing object body"
        );
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
                timeout_seconds: None,
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
                timeout_seconds: None,
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

    // -- is_seeded_rbac_object --

    #[test]
    fn seeded_rbac_protects_cluster_admin() {
        assert!(
            is_seeded_rbac_object(RBAC_GROUP, "cluster-admin"),
            "cluster-admin must be protected — sonobuoy delete --all must not wipe it"
        );
    }

    #[test]
    fn seeded_rbac_protects_system_prefix() {
        assert!(is_seeded_rbac_object(RBAC_GROUP, "system:node"));
        assert!(is_seeded_rbac_object(RBAC_GROUP, "system:masters"));
        assert!(is_seeded_rbac_object(RBAC_GROUP, "system:basic-user"));
    }

    #[test]
    fn seeded_rbac_allows_user_roles() {
        assert!(!is_seeded_rbac_object(
            RBAC_GROUP,
            "sonobuoy-serviceaccount-cr"
        ));
        assert!(!is_seeded_rbac_object(RBAC_GROUP, "my-custom-role"));
    }

    #[test]
    fn seeded_rbac_wrong_group_is_not_protected() {
        assert!(!is_seeded_rbac_object("apps", "cluster-admin"));
        assert!(!is_seeded_rbac_object("", "system:node"));
    }

    // ---------------------------------------------------------------------------
    // Service IP field defaulting — integration tests
    // ---------------------------------------------------------------------------

    /// POSTing a Service with only spec.clusterIP must cause the GET response to include
    /// ipFamilies, ipFamilyPolicy, and clusterIPs.
    ///
    /// KCM's endpoints-controller crashes at IPFamilies[0] when these fields are absent.
    /// Write-time defaulting ensures any Service stored after this fix has the fields.
    /// Read-time defaulting in the GET handler covers pre-fix objects in the store.
    #[tokio::test]
    async fn service_create_and_get_has_ip_family_fields() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "my-svc", "namespace": "default" },
            "spec": { "clusterIP": "10.96.0.1", "ports": [{ "port": 80 }] }
        });

        // Create via namespaced POST.
        let create_result = create_namespaced_resource(
            State(state.clone()),
            Path(("".into(), "v1".into(), "default".into(), "services".into())),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("Service create must succeed"))
        .into_response();
        assert_eq!(create_result.status(), axum::http::StatusCode::CREATED);

        // GET it back.
        let get_result = get_namespaced_resource(
            State(state.clone()),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "services".into(),
                "my-svc".into(),
            )),
        )
        .await
        .unwrap_or_else(|_| panic!("Service GET must succeed"));

        let body = to_bytes(get_result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["spec"]["ipFamilyPolicy"], "SingleStack",
            "GET must return ipFamilyPolicy=SingleStack"
        );
        assert_eq!(
            v["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "GET must return ipFamilies=[IPv4] for an IPv4 clusterIP"
        );
        assert_eq!(
            v["spec"]["clusterIPs"],
            serde_json::json!(["10.96.0.1"]),
            "GET must return clusterIPs=[clusterIP]"
        );
    }

    /// A headless Service (clusterIP="None") must get ipFamilies defaulted but no clusterIPs.
    ///
    /// "None" is a sentinel that kube uses for headless Services; it must not appear
    /// in clusterIPs.  KCM reads IPFamilies[0] even for headless Services, so
    /// the field must be present.
    #[tokio::test]
    async fn headless_service_get_has_ip_family_but_no_cluster_ips() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "headless-svc", "namespace": "default" },
            "spec": { "clusterIP": "None" }
        });

        let _ = create_namespaced_resource(
            State(state.clone()),
            Path(("".into(), "v1".into(), "default".into(), "services".into())),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("headless Service create must succeed"))
        .into_response();

        let get_result = get_namespaced_resource(
            State(state.clone()),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "services".into(),
                "headless-svc".into(),
            )),
        )
        .await
        .unwrap_or_else(|_| panic!("headless Service GET must succeed"));

        let body = to_bytes(get_result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "headless Service must have ipFamilies=[IPv4]"
        );
        assert!(
            v["spec"]["clusterIPs"].is_null(),
            "headless Service must not have clusterIPs set"
        );
    }

    // -- delete_collection_namespaced_resource releases clusterIP sentinels --

    /// Deleting a Service collection must release the clusterIP sentinels so those
    /// IPs can be re-allocated.  Without this fix, each create-then-delete cycle
    /// leaks a sentinel, causing CIDR exhaustion on clusters that churn Services.
    #[tokio::test]
    async fn delete_collection_releases_cluster_ip_sentinels() {
        use crate::state::ServiceIpAllocator;
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        // /30 gives exactly one usable IP (.2); .1 is reserved for kubernetes service.
        // Use /29 so we have two usable IPs for two Services.
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let alloc = ServiceIpAllocator::from_cidr("10.0.0.0/29").expect("valid CIDR");
        let state = crate::state::AppState::new_with_config(crate::state::AppStateConfig {
            store: store.clone(),
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: None,
            webhook_identity_pem: None,
            service_ip_allocator: Some(alloc),
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            continue_token_key: None,
        });

        // Create two Services — allocation attaches a sentinel for each IP.
        for name in &["svc-a", "svc-b"] {
            let svc = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": { "name": name, "namespace": "default" },
                "spec": {}
            });
            let _ = create_namespaced_resource(
                State(state.clone()),
                Path(("".into(), "v1".into(), "default".into(), "services".into())),
                json_headers(),
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
            )
            .await
            .unwrap_or_else(|_| panic!("Service create must succeed"))
            .into_response();
        }

        // Confirm two sentinels exist.
        let sentinel_prefix = crate::state::SERVICE_IP_PREFIX;
        let sentinels_before = store
            .list(sentinel_prefix, u7s_store::ListOptions::default())
            .await
            .expect("list sentinels");
        assert_eq!(
            sentinels_before.items.len(),
            2,
            "two Services must produce two clusterIP sentinels"
        );

        // Delete the entire services collection in the default namespace.
        delete_collection_namespaced_resource(
            State(state.clone()),
            Path(("".into(), "v1".into(), "default".into(), "services".into())),
            Query(CollectionQuery {
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
        )
        .await
        .unwrap_or_else(|_| panic!("delete_collection must succeed"));

        // Sentinels must be gone — without the fix they would remain and exhaust the CIDR.
        let sentinels_after = store
            .list(sentinel_prefix, u7s_store::ListOptions::default())
            .await
            .expect("list sentinels after delete");
        assert_eq!(
            sentinels_after.items.len(),
            0,
            "delete_collection must release clusterIP sentinels; \
             leaked sentinels cause CIDR exhaustion"
        );

        // Verify the CIDR can be fully allocated again (two IPs available).
        let ip1 = state
            .allocate_service_ip(false)
            .await
            .expect("allocation must not error")
            .expect("allocation must return Some after sentinels released");
        let ip2 = state
            .allocate_service_ip(false)
            .await
            .expect("allocation must not error")
            .expect("second allocation must return Some after sentinels released");
        assert_ne!(ip1, ip2, "reallocated IPs must be distinct");
    }

    // ---------------------------------------------------------------------------
    // fieldValidation query param regression (mayor-hww0)
    // ---------------------------------------------------------------------------

    /// create_resource with a valid ClusterRole body must return 201.
    ///
    /// `kubectl create` always sends `?fieldValidation=Strict` in the query string.
    /// The handler must accept and ignore unknown query parameters — it has no Query
    /// extractor, so serde never sees them, but this test guards the handler body-parsing
    /// path against regressions that could cause the body to appear empty or invalid.
    ///
    /// If this test fails it means the ClusterRole handler itself is broken, not the
    /// query-param routing. The full-router regression (in main.rs) validates the
    /// query-param path end-to-end.
    #[tokio::test]
    async fn create_clusterrole_with_valid_body_returns_201() {
        use axum::extract::{Path, State};
        use axum::http::StatusCode;

        let state = make_state();

        // kubectl create clusterrole body shape — minimal but structurally correct.
        let body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": { "name": "sonobuoy-clusteradmin" },
            "rules": [
                { "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }
            ]
        });

        let result = create_resource(
            State(state),
            Path((
                "rbac.authorization.k8s.io".into(),
                "v1".into(),
                "clusterroles".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "kubectl".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;

        let resp = result
            .unwrap_or_else(|e| panic!("ClusterRole create must succeed; got error: {e:?}"))
            .into_response();

        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "valid ClusterRole body must produce 201 Created — \
             kubectl create always sends this shape and must not get 400"
        );
    }

    /// delete_collection_namespaced_resource must remove every object in the
    /// namespace so that the KCM namespace controller can finish namespace
    /// deletion.  Without this, services linger after namespace deletion and
    /// the finalizer is never removed, blocking namespace cleanup indefinitely.
    #[tokio::test]
    async fn delete_collection_namespaced_removes_all_objects() {
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

        for name in &["alpha", "beta"] {
            let body = serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": { "name": name, "namespace": "test-ns" },
                "spec": { "holderIdentity": name }
            });
            create_namespaced_resource(
                State(state.clone()),
                Path((
                    "coordination.k8s.io".into(),
                    "v1".into(),
                    "test-ns".into(),
                    "leases".into(),
                )),
                json_headers(),
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            )
            .await
            .unwrap_or_else(|_| panic!("Lease create must succeed"));
        }

        let prefix =
            crate::keys::group_list_prefix("coordination.k8s.io", "leases", Some("test-ns"));
        let before = store
            .list(&prefix, u7s_store::ListOptions::default())
            .await
            .expect("list before delete");
        assert_eq!(
            before.items.len(),
            2,
            "two Leases must exist before collection delete"
        );

        delete_collection_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "test-ns".into(),
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
                timeout_seconds: None,
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("delete_collection must succeed"));

        let after = store
            .list(&prefix, u7s_store::ListOptions::default())
            .await
            .expect("list after delete");
        assert_eq!(
            after.items.len(),
            0,
            "delete_collection must remove all objects in namespace — \
             lingering objects block namespace finalizer removal and prevent \
             namespace deletion from completing"
        );
    }

    /// POST conflict on a namespaced resource must return 409 with the existing object body.
    ///
    /// KCM's token publisher POSTs kube-root-ca.crt on every namespace reconcile. When the
    /// ConfigMap already exists, KCM reads the 409 body to extract the current resourceVersion
    /// and retries as a PUT. Without the existing object in the body, KCM gets resourceVersion=0
    /// and loops forever between AlreadyExists and revision-mismatch errors.
    #[tokio::test]
    async fn post_conflict_namespaced_returns_existing_object_with_resource_version() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "kube-root-ca.crt", "namespace": "default" },
            "data": { "ca.crt": "CERT" }
        });
        let body = bytes::Bytes::from(serde_json::to_vec(&cm).unwrap());

        let first = create_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "configmaps".into(),
            )),
            json_headers(),
            body.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("first POST must succeed; got: {e:?}"))
        .into_response();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_body = to_bytes(first.into_body(), usize::MAX).await.unwrap();
        let first_obj: serde_json::Value = serde_json::from_slice(&first_body).unwrap();
        let created_rv = first_obj["metadata"]["resourceVersion"]
            .as_str()
            .expect("first POST response must include resourceVersion")
            .to_string();

        let second = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "configmaps".into(),
            )),
            json_headers(),
            body,
        )
        .await
        .unwrap_or_else(|e| panic!("second POST must not hard-error; got: {e:?}"))
        .into_response();

        assert_eq!(
            second.status(),
            StatusCode::CONFLICT,
            "duplicate POST must return 409 Conflict so KCM can extract resourceVersion"
        );

        let conflict_body = to_bytes(second.into_body(), usize::MAX).await.unwrap();
        let conflict_obj: serde_json::Value = serde_json::from_slice(&conflict_body).unwrap();

        let conflict_rv = conflict_obj["metadata"]["resourceVersion"]
            .as_str()
            .expect("409 body must include metadata.resourceVersion so KCM can retry as PUT");

        assert_eq!(
            conflict_rv, created_rv,
            "409 body resourceVersion must match the version assigned at creation — \
             KCM uses this to form the subsequent PUT and breaks the conflict loop"
        );
    }

    /// POST conflict on a cluster-scoped resource must return 409 with the existing object body.
    ///
    /// Same as the namespaced case: the 409 body must contain the existing object so callers
    /// can extract resourceVersion for a follow-up PUT.
    #[tokio::test]
    async fn post_conflict_cluster_scoped_returns_existing_object_with_resource_version() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let sc = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": { "name": "standard" },
            "provisioner": "kubernetes.io/no-provisioner",
            "volumeBindingMode": "WaitForFirstConsumer"
        });
        let body = bytes::Bytes::from(serde_json::to_vec(&sc).unwrap());

        let first = create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "storageclasses".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "test".into(),
                uid: String::new(),
                groups: vec![],
            }),
            json_headers(),
            body.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("first POST must succeed; got: {e:?}"))
        .into_response();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_body = to_bytes(first.into_body(), usize::MAX).await.unwrap();
        let first_obj: serde_json::Value = serde_json::from_slice(&first_body).unwrap();
        let created_rv = first_obj["metadata"]["resourceVersion"]
            .as_str()
            .expect("first POST response must include resourceVersion")
            .to_string();

        let second = create_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "storageclasses".into(),
            )),
            Extension(crate::auth::UserInfo {
                username: "test".into(),
                uid: String::new(),
                groups: vec![],
            }),
            json_headers(),
            body,
        )
        .await
        .unwrap_or_else(|e| panic!("second POST must not hard-error; got: {e:?}"))
        .into_response();

        assert_eq!(
            second.status(),
            StatusCode::CONFLICT,
            "duplicate cluster-scoped POST must return 409 Conflict"
        );

        let conflict_body = to_bytes(second.into_body(), usize::MAX).await.unwrap();
        let conflict_obj: serde_json::Value = serde_json::from_slice(&conflict_body).unwrap();

        let conflict_rv = conflict_obj["metadata"]["resourceVersion"]
            .as_str()
            .expect("409 body must include metadata.resourceVersion");

        assert_eq!(
            conflict_rv, created_rv,
            "409 body resourceVersion must match the version assigned at creation"
        );
    }

    /// POST create handlers must always return a non-empty metadata.uid even when the
    /// client supplies uid:"" (empty string). KCM's token controller parses the UID as a
    /// typed field; an empty UID causes it to log an error and skip the ServiceAccount,
    /// which means the SA never gets a token and workloads in that namespace cannot
    /// authenticate with the API server.
    #[tokio::test]
    async fn create_namespaced_resource_always_sets_non_empty_uid() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let sa = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "default",
                "namespace": "default",
                "uid": ""
            }
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "serviceaccounts".to_string(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&sa).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("POST ServiceAccount must succeed; got: {e:?}"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::CREATED);

        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let uid = v["metadata"]["uid"].as_str().unwrap_or("");
        assert!(
            !uid.is_empty(),
            "POST response must contain a non-empty metadata.uid; \
             KCM token controller rejects ServiceAccounts with empty uid"
        );
        assert!(
            uuid::Uuid::parse_str(uid).is_ok(),
            "metadata.uid must be a valid UUID; got: {uid}"
        );
    }

    /// Regression test (mayor-2cwk): patching a ConfigMap must emit a MODIFIED watch event
    /// with the updated data (missing the deleted key).
    ///
    /// Symptom: after patching a ConfigMap to remove a key, the kubelet's projected volume
    /// syncer did not update the mounted file.  The root cause hypothesis was that PATCH
    /// mutations do not emit a MODIFIED watch event.  This test verifies the full chain:
    /// create → ADDED event in ring buffer, merge-patch removing a key → MODIFIED event
    /// in ring buffer, subscribe from rv=0 → both events replayed, MODIFIED has key absent.
    ///
    /// If do_patch ever stops calling store.put() (which broadcasts the InternalEvent),
    /// or if store.put() stops emitting the Modified WatchEvent, this test will fail —
    /// no MODIFIED event will appear in the stream.
    ///
    /// Test structure: events are pre-seeded into the ring buffer BEFORE opening the watch
    /// so replay is synchronous.  The state is consumed (not cloned) into watch_generic so
    /// the broadcast channel closes when the watch is done, terminating the stream body.
    #[tokio::test]
    async fn configmap_patch_emits_modified_watch_event_with_deleted_key_absent() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Build a temporary state just for create+patch; consumed before watch.
        {
            let tmp_state = crate::state::AppState::new(
                Arc::clone(&store),
                None,
                None,
                std::collections::HashMap::new(),
                "https://localhost:6443".into(),
            );

            // 1. Create a ConfigMap with two data keys.
            let cm = serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "name": "app-config", "namespace": "default" },
                "data": {
                    "key-to-keep": "value-a",
                    "key-to-delete": "value-b"
                }
            });
            create_namespaced_resource(
                axum::extract::State(tmp_state.clone()),
                axum::extract::Path((
                    "".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "configmaps".to_string(),
                )),
                json_headers(),
                bytes::Bytes::from(serde_json::to_vec(&cm).unwrap()),
            )
            .await
            .unwrap_or_else(|_| panic!("ConfigMap create must succeed"));

            // 2. Patch the ConfigMap: set key-to-delete to null (JSON merge-patch removes it).
            let patch = serde_json::json!({"data": {"key-to-delete": null}});
            let mut mp_headers = axum::http::HeaderMap::new();
            mp_headers.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/merge-patch+json"),
            );
            let _ = patch_namespaced_resource(
                axum::extract::State(tmp_state),
                axum::extract::Path((
                    "".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "configmaps".to_string(),
                    "app-config".to_string(),
                )),
                axum::extract::Query(PatchQuery::default()),
                mp_headers,
                bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
            )
            .await
            .unwrap_or_else(|_| panic!("ConfigMap merge-patch must succeed"))
            .into_response();
            // tmp_state is dropped here; the store Arc count goes back down to 1 (only `store`).
        }

        // 3. Build watch state consuming the store Arc so the broadcast channel closes
        //    when watch_generic drops its state — allowing to_bytes to complete.
        let watch_state = crate::state::AppState::new(
            store, // consumed: no other Arc refs after this
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // 4. Subscribe a WATCH from rv=0 so the ring buffer replays ADDED and MODIFIED.
        //    watch_state is consumed (not cloned), so when the stream generator drops it
        //    the broadcast channel closes and the Body terminates.
        let resp = super::watch_generic(
            watch_state,
            super::WatchConfig {
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
                timeout_seconds: None,
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        // 5. Collect the body (terminates when broadcast channel closes).
        let body_bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        let text = std::str::from_utf8(&body_bytes).unwrap_or("");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        // 6. There must be exactly one MODIFIED event in the stream.
        let modified_events: Vec<&serde_json::Value> =
            lines.iter().filter(|v| v["type"] == "MODIFIED").collect();
        assert_eq!(
            modified_events.len(),
            1,
            "PATCH must emit exactly one MODIFIED watch event so the kubelet projected \
             volume syncer can update mounted ConfigMap files; got lines: {:?}",
            lines
        );

        let modified_obj = &modified_events[0]["object"];

        // 7. The MODIFIED event must not contain key-to-delete (it was removed by the patch).
        assert!(
            modified_obj["data"].get("key-to-delete").is_none()
                || modified_obj["data"]["key-to-delete"].is_null(),
            "MODIFIED event must reflect the deletion of key-to-delete; \
             if this key is present, the kubelet will not remove the file from the volume mount. \
             Got data: {:?}",
            modified_obj["data"]
        );

        // 8. The MODIFIED event must still carry key-to-keep.
        assert_eq!(
            modified_obj["data"]["key-to-keep"].as_str().unwrap_or(""),
            "value-a",
            "MODIFIED event must preserve key-to-keep — only the patched key must change"
        );
    }

    /// Same guarantee for cluster-scoped POST: metadata.uid must be non-empty
    /// even if the client supplies uid:"".
    #[tokio::test]
    async fn create_resource_always_sets_non_empty_uid() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "uid-test-node",
                "uid": ""
            }
        });

        let result = create_resource(
            axum::extract::State(state),
            axum::extract::Path(("".to_string(), "v1".to_string(), "nodes".to_string())),
            Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&node).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("POST Node must succeed; got: {e:?}"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::CREATED);

        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let uid = v["metadata"]["uid"].as_str().unwrap_or("");
        assert!(
            !uid.is_empty(),
            "cluster-scoped POST response must contain a non-empty metadata.uid"
        );
        assert!(
            uuid::Uuid::parse_str(uid).is_ok(),
            "metadata.uid must be a valid UUID; got: {uid}"
        );
    }

    /// Regression test (mayor-bdsj): GET on a stored namespaced object must return
    /// metadata.resourceVersion that is non-empty and non-zero.
    ///
    /// Why this matters: KCM's root CA publisher controller reads kube-root-ca.crt
    /// via GET, then issues a PUT with the resourceVersion it got back as a
    /// precondition. If GET returns resourceVersion="" or "0", the PUT fails with
    /// "resource version mismatch (expected N, current 0)" and the controller loops
    /// forever.  The store's put_sync stamps every write with a global counter (>=1)
    /// via stamp_resource_version; if that stamping were removed or zeroed, this
    /// test would fail.
    #[tokio::test]
    async fn get_namespaced_resource_returns_non_zero_resource_version() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "kube-root-ca.crt", "namespace": "default" },
            "data": { "ca.crt": "CERT-DATA" }
        });

        // Create the ConfigMap — store assigns revision >= 1 and stamps it
        create_namespaced_resource(
            State(state.clone()),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "configmaps".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&cm).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("ConfigMap POST must succeed; got: {e:?}"));

        // GET it back and verify resourceVersion is propagated from the store
        let get_resp = get_namespaced_resource(
            State(state),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "configmaps".into(),
                "kube-root-ca.crt".into(),
            )),
        )
        .await
        .unwrap_or_else(|e| panic!("ConfigMap GET must succeed; got: {e:?}"))
        .into_response();

        let body = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let rv = v["metadata"]["resourceVersion"].as_str().unwrap_or("");
        assert!(
            !rv.is_empty(),
            "GET response must include metadata.resourceVersion — an absent field causes KCM's \
             root CA publisher to treat resourceVersion as 0 and loop forever on PUT \
             precondition failures (mayor-bdsj)"
        );
        assert_ne!(
            rv, "0",
            "GET response must not return metadata.resourceVersion=\"0\" — store must stamp the \
             actual revision (>= 1); returning 0 makes KCM's PUT fail with revision mismatch \
             (mayor-bdsj: root CA publisher loops on 'expected N, current 0')"
        );
        let rv_int: u64 = rv.parse().unwrap_or_else(|_| {
            panic!("metadata.resourceVersion must be a decimal integer string; got: {rv:?}")
        });
        assert!(
            rv_int > 0,
            "metadata.resourceVersion must be > 0 after first write; got: {rv_int} \
             (mayor-bdsj: store counter starts at 1)"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: selector defaulting for Deployment/RS/StatefulSet (mayor-2fja)
    // ---------------------------------------------------------------------------

    /// POST a Deployment without spec.selector returns 201 and spec.selector is
    /// populated from spec.template.metadata.labels.
    ///
    /// Conformance workload tests create Deployments without an explicit selector,
    /// relying on the apiserver to default it from template labels (matching real
    /// kube-apiserver behavior). Without this fix the server returns 400 with
    /// "spec.selector is required", blocking all Deployment workload tests.
    ///
    /// This test fails if the selector-defaulting code in default_deployment is removed.
    #[tokio::test]
    async fn deployment_without_selector_is_accepted_and_selector_defaulted() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let deployment = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "my-deploy", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "my-deploy", "env": "test" } },
                    "spec": { "containers": [{ "name": "c", "image": "nginx" }] }
                }
            }
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&deployment).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Deployment POST without selector must return 201, got: {e:?}"))
        .into_response();

        assert_eq!(
            result.status(),
            axum::http::StatusCode::CREATED,
            "Deployment without spec.selector must be accepted (201) — spec.selector \
             must be defaulted from template labels, not rejected"
        );

        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "my-deploy", "env": "test" } }),
            "spec.selector must be populated from spec.template.metadata.labels — \
             a nil selector panics the KCM deployment-controller"
        );
    }

    /// POST a ReplicaSet without spec.selector returns 201 and spec.selector is
    /// populated from spec.template.metadata.labels.
    ///
    /// Conformance workload tests create ReplicaSets without spec.selector. Without
    /// this fix the server returns 400 "spec.selector is required", blocking RS tests.
    ///
    /// This test fails if the selector-defaulting code in default_replicaset is removed.
    #[tokio::test]
    async fn replicaset_without_selector_is_accepted_and_selector_defaulted() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let rs = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "my-rs", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "my-rs" } },
                    "spec": { "containers": [{ "name": "c", "image": "nginx" }] }
                }
            }
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "replicasets".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&rs).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("ReplicaSet POST without selector must return 201, got: {e:?}"))
        .into_response();

        assert_eq!(
            result.status(),
            axum::http::StatusCode::CREATED,
            "ReplicaSet without spec.selector must be accepted (201) — spec.selector \
             must be defaulted from template labels, not rejected"
        );

        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "my-rs" } }),
            "spec.selector must be populated from spec.template.metadata.labels"
        );
    }

    /// POST a StatefulSet without spec.selector returns 201 and spec.selector is
    /// populated from spec.template.metadata.labels.
    ///
    /// Conformance workload tests create StatefulSets without spec.selector. Without
    /// this fix the server returns 400 "spec.selector is required", blocking SS tests.
    ///
    /// This test fails if the selector-defaulting code in default_statefulset is removed.
    #[tokio::test]
    async fn statefulset_without_selector_is_accepted_and_selector_defaulted() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let ss = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "my-ss", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "my-ss" } },
                    "spec": { "containers": [{ "name": "c", "image": "nginx" }] }
                }
            }
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "statefulsets".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&ss).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("StatefulSet POST without selector must return 201, got: {e:?}"))
        .into_response();

        assert_eq!(
            result.status(),
            axum::http::StatusCode::CREATED,
            "StatefulSet without spec.selector must be accepted (201) — spec.selector \
             must be defaulted from template labels, not rejected"
        );

        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "my-ss" } }),
            "spec.selector must be populated from spec.template.metadata.labels"
        );
    }

    // -- expired continue token returns 410 Gone (mayor-snp5) --

    /// Build a continue token payload signed with the given 32-byte key and the given
    /// issued-at timestamp.  Mirrors the format of `encode_continue` in generic.rs so
    /// we can forge a token with a controlled (expired) `t` field without sleeping.
    fn build_signed_token(store_key: &str, signing_key: &[u8; 32], issued_at: u64) -> String {
        use base64::Engine;
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload = serde_json::json!({"k": store_key, "t": issued_at}).to_string();
        let payload_b64 = b64.encode(payload.as_bytes());
        let mut mac = <Hmac<Sha256>>::new_from_slice(signing_key).expect("HMAC accepts any key");
        mac.update(payload.as_bytes());
        let sig = mac.finalize().into_bytes();
        format!("{payload_b64}.{}", b64.encode(sig))
    }

    /// A list request that carries an expired continue token must return HTTP 410 Gone
    /// with Status.reason == "Expired", not HTTP 200 with items.
    ///
    /// Without this property the Kubernetes chunking conformance test accumulates
    /// 40 (first page) + 400 (full re-list) = 440 items instead of restarting
    /// cleanly from scratch after the server signals expiry via 410.
    ///
    /// This test exercises the full handler path (list_namespaced_resource) so that
    /// it would catch any regression in the `?` propagation of the decode_continue error,
    /// not just the decode_continue unit in isolation.
    #[tokio::test]
    async fn list_namespaced_resource_expired_continue_token_returns_410() {
        use axum::extract::{Path, Query, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        // Fixed signing key so we can forge a token with a controlled `t` field.
        let signing_key: [u8; 32] = *b"test-signing-key-32-bytes-padded";
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: None,
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            continue_token_key: Some(signing_key),
        });

        // Forge a properly signed token whose `t` (issued-at) is Unix epoch 0 — always expired.
        let expired_token = build_signed_token(
            "/registry/podtemplates/default/pt-0",
            &signing_key,
            0, // Unix epoch — definitely older than CONTINUE_TOKEN_TTL_SECS (60s)
        );

        let result = list_namespaced_resource(
            State(state),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "podtemplates".into(),
            )),
            Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: None,
                limit: Some(40),
                continue_token: Some(expired_token),
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            }),
            axum::http::HeaderMap::new(),
            Extension(crate::auth::UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await;

        let err = result.expect_err(
            "list with expired continue token must return Err(StatusError), not Ok(200 with items); \
             a 200 response causes client-go to append items across pages, yielding wrong counts",
        );
        assert_eq!(
            err.0,
            axum::http::StatusCode::GONE,
            "expired continue token must return HTTP 410 Gone so client-go knows \
             to restart the list from the beginning (Kubernetes chunking contract)"
        );
        assert_eq!(
            err.1.reason, "Expired",
            "Status.reason must be 'Expired' so client-go's pagination handler \
             recognises the signal and re-issues a fresh list without a continue token"
        );
    }

    /// A list request with an invalid (garbage) continue token whose HMAC signature
    /// does not match must also return HTTP 410 Gone with Status.reason == "Expired".
    ///
    /// The Kubernetes spec treats any unverifiable continue token as expired, so
    /// client-go retries from the beginning rather than propagating a hard error.
    #[tokio::test]
    async fn list_resource_invalid_continue_token_returns_410() {
        use axum::extract::{Path, Query, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let signing_key: [u8; 32] = *b"test-signing-key-32-bytes-padded";
        let other_key: [u8; 32] = *b"different-key-32-bytes-padding!x";
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: None,
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            continue_token_key: Some(signing_key),
        });

        // Token signed with a DIFFERENT key — HMAC verification fails.
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let wrong_sig_token = build_signed_token(
            "/registry/podtemplates/default/pt-0",
            &other_key, // signed with wrong key
            now,
        );

        let result = list_resource(
            State(state),
            Path(("".into(), "v1".into(), "podtemplates".into())),
            Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: None,
                limit: Some(40),
                continue_token: Some(wrong_sig_token),
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            }),
            axum::http::HeaderMap::new(),
            Extension(crate::auth::UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await;

        let err = result.expect_err(
            "list with wrong-signature continue token must return Err, not Ok; \
             accepting a forged token could allow cross-namespace pagination attacks",
        );
        assert_eq!(
            err.0,
            axum::http::StatusCode::GONE,
            "a token whose HMAC does not match must return 410 Gone (treated as expired) \
             so client-go restarts the list cleanly"
        );
        assert_eq!(
            err.1.reason, "Expired",
            "Status.reason must be 'Expired' for invalid-signature tokens"
        );
    }
}
