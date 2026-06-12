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
    keys::{cluster_object_key, group_list_prefix, group_object_key},
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
    apply_field_validation, apply_json_patch, detect_patch_type, inject_managed_fields,
    strip_managed_fields, CreateQuery, PatchQuery, PatchType, ReplaceQuery,
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
        let initial = fetch_initial_events(
            &state,
            &prefix,
            query.send_initial_events == Some(true),
            &group,
            &plural,
        )
        .await?;
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
    Query(create_query): Query<CreateQuery>,
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

    // Field validation: detect unknown fields per ?fieldValidation= query param.
    let warn_header = apply_field_validation(
        &obj.body,
        create_query.field_validation.as_deref(),
        &group,
        &plural,
    )?;

    // Escalation prevention: before persisting a ClusterRoleBinding, verify the
    // caller already holds all rules of the referenced ClusterRole. This prevents
    // users from granting themselves permissions they don't currently have.
    check_crb_escalation(&plural, &group, &user, &obj.body, &state)?;

    let name = resolve_name(&mut obj)?;
    stamp_metadata(&mut obj);
    super::defaults::apply_defaults(&group, &plural, &mut obj.body);
    super::defaults::validate_resource(&group, &plural, &obj.body)
        .map_err(Status::unprocessable_entity)?;

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
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
    obj.body = run_mutating_webhooks(&state, obj.body, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, &admission_ctx).await?;

    // Dry-run: validation and admission passed; return the would-be created object without persisting.
    if create_query.is_dry_run() {
        inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
        let mut resp = (StatusCode::CREATED, Json(obj.body)).into_response();
        if let Some(hv) = warn_header {
            resp.headers_mut().insert(axum::http::header::WARNING, hv);
        }
        return Ok(resp);
    }

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
    write_vap_status(&*state.store, &group, &plural, &key, &mut obj.body, new_rv).await;
    inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
    let mut resp = (StatusCode::CREATED, Json(obj.body)).into_response();
    if let Some(hv) = warn_header {
        resp.headers_mut().insert(axum::http::header::WARNING, hv);
    }
    Ok(resp)
}

pub async fn replace_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Query(replace_query): Query<ReplaceQuery>,
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

    // Read the stored status so we can restore it after the PUT — controllers write
    // status via /status; a full PUT on the main endpoint must not wipe it out.
    let stored_status = if meta.has_status_subresource {
        let key = group_object_key(&group, &plural, None, &name);
        state
            .store
            .get(&key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .and_then(|stored| serde_json::from_slice::<serde_json::Value>(&stored.value).ok())
            .map(|v| v["status"].clone())
    } else {
        None
    };

    super::defaults::apply_defaults(&group, &plural, &mut obj.body);
    super::defaults::validate_resource(&group, &plural, &obj.body)
        .map_err(Status::unprocessable_entity)?;

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: None,
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

    // Restore the stored status: controllers write status via /status; a full PUT on
    // the main endpoint must preserve whatever the controller last wrote.
    if meta.has_status_subresource {
        match stored_status {
            Some(ref s) if !s.is_null() => {
                obj.body["status"] = s.clone();
            }
            _ => {
                obj.body.as_object_mut().map(|m| m.remove("status"));
            }
        }
    }

    // Dry-run: validation and admission passed; return the would-be result without persisting.
    if replace_query.is_dry_run() {
        return Ok(Json(obj.body).into_response());
    }

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
    write_vap_status(&*state.store, &group, &plural, &key, &mut obj.body, new_rv).await;
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
    /// When true, run all validation but skip the store write.
    /// Set when `?dryRun=All` is present in the request query string.
    pub dry_run: bool,
    /// Authenticated user info for the request. Used by VAP CEL expressions
    /// that reference `request.userInfo.*`.
    pub user_info: Option<serde_json::Value>,
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
        dry_run,
        user_info,
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
            .map_err(Status::unprocessable_entity)?;
        if dry_run {
            // Dry-run: validation passed; return the would-be created object without persisting.
            if let Some(fm) = field_manager {
                let api_ver = obj.body["apiVersion"].as_str().unwrap_or("").to_string();
                let now = crate::util::utc_now_rfc3339();
                inject_managed_fields(&mut obj.body, fm, &api_ver, &now);
            }
            return Ok((StatusCode::CREATED, Json(obj.body)).into_response());
        }
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
                    .map_err(Status::unprocessable_entity)?;
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

    // Immutability check: if the stored Secret or ConfigMap has `immutable: true`,
    // reject any patch attempt.  Real kube-apiserver returns 422 "Invalid".
    if group.is_empty()
        && (plural == "secrets" || plural == "configmaps")
        && current.body["immutable"] == serde_json::Value::Bool(true)
    {
        return Err(Status::unprocessable_entity(format!(
            "{plural}/{name} is immutable and cannot be updated"
        )));
    }

    // Capture spec before patch for generation tracking on workload resources.
    let spec_before_patch = if super::defaults::is_workload_resource(group, plural) {
        Some(current.body["spec"].clone())
    } else {
        None
    };

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
        .map_err(Status::unprocessable_entity)?;

    if let Some(ref spec_before) = spec_before_patch {
        super::defaults::increment_workload_generation_if_spec_changed(
            &mut current.body,
            spec_before,
        );
    }

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
        user_info,
        dry_run: false,
    };
    current.body = run_mutating_webhooks(state, current.body, &admission_ctx).await?;
    run_validating_webhooks(state, &current.body, &admission_ctx).await?;

    // A user PATCH on an Endpoints object signals that the endpoints are now user-managed.
    // Clear the annotation the KCM endpoints-controller stamps; the mirroring controller
    // skips any Endpoints that carry it, blocking EndpointSliceMirroring.
    if plural == "endpoints" {
        let mut patch_meta: ObjectMeta =
            serde_json::from_value(current.body["metadata"].clone()).unwrap_or_default();
        if let Some(ref mut annotations) = patch_meta.annotations {
            annotations.remove("endpoints.kubernetes.io/last-change-trigger-time");
        }
        current.body["metadata"] =
            serde_json::to_value(patch_meta).map_err(|e| Status::internal(e.to_string()))?;
    }

    // Dry-run: validation and admission passed; return the would-be result without persisting.
    if dry_run {
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
    Extension(user): Extension<UserInfo>,
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
            dry_run: patch_query.is_dry_run(),
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
            })),
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
        let initial = fetch_initial_events(
            &state,
            &prefix,
            query.send_initial_events == Some(true),
            &group,
            &plural,
        )
        .await?;
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
    Query(create_query): Query<CreateQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    // Reject object creation in a Terminating namespace — matches kube-apiserver behaviour:
    // 403 Forbidden: unable to create new content in namespace <ns> because it is being terminated
    {
        let ns_key = cluster_object_key("namespaces", &ns);
        if let Ok(Some(stored)) = state.store.get(&ns_key).await {
            if let Ok(ns_obj) = serde_json::from_slice::<serde_json::Value>(&stored.value) {
                if ns_obj["status"]["phase"].as_str() == Some("Terminating") {
                    return Err(Status::forbidden(format!(
                        "unable to create new content in namespace {ns} because it is being terminated"
                    )));
                }
            }
        }
    }
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

    // Field validation: detect unknown fields per ?fieldValidation= query param.
    let warn_header = apply_field_validation(
        &obj.body,
        create_query.field_validation.as_deref(),
        &group,
        &plural,
    )?;

    let name = resolve_name(&mut obj)?;

    // Capture RS revision propagation info BEFORE ns_meta processing drops ownerReferences.
    // ObjectMeta serde drops unknown fields (including ownerReferences), so we must extract
    // what we need from obj.body before it's overwritten.
    let rs_revision_info: Option<(String, serde_json::Value)> =
        if group == "apps" && plural == "replicasets" {
            let revision = obj.body["metadata"]["annotations"]["deployment.kubernetes.io/revision"]
                .as_str()
                .filter(|r| !r.is_empty())
                .map(|r| r.to_string());
            let owner_refs = obj.body["metadata"]["ownerReferences"].clone();
            revision.map(|r| (r, owner_refs))
        } else {
            None
        };

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
    super::defaults::validate_resource(&group, &plural, &obj.body)
        .map_err(Status::unprocessable_entity)?;

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: Some(&ns),
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

    // LimitRange: inject defaults then validate min/max bounds (pods only).
    obj.body = limit_range::apply_limit_ranges(&state, obj.body, &ns, &plural).await?;

    // ResourceQuota: ensure object count does not exceed hard limits.
    quota::check_resource_quota(&state, &ns, &group, &plural).await?;

    // Dry-run: validation and admission passed; return the would-be created object without persisting.
    if create_query.is_dry_run() {
        inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
        let mut resp = (StatusCode::CREATED, Json(obj.body)).into_response();
        if let Some(hv) = warn_header {
            resp.headers_mut().insert(axum::http::header::WARNING, hv);
        }
        return Ok(resp);
    }

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
    inject_type_meta(&mut obj.body, &group, &version, &meta.kind);

    // KCM 1.36 sets deployment.kubernetes.io/revision on the ReplicaSet when creating it,
    // but does NOT subsequently PATCH the Deployment with the same annotation (it only does
    // so in updateNewReplicaSetAnnotations, which only runs when the RS revision CHANGES,
    // but since the RS was just created with revision=1, it never changes on re-sync).
    // Fix: when an RS is created with this annotation and an ownerReference to a Deployment,
    // propagate the annotation to the Deployment so KCM sees it on the next LIST/GET.
    //
    // NOTE: the ownerReferences captured before ns_meta processing are passed here because
    // the ns_meta round-trip (ObjectMeta serde) drops ownerReferences from obj.body.
    if group == "apps" && plural == "replicasets" {
        propagate_rs_revision_to_deployment(&state, &rs_revision_info, &ns).await;
    }

    let mut resp = (StatusCode::CREATED, Json(obj.body)).into_response();
    if let Some(hv) = warn_header {
        resp.headers_mut().insert(axum::http::header::WARNING, hv);
    }
    Ok(resp)
}

/// When KCM creates a ReplicaSet with `deployment.kubernetes.io/revision` annotation
/// and an ownerReference to a Deployment (controller=true), propagate that annotation
/// to the owning Deployment.
///
/// KCM's `updateNewReplicaSetAnnotations` only patches the Deployment revision when
/// `SetNewReplicaSetAnnotations` returns true (i.e., when the RS revision *changes*).
/// Since the RS is created with the annotation already set, KCM never detects a change
/// and therefore never patches the Deployment.  Without this propagation the Deployment's
/// `deployment.kubernetes.io/revision` stays null forever, breaking AdmissionWebhook
/// conformance tests that assert the annotation is present.
///
/// `rs_revision_info` is `Some((revision, owner_refs_json))` extracted BEFORE the
/// ns_meta ObjectMeta round-trip which drops ownerReferences from the body.
///
/// Errors are logged and silently swallowed — the RS creation already succeeded and
/// the Deployment annotation is a best-effort annotation set by the controller plane.
async fn propagate_rs_revision_to_deployment<S: Store>(
    state: &AppState<S>,
    rs_revision_info: &Option<(String, serde_json::Value)>,
    ns: &str,
) {
    let (revision, owner_refs_json) = match rs_revision_info {
        Some(info) => (&info.0, &info.1),
        None => return,
    };

    // Find the ownerReference to a Deployment with controller=true.
    let owner_refs = match owner_refs_json.as_array() {
        Some(refs) => refs,
        None => return,
    };
    let deploy_name = owner_refs
        .iter()
        .find(|r| {
            r["kind"].as_str() == Some("Deployment")
                && r["controller"].as_bool() == Some(true)
                && r["apiVersion"].as_str().map(|v| v.starts_with("apps/")) == Some(true)
        })
        .and_then(|r| r["name"].as_str())
        .map(|s| s.to_string());
    let deploy_name = match deploy_name {
        Some(n) => n,
        None => return, // no controlling Deployment ownerRef
    };

    // Load the Deployment from the store.
    let deploy_key = group_object_key("apps", "deployments", Some(ns), &deploy_name);
    let stored = match state.store.get(&deploy_key).await {
        Ok(Some(s)) => s,
        _ => return, // Deployment not found or store error
    };
    let mut deploy: serde_json::Value = match serde_json::from_slice(&stored.value) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Only update if the annotation is absent or older.
    let current = deploy["metadata"]["annotations"]["deployment.kubernetes.io/revision"]
        .as_str()
        .unwrap_or("0")
        .parse::<i64>()
        .unwrap_or(0);
    let new_rev = revision.parse::<i64>().unwrap_or(0);
    if new_rev <= current {
        return; // already up-to-date
    }

    // Set the annotation on the Deployment.
    if !deploy["metadata"]["annotations"].is_object() {
        deploy["metadata"]["annotations"] = serde_json::json!({});
    }
    deploy["metadata"]["annotations"]["deployment.kubernetes.io/revision"] =
        serde_json::Value::String(revision.clone());

    // Store the updated Deployment with CAS to avoid clobbering concurrent spec changes.
    // If a concurrent writer updated the Deployment between our get and put, this put
    // is skipped — that's fine: the annotation will be set on the next RS creation or
    // when the Deployment is next written.
    let expected_rv = stored.revision;
    let deploy_bytes = bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap_or_default());
    if let Err(e) = state
        .store
        .put(&deploy_key, deploy_bytes, Some(expected_rv))
        .await
    {
        tracing::debug!(
            deployment = %deploy_name,
            ns = %ns,
            "skipping RS revision annotation propagation (concurrent update): {e}"
        );
    }
}

pub async fn replace_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    Query(replace_query): Query<ReplaceQuery>,
    Extension(user): Extension<UserInfo>,
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

    // Stamp namespace from the URL into the body. If the client omits metadata.namespace
    // in the PUT body, the stored object would have no namespace. A cluster-wide Watch
    // (e.g. the KCM EndpointSlice mirroring controller watching /api/v1/endpoints) would
    // then return the object with a blank namespace, causing the informer to build a key
    // with no namespace prefix and all DELETE operations to target the wrong URL path.
    obj.body["metadata"]["namespace"] = serde_json::Value::String(ns.clone());

    // Strip status from the incoming body on the main endpoint when the resource
    // has a dedicated status subresource.
    if meta.has_status_subresource {
        if let Some(map) = obj.body.as_object_mut() {
            map.remove("status");
        }
    }

    let expected_revision = parse_resource_version(obj.resource_version())?;

    let key = group_object_key(&group, &plural, Some(&ns), &name);

    // Read the stored object once: used for (a) immutability enforcement on
    // Secrets/ConfigMaps, (b) generation tracking on workload resources, and
    // (c) status restoration when the resource has a dedicated status subresource.
    let needs_stored_read = super::defaults::is_workload_resource(&group, &plural)
        || meta.has_status_subresource
        || (group.is_empty() && (plural == "secrets" || plural == "configmaps"));
    let (spec_before_replace, stored_status) = if needs_stored_read {
        let parsed = state
            .store
            .get(&key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .and_then(|stored| serde_json::from_slice::<serde_json::Value>(&stored.value).ok());

        // Immutability check: if the stored Secret or ConfigMap has `immutable: true`,
        // reject any update that modifies data/binaryData/stringData or clears the
        // immutable flag.  Real kube-apiserver returns 422 "Invalid" in this case.
        if group.is_empty() && (plural == "secrets" || plural == "configmaps") {
            if let Some(ref stored) = parsed {
                if stored["immutable"] == serde_json::Value::Bool(true) {
                    let new_immutable = &obj.body["immutable"];
                    let immutable_cleared =
                        new_immutable == &serde_json::Value::Bool(false) || new_immutable.is_null();
                    let data_changed = obj.body["data"] != stored["data"];
                    let binary_data_changed = obj.body["binaryData"] != stored["binaryData"];
                    let string_data_changed = obj.body["stringData"] != stored["stringData"];
                    if immutable_cleared
                        || data_changed
                        || binary_data_changed
                        || string_data_changed
                    {
                        return Err(Status::unprocessable_entity(format!(
                            "{plural}/{name} is immutable and cannot be updated"
                        )));
                    }
                }
            }
        }

        let spec = if super::defaults::is_workload_resource(&group, &plural) {
            parsed.as_ref().map(|v| v["spec"].clone())
        } else {
            None
        };
        let status = if meta.has_status_subresource {
            parsed.as_ref().map(|v| v["status"].clone())
        } else {
            None
        };
        (spec, status)
    } else {
        (None, None)
    };

    super::defaults::apply_defaults(&group, &plural, &mut obj.body);
    super::defaults::validate_resource(&group, &plural, &obj.body)
        .map_err(Status::unprocessable_entity)?;

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: Some(&ns),
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

    if let Some(ref spec_before) = spec_before_replace {
        super::defaults::increment_workload_generation_if_spec_changed(&mut obj.body, spec_before);
    }

    // Restore the stored status: controllers write status via /status; a full PUT on
    // the main endpoint must preserve whatever the controller last wrote.
    if meta.has_status_subresource {
        match stored_status {
            Some(ref s) if !s.is_null() => {
                obj.body["status"] = s.clone();
            }
            _ => {
                obj.body.as_object_mut().map(|m| m.remove("status"));
            }
        }
    }

    // A user PUT on an Endpoints object signals that the endpoints are now user-managed,
    // not service-controller-managed.  Clear the annotation the KCM endpoints-controller
    // stamps on objects it owns; the mirroring controller skips any Endpoints that carry
    // this annotation, so leaving it causes EndpointSliceMirroring to produce no slice.
    if plural == "endpoints" {
        let mut put_meta: ObjectMeta =
            serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
        if let Some(ref mut annotations) = put_meta.annotations {
            annotations.remove("endpoints.kubernetes.io/last-change-trigger-time");
        }
        obj.body["metadata"] =
            serde_json::to_value(put_meta).map_err(|e| Status::internal(e.to_string()))?;
    }

    // Dry-run: validation and admission passed; return the would-be result without persisting.
    if replace_query.is_dry_run() {
        return Ok(Json(obj.body).into_response());
    }

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

    // Cascade-delete pods owned by a deleted DaemonSet.
    // When a DaemonSet is deleted, pods with ownerReferences pointing to it must be
    // deleted immediately — otherwise they remain Running for the full pod GC timeout
    // (10+ minutes), blocking AfterEach cleanup in conformance tests.
    if group == "apps" && plural == "daemonsets" {
        let ds_uid = obj.body["metadata"]["uid"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if !ds_uid.is_empty() {
            delete_pods_owned_by(&state, &ns, &ds_uid, "DaemonSet").await;
        }
    }

    // Cascade-delete ReplicaSets owned by a deleted Deployment.
    // Without this, orphaned ReplicaSets continue creating pods indefinitely —
    // observed: smoke-test-mutate RS (desired: 1337) created 14000+ pods after
    // its Deployment was deleted.
    if group == "apps" && plural == "deployments" {
        let deploy_uid = obj.body["metadata"]["uid"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if !deploy_uid.is_empty() {
            delete_replicasets_owned_by(&state, &ns, &deploy_uid).await;
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

pub async fn patch_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    Query(patch_query): Query<PatchQuery>,
    Extension(user): Extension<UserInfo>,
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
            dry_run: patch_query.is_dry_run(),
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
            })),
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Collection patch handlers  (PATCH on collection endpoint)
// ---------------------------------------------------------------------------

/// PATCH /apis/{group}/{version}/namespaces/{ns}/{resource}?labelSelector=...
///
/// Applies the same patch body to every matched resource in the namespace.
/// The conformance test "should list, patch and delete a collection of StatefulSets"
/// uses this endpoint to batch-update a StatefulSet's image via labelSelector.
pub async fn patch_collection_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    Query(query): Query<CollectionQuery>,
    Query(patch_query): Query<PatchQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    let meta = lookup(&state, &group, &version, &plural)
        .cloned()
        .map_err(|_| Status::not_found(&plural, &format!("{group}/{version}/{plural}")))?;

    let prefix = group_list_prefix(&group, &plural, Some(&ns));
    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(parse_label_selector)
        .transpose()?;

    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");
    let user_info = Some(serde_json::json!({
        "username": user.username,
        "uid": user.uid,
        "groups": user.groups,
    }));

    let mut patched_items: Vec<serde_json::Value> = Vec::new();

    for obj in resp.items {
        let parsed = match serde_json::from_slice::<serde_json::Value>(&obj.value) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(ref pairs) = label_pairs {
            let kept = apply_label_selector(vec![parsed.clone()], pairs);
            if kept.is_empty() {
                continue;
            }
        }

        let name = match parsed["metadata"]["name"].as_str() {
            Some(n) => n.to_string(),
            None => continue,
        };

        let key = group_object_key(&group, &plural, Some(&ns), &name);
        let result = do_patch(
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
                body: body.clone(),
                dry_run: patch_query.is_dry_run(),
                user_info: user_info.clone(),
            },
        )
        .await;

        match result {
            Ok(resp) => {
                let resp = resp.into_response();
                let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap_or_default();
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                    patched_items.push(v);
                }
            }
            Err(_) => continue,
        }
    }

    let api_version = if group.is_empty() {
        version.clone()
    } else {
        format!("{}/{}", group, version)
    };
    let list_kind = format!("{}List", meta.kind);
    let body = serde_json::json!({
        "apiVersion": api_version,
        "kind": list_kind,
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": patched_items
    });
    Ok(Json(body).into_response())
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

/// Delete all pods in `namespace` whose `ownerReferences` contain an entry with
/// `kind == owner_kind` and `uid == owner_uid`.
///
/// Called after a DaemonSet hard-delete to cascade-delete owned pods immediately.
/// Without this, DaemonSet pods linger for the full pod GC timeout (10+ minutes),
/// burning AfterEach cleanup in conformance tests (~35 min per full run).
async fn delete_pods_owned_by<S: Store>(
    state: &crate::state::AppState<S>,
    namespace: &str,
    owner_uid: &str,
    owner_kind: &str,
) {
    let prefix = crate::keys::group_list_prefix("", "pods", Some(namespace));
    let resp = match state
        .store
        .list(&prefix, u7s_store::ListOptions::default())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("cascade-delete pods in {namespace}: list failed: {e}");
            return;
        }
    };

    for item in resp.items {
        let pod: serde_json::Value = match serde_json::from_slice(&item.value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let owned = pod["metadata"]["ownerReferences"]
            .as_array()
            .map(|refs| {
                refs.iter().any(|r| {
                    r["uid"].as_str() == Some(owner_uid) && r["kind"].as_str() == Some(owner_kind)
                })
            })
            .unwrap_or(false);
        if !owned {
            continue;
        }
        let pod_name = pod["metadata"]["name"].as_str().unwrap_or("").to_string();
        if pod_name.is_empty() {
            continue;
        }
        let pod_key = crate::keys::group_object_key("", "pods", Some(namespace), &pod_name);
        if let Err(e) = state.store.delete(&pod_key, None).await {
            tracing::warn!("cascade-delete pod {namespace}/{pod_name}: {e}");
        }
    }
}

/// Called after a Deployment hard-delete to cascade-delete owned ReplicaSets immediately.
/// Without this, orphaned ReplicaSets keep their desired-replica count active and continue
/// creating pods indefinitely — observed: RS with desired=1337 created 14000+ pods after
/// its Deployment was deleted.
async fn delete_replicasets_owned_by<S: Store>(
    state: &crate::state::AppState<S>,
    namespace: &str,
    owner_uid: &str,
) {
    let prefix = crate::keys::group_list_prefix("apps", "replicasets", Some(namespace));
    let resp = match state
        .store
        .list(&prefix, u7s_store::ListOptions::default())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("cascade-delete replicasets in {namespace}: list failed: {e}");
            return;
        }
    };

    for item in resp.items {
        let rs: serde_json::Value = match serde_json::from_slice(&item.value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let owned = rs["metadata"]["ownerReferences"]
            .as_array()
            .map(|refs| {
                refs.iter().any(|r| {
                    r["uid"].as_str() == Some(owner_uid) && r["kind"].as_str() == Some("Deployment")
                })
            })
            .unwrap_or(false);
        if !owned {
            continue;
        }
        let rs_name = rs["metadata"]["name"].as_str().unwrap_or("").to_string();
        if rs_name.is_empty() {
            continue;
        }
        let rs_key =
            crate::keys::group_object_key("apps", "replicasets", Some(namespace), &rs_name);
        if let Err(e) = state.store.delete(&rs_key, None).await {
            tracing::warn!("cascade-delete replicaset {namespace}/{rs_name}: {e}");
        }
    }
}

/// Inject `kind` and `apiVersion` into an object response body.
///
/// The Kubernetes API contract requires every response object to include TypeMeta
/// (kind + apiVersion). Clients (kubectl, client-go, conformance tests) assert
/// these fields are non-empty on every create/get/update response. Without this,
/// client-go reports "Object Kind is missing" and the operation fails.
pub(crate) const ADMISSION_GROUP: &str = "admissionregistration.k8s.io";
pub(crate) const VAP_PLURAL: &str = "validatingadmissionpolicies";
pub(crate) const VAPB_PLURAL: &str = "validatingadmissionpolicybindings";

const BUILTIN_GROUPS: &[&str] = &[
    "",
    "apps",
    "batch",
    "extensions",
    "networking.k8s.io",
    "policy",
    "rbac.authorization.k8s.io",
    "storage.k8s.io",
    "autoscaling",
    "authentication.k8s.io",
    "authorization.k8s.io",
    "admissionregistration.k8s.io",
    "apiextensions.k8s.io",
    "apiregistration.k8s.io",
    "coordination.k8s.io",
    "events.k8s.io",
    "scheduling.k8s.io",
    "certificates.k8s.io",
    "discovery.k8s.io",
    "flowcontrol.apiserver.k8s.io",
    "internal.apiserver.k8s.io",
    "node.k8s.io",
];

const BUILTIN_SPEC_FIELDS: &[&str] = &[
    "replicas",
    "selector",
    "template",
    "containers",
    "initContainers",
    "ephemeralContainers",
    "volumes",
    "ports",
    "image",
    "name",
    "namespace",
    "labels",
    "annotations",
    "nodeName",
    "nodeSelector",
    "serviceAccountName",
    "restartPolicy",
    "terminationGracePeriodSeconds",
    "activeDeadlineSeconds",
    "strategy",
    "minReadySeconds",
    "revisionHistoryLimit",
    "paused",
    "progressDeadlineSeconds",
    "completions",
    "parallelism",
    "backoffLimit",
    "schedule",
    "concurrencyPolicy",
    "successfulJobsHistoryLimit",
    "failedJobsHistoryLimit",
    "suspend",
    "ingressClassName",
    "rules",
    "tls",
    "backend",
    "clusterIP",
    "type",
    "externalIPs",
    "loadBalancerIP",
    "sessionAffinity",
    "externalName",
    "storageClassName",
    "accessModes",
    "resources",
    "volumeName",
    "volumeMode",
    "capacity",
    "podSelector",
    "ingress",
    "egress",
    "policyTypes",
    "hostNetwork",
    "hostPID",
    "hostIPC",
    "securityContext",
    "imagePullSecrets",
    "affinity",
    "tolerations",
    "topologySpreadConstraints",
    "readinessGates",
    "runtimeClassName",
    "priority",
    "priorityClassName",
    "preemptionPolicy",
    "overhead",
    "dnsPolicy",
    "dnsConfig",
    "subdomain",
    "hostname",
    "automountServiceAccountToken",
    "shareProcessNamespace",
    "enableServiceLinks",
    "setHostnameAsFQDN",
    "os",
];

fn is_crd_group(group: &str) -> bool {
    !BUILTIN_GROUPS.contains(&group)
}

fn int_vs_string_operator(expr: &str) -> Option<&'static str> {
    let operators = [">=", "<=", "!=", "==", ">", "<"];
    for op in &operators {
        if let Some(idx) = expr.find(op) {
            let rhs = expr[idx + op.len()..].trim_start();
            if rhs.starts_with('\'') {
                return Some(op);
            }
        }
    }
    None
}

fn has_string_plus_int(expr: &str) -> bool {
    if let Some(idx) = expr.find('+') {
        let lhs = expr[..idx].trim_end();
        lhs.ends_with('\'')
    } else {
        false
    }
}

fn undefined_spec_field(expr: &str) -> Option<String> {
    let marker = "object.spec.";
    if let Some(start) = expr.find(marker) {
        let rest = &expr[start + marker.len()..];
        let field: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !field.is_empty() && !BUILTIN_SPEC_FIELDS.contains(&field.as_str()) {
            return Some(field);
        }
    }
    None
}

pub(crate) fn cel_type_warnings(
    validations: &serde_json::Value,
    match_constraints: &serde_json::Value,
) -> serde_json::Value {
    let empty = serde_json::Value::Array(vec![]);
    let entries = match validations.as_array() {
        Some(a) => a,
        None => return empty,
    };

    let targeting_crd = {
        let rules = match_constraints["resourceRules"].as_array();
        rules.is_some_and(|rs| {
            rs.iter().any(|r| {
                r["apiGroups"].as_array().is_some_and(|gs| {
                    gs.iter()
                        .any(|g| g.as_str().is_some_and(|s| is_crd_group(s) && s != "*"))
                })
            })
        })
    };

    let mut warnings: Vec<serde_json::Value> = Vec::new();

    for (i, entry) in entries.iter().enumerate() {
        if let Some(expr) = entry["expression"].as_str() {
            let field_ref = format!("spec.validations[{i}].expression");
            if let Some(op) = int_vs_string_operator(expr) {
                let op_escaped = match op {
                    ">" => "_>_",
                    "<" => "_<_",
                    ">=" => "_>=_",
                    "<=" => "_<=_",
                    "==" => "_==_",
                    "!=" => "_!=_",
                    _ => "_>_",
                };
                warnings.push(serde_json::json!({
                    "fieldRef": field_ref,
                    "warning": format!("found no matching overload for '{op_escaped}' applied to '(int, string)'")
                }));
            } else if targeting_crd {
                if let Some(field) = undefined_spec_field(expr) {
                    warnings.push(serde_json::json!({
                        "fieldRef": field_ref,
                        "warning": format!("undefined field '{field}'")
                    }));
                }
            }
        }

        if let Some(msg_expr) = entry["messageExpression"].as_str() {
            let field_ref = format!("spec.validations[{i}].messageExpression");
            if has_string_plus_int(msg_expr) {
                warnings.push(serde_json::json!({
                    "fieldRef": field_ref,
                    "warning": "found no matching overload for '_+_' applied to '(string, int)'"
                }));
            }
        }
    }

    serde_json::Value::Array(warnings)
}

/// After a VAP or VAPB write, set status.observedGeneration, a Ready=True
/// condition, and (for VAPs) status.typeChecking so conformance tests can
/// proceed without hanging on poll-until-typeChecking-non-nil.
/// Real kube does this via a background controller; u7s has no controller loop,
/// so set it synchronously.  Store errors are silenced with `let _ =` so a
/// status write failure never breaks the create/update response.
pub(crate) async fn write_vap_status<S: Store>(
    store: &S,
    group: &str,
    plural: &str,
    key: &str,
    obj_body: &mut serde_json::Value,
    stored_rv: u64,
) {
    if group != ADMISSION_GROUP || (plural != VAP_PLURAL && plural != VAPB_PLURAL) {
        return;
    }
    let generation = {
        let g = obj_body["metadata"]["generation"].as_i64().unwrap_or(0);
        if g < 1 {
            obj_body["metadata"]["generation"] = serde_json::json!(1i64);
            1i64
        } else {
            g
        }
    };
    let now = crate::util::utc_now_rfc3339();
    let type_checking = if plural == VAP_PLURAL {
        let validations = obj_body["spec"]["validations"].clone();
        let match_constraints = obj_body["spec"]["matchConstraints"].clone();
        let warnings = cel_type_warnings(&validations, &match_constraints);
        serde_json::json!({ "expressionWarnings": warnings })
    } else {
        serde_json::Value::Null
    };
    let mut status = serde_json::json!({
        "observedGeneration": generation,
        "conditions": [{
            "type": "Ready",
            "status": "True",
            "reason": "ValidationSucceeded",
            "message": "Expression compilation succeeded",
            "lastTransitionTime": now
        }]
    });
    if plural == VAP_PLURAL {
        status["typeChecking"] = type_checking;
    }
    obj_body["status"] = status;
    let bytes = match serde_json::to_vec(obj_body) {
        Ok(b) => bytes::Bytes::from(b),
        Err(_) => return,
    };
    if let Ok(new_rv) = store.put(key, bytes, Some(stored_rv)).await {
        obj_body["metadata"]["resourceVersion"] = serde_json::Value::String(new_rv.to_string());
    }
}

fn inject_type_meta(body: &mut serde_json::Value, group: &str, version: &str, kind: &str) {
    let api_version = if group.is_empty() {
        version.to_string()
    } else {
        format!("{group}/{version}")
    };
    body["kind"] = serde_json::Value::String(kind.to_string());
    body["apiVersion"] = serde_json::Value::String(api_version);
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

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
        })
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            test_user(),
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
            test_user(),
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
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            test_user(),
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
                dry_run: None,
            }),
            test_user(),
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
                dry_run: None,
            }),
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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

    /// Deleting a DaemonSet must cascade-delete pods owned by it immediately.
    ///
    /// Without this, pods remain Running for the full pod GC timeout (10+ minutes).
    /// AfterEach in conformance tests waits for pods to disappear — if they don't,
    /// each test burns ~600s and the full run wastes ~35 min.
    #[tokio::test]
    async fn delete_daemonset_cascades_to_owned_pods() {
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

        let ds_uid = "aaaaaaaa-0000-0000-0000-000000000001";
        let ns = "kube-system";

        // Seed the DaemonSet.
        let ds = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": { "name": "my-ds", "namespace": ns, "uid": ds_uid }
        });
        let ds_key = "/registry/apps/daemonsets/kube-system/my-ds";
        store
            .put(
                ds_key,
                bytes::Bytes::from(serde_json::to_vec(&ds).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed a pod owned by this DaemonSet.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-ds-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "DaemonSet",
                    "name": "my-ds",
                    "uid": ds_uid,
                    "controller": true
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_key = "/registry/pods/kube-system/my-ds-pod";
        store
            .put(
                pod_key,
                bytes::Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed an unrelated pod (must NOT be deleted).
        let other_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "other-pod", "namespace": ns }
        });
        let other_pod_key = "/registry/pods/kube-system/other-pod";
        store
            .put(
                other_pod_key,
                bytes::Bytes::from(serde_json::to_vec(&other_pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Delete the DaemonSet.
        delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                ns.to_string(),
                "daemonsets".into(),
                "my-ds".into(),
            )),
        )
        .await
        .unwrap_or_else(|e| panic!("delete must succeed: {e:?}"));

        // Owned pod must be deleted.
        assert!(
            store.get(pod_key).await.unwrap().is_none(),
            "pod owned by deleted DaemonSet must be cascade-deleted — \
             without this pods block AfterEach cleanup for 10+ minutes"
        );

        // DaemonSet itself must be deleted.
        assert!(
            store.get(ds_key).await.unwrap().is_none(),
            "DaemonSet itself must be deleted"
        );

        // Unrelated pod must survive.
        assert!(
            store.get(other_pod_key).await.unwrap().is_some(),
            "pod not owned by the deleted DaemonSet must not be affected"
        );
    }

    /// Deleting a Deployment must cascade-delete owned ReplicaSets immediately.
    ///
    /// Without this, orphaned ReplicaSets keep their desired-replica count active and
    /// continue creating pods indefinitely — observed: RS with desired=1337 created
    /// 14000+ pods after its Deployment was deleted.
    #[tokio::test]
    async fn delete_deployment_cascades_to_owned_replicasets() {
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

        let deploy_uid = "bbbbbbbb-0000-0000-0000-000000000001";
        let ns = "default";

        // Seed the Deployment.
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "my-deploy", "namespace": ns, "uid": deploy_uid }
        });
        let deploy_key = "/registry/apps/deployments/default/my-deploy";
        store
            .put(
                deploy_key,
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed a ReplicaSet owned by this Deployment.
        let rs = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": "my-deploy-7f96b54d4b",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "my-deploy",
                    "uid": deploy_uid,
                    "controller": true
                }]
            },
            "spec": { "replicas": 1337 }
        });
        let rs_key = "/registry/apps/replicasets/default/my-deploy-7f96b54d4b";
        store
            .put(
                rs_key,
                bytes::Bytes::from(serde_json::to_vec(&rs).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed an unrelated ReplicaSet (must NOT be deleted).
        let other_rs = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "other-rs", "namespace": ns }
        });
        let other_rs_key = "/registry/apps/replicasets/default/other-rs";
        store
            .put(
                other_rs_key,
                bytes::Bytes::from(serde_json::to_vec(&other_rs).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Delete the Deployment.
        delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                ns.to_string(),
                "deployments".into(),
                "my-deploy".into(),
            )),
        )
        .await
        .unwrap_or_else(|e| panic!("delete must succeed: {e:?}"));

        // Owned ReplicaSet must be cascade-deleted so it stops creating pods.
        assert!(
            store.get(rs_key).await.unwrap().is_none(),
            "ReplicaSet owned by deleted Deployment must be cascade-deleted — \
             without this, RS keeps desired-replica count active and creates pods indefinitely"
        );

        // Deployment itself must be deleted.
        assert!(
            store.get(deploy_key).await.unwrap().is_none(),
            "Deployment itself must be deleted"
        );

        // Unrelated ReplicaSet must survive.
        assert!(
            store.get(other_rs_key).await.unwrap().is_some(),
            "ReplicaSet not owned by the deleted Deployment must not be affected"
        );
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
            axum::extract::Query(CreateQuery::default()),
            admin_user.clone(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&cr).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("ClusterRole creation must succeed"));

        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((group.to_string(), version.to_string(), plural.to_string())),
            axum::extract::Query(CreateQuery::default()),
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
            axum::extract::Query(ReplaceQuery::default()),
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
            axum::extract::Query(ReplaceQuery::default()),
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
            axum::extract::Query(ReplaceQuery::default()),
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
            axum::extract::Query(ReplaceQuery::default()),
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
            axum::extract::Query(ReplaceQuery::default()),
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
            test_user(),
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
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
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
            axum::extract::Query(CreateQuery::default()),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
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
            axum::extract::Query(CreateQuery::default()),
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
            test_user(),
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
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            test_user(),
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
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
                timeout_seconds: Some(1), // stream closes after 1s so to_bytes can return with collected data
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

        // Read until stream closes (timeout_seconds=1) or the 3-second guard fires.
        // Initial events are emitted synchronously before the live-event wait.
        use tokio::time::{timeout, Duration};
        let body = resp.into_body();
        let bytes = timeout(
            Duration::from_secs(3),
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
            axum::extract::Query(CreateQuery::default()),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            axum::extract::Query(ReplaceQuery::default()),
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
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
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

    /// Regression test for the blank-namespace EndpointSlice mirroring retry loop:
    /// replace_namespaced_resource (PUT) must stamp metadata.namespace from the URL path into the
    /// stored body even when the client omits it from the request body.
    ///
    /// Without the fix: a PUT body without metadata.namespace stores the object with namespace="".
    /// The KCM EndpointSlice mirroring controller watches /api/v1/endpoints cluster-wide and builds
    /// an informer key of just "<name>" (no "namespace/" prefix) for objects with blank namespace.
    /// The controller then issues DELETE requests without a namespace in the URL path, producing
    /// a "not found" retry loop that never resolves.
    ///
    /// This test fails on revert: if the namespace-stamp line is removed, the PUT body without
    /// namespace gets stored with namespace="" and the list returns namespace="" for the object.
    #[tokio::test]
    async fn replace_namespaced_resource_stamps_namespace_when_body_omits_it() {
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

        // PUT body deliberately omits metadata.namespace — simulates a test client or
        // kubectl apply that does not include the namespace field in the body.
        let body_without_ns = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "my-lease" },
            "spec": { "holderIdentity": "test-holder" }
        });

        let resp = replace_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "my-lease".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body_without_ns).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("replace must succeed when body omits namespace"))
        .into_response();

        // The response body must have the namespace stamped.
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let returned: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            returned["metadata"]["namespace"], "kube-node-lease",
            "PUT response must include the URL namespace in metadata.namespace; \
             without the fix, namespace is absent and the mirroring controller builds \
             a blank-namespace informer key, causing an infinite DELETE retry loop"
        );

        // The stored object must also have namespace stamped so cluster-wide LIST/Watch events
        // include the namespace — this is what the KCM mirroring controller sees.
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/my-lease";
        let stored = store
            .get(key)
            .await
            .expect("store get must succeed")
            .expect("object must be stored");
        let stored_obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_obj["metadata"]["namespace"], "kube-node-lease",
            "stored object must have metadata.namespace='kube-node-lease'; \
             a cluster-wide Watch emits the raw stored JSON — if namespace is missing there, \
             KCM informers receive blank-namespace objects and the EndpointSlice mirroring \
             controller enters an infinite retry loop (blank-namespace DELETE requests fail \
             with 'not found')"
        );
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            konnectivity_proxy_addr: None,
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
                axum::extract::Query(CreateQuery::default()),
                test_user(),
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
    // ClusterIP auto-allocation regression tests (mayor-pzkt)
    //
    // These tests verify that POST /api/v1/namespaces/{ns}/services with an
    // allocator configured returns a Service with .spec.clusterIP populated.
    // If maybe_allocate_cluster_ip is removed or broken, all four tests fail.
    // ---------------------------------------------------------------------------

    fn make_state_with_cidr_for_resource_tests(
        cidr: &str,
    ) -> crate::state::AppState<u7s_store::SqliteStore> {
        use crate::state::{AppStateConfig, ServiceIpAllocator};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let alloc = ServiceIpAllocator::from_cidr(cidr).expect("valid CIDR");
        crate::state::AppState::new_with_config(AppStateConfig {
            store,
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
            konnectivity_proxy_addr: None,
        })
    }

    /// POST of a ClusterIP Service must return a response with spec.clusterIP set to
    /// an address within the configured CIDR.
    ///
    /// Without maybe_allocate_cluster_ip, spec.clusterIP is never populated — the
    /// field comes back empty and DNS/kube-proxy cannot program service routing.
    #[tokio::test]
    async fn allocate_assigns_ip_from_cidr() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        let state = make_state_with_cidr_for_resource_tests("10.96.0.0/12");

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "auto-ip-svc", "namespace": "default" },
            "spec": { "type": "ClusterIP", "ports": [{ "port": 80 }] }
        });

        let resp = create_namespaced_resource(
            State(state),
            Path(("".into(), "v1".into(), "default".into(), "services".into())),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Service create must succeed: {e:?}"))
        .into_response();

        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let cluster_ip = v["spec"]["clusterIP"].as_str().unwrap_or("").to_string();
        assert!(
            !cluster_ip.is_empty() && cluster_ip != "None",
            "spec.clusterIP must be populated after create — empty clusterIP breaks kube-proxy and DNS"
        );

        // Must be a valid IPv4 address within 10.96.0.0/12.
        let ip = Ipv4Addr::from_str(&cluster_ip).unwrap_or_else(|_| {
            panic!("spec.clusterIP must be a valid IPv4 address, got {cluster_ip}")
        });
        let base = u32::from(Ipv4Addr::new(10, 96, 0, 0));
        let mask: u32 = !((1u32 << (32 - 12)) - 1);
        assert_eq!(
            u32::from(ip) & mask,
            base & mask,
            "allocated clusterIP {ip} must be within 10.96.0.0/12"
        );
    }

    /// Creating 10 ClusterIP Services must produce 10 distinct clusterIPs.
    ///
    /// Duplicate clusterIPs mis-route traffic: two services sharing one IP means
    /// only one can be reached via kube-proxy iptables rules.
    #[tokio::test]
    async fn allocate_no_duplicates() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use std::collections::HashSet;

        // /24 has 254 usable IPs — enough for 10 services without exhaustion.
        let state = make_state_with_cidr_for_resource_tests("10.0.0.0/24");

        let mut ips: HashSet<String> = HashSet::new();
        for i in 0..10u32 {
            let svc = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": { "name": format!("svc-{i}"), "namespace": "default" },
                "spec": { "type": "ClusterIP", "ports": [{ "port": 80 }] }
            });
            let resp = create_namespaced_resource(
                State(state.clone()),
                Path(("".into(), "v1".into(), "default".into(), "services".into())),
                axum::extract::Query(CreateQuery::default()),
                test_user(),
                json_headers(),
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
            )
            .await
            .unwrap_or_else(|e| panic!("Service {i} create must succeed: {e:?}"))
            .into_response();

            let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let ip = v["spec"]["clusterIP"].as_str().unwrap_or("").to_string();
            assert!(
                !ip.is_empty() && ip != "None",
                "Service {i} must get a clusterIP — empty means allocation is broken"
            );
            assert!(
                ips.insert(ip.clone()),
                "clusterIP {ip} for Service {i} duplicates an earlier allocation — \
                 duplicate IPs mis-route traffic"
            );
        }

        assert_eq!(
            ips.len(),
            10,
            "10 Services must produce 10 distinct clusterIPs"
        );
    }

    /// A headless Service (clusterIP: None) must NOT have a clusterIP auto-allocated.
    ///
    /// Headless services have no cluster IP; they return all Pod IPs directly via DNS.
    /// Auto-allocating an IP for them would break DNS round-robin and confuse kube-proxy.
    #[tokio::test]
    async fn headless_service_skips_allocation() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;

        let state = make_state_with_cidr_for_resource_tests("10.0.0.0/24");

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "headless", "namespace": "default" },
            "spec": { "clusterIP": "None", "ports": [{ "port": 80 }] }
        });

        let resp = create_namespaced_resource(
            State(state),
            Path(("".into(), "v1".into(), "default".into(), "services".into())),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("headless Service create must succeed: {e:?}"))
        .into_response();

        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["spec"]["clusterIP"].as_str(),
            Some("None"),
            "headless Service must retain clusterIP=None — overwriting it with an allocated IP \
             would break DNS round-robin by making the service behave like a normal ClusterIP service"
        );
    }

    /// A Service with a pre-set spec.clusterIP must keep that IP (static allocation).
    ///
    /// When a user explicitly sets spec.clusterIP (e.g. to pin a well-known address),
    /// the auto-allocator must not overwrite it with a different IP. Overwriting would
    /// break any in-cluster code that has the old IP hard-coded.
    #[tokio::test]
    async fn static_clusterip_is_respected() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;

        let state = make_state_with_cidr_for_resource_tests("10.0.0.0/24");

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "static-ip-svc", "namespace": "default" },
            "spec": { "clusterIP": "10.0.0.99", "ports": [{ "port": 80 }] }
        });

        let resp = create_namespaced_resource(
            State(state),
            Path(("".into(), "v1".into(), "default".into(), "services".into())),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Service with static clusterIP must succeed: {e:?}"))
        .into_response();

        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["spec"]["clusterIP"].as_str(),
            Some("10.0.0.99"),
            "static clusterIP 10.0.0.99 must be preserved — \
             overwriting a user-specified clusterIP would break any code that has that IP hard-coded"
        );
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
            axum::extract::Query(CreateQuery::default()),
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
                axum::extract::Query(CreateQuery::default()),
                test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
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
            axum::extract::Query(CreateQuery::default()),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
    /// so replay is synchronous. timeout_seconds=1 closes the stream after 1s, allowing
    /// to_bytes to return with the collected data.
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
                axum::extract::Query(CreateQuery::default()),
                test_user(),
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
                test_user(),
                mp_headers,
                bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
            )
            .await
            .unwrap_or_else(|_| panic!("ConfigMap merge-patch must succeed"))
            .into_response();
            // tmp_state is dropped here; the store Arc count goes back down to 1 (only `store`).
        }

        // 3. Build watch state from the store Arc.
        let watch_state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // 4. Subscribe a WATCH from rv=0 so the ring buffer replays ADDED and MODIFIED.
        //    timeout_seconds=1 closes the stream after 1s so to_bytes can return with data.
        //    (Previously this relied on watch_state being the only store Arc so the broadcast
        //    channel would close when watch_generic dropped it — that shortcut was fixed by
        //    the mayor-8tiu _store_keepalive fix which keeps the store alive for the stream.)
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
                timeout_seconds: Some(1), // stream closes after 1s; ring buffer events arrive before that
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        // 5. Collect the body (terminates when timeout_seconds=1 fires, or 3s guard).
        let body_bytes = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            to_bytes(resp.into_body(), usize::MAX),
        )
        .await
        .unwrap_or(Ok(bytes::Bytes::new()))
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
            axum::extract::Query(CreateQuery::default()),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
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

    /// POST a Deployment with no spec.selector AND no spec.template.metadata.labels must
    /// return 422 Unprocessable Entity (not 500, not 400, not 201).
    ///
    /// The real kube-apiserver returns 422 for this case.  Without the fix, u7s returned
    /// 400 (bad_request) instead of 422 (unprocessable_entity), so the AdmissionWebhook
    /// conformance test's BeforeEach failed to create sample-webhook-deployment with:
    ///   "Deployment.spec.selector is required and could not be defaulted"
    ///
    /// This test FAILS if the validate_resource error is mapped to Status::bad_request
    /// instead of Status::unprocessable_entity, or if validation is skipped entirely.
    #[tokio::test]
    async fn deployment_without_selector_or_labels_returns_422() {
        use axum::response::IntoResponse;

        let state = make_state();

        // No spec.selector, no spec.template.metadata.labels — cannot be defaulted.
        let deployment = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "bad-deploy", "namespace": "default" },
            "spec": {
                "template": {
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&deployment).unwrap()),
        )
        .await
        .map(|r| r.into_response())
        .unwrap_or_else(|e| e.into_response());

        assert_eq!(
            result.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "Deployment with no selector and no template labels must return 422 — \
             the real kube-apiserver returns 422 Invalid for this case; returning 400 or 500 \
             breaks the AdmissionWebhook conformance test's BeforeEach (mayor-p807)"
        );
    }

    /// Creating a Deployment must NOT inject SA token volumes or volume defaults into
    /// spec.template — the stored pod template must be verbatim (no kube-api-access-*
    /// volumes, no defaultMode stamps).
    ///
    /// KCM's deployment controller computes pod-template-hash from the pod template AS
    /// SUBMITTED and stores the RS with that hash.  If the apiserver mutates spec.template
    /// (e.g. by running inject_sa_token_volume or apply_pod_create_defaults on the
    /// Deployment), the hash KCM recomputes from the stored template differs → FindNewReplicaSet
    /// returns nil → KCM logs "new replicaset is yet to be created" forever.
    ///
    /// Correct Kubernetes semantics: Deployments are stored verbatim; pod mutations
    /// (SA volume injection, defaultMode) happen only when a Pod is actually created by
    /// the RS controller, not when the workload resource is stored.
    ///
    /// This test fails if inject_sa_token_volume or apply_pod_create_defaults is
    /// ever added to the Deployment create path.
    #[tokio::test]
    async fn deployment_pod_template_stored_verbatim_no_sa_volume_injected() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        // Deployment with a serviceAccountName — the trigger for SA volume injection.
        // If the create path ever calls inject_sa_token_volume on Deployments, this
        // will add a kube-api-access-* projected volume to spec.template.spec.volumes.
        let deployment = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test-deploy", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {
                    "metadata": { "labels": { "app": "test" } },
                    "spec": {
                        "serviceAccountName": "default",
                        "containers": [{ "name": "c", "image": "nginx" }]
                    }
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
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&deployment).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Deployment POST must return 201, got: {e:?}"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::CREATED);

        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // spec.template.spec.volumes must be null — no kube-api-access-* volume injected.
        // If this assertion fails, inject_sa_token_volume or apply_pod_create_defaults was
        // called on the Deployment create path, breaking KCM's pod-template-hash computation.
        assert!(
            stored["spec"]["template"]["spec"]["volumes"].is_null(),
            "Deployment spec.template.spec.volumes must be null after create — \
             SA token volume must NOT be injected into Deployment templates. \
             Injecting it causes pod-template-hash mismatch: KCM hashes the submitted \
             template (no volume), stores RS with that hash, then reads the mutated \
             stored template (with volume) and computes a different hash → FindNewReplicaSet \
             returns nil → 'new replicaset is yet to be created' loop"
        );

        // spec.template.spec.serviceAccountName must be preserved verbatim.
        assert_eq!(
            stored["spec"]["template"]["spec"]["serviceAccountName"], "default",
            "spec.template.spec.serviceAccountName must be stored as submitted"
        );
    }

    /// POST a ReplicaSet then PUT with the resourceVersion from the POST response must succeed.
    ///
    /// The RS controller (KCM) creates a ReplicaSet via POST, extracts the resourceVersion
    /// from the response, and subsequently PUTs the same object with that resourceVersion as
    /// the optimistic-concurrency precondition.  If the POST response returns a stale or
    /// incorrect resourceVersion (e.g. "0" or None because set_resource_version was not called),
    /// the PUT is rejected with 409 Conflict and the RS controller log shows:
    ///   "read version X is not as new as written version Y for group resource replicasets.apps"
    ///
    /// This test fails if `obj.set_resource_version(new_rv)` is removed from
    /// create_namespaced_resource, because the response would then contain no resourceVersion
    /// (or the pre-store value), and the subsequent PUT with that value would be rejected.
    #[tokio::test]
    async fn replicaset_post_then_put_with_create_rv_succeeds() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let rs = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "my-rs", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "my-rs" } },
                "template": {
                    "metadata": { "labels": { "app": "my-rs" } },
                    "spec": { "containers": [{ "name": "c", "image": "nginx" }] }
                }
            }
        });
        let body_bytes = bytes::Bytes::from(serde_json::to_vec(&rs).unwrap());

        // Step 1: POST to create the ReplicaSet.
        let create_resp = create_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "replicasets".into(),
            )),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            body_bytes,
        )
        .await
        .unwrap_or_else(|e| panic!("ReplicaSet POST must succeed; got: {e:?}"))
        .into_response();

        assert_eq!(
            create_resp.status(),
            axum::http::StatusCode::CREATED,
            "POST must return 201 Created"
        );

        let create_body = to_bytes(create_resp.into_body(), usize::MAX).await.unwrap();
        let created: serde_json::Value = serde_json::from_slice(&create_body).unwrap();

        // The POST response must include a non-zero resourceVersion stamped by the store.
        // If set_resource_version(new_rv) is not called, this will be missing or "0",
        // and the subsequent PUT will be rejected with 409 Conflict.
        let rv = created["metadata"]["resourceVersion"]
            .as_str()
            .expect("POST response must include metadata.resourceVersion");
        let rv_num: u64 = rv
            .parse()
            .expect("metadata.resourceVersion must be a valid integer string");
        assert!(
            rv_num > 0,
            "POST response resourceVersion must be > 0 (the store-assigned revision); \
             got '{}' — if this is 0 or missing, the RS controller's subsequent PUT \
             will be rejected with 409 Conflict",
            rv
        );

        // Step 2: PUT with the resourceVersion from the POST response.
        // This simulates the RS controller's first sync after creation.
        // The PUT body must include the resourceVersion so the store can verify
        // the precondition (optimistic concurrency).
        let mut put_body = created.clone();
        put_body["metadata"]["resourceVersion"] = serde_json::Value::String(rv.to_string());
        // Remove status — the replace handler strips it for resources with a status subresource.
        if let Some(m) = put_body.as_object_mut() {
            m.remove("status");
        }
        let put_bytes = bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap());

        let put_result = replace_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "replicasets".into(),
                "my-rs".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            put_bytes,
        )
        .await;

        assert!(
            put_result.is_ok(),
            "PUT with resourceVersion from POST response must succeed — a 409 here means \
             the POST response returned a stale resourceVersion that doesn't match the store, \
             which causes the RS controller to log 'read version X is not as new as written \
             version Y for group resource replicasets.apps'; got: {:?}",
            put_result.err()
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
            konnectivity_proxy_addr: None,
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
            konnectivity_proxy_addr: None,
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

    /// Regression test (mayor-9ejz): expired continue token must include `metadata.continue`
    /// in the 410 response so clients can restart pagination from the beginning.
    ///
    /// Kubernetes conformance test chunking.go:202 (step 3 → 4):
    /// 1. List page 1, save continue token.
    /// 2. Wait for token TTL (60 s) to elapse.
    /// 3. Use expired token → expect 410 with `metadata.continue`.
    /// 4. Use the new token to fetch page 2.
    ///
    /// Without `metadata.continue` in the 410 body, step 4 cannot proceed and the
    /// conformance test fails.  This test MUST FAIL if the fix is reverted.
    #[tokio::test]
    async fn expired_continue_token_410_response_contains_metadata_continue() {
        use axum::extract::{Path, Query, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

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
            konnectivity_proxy_addr: None,
        });

        // Forge a valid-signature token with Unix epoch timestamp so it is always expired.
        let expired_token = build_signed_token(
            "/registry/podtemplates/default/pt-0",
            &signing_key,
            0, // Unix epoch — older than CONTINUE_TOKEN_TTL_SECS (60s) by ~55 years
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

        let err = result.expect_err("expired continue token must return 410, not 200");
        assert_eq!(err.0, axum::http::StatusCode::GONE);

        // The 410 body must include metadata.continue with a fresh token so the client
        // can restart pagination.  Without this, the conformance test cannot proceed to
        // page 2 after the token TTL expires.
        let meta = err.1.metadata.as_ref().expect(
            "expired-token 410 must include metadata.continue; \
             Kubernetes chunking conformance (chunking.go:202) reads this to restart pagination",
        );
        let cont = meta["continue"]
            .as_str()
            .expect("metadata.continue must be a non-null string");
        assert!(
            !cont.is_empty(),
            "metadata.continue in the 410 response must be a non-empty token"
        );
    }

    /// Regression test (mayor-quqc): PATCHing Event series.lastObservedTime must persist and
    /// be normalized to microsecond precision on GET.
    ///
    /// The Kubernetes Event controller uses merge-patch to update series.count and
    /// series.lastObservedTime on repeated events.  If series.lastObservedTime is stored
    /// without microsecond precision (e.g. "2024-01-01T00:00:01Z"), client-go's MicroTime
    /// codec raises "cannot parse Z as .000000" and treats it as zero — making every
    /// occurrence appear as a new event and breaking deduplication (core_events.go:144).
    ///
    /// This test fails if normalize_event_timestamps stops normalizing series.lastObservedTime,
    /// or if do_patch stops persisting the series field.
    #[tokio::test]
    async fn event_patch_series_last_observed_time_persists_and_is_normalized() {
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

        // 1. Seed an Event with series.lastObservedTime at original time (second precision).
        let event = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": {
                "name": "my-pod.series-event",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "involvedObject": {
                "kind": "Pod",
                "name": "my-pod",
                "namespace": "default"
            },
            "reason": "BackOff",
            "message": "Back-off restarting failed container",
            "series": {
                "count": 1,
                "lastObservedTime": "2024-01-01T00:00:00Z"
            }
        });
        store
            .put(
                "/registry/events/default/my-pod.series-event",
                bytes::Bytes::from(serde_json::to_vec(&event).unwrap()),
                None,
            )
            .await
            .expect("seed Event");

        // 2. PATCH with updated series.lastObservedTime (second precision, as some clients send).
        let mut mp_headers = axum::http::HeaderMap::new();
        mp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        let patch = serde_json::json!({
            "metadata": {"creationTimestamp": null},
            "series": {
                "count": 2,
                "lastObservedTime": "2024-01-01T00:00:01Z"
            }
        });

        let patch_result = patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "events".to_string(),
                "my-pod.series-event".to_string(),
            )),
            axum::extract::Query(PatchQuery::default()),
            test_user(),
            mp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Event PATCH must succeed; got: {e:?}"))
        .into_response();

        assert_eq!(
            patch_result.status(),
            axum::http::StatusCode::OK,
            "Event PATCH must return 200 OK"
        );

        // 3. GET the Event and verify series.lastObservedTime is updated AND normalized.
        let get_result = get_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "events".to_string(),
                "my-pod.series-event".to_string(),
            )),
        )
        .await
        .unwrap_or_else(|e| panic!("Event GET must succeed; got: {e:?}"))
        .into_response();

        let body = to_bytes(get_result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["series"]["count"], 2,
            "series.count must be updated by the PATCH to 2; \
             if this fails the merge-patch is not being applied"
        );
        assert_eq!(
            v["series"]["lastObservedTime"], "2024-01-01T00:00:01.000000Z",
            "series.lastObservedTime must be updated to the patched value AND normalized \
             to microsecond precision; client-go MicroTime rejects bare RFC3339 without \
             '.000000' — causing every event occurrence to appear new (deduplication breaks)"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: fieldValidation=Strict/Warn/Ignore (mayor-7exg)
    // ---------------------------------------------------------------------------

    /// POST with an unknown top-level field and ?fieldValidation=Strict must return
    /// 422 UnprocessableEntity with a well-formed Kubernetes Status body.
    ///
    /// The conformance tests PANICKED because the server previously ignored
    /// fieldValidation=Strict and returned 201 with the object body. The test client
    /// expected a 422 Status body and crashed trying to parse a ConfigMap as a Status.
    ///
    /// This test fails if apply_field_validation no longer rejects unknown fields in
    /// Strict mode — the conformance tests would panic again.
    #[tokio::test]
    async fn create_namespaced_resource_strict_rejects_unknown_field() {
        let state = make_state();

        // ConfigMap with an unknown top-level field — "unknownField" is not in the
        // known schema for configmaps.
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "strict-test", "namespace": "default" },
            "data": { "key": "value" },
            "unknownField": "this-should-be-rejected"
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "configmaps".to_string(),
            )),
            axum::extract::Query(CreateQuery {
                field_validation: Some("Strict".to_string()),
                ..Default::default()
            }),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;

        match result {
            Err(err) => {
                assert_eq!(
                    err.0,
                    axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "fieldValidation=Strict must produce 422 UnprocessableEntity — \
                     the conformance test client parses the response as a Status object; \
                     a non-422 response causes a panic in the Go client"
                );
                assert_eq!(
                    err.1.reason, "Invalid",
                    "Status.reason must be 'Invalid' for field validation errors"
                );
                assert!(
                    err.1.message.contains("unknownField"),
                    "Status.message must name the unknown field; got: {}",
                    err.1.message
                );
            }
            Ok(_) => panic!(
                "POST with unknown field + fieldValidation=Strict must return 422; \
                 the conformance test panics when it gets a 201 object body instead of a 422 Status"
            ),
        }
    }

    /// POST with an unknown top-level field and ?fieldValidation=Ignore must return 201.
    ///
    /// Ignore (the default) silently strips/tolerates unknown fields — existing behavior.
    #[tokio::test]
    async fn create_namespaced_resource_ignore_accepts_unknown_field() {
        use axum::response::IntoResponse;

        let state = make_state();

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "ignore-test", "namespace": "default" },
            "data": { "key": "value" },
            "unknownField": "this-should-be-ignored"
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "configmaps".to_string(),
            )),
            axum::extract::Query(CreateQuery {
                field_validation: Some("Ignore".to_string()),
                ..Default::default()
            }),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Ignore mode must accept unknown fields; got: {e:?}"))
        .into_response();

        assert_eq!(
            result.status(),
            axum::http::StatusCode::CREATED,
            "fieldValidation=Ignore must return 201 — unknown fields are silently tolerated"
        );
    }

    /// POST with an unknown top-level field and ?fieldValidation=Warn must return 201
    /// with a Warning response header listing the unknown field.
    #[tokio::test]
    async fn create_namespaced_resource_warn_returns_warning_header() {
        use axum::response::IntoResponse;

        let state = make_state();

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "warn-test", "namespace": "default" },
            "data": { "key": "value" },
            "unknownField": "trigger-warning"
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "configmaps".to_string(),
            )),
            axum::extract::Query(CreateQuery {
                field_validation: Some("Warn".to_string()),
                ..Default::default()
            }),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Warn mode must accept unknown fields; got: {e:?}"))
        .into_response();

        assert_eq!(
            result.status(),
            axum::http::StatusCode::CREATED,
            "fieldValidation=Warn must return 201 — the object is stored despite warnings"
        );
        assert!(
            result.headers().contains_key(axum::http::header::WARNING),
            "fieldValidation=Warn must add a Warning response header listing the unknown field"
        );
    }

    /// POST with an unknown metadata field and ?fieldValidation=Strict must return 422.
    ///
    /// Corresponds to the conformance test "detect unknown metadata fields of a typed object".
    #[tokio::test]
    async fn create_namespaced_resource_strict_rejects_unknown_metadata_field() {
        let state = make_state();

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "meta-strict-test",
                "namespace": "default",
                "unknownMetaField": "should-be-rejected"
            },
            "data": {}
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "configmaps".to_string(),
            )),
            axum::extract::Query(CreateQuery {
                field_validation: Some("Strict".to_string()),
                ..Default::default()
            }),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;

        match result {
            Err(err) => {
                assert_eq!(
                    err.0,
                    axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "unknown metadata field with Strict must produce 422"
                );
                assert!(
                    err.1.message.contains("unknownMetaField"),
                    "Status.message must name the unknown metadata field; got: {}",
                    err.1.message
                );
            }
            Ok(_) => panic!(
                "POST with unknown metadata field + fieldValidation=Strict must return 422; \
                 the conformance test 'detect unknown metadata fields' panics when it gets \
                 a 201 object body instead of a 422 Status"
            ),
        }
    }

    // -- events.k8s.io/v1 registration --

    /// POST to /apis/events.k8s.io/v1/namespaces/default/events must return 201.
    ///
    /// Without the registry entry for ("events.k8s.io", "v1", "events"), the lookup
    /// in create_namespaced_resource returns a 404 StatusError before any store access.
    /// Sonobuoy conformance test "Events API should ensure that an event can be fetched,
    /// patched, deleted, and listed" fails with 'Resource "events.k8s.io/v1/events" not found'.
    /// This test fails if the registry entry is removed from state.rs.
    #[tokio::test]
    async fn events_k8s_io_v1_post_returns_201() {
        use axum::response::IntoResponse;

        let state = make_state();

        let event = serde_json::json!({
            "apiVersion": "events.k8s.io/v1",
            "kind": "Event",
            "metadata": { "name": "test-event", "namespace": "default" },
            "eventTime": "2026-05-30T00:00:00.000000Z",
            "action": "Started",
            "reason": "TestReason",
            "regarding": {
                "apiVersion": "v1",
                "kind": "Pod",
                "name": "test-pod",
                "namespace": "default"
            },
            "reportingController": "test-controller",
            "reportingInstance": "test-instance",
            "type": "Normal"
        });

        let result = create_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "events.k8s.io".into(),
                "v1".into(),
                "default".into(),
                "events".into(),
            )),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&event).unwrap()),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "POST events.k8s.io/v1 Event must return 201, not error {:?}; \
             events.k8s.io/v1 must be registered in build_registry()",
                e.0
            )
        })
        .into_response();

        assert_eq!(
            result.status(),
            axum::http::StatusCode::CREATED,
            "POST events.k8s.io/v1 Event must return 201; \
             if this fails the events.k8s.io/v1 registry entry was removed from state.rs"
        );
    }

    // -- Regression: ResourceSlice create response must include kind and apiVersion (mayor-lf0w) --

    /// The Kubernetes API contract requires every response object to include TypeMeta
    /// (kind + apiVersion). client-go (and the DRA conformance test) call create and then
    /// assert the returned object has a non-empty Kind. Without inject_type_meta, objects
    /// whose client bodies omit kind/apiVersion (as client-go sometimes does) would be
    /// returned without TypeMeta, causing the conformance error:
    ///   "Object Kind is missing in {\"metadata\":{...},\"spec\":{...}}"
    ///
    /// This test sends a body without kind/apiVersion (matching client-go behaviour) to
    /// verify the server always injects them. Removing inject_type_meta must make this fail.
    #[tokio::test]
    async fn create_resource_slice_response_has_type_meta() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        // Intentionally omit kind and apiVersion — matching what client-go does when it
        // serialises a struct whose TypeMeta fields are zero-valued.
        let body = serde_json::json!({
            "metadata": {
                "name": "test-node-slice"
            },
            "spec": {
                "driver": "test.csi.k8s.io",
                "pool": {
                    "name": "test-pool",
                    "generation": 0,
                    "resourceSliceCount": 1
                },
                "nodeName": "test-node",
                "devices": []
            }
        });

        let result = create_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "resource.k8s.io".to_string(),
                "v1".to_string(),
                "resourceslices".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
            Extension(crate::auth::UserInfo {
                username: "system:masters".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
            }),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("ResourceSlice create must succeed"))
        .into_response();

        assert_eq!(
            result.status(),
            axum::http::StatusCode::CREATED,
            "ResourceSlice create must return 201"
        );

        let body_bytes = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            v["kind"], "ResourceSlice",
            "response must have kind=ResourceSlice — client-go asserts this and returns \
             'Object Kind is missing' when absent (DRA conformance test mayor-lf0w)"
        );
        assert_eq!(
            v["apiVersion"], "resource.k8s.io/v1",
            "response must have apiVersion=resource.k8s.io/v1 — required by Kubernetes API contract"
        );
    }

    // -- Regression: KCM deployment controller revision annotation (mayor-ufa4) --

    /// KCM annotates the Deployment with `deployment.kubernetes.io/revision=1` after
    /// creating the initial ReplicaSet. It uses a strategic-merge-patch body that contains
    /// the new annotation nested inside `metadata.annotations`.
    ///
    /// The annotation MUST persist in the stored object. Without it, the AdmissionWebhook
    /// conformance test's BeforeEach times out waiting for the annotation to appear, causing
    /// every webhook test to fail.
    ///
    /// This test fails if strategic_merge_patch silently drops metadata.annotations when
    /// the existing Deployment has annotations=null (the initial stored state).
    #[tokio::test]
    async fn kcm_deployment_revision_annotation_persists_after_strategic_merge_patch() {
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

        // Step 1: Create a Deployment (as kubectl or a test framework would).
        // The Deployment starts with no annotations.
        let deployment = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "sample-webhook-deployment",
                "namespace": "webhook-test",
                "labels": {"app": "webhook"}
            },
            "spec": {
                "selector": {"matchLabels": {"app": "webhook"}},
                "replicas": 1,
                "template": {
                    "metadata": {"labels": {"app": "webhook"}},
                    "spec": {
                        "containers": [{"name": "webhook", "image": "nginx:latest"}]
                    }
                }
            }
        });
        let deploy_bytes = bytes::Bytes::from(serde_json::to_vec(&deployment).unwrap());

        let mut json_hdrs = axum::http::HeaderMap::new();
        json_hdrs.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let create_result = create_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                "webhook-test".to_string(),
                "deployments".to_string(),
            )),
            axum::extract::Query(super::super::json_patch::CreateQuery::default()),
            test_user(),
            json_hdrs.clone(),
            deploy_bytes,
        )
        .await
        .unwrap_or_else(|e| panic!("Deployment create must succeed: {e:?}"))
        .into_response();

        assert_eq!(
            create_result.status(),
            axum::http::StatusCode::CREATED,
            "Deployment create must return 201"
        );

        // Step 2: KCM sends strategic-merge-patch to add revision annotation.
        // client-go's CreateTwoWayMergePatch includes creationTimestamp:null (zero time).
        // The Content-Type is application/strategic-merge-patch+json.
        let revision_patch = serde_json::json!({
            "metadata": {
                "annotations": {
                    "deployment.kubernetes.io/revision": "1"
                },
                "creationTimestamp": null
            }
        });
        let patch_bytes = bytes::Bytes::from(serde_json::to_vec(&revision_patch).unwrap());

        let mut smp_hdrs = axum::http::HeaderMap::new();
        smp_hdrs.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );

        let patch_result = patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                "webhook-test".to_string(),
                "deployments".to_string(),
                "sample-webhook-deployment".to_string(),
            )),
            axum::extract::Query(PatchQuery::default()),
            test_user(),
            smp_hdrs,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|e| panic!("Deployment PATCH must succeed: {e:?}"))
        .into_response();

        assert_eq!(
            patch_result.status(),
            axum::http::StatusCode::OK,
            "KCM's strategic-merge-patch to add revision annotation must return 200"
        );

        let patch_body = to_bytes(patch_result.into_body(), usize::MAX)
            .await
            .unwrap();
        let pv: serde_json::Value = serde_json::from_slice(&patch_body).unwrap();

        // Step 3: Verify the annotation appears in the PATCH response.
        assert_eq!(
            pv["metadata"]["annotations"]["deployment.kubernetes.io/revision"], "1",
            "PATCH response must include deployment.kubernetes.io/revision=1 annotation; \
             without it AdmissionWebhook BeforeEach times out waiting for the annotation"
        );

        // Step 4: Verify the annotation persists in the stored object.
        let key = "/registry/apps/deployments/webhook-test/sample-webhook-deployment";
        let stored = store
            .get(key)
            .await
            .expect("store get must not fail")
            .expect("Deployment must exist in store");
        let sv: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            sv["metadata"]["annotations"]["deployment.kubernetes.io/revision"], "1",
            "deployment.kubernetes.io/revision annotation must be persisted in store; \
             KCM reads the annotation on subsequent reconcile loops and must find it"
        );

        // Bonus: creationTimestamp must NOT be removed (the null guard must protect it).
        assert!(
            !sv["metadata"]["creationTimestamp"].is_null(),
            "creationTimestamp must not be removed by the null in the KCM patch body"
        );
    }

    // -- Regression: KCM 1.36 RS create propagates revision to Deployment (mayor-tt5j) --

    /// KCM 1.36 sets `deployment.kubernetes.io/revision=1` on the ReplicaSet body before
    /// POSTing it (in-memory, as part of the creation body), but does NOT subsequently
    /// PATCH the Deployment with the same annotation.  `updateNewReplicaSetAnnotations`
    /// only patches the Deployment when `SetNewReplicaSetAnnotations` returns true (i.e.,
    /// the RS revision CHANGED).  Since the RS was created with revision=1 already set,
    /// subsequent reconcile loops see no change and never patch the Deployment.
    ///
    /// Our fix: when a ReplicaSet is created with `deployment.kubernetes.io/revision` and
    /// an ownerReference pointing to a Deployment (controller=true), propagate that
    /// annotation to the Deployment atomically.
    ///
    /// This test MUST FAIL if `propagate_rs_revision_to_deployment` is removed, because
    /// the Deployment's annotation would stay null and the AdmissionWebhook conformance
    /// test's BeforeEach would time out waiting for `deployment.kubernetes.io/revision=1`.
    #[tokio::test]
    async fn rs_create_propagates_revision_annotation_to_owning_deployment() {
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

        let ns = "default";
        let deploy_name = "my-deployment";
        let deploy_uid = "abc-deploy-uid";

        // 1. Create the Deployment (no annotations — fresh from kubectl).
        let deployment = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": deploy_name,
                "namespace": ns,
                "labels": {"app": "myapp"}
            },
            "spec": {
                "selector": {"matchLabels": {"app": "myapp"}},
                "replicas": 1,
                "template": {
                    "metadata": {"labels": {"app": "myapp"}},
                    "spec": {"containers": [{"name": "c", "image": "busybox"}]}
                }
            }
        });
        let mut json_hdrs = axum::http::HeaderMap::new();
        json_hdrs.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        let _ = create_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                ns.to_string(),
                "deployments".to_string(),
            )),
            axum::extract::Query(super::super::json_patch::CreateQuery::default()),
            test_user(),
            json_hdrs.clone(),
            bytes::Bytes::from(serde_json::to_vec(&deployment).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Deployment create must succeed: {e:?}"))
        .into_response();

        // Verify Deployment has no revision annotation yet.
        let deploy_key = format!("/registry/apps/deployments/{ns}/{deploy_name}");
        let before = store
            .get(&deploy_key)
            .await
            .unwrap()
            .expect("Deployment must be stored");
        let before_val: serde_json::Value = serde_json::from_slice(&before.value).unwrap();
        assert!(
            before_val["metadata"]["annotations"]["deployment.kubernetes.io/revision"].is_null(),
            "Deployment must start with no revision annotation — precondition for the regression test"
        );

        // Fetch the Deployment UID to construct the ownerReference.
        let deploy_uid_stored = before_val["metadata"]["uid"]
            .as_str()
            .unwrap_or(deploy_uid)
            .to_string();

        // 2. KCM creates a ReplicaSet with revision=1 annotation and ownerRef pointing to Deployment.
        //    This is what KCM does in getNewReplicaSet: set revision in memory, then POST the RS.
        let rs = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": "my-deployment-79d557df97",
                "namespace": ns,
                "annotations": {
                    "deployment.kubernetes.io/revision": "1",
                    "deployment.kubernetes.io/desired-replicas": "1",
                    "deployment.kubernetes.io/max-replicas": "2"
                },
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": deploy_name,
                    "uid": deploy_uid_stored,
                    "controller": true,
                    "blockOwnerDeletion": true
                }],
                "labels": {
                    "app": "myapp",
                    "pod-template-hash": "79d557df97"
                }
            },
            "spec": {
                "selector": {"matchLabels": {"app": "myapp", "pod-template-hash": "79d557df97"}},
                "replicas": 1,
                "template": {
                    "metadata": {"labels": {"app": "myapp", "pod-template-hash": "79d557df97"}},
                    "spec": {"containers": [{"name": "c", "image": "busybox"}]}
                }
            }
        });
        let _ = create_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                ns.to_string(),
                "replicasets".to_string(),
            )),
            axum::extract::Query(super::super::json_patch::CreateQuery::default()),
            test_user(),
            json_hdrs,
            bytes::Bytes::from(serde_json::to_vec(&rs).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("ReplicaSet create must succeed: {e:?}"))
        .into_response();

        // 3. The Deployment must now have revision=1 propagated by our handler.
        //    Without propagate_rs_revision_to_deployment, this assertion fails —
        //    proving the test is a true regression guard.
        let after = store
            .get(&deploy_key)
            .await
            .unwrap()
            .expect("Deployment must still be stored after RS creation");
        let after_val: serde_json::Value = serde_json::from_slice(&after.value).unwrap();

        assert_eq!(
            after_val["metadata"]["annotations"]["deployment.kubernetes.io/revision"], "1",
            "Deployment must have deployment.kubernetes.io/revision=1 after KCM creates the RS — \
             KCM 1.36 sets the annotation on the RS body before POST but never subsequently \
             PATCHes the Deployment; without our propagation the annotation stays null and \
             the AdmissionWebhook conformance test BeforeEach times out"
        );
    }

    /// POST to a namespace whose status.phase is "Terminating" must return 403 Forbidden.
    /// Real kube-apiserver rejects all new object creation in a Terminating namespace;
    /// without this check our apiserver would allow objects to be created in dying namespaces,
    /// causing orphaned resources and breaking the namespace GC lifecycle.
    #[tokio::test]
    async fn create_namespaced_resource_rejects_terminating_namespace() {
        use axum::extract::State;
        use bytes::Bytes;
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

        // Seed the namespace object with status.phase = "Terminating".
        let ns_key = "/registry/namespaces/dying-ns";
        let ns_obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "dying-ns" },
            "status": { "phase": "Terminating" }
        });
        store
            .put(
                ns_key,
                Bytes::from(serde_json::to_vec(&ns_obj).unwrap()),
                None,
            )
            .await
            .expect("seed terminating namespace");

        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "test-cm", "namespace": "dying-ns" }
        });

        let result = create_namespaced_resource(
            State(state),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "dying-ns".to_string(),
                "configmaps".to_string(),
            )),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            json_headers(),
            Bytes::from(serde_json::to_vec(&cm).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "POST to Terminating namespace must be rejected — namespace GC would leave orphans otherwise"
            ),
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 403,
            "Terminating namespace must return 403 Forbidden"
        );
        assert_eq!(json["reason"], "Forbidden");
        assert!(
            json["message"].as_str().unwrap_or("").contains("dying-ns"),
            "error message must name the namespace"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("being terminated"),
            "error message must say namespace is being terminated"
        );
    }

    // -----------------------------------------------------------------------
    // Status preservation on PUT (mayor-pv04)
    // -----------------------------------------------------------------------

    /// PUT (full replace) on a StatefulSet must preserve the current stored status.
    ///
    /// Real kube-apiserver strips status from PUT bodies on the main endpoint
    /// AND restores the currently-stored status — controllers write status via
    /// /status; a spec-only PUT must not wipe their work.
    ///
    /// Without this fix, after `kubectl apply`, status.replicas resets to 0 or
    /// disappears. The KCM statefulset controller then must re-update status from
    /// scratch, but if there are concurrent OCC conflicts it may never converge
    /// — causing AfterEach to poll status.replicas==0 for 10 minutes (mayor-pv04).
    ///
    /// This test fails if the status restoration is removed from
    /// replace_namespaced_resource.
    #[tokio::test]
    async fn put_statefulset_preserves_stored_status() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed a StatefulSet with status.replicas = 3 (set by KCM).
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "web",
                "namespace": "default",
                "generation": 1,
                "uid": "aaaa-bbbb"
            },
            "spec": {
                "replicas": 3,
                "selector": { "matchLabels": { "app": "nginx" } },
                "template": {
                    "metadata": { "labels": { "app": "nginx" } },
                    "spec": { "containers": [{ "name": "nginx", "image": "nginx:latest" }] }
                }
            },
            "status": { "replicas": 3, "readyReplicas": 3, "observedGeneration": 1 }
        });
        let key = "/registry/apps/statefulsets/default/web";
        let stored_rv = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&sts).unwrap()),
                None,
            )
            .await
            .unwrap();

        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Client (kubectl scale / apply) PUTs spec-only body — no status field.
        // The stored status.replicas=3 must survive this PUT.
        let put_body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "web",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {
                "replicas": 0,
                "selector": { "matchLabels": { "app": "nginx" } },
                "template": {
                    "metadata": { "labels": { "app": "nginx" } },
                    "spec": { "containers": [{ "name": "nginx", "image": "nginx:latest" }] }
                }
            }
        });

        let result = replace_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "statefulsets".to_string(),
                "web".to_string(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("PUT StatefulSet must succeed, got: {e:?}"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::OK);

        // Read the stored object and verify status is preserved.
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["replicas"], 3,
            "status.replicas must be preserved after full PUT — the KCM writes \
             status via /status; a spec-only PUT must not wipe it out (mayor-pv04)"
        );
        assert_eq!(
            v["status"]["readyReplicas"], 3,
            "status.readyReplicas must be preserved after full PUT"
        );
        // The spec change must be applied.
        assert_eq!(
            v["spec"]["replicas"], 0,
            "spec.replicas must be updated by the PUT"
        );
    }

    /// PUT with an explicit status field in the body must NOT use the body's status
    /// — it must be stripped and the stored status used instead.
    ///
    /// This ensures clients cannot accidentally reset status via the main endpoint.
    /// This test fails if status stripping is removed from replace_namespaced_resource.
    #[tokio::test]
    async fn put_statefulset_ignores_body_status_uses_stored_status() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed StatefulSet with status.replicas=5 (KCM-set).
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "web",
                "namespace": "default"
            },
            "spec": {
                "replicas": 5,
                "selector": { "matchLabels": { "app": "web" } },
                "template": {
                    "metadata": { "labels": { "app": "web" } },
                    "spec": { "containers": [{ "name": "web", "image": "nginx" }] }
                }
            },
            "status": { "replicas": 5, "readyReplicas": 5 }
        });
        let key = "/registry/apps/statefulsets/default/web";
        let stored_rv = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&sts).unwrap()),
                None,
            )
            .await
            .unwrap();

        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Client PUTs with a stale/wrong status — must be ignored.
        let put_body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "web", "namespace": "default", "resourceVersion": stored_rv.to_string() },
            "spec": {
                "replicas": 5,
                "selector": { "matchLabels": { "app": "web" } },
                "template": {
                    "metadata": { "labels": { "app": "web" } },
                    "spec": { "containers": [{ "name": "web", "image": "nginx" }] }
                }
            },
            "status": { "replicas": 0, "readyReplicas": 0 }
        });

        let result = replace_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "statefulsets".to_string(),
                "web".to_string(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("PUT must succeed: {e:?}"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::OK);

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["replicas"], 5,
            "body status (replicas=0) must be ignored; stored status (replicas=5) \
             must be preserved — the main endpoint must not let clients reset status"
        );
    }

    // -- dryRun=All regression tests --
    //
    // These tests verify that ?dryRun=All never mutates the store.
    // If the fix is reverted (dry_run check removed), the stored object's identity
    // changes to the patched value, causing the assertion to fail.

    fn merge_patch_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        h
    }

    /// PATCH with ?dryRun=All must return the would-be patched object but must NOT
    /// mutate the stored object.  This is the primary regression guard for the fix:
    /// reverting the dry_run check in do_patch causes the stored holderIdentity to change
    /// to "patched-holder", failing the assertion.
    #[tokio::test]
    async fn patch_with_dry_run_all_does_not_mutate_store() {
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

        // Seed a Lease with holderIdentity="original-holder" directly in the store.
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/dry-run-lease";
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "dry-run-lease",
                "namespace": "kube-node-lease",
                "resourceVersion": "1"
            },
            "spec": { "holderIdentity": "original-holder", "leaseDurationSeconds": 40 }
        });
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();

        // PATCH with dryRun=All: change holderIdentity.
        let patch_body = serde_json::json!({"spec": {"holderIdentity": "patched-holder"}});
        let dry_run_query = PatchQuery {
            field_manager: None,
            _field_validation: None,
            dry_run: Some("All".to_string()),
        };
        let patch_resp = patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "dry-run-lease".to_string(),
            )),
            axum::extract::Query(dry_run_query),
            test_user(),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("dry-run PATCH must succeed (200): {e:?}"))
        .into_response();

        // The response must show the would-be patched value.
        let resp_bytes = to_bytes(patch_resp.into_body(), usize::MAX).await.unwrap();
        let resp_body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(
            resp_body["spec"]["holderIdentity"], "patched-holder",
            "dry-run response must show the would-be patched value"
        );

        // But the STORE must still have the original value — the write was skipped.
        let stored = store.get(key).await.unwrap().unwrap();
        let stored_body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_body["spec"]["holderIdentity"],
            "original-holder",
            "dry-run PATCH must NOT mutate the store — holderIdentity must remain 'original-holder'; \
             if this fails, the dryRun=All check was removed and the write went through"
        );
    }

    /// PUT (replace) with ?dryRun=All must return the would-be replaced object but
    /// must NOT persist it.  Reverting the dry_run check in replace_namespaced_resource
    /// causes the stored object's holderIdentity to change, failing the assertion.
    #[tokio::test]
    async fn replace_with_dry_run_all_does_not_mutate_store() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        // Seed a Lease (no resourceVersion → unconditional create).
        replace_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "dry-run-node".to_string(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "apiVersion": "coordination.k8s.io/v1",
                    "kind": "Lease",
                    "metadata": { "name": "dry-run-node", "namespace": "kube-node-lease" },
                    "spec": { "holderIdentity": "original-holder", "leaseDurationSeconds": 40 }
                }))
                .unwrap(),
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("seed Lease must succeed: {e:?}"));

        // PUT with dryRun=All: change holderIdentity to "new-holder".
        let dry_run_query = ReplaceQuery {
            _field_manager: None,
            dry_run: Some("All".to_string()),
        };
        let put_resp = replace_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "dry-run-node".to_string(),
            )),
            axum::extract::Query(dry_run_query),
            test_user(),
            json_headers(),
            bytes::Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "apiVersion": "coordination.k8s.io/v1",
                    "kind": "Lease",
                    "metadata": { "name": "dry-run-node", "namespace": "kube-node-lease" },
                    "spec": { "holderIdentity": "new-holder", "leaseDurationSeconds": 40 }
                }))
                .unwrap(),
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("dry-run PUT must succeed: {e:?}"))
        .into_response();

        // Response must show the would-be new holder.
        let resp_bytes = to_bytes(put_resp.into_body(), usize::MAX).await.unwrap();
        let resp_body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(
            resp_body["spec"]["holderIdentity"], "new-holder",
            "dry-run PUT response must show the would-be new value"
        );

        // The store must still have the original holder.
        let key = crate::keys::group_object_key(
            "coordination.k8s.io",
            "leases",
            Some("kube-node-lease"),
            "dry-run-node",
        );
        let stored = state.store.get(&key).await.unwrap().unwrap();
        let stored_body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_body["spec"]["holderIdentity"],
            "original-holder",
            "dry-run PUT must NOT mutate the store — holderIdentity must remain 'original-holder'; \
             if this fails, the dryRun=All check in replace_namespaced_resource was removed"
        );
    }

    /// POST with ?dryRun=All must return 201 with the would-be object but must NOT
    /// persist it.  Reverting the dry_run check in create_namespaced_resource causes
    /// the store to contain the Lease, failing the assertion.
    #[tokio::test]
    async fn create_with_dry_run_all_does_not_mutate_store() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "dry-run-new-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "new-node", "leaseDurationSeconds": 40 }
        });
        let dry_run_query = CreateQuery {
            _field_manager: None,
            field_validation: None,
            dry_run: Some("All".to_string()),
        };
        let create_resp = create_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
            )),
            axum::extract::Query(dry_run_query),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("dry-run POST must succeed: {e:?}"))
        .into_response();

        // Response must be 201 with the would-be object.
        assert_eq!(
            create_resp.status(),
            axum::http::StatusCode::CREATED,
            "dry-run POST must return 201 CREATED"
        );
        let resp_bytes = to_bytes(create_resp.into_body(), usize::MAX).await.unwrap();
        let resp_body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(resp_body["metadata"]["name"], "dry-run-new-lease");

        // The store must NOT contain the Lease — the write was skipped.
        let key = crate::keys::group_object_key(
            "coordination.k8s.io",
            "leases",
            Some("kube-node-lease"),
            "dry-run-new-lease",
        );
        let stored = state.store.get(&key).await.unwrap();
        assert!(
            stored.is_none(),
            "dry-run POST must NOT persist the object — store must remain empty; \
             if this fails, the dryRun=All check in create_namespaced_resource was removed"
        );
    }

    /// SSA PATCH (application/apply-patch+yaml) with ?dryRun=All must return the would-be
    /// result but must NOT persist the change.  This is the regression test for the kubectl
    /// diff (Deployment) and kubectl server-side dry-run paths: both send SSA PATCH with
    /// dryRun=All.  If do_patch's dry_run guard is removed, the stored spec changes.
    #[tokio::test]
    async fn ssa_patch_with_dry_run_all_does_not_mutate_store() {
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

        // Seed a Lease with holderIdentity="original-ssa-holder".
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/ssa-dry-run-lease";
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "ssa-dry-run-lease",
                "namespace": "kube-node-lease",
                "resourceVersion": "1"
            },
            "spec": { "holderIdentity": "original-ssa-holder", "leaseDurationSeconds": 40 }
        });
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();

        // SSA PATCH with dryRun=All: change holderIdentity.
        let patch_body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "ssa-dry-run-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "new-ssa-holder", "leaseDurationSeconds": 40 }
        });
        let dry_run_query = PatchQuery {
            field_manager: Some("kubectl-client-side-apply".to_string()),
            _field_validation: None,
            dry_run: Some("All".to_string()),
        };

        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        let patch_resp = patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "coordination.k8s.io".to_string(),
                "v1".to_string(),
                "kube-node-lease".to_string(),
                "leases".to_string(),
                "ssa-dry-run-lease".to_string(),
            )),
            axum::extract::Query(dry_run_query),
            test_user(),
            ssa_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("SSA dry-run PATCH must succeed: {e:?}"))
        .into_response();

        // The response must show the would-be new holder.
        let resp_bytes = to_bytes(patch_resp.into_body(), usize::MAX).await.unwrap();
        let resp_body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(
            resp_body["spec"]["holderIdentity"], "new-ssa-holder",
            "SSA dry-run response must show the would-be new holderIdentity"
        );

        // The store must still have the original holder — the write was skipped.
        let stored = store.get(key).await.unwrap().unwrap();
        let stored_body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_body["spec"]["holderIdentity"], "original-ssa-holder",
            "SSA PATCH with dryRun=All must NOT mutate the store — holderIdentity must remain \
             'original-ssa-holder'; if this fails, do_patch's dry_run guard was removed and \
             kubectl diff / kubectl server-side dry-run tests will fail"
        );
    }

    // -- Regression: EndpointSlice mirroring blocked by last-change-trigger-time (mayor-tjtl) --

    /// PUT on an Endpoints object must clear `endpoints.kubernetes.io/last-change-trigger-time`.
    ///
    /// Root cause: the KCM endpoints-controller stamps this annotation on Endpoints it owns.
    /// When the user then PUTs custom subsets, the annotation persists and the KCM mirroring
    /// controller sees it and skips mirroring — no EndpointSlice is ever created.
    /// Clearing the annotation on user PUT signals "user-managed" to the mirroring controller.
    #[tokio::test]
    async fn put_endpoints_clears_last_change_trigger_time_annotation() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        // First create an Endpoints object (simulating what the KCM endpoints-controller
        // creates for a Service — with the annotation stamped).
        let ep_with_annotation = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Endpoints",
            "metadata": {
                "name": "my-svc",
                "namespace": "default",
                "annotations": {
                    "endpoints.kubernetes.io/last-change-trigger-time": "2024-01-01T00:00:00Z"
                }
            },
            "subsets": []
        });
        let _ = replace_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "endpoints".to_string(),
                "my-svc".to_string(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&ep_with_annotation).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("initial Endpoints PUT must succeed: {e:?}"));

        // Now simulate the user overwriting the Endpoints with custom subsets.
        // The annotation is still present in the body (it was retrieved from the API and re-PUT).
        let ep_user_put = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Endpoints",
            "metadata": {
                "name": "my-svc",
                "namespace": "default",
                "annotations": {
                    "endpoints.kubernetes.io/last-change-trigger-time": "2024-01-01T00:00:00Z"
                }
            },
            "subsets": [{"addresses": [{"ip": "10.0.0.1"}], "ports": [{"port": 8080}]}]
        });
        let resp = replace_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "endpoints".to_string(),
                "my-svc".to_string(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&ep_user_put).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("user PUT of Endpoints must succeed: {e:?}"))
        .into_response();

        let resp_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let resp_body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        assert!(
            resp_body["metadata"]["annotations"]
                ["endpoints.kubernetes.io/last-change-trigger-time"]
                .is_null(),
            "PUT on Endpoints must clear 'endpoints.kubernetes.io/last-change-trigger-time'; \
             if this annotation persists, the KCM mirroring controller skips the object and \
             no EndpointSlice is created — EndpointSliceMirroring conformance test fails"
        );
    }

    /// PATCH on an Endpoints object must clear `endpoints.kubernetes.io/last-change-trigger-time`.
    ///
    /// Same root cause as the PUT case: the annotation signals KCM-managed endpoints and
    /// blocks the mirroring controller.  A user PATCH must also clear it.
    #[tokio::test]
    async fn patch_endpoints_clears_last_change_trigger_time_annotation() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        // Create the Endpoints with the annotation.
        let ep_with_annotation = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Endpoints",
            "metadata": {
                "name": "patched-svc",
                "namespace": "default",
                "annotations": {
                    "endpoints.kubernetes.io/last-change-trigger-time": "2024-01-01T00:00:00Z"
                }
            },
            "subsets": []
        });
        let _ = replace_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "endpoints".to_string(),
                "patched-svc".to_string(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&ep_with_annotation).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("initial Endpoints PUT must succeed: {e:?}"));

        // PATCH with merge-patch to update subsets (annotation still present in store).
        let merge_patch = serde_json::json!({
            "subsets": [{"addresses": [{"ip": "10.0.0.2"}], "ports": [{"port": 9090}]}]
        });
        let mut merge_headers = axum::http::HeaderMap::new();
        merge_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        let resp = patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "endpoints".to_string(),
                "patched-svc".to_string(),
            )),
            axum::extract::Query(PatchQuery::default()),
            test_user(),
            merge_headers,
            bytes::Bytes::from(serde_json::to_vec(&merge_patch).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("merge-patch on Endpoints must succeed: {e:?}"))
        .into_response();

        let resp_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let resp_body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        assert!(
            resp_body["metadata"]["annotations"]
                ["endpoints.kubernetes.io/last-change-trigger-time"]
                .is_null(),
            "PATCH on Endpoints must clear 'endpoints.kubernetes.io/last-change-trigger-time'; \
             if this annotation persists, the KCM mirroring controller skips the object and \
             no EndpointSlice is created — EndpointSliceMirroring conformance test fails"
        );
    }

    /// VAP observedGeneration must be set so conformance test framework does not hang
    /// waiting for policy readiness.
    ///
    /// The Kubernetes conformance e2e framework polls
    ///   GET /apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/<name>
    /// and waits until status.observedGeneration == metadata.generation before proceeding.
    /// Without this field the poll never resolves and every VAP conformance test hangs
    /// until the global Ginkgo suite timeout (~30 min).
    #[tokio::test]
    async fn vap_create_sets_observed_generation_and_ready_condition() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let vap = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": { "name": "test-vap" },
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{ "apiGroups": [""], "apiVersions": ["v1"],
                                        "operations": ["CREATE"], "resources": ["pods"] }]
                },
                "validations": [{ "expression": "true" }]
            }
        });
        let body = bytes::Bytes::from(serde_json::to_vec(&vap).unwrap());

        let resp = create_resource(
            State(state.clone()),
            axum::extract::Path((
                "admissionregistration.k8s.io".to_string(),
                "v1".to_string(),
                "validatingadmissionpolicies".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .unwrap_or_else(|e| panic!("VAP create must succeed: {e:?}"))
        .into_response();

        let resp_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        let observed_gen = body["status"]["observedGeneration"].as_i64();
        assert!(
            observed_gen.is_some() && observed_gen.unwrap() >= 1,
            "status.observedGeneration must be set after VAP create — conformance framework \
             polls observedGeneration == metadata.generation and hangs forever if absent; got {:?}",
            body["status"]
        );

        let conditions = body["status"]["conditions"].as_array();
        assert!(
            conditions.is_some() && !conditions.unwrap().is_empty(),
            "status.conditions must be set after VAP create — conformance test checks for \
             Ready condition before proceeding; got {:?}",
            body["status"]
        );

        let ready = conditions
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("Ready") && c["status"].as_str() == Some("True"));
        assert!(
            ready.is_some(),
            "status.conditions must contain Ready=True after VAP create — conformance framework \
             waits for policy readiness before running admission tests; got {:?}",
            body["status"]["conditions"]
        );
    }

    /// VAPB (ValidatingAdmissionPolicyBinding) observedGeneration must be set on create
    /// so the conformance framework does not hang waiting for binding readiness.
    #[tokio::test]
    async fn vapb_create_sets_observed_generation_and_ready_condition() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let vapb = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": { "name": "test-vapb" },
            "spec": {
                "policyName": "test-vap",
                "validationActions": ["Deny"]
            }
        });
        let body = bytes::Bytes::from(serde_json::to_vec(&vapb).unwrap());

        let resp = create_resource(
            State(state.clone()),
            axum::extract::Path((
                "admissionregistration.k8s.io".to_string(),
                "v1".to_string(),
                "validatingadmissionpolicybindings".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .unwrap_or_else(|e| panic!("VAPB create must succeed: {e:?}"))
        .into_response();

        let resp_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        let observed_gen = body["status"]["observedGeneration"].as_i64();
        assert!(
            observed_gen.is_some() && observed_gen.unwrap() >= 1,
            "status.observedGeneration must be set after VAPB create — conformance framework \
             polls observedGeneration == metadata.generation and hangs forever if absent; got {:?}",
            body["status"]
        );
    }

    /// VAP GET after create must return the same status.observedGeneration that was set
    /// on create — proving the status was persisted to the store, not just in the response.
    #[tokio::test]
    async fn vap_get_after_create_returns_persisted_observed_generation() {
        use axum::body::to_bytes;

        let state = make_state();

        let vap = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": { "name": "test-vap-persist" },
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{ "apiGroups": [""], "apiVersions": ["v1"],
                                        "operations": ["CREATE"], "resources": ["pods"] }]
                },
                "validations": [{ "expression": "true" }]
            }
        });
        let body = bytes::Bytes::from(serde_json::to_vec(&vap).unwrap());

        create_resource(
            State(state.clone()),
            axum::extract::Path((
                "admissionregistration.k8s.io".to_string(),
                "v1".to_string(),
                "validatingadmissionpolicies".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .unwrap_or_else(|e| panic!("VAP create must succeed: {e:?}"));

        let get_resp = get_resource(
            State(state.clone()),
            axum::extract::Path((
                "admissionregistration.k8s.io".to_string(),
                "v1".to_string(),
                "validatingadmissionpolicies".to_string(),
                "test-vap-persist".to_string(),
            )),
        )
        .await
        .unwrap_or_else(|e| panic!("VAP get must succeed: {e:?}"));

        let resp_bytes = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        let observed_gen = body["status"]["observedGeneration"].as_i64();
        assert!(
            observed_gen.is_some() && observed_gen.unwrap() >= 1,
            "GET must return persisted status.observedGeneration — if only set in the create \
             response but not stored, the conformance framework's poll loop will never see it \
             and will hang; got {:?}",
            body["status"]
        );
    }

    fn builtin_match_constraints() -> serde_json::Value {
        serde_json::json!({
            "resourceRules": [{
                "apiGroups": ["apps"],
                "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"],
                "resources": ["deployments"]
            }]
        })
    }

    fn crd_match_constraints() -> serde_json::Value {
        serde_json::json!({
            "resourceRules": [{
                "apiGroups": ["example.io"],
                "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"],
                "resources": ["foos"]
            }]
        })
    }

    /// A valid expression must produce no warnings — the conformance test polls
    /// status.typeChecking and asserts expressionWarnings is empty.  If we emit
    /// spurious warnings here the test fails asserting len == 0.
    #[test]
    fn cel_type_warnings_valid_expression_returns_empty() {
        let validations = serde_json::json!([
            { "expression": "object.spec.replicas > 1" }
        ]);
        let warnings = cel_type_warnings(&validations, &builtin_match_constraints());
        assert_eq!(
            warnings.as_array().unwrap().len(),
            0,
            "valid expression must produce no warnings; conformance test polls until \
             typeChecking is set then asserts expressionWarnings is empty"
        );
    }

    /// Comparing an int field with a string literal using > must warn — the
    /// conformance test asserts a warning with overload text for (int, string).
    #[test]
    fn cel_type_warnings_int_vs_string_gt_produces_warning() {
        let validations = serde_json::json!([
            { "expression": "object.spec.replicas > '1'" }
        ]);
        let warnings = cel_type_warnings(&validations, &builtin_match_constraints());
        let arr = warnings.as_array().unwrap();
        assert_eq!(
            arr.len(),
            1,
            "int-vs-string > must produce exactly one warning; \
             conformance test asserts expressionWarnings has specific entries"
        );
        assert_eq!(
            arr[0]["fieldRef"], "spec.validations[0].expression",
            "fieldRef must point to the validation expression index"
        );
        let warning = arr[0]["warning"].as_str().unwrap();
        assert!(
            warning.contains("_>_") && warning.contains("(int, string)"),
            "warning must name the operator and type pair so conformance test substring match passes; got: {warning}"
        );
    }

    /// String concatenation with an int via + must warn — the conformance test
    /// asserts a warning with overload text for (string, int) in messageExpression.
    #[test]
    fn cel_type_warnings_string_plus_int_in_message_expression_produces_warning() {
        let validations = serde_json::json!([
            {
                "expression": "object.spec.replicas > '1'",
                "messageExpression": "'wants replicas > 1, got ' + object.spec.replicas"
            }
        ]);
        let warnings = cel_type_warnings(&validations, &builtin_match_constraints());
        let arr = warnings.as_array().unwrap();
        assert_eq!(
            arr.len(),
            2,
            "both expression and messageExpression must produce warnings; \
             conformance test asserts exactly 2 entries"
        );
        let msg_warning = arr.iter().find(|w| {
            w["fieldRef"]
                .as_str()
                .is_some_and(|r| r.contains("messageExpression"))
        });
        assert!(
            msg_warning.is_some(),
            "one warning must reference messageExpression fieldRef"
        );
        let w_text = msg_warning.unwrap()["warning"].as_str().unwrap();
        assert!(
            w_text.contains("_+_") && w_text.contains("(string, int)"),
            "messageExpression warning must name _+_ and (string, int); got: {w_text}"
        );
    }

    /// For a CRD-targeting VAP, object.spec.<unknown-field> must warn about
    /// undefined field — the conformance test polls until expressionWarnings is
    /// non-empty and asserts the undefined-field warning exists.
    #[test]
    fn cel_type_warnings_undefined_crd_field_produces_warning() {
        let validations = serde_json::json!([
            { "expression": "object.spec.maxRetries < 10" }
        ]);
        let warnings = cel_type_warnings(&validations, &crd_match_constraints());
        let arr = warnings.as_array().unwrap();
        assert_eq!(
            arr.len(),
            1,
            "object.spec.<unknown-field> on a CRD-targeting VAP must warn; \
             conformance test polls until expressionWarnings is non-empty"
        );
        let w_text = arr[0]["warning"].as_str().unwrap();
        assert!(
            w_text.contains("maxRetries"),
            "warning must name the unknown field; got: {w_text}"
        );
    }

    /// For a CRD-targeting VAP, object.spec.replicas must NOT warn — it is in
    /// the built-in-field whitelist.  The conformance test's first (valid) VAP
    /// asserts expressionWarnings is empty; a false positive here would fail it.
    #[test]
    fn cel_type_warnings_known_field_on_crd_is_not_flagged() {
        let validations = serde_json::json!([
            { "expression": "object.spec.replicas > 1" }
        ]);
        let warnings = cel_type_warnings(&validations, &crd_match_constraints());
        assert_eq!(
            warnings.as_array().unwrap().len(),
            0,
            "object.spec.replicas is a known field and must not produce warnings \
             even when targeting a CRD group"
        );
    }

    /// PATCH on the collection endpoint must apply the patch body to every
    /// resource that matches the labelSelector.  Without this handler the
    /// conformance test "should list, patch and delete a collection of
    /// StatefulSets" fails because axum returns 405 Method Not Allowed.
    #[tokio::test]
    async fn patch_collection_namespaced_resource_applies_patch_to_matched_objects() {
        use axum::body::to_bytes;
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        for name in &["lease-a", "lease-b"] {
            let body = serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns",
                    "labels": { "app": "target" }
                },
                "spec": { "holderIdentity": "original" }
            });
            create_namespaced_resource(
                State(state.clone()),
                Path((
                    "coordination.k8s.io".into(),
                    "v1".into(),
                    "test-ns".into(),
                    "leases".into(),
                )),
                axum::extract::Query(CreateQuery::default()),
                test_user(),
                json_headers(),
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            )
            .await
            .unwrap_or_else(|_| panic!("lease create must succeed"));
        }

        let unrelated = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "lease-unrelated",
                "namespace": "test-ns",
                "labels": { "app": "other" }
            },
            "spec": { "holderIdentity": "untouched" }
        });
        create_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "test-ns".into(),
                "leases".into(),
            )),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&unrelated).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("unrelated lease create must succeed"));

        let mut patch_headers = axum::http::HeaderMap::new();
        patch_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        let patch = serde_json::json!({"spec": {"holderIdentity": "patched"}});

        let result = patch_collection_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "test-ns".into(),
                "leases".into(),
            )),
            Query(CollectionQuery {
                label_selector: Some("app=target".into()),
                watch: None,
                resource_version: None,
                field_selector: None,
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            }),
            Query(PatchQuery::default()),
            test_user(),
            patch_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("collection PATCH must succeed: {e:?}"));

        let resp = result.into_response();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let list: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let items = list["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            2,
            "collection PATCH must return only the two matched objects, not the unrelated one"
        );
        for item in items {
            assert_eq!(
                item["spec"]["holderIdentity"], "patched",
                "every matched lease must have holderIdentity updated to 'patched'; \
                 if this fails, the collection PATCH handler stopped applying the patch"
            );
        }

        let unrelated_key = "/registry/coordination.k8s.io/leases/test-ns/lease-unrelated";
        let stored = state
            .store
            .get(unrelated_key)
            .await
            .expect("store get must succeed")
            .expect("unrelated lease must still exist");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["holderIdentity"], "untouched",
            "unmatched lease must not be patched — labelSelector filtering is broken \
             if this fails"
        );
    }

    /// PUT on a Secret with `immutable: true` must return 422 Invalid when the caller
    /// attempts to modify the data field.
    ///
    /// The conformance test "should be immutable if `immutable` field is set" (secrets_volume.go:407)
    /// creates an immutable Secret then PUTs an update to its data.  Real kube-apiserver returns
    /// 422 "Invalid"; without this check u7s returns 200 OK, causing the test to fail with
    /// "expected 'invalid' as error, got instead: <nil>".
    ///
    /// This test fails if the immutability check is removed from replace_namespaced_resource.
    #[tokio::test]
    async fn replace_immutable_secret_returns_422() {
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        // Step 1: create the secret with immutable:true via PUT (upsert)
        let secret_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "my-immutable", "namespace": "default" },
            "immutable": true,
            "data": { "key1": "dmFsdWUx" }
        });
        let result = replace_namespaced_resource(
            State(state.clone()),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "secrets".into(),
                "my-immutable".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&secret_v1).unwrap()),
        )
        .await;
        let _ = result
            .expect("initial secret create must succeed")
            .into_response();

        // Step 2: try to modify data — must be rejected with 422
        let secret_v2 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "my-immutable", "namespace": "default" },
            "immutable": true,
            "data": { "key1": "bmV3dmFsdWU=" }  // different value
        });
        let result = replace_namespaced_resource(
            State(state.clone()),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "secrets".into(),
                "my-immutable".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&secret_v2).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "PUT on immutable secret with changed data must return 422 Invalid — without this \
                 check u7s accepts the update and the conformance test 'should be immutable if \
                 immutable field is set' fails with 'expected invalid as error, got nil'"
            ),
            Ok(_) => panic!(
                "PUT on immutable secret must return 422, not 200 — immutability enforcement is \
                 missing from replace_namespaced_resource"
            ),
        }
    }

    /// PATCH on a Secret with `immutable: true` must return 422 Invalid.
    ///
    /// Mirrors the PUT test above but for PATCH (merge-patch).  Immutable secrets must reject
    /// all modification attempts regardless of the HTTP method used.
    ///
    /// This test fails if the immutability check is removed from do_patch.
    #[tokio::test]
    async fn patch_immutable_secret_returns_422() {
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        // Step 1: create the secret with immutable:true
        let secret_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "patched-immutable", "namespace": "default" },
            "immutable": true,
            "data": { "key1": "dmFsdWUx" }
        });
        let result = replace_namespaced_resource(
            State(state.clone()),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "secrets".into(),
                "patched-immutable".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&secret_v1).unwrap()),
        )
        .await;
        let _ = result
            .expect("initial secret create must succeed")
            .into_response();

        // Step 2: PATCH to modify data — must be rejected with 422
        let patch = serde_json::json!({ "data": { "key1": "bmV3dmFsdWU=" } });
        let mut merge_headers = json_headers();
        merge_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        let result = patch_namespaced_resource(
            State(state),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "secrets".into(),
                "patched-immutable".into(),
            )),
            Query(PatchQuery::default()),
            test_user(),
            merge_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "PATCH on immutable secret must return 422 Invalid — immutability must be \
                 enforced for all write methods, not just PUT"
            ),
            Ok(_) => panic!(
                "PATCH on immutable secret must return 422 — immutability check is missing \
                 from do_patch"
            ),
        }
    }
}
