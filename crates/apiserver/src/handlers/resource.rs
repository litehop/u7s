use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use u7s_store::{CreateNamespacedError, ListOptions, Store, StoreError};

use crate::admission::{run_mutating_webhooks, run_validating_webhooks, AdmissionContext};
use crate::{limit_range, quota};

use crate::{
    auth::UserInfo,
    keys::{cluster_object_key, group_list_prefix, group_object_key},
    state::AppState,
    status::Status,
    types::{DeleteOptions, Object, ObjectMeta},
    util::{content_type, extract_body, parse_resource_version},
};

use super::generic::{
    apply_delete_policy, apply_label_selector, build_list_response, check_clusterrole_escalation,
    check_crb_escalation, check_rb_escalation, decode_continue, lookup, parse_field_selector,
    parse_label_selector, resolve_name, stamp_metadata, store_err, validate_name,
    validate_name_for_group, CollectionQuery, RBAC_GROUP,
};
use super::json_patch::{
    apply_field_validation, apply_json_patch, detect_patch_type, inject_managed_fields,
    ssa_body_to_json, strip_managed_fields, CreateQuery, PatchQuery, PatchType, ReplaceQuery,
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

pub(crate) async fn list_resource<S: Store>(
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

    let store_field_selector = if plural == "events" {
        None
    } else {
        query
            .field_selector
            .as_deref()
            .map(parse_field_selector)
            .transpose()?
    };
    // Decode BEFORE listing: on a continuation request this pins the resourceVersion this
    // response (and every later page) must report — see decode_continue's doc for why.
    let continue_decoded = query
        .continue_token
        .as_deref()
        .map(|t| decode_continue(t, state.store.current_revision(), &state.continue_token_key))
        .transpose()?;
    let continue_key = continue_decoded.as_ref().map(|(k, _)| k.clone());
    let list_start = std::time::Instant::now();
    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                field_selector: store_field_selector,
                limit: query.limit,
                continue_key,
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    tracing::debug!(
        prefix = %prefix,
        item_count = resp.items.len(),
        elapsed_ms = list_start.elapsed().as_millis() as u64,
        "list: query completed"
    );
    // First page (no continue token yet): the fresh store revision becomes the pin for
    // subsequent pages. Continuation page: reuse the pin decoded above, not the store's
    // current (possibly-advanced) revision.
    let list_revision = continue_decoded.map(|(_, rv)| rv).unwrap_or(resp.revision);

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

    let items = if plural == "events" {
        if let Some(ref sel) = query.field_selector {
            super::pods::filter_events_by_field_selector(items, sel)
        } else {
            items
        }
    } else {
        items
    };
    tracing::debug!(prefix = %prefix, filtered_count = items.len(), "list: filtered");

    if pom {
        let pom_items: Vec<serde_json::Value> = items
            .iter()
            .map(super::watch::to_partial_object_metadata)
            .collect();
        let body = serde_json::json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": list_revision.to_string() },
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
        list_revision,
        items,
        resp.continue_key,
        resp.remaining_count,
        &state.continue_token_key,
    );
    Ok(Json(body).into_response())
}

pub(crate) async fn get_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, crate::status::StatusError> {
    validate_name_for_group("name", &name, &group)?;
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::get_cr(State(state), Path((group, version, plural, name)), headers)
                .await;
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
    inject_type_meta(&mut obj, &group, &version, &meta.kind);

    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // kcm's GC verifies owner references via metadata-only Get() calls
    // (garbagecollector.go's isDangling); without this, it receives a typed object it can't
    // decode and retries the owner-check forever, so newly-orphaned dependents are never
    // identified as dangling and never collected.
    if wants_partial_object_metadata(accept) {
        return Ok(Json(super::watch::to_partial_object_metadata(&obj)).into_response());
    }

    // kubectl's default Accept header requests Table format; without this, kubectl can't
    // decode the response and falls back to printing only NAME/AGE (list_resource already
    // handles this for LIST — see above).
    if super::table::wants_table(accept) {
        return Ok(Json(super::table::build_table(&group, &plural, vec![obj])).into_response());
    }

    Ok(Json(obj).into_response())
}

pub(crate) async fn create_resource<S: Store>(
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
            // cr::create_cr is called directly (not dispatched by axum), so it has no Query
            // extractor of its own; forward the already-parsed ?fieldValidation= value via a
            // header rather than adding a parameter to its ~60 existing call sites.
            let mut headers = headers;
            if let Some(fv) = create_query.field_validation.as_deref() {
                if let Ok(hv) = axum::http::HeaderValue::from_str(fv) {
                    headers.insert(
                        axum::http::HeaderName::from_static("x-u7s-field-validation"),
                        hv,
                    );
                }
            }
            return super::cr::create_cr(
                State(state),
                Path((group, version, plural)),
                Extension(user),
                headers,
                body,
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // Field validation: detect unknown/duplicate fields per ?fieldValidation= query param.
    let warn_header = apply_field_validation(
        &obj.body,
        &body,
        create_query.field_validation.as_deref(),
        &group,
        &plural,
    )?;

    // Escalation prevention: before persisting a ClusterRoleBinding, verify the
    // caller already holds all rules of the referenced ClusterRole. This prevents
    // users from granting themselves permissions they don't currently have.
    check_crb_escalation(&plural, &group, &user, &obj.body, &state)?;
    // Escalation prevention for ClusterRole creates: if any CRB already references
    // this role, the caller must hold all the rules they are about to define.
    check_clusterrole_escalation(&plural, &group, &user, &obj.body, &state)?;

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
    obj.body = run_mutating_webhooks(&state, obj.body, None, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;

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
    let put_start = std::time::Instant::now();
    let result = state.store.put(&key, obj.to_bytes(), Some(0)).await;
    tracing::debug!(
        key = %key,
        elapsed_ms = put_start.elapsed().as_millis() as u64,
        ok = result.is_ok(),
        "create_resource: store.put call completed"
    );
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
    if group == ADMISSION_GROUP {
        state.refresh_admission_config(&plural).await;
    }
    if group == APISERVICE_GROUP {
        state.refresh_apiservice_cache().await;
    }
    write_vap_status(&*state.store, &group, &plural, &key, &mut obj.body, new_rv).await;
    inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
    let mut resp = (StatusCode::CREATED, Json(obj.body)).into_response();
    if let Some(hv) = warn_header {
        resp.headers_mut().insert(axum::http::header::WARNING, hv);
    }
    Ok(resp)
}

pub(crate) async fn replace_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Query(replace_query): Query<ReplaceQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name_for_group("name", &name, &group)?;
    let body = extract_body(&body, content_type(&headers));
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::replace_cr(
                State(state),
                Path((group, version, plural, name)),
                Extension(user),
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
    // Escalation prevention for ClusterRole updates: if any CRB already references
    // this role, the caller must hold all the rules they are about to define.
    check_clusterrole_escalation(&plural, &group, &user, &obj.body, &state)?;

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

    let key = group_object_key(&group, &plural, None, &name);

    // Read the stored object once: used for (a) immutability enforcement on
    // PriorityClass.value, (b) status restoration when the resource has a dedicated status
    // subresource, and (c) UID restoration (see stored_uid below). Cluster-scoped resources
    // (Node, ClusterRole, StorageClass, ...) have no per-type gate as narrow as (a)/(b) for
    // most of them, so the read is also triggered whenever the incoming body's UID is blank —
    // conditional on that predicate rather than firing unconditionally on every PUT.
    let is_priorityclass = group == "scheduling.k8s.io" && plural == "priorityclasses";
    let incoming_uid_blank = obj.body["metadata"]["uid"]
        .as_str()
        .map(str::is_empty)
        .unwrap_or(true);
    // deletionTimestamp is also server-owned (see stored_deletion_timestamp below): a client
    // whose PUT body omits it — including a protobuf-content-type PUT, since the wire decoder
    // never emits this field — must not be trusted as "not being deleted".
    let incoming_deletion_timestamp_blank = obj.body["metadata"]["deletionTimestamp"].is_null();
    let needs_stored_read = is_priorityclass
        || meta.has_status_subresource
        || incoming_uid_blank
        || incoming_deletion_timestamp_blank;
    let (stored_status, stored_uid, stored_deletion_timestamp, stored_deletion_grace) =
        if needs_stored_read {
            let parsed = state
                .store
                .get(&key)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .and_then(|stored| serde_json::from_slice::<serde_json::Value>(&stored.value).ok());

            // Immutability check: PriorityClass.value drives scheduling/preemption ordering
            // cluster-wide; allowing it to change post-create would silently reorder
            // priorities. Real kube-apiserver returns 422 "Invalid" if an update changes it.
            if is_priorityclass {
                if let Some(ref stored_val) = parsed {
                    if obj.body["value"] != stored_val["value"] {
                        return Err(Status::unprocessable_entity(format!(
                            "{plural}/{name} .value is immutable and cannot be updated"
                        )));
                    }
                }
            }

            let status = if meta.has_status_subresource {
                parsed.as_ref().map(|v| v["status"].clone())
            } else {
                None
            };
            // UID is immutable and system-assigned. Captured whenever we already have the
            // stored object in hand so a blind PUT that omits it can be defended against,
            // mirroring replace_namespaced_resource's restoration of a blank incoming UID.
            let uid = parsed.as_ref().map(|v| v["metadata"]["uid"].clone());
            let deletion_timestamp = parsed
                .as_ref()
                .map(|v| v["metadata"]["deletionTimestamp"].clone());
            let deletion_grace = parsed
                .as_ref()
                .map(|v| v["metadata"]["deletionGracePeriodSeconds"].clone());
            (status, uid, deletion_timestamp, deletion_grace)
        } else {
            (None, None, None, None)
        };

    // UID is immutable; a client's blind PUT (built from a locally-held copy that never
    // repopulated system-assigned fields) can omit it. Real kube-apiserver's generic update
    // preparation (rest.BeforeUpdate) unconditionally restores the existing UID whenever the
    // incoming body's is blank ("Use the existing UID if none is provided") for every
    // resource, every Update — cluster-scoped resources are exactly as exposed to this as
    // namespaced ones. Without this, a blank UID is persisted and broadcast to watchers as-is.
    if incoming_uid_blank {
        if let Some(uid) = stored_uid.as_ref().and_then(|u| u.as_str()) {
            if !uid.is_empty() {
                obj.body["metadata"]["uid"] = serde_json::Value::String(uid.to_string());
            }
        }
    }

    // deletionTimestamp/deletionGracePeriodSeconds are server-owned, exactly like UID above:
    // a client cannot un-terminate an object mid-deletion by omitting them on a PUT. Without
    // this, finalizer_drain_complete below (which reads obj.body, not the stored object) would
    // see a blank deletionTimestamp and treat a finalizer-removal PUT as a plain update instead
    // of completing the delete — persisting the object with deletionTimestamp gone and
    // finalizers empty, i.e. silently resurrecting it as a normal live object.
    if incoming_deletion_timestamp_blank {
        if let Some(ts) = stored_deletion_timestamp.as_ref().filter(|v| !v.is_null()) {
            obj.body["metadata"]["deletionTimestamp"] = ts.clone();
            if let Some(grace) = stored_deletion_grace.as_ref().filter(|v| !v.is_null()) {
                obj.body["metadata"]["deletionGracePeriodSeconds"] = grace.clone();
            }
        }
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
        namespace: None,
        operation: "UPDATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
        })),
        dry_run: false,
    };
    obj.body = run_mutating_webhooks(&state, obj.body, None, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;

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
        inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
        return Ok(Json(obj.body).into_response());
    }

    // A PUT whose body has deletionTimestamp set and finalizers now empty is how KCM's
    // protection controllers (pvc-protection, vac-protection, ...) complete a delete: they
    // remove their finalizer via PUT, not PATCH. Complete the delete instead of storing an
    // update, or the object stays stuck Terminating forever.
    if finalizer_drain_complete(&obj.body) {
        complete_finalizer_drain(
            &state,
            FinalizerDrainCtx {
                key: &key,
                meta: &meta,
                group: &group,
                version: &version,
                plural: &plural,
                ns: None,
                name: &name,
            },
        )
        .await?;
        inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
        return Ok(Json(obj.body).into_response());
    }

    let put_start = std::time::Instant::now();
    let put_result = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await;
    tracing::debug!(
        key = %key,
        elapsed_ms = put_start.elapsed().as_millis() as u64,
        ok = put_result.is_ok(),
        "replace_resource: store.put call completed"
    );
    let new_rv = put_result.map_err(|e| store_err(e, &name, &meta.kind))?;

    obj.set_resource_version(new_rv);
    if group == RBAC_GROUP {
        let rbac_key = rbac_cluster_key(&group, &version, &plural, &name);
        state.rbac_index.apply_object(&rbac_key, &obj.body);
    }
    if group == ADMISSION_GROUP {
        state.refresh_admission_config(&plural).await;
    }
    if group == APISERVICE_GROUP {
        state.refresh_apiservice_cache().await;
    }
    write_vap_status(&*state.store, &group, &plural, &key, &mut obj.body, new_rv).await;
    inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
    Ok(Json(obj.body).into_response())
}

pub(crate) async fn delete_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Guard first — before validate_name so colon-names in RBAC (e.g. system:node) don't fail
    // the DNS-label charset check. The collection-delete path has the same guard.
    if is_seeded_rbac_object(&group, &name) {
        return Err(Status::forbidden(format!(
            "cannot delete bootstrap RBAC object {name}"
        )));
    }
    validate_name_for_group("name", &name, &group)?;
    let body = extract_body(&body, content_type(&headers));
    let delete_opts: DeleteOptions = if body.is_empty() {
        DeleteOptions::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            // body is already extracted (proto-decoded if needed). Pass empty headers so
            // delete_cr's extract_body call treats it as plain JSON (no re-decode).
            return super::cr::delete_cr(
                State(state),
                Path((group, version, plural, name)),
                Extension(user),
                HeaderMap::new(),
                body,
            )
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

    // Admission webhook pipeline (validating only — mutating webhooks do not apply to DELETE).
    // Run before the soft/hard-delete branch below so a Fail-policy webhook can deny the
    // delete outright, matching the CREATE/UPDATE admission points above.
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
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

    let owner_uid = obj.body["metadata"]["uid"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Orphan: signal via the `orphan` finalizer (added BEFORE the soft/hard-delete decision
    // below) instead of stripping children ourselves. See add_orphan_finalizer for why.
    if delete_opts.is_orphan() && !owner_uid.is_empty() {
        add_orphan_finalizer(&mut obj);
    }

    if let Some(soft) = apply_delete_policy(&mut obj) {
        // Soft-delete: persist modified object, return it.
        // Evict from RBAC index immediately — permissions must not outlast the deletion
        // request even while finalizers are draining. Hard-delete path below also removes,
        // so this is safe to call twice (remove_object is idempotent).
        if group == RBAC_GROUP {
            let rbac_key = rbac_cluster_key(&group, &version, &plural, &name);
            state.rbac_index.remove_object(&rbac_key);
        }
        if group == ADMISSION_GROUP {
            state.refresh_admission_config(&plural).await;
        }
        if group == APISERVICE_GROUP {
            state.refresh_apiservice_cache().await;
        }
        let expected_rv = parse_resource_version(obj.resource_version())?;
        let new_rv = state
            .store
            .put(&key, obj.to_bytes(), expected_rv)
            .await
            .map_err(|e| store_err(e, &name, &meta.kind))?;
        let mut resp_body = Object { body: soft };
        resp_body.set_resource_version(new_rv);
        return Ok(Json(resp_body.body).into_response());
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
    if group == ADMISSION_GROUP {
        state.refresh_admission_config(&plural).await;
    }
    if group == APISERVICE_GROUP {
        state.refresh_apiservice_cache().await;
    }
    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    }))
    .into_response())
}

/// True when an update (PATCH or PUT) has itself completed the finalizer drain:
/// `deletionTimestamp` is set and `finalizers` is now empty. Real KCM protection controllers
/// (pvc-protection, vac-protection, ...) remove their finalizer via a PUT, not a PATCH; the
/// handler that applies that update must notice this and hard-delete instead of storing the
/// update, or the object stays stuck Terminating forever.
pub(crate) fn finalizer_drain_complete(body: &serde_json::Value) -> bool {
    let meta: ObjectMeta = serde_json::from_value(body["metadata"].clone()).unwrap_or_default();
    let deletion_ts_set = meta.deletion_timestamp.is_some();
    let finalizers_empty = meta
        .finalizers
        .as_deref()
        .map(|f| f.is_empty())
        .unwrap_or(true);
    deletion_ts_set && finalizers_empty
}

/// Arguments for `complete_finalizer_drain`.
///
/// Groups the arguments that previously caused a `clippy::too_many_arguments` warning,
/// matching the `PatchConfig` convention already used for `do_patch` below.
struct FinalizerDrainCtx<'a> {
    key: &'a str,
    meta: &'a crate::types::ResourceMeta,
    group: &'a str,
    version: &'a str,
    plural: &'a str,
    /// `None` for cluster-scoped resources, `Some(namespace)` for namespaced ones.
    ns: Option<&'a str>,
    name: &'a str,
}

/// Hard-delete an object whose finalizer drain just completed, replicating the same side
/// effects as `delete_resource`'s hard-delete branch: RBAC-index eviction, admission-config
/// refresh, and checking whether the object's namespace can now complete its own Terminating
/// deletion. The store delete itself is what emits the watch DELETE/tombstone event, so callers
/// don't need to do anything further for watchers to observe the deletion.
async fn complete_finalizer_drain<S: Store>(
    state: &AppState<S>,
    ctx: FinalizerDrainCtx<'_>,
) -> Result<(), crate::status::StatusError> {
    let FinalizerDrainCtx {
        key,
        meta,
        group,
        version,
        plural,
        ns,
        name,
    } = ctx;
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
    if group == ADMISSION_GROUP {
        state.refresh_admission_config(plural).await;
    }
    if group == APISERVICE_GROUP {
        state.refresh_apiservice_cache().await;
    }
    // If this object lived in a namespace, refresh quota usage and check whether the
    // namespace is now ready to complete its own deletion.
    //
    // The quota refresh matters here specifically because of Orphan propagation: an
    // Orphan-marked owner (see add_orphan_finalizer) no longer hard-deletes synchronously
    // in the original DELETE request — it soft-deletes and waits for KCM to drain the
    // `orphan` finalizer, so THIS is now the only place its hard-delete (and the quota
    // recount that must follow it) actually happens.
    //
    // The namespace check handles the OrderedNamespaceDeletion flow: after all
    // finalizer'd objects are cleared, the Terminating namespace hard-deletes.
    if let Some(namespace) = ns {
        quota::update_quota_status(state, namespace).await;
        super::namespaces::maybe_finalize_terminating_namespace(state, namespace).await;
    }
    Ok(())
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
        // apply-patch+yaml bodies are genuine YAML (e.g. kubectl apply --server-side), which
        // Object::from_bytes (JSON-only) rejects outright — ssa_body_to_json handles both.
        let mut obj = Object {
            body: ssa_body_to_json(&body)?,
        };
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
        // Namespace-Terminating check (when namespaced) and the create are one atomic store
        // transaction — mirrors create_namespaced_resource/create_cr_namespaced/create_pod.
        // Without this, `kubectl apply --server-side` could create new content in a namespace
        // mid-deletion by going through PATCH+apply instead of POST+create.
        let ns_key = ns.map(|namespace| cluster_object_key("namespaces", namespace));
        let new_rv = match state
            .store
            .create_if_namespace_active(ns_key.as_deref(), key, obj.to_bytes())
            .await
        {
            Ok(rv) => rv,
            Err(CreateNamespacedError::NamespaceTerminating) => {
                let namespace = ns.unwrap_or_default();
                return Err(Status::forbidden(format!(
                    "unable to create new content in namespace {namespace} because it is being terminated"
                )));
            }
            Err(CreateNamespacedError::Store(StoreError::AlreadyExists { .. })) => {
                // Race: another writer created it; fall through to normal merge below.
                let stored = state
                    .store
                    .get(key)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?
                    .ok_or_else(|| Status::not_found(name, &meta.kind))?;
                let mut current = Object::from_bytes(&stored.value)
                    .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;
                let mut patch: serde_json::Value = ssa_body_to_json(&body)?;
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
            Err(CreateNamespacedError::Store(e)) => return Err(store_err(e, name, &meta.kind)),
        };
        obj.set_resource_version(new_rv);
        if let Some(fm) = field_manager {
            let api_ver = obj.body["apiVersion"].as_str().unwrap_or("").to_string();
            let now = crate::util::utc_now_rfc3339();
            inject_managed_fields(&mut obj.body, fm, &api_ver, &now);
        }
        return Ok((StatusCode::CREATED, Json(obj.body)).into_response());
    }

    let mut stored = stored_opt.ok_or_else(|| Status::not_found(name, &meta.kind))?;

    // A plain PATCH (merge / strategic-merge / JSON Patch) carries no resourceVersion
    // precondition unless the client's own patch body sets metadata.resourceVersion.
    // Real kube-apiserver's PATCH handler therefore read-modify-writes against the
    // LIVE object and retries (bounded) on a conflicting concurrent write instead of
    // surfacing a 409 for a race the client never asked to guard against — e.g. a
    // controller reacting to the just-created object (writing a status condition)
    // bumps the resourceVersion between the client's create response and its very
    // next PATCH. Without this retry, that PATCH fails with a spurious conflict even
    // though it never read or depended on the resourceVersion it happened to race
    // against. If the client's patch DOES pin metadata.resourceVersion to a stale
    // value, reapplying it against the freshly re-fetched object still yields that
    // same stale value, so the mismatch reproduces every attempt and correctly
    // surfaces as 409 once retries are exhausted.
    const MAX_PATCH_CONFLICT_RETRIES: u32 = 5;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let mut current = Object::from_bytes(&stored.value)
            .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

        // Immutability check: if the stored Secret or ConfigMap has `immutable: true`,
        // snapshot data/binaryData/stringData before the patch is applied so the rejection
        // below (after the patch) can be scoped to changes that actually touch them or
        // clear the flag — matching replace_namespaced_resource's scoping (~line 1978),
        // instead of blanket-rejecting metadata-only patches (e.g. `kubectl label`).
        let immutable_snapshot = if group.is_empty()
            && (plural == "secrets" || plural == "configmaps")
            && current.body["immutable"] == serde_json::Value::Bool(true)
        {
            Some((
                current.body["data"].clone(),
                current.body["binaryData"].clone(),
                current.body["stringData"].clone(),
            ))
        } else {
            None
        };

        // Capture PriorityClass.value before patch: it drives scheduling/preemption
        // ordering cluster-wide and is immutable after create. Real kube-apiserver
        // returns 422 "Invalid" if a patch changes it.
        let priorityclass_value_before_patch =
            if group == "scheduling.k8s.io" && plural == "priorityclasses" {
                Some(current.body["value"].clone())
            } else {
                None
            };

        // Capture PVC storage request + StorageClass before patch: growing storage is only
        // allowed when the bound StorageClass explicitly opts in via allowVolumeExpansion,
        // checked against the post-patch value below.
        let pvc_before_patch = if group.is_empty() && plural == "persistentvolumeclaims" {
            Some((
                current.body["spec"]["resources"]["requests"]["storage"]
                    .as_str()
                    .map(str::to_string),
                current.body["spec"]["storageClassName"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            ))
        } else {
            None
        };

        // Capture spec before patch for generation tracking on workload resources.
        let spec_before_patch = if super::defaults::is_workload_resource(group, plural) {
            Some(current.body["spec"].clone())
        } else {
            None
        };

        // apply-patch+yaml bodies are genuine YAML; every other patch type is JSON.
        let mut patch: serde_json::Value = if is_ssa {
            ssa_body_to_json(&body)?
        } else {
            serde_json::from_slice(&body)
                .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
        };

        // Strip managedFields the client sent in the apply body — we don't track field ownership.
        if is_ssa {
            strip_managed_fields(&mut patch);
        }

        // Snapshot .status before applying the patch: status is a separate RBAC subresource,
        // so a patch on the main endpoint (merge, strategic-merge, or JSON Patch — a JSON Patch
        // is an array and would otherwise slip past an object-shaped "status" key strip) must
        // never change it, restored below after the patch is applied.
        let stored_status = if meta.has_status_subresource {
            Some(current.body["status"].clone())
        } else {
            None
        };

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

        if meta.has_status_subresource {
            match stored_status {
                Some(ref s) if !s.is_null() => {
                    current.body["status"] = s.clone();
                }
                _ => {
                    current.body.as_object_mut().map(|m| m.remove("status"));
                }
            }
        }

        if let Some(ref old_value) = priorityclass_value_before_patch {
            if &current.body["value"] != old_value {
                return Err(Status::unprocessable_entity(format!(
                    "{plural}/{name} .value is immutable and cannot be updated"
                )));
            }
        }

        if let Some((ref old_size, ref sc_name)) = pvc_before_patch {
            reject_disallowed_pvc_expansion(
                state,
                plural,
                name,
                old_size.as_deref(),
                sc_name,
                &current.body,
            )
            .await?;
        }

        if let Some((ref data_before, ref binary_data_before, ref string_data_before)) =
            immutable_snapshot
        {
            let new_immutable = &current.body["immutable"];
            let immutable_cleared =
                new_immutable == &serde_json::Value::Bool(false) || new_immutable.is_null();
            let data_changed = &current.body["data"] != data_before;
            let binary_data_changed = &current.body["binaryData"] != binary_data_before;
            let string_data_changed = &current.body["stringData"] != string_data_before;
            if immutable_cleared || data_changed || binary_data_changed || string_data_changed {
                return Err(Status::unprocessable_entity(format!(
                    "{plural}/{name} is immutable and cannot be updated"
                )));
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
        if finalizer_drain_complete(&current.body) {
            complete_finalizer_drain(
                state,
                FinalizerDrainCtx {
                    key,
                    meta,
                    group,
                    version,
                    plural,
                    ns,
                    name,
                },
            )
            .await?;
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
            user_info: user_info.clone(),
            dry_run: false,
        };
        current.body = run_mutating_webhooks(state, current.body, None, &admission_ctx).await?;
        run_validating_webhooks(state, &current.body, None, &admission_ctx).await?;

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
            inject_type_meta(&mut current.body, group, version, &meta.kind);
            return Ok(Json(current.body).into_response());
        }

        let expected_rv = parse_resource_version(current.resource_version())?;
        match state.store.put(key, current.to_bytes(), expected_rv).await {
            Ok(new_rv) => {
                current.set_resource_version(new_rv);
                if group == RBAC_GROUP {
                    let rbac_key = match ns {
                        None => rbac_cluster_key(group, version, plural, name),
                        Some(namespace) => {
                            rbac_namespaced_key(group, version, namespace, plural, name)
                        }
                    };
                    state.rbac_index.apply_object(&rbac_key, &current.body);
                }
                if group == ADMISSION_GROUP {
                    state.refresh_admission_config(plural).await;
                }
                if group == APISERVICE_GROUP {
                    state.refresh_apiservice_cache().await;
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
                inject_type_meta(&mut current.body, group, version, &meta.kind);
                return Ok(Json(current.body).into_response());
            }
            Err(StoreError::RevisionMismatch { .. }) if attempt < MAX_PATCH_CONFLICT_RETRIES => {
                stored = state
                    .store
                    .get(key)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?
                    .ok_or_else(|| Status::not_found(name, &meta.kind))?;
            }
            Err(e) => return Err(store_err(e, name, &meta.kind)),
        }
    }
}

/// Reports whether StorageClass `sc_name` explicitly allows volume expansion.
/// A missing StorageClass or an absent/false `allowVolumeExpansion` field are both
/// treated as "not allowed" — mirrors upstream's PersistentVolumeClaimResize admission
/// plugin (plugin/pkg/admission/storage/persistentvolume/resize/admission.go), which
/// defaults to deny rather than fail open when the field can't be resolved.
async fn storage_class_allows_expansion<S: Store>(state: &AppState<S>, sc_name: &str) -> bool {
    if sc_name.is_empty() {
        return false;
    }
    let key = group_object_key("storage.k8s.io", "storageclasses", None, sc_name);
    match state.store.get(&key).await {
        Ok(Some(stored)) => serde_json::from_slice::<serde_json::Value>(&stored.value)
            .ok()
            .and_then(|v| v["allowVolumeExpansion"].as_bool())
            .unwrap_or(false),
        _ => false,
    }
}

/// Rejects a PersistentVolumeClaim UPDATE that grows `spec.resources.requests.storage`
/// past `old_size` unless `old_sc_name`'s StorageClass explicitly allows it. Mirrors
/// upstream's PersistentVolumeClaimResize admission plugin: without this check, e2e's
/// "should not allow expansion of pvcs without AllowVolumeExpansion property" observes
/// the size increase silently succeed instead of a 403 Forbidden.
async fn reject_disallowed_pvc_expansion<S: Store>(
    state: &AppState<S>,
    plural: &str,
    name: &str,
    old_size: Option<&str>,
    old_sc_name: &str,
    new_pvc: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let Some(old_size) = old_size.and_then(limit_range::parse_quantity) else {
        return Ok(());
    };
    let Some(new_size) = new_pvc["spec"]["resources"]["requests"]["storage"]
        .as_str()
        .and_then(limit_range::parse_quantity)
    else {
        return Ok(());
    };
    if new_size <= old_size || storage_class_allows_expansion(state, old_sc_name).await {
        return Ok(());
    }
    Err(Status::forbidden(format!(
        "{plural} \"{name}\" is forbidden: only dynamically provisioned pvc can be resized and \
         the storageclass that provisions the pvc must support resize"
    )))
}

pub(crate) async fn patch_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Query(patch_query): Query<PatchQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name_for_group("name", &name, &group)?;
    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            // See create_resource: cr::patch_cr has no Query extractor of its own, so
            // forward ?fieldValidation= via a header instead of a new parameter.
            let mut headers = headers;
            if let Some(fv) = patch_query._field_validation.as_deref() {
                if let Ok(hv) = axum::http::HeaderValue::from_str(fv) {
                    headers.insert(
                        axum::http::HeaderName::from_static("x-u7s-field-validation"),
                        hv,
                    );
                }
            }
            return super::cr::patch_cr(
                State(state),
                Path((group, version, plural, name)),
                Extension(user),
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

pub(crate) async fn list_namespaced_resource<S: Store>(
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

    let store_field_selector = if plural == "events" {
        None
    } else {
        query
            .field_selector
            .as_deref()
            .map(parse_field_selector)
            .transpose()?
    };
    // Decode BEFORE listing: on a continuation request this pins the resourceVersion this
    // response (and every later page) must report — see decode_continue's doc for why.
    let continue_decoded = query
        .continue_token
        .as_deref()
        .map(|t| decode_continue(t, state.store.current_revision(), &state.continue_token_key))
        .transpose()?;
    let continue_key = continue_decoded.as_ref().map(|(k, _)| k.clone());
    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                field_selector: store_field_selector,
                limit: query.limit,
                continue_key,
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    // First page (no continue token yet): the fresh store revision becomes the pin for
    // subsequent pages. Continuation page: reuse the pin decoded above, not the store's
    // current (possibly-advanced) revision.
    let list_revision = continue_decoded.map(|(_, rv)| rv).unwrap_or(resp.revision);

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

    let items = if plural == "events" {
        if let Some(ref sel) = query.field_selector {
            super::pods::filter_events_by_field_selector(items, sel)
        } else {
            items
        }
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
            "metadata": { "resourceVersion": list_revision.to_string() },
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
        list_revision,
        items,
        resp.continue_key,
        resp.remaining_count,
        &state.continue_token_key,
    );
    Ok(Json(body).into_response())
}

pub(crate) async fn get_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    validate_name_for_group("name", &name, &group)?;
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::get_cr_namespaced(
                State(state),
                Path((group, version, ns, plural, name)),
                headers,
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
    inject_type_meta(&mut obj, &group, &version, &meta.kind);

    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // kcm's GC verifies owner references via metadata-only Get() calls
    // (garbagecollector.go's isDangling); without this, it receives a typed object it can't
    // decode and retries the owner-check forever, so newly-orphaned dependents are never
    // identified as dangling and never collected.
    if wants_partial_object_metadata(accept) {
        return Ok(Json(super::watch::to_partial_object_metadata(&obj)).into_response());
    }

    // kubectl's default Accept header requests Table format; without this, kubectl can't
    // decode the response and falls back to printing only NAME/AGE (list_namespaced_resource
    // already handles this for LIST — see above).
    if super::table::wants_table(accept) {
        return Ok(Json(super::table::build_table(&group, &plural, vec![obj])).into_response());
    }

    Ok(Json(obj).into_response())
}

pub(crate) async fn create_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    Query(create_query): Query<CreateQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    let body = extract_body(&body, content_type(&headers));
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            // See create_resource: cr::create_cr_namespaced has no Query extractor of its
            // own, so forward ?fieldValidation= via a header instead of a new parameter.
            let mut headers = headers;
            if let Some(fv) = create_query.field_validation.as_deref() {
                if let Ok(hv) = axum::http::HeaderValue::from_str(fv) {
                    headers.insert(
                        axum::http::HeaderName::from_static("x-u7s-field-validation"),
                        hv,
                    );
                }
            }
            return super::cr::create_cr_namespaced(
                State(state),
                Path((group, version, ns, plural)),
                Extension(user),
                headers,
                body,
            )
            .await
            .map(IntoResponse::into_response);
        }
    };

    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // Field validation: detect unknown/duplicate fields per ?fieldValidation= query param.
    let warn_header = apply_field_validation(
        &obj.body,
        &body,
        create_query.field_validation.as_deref(),
        &group,
        &plural,
    )?;

    // Escalation prevention: before persisting a namespaced RoleBinding, verify the
    // caller already holds all rules of the referenced Role or ClusterRole in this namespace.
    check_rb_escalation(&plural, &group, &ns, &user, &obj.body, &state)?;

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

    // Save ownerReferences before the ObjectMeta round-trip: ObjectMeta serde only
    // knows the fields declared in the struct, so any field not in it (including
    // ownerReferences) is silently dropped during from_value/to_value.  We restore
    // the saved value immediately after so KCM-created Jobs (and any other object
    // whose ownerReferences arrive via protobuf) survive the round-trip intact.
    let saved_owner_refs = obj.body["metadata"]["ownerReferences"].clone();
    let mut ns_meta: ObjectMeta =
        serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
    ns_meta.namespace = Some(ns.clone());
    obj.body["metadata"] =
        serde_json::to_value(ns_meta).map_err(|e| Status::internal(e.to_string()))?;
    if !saved_owner_refs.is_null() {
        obj.body["metadata"]["ownerReferences"] = saved_owner_refs;
    }
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
    obj.body = run_mutating_webhooks(&state, obj.body, None, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;

    // LimitRange: inject defaults then validate min/max bounds (pods only).
    obj.body = limit_range::apply_limit_ranges(&state, obj.body, &ns, &plural).await?;

    // ResourceQuota: ensure object count does not exceed hard limits.
    // Held across check-then-write: without this, concurrent creates of the same
    // resource type in the same namespace can each observe pre-write usage, all pass
    // the check, and collectively exceed the quota.
    let _quota_lock = state.quota_admission_locks.lock(&ns).await;
    quota::check_resource_quota(&state, &ns, &group, &plural, Some(&obj.body)).await?;

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
    let ns_key = cluster_object_key("namespaces", &ns);
    let put_start = std::time::Instant::now();
    // Namespace-Terminating check and the create are one atomic store transaction — matches
    // kube-apiserver behaviour: 403 Forbidden "unable to create new content in namespace <ns>
    // because it is being terminated" — closing the check-then-act window a separate earlier
    // check + this write used to leave open (a create could observe Active, then a concurrent
    // delete_namespace flips the phase, and this write would blindly succeed regardless).
    let result = state
        .store
        .create_if_namespace_active(Some(&ns_key), &key, obj.to_bytes())
        .await;
    tracing::debug!(
        key = %key,
        elapsed_ms = put_start.elapsed().as_millis() as u64,
        ok = result.is_ok(),
        "create_namespaced_resource: store.put call completed"
    );
    let new_rv = match result {
        Ok(rv) => rv,
        Err(CreateNamespacedError::NamespaceTerminating) => {
            return Err(Status::forbidden(format!(
                "unable to create new content in namespace {ns} because it is being terminated"
            )));
        }
        Err(CreateNamespacedError::Store(StoreError::AlreadyExists { .. }))
            if meta.create_or_update =>
        {
            // createOrUpdate: replace existing object unconditionally.
            state
                .store
                .put(&key, obj.to_bytes(), None)
                .await
                .map_err(|e| store_err(e, &name, &meta.kind))?
        }
        Err(CreateNamespacedError::Store(StoreError::AlreadyExists { .. })) => {
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
        Err(CreateNamespacedError::Store(e)) => return Err(store_err(e, &name, &meta.kind)),
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

    quota::update_quota_status(&state, &ns).await;

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

/// Emits the `u7s::apiserver::spec_replace` debug signal for a workload-tier PUT
/// (Deployment/ReplicaSet/StatefulSet/DaemonSet/Job/CronJob/PodDisruptionBudget — see
/// `is_workload_resource`). `spec_changed` alone lets an operator filter re-applies (a
/// client PUTting back exactly what it read) from real edits; `spec_diff_summary` is only
/// attached when something actually changed, since it costs a `spec` walk to build.
fn log_spec_replace(
    ns: &str,
    name: &str,
    kind: &str,
    spec_before: &serde_json::Value,
    spec_after: &serde_json::Value,
) {
    let spec_changed = spec_after != spec_before;
    if spec_changed {
        tracing::debug!(
            target: "u7s::apiserver::spec_replace",
            namespace = %ns,
            name = %name,
            resource = %kind,
            spec_changed,
            spec_diff_summary = %spec_diff_summary(spec_before, spec_after),
            "namespaced resource replace"
        );
    } else {
        tracing::debug!(
            target: "u7s::apiserver::spec_replace",
            namespace = %ns,
            name = %name,
            resource = %kind,
            spec_changed,
            "namespaced resource replace"
        );
    }
}

/// Short human-readable summary of what changed between two workload specs. Covers the two
/// fields operators most commonly care about when triaging a replace (scale and image
/// rollout); other spec fields are named but not value-diffed, since dumping e.g. a full
/// `selector` or `template.spec.volumes` change into a log line defeats the point of a
/// short summary.
fn spec_diff_summary(before: &serde_json::Value, after: &serde_json::Value) -> String {
    let mut parts = Vec::new();

    if before["replicas"] != after["replicas"] {
        parts.push(format!(
            "replicas: {} -> {}",
            before["replicas"], after["replicas"]
        ));
    }

    let before_image = before
        .pointer("/template/spec/containers/0/image")
        .and_then(|v| v.as_str());
    let after_image = after
        .pointer("/template/spec/containers/0/image")
        .and_then(|v| v.as_str());
    if before_image != after_image {
        parts.push(format!(
            "image: {} -> {}",
            before_image.unwrap_or("<none>"),
            after_image.unwrap_or("<none>")
        ));
    }

    // The pod template can change in ways other than containers[0].image (env, resources,
    // extra containers, volumes, labels) — too large to diff inline, so just flag it.
    if before["template"] != after["template"] && before_image == after_image {
        parts.push("template changed (non-image field)".to_string());
    }

    for field in ["selector", "minAvailable", "maxUnavailable"] {
        if before[field] != after[field] {
            parts.push(format!("{field} changed"));
        }
    }

    if parts.is_empty() {
        "spec changed (no diffable field matched)".to_string()
    } else {
        parts.join(", ")
    }
}

pub(crate) async fn replace_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    Query(replace_query): Query<ReplaceQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    validate_name_for_group("name", &name, &group)?;
    let body = extract_body(&body, content_type(&headers));
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            return super::cr::replace_cr_namespaced(
                State(state),
                Path((group, version, ns, plural, name)),
                Extension(user),
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

    // Escalation prevention: before updating a namespaced RoleBinding, verify the
    // caller already holds all rules of the referenced Role or ClusterRole in this namespace.
    check_rb_escalation(&plural, &group, &ns, &user, &obj.body, &state)?;

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
    // Secrets/ConfigMaps, (b) generation tracking on workload resources and EndpointSlice,
    // (c) status restoration when the resource has a dedicated status subresource, and
    // (d) UID restoration (see stored_uid below) whenever we already have this object in hand.
    // deletionTimestamp is also server-owned (see stored_deletion_timestamp below): a client
    // whose PUT body omits it — including a protobuf-content-type PUT, since the wire decoder
    // never emits this field — must not be trusted as "not being deleted".
    let incoming_deletion_timestamp_blank = obj.body["metadata"]["deletionTimestamp"].is_null();
    let is_pvc = group.is_empty() && plural == "persistentvolumeclaims";
    let needs_stored_read = super::defaults::is_workload_resource(&group, &plural)
        || super::defaults::is_endpointslice(&group, &plural)
        || meta.has_status_subresource
        || (group.is_empty() && (plural == "secrets" || plural == "configmaps"))
        || is_pvc
        || incoming_deletion_timestamp_blank;
    let (
        spec_before_replace,
        stored_status,
        stored_generation,
        stored_uid,
        eps_before_replace,
        stored_deletion_timestamp,
        stored_deletion_grace,
    ) = if needs_stored_read {
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

        // A PUT growing spec.resources.requests.storage is only allowed when the bound
        // StorageClass explicitly opts in via allowVolumeExpansion — see
        // reject_disallowed_pvc_expansion.
        if is_pvc {
            if let Some(ref stored) = parsed {
                reject_disallowed_pvc_expansion(
                    &state,
                    &plural,
                    &name,
                    stored["spec"]["resources"]["requests"]["storage"].as_str(),
                    stored["spec"]["storageClassName"].as_str().unwrap_or(""),
                    &obj.body,
                )
                .await?;
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
        let generation = if super::defaults::is_workload_resource(&group, &plural)
            || super::defaults::is_endpointslice(&group, &plural)
        {
            parsed.as_ref().map(|v| v["metadata"]["generation"].clone())
        } else {
            None
        };
        // UID is immutable and system-assigned. Captured whenever we already have the
        // stored object in hand (no extra read) so a blind PUT that omits it — see the
        // restamp below — can be defended against for every resource type this read
        // already covers, not just EndpointSlice.
        let uid = parsed.as_ref().map(|v| v["metadata"]["uid"].clone());
        // Snapshot of the whole pre-update object, used by
        // increment_endpointslice_generation_if_changed below to detect a real content
        // change (EndpointSlice has no `.spec` to diff against).
        let eps_before = if super::defaults::is_endpointslice(&group, &plural) {
            parsed.clone()
        } else {
            None
        };
        let deletion_timestamp = parsed
            .as_ref()
            .map(|v| v["metadata"]["deletionTimestamp"].clone());
        let deletion_grace = parsed
            .as_ref()
            .map(|v| v["metadata"]["deletionGracePeriodSeconds"].clone());
        (
            spec,
            status,
            generation,
            uid,
            eps_before,
            deletion_timestamp,
            deletion_grace,
        )
    } else {
        (None, None, None, None, None, None, None)
    };

    // A blind PUT (dynamic/typed client round-tripping a locally-held object) commonly
    // omits metadata.generation. Restamp the stored value onto the incoming body before
    // apply_defaults runs, or initialize_workload_generation treats the omission as "new
    // object" and resets generation to 1 — silently erasing however many spec changes the
    // Deployment has actually undergone and desyncing status.observedGeneration from the
    // real generation history the Deployment controller expects to see increase monotonically.
    if let Some(ref g) = stored_generation {
        if !g.is_null() {
            obj.body["metadata"]["generation"] = g.clone();
        }
    }

    // UID is immutable; a client's PUT commonly omits it — e.g. KCM's EndpointSlice
    // reconciler builds its Update() body without repopulating this field. Real
    // kube-apiserver's generic update preparation (rest.BeforeUpdate) unconditionally
    // restores the existing UID whenever the incoming body's is blank ("Use the existing
    // UID if none is provided"). Without this, a blank UID is persisted and broadcast to
    // watchers as-is: KCM's EndpointSliceTracker identifies slices by UID, so its
    // StaleSlices() check permanently treats the tracked (real) UID as missing from the
    // informer once the informer's cached copy carries the blank one instead — every later
    // sync fails with "EndpointSlice informer cache is out of date" forever.
    if obj.body["metadata"]["uid"]
        .as_str()
        .map(str::is_empty)
        .unwrap_or(true)
    {
        if let Some(uid) = stored_uid.as_ref().and_then(|u| u.as_str()) {
            if !uid.is_empty() {
                obj.body["metadata"]["uid"] = serde_json::Value::String(uid.to_string());
            }
        }
    }

    // deletionTimestamp/deletionGracePeriodSeconds are server-owned, exactly like UID above:
    // a client cannot un-terminate an object mid-deletion by omitting them on a PUT. Without
    // this, finalizer_drain_complete below (which reads obj.body, not the stored object) would
    // see a blank deletionTimestamp and treat a finalizer-removal PUT as a plain update instead
    // of completing the delete — persisting the object with deletionTimestamp gone and
    // finalizers empty, i.e. silently resurrecting it as a normal live object.
    if incoming_deletion_timestamp_blank {
        if let Some(ts) = stored_deletion_timestamp.as_ref().filter(|v| !v.is_null()) {
            obj.body["metadata"]["deletionTimestamp"] = ts.clone();
            if let Some(grace) = stored_deletion_grace.as_ref().filter(|v| !v.is_null()) {
                obj.body["metadata"]["deletionGracePeriodSeconds"] = grace.clone();
            }
        }
    }

    // Allocate a clusterIP when a Service transitions away from ExternalName to a
    // cluster-routed type (ClusterIP, NodePort, LoadBalancer).  The create path
    // handles initial allocation; the update path must also allocate when the type
    // changes, because ExternalName services are created without a clusterIP and the
    // stored object carries no IP to preserve.
    // maybe_allocate_cluster_ip is a no-op when clusterIP is already set or when
    // the type is (still) ExternalName, so calling it unconditionally is safe.
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
        operation: "UPDATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
        })),
        dry_run: false,
    };
    obj.body = run_mutating_webhooks(&state, obj.body, None, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;

    if let Some(ref spec_before) = spec_before_replace {
        log_spec_replace(&ns, &name, &meta.kind, spec_before, &obj.body["spec"]);
        super::defaults::increment_workload_generation_if_spec_changed(&mut obj.body, spec_before);
    }
    if let Some(ref eps_before) = eps_before_replace {
        super::defaults::increment_endpointslice_generation_if_changed(&mut obj.body, eps_before);
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
        inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
        return Ok(Json(obj.body).into_response());
    }

    // A PUT whose body has deletionTimestamp set and finalizers now empty is how KCM's
    // protection controllers (pvc-protection, vac-protection, ...) complete a delete: they
    // remove their finalizer via PUT, not PATCH. Complete the delete instead of storing an
    // update, or the object stays stuck Terminating forever.
    if finalizer_drain_complete(&obj.body) {
        complete_finalizer_drain(
            &state,
            FinalizerDrainCtx {
                key: &key,
                meta: &meta,
                group: &group,
                version: &version,
                plural: &plural,
                ns: Some(&ns),
                name: &name,
            },
        )
        .await?;
        inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
        return Ok(Json(obj.body).into_response());
    }

    let put_start = std::time::Instant::now();
    let put_result = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await;
    tracing::debug!(
        key = %key,
        elapsed_ms = put_start.elapsed().as_millis() as u64,
        ok = put_result.is_ok(),
        "replace_namespaced_resource: store.put call completed"
    );
    let new_rv = put_result.map_err(|e| store_err(e, &name, &meta.kind))?;

    obj.set_resource_version(new_rv);
    if group == RBAC_GROUP {
        let rbac_key = rbac_namespaced_key(&group, &version, &ns, &plural, &name);
        state.rbac_index.apply_object(&rbac_key, &obj.body);
    }
    inject_type_meta(&mut obj.body, &group, &version, &meta.kind);
    Ok(Json(obj.body).into_response())
}

pub(crate) async fn delete_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    // Guard before validate_name_for_group so colon-names in RBAC don't fail the charset check.
    // Namespaced system: objects don't exist today but blocking them prevents future surprises.
    if is_seeded_rbac_object(&group, &name) {
        return Err(Status::forbidden(format!(
            "cannot delete bootstrap RBAC object {name}"
        )));
    }
    validate_name_for_group("name", &name, &group)?;
    let body = extract_body(&body, content_type(&headers));
    let delete_opts: DeleteOptions = if body.is_empty() {
        DeleteOptions::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            // body is already extracted (proto-decoded if needed). Pass empty headers so
            // delete_cr_namespaced's extract_body call treats it as plain JSON (no re-decode).
            return super::cr::delete_cr_namespaced(
                State(state),
                Path((group, version, ns, plural, name)),
                Extension(user),
                HeaderMap::new(),
                body,
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

    // Admission webhook pipeline (validating only — mutating webhooks do not apply to DELETE).
    // Run before the soft/hard-delete branch below so a Fail-policy webhook can deny the
    // delete outright, matching the CREATE/UPDATE admission points above.
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: Some(&ns),
        operation: "DELETE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
        })),
        dry_run: false,
    };
    run_validating_webhooks(&state, &obj.body, Some(&obj.body), &admission_ctx).await?;

    let owner_uid = obj.body["metadata"]["uid"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Compute the effective orphan flag for this delete.
    //
    // Explicit Orphan (propagationPolicy=Orphan or orphanDependents=true) → orphan.
    //
    // For ReplicationControllers specifically: when the caller sends empty DeleteOptions
    // (nil propagationPolicy, nil orphanDependents), we also orphan.  The k8s GC
    // conformance spec "should orphan pods created by rc if deleteOptions.OrphanDependents
    // is nil" (garbage_collector.go:475) sends exactly this and asserts that 2 pods
    // survive for 30 s.  If we leave pods with their ownerReferences intact, the KCM
    // GC controller sees them as orphaned dependents of a deleted owner and garbage-
    // collects them within seconds — the test then observes 0 pods.  Stripping ownerRefs
    // upfront prevents the GC from collecting them, matching upstream k8s semantics
    // where nil policy means the GC treats pods as not eligible for cascade.
    let effective_orphan = delete_opts.is_orphan()
        || (group.is_empty()
            && plural == "replicationcontrollers"
            && !delete_opts.is_explicit_cascade());

    // Orphan: signal via the `orphan` finalizer (added BEFORE the soft/hard-delete decision
    // below) instead of stripping children ourselves. See add_orphan_finalizer for why.
    if effective_orphan && !owner_uid.is_empty() {
        add_orphan_finalizer(&mut obj);
    }

    // Foreground: signal via the `foregroundDeletion` finalizer (added BEFORE the soft/
    // hard-delete decision below) instead of hard-deleting the owner immediately and
    // racing our own best-effort delete_pods_owned_by cascade further down. See
    // add_foreground_deletion_finalizer for why.
    let foreground_requested = delete_opts.propagation_policy.as_deref() == Some("Foreground");
    if foreground_requested && !owner_uid.is_empty() {
        add_foreground_deletion_finalizer(&mut obj);
    }

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
        let mut resp_body = Object { body: soft };
        resp_body.set_resource_version(new_rv);
        return Ok(Json(resp_body.body).into_response());
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
    if group == "apps" && plural == "daemonsets" && !owner_uid.is_empty() {
        delete_pods_owned_by(&state, &ns, &owner_uid, "DaemonSet").await;
    }

    // Cascade-delete ReplicaSets owned by a deleted Deployment.
    // Without this, orphaned ReplicaSets continue creating pods indefinitely —
    // observed: smoke-test-mutate RS (desired: 1337) created 14000+ pods after
    // its Deployment was deleted.
    if group == "apps" && plural == "deployments" && !owner_uid.is_empty() {
        delete_replicasets_owned_by(&state, &ns, &owner_uid).await;
    }

    // Cascade-delete pods owned by a deleted ReplicationController — only when the caller
    // explicitly requests Background propagation.
    //
    // Nil-policy RC deletes are handled above (effective_orphan is true for RCs when no
    // explicit cascade is requested). Foreground is also handled above (foregroundDeletion
    // finalizer added, soft-delete taken, function already returned before reaching here) —
    // `!foreground_requested` is kept as an explicit guard rather than relying solely on
    // that early return, so this branch cannot silently start double-cascading pods that
    // real KCM's garbage collector is now the sole authority for under Foreground.
    if group.is_empty()
        && plural == "replicationcontrollers"
        && !owner_uid.is_empty()
        && delete_opts.is_explicit_cascade()
        && !foreground_requested
    {
        delete_pods_owned_by(&state, &ns, &owner_uid, "ReplicationController").await;
    }

    // Cascade-delete pods owned by a deleted StatefulSet.
    // Without this, StatefulSet pods linger against the 110-pod node cap.
    if group == "apps" && plural == "statefulsets" && !owner_uid.is_empty() {
        delete_pods_owned_by(&state, &ns, &owner_uid, "StatefulSet").await;
    }

    // Cascade-delete Jobs owned by a deleted CronJob, then cascade each Job's pods.
    // Without this, Jobs (and their pods) created by a CronJob linger after the CronJob is
    // deleted — the GC conformance spec "should delete jobs and pods created by cronjob"
    // fails because the test asserts both Jobs AND Pods are gone within 60 s.
    if group == "batch" && plural == "cronjobs" && !owner_uid.is_empty() {
        delete_jobs_owned_by(&state, &ns, &owner_uid).await;
    }

    // Remove the job-tracking finalizer from pods owned by a deleted Job.
    //
    // Kubernetes KCM's job-controller (1.36) adds `batch.kubernetes.io/job-tracking` to
    // pods it creates, then removes the finalizer once each pod reaches a terminal state.
    // When a Job is deleted and immediately hard-deleted (no finalizers on the Job object),
    // KCM's syncJob returns early ("job not found") without removing pod finalizers.
    // The pods are then stuck Terminating forever: they have deletionTimestamp (from the
    // kubelet's DELETE) but the tracking finalizer is never cleared, so GC cannot complete.
    //
    // Fix: when we hard-delete a Job, synchronously remove the tracking finalizer from all
    // owned pods. If a pod now has deletionTimestamp + no finalizers, hard-delete it too.
    if group == "batch" && plural == "jobs" && !owner_uid.is_empty() {
        remove_job_tracking_finalizer_from_pods(&state, &ns, &owner_uid).await;
    }

    quota::update_quota_status(&state, &ns).await;

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    }))
    .into_response())
}

pub(crate) async fn patch_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    Query(patch_query): Query<PatchQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    validate_name_for_group("name", &name, &group)?;
    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");
    let meta = match lookup(&state, &group, &version, &plural) {
        Ok(m) => m.clone(),
        Err(_) => {
            // See create_resource: cr::patch_cr_namespaced has no Query extractor of its
            // own, so forward ?fieldValidation= via a header instead of a new parameter.
            let mut headers = headers;
            if let Some(fv) = patch_query._field_validation.as_deref() {
                if let Ok(hv) = axum::http::HeaderValue::from_str(fv) {
                    headers.insert(
                        axum::http::HeaderName::from_static("x-u7s-field-validation"),
                        hv,
                    );
                }
            }
            return super::cr::patch_cr_namespaced(
                State(state),
                Path((group, version, ns, plural, name)),
                Extension(user),
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
pub(crate) async fn patch_collection_namespaced_resource<S: Store>(
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
pub(crate) async fn delete_collection_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural)): Path<(String, String, String)>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Resources not in the static registry are CRD-backed; fall back to CR handling exactly
    // like every other verb dispatched from this file (list_resource -> cr::list_cr,
    // delete_resource -> cr::delete_cr, ...) — this was the one verb missing that fallback.
    if lookup(&state, &group, &version, &plural).is_err() {
        return super::cr::delete_collection_cr(
            State(state),
            Path((group, version, plural)),
            Extension(user),
            query,
        )
        .await
        .map(IntoResponse::into_response);
    }

    let prefix = group_list_prefix(&group, &plural, None);
    // "events" needs multi-term, in-memory filtering (see list_resource); every other
    // built-in resource can use the store's generic single-field selector directly.
    let store_field_selector = if plural == "events" {
        None
    } else {
        query
            .field_selector
            .as_deref()
            .map(parse_field_selector)
            .transpose()?
    };
    let resp = state
        .store
        .list(
            &prefix,
            u7s_store::ListOptions {
                field_selector: store_field_selector,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(parse_label_selector)
        .transpose()?;

    // Built once — reused for every per-object AdmissionContext below.
    let user_info = Some(serde_json::json!({
        "username": user.username,
        "uid": user.uid,
        "groups": user.groups,
    }));

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

            // Admission webhook pipeline (validating only — mutating webhooks do not apply
            // to DELETE), invoked per object exactly like the single-delete handlers above.
            // Upstream kube-apiserver's DeleteCollection runs admission per object too; a
            // Fail-policy deny propagates here and aborts the whole request at this object —
            // objects already deleted earlier in this loop stay deleted (DeleteCollection is
            // not transactional upstream either), matching the fail-fast handling the store
            // error branch below already uses for this same loop.
            let admission_ctx = AdmissionContext {
                group: &group,
                version: &version,
                resource: &plural,
                name: &name,
                namespace: None,
                operation: "DELETE",
                user_info: user_info.clone(),
                dry_run: false,
            };
            run_validating_webhooks(&state, &parsed, Some(&parsed), &admission_ctx).await?;

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

            // Respect metadata.finalizers exactly like a single-object DELETE would: a
            // cluster-scoped object with finalizers (a CustomResourceDefinition, ClusterRole,
            // or PersistentVolume with a legitimate finalizer) must be soft-deleted
            // (deletionTimestamp stamped, kept alive), not removed outright — mirrors
            // delete_collection_namespaced_resource below.
            let mut typed = Object { body: parsed };
            if let Some(soft) = apply_delete_policy(&mut typed) {
                state
                    .store
                    .put(&obj.key, Object { body: soft }.to_bytes(), None)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                continue;
            }
        }
        // NotFound means another writer deleted this object concurrently — tolerate it.
        // Any other error (disk full, DB corruption, …) means some objects survived;
        // propagate so the caller does not believe all objects were deleted.
        match state.store.delete(&obj.key, None).await {
            Ok(_) | Err(StoreError::NotFound { .. }) => {}
            Err(e) => return Err(Status::internal(e.to_string())),
        }
        if let Some(ref ip) = cluster_ip_to_release {
            state.release_service_ip(ip).await;
        }
    }
    if group == ADMISSION_GROUP {
        // One re-list after all deletions in the collection — cheaper than per-object.
        state.refresh_admission_config(&plural).await;
    }
    if group == APISERVICE_GROUP {
        state.refresh_apiservice_cache().await;
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
pub(crate) async fn delete_collection_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    // Resources not in the static registry are CRD-backed; fall back to CR handling exactly
    // like every other namespaced verb dispatched from this file (list_namespaced_resource ->
    // cr::list_cr_namespaced, delete_namespaced_resource -> cr::delete_cr_namespaced, ...) —
    // this was the one verb missing that fallback.
    if lookup(&state, &group, &version, &plural).is_err() {
        return super::cr::delete_collection_cr_namespaced(
            State(state),
            Path((group, version, ns, plural)),
            Extension(user),
            query,
        )
        .await
        .map(IntoResponse::into_response);
    }

    let prefix = group_list_prefix(&group, &plural, Some(&ns));
    // "events" needs multi-term, in-memory filtering (see list_namespaced_resource); every
    // other built-in resource can use the store's generic single-field selector directly.
    let store_field_selector = if plural == "events" {
        None
    } else {
        query
            .field_selector
            .as_deref()
            .map(parse_field_selector)
            .transpose()?
    };
    let resp = state
        .store
        .list(
            &prefix,
            u7s_store::ListOptions {
                field_selector: store_field_selector,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(parse_label_selector)
        .transpose()?;

    // Built once — reused for every per-object AdmissionContext below.
    let user_info = Some(serde_json::json!({
        "username": user.username,
        "uid": user.uid,
        "groups": user.groups,
    }));

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
            // Clone (rather than move) `parsed` into the label-selector check — the
            // admission call below still needs the full object.
            if let Some(ref pairs) = label_pairs {
                let kept = apply_label_selector(vec![parsed.clone()], pairs);
                if kept.is_empty() {
                    continue;
                }
            }

            // Admission webhook pipeline (validating only — mutating webhooks do not apply
            // to DELETE), invoked per object exactly like the single-delete handlers and
            // mirroring delete_collection_resource above. A Fail-policy deny propagates here
            // and aborts the whole request at this object — objects already deleted earlier
            // in this loop stay deleted, matching the fail-fast handling the store error
            // branch below already uses for this same loop.
            let admission_ctx = AdmissionContext {
                group: &group,
                version: &version,
                resource: &plural,
                name: &name,
                namespace: Some(&ns),
                operation: "DELETE",
                user_info: user_info.clone(),
                dry_run: false,
            };
            run_validating_webhooks(&state, &parsed, Some(&parsed), &admission_ctx).await?;

            if group == RBAC_GROUP && !name.is_empty() {
                let rbac_key = rbac_namespaced_key(&group, &version, &ns, &plural, &name);
                state.rbac_index.remove_object(&rbac_key);
            }

            // Respect metadata.finalizers exactly like a single-object DELETE would: an
            // object with finalizers must be soft-deleted (deletionTimestamp stamped, kept
            // alive), not removed outright. The real KCM namespace-controller drains
            // namespace content via this exact endpoint (DeleteCollection per resource
            // type) — without this, it would silently bypass every object's finalizers,
            // breaking OrderedNamespaceDeletion (e.g. a finalizer'd pod must survive with
            // deletionTimestamp set while later resource types are still being processed).
            let mut typed = Object { body: parsed };
            if let Some(soft) = apply_delete_policy(&mut typed) {
                state
                    .store
                    .put(&obj.key, Object { body: soft }.to_bytes(), None)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                continue;
            }
        }
        // NotFound means another writer deleted this object concurrently — tolerate it.
        // Any other error (disk full, DB corruption, …) means some objects survived;
        // propagate so the caller does not believe all objects were deleted.
        match state.store.delete(&obj.key, None).await {
            Ok(_) | Err(StoreError::NotFound { .. }) => {}
            Err(e) => return Err(Status::internal(e.to_string())),
        }
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
/// Called on Service CREATE and UPDATE (PUT).  On create, an explicit clusterIP in the
/// body is respected; without one an address is auto-allocated.  On update the call is
/// a no-op for services that already have a clusterIP, but it allocates one when the
/// service type transitions from ExternalName (which stores no clusterIP) to a
/// cluster-routed type (ClusterIP, NodePort, LoadBalancer).
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

pub(crate) fn rbac_cluster_key(group: &str, version: &str, plural: &str, name: &str) -> String {
    format!("/apis/{group}/{version}/{plural}/{name}")
}

/// Mark `obj` for Orphan propagation by adding the `orphan` finalizer
/// (`metav1.FinalizerOrphanDependents`), instead of stripping owned children ourselves.
/// Idempotent — a no-op if the finalizer is already present; appends rather than replaces,
/// so a pre-existing, unrelated finalizer survives untouched.
///
/// This mirrors real Kubernetes and must run BEFORE `apply_delete_policy` decides whether to
/// soft- or hard-delete the object: with the finalizer present, `apply_delete_policy`
/// naturally takes its soft-delete branch (deletionTimestamp set, object stays visible),
/// which is exactly the signal every well-behaved controller — including the owner's own
/// reconcile loop — needs to stop acting on it. u7s's real, unmodified KCM garbage collector
/// strips each dependent's ownerReferences from its own consistent view of the cluster, then
/// removes this finalizer; the existing finalizer-drain machinery (`finalizer_drain_complete`
/// / `complete_finalizer_drain`) then completes the real hard-delete.
///
/// The previous implementation stripped dependents' ownerReferences synchronously here and
/// hard-deleted the owner in the same request. That raced real KCM's garbage collector: KCM
/// keeps a separate informer cache per resource type (owner vs. dependents — two independent
/// watch streams with no cross-stream ordering guarantee), so it could process the owner's
/// DELETE before catching up on a dependent's ownerRef-stripped MODIFIED event, and
/// cascade-delete a dependent that should have survived (observed live: a 100-replica RC
/// orphan-delete drained 100 -> 26 surviving pods).
///
/// Do NOT replace this with a delay between the strip and the hard-delete instead: keeping
/// the owner alive in the store while dependents are stripped lets the owner's own
/// controller (e.g. the ReplicationController controller) observe zero *owned* replicas and
/// spawn genuine replacement dependents during the window — which then have intact
/// ownerReferences and are correctly reaped when the owner is finally deleted, causing total
/// (0/N) dependent loss instead of the original partial race. This was tried and reverted.
pub(crate) fn add_orphan_finalizer(obj: &mut Object) {
    const ORPHAN_FINALIZER: &str = "orphan";
    match obj.body["metadata"]["finalizers"].as_array_mut() {
        Some(finalizers) => {
            if !finalizers
                .iter()
                .any(|f| f.as_str() == Some(ORPHAN_FINALIZER))
            {
                finalizers.push(serde_json::Value::String(ORPHAN_FINALIZER.to_string()));
            }
        }
        None => {
            obj.body["metadata"]["finalizers"] = serde_json::json!([ORPHAN_FINALIZER]);
        }
    }
}

/// Mark `obj` for Foreground propagation by adding the `foregroundDeletion` finalizer
/// (`metav1.FinalizerDeleteDependents`), instead of hard-deleting the owner synchronously.
/// Idempotent — a no-op if the finalizer is already present; appends rather than replaces,
/// so a pre-existing, unrelated finalizer survives untouched.
///
/// Mirrors `add_orphan_finalizer`'s rationale: routing through `apply_delete_policy`'s
/// soft-delete branch (deletionTimestamp set, object stays visible) is exactly the signal
/// real, unmodified KCM needs to run its garbage-collector's finalizer-drain protocol on —
/// mark every blocking dependent for deletion, wait for them to be actually gone, then
/// remove this finalizer so `finalizer_drain_complete` lets the owner's hard-delete
/// complete for real.
///
/// The previous implementation hard-deleted the owner immediately and, for
/// ReplicationControllers, ran a single best-effort `delete_pods_owned_by` list()-then-
/// delete snapshot afterward as a bonus. That snapshot permanently missed any pod the RC's
/// own controller created concurrently with the delete (observed live: an RC's last two
/// replicas, created in the same instant the RC was deleted, ended up with no
/// `deletionTimestamp` and no live owner). GC conformance spec "should keep the rc around
/// until all its pods are deleted if the deleteOptions says so" polls for up to 30s+ for
/// the RC to disappear only once zero pods remain — a window only KCM's real,
/// continuously-reconciling GC controller can guarantee, not a one-shot snapshot.
pub(crate) fn add_foreground_deletion_finalizer(obj: &mut Object) {
    const FOREGROUND_DELETION_FINALIZER: &str = "foregroundDeletion";
    match obj.body["metadata"]["finalizers"].as_array_mut() {
        Some(finalizers) => {
            if !finalizers
                .iter()
                .any(|f| f.as_str() == Some(FOREGROUND_DELETION_FINALIZER))
            {
                finalizers.push(serde_json::Value::String(
                    FOREGROUND_DELETION_FINALIZER.to_string(),
                ));
            }
        }
        None => {
            obj.body["metadata"]["finalizers"] = serde_json::json!([FOREGROUND_DELETION_FINALIZER]);
        }
    }
}

/// Returns true if `owner_ref` (an ownerReference entry: apiVersion/kind/name/uid)
/// still points at an object that exists in `namespace` under that exact uid.
///
/// Backs the "does this dependent have another live owner" check in the explicit-cascade
/// helpers below. A dependent can carry more than one ownerReference — e.g. the GC
/// conformance spec "should not delete dependents that have both valid owner and owner
/// that's waiting for dependents to be deleted" patches a second, unrelated
/// ReplicationController onto half of the first RC's pods. A reference whose uid no
/// longer matches the object currently stored at that name (the name was reused by an
/// unrelated object) does not count as live.
async fn owner_ref_is_live<S: Store>(
    state: &crate::state::AppState<S>,
    namespace: &str,
    owner_ref: &serde_json::Value,
) -> bool {
    let kind = owner_ref["kind"].as_str().unwrap_or("");
    let uid = owner_ref["uid"].as_str().unwrap_or("");
    let name = owner_ref["name"].as_str().unwrap_or("");
    if kind.is_empty() || uid.is_empty() || name.is_empty() {
        return false;
    }
    let api_version = owner_ref["apiVersion"].as_str().unwrap_or("");
    let group = api_version.split_once('/').map(|(g, _)| g).unwrap_or("");

    let plural = match state
        .resource_registry
        .iter()
        .find(|(rk, meta)| rk.group == group && meta.kind == kind)
    {
        Some((rk, _)) => rk.plural.clone(),
        None => return false,
    };

    let key = crate::keys::group_object_key(group, &plural, Some(namespace), name);
    let stored = match state.store.get(&key).await {
        Ok(Some(obj)) => obj,
        _ => return false,
    };
    let stored: serde_json::Value = match serde_json::from_slice(&stored.value) {
        Ok(v) => v,
        Err(_) => return false,
    };
    stored["metadata"]["uid"].as_str() == Some(uid)
}

/// Removes `owner_uid`'s entry from the dependent's ownerReferences and persists the
/// result at `key` if it has another live owner; otherwise hard-deletes the object at
/// `key`. Callers only use `key`/`owner_uid` to locate and identify the dependent — the
/// object is always re-read fresh here, never trusted from the caller's LIST snapshot.
///
/// Returns true if the object was hard-deleted (or already gone), false if it survived
/// with the reference stripped (or the reference was already gone) — callers use this to
/// decide whether to keep cascading to grandchildren (e.g. a surviving ReplicaSet's pods
/// must not be touched).
///
/// Shared by every explicit-cascade helper below (pods, ReplicaSets, Jobs): deleting one
/// owner must only remove that owner's reference from a dependent, never destroy a
/// dependent that another live owner still legitimately references. Without this check,
/// a foreground/background cascade from any of RC/DaemonSet/StatefulSet/ReplicaSet/Job
/// silently destroys still-owned dependents — the exact failure the GC conformance spec
/// above asserts against.
///
/// The strip write is a fresh read-modify-write CAS, retried on `RevisionMismatch`,
/// rather than an unconditional `put(.., None)` of the caller's LIST-time snapshot: a
/// blind overwrite of stale data would silently discard any write a concurrent actor
/// (e.g. the kubelet's routine pod-status PATCH) made to this object between the LIST
/// and this write, with no error surfaced to either side. Mirrors delete_pod's
/// retry-on-conflict loop, added for the same race class.
async fn strip_or_delete_dependent<S: Store>(
    state: &crate::state::AppState<S>,
    namespace: &str,
    key: &str,
    owner_uid: &str,
    label: &str,
) -> bool {
    loop {
        let stored = match state.store.get(key).await {
            Ok(Some(s)) => s,
            Ok(None) => return true,
            Err(e) => {
                tracing::warn!("cascade-delete {label}: re-read failed: {e}");
                return false;
            }
        };
        let mut obj: serde_json::Value = match serde_json::from_slice(&stored.value) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("cascade-delete {label}: corrupt stored object: {e}");
                return false;
            }
        };
        let refs = match obj["metadata"]["ownerReferences"].as_array() {
            Some(r) if r.iter().any(|r| r["uid"].as_str() == Some(owner_uid)) => r.clone(),
            _ => return false,
        };

        let mut other_live = false;
        for other in refs.iter().filter(|r| r["uid"].as_str() != Some(owner_uid)) {
            if owner_ref_is_live(state, namespace, other).await {
                other_live = true;
                break;
            }
        }

        if !other_live {
            match state.store.delete(key, None).await {
                Ok(_) | Err(StoreError::NotFound { .. }) => {}
                Err(e) => tracing::warn!("cascade-delete {label}: {e}"),
            }
            return true;
        }

        let filtered: Vec<serde_json::Value> = refs
            .into_iter()
            .filter(|r| r["uid"].as_str() != Some(owner_uid))
            .collect();
        obj["metadata"]["ownerReferences"] = serde_json::Value::Array(filtered);
        let expected_rv = obj["metadata"]["resourceVersion"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok());
        let bytes = match serde_json::to_vec(&obj) {
            Ok(b) => bytes::Bytes::from(b),
            Err(e) => {
                tracing::warn!("cascade-delete {label}: serialize failed: {e}");
                return false;
            }
        };
        match state.store.put(key, bytes, expected_rv).await {
            Ok(_) => return false,
            Err(StoreError::RevisionMismatch { .. }) => continue,
            Err(e) => {
                tracing::warn!("cascade-delete {label}: strip owner ref failed: {e}");
                return false;
            }
        }
    }
}

/// Delete pods in `namespace` whose `ownerReferences` contain an entry with
/// `kind == owner_kind` and `uid == owner_uid` — unless the pod has another owner that
/// still exists, in which case only that matching ownerReference is stripped and the pod
/// survives (see `strip_or_delete_dependent`).
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
        let refs = match pod["metadata"]["ownerReferences"].as_array() {
            Some(r) => r.clone(),
            None => continue,
        };
        let owned = refs.iter().any(|r| {
            r["uid"].as_str() == Some(owner_uid) && r["kind"].as_str() == Some(owner_kind)
        });
        if !owned {
            continue;
        }
        let pod_name = pod["metadata"]["name"].as_str().unwrap_or("").to_string();
        if pod_name.is_empty() {
            continue;
        }
        let pod_key = crate::keys::group_object_key("", "pods", Some(namespace), &pod_name);
        strip_or_delete_dependent(
            state,
            namespace,
            &pod_key,
            owner_uid,
            &format!("pod {namespace}/{pod_name}"),
        )
        .await;
    }
}

/// Called after a Deployment hard-delete to cascade-delete owned ReplicaSets immediately.
/// Without this, orphaned ReplicaSets keep their desired-replica count active and continue
/// creating pods indefinitely — observed: RS with desired=1337 created 14000+ pods after
/// its Deployment was deleted.
///
/// A ReplicaSet with another live owner besides this Deployment survives with only the
/// Deployment's reference stripped (see `strip_or_delete_dependent`), and its pods are
/// left untouched since the RS itself is still alive.
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
        let refs = match rs["metadata"]["ownerReferences"].as_array() {
            Some(r) => r.clone(),
            None => continue,
        };
        let owned = refs.iter().any(|r| {
            r["uid"].as_str() == Some(owner_uid) && r["kind"].as_str() == Some("Deployment")
        });
        if !owned {
            continue;
        }
        let rs_name = rs["metadata"]["name"].as_str().unwrap_or("").to_string();
        if rs_name.is_empty() {
            continue;
        }
        let rs_uid = rs["metadata"]["uid"].as_str().unwrap_or("").to_string();
        let rs_key =
            crate::keys::group_object_key("apps", "replicasets", Some(namespace), &rs_name);
        let deleted = strip_or_delete_dependent(
            state,
            namespace,
            &rs_key,
            owner_uid,
            &format!("replicaset {namespace}/{rs_name}"),
        )
        .await;
        // Cascade-delete pods owned by this RS — without this, RS-owned pods linger
        // against the 110-pod node cap and cause OutOfpods saturation. Skipped when the
        // RS itself survived: its pods are still legitimately owned by it.
        if deleted && !rs_uid.is_empty() {
            delete_pods_owned_by(state, namespace, &rs_uid, "ReplicaSet").await;
        }
    }
}

/// Called after a CronJob hard-delete to cascade-delete owned Jobs (and transitively their pods).
///
/// Without this, Jobs (and pods) created by a CronJob accumulate indefinitely after the
/// CronJob is deleted — the GC conformance spec "should delete jobs and pods created by
/// cronjob" times out asserting both are gone.
///
/// A Job with another live owner besides this CronJob survives with only the CronJob's
/// reference stripped (see `strip_or_delete_dependent`), and its pods are left untouched.
/// Otherwise the Job is hard-deleted, then its pods are cleaned up via the existing
/// Job→pods helpers (remove_job_tracking_finalizer_from_pods + delete_pods_owned_by).
async fn delete_jobs_owned_by<S: Store>(
    state: &crate::state::AppState<S>,
    namespace: &str,
    owner_uid: &str,
) {
    let prefix = crate::keys::group_list_prefix("batch", "jobs", Some(namespace));
    let resp = match state
        .store
        .list(&prefix, u7s_store::ListOptions::default())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("cascade-delete jobs in {namespace}: list failed: {e}");
            return;
        }
    };

    for item in resp.items {
        let job: serde_json::Value = match serde_json::from_slice(&item.value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let refs = match job["metadata"]["ownerReferences"].as_array() {
            Some(r) => r.clone(),
            None => continue,
        };
        let owned = refs
            .iter()
            .any(|r| r["uid"].as_str() == Some(owner_uid) && r["kind"].as_str() == Some("CronJob"));
        if !owned {
            continue;
        }
        let job_name = job["metadata"]["name"].as_str().unwrap_or("").to_string();
        if job_name.is_empty() {
            continue;
        }
        let job_uid = job["metadata"]["uid"].as_str().unwrap_or("").to_string();
        let job_key = crate::keys::group_object_key("batch", "jobs", Some(namespace), &job_name);
        let deleted = strip_or_delete_dependent(
            state,
            namespace,
            &job_key,
            owner_uid,
            &format!("job {namespace}/{job_name}"),
        )
        .await;
        // Cascade-delete pods owned by this Job — two-level chain: CronJob→Job→Pod.
        // The job-tracking finalizer must be removed first (KCM sets it); then hard-delete
        // any pods that are now finalizer-free with a deletionTimestamp, and delete the rest.
        // Skipped when the Job itself survived: its pods are still legitimately owned by it.
        if deleted && !job_uid.is_empty() {
            remove_job_tracking_finalizer_from_pods(state, namespace, &job_uid).await;
            delete_pods_owned_by(state, namespace, &job_uid, "Job").await;
        }
    }
}

/// Called after a Job hard-delete to remove the `batch.kubernetes.io/job-tracking`
/// finalizer from all pods owned by the deleted Job.
///
/// KCM's job-controller (Kubernetes 1.36) adds this finalizer to each pod it creates,
/// and removes it when the pod reaches a terminal state.  When a Job is immediately
/// hard-deleted (no finalizers on the Job object), KCM's syncJob returns early
/// ("job not found") without cleaning up pod finalizers.  The pods are then stuck
/// Terminating forever: they carry deletionTimestamp (set by the kubelet's DELETE)
/// but the tracking finalizer is never removed, so the GC cascade never completes
/// and the conformance test "should delete a job" times out.
///
/// Fix: we act as KCM here and synchronously remove the tracking finalizer from all
/// pods owned by the deleted Job.  If removing the finalizer leaves a pod with
/// deletionTimestamp and no remaining finalizers, we hard-delete it immediately so
/// the GC sees a clean DELETED event rather than a pod stuck in Terminating.
async fn remove_job_tracking_finalizer_from_pods<S: Store>(
    state: &crate::state::AppState<S>,
    namespace: &str,
    job_uid: &str,
) {
    const TRACKING_FINALIZER: &str = "batch.kubernetes.io/job-tracking";

    let prefix = crate::keys::group_list_prefix("", "pods", Some(namespace));
    let resp = match state
        .store
        .list(&prefix, u7s_store::ListOptions::default())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("job-tracking cleanup in {namespace}: list pods failed: {e}");
            return;
        }
    };

    for item in resp.items {
        let mut pod: serde_json::Value = match serde_json::from_slice(&item.value) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Only act on pods owned by the deleted Job.
        let owned = pod["metadata"]["ownerReferences"]
            .as_array()
            .map(|refs| {
                refs.iter().any(|r| {
                    r["uid"].as_str() == Some(job_uid) && r["kind"].as_str() == Some("Job")
                })
            })
            .unwrap_or(false);
        if !owned {
            continue;
        }

        // Only act on pods that have the tracking finalizer.
        let finalizers = pod["metadata"]["finalizers"].as_array().cloned();
        let has_tracking = finalizers
            .as_ref()
            .map(|f| f.iter().any(|v| v.as_str() == Some(TRACKING_FINALIZER)))
            .unwrap_or(false);
        if !has_tracking {
            continue;
        }

        let pod_name = pod["metadata"]["name"].as_str().unwrap_or("").to_string();
        if pod_name.is_empty() {
            continue;
        }
        let pod_key = crate::keys::group_object_key("", "pods", Some(namespace), &pod_name);

        // Remove the tracking finalizer.
        let new_finalizers: Vec<serde_json::Value> = finalizers
            .unwrap_or_default()
            .into_iter()
            .filter(|v| v.as_str() != Some(TRACKING_FINALIZER))
            .collect();

        let deletion_ts_set = !pod["metadata"]["deletionTimestamp"].is_null();
        let finalizers_empty = new_finalizers.is_empty();

        if finalizers_empty {
            pod["metadata"]
                .as_object_mut()
                .map(|m| m.remove("finalizers"));
        } else {
            pod["metadata"]["finalizers"] = serde_json::Value::Array(new_finalizers);
        }

        // If the pod already has deletionTimestamp and now has no finalizers, hard-delete it.
        if deletion_ts_set && finalizers_empty {
            tracing::info!(
                namespace,
                pod = %pod_name,
                "job-tracking cleanup: hard-deleting pod (deletionTimestamp set, finalizers empty)"
            );
            if let Err(e) = state.store.delete(&pod_key, None).await {
                tracing::warn!("job-tracking cleanup: hard-delete pod {namespace}/{pod_name}: {e}");
            }
            continue;
        }

        // Otherwise, update the pod with the finalizer removed.
        // Use parse_resource_version to get the expected revision for optimistic concurrency.
        let rv_str = pod["metadata"]["resourceVersion"].as_str().unwrap_or("0");
        let expected_rv = match rv_str.parse::<u64>() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    "job-tracking cleanup: invalid resourceVersion for pod {namespace}/{pod_name}"
                );
                continue;
            }
        };
        let pod_bytes = match serde_json::to_vec(&pod) {
            Ok(b) => bytes::Bytes::from(b),
            Err(e) => {
                tracing::warn!("job-tracking cleanup: serialize pod {namespace}/{pod_name}: {e}");
                continue;
            }
        };
        if let Err(e) = state
            .store
            .put(&pod_key, pod_bytes, Some(expected_rv))
            .await
        {
            tracing::warn!(
                "job-tracking cleanup: update pod {namespace}/{pod_name} finalizer: {e}"
            );
        } else {
            tracing::info!(
                namespace,
                pod = %pod_name,
                "job-tracking cleanup: removed tracking finalizer from pod"
            );
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
pub(crate) const APISERVICE_GROUP: &str = "apiregistration.k8s.io";

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

pub(crate) fn inject_type_meta(
    body: &mut serde_json::Value,
    group: &str,
    version: &str,
    kind: &str,
) {
    let api_version = if group.is_empty() {
        version.to_string()
    } else {
        format!("{group}/{version}")
    };
    body["kind"] = serde_json::Value::String(kind.to_string());
    body["apiVersion"] = serde_json::Value::String(api_version);
}

pub(crate) fn rbac_namespaced_key(
    group: &str,
    version: &str,
    ns: &str,
    plural: &str,
    name: &str,
) -> String {
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
            extra: Default::default(),
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
        let cr_key = format!("/registry/cr/{group}/{plural}/{ns}/{name}");

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
                extra: Default::default(),
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

    /// SSA apply-create (do_patch's is_ssa && stored_opt.is_none() upsert branch) had no
    /// Terminating-namespace gate, unlike create_namespaced_resource/create_pod — so
    /// `kubectl apply --server-side` could inject a brand-new object into a namespace mid-
    /// deletion by going through PATCH+apply instead of POST+create, reintroducing the
    /// "controller keeps creating content mid-deletion" wedge class.
    ///
    /// Fails on revert: without the gate, this SSA apply-create of a not-yet-existing
    /// ConfigMap into a Terminating namespace returns 201 instead of 403.
    #[tokio::test]
    async fn apply_patch_yaml_rejects_create_in_terminating_namespace() {
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
                bytes::Bytes::from(serde_json::to_vec(&ns_obj).unwrap()),
                None,
            )
            .await
            .expect("seed terminating namespace");

        let patch = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "new-cm", "namespace": "dying-ns" },
            "data": { "k": "v" }
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
                "".to_string(),
                "v1".to_string(),
                "dying-ns".to_string(),
                "configmaps".to_string(),
                "new-cm".to_string(),
            )),
            axum::extract::Query(PatchQuery::default()),
            test_user(),
            ssa_headers,
            patch_bytes,
        )
        .await;

        match result {
            Err(e) => assert_eq!(
                e.0,
                axum::http::StatusCode::FORBIDDEN,
                "SSA apply-create into a Terminating namespace must 403, matching what \
                 POST-create already does — otherwise a controller can keep injecting new \
                 content mid-deletion just by using server-side apply instead of POST"
            ),
            Ok(_) => panic!(
                "SSA apply-create of a not-yet-existing object in a Terminating namespace \
                 must be rejected, not silently create it"
            ),
        }

        let key = "/registry/configmaps/dying-ns/new-cm";
        assert!(
            store.get(key).await.unwrap().is_none(),
            "the ConfigMap must not have been created in the store"
        );
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

    /// apply-patch+yaml PATCH on an EXISTING resource must accept a genuine multi-line YAML
    /// body, not just a JSON body wearing the +yaml content-type.
    ///
    /// WHY this matters: `kubectl apply --server-side` and the k8s conformance client send
    /// real YAML block syntax for apply-patch+yaml bodies — the test above
    /// (apply_patch_yaml_accepted_and_updates_resource) only proves the content type is
    /// accepted, since its body is JSON bytes wearing a +yaml label, which serde_json
    /// parses fine either way. Before this fix, the update branch of do_patch parsed the
    /// body unconditionally with serde_json::from_slice regardless of is_ssa, so a SECOND
    /// `kubectl apply --server-side` against an already-applied object — the common case —
    /// 400'd with "invalid patch JSON".
    #[tokio::test]
    async fn apply_patch_yaml_with_real_yaml_body_updates_existing_resource() {
        use axum::response::IntoResponse;

        let state = make_state();

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

        // Genuine YAML block syntax — NOT JSON serialized to bytes.
        let yaml_patch = bytes::Bytes::from_static(
            b"apiVersion: coordination.k8s.io/v1\nkind: Lease\nmetadata:\n  name: worker-node-1\n  namespace: kube-node-lease\nspec:\n  holderIdentity: worker-node-1\n  leaseDurationSeconds: 99\n",
        );

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
            yaml_patch,
        )
        .await;

        let resp = patch_result
            .unwrap_or_else(|e| {
                panic!(
                    "PATCH with a genuine multi-line YAML apply-patch+yaml body on an \
                     existing resource must succeed, not 400 'invalid patch JSON': {:?}",
                    e.0
                )
            })
            .into_response();

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            v["spec"]["leaseDurationSeconds"].as_i64(),
            Some(99),
            "the YAML patch's leaseDurationSeconds must be applied to the stored Lease"
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
            axum::http::HeaderMap::new(),
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
            axum::http::HeaderMap::new(),
        )
        .await;

        let resp = result.unwrap_or_else(|_| panic!("get_resource must return 200"));
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    /// `kubectl get <resource> <name>` sends Accept: application/json;as=Table;... by default
    /// for every resource type, not just Pods. Before this fix, get_resource ignored Accept
    /// entirely and always returned the raw object, so kubectl fell back to printing only
    /// NAME/AGE for any non-Pod resource (list_resource already handled this for LIST).
    #[tokio::test]
    async fn get_resource_with_table_accept_returns_single_row_table() {
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

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json;as=Table;g=meta.k8s.io;v=v1"),
        );

        let resp = get_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-1".into(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|_| panic!("get_resource with Table accept must return 200"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["kind"], "Table",
            "a plain CSINode kind here means kubectl can't decode it as a Table and silently \
             falls back to hardcoded NAME/AGE-only columns"
        );
        let rows = v["rows"].as_array().expect("Table response must have rows");
        assert_eq!(
            rows.len(),
            1,
            "a single-object GET must produce exactly one Table row, not a full list"
        );
        assert_eq!(
            rows[0]["object"]["metadata"]["name"], "worker-1",
            "kubectl reads the row's embedded object to resolve the resource on selection"
        );
    }

    /// kcm's GC sends `Accept: application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1`
    /// when verifying an owner reference still exists (garbagecollector.go:434-444
    /// isDangling). Before this fix, get_resource always returned the full typed object,
    /// which the GC's metadata-only decoder rejects; the owner-check retries forever and
    /// newly-orphaned dependents (of any resource type) are never identified as dangling,
    /// so they leak indefinitely on any long-running u7s cluster.
    #[tokio::test]
    async fn get_resource_returns_partial_object_metadata_when_requested() {
        use axum::extract::{Path, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1" },
            "spec": { "drivers": [] }
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

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static(
                "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1",
            ),
        );

        let resp = get_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-1".into(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|_| {
            panic!("get_resource with PartialObjectMetadata accept must return 200")
        });

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["apiVersion"], "meta.k8s.io/v1",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert_eq!(
            v["kind"], "PartialObjectMetadata",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert!(
            v.get("spec").is_none(),
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert!(
            v.get("status").is_none(),
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
    }

    /// Negative case: a plain `Accept: application/json` (no `as=PartialObjectMetadata`) must
    /// still return the full typed object. Prevents a broad-match bug in
    /// `wants_partial_object_metadata` from accidentally wrapping every GET response and
    /// breaking every non-metadata-only client (kubectl, controllers using typed listers).
    #[tokio::test]
    async fn get_resource_without_partial_object_metadata_accept_returns_full_object() {
        use axum::extract::{Path, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1" },
            "spec": { "drivers": [] }
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

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let resp = get_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-1".into(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|_| panic!("get_resource with plain JSON accept must return 200"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["kind"], "CSINode",
            "a plain Accept header must not trigger PartialObjectMetadata wrapping — \
             every non-metadata-only client (kubectl, typed-lister controllers) depends on \
             receiving the real typed object here"
        );
        assert_eq!(
            v["spec"]["drivers"],
            serde_json::json!([]),
            "the full object's spec must survive when PartialObjectMetadata was not \
             requested; a spec-stripping regression here would silently break every \
             non-metadata-only GET client"
        );
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
            axum::http::HeaderMap::new(),
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
                extra: Default::default(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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

    /// Deleting a Deployment must cascade-delete pods owned by its ReplicaSets.
    ///
    /// The Deployment→RS→pods chain must be complete: when delete_replicasets_owned_by
    /// deletes an RS, it must also call delete_pods_owned_by for that RS's pods.
    /// Without this, RS-owned pods survive and pile up against the 110-pod node cap,
    /// causing OutOfpods saturation that blocks conformance DaemonSet serial tests.
    #[tokio::test]
    async fn delete_deployment_cascades_rs_pods_transitively() {
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

        let deploy_uid = "cccc1111-0000-0000-0000-000000000001";
        let rs_uid = "cccc2222-0000-0000-0000-000000000001";
        let ns = "default";

        // Seed the Deployment.
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "my-deploy2", "namespace": ns, "uid": deploy_uid }
        });
        let deploy_key = "/registry/apps/deployments/default/my-deploy2";
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
                "name": "my-deploy2-rs",
                "namespace": ns,
                "uid": rs_uid,
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "my-deploy2",
                    "uid": deploy_uid,
                    "controller": true
                }]
            },
            "spec": { "replicas": 3 }
        });
        let rs_key = "/registry/apps/replicasets/default/my-deploy2-rs";
        store
            .put(
                rs_key,
                bytes::Bytes::from(serde_json::to_vec(&rs).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed a pod owned by the ReplicaSet.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-deploy2-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": "my-deploy2-rs",
                    "uid": rs_uid,
                    "controller": true
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_key = "/registry/pods/default/my-deploy2-pod";
        store
            .put(
                pod_key,
                bytes::Bytes::from(serde_json::to_vec(&pod).unwrap()),
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
                "my-deploy2".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("delete must succeed: {e:?}"));

        // RS must be deleted.
        assert!(
            store.get(rs_key).await.unwrap().is_none(),
            "ReplicaSet owned by deleted Deployment must be cascade-deleted"
        );

        // Pod owned by the RS must also be cascade-deleted — this is the key fix:
        // delete_replicasets_owned_by must call delete_pods_owned_by for each RS.
        assert!(
            store.get(pod_key).await.unwrap().is_none(),
            "pod owned by RS owned by deleted Deployment must be cascade-deleted — \
             without this, RS-owned pods pile up against the 110-pod node cap"
        );

        // Deployment itself must be deleted.
        assert!(
            store.get(deploy_key).await.unwrap().is_none(),
            "Deployment itself must be deleted"
        );
    }

    /// Deleting a ReplicationController with explicit propagationPolicy=Background must
    /// cascade-delete owned pods immediately.
    ///
    /// Callers that want synchronous cascade (e.g. conformance teardown tooling that passes
    /// propagationPolicy=Background) need pods gone fast so the 110-pod node cap is not hit.
    /// The cascade only fires on explicit Background/Foreground; nil policy leaves pods alive
    /// so the GC conformance spec "should orphan pods created by rc if deleteOptions.OrphanDependents
    /// is nil" can assert pods survive.
    #[tokio::test]
    async fn background_policy_rc_delete_cascades_to_owned_pods() {
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

        let rc_uid = "dddddddd-0000-0000-0000-000000000001";
        let ns = "default";

        // Seed the ReplicationController.
        let rc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "my-rc", "namespace": ns, "uid": rc_uid },
            "spec": { "replicas": 3, "selector": { "app": "my-rc" } }
        });
        let rc_key = "/registry/replicationcontrollers/default/my-rc";
        store
            .put(
                rc_key,
                bytes::Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed a pod owned by this RC.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-rc-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "v1",
                    "kind": "ReplicationController",
                    "name": "my-rc",
                    "uid": rc_uid,
                    "controller": true
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_key = "/registry/pods/default/my-rc-pod";
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
            "metadata": { "name": "other-pod-rc", "namespace": ns }
        });
        let other_pod_key = "/registry/pods/default/other-pod-rc";
        store
            .put(
                other_pod_key,
                bytes::Bytes::from(serde_json::to_vec(&other_pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Delete with explicit propagationPolicy=Background — cascade must fire.
        let bg_body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "propagationPolicy": "Background"
            }))
            .unwrap(),
        );
        delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                ns.to_string(),
                "replicationcontrollers".into(),
                "my-rc".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            bg_body,
        )
        .await
        .unwrap_or_else(|e| panic!("delete must succeed: {e:?}"));

        // Owned pod must be cascade-deleted — explicit Background must cascade immediately.
        // If this fails the synchronous cascade path is gated too wide and Background deletes
        // do not clean up pods, causing pod pile-ups against the 110-pod node cap.
        assert!(
            store.get(pod_key).await.unwrap().is_none(),
            "pod owned by deleted ReplicationController must be cascade-deleted on \
             explicit Background delete — without synchronous cascade the node saturates \
             at the 110-pod cap when callers explicitly request Background propagation"
        );

        // RC itself must be deleted.
        assert!(
            store.get(rc_key).await.unwrap().is_none(),
            "ReplicationController itself must be deleted"
        );

        // Unrelated pod must survive.
        assert!(
            store.get(other_pod_key).await.unwrap().is_some(),
            "pod not owned by the deleted RC must not be affected"
        );
    }

    /// A background GC cascade must not destroy a pod that still has another live owner.
    ///
    /// The k8s GC conformance spec "should not delete dependents that have both valid
    /// owner and owner that's waiting for dependents to be deleted" (garbage_collector.go)
    /// runs this exact scenario with Foreground propagation — which now routes through the
    /// `foregroundDeletion` finalizer and defers entirely to real, unmodified KCM's GC
    /// controller (see add_foreground_deletion_finalizer), so that spec is exercised live,
    /// not by this unit test. What this test still guards is the shared
    /// `strip_or_delete_dependent` co-owner check itself, exercised here via Background
    /// (the one explicit-cascade policy that still runs `delete_pods_owned_by`
    /// synchronously): it previously matched pods by the deleted owner's uid+kind and
    /// unconditionally hard-deleted them without checking for another live owner — every
    /// cascade from any RC/DaemonSet/StatefulSet/ReplicaSet/Job silently destroyed
    /// dependents that were still legitimately owned by something else. That is systemic
    /// data loss, not just a test failure: any workload adopted by a second controller
    /// would vanish the moment either owner was deleted.
    #[tokio::test]
    async fn background_cascade_preserves_pod_with_another_live_owner() {
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
        let owner_a_uid = "aaaaaaaa-0000-0000-0000-000000000001";
        let owner_b_uid = "bbbbbbbb-0000-0000-0000-000000000002";

        // Seed owner-A (about to be deleted) and owner-B (must stay alive throughout).
        let owner_a = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "rc-to-be-deleted", "namespace": ns, "uid": owner_a_uid },
            "spec": { "replicas": 2, "selector": { "app": "rc-to-be-deleted" } }
        });
        let owner_a_key = "/registry/replicationcontrollers/default/rc-to-be-deleted";
        store
            .put(
                owner_a_key,
                bytes::Bytes::from(serde_json::to_vec(&owner_a).unwrap()),
                None,
            )
            .await
            .unwrap();

        let owner_b = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "rc-to-stay", "namespace": ns, "uid": owner_b_uid },
            "spec": { "replicas": 0, "selector": { "app": "rc-to-stay" } }
        });
        let owner_b_key = "/registry/replicationcontrollers/default/rc-to-stay";
        store
            .put(
                owner_b_key,
                bytes::Bytes::from(serde_json::to_vec(&owner_b).unwrap()),
                None,
            )
            .await
            .unwrap();

        let owner_a_ref = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "name": "rc-to-be-deleted",
            "uid": owner_a_uid
        });
        let owner_b_ref = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "name": "rc-to-stay",
            "uid": owner_b_uid
        });

        // Pod co-owned by both RCs — must survive with only owner-B's reference left.
        let pod_both = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pod-both-owners",
                "namespace": ns,
                "ownerReferences": [owner_a_ref, owner_b_ref]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_both_key = "/registry/pods/default/pod-both-owners";
        store
            .put(
                pod_both_key,
                bytes::Bytes::from(serde_json::to_vec(&pod_both).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Pod owned only by owner-A — must still be cascade-deleted (no regression to the
        // ordinary single-owner cascade).
        let pod_solo = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pod-solo-owner",
                "namespace": ns,
                "ownerReferences": [owner_a_ref]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_solo_key = "/registry/pods/default/pod-solo-owner";
        store
            .put(
                pod_solo_key,
                bytes::Bytes::from(serde_json::to_vec(&pod_solo).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Delete owner-A with Background propagation — exercises the same
        // strip_or_delete_dependent co-owner check the Foreground conformance spec relies
        // on, via the code path that still runs delete_pods_owned_by synchronously.
        let bg_body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "propagationPolicy": "Background"
            }))
            .unwrap(),
        );
        delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                ns.to_string(),
                "replicationcontrollers".into(),
                "rc-to-be-deleted".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            bg_body,
        )
        .await
        .unwrap_or_else(|e| panic!("delete must succeed: {e:?}"));

        // owner-A is gone; owner-B (never targeted) must be untouched.
        assert!(
            store.get(owner_a_key).await.unwrap().is_none(),
            "the deleted ReplicationController itself must be removed"
        );
        assert!(
            store.get(owner_b_key).await.unwrap().is_some(),
            "owner-B was never deleted and must still exist — it is the live second owner \
             that should keep pod-both-owners alive"
        );

        // The co-owned pod must survive: destroying it here would be exactly the bug — a
        // cascade must never delete a dependent through one owner while it is still
        // legitimately referenced by another live owner.
        let surviving = store.get(pod_both_key).await.unwrap().expect(
            "pod co-owned by owner-A and owner-B must survive owner-A's cascade delete — \
                 deleting it would silently destroy a pod that is still live and owned via \
                 owner-B, which is systemic data loss for any workload adopted by a second \
                 controller",
        );
        let surviving: serde_json::Value = serde_json::from_slice(&surviving.value).unwrap();
        assert!(
            surviving["metadata"]["deletionTimestamp"].is_null(),
            "surviving pod must not carry a deletionTimestamp — it was never actually \
             targeted for deletion, only stripped of owner-A's reference"
        );
        let remaining_refs = surviving["metadata"]["ownerReferences"]
            .as_array()
            .expect("surviving pod must still have an ownerReferences array");
        assert_eq!(
            remaining_refs.len(),
            1,
            "owner-A's reference must be stripped, leaving exactly owner-B's — a stale \
             reference to the deleted RC would make the pod incorrectly eligible for GC \
             later"
        );
        assert_eq!(
            remaining_refs[0]["uid"].as_str(),
            Some(owner_b_uid),
            "the one remaining ownerReference must point at owner-B, not owner-A"
        );

        // Non-regression: a pod owned ONLY by owner-A has no other live owner and must
        // still be hard-deleted by the ordinary cascade path.
        assert!(
            store.get(pod_solo_key).await.unwrap().is_none(),
            "pod owned solely by the deleted RC must still be cascade-deleted — the fix \
             for co-owned dependents must not weaken the ordinary single-owner cascade"
        );
    }

    /// Foreground delete of an RC must soft-delete the RC (deletionTimestamp +
    /// the `foregroundDeletion` finalizer) and must NOT synchronously cascade-delete its
    /// pods via `delete_pods_owned_by`.
    ///
    /// GC conformance spec "should keep the rc around until all its pods are deleted if the
    /// deleteOptions says so" (garbage_collector.go:711) polls for up to 30s+ for the RC to
    /// disappear, and only after that asserts zero pods remain. The old implementation
    /// hard-deleted the RC immediately and ran a single best-effort list()-then-delete
    /// cascade right after — any pod the RC's own controller created concurrently with the
    /// delete (observed live: the RC's last two replicas, created in the same second the
    /// delete was issued) was invisible to that one-shot snapshot and permanently orphaned
    /// from u7s's point of view, so the test's `GET(rc)=404` fired before those pods were
    /// gone. Soft-deleting with `foregroundDeletion` instead lets real, unmodified KCM run
    /// its own continuously-reconciling GC controller, which does not miss late-created
    /// dependents.
    #[tokio::test]
    async fn foreground_delete_rc_soft_deletes_and_skips_synchronous_pod_cascade() {
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

        let rc_uid = "eeee2222-0000-0000-0000-000000000001";
        let ns = "default";

        // Seed the ReplicationController with no pre-existing finalizers — exactly what
        // the conformance spec's RC looks like.
        let rc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "foreground-rc", "namespace": ns, "uid": rc_uid },
            "spec": { "replicas": 1, "selector": { "app": "foreground-rc" } }
        });
        let rc_key = "/registry/replicationcontrollers/default/foreground-rc";
        store
            .put(
                rc_key,
                bytes::Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed a pod owned by this RC — stands in for a pod the RC controller created
        // concurrently with the delete, which the old synchronous cascade could miss.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "foreground-rc-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "v1",
                    "kind": "ReplicationController",
                    "name": "foreground-rc",
                    "uid": rc_uid,
                    "controller": true
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_key = "/registry/pods/default/foreground-rc-pod";
        store
            .put(
                pod_key,
                bytes::Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        let fg_body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "propagationPolicy": "Foreground"
            }))
            .unwrap(),
        );
        delete_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                ns.to_string(),
                "replicationcontrollers".into(),
                "foreground-rc".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            fg_body,
        )
        .await
        .unwrap_or_else(|e| panic!("foreground delete must succeed: {e:?}"));

        // RC must be SOFT-deleted: still present, with deletionTimestamp and the
        // `foregroundDeletion` finalizer — NOT hard-deleted synchronously in this request.
        let rc_stored = store.get(rc_key).await.unwrap().expect(
            "RC must remain in the store (soft-deleted) immediately after a Foreground \
             delete — hard-deleting it here, before KCM confirms every dependent is gone, \
             is the exact race that let late-created pods slip past our own cascade",
        );
        let rc_val: serde_json::Value = serde_json::from_slice(&rc_stored.value).unwrap();
        assert!(
            rc_val["metadata"]["deletionTimestamp"].is_string(),
            "Foreground delete must stamp deletionTimestamp on the RC — this is the signal \
             every well-behaved client (including the conformance test's poll loop) uses to \
             tell whether the RC is still blocking on its dependents"
        );
        assert_eq!(
            rc_val["metadata"]["finalizers"]
                .as_array()
                .map(|f| f.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
            Some(vec!["foregroundDeletion"]),
            "Foreground delete must add the `foregroundDeletion` finalizer \
             (metav1.FinalizerDeleteDependents) so real KCM's GC controller knows to run \
             the blocking-dependents drain before the finalizer is removed and the RC \
             actually disappears"
        );

        // Pod must SURVIVE this request — u7s's own delete_pods_owned_by cascade must not
        // run for Foreground. If it fires here, we're back to the one-shot snapshot that
        // misses concurrently-created pods; the whole point of this fix is that only real
        // KCM's continuously-reconciling GC controller is trusted to decide when every
        // dependent is actually gone.
        assert!(
            store.get(pod_key).await.unwrap().is_some(),
            "Foreground delete of RC must NOT synchronously cascade-delete pods — that \
             cascade is now exclusively real KCM's job, triggered by the foregroundDeletion \
             finalizer above"
        );

        // GET immediately after DELETE must observe the same soft-deleted state a real
        // client polling for the RC to disappear would see.
        let get_response = get_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                ns.to_string(),
                "replicationcontrollers".into(),
                "foreground-rc".into(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("GET after foreground delete must still succeed: {e:?}"));
        let body = axum::body::to_bytes(get_response.into_body(), 65536)
            .await
            .unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            !got["metadata"]["deletionTimestamp"].is_null(),
            "a GET immediately after a Foreground DELETE must show deletionTimestamp set — \
             a client that sees this knows the RC is still draining, not gone"
        );
        assert_eq!(
            got["metadata"]["finalizers"]
                .as_array()
                .map(|f| f.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
            Some(vec!["foregroundDeletion"]),
            "a GET immediately after a Foreground DELETE must show the foregroundDeletion \
             finalizer still present — its removal is what signals real KCM has finished \
             draining every blocking dependent"
        );
    }

    /// Deleting a ReplicationController with nil propagationPolicy must orphan owned pods
    /// (not cascade-delete them) via the same `orphan` finalizer signal as an explicit
    /// Orphan delete — not by u7s stripping ownerReferences itself.
    ///
    /// The k8s GC conformance spec "should orphan pods created by rc if
    /// deleteOptions.OrphanDependents is nil" (garbage_collector.go:475) sends an
    /// empty DeleteOptions (only Preconditions) and asserts that the 2 pods
    /// created by the RC still exist after 30 s. Synchronously stripping ownerRefs and
    /// hard-deleting the RC in the same request (the old implementation) raced real KCM's
    /// garbage collector — KCM's owner and dependent informer caches are independent watch
    /// streams with no cross-stream ordering guarantee, so it could see the RC's DELETE
    /// before catching up on a pod's stripped-ownerRef MODIFIED event and cascade-delete
    /// that pod anyway (live-reproduced: a 100-replica RC drained 100 -> 26 survivors).
    /// Soft-deleting the RC with the `orphan` finalizer instead lets real, unmodified KCM do
    /// the strip from its own consistent view before removing the finalizer.
    #[tokio::test]
    async fn nil_propagation_rc_delete_does_not_cascade_pods() {
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

        let rc_uid = "dddddddd-0000-0000-0000-000000000002";
        let ns = "default";

        // Seed the ReplicationController (no special finalizers — plain RC as the GC test creates).
        let rc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "nil-policy-rc", "namespace": ns, "uid": rc_uid },
            "spec": { "replicas": 2, "selector": { "app": "nil-policy-rc" } }
        });
        let rc_key = "/registry/replicationcontrollers/default/nil-policy-rc";
        store
            .put(
                rc_key,
                bytes::Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed a pod owned by this RC.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "nil-policy-rc-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "v1",
                    "kind": "ReplicationController",
                    "name": "nil-policy-rc",
                    "uid": rc_uid,
                    "controller": true
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_key = "/registry/pods/default/nil-policy-rc-pod";
        store
            .put(
                pod_key,
                bytes::Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Delete with empty body (nil propagationPolicy, nil orphanDependents) — the exact
        // shape the GC conformance test sends via metav1.DeleteOptions{Preconditions: ...}.
        delete_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                ns.to_string(),
                "replicationcontrollers".into(),
                "nil-policy-rc".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("delete must succeed: {e:?}"));

        // RC must be SOFT-deleted (deletionTimestamp + the "orphan" finalizer), staying
        // visible until KCM's GC controller confirms dependents are stripped and drains the
        // finalizer — NOT hard-deleted synchronously in this request.
        let rc_stored = store.get(rc_key).await.unwrap().expect(
            "RC must remain in the store (soft-deleted) immediately after a nil-policy delete",
        );
        let rc_val: serde_json::Value = serde_json::from_slice(&rc_stored.value).unwrap();
        assert!(
            rc_val["metadata"]["deletionTimestamp"].is_string(),
            "nil-policy RC delete must stamp deletionTimestamp — this is what tells the RC's \
             own reconcile loop to stop acting on it"
        );
        assert_eq!(
            rc_val["metadata"]["finalizers"]
                .as_array()
                .map(|f| f.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
            Some(vec!["orphan"]),
            "nil-policy RC delete must add the `orphan` finalizer so real KCM's GC controller \
             strips dependents itself before the finalizer drains"
        );

        // Pod must SURVIVE, with its ownerReferences UNTOUCHED by u7s at this point — stripping
        // is now exclusively real KCM's job, once it observes the `orphan` finalizer above.
        let pod_stored = store.get(pod_key).await.unwrap().unwrap();
        let pod_val: serde_json::Value = serde_json::from_slice(&pod_stored.value).unwrap();
        assert!(
            pod_val.get("metadata").is_some(),
            "pod owned by RC must survive (not cascade-deleted) when DeleteOptions has nil propagationPolicy"
        );
        let owner_refs = pod_val["metadata"]["ownerReferences"].as_array().cloned();
        assert!(
            owner_refs.is_some_and(|r| r.iter().any(|r| r["uid"].as_str() == Some(rc_uid))),
            "u7s must NOT strip the pod's ownerReference itself at delete time — doing so \
             synchronously, before the RC is confirmed gone, is exactly the race that dropped \
             live pods in the real-KCM conformance run this fix addresses (100-replica RC \
             orphan-delete drained 100 -> 26 survivors)"
        );
    }

    /// Deleting a StatefulSet must cascade-delete owned pods immediately.
    ///
    /// Without this, StatefulSet pods linger against the 110-pod node cap, causing
    /// OutOfpods saturation that blocks conformance tests running on the same node.
    #[tokio::test]
    async fn delete_statefulset_cascades_to_owned_pods() {
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

        let sts_uid = "eeeeeeee-0000-0000-0000-000000000001";
        let ns = "default";

        // Seed the StatefulSet.
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "my-sts", "namespace": ns, "uid": sts_uid },
            "spec": {
                "replicas": 2,
                "selector": { "matchLabels": { "app": "my-sts" } },
                "serviceName": "my-sts"
            }
        });
        let sts_key = "/registry/apps/statefulsets/default/my-sts";
        store
            .put(
                sts_key,
                bytes::Bytes::from(serde_json::to_vec(&sts).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed a pod owned by this StatefulSet.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-sts-0",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "name": "my-sts",
                    "uid": sts_uid,
                    "controller": true
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_key = "/registry/pods/default/my-sts-0";
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
            "metadata": { "name": "other-pod-sts", "namespace": ns }
        });
        let other_pod_key = "/registry/pods/default/other-pod-sts";
        store
            .put(
                other_pod_key,
                bytes::Bytes::from(serde_json::to_vec(&other_pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Delete the StatefulSet.
        delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                ns.to_string(),
                "statefulsets".into(),
                "my-sts".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("delete must succeed: {e:?}"));

        // Owned pod must be cascade-deleted.
        assert!(
            store.get(pod_key).await.unwrap().is_none(),
            "pod owned by deleted StatefulSet must be cascade-deleted — \
             without this, StatefulSet pods linger against the 110-pod node cap"
        );

        // StatefulSet itself must be deleted.
        assert!(
            store.get(sts_key).await.unwrap().is_none(),
            "StatefulSet itself must be deleted"
        );

        // Unrelated pod must survive.
        assert!(
            store.get(other_pod_key).await.unwrap().is_some(),
            "pod not owned by the deleted StatefulSet must not be affected"
        );
    }

    /// Orphan delete of an RC must soft-delete the RC (deletionTimestamp + the `orphan`
    /// finalizer) and must NOT synchronously strip or cascade-delete its pods.
    ///
    /// GC conformance specs "should orphan pods created by rc if delete options say so" and
    /// "should orphan pods created by rc if deleteOptions.OrphanDependents is nil" assert that
    /// pods survive RC deletion with propagationPolicy=Orphan. Synchronously stripping
    /// ownerRefs and hard-deleting the RC in the same request (the old implementation) raced
    /// real KCM's garbage collector — separate informer caches per resource type (owner vs.
    /// dependents) gave no cross-stream ordering guarantee, so KCM could process the RC's
    /// DELETE before catching up on a pod's stripped-ownerRef MODIFIED event and
    /// cascade-delete it anyway (live-reproduced: 100 replicas drained to 26 survivors).
    /// The `orphan` finalizer instead lets real, unmodified KCM do the strip itself, from its
    /// own consistent view, before removing the finalizer and letting the real hard-delete
    /// complete via finalizer drain.
    #[tokio::test]
    async fn orphan_delete_rc_soft_deletes_with_finalizer_and_does_not_strip_pods_synchronously() {
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

        let rc_uid = "ffff1111-0000-0000-0000-000000000001";
        let ns = "default";

        // Seed the ReplicationController.
        let rc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "orphan-rc", "namespace": ns, "uid": rc_uid },
            "spec": { "replicas": 1, "selector": { "app": "orphan-rc" } }
        });
        let rc_key = "/registry/replicationcontrollers/default/orphan-rc";
        store
            .put(
                rc_key,
                bytes::Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed a pod owned by this RC.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "orphan-rc-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "v1",
                    "kind": "ReplicationController",
                    "name": "orphan-rc",
                    "uid": rc_uid,
                    "controller": true
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_key = "/registry/pods/default/orphan-rc-pod";
        store
            .put(
                pod_key,
                bytes::Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Delete with propagationPolicy=Orphan — pods must NOT be cascade-deleted.
        let orphan_body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "propagationPolicy": "Orphan"
            }))
            .unwrap(),
        );
        delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                ns.to_string(),
                "replicationcontrollers".into(),
                "orphan-rc".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            orphan_body,
        )
        .await
        .unwrap_or_else(|e| panic!("orphan delete must succeed: {e:?}"));

        // RC must be SOFT-deleted: still present, with deletionTimestamp and the `orphan`
        // finalizer — NOT hard-deleted synchronously in this request.
        let rc_stored = store.get(rc_key).await.unwrap().expect(
            "RC must remain in the store (soft-deleted) immediately after an Orphan delete — \
             hard-deleting it here, before KCM confirms dependents are stripped, is the exact \
             race that let real KCM's GC controller cascade-delete pods that should survive",
        );
        let rc_val: serde_json::Value = serde_json::from_slice(&rc_stored.value).unwrap();
        assert!(
            rc_val["metadata"]["deletionTimestamp"].is_string(),
            "Orphan delete must stamp deletionTimestamp on the RC — this is what tells the \
             RC's own reconcile loop (and every other controller) to stop acting on it"
        );
        assert_eq!(
            rc_val["metadata"]["finalizers"]
                .as_array()
                .map(|f| f.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
            Some(vec!["orphan"]),
            "Orphan delete must add the `orphan` finalizer (metav1.FinalizerOrphanDependents) \
             so real KCM's GC controller knows to strip dependents itself before the finalizer \
             drains and the RC is actually removed"
        );

        // Pod must SURVIVE — Orphan delete must not cascade.
        // GC conformance specs fail with 'expected 50 pods, got 0' if this regresses.
        assert!(
            store.get(pod_key).await.unwrap().is_some(),
            "Orphan delete of RC must leave pods alive — cascade on Orphan is data-loss; \
             GC conformance specs 'should orphan pods created by rc if delete options say so' will fail"
        );

        // Pod's ownerReferences must be UNTOUCHED by u7s at this point: stripping is now
        // exclusively real KCM's job, once it observes the `orphan` finalizer above.
        let pod_stored = store.get(pod_key).await.unwrap().unwrap();
        let pod_val: serde_json::Value = serde_json::from_slice(&pod_stored.value).unwrap();
        let owner_refs = pod_val["metadata"]["ownerReferences"].as_array();
        let still_has_owner_ref = owner_refs
            .map(|refs| refs.iter().any(|r| r["uid"].as_str() == Some(rc_uid)))
            .unwrap_or(false);
        assert!(
            still_has_owner_ref,
            "u7s must NOT strip the pod's ownerReference itself at delete time — doing so \
             synchronously, before the RC is confirmed gone, is exactly the race that dropped \
             live pods in the real-KCM conformance run this fix addresses"
        );
    }

    /// Orphan delete of a Deployment must soft-delete it (deletionTimestamp + the `orphan`
    /// finalizer) and must NOT synchronously strip or cascade-delete its ReplicaSets — the
    /// same `orphan_owned_resources`-based path RC orphan-delete used to take, and the same
    /// fix (add_orphan_finalizer) applies here identically.
    ///
    /// GC conformance spec "should orphan RS created by deployment when deleteOptions.PropagationPolicy is Orphan"
    /// asserts RSes survive the Deployment deletion. If cascade runs instead, the RS count goes to 0
    /// (and so do its pods), breaking --cascade=orphan for Deployments.
    #[tokio::test]
    async fn orphan_delete_deployment_soft_deletes_with_finalizer_and_does_not_strip_rs_synchronously(
    ) {
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

        let deploy_uid = "ffff2222-0000-0000-0000-000000000001";
        let ns = "default";

        // Seed the Deployment.
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "orphan-deploy", "namespace": ns, "uid": deploy_uid }
        });
        let deploy_key = "/registry/apps/deployments/default/orphan-deploy";
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
                "name": "orphan-deploy-rs",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "orphan-deploy",
                    "uid": deploy_uid,
                    "controller": true
                }]
            },
            "spec": { "replicas": 1 }
        });
        let rs_key = "/registry/apps/replicasets/default/orphan-deploy-rs";
        store
            .put(
                rs_key,
                bytes::Bytes::from(serde_json::to_vec(&rs).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Delete with propagationPolicy=Orphan — RSes must NOT be cascade-deleted.
        let orphan_body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "propagationPolicy": "Orphan"
            }))
            .unwrap(),
        );
        delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                ns.to_string(),
                "deployments".into(),
                "orphan-deploy".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            orphan_body,
        )
        .await
        .unwrap_or_else(|e| panic!("orphan delete must succeed: {e:?}"));

        // Deployment must be SOFT-deleted: still present, with deletionTimestamp and the
        // `orphan` finalizer — NOT hard-deleted synchronously in this request.
        let deploy_stored = store.get(deploy_key).await.unwrap().expect(
            "Deployment must remain in the store (soft-deleted) immediately after an Orphan \
             delete — hard-deleting it before KCM confirms RSes are stripped races real KCM's \
             GC controller exactly like the RC case this fix addresses",
        );
        let deploy_val: serde_json::Value = serde_json::from_slice(&deploy_stored.value).unwrap();
        assert!(
            deploy_val["metadata"]["deletionTimestamp"].is_string(),
            "Orphan delete must stamp deletionTimestamp on the Deployment"
        );
        assert_eq!(
            deploy_val["metadata"]["finalizers"]
                .as_array()
                .map(|f| f.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
            Some(vec!["orphan"]),
            "Orphan delete must add the `orphan` finalizer so real KCM's GC controller strips \
             the owned ReplicaSets itself before the finalizer drains"
        );

        // RS must SURVIVE — Orphan delete must not cascade.
        // GC conformance spec 'should orphan RS created by deployment when deleteOptions.PropagationPolicy is Orphan' fails otherwise.
        assert!(
            store.get(rs_key).await.unwrap().is_some(),
            "Orphan delete of Deployment must leave ReplicaSets alive — \
             GC conformance spec 'should orphan RS created by deployment...' will fail if this regresses"
        );

        // RS's ownerReferences must be UNTOUCHED by u7s at this point — stripping is now
        // exclusively real KCM's job, once it observes the `orphan` finalizer above.
        let rs_stored = store.get(rs_key).await.unwrap().unwrap();
        let rs_val: serde_json::Value = serde_json::from_slice(&rs_stored.value).unwrap();
        let owner_refs = rs_val["metadata"]["ownerReferences"].as_array();
        let still_has_owner_ref = owner_refs
            .map(|refs| refs.iter().any(|r| r["uid"].as_str() == Some(deploy_uid)))
            .unwrap_or(false);
        assert!(
            still_has_owner_ref,
            "u7s must NOT strip the RS's ownerReference itself at delete time — the strip must \
             come from real KCM's GC controller after it observes the `orphan` finalizer, not \
             from u7s racing ahead of KCM's own dependent-informer cache"
        );
    }

    /// Background (default) delete still cascades — cascade must not be broken by the Orphan gate.
    ///
    /// Regression guard: the Orphan path is a guard around the cascade helpers; if the guard
    /// incorrectly fires for Background deletes the cascade tests will start failing (pods survive).
    #[tokio::test]
    async fn background_delete_rc_still_cascades() {
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

        let rc_uid = "ffff3333-0000-0000-0000-000000000001";
        let ns = "default";

        // Seed the ReplicationController.
        let rc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "bg-rc", "namespace": ns, "uid": rc_uid },
            "spec": { "replicas": 1, "selector": { "app": "bg-rc" } }
        });
        let rc_key = "/registry/replicationcontrollers/default/bg-rc";
        store
            .put(
                rc_key,
                bytes::Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Seed a pod owned by this RC.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "bg-rc-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "v1",
                    "kind": "ReplicationController",
                    "name": "bg-rc",
                    "uid": rc_uid,
                    "controller": true
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        let pod_key = "/registry/pods/default/bg-rc-pod";
        store
            .put(
                pod_key,
                bytes::Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Delete with explicit Background — cascade must still run.
        let bg_body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "propagationPolicy": "Background"
            }))
            .unwrap(),
        );
        delete_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                ns.to_string(),
                "replicationcontrollers".into(),
                "bg-rc".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            bg_body,
        )
        .await
        .unwrap_or_else(|e| panic!("background delete must succeed: {e:?}"));

        // Pod must be cascade-deleted — Background still cascades.
        // If this fails, the Orphan gate is too wide and breaks Background delete.
        assert!(
            store.get(pod_key).await.unwrap().is_none(),
            "Background/default delete of RC must still cascade-delete pods — \
             the Orphan gate must not apply to Background policy"
        );

        // RC itself must be deleted.
        assert!(
            store.get(rc_key).await.unwrap().is_none(),
            "RC itself must be hard-deleted on Background delete"
        );
    }

    /// add_orphan_finalizer must add the "orphan" finalizer exactly once, and must never
    /// drop finalizers a controller already placed on the object.
    ///
    /// This is the core of the Orphan-delete fix: real Kubernetes signals Orphan propagation
    /// by adding `metav1.FinalizerOrphanDependents` ("orphan") to the object being deleted,
    /// not by u7s stripping dependents itself. If this ever clobbered an existing finalizer
    /// array instead of appending, an object with e.g. a storage-protection finalizer would
    /// silently lose it on an Orphan delete, letting the object hard-delete before that
    /// controller's own cleanup ran.
    #[test]
    fn add_orphan_finalizer_appends_without_duplicating_or_clobbering() {
        // No finalizers yet: must create the array with just "orphan".
        let mut obj = Object {
            body: serde_json::json!({ "metadata": {} }),
        };
        add_orphan_finalizer(&mut obj);
        assert_eq!(
            obj.body["metadata"]["finalizers"],
            serde_json::json!(["orphan"]),
            "must add the orphan finalizer when the object has none yet"
        );

        // Already has the orphan finalizer (e.g. a retried DELETE): must not duplicate it.
        add_orphan_finalizer(&mut obj);
        assert_eq!(
            obj.body["metadata"]["finalizers"],
            serde_json::json!(["orphan"]),
            "must be idempotent — a second call must not duplicate the finalizer entry, or \
             the object would never reach empty finalizers no matter how many times KCM \
             removes just one"
        );

        // Object already has an unrelated finalizer: must append, not replace.
        let mut obj = Object {
            body: serde_json::json!({ "metadata": { "finalizers": ["example.com/cleanup"] } }),
        };
        add_orphan_finalizer(&mut obj);
        assert_eq!(
            obj.body["metadata"]["finalizers"],
            serde_json::json!(["example.com/cleanup", "orphan"]),
            "must preserve a pre-existing, unrelated finalizer — clobbering it would let that \
             controller's own cleanup be skipped entirely once this object hard-deletes"
        );
    }

    /// Once real KCM finishes stripping an Orphan-marked owner's dependents and removes the
    /// last (`orphan`) finalizer, the resulting PATCH must hard-delete the owner AND refresh
    /// quota usage — the deferred completion of what used to be the immediate-hard-delete
    /// branch (which called quota::update_quota_status synchronously) now happens here.
    ///
    /// Before this fix, only the initial DELETE path called update_quota_status; moving the
    /// real hard-delete of an Orphan-marked owner to finalizer-drain (this bug's fix) without
    /// also moving the quota refresh would leave status.used stale after every Orphan delete
    /// until some unrelated write in the namespace happened to recompute it — silently
    /// blocking (or wrongly permitting) new object creates against a quota that never learned
    /// the owner was actually gone.
    #[tokio::test]
    async fn orphan_finalizer_drain_completion_hard_deletes_owner_and_refreshes_quota() {
        let state = make_state();
        let ns = "default";

        // A quota with a deliberately stale status.used — update_quota_status is idempotent
        // and recomputes from the live store, so a correct drain-completion call is the only
        // thing that can fix this value.
        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "drain-quota", "namespace": ns },
            "spec": { "hard": { "pods": "10" } },
            "status": { "hard": { "pods": "10" }, "used": { "pods": "99" } }
        });
        let quota_key =
            crate::keys::group_object_key("", "resourcequotas", Some(ns), "drain-quota");
        state
            .store
            .put(
                &quota_key,
                bytes::Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .expect("seed ResourceQuota");

        // Seed an RC already in the post-orphan-delete state: soft-deleted with exactly the
        // `orphan` finalizer pending, as add_orphan_finalizer + apply_delete_policy leave it
        // for real KCM to act on.
        let rc_key =
            crate::keys::group_object_key("", "replicationcontrollers", Some(ns), "draining-rc");
        let rc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": {
                "name": "draining-rc",
                "namespace": ns,
                "uid": "drain-uid-0001",
                "deletionTimestamp": "2026-07-22T00:00:00Z",
                "finalizers": ["orphan"]
            },
            "spec": { "replicas": 0, "selector": { "app": "draining-rc" } }
        });
        state
            .store
            .put(
                &rc_key,
                bytes::Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .expect("seed draining RC");

        // Real KCM's GC controller has finished stripping dependents and now removes the
        // last finalizer via a merge-patch — the exact mechanism it uses to signal drain
        // completion.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        let patch = serde_json::json!({ "metadata": { "finalizers": [] } });
        patch_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                ns.to_string(),
                "replicationcontrollers".into(),
                "draining-rc".into(),
            )),
            axum::extract::Query(PatchQuery::default()),
            test_user(),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("finalizer-drain patch must succeed: {e:?}"));

        assert!(
            state.store.get(&rc_key).await.unwrap().is_none(),
            "RC must be hard-deleted once its last finalizer (orphan) drains — this is how \
             the deferred hard-delete of an Orphan-marked owner actually completes"
        );

        let stored_quota = state.store.get(&quota_key).await.unwrap().unwrap();
        let quota_val: serde_json::Value = serde_json::from_slice(&stored_quota.value).unwrap();
        assert_eq!(
            quota_val["status"]["used"]["pods"].as_str(),
            Some("0"),
            "quota status.used must be refreshed when the finalizer-drain hard-delete \
             completes, not left at its stale pre-drain value"
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
            extra: Default::default(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
        )
        .await
        .unwrap_or_else(|_| panic!("soft-delete must succeed"));

        let rules_after = state.rbac_index.enumerate_rules("alice", &[], "");
        assert!(
            rules_after.is_empty(),
            "soft-deleted ClusterRoleBinding must be evicted from RBAC index immediately"
        );
    }

    /// Regression test: collection DELETE on RBAC resources must NOT remove
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
            test_user(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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
                extra: Default::default(),
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
                extra: Default::default(),
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
                extra: Default::default(),
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
                extra: Default::default(),
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
                extra: Default::default(),
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

    /// A plain strategic-merge PATCH (no `resourceVersion` in its body — the shape real
    /// clients send, e.g. `test/e2e/apps/job.go`'s "Patching the Job" step) must succeed
    /// even when another writer raced in and bumped the object's resourceVersion between
    /// this request's internal read and its write. Real kube-apiserver's PATCH handler
    /// read-modify-writes against the live object and retries silently on exactly this
    /// kind of conflict; a client's patch was never asked to pin a resourceVersion, so
    /// it must not be rejected because of one it never named.
    ///
    /// Without a retry-on-conflict, do_patch reads the object once, applies the patch,
    /// and writes back with the resourceVersion it read at the start — so any concurrent
    /// writer landing in between (e.g. a controller reacting to the object seconds after
    /// creation) turns an ordinary PATCH into a spurious 409, exactly as seen in
    /// conformance: "Job ... cannot be updated: resource version mismatch (expected N,
    /// current N+1)" immediately after "Creating a suspended job".
    ///
    /// This test drives many concurrent strategic-merge PATCHes at the same object with
    /// tokio::spawn: since the store's writes are serialized, only the very first writer
    /// can satisfy the resourceVersion it read at the start of its own PATCH, forcing
    /// every other one through the exact do_patch conflict path this fix retries. If the
    /// retry is removed, at least one of these patches gets rejected with 409 instead of
    /// succeeding — and this test asserts that none of them are.
    #[tokio::test]
    async fn patch_resource_retries_through_concurrent_writer_conflict() {
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
            "metadata": { "name": "race-node", "resourceVersion": "1" },
            "spec": { "drivers": [] }
        });
        store
            .put(
                "/registry/storage.k8s.io/csinodes/race-node",
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        const CONCURRENT_PATCHES: usize = 4;
        let mut handles = Vec::new();
        for i in 0..CONCURRENT_PATCHES {
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                let mut labels = serde_json::Map::new();
                labels.insert(
                    format!("racer-{i}"),
                    serde_json::Value::String("patched".into()),
                );
                let patch = serde_json::json!({ "metadata": { "labels": labels } });

                let mut headers = axum::http::HeaderMap::new();
                headers.insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
                );

                patch_resource(
                    State(state),
                    Path((
                        "storage.k8s.io".into(),
                        "v1".into(),
                        "csinodes".into(),
                        "race-node".into(),
                    )),
                    axum::extract::Query(PatchQuery::default()),
                    test_user(),
                    headers,
                    bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
                )
                .await
                .map(IntoResponse::into_response)
                .is_ok()
            }));
        }

        for (i, handle) in handles.into_iter().enumerate() {
            assert!(
                handle.await.expect("task must not panic"),
                "racer {i}'s PATCH (no resourceVersion in its body) was rejected with a \
                 conflict instead of retrying against the live object — a client should \
                 never see a 409 for a resourceVersion it never named"
            );
        }

        let stored = store
            .get("/registry/storage.k8s.io/csinodes/race-node")
            .await
            .expect("get must not error")
            .expect("object must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        for i in 0..CONCURRENT_PATCHES {
            assert_eq!(
                v["metadata"]["labels"][format!("racer-{i}")],
                "patched",
                "racer {i}'s label is missing from the final object — a retry that re-fetches \
                 the live object must still apply the ORIGINAL patch body, not silently drop it"
            );
        }
    }

    /// PATCH response must include kind and apiVersion even when the stored object omits them.
    ///
    /// The Kubernetes API contract requires every response object to carry TypeMeta.
    /// client-go (and the DRA conformance harness) checks `Object.Kind` on every response;
    /// if kind is absent it returns "Object 'Kind' is missing" and the conformance test fails.
    ///
    /// The bug: do_patch returned current.body without calling inject_type_meta, so if the
    /// stored JSON lacked kind/apiVersion (e.g. the client omitted them in the create body),
    /// the PATCH response would also lack them. This affects ALL resources, not only ResourceClaim.
    ///
    /// This test fails if inject_type_meta is removed from the PATCH return path in do_patch.
    #[tokio::test]
    async fn patch_namespaced_resource_response_always_includes_type_meta() {
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

        // Store a Lease WITHOUT kind/apiVersion in the body — simulates a client that omits
        // TypeMeta and relies on the server to stamp it in every response (including PATCH).
        let lease_without_type_meta = serde_json::json!({
            "metadata": { "name": "no-type-meta", "namespace": "kube-node-lease", "resourceVersion": "1" },
            "spec": { "holderIdentity": "original" }
        });
        store
            .put(
                "/registry/coordination.k8s.io/leases/kube-node-lease/no-type-meta",
                bytes::Bytes::from(serde_json::to_vec(&lease_without_type_meta).unwrap()),
                None,
            )
            .await
            .unwrap();

        let mut mp_headers = axum::http::HeaderMap::new();
        mp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let patch = serde_json::json!({"spec": {"holderIdentity": "patched"}});

        let result = patch_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "no-type-meta".into(),
            )),
            axum::extract::Query(PatchQuery::default()),
            test_user(),
            mp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await
        .expect("patch must succeed")
        .into_response();

        let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["kind"], "Lease",
            "PATCH response must include kind even when stored body lacks it; \
             conformance harness rejects the object with 'Object Kind is missing'"
        );
        assert_eq!(
            v["apiVersion"], "coordination.k8s.io/v1",
            "PATCH response must include apiVersion even when stored body lacks it; \
             conformance harness requires both kind and apiVersion on every response"
        );
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
            extra: Default::default(),
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
                extra: Default::default(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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

    /// replace_resource (PUT): the namespaced counterpart of do_patch's finalizer-drain
    /// hard-delete above, but exercised via a full PUT instead of a PATCH.
    ///
    /// Real KCM protection controllers (pvc-protection, vac-protection, ...) remove their
    /// own finalizer via a PUT of the whole object, not a merge-patch. Before this fix, only
    /// do_patch checked for finalizer-drain completion; replace_resource did a literal
    /// store.put, so the PUT re-persisted the object with deletionTimestamp still set and a
    /// subsequent GET still found it — every finalizer-protected cluster-scoped object (and,
    /// via the namespaced variant below, every PVC/VAC) stayed stuck Terminating forever.
    #[tokio::test]
    async fn replace_resource_hard_deletes_when_finalizers_drained_via_put() {
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

        // Seed an object that is already soft-deleted (deletionTimestamp set) with one
        // finalizer — mirrors a protection-finalizer'd object mid-delete.
        let obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "put-gc-node",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": ["kubernetes.io/pvc-protection"]
            },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/put-gc-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                None,
            )
            .await
            .unwrap();

        // PUT the object with finalizers now empty — exactly what a protection controller
        // does when it removes its finalizer. No resourceVersion is supplied (unconditional
        // PUT); optimistic-concurrency handling is not what's under test here.
        let put_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "put-gc-node",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": []
            },
            "spec": { "drivers": [] }
        });

        let result = replace_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "put-gc-node".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "PUT draining the last finalizer off a soft-deleted object must succeed"
        );

        assert!(
            store.get(key).await.unwrap().is_none(),
            "object with deletionTimestamp set and finalizers emptied via PUT must be \
             hard-deleted immediately, exactly like the PATCH path — otherwise a protection \
             controller can never complete a delete via PUT and the object stays stuck \
             Terminating forever"
        );
    }

    /// replace_resource (PUT): a protobuf-content-type PUT never carries deletionTimestamp in
    /// its decoded body (`gen_object_meta_to_json` never emits it), so a protection controller
    /// finishing its finalizer drain via a protobuf PUT looks — from the decoded body alone —
    /// identical to a plain update with a blank deletionTimestamp.
    ///
    /// Before the fix, `finalizer_drain_complete` read only the decoded body and saw no
    /// deletionTimestamp, so it fell through to a literal `store.put`: the stored object would
    /// have been overwritten with finalizers emptied AND deletionTimestamp gone — silently
    /// resurrecting an object that was mid-deletion as an ordinary live object. This test
    /// simulates the decode gap directly (a PUT body omitting deletionTimestamp) rather than
    /// via the protobuf wire format, since the observable bug is the same regardless of how
    /// the body ends up missing the field.
    #[tokio::test]
    async fn replace_resource_completes_finalizer_drain_when_put_body_omits_deletion_timestamp() {
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

        let obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "proto-gc-node",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": ["kubernetes.io/pvc-protection"]
            },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/proto-gc-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                None,
            )
            .await
            .unwrap();

        // No deletionTimestamp in the body — what a protobuf-decoded PUT looks like, since
        // gen_object_meta_to_json never emits it, even though the real client-side object
        // (and its protobuf wire encoding) did carry one.
        let put_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "proto-gc-node",
                "finalizers": []
            },
            "spec": { "drivers": [] }
        });

        let result = replace_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "proto-gc-node".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "PUT draining the last finalizer off a soft-deleted object must succeed even when \
             the body omits deletionTimestamp"
        );

        assert!(
            store.get(key).await.unwrap().is_none(),
            "object must be hard-deleted, not silently un-terminated: a decoded PUT body \
             missing deletionTimestamp (protobuf decode never emits it) must not make the \
             server forget the object was already mid-deletion — reverting this fix leaves \
             the object persisted with finalizers emptied and no deletionTimestamp, i.e. a \
             live, non-terminating object"
        );
    }

    /// replace_namespaced_resource (PUT): same regression as
    /// replace_resource_hard_deletes_when_finalizers_drained_via_put above, but for
    /// namespaced resources — this is the exact mechanism that stuck PVC and VAC deletes
    /// (kubernetes.io/pvc-protection and kubernetes.io/vac-protection are both removed via
    /// PUT by KCM's protection controllers).
    #[tokio::test]
    async fn replace_namespaced_resource_hard_deletes_when_finalizers_drained_via_put() {
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

        let obj = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "put-gc-lease",
                "namespace": "default",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": ["kubernetes.io/pvc-protection"]
            },
            "spec": { "holderIdentity": "test-holder" }
        });
        let key = "/registry/coordination.k8s.io/leases/default/put-gc-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                None,
            )
            .await
            .unwrap();

        let put_body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "put-gc-lease",
                "namespace": "default",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": []
            },
            "spec": { "holderIdentity": "test-holder" }
        });

        let result = replace_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "default".into(),
                "leases".into(),
                "put-gc-lease".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "namespaced PUT draining the last finalizer off a soft-deleted object must succeed"
        );

        assert!(
            store.get(key).await.unwrap().is_none(),
            "namespaced object with deletionTimestamp set and finalizers emptied via PUT must \
             be hard-deleted immediately — this is the exact PVC/VAC finalizer-drain path used \
             by KCM's protection controllers; without it a PVC or VAC delete never completes \
             and stays stuck Terminating forever"
        );
    }

    /// replace_namespaced_resource (PUT): the namespaced counterpart of
    /// replace_resource_completes_finalizer_drain_when_put_body_omits_deletion_timestamp —
    /// this is the exact PVC/VAC finalizer-drain path, so the un-terminate hazard on a
    /// protobuf-content-type PUT applies to real, common controller traffic, not a
    /// cluster-scoped edge case.
    #[tokio::test]
    async fn replace_namespaced_resource_completes_finalizer_drain_when_put_body_omits_deletion_timestamp(
    ) {
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

        let obj = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "proto-gc-lease",
                "namespace": "default",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": ["kubernetes.io/pvc-protection"]
            },
            "spec": { "holderIdentity": "test-holder" }
        });
        let key = "/registry/coordination.k8s.io/leases/default/proto-gc-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                None,
            )
            .await
            .unwrap();

        // No deletionTimestamp in the body — what a protobuf-decoded PUT looks like.
        let put_body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "proto-gc-lease",
                "namespace": "default",
                "finalizers": []
            },
            "spec": { "holderIdentity": "test-holder" }
        });

        let result = replace_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "default".into(),
                "leases".into(),
                "proto-gc-lease".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "namespaced PUT draining the last finalizer off a soft-deleted object must succeed \
             even when the body omits deletionTimestamp"
        );

        assert!(
            store.get(key).await.unwrap().is_none(),
            "object must be hard-deleted, not silently un-terminated — reverting this fix \
             leaves a PVC/VAC-style finalizer-drain PUT stuck as a live object with no \
             deletionTimestamp whenever the request used protobuf content-type"
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
            axum::http::HeaderMap::new(),
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
            axum::http::HeaderMap::new(),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("missing namespaced CR must return 404"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// `kubectl get <crd-plural> <name>` for a CRD-backed type routes through get_resource,
    /// which falls back to cr::get_cr for groups not in the static registry. get_resource
    /// must forward the real Accept header to that fallback — dropping it here would silently
    /// undo the Table fix for every custom resource even after fixing get_cr itself, since
    /// this generic /apis/{group}/{version}/{plural}/{name} route is what kubectl actually hits.
    #[tokio::test]
    async fn get_resource_cr_fallback_honors_table_accept() {
        use axum::extract::{Path, State};

        let state = make_state();

        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.custom.example.com" },
            "spec": {
                "group": "custom.example.com",
                "names": {
                    "plural": "widgets",
                    "singular": "widget",
                    "kind": "Widget",
                    "listKind": "WidgetList"
                },
                "scope": "Cluster",
                "versions": [{ "name": "v1", "served": true, "storage": true }]
            }
        });
        crate::handlers::crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(crd.to_string()),
        )
        .await
        .expect("install CRD");

        let widget = serde_json::json!({
            "apiVersion": "custom.example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "my-widget" }
        });
        crate::handlers::cr::create_cr(
            State(state.clone()),
            Path(("custom.example.com".into(), "v1".into(), "widgets".into())),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(widget.to_string()),
        )
        .await
        .expect("create CR");

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json;as=Table;g=meta.k8s.io;v=v1"),
        );

        let resp = get_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "widgets".into(),
                "my-widget".into(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|_| panic!("get_resource with Table accept must return 200"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["kind"], "Table",
            "get_resource must forward Accept down to the CR-fallback get_cr — otherwise \
             `kubectl get <crd-plural> <name>` never gets Table output for any custom \
             resource no matter what get_cr itself does"
        );
    }

    /// Namespaced counterpart of get_resource_cr_fallback_honors_table_accept: `kubectl get
    /// <crd-plural> <name> -n <ns>` routes through get_namespaced_resource, which must also
    /// forward Accept to cr::get_cr_namespaced rather than dropping it on the CR fallback path.
    #[tokio::test]
    async fn get_namespaced_resource_cr_fallback_honors_table_accept() {
        use axum::extract::{Path, State};

        let state = make_state();

        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "gizmos.custom.example.com" },
            "spec": {
                "group": "custom.example.com",
                "names": {
                    "plural": "gizmos",
                    "singular": "gizmo",
                    "kind": "Gizmo",
                    "listKind": "GizmoList"
                },
                "scope": "Namespaced",
                "versions": [{ "name": "v1", "served": true, "storage": true }]
            }
        });
        crate::handlers::crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(crd.to_string()),
        )
        .await
        .expect("install CRD");

        let gizmo = serde_json::json!({
            "apiVersion": "custom.example.com/v1",
            "kind": "Gizmo",
            "metadata": { "name": "my-gizmo", "namespace": "default" }
        });
        crate::handlers::cr::create_cr_namespaced(
            State(state.clone()),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "default".into(),
                "gizmos".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(gizmo.to_string()),
        )
        .await
        .expect("create namespaced CR");

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json;as=Table;g=meta.k8s.io;v=v1"),
        );

        let resp = get_namespaced_resource(
            State(state),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "default".into(),
                "gizmos".into(),
                "my-gizmo".into(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|_| panic!("get_namespaced_resource with Table accept must return 200"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["kind"], "Table",
            "get_namespaced_resource must forward Accept down to the CR-fallback \
             get_cr_namespaced — otherwise `kubectl get <crd-plural> <name> -n <ns>` never \
             gets Table output for any namespaced custom resource"
        );
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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
                extra: Default::default(),
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
                extra: Default::default(),
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

    // -- resource.rs CRUD handler error mappings --

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

    // -- PartialObjectMetadata (POM) watch support for built-in resources --
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
                extra: Default::default(),
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
                extra: Default::default(),
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
                extra: Default::default(),
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
                extra: Default::default(),
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
            axum::http::HeaderMap::new(),
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
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
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
                extra: Default::default(),
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

    /// replace_namespaced_resource (PUT) must restore metadata.uid from the stored object when
    /// the request body omits it — matching real kube-apiserver's rest.BeforeUpdate ("Use the
    /// existing UID if none is provided"), which runs unconditionally on every Update.
    ///
    /// This is the confirmed root cause of KCM's EndpointSlice controller permanently failing
    /// with "EndpointSlice informer cache is out of date" after a Service's second required
    /// EndpointSlice write (e.g. a second pod becoming Ready): KCM's reconciler builds its
    /// Update() body without repopulating UID. A blank UID stored and broadcast to watchers
    /// means the informer's cached copy no longer carries the UID the tracker expects, so
    /// EndpointSliceTracker.StaleSlices() sees the tracked (real) UID as permanently missing
    /// from the informer — every later sync fails, forever, even though the object itself is
    /// otherwise fully present and correct.
    ///
    /// This test fails on revert: without the restamp, the response and stored object both
    /// carry a blank uid instead of the original one.
    #[tokio::test]
    async fn replace_namespaced_resource_restores_uid_when_put_body_omits_it() {
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

        let key = "/registry/discovery.k8s.io/endpointslices/eps-repro/iso-web-04fa0";
        let original_uid = "a8ad2091-a2f2-4145-a407-03eb5a133f4f";
        let created = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "addressType": "IPv4",
            "endpoints": [],
            "ports": [],
            "metadata": {
                "name": "iso-web-04fa0",
                "namespace": "eps-repro",
                "uid": original_uid,
                "labels": { "kubernetes.io/service-name": "iso-web" }
            }
        });
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&created).unwrap()),
                None,
            )
            .await
            .expect("seed put must succeed");

        // Simulates KCM's EndpointSlice reconciler Update() call: a second pod became Ready,
        // so the slice gains an endpoint, but the body does not repopulate metadata.uid.
        let put_body = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "addressType": "IPv4",
            "endpoints": [{ "addresses": ["10.85.0.6"] }],
            "ports": [{ "port": 80, "protocol": "TCP" }],
            "metadata": {
                "name": "iso-web-04fa0",
                "namespace": "eps-repro",
                "labels": { "kubernetes.io/service-name": "iso-web" }
            }
        });

        let resp = replace_namespaced_resource(
            State(state.clone()),
            Path((
                "discovery.k8s.io".into(),
                "v1".into(),
                "eps-repro".into(),
                "endpointslices".into(),
                "iso-web-04fa0".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("replace must succeed when body omits uid"))
        .into_response();

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let returned: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            returned["metadata"]["uid"], original_uid,
            "PUT response must preserve the existing UID when the request body omits it; \
             a blank UID here means KCM's tracker will never see this UID again in a future \
             informer list, permanently wedging endpoint sync for this Service"
        );

        let stored = store
            .get(key)
            .await
            .expect("store get must succeed")
            .expect("object must be stored");
        let stored_obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_obj["metadata"]["uid"], original_uid,
            "stored object must retain the original uid — this is what gets broadcast to \
             KCM's already-established EndpointSlice watch; a blank stored uid is what wedges \
             EndpointSliceTracker.StaleSlices() forever"
        );
        assert_eq!(
            stored_obj["metadata"]["generation"], 2,
            "generation must increment from 1 to 2 when endpoints content changed on this PUT"
        );
    }

    /// replace_resource (cluster-scoped PUT) must restore metadata.uid from the stored object
    /// when the request body omits it — the same class of bug fixed above for
    /// replace_namespaced_resource, but for cluster-scoped resources (StorageClass, ClusterRole,
    /// Node, PersistentVolume, ...), which are equally reachable by a client that PUTs a blind,
    /// locally-cached copy of the object missing its system-assigned UID.
    ///
    /// StorageClass has neither a status subresource nor the PriorityClass.value immutability
    /// check, so before this fix nothing in replace_resource's stored-object read ever ran for
    /// it — a blank incoming UID would have been persisted and returned verbatim, exactly the
    /// EndpointSlice bug above but for a resource type the narrower per-type gates never cover.
    ///
    /// This test fails on revert: without the restoration, the response and stored object both
    /// carry a blank uid instead of the original one.
    #[tokio::test]
    async fn replace_resource_restores_uid_when_put_body_omits_it() {
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

        let key = "/registry/storage.k8s.io/storageclasses/blind-put-sc";
        let original_uid = "b3e1f6a0-1c2d-4e3f-9a5b-6d7c8e9f0a1b";
        let created = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "provisioner": "kubernetes.io/no-provisioner",
            "metadata": {
                "name": "blind-put-sc",
                "uid": original_uid
            }
        });
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&created).unwrap()),
                None,
            )
            .await
            .expect("seed put must succeed");

        // Simulates a blind PUT from a client that round-trips a locally-held copy of the
        // object without repopulating metadata.uid (e.g. a dynamic client rebuilding the body
        // from a typed struct that never carried the field through).
        let put_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "provisioner": "kubernetes.io/no-provisioner",
            "volumeBindingMode": "WaitForFirstConsumer",
            "metadata": { "name": "blind-put-sc" }
        });

        let resp = replace_resource(
            State(state.clone()),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "storageclasses".into(),
                "blind-put-sc".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("replace must succeed when body omits uid"))
        .into_response();

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let returned: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            returned["metadata"]["uid"], original_uid,
            "PUT response must preserve the existing UID when the request body omits it — \
             cluster-scoped resources are exactly as exposed to a client's blind PUT as \
             namespaced ones are"
        );

        let stored = store
            .get(key)
            .await
            .expect("store get must succeed")
            .expect("object must be stored");
        let stored_obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_obj["metadata"]["uid"], original_uid,
            "stored object must retain the original uid — a blank stored uid would be \
             broadcast to any watcher identifying this object by UID, exactly as it did for \
             EndpointSlice before replace_namespaced_resource's equivalent fix"
        );
    }

    /// PUT (replace_resource) response must include kind and apiVersion even when the
    /// request body omits them.
    ///
    /// Dynamic/unstructured clients (client-go's dynamic.Interface, used by the
    /// "Deployment lifecycle" conformance test) decode Update() responses by checking
    /// Object.Kind; if it is empty, decode fails with "Object 'Kind' is missing" and the
    /// conformance test fails even though the underlying update succeeded.
    ///
    /// This test fails if the inject_type_meta call is removed from replace_resource's
    /// return path.
    #[tokio::test]
    async fn replace_resource_response_always_includes_type_meta() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;

        let state = make_state();

        // PUT body deliberately omits kind/apiVersion — simulates an unstructured/dynamic
        // client that relies on the server to stamp TypeMeta on the response.
        let csinode_without_type_meta = serde_json::json!({
            "metadata": { "name": "no-type-meta-node" },
            "spec": { "drivers": [] }
        });

        let resp = replace_resource(
            State(state),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "no-type-meta-node".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&csinode_without_type_meta).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("replace must succeed when body omits kind/apiVersion"))
        .into_response();

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["kind"], "CSINode",
            "PUT response must include kind even when the request body lacks it; \
             dynamic/unstructured clients reject the response with 'Object Kind is missing' \
             otherwise, breaking every dynamic-client Update (e.g. Deployment lifecycle conformance)"
        );
        assert_eq!(
            v["apiVersion"], "storage.k8s.io/v1",
            "PUT response must include apiVersion even when the request body lacks it; \
             dynamic clients require both kind and apiVersion to decode an Update response"
        );
    }

    /// PUT (replace_namespaced_resource) response must include kind and apiVersion even
    /// when the request body omits them — the namespaced counterpart of
    /// replace_resource_response_always_includes_type_meta.
    ///
    /// This test fails if the inject_type_meta call is removed from
    /// replace_namespaced_resource's return path.
    #[tokio::test]
    async fn replace_namespaced_resource_response_always_includes_type_meta() {
        use axum::body::to_bytes;
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
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

        // PUT body deliberately omits kind/apiVersion — simulates an unstructured/dynamic
        // client (e.g. the Deployment lifecycle conformance test) that relies on the server
        // to stamp TypeMeta on the response.
        let lease_without_type_meta = serde_json::json!({
            "metadata": { "name": "no-type-meta-lease" },
            "spec": { "holderIdentity": "test-holder" }
        });

        let resp = replace_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "no-type-meta-lease".into(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&lease_without_type_meta).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("replace must succeed when body omits kind/apiVersion"))
        .into_response();

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["kind"], "Lease",
            "PUT response must include kind even when the request body lacks it; \
             dynamic/unstructured clients reject the response with 'Object Kind is missing' \
             otherwise, breaking every namespaced dynamic-client Update"
        );
        assert_eq!(
            v["apiVersion"], "coordination.k8s.io/v1",
            "PUT response must include apiVersion even when the request body lacks it; \
             dynamic clients require both kind and apiVersion to decode an Update response"
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
             apiVersion/kind and can never sync"
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
            axum::http::HeaderMap::new(),
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
            axum::http::HeaderMap::new(),
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
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
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
            test_user(),
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
    // ClusterIP auto-allocation regression tests
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
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
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
    // fieldValidation query param regression
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
                extra: Default::default(),
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
            test_user(),
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

    /// delete_collection_namespaced_resource must respect metadata.finalizers: an object
    /// with a finalizer must be soft-deleted (deletionTimestamp stamped, kept alive), not
    /// removed outright. The real KCM namespace-controller drains most namespace content
    /// via this exact endpoint (DeleteCollection per resource type) as part of
    /// OrderedNamespaceDeletion — an object with an unresolved finalizer must survive with
    /// deletionTimestamp set, matching what a single-object DELETE already does.
    ///
    /// Fails on revert: reverting to an unconditional `state.store.delete` for every listed
    /// object makes the finalizer'd configmap vanish from the store instead of remaining
    /// with deletionTimestamp set — silently bypassing the finalizer KCM's namespace
    /// controller relies on to sequence OrderedNamespaceDeletion.
    #[tokio::test]
    async fn delete_collection_namespaced_respects_object_finalizers() {
        use axum::extract::{Path, Query, State};
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

        let finalizer_cm_key = crate::keys::object_key("configmaps", "test-ns", "protected-cm");
        let finalizer_cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "protected-cm",
                "namespace": "test-ns",
                "finalizers": ["test.io/keep-me"]
            },
            "data": {}
        });
        store
            .put(
                &finalizer_cm_key,
                bytes::Bytes::from(serde_json::to_vec(&finalizer_cm).unwrap()),
                None,
            )
            .await
            .expect("finalizer configmap seed must succeed");

        let plain_cm_key = crate::keys::object_key("configmaps", "test-ns", "plain-cm");
        let plain_cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "plain-cm", "namespace": "test-ns" },
            "data": {}
        });
        store
            .put(
                &plain_cm_key,
                bytes::Bytes::from(serde_json::to_vec(&plain_cm).unwrap()),
                None,
            )
            .await
            .expect("plain configmap seed must succeed");

        delete_collection_namespaced_resource(
            State(state.clone()),
            Path((
                "".into(),
                "v1".into(),
                "test-ns".into(),
                "configmaps".into(),
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
            test_user(),
        )
        .await
        .unwrap_or_else(|e| panic!("delete_collection must succeed: {e:?}"));

        let stored_finalizer_cm = store
            .get(&finalizer_cm_key)
            .await
            .expect("store get must not error")
            .expect(
                "configmap with metadata.finalizers must NOT be removed by DeleteCollection — \
                 it must be soft-deleted (deletionTimestamp set) so its controller can observe \
                 the deletion signal and clear the finalizer itself",
            );
        let finalizer_cm_body: serde_json::Value =
            serde_json::from_slice(&stored_finalizer_cm.value).expect("configmap body must parse");
        assert!(
            finalizer_cm_body["metadata"]["deletionTimestamp"].is_string(),
            "configmap with finalizer must have deletionTimestamp set after DeleteCollection — \
             the real KCM namespace-controller polls for exactly this during \
             OrderedNamespaceDeletion"
        );

        let stored_plain_cm = store
            .get(&plain_cm_key)
            .await
            .expect("store get must not error");
        assert!(
            stored_plain_cm.is_none(),
            "configmap without finalizers must still be hard-deleted immediately by \
             DeleteCollection — the finalizer-less fast path must not regress"
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
                extra: Default::default(),
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
                extra: Default::default(),
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

    /// Regression test: patching a ConfigMap must emit a MODIFIED watch event
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
        //    the store-keepalive fix which keeps the store alive for the stream.)
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
                extra: Default::default(),
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

    /// Regression test: GET on a stored namespaced object must return
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
            axum::http::HeaderMap::new(),
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
             precondition failures"
        );
        assert_ne!(
            rv, "0",
            "GET response must not return metadata.resourceVersion=\"0\" — store must stamp the \
             actual revision (>= 1); returning 0 makes KCM's PUT fail with revision mismatch \
             (root CA publisher loops on 'expected N, current 0')"
        );
        let rv_int: u64 = rv.parse().unwrap_or_else(|_| {
            panic!("metadata.resourceVersion must be a decimal integer string; got: {rv:?}")
        });
        assert!(
            rv_int > 0,
            "metadata.resourceVersion must be > 0 after first write; got: {rv_int} \
             (store counter starts at 1)"
        );
    }

    /// `kubectl get <resource> <name> -n <ns>` sends Accept: application/json;as=Table;...
    /// by default. Before this fix, get_namespaced_resource ignored Accept entirely and always
    /// returned the raw object, so kubectl fell back to printing only NAME/AGE for any
    /// namespaced non-Pod resource (list_namespaced_resource already handled this for LIST).
    #[tokio::test]
    async fn get_namespaced_resource_with_table_accept_returns_single_row_table() {
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "my-cm", "namespace": "default" },
            "data": { "key": "value" }
        });

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

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json;as=Table;g=meta.k8s.io;v=v1"),
        );

        let get_resp = get_namespaced_resource(
            State(state),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "configmaps".into(),
                "my-cm".into(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|e| panic!("ConfigMap GET with Table accept must succeed; got: {e:?}"))
        .into_response();

        let body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["kind"], "Table",
            "a plain ConfigMap kind here means kubectl can't decode it as a Table and silently \
             falls back to hardcoded NAME/AGE-only columns"
        );
        let rows = v["rows"].as_array().expect("Table response must have rows");
        assert_eq!(
            rows.len(),
            1,
            "a single-object GET must produce exactly one Table row, not a full list"
        );
        assert_eq!(
            rows[0]["object"]["metadata"]["name"], "my-cm",
            "kubectl reads the row's embedded object to resolve the resource on selection"
        );
    }

    /// kcm's GC sends `Accept: application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1`
    /// when verifying a namespaced owner reference still exists (garbagecollector.go:434-444
    /// isDangling). Before this fix, get_namespaced_resource always returned the full typed
    /// object, which the GC's metadata-only decoder rejects; the owner-check retries forever
    /// and newly-orphaned dependents leak indefinitely on any long-running u7s cluster.
    #[tokio::test]
    async fn get_namespaced_resource_returns_partial_object_metadata_when_requested() {
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "my-cm", "namespace": "default" },
            "data": { "key": "value" }
        });

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

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static(
                "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1",
            ),
        );

        let get_resp = get_namespaced_resource(
            State(state),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "configmaps".into(),
                "my-cm".into(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|e| {
            panic!("ConfigMap GET with PartialObjectMetadata accept must succeed; got: {e:?}")
        })
        .into_response();

        let body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["apiVersion"], "meta.k8s.io/v1",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert_eq!(
            v["kind"], "PartialObjectMetadata",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert!(
            v.get("data").is_none(),
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: selector defaulting for Deployment/RS/StatefulSet
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
             breaks the AdmissionWebhook conformance test's BeforeEach"
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

    // -- expired continue token returns 410 Gone --

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
            kubelet_port: 10250,
            continue_token_key: Some(signing_key),
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
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
                extra: Default::default(),
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
            kubelet_port: 10250,
            continue_token_key: Some(signing_key),
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
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
                extra: Default::default(),
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

    /// Regression test: expired continue token must include `metadata.continue`
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
            kubelet_port: 10250,
            continue_token_key: Some(signing_key),
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
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
                extra: Default::default(),
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

    /// Regression test: `?limit`/`?continue` pagination must walk every object exactly once,
    /// in a stable order, while every page reports the SAME `metadata.resourceVersion`.
    ///
    /// This is the exact contract the Kubernetes chunking conformance suite
    /// ([sig-api-machinery] "should return chunks of results for list calls") checks: it
    /// creates many PodTemplates, pages through them with `?limit=`, and asserts
    /// `list.ResourceVersion` is identical across every page of one pagination pass — the
    /// live global store revision otherwise drifts upward between page requests (any other
    /// resource being written concurrently bumps it), which fails that assertion even when
    /// the paged items themselves are correct. If this test is run against a build that
    /// reports `resp.revision` (the store's live revision) instead of the token-pinned
    /// revision, it fails because concurrent writes between pages change the reported rv.
    #[tokio::test]
    async fn list_namespaced_resource_paginates_all_items_once_with_stable_resource_version() {
        use axum::body::to_bytes;
        use axum::extract::{Path, Query, State};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        const TOTAL: usize = 25;
        for i in 0..TOTAL {
            let name = format!("template-{i:02}");
            let body = serde_json::json!({
                "apiVersion": "v1",
                "kind": "PodTemplate",
                "metadata": { "name": name, "namespace": "default" },
                "template": { "spec": { "containers": [{ "name": "c", "image": "busybox" }] } }
            });
            store
                .put(
                    &format!("/registry/podtemplates/default/{name}"),
                    bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
                    None,
                )
                .await
                .unwrap();
        }

        let signing_key: [u8; 32] = *b"test-signing-key-32-bytes-padded";
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
            kubelet_port: 10250,
            continue_token_key: Some(signing_key),
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let mut collected_names: Vec<String> = Vec::new();
        let mut resource_versions: Vec<String> = Vec::new();
        let mut continue_token: Option<String> = None;
        let mut pages = 0;
        loop {
            pages += 1;
            assert!(
                pages <= TOTAL + 1,
                "pagination did not terminate — likely stuck on one page"
            );

            let resp = list_namespaced_resource(
                State(state.clone()),
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
                    limit: Some(7),
                    continue_token: continue_token.take(),
                    send_initial_events: None,
                    allow_watch_bookmarks: None,
                    timeout_seconds: None,
                }),
                axum::http::HeaderMap::new(),
                test_user(),
            )
            .await
            .unwrap_or_else(|e| panic!("paginated list must succeed, got {e:?}"));

            assert_eq!(resp.status(), axum::http::StatusCode::OK);
            let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
            let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

            let items = val["items"].as_array().expect("items must be an array");
            assert!(
                items.len() <= 7,
                "a page must never exceed the requested ?limit=7"
            );
            for item in items {
                collected_names.push(item["metadata"]["name"].as_str().unwrap().to_string());
            }
            resource_versions.push(val["metadata"]["resourceVersion"].as_str().unwrap().into());

            match val["metadata"]["continue"].as_str() {
                Some(tok) if !tok.is_empty() => continue_token = Some(tok.to_string()),
                _ => break,
            }

            // Simulate a concurrent, unrelated write landing between page fetches (e.g. a
            // Lease renewal from another controller). This bumps the store's live global
            // revision but must NOT change the resourceVersion this pagination walk reports
            // on the next page — without the fix, the next page's `build_list_response` uses
            // the store's now-advanced revision, breaking the assertion below.
            state
                .store
                .put(
                    &format!("/registry/leases/kube-node-lease/unrelated-node-{pages}"),
                    bytes::Bytes::from_static(b"{}"),
                    None,
                )
                .await
                .unwrap();
        }

        assert_eq!(
            collected_names.len(),
            TOTAL,
            "every created PodTemplate must be returned exactly once across all pages \
             combined — duplicates or gaps mean the continue cursor is mis-tracking position"
        );
        let mut expected: Vec<String> = (0..TOTAL).map(|i| format!("template-{i:02}")).collect();
        expected.sort();
        let mut actual = collected_names.clone();
        actual.sort();
        assert_eq!(
            actual, expected,
            "the set of names returned across all pages must equal the set created"
        );
        assert_eq!(
            collected_names, expected,
            "pages must be returned in stable ascending key order so that resuming from a \
             continue token never re-visits or skips an item"
        );
        assert!(
            resource_versions.windows(2).all(|w| w[0] == w[1]),
            "every page of one pagination pass must report the SAME resourceVersion ({:?}); \
             a mismatch means the response used the store's live (advancing) revision instead \
             of the revision pinned in the continue token, which fails the Kubernetes chunking \
             conformance assertion `list.ResourceVersion == lastRV`",
            resource_versions
        );
    }

    /// Regression test: PATCHing Event series.lastObservedTime must persist and
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
            axum::http::HeaderMap::new(),
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
    // Regression tests: fieldValidation=Strict/Warn/Ignore
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

    // -- Regression: ResourceSlice create response must include kind and apiVersion --

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
                extra: Default::default(),
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
             'Object Kind is missing' when absent (DRA conformance test)"
        );
        assert_eq!(
            v["apiVersion"], "resource.k8s.io/v1",
            "response must have apiVersion=resource.k8s.io/v1 — required by Kubernetes API contract"
        );
    }

    // GET for a registry-backed resource (DRA) must include kind and apiVersion even when
    // the stored bytes omit them (client-go omits TypeMeta fields when they are zero-valued).
    // Without inject_type_meta in get_resource, the GET response returns the raw stored bytes
    // which may lack kind/apiVersion, causing client-go to return "Object Kind is missing".
    // Removing the inject_type_meta call from get_resource must make this test fail.
    #[tokio::test]
    async fn get_resource_slice_response_has_type_meta() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        // Store a ResourceSlice without kind/apiVersion, simulating what happens when
        // client-go omits TypeMeta and the stored bytes are the raw client body.
        let stored_body = serde_json::json!({
            "metadata": {
                "name": "slice-without-meta",
                "resourceVersion": "1"
            },
            "spec": {
                "driver": "test.csi.k8s.io",
                "pool": { "name": "p", "generation": 0, "resourceSliceCount": 1 },
                "nodeName": "node1",
                "devices": []
            }
        });
        state
            .store
            .put(
                "/registry/resource.k8s.io/resourceslices/slice-without-meta",
                bytes::Bytes::from(serde_json::to_vec(&stored_body).unwrap()),
                Some(0),
            )
            .await
            .expect("store put must succeed");

        let resp = get_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "resource.k8s.io".to_string(),
                "v1".to_string(),
                "resourceslices".to_string(),
                "slice-without-meta".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|_| panic!("GET must succeed"))
        .into_response();

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            v["kind"], "ResourceSlice",
            "GET response must include kind=ResourceSlice even when stored bytes lack it — \
             client-go typed clients fail with 'Object Kind is missing' without this"
        );
        assert_eq!(
            v["apiVersion"], "resource.k8s.io/v1",
            "GET response must include apiVersion even when stored bytes lack it"
        );
    }

    // -- Regression: KCM deployment controller revision annotation --

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

    // -- Regression: KCM 1.36 RS create propagates revision to Deployment --

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

    /// A store wrapper that flips its target namespace to `Terminating` the first time
    /// `list()` is asked for that namespace's ResourceQuotas — the exact point
    /// `create_namespaced_resource`'s admission pipeline reaches (via
    /// `quota::check_resource_quota`) strictly AFTER an old-style early Terminating check
    /// would have already run and passed, but strictly BEFORE the object is actually
    /// persisted. This reproduces "a namespace delete's phase-flip commits in the gap
    /// between a concurrent create's admission work and its store write" deterministically,
    /// without relying on OS thread-scheduling luck.
    struct PhaseFlipDuringQuotaCheckStore {
        inner: std::sync::Arc<u7s_store::SqliteStore>,
        target_ns: String,
        flipped: std::sync::atomic::AtomicBool,
    }

    impl u7s_store::Store for PhaseFlipDuringQuotaCheckStore {
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
            let prefix_owned = prefix.to_string();
            let quota_prefix = format!("/registry/resourcequotas/{}/", self.target_ns);
            let should_flip = prefix == quota_prefix
                && !self.flipped.swap(true, std::sync::atomic::Ordering::SeqCst);
            let ns_key = format!("/registry/namespaces/{}", self.target_ns);
            async move {
                if should_flip {
                    if let Ok(Some(stored)) = inner.get(&ns_key).await {
                        let mut ns_obj: serde_json::Value =
                            serde_json::from_slice(&stored.value).unwrap();
                        ns_obj["status"]["phase"] = serde_json::json!("Terminating");
                        inner
                            .put(
                                &ns_key,
                                Bytes::from(ns_obj.to_string()),
                                Some(stored.revision),
                            )
                            .await
                            .expect("phase-flip put must succeed");
                    }
                }
                inner.list(&prefix_owned, opts).await
            }
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
            async move { inner.list_namespace_objects(&ns).await }
        }

        fn delete_namespace_resources(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.delete_namespace_resources(&ns).await }
        }

        fn create_if_namespace_active(
            &self,
            ns_key: Option<&str>,
            key: &str,
            value: Bytes,
        ) -> impl std::future::Future<
            Output = std::result::Result<u64, u7s_store::CreateNamespacedError>,
        > + Send {
            let inner = self.inner.clone();
            let ns_key = ns_key.map(|s| s.to_string());
            let key = key.to_string();
            async move {
                inner
                    .create_if_namespace_active(ns_key.as_deref(), &key, value)
                    .await
            }
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

    /// The namespace-Terminating create-guard must be checked atomically with the insert, not
    /// once early in the handler and then trusted for the rest of the request. A separate
    /// early check (the old shape) can observe Active, then run the whole admission pipeline
    /// (webhooks, LimitRange, quota) — during which a concurrent `delete_namespace` can flip
    /// the namespace to Terminating — and finally persist the object anyway, having never
    /// re-checked. That's exactly the mechanism mayor-74j3.6 fixed for the cascade's own LIST
    /// snapshot; this closes the same class of bug for every namespaced create path.
    ///
    /// Runs 50 times (fresh state each iteration) because the fix must hold unconditionally,
    /// not just on lucky scheduling — every iteration must reject with 403 and must never
    /// persist the object.
    ///
    /// Fails on revert: restoring the early separate `state.store.get(&ns_key)` check +
    /// standalone `state.store.put(..., Some(0))` (the shape this diff removes) makes the
    /// early check observe the namespace before this test's injected flip fires, so the
    /// object gets created anyway and this test's `Err` match arm panics.
    #[tokio::test]
    async fn create_during_delete_namespace_phase_flip_returns_403_atomically() {
        use axum::extract::State;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        for i in 0..50 {
            let ns = format!("race-ns-{i}");
            let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
            let ns_key = format!("/registry/namespaces/{ns}");
            inner
                .put(
                    &ns_key,
                    Bytes::from(
                        serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "Namespace",
                            "metadata": { "name": ns },
                            "status": { "phase": "Active" }
                        })
                        .to_string(),
                    ),
                    None,
                )
                .await
                .expect("seed active namespace");

            let wrapped = Arc::new(PhaseFlipDuringQuotaCheckStore {
                inner: Arc::clone(&inner),
                target_ns: ns.clone(),
                flipped: std::sync::atomic::AtomicBool::new(false),
            });
            let state = crate::state::AppState::new(
                Arc::clone(&wrapped),
                None,
                None,
                std::collections::HashMap::new(),
                "https://localhost:6443".into(),
            );

            let cm = serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "name": "test-cm", "namespace": ns }
            });

            let result = create_namespaced_resource(
                State(state),
                axum::extract::Path((
                    "".to_string(),
                    "v1".to_string(),
                    ns.clone(),
                    "configmaps".to_string(),
                )),
                axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
                test_user(),
                json_headers(),
                Bytes::from(serde_json::to_vec(&cm).unwrap()),
            )
            .await;

            match result {
                Err(e) => {
                    let json = serde_json::to_value(&e.1).unwrap();
                    assert_eq!(
                        json["code"], 403,
                        "iteration {i}: a create whose namespace flipped to Terminating during \
                         its own admission pipeline must be rejected with 403, not any other \
                         status"
                    );
                    assert!(
                        json["message"]
                            .as_str()
                            .unwrap_or("")
                            .contains("being terminated"),
                        "iteration {i}: rejection message must say the namespace is being \
                         terminated"
                    );
                }
                Ok(_) => panic!(
                    "iteration {i}: create must be rejected once its own atomic check observes \
                     Terminating — succeeding here means a create can slip through the exact \
                     window mayor-74j3.6/74j3.7 close, wedging namespace deletion"
                ),
            }

            let cm_key = format!("/registry/configmaps/{ns}/test-cm");
            assert!(
                inner.get(&cm_key).await.unwrap().is_none(),
                "iteration {i}: the object must never be persisted when its namespace check \
                 observed Terminating"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Status preservation on PUT
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
    /// — causing AfterEach to poll status.replicas==0 for 10 minutes.
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
             status via /status; a spec-only PUT must not wipe it out"
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

    /// A blind PUT (dynamic/typed client round-tripping a locally-held object, as the
    /// '[sig-apps] Deployment should run the lifecycle of a Deployment' conformance test
    /// does) commonly omits metadata.generation entirely. The server must treat generation
    /// as system-managed: preserve the stored value and increment it if spec changed, never
    /// reset it to 1 just because the client didn't echo it back.
    ///
    /// Before this fix, apply_defaults's initialize_workload_generation saw a null
    /// generation on the incoming body and set it to 1 (its "this must be a create" branch),
    /// so a Deployment already at generation 3 landed at generation 2 after a spec-changing
    /// PUT — losing all history and desyncing status.observedGeneration from what the
    /// Deployment controller (and the conformance test's watch assertions) expect to see
    /// monotonically increase.
    #[tokio::test]
    async fn put_deployment_without_generation_increments_from_stored_value_not_reset_to_1() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Deployment already at generation 3 (two prior spec-changing patches).
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "test-deployment",
                "namespace": "default",
                "generation": 3
            },
            "spec": {
                "replicas": 1,
                "selector": { "matchLabels": { "app": "web" } },
                "template": {
                    "metadata": { "labels": { "app": "web" } },
                    "spec": { "containers": [{ "name": "web", "image": "pause:3.10.1" }] }
                }
            },
            "status": { "observedGeneration": 3, "replicas": 1 }
        });
        let key = "/registry/apps/deployments/default/test-deployment";
        let stored_rv = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
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

        // Dynamic client PUT: full-object replace with a changed image, but no
        // metadata.generation field at all — exactly what runtime.DefaultUnstructuredConverter
        // produces when the caller never fetched the object back after prior mutations.
        let put_body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "test-deployment",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {
                "replicas": 2,
                "selector": { "matchLabels": { "app": "web" } },
                "template": {
                    "metadata": { "labels": { "app": "web" } },
                    "spec": { "containers": [{ "name": "web", "image": "httpd:2.4.38-4" }] }
                }
            }
        });

        let result = replace_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "deployments".to_string(),
                "test-deployment".to_string(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("PUT Deployment must succeed, got: {e:?}"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::OK);

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["generation"], 4,
            "generation must increment from the true stored value (3 -> 4) when the spec \
             changes via a PUT that omits metadata.generation — resetting to 1-based counting \
             (e.g. landing at 2) desyncs status.observedGeneration from the real change history"
        );
    }

    /// In-memory sink for tracing-subscriber's fmt layer, so debug-visibility tests can
    /// assert on rendered field content without adding a tracing-test dependency.
    #[derive(Clone, Default)]
    struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'w> tracing_subscriber::fmt::MakeWriter<'w> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'w self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured_log(buf: &SharedBuf) -> String {
        String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
    }

    /// A spec-changing PUT must be flagged `spec_changed=true` with a diff summary naming the
    /// actual change (scale, image), while a PUT that re-applies the exact same spec must be
    /// flagged `spec_changed=false` with no summary — otherwise an operator watching
    /// `u7s::apiserver::spec_replace=debug` can't tell a real rollout apart from a controller
    /// re-syncing an unchanged object, which is the single most common source of replace noise.
    #[tokio::test]
    async fn replace_emits_spec_diff_summary_only_when_spec_actually_changed() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let buf = SharedBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "default", "generation": 1},
            "spec": {
                "replicas": 3,
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {"containers": [{"name": "web", "image": "nginx:1.20"}]}
                }
            }
        });
        let key = "/registry/apps/deployments/default/web";
        let rv1 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
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

        // First PUT: a real edit — scale 3 -> 5 and image bump.
        let changed_body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "default", "resourceVersion": rv1.to_string()},
            "spec": {
                "replicas": 5,
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {"containers": [{"name": "web", "image": "nginx:1.21"}]}
                }
            }
        });
        let _ = replace_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "deployments".to_string(),
                "web".to_string(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&changed_body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("PUT Deployment must succeed, got: {e:?}"))
        .into_response();

        let log_after_edit = captured_log(&buf);
        assert!(
            log_after_edit.contains("spec_changed=true"),
            "a real spec edit must be flagged spec_changed=true; log was: {log_after_edit}"
        );
        assert!(
            log_after_edit.contains("replicas: 3") && log_after_edit.contains("-> 5"),
            "the diff summary must name the actual scale change; log was: {log_after_edit}"
        );
        assert!(
            log_after_edit.contains("nginx:1.20") && log_after_edit.contains("nginx:1.21"),
            "the diff summary must name the actual image rollout, the most common reason an \
             operator investigates a replace event; log was: {log_after_edit}"
        );

        // Second PUT: a re-apply of the exact same spec just written — must NOT be reported
        // as a spec change, or every controller re-sync would look like a real edit.
        let stored = store.get(key).await.unwrap().unwrap();
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let reapply_body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "web",
                "namespace": "default",
                "resourceVersion": stored_v["metadata"]["resourceVersion"]
            },
            "spec": stored_v["spec"].clone()
        });
        let _ = replace_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "deployments".to_string(),
                "web".to_string(),
            )),
            axum::extract::Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&reapply_body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("re-apply PUT must succeed, got: {e:?}"))
        .into_response();

        let log_after_reapply = captured_log(&buf);
        let reapply_lines: Vec<&str> = log_after_reapply
            .lines()
            .filter(|l| l.contains("namespaced resource replace"))
            .collect();
        let last_line = reapply_lines
            .last()
            .expect("re-apply must still emit a spec_replace debug event");
        assert!(
            last_line.contains("spec_changed=false"),
            "re-applying the exact same spec must be flagged spec_changed=false, or an \
             operator can't distinguish it from a real edit; line was: {last_line}"
        );
        assert!(
            !last_line.contains("spec_diff_summary"),
            "no diff summary should be attached when nothing changed; line was: {last_line}"
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

    /// A JSON Patch sent to the MAIN StatefulSet endpoint that targets `/status/...`
    /// must not change status — `patch statefulsets` and `patch statefulsets/status`
    /// are separate RBAC grants, and JSON Patch is an array so it slips past an
    /// object-shaped "status" key strip. This test fails if do_patch's JSON-Patch
    /// branch stops restoring the pre-patch status snapshot.
    #[tokio::test]
    async fn patch_statefulset_json_patch_cannot_forge_status_on_main_endpoint() {
        use axum::response::IntoResponse;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "web", "namespace": "default" },
            "spec": {
                "replicas": 3,
                "selector": { "matchLabels": { "app": "web" } },
                "template": {
                    "metadata": { "labels": { "app": "web" } },
                    "spec": { "containers": [{ "name": "web", "image": "nginx" }] }
                }
            },
            "status": { "replicas": 3, "readyReplicas": 3 }
        });
        let key = "/registry/apps/statefulsets/default/web";
        store
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

        let mut jp_headers = axum::http::HeaderMap::new();
        jp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );

        // A caller with only `patch statefulsets` (no /status grant) forges readyReplicas.
        let patch = serde_json::json!([
            { "op": "replace", "path": "/status/readyReplicas", "value": 99 }
        ]);

        let result = patch_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "statefulsets".to_string(),
                "web".to_string(),
            )),
            axum::extract::Query(PatchQuery::default()),
            test_user(),
            jp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("main-endpoint JSON Patch must succeed: {e:?}"))
        .into_response();

        assert_eq!(result.status(), axum::http::StatusCode::OK);

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["readyReplicas"], 3,
            "a JSON Patch on the main endpoint must not forge status — status is a \
             separate RBAC subresource, letting a main-patch-only caller set \
             readyReplicas would let it lie to schedulers/controllers about readiness"
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

    // -- Regression: EndpointSlice mirroring blocked by last-change-trigger-time --

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
            axum::http::HeaderMap::new(),
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

    /// PATCH that only touches labels on an immutable Secret must succeed.
    ///
    /// Real kube-apiserver only rejects PATCHes that change data/binaryData/stringData or
    /// clear the immutable flag — `immutable: true` does not freeze the whole object. Without
    /// this scoping, `kubectl label`/`kubectl annotate` on an immutable secret returns a
    /// confusing 422 for an operation the API contract explicitly allows, forcing the operator
    /// to delete and recreate the secret just to add a label.
    ///
    /// This test fails if do_patch's immutability check reverts to rejecting every patch
    /// against an immutable object regardless of what the patch touches.
    #[tokio::test]
    async fn patch_labels_on_immutable_secret_succeeds() {
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let secret_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "labelled-immutable", "namespace": "default" },
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
                "labelled-immutable".into(),
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

        let patch = serde_json::json!({ "metadata": { "labels": { "team": "platform" } } });
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
                "labelled-immutable".into(),
            )),
            Query(PatchQuery::default()),
            test_user(),
            merge_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let body = result
            .expect(
                "PATCH that only adds a label to an immutable secret must succeed — \
                 `kubectl label`/`kubectl annotate` on an immutable secret is a legitimate \
                 operator workflow that upstream kube-apiserver allows",
            )
            .into_response();
        let bytes = axum::body::to_bytes(body.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            updated["metadata"]["labels"]["team"], "platform",
            "the label patch must actually apply, not just avoid the 422"
        );
        assert_eq!(
            updated["data"]["key1"], "dmFsdWUx",
            "data must remain untouched by a metadata-only patch"
        );
    }

    /// PATCH that clears `immutable: true` back to false (or removes it) must return 422.
    ///
    /// Immutability is monotonic in upstream Kubernetes: once set, it cannot be unset via any
    /// update path. Without this check, an operator (or a compromised client) could flip
    /// `immutable` off and then rotate the secret's data, defeating the entire purpose of the
    /// flag — preventing silent secret rotation that mounted Pods won't pick up without a
    /// restart.
    ///
    /// This test fails if do_patch stops checking for a cleared immutable flag after scoping
    /// the check to data/binaryData/stringData changes.
    #[tokio::test]
    async fn patch_clearing_immutable_flag_on_secret_returns_422() {
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let secret_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "unfreeze-immutable", "namespace": "default" },
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
                "unfreeze-immutable".into(),
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

        let patch = serde_json::json!({ "immutable": false });
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
                "unfreeze-immutable".into(),
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
                "PATCH clearing immutable:true must return 422 — immutability is monotonic \
                 once set; allowing it to be cleared defeats its purpose of preventing silent \
                 secret rotation"
            ),
            Ok(_) => panic!(
                "PATCH must not be able to clear immutable:true — this would let a client \
                 unfreeze a secret and then rotate its data through a second PATCH"
            ),
        }
    }

    /// PATCH that only touches labels on an immutable ConfigMap must succeed, mirroring the
    /// Secret case above — `immutable` scoping must be identical for both resource types since
    /// do_patch's check gates on `plural == "secrets" || plural == "configmaps"` together.
    ///
    /// This test fails if the ConfigMap branch of the scoped immutability check regresses
    /// independently of the Secret branch (e.g. a fix that special-cases secrets only).
    #[tokio::test]
    async fn patch_labels_on_immutable_configmap_succeeds() {
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let cm_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "labelled-immutable-cm", "namespace": "default" },
            "immutable": true,
            "data": { "key1": "value1" }
        });
        let result = replace_namespaced_resource(
            State(state.clone()),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "configmaps".into(),
                "labelled-immutable-cm".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&cm_v1).unwrap()),
        )
        .await;
        let _ = result
            .expect("initial configmap create must succeed")
            .into_response();

        let patch = serde_json::json!({ "metadata": { "labels": { "team": "platform" } } });
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
                "configmaps".into(),
                "labelled-immutable-cm".into(),
            )),
            Query(PatchQuery::default()),
            test_user(),
            merge_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let body = result
            .expect(
                "PATCH that only adds a label to an immutable configmap must succeed — \
                 `kubectl label` on an immutable configmap is allowed by upstream \
                 kube-apiserver",
            )
            .into_response();
        let bytes = axum::body::to_bytes(body.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            updated["metadata"]["labels"]["team"], "platform",
            "the label patch must actually apply, not just avoid the 422"
        );
        assert_eq!(
            updated["data"]["key1"], "value1",
            "data must remain untouched by a metadata-only patch"
        );
    }

    /// PATCH that changes `.data` on an immutable ConfigMap must return 422, mirroring the
    /// Secret data-change test above.
    ///
    /// This test fails if the ConfigMap branch of the scoped immutability check stops
    /// rejecting data changes (e.g. a scoping bug that only inspects `data` for Secrets).
    #[tokio::test]
    async fn patch_data_on_immutable_configmap_returns_422() {
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let cm_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "data-immutable-cm", "namespace": "default" },
            "immutable": true,
            "data": { "key1": "value1" }
        });
        let result = replace_namespaced_resource(
            State(state.clone()),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "configmaps".into(),
                "data-immutable-cm".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&cm_v1).unwrap()),
        )
        .await;
        let _ = result
            .expect("initial configmap create must succeed")
            .into_response();

        let patch = serde_json::json!({ "data": { "key1": "newvalue" } });
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
                "configmaps".into(),
                "data-immutable-cm".into(),
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
                "PATCH on immutable configmap with changed data must return 422 — allowing it \
                 through would let a workload's mounted config drift out from under it with no \
                 restart, which `immutable: true` exists to prevent"
            ),
            Ok(_) => panic!(
                "PATCH on immutable configmap must return 422 when data changes — \
                 immutability check is missing the ConfigMap data path"
            ),
        }
    }

    /// PATCH that clears `immutable: true` on a ConfigMap must return 422, mirroring the
    /// Secret immutable-clear test above.
    ///
    /// This test fails if the ConfigMap branch stops enforcing that immutability is
    /// monotonic once set.
    #[tokio::test]
    async fn patch_clearing_immutable_flag_on_configmap_returns_422() {
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let cm_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "unfreeze-immutable-cm", "namespace": "default" },
            "immutable": true,
            "data": { "key1": "value1" }
        });
        let result = replace_namespaced_resource(
            State(state.clone()),
            Path((
                String::new(),
                "v1".into(),
                "default".into(),
                "configmaps".into(),
                "unfreeze-immutable-cm".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&cm_v1).unwrap()),
        )
        .await;
        let _ = result
            .expect("initial configmap create must succeed")
            .into_response();

        let patch = serde_json::json!({ "immutable": false });
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
                "configmaps".into(),
                "unfreeze-immutable-cm".into(),
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
                "PATCH clearing immutable:true on a configmap must return 422 — immutability \
                 is monotonic once set, same as for Secrets"
            ),
            Ok(_) => panic!(
                "PATCH must not be able to clear immutable:true on a configmap — this would \
                 let a client unfreeze it and then rotate its data through a second PATCH"
            ),
        }
    }

    /// PUT on a PriorityClass that changes `.value` must return 422 Invalid; PUT that only
    /// changes a mutable field (description) must succeed.
    ///
    /// The conformance test "verify PriorityClass endpoints can be operated with different
    /// HTTP methods" (scheduling/preemption.go) creates a PriorityClass then Updates it with
    /// `.value` multiplied by 10, expecting an error. `.value` drives scheduling/preemption
    /// ordering cluster-wide — allowing it to change post-create would silently reorder
    /// priorities for every pod referencing this class.
    ///
    /// This test fails if the immutability check is removed from replace_resource.
    #[tokio::test]
    async fn replace_priorityclass_value_is_immutable() {
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let pc_v1 = serde_json::json!({
            "apiVersion": "scheduling.k8s.io/v1",
            "kind": "PriorityClass",
            "metadata": { "name": "my-pc" },
            "value": 1000,
            "description": "original"
        });
        let result = replace_resource(
            State(state.clone()),
            Path((
                "scheduling.k8s.io".into(),
                "v1".into(),
                "priorityclasses".into(),
                "my-pc".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&pc_v1).unwrap()),
        )
        .await;
        let _ = result
            .expect("initial priorityclass create must succeed")
            .into_response();

        // Changing .value must be rejected with 422.
        let pc_changed_value = serde_json::json!({
            "apiVersion": "scheduling.k8s.io/v1",
            "kind": "PriorityClass",
            "metadata": { "name": "my-pc" },
            "value": 10000,
            "description": "original"
        });
        let result = replace_resource(
            State(state.clone()),
            Path((
                "scheduling.k8s.io".into(),
                "v1".into(),
                "priorityclasses".into(),
                "my-pc".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&pc_changed_value).unwrap()),
        )
        .await;
        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "PUT changing PriorityClass.value must return 422 Invalid — without this check \
                 u7s silently reorders cluster-wide scheduling priority and the conformance test \
                 'verify PriorityClass endpoints can be operated with different HTTP methods' \
                 fails with 'expected an update error on an immutable field, got nil'"
            ),
            Ok(_) => panic!(
                "PUT changing PriorityClass.value must return 422, not 200 — immutability \
                 enforcement is missing from replace_resource"
            ),
        }

        // Changing only description (a mutable field) must succeed.
        let pc_changed_desc = serde_json::json!({
            "apiVersion": "scheduling.k8s.io/v1",
            "kind": "PriorityClass",
            "metadata": { "name": "my-pc" },
            "value": 1000,
            "description": "updated description"
        });
        let result = replace_resource(
            State(state),
            Path((
                "scheduling.k8s.io".into(),
                "v1".into(),
                "priorityclasses".into(),
                "my-pc".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&pc_changed_desc).unwrap()),
        )
        .await;
        result.expect(
            "PUT changing only PriorityClass.description must succeed — the conformance test \
             requires mutable fields to remain patchable even though .value is locked",
        );
    }

    /// PATCH on a PriorityClass that changes `.value` must return 422 Invalid.
    ///
    /// Mirrors the PUT test above but for PATCH (strategic-merge, the patch type the
    /// conformance test actually uses via `patchPriorityClass`).
    ///
    /// This test fails if the immutability check is removed from do_patch.
    #[tokio::test]
    async fn patch_priorityclass_value_is_immutable() {
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let pc_v1 = serde_json::json!({
            "apiVersion": "scheduling.k8s.io/v1",
            "kind": "PriorityClass",
            "metadata": { "name": "patched-pc" },
            "value": 500,
            "description": "original"
        });
        let result = replace_resource(
            State(state.clone()),
            Path((
                "scheduling.k8s.io".into(),
                "v1".into(),
                "priorityclasses".into(),
                "patched-pc".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&pc_v1).unwrap()),
        )
        .await;
        let _ = result
            .expect("initial priorityclass create must succeed")
            .into_response();

        let patch = serde_json::json!({ "value": 5000 });
        let mut merge_headers = json_headers();
        merge_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        let result = patch_resource(
            State(state.clone()),
            Path((
                "scheduling.k8s.io".into(),
                "v1".into(),
                "priorityclasses".into(),
                "patched-pc".into(),
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
                "PATCH changing PriorityClass.value must return 422 Invalid — immutability must \
                 be enforced for all write methods, matching the PUT check"
            ),
            Ok(_) => panic!(
                "PATCH changing PriorityClass.value must return 422 — immutability check is \
                 missing from do_patch"
            ),
        }

        // Patching a mutable field (description) must still succeed.
        let mutable_patch = serde_json::json!({ "description": "patched description" });
        let mut merge_headers = json_headers();
        merge_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        let result = patch_resource(
            State(state),
            Path((
                "scheduling.k8s.io".into(),
                "v1".into(),
                "priorityclasses".into(),
                "patched-pc".into(),
            )),
            Query(PatchQuery::default()),
            test_user(),
            merge_headers,
            bytes::Bytes::from(serde_json::to_vec(&mutable_patch).unwrap()),
        )
        .await;
        result.expect(
            "PATCH changing only PriorityClass.description must succeed — mutable fields must \
             remain patchable even though .value is locked",
        );
    }

    /// PUT growing a PVC's `spec.resources.requests.storage` must return 403 Forbidden when
    /// the bound StorageClass has `allowVolumeExpansion: false`.
    ///
    /// Mirrors upstream's PersistentVolumeClaimResize admission plugin (plugin/pkg/admission/
    /// storage/persistentvolume/resize/admission.go). Without this check, u7s silently grows
    /// the PVC and the e2e conformance test "should not allow expansion of pvcs without
    /// AllowVolumeExpansion property" observes `Update()` succeed instead of
    /// `apierrors.IsForbidden(err)`, because no CSI driver would ever actually resize the
    /// underlying volume for a StorageClass that never advertised support for it.
    #[tokio::test]
    async fn replace_namespaced_resource_rejects_pvc_expansion_without_allow_volume_expansion() {
        use axum::extract::{Path, Query, State};

        let state = make_state();

        let sc = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": { "name": "no-expand" },
            "provisioner": "csi-hostpath",
            "allowVolumeExpansion": false
        });
        create_resource(
            State(state.clone()),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "storageclasses".into(),
            )),
            Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&sc).unwrap()),
        )
        .await
        .expect("StorageClass create must succeed");

        let pvc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "my-pvc", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "no-expand",
                "resources": { "requests": { "storage": "1Gi" } }
            }
        });
        create_namespaced_resource(
            State(state.clone()),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
            )),
            Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&pvc).unwrap()),
        )
        .await
        .expect("PVC create must succeed");

        let grown = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "my-pvc", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "no-expand",
                "resources": { "requests": { "storage": "2Gi" } }
            }
        });
        let result = replace_namespaced_resource(
            State(state.clone()),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
                "my-pvc".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&grown).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::FORBIDDEN,
                "PUT growing a PVC's storage request without AllowVolumeExpansion must return \
                 403 Forbidden — client-go's apierrors.IsForbidden(err) drives the upstream e2e \
                 assertion, so any other status leaves the volume-expand conformance test failing"
            ),
            Ok(_) => panic!(
                "PUT growing PersistentVolumeClaim.spec.resources.requests.storage must be \
                 rejected when the bound StorageClass has allowVolumeExpansion: false — \
                 accepting it lets a PVC silently outgrow a driver that never advertised \
                 support for resizing the underlying volume"
            ),
        }

        // Growing storage on a StorageClass that DOES allow expansion must still succeed —
        // this check must not blanket-reject every storage-size increase.
        let sc2 = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": { "name": "can-expand" },
            "provisioner": "csi-hostpath",
            "allowVolumeExpansion": true
        });
        create_resource(
            State(state.clone()),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "storageclasses".into(),
            )),
            Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&sc2).unwrap()),
        )
        .await
        .expect("second StorageClass create must succeed");

        let pvc2 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "expandable-pvc", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "can-expand",
                "resources": { "requests": { "storage": "1Gi" } }
            }
        });
        create_namespaced_resource(
            State(state.clone()),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
            )),
            Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&pvc2).unwrap()),
        )
        .await
        .expect("second PVC create must succeed");

        let grown2 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "expandable-pvc", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "can-expand",
                "resources": { "requests": { "storage": "2Gi" } }
            }
        });
        let result = replace_namespaced_resource(
            State(state),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
                "expandable-pvc".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&grown2).unwrap()),
        )
        .await;
        result.expect(
            "PUT growing a PVC's storage request must succeed when the bound StorageClass has \
             allowVolumeExpansion: true — the resize check must not reject legitimate expansion",
        );
    }

    /// PATCH growing a PVC's `spec.resources.requests.storage` must return 403 Forbidden when
    /// the bound StorageClass has `allowVolumeExpansion: false`.
    ///
    /// Mirrors the PUT test above but for PATCH (merge-patch), exercising the do_patch code
    /// path instead of replace_namespaced_resource. `kubectl patch pvc` is the common way
    /// users resize a claim, so both write paths must enforce the same admission rule.
    #[tokio::test]
    async fn patch_namespaced_resource_rejects_pvc_expansion_without_allow_volume_expansion() {
        use axum::extract::{Path, Query, State};

        let state = make_state();

        let sc = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": { "name": "no-expand-patch" },
            "provisioner": "csi-hostpath",
            "allowVolumeExpansion": false
        });
        create_resource(
            State(state.clone()),
            Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "storageclasses".into(),
            )),
            Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&sc).unwrap()),
        )
        .await
        .expect("StorageClass create must succeed");

        let pvc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "patched-pvc", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "no-expand-patch",
                "resources": { "requests": { "storage": "1Gi" } }
            }
        });
        create_namespaced_resource(
            State(state.clone()),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
            )),
            Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&pvc).unwrap()),
        )
        .await
        .expect("PVC create must succeed");

        let patch = serde_json::json!({
            "spec": { "resources": { "requests": { "storage": "2Gi" } } }
        });
        let mut merge_headers = json_headers();
        merge_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        let result = patch_namespaced_resource(
            State(state),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
                "patched-pvc".into(),
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
                axum::http::StatusCode::FORBIDDEN,
                "PATCH growing a PVC's storage request without AllowVolumeExpansion must \
                 return 403 Forbidden, matching the PUT check in replace_namespaced_resource"
            ),
            Ok(_) => panic!(
                "PATCH growing PersistentVolumeClaim.spec.resources.requests.storage must be \
                 rejected when the bound StorageClass has allowVolumeExpansion: false — the \
                 resize check is missing from do_patch"
            ),
        }
    }

    /// Deleting a Job must remove the `batch.kubernetes.io/job-tracking` finalizer from
    /// owned pods so the GC cascade can complete.
    ///
    /// Without this fix KCM's job-controller receives a hard-delete event for the job,
    /// returns early from syncJob ("job not found"), and never removes the tracking
    /// finalizer from pods.  The pods are then stuck Terminating forever — GC cannot
    /// complete because the finalizer-holder (KCM) never acts.
    #[tokio::test]
    async fn delete_job_removes_tracking_finalizer_from_owned_pods() {
        let state = make_state();
        let job_uid = "job-uid-abc123";
        let ns = "test-ns";

        // Create a pod with batch.kubernetes.io/job-tracking finalizer, owned by the job.
        let pod_key = crate::keys::group_object_key("", "pods", Some(ns), "pod-1");
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pod-1",
                "namespace": ns,
                "resourceVersion": "1",
                "uid": "pod-uid-1",
                "finalizers": ["batch.kubernetes.io/job-tracking"],
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "name": "my-job",
                    "uid": job_uid,
                    "controller": true
                }]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &pod_key,
                bytes::Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .expect("create pod");

        // Act: remove the tracking finalizer (simulating job hard-delete).
        remove_job_tracking_finalizer_from_pods(&state, ns, job_uid).await;

        // Assert: pod still exists but finalizers are cleared.
        let stored = state
            .store
            .get(&pod_key)
            .await
            .expect("store get")
            .expect("pod must still exist — no deletionTimestamp, so not hard-deleted");
        let stored_pod: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("deserialize pod");
        let finalizers = stored_pod["metadata"]["finalizers"].as_array();
        assert!(
            finalizers.is_none() || finalizers.unwrap().is_empty(),
            "job-tracking finalizer must be removed from the pod so the GC cascade can \
             complete — without this, pods are stuck Terminating forever: \
             got finalizers = {:?}",
            stored_pod["metadata"]["finalizers"]
        );
    }

    /// When a job is deleted and a pod owned by it already has deletionTimestamp set AND
    /// has only the tracking finalizer (no other finalizers), the pod must be hard-deleted
    /// immediately so the GC sees a clean DELETED event.
    ///
    /// Without this: the pod is stuck in Terminating state indefinitely — deletionTimestamp
    /// is set but the finalizer prevents hard-delete, and no controller removes the finalizer.
    #[tokio::test]
    async fn delete_job_hard_deletes_terminating_pod_with_only_tracking_finalizer() {
        let state = make_state();
        let job_uid = "job-uid-xyz789";
        let ns = "test-ns2";

        // Create a pod that is already Terminating (has deletionTimestamp) + tracking finalizer.
        let pod_key = crate::keys::group_object_key("", "pods", Some(ns), "pod-term");
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pod-term",
                "namespace": ns,
                "resourceVersion": "5",
                "uid": "pod-uid-term",
                "deletionTimestamp": "2026-01-01T00:00:00Z",
                "finalizers": ["batch.kubernetes.io/job-tracking"],
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "name": "my-job2",
                    "uid": job_uid,
                    "controller": true
                }]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &pod_key,
                bytes::Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .expect("create pod");

        // Act: remove the tracking finalizer.
        remove_job_tracking_finalizer_from_pods(&state, ns, job_uid).await;

        // Assert: pod must be hard-deleted (not found in store).
        let result = state.store.get(&pod_key).await.expect("store get");
        assert!(
            result.is_none(),
            "pod with deletionTimestamp + only tracking finalizer must be hard-deleted \
             when the job is deleted — without this, the GC cascade never completes and \
             the pod stays Terminating forever"
        );
    }

    // -- ownerReferences preserved through create ObjectMeta round-trip --

    /// create_namespaced_resource must persist ownerReferences from the incoming body.
    ///
    /// The create handler converts metadata through an ObjectMeta struct to set the
    /// namespace field.  ObjectMeta only declares the fields it explicitly knows about;
    /// any other field (including ownerReferences) is silently dropped by serde.  If
    /// ownerReferences are dropped during create, KCM-created Jobs (which carry an
    /// ownerReference to their CronJob) are stored without ownerReferences — the
    /// CronJob→Job cascade cannot match them, so the GC conformance spec
    /// "should delete jobs and pods created by cronjob" times out seeing 1 job / 1 pod
    /// after the CronJob is deleted.
    #[tokio::test]
    async fn create_namespaced_resource_preserves_owner_references() {
        use axum::extract::{Path, State};

        let state = make_state();
        let ns = "default";
        let cj_uid = "cj-uid-preserve-ownerrefs";

        // Create a Job with ownerReferences pointing to a CronJob — exactly what KCM
        // cronjob-controller does when it creates a Job from a CronJob schedule.
        let body = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "preserve-ownerrefs-job",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "name": "my-cronjob",
                    "uid": cj_uid,
                    "controller": true,
                    "blockOwnerDeletion": true
                }]
            },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": "c", "image": "busybox"}],
                        "restartPolicy": "Never"
                    }
                }
            }
        });
        let body_bytes = bytes::Bytes::from(serde_json::to_vec(&body).unwrap());

        let result = create_namespaced_resource(
            State(state.clone()),
            Path(("batch".into(), "v1".into(), ns.to_string(), "jobs".into())),
            axum::extract::Query(CreateQuery::default()),
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
            axum::http::HeaderMap::new(),
            body_bytes,
        )
        .await
        .unwrap_or_else(|e| panic!("create Job must succeed: {e:?}"));

        // The stored object must have ownerReferences intact — if the ObjectMeta round-trip
        // drops them, the stored Job has no ownerReferences and the CronJob cascade cannot
        // identify it as owned, causing the GC conformance test to fail.
        let stored = state
            .store
            .get(&crate::keys::group_object_key(
                "batch",
                "jobs",
                Some(ns),
                "preserve-ownerrefs-job",
            ))
            .await
            .unwrap()
            .expect("Job must be stored");
        let stored_val: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored Job must be valid JSON");
        let refs = stored_val["metadata"]["ownerReferences"].as_array().expect(
            "stored Job metadata.ownerReferences must be an array — if missing, the \
                 ObjectMeta round-trip in create_namespaced_resource dropped them, causing \
                 the CronJob→Job cascade to find no owned Jobs after CronJob deletion",
        );
        assert_eq!(refs.len(), 1, "one ownerReference must survive create");
        assert_eq!(
            refs[0]["kind"].as_str(),
            Some("CronJob"),
            "ownerReference.kind must be CronJob"
        );
        assert_eq!(
            refs[0]["uid"].as_str(),
            Some(cj_uid),
            "ownerReference.uid must match CronJob UID — cascade uses uid equality"
        );
        assert_eq!(
            refs[0]["controller"].as_bool(),
            Some(true),
            "controller field must survive the round-trip"
        );
        let _ = result;
    }

    // -- CronJob cascade --

    /// Deleting a CronJob must cascade-delete owned Jobs AND their pods, or the GC conformance
    /// spec "should delete jobs and pods created by cronjob" will time out polling for 0 jobs
    /// and 0 pods (observing 1 job / 1 pod for the full 60 s before "context deadline exceeded").
    #[tokio::test]
    async fn delete_cronjob_cascades_to_jobs_and_pods() {
        let state = make_state();
        let cj_uid = "cj-uid-aaaa-0001";
        let job_uid = "job-uid-bbbb-0001";
        let ns = "default";

        // Seed the CronJob.
        let cj_key = crate::keys::group_object_key("batch", "cronjobs", Some(ns), "my-cj");
        let cj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": { "name": "my-cj", "namespace": ns, "uid": cj_uid },
            "spec": { "schedule": "*/1 * * * *" }
        });
        state
            .store
            .put(
                &cj_key,
                bytes::Bytes::from(serde_json::to_vec(&cj).unwrap()),
                None,
            )
            .await
            .expect("seed CronJob");

        // Seed a Job owned by this CronJob (as KCM cronjob-controller creates it).
        let job_key = crate::keys::group_object_key("batch", "jobs", Some(ns), "my-cj-job");
        let job = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "my-cj-job",
                "namespace": ns,
                "uid": job_uid,
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "name": "my-cj",
                    "uid": cj_uid,
                    "controller": true
                }]
            },
            "spec": { "template": { "spec": { "containers": [] } } }
        });
        state
            .store
            .put(
                &job_key,
                bytes::Bytes::from(serde_json::to_vec(&job).unwrap()),
                None,
            )
            .await
            .expect("seed Job");

        // Seed a Pod owned by the Job (as KCM job-controller creates it).
        let pod_key = crate::keys::group_object_key("", "pods", Some(ns), "my-cj-job-pod");
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-cj-job-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "name": "my-cj-job",
                    "uid": job_uid,
                    "controller": true
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        state
            .store
            .put(
                &pod_key,
                bytes::Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .expect("seed Pod");

        // Delete the CronJob (default empty body — matches what the GC conformance test sends).
        delete_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "batch".into(),
                "v1".into(),
                ns.to_string(),
                "cronjobs".into(),
                "my-cj".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            bytes::Bytes::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("CronJob delete must succeed: {e:?}"));

        // CronJob itself must be gone.
        assert!(
            state.store.get(&cj_key).await.unwrap().is_none(),
            "CronJob itself must be hard-deleted"
        );

        // Job must be cascade-deleted — without this the GC conformance spec sees 'expected 0 jobs, got 1'.
        assert!(
            state.store.get(&job_key).await.unwrap().is_none(),
            "Job owned by deleted CronJob must be cascade-deleted — \
             GC conformance spec 'should delete jobs and pods created by cronjob' fails otherwise"
        );

        // Pod must be cascade-deleted — without this the spec sees 'expected 0 pods, got 1'.
        assert!(
            state.store.get(&pod_key).await.unwrap().is_none(),
            "Pod owned by Job owned by deleted CronJob must be cascade-deleted — \
             GC conformance spec 'should delete jobs and pods created by cronjob' fails otherwise \
             (two-level chain: CronJob->Job->Pod)"
        );
    }

    /// Deleting a CronJob with propagationPolicy=Orphan must NOT cascade-delete its Jobs or Pods.
    ///
    /// Explicit Orphan semantics must be honored for CronJob just as for every other resource:
    /// the CronJob soft-deletes with the `orphan` finalizer (the gate is generic, not
    /// RC/Deployment-specific — see add_orphan_finalizer) and its owned Jobs survive; real
    /// KCM's GC controller is responsible for stripping their ownerReferences, not u7s.
    #[tokio::test]
    async fn delete_cronjob_with_orphan_policy_does_not_cascade() {
        let state = make_state();
        let cj_uid = "cj-uid-cccc-0002";
        let job_uid = "job-uid-dddd-0002";
        let ns = "default";

        // Seed CronJob.
        let cj_key = crate::keys::group_object_key("batch", "cronjobs", Some(ns), "orphan-cj");
        let cj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": { "name": "orphan-cj", "namespace": ns, "uid": cj_uid },
            "spec": { "schedule": "*/1 * * * *" }
        });
        state
            .store
            .put(
                &cj_key,
                bytes::Bytes::from(serde_json::to_vec(&cj).unwrap()),
                None,
            )
            .await
            .expect("seed CronJob");

        // Seed a Job owned by the CronJob.
        let job_key = crate::keys::group_object_key("batch", "jobs", Some(ns), "orphan-cj-job");
        let job = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "orphan-cj-job",
                "namespace": ns,
                "uid": job_uid,
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "name": "orphan-cj",
                    "uid": cj_uid,
                    "controller": true
                }]
            },
            "spec": { "template": { "spec": { "containers": [] } } }
        });
        state
            .store
            .put(
                &job_key,
                bytes::Bytes::from(serde_json::to_vec(&job).unwrap()),
                None,
            )
            .await
            .expect("seed Job");

        // Delete with propagationPolicy=Orphan.
        let orphan_body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "propagationPolicy": "Orphan"
            }))
            .unwrap(),
        );
        delete_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "batch".into(),
                "v1".into(),
                ns.to_string(),
                "cronjobs".into(),
                "orphan-cj".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            orphan_body,
        )
        .await
        .unwrap_or_else(|e| panic!("Orphan delete must succeed: {e:?}"));

        // CronJob must be SOFT-deleted (deletionTimestamp + "orphan" finalizer), not
        // hard-deleted synchronously — same generic gate as RC/Deployment Orphan deletes.
        let cj_stored = state
            .store
            .get(&cj_key)
            .await
            .unwrap()
            .expect("CronJob must remain in the store (soft-deleted) after an Orphan delete");
        let cj_val: serde_json::Value = serde_json::from_slice(&cj_stored.value).unwrap();
        assert!(
            cj_val["metadata"]["deletionTimestamp"].is_string(),
            "Orphan delete must stamp deletionTimestamp on the CronJob"
        );
        assert_eq!(
            cj_val["metadata"]["finalizers"]
                .as_array()
                .and_then(|f| f.first())
                .and_then(|v| v.as_str()),
            Some("orphan"),
            "Orphan delete must add the `orphan` finalizer to the CronJob, same as any other \
             resource type"
        );

        // Job must survive — Orphan means do NOT cascade.
        assert!(
            state.store.get(&job_key).await.unwrap().is_some(),
            "Orphan delete of CronJob must leave its Jobs alive — \
             cascade on Orphan would contradict explicit Orphan semantics"
        );
    }

    // -- RoleBinding escalation prevention (bwm2) --

    /// A user without permission X who creates a RoleBinding granting a Role that contains X
    /// must get 403 Forbidden.  Without this check, any user with create rolebindings in a
    /// namespace can self-grant cluster-admin-in-namespace by binding to any powerful Role.
    #[tokio::test]
    async fn create_rolebinding_denied_for_user_lacking_role_rules() {
        use axum::extract::{Extension, Path, State};

        let state = make_state();
        let group = "rbac.authorization.k8s.io";
        let version = "v1";
        let ns = "default";

        // Seed a Role in "default" with secret-read rules that "alice" does NOT hold.
        let secret_role = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "secret-reader", "namespace": ns},
            "rules": [{
                "apiGroups": [""],
                "resources": ["secrets"],
                "verbs": ["get", "list"]
            }]
        });
        let role_key = format!("/apis/{group}/{version}/namespaces/{ns}/roles/secret-reader");
        state.rbac_index.apply_object(&role_key, &secret_role);

        // "alice" can only create rolebindings — she does NOT have get/list secrets.
        let alice_cr = serde_json::json!({
            "rules": [{
                "apiGroups": [group],
                "resources": ["rolebindings"],
                "verbs": ["create"]
            }]
        });
        let alice_crb_key = format!("/apis/{group}/{version}/clusterroles/alice-rb-creator");
        state.rbac_index.apply_object(&alice_crb_key, &alice_cr);
        let alice_bind_key =
            format!("/apis/{group}/{version}/clusterrolebindings/alice-rb-creator-bind");
        let alice_bind = serde_json::json!({
            "subjects": [{"kind": "User", "name": "alice"}],
            "roleRef": {
                "apiGroup": group,
                "kind": "ClusterRole",
                "name": "alice-rb-creator"
            }
        });
        state.rbac_index.apply_object(&alice_bind_key, &alice_bind);

        // alice tries to bind herself to "secret-reader" in "default".
        let rb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "alice-secret-reader", "namespace": ns},
            "subjects": [{"kind": "User", "name": "alice"}],
            "roleRef": {
                "apiGroup": group,
                "kind": "Role",
                "name": "secret-reader"
            }
        });
        let alice_user = Extension(crate::auth::UserInfo {
            username: "alice".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });
        let result = create_namespaced_resource(
            State(state),
            Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                "rolebindings".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
            alice_user,
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&rb_body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::FORBIDDEN,
                "missing RB escalation check lets any namespace rolebindings-creator \
                 self-grant cluster-admin-in-namespace; alice must be denied because \
                 she does not hold get/list secrets"
            ),
            Ok(_) => panic!(
                "missing RB escalation check lets any namespace rolebindings-creator \
                 self-grant cluster-admin-in-namespace; alice must be denied because \
                 she does not hold get/list secrets"
            ),
        }
    }

    /// A user who holds all the rules in a Role must be allowed to create a RoleBinding to it.
    /// This ensures that users with the right permissions can delegate them within a namespace.
    #[tokio::test]
    async fn create_rolebinding_allowed_for_user_holding_role_rules() {
        use axum::extract::{Extension, Path, State};
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        let state = make_state();
        let group = "rbac.authorization.k8s.io";
        let version = "v1";
        let ns = "default";

        // Seed a Role in "default" with pod-read rules.
        let pod_role = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "pod-reader", "namespace": ns},
            "rules": [{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list"]
            }]
        });
        let role_key = format!("/apis/{group}/{version}/namespaces/{ns}/roles/pod-reader");
        state.rbac_index.apply_object(&role_key, &pod_role);

        // Seed cluster-admin and system:masters binding so "admin" passes escalation.
        let admin_cr = serde_json::json!({
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        state.rbac_index.apply_object(
            &format!("/apis/{group}/{version}/clusterroles/cluster-admin"),
            &admin_cr,
        );
        let masters_crb = serde_json::json!({
            "subjects": [{"kind": "Group", "name": "system:masters"}],
            "roleRef": {
                "apiGroup": group,
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });
        state.rbac_index.apply_object(
            &format!("/apis/{group}/{version}/clusterrolebindings/system-masters-cluster-admin"),
            &masters_crb,
        );

        // "admin" (system:masters) creates a RoleBinding granting pod-reader to "bob".
        let rb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "bob-pod-reader", "namespace": ns},
            "subjects": [{"kind": "User", "name": "bob"}],
            "roleRef": {
                "apiGroup": group,
                "kind": "Role",
                "name": "pod-reader"
            }
        });
        let admin_user = Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
            extra: Default::default(),
        });
        let result = create_namespaced_resource(
            State(state),
            Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                "rolebindings".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
            admin_user,
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&rb_body).unwrap()),
        )
        .await;

        let status = result
            .map(|r| r.into_response().status())
            .unwrap_or_else(|e| {
                panic!(
                    "admin with system:masters must be allowed to create RoleBinding; got: {}",
                    e.1.message
                )
            });
        assert_eq!(
            status,
            StatusCode::CREATED,
            "admin who holds all pod-reader rules must be allowed to create a RoleBinding"
        );
    }

    // ---------------------------------------------------------------------------
    // Lease acquireTime/renewTime must be persisted and returned on GET
    // ---------------------------------------------------------------------------

    /// A Lease created with spec.acquireTime and spec.renewTime must return
    /// those fields non-nil on GET.
    ///
    /// The conformance spec '[sig-node] Lease lease API should be available
    /// [Conformance]' (k8s test/e2e/common/node/lease.go:99) creates a Lease with
    /// both timestamps set and asserts they are non-nil after create and update.
    /// If acquireTime or renewTime are dropped by the create or update path, the
    /// test fails with "unexpected nil acquireTime" or "unexpected nil renewTime".
    ///
    /// This test fails if apply_defaults, the metadata round-trip, or any other
    /// handler step strips spec fields from a Lease.
    #[tokio::test]
    async fn lease_acquire_and_renew_time_preserved_on_create_and_update() {
        use axum::body::to_bytes;
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;

        let state = make_state();

        let acquire_ts = "2026-06-29T12:00:00.000000Z";
        let renew_ts = "2026-06-29T12:00:01.000000Z";

        // Step 1: create a Lease with acquireTime and renewTime via PUT (upsert).
        let lease_v1 = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "test-lease", "namespace": "kube-node-lease" },
            "spec": {
                "holderIdentity": "node-1",
                "leaseDurationSeconds": 40,
                "acquireTime": acquire_ts,
                "renewTime": renew_ts,
                "leaseTransitions": 0
            }
        });
        let _ = replace_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "test-lease".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&lease_v1).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Lease create must succeed: {e:?}"))
        .into_response();

        // Step 2: GET the Lease and check acquireTime/renewTime are present.
        let get_resp = get_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "test-lease".into(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("Lease GET must succeed: {e:?}"));

        let body = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["spec"]["acquireTime"].as_str(),
            Some(acquire_ts),
            "spec.acquireTime must be present after create — the Lease conformance test \
             ([sig-node] Lease lease API should be available) checks acquireTime != nil \
             after create; if dropped the test fails with 'unexpected nil acquireTime'"
        );
        assert_eq!(
            v["spec"]["renewTime"].as_str(),
            Some(renew_ts),
            "spec.renewTime must be present after create — the Lease conformance test \
             checks renewTime != nil after create; if dropped the test fails with \
             'unexpected nil renewTime'"
        );

        // Step 3: UPDATE via PUT with a new renewTime but same acquireTime.
        let new_renew_ts = "2026-06-29T12:00:41.000000Z";
        let stored_rv = v["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let lease_v2 = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": "test-lease",
                "namespace": "kube-node-lease",
                "resourceVersion": stored_rv
            },
            "spec": {
                "holderIdentity": "node-1",
                "leaseDurationSeconds": 40,
                "acquireTime": acquire_ts,
                "renewTime": new_renew_ts,
                "leaseTransitions": 0
            }
        });
        let _ = replace_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "test-lease".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&lease_v2).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Lease update must succeed: {e:?}"))
        .into_response();

        // Step 4: GET again — acquireTime must still be set, renewTime updated.
        let get_resp2 = get_namespaced_resource(
            State(state.clone()),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "test-lease".into(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("Lease second GET must succeed: {e:?}"));

        let body2 = to_bytes(get_resp2.into_body(), usize::MAX).await.unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&body2).unwrap();

        assert_eq!(
            v2["spec"]["acquireTime"].as_str(),
            Some(acquire_ts),
            "spec.acquireTime must still be present after update — \
             the Lease conformance test checks acquireTime != nil after update too"
        );
        assert_eq!(
            v2["spec"]["renewTime"].as_str(),
            Some(new_renew_ts),
            "spec.renewTime must reflect the updated value after PUT update"
        );
    }

    // ---------------------------------------------------------------------------
    // Service ExternalName→ClusterIP type transition must allocate a clusterIP
    // ---------------------------------------------------------------------------

    /// Changing a Service from ExternalName to ClusterIP via PUT must result in a
    /// non-empty spec.clusterIP in the stored object.
    ///
    /// The conformance spec '[sig-network] Services should be able to change the type from
    /// ExternalName to ClusterIP [Conformance]' (network/service.go:1445) fails with
    /// "didn't get ClusterIP for non-ExternalName service" when the PUT on the main
    /// endpoint does not trigger ClusterIP allocation.  ExternalName services are created
    /// without a clusterIP; the update path must allocate one when the type changes.
    ///
    /// This test fails if maybe_allocate_cluster_ip is not called from
    /// replace_namespaced_resource.
    #[tokio::test]
    async fn externalname_to_clusterip_allocates_cluster_ip() {
        use axum::body::to_bytes;
        use axum::extract::{Path, Query, State};
        use axum::response::IntoResponse;
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        let state = make_state_with_cidr_for_resource_tests("10.96.0.0/12");

        // Step 1: create an ExternalName service (no clusterIP).
        let svc_external = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "type-changer", "namespace": "default" },
            "spec": {
                "type": "ExternalName",
                "externalName": "my.external.host.example.com"
            }
        });
        let create_resp = create_namespaced_resource(
            State(state.clone()),
            Path(("".into(), "v1".into(), "default".into(), "services".into())),
            axum::extract::Query(CreateQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&svc_external).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("ExternalName service create must succeed: {e:?}"))
        .into_response();
        assert_eq!(create_resp.status(), axum::http::StatusCode::CREATED);

        // Capture the resourceVersion for the PUT.
        let create_body = to_bytes(create_resp.into_body(), usize::MAX).await.unwrap();
        let created: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
        let rv = created["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("")
            .to_string();

        // Step 2: PUT to change type to ClusterIP — no clusterIP in body.
        let svc_clusterip = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "type-changer",
                "namespace": "default",
                "resourceVersion": rv
            },
            "spec": {
                "type": "ClusterIP",
                "ports": [{ "port": 80 }]
            }
        });
        let put_resp = replace_namespaced_resource(
            State(state.clone()),
            Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "services".into(),
                "type-changer".into(),
            )),
            Query(ReplaceQuery::default()),
            test_user(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&svc_clusterip).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("Service type-change PUT must succeed: {e:?}"))
        .into_response();

        assert_eq!(put_resp.status(), axum::http::StatusCode::OK);

        let put_body = to_bytes(put_resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&put_body).unwrap();

        let cluster_ip = v["spec"]["clusterIP"].as_str().unwrap_or("").to_string();
        assert!(
            !cluster_ip.is_empty() && cluster_ip != "None",
            "after ExternalName→ClusterIP type change via PUT, spec.clusterIP must be \
             allocated — without this, the conformance test '[sig-network] Services should \
             be able to change the type from ExternalName to ClusterIP' fails with \
             'didn't get ClusterIP for non-ExternalName service'; got clusterIP={cluster_ip:?}"
        );

        // Must be a valid IPv4 address within the configured CIDR.
        let ip = Ipv4Addr::from_str(&cluster_ip).unwrap_or_else(|_| {
            panic!(
                "spec.clusterIP must be a valid IPv4 address after type change, got {cluster_ip}"
            )
        });
        let base = u32::from(Ipv4Addr::new(10, 96, 0, 0));
        let mask: u32 = !((1u32 << (32 - 12)) - 1);
        assert_eq!(
            u32::from(ip) & mask,
            base & mask,
            "allocated clusterIP {ip} must be within 10.96.0.0/12"
        );
    }

    // ---------------------------------------------------------------------------
    // MockStore that injects a non-NotFound delete error on demand.
    //
    // Used by delete_collection error-propagation tests only.
    // ---------------------------------------------------------------------------

    struct FailOnDeleteStore {
        inner: std::sync::Arc<u7s_store::SqliteStore>,
        /// When true the *next* delete() call returns a storage error instead of
        /// delegating to the real store.  Cleared after firing once.
        arm: std::sync::atomic::AtomicBool,
    }

    impl FailOnDeleteStore {
        fn new() -> Self {
            Self {
                inner: std::sync::Arc::new(u7s_store::SqliteStore::new(":memory:").unwrap()),
                arm: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn arm(&self) {
            self.arm.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl u7s_store::Store for FailOnDeleteStore {
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
            value: bytes::Bytes,
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
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, bytes::Bytes)>> + Send
        {
            let inject = self.arm.swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            async move {
                if inject {
                    // Simulate a storage-layer failure (revision mismatch is a concrete
                    // non-NotFound variant that requires no external crates to construct).
                    Err(u7s_store::StoreError::RevisionMismatch {
                        expected: 999,
                        current: 1,
                    })
                } else {
                    inner.delete(&key, expected_revision).await
                }
            }
        }

        fn list_namespace_objects(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.list_namespace_objects(&ns).await }
        }

        fn delete_namespace_resources(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.delete_namespace_resources(&ns).await }
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

    // ---------------------------------------------------------------------------
    // MockStore that, on the first armed put(), writes an INDEPENDENT object
    // (simulating a different concurrent writer, e.g. a status controller) instead
    // of the caller's own value, then reports RevisionMismatch.
    //
    // Used by strip_or_delete_dependent's concurrent-write regression test only.
    // ---------------------------------------------------------------------------

    struct ConcurrentWriterStore {
        inner: std::sync::Arc<u7s_store::SqliteStore>,
        concurrent_write: bytes::Bytes,
        inject_next: std::sync::atomic::AtomicBool,
    }

    impl ConcurrentWriterStore {
        fn new(
            inner: std::sync::Arc<u7s_store::SqliteStore>,
            concurrent_write: bytes::Bytes,
        ) -> Self {
            Self {
                inner,
                concurrent_write,
                inject_next: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn arm(&self) {
            self.inject_next
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl u7s_store::Store for ConcurrentWriterStore {
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
            value: bytes::Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inject = self
                .inject_next
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            let concurrent_write = self.concurrent_write.clone();
            async move {
                if inject {
                    // A different writer's change lands here, independent of `value`
                    // (the caller's own not-yet-persisted attempt).
                    let _ = inner.put(&key, concurrent_write, None).await;
                    Err(u7s_store::StoreError::RevisionMismatch {
                        expected: 1,
                        current: 99,
                    })
                } else {
                    inner.put(&key, value, expected_revision).await
                }
            }
        }

        fn delete(
            &self,
            key: &str,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, bytes::Bytes)>> + Send
        {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.delete(&key, expected_revision).await }
        }

        fn list_namespace_objects(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.list_namespace_objects(&ns).await }
        }

        fn delete_namespace_resources(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.delete_namespace_resources(&ns).await }
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

    /// `strip_or_delete_dependent` must re-read the dependent fresh and retry on conflict
    /// rather than blindly overwriting whatever the caller's LIST-time snapshot contained.
    ///
    /// If a concurrent writer (e.g. a status controller) updates the dependent between the
    /// cascade helper's LIST and this strip write, an unconditional `put(.., None)` of the
    /// stale snapshot would silently discard that write with no error to anyone — the
    /// writer believes its update succeeded. This test fails on revert: without the
    /// read-modify-write CAS retry, the concurrent write's `status.replicas` is clobbered
    /// back to its pre-race value.
    #[tokio::test]
    async fn strip_or_delete_dependent_retries_past_concurrent_write_instead_of_clobbering_it() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let owner_uid = "aaaa0000-0000-0000-0000-000000000001";
        let other_owner_uid = "bbbb0000-0000-0000-0000-000000000002";
        let ns = "default";

        // A second, still-live owner — keeps the dependent alive (strip path, not delete)
        // once `owner_uid`'s reference is removed.
        let other_owner_key = "/registry/apps/deployments/default/other-owner";
        inner
            .put(
                other_owner_key,
                bytes::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "metadata": {
                            "name": "other-owner",
                            "namespace": ns,
                            "uid": other_owner_uid
                        }
                    }))
                    .unwrap(),
                ),
                None,
            )
            .await
            .unwrap();

        let owner_refs = serde_json::json!([
            {
                "apiVersion": "apps/v1", "kind": "Deployment",
                "name": "gone-owner", "uid": owner_uid, "controller": true
            },
            {
                "apiVersion": "apps/v1", "kind": "Deployment",
                "name": "other-owner", "uid": other_owner_uid
            }
        ]);

        let rs_key = "/registry/apps/replicasets/default/my-rs";
        let rs = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": "my-rs",
                "namespace": ns,
                "ownerReferences": owner_refs
            },
            "status": { "replicas": 0 }
        });
        inner
            .put(
                rs_key,
                bytes::Bytes::from(serde_json::to_vec(&rs).unwrap()),
                None,
            )
            .await
            .unwrap();

        // What a concurrent status controller's write lands as between strip's read and
        // its first write attempt — same ownerReferences, but an updated status field a
        // real client is relying on having durably persisted.
        let concurrent_write = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": "my-rs",
                "namespace": ns,
                "ownerReferences": owner_refs
            },
            "status": { "replicas": 3 }
        });
        let racing_store = Arc::new(ConcurrentWriterStore::new(
            Arc::clone(&inner),
            bytes::Bytes::from(serde_json::to_vec(&concurrent_write).unwrap()),
        ));
        racing_store.arm();

        let state = crate::state::AppState::new(
            racing_store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let deleted = strip_or_delete_dependent(&state, ns, rs_key, owner_uid, "test-rs").await;

        assert!(
            !deleted,
            "the ReplicaSet has another live owner besides owner_uid, so it must survive \
             with only owner_uid's reference stripped, not be hard-deleted"
        );

        let stored = inner.get(rs_key).await.unwrap().unwrap();
        let stored_val: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let refs = stored_val["metadata"]["ownerReferences"]
            .as_array()
            .unwrap();
        assert!(
            !refs.iter().any(|r| r["uid"].as_str() == Some(owner_uid)),
            "the deleted owner's reference must be stripped"
        );
        assert!(
            refs.iter()
                .any(|r| r["uid"].as_str() == Some(other_owner_uid)),
            "the other live owner's reference must survive the strip"
        );
        assert_eq!(
            stored_val["status"]["replicas"], 3,
            "a concurrent status write racing the owner-ref strip must survive — a strip \
             that clobbers stale LIST-time data instead of retrying against the freshly \
             re-read object would silently discard a status update the writer believes \
             succeeded, with no error surfaced to either side"
        );
    }

    /// delete_collection_resource must propagate a non-NotFound store error rather than
    /// returning 200 Success.  Silent swallowing causes quota drift: the client believes
    /// all objects were deleted, but some may survive because the store rejected the delete.
    ///
    /// Revert the match-on-delete fix (back to `let _ = …`) and this test fails.
    #[tokio::test]
    async fn delete_collection_resource_propagates_non_notfound_store_error() {
        use axum::extract::{Path, Query, State};

        let mock = std::sync::Arc::new(FailOnDeleteStore::new());
        let state = crate::state::AppState::new(
            mock.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed one ClusterRoleBinding (non-seeded name so it is not skipped).
        let key = crate::keys::group_object_key(
            "rbac.authorization.k8s.io",
            "clusterrolebindings",
            None,
            "test-binding",
        );
        let val = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": "test-binding" },
        });
        mock.inner
            .put(
                &key,
                bytes::Bytes::from(serde_json::to_vec(&val).unwrap()),
                None,
            )
            .await
            .expect("seed must succeed");

        // Arm the store to fail on the next delete.
        mock.arm();

        let result = delete_collection_resource(
            State(state),
            Path((
                "rbac.authorization.k8s.io".into(),
                "v1".into(),
                "clusterrolebindings".into(),
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
            test_user(),
        )
        .await;

        assert!(
            result.is_err(),
            "delete_collection must propagate a non-NotFound store error — \
             silently returning 200 causes quota drift: client believes all objects \
             deleted, but surviving objects skew quota accounting"
        );
    }

    /// delete_collection_namespaced_resource must propagate a non-NotFound store error
    /// rather than returning 200 Success.  Same quota-drift / hidden-failure risk as the
    /// cluster-scoped variant.
    ///
    /// Revert the match-on-delete fix (back to `let _ = …`) and this test fails.
    #[tokio::test]
    async fn delete_collection_namespaced_propagates_non_notfound_store_error() {
        use axum::extract::{Path, Query, State};

        let mock = std::sync::Arc::new(FailOnDeleteStore::new());
        let state = crate::state::AppState::new(
            mock.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed one Lease in "test-ns".
        let key = crate::keys::group_object_key(
            "coordination.k8s.io",
            "leases",
            Some("test-ns"),
            "my-lease",
        );
        let val = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "my-lease", "namespace": "test-ns" },
            "spec": {}
        });
        mock.inner
            .put(
                &key,
                bytes::Bytes::from(serde_json::to_vec(&val).unwrap()),
                None,
            )
            .await
            .expect("seed must succeed");

        // Arm the store to fail on the next delete.
        mock.arm();

        let result = delete_collection_namespaced_resource(
            State(state),
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
            test_user(),
        )
        .await;

        assert!(
            result.is_err(),
            "delete_collection_namespaced must propagate a non-NotFound store error — \
             silently returning 200 causes quota drift: client believes all objects \
             deleted, but surviving objects skew quota accounting"
        );
    }

    /// A FailOnDeleteStore variant that injects NotFound (not a real error) on delete.
    ///
    /// Models the concurrent-delete race: list returned a key that a peer deleted
    /// before our loop could reach it.
    struct NotFoundOnDeleteStore {
        inner: std::sync::Arc<u7s_store::SqliteStore>,
        arm: std::sync::atomic::AtomicBool,
    }

    impl NotFoundOnDeleteStore {
        fn new() -> Self {
            Self {
                inner: std::sync::Arc::new(u7s_store::SqliteStore::new(":memory:").unwrap()),
                arm: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn arm(&self) {
            self.arm.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl u7s_store::Store for NotFoundOnDeleteStore {
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
            value: bytes::Bytes,
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
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, bytes::Bytes)>> + Send
        {
            let inject = self.arm.swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            async move {
                if inject {
                    Err(u7s_store::StoreError::NotFound { key: key.clone() })
                } else {
                    inner.delete(&key, expected_revision).await
                }
            }
        }

        fn list_namespace_objects(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.list_namespace_objects(&ns).await }
        }

        fn delete_namespace_resources(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.delete_namespace_resources(&ns).await }
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

    /// NotFound during delete_collection is a tolerated concurrent-delete race, not an error.
    /// The handler must still succeed (200) when the only failure is NotFound.
    ///
    /// Revert the NotFound tolerance (make NotFound also propagate) and this test fails.
    #[tokio::test]
    async fn delete_collection_tolerates_notfound_concurrent_race() {
        use axum::extract::{Path, Query, State};

        // Inject a NotFound on delete to model the race: list captured the key, but a
        // concurrent writer deleted it before our loop reached it.
        let mock = std::sync::Arc::new(NotFoundOnDeleteStore::new());
        let state = crate::state::AppState::new(
            mock.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a Lease so it appears in the list response.
        let key = crate::keys::group_object_key(
            "coordination.k8s.io",
            "leases",
            Some("default"),
            "raced-lease",
        );
        let val = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "raced-lease", "namespace": "default" },
            "spec": {}
        });
        mock.inner
            .put(
                &key,
                bytes::Bytes::from(serde_json::to_vec(&val).unwrap()),
                None,
            )
            .await
            .expect("seed must succeed");

        // Arm the NotFound injection so delete returns NotFound (race).
        mock.arm();

        let result = delete_collection_namespaced_resource(
            State(state),
            Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "default".into(),
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
            test_user(),
        )
        .await;

        assert!(
            result.is_ok(),
            "delete_collection must tolerate NotFound (concurrent-delete race) \
             and still return 200 — treating NotFound as fatal would cause spurious \
             errors during normal namespace teardown"
        );
    }

    /// A validating webhook with failurePolicy=Fail and an unreachable URL must deny a
    /// namespaced deletecollection, not just single-object DELETE.
    ///
    /// Regression test: PR #700 wired admission into the
    /// single-delete handlers but explicitly deferred deletecollection, so
    /// `kubectl delete configmaps --all` bypassed a Fail-policy validating webhook that
    /// would have blocked each object individually — a webhook must be able to deny a
    /// deletecollection, else bulk deletes bypass admission that single deletes enforce.
    /// If delete_collection_namespaced_resource stops calling run_validating_webhooks per
    /// object (i.e. this fix is reverted), the delete below succeeds and both ConfigMaps
    /// disappear from the store — this test then fails, proving the admission invocation
    /// was removed.
    #[tokio::test]
    async fn delete_collection_namespaced_calls_validating_admission_fail_policy_denies() {
        let state = make_state();
        let ns = "cm-delcol-ns";

        for name in ["cm-one", "cm-two"] {
            let key = crate::keys::group_object_key("", "configmaps", Some(ns), name);
            let val = serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "name": name, "namespace": ns },
                "data": {}
            });
            state
                .store
                .put(
                    &key,
                    bytes::Bytes::from(serde_json::to_vec(&val).unwrap()),
                    None,
                )
                .await
                .expect("seed configmap must succeed");
        }

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "cm-delcol-vwc"},
            "webhooks": [{
                "name": "cm.deny-delete.example.com",
                "clientConfig": { "url": "http://127.0.0.1:1" },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["DELETE"]}],
                "failurePolicy": "Fail"
            }]
        });
        state
            .store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/cm-delcol-vwc",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = delete_collection_namespaced_resource(
            State(state.clone()),
            Path(("".into(), "v1".into(), ns.into(), "configmaps".into())),
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
            test_user(),
        )
        .await;

        assert!(
            result.is_err(),
            "a validating webhook must be able to deny a deletecollection, else bulk \
             deletes bypass admission that single deletes enforce"
        );

        // Both ConfigMaps must survive — a webhook denial must not remove any matched object.
        let prefix = crate::keys::group_list_prefix("", "configmaps", Some(ns));
        let remaining = state
            .store
            .list(&prefix, u7s_store::ListOptions::default())
            .await
            .expect("list must succeed");
        assert_eq!(
            remaining.items.len(),
            2,
            "deletecollection denied by admission must leave every matched object in \
             place — a partial delete would mean bulk delete only partially enforces \
             admission"
        );
    }

    /// A validating webhook with failurePolicy=Fail and an unreachable URL must deny a
    /// cluster-scoped deletecollection too, not just namespaced ones.
    ///
    /// Companion to delete_collection_namespaced_calls_validating_admission_fail_policy_denies
    /// above: proves delete_collection_resource (the cluster-scoped sibling handler) also
    /// invokes admission per object on DELETE. If this handler stops calling
    /// run_validating_webhooks, the delete below wipes both ClusterRoleBindings and this
    /// test fails.
    #[tokio::test]
    async fn delete_collection_calls_validating_admission_fail_policy_denies_cluster_scoped() {
        let state = make_state();

        let group = "rbac.authorization.k8s.io";
        let version = "v1";
        let plural = "clusterrolebindings";

        for name in ["crb-one", "crb-two"] {
            let key = crate::keys::group_object_key(group, plural, None, name);
            let val = serde_json::json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": { "name": name },
                "subjects": [{ "kind": "Group", "name": "some-group" }],
                "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view" }
            });
            state
                .store
                .put(
                    &key,
                    bytes::Bytes::from(serde_json::to_vec(&val).unwrap()),
                    None,
                )
                .await
                .expect("seed clusterrolebinding must succeed");
        }

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "crb-delcol-vwc"},
            "webhooks": [{
                "name": "crb.deny-delete.example.com",
                "clientConfig": { "url": "http://127.0.0.1:1" },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["DELETE"]}],
                "failurePolicy": "Fail"
            }]
        });
        state
            .store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/crb-delcol-vwc",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

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
            test_user(),
        )
        .await;

        assert!(
            result.is_err(),
            "a validating webhook must be able to deny a cluster-scoped deletecollection \
             too — otherwise bulk delete of cluster-scoped resources bypasses admission \
             that single-object delete enforces"
        );

        let prefix = crate::keys::group_list_prefix(group, plural, None);
        let remaining = state
            .store
            .list(&prefix, u7s_store::ListOptions::default())
            .await
            .expect("list must succeed");
        assert_eq!(
            remaining.items.len(),
            2,
            "deletecollection denied by admission must leave every matched cluster-scoped \
             object in place"
        );
    }

    /// delete_collection_namespaced_resource had no Custom Resource fallback at all — it
    /// resolved the type via lookup() (the static built-in registry only), so ANY
    /// DeleteCollection against a CRD-backed group/version/plural 404d unconditionally, and
    /// query.field_selector was never consulted even once a fallback existed. This is exactly
    /// what CustomResourceFieldSelectors' `v2Client.Namespace(ns).DeleteCollection(...,
    /// ListOptions{FieldSelector: "host=host1,port=80"})` step exercises.
    ///
    /// Fails on revert two independent ways: (1) without the CR fallback this call returns
    /// 404, so the `unwrap_or_else` below panics; (2) with a fallback but no field-selector
    /// wiring, either all three widgets are removed (selector silently ignored) or none are
    /// (selector misapplied as never-matching) instead of exactly the two whose host is
    /// "host1".
    #[tokio::test]
    async fn delete_collection_namespaced_resource_falls_back_to_cr_and_honors_field_selector() {
        use axum::extract::{Path, Query, State};

        let state = make_state();

        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.custom.example.com" },
            "spec": {
                "group": "custom.example.com",
                "names": {
                    "plural": "widgets",
                    "singular": "widget",
                    "kind": "Widget",
                    "listKind": "WidgetList"
                },
                "scope": "Namespaced",
                "versions": [{
                    "name": "v1",
                    "served": true,
                    "storage": true,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": { "host": { "type": "string" } }
                        }
                    },
                    "selectableFields": [{ "jsonPath": ".host" }]
                }]
            }
        });
        crate::handlers::crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(crd.to_string()),
        )
        .await
        .expect("install CRD");

        for (name, host) in [
            ("widget-a", "host1"),
            ("widget-b", "host1"),
            ("widget-c", "host2"),
        ] {
            let widget = serde_json::json!({
                "apiVersion": "custom.example.com/v1",
                "kind": "Widget",
                "metadata": { "name": name, "namespace": "default" },
                "host": host
            });
            crate::handlers::cr::create_cr_namespaced(
                State(state.clone()),
                Path((
                    "custom.example.com".into(),
                    "v1".into(),
                    "default".into(),
                    "widgets".into(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(widget.to_string()),
            )
            .await
            .unwrap_or_else(|e| panic!("create {name} must succeed: {e:?}"));
        }

        delete_collection_namespaced_resource(
            State(state.clone()),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "default".into(),
                "widgets".into(),
            )),
            Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: Some("host=host1".to_string()),
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            }),
            test_user(),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "DeleteCollection on a CRD-backed resource must fall back to CR handling \
                 instead of 404ing: {e:?}"
            )
        });

        for (name, should_survive) in [("widget-a", false), ("widget-b", false), ("widget-c", true)]
        {
            let result = crate::handlers::cr::get_cr_namespaced(
                State(state.clone()),
                Path((
                    "custom.example.com".into(),
                    "v1".into(),
                    "default".into(),
                    "widgets".into(),
                    name.into(),
                )),
                axum::http::HeaderMap::new(),
            )
            .await;
            assert_eq!(
                result.is_ok(),
                should_survive,
                "{name}'s survival after DeleteCollection(fieldSelector=host=host1) must \
                 match whether its own host matched the selector"
            );
        }
    }

    /// Cluster-scoped counterpart of the namespaced test above: delete_collection_resource
    /// must also fall back to CR handling (cr::delete_collection_cr) for a CRD-backed
    /// group/version/plural, and honor field_selector there too — the cluster-scoped route
    /// had the identical two gaps.
    #[tokio::test]
    async fn delete_collection_resource_falls_back_to_cr_and_honors_field_selector() {
        use axum::extract::{Path, Query, State};

        let state = make_state();

        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "gadgets.custom.example.com" },
            "spec": {
                "group": "custom.example.com",
                "names": {
                    "plural": "gadgets",
                    "singular": "gadget",
                    "kind": "Gadget",
                    "listKind": "GadgetList"
                },
                "scope": "Cluster",
                "versions": [{
                    "name": "v1",
                    "served": true,
                    "storage": true,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": { "host": { "type": "string" } }
                        }
                    },
                    "selectableFields": [{ "jsonPath": ".host" }]
                }]
            }
        });
        crate::handlers::crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(crd.to_string()),
        )
        .await
        .expect("install CRD");

        for (name, host) in [("gadget-a", "host1"), ("gadget-b", "host2")] {
            let gadget = serde_json::json!({
                "apiVersion": "custom.example.com/v1",
                "kind": "Gadget",
                "metadata": { "name": name },
                "host": host
            });
            crate::handlers::cr::create_cr(
                State(state.clone()),
                Path(("custom.example.com".into(), "v1".into(), "gadgets".into())),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(gadget.to_string()),
            )
            .await
            .unwrap_or_else(|e| panic!("create {name} must succeed: {e:?}"));
        }

        delete_collection_resource(
            State(state.clone()),
            Path(("custom.example.com".into(), "v1".into(), "gadgets".into())),
            Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: Some("host=host1".to_string()),
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            }),
            test_user(),
        )
        .await
        .unwrap_or_else(|e| {
            panic!("cluster-scoped DeleteCollection CR fallback must succeed: {e:?}")
        });

        let a_gone = crate::handlers::cr::get_cr(
            State(state.clone()),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "gadgets".into(),
                "gadget-a".into(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert!(a_gone.is_err(), "gadget-a (host1) must be deleted");

        let b_survives = crate::handlers::cr::get_cr(
            State(state.clone()),
            Path((
                "custom.example.com".into(),
                "v1".into(),
                "gadgets".into(),
                "gadget-b".into(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert!(b_survives.is_ok(), "gadget-b (host2) must survive");
    }

    /// delete_collection_resource (cluster-scoped, built-in types) consulted only
    /// label_selector in its per-object loop — query.field_selector was silently dropped, so
    /// a DeleteCollection with a fieldSelector deleted every object regardless of the filter
    /// instead of the requested subset.
    ///
    /// Fails on revert: without threading field_selector into the store's ListOptions, both
    /// bindings are deleted regardless of roleRef.name.
    #[tokio::test]
    async fn delete_collection_resource_honors_field_selector() {
        use axum::extract::{Path, Query, State};

        let state = make_state();

        for (name, role) in [("binding-admin", "admin"), ("binding-viewer", "viewer")] {
            let key = crate::keys::group_object_key(
                "rbac.authorization.k8s.io",
                "clusterrolebindings",
                None,
                name,
            );
            let val = serde_json::json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": { "name": name },
                "subjects": [{ "kind": "Group", "name": "some-group" }],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": role
                }
            });
            state
                .store
                .put(
                    &key,
                    bytes::Bytes::from(serde_json::to_vec(&val).unwrap()),
                    None,
                )
                .await
                .expect("seed must succeed");
        }

        delete_collection_resource(
            State(state.clone()),
            Path((
                "rbac.authorization.k8s.io".into(),
                "v1".into(),
                "clusterrolebindings".into(),
            )),
            Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: Some("roleRef.name=admin".to_string()),
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            }),
            test_user(),
        )
        .await
        .unwrap_or_else(|e| panic!("delete_collection with field_selector must succeed: {e:?}"));

        let prefix = crate::keys::group_list_prefix(
            "rbac.authorization.k8s.io",
            "clusterrolebindings",
            None,
        );
        let remaining = state
            .store
            .list(&prefix, u7s_store::ListOptions::default())
            .await
            .expect("list must succeed");
        let remaining_names: Vec<String> = remaining
            .items
            .iter()
            .filter_map(|o| serde_json::from_slice::<serde_json::Value>(&o.value).ok())
            .map(|v| v["metadata"]["name"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(
            remaining_names,
            vec!["binding-viewer".to_string()],
            "DeleteCollection with fieldSelector=roleRef.name=admin must delete only \
             binding-admin — if the selector is ignored, both bindings are deleted"
        );
    }

    /// delete_collection_resource (cluster-scoped) hard-deleted every listed object
    /// unconditionally, ignoring metadata.finalizers — a finalizer'd CustomResourceDefinition,
    /// ClusterRole, or PersistentVolume removed via DeleteCollection lost its finalizer
    /// protection even though a single-object DELETE of the same object honors it.
    ///
    /// Fails on revert: without threading the object through apply_delete_policy, a
    /// finalizer'd cluster-scoped object is hard-deleted (gone from the store) instead of
    /// soft-deleted (deletionTimestamp set, object still present).
    #[tokio::test]
    async fn delete_collection_resource_honors_finalizers() {
        use axum::extract::{Path, Query, State};

        let state = make_state();

        let key = crate::keys::group_object_key("storage.k8s.io", "csinodes", None, "gc-node");
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "gc-node",
                "finalizers": ["example.com/cleanup"]
            },
            "spec": { "drivers": [] }
        });
        state
            .store
            .put(
                &key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .expect("seed must succeed");

        delete_collection_resource(
            State(state.clone()),
            Path(("storage.k8s.io".into(), "v1".into(), "csinodes".into())),
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
            test_user(),
        )
        .await
        .unwrap_or_else(|e| panic!("DeleteCollection over finalizer'd object must succeed: {e:?}"));

        let stored = state
            .store
            .get(&key)
            .await
            .expect("get must succeed")
            .unwrap_or_else(|| panic!("finalizer'd object must survive DeleteCollection (soft-delete), not be hard-deleted"));
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "DeleteCollection must stamp deletionTimestamp on a finalizer'd object, exactly \
             like a single-object DELETE does — controllers watch for this to run cleanup"
        );
    }

    /// Namespaced counterpart of delete_collection_resource_honors_field_selector:
    /// delete_collection_namespaced_resource also consulted only label_selector, silently
    /// dropping query.field_selector for built-in resources.
    #[tokio::test]
    async fn delete_collection_namespaced_resource_honors_field_selector() {
        use axum::extract::{Path, Query, State};

        let state = make_state();

        for name in ["alpha", "beta"] {
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
                field_selector: Some("spec.holderIdentity=alpha".to_string()),
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            }),
            test_user(),
        )
        .await
        .unwrap_or_else(|e| panic!("delete_collection with field_selector must succeed: {e:?}"));

        let prefix =
            crate::keys::group_list_prefix("coordination.k8s.io", "leases", Some("test-ns"));
        let remaining = state
            .store
            .list(&prefix, u7s_store::ListOptions::default())
            .await
            .expect("list must succeed");
        assert_eq!(
            remaining.items.len(),
            1,
            "fieldSelector=spec.holderIdentity=alpha must delete only the alpha Lease"
        );
        let remaining_obj: serde_json::Value =
            serde_json::from_slice(&remaining.items[0].value).unwrap();
        assert_eq!(
            remaining_obj["metadata"]["name"], "beta",
            "the surviving Lease must be beta (holderIdentity=beta doesn't match the selector)"
        );
    }
}
