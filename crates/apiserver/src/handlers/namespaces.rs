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
    handlers::{
        generic::apply_delete_policy,
        json_patch::{
            apply_json_patch, detect_patch_type, is_dry_run_header, ssa_body_to_json, PatchQuery,
            PatchType,
        },
        resource::{do_patch, PatchConfig},
    },
    keys::{cluster_list_prefix, cluster_object_key},
    proto,
    state::AppState,
    status::Status,
    types::{DeleteOptions, NamespaceSpec, Object, ObjectMeta, ResourceMeta},
    util::{
        content_type, extract_body, extract_body_quiet, parse_resource_version, utc_now_rfc3339,
    },
};

fn store_err_to_status(err: StoreError, name: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found("", "namespaces", name),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, "Namespace"),
        StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "Namespace \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => Status::internal(other.to_string()),
    }
}

pub(crate) async fn list_namespaces<S: Store>(
    State(state): State<AppState<S>>,
    Query(query): Query<super::generic::CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    let prefix = cluster_list_prefix("namespaces");
    let field_selector = super::field_selector::FieldSelector::parse(
        query.field_selector.as_deref(),
        "",
        "namespaces",
    )?;

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
        .list(
            &prefix,
            ListOptions {
                field_selector: field_selector.store_selector(),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // A plain (non-watch) `kubectl get namespaces --field-selector=status.phase=Terminating`
    // must filter like the watch does, so evaluate against the defaulted object.
    let mut items = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        if field_selector.matches_defaulted("", "namespaces", &v) {
            items.push(v);
        }
    }

    let body = serde_json::json!({
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items
    });

    Ok(Json(body).into_response())
}

pub(crate) async fn create_namespace<S: Store>(
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

    let name =
        crate::handlers::generic::resolve_valid_name(&mut obj, "", "namespaces", "Namespace")?;

    // Ensure kind/apiVersion are set
    if obj.body.get("kind").is_none() {
        obj.body["kind"] = serde_json::Value::String("Namespace".into());
    }
    if obj.body.get("apiVersion").is_none() {
        obj.body["apiVersion"] = serde_json::Value::String("v1".into());
    }
    // Reject a scalar/array client status at typed decode (400), then discard whatever the
    // client sent — matches upstream's unconditional PrepareForCreate wipe (see
    // clear_create_status's doc comment). status.phase=Active is then set by apply_defaults,
    // the same defaulter the SSA create-on-missing path (do_patch) uses — see its
    // "namespaces" branch.
    crate::handlers::generic::clear_create_status(true, "v1", "Namespace", &mut obj.body)?;
    crate::handlers::defaults::apply_defaults("", "namespaces", &mut obj.body);

    crate::handlers::defaults::prepare_namespace_for_create(&mut obj.body)
        .map_err(Status::internal)?;

    // Assign a UID if none provided — required for owner references and garbage collection.
    {
        let meta: ObjectMeta = ObjectMeta::deserialize(&obj.body["metadata"]).unwrap_or_default();
        if meta.uid.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
            obj.body["metadata"]["uid"] =
                serde_json::Value::String(uuid::Uuid::new_v4().to_string());
        }
    }

    obj.body["metadata"]["creationTimestamp"] = serde_json::Value::String(utc_now_rfc3339());

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
            "extra": user.extra,
        })),
        dry_run: is_dry_run_header(&headers),
    };
    obj.body = run_mutating_webhooks(&state, obj.body, None, &admission_ctx).await?;
    // Re-clear status after mutating webhooks — see create_resource's identical call
    // (resource.rs) for why: a webhook can reinject a forged/scalar status the earlier
    // clear_create_status already stripped, and this is the last point before
    // persistence that can discard it.
    crate::handlers::generic::clear_create_status(true, "v1", "Namespace", &mut obj.body)?;
    crate::handlers::defaults::apply_defaults("", "namespaces", &mut obj.body);
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;
    crate::field_manager::WriteIdentity::new(None, &headers).record(
        &serde_json::Value::Null,
        &mut obj.body,
        "v1",
        None,
        None,
    );

    // Dry-run: validation and admission passed; return the would-be created namespace
    // without persisting — mirrors create_resource's dry-run early-return in resource.rs.
    // Also skips the kube-root-ca.crt seed below, which is itself a store write.
    if is_dry_run_header(&headers) {
        return Ok((StatusCode::CREATED, Json(obj.body)));
    }

    let key = cluster_object_key("namespaces", &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), Some(0))
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    seed_root_ca_configmap(&state, &name).await;

    Ok((StatusCode::CREATED, Json(obj.body)))
}

/// Seed kube-root-ca.crt synchronously so a pod admitted into a new namespace
/// immediately after creation never races KCM's root-ca-cert-publisher for it.
/// Upstream, the publisher creates this ConfigMap asynchronously on its own
/// reconcile loop; a pod can be created (and its SA token volume admitted)
/// before that reconcile fires, and the kubelet then fails to mount the
/// projected volume with "configmap kube-root-ca.crt not found", hanging the
/// pod forever. KCM's publisher still POSTs its own copy later — that becomes
/// a 409 which the generic create-conflict path already handles.
pub(crate) async fn seed_root_ca_configmap<S: Store>(state: &AppState<S>, name: &str) {
    if let Some(ca_der) = state.cluster_ca_der.as_deref() {
        let cm_key = crate::keys::object_key("configmaps", name, "kube-root-ca.crt");
        let ca_pem =
            String::from_utf8_lossy(&crate::tls::pem_encode("CERTIFICATE", ca_der)).into_owned();
        let cm_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "kube-root-ca.crt", "namespace": name },
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
}

pub(crate) async fn get_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
) -> Result<Response, crate::status::StatusError> {
    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found("", "namespaces", &name))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

/// Bound on re-read-and-retry attempts when an unconditional PUT (no client resourceVersion)
/// loses a write race, as upstream GuaranteedUpdate does.
const MAX_REPLACE_CONFLICT_RETRIES: u32 = 5;

/// A PUT without a resourceVersion must still be conditioned on the revision just read, or a
/// DELETE landing between that read and the write would be undone by an unconditional put
/// recreating the namespace without its finalizers.
fn replace_put_precondition(client_rv: Option<u64>, stored_rv: Option<u64>) -> Option<u64> {
    client_rv.or(stored_rv)
}

pub(crate) async fn replace_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct)?;
    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj.name().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let expected_revision = parse_resource_version(obj.resource_version())?;
    let key = cluster_object_key("namespaces", &name);

    // Namespace has a dedicated /status subresource (has_status_subresource=true, see
    // patch_namespace below) — a plain PUT to this main endpoint must not let the client's
    // body (a stale client-go cache, a metadata-only kubectl replace, ...) clobber
    // status.phase/status.conditions that the real namespace controller last wrote via
    // /status. Mirrors replace_pod's stored_status handling and the generic
    // replace_namespaced_resource in resource.rs.
    let original_body = obj.body.clone();
    let mut attempt = 0u32;
    let new_rv = loop {
        attempt += 1;
        obj.body = original_body.clone();
        let stored_entry = state
            .store
            .get(&key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let stored_revision = stored_entry.as_ref().map(|s| s.revision);
        let stored_obj = stored_entry
            .and_then(|stored| serde_json::from_slice::<serde_json::Value>(&stored.value).ok());
        // Upstream disallows create-on-update for Namespace; creating here would skip the create
        // preparation (spec.finalizers), so a later delete would orphan the namespace's content.
        if stored_obj.is_none() {
            return Err(Status::not_found("", "namespaces", &name));
        }
        let stored_status = stored_obj.as_ref().map(|v| v["status"].clone());
        match stored_status {
            Some(ref s) if !s.is_null() => {
                obj.body["status"] = s.clone();
            }
            _ => {
                obj.body.as_object_mut().map(|m| m.remove("status"));
            }
        }

        // metadata.uid is immutable identity, exactly like the generic replace_namespaced_resource
        // path (resource.rs): a blank incoming uid is restored from the stored object, but a
        // non-blank incoming uid that mismatches the stored one is identity forgery, not a
        // legitimate update — allowing it would let a client forge a match against a stale/foreign
        // ownerReference (corrupting the garbage collector's cascade-GC decision) or defeat
        // controllers' "same name, different uid ⇒ different object" recreate-detection. Namespace
        // routes around the generic path entirely (bespoke handler), so it never got 2pzru's fix.
        let stored_uid = stored_obj.as_ref().map(|v| v["metadata"]["uid"].clone());
        let incoming_uid_blank = obj.body["metadata"]["uid"]
            .as_str()
            .map(str::is_empty)
            .unwrap_or(true);
        if incoming_uid_blank {
            if let Some(uid) = stored_uid.as_ref().and_then(|u| u.as_str()) {
                if !uid.is_empty() {
                    obj.body["metadata"]["uid"] = serde_json::Value::String(uid.to_string());
                }
            }
        } else if let Some(stored_uid_str) = stored_uid
            .as_ref()
            .and_then(|u| u.as_str())
            .filter(|s| !s.is_empty())
        {
            let incoming_uid_str = obj.body["metadata"]["uid"].as_str().unwrap_or("");
            if incoming_uid_str != stored_uid_str {
                return Err(Status::conflict(format!(
                    "Namespace \"{name}\": the object was updated with a mismatched uid \
                 (got {incoming_uid_str}, expected {stored_uid_str}) — uid is immutable"
                )));
            }
        }

        // Admission webhook pipeline (mutating then validating), threading the pre-existing
        // namespace as oldObject — mirrors create_namespace's CREATE call above. Previously
        // replace_namespace called neither hook at all, so a webhook registered for
        // namespaces/UPDATE was silently skipped on every PUT.
        let admission_ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "namespaces",
            name: &name,
            namespace: None,
            operation: "UPDATE",
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
                "extra": user.extra,
            })),
            dry_run: is_dry_run_header(&headers),
        };
        obj.body =
            run_mutating_webhooks(&state, obj.body, stored_obj.as_ref(), &admission_ctx).await?;

        // Re-restore status after mutating webhooks — a webhook's JSON patch can reinject a
        // forged/scalar status the earlier restore already discarded, and this is the last point
        // before persistence that can discard it again. Mirrors do_patch's (resource.rs) identical
        // post-webhook re-restore on its generic PATCH/PUT-onto-live-object path.
        match stored_status {
            Some(ref s) if !s.is_null() => {
                obj.body["status"] = s.clone();
            }
            _ => {
                obj.body.as_object_mut().map(|m| m.remove("status"));
            }
        }

        run_validating_webhooks(&state, &obj.body, stored_obj.as_ref(), &admission_ctx).await?;
        crate::field_manager::WriteIdentity::new(None, &headers).record(
            stored_obj.as_ref().unwrap_or(&serde_json::Value::Null),
            &mut obj.body,
            "v1",
            None,
            None,
        );

        // Dry-run: return the would-be replaced object without persisting — mirrors
        // create_namespace's dry-run early-return (is_dry_run_header is the router-wide
        // ?dryRun=All signal for handlers, like this one, with no Query<...> extractor of
        // their own).
        if is_dry_run_header(&headers) {
            return Ok(Json(obj.body).into_response());
        }

        match state
            .store
            .put(
                &key,
                obj.to_bytes(),
                replace_put_precondition(expected_revision, stored_revision),
            )
            .await
        {
            Ok(rv) => break rv,
            // Upstream GuaranteedUpdate re-reads and retries an unconditional update on conflict.
            Err(StoreError::RevisionMismatch { .. })
                if expected_revision.is_none() && attempt < MAX_REPLACE_CONFLICT_RETRIES => {}
            Err(e) => return Err(store_err_to_status(e, &name)),
        }
    };

    obj.set_resource_version(new_rv);

    let replace_meta: ObjectMeta =
        ObjectMeta::deserialize(&obj.body["metadata"]).unwrap_or_default();
    let deletion_ts_set = replace_meta.deletion_timestamp.is_some();
    let replace_spec: NamespaceSpec =
        NamespaceSpec::deserialize(&obj.body["spec"]).unwrap_or_default();
    let finalizers_empty = replace_spec
        .finalizers
        .as_deref()
        .map(|f| f.is_empty())
        .unwrap_or(true);
    if deletion_ts_set && finalizers_empty {
        delete_finalized_namespace(&state, &name).await;
    }

    Ok(Json(obj.body).into_response())
}

pub(crate) async fn patch_namespace<S: Store>(
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
                user_agent: crate::handlers::json_patch::user_agent(&headers),
                force: patch_query.force.unwrap_or(false),
                patch_type: PatchType::StrategicMerge,
                body,
                dry_run: patch_query.is_dry_run(),
                user_info: Some(serde_json::json!({
                    "username": user.username,
                    "uid": user.uid,
                    "groups": user.groups,
                    "extra": user.extra,
                })),
                user: &user,
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
        .ok_or_else(|| Status::not_found("", "namespaces", &name))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // Snapshotted before the patch mutates current.body in place below — the only pre-patch
    // copy available to pass as oldObject to the admission webhooks.
    let pre_patch_obj = current.body.clone();

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // metadata.uid is immutable identity, restored unconditionally after the patch is
    // applied — exactly like do_patch (resource.rs) already does for the generic path. This
    // branch applies the merge-patch directly to the full stored object body (including
    // metadata.uid) with no other uid handling, so without this a caller holding only
    // ordinary namespace `patch` rights could forge uid to match a stale/foreign
    // ownerReference and corrupt the garbage collector's cascade-GC decision.
    let stored_uid = current.body["metadata"]["uid"].clone();

    // Snapshot .status before applying the patch: Namespace has a dedicated /status
    // subresource, so a patch on this main endpoint (merge or strategic-merge — both content
    // types share this branch, see the ct check above) must never change it — restored below,
    // mirroring do_patch's (resource.rs) identical stored_status handling. Without this, a
    // caller holding only ordinary namespace `patch` rights (not `namespaces/status`) could
    // persist a scalar status via `{"status":"x"}`, corrupting the object and later panicking
    // any in-place status stamper (e.g. stamp_terminating) that indexes it with a str key.
    let stored_status = current.body["status"].clone();

    crate::patch::merge_patch(&mut current.body, &patch);

    current.body["metadata"]["uid"] = stored_uid;
    super::json_patch::enforce_patch_identity(&mut current.body, &name, None)?;

    if stored_status.is_null() {
        current.body.as_object_mut().map(|m| m.remove("status"));
    } else {
        current.body["status"] = stored_status.clone();
    }

    // Admission webhook pipeline (mutating then validating), threading the pre-patch stored
    // namespace as oldObject — mirrors replace_namespace's UPDATE call. The SSA branch above
    // already gets webhooks for free via do_patch; this merge/strategic-merge branch has its
    // own store.put and previously called neither hook at all.
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "namespaces",
        name: &name,
        namespace: None,
        operation: "UPDATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: patch_query.is_dry_run(),
    };
    current.body =
        run_mutating_webhooks(&state, current.body, Some(&pre_patch_obj), &admission_ctx).await?;

    // Re-restore status after mutating webhooks — a webhook's JSON patch can reinject a
    // forged/scalar status the earlier restore already discarded, and this is the last point
    // before persistence that can discard it again. Mirrors do_patch's (resource.rs) identical
    // post-webhook re-restore on its generic PATCH/PUT-onto-live-object path.
    if stored_status.is_null() {
        current.body.as_object_mut().map(|m| m.remove("status"));
    } else {
        current.body["status"] = stored_status;
    }

    run_validating_webhooks(&state, &current.body, Some(&pre_patch_obj), &admission_ctx).await?;
    crate::field_manager::WriteIdentity::new(None, &headers).record(
        &pre_patch_obj,
        &mut current.body,
        "v1",
        None,
        None,
    );

    // Post-patch: if deletionTimestamp is set and spec.finalizers are empty, hard-delete.
    let current_meta: ObjectMeta =
        ObjectMeta::deserialize(&current.body["metadata"]).unwrap_or_default();
    let deletion_ts_set = current_meta.deletion_timestamp.is_some();
    let patch_spec: NamespaceSpec =
        NamespaceSpec::deserialize(&current.body["spec"]).unwrap_or_default();
    let finalizers_empty = patch_spec
        .finalizers
        .as_deref()
        .map(|f| f.is_empty())
        .unwrap_or(true);

    // Dry-run: return the would-be patched object without persisting — mirrors do_patch's
    // dry-run early-return, which the SSA branch above already gets for free but this
    // merge/strategic-merge branch has its own store.put and needed its own guard.
    if patch_query.is_dry_run() {
        return Ok(Json(current.body).into_response());
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current.set_resource_version(new_rv);

    if deletion_ts_set && finalizers_empty {
        delete_finalized_namespace(&state, &name).await;
    }

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
pub(crate) async fn finalize_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = crate::util::extract_body(&body, ct)?;

    // Parse the finalizers from the request body.
    // KCM sends the finalizers in spec.finalizers. We also accept metadata.finalizers
    // as a fallback for clients that write the field in standard metadata position.
    let req: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // KCM writes spec.finalizers; fall back to metadata.finalizers.
    let new_finalizers: Option<Vec<String>> =
        if !req["spec"]["finalizers"].is_null() && req["spec"].get("finalizers").is_some() {
            Option::deserialize(&req["spec"]["finalizers"]).unwrap_or_default()
        } else {
            Option::deserialize(&req["metadata"]["finalizers"]).unwrap_or_default()
        };

    // Fetch the current namespace from the store.
    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found("", "namespaces", &name))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // Namespace finalizers live in spec.finalizers (not metadata.finalizers).
    let mut spec: NamespaceSpec =
        NamespaceSpec::deserialize(&current.body["spec"]).unwrap_or_default();
    spec.finalizers = new_finalizers;
    let before_write = current.body.clone();
    current.body["spec"] = serde_json::to_value(&spec)
        .map_err(|e| Status::internal(format!("failed to serialize NamespaceSpec: {e}")))?;
    crate::field_manager::WriteIdentity::new(None, &headers).record(
        &before_write,
        &mut current.body,
        "v1",
        Some("finalize"),
        None,
    );

    // Check: if deletionTimestamp is set and spec.finalizers are now empty → hard-delete.
    let current_meta: ObjectMeta =
        ObjectMeta::deserialize(&current.body["metadata"]).unwrap_or_default();
    let deletion_ts_set = current_meta.deletion_timestamp.is_some();
    let current_spec: NamespaceSpec =
        NamespaceSpec::deserialize(&current.body["spec"]).unwrap_or_default();
    let finalizers_empty = current_spec
        .finalizers
        .as_deref()
        .map(|f| f.is_empty())
        .unwrap_or(true);

    // Dry-run: return the would-be finalized namespace without persisting — mirrors
    // replace_namespace's dry-run early-return above.
    if is_dry_run_header(&headers) {
        return Ok(Json(current.body).into_response());
    }

    // Persist the updated object first.
    // CAS on the INCOMING request's resourceVersion, not the stored object's: /finalize is
    // a replace subresource, so a client holding a stale snapshot must get 409 and retry
    // rather than clobber a concurrent write. Absent rv stays unconditional (returns None).
    let incoming_meta: ObjectMeta = ObjectMeta::deserialize(&req["metadata"]).unwrap_or_default();
    let expected_rv = parse_resource_version(incoming_meta.resource_version.as_deref())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current.set_resource_version(new_rv);

    if deletion_ts_set && finalizers_empty {
        delete_finalized_namespace(&state, &name).await;
    }

    Ok(Json(current.body).into_response())
}

/// GET /api/v1/namespaces/{name}/status
///
/// Returns the full namespace object. Status is embedded, not a separate subresource store.
pub(crate) async fn get_namespace_status<S: Store>(
    state: State<AppState<S>>,
    Path(name): Path<String>,
) -> Result<Response, crate::status::StatusError> {
    get_namespace(state, Path(name)).await
}

/// PUT /api/v1/namespaces/{name}/status
///
/// Replaces only the status field of a namespace. The KCM namespace controller calls this
/// to set status.conditions (e.g. NamespaceDeletionContentFailure) during namespace deletion.
pub(crate) async fn put_namespace_status<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct)?;
    let incoming =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found("", "namespaces", &name))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let before_write = current.body.clone();
    match &incoming.body["status"] {
        serde_json::Value::Null => {
            current.body.as_object_mut().map(|m| m.remove("status"));
        }
        v => {
            current.body["status"] =
                crate::status_dispatch::decode_status_put("v1", "Namespace", v)
                    .expect("Namespace is always registered in status_dispatch")?;
        }
    }

    crate::handlers::status::merge_incoming_metadata(
        &mut current.body,
        &incoming.body,
        "Namespace",
    );

    super::status::record_status_write(&headers, &before_write, &mut current.body, "", "v1");

    // Dry-run: return the would-be status object without persisting — mirrors
    // put_resource_status's dry-run early-return.
    if is_dry_run_header(&headers) {
        return Ok(Json(current.body));
    }

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
pub(crate) async fn patch_namespace_status<S: Store>(
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
        .ok_or_else(|| Status::not_found("", "namespaces", &name))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let before_write = current.body.clone();

    // apply-patch+yaml bodies are genuine YAML (e.g. kubectl apply --server-side status);
    // every other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
    };
    crate::handlers::status::reject_patch_identity_mismatch(&patch, &name, Some(&name))?;

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
            crate::handlers::status::merge_incoming_metadata(
                &mut current.body,
                &patch,
                "Namespace",
            );
        }
    }
    // Convergence point for every patch content-type above (JSON Patch, merge, strategic
    // merge): guard once here, right before the store write, instead of per-branch — this
    // handler previously guarded neither branch, so a merge-patch or JSON Patch `/status`
    // replace could persist a scalar status and later panic the in-place terminating-stamp.
    // `null` bypasses the check (RFC 7396 field deletion is legal regardless of typed shape,
    // and the codec has no null case to decode into). Namespace is unconditionally
    // registered in status_dispatch, so `decode_status_patch` never actually misses here —
    // it also fails on a wrong-typed enumerated field (e.g. `status.phase: 5`), which a bare
    // object-shape check can't see.
    if !current.body["status"].is_null() {
        match crate::status_dispatch::decode_status_patch(
            "v1",
            "Namespace",
            &current.body["status"],
        ) {
            Some(result) => {
                result?;
            }
            None => crate::handlers::status::reject_non_object_status(&current.body["status"])?,
        }
    }

    super::status::record_status_write(&headers, &before_write, &mut current.body, "", "v1");

    // Dry-run: same convergence point as reject_non_object_status above — return the
    // would-be patched status object without persisting.
    if is_dry_run_header(&headers) {
        return Ok(Json(current.body));
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

/// Remove a Terminating namespace whose `spec.finalizers` just went empty, as upstream's
/// namespace REST does in the same write. Content is never touched: the namespace controller
/// only empties `spec.finalizers` after its own drain, and every deletion it issued went
/// through the object's own DELETE path.
async fn delete_finalized_namespace<S: Store>(state: &AppState<S>, name: &str) {
    let key = cluster_object_key("namespaces", name);
    let _ = state.store.delete(&key, None).await;
    state.quota_admission_locks.evict(name);
}

pub(crate) async fn delete_namespace<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let key = cluster_object_key("namespaces", &name);

    // Fetch current to check finalizers.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found("", "namespaces", &name))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // Parse DeleteOptions from the request body (same pattern as other delete handlers).
    // client-go's typed Delete() sends DryRun in this body; a raw/proxied caller may
    // instead send it as ?dryRun=All (caught by the router-wide inject_dry_run_header
    // layer) — accept either.
    // DeleteOptions parsing is intentionally lenient: a malformed/undecodable body must never
    // block a DELETE, so extract_body_quiet's Err falls back to the original bytes here
    // (matching the pre-existing serde_json::from_slice(...).unwrap_or_default() below) without
    // warning — this path is hit by every real client's protobuf DELETE.
    let body = extract_body_quiet(&body, content_type(&headers)).unwrap_or_else(|_| body.clone());
    let delete_opts: DeleteOptions = if body.is_empty() {
        DeleteOptions::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };
    let dry_run = delete_opts.is_dry_run() || is_dry_run_header(&headers);

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
            "extra": user.extra,
        })),
        dry_run,
    };
    run_validating_webhooks(&state, &obj.body, Some(&obj.body), &admission_ctx).await?;

    if let Some(soft) = apply_delete_policy(&mut obj) {
        // apply_delete_policy already stamped status.phase=Terminating in place
        // (obj.body["status"]["phase"] = ...), preserving every other status field. Rebuilding
        // `soft["status"]` wholesale from a fresh NamespaceStatus here — as this used to do —
        // wiped status.conditions (e.g. NamespaceDeletionContentFailure) on every repeat DELETE
        // of an already-terminating namespace, discarding the real KCM namespace-controller's
        // drain-progress signal that a client polls for.
        obj.body = soft;

        // Dry-run: validation passed and this is what a real DELETE would soft-delete to
        // (status.phase=Terminating); return it without persisting.
        if dry_run {
            return Ok(Json(obj.body).into_response());
        }

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
        // (or anything else) does any further work.
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

        return Ok(Json(obj.body).into_response());
    }

    // Dry-run: no spec.finalizers means a real DELETE removes the namespace immediately;
    // return the would-be Success status without the namespace's own store.delete.
    if dry_run {
        return Ok(Json(serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Success",
            "code": 200
        }))
        .into_response());
    }

    // No spec.finalizers — remove the namespace at once, like upstream's namespace REST
    // Delete. Content is never cascaded here: API-created namespaces always carry
    // "kubernetes", so this is the namespace controller's final DELETE after its own drain.
    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;
    state.quota_admission_locks.evict(&name);

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

    use crate::handlers::test_support::{assert_invalid_name_field, make_state};

    fn generate_name_body(prefix: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "generateName": prefix }
            })
            .to_string(),
        )
    }

    async fn create_ns(
        state: &crate::state::AppState,
        body: Bytes,
    ) -> Result<(), crate::status::StatusError> {
        create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .map(|_| ())
    }

    // A namespace created with a name the read path rejects can never be addressed again, so
    // it can never be deleted or drained and wedges forever. Create must refuse every such
    // name with upstream's 422 Invalid, for explicit names and generateName prefixes alike.
    #[tokio::test]
    async fn create_namespace_refuses_names_the_read_path_rejects() {
        let state = make_state();
        let too_long = "a".repeat(64);
        let bad = [
            "Bad-NS",
            too_long.as_str(),
            "-lead",
            "trail-",
            "has.dot",
            "under_score",
        ];
        for name in bad {
            assert!(
                crate::types::Namespace::parse(name).is_err(),
                "read path must reject {name:?}"
            );
            let err = create_ns(&state, namespace_body(name))
                .await
                .err()
                .unwrap_or_else(|| panic!("create of {name:?} must be refused"));
            assert_invalid_name_field(&err, "metadata.name");
            let body = serde_json::to_value(&err.1).unwrap();
            assert_eq!(body["details"]["kind"], "Namespace");

            // A trailing '-' is a legal generateName prefix (the suffix follows it).
            if name.len() <= 40 && !name.ends_with('-') {
                let err = create_ns(&state, generate_name_body(name))
                    .await
                    .err()
                    .unwrap_or_else(|| panic!("generateName {name:?} must be refused"));
                assert_invalid_name_field(&err, "metadata.generateName");
            }
        }
    }

    // Upstream truncates the generateName base to 58 chars so a valid-length (<=63) prefix
    // always yields a valid name; only a prefix that is itself over the label limit is refused.
    #[tokio::test]
    async fn create_namespace_truncates_generate_name_prefix_instead_of_overflowing() {
        let state = make_state();
        assert!(
            create_ns(&state, generate_name_body(&"a".repeat(62)))
                .await
                .is_ok(),
            "62-char prefix must be truncated to 58 + 5-char suffix, not rejected"
        );
        let err = create_ns(&state, generate_name_body(&"a".repeat(64)))
            .await
            .expect_err("64-char prefix is itself an invalid label");
        assert_invalid_name_field(&err, "metadata.generateName");
    }

    // The guard must not reject legitimate names, including a 63-char boundary name.
    #[tokio::test]
    async fn create_namespace_accepts_valid_label_names() {
        let state = make_state();
        for name in ["kube-test", "a", "ns-1-x", &"a".repeat(63)] {
            assert!(
                create_ns(&state, namespace_body(name)).await.is_ok(),
                "{name:?} is a valid DNS-1123 label"
            );
            assert!(crate::types::Namespace::parse(name).is_ok());
        }
        let resp = create_ns(&state, generate_name_body("gen-")).await;
        assert!(resp.is_ok(), "valid generateName must round-trip");
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

    // The non-watch LIST path used to call state.store.list with ListOptions::default(),
    // dropping query.field_selector entirely — only the watch=true branch ever read it. A
    // user running `kubectl get namespaces --field-selector=status.phase=Terminating` (the
    // exact diagnostic command used to hunt a stuck namespace) got back every namespace,
    // silently defeating the filter. This test fails on revert: without threading
    // field_selector into ListOptions on the plain-LIST branch, both namespaces would come
    // back and the length/name assertions below would fail.
    #[tokio::test]
    async fn list_namespaces_non_watch_honors_field_selector_for_terminating_phase() {
        use axum::body::to_bytes;

        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("term-ns"),
            )
            .await
            .is_ok(),
            "create of term-ns must succeed"
        );
        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("active-ns"),
            )
            .await
            .is_ok(),
            "create of active-ns must succeed"
        );

        // create_namespace auto-stamps the "kubernetes" finalizer, so this soft-deletes
        // term-ns and sets status.phase=Terminating without hard-deleting it — matching
        // how a real cluster's namespace controller leaves a draining namespace visible.
        assert!(
            delete_namespace(
                State(state.clone()),
                Path("term-ns".to_string()),
                test_user(),
                HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .is_ok(),
            "delete of term-ns must not error"
        );

        let query = crate::handlers::generic::CollectionQuery {
            watch: None,
            resource_version: None,
            label_selector: None,
            field_selector: Some("status.phase=Terminating".to_string()),
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        };

        let resp = list_namespaces(State(state), Query(query), test_user())
            .await
            .expect("list with a valid field selector must not error");

        let body_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("response must be valid JSON");
        let names: Vec<&str> = body["items"]
            .as_array()
            .expect("items must be an array")
            .iter()
            .map(|item| item["metadata"]["name"].as_str().unwrap_or(""))
            .collect();

        assert_eq!(
            names,
            vec!["term-ns"],
            "field_selector=status.phase=Terminating must return exactly the Terminating \
             namespace and exclude the Active one — a client filtering for stuck-terminating \
             namespaces must not silently get back the full unfiltered list"
        );
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

    /// A client POSTing a scalar `status` on Namespace create must be rejected (400), not
    /// silently coerced to a default: KCM's ServiceAccount controller and the disruption
    /// controller both index `status.phase`/`status.conditions` as objects, and the terminating
    /// stamp (`generic.rs`) writes into `status` in place — a scalar there is the same
    /// stamper-panic vector the ResourceQuota reconciler has, just for Namespace's own
    /// internal writers.
    #[tokio::test]
    async fn create_namespace_rejects_scalar_status_preventing_stamper_panic() {
        let state = make_state();

        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "evil-ns" },
                "status": "oops"
            })
            .to_string(),
        );

        let err = create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("a scalar status must fail typed decode on create"));

        assert_eq!(
            err.0,
            axum::http::StatusCode::BAD_REQUEST,
            "CREATE with a scalar status is a whole-body typed-decode failure (400)"
        );
        assert!(
            state
                .store
                .get(&crate::keys::cluster_object_key("namespaces", "evil-ns"))
                .await
                .unwrap()
                .is_none(),
            "the rejected create must not have persisted anything"
        );
    }

    /// A client POSTing a validly-shaped but forged `status.phase` (e.g. claiming the
    /// namespace is already Active with no server-side check) must still not have that exact
    /// value trusted — apply_defaults independently re-derives phase=Active on create, so this
    /// mainly proves create_namespace's own status handling doesn't reject a normal object
    /// status outright.
    #[tokio::test]
    async fn create_namespace_sets_active_phase_regardless_of_client_supplied_status() {
        let state = make_state();

        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "phase-test-ns" },
                "status": { "phase": "Terminating" }
            })
            .to_string(),
        );

        create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .unwrap_or_else(|e| panic!("a validly-shaped status must not be rejected: {e:?}"));

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "phase-test-ns",
            ))
            .await
            .unwrap()
            .expect("namespace must have been created");
        let stored_val: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_val["status"]["phase"], "Active",
            "a client claiming Terminating on create must not be trusted — a namespace born \
             Terminating would never let KCM's ServiceAccount controller seed the default SA"
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
                test_user(),
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

    /// `kubectl replace --dry-run=server` on a Namespace must NOT persist the replacement —
    /// a dry-run that writes anyway silently mutates cluster state against the client's
    /// explicit intent. This test fails on revert with the stored labels changed to
    /// `{"env": "prod"}`.
    #[tokio::test]
    async fn replace_namespace_dry_run_does_not_mutate_store() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("dry-run-replace-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored_entry = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "dry-run-replace-ns",
            ))
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

        let replace_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "dry-run-replace-ns",
                    "uid": uid,
                    "resourceVersion": rv,
                    "labels": { "env": "prod" }
                }
            })
            .to_string(),
        );

        let mut dry_run_headers = axum::http::HeaderMap::new();
        dry_run_headers.insert(
            axum::http::HeaderName::from_static(crate::handlers::json_patch::DRY_RUN_HEADER),
            axum::http::HeaderValue::from_static("true"),
        );

        assert!(
            replace_namespace(
                State(state.clone()),
                Path("dry-run-replace-ns".to_string()),
                test_user(),
                dry_run_headers,
                replace_body,
            )
            .await
            .is_ok(),
            "dry-run replace must still return a success response"
        );

        let after = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "dry-run-replace-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("must still exist");
        let body: serde_json::Value = serde_json::from_slice(&after.value).expect("parse after");
        assert!(
            body["metadata"]["labels"]["env"].is_null(),
            "dryRun=All must NOT persist the replacement — if this fails, replace_namespace's \
             dry-run guard was removed and labels.env was actually written to the store"
        );
    }

    // A plain PUT to the main /namespaces endpoint must never let the client body's
    // `.status` clobber the server's stored status: status is owned by the dedicated
    // `/status` subresource (see put_namespace_status), and any client holding a locally
    // cached copy (client-go Update(), kubectl replace, a controller's informer cache)
    // commonly carries stale status.phase. Regression this guards against: the real
    // namespace controller sets status.phase=Terminating via /status mid-drain, then a
    // concurrent metadata-only PUT from a client still holding an Active snapshot would
    // silently resurrect the namespace as Active — breaking the drain and letting
    // create_namespaced_resource's Terminating-namespace rejection be bypassed. Also
    // verifies that simply omitting `status` from the PUT body (the common case) does
    // not wipe it either. This test fails if replace_namespace stops restoring the
    // stored status before writing.
    #[tokio::test]
    async fn replace_namespace_ignores_body_status_uses_stored_status() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("status-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Set status.phase=Terminating via the /status subresource, as the real
        // namespace controller does mid-drain.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "status-ns"))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored_val: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored");
        let rv = stored_val["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("1")
            .to_string();
        let uid = stored_val["metadata"]["uid"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "status-ns", "resourceVersion": rv },
                "status": { "phase": "Terminating" }
            })
            .to_string(),
        );
        assert!(
            put_namespace_status(
                State(state.clone()),
                Path("status-ns".to_string()),
                axum::http::HeaderMap::new(),
                status_body,
            )
            .await
            .is_ok(),
            "put_namespace_status must succeed"
        );

        // A client PUTs to the main endpoint carrying a stale/bogus status (Active) in
        // the body — e.g. a client-go Update() built from a local cache predating the
        // drain.
        let fetch_rv_and_uid = |v: &serde_json::Value| {
            (
                v["metadata"]["resourceVersion"]
                    .as_str()
                    .unwrap_or("1")
                    .to_string(),
                v["metadata"]["uid"].as_str().unwrap_or("").to_string(),
            )
        };
        let after_status = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "status-ns"))
            .await
            .expect("store get")
            .expect("must exist");
        let after_status_val: serde_json::Value =
            serde_json::from_slice(&after_status.value).expect("parse");
        let (rv2, uid2) = fetch_rv_and_uid(&after_status_val);
        assert_eq!(uid2, uid, "uid must be stable across the /status write");

        let put_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "status-ns",
                    "uid": uid2,
                    "resourceVersion": rv2,
                    "labels": { "env": "prod" }
                },
                "status": { "phase": "Active" }
            })
            .to_string(),
        );

        assert!(
            replace_namespace(
                State(state.clone()),
                Path("status-ns".to_string()),
                test_user(),
                axum::http::HeaderMap::new(),
                put_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        let after_bogus_status = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "status-ns"))
            .await
            .expect("store get")
            .expect("must still exist");
        let after_bogus_val: serde_json::Value =
            serde_json::from_slice(&after_bogus_status.value).expect("parse final");
        assert_eq!(
            after_bogus_val["status"]["phase"], "Terminating",
            "PUT body status (Active) must be ignored; stored status (Terminating) set \
             via the /status subresource must be preserved — otherwise a metadata-only \
             PUT could silently resurrect a draining namespace as Active"
        );
        assert_eq!(
            after_bogus_val["metadata"]["labels"]["env"], "prod",
            "the PUT's actual metadata update (labels) must still apply"
        );

        // A second PUT that omits `status` entirely (the common case for a metadata-only
        // update) must also preserve the stored status, not wipe it.
        let (rv3, uid3) = fetch_rv_and_uid(&after_bogus_val);
        let put_body_no_status = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "status-ns",
                    "uid": uid3,
                    "resourceVersion": rv3,
                    "labels": { "env": "staging" }
                }
            })
            .to_string(),
        );

        assert!(
            replace_namespace(
                State(state.clone()),
                Path("status-ns".to_string()),
                test_user(),
                axum::http::HeaderMap::new(),
                put_body_no_status,
            )
            .await
            .is_ok(),
            "replace without a status field must succeed"
        );

        let final_val = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "status-ns"))
            .await
            .expect("store get")
            .expect("must still exist");
        let final_body: serde_json::Value =
            serde_json::from_slice(&final_val.value).expect("parse final");
        assert_eq!(
            final_body["status"]["phase"], "Terminating",
            "omitting `status` from the PUT body must not wipe the stored status either"
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

    /// A Namespace patch (merge, strategic-merge, apply) that renames the object must be
    /// refused with upstream's 400 and leave the stored namespace untouched: cascade deletion
    /// selects objects by body namespace, so a renamed body would orphan or destroy the wrong
    /// namespace's contents.
    #[tokio::test]
    async fn patch_namespace_rejects_rename_for_every_patch_type() {
        use crate::handlers::test_support::{
            assert_identity_mismatch, content_type_headers, identity_rewrite_patches,
        };
        let state = make_state();
        assert!(create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            namespace_body("ns1"),
        )
        .await
        .is_ok());
        let key = crate::keys::cluster_object_key("namespaces", "ns1");
        let before = state.store.get(&key).await.unwrap().unwrap().value;

        for (label, ct, body) in identity_rewrite_patches("name", "kube-system", "v1", "Namespace")
            .into_iter()
            .filter(|(label, _, _)| *label != "json-patch")
        {
            let err = patch_namespace(
                State(state.clone()),
                Path("ns1".to_string()),
                axum::extract::Query(PatchQuery::default()),
                test_user(),
                content_type_headers(ct),
                body,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("{label} rename must be rejected"));
            assert_identity_mismatch(&err, label, "name");
            assert_eq!(
                state.store.get(&key).await.unwrap().unwrap().value,
                before,
                "{label} rename must not change the stored namespace"
            );
        }
    }

    /// `kubectl patch namespace --dry-run=server` (merge-patch branch) must NOT persist the
    /// patch — a dry-run that writes anyway silently mutates cluster state against the
    /// client's explicit intent. This test fails on revert with the stored labels changed
    /// to `{"patched": "yes"}`.
    #[tokio::test]
    async fn patch_namespace_merge_dry_run_does_not_mutate_store() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("dry-run-patch-ns"),
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
        let dry_run_query = PatchQuery {
            field_manager: None,
            _field_validation: None,
            dry_run: Some("All".to_string()),
            ..Default::default()
        };

        assert!(
            patch_namespace(
                State(state.clone()),
                Path("dry-run-patch-ns".to_string()),
                axum::extract::Query(dry_run_query),
                test_user(),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "dry-run patch must still return a success response"
        );

        let after = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "dry-run-patch-ns",
            ))
            .await
            .expect("store get")
            .expect("must still exist");
        let body: serde_json::Value =
            serde_json::from_slice(&after.value).expect("parse after patch");
        assert!(
            body["metadata"]["labels"]["patched"].is_null(),
            "dryRun=All must NOT persist the patch — if this fails, patch_namespace's \
             merge-branch dry-run guard was removed and labels.patched was actually written \
             to the store"
        );
    }

    // patch_namespace's merge-patch branch applies the patch directly to the full stored
    // object body (including metadata.uid) and used to persist the result with zero uid
    // handling. A caller holding only ordinary namespace `patch` rights could forge uid to
    // match a stale/foreign ownerReference, corrupting the garbage collector's cascade-GC
    // decision. Fails on revert: without restoring the pre-patch uid after merge_patch, the
    // forged uid below would be persisted and this assertion would fail.
    #[tokio::test]
    async fn patch_namespace_cannot_change_uid() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("uid-forge-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "uid-forge-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored_val: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored");
        let real_uid = stored_val["metadata"]["uid"]
            .as_str()
            .expect("create must assign a uid")
            .to_string();
        assert!(!real_uid.is_empty());

        let patch_body =
            Bytes::from(serde_json::json!({ "metadata": { "uid": "attacker-uid" } }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_namespace(
                State(state.clone()),
                Path("uid-forge-ns".to_string()),
                axum::extract::Query(PatchQuery::default()),
                test_user(),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "a patch attempting to set uid must still succeed (uid is silently restored, \
             not rejected — matches do_patch's PATCH semantics)"
        );

        let after = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "uid-forge-ns",
            ))
            .await
            .expect("store get")
            .expect("must still exist");
        let after_val: serde_json::Value =
            serde_json::from_slice(&after.value).expect("parse after patch");
        assert_eq!(
            after_val["metadata"]["uid"], real_uid,
            "a merge-patch carrying metadata.uid must not change the stored uid"
        );
    }

    /// Round 5 of the non-object-status bug class: patch_namespace (the MAIN `/api/v1/namespaces/{name}` PATCH
    /// endpoint, NOT `/status`) applied a merge-patch to the whole stored object body and
    /// restored only metadata.uid — a body `{"status":"x"}` persisted a scalar status using
    /// only ordinary namespace `patch` rights (no `namespaces/status` rights needed).
    ///
    /// Fails on revert: without restoring stored_status after the merge-patch, the stored
    /// object's status becomes the raw string "x" instead of staying an object, and any
    /// later in-place status stamper (e.g. stamp_terminating) that indexes it with a str key
    /// panics — crashing the apiserver for every other request in flight.
    #[tokio::test]
    async fn patch_namespace_rejects_scalar_status_merge_patch() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("scalar-status-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(serde_json::json!({ "status": "x" }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_namespace(
                State(state.clone()),
                Path("scalar-status-ns".to_string()),
                axum::extract::Query(PatchQuery::default()),
                test_user(),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "the main-endpoint patch itself must still succeed (status is silently ignored, \
             not rejected — the main endpoint doesn't own status at all)"
        );

        let after = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "scalar-status-ns",
            ))
            .await
            .expect("store get")
            .expect("must still exist");
        let after_val: serde_json::Value =
            serde_json::from_slice(&after.value).expect("parse after patch");
        assert!(
            !after_val["status"].is_string(),
            "a merge-patch body's scalar status must never be persisted as-is — got {:?}; a \
             string status corrupts the object's schema and panics the next in-place status \
             stamper",
            after_val["status"]
        );
    }

    /// Companion to the scalar-status regression above: a legitimate status the real
    /// namespace controller wrote via `/status` (e.g. mid-drain Terminating) must survive a
    /// main-endpoint patch exactly like it survives a main-endpoint PUT
    /// (`replace_namespace_ignores_body_status_uses_stored_status`) — otherwise any ordinary
    /// `kubectl patch namespace` metadata edit would silently resurrect a draining namespace
    /// as whatever stale status the client's patch body happened to carry.
    #[tokio::test]
    async fn patch_namespace_ignores_body_status_uses_stored_status() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("patch-status-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "patch-status-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored_val: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored");
        let rv = stored_val["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("1")
            .to_string();

        // Set status.phase=Terminating via the /status subresource, as the real namespace
        // controller does mid-drain.
        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "patch-status-ns", "resourceVersion": rv },
                "status": { "phase": "Terminating" }
            })
            .to_string(),
        );
        assert!(
            put_namespace_status(
                State(state.clone()),
                Path("patch-status-ns".to_string()),
                axum::http::HeaderMap::new(),
                status_body,
            )
            .await
            .is_ok(),
            "put_namespace_status must succeed"
        );

        // A client patches the main endpoint carrying a stale/bogus status (Active) in the
        // body, plus a real metadata update.
        let patch_body = Bytes::from(
            serde_json::json!({
                "metadata": { "labels": { "env": "prod" } },
                "status": { "phase": "Active" }
            })
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_namespace(
                State(state.clone()),
                Path("patch-status-ns".to_string()),
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
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "patch-status-ns",
            ))
            .await
            .expect("store get")
            .expect("must still exist");
        let after_val: serde_json::Value =
            serde_json::from_slice(&after.value).expect("parse final");
        assert_eq!(
            after_val["status"]["phase"], "Terminating",
            "patch body status (Active) must be ignored; stored status (Terminating) set \
             via the /status subresource must be preserved"
        );
        assert_eq!(
            after_val["metadata"]["labels"]["env"], "prod",
            "the patch's actual metadata update (labels) must still apply"
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
                test_user(),
                HeaderMap::new(),
                Bytes::new(),
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
                test_user(),
                HeaderMap::new(),
                Bytes::new(),
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
            test_user(),
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

    // Upstream disallows create-on-update for Namespace. A PUT that created one would bypass the
    // create preparation (spec.finalizers), so deleting it later would orphan its content.
    #[tokio::test]
    async fn put_to_a_missing_namespace_returns_404_and_creates_nothing() {
        use u7s_store::Store;
        let state = make_state();

        let result = replace_namespace(
            State(state.clone()),
            Path("ghost-ns".to_string()),
            test_user(),
            axum::http::HeaderMap::new(),
            namespace_body("ghost-ns"),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("PUT to a missing namespace must fail"),
        };
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        let key = crate::keys::cluster_object_key("namespaces", "ghost-ns");
        assert!(
            state.store.get(&key).await.unwrap().is_none(),
            "a failed PUT must not leave a namespace behind"
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
            HeaderMap::new(),
            Bytes::new(),
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
                test_user(),
                HeaderMap::new(),
                Bytes::new(),
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

    // A repeat DELETE on an already-terminating namespace re-enters the soft-delete branch
    // (spec.finalizers is still non-empty) and must NOT clobber status.conditions the real
    // KCM namespace-controller wrote via PUT /status in between. A client (or GC) polling
    // status.conditions for NamespaceDeletionContentFailure to decide whether drain is stuck
    // would silently lose that signal if a redundant DELETE retry wiped it.
    #[tokio::test]
    async fn delete_namespace_repeat_delete_preserves_controller_set_conditions() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body_with_finalizers("repeat-delete-ns", &["kubernetes"]),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // First DELETE: soft-delete, stamps deletionTimestamp + status.phase=Terminating.
        assert!(
            delete_namespace(
                State(state.clone()),
                Path("repeat-delete-ns".to_string()),
                test_user(),
                HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .is_ok(),
            "first delete must not error"
        );

        // Simulate the KCM namespace controller reporting drain progress via PUT /status,
        // the same call path put_namespace_status_updates_conditions exercises.
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "repeat-delete-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let before: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let rv = before["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("1");

        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "repeat-delete-ns", "resourceVersion": rv },
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
                Path("repeat-delete-ns".to_string()),
                axum::http::HeaderMap::new(),
                status_body,
            )
            .await
            .is_ok(),
            "put_namespace_status must succeed"
        );

        // Repeat DELETE: spec.finalizers is unchanged (still ["kubernetes"]), so this re-enters
        // the same soft-delete branch as the first call — the one that used to rebuild
        // status.conditions is untouched.
        assert!(
            delete_namespace(
                State(state.clone()),
                Path("repeat-delete-ns".to_string()),
                test_user(),
                HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .is_ok(),
            "repeat delete must not error"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "repeat-delete-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            body["status"]["conditions"][0]["type"], "NamespaceDeletionContentFailure",
            "a repeat DELETE must not clobber status.conditions set by the real namespace \
             controller between DELETE calls — a client watching namespace-deletion progress \
             would lose the failure signal if this regresses"
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
                test_user(),
                HeaderMap::new(),
                Bytes::new(),
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

    // Every namespace that is ever created and deleted must not leave a permanent
    // QuotaAdmissionLocks map entry -- a conformance-style run that churns through
    // hundreds of ephemeral namespaces would otherwise grow this map forever, one
    // entry per dead namespace, for the life of the process.
    #[tokio::test]
    async fn delete_namespace_without_finalizers_evicts_quota_admission_lock() {
        use u7s_store::Store;
        let state = make_state();

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

        // Take the sole quota-admission permit for this namespace before deleting it, and
        // hold it across the delete — if the delete path failed to evict the map entry,
        // "no-fin-ns" would still resolve to THIS exhausted semaphore afterward.
        let held = state.quota_admission_locks.lock("no-fin-ns").await;

        delete_namespace(
            State(state.clone()),
            Path("no-fin-ns".to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete without finalizers must succeed");

        // Must resolve immediately via a freshly-created semaphore, not block on the one
        // `held` is still sitting on — a timeout here means eviction did not run.
        let _fresh = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            state.quota_admission_locks.lock("no-fin-ns"),
        )
        .await
        .expect("namespace hard-delete must evict its quota-admission lock entry");

        drop(held);
    }

    // Upstream's namespace Delete never touches content: the namespace controller deletes it
    // through each object's own DELETE so admission webhooks and dependent finalizers apply.
    // A raw in-process purge here would bypass both for every object in the namespace.
    #[tokio::test]
    async fn delete_namespace_without_finalizers_does_not_cascade_content() {
        use u7s_store::Store;
        let state = make_state();

        let ns_key = crate::keys::cluster_object_key("namespaces", "no-cascade-ns");
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "no-cascade-ns", "uid": "u-1", "resourceVersion": "1", "finalizers": []
            },
            "spec": { "finalizers": [] },
            "status": { "phase": "Active" }
        });
        state
            .store
            .put(&ns_key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed namespace");
        let cm_key = "/registry/configmaps/no-cascade-ns/cm1";
        state
            .store
            .put(
                cm_key,
                bytes::Bytes::from(
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "metadata": { "name": "cm1", "namespace": "no-cascade-ns" }
                    })
                    .to_string(),
                ),
                Some(0),
            )
            .await
            .expect("seed configmap");

        delete_namespace(
            State(state.clone()),
            Path("no-cascade-ns".to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete must succeed");

        assert!(
            state.store.get(&ns_key).await.unwrap().is_none(),
            "the namespace itself is removed at once when both spec.finalizers and \
             metadata.finalizers are empty"
        );
        assert!(
            state.store.get(cm_key).await.unwrap().is_some(),
            "namespace DELETE must not purge content in-process; that is the namespace \
             controller's job, via per-object DELETEs that run admission"
        );
    }

    #[test]
    fn replace_put_precondition_falls_back_to_read_revision_only_without_client_resource_version() {
        assert_eq!(
            replace_put_precondition(None, Some(7)),
            Some(7),
            "an unconditional put would recreate a namespace deleted after the existence check"
        );
        assert_eq!(
            replace_put_precondition(Some(3), Some(7)),
            Some(3),
            "a client-supplied resourceVersion keeps its own optimistic-concurrency check"
        );
    }

    // DELETE namespaces/io must never touch cluster-scoped CRDs. A substring match on
    // spec.group once let any namespace delete every CRD (and their CRs) whose group contained
    // the namespace name, with no CRD authorization. Content deletion belongs to the namespace
    // controller, which deletes only objects living in the namespace.
    #[tokio::test]
    async fn delete_namespace_leaves_crds_whose_group_contains_its_name_and_all_crs() {
        use crate::handlers::crd;
        use u7s_store::Store;
        let state = make_state();

        for (group, plural, kind, scope) in [
            ("example.io", "widgets", "Widget", "Namespaced"),
            ("istio.io", "gateways", "Gateway", "Namespaced"),
            ("io", "clusterthings", "ClusterThing", "Cluster"),
        ] {
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "apiextensions.k8s.io/v1",
                        "kind": "CustomResourceDefinition",
                        "metadata": { "name": format!("{plural}.{group}") },
                        "spec": {
                            "group": group,
                            "names": { "plural": plural, "singular": plural,
                                       "kind": kind, "listKind": format!("{kind}List") },
                            "scope": scope,
                            "versions": [{ "name": "v1", "served": true, "storage": true }]
                        }
                    })
                    .to_string(),
                ),
            )
            .await
            .unwrap_or_else(|e| panic!("install CRD {group}: {e:?}"));
        }

        let cr_keys = [
            crate::handlers::cr::cr_list_prefix("example.io", "widgets", Some("io")) + "in-ns",
            crate::handlers::cr::cr_list_prefix("example.io", "widgets", Some("other"))
                + "other-ns",
            crate::handlers::cr::cr_list_prefix("io", "clusterthings", None) + "cluster-cr",
        ];
        for key in &cr_keys {
            state
                .store
                .put(key, Bytes::from_static(b"{}"), Some(0))
                .await
                .expect("seed CR");
        }

        let ns_key = crate::keys::cluster_object_key("namespaces", "io");
        state
            .store
            .put(
                &ns_key,
                bytes::Bytes::from(
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "Namespace",
                        "metadata": { "name": "io", "uid": "u-1", "resourceVersion": "1" },
                        "spec": { "finalizers": ["kubernetes"] },
                        "status": { "phase": "Active" }
                    })
                    .to_string(),
                ),
                Some(0),
            )
            .await
            .expect("seed namespace");

        delete_namespace(
            State(state.clone()),
            Path("io".to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete must succeed");

        for crd_name in [
            "widgets.example.io",
            "gateways.istio.io",
            "clusterthings.io",
        ] {
            let key =
                format!("/registry/apiextensions.k8s.io/customresourcedefinitions/{crd_name}");
            assert!(
                state.store.get(&key).await.unwrap().is_some(),
                "CRD {crd_name} is cluster-scoped and must survive deletion of namespace io"
            );
        }
        for key in &cr_keys {
            assert!(
                state.store.get(key).await.unwrap().is_some(),
                "namespace deletion must not remove {key} itself; only the namespace \
                 controller removes objects in the namespace via their own DELETE"
            );
        }
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
            test_user(),
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

    // replace_namespace never touched metadata.uid at all — a non-blank, mismatched
    // client-supplied uid was silently persisted, unlike the generic replace_resource path
    // (resource.rs), which 409s on exactly this. Letting it through would let a client forge
    // a match against a stale/foreign ownerReference, corrupting the garbage collector's
    // cascade-GC decision. Fails on revert: without the uid-mismatch check, this PUT (valid
    // resourceVersion, forged uid) would succeed with 200 instead of 409.
    #[tokio::test]
    async fn replace_namespace_rejects_mismatched_uid_with_409() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("uid-guard-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored_entry = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "uid-guard-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored: serde_json::Value =
            serde_json::from_slice(&stored_entry.value).expect("parse stored");
        let rv = stored["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("1")
            .to_string();
        let real_uid = stored["metadata"]["uid"].as_str().unwrap_or("").to_string();
        assert!(!real_uid.is_empty());

        let replace_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "uid-guard-ns",
                    "uid": "attacker-uid",
                    "resourceVersion": rv
                }
            })
            .to_string(),
        );

        let result = replace_namespace(
            State(state),
            Path("uid-guard-ns".to_string()),
            test_user(),
            axum::http::HeaderMap::new(),
            replace_body,
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("replace with a mismatched, non-blank uid must fail"),
        };
        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "PUT with a mismatched non-blank metadata.uid must return 409 Conflict — uid is \
             immutable identity, not a client-settable field"
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

    /// `PUT /finalize?dryRun=All` draining the last finalizer must NOT hard-delete the
    /// namespace. Before this fix, finalize_namespace had no dry-run check at all.
    #[tokio::test]
    async fn finalize_namespace_dry_run_all_does_not_hard_delete_or_persist() {
        use u7s_store::Store;
        let state = make_state();

        let key = crate::keys::cluster_object_key("namespaces", "finalize-ns-dry-run");
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "finalize-ns-dry-run",
                "uid": "00000000-0000-0000-0000-000000000003",
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

        let finalize_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "finalize-ns-dry-run" },
                "spec": { "finalizers": [] }
            })
            .to_string(),
        );

        let mut dry_run_headers = axum::http::HeaderMap::new();
        dry_run_headers.insert(
            axum::http::HeaderName::from_static(crate::handlers::json_patch::DRY_RUN_HEADER),
            axum::http::HeaderValue::from_static("true"),
        );

        let resp = finalize_namespace(
            State(state.clone()),
            Path("finalize-ns-dry-run".to_string()),
            dry_run_headers,
            finalize_body,
        )
        .await
        .expect("dry-run finalize must succeed");
        let resp_body = axum::body::to_bytes(resp.into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert!(
            v["spec"]["finalizers"].as_array().unwrap().is_empty(),
            "dry-run response must show the would-be empty finalizers list"
        );

        let stored = state
            .store
            .get(&key)
            .await
            .expect("store get must not error")
            .expect("dryRun=All must not hard-delete the namespace");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["finalizers"],
            serde_json::json!(["other-controller"]),
            "dryRun=All must not persist the finalizer removal"
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

    // The finalizers subresource PUT writes spec.finalizers through NamespaceSpec and then
    // immediately re-parses the same field into NamespaceSpec again to decide whether to
    // hard-delete. Nothing used to force those two steps to agree on shape — a raw Value write
    // sandwiched between two typed round-trips could drift from what the response (and the
    // store's own copy) shows. If the write and the read ever disagreed, a client acting on the
    // response (e.g. KCM deciding a finalizer removal took effect) and the store's actual state
    // would desync, and the namespace could get stuck Terminating forever.
    #[tokio::test]
    async fn finalize_namespace_response_and_persisted_spec_never_diverge() {
        use axum::response::IntoResponse;
        use u7s_store::Store;
        let state = make_state();

        let key = crate::keys::cluster_object_key("namespaces", "divergence-ns");
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "divergence-ns",
                "uid": "00000000-0000-0000-0000-000000000005",
                "resourceVersion": "1"
            },
            "spec": { "finalizers": ["kubernetes", "custom.io/finalizer"] }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(ns.to_string()), Some(0))
            .await
            .expect("direct store write must succeed");

        let finalize_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "divergence-ns" },
                "spec": { "finalizers": ["kubernetes"] }
            })
            .to_string(),
        );

        let resp = finalize_namespace(
            State(state.clone()),
            Path("divergence-ns".to_string()),
            axum::http::HeaderMap::new(),
            finalize_body,
        )
        .await
        .expect("finalize must succeed")
        .into_response();

        let response_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body must be readable");
        let response_body: serde_json::Value =
            serde_json::from_slice(&response_bytes).expect("response body must be valid JSON");
        let response_spec: NamespaceSpec =
            serde_json::from_value(response_body["spec"].clone()).unwrap_or_default();

        let stored = state
            .store
            .get(&key)
            .await
            .expect("store get must not error")
            .expect("namespace must still exist — one finalizer remains, no hard-delete yet");
        let stored_body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored value must be valid JSON");
        let stored_spec: NamespaceSpec =
            serde_json::from_value(stored_body["spec"].clone()).unwrap_or_default();

        assert_eq!(
            response_spec.finalizers.as_deref(),
            Some(["kubernetes".to_string()].as_slice()),
            "the finalize response must reflect exactly the requested finalizer set, not \
             whatever the raw pre-typed write happened to leave in place"
        );
        assert_eq!(
            response_spec.finalizers, stored_spec.finalizers,
            "the response returned from PUT /finalize and the store's persisted copy must \
             never disagree about spec.finalizers — divergence here is exactly the class of \
             bug that leaves a namespace stuck Terminating forever because callers and the \
             store disagree on whether a finalizer was actually removed"
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
        let seeded_rv = state
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
                    "resourceVersion": seeded_rv.to_string(),
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
                test_user(),
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

    /// Regression for the silent-coercion bug: before status_dispatch, PUT
    /// decoded via `NamespaceStatus::deserialize(v).unwrap_or_default()`, which swallowed a
    /// decode failure and stored `status: {}` with a 200 — a caller whose controller sent a
    /// malformed status got no error and a namespace that silently lost its real status.
    /// Reverting to that `.unwrap_or_default()` makes this test fail: it would see 200 and
    /// an overwritten `{}` instead of a 400 and the original status left untouched.
    #[tokio::test]
    async fn put_namespace_status_rejects_scalar_status_instead_of_silently_defaulting() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("status-scalar-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored_before = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "status-scalar-ns",
            ))
            .await
            .unwrap()
            .unwrap();

        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "status-scalar-ns" },
                "status": "oops"
            })
            .to_string(),
        );

        let result = put_namespace_status(
            State(state.clone()),
            Path("status-scalar-ns".to_string()),
            axum::http::HeaderMap::new(),
            status_body,
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "a scalar status PUT must be rejected, not silently coerced to {{}} — this is \
                 exactly the silent-corruption bug status_dispatch closes"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::BAD_REQUEST,
            "a scalar status on PUT /status must fail at typed decode (400), matching \
             upstream's whole-body decode-failure semantics"
        );

        let stored_after = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "status-scalar-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_after.value, stored_before.value,
            "the rejected PUT must not have persisted anything — the namespace's status must \
             be exactly what it was before, not overwritten with a defaulted {{}}"
        );
    }

    /// `PUT /status?dryRun=All` must return the would-be status object but leave the stored
    /// namespace's status untouched. Before this fix, put_namespace_status had no dry-run
    /// check at all.
    #[tokio::test]
    async fn put_namespace_status_dry_run_all_does_not_persist() {
        let state = make_state();

        assert!(create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            namespace_body("status-put-dry-run-ns"),
        )
        .await
        .is_ok());

        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "status-put-dry-run-ns" },
                "status": { "phase": "Terminating" }
            })
            .to_string(),
        );

        let mut dry_run_headers = axum::http::HeaderMap::new();
        dry_run_headers.insert(
            axum::http::HeaderName::from_static(crate::handlers::json_patch::DRY_RUN_HEADER),
            axum::http::HeaderValue::from_static("true"),
        );

        let resp = put_namespace_status(
            State(state.clone()),
            Path("status-put-dry-run-ns".to_string()),
            dry_run_headers,
            status_body,
        )
        .await
        .expect("dry-run put must succeed");
        let resp_body = axum::body::to_bytes(resp.into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(
            v["status"]["phase"], "Terminating",
            "dry-run response must show the would-be status"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "status-put-dry-run-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["status"]["phase"], "Active",
            "dryRun=All must not persist the status change (create_namespace defaults to Active)"
        );
    }

    // put_namespace_status routes the incoming status through NamespaceStatus instead of
    // copying the raw Value. That only pays off if NamespaceStatus's flattened `rest` field
    // actually preserves every status field the raw copy used to preserve verbatim — not just
    // `phase`, which is the only field the struct names explicitly. Dropping any other field
    // (e.g. a second condition) would silently erase drain-progress signals
    // OrderedNamespaceDeletion polls for, hiding a real content-deletion failure.
    #[tokio::test]
    async fn put_namespace_status_typed_round_trip_preserves_all_status_fields() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("status-fields-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let stored_before = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "status-fields-ns",
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
                "metadata": { "name": "status-fields-ns", "resourceVersion": rv },
                "status": {
                    "phase": "Terminating",
                    "conditions": [
                        {
                            "type": "NamespaceDeletionContentFailure",
                            "status": "True",
                            "reason": "ContentDeletionFailed",
                            "message": "test-pod has a finalizer"
                        },
                        {
                            "type": "NamespaceDeletionDiscoveryFailure",
                            "status": "False",
                            "reason": "ResourcesDiscovered",
                            "message": "discovery succeeded"
                        }
                    ]
                }
            })
            .to_string(),
        );

        assert!(
            put_namespace_status(
                State(state.clone()),
                Path("status-fields-ns".to_string()),
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
                "status-fields-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            body["status"]["phase"], "Terminating",
            "typed status round-trip must still update phase"
        );
        let conditions = body["status"]["conditions"]
            .as_array()
            .expect("conditions must survive the typed NamespaceStatus round-trip");
        assert_eq!(
            conditions.len(),
            2,
            "both conditions must survive the typed round-trip via NamespaceStatus.rest — \
             dropping either would hide a drain-progress signal OrderedNamespaceDeletion polls \
             for, making a real content-deletion failure invisible to KCM"
        );
        assert_eq!(
            conditions[1]["type"], "NamespaceDeletionDiscoveryFailure",
            "condition fields beyond phase must round-trip unmodified through NamespaceStatus"
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

    /// `PATCH /status?dryRun=All` must return the would-be patched status but leave the
    /// stored namespace's status untouched. Before this fix, patch_namespace_status had no
    /// dry-run check at all.
    #[tokio::test]
    async fn patch_namespace_status_dry_run_all_does_not_persist() {
        let state = make_state();

        assert!(create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            namespace_body("status-patch-dry-run-ns"),
        )
        .await
        .is_ok());

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
        headers.insert(
            axum::http::HeaderName::from_static(crate::handlers::json_patch::DRY_RUN_HEADER),
            axum::http::HeaderValue::from_static("true"),
        );

        let resp = patch_namespace_status(
            State(state.clone()),
            Path("status-patch-dry-run-ns".to_string()),
            headers,
            patch_body,
        )
        .await
        .expect("dry-run patch must succeed");
        let resp_body = axum::body::to_bytes(resp.into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(
            v["status"]["conditions"][0]["type"], "NamespaceDeletionContentFailure",
            "dry-run response must show the would-be patched condition"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "status-patch-dry-run-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            stored_v["status"]["conditions"].is_null(),
            "dryRun=All must not persist the condition"
        );
    }

    /// patch_namespace_status with a merge-patch body `{"status":"x"}` must be rejected with
    /// 422, not persisted. Unlike the generic status-subresource handlers, this handler had
    /// NO guard on either patch-content-type branch — a scalar status corrupts the object's
    /// schema and later panics the in-place namespace terminating-stamp on DELETE.
    #[tokio::test]
    async fn patch_namespace_status_rejects_scalar_status_merge_patch() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("scalar-status-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        let patch_body = Bytes::from(serde_json::json!({ "status": "x" }).to_string());

        let result = patch_namespace_status(
            State(state.clone()),
            Path("scalar-status-ns".to_string()),
            headers,
            patch_body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "a scalar status merge-patch must be rejected, not accepted — it would \
                 corrupt the object's schema and later crash the terminating-stamp on DELETE"
            ),
        };
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "scalar-status-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            body.get("status").is_none() || body["status"].is_object(),
            "the rejected patch must not have been persisted — status must remain absent \
             or an object, never the scalar \"x\""
        );
    }

    /// patch_namespace_status with a JSON Patch body
    /// `[{"op":"replace","path":"/status","value":"x"}]` must be rejected too —
    /// `validate_status_json_patch_paths` explicitly permits a whole-`/status` replace path.
    #[tokio::test]
    async fn patch_namespace_status_rejects_scalar_status_json_patch() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("scalar-status-jp-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );
        let patch_body = Bytes::from(
            serde_json::json!([{"op": "replace", "path": "/status", "value": "x"}]).to_string(),
        );

        let result = patch_namespace_status(
            State(state.clone()),
            Path("scalar-status-jp-ns".to_string()),
            headers,
            patch_body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "a JSON Patch replacing /status with a scalar must be rejected, not \
                 accepted — same corruption as the merge-patch case, different content-type"
            ),
        };
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "scalar-status-jp-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            body.get("status").is_none() || body["status"].is_object(),
            "the rejected patch must not have been persisted — status must remain absent \
             or an object, never the scalar \"x\""
        );
    }

    /// patch_namespace_status with an OBJECT-shaped status whose `phase` field is the wrong
    /// JSON type (a number, not a string) must also be 422. The two scalar-status tests above
    /// never reach `decode_status_patch`: `reject_non_object_status` already rejects a
    /// scalar/array before typed dispatch runs, so they'd pass identically even if the
    /// `decode_status_patch` call in `patch_namespace_status` were deleted. This status IS an
    /// object, so it clears that guard — only the typed decode inside `decode_status_patch`
    /// can catch the wrong-typed `phase` field, making this the real fail-on-revert case.
    #[tokio::test]
    async fn patch_namespace_status_rejects_object_status_wrong_typed_phase_merge_patch() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespace_body("wrong-typed-phase-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        let patch_body = Bytes::from(serde_json::json!({ "status": { "phase": 5 } }).to_string());

        let result = patch_namespace_status(
            State(state.clone()),
            Path("wrong-typed-phase-ns".to_string()),
            headers,
            patch_body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "an object status with a wrong-typed `phase` field must be rejected — \
                 reject_non_object_status alone can't see inside the object, so this only \
                 fails if decode_status_patch's typed decode is actually wired in"
            ),
        };
        assert_eq!(
            err.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "typed decode failure on an object-shaped status is still upstream's post-merge \
             validation semantics (422), same code as the scalar case"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "wrong-typed-phase-ns",
            ))
            .await
            .unwrap()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_ne!(
            body["status"]["phase"], 5,
            "the rejected patch must not have been persisted"
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
    // must persist status.conditions (PANIC-1)
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
    // so that is the content type the conformance run actually hits. Before the
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

    // `kubectl apply --server-side` on a new namespace goes through the SSA create-on-missing
    // path, not create_namespace. If that path skips the "kubernetes" finalizer, a later DELETE
    // hard-deletes the namespace and orphans every object in it, because no namespace
    // controller ever sees a Terminating phase to drain.
    #[tokio::test]
    async fn ssa_apply_created_namespace_soft_deletes_so_controller_can_drain_it() {
        use u7s_store::Store;
        let state = make_state();

        let patch = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "ssa-new-ns" }
        });
        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );
        patch_namespace(
            State(state.clone()),
            Path("ssa-new-ns".to_string()),
            axum::extract::Query(PatchQuery {
                field_manager: Some("kubectl".to_string()),
                _field_validation: None,
                dry_run: None,
                ..Default::default()
            }),
            test_user(),
            ssa_headers,
            Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("SSA apply-create of a Namespace must succeed: {:?}", e.0));

        let key = crate::keys::cluster_object_key("namespaces", "ssa-new-ns");
        let stored = state.store.get(&key).await.unwrap().expect("created");
        let created: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            created["spec"]["finalizers"],
            serde_json::json!(["kubernetes"]),
            "SSA apply-create must stamp spec.finalizers like POST does"
        );

        delete_namespace(
            State(state.clone()),
            Path("ssa-new-ns".to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete must succeed");

        let stored = state.store.get(&key).await.unwrap().expect(
            "namespace must still exist (Terminating) so the namespace controller can drain it",
        );
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Terminating");
        assert!(v["metadata"]["deletionTimestamp"].is_string());
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
                ..Default::default()
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
                ..Default::default()
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
        let applied = mf
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["manager"] == "kubectl-apply")
            .expect("managedFields must name the ?fieldManager query parameter as a manager");
        assert_eq!(
            applied["operation"], "Apply",
            "the ?fieldManager entry's operation must be 'Apply' for SSA requests"
        );
    }

    /// A Namespace created via SSA PATCH on a name that does not yet exist (the
    /// `kubectl apply` create-on-missing path, `do_patch`'s `is_ssa && stored_opt.is_none()`
    /// branch) must get `status.phase: Active`, exactly like plain `kubectl create`.
    ///
    /// Before the fix, `apply_defaults` had no Namespace case, so this path stored
    /// `status: {}`. KCM's ServiceAccount controller skips reconciling the default SA
    /// for any namespace whose status.phase != Active — so an apply-created namespace
    /// silently never gets its `default` ServiceAccount, and any pod created in it with
    /// the pod-spec default `automountServiceAccountToken: true` sticks in
    /// ContainerCreating forever with a misleading kubelet TokenRequest error.
    #[tokio::test]
    async fn apply_created_namespace_gets_status_phase_active() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        let manifest = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "apply-created-ns" }
        });
        let patch_bytes = Bytes::from(serde_json::to_vec(&manifest).unwrap());
        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let result = patch_namespace(
            State(state.clone()),
            Path("apply-created-ns".to_string()),
            axum::extract::Query(PatchQuery {
                field_manager: Some("kubectl-apply".to_string()),
                _field_validation: None,
                dry_run: None,
                ..Default::default()
            }),
            test_user(),
            ssa_headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|e| panic!("SSA create-on-missing must succeed, got {:?}", e.0))
        .into_response();

        let body_bytes = to_bytes(result.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            v["status"]["phase"], "Active",
            "apply-created Namespace must get status.phase=Active in the response; \
             if this regresses, KCM's ServiceAccount controller silently skips \
             reconciling the default SA for apply-created namespaces, and any pod in \
             that namespace with default automountServiceAccountToken: true sticks in \
             ContainerCreating forever with a misleading kubelet TokenRequest error"
        );

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "apply-created-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("namespace must exist in store");
        let stored_body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_body["status"]["phase"], "Active",
            "the STORED apply-created Namespace must have status.phase=Active, not just \
             the response body — KCM's ServiceAccount controller reads the stored object"
        );
    }

    /// Plain `kubectl create namespace` (POST) must still get status.phase=Active after
    /// routing through the shared `apply_defaults` defaulter.
    ///
    /// Regression guard for the refactor that made `create_namespace` call
    /// `apply_defaults` instead of setting status inline: this must not silently drop
    /// the default kube-controller-manager's ServiceAccount controller (and every other
    /// consumer of namespace status) depends on for every plain-created namespace.
    #[tokio::test]
    async fn plain_created_namespace_still_gets_status_phase_active() {
        let state = make_state();

        create_namespace(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            namespace_body("plain-created-ns"),
        )
        .await
        .expect("create must succeed");

        let stored = state
            .store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "plain-created-ns",
            ))
            .await
            .expect("store get must not error")
            .expect("namespace must exist in store");
        let body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            body["status"]["phase"], "Active",
            "plain-created Namespace must still get status.phase=Active after routing \
             through apply_defaults; a regression here breaks the working plain-create \
             path that KCM's ServiceAccount controller and every namespace-scoped \
             conformance test depend on"
        );
    }

    /// Regression test: `GET /api/v1/namespaces?watch=true` with no
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
             keep the store alive for the stream's lifetime",
            elapsed.as_millis()
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

    use crate::handlers::test_support::make_state_with_store as make_state;

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
// admission webhook pipeline.
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

    use crate::handlers::test_support::make_state_with_store as make_state;

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

    fn deny_webhook_router() -> Router {
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

    /// Registers a webhook that, on its first UPDATE admission call, bumps the namespace's
    /// revision in the store — a deterministic concurrent write landing between
    /// replace_namespace's read and its write.
    async fn install_revision_bumping_webhook(store: Arc<SqliteStore>, ns: &str) {
        let bumped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let key = crate::keys::cluster_object_key("namespaces", ns);
        let bump_store = store.clone();
        let router = Router::new().route(
            "/webhook",
            post(move || {
                let (store, key, bumped) = (bump_store.clone(), key.clone(), bumped.clone());
                async move {
                    if !bumped.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        let cur = store.get(&key).await.unwrap().unwrap();
                        let mut v: serde_json::Value = serde_json::from_slice(&cur.value).unwrap();
                        v["metadata"]["labels"] = serde_json::json!({"concurrent": "writer"});
                        store
                            .put(
                                &key,
                                Bytes::from(serde_json::to_vec(&v).unwrap()),
                                Some(cur.revision),
                            )
                            .await
                            .unwrap();
                    }
                    axum::Json(serde_json::json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": {"uid": "test-uid", "allowed": true}
                    }))
                }
            }),
        );
        let (url, _handle) = start_mock_webhook(router).await;
        std::mem::forget(_handle);
        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "bump-on-update"},
            "webhooks": [{
                "name": "bump.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["namespaces"], "operations": ["UPDATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/bump-on-update",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();
    }

    fn ns_json(name: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}})
                .to_string(),
        )
    }

    async fn put_namespace_with_rv(
        state: &crate::state::AppState<SqliteStore>,
        name: &str,
        rv: Option<&str>,
    ) -> Result<(), crate::status::StatusError> {
        let mut meta = serde_json::json!({"name": name, "labels": {"env": "prod"}});
        if let Some(rv) = rv {
            meta["resourceVersion"] = rv.into();
        }
        replace_namespace(
            axum::extract::State(state.clone()),
            Path(name.to_string()),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(
                serde_json::json!({"apiVersion": "v1", "kind": "Namespace", "metadata": meta})
                    .to_string(),
            ),
        )
        .await
        .map(|_| ())
    }

    /// Upstream GuaranteedUpdate re-reads and retries an update that carries no
    /// resourceVersion, so a concurrent label writer must never surface as a 409 to
    /// `kubectl replace`-style unconditional PUTs.
    #[tokio::test]
    async fn unconditional_namespace_put_retries_when_a_concurrent_write_lands() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());
        create_namespace(
            axum::extract::State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            ns_json("race-ns"),
        )
        .await
        .map_err(|e| e.0)
        .expect("create must succeed");
        install_revision_bumping_webhook(store.clone(), "race-ns").await;

        put_namespace_with_rv(&state, "race-ns", None)
            .await
            .map_err(|e| e.0)
            .expect("unconditional PUT must retry past a concurrent write, not 409");

        let stored = store
            .get(&crate::keys::cluster_object_key("namespaces", "race-ns"))
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["metadata"]["labels"]["env"], "prod");
    }

    /// A client-supplied resourceVersion is the client's optimistic-concurrency contract:
    /// a mismatch must stay a 409, never be silently retried over the other writer.
    #[tokio::test]
    async fn explicit_rv_namespace_put_still_409s_when_a_concurrent_write_lands() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());
        create_namespace(
            axum::extract::State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            ns_json("race-rv-ns"),
        )
        .await
        .map_err(|e| e.0)
        .expect("create must succeed");
        let rv = store
            .get(&crate::keys::cluster_object_key("namespaces", "race-rv-ns"))
            .await
            .unwrap()
            .unwrap()
            .revision
            .to_string();
        install_revision_bumping_webhook(store.clone(), "race-rv-ns").await;

        let err = put_namespace_with_rv(&state, "race-rv-ns", Some(&rv))
            .await
            .expect_err("stale explicit-RV PUT must fail");
        assert_eq!(err.0, StatusCode::CONFLICT);
    }

    /// replace_namespace must invoke the validating admission pipeline.
    /// A validating webhook that denies UPDATE must cause replace_namespace to return an
    /// error, and the stored namespace must be unchanged. Without this fix,
    /// replace_namespace called neither admission hook at all, so a webhook registered for
    /// namespaces/UPDATE was silently skipped on every PUT.
    #[tokio::test]
    async fn replace_namespace_invokes_validating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        let ns_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": "replace-denied-ns"}
            })
            .to_string(),
        );
        create_namespace(
            axum::extract::State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            ns_body,
        )
        .await
        .expect("create must succeed");

        let (url, _handle) = start_mock_webhook(deny_webhook_router()).await;

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-validating-replace-ns"},
            "webhooks": [{
                "name": "deny.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["namespaces"], "operations": ["UPDATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-validating-replace-ns",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let replace_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": "replace-denied-ns", "labels": {"env": "prod"}}
            })
            .to_string(),
        );

        let result = replace_namespace(
            axum::extract::State(state),
            Path("replace-denied-ns".to_string()),
            test_user(),
            axum::http::HeaderMap::new(),
            replace_body,
        )
        .await;

        assert!(
            result.is_err(),
            "replace_namespace must be rejected when validating webhook denies — \
             without the fix, admission was bypassed and the PUT was silently applied"
        );

        let stored = store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "replace-denied-ns",
            ))
            .await
            .unwrap()
            .expect("namespace must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["labels"].get("env").is_none(),
            "denied replace must not be persisted"
        );
    }

    /// patch_namespace's merge/strategic-merge branch must invoke the validating admission
    /// pipeline. A validating webhook that denies UPDATE must cause it to return an error,
    /// and the stored namespace must be unchanged. Without this fix, this branch called
    /// neither admission hook at all — the SSA branch of the same handler delegates into
    /// do_patch and got admission for free, so this was a sibling-drift gap within one
    /// handler.
    #[tokio::test]
    async fn patch_namespace_merge_patch_invokes_validating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        let ns_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": "patch-denied-ns"}
            })
            .to_string(),
        );
        create_namespace(
            axum::extract::State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            ns_body,
        )
        .await
        .expect("create must succeed");

        let (url, _handle) = start_mock_webhook(deny_webhook_router()).await;

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-validating-patch-ns"},
            "webhooks": [{
                "name": "deny.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["namespaces"], "operations": ["UPDATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-validating-patch-ns",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let patch_body =
            Bytes::from(serde_json::json!({"metadata": {"labels": {"env": "prod"}}}).to_string());

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_namespace(
            axum::extract::State(state),
            Path("patch-denied-ns".to_string()),
            Query(PatchQuery::default()),
            test_user(),
            headers,
            patch_body,
        )
        .await;

        assert!(
            result.is_err(),
            "patch_namespace's merge/strategic-merge branch must be rejected when validating \
             webhook denies — without the fix, admission was bypassed and the patch was \
             silently applied"
        );

        let stored = store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "patch-denied-ns",
            ))
            .await
            .unwrap()
            .expect("namespace must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["labels"].get("env").is_none(),
            "denied patch must not be persisted"
        );
    }

    /// `kubectl apply --server-side` onto a not-yet-existing Namespace name delegates into
    /// do_patch's SSA-create branch (see patch_namespace's apply-patch+yaml branch above) — a
    /// validating webhook that denies CREATE must reject it, and the namespace must never be
    /// created. Without do_patch's own SSA-create fix, this bypassed admission entirely: not
    /// just Namespace, but ANY built-in resource created via `kubectl apply --server-side`
    /// onto a missing name skipped both mutating and validating webhooks.
    #[tokio::test]
    async fn patch_namespace_ssa_create_invokes_validating_admission_when_missing() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        let (url, _handle) = start_mock_webhook(deny_webhook_router()).await;

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-validating-ssa-create-ns"},
            "webhooks": [{
                "name": "deny.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["namespaces"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-validating-ssa-create-ns",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let apply_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": "ssa-denied-ns"}
            })
            .to_string(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let result = patch_namespace(
            axum::extract::State(state),
            Path("ssa-denied-ns".to_string()),
            Query(PatchQuery::default()),
            test_user(),
            headers,
            apply_body,
        )
        .await;

        assert!(
            result.is_err(),
            "SSA-create of a not-yet-existing Namespace must be rejected when validating \
             webhook denies — without do_patch's SSA-create fix, admission was bypassed \
             entirely and the namespace was silently created"
        );

        let stored = store
            .get(&crate::keys::cluster_object_key(
                "namespaces",
                "ssa-denied-ns",
            ))
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "denied SSA-create must not persist the namespace"
        );
    }
}

// ---------------------------------------------------------------------------
// Regression tests: put_namespace_status must CAS on the
// INCOMING body's resourceVersion, not the stored object's RV.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod namespace_status_cas_tests {
    use super::*;
    use std::sync::Arc;
    use u7s_store::{SqliteStore, Store};

    use crate::handlers::test_support::make_state_with_store as make_state;

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

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use crate::handlers::test_support::make_state;
    use axum::http::{header, HeaderValue};

    type TestState = crate::state::AppState;

    fn user() -> Extension<UserInfo> {
        Extension(UserInfo {
            username: "admin".into(),
            ..Default::default()
        })
    }

    fn headers(content_type: &'static str, user_agent: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        h.insert(header::USER_AGENT, HeaderValue::from_static(user_agent));
        h
    }

    async fn create(state: &TestState, name: &str) {
        create_namespace(
            State(state.clone()),
            user(),
            headers("application/json", "creator/1.0"),
            Bytes::from(
                serde_json::json!({"apiVersion": "v1", "kind": "Namespace",
                                   "metadata": {"name": name}})
                .to_string(),
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("create: {e:?}"));
    }

    async fn apply(state: &TestState, name: &str, manager: &str, labels: serde_json::Value) {
        patch_namespace(
            State(state.clone()),
            Path(name.into()),
            Query(PatchQuery {
                field_manager: Some(manager.into()),
                force: Some(false),
                ..Default::default()
            }),
            user(),
            headers("application/apply-patch+yaml", "applier/1.0"),
            Bytes::from({
                let mut ns = serde_json::json!({"apiVersion": "v1", "kind": "Namespace",
                                                "metadata": {"name": name}});
                if !labels.is_null() {
                    ns["metadata"]["labels"] = labels;
                }
                ns.to_string()
            }),
        )
        .await
        .unwrap_or_else(|e| panic!("apply: {e:?}"));
    }

    async fn stored(state: &TestState, name: &str) -> serde_json::Value {
        let s = state
            .store
            .get(&cluster_object_key("namespaces", name))
            .await
            .unwrap()
            .unwrap();
        serde_json::from_slice(&s.value).unwrap()
    }

    fn manager<'a>(
        obj: &'a serde_json::Value,
        name: &str,
        subresource: Option<&str>,
    ) -> Option<&'a serde_json::Value> {
        obj["metadata"]["managedFields"]
            .as_array()?
            .iter()
            .find(|m| m["manager"] == name && m["subresource"].as_str() == subresource)
    }

    /// An applier owns `team`; another tool PUTs a new value; the applier then stops
    /// naming the label. Without recording the PUT, the applier still owns the label and
    /// the apply silently deletes the other tool's change.
    #[tokio::test]
    async fn apply_dropping_a_label_keeps_the_value_another_manager_put() {
        let state = make_state();
        create(&state, "ns-put").await;
        apply(&state, "ns-put", "tool-a", serde_json::json!({"team": "a"})).await;

        let mut ns = stored(&state, "ns-put").await;
        ns["metadata"]["labels"]["team"] = serde_json::json!("b");
        replace_namespace(
            State(state.clone()),
            Path("ns-put".into()),
            user(),
            headers("application/json", "other-tool/2.0"),
            Bytes::from(ns.to_string()),
        )
        .await
        .unwrap_or_else(|e| panic!("put: {e:?}"));

        apply(&state, "ns-put", "tool-a", serde_json::Value::Null).await;
        let after = stored(&state, "ns-put").await;
        assert_eq!(
            after["metadata"]["labels"]["team"], "b",
            "apply deleted a label another manager changed via PUT"
        );
        assert!(manager(&after, "other-tool", None).is_some());
    }

    /// Same data loss through merge-patch, the verb `kubectl label` uses.
    #[tokio::test]
    async fn apply_dropping_a_label_keeps_the_value_another_manager_merge_patched() {
        let state = make_state();
        create(&state, "ns-merge").await;
        apply(
            &state,
            "ns-merge",
            "tool-a",
            serde_json::json!({"team": "a"}),
        )
        .await;

        patch_namespace(
            State(state.clone()),
            Path("ns-merge".into()),
            Query(PatchQuery::default()),
            user(),
            headers("application/merge-patch+json", "kubectl-label/1.0"),
            Bytes::from(r#"{"metadata":{"labels":{"team":"b"}}}"#),
        )
        .await
        .unwrap_or_else(|e| panic!("merge patch: {e:?}"));

        apply(&state, "ns-merge", "tool-a", serde_json::Value::Null).await;
        let after = stored(&state, "ns-merge").await;
        assert_eq!(
            after["metadata"]["labels"]["team"], "b",
            "apply deleted a label another manager changed via merge-patch"
        );
    }

    /// A created Namespace is owned by its creator, so a later apply that drops a field
    /// the creator set does not delete it.
    #[tokio::test]
    async fn namespace_create_records_the_creator_as_an_update_manager() {
        let state = make_state();
        create(&state, "ns-create").await;
        let ns = stored(&state, "ns-create").await;
        let m = manager(&ns, "creator", None).expect("creator recorded");
        assert_eq!(m["operation"], "Update");
        assert!(m["fieldsV1"]["f:metadata"]["f:labels"].is_object());
    }

    /// The namespace controller's /status and /finalize writes are recorded under their
    /// own subresource so they do not take ownership of main-resource fields.
    #[tokio::test]
    async fn namespace_status_and_finalize_writes_are_recorded_per_subresource() {
        let state = make_state();
        create(&state, "ns-sub").await;
        let mut ns = stored(&state, "ns-sub").await;
        ns["status"] = serde_json::json!({"phase": "Active",
            "conditions": [{"type": "NamespaceFinalizersRemaining", "status": "True"}]});
        put_namespace_status(
            State(state.clone()),
            Path("ns-sub".into()),
            headers("application/json", "ns-controller/1.0"),
            Bytes::from(ns.to_string()),
        )
        .await
        .unwrap_or_else(|e| panic!("status put: {e:?}"));
        finalize_namespace(
            State(state.clone()),
            Path("ns-sub".into()),
            headers("application/json", "ns-finalizer/1.0"),
            Bytes::from(r#"{"spec":{"finalizers":["kubernetes","example.com/x"]}}"#),
        )
        .await
        .unwrap_or_else(|e| panic!("finalize: {e:?}"));

        let after = stored(&state, "ns-sub").await;
        assert!(manager(&after, "ns-controller", Some("status")).is_some());
        assert!(manager(&after, "ns-finalizer", Some("finalize")).is_some());
    }
}
