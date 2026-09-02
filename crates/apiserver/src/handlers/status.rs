use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use serde::Deserialize;
use u7s_store::Store;

use crate::{
    auth::UserInfo,
    keys::group_object_key,
    state::AppState,
    status::Status,
    types::Object,
    util::{content_type, extract_body, parse_resource_version},
};

use super::generic::{lookup, store_err, validate_name};
use super::json_patch::{apply_json_patch, detect_patch_type, ssa_body_to_json, PatchType};
use super::resource::{get_namespaced_resource, get_resource, inject_type_meta};

/// Merge incoming metadata onto the current object's metadata, preserving fields that
/// must never change via a status subresource write.
///
/// Protected fields: identity fields (name, namespace, uid, creationTimestamp,
/// resourceVersion, generation) AND lifecycle-control fields (finalizers,
/// deletionTimestamp). A status write that changes finalizers can restore a finalizer
/// a peer controller just removed, causing livelock where the object stays Terminating
/// forever.
///
/// `labels` is also protected: labels drive policy decisions elsewhere (Namespace's
/// `pod-security.kubernetes.io/enforce`, selector-based webhook/NetworkPolicy matching),
/// so a caller with only `<resource>/status` rights must not be able to rewrite them via
/// a merge/strategic-merge-patch or PUT to /status — the same RBAC-isolation rule that
/// `validate_status_json_patch_paths` already enforces for JSON Patch. `annotations` stays
/// unprotected: CronJob and other controllers rely on setting annotations via /status, and
/// annotations do not gate policy the way labels do.
///
/// `Node` is the one built-in exception to the `labels` rule: upstream's
/// `nodeStatusStrategy.PrepareForUpdate` (pkg/registry/core/node/strategy.go) only resets
/// `.spec` on a status update and deliberately leaves labels alone, because kubelet holds
/// only `nodes/status` RBAC and relies on exactly this path (`nodeinfomanager.go`'s
/// `updateNode`/`PatchNodeStatus`) to publish arch/os labels and CSI topology labels.
/// Protecting labels here for Node silently drops those labels and breaks CSI
/// topology-aware provisioning: the external-provisioner sidecar can never find a node
/// carrying the driver's topology key, so PVCs never leave Pending.
///
/// Restore semantics: if the field was absent (null) in the stored object, the field is
/// removed after merge even if the incoming body added it. If it was present, it is
/// restored to its stored value unconditionally.
pub(crate) fn merge_incoming_metadata(
    current: &mut serde_json::Value,
    incoming: &serde_json::Value,
    kind: &str,
) {
    let incoming_meta = &incoming["metadata"];
    if !incoming_meta.is_object() {
        return;
    }
    const PROTECTED: &[&str] = &[
        "name",
        "namespace",
        "uid",
        "creationTimestamp",
        "resourceVersion",
        "generation",
        "finalizers",
        "deletionTimestamp",
        "labels",
    ];
    let saved: Vec<(&str, serde_json::Value)> = PROTECTED
        .iter()
        .filter(|&&k| !(kind == "Node" && k == "labels"))
        .map(|&k| (k, current["metadata"][k].clone()))
        .collect();

    crate::patch::merge_patch(&mut current["metadata"], incoming_meta);

    for (k, v) in saved {
        if v.is_null() {
            if let Some(meta_obj) = current["metadata"].as_object_mut() {
                meta_obj.remove(k);
            }
        } else {
            current["metadata"][k] = v;
        }
    }
}

// -- cluster-scoped --

pub async fn get_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    // Same as get_resource; status is embedded in the object. Table format is a
    // `kubectl get <resource>` concern, not applicable to the /status subresource, so
    // no Accept header is forwarded here.
    get_resource(
        State(state),
        Path((group, version, plural, name)),
        HeaderMap::new(),
    )
    .await
}

pub async fn put_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("name", &name)?;
    let meta = lookup(&state, &group, &version, &plural)?.clone();
    let body = extract_body(&body, content_type(&headers));
    let incoming =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = group_object_key(&group, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;
    // node_authz's own doc comment on restrict_node_self_write: upstream's NodeRestriction
    // admission plugin runs on every subresource, not just the main resource — a
    // `system:node:<name>` identity holding only `nodes/status` RBAC (which is all kubelet
    // ever needs) could otherwise set a `node-restriction.kubernetes.io/*` label through this
    // path even though the main-resource PUT/PATCH above already blocks it.
    let node_before = if group.is_empty() && plural == "nodes" {
        Some(current.body.clone())
    } else {
        None
    };

    // Replace status and merge metadata; leave spec and identity fields untouched.
    replace_status_field(&mut current.body, &incoming.body["status"])?;
    merge_incoming_metadata(&mut current.body, &incoming.body, &meta.kind);

    if let Some(ref old_node) = node_before {
        crate::node_authz::restrict_node_self_write(
            &user.username,
            &user.groups,
            &name,
            Some(old_node),
            &current.body,
        )
        .map_err(Status::forbidden)?;
    }

    let expected_rv = parse_resource_version(incoming.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    current.set_resource_version(new_rv);
    inject_type_meta(&mut current.body, &group, &version, &meta.kind);
    Ok(Json(current.body))
}

pub async fn patch_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("name", &name)?;
    let meta = lookup(&state, &group, &version, &plural)?.clone();
    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");

    let key = group_object_key(&group, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &meta.kind))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;
    // See put_resource_status's node_before comment: same gap applies to PATCH /status.
    let node_before = if group.is_empty() && plural == "nodes" {
        Some(current.body.clone())
    } else {
        None
    };

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
            validate_status_json_patch_paths(&patch)?;
            apply_json_patch(&mut current.body, &patch)?;
        }
        _ => {
            // Merge and strategic merge: apply status and metadata from the patch body.
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
            merge_incoming_metadata(&mut current.body, &patch, &meta.kind);
        }
    }
    // Convergence point for every patch content-type above (JSON Patch, merge, strategic
    // merge): guard once here, right before the store write, instead of per-branch. A
    // per-branch guard covered merge/strategic-merge but missed PatchType::Json, since
    // `validate_status_json_patch_paths` permits a whole-`/status` replace and
    // `apply_json_patch` happily turns that into a scalar.
    reject_non_object_status(&current.body["status"])?;

    if let Some(ref old_node) = node_before {
        crate::node_authz::restrict_node_self_write(
            &user.username,
            &user.groups,
            &name,
            Some(old_node),
            &current.body,
        )
        .map_err(Status::forbidden)?;
    }

    let expected_rv = parse_resource_version(patch["metadata"]["resourceVersion"].as_str())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &meta.kind))?;

    current.set_resource_version(new_rv);
    inject_type_meta(&mut current.body, &group, &version, &meta.kind);
    Ok(Json(current.body))
}

/// Typed view of just the `kind` field, used by the CR-fallback /status handlers
/// below to recover the real kind from the stored object when the static resource
/// registry has no entry for this group (so `lookup` can't supply one).
#[derive(Debug, Deserialize)]
struct StatusEnvelope {
    kind: String,
}

// -- namespaced --

pub async fn get_namespaced_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    // Same as get_namespaced_resource; status is embedded in the object. Table format is a
    // `kubectl get <resource>` concern, not applicable to the /status subresource, so
    // no Accept header is forwarded here.
    get_namespaced_resource(
        State(state),
        Path((group, version, ns, plural, name)),
        HeaderMap::new(),
    )
    .await
}

pub async fn put_namespaced_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    validate_name("name", &name)?;
    let body = extract_body(&body, content_type(&headers));
    let incoming =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // CR fallback: if the resource is not in the registry (e.g. Gateway API CRDs), fall back
    // to the CR storage key. This allows Gateway/GatewayClass controllers to PUT status on
    // their custom resources using the same /status route as built-in types.
    let (key, kind_fallback) = match lookup(&state, &group, &version, &plural) {
        Ok(meta) => (
            group_object_key(&group, &plural, Some(&ns), &name),
            meta.kind.clone(),
        ),
        Err(_) => {
            // CR fallback: CRs are stored under /registry/cr/<group>/<plural>/<ns>/<name> —
            // version-independent, matching cr_store_key (a CR's storage location must not
            // depend on which served version this request names).
            let cr_key = format!("/registry/cr/{group}/{plural}/{ns}/{name}");
            (cr_key, plural.clone())
        }
    };

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &kind_fallback))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let kind = StatusEnvelope::deserialize(&current.body)
        .map(|e| e.kind)
        .unwrap_or(kind_fallback);

    replace_status_field(&mut current.body, &incoming.body["status"])?;
    merge_incoming_metadata(&mut current.body, &incoming.body, &kind);

    let expected_rv = parse_resource_version(incoming.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &kind))?;

    current.set_resource_version(new_rv);
    inject_type_meta(&mut current.body, &group, &version, &kind);
    Ok(Json(current.body))
}

pub async fn patch_namespaced_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("namespace", &ns)?;
    validate_name("name", &name)?;
    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");

    let (key, kind_fallback) = match lookup(&state, &group, &version, &plural) {
        Ok(meta) => (
            group_object_key(&group, &plural, Some(&ns), &name),
            meta.kind.clone(),
        ),
        Err(_) => {
            // CR fallback: CRs are stored under /registry/cr/<group>/<plural>/<ns>/<name> —
            // version-independent, matching cr_store_key (a CR's storage location must not
            // depend on which served version this request names).
            (
                format!("/registry/cr/{group}/{plural}/{ns}/{name}"),
                plural.clone(),
            )
        }
    };

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &plural))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let kind = StatusEnvelope::deserialize(&current.body)
        .map(|e| e.kind)
        .unwrap_or(kind_fallback);

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
            validate_status_json_patch_paths(&patch)?;
            apply_json_patch(&mut current.body, &patch)?;
        }
        _ => {
            // Merge and strategic merge: apply status and metadata from the patch body.
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
            merge_incoming_metadata(&mut current.body, &patch, &kind);
        }
    }
    // Convergence point for every patch content-type above (JSON Patch, merge, strategic
    // merge): guard once here, right before the store write, instead of per-branch. A
    // per-branch guard covered merge/strategic-merge but missed PatchType::Json, since
    // `validate_status_json_patch_paths` permits a whole-`/status` replace and
    // `apply_json_patch` happily turns that into a scalar.
    reject_non_object_status(&current.body["status"])?;

    let expected_rv = parse_resource_version(patch["metadata"]["resourceVersion"].as_str())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, &kind))?;

    current.set_resource_version(new_rv);
    inject_type_meta(&mut current.body, &group, &version, &kind);
    Ok(Json(current.body))
}

/// A resource's `status` is always a message/object type in the Kubernetes API — never a
/// scalar or array. `merge_patch` (RFC 7396) legitimately replaces `target` wholesale
/// whenever `patch` is not itself an object, so a merge-patch body like `{"status":"x"}`
/// would otherwise silently persist a scalar `status`. That corrupts the object's own
/// schema and, worse, panics any code that later stamps status fields in place via
/// `obj.body["status"]["field"] = ...` (e.g. `apply_delete_policy`), crashing the apiserver.
/// Reject before it's ever written to the store.
///
/// `null` is explicitly ALLOWED (not rejected): `{"status": null}` is RFC 7396's own
/// field-deletion syntax, not an invalid scalar — a merge-patch that clears status
/// entirely is legitimate and must not 422.
pub(crate) fn reject_non_object_status(
    status: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    if status.is_object() || status.is_null() {
        return Ok(());
    }
    Err(Status::unprocessable_entity(format!(
        "status must be an object, got {status}"
    )))
}

/// Shared PUT-/status body: replace `current`'s `status` field with `incoming_status`
/// (null removes the field — a PUT's own field-clearing convention), or reject with 422
/// if `incoming_status` is a present-but-non-object scalar/array. Every PUT /status
/// handler in this codebase (`put_resource_status`, `put_namespaced_resource_status`,
/// `put_cr_status`, `put_crd_status`, `replace_pod_status`) round-trips through here
/// instead of assigning `current["status"] = incoming_status.clone()` inline, so the
/// object-type invariant `reject_non_object_status` enforces for merge-patch status
/// writes cannot be missed for a PUT handler the way it was in two prior review rounds.
pub(crate) fn replace_status_field(
    current: &mut serde_json::Value,
    incoming_status: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    reject_non_object_status(incoming_status)?;
    match incoming_status {
        serde_json::Value::Null => {
            if let Some(m) = current.as_object_mut() {
                m.remove("status");
            }
        }
        v => {
            current["status"] = v.clone();
        }
    }
    Ok(())
}

/// Validate that every op in a JSON Patch sent to a /status subresource targets
/// only `/status/...`. A client with `patch <res>/status` must not be able to write
/// spec OR metadata via this endpoint — both are privilege escalation: `/spec` lets a
/// status-only grant control the resource's desired state, and `/metadata` (e.g.
/// `/metadata/labels`) lets it rewrite labels that drive policy decisions elsewhere
/// (for Namespace, the pod-security.kubernetes.io/enforce label PSA reads).
///
/// Returns 422 if any op path is outside `/status`.
pub(crate) fn validate_status_json_patch_paths(
    patch: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let ops = patch
        .as_array()
        .ok_or_else(|| Status::unprocessable_entity("JSON patch must be an array".into()))?;
    for op in ops {
        let path = op["path"].as_str().ok_or_else(|| {
            Status::unprocessable_entity("JSON patch op missing 'path' field".into())
        })?;
        if !path.starts_with("/status/") && path != "/status" {
            return Err(Status::unprocessable_entity(format!(
                "JSON patch on /status subresource may only target /status paths; got '{path}'"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use u7s_store::SqliteStore;

    use crate::handlers::test_support::make_state;

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

    /// A non-node identity: restrict_node_self_write is a no-op for anyone but a genuine
    /// `system:node:<name>`, so this is the safe default for every test that isn't itself
    /// exercising node self-write restriction.
    fn test_user() -> UserInfo {
        UserInfo {
            username: "test-user".into(),
            uid: "test-uid".into(),
            groups: vec!["system:authenticated".into()],
            extra: Default::default(),
        }
    }

    fn node_user(name: &str) -> UserInfo {
        UserInfo {
            username: format!("system:node:{name}"),
            uid: "kubelet-uid".into(),
            groups: vec!["system:nodes".into()],
            extra: Default::default(),
        }
    }

    /// get_resource_status returns 404 when the cluster-scoped object does not exist.
    /// Status reads delegate to get_resource; a missing object must never return 200.
    #[tokio::test]
    async fn get_resource_status_returns_404_for_missing() {
        let state = make_state();
        let result = get_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "nonexistent".into(),
            )),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// get_resource_status returns the stored object (same as get_resource) when it exists.
    /// Controllers read status via this path; returning the full object is correct.
    #[tokio::test]
    async fn get_resource_status_returns_stored_object() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1" },
            "spec": { "drivers": [] },
            "status": { "ready": true }
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
        let result = get_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-1".into(),
            )),
        )
        .await;
        let resp = match result {
            Ok(r) => r,
            Err(_) => panic!("get_resource_status must succeed when object exists"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    /// put_resource_status returns 404 when the cluster-scoped object does not exist.
    /// Controllers must not create objects via the status subresource.
    #[tokio::test]
    async fn put_resource_status_returns_404_for_missing_resource() {
        let state = make_state();
        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "nonexistent" },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "nonexistent".into(),
            )),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// put_resource_status with a null status body removes the status field.
    /// When a controller explicitly sets status=null, the field must be removed
    /// rather than set to null — Kubernetes serializes absent and null fields differently.
    #[tokio::test]
    async fn put_resource_status_null_status_removes_field() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-3" },
            "spec": { "drivers": [] },
            "status": { "ready": true }
        });
        let key = "/registry/storage.k8s.io/csinodes/worker-3";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
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

        // PUT body with explicit null status (JSON: "status": null)
        let null_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-3" },
            "status": null
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-3".into(),
            )),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&null_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "put with null status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v.get("status").is_none(),
            "null status in PUT body must remove the status field from the stored object"
        );
    }

    /// put_resource_status with a scalar or array `status` body must be rejected with 422,
    /// not persisted. `status` is a message/object type for every resource; a PUT that
    /// wholesale-replaces it with a scalar corrupts the object's own schema and panics any
    /// later in-place status stamper (e.g. `apply_delete_policy`) that indexes
    /// `["status"]["field"]` on it, crashing the apiserver for every other request in flight.
    #[tokio::test]
    async fn put_resource_status_rejects_non_object_status() {
        for bad_status in [serde_json::json!("x"), serde_json::json!(["a", "b"])] {
            let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
            let csinode = serde_json::json!({
                "apiVersion": "storage.k8s.io/v1",
                "kind": "CSINode",
                "metadata": { "name": "put-scalar-node" },
                "spec": { "drivers": [] },
                "status": { "ready": true }
            });
            let key = "/registry/storage.k8s.io/csinodes/put-scalar-node";
            store
                .put(
                    key,
                    bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
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

            let bad_body = serde_json::json!({
                "apiVersion": "storage.k8s.io/v1",
                "kind": "CSINode",
                "metadata": { "name": "put-scalar-node" },
                "status": bad_status
            });
            let result = put_resource_status(
                axum::extract::State(state),
                axum::extract::Path((
                    "storage.k8s.io".into(),
                    "v1".into(),
                    "csinodes".into(),
                    "put-scalar-node".into(),
                )),
                axum::Extension(test_user()),
                json_headers(),
                bytes::Bytes::from(serde_json::to_vec(&bad_body).unwrap()),
            )
            .await;

            let err = match result {
                Err(e) => e,
                Ok(_) => panic!(
                    "a non-object status ({bad_status}) via PUT must be rejected, not \
                     persisted — it would corrupt the object's schema and later crash any \
                     in-place status stamper"
                ),
            };
            assert_eq!(
                err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "a non-object status must be rejected with 422, matching upstream schema \
                 validation: got {bad_status}"
            );

            let stored = store.get(key).await.unwrap().unwrap();
            let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
            assert_eq!(
                v["status"]["ready"], true,
                "the rejected PUT must not have been persisted — status must remain the \
                 original object for input {bad_status}"
            );
        }
    }

    /// patch_resource_status returns 404 when cluster-scoped object does not exist.
    /// Controllers must receive an unambiguous error so they know the resource is gone.
    #[tokio::test]
    async fn patch_resource_status_returns_404_for_missing_resource() {
        let state = make_state();
        let patch = serde_json::json!({"status": {"phase": "Failed"}});
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "nonexistent".into(),
            )),
            axum::Extension(test_user()),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// get_namespaced_resource_status returns the stored object when it exists.
    /// Namespaced controllers (e.g. Deployment controller) read status via this path.
    #[tokio::test]
    async fn get_namespaced_resource_status_returns_stored_object() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-x", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "node-x" }
        });
        store
            .put(
                "/registry/coordination.k8s.io/leases/kube-node-lease/node-x",
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
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
        let result = get_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "node-x".into(),
            )),
        )
        .await;
        let resp = match result {
            Ok(r) => r,
            Err(_) => panic!("get_namespaced_resource_status must succeed when object exists"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    /// get_namespaced_resource_status returns 404 when the object does not exist.
    #[tokio::test]
    async fn get_namespaced_resource_status_returns_404_for_missing() {
        let state = make_state();
        let result = get_namespaced_resource_status(
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
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// put_namespaced_resource_status updates only the status field for a registered resource.
    /// The spec must remain unchanged — status isolation is critical for controllers.
    #[tokio::test]
    async fn put_namespaced_resource_status_updates_status() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-y", "namespace": "kube-node-lease", "resourceVersion": "1" },
            "spec": { "holderIdentity": "node-y", "leaseDurationSeconds": 40 }
        });
        store
            .put(
                "/registry/coordination.k8s.io/leases/kube-node-lease/node-y",
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
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
        let put_body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-y", "namespace": "kube-node-lease" },
            "status": { "phase": "Active" }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "node-y".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "put_namespaced_resource_status must succeed"
        );
        let stored = store
            .get("/registry/coordination.k8s.io/leases/kube-node-lease/node-y")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Active");
        assert_eq!(v["spec"]["holderIdentity"], "node-y");
    }

    /// put_namespaced_resource_status returns 404 when the object does not exist.
    #[tokio::test]
    async fn put_namespaced_resource_status_returns_404_for_missing() {
        let state = make_state();
        let body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "missing", "namespace": "kube-node-lease" },
            "status": { "phase": "Active" }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "missing".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// put_namespaced_resource_status with null status removes the status field.
    /// Same semantics as the cluster-scoped variant — controllers can clear status.
    #[tokio::test]
    async fn put_namespaced_resource_status_null_status_removes_field() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-z", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "node-z" },
            "status": { "phase": "Active" }
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/node-z";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
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

        let null_body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-z", "namespace": "kube-node-lease" },
            "status": null
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "node-z".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&null_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "put with null status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v.get("status").is_none(),
            "null status in PUT body must remove the status field"
        );
    }

    /// put_namespaced_resource_status with a scalar or array `status` body must be rejected
    /// with 422, not persisted — same protection as the cluster-scoped handler above, on the
    /// namespaced route most real resources (Deployments, Leases, ...) actually use.
    #[tokio::test]
    async fn put_namespaced_resource_status_rejects_non_object_status() {
        for bad_status in [serde_json::json!("x"), serde_json::json!(["a", "b"])] {
            let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
            let lease = serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": { "name": "put-scalar-lease", "namespace": "kube-node-lease" },
                "spec": { "holderIdentity": "put-scalar-lease" },
                "status": { "phase": "Active" }
            });
            let key = "/registry/coordination.k8s.io/leases/kube-node-lease/put-scalar-lease";
            store
                .put(
                    key,
                    bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
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

            let bad_body = serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": { "name": "put-scalar-lease", "namespace": "kube-node-lease" },
                "status": bad_status
            });
            let result = put_namespaced_resource_status(
                axum::extract::State(state),
                axum::extract::Path((
                    "coordination.k8s.io".into(),
                    "v1".into(),
                    "kube-node-lease".into(),
                    "leases".into(),
                    "put-scalar-lease".into(),
                )),
                json_headers(),
                bytes::Bytes::from(serde_json::to_vec(&bad_body).unwrap()),
            )
            .await;

            let err = match result {
                Err(e) => e,
                Ok(_) => panic!(
                    "a non-object status ({bad_status}) via PUT must be rejected, not persisted"
                ),
            };
            assert_eq!(
                err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "a non-object status must be rejected with 422: got {bad_status}"
            );

            let stored = store.get(key).await.unwrap().unwrap();
            let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
            assert_eq!(
                v["status"]["phase"], "Active",
                "the rejected PUT must not have been persisted for input {bad_status}"
            );
        }
    }

    /// patch_namespaced_resource_status with merge-patch updates the status field.
    /// This is the primary path used by namespaced controllers to report status.
    #[tokio::test]
    async fn patch_namespaced_resource_status_with_merge_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "node-w", "namespace": "kube-node-lease", "resourceVersion": "1" },
            "spec": { "holderIdentity": "node-w" },
            "status": {}
        });
        store
            .put(
                "/registry/coordination.k8s.io/leases/kube-node-lease/node-w",
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
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
        let patch = serde_json::json!({"status": {"phase": "Bound"}});
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "node-w".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "patch_namespaced_resource_status must succeed"
        );
        let stored = store
            .get("/registry/coordination.k8s.io/leases/kube-node-lease/node-w")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Bound");
        assert_eq!(v["spec"]["holderIdentity"], "node-w");
    }

    /// patch_resource_status with strategic-merge-patch applies the status portion only.
    #[tokio::test]
    async fn patch_resource_status_with_strategic_merge_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "smp-node" },
            "spec": { "drivers": [] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/smp-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
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

        let mut smp_headers = axum::http::HeaderMap::new();
        smp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        let patch =
            serde_json::json!({"status": {"conditions": [{"type": "Ready", "status": "True"}]}});

        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "smp-node".into(),
            )),
            axum::Extension(test_user()),
            smp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "strategic-merge-patch on status must succeed"
        );
    }

    /// patch_resource_status must accept a genuine multi-line YAML apply-patch+yaml body,
    /// not just a JSON body wearing the +yaml content-type.
    ///
    /// WHY this matters: `kubectl apply --server-side` against a /status subresource
    /// (e.g. e2e ApplyStatus()) sends real YAML block syntax. Before this fix,
    /// patch_resource_status had no is_ssa handling at all — every apply-patch+yaml body
    /// was parsed with serde_json::from_slice, which rejects YAML outright with "invalid
    /// patch JSON", so ApplyStatus() 400'd on every call.
    #[tokio::test]
    async fn patch_resource_status_accepts_real_yaml_apply_patch_body() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "ssa-node" },
            "spec": { "drivers": [] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/ssa-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
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

        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );
        // Genuine YAML block syntax — NOT JSON serialized to bytes.
        let yaml_body = b"status:\n  conditions:\n  - type: Ready\n    status: \"True\"\n".to_vec();

        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "ssa-node".into(),
            )),
            axum::Extension(test_user()),
            ssa_headers,
            bytes::Bytes::from(yaml_body),
        )
        .await;
        assert!(
            result.is_ok(),
            "apply-patch+yaml with a genuine YAML body on /status must succeed, not 400 \
             'invalid patch JSON': {:?}",
            result.err()
        );
    }

    /// patch_namespaced_resource_status with strategic-merge-patch.
    #[tokio::test]
    async fn patch_namespaced_resource_status_with_strategic_merge_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "smp-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "smp-lease" },
            "status": {}
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/smp-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
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

        let mut smp_headers = axum::http::HeaderMap::new();
        smp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        let patch = serde_json::json!({"status": {"conditions": [{"type": "Available", "status": "True"}]}});

        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "smp-lease".into(),
            )),
            smp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "strategic-merge-patch on namespaced status must succeed"
        );
    }

    /// patch_namespaced_resource_status must accept a genuine multi-line YAML
    /// apply-patch+yaml body, not just a JSON body wearing the +yaml content-type.
    ///
    /// WHY this matters: same ApplyStatus() SSA gap as the cluster-scoped test above,
    /// but for namespaced resources (e.g. Deployment/status, which conformance also
    /// applies via SSA).
    #[tokio::test]
    async fn patch_namespaced_resource_status_accepts_real_yaml_apply_patch_body() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "ssa-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "ssa-lease" },
            "status": {}
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/ssa-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
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

        let mut ssa_headers = axum::http::HeaderMap::new();
        ssa_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );
        // Genuine YAML block syntax — NOT JSON serialized to bytes.
        let yaml_body =
            b"status:\n  conditions:\n  - type: Available\n    status: \"True\"\n".to_vec();

        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "ssa-lease".into(),
            )),
            ssa_headers,
            bytes::Bytes::from(yaml_body),
        )
        .await;
        assert!(
            result.is_ok(),
            "apply-patch+yaml with a genuine YAML body on namespaced /status must succeed, \
             not 400 'invalid patch JSON': {:?}",
            result.err()
        );
    }

    /// patch_namespaced_resource_status returns 404 when the object does not exist.
    #[tokio::test]
    async fn patch_namespaced_resource_status_returns_404_for_missing() {
        let state = make_state();
        let patch = serde_json::json!({"status": {"phase": "Failed"}});
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "nonexistent".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 404 error"),
        };
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// put_resource_status replaces only the status field, leaving spec untouched.
    /// Status subresource isolation is required so that controllers cannot accidentally
    /// overwrite spec data when updating status (and vice versa).
    #[tokio::test]
    async fn put_resource_status_replaces_status_only() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a CSINode in the store.
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1", "resourceVersion": "1" },
            "spec": { "drivers": [{"name": "csi.io", "nodeID": "worker-1"}] }
        });
        let key = "/registry/storage.k8s.io/csinodes/worker-1";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        let put_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1" },
            "status": { "allocatable": {"count": 10} }
        });

        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-1".into(),
            )),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        assert!(result.is_ok(), "put_resource_status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["allocatable"]["count"], 10);
        assert_eq!(v["spec"]["drivers"][0]["name"], "csi.io");
    }

    /// patch_resource_status with merge-patch updates only the status sub-field.
    #[tokio::test]
    async fn patch_resource_status_merge_patch_updates_status() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
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
            "metadata": { "name": "worker-2", "resourceVersion": "1" },
            "spec": { "drivers": [{"name": "csi.io", "nodeID": "worker-2"}] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/worker-2";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        let patch = serde_json::json!({"status": {"phase": "Ready"}});
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "worker-2".into(),
            )),
            axum::Extension(test_user()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        assert!(result.is_ok(), "patch_resource_status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Ready");
        assert_eq!(v["spec"]["drivers"][0]["name"], "csi.io");
    }

    /// patch_resource_status with a merge-patch body `{"status":"x"}` must be rejected with
    /// 422, not persisted.
    ///
    /// WHY this matters: `status` is a message/object type for every Kubernetes resource.
    /// `merge_patch` (RFC 7396) legitimately replaces the whole target with the patch value
    /// whenever the patch is not itself an object, so without this check a scalar `status`
    /// would silently overwrite the object's status field. That corrupts the stored object's
    /// own schema AND panics `apply_delete_policy`'s in-place `status["phase"] = ...` stamp on
    /// the next DELETE of this object — crashing the apiserver for every other request in
    /// flight, not just failing this one write.
    #[tokio::test]
    async fn patch_resource_status_rejects_scalar_status_merge_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
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
            "metadata": { "name": "scalar-status-node", "resourceVersion": "1" },
            "spec": { "drivers": [] },
            "status": { "phase": "Ready" }
        });
        let key = "/registry/storage.k8s.io/csinodes/scalar-status-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        let patch = serde_json::json!({"status": "x"});
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "scalar-status-node".into(),
            )),
            axum::Extension(test_user()),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "a scalar status merge-patch must be rejected, not accepted — it would \
                 corrupt the object's schema and later crash apply_delete_policy on DELETE"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "a scalar status must be rejected with 422, matching upstream schema validation"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["phase"], "Ready",
            "the rejected patch must not have been persisted — status must remain the \
             original object"
        );
    }

    /// `validate_status_json_patch_paths` explicitly permits a JSON Patch op whose path is
    /// exactly `/status` (a whole-status replace, not a sub-field), so a
    /// `[{"op":"replace","path":"/status","value":"x"}]` body must be rejected the same way
    /// the merge-patch equivalent above is — same corrupted-schema-then-apiserver-panic
    /// outcome, just reached via a different content-type. This is the gap two prior review
    /// rounds each closed for the merge/strategic-merge branch but left open here.
    #[tokio::test]
    async fn patch_resource_status_rejects_scalar_status_json_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
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
            "metadata": { "name": "scalar-status-jp-node", "resourceVersion": "1" },
            "spec": { "drivers": [] },
            "status": { "phase": "Ready" }
        });
        let key = "/registry/storage.k8s.io/csinodes/scalar-status-jp-node";
        store
            .put(
                key,
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
        let patch = serde_json::json!([{"op": "replace", "path": "/status", "value": "x"}]);
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "scalar-status-jp-node".into(),
            )),
            axum::Extension(test_user()),
            jp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "a JSON Patch replacing /status with a scalar must be rejected, not \
                 accepted — it would corrupt the object's schema and later crash \
                 apply_delete_policy on DELETE"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "a scalar status must be rejected with 422, matching the merge-patch behavior"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["phase"], "Ready",
            "the rejected patch must not have been persisted — status must remain the \
             original object"
        );
    }

    /// patch_resource_status with a merge-patch body `{"status": null}` must be ACCEPTED,
    /// not 422'd. `null` is RFC 7396's own field-deletion syntax, not an invalid scalar —
    /// a controller clearing status entirely via /status is legitimate traffic that must
    /// not be confused with the scalar-status attack the 422 check above exists to reject.
    #[tokio::test]
    async fn patch_resource_status_accepts_null_status_as_field_deletion() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
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
            "metadata": { "name": "null-status-node", "resourceVersion": "1" },
            "spec": { "drivers": [] },
            "status": { "phase": "Ready" }
        });
        let key = "/registry/storage.k8s.io/csinodes/null-status-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        let patch = serde_json::json!({"status": null});
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "null-status-node".into(),
            )),
            axum::Extension(test_user()),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "a null status merge-patch is RFC 7396 field deletion, not a 422: {:?}",
            result.err()
        );
    }

    /// patch_namespaced_resource_status with a merge-patch body `{"status":"x"}` must be
    /// rejected with 422, not persisted — same protection as the cluster-scoped handler above,
    /// exercised on the namespaced route since most real resources (Deployments, Leases, etc.)
    /// are namespaced.
    #[tokio::test]
    async fn patch_namespaced_resource_status_rejects_scalar_status_merge_patch() {
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
            "metadata": { "name": "scalar-status-lease", "namespace": "kube-node-lease", "resourceVersion": "1" },
            "spec": { "holderIdentity": "scalar-status-lease" },
            "status": { "phase": "Active" }
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/scalar-status-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();

        let patch = serde_json::json!({"status": "x"});
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "scalar-status-lease".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("a scalar status merge-patch must be rejected, not accepted"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "a scalar status must be rejected with 422, matching upstream schema validation"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["phase"], "Active",
            "the rejected patch must not have been persisted — status must remain the \
             original object"
        );
    }

    /// patch_namespaced_resource_status with a JSON Patch body
    /// `[{"op":"replace","path":"/status","value":"x"}]` must be rejected too — same
    /// `validate_status_json_patch_paths` whole-`/status`-replace gap as the cluster-scoped
    /// handler, exercised on the namespaced route.
    #[tokio::test]
    async fn patch_namespaced_resource_status_rejects_scalar_status_json_patch() {
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
            "metadata": { "name": "scalar-status-jp-lease", "namespace": "kube-node-lease", "resourceVersion": "1" },
            "spec": { "holderIdentity": "scalar-status-jp-lease" },
            "status": { "phase": "Active" }
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/scalar-status-jp-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
                None,
            )
            .await
            .unwrap();

        let mut jp_headers = axum::http::HeaderMap::new();
        jp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );
        let patch = serde_json::json!([{"op": "replace", "path": "/status", "value": "x"}]);
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "scalar-status-jp-lease".into(),
            )),
            jp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "a JSON Patch replacing /status with a scalar must be rejected, not accepted"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "a scalar status must be rejected with 422, matching the merge-patch behavior"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["phase"], "Active",
            "the rejected patch must not have been persisted — status must remain the \
             original object"
        );
    }

    /// patch_resource_status with JSON Patch (`application/json-patch+json`) applies operations
    /// on the full document. JSON Patch addresses the /status prefix explicitly.
    #[tokio::test]
    async fn patch_resource_status_with_json_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "jp-node" },
            "spec": { "drivers": [] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/jp-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
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
        let patch = serde_json::json!([
            {"op": "add", "path": "/status/ready", "value": true}
        ]);

        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "jp-node".into(),
            )),
            axum::Extension(test_user()),
            jp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "JSON patch on status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["ready"], true);
    }

    /// patch_namespaced_resource_status with JSON Patch applies operations on the full document.
    #[tokio::test]
    async fn patch_namespaced_resource_status_with_json_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let lease = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "jp-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "jp-lease" },
            "status": {}
        });
        let key = "/registry/coordination.k8s.io/leases/kube-node-lease/jp-lease";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&lease).unwrap()),
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
        let patch = serde_json::json!([
            {"op": "add", "path": "/status/phase", "value": "Bound"}
        ]);

        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "coordination.k8s.io".into(),
                "v1".into(),
                "kube-node-lease".into(),
                "leases".into(),
                "jp-lease".into(),
            )),
            jp_headers,
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "JSON patch on namespaced status must succeed"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Bound");
    }

    // OCC is enforced by SqliteStore::put's CAS; tested in crates/store/src/lib.rs.

    /// put_namespaced_resource_status uses the CR fallback key when the group is not
    /// in the static resource registry. This allows CRD-backed controllers (e.g. cert-manager)
    /// to update status on their custom resources via the same /status route as built-in types.
    #[tokio::test]
    async fn put_namespaced_resource_status_uses_cr_fallback_key_for_unknown_group() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        // Store a CR under the CR fallback key path.
        // "certificates.cert-manager.io" is not in the static registry, so the handler
        // must fall back to /registry/cr/<group>/<plural>/<ns>/<name> (version-independent —
        // see cr_store_key).
        let cert = serde_json::json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": { "name": "my-cert", "namespace": "default" },
            "spec": { "secretName": "my-tls" }
        });
        let cr_key = "/registry/cr/cert-manager.io/certificates/default/my-cert";
        store
            .put(
                cr_key,
                bytes::Bytes::from(serde_json::to_vec(&cert).unwrap()),
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

        let put_body = serde_json::json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": { "name": "my-cert", "namespace": "default" },
            "status": { "conditions": [{"type": "Ready", "status": "True"}] }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "cert-manager.io".into(),
                "v1".into(),
                "default".into(),
                "certificates".into(),
                "my-cert".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "put_namespaced_resource_status must succeed via CR fallback key for unknown group"
        );

        let stored = store.get(cr_key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["conditions"][0]["type"], "Ready",
            "status must be updated via CR fallback key"
        );
        // spec must be unchanged — status subresource isolation applies to CRs too
        assert_eq!(
            v["spec"]["secretName"], "my-tls",
            "spec must not be modified"
        );
    }

    /// patch_namespaced_resource_status uses the CR fallback key when the group is not
    /// in the static resource registry. Controllers that manage custom resources must be
    /// able to patch status via the same /status route used for built-in resources.
    #[tokio::test]
    async fn patch_namespaced_resource_status_uses_cr_fallback_key_for_unknown_group() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let cert = serde_json::json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": { "name": "patch-cert", "namespace": "default" },
            "spec": { "secretName": "patch-tls" },
            "status": {}
        });
        let cr_key = "/registry/cr/cert-manager.io/certificates/default/patch-cert";
        store
            .put(
                cr_key,
                bytes::Bytes::from(serde_json::to_vec(&cert).unwrap()),
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

        let patch =
            serde_json::json!({"status": {"conditions": [{"type": "Issued", "status": "True"}]}});
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "cert-manager.io".into(),
                "v1".into(),
                "default".into(),
                "certificates".into(),
                "patch-cert".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "patch_namespaced_resource_status must succeed via CR fallback key for unknown group"
        );

        let stored = store.get(cr_key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["conditions"][0]["type"], "Issued",
            "status must be patched via CR fallback key"
        );
        assert_eq!(
            v["spec"]["secretName"], "patch-tls",
            "spec must not be modified by status patch"
        );
    }

    /// put_resource_status returns 400 when the name parameter is empty.
    /// validate_name runs before any store access, so an empty name is rejected
    /// before touching the database — this prevents path-traversal store key attacks.
    #[tokio::test]
    async fn put_resource_status_rejects_empty_name() {
        let state = make_state();
        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "" },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "".into(), // empty name
            )),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 400 for empty name"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::BAD_REQUEST,
            "empty name must return 400, not reach the store"
        );
    }

    /// Regression test: PATCH resourcequotas/status updates status.used
    /// but must not touch spec.hard.
    ///
    /// The KCM's resourcequota controller patches this endpoint to record how many objects
    /// have been created against each quota. If the patch clobbers spec.hard, the quota's
    /// hard limits are lost and subsequent enforcement checks will allow unlimited creates.
    #[tokio::test]
    async fn patch_resourcequota_status_updates_used_not_spec() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "compute-quota", "namespace": "default", "resourceVersion": "1" },
            "spec": { "hard": { "pods": "10", "services": "5" } },
            "status": { "hard": { "pods": "10", "services": "5" }, "used": { "pods": "0", "services": "0" } }
        });
        let key = "/registry/resourcequotas/default/compute-quota";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&quota).unwrap()),
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

        // KCM quota controller patches status.used after a pod is created.
        let patch = serde_json::json!({
            "status": {
                "hard": { "pods": "10", "services": "5" },
                "used": { "pods": "1", "services": "0" }
            }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "resourcequotas".into(),
                "compute-quota".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PATCH resourcequotas/status must succeed so KCM quota controller can update used counts"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["status"]["used"]["pods"], "1",
            "status.used.pods must be updated to 1 after KCM patches it — \
             if not, kubectl describe quota shows stale counts and conformance polls forever"
        );
        assert_eq!(
            v["spec"]["hard"]["pods"], "10",
            "spec.hard must not be modified by a PATCH to /status — \
             status subresource isolation prevents controllers from accidentally overwriting limits"
        );
        assert_eq!(
            v["spec"]["hard"]["services"], "5",
            "spec.hard.services must survive a PATCH to /status"
        );
    }

    /// Regression test: PATCH/PUT poddisruptionbudgets/status must persist
    /// status.disruptedPods so the DisruptionController conformance test passes.
    ///
    /// The spec '[sig-apps] DisruptionController should update/patch PodDisruptionBudget status'
    /// writes status.disruptedPods['pod-0'] via the PDB /status subresource and reads back the
    /// key. If the handler wipes status (because the incoming proto-decoded body had null status),
    /// the read-back returns an empty map and the conformance test fails with:
    ///   `<map[string]v1.Time | len:0>: nil, expected key 'pod-0'`
    ///
    /// This test operates at the JSON level (the proto-decode layer is tested in proto.rs).
    /// It fails if put_namespaced_resource_status removes status when incoming status is non-null.
    #[tokio::test]
    async fn put_pdb_status_persists_disrupted_pods() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {
                "name": "my-pdb",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": { "minAvailable": 1 }
        });
        let key = "/registry/policy/poddisruptionbudgets/default/my-pdb";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb).unwrap()),
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

        // DisruptionController PUT /status body with disruptedPods set.
        let put_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "my-pdb", "namespace": "default" },
            "status": {
                "disruptedPods": { "pod-0": "2024-01-01T00:00:00Z" },
                "disruptionsAllowed": 0,
                "currentHealthy": 1,
                "desiredHealthy": 1,
                "expectedPods": 1
            }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "policy".into(),
                "v1".into(),
                "default".into(),
                "poddisruptionbudgets".into(),
                "my-pdb".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PUT poddisruptionbudgets/status must succeed — DisruptionController calls this \
             to record disrupted pods"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let disrupted_pods = v["status"]["disruptedPods"].as_object().expect(
            "status.disruptedPods must be present after PUT /status — \
             the conformance test reads it back and expects key 'pod-0'; \
             if missing the test fails with `<map[string]v1.Time | len:0>: nil`",
        );
        assert!(
            disrupted_pods.contains_key("pod-0"),
            "pod-0 must be in status.disruptedPods after PUT /status — \
             the DisruptionController conformance test fails if this key is absent"
        );

        // spec must be unchanged — status subresource isolation applies to PDB too
        assert_eq!(
            v["spec"]["minAvailable"], 1,
            "spec.minAvailable must not be modified by a PUT to /status"
        );
    }

    /// Regression test: PATCH poddisruptionbudgets/status with merge-patch must persist
    /// status.disruptedPods. The DisruptionController may use PATCH instead of PUT.
    ///
    /// This test fails if patch_namespaced_resource_status drops the status field when
    /// applying a merge-patch that includes status.disruptedPods.
    #[tokio::test]
    async fn patch_pdb_status_persists_disrupted_pods() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {
                "name": "patch-pdb",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": { "minAvailable": 2 },
            "status": {}
        });
        let key = "/registry/policy/poddisruptionbudgets/default/patch-pdb";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb).unwrap()),
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

        let patch = serde_json::json!({
            "status": {
                "disruptedPods": { "pod-0": "2024-01-01T00:00:00Z" },
                "disruptionsAllowed": 1,
                "currentHealthy": 2,
                "desiredHealthy": 2,
                "expectedPods": 2
            }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "policy".into(),
                "v1".into(),
                "default".into(),
                "poddisruptionbudgets".into(),
                "patch-pdb".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PATCH poddisruptionbudgets/status must succeed"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let disrupted_pods = v["status"]["disruptedPods"].as_object().expect(
            "status.disruptedPods must survive PATCH /status — \
             the DisruptionController conformance test fails if this field is absent after patch",
        );
        assert!(
            disrupted_pods.contains_key("pod-0"),
            "pod-0 must be in status.disruptedPods after PATCH /status"
        );
        assert_eq!(
            v["spec"]["minAvailable"], 2,
            "spec.minAvailable must not be changed by PATCH /status"
        );
    }

    // ---------------------------------------------------------------------------
    // MockStore — injects RevisionMismatch on the first put() after arm() is called.
    //
    // Using Arc<SqliteStore> for inner so we can clone the handle into the async
    // block without borrowing self (SqliteStore is not Clone).
    // ---------------------------------------------------------------------------

    struct MockStore {
        inner: Arc<SqliteStore>,
        inject_next: std::sync::atomic::AtomicBool,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(SqliteStore::new(":memory:").unwrap()),
                inject_next: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn arm(&self) {
            self.inject_next
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl u7s_store::Store for MockStore {
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
            async move {
                if inject {
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
            // MockStore::watch is not called by the OCC tests (they only test put).
            // Return an empty stream so MockStore compiles as a Store impl.
            // Delegating to inner.watch() is not possible because SqliteStore::watch
            // is async fn taking &self — the desugared future captures &self for its
            // full lifetime, creating a borrow-across-await that the borrow checker
            // rejects inside async move blocks.
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

    /// put_resource_status returns 409 Conflict when the store rejects the write
    /// with RevisionMismatch (OCC: another writer updated the object concurrently).
    ///
    /// The handler must propagate RevisionMismatch as 409, not 500.  Without this
    /// guarantee, controllers that retry on 409 would instead see 500 and stop
    /// retrying, leaving the status field permanently stale.
    #[tokio::test]
    async fn put_resource_status_returns_409_on_revision_mismatch() {
        let mock = Arc::new(MockStore::new());
        // Seed a CSINode via the inner store (bypasses the inject flag).
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "node-occ" },
            "spec": { "drivers": [] }
        });
        mock.inner
            .put(
                "/registry/storage.k8s.io/csinodes/node-occ",
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Arm the mock so the next put() injects RevisionMismatch.
        mock.arm();

        let state = crate::state::AppState::new(
            mock,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "node-occ" },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "node-occ".into(),
            )),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 409 but handler returned Ok"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "RevisionMismatch must produce 409 Conflict so controllers can retry"
        );
    }

    /// put_namespaced_resource_status returns 409 Conflict when the store rejects
    /// the write with RevisionMismatch.
    ///
    /// Same OCC contract as the cluster-scoped variant above, but exercising the
    /// namespaced code path which has its own lookup and put call.
    #[tokio::test]
    async fn put_namespaced_resource_status_returns_409_on_revision_mismatch() {
        let mock = Arc::new(MockStore::new());
        // Seed a Deployment via the inner store.
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "myapp", "namespace": "default" },
            "spec": { "replicas": 1, "selector": {"matchLabels": {"app": "myapp"}}, "template": {} }
        });
        mock.inner
            .put(
                "/registry/apps/deployments/default/myapp",
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Arm the mock so the next put() injects RevisionMismatch.
        mock.arm();

        let state = crate::state::AppState::new(
            mock,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "myapp", "namespace": "default" },
            "status": { "readyReplicas": 1 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "myapp".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected 409 but handler returned Ok"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "RevisionMismatch must produce 409 Conflict so controllers can retry"
        );
    }

    /// Regression test: PATCH /status on a ValidatingAdmissionPolicy must return
    /// exactly what the client sent in the patch, not a hardcoded Ready condition injected by
    /// write_vap_status.
    ///
    /// The conformance test at validatingadmissionpolicy.go:601 PATCHes status.conditions with a
    /// custom condition (PatchStatusFailed) and immediately reads the response body. If
    /// write_vap_status overwrites status after the store write, the client sees Ready instead of
    /// PatchStatusFailed and the conformance test fails.
    #[tokio::test]
    async fn vap_patch_status_preserves_client_conditions_not_overwritten_by_write_vap_status() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let vap = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {
                "name": "test-vap",
                "generation": 1
            },
            "spec": {
                "validations": [{"expression": "true"}]
            },
            "status": {}
        });
        let key = "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/test-vap";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&vap).unwrap()),
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

        // Patch with a custom condition — exactly what the conformance test does.
        let patch = serde_json::json!({
            "status": {
                "conditions": [{"type": "PatchStatusFailed", "status": "False", "reason": "Test"}]
            }
        });
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "admissionregistration.k8s.io".into(),
                "v1".into(),
                "validatingadmissionpolicies".into(),
                "test-vap".into(),
            )),
            axum::Extension(test_user()),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let resp = match result {
            Ok(r) => r.into_response(),
            Err(e) => panic!("PATCH /status on VAP must succeed, got: {e:?}"),
        };
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let conditions = v["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be an array in the response");
        assert_eq!(
            conditions.len(), 1,
            "conformance test polls for a custom status condition after PATCH /status; \
             if write_vap_status overwrites it the test sees Ready instead of PatchStatusFailed and fails"
        );
        assert_eq!(
            conditions[0]["type"], "PatchStatusFailed",
            "conformance test polls for a custom status condition after PATCH /status; \
             if write_vap_status overwrites it the test sees Ready instead of PatchStatusFailed and fails"
        );
    }

    /// PUT /status with metadata.annotations must persist the annotation.
    /// Controllers (e.g. CronJob) set annotations via /status; dropping them causes
    /// the CronJob conformance test to fail because it asserts the annotation is present
    /// after the PUT returns 200.
    #[tokio::test]
    async fn put_namespaced_status_persists_metadata_annotations() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let cronjob = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {
                "name": "test-cj",
                "namespace": "default",
                "uid": "abc-123",
                "resourceVersion": "1"
            },
            "spec": { "schedule": "* * * * *" },
            "status": {}
        });
        let key = "/registry/batch/cronjobs/default/test-cj";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&cronjob).unwrap()),
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

        let put_body = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {
                "name": "test-cj",
                "namespace": "default",
                "annotations": { "patchedstatus": "true" }
            },
            "status": { "active": [] }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "batch".into(),
                "v1".into(),
                "default".into(),
                "cronjobs".into(),
                "test-cj".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["annotations"]["patchedstatus"], "true",
            "annotation set via PUT /status must be stored; \
             dropping it breaks CronJob conformance which sets annotations this way"
        );
        assert_eq!(
            v["status"]["active"],
            serde_json::json!([]),
            "status must be updated"
        );
        assert_eq!(
            v["spec"]["schedule"], "* * * * *",
            "spec must not be modified by /status PUT"
        );
        assert_eq!(
            v["metadata"]["uid"], "abc-123",
            "uid must not change via /status PUT"
        );
    }

    /// PATCH /status (merge-patch) with metadata.annotations must persist the annotation.
    /// Same contract as PUT; this is the path taken by kubectl patch --subresource=status.
    #[tokio::test]
    async fn patch_namespaced_status_persists_metadata_annotations() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let cronjob = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {
                "name": "ann-cj",
                "namespace": "default",
                "uid": "def-456",
                "resourceVersion": "1"
            },
            "spec": { "schedule": "*/5 * * * *" },
            "status": {}
        });
        let key = "/registry/batch/cronjobs/default/ann-cj";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&cronjob).unwrap()),
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

        let patch = serde_json::json!({
            "metadata": { "annotations": { "xzmpcheck": "ok" } },
            "status": { "lastScheduleTime": "2024-01-01T00:00:00Z" }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "batch".into(),
                "v1".into(),
                "default".into(),
                "cronjobs".into(),
                "ann-cj".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PATCH /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["annotations"]["xzmpcheck"], "ok",
            "annotation set via PATCH /status must be stored; \
             dropping it breaks kubectl patch --subresource=status and CronJob conformance"
        );
        assert_eq!(
            v["status"]["lastScheduleTime"], "2024-01-01T00:00:00Z",
            "status must also be updated alongside metadata"
        );
        assert_eq!(
            v["spec"]["schedule"], "*/5 * * * *",
            "spec must not change from /status PATCH"
        );
        assert_eq!(
            v["metadata"]["uid"], "def-456",
            "uid must not change via /status PATCH"
        );
    }

    /// A merge-patch to a generic resource's /status must NOT change `metadata.labels`,
    /// even though (per the test above) it IS allowed to change `metadata.annotations`.
    /// Labels drive policy decisions elsewhere (Namespace's PSA enforce label, selector-based
    /// webhook/NetworkPolicy matching) while annotations do not, so the merge/strategic-merge
    /// path — used generically by every resource's /status endpoint, not just Namespace/CRD —
    /// must block label writes the same way `validate_status_json_patch_paths` already blocks
    /// them for JSON Patch.
    #[tokio::test]
    async fn patch_namespaced_status_merge_patch_rejects_metadata_labels() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let cronjob = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {
                "name": "label-cj",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": { "schedule": "* * * * *" },
            "status": {}
        });
        let key = "/registry/batch/cronjobs/default/label-cj";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&cronjob).unwrap()),
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

        let patch = serde_json::json!({
            "metadata": { "labels": { "attacker": "true" } },
            "status": { "lastScheduleTime": "2024-01-01T00:00:00Z" }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "batch".into(),
                "v1".into(),
                "default".into(),
                "cronjobs".into(),
                "label-cj".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "a merge-patch to /status must still succeed — the label change is dropped, \
             not rejected"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["labels"]["attacker"].is_null(),
            "a merge-patch on /status must NOT be able to set arbitrary labels"
        );
        assert_eq!(
            v["status"]["lastScheduleTime"], "2024-01-01T00:00:00Z",
            "the legitimate status change in the same patch must still apply"
        );
    }

    /// Unlike every other kind, a merge-patch to `/api/v1/nodes/{name}/status` MUST apply
    /// `metadata.labels`. kubelet holds only `nodes/status` RBAC (never bare `nodes` write
    /// access) and relies on exactly this path — upstream's `nodeinfomanager.go` calls
    /// `PatchNodeStatus`, which bundles a labels change into a status-subresource patch —
    /// to publish CSI topology labels once a driver registers. If this endpoint dropped
    /// labels the way the generic protection above does for every other resource, the
    /// external-provisioner sidecar could never find a node carrying the driver's topology
    /// key, so every PVC using that storage class would stay Pending forever (confirmed via
    /// a live conformance repro: CSINode.spec.drivers populated correctly, but the Node
    /// object's labels never gained the topology key, and `external-provisioner` logged
    /// "topologyKeys ... were not found on any nodes" for the full 5-minute bind wait).
    #[tokio::test]
    async fn patch_resource_status_merge_patch_allows_metadata_labels_for_node() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": { "name": "worker-1", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        let key = "/registry/nodes/worker-1";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&node).unwrap()),
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

        let patch = serde_json::json!({
            "metadata": { "labels": { "topology.hostpath.csi/node": "worker-1" } },
            "status": { "nodeInfo": { "architecture": "arm64" } }
        });
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path(("".into(), "v1".into(), "nodes".into(), "worker-1".into())),
            // A genuine kubelet identity: proves the NodeRestriction label check added
            // alongside this test (which blocks node-restriction.kubernetes.io/* labels)
            // does not also block the CSI topology labels kubelet legitimately publishes.
            axum::Extension(node_user("worker-1")),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "a merge-patch to node/status must still succeed"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["labels"]["topology.hostpath.csi/node"], "worker-1",
            "CSI topology labels published via node/status must persist — kubelet has no \
             other RBAC-permitted way to set them, and without this label \
             external-provisioner can never bind a PVC to this node's storage class"
        );
        assert_eq!(
            v["status"]["nodeInfo"]["architecture"], "arm64",
            "the legitimate status change in the same patch must still apply"
        );
    }

    /// Unlike the CSI topology label above, a `node-restriction.kubernetes.io/*` label exists
    /// precisely so an RBAC-holding human/controller can place a trust marker a compromised
    /// kubelet cannot forge for itself. `merge_incoming_metadata`'s Node exception lets ALL
    /// labels through on /status (needed for the CSI case), so without a NodeRestriction-style
    /// check on this path specifically, a `system:node:<name>` identity — which upstream only
    /// ever grants `nodes/status` RBAC, never plain `nodes` write — could set this label on
    /// itself via /status even though the main-resource PATCH/PUT already blocks it.
    #[tokio::test]
    async fn patch_resource_status_denies_node_restriction_label_for_node() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": { "name": "worker-1", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        let key = "/registry/nodes/worker-1";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&node).unwrap()),
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

        let patch = serde_json::json!({
            "metadata": { "labels": {
                "node-restriction.kubernetes.io/trusted": "true"
            } },
            "status": { "nodeInfo": { "architecture": "arm64" } }
        });
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path(("".into(), "v1".into(), "nodes".into(), "worker-1".into())),
            axum::Extension(node_user("worker-1")),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "a system:node identity setting a node-restriction.kubernetes.io/* label via \
                 nodes/status must be rejected — this label namespace exists so it can't be \
                 forged by the node itself"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::FORBIDDEN,
            "the label rejection must surface as 403, matching the main-resource PATCH/PUT \
             behavior for the same label"
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["labels"]["node-restriction.kubernetes.io/trusted"].is_null(),
            "the rejected patch must not have been persisted"
        );
    }

    /// PATCH /status must NOT apply spec even if the body contains a spec field.
    /// A controller that accidentally includes spec in its /status PATCH must not
    /// corrupt the stored spec — spec isolation is what makes the status subresource safe.
    #[tokio::test]
    async fn patch_namespaced_status_ignores_spec_in_body() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "safe-deploy", "namespace": "default", "resourceVersion": "1" },
            "spec": { "replicas": 3 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/safe-deploy";
        store
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

        let patch = serde_json::json!({
            "spec": { "replicas": 99 },
            "status": { "readyReplicas": 3 }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "safe-deploy".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PATCH /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["replicas"], 3,
            "spec must be unchanged after PATCH /status even when spec is in the patch body; \
             status subresource isolation prevents controllers from corrupting spec"
        );
        assert_eq!(v["status"]["readyReplicas"], 3, "status must be updated");
    }

    /// PUT /status must NOT apply spec from the incoming body.
    /// The stored spec must survive — status subresource writes only touch status+metadata.
    #[tokio::test]
    async fn put_resource_status_ignores_spec_in_body() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "specguard-node", "resourceVersion": "1" },
            "spec": { "drivers": [{"name": "csi.io"}] }
        });
        let key = "/registry/storage.k8s.io/csinodes/specguard-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
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

        let put_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "specguard-node", "annotations": { "x": "y" } },
            "spec": { "drivers": [] },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "specguard-node".into(),
            )),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["drivers"][0]["name"], "csi.io",
            "spec from the stored object must survive a PUT /status that contains a different spec"
        );
        assert_eq!(
            v["metadata"]["annotations"]["x"], "y",
            "annotation from PUT body must be applied"
        );
        assert_eq!(v["status"]["ready"], true, "status must be updated");
    }

    /// PUT /status must not let a status write overwrite immutable identity (uid).
    /// If uid could be changed via /status, a compromised controller could silently
    /// re-point a resource to a different object identity, breaking GC and admission.
    #[tokio::test]
    async fn put_namespaced_status_does_not_overwrite_uid() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "uid-guard", "namespace": "default", "uid": "real-uid-1", "resourceVersion": "1" },
            "spec": { "replicas": 1 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/uid-guard";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
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

        let put_body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "uid-guard", "namespace": "default", "uid": "attacker-uid", "annotations": { "safe": "yes" } },
            "status": { "readyReplicas": 1 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "uid-guard".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["uid"], "real-uid-1",
            "uid must not be overwritten by a status write; \
             allowing uid changes via /status would break GC and object identity guarantees"
        );
        assert_eq!(
            v["metadata"]["annotations"]["safe"], "yes",
            "non-identity annotations must still land"
        );
    }

    /// PUT /status on a cluster-scoped resource must not overwrite finalizers or deletionTimestamp.
    /// A status PUT that clears finalizers can race with a peer controller that just removed a
    /// finalizer, restoring it and causing the object to be stuck Terminating forever (livelock).
    #[tokio::test]
    async fn put_resource_status_preserves_finalizers_and_deletion_timestamp() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "fin-node",
                "resourceVersion": "1",
                "finalizers": ["storage.kubernetes.io/csinode-protection"],
                "deletionTimestamp": "2024-01-01T00:00:00Z"
            },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/fin-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
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

        let put_body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": {
                "name": "fin-node",
                "finalizers": [],
                "deletionTimestamp": "2099-12-31T00:00:00Z"
            },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "fin-node".into(),
            )),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["finalizers"][0], "storage.kubernetes.io/csinode-protection",
            "finalizers must survive PUT /status — a status PUT that clears finalizers can \
             restore a just-removed finalizer causing the object to be stuck Terminating forever (livelock)"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2024-01-01T00:00:00Z",
            "deletionTimestamp must survive PUT /status — changing it via status would allow \
             a controller to bypass the graceful deletion lifecycle"
        );
    }

    /// PUT /status on a namespaced resource must not overwrite finalizers or deletionTimestamp.
    /// Same livelock risk as the cluster-scoped path: if a controller PUT /status and the body
    /// reflects an older version of the object that still has a finalizer a peer just removed,
    /// the finalizer is restored and the object is stuck Terminating forever.
    #[tokio::test]
    async fn put_namespaced_resource_status_preserves_finalizers_and_deletion_timestamp() {
        let store = Arc::new(SqliteStore::new(":memory:").unwrap());
        let obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "fin-deploy",
                "namespace": "default",
                "resourceVersion": "1",
                "finalizers": ["foregroundDeletion"],
                "deletionTimestamp": "2024-06-01T00:00:00Z"
            },
            "spec": { "replicas": 1 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/fin-deploy";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
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

        let put_body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "fin-deploy",
                "namespace": "default",
                "finalizers": [],
                "deletionTimestamp": "2099-01-01T00:00:00Z"
            },
            "status": { "readyReplicas": 1 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "fin-deploy".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /status must succeed");

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["finalizers"][0], "foregroundDeletion",
            "finalizers must survive PUT /namespaced/status — a status PUT that clears finalizers \
             can restore a just-removed finalizer causing the object to be stuck Terminating forever (livelock)"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2024-06-01T00:00:00Z",
            "deletionTimestamp must survive PUT /namespaced/status"
        );
    }

    // ---------------------------------------------------------------------------
    // PVC status.conditions must be persisted via /status subresource
    // ---------------------------------------------------------------------------

    /// PATCH /pvc/status with conditions must persist the conditions so they are
    /// present on subsequent GET.
    ///
    /// The conformance spec '[sig-storage] PersistentVolumes CSI Conformance should
    /// apply changes to a pv/pvc status [Conformance]' (storage/persistent_volumes.go:789)
    /// patches PVC /status with a condition {type: "StatusUpdated"} and then reads it
    /// back.  If the condition is not persisted, the test fails with
    /// "got conditions=nil, expected StatusUpdated".
    ///
    /// This test fails if the merge_patch path in patch_namespaced_resource_status
    /// does not propagate status.conditions to the stored object.
    #[tokio::test]
    async fn pvc_status_conditions_persisted_via_patch() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed a PVC with initial status.phase=Pending (as apply_defaults would set).
        let pvc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": "my-pvc",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "1Gi" } }
            },
            "status": { "phase": "Pending" }
        });
        let key = "/registry/persistentvolumeclaims/default/my-pvc";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pvc).unwrap()),
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

        // PATCH /pvc/status with a CSI condition.
        let patch = serde_json::json!({
            "status": {
                "conditions": [
                    {
                        "type": "StatusUpdated",
                        "status": "True",
                        "reason": "CSITest",
                        "message": "applied by conformance test"
                    }
                ]
            }
        });

        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
                "my-pvc".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PATCH /pvc/status must succeed — got: {:?}",
            result.err()
        );

        // Verify the conditions are now stored.
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let conditions = v["status"]["conditions"].as_array().expect(
            "status.conditions must be an array after PATCH /pvc/status — \
                 the conformance test '[sig-storage] PersistentVolumes CSI Conformance should \
                 apply changes to a pv/pvc status' checks conditions != nil after the patch; \
                 nil conditions means the PATCH did not persist",
        );
        assert_eq!(
            conditions.len(),
            1,
            "exactly one condition must be stored after PATCH"
        );
        assert_eq!(
            conditions[0]["type"], "StatusUpdated",
            "condition type must be StatusUpdated — if this fails, patch_namespaced_resource_status \
             is not merging status.conditions into the stored PVC object"
        );

        // The original phase must still be present (merge-patch preserves existing keys).
        assert_eq!(
            v["status"]["phase"], "Pending",
            "status.phase must survive the PATCH — merge-patch must not wipe existing status keys"
        );

        // Spec must be untouched.
        assert_eq!(
            v["spec"]["accessModes"][0], "ReadWriteOnce",
            "spec must be unchanged after PATCH /pvc/status"
        );
    }

    /// PUT /pvc/status with conditions replaces status and conditions are readable.
    ///
    /// The CSI provisioner may use PUT instead of PATCH to set PVC status conditions.
    /// If PUT /pvc/status doesn't persist conditions, CSI provisioning status is invisible.
    ///
    /// This test fails if put_namespaced_resource_status does not replace the status
    /// field with the incoming value when that value contains conditions.
    #[tokio::test]
    async fn pvc_status_conditions_persisted_via_put() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let pvc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": "put-pvc",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "2Gi" } }
            },
            "status": { "phase": "Pending" }
        });
        let key = "/registry/persistentvolumeclaims/default/put-pvc";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pvc).unwrap()),
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

        // PUT /pvc/status with phase=Bound and conditions.
        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "put-pvc", "namespace": "default" },
            "status": {
                "phase": "Bound",
                "conditions": [
                    { "type": "StatusUpdated", "status": "True" }
                ]
            }
        });

        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "".into(),
                "v1".into(),
                "default".into(),
                "persistentvolumeclaims".into(),
                "put-pvc".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "PUT /pvc/status must succeed — got: {:?}",
            result.err()
        );

        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["status"]["phase"], "Bound",
            "status.phase must be Bound after PUT /pvc/status"
        );
        let conditions = v["status"]["conditions"].as_array().expect(
            "status.conditions must be present after PUT /pvc/status — \
             if nil, the PUT did not replace status with the incoming value",
        );
        assert_eq!(
            conditions[0]["type"], "StatusUpdated",
            "condition type must be StatusUpdated after PUT /pvc/status"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: subresource PUT CAS must use the INCOMING
    // body's resourceVersion, not the stored object's.  Without this fix, a writer
    // holding a stale RV can overwrite a newer write (concurrent clobber) instead
    // of receiving 409 Conflict and retrying from a fresh GET.
    // ---------------------------------------------------------------------------

    /// put_resource_status with a stale resourceVersion in the body must return 409 Conflict.
    ///
    /// Without this fix the handler used the stored object's RV as the CAS token, making
    /// every PUT unconditional — a controller holding stale state would silently overwrite
    /// a peer's concurrent write instead of receiving 409 and retrying from a fresh GET.
    #[tokio::test]
    async fn put_resource_status_stale_rv_returns_409_else_concurrent_writers_clobber() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "rv-test-node" },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/rv-test-node";
        // First write gives rv=1.
        let rv1 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                None,
            )
            .await
            .unwrap();
        // Second write advances to rv=2 (simulates a concurrent writer actually changing the
        // object — the store now suppresses no-op writes, so the payload must genuinely differ
        // from what's stored or the revision would correctly stay at rv1).
        let mut obj2 = obj.clone();
        obj2["metadata"]["resourceVersion"] = serde_json::json!(rv1.to_string());
        obj2["spec"]["drivers"] = serde_json::json!([{"name": "example-driver"}]);
        let rv2 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance after second write");

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // PUT body carries the now-stale rv1 — must be rejected with 409.
        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "rv-test-node", "resourceVersion": rv1.to_string() },
            "status": { "ready": true }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "rv-test-node".into(),
            )),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "stale-rv PUT to put_resource_status must return 409 — \
                 without this check concurrent controllers silently clobber each other"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "stale resourceVersion in PUT /status body must produce 409 Conflict, \
             not 200 — controllers must retry from a fresh GET when they lose the CAS race"
        );
    }

    /// put_resource_status with an absent resourceVersion in the body succeeds unconditionally.
    ///
    /// Clients that legitimately omit resourceVersion (e.g. single-writer bootstrapping)
    /// must not be broken by the stale-RV fix.  parse_resource_version returns None for
    /// absent/empty rv, and the store treats None as unconditional.
    #[tokio::test]
    async fn put_resource_status_absent_rv_is_unconditional_write() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "no-rv-node" },
            "spec": { "drivers": [] }
        });
        let key = "/registry/storage.k8s.io/csinodes/no-rv-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
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

        // Body has no resourceVersion — must succeed (unconditional write).
        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "no-rv-node" },
            "status": { "ready": false }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "no-rv-node".into(),
            )),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "absent resourceVersion in PUT /status body must succeed (unconditional write) — \
             single-writer bootstrap clients must not be broken by the stale-RV fix"
        );
    }

    /// put_resource_status against an EXISTING object with an explicit `resourceVersion: "0"`
    /// in the body must succeed, not fail with 409 AlreadyExists.
    ///
    /// This is the sig-scheduling node-status conformance scenario: the test's BeforeEach
    /// does `nodeCopy.ResourceVersion = "0"; cs.CoreV1().Nodes().UpdateStatus(...)` on an
    /// already-existing node to force the write through regardless of the node's current
    /// (possibly stale) resourceVersion — real kube-apiserver treats resourceVersion 0 on an
    /// Update as "unconditional", not as "must not exist". Before the fix,
    /// parse_resource_version mapped "0" to `Some(0)`, which `Store::put` interprets as
    /// create-only, so writing status onto an existing node spuriously 409'd with
    /// "Node already exists" and broke both the BeforeEach and the mirrored AfterEach cleanup.
    #[tokio::test]
    async fn put_resource_status_explicit_zero_rv_is_unconditional_write_on_existing_object() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": { "name": "lima-node-5" },
            "status": { "capacity": { "cpu": "4" } }
        });
        let key = "/registry/nodes/lima-node-5";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&node).unwrap()),
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

        // Mirrors predicates.go: fetch, set ResourceVersion="0", PUT the full status back
        // with an extended resource added to capacity.
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": { "name": "lima-node-5", "resourceVersion": "0" },
            "status": { "capacity": { "cpu": "4", "example.com/beardsecond": "1000" } }
        });
        let result = put_resource_status(
            axum::extract::State(state),
            axum::extract::Path(("".into(), "v1".into(), "nodes".into(), "lima-node-5".into())),
            axum::Extension(test_user()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "resourceVersion \"0\" against an existing node must be treated as an \
             unconditional update, not rejected with 409 AlreadyExists: {:?}",
            result.err().map(|e| e.0)
        );
    }

    /// put_namespaced_resource_status with a stale resourceVersion in the body must return 409.
    ///
    /// This is the PDB conformance scenario: the DisruptionController holds a snapshot at rv=R0,
    /// the test's UpdateStatus advances the store to R1, then the controller's stale PUT (still
    /// body rv=R0) must get 409 so it retries with a fresh GET and preserves disruptedPods.
    /// Without this fix the controller's write was accepted unconditionally, wiping disruptedPods.
    #[tokio::test]
    async fn put_namespaced_resource_status_stale_rv_returns_409_else_concurrent_writers_clobber() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "cas-pdb", "namespace": "default" },
            "spec": { "minAvailable": 1 }
        });
        let key = "/registry/policy/poddisruptionbudgets/default/cas-pdb";
        let rv1 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();
        // Advance the store to rv2 (peer writer succeeded with a genuine change — the store
        // suppresses no-op writes, so disruptedPods must actually differ from the first write).
        let mut pdb2 = pdb.clone();
        pdb2["metadata"]["resourceVersion"] = serde_json::json!(rv1.to_string());
        pdb2["status"] = serde_json::json!({"disruptedPods": {"pod-a": "2024-01-01T00:00:00Z"}});
        let rv2 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance after second write");

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // PUT body carries the now-stale rv1 — must be rejected with 409.
        let body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "cas-pdb", "namespace": "default", "resourceVersion": rv1.to_string() },
            "status": { "disruptedPods": {}, "disruptionsAllowed": 1 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "policy".into(),
                "v1".into(),
                "default".into(),
                "poddisruptionbudgets".into(),
                "cas-pdb".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "stale-rv PUT to put_namespaced_resource_status must return 409 — \
                 the PDB conformance test fails when the DisruptionController's stale write \
                 is accepted unconditionally and wipes disruptedPods"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "stale resourceVersion in namespaced PUT /status body must produce 409 — \
             controllers must retry from fresh GET, not silently clobber concurrent writes"
        );
    }

    /// put_namespaced_resource_status with an absent resourceVersion in the body succeeds.
    ///
    /// Upstream k8s allows omitting resourceVersion in a subresource PUT, treating it as
    /// an unconditional write.  The fix must not break this.
    #[tokio::test]
    async fn put_namespaced_resource_status_absent_rv_is_unconditional_write() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "norev-pdb", "namespace": "default" },
            "spec": { "minAvailable": 1 }
        });
        let key = "/registry/policy/poddisruptionbudgets/default/norev-pdb";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&pdb).unwrap()),
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

        // No resourceVersion in body — must succeed unconditionally.
        let body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "norev-pdb", "namespace": "default" },
            "status": { "disruptionsAllowed": 2 }
        });
        let result = put_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "policy".into(),
                "v1".into(),
                "default".into(),
                "poddisruptionbudgets".into(),
                "norev-pdb".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "absent resourceVersion in namespaced PUT /status body must succeed (unconditional) — \
             clients that omit rv must not be broken by the stale-RV CAS fix"
        );
    }

    fn json_patch_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );
        h
    }

    /// JSON Patch on /status with a spec-targeting op must be rejected 422.
    ///
    /// A client that has `patch <resource>/status` RBAC must not be able to write
    /// spec fields by sending a JSON Patch with path "/spec/...". Without this guard,
    /// privilege escalation allows overwriting the resource spec via the /status route.
    #[tokio::test]
    async fn patch_resource_status_json_patch_targeting_spec_is_rejected_422() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "spec-guard-node" },
            "spec": { "drivers": [{"name": "original.csi.io"}] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/spec-guard-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
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

        let patch = serde_json::json!([
            {"op": "replace", "path": "/spec/drivers/0/name", "value": "attacker.csi.io"}
        ]);
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "spec-guard-node".into(),
            )),
            axum::Extension(test_user()),
            json_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "JSON Patch with /spec path on /status subresource must be rejected — \
                 a client with only patch status RBAC must not be able to overwrite spec"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "spec-targeting JSON Patch on /status must return 422 — \
             privilege escalation: patch status can write spec without this guard"
        );

        // Confirm spec was NOT modified.
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["drivers"][0]["name"], "original.csi.io",
            "spec.drivers must not be modified by a /status JSON Patch with a /spec path"
        );
    }

    /// JSON Patch on /status with a /status/* op succeeds.
    ///
    /// Legitimate controllers that PATCH /status with JSON Patch using /status/* paths
    /// must continue to work after the path-isolation guard is added.
    #[tokio::test]
    async fn patch_resource_status_json_patch_targeting_status_succeeds() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "status-ok-node" },
            "spec": { "drivers": [] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/status-ok-node";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
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

        let patch = serde_json::json!([
            {"op": "add", "path": "/status/ready", "value": true}
        ]);
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "status-ok-node".into(),
            )),
            axum::Extension(test_user()),
            json_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "JSON Patch with /status/* path on /status subresource must succeed — \
             the path-isolation guard must not block legitimate status writes"
        );
    }

    /// JSON Patch on namespaced /status with a spec-targeting op must be rejected 422.
    ///
    /// Same privilege-escalation guard as the cluster-scoped variant, applied to the
    /// namespaced code path. A client with `patch deployments/status` must not write spec.
    #[tokio::test]
    async fn patch_namespaced_resource_status_json_patch_targeting_spec_is_rejected_422() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "guarded-deploy", "namespace": "default" },
            "spec": { "replicas": 3 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/guarded-deploy";
        store
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

        let patch = serde_json::json!([
            {"op": "replace", "path": "/spec/replicas", "value": 0}
        ]);
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "guarded-deploy".into(),
            )),
            json_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "JSON Patch with /spec path on namespaced /status subresource must be rejected — \
                 a client with only patch deployments/status RBAC must not overwrite spec.replicas"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "spec-targeting JSON Patch on namespaced /status must return 422 — \
             without this guard, patch status RBAC can silently scale down a Deployment"
        );

        // Confirm spec.replicas was NOT modified.
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["replicas"], 3,
            "spec.replicas must not be modified by a /status JSON Patch with /spec path"
        );
    }

    /// JSON Patch on namespaced /status with a /status/* op succeeds.
    ///
    /// The guard must permit legitimate status writes via /status/* paths.
    #[tokio::test]
    async fn patch_namespaced_resource_status_json_patch_targeting_status_succeeds() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "status-write-deploy", "namespace": "default" },
            "spec": { "replicas": 1 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/status-write-deploy";
        store
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

        let patch = serde_json::json!([
            {"op": "add", "path": "/status/readyReplicas", "value": 1}
        ]);
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "status-write-deploy".into(),
            )),
            json_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "JSON Patch with /status/* path on namespaced /status subresource must succeed — \
             the guard must not block legitimate controller status writes"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests for PATCH /status CAS (the PUT sibling was fixed but PATCH
    // was left reading the stored object's RV — unconditional writes).
    // ---------------------------------------------------------------------------

    /// PATCH cluster-scoped /status with a stale resourceVersion must return 409 Conflict.
    ///
    /// Without this fix, patch_resource_status used current.resource_version() (the stored
    /// object's RV, just fetched) as the CAS token — always matches, making every PATCH
    /// unconditional. A controller holding a stale snapshot silently clobbers concurrent writes.
    #[tokio::test]
    async fn patch_resource_status_stale_rv_returns_409_else_concurrent_controllers_clobber() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "stale-node" },
            "spec": { "drivers": [] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/stale-node";
        let rv1 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Advance to rv2 (simulates a concurrent controller write).
        let mut csinode2 = csinode.clone();
        csinode2["status"]["ready"] = serde_json::json!(true);
        let rv2 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&csinode2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance");

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Patch carries the stale rv1 in metadata.resourceVersion.
        let patch = serde_json::json!({
            "metadata": { "resourceVersion": rv1.to_string() },
            "status": { "phase": "Failed" }
        });
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "stale-node".into(),
            )),
            axum::Extension(test_user()),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "PATCH /status with stale resourceVersion must return 409 — \
                 without CAS, concurrent controllers silently overwrite each other's status"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "stale resourceVersion in PATCH cluster-scoped /status must return 409 — \
             controllers must retry from a fresh GET when their snapshot is stale"
        );
    }

    /// PATCH cluster-scoped /status with no resourceVersion succeeds unconditionally.
    ///
    /// Clients that omit metadata.resourceVersion must not be broken by the PATCH CAS fix.
    #[tokio::test]
    async fn patch_resource_status_absent_rv_is_unconditional_write() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let csinode = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "norev-node" },
            "spec": { "drivers": [] },
            "status": {}
        });
        let key = "/registry/storage.k8s.io/csinodes/norev-node";
        store
            .put(
                key,
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

        let patch = serde_json::json!({"status": {"phase": "Ready"}});
        let result = patch_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".into(),
                "v1".into(),
                "csinodes".into(),
                "norev-node".into(),
            )),
            axum::Extension(test_user()),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "PATCH cluster-scoped /status without metadata.resourceVersion must succeed — \
             the PATCH CAS fix must not break clients that omit the resourceVersion"
        );
    }

    /// PATCH namespaced /status with a stale resourceVersion must return 409 Conflict.
    ///
    /// Same OCC contract as the cluster-scoped variant, applied to the namespaced path.
    /// Without this fix, a controller updating deployments/status with a stale snapshot
    /// silently clobbers the Deployment controller's concurrent status write.
    #[tokio::test]
    async fn patch_namespaced_resource_status_stale_rv_returns_409_else_concurrent_controllers_clobber(
    ) {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "stale-status-deploy", "namespace": "default" },
            "spec": { "replicas": 1 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/stale-status-deploy";
        let rv1 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Advance to rv2 (simulates a concurrent Deployment controller write).
        let mut deploy2 = deploy.clone();
        deploy2["status"]["readyReplicas"] = serde_json::json!(1);
        let rv2 = store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&deploy2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance");

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Patch carries the stale rv1.
        let patch = serde_json::json!({
            "metadata": { "resourceVersion": rv1.to_string() },
            "status": { "readyReplicas": 0 }
        });
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "stale-status-deploy".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "PATCH namespaced /status with stale resourceVersion must return 409 — \
                 without CAS, a controller with a stale snapshot silently clobbers concurrent writes"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "stale resourceVersion in PATCH namespaced /status must return 409 — \
             controllers must retry from a fresh GET; without this they silently lose updates"
        );
    }

    /// PATCH namespaced /status with no resourceVersion succeeds unconditionally.
    ///
    /// Clients that omit metadata.resourceVersion must not be broken by the PATCH CAS fix.
    #[tokio::test]
    async fn patch_namespaced_resource_status_absent_rv_is_unconditional_write() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "norev-status-deploy", "namespace": "default" },
            "spec": { "replicas": 1 },
            "status": {}
        });
        let key = "/registry/apps/deployments/default/norev-status-deploy";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&deploy).unwrap()),
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

        let patch = serde_json::json!({"status": {"readyReplicas": 1}});
        let result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "norev-status-deploy".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "PATCH namespaced /status without metadata.resourceVersion must succeed — \
             the PATCH CAS fix must not break controllers that omit the resourceVersion"
        );
    }

    /// PUT and PATCH on /status must stamp kind/apiVersion on the response even when the
    /// request body (and the stored object) omit them.
    ///
    /// UpdateStatus() in typed and dynamic clients decodes the response body and requires
    /// TypeMeta to resolve the object's Go type; without kind/apiVersion the client returns
    /// "Object 'Kind' is missing", which is exactly what breaks the
    /// '[sig-apps] Deployment should run the lifecycle of a Deployment' conformance test
    /// (it calls UpdateStatus on the Deployment after mutating replicas).
    ///
    /// This test fails if the inject_type_meta call is removed from either status handler.
    #[tokio::test]
    async fn status_put_and_patch_responses_always_include_type_meta() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Stored object omits kind/apiVersion, simulating a client that never set TypeMeta.
        let deploy_without_type_meta = serde_json::json!({
            "metadata": { "name": "notm-deploy", "namespace": "default", "resourceVersion": "1" },
            "spec": { "replicas": 1 }
        });
        let key = "/registry/apps/deployments/default/notm-deploy";
        store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&deploy_without_type_meta).unwrap()),
                None,
            )
            .await
            .unwrap();

        // PUT body also omits kind/apiVersion — the server must stamp TypeMeta regardless.
        let put_body = serde_json::json!({
            "metadata": { "name": "notm-deploy", "namespace": "default" },
            "status": { "readyReplicas": 1 }
        });
        let put_result = put_namespaced_resource_status(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "notm-deploy".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await
        .expect("PUT /status must succeed")
        .into_response();
        let put_body_bytes = to_bytes(put_result.into_body(), usize::MAX).await.unwrap();
        let put_json: serde_json::Value = serde_json::from_slice(&put_body_bytes).unwrap();
        assert_eq!(
            put_json["kind"], "Deployment",
            "PUT /status response must include kind even when the request and stored body omit it; \
             UpdateStatus() clients reject responses missing TypeMeta"
        );
        assert_eq!(
            put_json["apiVersion"], "apps/v1",
            "PUT /status response must include apiVersion even when the request and stored body omit it"
        );

        // PATCH body also omits kind/apiVersion.
        let patch = serde_json::json!({"status": {"readyReplicas": 2}});
        let patch_result = patch_namespaced_resource_status(
            axum::extract::State(state),
            axum::extract::Path((
                "apps".into(),
                "v1".into(),
                "default".into(),
                "deployments".into(),
                "notm-deploy".into(),
            )),
            merge_patch_headers(),
            bytes::Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await
        .expect("PATCH /status must succeed")
        .into_response();
        let patch_body_bytes = to_bytes(patch_result.into_body(), usize::MAX)
            .await
            .unwrap();
        let patch_json: serde_json::Value = serde_json::from_slice(&patch_body_bytes).unwrap();
        assert_eq!(
            patch_json["kind"], "Deployment",
            "PATCH /status response must include kind even when the request and stored body omit it; \
             UpdateStatus() clients reject responses missing TypeMeta"
        );
        assert_eq!(
            patch_json["apiVersion"], "apps/v1",
            "PATCH /status response must include apiVersion even when the request and stored body omit it"
        );
    }

    /// Every PUT status-subresource handler must reject a non-object (scalar/array) status
    /// before persisting it, or a corrupted status crashes the apiserver the next time any
    /// in-place status stamper (`apply_delete_policy`, `merge_approval_conditions`, ...)
    /// indexes it. Two prior review rounds each missed a subset of these handlers by
    /// checking only the ones a reviewer happened to look at — round 1 fixed the
    /// merge-patch handlers, round 2 fixed two more PATCH sites plus DiD sweep guards, and
    /// still missed the entire PUT path. Rather than trust a human to re-enumerate every
    /// handler by hand a fourth time, this test greps every `.rs` file under
    /// `src/handlers/` for the naming convention every PUT status handler in this codebase
    /// follows (`fn put_..._status` / `fn replace_..._status`) and fails the moment a new
    /// one is added without calling the shared guard.
    #[test]
    fn every_status_put_handler_guards_against_non_object_status() {
        // put_namespace_status is the one handler exempt from calling the guard directly: it
        // round-trips the incoming status through the typed `NamespaceStatus` struct
        // (`serde_json::from_value::<NamespaceStatus>` then `serde_json::to_value`) before
        // ever assigning it back, so a scalar/array status is structurally impossible to
        // produce there — `to_value` on a struct always yields a JSON object.
        const TYPED_SAFE: &[&str] = &["put_namespace_status"];

        let handlers_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
        let mut checked = Vec::new();
        let mut unguarded = Vec::new();

        for entry in std::fs::read_dir(&handlers_dir)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", handlers_dir.display()))
            .flatten()
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            for (name, body) in status_put_handler_bodies(&source) {
                checked.push(name.clone());
                if TYPED_SAFE.contains(&name.as_str()) {
                    continue;
                }
                if !body.contains("reject_non_object_status(")
                    && !body.contains("replace_status_field(")
                {
                    unguarded.push(format!("{name} in {}", path.display()));
                }
            }
        }

        assert!(
            checked.len() >= 6,
            "sanity check: expected at least 6 status-subresource PUT handlers \
             (put_resource_status, put_namespaced_resource_status, put_cr_status, \
             put_crd_status, replace_pod_status, put_namespace_status), found {} — did the \
             put_/replace_ + \"status\" naming convention change (this test would otherwise \
             pass vacuously)?",
            checked.len()
        );
        assert!(
            unguarded.is_empty(),
            "status-subresource PUT handler(s) persist a raw status value without \
             rejecting a non-object (scalar/array) status first: {unguarded:?} — a scalar \
             status corrupts the object's schema and panics the next in-place status \
             stamper, crashing the apiserver for every other request in flight. Call \
             replace_status_field (or reject_non_object_status) before persisting, or add \
             the handler to TYPED_SAFE with a comment proving it structurally cannot store \
             a non-object status."
        );
    }

    /// A guard call *inside* only one patch-content-type branch is not enough: round 3
    /// added `reject_non_object_status` inside the merge/strategic-merge arm and the
    /// `PatchType::Json` arm right next to it stayed unguarded, because
    /// `validate_status_json_patch_paths` explicitly permits a whole-`/status` replace and
    /// nothing re-checked the result afterward. Every PATCH status-subresource handler must
    /// instead call the guard as an unconditional statement placed directly in the
    /// function body — reached no matter which `match patch_type` arm ran — rather than
    /// nested inside one specific arm. rustfmt indents a function's own top-level
    /// statements at exactly 4 spaces, so a guard call that only ever shows up deeper than
    /// that proves it is per-branch rather than a shared convergence point that runs before
    /// every store write.
    #[test]
    fn every_status_patch_handler_guards_non_object_status_outside_any_branch() {
        let handlers_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
        let mut checked = Vec::new();
        let mut unguarded = Vec::new();

        for entry in std::fs::read_dir(&handlers_dir)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", handlers_dir.display()))
            .flatten()
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            for (name, body) in patch_status_handler_bodies(&source) {
                // Only handlers that dispatch on PatchType::Json are exposed to this bug
                // class — e.g. patch_pod_status rejects every content-type but
                // merge/strategic-merge with 415, so it never reaches a JSON Patch arm.
                if !body.contains("PatchType::Json") {
                    continue;
                }
                checked.push(name.clone());

                let min_guard_indent = body
                    .lines()
                    .filter(|l| {
                        l.contains("reject_non_object_status(")
                            || l.contains("replace_status_field(")
                    })
                    .map(|l| l.len() - l.trim_start().len())
                    .min();

                if min_guard_indent != Some(4) {
                    unguarded.push(format!("{name} in {}", path.display()));
                }
            }
        }

        assert!(
            checked.len() >= 4,
            "sanity check: expected at least 4 JSON-Patch-capable PATCH status-subresource \
             handlers (patch_resource_status, patch_namespaced_resource_status, \
             patch_cr_status, patch_crd_status), found {} — did the patch_ + \"status\" \
             naming convention or the PatchType::Json dispatch change (this test would \
             otherwise pass vacuously)?",
            checked.len()
        );
        assert!(
            unguarded.is_empty(),
            "PATCH status-subresource handler(s) guard a non-object status only inside one \
             patch-content-type branch (or not at all), not at a shared convergence point \
             reached by every branch: {unguarded:?} — a per-branch guard has been missed for \
             a different content-type in three review rounds running. Call \
             reject_non_object_status (or replace_status_field) as its own top-level \
             statement right after the `match patch_type` block, before the store write, so \
             JSON Patch, merge, and strategic-merge patches are all covered by the same \
             check."
        );
    }

    /// Rounds 1-4 closed every `/status` subresource hole this bug class hid in — round 5's
    /// independent re-enumeration then found it hiding on the OTHER axis: `patch_namespace`,
    /// the MAIN `/api/v1/namespaces/{name}` PATCH handler (not `/status`), applied a
    /// merge-patch to the whole stored object body and restored only `metadata.uid`. A body
    /// `{"status":"x"}` therefore persisted a scalar status using only ordinary `namespaces`
    /// `patch` rights — no `namespaces/status` rights needed — corrupting the object exactly
    /// like the four `/status` holes did, just reached through a different endpoint.
    ///
    /// This test covers that other axis: every MAIN-resource (non-status) handler that
    /// itself persists a write (calls `.put(`, as opposed to a thin wrapper delegating to an
    /// already-covered handler like `do_patch`) must restore whatever status is already
    /// stored rather than trust the request body — following the `stored_status` naming
    /// convention `do_patch` (resource.rs) established, which every fixed site in this repo
    /// (including this round's `patch_namespace`/`replace_crd`/`patch_crd` fixes) already
    /// uses. A handler that never touches `status` at all is listed in SAFE with a comment
    /// proving it structurally cannot.
    #[test]
    fn every_main_resource_write_handler_preserves_stored_status() {
        // Verified by reading each one: `patch_ephemeral_containers` only ever writes
        // `spec.ephemeralContainers` and never reads `incoming["status"]`; `patch_approval`
        // only ever writes `status.conditions` from a typed `CertificateSigningRequestStatus`
        // round-trip (a scalar body value fails to deserialize and is silently ignored via
        // `.ok()`), and unconditionally restores `spec`/`status.certificate` regardless of
        // patch type; `patch_pod_resize`'s `apply_resize_patch` never reads
        // `incoming["status"]` either, only stamping the fixed leaf `status.resize` behind
        // its own is-object-or-null guard (not the `stored_status` convention, but not a
        // whole-body clobber this test is about).
        const SAFE: &[&str] = &[
            "patch_ephemeral_containers",
            "patch_approval",
            "patch_pod_resize",
        ];

        let handlers_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
        let mut checked = Vec::new();
        let mut unguarded = Vec::new();

        for entry in std::fs::read_dir(&handlers_dir)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", handlers_dir.display()))
            .flatten()
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            for (name, body) in main_resource_handler_bodies(&source) {
                // A handler whose own body never calls a Store write entry point doesn't
                // persist anything itself — it's a thin wrapper delegating to an
                // already-checked handler (patch_resource/patch_namespaced_resource ->
                // do_patch, the core.rs/certificates.rs wrappers -> resource.rs, the scale
                // PATCH handlers -> their shared *_impl). Nothing new to check.
                if !calls_store_write_entry_point(&body) {
                    continue;
                }
                checked.push(name.clone());
                if SAFE.contains(&name.as_str()) {
                    continue;
                }
                if !body.contains("stored_status") {
                    unguarded.push(format!("{name} in {}", path.display()));
                }
            }
        }

        assert!(
            checked.len() >= 10,
            "sanity check: expected at least 10 main-resource write handlers (replace_namespace, \
             patch_namespace, replace_resource, replace_namespaced_resource, replace_cr, \
             replace_cr_namespaced, patch_cr, patch_cr_namespaced, replace_crd, patch_crd, \
             replace_pod, patch_pod, ...), found {} — did the replace_/patch_ naming \
             convention change (this test would otherwise pass vacuously)?",
            checked.len()
        );
        assert!(
            unguarded.is_empty(),
            "main-resource (non-status) write handler(s) can persist the request body's \
             `status` field without restoring the stored value first: {unguarded:?} — a \
             caller holding only ordinary (non-status-subresource) write rights could \
             persist a scalar status and later panic the next in-place status stamper, \
             crashing the apiserver for every other request in flight. Capture \
             `stored_status` before applying the patch/replace and restore it after (see \
             do_patch in resource.rs), or add the handler to SAFE with a comment proving it \
             structurally cannot touch status."
        );
    }

    /// Extracts `(function_name, body)` for every top-level `pub`/`pub(crate)` function in
    /// `source` whose name satisfies `matches_name`. Deliberately requires the signature to
    /// start at column 0 (`line.starts_with("pub")`) so indented `#[tokio::test] async fn
    /// ..._status_...()` test functions inside `mod tests` are never mistaken for a
    /// production handler.
    fn handler_bodies_matching(
        source: &str,
        matches_name: impl Fn(&str) -> bool,
    ) -> Vec<(String, String)> {
        let mut results = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if let Some(name) = line
                .starts_with("pub")
                .then(|| line.find("fn "))
                .flatten()
                .map(|fn_idx| {
                    let after = &line[fn_idx + 3..];
                    let end = after
                        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .unwrap_or(after.len());
                    after[..end].to_string()
                })
            {
                if matches_name(&name) {
                    let mut depth = 0i32;
                    let mut started = false;
                    let mut body = String::new();
                    let mut j = i;
                    while j < lines.len() {
                        let l = lines[j];
                        for ch in l.chars() {
                            if ch == '{' {
                                depth += 1;
                                started = true;
                            } else if ch == '}' {
                                depth -= 1;
                            }
                        }
                        body.push_str(l);
                        body.push('\n');
                        j += 1;
                        if started && depth <= 0 {
                            break;
                        }
                    }
                    results.push((name, body));
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
        results
    }

    /// Naming convention every status-subresource PUT handler in this codebase follows.
    fn status_put_handler_bodies(source: &str) -> Vec<(String, String)> {
        handler_bodies_matching(source, |name| {
            (name.starts_with("put_") || name.starts_with("replace_")) && name.contains("status")
        })
    }

    /// Naming convention every status-subresource PATCH handler in this codebase follows.
    fn patch_status_handler_bodies(source: &str) -> Vec<(String, String)> {
        handler_bodies_matching(source, |name| {
            name.starts_with("patch_") && name.contains("status")
        })
    }

    /// Naming convention every MAIN-resource (non-status) mutating handler in this codebase
    /// follows: a full-object PUT is always named `replace_*`, a PATCH is always `patch_*`.
    fn main_resource_handler_bodies(source: &str) -> Vec<(String, String)> {
        handler_bodies_matching(source, |name| {
            (name.starts_with("patch_") || name.starts_with("replace_")) && !name.contains("status")
        })
    }

    /// Every `Store` method that actually persists new object bytes, as called from
    /// handler source text. `create_if_namespace_active` wraps `put` internally (see
    /// `Store::create_if_namespace_active`'s default impl in store/src/lib.rs) — listed
    /// separately here because a handler persisting solely through it has no literal
    /// `.put(` substring in its own body and would otherwise be silently skipped by
    /// `every_main_resource_write_handler_preserves_stored_status`.
    fn calls_store_write_entry_point(body: &str) -> bool {
        const STORE_WRITE_ENTRY_POINTS: &[&str] = &[".put(", ".create_if_namespace_active("];
        STORE_WRITE_ENTRY_POINTS
            .iter()
            .any(|entry_point| body.contains(entry_point))
    }

    /// `every_main_resource_write_handler_preserves_stored_status` only inspects handlers
    /// whose body trips this detector — a future handler that persists solely through
    /// `create_if_namespace_active` (skipping `put` entirely) must not be silently exempted
    /// from the stored_status check just because that method's name doesn't contain the
    /// literal substring `.put(`. Fails on revert: narrowing `calls_store_write_entry_point`
    /// back to only `.put(` makes the `create_if_namespace_active`-only case below return
    /// false.
    #[test]
    fn calls_store_write_entry_point_catches_create_if_namespace_active_only_handlers() {
        assert!(
            calls_store_write_entry_point("state.store.put(&key, bytes, None).await"),
            "a handler calling .put( directly must be detected"
        );
        assert!(
            calls_store_write_entry_point(
                "state.store.create_if_namespace_active(Some(&ns_key), &key, bytes).await"
            ),
            "a handler persisting solely via create_if_namespace_active (which wraps put \
             internally) must still be detected, not silently skipped by the completeness \
             scan just because its body lacks the literal substring \".put(\""
        );
        assert!(
            !calls_store_write_entry_point("state.store.get(&key).await"),
            "a handler that only reads from the store must not be flagged as a write handler"
        );
    }
}
