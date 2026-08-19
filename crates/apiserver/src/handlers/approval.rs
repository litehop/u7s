//! /approval subresource handler for CertificateSigningRequest.
//!
//! `kubectl certificate approve/deny` and the kube-controller-manager CSR controller
//! use PUT/PATCH on `.../certificatesigningrequests/{name}/approval` exclusively.
//!
//! Semantics:
//!   - Merges incoming `status.conditions` into the stored object's conditions list.
//!   - Merges incoming `metadata` (labels/annotations) — same isolation rules as
//!     the /status subresource (identity fields and finalizers are protected).
//!   - MUST NOT touch `spec` or `status.certificate` — those are controlled by
//!     the signer, not the approver. For `application/json-patch+json`, which
//!     addresses the whole document with no structural isolation, ops outside
//!     `status.conditions`/`metadata.annotations` are rejected with 422 rather
//!     than silently dropped (see `validate_approval_json_patch_paths`).
//!   - Honours `resourceVersion` in incoming body for OCC (returns 409 on conflict).

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use bytes::Bytes;

use crate::{
    handlers::generic::{store_err, validate_name},
    handlers::json_patch::{apply_json_patch, detect_patch_type, ssa_body_to_json, PatchType},
    handlers::status::merge_incoming_metadata,
    keys::group_object_key,
    state::AppState,
    status::Status,
    types::{CertificateSigningRequestStatus, Object},
    util::{content_type, extract_body, parse_resource_version},
};
use u7s_store::Store;

const GROUP: &str = "certificates.k8s.io";
const PLURAL: &str = "certificatesigningrequests";
const KIND: &str = "CertificateSigningRequest";

/// PUT /apis/certificates.k8s.io/v1/certificatesigningrequests/{name}/approval
///
/// Merges `status.conditions` and `metadata` (labels/annotations) from the
/// incoming body into the stored object. Never modifies `spec` or `status.certificate`.
pub async fn put_approval<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("name", &name)?;
    let body = extract_body(&body, content_type(&headers));
    let incoming =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = group_object_key(GROUP, PLURAL, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // OCC: if incoming has a resourceVersion, it must match the stored one.
    let expected_rv = parse_resource_version(incoming.resource_version())?;

    // Merge status.conditions and metadata (labels/annotations) — never touch spec or
    // status.certificate. kubectl certificate approve/deny sends the whole object back,
    // and clients (e.g. this conformance test) also PATCH/PUT annotations via /approval.
    merge_approval_conditions(&mut current, &incoming);
    merge_incoming_metadata(&mut current.body, &incoming.body, KIND);

    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, KIND))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

/// PATCH /apis/certificates.k8s.io/v1/certificatesigningrequests/{name}/approval
///
/// Applies a patch to the approval subresource. Only status.conditions may be
/// changed. spec and status.certificate are never modified — for JSON Patch,
/// which addresses the whole document, ops outside status.conditions/
/// metadata.annotations are rejected outright (see `validate_approval_json_patch_paths`).
pub async fn patch_approval<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("name", &name)?;
    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");

    let key = group_object_key(GROUP, PLURAL, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // apply-patch+yaml bodies are genuine YAML (e.g. kubectl apply --server-side); every
    // other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
    };

    // Snapshot fields /approval must never change, before applying any patch type.
    // `spec_before` is restored unconditionally below regardless of patch type —
    // defense in depth alongside the PatchType::Json path check just below, so a
    // bug in (or future change to) that check can never let a JSON Patch smuggle a
    // different spec.request/spec.signerName past approval.
    let spec_before = current.body["spec"].clone();
    let status_before: CertificateSigningRequestStatus =
        serde_json::from_value(current.body["status"].clone()).unwrap_or_else(|_| {
            CertificateSigningRequestStatus {
                certificate: None,
                conditions: None,
                rest: serde_json::Value::Object(Default::default()),
            }
        });

    match patch_type {
        PatchType::Json => {
            // Unlike a merge patch, JSON Patch addresses the full document with no
            // structural isolation — an op can name /spec or any metadata field.
            // Reject the whole patch up front if it targets anything outside the
            // fields /approval may change, instead of applying it and relying
            // solely on restoring the damage afterward.
            validate_approval_json_patch_paths(&patch)?;
            apply_json_patch(&mut current.body, &patch)?;
        }
        PatchType::Merge | PatchType::StrategicMerge => {
            // Deserialize the patch status to get typed conditions.
            let patch_status: Option<CertificateSigningRequestStatus> = patch
                .get("status")
                .and_then(|s| serde_json::from_value(s.clone()).ok());
            if let Some(ps) = patch_status {
                if let Some(conditions) = ps.conditions {
                    current.body["status"]["conditions"] =
                        serde_json::to_value(conditions).unwrap_or(serde_json::Value::Null);
                }
            }
            // Merge metadata (labels/annotations) from the patch — kubectl certificate
            // approve/deny and this conformance test also patch annotations via /approval.
            merge_incoming_metadata(&mut current.body, &patch, KIND);
        }
    }

    // Restore protected fields — spec and status.certificate must never change via
    // /approval, for every patch type (not just PatchType::Json).
    match spec_before {
        serde_json::Value::Null => {
            // Make sure spec wasn't introduced by the patch (a CSR always has one,
            // but a stored object shouldn't gain a spec it didn't have).
            if let Some(m) = current.body.as_object_mut() {
                m.remove("spec");
            }
        }
        v => current.body["spec"] = v,
    }
    match &status_before.certificate {
        Some(cert) => {
            current.body["status"]["certificate"] = serde_json::Value::String(cert.clone());
        }
        None => {
            // Make sure it wasn't introduced by the patch.
            if let Some(s) = current.body["status"].as_object_mut() {
                s.remove("certificate");
            }
        }
    }

    let expected_rv = parse_resource_version(patch["metadata"]["resourceVersion"].as_str())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, &name, KIND))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

/// Validate that every JSON Patch op targeting `/approval` addresses only
/// `status.conditions` or `metadata.annotations` — the two fields `/approval` may
/// change. Mirrors `handlers::status::validate_status_json_patch_paths`, which
/// exists for the identical reason on the `/status` subresource.
///
/// JSON Patch (RFC 6902) addresses the entire stored document with no built-in
/// notion of subresource boundaries, unlike the Merge/StrategicMerge branch in
/// `patch_approval`, which only ever writes `status.conditions` and routes
/// metadata through `merge_incoming_metadata`. Without this check, a caller
/// holding only `certificatesigningrequests/approval` update rights — granted
/// specifically so they can approve/deny a CSR WITHOUT controlling what gets
/// signed — could get a CSR approved, then PATCH `/approval` again with a JSON
/// Patch replacing `spec.request`/`spec.signerName` with a different, unreviewed
/// request and have an external signer issue a trusted certificate for an
/// attacker-chosen identity.
///
/// Rejects (422) the whole patch rather than silently dropping the offending op,
/// so the caller gets a clear signal instead of a write that looks like it worked
/// but didn't.
pub(crate) fn validate_approval_json_patch_paths(
    patch: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    const ALLOWED: &[&str] = &["/status/conditions", "/metadata/annotations"];
    let ops = patch
        .as_array()
        .ok_or_else(|| Status::unprocessable_entity("JSON patch must be an array".into()))?;
    for op in ops {
        let path = op["path"].as_str().ok_or_else(|| {
            Status::unprocessable_entity("JSON patch op missing 'path' field".into())
        })?;
        let allowed = ALLOWED
            .iter()
            .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")));
        if !allowed {
            return Err(Status::unprocessable_entity(format!(
                "JSON patch on /approval subresource may only target /status/conditions or \
                 /metadata/annotations; got '{path}'"
            )));
        }
    }
    Ok(())
}

/// Merge `status.conditions` from `incoming` into `current`.
///
/// Replaces the entire conditions list with the incoming one. This matches
/// kubectl certificate approve/deny behaviour: the client reads the object,
/// appends/modifies conditions, and writes it back.
///
/// INVARIANT: `status.certificate` in `current` is never touched.
pub(crate) fn merge_approval_conditions(current: &mut Object, incoming: &Object) {
    // Deserialize the incoming status to get typed conditions.
    let incoming_status: Option<CertificateSigningRequestStatus> =
        serde_json::from_value(incoming.body["status"].clone()).ok();

    if let Some(status) = incoming_status {
        if let Some(conditions) = status.conditions {
            current.body["status"]["conditions"] =
                serde_json::to_value(conditions).unwrap_or(serde_json::Value::Null);
        }
    }
    // Explicitly do NOT copy status.certificate from incoming.
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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

    async fn seed_csr(store: &Arc<SqliteStore>, name: &str, certificate: Option<&str>) -> String {
        let mut status = json!({
            "conditions": []
        });
        if let Some(cert) = certificate {
            status["certificate"] = json!(cert);
        }
        let csr = json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {
                "name": name,
                "resourceVersion": "1"
            },
            "spec": {
                "request": "dGVzdA==",
                "signerName": "kubernetes.io/kube-apiserver-client"
            },
            "status": status
        });
        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let bytes = bytes::Bytes::from(serde_json::to_vec(&csr).unwrap());
        store.put(&key, bytes, None).await.unwrap();
        key
    }

    /// PUT /approval with Denied condition must NOT write status.certificate.
    ///
    /// An approver sets conditions[].type=Denied. The signer should never issue
    /// a certificate for a denied request. If /approval could write the certificate
    /// field, a malicious approver could bypass the signer entirely.
    #[tokio::test]
    async fn put_approval_denied_does_not_write_certificate() {
        let state = make_state();
        let name = "denied-csr";
        seed_csr(&state.store, name, None).await;

        let put_body = json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": name, "resourceVersion": "1"},
            "spec": {
                "request": "dGVzdA==",
                "signerName": "kubernetes.io/kube-apiserver-client"
            },
            "status": {
                "conditions": [{
                    "type": "Denied",
                    "status": "True",
                    "reason": "Denied by test",
                    "message": "denied"
                }],
                "certificate": "SHOULD_NOT_BE_STORED"
            }
        });

        let result = put_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        assert!(result.is_ok(), "PUT /approval must succeed");

        // Verify: conditions were written, but certificate was NOT written.
        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = state.store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let conditions = v["status"]["conditions"].as_array().unwrap();
        assert_eq!(conditions.len(), 1, "Denied condition must be stored");
        assert_eq!(conditions[0]["type"], "Denied");

        // The certificate field must not have been written by /approval.
        assert!(
            v["status"]["certificate"].is_null() || v["status"].get("certificate").is_none(),
            "PUT /approval with Denied condition must NOT write status.certificate — \
             only the signer controller may write certificates"
        );
    }

    /// PUT /approval with Approved condition — conditions stored, no certificate.
    ///
    /// After approval, the signer writes the certificate via /status. The /approval
    /// handler must not write it. This test covers the normal approve workflow.
    #[tokio::test]
    async fn put_approval_approved_stores_conditions_not_certificate() {
        let state = make_state();
        let name = "approved-csr";
        seed_csr(&state.store, name, None).await;

        let put_body = json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": name, "resourceVersion": "1"},
            "spec": {
                "request": "dGVzdA==",
                "signerName": "kubernetes.io/kube-apiserver-client"
            },
            "status": {
                "conditions": [{
                    "type": "Approved",
                    "status": "True",
                    "reason": "Approved by test",
                    "message": "approved"
                }]
            }
        });

        let result = put_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        assert!(result.is_ok(), "PUT /approval with Approved must succeed");

        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = state.store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let conditions = v["status"]["conditions"].as_array().unwrap();
        assert_eq!(conditions[0]["type"], "Approved");
        assert!(
            v["status"]["certificate"].is_null() || v["status"].get("certificate").is_none(),
            "/approval must not write certificate — that is the signer's job"
        );
    }

    /// PUT /approval must persist every typed `CsrCondition` field exactly as
    /// sent, and must persist them via the typed `CertificateSigningRequestStatus`/
    /// `CsrCondition` structs, not by re-serializing an untouched raw `Value`.
    ///
    /// WHY this matters: approval is a security-relevant decision record — `reason`
    /// and `lastUpdateTime` are the audit trail of who approved a CSR and when. If
    /// the typed struct silently dropped a field (e.g. a future refactor removes
    /// `reason` from `CsrCondition`), the condition would still "look" stored (the
    /// `type`/`status` checks in other tests would still pass) while quietly losing
    /// the audit fields regulators and cluster admins rely on to review approvals.
    #[tokio::test]
    async fn put_approval_persists_every_typed_condition_field() {
        let state = make_state();
        let name = "full-fields-csr";
        seed_csr(&state.store, name, None).await;

        let put_body = json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": name, "resourceVersion": "1"},
            "spec": {
                "request": "dGVzdA==",
                "signerName": "kubernetes.io/kube-apiserver-client"
            },
            "status": {
                "conditions": [{
                    "type": "Approved",
                    "status": "True",
                    "reason": "AutoApproved",
                    "message": "approved by node-csr-approver",
                    "lastUpdateTime": "2024-01-01T00:00:00Z"
                }]
            }
        });

        let result = put_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;
        assert!(result.is_ok(), "PUT /approval must succeed");

        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = state.store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let cond = &v["status"]["conditions"][0];

        assert_eq!(cond["type"], "Approved", "condition type must be preserved");
        assert_eq!(cond["status"], "True", "condition status must be preserved");
        assert_eq!(
            cond["reason"], "AutoApproved",
            "condition reason must be preserved — it's the audit record of why a CSR was approved"
        );
        assert_eq!(
            cond["message"], "approved by node-csr-approver",
            "condition message must be preserved — it's part of the same audit record"
        );
        assert_eq!(
            cond["lastUpdateTime"], "2024-01-01T00:00:00Z",
            "condition lastUpdateTime must be preserved — it's the audit record of when a CSR was approved"
        );

        // Same security invariant as put_approval_approved_stores_conditions_not_certificate,
        // asserted again here so a fields-only regression can't accidentally also start
        // writing the certificate.
        assert!(
            v["status"]["certificate"].is_null() || v["status"].get("certificate").is_none(),
            "/approval must never write status.certificate, regardless of which condition \
             fields are sent — only the signer may issue a certificate"
        );
    }

    /// PUT /approval with stale resourceVersion → 409 Conflict.
    ///
    /// OCC prevents two approvers from overwriting each other's decisions.
    /// A stale PUT must be rejected to avoid a lost-update scenario.
    #[tokio::test]
    async fn put_approval_stale_resource_version_returns_409() {
        let state = make_state();
        let name = "occ-csr";
        seed_csr(&state.store, name, None).await;

        let put_body = json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": name, "resourceVersion": "9999"},
            "spec": {"request": "dGVzdA==", "signerName": "kubernetes.io/kube-apiserver-client"},
            "status": {
                "conditions": [{"type": "Approved", "status": "True", "reason": "test", "message": ""}]
            }
        });

        let result = put_approval(
            axum::extract::State(state),
            axum::extract::Path(name.to_owned()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::CONFLICT,
                "stale resourceVersion on /approval must return 409 Conflict — OCC violated"
            ),
            Ok(_) => panic!("stale PUT /approval must be rejected"),
        }
    }

    /// PUT /approval on non-existent CSR → 404.
    #[tokio::test]
    async fn put_approval_missing_csr_returns_404() {
        let state = make_state();

        let put_body = json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "nonexistent"},
            "spec": {"request": "dGVzdA==", "signerName": "kubernetes.io/kube-apiserver-client"},
            "status": {"conditions": []}
        });

        let result = put_approval(
            axum::extract::State(state),
            axum::extract::Path("nonexistent".to_owned()),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND),
            Ok(_) => panic!("PUT /approval on missing CSR must return 404"),
        }
    }

    /// PATCH /approval with merge-patch+json must update status.conditions.
    ///
    /// kubectl certificate approve sends a strategic-merge-patch or merge-patch.
    /// The handler must accept it and apply only the conditions — never spec or certificate.
    #[tokio::test]
    async fn patch_approval_merge_patch_updates_conditions() {
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
        let name = "patch-merge-csr";
        seed_csr(&store, name, None).await;

        let patch_body = json!({
            "status": {
                "conditions": [{
                    "type": "Approved",
                    "status": "True",
                    "reason": "ManualApproval",
                    "message": "approved via patch"
                }]
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "PATCH /approval with merge-patch must succeed"
        );

        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let conds = v["status"]["conditions"].as_array().unwrap();
        assert_eq!(
            conds[0]["type"], "Approved",
            "merge-patch on /approval must write Approved condition"
        );
        assert!(
            v["status"]["certificate"].is_null() || v["status"].get("certificate").is_none(),
            "patch_approval must not write certificate field — that belongs to the signer"
        );
    }

    /// PATCH /approval with a genuine multi-line YAML apply-patch+yaml body must succeed,
    /// not 400 "invalid patch JSON".
    ///
    /// WHY this matters: `kubectl certificate approve/deny --server-side` sends real YAML
    /// block syntax. Before this fix, patch_approval had no is_ssa handling at all — every
    /// apply-patch+yaml body was parsed with serde_json::from_slice, which rejects YAML
    /// outright, even though detect_patch_type already accepted the content type.
    #[tokio::test]
    async fn patch_approval_accepts_real_yaml_apply_patch_body() {
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
        let name = "yaml-approval-csr";
        seed_csr(&store, name, None).await;

        // Genuine YAML block syntax — NOT JSON serialized to bytes.
        let patch_body = "status:\n  conditions:\n  - type: Approved\n    status: \"True\"\n    reason: ManualApproval\n    message: approved via yaml ssa\n";

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        let result = patch_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from_static(patch_body.as_bytes()),
        )
        .await;

        assert!(
            result.is_ok(),
            "PATCH /approval with a genuine YAML apply-patch+yaml body must succeed, not 400 \
             'invalid patch JSON': {:?}",
            result.err()
        );
    }

    /// PATCH /approval with a merge-patch carrying both `metadata.annotations` and
    /// `status.conditions` must apply both — not just the conditions.
    ///
    /// The sig-auth "CSR API operations" conformance test sends exactly this shape
    /// (`{"metadata":{"annotations":{"patchedapproval":"true"}},"status":{"conditions":[...]}}`)
    /// and asserts the returned object has the annotation. If patch_approval only merged
    /// status.conditions and silently dropped the metadata half, the response reflects the
    /// object's annotations from *before* this patch — which breaks any client (including
    /// this test) that patches metadata and status together via /approval.
    #[tokio::test]
    async fn patch_approval_merge_patch_applies_annotations_and_conditions_together() {
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
        let name = "patch-approval-annotation-csr";
        seed_csr(&store, name, None).await;

        let patch_body = json!({
            "metadata": {"annotations": {"patchedapproval": "true"}},
            "status": {
                "conditions": [{
                    "type": "ApprovalPatch",
                    "status": "True",
                    "reason": "e2e",
                    "message": ""
                }]
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        let resp = match result {
            Ok(r) => r.into_response(),
            Err(e) => panic!("PATCH /approval with annotations+conditions must succeed: {e:?}"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let returned: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            returned["metadata"]["annotations"]["patchedapproval"], "true",
            "patched object should have the applied annotation — the response must reflect \
             the metadata half of the merge patch, not just status.conditions"
        );
        let conds = returned["status"]["conditions"].as_array().unwrap();
        assert_eq!(
            conds.len(),
            1,
            "patched object should have the applied condition"
        );
        assert_eq!(conds[0]["type"], "ApprovalPatch");
    }

    /// PATCH /approval with json-patch+json must apply the patch (JSON Patch path).
    ///
    /// This covers the PatchType::Json branch, which addresses the full document
    /// then restores protected fields. The net effect must be correct conditions.
    #[tokio::test]
    async fn patch_approval_json_patch_updates_conditions() {
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
        let name = "patch-json-csr";
        seed_csr(&store, name, None).await;

        // Add a condition via JSON Patch
        let patch_body = json!([
            {
                "op": "add",
                "path": "/status/conditions/-",
                "value": {
                    "type": "Denied",
                    "status": "True",
                    "reason": "SecurityPolicy",
                    "message": "denied via json-patch"
                }
            }
        ]);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "PATCH /approval with json-patch must succeed"
        );

        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let conds = v["status"]["conditions"].as_array().unwrap();
        assert!(
            conds.iter().any(|c| c["type"] == "Denied"),
            "json-patch on /approval must add the Denied condition"
        );
    }

    // ---------------------------------------------------------------------------
    // JSON-Patch /spec and protected-metadata escalation — security regression
    // ---------------------------------------------------------------------------

    /// PATCH /approval with json-patch+json replacing /spec/request must be
    /// rejected and must NOT change the stored spec.request.
    ///
    /// `certificatesigningrequests/approval` is RBAC's mechanism for granting
    /// "can approve/deny" WITHOUT granting control over what's being signed.
    /// Before this fix, `apply_json_patch` mutated the whole stored document and
    /// only `status.certificate` was restored afterward, so a caller with only
    /// approval rights could get a CSR approved, then swap `spec.request` to a
    /// different, unreviewed request via this same subresource and have an
    /// external signer (e.g. kube-controller-manager's csrsigningcontroller)
    /// issue a trusted certificate for whatever identity the replacement request
    /// encodes — a full authentication-boundary escalation, not just a
    /// data-integrity bug.
    #[tokio::test]
    async fn patch_approval_json_patch_cannot_replace_spec_request() {
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
        let name = "escalation-request-csr";
        seed_csr(&store, name, None).await;

        // Attacker-controlled request encoding a different, unreviewed CSR — in a
        // real cluster this would be one requesting e.g. O=system:masters.
        let patch_body = json!([
            {
                "op": "replace",
                "path": "/spec/request",
                "value": "QVRUQUNLRVJfQ09OVFJPTExFRF9DU1I="
            }
        ]);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "a JSON Patch targeting /spec via /approval must be rejected with 422, \
                 not silently applied or silently dropped"
            ),
            Ok(_) => panic!(
                "PATCH /approval must reject a JSON Patch targeting /spec/request — \
                 accepting it lets an approval-only-scoped caller swap in an unreviewed \
                 signing request after approval and get a certificate issued for an \
                 attacker-chosen identity"
            ),
        }

        // Whatever the response, the stored spec.request must be untouched — this
        // is the exact escalation path the audit found.
        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["request"], "dGVzdA==",
            "spec.request must never change via /approval regardless of patch type — \
             an approval-only RBAC grant must not be able to control what gets signed"
        );
    }

    /// PATCH /approval with json-patch+json replacing /spec/signerName must be
    /// rejected and must NOT change the stored spec.signerName.
    ///
    /// Same escalation as spec.request: swapping the signer can route an
    /// already-approved CSR to a signer whose issuance policy the approver never
    /// reviewed (e.g. from a narrowly-scoped signer to `kubernetes.io/kube-apiserver-client`).
    #[tokio::test]
    async fn patch_approval_json_patch_cannot_replace_spec_signer_name() {
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
        let name = "escalation-signer-csr";
        seed_csr(&store, name, None).await;

        // seed_csr sets signerName to "kubernetes.io/kube-apiserver-client"; the
        // attacker reroutes to a different signer that never reviewed the request.
        let patch_body = json!([
            {
                "op": "replace",
                "path": "/spec/signerName",
                "value": "attacker.example.com/evil-signer"
            }
        ]);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "a JSON Patch targeting /spec via /approval must be rejected with 422"
            ),
            Ok(_) => panic!(
                "PATCH /approval must reject a JSON Patch targeting /spec/signerName — \
                 an approval-only-scoped caller must not be able to reroute an approved \
                 CSR to a different signer"
            ),
        }

        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["signerName"], "kubernetes.io/kube-apiserver-client",
            "spec.signerName must never change via /approval regardless of patch type — \
             rerouting an approved CSR to a different, unreviewed signer is the same \
             authentication-boundary escalation as swapping spec.request"
        );
    }

    /// PATCH /approval with json-patch+json adding `/metadata/labels` must be
    /// rejected and must NOT change the stored labels.
    ///
    /// Labels drive policy decisions elsewhere (selector-based matching, PSA
    /// enforcement) and are protected on `/status` for the same reason (see
    /// `merge_incoming_metadata`'s PROTECTED list) — `/approval` must not let a
    /// JSON Patch bypass that protection just because JSON Patch addresses the
    /// whole document instead of a scoped sub-object.
    #[tokio::test]
    async fn patch_approval_json_patch_cannot_change_protected_metadata_labels() {
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
        let name = "escalation-labels-csr";
        seed_csr(&store, name, None).await;

        let patch_body = json!([
            {
                "op": "add",
                "path": "/metadata/labels",
                "value": {"escalated": "true"}
            }
        ]);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "a JSON Patch targeting /metadata/labels via /approval must be rejected \
                 with 422 — approval-only rights must not be able to rewrite labels"
            ),
            Ok(_) => panic!("PATCH /approval must reject a JSON Patch targeting /metadata/labels"),
        }

        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"].get("labels").is_none() || v["metadata"]["labels"].is_null(),
            "labels must never be introduced via a JSON Patch to /approval"
        );
    }

    /// PATCH /approval with json-patch+json adding `/metadata/annotations` must
    /// still succeed — the path-restriction fix must not break this legitimate,
    /// already-supported use (kubectl certificate approve/deny and the sig-auth
    /// CSR conformance test also tag approvals via annotations, just via merge
    /// patch rather than JSON Patch).
    #[tokio::test]
    async fn patch_approval_json_patch_can_still_add_annotation() {
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
        let name = "legit-annotation-csr";
        seed_csr(&store, name, None).await;

        let patch_body = json!([
            {
                "op": "add",
                "path": "/metadata/annotations",
                "value": {"approved-by": "test-operator"}
            }
        ]);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        if let Err(e) = &result {
            panic!(
                "a JSON Patch adding /metadata/annotations via /approval must still succeed — \
                 over-tightening the /spec fix must not break this legitimate use: {e:?}"
            );
        }

        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["annotations"]["approved-by"], "test-operator",
            "the annotation from a legitimate JSON Patch must be persisted"
        );
    }

    /// PATCH /approval with a stale resourceVersion must return 409 Conflict.
    ///
    /// Two approvers patching the same CSR concurrently must not silently clobber each other.
    /// Without CAS, the second PATCH always succeeds regardless of resourceVersion because
    /// patch_approval used the stored object's RV (always matches) as the CAS token.
    #[tokio::test]
    async fn patch_approval_stale_rv_returns_409_else_concurrent_approvers_clobber() {
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
        let name = "stale-rv-csr";
        seed_csr(&store, name, None).await;

        // Advance the stored object so rv=1 is now stale, via a genuine change (a peer
        // approver's condition) — the store suppresses no-op writes, so re-writing the same
        // empty conditions list would not have advanced the revision at all.
        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = store.get(&key).await.unwrap().unwrap();
        let mut obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        obj["status"]["conditions"] = serde_json::json!([
            {"type": "Approved", "status": "True", "reason": "peer", "message": ""}
        ]);
        let rv1 = stored.revision;
        // Write a new revision so rv1 becomes stale.
        let rv2 = store
            .put(
                &key,
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance");

        // PATCH carries the stale rv1.
        let patch_body = serde_json::json!({
            "metadata": { "name": name, "resourceVersion": rv1.to_string() },
            "status": {
                "conditions": [{"type": "Approved", "status": "True", "reason": "test", "message": ""}]
            }
        });
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::CONFLICT,
                "stale resourceVersion in PATCH /approval body must return 409 — \
                 two concurrent approvers must not silently clobber each other"
            ),
            Ok(_) => panic!(
                "PATCH /approval with stale resourceVersion must be rejected with 409, \
                 else concurrent approvers silently overwrite each other's decisions"
            ),
        }
    }

    /// PATCH /approval with no resourceVersion in the patch body succeeds unconditionally.
    ///
    /// Clients that omit metadata.resourceVersion must not be broken by the PATCH CAS fix.
    #[tokio::test]
    async fn patch_approval_absent_rv_is_unconditional_write() {
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
        let name = "norev-approval-csr";
        seed_csr(&store, name, None).await;

        let patch_body = serde_json::json!({
            "status": {
                "conditions": [{"type": "Approved", "status": "True", "reason": "test", "message": ""}]
            }
        });
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "PATCH /approval without metadata.resourceVersion must succeed (unconditional) — \
             clients that omit rv must not be broken by the stale-RV CAS fix"
        );
    }

    /// PATCH /approval on a missing CSR must return 404.
    ///
    /// There is nothing to patch if the CSR doesn't exist.
    #[tokio::test]
    async fn patch_approval_missing_csr_returns_404() {
        let state = make_state();

        let patch_body = json!({"status": {"conditions": []}});

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state),
            axum::extract::Path("nonexistent-csr".to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::NOT_FOUND,
                "PATCH /approval on missing CSR must return 404"
            ),
            Ok(_) => panic!("PATCH /approval on missing CSR must return 404"),
        }
    }

    /// PATCH /approval with wrong content-type must return 415.
    ///
    /// patch_approval delegates content-type detection to detect_patch_type,
    /// which rejects unknown types with 415 Unsupported Media Type.
    #[tokio::test]
    async fn patch_approval_wrong_content_type_returns_415() {
        let state = make_state();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let result = patch_approval(
            axum::extract::State(state),
            axum::extract::Path("any-csr".to_owned()),
            headers,
            bytes::Bytes::from(r#"{"status":{}}"#),
        )
        .await;

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "PATCH /approval with application/json must return 415 — \
                 only merge-patch, strategic-merge-patch, and json-patch are valid"
            ),
            Ok(_) => panic!("wrong content-type must return 415"),
        }
    }

    /// PATCH /approval with strategic-merge-patch must update conditions.
    ///
    /// Same semantics as merge-patch: only the status.conditions from the patch body
    /// are applied. spec and status.certificate must not be modified.
    #[tokio::test]
    async fn patch_approval_strategic_merge_patch_updates_conditions() {
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
        let name = "smp-csr";
        seed_csr(&store, name, Some("EXISTING_CERT")).await;

        let patch_body = json!({
            "status": {
                "conditions": [{
                    "type": "Approved",
                    "status": "True",
                    "reason": "SMP",
                    "message": "approved via smp"
                }]
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );

        let result = patch_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path(name.to_owned()),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&patch_body).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "PATCH /approval with strategic-merge-patch must succeed"
        );

        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = store.get(&key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let conds = v["status"]["conditions"].as_array().unwrap();
        assert_eq!(
            conds[0]["type"], "Approved",
            "strategic-merge-patch on /approval must write Approved condition"
        );

        // status.certificate was present before patch — it must be preserved.
        assert_eq!(
            v["status"]["certificate"], "EXISTING_CERT",
            "patch_approval must not erase a pre-existing status.certificate — \
             the signer already issued a cert; patching approval conditions must not invalidate it"
        );
    }

    /// merge_approval_conditions must preserve status.certificate when present.
    ///
    /// The signer writes status.certificate. If a subsequent /approval PUT is made,
    /// merge_approval_conditions must not erase the certificate.
    #[test]
    fn merge_approval_conditions_preserves_existing_certificate() {
        let mut current = Object {
            body: json!({
                "metadata": {"name": "test", "resourceVersion": "5"},
                "spec": {"request": "dGVzdA=="},
                "status": {
                    "certificate": "CERT_DATA",
                    "conditions": []
                }
            }),
        };
        let incoming = Object {
            body: json!({
                "status": {
                    "conditions": [{"type": "Approved", "status": "True", "reason": "ok", "message": ""}]
                }
            }),
        };

        merge_approval_conditions(&mut current, &incoming);

        assert_eq!(
            current.body["status"]["certificate"], "CERT_DATA",
            "merge_approval_conditions must preserve existing status.certificate — \
             erasing it would force the signer to re-issue the certificate"
        );
        let conds = current.body["status"]["conditions"].as_array().unwrap();
        assert_eq!(conds[0]["type"], "Approved");
    }
}
