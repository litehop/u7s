//! /approval subresource handler for CertificateSigningRequest.
//!
//! `kubectl certificate approve/deny` and the kube-controller-manager CSR controller
//! use PUT/PATCH on `.../certificatesigningrequests/{name}/approval` exclusively.
//!
//! Semantics:
//!   - Merges incoming `status.conditions` into the stored object's conditions list.
//!   - MUST NOT touch `spec` or `status.certificate` — those are controlled by
//!     the signer, not the approver.
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
    handlers::json_patch::{apply_json_patch, detect_patch_type, PatchType},
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
/// Merges `status.conditions` from the incoming body into the stored object.
/// Never modifies `spec` or `status.certificate`.
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

    // Merge only status.conditions — never touch spec or status.certificate.
    merge_approval_conditions(&mut current, &incoming);

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
/// changed. spec and status.certificate are never modified.
pub async fn patch_approval<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_name("name", &name)?;
    let patch_type = detect_patch_type(&headers)?;

    let key = group_object_key(GROUP, PLURAL, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // Deserialize current status to extract the certificate field before patching.
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
            // JSON Patch addresses the full document — apply as-is, then restore protected fields.
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
        }
    }

    // Restore protected fields — spec and status.certificate must never change via /approval.
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

    fn json_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    }

    fn make_state() -> AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
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

        // Advance the stored object so rv=1 is now stale.
        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        let stored = store.get(&key).await.unwrap().unwrap();
        let mut obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        obj["status"]["conditions"] = serde_json::json!([]);
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
