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
    types::Object,
    util::{content_type, extract_body, parse_resource_version},
};
use u7s_store::Store as _;

const GROUP: &str = "certificates.k8s.io";
const PLURAL: &str = "certificatesigningrequests";
const KIND: &str = "CertificateSigningRequest";

/// PUT /apis/certificates.k8s.io/v1/certificatesigningrequests/{name}/approval
///
/// Merges `status.conditions` from the incoming body into the stored object.
/// Never modifies `spec` or `status.certificate`.
pub async fn put_approval(
    State(state): State<AppState>,
    Path((_group, _version, _plural, name)): Path<(String, String, String, String)>,
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
pub async fn patch_approval(
    State(state): State<AppState>,
    Path((_group, _version, _plural, name)): Path<(String, String, String, String)>,
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

    // Save the certificate field before patching so we can restore it afterward.
    let certificate_before = current.body["status"]["certificate"].clone();

    match patch_type {
        PatchType::Json => {
            // JSON Patch addresses the full document — apply as-is, then restore protected fields.
            apply_json_patch(&mut current.body, &patch)?;
        }
        PatchType::Merge | PatchType::StrategicMerge => {
            // Only merge the conditions portion of status.
            if let Some(conditions) = patch.get("status").and_then(|s| s.get("conditions")) {
                current.body["status"]["conditions"] = conditions.clone();
            }
        }
    }

    // Restore protected fields — spec and status.certificate must never change via /approval.
    if !certificate_before.is_null() {
        current.body["status"]["certificate"] = certificate_before;
    } else {
        // Make sure it wasn't introduced by the patch.
        if let Some(s) = current.body["status"].as_object_mut() {
            s.remove("certificate");
        }
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
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
    // Replace conditions list; leave everything else in status (including certificate) alone.
    let new_conditions = &incoming.body["status"]["conditions"];
    if !new_conditions.is_null() {
        current.body["status"]["conditions"] = new_conditions.clone();
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
            axum::extract::Path((
                "certificates.k8s.io".into(),
                "v1".into(),
                "certificatesigningrequests".into(),
                name.into(),
            )),
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
            axum::extract::Path((
                "certificates.k8s.io".into(),
                "v1".into(),
                "certificatesigningrequests".into(),
                name.into(),
            )),
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
            axum::extract::Path((
                "certificates.k8s.io".into(),
                "v1".into(),
                "certificatesigningrequests".into(),
                name.into(),
            )),
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
            axum::extract::Path((
                "certificates.k8s.io".into(),
                "v1".into(),
                "certificatesigningrequests".into(),
                "nonexistent".into(),
            )),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&put_body).unwrap()),
        )
        .await;

        match result {
            Err(err) => assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND),
            Ok(_) => panic!("PUT /approval on missing CSR must return 404"),
        }
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
