//! Dedicated CSR POST handler with strict validation.
//!
//! The CSR POST path is security-critical: spec.request contains a base64-encoded
//! PEM-armored PKCS#10 CertificationRequest (this is the upstream Kubernetes wire
//! format — kubectl/client-go always base64-encode the PEM text, not raw DER). We
//! validate it here before storing — a signer that blindly issues a cert from
//! unchecked bytes could be tricked into signing arbitrary requests.
//!
//! Validation rules:
//!   1. spec.request must be present and non-empty (base64 string).
//!   2. spec.request must decode as valid standard base64.
//!   3. Decoded bytes must parse as a valid PEM-encoded PKCS#10 CertificationRequest.
//!   4. spec.signerName must be present and non-empty.
//!
//! Returns 422 Unprocessable Entity on any violation.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::Engine as _;
use bytes::Bytes;
use x509_cert::der::DecodePem as _;
use x509_cert::request::CertReq;

use u7s_store::{ListOptions, Store, StoreError};

use crate::{
    admission::{run_mutating_webhooks, run_validating_webhooks, AdmissionContext},
    auth::UserInfo,
    handlers::{
        generic::{
            apply_label_selector, build_list_response, decode_continue, generate_suffix, lookup,
            parse_field_selector, parse_label_selector, resolve_name, stamp_metadata,
            validate_name, wants_generate_name, CollectionQuery, MAX_GENERATE_NAME_CREATE_ATTEMPTS,
        },
        json_patch::is_dry_run_header,
        watch::{fetch_initial_events, watch_generic, WatchConfig},
    },
    keys::{group_list_prefix, group_object_key},
    state::AppState,
    status::Status,
    types::{CertificateSigningRequestSpec, Object},
    util::{content_type, extract_body},
};

const GROUP: &str = "certificates.k8s.io";
const VERSION: &str = "v1";
const PLURAL: &str = "certificatesigningrequests";
const KIND: &str = "CertificateSigningRequest";

/// Validate spec.request and spec.signerName, returning 422 on any violation.
///
/// Extracted as a pure function so it can be unit-tested without an HTTP stack.
pub(crate) fn validate_csr_spec(
    body: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    // Deserialize spec into a typed struct so field access is compiler-checked.
    let spec: CertificateSigningRequestSpec = serde_json::from_value(body["spec"].clone())
        .map_err(|e| {
            Status::unprocessable_entity(format!(
                "spec.request is required and must be a non-empty base64-encoded string: {e}"
            ))
        })?;

    // spec.request: required, must be non-empty base64, decoded bytes must be valid PEM PKCS#10.
    if spec.request.is_empty() {
        return Err(Status::unprocessable_entity(
            "spec.request is required and must be a non-empty base64-encoded string".into(),
        ));
    }

    let pem_bytes = base64::engine::general_purpose::STANDARD
        .decode(&spec.request)
        .map_err(|e| {
            Status::unprocessable_entity(format!("spec.request is not valid base64: {e}"))
        })?;

    CertReq::from_pem(&pem_bytes).map_err(|e| {
        Status::unprocessable_entity(format!(
            "spec.request does not contain a valid PEM-encoded PKCS#10 CertificationRequest: {e}"
        ))
    })?;

    // spec.signerName: required, non-empty.
    if spec.signer_name.is_empty() {
        return Err(Status::unprocessable_entity(
            "spec.signerName is required and must be a non-empty string".into(),
        ));
    }

    Ok(())
}

/// Stamp spec.username/uid/groups/extra from the authenticated caller's UserInfo,
/// discarding any client-supplied values for these fields.
///
/// Security-critical: kube-controller-manager's builtin csrapproving controller
/// authorizes auto-approval by building a SubjectAccessReview directly from these
/// spec fields (pkg/controller/certificates/approver/sarapprove.go's `authorize()`).
/// If a client could set them, it could submit a CSR claiming to be `system:node:foo`
/// in group `system:nodes` while authenticated as someone else entirely — KCM would
/// then approve and sign a client certificate for an identity the caller never proved
/// it holds. Called AFTER admission webhooks run (mirroring the existing status-strip's
/// position, not stamp_metadata's) so a registered mutating webhook cannot reintroduce
/// a spoofed value into these fields either — nothing downstream of this call can
/// undo the stamp before the object is persisted.
fn stamp_csr_identity(body: &mut serde_json::Value, user: &UserInfo) {
    if let Some(spec) = body.get_mut("spec").and_then(|s| s.as_object_mut()) {
        spec.insert(
            "username".to_string(),
            serde_json::Value::String(user.username.clone()),
        );
        spec.insert(
            "uid".to_string(),
            serde_json::Value::String(user.uid.clone()),
        );
        spec.insert(
            "groups".to_string(),
            serde_json::to_value(&user.groups).expect("Vec<String> always serializes"),
        );
        spec.insert(
            "extra".to_string(),
            serde_json::to_value(&user.extra)
                .expect("HashMap<String, Vec<String>> always serializes"),
        );
    }
}

/// GET /apis/certificates.k8s.io/v1/certificatesigningrequests
///
/// List all CertificateSigningRequests. The route is a hardcoded literal (no
/// path captures), so we hardcode group/version/plural instead of extracting
/// them — the generic list_resource handler requires Path<(String,String,String)>
/// which panics when axum finds 0 capture groups.
pub async fn list_csr<S: Store>(
    State(state): State<AppState<S>>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    // Lookup is infallible for the built-in CSR resource type.
    let meta = lookup(&state, GROUP, VERSION, PLURAL)?;
    let kind = meta.kind.clone();
    let prefix = group_list_prefix(GROUP, PLURAL, None);

    if query.watch == Some(true) {
        let from_rv = query.resource_version.unwrap_or(0);
        let initial = fetch_initial_events(
            &state,
            &prefix,
            query.send_initial_events == Some(true),
            "certificates.k8s.io",
            "certificatesigningrequests",
        )
        .await?;
        return watch_generic(
            state,
            WatchConfig {
                prefix,
                api_version: format!("{GROUP}/{VERSION}"),
                kind,
                from_revision: from_rv,
                initial_items: initial,
                label_selector: query.label_selector,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username: user.username,
                as_partial_object_metadata: false,
                group: GROUP.to_string(),
                plural: PLURAL.to_string(),
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
                field_selector,
                limit: query.limit,
                continue_key,
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let list_revision = continue_decoded.map(|(_, rv)| rv).unwrap_or(resp.revision);

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

    let body = build_list_response(
        &kind,
        GROUP,
        VERSION,
        list_revision,
        items,
        resp.continue_key,
        resp.remaining_count,
        &state.continue_token_key,
    );
    Ok(Json(body).into_response())
}

/// GET /apis/certificates.k8s.io/v1/certificatesigningrequests/{name}
/// (also used for the /approval subresource GET)
///
/// The approval route `/apis/certificates.k8s.io/v1/certificatesigningrequests/{name}/approval`
/// has only `{name}` as a capture group. The generic get_resource handler expects
/// Path<(String,String,String,String)> and would panic. This handler extracts only
/// the name and hardcodes the rest.
pub async fn get_csr<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
) -> Result<Response, crate::status::StatusError> {
    validate_name("name", &name)?;
    let key = group_object_key(GROUP, PLURAL, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

/// POST /apis/certificates.k8s.io/v1/certificatesigningrequests
///
/// Validates spec.request (base64 + PEM PKCS#10) and spec.signerName before
/// storing. Returns 422 on validation failure, 201 on success.
pub async fn create_csr<S: Store>(
    State(state): State<AppState<S>>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let body = extract_body(&body, content_type(&headers));
    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    validate_csr_spec(&obj.body)?;

    // Captured before resolve_name mutates metadata.name, so a store collision below
    // knows whether it's allowed to retry under a freshly generated name.
    let generate_name_prefix = wants_generate_name(&obj);
    let mut name = resolve_name(&mut obj)?;
    stamp_metadata(&mut obj);

    let admission_ctx = AdmissionContext {
        group: GROUP,
        version: VERSION,
        resource: PLURAL,
        name: &name,
        namespace: None,
        operation: "CREATE",
        user_info: Some(serde_json::json!({
            "username": user.username.clone(),
            "uid": user.uid.clone(),
            "groups": user.groups.clone(),
            "extra": user.extra.clone(),
        })),
        dry_run: is_dry_run_header(&headers),
    };
    obj.body = run_mutating_webhooks(&state, obj.body, None, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;

    // Re-stamp spec identity from the authenticated caller and strip status — neither may
    // survive a client, OR a mutating webhook, attempting to set them. spec is immutable
    // after create; status is the signer's exclusive write.
    stamp_csr_identity(&mut obj.body, &user);
    if let Some(map) = obj.body.as_object_mut() {
        map.remove("status");
    }

    // Counts store.put attempts made so far (the loop's first iteration is attempt 1).
    // Bounded at MAX_GENERATE_NAME_CREATE_ATTEMPTS TOTAL attempts, mirroring
    // create_resource/create_cr's generateName-collision retry (see resource.rs/cr.rs) —
    // a controller mass-creating CSRs via bare `metadata.generateName` must not see a
    // spurious 409 just because the server's random suffix landed on an existing name.
    let mut attempts_made = 1u32;
    let new_rv = loop {
        let key = group_object_key(GROUP, PLURAL, None, &name);
        match state.store.put(&key, obj.to_bytes(), Some(0)).await {
            Ok(rv) => break rv,
            // The client never chose this name (it came from generateName) — a collision
            // is the server's random suffix landing on an existing object, not a real
            // conflict the client should see. Retry with a fresh suffix instead of
            // surfacing a spurious 409 on what the client experiences as a plain create.
            Err(StoreError::AlreadyExists { .. })
                if generate_name_prefix.is_some()
                    && attempts_made < MAX_GENERATE_NAME_CREATE_ATTEMPTS =>
            {
                attempts_made += 1;
                name = format!(
                    "{}{}",
                    generate_name_prefix.as_deref().unwrap_or_default(),
                    generate_suffix()
                );
                obj.body["metadata"]["name"] = serde_json::Value::String(name.clone());
                // Re-validate the regenerated name — mirrors create_resource's retry, which
                // re-runs validating admission once per attempt, not just for the first
                // candidate name.
                let retry_ctx = AdmissionContext {
                    group: GROUP,
                    version: VERSION,
                    resource: PLURAL,
                    name: &name,
                    namespace: None,
                    operation: "CREATE",
                    user_info: Some(serde_json::json!({
                        "username": user.username.clone(),
                        "uid": user.uid.clone(),
                        "groups": user.groups.clone(),
                        "extra": user.extra.clone(),
                    })),
                    dry_run: is_dry_run_header(&headers),
                };
                run_validating_webhooks(&state, &obj.body, None, &retry_ctx).await?;
            }
            Err(e) => return Err(crate::handlers::generic::store_err(e, &name, KIND)),
        }
    };

    obj.set_resource_version(new_rv);
    Ok((StatusCode::CREATED, Json(obj.body)).into_response())
}

/// DELETE /apis/certificates.k8s.io/v1/certificatesigningrequests
///
/// The CSR collection route is registered as a literal path (not the generic
/// `{group}/{version}/{resource}` template) so create/list can run CSR-specific
/// validation. That means axum never falls back to the templated route's DELETE
/// handler — without this wrapper the route only has GET/POST registered and axum
/// returns 405 on DELETE, breaking `kubectl delete csr --all` and the sig-auth
/// "CSR API operations" conformance test's DeleteCollection call.
pub async fn delete_collection_csr<S: Store>(
    State(state): State<AppState<S>>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    crate::handlers::resource::delete_collection_resource(
        State(state),
        Path((GROUP.to_string(), VERSION.to_string(), PLURAL.to_string())),
        Query(query),
        Extension(user),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::handlers::test_support::make_state;

    /// Generate a minimal valid base64(PEM)-encoded PKCS#10 CSR using rcgen.
    ///
    /// rcgen is already a workspace dependency (used for TLS cert generation).
    /// Generating the CSR in the test avoids a hardcoded byte string that would
    /// be opaque and potentially stale — the test self-documents its own inputs.
    ///
    /// kubectl/client-go always submit spec.request as base64(PEM), never base64(DER)
    /// directly — this fixture mirrors the real wire format so the test can't pass
    /// against a handler that (incorrectly) expects raw DER.
    fn valid_csr_b64() -> String {
        use rcgen::{CertificateParams, KeyPair};
        let key_pair = KeyPair::generate().expect("key generation must succeed");
        let params = CertificateParams::default();
        let csr = params
            .serialize_request(&key_pair)
            .expect("CSR generation must succeed");
        let pem = csr.pem().expect("CSR PEM serialization must succeed");
        base64::engine::general_purpose::STANDARD.encode(pem)
    }

    /// Missing spec.request → 422.
    ///
    /// The signer controller must not accept a CSR without a request field —
    /// there is nothing to sign. This is the most basic security invariant.
    #[test]
    fn validate_missing_spec_request_returns_422() {
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "test-csr"},
            "spec": {
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });
        let err = validate_csr_spec(&body).expect_err("must reject missing spec.request");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "missing spec.request must return 422 — any other code silently bypasses CSR validation");
    }

    /// Empty spec.request → 422.
    ///
    /// An empty string is not a valid base64 CSR. The validator must reject it
    /// before attempting any decode.
    #[test]
    fn validate_empty_spec_request_returns_422() {
        let body = serde_json::json!({
            "spec": {
                "request": "",
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });
        let err = validate_csr_spec(&body).expect_err("must reject empty spec.request");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Invalid base64 in spec.request → 422.
    ///
    /// If spec.request is not valid base64 the decoder would panic or return garbage.
    /// Reject early to prevent downstream parsers from seeing malformed bytes.
    #[test]
    fn validate_invalid_base64_returns_422() {
        let body = serde_json::json!({
            "spec": {
                "request": "not-valid-base64!!!",
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });
        let err = validate_csr_spec(&body).expect_err("must reject invalid base64");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "invalid base64 in spec.request must return 422 — a signer that accepts this could be fed arbitrary bytes");
    }

    /// Valid base64 but not a PEM PKCS#10 → 422.
    ///
    /// base64("hello world") is valid base64 but not a PKCS#10 CSR. The PEM parser
    /// must catch this to prevent a signer from issuing a cert based on garbage data.
    #[test]
    fn validate_valid_base64_invalid_pem_returns_422() {
        // "hello world" is valid base64 (aGVsbG8gd29ybGQ=) but not PEM-armored PKCS#10.
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"hello world");
        let body = serde_json::json!({
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });
        let err = validate_csr_spec(&body).expect_err("must reject non-PEM bytes");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "valid base64 but invalid PKCS#10 PEM must return 422 — a signer must not process malformed CSRs");
    }

    /// A raw DER-encoded CSR (not PEM-armored) in spec.request → 422.
    ///
    /// Pins the handler to the PEM decode path: raw base64(DER) is not the
    /// upstream Kubernetes wire format (kubectl/client-go always send
    /// base64(PEM)) and must be rejected even though it is well-formed PKCS#10.
    #[test]
    fn validate_raw_der_without_pem_armor_returns_422() {
        use rcgen::{CertificateParams, KeyPair};
        let key_pair = KeyPair::generate().expect("key generation must succeed");
        let params = CertificateParams::default();
        let csr = params
            .serialize_request(&key_pair)
            .expect("CSR generation must succeed");
        let der_b64 = base64::engine::general_purpose::STANDARD.encode(csr.der());

        let body = serde_json::json!({
            "spec": {
                "request": der_b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });
        let err = validate_csr_spec(&body)
            .expect_err("raw DER without PEM armor must be rejected by the PEM decoder");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "spec.request must be base64(PEM) per the upstream Kubernetes CSR wire format — raw base64(DER) is not the same wire format and must not be silently accepted");
    }

    /// Missing spec.signerName → 422.
    ///
    /// Without a signerName, no signer controller knows it should sign the request.
    /// The request would silently sit unprocessed forever. Reject at create time.
    #[test]
    fn validate_missing_signer_name_returns_422() {
        let b64 = valid_csr_b64();
        let body = serde_json::json!({
            "spec": {
                "request": b64
            }
        });
        let err = validate_csr_spec(&body).expect_err("must reject missing spec.signerName");
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "missing spec.signerName must return 422 — a CSR without a signer is unroutable"
        );
    }

    /// Empty spec.signerName → 422.
    #[test]
    fn validate_empty_signer_name_returns_422() {
        let b64 = valid_csr_b64();
        let body = serde_json::json!({
            "spec": {
                "request": b64,
                "signerName": ""
            }
        });
        let err = validate_csr_spec(&body).expect_err("must reject empty spec.signerName");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Valid CSR with all required fields → Ok.
    ///
    /// The happy path: a real PKCS#10 PEM CSR encoded as base64 with a signerName.
    /// If this test fails, we've broken something in the validation logic.
    #[test]
    fn validate_valid_csr_returns_ok() {
        let b64 = valid_csr_b64();
        let body = serde_json::json!({
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });
        if let Err(err) = validate_csr_spec(&body) {
            panic!(
                "valid CSR with valid signerName must pass validation, got status={}",
                err.0
            );
        }
    }

    // -----------------------------------------------------------------------
    // list_csr regression test
    //
    // Before the fix, GET /apis/certificates.k8s.io/v1/certificatesigningrequests
    // was wired to list_resource which extracts Path<(String,String,String)>.
    // The route is a hardcoded literal with 0 capture groups — axum panicked with
    // "Wrong number of path arguments for Path. Expected 3 but got 0".
    //
    // This test verifies that the route returns 200 (not a 500/panic).
    // It will fail if the route is re-wired to a handler that extracts Path params
    // from a literal route.
    // -----------------------------------------------------------------------

    async fn seed_csr_for_get(state: &AppState, name: &str) {
        let b64 = valid_csr_b64();
        let csr = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": name, "resourceVersion": "1"},
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            },
            "status": {"conditions": []}
        });
        let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
        state
            .store
            .put(
                &key,
                bytes::Bytes::from(serde_json::to_vec(&csr).unwrap()),
                None,
            )
            .await
            .expect("seed CSR");
    }

    /// get_csr returns 200 when the CSR exists.
    /// kcm reads back CSRs after approval to check the certificate field.
    #[tokio::test]
    async fn get_csr_returns_200_for_existing() {
        let state = make_state();
        seed_csr_for_get(&state, "existing-csr").await;

        let result = get_csr(
            axum::extract::State(state),
            axum::extract::Path("existing-csr".to_string()),
        )
        .await;

        let resp = result.unwrap_or_else(|_| panic!("get_csr on existing CSR must succeed"));
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "get_csr must return 200 for an existing CSR"
        );
    }

    /// get_csr returns 404 when the CSR does not exist.
    /// kcm must distinguish a missing CSR from a server error.
    #[tokio::test]
    async fn get_csr_returns_404_for_missing() {
        let state = make_state();

        let result = get_csr(
            axum::extract::State(state),
            axum::extract::Path("no-such-csr".to_string()),
        )
        .await;

        let err = result.expect_err("get_csr on missing CSR must return error");
        assert_eq!(
            err.0,
            axum::http::StatusCode::NOT_FOUND,
            "get_csr on non-existent CSR must return 404"
        );
    }

    /// create_csr with a valid CSR body must return 201 and store the object.
    /// This is the primary happy path: a client submits a node cert request.
    #[tokio::test]
    async fn create_csr_valid_body_returns_201() {
        use axum::response::IntoResponse;

        let state = make_state();
        let b64 = valid_csr_b64();

        let csr_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "valid-csr"},
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client",
                "usages": ["client auth"]
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let result = create_csr(
            axum::extract::State(state.clone()),
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&csr_body).unwrap()),
        )
        .await
        .map(IntoResponse::into_response);

        let resp = result.unwrap_or_else(|_| panic!("create_csr with valid body must succeed"));
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::CREATED,
            "create_csr must return 201 on success"
        );

        let key = "/registry/certificates.k8s.io/certificatesigningrequests/valid-csr";
        assert!(
            state.store.get(key).await.unwrap().is_some(),
            "created CSR must be persisted in the store"
        );
    }

    /// DELETE on the CSR collection route must actually remove the stored CSRs.
    ///
    /// The CSR collection route is a literal path (not the generic
    /// `{group}/{version}/{resource}` template), so before this fix only GET/POST were
    /// registered on it and axum answered DELETE with 405 "the server does not allow
    /// this method on the requested resource". `kubectl delete csr --all` and the
    /// sig-auth "CSR API operations" conformance test's DeleteCollection step both
    /// depend on this route accepting DELETE.
    #[tokio::test]
    async fn delete_collection_csr_removes_stored_csrs() {
        let state = make_state();
        seed_csr_for_get(&state, "csr-one").await;
        seed_csr_for_get(&state, "csr-two").await;

        let result = delete_collection_csr(
            axum::extract::State(state.clone()),
            axum::extract::Query(CollectionQuery {
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
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec!["system:masters".into()],
                extra: Default::default(),
            }),
        )
        .await;

        assert!(
            result.is_ok(),
            "delete_collection_csr must succeed instead of 405 — without the DELETE \
             route registration this call never reaches the handler at all"
        );

        for name in ["csr-one", "csr-two"] {
            let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
            assert!(
                state.store.get(&key).await.unwrap().is_none(),
                "DeleteCollection must remove CSR '{name}' — a leftover CSR fails the \
                 conformance test's final 'filtered list should have 0 items' assertion"
            );
        }
    }

    /// create_csr with duplicate name must return 409 Conflict.
    /// OCC: the store returns AlreadyExists which maps to 409.
    #[tokio::test]
    async fn create_csr_duplicate_returns_409() {
        use axum::response::IntoResponse;

        let state = make_state();
        let b64 = valid_csr_b64();

        let csr_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "dup-csr"},
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        // First create — must succeed.
        create_csr(
            axum::extract::State(state.clone()),
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
            headers.clone(),
            bytes::Bytes::from(serde_json::to_vec(&csr_body).unwrap()),
        )
        .await
        .map(IntoResponse::into_response)
        .unwrap_or_else(|_| panic!("first create must succeed"));

        // Second create with same name — must return 409.
        let result = create_csr(
            axum::extract::State(state),
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&csr_body).unwrap()),
        )
        .await
        .map(IntoResponse::into_response);

        match result {
            Err(err) => assert_eq!(
                err.0,
                axum::http::StatusCode::CONFLICT,
                "duplicate CSR create must return 409 Conflict"
            ),
            Ok(resp) => panic!("duplicate create must return 409, got {}", resp.status()),
        }
    }

    /// create_csr strips the status field from the stored object.
    /// spec is immutable after create; status is written by the signer via /status.
    /// A client that sends status in the body must not have it persisted.
    #[tokio::test]
    async fn create_csr_strips_status_from_stored_body() {
        use axum::response::IntoResponse;

        let state = make_state();
        let b64 = valid_csr_b64();

        let csr_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "no-status-csr"},
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            },
            "status": {
                "certificate": "SHOULD_BE_STRIPPED",
                "conditions": [{"type": "Approved"}]
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        create_csr(
            axum::extract::State(state.clone()),
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&csr_body).unwrap()),
        )
        .await
        .map(IntoResponse::into_response)
        .unwrap_or_else(|_| panic!("create must succeed"));

        let key = "/registry/certificates.k8s.io/certificatesigningrequests/no-status-csr";
        let stored = state.store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert!(
            v.get("status").is_none() || v["status"].is_null(),
            "create_csr must strip the status field from stored body — \
             clients must not pre-set status; that is the signer's exclusive right. \
             Got: {:?}",
            v.get("status")
        );
    }

    /// stamp_csr_identity overwrites a client-supplied spec.username/uid/groups/extra
    /// with the authenticated caller's real identity.
    ///
    /// KCM's builtin csrapproving controller authorizes auto-approval via a
    /// SubjectAccessReview built directly from these spec fields. If a client could set
    /// them, it could submit a CSR claiming to be `system:node:victim` in group
    /// `system:nodes` while authenticated as an unrelated, unprivileged identity — KCM
    /// would approve and sign a client certificate for an identity the caller never
    /// proved it holds.
    #[test]
    fn stamp_csr_identity_overwrites_client_supplied_spoof() {
        let mut body = serde_json::json!({
            "spec": {
                "request": "irrelevant-for-this-test",
                "signerName": "kubernetes.io/kube-apiserver-client-kubelet",
                "username": "system:node:victim",
                "uid": "attacker-chosen-uid",
                "groups": ["system:masters"],
                "extra": {"attacker-key": ["attacker-value"]}
            }
        });

        let real_caller = crate::auth::UserInfo {
            username: "system:bootstrap:abcdef".into(),
            uid: "real-uid".into(),
            groups: vec!["system:bootstrappers".into()],
            extra: [("real-key".to_string(), vec!["real-value".to_string()])].into(),
        };
        stamp_csr_identity(&mut body, &real_caller);

        assert_eq!(
            body["spec"]["username"], "system:bootstrap:abcdef",
            "client-supplied spec.username must be discarded — a caller must never be \
             able to request approval for an identity it did not authenticate as"
        );
        assert_eq!(
            body["spec"]["uid"], "real-uid",
            "client-supplied spec.uid must be discarded, matching the real caller's uid"
        );
        assert_eq!(
            body["spec"]["groups"],
            serde_json::json!(["system:bootstrappers"]),
            "client-supplied spec.groups must be discarded — a caller must not be able \
             to forge membership in a privileged group like system:masters"
        );
        assert_eq!(
            body["spec"]["extra"],
            serde_json::json!({"real-key": ["real-value"]}),
            "client-supplied spec.extra must be discarded"
        );
    }

    /// create_csr end-to-end: a client-supplied spec.username/uid/groups/extra never
    /// reaches the stored object — the authenticated caller's identity always wins.
    ///
    /// This is the regression test for the CSR identity-spoofing security fix: without
    /// the stamp, an unprivileged caller could submit a CSR with spec.username set to
    /// a node identity and spec.groups set to system:nodes, and KCM's csrapproving
    /// controller (which authorizes purely from these stored spec fields) would approve
    /// and sign a client certificate for that forged identity.
    #[tokio::test]
    async fn create_csr_stamps_authenticated_identity_over_client_supplied_spoof() {
        use axum::response::IntoResponse;

        let state = make_state();
        let b64 = valid_csr_b64();

        let csr_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "spoofed-csr"},
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client-kubelet",
                "username": "system:node:victim",
                "uid": "attacker-chosen-uid",
                "groups": ["system:nodes", "system:masters"],
                "extra": {"attacker-key": ["attacker-value"]}
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        create_csr(
            axum::extract::State(state.clone()),
            axum::Extension(crate::auth::UserInfo {
                username: "system:bootstrap:abcdef".into(),
                uid: String::new(),
                groups: vec!["system:bootstrappers".into()],
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&csr_body).unwrap()),
        )
        .await
        .map(IntoResponse::into_response)
        .unwrap_or_else(|_| panic!("create must succeed"));

        let key = "/registry/certificates.k8s.io/certificatesigningrequests/spoofed-csr";
        let stored = state.store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["spec"]["username"], "system:bootstrap:abcdef",
            "stored spec.username must be the authenticated caller, not the client-supplied \
             value — a mismatch here means KCM's SAR-based auto-approval would authorize \
             the wrong identity"
        );
        assert_eq!(
            v["spec"]["groups"],
            serde_json::json!(["system:bootstrappers"]),
            "stored spec.groups must be the authenticated caller's real groups, not the \
             client-supplied system:nodes/system:masters spoof"
        );
    }

    /// list_csr with label selector must filter results.
    /// This covers the label_selector branch in list_csr (non-watch path).
    #[tokio::test]
    async fn list_csr_with_label_selector_filters_results() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let b64 = valid_csr_b64();

        // Seed two CSRs with different labels.
        for (name, env) in [("csr-foo", "foo"), ("csr-bar", "bar")] {
            let csr = serde_json::json!({
                "apiVersion": "certificates.k8s.io/v1",
                "kind": "CertificateSigningRequest",
                "metadata": {
                    "name": name,
                    "labels": {"env": env}
                },
                "spec": {
                    "request": b64,
                    "signerName": "kubernetes.io/kube-apiserver-client"
                }
            });
            let key = format!("/registry/certificates.k8s.io/certificatesigningrequests/{name}");
            store
                .put(
                    &key,
                    bytes::Bytes::from(serde_json::to_vec(&csr).unwrap()),
                    Some(0),
                )
                .await
                .unwrap();
        }

        let user = crate::auth::UserInfo {
            username: "test".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };

        let result = list_csr(
            axum::extract::State(state),
            axum::extract::Query(CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: Some("env=foo".into()),
                field_selector: None,
                limit: None,
                continue_token: None,
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            }),
            axum::Extension(user),
        )
        .await;

        let resp = result.unwrap_or_else(|_| panic!("list_csr with label selector must succeed"));
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = v["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            1,
            "label selector env=foo must filter to 1 matching CSR"
        );
        assert_eq!(items[0]["metadata"]["name"], "csr-foo");
    }

    /// GET /apis/certificates.k8s.io/v1/certificatesigningrequests returns 200.
    ///
    /// The kcm controller calls this on startup. Before the fix it panicked
    /// because the hardcoded literal route had no path captures but the handler
    /// expected three. An empty list is a valid response.
    #[tokio::test]
    async fn list_csr_returns_200_not_panic() {
        use std::sync::Arc;

        use axum::{
            body::Body,
            http::{Request, StatusCode},
            routing::get,
            Extension, Router,
        };
        use tower::ServiceExt as _;
        use u7s_store::SqliteStore;

        use crate::{auth::UserInfo, state::AppState};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let app = Router::new()
            .route(
                "/apis/certificates.k8s.io/v1/certificatesigningrequests",
                get(list_csr),
            )
            .layer(Extension(UserInfo {
                username: "test".into(),
                uid: "".into(),
                groups: vec![],
                extra: Default::default(),
            }))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/apis/certificates.k8s.io/v1/certificatesigningrequests")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET CSR list must return 200 — a 500 indicates the route panicked due to \
             wrong path param count (regression: literal route wired to handler expecting \
             Path captures)"
        );
    }

    /// A validating webhook that denies CSR creates must cause create_csr to return 403.
    ///
    /// Without admission wiring in create_csr, the webhook is never called and
    /// policy-denied requests are silently admitted — a security regression.
    #[tokio::test]
    async fn create_csr_validating_webhook_denial_returns_403() {
        use std::sync::Arc;

        use axum::{routing::post, Router};
        use tokio::net::TcpListener;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, deny_router)
                .await
                .expect("mock webhook server must not fail");
        });
        let url = format!("http://{addr}");

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "deny-csr"},
            "webhooks": [{
                "name": "deny-csr.test.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{
                    "apiGroups": ["certificates.k8s.io"],
                    "apiVersions": ["v1"],
                    "resources": ["certificatesigningrequests"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/deny-csr",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .expect("seed ValidatingWebhookConfiguration");

        let b64 = valid_csr_b64();
        let csr_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "denied-csr"},
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let result = create_csr(
            axum::extract::State(state),
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&csr_body).unwrap()),
        )
        .await;

        let err = result
            .map(|r| {
                use axum::response::IntoResponse;
                r.into_response()
            })
            .expect_err("validating webhook denial must cause create_csr to return an error");
        assert_eq!(
            err.0,
            axum::http::StatusCode::FORBIDDEN,
            "a denying validating webhook must produce 403 — \
             without admission wiring the webhook is never called and policy is bypassed"
        );
    }

    /// A mutating webhook that patches spec.username/groups must NOT have its patch
    /// survive into the stored object — stamp_csr_identity must run AFTER the admission
    /// webhook chain, re-overwriting whatever a webhook injected.
    ///
    /// KCM's csrapproving controller authorizes auto-approval from the STORED
    /// spec.username/groups. If stamp_csr_identity ran before mutating webhooks (or was
    /// otherwise reverted to that ordering), a compromised or misconfigured mutating
    /// webhook could reintroduce a spoofed identity after the honest stamp, defeating the
    /// fix at the very last step before persistence. This test fails if that ordering
    /// regresses: the JSONPatch below injects an attacker identity, and the assertions
    /// require the caller's REAL identity to win regardless.
    #[tokio::test]
    async fn create_csr_mutating_webhook_cannot_reintroduce_spoofed_identity() {
        use std::sync::Arc;

        use axum::{routing::post, Router};
        use base64::Engine as _;
        use tokio::net::TcpListener;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let patch_router = Router::new().route(
            "/webhook",
            post(|| async {
                let patch = serde_json::json!([
                    {"op": "add", "path": "/spec/username", "value": "system:node:mutated-by-webhook"},
                    {"op": "add", "path": "/spec/groups", "value": ["system:masters"]}
                ]);
                let patch_b64 = base64::engine::general_purpose::STANDARD
                    .encode(serde_json::to_string(&patch).unwrap());
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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, patch_router)
                .await
                .expect("mock webhook server must not fail");
        });
        let url = format!("http://{addr}");

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "mutate-csr-identity"},
            "webhooks": [{
                "name": "mutate-csr-identity.test.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{
                    "apiGroups": ["certificates.k8s.io"],
                    "apiVersions": ["v1"],
                    "resources": ["certificatesigningrequests"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/mutate-csr-identity",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .expect("seed MutatingWebhookConfiguration");

        let b64 = valid_csr_b64();
        let csr_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "webhook-cannot-spoof-csr"},
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client-kubelet"
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        create_csr(
            axum::extract::State(state.clone()),
            axum::Extension(crate::auth::UserInfo {
                username: "real-caller".into(),
                uid: String::new(),
                groups: vec!["real-group".into()],
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&csr_body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("create must succeed, got status={}", e.0));

        let key =
            "/registry/certificates.k8s.io/certificatesigningrequests/webhook-cannot-spoof-csr";
        let stored = state.store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["spec"]["username"], "real-caller",
            "a mutating webhook's patch to spec.username must not survive into the stored \
             object — stamp_csr_identity must run after the admission webhook chain, or a \
             webhook could reintroduce a spoofed identity that KCM's SAR-based auto-approval \
             would then trust"
        );
        assert_eq!(
            v["spec"]["groups"],
            serde_json::json!(["real-group"]),
            "a mutating webhook's patch to spec.groups (here: forging system:masters) must \
             not survive into the stored object"
        );
    }

    /// A store wrapper whose first `put()` call always fails with AlreadyExists,
    /// regardless of key — simulating a generateName suffix landing on some unrelated
    /// existing object. Delegates every other call to the inner SqliteStore.
    ///
    /// Mirrors create_cr's identical test double in cr.rs (see its doc comment) — used
    /// here by create_csr's generateName-collision-retry regression test.
    struct FirstPutAlreadyExistsStore {
        inner: std::sync::Arc<u7s_store::SqliteStore>,
        fire_once: std::sync::atomic::AtomicBool,
    }

    impl FirstPutAlreadyExistsStore {
        fn new(inner: std::sync::Arc<u7s_store::SqliteStore>) -> Self {
            Self {
                inner,
                fire_once: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    impl u7s_store::Store for FirstPutAlreadyExistsStore {
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
                .fire_once
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            async move {
                if inject {
                    Err(u7s_store::StoreError::AlreadyExists { key })
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

    /// A controller mass-creating CSRs via bare `metadata.generateName` must not see a
    /// spurious 409 just because the server's random name suffix happened to collide with
    /// an unrelated object. This forces that collision on the very first `put()` and
    /// asserts create_csr retries with a fresh suffix and succeeds, rather than surfacing
    /// the collision as AlreadyExists to the client.
    ///
    /// Fails on revert: without the retry, create_csr's single `store.put` call returns
    /// AlreadyExists and the handler maps it straight to 409 — reverting the fix and
    /// re-running this test reproduces exactly that 409.
    #[tokio::test]
    async fn create_csr_retries_generate_name_collision_instead_of_409ing() {
        use axum::response::IntoResponse;
        use u7s_store::SqliteStore;

        let inner = std::sync::Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let collision_store = std::sync::Arc::new(FirstPutAlreadyExistsStore::new(inner));
        let state = AppState::new(
            collision_store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let b64 = valid_csr_b64();
        let csr_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"generateName": "repro-csr-"},
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let result = create_csr(
            axum::extract::State(state),
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&csr_body).unwrap()),
        )
        .await
        .map(IntoResponse::into_response);

        let resp = match result {
            Ok(r) => r,
            Err(e) => panic!(
                "a generateName-based CSR create must retry past a spurious store \
                 collision, not hard-error: status={}",
                e.0
            ),
        };
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::CREATED,
            "a generateName-based CSR create must retry past a spurious store collision, \
             not hard-error with 409 — a controller mass-creating CSRs via generateName \
             would otherwise see spurious create failures"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(
            created["metadata"]["name"]
                .as_str()
                .is_some_and(|n| n.starts_with("repro-csr-")),
            "created CSR must still carry the generateName prefix after the retry"
        );
    }
}
