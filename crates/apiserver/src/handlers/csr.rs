//! Dedicated CSR POST handler with strict validation.
//!
//! The CSR POST path is security-critical: spec.request contains a DER PKCS#10
//! CertificationRequest. We validate it here before storing — a signer that blindly
//! issues a cert from unchecked bytes could be tricked into signing arbitrary requests.
//!
//! Validation rules:
//!   1. spec.request must be present and non-empty (base64 string).
//!   2. spec.request must decode as valid standard base64.
//!   3. Decoded bytes must parse as a valid DER-encoded PKCS#10 CertificationRequest.
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
use x509_cert::der::Decode as _;
use x509_cert::request::CertReq;

use u7s_store::{ListOptions, Store};

use crate::{
    auth::UserInfo,
    handlers::{
        generic::{
            apply_label_selector, build_list_response, decode_continue, lookup,
            parse_field_selector, parse_label_selector, resolve_name, stamp_metadata,
            validate_name, CollectionQuery,
        },
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

    // spec.request: required, must be non-empty base64, decoded bytes must be valid DER PKCS#10.
    if spec.request.is_empty() {
        return Err(Status::unprocessable_entity(
            "spec.request is required and must be a non-empty base64-encoded string".into(),
        ));
    }

    let der_bytes = base64::engine::general_purpose::STANDARD
        .decode(&spec.request)
        .map_err(|e| {
            Status::unprocessable_entity(format!("spec.request is not valid base64: {e}"))
        })?;

    CertReq::from_der(&der_bytes).map_err(|e| {
        Status::unprocessable_entity(format!(
            "spec.request does not contain a valid DER-encoded PKCS#10 CertificationRequest: {e}"
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
        let initial =
            fetch_initial_events(&state, &prefix, query.send_initial_events == Some(true)).await?;
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

    let body = build_list_response(
        &kind,
        GROUP,
        VERSION,
        resp.revision,
        items,
        resp.continue_key,
        resp.remaining_count,
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
/// Validates spec.request (base64 + DER PKCS#10) and spec.signerName before
/// storing. Returns 422 on validation failure, 201 on success.
pub async fn create_csr<S: Store>(
    State(state): State<AppState<S>>,
    Extension(_user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let body = extract_body(&body, content_type(&headers));
    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    validate_csr_spec(&obj.body)?;

    let name = resolve_name(&mut obj)?;
    stamp_metadata(&mut obj);

    // Strip status from incoming body — spec is immutable after create.
    if let Some(map) = obj.body.as_object_mut() {
        map.remove("status");
    }

    let key = group_object_key(GROUP, PLURAL, None, &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), Some(0))
        .await
        .map_err(|e| crate::handlers::generic::store_err(e, &name, KIND))?;

    obj.set_resource_version(new_rv);
    Ok((StatusCode::CREATED, Json(obj.body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a minimal valid DER-encoded PKCS#10 CSR as base64 using rcgen.
    ///
    /// rcgen is already a workspace dependency (used for TLS cert generation).
    /// Generating the CSR in the test avoids a hardcoded byte string that would
    /// be opaque and potentially stale — the test self-documents its own inputs.
    fn valid_csr_b64() -> String {
        use rcgen::{CertificateParams, KeyPair};
        let key_pair = KeyPair::generate().expect("key generation must succeed");
        let params = CertificateParams::default();
        let csr = params
            .serialize_request(&key_pair)
            .expect("CSR generation must succeed");
        base64::engine::general_purpose::STANDARD.encode(csr.der())
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

    /// Valid base64 but not a DER PKCS#10 → 422.
    ///
    /// base64("hello world") is valid base64 but not a PKCS#10 CSR. The DER parser
    /// must catch this to prevent a signer from issuing a cert based on garbage data.
    #[test]
    fn validate_valid_base64_invalid_der_returns_422() {
        // "hello world" is valid base64 (aGVsbG8gd29ybGQ=) but not a PKCS#10 DER.
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"hello world");
        let body = serde_json::json!({
            "spec": {
                "request": b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });
        let err = validate_csr_spec(&body).expect_err("must reject non-DER bytes");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "valid base64 but invalid PKCS#10 DER must return 422 — a signer must not process malformed CSRs");
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
    /// The happy path: a real PKCS#10 DER CSR encoded as base64 with a signerName.
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

    fn make_state() -> AppState {
        use std::sync::Arc;
        use u7s_store::SqliteStore;
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

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
}
