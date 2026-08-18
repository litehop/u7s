//! Dedicated create-validation for certificates.k8s.io/v1beta1 ClusterTrustBundle and
//! PodCertificateRequest.
//!
//! Both types are pure CRUD surfaces here (no signer/controller logic — a real signer
//! implementation is a separate, later piece of work). Validation on create matters
//! anyway: `ClusterTrustBundle.spec.trustBundle` is mounted verbatim into every pod that
//! references it via a `clusterTrustBundle` projected volume, and
//! `PodCertificateRequest.spec` fields identify the exact pod/node/service-account a
//! signer must bind an issued certificate to — garbage in either would only surface much
//! later, at a kubelet or signer far from the client that created the object.
//!
//! List/get/replace/patch/delete/status all reuse the fully generic resource handlers
//! (`handlers::resource`, `handlers::status`) via the `resource_registry` entries in
//! `state.rs` — only POST (and the collection GET/DELETE/PATCH routes it displaces by
//! being registered as a literal path) needs a dedicated handler here.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Extension,
};
use bytes::Bytes;
use x509_cert::der::{asn1::Any, Decode as _, Tag, Tagged as _};

use u7s_store::Store;

use crate::{
    auth::UserInfo,
    state::AppState,
    status::Status,
    types::{ClusterTrustBundleSpec, Object, PodCertificateRequestSpec},
    util::{content_type, extract_body},
};

use super::generic::CollectionQuery;
use super::json_patch::{CreateQuery, PatchQuery};

const GROUP: &str = "certificates.k8s.io";
const VERSION: &str = "v1beta1";
const CTB_PLURAL: &str = "clustertrustbundles";
const PCR_PLURAL: &str = "podcertificaterequests";

/// Upstream kube-apiserver's `certificates.MaxTrustBundleSize`
/// (pkg/apis/certificates/types.go): 1 MiB. Enforced here so a client can't force every
/// kubelet that mounts this bundle to fetch and hold an unbounded blob.
const MAX_TRUST_BUNDLE_SIZE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// ClusterTrustBundle
// ---------------------------------------------------------------------------

/// Validate `spec.trustBundle`, returning 422 on any violation.
///
/// Extracted as a pure function so it can be unit-tested without an HTTP stack —
/// mirrors `csr::validate_csr_spec`.
pub(crate) fn validate_cluster_trust_bundle_spec(
    body: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let spec: ClusterTrustBundleSpec = serde_json::from_value(body["spec"].clone())
        .map_err(|e| {
            Status::unprocessable_entity(format!(
                "spec.trustBundle is required and must be a PEM bundle of X.509 CA certificates: {e}"
            ))
        })?;

    if spec.trust_bundle.len() > MAX_TRUST_BUNDLE_SIZE {
        return Err(Status::unprocessable_entity(format!(
            "spec.trustBundle must not exceed {MAX_TRUST_BUNDLE_SIZE} bytes"
        )));
    }

    let anchor_count =
        parse_trust_bundle_pem(&spec.trust_bundle).map_err(Status::unprocessable_entity)?;
    if anchor_count == 0 {
        return Err(Status::unprocessable_entity(
            "spec.trustBundle must contain at least one PEM-encoded CERTIFICATE block".into(),
        ));
    }

    Ok(())
}

/// Split `pem_text` into consecutive `-----BEGIN ...-----`/`-----END ...-----` documents
/// and validate each one as a well-formed X.509 certificate. Returns the number of
/// documents found.
///
/// Every kubelet that mounts this bundle trusts every certificate in it to validate peer
/// connections — a block that isn't actually `CERTIFICATE`-typed, or isn't even
/// syntactically valid DER, must be rejected here rather than silently mis-trusted (or
/// silently dropped) downstream.
///
/// Deliberately does NOT fully decode each block as an `x509_cert::Certificate` (i.e. does
/// not recurse into the X.509 `TBSCertificate` structure, including its `Validity` field).
/// Real, legitimately-issued certificates can encode a degenerate `notBefore`/`notAfter`
/// (e.g. Go's zero-value `time.Time`, year 1) as a `GeneralizedTime` that the `der` crate's
/// strict X.509 `Time` decoder rejects even though the certificate is otherwise
/// well-formed DER — confirmed against upstream's own
/// `test/e2e/auth/projected_clustertrustbundle.go` fixtures, which construct exactly such a
/// certificate. Decoding each block as a bare `Any` and checking its outer tag is `SEQUENCE`
/// (the universal top-level ASN.1 type for `Certificate ::= SEQUENCE { ... }`) confirms the
/// payload is syntactically well-formed DER without tripping over that inner field.
fn parse_trust_bundle_pem(pem_text: &str) -> Result<usize, String> {
    const BEGIN: &str = "-----BEGIN ";
    let mut remaining = pem_text.trim();
    let mut count = 0;
    while !remaining.is_empty() {
        if !remaining.starts_with(BEGIN) {
            return Err("spec.trustBundle contains data outside of a PEM block".to_string());
        }
        let after_begin = &remaining[BEGIN.len()..];
        let label_end = after_begin
            .find("-----")
            .ok_or_else(|| "spec.trustBundle has a malformed PEM header".to_string())?;
        let label = &after_begin[..label_end];
        if label != "CERTIFICATE" {
            return Err(format!(
                "spec.trustBundle entry {count} has PEM block type {label:?}: only CERTIFICATE blocks are allowed"
            ));
        }
        let end_marker = format!("-----END {label}-----");
        let end_idx = remaining.find(end_marker.as_str()).ok_or_else(|| {
            format!("spec.trustBundle entry {count} is missing its {end_marker} terminator")
        })?;
        let doc_end = end_idx + end_marker.len();
        let doc = &remaining[..doc_end];

        let (_, der_bytes) = x509_cert::der::pem::decode_vec(doc.as_bytes())
            .map_err(|e| format!("spec.trustBundle entry {count} is not valid base64 PEM: {e}"))?;
        let any = Any::from_der(&der_bytes)
            .map_err(|e| format!("spec.trustBundle entry {count} is not well-formed DER: {e}"))?;
        if any.tag() != Tag::Sequence {
            return Err(format!(
                "spec.trustBundle entry {count} is not a DER SEQUENCE (X.509 certificates are DER-encoded SEQUENCEs)"
            ));
        }

        count += 1;
        remaining = remaining[doc_end..].trim_start();
    }
    Ok(count)
}

/// POST /apis/certificates.k8s.io/v1beta1/clustertrustbundles
///
/// Validates `spec.trustBundle` before delegating to the generic cluster-scoped create
/// handler for everything else (defaulting, admission, persistence).
pub(crate) async fn create_cluster_trust_bundle<S: Store>(
    State(state): State<AppState<S>>,
    Query(create_query): Query<CreateQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, crate::status::StatusError> {
    let decoded = extract_body(&body, content_type(&headers));
    let obj = Object::from_bytes(&decoded)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;
    validate_cluster_trust_bundle_spec(&obj.body)?;

    super::resource::create_resource(
        State(state),
        Path((
            GROUP.to_string(),
            VERSION.to_string(),
            CTB_PLURAL.to_string(),
        )),
        Query(create_query),
        Extension(user),
        headers,
        body,
    )
    .await
    .map(IntoResponse::into_response)
}

/// GET /apis/certificates.k8s.io/v1beta1/clustertrustbundles
///
/// The collection route is a hardcoded literal (needed so POST can run the validation
/// above), so GET/DELETE on the same literal path must also be registered here — axum
/// answers unregistered methods on a literal route with 405, it never falls through to
/// the generic `{group}/{version}/{resource}` template for the same concrete path.
pub(crate) async fn list_cluster_trust_bundles<S: Store>(
    State(state): State<AppState<S>>,
    Query(query): Query<CollectionQuery>,
    headers: HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    super::resource::list_resource(
        State(state),
        Path((
            GROUP.to_string(),
            VERSION.to_string(),
            CTB_PLURAL.to_string(),
        )),
        Query(query),
        headers,
        Extension(user),
    )
    .await
}

/// DELETE /apis/certificates.k8s.io/v1beta1/clustertrustbundles (DeleteCollection)
pub(crate) async fn delete_collection_cluster_trust_bundles<S: Store>(
    State(state): State<AppState<S>>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    super::resource::delete_collection_resource(
        State(state),
        Path((
            GROUP.to_string(),
            VERSION.to_string(),
            CTB_PLURAL.to_string(),
        )),
        Query(query),
        Extension(user),
    )
    .await
}

// ---------------------------------------------------------------------------
// PodCertificateRequest
// ---------------------------------------------------------------------------

/// Validate the `+required` spec fields, returning 422 if any is missing or empty.
pub(crate) fn validate_pod_certificate_request_spec(
    body: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let spec: PodCertificateRequestSpec =
        serde_json::from_value(body["spec"].clone()).map_err(|e| {
            Status::unprocessable_entity(format!(
                "spec.signerName, spec.podName, spec.podUID, spec.serviceAccountName, \
                 spec.serviceAccountUID, spec.nodeName, and spec.nodeUID are all required: {e}"
            ))
        })?;

    // Deserialization above only catches a field being entirely absent; a field present
    // but set to "" still deserializes fine and must be caught here.
    let empty: Vec<&str> = [
        ("signerName", spec.signer_name.as_str()),
        ("podName", spec.pod_name.as_str()),
        ("podUID", spec.pod_uid.as_str()),
        ("serviceAccountName", spec.service_account_name.as_str()),
        ("serviceAccountUID", spec.service_account_uid.as_str()),
        ("nodeName", spec.node_name.as_str()),
        ("nodeUID", spec.node_uid.as_str()),
    ]
    .into_iter()
    .filter(|(_, v)| v.is_empty())
    .map(|(field, _)| field)
    .collect();

    if !empty.is_empty() {
        return Err(Status::unprocessable_entity(format!(
            "spec.{} must not be empty",
            empty.join(", spec.")
        )));
    }

    validate_max_expiration_seconds(&spec)?;

    Ok(())
}

/// Validate `spec.maxExpirationSeconds`, mirroring upstream's
/// `ValidatePodCertificateRequestCreate` (pkg/apis/certificates/validation/validation.go):
/// the field is `+required`, and bounded to `[MinMaxExpirationSeconds,
/// MaxMaxExpirationSeconds]` (1h–91d) for ordinary signers, or the tighter
/// `KubernetesMaxMaxExpirationSeconds` (24h) ceiling for `kubernetes.io` signers.
///
/// Without this check a client (including a buggy or malicious signer-adjacent
/// controller) could request a PodCertificateRequest with an absurdly long-lived
/// certificate — kubelet mounts whatever a signer eventually issues into the pod's
/// filesystem verbatim, so an unbounded lifetime here becomes an unbounded-lifetime
/// credential on disk.
fn validate_max_expiration_seconds(
    spec: &PodCertificateRequestSpec,
) -> Result<(), crate::status::StatusError> {
    use super::defaults::{
        is_kubernetes_signer_name, KUBERNETES_MAX_MAX_EXPIRATION_SECONDS,
        MAX_MAX_EXPIRATION_SECONDS, MIN_MAX_EXPIRATION_SECONDS,
    };

    let Some(seconds) = spec.max_expiration_seconds else {
        return Err(Status::unprocessable_entity(
            "spec.maxExpirationSeconds must be set".to_string(),
        ));
    };

    if seconds < MIN_MAX_EXPIRATION_SECONDS {
        return Err(Status::unprocessable_entity(format!(
            "spec.maxExpirationSeconds: Invalid value: {seconds}: must be in the range \
             [{MIN_MAX_EXPIRATION_SECONDS}, {MAX_MAX_EXPIRATION_SECONDS}]"
        )));
    }
    let max = if is_kubernetes_signer_name(&spec.signer_name) {
        KUBERNETES_MAX_MAX_EXPIRATION_SECONDS
    } else {
        MAX_MAX_EXPIRATION_SECONDS
    };
    if seconds > max {
        return Err(Status::unprocessable_entity(format!(
            "spec.maxExpirationSeconds: Invalid value: {seconds}: must be in the range \
             [{MIN_MAX_EXPIRATION_SECONDS}, {max}]"
        )));
    }

    Ok(())
}

/// POST /apis/certificates.k8s.io/v1beta1/namespaces/{ns}/podcertificaterequests
///
/// Validates the required spec fields and strips any client-supplied `status` before
/// delegating to the generic namespaced create handler — spec is immutable after create,
/// and status is the signer's exclusive right, written only via `/status`. Mirrors
/// `csr::create_csr`'s status-stripping for the same reason.
pub(crate) async fn create_pod_certificate_request<S: Store>(
    State(state): State<AppState<S>>,
    Path(ns): Path<String>,
    Query(create_query): Query<CreateQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, crate::status::StatusError> {
    let decoded = extract_body(&body, content_type(&headers));
    let mut obj = Object::from_bytes(&decoded)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;
    validate_pod_certificate_request_spec(&obj.body)?;

    if let Some(map) = obj.body.as_object_mut() {
        map.remove("status");
    }

    // The body handed to the delegate below is the already-decoded-and-stripped JSON
    // (not the original bytes, which may have been protobuf-encoded), so the Content-Type
    // forwarded with it must say so — otherwise the generic handler would try to
    // protobuf-decode plain JSON.
    let mut forward_headers = headers;
    forward_headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );

    super::resource::create_namespaced_resource(
        State(state),
        Path((
            GROUP.to_string(),
            VERSION.to_string(),
            ns,
            PCR_PLURAL.to_string(),
        )),
        Query(create_query),
        Extension(user),
        forward_headers,
        obj.to_bytes(),
    )
    .await
    .map(IntoResponse::into_response)
}

/// GET /apis/certificates.k8s.io/v1beta1/namespaces/{ns}/podcertificaterequests
///
/// Same reasoning as `list_cluster_trust_bundles`: the collection route is a literal
/// path (for POST's validation), so GET/DELETE/PATCH must be registered alongside it.
pub(crate) async fn list_pod_certificate_requests<S: Store>(
    State(state): State<AppState<S>>,
    Path(ns): Path<String>,
    Query(query): Query<CollectionQuery>,
    headers: HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    super::resource::list_namespaced_resource(
        State(state),
        Path((
            GROUP.to_string(),
            VERSION.to_string(),
            ns,
            PCR_PLURAL.to_string(),
        )),
        Query(query),
        headers,
        Extension(user),
    )
    .await
}

/// DELETE /apis/certificates.k8s.io/v1beta1/namespaces/{ns}/podcertificaterequests
/// (DeleteCollection)
pub(crate) async fn delete_collection_pod_certificate_requests<S: Store>(
    State(state): State<AppState<S>>,
    Path(ns): Path<String>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    super::resource::delete_collection_namespaced_resource(
        State(state),
        Path((
            GROUP.to_string(),
            VERSION.to_string(),
            ns,
            PCR_PLURAL.to_string(),
        )),
        Query(query),
        Extension(user),
    )
    .await
}

/// PATCH /apis/certificates.k8s.io/v1beta1/namespaces/{ns}/podcertificaterequests
/// (collection patch — matches the generic namespaced collection route's method set)
pub(crate) async fn patch_collection_pod_certificate_requests<S: Store>(
    State(state): State<AppState<S>>,
    Path(ns): Path<String>,
    Query(query): Query<CollectionQuery>,
    Query(patch_query): Query<PatchQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    super::resource::patch_collection_namespaced_resource(
        State(state),
        Path((
            GROUP.to_string(),
            VERSION.to_string(),
            ns,
            PCR_PLURAL.to_string(),
        )),
        Query(query),
        Query(patch_query),
        Extension(user),
        headers,
        body,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::http::{header::CONTENT_TYPE, HeaderValue, StatusCode};
    use u7s_store::SqliteStore;

    fn make_state() -> AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    fn test_user() -> UserInfo {
        UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        }
    }

    fn json_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    /// A real, well-formed X.509 certificate PEM (not a CA, but `parse_trust_bundle_pem`
    /// only checks well-formedness — see its doc for why the CA-bit check is out of scope).
    fn valid_cert_pem() -> String {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(vec!["example.com".to_string()])
                .expect("self-signed cert generation must succeed");
        cert.pem()
    }

    /// DER for a bare SEQUENCE containing one GeneralizedTime value, `"00010101000000Z"` --
    /// the wire encoding Go's `crypto/x509` marshaler produces for the zero value of
    /// `time.Time` (year 1). Upstream's own `test/e2e/auth/projected_clustertrustbundle.go`
    /// fixture certificates set no explicit `NotBefore`/`NotAfter` and hit exactly this
    /// encoding (confirmed against a real sonobuoy run: `spec.trustBundle entry 0 does not
    /// parse as a valid X.509 certificate: malformed ASN.1 DER value for GeneralizedTime at
    /// DER byte 59`, before this fix).
    fn degenerate_generalizedtime_der() -> Vec<u8> {
        let mut inner = vec![0x18, 0x0F]; // GeneralizedTime, length 15
        inner.extend_from_slice(b"00010101000000Z");
        let mut outer = vec![0x30, inner.len() as u8]; // SEQUENCE
        outer.extend_from_slice(&inner);
        outer
    }

    fn pem_armor_certificate(der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")
    }

    /// Regression test: a well-formed DER SEQUENCE carrying a degenerate GeneralizedTime
    /// must still be accepted by `validate_cluster_trust_bundle_spec`, even though a full
    /// X.509 semantic decode of the same bytes fails. Reverting `parse_trust_bundle_pem` to
    /// call `x509_cert::Certificate::from_pem` (as an earlier version of this handler did)
    /// would 422 every ClusterTrustBundle create using a Go zero-value timestamp -- which is
    /// exactly what broke every `BeforeEach` in upstream's
    /// `projected_clustertrustbundle.go` conformance suite before this fix.
    #[test]
    fn validate_cluster_trust_bundle_accepts_degenerate_generalizedtime_because_real_e2e_fixtures_use_it(
    ) {
        let der = degenerate_generalizedtime_der();

        // Sanity-check the fixture: it must NOT be a syntactically complete X.509
        // Certificate, so a full semantic decode is expected to fail here. This is the
        // exact failure mode the fix works around -- if it stopped failing, the fixture
        // would no longer exercise the bug.
        assert!(
            x509_cert::Certificate::from_der(&der).is_err(),
            "sanity check: fixture must not decode as a complete X.509 Certificate"
        );

        let body = serde_json::json!({"spec": {"trustBundle": pem_armor_certificate(&der)}});
        if let Err(err) = validate_cluster_trust_bundle_spec(&body) {
            panic!(
                "a well-formed DER SEQUENCE with a degenerate GeneralizedTime must still be \
                 accepted -- upstream's ClusterTrustBundle e2e fixtures hit exactly this \
                 shape, and rejecting them breaks every BeforeEach at create time, got \
                 status={}",
                err.0
            );
        }
    }

    fn valid_pcr_spec() -> serde_json::Value {
        serde_json::json!({
            "signerName": "example.com/signer",
            "podName": "my-pod",
            "podUID": "pod-uid-1",
            "serviceAccountName": "default",
            "serviceAccountUID": "sa-uid-1",
            "nodeName": "node-1",
            "nodeUID": "node-uid-1",
            "maxExpirationSeconds": 3600
        })
    }

    // -----------------------------------------------------------------------
    // ClusterTrustBundle
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn clustertrustbundle_create_persists_trustbundle_pem_because_kubelet_will_mount_it_into_pods(
    ) {
        let state = make_state();
        let pem = valid_cert_pem();
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1beta1",
            "kind": "ClusterTrustBundle",
            "metadata": {"name": "example-bundle"},
            "spec": {"trustBundle": pem}
        });

        let result = create_cluster_trust_bundle(
            State(state.clone()),
            Query(CreateQuery::default()),
            Extension(test_user()),
            json_headers(),
            Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;

        let resp = result.unwrap_or_else(|e| panic!("create must succeed, got status {}", e.0));
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "create_cluster_trust_bundle must return 201 on a valid bundle"
        );

        let key = "/registry/certificates.k8s.io/clustertrustbundles/example-bundle";
        let stored = state
            .store
            .get(key)
            .await
            .unwrap()
            .expect("bundle must be persisted");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["trustBundle"], pem,
            "kubelet mounts spec.trustBundle verbatim via the clusterTrustBundle projected \
             volume -- if create mangled or dropped it, every pod referencing this bundle \
             would fail TLS validation against its intended CA"
        );
    }

    #[tokio::test]
    async fn clustertrustbundle_list_returns_all_bundles_because_multiple_signers_may_coexist() {
        let state = make_state();
        let pem = valid_cert_pem();
        for (name, signer) in [("bundle-a", "example.com/a"), ("bundle-b", "example.com/b")] {
            let body = serde_json::json!({
                "apiVersion": "certificates.k8s.io/v1beta1",
                "kind": "ClusterTrustBundle",
                "metadata": {"name": name},
                "spec": {"signerName": signer, "trustBundle": pem}
            });
            create_cluster_trust_bundle(
                State(state.clone()),
                Query(CreateQuery::default()),
                Extension(test_user()),
                json_headers(),
                Bytes::from(serde_json::to_vec(&body).unwrap()),
            )
            .await
            .unwrap_or_else(|e| panic!("seed create must succeed, got status {}", e.0));
        }

        let resp = list_cluster_trust_bundles(
            State(state),
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
            HeaderMap::new(),
            Extension(test_user()),
        )
        .await
        .unwrap_or_else(|e| panic!("list must succeed, got status {}", e.0));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = v["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            2,
            "two ClusterTrustBundles for two different signers must both be listed -- a \
             cluster commonly has more than one signer, each with its own trust anchors"
        );
    }

    #[test]
    fn validate_cluster_trust_bundle_missing_trust_bundle_returns_422() {
        let body = serde_json::json!({"spec": {"signerName": "example.com/a"}});
        let err = validate_cluster_trust_bundle_spec(&body)
            .expect_err("must reject a ClusterTrustBundle with no trustBundle at all");
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn validate_cluster_trust_bundle_oversized_returns_422() {
        let body = serde_json::json!({
            "spec": {"trustBundle": "a".repeat(MAX_TRUST_BUNDLE_SIZE + 1)}
        });
        let err = validate_cluster_trust_bundle_spec(&body).expect_err(
            "a trustBundle over the 1 MiB upstream limit must be rejected -- otherwise a \
             malicious or buggy client can force every kubelet that mounts it to fetch and \
             hold an unbounded blob",
        );
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn validate_cluster_trust_bundle_invalid_pem_returns_422() {
        let body = serde_json::json!({"spec": {"trustBundle": "not a PEM bundle"}});
        let err = validate_cluster_trust_bundle_spec(&body)
            .expect_err("garbage trustBundle content must be rejected before storage");
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn validate_cluster_trust_bundle_wrong_pem_block_type_returns_422() {
        // A CSR PEM (real, well-formed PEM, just the wrong block type) must still be
        // rejected -- ClusterTrustBundle.spec.trustBundle only holds CA certificates.
        let body = serde_json::json!({
            "spec": {"trustBundle": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"}
        });
        let err = validate_cluster_trust_bundle_spec(&body)
            .expect_err("a non-CERTIFICATE PEM block type must be rejected");
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn validate_cluster_trust_bundle_valid_pem_returns_ok() {
        let body = serde_json::json!({"spec": {"trustBundle": valid_cert_pem()}});
        if let Err(err) = validate_cluster_trust_bundle_spec(&body) {
            panic!(
                "a well-formed CERTIFICATE PEM must pass validation, got status={}",
                err.0
            );
        }
    }

    // -----------------------------------------------------------------------
    // PodCertificateRequest
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn podcertificaterequest_create_stores_spec_and_leaves_status_empty_because_controller_populates_status_out_of_band(
    ) {
        let state = make_state();
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1beta1",
            "kind": "PodCertificateRequest",
            "metadata": {"name": "req-1"},
            "spec": valid_pcr_spec(),
            // A client should never be able to pre-seed status this way -- it is the
            // signer's exclusive right, written only via the /status subresource.
            "status": {"certificateChain": "SHOULD_BE_STRIPPED"}
        });

        let result = create_pod_certificate_request(
            State(state.clone()),
            Path("default".to_string()),
            Query(CreateQuery::default()),
            Extension(test_user()),
            json_headers(),
            Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;

        let resp = result.unwrap_or_else(|e| panic!("create must succeed, got status {}", e.0));
        assert_eq!(resp.status(), StatusCode::CREATED);

        let key = "/registry/certificates.k8s.io/podcertificaterequests/default/req-1";
        let stored = state.store.get(key).await.unwrap().expect("must persist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["spec"]["podName"], "my-pod",
            "the +required spec fields identify exactly which pod a signer must bind an \
             issued certificate to -- they must survive create unchanged"
        );
        assert!(
            v.get("status").is_none() || v["status"].is_null(),
            "status must never be settable at create time -- a controller populates it \
             out-of-band via /status once (and if) it issues a certificate. Got: {:?}",
            v.get("status")
        );
    }

    #[tokio::test]
    async fn podcertificaterequest_status_subresource_updates_only_status_field_because_spec_is_immutable_post_create(
    ) {
        let state = make_state();
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1beta1",
            "kind": "PodCertificateRequest",
            "metadata": {"name": "req-1"},
            "spec": valid_pcr_spec()
        });
        create_pod_certificate_request(
            State(state.clone()),
            Path("default".to_string()),
            Query(CreateQuery::default()),
            Extension(test_user()),
            json_headers(),
            Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("create must succeed, got status {}", e.0));

        // Attempt to smuggle a spec change through the /status subresource alongside a
        // legitimate status write.
        let mut smuggled_spec = valid_pcr_spec();
        smuggled_spec["podName"] = serde_json::Value::String("attacker-controlled-pod".into());
        let status_write = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1beta1",
            "kind": "PodCertificateRequest",
            "metadata": {"name": "req-1", "namespace": "default"},
            "spec": smuggled_spec,
            "status": {"certificateChain": "issued-cert-pem"}
        });

        let result = crate::handlers::status::put_namespaced_resource_status(
            State(state.clone()),
            Path((
                GROUP.to_string(),
                VERSION.to_string(),
                "default".to_string(),
                PCR_PLURAL.to_string(),
                "req-1".to_string(),
            )),
            HeaderMap::new(),
            Bytes::from(serde_json::to_vec(&status_write).unwrap()),
        )
        .await;
        result.unwrap_or_else(|e| panic!("status PUT must succeed, got status {}", e.0));

        let key = "/registry/certificates.k8s.io/podcertificaterequests/default/req-1";
        let stored = state.store.get(key).await.unwrap().expect("must exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["status"]["certificateChain"], "issued-cert-pem",
            "a legitimate /status write must still take effect"
        );
        assert_eq!(
            v["spec"]["podName"], "my-pod",
            "spec is immutable after create -- a write to /status must never be able to \
             change which pod a certificate is bound to, even if the request body includes \
             a spec block"
        );
    }

    #[test]
    fn validate_pod_certificate_request_missing_field_returns_422() {
        let mut spec = valid_pcr_spec();
        spec.as_object_mut().unwrap().remove("podName");
        let body = serde_json::json!({"spec": spec});
        let err = validate_pod_certificate_request_spec(&body).expect_err(
            "a PodCertificateRequest missing podName must be rejected -- the \
                signer has no idea which pod to bind the certificate to",
        );
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn validate_pod_certificate_request_empty_field_returns_422() {
        let mut spec = valid_pcr_spec();
        spec["nodeUID"] = serde_json::Value::String(String::new());
        let body = serde_json::json!({"spec": spec});
        let err = validate_pod_certificate_request_spec(&body).expect_err(
            "an empty (but present) required field must be rejected the same \
                way an absent one is",
        );
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn validate_pod_certificate_request_valid_spec_returns_ok() {
        let body = serde_json::json!({"spec": valid_pcr_spec()});
        if let Err(err) = validate_pod_certificate_request_spec(&body) {
            panic!(
                "a spec with all seven required fields present must pass validation, got status={}",
                err.0
            );
        }
    }

    // -----------------------------------------------------------------------
    // PodCertificateRequest: spec.maxExpirationSeconds bounds
    // -----------------------------------------------------------------------

    /// Upstream's `ValidatePodCertificateRequestCreate` treats `maxExpirationSeconds` as
    /// `+required` (no `omitempty`) -- a request that omits it entirely must be rejected,
    /// not silently accepted with an unbounded/undefined certificate lifetime.
    #[test]
    fn validate_pod_certificate_request_missing_max_expiration_seconds_returns_422() {
        let mut spec = valid_pcr_spec();
        spec.as_object_mut().unwrap().remove("maxExpirationSeconds");
        let body = serde_json::json!({"spec": spec});
        let err = validate_pod_certificate_request_spec(&body)
            .expect_err("maxExpirationSeconds must be required, matching upstream");
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A value below the upstream 1-hour floor (`certificates.MinMaxExpirationSeconds`)
    /// must be rejected -- a shorter-lived cert than any signer can reasonably issue and
    /// rotate in time is a footgun, not a valid request.
    #[test]
    fn validate_pod_certificate_request_max_expiration_seconds_below_minimum_returns_422() {
        let mut spec = valid_pcr_spec();
        spec["maxExpirationSeconds"] = serde_json::json!(3599);
        let body = serde_json::json!({"spec": spec});
        let err = validate_pod_certificate_request_spec(&body)
            .expect_err("3599s is below the 3600s (1h) upstream minimum and must be rejected");
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A value above the upstream 91-day ceiling (`certificates.MaxMaxExpirationSeconds`)
    /// for a non-`kubernetes.io` signer must be rejected -- kubelet mounts whatever a
    /// signer eventually issues verbatim onto disk, so an unbounded lifetime here becomes
    /// an unbounded-lifetime credential on the node.
    #[test]
    fn validate_pod_certificate_request_max_expiration_seconds_above_maximum_returns_422() {
        let mut spec = valid_pcr_spec();
        spec["maxExpirationSeconds"] = serde_json::json!(91 * 24 * 60 * 60 + 1);
        let body = serde_json::json!({"spec": spec});
        let err = validate_pod_certificate_request_spec(&body).expect_err(
            "91d + 1s exceeds the 91-day upstream maximum for a non-kubernetes.io signer",
        );
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A `kubernetes.io`-namespaced signer is held to the tighter 24h ceiling
    /// (`certificates.KubernetesMaxMaxExpirationSeconds`), not the generic 91-day one --
    /// a request that would be valid for any other signer must still be rejected here.
    #[test]
    fn validate_pod_certificate_request_kubernetes_signer_max_expiration_seconds_uses_24h_ceiling()
    {
        let mut spec = valid_pcr_spec();
        spec["signerName"] = serde_json::json!("kubernetes.io/kube-apiserver-client");
        spec["maxExpirationSeconds"] = serde_json::json!(25 * 60 * 60);
        let body = serde_json::json!({"spec": spec});
        let err = validate_pod_certificate_request_spec(&body).expect_err(
            "a kubernetes.io signer must reject 25h -- its ceiling is 24h, not the generic 91d",
        );
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// The upstream minimum (3600s, exactly 1h) is inclusive -- the boundary value itself
    /// must be accepted, not rejected as "below minimum".
    #[test]
    fn validate_pod_certificate_request_max_expiration_seconds_at_minimum_boundary_is_ok() {
        let mut spec = valid_pcr_spec();
        spec["maxExpirationSeconds"] = serde_json::json!(3600);
        let body = serde_json::json!({"spec": spec});
        if let Err(err) = validate_pod_certificate_request_spec(&body) {
            panic!(
                "exactly 3600s (the minimum) must be accepted, got status={}",
                err.0
            );
        }
    }
}
