//! Dedicated create-validation for certificates.k8s.io ClusterTrustBundle (v1 and v1beta1)
//! and PodCertificateRequest (v1 and v1beta1).
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
use serde::Deserialize;
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
const CTB_PLURAL: &str = "clustertrustbundles";
const PCR_PLURAL: &str = "podcertificaterequests";

/// Upstream kube-apiserver's `certificates.MaxTrustBundleSize`
/// (pkg/apis/certificates/types.go): 1 MiB. Enforced here so a client can't force every
/// kubelet that mounts this bundle to fetch and hold an unbounded blob.
const MAX_TRUST_BUNDLE_SIZE: usize = 1024 * 1024;

/// Upstream `ValidateSignerName`: 253 (domain) + '/' + 317 (path) characters.
const MAX_SIGNER_NAME_LENGTH: usize = 571;

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
    let spec: ClusterTrustBundleSpec = ClusterTrustBundleSpec::deserialize(&body["spec"])
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

    validate_name_matches_signer(body, &spec.signer_name)
}

/// Upstream `ValidateClusterTrustBundle`: a signer-linked bundle must be named
/// `<signerName with '/' replaced by ':'>:<suffix>` (so the name alone reveals the owning
/// signer and signers cannot squat each other's names); a bundle without a signer must not
/// use `:` at all, keeping that namespace exclusively signer-scoped. Like upstream's
/// `ValidateObjectMeta`, the rule applies to `metadata.generateName` (as a prefix) and to
/// `metadata.name`, whichever are set.
fn validate_name_matches_signer(
    body: &serde_json::Value,
    signer_name: &str,
) -> Result<(), crate::status::StatusError> {
    if !signer_name.is_empty() {
        let mut parts = signer_name.split('/');
        let well_formed = matches!(
            (parts.next(), parts.next(), parts.next()),
            (Some(d), Some(p), None) if !d.is_empty() && !p.is_empty()
        );
        if !well_formed || signer_name.len() > MAX_SIGNER_NAME_LENGTH {
            return Err(Status::unprocessable_entity(format!(
                "spec.signerName: Invalid value: {signer_name:?}: must be of the form \
                 <domain>/<path> and at most {MAX_SIGNER_NAME_LENGTH} characters"
            )));
        }
    }

    let prefix = format!("{}:", signer_name.replace('/', ":"));
    for field in ["generateName", "name"] {
        let Some(value) = body["metadata"][field].as_str().filter(|v| !v.is_empty()) else {
            continue;
        };
        if signer_name.is_empty() {
            if value.contains(':') {
                return Err(Status::unprocessable_entity(format!(
                    "metadata.{field}: Invalid value: {value:?}: ClusterTrustBundle without \
                     spec.signerName must not contain ':'"
                )));
            }
        } else if !value.starts_with(&prefix) {
            return Err(Status::unprocessable_entity(format!(
                "metadata.{field}: Invalid value: {value:?}: ClusterTrustBundle for signerName \
                 {signer_name} must be named with prefix {prefix}"
            )));
        }
    }
    Ok(())
}

/// Upstream `ValidateClusterTrustBundleUpdate`: `spec.signerName` is immutable, otherwise a
/// writer could re-home a bundle under another signer while its name (which consumers use to
/// select by signer) still claims the original one.
pub(crate) fn validate_cluster_trust_bundle_signer_immutable(
    old: &serde_json::Value,
    new: &serde_json::Value,
) -> Result<(), String> {
    let signer = |v: &serde_json::Value| v["spec"]["signerName"].as_str().unwrap_or("").to_string();
    if signer(old) != signer(new) {
        return Err("spec.signerName: Invalid value: field is immutable".to_string());
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

/// POST /apis/certificates.k8s.io/{version}/clustertrustbundles
///
/// Validates `spec.trustBundle` before delegating to the generic cluster-scoped create
/// handler for everything else (defaulting, admission, persistence).
pub(crate) async fn create_cluster_trust_bundle<S: Store>(
    State(state): State<AppState<S>>,
    Path(version): Path<String>,
    Query(create_query): Query<CreateQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, crate::status::StatusError> {
    let decoded = extract_body(&body, content_type(&headers))?;
    let obj = Object::from_bytes(&decoded)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;
    validate_cluster_trust_bundle_spec(&obj.body)?;

    super::resource::create_resource(
        State(state),
        Path((GROUP.to_string(), version, CTB_PLURAL.to_string())),
        Query(create_query),
        Extension(user),
        headers,
        body,
    )
    .await
    .map(IntoResponse::into_response)
}

/// GET /apis/certificates.k8s.io/{version}/clustertrustbundles
///
/// The collection route is a hardcoded literal (needed so POST can run the validation
/// above), so GET/DELETE on the same literal path must also be registered here — axum
/// answers unregistered methods on a literal route with 405, it never falls through to
/// the generic `{group}/{version}/{resource}` template for the same concrete path.
pub(crate) async fn list_cluster_trust_bundles<S: Store>(
    State(state): State<AppState<S>>,
    Path(version): Path<String>,
    Query(query): Query<CollectionQuery>,
    headers: HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    super::resource::list_resource(
        State(state),
        Path((GROUP.to_string(), version, CTB_PLURAL.to_string())),
        Query(query),
        headers,
        Extension(user),
    )
    .await
}

/// DELETE /apis/certificates.k8s.io/{version}/clustertrustbundles (DeleteCollection)
pub(crate) async fn delete_collection_cluster_trust_bundles<S: Store>(
    State(state): State<AppState<S>>,
    Path(version): Path<String>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    super::resource::delete_collection_resource(
        State(state),
        Path((GROUP.to_string(), version, CTB_PLURAL.to_string())),
        Query(query),
        Extension(user),
        headers,
        body,
    )
    .await
}

// ---------------------------------------------------------------------------
// PodCertificateRequest
// ---------------------------------------------------------------------------

/// Upstream `IsDNS1123Label`: 1-63 chars of `[a-z0-9-]`, alphanumeric at both ends.
pub(crate) fn is_dns1123_label(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// Upstream `IsDNS1123Subdomain`: at most 253 chars, dot-separated DNS labels.
pub(crate) fn is_dns1123_subdomain(s: &str) -> bool {
    s.len() <= 253 && s.split('.').all(is_dns1123_label)
}

/// Upstream `ValidateSignerName` (pkg/apis/core/validation/names.go): `<domain>/<path>`
/// where the domain is at least two DNS labels and the path is dot-separated DNS subdomains.
fn validate_pod_certificate_signer_name(signer_name: &str) -> Result<(), String> {
    if signer_name.is_empty() {
        return Err("must not be empty".into());
    }
    let mut parts = signer_name.split('/');
    let (Some(domain), Some(path), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(
            "must be a fully qualified domain and path of the form 'example.com/signer-name'"
                .into(),
        );
    };
    if domain.len() > 253 {
        return Err("domain segment must be no more than 253 characters".into());
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if let Some(bad) = labels.iter().find(|l| !is_dns1123_label(l)) {
        return Err(format!(
            "validating label {bad:?}: must be a DNS-1123 label"
        ));
    }
    if labels.len() < 2 {
        return Err("should be a domain with at least two segments separated by dots".into());
    }
    if let Some(bad) = path.split('.').find(|l| !is_dns1123_subdomain(l)) {
        return Err(format!(
            "validating label {bad:?}: must be a DNS-1123 subdomain"
        ));
    }
    if signer_name.len() > MAX_SIGNER_NAME_LENGTH {
        return Err(format!(
            "must be no more than {MAX_SIGNER_NAME_LENGTH} characters"
        ));
    }
    Ok(())
}

/// Upstream `IsDomainPrefixedKey` on a lower-cased key: `<dns-subdomain>/<qualified-name>`.
fn is_domain_prefixed_key(key: &str) -> bool {
    let mut parts = key.split('/');
    let (Some(prefix), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let b = name.as_bytes();
    is_dns1123_subdomain(prefix)
        && !b.is_empty()
        && b.len() <= 63
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
}

/// Upstream `certificates.MaxPKIXPublicKeySize` / `MaxProofOfPossessionSize` /
/// `MaxStubPKCS10RequestSize`.
const MAX_KEY_MATERIAL_SIZE: usize = 10 * 1024;
/// Upstream `certificates.MaxCertificateChainSize`.
const MAX_CERTIFICATE_CHAIN_SIZE: usize = 100 * 1024;
/// Upstream `apimachineryvalidation.TotalAnnotationSizeLimitB`.
const MAX_USER_ANNOTATIONS_SIZE: usize = 256 * 1024;
const MAX_UID_LENGTH: usize = 128;

const API_VERSION_V1: &str = "certificates.k8s.io/v1";

/// Validate a PodCertificateRequest `spec`, mirroring upstream's
/// `ValidatePodCertificateRequestCreate` (pkg/apis/certificates/validation/validation.go),
/// returning 422 on any violation. Run on every write path that can set `spec` (create, PUT,
/// every PATCH flavor, apply) via `defaults::validate_resource`: the spec names the exact
/// pod/node/service-account identity a signer binds an issued certificate to, so a write
/// path that skips these checks would let a request for a nonsense identity through.
///
/// Not implemented (no crypto backend in this crate): the stub PKCS#10 self-signature check
/// and the v1beta1 `proofOfPossession` signature check. Key type and size are validated.
pub(crate) fn validate_pod_certificate_request_spec(
    body: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let spec: PodCertificateRequestSpec = PodCertificateRequestSpec::deserialize(&body["spec"])
        .map_err(|e| {
            Status::unprocessable_entity(format!(
                "spec.signerName, spec.podName, spec.podUID, spec.serviceAccountName, \
                 spec.serviceAccountUID, spec.nodeName, and spec.nodeUID are all required: {e}"
            ))
        })?;

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

    validate_pod_certificate_signer_name(&spec.signer_name).map_err(|e| {
        Status::unprocessable_entity(format!(
            "spec.signerName: Invalid value: {:?}: {e}",
            spec.signer_name
        ))
    })?;
    for (field, v) in [
        ("podName", &spec.pod_name),
        ("serviceAccountName", &spec.service_account_name),
        ("nodeName", &spec.node_name),
    ] {
        if !is_dns1123_subdomain(v) {
            return Err(Status::unprocessable_entity(format!(
                "spec.{field}: Invalid value: {v:?}: must be a valid DNS-1123 subdomain"
            )));
        }
    }
    for (field, v) in [
        ("podUID", &spec.pod_uid),
        ("serviceAccountUID", &spec.service_account_uid),
        ("nodeUID", &spec.node_uid),
    ] {
        if v.len() > MAX_UID_LENGTH {
            return Err(Status::unprocessable_entity(format!(
                "spec.{field}: Too long: may not be more than {MAX_UID_LENGTH} bytes"
            )));
        }
    }

    if let Some(annotations) = &spec.unverified_user_annotations {
        let mut total = 0;
        for (k, v) in annotations {
            if !is_domain_prefixed_key(&k.to_lowercase()) {
                return Err(Status::unprocessable_entity(format!(
                    "spec.unverifiedUserAnnotations: Invalid value: {k:?}: must be a \
                     domain-prefixed key (such as \"acme.io/foo\")"
                )));
            }
            total += k.len() + v.len();
        }
        if total > MAX_USER_ANNOTATIONS_SIZE {
            return Err(Status::unprocessable_entity(format!(
                "spec.unverifiedUserAnnotations: Too long: may not be more than \
                 {MAX_USER_ANNOTATIONS_SIZE} bytes"
            )));
        }
    }

    validate_max_expiration_seconds(&spec)?;

    let v1 = body["apiVersion"].as_str() == Some(API_VERSION_V1);
    validate_pod_certificate_request_keys(&spec, v1).map_err(Status::unprocessable_entity)
}

/// `spec` key material: exactly one of `stubPKCS10Request` or (v1beta1 only)
/// `pkixPublicKey` + `proofOfPossession`, each within its size limit and using a supported
/// key type. v1 dropped the deprecated pair, so a v1 body carrying either is rejected rather
/// than silently stored.
fn validate_pod_certificate_request_keys(
    spec: &PodCertificateRequestSpec,
    v1: bool,
) -> Result<(), String> {
    use base64::Engine as _;
    let decode = |field: &str, v: &Option<String>| -> Result<Vec<u8>, String> {
        let raw = v.as_deref().unwrap_or("");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw)
            .map_err(|_| format!("spec.{field}: Invalid value: must be base64-encoded"))?;
        if bytes.len() > MAX_KEY_MATERIAL_SIZE {
            return Err(format!(
                "spec.{field}: Too long: may not be more than {MAX_KEY_MATERIAL_SIZE} bytes"
            ));
        }
        Ok(bytes)
    };
    let stub = decode("stubPKCS10Request", &spec.stub_pkcs10_request)?;
    let pkix = decode("pkixPublicKey", &spec.pkix_public_key)?;
    let pop = decode("proofOfPossession", &spec.proof_of_possession)?;

    if v1 && (!pkix.is_empty() || !pop.is_empty()) {
        return Err(
            "spec: pkixPublicKey and proofOfPossession are not part of certificates.k8s.io/v1; \
             use stubPKCS10Request"
                .into(),
        );
    }

    match (!stub.is_empty(), !pkix.is_empty(), !pop.is_empty()) {
        (true, false, false) => {
            let req = x509_cert::request::CertReq::from_der(&stub).map_err(|_| {
                "spec.stubPKCS10Request: Invalid value: must be a valid PKCS#10 CSR".to_string()
            })?;
            validate_spki_key_type(&req.info.public_key)
                .map_err(|e| format!("spec.stubPKCS10Request: Invalid value: {e}"))
        }
        (false, true, true) => {
            let spki =
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&pkix).map_err(|_| {
                    "spec.pkixPublicKey: Invalid value: must be a valid PKIX-serialized public key"
                        .to_string()
                })?;
            validate_spki_key_type(&spki)
                .map_err(|e| format!("spec.pkixPublicKey: Invalid value: {e}"))
        }
        _ => Err(
            "spec: Invalid value: exactly one of (stubPKCS10Request) or (pkixPublicKey, \
             proofOfPossession) must be set"
                .into(),
        ),
    }
}

/// Supported key types: Ed25519, ECDSA P-256/P-384/P-521, RSA 3072/4096 (upstream's set).
fn validate_spki_key_type(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<(), String> {
    const ED25519: &str = "1.3.101.112";
    const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    const EC_CURVES: [&str; 3] = ["1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35"];

    match spki.algorithm.oid.to_string().as_str() {
        ED25519 => Ok(()),
        EC_PUBLIC_KEY => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<x509_cert::der::asn1::ObjectIdentifier>().ok())
                .map(|oid| oid.to_string());
            match curve {
                Some(c) if EC_CURVES.contains(&c.as_str()) => Ok(()),
                _ => Err("elliptic public keys must use curve P256, P384, or P521".into()),
            }
        }
        RSA_ENCRYPTION => {
            let key = rsa::pkcs1::RsaPublicKey::try_from(spki.subject_public_key.raw_bytes())
                .map_err(|_| "invalid RSA public key".to_string())?;
            let bits = key.modulus.as_bytes().len() * 8;
            if bits == 3072 || bits == 4096 {
                Ok(())
            } else {
                Err(format!(
                    "{bits}-bit modulus: RSA keys must have modulus size 3072 or 4096"
                ))
            }
        }
        _ => Err("unknown public key type; supported types are Ed25519, ECDSA, and RSA".into()),
    }
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

/// Upstream `ValidatePodCertificateRequestUpdate`: every spec field is immutable, because a
/// signer may already have issued against the identity it names. Status changes only via
/// `/status`.
pub(crate) fn validate_pod_certificate_request_spec_immutable(
    old: &serde_json::Value,
    new: &serde_json::Value,
) -> Result<(), String> {
    if old["spec"] != new["spec"] {
        return Err("spec: Invalid value: field is immutable".to_string());
    }
    Ok(())
}

const CONDITION_ISSUED: &str = "Issued";
const CONDITION_DENIED: &str = "Denied";
const CONDITION_FAILED: &str = "Failed";

fn pcr_has_true_condition(status: &serde_json::Value, cond_type: &str) -> bool {
    status["conditions"].as_array().is_some_and(|conds| {
        conds
            .iter()
            .any(|c| c["type"] == cond_type && c["status"] == "True")
    })
}

/// `status` equality that treats an absent status, `null`, `{}` and an empty condition list
/// as the same empty status (Go's `Semantic.DeepEqual` on the typed struct does).
fn pcr_status_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    fn norm(v: &serde_json::Value) -> serde_json::Value {
        let mut v = if v.is_null() {
            serde_json::json!({})
        } else {
            v.clone()
        };
        if let Some(m) = v.as_object_mut() {
            if m.get("conditions")
                .and_then(|c| c.as_array())
                .is_some_and(Vec::is_empty)
            {
                m.remove("conditions");
            }
        }
        v
    }
    norm(a) == norm(b)
}

fn validate_pcr_condition_shape(cond: &serde_json::Value, idx: usize) -> Result<(), String> {
    let path = format!("status.conditions[{idx}]");
    let cond_type = cond["type"].as_str().unwrap_or("");
    if ![CONDITION_ISSUED, CONDITION_DENIED, CONDITION_FAILED].contains(&cond_type) {
        return Err(format!(
            "{path}.type: Unsupported value: {cond_type:?}: supported values: \
             \"Issued\", \"Denied\", \"Failed\""
        ));
    }
    if cond["status"] != "True" {
        return Err(format!(
            "{path}.status: Unsupported value: {}: supported values: \"True\"",
            cond["status"]
        ));
    }
    let reason = cond["reason"].as_str().unwrap_or("");
    let b = reason.as_bytes();
    let reason_ok = !b.is_empty()
        && b[0].is_ascii_alphabetic()
        && (b[b.len() - 1].is_ascii_alphanumeric() || b[b.len() - 1] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b',' | b':'));
    if !reason_ok {
        return Err(format!(
            "{path}.reason: Invalid value: {reason:?}: must be set and match \
             ^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$"
        ));
    }
    if cond["message"].as_str().is_some_and(|m| m.len() > 32768) {
        return Err(format!(
            "{path}.message: Too long: may not be more than 32768 bytes"
        ));
    }
    if cond["lastTransitionTime"]
        .as_str()
        .and_then(crate::util::rfc3339_to_unix_secs)
        .is_none()
    {
        return Err(format!(
            "{path}.lastTransitionTime: Required value: must be set"
        ));
    }
    Ok(())
}

/// Upstream `ValidatePodCertificateRequestStatusUpdate` plus `StatusStrategy.PrepareForUpdate`
/// metadata/spec reset: a `/status` write may not change spec or (beyond managedFields)
/// metadata, may only move a request into one terminal condition (`Issued`, `Denied`,
/// `Failed`) once, and an `Issued` status must carry a chain whose leaf was issued to the
/// requested public key with timestamps matching the leaf. Otherwise a signer (or anyone
/// holding `podcertificaterequests/status`) could hand a pod a certificate for someone
/// else's key, or rewrite an already-issued certificate.
///
/// Not implemented: upstream's `mail.ParseAddress` check on leaf email SANs.
pub(crate) fn validate_pod_certificate_request_status_update(
    old: &serde_json::Value,
    new: &serde_json::Value,
    now_unix_secs: i64,
) -> Result<(), String> {
    if old["spec"] != new["spec"] {
        return Err("spec: Invalid value: field is immutable via the status subresource".into());
    }
    let meta_without_managed = |v: &serde_json::Value| {
        let mut m = v["metadata"].clone();
        if let Some(o) = m.as_object_mut() {
            o.remove("managedFields");
            o.remove("resourceVersion");
        }
        m
    };
    if meta_without_managed(old) != meta_without_managed(new) {
        return Err(
            "metadata: Invalid value: field is immutable via the status subresource".into(),
        );
    }

    let (old_status, new_status) = (&old["status"], &new["status"]);
    let empty = Vec::new();
    let conds = new_status["conditions"].as_array().unwrap_or(&empty);
    for (i, cond) in conds.iter().enumerate() {
        validate_pcr_condition_shape(cond, i)?;
        if i > 0 {
            return Err(format!(
                "status.conditions[{i}].type: Invalid value: {}: There may be at most one \
                 condition with type \"Issued\", \"Denied\", or \"Failed\"",
                cond["type"]
            ));
        }
    }

    let is_terminal = |s: &serde_json::Value| {
        [CONDITION_ISSUED, CONDITION_DENIED, CONDITION_FAILED]
            .iter()
            .any(|t| pcr_has_true_condition(s, t))
    };
    if is_terminal(old_status) {
        return if pcr_status_eq(old_status, new_status) {
            Ok(())
        } else {
            Err(
                "status: Invalid value: immutable after PodCertificateRequest is issued, \
                 denied, or failed"
                    .into(),
            )
        };
    }

    if pcr_has_true_condition(new_status, CONDITION_DENIED)
        || pcr_has_true_condition(new_status, CONDITION_FAILED)
    {
        let only_conditions = serde_json::json!({"conditions": new_status["conditions"]});
        return if pcr_status_eq(new_status, &only_conditions) {
            Ok(())
        } else {
            Err(
                "status: Invalid value: non-condition status fields must be empty when \
                 denying or failing the PodCertificateRequest"
                    .into(),
            )
        };
    }

    if pcr_has_true_condition(new_status, CONDITION_ISSUED) {
        return validate_issued_pcr_status(old, new_status, now_unix_secs);
    }

    if pcr_status_eq(old_status, new_status) {
        Ok(())
    } else {
        Err(
            "status: Invalid value: status is immutable unless transitioning to \"Issued\", \
             \"Denied\", or \"Failed\""
                .into(),
        )
    }
}

fn validate_issued_pcr_status(
    old: &serde_json::Value,
    status: &serde_json::Value,
    now_unix_secs: i64,
) -> Result<(), String> {
    use base64::Engine as _;
    use x509_cert::der::Encode as _;

    let chain = status["certificateChain"].as_str().unwrap_or("");
    if chain.len() > MAX_CERTIFICATE_CHAIN_SIZE {
        return Err(format!(
            "status.certificateChain: Too long: may not be more than \
             {MAX_CERTIFICATE_CHAIN_SIZE} bytes"
        ));
    }
    let certs = x509_cert::Certificate::load_pem_chain(chain.as_bytes())
        .ok()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            "status.certificateChain: Invalid value: issued certificate chain must consist of \
             one or more valid CERTIFICATE PEM blocks"
                .to_string()
        })?;
    let leaf = &certs[0];

    if let Ok(Some((_, san))) = leaf
        .tbs_certificate()
        .get_extension::<x509_cert::ext::pkix::SubjectAltName>()
    {
        for name in &san.0 {
            if let x509_cert::ext::pkix::name::GeneralName::DnsName(d) = name {
                let d = d.as_str();
                if d.is_empty() || d.contains("..") || d.starts_with('.') || d.ends_with('.') {
                    return Err(format!(
                        "status.certificateChain: Invalid value: {d:?}: leaf certificate has a \
                         malformed DNSName"
                    ));
                }
            }
        }
    }

    let spec = &old["spec"];
    let b64 = |field: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(spec[field].as_str().unwrap_or(""))
            .unwrap_or_default()
    };
    let stub = b64("stubPKCS10Request");
    let want_spki = if !stub.is_empty() {
        x509_cert::request::CertReq::from_der(&stub)
            .map_err(|_| "spec.stubPKCS10Request: Invalid value: must be a valid PKCS#10 CSR")?
            .info
            .public_key
    } else {
        x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&b64("pkixPublicKey")).map_err(
            |_| "spec.pkixPublicKey: Invalid value: must be a valid PKIX-serialized public key",
        )?
    };
    let spki_der = |s: &x509_cert::spki::SubjectPublicKeyInfoOwned| s.to_der().ok();
    if spki_der(&want_spki) != spki_der(leaf.tbs_certificate().subject_public_key_info()) {
        return Err(
            "status.certificateChain: Invalid value: leaf certificate was not issued to the \
             requested public key"
                .into(),
        );
    }

    let ts = |field: &str| {
        status[field]
            .as_str()
            .and_then(crate::util::rfc3339_to_unix_secs)
    };
    let (Some(not_before), Some(not_after), Some(begin_refresh)) =
        (ts("notBefore"), ts("notAfter"), ts("beginRefreshAt"))
    else {
        return Err(
            "status: Required value: notBefore, notAfter and beginRefreshAt must be present and \
             consistent with the issued certificate"
                .into(),
        );
    };

    let validity = leaf.tbs_certificate().validity();
    let leaf_not_before = validity.not_before.to_unix_duration().as_secs() as i64;
    let leaf_not_after = validity.not_after.to_unix_duration().as_secs() as i64;
    if not_before != leaf_not_before {
        return Err("status.notBefore: Invalid value: must be set to the NotBefore time encoded in the leaf certificate".into());
    }
    if (not_before - now_unix_secs).abs() >= 5 * 60 {
        return Err("status.notBefore: Invalid value: must be set to within 5 minutes of kube-apiserver's current time".into());
    }
    if not_after != leaf_not_after {
        return Err("status.notAfter: Invalid value: must be set to the NotAfter time encoded in the leaf certificate".into());
    }

    let lifetime = leaf_not_after - leaf_not_before;
    if lifetime < 3600 {
        return Err(format!(
            "status.certificateChain: Invalid value: {lifetime}s: leaf certificate lifetime must be >= 1 hour"
        ));
    }
    let max = spec["maxExpirationSeconds"].as_i64().unwrap_or(0);
    if lifetime > max {
        return Err(format!(
            "status.certificateChain: Invalid value: {lifetime}s: leaf certificate lifetime must be <= spec.maxExpirationSeconds ({max})"
        ));
    }
    if begin_refresh < not_before + 600 {
        return Err("status.beginRefreshAt: Invalid value: must be at least 10 minutes after status.notBefore".into());
    }
    if begin_refresh > not_after - 600 {
        return Err("status.beginRefreshAt: Invalid value: must be at least 10 minutes before status.notAfter".into());
    }
    Ok(())
}

/// Upstream `StatusStrategy.ValidateUpdate` sign check: changing any status field requires
/// the `sign` verb on `signers/<signerName>` (or `signers/<domain>/*`), so holding
/// `podcertificaterequests/status` alone does not let a caller issue under any signer name.
fn user_may_sign<S: Store>(state: &AppState<S>, user: &UserInfo, signer_name: &str) -> bool {
    let allowed = |name: &str| {
        state.rbac_index.is_allowed(&crate::rbac::AuthzRequest {
            username: &user.username,
            groups: &user.groups,
            verb: "sign",
            api_group: GROUP,
            resource: "signers",
            subresource: "",
            namespace: None,
            name: Some(name),
            non_resource_url: None,
        })
    };
    let domain = signer_name.split('/').next().unwrap_or("");
    allowed(signer_name) || allowed(&format!("{domain}/*"))
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The guard every `/status` write on a PodCertificateRequest passes through: content
/// validation, then the signer authorization check when the status actually changes.
fn guard_pod_certificate_request_status_write<S: Store>(
    state: &AppState<S>,
    user: &UserInfo,
    old: &serde_json::Value,
    new: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    validate_pod_certificate_request_status_update(old, new, now_unix_secs())
        .map_err(Status::unprocessable_entity)?;
    if !pcr_status_eq(&old["status"], &new["status"]) {
        let signer = old["spec"]["signerName"].as_str().unwrap_or("");
        if !user_may_sign(state, user, signer) {
            return Err(Status::forbidden(format!(
                "spec.signerName: Forbidden: User {:?} is not permitted to \"sign\" for signer {signer:?}",
                user.username
            )));
        }
    }
    Ok(())
}

async fn fetch_json<S: Store>(
    state: &AppState<S>,
    key: &str,
    what: &str,
) -> Result<serde_json::Value, crate::status::StatusError> {
    let stored = state
        .store
        .get(key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::conflict(format!("{what} not found; retry once it is visible")))?;
    serde_json::from_slice(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored {what}: {e}")))
}

/// NodeRestriction for PodCertificateRequest CREATE
/// (plugin/pkg/admission/noderestriction `admitPodCertificateRequest`): a `system:node:<n>`
/// identity may only request a certificate for a pod that is bound to node `<n>`, with the
/// pod, service-account and node UIDs it actually has, and only for a signer the pod mounts
/// a `podCertificate` volume for (or that RBAC explicitly allows for that service account).
/// Without it any kubelet could obtain a certificate for any pod's identity in the cluster.
/// A no-op for non-node callers.
async fn restrict_node_pod_certificate_request_create<S: Store>(
    state: &AppState<S>,
    user: &UserInfo,
    ns: &str,
    body: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let Some(node_name) = crate::node_authz::node_identity(&user.username, &user.groups) else {
        return Ok(());
    };
    let spec = &body["spec"];
    let field = |k: &str| spec[k].as_str().unwrap_or("");
    let forbid = |msg: String| Err(Status::forbidden(msg));

    if field("nodeName") != node_name {
        return forbid(format!(
            "PodCertificateRequest.Spec.NodeName={:?}, which is not the requesting node {node_name:?}",
            field("nodeName")
        ));
    }
    let node = fetch_json(
        state,
        &crate::keys::cluster_object_key("nodes", node_name),
        "node",
    )
    .await?;
    if node["metadata"]["uid"].as_str() != Some(field("nodeUID")) {
        return Err(Status::conflict(format!(
            "PodCertificateRequest names node UID {:?}, inconsistent with the running node",
            field("nodeUID")
        )));
    }

    let pod_name = field("podName");
    let pod = fetch_json(state, &crate::keys::object_key("pods", ns, pod_name), "pod").await?;
    if pod["metadata"]["uid"].as_str() != Some(field("podUID")) {
        return Err(Status::conflict(format!(
            "PodCertificateRequest for pod \"{ns}/{pod_name}\" contains pod UID {:?} which differs from the running pod",
            field("podUID")
        )));
    }
    if pod["spec"]["nodeName"].as_str() != Some(node_name) {
        return forbid(format!(
            "pod \"{ns}/{pod_name}\" is not running on node {node_name:?} named in the PodCertificateRequest"
        ));
    }
    if pod["metadata"]["annotations"]
        .get("kubernetes.io/config.mirror")
        .is_some()
    {
        return forbid(format!("pod \"{ns}/{pod_name}\" is a mirror pod"));
    }

    let sa_name = field("serviceAccountName");
    if pod["spec"]["serviceAccountName"]
        .as_str()
        .unwrap_or("default")
        != sa_name
    {
        return forbid(format!(
            "PodCertificateRequest for pod \"{ns}/{pod_name}\" contains serviceAccountName {sa_name:?} that differs from the running pod"
        ));
    }
    let sa = fetch_json(
        state,
        &crate::keys::object_key("serviceaccounts", ns, sa_name),
        "service account",
    )
    .await?;
    if sa["metadata"]["uid"].as_str() != Some(field("serviceAccountUID")) {
        return Err(Status::conflict(format!(
            "PodCertificateRequest for pod \"{ns}/{pod_name}\" names service account UID {:?}, which differs from the running service account",
            field("serviceAccountUID")
        )));
    }

    let signer = field("signerName");
    if pod_mounts_pod_certificate_for_signer(&pod, signer) {
        return Ok(());
    }
    let munged = signer.replace('/', ":");
    let allowed = state.rbac_index.is_allowed(&crate::rbac::AuthzRequest {
        username: &user.username,
        groups: &user.groups,
        verb: "request-serviceaccounts-podcertificate-signer",
        api_group: GROUP,
        resource: &munged,
        subresource: "",
        namespace: Some(ns),
        name: Some(sa_name),
        non_resource_url: None,
    });
    if allowed {
        Ok(())
    } else {
        forbid(format!(
            "pod \"{ns}/{pod_name}\" does not mount a podCertificate projected volume for signer {signer:?}"
        ))
    }
}

fn pod_mounts_pod_certificate_for_signer(pod: &serde_json::Value, signer: &str) -> bool {
    pod["spec"]["volumes"].as_array().is_some_and(|vols| {
        vols.iter().any(|v| {
            v["projected"]["sources"].as_array().is_some_and(|srcs| {
                srcs.iter()
                    .any(|s| s["podCertificate"]["signerName"].as_str() == Some(signer))
            })
        })
    })
}

/// POST /apis/certificates.k8s.io/{version}/namespaces/{ns}/podcertificaterequests
///
/// Applies NodeRestriction and strips any client-supplied `status` (the signer's exclusive
/// right, written only via `/status`) before delegating to the generic namespaced create
/// handler, which runs the spec validation. Mirrors `csr::create_csr`'s status-stripping.
pub(crate) async fn create_pod_certificate_request<S: Store>(
    State(state): State<AppState<S>>,
    Path((version, ns)): Path<(String, String)>,
    Query(create_query): Query<CreateQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, crate::status::StatusError> {
    let decoded = extract_body(&body, content_type(&headers))?;
    let mut obj = Object::from_bytes(&decoded)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    restrict_node_pod_certificate_request_create(&state, &user, &ns, &obj.body).await?;

    if let Some(map) = obj.body.as_object_mut() {
        map.remove("status");
    }
    obj.body["apiVersion"] = format!("{GROUP}/{version}").into();

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
        Path((GROUP.to_string(), version, ns, PCR_PLURAL.to_string())),
        Query(create_query),
        Extension(user),
        forward_headers,
        obj.to_bytes(),
    )
    .await
    .map(IntoResponse::into_response)
}

/// GET /apis/certificates.k8s.io/{version}/namespaces/{ns}/podcertificaterequests
///
/// Same reasoning as `list_cluster_trust_bundles`: the collection route is a literal
/// path (for POST's validation), so GET/DELETE/PATCH must be registered alongside it.
pub(crate) async fn list_pod_certificate_requests<S: Store>(
    State(state): State<AppState<S>>,
    Path((version, ns)): Path<(String, String)>,
    Query(query): Query<CollectionQuery>,
    headers: HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    super::resource::list_namespaced_resource(
        State(state),
        Path((GROUP.to_string(), version, ns, PCR_PLURAL.to_string())),
        Query(query),
        headers,
        Extension(user),
    )
    .await
}

/// DELETE /apis/certificates.k8s.io/{version}/namespaces/{ns}/podcertificaterequests
/// (DeleteCollection)
pub(crate) async fn delete_collection_pod_certificate_requests<S: Store>(
    State(state): State<AppState<S>>,
    Path((version, ns)): Path<(String, String)>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    super::resource::delete_collection_namespaced_resource(
        State(state),
        Path((GROUP.to_string(), version, ns, PCR_PLURAL.to_string())),
        Query(query),
        Extension(user),
        headers,
        body,
    )
    .await
}

/// PATCH /apis/certificates.k8s.io/{version}/namespaces/{ns}/podcertificaterequests
/// (collection patch — matches the generic namespaced collection route's method set)
pub(crate) async fn patch_collection_pod_certificate_requests<S: Store>(
    State(state): State<AppState<S>>,
    Path((version, ns)): Path<(String, String)>,
    Query(query): Query<CollectionQuery>,
    Query(patch_query): Query<PatchQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    super::resource::patch_collection_namespaced_resource(
        State(state),
        Path((GROUP.to_string(), version, ns, PCR_PLURAL.to_string())),
        Query(query),
        Query(patch_query),
        Extension(user),
        headers,
        body,
    )
    .await
}

/// GET .../podcertificaterequests/{name}/status
pub(crate) async fn get_pod_certificate_request_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((version, ns, name)): Path<(String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    super::status::get_namespaced_resource_status(
        State(state),
        Path((GROUP.to_string(), version, ns, PCR_PLURAL.to_string(), name)),
    )
    .await
}

/// PUT .../podcertificaterequests/{name}/status — the generic status PUT with the PCR guard
/// (spec/metadata immutability, terminal-condition rules, issued-certificate checks, sign
/// permission) applied just before the store write.
pub(crate) async fn put_pod_certificate_request_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((version, ns, name)): Path<(String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, crate::status::StatusError> {
    let guard = |old: &serde_json::Value, new: &serde_json::Value| {
        guard_pod_certificate_request_status_write(&state, &user, old, new)
    };
    super::status::put_namespaced_resource_status_guarded(
        State(state.clone()),
        Path((GROUP.to_string(), version, ns, PCR_PLURAL.to_string(), name)),
        headers,
        body,
        Some(&guard),
    )
    .await
}

/// PATCH .../podcertificaterequests/{name}/status — see `put_pod_certificate_request_status`.
pub(crate) async fn patch_pod_certificate_request_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((version, ns, name)): Path<(String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, crate::status::StatusError> {
    let guard = |old: &serde_json::Value, new: &serde_json::Value| {
        guard_pod_certificate_request_status_write(&state, &user, old, new)
    };
    super::status::patch_namespaced_resource_status_guarded(
        State(state.clone()),
        Path((GROUP.to_string(), version, ns, PCR_PLURAL.to_string(), name)),
        headers,
        body,
        Some(&guard),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::{header::CONTENT_TYPE, HeaderValue, StatusCode};

    use crate::handlers::test_support::make_state;

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

    /// Fresh key plus the base64 of a real stub PKCS#10 CSR for it (what kubelet sends).
    fn stub_csr() -> (rcgen::KeyPair, String) {
        use base64::Engine as _;
        let key = rcgen::KeyPair::generate().expect("key generation must succeed");
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .expect("CSR generation must succeed");
        let b64 = base64::engine::general_purpose::STANDARD.encode(csr.der());
        (key, b64)
    }

    fn pcr_spec(csr_b64: &str) -> serde_json::Value {
        serde_json::json!({
            "signerName": "example.com/signer",
            "podName": "my-pod",
            "podUID": "pod-uid-1",
            "serviceAccountName": "default",
            "serviceAccountUID": "sa-uid-1",
            "nodeName": "node-1",
            "nodeUID": "node-uid-1",
            "maxExpirationSeconds": 3600,
            "stubPKCS10Request": csr_b64
        })
    }

    fn valid_pcr_spec() -> serde_json::Value {
        pcr_spec(&stub_csr().1)
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
            Path("v1beta1".to_string()),
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
        for (name, signer) in [
            ("example.com:a:bundle-a", "example.com/a"),
            ("example.com:b:bundle-b", "example.com/b"),
        ] {
            let body = serde_json::json!({
                "apiVersion": "certificates.k8s.io/v1beta1",
                "kind": "ClusterTrustBundle",
                "metadata": {"name": name},
                "spec": {"signerName": signer, "trustBundle": pem}
            });
            create_cluster_trust_bundle(
                State(state.clone()),
                Path("v1beta1".to_string()),
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
            Path("v1beta1".to_string()),
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

    fn ctb_body(name: &str, signer: &str) -> serde_json::Value {
        serde_json::json!({
            "metadata": {"name": name},
            "spec": {"signerName": signer, "trustBundle": valid_cert_pem()}
        })
    }

    #[test]
    fn validate_cluster_trust_bundle_signer_name_must_prefix_object_name() {
        validate_cluster_trust_bundle_spec(&ctb_body(
            "test.test:signer-one:0",
            "test.test/signer-one",
        ))
        .unwrap_or_else(|e| panic!("signer-scoped name must be accepted, got {}", e.0));
        let err =
            validate_cluster_trust_bundle_spec(&ctb_body("other:name", "test.test/signer-one"))
                .expect_err(
                    "a bundle whose name is not prefixed by its signer would let one signer \
                 squat another signer's bundle names",
                );
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn validate_cluster_trust_bundle_without_signer_rejects_colon_in_name() {
        let err = validate_cluster_trust_bundle_spec(&ctb_body("a:b", ""))
            .expect_err("colon names are reserved for signer-linked bundles");
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
        validate_cluster_trust_bundle_spec(&ctb_body("plain-name", ""))
            .unwrap_or_else(|e| panic!("signerless plain name must be accepted, got {}", e.0));
    }

    #[test]
    fn validate_cluster_trust_bundle_rejects_malformed_signer_name() {
        for signer in ["no-slash", "/path", "domain/", "a/b/c"] {
            let name = format!("{}:x", signer.replace('/', ":"));
            let err = validate_cluster_trust_bundle_spec(&ctb_body(&name, signer))
                .expect_err("signerName must be <domain>/<path>");
            assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY, "signer {signer}");
        }
    }

    #[tokio::test]
    async fn clustertrustbundle_v1_create_is_served_because_ga_clients_use_v1() {
        let state = make_state();
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "ClusterTrustBundle",
            "metadata": {"name": "v1-bundle", "labels": {"k": "v"}},
            "spec": {"trustBundle": valid_cert_pem()}
        });
        let resp = create_cluster_trust_bundle(
            State(state.clone()),
            Path("v1".to_string()),
            Query(CreateQuery::default()),
            Extension(test_user()),
            json_headers(),
            Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("v1 create must succeed, got status {}", e.0));
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[test]
    fn validate_cluster_trust_bundle_generate_name_must_carry_signer_prefix_so_random_suffix_cannot_squat_another_signers_namespace(
    ) {
        let body = |generate: &str| {
            serde_json::json!({
                "metadata": {"generateName": generate},
                "spec": {"signerName": "a.com/s", "trustBundle": valid_cert_pem()}
            })
        };
        let err = validate_cluster_trust_bundle_spec(&body("b.com:s:"))
            .expect_err("generateName outside the signer's prefix must be rejected");
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            err.1.message.contains("generateName"),
            "got {}",
            err.1.message
        );
        validate_cluster_trust_bundle_spec(&body("a.com:s:"))
            .unwrap_or_else(|e| panic!("correct prefix must be accepted, got {}", e.1.message));

        let signerless = serde_json::json!({
            "metadata": {"generateName": "x:"},
            "spec": {"trustBundle": valid_cert_pem()}
        });
        validate_cluster_trust_bundle_spec(&signerless)
            .expect_err("signer-less bundle may not use ':' in generateName");
    }

    const OLD_SIGNER: &str = "a.com/s";
    const OLD_NAME: &str = "a.com:s:x:y";

    fn ctb_full(signer: &str, bundle: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "ClusterTrustBundle",
            "metadata": {"name": OLD_NAME},
            "spec": {"signerName": signer, "trustBundle": bundle}
        })
    }

    async fn seeded_ctb_state() -> crate::state::AppState {
        let state = make_state();
        create_cluster_trust_bundle(
            State(state.clone()),
            Path("v1".to_string()),
            Query(CreateQuery::default()),
            Extension(test_user()),
            json_headers(),
            Bytes::from(serde_json::to_vec(&ctb_full(OLD_SIGNER, &valid_cert_pem())).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("seed create must succeed, got {}", e.0));
        state
    }

    /// Returns the (status, message) of one update attempt, `mode` naming the write path.
    async fn update_ctb(
        state: &crate::state::AppState,
        mode: &str,
        signer: &str,
        bundle: &str,
    ) -> (StatusCode, String) {
        let path = Path((
            GROUP.to_string(),
            "v1".to_string(),
            CTB_PLURAL.to_string(),
            OLD_NAME.to_string(),
        ));
        let full = serde_json::to_vec(&ctb_full(signer, bundle)).unwrap();
        let partial = serde_json::to_vec(
            &serde_json::json!({"spec": {"signerName": signer, "trustBundle": bundle}}),
        )
        .unwrap();
        let json_patch = serde_json::to_vec(&serde_json::json!([
            {"op": "replace", "path": "/spec/signerName", "value": signer},
            {"op": "replace", "path": "/spec/trustBundle", "value": bundle},
        ]))
        .unwrap();
        let mut headers = HeaderMap::new();
        let content_type = match mode {
            "put" => "application/json",
            "merge" => "application/merge-patch+json",
            "smp" => "application/strategic-merge-patch+json",
            "json-patch" => "application/json-patch+json",
            "apply" => "application/apply-patch+yaml",
            _ => unreachable!(),
        };
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        let result = match mode {
            "put" => super::super::resource::replace_resource(
                State(state.clone()),
                path,
                Query(super::super::json_patch::ReplaceQuery::default()),
                Extension(test_user()),
                headers,
                Bytes::from(full),
            )
            .await
            .map(IntoResponse::into_response),
            _ => super::super::resource::patch_resource(
                State(state.clone()),
                path,
                Query(PatchQuery::default()),
                Extension(test_user()),
                headers,
                Bytes::from(match mode {
                    "json-patch" => json_patch,
                    "apply" => full,
                    _ => partial,
                }),
            )
            .await
            .map(IntoResponse::into_response),
        };
        match result {
            Ok(resp) => (resp.status(), String::new()),
            Err(e) => (e.0, e.1.message),
        }
    }

    /// Every write path must run the same name/signer, signer-immutability and PEM checks.
    /// A path that skips them lets a client re-home a bundle under another signer's name
    /// (or plant an unparseable bundle) that kubelets then mount into pods as a trust root.
    #[tokio::test]
    async fn clustertrustbundle_every_update_path_enforces_signer_immutability_name_prefix_and_pem_because_a_single_unguarded_path_defeats_them_all(
    ) {
        let state = seeded_ctb_state().await;
        let mut guarded = 0;
        let mut total = 0;
        for mode in ["put", "merge", "smp", "json-patch", "apply"] {
            // Name still matches the new signer's prefix, so only immutability can reject it.
            let cases = [
                (
                    "signerName change",
                    "a.com/s:x",
                    valid_cert_pem(),
                    "immutable",
                ),
                (
                    "name/signer mismatch",
                    "b.com/s",
                    valid_cert_pem(),
                    "must be named with prefix",
                ),
                (
                    "invalid PEM",
                    OLD_SIGNER,
                    "garbage".to_string(),
                    "trustBundle",
                ),
            ];
            for (label, signer, bundle, expect) in cases {
                total += 1;
                let (status, message) = update_ctb(&state, mode, signer, &bundle).await;
                if status == StatusCode::UNPROCESSABLE_ENTITY && message.contains(expect) {
                    guarded += 1;
                } else {
                    eprintln!("UNGUARDED {mode} / {label}: {status} {message:?}");
                }
            }
        }
        eprintln!("sites: {guarded}/{total} guarded");
        assert_eq!(
            guarded, total,
            "every update path must reject all three violations"
        );

        let (status, message) = update_ctb(&state, "merge", OLD_SIGNER, &valid_cert_pem()).await;
        assert!(
            status.is_success(),
            "a legitimate no-op update must still succeed, got {status} {message}"
        );
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
            Path(("v1beta1".to_string(), "default".to_string())),
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

    // -----------------------------------------------------------------------
    // PodCertificateRequest: guard matrix
    // -----------------------------------------------------------------------

    const PCR_NAME: &str = "req-1";

    fn pcr_object(version: &str, name: &str, spec: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": format!("certificates.k8s.io/{version}"),
            "kind": "PodCertificateRequest",
            "metadata": {"name": name, "namespace": "default"},
            "spec": spec
        })
    }

    fn outcome(result: Result<Response, crate::status::StatusError>) -> (StatusCode, String) {
        match result {
            Ok(resp) => (resp.status(), String::new()),
            Err(e) => (e.0, e.1.message),
        }
    }

    fn content_type_for(mode: &str) -> &'static str {
        match mode {
            "post" | "put" | "put-create" => "application/json",
            "merge" => "application/merge-patch+json",
            "smp" => "application/strategic-merge-patch+json",
            "json-patch" => "application/json-patch+json",
            "apply" | "apply-create" => "application/apply-patch+yaml",
            _ => unreachable!(),
        }
    }

    fn headers_for(mode: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(content_type_for(mode)),
        );
        headers
    }

    const UPDATE_MODES: [&str; 5] = ["put", "merge", "smp", "json-patch", "apply"];

    async fn create_pcr_as(
        state: &crate::state::AppState,
        user: UserInfo,
        version: &str,
        spec: serde_json::Value,
    ) -> (StatusCode, String) {
        outcome(
            create_pod_certificate_request(
                State(state.clone()),
                Path((version.to_string(), "default".to_string())),
                Query(CreateQuery::default()),
                Extension(user),
                json_headers(),
                Bytes::from(serde_json::to_vec(&pcr_object(version, PCR_NAME, spec)).unwrap()),
            )
            .await,
        )
    }

    /// Seeds a v1 PodCertificateRequest whose spec allows a 24h certificate and returns the
    /// key its stub CSR was made for.
    async fn seeded_pcr_state() -> (crate::state::AppState, rcgen::KeyPair) {
        let state = make_state();
        let (key, csr) = stub_csr();
        let mut spec = pcr_spec(&csr);
        spec["maxExpirationSeconds"] = 86400.into();
        let (status, message) = create_pcr_as(&state, test_user(), "v1", spec).await;
        assert!(
            status.is_success(),
            "seed create failed: {status} {message}"
        );
        (state, key)
    }

    async fn stored_pcr(state: &crate::state::AppState) -> serde_json::Value {
        let key =
            format!("/registry/certificates.k8s.io/podcertificaterequests/default/{PCR_NAME}");
        let stored = state.store.get(&key).await.unwrap().expect("must exist");
        serde_json::from_slice(&stored.value).unwrap()
    }

    /// One write against the main (non-status) endpoint. `full` is the complete object
    /// (PUT / apply), `partial` the merge body, `ops` the JSON Patch document.
    async fn send_main(
        state: &crate::state::AppState,
        mode: &str,
        name: &str,
        full: &serde_json::Value,
        partial: &serde_json::Value,
        ops: &serde_json::Value,
    ) -> (StatusCode, String) {
        let path = Path((
            GROUP.to_string(),
            "v1".to_string(),
            "default".to_string(),
            PCR_PLURAL.to_string(),
            name.to_string(),
        ));
        let bytes = |v: &serde_json::Value| Bytes::from(serde_json::to_vec(v).unwrap());
        match mode {
            "post" => outcome(
                create_pod_certificate_request(
                    State(state.clone()),
                    Path(("v1".to_string(), "default".to_string())),
                    Query(CreateQuery::default()),
                    Extension(test_user()),
                    headers_for(mode),
                    bytes(full),
                )
                .await,
            ),
            "put" | "put-create" => outcome(
                super::super::resource::replace_namespaced_resource(
                    State(state.clone()),
                    path,
                    Query(super::super::json_patch::ReplaceQuery::default()),
                    Extension(test_user()),
                    headers_for(mode),
                    bytes(full),
                )
                .await
                .map(IntoResponse::into_response),
            ),
            _ => outcome(
                super::super::resource::patch_namespaced_resource(
                    State(state.clone()),
                    path,
                    Query(PatchQuery::default()),
                    Extension(test_user()),
                    headers_for(mode),
                    match mode {
                        "json-patch" => bytes(ops),
                        "apply" | "apply-create" => bytes(full),
                        _ => bytes(partial),
                    },
                )
                .await
                .map(IntoResponse::into_response),
            ),
        }
    }

    /// A create carrying a nonsense identity must be refused on every route that can create:
    /// POST, PUT-on-missing and apply-on-missing. The spec names the pod/node/SA a signer
    /// binds a certificate to, so one unvalidated create route would let a client mint
    /// requests for an identity that cannot exist.
    #[tokio::test]
    async fn podcertificaterequest_every_create_path_validates_spec_because_a_signer_trusts_its_identity_fields(
    ) {
        let mut guarded = 0;
        let mut total = 0;
        for mode in ["post", "put-create", "apply-create"] {
            let state = make_state();
            for (label, field, bad) in [
                ("signerName without domain", "signerName", "nodomain"),
                ("podName not a DNS name", "podName", "Bad_Pod"),
                ("nodeName not a DNS name", "nodeName", "Node 1"),
                ("stub CSR not DER", "stubPKCS10Request", "AAAA"),
            ] {
                total += 1;
                let mut spec = valid_pcr_spec();
                spec[field] = bad.into();
                let full = pcr_object("v1", "req-new", spec);
                let (status, message) = send_main(
                    &state,
                    mode,
                    "req-new",
                    &full,
                    &serde_json::Value::Null,
                    &serde_json::Value::Null,
                )
                .await;
                if status == StatusCode::UNPROCESSABLE_ENTITY && message.contains(field) {
                    guarded += 1;
                } else {
                    eprintln!("UNGUARDED {mode} / {label}: {status} {message:?}");
                }
            }
        }
        eprintln!("sites: {guarded}/{total} guarded");
        assert_eq!(guarded, total, "every create path must validate the spec");
    }

    /// After create, no non-status write may change spec (a signer may have issued against
    /// it), validation still applies to whatever a patch produces, and a status smuggled into
    /// the main endpoint must be discarded — status belongs to the signer via `/status`.
    #[tokio::test]
    async fn podcertificaterequest_every_update_path_keeps_spec_immutable_validated_and_status_out_of_reach(
    ) {
        let mut guarded = 0;
        let mut total = 0;
        for mode in UPDATE_MODES {
            let (state, _key) = seeded_pcr_state().await;
            let seeded = stored_pcr(&state).await;
            let spec = seeded["spec"].clone();

            let with_spec = |field: &str, value: &str| {
                let mut s = spec.clone();
                s[field] = value.into();
                s
            };
            let cases = [
                ("podName change", "podName", "other-pod", "immutable"),
                ("nodeName change", "nodeName", "node-2", "immutable"),
                ("invalid signerName", "signerName", "nodomain", "signerName"),
            ];
            for (label, field, value, expect) in cases {
                total += 1;
                let new_spec = with_spec(field, value);
                let full = pcr_object("v1", PCR_NAME, new_spec.clone());
                let partial = serde_json::json!({"spec": {field: value}});
                let ops = serde_json::json!([
                    {"op": "replace", "path": format!("/spec/{field}"), "value": value}
                ]);
                let (status, message) =
                    send_main(&state, mode, PCR_NAME, &full, &partial, &ops).await;
                if status == StatusCode::UNPROCESSABLE_ENTITY && message.contains(expect) {
                    guarded += 1;
                } else {
                    eprintln!("UNGUARDED {mode} / {label}: {status} {message:?}");
                }
            }

            total += 1;
            let forged = serde_json::json!({"certificateChain": "FORGED"});
            let mut full = pcr_object("v1", PCR_NAME, spec.clone());
            full["status"] = forged.clone();
            let partial = serde_json::json!({"status": forged});
            let ops = serde_json::json!([{"op": "add", "path": "/status", "value": forged}]);
            let (status, message) = send_main(&state, mode, PCR_NAME, &full, &partial, &ops).await;
            let after = stored_pcr(&state).await;
            let status_untouched = after["status"].is_null()
                || after["status"]
                    .as_object()
                    .is_some_and(|m| !m.contains_key("certificateChain"));
            if status_untouched && after["spec"] == spec {
                guarded += 1;
            } else {
                eprintln!("UNGUARDED {mode} / status smuggle: {status} {message:?}");
            }

            let labels = serde_json::json!({"metadata": {"labels": {"a": "b"}}});
            let mut relabel = pcr_object("v1", PCR_NAME, spec.clone());
            relabel["metadata"]["labels"] = serde_json::json!({"a": "b"});
            let ops = serde_json::json!([
                {"op": "add", "path": "/metadata/labels", "value": {"a": "b"}}
            ]);
            let (status, message) =
                send_main(&state, mode, PCR_NAME, &relabel, &labels, &ops).await;
            assert!(
                status.is_success(),
                "{mode}: a metadata-only update must still work (conformance updates labels), got {status} {message}"
            );
        }
        eprintln!("sites: {guarded}/{total} guarded");
        assert_eq!(
            guarded, total,
            "every update path must enforce spec immutability, validation and status isolation"
        );
    }

    /// Kubelet copies an unset pod-level `maxExpirationSeconds` straight into the request, so
    /// the apiserver must default it to 24h; rejecting it leaves the pod's volume (and the pod)
    /// stuck forever.
    #[tokio::test]
    async fn podcertificaterequest_create_without_max_expiration_defaults_to_24h_because_kubelet_forwards_the_unset_pod_value(
    ) {
        let state = make_state();
        let mut spec = valid_pcr_spec();
        spec.as_object_mut().unwrap().remove("maxExpirationSeconds");
        let (status, message) = create_pcr_as(&state, test_user(), "v1", spec).await;
        assert!(status.is_success(), "got {status} {message}");
        assert_eq!(
            stored_pcr(&state).await["spec"]["maxExpirationSeconds"],
            86400
        );
    }

    fn signer_user() -> UserInfo {
        UserInfo {
            username: "signer".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        }
    }

    fn grant_sign(state: &crate::state::AppState, resource_name: &str) {
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/signer",
            &serde_json::json!({"rules": [{
                "apiGroups": ["certificates.k8s.io"],
                "resources": ["signers"],
                "resourceNames": [resource_name],
                "verbs": ["sign"]
            }]}),
        );
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/signer",
            &serde_json::json!({
                "subjects": [{"kind": "User", "name": "signer"}],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "signer"
                }
            }),
        );
    }

    fn denied_status() -> serde_json::Value {
        serde_json::json!({"conditions": [{
            "type": "Denied", "status": "True", "reason": "Nope", "message": "no",
            "lastTransitionTime": "2026-01-01T00:00:00Z"
        }]})
    }

    async fn send_status(
        state: &crate::state::AppState,
        user: UserInfo,
        mode: &str,
        body: &serde_json::Value,
    ) -> (StatusCode, String) {
        let path = Path((
            "v1".to_string(),
            "default".to_string(),
            PCR_NAME.to_string(),
        ));
        let status = body["status"].clone();
        let bytes = Bytes::from(match mode {
            "json-patch" => serde_json::to_vec(
                &serde_json::json!([{"op": "add", "path": "/status", "value": status}]),
            )
            .unwrap(),
            _ => serde_json::to_vec(body).unwrap(),
        });
        outcome(if mode == "put" {
            put_pod_certificate_request_status(
                State(state.clone()),
                path,
                Extension(user),
                headers_for(mode),
                bytes,
            )
            .await
        } else {
            patch_pod_certificate_request_status(
                State(state.clone()),
                path,
                Extension(user),
                headers_for(mode),
                bytes,
            )
            .await
        })
    }

    /// Every `/status` route must run the same guard: nobody but an authorized signer may
    /// write status, issued/denied status is final, the write cannot smuggle a spec or
    /// annotation change, and an `Issued` status must pass certificate checks. A route that
    /// skips any of these lets a caller with only `podcertificaterequests/status` mint or
    /// rewrite a pod's credential.
    #[tokio::test]
    async fn podcertificaterequest_every_status_path_enforces_sign_permission_finality_and_certificate_checks(
    ) {
        let mut guarded = 0;
        let mut total = 0;
        for mode in UPDATE_MODES {
            let (state, _key) = seeded_pcr_state().await;
            let seeded = stored_pcr(&state).await;
            let body = |status: serde_json::Value| {
                let mut b = pcr_object("v1", PCR_NAME, seeded["spec"].clone());
                b["status"] = status;
                b
            };

            total += 1;
            let (status, message) =
                send_status(&state, test_user(), mode, &body(denied_status())).await;
            if status == StatusCode::FORBIDDEN && message.contains("sign") {
                guarded += 1;
            } else {
                eprintln!("UNGUARDED {mode} / write without sign permission: {status} {message:?}");
            }
            assert!(
                stored_pcr(&state).await["status"].is_null(),
                "{mode}: a rejected status write must not persist anything"
            );

            grant_sign(&state, "example.com/other-signer");
            total += 1;
            let (status, message) =
                send_status(&state, signer_user(), mode, &body(denied_status())).await;
            if status == StatusCode::FORBIDDEN {
                guarded += 1;
            } else {
                eprintln!("UNGUARDED {mode} / sign on a different signer: {status} {message:?}");
            }

            grant_sign(&state, "example.com/signer");
            total += 1;
            let mut smuggled = body(serde_json::json!({}));
            smuggled["metadata"]["annotations"] = serde_json::json!({"x": "y"});
            smuggled["spec"]["podName"] = "other-pod".into();
            let (status, message) = send_status(&state, signer_user(), mode, &smuggled).await;
            let after = stored_pcr(&state).await;
            if after["spec"] == seeded["spec"]
                && (status == StatusCode::UNPROCESSABLE_ENTITY
                    || after["metadata"]["annotations"].is_null())
            {
                guarded += 1;
            } else {
                eprintln!("UNGUARDED {mode} / spec+annotation smuggle: {status} {message:?}");
            }

            total += 1;
            let mut issued = serde_json::json!({"conditions": [{
                "type": "Issued", "status": "True", "reason": "Ok",
                "lastTransitionTime": "2020-01-01T00:00:00Z"
            }], "certificateChain": "not a certificate"});
            issued["notBefore"] = "2020-01-01T00:00:00Z".into();
            let (status, message) = send_status(&state, signer_user(), mode, &body(issued)).await;
            if status == StatusCode::UNPROCESSABLE_ENTITY && message.contains("certificateChain") {
                guarded += 1;
            } else {
                eprintln!("UNGUARDED {mode} / issued with garbage chain: {status} {message:?}");
            }

            total += 1;
            let (status, message) =
                send_status(&state, signer_user(), mode, &body(denied_status())).await;
            assert!(
                status.is_success(),
                "{mode}: an authorized signer denying a request must succeed, got {status} {message}"
            );
            let mut changed = denied_status();
            changed["conditions"][0]["reason"] = "Changed".into();
            let (status, message) = send_status(&state, signer_user(), mode, &body(changed)).await;
            if status == StatusCode::UNPROCESSABLE_ENTITY && message.contains("immutable") {
                guarded += 1;
            } else {
                eprintln!("UNGUARDED {mode} / rewrite after terminal: {status} {message:?}");
            }
        }
        eprintln!("sites: {guarded}/{total} guarded");
        assert_eq!(guarded, total, "every /status path must run the full guard");
    }

    // -----------------------------------------------------------------------
    // PodCertificateRequest: status validation (pure)
    // -----------------------------------------------------------------------

    const T0: &str = "2020-01-01T00:00:00Z";

    fn t0_secs() -> i64 {
        crate::util::rfc3339_to_unix_secs(T0).unwrap()
    }

    fn leaf_pem(key: &rcgen::KeyPair) -> String {
        let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2020, 1, 2);
        params.self_signed(key).unwrap().pem()
    }

    fn issued_status(chain: &str) -> serde_json::Value {
        serde_json::json!({
            "certificateChain": chain,
            "notBefore": T0,
            "notAfter": "2020-01-02T00:00:00Z",
            "beginRefreshAt": "2020-01-01T00:15:00Z",
            "conditions": [{
                "type": "Issued", "status": "True", "reason": "Ok",
                "lastTransitionTime": T0
            }]
        })
    }

    fn pcr_with_status(
        key_csr: &str,
        max: i64,
        status: serde_json::Value,
    ) -> (serde_json::Value, serde_json::Value) {
        let mut spec = pcr_spec(key_csr);
        spec["maxExpirationSeconds"] = max.into();
        let old = pcr_object("v1", PCR_NAME, spec);
        let mut new = old.clone();
        new["status"] = status;
        (old, new)
    }

    #[test]
    fn status_update_accepts_a_certificate_issued_to_the_requested_key() {
        let (key, csr) = stub_csr();
        let (old, new) = pcr_with_status(&csr, 86400, issued_status(&leaf_pem(&key)));
        if let Err(e) = validate_pod_certificate_request_status_update(&old, &new, t0_secs() + 60) {
            panic!("a correctly issued certificate must be accepted, got: {e}");
        }
    }

    #[test]
    fn status_update_rejects_a_certificate_for_someone_elses_key_because_the_pod_would_hold_a_credential_it_cannot_use_or_an_attacker_could_use(
    ) {
        let (_key, csr) = stub_csr();
        let other = rcgen::KeyPair::generate().unwrap();
        let (old, new) = pcr_with_status(&csr, 86400, issued_status(&leaf_pem(&other)));
        let err = validate_pod_certificate_request_status_update(&old, &new, t0_secs() + 60)
            .expect_err("leaf for a different public key must be rejected");
        assert!(err.contains("requested public key"), "got: {err}");
    }

    #[test]
    fn status_update_enforces_certificate_timing_rules() {
        let (key, csr) = stub_csr();
        let pem = leaf_pem(&key);
        let now = t0_secs() + 60;
        let cases: [(&str, i64, &str, &str, &str); 5] = [
            (
                "clock skew beyond 5 minutes",
                86400,
                "notBefore",
                T0,
                "5 minutes",
            ),
            (
                "lifetime above maxExpirationSeconds",
                3600,
                "notBefore",
                T0,
                "spec.maxExpirationSeconds",
            ),
            (
                "notAfter not the leaf's",
                86400,
                "notAfter",
                "2020-01-03T00:00:00Z",
                "NotAfter",
            ),
            (
                "refresh too early",
                86400,
                "beginRefreshAt",
                "2020-01-01T00:05:00Z",
                "10 minutes after",
            ),
            (
                "refresh too late",
                86400,
                "beginRefreshAt",
                "2020-01-01T23:55:00Z",
                "10 minutes before",
            ),
        ];
        for (label, max, field, value, expect) in cases {
            let mut status = issued_status(&pem);
            status[field] = value.into();
            let skew_now = if label.starts_with("clock") {
                now + 3600
            } else {
                now
            };
            let (old, new) = pcr_with_status(&csr, max, status);
            let err = validate_pod_certificate_request_status_update(&old, &new, skew_now)
                .expect_err(label);
            assert!(err.contains(expect), "{label}: got {err}");
        }

        let mut status = issued_status(&pem);
        status.as_object_mut().unwrap().remove("beginRefreshAt");
        let (old, new) = pcr_with_status(&csr, 86400, status);
        assert!(
            validate_pod_certificate_request_status_update(&old, &new, now).is_err(),
            "an issued status without beginRefreshAt would leave kubelet with no rotation time"
        );
    }

    #[test]
    fn status_update_terminal_conditions_are_final_and_denials_carry_no_certificate() {
        let (key, csr) = stub_csr();
        let (old, mut issued) = pcr_with_status(&csr, 86400, issued_status(&leaf_pem(&key)));
        let now = t0_secs() + 60;

        let mut stored_issued = old.clone();
        stored_issued["status"] = issued["status"].clone();
        issued["status"]["certificateChain"] = "rewritten".into();
        assert!(
            validate_pod_certificate_request_status_update(&stored_issued, &issued, now).is_err(),
            "an issued certificate must never be replaceable"
        );
        assert!(
            validate_pod_certificate_request_status_update(&stored_issued, &stored_issued, now)
                .is_ok(),
            "rewriting identical status (e.g. a retried signer write) must stay idempotent"
        );

        let mut denied_with_cert = old.clone();
        denied_with_cert["status"] = denied_status();
        denied_with_cert["status"]["certificateChain"] = "x".into();
        assert!(
            validate_pod_certificate_request_status_update(&old, &denied_with_cert, now).is_err(),
            "a denied request must not also carry a certificate"
        );

        for (label, cond) in [
            (
                "unknown type",
                serde_json::json!({"type": "Approved", "status": "True", "reason": "Ok", "lastTransitionTime": T0}),
            ),
            (
                "status False",
                serde_json::json!({"type": "Denied", "status": "False", "reason": "Ok", "lastTransitionTime": T0}),
            ),
            (
                "missing reason",
                serde_json::json!({"type": "Denied", "status": "True", "lastTransitionTime": T0}),
            ),
            (
                "missing transition time",
                serde_json::json!({"type": "Denied", "status": "True", "reason": "Ok"}),
            ),
        ] {
            let mut bad = old.clone();
            bad["status"] = serde_json::json!({"conditions": [cond]});
            assert!(
                validate_pod_certificate_request_status_update(&old, &bad, now).is_err(),
                "{label} must be rejected"
            );
        }
        let mut two = old.clone();
        let c = denied_status()["conditions"][0].clone();
        two["status"] = serde_json::json!({"conditions": [c.clone(), c]});
        assert!(
            validate_pod_certificate_request_status_update(&old, &two, now).is_err(),
            "at most one terminal condition may be set"
        );
    }

    #[test]
    fn status_update_cannot_touch_spec_or_metadata() {
        let (_key, csr) = stub_csr();
        let (old, mut new) = pcr_with_status(&csr, 86400, denied_status());
        new["spec"]["podName"] = "other".into();
        assert!(validate_pod_certificate_request_status_update(&old, &new, 0).is_err());
        let (old, mut new) = pcr_with_status(&csr, 86400, denied_status());
        new["metadata"]["annotations"] = serde_json::json!({"a": "b"});
        assert!(validate_pod_certificate_request_status_update(&old, &new, 0).is_err());
        let (old, mut new) = pcr_with_status(&csr, 86400, denied_status());
        new["metadata"]["managedFields"] = serde_json::json!([]);
        assert!(
            validate_pod_certificate_request_status_update(&old, &new, 0).is_ok(),
            "managedFields bookkeeping must stay writable"
        );
    }

    #[test]
    fn sign_permission_accepts_domain_wildcard_like_upstream() {
        let state = make_state();
        grant_sign(&state, "example.com/*");
        assert!(user_may_sign(
            &state,
            &signer_user(),
            "example.com/anything"
        ));
        assert!(!user_may_sign(&state, &signer_user(), "other.com/anything"));
        assert!(!user_may_sign(&state, &test_user(), "example.com/anything"));
    }

    // -----------------------------------------------------------------------
    // PodCertificateRequest: spec validation details
    // -----------------------------------------------------------------------

    fn spec_error(spec: serde_json::Value, api_version: &str) -> Option<String> {
        let body = serde_json::json!({"apiVersion": api_version, "spec": spec});
        validate_pod_certificate_request_spec(&body)
            .err()
            .map(|e| e.1.message)
    }

    #[test]
    fn spec_validation_rejects_malformed_identity_and_annotation_fields() {
        let mut over_long = valid_pcr_spec();
        over_long["podUID"] = "x".repeat(129).into();
        let mut bad_annotation = valid_pcr_spec();
        bad_annotation["unverifiedUserAnnotations"] = serde_json::json!({"no-slash": "v"});
        let mut good_annotation = valid_pcr_spec();
        good_annotation["unverifiedUserAnnotations"] =
            serde_json::json!({"Example.com/Path": "/custom"});
        let mut bad_signer = valid_pcr_spec();
        bad_signer["signerName"] = "a.com/b/c".into();
        let mut short_domain = valid_pcr_spec();
        short_domain["signerName"] = "localhost/x".into();

        assert!(spec_error(over_long, "certificates.k8s.io/v1")
            .unwrap()
            .contains("podUID"));
        assert!(spec_error(bad_annotation, "certificates.k8s.io/v1")
            .unwrap()
            .contains("unverifiedUserAnnotations"));
        assert!(
            spec_error(good_annotation, "certificates.k8s.io/v1").is_none(),
            "SPIFFE-style user annotations are what the projected-volume feature sends"
        );
        assert!(spec_error(bad_signer, "certificates.k8s.io/v1").is_some());
        assert!(spec_error(short_domain, "certificates.k8s.io/v1").is_some());
    }

    #[test]
    fn spec_validation_requires_exactly_one_supported_key_source() {
        use base64::Engine as _;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let v1 = "certificates.k8s.io/v1";
        let beta = "certificates.k8s.io/v1beta1";
        let (key, csr) = stub_csr();
        let pkix = b64(&rcgen::PublicKeyData::subject_public_key_info(&key));

        let mut none = valid_pcr_spec();
        none.as_object_mut().unwrap().remove("stubPKCS10Request");
        assert!(spec_error(none, v1).unwrap().contains("exactly one"));

        let mut both = pcr_spec(&csr);
        both["pkixPublicKey"] = pkix.clone().into();
        both["proofOfPossession"] = b64(b"sig").into();
        assert!(spec_error(both, beta).unwrap().contains("exactly one"));

        let mut pkix_only = valid_pcr_spec();
        pkix_only
            .as_object_mut()
            .unwrap()
            .remove("stubPKCS10Request");
        pkix_only["pkixPublicKey"] = pkix.clone().into();
        assert!(
            spec_error(pkix_only, beta).unwrap().contains("exactly one"),
            "pkixPublicKey without proofOfPossession proves nothing about key ownership"
        );

        let mut beta_pair = valid_pcr_spec();
        beta_pair
            .as_object_mut()
            .unwrap()
            .remove("stubPKCS10Request");
        beta_pair["pkixPublicKey"] = pkix.clone().into();
        beta_pair["proofOfPossession"] = b64(b"sig").into();
        assert!(spec_error(beta_pair.clone(), beta).is_none());
        assert!(
            spec_error(beta_pair, v1).unwrap().contains("v1"),
            "v1 dropped pkixPublicKey; accepting it would store a field the version does not define"
        );

        let mut garbage = valid_pcr_spec();
        garbage["stubPKCS10Request"] = b64(b"not der").into();
        assert!(spec_error(garbage, v1).unwrap().contains("PKCS#10"));

        let mut not_b64 = valid_pcr_spec();
        not_b64["stubPKCS10Request"] = "%%%".into();
        assert!(spec_error(not_b64, v1).unwrap().contains("base64"));

        let mut huge = valid_pcr_spec();
        huge["stubPKCS10Request"] = b64(&vec![0u8; MAX_KEY_MATERIAL_SIZE + 1]).into();
        assert!(spec_error(huge, v1).unwrap().contains("Too long"));
    }

    #[test]
    fn spec_validation_accepts_ed25519_and_p384_but_not_unknown_curves() {
        use base64::Engine as _;
        for alg in [&rcgen::PKCS_ED25519, &rcgen::PKCS_ECDSA_P384_SHA384] {
            let key = rcgen::KeyPair::generate_for(alg).unwrap();
            let csr = rcgen::CertificateParams::default()
                .serialize_request(&key)
                .unwrap();
            let spec = pcr_spec(&base64::engine::general_purpose::STANDARD.encode(csr.der()));
            assert_eq!(spec_error(spec, "certificates.k8s.io/v1"), None);
        }
    }

    // -----------------------------------------------------------------------
    // PodCertificateRequest: NodeRestriction
    // -----------------------------------------------------------------------

    fn node_user(name: &str) -> UserInfo {
        UserInfo {
            username: format!("system:node:{name}"),
            uid: String::new(),
            groups: vec!["system:nodes".into()],
            extra: Default::default(),
        }
    }

    async fn put_raw(state: &crate::state::AppState, key: &str, v: serde_json::Value) {
        state
            .store
            .put(
                key,
                bytes::Bytes::from(serde_json::to_vec(&v).unwrap()),
                Some(0),
            )
            .await
            .unwrap();
    }

    /// Node `node-1` (uid node-uid-1) running pod `my-pod` (uid pod-uid-1) that uses service
    /// account `default` (uid sa-uid-1) and mounts a podCertificate volume for the signer.
    async fn node_restriction_state(pod_overrides: serde_json::Value) -> crate::state::AppState {
        let state = make_state();
        put_raw(
            &state,
            "/registry/nodes/node-1",
            serde_json::json!({"metadata": {"name": "node-1", "uid": "node-uid-1"}}),
        )
        .await;
        put_raw(
            &state,
            "/registry/serviceaccounts/default/default",
            serde_json::json!({"metadata": {"name": "default", "uid": "sa-uid-1"}}),
        )
        .await;
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod", "namespace": "default", "uid": "pod-uid-1"},
            "spec": {
                "nodeName": "node-1",
                "serviceAccountName": "default",
                "volumes": [{"name": "creds", "projected": {"sources": [{"podCertificate": {"signerName": "example.com/signer"}}]}}]
            }
        });
        crate::patch::merge_patch(&mut pod, &pod_overrides);
        put_raw(&state, "/registry/pods/default/my-pod", pod).await;
        state
    }

    /// A kubelet may only obtain certificates for pods actually bound to it. Each case here
    /// is an identity a compromised node could otherwise claim for a pod it does not run.
    #[tokio::test]
    async fn podcertificaterequest_create_by_a_node_is_restricted_to_its_own_pods_because_a_compromised_kubelet_must_not_obtain_another_pods_identity(
    ) {
        let ok_state = node_restriction_state(serde_json::json!({})).await;
        let (status, message) =
            create_pcr_as(&ok_state, node_user("node-1"), "v1", valid_pcr_spec()).await;
        assert!(
            status.is_success(),
            "the node's own pod must be allowed: {status} {message}"
        );

        let cases: [(&str, &str, serde_json::Value, &str, &str, StatusCode); 7] = [
            (
                "another node's request",
                "node-2",
                serde_json::json!({}),
                "",
                "",
                StatusCode::FORBIDDEN,
            ),
            (
                "pod bound to another node",
                "node-1",
                serde_json::json!({"spec": {"nodeName": "node-2"}}),
                "",
                "",
                StatusCode::FORBIDDEN,
            ),
            (
                "pod UID mismatch",
                "node-1",
                serde_json::json!({"metadata": {"uid": "someone-else"}}),
                "",
                "",
                StatusCode::CONFLICT,
            ),
            (
                "service account name differs",
                "node-1",
                serde_json::json!({"spec": {"serviceAccountName": "other"}}),
                "",
                "",
                StatusCode::FORBIDDEN,
            ),
            (
                "mirror pod",
                "node-1",
                serde_json::json!({"metadata": {"annotations": {"kubernetes.io/config.mirror": "x"}}}),
                "",
                "",
                StatusCode::FORBIDDEN,
            ),
            (
                "signer not mounted",
                "node-1",
                serde_json::json!({"spec": {"volumes": []}}),
                "",
                "",
                StatusCode::FORBIDDEN,
            ),
            (
                "service account UID mismatch",
                "node-1",
                serde_json::json!({}),
                "serviceAccountUID",
                "forged-uid",
                StatusCode::CONFLICT,
            ),
        ];
        let mut guarded = 0;
        for (label, node, pod_override, field, value, want) in cases {
            let state = node_restriction_state(pod_override).await;
            let mut spec = valid_pcr_spec();
            if !field.is_empty() {
                spec[field] = value.into();
            }
            let (status, message) = create_pcr_as(&state, node_user(node), "v1", spec).await;
            if status == want {
                guarded += 1;
            } else {
                eprintln!("UNGUARDED {label}: {status} {message:?}");
            }
        }
        eprintln!("sites: {guarded}/{} guarded", 7);
        assert_eq!(guarded, 7);

        let state = node_restriction_state(serde_json::json!({})).await;
        let mut spec = valid_pcr_spec();
        spec["nodeUID"] = "forged".into();
        let (status, _) = create_pcr_as(&state, node_user("node-1"), "v1", spec).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "node UID must match the real node"
        );

        let (status, _) = create_pcr_as(&make_state(), test_user(), "v1", valid_pcr_spec()).await;
        assert!(
            status.is_success(),
            "non-node callers (controllers, tests) are not bound to pod placement"
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
