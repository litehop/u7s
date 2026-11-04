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
use serde::Deserialize;
use x509_cert::der::Decode as _;
use x509_cert::request::CertReq;

use u7s_store::{ListOptions, Store, StoreError};

use crate::{
    admission::{run_mutating_webhooks, run_validating_webhooks, AdmissionContext},
    auth::UserInfo,
    handlers::{
        field_selector::FieldSelector,
        generic::{
            apply_label_selector, build_list_response, decode_continue, generate_name, lookup,
            parse_label_selector, resolve_valid_name, stamp_metadata, validate_path_segment,
            wants_generate_name, CollectionQuery, MAX_GENERATE_NAME_CREATE_ATTEMPTS,
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

/// The single parser for `spec.request`. Go's `ParseCSR` (create-time validation, signer) takes
/// the FIRST PEM block, skips junk before it, ignores everything after it and accepts PEM
/// headers; any consumer here that read a different block or tolerated different bytes than
/// the signer would see another subject than the one that gets signed. So accept only exactly
/// one `CERTIFICATE REQUEST` block with nothing but whitespace around it, no headers, and
/// strict DER with no trailing bytes: input that passes here parses identically in Go.
pub(crate) fn parse_csr_pem(pem: &[u8]) -> Result<CertReq, String> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    let pem = pem.trim_ascii();
    if pem.windows(BEGIN.len()).filter(|w| *w == BEGIN).count() != 1 {
        return Err("request must contain exactly one PEM block".into());
    }
    if !pem.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----")
        || !pem.ends_with(b"-----END CERTIFICATE REQUEST-----")
    {
        return Err(
            "request must be a single CERTIFICATE REQUEST PEM block with no surrounding data"
                .into(),
        );
    }
    let (_, der) = x509_cert::der::pem::decode_vec(pem).map_err(|e| format!("invalid PEM: {e}"))?;
    CertReq::from_der(&der).map_err(|e| format!("invalid DER PKCS#10: {e}"))
}

const UNIMPLEMENTED: &str = "x509: cannot verify signature: algorithm unimplemented";

fn insecure(alg: &str) -> String {
    format!("x509: cannot verify signature: insecure algorithm {alg}")
}

/// Go's `CertificateRequest.CheckSignature`: verifies the PKCS#10 self-signature over the
/// request info with the embedded public key. Errors carry Go's text. ECDSA over P-224 is
/// not verifiable here although Go accepts it.
pub(crate) fn check_csr_signature(req: &CertReq) -> Result<(), String> {
    use aws_lc_rs::signature::{self as sig, VerificationAlgorithm};
    use x509_cert::der::Encode as _;

    const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    const ED25519: &str = "1.3.101.112";

    let sig_oid = req.algorithm.oid.to_string();
    let spki = &req.info.public_key;
    let key_oid = spki.algorithm.oid.to_string();

    match sig_oid.as_str() {
        "1.2.840.113549.1.1.5" => return Err(insecure("SHA1-RSA")),
        "1.2.840.10045.4.1" => return Err(insecure("ECDSA-SHA1")),
        "1.2.840.113549.1.1.4" => return Err(insecure("MD5-RSA")),
        _ => {}
    }
    if key_oid == RSA_ENCRYPTION {
        return check_rsa_signature(req, &sig_oid);
    }

    let (alg, err): (&'static dyn VerificationAlgorithm, &str) =
        match (key_oid.as_str(), sig_oid.as_str()) {
            (
                EC_PUBLIC_KEY,
                ecdsa_sig @ ("1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3" | "1.2.840.10045.4.3.4"),
            ) => {
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.decode_as::<x509_cert::der::asn1::ObjectIdentifier>().ok())
                    .map(|o| o.to_string())
                    .unwrap_or_default();
                let alg: &'static dyn VerificationAlgorithm = match (curve.as_str(), ecdsa_sig) {
                    ("1.2.840.10045.3.1.7", "1.2.840.10045.4.3.2") => &sig::ECDSA_P256_SHA256_ASN1,
                    ("1.2.840.10045.3.1.7", "1.2.840.10045.4.3.3") => &sig::ECDSA_P256_SHA384_ASN1,
                    ("1.2.840.10045.3.1.7", _) => &sig::ECDSA_P256_SHA512_ASN1,
                    ("1.3.132.0.34", "1.2.840.10045.4.3.2") => &sig::ECDSA_P384_SHA256_ASN1,
                    ("1.3.132.0.34", "1.2.840.10045.4.3.3") => &sig::ECDSA_P384_SHA384_ASN1,
                    ("1.3.132.0.34", _) => &sig::ECDSA_P384_SHA512_ASN1,
                    ("1.3.132.0.35", "1.2.840.10045.4.3.2") => &sig::ECDSA_P521_SHA256_ASN1,
                    ("1.3.132.0.35", "1.2.840.10045.4.3.3") => &sig::ECDSA_P521_SHA384_ASN1,
                    ("1.3.132.0.35", _) => &sig::ECDSA_P521_SHA512_ASN1,
                    _ => return Err(UNIMPLEMENTED.into()),
                };
                (alg, "x509: ECDSA verification failure")
            }
            (ED25519, ED25519) => (&sig::ED25519, "x509: Ed25519 verification failure"),
            _ => return Err(UNIMPLEMENTED.into()),
        };

    let message = req.info.to_der().map_err(|e| e.to_string())?;
    let (Some(key), Some(signature)) =
        (spki.subject_public_key.as_bytes(), req.signature.as_bytes())
    else {
        return Err(err.into());
    };
    sig::UnparsedPublicKey::new(alg, key)
        .verify(&message, signature)
        .map_err(|_| err.into())
}

#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: x509_cert::der::asn1::UintRef<'a>,
    exponent: x509_cert::der::asn1::UintRef<'a>,
}

#[derive(der::Sequence)]
struct PssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<x509_cert::spki::AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask_gen: Option<x509_cert::spki::AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    salt_len: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    trailer: Option<u32>,
}

const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
const SHA384_OID: &str = "2.16.840.1.101.3.4.2.2";
const SHA512_OID: &str = "2.16.840.1.101.3.4.2.3";
const MGF1_OID: &str = "1.2.840.113549.1.1.8";

/// Hash OID of an RSASSA-PSS parameter block Go would accept: SHA-2 with MGF1 over the same
/// hash, salt equal to the digest length (what aws-lc verifies) and the default trailer.
fn pss_hash_oid(req: &CertReq) -> Option<String> {
    let params = req
        .algorithm
        .parameters
        .as_ref()?
        .decode_as::<PssParams>()
        .ok()?;
    let hash = params.hash?.oid.to_string();
    let mgf = params.mask_gen?;
    let mgf_hash = mgf
        .parameters?
        .decode_as::<x509_cert::spki::AlgorithmIdentifierOwned>()
        .ok()?
        .oid
        .to_string();
    let digest_len = match hash.as_str() {
        SHA256_OID => 32,
        SHA384_OID => 48,
        SHA512_OID => 64,
        _ => return None,
    };
    (mgf.oid.to_string() == MGF1_OID
        && mgf_hash == hash
        && params.salt_len? == digest_len
        && matches!(params.trailer, None | Some(1)))
    .then_some(hash)
}

/// RSA is verified by aws-lc only, and only from 2048 bits for both PKCS#1 v1.5 and PSS: a
/// deliberate divergence from Go, which accepts 1024-bit keys.
fn check_rsa_signature(req: &CertReq, sig_oid: &str) -> Result<(), String> {
    use aws_lc_rs::signature::{self as sig, VerificationAlgorithm};
    use x509_cert::der::{Decode as _, Encode as _};

    let spki = &req.info.public_key;
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or("x509: failed to parse public key")?;
    let pk = RsaPublicKey::from_der(key).map_err(|_| "x509: failed to parse public key")?;
    let modulus = pk.modulus.as_bytes();
    let bits = modulus.len() * 8 - modulus.first().map_or(0, |b| b.leading_zeros() as usize);
    if bits < 2048 {
        return Err(format!(
            "crypto/rsa: {bits}-bit RSA keys are not accepted; minimum is 2048"
        ));
    }

    let alg: &'static dyn VerificationAlgorithm = match sig_oid {
        "1.2.840.113549.1.1.11" => &sig::RSA_PKCS1_2048_8192_SHA256,
        "1.2.840.113549.1.1.12" => &sig::RSA_PKCS1_2048_8192_SHA384,
        "1.2.840.113549.1.1.13" => &sig::RSA_PKCS1_2048_8192_SHA512,
        "1.2.840.113549.1.1.10" => match pss_hash_oid(req).as_deref() {
            Some(SHA256_OID) => &sig::RSA_PSS_2048_8192_SHA256,
            Some(SHA384_OID) => &sig::RSA_PSS_2048_8192_SHA384,
            Some(SHA512_OID) => &sig::RSA_PSS_2048_8192_SHA512,
            _ => return Err(UNIMPLEMENTED.into()),
        },
        _ => return Err(UNIMPLEMENTED.into()),
    };
    const VERIFY: &str = "crypto/rsa: verification error";
    let message = req.info.to_der().map_err(|e| e.to_string())?;
    let signature = req.signature.as_bytes().ok_or(VERIFY)?;
    sig::UnparsedPublicKey::new(alg, key)
        .verify(&message, signature)
        .map_err(|_| VERIFY.into())
}

/// Validate spec.request and spec.signerName, returning 422 on any violation.
///
/// Extracted as a pure function so it can be unit-tested without an HTTP stack.
pub(crate) fn validate_csr_spec(
    body: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    // Deserialize spec into a typed struct so field access is compiler-checked.
    let spec: CertificateSigningRequestSpec =
        CertificateSigningRequestSpec::deserialize(&body["spec"]).map_err(|e| {
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

    let req = parse_csr_pem(&pem_bytes).map_err(|e| {
        Status::unprocessable_entity(format!(
            "spec.request does not contain a valid PEM-encoded PKCS#10 CertificationRequest: {e}"
        ))
    })?;
    check_csr_signature(&req).map_err(|e| {
        let name = body["metadata"]["name"].as_str().unwrap_or_default();
        let cause = format!("Invalid value: {:?}: {e}", spec.request);
        let mut err = Status::unprocessable_entity(format!(
            "{KIND}.{GROUP} \"{name}\" is invalid: spec.request: {cause}"
        ));
        err.1.details = Some(Box::new(serde_json::json!({
            "name": name,
            "group": GROUP,
            "kind": KIND,
            "causes": [{"reason": "FieldValueInvalid", "message": cause, "field": "spec.request"}]
        })));
        err
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
    headers: HeaderMap,
) -> Result<Response, crate::status::StatusError> {
    // Lookup is infallible for the built-in CSR resource type.
    let meta = lookup(&state, GROUP, VERSION, PLURAL)?;
    let kind = meta.kind.clone();
    let prefix = group_list_prefix(GROUP, PLURAL, None);
    let field_selector = FieldSelector::parse(query.field_selector.as_deref(), GROUP, PLURAL)?;

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
                explicit_no_initial_events: query.send_initial_events == Some(false),
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
                field_selector: field_selector.store_selector(),
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
    let items = field_selector.filter(items);

    let items = if let Some(ref sel) = query.label_selector {
        let pairs = parse_label_selector(sel)?;
        apply_label_selector(items, &pairs)
    } else {
        items
    };

    let accept = accept_header(&headers);
    if super::table::wants_table(accept) {
        let continue_token = resp.continue_key.map(|key| {
            super::generic::encode_continue(&key, list_revision, &state.continue_token_key)
        });
        let built = super::table::build_table(GROUP, PLURAL, items);
        return Ok(Json(super::table::finalize_table(
            built,
            &super::table::table_api_version(accept),
            Some(&list_revision.to_string()),
            continue_token,
        ))
        .into_response());
    }

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

fn accept_header(headers: &HeaderMap) -> &str {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
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
    headers: HeaderMap,
) -> Result<Response, crate::status::StatusError> {
    validate_path_segment("name", &name)?;
    let key = group_object_key(GROUP, PLURAL, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(GROUP, PLURAL, &name))?;

    let accept = accept_header(&headers);
    if super::table::wants_table(accept) {
        let obj: serde_json::Value = serde_json::from_slice(&stored.value)
            .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;
        let built = super::table::build_table(GROUP, PLURAL, vec![obj]);
        return Ok(Json(super::table::finalize_table(
            built,
            &super::table::table_api_version(accept),
            Some(&stored.revision.to_string()),
            None,
        ))
        .into_response());
    }

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
    let body = extract_body(&body, content_type(&headers))?;
    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // Captured before resolve_name mutates metadata.name, so a store collision below
    // knows whether it's allowed to retry under a freshly generated name.
    let generate_name_prefix = wants_generate_name(&obj);
    let mut name = resolve_valid_name(
        &mut obj,
        "certificates.k8s.io",
        "certificatesigningrequests",
        "CertificateSigningRequest",
    )?;
    validate_csr_spec(&obj.body)?;
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
    finalize_csr_create(&state, &mut obj.body, &user).await?;
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;
    crate::field_manager::WriteIdentity::new(None, &headers).record(
        &serde_json::Value::Null,
        &mut obj.body,
        "certificates.k8s.io/v1",
        None,
        None,
    );

    // Dry-run: validation and admission passed; return the would-be created object without
    // persisting — mirrors create_resource's dry-run early-return in resource.rs.
    if is_dry_run_header(&headers) {
        return Ok((StatusCode::CREATED, Json(obj.body)).into_response());
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
                name = generate_name(generate_name_prefix.as_deref().unwrap_or_default());
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
            Err(e) => {
                return Err(crate::handlers::generic::store_err(
                    e, GROUP, PLURAL, &name, KIND,
                ))
            }
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    crate::handlers::resource::delete_collection_resource(
        State(state),
        Path((GROUP.to_string(), VERSION.to_string(), PLURAL.to_string())),
        Query(query),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub(crate) fn is_csr(group: &str, plural: &str) -> bool {
    group == GROUP && plural == PLURAL
}

/// Upstream `csrStrategy.PrepareForUpdate`: spec is immutable after create. Without this a
/// requester could get a benign request approved, then swap in a different request/signer.
pub(crate) fn preserve_csr_spec(old: &serde_json::Value, new: &mut serde_json::Value) {
    new["spec"] = old["spec"].clone();
}

/// Create-time admission shared by POST and SSA apply-create, run after mutating webhooks:
/// subject restriction, then identity re-stamped from the authenticated caller and status
/// stripped — neither may survive a client, or a mutating webhook, setting them. Spec is
/// immutable after create; status is the signer's exclusive write.
pub(crate) async fn finalize_csr_create<S: Store>(
    state: &AppState<S>,
    body: &mut serde_json::Value,
    user: &UserInfo,
) -> Result<(), crate::status::StatusError> {
    reject_system_masters_client_csr(body)?;
    reject_bootstrap_node_takeover(state, body, user).await?;
    stamp_csr_identity(body, user);
    if let Some(map) = body.as_object_mut() {
        map.remove("status");
    }
    Ok(())
}

const KUBE_APISERVER_CLIENT_SIGNER: &str = "kubernetes.io/kube-apiserver-client";
const OID_ORGANIZATION: &str = "2.5.4.10";
const OID_COMMON_NAME: &str = "2.5.4.3";

/// The Node name a kubelet client CSR claims via `CN=system:node:<name>`; `Ok(None)` for other
/// signers or a CN that is not a node identity. Fails closed: an unparseable request, a CN
/// in a string type `atv_string` does not decode, or anything but exactly one CN is an error,
/// because x509 auth takes the LAST CN and a decoy CN placed first would hide the real one.
fn claimed_kubelet_node_name(body: &serde_json::Value) -> Result<Option<String>, String> {
    let spec = &body["spec"];
    if spec["signerName"].as_str() != Some(KUBELET_CLIENT_SIGNER) {
        return Ok(None);
    }
    let pem = base64::engine::general_purpose::STANDARD
        .decode(spec["request"].as_str().unwrap_or(""))
        .map_err(|e| format!("failed to parse CSR: {e}"))?;
    let req = parse_csr_pem(&pem).map_err(|e| format!("failed to parse CSR: {e}"))?;
    let mut cns = req
        .info
        .subject
        .iter()
        .filter(|atv| atv.oid.to_string() == OID_COMMON_NAME);
    let (Some(atv), None) = (cns.next(), cns.next()) else {
        return Err("CSR subject must contain exactly one CommonName".into());
    };
    let cn = crate::auth::atv_string(&atv.value)
        .ok_or_else(|| "CSR subject CommonName has an undecodable string type".to_string())?;
    Ok(cn.strip_prefix("system:node:").map(str::to_string))
}

/// A joiner (member of `system:bootstrappers`, which upstream's `nodeclient` approval is bound
/// to) may not claim the `--local-node-name` identity: the resulting certificate authorizes the
/// apiserver-IP kubelet-serving exemption for that node. Other existing Node names stay
/// claimable, as upstream, so expired-cert recovery and worker re-join work. Nodes renewing
/// authenticate as `system:node:<name>` and are unaffected.
async fn reject_bootstrap_node_takeover<S: Store>(
    state: &AppState<S>,
    body: &serde_json::Value,
    user: &UserInfo,
) -> Result<(), crate::status::StatusError> {
    if !user.groups.iter().any(|g| g == "system:bootstrappers") {
        return Ok(());
    }
    let Some(node) = claimed_kubelet_node_name(body).map_err(Status::forbidden)? else {
        return Ok(());
    };
    if state.local_node_name.as_deref() == Some(node.as_str()) {
        return Err(Status::forbidden(format!(
            "{:?} may not request a client certificate for node {node:?}: it is the \
             control-plane node (choose a different --node-name)",
            user.username,
        )));
    }
    Ok(())
}

/// Upstream CertificateSubjectRestriction: the `kube-apiserver-client` signer must never be
/// asked for a `system:masters` identity. The cluster CA is trusted for client auth, so a
/// signed `O=system:masters` certificate is cluster-admin. An unreadable `O` value fails
/// closed because the signer may decode it where this parser cannot.
pub(crate) fn reject_system_masters_client_csr(
    body: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let spec = &body["spec"];
    if spec["signerName"].as_str() != Some(KUBE_APISERVER_CLIENT_SIGNER) {
        return Ok(());
    }
    let forbidden = |why: String| Err(Status::forbidden(why));
    let pem = base64::engine::general_purpose::STANDARD
        .decode(spec["request"].as_str().unwrap_or(""))
        .map_err(|e| Status::forbidden(format!("failed to parse CSR: {e}")))?;
    let req =
        parse_csr_pem(&pem).map_err(|e| Status::forbidden(format!("failed to parse CSR: {e}")))?;
    for atv in req.info.subject.iter() {
        if atv.oid.to_string() != OID_ORGANIZATION {
            continue;
        }
        match crate::auth::atv_string(&atv.value) {
            Some(org) if org == "system:masters" => {
                return forbidden(format!(
                    "use of {KUBE_APISERVER_CLIENT_SIGNER} signer with system:masters group is not allowed"
                ))
            }
            None => {
                return forbidden(format!(
                    "use of {KUBE_APISERVER_CLIENT_SIGNER} signer with an undecodable organization is not allowed"
                ))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Upstream CertificateApproval admission: `/approval` writes need `approve` on the signer
/// of the stored (not the submitted) CSR.
pub(crate) fn authorize_csr_approval<S: Store>(
    state: &AppState<S>,
    user: &UserInfo,
    stored: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let signer = stored["spec"]["signerName"].as_str().unwrap_or("");
    if super::certificates::user_may_for_signer(state, user, "approve", signer) {
        return Ok(());
    }
    Err(Status::forbidden(format!(
        "user not permitted to approve requests with signerName {signer:?}"
    )))
}

fn is_unset(v: &serde_json::Value) -> bool {
    v.is_null() || v.as_str() == Some("")
}

/// Upstream `populateConditionTimestamps`: defaults an unset `lastUpdateTime` to `now`, and an
/// unset `lastTransitionTime` to the old condition's value for the same type+status, else `now`.
pub(crate) fn populate_condition_timestamps(
    new: &mut serde_json::Value,
    old: &serde_json::Value,
    now: &str,
) {
    let old_conditions = csr_conditions(old);
    let Some(conditions) = new["status"]["conditions"].as_array_mut() else {
        return;
    };
    for c in conditions {
        if is_unset(&c["lastUpdateTime"]) {
            c["lastUpdateTime"] = now.into();
        }
        if is_unset(&c["lastTransitionTime"]) {
            let carried = old_conditions
                .iter()
                .find(|o| {
                    o["type"] == c["type"]
                        && o["status"] == c["status"]
                        && !is_unset(&o["lastTransitionTime"])
                })
                .map(|o| o["lastTransitionTime"].clone());
            c["lastTransitionTime"] = carried.unwrap_or_else(|| now.into());
        }
    }
}

/// Server-defaulted timestamps are not a client-intended change, so a client that omits them
/// when echoing the stored conditions is not "changing" anything.
fn without_timestamps(conditions: &[serde_json::Value]) -> Vec<serde_json::Value> {
    conditions
        .iter()
        .cloned()
        .map(|mut c| {
            if let Some(m) = c.as_object_mut() {
                m.remove("lastUpdateTime");
                m.remove("lastTransitionTime");
            }
            c
        })
        .collect()
}

fn csr_conditions(body: &serde_json::Value) -> Vec<serde_json::Value> {
    body["status"]["conditions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn csr_certificate(body: &serde_json::Value) -> &str {
    body["status"]["certificate"].as_str().unwrap_or("")
}

fn condition_indices(conditions: &[serde_json::Value], ty: &str) -> Vec<usize> {
    (0..conditions.len())
        .filter(|&i| conditions[i]["type"].as_str() == Some(ty))
        .collect()
}

/// Upstream CertificateSigning admission plus the `/status` strategy: a `/status` write
/// that changes `status.certificate` or `status.conditions` needs `sign` on the signer;
/// Approved/Denied conditions belong to `/approval` and cannot be added or removed here
/// (existing ones are restored, as upstream's `preserveConditionInstances` does);
/// Failed conditions cannot be removed; an issued certificate cannot be replaced.
pub(crate) fn guard_csr_status_write<S: Store>(
    state: &AppState<S>,
    user: &UserInfo,
    old: &serde_json::Value,
    new: &mut serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let old_conditions = csr_conditions(old);
    let mut new_conditions = csr_conditions(new);
    let changed = csr_certificate(old) != csr_certificate(new)
        || without_timestamps(&old_conditions) != without_timestamps(&new_conditions);
    if !changed {
        // Equal modulo timestamps: restore the stored conditions so a caller without `sign`
        // cannot rewrite timestamps of existing Approved/Denied/Failed conditions.
        if new["status"]["conditions"].is_array() {
            new["status"]["conditions"] = serde_json::Value::Array(old_conditions);
        }
        populate_condition_timestamps(new, old, &crate::util::utc_now_rfc3339());
        return Ok(());
    }
    let signer = old["spec"]["signerName"].as_str().unwrap_or("");
    if !super::certificates::user_may_for_signer(state, user, "sign", signer) {
        return Err(Status::forbidden(format!(
            "user not permitted to sign requests with signerName {signer:?}"
        )));
    }

    for ty in ["Approved", "Denied"] {
        let old_idx = condition_indices(&old_conditions, ty);
        let new_idx = condition_indices(&new_conditions, ty);
        if new_idx.len() != old_idx.len() {
            let verb = if new_idx.len() > old_idx.len() {
                "add"
            } else {
                "remove"
            };
            return Err(Status::unprocessable_entity(format!(
                "status.conditions: Forbidden: updates may not {verb} a condition of type {ty:?}"
            )));
        }
        for (o, n) in old_idx.into_iter().zip(new_idx) {
            new_conditions[n] = old_conditions[o].clone();
        }
    }
    if condition_indices(&new_conditions, "Failed").len()
        < condition_indices(&old_conditions, "Failed").len()
    {
        return Err(Status::unprocessable_entity(
            "status.conditions: Forbidden: updates may not remove a condition of type \"Failed\""
                .into(),
        ));
    }
    if !csr_certificate(old).is_empty() && csr_certificate(old) != csr_certificate(new) {
        return Err(Status::unprocessable_entity(
            "status.certificate: Forbidden: updates may not modify existing certificate content"
                .into(),
        ));
    }
    if csr_certificate(old).is_empty() && !csr_certificate(new).is_empty() {
        let chained =
            append_signing_chain(csr_certificate(new), &state.signing_intermediates.get());
        if let Some(chained) = chained {
            new["status"]["certificate"] = serde_json::Value::String(chained);
        }
    }
    if new["status"]["conditions"].is_array() {
        new["status"]["conditions"] = serde_json::Value::Array(new_conditions);
    }
    populate_condition_timestamps(new, old, &crate::util::utc_now_rfc3339());
    Ok(())
}

/// Upstream `ValidateCertificateSigningRequestApprovalUpdate` over `status.conditions`:
/// Approved/Denied/Failed cannot be removed, Approved and Denied are mutually exclusive,
/// types are non-empty and unique, and Approved/Denied/Failed only take status "True".
/// Pre-existing violations (both Approved and Denied, duplicates, an empty type) are
/// tolerated as upstream does for stored data.
pub(crate) fn validate_approval_conditions(
    old: &serde_json::Value,
    new: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let old_conditions = csr_conditions(old);
    let new_conditions = csr_conditions(new);
    let mut errs: Vec<String> = Vec::new();

    for ty in ["Approved", "Denied", "Failed"] {
        if condition_indices(&new_conditions, ty).len()
            < condition_indices(&old_conditions, ty).len()
        {
            errs.push(format!(
                "status.conditions: Forbidden: updates may not remove a condition of type {ty:?}"
            ));
        }
    }

    let has = |c: &[serde_json::Value], ty| !condition_indices(c, ty).is_empty();
    let old_had_both = has(&old_conditions, "Approved") && has(&old_conditions, "Denied");
    if !old_had_both && has(&new_conditions, "Approved") && has(&new_conditions, "Denied") {
        let first = |ty| condition_indices(&new_conditions, ty)[0];
        let second = if first("Approved") > first("Denied") {
            "Approved"
        } else {
            "Denied"
        };
        errs.push(format!(
            "status.conditions: Invalid value: {second:?}: Approved and Denied conditions are \
             mutually exclusive"
        ));
    }

    let old_types: Vec<&str> = old_conditions
        .iter()
        .map(|c| c["type"].as_str().unwrap_or(""))
        .collect();
    let old_has_dup = old_types
        .iter()
        .enumerate()
        .any(|(i, t)| old_types[..i].contains(t));
    let old_has_empty = old_types.contains(&"");
    let mut seen: Vec<&str> = Vec::new();
    for (i, c) in new_conditions.iter().enumerate() {
        let ty = c["type"].as_str().unwrap_or("");
        if ty.is_empty() && !old_has_empty {
            errs.push(format!("status.conditions[{i}].type: Required value"));
        }
        let supported: &[&str] = if matches!(ty, "Approved" | "Denied" | "Failed") {
            &["True"]
        } else {
            &["False", "True", "Unknown"]
        };
        match c["status"].as_str().unwrap_or("") {
            "" => errs.push(format!("status.conditions[{i}].status: Required value")),
            s if !supported.contains(&s) => errs.push(format!(
                "status.conditions[{i}].status: Unsupported value: {s:?}: supported values: {}",
                supported
                    .iter()
                    .map(|v| format!("{v:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            _ => {}
        }
        if !old_has_dup && seen.contains(&ty) {
            errs.push(format!(
                "status.conditions[{i}].type: Duplicate value: {ty:?}"
            ));
        }
        seen.push(ty);
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(Status::unprocessable_entity(errs.join(", ")))
    }
}

/// A newly issued `status.certificate` (base64 of PEM) with the intermediate that signed it
/// appended. kube-controller-manager signs with a single-certificate file and returns the bare
/// leaf, but clients pin only the root, so a leaf alone cannot be verified. The API allows
/// intermediates after the leaf. None when no known intermediate signed the leaf (e.g. it is
/// root-signed) or the chain is already there. Deliberately diverges from upstream, which
/// returns the leaf only.
pub(crate) fn append_signing_chain(
    certificate_b64: &str,
    intermediates: &[Vec<u8>],
) -> Option<String> {
    use base64::Engine as _;
    use rustls::pki_types::{pem::PemObject as _, CertificateDer};
    let engine = base64::engine::general_purpose::STANDARD;
    let mut pem = engine.decode(certificate_b64).ok()?;
    let certs: Vec<CertificateDer<'_>> = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<_, _>>()
        .ok()?;
    let leaf = certs.first()?;
    let issuer = intermediates
        .iter()
        .find(|i| crate::pki::ensure_signed_by(leaf, i).is_ok())?;
    if certs
        .iter()
        .skip(1)
        .any(|c| c.as_ref() == issuer.as_slice())
    {
        return None;
    }
    if !pem.ends_with(b"\n") {
        pem.push(b'\n');
    }
    pem.extend(crate::tls::pem_encode("CERTIFICATE", issuer));
    Some(engine.encode(pem))
}

const KUBELET_CLIENT_SIGNER: &str = "kubernetes.io/kube-apiserver-client-kubelet";

/// Join tokens are single-use: the Secret to delete when `new` is the write that first
/// issues an approved kubelet client certificate to a bootstrap-token identity. `None` for
/// everything else — an approve-only write (the joiner still needs the token to fetch the
/// certificate), non-bootstrap requestors, other signers, or an already-issued certificate.
pub(crate) fn join_token_secret_to_consume(
    old: &serde_json::Value,
    new: &serde_json::Value,
) -> Option<String> {
    if !csr_certificate(old).is_empty() || csr_certificate(new).is_empty() {
        return None;
    }
    if new["spec"]["signerName"].as_str() != Some(KUBELET_CLIENT_SIGNER) {
        return None;
    }
    let conditions = csr_conditions(new);
    if condition_indices(&conditions, "Approved").is_empty()
        || !condition_indices(&conditions, "Denied").is_empty()
    {
        return None;
    }
    let id = new["spec"]["username"]
        .as_str()?
        .strip_prefix(crate::bootstrap_token::USER_PREFIX)?;
    crate::bootstrap_token::is_valid_token_id(id)
        .then(|| format!("{}{id}", crate::bootstrap_token::SECRET_NAME_PREFIX))
}

/// Deletes the join token Secret once its CSR has been issued (see
/// [`join_token_secret_to_consume`]). Already gone (expired, cleaned, re-delivered write) is
/// fine; a store failure is logged and left to the token's TTL.
pub(crate) async fn consume_join_token<S: Store>(
    store: &S,
    old: &serde_json::Value,
    new: &serde_json::Value,
) {
    if let Some(name) = join_token_secret_to_consume(old, new) {
        crate::bootstrap_token::delete_token_secret(store, &name).await;
    }
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
            HeaderMap::new(),
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
            HeaderMap::new(),
        )
        .await;

        let err = result.expect_err("get_csr on missing CSR must return error");
        assert_eq!(
            err.0,
            axum::http::StatusCode::NOT_FOUND,
            "get_csr on non-existent CSR must return 404"
        );
    }

    /// A CSR stored under an uppercase name (explicit or generateName-derived) could never be
    /// approved or read by name: get_csr and the approval/status subresources 400 on it.
    #[tokio::test]
    async fn create_csr_rejects_names_the_read_path_would_reject() {
        let state = make_state();
        let b64 = valid_csr_b64();

        for (meta, field) in [
            (serde_json::json!({"name": "Bad-CSR"}), "metadata.name"),
            (
                serde_json::json!({"generateName": "Bad-CSR-"}),
                "metadata.generateName",
            ),
        ] {
            let csr_body = serde_json::json!({
                "apiVersion": "certificates.k8s.io/v1",
                "kind": "CertificateSigningRequest",
                "metadata": meta,
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
            let err = create_csr(
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
            .err()
            .expect("invalid CSR name must be refused at create");
            crate::handlers::test_support::assert_invalid_name_field(&err, field);
        }
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
            HeaderMap::new(),
            Bytes::new(),
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

    /// The generic cluster-scoped create must apply the CSR guards itself: a request that
    /// reaches it by any route would otherwise store an unvalidated spec carrying a forged
    /// requester identity and a pre-set status.
    #[tokio::test]
    async fn generic_create_applies_csr_validation_and_identity_stamping_on_every_route() {
        use axum::extract::{Path, Query, State};

        let state = make_state();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        let user = || crate::auth::UserInfo {
            username: "alice".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };
        let create = |body: serde_json::Value| {
            super::super::resource::create_resource(
                State(state.clone()),
                Path((
                    "certificates.k8s.io".to_string(),
                    "v1".to_string(),
                    "certificatesigningrequests".to_string(),
                )),
                Query(Default::default()),
                axum::Extension(user()),
                headers.clone(),
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            )
        };
        let csr = |name: &str, request: &str| {
            serde_json::json!({
                "apiVersion": "certificates.k8s.io/v1",
                "kind": "CertificateSigningRequest",
                "metadata": {"name": name},
                "spec": {
                    "request": request,
                    "signerName": "kubernetes.io/kube-apiserver-client",
                    "usages": ["client auth"],
                    "username": "forged"
                },
                "status": {"certificate": "Zm9yZ2Vk"}
            })
        };

        match create(csr("bad", "not-a-csr")).await {
            Err(e) => assert_eq!(e.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY),
            Ok(_) => panic!("an invalid PKCS#10 request must be rejected on the generic route"),
        }

        create(csr("good", &valid_csr_b64()))
            .await
            .unwrap_or_else(|e| panic!("valid CSR must be created, got {}", e.0));
        let stored = state
            .store
            .get("/registry/certificates.k8s.io/certificatesigningrequests/good")
            .await
            .unwrap()
            .expect("persisted");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["username"], "alice",
            "requester identity must come from the caller, never the body"
        );
        assert!(
            v.get("status")
                .is_none_or(|s| s.get("certificate").is_none()),
            "a client must not pre-set the issued certificate. Got: {:?}",
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

    fn kubelet_client_csr_b64(cn: &str) -> String {
        use rcgen::{CertificateParams, DnType, KeyPair};
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "system:nodes");
        let pem = params
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(pem)
    }

    /// POSTs a kubelet client CSR for `system:node:<node>` as `username`; Ok(()) if created.
    async fn post_kubelet_client_csr(
        state: &AppState<u7s_store::SqliteStore>,
        username: &str,
        node: &str,
    ) -> Result<(), crate::status::StatusError> {
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": format!("csr-{node}")},
            "spec": {
                "request": kubelet_client_csr_b64(&format!("system:node:{node}")),
                "signerName": KUBELET_CLIENT_SIGNER,
                "usages": ["digital signature", "key encipherment", "client auth"],
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
                username: username.into(),
                uid: String::new(),
                groups: if username.starts_with("system:bootstrap:") {
                    vec!["system:bootstrappers".into()]
                } else {
                    vec!["system:nodes".into()]
                },
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .map(|_| ())
    }

    async fn csr_stored(state: &AppState<u7s_store::SqliteStore>, node: &str) -> bool {
        let key = group_object_key(GROUP, PLURAL, None, &format!("csr-{node}"));
        state.store.get(&key).await.unwrap().is_some()
    }

    async fn seed_node(state: &AppState<u7s_store::SqliteStore>, name: &str) {
        let node = serde_json::json!({
            "apiVersion": "v1", "kind": "Node", "metadata": {"name": name},
        });
        state
            .store
            .put(
                &group_object_key("", "nodes", None, name),
                serde_json::to_vec(&node).unwrap().into(),
                Some(0),
            )
            .await
            .unwrap();
    }

    fn state_with_local_node(name: &str) -> AppState<u7s_store::SqliteStore> {
        let mut state = make_state();
        state.local_node_name = Some(name.into());
        state
    }

    #[tokio::test]
    async fn join_token_holder_cannot_claim_the_control_plane_node_name_because_that_identity_unlocks_the_apiserver_ip_serving_cert(
    ) {
        let state = state_with_local_node("cp");
        assert_status(
            post_kubelet_client_csr(&state, "system:bootstrap:abcdef", "cp").await,
            StatusCode::FORBIDDEN,
            "joiner naming itself after the control-plane node",
        );
        assert!(
            !csr_stored(&state, "cp").await,
            "a refused CSR must not be persisted, or KCM would still approve it"
        );
    }

    #[tokio::test]
    async fn join_token_holder_may_reclaim_an_existing_worker_name_like_upstream_so_expired_cert_recovery_and_rejoin_work(
    ) {
        let state = state_with_local_node("cp");
        seed_node(&state, "worker-1").await;
        post_kubelet_client_csr(&state, "system:bootstrap:abcdef", "worker-1")
            .await
            .unwrap_or_else(|_| {
                panic!("refusing existing names strands workers with expired certs")
            });
        assert!(csr_stored(&state, "worker-1").await);
    }

    #[tokio::test]
    async fn guard_keys_on_bootstrappers_group_not_the_username_prefix() {
        let state = state_with_local_node("cp");
        let mut body = serde_json::json!({"spec": {
            "request": kubelet_client_csr_b64("system:node:cp"),
            "signerName": KUBELET_CLIENT_SIGNER,
        }});
        let joiner = crate::auth::UserInfo {
            username: "custom-joiner".into(),
            uid: String::new(),
            groups: vec!["system:bootstrappers".into()],
            extra: Default::default(),
        };
        assert!(
            finalize_csr_create(&state, &mut body, &joiner)
                .await
                .is_err(),
            "upstream approves nodeclient CSRs by group, so the guard must too"
        );
    }

    #[tokio::test]
    async fn join_token_holder_with_a_fresh_node_name_still_enrolls() {
        let state = state_with_local_node("cp");
        seed_node(&state, "worker-1").await;
        post_kubelet_client_csr(&state, "system:bootstrap:abcdef", "worker-2")
            .await
            .unwrap_or_else(|_| panic!("a new node name must enroll or no worker can ever join"));
        assert!(csr_stored(&state, "worker-2").await);
    }

    #[tokio::test]
    async fn existing_node_renews_its_client_cert_with_its_own_credential() {
        let state = state_with_local_node("cp");
        seed_node(&state, "worker-1").await;
        post_kubelet_client_csr(&state, "system:node:worker-1", "worker-1")
            .await
            .unwrap_or_else(|_| panic!("renewal by the node itself must keep working"));
        post_kubelet_client_csr(&state, "system:node:cp", "cp")
            .await
            .unwrap_or_else(|_| panic!("the control-plane node renews with its own credential"));
    }

    /// POST, generic create and server-side-apply create all end in `finalize_csr_create`, so
    /// the takeover check there covers every path that can create a CSR.
    #[tokio::test]
    async fn finalize_csr_create_enforces_the_takeover_check_for_every_create_path() {
        let state = state_with_local_node("cp");
        let mut body = serde_json::json!({"spec": {
            "request": kubelet_client_csr_b64("system:node:cp"),
            "signerName": KUBELET_CLIENT_SIGNER,
        }});
        let joiner = crate::auth::UserInfo {
            username: "system:bootstrap:abcdef".into(),
            uid: String::new(),
            groups: vec!["system:bootstrappers".into()],
            extra: Default::default(),
        };
        assert!(finalize_csr_create(&state, &mut body, &joiner)
            .await
            .is_err());
    }

    fn csr_b64_with_dn(entries: Vec<(rcgen::DnType, rcgen::DnValue)>) -> String {
        use rcgen::{CertificateParams, KeyPair};
        let mut params = CertificateParams::default();
        for (t, v) in entries {
            params.distinguished_name.push(t, v);
        }
        let pem = params
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(pem)
    }

    /// A second CN uses the CN OID as a custom type so rcgen does not dedupe it.
    fn cn(v: &str) -> (rcgen::DnType, rcgen::DnValue) {
        (rcgen::DnType::CommonName, v.to_string().into())
    }
    fn extra_cn(v: &str) -> (rcgen::DnType, rcgen::DnValue) {
        (
            rcgen::DnType::CustomDnType(vec![2, 5, 4, 3]),
            v.to_string().into(),
        )
    }

    async fn joiner_create(
        entries: Vec<(rcgen::DnType, rcgen::DnValue)>,
    ) -> Result<(), crate::status::StatusError> {
        joiner_create_raw(csr_b64_with_dn(entries)).await
    }

    async fn joiner_create_raw(request: String) -> Result<(), crate::status::StatusError> {
        let state = state_with_local_node("cp");
        let mut body = serde_json::json!({"spec": {
            "request": request,
            "signerName": KUBELET_CLIENT_SIGNER,
        }});
        let joiner = crate::auth::UserInfo {
            username: "system:bootstrap:abcdef".into(),
            uid: String::new(),
            groups: vec!["system:bootstrappers".into()],
            extra: Default::default(),
        };
        finalize_csr_create(&state, &mut body, &joiner).await
    }

    #[tokio::test]
    async fn decoy_first_cn_cannot_hide_the_local_node_name_that_auth_reads_last() {
        joiner_create(vec![cn("decoy"), extra_cn("system:node:cp")])
            .await
            .expect_err(
                "auth takes the LAST CN; a first-CN-only guard lets a joiner mint the \
                 control-plane node identity",
            );
    }

    #[tokio::test]
    async fn two_decoy_cns_are_rejected_because_cn_count_must_be_exactly_one() {
        joiner_create(vec![cn("decoy-a"), extra_cn("decoy-b")])
            .await
            .expect_err("multi-CN subjects are ambiguous across parsers and must fail closed");
    }

    #[tokio::test]
    async fn single_cn_naming_the_local_node_is_rejected() {
        joiner_create(vec![cn("system:node:cp")])
            .await
            .expect_err("joiners may not claim the control-plane node identity");
    }

    #[tokio::test]
    async fn single_fresh_cn_is_accepted() {
        joiner_create(vec![cn("system:node:worker-9")])
            .await
            .unwrap_or_else(|_| panic!("a fresh node name must enroll or no worker can join"));
    }

    #[tokio::test]
    async fn bmpstring_cn_naming_the_local_node_is_rejected_not_skipped() {
        let units: Vec<u8> = "system:node:cp"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        let bmp = rcgen::DnValue::BmpString(
            rcgen::string::BmpString::from_utf16be(units).expect("valid bmp string"),
        );
        joiner_create(vec![(rcgen::DnType::CommonName, bmp)])
            .await
            .expect_err("a CN type the guard cannot decode must fail closed, not bypass it");
    }

    #[tokio::test]
    async fn unparseable_request_from_a_joiner_is_rejected() {
        joiner_create_raw("bm90IGEgY3Ny".into())
            .await
            .expect_err("a request the guard cannot read must fail closed, not skip the check");
    }

    fn csr_pem_for(cn_value: &str) -> String {
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn_value.to_string());
        params
            .serialize_request(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap()
    }

    fn b64(bytes: impl AsRef<[u8]>) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn pem_of_der(der: &[u8]) -> String {
        x509_cert::der::pem::encode_string(
            "CERTIFICATE REQUEST",
            x509_cert::der::pem::LineEnding::LF,
            der,
        )
        .unwrap()
    }

    fn der_of(pem: &str) -> Vec<u8> {
        x509_cert::der::pem::decode_vec(pem.as_bytes()).unwrap().1
    }

    #[test]
    fn single_well_formed_block_is_accepted_with_surrounding_whitespace() {
        let pem = format!("\n  {}\n\n", csr_pem_for("system:node:w1"));
        let req = parse_csr_pem(pem.as_bytes()).expect("a normal kubectl/kubelet CSR must parse");
        let atv = req
            .info
            .subject
            .iter()
            .find(|a| a.oid.to_string() == OID_COMMON_NAME)
            .unwrap();
        assert_eq!(
            crate::auth::atv_string(&atv.value).unwrap(),
            "system:node:w1"
        );
    }

    fn signed_csr_pem(cn: &str, key: &rcgen::KeyPair) -> String {
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.serialize_request(key).unwrap().pem().unwrap()
    }

    /// `openssl req -new -newkey rsa:2048 -subj /CN=system:node:aaa -sha256`; rcgen cannot
    /// generate RSA keys with this backend.
    const RSA_2048_CSR: &str = "-----BEGIN CERTIFICATE REQUEST-----
MIICXzCCAUcCAQAwGjEYMBYGA1UEAwwPc3lzdGVtOm5vZGU6YWFhMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoJVTKJS7+rxkEEXPNrqm9u8man9RV5WT
DDdE8EvrqIgZUKTjODSflD6+xjPzWv5yN/N3cHeW6PcRQTzfvMyXS8kWpXb6AO0c
6aU4InMtEZieI5avdrGaQINzPcGdy97WWP1jJei8DFeUtA070fQb3jeKSRcssJhU
EYqLpyaEWkuHE+LtxHiY5wQop5+yVGq4H3H4XT8l56sWbSQnAeeY5JNF0wHWZPPE
WlMNy2iLlkMLRiQxKbCKqOKPcNaY/N7vz0kt0HxC10b5eNKGfbjVN9y8cujCjQm5
akuhd9/k6o+UXpfgYEEjaK0CVlQUBJC5jSR1ObHB1pVUv/dEjqUydwIDAQABoAAw
DQYJKoZIhvcNAQELBQADggEBADFEduLVXwteRzJ3SNe2WJV7fkmGrH4/FysrU7Si
v710/gOZxdqpmwMmyI82YxX+6vWfeHS4Nv8wx8/aXW/Km1tS4QxTPWG3aDcZiJ4u
LzVTYci9xSVsFbMPXnBebY9/VGZckOle2JRgf6gSkHAlZS200qKzb5XbnciOmSMs
a3Rad9ZG/JeHaFvNJe904AjR/AY6TheEWkmZ712jTAIlDdzMrOS3Z7O/l6T4tXO1
rAOgUk5Fly7dDCDGKj0xh1y+Dvy0q/iCmAL/OpgMyExJFP3fKl2gHajLraIjXiKW
jM1qzaNxAp+05IBrgXkfOr8eqwGpH7/ICzhwsSKgc4Z0+d0=
-----END CERTIFICATE REQUEST-----
";

    // `openssl req -new -subj /CN=system:node:aaa` over RSA keys of 2048 (-sha384/-sha512 and
    // `-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32`), 1024 (-sha256, -sha1, PSS)
    // and 768 bits, over secp521r1 with -sha512 and over secp224r1.
    const RSA_2048_SHA384: &str = include_str!("csr_fixtures/r2048_sha384.pem");
    const RSA_2048_SHA512: &str = include_str!("csr_fixtures/r2048_sha512.pem");
    const RSA_2048_PSS: &str = include_str!("csr_fixtures/r2048_pss.pem");
    const RSA_1024_SHA256: &str = include_str!("csr_fixtures/r1024_sha256.pem");
    const RSA_1024_SHA1: &str = include_str!("csr_fixtures/r1024_sha1.pem");
    const RSA_1024_PSS: &str = include_str!("csr_fixtures/r1024_pss.pem");
    const RSA_768_SHA256: &str = include_str!("csr_fixtures/r768.pem");
    const ECDSA_P521: &str = include_str!("csr_fixtures/p521.pem");
    const ECDSA_P224: &str = include_str!("csr_fixtures/p224.pem");

    fn rejection(pem: &str) -> String {
        let body = serde_json::json!({
            "metadata": {"name": "csr-1"},
            "spec": {"request": b64(pem), "signerName": "x"}
        });
        let err = validate_csr_spec(&body).expect_err("CSR must be rejected");
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
        let prefix = format!(
            "CertificateSigningRequest.certificates.k8s.io \"csr-1\" is invalid: spec.request: Invalid value: {:?}: ",
            b64(pem)
        );
        err.1
            .message
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("unexpected message prefix: {}", err.1.message))
            .to_string()
    }

    #[test]
    fn rsa_pss_and_every_pkcs1_sha2_hash_are_accepted_at_2048_bits_because_clients_sign_with_either_scheme(
    ) {
        for pem in [RSA_2048_PSS, RSA_2048_SHA384, RSA_2048_SHA512] {
            validate_csr_spec(&spec_with(pem)).unwrap();
        }
    }

    #[test]
    fn deliberate_divergence_rsa_1024_is_rejected_for_pkcs1_and_pss_because_u7s_floors_rsa_at_2048_where_go_accepts_1024(
    ) {
        for pem in [RSA_1024_SHA256, RSA_1024_PSS] {
            assert_eq!(
                rejection(pem),
                "crypto/rsa: 1024-bit RSA keys are not accepted; minimum is 2048"
            );
        }
    }

    #[test]
    fn rsa_key_below_1024_bits_is_rejected_with_the_same_floor_message() {
        assert_eq!(
            rejection(RSA_768_SHA256),
            "crypto/rsa: 768-bit RSA keys are not accepted; minimum is 2048"
        );
    }

    #[test]
    fn sha1_signed_csr_is_rejected_with_go_text_because_go_refuses_insecure_signature_algorithms() {
        assert_eq!(
            rejection(RSA_1024_SHA1),
            "x509: cannot verify signature: insecure algorithm SHA1-RSA"
        );
    }

    #[test]
    fn deliberate_divergence_p224_csr_is_rejected_because_no_hand_rolled_verifier_is_allowed_and_aws_lc_has_none(
    ) {
        assert_eq!(
            rejection(ECDSA_P224),
            "x509: cannot verify signature: algorithm unimplemented"
        );
    }

    #[test]
    fn rsa_pss_with_wrong_salt_length_is_rejected_as_unimplemented_because_go_only_knows_salt_equal_to_hash_length(
    ) {
        let mut der = der_of(RSA_2048_PSS);
        // The PSS params end with `a2 03 02 01 20` (salt length 32).
        let at = der
            .windows(5)
            .position(|w| w == [0xa2, 0x03, 0x02, 0x01, 0x20])
            .unwrap();
        der[at + 4] = 0x10;
        assert_eq!(
            rejection(&pem_of_der(&der)),
            "x509: cannot verify signature: algorithm unimplemented"
        );
    }

    #[test]
    fn rejection_message_names_the_object_like_upstream_so_kubectl_prints_the_same_error() {
        let mut der = der_of(RSA_2048_CSR);
        let at = der.windows(3).position(|w| w == b"aaa").unwrap();
        der[at..at + 3].copy_from_slice(b"bbb");
        assert_eq!(
            rejection(&pem_of_der(&der)),
            "crypto/rsa: verification error"
        );
    }

    fn csrs_per_algorithm() -> Vec<(&'static str, String)> {
        let mut out = vec![
            ("rsa-2048", RSA_2048_CSR.to_string()),
            ("rsa-2048-sha384", RSA_2048_SHA384.to_string()),
            ("rsa-2048-sha512", RSA_2048_SHA512.to_string()),
            ("rsa-2048-pss-sha256", RSA_2048_PSS.to_string()),
            ("ecdsa-p521", ECDSA_P521.to_string()),
        ];
        for (name, alg) in [
            ("ecdsa-p256", &rcgen::PKCS_ECDSA_P256_SHA256),
            ("ecdsa-p384", &rcgen::PKCS_ECDSA_P384_SHA384),
            ("ed25519", &rcgen::PKCS_ED25519),
        ] {
            let key = rcgen::KeyPair::generate_for(alg).unwrap();
            out.push((name, signed_csr_pem("system:node:aaa", &key)));
        }
        out
    }

    fn spec_with(pem: &str) -> serde_json::Value {
        serde_json::json!({"spec": {"request": b64(pem), "signerName": "x"}})
    }

    #[test]
    fn validly_signed_csr_is_accepted_for_every_key_algorithm_so_kubelet_and_kubectl_csrs_still_enroll(
    ) {
        for (name, pem) in csrs_per_algorithm() {
            let body = spec_with(&pem);
            validate_csr_spec(&body).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        }
    }

    #[test]
    fn subject_edited_after_signing_is_rejected_for_every_key_algorithm_because_signer_would_issue_an_identity_the_key_holder_never_asked_for(
    ) {
        for (name, pem) in csrs_per_algorithm() {
            let mut der = der_of(&pem);
            let at = der.windows(3).position(|w| w == b"aaa").unwrap();
            der[at..at + 3].copy_from_slice(b"bbb");
            let err = validate_csr_spec(&spec_with(&pem_of_der(&der)))
                .expect_err(&format!("{name}: tampered subject must be rejected"));
            assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY, "{name}");
            let msg = err.1.message;
            assert!(msg.contains("spec.request: Invalid value"), "{name}: {msg}");
            assert!(
                msg.ends_with("verification error") || msg.ends_with("verification failure"),
                "{name}: {msg}"
            );
        }
    }

    #[test]
    fn crlf_terminated_block_is_accepted_because_go_pem_decode_accepts_windows_authored_files() {
        let pem = csr_pem_for("system:node:w1").replace('\n', "\r\n");
        assert!(pem.contains("\r\n"));
        parse_csr_pem(pem.as_bytes()).expect("CRLF-encoded CSR must parse like in Go");
    }

    /// Go signs the first block and ignores the rest; a parser that picked another block would
    /// let the guard approve a decoy while KCM signs the claimed control-plane name.
    #[test]
    fn loosening_guard_two_blocks_are_rejected_in_either_order_so_guard_and_signer_cannot_pick_different_ones(
    ) {
        let (decoy, real) = (
            csr_pem_for("system:node:fresh"),
            csr_pem_for("system:node:cp"),
        );
        for pem in [format!("{decoy}{real}"), format!("{real}{decoy}")] {
            parse_csr_pem(pem.as_bytes()).expect_err("two PEM blocks are ambiguous");
        }
    }

    #[test]
    fn loosening_guard_data_around_the_block_is_rejected_because_go_skips_it_silently() {
        let pem = csr_pem_for("system:node:w1");
        for bad in [
            format!("junk\n{pem}"),
            format!("{pem}junk"),
            format!("{pem}\n-----BEGIN CERTIFICATE-----\n"),
        ] {
            parse_csr_pem(bad.as_bytes()).expect_err("only whitespace may surround the block");
        }
    }

    #[test]
    fn loosening_guard_wrong_block_type_is_rejected_because_go_requires_certificate_request() {
        let pem =
            csr_pem_for("system:node:w1").replace("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST");
        parse_csr_pem(pem.as_bytes()).expect_err("block type must be CERTIFICATE REQUEST");
    }

    #[test]
    fn loosening_guard_pem_headers_are_rejected_because_go_accepts_them_and_parsers_disagree_on_them(
    ) {
        let pem = csr_pem_for("system:node:w1").replacen(
            "-----BEGIN CERTIFICATE REQUEST-----\n",
            "-----BEGIN CERTIFICATE REQUEST-----\nProc-Type: 4,ENCRYPTED\n\n",
            1,
        );
        parse_csr_pem(pem.as_bytes()).expect_err("encapsulated headers must be rejected");
    }

    #[test]
    fn trailing_bytes_after_the_der_are_rejected_because_go_errors_on_them() {
        let mut der = der_of(&csr_pem_for("system:node:w1"));
        der.extend_from_slice(&[0x30, 0x00]);
        parse_csr_pem(pem_of_der(&der).as_bytes()).expect_err("trailing DER data");
    }

    #[test]
    fn ber_indefinite_length_is_rejected_because_go_requires_strict_der() {
        let der = der_of(&csr_pem_for("system:node:w1"));
        let hdr = if der[1] & 0x80 != 0 {
            2 + (der[1] & 0x7f) as usize
        } else {
            2
        };
        let mut ber = vec![0x30, 0x80];
        ber.extend_from_slice(&der[hdr..]);
        ber.extend_from_slice(&[0, 0]);
        parse_csr_pem(pem_of_der(&ber).as_bytes()).expect_err("BER must not parse");
    }

    #[tokio::test]
    async fn guard_rejects_decoy_plus_real_two_block_request_naming_the_local_node() {
        let (decoy, real) = (
            csr_pem_for("system:node:fresh"),
            csr_pem_for("system:node:cp"),
        );
        for pem in [format!("{decoy}{real}"), format!("{real}{decoy}")] {
            joiner_create_raw(b64(pem))
                .await
                .expect_err("a joiner must not smuggle the control-plane name in a second block");
        }
    }

    #[test]
    fn create_time_validation_rejects_what_the_guard_rejects() {
        let two = format!("{}{}", csr_pem_for("a"), csr_pem_for("b"));
        let body = serde_json::json!({"spec": {"request": b64(two), "signerName": "x"}});
        validate_csr_spec(&body).expect_err("create must reject ambiguous requests");
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
            HeaderMap::new(),
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
            key: impl Into<String> + Send,
        ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let key: String = key.into();
            async move { inner.get(&key).await }
        }

        fn list(
            &self,
            prefix: impl Into<String> + Send,
            opts: u7s_store::ListOptions,
        ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send
        {
            let inner = self.inner.clone();
            let prefix: String = prefix.into();
            async move { inner.list(&prefix, opts).await }
        }

        fn put(
            &self,
            key: impl Into<String> + Send,
            value: bytes::Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inject = self
                .fire_once
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key: String = key.into();
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
            key: impl Into<String> + Send,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, bytes::Bytes)>> + Send
        {
            let inner = self.inner.clone();
            let key: String = key.into();
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

    const CLIENT_SIGNER: &str = "kubernetes.io/kube-apiserver-client";

    fn csr_b64_with_org(org: Option<&str>) -> String {
        use rcgen::{CertificateParams, DnType, KeyPair};
        let key_pair = KeyPair::generate().expect("key generation must succeed");
        let mut params = CertificateParams::default();
        if let Some(org) = org {
            params
                .distinguished_name
                .push(DnType::OrganizationName, org);
        }
        let pem = params
            .serialize_request(&key_pair)
            .expect("CSR generation must succeed")
            .pem()
            .expect("CSR PEM serialization must succeed");
        base64::engine::general_purpose::STANDARD.encode(pem)
    }

    fn user(name: &str) -> UserInfo {
        UserInfo {
            username: name.into(),
            ..Default::default()
        }
    }

    async fn seed_csr_with(state: &AppState, name: &str, signer: &str, status: serde_json::Value) {
        let csr = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": name},
            "spec": {"request": csr_b64_with_org(None), "signerName": signer},
            "status": status
        });
        let key = group_object_key(GROUP, PLURAL, None, name);
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

    async fn stored_csr(state: &AppState, name: &str) -> serde_json::Value {
        let key = group_object_key(GROUP, PLURAL, None, name);
        let stored = state.store.get(&key).await.unwrap().unwrap();
        serde_json::from_slice(&stored.value).unwrap()
    }

    fn json_headers(content_type: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(content_type),
        );
        h
    }

    fn approved() -> serde_json::Value {
        serde_json::json!({"type": "Approved", "status": "True", "reason": "r", "message": "m"})
    }

    async fn status_put(
        state: &AppState,
        who: &UserInfo,
        name: &str,
        status: serde_json::Value,
    ) -> Result<(), crate::status::StatusError> {
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
            "metadata": {"name": name}, "status": status
        });
        crate::handlers::cr::put_cr_status(
            State(state.clone()),
            Extension(who.clone()),
            Path((GROUP.into(), VERSION.into(), PLURAL.into(), name.into())),
            json_headers("application/json"),
            Bytes::from(body.to_string()),
        )
        .await
        .map(|_| ())
    }

    async fn status_patch(
        state: &AppState,
        who: &UserInfo,
        name: &str,
        status: serde_json::Value,
    ) -> Result<(), crate::status::StatusError> {
        crate::handlers::cr::patch_cr_status(
            State(state.clone()),
            Extension(who.clone()),
            Path((GROUP.into(), VERSION.into(), PLURAL.into(), name.into())),
            json_headers("application/merge-patch+json"),
            Bytes::from(serde_json::json!({"status": status}).to_string()),
        )
        .await
        .map(|_| ())
    }

    async fn approval_put(
        state: &AppState,
        who: &UserInfo,
        name: &str,
    ) -> Result<(), crate::status::StatusError> {
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
            "metadata": {"name": name}, "status": {"conditions": [approved()]}
        });
        crate::handlers::approval::put_approval(
            State(state.clone()),
            Extension(who.clone()),
            Path(name.to_owned()),
            json_headers("application/json"),
            Bytes::from(body.to_string()),
        )
        .await
        .map(|_| ())
    }

    async fn approval_patch(
        state: &AppState,
        who: &UserInfo,
        name: &str,
    ) -> Result<(), crate::status::StatusError> {
        crate::handlers::approval::patch_approval(
            State(state.clone()),
            Extension(who.clone()),
            Path(name.to_owned()),
            json_headers("application/merge-patch+json"),
            Bytes::from(serde_json::json!({"status": {"conditions": [approved()]}}).to_string()),
        )
        .await
        .map(|_| ())
    }

    fn assert_status(r: Result<(), crate::status::StatusError>, code: StatusCode, why: &str) {
        match r {
            Err(e) => assert_eq!(e.0, code, "{why}: {}", serde_json::to_value(&e.1).unwrap()),
            Ok(()) => panic!("{why}: write unexpectedly succeeded"),
        }
    }

    #[tokio::test]
    async fn approval_without_approve_on_signer_is_forbidden_so_scoped_roles_cannot_self_approve() {
        let state = make_state();
        seed_csr_with(&state, "c1", CLIENT_SIGNER, serde_json::json!({})).await;
        let mallory = user("mallory");

        assert_status(
            approval_put(&state, &mallory, "c1").await,
            StatusCode::FORBIDDEN,
            "PUT /approval without approve on the signer",
        );
        assert_status(
            approval_patch(&state, &mallory, "c1").await,
            StatusCode::FORBIDDEN,
            "PATCH /approval without approve on the signer",
        );
        assert!(
            stored_csr(&state, "c1").await["status"]["conditions"].is_null(),
            "a refused approval must not have been persisted"
        );
    }

    #[tokio::test]
    async fn approve_is_scoped_to_the_csr_signer_not_any_signer() {
        let state = make_state();
        seed_csr_with(&state, "c1", CLIENT_SIGNER, serde_json::json!({})).await;
        let ca = user("other-approver");
        crate::handlers::test_support::grant_signer_verb(
            &state,
            "other-approver",
            "approve",
            "example.com/other",
        );
        assert_status(
            approval_put(&state, &ca, "c1").await,
            StatusCode::FORBIDDEN,
            "approve on a different signer must not authorize this CSR",
        );

        let dom = user("domain-approver");
        crate::handlers::test_support::grant_signer_verb(
            &state,
            "domain-approver",
            "approve",
            "kubernetes.io/*",
        );
        approval_put(&state, &dom, "c1")
            .await
            .expect("approve on <domain>/* authorizes every signer in the domain");
    }

    #[tokio::test]
    async fn status_cannot_set_approved_so_sign_does_not_imply_approve() {
        let state = make_state();
        seed_csr_with(&state, "c1", CLIENT_SIGNER, serde_json::json!({})).await;
        let signer = user("signer");
        crate::handlers::test_support::grant_signer_verb(&state, "signer", "sign", CLIENT_SIGNER);

        assert_status(
            status_put(
                &state,
                &signer,
                "c1",
                serde_json::json!({"conditions": [approved()]}),
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "PUT /status adding Approved",
        );
        assert_status(
            status_patch(
                &state,
                &signer,
                "c1",
                serde_json::json!({"conditions": [approved()]}),
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "PATCH /status adding Approved",
        );
        assert!(
            stored_csr(&state, "c1").await["status"]["conditions"].is_null(),
            "/status must never leave an Approved condition behind"
        );
    }

    #[tokio::test]
    async fn status_certificate_requires_sign_on_the_signer() {
        let state = make_state();
        seed_csr_with(&state, "c1", CLIENT_SIGNER, serde_json::json!({})).await;
        let mallory = user("mallory");
        let forged = serde_json::json!({"certificate": "Zm9yZ2Vk"});

        assert_status(
            status_put(&state, &mallory, "c1", forged.clone()).await,
            StatusCode::FORBIDDEN,
            "PUT /status certificate without sign",
        );
        assert_status(
            status_patch(&state, &mallory, "c1", forged.clone()).await,
            StatusCode::FORBIDDEN,
            "PATCH /status certificate without sign",
        );
        assert!(
            stored_csr(&state, "c1").await["status"]["certificate"].is_null(),
            "a forged certificate must not be persisted"
        );

        let signer = user("signer");
        crate::handlers::test_support::grant_signer_verb(&state, "signer", "sign", CLIENT_SIGNER);
        status_put(&state, &signer, "c1", forged)
            .await
            .expect("a holder of sign on the signer may set the certificate");
        assert_status(
            status_put(
                &state,
                &signer,
                "c1",
                serde_json::json!({"certificate": "b3RoZXI="}),
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "replacing an issued certificate",
        );
    }

    #[tokio::test]
    async fn status_write_preserves_existing_approval_and_needs_no_sign_when_nothing_changes() {
        let state = make_state();
        seed_csr_with(
            &state,
            "c1",
            CLIENT_SIGNER,
            serde_json::json!({"conditions": [approved()]}),
        )
        .await;
        let signer = user("signer");
        crate::handlers::test_support::grant_signer_verb(&state, "signer", "sign", CLIENT_SIGNER);
        let denied = serde_json::json!({"type": "Denied", "status": "True"});
        assert_status(
            status_patch(
                &state,
                &signer,
                "c1",
                serde_json::json!({"conditions": [denied]}),
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "swapping Approved for Denied through /status",
        );
        let mut tampered = approved();
        tampered["reason"] = "rewritten".into();
        status_put(
            &state,
            &signer,
            "c1",
            serde_json::json!({"conditions": [tampered]}),
        )
        .await
        .expect("editing an Approved condition is silently reverted, as upstream does");
        assert_eq!(
            stored_csr(&state, "c1").await["status"]["conditions"][0]["reason"],
            "r",
            "/status must not rewrite the approver's condition"
        );

        let unchanged = user("nobody");
        status_put(
            &state,
            &unchanged,
            "c1",
            serde_json::json!({"conditions": [approved()]}),
        )
        .await
        .expect("a /status write that changes neither certificate nor conditions needs no sign");
    }

    #[tokio::test]
    async fn kcm_style_approve_then_sign_still_works() {
        let state = make_state();
        seed_csr_with(&state, "c1", CLIENT_SIGNER, serde_json::json!({})).await;
        let kcm = user("kcm");
        crate::handlers::test_support::grant_signer_verb(&state, "kcm", "approve", CLIENT_SIGNER);
        crate::handlers::test_support::grant_signer_verb(&state, "kcm", "sign", CLIENT_SIGNER);

        approval_put(&state, &kcm, "c1").await.expect("approve");
        status_put(
            &state,
            &kcm,
            "c1",
            serde_json::json!({"conditions": [approved()], "certificate": "Y2VydA=="}),
        )
        .await
        .expect("sign");
        let s = stored_csr(&state, "c1").await;
        assert_eq!(s["status"]["certificate"], "Y2VydA==");
        assert_eq!(s["status"]["conditions"][0]["type"], "Approved");
    }

    async fn create_as(
        state: &AppState,
        signer: &str,
        org: Option<&str>,
    ) -> Result<(), crate::status::StatusError> {
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
            "metadata": {"generateName": "csr-"},
            "spec": {"request": csr_b64_with_org(org), "signerName": signer,
                     "usages": ["client auth"]}
        });
        create_csr(
            State(state.clone()),
            Extension(user("alice")),
            json_headers("application/json"),
            Bytes::from(body.to_string()),
        )
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn client_signer_refuses_system_masters_organization_because_ca_is_trusted_for_admin() {
        let state = make_state();
        assert_status(
            create_as(&state, CLIENT_SIGNER, Some("system:masters")).await,
            StatusCode::FORBIDDEN,
            "kube-apiserver-client with O=system:masters",
        );
        create_as(&state, CLIENT_SIGNER, Some("developers"))
            .await
            .expect("other organizations stay allowed");
        create_as(&state, CLIENT_SIGNER, None)
            .await
            .expect("no organization stays allowed");
        create_as(&state, "example.com/custom", Some("system:masters"))
            .await
            .expect("the restriction is specific to the kube-apiserver-client signer");
    }

    #[test]
    fn client_signer_fails_closed_on_undecodable_request_because_signer_may_decode_it() {
        let junk = |pem: &str| {
            serde_json::json!({"spec": {
                "signerName": CLIENT_SIGNER,
                "request": base64::engine::general_purpose::STANDARD.encode(pem),
            }})
        };
        for body in [
            junk("not a pem"),
            junk("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"),
            serde_json::json!({"spec": {"signerName": CLIENT_SIGNER, "request": "!!!"}}),
        ] {
            assert_status(
                reject_system_masters_client_csr(&body),
                StatusCode::FORBIDDEN,
                "undecodable PKCS#10 on the client signer",
            );
        }
    }

    #[test]
    fn client_signer_fails_closed_on_non_utf8_organization_because_it_could_hide_system_masters() {
        use rcgen::{CertificateParams, DnType, DnValue, KeyPair};
        let mut params = CertificateParams::default();
        params.distinguished_name.push(
            DnType::OrganizationName,
            DnValue::TeletexString("system:masters".try_into().unwrap()),
        );
        let pem = params
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        let body = serde_json::json!({"spec": {
            "signerName": CLIENT_SIGNER,
            "request": base64::engine::general_purpose::STANDARD.encode(pem),
        }});
        assert_status(
            reject_system_masters_client_csr(&body),
            StatusCode::FORBIDDEN,
            "O encoded as TeletexString",
        );
    }

    #[tokio::test]
    async fn approval_authorizes_the_stored_signer_not_the_one_in_the_body() {
        let state = make_state();
        seed_csr_with(&state, "c1", CLIENT_SIGNER, serde_json::json!({})).await;
        crate::handlers::test_support::grant_signer_verb(
            &state,
            "mallory",
            "approve",
            "example.com/harmless",
        );
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
            "metadata": {"name": "c1"},
            "spec": {"signerName": "example.com/harmless"},
            "status": {"conditions": [approved()]}
        });
        let r = crate::handlers::approval::put_approval(
            State(state.clone()),
            Extension(user("mallory")),
            Path("c1".to_owned()),
            json_headers("application/json"),
            Bytes::from(body.to_string()),
        )
        .await
        .map(|_| ());
        assert_status(
            r,
            StatusCode::FORBIDDEN,
            "approve rights on a body-supplied signer must not approve a CSR stored under another",
        );
    }

    fn csr_body(name: &str, signer: &str, org: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
            "metadata": {"name": name},
            "spec": {"request": csr_b64_with_org(org), "signerName": signer,
                     "usages": ["client auth"]}
        })
    }

    fn admin() -> UserInfo {
        UserInfo {
            username: "admin".into(),
            groups: vec!["system:masters".into()],
            ..Default::default()
        }
    }

    async fn generic_put(state: &AppState, name: &str, body: &serde_json::Value) -> StatusCode {
        crate::handlers::resource::replace_resource(
            State(state.clone()),
            Path((GROUP.into(), VERSION.into(), PLURAL.into(), name.into())),
            axum::extract::Query(Default::default()),
            Extension(admin()),
            json_headers("application/json"),
            Bytes::from(body.to_string()),
        )
        .await
        .map(|r| r.into_response().status())
        .unwrap_or_else(|e| e.0)
    }

    async fn generic_patch(
        state: &AppState,
        name: &str,
        content_type: &'static str,
        body: String,
    ) -> StatusCode {
        crate::handlers::resource::patch_resource(
            State(state.clone()),
            Path((GROUP.into(), VERSION.into(), PLURAL.into(), name.into())),
            axum::extract::Query(Default::default()),
            Extension(admin()),
            json_headers(content_type),
            Bytes::from(body),
        )
        .await
        .map(|r| r.into_response().status())
        .unwrap_or_else(|e| e.0)
    }

    #[tokio::test]
    async fn put_cannot_create_a_missing_csr_because_it_would_skip_the_subject_restriction() {
        let state = make_state();
        let body = csr_body("evil", CLIENT_SIGNER, Some("system:masters"));
        assert_eq!(
            generic_put(&state, "evil", &body).await,
            StatusCode::NOT_FOUND
        );
        assert!(state
            .store
            .get(&group_object_key(GROUP, PLURAL, None, "evil"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn server_side_apply_create_runs_the_subject_restriction_like_post() {
        let state = make_state();
        let body = csr_body("evil", CLIENT_SIGNER, Some("system:masters")).to_string();
        assert_eq!(
            generic_patch(&state, "evil", "application/apply-patch+yaml", body).await,
            StatusCode::FORBIDDEN
        );
        assert!(state
            .store
            .get(&group_object_key(GROUP, PLURAL, None, "evil"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn server_side_apply_creates_a_normal_csr_with_status_stripped_and_identity_stamped() {
        let state = make_state();
        let mut body = csr_body("ok", CLIENT_SIGNER, Some("developers"));
        body["status"] = serde_json::json!({"conditions": [approved()]});
        body["spec"]["username"] = "spoofed".into();
        let code = generic_patch(
            &state,
            "ok",
            "application/apply-patch+yaml",
            body.to_string(),
        )
        .await;
        assert!(code.is_success(), "apply-create of a CSR must work: {code}");
        let s = stored_csr(&state, "ok").await;
        assert!(
            s["status"]["conditions"].is_null(),
            "apply must not pre-approve"
        );
        assert_eq!(s["spec"]["username"], "admin", "identity is server-stamped");
    }

    #[tokio::test]
    async fn plain_put_and_patch_leave_the_stored_spec_intact() {
        let state = make_state();
        seed_csr_with(&state, "c1", "example.com/custom", serde_json::json!({})).await;
        let before = stored_csr(&state, "c1").await["spec"].clone();

        let swapped = csr_body("c1", CLIENT_SIGNER, Some("system:masters"));
        assert_eq!(generic_put(&state, "c1", &swapped).await, StatusCode::OK);
        assert_eq!(stored_csr(&state, "c1").await["spec"], before, "PUT");

        let patch = serde_json::json!({"spec": swapped["spec"]}).to_string();
        generic_patch(&state, "c1", "application/merge-patch+json", patch.clone()).await;
        assert_eq!(
            stored_csr(&state, "c1").await["spec"],
            before,
            "merge patch"
        );

        generic_patch(
            &state,
            "c1",
            "application/apply-patch+yaml",
            swapped.to_string(),
        )
        .await;
        assert_eq!(stored_csr(&state, "c1").await["spec"], before, "apply");
    }

    #[tokio::test]
    async fn approve_then_swap_spec_cannot_yield_an_approved_system_masters_client_csr() {
        let state = make_state();
        let signer = "example.com/custom";
        seed_csr_with(&state, "c1", signer, serde_json::json!({})).await;
        crate::handlers::test_support::grant_signer_verb(&state, "approver", "approve", signer);
        approval_put(&state, &user("approver"), "c1")
            .await
            .expect("approval on the benign signer");

        let swapped = csr_body("c1", CLIENT_SIGNER, Some("system:masters"));
        generic_put(&state, "c1", &swapped).await;
        let patch = serde_json::json!({"spec": swapped["spec"]}).to_string();
        generic_patch(&state, "c1", "application/merge-patch+json", patch).await;

        let s = stored_csr(&state, "c1").await;
        assert_eq!(s["status"]["conditions"][0]["type"], "Approved");
        assert_eq!(
            s["spec"]["signerName"], signer,
            "the approved CSR must not become a kube-apiserver-client request"
        );
        assert!(
            s["spec"]["request"] != swapped["spec"]["request"],
            "the approved request must not be swappable for an O=system:masters one"
        );
    }

    fn join_csr(username: &str, signer: &str, is_approved: bool, cert: &str) -> serde_json::Value {
        let mut status = serde_json::json!({});
        if is_approved {
            status["conditions"] = serde_json::json!([approved()]);
        }
        if !cert.is_empty() {
            status["certificate"] = cert.into();
        }
        serde_json::json!({
            "metadata": {"name": "c1"},
            "spec": {"username": username, "signerName": signer},
            "status": status
        })
    }

    const BOOTSTRAP_USER: &str = "system:bootstrap:abcdef";

    #[test]
    fn issued_kubelet_client_cert_for_bootstrap_user_consumes_that_token_so_a_leaked_token_cannot_join_again(
    ) {
        let old = join_csr(BOOTSTRAP_USER, KUBELET_CLIENT_SIGNER, true, "");
        let new = join_csr(BOOTSTRAP_USER, KUBELET_CLIENT_SIGNER, true, "Q0VSVA==");
        assert_eq!(
            join_token_secret_to_consume(&old, &new).as_deref(),
            Some("bootstrap-token-abcdef")
        );
    }

    #[test]
    fn approve_only_keeps_the_token_because_the_joiner_still_needs_it_to_fetch_the_certificate() {
        let old = join_csr(BOOTSTRAP_USER, KUBELET_CLIENT_SIGNER, false, "");
        let new = join_csr(BOOTSTRAP_USER, KUBELET_CLIENT_SIGNER, true, "");
        assert_eq!(join_token_secret_to_consume(&old, &new), None);
    }

    #[test]
    fn non_bootstrap_requestors_and_other_signers_never_delete_a_token_secret() {
        for (user, signer) in [
            ("system:node:n1", KUBELET_CLIENT_SIGNER),
            ("alice", KUBELET_CLIENT_SIGNER),
            ("system:bootstrap:", KUBELET_CLIENT_SIGNER),
            ("system:bootstrap:../x", KUBELET_CLIENT_SIGNER),
            (BOOTSTRAP_USER, CLIENT_SIGNER),
            (BOOTSTRAP_USER, "kubernetes.io/kubelet-serving"),
        ] {
            let old = join_csr(user, signer, true, "");
            let new = join_csr(user, signer, true, "Q0VSVA==");
            assert_eq!(
                join_token_secret_to_consume(&old, &new),
                None,
                "{user} / {signer}"
            );
        }
    }

    #[test]
    fn already_issued_certificate_does_not_consume_again_on_later_status_writes() {
        let old = join_csr(BOOTSTRAP_USER, KUBELET_CLIENT_SIGNER, true, "Q0VSVA==");
        let new = join_csr(BOOTSTRAP_USER, KUBELET_CLIENT_SIGNER, true, "Q0VSVA==");
        assert_eq!(join_token_secret_to_consume(&old, &new), None);
    }

    #[test]
    fn unapproved_or_denied_csr_with_a_certificate_does_not_consume_the_token() {
        let old = join_csr(BOOTSTRAP_USER, KUBELET_CLIENT_SIGNER, false, "");
        let new = join_csr(BOOTSTRAP_USER, KUBELET_CLIENT_SIGNER, false, "Q0VSVA==");
        assert_eq!(join_token_secret_to_consume(&old, &new), None);
        let mut denied = join_csr(BOOTSTRAP_USER, KUBELET_CLIENT_SIGNER, true, "Q0VSVA==");
        denied["status"]["conditions"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"type": "Denied", "status": "True"}));
        assert_eq!(join_token_secret_to_consume(&old, &denied), None);
    }

    async fn seed_join_token_and_csr(state: &AppState, csr_user: &str) {
        crate::handlers::test_support::grant_signer_verb(
            state,
            "signer",
            "sign",
            KUBELET_CLIENT_SIGNER,
        );
        let secret = serde_json::json!({
            "kind": "Secret",
            "metadata": {"name": "bootstrap-token-abcdef", "namespace": "kube-system"},
            "type": "bootstrap.kubernetes.io/token",
            "data": {}
        });
        let secret_key =
            crate::keys::object_key("secrets", "kube-system", "bootstrap-token-abcdef");
        state
            .store
            .put(
                &secret_key,
                bytes::Bytes::from(serde_json::to_vec(&secret).unwrap()),
                None,
            )
            .await
            .unwrap();
        let mut csr = join_csr(csr_user, KUBELET_CLIENT_SIGNER, true, "");
        csr["apiVersion"] = "certificates.k8s.io/v1".into();
        csr["kind"] = "CertificateSigningRequest".into();
        csr["spec"]["request"] = csr_b64_with_org(None).into();
        state
            .store
            .put(
                &group_object_key(GROUP, PLURAL, None, "c1"),
                bytes::Bytes::from(serde_json::to_vec(&csr).unwrap()),
                None,
            )
            .await
            .unwrap();
    }

    async fn token_secret_exists(state: &AppState) -> bool {
        let key = crate::keys::object_key("secrets", "kube-system", "bootstrap-token-abcdef");
        state.store.get(&key).await.unwrap().is_some()
    }

    #[tokio::test]
    async fn status_write_issuing_the_join_certificate_deletes_the_token_secret() {
        let state = make_state();
        seed_join_token_and_csr(&state, BOOTSTRAP_USER).await;
        status_put(
            &state,
            &user("signer"),
            "c1",
            serde_json::json!({"conditions": [approved()], "certificate": "Q0VSVA=="}),
        )
        .await
        .expect("signer writes the certificate");
        assert!(
            !token_secret_exists(&state).await,
            "a join token must die with its first issued certificate, or a leaked token joins nodes forever"
        );
    }

    #[tokio::test]
    async fn status_patch_issuing_the_join_certificate_deletes_the_token_secret() {
        let state = make_state();
        seed_join_token_and_csr(&state, BOOTSTRAP_USER).await;
        status_patch(
            &state,
            &user("signer"),
            "c1",
            serde_json::json!({"certificate": "Q0VSVA=="}),
        )
        .await
        .expect("signer patches the certificate");
        assert!(!token_secret_exists(&state).await);
    }

    #[tokio::test]
    async fn issuing_a_certificate_to_a_non_bootstrap_requestor_leaves_token_secrets_alone() {
        let state = make_state();
        seed_join_token_and_csr(&state, "system:node:n1").await;
        status_put(
            &state,
            &user("signer"),
            "c1",
            serde_json::json!({"conditions": [approved()], "certificate": "Q0VSVA=="}),
        )
        .await
        .expect("signer writes the certificate");
        assert!(
            token_secret_exists(&state).await,
            "a node's own cert rotation must not revoke an unrelated join token"
        );
    }

    #[tokio::test]
    async fn issuing_when_the_token_is_already_gone_still_succeeds() {
        let state = make_state();
        seed_join_token_and_csr(&state, BOOTSTRAP_USER).await;
        let key = crate::keys::object_key("secrets", "kube-system", "bootstrap-token-abcdef");
        state.store.delete(&key, None).await.unwrap();
        status_put(
            &state,
            &user("signer"),
            "c1",
            serde_json::json!({"conditions": [approved()], "certificate": "Q0VSVA=="}),
        )
        .await
        .expect("an expired or already-cleaned token must not fail certificate issuance");
    }

    #[tokio::test]
    async fn namespaced_status_path_cannot_write_a_cluster_scoped_csr_around_the_token_consumption_hook(
    ) {
        let state = make_state();
        seed_join_token_and_csr(&state, BOOTSTRAP_USER).await;
        let body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
            "metadata": {"name": "c1"},
            "status": {"conditions": [approved()], "certificate": "Q0VSVA=="}
        });
        let res = crate::handlers::status::put_namespaced_resource_status(
            State(state.clone()),
            Path((
                GROUP.into(),
                VERSION.into(),
                "x".into(),
                PLURAL.into(),
                "c1".into(),
            )),
            None,
            json_headers("application/json"),
            Bytes::from(body.to_string()),
        )
        .await;
        assert!(
            res.is_err(),
            "a namespaced /status path must not reach a cluster-scoped CSR"
        );
        assert!(
            stored_csr(&state, "c1").await["status"]["certificate"].is_null(),
            "the CSR must be untouched, or a certificate could be issued without consuming the token"
        );
    }

    /// Dropping the carried-over transition time would make a CSR look freshly approved
    /// every time a signer or controller rewrites its conditions.
    #[test]
    fn populate_timestamps_keeps_transition_for_unchanged_type_and_status_but_resets_on_flip() {
        let old = serde_json::json!({"status": {"conditions": [
            {"type": "Failed", "status": "True", "lastTransitionTime": "2020-01-01T00:00:00Z"}
        ]}});
        let mut new = serde_json::json!({"status": {"conditions": [
            {"type": "Failed", "status": "True", "lastUpdateTime": "2021-01-01T00:00:00Z"},
            {"type": "Failed", "status": "False"}
        ]}});
        populate_condition_timestamps(&mut new, &old, "2030-01-01T00:00:00Z");
        let c = &new["status"]["conditions"];
        assert_eq!(c[0]["lastTransitionTime"], "2020-01-01T00:00:00Z");
        assert_eq!(c[0]["lastUpdateTime"], "2021-01-01T00:00:00Z");
        assert_eq!(c[1]["lastTransitionTime"], "2030-01-01T00:00:00Z");
        assert_eq!(c[1]["lastUpdateTime"], "2030-01-01T00:00:00Z");
    }

    /// `kubectl get csr [name]` asks for a Table; the dedicated CSR GET/LIST handlers must honour
    /// it or kubectl falls back to NAME/AGE only.
    #[tokio::test]
    async fn get_and_list_csr_return_table_when_kubectl_asks_for_one() {
        let state = make_state();
        seed_csr_for_get(&state, "tbl").await;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json;as=Table;g=meta.k8s.io;v=v1"),
        );
        let body = |resp: Response| async move {
            let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&b).unwrap()
        };

        let resp = get_csr(State(state.clone()), Path("tbl".into()), headers.clone())
            .await
            .unwrap();
        let t = body(resp).await;
        assert_eq!(t["kind"], "Table");
        assert_eq!(t["columnDefinitions"][5]["name"], "Condition");
        assert_eq!(t["rows"][0]["cells"][5], "Pending");

        let resp = list_csr(
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
            Extension(user("x")),
            headers,
        )
        .await
        .unwrap();
        let t = body(resp).await;
        assert_eq!(t["kind"], "Table");
        assert_eq!(t["rows"][0]["cells"][0], "tbl");
    }

    /// Upstream silently preserves existing Approved/Denied conditions on /status; a caller
    /// without `sign` must not be able to rewrite the recorded approval time.
    #[tokio::test]
    async fn status_write_without_sign_cannot_alter_existing_condition_timestamps() {
        let state = make_state();
        let ts = "2020-01-01T00:00:00Z";
        let mk = |ty: &str, t: &str| {
            serde_json::json!({"type": ty, "status": "True",
                "lastUpdateTime": t, "lastTransitionTime": t})
        };
        seed_csr_with(
            &state,
            "ts2",
            CLIENT_SIGNER,
            serde_json::json!({"conditions": [mk("Approved", ts), mk("Failed", ts)]}),
        )
        .await;
        let nobody = user("nobody");
        let forged = "2030-01-01T00:00:00Z";
        status_put(
            &state,
            &nobody,
            "ts2",
            serde_json::json!({"conditions": [mk("Approved", forged), mk("Failed", forged)]}),
        )
        .await
        .expect("timestamp-only write is a no-op, not an error, as upstream");
        let c = &stored_csr(&state, "ts2").await["status"]["conditions"];
        for i in 0..2 {
            assert_eq!(c[i]["lastTransitionTime"], ts, "{c}");
            assert_eq!(c[i]["lastUpdateTime"], ts, "{c}");
        }
    }

    /// A signer adding a Failed condition through /status must get timestamps, like /approval.
    #[tokio::test]
    async fn status_write_adding_failed_condition_defaults_timestamps() {
        let state = make_state();
        let who = user("signer");
        crate::handlers::test_support::grant_signer_verb(&state, "signer", "sign", CLIENT_SIGNER);
        seed_csr_with(&state, "ts1", CLIENT_SIGNER, serde_json::json!({})).await;
        status_put(
            &state,
            &who,
            "ts1",
            serde_json::json!({"conditions": [{"type": "Failed", "status": "True"}]}),
        )
        .await
        .expect("status write");
        let s = stored_csr(&state, "ts1").await;
        let c = &s["status"]["conditions"][0];
        assert!(c["lastUpdateTime"].is_string(), "{c}");
        assert!(c["lastTransitionTime"].is_string(), "{c}");
    }

    /// A root, an intermediate under it, and a leaf under the intermediate, like what KCM
    /// signs: the leaf alone cannot be verified by a client that pins only the root.
    fn issued_by_intermediate(
        intermediate_cn: &str,
    ) -> (Vec<u8>, Vec<u8>, rcgen::Issuer<'static, rcgen::KeyPair>) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
        let ca = |cn: &str, constraint| {
            let mut p = CertificateParams::default();
            p.is_ca = IsCa::Ca(constraint);
            p.distinguished_name.push(DnType::CommonName, cn);
            p
        };
        let root_key = KeyPair::generate().unwrap();
        let root_params = ca("test-root", BasicConstraints::Unconstrained);
        let root = Issuer::new(root_params, root_key);
        let int_key = KeyPair::generate().unwrap();
        let int_params = ca(intermediate_cn, BasicConstraints::Constrained(0));
        let int_cert = int_params.clone().signed_by(&int_key, &root).unwrap();
        let int_issuer = Issuer::new(int_params, int_key);
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "system:node:n1");
        let leaf = leaf_params.signed_by(&leaf_key, &int_issuer).unwrap();
        (leaf.der().to_vec(), int_cert.der().to_vec(), int_issuer)
    }

    fn pem_b64(der: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(crate::tls::pem_encode("CERTIFICATE", der))
    }

    fn decoded_chain(certificate_b64: &str) -> Vec<Vec<u8>> {
        use base64::Engine as _;
        use rustls::pki_types::{pem::PemObject as _, CertificateDer};
        let pem = base64::engine::general_purpose::STANDARD
            .decode(certificate_b64)
            .unwrap();
        CertificateDer::pem_slice_iter(&pem)
            .map(|c| c.unwrap().to_vec())
            .collect()
    }

    /// KCM returns the bare leaf; a client that pins only the root can verify it only if the
    /// signing intermediate follows it, so the stored certificate must carry that chain.
    #[test]
    fn issued_certificate_gets_its_signing_intermediate_appended_once() {
        let (leaf, intermediate, _) = issued_by_intermediate("u7s-intermediate-a");
        let issued = pem_b64(&leaf);
        let chained = append_signing_chain(&issued, std::slice::from_ref(&intermediate))
            .expect("a leaf signed by a known intermediate must get the chain");
        assert_eq!(decoded_chain(&chained), vec![leaf, intermediate.clone()]);
        assert_eq!(
            append_signing_chain(&chained, &[intermediate]),
            None,
            "a certificate that already carries its intermediate must not be extended again"
        );
    }

    /// After a rotation KCM may still sign with the previous intermediate for a moment; the
    /// chain must name the one that actually signed, not simply the newest.
    #[test]
    fn chain_names_the_intermediate_that_signed_not_the_newest() {
        let (leaf, signer, _) = issued_by_intermediate("u7s-intermediate-old");
        let (_, newer, _) = issued_by_intermediate("u7s-intermediate-new");
        let chained = append_signing_chain(&pem_b64(&leaf), &[newer.clone(), signer.clone()])
            .expect("the older intermediate is still known");
        assert_eq!(decoded_chain(&chained)[1], signer);
        assert_eq!(
            append_signing_chain(&pem_b64(&leaf), &[newer]),
            None,
            "an intermediate that did not sign the leaf must never be appended"
        );
    }

    #[test]
    fn unparseable_certificate_is_left_untouched() {
        let (_, intermediate, _) = issued_by_intermediate("u7s-intermediate-a");
        assert_eq!(append_signing_chain("Zm9yZ2Vk", &[intermediate]), None);
    }

    #[tokio::test]
    async fn status_write_stores_the_certificate_with_the_signing_chain() {
        let (leaf, intermediate, _) = issued_by_intermediate("u7s-intermediate-a");
        for patch in [false, true] {
            let state = make_state();
            state
                .signing_intermediates
                .set(std::sync::Arc::new(vec![intermediate.clone()]));
            seed_csr_with(&state, "c1", CLIENT_SIGNER, serde_json::json!({})).await;
            let signer = user("signer");
            crate::handlers::test_support::grant_signer_verb(
                &state,
                "signer",
                "sign",
                CLIENT_SIGNER,
            );
            let status = serde_json::json!({"certificate": pem_b64(&leaf)});
            if patch {
                status_patch(&state, &signer, "c1", status).await
            } else {
                status_put(&state, &signer, "c1", status).await
            }
            .expect("signer writes the certificate");
            let stored = stored_csr(&state, "c1").await;
            assert_eq!(
                decoded_chain(stored["status"]["certificate"].as_str().unwrap()),
                vec![leaf.clone(), intermediate.clone()],
                "the stored certificate must carry the chain (patch={patch}): the kubelet \
                 writes it verbatim as its client cert and presents whatever it holds"
            );
        }
    }
}
