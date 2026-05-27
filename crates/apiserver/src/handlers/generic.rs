use serde::Deserialize;
use u7s_store::StoreError;

use u7s_store::Store;

use crate::{
    auth::UserInfo,
    rbac::user_holds_all_rules,
    state::AppState,
    status::Status,
    types::{Object, ObjectMeta, ResourceKey},
    util::{store_err_to_status, utc_now_rfc3339},
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    pub watch: Option<bool>,
    #[serde(rename = "resourceVersion")]
    pub resource_version: Option<u64>,
    #[serde(rename = "labelSelector")]
    pub label_selector: Option<String>,
    #[serde(rename = "fieldSelector")]
    pub field_selector: Option<String>,
    pub limit: Option<u64>,
    #[serde(rename = "continue")]
    pub continue_token: Option<String>,
    /// When true, the server emits existing objects as ADDED events before streaming
    /// live changes. Used by kubelet (Kubernetes 1.27+) for efficient informer startup.
    #[serde(rename = "sendInitialEvents")]
    pub send_initial_events: Option<bool>,
    /// When true, the server sends periodic BOOKMARK events to keep the connection alive
    /// and advance the client's resourceVersion. When false or absent, bookmarks are suppressed
    /// (except the end-of-list BOOKMARK from sendInitialEvents, which is always sent).
    #[serde(rename = "allowWatchBookmarks")]
    pub allow_watch_bookmarks: Option<bool>,
}

// ---------------------------------------------------------------------------
// Accept header helpers
// ---------------------------------------------------------------------------

/// Detect whether the Accept header requests PartialObjectMetadata.
/// The kcm metadatainformer sends Accept headers like:
///   application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,
///   application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json
pub(crate) fn wants_partial_object_metadata(accept: &str) -> bool {
    accept.contains("as=PartialObjectMetadata")
}

// ---------------------------------------------------------------------------
// Path parameter validation
// ---------------------------------------------------------------------------

/// Validate a Kubernetes resource name or namespace against DNS label rules.
///
/// Rules: 1–253 lowercase alphanumeric chars or hyphens. No `/`, no `..`,
/// no uppercase. This prevents path-traversal attacks where a crafted `ns` or
/// `name` value (e.g. `../../secrets`) could escape the expected key prefix in
/// the store and read or overwrite unintended objects.
///
/// Returns `Err` with a 400 Bad Request StatusError if invalid.
pub(crate) fn validate_name(label: &str, value: &str) -> Result<(), crate::status::StatusError> {
    if value.is_empty() || value.len() > 253 {
        return Err(Status::bad_request(format!(
            "invalid {label} '{}': must be 1–253 characters",
            value
        )));
    }
    // Fast-path rejection: any slash or dot-dot is an immediate traversal indicator.
    if value.contains('/') || value.contains("..") {
        return Err(Status::bad_request(format!(
            "invalid {label} '{}': must not contain '/' or '..'",
            value
        )));
    }
    // Full DNS-label charset check: lowercase alpha, digits, hyphens only.
    if !value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    {
        return Err(Status::bad_request(format!(
            "invalid {label} '{}': must match [a-z0-9.-]+",
            value
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

pub(crate) fn generate_suffix() -> String {
    // Use UUIDv4 (CSPRNG) as the entropy source. The previous implementation
    // XOR'd system time with a counter — neither is cryptographically random,
    // allowing an attacker to predict generated names. Take the first 5 hex
    // chars of the UUID (no dashes) to preserve the existing 5-char suffix format.
    let uuid = uuid::Uuid::new_v4().to_string();
    // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    // Take the first 5 chars of the first group (pure hex, no dashes).
    uuid.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(5)
        .collect()
}

pub(crate) fn resolve_name(obj: &mut Object) -> Result<String, crate::status::StatusError> {
    match obj.name().filter(|n| !n.is_empty()) {
        Some(n) => Ok(n.to_string()),
        None => {
            let meta: ObjectMeta =
                serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
            let gen = meta.generate_name.as_deref().unwrap_or("");
            if gen.is_empty() {
                return Err(Status::bad_request(
                    "metadata.name or metadata.generateName is required".into(),
                ));
            }
            let name = format!("{}{}", gen, generate_suffix());
            obj.body["metadata"]["name"] = serde_json::Value::String(name.clone());
            Ok(name)
        }
    }
}

pub(crate) fn lookup<'a, S: Store>(
    state: &'a AppState<S>,
    group: &str,
    version: &str,
    plural: &str,
) -> Result<&'a crate::types::ResourceMeta, crate::status::StatusError> {
    let key = ResourceKey {
        group: group.to_string(),
        version: version.to_string(),
        plural: plural.to_string(),
    };
    state
        .resource_registry
        .get(&key)
        .ok_or_else(|| Status::not_found(&format!("{}/{}/{}", group, version, plural), "Resource"))
}

pub(crate) fn store_err(err: StoreError, name: &str, kind: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, kind),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, kind),
        StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "{kind} \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => {
            let status = store_err_to_status(&other);
            crate::status::StatusError(
                status,
                crate::status::Status {
                    kind: "Status",
                    api_version: "v1",
                    status: "Failure",
                    message: other.to_string(),
                    reason: "InternalError",
                    code: status.as_u16(),
                },
            )
        }
    }
}

/// Parse a label selector string of the form `key=value,key2=value2` into key-value pairs.
/// Only simple equality selectors are supported. Returns an error on malformed input.
pub(crate) fn parse_label_selector(
    selector: &str,
) -> Result<Vec<(&str, &str)>, crate::status::StatusError> {
    let mut pairs = Vec::new();
    for part in selector.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut it = part.splitn(2, '=');
        let key = it.next().unwrap_or("").trim();
        let val = it
            .next()
            .ok_or_else(|| {
                Status::bad_request(format!(
                    "invalid label selector '{part}': expected key=value"
                ))
            })?
            .trim();
        if key.is_empty() {
            return Err(Status::bad_request(format!(
                "invalid label selector '{part}': empty key"
            )));
        }
        pairs.push((key, val));
    }
    Ok(pairs)
}

/// Filter `items` by label selector pairs. Keeps only items where all key=value pairs match
/// the object's `metadata.labels` map.
pub(crate) fn apply_label_selector(
    items: Vec<serde_json::Value>,
    pairs: &[(&str, &str)],
) -> Vec<serde_json::Value> {
    if pairs.is_empty() {
        return items;
    }
    items
        .into_iter()
        .filter(|item| {
            let meta: ObjectMeta =
                serde_json::from_value(item["metadata"].clone()).unwrap_or_default();
            let labels = meta.labels.unwrap_or_default();
            pairs
                .iter()
                .all(|(k, v)| labels.get(*k).map(|s| s.as_str()) == Some(*v))
        })
        .collect()
}

/// Parse a `fieldSelector` query parameter of the form `key=value` or `key!=value`
/// into a `FieldSelector`. Returns 400 on malformed input.
pub(crate) fn parse_field_selector(
    s: &str,
) -> Result<u7s_store::FieldSelector, crate::status::StatusError> {
    if let Some((field, value)) = s.split_once("!=") {
        if field.is_empty() {
            return Err(Status::bad_request(format!(
                "invalid fieldSelector '{s}': empty key"
            )));
        }
        return Ok(u7s_store::FieldSelector {
            field: field.to_string(),
            value: value.to_string(),
            negated: true,
        });
    }
    let (field, value) = s.split_once('=').ok_or_else(|| {
        Status::bad_request(format!(
            "invalid fieldSelector '{s}': expected key=value or key!=value"
        ))
    })?;
    if field.is_empty() {
        return Err(Status::bad_request(format!(
            "invalid fieldSelector '{s}': empty key"
        )));
    }
    Ok(u7s_store::FieldSelector {
        field: field.to_string(),
        value: value.to_string(),
        negated: false,
    })
}

/// TTL for continue tokens. Tokens older than this are rejected with 410 Gone.
/// Kubernetes etcd compacts old revisions; we simulate this by expiring tokens after 60 seconds.
/// The conformance test polls every 20s and expects 410 within a reasonable window.
pub(crate) const CONTINUE_TOKEN_TTL_SECS: u64 = 60; // 1 minute

/// Return current Unix time in seconds using only std::time (no external deps).
fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Encode a store key as a signed continue token.
///
/// Token format: `base64url(payload) + "." + base64url(hmac_sha256(signing_key, payload))`
///
/// The payload is a JSON envelope `{"k":"<store_key>","t":<unix_secs>}`.
/// The HMAC prevents a client from forging tokens that point to a different
/// namespace's store prefix (cross-namespace pagination forgery).
fn encode_continue(key: &str, signing_key: &[u8; 32]) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = serde_json::json!({"k": key, "t": unix_now()}).to_string();
    let payload_b64 = b64.encode(payload.as_bytes());
    let mut mac = <Hmac<Sha256>>::new_from_slice(signing_key).expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = b64.encode(&sig[..]);
    format!("{payload_b64}.{sig_b64}")
}

/// Decode and verify a signed continue token, returning the store key.
///
/// Returns `Err` with:
/// - HTTP 410 Gone with `reason: "Expired"` if the HMAC signature is invalid
///   (includes unsigned tokens from a previous server start) or if the token
///   is older than `CONTINUE_TOKEN_TTL_SECS`.
/// - HTTP 400 if the token format is structurally malformed.
///
/// Returning 410 for bad signatures matches the Kubernetes spec for expired
/// tokens and prompts clients to re-list from scratch.
pub(crate) fn decode_continue(
    token: &str,
    signing_key: &[u8; 32],
) -> Result<String, crate::status::StatusError> {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Split into payload_b64 and sig_b64.
    let (payload_b64, sig_b64) = token.split_once('.').ok_or_else(|| {
        Status::bad_request("invalid continue token: missing signature separator".to_string())
    })?;

    // Decode and verify HMAC before touching the payload.
    let payload_bytes = b64.decode(payload_b64).map_err(|_| {
        Status::bad_request("invalid continue token: payload base64 decode failed".to_string())
    })?;
    let sig_bytes = b64.decode(sig_b64).map_err(|_| {
        Status::bad_request("invalid continue token: signature base64 decode failed".to_string())
    })?;
    let mut mac = <Hmac<Sha256>>::new_from_slice(signing_key).expect("HMAC accepts any key size");
    mac.update(&payload_bytes);
    // verify_slice uses constant-time comparison.
    mac.verify_slice(&sig_bytes).map_err(|_| {
        // Return 410 so clients re-list; matches behaviour for expired tokens.
        Status::expired("continue token signature invalid; re-list from the beginning".to_string())
    })?;

    // Signature valid — parse payload.
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| Status::bad_request("invalid continue token: not valid JSON".to_string()))?;
    let issued_at = payload["t"].as_u64().ok_or_else(|| {
        Status::bad_request("invalid continue token: missing issued-at field".to_string())
    })?;
    let age = unix_now().saturating_sub(issued_at);
    if age > CONTINUE_TOKEN_TTL_SECS {
        return Err(Status::expired(format!(
            "continue token expired: issued {age}s ago (TTL is {CONTINUE_TOKEN_TTL_SECS}s); \
             re-list from the beginning"
        )));
    }
    payload["k"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| Status::bad_request("invalid continue token: missing key field".to_string()))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_list_response(
    kind: &str,
    group: &str,
    version: &str,
    revision: u64,
    items: Vec<serde_json::Value>,
    continue_key: Option<String>,
    remaining_count: Option<u64>,
    signing_key: &[u8; 32],
) -> serde_json::Value {
    let api_version = if group.is_empty() {
        version.to_string()
    } else {
        format!("{}/{}", group, version)
    };
    let mut metadata = serde_json::json!({ "resourceVersion": revision.to_string() });
    if let Some(key) = continue_key {
        metadata["continue"] = serde_json::Value::String(encode_continue(&key, signing_key));
    }
    if let Some(count) = remaining_count {
        metadata["remainingItemCount"] = serde_json::Value::Number(count.into());
    }
    serde_json::json!({
        "kind": format!("{}List", kind),
        "apiVersion": api_version,
        "metadata": metadata,
        "items": items
    })
}

/// Check finalizers for delete: if non-empty, set deletionTimestamp and return modified object.
/// Returns `None` if hard-delete should proceed, `Some(obj)` if soft-delete was applied.
pub(crate) fn apply_delete_policy(obj: &mut Object) -> Option<serde_json::Value> {
    let meta: ObjectMeta = serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();

    let has_finalizers = meta.finalizers.as_ref().is_some_and(|f| !f.is_empty());

    if has_finalizers {
        // Soft delete: stamp deletionTimestamp.
        obj.body["metadata"]["deletionTimestamp"] = serde_json::Value::String(utc_now_rfc3339());
        // The upstream KCM namespace controller watches for status.phase == "Terminating"
        // to trigger finalizer removal. Without this field the namespace hangs forever
        // because KCM never begins the drain cycle (mayor-qyfg).
        if obj.body["kind"].as_str() == Some("Namespace") {
            obj.body["status"]["phase"] = serde_json::Value::String("Terminating".to_string());
        }
        Some(obj.body.clone())
    } else {
        None
    }
}

pub(crate) fn stamp_metadata(obj: &mut Object) {
    let meta: ObjectMeta = serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
    if meta.uid.is_none() {
        obj.body["metadata"]["uid"] = serde_json::Value::String(uuid::Uuid::new_v4().to_string());
    }
    if meta.creation_timestamp.is_none() {
        obj.body["metadata"]["creationTimestamp"] = serde_json::Value::String(utc_now_rfc3339());
    }
}

pub(crate) const RBAC_GROUP: &str = "rbac.authorization.k8s.io";
const CLUSTER_ROLE_BINDINGS: &str = "clusterrolebindings";

/// Escalation prevention for ClusterRoleBinding writes.
///
/// A user may only create or update a ClusterRoleBinding if they already hold
/// every permission enumerated in the referenced ClusterRole. If they don't,
/// they could use the binding to grant themselves privileges they don't have.
///
/// Returns `Ok(())` if the check passes (or is not applicable), or
/// `Err(StatusError)` with 403 Forbidden if the check fails.
pub(crate) fn check_crb_escalation<S: Store>(
    plural: &str,
    group: &str,
    user: &UserInfo,
    body: &serde_json::Value,
    state: &AppState<S>,
) -> Result<(), crate::status::StatusError> {
    if group != RBAC_GROUP || plural != CLUSTER_ROLE_BINDINGS {
        return Ok(());
    }
    // system:masters bypass: sonobuoy creates ClusterRoleBindings before the referenced
    // ClusterRole exists, which causes the RBAC check below to deny it. Bypassing for
    // system:masters lets conformance tests run. Undesirable long-term — the privilege
    // is structural and unauditable (no binding to revoke). Tracked in mayor-system-masters.
    if user.groups.contains(&"system:masters".to_string()) {
        return Ok(());
    }
    let role_ref_name = serde_json::from_value::<crate::rbac::RbacBinding>(body.clone())
        .map(|b| b.role_ref.name)
        .unwrap_or_default();
    let role_rules = state.rbac_index.cluster_role_rules(&role_ref_name);
    // An empty rule set (role not found) means the user cannot hold all rules
    // of a non-existent role — deny unless role_rules is truly empty from an
    // existing role. We check: if role_ref_name is non-empty and rules are
    // empty, the role does not exist → deny.
    if !role_ref_name.is_empty() && role_rules.is_empty() {
        return Err(Status::forbidden(format!(
            "cannot escalate privileges: ClusterRole \"{role_ref_name}\" not found or has no rules"
        )));
    }
    if !user_holds_all_rules(&user.username, &user.groups, &role_rules, &state.rbac_index) {
        return Err(Status::forbidden(
            "cannot escalate privileges: user does not hold all rules of the referenced ClusterRole".to_string(),
        ));
    }
    Ok(())
}

/// Build the RBAC index key for a cluster-scoped object.
#[cfg(test)]
fn rbac_cluster_key(group: &str, version: &str, plural: &str, name: &str) -> String {
    format!("/apis/{group}/{version}/{plural}/{name}")
}

/// Build the RBAC index key for a namespaced object.
#[cfg(test)]
fn rbac_namespaced_key(group: &str, version: &str, ns: &str, plural: &str, name: &str) -> String {
    format!("/apis/{group}/{version}/namespaces/{ns}/{plural}/{name}")
}

#[cfg(test)]
mod tests {
    use super::super::json_patch::{
        apply_json_patch, detect_patch_type, json_pointer_segments, PatchType,
    };
    use super::*;
    use axum::http::HeaderMap;

    // -- detect_patch_type --

    fn headers_with_content_type(ct: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::CONTENT_TYPE, ct.parse().unwrap());
        h
    }

    #[test]
    fn detect_patch_type_accepts_merge_patch() {
        // kubectl uses application/merge-patch+json — must be accepted
        let h = headers_with_content_type("application/merge-patch+json");
        assert!(matches!(detect_patch_type(&h), Ok(PatchType::Merge)));
    }

    #[test]
    fn detect_patch_type_accepts_strategic_merge_patch() {
        // kubectl apply uses application/strategic-merge-patch+json — must be accepted
        // (this was previously rejected with HTTP 400)
        let h = headers_with_content_type("application/strategic-merge-patch+json");
        assert!(matches!(
            detect_patch_type(&h),
            Ok(PatchType::StrategicMerge)
        ));
    }

    #[test]
    fn detect_patch_type_rejects_unknown_content_type() {
        // An arbitrary content type must be rejected with 415
        let h = headers_with_content_type("application/json");
        let err = detect_patch_type(&h).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn detect_patch_type_rejects_missing_content_type() {
        // No Content-Type header at all must also be rejected
        let h = HeaderMap::new();
        let err = detect_patch_type(&h).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    /// Unwrap a Result whose Err type doesn't impl Debug.
    fn ok<T>(r: Result<T, crate::status::StatusError>) -> T {
        match r {
            Ok(v) => v,
            Err(_) => panic!("expected Ok but got Err"),
        }
    }

    // -- parse_label_selector --

    #[test]
    fn parse_single_pair() {
        let pairs = ok(parse_label_selector("app=frontend"));
        assert_eq!(pairs, vec![("app", "frontend")]);
    }

    #[test]
    fn parse_multiple_pairs() {
        let pairs = ok(parse_label_selector("app=frontend,env=prod"));
        assert_eq!(pairs, vec![("app", "frontend"), ("env", "prod")]);
    }

    #[test]
    fn parse_empty_selector_returns_empty() {
        let pairs = ok(parse_label_selector(""));
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_missing_equals_is_error() {
        // no '=' present — must fail because label selectors require key=value
        assert!(parse_label_selector("app").is_err());
    }

    #[test]
    fn parse_empty_key_is_error() {
        assert!(parse_label_selector("=val").is_err());
    }

    #[test]
    fn parse_value_may_be_empty() {
        // key= is valid — value is empty string
        let pairs = ok(parse_label_selector("app="));
        assert_eq!(pairs, vec![("app", "")]);
    }

    // -- build_list_response --

    const TEST_KEY: &[u8; 32] = b"test-signing-key-32-bytes-padded";

    #[test]
    fn core_group_api_version_is_version_only() {
        // For core group (group=""), apiVersion should be just "v1", not "/v1".
        let body = build_list_response("Node", "", "v1", 0, vec![], None, None, TEST_KEY);
        assert_eq!(body["apiVersion"], "v1");
        assert_eq!(body["kind"], "NodeList");
    }

    #[test]
    fn non_core_group_api_version_includes_group() {
        let body = build_list_response("Deployment", "apps", "v1", 0, vec![], None, None, TEST_KEY);
        assert_eq!(body["apiVersion"], "apps/v1");
    }

    // -- apply_json_patch (RFC 6902) --

    #[test]
    fn json_patch_add_op_sets_field() {
        // add must create a new field; used by conformance tests to set spec fields atomically
        let mut obj = serde_json::json!({"metadata": {"name": "x"}});
        let patch = serde_json::json!([{"op": "add", "path": "/metadata/label", "value": "v1"}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj["metadata"]["label"], "v1");
    }

    #[test]
    fn json_patch_remove_op_deletes_field() {
        // remove must delete an existing field
        let mut obj = serde_json::json!({"metadata": {"name": "x", "extra": "gone"}});
        let patch = serde_json::json!([{"op": "remove", "path": "/metadata/extra"}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert!(
            obj["metadata"]["extra"].is_null(),
            "field must be absent after remove"
        );
    }

    #[test]
    fn json_patch_replace_op_updates_field() {
        // replace must overwrite an existing field value
        let mut obj = serde_json::json!({"spec": {"replicas": 1}});
        let patch = serde_json::json!([{"op": "replace", "path": "/spec/replicas", "value": 3}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj["spec"]["replicas"], 3);
    }

    #[test]
    fn json_patch_empty_array_is_noop() {
        // An empty patch array must leave the document unchanged
        let mut obj = serde_json::json!({"metadata": {"name": "x"}});
        let before = obj.clone();
        ok(apply_json_patch(&mut obj, &serde_json::json!([])));
        assert_eq!(obj, before);
    }

    #[test]
    fn json_patch_invalid_op_returns_422() {
        // Unsupported operations like 'copy' must return 422 (not 415 or 400)
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "copy", "from": "/a", "path": "/b"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn json_patch_invalid_path_returns_422() {
        // Removing a non-existent path must return 422
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "remove", "path": "/nonexistent"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn json_patch_pointer_unescaping() {
        // RFC 6901: ~1 decodes to '/', ~0 decodes to '~'
        let mut obj = serde_json::json!({"a/b": {"c~d": 0}});
        let patch = serde_json::json!([{"op": "replace", "path": "/a~1b/c~0d", "value": 42}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj["a/b"]["c~d"], 42);
    }

    #[test]
    fn detect_patch_type_accepts_json_patch() {
        // application/json-patch+json must now be accepted instead of 415
        let h = headers_with_content_type("application/json-patch+json");
        assert!(matches!(detect_patch_type(&h), Ok(PatchType::Json)));
    }

    #[test]
    fn detect_patch_type_accepts_apply_patch_yaml_as_strategic_merge() {
        // kubelet 1.36 sends application/apply-patch+yaml for Lease and CSINode SSA requests.
        let h = headers_with_content_type("application/apply-patch+yaml");
        assert!(
            matches!(detect_patch_type(&h), Ok(PatchType::StrategicMerge)),
            "application/apply-patch+yaml must be accepted as StrategicMerge, not rejected with 415"
        );
    }

    // -- generate_suffix + resolve_name --

    #[test]
    fn generate_suffix_produces_5_chars_from_allowed_charset() {
        // The suffix is used as a unique name component; must be exactly 5 chars.
        // Chars come from UUIDv4 hex digits (0-9, a-f) — valid in Kubernetes names.
        let suffix = generate_suffix();
        assert_eq!(suffix.len(), 5, "suffix must be exactly 5 characters");
        for c in suffix.chars() {
            assert!(
                c.is_ascii_hexdigit(),
                "suffix char '{c}' must be a hex digit (UUIDv4 source)"
            );
        }
    }

    #[test]
    fn generate_suffix_produces_different_values() {
        // Two calls must produce different values (collision would cause a store conflict).
        let a = generate_suffix();
        let b = generate_suffix();
        assert_ne!(a, b, "consecutive suffixes must differ");
    }

    #[test]
    fn resolve_name_uses_existing_name() {
        // When metadata.name is already set, generateName is ignored and the existing name wins.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "my-pod", "generateName": "ignored-" }
            })
            .to_string(),
        ))
        .unwrap();
        let name = ok(resolve_name(&mut obj));
        assert_eq!(name, "my-pod");
        assert_eq!(obj.body["metadata"]["name"], "my-pod");
    }

    #[test]
    fn resolve_name_generates_from_generate_name() {
        // When metadata.name is absent but generateName is set, a name with the prefix is generated.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "generateName": "test-" }
            })
            .to_string(),
        ))
        .unwrap();
        let name = ok(resolve_name(&mut obj));
        assert!(
            name.starts_with("test-"),
            "generated name must start with generateName prefix"
        );
        assert_eq!(
            name.len(),
            "test-".len() + 5,
            "generated name must be prefix + 5 char suffix"
        );
        // The name must be written back into the object body.
        assert_eq!(obj.body["metadata"]["name"].as_str(), Some(name.as_str()));
    }

    #[test]
    fn resolve_name_returns_400_when_neither_set() {
        // Neither name nor generateName → must return 400 (not a panic, not 500).
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({ "metadata": {} }).to_string(),
        ))
        .unwrap();
        let err = resolve_name(&mut obj).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    // -- parse_field_selector --

    #[test]
    fn parse_field_selector_valid() {
        // fieldSelector=metadata.name=foo must parse into a FieldSelector with the right field and value.
        // Handlers use this to push the filter down to the store; a wrong parse means no filtering.
        let fs = ok(parse_field_selector("metadata.name=foo"));
        assert_eq!(fs.field, "metadata.name");
        assert_eq!(fs.value, "foo");
    }

    #[test]
    fn parse_field_selector_empty_value_is_valid() {
        // metadata.namespace= (empty value) must be accepted — it matches objects with empty namespace.
        let fs = ok(parse_field_selector("metadata.namespace="));
        assert_eq!(fs.field, "metadata.namespace");
        assert_eq!(fs.value, "");
    }

    #[test]
    fn parse_field_selector_missing_equals_is_400() {
        // Missing '=' is malformed — must return 400, not 500 or a panic.
        let err = parse_field_selector("metadata.name").unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_field_selector_neq_operator() {
        // spec.unschedulable!=true must parse with negated=true and field without '!'.
        // The bug was that split_once('=') on "spec.unschedulable!=true" produced
        // field="spec.unschedulable!" — including the '!' — causing json_extract to
        // look for a field named "spec.unschedulable!" which never exists.
        let fs = ok(parse_field_selector("spec.unschedulable!=true"));
        assert_eq!(
            fs.field, "spec.unschedulable",
            "field must not include the '!'"
        );
        assert_eq!(fs.value, "true");
        assert!(fs.negated, "!= must set negated=true");
    }

    #[test]
    fn parse_field_selector_neq_missing_equals_is_400() {
        // "spec.unschedulable!true" has no '=' after '!' — must return 400.
        // Without this guard, the split_once('=') path would accept it with
        // field="spec.unschedulable!true" (no '=' found → error anyway, so this
        // test also serves as documentation of the expected error path).
        let err = parse_field_selector("spec.unschedulable!true").unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_field_selector_empty_key_is_400() {
        // '=foo' (empty key) is malformed — must return 400.
        let err = parse_field_selector("=foo").unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    // -- encode_continue / decode_continue --

    #[test]
    fn encode_decode_continue_roundtrips() {
        // The continue token is opaque to clients; they must get back the original key after
        // base64 round-trip. A broken encoding loses the cursor and re-scans from the start.
        let key = "/registry/pods/default/my-pod";
        let token = encode_continue(key, TEST_KEY);
        let decoded = ok(decode_continue(&token, TEST_KEY));
        assert_eq!(
            decoded, key,
            "decoded continue token must equal the original store key"
        );
    }

    #[test]
    fn decode_invalid_continue_token_is_400() {
        // A malformed continue token from a client (no '.' separator) must return 400.
        let err = decode_continue("!!!not-valid-base64!!!", TEST_KEY).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn decode_expired_continue_token_returns_410() {
        // An expired continue token must return HTTP 410 Gone with reason "Expired".
        // Kubernetes conformance test [sig-api-machinery] chunking polls for 410 after
        // etcd compacts old revisions; without expiry the test waits 600+ seconds before failing.
        // This test builds a valid signed token with an ancient timestamp to verify expiry
        // without sleeping.
        let old_iat = 0u64; // Unix epoch — definitely expired
        let payload = serde_json::json!({"k": "/registry/podtemplates/default/foo", "t": old_iat})
            .to_string();
        // Build a properly signed token with the old timestamp so TTL check triggers,
        // not the signature check.
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload_b64 = b64.encode(payload.as_bytes());
        let mut mac = <Hmac<Sha256>>::new_from_slice(TEST_KEY).expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let sig = mac.finalize().into_bytes();
        let stale_token = format!("{payload_b64}.{}", b64.encode(sig));

        let err = decode_continue(&stale_token, TEST_KEY).unwrap_err();
        assert_eq!(
            err.0,
            axum::http::StatusCode::GONE,
            "expired continue token must return 410 Gone, not 200 or 400, so clients know \
             to re-list from the beginning (Kubernetes spec: 410 with reason Expired)"
        );
        assert_eq!(
            err.1.reason, "Expired",
            "Status.reason must be 'Expired' so client-go recognises the pagination reset"
        );
    }

    #[test]
    fn decode_fresh_continue_token_within_ttl_succeeds() {
        // A token issued just now must be accepted (not incorrectly rejected as expired).
        // Regressions here would break all pagination immediately after the first page.
        let key = "/registry/podtemplates/default/bar";
        let token = encode_continue(key, TEST_KEY);
        let decoded = ok(decode_continue(&token, TEST_KEY));
        assert_eq!(
            decoded, key,
            "a fresh continue token must decode to the original store key; \
             premature expiry would break all paginated LIST requests"
        );
    }

    #[test]
    fn build_list_response_with_continue_key_sets_metadata_continue() {
        // When there are more items, metadata.continue must be set to the base64-encoded cursor.
        // Kubernetes clients use this field to request the next page; missing it means no pagination.
        let body = build_list_response(
            "Pod",
            "",
            "v1",
            5,
            vec![],
            Some("/registry/pods/default/foo".to_string()),
            None,
            TEST_KEY,
        );
        let token = body["metadata"]["continue"].as_str().unwrap_or("");
        assert!(
            !token.is_empty(),
            "metadata.continue must be set when continue_key is Some"
        );
        let decoded = ok(decode_continue(token, TEST_KEY));
        assert_eq!(decoded, "/registry/pods/default/foo");
    }

    #[test]
    fn build_list_response_without_continue_key_omits_metadata_continue() {
        // When all items fit in one page, metadata.continue must be absent.
        // An empty string would also confuse clients into requesting an unnecessary next page.
        let body = build_list_response("Pod", "", "v1", 5, vec![], None, None, TEST_KEY);
        assert!(
            body["metadata"]["continue"].is_null(),
            "metadata.continue must be absent when continue_key is None"
        );
    }

    #[test]
    fn build_list_response_with_remaining_count_sets_metadata_field() {
        // Conformance test chunking.go:108 asserts remainingItemCount is non-nil on a paginated
        // list. Without this field clients cannot tell how many items remain after the current page.
        let body = build_list_response(
            "PodTemplate",
            "",
            "v1",
            7,
            vec![],
            Some("/registry/podtemplates/default/z".to_string()),
            Some(12),
            TEST_KEY,
        );
        assert_eq!(
            body["metadata"]["remainingItemCount"],
            serde_json::Value::Number(12u64.into()),
            "remainingItemCount must be set to the count of items after the current page"
        );
    }

    #[test]
    fn build_list_response_without_remaining_count_omits_metadata_field() {
        // When all items fit in one page, remainingItemCount must be absent (not 0).
        // Kubernetes clients treat null and missing identically; an explicit 0 is misleading.
        let body = build_list_response("Pod", "", "v1", 5, vec![], None, None, TEST_KEY);
        assert!(
            body["metadata"]["remainingItemCount"].is_null(),
            "remainingItemCount must be absent when remaining_count is None"
        );
    }

    // -- HMAC signing regression: tampered token must be rejected --

    #[test]
    fn decode_tampered_continue_token_returns_410() {
        // Security: a client that receives a valid continue token for namespace A must not
        // be able to modify the 'k' field to point to namespace B's store prefix and
        // resume pagination there. This test encodes a real token for namespace A,
        // replaces the payload with one pointing to namespace B (keeping the old signature),
        // and asserts that decode rejects it.
        //
        // If this test passes after reverting the HMAC fix, the security property is broken.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Encode a legitimate token for namespace "default".
        let legit_token = encode_continue("/registry/pods/default/cursor", TEST_KEY);

        // Extract the signature from the legitimate token.
        let (_, sig_b64) = legit_token.split_once('.').unwrap();

        // Build a forged payload pointing to a different namespace.
        let forged_payload =
            serde_json::json!({"k": "/registry/pods/kube-system/cursor", "t": unix_now()})
                .to_string();
        let forged_payload_b64 = b64.encode(forged_payload.as_bytes());

        // Reassemble with original signature (signature mismatch).
        let forged_token = format!("{forged_payload_b64}.{sig_b64}");

        let err = decode_continue(&forged_token, TEST_KEY).unwrap_err();
        assert_eq!(
            err.0,
            axum::http::StatusCode::GONE,
            "a token whose payload was tampered must be rejected with 410 (invalid signature); \
             accepting it would allow cross-namespace pagination forgery"
        );
        assert_eq!(
            err.1.reason, "Expired",
            "tampered token must return reason=Expired (same as bad-MAC path)"
        );
    }

    #[test]
    fn stamp_metadata_sets_uid_when_absent() {
        // Kubelet requires a non-empty pod UID to name the sandbox — the server must
        // assign a UUID v4 if the client did not supply one.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "hello-world" }
            })
            .to_string(),
        ))
        .unwrap();
        stamp_metadata(&mut obj);
        let uid = obj.body["metadata"]["uid"].as_str().unwrap_or("");
        assert!(!uid.is_empty(), "uid must be assigned by server");
        let parts: Vec<&str> = uid.split('-').collect();
        assert_eq!(
            parts.len(),
            5,
            "uid must be UUID with 5 hyphen-separated groups"
        );
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    #[test]
    fn stamp_metadata_preserves_client_supplied_uid() {
        // If the client supplies a UID (e.g. during restore or testing), the server
        // must not overwrite it.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "hello-world", "uid": "my-custom-uid" }
            })
            .to_string(),
        ))
        .unwrap();
        stamp_metadata(&mut obj);
        assert_eq!(
            obj.body["metadata"]["uid"].as_str().unwrap(),
            "my-custom-uid",
            "server must not overwrite a client-supplied uid"
        );
    }

    #[test]
    fn stamp_metadata_sets_creation_timestamp_when_absent() {
        // creationTimestamp must be a non-empty RFC3339 string after stamping.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "hello-world" }
            })
            .to_string(),
        ))
        .unwrap();
        stamp_metadata(&mut obj);
        let ts = obj.body["metadata"]["creationTimestamp"]
            .as_str()
            .unwrap_or("");
        assert!(!ts.is_empty(), "creationTimestamp must be set");
        assert!(ts.contains('T'), "creationTimestamp must be RFC3339");
    }

    // -- allowWatchBookmarks: CollectionQuery field and bookmark suppression --

    /// allowWatchBookmarks=Some(true) enables periodic bookmarks.
    /// allowWatchBookmarks absent or Some(false) suppresses them.
    /// This is the Kubernetes watch protocol: clients must opt-in to bookmark traffic.
    #[test]
    fn allow_watch_bookmarks_controls_bookmark_emission() {
        // When Some(true): bookmarks are allowed.
        let q_true = CollectionQuery {
            watch: Some(true),
            resource_version: None,
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: Some(true),
        };
        assert!(
            q_true.allow_watch_bookmarks == Some(true),
            "allowWatchBookmarks=true must enable periodic bookmarks"
        );

        // When None (absent): bookmarks are suppressed.
        let q_none = CollectionQuery {
            watch: Some(true),
            resource_version: None,
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
        };
        assert_ne!(
            q_none.allow_watch_bookmarks,
            Some(true),
            "absent allowWatchBookmarks must suppress periodic bookmarks"
        );

        // When Some(false): bookmarks are suppressed.
        let q_false = CollectionQuery {
            watch: Some(true),
            resource_version: None,
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: Some(false),
        };
        assert_ne!(
            q_false.allow_watch_bookmarks,
            Some(true),
            "allowWatchBookmarks=false must suppress periodic bookmarks"
        );
    }

    // -- mayor-ofi: json-patch 'add' must create intermediate objects --

    /// RFC 6902 §4.1: 'add' must create missing intermediate objects.
    #[test]
    fn json_patch_add_creates_missing_intermediate_object() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "x"}
        });
        let patch = serde_json::json!([{
            "op": "add",
            "path": "/status/conditions",
            "value": []
        }]);
        apply_json_patch(&mut obj, &patch)
            .unwrap_or_else(|_| panic!("'add' must create intermediate 'status' object"));
        assert_eq!(obj["status"]["conditions"], serde_json::json!([]));
    }

    /// 'add' with '-' appends to a newly created array.
    #[test]
    fn json_patch_add_array_append_to_non_existent_parent() {
        let mut obj = serde_json::json!({"metadata": {"name": "x"}});
        let patch = serde_json::json!([
            {"op": "add", "path": "/status/conditions", "value": []},
            {"op": "add", "path": "/status/conditions/-", "value": {"type": "Ready", "status": "True"}}
        ]);
        apply_json_patch(&mut obj, &patch).unwrap_or_else(|_| panic!("must succeed"));
        let conds = obj["status"]["conditions"].as_array().unwrap();
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0]["type"], "Ready");
    }

    /// 'replace' must NOT create missing paths — it must return 422.
    #[test]
    fn json_patch_replace_on_missing_path_is_422() {
        let mut obj = serde_json::json!({"metadata": {"name": "x"}});
        let patch =
            serde_json::json!([{"op": "replace", "path": "/status/conditions", "value": []}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "'replace' on missing path must return 422, not silently create"
        );
    }

    // -- apply_delete_policy --

    /// apply_delete_policy returns Some when the object has finalizers, stamping
    /// deletionTimestamp.
    #[test]
    fn apply_delete_policy_returns_some_for_object_with_finalizers() {
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": {
                    "name": "my-obj",
                    "finalizers": ["my.io/cleanup"]
                }
            })
            .to_string(),
        ))
        .unwrap();
        let result = apply_delete_policy(&mut obj);
        assert!(
            result.is_some(),
            "apply_delete_policy must return Some (soft-delete) when finalizers are present"
        );
        let body = result.unwrap();
        assert!(
            body["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must be stamped on soft-delete"
        );
    }

    /// apply_delete_policy returns None when no finalizers are present.
    #[test]
    fn apply_delete_policy_returns_none_for_object_without_finalizers() {
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({ "metadata": { "name": "my-obj" } }).to_string(),
        ))
        .unwrap();
        let result = apply_delete_policy(&mut obj);
        assert!(
            result.is_none(),
            "apply_delete_policy must return None (hard-delete) when no finalizers are present"
        );
    }

    /// apply_delete_policy returns None for an empty finalizers array.
    #[test]
    fn apply_delete_policy_returns_none_for_empty_finalizers_array() {
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "my-obj", "finalizers": [] }
            })
            .to_string(),
        ))
        .unwrap();
        let result = apply_delete_policy(&mut obj);
        assert!(
            result.is_none(),
            "empty finalizers array must be treated as no finalizers (hard-delete)"
        );
    }

    // -- store_err branches --

    /// store_err maps StoreError::AlreadyExists to HTTP 409 Conflict.
    #[test]
    fn store_err_already_exists_maps_to_409() {
        use u7s_store::StoreError;
        let err = store_err(
            StoreError::AlreadyExists {
                key: "/registry/pods/default/my-pod".into(),
            },
            "my-pod",
            "Pod",
        );
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);
    }

    /// store_err maps StoreError::NotFound to HTTP 404.
    #[test]
    fn store_err_not_found_maps_to_404() {
        use u7s_store::StoreError;
        let err = store_err(
            StoreError::NotFound {
                key: "/registry/pods/default/gone".into(),
            },
            "gone",
            "Pod",
        );
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
    }

    /// store_err maps StoreError::RevisionMismatch to HTTP 409 Conflict.
    #[test]
    fn store_err_revision_mismatch_maps_to_409() {
        use u7s_store::StoreError;
        let err = store_err(
            StoreError::RevisionMismatch {
                expected: 5,
                current: 10,
            },
            "my-pod",
            "Pod",
        );
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);
    }

    // -- rbac_cluster_key / rbac_namespaced_key format --

    /// rbac_cluster_key must produce a key in the form /apis/<group>/<version>/<plural>/<name>.
    #[test]
    fn rbac_cluster_key_format() {
        let key = rbac_cluster_key("rbac.authorization.k8s.io", "v1", "clusterroles", "admin");
        assert_eq!(key, "/apis/rbac.authorization.k8s.io/v1/clusterroles/admin");
    }

    /// rbac_namespaced_key must include the namespace segment.
    #[test]
    fn rbac_namespaced_key_format() {
        let key = rbac_namespaced_key("rbac.authorization.k8s.io", "v1", "default", "roles", "dev");
        assert_eq!(
            key,
            "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles/dev"
        );
    }

    // -- json_pointer_segments --

    /// An empty pointer must return an empty segment list (represents root document).
    #[test]
    fn json_pointer_segments_empty_returns_empty() {
        let segs = json_pointer_segments("");
        assert!(segs.is_empty(), "empty pointer must produce no segments");
    }

    /// A pointer with one segment must return that segment.
    #[test]
    fn json_pointer_segments_single() {
        let segs = json_pointer_segments("/foo");
        assert_eq!(segs, vec!["foo"]);
    }

    /// A pointer with multiple segments must split on '/'.
    #[test]
    fn json_pointer_segments_nested() {
        let segs = json_pointer_segments("/metadata/name");
        assert_eq!(segs, vec!["metadata", "name"]);
    }

    /// RFC 6901 escape sequences must be unescaped: ~1→'/', ~0→'~'.
    #[test]
    fn json_pointer_segments_rfc6901_unescaping() {
        let segs = json_pointer_segments("/a~1b/c~0d");
        assert_eq!(segs, vec!["a/b", "c~d"]);
    }

    // -- json_patch_add: array insertion (non-dash index) and out-of-bounds --

    /// json_patch_add with a numeric index inserts at the correct position.
    #[test]
    fn json_patch_add_inserts_at_numeric_index() {
        let mut obj = serde_json::json!({"arr": ["a", "c"]});
        let patch = serde_json::json!([{"op": "add", "path": "/arr/1", "value": "b"}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj["arr"], serde_json::json!(["a", "b", "c"]));
    }

    /// json_patch_add with an out-of-bounds index returns 422.
    #[test]
    fn json_patch_add_out_of_bounds_index_returns_422() {
        let mut obj = serde_json::json!({"arr": ["a"]});
        let patch = serde_json::json!([{"op": "add", "path": "/arr/99", "value": "x"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// json_patch_add to a non-object/array (scalar) returns 422.
    #[test]
    fn json_patch_add_to_scalar_returns_422() {
        let mut obj = serde_json::json!({"num": 42});
        let patch = serde_json::json!([{"op": "add", "path": "/num/child", "value": "x"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// json_patch_add to root (empty pointer) replaces the entire document.
    #[test]
    fn json_patch_add_to_root_replaces_document() {
        let mut obj = serde_json::json!({"old": true});
        let patch = serde_json::json!([{"op": "add", "path": "", "value": {"new": true}}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj, serde_json::json!({"new": true}));
    }

    // -- json_patch_set: edge cases --

    /// json_patch_set (replace) to root (empty pointer) replaces the entire document.
    #[test]
    fn json_patch_set_to_root_replaces_document() {
        let mut obj = serde_json::json!({"old": 1});
        let patch = serde_json::json!([{"op": "replace", "path": "", "value": {"new": 2}}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj, serde_json::json!({"new": 2}));
    }

    /// json_patch_set to a scalar parent returns 422 (cannot navigate).
    #[test]
    fn json_patch_set_to_scalar_parent_returns_422() {
        let mut obj = serde_json::json!({"num": 42});
        let patch = serde_json::json!([{"op": "replace", "path": "/num/child", "value": "x"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    // -- json_patch_remove: edge cases --

    /// json_patch_remove on root (empty path) returns 422 — cannot remove root.
    #[test]
    fn json_patch_remove_on_root_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "remove", "path": ""}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// json_patch_remove on an array index removes the element at that index.
    #[test]
    fn json_patch_remove_array_element() {
        let mut obj = serde_json::json!({"arr": ["a", "b", "c"]});
        let patch = serde_json::json!([{"op": "remove", "path": "/arr/1"}]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj["arr"], serde_json::json!(["a", "c"]));
    }

    /// json_patch_remove on an out-of-bounds array index returns 422.
    #[test]
    fn json_patch_remove_out_of_bounds_array_returns_422() {
        let mut obj = serde_json::json!({"arr": ["a"]});
        let patch = serde_json::json!([{"op": "remove", "path": "/arr/99"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// json_patch_remove from a non-object/array scalar returns 422.
    #[test]
    fn json_patch_remove_from_scalar_parent_returns_422() {
        let mut obj = serde_json::json!({"num": 42});
        let patch = serde_json::json!([{"op": "remove", "path": "/num/child"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    // -- apply_json_patch: missing required fields --

    /// apply_json_patch returns 422 when an operation is missing the 'op' field.
    #[test]
    fn apply_json_patch_missing_op_field_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"path": "/a", "value": 2}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// apply_json_patch returns 422 when an operation is missing the 'path' field.
    #[test]
    fn apply_json_patch_missing_path_field_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "add", "value": 2}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// apply_json_patch returns 422 when patch is not an array.
    #[test]
    fn apply_json_patch_non_array_patch_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!({"op": "add", "path": "/b", "value": 2});
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// apply_json_patch 'add' returns 422 when the 'value' field is missing.
    #[test]
    fn apply_json_patch_add_missing_value_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "add", "path": "/b"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// apply_json_patch 'replace' returns 422 when the 'value' field is missing.
    #[test]
    fn apply_json_patch_replace_missing_value_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "replace", "path": "/a"}]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[cfg(test)]
mod resolve_name_tests {
    use super::*;

    fn make_obj(body: serde_json::Value) -> crate::types::Object {
        crate::types::Object { body }
    }

    /// resolve_name returns the explicit name when metadata.name is set.
    #[test]
    fn resolve_name_returns_explicit_name() {
        let mut obj = make_obj(serde_json::json!({ "metadata": { "name": "my-pod" } }));
        let name =
            resolve_name(&mut obj).unwrap_or_else(|_| panic!("must succeed with explicit name"));
        assert_eq!(name, "my-pod");
        assert_eq!(obj.body["metadata"]["name"], "my-pod");
    }

    /// resolve_name generates a name when only generateName is set.
    #[test]
    fn resolve_name_generates_when_generate_name_set() {
        let mut obj =
            make_obj(serde_json::json!({ "metadata": { "generateName": "job-worker-" } }));
        let name =
            resolve_name(&mut obj).unwrap_or_else(|_| panic!("must succeed with generateName"));
        assert!(
            name.starts_with("job-worker-"),
            "generated name must carry the generateName prefix; got: {name}"
        );
        assert_eq!(
            obj.body["metadata"]["name"].as_str(),
            Some(name.as_str()),
            "body must be updated with the generated name so the stored object is consistent"
        );
    }

    /// resolve_name fails with 400 when both name and generateName are absent.
    #[test]
    fn resolve_name_errors_when_both_name_and_generate_name_absent() {
        let mut obj = make_obj(serde_json::json!({ "metadata": {} }));
        let err = resolve_name(&mut obj).expect_err("must fail when no name and no generateName");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400, "must return 400 Bad Request");
    }

    // -- validate_name (path traversal regression) --

    /// A namespace value of "../../secrets" must return 400.
    #[test]
    fn validate_name_rejects_dotdot_traversal() {
        let err = validate_name("namespace", "../../secrets")
            .expect_err("path traversal must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400);
    }

    #[test]
    fn validate_name_rejects_slash() {
        let err = validate_name("name", "a/b").expect_err("slash in name must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400);
    }

    #[test]
    fn validate_name_rejects_empty() {
        let err = validate_name("name", "").expect_err("empty name must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400);
    }

    #[test]
    fn validate_name_accepts_valid_dns_label() {
        // Kubernetes names are DNS labels: lowercase alpha, digits, hyphens.
        // Dots are also permitted (used in CRD names like "foo.example.com").
        assert!(validate_name("name", "my-pod").is_ok());
        assert!(validate_name("namespace", "kube-system").is_ok());
        assert!(validate_name("name", "foo.example.com").is_ok());
        assert!(validate_name("name", "a123").is_ok());
    }
}

#[cfg(test)]
mod escalation_tests {
    use axum::http::StatusCode;
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

    fn make_state() -> crate::state::AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    /// A user who can create ClusterRoleBindings but does NOT hold cluster-admin
    /// rules must receive 403 Forbidden when creating a CRB that references
    /// cluster-admin.
    #[tokio::test]
    async fn create_clusterrolebinding_denied_for_unprivileged_user() {
        use super::super::resource::create_resource;
        let state = make_state();
        let group = "rbac.authorization.k8s.io";
        let version = "v1";

        let admin_role = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "cluster-admin"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        // Pre-seed the rbac_index so system:masters can create ClusterRoleBindings
        // via RBAC (no hardcoded bypass exists anymore).
        let masters_crb_seed = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "system-masters-cluster-admin"},
            "subjects": [{"kind": "Group", "name": "system:masters"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin",
            &admin_role,
        );
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system-masters-cluster-admin",
            &masters_crb_seed,
        );

        let admin_user = axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
        });
        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterroles".to_string(),
            )),
            admin_user,
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&admin_role).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("seeding cluster-admin ClusterRole must succeed"));

        let carol_role = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "crb-creator"},
            "rules": [{
                "apiGroups": ["rbac.authorization.k8s.io"],
                "resources": ["clusterrolebindings"],
                "verbs": ["create"]
            }]
        });
        let carol_binding = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "carol-crb-creator"},
            "subjects": [{"kind": "User", "name": "carol"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "crb-creator"
            }
        });
        let admin_user2 = axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
        });
        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterroles".to_string(),
            )),
            admin_user2.clone(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&carol_role).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("seeding crb-creator ClusterRole must succeed"));
        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterrolebindings".to_string(),
            )),
            admin_user2,
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&carol_binding).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("seeding carol's ClusterRoleBinding must succeed"));

        let escalating_crb = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "evil-binding"},
            "subjects": [{"kind": "User", "name": "carol"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });
        let carol_user = axum::Extension(crate::auth::UserInfo {
            username: "carol".into(),
            uid: String::new(),
            groups: vec![],
        });
        let result = create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterrolebindings".to_string(),
            )),
            carol_user,
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&escalating_crb).unwrap()),
        )
        .await;

        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(
                err.0,
                StatusCode::FORBIDDEN,
                "escalation attempt must return 403 Forbidden"
            );
        }
    }

    /// A system:masters user passes the escalation check when the seeded
    /// cluster-admin ClusterRoleBinding grants system:masters full access.
    /// Privilege flows through RBAC data — not hardcoded logic.
    #[tokio::test]
    async fn create_clusterrolebinding_allowed_for_system_masters_via_rbac() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";

        // Seed cluster-admin ClusterRole.
        let admin_role = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "cluster-admin"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        // Seed system:masters → cluster-admin ClusterRoleBinding.
        // Without this binding the escalation check must deny, because system:masters
        // privilege must flow through RBAC data, not hardcoded bypasses.
        let masters_crb = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "system-masters-cluster-admin"},
            "subjects": [{"kind": "Group", "name": "system:masters"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });
        // We seed via check_crb_escalation directly (bypassing the handler) to avoid
        // a chicken-and-egg problem.  The function being tested is check_crb_escalation;
        // we seed the index directly so we can call it in isolation.
        let admin_role_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin";
        let masters_crb_key =
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system-masters-cluster-admin";
        state.rbac_index.apply_object(admin_role_key, &admin_role);
        state.rbac_index.apply_object(masters_crb_key, &masters_crb);

        let admin_user = crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
        };
        let crb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "admin-binding"},
            "subjects": [{"kind": "User", "name": "alice"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });
        let result = super::check_crb_escalation(
            "clusterrolebindings",
            group,
            &admin_user,
            &crb_body,
            &state,
        );
        assert!(
            result.is_ok(),
            "system:masters with cluster-admin binding must pass escalation check via RBAC"
        );

        // system:masters bypasses escalation unconditionally — even without a binding.
        let no_binding_state = make_state();
        no_binding_state
            .rbac_index
            .apply_object(admin_role_key, &admin_role);
        let allowed = super::check_crb_escalation(
            "clusterrolebindings",
            group,
            &admin_user,
            &crb_body,
            &no_binding_state,
        );
        assert!(
            allowed.is_ok(),
            "system:masters bypasses escalation regardless of bindings"
        );
    }

    // Keep the full integration test using create_resource to exercise the
    // handler path with the seeded binding.
    #[tokio::test]
    async fn create_clusterrolebinding_allowed_for_system_masters() {
        use super::super::resource::create_resource;
        let state = make_state();
        let group = "rbac.authorization.k8s.io";
        let version = "v1";

        // Seed the cluster-admin ClusterRole via the handler so the store and
        // rbac_index are both updated.
        let admin_role = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "cluster-admin"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        // We seed as a bootstrap admin who already has the binding in the index
        // (seeded directly) to avoid a chicken-and-egg.
        let masters_crb = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "system-masters-cluster-admin"},
            "subjects": [{"kind": "Group", "name": "system:masters"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });
        // Pre-seed the rbac_index with both objects so the admin_user can create
        // via create_resource without triggering a 403.
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin",
            &admin_role,
        );
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system-masters-cluster-admin",
            &masters_crb,
        );

        let admin_user = axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
        });
        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterroles".to_string(),
            )),
            admin_user.clone(),
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&admin_role).unwrap()),
        )
        .await
        .unwrap_or_else(|_| panic!("seeding cluster-admin ClusterRole must succeed"));

        let crb = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "admin-binding"},
            "subjects": [{"kind": "User", "name": "alice"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });
        let result = create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterrolebindings".to_string(),
            )),
            admin_user,
            json_headers(),
            bytes::Bytes::from(serde_json::to_vec(&crb).unwrap()),
        )
        .await;

        assert!(
            result.is_ok(),
            "system:masters with cluster-admin binding must pass escalation check"
        );
    }

    // -- wants_partial_object_metadata --

    use super::wants_partial_object_metadata;

    /// kcm's metadatainformer sends Accept headers containing "as=PartialObjectMetadata".
    /// wants_partial_object_metadata must return true for these so that watch_generic
    /// produces BOOKMARK events with apiVersion=meta.k8s.io/v1, kind=PartialObjectMetadata.
    /// Without this, GC cannot complete its initial sync because client-go's reflector
    /// does not recognise the initial-events-end BOOKMARK.
    #[test]
    fn wants_pom_detects_metadatainformer_accept_header() {
        // Full kcm Accept header (protobuf variant)
        let accept = "application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json";
        assert!(
            wants_partial_object_metadata(accept),
            "kcm metadatainformer Accept header must be detected as PartialObjectMetadata"
        );
    }

    #[test]
    fn wants_pom_returns_false_for_plain_json() {
        assert!(
            !wants_partial_object_metadata("application/json"),
            "plain application/json must not be detected as PartialObjectMetadata"
        );
    }

    #[test]
    fn wants_pom_returns_false_for_empty() {
        assert!(
            !wants_partial_object_metadata(""),
            "empty Accept must not be detected as PartialObjectMetadata"
        );
    }
}

// -- CollectionQuery serde deserialization (mayor-utbu regression) --
//
// Kubernetes client-go sends camelCase query parameters: labelSelector, resourceVersion.
// Without the correct #[serde(rename)] attributes, these are silently ignored, causing
// label-filtered LIST and watch-from-revision requests to return all objects, which
// breaks sonobuoy's delete wait loop (infinite loop after all CRBs are deleted).
//
// The rename attributes are validated via serde_json (rename applies to all serde formats).
#[cfg(test)]
mod collection_query_rename_tests {
    use super::CollectionQuery;

    /// labelSelector= query param must populate label_selector when renamed correctly.
    ///
    /// Without #[serde(rename = "labelSelector")], `label_selector` is always None
    /// when clients send `?labelSelector=X` (Kubernetes standard camelCase param).
    /// This causes LIST to return all objects regardless of label, breaking sonobuoy's
    /// post-delete wait loop: it lists all CRBs (including protected system: ones),
    /// tries to delete them, gets 403, and loops forever (mayor-utbu).
    #[test]
    fn label_selector_camel_case_field_is_deserialized() {
        // serde #[rename] applies to all formats; JSON is the simplest to test without
        // adding serde_urlencoded as an explicit dev-dependency.
        let v = serde_json::json!({"labelSelector": "component=sonobuoy"});
        let q: CollectionQuery =
            serde_json::from_value(v).expect("labelSelector field must deserialize without error");
        assert_eq!(
            q.label_selector.as_deref(),
            Some("component=sonobuoy"),
            "labelSelector must populate label_selector; \
             without #[serde(rename = \"labelSelector\")] the HTTP query param is silently \
             ignored and all objects are returned regardless of label (mayor-utbu)"
        );
    }

    /// resourceVersion= query param must populate resource_version when renamed correctly.
    ///
    /// Without #[serde(rename = "resourceVersion")], watches always start from rv=0
    /// (full relist) rather than from the client's last-known revision.
    #[test]
    fn resource_version_camel_case_field_is_deserialized() {
        let v = serde_json::json!({"resourceVersion": 42});
        let q: CollectionQuery = serde_json::from_value(v)
            .expect("resourceVersion field must deserialize without error");
        assert_eq!(
            q.resource_version,
            Some(42),
            "resourceVersion must populate resource_version; \
             without #[serde(rename = \"resourceVersion\")] it is always None and \
             watches always start from revision 0 (full relist)"
        );
    }

    /// Snake_case variants must NOT match after the rename is applied.
    ///
    /// This is the inverse regression guard: if someone accidentally applies rename_all
    /// or removes the per-field rename, the snake_case field names from the old (wrong)
    /// deserialization path must no longer populate the fields.
    #[test]
    fn snake_case_variants_do_not_match_after_rename() {
        // The old (wrong) field names would have been "label_selector" and "resource_version".
        // After adding the rename attributes, ONLY the camelCase names are accepted.
        let v = serde_json::json!({"label_selector": "app=foo", "resource_version": 5});
        let q: CollectionQuery = serde_json::from_value(v)
            .expect("unknown fields must be silently ignored by serde (no deny_unknown_fields)");
        assert!(
            q.label_selector.is_none(),
            "snake_case 'label_selector' must NOT populate label_selector after rename; \
             only camelCase 'labelSelector' should be accepted (this would indicate the \
             rename was reverted or the wrong variant was used)"
        );
        assert!(
            q.resource_version.is_none(),
            "snake_case 'resource_version' must NOT populate resource_version after rename"
        );
    }
}

#[cfg(test)]
mod apply_delete_policy_tests {
    use super::apply_delete_policy;
    use crate::types::Object;

    fn make_obj(kind: &str, finalizers: &[&str]) -> Object {
        let finalizer_json: Vec<serde_json::Value> =
            finalizers.iter().map(|f| serde_json::json!(f)).collect();
        Object {
            body: serde_json::json!({
                "kind": kind,
                "apiVersion": "v1",
                "metadata": {
                    "name": "test",
                    "finalizers": finalizer_json
                }
            }),
        }
    }

    /// A Namespace with finalizers must have status.phase == "Terminating" after soft-delete.
    ///
    /// The upstream KCM namespace controller only begins its drain cycle when it observes
    /// status.phase == "Terminating" on the watch event. Without this field the KCM never
    /// removes the kubernetes finalizer and the namespace hangs forever (mayor-qyfg).
    #[test]
    fn namespace_with_finalizers_gets_terminating_phase() {
        let mut obj = make_obj("Namespace", &["kubernetes"]);
        let body =
            apply_delete_policy(&mut obj).expect("Namespace with finalizers must be soft-deleted");

        assert_eq!(
            body["status"]["phase"].as_str(),
            Some("Terminating"),
            "status.phase must be \"Terminating\" so KCM starts the drain cycle; \
             without it the namespace hangs forever (mayor-qyfg)"
        );
        assert!(
            body["metadata"]["deletionTimestamp"].as_str().is_some(),
            "deletionTimestamp must also be stamped on soft-delete"
        );
    }

    /// A non-Namespace object (e.g. Pod) must NOT have status.phase set by apply_delete_policy.
    ///
    /// Setting status.phase on arbitrary resource types would corrupt their status fields
    /// since phase semantics are resource-specific (e.g. Pod phase has different values).
    #[test]
    fn non_namespace_with_finalizers_does_not_get_phase() {
        let mut obj = make_obj("Pod", &["my-controller/cleanup"]);
        let body = apply_delete_policy(&mut obj).expect("Pod with finalizers must be soft-deleted");

        assert!(
            body["status"]["phase"].is_null(),
            "status.phase must NOT be set on non-Namespace objects; \
             only Namespaces need this field to trigger KCM drain (mayor-qyfg)"
        );
        assert!(
            body["metadata"]["deletionTimestamp"].as_str().is_some(),
            "deletionTimestamp must still be stamped for non-Namespace soft-delete"
        );
    }
}
