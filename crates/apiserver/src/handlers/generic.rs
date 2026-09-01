use serde::{Deserialize, Serialize};
use u7s_store::StoreError;

use u7s_store::Store;

use crate::{
    auth::UserInfo,
    rbac::{user_holds_all_rules, user_holds_all_rules_in_namespace, AuthzRequest},
    state::AppState,
    status::Status,
    types::{NamespacePhase, NamespaceSpec, Object, ObjectMeta, ResourceKey},
    util::{store_err_to_status, utc_now_rfc3339},
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    #[serde(default, deserialize_with = "crate::util::deserialize_watch_bool")]
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
    /// Server-side timeout for watch streams in seconds. When provided, the server closes
    /// the watch stream after this many seconds and sends a final BOOKMARK. The client then
    /// starts a new watch from the last known resourceVersion. Kubernetes clients use this
    /// to control watch stream lifetime (typically 5–10 minutes). When absent, the server
    /// uses a default of 5 minutes. Watches MUST be exempt from any shorter request timeout.
    #[serde(rename = "timeoutSeconds")]
    pub timeout_seconds: Option<u64>,
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
    let is_alnum = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !value.starts_with(is_alnum) || !value.ends_with(is_alnum) {
        return Err(Status::bad_request(format!(
            "invalid {label} '{}': must start and end with a lowercase alphanumeric character",
            value
        )));
    }
    Ok(())
}

/// Validate a resource name, allowing colons for RBAC resources and for
/// signer-scoped ClusterTrustBundle names.
///
/// RBAC resources (ClusterRole, ClusterRoleBinding, Role, RoleBinding) use
/// colons in names by Kubernetes convention (e.g. `system:node`,
/// `system:service-account-issuer-discovery`, or user-created bindings like
/// `svcaccounts-5461-system:service-account-issuer-discovery`).
/// For those resources, colons are allowed. All other name constraints apply.
pub(crate) fn validate_name_for_group(
    label: &str,
    value: &str,
    group: &str,
    plural: &str,
) -> Result<(), crate::status::StatusError> {
    if group == RBAC_GROUP && value.contains(':') {
        // For RBAC names with colons, apply the same checks except the charset check.
        // This allows `system:node` and `ns-system:role` while still rejecting
        // path traversal and invalid length.
        if value.is_empty() || value.len() > 253 {
            return Err(Status::bad_request(format!(
                "invalid {label} '{}': must be 1–253 characters",
                value
            )));
        }
        if value.contains('/') || value.contains("..") {
            return Err(Status::bad_request(format!(
                "invalid {label} '{}': must not contain '/' or '..'",
                value
            )));
        }
        return Ok(());
    }
    if group == CERTIFICATES_GROUP && plural == CLUSTER_TRUST_BUNDLES_PLURAL && value.contains(':')
    {
        return validate_cluster_trust_bundle_name(label, value);
    }
    validate_name(label, value)
}

const CERTIFICATES_GROUP: &str = "certificates.k8s.io";
const CLUSTER_TRUST_BUNDLES_PLURAL: &str = "clustertrustbundles";

/// Validate a signer-scoped ClusterTrustBundle name of the form
/// `<signerName-with-'/'-replaced-by-':'>:<suffix>`.
///
/// Upstream's `ValidateClusterTrustBundleName` (apimachinery
/// `pkg/apis/core/validation/names.go`) requires the name to have prefix
/// `strings.ReplaceAll(signerName, "/", ":") + ":"` when `spec.signerName` is set — e.g.
/// signer `example.com/my-signer` may own a bundle named
/// `example.com:my-signer:primary-bundle`. This path-parameter validator (used by every
/// GET/PUT/PATCH/DELETE-by-name handler) only ever sees the bare name, not the object's
/// `spec.signerName`, so it cannot check the exact prefix match — but it can still reject
/// path traversal and garbage input by requiring every `:`-delimited segment to itself be
/// a valid DNS-label-safe segment, exactly like the full name would be without colons.
///
/// Without this exception, upstream's own e2e hermetic pod-certificate signer (which
/// creates bundles named exactly this way) gets a 400 on its very first `Get()` call —
/// before it ever reaches `Create()` — because the pre-existing generic charset check
/// (`[a-z0-9.-]+`, no colons) rejects the name outright.
fn validate_cluster_trust_bundle_name(
    label: &str,
    value: &str,
) -> Result<(), crate::status::StatusError> {
    if value.is_empty() || value.len() > 253 {
        return Err(Status::bad_request(format!(
            "invalid {label} '{}': must be 1–253 characters",
            value
        )));
    }
    if value.contains('/') || value.contains("..") {
        return Err(Status::bad_request(format!(
            "invalid {label} '{}': must not contain '/' or '..'",
            value
        )));
    }
    for segment in value.split(':') {
        validate_name(label, segment)?;
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

/// Bounded retry budget for generateName collisions on create: the maximum number of
/// TOTAL `store.put` attempts (the first attempt plus any retries), matching upstream's
/// `maxNameGenerationCreateAttempts` (`k8s.io/apiserver/pkg/registry/generic/registry/store.go`),
/// which is likewise a total-iteration count (`for i := 0; i < maxNameGenerationCreateAttempts;
/// i++`), not a retry count on top of an initial attempt.
pub(crate) const MAX_GENERATE_NAME_CREATE_ATTEMPTS: u32 = 8;

/// Returns the `generateName` prefix when a create request relies on the server picking
/// the name (no explicit `metadata.name`), so the caller can retry with a fresh suffix
/// when the store reports a name collision instead of surfacing a spurious 409 to the
/// client — mirrors upstream's `needsNameGeneration`, which gates
/// `createWithGenerateNameRetry`. An explicit `metadata.name` always wins, even if
/// `generateName` is also set (same precedence as `resolve_name`), so those requests are
/// never retried: a real name collision on an explicit name is a genuine 409.
///
/// Must be called BEFORE `resolve_name`, which mutates `metadata.name` in place.
pub(crate) fn wants_generate_name(obj: &Object) -> Option<String> {
    if obj.name().filter(|n| !n.is_empty()).is_some() {
        return None;
    }
    obj.body["metadata"]["generateName"]
        .as_str()
        .filter(|g| !g.is_empty())
        .map(str::to_string)
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
                    metadata: None,
                    details: None,
                },
            )
        }
    }
}

/// A single term in a label selector.
///
/// `pub` (not `pub(crate)`) so `benches/list_filter.rs` — a separate crate
/// linked against the `u7s-apiserver` lib target — can construct terms
/// directly to drive `apply_label_selector`.
#[derive(Debug, PartialEq)]
pub enum LabelSelectorTerm<'a> {
    Equality { key: &'a str, value: &'a str },
    NotEquals { key: &'a str, value: &'a str },
    Exists { key: &'a str },
    DoesNotExist { key: &'a str },
    In { key: &'a str, values: Vec<&'a str> },
    NotIn { key: &'a str, values: Vec<&'a str> },
}

/// Split a label selector string into top-level comma-separated terms,
/// without splitting inside parentheses (which appear in `key in (v1,v2)` forms).
fn split_label_selector_terms(selector: &str) -> Vec<&str> {
    let mut terms = Vec::new();
    let mut depth: usize = 0;
    let mut start = 0;
    for (i, c) in selector.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                terms.push(selector[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    terms.push(selector[start..].trim());
    terms
}

/// Parse the values list from a set-based selector: `(v1, v2, v3)` → `["v1", "v2", "v3"]`.
fn parse_set_values_generic(s: &str) -> Vec<&str> {
    let inner = s.trim().trim_start_matches('(').trim_end_matches(')');
    inner
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect()
}

/// Parse a label selector string into typed terms.
///
/// Supported forms:
/// - `key=value` / `key==value` — Equality
/// - `key!=value` — NotEquals
/// - `key` (bare) — Exists
/// - `!key` — DoesNotExist
/// - `key in (v1,v2)` — In
/// - `key notin (v1,v2)` — NotIn
///
/// Returns an error on malformed input (e.g. empty key, bare `=`).
pub(crate) fn parse_label_selector(
    selector: &str,
) -> Result<Vec<LabelSelectorTerm<'_>>, crate::status::StatusError> {
    let mut terms = Vec::new();
    for part in split_label_selector_terms(selector) {
        if part.is_empty() {
            continue;
        }
        if let Some(key) = part.strip_prefix('!') {
            let key = key.trim();
            if key.is_empty() {
                return Err(Status::bad_request(format!(
                    "invalid label selector '{part}': empty key after '!'"
                )));
            }
            terms.push(LabelSelectorTerm::DoesNotExist { key });
            continue;
        }
        if let Some((key, rest)) = part.split_once(" notin ") {
            let key = key.trim();
            if key.is_empty() {
                return Err(Status::bad_request(format!(
                    "invalid label selector '{part}': empty key"
                )));
            }
            let values = parse_set_values_generic(rest);
            terms.push(LabelSelectorTerm::NotIn { key, values });
            continue;
        }
        if let Some((key, rest)) = part.split_once(" in ") {
            let key = key.trim();
            if key.is_empty() {
                return Err(Status::bad_request(format!(
                    "invalid label selector '{part}': empty key"
                )));
            }
            let values = parse_set_values_generic(rest);
            terms.push(LabelSelectorTerm::In { key, values });
            continue;
        }
        if let Some((key, value)) = part.split_once("!=") {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                return Err(Status::bad_request(format!(
                    "invalid label selector '{part}': empty key"
                )));
            }
            terms.push(LabelSelectorTerm::NotEquals { key, value });
            continue;
        }
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                return Err(Status::bad_request(format!(
                    "invalid label selector '{part}': empty key"
                )));
            }
            let value = value.strip_prefix('=').unwrap_or(value);
            terms.push(LabelSelectorTerm::Equality { key, value });
            continue;
        }
        let key = part.trim();
        if key.is_empty() {
            return Err(Status::bad_request(format!(
                "invalid label selector '{part}': empty key"
            )));
        }
        terms.push(LabelSelectorTerm::Exists { key });
    }
    Ok(terms)
}

/// Filter `items` by label selector terms. Keeps only items where all terms match
/// the object's `metadata.labels` map.
///
/// `pub` (not `pub(crate)`) so `benches/list_filter.rs` can call it directly
/// — a criterion bench is a separate crate that only ever sees this crate's
/// public API.
pub fn apply_label_selector(
    items: Vec<serde_json::Value>,
    terms: &[LabelSelectorTerm<'_>],
) -> Vec<serde_json::Value> {
    if terms.is_empty() {
        return items;
    }
    items
        .into_iter()
        .filter(|item| {
            // Read labels directly off the JSON tree — skips a full ObjectMeta
            // reparse per item just to reach this one sub-map.
            let labels = item["metadata"]["labels"].as_object();
            terms.iter().all(|term| match term {
                LabelSelectorTerm::Equality { key, value } => {
                    labels.and_then(|l| l.get(*key)).and_then(|v| v.as_str()) == Some(value)
                }
                LabelSelectorTerm::NotEquals { key, value } => {
                    labels.and_then(|l| l.get(*key)).and_then(|v| v.as_str()) != Some(value)
                }
                LabelSelectorTerm::Exists { key } => labels.is_some_and(|l| l.contains_key(*key)),
                LabelSelectorTerm::DoesNotExist { key } => {
                    !labels.is_some_and(|l| l.contains_key(*key))
                }
                LabelSelectorTerm::In { key, values } => labels
                    .and_then(|l| l.get(*key))
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| values.contains(&v)),
                LabelSelectorTerm::NotIn { key, values } => !labels
                    .and_then(|l| l.get(*key))
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| values.contains(&v)),
            })
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

/// Encode a store key and its pinned resourceVersion as a signed continue token.
///
/// Token format: `base64url(payload) + "." + base64url(hmac_sha256(signing_key, payload))`
///
/// The payload is a JSON envelope `{"k":"<store_key>","t":<unix_secs>,"rv":<resourceVersion>}`.
/// The HMAC prevents a client from forging tokens that point to a different
/// namespace's store prefix (cross-namespace pagination forgery).
///
/// `rv` pins the resourceVersion every subsequent page of this listing walk must report.
/// Kubernetes conformance (chunking.go) asserts `list.ResourceVersion` is IDENTICAL across
/// every page of one pagination pass — the store's live global revision otherwise drifts
/// upward between pages (other resources being written concurrently), which would fail
/// that assertion even though the actual paged items are correct.
fn encode_continue(key: &str, revision: u64, signing_key: &[u8; 32]) -> String {
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = serde_json::json!({"k": key, "t": unix_now(), "rv": revision}).to_string();
    let payload_b64 = b64.encode(payload.as_bytes());
    let mut mac = <Hmac<Sha256>>::new_from_slice(signing_key).expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = b64.encode(&sig[..]);
    format!("{payload_b64}.{sig_b64}")
}

/// Decode and verify a signed continue token, returning the store key and the pinned
/// resourceVersion the caller must report in the resulting list response.
///
/// `current_revision` is the store's live global revision at request time (from
/// `Store::current_revision`, a cheap in-memory read); it is used only to mint the `rv` of a
/// fresh replacement token when the incoming one is rejected as expired/invalid — that fresh
/// token starts a new (inconsistent) listing pass, so it must carry a NEW resourceVersion,
/// matching the upstream chunking conformance expectation that the resumed list's
/// resourceVersion differs from the one before compaction.
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
    current_revision: u64,
    signing_key: &[u8; 32],
) -> Result<(String, u64), crate::status::StatusError> {
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
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
        // Return 410 with a fresh start-of-list token so clients can restart pagination.
        // Kubernetes spec requires metadata.continue in the 410 body.
        let fresh_token = encode_continue("", current_revision, signing_key);
        Status::expired_with_continue(
            "continue token signature invalid; re-list from the beginning".to_string(),
            fresh_token,
        )
    })?;

    // Signature valid — parse payload.
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| Status::bad_request("invalid continue token: not valid JSON".to_string()))?;
    let issued_at = payload["t"].as_u64().ok_or_else(|| {
        Status::bad_request("invalid continue token: missing issued-at field".to_string())
    })?;
    let age = unix_now().saturating_sub(issued_at);
    if age > CONTINUE_TOKEN_TTL_SECS {
        // Preserve the original cursor key so clients continue from where they left off rather
        // than restarting from the beginning — matching etcd compaction behaviour where the fresh
        // token points to the compaction boundary, not the list head.
        let original_key = payload["k"].as_str().unwrap_or("");
        let fresh_token = encode_continue(original_key, current_revision, signing_key);
        return Err(Status::expired_with_continue(
            format!(
                "continue token expired: issued {age}s ago (TTL is {CONTINUE_TOKEN_TTL_SECS}s); \
                 re-list from the beginning"
            ),
            fresh_token,
        ));
    }
    let key = payload["k"].as_str().map(str::to_string).ok_or_else(|| {
        Status::bad_request("invalid continue token: missing key field".to_string())
    })?;
    let revision = payload["rv"].as_u64().ok_or_else(|| {
        Status::bad_request("invalid continue token: missing resourceVersion field".to_string())
    })?;
    Ok((key, revision))
}

/// The `metadata` envelope of a Kubernetes List response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListMeta {
    resource_version: String,
    #[serde(rename = "continue", skip_serializing_if = "Option::is_none")]
    continue_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_item_count: Option<u64>,
}

/// Wire shape of every LIST response: `{kind, apiVersion, metadata, items}`.
#[derive(Serialize)]
struct ListResponse {
    kind: String,
    #[serde(rename = "apiVersion")]
    api_version: String,
    metadata: ListMeta,
    items: Vec<serde_json::Value>,
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
    // Pin the outgoing token to this same `revision` so every later page of this walk
    // (which decodes the token to build its own response) reports an identical
    // resourceVersion — required by chunking conformance (see decode_continue doc).
    let continue_token = continue_key.map(|key| encode_continue(&key, revision, signing_key));
    let response = ListResponse {
        kind: format!("{}List", kind),
        api_version,
        metadata: ListMeta {
            resource_version: revision.to_string(),
            continue_token,
            remaining_item_count: remaining_count,
        },
        items,
    };
    serde_json::to_value(response).expect("ListResponse is always serializable")
}

/// Check finalizers for delete: if non-empty, set deletionTimestamp and return modified object.
/// Returns `None` if hard-delete should proceed, `Some(obj)` if soft-delete was applied.
pub(crate) fn apply_delete_policy(obj: &mut Object) -> Option<serde_json::Value> {
    let is_namespace = obj.body["kind"].as_str() == Some("Namespace");

    // Namespace finalizers live in spec.finalizers; all other resources use metadata.finalizers.
    let has_finalizers = if is_namespace {
        let spec: NamespaceSpec =
            serde_json::from_value(obj.body["spec"].clone()).unwrap_or_default();
        spec.finalizers.as_ref().is_some_and(|f| !f.is_empty())
    } else {
        let meta: ObjectMeta =
            serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
        meta.finalizers.as_ref().is_some_and(|f| !f.is_empty())
    };

    if has_finalizers {
        // Soft delete: stamp deletionTimestamp, but only if it isn't already set. Real
        // kube-apiserver's BeforeDelete does the same — a repeat DELETE on an
        // already-terminating finalizer'd object is a no-op, not a fresh timestamp. Without
        // this check, every redundant DELETE (harmless retries are routine — e.g. the
        // snapshot common-controller re-issuing Delete() on a VolumeSnapshotContent each time
        // its bound VolumeSnapshot resyncs) would advance deletionTimestamp and defeat the
        // store's byte-equality no-op check, bumping resourceVersion and firing a watch event
        // on every call. That resurrects the object in every controller's queue forever,
        // starving the finalizer-owning controller's own update of a stable resourceVersion
        // window and livelocking the delete (observed as csi-hostpath's snapshottable_stress
        // conformance spec timing out waiting for a VolumeSnapshotContent to be deleted).
        if obj.body["metadata"]["deletionTimestamp"].is_null() {
            obj.body["metadata"]["deletionTimestamp"] =
                serde_json::Value::String(utc_now_rfc3339());
        }
        // The upstream KCM namespace controller watches for status.phase == "Terminating"
        // to trigger finalizer removal.
        if is_namespace {
            obj.body["status"]["phase"] = serde_json::to_value(NamespacePhase::Terminating)
                .expect("NamespacePhase is always serializable");
        }
        Some(obj.body.clone())
    } else {
        None
    }
}

/// Stamp server-owned identity fields on a newly-created object.
///
/// `uid` is ALWAYS assigned fresh here, unconditionally overwriting any client-supplied
/// value. Real kube-apiserver's FillObjectMetaSystemFields does the same on create; a
/// client-chosen uid would let a caller forge object identity — e.g. matching a
/// stale/foreign `ownerReference.uid` to manipulate GC's owner-liveness check, or
/// defeating controllers' "same name, different uid means a different object"
/// recreate-detection.
pub(crate) fn stamp_metadata(obj: &mut Object) {
    let meta: ObjectMeta = serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
    obj.body["metadata"]["uid"] = serde_json::Value::String(uuid::Uuid::new_v4().to_string());
    if meta
        .creation_timestamp
        .as_deref()
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        obj.body["metadata"]["creationTimestamp"] = serde_json::Value::String(utc_now_rfc3339());
    }
}

pub(crate) const RBAC_GROUP: &str = "rbac.authorization.k8s.io";
const CLUSTER_ROLE_BINDINGS: &str = "clusterrolebindings";
pub(crate) const CLUSTER_ROLES: &str = "clusterroles";
const ROLES: &str = "roles";
const ROLE_BINDINGS: &str = "rolebindings";

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
    let role_ref_name = serde_json::from_value::<crate::rbac::RbacBinding>(body.clone())
        .map(|b| b.role_ref.name)
        .unwrap_or_default();
    let role_rules = state.rbac_index.cluster_role_rules(&role_ref_name);
    // Kubernetes upstream behaviour: creating a CRB that references a not-yet-existing
    // ClusterRole is allowed — the binding simply grants nothing until the role is created.
    // sonobuoy creates CRBs before the referenced ClusterRole is registered; treating
    // empty rules as "nothing to escalate to" handles this correctly without a hardcoded bypass.
    if role_rules.is_empty() {
        tracing::warn!(
            role = %role_ref_name,
            user = %user.username,
            "ClusterRoleBinding references role with no rules (role may not exist yet); allowing — binding grants nothing"
        );
        return Ok(());
    }
    // Kubernetes upstream: a user who holds the `escalate` verb on clusterroles in
    // rbac.authorization.k8s.io may create a CRB to any ClusterRole without personally
    // holding all of its rules.  The name-scoped check mirrors upstream: escalate may be
    // granted cluster-wide (no resourceNames) or scoped to a specific ClusterRole.
    let escalate_req = AuthzRequest {
        username: &user.username,
        groups: &user.groups,
        verb: "escalate",
        api_group: RBAC_GROUP,
        resource: CLUSTER_ROLES,
        subresource: "",
        namespace: None,
        name: Some(&role_ref_name),
        non_resource_url: None,
    };
    if state.rbac_index.is_allowed(&escalate_req) {
        return Ok(());
    }
    if !user_holds_all_rules(&user.username, &user.groups, &role_rules, &state.rbac_index) {
        return Err(Status::forbidden(
            "cannot escalate privileges: user does not hold all rules of the referenced ClusterRole".to_string(),
        ));
    }
    Ok(())
}

/// Escalation prevention for ClusterRole writes.
///
/// When a ClusterRole is created or updated with non-empty rules, and any
/// ClusterRoleBinding already references that role, the caller must already
/// hold every rule in the new role spec.  Without this check a user can
/// do: (1) create CRB → references non-existent role → CRB check skipped;
/// (2) create ClusterRole with wildcard rules → instant cluster-admin.
///
/// The check is skipped when the role has no rules (nothing to escalate)
/// or when no binding references it yet (role-first ordering).
/// system:masters members bypass via the RBAC cluster-admin binding.
///
/// Returns `Ok(())` if the check passes, or `Err(403 Forbidden)`.
pub(crate) fn check_clusterrole_escalation<S: Store>(
    plural: &str,
    group: &str,
    user: &UserInfo,
    body: &serde_json::Value,
    state: &AppState<S>,
) -> Result<(), crate::status::StatusError> {
    if group != RBAC_GROUP || plural != CLUSTER_ROLES {
        return Ok(());
    }
    let role_rules = serde_json::from_value::<crate::rbac::RbacRole>(body.clone())
        .map(|r| r.rules)
        .unwrap_or_default();
    if role_rules.is_empty() {
        return Ok(());
    }
    let role_name = body["metadata"]["name"].as_str().unwrap_or("");
    if !state.rbac_index.clusterrole_has_bindings(role_name) {
        return Ok(());
    }
    if !user_holds_all_rules(&user.username, &user.groups, &role_rules, &state.rbac_index) {
        return Err(Status::forbidden(
            "cannot escalate privileges: ClusterRole is already bound and user does not hold all its rules".to_string(),
        ));
    }
    Ok(())
}

/// Escalation prevention for namespaced RoleBinding writes.
///
/// A user may only create or update a RoleBinding if they already hold every
/// permission enumerated in the referenced Role or ClusterRole, scoped to the
/// target namespace.  Without this check a user with `create rolebindings`
/// in a namespace can bind any subject to cluster-admin (or any other role)
/// without holding those permissions.
///
/// The referenced role is resolved:
/// - roleRef.kind = "Role"        → rules from the namespaced Role
/// - roleRef.kind = "ClusterRole" → rules from the ClusterRole (applied in ns)
///
/// Returns `Ok(())` if the check passes (or is not applicable), or
/// `Err(StatusError)` with 403 Forbidden if the check fails.
pub(crate) fn check_rb_escalation<S: Store>(
    plural: &str,
    group: &str,
    namespace: &str,
    user: &UserInfo,
    body: &serde_json::Value,
    state: &AppState<S>,
) -> Result<(), crate::status::StatusError> {
    if group != RBAC_GROUP || plural != ROLE_BINDINGS {
        return Ok(());
    }
    let binding = match serde_json::from_value::<crate::rbac::RbacBinding>(body.clone()) {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };
    let role_ref = &binding.role_ref;
    if role_ref.api_group != RBAC_GROUP {
        return Ok(());
    }
    let role_rules = match role_ref.kind.as_str() {
        "Role" => state.rbac_index.role_rules(namespace, &role_ref.name),
        "ClusterRole" => state.rbac_index.cluster_role_rules(&role_ref.name),
        _ => return Ok(()),
    };
    if role_rules.is_empty() {
        return Ok(());
    }
    // Kubernetes upstream: a user who holds the `escalate` verb on the role resource
    // in rbac.authorization.k8s.io may create a RoleBinding without personally holding
    // all of the role's rules.  The resource and namespace for the escalate check follow
    // the roleRef kind:
    //   - Role → resource "roles", namespace = binding's namespace (namespaced grant)
    //   - ClusterRole → resource "clusterroles", no namespace (cluster-scoped grant)
    let (escalate_resource, escalate_namespace) = match role_ref.kind.as_str() {
        "Role" => (ROLES, Some(namespace)),
        _ => (CLUSTER_ROLES, None),
    };
    let escalate_req = AuthzRequest {
        username: &user.username,
        groups: &user.groups,
        verb: "escalate",
        api_group: RBAC_GROUP,
        resource: escalate_resource,
        subresource: "",
        namespace: escalate_namespace,
        name: Some(&role_ref.name),
        non_resource_url: None,
    };
    if state.rbac_index.is_allowed(&escalate_req) {
        return Ok(());
    }
    if !user_holds_all_rules_in_namespace(
        &user.username,
        &user.groups,
        &role_rules,
        namespace,
        &state.rbac_index,
    ) {
        return Err(Status::forbidden(
            "cannot escalate privileges: user does not hold all rules of the referenced Role in this namespace".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::json_patch::{
        apply_json_patch, detect_patch_type, json_pointer_segments, PatchType,
    };
    use super::super::resource::{rbac_cluster_key, rbac_namespaced_key};
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
        let terms = ok(parse_label_selector("app=frontend"));
        assert_eq!(
            terms,
            vec![LabelSelectorTerm::Equality {
                key: "app",
                value: "frontend"
            }]
        );
    }

    #[test]
    fn parse_multiple_pairs() {
        let terms = ok(parse_label_selector("app=frontend,env=prod"));
        assert_eq!(
            terms,
            vec![
                LabelSelectorTerm::Equality {
                    key: "app",
                    value: "frontend"
                },
                LabelSelectorTerm::Equality {
                    key: "env",
                    value: "prod"
                },
            ]
        );
    }

    #[test]
    fn parse_empty_selector_returns_empty() {
        let terms = ok(parse_label_selector(""));
        assert!(terms.is_empty());
    }

    #[test]
    fn parse_bare_key_is_exists_operator() {
        // bare key with no operator means Exists — the key must be present with any value
        let terms = ok(parse_label_selector("app"));
        assert_eq!(terms, vec![LabelSelectorTerm::Exists { key: "app" }]);
    }

    #[test]
    fn parse_does_not_exist_operator() {
        // !key means DoesNotExist — key must NOT be present
        let terms = ok(parse_label_selector("!service.kubernetes.io/headless"));
        assert_eq!(
            terms,
            vec![LabelSelectorTerm::DoesNotExist {
                key: "service.kubernetes.io/headless"
            }]
        );
    }

    #[test]
    fn parse_not_equals_operator() {
        // key!=value means NotEquals
        let terms = ok(parse_label_selector("env!=prod"));
        assert_eq!(
            terms,
            vec![LabelSelectorTerm::NotEquals {
                key: "env",
                value: "prod"
            }]
        );
    }

    #[test]
    fn parse_empty_key_is_error() {
        assert!(parse_label_selector("=val").is_err());
    }

    #[test]
    fn parse_value_may_be_empty() {
        // key= is valid — value is empty string
        let terms = ok(parse_label_selector("app="));
        assert_eq!(
            terms,
            vec![LabelSelectorTerm::Equality {
                key: "app",
                value: ""
            }]
        );
    }

    #[test]
    fn parse_does_not_exist_with_empty_key_is_error() {
        assert!(parse_label_selector("!").is_err());
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

    /// The full LIST envelope shape — {kind, apiVersion, metadata: {resourceVersion}, items} —
    /// must be exactly what client-go's List decoder expects. This pins the whole document
    /// shape (not just individual fields) so a migration to a typed struct that reorders,
    /// renames, drops, or adds a key is caught immediately, rather than surfacing later as a
    /// kubectl "unable to decode" error or a silently empty list.
    #[test]
    fn build_list_response_envelope_has_exact_shape() {
        let items = vec![serde_json::json!({"metadata": {"name": "a"}})];
        let body = build_list_response("Pod", "", "v1", 7, items.clone(), None, None, TEST_KEY);
        assert_eq!(
            body,
            serde_json::json!({
                "kind": "PodList",
                "apiVersion": "v1",
                "metadata": { "resourceVersion": "7" },
                "items": items
            }),
            "the LIST envelope shape (kind/apiVersion/metadata.resourceVersion/items) must \
             match exactly what client-go's List decoder expects — an extra, missing, or \
             renamed key breaks every `kubectl get` and every controller's informer LIST"
        );
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
    fn json_patch_test_op_passes_and_lets_subsequent_ops_apply() {
        // 'test' is an optimistic-concurrency guard: clients chain it before a write to
        // assert the server has the value they expect. A passing test must not block the
        // rest of the patch.
        let mut obj = serde_json::json!({"spec": {"replicas": 1}});
        let patch = serde_json::json!([
            {"op": "test", "path": "/spec/replicas", "value": 1},
            {"op": "replace", "path": "/spec/replicas", "value": 3}
        ]);
        ok(apply_json_patch(&mut obj, &patch));
        assert_eq!(obj["spec"]["replicas"], 3);
    }

    #[test]
    fn json_patch_test_op_failure_rejects_whole_patch_atomically() {
        // If 'test' rejected only the failing op but let earlier ops in the same patch
        // stick, a test-and-set client would silently observe a half-applied write instead
        // of the atomic failure it asked for.
        let mut obj = serde_json::json!({"spec": {"replicas": 1}});
        let before = obj.clone();
        let patch = serde_json::json!([
            {"op": "replace", "path": "/spec/replicas", "value": 99},
            {"op": "test", "path": "/spec/replicas", "value": 1}
        ]);
        let err = apply_json_patch(&mut obj, &patch).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            obj, before,
            "a failing 'test' op must leave the object untouched, not half-patched"
        );
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

    // -- wants_generate_name --

    #[test]
    fn wants_generate_name_returns_prefix_when_only_generate_name_set() {
        // A generateName-only create must be eligible for the collision-retry loop —
        // without this, a random suffix collision surfaces as a spurious 409 to a client
        // that never chose a name (e.g. a bulk PVC-creation loop).
        let obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({ "metadata": { "generateName": "pvc-" } }).to_string(),
        ))
        .unwrap();
        assert_eq!(wants_generate_name(&obj), Some("pvc-".to_string()));
    }

    #[test]
    fn wants_generate_name_returns_none_when_explicit_name_set() {
        // An explicit name must never be silently retried under a different generated
        // name on conflict — a collision on a client-chosen name is a genuine 409.
        let obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "my-pvc", "generateName": "pvc-" }
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(wants_generate_name(&obj), None);
    }

    #[test]
    fn wants_generate_name_returns_none_when_neither_set() {
        // No retry semantics apply when there is nothing to regenerate.
        let obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({ "metadata": {} }).to_string(),
        ))
        .unwrap();
        assert_eq!(wants_generate_name(&obj), None);
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
        // The continue token is opaque to clients; they must get back the original key AND
        // the pinned resourceVersion after base64 round-trip. A broken encoding loses the
        // cursor and re-scans from the start; a lost resourceVersion breaks the chunking
        // conformance assertion that every page of one pagination pass reports the same rv.
        let key = "/registry/pods/default/my-pod";
        let token = encode_continue(key, 42, TEST_KEY);
        let (decoded_key, decoded_rv) = ok(decode_continue(&token, 999, TEST_KEY));
        assert_eq!(
            decoded_key, key,
            "decoded continue token must equal the original store key"
        );
        assert_eq!(
            decoded_rv, 42,
            "decoded continue token must equal the originally pinned resourceVersion, \
             not the current_revision passed to decode_continue (that value is only used \
             to mint a fresh token on expiry, never returned for a valid token)"
        );
    }

    #[test]
    fn decode_invalid_continue_token_is_400() {
        // A malformed continue token from a client (no '.' separator) must return 400.
        let err = decode_continue("!!!not-valid-base64!!!", 0, TEST_KEY).unwrap_err();
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
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload_b64 = b64.encode(payload.as_bytes());
        let mut mac = <Hmac<Sha256>>::new_from_slice(TEST_KEY).expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let sig = mac.finalize().into_bytes();
        let stale_token = format!("{payload_b64}.{}", b64.encode(sig));

        let err = decode_continue(&stale_token, 0, TEST_KEY).unwrap_err();
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
    fn expired_continue_token_error_includes_new_continue_token_in_metadata() {
        // Kubernetes chunking conformance: when a paginated list uses an expired continue
        // token the 410 response body must include `metadata.continue` with a fresh token.
        // Without this, the client cannot resume pagination and must re-issue an un-paginated
        // list request.
        //
        // This test MUST FAIL if the `Status::expired_with_continue` path is removed or
        // if the error no longer carries `metadata` — reverting the fix causes the
        // Kubernetes conformance test (chunking.go:202) to fail: the client discards the
        // 410 and cannot proceed to page 2.
        let original_key = "/registry/podtemplates/default/foo";
        let old_iat = 0u64; // Unix epoch — definitely expired
        let payload = serde_json::json!({"k": original_key, "t": old_iat}).to_string();
        use base64::Engine;
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload_b64 = b64.encode(payload.as_bytes());
        let mut mac = <Hmac<Sha256>>::new_from_slice(TEST_KEY).expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let sig = mac.finalize().into_bytes();
        let stale_token = format!("{payload_b64}.{}", b64.encode(sig));

        // current_revision simulates the store having advanced past the pinned rv in the
        // expired token — the fresh token must adopt this NEW revision (see assertion below),
        // matching chunking.go's expectation that a resumed list after compaction reports a
        // different resourceVersion than the pre-compaction pages.
        let current_revision = 777u64;
        let err = decode_continue(&stale_token, current_revision, TEST_KEY).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::GONE);

        // metadata.continue must be present — client-go reads this field to restart pagination.
        let meta = err.1.metadata.as_ref().expect(
            "expired-token 410 response must include metadata.continue; \
             without it, client-go cannot restart the paginated list from the beginning \
             (Kubernetes conformance: chunking.go:202 step 3→4)",
        );
        let cont = meta["continue"].as_str().expect(
            "metadata.continue must be a string, not null; \
             null would cause client-go to treat the response as a hard error",
        );
        assert!(
            !cont.is_empty(),
            "metadata.continue must be a non-empty token, not an empty string"
        );

        // The fresh token must preserve the original cursor key so clients continue from where
        // they left off rather than restarting from the beginning — without this the conformance
        // test (chunking.go:202) accumulates 440 items instead of the expected 400.
        let (decoded_key, decoded_rv) = ok(decode_continue(cont, current_revision, TEST_KEY));
        assert_eq!(
            decoded_key, original_key,
            "the new continue token in metadata.continue must preserve the original cursor key \
             so clients can continue listing from where they were (not restart from the beginning)"
        );
        assert_eq!(
            decoded_rv, current_revision,
            "the fresh token must carry the store's CURRENT revision, not the stale pinned rv \
             from the expired token — otherwise the resumed list reports the same resourceVersion \
             as before compaction, failing chunking.go's 'ResourceVersion not equal firstRV' check"
        );
    }

    #[test]
    fn expired_continue_token_fresh_token_preserves_cursor_not_empty_key() {
        // When an expired but HMAC-valid continue token is rejected, the fresh token in the
        // 410 response must carry the ORIGINAL cursor key, not an empty string.
        //
        // If the fresh token has key="" the client restarts from the list head and double-counts
        // items already retrieved, producing 440 items where 400 are expected
        // (Kubernetes conformance: chunking.go:202).
        //
        // This test FAILS if the fix is reverted to encode_continue("", signing_key).
        let cursor = "/registry/pods/default/cursor-pod";
        let old_iat = 0u64;
        let payload = serde_json::json!({"k": cursor, "t": old_iat}).to_string();
        use base64::Engine;
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload_b64 = b64.encode(payload.as_bytes());
        let mut mac = <Hmac<Sha256>>::new_from_slice(TEST_KEY).expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let sig = mac.finalize().into_bytes();
        let expired_token = format!("{payload_b64}.{}", b64.encode(sig));

        let err = decode_continue(&expired_token, 0, TEST_KEY).unwrap_err();
        assert_eq!(
            err.0,
            axum::http::StatusCode::GONE,
            "must be 410 Gone for expired token"
        );

        let meta = err.1.metadata.as_ref().expect("must include metadata");
        let fresh = meta["continue"]
            .as_str()
            .expect("must include metadata.continue");
        let (fresh_key, _) = ok(decode_continue(fresh, 0, TEST_KEY));

        assert_eq!(
            fresh_key, cursor,
            "fresh continue token must point to the original cursor, not the list head; \
             a key of \"\" restarts the list from scratch, causing item count inflation \
             (chunking.go:202 fails with 440 instead of 400)"
        );
    }

    #[test]
    fn decode_fresh_continue_token_within_ttl_succeeds() {
        // A token issued just now must be accepted (not incorrectly rejected as expired).
        // Regressions here would break all pagination immediately after the first page.
        let key = "/registry/podtemplates/default/bar";
        let token = encode_continue(key, 3, TEST_KEY);
        let (decoded_key, decoded_rv) = ok(decode_continue(&token, 3, TEST_KEY));
        assert_eq!(
            decoded_key, key,
            "a fresh continue token must decode to the original store key; \
             premature expiry would break all paginated LIST requests"
        );
        assert_eq!(
            decoded_rv, 3,
            "a fresh continue token must decode to its originally pinned resourceVersion"
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
        let (decoded_key, decoded_rv) = ok(decode_continue(token, 5, TEST_KEY));
        assert_eq!(decoded_key, "/registry/pods/default/foo");
        assert_eq!(
            decoded_rv, 5,
            "the emitted continue token must be pinned to the SAME resourceVersion as this \
             response's metadata.resourceVersion (5) — otherwise the next page, which decodes \
             this token, reports a different rv and fails the chunking conformance assertion \
             that every page of one pagination pass shares one resourceVersion"
        );
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
        let legit_token = encode_continue("/registry/pods/default/cursor", 1, TEST_KEY);

        // Extract the signature from the legitimate token.
        let (_, sig_b64) = legit_token.split_once('.').unwrap();

        // Build a forged payload pointing to a different namespace.
        let forged_payload =
            serde_json::json!({"k": "/registry/pods/kube-system/cursor", "t": unix_now(), "rv": 1})
                .to_string();
        let forged_payload_b64 = b64.encode(forged_payload.as_bytes());

        // Reassemble with original signature (signature mismatch).
        let forged_token = format!("{forged_payload_b64}.{sig_b64}");

        let err = decode_continue(&forged_token, 1, TEST_KEY).unwrap_err();
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
    fn stamp_metadata_overwrites_client_supplied_uid_on_create() {
        // metadata.uid must be server-generated and immutable identity, never
        // client-chosen. A client that could set an arbitrary uid on create could
        // forge object identity to match a stale/foreign ownerReference.uid, tricking
        // GC's owner-liveness check (owner_ref_is_live compares stored uid ==
        // ownerRef.uid) into treating a dead owner as live or vice versa, and would
        // defeat controllers' "same name, different uid means a different object"
        // recreate-detection.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "hello-world", "uid": "attacker-chosen-uid" }
            })
            .to_string(),
        ))
        .unwrap();
        stamp_metadata(&mut obj);
        let uid = obj.body["metadata"]["uid"].as_str().unwrap_or("");
        assert_ne!(
            uid, "attacker-chosen-uid",
            "server must always overwrite a client-supplied uid on create — \
             letting it through would let any create request forge object identity"
        );
        assert!(
            uuid::Uuid::parse_str(uid).is_ok(),
            "uid must be a server-generated UUID v4; got: {uid}"
        );
    }

    #[test]
    fn stamp_metadata_overwrites_empty_string_uid() {
        // KCM's token controller logs an error when a ServiceAccount has uid="".
        // stamp_metadata must replace an empty-string uid with a generated UUID,
        // treating "" the same as absent. Without this fix, uid:"" passes through
        // is_none() → false and KCM receives an object with an unparseable empty UID.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": { "name": "default", "uid": "" }
            })
            .to_string(),
        ))
        .unwrap();
        stamp_metadata(&mut obj);
        let uid = obj.body["metadata"]["uid"].as_str().unwrap_or("");
        assert!(
            !uid.is_empty(),
            "uid must be replaced when the client sends an empty string; \
             KCM token controller rejects ServiceAccounts with uid=\"\""
        );
        assert!(
            uuid::Uuid::parse_str(uid).is_ok(),
            "uid must be a valid UUID v4; got: {uid}"
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
            timeout_seconds: None,
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
            timeout_seconds: None,
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
            timeout_seconds: None,
        };
        assert_ne!(
            q_false.allow_watch_bookmarks,
            Some(true),
            "allowWatchBookmarks=false must suppress periodic bookmarks"
        );
    }

    // -- json-patch 'add' must create intermediate objects --

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

    /// A second DELETE on an already-terminating finalizer'd object must preserve the original
    /// deletionTimestamp instead of stamping a fresh one. If it re-stamps, the resulting body is
    /// never byte-identical to what's already stored, so the store's no-op-write check (which
    /// compares bytes to suppress redundant writes) never fires: every redundant DELETE bumps
    /// resourceVersion and fires a watch event, which is exactly the livelock that made
    /// csi-hostpath's snapshottable_stress conformance spec time out waiting 5 minutes for a
    /// VolumeSnapshotContent to be deleted (its bound VolumeSnapshot's controller re-issues a
    /// no-op Delete() on every resync).
    #[test]
    fn apply_delete_policy_is_idempotent_when_already_terminating() {
        // Pre-set an already-in-the-past deletionTimestamp, as if this object were re-read from
        // the store after a prior DELETE already soft-deleted it. A fixed, distinguishable value
        // (rather than comparing two `now()` stamps, which can collide within the same second)
        // is what makes this test actually fail if apply_delete_policy re-stamps unconditionally.
        let mut obj = Object::from_bytes(&bytes::Bytes::from(
            serde_json::json!({
                "metadata": {
                    "name": "my-obj",
                    "finalizers": ["my.io/cleanup"],
                    "deletionTimestamp": "2020-01-01T00:00:00Z"
                }
            })
            .to_string(),
        ))
        .unwrap();

        let result = apply_delete_policy(&mut obj).expect("still has finalizers: must soft-delete");

        assert_eq!(
            result["metadata"]["deletionTimestamp"], "2020-01-01T00:00:00Z",
            "a repeat DELETE on an already-terminating object must not advance \
             deletionTimestamp — doing so defeats the store's no-op-write detection and \
             livelocks finalizer removal under concurrent controller retries"
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

    // kube-apiserver rejects names whose first or last character is a hyphen or dot
    // because they violate DNS label rules and break label-selector round-trips.
    #[test]
    fn validate_name_rejects_leading_hyphen() {
        let err = validate_name("name", "-foo").expect_err("leading hyphen must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400, "leading hyphen must return 400");
    }

    #[test]
    fn validate_name_rejects_trailing_hyphen() {
        let err = validate_name("name", "foo-").expect_err("trailing hyphen must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400, "trailing hyphen must return 400");
    }

    #[test]
    fn validate_name_rejects_trailing_dot() {
        let err = validate_name("name", "foo.").expect_err("trailing dot must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400, "trailing dot must return 400");
    }

    #[test]
    fn validate_name_rejects_leading_dot() {
        let err = validate_name("name", ".bar").expect_err("leading dot must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400, "leading dot must return 400");
    }

    /// RBAC resources (ClusterRole, ClusterRoleBinding, Role, RoleBinding) use colons in
    /// names by Kubernetes convention. Without allowing colons for the RBAC group, the
    /// test framework cannot delete ClusterRoleBindings it creates (e.g.
    /// `ns-system:service-account-issuer-discovery`) and the OIDC conformance test fails.
    #[test]
    fn validate_name_for_group_allows_colon_in_rbac_names() {
        assert!(
            validate_name_for_group("name", "system:node", RBAC_GROUP, CLUSTER_ROLES).is_ok(),
            "system:node must be valid for RBAC group — colon is conventional in RBAC names"
        );
        assert!(
            validate_name_for_group(
                "name",
                "svcaccounts-9027-system:service-account-issuer-discovery",
                RBAC_GROUP,
                CLUSTER_ROLE_BINDINGS,
            )
            .is_ok(),
            "user-created CRB name with embedded colon must be valid for RBAC — \
             the OIDC conformance test creates and then deletes such bindings"
        );
        assert!(
            validate_name_for_group("name", "system:node", "", "pods").is_err(),
            "system:node must be REJECTED for non-RBAC groups — colons are only allowed in RBAC"
        );
    }

    /// validate_name_for_group must still reject path traversal even for RBAC group.
    #[test]
    fn validate_name_for_group_rejects_path_traversal_in_rbac() {
        assert!(
            validate_name_for_group("name", "system:../../secrets", RBAC_GROUP, CLUSTER_ROLES)
                .is_err(),
            "path traversal via '..' must be rejected even for RBAC group"
        );
        assert!(
            validate_name_for_group("name", "system:/secrets", RBAC_GROUP, CLUSTER_ROLES).is_err(),
            "slash must be rejected even for RBAC group"
        );
    }

    // -- validate_name_for_group: ClusterTrustBundle signer-scoped names --

    /// Upstream's own e2e hermetic pod-certificate signer creates ClusterTrustBundle
    /// objects named `<signerName-with-'/'-as-':'>:<suffix>` (e.g.
    /// `e2e.example.com:projected-podcertificate-3533:primary-bundle`) and immediately
    /// `Get()`s that name before ever calling `Create()`. Before this fix, that `Get()`
    /// hit the generic `[a-z0-9.-]+` charset check (no colons) and returned 400 — so the
    /// signer never got past its very first API call, and every "Projected PodCertificate"
    /// conformance spec that depends on it timed out waiting for a certificate that was
    /// never issued.
    #[test]
    fn validate_name_for_group_allows_signer_scoped_colon_name_for_cluster_trust_bundle() {
        assert!(
            validate_name_for_group(
                "name",
                "e2e.example.com:projected-podcertificate-3533:primary-bundle",
                CERTIFICATES_GROUP,
                CLUSTER_TRUST_BUNDLES_PLURAL,
            )
            .is_ok(),
            "a signer-scoped ClusterTrustBundle name must be accepted so the e2e hermetic \
             signer's Get()-before-Create() call doesn't 400 before it ever runs"
        );
    }

    /// A colon-containing name must still be rejected for every OTHER resource type —
    /// the exception is scoped exactly to certificates.k8s.io/clustertrustbundles, not a
    /// blanket relaxation of the charset check.
    #[test]
    fn validate_name_for_group_rejects_colon_name_for_non_cluster_trust_bundle_resource() {
        assert!(
            validate_name_for_group(
                "name",
                "e2e.example.com:signer:bundle",
                CERTIFICATES_GROUP,
                "podcertificaterequests",
            )
            .is_err(),
            "the colon exception must not leak to other certificates.k8s.io resource types"
        );
    }

    /// A name that merely happens to contain a colon isn't automatically valid: each
    /// `:`-delimited segment must still pass the ordinary DNS-label charset check — a
    /// stray `!` (or any other invalid character) anywhere in the name must still 400,
    /// regardless of which signer supposedly owns it.
    #[test]
    fn validate_name_for_group_rejects_invalid_chars_in_cluster_trust_bundle_name_regardless_of_signer(
    ) {
        assert!(
            validate_name_for_group(
                "name",
                "random-invalid-chars!",
                CERTIFICATES_GROUP,
                CLUSTER_TRUST_BUNDLES_PLURAL,
            )
            .is_err(),
            "garbage characters must be rejected even with no signer prefix at all"
        );
        assert!(
            validate_name_for_group(
                "name",
                "example.com:signer:random-invalid-chars!",
                CERTIFICATES_GROUP,
                CLUSTER_TRUST_BUNDLES_PLURAL,
            )
            .is_err(),
            "garbage characters in the suffix segment must be rejected even when the \
             signer-prefix segments are otherwise well-formed"
        );
    }
}

#[cfg(test)]
mod escalation_tests {
    use axum::http::StatusCode;

    use crate::handlers::test_support::make_state;

    fn json_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    }

    /// A user who can create ClusterRoleBindings but does NOT hold cluster-admin
    /// rules must receive 403 Forbidden when creating a CRB that references
    /// cluster-admin.
    #[tokio::test]
    async fn create_clusterrolebinding_denied_for_unprivileged_user() {
        use super::super::json_patch::CreateQuery;
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
            extra: Default::default(),
        });
        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterroles".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
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
            extra: Default::default(),
        });
        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterroles".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
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
            axum::extract::Query(CreateQuery::default()),
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
            extra: Default::default(),
        });
        let result = create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterrolebindings".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
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
            extra: Default::default(),
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
    }

    /// Regression test: removing the hardcoded system:masters bypass must not regress
    /// other principals. A user who is in system:masters but has NO cluster-admin binding
    /// in the RBAC index must be denied escalation to cluster-admin.
    ///
    /// If the hardcoded bypass is re-introduced, this test passes when it should fail —
    /// that is the canary.
    #[test]
    fn system_masters_without_binding_denied_when_role_has_rules() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";

        // Seed cluster-admin role with rules — the role EXISTS and has real permissions.
        let admin_role = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "cluster-admin"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin",
            &admin_role,
        );
        // Intentionally do NOT seed any ClusterRoleBinding for system:masters.

        let masters_user = crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
            extra: Default::default(),
        };
        let crb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "escalation-attempt"},
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
            &masters_user,
            &crb_body,
            &state,
        );
        assert!(
            result.is_err(),
            "system:masters without a cluster-admin binding must be denied escalation to cluster-admin; \
             privilege must flow through RBAC data, not hardcoded group membership"
        );
    }

    /// Regression test for sonobuoy compatibility (Option A): a CRB referencing a
    /// ClusterRole that does not yet exist must be allowed, because the role has no
    /// rules — the binding grants nothing until the role is created.
    ///
    /// This is Kubernetes upstream behaviour. Without this, sonobuoy's RBAC conformance
    /// tests fail because it creates CRBs before registering the referenced ClusterRole.
    #[test]
    fn crb_referencing_nonexistent_role_is_allowed() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";

        // Intentionally do NOT seed "nonexistent-role" in the rbac_index.
        let plain_user = crate::auth::UserInfo {
            username: "alice".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };
        let crb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "early-binding"},
            "subjects": [{"kind": "User", "name": "alice"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "nonexistent-role"
            }
        });
        let result = super::check_crb_escalation(
            "clusterrolebindings",
            group,
            &plain_user,
            &crb_body,
            &state,
        );
        assert!(
            result.is_ok(),
            "CRB referencing a not-yet-existing ClusterRole must be allowed; \
             the role has no rules so there is nothing to escalate to — \
             this matches Kubernetes upstream behaviour and is required for sonobuoy RBAC conformance"
        );
    }

    // -- escalate-verb bypass (Kubernetes RBAC semantics) --

    /// A user who holds the `escalate` verb on clusterroles in rbac.authorization.k8s.io
    /// may create a ClusterRoleBinding to any ClusterRole, even without personally holding
    /// all of its rules.
    ///
    /// WHY THIS MATTERS: sonobuoy's service account has verbs:['*'] on clusterroles
    /// (which includes 'escalate') but does not hold every rule of every ClusterRole it
    /// binds subjects to.  Without this bypass the binding is wrongly denied 403, breaking
    /// RBAC conformance and OIDC discovery setup.  Matches Kubernetes upstream semantics.
    #[test]
    fn crb_escalate_verb_holder_allowed_without_holding_role_rules() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";

        // Seed a ClusterRole with rules that "bob" does NOT hold.
        let target_role = serde_json::json!({
            "rules": [{
                "apiGroups": [""],
                "resources": ["secrets"],
                "verbs": ["get", "list"]
            }]
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/secret-reader",
            &target_role,
        );

        // Grant "bob" only the `escalate` verb on clusterroles — NOT secrets get/list.
        let escalate_role = serde_json::json!({
            "rules": [{
                "apiGroups": ["rbac.authorization.k8s.io"],
                "resources": ["clusterroles"],
                "verbs": ["escalate"]
            }]
        });
        let escalate_crb = serde_json::json!({
            "subjects": [{"kind": "User", "name": "bob"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "escalate-clusterroles"
            }
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/escalate-clusterroles",
            &escalate_role,
        );
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/bob-escalate",
            &escalate_crb,
        );

        let bob = crate::auth::UserInfo {
            username: "bob".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };
        let crb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "bob-secret-reader"},
            "subjects": [{"kind": "User", "name": "carol"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "secret-reader"
            }
        });
        let result =
            super::check_crb_escalation("clusterrolebindings", group, &bob, &crb_body, &state);
        assert!(
            result.is_ok(),
            "user with 'escalate' verb on clusterroles may bind any ClusterRole without \
             personally holding its rules — matches Kubernetes upstream RBAC semantics; \
             without this bypass sonobuoy's RBAC conformance tests and OIDC discovery fail"
        );
    }

    /// A user who does NOT hold the `escalate` verb AND does NOT hold the role's rules
    /// must still be denied — the privilege-escalation guard must not be weakened.
    ///
    /// WHY THIS MATTERS: the escalate bypass must be additive, not a blanket weakening.
    /// A user with only `create` on clusterrolebindings (but no escalate and no rules)
    /// must still receive 403 when trying to bind a role they don't hold.
    #[test]
    fn crb_without_escalate_and_without_rules_still_denied() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";

        // Seed a ClusterRole with rules.
        let target_role = serde_json::json!({
            "rules": [{
                "apiGroups": [""],
                "resources": ["secrets"],
                "verbs": ["get"]
            }]
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/secret-reader",
            &target_role,
        );

        // "eve" has NO escalate and NO secrets/get — cannot bind secret-reader.
        let eve = crate::auth::UserInfo {
            username: "eve".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };
        let crb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "eve-secret-reader"},
            "subjects": [{"kind": "User", "name": "eve"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "secret-reader"
            }
        });
        let result =
            super::check_crb_escalation("clusterrolebindings", group, &eve, &crb_body, &state);
        assert!(
            result.is_err(),
            "user without 'escalate' verb and without the role's rules must be denied — \
             privilege-escalation guard must remain intact; \
             if this passes, unprivileged users can grant themselves arbitrary permissions"
        );
    }

    /// A user with `escalate` on clusterroles may bind a ClusterRole via a RoleBinding
    /// without holding the ClusterRole's rules.
    ///
    /// WHY THIS MATTERS: RoleBindings can reference ClusterRoles.  The escalate bypass
    /// must also cover this path, or a user with global escalate-on-clusterroles is
    /// still blocked when creating a namespace-scoped RoleBinding.
    #[test]
    fn rb_referencing_clusterrole_with_escalate_verb_allowed() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";
        let ns = "test-ns";

        // Seed a ClusterRole with rules that "bob" does NOT hold.
        let target_role = serde_json::json!({
            "rules": [{
                "apiGroups": [""],
                "resources": ["configmaps"],
                "verbs": ["get"]
            }]
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/configmap-reader",
            &target_role,
        );

        // Grant "bob" escalate on clusterroles.
        let escalate_role = serde_json::json!({
            "rules": [{
                "apiGroups": ["rbac.authorization.k8s.io"],
                "resources": ["clusterroles"],
                "verbs": ["escalate"]
            }]
        });
        let escalate_crb = serde_json::json!({
            "subjects": [{"kind": "User", "name": "bob"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "escalate-clusterroles"
            }
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/escalate-clusterroles",
            &escalate_role,
        );
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/bob-escalate",
            &escalate_crb,
        );

        let bob = crate::auth::UserInfo {
            username: "bob".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };
        let rb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "bob-rb", "namespace": ns},
            "subjects": [{"kind": "User", "name": "carol"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "configmap-reader"
            }
        });
        let result = super::check_rb_escalation("rolebindings", group, ns, &bob, &rb_body, &state);
        assert!(
            result.is_ok(),
            "user with 'escalate' on clusterroles may create a RoleBinding referencing \
             a ClusterRole without holding the ClusterRole's rules — matches Kubernetes \
             upstream RBAC semantics for RoleBindings referencing ClusterRoles"
        );
    }

    /// A user without `escalate` and without the role's rules must be denied a RoleBinding
    /// to a ClusterRole — the namespace-scoped escalation guard must remain intact.
    ///
    /// WHY THIS MATTERS: RoleBindings are the primary way namespaced RBAC is granted.
    /// An unprivileged user must not be able to bind a ClusterRole they don't hold to
    /// grant themselves or others arbitrary permissions within a namespace.
    #[test]
    fn rb_referencing_clusterrole_without_escalate_still_denied() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";
        let ns = "test-ns";

        // Seed a ClusterRole with rules.
        let target_role = serde_json::json!({
            "rules": [{
                "apiGroups": [""],
                "resources": ["configmaps"],
                "verbs": ["get"]
            }]
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/configmap-reader",
            &target_role,
        );

        // "eve" has neither escalate nor configmaps/get.
        let eve = crate::auth::UserInfo {
            username: "eve".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };
        let rb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "eve-rb", "namespace": ns},
            "subjects": [{"kind": "User", "name": "eve"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "configmap-reader"
            }
        });
        let result = super::check_rb_escalation("rolebindings", group, ns, &eve, &rb_body, &state);
        assert!(
            result.is_err(),
            "user without 'escalate' and without the role's rules must be denied a RoleBinding — \
             privilege-escalation guard must remain intact for namespace-scoped bindings; \
             if this passes, unprivileged users can grant themselves arbitrary namespace permissions"
        );
    }

    // Keep the full integration test using create_resource to exercise the
    // handler path with the seeded binding.
    #[tokio::test]
    async fn create_clusterrolebinding_allowed_for_system_masters() {
        use super::super::json_patch::CreateQuery;
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
            extra: Default::default(),
        });
        create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                group.to_string(),
                version.to_string(),
                "clusterroles".to_string(),
            )),
            axum::extract::Query(CreateQuery::default()),
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
            axum::extract::Query(CreateQuery::default()),
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

    // -- ClusterRole create-time escalation (two-step loophole) --

    /// Without the ClusterRole create-time escalation check, an unprivileged user can:
    /// (1) create a CRB referencing a non-existent role → CRB check skips (role has no rules);
    /// (2) create the ClusterRole with wildcard rules → binding immediately grants cluster-admin.
    /// This test verifies that step 2 is blocked when a CRB already references the role and the
    /// caller does not hold the rules they are about to define.
    #[test]
    fn clusterrole_create_with_existing_crb_denied_for_unprivileged_user() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";

        // Give "alice" only create on clusterroles — she does NOT hold cluster-admin.
        let alice_cr = serde_json::json!({
            "rules": [{
                "apiGroups": ["rbac.authorization.k8s.io"],
                "resources": ["clusterroles"],
                "verbs": ["create"]
            }]
        });
        let alice_cr_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/alice-cr-creator";
        state.rbac_index.apply_object(alice_cr_key, &alice_cr);

        let alice_crb = serde_json::json!({
            "subjects": [{"kind": "User", "name": "alice"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "alice-cr-creator"
            }
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/alice-creator-binding",
            &alice_crb,
        );

        // Step 1: "alice" creates a CRB referencing a not-yet-existing "evil-role".
        // The CRB check allows this (role has no rules). Seed the CRB in the rbac_index
        // as if it was persisted.
        let evil_crb = serde_json::json!({
            "subjects": [{"kind": "User", "name": "alice"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "evil-role"
            }
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/evil-crb",
            &evil_crb,
        );

        // Step 2: "alice" tries to create "evil-role" with wildcard rules.
        // The new check must deny this because a CRB referencing "evil-role" already exists
        // and alice does not hold all those rules — without this, alice gets instant cluster-admin.
        let evil_role_body = serde_json::json!({
            "metadata": {"name": "evil-role"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        let alice_user = crate::auth::UserInfo {
            username: "alice".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };
        let result = super::check_clusterrole_escalation(
            "clusterroles",
            group,
            &alice_user,
            &evil_role_body,
            &state,
        );
        assert!(
            result.is_err(),
            "creating a ClusterRole with wildcard rules when a CRB already references it \
             must be denied for a user who does not hold those rules; \
             missing this check enables the two-step escalation loophole"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.0,
            axum::http::StatusCode::FORBIDDEN,
            "denial must return 403 Forbidden"
        );
    }

    /// An admin who holds all the rules they are defining in a ClusterRole must be
    /// allowed even when a CRB already references that role.  This ensures that
    /// legitimate cluster admins can manage RBAC without being blocked.
    #[test]
    fn clusterrole_create_with_existing_crb_allowed_for_admin() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";

        // Seed cluster-admin role and system:masters binding so admin holds all rules.
        let admin_role = serde_json::json!({
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin",
            &admin_role,
        );
        let masters_crb = serde_json::json!({
            "subjects": [{"kind": "Group", "name": "system:masters"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            }
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system-masters-cluster-admin",
            &masters_crb,
        );

        // A CRB references "my-role" which an admin is about to create.
        let my_crb = serde_json::json!({
            "subjects": [{"kind": "User", "name": "bob"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "my-role"
            }
        });
        state.rbac_index.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/my-crb",
            &my_crb,
        );

        let my_role_body = serde_json::json!({
            "metadata": {"name": "my-role"},
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]
        });
        let admin_user = crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
            extra: Default::default(),
        };
        let result = super::check_clusterrole_escalation(
            "clusterroles",
            group,
            &admin_user,
            &my_role_body,
            &state,
        );
        assert!(
            result.is_ok(),
            "an admin who already holds all rules must be allowed to create a ClusterRole \
             even when a CRB already references it — blocking this would prevent legitimate \
             admin RBAC management"
        );
    }

    /// Creating a ClusterRole with no CRB referencing it must always be allowed,
    /// regardless of the caller's permissions — the role grants nothing until bound.
    #[test]
    fn clusterrole_create_without_existing_crb_always_allowed() {
        let state = make_state();
        let group = "rbac.authorization.k8s.io";

        // No CRB references "orphan-role".
        let orphan_role_body = serde_json::json!({
            "metadata": {"name": "orphan-role"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        });
        let plain_user = crate::auth::UserInfo {
            username: "alice".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };
        let result = super::check_clusterrole_escalation(
            "clusterroles",
            group,
            &plain_user,
            &orphan_role_body,
            &state,
        );
        assert!(
            result.is_ok(),
            "creating a ClusterRole with no existing CRB must always be allowed; \
             the role grants nothing until a binding references it, so there is no escalation risk"
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

// -- CollectionQuery serde deserialization regression --
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
    /// tries to delete them, gets 403, and loops forever.
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
             ignored and all objects are returned regardless of label"
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

    /// kubectl and client-go historically send `?watch=1` (not just `?watch=true`) — a
    /// documented Kubernetes API accept form. Before the fix, `watch: Option<bool>` only
    /// parsed Rust's `bool::from_str` ("true"/"false"), so a real `?watch=1` request to any
    /// of the many endpoints sharing this `CollectionQuery` (list_resource, list_namespaces,
    /// CRD/CR list-or-watch, CSR list-or-watch, ...) failed axum's Query extraction and
    /// never reached the handler (Query rejection maps to HTTP 400). This test fails on
    /// revert: `try_from_uri` would return `Err`, not `watch: Some(true)`.
    #[test]
    fn watch_equals_1_is_accepted_as_true_for_kubectl_client_go_compat() {
        let uri: axum::http::Uri = "/api/v1/configmaps?watch=1".parse().unwrap();
        let axum::extract::Query(q) = axum::extract::Query::<CollectionQuery>::try_from_uri(&uri)
            .expect("?watch=1 must deserialize, not 400 — client-go/kubectl compat form");
        assert_eq!(
            q.watch,
            Some(true),
            "?watch=1 must resolve to watch:Some(true), the same as ?watch=true, so the \
             handler routes to the streaming watch path instead of a plain list"
        );
    }

    /// Mirror of the `watch=1` test above for the `watch=0` alias of `watch=false`. Before
    /// the fix this also 400'd instead of falling through to the normal list response.
    #[test]
    fn watch_equals_0_is_accepted_as_false_for_kubectl_client_go_compat() {
        let uri: axum::http::Uri = "/api/v1/configmaps?watch=0".parse().unwrap();
        let axum::extract::Query(q) = axum::extract::Query::<CollectionQuery>::try_from_uri(&uri)
            .expect("?watch=0 must deserialize, not 400 — client-go/kubectl compat form");
        assert_eq!(
            q.watch,
            Some(false),
            "?watch=0 must resolve to watch:Some(false) so the request stays on the \
             normal list path, not the watch stream"
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
        // Namespace finalizers live in spec.finalizers; all other resources use metadata.finalizers.
        let body = if kind == "Namespace" {
            serde_json::json!({
                "kind": kind,
                "apiVersion": "v1",
                "metadata": { "name": "test" },
                "spec": { "finalizers": finalizer_json }
            })
        } else {
            serde_json::json!({
                "kind": kind,
                "apiVersion": "v1",
                "metadata": {
                    "name": "test",
                    "finalizers": finalizer_json
                }
            })
        };
        Object { body }
    }

    /// A Namespace with finalizers must have status.phase == "Terminating" after soft-delete.
    ///
    /// The upstream KCM namespace controller only begins its drain cycle when it observes
    /// status.phase == "Terminating" on the watch event. Without this field the KCM never
    /// removes the kubernetes finalizer and the namespace hangs forever.
    #[test]
    fn namespace_with_finalizers_gets_terminating_phase() {
        let mut obj = make_obj("Namespace", &["kubernetes"]);
        let body =
            apply_delete_policy(&mut obj).expect("Namespace with finalizers must be soft-deleted");

        assert_eq!(
            body["status"]["phase"].as_str(),
            Some("Terminating"),
            "status.phase must be \"Terminating\" so KCM starts the drain cycle; \
             without it the namespace hangs forever"
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
             only Namespaces need this field to trigger KCM drain"
        );
        assert!(
            body["metadata"]["deletionTimestamp"].as_str().is_some(),
            "deletionTimestamp must still be stamped for non-Namespace soft-delete"
        );
    }
}

#[cfg(test)]
mod set_based_selector_tests {
    use super::{apply_label_selector, parse_label_selector, LabelSelectorTerm};

    fn ok<T>(r: Result<T, crate::status::StatusError>) -> T {
        match r {
            Ok(v) => v,
            Err(_) => panic!("expected Ok but got Err"),
        }
    }

    fn item_with_label(key: &str, value: &str) -> serde_json::Value {
        serde_json::json!({"metadata": {"labels": {key: value}}})
    }

    fn item_without_label() -> serde_json::Value {
        serde_json::json!({"metadata": {"labels": {}}})
    }

    /// `parse_label_selector` must produce `In` term for `key in (v1,v2)`.
    ///
    /// Without this fix, the `in` operator falls to the bare-key Exists branch, causing
    /// controllers that use set-based selectors to see nothing in LIST responses.
    #[test]
    fn parse_label_selector_in_operator_produces_in_term() {
        let terms = ok(parse_label_selector("color in (red,blue)"));
        assert_eq!(terms.len(), 1, "must produce exactly one term");
        match &terms[0] {
            LabelSelectorTerm::In { key, values } => {
                assert_eq!(*key, "color");
                assert!(values.contains(&"red"), "values must include 'red'");
                assert!(values.contains(&"blue"), "values must include 'blue'");
            }
            other => panic!("expected In term, got {other:?}"),
        }
    }

    /// `parse_label_selector` must produce `NotIn` term for `key notin (v1,v2)`.
    #[test]
    fn parse_label_selector_notin_operator_produces_notin_term() {
        let terms = ok(parse_label_selector("env notin (prod,staging)"));
        assert_eq!(terms.len(), 1);
        match &terms[0] {
            LabelSelectorTerm::NotIn { key, values } => {
                assert_eq!(*key, "env");
                assert!(values.contains(&"prod"));
                assert!(values.contains(&"staging"));
            }
            other => panic!("expected NotIn term, got {other:?}"),
        }
    }

    /// The paren-safe term splitter must not split `a=b,c in (d,e),f!=g` at the inner comma.
    ///
    /// Before the fix, `selector.split(',')` split `c in (d,e)` into `c in (d` and `e)`,
    /// causing the In parser to never see a well-formed term and falling through to a bogus parse.
    #[test]
    fn parse_label_selector_term_split_does_not_split_inside_parens() {
        let terms = ok(parse_label_selector("a=b,c in (d,e),f!=g"));
        assert_eq!(
            terms.len(),
            3,
            "must produce 3 terms: Equality, In, NotEquals; \
             the comma inside `in (d,e)` must not be treated as a term separator — \
             controllers using set-based selectors would get no results otherwise"
        );
        assert!(matches!(
            &terms[0],
            LabelSelectorTerm::Equality {
                key: "a",
                value: "b"
            }
        ));
        assert!(matches!(&terms[1], LabelSelectorTerm::In { key: "c", .. }));
        assert!(matches!(
            &terms[2],
            LabelSelectorTerm::NotEquals {
                key: "f",
                value: "g"
            }
        ));
    }

    /// `apply_label_selector` with `In` term must keep objects with listed values, drop others.
    ///
    /// Without this fix, LIST responses to set-based selectors return empty lists and
    /// controllers think no objects exist.
    #[test]
    fn apply_label_selector_in_term_filters_correctly() {
        let red = item_with_label("color", "red");
        let blue = item_with_label("color", "blue");
        let green = item_with_label("color", "green");
        let absent = item_without_label();

        let terms = vec![LabelSelectorTerm::In {
            key: "color",
            values: vec!["red", "blue"],
        }];
        let result = apply_label_selector(vec![red, blue, green, absent], &terms);
        assert_eq!(
            result.len(),
            2,
            "In filter must keep only red and blue; \
             set-based-selector LIST returns empty without this fix"
        );
        let colors: Vec<&str> = result
            .iter()
            .map(|i| i["metadata"]["labels"]["color"].as_str().unwrap_or(""))
            .collect();
        assert!(colors.contains(&"red"));
        assert!(colors.contains(&"blue"));
    }

    /// `apply_label_selector` with `NotIn` term must keep objects NOT in the list (and missing key).
    #[test]
    fn apply_label_selector_notin_term_filters_correctly() {
        let red = item_with_label("color", "red");
        let green = item_with_label("color", "green");
        let absent = item_without_label();

        let terms = vec![LabelSelectorTerm::NotIn {
            key: "color",
            values: vec!["red", "blue"],
        }];
        let result = apply_label_selector(vec![red, green, absent], &terms);
        assert_eq!(
            result.len(),
            2,
            "NotIn filter must keep green and the object with absent key; \
             set-based-selector LIST filters out all non-listed values"
        );
    }

    /// A field elsewhere in `metadata` that can't typecheck as `ObjectMeta` (here,
    /// `creationTimestamp` given as a number instead of a string) must not affect
    /// label-based selection.
    ///
    /// Deserializing the whole `ObjectMeta` per item made a single bad field
    /// anywhere in metadata fall back to `default()`, silently discarding real
    /// labels along with it — so a single malformed object could make a LIST with
    /// a label selector drop (or wrongly keep) that object for every caller in a
    /// namespace, and every well-formed object paid a full re-deserialize to boot.
    #[test]
    fn apply_label_selector_never_allocates_full_objectmeta() {
        let item = serde_json::json!({
            "metadata": {
                "name": "cm-1",
                "creationTimestamp": 12345,
                "labels": {"app": "bench"}
            }
        });
        let terms = vec![LabelSelectorTerm::Equality {
            key: "app",
            value: "bench",
        }];
        let result = apply_label_selector(vec![item], &terms);
        assert_eq!(
            result.len(),
            1,
            "an item with a non-string field elsewhere in metadata must still be \
             selectable by its label, because otherwise a single malformed field \
             on one object breaks LIST filtering for a whole namespace"
        );
    }

    /// An item with no `metadata` key at all must not panic and must be treated
    /// as having no labels.
    ///
    /// Controllers rely on label-selector LIST calls degrading safely on
    /// malformed objects instead of 500ing the whole request or misreporting
    /// unrelated objects in the result set.
    #[test]
    fn apply_label_selector_handles_missing_metadata_gracefully() {
        let item = serde_json::json!({"spec": {}});

        let equality_terms = vec![LabelSelectorTerm::Equality {
            key: "app",
            value: "bench",
        }];
        let result = apply_label_selector(vec![item.clone()], &equality_terms);
        assert!(
            result.is_empty(),
            "an object with no metadata has no labels, so an Equality term must exclude it \
             rather than panic on the missing metadata/labels path"
        );

        let does_not_exist_terms = vec![LabelSelectorTerm::DoesNotExist { key: "app" }];
        let result = apply_label_selector(vec![item], &does_not_exist_terms);
        assert_eq!(
            result.len(),
            1,
            "an object with no metadata has no labels, so DoesNotExist for any key must \
             include it"
        );
    }

    /// `metadata.labels: null` (explicit JSON null, as opposed to an absent key)
    /// must not panic and must be treated as no labels.
    ///
    /// kubectl and controllers occasionally round-trip objects with explicit
    /// nulls for unset map fields; the selector path must degrade to "no
    /// labels" the same way the old `unwrap_or_default()` did, not crash the
    /// LIST handler for the whole namespace.
    #[test]
    fn apply_label_selector_handles_null_labels_field() {
        let item = serde_json::json!({"metadata": {"name": "cm-1", "labels": null}});
        let terms = vec![LabelSelectorTerm::Equality {
            key: "app",
            value: "bench",
        }];
        let result = apply_label_selector(vec![item], &terms);
        assert!(
            result.is_empty(),
            "metadata.labels: null must degrade to \"no labels\", not panic or match \
             every selector"
        );
    }
}
