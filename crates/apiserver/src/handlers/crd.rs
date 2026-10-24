use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use u7s_store::{ListOptions, Store, StoreError};

use crate::handlers::json_patch::{
    apply_json_patch, detect_patch_type, is_dry_run_header, ssa_body_to_json, PatchType,
};
use crate::{
    admission::{
        run_mutating_webhooks, run_validating_webhooks, AdmissionContext, AdmissionTarget,
    },
    auth::UserInfo,
    state::AppState,
    status::Status,
    types::{DeleteOptions, Object},
    util::{
        content_type, extract_body, extract_body_quiet, parse_resource_version, utc_now_rfc3339,
    },
};

const GROUP: &str = "apiextensions.k8s.io";
const PLURAL: &str = "customresourcedefinitions";
const KIND: &str = "CustomResourceDefinition";
const API_VERSION: &str = "apiextensions.k8s.io/v1";

fn store_key(name: &str) -> String {
    format!("/registry/{GROUP}/{PLURAL}/{name}")
}

fn list_prefix() -> String {
    format!("/registry/{GROUP}/{PLURAL}/")
}

/// Key written as a tombstone when a CRD group is permanently deleted.
/// Presence of this key tells the CR handlers to return 410 Gone instead of
/// 404 Not Found — informers treat 410 as "stop watching" and 404 as a
/// transient error that should be retried indefinitely.
pub(crate) fn deleted_group_tombstone_key(group: &str) -> String {
    format!("/registry/apiextensions.k8s.io/deleted-groups/{group}")
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomResourceDefinitionNames {
    pub plural: String,
    pub singular: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub short_names: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub list_kind: String,
}

/// A single `x-kubernetes-selectable-fields` entry: a JSON path (e.g. ".spec.host") that
/// CR field selectors are allowed to reference for this version.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectableField {
    pub json_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomResourceDefinitionVersion {
    pub name: String,
    pub served: bool,
    pub storage: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
    /// Subresources declared for this version. The `status` key, if present
    /// and non-null, indicates that this version has a status subresource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subresources: Option<serde_json::Value>,
    /// Field paths CR field selectors may reference for this version (backs
    /// CustomResourceFieldSelectors). Without this field, `parse_crd`/`patch_crd` round-trip
    /// every CRD through this struct and silently drop any `selectableFields` the client sent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectable_fields: Vec<SelectableField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomResourceDefinitionSpec {
    pub group: String,
    pub names: CustomResourceDefinitionNames,
    pub scope: String,
    pub versions: Vec<CustomResourceDefinitionVersion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversion: Option<serde_json::Value>,
    #[serde(default)]
    pub preserve_unknown_fields: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrdMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resource_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub creation_timestamp: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub generation: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finalizers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_fields: Option<serde_json::Value>,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomResourceDefinition {
    pub api_version: String,
    pub kind: String,
    pub metadata: CrdMetadata,
    pub spec: CustomResourceDefinitionSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Built-in API group protection
// ---------------------------------------------------------------------------

/// API groups that CRDs must never shadow. Allowing a CRD to claim one of
/// these groups would let an unprivileged actor intercept or replace built-in
/// Kubernetes API objects (e.g. create a "pods" CRD in group "apps" and have
/// it served instead of the real apps/v1 Deployments).
const BUILTIN_GROUPS: &[&str] = &[
    "",
    "apps",
    "batch",
    "autoscaling",
    "rbac.authorization.k8s.io",
    "authorization.k8s.io",
    "authentication.k8s.io",
    "apiextensions.k8s.io",
    "admissionregistration.k8s.io",
    "networking.k8s.io",
    "policy",
    "storage.k8s.io",
    "scheduling.k8s.io",
    "coordination.k8s.io",
    "node.k8s.io",
    "discovery.k8s.io",
    "events.k8s.io",
    "internal.apiserver.k8s.io",
];

/// Validate that a CRD spec.group does not shadow a built-in API group and
/// contains no path traversal characters.
fn validate_crd_group(group: &str) -> Result<(), crate::status::StatusError> {
    // Block path traversal in group name.
    if group.contains('/') || group.contains("..") {
        return Err(Status::unprocessable_entity(format!(
            "spec.group '{}' must not contain '/' or '..'",
            group
        )));
    }
    // Block built-in groups.
    if BUILTIN_GROUPS.contains(&group) {
        return Err(Status::unprocessable_entity(format!(
            "spec.group '{}' shadows a built-in Kubernetes API group and is not allowed; \
             choose a group name you control (e.g. 'myapp.example.com')",
            group
        )));
    }
    Ok(())
}

/// Maximum length, in bytes, for a `pattern` string or a `patternProperties` key in a
/// CRD's `openAPIV3Schema`. boon (the JSON-schema engine u7s compiles CRD schemas with)
/// runs an ECMA-to-Rust-regex compatibility rewrite (boon-0.6.1 src/ecma.rs::convert)
/// before `Regex::new` ever sees the pattern, and that rewrite is O(pattern_length^2) —
/// so `regex::RegexBuilder::size_limit` cannot protect against it, since the shim's cost
/// is paid before compilation. Real-world CRD patterns top out at 113 bytes (median 91);
/// this cap gives ~9x headroom while keeping worst-case compile cost bounded.
pub(crate) const MAX_CRD_PATTERN_BYTES: usize = 1024;

/// Walk a single JSON-Schema node (and everything nested under it — `properties`,
/// `items`, `additionalProperties`, `allOf`/`anyOf`/`oneOf`, etc.) rejecting the two
/// `openAPIV3Schema` shapes that can blow up boon's ECMA-compat regex rewrite:
/// `patternProperties` (forbidden outright, matching upstream K8s's structural-schema
/// rule, apiextensions-apiserver release-1.36 validation.go:1493-1494) and any `pattern`
/// longer than `MAX_CRD_PATTERN_BYTES`.
pub(crate) fn walk_schema_dos_bounds(
    node: &serde_json::Value,
    field_path: &str,
) -> Result<(), crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => {
            if let Some(pp) = map.get("patternProperties").and_then(|v| v.as_object()) {
                // Defense-in-depth: bound key length unconditionally, not only when
                // patternProperties happens to be non-empty below — a future change that
                // relaxes the outright rejection must not silently reopen the boon
                // O(n^2) ReDoS via unbounded patternProperties keys.
                for key in pp.keys() {
                    if key.len() > MAX_CRD_PATTERN_BYTES {
                        return Err(Status::unprocessable_entity(format!(
                            "{field_path}.patternProperties key exceeds maximum length of \
                             {MAX_CRD_PATTERN_BYTES} bytes (was {} bytes) — see ReDoS defense",
                            key.len()
                        )));
                    }
                }
                if !pp.is_empty() {
                    return Err(Status::unprocessable_entity(format!(
                        "{field_path}.patternProperties: patternProperties is not supported"
                    )));
                }
            }
            if let Some(pattern) = map.get("pattern").and_then(|v| v.as_str()) {
                if pattern.len() > MAX_CRD_PATTERN_BYTES {
                    return Err(Status::unprocessable_entity(format!(
                        "{field_path}.pattern exceeds maximum length of {MAX_CRD_PATTERN_BYTES} \
                         bytes (was {} bytes) — see ReDoS defense",
                        pattern.len()
                    )));
                }
            }
            for (key, value) in map {
                walk_schema_dos_bounds(value, &format!("{field_path}.{key}"))?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk_schema_dos_bounds(item, &format!("{field_path}[{i}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Validate a CRD's `openAPIV3Schema` (across all versions) against the boon-ReDoS
/// class of bugs before persisting the CRD. `stored` is the previous CRD on update: its
/// expressions and unchanged version schemas are ratcheted so an unrelated write cannot
/// start failing on a rule that was already accepted.
fn validate_crd_schema(
    spec: &CustomResourceDefinitionSpec,
    stored: Option<&serde_json::Value>,
) -> Result<(), crate::status::StatusError> {
    let mut preexisting = std::collections::HashSet::new();
    if let Some(stored) = stored {
        crate::handlers::cel_rules::collect_expressions(&stored["spec"], &mut preexisting);
    }
    for version in &spec.versions {
        let Some(schema) = version
            .schema
            .as_ref()
            .and_then(|s| s.get("openAPIV3Schema"))
        else {
            continue;
        };
        let path = format!("spec.versions[{}].schema.openAPIV3Schema", version.name);
        walk_schema_dos_bounds(schema, &path)?;
        let ratchet = crate::handlers::cel_rules::Ratchet {
            preexisting: stored.map(|_| &preexisting),
        };
        crate::handlers::cel_rules::check_schema_rules(schema, &path, true, &ratchet)?;
    }
    Ok(())
}

/// Reject a PUT/PATCH that changes spec.group, spec.scope, or spec.names.{plural,singular,kind}
/// relative to the stored CRD. These four fields are structural identity, immutable upstream:
/// CRs are stored under a group-and-plural-keyed prefix (see build_new_crd's storage-key
/// comment), so changing spec.group or spec.names.plural on an existing CRD orphans every
/// already-stored CR under the old key prefix — permanently unreachable through the CRD's new
/// identity, not merely a validation gap. Changing spec.scope would likewise desync
/// namespaced-vs-cluster-scoped storage key shape for existing objects.
fn reject_structural_field_change(
    existing: &serde_json::Value,
    new_spec: &CustomResourceDefinitionSpec,
    name: &str,
) -> Result<(), crate::status::StatusError> {
    let existing_group = existing["spec"]["group"].as_str().unwrap_or("");
    if existing_group != new_spec.group {
        return Err(Status::unprocessable_entity(format!(
            "{name}: spec.group is immutable (was '{existing_group}', got '{}')",
            new_spec.group
        )));
    }
    let existing_scope = existing["spec"]["scope"].as_str().unwrap_or("");
    if existing_scope != new_spec.scope {
        return Err(Status::unprocessable_entity(format!(
            "{name}: spec.scope is immutable (was '{existing_scope}', got '{}')",
            new_spec.scope
        )));
    }
    let existing_plural = existing["spec"]["names"]["plural"].as_str().unwrap_or("");
    if existing_plural != new_spec.names.plural {
        return Err(Status::unprocessable_entity(format!(
            "{name}: spec.names.plural is immutable (was '{existing_plural}', got '{}')",
            new_spec.names.plural
        )));
    }
    let existing_singular = existing["spec"]["names"]["singular"].as_str().unwrap_or("");
    if existing_singular != new_spec.names.singular {
        return Err(Status::unprocessable_entity(format!(
            "{name}: spec.names.singular is immutable (was '{existing_singular}', got '{}')",
            new_spec.names.singular
        )));
    }
    let existing_kind = existing["spec"]["names"]["kind"].as_str().unwrap_or("");
    if existing_kind != new_spec.names.kind {
        return Err(Status::unprocessable_entity(format!(
            "{name}: spec.names.kind is immutable (was '{existing_kind}', got '{}')",
            new_spec.names.kind
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_crd(body: &Bytes) -> Result<CustomResourceDefinition, crate::status::StatusError> {
    serde_json::from_slice(body)
        .map_err(|e| Status::unprocessable_entity(format!("invalid CustomResourceDefinition: {e}")))
}

fn store_err_crd(err: StoreError, name: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(GROUP, PLURAL, name),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, KIND),
        other => Status::internal(other.to_string()),
    }
}

fn stamp_server_fields(crd: &mut CustomResourceDefinition) {
    if crd.metadata.uid.is_empty() {
        crd.metadata.uid = new_uid();
    }
    crd.metadata.creation_timestamp = utc_now_rfc3339();
    crd.metadata.deletion_timestamp = None;
    crd.api_version = API_VERSION.to_string();
    crd.kind = KIND.to_string();
}

/// Upstream `crdStrategy.PrepareForUpdate`: the stored generation always wins over the
/// client/webhook value, and any `spec` change bumps it by one.
fn prepare_crd_generation_for_update(
    existing: &serde_json::Value,
    crd: &mut CustomResourceDefinition,
) {
    let stored = existing["metadata"]["generation"].as_i64().unwrap_or(0);
    let spec_changed = serde_json::to_value(&crd.spec)
        .map(|spec| spec != existing["spec"])
        .unwrap_or(false);
    crd.metadata.generation = if spec_changed {
        stored.saturating_add(1)
    } else {
        stored
    };
}

fn new_uid() -> String {
    // Use UUIDv4 (CSPRNG) for uid generation. The previous implementation
    // formatted system time as hex — two CRDs created in the same nanosecond
    // would collide, and the value was predictable (no entropy). Kubernetes
    // expects UIDs in UUID string format (RFC 4122).
    uuid::Uuid::new_v4().to_string()
}

/// Record the writer of a non-apply write as owner of every field it changed from `before`
/// (`Value::Null` for a create).
fn record_crd_write(
    headers: &HeaderMap,
    before: &serde_json::Value,
    crd: &mut CustomResourceDefinition,
) -> Result<(), crate::status::StatusError> {
    let mut after = serde_json::to_value(&*crd).map_err(|e| Status::internal(e.to_string()))?;
    crate::field_manager::WriteIdentity::new(None, headers).record(
        before,
        &mut after,
        API_VERSION,
        None,
        None,
    );
    crd.metadata.managed_fields = after["metadata"].get("managedFields").cloned();
    Ok(())
}

fn to_bytes(crd: &CustomResourceDefinition) -> Result<Bytes, crate::status::StatusError> {
    serde_json::to_vec(crd)
        .map(Bytes::from)
        .map_err(|e| Status::internal(e.to_string()))
}

/// Remove `cr_schema_cache` entries left behind by a CRD generation that a write
/// (replace/patch) or a delete just superseded. `old_group`/`old_version_names`/
/// `old_resource_version` describe the CRD *before* that write, i.e. exactly the values
/// the now-stale entries were cached under. This is memory hygiene only, not a
/// correctness requirement: the CRD's next resourceVersion is always different (the
/// store's revision counter is global and never reused), so a stale entry could never
/// be looked up again even if this were never called.
pub(crate) fn evict_cr_schema_cache<S: Store>(
    state: &AppState<S>,
    old_group: &str,
    old_version_names: &[String],
    old_resource_version: &str,
) {
    if old_resource_version.is_empty() {
        return;
    }
    for version in old_version_names {
        state.cr_schema_cache.invalidate(&(
            old_group.to_string(),
            version.clone(),
            old_resource_version.to_string(),
        ));
    }
}

/// Remove `cr_context_cache` entries for a CRD's every served version. Unlike
/// `evict_cr_schema_cache` above, this IS a correctness requirement, not just hygiene: the
/// cache key (`state::CrContextCache`) has no resourceVersion component, so a stale entry
/// stays a "hit" indefinitely until explicitly removed — a write that changes the CRD's
/// schema, subresources, or served-version list must evict here or `find_crd` keeps handing
/// out the pre-write `CrContext` forever. `group`/`plural` are invariant across a CRD's
/// lifetime (rejected by `reject_structural_field_change`), so the same (group, plural) is
/// correct whether called with the pre- or post-write version list.
pub(crate) fn evict_cr_context_cache<S: Store>(
    state: &AppState<S>,
    group: &str,
    plural: &str,
    version_names: &[String],
) {
    for version in version_names {
        state.cr_context_cache.invalidate(&(
            group.to_string(),
            version.clone(),
            plural.to_string(),
        ));
    }
}

/// Extract `(spec.group, [versions[].name], spec.names.plural, metadata.resourceVersion)`
/// from a raw CRD `Value` — used to find the `cr_schema_cache`/`cr_context_cache` keys a CRD
/// generation was cached under, without needing a full `CustomResourceDefinition` parse.
pub(crate) fn crd_cache_identity(crd: &serde_json::Value) -> (String, Vec<String>, String, String) {
    let group = crd["spec"]["group"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let versions = crd["spec"]["versions"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let plural = crd["spec"]["names"]["plural"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let resource_version = crd["metadata"]["resourceVersion"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (group, versions, plural, resource_version)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn list_crds<S: Store>(
    State(state): State<AppState<S>>,
    Query(query): Query<super::generic::CollectionQuery>,
    headers: HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    let prefix = list_prefix();
    let field_selector = super::field_selector::FieldSelector::parse(
        query.field_selector.as_deref(),
        GROUP,
        PLURAL,
    )?;

    if query.watch == Some(true) {
        let accept = headers
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let pom = super::generic::wants_partial_object_metadata(accept);
        let (watch_api_version, watch_kind) = if pom {
            (
                "meta.k8s.io/v1".to_string(),
                "PartialObjectMetadata".to_string(),
            )
        } else {
            (API_VERSION.to_string(), KIND.to_string())
        };
        let initial_items = super::watch::fetch_initial_events(
            &state,
            &prefix,
            query.send_initial_events == Some(true),
            "apiextensions.k8s.io",
            "customresourcedefinitions",
        )
        .await?;
        return super::watch::watch_generic(
            state,
            super::watch::WatchConfig {
                prefix,
                api_version: watch_api_version,
                kind: watch_kind,
                from_revision: query.resource_version.unwrap_or(0),
                initial_items,
                explicit_no_initial_events: query.send_initial_events == Some(false),
                label_selector: query.label_selector,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username: user.username,
                as_partial_object_metadata: pom,
                group: GROUP.to_string(),
                plural: PLURAL.to_string(),
                timeout_seconds: query.timeout_seconds,
            },
        )
        .await;
    }

    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                field_selector: field_selector.store_selector(),
                ..ListOptions::default()
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
    let items = field_selector.filter(items);

    let items = if let Some(ref sel) = query.label_selector {
        let pairs = super::generic::parse_label_selector(sel)?;
        super::generic::apply_label_selector(items, &pairs)
    } else {
        items
    };

    let body = serde_json::json!({
        "kind": "CustomResourceDefinitionList",
        "apiVersion": API_VERSION,
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items,
    });
    Ok(Json(body).into_response())
}

/// Run the defaulting/validation/admission/status-stamping pipeline a brand-new CRD must go
/// through before it is persisted. Shared by `create_crd` (POST) and `patch_crd`'s SSA
/// create-on-missing branch, so `kubectl apply --server-side` against a CRD name that doesn't
/// exist yet gets the same name-format check, group/schema validation, admission webhooks, and
/// Established/NamesAccepted status stamping as `kubectl create` — instead of drifting out of
/// sync with `create_crd` over time.
async fn build_new_crd<S: Store>(
    state: &AppState<S>,
    user: &UserInfo,
    name: &str,
    mut crd: CustomResourceDefinition,
    headers: &HeaderMap,
) -> Result<CustomResourceDefinition, crate::status::StatusError> {
    if name.is_empty() {
        return Err(Status::unprocessable_entity(
            "metadata.name is required".into(),
        ));
    }

    validate_crd_group(&crd.spec.group)?;
    validate_crd_schema(&crd.spec, None)?;

    let expected_name = format!("{}.{}", crd.spec.names.plural, crd.spec.group);
    if name != expected_name {
        return Err(Status::unprocessable_entity(format!(
            "metadata.name must be {expected_name} (got {name})"
        )));
    }

    stamp_server_fields(&mut crd);

    // Admission webhook pipeline (mutating then validating).
    {
        let admission_ctx = AdmissionContext {
            group: "apiextensions.k8s.io",
            version: "v1",
            resource: "customresourcedefinitions",
            name,
            namespace: None,
            operation: "CREATE",
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
                "extra": user.extra,
            })),
            dry_run: is_dry_run_header(headers),
        };
        let obj_val = serde_json::to_value(&crd).map_err(|e| Status::internal(e.to_string()))?;
        let mutated = run_mutating_webhooks(state, obj_val, None, &admission_ctx).await?;
        run_validating_webhooks(state, &mutated, None, &admission_ctx).await?;
        crd = serde_json::from_value(mutated)
            .map_err(|e| Status::internal(format!("admission mutated CRD is invalid: {e}")))?;
    }
    crd.metadata.generation = 1;
    if !crd
        .metadata
        .finalizers
        .iter()
        .any(|f| f == CLEANUP_FINALIZER)
    {
        crd.metadata.finalizers.push(CLEANUP_FINALIZER.into());
    }

    // Stamp status.conditions so controllers and conformance tests see the CRD
    // as ready immediately after creation (no separate status update loop).
    crd.status = Some(serde_json::json!({
        "conditions": [
            {
                "type": "Established",
                "status": "True",
                "reason": "InitialNamesAccepted",
                "message": "the initial names have been accepted"
            },
            {
                "type": "NamesAccepted",
                "status": "True",
                "reason": "NoConflicts",
                "message": "no conflicts found"
            }
        ]
    }));

    Ok(crd)
}

pub async fn create_crd<S: Store>(
    State(state): State<AppState<S>>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct)?;
    let crd = parse_crd(&body)?;
    let name = crd.metadata.name.clone();
    let mut crd = build_new_crd(&state, &user, &name, crd, &headers).await?;
    record_crd_write(&headers, &serde_json::Value::Null, &mut crd)?;

    // Dry-run: validation and admission passed; return the would-be created CRD without
    // persisting — mirrors create_resource's dry-run early-return in resource.rs.
    if is_dry_run_header(&headers) {
        return Ok((StatusCode::CREATED, Json(crd)));
    }

    let key = store_key(&name);
    let rv = state
        .store
        .put(&key, to_bytes(&crd)?, Some(0))
        .await
        .map_err(|e| store_err_crd(e, &name))?;

    state.cr_context_cache.invalidate_absent();
    let tombstone_key = deleted_group_tombstone_key(&crd.spec.group);
    let _ = state.store.delete(&tombstone_key, None).await;
    crate::handlers::discovery::refresh_discovery_cache(&state).await;

    crd.metadata.resource_version = rv.to_string();
    Ok((StatusCode::CREATED, Json(crd)))
}

pub async fn get_crd<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
) -> Result<Response, crate::status::StatusError> {
    let key = store_key(&name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(GROUP, PLURAL, &name))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn replace_crd<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct)?;
    let mut crd = parse_crd(&body)?;

    if crd.metadata.name != name {
        return Err(Status::unprocessable_entity(format!(
            "the name of the object ({}) does not match the name on the URL ({name})",
            crd.metadata.name
        )));
    }

    let key = store_key(&name);

    // Ensure the object exists before replacing.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(GROUP, PLURAL, &name))?;

    let existing: serde_json::Value =
        serde_json::from_slice(&stored.value).unwrap_or(serde_json::Value::Null);

    // PUT .../customresourcedefinitions/{name} is the MAIN endpoint; the CRD's own status
    // (Established/NamesAccepted/StoredVersions conditions) is a dedicated subresource —
    // clients must use PUT .../status. Restore whatever is already stored rather than
    // trusting `crd.status` as parsed from the client body: unlike a Custom Resource's
    // schema-typed status, `CustomResourceDefinition.status` is a bare
    // `Option<serde_json::Value>`, so a body like {"status":"x"} deserializes successfully
    // in parse_crd and would otherwise persist an invalid scalar status (or, on any normal
    // status-omitting PUT, silently wipe the conditions create_crd stamped).
    let stored_status = existing["status"].clone();
    crd.status = if stored_status.is_null() {
        None
    } else {
        Some(stored_status)
    };

    reject_structural_field_change(&existing, &crd.spec, &name)?;
    validate_crd_schema(&crd.spec, Some(&existing))?;

    // Preserve server-assigned creationTimestamp from stored copy if not present in incoming.
    if crd.metadata.creation_timestamp.is_empty() {
        if let Some(ts) = existing["metadata"]["creationTimestamp"].as_str() {
            crd.metadata.creation_timestamp = ts.to_string();
        }
    }

    // metadata.uid is immutable identity, exactly like the generic replace_resource path
    // (resource.rs): a blank incoming uid is restored from the stored object, but a
    // non-blank incoming uid that mismatches the stored one is identity forgery, not a
    // legitimate update — allowing it would let a client forge a match against a
    // stale/foreign ownerReference (corrupting the garbage collector's cascade-GC decision) or
    // defeat controllers' "same name, different uid ⇒ different object" recreate-detection.
    // CustomResourceDefinition routes around the generic path entirely (bespoke handler), so
    // it never got 2pzru's fix.
    let existing_uid = existing["metadata"]["uid"].as_str().unwrap_or("");
    if crd.metadata.uid.is_empty() {
        if !existing_uid.is_empty() {
            crd.metadata.uid = existing_uid.to_string();
        }
    } else if !existing_uid.is_empty() && crd.metadata.uid != existing_uid {
        return Err(Status::conflict(format!(
            "{KIND} \"{name}\": the object was updated with a mismatched uid \
             (got {}, expected {existing_uid}) — uid is immutable",
            crd.metadata.uid
        )));
    }

    crd.metadata.deletion_timestamp = existing["metadata"]["deletionTimestamp"]
        .as_str()
        .map(str::to_string);

    crd.api_version = API_VERSION.to_string();
    crd.kind = KIND.to_string();

    let expected_rv: Option<u64> = if crd.metadata.resource_version.is_empty() {
        None
    } else {
        crd.metadata.resource_version.parse::<u64>().ok()
    };

    // Admission webhook pipeline (mutating then validating).
    {
        let admission_ctx = AdmissionContext {
            group: "apiextensions.k8s.io",
            version: "v1",
            resource: "customresourcedefinitions",
            name: &name,
            namespace: None,
            operation: "UPDATE",
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
                "extra": user.extra,
            })),
            dry_run: is_dry_run_header(&headers),
        };
        let obj_val = serde_json::to_value(&crd).map_err(|e| Status::internal(e.to_string()))?;
        let mutated =
            run_mutating_webhooks(&state, obj_val, Some(&existing), &admission_ctx).await?;
        run_validating_webhooks(&state, &mutated, Some(&existing), &admission_ctx).await?;
        crd = serde_json::from_value(mutated)
            .map_err(|e| Status::internal(format!("admission mutated CRD is invalid: {e}")))?;
    }
    prepare_crd_generation_for_update(&existing, &mut crd);
    record_crd_write(&headers, &existing, &mut crd)?;

    // Dry-run: validation and admission passed; return the would-be replaced CRD without
    // persisting — mirrors replace_namespaced_resource's dry-run early-return in resource.rs.
    if is_dry_run_header(&headers) {
        return Ok(Json(crd));
    }

    let rv = state
        .store
        .put(&key, to_bytes(&crd)?, expected_rv)
        .await
        .map_err(|e| store_err_crd(e, &name))?;
    if crd.metadata.deletion_timestamp.is_some() {
        state.crd_finalizer_wake.notify_one();
    }

    // Clear any stale tombstone for this group. Without this, a CRD deleted then
    // re-created via PUT (replace_crd) would leave a tombstone in the store — mirroring
    // the tombstone-clear that create_crd (POST) already does at crd.rs:362-363.
    let tombstone_key = deleted_group_tombstone_key(&crd.spec.group);
    let _ = state.store.delete(&tombstone_key, None).await;

    let (old_group, old_versions, old_plural, old_rv) = crd_cache_identity(&existing);
    evict_cr_schema_cache(&state, &old_group, &old_versions, &old_rv);
    evict_cr_context_cache(&state, &old_group, &old_plural, &old_versions);
    crate::handlers::discovery::refresh_discovery_cache(&state).await;

    crd.metadata.resource_version = rv.to_string();
    Ok(Json(crd))
}

pub async fn delete_crd<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let key = store_key(&name);

    // Check existence first to return 404 rather than a store error.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(GROUP, PLURAL, &name))?;

    // Parse DeleteOptions from the request body (same pattern as single-object delete
    // handlers). client-go's typed Delete() sends DryRun in this body; a raw/proxied caller
    // may instead send it as ?dryRun=All (caught by the router-wide inject_dry_run_header
    // layer) — accept either.
    // DeleteOptions parsing is intentionally lenient: a malformed/undecodable body must never
    // block a DELETE, so extract_body_quiet's Err falls back to the original bytes here
    // (matching the pre-existing serde_json::from_slice(...).unwrap_or_default() below) without
    // warning — this path is hit by every real client's protobuf DELETE.
    let body = extract_body_quiet(&body, content_type(&headers)).unwrap_or_else(|_| body.clone());
    let delete_opts: DeleteOptions = if body.is_empty() {
        DeleteOptions::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };
    let dry_run = delete_opts.is_dry_run() || is_dry_run_header(&headers);

    // Parsed once as the admission review object.
    let existing: serde_json::Value =
        serde_json::from_slice(&stored.value).unwrap_or(serde_json::Value::Null);

    // Admission webhook pipeline (validating only — mutating webhooks do not apply to DELETE).
    let admission_ctx = AdmissionContext {
        group: "apiextensions.k8s.io",
        version: "v1",
        resource: "customresourcedefinitions",
        name: &name,
        namespace: None,
        operation: "DELETE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run,
    };
    run_validating_webhooks(&state, &existing, Some(&existing), &admission_ctx).await?;

    // Dry-run: validation passed; return the would-be Success status without persisting or
    // running any of the cascade side effects (schema/conversion-cache evict, watch-ring
    // free, discovery refresh, group tombstone) below.
    if dry_run {
        return Ok(Json(serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Success",
            "code": 200
        })));
    }

    soft_delete_crd(&state, &name, existing, stored.revision)
        .await
        .map(Json)
}

/// Marks a CRD Terminating (deletionTimestamp + cleanup finalizer) and runs one finalizer
/// pass. Skips admission, so the namespace cascade can share it with the DELETE handler.
pub(crate) async fn soft_delete_crd<S: Store>(
    state: &AppState<S>,
    name: &str,
    existing: serde_json::Value,
    expected_rv: u64,
) -> Result<serde_json::Value, crate::status::StatusError> {
    let key = store_key(name);
    let (group, versions, plural, resource_version) = crd_cache_identity(&existing);
    // Upstream's registry soft-deletes any object carrying finalizers; the cleanup finalizer
    // is added unconditionally here so CRDs persisted before it existed also get their
    // instances removed.
    let mut crd = existing;
    let finalizers = crd["metadata"]["finalizers"].take();
    let mut finalizers = finalizers.as_array().cloned().unwrap_or_default();
    if !finalizers.iter().any(|f| f == CLEANUP_FINALIZER) {
        finalizers.push(serde_json::Value::String(CLEANUP_FINALIZER.into()));
    }
    crd["metadata"]["finalizers"] = serde_json::Value::Array(finalizers);
    if crd["metadata"]["deletionTimestamp"].is_null() {
        crd["metadata"]["deletionTimestamp"] = serde_json::Value::String(utc_now_rfc3339());
    }
    set_terminating_condition(
        &mut crd,
        "True",
        "InstanceDeletionInProgress",
        "CustomResource deletion is in progress",
    );
    let rv = state
        .store
        .put(&key, Bytes::from(crd.to_string()), Some(expected_rv))
        .await
        .map_err(|e| store_err_crd(e, name))?;
    crd["metadata"]["resourceVersion"] = serde_json::Value::String(rv.to_string());
    // New instance creates must see the Terminating state immediately.
    evict_cr_schema_cache(state, &group, &versions, &resource_version);
    evict_cr_context_cache(state, &group, &plural, &versions);

    if finalize_crd(state, name).await {
        state.crd_finalizer_wake.notify_one();
    }

    Ok(crd)
}

pub(crate) const CLEANUP_FINALIZER: &str = "customresourcecleanup.apiextensions.k8s.io";

/// Upserts the `Terminating` condition; returns whether `crd` changed. `lastTransitionTime`
/// only moves when the status flips, so re-asserting the same state is a byte-identical
/// no-op write instead of a resourceVersion bump per sweep.
fn set_terminating_condition(
    crd: &mut serde_json::Value,
    status: &str,
    reason: &str,
    message: &str,
) -> bool {
    if !crd["status"].is_object() {
        crd["status"] = serde_json::json!({});
    }
    if !crd["status"]["conditions"].is_array() {
        crd["status"]["conditions"] = serde_json::json!([]);
    }
    let conds = crd["status"]["conditions"]
        .as_array_mut()
        .expect("conditions was just coerced to an array");
    let existing = conds
        .iter_mut()
        .find(|c| c["type"].as_str() == Some("Terminating"));
    let transition = match &existing {
        Some(c) if c["status"].as_str() == Some(status) => c["lastTransitionTime"].clone(),
        _ => serde_json::Value::String(utc_now_rfc3339()),
    };
    let new = serde_json::json!({
        "type": "Terminating",
        "status": status,
        "reason": reason,
        "message": message,
        "lastTransitionTime": transition,
    });
    match existing {
        Some(c) if *c == new => false,
        Some(c) => {
            *c = new;
            true
        }
        None => {
            conds.push(new);
            true
        }
    }
}

/// Terminating-condition (reason, message) for a failed instance deletion, matching upstream's
/// `InstanceDeletionFailed` shapes.
type InstanceDeletionFailure = (&'static str, String);

/// Deletes every instance of the CRD's resource. Instances carrying their own finalizers are
/// only marked for deletion, so the count of instances still present is returned, plus whether
/// this pass issued any new delete (false means every remaining instance was already held by
/// its own finalizers from an earlier pass).
async fn delete_instances<S: Store>(
    state: &AppState<S>,
    group: &str,
    plural: &str,
) -> Result<(usize, bool), InstanceDeletionFailure> {
    let prefix = crate::handlers::cr::cr_list_prefix(group, plural, None);
    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| {
            (
                "InstanceDeletionFailed",
                format!("could not list instances: {e}"),
            )
        })?;
    let mut remaining = 0;
    let mut issued = false;
    let mut errors: Vec<String> = Vec::new();
    for item in resp.items {
        let Ok(mut obj) = Object::from_bytes(&item.value) else {
            remaining += 1;
            continue;
        };
        if !obj.body["metadata"]["deletionTimestamp"].is_null() {
            remaining += 1;
            continue;
        }
        issued = true;
        let result = if crate::handlers::generic::apply_delete_policy(&mut obj).is_some() {
            remaining += 1;
            state
                .store
                .put(&item.key, obj.to_bytes(), Some(item.revision))
                .await
                .map(|_| ())
        } else {
            state
                .store
                .delete(&item.key, Some(item.revision))
                .await
                .map(|_| ())
        };
        match result {
            Ok(()) | Err(StoreError::NotFound { .. }) => {}
            // Written concurrently (another finalizer pass or a client); the next pass retries.
            Err(StoreError::RevisionMismatch { .. }) => remaining += 1,
            Err(e) => errors.push(format!("{}: {e}", item.key)),
        }
    }
    if errors.is_empty() {
        Ok((remaining, issued))
    } else {
        Err((
            "InstanceDeletionFailed",
            format!("could not issue all deletes: [{}]", errors.join(", ")),
        ))
    }
}

fn terminating_condition_status(crd: &serde_json::Value) -> Option<&str> {
    crd["status"]["conditions"]
        .as_array()?
        .iter()
        .find(|c| c["type"].as_str() == Some("Terminating"))
        .and_then(|c| c["status"].as_str())
}

fn is_established(crd: &serde_json::Value) -> bool {
    crd["status"]["conditions"].as_array().is_some_and(|conds| {
        conds
            .iter()
            .any(|c| c["type"].as_str() == Some("Established") && c["status"] == "True")
    })
}

/// One pass of upstream's CRD finalizing controller for a terminating CRD: delete its
/// instances, and once none remain drop the cleanup finalizer; the CRD itself goes away when
/// no finalizers are left. Safe to call repeatedly and concurrently — every write is
/// resourceVersion-checked and a lost race is retried by the next pass.
///
/// Like upstream, instances are removed straight from storage: no admission webhooks run.
/// Returns whether the CRD still exists after the pass.
pub(crate) async fn finalize_crd<S: Store>(state: &AppState<S>, name: &str) -> bool {
    let key = store_key(name);
    let Ok(Some(stored)) = state.store.get(&key).await else {
        return false;
    };
    let Ok(mut crd) = serde_json::from_slice::<serde_json::Value>(&stored.value) else {
        return false;
    };
    if crd["metadata"]["deletionTimestamp"].is_null() {
        return false;
    }
    let mut rv = stored.revision;
    let finalizers: Vec<serde_json::Value> = crd["metadata"]["finalizers"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    if finalizers.iter().any(|f| f == CLEANUP_FINALIZER) {
        // A condition already True (including a failure reason) is left alone so a failing
        // CRD is not rewritten on every retry.
        if terminating_condition_status(&crd) != Some("True")
            && set_terminating_condition(
                &mut crd,
                "True",
                "InstanceDeletionInProgress",
                "CustomResource deletion is in progress",
            )
        {
            let Ok(new_rv) = state
                .store
                .put(&key, Bytes::from(crd.to_string()), Some(rv))
                .await
            else {
                return true;
            };
            rv = new_rv;
        }
        if is_established(&crd) {
            let group = crd["spec"]["group"].as_str().unwrap_or("").to_string();
            let plural = crd["spec"]["names"]["plural"]
                .as_str()
                .unwrap_or("")
                .to_string();
            match delete_instances(state, &group, &plural).await {
                Ok((0, _)) => {
                    set_terminating_condition(
                        &mut crd,
                        "False",
                        "InstanceDeletionCompleted",
                        "removed all instances",
                    );
                }
                Ok((remaining, issued)) => {
                    // Upstream polls for zero instances after the delete pass and reports
                    // InstanceDeletionCheck when some never go away; here that is every
                    // remaining instance already held by its own finalizers from a prior pass.
                    // Otherwise deletes were just issued; this also clears any earlier failure.
                    let (reason, message) = if issued {
                        (
                            "InstanceDeletionInProgress",
                            "CustomResource deletion is in progress".to_string(),
                        )
                    } else {
                        (
                            "InstanceDeletionCheck",
                            format!(
                                "could not confirm zero CustomResources remaining: \
                                 {remaining} instance(s) still present"
                            ),
                        )
                    };
                    if set_terminating_condition(&mut crd, "True", reason, &message) {
                        let _ = state
                            .store
                            .put(&key, Bytes::from(crd.to_string()), Some(rv))
                            .await;
                    }
                    return true;
                }
                Err((reason, message)) => {
                    if set_terminating_condition(&mut crd, "True", reason, &message) {
                        let _ = state
                            .store
                            .put(&key, Bytes::from(crd.to_string()), Some(rv))
                            .await;
                    }
                    return true;
                }
            }
        } else {
            set_terminating_condition(
                &mut crd,
                "False",
                "NeverEstablished",
                "resource was never established",
            );
        }
        let kept: Vec<serde_json::Value> = finalizers
            .into_iter()
            .filter(|f| f != CLEANUP_FINALIZER)
            .collect();
        if kept.is_empty() {
            crd["metadata"]
                .as_object_mut()
                .expect("metadata is an object")
                .remove("finalizers");
        } else {
            crd["metadata"]["finalizers"] = serde_json::Value::Array(kept);
        }
        let Ok(new_rv) = state
            .store
            .put(&key, Bytes::from(crd.to_string()), Some(rv))
            .await
        else {
            return true;
        };
        rv = new_rv;
    }

    let drained = crd["metadata"]["finalizers"]
        .as_array()
        .is_none_or(|f| f.is_empty());
    if drained {
        crd["metadata"]["resourceVersion"] = serde_json::Value::String(rv.to_string());
        return purge_crd(state, &key, name, &crd, rv).await.is_err();
    }
    true
}

/// Finalizes every terminating CRD and returns how many remain, so the caller can keep
/// retrying only while there is work. Listing every CRD is the price of resuming after an
/// apiserver restart, so callers must not run this on an idle timer.
pub(crate) async fn reconcile_terminating_crds<S: Store>(state: &AppState<S>) -> usize {
    let Ok(resp) = state
        .store
        .list(&list_prefix(), ListOptions::default())
        .await
    else {
        return 1;
    };
    let mut remaining = 0;
    for item in resp.items {
        let Ok(crd) = serde_json::from_slice::<serde_json::Value>(&item.value) else {
            continue;
        };
        if crd["metadata"]["deletionTimestamp"].is_null() {
            continue;
        }
        if let Some(name) = crd["metadata"]["name"].as_str() {
            if finalize_crd(state, name).await {
                remaining += 1;
            }
        }
    }
    remaining
}

/// Drives `scan` (which returns how many CRDs are still terminating): once at startup, then
/// whenever `wake` fires, and on `retry` only while the last scan left work behind. With
/// nothing terminating the loop parks, so an idle server never lists CRDs.
pub(crate) async fn run_crd_finalizer<F, Fut>(
    wake: &tokio::sync::Notify,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    retry: std::time::Duration,
    mut scan: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = usize>,
{
    loop {
        let terminating = scan().await;
        let retry_sleep = async {
            if terminating > 0 {
                tokio::time::sleep(retry).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            _ = wake.notified() => {}
            _ = retry_sleep => {}
            _ = shutdown.changed() => break,
        }
    }
}

async fn purge_crd<S: Store>(
    state: &AppState<S>,
    key: &str,
    name: &str,
    existing: &serde_json::Value,
    expected_rv: u64,
) -> Result<(), crate::status::StatusError> {
    let (group, versions, plural, resource_version) = crd_cache_identity(existing);
    state
        .store
        .delete(key, Some(expected_rv))
        .await
        .map_err(|e| store_err_crd(e, name))?;

    evict_cr_schema_cache(state, &group, &versions, &resource_version);
    evict_cr_context_cache(state, &group, &plural, &versions);
    crate::handlers::discovery::refresh_discovery_cache(state).await;

    // A deleted CRD's versions can never be requested (or converted to) again, so every
    // cr_conversion_cache entry targeting one of them is now permanently unreachable —
    // unlike evict_cr_schema_cache above, this sweeps ALL rvs cached under these target
    // versions, not just one CRD generation's, since conversion-cache entries are keyed
    // per source-object write, not per CRD generation.
    if !versions.is_empty() {
        let target_api_versions: HashSet<String> =
            versions.iter().map(|v| format!("{group}/{v}")).collect();
        state
            .cr_conversion_cache
            .invalidate_by_target_api_versions(&target_api_versions);
    }

    // Eagerly free this CRD's watch-ring shard(s) instead of waiting up to
    // RING_SHARD_IDLE_GRACE after the last watcher disconnects: a deleted CRD's resource type
    // can never be watched again, so there is no reason to hold its history alive. The prefix
    // is version-independent (CRs are stored under `/registry/cr/{group}/{plural}/...` regardless
    // of served version), so this needs to run once per CRD, not once per version.
    if let Some(plural) = existing["spec"]["names"]["plural"].as_str() {
        state
            .store
            .evict_resource_type(&crate::handlers::cr::cr_list_prefix(&group, plural, None));
    }

    // Write a tombstone so CR handlers can return 410 Gone (not 404) for this
    // group after deletion. Informers treat 410 as "stop watching" and 404 as
    // a transient error retried indefinitely — without this, namespace deletion
    // hangs because the GC informer keeps retrying the deleted CR endpoint.
    //
    // The value must be a JSON object (not a scalar) because the store's
    // stamp_resource_version function indexes into ["metadata"]["resourceVersion"].
    if !group.is_empty() {
        let tombstone_key = deleted_group_tombstone_key(&group);
        let tombstone_val =
            serde_json::to_vec(&serde_json::json!({ "group": &group })).unwrap_or_default();
        // Use None as expected_rv to unconditionally create-or-update.
        let _ = state
            .store
            .put(&tombstone_key, bytes::Bytes::from(tombstone_val), None)
            .await;
    }

    Ok(())
}

/// DELETE /apis/apiextensions.k8s.io/v1/customresourcedefinitions (delete collection)
///
/// Honors ?labelSelector= like the generic delete_collection_resource, so tooling that
/// labels its own CRDs can clean them up in one call. Without this route the collection
/// endpoint only supported GET/POST, so DeleteCollection returned 405 — conformance's
/// "listing custom resource definition objects works" test creates 10 labeled CRDs and
/// relies on DeleteCollection(labelSelector) to remove exactly those.
pub async fn delete_collection_crds<S: Store>(
    State(state): State<AppState<S>>,
    Query(query): Query<super::generic::CollectionQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let prefix = list_prefix();
    let field_selector = super::field_selector::FieldSelector::parse(
        query.field_selector.as_deref(),
        GROUP,
        PLURAL,
    )?;
    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(super::generic::parse_label_selector)
        .transpose()?;

    for obj in resp.items {
        let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.value) else {
            continue;
        };
        let name = parsed["metadata"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if name.is_empty() || !field_selector.matches(&parsed) {
            continue;
        }
        if let Some(ref pairs) = label_pairs {
            if super::generic::apply_label_selector(vec![parsed], pairs).is_empty() {
                continue;
            }
        }
        delete_crd(
            State(state.clone()),
            Path(name),
            Extension(user.clone()),
            headers.clone(),
            body.clone(),
        )
        .await?;
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

pub async fn patch_crd<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");

    let key = store_key(&name);
    let stored_opt = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // SSA create-on-missing: `kubectl apply --server-side -f my-crd.yaml` against a CRD name
    // that doesn't exist yet sends exactly this PATCH (Content-Type: application/apply-patch+yaml)
    // and relies on the apiserver to create it — this is core SSA semantics, not an edge case
    // (see do_patch's identical `is_ssa && stored_opt.is_none()` branch for the generic resource
    // path). A non-SSA patch type (merge/strategic-merge/JSON Patch) on a missing CRD still 404s,
    // matching upstream: those patch types have no create-on-missing semantics.
    if is_ssa && stored_opt.is_none() {
        let mut body_json = ssa_body_to_json(&body)?;
        crate::handlers::json_patch::strip_managed_fields(&mut body_json);
        // The URL name is authoritative for what gets created, regardless of what (if anything)
        // the apply body's metadata.name says — mirrors do_patch's obj_meta.name override.
        body_json["metadata"]["name"] = serde_json::Value::String(name.clone());
        let crd: CustomResourceDefinition = serde_json::from_value(body_json).map_err(|e| {
            Status::unprocessable_entity(format!("invalid CustomResourceDefinition: {e}"))
        })?;
        let mut crd = build_new_crd(&state, &user, &name, crd, &headers).await?;

        // Dry-run: validation and admission passed; return the would-be created CRD without
        // persisting — mirrors create_crd's dry-run early-return.
        if is_dry_run_header(&headers) {
            return Ok((StatusCode::CREATED, Json(crd)).into_response());
        }

        let rv = state
            .store
            .put(&key, to_bytes(&crd)?, Some(0))
            .await
            .map_err(|e| store_err_crd(e, &name))?;

        state.cr_context_cache.invalidate_absent();
        let tombstone_key = deleted_group_tombstone_key(&crd.spec.group);
        let _ = state.store.delete(&tombstone_key, None).await;
        crate::handlers::discovery::refresh_discovery_cache(&state).await;

        crd.metadata.resource_version = rv.to_string();
        return Ok((StatusCode::CREATED, Json(crd)).into_response());
    }

    let stored = stored_opt.ok_or_else(|| Status::not_found(GROUP, PLURAL, &name))?;

    let mut current: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;
    // Captured before the patch mutates `current` in place, so this reflects the CRD
    // generation the pre-patch cr_schema_cache entries were cached under.
    let (old_group, old_versions, old_plural, old_rv) = crd_cache_identity(&current);
    // Snapshot the pre-patch value for reject_structural_field_change below — `current` is
    // mutated in place by the patch application, so the stored spec.group/scope/names.* would
    // otherwise be lost by the time we can compare against them.
    let existing = current.clone();

    // Snapshot .status before applying the patch: the CRD's own status
    // (Established/NamesAccepted/StoredVersions conditions) is a dedicated subresource
    // (.../status) — a main-endpoint patch must never change it, including via JSON Patch,
    // whose array shape slips past an object-key "status" strip. Restored below before
    // `current` is deserialized into `CustomResourceDefinition`, whose status field is a
    // bare `Option<serde_json::Value>` (not a typed shape that would reject a scalar).
    let stored_status = existing["status"].clone();

    // apply-patch+yaml bodies are genuine YAML (e.g. kubectl apply --server-side); every
    // other patch type here is JSON.
    let mut patch: serde_json::Value = if is_ssa {
        ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::unprocessable_entity(format!("invalid patch: {e}")))?
    };
    if is_ssa {
        crate::handlers::json_patch::strip_managed_fields(&mut patch);
    }

    match patch_type {
        PatchType::Merge | PatchType::StrategicMerge => {
            crate::patch::merge_patch(&mut current, &patch);
        }
        PatchType::Json => {
            apply_json_patch(&mut current, &patch)?;
        }
    }

    crate::handlers::json_patch::enforce_patch_identity(&mut current, &name, None)?;

    if stored_status.is_null() {
        current.as_object_mut().map(|m| m.remove("status"));
    } else {
        current["status"] = stored_status;
    }

    // Validate that the patched value is still a valid CRD shape.
    let mut crd: CustomResourceDefinition = serde_json::from_value(current).map_err(|e| {
        Status::unprocessable_entity(format!(
            "patched object is not a valid CustomResourceDefinition: {e}"
        ))
    })?;

    // Preserve server-assigned type meta.
    crd.api_version = API_VERSION.to_string();
    crd.kind = KIND.to_string();

    // Reject rather than silently drop: a patch that changes a structural identity field
    // is a client error the caller must correct, not something to merge-and-ignore.
    reject_structural_field_change(&existing, &crd.spec, &name)?;

    // metadata.uid is immutable identity, restored unconditionally after every patch type
    // above — mirrors do_patch (resource.rs) and patch_cr's restore, since
    // CustomResourceDefinition routes around the generic PATCH path entirely and previously
    // had no uid handling at all. Without this, a caller holding only ordinary CRD `patch`
    // rights could forge uid to match a stale/foreign ownerReference and corrupt
    // the garbage collector's cascade-GC decision.
    crd.metadata.uid = existing["metadata"]["uid"]
        .as_str()
        .unwrap_or("")
        .to_string();
    crd.metadata.deletion_timestamp = existing["metadata"]["deletionTimestamp"]
        .as_str()
        .map(str::to_string);

    validate_crd_schema(&crd.spec, Some(&existing))?;

    // Admission webhook pipeline (mutating then validating).
    {
        let admission_ctx = AdmissionContext {
            group: "apiextensions.k8s.io",
            version: "v1",
            resource: "customresourcedefinitions",
            name: &name,
            namespace: None,
            operation: "UPDATE",
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
                "extra": user.extra,
            })),
            dry_run: is_dry_run_header(&headers),
        };
        let obj_val = serde_json::to_value(&crd).map_err(|e| Status::internal(e.to_string()))?;
        let mutated =
            run_mutating_webhooks(&state, obj_val, Some(&existing), &admission_ctx).await?;
        run_validating_webhooks(&state, &mutated, Some(&existing), &admission_ctx).await?;
        crd = serde_json::from_value(mutated)
            .map_err(|e| Status::internal(format!("admission mutated CRD is invalid: {e}")))?;
    }
    prepare_crd_generation_for_update(&existing, &mut crd);
    if !is_ssa {
        record_crd_write(&headers, &existing, &mut crd)?;
    }

    // Dry-run: validation and admission passed; return the would-be patched CRD without
    // persisting — mirrors do_patch's dry-run early-return in resource.rs.
    if is_dry_run_header(&headers) {
        return Ok(Json(crd).into_response());
    }

    let rv = state
        .store
        .put(&key, to_bytes(&crd)?, None)
        .await
        .map_err(|e| store_err_crd(e, &name))?;
    if crd.metadata.deletion_timestamp.is_some() {
        state.crd_finalizer_wake.notify_one();
    }

    evict_cr_schema_cache(&state, &old_group, &old_versions, &old_rv);
    evict_cr_context_cache(&state, &old_group, &old_plural, &old_versions);
    crate::handlers::discovery::refresh_discovery_cache(&state).await;

    crd.metadata.resource_version = rv.to_string();
    Ok(Json(crd).into_response())
}

/// GET /apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}/status
///
/// A CRD's status (Established/NamesAccepted/StoredVersions conditions) is embedded
/// in the object, not a separate subresource store — so GET returns the full object,
/// mirroring get_namespace_status.
pub async fn get_crd_status<S: Store>(
    state: State<AppState<S>>,
    Path(name): Path<String>,
) -> Result<Response, crate::status::StatusError> {
    get_crd(state, Path(name)).await
}

async fn admit_crd_status<S: Store>(
    state: &AppState<S>,
    name: &str,
    user: Option<&UserInfo>,
    headers: &HeaderMap,
    old: &serde_json::Value,
    new: serde_json::Value,
) -> Result<serde_json::Value, crate::status::StatusError> {
    crate::handlers::status::admit_status_write(
        state,
        &AdmissionTarget {
            group: GROUP,
            version: "v1",
            resource: "customresourcedefinitions/status",
            name,
            namespace: None,
            user,
            dry_run: is_dry_run_header(headers),
        },
        old,
        new,
        KIND,
    )
    .await
}

/// PUT /apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}/status
///
/// Replaces only the status field. Without this route, status requests fell through
/// to the generic CR catch-all, which searched for a CRD-of-CRDs that can never exist
/// and returned 404 — so controllers gating on CRD readiness (Established, NamesAccepted)
/// could never observe or set those conditions.
pub async fn put_crd_status<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    user: Option<Extension<UserInfo>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct)?;
    let incoming =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = store_key(&name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(GROUP, PLURAL, &name))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let before_write = current.body.clone();
    // `_dynamic`, not the built-in `replace_status_field`: a scalar status here is caught
    // by structural-schema validation (422), not a typed decode failure (400) — see
    // replace_status_field_dynamic's doc comment.
    crate::handlers::status::replace_status_field_dynamic(
        &mut current.body,
        &incoming.body["status"],
    )?;

    crate::handlers::status::merge_incoming_metadata(&mut current.body, &incoming.body, KIND);
    current.body = admit_crd_status(
        &state,
        &name,
        user.as_ref().map(|u| &u.0),
        &headers,
        &before_write,
        current.body,
    )
    .await?;
    crate::handlers::status::record_status_write(
        &headers,
        None,
        &before_write,
        &mut current.body,
        GROUP,
        "v1",
    );

    // Dry-run: return the would-be status object without persisting — mirrors
    // put_resource_status's dry-run early-return.
    if is_dry_run_header(&headers) {
        return Ok(Json(current.body));
    }

    let expected_rv = parse_resource_version(incoming.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_crd(e, &name))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

/// PATCH /apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}/status
///
/// Patches only the status field. Supports merge-patch, strategic-merge-patch, and
/// json-patch, mirroring patch_namespace_status.
pub async fn patch_crd_status<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    user: Option<Extension<UserInfo>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");

    let key = store_key(&name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(GROUP, PLURAL, &name))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let before_write = current.body.clone();

    // apply-patch+yaml bodies are genuine YAML (e.g. kubectl apply --server-side status);
    // every other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
    };
    crate::handlers::status::reject_patch_identity_mismatch(&patch, &name, None)?;
    let ssa_plan = crate::handlers::status::plan_status_apply(
        &headers,
        is_ssa,
        &current.body,
        &patch,
        GROUP,
        "v1",
    )?;

    match patch_type {
        PatchType::Json => {
            // /status is a separate RBAC subresource from the main CRD endpoint — a
            // caller with only `customresourcedefinitions/status` must not be able to
            // write /spec or /metadata via a JSON Patch on this endpoint.
            crate::handlers::status::validate_status_json_patch_paths(&patch)?;
            apply_json_patch(&mut current.body, &patch)?;
        }
        _ => {
            if let Some(status_patch) = patch.get("status") {
                let entry = current.body.as_object_mut().map(|m| {
                    m.entry("status")
                        .or_insert(serde_json::Value::Object(Default::default()))
                });
                if let Some(entry) = entry {
                    match patch_type {
                        PatchType::Merge => crate::patch::merge_patch(entry, status_patch),
                        PatchType::StrategicMerge => {
                            crate::patch::strategic_merge_patch(entry, status_patch)
                                .map_err(Status::patch_error)?;
                        }
                        PatchType::Json => unreachable!(),
                    }
                }
            }
            crate::handlers::status::merge_incoming_metadata(&mut current.body, &patch, KIND);
        }
    }
    if let Some(plan) = &ssa_plan {
        plan.remove_dropped_fields(&mut current.body);
    }
    // Convergence point for every patch content-type above (JSON Patch, merge, strategic
    // merge): guard once here, right before the store write, instead of per-branch. A
    // per-branch guard covered merge/strategic-merge but missed PatchType::Json, since
    // `validate_status_json_patch_paths` permits a whole-`/status` replace and
    // `apply_json_patch` happily turns that into a scalar.
    crate::handlers::status::reject_non_object_status(&current.body["status"])?;
    current.body = admit_crd_status(
        &state,
        &name,
        user.as_ref().map(|u| &u.0),
        &headers,
        &before_write,
        current.body,
    )
    .await?;
    crate::handlers::status::record_status_write(
        &headers,
        ssa_plan.as_ref(),
        &before_write,
        &mut current.body,
        GROUP,
        "v1",
    );

    // Dry-run: same convergence point as reject_non_object_status above — return the
    // would-be patched status object without persisting.
    if is_dry_run_header(&headers) {
        return Ok(Json(current.body));
    }

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_crd(e, &name))?;

    current.set_resource_version(new_rv);
    Ok(Json(current.body))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::handlers::test_support::make_state;

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
    }

    fn minimal_crd_bytes(name: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": name },
                "spec": {
                    "group": "argoproj.io",
                    "names": {
                        "plural": "applications",
                        "singular": "application",
                        "kind": "Application",
                        "listKind": "ApplicationList"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        { "name": "v1alpha1", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        )
    }

    pub(super) fn minimal_crd_bytes_with_group(name: &str, group: &str, plural: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": name },
                "spec": {
                    "group": group,
                    "names": {
                        "plural": plural,
                        "singular": plural.trim_end_matches('s'),
                        "kind": "Widget"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        { "name": "v1", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        )
    }

    fn ok_crd(
        r: Result<CustomResourceDefinition, crate::status::StatusError>,
    ) -> CustomResourceDefinition {
        match r {
            Ok(v) => v,
            Err(_) => panic!("expected Ok but got StatusError"),
        }
    }

    fn err_status(
        r: Result<impl IntoResponse, crate::status::StatusError>,
    ) -> crate::status::StatusError {
        match r {
            Ok(_) => panic!("expected Err but got Ok"),
            Err(e) => e,
        }
    }

    // parse_crd must succeed for a valid body and fail for invalid JSON.
    #[test]
    fn parse_crd_valid() {
        let body = minimal_crd_bytes("applications.argoproj.io");
        let crd = ok_crd(parse_crd(&body));
        assert_eq!(crd.metadata.name, "applications.argoproj.io");
        assert_eq!(crd.spec.group, "argoproj.io");
        assert_eq!(crd.spec.names.kind, "Application");
    }

    #[test]
    fn parse_crd_invalid_returns_422() {
        let body = Bytes::from(b"not json".as_ref());
        let err = match parse_crd(&body) {
            Ok(_) => panic!("expected Err"),
            Err(e) => e,
        };
        // StatusError wraps a Status with code 422 — invalid body must be rejected.
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422);
        assert_eq!(json["reason"], "Invalid");
    }

    // stamp_server_fields must assign uid and creation_timestamp when absent.
    #[test]
    fn stamp_server_fields_assigns_uid_and_timestamp() {
        let body = minimal_crd_bytes("foo.example.com");
        let mut crd = ok_crd(parse_crd(&body));
        assert!(crd.metadata.uid.is_empty(), "uid should start empty");
        assert!(
            crd.metadata.creation_timestamp.is_empty(),
            "timestamp should start empty"
        );

        stamp_server_fields(&mut crd);

        assert!(!crd.metadata.uid.is_empty(), "uid must be assigned");
        assert!(
            !crd.metadata.creation_timestamp.is_empty(),
            "timestamp must be assigned"
        );
        assert_eq!(crd.api_version, "apiextensions.k8s.io/v1");
        assert_eq!(crd.kind, "CustomResourceDefinition");
    }

    /// new_uid() must return a valid UUIDv4 string. Two calls must produce
    /// different values — a time-based uid (the previous impl) would collide
    /// for CRDs created in the same nanosecond and is also predictable.
    #[test]
    fn new_uid_returns_uuid_format() {
        let uid1 = new_uid();
        let uid2 = new_uid();
        // UUID format: 8-4-4-4-12 hex chars separated by dashes, 36 total chars.
        assert_eq!(uid1.len(), 36, "uid must be a 36-char UUID string");
        assert!(
            uid1.parse::<uuid::Uuid>().is_ok(),
            "uid must parse as a valid UUID (got '{uid1}')"
        );
        assert_ne!(uid1, uid2, "consecutive UIDs must differ (CSPRNG source)");
    }

    // A client-supplied creationTimestamp must be replaced on create (upstream
    // FillObjectMetaSystemFields), else a CRD can be backdated.
    #[test]
    fn stamp_server_fields_resets_client_supplied_creation_timestamp() {
        let body = minimal_crd_bytes("foo.example.com");
        let mut crd = ok_crd(parse_crd(&body));
        crd.metadata.uid = "my-uid".into();
        crd.metadata.creation_timestamp = "2024-01-01T00:00:00Z".into();

        stamp_server_fields(&mut crd);

        assert_eq!(crd.metadata.uid, "my-uid");
        assert_ne!(
            crd.metadata.creation_timestamp, "2024-01-01T00:00:00Z",
            "a backdated creationTimestamp must not survive create"
        );
    }

    fn crd_with_versions(
        name: &str,
        versions: serde_json::Value,
        generation: Option<i64>,
    ) -> Bytes {
        let mut meta = serde_json::json!({ "name": name });
        if let Some(g) = generation {
            meta["generation"] = serde_json::json!(g);
        }
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": meta,
                "spec": {
                    "group": "argoproj.io",
                    "names": { "plural": "applications", "singular": "application",
                               "kind": "Application", "listKind": "ApplicationList" },
                    "scope": "Namespaced",
                    "versions": versions
                }
            })
            .to_string(),
        )
    }

    async fn stored_crd_generation(state: &AppState, name: &str) -> serde_json::Value {
        let stored = state
            .store
            .get(&store_key(name))
            .await
            .unwrap()
            .expect("stored CRD");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        v["metadata"]["generation"].clone()
    }

    /// Upstream sets CRD generation to 1 on create and bumps it on spec change; the typed
    /// CrdMetadata used to drop the field entirely, so nothing observing a CRD's generation
    /// (e.g. a status.observedGeneration comparison) could ever tell a spec change happened.
    #[tokio::test]
    async fn crd_generation_is_1_on_create_and_bumps_on_spec_change_only() {
        let state = make_state();
        let name = "applications.argoproj.io";
        let one = serde_json::json!([{ "name": "v1alpha1", "served": true, "storage": true }]);
        let two = serde_json::json!([
            { "name": "v1alpha1", "served": true, "storage": true },
            { "name": "v1beta1", "served": true, "storage": false }
        ]);

        assert!(create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            crd_with_versions(name, one.clone(), Some(9)),
        )
        .await
        .is_ok());
        assert_eq!(
            stored_crd_generation(&state, name).await,
            1,
            "create must stamp generation 1 over the client's 9"
        );

        let replace = |versions: serde_json::Value, generation: Option<i64>| {
            replace_crd(
                State(state.clone()),
                Path(name.to_string()),
                test_user(),
                HeaderMap::new(),
                crd_with_versions(name, versions, generation),
            )
        };
        assert!(replace(two.clone(), None).await.is_ok());
        assert_eq!(
            stored_crd_generation(&state, name).await,
            2,
            "spec change must bump, and a PUT omitting generation must not drop it"
        );
        assert!(replace(two.clone(), Some(77)).await.is_ok());
        assert_eq!(
            stored_crd_generation(&state, name).await,
            2,
            "unchanged spec must not bump and a client-chosen generation is ignored"
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        assert!(patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers.clone(),
            Bytes::from(r#"{"metadata":{"labels":{"k":"v"},"generation":1}}"#),
        )
        .await
        .is_ok());
        assert_eq!(
            stored_crd_generation(&state, name).await,
            2,
            "a metadata-only PATCH must neither bump nor accept the smuggled generation"
        );
        assert!(patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers,
            Bytes::from(serde_json::json!({ "spec": { "versions": one } }).to_string()),
        )
        .await
        .is_ok());
        assert_eq!(stored_crd_generation(&state, name).await, 3);
    }

    /// A CRD patch (any type) that renames the object must be refused with upstream's 400 and
    /// leave the stored CRD untouched: the store key is URL-derived, but discovery and the CR
    /// router resolve CRDs by body, so a renamed body would shadow another CRD's resources.
    #[tokio::test]
    async fn patch_crd_rejects_rename_for_every_patch_type() {
        use crate::handlers::test_support::{
            assert_identity_mismatch, content_type_headers, identity_rewrite_patches,
        };
        let state = make_state();
        let name = "applications.argoproj.io";
        assert!(create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes(name)
        )
        .await
        .is_ok());
        let key = crate::keys::group_object_key(GROUP, PLURAL, None, name);
        let before = state.store.get(&key).await.unwrap().unwrap().value;

        for (label, ct, body) in identity_rewrite_patches(
            "name",
            "widgets.example.io",
            "apiextensions.k8s.io/v1",
            "CustomResourceDefinition",
        ) {
            let err = patch_crd(
                State(state.clone()),
                Path(name.to_string()),
                test_user(),
                content_type_headers(ct),
                body,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("{label} rename must be rejected"));
            assert_identity_mismatch(&err, label, "name");
            assert_eq!(
                state.store.get(&key).await.unwrap().unwrap().value,
                before,
                "{label} rename must not change the stored CRD"
            );
        }
    }

    // create_crd → 201; get_crd → 200 with stored object.
    #[tokio::test]
    async fn create_and_get_round_trip() {
        let state = make_state();
        let name = "applications.argoproj.io";
        let body = minimal_crd_bytes(name);

        assert!(
            create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
                .await
                .is_ok(),
            "create must succeed"
        );

        let resp = match get_crd(State(state), Path(name.to_string())).await {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after create"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // create_crd twice with the same name must return 409 AlreadyExists.
    #[tokio::test]
    async fn create_duplicate_returns_409() {
        let state = make_state();
        let name = "applications.argoproj.io";
        let body = minimal_crd_bytes(name);

        assert!(
            create_crd(
                State(state.clone()),
                test_user(),
                HeaderMap::new(),
                body.clone()
            )
            .await
            .is_ok(),
            "first create must succeed"
        );

        let err = err_status(create_crd(State(state), test_user(), HeaderMap::new(), body).await);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 409);
        assert_eq!(json["reason"], "AlreadyExists");
    }

    // get_crd for a non-existent name must return 404.
    #[tokio::test]
    async fn get_missing_returns_404() {
        let state = make_state();
        let err = match get_crd(State(state), Path("missing.example.com".to_string())).await {
            Ok(_) => panic!("expected 404 error"),
            Err(e) => e,
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // delete_crd for a non-existent name must return 404.
    #[tokio::test]
    async fn delete_missing_returns_404() {
        let state = make_state();
        let err = err_status(
            delete_crd(
                State(state),
                Path("missing.example.com".to_string()),
                test_user(),
                HeaderMap::new(),
                Bytes::new(),
            )
            .await,
        );
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // replace_crd for a non-existent name must return 404.
    #[tokio::test]
    async fn replace_missing_returns_404() {
        let state = make_state();
        let body = minimal_crd_bytes("missing.example.com");
        let err = err_status(
            replace_crd(
                State(state),
                Path("missing.example.com".to_string()),
                test_user(),
                HeaderMap::new(),
                body,
            )
            .await,
        );
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // list_crds must return empty list when nothing is stored.
    #[tokio::test]
    async fn list_empty() {
        let state = make_state();
        let resp = match list_crds(
            State(state),
            Query(crate::handlers::generic::CollectionQuery {
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
            Extension(UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must succeed"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Kubernetes requires metadata.name == "{plural}.{group}".
    // A mismatched name must be rejected with 422 so kubectl and controllers
    // can rely on the name encoding the resource identity.
    #[tokio::test]
    async fn create_crd_rejects_mismatched_name() {
        let state = make_state();
        // Correct would be "widgets.example.io" but we pass "wrong.example.io".
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "wrong.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget"
                    },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );

        let err = err_status(create_crd(State(state), test_user(), HeaderMap::new(), body).await);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422, "mismatched name must return 422");
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("widgets.example.io"),
            "error must mention the expected name"
        );
    }

    // A CRD whose metadata.name is exactly "{plural}.{group}" must be accepted.
    #[tokio::test]
    async fn create_crd_accepts_correct_name() {
        let state = make_state();
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget"
                    },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );

        assert!(
            create_crd(State(state), test_user(), HeaderMap::new(), body)
                .await
                .is_ok(),
            "correct name widgets.example.io must be accepted"
        );
    }

    fn dry_run_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::HeaderName::from_static(crate::handlers::json_patch::DRY_RUN_HEADER),
            axum::http::HeaderValue::from_static("true"),
        );
        h
    }

    /// `kubectl create -f my-crd.yaml --dry-run=server` must NOT persist the CRD — a
    /// dry-run that actually creates it silently mutates cluster state (and the discovery
    /// cache) against the client's explicit intent. This test fails on revert with the CRD
    /// present in the store.
    #[tokio::test]
    async fn create_crd_dry_run_does_not_persist() {
        let state = make_state();
        let name = "applications.argoproj.io";

        let result = create_crd(
            State(state.clone()),
            test_user(),
            dry_run_headers(),
            minimal_crd_bytes(name),
        )
        .await;
        assert!(
            result.is_ok(),
            "dry-run create must still return a success response with the would-be CRD"
        );

        let stored = state.store.get(&store_key(name)).await.unwrap();
        assert!(
            stored.is_none(),
            "dryRun=All must NOT persist the CRD — if this fails, create_crd's dry-run \
             guard was removed and the CRD was actually written to the store"
        );
    }

    async fn crd_status_apply(
        state: &crate::state::AppState,
        manager: &str,
        force: bool,
        yaml: String,
    ) -> Result<serde_json::Value, crate::status::StatusError> {
        let resp = patch_crd_status(
            State(state.clone()),
            Path("widgets.example.io".to_string()),
            None,
            crate::handlers::test_support::apply_headers(manager, force),
            Bytes::from(yaml),
        )
        .await?
        .into_response();
        Ok(crate::handlers::test_support::response_json(resp).await)
    }

    /// An apply to a CRD's /status must be owned under a status-scoped Apply entry and a later
    /// apply must delete what it stops sending; a CRD's spec is never taken from /status.
    #[tokio::test]
    async fn crd_status_apply_is_scoped_and_prunes() {
        let state = make_state();
        crate::handlers::test_support::install_namespaced_crd(
            &state,
            "example.io",
            "v1",
            "widgets",
            "Widget",
        )
        .await;
        let cond = |t: &str| {
            format!(
                "status:\n  conditions:\n  - type: {t}\n    status: \"True\"\n    reason: r\n    message: m\n    lastTransitionTime: \"2026-01-01T00:00:00Z\"\n"
            )
        };
        let (_, second) = crate::handlers::test_support::assert_status_apply_is_scoped_and_prunes(
            |m, f, y| crd_status_apply(&state, m, f, y),
            &cond("Custom1"),
            &cond("Custom2"),
        )
        .await;
        let types: Vec<&str> = second["status"]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["type"].as_str())
            .collect();
        assert!(
            types.contains(&"Custom2") && !types.contains(&"Custom1"),
            "a condition the applier stopped sending must be removed: {types:?}"
        );
        assert_eq!(
            second["spec"]["group"], "example.io",
            "/status must not touch spec"
        );
    }

    /// `kubectl apply --server-side --dry-run=server -f my-crd.yaml` against a CRD name
    /// that does not exist yet takes patch_crd's SSA create-on-missing branch — a separate
    /// code path from create_crd with its own store.put. This test fails on revert with the
    /// CRD present in the store.
    #[tokio::test]
    async fn patch_crd_ssa_create_dry_run_does_not_persist() {
        let state = make_state();
        let name = "applications.argoproj.io";

        let mut headers = dry_run_headers();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );
        let yaml_body = Bytes::from_static(
            b"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: applications.argoproj.io\nspec:\n  group: argoproj.io\n  names:\n    plural: applications\n    singular: application\n    kind: Application\n    listKind: ApplicationList\n  scope: Namespaced\n  versions:\n  - name: v1alpha1\n    served: true\n    storage: true\n",
        );

        let result = patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers,
            yaml_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "dry-run SSA create-on-missing must still return a success response"
        );

        let stored = state.store.get(&store_key(name)).await.unwrap();
        assert!(
            stored.is_none(),
            "dryRun=All must NOT persist the CRD via the SSA create-on-missing branch — if \
             this fails, patch_crd's SSA-create dry-run guard was removed and the CRD was \
             actually written to the store"
        );
    }

    /// `kubectl patch --dry-run=server` against an EXISTING CRD must NOT mutate the stored
    /// object — this exercises patch_crd's merge-into-existing branch, a distinct code path
    /// from the SSA create-on-missing branch above with its own store.put. This test fails
    /// on revert with the stored metadata.labels actually updated.
    #[tokio::test]
    async fn patch_crd_merge_dry_run_does_not_mutate_store() {
        let state = make_state();
        let name = "applications.argoproj.io";

        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes(name),
        )
        .await
        .expect("create must succeed");

        let mut headers = dry_run_headers();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        let patch_body = Bytes::from(
            serde_json::json!({ "metadata": { "labels": { "team": "dry-run" } } }).to_string(),
        );

        let result = patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers,
            patch_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "dry-run patch must still return a success response"
        );

        let stored = state
            .store
            .get(&store_key(name))
            .await
            .unwrap()
            .expect("CRD must still exist");
        let stored_json: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            stored_json["metadata"]["labels"].is_null(),
            "dryRun=All must NOT mutate the stored CRD — if this fails, patch_crd's \
             merge-branch dry-run guard was removed and metadata.labels.team was actually \
             persisted as \"dry-run\""
        );
    }

    // list_crds must apply ?labelSelector= like the generic resource list does.
    // Without this, tooling that scopes itself to "only my CRDs" via a label
    // selector would instead see every CRD in the cluster.
    #[tokio::test]
    async fn list_crds_applies_label_selector() {
        let state = make_state();

        let matching = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "foos.example.io", "labels": { "team": "a" } },
                "spec": {
                    "group": "example.io",
                    "names": { "plural": "foos", "singular": "foo", "kind": "Foo" },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );
        let non_matching = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "bars.example.io", "labels": { "team": "b" } },
                "spec": {
                    "group": "example.io",
                    "names": { "plural": "bars", "singular": "bar", "kind": "Bar" },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );

        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            matching,
        )
        .await
        .expect("create matching CRD must succeed");
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            non_matching,
        )
        .await
        .expect("create non-matching CRD must succeed");

        let query = Query(crate::handlers::generic::CollectionQuery {
            watch: None,
            resource_version: None,
            label_selector: Some("team=a".to_string()),
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        });

        let resp = list_crds(State(state), query, HeaderMap::new(), test_user())
            .await
            .expect("list must succeed");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["metadata"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["foos.example.io"],
            "labelSelector=team=a must scope the list to matching CRDs only — \
             returning every CRD breaks tooling that lists only its own CRDs"
        );
    }

    /// DELETE on the CRD collection with a labelSelector must remove only the matching
    /// CRDs — before this route existed the collection endpoint only supported GET/POST
    /// and DeleteCollection returned 405, failing conformance's "listing custom resource
    /// definition objects works" test (which cleans up its 10 labeled CRDs this way).
    #[tokio::test]
    async fn delete_collection_crds_honors_label_selector() {
        let state = make_state();

        let matching = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "foos.example.io", "labels": { "team": "a" } },
                "spec": {
                    "group": "example.io",
                    "names": { "plural": "foos", "singular": "foo", "kind": "Foo" },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );
        let non_matching = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "bars.example.io", "labels": { "team": "b" } },
                "spec": {
                    "group": "example.io",
                    "names": { "plural": "bars", "singular": "bar", "kind": "Bar" },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            matching,
        )
        .await
        .expect("create matching CRD must succeed");
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            non_matching,
        )
        .await
        .expect("create non-matching CRD must succeed");

        let query = Query(crate::handlers::generic::CollectionQuery {
            watch: None,
            resource_version: None,
            label_selector: Some("team=a".to_string()),
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        });
        delete_collection_crds(
            State(state.clone()),
            query,
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect(
            "delete collection must succeed — before the fix this route did not \
                     exist and DELETE on the collection returned 405",
        );

        assert!(
            get_crd(State(state.clone()), Path("foos.example.io".to_string()))
                .await
                .is_err(),
            "the labeled CRD must be deleted"
        );
        assert!(
            get_crd(State(state), Path("bars.example.io".to_string()))
                .await
                .is_ok(),
            "the non-matching CRD must survive a label-scoped delete collection"
        );
    }

    // When ?watch=true, list_crds must route to the watch stream (chunked transfer)
    // rather than returning a normal CustomResourceDefinitionList. This verifies that
    // clients watching /apis/apiextensions.k8s.io/v1/customresourcedefinitions get a
    // streaming response.
    #[tokio::test]
    async fn list_crds_watch_returns_chunked_stream() {
        let state = make_state();
        let query = Query(crate::handlers::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        });

        let resp = match list_crds(
            State(state),
            query,
            HeaderMap::new(),
            Extension(UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        // watch_generic always sets transfer-encoding: chunked
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "watch response must use chunked transfer encoding"
        );
    }

    // -- patch_crd: merge-patch support for schema defaults --

    /// PATCH /apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name} must apply a
    /// merge patch and return 200 with the updated CRD.
    ///
    /// The conformance test "custom resource defaulting for requests and from storage works"
    /// patches a CRD to set x-kubernetes-default in its schema.  Before this fix the server
    /// returned 405 Method Not Allowed because no PATCH handler was registered, causing the
    /// test to fail with "the server does not allow this method on the requested resource".
    #[tokio::test]
    async fn patch_crd_merge_patch_adds_schema_default() {
        use axum::response::IntoResponse;

        let state = make_state();
        let name = "applications.argoproj.io";

        // Create CRD first.
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes(name),
        )
        .await
        .expect("create must succeed");

        // Build a merge patch that sets a schema default inside spec.versions[0].schema.
        let patch = serde_json::json!({
            "spec": {
                "versions": [{
                    "name": "v1alpha1",
                    "served": true,
                    "storage": true,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": {
                                "spec": {
                                    "type": "object",
                                    "properties": {
                                        "a": {
                                            "type": "string",
                                            "default": "A"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }]
            }
        });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers,
            patch_bytes,
        )
        .await
        .expect("PATCH must succeed — 405 Method Not Allowed means the route is missing")
        .into_response();

        assert_eq!(
            result.status(),
            StatusCode::OK,
            "PATCH CRD must return 200 OK — conformance test patches schema defaults and expects 200"
        );

        // Verify the default is present in the response body.
        let body = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["a"]["default"],
            "A",
            "patched schema default must be present in the response — this is what the conformance \
             test reads after patching the CRD"
        );
    }

    /// PATCH /apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name} must apply a
    /// JSON Patch (RFC 6902) 'add' whose path traverses an *existing* array element, not
    /// just an object.
    ///
    /// This reproduces the conformance test's literal request: it patches a CRD with
    /// `types.JSONPatchType` and path `/spec/versions/0/schema/openAPIV3Schema/properties/a/default`
    /// — `versions` is an array and `0` is an existing element, so nothing needs to be
    /// fabricated except the final `default` key. Before this fix the server 422'd with
    /// "cannot create intermediate key '0' in non-object" because the JSON-Patch 'add'
    /// intermediate-navigation helper only knew how to descend into objects, never arrays,
    /// even when the indexed element already existed.
    #[tokio::test]
    async fn patch_crd_json_patch_add_through_existing_array_index_sets_schema_default() {
        use axum::response::IntoResponse;

        let state = make_state();
        let name = "widgets.example.io";

        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": name },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "a": { "type": "string" }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            crd_bytes,
        )
        .await
        .expect("create must succeed");

        let patch = serde_json::json!([
            {"op": "add", "path": "/spec/versions/0/schema/openAPIV3Schema/properties/a/default", "value": "A"}
        ]);
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );

        let result = patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "JSON Patch 'add' through an existing array index must not 422 — a CRD \
                 always has at least one version, so index 0 always exists: {e:?}"
            )
        })
        .into_response();

        assert_eq!(result.status(), StatusCode::OK);

        let body = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["a"]["default"],
            "A",
            "the schema default added via JSON Patch must round-trip in the response, \
             matching what the conformance test reads back after this exact PATCH"
        );
    }

    /// PATCH .../customresourcedefinitions/{name} must accept a genuine multi-line YAML
    /// apply-patch+yaml body, not just a JSON body wearing the +yaml content-type.
    ///
    /// WHY this matters: `kubectl apply --server-side` against a CRD (and the k8s
    /// conformance suite's own SSA clients) send real YAML block syntax. Before this fix,
    /// detect_patch_type accepted the apply-patch+yaml content type, but the body was still
    /// parsed with serde_json::from_slice, which rejects YAML outright with "invalid patch:
    /// expected value..." — every server-side apply against a CRD 400'd.
    #[tokio::test]
    async fn patch_crd_accepts_real_yaml_apply_patch_body() {
        use axum::response::IntoResponse;

        let state = make_state();
        let name = "applications.argoproj.io";

        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes(name),
        )
        .await
        .expect("create must succeed");

        // Genuine YAML block syntax — NOT JSON serialized to bytes.
        let patch_bytes = Bytes::from_static(
            b"spec:\n  versions:\n  - name: v1alpha1\n    served: true\n    storage: true\n    schema:\n      openAPIV3Schema:\n        type: object\n        properties:\n          spec:\n            type: object\n            properties:\n              a:\n                type: string\n                default: A\n",
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let result = patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|e| {
            panic!("apply-patch+yaml with a genuine YAML body must succeed, not 400 'invalid patch': {e:?}")
        })
        .into_response();

        assert_eq!(
            result.status(),
            StatusCode::OK,
            "server-side apply against a CRD must return 200 OK with the patched object"
        );
        let body = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
                ["properties"]["a"]["default"],
            "A",
            "the YAML-encoded schema default must be persisted and echoed back, proving the \
             body was actually parsed rather than silently dropped"
        );
    }

    /// PATCH on a missing CRD must return 404, not 500.
    #[tokio::test]
    async fn patch_crd_missing_returns_404() {
        let patch = serde_json::json!({"spec": {}});
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let state = make_state();
        let err = match patch_crd(
            State(state),
            Path("missing.example.com".to_string()),
            test_user(),
            headers,
            patch_bytes,
        )
        .await
        {
            Ok(_) => panic!("expected 404 error"),
            Err(e) => e,
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 404,
            "PATCH on missing CRD must return 404 NotFound"
        );
    }

    /// replace_crd must reject a PUT that changes spec.group relative to the stored CRD.
    ///
    /// CRs are stored under a group-and-plural-keyed prefix (see build_new_crd's storage-key
    /// comment): if a client could silently change spec.group via PUT, every CR already stored
    /// under the old group prefix becomes permanently unreachable — a silent data-loss-adjacent
    /// bug, not just a validation gap. Fails on revert: without the reject_structural_field_change
    /// call in replace_crd, this PUT (which only changes spec.group) succeeds with 200.
    #[tokio::test]
    async fn replace_crd_rejects_mismatched_spec_group_with_422() {
        let state = make_state();
        let name = "widgets.example.com";
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, "example.com", "widgets"),
        )
        .await
        .expect("create must succeed");

        let stored = state
            .store
            .get(&store_key(name))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored_val: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored");
        let rv = stored_val["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let replace_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": name, "resourceVersion": rv },
                "spec": {
                    "group": "other.com",
                    "names": { "plural": "widgets", "singular": "widget", "kind": "Widget" },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );

        let err = err_status(
            replace_crd(
                State(state),
                Path(name.to_string()),
                test_user(),
                HeaderMap::new(),
                replace_body,
            )
            .await,
        );
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "PUT changing spec.group must be rejected with 422 Invalid, not silently accepted \
             — otherwise every CR already stored under the old group prefix is orphaned"
        );
    }

    /// patch_crd must reject a merge-patch that changes spec.names.plural relative to the
    /// stored CRD.
    ///
    /// spec.names.plural determines the storage key prefix CRs live under; a patch that changes
    /// it must be rejected outright (422) rather than merged-and-applied, since silently
    /// orphaning every already-stored CR under the old plural is worse than refusing the patch.
    /// Fails on revert: without the reject_structural_field_change call in patch_crd, this
    /// merge-patch (which only changes spec.names.plural) succeeds with 200.
    #[tokio::test]
    async fn patch_crd_rejects_change_to_names_plural_with_422() {
        let state = make_state();
        let name = "widgets.example.com";
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, "example.com", "widgets"),
        )
        .await
        .expect("create must succeed");

        let patch = serde_json::json!({ "spec": { "names": { "plural": "gadgets" } } });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = err_status(
            patch_crd(
                State(state),
                Path(name.to_string()),
                test_user(),
                headers,
                patch_bytes,
            )
            .await,
        );
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "merge-patch changing spec.names.plural must be rejected with 422 Invalid, not \
             silently merged — otherwise every CR already stored under the old plural is orphaned"
        );
    }

    /// Round 5 of the non-object-status bug class: replace_crd is the MAIN `/customresourcedefinitions/{name}` PUT
    /// endpoint (not `.../status`). Unlike a Custom Resource's has_status_subresource-gated
    /// restore (replace_cr), replace_crd built `CustomResourceDefinition` straight from
    /// `parse_crd(&body)` and persisted whatever `crd.status` — a bare
    /// `Option<serde_json::Value>`, not a typed shape — the client's body happened to
    /// deserialize into, with no restore of the stored value at all.
    ///
    /// Fails on revert: create_crd stamps status.conditions (Established/NamesAccepted) at
    /// creation; without restoring stored_status in replace_crd, a PUT body that simply
    /// omits "status" (as a real `kubectl replace -f crd.yaml` does) silently wipes those
    /// conditions to null, and a malicious body `{"status":"x"}` persists a scalar that
    /// later panics any in-place status stamper.
    #[tokio::test]
    async fn replace_crd_ignores_body_status_uses_stored_status() {
        let state = make_state();
        let name = "widgets.example.com";
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, "example.com", "widgets"),
        )
        .await
        .expect("create must succeed");

        let stored = state
            .store
            .get(&store_key(name))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored_val: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored");
        assert!(
            stored_val["status"]["conditions"][0]["type"] == "Established",
            "sanity check: create_crd must stamp status.conditions"
        );
        let rv = stored_val["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("")
            .to_string();

        // A PUT body carrying a scalar "status" — a real client would never send this, but
        // it must not be trusted even if it does — plus a real, unrelated spec change.
        let replace_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": name, "resourceVersion": rv, "labels": { "env": "prod" } },
                "spec": {
                    "group": "example.com",
                    "names": { "plural": "widgets", "singular": "widget", "kind": "Widget" },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                },
                "status": "x"
            })
            .to_string(),
        );

        assert!(
            replace_crd(
                State(state.clone()),
                Path(name.to_string()),
                test_user(),
                HeaderMap::new(),
                replace_body,
            )
            .await
            .is_ok(),
            "PUT must still succeed — status is silently ignored, not rejected"
        );

        let after = state
            .store
            .get(&store_key(name))
            .await
            .expect("store get")
            .expect("must still exist");
        let after_val: serde_json::Value =
            serde_json::from_slice(&after.value).expect("parse after replace");
        assert_eq!(
            after_val["status"]["conditions"][0]["type"], "Established",
            "PUT body status must be ignored; the create_crd-stamped conditions must survive \
             — a scalar status here would panic the next in-place status stamper"
        );
        assert_eq!(
            after_val["metadata"]["labels"]["env"], "prod",
            "the PUT's actual metadata update (labels) must still apply"
        );
    }

    /// Round 5 sibling of the replace_crd fix above: patch_crd (the MAIN PATCH
    /// endpoint, not `.../status`) deserializes the merge-patched raw JSON straight into
    /// `CustomResourceDefinition`, whose status field is a bare `Option<serde_json::Value>`
    /// — a merge-patch body `{"status":"x"}` deserialized and persisted successfully with no
    /// object-type check.
    ///
    /// Fails on revert: without restoring stored_status after the patch is applied, the
    /// stored status becomes the raw string "x" instead of staying the create_crd-stamped
    /// conditions object.
    #[tokio::test]
    async fn patch_crd_rejects_scalar_status_merge_patch() {
        let state = make_state();
        let name = "widgets.example.com";
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, "example.com", "widgets"),
        )
        .await
        .expect("create must succeed");

        let patch = serde_json::json!({ "status": "x" });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_crd(
                State(state.clone()),
                Path(name.to_string()),
                test_user(),
                headers,
                patch_bytes,
            )
            .await
            .is_ok(),
            "PATCH must still succeed — status is silently ignored, not rejected"
        );

        let after = state
            .store
            .get(&store_key(name))
            .await
            .expect("store get")
            .expect("must still exist");
        let after_val: serde_json::Value =
            serde_json::from_slice(&after.value).expect("parse after patch");
        assert!(
            !after_val["status"].is_string(),
            "a merge-patch body's scalar status must never be persisted as-is — got {:?}",
            after_val["status"]
        );
        assert_eq!(
            after_val["status"]["conditions"][0]["type"], "Established",
            "the create_crd-stamped conditions must survive an unrelated main-endpoint patch"
        );
    }

    /// replace_crd only filled `crd.metadata.uid` from the stored object when the incoming
    /// uid was empty — a non-empty, mismatched client-supplied uid was silently persisted,
    /// unlike the generic replace_resource path (resource.rs), which 409s on exactly this.
    /// Letting it through would let a client forge a match against a stale/foreign
    /// ownerReference, corrupting the garbage collector's cascade-GC decision. Fails on revert:
    /// without the uid-mismatch check, this PUT (matching resourceVersion, forged uid) would
    /// succeed with 200 instead of 409.
    #[tokio::test]
    async fn replace_crd_rejects_mismatched_uid_with_409() {
        let state = make_state();
        let name = "widgets.example.com";
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, "example.com", "widgets"),
        )
        .await
        .expect("create must succeed");

        let stored = state
            .store
            .get(&store_key(name))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored_val: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored");
        let rv = stored_val["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let real_uid = stored_val["metadata"]["uid"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(!real_uid.is_empty(), "create must assign a uid");

        let replace_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": name, "uid": "attacker-uid", "resourceVersion": rv },
                "spec": {
                    "group": "example.com",
                    "names": { "plural": "widgets", "singular": "widget", "kind": "Widget" },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );

        let err = err_status(
            replace_crd(
                State(state),
                Path(name.to_string()),
                test_user(),
                HeaderMap::new(),
                replace_body,
            )
            .await,
        );
        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "PUT with a mismatched non-blank metadata.uid must return 409 Conflict — uid is \
             immutable identity, not a client-settable field"
        );
    }

    /// patch_crd applied merge_patch/apply_json_patch directly to the full stored JSON
    /// (including metadata.uid) with zero uid handling anywhere in the function. A caller
    /// holding only ordinary CRD `patch` rights could forge uid to match a stale/foreign
    /// ownerReference, corrupting the garbage collector's cascade-GC decision. Fails on revert:
    /// without restoring the pre-patch uid after the patch is applied, the forged uid below
    /// would be persisted and this assertion would fail.
    #[tokio::test]
    async fn patch_crd_cannot_change_uid() {
        use axum::response::IntoResponse;

        let state = make_state();
        let name = "widgets.example.com";
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, "example.com", "widgets"),
        )
        .await
        .expect("create must succeed");

        let stored = state
            .store
            .get(&store_key(name))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored_val: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("parse stored");
        let real_uid = stored_val["metadata"]["uid"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(!real_uid.is_empty(), "create must assign a uid");

        let patch = serde_json::json!({ "metadata": { "uid": "attacker-uid" } });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers,
            patch_bytes,
        )
        .await
        .expect(
            "a patch attempting to set uid must still succeed (uid is silently restored, \
             not rejected — matches do_patch's PATCH semantics)",
        )
        .into_response();

        let body = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["metadata"]["uid"], real_uid,
            "a merge-patch carrying metadata.uid must not change the stored uid"
        );
    }

    /// SSA apply-patch on a CRD name that does not exist yet must create it — with the same
    /// Established/NamesAccepted status stamping `create_crd` gives a plain POST — instead of
    /// 404ing. Real Server-Side Apply creates the target object on first apply; before this
    /// fix, `kubectl apply --server-side -f my-crd.yaml` against a fresh CRD 404'd outright,
    /// breaking any GitOps flow that applies (rather than creates) CRDs.
    #[tokio::test]
    async fn ssa_apply_patch_creates_missing_crd_with_full_status_stamping() {
        use axum::response::IntoResponse;

        let state = make_state();
        let name = "widgets.example.io";

        let manifest = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": name },
            "spec": {
                "group": "example.io",
                "names": {
                    "plural": "widgets",
                    "singular": "widget",
                    "kind": "Widget",
                    "listKind": "WidgetList"
                },
                "scope": "Namespaced",
                "versions": [{ "name": "v1", "served": true, "storage": true }]
            }
        });
        let patch_bytes = Bytes::from(serde_json::to_vec(&manifest).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let result = patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "SSA apply-patch on a missing CRD must create it, not 404 — this breaks any \
                 GitOps flow using `kubectl apply --server-side` on a fresh CRD: {e:?}"
            )
        })
        .into_response();

        assert_eq!(
            result.status(),
            StatusCode::CREATED,
            "creating a CRD via SSA apply must return 201, matching create_crd's POST response"
        );

        let body = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["metadata"]["name"], name);

        let condition_types: Vec<&str> = v["status"]["conditions"]
            .as_array()
            .expect("SSA-created CRD must have status.conditions stamped, matching create_crd")
            .iter()
            .map(|c| c["type"].as_str().unwrap())
            .collect();
        assert_eq!(
            condition_types,
            vec!["Established", "NamesAccepted"],
            "SSA create-on-missing must stamp the same conditions as plain `kubectl create` — \
             without this, controllers gating on CRD readiness never see it as usable"
        );

        // Persisted, not just echoed back — get_crd must independently observe the new CRD.
        let stored = get_crd(State(state), Path(name.to_string())).await.expect(
            "the SSA-created CRD must be durably persisted, not merely returned in the response",
        );
        assert_eq!(stored.status(), StatusCode::OK);
    }

    /// SSA apply-patch on a CRD that already exists must update it in place, not create a
    /// second copy — this guards the upsert branch's `stored_opt.is_none()` gate. If that
    /// check ever regressed to fire unconditionally, a second `kubectl apply --server-side`
    /// on an existing CRD would reset server-assigned fields (uid) instead of patching the
    /// live object, silently breaking identity-sensitive consumers (owner references, caches
    /// keyed by uid).
    #[tokio::test]
    async fn ssa_apply_patch_on_existing_crd_still_updates_not_creates() {
        use axum::response::IntoResponse;

        let state = make_state();
        let name = "widgets.example.io";

        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, "example.io", "widgets"),
        )
        .await
        .expect("create must succeed");

        let existing = get_crd(State(state.clone()), Path(name.to_string()))
            .await
            .expect("get after create must succeed");
        let existing_body = axum::body::to_bytes(existing.into_body(), usize::MAX)
            .await
            .unwrap();
        let existing_json: serde_json::Value = serde_json::from_slice(&existing_body).unwrap();
        let original_uid = existing_json["metadata"]["uid"]
            .as_str()
            .expect("create_crd must stamp a uid")
            .to_string();

        let manifest = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": name },
            "spec": {
                "group": "example.io",
                "names": { "plural": "widgets", "singular": "widget", "kind": "Widget" },
                "scope": "Namespaced",
                "versions": [{
                    "name": "v1", "served": true, "storage": true,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": { "spec": { "type": "object" } }
                        }
                    }
                }]
            }
        });
        let patch_bytes = Bytes::from(serde_json::to_vec(&manifest).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let result = patch_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            headers,
            patch_bytes,
        )
        .await
        .expect("SSA apply on an existing CRD must succeed")
        .into_response();

        assert_eq!(
            result.status(),
            StatusCode::OK,
            "SSA apply on an EXISTING CRD must return 200 (update), not 201 (create) — a 201 \
             here would mean the create-on-missing branch fired despite the CRD already existing"
        );

        let body = axum::body::to_bytes(result.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["metadata"]["uid"], original_uid,
            "updating via SSA apply must preserve the original uid — a fresh uid means the \
             object was recreated rather than patched in place"
        );
        assert_eq!(
            v["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["type"],
            "object",
            "the patch's schema change must be applied to the existing object"
        );
    }

    // -- CRD status subresource: without a dedicated route these fell through to the
    // generic CR catch-all, which looked for a CRD-of-CRDs that can never exist and
    // returned 404 — so controllers gating on Established/NamesAccepted conditions
    // could never observe or set them. --

    /// GET .../{name}/status must return the full CRD (status is embedded, not a
    /// separate store) — this is what conformance's "getting" CRD status subresource
    /// scenario asserts.
    #[tokio::test]
    async fn get_crd_status_returns_full_object() {
        let state = make_state();
        let name = "widgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "widgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let resp = get_crd_status(State(state), Path(name.to_string()))
            .await
            .expect(
                "get status must succeed — before the fix this fell through to the \
                     generic CR catch-all and returned 404",
            );
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["metadata"]["name"], name);
    }

    /// PUT .../{name}/status must round-trip a status update (e.g. the Established
    /// condition) without touching spec — this is exactly what the conformance
    /// "updating" CRD status subresource scenario does.
    #[tokio::test]
    async fn put_crd_status_round_trips_conditions() {
        let state = make_state();
        let name = "widgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "widgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let get_resp = get_crd(State(state.clone()), Path(name.to_string()))
            .await
            .expect("get must succeed");
        let get_body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let mut current: serde_json::Value = serde_json::from_slice(&get_body).unwrap();
        current["status"] = serde_json::json!({
            "conditions": [{ "type": "Established", "status": "True", "reason": "InitialNamesAccepted" }]
        });
        let put_body = Bytes::from(current.to_string());

        let resp = put_crd_status(
            State(state.clone()),
            Path(name.to_string()),
            None,
            HeaderMap::new(),
            put_body,
        )
        .await
        .expect(
            "put status must succeed — before the fix this route did not exist \
                     and the request 404'd on the generic CR catch-all",
        )
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["status"]["conditions"][0]["type"], "Established",
            "the Established condition set via PUT status must be persisted and echoed back"
        );
        assert_eq!(
            v["spec"]["group"], "example.io",
            "PUT on the status subresource must not touch spec"
        );

        // Verify the update actually persisted, not just echoed in the response.
        let reget = get_crd(State(state), Path(name.to_string()))
            .await
            .expect("get must succeed after status update");
        let reget_body = axum::body::to_bytes(reget.into_body(), usize::MAX)
            .await
            .unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&reget_body).unwrap();
        assert_eq!(v2["status"]["conditions"][0]["type"], "Established");
    }

    /// `PUT .../{name}/status?dryRun=All` must return the would-be status object but leave
    /// the stored CRD's status untouched. Before this fix, put_crd_status had no dry-run
    /// check at all.
    #[tokio::test]
    async fn put_crd_status_dry_run_all_does_not_persist() {
        let state = make_state();
        let name = "dryrunwidgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "dryrunwidgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let get_resp = get_crd(State(state.clone()), Path(name.to_string()))
            .await
            .expect("get must succeed");
        let get_body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let mut current: serde_json::Value = serde_json::from_slice(&get_body).unwrap();
        current["status"] = serde_json::json!({
            "conditions": [{ "type": "Established", "status": "True", "reason": "InitialNamesAccepted" }]
        });
        let put_body = Bytes::from(current.to_string());

        let mut dry_run_headers = HeaderMap::new();
        dry_run_headers.insert(
            axum::http::HeaderName::from_static(crate::handlers::json_patch::DRY_RUN_HEADER),
            axum::http::HeaderValue::from_static("true"),
        );

        let resp = put_crd_status(
            State(state.clone()),
            Path(name.to_string()),
            None,
            dry_run_headers,
            put_body,
        )
        .await
        .expect("dry-run put status must succeed")
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["status"]["conditions"][0]["type"], "Established",
            "dry-run response must show the would-be status"
        );

        // create_crd stamps exactly two conditions (Established + NamesAccepted, see
        // build_new_crd). The dry-run PUT body above replaces status wholesale with a
        // single-entry array — if that were persisted, NamesAccepted would be gone.
        let reget = get_crd(State(state), Path(name.to_string()))
            .await
            .expect("get must succeed after dry-run");
        let reget_body = axum::body::to_bytes(reget.into_body(), usize::MAX)
            .await
            .unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&reget_body).unwrap();
        let stored_conditions = v2["status"]["conditions"].as_array().unwrap();
        assert_eq!(
            stored_conditions.len(),
            2,
            "dryRun=All must not persist the PUT's replacement status — the CRD's \
             creation-time Established+NamesAccepted conditions must be unchanged"
        );
        assert_eq!(stored_conditions[1]["type"], "NamesAccepted");
    }

    /// PUT .../{name}/status with a scalar or array `status` body must be rejected with
    /// 422, not persisted. `status` is a message/object type for every resource including a
    /// CustomResourceDefinition's own status; a PUT that wholesale-replaces it with a scalar
    /// corrupts the stored object's schema and later panics `apply_delete_policy`'s in-place
    /// `status["field"] = ...` stamp on the next DELETE, crashing the apiserver for every
    /// other request in flight. 422, matching the merge-patch equivalent: this handler
    /// guards with `replace_status_field_dynamic`, the CR-shaped 422 check, same as
    /// `put_cr_status`.
    #[tokio::test]
    async fn put_crd_status_rejects_non_object_status() {
        for bad_status in [serde_json::json!("x"), serde_json::json!(["a", "b"])] {
            let state = make_state();
            let name = "putscalarstatuses.example.io";
            let body = minimal_crd_bytes_with_group(name, "example.io", "putscalarstatuses");
            create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
                .await
                .expect("create must succeed");

            let put_body = Bytes::from(
                serde_json::json!({
                    "metadata": { "name": name },
                    "status": bad_status
                })
                .to_string(),
            );
            let result = put_crd_status(
                State(state.clone()),
                Path(name.to_string()),
                None,
                HeaderMap::new(),
                put_body,
            )
            .await;

            let err = match result {
                Err(e) => e,
                Ok(_) => panic!(
                    "a non-object status ({bad_status}) via PUT must be rejected, not \
                     persisted — it would corrupt the CRD's schema and later crash \
                     apply_delete_policy on DELETE"
                ),
            };
            assert_eq!(
                err.0,
                StatusCode::UNPROCESSABLE_ENTITY,
                "a non-object status must be rejected with 422: got {bad_status}"
            );
        }
    }

    /// PUT .../{name}/status with an explicit `status: null` body must still succeed and
    /// clear the field — the 422 guard above must reject only a present scalar/array.
    #[tokio::test]
    async fn put_crd_status_accepts_null_status() {
        let state = make_state();
        let name = "putnullstatuses.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "putnullstatuses");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let put_body = Bytes::from(
            serde_json::json!({
                "metadata": { "name": name },
                "status": null
            })
            .to_string(),
        );
        let result = put_crd_status(
            State(state.clone()),
            Path(name.to_string()),
            None,
            HeaderMap::new(),
            put_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "a null status PUT is legitimate field-clearing, not a 422: {:?}",
            result.err()
        );
    }

    /// PATCH .../{name}/status with a merge-patch must update only the status field —
    /// this is exactly what conformance's "patching" CRD status subresource scenario does.
    #[tokio::test]
    async fn patch_crd_status_merge_patch_updates_status_only() {
        let state = make_state();
        let name = "widgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "widgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let patch = serde_json::json!({
            "status": { "conditions": [{ "type": "NamesAccepted", "status": "True" }] }
        });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let resp = patch_crd_status(
            State(state),
            Path(name.to_string()),
            None,
            headers,
            patch_bytes,
        )
        .await
        .expect("patch status must succeed — before the fix this route did not exist")
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"]["conditions"][0]["type"], "NamesAccepted");
        assert_eq!(
            v["spec"]["group"], "example.io",
            "PATCH on the status subresource must not touch spec"
        );
    }

    /// `PATCH .../{name}/status?dryRun=All` must return the would-be patched status but leave
    /// the stored CRD's status untouched. Before this fix, patch_crd_status had no dry-run
    /// check at all.
    #[tokio::test]
    async fn patch_crd_status_dry_run_all_does_not_persist() {
        let state = make_state();
        let name = "dryrunpatchwidgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "dryrunpatchwidgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let patch = serde_json::json!({
            "status": { "conditions": [{ "type": "NamesAccepted", "status": "True" }] }
        });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        headers.insert(
            axum::http::HeaderName::from_static(crate::handlers::json_patch::DRY_RUN_HEADER),
            axum::http::HeaderValue::from_static("true"),
        );

        let resp = patch_crd_status(
            State(state.clone()),
            Path(name.to_string()),
            None,
            headers,
            patch_bytes,
        )
        .await
        .expect("dry-run patch status must succeed")
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["status"]["conditions"][0]["type"], "NamesAccepted",
            "dry-run response must show the would-be patched condition"
        );

        let reget = get_crd(State(state), Path(name.to_string()))
            .await
            .expect("get must succeed after dry-run");
        let reget_body = axum::body::to_bytes(reget.into_body(), usize::MAX)
            .await
            .unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&reget_body).unwrap();
        let stored_conditions = v2["status"]["conditions"].as_array().unwrap();
        assert_eq!(
            stored_conditions.len(),
            2,
            "dryRun=All must not persist the PATCH's replacement conditions array — the CRD's \
             creation-time Established+NamesAccepted conditions must be unchanged"
        );
        assert_eq!(stored_conditions[0]["type"], "Established");
    }

    /// PATCH .../{name}/status with a merge-patch body `{"status":"x"}` must be rejected
    /// with 422, not persisted. `status` is a message/object type for every resource
    /// (including a CustomResourceDefinition's own status), so a scalar `status` corrupts
    /// the stored object's schema and later panics `apply_delete_policy`'s in-place
    /// `status["field"] = ...` stamp on the next DELETE, crashing the apiserver for every
    /// other request in flight.
    #[tokio::test]
    async fn patch_crd_status_rejects_scalar_status_merge_patch() {
        let state = make_state();
        let name = "scalarstatuses.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "scalarstatuses");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let patch = serde_json::json!({ "status": "x" });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = patch_crd_status(
            State(state.clone()),
            Path(name.to_string()),
            None,
            headers,
            patch_bytes,
        )
        .await
        .err()
        .expect(
            "a scalar status merge-patch must be rejected, not accepted — it would \
                 corrupt the object's schema and later crash apply_delete_policy on DELETE",
        );
        assert_eq!(
            err.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a scalar status must be rejected with 422, matching upstream schema validation"
        );

        let resp = get_crd_status(State(state), Path(name.to_string()))
            .await
            .expect("get_crd_status must still succeed")
            .into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            v.get("status").is_none() || v["status"].is_object(),
            "the rejected patch must not have been persisted — status must remain absent \
             or an object, never the scalar \"x\""
        );
    }

    /// PATCH .../{name}/status with a JSON Patch body
    /// `[{"op":"replace","path":"/status","value":"x"}]` must be rejected too —
    /// `validate_status_json_patch_paths` explicitly permits a whole-`/status` replace path,
    /// which `apply_json_patch` turns into a scalar with no further check.
    #[tokio::test]
    async fn patch_crd_status_rejects_scalar_status_json_patch() {
        let state = make_state();
        let name = "scalarstatusesjp.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "scalarstatusesjp");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let patch = serde_json::json!([{"op": "replace", "path": "/status", "value": "x"}]);
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );

        let err = patch_crd_status(
            State(state.clone()),
            Path(name.to_string()),
            None,
            headers,
            patch_bytes,
        )
        .await
        .err()
        .expect(
            "a JSON Patch replacing /status with a scalar must be rejected, not accepted — \
             it would corrupt the object's schema and later crash apply_delete_policy on DELETE",
        );
        assert_eq!(
            err.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a scalar status must be rejected with 422, matching the merge-patch behavior"
        );

        let resp = get_crd_status(State(state), Path(name.to_string()))
            .await
            .expect("get_crd_status must still succeed")
            .into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            v.get("status").is_none() || v["status"].is_object(),
            "the rejected patch must not have been persisted — status must remain absent \
             or an object, never the scalar \"x\""
        );
    }

    /// PATCH .../customresourcedefinitions/{name}/status must accept a genuine multi-line
    /// YAML apply-patch+yaml body, not just a JSON body wearing the +yaml content-type.
    ///
    /// WHY this matters: `kubectl apply --server-side` against a CRD's status subresource
    /// (and the k8s conformance suite's ApplyStatus() calls) send real YAML block syntax.
    /// Before this fix, detect_patch_type accepted the apply-patch+yaml content type, but
    /// the body was still parsed with serde_json::from_slice, which rejects YAML outright
    /// with "invalid patch JSON" — every server-side status apply against a CRD 400'd.
    #[tokio::test]
    async fn patch_crd_status_accepts_real_yaml_apply_patch_body() {
        let state = make_state();
        let name = "widgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "widgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        // Genuine YAML block syntax — NOT JSON serialized to bytes. Uses a condition type
        // ("StoredVersionsPruned") that create_crd never seeds, so its presence can only be
        // explained by this patch actually being parsed and merged — a merge key match
        // against the pre-existing Established/NamesAccepted conditions would prove nothing.
        let patch_bytes = Bytes::from_static(
            b"status:\n  conditions:\n  - type: StoredVersionsPruned\n    status: \"True\"\n",
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let resp = patch_crd_status(
            State(state),
            Path(name.to_string()),
            None,
            headers,
            patch_bytes,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "apply-patch+yaml with a genuine YAML body on CRD /status must succeed, \
                     not 400 'invalid patch JSON': {e:?}"
            )
        })
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let conditions = v["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be an array");
        assert!(
            conditions
                .iter()
                .any(|c| c["type"] == "StoredVersionsPruned" && c["status"] == "True"),
            "the YAML-encoded condition must be persisted and echoed back, proving the body \
             was actually parsed rather than silently dropped: {conditions:?}"
        );
    }

    /// A MERGE patch to .../customresourcedefinitions/{name}/status setting
    /// `metadata.labels` must not change the stored labels — same PSA-bypass class as
    /// #733's JSON-Patch fix, but merge-patch reaches /status through
    /// `merge_incoming_metadata` rather than `validate_status_json_patch_paths`, so
    /// closing only the JSON-Patch vector left this one open. CRD labels can gate policy
    /// elsewhere (e.g. namespace/webhook selectors), so a `customresourcedefinitions/status`
    /// grant must not be able to rewrite them via a plain merge-patch.
    #[tokio::test]
    async fn patch_crd_status_merge_patch_rejects_metadata_labels() {
        let state = make_state();
        let name = "widgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "widgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let patch = serde_json::json!({
            "metadata": { "labels": { "attacker": "true" } },
            "status": { "conditions": [{ "type": "NamesAccepted", "status": "True" }] }
        });
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let resp = patch_crd_status(
            State(state.clone()),
            Path(name.to_string()),
            None,
            headers,
            patch_bytes,
        )
        .await
        .expect(
            "a merge-patch to /status must still succeed — the label change is \
                     dropped, not rejected",
        )
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            v["metadata"]["labels"]["attacker"].is_null(),
            "a merge-patch on /status must NOT be able to set arbitrary labels — \
             otherwise a status-only grant can rewrite labels used for policy elsewhere"
        );
        assert_eq!(
            v["status"]["conditions"][0]["type"], "NamesAccepted",
            "the legitimate status change in the same patch must still apply"
        );

        let reget = get_crd(State(state), Path(name.to_string()))
            .await
            .expect("get must succeed");
        let reget_body = axum::body::to_bytes(reget.into_body(), usize::MAX)
            .await
            .unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&reget_body).unwrap();
        assert!(
            v2["metadata"]["labels"]["attacker"].is_null(),
            "the dropped label must not have been persisted to the store either"
        );
    }

    /// A JSON Patch to .../customresourcedefinitions/{name}/status targeting /spec must be
    /// REJECTED — /status is a separate RBAC subresource from the main CRD endpoint. A
    /// caller with only `customresourcedefinitions/status` rights must not be able to
    /// rewrite spec.versions/spec.group via the status endpoint (this would let it
    /// redefine served versions or schema validation without the main-resource grant).
    #[tokio::test]
    async fn patch_crd_status_json_patch_rejects_spec() {
        let state = make_state();
        let name = "widgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "widgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let patch = serde_json::json!([
            { "op": "replace", "path": "/spec/group", "value": "attacker.io" }
        ]);
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );

        let err = match patch_crd_status(
            State(state.clone()),
            Path(name.to_string()),
            None,
            headers,
            patch_bytes,
        )
        .await
        {
            Ok(_) => panic!(
                "a JSON Patch on /status targeting /spec must be rejected — a status-only \
                 grant must not be able to redefine spec.group/spec.versions"
            ),
            Err(e) => e,
        };
        assert_eq!(serde_json::to_value(&err.1).unwrap()["code"], 422);

        let reget = get_crd(State(state), Path(name.to_string()))
            .await
            .expect("get must succeed");
        let reget_body = axum::body::to_bytes(reget.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&reget_body).unwrap();
        assert_eq!(
            v["spec"]["group"], "example.io",
            "spec.group must not be changed by the rejected status JSON Patch"
        );
    }

    /// A JSON Patch to .../customresourcedefinitions/{name}/status targeting
    /// /metadata/labels must be REJECTED — same RBAC-isolation rule as /spec. Metadata
    /// labels can gate policy elsewhere (e.g. namespace selectors), so a status-only
    /// grant must not be able to rewrite them via this endpoint.
    #[tokio::test]
    async fn patch_crd_status_json_patch_rejects_metadata_labels() {
        let state = make_state();
        let name = "widgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "widgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let patch = serde_json::json!([
            { "op": "add", "path": "/metadata/labels", "value": { "attacker": "true" } }
        ]);
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );

        let err = match patch_crd_status(
            State(state),
            Path(name.to_string()),
            None,
            headers,
            patch_bytes,
        )
        .await
        {
            Ok(_) => panic!("a JSON Patch on /status targeting /metadata/labels must be rejected"),
            Err(e) => e,
        };
        assert_eq!(serde_json::to_value(&err.1).unwrap()["code"], 422);
    }

    /// A JSON Patch touching only /status must still be accepted on the CRD /status
    /// endpoint — the path guard must not block legitimate status-only JSON Patches.
    #[tokio::test]
    async fn patch_crd_status_json_patch_touching_only_status_succeeds() {
        let state = make_state();
        let name = "widgets.example.io";
        let body = minimal_crd_bytes_with_group(name, "example.io", "widgets");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("create must succeed");

        let patch = serde_json::json!([
            {
                "op": "add",
                "path": "/status/conditions",
                "value": [{ "type": "NamesAccepted", "status": "True" }]
            }
        ]);
        let patch_bytes = Bytes::from(serde_json::to_vec(&patch).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );

        let resp = patch_crd_status(
            State(state),
            Path(name.to_string()),
            None,
            headers,
            patch_bytes,
        )
        .await
        .expect("a JSON Patch touching only /status must be accepted")
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// GET/PUT/PATCH .../{name}/status on a missing CRD must return 404, not fall through
    /// to the generic CR catch-all's "CRD-of-CRDs not found" error.
    #[tokio::test]
    async fn crd_status_missing_returns_404() {
        let state = make_state();
        let name = "missing.example.io";

        let err = match get_crd_status(State(state.clone()), Path(name.to_string())).await {
            Ok(_) => panic!("expected 404"),
            Err(e) => e,
        };
        assert_eq!(serde_json::to_value(&err.1).unwrap()["code"], 404);

        let put_body = Bytes::from(serde_json::json!({"status": {}}).to_string());
        let err = match put_crd_status(
            State(state.clone()),
            Path(name.to_string()),
            None,
            HeaderMap::new(),
            put_body,
        )
        .await
        {
            Ok(_) => panic!("expected 404"),
            Err(e) => e,
        };
        assert_eq!(serde_json::to_value(&err.1).unwrap()["code"], 404);

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        let patch_body = Bytes::from(serde_json::json!({"status": {}}).to_string());
        let err = match patch_crd_status(
            State(state),
            Path(name.to_string()),
            None,
            headers,
            patch_body,
        )
        .await
        {
            Ok(_) => panic!("expected 404"),
            Err(e) => e,
        };
        assert_eq!(serde_json::to_value(&err.1).unwrap()["code"], 404);
    }

    // -- validate_crd_group: built-in group shadowing protection --

    /// A CRD with spec.group="apps" must be rejected with 422.
    /// Allowing it would let unprivileged users shadow the real apps/v1 API group
    /// and intercept Deployment, ReplicaSet, etc. traffic.
    #[tokio::test]
    async fn create_crd_rejects_builtin_group_apps() {
        let state = make_state();
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "foos.apps" },
                "spec": {
                    "group": "apps",
                    "names": {
                        "plural": "foos",
                        "singular": "foo",
                        "kind": "Foo"
                    },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );

        let err = err_status(create_crd(State(state), test_user(), HeaderMap::new(), body).await);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "built-in group 'apps' must return 422 Unprocessable Entity"
        );
        assert!(
            json["message"].as_str().unwrap_or("").contains("built-in"),
            "error must mention built-in group restriction"
        );
    }

    /// A CRD with a valid user-controlled group must be accepted.
    #[tokio::test]
    async fn create_crd_accepts_user_controlled_group() {
        let state = make_state();
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.myapp.example.com" },
                "spec": {
                    "group": "myapp.example.com",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget"
                    },
                    "scope": "Namespaced",
                    "versions": [{ "name": "v1", "served": true, "storage": true }]
                }
            })
            .to_string(),
        );

        assert!(
            create_crd(State(state), test_user(), HeaderMap::new(), body)
                .await
                .is_ok(),
            "user-controlled group must be accepted"
        );
    }

    /// validate_crd_group unit tests for all built-in groups and edge cases.
    #[test]
    fn validate_crd_group_blocks_all_builtin_groups() {
        for group in BUILTIN_GROUPS {
            let result = validate_crd_group(group);
            assert!(
                result.is_err(),
                "built-in group '{group}' must be rejected by validate_crd_group"
            );
        }
    }

    #[test]
    fn validate_crd_group_rejects_path_traversal() {
        assert!(validate_crd_group("../../etc").is_err());
        assert!(validate_crd_group("foo/bar").is_err());
    }

    #[test]
    fn validate_crd_group_accepts_valid_user_groups() {
        assert!(validate_crd_group("example.com").is_ok());
        assert!(validate_crd_group("argoproj.io").is_ok());
        assert!(validate_crd_group("gateway.networking.x-k8s.io").is_ok());
    }

    // -- validate_crd_schema: patternProperties rejected outright, matching upstream --

    fn crd_bytes_with_schema(name: &str, schema: serde_json::Value) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": name },
                "spec": {
                    "group": "example.io",
                    "names": { "plural": "widgets", "singular": "widget", "kind": "Widget" },
                    "scope": "Namespaced",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": { "openAPIV3Schema": schema }
                    }]
                }
            })
            .to_string(),
        )
    }

    /// Upstream K8s (apiextensions-apiserver validation.go:1493-1494) unconditionally
    /// rejects `patternProperties` at the schema root as a structural-schema violation.
    /// A u7s CRD accepting it would let an unprivileged CR author install a resource
    /// upstream would have refused, breaking portability of CRDs across clusters.
    #[tokio::test]
    async fn create_crd_rejects_root_pattern_properties_to_match_upstream() {
        let state = make_state();
        let schema = serde_json::json!({
            "type": "object",
            "patternProperties": { "^x-": { "type": "string" } }
        });
        let body = crd_bytes_with_schema("widgets.example.io", schema);

        let err = err_status(create_crd(State(state), test_user(), HeaderMap::new(), body).await);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "root-level patternProperties must be rejected with 422"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("patternProperties is not supported"),
            "error must echo upstream's exact wording so K8s clients parse it identically: {json}"
        );
    }

    /// A rule naming a property the schema never declared can never hold; accepting the
    /// CRD would turn a typo into a 422 on every CR write instead of at install time.
    #[tokio::test]
    async fn create_crd_rejects_validation_rule_referencing_undeclared_property() {
        let state = make_state();
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "spec": {
                "type": "object",
                "x-kubernetes-validations": [{ "rule": "self.z == 100" }],
                "properties": { "x": { "type": "integer" } }
            } }
        });
        let body = crd_bytes_with_schema("widgets.example.io", schema);
        let err = err_status(create_crd(State(state), test_user(), HeaderMap::new(), body).await);
        assert_eq!(err.1.code, 422);
        assert!(
            err.1.message.contains("undefined field 'z'"),
            "{}",
            err.1.message
        );
    }

    /// A rule that does not parse must be refused at install time for the same reason.
    #[tokio::test]
    async fn create_crd_rejects_validation_rule_with_syntax_error() {
        let state = make_state();
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "spec": {
                "type": "object",
                "x-kubernetes-validations": [{ "rule": "self = 42" }]
            } }
        });
        let body = crd_bytes_with_schema("widgets.example.io", schema);
        let err = err_status(create_crd(State(state), test_user(), HeaderMap::new(), body).await);
        assert_eq!(err.1.code, 422);
        assert!(err.1.message.contains("Syntax error"), "{}", err.1.message);
    }

    /// patternProperties nested inside a `properties` map entry (not just the schema
    /// root) must also be rejected — a CRD author could otherwise bury the forbidden
    /// keyword one level deep to evade a root-only check.
    #[tokio::test]
    async fn create_crd_rejects_pattern_properties_nested_in_properties_map() {
        let state = make_state();
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "patternProperties": { "^x-": { "type": "string" } }
                }
            }
        });
        let body = crd_bytes_with_schema("widgets.example.io", schema);

        let err = err_status(create_crd(State(state), test_user(), HeaderMap::new(), body).await);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "patternProperties nested under properties.spec must be rejected"
        );
        assert!(json["message"]
            .as_str()
            .unwrap_or("")
            .contains("patternProperties is not supported"));
    }

    /// patternProperties nested inside an array item schema must also be rejected —
    /// the walk must recurse into `items`, not just `properties`.
    #[tokio::test]
    async fn create_crd_rejects_pattern_properties_nested_in_array_item_schema() {
        let state = make_state();
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "list": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "patternProperties": { "^x-": { "type": "string" } }
                    }
                }
            }
        });
        let body = crd_bytes_with_schema("widgets.example.io", schema);

        let err = err_status(create_crd(State(state), test_user(), HeaderMap::new(), body).await);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "patternProperties nested under an array item schema must be rejected"
        );
        assert!(json["message"]
            .as_str()
            .unwrap_or("")
            .contains("patternProperties is not supported"));
    }

    /// Positive control: a schema with no patternProperties anywhere must be accepted —
    /// otherwise the walk is over-eager and blocks legitimate CRDs that only use `pattern`.
    #[tokio::test]
    async fn create_crd_accepts_schema_without_pattern_properties() {
        let state = make_state();
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": {
                        "cpu": { "type": "string", "pattern": "^[0-9]+m?$" }
                    }
                }
            }
        });
        let body = crd_bytes_with_schema("widgets.example.io", schema);

        assert!(
            create_crd(State(state), test_user(), HeaderMap::new(), body)
                .await
                .is_ok(),
            "a schema using only `pattern` (no patternProperties) must be accepted"
        );
    }

    // -- validate_crd_schema: pattern length cap (boon O(n^2) ReDoS defense) --

    /// A `pattern` over MAX_CRD_PATTERN_BYTES must be rejected at CRD admission time —
    /// otherwise any principal with mere create/update RBAC on the resulting Custom
    /// Resource kind can retrigger boon's O(n^2) ECMA-compat rewrite on every CR write,
    /// pinning a CPU core for the duration of the compile.
    #[tokio::test]
    async fn crd_admission_rejects_oversized_pattern_to_prevent_boon_o_n_squared_dos() {
        let state = make_state();
        let oversized = "a".repeat(MAX_CRD_PATTERN_BYTES + 1);
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": { "field": { "type": "string", "pattern": oversized } }
                }
            }
        });
        let body = crd_bytes_with_schema("widgets.example.io", schema);

        let err = err_status(create_crd(State(state), test_user(), HeaderMap::new(), body).await);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "a pattern exceeding the {MAX_CRD_PATTERN_BYTES}-byte cap must be rejected"
        );
        let message = json["message"].as_str().unwrap_or("");
        assert!(
            message.contains("exceeds maximum length") && message.contains("1025 bytes"),
            "error must report the actual oversized length so the CRD author can fix it: {message}"
        );
    }

    /// A `pattern` exactly at the MAX_CRD_PATTERN_BYTES boundary must be accepted —
    /// an off-by-one here would reject legitimate schemas that happen to sit right at
    /// the cap (e.g. hand-written alternation patterns).
    #[tokio::test]
    async fn crd_admission_accepts_at_cap_pattern() {
        let state = make_state();
        let at_cap = "a".repeat(MAX_CRD_PATTERN_BYTES);
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": { "field": { "type": "string", "pattern": at_cap } }
                }
            }
        });
        let body = crd_bytes_with_schema("widgets.example.io", schema);

        assert!(
            create_crd(State(state), test_user(), HeaderMap::new(), body)
                .await
                .is_ok(),
            "a pattern exactly at the {MAX_CRD_PATTERN_BYTES}-byte cap must be accepted \
             (off-by-one guard)"
        );
    }

    /// Regression: when kcm's metadatainformer opens a watch on CRDs with an Accept header
    /// requesting PartialObjectMetadata and sendInitialEvents=true, the initial-events-end
    /// BOOKMARK must have apiVersion=meta.k8s.io/v1 and kind=PartialObjectMetadata.
    ///
    /// Without the fix, list_crds ignored the Accept header and called watch_generic with
    /// as_partial_object_metadata=false, producing a BOOKMARK with
    /// apiVersion=apiextensions.k8s.io/v1, kind=CustomResourceDefinition — which client-go's
    /// reflector does not recognise, so GC never completes cache sync and the deployment
    /// controller never reconciles.
    #[tokio::test]
    async fn list_crds_pom_watch_bookmark_has_meta_k8s_io_api_version() {
        use tokio::time::{timeout, Duration};

        let state = make_state();

        // Seed one CRD so the initial-events stream is non-empty.
        let body = minimal_crd_bytes("applications.argoproj.io");
        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .unwrap_or_else(|_| panic!("create must succeed"));

        let mut pom_headers = HeaderMap::new();
        pom_headers.insert(
            axum::http::header::ACCEPT,
            "application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json"
                .parse()
                .unwrap(),
        );

        let query = Query(crate::handlers::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: Some(true),
            allow_watch_bookmarks: Some(true),
            timeout_seconds: Some(1), // stream closes after 1s so to_bytes can return with collected data
        });

        let resp = list_crds(
            State(state),
            query,
            pom_headers,
            Extension(UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("list_crds with POM Accept must succeed"));

        // Read until stream closes (timeout_seconds=1) or the 3-second guard fires.
        // The initial-events BOOKMARK is emitted before any live-event wait.
        let body = resp.into_body();
        let bytes = timeout(
            Duration::from_secs(3),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await
        .unwrap_or_else(|_| Ok(bytes::Bytes::new()))
        .unwrap_or_default();
        let text = std::str::from_utf8(&bytes).unwrap_or("");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        let bookmark = lines.iter().find(|v| {
            v["type"] == "BOOKMARK"
                && v["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
        });
        assert!(
            bookmark.is_some(),
            "list_crds with POM Accept and sendInitialEvents=true must emit initial-events-end BOOKMARK; \
             without it GC never completes cache sync. Lines: {:?}",
            lines
        );

        let bm = bookmark.unwrap();
        assert_eq!(
            bm["object"]["apiVersion"], "meta.k8s.io/v1",
            "BOOKMARK for POM watch must have apiVersion=meta.k8s.io/v1, not apiextensions.k8s.io/v1; \
             client-go reflector uses apiVersion to identify the BOOKMARK type"
        );
        assert_eq!(
            bm["object"]["kind"], "PartialObjectMetadata",
            "BOOKMARK for POM watch must have kind=PartialObjectMetadata, not CustomResourceDefinition"
        );
    }

    /// Re-creating a CRD after deletion must remove the deleted-group tombstone.
    ///
    /// Without this fix, a CRD deleted and then re-created for the same spec.group
    /// leaves a stale tombstone that causes all CR requests for that group to return
    /// 410 Gone instead of routing to the new CRD. Informers treat 410 as "stop
    /// watching" and never recover — controllers lose visibility into the resource
    /// forever until the server restarts.
    #[tokio::test]
    async fn recreate_crd_clears_deleted_group_tombstone() {
        use std::sync::Arc;
        use u7s_store::{SqliteStore, Store};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let name = "applications.argoproj.io";
        let body = minimal_crd_bytes(name);
        let group = "argoproj.io";

        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            body.clone(),
        )
        .await
        .expect("initial create must succeed");

        delete_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete must succeed");

        let tombstone_key = deleted_group_tombstone_key(group);
        let after_delete = store
            .get(&tombstone_key)
            .await
            .expect("store get must not error");
        assert!(
            after_delete.is_some(),
            "tombstone must be written after CRD deletion so CR handlers return 410 Gone"
        );

        create_crd(State(state.clone()), test_user(), HeaderMap::new(), body)
            .await
            .expect("re-create must succeed — AlreadyExists means delete did not fully clean up");

        let after_recreate = store
            .get(&tombstone_key)
            .await
            .expect("store get must not error");
        assert!(
            after_recreate.is_none(),
            "tombstone must be removed when CRD is re-created; if it persists, CR requests \
             for group '{}' return 410 Gone instead of routing to the new CRD",
            group
        );
    }

    /// Deleting a CRD must free its watch-ring shard immediately, not merely once idle-GC's
    /// RING_SHARD_IDLE_GRACE elapses after the last watcher disconnects.
    ///
    /// Why it matters: CRD conformance churn creates and deletes dozens of transient CRDs per
    /// run — leaving each one's shard alive until idle-GC would pin many-KiB of ring capacity
    /// per dead CRD for up to 120s, and any watcher reconnecting with a stale resourceVersion
    /// in that window would silently get a fresh-empty replay instead of the correct 410 Gone.
    ///
    /// Fails on revert: without the `evict_resource_type` call, the shard stays live and quiet
    /// (it never evicted anything on its own, so its `horizon` field stays 0), and
    /// `compaction_horizon_for` keeps reporting 0 after delete. This test asserts it instead
    /// reflects the shard's highest-held revision, which only happens once the shard has
    /// actually been torn down and its floor preserved into `reclaimed_horizons`.
    #[tokio::test]
    async fn delete_crd_evicts_watch_ring_shard_immediately() {
        use std::sync::Arc;
        use u7s_store::{SqliteStore, Store};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let name = "widgets.teardown.example.com";
        let group = "teardown.example.com";
        let plural = "widgets";
        let prefix = crate::handlers::cr::cr_list_prefix(group, plural, None);

        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, group, plural),
        )
        .await
        .expect("create must succeed");

        // Opening a watch is what brings a shard into existence (writes alone do not — see
        // SqliteStore::watch's doc). Dropping it immediately still leaves the shard live until
        // idle-GC's grace period — 120s in this non-store-crate build — which is exactly the
        // delay this bead's fix must not wait for.
        let watch_stream = store.watch(&prefix, 0).await.expect("watch must succeed");
        drop(watch_stream);

        // One real CR write, nowhere near RING_CAPACITY, so the shard's own eviction floor
        // (`horizon`) never advances past 0 on its own — isolating "torn down" from "compacted".
        let cr_key = format!("{prefix}default/widget-a");
        let rv = store
            .put(
                &cr_key,
                Bytes::from(
                    serde_json::json!({"metadata": {"name": "widget-a", "namespace": "default"}})
                        .to_string(),
                ),
                None,
            )
            .await
            .expect("CR write must succeed");

        assert_eq!(
            store.compaction_horizon_for(&prefix),
            0,
            "sanity check on test setup: a quiet shard that never evicted anything must report \
             horizon 0 while it is still live"
        );

        delete_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete must succeed");

        assert!(
            store.compaction_horizon_for(&prefix) >= rv,
            "CRD delete must eagerly free the resource-type shard rather than waiting 120s for \
             idle-GC — CRD conformance churn (dozens of transient CRDs per run) would otherwise \
             pin many-KiB of ring capacity per dead CRD until the grace period expires, and any \
             watcher reconnecting with a stale RV in that window would silently get a \
             fresh-empty replay instead of the correct 410 Gone"
        );
    }

    /// Deleting a CRD must tear down EVERY shard rooted at its resource type, not just the
    /// exact cluster-scoped key — a namespace-scoped shard for the same plural can coexist
    /// alongside the cluster-scoped one (see `matching_shards`' doc in the store crate), and a
    /// naive `shards.remove(cluster_scoped_key)` would miss it.
    ///
    /// Fails on revert to an exact-key-only teardown: the namespace-scoped shard (opened first
    /// below, so it gets its own distinct map entry rather than being reused by the broader
    /// cluster-scoped watch opened afterward — see `find_shard`'s doc) stays live and
    /// untouched, so its `compaction_horizon_for` value never advances off 0 the way the
    /// assertion below requires.
    #[tokio::test]
    async fn delete_crd_evicts_namespace_scoped_shard_too() {
        use std::sync::Arc;
        use u7s_store::{SqliteStore, Store};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let name = "gadgets.teardown2.example.com";
        let group = "teardown2.example.com";
        let plural = "gadgets";
        let cluster_prefix = crate::handlers::cr::cr_list_prefix(group, plural, None);
        let ns_prefix = crate::handlers::cr::cr_list_prefix(group, plural, Some("default"));

        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, group, plural),
        )
        .await
        .expect("create must succeed");

        // Namespace-scoped watch FIRST: opening the broader cluster-scoped watch afterward
        // cannot reuse this shard (its key is longer than, and so not a prefix of, the
        // cluster-scoped root), so both end up as distinct map entries — exactly the situation
        // a naive exact-key teardown mishandles.
        let ns_watch = store
            .watch(&ns_prefix, 0)
            .await
            .expect("namespace-scoped watch must succeed");
        drop(ns_watch);
        let cluster_watch = store
            .watch(&cluster_prefix, 0)
            .await
            .expect("cluster-scoped watch must succeed");
        drop(cluster_watch);

        // One write to an object under the namespace fans into BOTH shards (matching_shards
        // finds every shard whose key is a prefix of this write's key), so both stay quiet
        // (never evict on their own) yet both hold a real, nonzero revision.
        let cr_key = format!("{ns_prefix}gadget-a");
        let rv = store
            .put(
                &cr_key,
                Bytes::from(
                    serde_json::json!({"metadata": {"name": "gadget-a", "namespace": "default"}})
                        .to_string(),
                ),
                None,
            )
            .await
            .expect("CR write must succeed");

        assert_eq!(store.compaction_horizon_for(&ns_prefix), 0);
        assert_eq!(store.compaction_horizon_for(&cluster_prefix), 0);

        delete_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete must succeed");

        assert!(
            store.compaction_horizon_for(&cluster_prefix) >= rv,
            "cluster-scoped shard must be torn down by CRD delete"
        );
        assert!(
            store.compaction_horizon_for(&ns_prefix) >= rv,
            "a naive exact-key `remove(cluster_scoped_key)` would leave namespace-scoped shards \
             for the same resource type alive after CRD delete — the namespace-scoped ones \
             would then serve empty/synthetic replays to reconnecting watchers, and their \
             KiB-per-shard cost would leak until idle-GC (or forever if a watcher stays \
             connected)"
        );
    }

    async fn install_widget_crd(state: &AppState<u7s_store::SqliteStore>, group: &str) -> String {
        let name = format!("widgets.{group}");
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(&name, group, "widgets"),
        )
        .await
        .expect("create must succeed");
        name
    }

    async fn delete_crd_ok(state: &AppState<u7s_store::SqliteStore>, name: &str) {
        delete_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete must succeed");
    }

    /// A deleted CRD's served versions can never be requested again, so conversion-cache
    /// entries targeting them leak for the life of the process if not swept.
    ///
    /// Fails on revert: without `invalidate_by_target_api_versions` in `purge_crd` the entry
    /// stays cached.
    #[tokio::test]
    async fn delete_crd_evicts_cr_conversion_cache_entries_for_its_target_api_versions() {
        let state = make_state();
        let group = "conv.example.com";
        let name = install_widget_crd(&state, group).await;
        let cache_key = ("42".to_string(), format!("{group}/v1"));
        state.cr_conversion_cache.insert(
            cache_key.clone(),
            &serde_json::json!({ "apiVersion": format!("{group}/v1"), "kind": "Widget" }),
        );
        assert!(
            state.cr_conversion_cache.contains(&cache_key),
            "precondition: the converted body must be cached before the CRD delete"
        );

        delete_crd_ok(&state, &name).await;

        assert!(
            !state.cr_conversion_cache.contains(&cache_key),
            "CRD delete must evict conversion-cache entries targeting its served versions"
        );
    }

    /// Aggregated /apis discovery is served from a cache with no TTL, refreshed only by an
    /// explicit call. A stale entry keeps advertising the deleted group, so KCM's namespace
    /// controller keeps rediscovering it and the namespace drain never finishes.
    ///
    /// Fails on revert: without `refresh_discovery_cache` in `purge_crd` the group stays listed.
    #[tokio::test]
    async fn delete_crd_refreshes_discovery_so_the_deleted_group_is_no_longer_listed() {
        let state = make_state();
        let group = "disc.example.com";
        let name = install_widget_crd(&state, group).await;
        let list_groups = || async {
            crate::handlers::discovery::build_aggregated_discovery(
                &state,
                "v2beta1",
                false,
                &crate::auth::UserInfo::default(),
                "/apis",
            )
            .await
        };
        assert!(
            list_groups()
                .await
                .items
                .iter()
                .any(|g| g.metadata.name == group),
            "precondition: the CRD's group must be in discovery right after creation"
        );

        delete_crd_ok(&state, &name).await;

        assert!(
            !list_groups()
                .await
                .items
                .iter()
                .any(|g| g.metadata.name == group),
            "the deleted CRD's group must disappear from discovery immediately"
        );
    }

    /// A connected CR watcher must see its objects DELETED when the CRD goes away, and the
    /// CRD's CR watch-ring shard must be reclaimed while that watcher is still attached —
    /// otherwise every deleted CRD leaks ring memory for as long as any client stays connected.
    ///
    /// Fails on revert to the wrong shard prefix (`group_list_prefix`, which is not where CRs
    /// live): the CR shard stays live, so its horizon never advances off 0.
    #[tokio::test]
    async fn deleted_crd_cr_watcher_gets_terminal_event_and_shard_is_reclaimed() {
        use futures_util::StreamExt;
        use std::sync::Arc;
        use u7s_store::{SqliteStore, Store, WatchEvent};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let name = "sprockets.teardown3.example.com";
        let group = "teardown3.example.com";
        let plural = "sprockets";
        let prefix = crate::handlers::cr::cr_list_prefix(group, plural, None);

        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(name, group, plural),
        )
        .await
        .expect("create must succeed");
        let cr_key = format!("{prefix}default/sprocket-a");
        let rv = store
            .put(
                &cr_key,
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": format!("{group}/v1"), "kind": "Sprocket",
                        "metadata": { "name": "sprocket-a", "namespace": "default" },
                    })
                    .to_string(),
                ),
                None,
            )
            .await
            .expect("CR write must succeed");

        let watch = store.watch(&prefix, 0).await.expect("watch must succeed");
        futures_util::pin_mut!(watch);
        assert!(
            matches!(watch.next().await, Some(WatchEvent::Added(o)) if o.key == cr_key),
            "watcher must first see the existing CR"
        );
        assert_eq!(store.compaction_horizon_for(&prefix), 0);

        delete_crd(
            State(state.clone()),
            Path(name.to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete must succeed");

        let terminal = tokio::time::timeout(std::time::Duration::from_secs(5), watch.next())
            .await
            .expect("watcher must not hang after its CRD is deleted");
        assert!(
            matches!(&terminal, Some(WatchEvent::Deleted { key, .. }) if *key == cr_key),
            "watcher of a deleted CRD must be told its objects are gone, got {terminal:?}"
        );
        assert!(
            store.compaction_horizon_for(&prefix) >= rv,
            "the CR watch-ring shard must be torn down with the CRD even while a watcher is \
             still attached; otherwise each deleted CRD leaks its ring until every client leaves"
        );
    }
}

// ---------------------------------------------------------------------------
// Admission regression tests — prove create_crd / replace_crd invoke the
// admission webhook pipeline.
//
// Without the fix, these handlers bypassed admission entirely.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod admission_tests {
    use std::sync::Arc;

    use axum::{routing::post, Router};
    use bytes::Bytes;
    use tokio::net::TcpListener;
    use u7s_store::{SqliteStore, Store};

    use super::*;

    use crate::handlers::test_support::make_state_with_store as make_state;

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
    }

    async fn start_mock_webhook(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock webhook server must not fail");
        });
        (format!("http://{addr}"), handle)
    }

    fn crd_body(name: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": {"name": name},
                "spec": {
                    "group": "example.com",
                    "names": {
                        "plural": "foos",
                        "singular": "foo",
                        "kind": "Foo",
                        "listKind": "FooList"
                    },
                    "scope": "Namespaced",
                    "versions": [{"name": "v1", "served": true, "storage": true}]
                }
            })
            .to_string(),
        )
    }

    fn deny_router() -> Router {
        Router::new().route(
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
        )
    }

    /// create_crd must invoke the validating admission pipeline.
    /// A validating webhook that denies must cause create_crd to return an error,
    /// and the CRD must NOT be stored. Before the fix, admission was bypassed.
    #[tokio::test]
    async fn create_crd_invokes_validating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        let (url, _handle) = start_mock_webhook(deny_router()).await;

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-validating-crd"},
            "webhooks": [{
                "name": "deny.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": ["apiextensions.k8s.io"], "apiVersions": ["v1"], "resources": ["customresourcedefinitions"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-validating-crd",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = create_crd(
            axum::extract::State(state),
            test_user(),
            HeaderMap::new(),
            crd_body("foos.example.com"),
        )
        .await;

        assert!(
            result.is_err(),
            "create_crd must be rejected when validating webhook denies — \
             without the fix, admission was bypassed and the CRD was silently stored"
        );

        let stored = store.get(&store_key("foos.example.com")).await.unwrap();
        assert!(
            stored.is_none(),
            "denied CRD must not be stored in the backing store"
        );
    }

    /// replace_crd must invoke the validating admission pipeline.
    /// A validating webhook that denies must cause replace_crd to return an error.
    #[tokio::test]
    async fn replace_crd_invokes_validating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        // First create the CRD (no webhook registered yet).
        let create_result = create_crd(
            axum::extract::State(state.clone()),
            test_user(),
            HeaderMap::new(),
            crd_body("foos.example.com"),
        )
        .await;
        assert!(create_result.is_ok(), "initial create must succeed");

        let (url, _handle) = start_mock_webhook(deny_router()).await;

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-validating-crd-update"},
            "webhooks": [{
                "name": "deny.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": ["apiextensions.k8s.io"], "apiVersions": ["v1"], "resources": ["customresourcedefinitions"], "operations": ["UPDATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-validating-crd-update",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = replace_crd(
            axum::extract::State(state),
            axum::extract::Path("foos.example.com".to_string()),
            test_user(),
            HeaderMap::new(),
            crd_body("foos.example.com"),
        )
        .await;

        assert!(
            result.is_err(),
            "replace_crd must be rejected when validating webhook denies — \
             without the fix, admission was bypassed and the CRD was silently updated"
        );
    }
}

#[cfg(test)]
mod ratchet_tests {
    use axum::extract::{Path, State};
    use axum::http::HeaderMap;
    use bytes::Bytes;
    use serde_json::{json, Value};
    use u7s_store::Store;

    use super::tests::minimal_crd_bytes_with_group;
    use super::*;
    use crate::handlers::test_support::make_state;

    const NAME: &str = "widgets.example.com";

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
    }

    fn expensive_rule() -> Value {
        json!({ "rule": "self.all(s, s == 'string constant')" })
    }

    fn schema_with_rules(spec_rules: Value, nested_rules: Value) -> Value {
        json!({ "openAPIV3Schema": {
            "type": "object",
            "properties": { "spec": {
                "type": "object",
                "x-kubernetes-validations": spec_rules,
                "properties": { "x": {
                    "maxItems": 10,
                    "type": "array",
                    "items": {
                        "type": "array",
                        "items": { "type": "string" },
                        "x-kubernetes-validations": nested_rules
                    }
                } }
            } }
        } })
    }

    fn crd_body(rv: &str, labels: Value, versions: Value) -> Bytes {
        Bytes::from(
            json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": NAME, "resourceVersion": rv, "labels": labels },
                "spec": {
                    "group": "example.com",
                    "names": { "plural": "widgets", "singular": "widget", "kind": "Widget" },
                    "scope": "Namespaced",
                    "versions": versions
                }
            })
            .to_string(),
        )
    }

    fn version(name: &str, schema: Value) -> Value {
        json!({ "name": name, "served": true, "storage": name == "v1", "schema": schema })
    }

    /// Stores a CRD carrying rules create-time validation would refuse, as an older
    /// binary (or a looser upstream) could have, and returns its resourceVersion.
    async fn seed_with_legacy_rules<S: Store>(state: &AppState<S>, schema: Value) -> String {
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            crd_body("", json!({}), json!([version("v1", json!({}))])),
        )
        .await
        .map_err(|_| ())
        .expect("seed create");
        let stored = state.store.get(&store_key(NAME)).await.unwrap().unwrap();
        let mut v: Value = serde_json::from_slice(&stored.value).unwrap();
        v["spec"]["versions"][0]["schema"] = schema;
        let rv = state
            .store
            .put(&store_key(NAME), Bytes::from(v.to_string()), None)
            .await
            .unwrap();
        rv.to_string()
    }

    async fn put<S: Store>(state: &AppState<S>, body: Bytes) -> bool {
        replace_crd(
            State(state.clone()),
            Path(NAME.to_string()),
            test_user(),
            HeaderMap::new(),
            body,
        )
        .await
        .is_ok()
    }

    fn legacy_schema() -> Value {
        schema_with_rules(
            json!([{ "rule": "self.nope == 1" }]),
            json!([expensive_rule()]),
        )
    }

    /// An update that leaves the schema alone (a controller stamping a label) must not be
    /// refused for rules the CRD already carried, or the CRD becomes unmanageable.
    #[tokio::test]
    async fn label_only_update_keeps_already_stored_expensive_and_unresolvable_rules() {
        let state = make_state();
        let rv = seed_with_legacy_rules(&state, legacy_schema()).await;
        let body = crd_body(
            &rv,
            json!({"a": "b"}),
            json!([version("v1", legacy_schema())]),
        );
        assert!(put(&state, body).await);
    }

    /// Adding another version leaves v1's schema unchanged, so v1's stored rules still pass.
    #[tokio::test]
    async fn unrelated_spec_change_keeps_already_stored_rules() {
        let state = make_state();
        let rv = seed_with_legacy_rules(&state, legacy_schema()).await;
        let versions = json!([version("v1", legacy_schema()), version("v2", json!({}))]);
        assert!(put(&state, crd_body(&rv, json!({}), versions)).await);
    }

    /// Ratcheting must not become a bypass: a rule absent from the stored CRD is checked.
    #[tokio::test]
    async fn newly_added_unresolvable_rule_is_still_rejected_on_update() {
        let state = make_state();
        let rv = seed_with_legacy_rules(&state, legacy_schema()).await;
        let bad = schema_with_rules(
            json!([{ "rule": "self.nope == 1" }, { "rule": "self.other == 2" }]),
            json!([expensive_rule()]),
        );
        let body = crd_body(&rv, json!({}), json!([version("v1", bad)]));
        assert!(!put(&state, body).await);
    }

    /// Editing one rule must not re-reject a different stored over-limit rule in the same
    /// version, or an operator cannot fix a small thing in a CRD that already shipped.
    #[tokio::test]
    async fn editing_another_rule_keeps_stored_over_limit_rule() {
        let state = make_state();
        let rv = seed_with_legacy_rules(&state, legacy_schema()).await;
        let edited = schema_with_rules(
            json!([{ "rule": "self.nope == 1" }, { "rule": "true" }]),
            json!([expensive_rule()]),
        );
        let body = crd_body(&rv, json!({}), json!([version("v1", edited)]));
        assert!(put(&state, body).await);
    }

    /// A new over-limit rule is refused even when the version also carries a stored one.
    #[tokio::test]
    async fn newly_added_expensive_rule_is_still_rejected_on_update() {
        let state = make_state();
        let rv = seed_with_legacy_rules(&state, legacy_schema()).await;
        let costly = schema_with_rules(
            json!([{ "rule": "self.nope == 1" }]),
            json!([expensive_rule(), { "rule": "self.all(s, s == 'another constant')" }]),
        );
        let body = crd_body(&rv, json!({}), json!([version("v1", costly)]));
        assert!(!put(&state, body).await);
    }

    #[tokio::test]
    async fn label_only_merge_patch_keeps_already_stored_rules() {
        let state = make_state();
        seed_with_legacy_rules(&state, legacy_schema()).await;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        let patch = Bytes::from(json!({ "metadata": { "labels": { "a": "b" } } }).to_string());
        let res = patch_crd(
            State(state.clone()),
            Path(NAME.to_string()),
            test_user(),
            headers,
            patch,
        )
        .await;
        assert!(res.is_ok());
    }

    const FIN_CRD: &str = "widgets.fin.io";

    async fn create_fin_crd(state: &AppState) {
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(FIN_CRD, "fin.io", "widgets"),
        )
        .await
        .expect("create CRD");
    }

    async fn put_widget(state: &AppState, name: &str, finalizers: &[&str]) -> String {
        let key = format!("/registry/cr/fin.io/widgets/default/{name}");
        let obj = serde_json::json!({
            "apiVersion": "fin.io/v1", "kind": "Widget",
            "metadata": { "name": name, "namespace": "default", "finalizers": finalizers },
        });
        state
            .store
            .put(&key, Bytes::from(obj.to_string()), Some(0))
            .await
            .expect("seed widget");
        key
    }

    async fn stored_json(state: &AppState, key: &str) -> Option<serde_json::Value> {
        state
            .store
            .get(key)
            .await
            .unwrap()
            .map(|o| serde_json::from_slice(&o.value).unwrap())
    }

    async fn delete_fin_crd(state: &AppState) {
        delete_crd(
            State(state.clone()),
            Path(FIN_CRD.to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete CRD");
    }

    #[tokio::test]
    async fn created_crd_carries_cleanup_finalizer() {
        let state = make_state();
        create_fin_crd(&state).await;
        let crd = stored_json(&state, &store_key(FIN_CRD)).await.unwrap();
        assert_eq!(
            crd["metadata"]["finalizers"],
            serde_json::json!([CLEANUP_FINALIZER]),
            "without the finalizer a CRD delete has no hook to remove its instances"
        );
    }

    #[tokio::test]
    async fn deleting_crd_removes_its_custom_resources() {
        let state = make_state();
        create_fin_crd(&state).await;
        let k1 = put_widget(&state, "w1", &[]).await;
        let k2 = put_widget(&state, "w2", &[]).await;

        delete_fin_crd(&state).await;

        assert!(
            stored_json(&state, &store_key(FIN_CRD)).await.is_none(),
            "CRD must be gone once its instances are removed"
        );
        for k in [k1, k2] {
            assert!(
                stored_json(&state, &k).await.is_none(),
                "instance {k} left behind would resurrect when a same-named CRD is re-created"
            );
        }
    }

    #[tokio::test]
    async fn crd_stays_terminating_while_an_instance_holds_a_finalizer() {
        let state = make_state();
        create_fin_crd(&state).await;
        let plain = put_widget(&state, "plain", &[]).await;
        let held = put_widget(&state, "held", &["example.com/hold"]).await;

        delete_fin_crd(&state).await;

        let crd = stored_json(&state, &store_key(FIN_CRD))
            .await
            .expect("CRD must survive until the instance finalizer is released");
        assert!(crd["metadata"]["deletionTimestamp"].is_string());
        let term = crd["status"]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"] == "Terminating")
            .expect("Terminating condition");
        assert_eq!(term["status"], "True");
        assert!(stored_json(&state, &plain).await.is_none());
        let held_obj = stored_json(&state, &held)
            .await
            .expect("held instance kept");
        assert!(
            held_obj["metadata"]["deletionTimestamp"].is_string(),
            "instance finalizers must be honored, not bypassed"
        );

        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "fin.io/v1", "kind": "Widget",
                "metadata": { "name": "held", "namespace": "default" },
            })
            .to_string(),
        );
        let err = crate::handlers::cr::create_cr_namespaced(
            State(state.clone()),
            Path((
                "fin.io".into(),
                "v1".into(),
                "default".into(),
                "widgets".into(),
            )),
            test_user(),
            HeaderMap::new(),
            body,
        )
        .await
        .err()
        .expect("create must be rejected while the CRD is terminating");
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        state.store.delete(&held, None).await.unwrap();
        finalize_crd(&state, FIN_CRD).await;
        assert!(
            stored_json(&state, &store_key(FIN_CRD)).await.is_none(),
            "CRD must complete deletion once no instances remain"
        );
    }

    /// `find_crd` caches a Terminating CRD's context too, so a CR request during the window
    /// between soft-delete and purge re-warms the key that soft-delete already evicted; a
    /// missed eviction at purge then keeps serving the deleted CRD's schema instead of 410.
    ///
    /// Fails on revert: without `evict_cr_context_cache` in `purge_crd`, the final `find_crd`
    /// returns the re-cached context instead of 410 Gone.
    #[tokio::test]
    async fn purge_evicts_context_recached_while_crd_was_terminating() {
        let state = make_state();
        create_fin_crd(&state).await;
        let held = put_widget(&state, "held", &["example.com/hold"]).await;
        delete_fin_crd(&state).await;

        let ctx = crate::handlers::cr::find_crd(&state, "fin.io", "v1", "widgets")
            .await
            .expect("a Terminating CRD is still found, re-warming cr_context_cache");
        assert!(
            ctx.terminating,
            "precondition: the cached CRD is Terminating"
        );

        state.store.delete(&held, None).await.unwrap();
        finalize_crd(&state, FIN_CRD).await;
        assert!(
            stored_json(&state, &store_key(FIN_CRD)).await.is_none(),
            "precondition: the CRD must be purged"
        );

        let err = match crate::handlers::cr::find_crd(&state, "fin.io", "v1", "widgets").await {
            Ok(_) => panic!("find_crd must not serve a stale CrContext for a purged CRD"),
            Err(e) => e,
        };
        assert_eq!(err.0, StatusCode::GONE);
    }

    #[tokio::test]
    async fn replace_does_not_clear_deletion_timestamp() {
        let state = make_state();
        create_fin_crd(&state).await;
        put_widget(&state, "held", &["example.com/hold"]).await;
        delete_fin_crd(&state).await;

        let mut body: serde_json::Value =
            serde_json::from_slice(&minimal_crd_bytes_with_group(FIN_CRD, "fin.io", "widgets"))
                .unwrap();
        body["metadata"]["finalizers"] = serde_json::json!([CLEANUP_FINALIZER]);
        replace_crd(
            State(state.clone()),
            Path(FIN_CRD.to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::from(body.to_string()),
        )
        .await
        .expect("replace");
        let crd = stored_json(&state, &store_key(FIN_CRD)).await.unwrap();
        assert!(
            crd["metadata"]["deletionTimestamp"].is_string(),
            "a client PUT must not un-terminate a CRD mid-finalization"
        );
    }

    /// Store double that counts `list` calls and can fail lists or deletes under a key
    /// prefix, delegating everything else to a real in-memory store.
    struct FaultStore {
        inner: std::sync::Arc<u7s_store::SqliteStore>,
        lists: std::sync::atomic::AtomicUsize,
        fail_list_prefix: std::sync::Mutex<Option<String>>,
        fail_delete_prefix: std::sync::Mutex<Option<String>>,
        /// Instance deletes succeed but report NotFound, as when another pass deleted first.
        vanish_on_delete: std::sync::atomic::AtomicBool,
    }

    impl FaultStore {
        fn new() -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                inner: std::sync::Arc::new(
                    u7s_store::SqliteStore::new(":memory:").expect("in-memory store"),
                ),
                lists: std::sync::atomic::AtomicUsize::new(0),
                fail_list_prefix: std::sync::Mutex::new(None),
                fail_delete_prefix: std::sync::Mutex::new(None),
                vanish_on_delete: std::sync::atomic::AtomicBool::new(false),
            })
        }

        fn list_count(&self) -> usize {
            self.lists.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn injected(_key: &str) -> StoreError {
        StoreError::Compacted {
            requested: 0,
            horizon: 0,
        }
    }

    impl Store for FaultStore {
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
            opts: ListOptions,
        ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send
        {
            self.lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let prefix: String = prefix.into();
            let fail = self
                .fail_list_prefix
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|p| prefix.starts_with(p.as_str()));
            async move {
                if fail {
                    return Err(injected(&prefix));
                }
                inner.list(&prefix, opts).await
            }
        }

        fn put(
            &self,
            key: impl Into<String> + Send,
            value: Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inner = self.inner.clone();
            let key: String = key.into();
            async move { inner.put(&key, value, expected_revision).await }
        }

        fn delete(
            &self,
            key: impl Into<String> + Send,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, Bytes)>> + Send {
            let inner = self.inner.clone();
            let key: String = key.into();
            let fail = self
                .fail_delete_prefix
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|p| key.starts_with(p.as_str()));
            let vanished = self
                .vanish_on_delete
                .load(std::sync::atomic::Ordering::SeqCst)
                && key.starts_with(FIN_CR_PREFIX);
            async move {
                if fail {
                    return Err(injected(&key));
                }
                let result = inner.delete(&key, expected_revision).await;
                if vanished {
                    return Err(StoreError::NotFound { key });
                }
                result
            }
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

    const FIN_CR_PREFIX: &str = "/registry/cr/fin.io/widgets/";

    fn fault_state() -> (std::sync::Arc<FaultStore>, AppState<FaultStore>) {
        let store = FaultStore::new();
        let state = AppState::new(
            store.clone(),
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        (store, state)
    }

    async fn terminating_condition(state: &AppState<FaultStore>) -> serde_json::Value {
        let crd = state
            .store
            .get(store_key(FIN_CRD))
            .await
            .unwrap()
            .map(|o| serde_json::from_slice::<serde_json::Value>(&o.value).unwrap())
            .expect("CRD must still exist");
        crd["status"]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"] == "Terminating")
            .cloned()
            .expect("Terminating condition")
    }

    async fn create_fin_crd_in(state: &AppState<FaultStore>) {
        create_crd(
            State(state.clone()),
            test_user(),
            HeaderMap::new(),
            minimal_crd_bytes_with_group(FIN_CRD, "fin.io", "widgets"),
        )
        .await
        .expect("create CRD");
    }

    async fn delete_fin_crd_in(state: &AppState<FaultStore>) {
        delete_crd(
            State(state.clone()),
            Path(FIN_CRD.to_string()),
            test_user(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete CRD");
    }

    #[tokio::test]
    async fn instance_list_failure_is_reported_as_instance_deletion_failed() {
        let (store, state) = fault_state();
        create_fin_crd_in(&state).await;
        *store.fail_list_prefix.lock().unwrap() = Some(FIN_CR_PREFIX.into());

        delete_fin_crd_in(&state).await;

        let cond = terminating_condition(&state).await;
        assert_eq!(cond["status"], "True");
        assert_eq!(
            cond["reason"], "InstanceDeletionFailed",
            "kubectl describe must show why a CRD is stuck Terminating"
        );
        assert!(cond["message"]
            .as_str()
            .unwrap()
            .starts_with("could not list instances:"));

        *store.fail_list_prefix.lock().unwrap() = None;
        finalize_crd(&state, FIN_CRD).await;
        assert!(
            state.store.get(store_key(FIN_CRD)).await.unwrap().is_none(),
            "finalization must recover once instances can be listed again"
        );
    }

    #[tokio::test]
    async fn instance_delete_failure_is_reported_as_instance_deletion_failed() {
        let (store, state) = fault_state();
        create_fin_crd_in(&state).await;
        let key = format!("{FIN_CR_PREFIX}default/w1");
        let obj = serde_json::json!({
            "apiVersion": "fin.io/v1", "kind": "Widget",
            "metadata": { "name": "w1", "namespace": "default" },
        });
        state
            .store
            .put(&key, Bytes::from(obj.to_string()), Some(0))
            .await
            .unwrap();
        *store.fail_delete_prefix.lock().unwrap() = Some(FIN_CR_PREFIX.into());

        delete_fin_crd_in(&state).await;

        let cond = terminating_condition(&state).await;
        assert_eq!(cond["status"], "True");
        assert_eq!(cond["reason"], "InstanceDeletionFailed");
        assert!(cond["message"]
            .as_str()
            .unwrap()
            .starts_with("could not issue all deletes:"));
    }

    #[tokio::test]
    async fn recovered_deletion_clears_the_failure_reason_while_instances_drain() {
        let (store, state) = fault_state();
        create_fin_crd_in(&state).await;
        let key = format!("{FIN_CR_PREFIX}default/held");
        let obj = serde_json::json!({
            "apiVersion": "fin.io/v1", "kind": "Widget",
            "metadata": { "name": "held", "namespace": "default", "finalizers": ["example.com/hold"] },
        });
        state
            .store
            .put(&key, Bytes::from(obj.to_string()), Some(0))
            .await
            .unwrap();
        *store.fail_list_prefix.lock().unwrap() = Some(FIN_CR_PREFIX.into());
        delete_fin_crd_in(&state).await;
        assert_eq!(
            terminating_condition(&state).await["reason"],
            "InstanceDeletionFailed"
        );

        *store.fail_list_prefix.lock().unwrap() = None;
        finalize_crd(&state, FIN_CRD).await;

        assert_eq!(
            terminating_condition(&state).await["reason"],
            "InstanceDeletionInProgress",
            "a stale failure reason would tell operators a recovered deletion is still broken"
        );
    }

    #[tokio::test]
    async fn finalizer_held_instances_report_instance_deletion_check() {
        let (_store, state) = fault_state();
        create_fin_crd_in(&state).await;
        let obj = serde_json::json!({
            "apiVersion": "fin.io/v1", "kind": "Widget",
            "metadata": {
                "name": "held", "namespace": "default",
                "finalizers": ["example.com/hold"],
            },
        });
        state
            .store
            .put(
                &format!("{FIN_CR_PREFIX}default/held"),
                Bytes::from(obj.to_string()),
                Some(0),
            )
            .await
            .expect("seed widget");
        delete_fin_crd_in(&state).await;
        assert_eq!(
            terminating_condition(&state).await["reason"],
            "InstanceDeletionInProgress",
            "the pass that issues deletes is still in progress"
        );

        finalize_crd(&state, FIN_CRD).await;

        let cond = terminating_condition(&state).await;
        assert_eq!(cond["status"], "True");
        assert_eq!(
            cond["reason"], "InstanceDeletionCheck",
            "operators must be told why the CRD is stuck: instances held by their own finalizers"
        );
        assert!(
            cond["message"]
                .as_str()
                .unwrap()
                .starts_with("could not confirm zero CustomResources remaining: "),
            "message must match upstream's wording, got {cond}"
        );
    }

    #[tokio::test]
    async fn instance_already_deleted_by_a_concurrent_pass_is_not_a_failure() {
        let (store, state) = fault_state();
        create_fin_crd_in(&state).await;
        let key = format!("{FIN_CR_PREFIX}default/w1");
        let obj = serde_json::json!({
            "apiVersion": "fin.io/v1", "kind": "Widget",
            "metadata": { "name": "w1", "namespace": "default" },
        });
        state
            .store
            .put(&key, Bytes::from(obj.to_string()), Some(0))
            .await
            .unwrap();
        store
            .vanish_on_delete
            .store(true, std::sync::atomic::Ordering::SeqCst);

        delete_fin_crd_in(&state).await;

        assert!(
            state.store.get(store_key(FIN_CRD)).await.unwrap().is_none(),
            "two finalizer passes racing on one instance must not wedge the CRD Terminating"
        );
    }

    #[tokio::test]
    async fn never_established_crd_is_removed_without_touching_instances() {
        let (_store, state) = fault_state();
        create_fin_crd_in(&state).await;
        let key = store_key(FIN_CRD);
        let stored = state.store.get(&key).await.unwrap().unwrap();
        let mut crd: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        crd["status"]["conditions"] = serde_json::json!([]);
        state
            .store
            .put(&key, Bytes::from(crd.to_string()), Some(stored.revision))
            .await
            .unwrap();
        let widget = format!("{FIN_CR_PREFIX}default/w1");
        let obj = serde_json::json!({
            "apiVersion": "fin.io/v1", "kind": "Widget",
            "metadata": { "name": "w1", "namespace": "default" },
        });
        state
            .store
            .put(&widget, Bytes::from(obj.to_string()), Some(0))
            .await
            .unwrap();

        delete_fin_crd_in(&state).await;

        assert!(state.store.get(&key).await.unwrap().is_none());
        assert!(
            state.store.get(&widget).await.unwrap().is_some(),
            "a CRD that was never established served no instances, so none may be deleted"
        );
    }

    #[tokio::test]
    async fn idle_finalizer_loop_scans_once_then_only_when_woken() {
        let scans = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake = std::sync::Arc::new(tokio::sync::Notify::new());
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let handle = {
            let scans = scans.clone();
            let wake = wake.clone();
            tokio::spawn(async move {
                run_crd_finalizer(&wake, &mut rx, std::time::Duration::from_millis(5), || {
                    scans.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    std::future::ready(0)
                })
                .await;
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            scans.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "with no Terminating CRD the loop must not poll: idle CPU/IO is budgeted"
        );
        wake.notify_one();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(scans.load(std::sync::atomic::Ordering::SeqCst), 2);
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn finalizer_loop_retries_while_a_crd_is_terminating() {
        let scans = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake = tokio::sync::Notify::new();
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let counter = scans.clone();
        let task = tokio::spawn(async move {
            run_crd_finalizer(&wake, &mut rx, std::time::Duration::from_millis(5), || {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::future::ready(1)
            })
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        tx.send(true).unwrap();
        task.await.unwrap();
        assert!(
            scans.load(std::sync::atomic::Ordering::SeqCst) > 3,
            "a CRD held by instance finalizers must keep being retried"
        );
    }

    #[tokio::test]
    async fn real_scan_does_no_store_list_when_idle() {
        let (store, state) = fault_state();
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let loop_state = state.clone();
        let task = tokio::spawn(async move {
            run_crd_finalizer(
                &loop_state.crd_finalizer_wake,
                &mut rx,
                std::time::Duration::from_millis(5),
                || reconcile_terminating_crds(&loop_state),
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            store.list_count(),
            1,
            "only the startup scan may list CRDs while none is Terminating"
        );
        tx.send(true).unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn crd_finalizes_after_instance_finalizer_is_released() {
        let state = make_state();
        create_fin_crd(&state).await;
        let held = put_widget(&state, "held", &["example.com/hold"]).await;
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let loop_state = state.clone();
        let task = tokio::spawn(async move {
            run_crd_finalizer(
                &loop_state.crd_finalizer_wake,
                &mut rx,
                std::time::Duration::from_secs(3600),
                || reconcile_terminating_crds(&loop_state),
            )
            .await;
        });
        delete_fin_crd(&state).await;
        assert!(stored_json(&state, &store_key(FIN_CRD)).await.is_some());

        let mut body = stored_json(&state, &held).await.expect("held instance");
        body["metadata"]["finalizers"] = serde_json::json!([]);
        crate::handlers::cr::replace_cr_namespaced(
            State(state.clone()),
            Path((
                "fin.io".into(),
                "v1".into(),
                "default".into(),
                "widgets".into(),
                "held".into(),
            )),
            test_user(),
            HeaderMap::new(),
            Bytes::from(body.to_string()),
        )
        .await
        .unwrap_or_else(|e| panic!("release finalizer: {e:?}"));

        let mut gone = false;
        for _ in 0..100 {
            if stored_json(&state, &store_key(FIN_CRD)).await.is_none() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        tx.send(true).unwrap();
        task.await.unwrap();
        assert!(
            gone,
            "releasing the last instance finalizer must wake the finalizer without waiting \
             for a poll, or `kubectl delete crd` hangs"
        );
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::tests::minimal_crd_bytes_with_group;
    use super::*;
    use crate::handlers::test_support::make_state;
    use axum::http::{header, HeaderValue};

    const NAME: &str = "widgets.example.com";

    fn user() -> axum::Extension<UserInfo> {
        axum::Extension(UserInfo {
            username: "admin".into(),
            ..Default::default()
        })
    }

    fn headers(content_type: &'static str, user_agent: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        h.insert(header::USER_AGENT, HeaderValue::from_static(user_agent));
        h
    }

    async fn stored(state: &AppState<u7s_store::SqliteStore>) -> serde_json::Value {
        let s = state.store.get(&store_key(NAME)).await.unwrap().unwrap();
        serde_json::from_slice(&s.value).unwrap()
    }

    fn owner<'a>(
        obj: &'a serde_json::Value,
        manager: &str,
        subresource: Option<&str>,
    ) -> Option<&'a serde_json::Value> {
        obj["metadata"]["managedFields"]
            .as_array()?
            .iter()
            .find(|m| m["manager"] == manager && m["subresource"].as_str() == subresource)
    }

    async fn seed(state: &AppState<u7s_store::SqliteStore>) {
        create_crd(
            axum::extract::State(state.clone()),
            user(),
            headers("application/json", "creator/1.0"),
            minimal_crd_bytes_with_group(NAME, "example.com", "widgets"),
        )
        .await
        .map_err(|_| ())
        .expect("create");
    }

    /// Every non-apply CRD write must name its writer in managedFields, or a later apply by
    /// another tool sees no owner for the field and overwrites or deletes it unchallenged.
    #[tokio::test]
    async fn crd_create_replace_patch_and_status_writes_record_their_writer() {
        let state = make_state();
        seed(&state).await;
        let created = stored(&state).await;
        let m = owner(&created, "creator", None).expect("create recorded");
        assert_eq!(m["operation"], "Update");

        let mut put = created.clone();
        put["metadata"]["labels"] = serde_json::json!({"via": "put"});
        replace_crd(
            axum::extract::State(state.clone()),
            Path(NAME.to_string()),
            user(),
            headers("application/json", "put-tool/1.0"),
            Bytes::from(put.to_string()),
        )
        .await
        .map_err(|_| ())
        .expect("replace");
        let after_put = stored(&state).await;
        assert!(
            owner(&after_put, "put-tool", None)
                .is_some_and(|m| m["fieldsV1"]["f:metadata"]["f:labels"].is_object()),
            "PUT must own the label it set: {after_put}"
        );

        patch_crd(
            axum::extract::State(state.clone()),
            Path(NAME.to_string()),
            user(),
            headers("application/merge-patch+json", "patch-tool/1.0"),
            Bytes::from(r#"{"metadata":{"annotations":{"a":"b"}}}"#),
        )
        .await
        .map_err(|_| ())
        .expect("patch");
        let after_patch = stored(&state).await;
        assert!(
            owner(&after_patch, "patch-tool", None)
                .is_some_and(|m| m["fieldsV1"]["f:metadata"]["f:annotations"].is_object()),
            "merge patch must own the annotation it set: {after_patch}"
        );
        assert!(
            owner(&after_patch, "put-tool", None).is_some(),
            "a later write must not wipe earlier owners"
        );

        let mut status = after_patch.clone();
        status["status"] = serde_json::json!({"conditions": [
            {"type": "Established", "status": "False", "reason": "Test"}]});
        put_crd_status(
            axum::extract::State(state.clone()),
            Path(NAME.to_string()),
            None,
            headers("application/json", "crd-controller/1.0"),
            Bytes::from(status.to_string()),
        )
        .await
        .map_err(|_| ())
        .expect("status put");
        assert!(owner(&stored(&state).await, "crd-controller", Some("status")).is_some());

        patch_crd_status(
            axum::extract::State(state.clone()),
            Path(NAME.to_string()),
            None,
            headers("application/merge-patch+json", "status-patcher/1.0"),
            Bytes::from(r#"{"status":{"storedVersions":["v1alpha1"]}}"#),
        )
        .await
        .map_err(|_| ())
        .expect("status patch");
        assert!(owner(&stored(&state).await, "status-patcher", Some("status")).is_some());
    }

    /// A client-supplied managedFields on an apply must not overwrite the server's record.
    #[tokio::test]
    async fn crd_apply_ignores_client_supplied_managed_fields() {
        let state = make_state();
        seed(&state).await;
        let body = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": NAME, "managedFields": [
                {"manager": "forged", "operation": "Update", "apiVersion": "v1",
                 "fieldsType": "FieldsV1", "fieldsV1": {"f:metadata": {"f:labels": {}}}}]}
        });
        patch_crd(
            axum::extract::State(state.clone()),
            Path(NAME.to_string()),
            user(),
            headers("application/apply-patch+yaml", "applier/1.0"),
            Bytes::from(body.to_string()),
        )
        .await
        .map_err(|_| ())
        .expect("apply");
        let after = stored(&state).await;
        assert!(owner(&after, "forged", None).is_none(), "{after}");
        assert!(owner(&after, "creator", None).is_some(), "{after}");
    }
}
