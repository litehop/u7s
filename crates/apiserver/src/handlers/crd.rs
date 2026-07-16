use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use u7s_store::{ListOptions, Store, StoreError};

use crate::handlers::json_patch::{
    apply_json_patch, detect_patch_type, ssa_body_to_json, PatchType,
};
use crate::{
    admission::{run_mutating_webhooks, run_validating_webhooks, AdmissionContext},
    auth::UserInfo,
    state::AppState,
    status::Status,
    types::Object,
    util::{content_type, extract_body, parse_resource_version, utc_now_rfc3339},
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_crd(body: &Bytes) -> Result<CustomResourceDefinition, crate::status::StatusError> {
    serde_json::from_slice(body)
        .map_err(|e| Status::unprocessable_entity(format!("invalid CustomResourceDefinition: {e}")))
}

fn store_err_crd(err: StoreError, name: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, KIND),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, KIND),
        other => Status::internal(other.to_string()),
    }
}

fn stamp_server_fields(crd: &mut CustomResourceDefinition) {
    if crd.metadata.uid.is_empty() {
        crd.metadata.uid = new_uid();
    }
    if crd.metadata.creation_timestamp.is_empty() {
        crd.metadata.creation_timestamp = utc_now_rfc3339();
    }
    crd.api_version = API_VERSION.to_string();
    crd.kind = KIND.to_string();
}

fn new_uid() -> String {
    // Use UUIDv4 (CSPRNG) for uid generation. The previous implementation
    // formatted system time as hex — two CRDs created in the same nanosecond
    // would collide, and the value was predictable (no entropy). Kubernetes
    // expects UIDs in UUID string format (RFC 4122).
    uuid::Uuid::new_v4().to_string()
}

fn to_bytes(crd: &CustomResourceDefinition) -> Result<Bytes, crate::status::StatusError> {
    serde_json::to_vec(crd)
        .map(Bytes::from)
        .map_err(|e| Status::internal(e.to_string()))
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

    let store_field_selector = query
        .field_selector
        .as_deref()
        .map(super::generic::parse_field_selector)
        .transpose()?;
    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                field_selector: store_field_selector,
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
    let body = extract_body(&body, ct);
    let mut crd = parse_crd(&body)?;

    let name = crd.metadata.name.clone();
    if name.is_empty() {
        return Err(Status::unprocessable_entity(
            "metadata.name is required".into(),
        ));
    }

    validate_crd_group(&crd.spec.group)?;

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
            name: &name,
            namespace: None,
            operation: "CREATE",
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
            })),
            dry_run: false,
        };
        let obj_val = serde_json::to_value(&crd).map_err(|e| Status::internal(e.to_string()))?;
        let mutated = run_mutating_webhooks(&state, obj_val, None, &admission_ctx).await?;
        run_validating_webhooks(&state, &mutated, None, &admission_ctx).await?;
        crd = serde_json::from_value(mutated)
            .map_err(|e| Status::internal(format!("admission mutated CRD is invalid: {e}")))?;
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

    let key = store_key(&name);
    let rv = state
        .store
        .put(&key, to_bytes(&crd)?, Some(0))
        .await
        .map_err(|e| store_err_crd(e, &name))?;

    let tombstone_key = deleted_group_tombstone_key(&crd.spec.group);
    let _ = state.store.delete(&tombstone_key, None).await;

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
        .ok_or_else(|| Status::not_found(&name, KIND))?;

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
    let body = extract_body(&body, ct);
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
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    // Preserve server-assigned fields from stored copy if not present in incoming.
    if crd.metadata.uid.is_empty() || crd.metadata.creation_timestamp.is_empty() {
        let existing: serde_json::Value =
            serde_json::from_slice(&stored.value).unwrap_or(serde_json::Value::Null);
        if crd.metadata.uid.is_empty() {
            if let Some(uid) = existing["metadata"]["uid"].as_str() {
                crd.metadata.uid = uid.to_string();
            }
        }
        if crd.metadata.creation_timestamp.is_empty() {
            if let Some(ts) = existing["metadata"]["creationTimestamp"].as_str() {
                crd.metadata.creation_timestamp = ts.to_string();
            }
        }
    }

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
            })),
            dry_run: false,
        };
        let obj_val = serde_json::to_value(&crd).map_err(|e| Status::internal(e.to_string()))?;
        let mutated = run_mutating_webhooks(&state, obj_val, None, &admission_ctx).await?;
        run_validating_webhooks(&state, &mutated, None, &admission_ctx).await?;
        crd = serde_json::from_value(mutated)
            .map_err(|e| Status::internal(format!("admission mutated CRD is invalid: {e}")))?;
    }

    let rv = state
        .store
        .put(&key, to_bytes(&crd)?, expected_rv)
        .await
        .map_err(|e| store_err_crd(e, &name))?;

    // Clear any stale tombstone for this group. Without this, a CRD deleted then
    // re-created via PUT (replace_crd) would leave a tombstone in the store — mirroring
    // the tombstone-clear that create_crd (POST) already does at crd.rs:362-363.
    let tombstone_key = deleted_group_tombstone_key(&crd.spec.group);
    let _ = state.store.delete(&tombstone_key, None).await;

    crd.metadata.resource_version = rv.to_string();
    Ok(Json(crd))
}

pub async fn delete_crd<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let key = store_key(&name);

    // Check existence first to return 404 rather than a store error.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    // Parse once: used both for the tombstone's group below and as the admission review object.
    let existing: serde_json::Value =
        serde_json::from_slice(&stored.value).unwrap_or(serde_json::Value::Null);
    let group: String = existing["spec"]["group"]
        .as_str()
        .unwrap_or_default()
        .to_string();

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
        })),
        dry_run: false,
    };
    run_validating_webhooks(&state, &existing, Some(&existing), &admission_ctx).await?;

    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err_crd(e, &name))?;

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

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
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
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let prefix = list_prefix();
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
        if name.is_empty() {
            continue;
        }
        if let Some(ref pairs) = label_pairs {
            if super::generic::apply_label_selector(vec![parsed], pairs).is_empty() {
                continue;
            }
        }
        delete_crd(State(state.clone()), Path(name), Extension(user.clone())).await?;
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
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    let mut current: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    // apply-patch+yaml bodies are genuine YAML (e.g. kubectl apply --server-side); every
    // other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::unprocessable_entity(format!("invalid patch: {e}")))?
    };

    match patch_type {
        PatchType::Merge | PatchType::StrategicMerge => {
            crate::patch::merge_patch(&mut current, &patch);
        }
        PatchType::Json => {
            apply_json_patch(&mut current, &patch)?;
        }
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
            })),
            dry_run: false,
        };
        let obj_val = serde_json::to_value(&crd).map_err(|e| Status::internal(e.to_string()))?;
        let mutated = run_mutating_webhooks(&state, obj_val, None, &admission_ctx).await?;
        run_validating_webhooks(&state, &mutated, None, &admission_ctx).await?;
        crd = serde_json::from_value(mutated)
            .map_err(|e| Status::internal(format!("admission mutated CRD is invalid: {e}")))?;
    }

    let rv = state
        .store
        .put(&key, to_bytes(&crd)?, None)
        .await
        .map_err(|e| store_err_crd(e, &name))?;

    crd.metadata.resource_version = rv.to_string();
    Ok(Json(crd))
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

/// PUT /apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}/status
///
/// Replaces only the status field. Without this route, status requests fell through
/// to the generic CR catch-all, which searched for a CRD-of-CRDs that can never exist
/// and returned 404 — so controllers gating on CRD readiness (Established, NamesAccepted)
/// could never observe or set those conditions.
pub async fn put_crd_status<S: Store>(
    State(state): State<AppState<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let incoming =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = store_key(&name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    match &incoming.body["status"] {
        serde_json::Value::Null => {
            current.body.as_object_mut().map(|m| m.remove("status"));
        }
        v => {
            current.body["status"] = v.clone();
        }
    }

    crate::handlers::status::merge_incoming_metadata(&mut current.body, &incoming.body);

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
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // apply-patch+yaml bodies are genuine YAML (e.g. kubectl apply --server-side status);
    // every other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
    };

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
                                .map_err(|e| Status::bad_request(e.to_string()))?;
                        }
                        PatchType::Json => unreachable!(),
                    }
                }
            }
            crate::handlers::status::merge_incoming_metadata(&mut current.body, &patch);
        }
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
    use std::sync::Arc;
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

    fn minimal_crd_bytes_with_group(name: &str, group: &str, plural: &str) -> Bytes {
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

    // stamp_server_fields must not overwrite existing uid/timestamp.
    #[test]
    fn stamp_server_fields_preserves_existing() {
        let body = minimal_crd_bytes("foo.example.com");
        let mut crd = ok_crd(parse_crd(&body));
        crd.metadata.uid = "my-uid".into();
        crd.metadata.creation_timestamp = "2024-01-01T00:00:00Z".into();

        stamp_server_fields(&mut crd);

        assert_eq!(crd.metadata.uid, "my-uid");
        assert_eq!(crd.metadata.creation_timestamp, "2024-01-01T00:00:00Z");
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
        delete_collection_crds(State(state.clone()), query, test_user())
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

        let resp = patch_crd_status(State(state), Path(name.to_string()), headers, patch_bytes)
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

        let resp = patch_crd_status(State(state), Path(name.to_string()), headers, patch_bytes)
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

        let err = match patch_crd_status(State(state), Path(name.to_string()), headers, patch_bytes)
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

        let resp = patch_crd_status(State(state), Path(name.to_string()), headers, patch_bytes)
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
        let err = match patch_crd_status(State(state), Path(name.to_string()), headers, patch_body)
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

        delete_crd(State(state.clone()), Path(name.to_string()), test_user())
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
}

// ---------------------------------------------------------------------------
// Admission regression tests — prove create_crd / replace_crd invoke the
// admission webhook pipeline (mayor-8sn9).
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
    use crate::state::AppState;

    fn make_state(store: Arc<SqliteStore>) -> AppState {
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

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
