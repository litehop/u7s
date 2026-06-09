use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store};

use crate::{
    handlers::crd::{deleted_group_tombstone_key, CustomResourceDefinition},
    keys::cluster_object_key,
    state::AppState,
    status::Status,
    util::{extract_body, parse_resource_version, utc_now_rfc3339},
};

const CRD_LIST_PREFIX: &str = "/registry/apiextensions.k8s.io/customresourcedefinitions/";

// ---------------------------------------------------------------------------
// CRD conversion webhook
// ---------------------------------------------------------------------------

/// Call the CRD conversion webhook with a set of objects and a desired API version.
///
/// The ConversionReview protocol (apiextensions.k8s.io/v1):
///   request.objects      — the stored objects to convert
///   request.desiredAPIVersion — the target version (e.g. "example.com/v2")
///   response.convertedObjects — the converted objects returned by the webhook
///
/// Returns the converted objects on success, or an error if the webhook fails or
/// the response is malformed.
pub(crate) async fn call_conversion_webhook<S: Store>(
    state: &AppState<S>,
    client_config: &serde_json::Value,
    objects: Vec<serde_json::Value>,
    desired_api_version: &str,
) -> Result<Vec<serde_json::Value>, crate::status::StatusError> {
    // Resolve the URL from the clientConfig (same logic as admission webhook).
    let url = resolve_conversion_webhook_url(state, client_config).await?;

    let uid = uuid::Uuid::new_v4().to_string();
    let review = serde_json::json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "ConversionReview",
        "request": {
            "uid": uid,
            "desiredAPIVersion": desired_api_version,
            "objects": objects
        }
    });

    let body = serde_json::to_vec(&review).map_err(|e| Status::internal(e.to_string()))?;
    let resp = state
        .webhook_client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| Status::internal(format!("conversion webhook call failed: {e}")))?;

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| Status::internal(format!("conversion webhook response read error: {e}")))?;

    let resp_val: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        Status::internal(format!("conversion webhook response JSON parse error: {e}"))
    })?;

    // Check result status.
    let result_status = resp_val["response"]["result"]["status"]
        .as_str()
        .unwrap_or("Failure");
    if result_status != "Success" {
        let msg = resp_val["response"]["result"]["message"]
            .as_str()
            .unwrap_or("conversion webhook returned failure");
        return Err(Status::internal(format!(
            "conversion webhook failed: {msg}"
        )));
    }

    let converted = resp_val["response"]["convertedObjects"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    if converted.is_empty() {
        return Err(Status::internal(
            "conversion webhook returned no converted objects".into(),
        ));
    }

    Ok(converted)
}

/// Resolve the conversion webhook URL from a clientConfig object.
///
/// Supports both `url` (direct URL) and `service` (in-cluster service reference).
async fn resolve_conversion_webhook_url<S: Store>(
    state: &AppState<S>,
    client_config: &serde_json::Value,
) -> Result<String, crate::status::StatusError> {
    if let Some(url) = client_config["url"].as_str() {
        return Ok(url.to_string());
    }

    if let Some(svc) = client_config.get("service").filter(|s| !s.is_null()) {
        let ns = svc["namespace"].as_str().unwrap_or("default");
        let name = svc["name"]
            .as_str()
            .ok_or_else(|| Status::internal("conversion webhook service has no name".into()))?;
        let port = svc["port"].as_u64().unwrap_or(443);
        let path = svc["path"].as_str().unwrap_or("/");

        let key = format!("/registry/services/{ns}/{name}");
        let obj = state
            .store
            .get(&key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::internal(format!("conversion webhook service {ns}/{name} not found"))
            })?;

        let val: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;

        let cluster_ip = val["spec"]["clusterIP"].as_str().ok_or_else(|| {
            Status::internal(format!(
                "conversion webhook service {ns}/{name} has no clusterIP"
            ))
        })?;

        return Ok(format!("https://{cluster_ip}:{port}{path}"));
    }

    Err(Status::internal(
        "conversion webhook clientConfig has neither url nor service".into(),
    ))
}

// ---------------------------------------------------------------------------
// CRD lookup
// ---------------------------------------------------------------------------

/// Information extracted from a CRD needed to serve a CR request.
pub struct CrContext {
    pub kind: String,
    pub namespaced: bool,
    /// True when at least one served version declares `subresources: {status: {}}`.
    /// Controls whether the main PUT/PATCH endpoint strips `.status` and whether
    /// the `/status` subresource endpoint is active.
    pub has_status_subresource: bool,
    /// The `openAPIV3Schema` from the matched version's schema field, if present.
    /// Used for server-side CR body validation on CREATE and UPDATE.
    pub schema: Option<serde_json::Value>,
    /// The storage version name (the CRD version with `storage: true`).
    /// Objects are stored in the store under this version's key.
    pub storage_version: String,
    /// Conversion configuration from the CRD spec. Present only when
    /// `spec.conversion.strategy == "Webhook"`.
    pub conversion_webhook_client_config: Option<serde_json::Value>,
}

/// Find the CRD whose spec.group == group and spec.names.plural == plural.
///
/// Returns:
/// - `Ok(CrContext)` when a matching, served CRD is found.
/// - `Err(410 Gone)` when the group was registered but its CRD has been deleted.
///   This signals informers (client-go reflector) to stop watching and clean up.
///   Without 410, informers treat the response as a transient 404 and retry
///   indefinitely, causing namespace deletion to hang.
/// - `Err(404 NotFound)` when the group/version/plural was never registered.
pub async fn find_crd<S: Store>(
    state: &AppState<S>,
    group: &str,
    version: &str,
    plural: &str,
) -> Result<CrContext, crate::status::StatusError> {
    let prefix = CRD_LIST_PREFIX;
    let resp = state
        .store
        .list(prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    for obj in &resp.items {
        let crd: CustomResourceDefinition = match serde_json::from_slice(&obj.value) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if crd.spec.group != group || crd.spec.names.plural != plural {
            continue;
        }
        // Matching group + plural. Now check version is served.
        let Some(matched_version) = crd
            .spec
            .versions
            .iter()
            .find(|v| v.name == version && v.served)
        else {
            return Err(Status::not_found(
                &format!("{group}/{version}/{plural}"),
                "Resource",
            ));
        };
        // Extract openAPIV3Schema from the matched version's schema field.
        let schema = matched_version
            .schema
            .as_ref()
            .and_then(|s| s.get("openAPIV3Schema"))
            .cloned();
        let namespaced = crd.spec.scope == "Namespaced";
        // A version has a status subresource when `subresources.status` is present
        // and non-null in the CRD spec. Check all versions; if any declares it, the
        // resource has a status subresource (all served versions must agree in practice).
        let has_status_subresource = crd.spec.versions.iter().any(|v| {
            v.subresources
                .as_ref()
                .and_then(|s| s.get("status"))
                .map(|st| !st.is_null())
                .unwrap_or(false)
        });
        // Find the storage version (exactly one version should have storage: true).
        let storage_version = crd
            .spec
            .versions
            .iter()
            .find(|v| v.storage)
            .map(|v| v.name.clone())
            .unwrap_or_else(|| version.to_string());
        // Extract conversion webhook clientConfig if strategy is Webhook.
        let conversion_webhook_client_config = crd
            .spec
            .conversion
            .as_ref()
            .filter(|c| c["strategy"].as_str() == Some("Webhook"))
            .and_then(|c| c["webhook"]["clientConfig"].as_object())
            .map(|cfg| serde_json::Value::Object(cfg.clone()));
        return Ok(CrContext {
            kind: crd.spec.names.kind.clone(),
            namespaced,
            has_status_subresource,
            schema,
            storage_version,
            conversion_webhook_client_config,
        });
    }

    // No live CRD found. Check whether this group was previously deleted.
    // If a tombstone exists, return 410 Gone so informers stop retrying.
    let tombstone_key = deleted_group_tombstone_key(group);
    let tombstone_exists = state
        .store
        .get(&tombstone_key)
        .await
        .unwrap_or(None)
        .is_some();

    if tombstone_exists {
        return Err(Status::gone(format!(
            "the custom resource definition for {group}/{version}/{plural} has been deleted"
        )));
    }

    Err(Status::not_found(
        &format!("{group}/{version}/{plural}"),
        "Resource",
    ))
}

// ---------------------------------------------------------------------------
// Store key helpers
// ---------------------------------------------------------------------------

fn cr_store_key(
    group: &str,
    version: &str,
    plural: &str,
    namespace: Option<&str>,
    name: &str,
) -> String {
    match namespace {
        Some(ns) => format!("/registry/cr/{group}/{version}/{plural}/{ns}/{name}"),
        None => format!("/registry/cr/{group}/{version}/{plural}/{name}"),
    }
}

fn cr_list_prefix(group: &str, version: &str, plural: &str, namespace: Option<&str>) -> String {
    match namespace {
        Some(ns) => format!("/registry/cr/{group}/{version}/{plural}/{ns}/"),
        None => format!("/registry/cr/{group}/{version}/{plural}/"),
    }
}

// ---------------------------------------------------------------------------
// Metadata stamping on create
// ---------------------------------------------------------------------------

fn stamp_cr_fields(obj: &mut serde_json::Value, group: &str, version: &str, kind: &str) {
    let api_version = format!("{group}/{version}");
    obj["apiVersion"] = serde_json::Value::String(api_version);
    obj["kind"] = serde_json::Value::String(kind.to_string());
    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    if meta.uid.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
        meta.uid = Some(new_cr_uid());
    }
    if meta
        .creation_timestamp
        .as_deref()
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        meta.creation_timestamp = Some(utc_now_rfc3339());
    }
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
}

fn validate_cr_name(name: &str) -> Result<(), crate::status::StatusError> {
    if name.is_empty() {
        return Err(Status::bad_request(
            "metadata.name must not be empty".into(),
        ));
    }
    // DNS label: lowercase alphanumeric and hyphens, must start/end with alphanumeric.
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(Status::bad_request(format!(
            "metadata.name \"{name}\" contains invalid characters (must be a DNS label)"
        )));
    }
    Ok(())
}

fn resolve_cr_metadata(stored: &serde_json::Value, incoming: &mut serde_json::Value) {
    let stored_meta: crate::types::ObjectMeta =
        serde_json::from_value(stored["metadata"].clone()).unwrap_or_default();
    let mut incoming_meta: crate::types::ObjectMeta =
        serde_json::from_value(incoming["metadata"].take()).unwrap_or_default();
    if incoming_meta
        .uid
        .as_deref()
        .map(|s| s.is_empty())
        .unwrap_or(true)
        && stored_meta.uid.is_some()
    {
        incoming_meta.uid = stored_meta.uid;
    }
    if incoming_meta
        .creation_timestamp
        .as_deref()
        .map(|s| s.is_empty())
        .unwrap_or(true)
        && stored_meta.creation_timestamp.is_some()
    {
        incoming_meta.creation_timestamp = stored_meta.creation_timestamp;
    }
    incoming["metadata"] = serde_json::to_value(incoming_meta).unwrap_or_default();
}

fn new_cr_uid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn store_err_cr(err: u7s_store::StoreError, name: &str, kind: &str) -> crate::status::StatusError {
    match err {
        u7s_store::StoreError::NotFound { .. } => Status::not_found(name, kind),
        u7s_store::StoreError::AlreadyExists { .. } => Status::already_exists(name, kind),
        u7s_store::StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "{kind} \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => Status::internal(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// openAPIV3Schema validation
// ---------------------------------------------------------------------------

/// Validate `obj` against the CRD schema in `ctx`, if a schema is present.
/// Uses boon for full openAPIV3Schema keyword coverage (enum, pattern, minimum,
/// maximum, format, items, oneOf, allOf, etc.).
/// Returns `Err(StatusError)` with HTTP 422 if validation fails.
fn validate_cr_schema(
    obj: &serde_json::Value,
    ctx: &CrContext,
) -> Result<(), crate::status::StatusError> {
    let Some(schema) = &ctx.schema else {
        return Ok(());
    };
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler
        .add_resource("schema.json", schema.clone())
        .map_err(|e| Status::internal(e.to_string()))?;
    let idx = compiler
        .compile("schema.json", &mut schemas)
        .map_err(|e| Status::internal(e.to_string()))?;
    schemas
        .validate(obj, idx)
        .map_err(|e| Status::unprocessable_entity(format!("CR schema validation failed: {e}")))
}

// ---------------------------------------------------------------------------
// Cluster-scoped CR handlers
// ---------------------------------------------------------------------------

/// Detect whether the Accept header requests PartialObjectMetadata or PartialObjectMetadataList.
/// The kcm metadatainformer sends Accept headers like:
///   application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,
///   application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json
fn wants_partial_object_metadata(accept: &str) -> bool {
    accept.contains("as=PartialObjectMetadata")
}

/// Strip spec/status from a full CR object, returning a PartialObjectMetadata-shaped value.
/// The GC only needs metadata (ownerReferences, finalizers, etc.) — spec/status are omitted.
fn to_partial_object_metadata(obj: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "PartialObjectMetadata",
        "metadata": obj.get("metadata").cloned().unwrap_or_default()
    })
}

pub async fn list_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural)): Path<(String, String, String)>,
    headers: axum::http::HeaderMap,
    query: super::generic::CollectionQuery,
    username: String,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    // When version != storage_version, list from the storage version's key prefix.
    // Watch streams are not converted (watch conversion is out of scope).
    let (list_version, needs_conversion) = if version != ctx.storage_version {
        (
            ctx.storage_version.as_str(),
            ctx.conversion_webhook_client_config.is_some(),
        )
    } else {
        (version.as_str(), false)
    };

    // For namespaced CRDs, the cluster-wide path lists across all namespaces.
    // Namespaced CRs are stored as /registry/cr/{group}/{version}/{plural}/{ns}/{name},
    // so prefix without namespace matches all of them.
    let prefix = cr_list_prefix(&group, list_version, &plural, None);

    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pom = wants_partial_object_metadata(accept);

    if query.watch == Some(true) {
        let (watch_api_version, watch_kind) = if pom {
            (
                "meta.k8s.io/v1".to_string(),
                "PartialObjectMetadata".to_string(),
            )
        } else {
            (format!("{group}/{version}"), ctx.kind.clone())
        };
        let initial_items = super::watch::fetch_initial_events(
            &state,
            &prefix,
            query.send_initial_events == Some(true),
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
                username,
                as_partial_object_metadata: pom,
                group: group.clone(),
                plural: plural.clone(),
                timeout_seconds: query.timeout_seconds,
            },
        )
        .await;
    }

    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut items: Vec<serde_json::Value> = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(v);
    }

    // Convert all items if needed. Batch the conversion in a single webhook call.
    if needs_conversion && !items.is_empty() {
        if let Some(cfg) = ctx.conversion_webhook_client_config.as_ref() {
            let desired_api_version = format!("{group}/{version}");
            items = call_conversion_webhook(&state, cfg, items, &desired_api_version).await?;
        }
    }

    if pom {
        let pom_items: Vec<serde_json::Value> =
            items.iter().map(to_partial_object_metadata).collect();
        let body = serde_json::json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": resp.revision.to_string() },
            "items": pom_items
        });
        return Ok(Json(body).into_response());
    }

    let body = super::generic::build_list_response(
        &ctx.kind,
        &group,
        &version,
        resp.revision,
        items,
        resp.continue_key,
        resp.remaining_count,
        &state.continue_token_key,
    );
    Ok(Json(body).into_response())
}

pub async fn get_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    // When version != storage_version, fall back to the storage version key.
    // If a conversion webhook is configured, call it; otherwise return as-is.
    let (fetch_version, needs_conversion) = if version != ctx.storage_version {
        (
            ctx.storage_version.as_str(),
            ctx.conversion_webhook_client_config.is_some(),
        )
    } else {
        (version.as_str(), false)
    };

    let key = cr_store_key(&group, fetch_version, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    if needs_conversion {
        if let Some(cfg) = ctx.conversion_webhook_client_config.as_ref() {
            let obj: serde_json::Value = serde_json::from_slice(&stored.value)
                .map_err(|e| Status::internal(e.to_string()))?;
            let desired_api_version = format!("{group}/{version}");
            let mut converted =
                call_conversion_webhook(&state, cfg, vec![obj], &desired_api_version).await?;
            let converted_obj = converted
                .pop()
                .ok_or_else(|| Status::internal("conversion webhook returned no objects".into()))?;
            let bytes =
                serde_json::to_vec(&converted_obj).map_err(|e| Status::internal(e.to_string()))?;
            return Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                bytes,
            )
                .into_response());
        }
    }

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn create_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let mut wrapped = crate::types::Object { body: obj };
    let name = crate::handlers::generic::resolve_name(&mut wrapped)?;
    let mut obj = wrapped.body;
    validate_cr_name(&name)?;

    validate_cr_schema(&obj, &ctx)?;

    stamp_cr_fields(&mut obj, &group, &version, &ctx.kind);

    let key = cr_store_key(&group, &version, &plural, None, &name);
    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let rv = state
        .store
        .put(&key, Bytes::from(bytes), Some(0))
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    Ok((StatusCode::CREATED, Json(obj)))
}

pub async fn replace_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].clone()).unwrap_or_default();
    let obj_name = obj_meta.name.as_deref().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let key = cr_store_key(&group, &version, &plural, None, &name);

    // Must exist before replace.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    // Preserve uid + creationTimestamp from stored.
    let existing: serde_json::Value =
        serde_json::from_slice(&stored.value).unwrap_or(serde_json::Value::Null);
    resolve_cr_metadata(&existing, &mut obj);

    // When the CRD declares a status subresource, the main PUT endpoint must not
    // update .status — clients must use PUT /status for that.
    if ctx.has_status_subresource {
        if let Some(map) = obj.as_object_mut() {
            map.remove("status");
        }
    }

    validate_cr_schema(&obj, &ctx)?;

    let meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].clone()).unwrap_or_default();
    let expected_rv = parse_resource_version(meta.resource_version.as_deref())?;

    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let rv = state
        .store
        .put(&key, Bytes::from(bytes), expected_rv)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    Ok(Json(obj))
}

pub async fn delete_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let key = cr_store_key(&group, &version, &plural, None, &name);

    let _ = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

// ---------------------------------------------------------------------------
// Namespaced CR handlers
// ---------------------------------------------------------------------------

pub async fn list_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    headers: axum::http::HeaderMap,
    query: super::generic::CollectionQuery,
    username: String,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let (list_version, needs_conversion) = if version != ctx.storage_version {
        (
            ctx.storage_version.as_str(),
            ctx.conversion_webhook_client_config.is_some(),
        )
    } else {
        (version.as_str(), false)
    };

    let prefix = cr_list_prefix(&group, list_version, &plural, Some(&ns));

    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pom = wants_partial_object_metadata(accept);

    if query.watch == Some(true) {
        let (watch_api_version, watch_kind) = if pom {
            (
                "meta.k8s.io/v1".to_string(),
                "PartialObjectMetadata".to_string(),
            )
        } else {
            (format!("{group}/{version}"), ctx.kind.clone())
        };
        let initial_items = super::watch::fetch_initial_events(
            &state,
            &prefix,
            query.send_initial_events == Some(true),
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
                username,
                as_partial_object_metadata: pom,
                group: group.clone(),
                plural: plural.clone(),
                timeout_seconds: query.timeout_seconds,
            },
        )
        .await;
    }

    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut items: Vec<serde_json::Value> = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(v);
    }

    if needs_conversion && !items.is_empty() {
        if let Some(cfg) = ctx.conversion_webhook_client_config.as_ref() {
            let desired_api_version = format!("{group}/{version}");
            items = call_conversion_webhook(&state, cfg, items, &desired_api_version).await?;
        }
    }

    if pom {
        let pom_items: Vec<serde_json::Value> =
            items.iter().map(to_partial_object_metadata).collect();
        let body = serde_json::json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": resp.revision.to_string() },
            "items": pom_items
        });
        return Ok(Json(body).into_response());
    }

    let body = super::generic::build_list_response(
        &ctx.kind,
        &group,
        &version,
        resp.revision,
        items,
        resp.continue_key,
        resp.remaining_count,
        &state.continue_token_key,
    );
    Ok(Json(body).into_response())
}

pub async fn get_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let (fetch_version, needs_conversion) = if version != ctx.storage_version {
        (
            ctx.storage_version.as_str(),
            ctx.conversion_webhook_client_config.is_some(),
        )
    } else {
        (version.as_str(), false)
    };

    let key = cr_store_key(&group, fetch_version, &plural, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    if needs_conversion {
        if let Some(cfg) = ctx.conversion_webhook_client_config.as_ref() {
            let obj: serde_json::Value = serde_json::from_slice(&stored.value)
                .map_err(|e| Status::internal(e.to_string()))?;
            let desired_api_version = format!("{group}/{version}");
            let mut converted =
                call_conversion_webhook(&state, cfg, vec![obj], &desired_api_version).await?;
            let converted_obj = converted
                .pop()
                .ok_or_else(|| Status::internal("conversion webhook returned no objects".into()))?;
            let bytes =
                serde_json::to_vec(&converted_obj).map_err(|e| Status::internal(e.to_string()))?;
            return Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                bytes,
            )
                .into_response());
        }
    }

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn create_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Reject object creation in a Terminating namespace — matches kube-apiserver behaviour:
    // 403 Forbidden: unable to create new content in namespace <ns> because it is being terminated
    {
        let ns_key = cluster_object_key("namespaces", &ns);
        if let Ok(Some(stored)) = state.store.get(&ns_key).await {
            if let Ok(ns_obj) = serde_json::from_slice::<serde_json::Value>(&stored.value) {
                if ns_obj["status"]["phase"].as_str() == Some("Terminating") {
                    return Err(Status::forbidden(format!(
                        "unable to create new content in namespace {ns} because it is being terminated"
                    )));
                }
            }
        }
    }
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let mut wrapped = crate::types::Object { body: obj };
    let name = crate::handlers::generic::resolve_name(&mut wrapped)?;
    let mut obj = wrapped.body;
    validate_cr_name(&name)?;

    validate_cr_schema(&obj, &ctx)?;

    {
        let mut meta: crate::types::ObjectMeta =
            serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
        meta.namespace = Some(ns.clone());
        obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    }
    stamp_cr_fields(&mut obj, &group, &version, &ctx.kind);

    let key = cr_store_key(&group, &version, &plural, Some(&ns), &name);
    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let rv = state
        .store
        .put(&key, Bytes::from(bytes), Some(0))
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    Ok((StatusCode::CREATED, Json(obj)))
}

pub async fn replace_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].clone()).unwrap_or_default();
    let obj_name = obj_meta.name.as_deref().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let key = cr_store_key(&group, &version, &plural, Some(&ns), &name);

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    let existing: serde_json::Value =
        serde_json::from_slice(&stored.value).unwrap_or(serde_json::Value::Null);
    resolve_cr_metadata(&existing, &mut obj);

    // When the CRD declares a status subresource, the main PUT endpoint must not
    // update .status — clients must use PUT /status for that.
    if ctx.has_status_subresource {
        if let Some(map) = obj.as_object_mut() {
            map.remove("status");
        }
    }

    validate_cr_schema(&obj, &ctx)?;

    let meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].clone()).unwrap_or_default();
    let expected_rv = parse_resource_version(meta.resource_version.as_deref())?;

    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let rv = state
        .store
        .put(&key, Bytes::from(bytes), expected_rv)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    Ok(Json(obj))
}

pub async fn delete_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let key = cr_store_key(&group, &version, &plural, Some(&ns), &name);

    let _ = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

// ---------------------------------------------------------------------------
// Patch helpers
// ---------------------------------------------------------------------------

fn validate_patch_content_type(headers: &HeaderMap) -> Result<(), crate::status::StatusError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/merge-patch+json")
        || content_type.contains("application/strategic-merge-patch+json")
    {
        return Ok(());
    }

    Err(Status::unsupported_media_type(format!(
        "unsupported media type '{content_type}'; use application/merge-patch+json"
    )))
}

// ---------------------------------------------------------------------------
// Cluster-scoped CR patch handler
// ---------------------------------------------------------------------------

pub async fn patch_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_patch_content_type(&headers)?;

    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let key = cr_store_key(&group, &version, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    let mut obj: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    let mut patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // When the CRD declares a status subresource, the main PATCH endpoint must not
    // update .status — clients must use PATCH /status for that.
    if ctx.has_status_subresource {
        if let Some(map) = patch.as_object_mut() {
            map.remove("status");
        }
    }

    crate::patch::merge_patch(&mut obj, &patch);

    validate_cr_schema(&obj, &ctx)?;

    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let new_rv = state
        .store
        .put(&key, Bytes::from(bytes), Some(stored.revision))
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(new_rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    Ok(Json(obj))
}

// ---------------------------------------------------------------------------
// Namespaced CR patch handler
// ---------------------------------------------------------------------------

pub async fn patch_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    validate_patch_content_type(&headers)?;

    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let key = cr_store_key(&group, &version, &plural, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    let mut obj: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    let mut patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // When the CRD declares a status subresource, the main PATCH endpoint must not
    // update .status — clients must use PATCH /status for that.
    if ctx.has_status_subresource {
        if let Some(map) = patch.as_object_mut() {
            map.remove("status");
        }
    }

    crate::patch::merge_patch(&mut obj, &patch);

    validate_cr_schema(&obj, &ctx)?;

    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let new_rv = state
        .store
        .put(&key, Bytes::from(bytes), Some(stored.revision))
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(new_rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    Ok(Json(obj))
}

// ---------------------------------------------------------------------------
// Status subresource handlers for cluster-scoped CRs
// ---------------------------------------------------------------------------

/// PUT /apis/{group}/{version}/{plural}/{name}/status
///
/// Handles both registry-backed resources (falls through to the same logic as
/// `generic::put_resource_status`) and custom resources (stored under
/// `/registry/cr/...`). Only updates the `.status` field; all other fields
/// including `.spec` are left unchanged.
pub async fn put_cr_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    use crate::{keys::group_object_key, types::ResourceKey, util::parse_resource_version};

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let incoming: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // Determine the store key: registry resources use the group-object key;
    // CRs use the /registry/cr/... key.
    let registry_key = ResourceKey {
        group: group.clone(),
        version: version.clone(),
        plural: plural.clone(),
    };
    let (key, kind) = if let Some(meta) = state.resource_registry.get(&registry_key) {
        (
            group_object_key(&group, &plural, None, &name),
            meta.kind.clone(),
        )
    } else {
        // CR fallback: find the CRD to get the kind name, use CR storage key.
        let ctx = find_crd(&state, &group, &version, &plural).await?;
        if ctx.namespaced {
            return Err(Status::not_found(&name, &ctx.kind));
        }
        (
            cr_store_key(&group, &version, &plural, None, &name),
            ctx.kind,
        )
    };

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &kind))?;

    let mut current: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    // Replace only the .status field; leave .spec and .metadata unchanged.
    match &incoming["status"] {
        serde_json::Value::Null => {
            if let Some(map) = current.as_object_mut() {
                map.remove("status");
            }
        }
        v => {
            current["status"] = v.clone();
        }
    }

    let current_meta: crate::types::ObjectMeta =
        serde_json::from_value(current["metadata"].clone()).unwrap_or_default();
    let expected_rv = parse_resource_version(current_meta.resource_version.as_deref())?;
    let bytes = serde_json::to_vec(&current).map_err(|e| Status::internal(e.to_string()))?;
    let new_rv = state
        .store
        .put(&key, Bytes::from(bytes), expected_rv)
        .await
        .map_err(|e| store_err_cr(e, &name, &kind))?;

    let mut current_meta: crate::types::ObjectMeta =
        serde_json::from_value(current["metadata"].take()).unwrap_or_default();
    current_meta.resource_version = Some(new_rv.to_string());
    current["metadata"] = serde_json::to_value(current_meta).unwrap_or_default();
    Ok(Json(current))
}

/// GET /apis/{group}/{version}/{plural}/{name}/status
///
/// Returns the full object (status is embedded). For CRs this is identical to
/// the main GET endpoint. For registry resources it delegates to get_resource.
pub async fn get_cr_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    use crate::types::ResourceKey;

    let registry_key = ResourceKey {
        group: group.clone(),
        version: version.clone(),
        plural: plural.clone(),
    };
    if state.resource_registry.contains_key(&registry_key) {
        // Delegate to the generic get handler for registry resources.
        return super::resource::get_resource(State(state), Path((group, version, plural, name)))
            .await;
    }

    // CR path.
    let ctx = find_crd(&state, &group, &version, &plural).await?;
    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }
    let key = cr_store_key(&group, &version, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use u7s_store::SqliteStore;

    fn no_watch_query() -> super::super::generic::CollectionQuery {
        super::super::generic::CollectionQuery {
            watch: None,
            resource_version: None,
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        }
    }

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
        })
    }

    fn expect_err_status<T>(
        result: Result<T, crate::status::StatusError>,
        msg: &str,
    ) -> crate::status::StatusError {
        match result {
            Ok(_) => panic!("expected Err but got Ok: {msg}"),
            Err(e) => e,
        }
    }

    fn namespaced_crd_bytes() -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "applications.argoproj.io" },
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

    fn cluster_crd_bytes() -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Cluster",
                    "versions": [
                        { "name": "v1", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        )
    }

    async fn install_namespaced_crd(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespaced_crd_bytes()
            )
            .await
            .is_ok(),
            "install namespaced CRD"
        );
    }

    async fn install_cluster_crd(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                cluster_crd_bytes()
            )
            .await
            .is_ok(),
            "install cluster CRD"
        );
    }

    fn app_body(name: &str, ns: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": name, "namespace": ns },
                "spec": { "destination": { "namespace": "default" } }
            })
            .to_string(),
        )
    }

    fn widget_body(name: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": name },
                "spec": { "color": "blue" }
            })
            .to_string(),
        )
    }

    // Create a namespaced CR then get it back — round-trip must return the stored object.
    #[tokio::test]
    async fn namespaced_create_and_get_round_trip() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural, name.clone())),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after create"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Request for an unknown group must return 404 (no CRD installed for that group).
    #[tokio::test]
    async fn unknown_group_returns_404() {
        let state = make_state();

        let err = expect_err_status(
            list_cr_namespaced(
                State(state.clone()),
                Path((
                    "unknown.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "things".to_string(),
                )),
                axum::http::HeaderMap::new(),
                no_watch_query(),
                "test-user".to_string(),
            )
            .await,
            "expected 404 for unknown group",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404, "must return 404 for unknown group");
        assert_eq!(json["reason"], "NotFound");
    }

    // Using a namespaced path for a cluster-scoped CRD must return 404.
    #[tokio::test]
    async fn namespaced_path_for_cluster_crd_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        // widgets is cluster-scoped; using namespaces/:ns path must be rejected.
        let err = expect_err_status(
            list_cr_namespaced(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                no_watch_query(),
                "test-user".to_string(),
            )
            .await,
            "cluster-scoped CRD must reject namespaced path",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // GET /apis/{group}/{version}/{plural} (no namespace segment) on a Namespaced CRD
    // must return 200 with an empty list, not 404. KCM GC informers watch this path to
    // garbage-collect custom resources cluster-wide; a 404 causes them to retry every 15s
    // and prevents namespace deletion from completing.
    #[tokio::test]
    async fn cluster_wide_list_for_namespaced_crd_returns_200() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let json = serde_json::to_value(&e.1).unwrap();
                panic!(
                    "cluster-wide list on namespaced CRD must return 200, got: {}",
                    json
                );
            }
        };

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "KCM informers watch cluster-wide path; 404 causes infinite retry"
        );
    }

    // GET /apis/{group}/{version}/{plural} on a Namespaced CRD with CRs in multiple
    // namespaces must return all of them. KCM GC needs the full cross-namespace view
    // to discover owner references and garbage-collect correctly.
    #[tokio::test]
    async fn cluster_wide_list_for_namespaced_crd_returns_all_namespaces() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        // Create CRs in two different namespaces.
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "ns-a".to_string(),
                    "applications".to_string(),
                )),
                axum::http::HeaderMap::new(),
                app_body("app-in-ns-a", "ns-a"),
            )
            .await
            .is_ok(),
            "create in ns-a must succeed"
        );
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "ns-b".to_string(),
                    "applications".to_string(),
                )),
                axum::http::HeaderMap::new(),
                app_body("app-in-ns-b", "ns-b"),
            )
            .await
            .is_ok(),
            "create in ns-b must succeed"
        );

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let json = serde_json::to_value(&e.1).unwrap();
                panic!("cluster-wide list must succeed, got: {}", json);
            }
        };

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = list["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            2,
            "cluster-wide list must include CRs from all namespaces, got {}",
            items.len()
        );
    }

    // WATCH /apis/{group}/{version}/{plural} (no namespace) on a Namespaced CRD must
    // return 200 with chunked streaming. KCM informers use this watch path.
    #[tokio::test]
    async fn cluster_wide_watch_for_namespaced_crd_returns_200_chunked() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let json = serde_json::to_value(&e.1).unwrap();
                panic!(
                    "cluster-wide watch on namespaced CRD must return 200, got: {}",
                    json
                );
            }
        };

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "cluster-wide watch on namespaced CRD must use chunked transfer encoding"
        );
    }

    // Creating the same CR twice must return 409 AlreadyExists.
    #[tokio::test]
    async fn duplicate_create_returns_409() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "first create must succeed"
        );

        let err = expect_err_status(
            create_cr_namespaced(
                State(state.clone()),
                Path((group, version, ns.clone(), plural)),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await,
            "duplicate create must fail with 409",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 409, "duplicate create must return 409");
        assert_eq!(json["reason"], "AlreadyExists");
    }

    // Getting a missing CR must return 404.
    #[tokio::test]
    async fn get_missing_cr_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let err = expect_err_status(
            get_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "argocd".to_string(),
                    "applications".to_string(),
                    "nonexistent".to_string(),
                )),
            )
            .await,
            "missing CR must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // Cluster-scoped CR create + get round-trip.
    #[tokio::test]
    async fn cluster_scoped_create_and_get() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string()
                )),
                axum::http::HeaderMap::new(),
                widget_body("my-widget"),
            )
            .await
            .is_ok(),
            "cluster-scoped create must succeed"
        );

        let resp = match get_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "my-widget".to_string(),
            )),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after create"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // List after create must return one item.
    #[tokio::test]
    async fn list_returns_created_items() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                app_body("app-one", &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match list_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural)),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must succeed"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Delete then get must return 404.
    #[tokio::test]
    async fn delete_then_get_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "app-to-delete".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        assert!(
            delete_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone()
                )),
            )
            .await
            .is_ok(),
            "delete must succeed"
        );

        let err = expect_err_status(
            get_cr_namespaced(
                State(state.clone()),
                Path((group, version, ns, plural, name)),
            )
            .await,
            "get after delete must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // PATCH applies the merge patch to the stored CR and returns 200 with the updated object.
    // This verifies that patch_cr_namespaced correctly mutates the stored value.
    #[tokio::test]
    async fn patch_cr_namespaced_applies_merge_patch() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "patch-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(serde_json::json!({ "spec": { "color": "red" } }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_cr_namespaced(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
            headers,
            patch_body,
        )
        .await;
        assert!(result.is_ok(), "patch must succeed");

        // Verify the stored value has color: red under spec.
        let stored_resp = match get_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural, name)),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after patch"),
        };
        assert_eq!(stored_resp.status(), StatusCode::OK);
    }

    // PATCH on a group with no CRD installed must return 404.
    // This verifies that patch_cr_namespaced correctly propagates CRD-not-found as 404.
    #[tokio::test]
    async fn patch_cr_namespaced_returns_404_for_unknown_group() {
        let state = make_state();

        let patch_body = Bytes::from(serde_json::json!({ "spec": {} }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr_namespaced(
                State(state.clone()),
                Path((
                    "unknown.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "things".to_string(),
                    "my-thing".to_string(),
                )),
                headers,
                patch_body,
            )
            .await,
            "expected 404 for unknown group",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404, "unknown CRD must return 404");
        assert_eq!(json["reason"], "NotFound");
    }

    // PATCH with Content-Type: application/json must return 415 Unsupported Media Type.
    // This verifies that the content-type guard fires before any store access.
    #[tokio::test]
    async fn patch_cr_namespaced_rejects_wrong_content_type() {
        let state = make_state();

        let patch_body = Bytes::from(serde_json::json!({ "spec": {} }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "argocd".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
                headers,
                patch_body,
            )
            .await,
            "expected 415 for wrong content type",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 415, "wrong content type must return 415");
    }

    // stamp_cr_fields must assign uid and creationTimestamp when absent,
    // and must set apiVersion and kind unconditionally.
    #[test]
    fn stamp_cr_sets_uid_and_timestamp_when_absent() {
        let mut obj = serde_json::json!({ "metadata": {} });
        stamp_cr_fields(&mut obj, "example.io", "v1", "Widget");
        assert_eq!(obj["apiVersion"], "example.io/v1");
        assert_eq!(obj["kind"], "Widget");
        let uid = obj["metadata"]["uid"].as_str().unwrap_or("");
        assert!(!uid.is_empty(), "uid must be assigned when absent");
        let ts = obj["metadata"]["creationTimestamp"].as_str().unwrap_or("");
        assert!(
            !ts.is_empty(),
            "creationTimestamp must be assigned when absent"
        );
    }

    // stamp_cr_fields must preserve existing uid when already present,
    // because a replace operation must not change the identity of the object.
    #[test]
    fn stamp_cr_preserves_existing_uid_on_replace() {
        let mut obj = serde_json::json!({
            "metadata": {
                "uid": "existing-uid-abc",
                "creationTimestamp": "2024-01-01T00:00:00Z"
            }
        });
        stamp_cr_fields(&mut obj, "example.io", "v1", "Widget");
        assert_eq!(
            obj["metadata"]["uid"], "existing-uid-abc",
            "existing uid must be preserved"
        );
        assert_eq!(
            obj["metadata"]["creationTimestamp"], "2024-01-01T00:00:00Z",
            "existing creationTimestamp must be preserved"
        );
    }

    // validate_cr_name must reject empty names — empty string is not a valid
    // Kubernetes resource name and must not be silently accepted.
    #[test]
    fn validate_cr_name_rejects_empty() {
        let result = validate_cr_name("");
        assert!(result.is_err(), "empty name must be rejected");
    }

    // validate_cr_name must accept a valid DNS label — the common case for CR names.
    #[test]
    fn validate_cr_name_accepts_valid_dns_label() {
        assert!(
            validate_cr_name("my-resource").is_ok(),
            "valid DNS label must be accepted"
        );
        assert!(
            validate_cr_name("foo123").is_ok(),
            "alphanumeric name must be accepted"
        );
    }

    // resolve_cr_metadata must copy uid from stored into incoming when incoming
    // has no uid set — replace handlers must preserve object identity.
    #[test]
    fn resolve_cr_metadata_copies_uid() {
        let stored = serde_json::json!({
            "metadata": {
                "uid": "stored-uid-xyz",
                "creationTimestamp": "2024-06-01T00:00:00Z"
            }
        });
        let mut incoming = serde_json::json!({ "metadata": {} });
        resolve_cr_metadata(&stored, &mut incoming);
        assert_eq!(
            incoming["metadata"]["uid"], "stored-uid-xyz",
            "uid must be copied from stored into incoming"
        );
        assert_eq!(
            incoming["metadata"]["creationTimestamp"], "2024-06-01T00:00:00Z",
            "creationTimestamp must be copied from stored into incoming"
        );
    }

    fn watch_query() -> super::super::generic::CollectionQuery {
        super::super::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        }
    }

    // When ?watch=true, list_cr must route to the watch stream rather than returning
    // a normal list. A CRD must exist for the request to succeed; without one, find_crd
    // returns 404 before reaching the watch branch.
    #[tokio::test]
    async fn list_cr_watch_returns_chunked_stream() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        // watch_generic always sets transfer-encoding: chunked — verifies the watch
        // branch was taken, not the normal list path.
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "cluster-scoped CR watch must use chunked transfer encoding"
        );
    }

    // When ?watch=true, list_cr_namespaced must route to the watch stream for a
    // namespaced CRD. This verifies the watch branch in the namespaced list handler.
    #[tokio::test]
    async fn list_cr_namespaced_watch_returns_chunked_stream() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let resp = match list_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "namespaced CR watch must use chunked transfer encoding"
        );
    }

    // validate_patch_content_type must accept application/strategic-merge-patch+json.
    // Conformance tests (label/annotation patches on Namespaces and DaemonSets) send
    // this content type; rejecting it with 415 breaks those tests. For CRDs the
    // strategic-merge array directives are not meaningful, but the JSON merge-patch
    // semantics (scalar overwrite, object recurse, null remove) are identical, so
    // we apply merge-patch logic regardless of which of the two types is sent.
    #[test]
    fn strategic_merge_patch_accepted_for_cr() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/strategic-merge-patch+json".parse().unwrap(),
        );
        assert!(
            validate_patch_content_type(&headers).is_ok(),
            "strategic-merge-patch must be accepted — conformance tests patch CRs with this type"
        );
    }

    // validate_patch_content_type must still reject genuinely unsupported types with 415.
    // Clients that accidentally send application/json get a clear 415, not a cryptic error.
    #[test]
    fn application_json_content_type_rejected_with_415() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        let err = validate_patch_content_type(&headers).unwrap_err();
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json must be rejected with 415 Unsupported Media Type"
        );
    }

    // new_cr_uid must produce valid RFC-4122 v4 UUIDs. Non-standard UIDs break
    // kubectl tools that parse UIDs (e.g. owner references, garbage collection).
    #[test]
    fn new_cr_uid_produces_valid_uuids() {
        for _ in 0..100 {
            let uid = new_cr_uid();
            let parsed = uuid::Uuid::parse_str(&uid)
                .unwrap_or_else(|_| panic!("new_cr_uid returned non-UUID: {uid}"));
            assert_eq!(
                parsed.get_version(),
                Some(uuid::Version::Random),
                "UID must be UUID v4 (Random), got: {uid}"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // Status subresource tests
    // ---------------------------------------------------------------------------

    /// Builds a namespaced CRD body with `subresources: {status: {}}` on the version.
    fn namespaced_crd_with_status_subresource_bytes() -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "applications.argoproj.io" },
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
                        {
                            "name": "v1alpha1",
                            "served": true,
                            "storage": true,
                            "subresources": { "status": {} }
                        }
                    ]
                }
            })
            .to_string(),
        )
    }

    /// Builds a cluster-scoped CRD body with `subresources: {status: {}}`.
    fn cluster_crd_with_status_subresource_bytes() -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Cluster",
                    "versions": [
                        {
                            "name": "v1",
                            "served": true,
                            "storage": true,
                            "subresources": { "status": {} }
                        }
                    ]
                }
            })
            .to_string(),
        )
    }

    async fn install_crd_with_status_subresource(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespaced_crd_with_status_subresource_bytes(),
            )
            .await
            .is_ok(),
            "install namespaced CRD with status subresource"
        );
    }

    async fn install_cluster_crd_with_status_subresource(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                cluster_crd_with_status_subresource_bytes(),
            )
            .await
            .is_ok(),
            "install cluster CRD with status subresource"
        );
    }

    // PUT to the main endpoint for a CR whose CRD declares a status subresource must
    // NOT update .status. Only .spec changes must be persisted.
    // This is the Kubernetes contract: controllers write spec via the main endpoint
    // and status via the /status subresource endpoint — mixing the two causes races.
    #[tokio::test]
    async fn namespaced_main_put_strips_status_when_has_status_subresource() {
        let state = make_state();
        install_crd_with_status_subresource(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        // Create without status so the stored object has no .status.
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // PUT to the main endpoint with both spec and status changes.
        // The CRD has a status subresource, so only spec must be persisted.
        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "production" } },
                "status": { "phase": "Injected" }
            })
            .to_string(),
        );

        assert!(
            replace_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        // Get the stored object and verify .status was NOT updated.
        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["spec"]["destination"]["namespace"], "production",
            "spec must be updated by main PUT"
        );
        assert!(
            obj["status"].is_null() || obj.get("status").is_none(),
            "status must NOT be persisted by main PUT when status subresource is declared"
        );
    }

    // Regression: A CRD WITHOUT a status subresource must persist .status normally
    // on the main PUT endpoint. This verifies the guard fires only when declared.
    #[tokio::test]
    async fn namespaced_main_put_persists_status_without_subresource() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "default" } },
                "status": { "phase": "Running" }
            })
            .to_string(),
        );

        assert!(
            replace_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["status"]["phase"], "Running",
            "status must be persisted when no status subresource is declared"
        );
    }

    // PUT to the /status endpoint for a namespaced CR must update ONLY .status;
    // the .spec must remain unchanged. This is tested via put_namespaced_resource_status
    // (the generic handler with CR fallback).
    //
    // The generic handler is tested here using its CR fallback path, which stores to
    // /registry/cr/... This verifies the Argo CD use-case: Application controller writes
    // Application.status via the status subresource.
    #[tokio::test]
    async fn namespaced_status_put_updates_only_status() {
        let state = make_state();
        install_crd_with_status_subresource(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        // Create with a spec field so we can verify it's unchanged after status PUT.
        let create_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "default" } }
            })
            .to_string(),
        );
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                create_body,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // PUT to /status: only .status should change.
        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "SHOULD_NOT_CHANGE" } },
                "status": { "phase": "Healthy", "ready": true }
            })
            .to_string(),
        );

        assert!(
            super::super::status::put_namespaced_resource_status(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                axum::http::HeaderMap::new(),
                status_body,
            )
            .await
            .is_ok(),
            "status PUT must succeed"
        );

        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["status"]["phase"], "Healthy",
            "status.phase must be updated by status PUT"
        );
        assert_eq!(
            obj["status"]["ready"], true,
            "status.ready must be updated by status PUT"
        );
        assert_eq!(
            obj["spec"]["destination"]["namespace"], "default",
            "spec must NOT be changed by status PUT"
        );
    }

    // PUT to /status for a cluster-scoped CR must update ONLY .status.
    // This tests put_cr_status which adds the CR fallback missing from put_resource_status.
    #[tokio::test]
    async fn cluster_scoped_status_put_updates_only_status() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "my-widget".to_string();

        // Create with a spec field.
        let create_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "blue" }
            })
            .to_string(),
        );
        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                create_body,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // PUT to /status: only .status should change.
        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "SHOULD_NOT_CHANGE" },
                "status": { "ready": true, "replicas": 3 }
            })
            .to_string(),
        );

        assert!(
            put_cr_status(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone(),)),
                axum::http::HeaderMap::new(),
                status_body,
            )
            .await
            .is_ok(),
            "cluster-scoped status PUT must succeed"
        );

        let resp = match get_cr(
            State(state.clone()),
            Path((group.clone(), version.clone(), plural.clone(), name.clone())),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["status"]["ready"], true,
            "status.ready must be updated by status PUT"
        );
        assert_eq!(
            obj["status"]["replicas"], 3,
            "status.replicas must be updated by status PUT"
        );
        assert_eq!(
            obj["spec"]["color"], "blue",
            "spec must NOT be changed by status PUT"
        );
    }

    // find_crd must detect has_status_subresource=true when the CRD spec declares
    // subresources.status on any version.
    #[tokio::test]
    async fn find_crd_detects_status_subresource() {
        let state = make_state();
        install_crd_with_status_subresource(&state).await;

        let ctx = match find_crd(&state, "argoproj.io", "v1alpha1", "applications").await {
            Ok(c) => c,
            Err(_) => panic!("find_crd must succeed"),
        };

        assert!(
            ctx.has_status_subresource,
            "has_status_subresource must be true when subresources.status is declared"
        );
    }

    // find_crd must return has_status_subresource=false when the CRD does not declare
    // the status subresource.
    #[tokio::test]
    async fn find_crd_no_status_subresource_when_not_declared() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let ctx = match find_crd(&state, "argoproj.io", "v1alpha1", "applications").await {
            Ok(c) => c,
            Err(_) => panic!("find_crd must succeed"),
        };

        assert!(
            !ctx.has_status_subresource,
            "has_status_subresource must be false when subresources.status is absent"
        );
    }

    // Main PUT for a namespaced CR with status subresource must strip .status
    // even when patched via merge-patch (PATCH /apis/...).
    #[tokio::test]
    async fn namespaced_main_patch_strips_status_when_has_status_subresource() {
        let state = make_state();
        install_crd_with_status_subresource(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "patch-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!({
                "spec": { "color": "green" },
                "status": { "phase": "MUST_NOT_BE_STORED" }
            })
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "patch must succeed"
        );

        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural, name)),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            obj["status"].is_null() || obj.get("status").is_none(),
            "status must NOT be stored by main PATCH when status subresource declared"
        );
    }

    // ---------------------------------------------------------------------------
    // openAPIV3Schema validation tests (boon-based)
    // ---------------------------------------------------------------------------

    /// Helper: call validate_cr_schema with an inline schema value.
    fn check_schema(
        obj: &serde_json::Value,
        schema: serde_json::Value,
    ) -> Result<(), crate::status::StatusError> {
        let ctx = CrContext {
            kind: "Test".into(),
            namespaced: false,
            has_status_subresource: false,
            schema: Some(schema),
            storage_version: "v1".into(),
            conversion_webhook_client_config: None,
        };
        validate_cr_schema(obj, &ctx)
    }

    // type:object with valid object passes.
    // This is the happy path — a properly typed CR body must not be rejected.
    #[test]
    fn schema_valid_object_passes() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": { "type": "object" }
            }
        });
        let value = serde_json::json!({ "spec": {} });
        assert!(
            check_schema(&value, schema).is_ok(),
            "valid object must pass schema validation"
        );
    }

    // type:object with spec as string fails.
    // Ensures the type constraint is actually enforced — wrong types must be caught.
    #[test]
    fn schema_wrong_type_for_property_fails() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": { "type": "object" }
            }
        });
        let value = serde_json::json!({ "spec": "not-an-object" });
        let err = check_schema(&value, schema).unwrap_err();
        let msg = &err.1.message;
        assert!(
            msg.contains("spec"),
            "error must name the offending field (got: {msg})"
        );
    }

    // required field missing causes an error.
    // Controllers rely on required fields being present — silent acceptance would
    // allow incomplete CRs that break the controller's assumptions.
    #[test]
    fn schema_required_field_missing_fails() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["spec"],
            "properties": {
                "spec": { "type": "object" }
            }
        });
        let value = serde_json::json!({ "metadata": { "name": "foo" } });
        let err = check_schema(&value, schema).unwrap_err();
        let msg = &err.1.message;
        assert!(
            msg.contains("spec"),
            "error must mention the missing required field (got: {msg})"
        );
    }

    // additionalProperties:false rejects unknown keys.
    // Strict schemas should prevent typos in field names from being silently stored.
    #[test]
    fn schema_additional_properties_false_rejects_unknown_key() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": { "type": "object" }
            },
            "additionalProperties": false
        });
        let value = serde_json::json!({ "spec": {}, "unknownField": "oops" });
        assert!(
            check_schema(&value, schema).is_err(),
            "additional property must be rejected"
        );
    }

    // Unknown extension keywords must not cause a compile error (permissive).
    // openAPIV3Schema CRDs use x-kubernetes-* extensions; boon must not reject them.
    #[test]
    fn schema_unknown_extension_keywords_do_not_fail_compile() {
        let schema = serde_json::json!({
            "type": "object",
            "x-kubernetes-preserve-unknown-fields": true,
            "description": "some doc"
        });
        let value = serde_json::json!({ "anything": "here" });
        assert!(
            check_schema(&value, schema).is_ok(),
            "schema with extension keywords must not cause compile or validation error"
        );
    }

    // scalar types are correctly checked.
    // These are the leaf types that CRD schemas declare for individual fields.
    #[test]
    fn schema_scalar_type_checks() {
        let string_schema = serde_json::json!({ "type": "string" });
        assert!(check_schema(&serde_json::json!("hello"), string_schema.clone()).is_ok());
        assert!(check_schema(&serde_json::json!(42), string_schema).is_err());

        let int_schema = serde_json::json!({ "type": "integer" });
        assert!(check_schema(&serde_json::json!(7), int_schema.clone()).is_ok());
        assert!(check_schema(&serde_json::json!("7"), int_schema).is_err());

        let bool_schema = serde_json::json!({ "type": "boolean" });
        assert!(check_schema(&serde_json::json!(true), bool_schema.clone()).is_ok());
        assert!(check_schema(&serde_json::json!(1), bool_schema).is_err());
    }

    // enum violation: value not in the allowed set must be rejected.
    // The old hand-rolled validator silently accepted enum violations — this test
    // ensures boon enforces enum correctly.
    #[test]
    fn schema_enum_violation_fails() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "kind": { "type": "string", "enum": ["Issuer", "ClusterIssuer"] }
            }
        });
        let value = serde_json::json!({ "kind": "BadValue" });
        assert!(
            check_schema(&value, schema).is_err(),
            "enum violation must be rejected by boon"
        );
    }

    // pattern violation: string not matching regex must be rejected.
    // The old hand-rolled validator silently accepted pattern violations — this test
    // ensures boon enforces pattern correctly.
    #[test]
    fn schema_pattern_violation_fails() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "duration": { "type": "string", "pattern": "^[0-9]+(h|m|s)$" }
            }
        });
        let value = serde_json::json!({ "duration": "90days" });
        assert!(
            check_schema(&value, schema).is_err(),
            "pattern violation must be rejected by boon"
        );
    }

    // CRD with schema: valid CR body accepted by create_cr_namespaced.
    // This is the integration path: schema extracted from CRD, CR body validated.
    #[tokio::test]
    async fn create_cr_namespaced_with_schema_accepts_valid_body() {
        let state = make_state();

        // Install CRD with openAPIV3Schema requiring spec to be an object.
        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
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
                                    "spec": { "type": "object" }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install CRD with schema"
        );

        // CR with spec as object — must pass validation.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "good-widget", "namespace": "default" },
                "spec": { "color": "blue" }
            })
            .to_string(),
        );

        let result = create_cr_namespaced(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            cr_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "CR with valid spec object must be accepted by schema validation"
        );
    }

    // CRD with schema: CR body with wrong spec type rejected with 422.
    // Server-side validation must fire when the CRD has a schema — wrong types
    // must not be silently stored (the whole point of this feature).
    #[tokio::test]
    async fn create_cr_namespaced_with_schema_rejects_wrong_spec_type() {
        let state = make_state();

        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
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
                                    "spec": { "type": "object" }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install CRD with schema"
        );

        // CR with spec as a string — must fail schema validation.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "bad-widget", "namespace": "default" },
                "spec": "not-an-object"
            })
            .to_string(),
        );

        let err = expect_err_status(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                cr_body,
            )
            .await,
            "CR with spec as string must be rejected",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422, "schema violation must return 422");
        assert_eq!(
            json["reason"], "Invalid",
            "schema violation must return reason=Invalid"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("schema validation failed"),
            "message must mention schema validation (got: {})",
            json["message"]
        );
    }

    // CRD with required field: CR missing that field is rejected with 422.
    // Required constraints protect controllers that always expect certain fields.
    #[tokio::test]
    async fn create_cr_namespaced_with_required_schema_rejects_missing_field() {
        let state = make_state();

        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
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
                                "required": ["spec"],
                                "properties": {
                                    "spec": { "type": "object" }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install CRD with required schema"
        );

        // CR without spec — must fail required constraint.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "no-spec-widget", "namespace": "default" }
            })
            .to_string(),
        );

        let err = expect_err_status(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                cr_body,
            )
            .await,
            "CR without required spec must be rejected",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422, "missing required field must return 422");
    }

    // CRD without schema: any CR body is accepted (permissive mode).
    // This preserves backward-compatible behaviour for CRDs that don't declare a schema.
    #[tokio::test]
    async fn create_cr_namespaced_without_schema_accepts_any_body() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        // Body with an unusual structure — must be accepted since no schema is declared.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": "any-body-app", "namespace": "argocd" },
                "weirdField": 42,
                "anotherField": [1, 2, 3]
            })
            .to_string(),
        );

        let result = create_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            cr_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "CRD without schema must accept any body (permissive mode)"
        );
    }

    // ---------------------------------------------------------------------------
    // Cluster-scoped replace_cr tests
    // ---------------------------------------------------------------------------

    // replace_cr (cluster-scoped) must update the stored object and return 200.
    // This is the happy-path for cluster-scoped CR updates — controllers call PUT
    // on the main endpoint to change spec.
    #[tokio::test]
    async fn cluster_scoped_replace_cr_round_trip() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "my-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "red" }
            })
            .to_string(),
        );

        assert!(
            replace_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "cluster-scoped replace must succeed"
        );

        // Verify the update was persisted.
        let resp = match get_cr(State(state.clone()), Path((group, version, plural, name))).await {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after replace"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["spec"]["color"], "red",
            "spec must be updated by replace"
        );
    }

    // replace_cr on a non-existent object must return 404.
    // Cluster-scoped PUT must not create resources that don't exist — that is
    // only the job of POST (create).
    #[tokio::test]
    async fn cluster_scoped_replace_cr_missing_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let err = expect_err_status(
            replace_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "nonexistent".to_string(),
                )),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "example.io/v1",
                        "kind": "Widget",
                        "metadata": { "name": "nonexistent" },
                        "spec": {}
                    })
                    .to_string(),
                ),
            )
            .await,
            "replace on missing object must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // replace_cr with a name mismatch between URL and body must return 400.
    // Kubernetes enforces that the object name in the body matches the URL segment.
    #[tokio::test]
    async fn cluster_scoped_replace_cr_name_mismatch_returns_400() {
        let state = make_state();
        install_cluster_crd(&state).await;

        // First create the object.
        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                widget_body("actual-name"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Attempt replace with body.metadata.name != URL segment.
        let err = expect_err_status(
            replace_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "actual-name".to_string(),
                )),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "example.io/v1",
                        "kind": "Widget",
                        "metadata": { "name": "different-name" },
                        "spec": {}
                    })
                    .to_string(),
                ),
            )
            .await,
            "name mismatch must return 400",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 400,
            "name mismatch must return 400 Bad Request"
        );
    }

    // replace_cr with a namespaced CRD must return 404 (wrong scope).
    // The cluster-scoped endpoint must not serve namespaced CRDs.
    #[tokio::test]
    async fn cluster_scoped_replace_cr_with_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let err = expect_err_status(
            replace_cr(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "argoproj.io/v1alpha1",
                        "kind": "Application",
                        "metadata": { "name": "my-app" },
                        "spec": {}
                    })
                    .to_string(),
                ),
            )
            .await,
            "namespaced CRD on cluster-scoped replace must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // replace_cr strips .status when the CRD declares a status subresource.
    // This is symmetric to the namespaced case tested in
    // `namespaced_main_put_strips_status_when_has_status_subresource`.
    #[tokio::test]
    async fn cluster_scoped_replace_cr_strips_status_when_has_status_subresource() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "my-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "green" },
                "status": { "ready": true, "message": "MUST_NOT_BE_STORED" }
            })
            .to_string(),
        );

        assert!(
            replace_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        let resp = match get_cr(State(state.clone()), Path((group, version, plural, name))).await {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            obj["status"].is_null() || obj.get("status").is_none(),
            "status must NOT be stored by main PUT when status subresource is declared"
        );
    }

    // ---------------------------------------------------------------------------
    // Cluster-scoped delete_cr tests
    // ---------------------------------------------------------------------------

    // delete_cr must remove the object from the store; a subsequent get must return 404.
    // This is the happy-path for cluster-scoped CR deletion.
    #[tokio::test]
    async fn cluster_scoped_delete_cr_success() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "to-delete".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        assert!(
            delete_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
            )
            .await
            .is_ok(),
            "delete must succeed"
        );

        // Subsequent get must return 404.
        let err = expect_err_status(
            get_cr(State(state.clone()), Path((group, version, plural, name))).await,
            "get after delete must return 404",
        );
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // delete_cr on a non-existent object must return 404.
    // Deleting a missing cluster-scoped CR must not silently succeed.
    #[tokio::test]
    async fn cluster_scoped_delete_cr_missing_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let err = expect_err_status(
            delete_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "nonexistent".to_string(),
                )),
            )
            .await,
            "delete on missing object must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // delete_cr with a namespaced CRD must return 404 (wrong scope).
    #[tokio::test]
    async fn cluster_scoped_delete_cr_with_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let err = expect_err_status(
            delete_cr(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
            )
            .await,
            "namespaced CRD on cluster-scoped delete must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // ---------------------------------------------------------------------------
    // Cluster-scoped patch_cr tests
    // ---------------------------------------------------------------------------

    // patch_cr must apply the merge patch and return the updated object.
    // This verifies the cluster-scoped patch handler — symmetric to
    // `patch_cr_namespaced_applies_merge_patch`.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_applies_merge_patch() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "patch-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body =
            Bytes::from(serde_json::json!({ "spec": { "color": "purple" } }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "cluster-scoped patch must succeed"
        );

        // Verify the patch was applied.
        let resp = match get_cr(State(state.clone()), Path((group, version, plural, name))).await {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after patch"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["spec"]["color"], "purple",
            "spec.color must be updated by patch"
        );
    }

    // patch_cr with wrong Content-Type must return 415.
    // This verifies validate_patch_content_type fires on the cluster-scoped path.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_rejects_wrong_content_type() {
        let state = make_state();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "my-widget".to_string(),
                )),
                headers,
                Bytes::from(b"{}".to_vec()),
            )
            .await,
            "wrong content type must return 415",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 415, "wrong content type must return 415");
    }

    // patch_cr on a non-existent object must return 404.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_missing_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "nonexistent".to_string(),
                )),
                headers,
                Bytes::from(serde_json::json!({ "spec": {} }).to_string()),
            )
            .await,
            "patch on missing object must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // patch_cr with a namespaced CRD must return 404 (wrong scope).
    #[tokio::test]
    async fn cluster_scoped_patch_cr_with_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
                headers,
                Bytes::from(serde_json::json!({ "spec": {} }).to_string()),
            )
            .await,
            "namespaced CRD on cluster-scoped patch must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // patch_cr strips .status when the CRD declares a status subresource.
    // Controllers must use PATCH /status for status updates; the main patch endpoint
    // must silently drop any .status in the patch to prevent accidental overwrites.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_strips_status_when_has_status_subresource() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "status-patch-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!({
                "spec": { "color": "orange" },
                "status": { "ready": true, "message": "MUST_NOT_BE_STORED" }
            })
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "patch must succeed"
        );

        let resp = match get_cr(State(state.clone()), Path((group, version, plural, name))).await {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            obj["status"].is_null() || obj.get("status").is_none(),
            "status must NOT be stored by main PATCH when status subresource is declared"
        );
    }

    // ---------------------------------------------------------------------------
    // get_cr_status tests
    // ---------------------------------------------------------------------------

    // get_cr_status must return the full object for a cluster-scoped CR.
    // The status field is embedded in the object — this handler is equivalent to
    // get_cr for CRs (there is no separate .status document).
    #[tokio::test]
    async fn get_cr_status_cluster_scoped_returns_object() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "status-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp =
            match get_cr_status(State(state.clone()), Path((group, version, plural, name))).await {
                Ok(r) => r,
                Err(_) => panic!("get_cr_status must succeed for existing cluster-scoped CR"),
            };
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "get_cr_status must return 200 for existing object"
        );
    }

    // get_cr_status for a missing cluster-scoped CR must return 404.
    #[tokio::test]
    async fn get_cr_status_missing_cluster_scoped_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let err = expect_err_status(
            get_cr_status(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "nonexistent".to_string(),
                )),
            )
            .await,
            "get_cr_status on missing object must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // get_cr_status for a namespaced CRD via the cluster-scoped path must return 404.
    // The cluster-scoped status endpoint must not serve namespaced CRDs.
    #[tokio::test]
    async fn get_cr_status_with_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let err = expect_err_status(
            get_cr_status(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
            )
            .await,
            "get_cr_status with namespaced CRD must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // ---------------------------------------------------------------------------
    // Additional coverage for validate_cr_name and list_cr normal path
    // ---------------------------------------------------------------------------

    // validate_cr_name must reject names with invalid characters (e.g. spaces or underscores).
    // Only ASCII alphanumeric, hyphens, and dots are permitted in CR names; other characters
    // would create objects that can't be round-tripped through standard Kubernetes tooling.
    #[test]
    fn validate_cr_name_rejects_invalid_chars() {
        let err = match validate_cr_name("invalid name!") {
            Err(e) => e,
            Ok(_) => panic!("expected Err for name with invalid chars"),
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 400,
            "invalid chars must return 400 Bad Request"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("invalid characters"),
            "error message must mention invalid characters"
        );
    }

    // list_cr (cluster-scoped, non-watch) must return an empty list when no CRs exist.
    // This tests the normal list path — distinct from the watch and 404 paths already
    // covered by other tests.
    #[tokio::test]
    async fn cluster_scoped_list_cr_empty() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must succeed even when empty"),
        };

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "cluster-scoped list must return 200"
        );
    }

    // list_cr (cluster-scoped, non-watch) must include created items.
    #[tokio::test]
    async fn cluster_scoped_list_cr_returns_created_items() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                widget_body("listed-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must succeed after create"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ---------------------------------------------------------------------------
    // Additional boon schema validation coverage
    // ---------------------------------------------------------------------------

    // type:string with null value must fail.
    // Ensures boon catches null values where a string is expected.
    #[test]
    fn schema_null_value_type_error() {
        let schema = serde_json::json!({ "type": "string" });
        assert!(
            check_schema(&serde_json::Value::Null, schema).is_err(),
            "type:string must reject null"
        );
    }

    // type:string with array value must fail.
    // Ensures boon catches array values where a string is expected.
    #[test]
    fn schema_array_value_type_error() {
        let schema = serde_json::json!({ "type": "string" });
        assert!(
            check_schema(&serde_json::json!([1, 2, 3]), schema).is_err(),
            "type:string must reject an array"
        );
    }

    // type:number accepts floats.
    // The type constraint "number" must accept floating-point values.
    #[test]
    fn schema_number_type_accepts_float() {
        let schema = serde_json::json!({ "type": "number" });
        assert!(
            check_schema(&serde_json::json!(1.5), schema).is_ok(),
            "type:number must accept a float value"
        );
    }

    // type:number rejects a string.
    #[test]
    fn schema_number_type_rejects_string() {
        let schema = serde_json::json!({ "type": "number" });
        assert!(
            check_schema(&serde_json::json!("not-a-number"), schema).is_err(),
            "type:number must reject a string"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression: RevisionMismatch must return 409, not 500 (mayor-5yfc)
    // ---------------------------------------------------------------------------

    // store_err_cr must map StoreError::RevisionMismatch to 409 Conflict.
    // Before the fix this arm fell through to the `other` branch and returned 500,
    // which misleads clients into thinking the server is broken rather than indicating
    // that they need to re-fetch and retry with the current resourceVersion.
    #[tokio::test]
    async fn replace_cr_with_wrong_resource_version_returns_409() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "rv-widget".to_string();

        // Create the CR — this assigns resourceVersion 1 (or similar).
        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Attempt replace with resourceVersion: "999" — a non-zero value that won't match.
        // The store will reject this with StoreError::RevisionMismatch, which must
        // produce HTTP 409 (Conflict), not 500 (Internal Server Error).
        // (resourceVersion "0" would produce AlreadyExists, not RevisionMismatch.)
        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name, "resourceVersion": "999" },
                "spec": { "color": "green" }
            })
            .to_string(),
        );

        let result = replace_cr(
            State(state.clone()),
            Path((group.clone(), version.clone(), plural.clone(), name.clone())),
            axum::http::HeaderMap::new(),
            update_body,
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected Err for wrong resourceVersion"),
        };

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 409,
            "revision mismatch must return 409 Conflict, not 500 (got: {json})"
        );
        assert_eq!(
            json["reason"], "Conflict",
            "reason must be Conflict (got: {json})"
        );
    }

    // replace_cr_namespaced with a stale resourceVersion must return 409 Conflict (mayor-gg9u).
    // Optimistic concurrency control (OCC) protects against lost updates: if a client sends
    // a PUT with a resourceVersion that no longer matches the stored revision, the server
    // must reject the write with 409 rather than silently overwriting concurrent changes.
    #[tokio::test]
    async fn replace_cr_namespaced_with_stale_resource_version_returns_409() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "occ-app".to_string();

        // Create the CR — this assigns an initial resourceVersion.
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Attempt replace with resourceVersion: "999" — a non-zero value that won't match
        // the actual stored revision. The store rejects this with RevisionMismatch, which
        // must produce HTTP 409 (not 500). Using "0" would yield AlreadyExists instead.
        let stale_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns, "resourceVersion": "999" },
                "spec": { "destination": { "namespace": "production" } }
            })
            .to_string(),
        );

        let err = expect_err_status(
            replace_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                axum::http::HeaderMap::new(),
                stale_body,
            )
            .await,
            "replace with stale resourceVersion must return 409",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 409,
            "stale resourceVersion must return 409 Conflict (got: {json})"
        );
        assert_eq!(
            json["reason"], "Conflict",
            "reason must be Conflict (got: {json})"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression: empty-group list response must not produce "/v1alpha1" apiVersion (mayor-q04t)
    // ---------------------------------------------------------------------------

    // build_list_response must produce apiVersion="v1alpha1" (not "/v1alpha1") when group="".
    // A leading slash in apiVersion is malformed and breaks kubectl and client-go parsing.
    // The old inlined `format!("{group}/{version}")` did not check for empty group; delegating
    // to build_list_response fixes this because that function has the guard:
    //   if group.is_empty() { version } else { format!("{}/{}", group, version) }
    #[test]
    fn build_list_response_empty_group_omits_slash() {
        let signing_key: &[u8; 32] = b"test-signing-key-32-bytes-padded";
        let body = super::super::generic::build_list_response(
            "Foo",
            "", // empty group
            "v1alpha1",
            42,
            vec![],
            None,
            None,
            signing_key,
        );
        let api_version = body["apiVersion"].as_str().unwrap_or("");
        assert_eq!(
            api_version, "v1alpha1",
            "empty group must produce apiVersion=\"v1alpha1\", not \"/v1alpha1\" (got: {api_version:?})"
        );
        assert_eq!(
            body["kind"].as_str().unwrap_or(""),
            "FooList",
            "kind must be <Kind>List"
        );
    }

    // Verify that list_cr routes through build_list_response by checking that a normal
    // (non-empty group) list response has the correct apiVersion format.
    // This is an integration smoke test for the code path — the unit test above verifies
    // the empty-group behavior directly.
    #[tokio::test]
    async fn list_cr_response_has_correct_api_version() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must succeed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let api_version = body["apiVersion"].as_str().unwrap_or("");
        assert_eq!(
            api_version, "example.io/v1",
            "non-empty group must produce apiVersion=\"group/version\" (got: {api_version:?})"
        );
    }

    // -- CRD conversion webhook tests --

    /// When a CRD has only one version with storage:true and no conversion config,
    /// get_cr must return the stored object as-is even if the URL version differs.
    /// This is the no-conversion baseline: stored version == requested version.
    #[tokio::test]
    async fn get_cr_same_version_no_conversion() {
        let state = make_state();

        // Single-version CRD (v1 is both storage and requested).
        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "widgets.example.com"},
            "spec": {
                "group": "example.com",
                "names": {"plural": "widgets", "singular": "widget", "kind": "Widget"},
                "scope": "Cluster",
                "versions": [{"name": "v1", "served": true, "storage": true}]
            }
        });
        state
            .store
            .put(
                "/registry/apiextensions.k8s.io/customresourcedefinitions/widgets.example.com",
                bytes::Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Store a widget under v1.
        let widget = serde_json::json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": {"name": "my-widget"},
            "spec": {"color": "blue"}
        });
        state
            .store
            .put(
                "/registry/cr/example.com/v1/widgets/my-widget",
                bytes::Bytes::from(serde_json::to_vec(&widget).unwrap()),
                None,
            )
            .await
            .unwrap();

        // GET the widget at v1 — same as storage version, no conversion needed.
        let resp = match get_cr(
            State(state),
            Path((
                "example.com".into(),
                "v1".into(),
                "widgets".into(),
                "my-widget".into(),
            )),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["spec"]["color"], "blue",
            "stored object must be returned unchanged"
        );
    }

    /// When a CRD has two versions (v1alpha1 as storage, v1 as served) and no conversion
    /// webhook is configured, GET for v1 must fall back to the v1alpha1 stored object
    /// and return it as-is. This is the no-webhook-conversion case.
    #[tokio::test]
    async fn get_cr_different_version_no_webhook_returns_stored_object() {
        let state = make_state();

        // CRD with v1alpha1 (storage) and v1 (served), no conversion webhook.
        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "widgets.example.com"},
            "spec": {
                "group": "example.com",
                "names": {"plural": "widgets", "singular": "widget", "kind": "Widget"},
                "scope": "Cluster",
                "versions": [
                    {"name": "v1alpha1", "served": true, "storage": true},
                    {"name": "v1", "served": true, "storage": false}
                ]
            }
        });
        state
            .store
            .put(
                "/registry/apiextensions.k8s.io/customresourcedefinitions/widgets.example.com",
                bytes::Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Store widget under v1alpha1 (the storage version).
        let widget = serde_json::json!({
            "apiVersion": "example.com/v1alpha1",
            "kind": "Widget",
            "metadata": {"name": "my-widget"},
            "spec": {"color": "blue"}
        });
        state
            .store
            .put(
                "/registry/cr/example.com/v1alpha1/widgets/my-widget",
                bytes::Bytes::from(serde_json::to_vec(&widget).unwrap()),
                None,
            )
            .await
            .unwrap();

        // GET at v1 — no conversion webhook, falls through to stored v1alpha1 object.
        // The stored object is returned as-is (no conversion attempted without webhook).
        let resp = match get_cr(
            State(state),
            Path((
                "example.com".into(),
                "v1".into(),
                "widgets".into(),
                "my-widget".into(),
            )),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed when no conversion is needed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Without a conversion webhook, the v1alpha1 stored data is returned unchanged.
        assert_eq!(
            body["spec"]["color"], "blue",
            "stored v1alpha1 object must be returned when no webhook is configured"
        );
    }

    /// find_crd extracts the storage version correctly from the CRD spec.
    /// If the storage version is wrong, conversion fallback uses the wrong key and
    /// returns 404 or a wrong object instead of calling the webhook.
    #[tokio::test]
    async fn find_crd_extracts_storage_version() {
        let state = make_state();

        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "gadgets.example.com"},
            "spec": {
                "group": "example.com",
                "names": {"plural": "gadgets", "singular": "gadget", "kind": "Gadget"},
                "scope": "Cluster",
                "versions": [
                    {"name": "v1alpha1", "served": true, "storage": true},
                    {"name": "v1", "served": true, "storage": false}
                ]
            }
        });
        state
            .store
            .put(
                "/registry/apiextensions.k8s.io/customresourcedefinitions/gadgets.example.com",
                bytes::Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .unwrap();

        let ctx = match find_crd(&state, "example.com", "v1", "gadgets").await {
            Ok(c) => c,
            Err(_) => panic!("find_crd must succeed for a matching CRD"),
        };
        assert_eq!(
            ctx.storage_version, "v1alpha1",
            "find_crd must extract the version marked storage:true as storage_version"
        );
    }

    /// find_crd extracts conversion webhook clientConfig when strategy is Webhook.
    /// If this is wrong, the conversion webhook call is skipped or uses the wrong endpoint.
    #[tokio::test]
    async fn find_crd_extracts_conversion_webhook_config() {
        let state = make_state();

        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "gadgets.example.com"},
            "spec": {
                "group": "example.com",
                "names": {"plural": "gadgets", "singular": "gadget", "kind": "Gadget"},
                "scope": "Cluster",
                "versions": [
                    {"name": "v1alpha1", "served": true, "storage": true},
                    {"name": "v1", "served": true, "storage": false}
                ],
                "conversion": {
                    "strategy": "Webhook",
                    "webhook": {
                        "clientConfig": {
                            "url": "https://converter.example.com/convert"
                        }
                    }
                }
            }
        });
        state
            .store
            .put(
                "/registry/apiextensions.k8s.io/customresourcedefinitions/gadgets.example.com",
                bytes::Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .unwrap();

        let ctx = match find_crd(&state, "example.com", "v1", "gadgets").await {
            Ok(c) => c,
            Err(_) => panic!("find_crd must succeed for a matching CRD"),
        };
        assert!(
            ctx.conversion_webhook_client_config.is_some(),
            "find_crd must extract conversion webhook clientConfig when strategy=Webhook"
        );
        let cfg = ctx.conversion_webhook_client_config.unwrap();
        assert_eq!(
            cfg["url"].as_str(),
            Some("https://converter.example.com/convert"),
            "clientConfig URL must be extracted correctly"
        );
    }

    // ---------------------------------------------------------------------------
    // call_conversion_webhook error paths (mayor-q402)
    // ---------------------------------------------------------------------------

    /// Start an axum router on a random local TCP port and return the base URL.
    /// The server runs until the returned JoinHandle is dropped/aborted.
    async fn start_mock_conversion_server(
        router: axum::Router,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock server must not fail");
        });
        (format!("http://{addr}"), handle)
    }

    fn make_state_for_conversion() -> AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    /// call_conversion_webhook must return Err when the response includes
    /// result.status="Failure". Conversion webhooks that reject the request
    /// (e.g. unsupported conversion direction) must propagate as errors so
    /// the apiserver rejects the client request rather than returning corrupt data.
    #[tokio::test]
    async fn call_conversion_webhook_returns_err_on_failure_status() {
        use axum::routing::post;
        use axum::Router;

        let router = Router::new().route(
            "/convert",
            post(|| async {
                axum::Json(serde_json::json!({
                    "apiVersion": "apiextensions.k8s.io/v1",
                    "kind": "ConversionReview",
                    "response": {
                        "uid": "test-uid",
                        "result": {
                            "status": "Failure",
                            "message": "unsupported conversion direction"
                        }
                    }
                }))
            }),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "call_conversion_webhook must return Err when result.status=Failure"
        );
        let err_msg = serde_json::to_string(&result.unwrap_err().1).unwrap();
        assert!(
            err_msg.contains("unsupported conversion direction"),
            "error must include the webhook's failure message"
        );
    }

    /// call_conversion_webhook must return Err when the webhook returns an empty
    /// convertedObjects array. Receiving 0 objects for N input objects is semantically
    /// invalid — the caller has no objects to serve and cannot proceed.
    #[tokio::test]
    async fn call_conversion_webhook_returns_err_when_converted_objects_empty() {
        use axum::routing::post;
        use axum::Router;

        let router = Router::new().route(
            "/convert",
            post(|| async {
                axum::Json(serde_json::json!({
                    "apiVersion": "apiextensions.k8s.io/v1",
                    "kind": "ConversionReview",
                    "response": {
                        "uid": "test-uid",
                        "result": { "status": "Success" },
                        "convertedObjects": []  // empty — must be rejected
                    }
                }))
            }),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "call_conversion_webhook must return Err when convertedObjects is empty"
        );
    }

    /// call_conversion_webhook must return Err when the HTTP call fails (bad URL).
    /// Network errors must be propagated as errors — callers must not silently
    /// succeed with the unconverted objects.
    #[tokio::test]
    async fn call_conversion_webhook_returns_err_on_http_failure() {
        let state = make_state_for_conversion();
        // Port 1 is never open — connection will be refused immediately.
        let client_config = serde_json::json!({ "url": "http://127.0.0.1:1/convert" });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "call_conversion_webhook must return Err when HTTP call fails (bad URL)"
        );
    }

    /// call_conversion_webhook must return Err when the response is not valid JSON.
    /// A webhook returning malformed bytes (e.g. a 500 HTML error page) must not
    /// panic or silently succeed — it must be detected and rejected.
    #[tokio::test]
    async fn call_conversion_webhook_returns_err_on_malformed_json_response() {
        use axum::routing::post;
        use axum::Router;

        let router = Router::new().route(
            "/convert",
            post(|| async {
                // Return plain text, not JSON — simulates an upstream error page.
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error (not JSON)",
                )
            }),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "call_conversion_webhook must return Err when response is not valid JSON"
        );
    }

    /// find_crd must NOT extract conversion config when strategy is None (no conversion).
    #[tokio::test]
    async fn find_crd_no_conversion_config_when_strategy_is_none() {
        let state = make_state();

        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "gadgets.example.com"},
            "spec": {
                "group": "example.com",
                "names": {"plural": "gadgets", "singular": "gadget", "kind": "Gadget"},
                "scope": "Cluster",
                "versions": [
                    {"name": "v1alpha1", "served": true, "storage": true},
                    {"name": "v1", "served": true, "storage": false}
                ],
                "conversion": {
                    "strategy": "None"
                }
            }
        });
        state
            .store
            .put(
                "/registry/apiextensions.k8s.io/customresourcedefinitions/gadgets.example.com",
                bytes::Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .unwrap();

        let ctx = match find_crd(&state, "example.com", "v1", "gadgets").await {
            Ok(c) => c,
            Err(_) => panic!("find_crd must succeed for a matching CRD"),
        };
        assert!(
            ctx.conversion_webhook_client_config.is_none(),
            "find_crd must not extract conversion config when strategy is not Webhook"
        );
    }

    // ---------------------------------------------------------------------------
    // PartialObjectMetadata media type negotiation (mayor-ve5z)
    // ---------------------------------------------------------------------------

    /// wants_partial_object_metadata must detect the kcm metadatainformer Accept header.
    /// The GC sends: application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,
    ///               application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json
    /// Without this detection the reflector gets full CR objects it can't decode as PartialObjectMetadata,
    /// causing it to restart without ever receiving the initial-events-end BOOKMARK.
    #[test]
    fn wants_pom_detects_partial_object_metadata_accept_header() {
        // Real kcm metadatainformer Accept header.
        let accept = "application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json";
        assert!(
            wants_partial_object_metadata(accept),
            "must detect as=PartialObjectMetadata in kcm metadatainformer Accept header"
        );
    }

    #[test]
    fn wants_pom_detects_partial_object_metadata_list() {
        let accept = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1";
        assert!(
            wants_partial_object_metadata(accept),
            "must detect as=PartialObjectMetadataList"
        );
    }

    #[test]
    fn wants_pom_returns_false_for_plain_json() {
        assert!(
            !wants_partial_object_metadata("application/json"),
            "plain application/json must NOT trigger POM transformation"
        );
    }

    /// to_partial_object_metadata must strip spec/status and set the correct apiVersion/kind.
    /// The GC needs metadata (ownerReferences, finalizers) but not spec/status — sending full
    /// objects causes the reflector to fail decoding and never receive the initial-events-end BOOKMARK.
    #[test]
    fn to_pom_strips_spec_and_sets_correct_kind() {
        let full_cr = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": { "name": "w1", "uid": "abc", "ownerReferences": [] },
            "spec": { "color": "blue" },
            "status": { "ready": true }
        });
        let pom = to_partial_object_metadata(&full_cr);
        assert_eq!(pom["apiVersion"], "meta.k8s.io/v1");
        assert_eq!(pom["kind"], "PartialObjectMetadata");
        assert_eq!(pom["metadata"]["name"], "w1");
        assert_eq!(pom["metadata"]["uid"], "abc");
        // spec and status must be absent — GC does not need them.
        assert!(
            pom.get("spec").is_none() || pom["spec"].is_null(),
            "spec must be absent in POM"
        );
        assert!(
            pom.get("status").is_none() || pom["status"].is_null(),
            "status must be absent in POM"
        );
    }

    /// LIST with as=PartialObjectMetadataList Accept header must return PartialObjectMetadataList
    /// with each item as PartialObjectMetadata (no spec). This is the critical path for the kcm
    /// garbage collector — it lists resources using this media type.
    #[tokio::test]
    async fn list_cr_with_pom_accept_returns_partial_object_metadata_list() {
        let state = make_state();
        install_cluster_crd(&state).await;

        // Create a widget with spec so we can verify spec is stripped.
        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                widget_body("pom-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let mut accept_headers = axum::http::HeaderMap::new();
        accept_headers.insert(
            axum::http::header::ACCEPT,
            "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
                .parse()
                .unwrap(),
        );

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            accept_headers,
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list with POM accept must succeed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            body["kind"], "PartialObjectMetadataList",
            "kind must be PartialObjectMetadataList when Accept requests POM"
        );
        assert_eq!(
            body["apiVersion"], "meta.k8s.io/v1",
            "apiVersion must be meta.k8s.io/v1 for POM list"
        );

        let items = body["items"].as_array().expect("items must be an array");
        assert_eq!(items.len(), 1, "must have exactly one item");
        assert_eq!(
            items[0]["kind"], "PartialObjectMetadata",
            "each item kind must be PartialObjectMetadata"
        );
        assert_eq!(
            items[0]["apiVersion"], "meta.k8s.io/v1",
            "each item apiVersion must be meta.k8s.io/v1"
        );
        assert_eq!(
            items[0]["metadata"]["name"], "pom-widget",
            "item metadata.name must be preserved"
        );
        assert!(
            items[0].get("spec").is_none() || items[0]["spec"].is_null(),
            "spec must be absent in PartialObjectMetadata item — GC does not need it \
             and its presence causes the reflector to fail decoding"
        );
    }

    /// WATCH with as=PartialObjectMetadata Accept header must emit ADDED events shaped as
    /// PartialObjectMetadata. Without this, the kcm reflector fails to decode the objects
    /// and the metadatainformer never syncs, blocking all GC-dependent controllers.
    #[tokio::test]
    async fn list_cr_watch_with_pom_accept_emits_partial_object_metadata_events() {
        let state = make_state();
        install_cluster_crd(&state).await;

        // Write a widget BEFORE subscribing so the ring buffer replays it.
        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                widget_body("watch-pom-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Accept header as sent by kcm metadatainformer.
        let mut accept_headers = axum::http::HeaderMap::new();
        accept_headers.insert(
            axum::http::header::ACCEPT,
            "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json"
                .parse()
                .unwrap(),
        );

        // Use timeout_seconds=1 so the stream closes after 1s, allowing to_bytes to return
        // with the ring-buffer events. The stream stays open (correct behavior per mayor-8tiu
        // fix: _store_keepalive keeps the store alive), so we need a bounded timeout.
        let query_with_timeout = super::super::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: Some(1),
        };

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            accept_headers,
            query_with_timeout,
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch with POM accept must succeed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "watch response must use chunked encoding"
        );

        // Read all events until the stream closes (timeout_seconds=1) or the 3-second guard.
        // The ring buffer replays the pre-existing widget as ADDED before the live-event wait.
        let body = resp.into_body();
        let bytes = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await
        .unwrap_or(Ok(bytes::Bytes::new()))
        .unwrap_or_default();

        let text = std::str::from_utf8(&bytes).unwrap_or("");
        let events: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        // The ring buffer must replay the ADDED event for the pre-existing widget.
        let added: Vec<_> = events.iter().filter(|e| e["type"] == "ADDED").collect();
        assert!(
            !added.is_empty(),
            "POM watch must emit at least one ADDED event from ring buffer; \
             without it the GC metadatainformer cache never syncs"
        );
        assert_eq!(
            added[0]["object"]["kind"], "PartialObjectMetadata",
            "ADDED event object kind must be PartialObjectMetadata, not the full CR kind — \
             full objects cause the kcm reflector to fail decoding and restart"
        );
        assert_eq!(
            added[0]["object"]["apiVersion"], "meta.k8s.io/v1",
            "ADDED event object apiVersion must be meta.k8s.io/v1"
        );
        assert_eq!(
            added[0]["object"]["metadata"]["name"], "watch-pom-widget",
            "ADDED event metadata.name must match"
        );
        assert!(
            added[0]["object"].get("spec").is_none() || added[0]["object"]["spec"].is_null(),
            "spec must be absent in POM ADDED event — the kcm scheme does not know Gateway, Widget etc."
        );
    }

    // ---------------------------------------------------------------------------
    // store_err_cr unit tests — all four branches must map to the right status code
    // ---------------------------------------------------------------------------

    /// store_err_cr must map NotFound to 404. This is the error users see when a
    /// CR they try to GET or DELETE does not exist — returning 500 would mislead them.
    #[test]
    fn store_err_cr_not_found_returns_404() {
        let err = store_err_cr(
            u7s_store::StoreError::NotFound {
                key: "/registry/cr/example.io/v1/widgets/my-widget".into(),
            },
            "my-widget",
            "Widget",
        );
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    /// store_err_cr must map AlreadyExists to 409. This is the error users see when
    /// they try to create a CR that already exists — 409 Conflict is the correct code.
    #[test]
    fn store_err_cr_already_exists_returns_409() {
        let err = store_err_cr(
            u7s_store::StoreError::AlreadyExists {
                key: "/registry/cr/example.io/v1/widgets/my-widget".into(),
            },
            "my-widget",
            "Widget",
        );
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 409);
        assert_eq!(json["reason"], "AlreadyExists");
    }

    /// store_err_cr must map RevisionMismatch to 409 Conflict with a message that
    /// explains the resource-version mismatch. This is the OCC guard — clients that
    /// send a stale resourceVersion receive a clear conflict error, not a silent failure.
    #[test]
    fn store_err_cr_revision_mismatch_returns_409() {
        let err = store_err_cr(
            u7s_store::StoreError::RevisionMismatch {
                expected: 42,
                current: 99,
            },
            "my-widget",
            "Widget",
        );
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 409);
        // Message must mention the version numbers so the client knows what happened.
        let msg = json["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("42") && msg.contains("99"),
            "conflict message must contain expected (42) and current (99) revisions, got: {msg}"
        );
    }

    /// store_err_cr maps RevisionMismatch to 409 with a message explaining the OCC conflict.
    /// The message must contain both expected and current revision numbers so the client
    /// can understand what version it should use for the retry.
    #[test]
    fn store_err_cr_revision_mismatch_message_contains_revisions() {
        let err = store_err_cr(
            u7s_store::StoreError::RevisionMismatch {
                expected: 1,
                current: 5,
            },
            "my-widget",
            "Widget",
        );
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        let msg = json["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("1") && msg.contains("5"),
            "conflict message must contain expected (1) and current (5) revision numbers, got: {msg}"
        );
    }

    // ---------------------------------------------------------------------------
    // cr_store_key and cr_list_prefix unit tests
    // ---------------------------------------------------------------------------

    /// cr_store_key must use the namespace segment for namespaced resources and
    /// omit it for cluster-scoped resources. The key structure is relied upon by
    /// list (prefix scan), get, put, and delete — a wrong key silently stores or
    /// retrieves data under an unexpected path.
    #[test]
    fn cr_store_key_namespaced_includes_namespace() {
        let key = cr_store_key("example.io", "v1", "widgets", Some("default"), "my-widget");
        assert_eq!(
            key, "/registry/cr/example.io/v1/widgets/default/my-widget",
            "namespaced key must include the namespace segment"
        );
    }

    #[test]
    fn cr_store_key_cluster_scoped_omits_namespace() {
        let key = cr_store_key("example.io", "v1", "widgets", None, "my-widget");
        assert_eq!(
            key, "/registry/cr/example.io/v1/widgets/my-widget",
            "cluster-scoped key must omit the namespace segment"
        );
    }

    /// cr_list_prefix must produce a prefix that correctly scopes the list scan.
    /// A prefix that is too broad (e.g. missing trailing slash) could scan across
    /// all namespaces or all resource types.
    #[test]
    fn cr_list_prefix_namespaced_ends_with_namespace_slash() {
        let prefix = cr_list_prefix("example.io", "v1", "widgets", Some("default"));
        assert_eq!(
            prefix, "/registry/cr/example.io/v1/widgets/default/",
            "namespaced prefix must end with namespace and slash"
        );
    }

    #[test]
    fn cr_list_prefix_cluster_scoped_ends_with_plural_slash() {
        let prefix = cr_list_prefix("example.io", "v1", "widgets", None);
        assert_eq!(
            prefix, "/registry/cr/example.io/v1/widgets/",
            "cluster-scoped prefix must end with plural and slash"
        );
    }

    // ---------------------------------------------------------------------------
    // resolve_conversion_webhook_url — service-based and error paths
    // ---------------------------------------------------------------------------

    /// resolve_conversion_webhook_url must return an error when clientConfig has
    /// neither a url nor a service field. Without a reachable endpoint the conversion
    /// cannot proceed, and silently returning an empty URL would call a bogus address.
    #[tokio::test]
    async fn resolve_webhook_url_empty_config_returns_err() {
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({});
        let result = resolve_conversion_webhook_url(&state, &client_config).await;
        assert!(
            result.is_err(),
            "clientConfig with neither url nor service must return Err"
        );
        let err_msg = serde_json::to_string(&result.unwrap_err().1).unwrap();
        assert!(
            err_msg.contains("neither url nor service"),
            "error must mention missing url/service, got: {err_msg}"
        );
    }

    /// resolve_conversion_webhook_url must return an error when the service field
    /// is present but the service object does not exist in the store.
    /// The error must surface as an internal error so the apiserver rejects the
    /// request rather than attempting to connect to an unknown endpoint.
    #[tokio::test]
    async fn resolve_webhook_url_service_not_found_returns_err() {
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({
            "service": {
                "namespace": "kube-system",
                "name": "webhook-svc",
                "port": 443,
                "path": "/convert"
            }
        });
        let result = resolve_conversion_webhook_url(&state, &client_config).await;
        assert!(result.is_err(), "service not in store must return Err");
        let err_msg = serde_json::to_string(&result.unwrap_err().1).unwrap();
        assert!(
            err_msg.contains("not found"),
            "error must mention service not found, got: {err_msg}"
        );
    }

    /// resolve_conversion_webhook_url must return an error when the service exists
    /// in the store but has no spec.clusterIP — without a clusterIP the URL cannot
    /// be built and the webhook call must not proceed.
    #[tokio::test]
    async fn resolve_webhook_url_service_missing_cluster_ip_returns_err() {
        let state = make_state_for_conversion();

        // Seed a service object with no clusterIP.
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "webhook-svc", "namespace": "kube-system" },
            "spec": { "ports": [{"port": 443}] }
            // no clusterIP field
        });
        state
            .store
            .put(
                "/registry/services/kube-system/webhook-svc",
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let client_config = serde_json::json!({
            "service": {
                "namespace": "kube-system",
                "name": "webhook-svc",
                "port": 443,
                "path": "/convert"
            }
        });
        let result = resolve_conversion_webhook_url(&state, &client_config).await;
        assert!(result.is_err(), "service without clusterIP must return Err");
        let err_msg = serde_json::to_string(&result.unwrap_err().1).unwrap();
        assert!(
            err_msg.contains("clusterIP"),
            "error must mention missing clusterIP, got: {err_msg}"
        );
    }

    /// resolve_conversion_webhook_url must build the correct https URL from a
    /// service reference. This is the primary in-cluster webhook path: the
    /// conversion webhook is deployed as a Service with a known clusterIP.
    #[tokio::test]
    async fn resolve_webhook_url_service_path_returns_correct_url() {
        let state = make_state_for_conversion();

        // Seed a service object with a clusterIP.
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "webhook-svc", "namespace": "kube-system" },
            "spec": { "clusterIP": "10.96.0.50", "ports": [{"port": 9443}] }
        });
        state
            .store
            .put(
                "/registry/services/kube-system/webhook-svc",
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let client_config = serde_json::json!({
            "service": {
                "namespace": "kube-system",
                "name": "webhook-svc",
                "port": 9443,
                "path": "/convert"
            }
        });
        let result = resolve_conversion_webhook_url(&state, &client_config).await;
        assert!(
            result.is_ok(),
            "service with clusterIP must resolve successfully"
        );
        let url = match result {
            Ok(u) => u,
            Err(_) => panic!("expected Ok but got Err"),
        };
        assert_eq!(
            url, "https://10.96.0.50:9443/convert",
            "URL must use clusterIP and port from service, got: {url}"
        );
    }

    /// resolve_conversion_webhook_url must return an error when the service field is
    /// present but has no name. A nameless service reference cannot be looked up.
    #[tokio::test]
    async fn resolve_webhook_url_service_missing_name_returns_err() {
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({
            "service": {
                "namespace": "kube-system"
                // no "name" field
            }
        });
        let result = resolve_conversion_webhook_url(&state, &client_config).await;
        assert!(result.is_err(), "service without name must return Err");
        let err_msg = serde_json::to_string(&result.unwrap_err().1).unwrap();
        assert!(
            err_msg.contains("no name"),
            "error must mention missing service name, got: {err_msg}"
        );
    }

    /// POST a namespaced CR to a namespace whose status.phase is "Terminating" must return 403.
    /// Real kube-apiserver rejects all new object creation in a Terminating namespace;
    /// without this check our apiserver would allow CRs to be created in dying namespaces,
    /// breaking the namespace GC lifecycle.
    #[tokio::test]
    async fn create_cr_namespaced_rejects_terminating_namespace() {
        use axum::extract::State;
        use bytes::Bytes;
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

        // Install a namespaced CRD so we have a real resource to try to create.
        install_namespaced_crd(&state).await;

        // Seed the namespace object with status.phase = "Terminating".
        let ns_key = "/registry/namespaces/dying-ns";
        let ns_obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "dying-ns" },
            "status": { "phase": "Terminating" }
        });
        store
            .put(
                ns_key,
                Bytes::from(serde_json::to_vec(&ns_obj).unwrap()),
                None,
            )
            .await
            .expect("seed terminating namespace");

        let result = create_cr_namespaced(
            State(state),
            axum::extract::Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "dying-ns".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            app_body("my-app", "dying-ns"),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "POST CR to Terminating namespace must be rejected — namespace GC would leave orphaned CRs otherwise"
            ),
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 403,
            "Terminating namespace must return 403 Forbidden"
        );
        assert_eq!(json["reason"], "Forbidden");
        assert!(
            json["message"].as_str().unwrap_or("").contains("dying-ns"),
            "error message must name the namespace"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("being terminated"),
            "error message must say namespace is being terminated"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression: deleted CRD group must return 410 Gone, not 404
    //
    // When a CRD is deleted, client-go informers watching its endpoints keep
    // retrying on 404 (treats it as transient) but stop on 410 Gone. Without 410,
    // namespace deletion hangs because the GC informer keeps the resource type
    // "alive" from its perspective, preventing the namespace controller from
    // draining all resources and removing the kubernetes finalizer.
    // ---------------------------------------------------------------------------

    // After a CRD is deleted, LIST for its group/version/plural must return 410 Gone.
    // If the fix is reverted (tombstone not written, or find_crd ignores it), this
    // test returns 404 instead of 410 and fails.
    #[tokio::test]
    async fn deleted_crd_group_returns_410_gone_not_404() {
        use crate::handlers::crd;

        let state = make_state();
        install_namespaced_crd(&state).await;

        // Verify the CRD is reachable before deletion.
        assert!(
            find_crd(&state, "argoproj.io", "v1alpha1", "applications")
                .await
                .is_ok(),
            "find_crd must succeed before deletion"
        );

        // Delete the CRD — this must write the tombstone.
        assert!(
            crd::delete_crd(
                State(state.clone()),
                axum::extract::Path("applications.argoproj.io".to_string()),
            )
            .await
            .is_ok(),
            "delete_crd must succeed"
        );

        // Now find_crd must return 410 Gone, not 404 Not Found.
        let err = match find_crd(&state, "argoproj.io", "v1alpha1", "applications").await {
            Ok(_) => panic!("find_crd must fail after CRD deletion"),
            Err(e) => e,
        };

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 410,
            "deleted CRD group must return 410 Gone so informers stop retrying — \
             404 causes infinite retry loops and namespace deletion hangs"
        );
        assert_eq!(
            json["reason"], "Gone",
            "reason must be 'Gone' to match Kubernetes informer semantics"
        );
    }

    // A group that was never registered must still return 404 (not 410).
    // 410 is only valid for groups that existed — an unknown group is a genuine 404.
    #[tokio::test]
    async fn never_registered_group_returns_404_not_410() {
        let state = make_state();

        let err = match find_crd(&state, "never-existed.example.com", "v1", "things").await {
            Ok(_) => panic!("find_crd must fail for unknown group"),
            Err(e) => e,
        };

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 404,
            "never-registered group must return 404 Not Found — \
             returning 410 would mislead informers about a group that was never installed"
        );
        assert_eq!(json["reason"], "NotFound");
    }

    // After a CRD is deleted, list_cr_namespaced must return 410 Gone (not 404).
    // This covers the HTTP handler path that informers actually call.
    #[tokio::test]
    async fn list_cr_namespaced_returns_410_after_crd_deleted() {
        use crate::handlers::crd;

        let state = make_state();
        install_namespaced_crd(&state).await;

        // Delete the CRD.
        crd::delete_crd(
            State(state.clone()),
            axum::extract::Path("applications.argoproj.io".to_string()),
        )
        .await
        .expect("delete_crd must succeed");

        let err = expect_err_status(
            list_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "default".to_string(),
                    "applications".to_string(),
                )),
                axum::http::HeaderMap::new(),
                no_watch_query(),
                "test-user".to_string(),
            )
            .await,
            "list_cr_namespaced must error after CRD deletion",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 410,
            "list after CRD deletion must return 410 Gone, not 404 — \
             404 causes GC informer to retry indefinitely, blocking namespace deletion"
        );
    }
}
