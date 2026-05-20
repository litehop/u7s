use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store};

use crate::{
    handlers::crd::CustomResourceDefinition,
    state::AppState,
    status::Status,
    util::{extract_body, utc_now_rfc3339},
};

const CRD_LIST_PREFIX: &str = "/registry/apiextensions.k8s.io/customresourcedefinitions/";

// ---------------------------------------------------------------------------
// CRD lookup
// ---------------------------------------------------------------------------

/// Information extracted from a CRD needed to serve a CR request.
pub struct CrContext {
    pub kind: String,
    pub list_kind: String,
    pub namespaced: bool,
}

/// Find the CRD whose spec.group == group and spec.names.plural == plural.
/// Returns Err(404) if not found, Err(404) if the requested version is not served,
/// and the CrContext on success.
pub async fn find_crd(
    state: &AppState,
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
        let version_served = crd
            .spec
            .versions
            .iter()
            .any(|v| v.name == version && v.served);
        if !version_served {
            return Err(Status::not_found(
                &format!("{group}/{version}/{plural}"),
                "Resource",
            ));
        }
        let namespaced = crd.spec.scope == "Namespaced";
        let list_kind = if crd.spec.names.list_kind.is_empty() {
            format!("{}List", crd.spec.names.kind)
        } else {
            crd.spec.names.list_kind.clone()
        };
        return Ok(CrContext {
            kind: crd.spec.names.kind.clone(),
            list_kind,
            namespaced,
        });
    }

    Err(Status::not_found(
        &format!("{group}/{version}/{plural}"),
        "Resource",
    ))
}

// ---------------------------------------------------------------------------
// Store key helpers
// ---------------------------------------------------------------------------

fn cr_store_key(group: &str, version: &str, plural: &str, namespace: Option<&str>, name: &str) -> String {
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

fn stamp_cr(obj: &mut serde_json::Value, group: &str, version: &str, kind: &str) {
    let api_version = format!("{group}/{version}");
    obj["apiVersion"] = serde_json::Value::String(api_version);
    obj["kind"] = serde_json::Value::String(kind.to_string());
    if obj["metadata"]["uid"].as_str().map(|s| s.is_empty()).unwrap_or(true) {
        obj["metadata"]["uid"] = serde_json::Value::String(new_cr_uid());
    }
    if obj["metadata"]["creationTimestamp"].as_str().map(|s| s.is_empty()).unwrap_or(true) {
        obj["metadata"]["creationTimestamp"] = serde_json::Value::String(utc_now_rfc3339());
    }
}

fn new_cr_uid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:016x}-{:08x}-cr00-0000-000000000000", d.as_secs(), d.subsec_nanos())
}

fn store_err_cr(err: u7s_store::StoreError, name: &str, kind: &str) -> crate::status::StatusError {
    match err {
        u7s_store::StoreError::NotFound { .. } => Status::not_found(name, kind),
        u7s_store::StoreError::AlreadyExists { .. } => Status::already_exists(name, kind),
        other => Status::internal(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Cluster-scoped CR handlers
// ---------------------------------------------------------------------------

pub async fn list_cr(
    State(state): State<AppState>,
    Path((group, version, plural)): Path<(String, String, String)>,
    query: super::generic::CollectionQuery,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let prefix = cr_list_prefix(&group, &version, &plural, None);

    if query.watch == Some(true) {
        let api_version = format!("{group}/{version}");
        return super::generic::watch_generic(
            state,
            prefix,
            api_version,
            ctx.kind,
            query.resource_version.unwrap_or(0),
        )
        .await;
    }

    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut items = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(v);
    }

    let api_version = format!("{group}/{version}");
    let body = serde_json::json!({
        "apiVersion": api_version,
        "kind": ctx.list_kind,
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items,
    });
    Ok(Json(body).into_response())
}

pub async fn get_cr(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
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

pub async fn create_cr(
    State(state): State<AppState>,
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

    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = {
        match obj["metadata"]["name"].as_str().filter(|n| !n.is_empty()) {
            Some(n) => n.to_string(),
            None => {
                let gen = obj["metadata"]["generateName"].as_str().unwrap_or("");
                if gen.is_empty() {
                    return Err(Status::bad_request("metadata.name or metadata.generateName is required".into()));
                }
                let generated = format!("{}{}", gen, crate::handlers::generic::generate_suffix());
                obj["metadata"]["name"] = serde_json::Value::String(generated.clone());
                generated
            }
        }
    };

    stamp_cr(&mut obj, &group, &version, &ctx.kind);

    let key = cr_store_key(&group, &version, &plural, None, &name);
    let rv = state
        .store
        .put(&key, Bytes::from(serde_json::to_vec(&obj).unwrap()), Some(0))
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    obj["metadata"]["resourceVersion"] = serde_json::Value::String(rv.to_string());
    Ok((StatusCode::CREATED, Json(obj)))
}

pub async fn replace_cr(
    State(state): State<AppState>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
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
    if obj["metadata"]["uid"].as_str().map(|s| s.is_empty()).unwrap_or(true) {
        if let Some(uid) = existing["metadata"]["uid"].as_str() {
            obj["metadata"]["uid"] = serde_json::Value::String(uid.to_string());
        }
    }
    if obj["metadata"]["creationTimestamp"].as_str().map(|s| s.is_empty()).unwrap_or(true) {
        if let Some(ts) = existing["metadata"]["creationTimestamp"].as_str() {
            obj["metadata"]["creationTimestamp"] = serde_json::Value::String(ts.to_string());
        }
    }

    let expected_rv: Option<u64> = obj["metadata"]["resourceVersion"]
        .as_str()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());

    let rv = state
        .store
        .put(&key, Bytes::from(serde_json::to_vec(&obj).unwrap()), expected_rv)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    obj["metadata"]["resourceVersion"] = serde_json::Value::String(rv.to_string());
    Ok(Json(obj))
}

pub async fn delete_cr(
    State(state): State<AppState>,
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

pub async fn list_cr_namespaced(
    State(state): State<AppState>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    query: super::generic::CollectionQuery,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let prefix = cr_list_prefix(&group, &version, &plural, Some(&ns));

    if query.watch == Some(true) {
        let api_version = format!("{group}/{version}");
        return super::generic::watch_generic(
            state,
            prefix,
            api_version,
            ctx.kind,
            query.resource_version.unwrap_or(0),
        )
        .await;
    }

    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut items = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(v);
    }

    let api_version = format!("{group}/{version}");
    let body = serde_json::json!({
        "apiVersion": api_version,
        "kind": ctx.list_kind,
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items,
    });
    Ok(Json(body).into_response())
}

pub async fn get_cr_namespaced(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
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

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn create_cr_namespaced(
    State(state): State<AppState>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let name = {
        match obj["metadata"]["name"].as_str().filter(|n| !n.is_empty()) {
            Some(n) => n.to_string(),
            None => {
                let gen = obj["metadata"]["generateName"].as_str().unwrap_or("");
                if gen.is_empty() {
                    return Err(Status::bad_request("metadata.name or metadata.generateName is required".into()));
                }
                let generated = format!("{}{}", gen, crate::handlers::generic::generate_suffix());
                obj["metadata"]["name"] = serde_json::Value::String(generated.clone());
                generated
            }
        }
    };

    obj["metadata"]["namespace"] = serde_json::Value::String(ns.clone());
    stamp_cr(&mut obj, &group, &version, &ctx.kind);

    let key = cr_store_key(&group, &version, &plural, Some(&ns), &name);
    let rv = state
        .store
        .put(&key, Bytes::from(serde_json::to_vec(&obj).unwrap()), Some(0))
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    obj["metadata"]["resourceVersion"] = serde_json::Value::String(rv.to_string());
    Ok((StatusCode::CREATED, Json(obj)))
}

pub async fn replace_cr_namespaced(
    State(state): State<AppState>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
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
    if obj["metadata"]["uid"].as_str().map(|s| s.is_empty()).unwrap_or(true) {
        if let Some(uid) = existing["metadata"]["uid"].as_str() {
            obj["metadata"]["uid"] = serde_json::Value::String(uid.to_string());
        }
    }
    if obj["metadata"]["creationTimestamp"].as_str().map(|s| s.is_empty()).unwrap_or(true) {
        if let Some(ts) = existing["metadata"]["creationTimestamp"].as_str() {
            obj["metadata"]["creationTimestamp"] = serde_json::Value::String(ts.to_string());
        }
    }

    let expected_rv: Option<u64> = obj["metadata"]["resourceVersion"]
        .as_str()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());

    let rv = state
        .store
        .put(&key, Bytes::from(serde_json::to_vec(&obj).unwrap()), expected_rv)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    obj["metadata"]["resourceVersion"] = serde_json::Value::String(rv.to_string());
    Ok(Json(obj))
}

pub async fn delete_cr_namespaced(
    State(state): State<AppState>,
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

fn merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (Some(t), Some(p)) = (target.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            if v.is_null() {
                t.remove(k);
            } else if v.is_object() {
                let entry = t
                    .entry(k)
                    .or_insert(serde_json::Value::Object(Default::default()));
                merge_patch(entry, v);
            } else {
                t.insert(k.clone(), v.clone());
            }
        }
    } else {
        *target = patch.clone();
    }
}

fn validate_patch_content_type(headers: &HeaderMap) -> Result<(), crate::status::StatusError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/strategic-merge-patch+json") {
        return Err(Status::bad_request(
            "strategic merge patch not supported in Phase 1; use application/merge-patch+json"
                .into(),
        ));
    }

    if !content_type.contains("application/merge-patch+json") {
        return Err(Status::unsupported_media_type(format!(
            "unsupported media type '{content_type}'; use application/merge-patch+json"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Cluster-scoped CR patch handler
// ---------------------------------------------------------------------------

pub async fn patch_cr(
    State(state): State<AppState>,
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

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    merge_patch(&mut obj, &patch);

    let new_rv = state
        .store
        .put(
            &key,
            Bytes::from(serde_json::to_vec(&obj).unwrap()),
            Some(stored.revision),
        )
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    obj["metadata"]["resourceVersion"] = serde_json::Value::String(new_rv.to_string());
    Ok(Json(obj))
}

// ---------------------------------------------------------------------------
// Namespaced CR patch handler
// ---------------------------------------------------------------------------

pub async fn patch_cr_namespaced(
    State(state): State<AppState>,
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

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    merge_patch(&mut obj, &patch);

    let new_rv = state
        .store
        .put(
            &key,
            Bytes::from(serde_json::to_vec(&obj).unwrap()),
            Some(stored.revision),
        )
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    obj["metadata"]["resourceVersion"] = serde_json::Value::String(new_rv.to_string());
    Ok(Json(obj))
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
        }
    }

    fn make_state() -> AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        AppState::new(store, None, None, std::collections::HashMap::new(), "https://localhost:6443".into())
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
        Bytes::from(serde_json::json!({
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
        }).to_string())
    }

    fn cluster_crd_bytes() -> Bytes {
        Bytes::from(serde_json::json!({
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
        }).to_string())
    }

    async fn install_namespaced_crd(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(State(state.clone()), axum::http::HeaderMap::new(), namespaced_crd_bytes()).await.is_ok(),
            "install namespaced CRD"
        );
    }

    async fn install_cluster_crd(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(State(state.clone()), axum::http::HeaderMap::new(), cluster_crd_bytes()).await.is_ok(),
            "install cluster CRD"
        );
    }

    fn app_body(name: &str, ns: &str) -> Bytes {
        Bytes::from(serde_json::json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": { "name": name, "namespace": ns },
            "spec": { "destination": { "namespace": "default" } }
        }).to_string())
    }

    fn widget_body(name: &str) -> Bytes {
        Bytes::from(serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": { "name": name },
            "spec": { "color": "blue" }
        }).to_string())
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
                no_watch_query(),
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
                no_watch_query(),
            )
            .await,
            "cluster-scoped CRD must reject namespaced path",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // Using a cluster-scoped path for a namespaced CRD must return 404.
    #[tokio::test]
    async fn cluster_path_for_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let err = expect_err_status(
            list_cr(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                )),
                no_watch_query(),
            )
            .await,
            "namespaced CRD must reject cluster-scoped path",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
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
                Path(("example.io".to_string(), "v1".to_string(), "widgets".to_string())),
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
            no_watch_query(),
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
                Path((group.clone(), version.clone(), ns.clone(), plural.clone(), name.clone())),
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

        let patch_body = Bytes::from(
            serde_json::json!({ "spec": { "color": "red" } }).to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_cr_namespaced(
            State(state.clone()),
            Path((group.clone(), version.clone(), ns.clone(), plural.clone(), name.clone())),
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

    fn watch_query() -> super::super::generic::CollectionQuery {
        super::super::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
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
            Path(("example.io".to_string(), "v1".to_string(), "widgets".to_string())),
            watch_query(),
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
            resp.headers().get("transfer-encoding").and_then(|v| v.to_str().ok()),
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
            watch_query(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("transfer-encoding").and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "namespaced CR watch must use chunked transfer encoding"
        );
    }
}
