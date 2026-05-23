// ---------------------------------------------------------------------------
// Core group (group="", version="v1") handler wrappers for /api/v1/... routes
// ---------------------------------------------------------------------------
//
// These inject the fixed (group, version) = ("", "v1") into the generic handlers
// so the router can use simpler path patterns like /api/v1/:resource.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store};

use crate::{auth::UserInfo, state::AppState, status::Status};

use super::generic::{
    apply_label_selector, build_list_response, decode_continue, parse_field_selector,
    parse_label_selector, CollectionQuery,
};
use super::json_patch::PatchQuery;
use super::resource::{
    create_namespaced_resource, create_resource, delete_namespaced_resource, delete_resource,
    get_namespaced_resource, get_resource, list_namespaced_resource, list_resource,
    patch_namespaced_resource, patch_resource, replace_namespaced_resource, replace_resource,
};
use super::status::{
    get_namespaced_resource_status, get_resource_status, patch_namespaced_resource_status,
    patch_resource_status, put_namespaced_resource_status, put_resource_status,
};
use super::watch::{fetch_initial_events, watch_generic};

pub async fn core_list_resource(
    State(state): State<AppState>,
    Path(plural): Path<String>,
    Query(query): Query<CollectionQuery>,
    headers: axum::http::HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Pods are namespaced; the registry has no cluster-scoped "pods" entry.
    // Handle GET /api/v1/pods by scanning across all namespaces.
    if plural == "pods" {
        let prefix = crate::keys::cluster_list_prefix("pods");
        if query.watch == Some(true) {
            let from_rv = query.resource_version.unwrap_or(0);
            let initial =
                fetch_initial_events(&state, &prefix, query.send_initial_events == Some(true))
                    .await?;
            return watch_generic(
                state,
                prefix,
                "v1".into(),
                "Pod".into(),
                from_rv,
                initial,
                query.label_selector,
                query.field_selector,
                query.allow_watch_bookmarks == Some(true),
                user.username,
                false,
            )
            .await
            .map(IntoResponse::into_response);
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
        let body = build_list_response("Pod", "", "v1", resp.revision, items, resp.continue_key);
        return Ok(Json(body).into_response());
    }

    list_resource(
        State(state),
        Path(("".into(), "v1".into(), plural)),
        Query(query),
        headers,
        Extension(user),
    )
    .await
    .map(IntoResponse::into_response)
}

pub async fn core_get_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_resource(State(state), Path(("".into(), "v1".into(), plural, name))).await
}

pub async fn core_create_resource(
    State(state): State<AppState>,
    Path(plural): Path<String>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    create_resource(
        State(state),
        Path(("".into(), "v1".into(), plural)),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_replace_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    replace_resource(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_delete_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    delete_resource(State(state), Path(("".into(), "v1".into(), plural, name))).await
}

pub async fn core_patch_resource(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    Query(patch_query): Query<PatchQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_resource(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        Query(patch_query),
        headers,
        body,
    )
    .await
}

pub async fn core_get_resource_status(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_resource_status(State(state), Path(("".into(), "v1".into(), plural, name))).await
}

pub async fn core_put_resource_status(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    put_resource_status(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        headers,
        body,
    )
    .await
}

pub async fn core_patch_resource_status(
    State(state): State<AppState>,
    Path((plural, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_resource_status(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        headers,
        body,
    )
    .await
}

pub async fn core_list_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural)): Path<(String, String)>,
    Query(query): Query<CollectionQuery>,
    headers: axum::http::HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    list_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural)),
        Query(query),
        headers,
        Extension(user),
    )
    .await
}

pub async fn core_get_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
    )
    .await
}

pub async fn core_create_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    create_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural)),
        headers,
        body,
    )
    .await
}

pub async fn core_replace_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    replace_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
        body,
    )
    .await
}

pub async fn core_delete_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    delete_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
    )
    .await
}

pub async fn core_patch_namespaced_resource(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    Query(patch_query): Query<PatchQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        Query(patch_query),
        headers,
        body,
    )
    .await
}

pub async fn core_get_namespaced_resource_status(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
    )
    .await
}

pub async fn core_put_namespaced_resource_status(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    put_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
        body,
    )
    .await
}

pub async fn core_patch_namespaced_resource_status(
    State(state): State<AppState>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
        body,
    )
    .await
}
