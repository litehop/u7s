use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use u7s_store::{ListOptions, Store, StoreError};

use crate::{state::AppState, status::Status, util::{extract_body, utc_now_rfc3339}};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomResourceDefinitionVersion {
    pub name: String,
    pub served: bool,
    pub storage: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
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
// Helpers
// ---------------------------------------------------------------------------

fn parse_crd(body: &Bytes) -> Result<CustomResourceDefinition, crate::status::StatusError> {
    serde_json::from_slice(body).map_err(|e| {
        Status::unprocessable_entity(format!("invalid CustomResourceDefinition: {e}"))
    })
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
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:016x}-{:08x}-crd0-0000-000000000000", d.as_secs(), d.subsec_nanos())
}

fn to_bytes(crd: &CustomResourceDefinition) -> Bytes {
    Bytes::from(serde_json::to_vec(crd).expect("CRD serialization never fails"))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn list_crds(
    State(state): State<AppState>,
    Query(query): Query<super::generic::CollectionQuery>,
) -> Result<Response, crate::status::StatusError> {
    let prefix = list_prefix();

    if query.watch == Some(true) {
        return super::generic::watch_generic(
            state,
            prefix,
            API_VERSION.to_string(),
            KIND.to_string(),
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

    let body = serde_json::json!({
        "kind": "CustomResourceDefinitionList",
        "apiVersion": API_VERSION,
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items,
    });
    Ok(Json(body).into_response())
}

pub async fn create_crd(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let body = extract_body(&body, ct);
    let mut crd = parse_crd(&body)?;

    let name = crd.metadata.name.clone();
    if name.is_empty() {
        return Err(Status::unprocessable_entity(
            "metadata.name is required".into(),
        ));
    }

    let expected_name = format!("{}.{}", crd.spec.names.plural, crd.spec.group);
    if name != expected_name {
        return Err(Status::unprocessable_entity(format!(
            "metadata.name must be {expected_name} (got {name})"
        )));
    }

    stamp_server_fields(&mut crd);

    let key = store_key(&name);
    let rv = state
        .store
        .put(&key, to_bytes(&crd), Some(0))
        .await
        .map_err(|e| store_err_crd(e, &name))?;

    crd.metadata.resource_version = rv.to_string();
    Ok((StatusCode::CREATED, Json(crd)))
}

pub async fn get_crd(
    State(state): State<AppState>,
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

pub async fn replace_crd(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
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

    let rv = state
        .store
        .put(&key, to_bytes(&crd), expected_rv)
        .await
        .map_err(|e| store_err_crd(e, &name))?;

    crd.metadata.resource_version = rv.to_string();
    Ok(Json(crd))
}

pub async fn delete_crd(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let key = store_key(&name);

    // Check existence first to return 404 rather than a store error.
    let _ = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, KIND))?;

    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err_crd(e, &name))?;

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
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
        AppState::new(store, None, None, std::collections::HashMap::new(), "https://localhost:6443".into())
    }

    fn minimal_crd_bytes(name: &str) -> Bytes {
        Bytes::from(serde_json::json!({
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
        }).to_string())
    }

    fn ok_crd(r: Result<CustomResourceDefinition, crate::status::StatusError>) -> CustomResourceDefinition {
        match r {
            Ok(v) => v,
            Err(_) => panic!("expected Ok but got StatusError"),
        }
    }

    fn err_status(r: Result<impl IntoResponse, crate::status::StatusError>) -> crate::status::StatusError {
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

        assert!(create_crd(State(state.clone()), HeaderMap::new(), body).await.is_ok(), "create must succeed");

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
            create_crd(State(state.clone()), HeaderMap::new(), body.clone()).await.is_ok(),
            "first create must succeed"
        );

        let err = err_status(create_crd(State(state), HeaderMap::new(), body).await);
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
        let err = err_status(delete_crd(State(state), Path("missing.example.com".to_string())).await);
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
            replace_crd(State(state), Path("missing.example.com".to_string()), HeaderMap::new(), body).await,
        );
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // list_crds must return empty list when nothing is stored.
    #[tokio::test]
    async fn list_empty() {
        let state = make_state();
        let resp = match list_crds(State(state), Query(crate::handlers::generic::CollectionQuery { watch: None, resource_version: None, label_selector: None })).await {
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
        let body = Bytes::from(serde_json::json!({
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
        }).to_string());

        let err = err_status(create_crd(State(state), HeaderMap::new(), body).await);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422, "mismatched name must return 422");
        assert!(
            json["message"].as_str().unwrap_or("").contains("widgets.example.io"),
            "error must mention the expected name"
        );
    }

    // A CRD whose metadata.name is exactly "{plural}.{group}" must be accepted.
    #[tokio::test]
    async fn create_crd_accepts_correct_name() {
        let state = make_state();
        let body = Bytes::from(serde_json::json!({
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
        }).to_string());

        assert!(
            create_crd(State(state), HeaderMap::new(), body).await.is_ok(),
            "correct name widgets.example.io must be accepted"
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
        });

        let resp = match list_crds(State(state), query).await {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        // watch_generic always sets transfer-encoding: chunked
        assert_eq!(
            resp.headers().get("transfer-encoding").and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "watch response must use chunked transfer encoding"
        );
    }
}
