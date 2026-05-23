use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use u7s_store::{ListOptions, Store, StoreError};

use crate::{
    admission::{run_mutating_webhooks, run_validating_webhooks, AdmissionContext},
    auth::UserInfo,
    state::AppState,
    status::Status,
    util::{extract_body, utc_now_rfc3339},
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
    /// Subresources declared for this version. The `status` key, if present
    /// and non-null, indicates that this version has a status subresource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subresources: Option<serde_json::Value>,
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
    "flowcontrol.apiserver.k8s.io",
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

pub async fn list_crds(
    State(state): State<AppState>,
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
        )
        .await?;
        return super::watch::watch_generic(
            state,
            prefix,
            watch_api_version,
            watch_kind,
            query.resource_version.unwrap_or(0),
            initial_items,
            query.label_selector,
            query.field_selector,
            query.allow_watch_bookmarks == Some(true),
            user.username,
            pom,
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
        };
        let obj_val = serde_json::to_value(&crd).map_err(|e| Status::internal(e.to_string()))?;
        let mutated = run_mutating_webhooks(&state, obj_val, &admission_ctx).await?;
        run_validating_webhooks(&state, &mutated, &admission_ctx).await?;
        crd = serde_json::from_value(mutated)
            .map_err(|e| Status::internal(format!("admission mutated CRD is invalid: {e}")))?;
    }

    let key = store_key(&name);
    let rv = state
        .store
        .put(&key, to_bytes(&crd)?, Some(0))
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
        };
        let obj_val = serde_json::to_value(&crd).map_err(|e| Status::internal(e.to_string()))?;
        let mutated = run_mutating_webhooks(&state, obj_val, &admission_ctx).await?;
        run_validating_webhooks(&state, &mutated, &admission_ctx).await?;
        crd = serde_json::from_value(mutated)
            .map_err(|e| Status::internal(format!("admission mutated CRD is invalid: {e}")))?;
    }

    let rv = state
        .store
        .put(&key, to_bytes(&crd)?, expected_rv)
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
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
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
            create_crd(State(state.clone()), HeaderMap::new(), body)
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
            create_crd(State(state.clone()), HeaderMap::new(), body.clone())
                .await
                .is_ok(),
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
        let err =
            err_status(delete_crd(State(state), Path("missing.example.com".to_string())).await);
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
            }),
            HeaderMap::new(),
            Extension(UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
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

        let err = err_status(create_crd(State(state), HeaderMap::new(), body).await);
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
            create_crd(State(state), HeaderMap::new(), body)
                .await
                .is_ok(),
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
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
        });

        let resp = match list_crds(
            State(state),
            query,
            HeaderMap::new(),
            Extension(UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
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

        let err = err_status(create_crd(State(state), HeaderMap::new(), body).await);
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
            create_crd(State(state), HeaderMap::new(), body)
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
        create_crd(State(state.clone()), HeaderMap::new(), body)
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
        });

        let resp = list_crds(
            State(state),
            query,
            pom_headers,
            Extension(UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("list_crds with POM Accept must succeed"));

        // Read the watch stream with a short timeout (initial-events BOOKMARK is emitted immediately).
        let body = resp.into_body();
        let bytes = timeout(
            Duration::from_millis(500),
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
