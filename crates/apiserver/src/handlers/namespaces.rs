use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store, StoreError};

use crate::{
    auth::UserInfo,
    keys::{cluster_list_prefix, cluster_object_key},
    proto,
    state::AppState,
    status::Status,
    types::{NamespaceStatus, Object, ObjectMeta},
    util::{extract_body, parse_resource_version},
};

/// Validate a namespace name: lowercase alphanumeric + hyphens, 1–63 chars.
/// Returns Err with 422 if invalid.
fn validate_namespace_name(name: &str) -> Result<(), crate::status::StatusError> {
    if name.is_empty() || name.len() > 63 {
        return Err(Status::unprocessable_entity(format!(
            "invalid namespace name '{name}': must be 1–63 characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Status::unprocessable_entity(format!(
            "invalid namespace name '{name}': must match [a-z0-9-]+"
        )));
    }
    Ok(())
}

fn store_err_to_status(err: StoreError, name: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, "Namespace"),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, "Namespace"),
        StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "Namespace \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => Status::internal(other.to_string()),
    }
}

pub async fn list_namespaces(
    State(state): State<AppState>,
    Query(query): Query<super::generic::CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    let prefix = cluster_list_prefix("namespaces");

    if query.watch == Some(true) {
        return super::watch::watch_generic(
            state,
            prefix,
            "v1".to_string(),
            "Namespace".to_string(),
            query.resource_version.unwrap_or(0),
            None,
            query.label_selector,
            query.field_selector,
            query.allow_watch_bookmarks == Some(true),
            user.username,
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
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items
    });

    Ok(Json(body).into_response())
}

pub async fn create_namespace(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Decode the request body. When kubectl sends Content-Type:
    // application/vnd.kubernetes.protobuf, the body is a k8s Unknown envelope. For core types
    // like Namespace, Unknown.raw is proto-encoded (contentType = protobuf), not JSON. We decode
    // the envelope to check the inner content-type and, if needed, decode the nested proto bytes
    // using the Namespace-specific decoder.
    let mut obj = if ct.starts_with("application/vnd.kubernetes.protobuf") {
        match proto::decode_k8s_proto_envelope(&body) {
            Some(env) if env.content_type == "application/json" => {
                // Inner bytes are explicitly JSON — parse normally.
                let b = bytes::Bytes::from(env.raw);
                Object::from_bytes(&b)
                    .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?
            }
            Some(env) => {
                // Inner bytes are proto-encoded. kubectl sends contentType="" (empty) with a
                // proto-encoded Namespace in Unknown.raw — not JSON. Decode using the
                // Namespace-specific proto decoder; fall back to JSON only if proto fails.
                match proto::decode_namespace_proto(&env.raw) {
                    Some(json_val) => Object { body: json_val },
                    None => Object::from_bytes(&bytes::Bytes::from(env.raw))
                        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?,
                }
            }
            None => {
                // Not a valid k8s proto envelope — fall back to raw JSON parse.
                Object::from_bytes(&body)
                    .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?
            }
        }
    } else {
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?
    };

    let name = {
        match obj.name().filter(|n| !n.is_empty()) {
            Some(n) => n.to_string(),
            None => {
                let meta: ObjectMeta =
                    serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
                let gen = meta.generate_name.as_deref().unwrap_or("");
                if gen.is_empty() {
                    return Err(Status::bad_request(
                        "metadata.name or metadata.generateName is required".into(),
                    ));
                }
                let generated = format!("{}{}", gen, crate::handlers::generic::generate_suffix());
                obj.body["metadata"]["name"] = serde_json::Value::String(generated.clone());
                generated
            }
        }
    };

    validate_namespace_name(&name)?;

    // Ensure kind/apiVersion and status are set
    if obj.body.get("kind").is_none() {
        obj.body["kind"] = serde_json::Value::String("Namespace".into());
    }
    if obj.body.get("apiVersion").is_none() {
        obj.body["apiVersion"] = serde_json::Value::String("v1".into());
    }
    if obj.body["status"].is_null() || obj.body.get("status").is_none() {
        obj.body["status"] = serde_json::to_value(NamespaceStatus {
            phase: "Active".to_owned(),
        })
        .expect("NamespaceStatus serializes");
    }

    // Assign a UID if none provided — required for owner references and garbage collection.
    {
        let meta: ObjectMeta =
            serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
        if meta.uid.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
            obj.body["metadata"]["uid"] =
                serde_json::Value::String(uuid::Uuid::new_v4().to_string());
        }
    }

    let key = cluster_object_key("namespaces", &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), Some(0))
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok((StatusCode::CREATED, Json(obj.body)))
}

pub async fn get_namespace(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Response, crate::status::StatusError> {
    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub async fn replace_namespace(
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
    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj.name().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let expected_revision = parse_resource_version(obj.resource_version())?;

    let key = cluster_object_key("namespaces", &name);
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    Ok(Json(obj.body))
}

pub async fn patch_namespace(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("application/merge-patch+json") {
        return Err(Status::unsupported_media_type(format!(
            "unsupported media type '{content_type}'; use application/merge-patch+json"
        )));
    }

    let key = cluster_object_key("namespaces", &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Namespace"))?;

    let mut current = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    crate::patch::merge_patch(&mut current.body, &patch);

    let expected_rv = parse_resource_version(current.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current.set_resource_version(new_rv);

    Ok(Json(current.body))
}

pub async fn delete_namespace(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let key = cluster_object_key("namespaces", &name);
    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_namespace_names() {
        assert!(validate_namespace_name("default").is_ok());
        assert!(validate_namespace_name("kube-system").is_ok());
        assert!(validate_namespace_name("a").is_ok());
        assert!(validate_namespace_name(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn invalid_namespace_names() {
        // empty
        assert!(validate_namespace_name("").is_err());
        // too long
        assert!(validate_namespace_name(&"a".repeat(64)).is_err());
        // uppercase rejected
        assert!(validate_namespace_name("Default").is_err());
        // underscore rejected
        assert!(validate_namespace_name("my_ns").is_err());
        // dot rejected
        assert!(validate_namespace_name("my.ns").is_err());
    }

    #[test]
    fn invalid_returns_422() {
        let result = validate_namespace_name("Bad_Name");
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // When ?watch=true, list_namespaces must route to the watch stream (chunked transfer)
    // rather than returning a normal NamespaceList JSON. This ensures clients that open
    // a watch on /api/v1/namespaces actually receive a streaming response.
    #[tokio::test]
    async fn list_namespaces_watch_returns_chunked_stream() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let query = crate::handlers::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
        };

        let resp = match list_namespaces(
            State(state),
            Query(query),
            Extension(crate::auth::UserInfo {
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

    fn make_state() -> AppState {
        use std::sync::Arc;
        use u7s_store::SqliteStore;
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    fn namespace_body(name: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": name }
            })
            .to_string(),
        )
    }

    // create_namespace must return 201 with the name set and a non-empty UID assigned.
    // A missing UID would break owner references and garbage collection.
    #[tokio::test]
    async fn create_namespace_returns_201_with_name_and_uid() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("my-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Verify the stored object has name and UID set
        let stored = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "my-ns"))
            .await
            .expect("store get must not error")
            .expect("namespace must exist in store");
        let body: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored value must be valid JSON");
        assert_eq!(
            body["metadata"]["name"], "my-ns",
            "created namespace must have correct name"
        );
        assert!(
            body["metadata"]["uid"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "created namespace must have a non-empty UID"
        );
    }

    // replace_namespace must reflect updated labels in the response body.
    // This verifies that PUT applies the full replacement, not a partial update.
    #[tokio::test]
    async fn replace_namespace_reflects_updated_labels() {
        let state = make_state();

        // Create first
        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("label-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Fetch to get uid and resourceVersion
        let stored_entry = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "label-ns"))
            .await
            .expect("store get must not error")
            .expect("must exist");
        let stored: serde_json::Value =
            serde_json::from_slice(&stored_entry.value).expect("parse stored");
        let rv = stored["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("1")
            .to_string();
        let uid = stored["metadata"]["uid"].as_str().unwrap_or("").to_string();

        // PUT with new labels, carrying back uid+rv
        let replace_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "label-ns",
                    "uid": uid,
                    "resourceVersion": rv,
                    "labels": { "env": "prod" }
                }
            })
            .to_string(),
        );

        // Verify stored state after replace reflects the label update
        assert!(
            replace_namespace(
                State(state.clone()),
                Path("label-ns".to_string()),
                axum::http::HeaderMap::new(),
                replace_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        let after = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "label-ns"))
            .await
            .expect("store get must not error")
            .expect("must still exist");
        let body: serde_json::Value = serde_json::from_slice(&after.value).expect("parse after");
        assert_eq!(
            body["metadata"]["labels"]["env"], "prod",
            "replace must persist the updated labels"
        );
    }

    // patch_namespace with merge-patch must return 200 and apply the patch.
    // This verifies the happy path: correct content-type, namespace exists, patch is valid JSON.
    #[tokio::test]
    async fn patch_namespace_applies_merge_patch() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("patch-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!({ "metadata": { "labels": { "patched": "yes" } } }).to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_namespace(
                State(state.clone()),
                Path("patch-ns".to_string()),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "patch must succeed"
        );

        let after = state
            .store
            .get(&crate::keys::cluster_object_key("namespaces", "patch-ns"))
            .await
            .expect("store get")
            .expect("must still exist");
        let body: serde_json::Value =
            serde_json::from_slice(&after.value).expect("parse after patch");
        assert_eq!(
            body["metadata"]["labels"]["patched"], "yes",
            "patch must apply the merge patch to the stored namespace"
        );
    }

    // delete_namespace must remove the resource so a subsequent GET returns 404.
    // A namespace that is not truly deleted would cause resource leaks.
    #[tokio::test]
    async fn delete_namespace_removes_resource() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("del-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        assert!(
            delete_namespace(State(state.clone()), Path("del-ns".to_string()))
                .await
                .is_ok(),
            "delete must succeed"
        );

        let result = get_namespace(State(state.clone()), Path("del-ns".to_string())).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 404,
            "deleted namespace must return 404 on GET"
        );
        assert_eq!(json["reason"], "NotFound");
    }

    // store_err_to_status must map each StoreError variant to the correct HTTP status code.
    // This mapping is what clients rely on to distinguish 404 from 409 from 500.
    #[test]
    fn store_err_to_status_not_found_maps_to_404() {
        let err = store_err_to_status(StoreError::NotFound { key: "k".into() }, "my-ns");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn store_err_to_status_already_exists_maps_to_409() {
        let err = store_err_to_status(StoreError::AlreadyExists { key: "k".into() }, "my-ns");
        assert_eq!(err.0, StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["reason"], "AlreadyExists");
    }

    #[test]
    fn store_err_to_status_revision_mismatch_maps_to_409_conflict() {
        let err = store_err_to_status(
            StoreError::RevisionMismatch {
                expected: 1,
                current: 2,
            },
            "my-ns",
        );
        assert_eq!(err.0, StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        // RevisionMismatch maps to Conflict reason, not AlreadyExists
        assert_eq!(json["reason"], "Conflict");
        assert!(
            json["message"].as_str().unwrap().contains("my-ns"),
            "conflict message must identify the namespace"
        );
    }

    #[test]
    fn store_err_to_status_other_maps_to_500() {
        // Compacted is a catch-all "other" arm — maps to internal server error.
        // This ensures unexpected store errors don't leak as 4xx to clients.
        let err = store_err_to_status(
            StoreError::Compacted {
                requested: 1,
                horizon: 5,
            },
            "any-ns",
        );
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["reason"], "InternalError");
    }

    // list_namespaces (non-watch) must return a NamespaceList with the created namespace.
    // This is the primary read path for `kubectl get namespaces`.
    #[tokio::test]
    async fn list_namespaces_returns_namespace_list() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("list-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match list_namespaces(
            State(state.clone()),
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
            Extension(crate::auth::UserInfo {
                username: "test-user".into(),
                uid: String::new(),
                groups: vec![],
            }),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
    }

    // get_namespace must return 200 with the namespace body when it exists.
    #[tokio::test]
    async fn get_namespace_returns_200_for_existing() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("get-ns"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match get_namespace(State(state.clone()), Path("get-ns".to_string())).await {
            Ok(r) => r,
            Err(_) => panic!("get must not error"),
        };

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "existing namespace must return 200"
        );
    }

    // get_namespace must return 404 when the namespace does not exist.
    // Clients depend on this to know a resource is absent.
    #[tokio::test]
    async fn get_namespace_returns_404_for_missing() {
        let state = make_state();

        let result = get_namespace(State(state.clone()), Path("no-such-ns".to_string())).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    // create_namespace must reject bodies with neither name nor generateName.
    // Without an identity, the object cannot be stored or referenced.
    #[tokio::test]
    async fn create_namespace_rejects_missing_name() {
        let state = make_state();
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {}
            })
            .to_string(),
        );

        let result =
            create_namespace(State(state.clone()), axum::http::HeaderMap::new(), body).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    // create_namespace must reject invalid namespace names with 422.
    // Kubernetes enforces strict DNS label rules on namespace names.
    #[tokio::test]
    async fn create_namespace_rejects_invalid_name() {
        let state = make_state();
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "INVALID_NAME" }
            })
            .to_string(),
        );

        let result =
            create_namespace(State(state.clone()), axum::http::HeaderMap::new(), body).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // create_namespace must reject a duplicate: second create for same name returns 409.
    // Kubernetes returns AlreadyExists (409) when a namespace already exists.
    #[tokio::test]
    async fn create_namespace_rejects_duplicate() {
        let state = make_state();

        assert!(
            create_namespace(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                namespace_body("dup-ns"),
            )
            .await
            .is_ok(),
            "first create must succeed"
        );

        let result = create_namespace(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            namespace_body("dup-ns"),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "second create of same namespace must return 409"
        );
    }

    // replace_namespace must reject a request where URL name != body name.
    // Kubernetes enforces name consistency to prevent accidental overwrites.
    #[tokio::test]
    async fn replace_namespace_rejects_name_mismatch() {
        let state = make_state();

        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "other-ns", "resourceVersion": "1" }
            })
            .to_string(),
        );

        let result = replace_namespace(
            State(state.clone()),
            Path("different-ns".to_string()),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::BAD_REQUEST,
            "name mismatch between URL and body must return 400"
        );
    }

    // patch_namespace must return 415 when Content-Type is not merge-patch+json.
    // Without the right content type, the patch semantics are undefined.
    #[tokio::test]
    async fn patch_namespace_rejects_wrong_content_type() {
        let state = make_state();

        let patch_body = Bytes::from(serde_json::json!({}).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let result = patch_namespace(
            State(state.clone()),
            Path("any-ns".to_string()),
            headers,
            patch_body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "wrong content type must return 415"
        );
    }

    // patch_namespace must return 404 when the namespace does not exist.
    #[tokio::test]
    async fn patch_namespace_returns_404_for_missing() {
        let state = make_state();

        let patch_body = Bytes::from(serde_json::json!({}).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_namespace(
            State(state.clone()),
            Path("no-such-ns".to_string()),
            headers,
            patch_body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::NOT_FOUND,
            "patch on non-existent namespace must return 404"
        );
    }

    // delete_namespace must return 404 when the namespace does not exist.
    #[tokio::test]
    async fn delete_namespace_returns_404_for_missing() {
        let state = make_state();

        let result = delete_namespace(State(state.clone()), Path("ghost-ns".to_string())).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.0,
            StatusCode::NOT_FOUND,
            "deleting non-existent namespace must return 404"
        );
    }
}
