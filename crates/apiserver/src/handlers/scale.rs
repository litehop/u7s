use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use u7s_store::Store as _;

use crate::{keys::group_object_key, state::AppState, status::Status, types::Object};

// ---------------------------------------------------------------------------
// Scale subresource — GET/PUT/PATCH
//
// Routes:
//   GET    /apis/apps/v1/namespaces/:ns/:resource/:name/scale
//   PUT    /apis/apps/v1/namespaces/:ns/:resource/:name/scale
//   PATCH  /apis/apps/v1/namespaces/:ns/:resource/:name/scale
//
// Only apps/v1 workloads (deployments, replicasets, statefulsets) support
// scale.  The handler validates the resource kind against this set.
//
// The Scale object (autoscaling/v1) is synthesised from the stored workload's
// spec.replicas.  PUT/PATCH write spec.replicas back to the stored object.
// ---------------------------------------------------------------------------

const SCALE_RESOURCES: &[&str] = &["deployments", "replicasets", "statefulsets"];

fn require_scale_resource(resource: &str) -> Result<(), crate::status::StatusError> {
    if SCALE_RESOURCES.contains(&resource) {
        Ok(())
    } else {
        Err(Status::not_found(
            resource,
            &format!("scale subresource for {resource}"),
        ))
    }
}

/// Build a Scale (autoscaling/v1) object from the given name, namespace, and
/// replica count.  `resource_version` is taken from the stored workload.
pub fn build_scale(
    name: &str,
    ns: &str,
    replicas: i64,
    resource_version: &str,
) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "autoscaling/v1",
        "kind": "Scale",
        "metadata": {
            "name": name,
            "namespace": ns,
            "resourceVersion": resource_version
        },
        "spec": { "replicas": replicas },
        "status": { "replicas": replicas, "selector": "" }
    })
}

/// Extract spec.replicas from a stored workload object (default 0).
pub fn extract_replicas(obj: &serde_json::Value) -> i64 {
    obj["spec"]["replicas"].as_i64().unwrap_or(0)
}

/// GET /apis/apps/v1/namespaces/:ns/:resource/:name/scale
pub async fn get_scale(
    State(state): State<AppState>,
    Path((ns, resource, name)): Path<(String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    require_scale_resource(&resource)?;

    let key = group_object_key("apps", &resource, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &resource))?;

    let obj: serde_json::Value = serde_json::from_slice(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let replicas = extract_replicas(&obj);
    let rv = obj["metadata"]["resourceVersion"]
        .as_str()
        .unwrap_or("")
        .to_string();

    Ok(Json(build_scale(&name, &ns, replicas, &rv)).into_response())
}

/// PUT /apis/apps/v1/namespaces/:ns/:resource/:name/scale
///
/// Accepts a Scale object body; writes `spec.replicas` back into the stored
/// workload, increments resourceVersion, returns the updated Scale.
pub async fn put_scale(
    State(state): State<AppState>,
    Path((ns, resource, name)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    require_scale_resource(&resource)?;

    let scale_body: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let new_replicas = scale_body["spec"]["replicas"]
        .as_i64()
        .ok_or_else(|| Status::bad_request("spec.replicas must be an integer".into()))?;

    let key = group_object_key("apps", &resource, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &resource))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    obj.body["spec"]["replicas"] = serde_json::Value::Number(new_replicas.into());

    let expected_rv = crate::util::parse_resource_version(obj.resource_version())?;
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Json(build_scale(
        &name,
        &ns,
        new_replicas,
        &new_rv.to_string(),
    )))
}

/// PATCH /apis/apps/v1/namespaces/:ns/:resource/:name/scale
///
/// Accepts a JSON merge-patch body targeting the Scale object.  Only
/// `spec.replicas` is extracted and written back to the stored workload.
pub async fn patch_scale(
    State(state): State<AppState>,
    Path((ns, resource, name)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    require_scale_resource(&resource)?;

    let scale_patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = group_object_key("apps", &resource, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &resource))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // Extract replicas from patch if present; otherwise keep current value.
    let new_replicas = if let Some(r) = scale_patch["spec"]["replicas"].as_i64() {
        obj.body["spec"]["replicas"] = serde_json::Value::Number(r.into());
        r
    } else {
        extract_replicas(&obj.body)
    };

    let expected_rv = crate::util::parse_resource_version(obj.resource_version())?;
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Json(build_scale(
        &name,
        &ns,
        new_replicas,
        &new_rv.to_string(),
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- build_scale --

    #[test]
    fn build_scale_returns_autoscaling_v1_shape() {
        // The Scale object must be autoscaling/v1 — kubectl and HPA both
        // assert on the apiVersion/kind to identify the response.
        let scale = build_scale("my-deploy", "default", 3, "42");
        assert_eq!(scale["apiVersion"], "autoscaling/v1");
        assert_eq!(scale["kind"], "Scale");
    }

    #[test]
    fn build_scale_embeds_replicas_in_spec_and_status() {
        // spec.replicas is what callers write; status.replicas is what the
        // controller reports.  Both must reflect the current count.
        let scale = build_scale("my-deploy", "default", 5, "7");
        assert_eq!(scale["spec"]["replicas"], 5);
        assert_eq!(scale["status"]["replicas"], 5);
    }

    #[test]
    fn build_scale_includes_metadata_name_namespace_rv() {
        let scale = build_scale("my-deploy", "production", 2, "99");
        assert_eq!(scale["metadata"]["name"], "my-deploy");
        assert_eq!(scale["metadata"]["namespace"], "production");
        assert_eq!(scale["metadata"]["resourceVersion"], "99");
    }

    // -- extract_replicas --

    #[test]
    fn extract_replicas_reads_spec_replicas() {
        // kubectl scale sets spec.replicas; the handler must read exactly that field.
        let obj = serde_json::json!({ "spec": { "replicas": 7 } });
        assert_eq!(extract_replicas(&obj), 7);
    }

    #[test]
    fn extract_replicas_defaults_to_zero_when_absent() {
        // A freshly-created Deployment may not have spec.replicas set; default to 0
        // rather than panicking or returning an error.
        let obj = serde_json::json!({ "spec": {} });
        assert_eq!(extract_replicas(&obj), 0);
    }

    #[test]
    fn extract_replicas_defaults_to_zero_for_null() {
        let obj = serde_json::json!({ "spec": { "replicas": null } });
        assert_eq!(extract_replicas(&obj), 0);
    }

    // -- require_scale_resource --

    #[test]
    fn require_scale_resource_accepts_workload_plurals() {
        // Only the three apps/v1 workload types expose a scale subresource in
        // Kubernetes; any other resource must return 404.
        assert!(require_scale_resource("deployments").is_ok());
        assert!(require_scale_resource("replicasets").is_ok());
        assert!(require_scale_resource("statefulsets").is_ok());
    }

    #[test]
    fn require_scale_resource_rejects_others() {
        assert!(require_scale_resource("daemonsets").is_err());
        assert!(require_scale_resource("pods").is_err());
        assert!(require_scale_resource("configmaps").is_err());
    }
}

// ---------------------------------------------------------------------------
// Handler integration tests (tower::ServiceExt::oneshot, in-memory store)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod handler_tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, patch, put},
        Router,
    };
    use bytes::Bytes;
    use tower::ServiceExt;
    use u7s_store::{SqliteStore, Store};

    use super::*;
    use crate::state::AppState;

    /// Build a minimal in-memory AppState for handler tests.
    fn make_state() -> (AppState, Arc<SqliteStore>) {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        (state, store)
    }

    /// Seed a workload (Deployment/ReplicaSet/StatefulSet) into the store.
    /// Uses the same key layout as group_object_key("apps", resource, ns, name).
    async fn seed_workload(
        store: &Arc<SqliteStore>,
        resource: &str,
        ns: &str,
        name: &str,
        replicas: i64,
    ) {
        let key = format!("/registry/apps/{resource}/{ns}/{name}");
        let val = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": name,
                "namespace": ns,
                "resourceVersion": "1"
            },
            "spec": { "replicas": replicas },
            "status": {}
        });
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed workload");
    }

    fn json_body(v: &serde_json::Value) -> Body {
        Body::from(Bytes::from(serde_json::to_vec(v).unwrap()))
    }

    // -----------------------------------------------------------------------
    // get_scale
    // -----------------------------------------------------------------------

    /// GET scale on a valid resource type that exists returns 200 with
    /// autoscaling/v1 Scale JSON containing the correct replica count.
    /// This matters because kubectl scale and HPA both read this endpoint.
    #[tokio::test]
    async fn get_scale_returns_200_with_scale_object() {
        let (state, store) = make_state();
        seed_workload(&store, "deployments", "default", "my-deploy", 3).await;

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                get(get_scale),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/apis/apps/v1/namespaces/default/deployments/my-deploy/scale")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["apiVersion"], "autoscaling/v1");
        assert_eq!(json["kind"], "Scale");
        assert_eq!(json["spec"]["replicas"], 3);
        assert_eq!(json["metadata"]["name"], "my-deploy");
        assert_eq!(json["metadata"]["namespace"], "default");
    }

    /// GET scale for a resource type that does not support scale (e.g. pods)
    /// must return 404. Scale is only valid for deployments, replicasets, statefulsets.
    #[tokio::test]
    async fn get_scale_returns_404_for_unsupported_resource() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                get(get_scale),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/apis/apps/v1/namespaces/default/pods/nginx/scale")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// GET scale for a workload that does not exist must return 404.
    #[tokio::test]
    async fn get_scale_returns_404_for_missing_workload() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                get(get_scale),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/apis/apps/v1/namespaces/default/deployments/ghost/scale")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// GET scale for a replicaset must also work — all three scalable types must be supported.
    #[tokio::test]
    async fn get_scale_works_for_replicasets_and_statefulsets() {
        let (state, store) = make_state();
        seed_workload(&store, "replicasets", "default", "my-rs", 2).await;
        seed_workload(&store, "statefulsets", "default", "my-sts", 5).await;

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                get(get_scale),
            )
            .with_state(state);

        // ReplicaSet
        let req = Request::builder()
            .method("GET")
            .uri("/apis/apps/v1/namespaces/default/replicasets/my-rs/scale")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["spec"]["replicas"], 2);

        // StatefulSet
        let req = Request::builder()
            .method("GET")
            .uri("/apis/apps/v1/namespaces/default/statefulsets/my-sts/scale")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["spec"]["replicas"], 5);
    }

    // -----------------------------------------------------------------------
    // put_scale
    // -----------------------------------------------------------------------

    /// PUT scale with valid JSON body writes spec.replicas back to the stored
    /// workload and returns the updated Scale.  HPA and kubectl scale both use
    /// this path to change replica counts.
    #[tokio::test]
    async fn put_scale_updates_replicas_and_returns_scale() {
        let (state, store) = make_state();
        seed_workload(&store, "deployments", "default", "my-deploy", 1).await;

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "autoscaling/v1",
            "kind": "Scale",
            "spec": { "replicas": 5 }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/deployments/my-deploy/scale")
            .header("content-type", "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(json["spec"]["replicas"], 5);
        assert_eq!(json["status"]["replicas"], 5);

        // Confirm the workload in the store was actually updated.
        let key = "/registry/apps/deployments/default/my-deploy";
        let stored = store.get(key).await.unwrap().unwrap();
        let stored_obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(stored_obj["spec"]["replicas"], 5);
    }

    /// PUT scale with invalid JSON must return 400.
    /// The handler must not panic or return 500 on malformed input.
    #[tokio::test]
    async fn put_scale_returns_400_for_invalid_json() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/deployments/my-deploy/scale")
            .body(Body::from(Bytes::from_static(b"not json")))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// PUT scale without spec.replicas must return 400.
    /// spec.replicas is required — without it the scale request is meaningless.
    #[tokio::test]
    async fn put_scale_returns_400_when_spec_replicas_missing() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": {} });

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/deployments/my-deploy/scale")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// PUT scale for a missing workload must return 404.
    #[tokio::test]
    async fn put_scale_returns_404_for_missing_workload() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "replicas": 3 } });

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/deployments/ghost/scale")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// PUT scale for an unsupported resource type must return 404.
    #[tokio::test]
    async fn put_scale_returns_404_for_unsupported_resource() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "replicas": 3 } });

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/daemonsets/my-ds/scale")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // patch_scale
    // -----------------------------------------------------------------------

    /// PATCH scale with spec.replicas updates the stored replica count.
    /// JSON merge-patch: only spec.replicas is extracted and applied.
    #[tokio::test]
    async fn patch_scale_updates_replicas_when_patch_contains_spec_replicas() {
        let (state, store) = make_state();
        seed_workload(&store, "deployments", "default", "my-deploy", 1).await;

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                patch(patch_scale),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "replicas": 7 } });

        let req = Request::builder()
            .method("PATCH")
            .uri("/apis/apps/v1/namespaces/default/deployments/my-deploy/scale")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(json["spec"]["replicas"], 7);
    }

    /// PATCH scale without spec.replicas in the patch body must keep the
    /// existing replica count — the patch is a no-op on replicas.
    #[tokio::test]
    async fn patch_scale_keeps_current_replicas_when_patch_omits_spec_replicas() {
        let (state, store) = make_state();
        seed_workload(&store, "deployments", "default", "my-deploy", 4).await;

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                patch(patch_scale),
            )
            .with_state(state);

        // Patch body has no spec.replicas — replicas should be preserved.
        let body = serde_json::json!({ "metadata": { "annotations": { "note": "test" } } });

        let req = Request::builder()
            .method("PATCH")
            .uri("/apis/apps/v1/namespaces/default/deployments/my-deploy/scale")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        // Original count must be preserved since the patch did not include spec.replicas.
        assert_eq!(json["spec"]["replicas"], 4);
    }

    /// PATCH scale with invalid JSON must return 400.
    #[tokio::test]
    async fn patch_scale_returns_400_for_invalid_json() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                patch(patch_scale),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/apis/apps/v1/namespaces/default/deployments/my-deploy/scale")
            .body(Body::from(Bytes::from_static(b"{{bad json")))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// PATCH scale for a missing workload must return 404.
    #[tokio::test]
    async fn patch_scale_returns_404_for_missing_workload() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                patch(patch_scale),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "replicas": 2 } });

        let req = Request::builder()
            .method("PATCH")
            .uri("/apis/apps/v1/namespaces/default/deployments/ghost/scale")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// PATCH scale for an unsupported resource type must return 404.
    #[tokio::test]
    async fn patch_scale_returns_404_for_unsupported_resource() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                patch(patch_scale),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "replicas": 2 } });

        let req = Request::builder()
            .method("PATCH")
            .uri("/apis/apps/v1/namespaces/default/configmaps/my-cm/scale")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
