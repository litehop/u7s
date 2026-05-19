use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use u7s_store::Store as _;

use crate::{
    keys::group_object_key,
    state::AppState,
    status::Status,
    types::Object,
};

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
pub fn build_scale(name: &str, ns: &str, replicas: i64, resource_version: &str) -> serde_json::Value {
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

    let expected_rv = crate::handlers::generic::parse_resource_version(obj.resource_version())?;
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Json(build_scale(&name, &ns, new_replicas, &new_rv.to_string())))
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

    let expected_rv = crate::handlers::generic::parse_resource_version(obj.resource_version())?;
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Json(build_scale(&name, &ns, new_replicas, &new_rv.to_string())))
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
