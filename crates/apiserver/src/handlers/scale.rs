use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use prost::Message;
use serde::{Deserialize, Serialize};
use u7s_store::Store;

use crate::{
    keys::group_object_key,
    state::AppState,
    status::Status,
    types::Object,
    util::{content_type, extract_body},
};

use super::generic::store_err;

// ---------------------------------------------------------------------------
// Typed Scale structs — local to this file (single-use, not in types.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ScaleMetadata {
    name: Option<String>,
    namespace: Option<String>,
    #[serde(
        rename = "resourceVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    resource_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ScaleSpec {
    replicas: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ScaleStatus {
    replicas: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Scale {
    #[serde(rename = "apiVersion", default)]
    api_version: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    metadata: ScaleMetadata,
    #[serde(default)]
    spec: ScaleSpec,
    #[serde(default)]
    status: ScaleStatus,
}

// ---------------------------------------------------------------------------
// Protobuf types for Scale body decoding
//
// kubectl and client-go send write requests with Content-Type:
// application/vnd.kubernetes.protobuf by default.  The wire format wraps the
// payload in a k8s Unknown envelope (4-byte magic + proto-encoded Unknown).
// For autoscaling/v1.Scale the `raw` field contains a proto-encoded Scale
// message; we only need spec.replicas from it.
//
// These types mirror the official k8s .proto definitions (field numbers are
// canonical and must not change).
// ---------------------------------------------------------------------------

const K8S_PROTO_MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];

/// k8s Unknown proto envelope — wraps the actual serialised object.
/// Source: apimachinery/pkg/runtime/generated.proto message Unknown
#[derive(Clone, PartialEq, Message)]
struct ProtoUnknown {
    /// typeMeta (field 1)
    #[prost(message, tag = "1")]
    type_meta: Option<ProtoTypeMeta>,
    /// raw bytes of the encoded object (field 2)
    #[prost(bytes = "vec", tag = "2")]
    raw: Vec<u8>,
    /// contentEncoding (field 3)
    #[prost(string, tag = "3")]
    content_encoding: String,
    /// contentType (field 4): "application/json" or "application/vnd.kubernetes.protobuf"
    #[prost(string, tag = "4")]
    content_type: String,
}

#[derive(Clone, PartialEq, Message)]
struct ProtoTypeMeta {
    #[prost(string, tag = "1")]
    api_version: String,
    #[prost(string, tag = "2")]
    kind: String,
}

/// autoscaling/v1 ScaleSpec — field 2 of Scale.
/// Source: k8s.io/api/autoscaling/v1/generated.proto message ScaleSpec
#[derive(Clone, PartialEq, Message)]
struct ProtoScaleSpec {
    /// replicas (field 1, int32)
    #[prost(int32, tag = "1")]
    replicas: i32,
}

/// autoscaling/v1 Scale — the object sent by client-go for PUT/PATCH scale.
/// Source: k8s.io/api/autoscaling/v1/generated.proto message Scale
///
/// We only need spec.replicas; metadata and status are ignored here.
#[derive(Clone, PartialEq, Message)]
struct ProtoScale {
    /// metadata (field 1, message) — skipped by using bytes
    #[prost(bytes = "vec", tag = "1")]
    metadata_raw: Vec<u8>,
    /// spec (field 2, message)
    #[prost(message, tag = "2")]
    spec: Option<ProtoScaleSpec>,
}

/// Try to decode a k8s proto envelope body as a Scale JSON object.
///
/// client-go (and kubectl) send `Content-Type: application/vnd.kubernetes.protobuf`
/// for PUT/PATCH requests.  The payload is:
///   [4-byte magic] [proto-encoded Unknown envelope]
///
/// The Unknown envelope may contain either:
///   - JSON bytes (contentType = "application/json")  — returned directly.
///   - Proto-encoded Scale bytes (contentType = "" or "…/protobuf") — decoded
///     using the minimal ProtoScale prost type above.
///
/// Returns `None` if the body is not a recognisable k8s proto envelope.  The
/// caller falls through to the plain-JSON path in that case.
fn try_decode_proto_scale_body(body: &Bytes) -> Option<Scale> {
    // Must start with k8s proto magic.
    if body.len() < 4 || &body[..4] != K8S_PROTO_MAGIC.as_slice() {
        return None;
    }
    let envelope = ProtoUnknown::decode(&body[4..]).ok()?;

    // If the raw field contains JSON (envelope was produced by a fallback path),
    // parse it directly — no proto decode needed.
    if envelope.content_type == "application/json" {
        return serde_json::from_slice(&envelope.raw).ok();
    }

    // Otherwise raw is proto-encoded autoscaling/v1 Scale.
    let proto_scale = ProtoScale::decode(envelope.raw.as_slice()).ok()?;
    let replicas = proto_scale.spec.map(|s| s.replicas);

    Some(Scale {
        api_version: "autoscaling/v1".into(),
        kind: "Scale".into(),
        metadata: ScaleMetadata::default(),
        spec: ScaleSpec { replicas },
        status: ScaleStatus::default(),
    })
}

/// Decode the request body into a `Scale` object.
///
/// Accepts both `application/json` and `application/vnd.kubernetes.protobuf`
/// bodies.  When the body is proto-encoded, the k8s Unknown envelope is
/// unwrapped and the Scale message is decoded with the minimal ProtoScale type.
///
/// Returns `Err(StatusError)` on parse failure so the caller can propagate the
/// 400 directly.
fn decode_scale_body(
    body: &Bytes,
    headers: &HeaderMap,
) -> Result<Scale, crate::status::StatusError> {
    let ct = content_type(headers);
    // Try extract_body first: handles JSON-in-proto-envelope transparently.
    let decoded = extract_body(body, ct);

    // Fast path: try JSON parse (works for plain JSON or JSON extracted from
    // a proto envelope by extract_body).
    if let Ok(s) = serde_json::from_slice::<Scale>(&decoded) {
        return Ok(s);
    }

    // Slow path: body was a proto envelope whose raw field is proto-encoded
    // Scale (not JSON).  extract_body returns the original bytes in this case
    // because there is no Scale decoder registered in decode_core_proto_by_kind.
    // Use the inline decoder instead.
    if let Some(s) = try_decode_proto_scale_body(body) {
        return Ok(s);
    }

    // Nothing worked — propagate the JSON parse error.
    let e = serde_json::from_slice::<Scale>(body)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "unrecognised body format".into());
    Err(Status::bad_request(format!("invalid JSON: {e}")))
}

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

const SCALE_RESOURCES: &[&str] = &[
    "deployments",
    "replicasets",
    "statefulsets",
    "replicationcontrollers",
];

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
/// replica counts.  `resource_version` is taken from the stored workload.
///
/// `spec_replicas` is the desired count written by clients (HPA, kubectl scale).
/// `status_replicas` is the actual count of pods currently managed by the controller;
/// it may lag `spec_replicas` while pods are being created or terminated.
/// `selector` is the workload's `spec.selector` rendered as a label selector
/// string (see `label_selector_to_string`) — the HPA controller treats an
/// empty selector as a hard error and never computes metrics if this is "".
pub fn build_scale(
    name: &str,
    ns: &str,
    spec_replicas: i64,
    status_replicas: i64,
    resource_version: &str,
    selector: &str,
) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "autoscaling/v1",
        "kind": "Scale",
        "metadata": {
            "name": name,
            "namespace": ns,
            "resourceVersion": resource_version
        },
        "spec": { "replicas": spec_replicas },
        "status": { "replicas": status_replicas, "selector": selector }
    })
}

/// Serialize a workload's `spec.selector` into the label-selector string form
/// required by the Scale subresource's `status.selector` field.
///
/// Upstream's HPA controller (`validateAndParseSelector`,
/// pkg/controller/podautoscaler/horizontal.go) treats an empty selector
/// string as a hard, unrecoverable error and never proceeds to metric
/// collection — so an empty result here (when a real selector exists)
/// permanently breaks HPA against this workload.
///
/// `spec.selector` has two on-disk shapes in this codebase (see defaults.rs):
///   - apps/v1 workloads (Deployment/ReplicaSet/StatefulSet): the structured
///     LabelSelector — `{"matchLabels": {...}, "matchExpressions": [...]}`.
///   - core/v1 ReplicationController: a flat `map<string,string>`, never
///     wrapped in matchLabels.
///
/// Equality terms render as `key=value`; matchExpressions render using the
/// standard Kubernetes selector string syntax (`key In (v1,v2)`, `key
/// NotIn (v1,v2)`, `key`, `!key`) — the same forms `parse_label_selector`
/// (handlers/generic.rs) understands, so a selector built here round-trips
/// through this codebase's own selector matching as well as client-go's
/// `labels.Parse`. Terms are comma-joined; malformed entries are skipped
/// rather than erroring, since callers only ever pass already-validated
/// stored selector values.
pub fn label_selector_to_string(selector: &serde_json::Value) -> String {
    let Some(obj) = selector.as_object() else {
        return String::new();
    };

    // Flat equality map (ReplicationController) — no matchLabels/matchExpressions keys.
    if !obj.contains_key("matchLabels") && !obj.contains_key("matchExpressions") {
        let mut terms: Vec<String> = obj
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|v| format!("{k}={v}")))
            .collect();
        terms.sort();
        return terms.join(",");
    }

    let mut terms: Vec<String> = obj
        .get("matchLabels")
        .and_then(|v| v.as_object())
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| v.as_str().map(|v| format!("{k}={v}")))
        .collect();
    terms.sort();

    if let Some(exprs) = obj.get("matchExpressions").and_then(|v| v.as_array()) {
        for expr in exprs {
            let key = expr["key"].as_str().unwrap_or_default();
            if key.is_empty() {
                continue;
            }
            let values: Vec<&str> = expr["values"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str())
                .collect();
            match expr["operator"].as_str().unwrap_or_default() {
                "In" => terms.push(format!("{key} In ({})", values.join(","))),
                "NotIn" => terms.push(format!("{key} NotIn ({})", values.join(","))),
                "Exists" => terms.push(key.to_string()),
                "DoesNotExist" => terms.push(format!("!{key}")),
                _ => {}
            }
        }
    }

    terms.join(",")
}

/// Extract spec.replicas from a stored workload object (default 0).
pub fn extract_replicas(obj: &serde_json::Value) -> i64 {
    let spec: ScaleSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    spec.replicas.unwrap_or(0) as i64
}

/// Extract status.replicas from a stored workload object.
///
/// Returns the actual pod count last reported by the controller.  Falls back to
/// `spec.replicas` when the status field has not yet been written (e.g. immediately
/// after creation before the first controller reconciliation).
pub fn extract_status_replicas(obj: &serde_json::Value) -> i64 {
    if let Some(n) = obj["status"]["replicas"].as_i64() {
        n
    } else {
        // Status not yet written by controller — treat as equal to spec.
        extract_replicas(obj)
    }
}

// ---------------------------------------------------------------------------
// Shared scale implementation — parameterised by group and resource.
//
// group="apps"  → apps/v1 workloads (deployments, replicasets, statefulsets)
// group=""       → core/v1 ReplicationController
//
// The public handlers below are thin wrappers that extract path segments and
// forward to these impls, keeping the route-specific Path extractor types out
// of the shared logic.
// ---------------------------------------------------------------------------

async fn scale_get_impl<S: Store>(
    state: AppState<S>,
    group: &str,
    resource: &str,
    ns: &str,
    name: &str,
) -> Result<Response, crate::status::StatusError> {
    let key = group_object_key(group, resource, Some(ns), name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(name, resource))?;

    let obj: serde_json::Value = serde_json::from_slice(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let spec_replicas = extract_replicas(&obj);
    let status_replicas = extract_status_replicas(&obj);
    let selector = label_selector_to_string(&obj["spec"]["selector"]);
    let rv = obj["metadata"]["resourceVersion"]
        .as_str()
        .unwrap_or("")
        .to_string();

    Ok(Json(build_scale(
        name,
        ns,
        spec_replicas,
        status_replicas,
        &rv,
        &selector,
    ))
    .into_response())
}

async fn scale_put_impl<S: Store>(
    state: AppState<S>,
    group: &str,
    resource: &str,
    ns: &str,
    name: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let scale = decode_scale_body(body, headers)?;

    let new_replicas = scale
        .spec
        .replicas
        .ok_or_else(|| Status::bad_request("spec.replicas must be an integer".into()))?
        as i64;

    let key = group_object_key(group, resource, Some(ns), name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(name, resource))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let old_replicas = extract_replicas(&obj.body);
    // Capture actual pod count before changing spec so the response reflects reality.
    let status_replicas = extract_status_replicas(&obj.body);
    let selector = label_selector_to_string(&obj.body["spec"]["selector"]);
    obj.body["spec"]["replicas"] = serde_json::Value::Number(new_replicas.into());

    // Increment generation when spec.replicas changes — controllers use
    // generation/observedGeneration to detect spec drift and trigger reconciliation.
    if new_replicas != old_replicas {
        let gen = obj.body["metadata"]["generation"].as_i64().unwrap_or(1);
        obj.body["metadata"]["generation"] = serde_json::json!(gen + 1);
    }

    let expected_rv =
        crate::util::parse_resource_version(scale.metadata.resource_version.as_deref())?;
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, name, resource))?;

    Ok(Json(build_scale(
        name,
        ns,
        new_replicas,
        status_replicas,
        &new_rv.to_string(),
        &selector,
    )))
}

async fn scale_patch_impl<S: Store>(
    state: AppState<S>,
    group: &str,
    resource: &str,
    ns: &str,
    name: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Accept both JSON and proto bodies; extract spec.replicas from whichever.
    let ct = content_type(headers);
    let decoded = extract_body(body, ct);
    let patch_body: serde_json::Value =
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&decoded) {
            v
        } else if let Some(scale) = try_decode_proto_scale_body(body) {
            serde_json::to_value(scale).unwrap_or_default()
        } else {
            let e = serde_json::from_slice::<serde_json::Value>(body)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unrecognised body format".into());
            return Err(Status::bad_request(format!("invalid JSON: {e}")));
        };
    let patch_scale_spec: ScaleSpec =
        serde_json::from_value(patch_body["spec"].clone()).unwrap_or_default();

    let key = group_object_key(group, resource, Some(ns), name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(name, resource))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let old_replicas = extract_replicas(&obj.body);
    // Capture actual pod count before changing spec so the response reflects reality.
    let status_replicas = extract_status_replicas(&obj.body);
    let selector = label_selector_to_string(&obj.body["spec"]["selector"]);

    // Extract replicas from patch if present; otherwise keep current value.
    let new_replicas = if let Some(r) = patch_scale_spec.replicas {
        let r = r as i64;
        obj.body["spec"]["replicas"] = serde_json::json!(r);
        r
    } else {
        old_replicas
    };

    // Increment generation when spec.replicas changes — controllers use
    // generation/observedGeneration to detect spec drift and trigger reconciliation.
    if new_replicas != old_replicas {
        let gen = obj.body["metadata"]["generation"].as_i64().unwrap_or(1);
        obj.body["metadata"]["generation"] = serde_json::json!(gen + 1);
    }

    let expected_rv =
        crate::util::parse_resource_version(patch_body["metadata"]["resourceVersion"].as_str())?;
    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err(e, name, resource))?;

    Ok(Json(build_scale(
        name,
        ns,
        new_replicas,
        status_replicas,
        &new_rv.to_string(),
        &selector,
    )))
}

// ---------------------------------------------------------------------------
// apps/v1 scale handlers — GET/PUT/PATCH
//
// Routes:
//   GET    /apis/apps/v1/namespaces/:ns/:resource/:name/scale
//   PUT    /apis/apps/v1/namespaces/:ns/:resource/:name/scale
//   PATCH  /apis/apps/v1/namespaces/:ns/:resource/:name/scale
//
// Supports deployments, replicasets, statefulsets (all stored under group="apps").
// ---------------------------------------------------------------------------

/// GET /apis/apps/v1/namespaces/:ns/:resource/:name/scale
pub async fn get_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, resource, name)): Path<(String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    require_scale_resource(&resource)?;
    scale_get_impl(state, "apps", &resource, &ns, &name).await
}

/// PUT /apis/apps/v1/namespaces/:ns/:resource/:name/scale
///
/// Accepts a Scale object body; writes `spec.replicas` back into the stored
/// workload, increments resourceVersion, returns the updated Scale.
///
/// Accepts both `application/json` and `application/vnd.kubernetes.protobuf`
/// request bodies — client-go sends protobuf by default.
pub async fn put_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, resource, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    require_scale_resource(&resource)?;
    scale_put_impl(state, "apps", &resource, &ns, &name, &headers, &body).await
}

/// PATCH /apis/apps/v1/namespaces/:ns/:resource/:name/scale
///
/// Accepts a JSON merge-patch body targeting the Scale object.  Only
/// `spec.replicas` is extracted and written back to the stored workload.
///
/// Accepts both `application/json` and `application/vnd.kubernetes.protobuf`
/// request bodies — client-go sends protobuf by default.
pub async fn patch_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, resource, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    require_scale_resource(&resource)?;
    scale_patch_impl(state, "apps", &resource, &ns, &name, &headers, &body).await
}

// ---------------------------------------------------------------------------
// ReplicationController scale handlers — GET/PUT/PATCH
//
// Routes:
//   GET    /api/v1/namespaces/:ns/replicationcontrollers/:name/scale
//   PUT    /api/v1/namespaces/:ns/replicationcontrollers/:name/scale
//   PATCH  /api/v1/namespaces/:ns/replicationcontrollers/:name/scale
//
// RCs are a core/v1 resource (group="") — their store key differs from apps/v1
// workloads.  These thin wrappers forward to the shared impl with group="".
// The 2-element path extractor (ns, name) matches the route pattern which has
// the resource fixed to "replicationcontrollers".
// ---------------------------------------------------------------------------

/// GET /api/v1/namespaces/:ns/replicationcontrollers/:name/scale
pub async fn get_rc_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    scale_get_impl(state, "", "replicationcontrollers", &ns, &name).await
}

/// PUT /api/v1/namespaces/:ns/replicationcontrollers/:name/scale
pub async fn put_rc_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    scale_put_impl(
        state,
        "",
        "replicationcontrollers",
        &ns,
        &name,
        &headers,
        &body,
    )
    .await
}

/// PATCH /api/v1/namespaces/:ns/replicationcontrollers/:name/scale
pub async fn patch_rc_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    scale_patch_impl(
        state,
        "",
        "replicationcontrollers",
        &ns,
        &name,
        &headers,
        &body,
    )
    .await
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
        let scale = build_scale("my-deploy", "default", 3, 3, "42", "app=my-deploy");
        assert_eq!(scale["apiVersion"], "autoscaling/v1");
        assert_eq!(scale["kind"], "Scale");
    }

    #[test]
    fn build_scale_embeds_spec_and_status_replicas_independently() {
        // spec.replicas is the desired count; status.replicas is the actual count.
        // They may differ while pods are being created or terminated — build_scale
        // must embed each value in the correct field so HPA and test AfterEach loops
        // can distinguish "desired=0" from "actual=0".
        let scale = build_scale("my-sts", "default", 0, 3, "7", "app=my-sts");
        assert_eq!(
            scale["spec"]["replicas"], 0,
            "spec.replicas must reflect the desired count written by kubectl scale"
        );
        assert_eq!(
            scale["status"]["replicas"], 3,
            "status.replicas must reflect the actual pod count, not spec.replicas — \
             scale-to-0 AfterEach loops poll status.replicas; if it equals spec.replicas \
             immediately the test cannot detect that pods are still running"
        );
    }

    #[test]
    fn build_scale_includes_metadata_name_namespace_rv() {
        let scale = build_scale("my-deploy", "production", 2, 2, "99", "app=my-deploy");
        assert_eq!(scale["metadata"]["name"], "my-deploy");
        assert_eq!(scale["metadata"]["namespace"], "production");
        assert_eq!(scale["metadata"]["resourceVersion"], "99");
    }

    #[test]
    fn build_scale_embeds_selector_in_status() {
        // The Scale object's status.selector is what upstream's HPA controller
        // (validateAndParseSelector) reads to build its pod-metrics query — an
        // empty string here is treated as a hard, unrecoverable error and the
        // HPA never proceeds to compute metrics.
        let scale = build_scale("my-deploy", "default", 3, 3, "42", "app=my-deploy");
        assert_eq!(
            scale["status"]["selector"], "app=my-deploy",
            "status.selector must carry the caller-supplied selector string, not \
             a hardcoded empty string — HPA treats \"\" as a fatal configuration error"
        );
    }

    // -- label_selector_to_string --

    #[test]
    fn label_selector_to_string_renders_apps_v1_match_labels_as_equality_terms() {
        // Deployment/ReplicaSet/StatefulSet store spec.selector as a structured
        // LabelSelector ({"matchLabels": {...}}). The HPA controller parses
        // status.selector with client-go's labels.Parse, which expects the
        // classic "key=value,key2=value2" form — this is the mandatory case
        // since every real HPA target hits this path.
        let sel = serde_json::json!({ "matchLabels": { "app": "web", "tier": "frontend" } });
        assert_eq!(label_selector_to_string(&sel), "app=web,tier=frontend");
    }

    #[test]
    fn label_selector_to_string_renders_replicationcontroller_flat_map_as_equality_terms() {
        // ReplicationController stores spec.selector as a flat map<string,string>,
        // never wrapped in matchLabels (see defaults.rs). Without this branch,
        // RC-backed HPAs would get status.selector="" even though a selector exists.
        let sel = serde_json::json!({ "app": "web" });
        assert_eq!(label_selector_to_string(&sel), "app=web");
    }

    #[test]
    fn label_selector_to_string_renders_match_expressions_in_standard_selector_syntax() {
        // A HorizontalPodAutoscaler target may use set-based matchExpressions
        // instead of/alongside matchLabels. client-go's labels.Parse (and this
        // codebase's own parse_label_selector) expect "key In (v1,v2)" syntax —
        // rendering anything else would make the HPA fail to parse the selector.
        let sel = serde_json::json!({
            "matchExpressions": [
                { "key": "env", "operator": "In", "values": ["prod", "staging"] }
            ]
        });
        assert_eq!(label_selector_to_string(&sel), "env In (prod,staging)");
    }

    #[test]
    fn label_selector_to_string_combines_match_labels_and_match_expressions() {
        let sel = serde_json::json!({
            "matchLabels": { "app": "web" },
            "matchExpressions": [
                { "key": "tier", "operator": "NotIn", "values": ["cache"] }
            ]
        });
        assert_eq!(label_selector_to_string(&sel), "app=web,tier NotIn (cache)");
    }

    #[test]
    fn label_selector_to_string_returns_empty_string_for_null_selector() {
        // A workload with no selector at all (should not occur for validated
        // apps/v1 workloads, but must not panic) renders to "" rather than error.
        assert_eq!(label_selector_to_string(&serde_json::Value::Null), "");
    }

    #[test]
    fn label_selector_to_string_round_trips_through_this_codebase_own_selector_parser() {
        // The real bar for this helper is not "does the string look right" but
        // "does a real selector-matching implementation accept it and match the
        // right pods" — parse_label_selector + apply_label_selector is the
        // selector-matching path this codebase uses for LIST ?labelSelector=,
        // and is structurally the same matcher an HPA-adjacent controller would
        // use. If label_selector_to_string ever produces a string this parser
        // rejects or matches incorrectly, this test fails.
        use crate::handlers::generic::{apply_label_selector, parse_label_selector};

        let sel = serde_json::json!({ "matchLabels": { "app": "web", "tier": "frontend" } });
        let selector_string = label_selector_to_string(&sel);

        let terms = parse_label_selector(&selector_string)
            .expect("a selector string built by label_selector_to_string must parse");

        let matching_pod = serde_json::json!({
            "metadata": { "labels": { "app": "web", "tier": "frontend", "extra": "ignored" } }
        });
        let other_pod = serde_json::json!({
            "metadata": { "labels": { "app": "web", "tier": "backend" } }
        });

        let matched = apply_label_selector(vec![matching_pod.clone(), other_pod], &terms);
        assert_eq!(
            matched,
            vec![matching_pod],
            "the selector string round-tripped through parse_label_selector/apply_label_selector \
             must match exactly the pods carrying all of the workload's selector labels — this is \
             the real end-to-end guarantee HPA depends on, not just string formatting"
        );
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

    // -- extract_status_replicas --

    #[test]
    fn extract_status_replicas_reads_status_replicas() {
        // The KCM writes status.replicas as pods are created/deleted; get_scale
        // must return this value so HPA and kubectl see the real pod count.
        let obj = serde_json::json!({ "spec": { "replicas": 0 }, "status": { "replicas": 3 } });
        assert_eq!(
            extract_status_replicas(&obj),
            3,
            "status.replicas must be read from status, not spec — scale-to-0 AfterEach \
             polls the Scale object; if status.replicas equals spec.replicas immediately \
             the test cannot distinguish desired=0 from actual=0"
        );
    }

    #[test]
    fn extract_status_replicas_falls_back_to_spec_when_status_absent() {
        // Before the KCM reconciles for the first time, status.replicas may be absent.
        // Fall back to spec.replicas so callers get a plausible default.
        let obj = serde_json::json!({ "spec": { "replicas": 5 } });
        assert_eq!(
            extract_status_replicas(&obj),
            5,
            "when status.replicas is absent, fall back to spec.replicas"
        );
    }

    #[test]
    fn extract_status_replicas_zero_is_terminal_state() {
        // A StatefulSet that has been fully scaled to 0 must return 0, not
        // fall back to spec.replicas. This is the terminal state AfterEach waits for.
        let obj = serde_json::json!({ "spec": { "replicas": 0 }, "status": { "replicas": 0 } });
        assert_eq!(
            extract_status_replicas(&obj),
            0,
            "status.replicas=0 must be returned as 0, not overridden by spec fallback"
        );
    }

    // -- require_scale_resource --

    #[test]
    fn require_scale_resource_accepts_workload_plurals() {
        // apps/v1 workloads and core/v1 replicationcontrollers expose a scale
        // subresource in Kubernetes; any other resource must return 404.
        assert!(require_scale_resource("deployments").is_ok());
        assert!(require_scale_resource("replicasets").is_ok());
        assert!(require_scale_resource("statefulsets").is_ok());
        assert!(require_scale_resource("replicationcontrollers").is_ok());
    }

    #[test]
    fn require_scale_resource_rejects_others() {
        assert!(require_scale_resource("daemonsets").is_err());
        assert!(require_scale_resource("pods").is_err());
        assert!(require_scale_resource("configmaps").is_err());
    }

    // -- ScaleSpec deserialization --

    #[test]
    fn scale_spec_deserializes_replicas() {
        // The compiler now enforces the field name — a typo ("replikas") would
        // be a compile error rather than a silent runtime zero.
        let spec: ScaleSpec = serde_json::from_str(r#"{"replicas": 3}"#).unwrap();
        assert_eq!(spec.replicas, Some(3));
    }

    #[test]
    fn scale_spec_defaults_missing_replicas() {
        // An absent replicas field must deserialize to None (not a panic or error).
        // Callers use unwrap_or(0) to get the default, preserving explicit intent.
        let spec: ScaleSpec = serde_json::from_str("{}").unwrap();
        assert_eq!(spec.replicas, None);
    }

    #[test]
    fn scale_spec_rejects_wrong_type() {
        // i32 deserialization is strict — a string "three" must fail.
        // This verifies the type guard that prevents silent coercions.
        let result: Result<ScaleSpec, _> = serde_json::from_str(r#"{"replicas": "three"}"#);
        assert!(result.is_err());
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

    /// GET scale on a Deployment with a real spec.selector must populate
    /// status.selector with the equivalent selector string, not "".
    ///
    /// This is the direct regression test for the HPA-breaking bug: upstream's
    /// HPA controller (validateAndParseSelector) treats status.selector=="" as
    /// a hard, unrecoverable error and never computes metrics — every HPA
    /// targeting any Deployment would fail permanently if this regresses.
    #[tokio::test]
    async fn get_scale_populates_status_selector_from_deployment_spec_selector() {
        let (state, store) = make_state();
        let key = "/registry/apps/deployments/default/my-deploy";
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "my-deploy", "namespace": "default", "resourceVersion": "1" },
            "spec": {
                "replicas": 3,
                "selector": { "matchLabels": { "app": "my-deploy" } }
            },
            "status": { "replicas": 3 }
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&deploy).unwrap()), None)
            .await
            .unwrap();

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
        assert_eq!(
            json["status"]["selector"], "app=my-deploy",
            "status.selector must reflect the Deployment's spec.selector — an empty \
             string here makes every HorizontalPodAutoscaler targeting this Deployment \
             fail permanently with kube-controller-manager's \"selector is required\" error"
        );
    }

    /// GET scale on a StatefulSet whose spec.replicas=0 but status.replicas=3 (pods still running)
    /// must return status.replicas=3, not 0.
    ///
    /// This is the regression test: after scale-to-0, AfterEach polls the scale
    /// subresource waiting for status.replicas==0. If status.replicas is always set to spec.replicas,
    /// it incorrectly shows 0 immediately even while pods are still running, making the AfterEach
    /// think cleanup is done prematurely while other tests see stale pods.
    #[tokio::test]
    async fn get_scale_status_replicas_reflects_stored_status_not_spec() {
        let (state, store) = make_state();

        // Simulate a StatefulSet that was scaled to 0 (spec.replicas=0) but whose pods
        // have not yet terminated (status.replicas=3 — written by the KCM).
        let key = "/registry/apps/statefulsets/default/web";
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "web", "namespace": "default", "resourceVersion": "10" },
            "spec": { "replicas": 0 },
            "status": { "replicas": 3 }
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&sts).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                get(get_scale),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/apis/apps/v1/namespaces/default/statefulsets/web/scale")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["spec"]["replicas"], 0,
            "spec.replicas must reflect the desired count (0 — scale-to-0 was issued)"
        );
        assert_eq!(
            json["status"]["replicas"], 3,
            "status.replicas must reflect actual pod count (3) even after scale-to-0 — \
             if it returned 0 immediately, AfterEach would think cleanup is done while \
             3 pods are still running, causing subsequent tests to see unexpected pods \
             (regression: scale subresource status.replicas must lag spec.replicas)"
        );
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
        // spec.replicas reflects the newly desired count.
        assert_eq!(json["spec"]["replicas"], 5);
        // status.replicas reflects the actual pod count (from stored status before write).
        // The stored deployment has no status.replicas yet, so it falls back to the
        // old spec.replicas (1). The controller will update status.replicas asynchronously.
        assert_eq!(
            json["status"]["replicas"], 1,
            "status.replicas must reflect the actual pod count at the time of the write, \
             not the newly-desired spec.replicas — the two may differ while pods are being \
             created or terminated"
        );

        // Confirm the workload in the store was actually updated.
        let key = "/registry/apps/deployments/default/my-deploy";
        let stored = store.get(key).await.unwrap().unwrap();
        let stored_obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(stored_obj["spec"]["replicas"], 5);
    }

    /// PUT scale on a workload with spec.selector must also populate status.selector
    /// in the response — HPA reads the Scale response returned from its own PUT/PATCH
    /// call, not just from a separate GET, so this path must carry the selector too.
    #[tokio::test]
    async fn put_scale_populates_status_selector_from_spec_selector() {
        let (state, store) = make_state();
        let key = "/registry/apps/statefulsets/default/web";
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "web", "namespace": "default", "resourceVersion": "1" },
            "spec": {
                "replicas": 1,
                "selector": { "matchLabels": { "app": "web", "tier": "backend" } }
            },
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&sts).unwrap()), None)
            .await
            .unwrap();

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
            .uri("/apis/apps/v1/namespaces/default/statefulsets/web/scale")
            .header("content-type", "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(
            json["status"]["selector"], "app=web,tier=backend",
            "PUT /scale response must carry status.selector from the stored workload's \
             spec.selector — an empty string here breaks HPA on this StatefulSet identically \
             to the GET path"
        );
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

    // -----------------------------------------------------------------------
    // Generation increment on scale change
    // -----------------------------------------------------------------------

    /// PUT scale that changes spec.replicas must increment metadata.generation.
    ///
    /// The StatefulSet controller (KCM) uses generation/observedGeneration to
    /// detect spec drift and trigger reconciliation. Without generation increment,
    /// scale-to-0 might not trigger a status update — `status.replicas` stays
    /// stale and AfterEach cleanup loops for 10 minutes.
    ///
    /// This test fails if the generation increment is removed from put_scale.
    #[tokio::test]
    async fn put_scale_increments_generation_when_replicas_change() {
        let (state, store) = make_state();
        // Seed StatefulSet with generation=1, replicas=3.
        let key = "/registry/apps/statefulsets/default/web";
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "web",
                "namespace": "default",
                "resourceVersion": "5",
                "generation": 1
            },
            "spec": { "replicas": 3 },
            "status": { "replicas": 3 }
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&sts).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "autoscaling/v1",
            "kind": "Scale",
            "spec": { "replicas": 0 }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/statefulsets/web/scale")
            .header("content-type", "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Confirm the stored object has generation=2.
        let stored = store.get(key).await.unwrap().unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            obj["metadata"]["generation"], 2,
            "generation must be incremented when spec.replicas changes — \
             the KCM statefulset controller uses generation/observedGeneration \
             to detect spec drift; without increment, status.replicas may not \
             be updated after scale-to-0"
        );
    }

    /// PUT scale that does NOT change spec.replicas must NOT increment generation.
    ///
    /// Setting replicas to the current value is a no-op; generation must stay
    /// the same so controllers don't do unnecessary reconciliation work.
    ///
    /// This test fails if generation is unconditionally incremented.
    #[tokio::test]
    async fn put_scale_does_not_increment_generation_when_replicas_unchanged() {
        let (state, store) = make_state();
        let key = "/registry/apps/statefulsets/default/web";
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "web",
                "namespace": "default",
                "resourceVersion": "5",
                "generation": 2
            },
            "spec": { "replicas": 3 },
            "status": { "replicas": 3 }
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&sts).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        // PUT with the same replicas count.
        let body = serde_json::json!({
            "apiVersion": "autoscaling/v1",
            "kind": "Scale",
            "spec": { "replicas": 3 }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/statefulsets/web/scale")
            .header("content-type", "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = store.get(key).await.unwrap().unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            obj["metadata"]["generation"], 2,
            "generation must NOT change when spec.replicas is unchanged — \
             no-op scale must not trigger unnecessary controller reconciliation"
        );
    }

    /// PATCH scale that changes spec.replicas must also increment metadata.generation.
    ///
    /// Same requirement as put_scale — this test fails if the generation increment
    /// is removed from patch_scale.
    #[tokio::test]
    async fn patch_scale_increments_generation_when_replicas_change() {
        let (state, store) = make_state();
        let key = "/registry/apps/statefulsets/default/web";
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "web",
                "namespace": "default",
                "resourceVersion": "5",
                "generation": 1
            },
            "spec": { "replicas": 5 },
            "status": { "replicas": 5 }
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&sts).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                patch(patch_scale),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "replicas": 0 } });

        let req = Request::builder()
            .method("PATCH")
            .uri("/apis/apps/v1/namespaces/default/statefulsets/web/scale")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = store.get(key).await.unwrap().unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            obj["metadata"]["generation"], 2,
            "generation must be incremented by patch_scale when spec.replicas changes — \
             kubectl scale uses PATCH; without increment the KCM may not reconcile"
        );
    }

    // -----------------------------------------------------------------------
    // Regression tests: proto body support and no-status
    // StatefulSet handling
    // -----------------------------------------------------------------------

    /// PUT scale on a StatefulSet with no status field returns valid JSON.
    ///
    /// This is the direct regression test. A freshly-created
    /// StatefulSet may have no `status` key at all (the KCM hasn't reconciled
    /// yet). Before the fix, `extract_status_replicas` could panic or produce
    /// an unexpected value; with the fix it falls back to `spec.replicas`.
    ///
    /// The response MUST be parseable JSON with the correct spec.replicas —
    /// the sonobuoy "should have a working scale subresource" test asserts on
    /// `scaleResult.Spec.Replicas` and treats any parse failure as a test error.
    #[tokio::test]
    async fn put_scale_on_statefulset_with_no_status_returns_valid_json() {
        let (state, store) = make_state();

        // Seed a StatefulSet with NO status field at all (no `status` key).
        // This is the state immediately after creation, before KCM reconciles.
        let key = "/registry/apps/statefulsets/default/web";
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "web",
                "namespace": "default",
                "resourceVersion": "1",
                "generation": 1
            },
            "spec": { "replicas": 1 }
            // Deliberately absent "status" key — simulates freshly-created StatefulSet
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&sts).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "autoscaling/v1",
            "kind": "Scale",
            "spec": { "replicas": 3 }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/statefulsets/web/scale")
            .header("content-type", "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // MUST return 200, not 400 or 500.
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PUT scale on a StatefulSet with no status must return 200 — \
             the sonobuoy 'should have a working scale subresource' conformance \
             test fails with 'invalid JSON' if the response body is empty or missing"
        );

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // MUST be parseable as JSON — if the body is empty the Go test reports
        // "invalid JSON: expected value at line 1 column 1".
        let json: serde_json::Value = serde_json::from_slice(&resp_body).expect(
            "PUT scale response must be valid JSON — empty body causes \
             'invalid JSON: expected value at line 1 column 1' in sonobuoy",
        );

        assert_eq!(
            json["apiVersion"], "autoscaling/v1",
            "PUT scale response must be an autoscaling/v1 Scale object"
        );
        assert_eq!(
            json["spec"]["replicas"], 3,
            "spec.replicas must reflect the PUT value (3)"
        );
        // status.replicas must fall back to the old spec.replicas (1) since the
        // StatefulSet has no status field — KCM hasn't reconciled yet.
        assert_eq!(
            json["status"]["replicas"], 1,
            "status.replicas must fall back to spec.replicas (1) when status is absent — \
             KCM hasn't written status.replicas yet for a freshly-created StatefulSet"
        );
    }

    /// PUT scale with a proto-encoded body returns valid JSON.
    ///
    /// client-go sends `Content-Type: application/vnd.kubernetes.protobuf` by
    /// default for write operations (PUT/PATCH).  Before the fix, put_scale
    /// tried to parse proto bytes as JSON, failed with "expected value at line 1
    /// column 1", and returned HTTP 400.  The sonobuoy conformance test then
    /// reported "Failed to put scale subresource: invalid JSON: …".
    ///
    /// This test constructs a minimal k8s proto envelope containing an
    /// autoscaling/v1 Scale and verifies that put_scale accepts it and returns
    /// valid JSON with the correct spec.replicas.
    #[tokio::test]
    async fn put_scale_accepts_proto_body_and_returns_valid_json() {
        let (state, store) = make_state();
        seed_workload(&store, "statefulsets", "default", "web", 1).await;

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        // Build a minimal k8s proto envelope whose raw field contains a
        // proto-encoded autoscaling/v1 Scale with spec.replicas = 3.
        //
        // Wire format:
        //   [4-byte magic: 0x6b, 0x38, 0x73, 0x00]
        //   [proto-encoded Unknown envelope]
        //     field 1 (TypeMeta):    tag=0x0a (field 1, wire type 2)
        //       field 1 (apiVersion): "autoscaling/v1"
        //       field 2 (kind):       "Scale"
        //     field 2 (raw bytes):   proto-encoded Scale
        //       Scale field 2 (ScaleSpec):
        //         ScaleSpec field 1 (replicas): 3 (varint)
        //     field 4 (contentType): "" (proto)

        fn varint(v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            let mut v = v;
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(b);
                    break;
                }
                out.push(b | 0x80);
            }
            out
        }

        fn ld(field: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field << 3) | 2;
            let mut out = varint(tag);
            out.extend(varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }

        fn vfield(field: u64, v: i32) -> Vec<u8> {
            let tag = field << 3; // wire type 0 = varint
            let mut out = varint(tag);
            out.extend(varint(v as u64));
            out
        }

        // TypeMeta { apiVersion: "autoscaling/v1", kind: "Scale" }
        let api_version = ld(1, b"autoscaling/v1");
        let kind = ld(2, b"Scale");
        let type_meta_bytes: Vec<u8> = [api_version, kind].concat();

        // ScaleSpec { replicas: 3 }
        let scale_spec_bytes = vfield(1, 3); // ScaleSpec.replicas = 3 (varint field 1)

        // Scale { spec: ScaleSpec } — spec is field 2 of Scale
        let scale_raw = ld(2, &scale_spec_bytes);

        // Unknown { typeMeta, raw, contentType="" }
        let envelope: Vec<u8> = [
            ld(1, &type_meta_bytes), // field 1: TypeMeta
            ld(2, &scale_raw),       // field 2: raw (proto-encoded Scale)
        ]
        .concat();

        let mut proto_body: Vec<u8> = K8S_PROTO_MAGIC.to_vec();
        proto_body.extend(envelope);

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/statefulsets/web/scale")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(Body::from(Bytes::from(proto_body)))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PUT scale with proto body must return 200 — before the fix, proto bytes \
             were passed to serde_json::from_slice which returned 'invalid JSON: \
             expected value at line 1 column 1' and the handler returned 400"
        );

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp_body)
            .expect("PUT scale response to proto body must be valid JSON");

        assert_eq!(
            json["spec"]["replicas"], 3,
            "spec.replicas must be 3 (the value from the proto body)"
        );
        assert_eq!(
            json["apiVersion"], "autoscaling/v1",
            "response must be autoscaling/v1 Scale"
        );
    }

    // -----------------------------------------------------------------------
    // ReplicationController scale subresource — core/v1 store key resolution
    //
    // RCs are stored at /registry/replicationcontrollers/{ns}/{name} (group=""),
    // not under apps/v1. These tests verify that the RC-specific handlers use the
    // correct store key so that HPA and kubectl scale work on RCs.
    // -----------------------------------------------------------------------

    /// Seed a ReplicationController into the store at the core/v1 key.
    async fn seed_rc(store: &Arc<SqliteStore>, ns: &str, name: &str, replicas: i64) {
        // Core/v1 RC store key: /registry/replicationcontrollers/{ns}/{name}
        let key = format!("/registry/replicationcontrollers/{ns}/{name}");
        let val = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": {
                "name": name,
                "namespace": ns,
                "resourceVersion": "1",
                "generation": 1
            },
            "spec": { "replicas": replicas },
            "status": {}
        });
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed rc");
    }

    /// GET scale on a ReplicationController resolves the core/v1 store key and returns
    /// autoscaling/v1 Scale. This verifies the RC handler does NOT look under apps/v1
    /// (which would yield 404) — kubectl and HPA use GET scale on RCs.
    ///
    /// Fails on revert: if get_rc_scale is removed or uses group="apps", the store lookup
    /// hits /registry/apps/replicationcontrollers/{ns}/{name} which does not exist → 404.
    #[tokio::test]
    async fn replicationcontroller_scale_subresource_resolves_core_rc_so_hpa_and_kubectl_scale_work(
    ) {
        let (state, store) = make_state();
        seed_rc(&store, "default", "my-rc", 2).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/replicationcontrollers/{name}/scale",
                get(get_rc_scale),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/replicationcontrollers/my-rc/scale")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET scale on an RC must return 200 — before this fix the route was missing \
             entirely → 404 'could not find the requested resource' (rc.go:302)"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["apiVersion"], "autoscaling/v1");
        assert_eq!(json["kind"], "Scale");
        assert_eq!(
            json["spec"]["replicas"], 2,
            "spec.replicas must reflect the RC's stored replica count"
        );
        assert_eq!(json["metadata"]["name"], "my-rc");
        assert_eq!(json["metadata"]["namespace"], "default");
    }

    /// GET scale on a ReplicationController must render its flat map<string,string>
    /// spec.selector (not wrapped in matchLabels — see defaults.rs) into status.selector.
    ///
    /// RC's selector shape differs from Deployment/ReplicaSet/StatefulSet's structured
    /// LabelSelector; without handling the flat-map case, RC-backed HPAs would also see
    /// status.selector="" and fail identically to the apps/v1 case.
    #[tokio::test]
    async fn get_rc_scale_populates_status_selector_from_flat_map_selector() {
        let (state, store) = make_state();
        let key = "/registry/replicationcontrollers/default/my-rc";
        let rc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "my-rc", "namespace": "default", "resourceVersion": "1" },
            "spec": {
                "replicas": 2,
                "selector": { "app": "my-rc" }
            },
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&rc).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/replicationcontrollers/{name}/scale",
                get(get_rc_scale),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/replicationcontrollers/my-rc/scale")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["status"]["selector"], "app=my-rc",
            "status.selector must render the RC's flat-map selector — an empty string \
             here breaks HPA on ReplicationControllers the same way it does for Deployments"
        );
    }

    /// PATCH scale on an RC writes spec.replicas back to the correct core/v1 store key
    /// and the updated replica count is visible via GET. This verifies the end-to-end
    /// conformance path: rc.go PATCHes /scale and then reads back to confirm the change.
    ///
    /// Fails on revert: if patch_rc_scale uses group="apps", the PUT hits the wrong key
    /// and the RC's actual spec.replicas is never updated — kubectl scale silently no-ops.
    #[tokio::test]
    async fn patch_rc_scale_writes_spec_replicas_to_core_store_key() {
        let (state, store) = make_state();
        seed_rc(&store, "default", "my-rc", 1).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/replicationcontrollers/{name}/scale",
                patch(patch_rc_scale),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "replicas": 3 } });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/replicationcontrollers/my-rc/scale")
            .header("content-type", "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH scale on an RC must return 200 — conformance test rc.go:302 \
             'Failed to patch ReplicationControllerScale: the server could not find the \
             requested resource' was a 404 because the route did not exist"
        );

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(
            json["spec"]["replicas"], 3,
            "response spec.replicas must reflect the patched value"
        );

        // Confirm the RC in the store was updated at the correct core/v1 key.
        let key = "/registry/replicationcontrollers/default/my-rc";
        let stored = store.get(key).await.unwrap().unwrap();
        let stored_obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_obj["spec"]["replicas"], 3,
            "RC spec.replicas in the store must be updated — if the handler used \
             group='apps' it would write to the wrong key and the RC would not scale"
        );
    }

    /// require_scale_resource must accept replicationcontrollers — without this entry
    /// the generic path (if ever used for RCs) would return 404.
    ///
    /// Fails on revert: removing "replicationcontrollers" from SCALE_RESOURCES causes
    /// this assertion to fail.
    #[test]
    fn require_scale_resource_accepts_replicationcontrollers() {
        // replicationcontrollers/scale is a core/v1 subresource granted to HPA by RBAC.
        // The allowlist must include it so the generic validation path does not reject RCs.
        assert!(
            require_scale_resource("replicationcontrollers").is_ok(),
            "replicationcontrollers must be in SCALE_RESOURCES — HPA and kubectl scale \
             both use the /scale subresource for RCs; without this entry any generic \
             require_scale_resource check would return 404"
        );
    }

    // -----------------------------------------------------------------------
    // Regression test: unified handler must keep RC on core key
    //
    // After the refactor the RC handlers delegate to scale_put_impl/scale_get_impl
    // with group="".  This test confirms the RC path still resolves the correct
    // core store key (/registry/replicationcontrollers/…) and does NOT fall back
    // to the apps store key (/registry/apps/replicationcontrollers/…).
    // -----------------------------------------------------------------------

    /// PUT scale on an RC via the unified handler writes spec.replicas to the
    /// core/v1 store key (group=""), not the apps/v1 key.
    ///
    /// Fails on revert: if put_rc_scale passes group="apps" to scale_put_impl,
    /// the store lookup hits /registry/apps/replicationcontrollers/{ns}/{name}
    /// which does not exist — the handler returns 404 instead of 200, and HPA
    /// cannot scale ReplicationControllers.
    #[tokio::test]
    async fn put_rc_scale_via_unified_handler_resolves_core_group_store_key() {
        let (state, store) = make_state();
        seed_rc(&store, "default", "my-rc", 1).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/replicationcontrollers/{name}/scale",
                put(put_rc_scale),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "autoscaling/v1",
            "kind": "Scale",
            "spec": { "replicas": 5 }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/replicationcontrollers/my-rc/scale")
            .header("content-type", "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PUT scale on an RC must return 200 — if the unified handler uses group='apps' \
             it looks up the wrong store key and returns 404, breaking HPA on RCs"
        );

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(
            json["spec"]["replicas"], 5,
            "response spec.replicas must reflect the PUT value"
        );

        // The RC must be updated at the core/v1 store key, not the apps key.
        let core_key = "/registry/replicationcontrollers/default/my-rc";
        let stored = store.get(core_key).await.unwrap().unwrap();
        let stored_obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_obj["spec"]["replicas"], 5,
            "RC spec.replicas must be written to the core/v1 store key — \
             a wrong group='apps' would write to /registry/apps/replicationcontrollers/… \
             (key not found) or silently create a stale entry, leaving the real RC unchanged"
        );

        // Confirm the apps key was NOT created (it should not exist).
        let apps_key = "/registry/apps/replicationcontrollers/default/my-rc";
        assert!(
            store.get(apps_key).await.unwrap().is_none(),
            "the apps/v1 store key must not be created for an RC — group must be '' not 'apps'"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: scale_put_impl must CAS on the incoming
    // Scale's metadata.resourceVersion, not the stored object's RV.
    // ---------------------------------------------------------------------------

    /// PUT /scale with a stale resourceVersion in the Scale body must return 409 Conflict.
    ///
    /// Without this fix scale_put_impl used the stored object's RV as the CAS token,
    /// making every PUT unconditional — HPA or kubectl scale holding a stale snapshot
    /// would silently overwrite a concurrent write instead of receiving 409 and retrying.
    #[tokio::test]
    async fn put_scale_stale_rv_returns_409_else_concurrent_writers_clobber() {
        let (state, store) = make_state();

        // Seed the deployment at rv=1.
        let key = "/registry/apps/deployments/default/cas-deploy";
        let val = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "cas-deploy", "namespace": "default", "resourceVersion": "1" },
            "spec": { "replicas": 1 },
            "status": {}
        });
        let rv1 = store
            .put(key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .unwrap();

        // Advance to rv2 (simulates a concurrent HPA write).
        let mut val2 = val.clone();
        val2["metadata"]["resourceVersion"] = serde_json::json!(rv1.to_string());
        val2["spec"]["replicas"] = serde_json::json!(3);
        let rv2 = store
            .put(
                key,
                Bytes::from(serde_json::to_vec(&val2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance after concurrent write");

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        // Scale body carries the now-stale rv1 — must be rejected with 409.
        let body = serde_json::json!({
            "apiVersion": "autoscaling/v1",
            "kind": "Scale",
            "metadata": { "name": "cas-deploy", "namespace": "default", "resourceVersion": rv1.to_string() },
            "spec": { "replicas": 2 }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/deployments/cas-deploy/scale")
            .header("content-type", "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "stale metadata.resourceVersion in PUT /scale body must return 409 Conflict — \
             without this, HPA and kubectl scale silently clobber concurrent replica updates"
        );
    }

    /// PUT /scale with an absent resourceVersion in the Scale body succeeds unconditionally.
    ///
    /// Clients that omit metadata.resourceVersion (e.g. single-writer kubectl scale calls)
    /// must not be broken by the stale-RV CAS fix.
    #[tokio::test]
    async fn put_scale_absent_rv_is_unconditional_write() {
        let (state, store) = make_state();
        seed_workload(&store, "deployments", "default", "no-rv-deploy", 1).await;

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                put(put_scale),
            )
            .with_state(state);

        // No metadata.resourceVersion — must succeed as unconditional write.
        let body = serde_json::json!({
            "apiVersion": "autoscaling/v1",
            "kind": "Scale",
            "spec": { "replicas": 4 }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/apis/apps/v1/namespaces/default/deployments/no-rv-deploy/scale")
            .header("content-type", "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "absent metadata.resourceVersion in PUT /scale body must succeed (unconditional) — \
             single-writer clients must not be broken by the stale-RV CAS fix"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests for PATCH /scale CAS (the PUT sibling was fixed but PATCH
    // was left reading the stored object's RV — unconditional writes).
    // HPA scales EXCLUSIVELY via PATCH — highest impact path.
    // ---------------------------------------------------------------------------

    /// PATCH /scale with a stale resourceVersion in the patch body must return 409 Conflict.
    ///
    /// HPA scales deployments/statefulsets exclusively via PATCH. Without this fix,
    /// patch_scale_impl used the stored object's RV as the CAS token, making every PATCH
    /// unconditional — a stale HPA write silently clobbers a concurrent write instead of
    /// receiving 409 and retrying from a fresh GET.
    #[tokio::test]
    async fn patch_scale_stale_rv_returns_409_else_hpa_silently_clobbers_concurrent_writes() {
        let (state, store) = make_state();

        let key = "/registry/apps/deployments/default/hpa-target";
        let val = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "hpa-target", "namespace": "default", "resourceVersion": "1" },
            "spec": { "replicas": 1 },
            "status": {}
        });
        let rv1 = store
            .put(key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .unwrap();

        // Advance to rv2 (simulates a concurrent write).
        let mut val2 = val.clone();
        val2["metadata"]["resourceVersion"] = serde_json::json!(rv1.to_string());
        val2["spec"]["replicas"] = serde_json::json!(5);
        let rv2 = store
            .put(
                key,
                Bytes::from(serde_json::to_vec(&val2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance after concurrent write");

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                patch(patch_scale),
            )
            .with_state(state);

        // Patch body carries the now-stale rv1 — must be rejected with 409.
        let body = serde_json::json!({
            "metadata": { "resourceVersion": rv1.to_string() },
            "spec": { "replicas": 2 }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/apis/apps/v1/namespaces/default/deployments/hpa-target/scale")
            .header("content-type", "application/merge-patch+json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "a stale HPA scale PATCH must 409, else it silently clobbers a concurrent write — \
             HPA scales exclusively via PATCH; without CAS it can overwrite a concurrent \
             kubectl scale or another HPA loop's update"
        );
    }

    /// PATCH /scale with no resourceVersion in the patch body succeeds unconditionally.
    ///
    /// Clients that omit metadata.resourceVersion must not be broken by the PATCH CAS fix.
    /// This is the common case: most PATCH scale bodies do not include metadata.resourceVersion.
    #[tokio::test]
    async fn patch_scale_absent_rv_is_unconditional_write() {
        let (state, store) = make_state();
        seed_workload(&store, "deployments", "default", "patch-norev", 3).await;

        let app = Router::new()
            .route(
                "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
                patch(patch_scale),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "replicas": 7 } });

        let req = Request::builder()
            .method("PATCH")
            .uri("/apis/apps/v1/namespaces/default/deployments/patch-norev/scale")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH /scale without metadata.resourceVersion must succeed (unconditional) — \
             the PATCH CAS fix must not break clients that omit the resourceVersion"
        );
    }
}
