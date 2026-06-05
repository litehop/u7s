use axum::http::{HeaderMap, HeaderValue};
use serde::Deserialize;

use crate::{status::Status, util::content_type};

/// Query parameters accepted by PATCH and write endpoints.
///
/// `field_validation` is accepted and ignored — the server does not implement
/// server-side field validation. Accepting it prevents 400 responses when clients
/// like `kubectl create` send `?fieldValidation=Strict` or `?fieldValidation=Warn`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct PatchQuery {
    #[serde(rename = "fieldManager")]
    pub field_manager: Option<String>,
    /// Accepted and ignored: we do not implement server-side field validation.
    #[serde(rename = "fieldValidation")]
    pub _field_validation: Option<String>,
}

/// Query parameters accepted by CREATE endpoints (POST).
///
/// `field_validation` drives server-side unknown-field detection:
///   - `Strict`  → 422 UnprocessableEntity with Status body listing unknown fields
///   - `Warn`    → 200/201 with `Warning: 299 - "..."` response header
///   - `Ignore`  → silently strip (default, existing behaviour)
#[derive(Debug, Default, Deserialize)]
pub(crate) struct CreateQuery {
    #[serde(rename = "fieldManager")]
    pub _field_manager: Option<String>,
    #[serde(rename = "fieldValidation")]
    pub field_validation: Option<String>,
}

// ---------------------------------------------------------------------------
// Known-field sets for top-level and metadata field validation
// ---------------------------------------------------------------------------

/// Known top-level fields for any Kubernetes typed object.
///
/// `apiVersion`, `kind`, `metadata` are universal.  The remaining fields cover
/// every resource in the static registry; unknown top-level keys trigger the
/// Strict/Warn validation path.
fn known_top_level_fields(group: &str, plural: &str) -> &'static [&'static str] {
    // Resource-specific extra fields beyond the universal set.
    match (group, plural) {
        // ConfigMap / Secret
        ("", "configmaps") => &[
            "apiVersion",
            "kind",
            "metadata",
            "data",
            "binaryData",
            "immutable",
        ],
        ("", "secrets") => &[
            "apiVersion",
            "kind",
            "metadata",
            "data",
            "stringData",
            "type",
            "immutable",
        ],
        // ServiceAccount
        ("", "serviceaccounts") => &[
            "apiVersion",
            "kind",
            "metadata",
            "secrets",
            "imagePullSecrets",
            "automountServiceAccountToken",
        ],
        // RBAC — cluster-scoped
        ("rbac.authorization.k8s.io", "clusterroles") => {
            &["apiVersion", "kind", "metadata", "rules", "aggregationRule"]
        }
        ("rbac.authorization.k8s.io", "clusterrolebindings") => {
            &["apiVersion", "kind", "metadata", "subjects", "roleRef"]
        }
        // RBAC — namespaced
        ("rbac.authorization.k8s.io", "roles") => &["apiVersion", "kind", "metadata", "rules"],
        ("rbac.authorization.k8s.io", "rolebindings") => {
            &["apiVersion", "kind", "metadata", "subjects", "roleRef"]
        }
        // StorageClass
        ("storage.k8s.io", "storageclasses") => &[
            "apiVersion",
            "kind",
            "metadata",
            "provisioner",
            "parameters",
            "reclaimPolicy",
            "volumeBindingMode",
            "allowVolumeExpansion",
            "mountOptions",
            "allowedTopologies",
        ],
        // VolumeAttributesClass
        ("storage.k8s.io", "volumeattributesclasses") => {
            &["apiVersion", "kind", "metadata", "driverName", "parameters"]
        }
        // PriorityClass
        ("scheduling.k8s.io", "priorityclasses") => &[
            "apiVersion",
            "kind",
            "metadata",
            "value",
            "preemptionPolicy",
            "globalDefault",
            "description",
        ],
        // RuntimeClass
        ("node.k8s.io", "runtimeclasses") => &[
            "apiVersion",
            "kind",
            "metadata",
            "handler",
            "overhead",
            "scheduling",
        ],
        // IngressClass
        ("networking.k8s.io", "ingressclasses") => &["apiVersion", "kind", "metadata", "spec"],
        // PodDisruptionBudget
        ("policy", "poddisruptionbudgets") => &["apiVersion", "kind", "metadata", "spec", "status"],
        // ControllerRevision
        ("apps", "controllerrevisions") => &["apiVersion", "kind", "metadata", "data", "revision"],
        // Lease
        ("coordination.k8s.io", "leases") => &["apiVersion", "kind", "metadata", "spec"],
        // EndpointSlice — top-level fields are not spec/status but addressType/endpoints/ports.
        // Without this entry, fieldValidation=Strict rejects valid EndpointSlice bodies with
        // 422 "unknown field" for addressType, endpoints, and ports.
        ("discovery.k8s.io", "endpointslices") => &[
            "apiVersion",
            "kind",
            "metadata",
            "addressType",
            "endpoints",
            "ports",
        ],
        // Default: universal set + spec + status covers most resources
        _ => &["apiVersion", "kind", "metadata", "spec", "status"],
    }
}

/// Known fields within `metadata` for any Kubernetes object.
///
/// This matches the full `ObjectMeta` schema from the Kubernetes API.
/// Unknown metadata keys (e.g. a misspelled annotation key at the wrong level)
/// trigger validation errors in Strict mode.
const KNOWN_METADATA_FIELDS: &[&str] = &[
    "name",
    "generateName",
    "namespace",
    "selfLink",
    "uid",
    "resourceVersion",
    "generation",
    "creationTimestamp",
    "deletionTimestamp",
    "deletionGracePeriodSeconds",
    "labels",
    "annotations",
    "ownerReferences",
    "finalizers",
    "managedFields",
    "clusterName",
];

/// Detect unknown top-level keys and unknown metadata keys in `body`.
///
/// Returns a list of dot-separated field paths that are not part of the
/// resource's known schema, e.g. `["unknownField", "metadata.bogusKey"]`.
pub(crate) fn detect_unknown_fields(
    body: &serde_json::Value,
    group: &str,
    plural: &str,
) -> Vec<String> {
    let mut unknown = Vec::new();
    let known_top = known_top_level_fields(group, plural);

    if let Some(obj) = body.as_object() {
        for key in obj.keys() {
            if !known_top.contains(&key.as_str()) {
                unknown.push(key.clone());
            }
        }

        // Check metadata fields.
        if let Some(meta) = obj.get("metadata").and_then(|m| m.as_object()) {
            for key in meta.keys() {
                if !KNOWN_METADATA_FIELDS.contains(&key.as_str()) {
                    unknown.push(format!("metadata.{key}"));
                }
            }
        }
    }

    unknown
}

/// Apply `?fieldValidation=` semantics.
///
/// - `Strict`  → returns `Err(422)` when unknown fields are detected.
/// - `Warn`    → returns `Ok(Some(warning_header_value))` when unknown fields are detected.
/// - `Ignore`  → returns `Ok(None)` unconditionally (existing strip-and-store behaviour).
/// - absent    → same as `Ignore`.
pub(crate) fn apply_field_validation(
    body: &serde_json::Value,
    mode: Option<&str>,
    group: &str,
    plural: &str,
) -> Result<Option<HeaderValue>, crate::status::StatusError> {
    let mode = mode.unwrap_or("Ignore");
    if mode == "Ignore" {
        return Ok(None);
    }

    let unknown = detect_unknown_fields(body, group, plural);
    if unknown.is_empty() {
        return Ok(None);
    }

    match mode {
        "Strict" => {
            let fields = unknown.join(", ");
            Err(Status::unprocessable_entity(format!(
                "strict decoding error: unknown field \"{fields}\""
            )))
        }
        "Warn" => {
            let fields = unknown.join(", ");
            let msg = format!("299 - \"unknown field: {fields}\"");
            let hv = HeaderValue::from_str(&msg).unwrap_or_else(|_| {
                HeaderValue::from_static("299 - \"unknown field(s) detected\"")
            });
            Ok(Some(hv))
        }
        // Any other value: treat as Ignore.
        _ => Ok(None),
    }
}

/// Strip `managedFields` from an SSA apply body before merging.
///
/// Kubernetes clients (including Argo CD) include a `managedFields` key in the
/// apply body to indicate their previous ownership. We don't track field
/// ownership, so we discard it before the merge to avoid persisting stale data.
pub(crate) fn strip_managed_fields(patch: &mut serde_json::Value) {
    if let Some(map) = patch.as_object_mut() {
        if let Some(meta) = map.get_mut("metadata") {
            if let Some(meta_map) = meta.as_object_mut() {
                meta_map.remove("managedFields");
            }
        }
    }
}

/// Inject a synthetic `managedFields` entry into a response object.
///
/// Argo CD's client library reads `managedFields` from apply responses to
/// determine field ownership. Without it, Argo CD treats every resource as
/// OutOfSync and loops forever. We echo back a single entry for the applying
/// manager; we do not implement full SSA field-level tracking.
pub(crate) fn inject_managed_fields(
    obj: &mut serde_json::Value,
    manager: &str,
    api_version: &str,
    now: &str,
) {
    if let Some(map) = obj.as_object_mut() {
        if let Some(meta) = map.get_mut("metadata") {
            if let Some(meta_map) = meta.as_object_mut() {
                meta_map.insert(
                    "managedFields".to_string(),
                    serde_json::json!([{
                        "manager": manager,
                        "operation": "Apply",
                        "apiVersion": api_version,
                        "time": now
                    }]),
                );
            }
        }
    }
}

/// Patch Content-Type variants understood by all patch endpoints.
#[derive(Debug)]
pub(crate) enum PatchType {
    Merge,
    StrategicMerge,
    Json,
}

pub(crate) fn detect_patch_type(
    headers: &HeaderMap,
) -> Result<PatchType, crate::status::StatusError> {
    let ct = content_type(headers);
    if ct.contains("application/strategic-merge-patch+json") {
        return Ok(PatchType::StrategicMerge);
    }
    if ct.contains("application/merge-patch+json") {
        return Ok(PatchType::Merge);
    }
    if ct.contains("application/json-patch+json") {
        return Ok(PatchType::Json);
    }
    // Treat server-side apply as strategic-merge-patch: we don't implement full SSA
    // semantics (field ownership, managed fields), but the apply body is structurally
    // identical to a strategic-merge-patch body.  This is sufficient for kubelet's
    // Lease and CSINode use cases; without this kubelet gets 415 and logs
    // "invalid JSON: expected value at line 1 column 1".
    if ct.contains("application/apply-patch+yaml") {
        return Ok(PatchType::StrategicMerge);
    }
    Err(Status::unsupported_media_type(format!(
        "unsupported media type '{ct}'; use application/merge-patch+json, application/strategic-merge-patch+json, or application/json-patch+json"
    )))
}

/// Apply a JSON Patch (RFC 6902) to `obj`.
/// Supports `add`, `remove`, and `replace` operations.
/// Returns Err(422) for unsupported operations or invalid paths.
pub(crate) fn apply_json_patch(
    obj: &mut serde_json::Value,
    patch: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let ops = patch.as_array().ok_or_else(|| {
        Status::unprocessable_entity("JSON patch must be an array of operations".into())
    })?;

    for op in ops {
        let op_str = op["op"].as_str().ok_or_else(|| {
            Status::unprocessable_entity("each JSON patch operation must have an 'op' field".into())
        })?;
        let path = op["path"].as_str().ok_or_else(|| {
            Status::unprocessable_entity(
                "each JSON patch operation must have a 'path' field".into(),
            )
        })?;

        match op_str {
            "add" => {
                let value = op
                    .get("value")
                    .ok_or_else(|| {
                        Status::unprocessable_entity(
                            "'add' operation requires a 'value' field".into(),
                        )
                    })?
                    .clone();
                // RFC 6902 §4.1: 'add' creates intermediate objects when missing.
                json_patch_add(obj, path, value)?;
            }
            "replace" => {
                let value = op
                    .get("value")
                    .ok_or_else(|| {
                        Status::unprocessable_entity(
                            "'replace' operation requires a 'value' field".into(),
                        )
                    })?
                    .clone();
                // 'replace' is strict: 422 if path does not exist.
                json_patch_set(obj, path, value)?;
            }
            "remove" => {
                json_patch_remove(obj, path)?;
            }
            other => {
                return Err(Status::unprocessable_entity(format!(
                    "unsupported JSON patch operation '{other}'; supported: add, remove, replace"
                )));
            }
        }
    }
    Ok(())
}

/// Parse a JSON Pointer (RFC 6901) into path segments.
pub(crate) fn json_pointer_segments(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return vec![];
    }
    // Leading '/' is required for non-empty pointers; skip it.
    let stripped = pointer.strip_prefix('/').unwrap_or(pointer);
    stripped
        .split('/')
        .map(|seg| seg.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// Navigate to the parent of the target, returning a mutable ref to the parent and the final key.
pub(crate) fn json_patch_navigate_mut<'a>(
    obj: &'a mut serde_json::Value,
    segments: &[String],
) -> Result<(&'a mut serde_json::Value, String), crate::status::StatusError> {
    if segments.is_empty() {
        return Err(Status::unprocessable_entity(
            "cannot operate on root document".into(),
        ));
    }
    let (parents, last) = segments.split_at(segments.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = json_navigate_one(cur, seg)?;
    }
    Ok((cur, last[0].clone()))
}

pub(crate) fn json_navigate_one<'a>(
    node: &'a mut serde_json::Value,
    seg: &str,
) -> Result<&'a mut serde_json::Value, crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => map
            .get_mut(seg)
            .ok_or_else(|| Status::unprocessable_entity(format!("path segment '{seg}' not found"))),
        serde_json::Value::Array(arr) => {
            let idx: usize = seg.parse().map_err(|_| {
                Status::unprocessable_entity(format!(
                    "path segment '{seg}' is not a valid array index"
                ))
            })?;
            arr.get_mut(idx).ok_or_else(|| {
                Status::unprocessable_entity(format!("array index {idx} out of bounds"))
            })
        }
        _ => Err(Status::unprocessable_entity(format!(
            "cannot traverse into non-object/array at segment '{seg}'"
        ))),
    }
}

/// Navigate to a child, creating an empty object if the key is absent.
/// Used by `json_patch_add` to satisfy RFC 6902 §4.1 intermediate-creation semantics.
pub(crate) fn json_navigate_one_or_create<'a>(
    node: &'a mut serde_json::Value,
    seg: &str,
) -> Result<&'a mut serde_json::Value, crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => {
            map.entry(seg)
                .or_insert_with(|| serde_json::Value::Object(Default::default()));
            Ok(map.get_mut(seg).unwrap())
        }
        _ => Err(Status::unprocessable_entity(format!(
            "cannot create intermediate key '{seg}' in non-object"
        ))),
    }
}

/// Apply RFC 6902 'add': navigate parents creating missing objects, then insert.
pub(crate) fn json_patch_add(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parents, last) = segs.split_at(segs.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = json_navigate_one_or_create(cur, seg)?;
    }
    let key = &last[0];
    match cur {
        serde_json::Value::Object(map) => {
            map.insert(key.clone(), value);
        }
        serde_json::Value::Array(arr) => {
            if key == "-" {
                arr.push(value);
            } else {
                let idx: usize = key.parse().map_err(|_| {
                    Status::unprocessable_entity(format!("invalid array index '{key}'"))
                })?;
                if idx <= arr.len() {
                    arr.insert(idx, value);
                } else {
                    return Err(Status::unprocessable_entity(format!(
                        "array index {idx} out of bounds (len {})",
                        arr.len()
                    )));
                }
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot add value to non-object/array".into(),
            ))
        }
    }
    Ok(())
}

pub(crate) fn json_patch_set(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parent, key) = json_patch_navigate_mut(obj, &segs)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.insert(key, value);
        }
        serde_json::Value::Array(arr) => {
            if key == "-" {
                arr.push(value);
            } else {
                let idx: usize = key.parse().map_err(|_| {
                    Status::unprocessable_entity(format!("invalid array index '{key}'"))
                })?;
                if idx <= arr.len() {
                    arr.insert(idx, value);
                } else {
                    return Err(Status::unprocessable_entity(format!(
                        "array index {idx} out of bounds (len {})",
                        arr.len()
                    )));
                }
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot set value on non-object/array".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn json_patch_remove(
    obj: &mut serde_json::Value,
    pointer: &str,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    let (parent, key) = json_patch_navigate_mut(obj, &segs)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.remove(&key).ok_or_else(|| {
                Status::unprocessable_entity(format!("path '{pointer}' not found"))
            })?;
        }
        serde_json::Value::Array(arr) => {
            let idx: usize = key.parse().map_err(|_| {
                Status::unprocessable_entity(format!("invalid array index '{key}'"))
            })?;
            if idx < arr.len() {
                arr.remove(idx);
            } else {
                return Err(Status::unprocessable_entity(format!(
                    "array index {idx} out of bounds"
                )));
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot remove from non-object/array".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// strip_managed_fields removes the managedFields key from metadata.
    /// This matters because Argo CD sends managedFields in apply bodies to signal
    /// previous ownership — we must not persist it or it corrupts the stored object.
    #[test]
    fn strip_managed_fields_removes_managed_fields_from_metadata() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "test",
                "managedFields": [{"manager": "argocd", "operation": "Apply"}]
            }
        });

        strip_managed_fields(&mut obj);

        assert!(
            obj["metadata"]["managedFields"].is_null(),
            "managedFields must be removed from metadata after strip"
        );
        // Other metadata fields must survive the strip.
        assert_eq!(obj["metadata"]["name"], "test");
    }

    /// strip_managed_fields is a no-op when managedFields is absent.
    #[test]
    fn strip_managed_fields_is_noop_when_absent() {
        let mut obj = serde_json::json!({
            "metadata": { "name": "clean" }
        });
        strip_managed_fields(&mut obj);
        assert_eq!(obj["metadata"]["name"], "clean");
    }

    /// inject_managed_fields inserts a synthetic SSA entry with the expected shape.
    /// Argo CD reads manager, operation, apiVersion, and time from this entry.
    #[test]
    fn inject_managed_fields_inserts_synthetic_ssa_entry() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "metadata": { "name": "my-deploy" }
        });

        inject_managed_fields(&mut obj, "argocd", "apps/v1", "2026-05-23T00:00:00Z");

        let mf = &obj["metadata"]["managedFields"];
        assert!(mf.is_array(), "managedFields must be an array");
        assert_eq!(mf[0]["manager"], "argocd");
        assert_eq!(mf[0]["operation"], "Apply");
        assert_eq!(mf[0]["apiVersion"], "apps/v1");
        assert_eq!(mf[0]["time"], "2026-05-23T00:00:00Z");
    }

    // ---------------------------------------------------------------------------
    // EndpointSlice field validation — regression for mayor-9b6g
    // ---------------------------------------------------------------------------

    /// EndpointSlice top-level fields (addressType, endpoints, ports) must not be
    /// reported as unknown by detect_unknown_fields.
    ///
    /// EndpointSlice uses a non-standard schema: its payload fields are at the top
    /// level instead of under spec/status.  Before this fix, fieldValidation=Strict
    /// rejected valid EndpointSlice bodies with 422 "unknown field" for all three
    /// resource-specific fields, blocking EndpointSlice create/update conformance
    /// tests.
    #[test]
    fn endpointslice_top_level_fields_are_not_unknown() {
        let body = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": { "name": "my-slice", "namespace": "default" },
            "addressType": "IPv4",
            "endpoints": [
                {
                    "addresses": ["10.0.0.1"],
                    "conditions": { "ready": true }
                }
            ],
            "ports": [
                { "name": "http", "port": 80, "protocol": "TCP" },
                { "name": "https", "port": 443, "protocol": "TCP" }
            ]
        });

        let unknown = detect_unknown_fields(&body, "discovery.k8s.io", "endpointslices");

        assert!(
            unknown.is_empty(),
            "EndpointSlice fields addressType/endpoints/ports must not be flagged as unknown — \
             before the fix, fieldValidation=Strict returned 422 rejecting valid EndpointSlice \
             creates, blocking conformance tests. Got unknown: {:?}",
            unknown
        );
    }

    /// A ConfigMap with the spec/status fields that don't belong to it must be
    /// flagged as unknown by detect_unknown_fields in Strict mode.  This ensures
    /// the detection logic still works for resources that use the default known set.
    #[test]
    fn unknown_top_level_field_is_detected_for_default_resource() {
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "test" },
            "data": { "key": "val" },
            "bogusField": "should be detected"
        });

        let unknown = detect_unknown_fields(&body, "", "configmaps");

        assert!(
            unknown.contains(&"bogusField".to_string()),
            "bogusField must be detected as unknown for ConfigMap — \
             the regression test protects against detect_unknown_fields being silently bypassed"
        );
    }

    /// apply_field_validation with Strict mode must return Ok when an EndpointSlice
    /// body has only known fields (addressType, endpoints, ports).
    ///
    /// Before the fix, this returned Err(422) because addressType/endpoints/ports
    /// were flagged as unknown, preventing EndpointSlice creation via kubectl.
    #[test]
    fn apply_field_validation_strict_accepts_valid_endpointslice() {
        let body = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": { "name": "my-slice", "namespace": "default" },
            "addressType": "IPv4",
            "endpoints": [{"addresses": ["10.0.0.1"]}],
            "ports": [{"name": "http", "port": 80, "protocol": "TCP"}]
        });

        let result =
            apply_field_validation(&body, Some("Strict"), "discovery.k8s.io", "endpointslices");

        assert!(
            result.is_ok(),
            "EndpointSlice with addressType/endpoints/ports must pass Strict validation — \
             before the fix, these fields were flagged as unknown and the create returned \
             422 blocking all EndpointSlice conformance tests. Error: {:?}",
            result.err()
        );
    }
}
