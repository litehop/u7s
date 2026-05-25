/// LimitRange admission plugin.
///
/// On Pod create/update:
///  1. Fetch all LimitRange objects in the pod's namespace from the store.
///  2. For each container (init + regular), inject default requests/limits if
///     absent (from the `defaultRequest` / `default` fields of a Container-type
///     LimitRange item).
///  3. Validate that every container's requests and limits fall within the
///     min/max bounds declared by any LimitRange.
///
/// Kubernetes spec reference:
///   https://kubernetes.io/docs/concepts/policy/limit-range/
use serde_json::Value;
use u7s_store::{ListOptions, Store};

use crate::{keys::list_prefix, state::AppState, status::Status, status::StatusError};

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// A parsed quantity as a raw string (e.g. "100m", "256Mi", "1").
/// We compare quantities as f64 millivalue after parsing.
#[derive(Debug, Clone)]
pub(crate) struct LimitItem {
    /// Minimum allowed value per resource name.
    min: std::collections::BTreeMap<String, f64>,
    /// Maximum allowed value per resource name.
    max: std::collections::BTreeMap<String, f64>,
    /// Default request (injected when the container omits requests).
    default_request: std::collections::BTreeMap<String, f64>,
    /// Default limit (injected when the container omits limits).
    default_limit: std::collections::BTreeMap<String, f64>,
}

// ---------------------------------------------------------------------------
// Quantity parsing
// ---------------------------------------------------------------------------

/// Parse a Kubernetes quantity string into a raw f64 millivalue.
///
/// Supported suffixes: m (milli), k/Ki, M/Mi, G/Gi, T/Ti, P/Pi, E/Ei.
/// Plain numbers are treated as whole units (×1000 millivalue).
/// Returns None on parse failure.
pub fn parse_quantity(s: &str) -> Option<f64> {
    if s.is_empty() {
        return None;
    }

    // Milli-suffix (e.g. "100m" → 0.1 cores → 100 millivalue)
    if let Some(num) = s.strip_suffix('m') {
        return num.parse::<f64>().ok();
    }

    // Binary suffixes (memory)
    let binary_suffixes: &[(&str, f64)] = &[
        ("Ei", 1024_f64.powi(6) * 1000.0),
        ("Pi", 1024_f64.powi(5) * 1000.0),
        ("Ti", 1024_f64.powi(4) * 1000.0),
        ("Gi", 1024_f64.powi(3) * 1000.0),
        ("Mi", 1024_f64.powi(2) * 1000.0),
        ("Ki", 1024_f64 * 1000.0),
    ];
    for (suffix, factor) in binary_suffixes {
        if let Some(num) = s.strip_suffix(suffix) {
            return num.parse::<f64>().ok().map(|n| n * factor);
        }
    }

    // Decimal suffixes
    let decimal_suffixes: &[(&str, f64)] = &[
        ("E", 1e18 * 1000.0),
        ("P", 1e15 * 1000.0),
        ("T", 1e12 * 1000.0),
        ("G", 1e9 * 1000.0),
        ("M", 1e6 * 1000.0),
        ("k", 1e3 * 1000.0),
    ];
    for (suffix, factor) in decimal_suffixes {
        if let Some(num) = s.strip_suffix(suffix) {
            return num.parse::<f64>().ok().map(|n| n * factor);
        }
    }

    // Plain number → multiply by 1000 to get millivalue
    s.parse::<f64>().ok().map(|n| n * 1000.0)
}

// ---------------------------------------------------------------------------
// Store helpers
// ---------------------------------------------------------------------------

/// Fetch all LimitRange objects for the given namespace.
async fn fetch_limit_ranges<S: Store>(state: &AppState<S>, namespace: &str) -> Vec<Value> {
    let prefix = list_prefix("limitranges", namespace);
    match state.store.list(&prefix, ListOptions::default()).await {
        Ok(resp) => resp
            .items
            .into_iter()
            .filter_map(|item| serde_json::from_slice(&item.value).ok())
            .collect(),
        Err(e) => {
            tracing::warn!("limit_range: failed to list LimitRanges in {namespace}: {e}");
            vec![]
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing LimitRange items
// ---------------------------------------------------------------------------

fn parse_quantity_map(obj: &Value) -> std::collections::BTreeMap<String, f64> {
    let mut out = std::collections::BTreeMap::new();
    if let Some(map) = obj.as_object() {
        for (k, v) in map {
            if let Some(s) = v.as_str() {
                if let Some(val) = parse_quantity(s) {
                    out.insert(k.clone(), val);
                }
            }
        }
    }
    out
}

/// Extract Container-scoped LimitItems from a single LimitRange object.
fn parse_container_limit_items(lr: &Value) -> Vec<LimitItem> {
    let items = match lr["spec"]["limits"].as_array() {
        Some(a) => a,
        None => return vec![],
    };
    let mut out = Vec::new();
    for item in items {
        let item_type = item["type"].as_str().unwrap_or("");
        // We only handle Container limits here (not Pod, PersistentVolumeClaim, etc.)
        if item_type != "Container" {
            continue;
        }
        out.push(LimitItem {
            min: parse_quantity_map(&item["min"]),
            max: parse_quantity_map(&item["max"]),
            default_request: parse_quantity_map(&item["defaultRequest"]),
            default_limit: parse_quantity_map(&item["default"]),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Default injection (mutating)
// ---------------------------------------------------------------------------

/// Inject default requests/limits into a single container's resources field.
/// Modifies `container` in-place.
pub fn inject_defaults(container: &mut Value, items: &[LimitItem]) {
    for item in items {
        // Inject default limit
        for (resource, &val) in &item.default_limit {
            if container["resources"]["limits"][resource].is_null() {
                // Convert millivalue back to a canonical quantity string.
                let qty = millivalue_to_quantity(val, resource);
                container["resources"]["limits"][resource] = Value::String(qty);
            }
        }
        // Inject default request
        for (resource, &val) in &item.default_request {
            if container["resources"]["requests"][resource].is_null() {
                let qty = millivalue_to_quantity(val, resource);
                container["resources"]["requests"][resource] = Value::String(qty);
            }
        }
    }
}

/// Convert a millivalue back to a simple quantity string.
/// For CPU (ends in "cpu"): if divisible by 1000, use whole cores; else use "Nm" form.
/// For memory: use bytes (millivalue / 1000).
fn millivalue_to_quantity(milli: f64, resource: &str) -> String {
    if resource.contains("cpu") {
        // CPU: millivalue is millicores directly
        if milli >= 1000.0 && milli % 1000.0 == 0.0 {
            format!("{}", (milli / 1000.0) as u64)
        } else {
            format!("{}m", milli as u64)
        }
    } else {
        // Memory: millivalue = bytes * 1000; divide back to bytes
        let bytes = (milli / 1000.0) as u64;
        if bytes >= 1024 * 1024 * 1024 && bytes.is_multiple_of(1024 * 1024 * 1024) {
            format!("{}Gi", bytes / (1024 * 1024 * 1024))
        } else if bytes >= 1024 * 1024 && bytes.is_multiple_of(1024 * 1024) {
            format!("{}Mi", bytes / (1024 * 1024))
        } else if bytes >= 1024 && bytes.is_multiple_of(1024) {
            format!("{}Ki", bytes / 1024)
        } else {
            format!("{bytes}")
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a container's resources against LimitItems. Returns Err if any
/// resource falls outside the declared min/max bounds.
pub fn validate_container_resources(
    container_name: &str,
    container: &Value,
    items: &[LimitItem],
) -> Result<(), StatusError> {
    for item in items {
        // Validate limits
        for (resource, &max) in &item.max {
            if let Some(val_str) = container["resources"]["limits"][resource].as_str() {
                if let Some(val) = parse_quantity(val_str) {
                    if val > max + 1e-6 {
                        return Err(Status::forbidden(format!(
                            "container \"{container_name}\" limit for \"{resource}\" ({val_str}) exceeds LimitRange max"
                        )));
                    }
                }
            }
        }
        for (resource, &min) in &item.min {
            if let Some(val_str) = container["resources"]["limits"][resource].as_str() {
                if let Some(val) = parse_quantity(val_str) {
                    if val < min - 1e-6 {
                        return Err(Status::forbidden(format!(
                            "container \"{container_name}\" limit for \"{resource}\" ({val_str}) is below LimitRange min"
                        )));
                    }
                }
            }
        }
        // Validate requests
        for (resource, &max) in &item.max {
            if let Some(val_str) = container["resources"]["requests"][resource].as_str() {
                if let Some(val) = parse_quantity(val_str) {
                    if val > max + 1e-6 {
                        return Err(Status::forbidden(format!(
                            "container \"{container_name}\" request for \"{resource}\" ({val_str}) exceeds LimitRange max"
                        )));
                    }
                }
            }
        }
        for (resource, &min) in &item.min {
            if let Some(val_str) = container["resources"]["requests"][resource].as_str() {
                if let Some(val) = parse_quantity(val_str) {
                    if val < min - 1e-6 {
                        return Err(Status::forbidden(format!(
                            "container \"{container_name}\" request for \"{resource}\" ({val_str}) is below LimitRange min"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply LimitRange enforcement to a pod body.
///
/// 1. Fetches all LimitRange objects in `namespace`.
/// 2. Injects default requests/limits into each container.
/// 3. Validates min/max bounds.
///
/// Returns the (possibly mutated) pod body, or a 403 StatusError if validation fails.
/// This is a no-op (returns body unchanged) if the resource is not a Pod or if there
/// are no LimitRanges in the namespace.
pub async fn apply_limit_ranges<S: Store>(
    state: &AppState<S>,
    mut body: Value,
    namespace: &str,
    resource: &str,
) -> Result<Value, StatusError> {
    if resource != "pods" {
        return Ok(body);
    }

    let lr_objects = fetch_limit_ranges(state, namespace).await;
    if lr_objects.is_empty() {
        return Ok(body);
    }

    // Parse all container-scoped items from all LimitRanges in this namespace.
    let items: Vec<LimitItem> = lr_objects
        .iter()
        .flat_map(parse_container_limit_items)
        .collect();

    if items.is_empty() {
        return Ok(body);
    }

    // Process init containers and regular containers.
    let container_keys = ["initContainers", "containers"];
    for key in &container_keys {
        if let Some(containers) = body["spec"][key].as_array_mut() {
            for container in containers {
                let name = container["name"]
                    .as_str()
                    .unwrap_or("<unknown>")
                    .to_string();
                inject_defaults(container, &items);
                validate_container_resources(&name, container, &items)?;
            }
        }
    }

    Ok(body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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

    // -- parse_quantity --

    /// Plain integer is treated as whole units (×1000 millivalue).
    /// This matters for CPU: "1" = 1 core = 1000m.
    #[test]
    fn parse_quantity_plain_integer() {
        assert_eq!(parse_quantity("1"), Some(1000.0));
        assert_eq!(parse_quantity("2"), Some(2000.0));
    }

    /// Milli suffix ('m') returns the value directly as millivalue.
    #[test]
    fn parse_quantity_milli_suffix() {
        assert_eq!(parse_quantity("100m"), Some(100.0));
        assert_eq!(parse_quantity("500m"), Some(500.0));
    }

    /// Mi suffix parses as mebibytes × 1000 millivalue.
    #[test]
    fn parse_quantity_mi_suffix() {
        let milli = parse_quantity("128Mi").unwrap();
        // 128 * 1024^2 * 1000
        assert!((milli - 128.0 * 1024.0 * 1024.0 * 1000.0).abs() < 1.0);
    }

    /// Unknown/empty input returns None.
    #[test]
    fn parse_quantity_empty_returns_none() {
        assert_eq!(parse_quantity(""), None);
    }

    // -- inject_defaults --

    /// Default CPU limit is injected when the container has no limits set.
    /// Without injection, a container without limits can use unbounded CPU,
    /// defeating the purpose of LimitRange.
    #[test]
    fn inject_defaults_injects_cpu_limit_when_absent() {
        let mut container = json!({
            "name": "app",
            "image": "nginx",
            "resources": {}
        });
        let items = vec![LimitItem {
            min: Default::default(),
            max: Default::default(),
            default_request: Default::default(),
            default_limit: [("cpu".to_string(), 500.0)].into_iter().collect(),
        }];
        inject_defaults(&mut container, &items);
        assert_eq!(
            container["resources"]["limits"]["cpu"],
            json!("500m"),
            "default CPU limit must be injected into container with no limits"
        );
    }

    /// Default memory request is injected when absent.
    #[test]
    fn inject_defaults_injects_memory_request_when_absent() {
        let mut container = json!({
            "name": "app",
            "resources": {}
        });
        // 128Mi in millivalue = 128 * 1024 * 1024 * 1000
        let mi128 = 128.0 * 1024.0 * 1024.0 * 1000.0;
        let items = vec![LimitItem {
            min: Default::default(),
            max: Default::default(),
            default_request: [("memory".to_string(), mi128)].into_iter().collect(),
            default_limit: Default::default(),
        }];
        inject_defaults(&mut container, &items);
        assert_eq!(
            container["resources"]["requests"]["memory"],
            json!("128Mi"),
            "default memory request must be injected"
        );
    }

    /// Existing limits are NOT overwritten by defaults.
    /// A container that explicitly sets its limits must not be overridden.
    #[test]
    fn inject_defaults_does_not_overwrite_existing_limit() {
        let mut container = json!({
            "name": "app",
            "resources": {
                "limits": { "cpu": "200m" }
            }
        });
        let items = vec![LimitItem {
            min: Default::default(),
            max: Default::default(),
            default_request: Default::default(),
            default_limit: [("cpu".to_string(), 500.0)].into_iter().collect(),
        }];
        inject_defaults(&mut container, &items);
        assert_eq!(
            container["resources"]["limits"]["cpu"],
            json!("200m"),
            "explicitly set limit must not be overwritten by LimitRange default"
        );
    }

    // -- validate_container_resources --

    /// Container with CPU limit above max must be rejected.
    /// Without this check, a pod could claim more CPU than the namespace allows.
    #[test]
    fn validate_rejects_cpu_limit_above_max() {
        let container = json!({
            "name": "app",
            "resources": { "limits": { "cpu": "2" } }  // 2000m
        });
        let items = vec![LimitItem {
            min: Default::default(),
            max: [("cpu".to_string(), 1000.0)].into_iter().collect(), // max 1 core
            default_request: Default::default(),
            default_limit: Default::default(),
        }];
        let result = validate_container_resources("app", &container, &items);
        assert!(result.is_err(), "cpu limit above max must be rejected");
    }

    /// Container with CPU limit within max must be accepted.
    #[test]
    fn validate_accepts_cpu_limit_within_max() {
        let container = json!({
            "name": "app",
            "resources": { "limits": { "cpu": "500m" } }
        });
        let items = vec![LimitItem {
            min: Default::default(),
            max: [("cpu".to_string(), 1000.0)].into_iter().collect(),
            default_request: Default::default(),
            default_limit: Default::default(),
        }];
        let result = validate_container_resources("app", &container, &items);
        assert!(result.is_ok(), "cpu limit within max must be accepted");
    }

    /// Container with CPU request below min must be rejected.
    /// LimitRange min enforces a floor so containers don't starve with near-zero requests.
    #[test]
    fn validate_rejects_cpu_request_below_min() {
        let container = json!({
            "name": "app",
            "resources": { "requests": { "cpu": "10m" } }
        });
        let items = vec![LimitItem {
            min: [("cpu".to_string(), 100.0)].into_iter().collect(), // min 100m
            max: Default::default(),
            default_request: Default::default(),
            default_limit: Default::default(),
        }];
        let result = validate_container_resources("app", &container, &items);
        assert!(result.is_err(), "cpu request below min must be rejected");
    }

    // -- namespace isolation --

    /// LimitRange in namespace A must not affect pods in namespace B.
    /// Namespace isolation is fundamental — cross-namespace pollution would be a security bug.
    #[tokio::test]
    async fn limit_range_in_different_namespace_is_ignored() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a LimitRange in namespace "team-a" with a very low CPU max.
        let lr = json!({
            "apiVersion": "v1",
            "kind": "LimitRange",
            "metadata": { "name": "strict", "namespace": "team-a" },
            "spec": { "limits": [{ "type": "Container", "max": { "cpu": "100m" } }] }
        });
        store
            .put(
                "/registry/limitranges/team-a/strict",
                bytes::Bytes::from(serde_json::to_vec(&lr).unwrap()),
                None,
            )
            .await
            .unwrap();

        // A pod in "team-b" with 2 CPU must NOT be rejected (different namespace).
        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "mypod", "namespace": "team-b" },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": { "limits": { "cpu": "2" } }
                }]
            }
        });

        let result = apply_limit_ranges(&state, pod.clone(), "team-b", "pods").await;
        assert!(
            result.is_ok(),
            "LimitRange in team-a must not reject pod in team-b"
        );
    }

    /// apply_limit_ranges injects defaults AND enforces max in the same namespace.
    #[tokio::test]
    async fn apply_limit_ranges_injects_and_validates() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // LimitRange: default CPU limit 500m, max 1 core.
        let lr = json!({
            "apiVersion": "v1",
            "kind": "LimitRange",
            "metadata": { "name": "default-limits", "namespace": "default" },
            "spec": { "limits": [{
                "type": "Container",
                "default": { "cpu": "500m" },
                "max": { "cpu": "1" }
            }] }
        });
        store
            .put(
                "/registry/limitranges/default/default-limits",
                bytes::Bytes::from(serde_json::to_vec(&lr).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Pod with no CPU limit → default should be injected.
        let pod_no_limit = json!({
            "spec": { "containers": [{ "name": "app", "resources": {} }] }
        });
        let result = apply_limit_ranges(&state, pod_no_limit, "default", "pods")
            .await
            .unwrap_or_else(|_| panic!("injection must succeed"));
        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["cpu"],
            json!("500m"),
            "default CPU limit must be injected"
        );

        // Pod with CPU limit above max → must be rejected.
        let pod_too_much = json!({
            "spec": { "containers": [{ "name": "app", "resources": {
                "limits": { "cpu": "2" }
            }}] }
        });
        let result2 = apply_limit_ranges(&state, pod_too_much, "default", "pods").await;
        assert!(result2.is_err(), "CPU limit above max must be rejected");
    }

    /// Non-pod resources are passed through unchanged (Services, ConfigMaps, etc. are not LimitRange-gated).
    #[tokio::test]
    async fn apply_limit_ranges_noop_for_non_pods() {
        let state = make_state();
        let svc = json!({ "kind": "Service", "metadata": { "name": "svc" } });
        let result = apply_limit_ranges(&state, svc.clone(), "default", "services").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or_else(|_| panic!("noop must succeed")), svc);
    }
}
