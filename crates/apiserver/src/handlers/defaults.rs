/// Apply upstream-compatible field defaults to a stored object.
///
/// Equivalent to what kube-apiserver does via `scheme.Default()` after decode
/// and before admission. Without this, controllers that expect defaulted fields
/// (e.g. kube-controller-manager reading `spec.strategy.type` on a Deployment)
/// crash with errors like "unexpected deployment strategy type: \"\"".
///
/// All writes are idempotent: existing non-null values are never overwritten.
pub fn apply_defaults(group: &str, plural: &str, obj: &mut serde_json::Value) {
    if let ("apps", "deployments") = (group, plural) {
        default_deployment(obj);
    }
    if let ("apps", "replicasets") = (group, plural) {
        default_replicaset(obj);
    }
    if let ("apps", "statefulsets") = (group, plural) {
        default_statefulset(obj);
    }
    if let ("apps", "daemonsets") = (group, plural) {
        default_daemonset(obj);
    }
    if let ("", "services") = (group, plural) {
        default_service(obj);
    }
    if let ("", "events") = (group, plural) {
        normalize_event_timestamps(obj);
    }
}

/// Apply all Service defaults in the correct order.
///
/// 1. Default spec.type to "ClusterIP" when absent — conformance tests check that a
///    Service with no explicit type comes back as ClusterIP.
/// 2. Allocate NodePorts for NodePort/LoadBalancer services — ports without a nodePort
///    get one assigned from the standard 30000-32767 range.
/// 3. Skip ClusterIP-family defaults for ExternalName — ExternalName services must not
///    have ipFamilies/ipFamilyPolicy/clusterIPs set (they have no cluster IP at all).
fn default_service(obj: &mut serde_json::Value) {
    // Ensure spec exists as an object.
    if !obj["spec"].is_object() {
        obj["spec"] = serde_json::json!({});
    }

    // 1. Default spec.type to "ClusterIP".
    if obj["spec"]["type"].is_null() {
        obj["spec"]["type"] = serde_json::Value::String("ClusterIP".to_string());
    }

    let svc_type = obj["spec"]["type"]
        .as_str()
        .unwrap_or("ClusterIP")
        .to_string();

    // 2. Allocate NodePorts for NodePort and LoadBalancer services.
    if svc_type == "NodePort" || svc_type == "LoadBalancer" {
        default_node_ports(obj);
    }

    // 3. ExternalName services must not have ClusterIP-family fields.
    if svc_type == "ExternalName" {
        return;
    }

    default_service_ip_fields(obj);
}

/// Assign NodePorts to ports that don't have one yet.
///
/// Scans spec.ports for any port with protocol TCP/UDP/SCTP that lacks a nodePort.
/// Assigns ports sequentially from 30000, skipping values already in use within this
/// object. The range 30000-32767 matches the Kubernetes default nodePort range.
///
/// Idempotent: ports that already have a nodePort are not modified.
fn default_node_ports(obj: &mut serde_json::Value) {
    let ports = match obj["spec"]["ports"].as_array_mut() {
        Some(p) => p,
        None => return,
    };

    // Collect already-assigned NodePorts so we don't re-use them.
    let mut used: std::collections::HashSet<u16> = ports
        .iter()
        .filter_map(|p| p["nodePort"].as_u64())
        .filter(|&n| (30000..=32767).contains(&n))
        .map(|n| n as u16)
        .collect();

    let mut next_candidate: u16 = 30000;

    for port in ports.iter_mut() {
        // Skip ports that already have a nodePort.
        if !port["nodePort"].is_null() {
            continue;
        }

        // Find the next unused port in the range.
        while used.contains(&next_candidate) || next_candidate > 32767 {
            next_candidate = next_candidate.saturating_add(1);
            if next_candidate > 32767 {
                // Range exhausted — leave remaining ports without a nodePort.
                return;
            }
        }

        port["nodePort"] = serde_json::Value::Number(next_candidate.into());
        used.insert(next_candidate);
        next_candidate += 1;
    }
}

/// Normalize Event timestamp fields to include microsecond precision.
///
/// client-go's MicroTime codec (used for `eventTime`) and some Event field
/// parsers require fractional seconds: `2017-09-20T13:49:16.000000Z`.
/// Without the `.000000` suffix, client-go raises:
///   `parsing time "…Z" as "…000000Z07:00": cannot parse "Z" as ".000000"`.
///
/// This function normalizes `lastTimestamp`, `firstTimestamp`, and `eventTime`
/// in-place by appending `.000000` to any second-precision RFC3339 string.
pub fn normalize_event_timestamps(obj: &mut serde_json::Value) {
    for field in &["lastTimestamp", "firstTimestamp", "eventTime"] {
        if let Some(s) = obj[field].as_str() {
            let normalized = crate::util::normalize_rfc3339_to_micro(s);
            obj[*field] = serde_json::Value::String(normalized);
        }
    }
}

/// Set ipFamilies, ipFamilyPolicy, and clusterIPs on a Service if they are absent.
///
/// KCM's endpoints-controller indexes `svc.Spec.IPFamilies[0]` and panics if the
/// slice is nil.  kube-apiserver populates these in write-time defaulting
/// (`initIPFamilyFields`).  We replicate that minimal subset here so that every
/// Service stored in u7s has the fields KCM requires.
///
/// Rules (matching upstream SingleStack defaults):
/// - ipFamilyPolicy → "SingleStack" (always safe for pre-alpha single-stack clusters)
/// - ipFamilies    → ["IPv6"] if clusterIP contains ':', else ["IPv4"]
/// - clusterIPs    → [clusterIP] if clusterIP is non-empty and not "None"
///
/// Only sets fields that are absent or null; never overwrites existing values.
///
/// Must NOT be called for ExternalName services (they have no ClusterIP family).
pub fn default_service_ip_fields(obj: &mut serde_json::Value) {
    // Ensure spec exists as an object.
    if !obj["spec"].is_object() {
        obj["spec"] = serde_json::json!({});
    }

    let cluster_ip = obj["spec"]["clusterIP"].as_str().unwrap_or("").to_string();

    // ipFamilyPolicy
    if obj["spec"]["ipFamilyPolicy"].is_null() {
        obj["spec"]["ipFamilyPolicy"] = serde_json::Value::String("SingleStack".to_string());
    }

    // ipFamilies
    if obj["spec"]["ipFamilies"].is_null() {
        let family = if cluster_ip.contains(':') {
            "IPv6"
        } else {
            "IPv4"
        };
        obj["spec"]["ipFamilies"] = serde_json::json!([family]);
    }

    // clusterIPs
    if obj["spec"]["clusterIPs"].is_null() && !cluster_ip.is_empty() && cluster_ip != "None" {
        obj["spec"]["clusterIPs"] = serde_json::json!([cluster_ip]);
    }
}

/// Validate a resource after defaults have been applied. Returns an error string
/// suitable for a 400 Bad Request if required fields are missing.
///
/// Must be called after `apply_defaults` so that fields defaultable from other
/// fields (e.g. spec.selector from template labels) have already been filled in.
pub fn validate_resource(group: &str, plural: &str, obj: &serde_json::Value) -> Result<(), String> {
    if let ("apps", "deployments") = (group, plural) {
        validate_deployment(obj)?;
    }
    if let ("apps", "replicasets") = (group, plural) {
        validate_selector(obj, "ReplicaSet")?;
    }
    if let ("apps", "statefulsets") = (group, plural) {
        validate_selector(obj, "StatefulSet")?;
    }
    Ok(())
}

fn validate_deployment(obj: &serde_json::Value) -> Result<(), String> {
    if obj["spec"]["selector"].is_null() {
        return Err(
            "Deployment.spec.selector is required and could not be defaulted \
             (spec.template.metadata.labels is also missing)"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_selector(obj: &serde_json::Value, kind: &str) -> Result<(), String> {
    if obj["spec"]["selector"].is_null() {
        return Err(format!("{kind}.spec.selector is required"));
    }
    Ok(())
}

fn default_replicaset(obj: &mut serde_json::Value) {
    if obj["spec"]["replicas"].is_null() {
        obj["spec"]["replicas"] = serde_json::Value::Number(1.into());
    }
}

fn default_statefulset(obj: &mut serde_json::Value) {
    if obj["spec"]["replicas"].is_null() {
        obj["spec"]["replicas"] = serde_json::Value::Number(1.into());
    }
    if obj["spec"]["podManagementPolicy"].is_null() {
        obj["spec"]["podManagementPolicy"] = serde_json::Value::String("OrderedReady".into());
    }
    if obj["spec"]["updateStrategy"]["type"].is_null() {
        if !obj["spec"]["updateStrategy"].is_object() {
            obj["spec"]["updateStrategy"] = serde_json::json!({});
        }
        obj["spec"]["updateStrategy"]["type"] = serde_json::Value::String("RollingUpdate".into());
    }
    if obj["spec"]["revisionHistoryLimit"].is_null() {
        obj["spec"]["revisionHistoryLimit"] = serde_json::Value::Number(10.into());
    }
}

fn default_daemonset(obj: &mut serde_json::Value) {
    if obj["spec"]["updateStrategy"]["type"].is_null() {
        if !obj["spec"]["updateStrategy"].is_object() {
            obj["spec"]["updateStrategy"] = serde_json::json!({});
        }
        obj["spec"]["updateStrategy"]["type"] = serde_json::Value::String("RollingUpdate".into());
    }
    if obj["spec"]["updateStrategy"]["type"].as_str() == Some("RollingUpdate") {
        if !obj["spec"]["updateStrategy"]["rollingUpdate"].is_object() {
            obj["spec"]["updateStrategy"]["rollingUpdate"] = serde_json::json!({});
        }
        if obj["spec"]["updateStrategy"]["rollingUpdate"]["maxUnavailable"].is_null() {
            obj["spec"]["updateStrategy"]["rollingUpdate"]["maxUnavailable"] =
                serde_json::Value::Number(1.into());
        }
        if obj["spec"]["updateStrategy"]["rollingUpdate"]["maxSurge"].is_null() {
            obj["spec"]["updateStrategy"]["rollingUpdate"]["maxSurge"] =
                serde_json::Value::Number(0.into());
        }
    }
    if obj["spec"]["revisionHistoryLimit"].is_null() {
        obj["spec"]["revisionHistoryLimit"] = serde_json::Value::Number(10.into());
    }
}

fn default_deployment(obj: &mut serde_json::Value) {
    // spec.selector defaults to matchLabels from spec.template.metadata.labels.
    // Upstream kube-apiserver rejects Deployments without spec.selector; u7s stores
    // them as-is, so the KCM deployment-controller hits a nil selector and panics.
    if obj["spec"]["selector"].is_null() {
        let labels = obj["spec"]["template"]["metadata"]["labels"].clone();
        if labels.is_object() {
            obj["spec"]["selector"] = serde_json::json!({ "matchLabels": labels });
        }
    }

    // spec.replicas defaults to 1
    if obj["spec"]["replicas"].is_null() {
        obj["spec"]["replicas"] = serde_json::Value::Number(1.into());
    }

    // spec.revisionHistoryLimit defaults to 10
    if obj["spec"]["revisionHistoryLimit"].is_null() {
        obj["spec"]["revisionHistoryLimit"] = serde_json::Value::Number(10.into());
    }

    // spec.progressDeadlineSeconds defaults to 600
    if obj["spec"]["progressDeadlineSeconds"].is_null() {
        obj["spec"]["progressDeadlineSeconds"] = serde_json::Value::Number(600.into());
    }

    // spec.strategy.type defaults to "RollingUpdate"
    if obj["spec"]["strategy"]["type"].is_null() {
        // Ensure spec.strategy exists as an object before writing into it.
        if !obj["spec"]["strategy"].is_object() {
            obj["spec"]["strategy"] = serde_json::json!({});
        }
        obj["spec"]["strategy"]["type"] = serde_json::Value::String("RollingUpdate".into());
    }

    // spec.strategy.rollingUpdate defaults only when strategy type is RollingUpdate.
    if obj["spec"]["strategy"]["type"].as_str() == Some("RollingUpdate") {
        if !obj["spec"]["strategy"]["rollingUpdate"].is_object() {
            obj["spec"]["strategy"]["rollingUpdate"] = serde_json::json!({});
        }
        if obj["spec"]["strategy"]["rollingUpdate"]["maxSurge"].is_null() {
            obj["spec"]["strategy"]["rollingUpdate"]["maxSurge"] =
                serde_json::Value::String("25%".into());
        }
        if obj["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"].is_null() {
            obj["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] =
                serde_json::Value::String("25%".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deployment with no strategy/replicas must have all 6 defaults applied.
    /// This is the bug that caused kcm to crash: "unexpected deployment strategy type: \"\"".
    /// If apply_defaults is not called, these fields are absent and controllers fail.
    #[test]
    fn deployment_defaults_applied() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {}
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(1.into()),
            "spec.replicas must default to 1"
        );
        assert_eq!(
            obj["spec"]["revisionHistoryLimit"],
            serde_json::Value::Number(10.into()),
            "spec.revisionHistoryLimit must default to 10"
        );
        assert_eq!(
            obj["spec"]["progressDeadlineSeconds"],
            serde_json::Value::Number(600.into()),
            "spec.progressDeadlineSeconds must default to 600"
        );
        assert_eq!(
            obj["spec"]["strategy"]["type"], "RollingUpdate",
            "spec.strategy.type must default to RollingUpdate"
        );
        assert_eq!(
            obj["spec"]["strategy"]["rollingUpdate"]["maxSurge"], "25%",
            "spec.strategy.rollingUpdate.maxSurge must default to 25%"
        );
        assert_eq!(
            obj["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"], "25%",
            "spec.strategy.rollingUpdate.maxUnavailable must default to 25%"
        );
    }

    /// Existing values must not be overwritten — apply_defaults is idempotent.
    /// If this test fails after reverting the idempotency guards, controllers that
    /// set Recreate strategy would silently have it overwritten to RollingUpdate.
    #[test]
    fn deployment_defaults_idempotent() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test" },
            "spec": {
                "replicas": 3,
                "strategy": { "type": "Recreate" }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(3.into()),
            "spec.replicas must not be overwritten when already set"
        );
        assert_eq!(
            obj["spec"]["strategy"]["type"], "Recreate",
            "spec.strategy.type must not be overwritten when already set"
        );
        // Recreate strategy: rollingUpdate sub-object must not be injected
        assert!(
            obj["spec"]["strategy"]["rollingUpdate"].is_null(),
            "rollingUpdate must not be added when strategy is Recreate"
        );
    }

    /// Deployment without spec.selector must have it defaulted from template labels.
    ///
    /// Upstream kube-apiserver rejects Deployments without spec.selector; u7s doesn't
    /// validate this. The KCM deployment-controller calls CloneSelectorAndAddLabel on
    /// spec.selector and panics with a nil-pointer dereference, killing the entire KCM
    /// process (including the serviceaccount-controller). This causes all new namespaces
    /// to never get a default ServiceAccount, breaking sonobuoy job tests.
    #[test]
    fn deployment_without_selector_gets_default_from_template_labels() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "test", "version": "v1" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "test", "version": "v1" } }),
            "spec.selector must be defaulted from template labels — nil selector panics the KCM deployment-controller"
        );
    }

    /// A Deployment with neither spec.selector nor template labels must be rejected.
    ///
    /// Upstream kube-apiserver returns 422 for this case. Without rejection, u7s stores
    /// the object, KCM reads it, CloneSelectorAndAddLabel(nil) panics, and the entire
    /// KCM process dies — taking the serviceaccount-controller with it.
    #[test]
    fn deployment_without_selector_or_labels_rejected() {
        let obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "bad", "namespace": "test" },
            "spec": {
                "template": { "spec": { "containers": [] } }
            }
        });

        let result = validate_resource("apps", "deployments", &obj);
        assert!(
            result.is_err(),
            "Deployment with no selector and no template labels must be rejected — \
             nil selector panics KCM deployment-controller"
        );
        assert!(
            result.unwrap_err().contains("spec.selector"),
            "error message must mention spec.selector"
        );
    }

    /// A Deployment with an explicit spec.selector must pass validation.
    #[test]
    fn deployment_with_valid_selector_passes_validation() {
        let obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "ok", "namespace": "test" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": { "spec": { "containers": [] } }
            }
        });

        assert!(
            validate_resource("apps", "deployments", &obj).is_ok(),
            "Deployment with explicit spec.selector must pass validation"
        );
    }

    /// apply_defaults + validate_resource must succeed for Deployments with template labels.
    ///
    /// Verifies the full write-path pipeline: selector is defaulted from template labels,
    /// then validation confirms the selector is present.
    #[test]
    fn deployment_selector_defaulted_then_passes_validation() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "test" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);
        assert!(
            validate_resource("apps", "deployments", &obj).is_ok(),
            "Deployment with template labels must pass validation after selector is defaulted"
        );
    }

    /// Existing spec.selector must not be overwritten.
    ///
    /// A Deployment may use a selector that's a strict subset of the template labels.
    /// Overwriting it would break the controller's ability to identify owned ReplicaSets.
    #[test]
    fn deployment_existing_selector_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test" },
            "spec": {
                "selector": { "matchLabels": { "app": "my-app" } },
                "template": {
                    "metadata": { "labels": { "app": "my-app", "extra": "label" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "my-app" } }),
            "existing spec.selector must not be overwritten — changing it breaks ReplicaSet ownership"
        );
    }

    /// Unknown resources must be passed through unchanged.
    /// If apply_defaults modifies unknown resources, it would corrupt arbitrary objects.
    #[test]
    fn unknown_resource_noop() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "test" },
            "data": { "key": "value" }
        });
        let original = obj.clone();

        apply_defaults("", "configmaps", &mut obj);

        assert_eq!(obj, original, "unknown resources must not be modified");
    }

    // ---------------------------------------------------------------------------
    // Service IP field defaulting
    // ---------------------------------------------------------------------------

    /// Service with clusterIP set must get ipFamilies=["IPv4"], ipFamilyPolicy="SingleStack",
    /// and clusterIPs=[clusterIP].
    ///
    /// Without these defaults, KCM's endpoints-controller panics at IPFamilies[0]
    /// (index into nil slice).  This test fails if default_service_ip_fields is removed
    /// or if it stops populating the required fields.
    #[test]
    fn service_ipv4_cluster_ip_gets_defaults() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "my-svc", "namespace": "default" },
            "spec": { "clusterIP": "10.96.0.1" }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ipFamilyPolicy"], "SingleStack",
            "ipFamilyPolicy must default to SingleStack"
        );
        assert_eq!(
            obj["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "ipFamilies must default to [IPv4] for an IPv4 clusterIP"
        );
        assert_eq!(
            obj["spec"]["clusterIPs"],
            serde_json::json!(["10.96.0.1"]),
            "clusterIPs must default to [clusterIP]"
        );
    }

    /// Headless Service (clusterIP="None") must get ipFamilies=["IPv4"] but no clusterIPs.
    ///
    /// "None" is a sentinel value meaning headless; it must not appear in clusterIPs.
    #[test]
    fn service_headless_gets_ip_family_but_no_cluster_ips() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "headless", "namespace": "default" },
            "spec": { "clusterIP": "None" }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ipFamilyPolicy"], "SingleStack",
            "ipFamilyPolicy must default to SingleStack for headless service"
        );
        assert_eq!(
            obj["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "ipFamilies must default to [IPv4] for headless service"
        );
        assert!(
            obj["spec"]["clusterIPs"].is_null(),
            "clusterIPs must not be set for headless service (clusterIP=None)"
        );
    }

    /// IPv6 Service must get ipFamilies=["IPv6"].
    #[test]
    fn service_ipv6_cluster_ip_gets_ipv6_family() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "ipv6-svc", "namespace": "default" },
            "spec": { "clusterIP": "fd00::1" }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ipFamilies"],
            serde_json::json!(["IPv6"]),
            "ipFamilies must be [IPv6] for an IPv6 clusterIP (contains ':')"
        );
        assert_eq!(
            obj["spec"]["clusterIPs"],
            serde_json::json!(["fd00::1"]),
            "clusterIPs must be set to [clusterIP] for IPv6"
        );
    }

    /// Service with no clusterIP must still get ipFamilies=["IPv4"] and ipFamilyPolicy.
    #[test]
    fn service_no_cluster_ip_gets_ipv4_defaults() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "no-ip-svc", "namespace": "default" },
            "spec": { "selector": { "app": "foo" } }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(obj["spec"]["ipFamilyPolicy"], "SingleStack");
        assert_eq!(obj["spec"]["ipFamilies"], serde_json::json!(["IPv4"]));
        assert!(
            obj["spec"]["clusterIPs"].is_null(),
            "clusterIPs must not be set when clusterIP is absent"
        );
    }

    /// Existing Service fields must not be overwritten (idempotency).
    ///
    /// If idempotency breaks, a DualStack Service would have its ipFamilies
    /// overwritten to SingleStack on every update.
    #[test]
    fn service_existing_fields_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "dual-svc", "namespace": "default" },
            "spec": {
                "clusterIP": "10.96.0.1",
                "ipFamilyPolicy": "PreferDualStack",
                "ipFamilies": ["IPv4", "IPv6"],
                "clusterIPs": ["10.96.0.1", "fd00::1"]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ipFamilyPolicy"], "PreferDualStack",
            "existing ipFamilyPolicy must not be overwritten"
        );
        assert_eq!(
            obj["spec"]["ipFamilies"],
            serde_json::json!(["IPv4", "IPv6"]),
            "existing ipFamilies must not be overwritten"
        );
        assert_eq!(
            obj["spec"]["clusterIPs"],
            serde_json::json!(["10.96.0.1", "fd00::1"]),
            "existing clusterIPs must not be overwritten"
        );
    }

    // ---------------------------------------------------------------------------
    // Event timestamp normalization
    // ---------------------------------------------------------------------------

    /// Event timestamps without microseconds must be normalized to include `.000000`.
    ///
    /// client-go's MicroTime codec uses format `2006-01-02T15:04:05.000000Z07:00`
    /// and fails to parse `2017-09-20T13:49:16Z` with:
    ///   `cannot parse "Z" as ".000000"`
    /// If this normalization is removed, conformance Event lifecycle tests will fail.
    #[test]
    fn event_timestamps_normalized_to_microsecond_precision() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "lastTimestamp": "2017-09-20T13:49:16Z",
            "firstTimestamp": "2017-09-20T13:49:10Z",
            "eventTime": "2017-09-20T13:49:16Z"
        });

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj["lastTimestamp"], "2017-09-20T13:49:16.000000Z",
            "lastTimestamp must have .000000 suffix so client-go MicroTime parses it"
        );
        assert_eq!(
            obj["firstTimestamp"], "2017-09-20T13:49:10.000000Z",
            "firstTimestamp must have .000000 suffix so client-go MicroTime parses it"
        );
        assert_eq!(
            obj["eventTime"], "2017-09-20T13:49:16.000000Z",
            "eventTime must have .000000 suffix so client-go MicroTime parses it"
        );
    }

    /// Already-precise timestamps must not be modified (idempotent).
    ///
    /// If already-precise timestamps were overwritten, sub-microsecond precision
    /// from client-go (e.g. `.123456`) would be silently truncated.
    #[test]
    fn event_timestamps_already_precise_are_unchanged() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "lastTimestamp": "2017-09-20T13:49:16.123456Z",
            "firstTimestamp": "2017-09-20T13:49:10.000001Z",
            "eventTime": "2017-09-20T13:49:16.999999Z"
        });

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj["lastTimestamp"], "2017-09-20T13:49:16.123456Z",
            "existing sub-second precision must not be overwritten"
        );
        assert_eq!(
            obj["firstTimestamp"], "2017-09-20T13:49:10.000001Z",
            "existing sub-second precision must not be overwritten"
        );
        assert_eq!(
            obj["eventTime"], "2017-09-20T13:49:16.999999Z",
            "existing sub-second precision must not be overwritten"
        );
    }

    // ---------------------------------------------------------------------------
    // ReplicaSet defaults
    // ---------------------------------------------------------------------------

    /// A ReplicaSet with no spec.replicas must have it defaulted to 1.
    ///
    /// KCM's replicaset-controller dereferences *rs.Spec.Replicas unconditionally.
    /// Nil causes a nil-pointer panic that kills the entire KCM process.
    #[test]
    fn replicaset_replicas_defaults_to_1() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {}
            }
        });

        apply_defaults("apps", "replicasets", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(1.into()),
            "spec.replicas must default to 1 — nil replicas panics KCM replicaset-controller"
        );
    }

    /// Existing spec.replicas on a ReplicaSet must not be overwritten.
    #[test]
    fn replicaset_existing_replicas_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": { "replicas": 3 }
        });

        apply_defaults("apps", "replicasets", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(3.into()),
            "existing spec.replicas must not be overwritten"
        );
    }

    // ---------------------------------------------------------------------------
    // StatefulSet defaults
    // ---------------------------------------------------------------------------

    /// A StatefulSet with no spec fields must have all four defaults applied.
    ///
    /// KCM's statefulset-controller dereferences *ss.Spec.Replicas and indexes
    /// UpdateStrategy fields without nil checks.
    #[test]
    fn statefulset_defaults_applied() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {}
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(1.into()),
            "spec.replicas must default to 1"
        );
        assert_eq!(
            obj["spec"]["podManagementPolicy"], "OrderedReady",
            "spec.podManagementPolicy must default to OrderedReady"
        );
        assert_eq!(
            obj["spec"]["updateStrategy"]["type"], "RollingUpdate",
            "spec.updateStrategy.type must default to RollingUpdate"
        );
        assert_eq!(
            obj["spec"]["revisionHistoryLimit"],
            serde_json::Value::Number(10.into()),
            "spec.revisionHistoryLimit must default to 10"
        );
    }

    /// Existing StatefulSet fields must not be overwritten.
    #[test]
    fn statefulset_existing_values_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "replicas": 5,
                "podManagementPolicy": "Parallel",
                "updateStrategy": { "type": "OnDelete" },
                "revisionHistoryLimit": 3
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);

        assert_eq!(obj["spec"]["replicas"], serde_json::Value::Number(5.into()));
        assert_eq!(obj["spec"]["podManagementPolicy"], "Parallel");
        assert_eq!(obj["spec"]["updateStrategy"]["type"], "OnDelete");
        assert_eq!(obj["spec"]["revisionHistoryLimit"], serde_json::Value::Number(3.into()));
    }

    // ---------------------------------------------------------------------------
    // DaemonSet defaults
    // ---------------------------------------------------------------------------

    /// A DaemonSet with no updateStrategy must have type, maxUnavailable, and maxSurge defaulted.
    #[test]
    fn daemonset_defaults_applied() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {}
        });

        apply_defaults("apps", "daemonsets", &mut obj);

        assert_eq!(
            obj["spec"]["updateStrategy"]["type"], "RollingUpdate",
            "spec.updateStrategy.type must default to RollingUpdate"
        );
        assert_eq!(
            obj["spec"]["updateStrategy"]["rollingUpdate"]["maxUnavailable"],
            serde_json::Value::Number(1.into()),
            "rollingUpdate.maxUnavailable must default to 1"
        );
        assert_eq!(
            obj["spec"]["updateStrategy"]["rollingUpdate"]["maxSurge"],
            serde_json::Value::Number(0.into()),
            "rollingUpdate.maxSurge must default to 0"
        );
        assert_eq!(
            obj["spec"]["revisionHistoryLimit"],
            serde_json::Value::Number(10.into()),
            "spec.revisionHistoryLimit must default to 10"
        );
    }

    /// Existing DaemonSet updateStrategy must not be overwritten.
    #[test]
    fn daemonset_existing_values_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "updateStrategy": { "type": "OnDelete" },
                "revisionHistoryLimit": 5
            }
        });

        apply_defaults("apps", "daemonsets", &mut obj);

        assert_eq!(obj["spec"]["updateStrategy"]["type"], "OnDelete");
        assert!(
            obj["spec"]["updateStrategy"]["rollingUpdate"].is_null(),
            "rollingUpdate must not be injected for OnDelete strategy"
        );
        assert_eq!(obj["spec"]["revisionHistoryLimit"], serde_json::Value::Number(5.into()));
    }

    /// Events without timestamp fields must not be modified.
    ///
    /// Prevents panics when optional fields are absent.
    #[test]
    fn event_without_timestamps_is_unchanged() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "message": "something happened"
        });
        let original = obj.clone();

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj, original,
            "Event without timestamp fields must not be modified"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: spec.type defaulting (mayor-51ji)
    // ---------------------------------------------------------------------------

    /// A Service with no spec.type must have spec.type defaulted to "ClusterIP".
    ///
    /// Sonobuoy conformance tests create Services without a type and assert the
    /// response carries type=ClusterIP. Without this default, the field comes back
    /// empty and the tests fail with "unexpected Spec.Type () for service, expected ClusterIP".
    #[test]
    fn service_without_type_defaults_to_cluster_ip() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "my-svc", "namespace": "default" },
            "spec": { "selector": { "app": "foo" }, "ports": [{ "port": 80 }] }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["type"], "ClusterIP",
            "spec.type must default to ClusterIP — sonobuoy checks the field and fails if empty"
        );
    }

    /// An existing spec.type must not be overwritten by defaulting.
    ///
    /// If idempotency breaks here, a NodePort service would be silently downgraded
    /// to ClusterIP on every read, breaking external traffic routing.
    #[test]
    fn service_existing_type_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "np-svc", "namespace": "default" },
            "spec": {
                "type": "NodePort",
                "ports": [{ "port": 80, "nodePort": 31000 }]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["type"], "NodePort",
            "existing spec.type must not be overwritten — changing NodePort to ClusterIP breaks external access"
        );
        // NodePort must not be re-allocated when already set.
        assert_eq!(
            obj["spec"]["ports"][0]["nodePort"], 31000,
            "existing nodePort must not be overwritten"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: NodePort allocation (mayor-51ji)
    // ---------------------------------------------------------------------------

    /// A NodePort Service with no nodePort on its ports must have one assigned.
    ///
    /// Sonobuoy tests create NodePort services and assert Spec.Ports[0].NodePort != 0.
    /// Without allocation, NodePort comes back as 0 and the tests fail.
    #[test]
    fn nodeport_service_gets_node_port_assigned() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "np-svc", "namespace": "default" },
            "spec": {
                "type": "NodePort",
                "ports": [{ "port": 80, "protocol": "TCP" }]
            }
        });

        apply_defaults("", "services", &mut obj);

        let node_port = obj["spec"]["ports"][0]["nodePort"]
            .as_u64()
            .expect("nodePort must be a number after defaulting");
        assert!(
            (30000..=32767).contains(&node_port),
            "nodePort must be in [30000, 32767], got {node_port} — sonobuoy checks for non-zero nodePort"
        );
    }

    /// Two ports on a NodePort service must each get a distinct nodePort.
    ///
    /// If both ports share the same nodePort, the OS will reject one bind and
    /// kube-proxy cannot set up the iptables rule for the second port.
    #[test]
    fn nodeport_service_multiple_ports_get_distinct_node_ports() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "np-multi", "namespace": "default" },
            "spec": {
                "type": "NodePort",
                "ports": [
                    { "port": 80, "protocol": "TCP" },
                    { "port": 443, "protocol": "TCP" }
                ]
            }
        });

        apply_defaults("", "services", &mut obj);

        let np0 = obj["spec"]["ports"][0]["nodePort"]
            .as_u64()
            .expect("port 0 must have nodePort");
        let np1 = obj["spec"]["ports"][1]["nodePort"]
            .as_u64()
            .expect("port 1 must have nodePort");
        assert_ne!(np0, np1, "each port must receive a distinct nodePort — duplicates break kube-proxy iptables rules");
        assert!((30000..=32767).contains(&np0));
        assert!((30000..=32767).contains(&np1));
    }

    /// LoadBalancer services also need NodePorts (cloud LBs route via nodePort internally).
    #[test]
    fn loadbalancer_service_gets_node_port_assigned() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "lb-svc", "namespace": "default" },
            "spec": {
                "type": "LoadBalancer",
                "ports": [{ "port": 80 }]
            }
        });

        apply_defaults("", "services", &mut obj);

        let node_port = obj["spec"]["ports"][0]["nodePort"]
            .as_u64()
            .expect("LoadBalancer port must have nodePort after defaulting");
        assert!(
            (30000..=32767).contains(&node_port),
            "LoadBalancer nodePort must be in [30000, 32767], got {node_port}"
        );
    }

    /// ClusterIP service must NOT get a nodePort injected.
    ///
    /// ClusterIP services have no node-level port mapping. Injecting a nodePort
    /// would confuse clients and waste ports from the NodePort range.
    #[test]
    fn clusterip_service_does_not_get_node_port() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "ci-svc", "namespace": "default" },
            "spec": {
                "type": "ClusterIP",
                "ports": [{ "port": 80 }]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert!(
            obj["spec"]["ports"][0]["nodePort"].is_null(),
            "ClusterIP service must not have a nodePort — injecting one wastes ports and confuses clients"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: ExternalName ClusterIP (mayor-bdum)
    // ---------------------------------------------------------------------------

    /// An ExternalName service must NOT get ipFamilies, ipFamilyPolicy, or clusterIPs.
    ///
    /// ExternalName services resolve to an external DNS name; they have no ClusterIP.
    /// Conformance tests fail with "unexpected Spec.ClusterIP (10.96.x.x) for ExternalName service"
    /// if we apply ClusterIP-family defaults to ExternalName.
    #[test]
    fn external_name_service_gets_no_ip_family_defaults() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "ext-svc", "namespace": "default" },
            "spec": {
                "type": "ExternalName",
                "externalName": "example.com"
            }
        });

        apply_defaults("", "services", &mut obj);

        assert!(
            obj["spec"]["ipFamilyPolicy"].is_null(),
            "ExternalName service must not have ipFamilyPolicy — it has no cluster IP"
        );
        assert!(
            obj["spec"]["ipFamilies"].is_null(),
            "ExternalName service must not have ipFamilies — it has no cluster IP"
        );
        assert!(
            obj["spec"]["clusterIPs"].is_null(),
            "ExternalName service must not have clusterIPs — it has no cluster IP"
        );
        assert!(
            obj["spec"]["clusterIP"].is_null(),
            "ExternalName service must not have clusterIP set by defaults"
        );
    }

    /// ExternalName service must get spec.type defaulted correctly when type is explicit.
    ///
    /// spec.type="ExternalName" is preserved (not overwritten to ClusterIP).
    #[test]
    fn external_name_type_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "ext2", "namespace": "default" },
            "spec": {
                "type": "ExternalName",
                "externalName": "db.example.com"
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["type"], "ExternalName",
            "spec.type=ExternalName must not be overwritten to ClusterIP"
        );
    }
}
