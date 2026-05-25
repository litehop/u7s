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
    if let ("", "services") = (group, plural) {
        default_service_ip_fields(obj);
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

fn default_deployment(obj: &mut serde_json::Value) {
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
}
