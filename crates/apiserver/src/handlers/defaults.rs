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
}
