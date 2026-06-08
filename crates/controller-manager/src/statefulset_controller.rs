/// StatefulSet controller — pure reconcile helpers.
///
/// Pure functions only; async I/O stays in main.rs.
use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Typed views
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodMeta {
    pub name: Option<String>,
    #[serde(rename = "deletionTimestamp")]
    pub deletion_timestamp: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodObject {
    pub metadata: PodMeta,
}

// ---------------------------------------------------------------------------
// mayor-z981: fast status.replicas=0 when scaling to zero
// ---------------------------------------------------------------------------

/// Returns true when `status.replicas` should be immediately set to 0.
///
/// Condition: spec.replicas is 0 and every pod in `pods` has a deletionTimestamp
/// set (i.e. all pods are terminating). Without this early update, AfterEach
/// polls for status.replicas==0 until the pods are fully removed from etcd,
/// which can take many minutes on a slow cluster.
pub fn should_reflect_zero_replicas(spec_replicas: i64, pods: &[PodObject]) -> bool {
    if spec_replicas != 0 {
        return false;
    }
    if pods.is_empty() {
        return true;
    }
    pods.iter().all(|p| p.metadata.deletion_timestamp.is_some())
}

/// Parse the pod list from a JSON list response into `PodObject` instances.
pub fn parse_pod_list(list: &Value) -> Vec<PodObject> {
    list["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect()
}

/// URL path to update StatefulSet status.
pub fn statefulset_status_path(namespace: &str, name: &str) -> String {
    format!("/apis/apps/v1/namespaces/{namespace}/statefulsets/{name}/status")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pod_running(name: &str) -> PodObject {
        PodObject {
            metadata: PodMeta {
                name: Some(name.to_owned()),
                deletion_timestamp: None,
            },
        }
    }

    fn pod_terminating(name: &str) -> PodObject {
        PodObject {
            metadata: PodMeta {
                name: Some(name.to_owned()),
                deletion_timestamp: Some("2024-01-01T00:00:00Z".to_owned()),
            },
        }
    }

    // --- mayor-z981 ---

    /// AfterEach polls status.replicas==0 after scale-to-zero. If we only set
    /// status.replicas=0 after pods are fully removed from etcd, AfterEach
    /// can stall for many minutes while pods are still terminating.
    #[test]
    fn zero_replicas_reflected_immediately_when_all_pods_terminating() {
        let pods = vec![pod_terminating("sts-0"), pod_terminating("sts-1")];
        assert!(
            should_reflect_zero_replicas(0, &pods),
            "status.replicas must be 0 immediately when spec.replicas==0 and all pods are \
             terminating — without this AfterEach stalls for up to 10 minutes per test"
        );
    }

    /// status.replicas must NOT be 0 while any pod is still running (not terminating),
    /// even when spec.replicas is 0. Prematurely reporting 0 would confuse clients
    /// about when the scale-down is complete.
    #[test]
    fn zero_replicas_not_reflected_while_any_pod_running() {
        let pods = vec![pod_terminating("sts-0"), pod_running("sts-1")];
        assert!(
            !should_reflect_zero_replicas(0, &pods),
            "must NOT set status.replicas=0 while any pod is still running — \
             would report scale-down complete before it is"
        );
    }

    /// When spec.replicas is non-zero, the condition must never trigger regardless
    /// of pod state.
    #[test]
    fn nonzero_spec_replicas_never_triggers_fast_zero() {
        let pods = vec![pod_terminating("sts-0")];
        assert!(
            !should_reflect_zero_replicas(1, &pods),
            "fast-zero logic must only apply when spec.replicas==0"
        );
    }

    /// When spec.replicas==0 and no pods exist, status.replicas should be 0 immediately.
    #[test]
    fn zero_replicas_reflected_when_no_pods_exist() {
        assert!(
            should_reflect_zero_replicas(0, &[]),
            "status.replicas must be 0 when spec.replicas==0 and the pod list is empty"
        );
    }

    /// parse_pod_list must extract deletionTimestamp correctly so the fast-zero
    /// condition works on real API server responses.
    #[test]
    fn parse_pod_list_extracts_deletion_timestamp() {
        let list = serde_json::json!({
            "items": [
                {"metadata": {"name": "sts-0", "deletionTimestamp": "2024-01-01T00:00:00Z"}},
                {"metadata": {"name": "sts-1"}}
            ]
        });
        let pods = parse_pod_list(&list);
        assert_eq!(pods.len(), 2);
        assert!(
            pods[0].metadata.deletion_timestamp.is_some(),
            "sts-0 must be seen as terminating"
        );
        assert!(
            pods[1].metadata.deletion_timestamp.is_none(),
            "sts-1 must be seen as running"
        );
    }

    /// URL path must be exact — wrong paths return 404 from the API server.
    #[test]
    fn statefulset_status_path_is_correct() {
        assert_eq!(
            statefulset_status_path("kube-system", "my-sts"),
            "/apis/apps/v1/namespaces/kube-system/statefulsets/my-sts/status"
        );
    }
}
