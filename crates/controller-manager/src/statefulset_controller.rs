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
// Fast status.replicas=0 when scaling to zero
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
// ControllerRevision creation on template update
// ---------------------------------------------------------------------------

/// Minimal view of a ControllerRevision object.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct ControllerRevisionMeta {
    pub name: Option<String>,
    pub labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ControllerRevision {
    pub metadata: ControllerRevisionMeta,
    pub revision: Option<i64>,
}

/// Returns true when a new ControllerRevision must be created for a StatefulSet.
///
/// A new revision is needed when no existing ControllerRevision carries the
/// given `template_hash` in its `controller-revision-hash` label.  Without
/// this, rollback tests panic because they expect >=2 ControllerRevisions
/// after a template update but find only 1.
pub fn needs_new_controller_revision(
    template_hash: &str,
    revisions: &[ControllerRevision],
) -> bool {
    !revisions.iter().any(|r| {
        r.metadata
            .labels
            .as_ref()
            .and_then(|l| l.get("controller-revision-hash"))
            .map(|h| h == template_hash)
            .unwrap_or(false)
    })
}

/// Parse a ControllerRevision list response into typed structs.
pub fn parse_controller_revision_list(list: &Value) -> Vec<ControllerRevision> {
    list["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect()
}

/// Build a ControllerRevision object for a StatefulSet template update.
///
/// `name` is typically `<statefulset>-<template_hash>`.
/// `revision` is the next monotone revision number (max existing + 1).
pub fn build_controller_revision(
    name: &str,
    namespace: &str,
    statefulset_name: &str,
    template_hash: &str,
    revision: i64,
    template: &Value,
) -> Value {
    serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "ControllerRevision",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": statefulset_name,
                "controller-revision-hash": template_hash
            },
            "ownerReferences": []
        },
        "revision": revision,
        "data": template
    })
}

/// URL path to list ControllerRevisions in a namespace.
pub fn controller_revisions_list_path(namespace: &str) -> String {
    format!("/apis/apps/v1/namespaces/{namespace}/controllerrevisions")
}

/// URL path to create a ControllerRevision in a namespace.
pub fn controller_revisions_post_path(namespace: &str) -> String {
    format!("/apis/apps/v1/namespaces/{namespace}/controllerrevisions")
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

    // --- Scale-to-zero status.replicas tests ---

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

    // --- ControllerRevision creation on template update tests ---

    fn revision_with_hash(hash: &str) -> ControllerRevision {
        let mut labels = std::collections::HashMap::new();
        labels.insert("controller-revision-hash".to_owned(), hash.to_owned());
        ControllerRevision {
            metadata: ControllerRevisionMeta {
                name: Some(format!("sts-{hash}")),
                labels: Some(labels),
            },
            revision: Some(1),
        }
    }

    /// Rolling update/rollback tests panic when only 1 ControllerRevision exists after a
    /// template update. A new ControllerRevision must be created whenever the template hash
    /// is not already represented in the existing revisions.
    #[test]
    fn new_revision_needed_when_hash_not_present() {
        let revisions = vec![revision_with_hash("abc123")];
        assert!(
            needs_new_controller_revision("def456", &revisions),
            "a new ControllerRevision must be created when no existing revision carries \
             the updated template hash — without this rollback tests panic"
        );
    }

    /// If a revision with the same hash already exists, no duplicate should be created.
    /// Creating duplicates would corrupt the revision history used by rollback.
    #[test]
    fn no_new_revision_when_hash_already_present() {
        let revisions = vec![revision_with_hash("abc123"), revision_with_hash("def456")];
        assert!(
            !needs_new_controller_revision("def456", &revisions),
            "must NOT create a duplicate ControllerRevision when the template hash is already \
             tracked — duplicates corrupt rollback history"
        );
    }

    /// With no existing revisions the first ControllerRevision must always be created.
    #[test]
    fn new_revision_needed_when_no_revisions_exist() {
        assert!(
            needs_new_controller_revision("abc123", &[]),
            "must create the initial ControllerRevision when none exists"
        );
    }

    /// build_controller_revision must produce a valid ControllerRevision object
    /// that the API server will accept. The revision number and hash label are
    /// both required for rollback to work correctly.
    #[test]
    fn build_controller_revision_has_required_fields() {
        let template = serde_json::json!({"spec": {"containers": []}});
        let cr =
            build_controller_revision("my-sts-abc123", "default", "my-sts", "abc123", 2, &template);
        assert_eq!(cr["kind"], "ControllerRevision");
        assert_eq!(cr["apiVersion"], "apps/v1");
        assert_eq!(cr["metadata"]["name"], "my-sts-abc123");
        assert_eq!(cr["metadata"]["namespace"], "default");
        assert_eq!(
            cr["metadata"]["labels"]["controller-revision-hash"], "abc123",
            "hash label must match so needs_new_controller_revision can find it"
        );
        assert_eq!(
            cr["revision"], 2,
            "revision number is required for ordering rollbacks"
        );
    }

    /// ControllerRevision URL paths must be exact — wrong paths return 404.
    #[test]
    fn controller_revision_url_paths_are_correct() {
        assert_eq!(
            controller_revisions_list_path("default"),
            "/apis/apps/v1/namespaces/default/controllerrevisions"
        );
        assert_eq!(
            controller_revisions_post_path("kube-system"),
            "/apis/apps/v1/namespaces/kube-system/controllerrevisions"
        );
    }
}
