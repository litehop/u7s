/// Namespace lifecycle controller.
///
/// Two responsibilities:
/// 1. ADDED namespace without the "kubernetes" finalizer → PATCH to add it.
///    This ensures all user-created namespaces go through the termination lifecycle.
/// 2. MODIFIED namespace with phase=Terminating → drain core namespaced resources,
///    then PATCH to remove the "kubernetes" finalizer, triggering apiserver hard-delete.
///
/// Pure helper functions are in lib.rs; I/O stays in this module.
use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Typed view of watch events for namespaces
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct NsMeta {
    pub name: Option<String>,
    #[serde(rename = "deletionTimestamp")]
    pub deletion_timestamp: Option<String>,
}

/// Namespace finalizers live in spec.finalizers, not metadata.finalizers.
#[derive(Debug, Default, Deserialize)]
pub struct NsSpec {
    pub finalizers: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct NsStatus {
    pub phase: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct NsObject {
    pub metadata: NsMeta,
    pub spec: Option<NsSpec>,
    pub status: Option<NsStatus>,
}

#[derive(Debug, Deserialize)]
struct NsWatchEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub object: NsObject,
}

// ---------------------------------------------------------------------------
// Pure logic — testable without I/O
// ---------------------------------------------------------------------------

/// Determine what action to take for a namespace watch event.
#[derive(Debug, PartialEq)]
pub enum NsAction {
    /// Namespace was added without the "kubernetes" finalizer — add it.
    AddFinalizer(String),
    /// Namespace is Terminating and has the "kubernetes" finalizer — drain and remove finalizer.
    Drain(String),
    /// No action needed.
    None,
}

/// Core resource types to drain from a terminating namespace.
/// Order matters: delete pods before services, secrets before service accounts.
pub const CORE_DRAIN_RESOURCES: &[&str] = &[
    "pods",
    "services",
    "configmaps",
    "secrets",
    "serviceaccounts",
    "endpoints",
    "persistentvolumeclaims",
    "replicationcontrollers",
];

/// Non-core (API-group) resource types to drain from a terminating namespace.
/// Each tuple is (group, version, plural).
pub const NON_CORE_DRAIN_RESOURCES: &[(&str, &str, &str)] = &[
    ("apps", "v1", "deployments"),
    ("apps", "v1", "replicasets"),
    ("apps", "v1", "statefulsets"),
    ("apps", "v1", "daemonsets"),
    ("rbac.authorization.k8s.io", "v1", "rolebindings"),
    ("rbac.authorization.k8s.io", "v1", "roles"),
    ("coordination.k8s.io", "v1", "leases"),
];

/// Parse a namespace watch event into an action.
pub fn parse_ns_event(event: &Value) -> NsAction {
    let watch_event: NsWatchEvent = match NsWatchEvent::deserialize(event) {
        Ok(e) => e,
        Err(_) => return NsAction::None,
    };

    let name = match watch_event.object.metadata.name.as_deref() {
        Some(n) if !n.is_empty() => n.to_owned(),
        _ => return NsAction::None,
    };

    match watch_event.event_type.as_str() {
        "ADDED" => {
            let has_k8s_finalizer = watch_event
                .object
                .spec
                .as_ref()
                .and_then(|s| s.finalizers.as_deref())
                .unwrap_or(&[])
                .iter()
                .any(|f| f == "kubernetes");
            let deletion_ts_set = watch_event.object.metadata.deletion_timestamp.is_some();
            let is_terminating = watch_event
                .object
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                == Some("Terminating");

            if deletion_ts_set && is_terminating && has_k8s_finalizer {
                // Namespace is already Terminating (e.g. watch reconnected while drain was
                // in progress and failed). Re-emit Drain so the controller retries.
                NsAction::Drain(name)
            } else if has_k8s_finalizer {
                // Active namespace that already has the finalizer — nothing to do.
                NsAction::None
            } else {
                // Add the "kubernetes" finalizer so every namespace goes through drain.
                NsAction::AddFinalizer(name)
            }
        }
        "MODIFIED" => {
            // Drain only when: deletionTimestamp set, phase=Terminating, "kubernetes" finalizer present.
            let is_terminating = watch_event
                .object
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                == Some("Terminating");
            let deletion_ts_set = watch_event.object.metadata.deletion_timestamp.is_some();
            let has_k8s_finalizer = watch_event
                .object
                .spec
                .as_ref()
                .and_then(|s| s.finalizers.as_deref())
                .unwrap_or(&[])
                .iter()
                .any(|f| f == "kubernetes");

            if deletion_ts_set && is_terminating && has_k8s_finalizer {
                NsAction::Drain(name)
            } else {
                NsAction::None
            }
        }
        _ => NsAction::None,
    }
}

// ---------------------------------------------------------------------------
// URL helpers for namespace controller
// ---------------------------------------------------------------------------

/// Path to add the "kubernetes" finalizer via merge-patch.
/// PATCH /api/v1/namespaces/<name>
pub fn namespace_patch_path(name: &str) -> String {
    format!("/api/v1/namespaces/{name}")
}

/// Path to list all objects of a core resource type in a namespace.
pub fn namespaced_resource_list_path(namespace: &str, resource: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/{resource}")
}

/// Path to delete a specific namespaced resource.
pub fn namespaced_resource_delete_path(namespace: &str, resource: &str, name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/{resource}/{name}")
}

/// Path to list all objects of a non-core (API-group) resource type in a namespace.
pub fn non_core_namespaced_resource_list_path(
    namespace: &str,
    group: &str,
    version: &str,
    plural: &str,
) -> String {
    format!("/apis/{group}/{version}/namespaces/{namespace}/{plural}")
}

/// Path to delete a specific non-core (API-group) namespaced resource.
pub fn non_core_namespaced_resource_delete_path(
    namespace: &str,
    group: &str,
    version: &str,
    plural: &str,
    name: &str,
) -> String {
    format!("/apis/{group}/{version}/namespaces/{namespace}/{plural}/{name}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn added_event(name: &str, finalizers: &[&str]) -> Value {
        serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": name },
                "spec": { "finalizers": finalizers },
                "status": { "phase": "Active" }
            }
        })
    }

    fn modified_terminating(name: &str, finalizers: &[&str]) -> Value {
        serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "name": name,
                    "deletionTimestamp": "2024-01-02T00:00:00Z"
                },
                "spec": { "finalizers": finalizers },
                "status": { "phase": "Terminating" }
            }
        })
    }

    // An ADDED namespace without the "kubernetes" finalizer must trigger AddFinalizer.
    // Without this, user-created namespaces would be hard-deleted without draining resources.
    #[test]
    fn added_without_finalizer_triggers_add() {
        let ev = added_event("my-ns", &[]);
        assert_eq!(parse_ns_event(&ev), NsAction::AddFinalizer("my-ns".into()));
    }

    // An ADDED namespace that already has the "kubernetes" finalizer and is Active must not
    // trigger any action. Adding it twice would produce a duplicate in the finalizers list.
    #[test]
    fn added_active_with_finalizer_is_noop() {
        let ev = added_event("my-ns", &["kubernetes"]);
        assert_eq!(parse_ns_event(&ev), NsAction::None);
    }

    // An ADDED namespace with deletionTimestamp set, phase=Terminating, and the "kubernetes"
    // finalizer must trigger Drain — not None.
    //
    // This covers the watch-reconnect case: when the watch stream dies while drain_namespace
    // is in progress (or after it errors out), the server re-delivers the Terminating namespace
    // as an ADDED event on reconnect. Without this fix the controller sees ADDED, notes that
    // the "kubernetes" finalizer is already present, and returns None — the namespace is never
    // drained and hangs in Terminating forever.
    #[test]
    fn added_terminating_with_finalizer_triggers_drain() {
        let ev = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "name": "stuck-ns",
                    "deletionTimestamp": "2024-01-02T00:00:00Z"
                },
                "spec": { "finalizers": ["kubernetes"] },
                "status": { "phase": "Terminating" }
            }
        });
        assert_eq!(
            parse_ns_event(&ev),
            NsAction::Drain("stuck-ns".into()),
            "ADDED event for a Terminating namespace must trigger Drain so the controller \
             retries after a watch reconnect; returning None here leaves the namespace stuck"
        );
    }

    // An ADDED namespace with deletionTimestamp but phase=Active must not trigger Drain —
    // the apiserver has not yet transitioned it to Terminating.
    #[test]
    fn added_deletion_ts_but_active_phase_is_noop() {
        let ev = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "name": "ns",
                    "deletionTimestamp": "2024-01-02T00:00:00Z"
                },
                "spec": { "finalizers": ["kubernetes"] },
                "status": { "phase": "Active" }
            }
        });
        assert_eq!(parse_ns_event(&ev), NsAction::None);
    }

    // An ADDED namespace with phase=Terminating but NO "kubernetes" finalizer must trigger
    // AddFinalizer — not Drain. If it has no finalizer, the drain lifecycle hasn't started.
    // (In practice this shouldn't happen since create_namespace stamps the finalizer, but
    // the controller must be defensive.)
    #[test]
    fn added_terminating_without_finalizer_triggers_add_finalizer() {
        let ev = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "name": "ns",
                    "deletionTimestamp": "2024-01-02T00:00:00Z"
                },
                "spec": { "finalizers": [] },
                "status": { "phase": "Terminating" }
            }
        });
        assert_eq!(parse_ns_event(&ev), NsAction::AddFinalizer("ns".into()));
    }

    // A MODIFIED namespace in Terminating phase with the "kubernetes" finalizer must trigger Drain.
    // This is the condition that means: all controllers have run, now drain resources.
    #[test]
    fn modified_terminating_triggers_drain() {
        let ev = modified_terminating("dying-ns", &["kubernetes"]);
        assert_eq!(parse_ns_event(&ev), NsAction::Drain("dying-ns".into()));
    }

    // A MODIFIED namespace with deletionTimestamp but phase≠Terminating must not trigger drain.
    // The apiserver sets Terminating when it soft-deletes; if the phase is wrong, wait.
    #[test]
    fn modified_deletion_ts_but_active_phase_is_noop() {
        let ev = serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "name": "ns",
                    "finalizers": ["kubernetes"],
                    "deletionTimestamp": "2024-01-02T00:00:00Z"
                },
                "status": { "phase": "Active" }
            }
        });
        assert_eq!(parse_ns_event(&ev), NsAction::None);
    }

    // A MODIFIED namespace in Terminating phase without the "kubernetes" finalizer is a noop.
    // Some other controller already removed it; we must not re-trigger a drain.
    #[test]
    fn modified_terminating_without_k8s_finalizer_is_noop() {
        let ev = serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "name": "ns",
                    "finalizers": [],
                    "deletionTimestamp": "2024-01-02T00:00:00Z"
                },
                "status": { "phase": "Terminating" }
            }
        });
        assert_eq!(parse_ns_event(&ev), NsAction::None);
    }

    // DELETED events must be ignored — they are informational only.
    #[test]
    fn deleted_event_is_noop() {
        let ev = serde_json::json!({
            "type": "DELETED",
            "object": {
                "metadata": { "name": "ns" },
                "status": { "phase": "Active" }
            }
        });
        assert_eq!(parse_ns_event(&ev), NsAction::None);
    }

    // An event with no name must be a noop — we cannot patch an unnamed namespace.
    #[test]
    fn event_without_name_is_noop() {
        let ev = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {},
                "status": { "phase": "Active" }
            }
        });
        assert_eq!(parse_ns_event(&ev), NsAction::None);
    }

    // URL helpers must produce the exact paths the Kubernetes API expects.
    #[test]
    fn url_helpers_correct() {
        assert_eq!(
            namespace_patch_path("default"),
            "/api/v1/namespaces/default"
        );
        assert_eq!(
            namespaced_resource_list_path("default", "pods"),
            "/api/v1/namespaces/default/pods"
        );
        assert_eq!(
            namespaced_resource_delete_path("default", "pods", "my-pod"),
            "/api/v1/namespaces/default/pods/my-pod"
        );
    }

    // CORE_DRAIN_RESOURCES must include all the resource types a namespace controller
    // is responsible for cleaning up. Missing a type means orphaned resources after deletion.
    #[test]
    fn drain_resources_includes_core_types() {
        assert!(CORE_DRAIN_RESOURCES.contains(&"pods"));
        assert!(CORE_DRAIN_RESOURCES.contains(&"services"));
        assert!(CORE_DRAIN_RESOURCES.contains(&"configmaps"));
        assert!(CORE_DRAIN_RESOURCES.contains(&"secrets"));
        assert!(CORE_DRAIN_RESOURCES.contains(&"serviceaccounts"));
    }

    // Non-core URL helpers must produce the exact /apis/{group}/{version}/namespaces/{ns}/{plural}
    // paths required by the Kubernetes API group routing. A wrong path silently skips the resource.
    #[test]
    fn non_core_url_helpers_correct() {
        assert_eq!(
            non_core_namespaced_resource_list_path("sonobuoy", "apps", "v1", "deployments"),
            "/apis/apps/v1/namespaces/sonobuoy/deployments"
        );
        assert_eq!(
            non_core_namespaced_resource_list_path(
                "kube-system",
                "coordination.k8s.io",
                "v1",
                "leases"
            ),
            "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases"
        );
        assert_eq!(
            non_core_namespaced_resource_delete_path(
                "sonobuoy",
                "rbac.authorization.k8s.io",
                "v1",
                "rolebindings",
                "sonobuoy-serviceaccount-edit"
            ),
            "/apis/rbac.authorization.k8s.io/v1/namespaces/sonobuoy/rolebindings/sonobuoy-serviceaccount-edit"
        );
    }

    // NON_CORE_DRAIN_RESOURCES must include the resource types that sonobuoy and other
    // controllers create. Missing any of these leaves orphaned objects that break re-runs.
    #[test]
    fn non_core_drain_resources_includes_required_types() {
        let plurals: Vec<&str> = NON_CORE_DRAIN_RESOURCES
            .iter()
            .map(|(_, _, p)| *p)
            .collect();
        assert!(plurals.contains(&"deployments"), "deployments missing");
        assert!(plurals.contains(&"replicasets"), "replicasets missing");
        assert!(plurals.contains(&"statefulsets"), "statefulsets missing");
        assert!(plurals.contains(&"daemonsets"), "daemonsets missing");
        assert!(plurals.contains(&"rolebindings"), "rolebindings missing");
        assert!(plurals.contains(&"roles"), "roles missing");
        assert!(plurals.contains(&"leases"), "leases missing");
    }
}
