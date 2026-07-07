/// Derives the store key for a namespace-scoped resource.
/// group="" for core/v1.
pub fn object_key(resource: &str, namespace: &str, name: &str) -> String {
    format!("/registry/{}/{}/{}", resource, namespace, name)
}

/// Derives the list prefix for a namespace-scoped resource.
pub fn list_prefix(resource: &str, namespace: &str) -> String {
    format!("/registry/{}/{}/", resource, namespace)
}

/// Derives the store key for a cluster-scoped resource (no namespace).
/// e.g. /registry/clusterroles/my-role
pub fn cluster_object_key(resource: &str, name: &str) -> String {
    format!("/registry/{}/{}", resource, name)
}

/// Derives the list prefix for a cluster-scoped resource.
pub fn cluster_list_prefix(resource: &str) -> String {
    format!("/registry/{}/", resource)
}

/// Kubernetes dual-groups the Event kind: core/v1 Event and events.k8s.io/v1 Event
/// are the same underlying object, both backed by one etcd keyspace
/// (/registry/events/<namespace>/<name>). Treat events.k8s.io as the core group
/// for key derivation so an Event created via one group is visible via the other.
fn is_dual_grouped_events(group: &str, plural: &str) -> bool {
    group == "events.k8s.io" && plural == "events"
}

/// Derives the store key for a resource in a non-core group.
/// For core group (group == ""), falls back to existing key layout.
/// Namespaced: /registry/<group>/<plural>/<namespace>/<name>
/// Cluster:    /registry/<group>/<plural>/<name>
pub fn group_object_key(group: &str, plural: &str, namespace: Option<&str>, name: &str) -> String {
    if group.is_empty() || is_dual_grouped_events(group, plural) {
        match namespace {
            Some(ns) => object_key(plural, ns, name),
            None => cluster_object_key(plural, name),
        }
    } else {
        match namespace {
            Some(ns) => format!("/registry/{}/{}/{}/{}", group, plural, ns, name),
            None => format!("/registry/{}/{}/{}", group, plural, name),
        }
    }
}

/// Derives the list prefix for a resource in a non-core group.
pub fn group_list_prefix(group: &str, plural: &str, namespace: Option<&str>) -> String {
    if group.is_empty() || is_dual_grouped_events(group, plural) {
        match namespace {
            Some(ns) => list_prefix(plural, ns),
            None => cluster_list_prefix(plural),
        }
    } else {
        match namespace {
            Some(ns) => format!("/registry/{}/{}/{}/", group, plural, ns),
            None => format!("/registry/{}/{}/", group, plural),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // object_key must produce the canonical namespace-scoped etcd path
    #[test]
    fn object_key_format() {
        assert_eq!(
            object_key("pods", "default", "my-pod"),
            "/registry/pods/default/my-pod"
        );
    }

    // list_prefix must end with a slash so etcd prefix scans don't bleed into sibling namespaces
    #[test]
    fn list_prefix_ends_with_slash() {
        assert_eq!(list_prefix("pods", "default"), "/registry/pods/default/");
    }

    // cluster_object_key must omit the namespace segment
    #[test]
    fn cluster_object_key_format() {
        assert_eq!(
            cluster_object_key("nodes", "my-node"),
            "/registry/nodes/my-node"
        );
    }

    // cluster_list_prefix must end with a slash for prefix scans
    #[test]
    fn cluster_list_prefix_ends_with_slash() {
        assert_eq!(cluster_list_prefix("nodes"), "/registry/nodes/");
    }

    // group_object_key with empty group + namespace must fall back to the core object_key layout
    #[test]
    fn group_object_key_core_namespaced() {
        assert_eq!(
            group_object_key("", "pods", Some("default"), "my-pod"),
            "/registry/pods/default/my-pod"
        );
    }

    // group_object_key with empty group + no namespace must fall back to cluster_object_key layout
    #[test]
    fn group_object_key_core_cluster() {
        assert_eq!(
            group_object_key("", "nodes", None, "my-node"),
            "/registry/nodes/my-node"
        );
    }

    // group_object_key with non-core group + namespace must insert the group prefix
    #[test]
    fn group_object_key_noncore_namespaced() {
        assert_eq!(
            group_object_key("apps", "deployments", Some("default"), "my-deploy"),
            "/registry/apps/deployments/default/my-deploy"
        );
    }

    // group_object_key with non-core group + no namespace must produce a cluster-scoped path
    #[test]
    fn group_object_key_noncore_cluster() {
        assert_eq!(
            group_object_key("rbac.authorization.k8s.io", "clusterroles", None, "my-role"),
            "/registry/rbac.authorization.k8s.io/clusterroles/my-role"
        );
    }

    // group_list_prefix with empty group + namespace must fall back to core list_prefix layout
    #[test]
    fn group_list_prefix_core_namespaced() {
        assert_eq!(
            group_list_prefix("", "pods", Some("default")),
            "/registry/pods/default/"
        );
    }

    // group_list_prefix with empty group + no namespace must fall back to cluster_list_prefix layout
    #[test]
    fn group_list_prefix_core_cluster() {
        assert_eq!(group_list_prefix("", "nodes", None), "/registry/nodes/");
    }

    // group_list_prefix with non-core group + namespace must insert group prefix and end with slash
    #[test]
    fn group_list_prefix_noncore_namespaced() {
        assert_eq!(
            group_list_prefix("apps", "deployments", Some("default")),
            "/registry/apps/deployments/default/"
        );
    }

    // group_list_prefix with non-core group + no namespace must produce cluster-scoped prefix
    #[test]
    fn group_list_prefix_noncore_cluster() {
        assert_eq!(
            group_list_prefix("rbac.authorization.k8s.io", "clusterroles", None),
            "/registry/rbac.authorization.k8s.io/clusterroles/"
        );
    }

    // events.k8s.io/v1 Event and core/v1 Event are the same underlying object in
    // Kubernetes, dual-grouped for client compatibility. If group_object_key kept
    // them in separate keyspaces, an Event created via events.k8s.io/v1 (used by
    // client-go's newer event recorder) would be invisible to core/v1 GET/LIST
    // callers (e.g. `kubectl get events`), and vice versa.
    #[test]
    fn group_object_key_events_k8s_io_matches_core_event_key() {
        assert_eq!(
            group_object_key("events.k8s.io", "events", Some("default"), "my-event"),
            group_object_key("", "events", Some("default"), "my-event"),
            "events.k8s.io/v1 Event must resolve to the same storage key as core/v1 Event"
        );
    }

    // Same rationale as above, but for LIST/WATCH prefix scans: if the prefixes
    // diverged, a `kubectl get events` (core/v1) would miss events written via
    // the events.k8s.io/v1 API, silently dropping event history from `describe`.
    #[test]
    fn group_list_prefix_events_k8s_io_matches_core_event_prefix() {
        assert_eq!(
            group_list_prefix("events.k8s.io", "events", Some("default")),
            group_list_prefix("", "events", Some("default")),
            "events.k8s.io/v1 Event list prefix must match core/v1 Event list prefix"
        );
    }
}
