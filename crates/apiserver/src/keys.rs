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

/// Derives the store key for a resource in a non-core group.
/// For core group (group == ""), falls back to existing key layout.
/// Namespaced: /registry/<group>/<plural>/<namespace>/<name>
/// Cluster:    /registry/<group>/<plural>/<name>
pub fn group_object_key(group: &str, plural: &str, namespace: Option<&str>, name: &str) -> String {
    if group.is_empty() {
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
    if group.is_empty() {
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
