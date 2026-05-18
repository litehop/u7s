/// Derives the store key for a namespace-scoped resource.
/// group="" for core/v1.
pub fn object_key(resource: &str, namespace: &str, name: &str) -> String {
    format!("/registry/{}/{}/{}", resource, namespace, name)
}

/// Derives the list prefix for a namespace-scoped resource.
pub fn list_prefix(resource: &str, namespace: &str) -> String {
    format!("/registry/{}/{}/", resource, namespace)
}
