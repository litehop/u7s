use std::collections::HashMap;
use std::sync::Arc;
use u7s_store::{ListOptions, SqliteStore, Store};

use crate::keys::group_list_prefix;
use crate::rbac::RbacIndex;
use crate::types::{ResourceKey, ResourceMeta};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<SqliteStore>,
    pub resource_registry: Arc<HashMap<ResourceKey, ResourceMeta>>,
    pub rbac_index: Arc<RbacIndex>,
    /// RSA signing key for service-account JWTs. None when SA key is unavailable.
    pub sa_key: Option<Arc<jsonwebtoken::EncodingKey>>,
}

const RBAC_GROUP: &str = "rbac.authorization.k8s.io";

impl AppState {
    pub async fn new(store: Arc<SqliteStore>, sa_key: Option<jsonwebtoken::EncodingKey>) -> Self {
        let registry = build_registry();
        let rbac_index = RbacIndex::new();
        seed_rbac_index(&store, &rbac_index).await;
        AppState {
            store,
            resource_registry: Arc::new(registry),
            rbac_index: Arc::new(rbac_index),
            sa_key: sa_key.map(Arc::new),
        }
    }
}

/// Scan the store for all RBAC objects and populate the index.
async fn seed_rbac_index(store: &SqliteStore, index: &RbacIndex) {
    // Cluster-scoped: clusterroles, clusterrolebindings.
    for plural in &["clusterroles", "clusterrolebindings"] {
        let prefix = group_list_prefix(RBAC_GROUP, plural, None);
        let Ok(resp) = store.list(&prefix, ListOptions::default()).await else { continue };
        for obj in &resp.items {
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&obj.value) else { continue };
            // Convert store key to the format apply_object() expects:
            // /registry/rbac.authorization.k8s.io/clusterroles/<name>
            // → /apis/rbac.authorization.k8s.io/v1/clusterroles/<name>
            let api_key = store_key_to_api_key(&obj.key);
            index.apply_object(&api_key, &value);
        }
    }

    // Namespaced: roles, rolebindings — list all namespaces at once via top-level prefix.
    for plural in &["roles", "rolebindings"] {
        let prefix = group_list_prefix(RBAC_GROUP, plural, None);
        let Ok(resp) = store.list(&prefix, ListOptions::default()).await else { continue };
        for obj in &resp.items {
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&obj.value) else { continue };
            let api_key = store_key_to_api_key(&obj.key);
            index.apply_object(&api_key, &value);
        }
    }
}

/// Convert a store key for an RBAC object to the API key format expected by RbacIndex::apply_object.
///
/// Cluster-scoped:
///   /registry/rbac.authorization.k8s.io/clusterroles/<name>
///   → /apis/rbac.authorization.k8s.io/v1/clusterroles/<name>
///
/// Namespaced:
///   /registry/rbac.authorization.k8s.io/roles/<ns>/<name>
///   → /apis/rbac.authorization.k8s.io/v1/namespaces/<ns>/roles/<name>
fn store_key_to_api_key(key: &str) -> String {
    // Strip "/registry/" prefix, leaving "rbac.authorization.k8s.io/<plural>/..."
    let stripped = key.strip_prefix("/registry/").unwrap_or(key);
    // parts: [group, plural, ...]
    let parts: Vec<&str> = stripped.splitn(4, '/').collect();
    match parts.as_slice() {
        [group, plural @ ("clusterroles" | "clusterrolebindings"), name] => {
            format!("/apis/{group}/v1/{plural}/{name}")
        }
        [group, plural @ ("roles" | "rolebindings"), ns, name] => {
            format!("/apis/{group}/v1/namespaces/{ns}/{plural}/{name}")
        }
        _ => key.to_owned(),
    }
}

fn rk(group: &str, version: &str, plural: &str) -> ResourceKey {
    ResourceKey {
        group: group.to_string(),
        version: version.to_string(),
        plural: plural.to_string(),
    }
}

fn rm(kind: &str, namespaced: bool, has_status: bool) -> ResourceMeta {
    ResourceMeta {
        kind: kind.to_string(),
        namespaced,
        has_status_subresource: has_status,
        create_or_update: false,
    }
}

fn rm_cou(kind: &str, namespaced: bool) -> ResourceMeta {
    ResourceMeta {
        kind: kind.to_string(),
        namespaced,
        has_status_subresource: false,
        create_or_update: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use u7s_store::Store;
    use crate::keys::group_object_key;
    use crate::rbac::AuthzRequest;

    fn make_store() -> Arc<SqliteStore> {
        Arc::new(SqliteStore::new(":memory:").expect("in-memory store"))
    }

    #[tokio::test]
    async fn rbac_index_populated_from_store_on_startup() {
        // RBAC rules stored in a previous run must survive restart — the index must
        // be populated from the store during AppState::new(), not left empty.
        let store = make_store();

        // Write a ClusterRole and ClusterRoleBinding before constructing AppState.
        let role_key = group_object_key(RBAC_GROUP, "clusterroles", None, "pod-reader");
        let role_val = Bytes::from(serde_json::json!({
            "metadata": { "name": "pod-reader" },
            "rules": [{ "apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"] }]
        }).to_string());
        store.put(&role_key, role_val, None).await.expect("store clusterrole");

        let bind_key = group_object_key(RBAC_GROUP, "clusterrolebindings", None, "alice-pod-reader");
        let bind_val = Bytes::from(serde_json::json!({
            "metadata": { "name": "alice-pod-reader" },
            "subjects": [{ "kind": "User", "name": "alice" }],
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "pod-reader" }
        }).to_string());
        store.put(&bind_key, bind_val, None).await.expect("store clusterrolebinding");

        // Also write a namespaced Role and RoleBinding.
        let ns_role_key = group_object_key(RBAC_GROUP, "roles", Some("default"), "secret-reader");
        let ns_role_val = Bytes::from(serde_json::json!({
            "metadata": { "name": "secret-reader", "namespace": "default" },
            "rules": [{ "apiGroups": [""], "resources": ["secrets"], "verbs": ["get"] }]
        }).to_string());
        store.put(&ns_role_key, ns_role_val, None).await.expect("store role");

        let ns_bind_key = group_object_key(RBAC_GROUP, "rolebindings", Some("default"), "bob-secret-reader");
        let ns_bind_val = Bytes::from(serde_json::json!({
            "metadata": { "name": "bob-secret-reader", "namespace": "default" },
            "subjects": [{ "kind": "User", "name": "bob" }],
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "secret-reader" },
            "namespace": "default"
        }).to_string());
        store.put(&ns_bind_key, ns_bind_val, None).await.expect("store rolebinding");

        // Construct AppState — this must seed the RBAC index from the store.
        let state = AppState::new(store, None).await;

        let no_groups: Vec<String> = vec![];

        // ClusterRoleBinding grants alice get/list pods in any namespace.
        assert!(
            state.rbac_index.is_allowed(&AuthzRequest {
                username: "alice", groups: &no_groups,
                verb: "get", api_group: "", resource: "pods", subresource: "",
                namespace: Some("default"), name: None,
            }),
            "alice must be allowed to get pods via ClusterRoleBinding loaded at startup"
        );

        // RoleBinding grants bob get secrets in namespace default.
        assert!(
            state.rbac_index.is_allowed(&AuthzRequest {
                username: "bob", groups: &no_groups,
                verb: "get", api_group: "", resource: "secrets", subresource: "",
                namespace: Some("default"), name: None,
            }),
            "bob must be allowed to get secrets in default via RoleBinding loaded at startup"
        );

        // bob must NOT be allowed in namespace other — binding is scoped to default.
        assert!(
            !state.rbac_index.is_allowed(&AuthzRequest {
                username: "bob", groups: &no_groups,
                verb: "get", api_group: "", resource: "secrets", subresource: "",
                namespace: Some("other"), name: None,
            }),
            "bob must be denied in namespace 'other' — RoleBinding is scoped to 'default'"
        );
    }

    #[test]
    fn store_key_to_api_key_cluster_scoped() {
        let key = "/registry/rbac.authorization.k8s.io/clusterroles/my-role";
        assert_eq!(
            store_key_to_api_key(key),
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/my-role"
        );
    }

    #[test]
    fn store_key_to_api_key_namespaced() {
        let key = "/registry/rbac.authorization.k8s.io/roles/default/my-role";
        assert_eq!(
            store_key_to_api_key(key),
            "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles/my-role"
        );
    }
}

fn build_registry() -> HashMap<ResourceKey, ResourceMeta> {
    let mut m = HashMap::new();

    // core/v1 — cluster-scoped
    m.insert(rk("", "v1", "nodes"),           rm("Node",           false, true));

    // core/v1 — namespaced
    m.insert(rk("", "v1", "services"),        rm("Service",        true,  false));
    m.insert(rk("", "v1", "serviceaccounts"), rm("ServiceAccount", true,  false));
    m.insert(rk("", "v1", "configmaps"),      rm("ConfigMap",      true,  false));
    m.insert(rk("", "v1", "secrets"),         rm("Secret",         true,  false));
    m.insert(rk("", "v1", "events"),          rm_cou("Event",      true));

    // apps/v1
    m.insert(rk("apps", "v1", "deployments"),   rm("Deployment",  true,  true));
    m.insert(rk("apps", "v1", "replicasets"),   rm("ReplicaSet",  true,  true));
    m.insert(rk("apps", "v1", "statefulsets"),  rm("StatefulSet", true,  true));

    // rbac.authorization.k8s.io/v1
    m.insert(rk("rbac.authorization.k8s.io", "v1", "clusterroles"),        rm("ClusterRole",        false, false));
    m.insert(rk("rbac.authorization.k8s.io", "v1", "clusterrolebindings"), rm("ClusterRoleBinding", false, false));
    m.insert(rk("rbac.authorization.k8s.io", "v1", "roles"),               rm("Role",               true,  false));
    m.insert(rk("rbac.authorization.k8s.io", "v1", "rolebindings"),        rm("RoleBinding",        true,  false));

    m
}
