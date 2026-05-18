use std::collections::HashMap;
use std::sync::Arc;
use u7s_store::SqliteStore;

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

impl AppState {
    pub fn new(store: Arc<SqliteStore>, sa_key: Option<jsonwebtoken::EncodingKey>) -> Self {
        let registry = build_registry();
        AppState {
            store,
            resource_registry: Arc::new(registry),
            rbac_index: Arc::new(RbacIndex::new()),
            sa_key: sa_key.map(Arc::new),
        }
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
