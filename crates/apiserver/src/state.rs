use std::collections::HashMap;
use std::sync::Arc;
use u7s_store::{ListOptions, SqliteStore, Store as _};

use crate::auth::UserInfo;
use crate::rbac::RbacIndex;
use crate::types::{ResourceKey, ResourceMeta};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<SqliteStore>,
    pub resource_registry: Arc<HashMap<ResourceKey, ResourceMeta>>,
    pub rbac_index: Arc<RbacIndex>,
    /// RSA signing key for service-account JWTs. None when SA key is unavailable.
    pub sa_key: Option<Arc<jsonwebtoken::EncodingKey>>,
    /// RSA public key for verifying inbound SA JWTs. None when SA key is unavailable.
    pub sa_decoding_key: Option<Arc<jsonwebtoken::DecodingKey>>,
    /// Static bearer-token map loaded from --token-auth-file. Empty when not configured.
    pub token_map: Arc<HashMap<String, UserInfo>>,
    /// Advertised server address returned in /api discovery (e.g. "https://1.2.3.4:6443").
    pub server_address: String,
}

impl AppState {
    pub fn new(
        store: Arc<SqliteStore>,
        sa_key: Option<jsonwebtoken::EncodingKey>,
        sa_decoding_key: Option<jsonwebtoken::DecodingKey>,
        token_map: HashMap<String, UserInfo>,
        server_address: String,
    ) -> Self {
        let registry = build_registry();
        AppState {
            store,
            resource_registry: Arc::new(registry),
            rbac_index: Arc::new(RbacIndex::new()),
            sa_key: sa_key.map(Arc::new),
            sa_decoding_key: sa_decoding_key.map(Arc::new),
            token_map: Arc::new(token_map),
            server_address,
        }
    }

    /// Populate the RBAC index from objects already persisted in the store.
    ///
    /// Must be called once at startup before serving requests.  Scans the four
    /// RBAC prefixes and calls `rbac_index.apply_object` for every entry found.
    ///
    /// Errors from individual objects are logged and skipped so that a single
    /// corrupt entry does not prevent the server from starting.
    pub async fn init(&self) {
        const GROUP: &str = "rbac.authorization.k8s.io";

        // Cluster-scoped resources.
        for plural in &["clusterroles", "clusterrolebindings"] {
            let prefix = format!("/registry/{GROUP}/{plural}/");
            match self.store.list(&prefix, ListOptions::default()).await {
                Err(e) => tracing::warn!("rbac init: list {prefix} failed: {e}"),
                Ok(resp) => {
                    for obj in resp.items {
                        // Store key: /registry/<group>/<plural>/<name>
                        // apply_object expects: /apis/<group>/v1/<plural>/<name>
                        // Use strip_prefix (strips exactly once) instead of
                        // trim_start_matches (strips all occurrences of the pattern).
                        let name = obj.key.strip_prefix(prefix.as_str()).unwrap_or(&obj.key);
                        let api_key = format!("/apis/{GROUP}/v1/{plural}/{name}");
                        match serde_json::from_slice::<serde_json::Value>(&obj.value) {
                            Ok(val) => self.rbac_index.apply_object(&api_key, &val),
                            Err(e) => tracing::warn!(
                                "rbac init: parse error for {}: {e}",
                                obj.key
                            ),
                        }
                    }
                }
            }
        }

        // Namespaced resources: /registry/<group>/<plural>/<ns>/<name>
        for plural in &["roles", "rolebindings"] {
            let prefix = format!("/registry/{GROUP}/{plural}/");
            match self.store.list(&prefix, ListOptions::default()).await {
                Err(e) => tracing::warn!("rbac init: list {prefix} failed: {e}"),
                Ok(resp) => {
                    for obj in resp.items {
                        // Store key: /registry/<group>/<plural>/<ns>/<name>
                        // apply_object expects: /apis/<group>/v1/namespaces/<ns>/<plural>/<name>
                        // Use strip_prefix (strips exactly once) instead of
                        // trim_start_matches (strips all occurrences of the pattern).
                        let rest = obj.key.strip_prefix(prefix.as_str()).unwrap_or(&obj.key);
                        // rest = "<ns>/<name>"
                        let api_key = match rest.split_once('/') {
                            Some((ns, name)) => {
                                format!("/apis/{GROUP}/v1/namespaces/{ns}/{plural}/{name}")
                            }
                            None => {
                                tracing::warn!(
                                    "rbac init: unexpected key format: {}",
                                    obj.key
                                );
                                continue;
                            }
                        };
                        match serde_json::from_slice::<serde_json::Value>(&obj.value) {
                            Ok(val) => self.rbac_index.apply_object(&api_key, &val),
                            Err(e) => tracing::warn!(
                                "rbac init: parse error for {}: {e}",
                                obj.key
                            ),
                        }
                    }
                }
            }
        }

        tracing::info!("rbac init: index populated from store");
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

    // networking.k8s.io/v1
    m.insert(rk("networking.k8s.io", "v1", "networkpolicies"), rm("NetworkPolicy", true,  false));
    m.insert(rk("networking.k8s.io", "v1", "ingresses"),       rm("Ingress",       true,  true));

    // admissionregistration.k8s.io/v1
    m.insert(rk("admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations"), rm("ValidatingWebhookConfiguration", false, false));
    m.insert(rk("admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations"),   rm("MutatingWebhookConfiguration",   false, false));

    // coordination.k8s.io/v1
    m.insert(rk("coordination.k8s.io", "v1", "leases"), rm("Lease", true, false));

    // policy/v1
    m.insert(rk("policy", "v1", "poddisruptionbudgets"), rm("PodDisruptionBudget", true, false));

    // storage.k8s.io/v1 — all cluster-scoped
    // kubelet uses create-or-update (PUT) semantics for csinodes
    m.insert(rk("storage.k8s.io", "v1", "csinodes"),          rm_cou("CSINode",          false));
    m.insert(rk("storage.k8s.io", "v1", "csidrivers"),        rm("CSIDriver",        false, false));
    m.insert(rk("storage.k8s.io", "v1", "storageclasses"),    rm("StorageClass",     false, false));
    m.insert(rk("storage.k8s.io", "v1", "volumeattachments"), rm("VolumeAttachment", false, true));

    // node.k8s.io/v1 — cluster-scoped
    // kubelet lists runtimeclasses on startup; serve as empty collection to stop the error loop.
    m.insert(rk("node.k8s.io", "v1", "runtimeclasses"), rm("RuntimeClass", false, false));

    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csinodes_registered_as_cluster_scoped_create_or_update() {
        let registry = build_registry();
        let key = rk("storage.k8s.io", "v1", "csinodes");
        let meta = registry.get(&key).expect("csinodes must be in build_registry");
        // kubelet PUTs CSINode on every boot; create_or_update must be true so the
        // handler doesn't reject the request when the object already exists.
        assert!(meta.create_or_update, "csinodes must have create_or_update=true");
        assert!(!meta.namespaced, "csinodes is cluster-scoped");
    }

    // Helper: mirrors the cluster-scoped key-to-api-path transformation used in init().
    fn cluster_key_to_api_path(group: &str, plural: &str, store_key: &str) -> String {
        let prefix = format!("/registry/{group}/{plural}/");
        let name = store_key.strip_prefix(prefix.as_str()).unwrap_or(store_key);
        format!("/apis/{group}/v1/{plural}/{name}")
    }

    // Helper: mirrors the namespaced key-to-api-path transformation used in init().
    fn namespaced_key_to_api_path(
        group: &str,
        plural: &str,
        store_key: &str,
    ) -> Option<String> {
        let prefix = format!("/registry/{group}/{plural}/");
        let rest = store_key.strip_prefix(prefix.as_str()).unwrap_or(store_key);
        rest.split_once('/').map(|(ns, name)| {
            format!("/apis/{group}/v1/namespaces/{ns}/{plural}/{name}")
        })
    }

    const GROUP: &str = "rbac.authorization.k8s.io";

    #[test]
    fn clusterrolebinding_store_key_parses_to_correct_name() {
        // A store key /registry/<group>/clusterrolebindings/system:node must produce
        // an api path ending in /clusterrolebindings/system:node so the RBAC index
        // receives the right key when AppState::init() populates it at startup.
        let store_key = format!("/registry/{GROUP}/clusterrolebindings/system:node");
        let api_path = cluster_key_to_api_path(GROUP, "clusterrolebindings", &store_key);
        assert_eq!(
            api_path,
            format!("/apis/{GROUP}/v1/clusterrolebindings/system:node"),
            "clusterrolebinding store key must map to correct api path"
        );
    }

    #[test]
    fn rolebinding_store_key_parses_to_correct_namespace_and_name() {
        // A store key /registry/<group>/rolebindings/<ns>/<name> must produce an api
        // path of /apis/<group>/v1/namespaces/<ns>/rolebindings/<name> so namespaced
        // RBAC policies are indexed under the right key at startup.
        let store_key = format!("/registry/{GROUP}/rolebindings/kube-system/my-binding");
        let api_path =
            namespaced_key_to_api_path(GROUP, "rolebindings", &store_key)
                .expect("valid namespaced key must produce Some");
        assert_eq!(
            api_path,
            format!("/apis/{GROUP}/v1/namespaces/kube-system/rolebindings/my-binding"),
            "rolebinding store key must map to correct namespaced api path"
        );
    }

    #[test]
    fn strip_prefix_strips_exactly_once_not_repeatedly() {
        // trim_start_matches would strip all leading occurrences of the pattern; strip_prefix
        // strips exactly one. This test encodes why we use strip_prefix: a name that begins
        // with the same characters as the suffix of the prefix must not be double-stripped.
        let group = "rbac.authorization.k8s.io";
        let plural = "clusterroles";
        let prefix = format!("/registry/{group}/{plural}/");
        let doubled = format!("{prefix}{prefix}");
        let name = doubled.strip_prefix(prefix.as_str()).unwrap_or(&doubled);
        assert_eq!(
            name, prefix.as_str(),
            "strip_prefix must strip exactly one prefix occurrence, not recursively"
        );
    }

    /// kubelet lists node.k8s.io/v1/runtimeclasses on startup. Without this entry the
    /// generic handler falls through to the CR handler which returns 404 (no CRD installed),
    /// causing a tight error loop and log spam every few seconds.
    #[test]
    fn runtimeclasses_registered_as_cluster_scoped() {
        let registry = build_registry();
        let key = rk("node.k8s.io", "v1", "runtimeclasses");
        let meta = registry.get(&key).expect("runtimeclasses must be in build_registry");
        assert!(!meta.namespaced, "runtimeclasses is cluster-scoped");
        assert_eq!(meta.kind, "RuntimeClass");
    }
}
