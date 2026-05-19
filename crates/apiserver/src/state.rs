use std::collections::HashMap;
use std::sync::Arc;
use u7s_store::{ListOptions, SqliteStore, Store as _};

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
    /// Advertised server address returned in /api discovery (e.g. "https://1.2.3.4:6443").
    pub server_address: String,
}

impl AppState {
    pub fn new(
        store: Arc<SqliteStore>,
        sa_key: Option<jsonwebtoken::EncodingKey>,
        sa_decoding_key: Option<jsonwebtoken::DecodingKey>,
        server_address: String,
    ) -> Self {
        let registry = build_registry();
        AppState {
            store,
            resource_registry: Arc::new(registry),
            rbac_index: Arc::new(RbacIndex::new()),
            sa_key: sa_key.map(Arc::new),
            sa_decoding_key: sa_decoding_key.map(Arc::new),
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
                        let name = obj.key.trim_start_matches(&prefix);
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
                        let rest = obj.key.trim_start_matches(&prefix);
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

    m
}
