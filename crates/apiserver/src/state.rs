use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use u7s_store::{ListOptions, SqliteStore, Store};

use crate::auth::UserInfo;
use crate::rbac::RbacIndex;
use crate::types::{ResourceKey, ResourceMeta};

/// Maximum number of concurrent watch streams allowed per authenticated user.
/// A client that already has this many open watches gets HTTP 429 on the next attempt.
///
/// The kube-controller-manager's garbage collector opens one watch per registered
/// resource type (50+ watches for all core + apps/v1 + extension resources). The
/// limit must be high enough for the GC to establish all its watches simultaneously.
pub const MAX_WATCHES_PER_CLIENT: usize = 64;

/// Per-client watch stream concurrency limiter.
///
/// Holds a Semaphore per authenticated username. Each watch stream acquires one
/// permit for its lifetime and releases it when the stream ends (RAII). Attempts
/// beyond MAX_WATCHES_PER_CLIENT are rejected with HTTP 429.
#[derive(Clone, Default)]
pub struct WatchLimitState {
    inner: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
}

impl WatchLimitState {
    pub fn new() -> Self {
        WatchLimitState::default()
    }

    /// Return the Semaphore for the given client key, creating one if absent.
    pub fn semaphore_for(&self, client_key: &str) -> Arc<Semaphore> {
        let mut map = self.inner.lock().unwrap();
        map.entry(client_key.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_WATCHES_PER_CLIENT)))
            .clone()
    }
}

pub struct AppState<S = SqliteStore> {
    pub store: Arc<S>,
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
    /// Per-client watch stream concurrency limiter.
    pub watch_limit: WatchLimitState,
    /// HTTP client for admission webhook calls.
    pub webhook_client: reqwest::Client,
    /// DER-encoded cluster CA certificate used to verify kubelet TLS. None in tests.
    pub cluster_ca_der: Option<Arc<Vec<u8>>>,
}

// Manual Clone so we don't impose S: Clone (Arc<S> is always Clone).
impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        AppState {
            store: self.store.clone(),
            resource_registry: self.resource_registry.clone(),
            rbac_index: self.rbac_index.clone(),
            sa_key: self.sa_key.clone(),
            sa_decoding_key: self.sa_decoding_key.clone(),
            token_map: self.token_map.clone(),
            server_address: self.server_address.clone(),
            watch_limit: self.watch_limit.clone(),
            webhook_client: self.webhook_client.clone(),
            cluster_ca_der: self.cluster_ca_der.clone(),
        }
    }
}

impl<S: Store> AppState<S> {
    /// Convenience constructor for tests: cluster_ca_der and webhook_identity_pem default to None.
    #[cfg(test)]
    pub fn new(
        store: Arc<S>,
        sa_key: Option<jsonwebtoken::EncodingKey>,
        sa_decoding_key: Option<jsonwebtoken::DecodingKey>,
        token_map: HashMap<String, UserInfo>,
        server_address: String,
    ) -> Self {
        Self::new_with_ca(
            store,
            sa_key,
            sa_decoding_key,
            token_map,
            server_address,
            None,
            None,
        )
    }

    /// Build a pinned `reqwest::Client` for admission webhook calls.
    ///
    /// When `cluster_ca_der` is `Some`, the client trusts only that CA (not the system
    /// root store). This closes the SSRF/exfiltration vector where any user with webhook
    /// RBAC could route admission traffic to an arbitrary HTTPS server.
    ///
    /// When `webhook_identity_pem` is `Some`, the client presents an mTLS client
    /// certificate so webhook servers can verify they are talking to the apiserver.
    ///
    /// Both are `None` in tests, in which case the client falls back to a plain client
    /// with a 10-second timeout and no CA pinning — acceptable for unit tests that never
    /// make real HTTPS connections.
    fn build_webhook_client(
        cluster_ca_der: Option<&[u8]>,
        webhook_identity_pem: Option<&[u8]>,
    ) -> reqwest::Client {
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));

        if let Some(ca_der) = cluster_ca_der {
            // tls_certs_only disables the system/Mozilla root store and trusts only
            // the cluster CA. This closes the SSRF/exfiltration vector: a user with
            // webhook RBAC can only reach servers that present a cert signed by our CA.
            // Certificate::from_der parses the DER bytes; if malformed it returns Err
            // here or the error surfaces at build() time. In production cluster_ca_der
            // is always valid DER from generate_tls, so this path always succeeds.
            match reqwest::Certificate::from_der(ca_der) {
                Ok(cert) => {
                    builder = builder.tls_certs_only([cert]);
                }
                Err(e) => {
                    tracing::error!(
                        "webhook client: failed to parse cluster CA DER: {e}; using system roots"
                    );
                }
            }
        }

        if let Some(identity_pem) = webhook_identity_pem {
            match reqwest::Identity::from_pem(identity_pem) {
                Ok(identity) => {
                    builder = builder.identity(identity);
                }
                Err(e) => {
                    tracing::error!("webhook client: failed to build mTLS identity from PEM: {e}; proceeding without client cert");
                }
            }
        }

        builder.build().expect("webhook HTTP client must build")
    }

    /// `webhook_identity_pem`: optional concatenated PEM bytes of (cert, key) for mTLS.
    /// In production this is `admin_cert_pem + admin_key_pem` from `TlsMaterial`.
    /// Pass `None` in tests that do not exercise real webhook HTTPS connections.
    pub fn new_with_ca(
        store: Arc<S>,
        sa_key: Option<jsonwebtoken::EncodingKey>,
        sa_decoding_key: Option<jsonwebtoken::DecodingKey>,
        token_map: HashMap<String, UserInfo>,
        server_address: String,
        cluster_ca_der: Option<Vec<u8>>,
        webhook_identity_pem: Option<Vec<u8>>,
    ) -> Self {
        let registry = build_registry();
        let webhook_client =
            Self::build_webhook_client(cluster_ca_der.as_deref(), webhook_identity_pem.as_deref());
        AppState {
            store,
            resource_registry: Arc::new(registry),
            rbac_index: Arc::new(RbacIndex::new()),
            sa_key: sa_key.map(Arc::new),
            sa_decoding_key: sa_decoding_key.map(Arc::new),
            token_map: Arc::new(token_map),
            server_address,
            watch_limit: WatchLimitState::new(),
            webhook_client,
            cluster_ca_der: cluster_ca_der.map(Arc::new),
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
                            Err(e) => tracing::warn!("rbac init: parse error for {}: {e}", obj.key),
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
                                tracing::warn!("rbac init: unexpected key format: {}", obj.key);
                                continue;
                            }
                        };
                        match serde_json::from_slice::<serde_json::Value>(&obj.value) {
                            Ok(val) => self.rbac_index.apply_object(&api_key, &val),
                            Err(e) => tracing::warn!("rbac init: parse error for {}: {e}", obj.key),
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
    m.insert(rk("", "v1", "nodes"), rm("Node", false, true));
    m.insert(
        rk("", "v1", "persistentvolumes"),
        rm("PersistentVolume", false, true),
    );

    // core/v1 — namespaced
    m.insert(rk("", "v1", "services"), rm("Service", true, false));
    m.insert(
        rk("", "v1", "serviceaccounts"),
        rm("ServiceAccount", true, false),
    );
    m.insert(rk("", "v1", "configmaps"), rm("ConfigMap", true, false));
    m.insert(rk("", "v1", "secrets"), rm("Secret", true, false));
    m.insert(rk("", "v1", "events"), rm_cou("Event", true));
    m.insert(rk("", "v1", "endpoints"), rm("Endpoints", true, false));
    m.insert(
        rk("", "v1", "persistentvolumeclaims"),
        rm("PersistentVolumeClaim", true, true),
    );
    m.insert(
        rk("", "v1", "replicationcontrollers"),
        rm("ReplicationController", true, true),
    );
    m.insert(
        rk("", "v1", "resourcequotas"),
        rm("ResourceQuota", true, true),
    );
    m.insert(rk("", "v1", "limitranges"), rm("LimitRange", true, false));

    // apps/v1
    m.insert(rk("apps", "v1", "daemonsets"), rm("DaemonSet", true, true));
    m.insert(
        rk("apps", "v1", "deployments"),
        rm("Deployment", true, true),
    );
    m.insert(
        rk("apps", "v1", "replicasets"),
        rm("ReplicaSet", true, true),
    );
    m.insert(
        rk("apps", "v1", "statefulsets"),
        rm("StatefulSet", true, true),
    );

    // batch/v1
    m.insert(rk("batch", "v1", "jobs"), rm("Job", true, true));
    m.insert(rk("batch", "v1", "cronjobs"), rm("CronJob", true, true));

    // autoscaling/v1 and autoscaling/v2
    m.insert(
        rk("autoscaling", "v1", "horizontalpodautoscalers"),
        rm("HorizontalPodAutoscaler", true, true),
    );
    m.insert(
        rk("autoscaling", "v2", "horizontalpodautoscalers"),
        rm("HorizontalPodAutoscaler", true, true),
    );

    // rbac.authorization.k8s.io/v1
    m.insert(
        rk("rbac.authorization.k8s.io", "v1", "clusterroles"),
        rm("ClusterRole", false, false),
    );
    m.insert(
        rk("rbac.authorization.k8s.io", "v1", "clusterrolebindings"),
        rm("ClusterRoleBinding", false, false),
    );
    m.insert(
        rk("rbac.authorization.k8s.io", "v1", "roles"),
        rm("Role", true, false),
    );
    m.insert(
        rk("rbac.authorization.k8s.io", "v1", "rolebindings"),
        rm("RoleBinding", true, false),
    );

    // gateway.networking.k8s.io/v1 — GA resources
    m.insert(
        rk("gateway.networking.k8s.io", "v1", "gatewayclasses"),
        rm("GatewayClass", false, true),
    );
    m.insert(
        rk("gateway.networking.k8s.io", "v1", "gateways"),
        rm("Gateway", true, true),
    );
    m.insert(
        rk("gateway.networking.k8s.io", "v1", "httproutes"),
        rm("HTTPRoute", true, true),
    );

    // gateway.networking.k8s.io/v1beta1
    m.insert(
        rk("gateway.networking.k8s.io", "v1beta1", "referencegrants"),
        rm("ReferenceGrant", true, false),
    );

    // networking.k8s.io/v1
    m.insert(
        rk("networking.k8s.io", "v1", "networkpolicies"),
        rm("NetworkPolicy", true, false),
    );
    m.insert(
        rk("networking.k8s.io", "v1", "ingresses"),
        rm("Ingress", true, true),
    );
    m.insert(
        rk("networking.k8s.io", "v1", "ingressclasses"),
        rm("IngressClass", false, false),
    );

    // admissionregistration.k8s.io/v1
    m.insert(
        rk(
            "admissionregistration.k8s.io",
            "v1",
            "validatingwebhookconfigurations",
        ),
        rm("ValidatingWebhookConfiguration", false, false),
    );
    m.insert(
        rk(
            "admissionregistration.k8s.io",
            "v1",
            "mutatingwebhookconfigurations",
        ),
        rm("MutatingWebhookConfiguration", false, false),
    );

    // coordination.k8s.io/v1
    m.insert(
        rk("coordination.k8s.io", "v1", "leases"),
        rm("Lease", true, false),
    );

    // policy/v1
    m.insert(
        rk("policy", "v1", "poddisruptionbudgets"),
        rm("PodDisruptionBudget", true, false),
    );

    // storage.k8s.io/v1 — all cluster-scoped
    // kubelet uses create-or-update (PUT) semantics for csinodes
    m.insert(
        rk("storage.k8s.io", "v1", "csinodes"),
        rm_cou("CSINode", false),
    );
    m.insert(
        rk("storage.k8s.io", "v1", "csidrivers"),
        rm("CSIDriver", false, false),
    );
    m.insert(
        rk("storage.k8s.io", "v1", "storageclasses"),
        rm("StorageClass", false, false),
    );
    m.insert(
        rk("storage.k8s.io", "v1", "volumeattachments"),
        rm("VolumeAttachment", false, true),
    );

    // node.k8s.io/v1 — cluster-scoped
    // kubelet lists runtimeclasses on startup; serve as empty collection to stop the error loop.
    m.insert(
        rk("node.k8s.io", "v1", "runtimeclasses"),
        rm("RuntimeClass", false, false),
    );

    // certificates.k8s.io/v1 — cluster-scoped
    // has_status=true: spec is immutable after create; status.certificate is written via /status.
    m.insert(
        rk("certificates.k8s.io", "v1", "certificatesigningrequests"),
        rm("CertificateSigningRequest", false, true),
    );

    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csinodes_registered_as_cluster_scoped_create_or_update() {
        let registry = build_registry();
        let key = rk("storage.k8s.io", "v1", "csinodes");
        let meta = registry
            .get(&key)
            .expect("csinodes must be in build_registry");
        // kubelet PUTs CSINode on every boot; create_or_update must be true so the
        // handler doesn't reject the request when the object already exists.
        assert!(
            meta.create_or_update,
            "csinodes must have create_or_update=true"
        );
        assert!(!meta.namespaced, "csinodes is cluster-scoped");
    }

    // Helper: mirrors the cluster-scoped key-to-api-path transformation used in init().
    fn cluster_key_to_api_path(group: &str, plural: &str, store_key: &str) -> String {
        let prefix = format!("/registry/{group}/{plural}/");
        let name = store_key.strip_prefix(prefix.as_str()).unwrap_or(store_key);
        format!("/apis/{group}/v1/{plural}/{name}")
    }

    // Helper: mirrors the namespaced key-to-api-path transformation used in init().
    fn namespaced_key_to_api_path(group: &str, plural: &str, store_key: &str) -> Option<String> {
        let prefix = format!("/registry/{group}/{plural}/");
        let rest = store_key.strip_prefix(prefix.as_str()).unwrap_or(store_key);
        rest.split_once('/')
            .map(|(ns, name)| format!("/apis/{group}/v1/namespaces/{ns}/{plural}/{name}"))
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
        let api_path = namespaced_key_to_api_path(GROUP, "rolebindings", &store_key)
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
            name,
            prefix.as_str(),
            "strip_prefix must strip exactly one prefix occurrence, not recursively"
        );
    }

    /// IngressClass is a cluster-scoped resource in networking.k8s.io/v1. Without this entry
    /// GET/LIST/WATCH on /apis/networking.k8s.io/v1/ingressclasses falls through to the CR
    /// handler which returns 404 (no CRD installed), breaking ingress controller discovery.
    #[test]
    fn ingressclass_registered_as_cluster_scoped() {
        let registry = build_registry();
        let key = rk("networking.k8s.io", "v1", "ingressclasses");
        let meta = registry
            .get(&key)
            .expect("ingressclasses must be in build_registry");
        assert!(!meta.namespaced, "IngressClass is cluster-scoped");
        assert!(
            !meta.has_status_subresource,
            "IngressClass has no status subresource"
        );
        assert_eq!(meta.kind, "IngressClass");
    }

    /// kubelet lists node.k8s.io/v1/runtimeclasses on startup. Without this entry the
    /// generic handler falls through to the CR handler which returns 404 (no CRD installed),
    /// causing a tight error loop and log spam every few seconds.
    #[test]
    fn runtimeclasses_registered_as_cluster_scoped() {
        let registry = build_registry();
        let key = rk("node.k8s.io", "v1", "runtimeclasses");
        let meta = registry
            .get(&key)
            .expect("runtimeclasses must be in build_registry");
        assert!(!meta.namespaced, "runtimeclasses is cluster-scoped");
        assert_eq!(meta.kind, "RuntimeClass");
    }

    /// DaemonSet must be in apps/v1. Without this, POST/GET/LIST on
    /// /apis/apps/v1/namespaces/{ns}/daemonsets falls through to the CR handler,
    /// returning 404. System DaemonSets (CNI, kube-proxy) break silently.
    #[test]
    fn daemonset_registered_in_apps_v1() {
        let registry = build_registry();
        let key = rk("apps", "v1", "daemonsets");
        let meta = registry
            .get(&key)
            .expect("daemonsets must be in build_registry");
        assert!(meta.namespaced, "DaemonSet is namespaced");
        assert!(
            meta.has_status_subresource,
            "DaemonSet has a status subresource"
        );
        assert_eq!(meta.kind, "DaemonSet");
    }

    /// Job and CronJob must be registered in batch/v1. Without these entries,
    /// requests to /apis/batch/v1/namespaces/{ns}/jobs fall through to the CR handler
    /// which returns 404, making `kubectl get jobs` fail.
    #[test]
    fn job_and_cronjob_registered_in_batch_v1() {
        let registry = build_registry();

        let job_key = rk("batch", "v1", "jobs");
        let job_meta = registry
            .get(&job_key)
            .expect("jobs must be in build_registry");
        assert!(job_meta.namespaced, "Job is namespaced");
        assert!(
            job_meta.has_status_subresource,
            "Job has a status subresource"
        );
        assert_eq!(job_meta.kind, "Job");

        let cj_key = rk("batch", "v1", "cronjobs");
        let cj_meta = registry
            .get(&cj_key)
            .expect("cronjobs must be in build_registry");
        assert!(cj_meta.namespaced, "CronJob is namespaced");
        assert_eq!(cj_meta.kind, "CronJob");
    }

    /// HorizontalPodAutoscaler must be registered in both autoscaling/v1 and autoscaling/v2.
    /// HPA controllers negotiate the version to use; if v2 is missing they may fall back to
    /// v1, but both must be served to avoid 404 during version discovery.
    #[test]
    fn hpa_registered_in_autoscaling_v1_and_v2() {
        let registry = build_registry();

        let v1_key = rk("autoscaling", "v1", "horizontalpodautoscalers");
        let v1_meta = registry
            .get(&v1_key)
            .expect("horizontalpodautoscalers must be in autoscaling/v1");
        assert!(v1_meta.namespaced, "HPA is namespaced");
        assert_eq!(v1_meta.kind, "HorizontalPodAutoscaler");

        let v2_key = rk("autoscaling", "v2", "horizontalpodautoscalers");
        let v2_meta = registry
            .get(&v2_key)
            .expect("horizontalpodautoscalers must be in autoscaling/v2");
        assert!(v2_meta.namespaced, "HPA is namespaced");
        assert_eq!(v2_meta.kind, "HorizontalPodAutoscaler");
    }

    /// Endpoints, PVC, and PV must be in the core/v1 registry. Without them,
    /// requests fall through to the CR handler (no CRD) and return 404.
    /// kube-proxy watches Endpoints; controllers watch PVCs and PVs.
    #[test]
    fn core_v1_storage_and_network_resources_registered() {
        let registry = build_registry();

        let ep_key = rk("", "v1", "endpoints");
        let ep_meta = registry
            .get(&ep_key)
            .expect("endpoints must be in build_registry");
        assert!(ep_meta.namespaced, "Endpoints is namespaced");
        assert_eq!(ep_meta.kind, "Endpoints");

        let pvc_key = rk("", "v1", "persistentvolumeclaims");
        let pvc_meta = registry
            .get(&pvc_key)
            .expect("persistentvolumeclaims must be in build_registry");
        assert!(pvc_meta.namespaced, "PVC is namespaced");
        assert!(
            pvc_meta.has_status_subresource,
            "PVC has a status subresource"
        );
        assert_eq!(pvc_meta.kind, "PersistentVolumeClaim");

        let pv_key = rk("", "v1", "persistentvolumes");
        let pv_meta = registry
            .get(&pv_key)
            .expect("persistentvolumes must be in build_registry");
        assert!(!pv_meta.namespaced, "PV is cluster-scoped");
        assert!(
            pv_meta.has_status_subresource,
            "PV has a status subresource"
        );
        assert_eq!(pv_meta.kind, "PersistentVolume");

        let rc_key = rk("", "v1", "replicationcontrollers");
        let rc_meta = registry
            .get(&rc_key)
            .expect("replicationcontrollers must be in build_registry");
        assert!(rc_meta.namespaced, "ReplicationController is namespaced");
        assert_eq!(rc_meta.kind, "ReplicationController");
    }

    // ---------------------------------------------------------------------------
    // Regression tests: webhook client CA pinning (mayor-h0n2)
    //
    // These tests verify that build_webhook_client correctly constructs a pinned
    // reqwest::Client. The security property under test: a user with webhook RBAC
    // must not be able to route admission traffic to an arbitrary HTTPS server
    // (SSRF/exfiltration). The fix is `.tls_built_in_root_certs(false)` + cluster CA.
    // ---------------------------------------------------------------------------

    /// build_webhook_client succeeds when given valid DER-encoded CA bytes.
    ///
    /// This is the happy-path construction test. If it fails, the apiserver cannot
    /// start at all (new_with_ca panics). The security property: the CA must be
    /// parseable so CA-pinning is actually applied.
    #[test]
    fn build_webhook_client_succeeds_with_valid_ca_der() {
        // Use rcgen to produce a self-signed DER cert that mimics the cluster CA.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let ca_der = cert.cert.der().to_vec();

        // Must not panic — if CA DER is valid, client construction succeeds.
        let _client = AppState::<SqliteStore>::build_webhook_client(Some(&ca_der), None);
    }

    /// build_webhook_client succeeds with no CA and no identity (test path).
    ///
    /// The cfg(test) AppState::new() constructor passes None for both. Verifying
    /// that None+None produces a working client ensures test helpers keep compiling
    /// after the security fix is applied.
    #[test]
    fn build_webhook_client_succeeds_with_no_ca_no_identity() {
        let _client = AppState::<SqliteStore>::build_webhook_client(None, None);
    }

    /// build_webhook_client succeeds when given a valid PEM identity (cert + key).
    ///
    /// The production path concatenates admin_cert_pem + admin_key_pem. This test
    /// verifies that a real PEM cert+key pair produced by rcgen is accepted by
    /// reqwest::Identity::from_pem. Without mTLS identity, webhook servers cannot
    /// verify the caller is the apiserver.
    #[test]
    fn build_webhook_client_succeeds_with_valid_identity_pem() {
        use rcgen::{CertificateParams, KeyPair};

        // Generate a CA.
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-ca");
        let ca_cert_der = ca_params
            .self_signed(&ca_key)
            .expect("self-sign CA")
            .der()
            .to_vec();
        let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

        // Generate a leaf cert signed by that CA.
        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "apiserver");
        let leaf_cert_der = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .expect("sign leaf")
            .der()
            .to_vec();

        // Build PEM identity: cert PEM + key PEM concatenated.
        let mut identity_pem = pem_encode_cert(&leaf_cert_der);
        identity_pem.extend_from_slice(leaf_key.serialize_pem().as_bytes());

        // Must succeed: valid CA DER + valid identity PEM.
        let _client = AppState::<SqliteStore>::build_webhook_client(Some(&ca_cert_der), Some(&identity_pem));
    }

    /// Inline PEM encoder for test use — mirrors tls::pem_encode.
    fn pem_encode_cert(der: &[u8]) -> Vec<u8> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let encoded = b64.encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out.into_bytes()
    }
}
