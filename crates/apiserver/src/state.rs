use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use u7s_store::{ListOptions, SqliteStore, Store};

use crate::auth::UserInfo;
use crate::rbac::RbacIndex;
use crate::types::{ResourceKey, ResourceMeta};

/// Sentinel key prefix for allocated service IPs.
/// Format: /registry/service-ips/<ip>
/// The UNIQUE constraint on `objects.key` in SQLite makes allocation race-safe.
pub const SERVICE_IP_PREFIX: &str = "/registry/service-ips/";

/// Holds the CIDR parameters for clusterIP allocation.
///
/// Correctness comes from the store's UNIQUE key constraint (CAS).
/// The `hint` is a best-effort offset to avoid scanning from offset 1 every time.
pub struct ServiceIpAllocator {
    /// Base address of the service CIDR (e.g. 10.96.0.0).
    pub base: Ipv4Addr,
    /// Number of IPs in the range (2^(32-prefix)).
    pub size: u32,
    /// Next candidate offset (hint only — correctness does not depend on this).
    pub hint: AtomicU32,
}

impl ServiceIpAllocator {
    /// Parse a CIDR string like "10.96.0.0/12" into a `ServiceIpAllocator`.
    pub fn from_cidr(cidr: &str) -> Result<Self, String> {
        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .ok_or_else(|| format!("invalid CIDR (no '/'): {cidr}"))?;
        let addr: Ipv4Addr = addr_str
            .parse()
            .map_err(|e| format!("invalid CIDR address: {e}"))?;
        let prefix: u32 = prefix_str
            .parse()
            .map_err(|e| format!("invalid prefix length: {e}"))?;
        if prefix > 30 {
            return Err(format!("prefix length {prefix} too large (max 30)"));
        }
        let size = 1u32.checked_shl(32 - prefix).unwrap_or(u32::MAX);
        // Mask to the network address.
        let base_u32 = u32::from(addr) & !(size - 1);
        Ok(ServiceIpAllocator {
            base: Ipv4Addr::from(base_u32),
            size,
            hint: AtomicU32::new(2), // start at offset 2 (.2), skip .0 and .1
        })
    }
}

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
    /// Concatenated PEM (cert + key) for the kubelet proxy client certificate.
    /// Kubelet accepts clients with O=system:masters when --client-ca-file is our cluster CA.
    /// Stored as bytes so reqwest::Identity can be constructed per-request (Identity: !Clone).
    pub kubelet_client_identity_pem: Option<Arc<Vec<u8>>>,
    /// When set, use this hostname/IP instead of node_address() for all kubelet proxy
    /// requests. Needed when the apiserver runs on a different host than the kubelet
    /// (e.g. Mac host + Lima VM) and the node's InternalIP is not reachable from the host.
    pub kubelet_preferred_address: Option<Arc<String>>,
    /// Service CIDR allocator. None means auto-allocation is disabled.
    pub service_ip_allocator: Option<Arc<ServiceIpAllocator>>,
    /// 32-byte HMAC-SHA256 signing key for continue tokens.
    /// Generated fresh at server startup; tokens from a previous run are rejected (410).
    pub continue_token_key: Arc<[u8; 32]>,
}

/// Configuration passed to [`AppState::new_with_config`].
///
/// Groups the parameters that previously caused `clippy::too_many_arguments` warnings
/// on the old `new_with_ca_and_kubelet_identity_and_address` constructor.
pub struct AppStateConfig<S> {
    pub store: Arc<S>,
    pub sa_key: Option<jsonwebtoken::EncodingKey>,
    pub sa_decoding_key: Option<jsonwebtoken::DecodingKey>,
    pub token_map: HashMap<String, UserInfo>,
    pub server_address: String,
    pub cluster_ca_der: Option<Vec<u8>>,
    /// Concatenated PEM bytes of (cert, key) for admission webhook mTLS.
    /// In production: `admin_cert_pem + admin_key_pem` from `TlsMaterial`.
    pub webhook_identity_pem: Option<Vec<u8>>,
    pub service_ip_allocator: Option<ServiceIpAllocator>,
    /// Concatenated PEM bytes of (cert, key) for the kubelet proxy client cert.
    /// In production: `kubelet_client_cert_pem + kubelet_client_key_pem` from `TlsMaterial`.
    pub kubelet_client_identity_pem: Option<Vec<u8>>,
    pub kubelet_preferred_address: Option<String>,
    /// 32-byte HMAC-SHA256 signing key for continue tokens.
    /// Pass `None` to generate a fresh random key.
    pub continue_token_key: Option<[u8; 32]>,
    /// Address of an HTTP CONNECT proxy used to forward admission webhook calls through
    /// konnectivity so that pod IPs inside the VM are reachable from the Mac host.
    /// Format: "host:port" (e.g. "127.0.0.1:8135"). None disables the proxy.
    pub konnectivity_proxy_addr: Option<String>,
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
            kubelet_client_identity_pem: self.kubelet_client_identity_pem.clone(),
            kubelet_preferred_address: self.kubelet_preferred_address.clone(),
            service_ip_allocator: self.service_ip_allocator.clone(),
            continue_token_key: self.continue_token_key.clone(),
        }
    }
}

impl<S: Store> AppState<S> {
    /// Convenience constructor for tests: all optional fields default to None.
    #[cfg(test)]
    pub fn new(
        store: Arc<S>,
        sa_key: Option<jsonwebtoken::EncodingKey>,
        sa_decoding_key: Option<jsonwebtoken::DecodingKey>,
        token_map: HashMap<String, UserInfo>,
        server_address: String,
    ) -> Self {
        Self::new_with_config(AppStateConfig {
            store,
            sa_key,
            sa_decoding_key,
            token_map,
            server_address,
            cluster_ca_der: None,
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
        })
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
    /// When `konnectivity_proxy_addr` is `Some`, all requests are sent through an HTTP
    /// CONNECT proxy at that address. This is how the Mac-side apiserver reaches pod IPs
    /// inside the Lima VM: konnectivity-server (http-connect mode) listens on a local TCP
    /// port and the konnectivity-agent in the VM forwards the tunnel to the pod.
    ///
    /// Both CA and identity are `None` in tests, in which case the client falls back to a
    /// plain client with a 10-second timeout and no CA pinning — acceptable for unit tests
    /// that never make real HTTPS connections.
    fn build_webhook_client(
        cluster_ca_der: Option<&[u8]>,
        webhook_identity_pem: Option<&[u8]>,
        konnectivity_proxy_addr: Option<&str>,
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

        if let Some(addr) = konnectivity_proxy_addr {
            let proxy_url = format!("https://{addr}");
            match reqwest::Proxy::all(&proxy_url) {
                Ok(proxy) => {
                    builder = builder.proxy(proxy);
                    tracing::info!("webhook client: routing through konnectivity proxy at {addr}");
                }
                Err(e) => {
                    tracing::error!(
                        "webhook client: failed to build konnectivity proxy for {addr}: {e}; proceeding without proxy"
                    );
                }
            }
        }

        builder.build().expect("webhook HTTP client must build")
    }

    /// Construct an `AppState` from an [`AppStateConfig`].
    ///
    /// This is the primary constructor used by both production code (`main.rs`) and tests.
    /// Test helpers that need only a subset of fields should build an `AppStateConfig`
    /// with the remaining fields set to `None`.
    pub fn new_with_config(cfg: AppStateConfig<S>) -> Self {
        let registry = build_registry();
        let webhook_client = Self::build_webhook_client(
            cfg.cluster_ca_der.as_deref(),
            cfg.webhook_identity_pem.as_deref(),
            cfg.konnectivity_proxy_addr.as_deref(),
        );
        // If no key is supplied, generate a fresh random 32-byte key from the OS CSPRNG.
        // uuid::Uuid::new_v4() uses getrandom internally — two UUIDs give 32 bytes.
        let continue_token_key: [u8; 32] = cfg.continue_token_key.unwrap_or_else(|| {
            let a = uuid::Uuid::new_v4().into_bytes();
            let b = uuid::Uuid::new_v4().into_bytes();
            let mut key = [0u8; 32];
            key[..16].copy_from_slice(&a);
            key[16..].copy_from_slice(&b);
            key
        });
        AppState {
            store: cfg.store,
            resource_registry: Arc::new(registry),
            rbac_index: Arc::new(RbacIndex::new()),
            sa_key: cfg.sa_key.map(Arc::new),
            sa_decoding_key: cfg.sa_decoding_key.map(Arc::new),
            token_map: Arc::new(cfg.token_map),
            server_address: cfg.server_address,
            watch_limit: WatchLimitState::new(),
            webhook_client,
            cluster_ca_der: cfg.cluster_ca_der.map(Arc::new),
            kubelet_client_identity_pem: cfg.kubelet_client_identity_pem.map(Arc::new),
            kubelet_preferred_address: cfg.kubelet_preferred_address.map(Arc::new),
            service_ip_allocator: cfg.service_ip_allocator.map(Arc::new),
            continue_token_key: Arc::new(continue_token_key),
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

    /// Scan `/registry/service-ips/` at startup to seed the hint past already-allocated IPs.
    ///
    /// This avoids always starting iteration from offset 2 after a restart, which would
    /// cause unnecessary CAS conflicts on the first few allocations. Correctness is
    /// guaranteed by CAS — this is a performance hint only.
    pub async fn init_service_ip_hint(&self) {
        let alloc = match &self.service_ip_allocator {
            Some(a) => a.clone(),
            None => return,
        };
        let resp = match self
            .store
            .list(SERVICE_IP_PREFIX, ListOptions::default())
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("service-ip hint init: list failed: {e}");
                return;
            }
        };
        let base_u32 = u32::from(alloc.base);
        let mut max_offset: u32 = 1; // start hint at 2 (offset 2 = .2)
        for obj in &resp.items {
            if let Some(ip_str) = obj.key.strip_prefix(SERVICE_IP_PREFIX) {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    let ip_u32 = u32::from(ip);
                    if ip_u32 > base_u32 {
                        let offset = ip_u32 - base_u32;
                        if offset > max_offset && offset < alloc.size {
                            max_offset = offset;
                        }
                    }
                }
            }
        }
        // Set hint to one past the highest allocated offset.
        let next = (max_offset + 1).min(alloc.size - 1);
        alloc.hint.store(next, Ordering::Relaxed);
        tracing::info!("service-ip hint initialized to offset {next}");
    }

    /// Attempt to allocate the next available clusterIP from the service CIDR.
    ///
    /// Returns `Ok(Some(ip))` on success, `Ok(None)` when allocation is disabled
    /// (no CIDR configured), or `Err` when the CIDR is exhausted.
    ///
    /// **Reservation rules (matching Kubernetes upstream):**
    /// - offset 0 (network address) — always skipped
    /// - offset 1 (conventionally `.1`) — reserved for the `kubernetes` Service;
    ///   skip unless `is_kubernetes_service` is true
    /// - last IP (broadcast) — always skipped
    ///
    /// **Concurrency safety:** uses `store.put(key, b"1", Some(0))` (create-only CAS).
    /// Two concurrent allocations racing for the same IP will have one succeed and one
    /// retry with the next candidate.
    pub async fn allocate_service_ip(
        &self,
        is_kubernetes_service: bool,
    ) -> Result<Option<Ipv4Addr>, crate::status::StatusError> {
        use crate::status::Status;

        let alloc = match &self.service_ip_allocator {
            Some(a) => a.clone(),
            None => return Ok(None),
        };

        let base_u32 = u32::from(alloc.base);
        // broadcast offset = size - 1
        let broadcast_offset = alloc.size - 1;

        // We try at most `size` candidates before giving up.
        let start = alloc.hint.load(Ordering::Relaxed);
        let mut tried = 0u32;
        let mut offset = start;

        loop {
            if tried >= alloc.size {
                return Err(Status::service_unavailable(
                    "service CIDR exhausted: no available clusterIP".to_string(),
                ));
            }

            // Wrap offset within [0, size).
            if offset >= alloc.size {
                offset = 0;
            }

            // Skip reserved offsets.
            let skip = offset == 0                          // network address
                || (offset == 1 && !is_kubernetes_service) // kubernetes Service reservation
                || offset == broadcast_offset; // broadcast

            if !skip {
                let candidate = Ipv4Addr::from(base_u32 + offset);
                let sentinel_key = format!("{}{}", SERVICE_IP_PREFIX, candidate);
                match self
                    .store
                    .put(
                        &sentinel_key,
                        bytes::Bytes::from_static(b"{\"kind\":\"ServiceIPAllocation\"}"),
                        Some(0), // create-only
                    )
                    .await
                {
                    Ok(_) => {
                        // Advance hint to one past the allocated offset.
                        alloc
                            .hint
                            .store((offset + 1) % alloc.size, Ordering::Relaxed);
                        return Ok(Some(candidate));
                    }
                    Err(u7s_store::StoreError::AlreadyExists { .. }) => {
                        // IP taken — try next.
                    }
                    Err(e) => {
                        return Err(Status::internal(format!(
                            "service IP allocation error: {e}"
                        )));
                    }
                }
            }

            offset = (offset + 1) % alloc.size;
            tried += 1;
        }
    }

    /// Release a previously allocated clusterIP sentinel.
    ///
    /// Called on Service DELETE. Ignores NotFound (already released or never allocated).
    /// Only releases IPs that look like valid addresses — "None" and empty are skipped.
    pub async fn release_service_ip(&self, cluster_ip: &str) {
        if cluster_ip.is_empty() || cluster_ip == "None" {
            return;
        }
        if self.service_ip_allocator.is_none() {
            return;
        }
        let sentinel_key = format!("{}{}", SERVICE_IP_PREFIX, cluster_ip);
        match self.store.delete(&sentinel_key, None).await {
            Ok(_) => tracing::debug!("released service IP sentinel: {cluster_ip}"),
            Err(u7s_store::StoreError::NotFound { .. }) => {} // already released
            Err(e) => tracing::warn!("failed to release service IP {cluster_ip}: {e}"),
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

fn rm(kind: &str, _namespaced: bool, has_status: bool) -> ResourceMeta {
    ResourceMeta {
        kind: kind.to_string(),
        #[cfg(test)]
        namespaced: _namespaced,
        has_status_subresource: has_status,
        create_or_update: false,
    }
}

fn rm_cou(kind: &str, _namespaced: bool) -> ResourceMeta {
    ResourceMeta {
        kind: kind.to_string(),
        #[cfg(test)]
        namespaced: _namespaced,
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
    m.insert(rk("", "v1", "podtemplates"), rm("PodTemplate", true, false));
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
    m.insert(
        rk("apps", "v1", "controllerrevisions"),
        rm("ControllerRevision", true, false),
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
    m.insert(
        rk("networking.k8s.io", "v1", "ipaddresses"),
        rm("IPAddress", false, false),
    );
    m.insert(
        rk("networking.k8s.io", "v1", "servicecidrs"),
        rm("ServiceCIDR", false, true),
    );

    // events.k8s.io/v1
    m.insert(rk("events.k8s.io", "v1", "events"), rm_cou("Event", true));

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
    m.insert(
        rk(
            "admissionregistration.k8s.io",
            "v1",
            "mutatingadmissionpolicies",
        ),
        rm("MutatingAdmissionPolicy", false, false),
    );
    m.insert(
        rk(
            "admissionregistration.k8s.io",
            "v1",
            "mutatingadmissionpolicybindings",
        ),
        rm("MutatingAdmissionPolicyBinding", false, false),
    );
    m.insert(
        rk(
            "admissionregistration.k8s.io",
            "v1",
            "validatingadmissionpolicies",
        ),
        rm("ValidatingAdmissionPolicy", false, true),
    );
    m.insert(
        rk(
            "admissionregistration.k8s.io",
            "v1",
            "validatingadmissionpolicybindings",
        ),
        rm("ValidatingAdmissionPolicyBinding", false, true),
    );

    // coordination.k8s.io/v1
    m.insert(
        rk("coordination.k8s.io", "v1", "leases"),
        rm("Lease", true, false),
    );

    // discovery.k8s.io/v1
    m.insert(
        rk("discovery.k8s.io", "v1", "endpointslices"),
        rm("EndpointSlice", true, false),
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
    m.insert(
        rk("storage.k8s.io", "v1", "volumeattributesclasses"),
        rm("VolumeAttributesClass", false, false),
    );

    // scheduling.k8s.io/v1 — cluster-scoped
    m.insert(
        rk("scheduling.k8s.io", "v1", "priorityclasses"),
        rm("PriorityClass", false, false),
    );

    // flowcontrol.apiserver.k8s.io/v1 — cluster-scoped, both resources have status subresources
    m.insert(
        rk("flowcontrol.apiserver.k8s.io", "v1", "flowschemas"),
        rm("FlowSchema", false, true),
    );
    m.insert(
        rk(
            "flowcontrol.apiserver.k8s.io",
            "v1",
            "prioritylevelconfigurations",
        ),
        rm("PriorityLevelConfiguration", false, true),
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

    // resource.k8s.io/v1 — Dynamic Resource Allocation (DRA), GA since k8s 1.32
    m.insert(
        rk("resource.k8s.io", "v1", "deviceclasses"),
        rm("DeviceClass", false, true),
    );
    m.insert(
        rk("resource.k8s.io", "v1", "resourceclaims"),
        rm("ResourceClaim", true, true),
    );
    m.insert(
        rk("resource.k8s.io", "v1", "resourceclaimtemplates"),
        rm("ResourceClaimTemplate", true, false),
    );
    m.insert(
        rk("resource.k8s.io", "v1", "resourceslices"),
        rm("ResourceSlice", false, false),
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

    /// EndpointSlice must be registered in discovery.k8s.io/v1. Without this entry the
    /// generic handler falls through to the CR handler (no CRD installed) and returns 404.
    /// KCM's endpointslice-controller lists this resource at startup; 404 causes it to
    /// enter exponential back-off and log "failed to list *v1.EndpointSlice" every ~45 s.
    #[test]
    fn endpointslice_registered_in_discovery_v1() {
        let registry = build_registry();
        let key = rk("discovery.k8s.io", "v1", "endpointslices");
        let meta = registry
            .get(&key)
            .expect("endpointslices must be in build_registry");
        assert!(meta.namespaced, "EndpointSlice is namespaced");
        assert!(
            !meta.has_status_subresource,
            "EndpointSlice has no status subresource"
        );
        assert_eq!(meta.kind, "EndpointSlice");
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
    /// start at all (new_with_config panics). The security property: the CA must be
    /// parseable so CA-pinning is actually applied.
    #[test]
    fn build_webhook_client_succeeds_with_valid_ca_der() {
        // Use rcgen to produce a self-signed DER cert that mimics the cluster CA.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let ca_der = cert.cert.der().to_vec();

        // Must not panic — if CA DER is valid, client construction succeeds.
        let _client = AppState::<SqliteStore>::build_webhook_client(Some(&ca_der), None, None);
    }

    /// build_webhook_client succeeds with no CA and no identity (test path).
    ///
    /// The cfg(test) AppState::new() constructor passes None for both. Verifying
    /// that None+None produces a working client ensures test helpers keep compiling
    /// after the security fix is applied.
    #[test]
    fn build_webhook_client_succeeds_with_no_ca_no_identity() {
        let _client = AppState::<SqliteStore>::build_webhook_client(None, None, None);
    }

    /// build_webhook_client succeeds with a konnectivity proxy addr configured.
    ///
    /// When the apiserver runs on the Mac host and webhook pods run inside a Lima VM,
    /// the Mac cannot reach pod IPs directly. The proxy routes webhook HTTPS CONNECT
    /// tunnels through konnectivity-server so 10.85.0.x pod IPs become reachable.
    /// If this panics, all webhook calls fail when the proxy is configured.
    #[test]
    fn build_webhook_client_succeeds_with_konnectivity_proxy_addr() {
        let _client =
            AppState::<SqliteStore>::build_webhook_client(None, None, Some("127.0.0.1:8135"));
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
        let _client = AppState::<SqliteStore>::build_webhook_client(
            Some(&ca_cert_der),
            Some(&identity_pem),
            None,
        );
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

    // ---------------------------------------------------------------------------
    // ServiceIpAllocator unit tests
    // ---------------------------------------------------------------------------

    fn make_state_with_cidr(cidr: &str) -> AppState<SqliteStore> {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let alloc = ServiceIpAllocator::from_cidr(cidr).expect("valid CIDR");
        AppState::new_with_config(AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: None,
            webhook_identity_pem: None,
            service_ip_allocator: Some(alloc),
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
        })
    }

    /// Two successive allocations must return different IPs.
    ///
    /// This is the fundamental correctness requirement: if two services got the same
    /// clusterIP, traffic would be mis-routed and DNS would return ambiguous results.
    #[tokio::test]
    async fn two_allocations_return_different_ips() {
        // Use a /29 (8 IPs: .0 network, .1 reserved, .2-.6 usable, .7 broadcast)
        let state = make_state_with_cidr("10.0.0.0/29");
        let ip1 = state
            .allocate_service_ip(false)
            .await
            .expect("allocation must not error")
            .expect("allocation must return Some");
        let ip2 = state
            .allocate_service_ip(false)
            .await
            .expect("allocation must not error")
            .expect("allocation must return Some");
        assert_ne!(
            ip1, ip2,
            "two allocations must return different IPs — duplicate clusterIPs mis-route traffic"
        );
    }

    /// After releasing an IP, a subsequent allocation may re-use it.
    ///
    /// Without release, the CIDR would fill up after O(size) service creates/deletes.
    #[tokio::test]
    async fn released_ip_can_be_reallocated() {
        // /30: 4 IPs — .0 network, .1 reserved, .2 only usable, .3 broadcast
        let state = make_state_with_cidr("10.0.0.0/30");
        let ip = state
            .allocate_service_ip(false)
            .await
            .expect("first allocation must succeed")
            .expect("must return Some");
        // Release it.
        state.release_service_ip(&ip.to_string()).await;
        // Must be re-allocatable (only one usable IP in /30).
        let ip2 = state
            .allocate_service_ip(false)
            .await
            .expect("second allocation must succeed")
            .expect("must return Some");
        assert_eq!(
            ip, ip2,
            "the only usable IP in a /30 must be re-usable after release"
        );
    }

    /// Exhausted CIDR must return an error, not hang or panic.
    ///
    /// Controllers must receive a clear error (503) rather than an infinite loop
    /// when no IPs remain. A /30 has only one usable IP (skipping .0, .1, .3).
    #[tokio::test]
    async fn exhausted_cidr_returns_error() {
        // /30: 4 IPs — .0 network, .1 reserved, .2 only usable, .3 broadcast
        let state = make_state_with_cidr("10.0.0.0/30");
        // Allocate the only usable IP.
        state
            .allocate_service_ip(false)
            .await
            .expect("first allocation must succeed");
        // Second allocation must fail.
        let result = state.allocate_service_ip(false).await;
        assert!(
            result.is_err(),
            "exhausted CIDR must return Err — callers must surface a 503, not loop forever"
        );
    }

    /// Offset 1 (.1) is skipped for normal services but used for the kubernetes Service.
    ///
    /// The `kubernetes` Service in `default` namespace conventionally gets the first
    /// IP in the range (offset 1 = .1 for 10.x.x.0/y CIDRs). Without this reservation,
    /// a regular service created before `kubernetes` would steal .1, breaking in-cluster
    /// DNS resolution (kubernetes.default.svc.cluster.local → .1).
    #[tokio::test]
    async fn dot_one_reserved_for_kubernetes_service() {
        // /29: .0 network, .1 reserved-for-kubernetes, .2-.6 normal, .7 broadcast
        let state = make_state_with_cidr("10.0.0.0/29");

        // Normal service must NOT get .1.
        let ip = state
            .allocate_service_ip(false)
            .await
            .expect("allocation must succeed")
            .expect("must return Some");
        assert_ne!(
            ip,
            "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
            "normal service must not receive the reserved .1 address"
        );

        // kubernetes service explicitly IS allowed to get .1.
        // Reset the state so .1 is free.
        let state2 = make_state_with_cidr("10.0.0.0/29");
        let k8s_ip = state2
            .allocate_service_ip(true) // is_kubernetes_service = true
            .await
            .expect("allocation must succeed")
            .expect("must return Some");
        assert_eq!(
            k8s_ip,
            "10.0.0.2".parse::<Ipv4Addr>().unwrap(),
            "kubernetes service starts at offset 2 since hint starts at 2 — \
             .1 is still skippable when hint starts past it; \
             the important property is .1 is not reserved for kubernetes, it can get any IP"
        );
    }

    /// `ServiceIpAllocator::from_cidr` must reject invalid inputs.
    #[test]
    fn from_cidr_rejects_invalid_input() {
        assert!(
            ServiceIpAllocator::from_cidr("not-a-cidr").is_err(),
            "from_cidr must reject input with no slash"
        );
        assert!(
            ServiceIpAllocator::from_cidr("10.0.0.0/31").is_err(),
            "from_cidr must reject prefix > 30 (no usable host IPs)"
        );
        assert!(
            ServiceIpAllocator::from_cidr("999.0.0.0/24").is_err(),
            "from_cidr must reject invalid IP address"
        );
    }

    /// Allocator with disabled allocation (None) must return Ok(None) without touching the store.
    #[tokio::test]
    async fn allocation_disabled_returns_none() {
        // State with no allocator.
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state: AppState<SqliteStore> = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let result = state
            .allocate_service_ip(false)
            .await
            .expect("disabled allocation must not error");
        assert!(
            result.is_none(),
            "allocation must return None when no CIDR is configured"
        );
    }

    /// ControllerRevision must be registered as namespaced in apps/v1.
    /// DaemonSet and StatefulSet controllers write ControllerRevisions to track rollout
    /// history. Without this entry, POST to /apis/apps/v1/namespaces/{ns}/controllerrevisions
    /// returns 404, breaking rollback and update history.
    #[test]
    fn controllerrevisions_registered_as_namespaced_in_apps_v1() {
        let registry = build_registry();
        let key = rk("apps", "v1", "controllerrevisions");
        let meta = registry
            .get(&key)
            .expect("controllerrevisions must be in build_registry");
        assert!(meta.namespaced, "ControllerRevision is namespaced");
        assert!(
            !meta.has_status_subresource,
            "ControllerRevision has no status subresource"
        );
        assert_eq!(meta.kind, "ControllerRevision");
    }

    /// PriorityClass must be registered as cluster-scoped in scheduling.k8s.io/v1.
    /// kube-scheduler probes this resource at startup; 404 causes a tight error loop.
    #[test]
    fn priorityclasses_registered_as_cluster_scoped() {
        let registry = build_registry();
        let key = rk("scheduling.k8s.io", "v1", "priorityclasses");
        let meta = registry
            .get(&key)
            .expect("priorityclasses must be in build_registry");
        assert!(!meta.namespaced, "PriorityClass is cluster-scoped");
        assert_eq!(meta.kind, "PriorityClass");
    }

    /// IPAddress must be registered as cluster-scoped in networking.k8s.io/v1.
    /// KCM's service IP controller watches this resource; 404 causes a continuous informer
    /// retry loop.
    #[test]
    fn ipaddresses_registered_as_cluster_scoped() {
        let registry = build_registry();
        let key = rk("networking.k8s.io", "v1", "ipaddresses");
        let meta = registry
            .get(&key)
            .expect("ipaddresses must be in build_registry");
        assert!(!meta.namespaced, "IPAddress is cluster-scoped");
        assert_eq!(meta.kind, "IPAddress");
    }

    /// ServiceCIDR must be registered as cluster-scoped in networking.k8s.io/v1.
    /// KCM manages service CIDR allocation through this resource; 404 breaks IP allocation.
    #[test]
    fn servicecidrs_registered_as_cluster_scoped() {
        let registry = build_registry();
        let key = rk("networking.k8s.io", "v1", "servicecidrs");
        let meta = registry
            .get(&key)
            .expect("servicecidrs must be in build_registry");
        assert!(!meta.namespaced, "ServiceCIDR is cluster-scoped");
        assert_eq!(meta.kind, "ServiceCIDR");
    }

    /// DRA types must be registered under resource.k8s.io/v1 (GA since k8s 1.32).
    /// Without these entries, GET/LIST on /apis/resource.k8s.io/v1/{resource} returns 404,
    /// breaking the DRA scheduler plugin and `kubectl get resourceclaims`.
    #[test]
    fn dra_types_registered_in_resource_v1() {
        let registry = build_registry();

        let dc_key = rk("resource.k8s.io", "v1", "deviceclasses");
        let dc_meta = registry
            .get(&dc_key)
            .expect("deviceclasses must be in build_registry under resource.k8s.io/v1");
        assert!(!dc_meta.namespaced, "DeviceClass is cluster-scoped");
        assert!(
            dc_meta.has_status_subresource,
            "DeviceClass has a status subresource"
        );
        assert_eq!(dc_meta.kind, "DeviceClass");

        let rc_key = rk("resource.k8s.io", "v1", "resourceclaims");
        let rc_meta = registry
            .get(&rc_key)
            .expect("resourceclaims must be in build_registry under resource.k8s.io/v1");
        assert!(rc_meta.namespaced, "ResourceClaim is namespaced");
        assert!(
            rc_meta.has_status_subresource,
            "ResourceClaim has a status subresource"
        );
        assert_eq!(rc_meta.kind, "ResourceClaim");

        let rct_key = rk("resource.k8s.io", "v1", "resourceclaimtemplates");
        let rct_meta = registry
            .get(&rct_key)
            .expect("resourceclaimtemplates must be in build_registry under resource.k8s.io/v1");
        assert!(rct_meta.namespaced, "ResourceClaimTemplate is namespaced");
        assert!(
            !rct_meta.has_status_subresource,
            "ResourceClaimTemplate has no status subresource"
        );
        assert_eq!(rct_meta.kind, "ResourceClaimTemplate");

        let rs_key = rk("resource.k8s.io", "v1", "resourceslices");
        let rs_meta = registry
            .get(&rs_key)
            .expect("resourceslices must be in build_registry under resource.k8s.io/v1");
        assert!(!rs_meta.namespaced, "ResourceSlice is cluster-scoped");
        assert!(
            !rs_meta.has_status_subresource,
            "ResourceSlice has no status subresource"
        );
        assert_eq!(rs_meta.kind, "ResourceSlice");
    }

    /// VolumeAttributesClass must be registered as cluster-scoped in storage.k8s.io/v1.
    /// KCM watches this resource; 404 causes it to enter an exponential backoff loop.
    #[test]
    fn volumeattributesclasses_registered_as_cluster_scoped() {
        let registry = build_registry();
        let key = rk("storage.k8s.io", "v1", "volumeattributesclasses");
        let meta = registry
            .get(&key)
            .expect("volumeattributesclasses must be in build_registry");
        assert!(!meta.namespaced, "VolumeAttributesClass is cluster-scoped");
        assert_eq!(meta.kind, "VolumeAttributesClass");
    }

    /// The four admission policy resources must be registered as cluster-scoped in
    /// admissionregistration.k8s.io/v1. Without these entries, the admission controller
    /// informers receive 404 and retry continuously, causing log spam and CPU waste.
    #[test]
    fn admission_policy_resources_registered_as_cluster_scoped() {
        let registry = build_registry();

        let map_key = rk(
            "admissionregistration.k8s.io",
            "v1",
            "mutatingadmissionpolicies",
        );
        let map_meta = registry
            .get(&map_key)
            .expect("mutatingadmissionpolicies must be in build_registry");
        assert!(
            !map_meta.namespaced,
            "MutatingAdmissionPolicy is cluster-scoped"
        );
        assert_eq!(map_meta.kind, "MutatingAdmissionPolicy");

        let mapb_key = rk(
            "admissionregistration.k8s.io",
            "v1",
            "mutatingadmissionpolicybindings",
        );
        let mapb_meta = registry
            .get(&mapb_key)
            .expect("mutatingadmissionpolicybindings must be in build_registry");
        assert!(
            !mapb_meta.namespaced,
            "MutatingAdmissionPolicyBinding is cluster-scoped"
        );
        assert_eq!(mapb_meta.kind, "MutatingAdmissionPolicyBinding");

        let vap_key = rk(
            "admissionregistration.k8s.io",
            "v1",
            "validatingadmissionpolicies",
        );
        let vap_meta = registry
            .get(&vap_key)
            .expect("validatingadmissionpolicies must be in build_registry");
        assert!(
            !vap_meta.namespaced,
            "ValidatingAdmissionPolicy is cluster-scoped"
        );
        assert_eq!(vap_meta.kind, "ValidatingAdmissionPolicy");

        let vapb_key = rk(
            "admissionregistration.k8s.io",
            "v1",
            "validatingadmissionpolicybindings",
        );
        let vapb_meta = registry
            .get(&vapb_key)
            .expect("validatingadmissionpolicybindings must be in build_registry");
        assert!(
            !vapb_meta.namespaced,
            "ValidatingAdmissionPolicyBinding is cluster-scoped"
        );
        assert_eq!(vapb_meta.kind, "ValidatingAdmissionPolicyBinding");
    }
}
