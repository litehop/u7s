/// EndpointSlice controller — selector-based sync.
///
/// For each Service with a `spec.selector`, finds all Pods in the same
/// namespace whose labels match the selector, and reconciles a single
/// EndpointSlice (named `<service>-<hash>`) for that Service.
///
/// For a Service with no selector (or an empty selector map), creates an
/// empty EndpointSlice so conformance tests can observe it exists.
///
/// Sets `endpointslice.kubernetes.io/managed-by: endpointslice-controller.k8s.io`
/// on every slice it manages.
///
/// Pure helpers are in this module; async I/O stays in main.rs.
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Typed watch-event views
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ServiceMeta {
    pub name: Option<String>,
    pub namespace: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ServiceSpec {
    #[serde(default)]
    pub selector: Option<HashMap<String, String>>,
    #[serde(default)]
    pub ports: Vec<ServicePort>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ServicePort {
    pub name: Option<String>,
    pub port: Option<i64>,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "TCP".to_owned()
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ServiceObject {
    pub metadata: ServiceMeta,
    pub spec: Option<ServiceSpec>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodMeta {
    pub name: Option<String>,
    pub namespace: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(rename = "deletionTimestamp")]
    pub deletion_timestamp: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodStatus {
    #[serde(rename = "podIP")]
    pub pod_ip: Option<String>,
    pub phase: Option<String>,
    #[serde(default)]
    pub conditions: Vec<PodCondition>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodCondition {
    #[serde(rename = "type")]
    pub condition_type: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodObject {
    pub metadata: PodMeta,
    pub status: Option<PodStatus>,
}

// ---------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------

/// Determine whether a pod's labels satisfy all key/value pairs in `selector`.
/// An empty selector matches nothing (no selector = no pod selection).
pub fn pod_matches_selector(
    pod_labels: &HashMap<String, String>,
    selector: &HashMap<String, String>,
) -> bool {
    if selector.is_empty() {
        return false;
    }
    selector
        .iter()
        .all(|(k, v)| pod_labels.get(k).map(String::as_str) == Some(v.as_str()))
}

/// Determine whether a pod is "ready" to serve traffic:
/// - Has a non-empty podIP
/// - Not being deleted (no deletionTimestamp)
/// - Phase is Running (or unset, for backwards compat)
/// - Ready condition is True (if present)
pub fn pod_is_ready(pod: &PodObject) -> bool {
    if pod.metadata.deletion_timestamp.is_some() {
        return false;
    }
    let status = match &pod.status {
        Some(s) => s,
        None => return false,
    };
    if status.pod_ip.as_deref().unwrap_or("").is_empty() {
        return false;
    }
    let phase = status.phase.as_deref().unwrap_or("Running");
    if phase != "Running" && phase != "Succeeded" {
        return false;
    }
    // If there's a Ready condition, it must be True.
    for cond in &status.conditions {
        if cond.condition_type.as_deref() == Some("Ready") {
            return cond.status.as_deref() == Some("True");
        }
    }
    true
}

/// A compact snapshot of a pod for EndpointSlice construction.
#[derive(Debug, Clone, PartialEq)]
pub struct PodEndpoint {
    pub ip: String,
    pub pod_name: String,
    pub namespace: String,
    pub ready: bool,
}

/// Extract a PodEndpoint from a PodObject. Returns None if the pod has no IP.
pub fn extract_pod_endpoint(pod: &PodObject) -> Option<PodEndpoint> {
    let ip = pod
        .status
        .as_ref()
        .and_then(|s| s.pod_ip.as_deref())
        .unwrap_or("")
        .to_owned();
    if ip.is_empty() {
        return None;
    }
    let pod_name = pod.metadata.name.clone().unwrap_or_default();
    let namespace = pod.metadata.namespace.clone().unwrap_or_default();
    Some(PodEndpoint {
        ip,
        pod_name,
        namespace,
        ready: pod_is_ready(pod),
    })
}

/// A compact snapshot of a Service for EndpointSlice construction.
#[derive(Debug, Clone)]
pub struct ServiceSnapshot {
    pub name: String,
    pub namespace: String,
    pub selector: Option<HashMap<String, String>>,
    pub ports: Vec<ServicePort>,
}

/// Parse a Service object from a JSON watch event.
/// Returns None if the Service has no name.
pub fn parse_service(obj: &Value) -> Option<ServiceSnapshot> {
    let svc: ServiceObject = serde_json::from_value(obj.clone()).ok()?;
    let name = svc.metadata.name.as_deref().unwrap_or("").to_owned();
    if name.is_empty() {
        return None;
    }
    let namespace = svc
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default")
        .to_owned();
    let spec = svc.spec.unwrap_or_default();
    Some(ServiceSnapshot {
        name,
        namespace,
        selector: spec.selector,
        ports: spec.ports,
    })
}

/// Parse a Pod object from a JSON watch event.
/// Returns None if the Pod has no name.
pub fn parse_pod(obj: &Value) -> Option<PodObject> {
    let pod: PodObject = serde_json::from_value(obj.clone()).ok()?;
    let name = pod.metadata.name.as_deref().unwrap_or("").to_owned();
    if name.is_empty() {
        return None;
    }
    Some(pod)
}

/// Build the EndpointSlice name for a Service.
/// Uses `<service>-<6-char-hash>` to avoid name collisions across namespaces.
pub fn endpoint_slice_name(service_name: &str) -> String {
    // Simple deterministic suffix: first 6 chars of a djb2-style hash.
    let hash: u32 = service_name.bytes().fold(5381u32, |acc, b| {
        acc.wrapping_mul(33).wrapping_add(b as u32)
    });
    format!("{service_name}-{:06x}", hash & 0xFFFFFF)
}

/// Build the full EndpointSlice JSON object for a selector-based Service.
///
/// `endpoints` is the list of pod IPs that match the selector.
/// An empty list produces a valid but empty EndpointSlice (Service with no matching pods).
pub fn build_endpoint_slice(
    service_name: &str,
    namespace: &str,
    ports: &[ServicePort],
    endpoints: &[PodEndpoint],
) -> Value {
    let slice_name = endpoint_slice_name(service_name);

    // Build the `ports` array — each service port becomes an endpointslice port.
    let eps_ports: Vec<Value> = if ports.is_empty() {
        vec![]
    } else {
        ports
            .iter()
            .map(|p| {
                let mut port_obj = serde_json::json!({
                    "protocol": p.protocol
                });
                if let Some(port_num) = p.port {
                    port_obj["port"] = Value::Number(serde_json::Number::from(port_num));
                }
                if let Some(name) = &p.name {
                    port_obj["name"] = Value::String(name.clone());
                }
                port_obj
            })
            .collect()
    };

    // Build the `endpoints` array.
    let eps_endpoints: Vec<Value> = endpoints
        .iter()
        .map(|ep| {
            serde_json::json!({
                "addresses": [ep.ip],
                "conditions": {
                    "ready": ep.ready,
                    "serving": ep.ready,
                    "terminating": false
                },
                "targetRef": {
                    "kind": "Pod",
                    "namespace": ep.namespace,
                    "name": ep.pod_name
                }
            })
        })
        .collect();

    serde_json::json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": slice_name,
            "namespace": namespace,
            "labels": {
                "kubernetes.io/service-name": service_name,
                "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"
            }
        },
        "addressType": "IPv4",
        "endpoints": eps_endpoints,
        "ports": eps_ports
    })
}

/// URL path to POST a new EndpointSlice for a namespace.
pub fn endpoint_slices_post_path(namespace: &str) -> String {
    format!("/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices")
}

/// URL path to PUT/GET a specific EndpointSlice.
pub fn endpoint_slice_path(namespace: &str, name: &str) -> String {
    format!("/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices/{name}")
}

/// URL path to list all pods in a namespace.
pub fn pods_list_path(namespace: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/pods")
}

/// URL path to list all services in a namespace.
pub fn services_list_path(namespace: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/services")
}

/// URL path to watch services across all namespaces.
pub fn services_watch_path() -> &'static str {
    "/api/v1/services?watch=true"
}

/// URL path to watch pods across all namespaces.
pub fn pods_watch_path() -> &'static str {
    "/api/v1/pods?watch=true"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pod_with_ip(name: &str, namespace: &str, labels: &[(&str, &str)], ip: &str) -> PodObject {
        PodObject {
            metadata: PodMeta {
                name: Some(name.to_owned()),
                namespace: Some(namespace.to_owned()),
                labels: labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                deletion_timestamp: None,
            },
            status: Some(PodStatus {
                pod_ip: Some(ip.to_owned()),
                phase: Some("Running".to_owned()),
                conditions: vec![PodCondition {
                    condition_type: Some("Ready".to_owned()),
                    status: Some("True".to_owned()),
                }],
            }),
        }
    }

    fn selector(labels: &[(&str, &str)]) -> HashMap<String, String> {
        labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ---------- pod_matches_selector ----------

    /// A pod whose labels contain all selector key/value pairs must match.
    /// Without this, the EndpointSlice would always be empty, breaking Service routing.
    #[test]
    fn pod_matches_selector_when_all_labels_present() {
        let labels = selector(&[("app", "web"), ("env", "prod")]);
        let sel = selector(&[("app", "web")]);
        assert!(
            pod_matches_selector(&labels, &sel),
            "pod with superset of selector labels must match"
        );
    }

    /// A pod missing any label in the selector must NOT match.
    /// Partial match would route traffic to the wrong pod.
    #[test]
    fn pod_does_not_match_selector_when_label_missing() {
        let labels = selector(&[("app", "web")]);
        let sel = selector(&[("app", "web"), ("env", "prod")]);
        assert!(
            !pod_matches_selector(&labels, &sel),
            "pod missing required label must not match — routing to wrong pod is a hard failure"
        );
    }

    /// An empty selector must not match any pod (Services with no selector
    /// use Endpoints mirroring, not pod selection).
    #[test]
    fn empty_selector_matches_no_pod() {
        let labels = selector(&[("app", "anything")]);
        let sel = selector(&[]);
        assert!(
            !pod_matches_selector(&labels, &sel),
            "empty selector must match nothing — a no-selector Service uses EndpointSlice mirroring"
        );
    }

    // ---------- pod_is_ready ----------

    /// A Running pod with a podIP and Ready=True must be considered ready.
    /// Only ready pods should receive traffic.
    #[test]
    fn ready_running_pod_is_ready() {
        let pod = pod_with_ip("web", "default", &[("app", "web")], "10.0.0.5");
        assert!(
            pod_is_ready(&pod),
            "Running pod with Ready=True must be ready"
        );
    }

    /// A pod being deleted (deletionTimestamp set) must NOT be ready.
    /// Routing to terminating pods breaks in-flight connections.
    #[test]
    fn terminating_pod_is_not_ready() {
        let mut pod = pod_with_ip("web", "default", &[("app", "web")], "10.0.0.5");
        pod.metadata.deletion_timestamp = Some("2024-01-01T00:00:00Z".to_owned());
        assert!(
            !pod_is_ready(&pod),
            "pod with deletionTimestamp set must not be ready"
        );
    }

    /// A pod with no podIP must not be ready — no address to route to.
    #[test]
    fn pod_with_no_ip_is_not_ready() {
        let pod = PodObject {
            metadata: PodMeta {
                name: Some("web".to_owned()),
                namespace: Some("default".to_owned()),
                labels: HashMap::new(),
                deletion_timestamp: None,
            },
            status: Some(PodStatus {
                pod_ip: None,
                phase: Some("Pending".to_owned()),
                conditions: vec![],
            }),
        };
        assert!(
            !pod_is_ready(&pod),
            "pod with no IP must not be ready — nothing to route to"
        );
    }

    /// A pod in Pending phase must not be ready even if it has an IP.
    #[test]
    fn pending_pod_is_not_ready() {
        let mut pod = pod_with_ip("web", "default", &[], "10.0.0.5");
        pod.status.as_mut().unwrap().phase = Some("Pending".to_owned());
        pod.status.as_mut().unwrap().conditions.clear();
        assert!(!pod_is_ready(&pod), "Pending pod must not be ready");
    }

    // ---------- extract_pod_endpoint ----------

    /// extract_pod_endpoint must return a PodEndpoint with the pod's IP.
    /// If this fails, pod IPs are never added to EndpointSlices.
    #[test]
    fn extract_pod_endpoint_returns_ip() {
        let pod = pod_with_ip("web-0", "default", &[], "10.0.0.10");
        let ep = extract_pod_endpoint(&pod).expect("must return Some for pod with IP");
        assert_eq!(ep.ip, "10.0.0.10");
        assert_eq!(ep.pod_name, "web-0");
        assert_eq!(ep.namespace, "default");
        assert!(ep.ready, "ready pod must produce ready endpoint");
    }

    /// extract_pod_endpoint must return None for a pod with no IP.
    #[test]
    fn extract_pod_endpoint_returns_none_for_no_ip() {
        let pod = PodObject {
            metadata: PodMeta {
                name: Some("web".to_owned()),
                namespace: Some("default".to_owned()),
                labels: HashMap::new(),
                deletion_timestamp: None,
            },
            status: Some(PodStatus {
                pod_ip: None,
                phase: Some("Pending".to_owned()),
                conditions: vec![],
            }),
        };
        assert!(
            extract_pod_endpoint(&pod).is_none(),
            "pod with no IP must return None — can't route to non-existent address"
        );
    }

    // ---------- build_endpoint_slice ----------

    /// build_endpoint_slice must produce a valid EndpointSlice JSON with the
    /// correct apiVersion, kind, and managed-by label. Without the managed-by
    /// label, the Kubernetes EndpointSlice controller will fight with our controller.
    #[test]
    fn build_endpoint_slice_has_correct_metadata() {
        let slice = build_endpoint_slice("my-svc", "default", &[], &[]);
        assert_eq!(slice["apiVersion"], "discovery.k8s.io/v1");
        assert_eq!(slice["kind"], "EndpointSlice");
        assert_eq!(slice["addressType"], "IPv4");
        assert_eq!(
            slice["metadata"]["labels"]["endpointslice.kubernetes.io/managed-by"],
            "endpointslice-controller.k8s.io",
            "managed-by label is required to prevent controller conflicts"
        );
        assert_eq!(
            slice["metadata"]["labels"]["kubernetes.io/service-name"], "my-svc",
            "service-name label is required for EndpointSlice→Service association"
        );
    }

    /// build_endpoint_slice with no matching pods must produce an empty endpoints
    /// array. The slice must still exist — tests expect it even for no-match Services.
    #[test]
    fn build_endpoint_slice_empty_for_no_pods() {
        let slice = build_endpoint_slice("empty-svc", "default", &[], &[]);
        let endpoints = slice["endpoints"]
            .as_array()
            .expect("endpoints must be array");
        assert!(
            endpoints.is_empty(),
            "Service with no matching pods must produce EndpointSlice with empty endpoints"
        );
    }

    /// build_endpoint_slice with a matching pod must include the pod's IP in endpoints.
    /// Without this, traffic is never routed to the pod.
    #[test]
    fn build_endpoint_slice_includes_pod_ip() {
        let ep = PodEndpoint {
            ip: "10.0.0.5".to_owned(),
            pod_name: "web-0".to_owned(),
            namespace: "default".to_owned(),
            ready: true,
        };
        let ports = vec![ServicePort {
            name: Some("http".to_owned()),
            port: Some(80),
            protocol: "TCP".to_owned(),
        }];
        let slice = build_endpoint_slice("web-svc", "default", &ports, &[ep]);
        let endpoints = slice["endpoints"]
            .as_array()
            .expect("endpoints must be array");
        assert_eq!(
            endpoints.len(),
            1,
            "one pod must produce one endpoint entry"
        );
        let addrs = endpoints[0]["addresses"]
            .as_array()
            .expect("addresses array");
        assert!(
            addrs.iter().any(|a| a.as_str() == Some("10.0.0.5")),
            "pod IP 10.0.0.5 must appear in EndpointSlice addresses"
        );
        assert_eq!(
            endpoints[0]["conditions"]["ready"], true,
            "ready pod must produce ready=true endpoint"
        );

        // Port must be carried through.
        let eps_ports = slice["ports"].as_array().expect("ports array");
        assert_eq!(eps_ports.len(), 1);
        assert_eq!(eps_ports[0]["port"], 80);
        assert_eq!(eps_ports[0]["protocol"], "TCP");
    }

    // ---------- endpoint_slice_name ----------

    /// endpoint_slice_name must be deterministic: same input → same output.
    /// If the name is non-deterministic, the controller creates duplicate slices
    /// on every reconcile.
    #[test]
    fn endpoint_slice_name_is_deterministic() {
        let n1 = endpoint_slice_name("my-service");
        let n2 = endpoint_slice_name("my-service");
        assert_eq!(
            n1, n2,
            "slice name must be deterministic for reconcile idempotency"
        );
    }

    /// Different service names must produce different slice names to avoid collisions.
    #[test]
    fn endpoint_slice_name_differs_for_different_services() {
        let n1 = endpoint_slice_name("service-a");
        let n2 = endpoint_slice_name("service-b");
        assert_ne!(n1, n2, "different services must get different slice names");
    }

    /// The slice name must start with the service name for debuggability.
    #[test]
    fn endpoint_slice_name_prefixed_with_service_name() {
        let name = endpoint_slice_name("frontend");
        assert!(
            name.starts_with("frontend-"),
            "slice name must start with service name for traceability; got {name}"
        );
    }

    // ---------- URL helpers ----------

    /// URL helpers must produce exact Kubernetes API paths.
    /// Wrong paths silently return 404, breaking controller startup.
    #[test]
    fn url_helpers_correct() {
        assert_eq!(
            endpoint_slices_post_path("default"),
            "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices"
        );
        assert_eq!(
            endpoint_slice_path("default", "web-abc123"),
            "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices/web-abc123"
        );
        assert_eq!(
            pods_list_path("kube-system"),
            "/api/v1/namespaces/kube-system/pods"
        );
    }

    // ---------- parse_service ----------

    /// parse_service must extract the service name, namespace, selector and ports.
    #[test]
    fn parse_service_extracts_fields() {
        let obj = serde_json::json!({
            "metadata": { "name": "my-svc", "namespace": "production" },
            "spec": {
                "selector": { "app": "web" },
                "ports": [{ "name": "http", "port": 80, "protocol": "TCP" }]
            }
        });
        let svc = parse_service(&obj).expect("must parse valid service");
        assert_eq!(svc.name, "my-svc");
        assert_eq!(svc.namespace, "production");
        assert_eq!(
            svc.selector
                .as_ref()
                .unwrap()
                .get("app")
                .map(String::as_str),
            Some("web")
        );
        assert_eq!(svc.ports.len(), 1);
        assert_eq!(svc.ports[0].port, Some(80));
    }

    /// parse_service must return None for a service with no name.
    #[test]
    fn parse_service_returns_none_for_nameless_service() {
        let obj = serde_json::json!({
            "metadata": { "namespace": "default" },
            "spec": {}
        });
        assert!(parse_service(&obj).is_none());
    }
}
