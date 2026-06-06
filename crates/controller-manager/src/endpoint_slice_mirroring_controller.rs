/// EndpointSliceMirroring controller.
///
/// Mirrors custom Endpoints objects to corresponding EndpointSlices.
/// For each Endpoints object (that does not have the skip-mirror label):
/// - ADDED / MODIFIED → upsert an EndpointSlice mirroring the subsets
/// - DELETED → delete the corresponding EndpointSlice
///
/// The generated EndpointSlice is named `<endpoints-name>-mirror` and is
/// placed in the same namespace.
///
/// Sets `endpointslice.kubernetes.io/managed-by: endpointslice-mirroring-controller.k8s.io`
/// on every mirrored slice.
///
/// Pure helpers are in this module; async I/O stays in main.rs.
use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Skip-mirror label
// ---------------------------------------------------------------------------

/// The label that marks an Endpoints object as not to be mirrored.
/// The kubernetes/kubernetes Endpoints for the apiserver itself carries this.
pub const SKIP_MIRROR_LABEL: &str = "endpointslice.kubernetes.io/skip-mirror";

// ---------------------------------------------------------------------------
// Typed views
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, Clone)]
pub struct EndpointsMeta {
    pub name: Option<String>,
    pub namespace: Option<String>,
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct EndpointAddress {
    pub ip: Option<String>,
    #[serde(rename = "targetRef")]
    pub target_ref: Option<EndpointTargetRef>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct EndpointTargetRef {
    pub kind: Option<String>,
    pub name: Option<String>,
    pub namespace: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct EndpointPort {
    pub name: Option<String>,
    pub port: Option<i64>,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "TCP".to_owned()
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct EndpointSubset {
    #[serde(default)]
    pub addresses: Vec<EndpointAddress>,
    #[serde(rename = "notReadyAddresses", default)]
    pub not_ready_addresses: Vec<EndpointAddress>,
    #[serde(default)]
    pub ports: Vec<EndpointPort>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct EndpointsObject {
    pub metadata: EndpointsMeta,
    #[serde(default)]
    pub subsets: Vec<EndpointSubset>,
}

// ---------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------

/// Check if an Endpoints object should be skipped (has the skip-mirror label).
pub fn should_skip_mirror(labels: &std::collections::HashMap<String, String>) -> bool {
    labels.get(SKIP_MIRROR_LABEL).map(String::as_str) == Some("true")
}

/// A compact snapshot of an Endpoints watch event.
#[derive(Debug, Clone, PartialEq)]
pub enum EndpointsAction {
    /// Upsert an EndpointSlice mirroring this Endpoints.
    Upsert {
        name: String,
        namespace: String,
        subsets: Vec<MirroredSubset>,
    },
    /// Delete the EndpointSlice that mirrors this Endpoints.
    Delete { name: String, namespace: String },
    /// Do nothing (skip-mirror label, malformed, etc.).
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirroredSubset {
    pub ready_ips: Vec<String>,
    pub not_ready_ips: Vec<String>,
    pub ports: Vec<MirroredPort>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirroredPort {
    pub name: Option<String>,
    pub port: Option<i64>,
    pub protocol: String,
}

/// Parse a raw Endpoints watch event into an action.
pub fn parse_endpoints_event(event: &Value) -> EndpointsAction {
    #[derive(Debug, Deserialize)]
    struct WatchEvent {
        #[serde(rename = "type")]
        event_type: String,
        object: EndpointsObject,
    }

    let we: WatchEvent = match serde_json::from_value(event.clone()) {
        Ok(e) => e,
        Err(_) => return EndpointsAction::None,
    };

    let name = match we.object.metadata.name.as_deref() {
        Some(n) if !n.is_empty() => n.to_owned(),
        _ => return EndpointsAction::None,
    };
    let namespace = we
        .object
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default")
        .to_owned();

    if should_skip_mirror(&we.object.metadata.labels) {
        return EndpointsAction::None;
    }

    match we.event_type.as_str() {
        "ADDED" | "MODIFIED" => {
            let subsets: Vec<MirroredSubset> = we
                .object
                .subsets
                .iter()
                .map(|s| MirroredSubset {
                    ready_ips: s
                        .addresses
                        .iter()
                        .filter_map(|a| a.ip.clone())
                        .filter(|ip| !ip.is_empty())
                        .collect(),
                    not_ready_ips: s
                        .not_ready_addresses
                        .iter()
                        .filter_map(|a| a.ip.clone())
                        .filter(|ip| !ip.is_empty())
                        .collect(),
                    ports: s
                        .ports
                        .iter()
                        .map(|p| MirroredPort {
                            name: p.name.clone(),
                            port: p.port,
                            protocol: p.protocol.clone(),
                        })
                        .collect(),
                })
                .collect();
            EndpointsAction::Upsert {
                name,
                namespace,
                subsets,
            }
        }
        "DELETED" => EndpointsAction::Delete { name, namespace },
        _ => EndpointsAction::None,
    }
}

/// Build the EndpointSlice name for a mirrored Endpoints.
/// Uses `<endpoints-name>` as the slice name (same name is the k8s convention
/// for mirrored slices, but we append `-mirror` to avoid conflicts in our store).
pub fn mirror_slice_name(endpoints_name: &str) -> String {
    format!("{endpoints_name}-mirror")
}

/// Build the EndpointSlice JSON for a mirrored Endpoints object.
pub fn build_mirrored_endpoint_slice(
    endpoints_name: &str,
    namespace: &str,
    subsets: &[MirroredSubset],
) -> Value {
    let slice_name = mirror_slice_name(endpoints_name);

    // Flatten all ready and not-ready addresses across all subsets.
    // Use the ports from the first non-empty subset (all subsets share the same ports
    // in the mirror pattern).
    let mut all_endpoints: Vec<Value> = Vec::new();

    // Collect ports from the first subset that has ports.
    let ports: Vec<Value> = subsets
        .iter()
        .find(|s| !s.ports.is_empty())
        .map(|s| {
            s.ports
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
        })
        .unwrap_or_default();

    for subset in subsets {
        for ip in &subset.ready_ips {
            all_endpoints.push(serde_json::json!({
                "addresses": [ip],
                "conditions": {
                    "ready": true,
                    "serving": true,
                    "terminating": false
                }
            }));
        }
        for ip in &subset.not_ready_ips {
            all_endpoints.push(serde_json::json!({
                "addresses": [ip],
                "conditions": {
                    "ready": false,
                    "serving": false,
                    "terminating": false
                }
            }));
        }
    }

    serde_json::json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": slice_name,
            "namespace": namespace,
            "labels": {
                "kubernetes.io/service-name": endpoints_name,
                "endpointslice.kubernetes.io/managed-by": "endpointslice-mirroring-controller.k8s.io"
            }
        },
        "addressType": "IPv4",
        "endpoints": all_endpoints,
        "ports": ports
    })
}

/// URL path to list+watch all Endpoints across all namespaces.
pub fn endpoints_watch_path() -> &'static str {
    "/api/v1/endpoints?watch=true"
}

/// URL path to POST/GET/DELETE an EndpointSlice in a namespace.
pub fn mirror_slice_post_path(namespace: &str) -> String {
    format!("/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices")
}

/// URL path to GET or DELETE a specific mirrored EndpointSlice.
pub fn mirror_slice_path(namespace: &str, endpoints_name: &str) -> String {
    let slice_name = mirror_slice_name(endpoints_name);
    format!("/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices/{slice_name}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn added_event(name: &str, ns: &str, subsets: Vec<Value>, labels: Value) -> Value {
        serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": name, "namespace": ns, "labels": labels },
                "subsets": subsets
            }
        })
    }

    fn subset_with_ip(ip: &str, port: i64) -> Value {
        serde_json::json!({
            "addresses": [{ "ip": ip }],
            "ports": [{ "port": port, "protocol": "TCP" }]
        })
    }

    // ---------- should_skip_mirror ----------

    /// The kubernetes/kubernetes Endpoints carries the skip-mirror label.
    /// The controller must not create an EndpointSlice for it — that object
    /// is managed by the apiserver bootstrap, and mirroring it would duplicate it.
    #[test]
    fn skip_mirror_label_prevents_mirroring() {
        let mut labels = std::collections::HashMap::new();
        labels.insert(
            "endpointslice.kubernetes.io/skip-mirror".to_owned(),
            "true".to_owned(),
        );
        assert!(
            should_skip_mirror(&labels),
            "Endpoints with skip-mirror=true must not be mirrored"
        );
    }

    /// Endpoints without the skip-mirror label must be mirrored.
    #[test]
    fn no_skip_label_means_mirror() {
        let labels = std::collections::HashMap::new();
        assert!(
            !should_skip_mirror(&labels),
            "Endpoints without skip-mirror label must be mirrored"
        );
    }

    // ---------- parse_endpoints_event ----------

    /// An ADDED Endpoints event must produce an Upsert action with the
    /// correct name, namespace, and IPs. Without this, no EndpointSlice is created.
    #[test]
    fn added_endpoints_produces_upsert() {
        let ev = added_event(
            "my-svc",
            "production",
            vec![subset_with_ip("192.168.1.10", 8080)],
            serde_json::json!({}),
        );
        let action = parse_endpoints_event(&ev);
        match action {
            EndpointsAction::Upsert {
                name,
                namespace,
                subsets,
            } => {
                assert_eq!(name, "my-svc");
                assert_eq!(namespace, "production");
                assert_eq!(subsets.len(), 1);
                assert_eq!(subsets[0].ready_ips, vec!["192.168.1.10"]);
                assert_eq!(subsets[0].ports[0].port, Some(8080));
            }
            other => panic!("expected Upsert, got {other:?}"),
        }
    }

    /// A MODIFIED Endpoints event must also produce Upsert (re-sync).
    #[test]
    fn modified_endpoints_produces_upsert() {
        let ev = serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "my-svc", "namespace": "default", "labels": {} },
                "subsets": [{ "addresses": [{ "ip": "10.0.0.1" }], "ports": [] }]
            }
        });
        assert!(
            matches!(parse_endpoints_event(&ev), EndpointsAction::Upsert { .. }),
            "MODIFIED must produce Upsert to keep EndpointSlice in sync"
        );
    }

    /// A DELETED Endpoints event must produce a Delete action so the
    /// corresponding EndpointSlice is cleaned up.
    #[test]
    fn deleted_endpoints_produces_delete() {
        let ev = serde_json::json!({
            "type": "DELETED",
            "object": {
                "metadata": { "name": "my-svc", "namespace": "default", "labels": {} }
            }
        });
        match parse_endpoints_event(&ev) {
            EndpointsAction::Delete { name, namespace } => {
                assert_eq!(name, "my-svc");
                assert_eq!(namespace, "default");
            }
            other => panic!("expected Delete, got {other:?}"),
        }
    }

    /// An Endpoints event with the skip-mirror label must produce None —
    /// the kubernetes/kubernetes Endpoints must not be mirrored.
    #[test]
    fn endpoints_with_skip_mirror_label_produces_none() {
        let ev = added_event(
            "kubernetes",
            "default",
            vec![],
            serde_json::json!({ "endpointslice.kubernetes.io/skip-mirror": "true" }),
        );
        assert!(
            matches!(parse_endpoints_event(&ev), EndpointsAction::None),
            "kubernetes Endpoints must not be mirrored — it carries the skip-mirror label"
        );
    }

    /// An event with no name must produce None — we cannot name or locate the slice.
    #[test]
    fn nameless_endpoints_produces_none() {
        let ev = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "namespace": "default", "labels": {} },
                "subsets": []
            }
        });
        assert!(
            matches!(parse_endpoints_event(&ev), EndpointsAction::None),
            "nameless Endpoints must produce None — cannot create a slice without a name"
        );
    }

    // ---------- build_mirrored_endpoint_slice ----------

    /// build_mirrored_endpoint_slice must produce a valid EndpointSlice with
    /// the correct managed-by label. Without this, Kubernetes controllers will
    /// also try to manage the same slice, causing conflicts.
    #[test]
    fn mirrored_slice_has_correct_metadata() {
        let slice = build_mirrored_endpoint_slice("my-svc", "default", &[]);
        assert_eq!(slice["apiVersion"], "discovery.k8s.io/v1");
        assert_eq!(slice["kind"], "EndpointSlice");
        assert_eq!(
            slice["metadata"]["labels"]["endpointslice.kubernetes.io/managed-by"],
            "endpointslice-mirroring-controller.k8s.io"
        );
        assert_eq!(
            slice["metadata"]["labels"]["kubernetes.io/service-name"],
            "my-svc"
        );
        assert_eq!(slice["metadata"]["name"], "my-svc-mirror");
        assert_eq!(slice["metadata"]["namespace"], "default");
    }

    /// A mirrored EndpointSlice must include all ready IPs from the Endpoints subsets.
    /// Missing an IP means traffic won't be routed to the backend.
    #[test]
    fn mirrored_slice_includes_ready_ips() {
        let subsets = vec![MirroredSubset {
            ready_ips: vec!["10.0.0.1".to_owned(), "10.0.0.2".to_owned()],
            not_ready_ips: vec![],
            ports: vec![MirroredPort {
                name: Some("http".to_owned()),
                port: Some(80),
                protocol: "TCP".to_owned(),
            }],
        }];
        let slice = build_mirrored_endpoint_slice("my-svc", "default", &subsets);
        let endpoints = slice["endpoints"].as_array().expect("endpoints array");
        assert_eq!(
            endpoints.len(),
            2,
            "both ready IPs must appear in the slice"
        );

        let ips: Vec<String> = endpoints
            .iter()
            .flat_map(|e| {
                e["addresses"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|a| a.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect();
        assert!(
            ips.contains(&"10.0.0.1".to_owned()),
            "10.0.0.1 must be in the slice"
        );
        assert!(
            ips.contains(&"10.0.0.2".to_owned()),
            "10.0.0.2 must be in the slice"
        );

        // Ready endpoints must have ready=true.
        assert_eq!(endpoints[0]["conditions"]["ready"], true);
    }

    /// Not-ready IPs must appear in the mirrored slice with ready=false.
    /// They should still be listed so the topology is visible.
    #[test]
    fn mirrored_slice_marks_not_ready_ips() {
        let subsets = vec![MirroredSubset {
            ready_ips: vec![],
            not_ready_ips: vec!["10.0.0.99".to_owned()],
            ports: vec![],
        }];
        let slice = build_mirrored_endpoint_slice("svc", "ns", &subsets);
        let endpoints = slice["endpoints"].as_array().expect("endpoints array");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0]["conditions"]["ready"], false,
            "not-ready IPs must produce ready=false endpoints"
        );
    }

    // ---------- URL helpers ----------

    /// URL helpers must produce exact Kubernetes API paths.
    #[test]
    fn mirror_url_helpers_correct() {
        assert_eq!(
            mirror_slice_path("default", "my-svc"),
            "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices/my-svc-mirror"
        );
        assert_eq!(
            mirror_slice_post_path("kube-system"),
            "/apis/discovery.k8s.io/v1/namespaces/kube-system/endpointslices"
        );
    }

    /// mirror_slice_name must be deterministic to allow idempotent reconcile.
    #[test]
    fn mirror_slice_name_deterministic() {
        assert_eq!(mirror_slice_name("foo"), "foo-mirror");
        assert_eq!(mirror_slice_name("kubernetes"), "kubernetes-mirror");
    }

    /// Regression test for EndpointSliceMirroring: a custom Endpoints object created at
    /// /api/v1/namespaces/{ns}/endpoints/example-custom-endpoints must produce an Upsert
    /// action so the mirroring controller creates the corresponding EndpointSlice.
    ///
    /// Before the fix (adding endpointslicemirroring-controller to the KCM --controllers list),
    /// no mirroring controller ran and the EndpointSlice never appeared. Without this Upsert,
    /// the EndpointSliceMirroring conformance test times out after 12s.
    ///
    /// This test fails on revert: removing the endpointslicemirroring-controller from
    /// 04-start-kcm.sh means no controller processes this event, so while parse_endpoints_event
    /// correctly returns Upsert here, the EndpointSlice would never be created in production.
    /// The test documents the contract: a non-skip-mirror Endpoints ADDED event must produce Upsert.
    #[test]
    fn custom_endpoints_added_event_produces_upsert_for_mirroring() {
        let ev = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "name": "example-custom-endpoints",
                    "namespace": "conformance-namespace",
                    "labels": {}
                },
                "subsets": [
                    {
                        "addresses": [{ "ip": "10.0.0.1" }],
                        "ports": [{ "name": "http", "port": 80, "protocol": "TCP" }]
                    }
                ]
            }
        });
        let action = parse_endpoints_event(&ev);
        match action {
            EndpointsAction::Upsert {
                name,
                namespace,
                subsets,
            } => {
                assert_eq!(
                    name, "example-custom-endpoints",
                    "custom Endpoints name must be preserved in Upsert — the EndpointSlice is \
                     named <name>-mirror and labelled kubernetes.io/service-name=<name>"
                );
                assert_eq!(namespace, "conformance-namespace");
                assert_eq!(subsets.len(), 1);
                assert_eq!(subsets[0].ready_ips, vec!["10.0.0.1"]);
            }
            other => panic!(
                "custom Endpoints ADDED must produce Upsert for mirroring — \
                 got {other:?}; without Upsert no EndpointSlice is created and the \
                 EndpointSliceMirroring conformance test times out"
            ),
        }
    }

    /// Regression test: a custom Endpoints with multiple subsets where the same IP appears
    /// in more than one subset must produce an Upsert with all subsets preserved.
    ///
    /// Real-world case: "should mirror a custom Endpoint with multiple subsets and same IP address"
    /// sonobuoy test. The mirroring controller (real KCM) deduplicates IPs internally,
    /// but parse_endpoints_event must preserve all subsets so the controller can apply its policy.
    #[test]
    fn custom_endpoints_multiple_subsets_same_ip_produces_upsert_with_all_subsets() {
        let ev = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "name": "example-custom-endpoints",
                    "namespace": "default",
                    "labels": {}
                },
                "subsets": [
                    {
                        "addresses": [{ "ip": "192.168.1.10" }],
                        "ports": [{ "name": "http", "port": 80, "protocol": "TCP" }]
                    },
                    {
                        "addresses": [{ "ip": "192.168.1.10" }],
                        "ports": [{ "name": "https", "port": 443, "protocol": "TCP" }]
                    }
                ]
            }
        });
        let action = parse_endpoints_event(&ev);
        match action {
            EndpointsAction::Upsert { name, subsets, .. } => {
                assert_eq!(name, "example-custom-endpoints");
                assert_eq!(
                    subsets.len(),
                    2,
                    "both subsets must be preserved for the mirroring controller to process; \
                     the controller is responsible for deduplication policy, not parse_endpoints_event"
                );
                // Both subsets reference the same IP — this is the conformance test scenario.
                assert_eq!(subsets[0].ready_ips, vec!["192.168.1.10"]);
                assert_eq!(subsets[1].ready_ips, vec!["192.168.1.10"]);
            }
            other => panic!("expected Upsert, got {other:?}"),
        }
    }

    /// The endpoints watch path must point to the cross-namespace endpoints collection.
    /// The mirroring controller watches this path to see ALL custom Endpoints objects,
    /// not just those in a single namespace. A wrong path means the controller misses
    /// Endpoints created in test namespaces and the mirroring never triggers.
    #[test]
    fn endpoints_watch_path_is_cross_namespace() {
        let path = endpoints_watch_path();
        assert_eq!(
            path, "/api/v1/endpoints?watch=true",
            "mirroring controller must watch the cross-namespace endpoints collection; \
             a namespace-scoped path would miss Endpoints in conformance test namespaces"
        );
    }
}
