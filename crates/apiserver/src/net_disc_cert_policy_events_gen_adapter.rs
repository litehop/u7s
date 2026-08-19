use prost::Message;

use u7s_proto_generated::k8s::io::api::certificates::v1 as certs_v1;
use u7s_proto_generated::k8s::io::api::discovery::v1 as discovery_v1;
use u7s_proto_generated::k8s::io::api::events::v1 as events_v1;
use u7s_proto_generated::k8s::io::api::networking::v1 as networking_v1;
use u7s_proto_generated::k8s::io::api::policy::v1 as policy_v1;
use u7s_proto_generated::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    crate::core_gen_adapter::gen_object_meta_to_json(meta)
}

fn gen_label_selector_to_json(sel: meta_v1::LabelSelector) -> serde_json::Value {
    crate::core_gen_adapter::gen_label_selector_to_json(sel)
}

fn gen_int_or_string_to_json(
    ios: &u7s_proto_generated::k8s::io::apimachinery::pkg::util::intstr::IntOrString,
) -> serde_json::Value {
    crate::core_gen_adapter::gen_int_or_string_to_json(ios)
}

fn gen_object_reference_to_json(
    r: u7s_proto_generated::k8s::io::api::core::v1::ObjectReference,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
        m.insert("kind".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.namespace.filter(|s| !s.is_empty()) {
        m.insert("namespace".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.uid.filter(|s| !s.is_empty()) {
        m.insert("uid".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.api_version.filter(|s| !s.is_empty()) {
        m.insert("apiVersion".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.resource_version.filter(|s| !s.is_empty()) {
        m.insert("resourceVersion".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.field_path.filter(|s| !s.is_empty()) {
        m.insert("fieldPath".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

// ---- Decoder A: Ingress (networking.k8s.io/v1) --------------------------------

fn gen_ingress_backend_to_json(b: networking_v1::IngressBackend) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    if let Some(svc) = b.service {
        let mut svc_json = serde_json::Map::new();
        if let Some(n) = svc.name.filter(|s| !s.is_empty()) {
            svc_json.insert("name".to_string(), serde_json::Value::String(n));
        }
        if let Some(p) = svc.port {
            let mut port_json = serde_json::Map::new();
            if let Some(n) = p.name.filter(|s| !s.is_empty()) {
                port_json.insert("name".to_string(), serde_json::Value::String(n));
            }
            if let Some(num) = p.number.filter(|&v| v != 0) {
                port_json.insert("number".to_string(), serde_json::Value::Number(num.into()));
            }
            svc_json.insert("port".to_string(), serde_json::Value::Object(port_json));
        }
        out.insert("service".to_string(), serde_json::Value::Object(svc_json));
    }
    // resource is the mutually-exclusive alternative to service (routes to a non-Service
    // Kubernetes resource, e.g. a custom-resource-backed backend); dropping it silently
    // turned every such Ingress rule/defaultBackend into one with no backend at all.
    if let Some(r) = b.resource {
        let mut rj = serde_json::Map::new();
        if let Some(v) = r.api_group.filter(|s| !s.is_empty()) {
            rj.insert("apiGroup".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
            rj.insert("kind".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = r.name.filter(|s| !s.is_empty()) {
            rj.insert("name".to_string(), serde_json::Value::String(v));
        }
        out.insert("resource".to_string(), serde_json::Value::Object(rj));
    }
    serde_json::Value::Object(out)
}

pub fn decode_ingress_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = networking_v1::Ingress::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::Map::new();
        if let Some(cn) = spec.ingress_class_name.filter(|s| !s.is_empty()) {
            spec_json.insert(
                "ingressClassName".to_string(),
                serde_json::Value::String(cn),
            );
        }
        if let Some(db) = spec.default_backend {
            spec_json.insert(
                "defaultBackend".to_string(),
                gen_ingress_backend_to_json(db),
            );
        }
        if !spec.tls.is_empty() {
            let tls_arr: Vec<serde_json::Value> = spec
                .tls
                .into_iter()
                .map(|t| {
                    let mut tj = serde_json::Map::new();
                    if !t.hosts.is_empty() {
                        tj.insert(
                            "hosts".to_string(),
                            serde_json::Value::Array(
                                t.hosts.into_iter().map(serde_json::Value::String).collect(),
                            ),
                        );
                    }
                    if let Some(sn) = t.secret_name.filter(|s| !s.is_empty()) {
                        tj.insert("secretName".to_string(), serde_json::Value::String(sn));
                    }
                    serde_json::Value::Object(tj)
                })
                .collect();
            spec_json.insert("tls".to_string(), serde_json::Value::Array(tls_arr));
        }
        if !spec.rules.is_empty() {
            let rules_arr: Vec<serde_json::Value> = spec
                .rules
                .into_iter()
                .map(|r| {
                    let mut rj = serde_json::Map::new();
                    if let Some(h) = r.host.filter(|s| !s.is_empty()) {
                        rj.insert("host".to_string(), serde_json::Value::String(h));
                    }
                    if let Some(irv) = r.ingress_rule_value {
                        if let Some(http) = irv.http {
                            let paths_arr: Vec<serde_json::Value> = http
                                .paths
                                .into_iter()
                                .map(|p| {
                                    let mut pj = serde_json::Map::new();
                                    if let Some(path) = p.path.filter(|s| !s.is_empty()) {
                                        pj.insert(
                                            "path".to_string(),
                                            serde_json::Value::String(path),
                                        );
                                    }
                                    if let Some(pt) = p.path_type.filter(|s| !s.is_empty()) {
                                        pj.insert(
                                            "pathType".to_string(),
                                            serde_json::Value::String(pt),
                                        );
                                    }
                                    if let Some(b) = p.backend {
                                        pj.insert(
                                            "backend".to_string(),
                                            gen_ingress_backend_to_json(b),
                                        );
                                    }
                                    serde_json::Value::Object(pj)
                                })
                                .collect();
                            rj.insert(
                                "http".to_string(),
                                serde_json::json!({ "paths": paths_arr }),
                            );
                        }
                    }
                    serde_json::Value::Object(rj)
                })
                .collect();
            spec_json.insert("rules".to_string(), serde_json::Value::Array(rules_arr));
        }
        if !spec_json.is_empty() {
            out["spec"] = serde_json::Value::Object(spec_json);
        }
    }
    if let Some(status) = obj.status {
        if let Some(lb) = status.load_balancer {
            if !lb.ingress.is_empty() {
                let ingress: Vec<serde_json::Value> = lb
                    .ingress
                    .into_iter()
                    .map(|i| {
                        let mut im = serde_json::Map::new();
                        if let Some(v) = i.ip.filter(|s| !s.is_empty()) {
                            im.insert("ip".to_string(), serde_json::Value::String(v));
                        }
                        if let Some(v) = i.hostname.filter(|s| !s.is_empty()) {
                            im.insert("hostname".to_string(), serde_json::Value::String(v));
                        }
                        if !i.ports.is_empty() {
                            let ports: Vec<serde_json::Value> = i
                                .ports
                                .into_iter()
                                .map(|p| {
                                    let mut pm = serde_json::Map::new();
                                    if let Some(v) = p.port.filter(|&n| n != 0) {
                                        pm.insert(
                                            "port".to_string(),
                                            serde_json::Value::Number(v.into()),
                                        );
                                    }
                                    if let Some(v) = p.protocol.filter(|s| !s.is_empty()) {
                                        pm.insert(
                                            "protocol".to_string(),
                                            serde_json::Value::String(v),
                                        );
                                    }
                                    if let Some(v) = p.error.filter(|s| !s.is_empty()) {
                                        pm.insert(
                                            "error".to_string(),
                                            serde_json::Value::String(v),
                                        );
                                    }
                                    serde_json::Value::Object(pm)
                                })
                                .collect();
                            im.insert("ports".to_string(), serde_json::Value::Array(ports));
                        }
                        serde_json::Value::Object(im)
                    })
                    .collect();
                out["status"] = serde_json::json!({ "loadBalancer": { "ingress": ingress } });
            }
        }
    }
    Some(out)
}

// ---- Decoder A: IngressClass (networking.k8s.io/v1) ---------------------------

pub fn decode_ingressclass_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = networking_v1::IngressClass::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "IngressClass",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::Map::new();
        if let Some(ctrl) = spec.controller.filter(|s| !s.is_empty()) {
            spec_json.insert("controller".to_string(), serde_json::Value::String(ctrl));
        }
        // parameters links this class to controller-specific config (e.g. an AWS ALB
        // IngressClassParams CRD); dropping it silently strips that config from every
        // Ingress routed through this class.
        if let Some(p) = spec.parameters {
            let mut pj = serde_json::Map::new();
            if let Some(v) = p.a_pi_group.filter(|s| !s.is_empty()) {
                pj.insert("apiGroup".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = p.kind.filter(|s| !s.is_empty()) {
                pj.insert("kind".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = p.name.filter(|s| !s.is_empty()) {
                pj.insert("name".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = p.scope.filter(|s| !s.is_empty()) {
                pj.insert("scope".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = p.namespace.filter(|s| !s.is_empty()) {
                pj.insert("namespace".to_string(), serde_json::Value::String(v));
            }
            spec_json.insert("parameters".to_string(), serde_json::Value::Object(pj));
        }
        if !spec_json.is_empty() {
            out["spec"] = serde_json::Value::Object(spec_json);
        }
    }
    Some(out)
}

// ---- Decoder A: NetworkPolicy (networking.k8s.io/v1) --------------------------
//
// Without a dispatch arm + decoder for this kind, a client-go networking/v1 typed clientset
// Create()/Update() of a NetworkPolicy (default content-type protobuf) hits extract_body's
// undecodable fallback and the generic create handler gets raw protobuf bytes it can't
// JSON-parse — every such request fails outright instead of just dropping fields.

fn gen_network_policy_port_to_json(p: networking_v1::NetworkPolicyPort) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = p.protocol.filter(|s| !s.is_empty()) {
        m.insert("protocol".to_string(), serde_json::Value::String(v));
    }
    if let Some(port) = p.port {
        m.insert("port".to_string(), gen_int_or_string_to_json(&port));
    }
    if let Some(v) = p.end_port.filter(|&n| n != 0) {
        m.insert("endPort".to_string(), serde_json::Value::Number(v.into()));
    }
    serde_json::Value::Object(m)
}

fn gen_ip_block_to_json(b: networking_v1::IpBlock) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = b.cidr.filter(|s| !s.is_empty()) {
        m.insert("cidr".to_string(), serde_json::Value::String(v));
    }
    if !b.except.is_empty() {
        m.insert(
            "except".to_string(),
            serde_json::Value::Array(
                b.except
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_network_policy_peer_to_json(p: networking_v1::NetworkPolicyPeer) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(sel) = p.pod_selector {
        m.insert("podSelector".to_string(), gen_label_selector_to_json(sel));
    }
    if let Some(sel) = p.namespace_selector {
        m.insert(
            "namespaceSelector".to_string(),
            gen_label_selector_to_json(sel),
        );
    }
    // ipBlock is mutually exclusive with the two selectors above; dropping it would silently
    // turn an IP-CIDR-scoped rule into one that matches nothing (no selector matches either).
    if let Some(b) = p.ip_block {
        m.insert("ipBlock".to_string(), gen_ip_block_to_json(b));
    }
    serde_json::Value::Object(m)
}

pub fn decode_networkpolicy_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = networking_v1::NetworkPolicy::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::Map::new();
        if let Some(sel) = spec.pod_selector {
            spec_json.insert("podSelector".to_string(), gen_label_selector_to_json(sel));
        }
        if !spec.ingress.is_empty() {
            let rules: Vec<serde_json::Value> = spec
                .ingress
                .into_iter()
                .map(|r| {
                    let mut rj = serde_json::Map::new();
                    if !r.ports.is_empty() {
                        rj.insert(
                            "ports".to_string(),
                            serde_json::Value::Array(
                                r.ports
                                    .into_iter()
                                    .map(gen_network_policy_port_to_json)
                                    .collect(),
                            ),
                        );
                    }
                    if !r.from.is_empty() {
                        rj.insert(
                            "from".to_string(),
                            serde_json::Value::Array(
                                r.from
                                    .into_iter()
                                    .map(gen_network_policy_peer_to_json)
                                    .collect(),
                            ),
                        );
                    }
                    serde_json::Value::Object(rj)
                })
                .collect();
            spec_json.insert("ingress".to_string(), serde_json::Value::Array(rules));
        }
        if !spec.egress.is_empty() {
            let rules: Vec<serde_json::Value> = spec
                .egress
                .into_iter()
                .map(|r| {
                    let mut rj = serde_json::Map::new();
                    if !r.ports.is_empty() {
                        rj.insert(
                            "ports".to_string(),
                            serde_json::Value::Array(
                                r.ports
                                    .into_iter()
                                    .map(gen_network_policy_port_to_json)
                                    .collect(),
                            ),
                        );
                    }
                    if !r.to.is_empty() {
                        rj.insert(
                            "to".to_string(),
                            serde_json::Value::Array(
                                r.to.into_iter()
                                    .map(gen_network_policy_peer_to_json)
                                    .collect(),
                            ),
                        );
                    }
                    serde_json::Value::Object(rj)
                })
                .collect();
            spec_json.insert("egress".to_string(), serde_json::Value::Array(rules));
        }
        if !spec.policy_types.is_empty() {
            spec_json.insert(
                "policyTypes".to_string(),
                serde_json::Value::Array(
                    spec.policy_types
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if !spec_json.is_empty() {
            out["spec"] = serde_json::Value::Object(spec_json);
        }
    }
    Some(out)
}

// ---- Decoder A: IPAddress (networking.k8s.io/v1) -----------------------------
//
// Without a dispatch arm + decoder for this kind, extract_body cannot decode a
// protobuf-encoded IPAddress body, falls through to raw bytes, and serde_json fails with
// "invalid JSON: expected value at line 1 column 1" — every typed-client Create() returns
// 400 instead of 201. client-go's typed clientsets (and the e2e suite) POST protobuf by
// default, so this is a hard failure for every IPAddress/ServiceCIDR API operation.

pub fn decode_ipaddress_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = networking_v1::IpAddress::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "IPAddress",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        if let Some(pr) = spec.parent_ref {
            let mut pr_json = serde_json::Map::new();
            if let Some(v) = pr.group.filter(|s| !s.is_empty()) {
                pr_json.insert("group".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = pr.resource.filter(|s| !s.is_empty()) {
                pr_json.insert("resource".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = pr.namespace.filter(|s| !s.is_empty()) {
                pr_json.insert("namespace".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = pr.name.filter(|s| !s.is_empty()) {
                pr_json.insert("name".to_string(), serde_json::Value::String(v));
            }
            out["spec"] = serde_json::json!({ "parentRef": serde_json::Value::Object(pr_json) });
        }
    }
    Some(out)
}

// ---- Decoder A: ServiceCIDR (networking.k8s.io/v1) ---------------------------

pub fn decode_servicecidr_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = networking_v1::ServiceCidr::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "ServiceCIDR",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        if !spec.cidrs.is_empty() {
            out["spec"] = serde_json::json!({
                "cidrs": spec.cidrs,
            });
        }
    }
    if let Some(status) = obj.status {
        if !status.conditions.is_empty() {
            let conditions: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(|c| {
                    let mut cm = serde_json::json!({
                        "type": c.r#type.unwrap_or_default(),
                        "status": c.status.unwrap_or_default(),
                    });
                    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                        cm["reason"] = v.into();
                    }
                    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                        cm["message"] = v.into();
                    }
                    if let Some(t) = c.last_transition_time {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            cm["lastTransitionTime"] =
                                serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                        }
                    }
                    cm
                })
                .collect();
            out["status"] = serde_json::json!({ "conditions": conditions });
        }
    }
    Some(out)
}

// ---- Decoder A: EndpointSlice (discovery.k8s.io/v1) --------------------------

pub fn decode_endpointslice_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = discovery_v1::EndpointSlice::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": meta,
        "addressType": obj.address_type.unwrap_or_default()
    });
    let endpoints_arr: Vec<serde_json::Value> = obj
        .endpoints
        .into_iter()
        .map(|ep| {
            let mut ej = serde_json::Map::new();
            ej.insert(
                "addresses".to_string(),
                serde_json::Value::Array(
                    ep.addresses
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
            if let Some(c) = ep.conditions {
                let mut cj = serde_json::Map::new();
                if let Some(v) = c.ready {
                    cj.insert("ready".to_string(), serde_json::Value::Bool(v));
                }
                if let Some(v) = c.serving {
                    cj.insert("serving".to_string(), serde_json::Value::Bool(v));
                }
                if let Some(v) = c.terminating {
                    cj.insert("terminating".to_string(), serde_json::Value::Bool(v));
                }
                if !cj.is_empty() {
                    ej.insert("conditions".to_string(), serde_json::Value::Object(cj));
                }
            }
            if let Some(h) = ep.hostname.filter(|s| !s.is_empty()) {
                ej.insert("hostname".to_string(), serde_json::Value::String(h));
            }
            if let Some(r) = ep.target_ref {
                let rj = gen_object_reference_to_json(r);
                if rj.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
                    ej.insert("targetRef".to_string(), rj);
                }
            }
            if let Some(nn) = ep.node_name.filter(|s| !s.is_empty()) {
                ej.insert("nodeName".to_string(), serde_json::Value::String(nn));
            }
            if let Some(z) = ep.zone.filter(|s| !s.is_empty()) {
                ej.insert("zone".to_string(), serde_json::Value::String(z));
            }
            if let Some(hints) = ep.hints {
                let mut hj = serde_json::Map::new();
                if !hints.for_zones.is_empty() {
                    let fz: Vec<serde_json::Value> = hints
                        .for_zones
                        .into_iter()
                        .filter_map(|fz| {
                            fz.name
                                .filter(|s| !s.is_empty())
                                .map(|n| serde_json::json!({ "name": n }))
                        })
                        .collect();
                    if !fz.is_empty() {
                        hj.insert("forZones".to_string(), serde_json::Value::Array(fz));
                    }
                }
                // forNodes is forZones' node-local counterpart for topology-aware routing;
                // dropping it silently discarded the hint kube-proxy uses to prefer
                // same-node endpoints.
                if !hints.for_nodes.is_empty() {
                    let fnodes: Vec<serde_json::Value> = hints
                        .for_nodes
                        .into_iter()
                        .filter_map(|n| {
                            n.name
                                .filter(|s| !s.is_empty())
                                .map(|n| serde_json::json!({ "name": n }))
                        })
                        .collect();
                    if !fnodes.is_empty() {
                        hj.insert("forNodes".to_string(), serde_json::Value::Array(fnodes));
                    }
                }
                if !hj.is_empty() {
                    ej.insert("hints".to_string(), serde_json::Value::Object(hj));
                }
            }
            serde_json::Value::Object(ej)
        })
        .collect();
    out["endpoints"] = serde_json::Value::Array(endpoints_arr);
    let ports_arr: Vec<serde_json::Value> = obj
        .ports
        .into_iter()
        .map(|p| {
            let mut pj = serde_json::Map::new();
            // EndpointPort.name is proto3 `optional string`: Some("") is the valid, common
            // "unnamed port" wire shape every single-port Service produces (KCM marshals
            // `Name: &""`, a non-nil pointer to an empty string). Filtering out the empty
            // string here — as most other fields in this file correctly do for fields where
            // empty and absent really are equivalent — collapses that into a missing "name"
            // key, which kube-proxy's endpointslicecache.go treats as `nil` and skips the
            // port entirely (zero backends registered, Connection refused). Emit the key
            // whenever the field is present, regardless of emptiness.
            if let Some(n) = p.name {
                pj.insert("name".to_string(), serde_json::Value::String(n));
            }
            if let Some(proto) = p.protocol.filter(|s| !s.is_empty()) {
                pj.insert("protocol".to_string(), serde_json::Value::String(proto));
            }
            if let Some(port_num) = p.port {
                pj.insert(
                    "port".to_string(),
                    serde_json::Value::Number(port_num.into()),
                );
            }
            if let Some(ap) = p.app_protocol.filter(|s| !s.is_empty()) {
                pj.insert("appProtocol".to_string(), serde_json::Value::String(ap));
            }
            serde_json::Value::Object(pj)
        })
        .collect();
    out["ports"] = serde_json::Value::Array(ports_arr);
    Some(out)
}

// ---- Decoder A: CertificateSigningRequest (certificates.k8s.io/v1) -----------

pub fn decode_csr_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = certs_v1::CertificateSigningRequest::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::Map::new();
        if let Some(req) = spec.request.filter(|v| !v.is_empty()) {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&req);
            spec_json.insert("request".to_string(), serde_json::Value::String(b64));
        }
        if let Some(sn) = spec.signer_name.filter(|s| !s.is_empty()) {
            spec_json.insert("signerName".to_string(), serde_json::Value::String(sn));
        }
        if let Some(exp) = spec.expiration_seconds.filter(|&v| v != 0) {
            spec_json.insert(
                "expirationSeconds".to_string(),
                serde_json::Value::Number(exp.into()),
            );
        }
        if !spec.usages.is_empty() {
            spec_json.insert(
                "usages".to_string(),
                serde_json::Value::Array(
                    spec.usages
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if let Some(u) = spec.username.filter(|s| !s.is_empty()) {
            spec_json.insert("username".to_string(), serde_json::Value::String(u));
        }
        if let Some(uid) = spec.uid.filter(|s| !s.is_empty()) {
            spec_json.insert("uid".to_string(), serde_json::Value::String(uid));
        }
        if !spec.groups.is_empty() {
            spec_json.insert(
                "groups".to_string(),
                serde_json::Value::Array(
                    spec.groups
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        // extra carries authenticator-supplied attributes about the CSR's creator (e.g.
        // impersonation extras); dropping it silently strips that context from the request a
        // signer or approval webhook may key its decision on.
        if !spec.extra.is_empty() {
            let extra: serde_json::Map<String, serde_json::Value> = spec
                .extra
                .into_iter()
                .map(|(k, v)| {
                    let items: Vec<serde_json::Value> =
                        v.items.into_iter().map(serde_json::Value::String).collect();
                    (k, serde_json::Value::Array(items))
                })
                .collect();
            spec_json.insert("extra".to_string(), serde_json::Value::Object(extra));
        }
        if !spec_json.is_empty() {
            out["spec"] = serde_json::Value::Object(spec_json);
        }
    }
    // status must be decoded too: kubectl certificate approve/deny and the sig-auth
    // "CSR API operations" conformance test PUT/PATCH the /approval and /status
    // subresources using the protobuf content-type. Dropping status here silently
    // discarded every condition and certificate written via those subresources.
    if let Some(status) = obj.status {
        let mut status_json = serde_json::Map::new();
        if !status.conditions.is_empty() {
            let conditions: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(|c| {
                    let mut cm = serde_json::json!({
                        "type": c.r#type.unwrap_or_default(),
                        "status": c.status.unwrap_or_default(),
                    });
                    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                        cm["reason"] = v.into();
                    }
                    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                        cm["message"] = v.into();
                    }
                    if let Some(t) = c.last_update_time {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            cm["lastUpdateTime"] =
                                serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                        }
                    }
                    if let Some(t) = c.last_transition_time {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            cm["lastTransitionTime"] =
                                serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                        }
                    }
                    cm
                })
                .collect();
            status_json.insert(
                "conditions".to_string(),
                serde_json::Value::Array(conditions),
            );
        }
        if let Some(cert) = status.certificate.filter(|c| !c.is_empty()) {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&cert);
            status_json.insert("certificate".to_string(), serde_json::Value::String(b64));
        }
        if !status_json.is_empty() {
            out["status"] = serde_json::Value::Object(status_json);
        }
    }
    Some(out)
}

// ---- Decoder A: PodDisruptionBudget (policy/v1) --------------------------------

pub fn decode_poddisruptionbudget_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = policy_v1::PodDisruptionBudget::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::Map::new();
        if let Some(min_avail) = spec.min_available {
            spec_json.insert(
                "minAvailable".to_string(),
                gen_int_or_string_to_json(&min_avail),
            );
        }
        if let Some(sel) = spec.selector {
            spec_json.insert("selector".to_string(), gen_label_selector_to_json(sel));
        }
        if let Some(max_unavail) = spec.max_unavailable {
            spec_json.insert(
                "maxUnavailable".to_string(),
                gen_int_or_string_to_json(&max_unavail),
            );
        }
        if let Some(policy) = spec.unhealthy_pod_eviction_policy.filter(|s| !s.is_empty()) {
            spec_json.insert(
                "unhealthyPodEvictionPolicy".to_string(),
                serde_json::Value::String(policy),
            );
        }
        result["spec"] = serde_json::Value::Object(spec_json);
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::Map::new();
        if let Some(og) = status.observed_generation.filter(|&v| v != 0) {
            status_json.insert(
                "observedGeneration".to_string(),
                serde_json::Value::Number(og.into()),
            );
        }
        if !status.disrupted_pods.is_empty() {
            let pods_map: serde_json::Map<String, serde_json::Value> = status
                .disrupted_pods
                .into_iter()
                .map(|(pod_name, t)| {
                    let secs = t.seconds.unwrap_or(0);
                    let ts = if secs > 0 {
                        serde_json::Value::String(crate::util::secs_to_rfc3339(secs))
                    } else {
                        serde_json::Value::String("1970-01-01T00:00:00Z".into())
                    };
                    (pod_name, ts)
                })
                .collect();
            status_json.insert(
                "disruptedPods".to_string(),
                serde_json::Value::Object(pods_map),
            );
        }
        status_json.insert(
            "disruptionsAllowed".to_string(),
            serde_json::Value::Number(status.disruptions_allowed.unwrap_or(0).into()),
        );
        status_json.insert(
            "currentHealthy".to_string(),
            serde_json::Value::Number(status.current_healthy.unwrap_or(0).into()),
        );
        status_json.insert(
            "desiredHealthy".to_string(),
            serde_json::Value::Number(status.desired_healthy.unwrap_or(0).into()),
        );
        status_json.insert(
            "expectedPods".to_string(),
            serde_json::Value::Number(status.expected_pods.unwrap_or(0).into()),
        );
        if !status.conditions.is_empty() {
            let conds: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(|c| {
                    let mut cond = serde_json::Map::new();
                    if let Some(t) = c.r#type.filter(|s| !s.is_empty()) {
                        cond.insert("type".to_string(), serde_json::Value::String(t));
                    }
                    if let Some(s) = c.status.filter(|s| !s.is_empty()) {
                        cond.insert("status".to_string(), serde_json::Value::String(s));
                    }
                    if let Some(og) = c.observed_generation.filter(|&v| v != 0) {
                        cond.insert(
                            "observedGeneration".to_string(),
                            serde_json::Value::Number(og.into()),
                        );
                    }
                    if let Some(ts) = c.last_transition_time {
                        if let Some(secs) = ts.seconds.filter(|&s| s > 0) {
                            cond.insert(
                                "lastTransitionTime".to_string(),
                                serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
                            );
                        }
                    }
                    if let Some(r) = c.reason.filter(|s| !s.is_empty()) {
                        cond.insert("reason".to_string(), serde_json::Value::String(r));
                    }
                    if let Some(msg) = c.message.filter(|s| !s.is_empty()) {
                        cond.insert("message".to_string(), serde_json::Value::String(msg));
                    }
                    serde_json::Value::Object(cond)
                })
                .collect();
            status_json.insert("conditions".to_string(), serde_json::Value::Array(conds));
        }
        result["status"] = serde_json::Value::Object(status_json);
    }
    Some(result)
}

// ---- Decoder A: events.k8s.io/v1 Event ----------------------------------------

pub fn decode_events_v1_event_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let ev = events_v1::Event::decode(data).ok()?;
    let meta = gen_object_meta_to_json(ev.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "events.k8s.io/v1",
        "kind": "Event",
        "metadata": meta
    });
    if let Some(t) = ev.event_time {
        // `seconds` must be explicitly present (not defaulted via unwrap_or(0)) — a MicroTime
        // message with no seconds field on the wire is "not set", not the Unix epoch.
        if let Some(secs) = t.seconds {
            let ts = crate::core_gen_adapter::gen_microtime_fields_to_rfc3339(
                secs,
                t.nanos.unwrap_or(0),
            );
            out["eventTime"] = serde_json::Value::String(ts);
        }
    }
    if let Some(s) = ev.series {
        let mut sj = serde_json::Map::new();
        if let Some(count) = s.count.filter(|&v| v != 0) {
            sj.insert("count".to_string(), serde_json::Value::Number(count.into()));
        }
        if let Some(t) = s.last_observed_time {
            if let Some(secs) = t.seconds {
                let ts = crate::core_gen_adapter::gen_microtime_fields_to_rfc3339(
                    secs,
                    t.nanos.unwrap_or(0),
                );
                sj.insert(
                    "lastObservedTime".to_string(),
                    serde_json::Value::String(ts),
                );
            }
        }
        if !sj.is_empty() {
            out["series"] = serde_json::Value::Object(sj);
        }
    }
    if let Some(rc) = ev.reporting_controller.filter(|s| !s.is_empty()) {
        out["reportingController"] = serde_json::Value::String(rc);
    }
    if let Some(ri) = ev.reporting_instance.filter(|s| !s.is_empty()) {
        out["reportingInstance"] = serde_json::Value::String(ri);
    }
    if let Some(a) = ev.action.filter(|s| !s.is_empty()) {
        out["action"] = serde_json::Value::String(a);
    }
    if let Some(r) = ev.reason.filter(|s| !s.is_empty()) {
        out["reason"] = serde_json::Value::String(r);
    }
    if let Some(r) = ev.regarding {
        let rj = gen_object_reference_to_json(r);
        if rj.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
            out["regarding"] = rj;
        }
    }
    if let Some(r) = ev.related {
        let rj = gen_object_reference_to_json(r);
        if rj.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
            out["related"] = rj;
        }
    }
    if let Some(n) = ev.note.filter(|s| !s.is_empty()) {
        out["note"] = serde_json::Value::String(n);
    }
    if let Some(t) = ev.r#type.filter(|s| !s.is_empty()) {
        out["type"] = serde_json::Value::String(t);
    }
    if let Some(count) = ev.deprecated_count.filter(|&v| v != 0) {
        out["deprecatedCount"] = serde_json::Value::Number(count.into());
    }
    // deprecatedSource/deprecatedFirstTimestamp/deprecatedLastTimestamp back-fill the legacy
    // core/v1 Event fields for clients still reading events.k8s.io/v1 Events the old way;
    // deprecatedCount already got this treatment above, these three should not be dropped
    // just because they share the "deprecated" name.
    if let Some(src) = ev.deprecated_source {
        let mut srcj = serde_json::Map::new();
        if let Some(v) = src.component.filter(|s| !s.is_empty()) {
            srcj.insert("component".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = src.host.filter(|s| !s.is_empty()) {
            srcj.insert("host".to_string(), serde_json::Value::String(v));
        }
        if !srcj.is_empty() {
            out["deprecatedSource"] = serde_json::Value::Object(srcj);
        }
    }
    if let Some(t) = ev.deprecated_first_timestamp {
        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
            out["deprecatedFirstTimestamp"] =
                serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
        }
    }
    if let Some(t) = ev.deprecated_last_timestamp {
        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
            out["deprecatedLastTimestamp"] =
                serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Encoder — JSON (u7s's own already-validated stored representation) -> Kubernetes
// protobuf wire format, for the EndpointSlice hot-path GET/LIST response (see
// content_type.rs). The input here is never untrusted wire data, so no defensive
// wire-type/size checking is needed.
// ---------------------------------------------------------------------------

fn jstr(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn ji32(v: &serde_json::Value, key: &str) -> Option<i32> {
    v.get(key).and_then(|x| x.as_i64()).map(|n| n as i32)
}

fn jbool(v: &serde_json::Value, key: &str) -> Option<bool> {
    v.get(key).and_then(|x| x.as_bool())
}

fn jstrs(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn json_to_object_meta_proto(obj: &serde_json::Value) -> meta_v1::ObjectMeta {
    let meta = obj
        .get("metadata")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let owner_references = meta
        .get("ownerReferences")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .map(|r| meta_v1::OwnerReference {
                    api_version: jstr(r, "apiVersion"),
                    kind: jstr(r, "kind"),
                    name: jstr(r, "name"),
                    uid: jstr(r, "uid"),
                    controller: jbool(r, "controller"),
                    block_owner_deletion: jbool(r, "blockOwnerDeletion"),
                })
                .collect()
        })
        .unwrap_or_default();
    meta_v1::ObjectMeta {
        name: jstr(&meta, "name"),
        generate_name: jstr(&meta, "generateName"),
        namespace: jstr(&meta, "namespace"),
        uid: jstr(&meta, "uid"),
        resource_version: jstr(&meta, "resourceVersion"),
        generation: meta.get("generation").and_then(|x| x.as_i64()),
        labels: meta
            .get("labels")
            .and_then(|m| m.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default(),
        annotations: meta
            .get("annotations")
            .and_then(|m| m.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default(),
        owner_references,
        finalizers: jstrs(&meta, "finalizers"),
        ..Default::default()
    }
}

fn json_to_list_meta_proto(v: &serde_json::Value) -> meta_v1::ListMeta {
    let meta = v
        .get("metadata")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    meta_v1::ListMeta {
        resource_version: jstr(&meta, "resourceVersion"),
        r#continue: jstr(&meta, "continue"),
        ..Default::default()
    }
}

fn json_to_object_reference_proto(
    v: &serde_json::Value,
) -> u7s_proto_generated::k8s::io::api::core::v1::ObjectReference {
    u7s_proto_generated::k8s::io::api::core::v1::ObjectReference {
        kind: jstr(v, "kind"),
        namespace: jstr(v, "namespace"),
        name: jstr(v, "name"),
        uid: jstr(v, "uid"),
        api_version: jstr(v, "apiVersion"),
        resource_version: jstr(v, "resourceVersion"),
        field_path: jstr(v, "fieldPath"),
    }
}

fn json_to_endpoint_conditions_proto(v: &serde_json::Value) -> discovery_v1::EndpointConditions {
    discovery_v1::EndpointConditions {
        ready: jbool(v, "ready"),
        serving: jbool(v, "serving"),
        terminating: jbool(v, "terminating"),
    }
}

fn json_to_endpoint_hints_proto(v: &serde_json::Value) -> discovery_v1::EndpointHints {
    discovery_v1::EndpointHints {
        for_zones: v
            .get("forZones")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|z| jstr(z, "name"))
                    .map(|name| discovery_v1::ForZone { name: Some(name) })
                    .collect()
            })
            .unwrap_or_default(),
        for_nodes: v
            .get("forNodes")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|n| jstr(n, "name"))
                    .map(|name| discovery_v1::ForNode { name: Some(name) })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn json_to_endpoint_proto(v: &serde_json::Value) -> discovery_v1::Endpoint {
    discovery_v1::Endpoint {
        addresses: jstrs(v, "addresses"),
        conditions: v.get("conditions").map(json_to_endpoint_conditions_proto),
        hostname: jstr(v, "hostname"),
        target_ref: v.get("targetRef").map(json_to_object_reference_proto),
        node_name: jstr(v, "nodeName"),
        zone: jstr(v, "zone"),
        hints: v.get("hints").map(json_to_endpoint_hints_proto),
        ..Default::default()
    }
}

fn json_to_endpointslice_port_proto(v: &serde_json::Value) -> discovery_v1::EndpointPort {
    discovery_v1::EndpointPort {
        // EndpointPort.name is proto3 `optional string`: an empty string is a valid,
        // meaningful "unnamed port" wire shape (see decode_endpointslice_proto_gen above) —
        // emit the key whenever it is present in the JSON, regardless of emptiness, rather
        // than using the `jstr` helper's "absent if empty" behavior.
        name: v.get("name").and_then(|n| n.as_str()).map(str::to_string),
        protocol: jstr(v, "protocol"),
        port: ji32(v, "port"),
        app_protocol: jstr(v, "appProtocol"),
    }
}

fn json_to_endpointslice_proto(v: &serde_json::Value) -> discovery_v1::EndpointSlice {
    discovery_v1::EndpointSlice {
        metadata: Some(json_to_object_meta_proto(v)),
        address_type: jstr(v, "addressType"),
        endpoints: v
            .get("endpoints")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().map(json_to_endpoint_proto).collect())
            .unwrap_or_default(),
        ports: v
            .get("ports")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().map(json_to_endpointslice_port_proto).collect())
            .unwrap_or_default(),
    }
}

pub fn encode_endpointslice_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    json_to_endpointslice_proto(v).encode_to_vec()
}

pub fn encode_endpointslicelist_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    let items = v
        .get("items")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().map(json_to_endpointslice_proto).collect())
        .unwrap_or_default();
    discovery_v1::EndpointSliceList {
        metadata: Some(json_to_list_meta_proto(v)),
        items,
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// decode_ingress_proto_gen must preserve status.loadBalancer.ingress (ip/hostname/ports).
    ///
    /// Clients read Ingress status to learn the load-balancer IP/hostname assigned by the
    /// ingress controller; decode_ingress_proto_gen never read `.status` at all, so
    /// "should support creating Ingress API operations" conformance saw an empty
    /// IngressLoadBalancerStatus after the controller updated it — the Ingress looked
    /// permanently unprovisioned.
    #[test]
    fn decode_ingress_proto_gen_preserves_load_balancer_status() {
        let obj = networking_v1::Ingress {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-ingress".to_string()),
                ..Default::default()
            }),
            status: Some(networking_v1::IngressStatus {
                load_balancer: Some(networking_v1::IngressLoadBalancerStatus {
                    ingress: vec![networking_v1::IngressLoadBalancerIngress {
                        ip: Some("203.0.113.10".to_string()),
                        hostname: Some("lb.example.com".to_string()),
                        ports: vec![networking_v1::IngressPortStatus {
                            port: Some(443),
                            protocol: Some("TCP".to_string()),
                            ..Default::default()
                        }],
                    }],
                }),
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_ingress_proto_gen(&buf).expect("Ingress with status must decode");

        assert_eq!(
            result["status"]["loadBalancer"]["ingress"][0]["ip"], "203.0.113.10",
            "status.loadBalancer.ingress[0].ip must survive decode; before the fix .status was \
             never read, so clients could not discover the assigned load-balancer IP"
        );
        assert_eq!(
            result["status"]["loadBalancer"]["ingress"][0]["hostname"], "lb.example.com",
            "status.loadBalancer.ingress[0].hostname must survive decode"
        );
        assert_eq!(
            result["status"]["loadBalancer"]["ingress"][0]["ports"][0]["port"], 443,
            "status.loadBalancer.ingress[0].ports[0].port must survive decode"
        );
    }

    /// decode_ipaddress_proto_gen must decode a protobuf-encoded IPAddress.
    ///
    /// Before adding this decoder + its proto.rs dispatch arm, extract_body had no way to
    /// turn the protobuf body client-go's typed IPAddress clientset sends into JSON, so
    /// every Create() fell through to "invalid JSON: expected value at line 1 column 1" and
    /// the apiserver returned 400 instead of 201.
    #[test]
    fn decode_ipaddress_proto_gen_preserves_parent_ref() {
        let obj = networking_v1::IpAddress {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("192.168.1.5".to_string()),
                ..Default::default()
            }),
            spec: Some(networking_v1::IpAddressSpec {
                parent_ref: Some(networking_v1::ParentReference {
                    group: Some("".to_string()),
                    resource: Some("services".to_string()),
                    namespace: Some("default".to_string()),
                    name: Some("my-svc".to_string()),
                }),
            }),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_ipaddress_proto_gen(&buf).expect("IPAddress must decode via proto");

        assert_eq!(result["kind"], "IPAddress");
        assert_eq!(
            result["spec"]["parentRef"]["resource"], "services",
            "spec.parentRef.resource must survive decode — an IPAddress without its parent \
             reference cannot be traced back to the Service that owns it"
        );
        assert_eq!(result["spec"]["parentRef"]["name"], "my-svc");
    }

    /// decode_servicecidr_proto_gen must decode a protobuf-encoded ServiceCIDR, including
    /// spec.cidrs and status.conditions.
    ///
    /// Same root cause as IPAddress: a missing dispatch arm/decoder means every protobuf
    /// Create() for ServiceCIDR returns 400 instead of 201.
    #[test]
    fn decode_servicecidr_proto_gen_preserves_cidrs_and_conditions() {
        let obj = networking_v1::ServiceCidr {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-cidr".to_string()),
                ..Default::default()
            }),
            spec: Some(networking_v1::ServiceCidrSpec {
                cidrs: vec!["10.0.0.0/24".to_string()],
            }),
            status: Some(networking_v1::ServiceCidrStatus {
                conditions: vec![meta_v1::Condition {
                    r#type: Some("Ready".to_string()),
                    status: Some("True".to_string()),
                    ..Default::default()
                }],
            }),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_servicecidr_proto_gen(&buf).expect("ServiceCIDR must decode via proto");

        assert_eq!(result["kind"], "ServiceCIDR");
        assert_eq!(
            result["spec"]["cidrs"][0], "10.0.0.0/24",
            "spec.cidrs must survive decode — without it, no IP range exists to allocate \
             ClusterIPs from"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "Ready",
            "status.conditions must survive decode"
        );
        assert!(
            result["status"]["conditions"][0]["reason"].is_null(),
            "condition.reason must stay absent when unset — a spurious empty-string reason \
             would make clients that check for reason's presence misread an unexplained condition \
             as an explained one"
        );
    }

    /// decode_csr_proto_gen must preserve status.conditions and status.certificate.
    ///
    /// `kubectl certificate approve/deny` PATCHes the /approval subresource and the signer
    /// controller PUTs the issued certificate through /status, both using protobuf
    /// content-type by default. The status branch here was added specifically to fix a
    /// silent-drop bug, but had no test coverage — a regression would silently make every CSR
    /// approval or issued certificate vanish on the next protobuf PUT.
    #[test]
    fn decode_csr_proto_gen_preserves_status_conditions_and_certificate() {
        let csr = certs_v1::CertificateSigningRequest {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-csr".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(certs_v1::CertificateSigningRequestStatus {
                conditions: vec![certs_v1::CertificateSigningRequestCondition {
                    r#type: Some("Approved".to_string()),
                    status: Some("True".to_string()),
                    reason: Some("KubectlApprove".to_string()),
                    ..Default::default()
                }],
                certificate: Some(
                    b"-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----".to_vec(),
                ),
            }),
        };
        let mut buf = Vec::new();
        csr.encode(&mut buf).unwrap();

        let result = decode_csr_proto_gen(&buf).expect("CSR with status must decode");

        assert_eq!(
            result["status"]["conditions"][0]["type"], "Approved",
            "status.conditions must survive decode — without it `kubectl certificate approve` \
             looks like it had no effect and the signer never issues a certificate"
        );
        use base64::Engine as _;
        let expected_cert = base64::engine::general_purpose::STANDARD
            .encode(b"-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----");
        assert_eq!(
            result["status"]["certificate"], expected_cert,
            "status.certificate must survive decode — without it the signer's protobuf \
             UpdateStatus PUT never actually delivers the issued certificate to the requester"
        );
    }

    /// decode_poddisruptionbudget_proto_gen must preserve status.disruptionsAllowed/
    /// currentHealthy/conditions.
    ///
    /// The eviction API handler consults status.disruptionsAllowed on every eviction request
    /// to decide whether to allow it; the disruption controller updates this status using
    /// protobuf content-type by default, so a dropped field here would either wrongly block
    /// every eviction (stuck at 0) or leave callers unable to see why evictions are refused.
    #[test]
    fn decode_poddisruptionbudget_proto_gen_preserves_status_counts_and_conditions() {
        let pdb = policy_v1::PodDisruptionBudget {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-pdb".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(policy_v1::PodDisruptionBudgetStatus {
                observed_generation: Some(1),
                disruptions_allowed: Some(2),
                current_healthy: Some(5),
                desired_healthy: Some(3),
                expected_pods: Some(5),
                conditions: vec![meta_v1::Condition {
                    r#type: Some("DisruptionAllowed".to_string()),
                    status: Some("True".to_string()),
                    reason: Some("SufficientPods".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        pdb.encode(&mut buf).unwrap();

        let result =
            decode_poddisruptionbudget_proto_gen(&buf).expect("PDB with status must decode");

        assert_eq!(
            result["status"]["disruptionsAllowed"], 2,
            "status.disruptionsAllowed must survive decode — the eviction API handler reads \
             this on every eviction request; a dropped value blocks all evictions at 0"
        );
        assert_eq!(
            result["status"]["currentHealthy"], 5,
            "status.currentHealthy must survive decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "DisruptionAllowed",
            "status.conditions must survive decode — kubectl and clients read this to explain \
             why evictions are or are not currently allowed"
        );
    }

    /// decode_ingressclass_proto_gen must preserve spec.controller.
    ///
    /// The ingress controller selects which IngressClass objects it manages by matching this
    /// field; a dropped controller value makes every Ingress referencing this class silently
    /// unmanaged by any controller.
    #[test]
    fn decode_ingressclass_proto_gen_preserves_controller() {
        let ic = networking_v1::IngressClass {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("nginx".to_string()),
                ..Default::default()
            }),
            spec: Some(networking_v1::IngressClassSpec {
                controller: Some("k8s.io/ingress-nginx".to_string()),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        ic.encode(&mut buf).unwrap();

        let result = decode_ingressclass_proto_gen(&buf).expect("IngressClass must decode");

        assert_eq!(
            result["spec"]["controller"], "k8s.io/ingress-nginx",
            "spec.controller must survive decode — without it no controller recognizes this \
             IngressClass as its own and every Ingress referencing it goes unserved"
        );
    }

    /// decode_endpointslice_proto_gen must preserve endpoints[].addresses/conditions and
    /// ports[].port.
    ///
    /// kube-proxy programs Service dataplane rules directly from EndpointSlice; a dropped
    /// address, readiness condition, or port means traffic silently never reaches a healthy pod.
    #[test]
    fn decode_endpointslice_proto_gen_preserves_addresses_conditions_and_ports() {
        let es = discovery_v1::EndpointSlice {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-svc-abcde".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            address_type: Some("IPv4".to_string()),
            endpoints: vec![discovery_v1::Endpoint {
                addresses: vec!["10.0.0.9".to_string()],
                conditions: Some(discovery_v1::EndpointConditions {
                    ready: Some(true),
                    serving: Some(true),
                    terminating: Some(false),
                }),
                hostname: Some("pod-a".to_string()),
                ..Default::default()
            }],
            ports: vec![discovery_v1::EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }],
        };
        let mut buf = Vec::new();
        es.encode(&mut buf).unwrap();

        let result = decode_endpointslice_proto_gen(&buf).expect("EndpointSlice must decode");

        assert_eq!(
            result["endpoints"][0]["addresses"][0], "10.0.0.9",
            "endpoints[].addresses must survive decode — without it kube-proxy programs no \
             backend and traffic to the Service black-holes"
        );
        assert_eq!(
            result["endpoints"][0]["conditions"]["ready"], true,
            "endpoints[].conditions.ready must survive decode — a dropped readiness condition \
             makes kube-proxy either send traffic to an unready pod or withhold it from a ready \
             one"
        );
        assert_eq!(
            result["ports"][0]["port"], 8080,
            "ports[].port must survive decode — without it kube-proxy has no port to forward to"
        );
    }

    /// decode_endpointslice_proto_gen must preserve a present-but-empty `ports[].name`, not
    /// collapse it to an absent key.
    ///
    /// `EndpointPort.name` is proto3 `optional string`: `Some("")` is the wire shape every
    /// single-port, unnamed-port Service produces (the most common Service shape in the whole
    /// conformance suite) — KCM marshals `Name: &""`, a non-nil pointer to an empty string, not
    /// a nil pointer. Kube-proxy's endpointslicecache.go distinguishes these two cases
    /// explicitly: a missing "name" key deserializes as `nil`, which it treats as "ignore this
    /// port" and `continue`s past, registering zero backends for it. A key present with value
    /// "" deserializes as a valid (if unnamed) port and is kept. Collapsing the two is exactly
    /// how a real Service went from "object looks perfect in `kubectl get -o yaml`" to
    /// "Connection refused" with zero ipvs rules programmed.
    #[test]
    fn decode_endpointslice_proto_gen_preserves_present_but_empty_port_name() {
        let es = discovery_v1::EndpointSlice {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-svc-abcde".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            address_type: Some("IPv4".to_string()),
            ports: vec![discovery_v1::EndpointPort {
                name: Some(String::new()),
                port: Some(80),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut buf = Vec::new();
        es.encode(&mut buf).unwrap();

        let result = decode_endpointslice_proto_gen(&buf).expect("EndpointSlice must decode");

        let port = result["ports"][0]
            .as_object()
            .expect("ports[0] must decode to a JSON object");
        assert!(
            port.contains_key("name"),
            "ports[0] must have a \"name\" key even when the name is the empty string — an \
             absent key and kube-proxy sees `Name == nil`, skips the port, and registers zero \
             backends for a single-port Service's ClusterIP"
        );
        assert_eq!(
            port["name"], "",
            "the present-but-empty name's value must round-trip as \"\", not be replaced or \
             coerced"
        );
    }

    /// decode_events_v1_event_proto_gen must preserve reason/regarding/series.
    ///
    /// This is the events.k8s.io/v1 Event type kubelet and controllers report through
    /// (distinct from the legacy core/v1 Event); a dropped `regarding` reference makes an
    /// event impossible to correlate back to the object it describes.
    #[test]
    fn decode_events_v1_event_proto_gen_preserves_reason_regarding_and_series() {
        let ev = events_v1::Event {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-pod.17abc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            regarding: Some(
                u7s_proto_generated::k8s::io::api::core::v1::ObjectReference {
                    kind: Some("Pod".to_string()),
                    name: Some("my-pod".to_string()),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                },
            ),
            reason: Some("Started".to_string()),
            note: Some("Started container demo".to_string()),
            r#type: Some("Normal".to_string()),
            action: Some("Started".to_string()),
            series: Some(events_v1::EventSeries {
                count: Some(4),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ev.encode(&mut buf).unwrap();

        let result =
            decode_events_v1_event_proto_gen(&buf).expect("events.k8s.io/v1 Event must decode");

        assert_eq!(
            result["regarding"]["name"], "my-pod",
            "regarding must survive decode — without it the event cannot be correlated back \
             to the object it describes"
        );
        assert_eq!(result["reason"], "Started", "reason must survive decode");
        assert_eq!(
            result["series"]["count"], 4,
            "series.count must survive decode — without it repeated identical events collapse \
             to a count of zero instead of the real occurrence count"
        );
    }

    // ---- Sentinel completeness ----
    //
    // Each test below builds a message with every field set to a value no zero/empty-elision
    // check in this file's gen_*_to_json functions could mistake for "unset" (see
    // u7s_sentinel::Sentinel), decodes it through the real decode_*_proto_gen entry point, and
    // asserts every field name shows up somewhere in the resulting JSON. A name that never
    // appears means some gen_*_to_json function never reads that field from the decoded
    // protobuf struct at all — this is exactly how IngressBackend.resource,
    // IngressClassSpec.parameters, EndpointHints.forNodes, CertificateSigningRequestSpec.extra,
    // and Event's deprecatedSource/deprecatedFirstTimestamp/deprecatedLastTimestamp were found
    // missing from this file.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    // selfLink is a legacy field the system no longer populates — permanently omitted.
    // deletionTimestamp/deletionGracePeriodSeconds/managedFields are left off `expected`
    // pending a separate investigation into gen_object_meta_to_json's correct handling of
    // them (this file's copy has the same omissions as every other gen_adapter's); do not
    // guess at the fix here.
    // labels/annotations are maps: their own field name is never a real leaf once populated,
    // only their sentinel-populated entry is (the deterministic "__sentinel__" map-key literal
    // u7s_sentinel's blanket `Sentinel for String` always produces). ownerReferences is an array
    // of a real struct (OwnerReference), so its own field name is likewise never a leaf; `uid`
    // pins the check to ownerReferences specifically rather than colliding with ObjectMeta's own
    // (separately checked) `uid`.
    const OBJECT_META_EXPECTED: &[&str] = &[
        "name",
        "generateName",
        "namespace",
        "uid",
        "resourceVersion",
        "generation",
        "creationTimestamp",
        "labels.__sentinel__",
        "annotations.__sentinel__",
        "ownerReferences.uid",
        "finalizers",
    ];

    // "matchLabels" is a map too, for the same reason as ObjectMeta's labels/annotations above.
    // "matchExpressions" is an array of a real struct (LabelSelectorRequirement): its own field
    // name is never a leaf either, so it's dropped in favor of its children (key/operator/values)
    // below, which already prove it survived decode.
    const LABEL_SELECTOR_EXPECTED: &[&str] =
        &["matchLabels.__sentinel__", "key", "operator", "values"];

    #[test]
    fn sentinel_completeness_decode_ingress_proto_gen() {
        let obj = networking_v1::Ingress {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(networking_v1::IngressSpec::sentinel()),
            status: Some(networking_v1::IngressStatus::sentinel()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_ingress_proto_gen(&buf)
            .expect("sentinel Ingress must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // "spec"/"defaultBackend"/"service"/"resource"/"tls"/"rules"/"http"/"backend"/"status"/
        // "loadBalancer"/"ingress"/"ports" are containers whose own field name is never itself a
        // leaf once populated; each is dropped in favor of the genuine leaf children below
        // (IngressBackend is a shared struct reachable via both defaultBackend and
        // rules[].http.paths[].backend, so port.number/apiGroup proving it survived at all is
        // sufficient — same acceptable ambiguity as everywhere else in this migration).
        expected.extend([
            "ingressClassName",
            "port",
            "number",
            // apiGroup/kind on IngressBackend.resource: apiGroup is unique and tested; kind is
            // deliberately excluded — masked by the envelope's own top-level "kind": "Ingress".
            "apiGroup",
            "hosts",
            "secretName",
            "host",
            "path",
            "pathType",
            "ip",
            "hostname",
            "protocol",
            "error",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_ingressclass_proto_gen() {
        let ic = networking_v1::IngressClass {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(networking_v1::IngressClassSpec::sentinel()),
        };
        let mut buf = Vec::new();
        ic.encode(&mut buf).unwrap();
        let result = decode_ingressclass_proto_gen(&buf)
            .expect("sentinel IngressClass must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // "spec"/"parameters" are containers whose own field name is never itself a leaf once
        // populated; controller/apiGroup/scope below already prove they survived decode.
        expected.extend([
            "controller",
            "apiGroup",
            "scope",
            // "kind"/"namespace" on IngressClassParametersReference deliberately excluded:
            // kind is masked by the envelope's top-level "kind": "IngressClass" literal, and
            // namespace is masked by metadata.namespace already being sentinel-populated.
        ]);
        assert_fields_present(&paths, &expected);
    }

    /// Derived from the .proto schema rather than hand-listed, so a field added upstream to
    /// NetworkPolicySpec (or its nested Ingress/Egress/Peer/Port/IPBlock messages) is demanded
    /// here automatically instead of when someone remembers to type it — see the Lease sentinel
    /// test in coord_gen_adapter.rs for the same pattern.
    #[test]
    fn sentinel_completeness_decode_networkpolicy_proto_gen() {
        let np = networking_v1::NetworkPolicy {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(networking_v1::NetworkPolicySpec::sentinel()),
        };
        let mut buf = Vec::new();
        np.encode(&mut buf).unwrap();
        let result = decode_networkpolicy_proto_gen(&buf)
            .expect("sentinel NetworkPolicy must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.networking.v1.NetworkPolicy",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// decode_proto_by_kind_and_version must dispatch NetworkPolicy proto and preserve
    /// spec.podSelector/ingress/policyTypes.
    ///
    /// Before adding this decoder + its proto.rs dispatch arm, "NetworkPolicy" had no match
    /// arm at all, so a client-go networking/v1 typed clientset Create() (default protobuf
    /// content-type) fell through extract_body's fallback and the generic create handler
    /// received raw protobuf bytes it can't JSON-parse, failing every such request outright.
    #[test]
    fn decode_networkpolicy_proto_gen_preserves_pod_selector_ingress_and_policy_types() {
        use u7s_proto_generated::k8s::io::apimachinery::pkg::util::intstr::IntOrString;

        let np = networking_v1::NetworkPolicy {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("deny-all-except-web".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(networking_v1::NetworkPolicySpec {
                pod_selector: Some(meta_v1::LabelSelector {
                    match_labels: [("app".to_string(), "web".to_string())]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                }),
                ingress: vec![networking_v1::NetworkPolicyIngressRule {
                    ports: vec![networking_v1::NetworkPolicyPort {
                        protocol: Some("TCP".to_string()),
                        port: Some(IntOrString {
                            r#type: Some(0),
                            int_val: Some(80),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    from: vec![networking_v1::NetworkPolicyPeer {
                        namespace_selector: Some(meta_v1::LabelSelector::default()),
                        ..Default::default()
                    }],
                }],
                policy_types: vec!["Ingress".to_string()],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        np.encode(&mut buf).unwrap();

        let result = crate::proto::decode_proto_by_kind_and_version(
            "NetworkPolicy",
            "networking.k8s.io/v1",
            &buf,
        )
        .expect(
            "NetworkPolicy must decode via decode_proto_by_kind_and_version — without this, \
             client-go's typed clientset POST returns 400 instead of 201 on every create",
        );

        assert_eq!(result["kind"], "NetworkPolicy");
        assert_eq!(
            result["spec"]["podSelector"]["matchLabels"]["app"], "web",
            "spec.podSelector must survive decode — without it every pod in the namespace, \
             not just app=web, would be (mis)covered by this policy"
        );
        assert_eq!(
            result["spec"]["ingress"][0]["ports"][0]["port"], 80,
            "spec.ingress[].ports[].port must survive decode — without it the rule matches \
             all ports instead of just 80"
        );
        assert_eq!(
            result["spec"]["ingress"][0]["from"][0]["namespaceSelector"],
            serde_json::json!({}),
            "spec.ingress[].from[].namespaceSelector must survive decode as an (empty) \
             selector, not be dropped — an absent selector and an empty one mean different \
             things (no restriction from namespaceSelector vs. matches every namespace)"
        );
        assert_eq!(
            result["spec"]["policyTypes"][0], "Ingress",
            "spec.policyTypes must survive decode — without it this policy defaults to \
             covering both Ingress and Egress, silently widening its scope"
        );
    }

    #[test]
    fn sentinel_completeness_decode_ipaddress_proto_gen() {
        let obj = networking_v1::IpAddress {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(networking_v1::IpAddressSpec::sentinel()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_ipaddress_proto_gen(&buf)
            .expect("sentinel IPAddress must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // "spec"/"parentRef" are containers whose own field name is never itself a leaf once
        // populated; group/resource below already prove they survived decode.
        expected.extend(["group", "resource"]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_servicecidr_proto_gen() {
        let obj = networking_v1::ServiceCidr {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(networking_v1::ServiceCidrSpec::sentinel()),
            status: Some(networking_v1::ServiceCidrStatus::sentinel()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_servicecidr_proto_gen(&buf)
            .expect("sentinel ServiceCIDR must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // "spec"/"conditions" are containers whose own field name is never itself a leaf once
        // populated; cidrs/reason/message/lastTransitionTime below already prove they survived.
        expected.extend([
            "cidrs",
            "status",
            "type",
            "reason",
            "message",
            "lastTransitionTime",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_endpointslice_proto_gen() {
        let es = discovery_v1::EndpointSlice {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            address_type: Some("IPv4".to_string()),
            endpoints: vec![discovery_v1::Endpoint::sentinel()],
            ports: vec![discovery_v1::EndpointPort::sentinel()],
        };
        let mut buf = Vec::new();
        es.encode(&mut buf).unwrap();
        let result = decode_endpointslice_proto_gen(&buf)
            .expect("sentinel EndpointSlice must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // "endpoints"/"conditions"/"targetRef"/"hints"/"ports" are containers whose own field
        // name is never itself a leaf once populated; each is dropped in favor of a genuine leaf
        // child instead ("forZones"/"forNodes" are containers too — ForZone/ForNode each have
        // only a "name" field, so they get their own dotted entry rather than relying on the
        // ambiguous bare "name" already satisfied by ObjectMeta's own).
        expected.extend([
            "addressType",
            "addresses",
            "ready",
            "serving",
            "terminating",
            "hostname",
            // targetRef.kind/apiVersion deliberately excluded — masked by the envelope's own
            // top-level "kind"/"apiVersion" literals. fieldPath is the one ObjectReference
            // field with no such collision, so it is the meaningful check here.
            "fieldPath",
            "nodeName",
            "zone",
            "hints.forZones.name",
            "hints.forNodes.name",
            // "ports.name" (rather than the bare, ObjectMeta-collision-prone "name") pins this
            // check to EndpointPort.name specifically — the field mayor-mb9ed's decoder bug
            // dropped whenever it was present-but-empty. The sentinel value here is non-empty
            // so this alone can't catch that regression (see
            // decode_endpointslice_proto_gen_preserves_present_but_empty_port_name for that);
            // this just proves the field is read from the decoded proto at all.
            "ports.name",
            "port",
            "protocol",
            "appProtocol",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_csr_proto_gen() {
        let csr = certs_v1::CertificateSigningRequest {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(certs_v1::CertificateSigningRequestSpec::sentinel()),
            status: Some(certs_v1::CertificateSigningRequestStatus::sentinel()),
        };
        let mut buf = Vec::new();
        csr.encode(&mut buf).unwrap();
        let result = decode_csr_proto_gen(&buf)
            .expect("sentinel CertificateSigningRequest must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // "spec"/"status"/"conditions" are containers whose own field name is never itself a
        // leaf once populated; their genuine leaf children below already prove they survived
        // decode. "extra" is a map<string, ExtraValue>, but ExtraValue (Go `[]string`) marshals
        // as a bare JSON array — the sentinel-populated map entry itself is the leaf.
        expected.extend([
            "request",
            "signerName",
            "expirationSeconds",
            "usages",
            "username",
            "groups",
            "extra.__sentinel__",
            "type",
            "reason",
            "message",
            "lastUpdateTime",
            "lastTransitionTime",
            "certificate",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_poddisruptionbudget_proto_gen() {
        let pdb = policy_v1::PodDisruptionBudget {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(policy_v1::PodDisruptionBudgetSpec::sentinel()),
            status: Some(policy_v1::PodDisruptionBudgetStatus::sentinel()),
        };
        let mut buf = Vec::new();
        pdb.encode(&mut buf).unwrap();
        let result = decode_poddisruptionbudget_proto_gen(&buf)
            .expect("sentinel PodDisruptionBudget must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(LABEL_SELECTOR_EXPECTED);
        // "spec"/"selector"/"conditions" are containers whose own field name is never itself a
        // leaf once populated; LABEL_SELECTOR_EXPECTED/reason/message/lastTransitionTime below
        // already prove they survived. "disruptedPods" is a map<string, Time>, so its leaf is
        // the sentinel-populated entry's own key.
        expected.extend([
            "minAvailable",
            "maxUnavailable",
            "unhealthyPodEvictionPolicy",
            "status",
            "observedGeneration",
            "disruptedPods.__sentinel__",
            "disruptionsAllowed",
            "currentHealthy",
            "desiredHealthy",
            "expectedPods",
            "type",
            "reason",
            "message",
            "lastTransitionTime",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_events_v1_event_proto_gen() {
        let ev = events_v1::Event {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            event_time: Some(meta_v1::MicroTime::sentinel()),
            series: Some(events_v1::EventSeries::sentinel()),
            reporting_controller: Some("kubernetes.io/kubelet".to_string()),
            reporting_instance: Some("kubelet-abc".to_string()),
            action: Some("Started".to_string()),
            reason: Some("Started".to_string()),
            regarding: Some(
                u7s_proto_generated::k8s::io::api::core::v1::ObjectReference::sentinel(),
            ),
            related: Some(u7s_proto_generated::k8s::io::api::core::v1::ObjectReference::sentinel()),
            note: Some("a note".to_string()),
            r#type: Some("Normal".to_string()),
            deprecated_source: Some(
                u7s_proto_generated::k8s::io::api::core::v1::EventSource::sentinel(),
            ),
            deprecated_first_timestamp: Some(meta_v1::Time::sentinel()),
            deprecated_last_timestamp: Some(meta_v1::Time::sentinel()),
            deprecated_count: Some(3),
        };
        let mut buf = Vec::new();
        ev.encode(&mut buf).unwrap();
        let result = decode_events_v1_event_proto_gen(&buf)
            .expect("sentinel events.k8s.io/v1 Event must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // "series"/"regarding"/"related"/"deprecatedSource" are containers whose own field name
        // is never itself a leaf once populated; each is dropped in favor of the genuine leaf
        // children below, which already prove it survived decode.
        expected.extend([
            "eventTime",
            "count",
            "lastObservedTime",
            "reportingController",
            "reportingInstance",
            "action",
            "reason",
            // regarding/related.kind/apiVersion deliberately excluded — masked by the
            // envelope's own top-level "kind"/"apiVersion" literals.
            "fieldPath",
            "note",
            "type",
            "deprecatedCount",
            "component",
            "host",
            "deprecatedFirstTimestamp",
            "deprecatedLastTimestamp",
        ]);
        assert_fields_present(&paths, &expected);
    }

    // ---- Field-omission: all-default proto must decode with no stray nulls ----
    //
    // Each test below builds a message with every optional field unset (`Default::default()`),
    // decodes it through the real entry point, and asserts no key survives as an explicit JSON
    // `null` (other than ObjectMeta's `creationTimestamp`) and that optional top-level blocks
    // (spec/status) are genuinely absent rather than present-with-nulls.

    use crate::util::sentinel_test_util::assert_no_stray_nulls;

    #[test]
    fn decode_ingress_proto_gen_omits_unset_spec_and_status_instead_of_emitting_null() {
        let obj = networking_v1::Ingress::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded = decode_ingress_proto_gen(&buf).expect("all-default Ingress must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none() && decoded.get("status").is_none(),
            "unset spec/status must be absent, not null — an ingress controller that checks \
             `status.loadBalancer != null` to decide whether an address has been assigned would \
             otherwise treat a brand-new Ingress as already provisioned"
        );
    }

    #[test]
    fn decode_ingressclass_proto_gen_omits_unset_spec_instead_of_emitting_null() {
        let obj = networking_v1::IngressClass::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded =
            decode_ingressclass_proto_gen(&buf).expect("all-default IngressClass must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none(),
            "an unset IngressClassSpec must be absent, not null"
        );
    }

    #[test]
    fn decode_ipaddress_proto_gen_omits_unset_spec_instead_of_emitting_null() {
        let obj = networking_v1::IpAddress::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded = decode_ipaddress_proto_gen(&buf).expect("all-default IPAddress must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none(),
            "an unset IPAddress spec.parentRef must leave `spec` entirely absent, not null — \
             an IPAddress with no parentRef isn't a valid allocation, so a caller must be able \
             to tell \"never set\" apart from \"explicitly cleared\""
        );
    }

    #[test]
    fn decode_servicecidr_proto_gen_omits_unset_spec_and_status_instead_of_emitting_null() {
        let obj = networking_v1::ServiceCidr::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded =
            decode_servicecidr_proto_gen(&buf).expect("all-default ServiceCIDR must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none() && decoded.get("status").is_none(),
            "unset spec/status must be absent, not null"
        );
    }

    #[test]
    fn decode_endpointslice_proto_gen_omits_no_nulls_on_all_default_input() {
        let obj = discovery_v1::EndpointSlice::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded =
            decode_endpointslice_proto_gen(&buf).expect("all-default EndpointSlice must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert_eq!(
            decoded["endpoints"].as_array().map(|a| a.len()),
            Some(0),
            "endpoints must decode to an empty array (matching upstream, which has no \
             omitempty), not null"
        );
    }

    #[test]
    fn decode_csr_proto_gen_omits_unset_spec_and_status_instead_of_emitting_null() {
        let obj = certs_v1::CertificateSigningRequest::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded =
            decode_csr_proto_gen(&buf).expect("all-default CertificateSigningRequest must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none() && decoded.get("status").is_none(),
            "unset spec/status must be absent, not null — an approval webhook that checks \
             `status != null` to mean \"has an approval decision\" would otherwise treat a \
             brand-new CSR as already decided"
        );
    }

    #[test]
    fn decode_poddisruptionbudget_proto_gen_omits_unset_spec_and_status_instead_of_emitting_null() {
        let obj = policy_v1::PodDisruptionBudget::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded = decode_poddisruptionbudget_proto_gen(&buf)
            .expect("all-default PodDisruptionBudget must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none() && decoded.get("status").is_none(),
            "unset spec/status must be absent, not null — the eviction API reads status to \
             decide whether a voluntary disruption is currently allowed; a present-but-empty \
             status (disruptionsAllowed defaulting to 0) would incorrectly block every eviction \
             instead of signaling \"never reconciled\""
        );
    }

    #[test]
    fn decode_events_v1_event_proto_gen_omits_unset_optional_fields_instead_of_emitting_null() {
        let ev = events_v1::Event::default();
        let mut buf = Vec::new();
        ev.encode(&mut buf).unwrap();
        let decoded =
            decode_events_v1_event_proto_gen(&buf).expect("all-default Event must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("eventTime").is_none()
                && decoded.get("series").is_none()
                && decoded.get("regarding").is_none(),
            "unset eventTime/series/regarding must be absent, not null — event-aggregation \
             tooling that groups by `series != null` to detect a repeated event would otherwise \
             misclassify every single-occurrence event as part of a series"
        );
    }

    /// EndpointSlice round-trips through the response-side protobuf encoder: kube-proxy's
    /// EndpointSlice-based dataplane (the default since 1.19) programs backend rules straight
    /// from addresses/ports/conditions.ready, so a silent drop here means traffic for that
    /// backend is never routed, or a not-ready backend is routed to anyway.
    ///
    /// This also exercises the mb9ed fix's encode-side counterpart: `ports[].name` must be
    /// emitted (even as `""`) whenever the JSON had the key at all, not only when non-empty —
    /// kube-proxy's endpointslicecache.go treats an absent `name` as a different port than an
    /// empty-string `name`.
    #[test]
    fn encode_endpointslice_proto_gen_round_trips_addresses_ports_and_empty_port_name() {
        let slice = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": { "name": "web-abcde", "namespace": "default" },
            "addressType": "IPv4",
            "endpoints": [{
                "addresses": ["10.244.0.5"],
                "conditions": { "ready": true },
                "nodeName": "worker-1"
            }],
            "ports": [{ "name": "", "port": 8080, "protocol": "TCP" }]
        });

        let raw = encode_endpointslice_proto_gen(&slice);
        let decoded =
            decode_endpointslice_proto_gen(&raw).expect("encoded EndpointSlice bytes must decode");

        assert_eq!(decoded["addressType"], "IPv4");
        assert_eq!(decoded["endpoints"][0]["addresses"][0], "10.244.0.5");
        assert_eq!(
            decoded["endpoints"][0]["conditions"]["ready"], true,
            "conditions.ready must survive — kube-proxy skips not-ready backends based on it"
        );
        assert_eq!(
            decoded["ports"][0]["name"], "",
            "an explicit empty-string port name must round-trip as present-and-empty, not \
             vanish into a missing key (see mb9ed: a missing key reads as a *different* port \
             to kube-proxy's endpointslicecache.go than an empty-string name does)"
        );
    }

    /// EndpointSliceList wraps each item through the same per-slice encoder.
    #[test]
    fn encode_endpointslicelist_proto_gen_round_trips_all_items() {
        let list = serde_json::json!({
            "kind": "EndpointSliceList",
            "apiVersion": "discovery.k8s.io/v1",
            "metadata": { "resourceVersion": "7" },
            "items": [
                { "metadata": { "name": "a" }, "addressType": "IPv4" },
                { "metadata": { "name": "b" }, "addressType": "IPv4" }
            ]
        });

        let raw = encode_endpointslicelist_proto_gen(&list);
        let decoded = discovery_v1::EndpointSliceList::decode(raw.as_slice())
            .expect("encoded EndpointSliceList bytes must decode");

        assert_eq!(
            decoded.items.len(),
            2,
            "both list items must survive the round trip"
        );
    }
}
