use prost::Message;

use crate::net_disc_cert_policy_events_gen::k8s::io::api::certificates::v1 as certs_v1;
use crate::net_disc_cert_policy_events_gen::k8s::io::api::discovery::v1 as discovery_v1;
use crate::net_disc_cert_policy_events_gen::k8s::io::api::events::v1 as events_v1;
use crate::net_disc_cert_policy_events_gen::k8s::io::api::networking::v1 as networking_v1;
use crate::net_disc_cert_policy_events_gen::k8s::io::api::policy::v1 as policy_v1;
use crate::net_disc_cert_policy_events_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    let mut m = serde_json::json!({ "creationTimestamp": serde_json::Value::Null });
    if let Some(n) = meta.name.filter(|s| !s.is_empty()) {
        m["name"] = serde_json::Value::String(n);
    }
    if let Some(n) = meta.generate_name.filter(|s| !s.is_empty()) {
        m["generateName"] = serde_json::Value::String(n);
    }
    if let Some(n) = meta.namespace.filter(|s| !s.is_empty()) {
        m["namespace"] = serde_json::Value::String(n);
    }
    if let Some(u) = meta.uid.filter(|s| !s.is_empty()) {
        m["uid"] = serde_json::Value::String(u);
    }
    if let Some(rv) = meta.resource_version.filter(|s| !s.is_empty()) {
        m["resourceVersion"] = serde_json::Value::String(rv);
    }
    if let Some(g) = meta.generation.filter(|&v| v != 0) {
        m["generation"] = serde_json::Value::Number(g.into());
    }
    if let Some(ts) = meta.creation_timestamp {
        if let Some(secs) = ts.seconds {
            if secs > 0 {
                m["creationTimestamp"] =
                    serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
            }
        }
    }
    if !meta.labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = meta
            .labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["labels"] = serde_json::Value::Object(labels);
    }
    if !meta.annotations.is_empty() {
        let annotations: serde_json::Map<String, serde_json::Value> = meta
            .annotations
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["annotations"] = serde_json::Value::Object(annotations);
    }
    if !meta.owner_references.is_empty() {
        let refs: Vec<serde_json::Value> = meta
            .owner_references
            .into_iter()
            .map(|r| {
                let mut entry = serde_json::json!({});
                if let Some(v) = r.api_version.filter(|s| !s.is_empty()) {
                    entry["apiVersion"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
                    entry["kind"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.name.filter(|s| !s.is_empty()) {
                    entry["name"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.uid.filter(|s| !s.is_empty()) {
                    entry["uid"] = serde_json::Value::String(v);
                }
                if let Some(ctrl) = r.controller {
                    entry["controller"] = serde_json::Value::Bool(ctrl);
                }
                if let Some(bod) = r.block_owner_deletion {
                    entry["blockOwnerDeletion"] = serde_json::Value::Bool(bod);
                }
                entry
            })
            .collect();
        if !refs.is_empty() {
            m["ownerReferences"] = serde_json::Value::Array(refs);
        }
    }
    if !meta.finalizers.is_empty() {
        let fins: Vec<serde_json::Value> = meta
            .finalizers
            .into_iter()
            .map(serde_json::Value::String)
            .collect();
        m["finalizers"] = serde_json::Value::Array(fins);
    }
    m
}

fn gen_label_selector_to_json(sel: meta_v1::LabelSelector) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !sel.match_labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = sel
            .match_labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m.insert("matchLabels".to_string(), serde_json::Value::Object(labels));
    }
    if !sel.match_expressions.is_empty() {
        let exprs: Vec<serde_json::Value> = sel
            .match_expressions
            .into_iter()
            .map(|e| {
                let mut em = serde_json::Map::new();
                if let Some(k) = e.key.filter(|s| !s.is_empty()) {
                    em.insert("key".to_string(), serde_json::Value::String(k));
                }
                if let Some(op) = e.operator.filter(|s| !s.is_empty()) {
                    em.insert("operator".to_string(), serde_json::Value::String(op));
                }
                if !e.values.is_empty() {
                    em.insert(
                        "values".to_string(),
                        serde_json::Value::Array(
                            e.values
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                }
                serde_json::Value::Object(em)
            })
            .collect();
        m.insert(
            "matchExpressions".to_string(),
            serde_json::Value::Array(exprs),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_int_or_string_to_json(
    ios: &crate::net_disc_cert_policy_events_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString,
) -> serde_json::Value {
    if ios.r#type.unwrap_or(0) == 0 {
        serde_json::Value::Number(ios.int_val.unwrap_or(0).into())
    } else {
        serde_json::Value::String(ios.str_val.clone().unwrap_or_default())
    }
}

fn gen_object_reference_to_json(
    r: crate::net_disc_cert_policy_events_gen::k8s::io::api::core::v1::ObjectReference,
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
            if let Some(n) = p.name.filter(|s| !s.is_empty()) {
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
    Some(out)
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
}
