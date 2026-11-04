//! Auto-approver for `kubernetes.io/kubelet-serving` CSRs.
//!
//! Upstream ships no in-tree approver for this signer: KCM's csrapproving controller only
//! recognises the kubelet *client* signer, and kubelet-serving requests wait for an
//! operator (or an out-of-tree controller such as kubelet-csr-approver). Without this a
//! joined node's `serverTLSBootstrap` request would sit Pending forever.
//!
//! The recogniser is deliberately narrower than "anything upstream's
//! `ValidateKubeletServingCSR` accepts": the CA is trusted by the apiserver to verify
//! kubelets, so a serving cert for another node's name or IP lets its holder impersonate
//! that node (logs/exec/attach are proxied to it). Every SAN must therefore be backed by
//! the requesting node's own `Node` object. Anything that does not match stays Pending —
//! this controller never denies, so an operator can still approve by hand.

use base64::Engine as _;
use std::collections::BTreeSet;
use std::net::IpAddr;
use u7s_store::{ListOptions, Store};
use x509_cert::der::{oid::AssociatedOid as _, Decode as _};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::Extension;
use x509_cert::request::{CertReq, ExtensionReq};

use crate::keys::{cluster_list_prefix, group_list_prefix};
use crate::state::AppState;

const GROUP: &str = "certificates.k8s.io";
const PLURAL: &str = "certificatesigningrequests";
const KUBELET_SERVING_SIGNER: &str = "kubernetes.io/kubelet-serving";
const NODE_USER_PREFIX: &str = "system:node:";
const NODES_GROUP: &str = "system:nodes";
const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_ORGANIZATION: &str = "2.5.4.10";

/// Upstream's `kubeletServingRequiredUsages` and `...NoRSA` (key encipherment is only
/// meaningful for RSA keys).
const USAGES_RSA: [&str; 3] = ["digital signature", "key encipherment", "server auth"];
const USAGES_NO_RSA: [&str; 2] = ["digital signature", "server auth"];

pub(crate) const APPROVAL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// `Ok` when the CSR may be auto-approved; `Err(reason)` leaves it Pending.
pub(crate) fn evaluate(
    csr: &serde_json::Value,
    node: Option<&serde_json::Value>,
    ctx: &IpContext,
) -> Result<(), String> {
    let spec = &csr["spec"];
    let username = spec["username"].as_str().unwrap_or("");
    let node_name = username
        .strip_prefix(NODE_USER_PREFIX)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| format!("requestor {username:?} is not system:node:<name>"))?;
    let in_nodes_group = spec["groups"]
        .as_array()
        .is_some_and(|g| g.iter().any(|v| v.as_str() == Some(NODES_GROUP)));
    if !in_nodes_group {
        return Err(format!(
            "requestor {username:?} is not in group {NODES_GROUP}"
        ));
    }

    let usages: BTreeSet<&str> = spec["usages"]
        .as_array()
        .map(|u| u.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let want = |set: &[&str]| usages == set.iter().copied().collect::<BTreeSet<_>>();
    if !want(&USAGES_RSA) && !want(&USAGES_NO_RSA) {
        return Err(format!("usages {usages:?} are not the kubelet-serving set"));
    }

    let pem = base64::engine::general_purpose::STANDARD
        .decode(spec["request"].as_str().unwrap_or(""))
        .map_err(|e| format!("request is not base64: {e}"))?;
    let req = crate::handlers::csr::parse_csr_pem(&pem)
        .map_err(|e| format!("request is not a PKCS#10 PEM: {e}"))?;

    let (mut cn, mut orgs) = (Vec::new(), Vec::new());
    for atv in req.info.subject.iter() {
        let value = crate::auth::atv_string(&atv.value)
            .ok_or_else(|| "subject has an undecodable attribute".to_string())?;
        match atv.oid.to_string().as_str() {
            OID_COMMON_NAME => cn.push(value),
            OID_ORGANIZATION => orgs.push(value),
            other => return Err(format!("subject has unexpected attribute {other}")),
        }
    }
    if cn != [username] {
        return Err(format!(
            "subject CN {cn:?} does not equal requestor {username:?}"
        ));
    }
    if orgs != [NODES_GROUP] {
        return Err(format!("subject O {orgs:?} is not [{NODES_GROUP}]"));
    }

    let sans = subject_alt_names(&req)?;
    if sans.is_empty() {
        return Err("no DNS or IP SAN".into());
    }

    let node = node.ok_or_else(|| format!("Node {node_name:?} does not exist yet"))?;
    let (node_dns, node_ips) = node_addresses(node, node_name);
    for san in &sans {
        match san {
            GeneralName::DnsName(d) if node_dns.contains(d.as_str()) => {}
            GeneralName::DnsName(d) => {
                return Err(format!(
                    "DNS SAN {:?} is not node {node_name:?}'s name or hostname",
                    d.as_str()
                ))
            }
            GeneralName::IpAddress(raw) => match ip_from_octets(raw.as_bytes()) {
                Some(ip) if node_ips.contains(&ip) => ctx.check_ip(ip, node_name)?,
                Some(ip) => {
                    return Err(format!(
                        "IP SAN {ip} is not in Node {node_name:?} status.addresses"
                    ))
                }
                None => return Err("IP SAN is not 4 or 16 bytes".into()),
            },
            _ => return Err("SAN of a type other than DNS or IP".into()),
        }
    }
    Ok(())
}

/// What an IP SAN must additionally avoid. A node may write any `status.addresses` on its
/// own Node object, so membership there proves nothing about who owns the address.
#[derive(Default)]
pub(crate) struct IpContext {
    /// Every IP any OTHER Node reports in any address field.
    pub other_node_ips: BTreeSet<IpAddr>,
    /// Service CIDR base and size, one per configured family.
    pub service_cidrs: Vec<(IpAddr, u128)>,
    /// The apiserver's own advertise and listen addresses.
    pub apiserver_ips: Vec<IpAddr>,
    /// Every Node's `spec.podCIDRs`/`spec.podCIDR` as (node name, base, prefix length). The
    /// apiserver has no cluster CIDR, so the union of per-node ranges is the pod range.
    pub pod_cidrs: Vec<(String, IpAddr, u8)>,
}

impl IpContext {
    fn add_pod_cidrs(&mut self, node: &serde_json::Value) {
        let name = node["metadata"]["name"].as_str().unwrap_or("");
        let spec = &node["spec"];
        let cidrs = spec["podCIDRs"]
            .as_array()
            .into_iter()
            .flatten()
            .chain([&spec["podCIDR"]]);
        for c in cidrs.filter_map(|c| c.as_str()) {
            let Some((base, len)) = c.split_once('/') else {
                continue;
            };
            if let (Ok(base), Ok(len)) = (base.parse::<IpAddr>(), len.parse::<u8>()) {
                let base = base.to_canonical();
                if len <= if base.is_ipv4() { 32 } else { 128 } {
                    self.pod_cidrs.push((name.to_string(), base, len));
                }
            }
        }
    }

    fn check_ip(&self, ip: IpAddr, node_name: &str) -> Result<(), String> {
        let ip = ip.to_canonical();
        let special = match ip {
            IpAddr::V4(v) => {
                v.is_loopback() || v.is_unspecified() || v.is_link_local() || v.is_multicast()
            }
            IpAddr::V6(v) => {
                v.is_loopback()
                    || v.is_unspecified()
                    || v.is_unicast_link_local()
                    || v.is_multicast()
            }
        };
        if special {
            return Err(format!(
                "IP SAN {ip} is loopback, unspecified, link-local or multicast"
            ));
        }
        for (base, size) in &self.service_cidrs {
            let off = match (ip, base) {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    u32::from(a).checked_sub(u32::from(*b)).map(u128::from)
                }
                (IpAddr::V6(a), IpAddr::V6(b)) => u128::from(a).checked_sub(u128::from(*b)),
                _ => None,
            };
            if off.is_some_and(|o| o < *size) {
                return Err(format!("IP SAN {ip} is inside the service CIDR"));
            }
        }
        for (owner, base, len) in &self.pod_cidrs {
            if cidr_contains(*base, *len, ip) {
                return Err(format!(
                    "IP SAN {ip} is inside Node {owner}'s podCIDR {base}/{len}"
                ));
            }
        }
        if self.apiserver_ips.iter().any(|a| a.to_canonical() == ip) {
            return Err(format!("IP SAN {ip} is the apiserver's own address"));
        }
        if self.other_node_ips.contains(&ip) {
            return Err(format!(
                "IP SAN {ip} is also reported by another Node, not only {node_name:?}"
            ));
        }
        Ok(())
    }
}

pub(crate) fn cidr_contains(base: IpAddr, len: u8, ip: IpAddr) -> bool {
    let (b, i, bits) = match (base, ip) {
        (IpAddr::V4(b), IpAddr::V4(i)) => (u128::from(u32::from(b)), u128::from(u32::from(i)), 32),
        (IpAddr::V6(b), IpAddr::V6(i)) => (u128::from(b), u128::from(i), 128),
        _ => return false,
    };
    let host_bits = u32::from(bits - len);
    host_bits >= 128 || (b >> host_bits) == (i >> host_bits)
}

/// Every GeneralName from every SAN extension in the CSR's extensionRequest attributes.
/// Undecodable extension data fails closed.
fn subject_alt_names(req: &CertReq) -> Result<Vec<GeneralName>, String> {
    let mut out = Vec::new();
    for attr in req.info.attributes.iter() {
        if attr.oid != ExtensionReq::OID {
            continue;
        }
        for value in attr.values.iter() {
            let exts: Vec<Extension> = value
                .decode_as()
                .map_err(|e| format!("undecodable extensionRequest: {e}"))?;
            for ext in exts.iter().filter(|e| e.extn_id == SubjectAltName::OID) {
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| format!("undecodable SAN extension: {e}"))?;
                out.extend(san.0);
            }
        }
    }
    Ok(out)
}

fn ip_from_octets(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => <[u8; 4]>::try_from(b).ok().map(IpAddr::from),
        16 => <[u8; 16]>::try_from(b).ok().map(IpAddr::from),
        _ => None,
    }
}

fn node_addresses(
    node: &serde_json::Value,
    node_name: &str,
) -> (BTreeSet<String>, BTreeSet<IpAddr>) {
    let mut dns = BTreeSet::from([node_name.to_string()]);
    let mut ips = BTreeSet::new();
    for a in node["status"]["addresses"].as_array().into_iter().flatten() {
        let Some(addr) = a["address"].as_str() else {
            continue;
        };
        match a["type"].as_str() {
            Some("Hostname" | "InternalDNS" | "ExternalDNS") => {
                dns.insert(addr.to_string());
            }
            Some("InternalIP" | "ExternalIP") => {
                if let Ok(ip) = addr.parse() {
                    ips.insert(ip);
                }
            }
            _ => {}
        }
    }
    (dns, ips)
}

fn is_undecided(csr: &serde_json::Value) -> bool {
    csr["spec"]["signerName"].as_str() == Some(KUBELET_SERVING_SIGNER)
        && csr["status"]["certificate"]
            .as_str()
            .unwrap_or("")
            .is_empty()
        && !csr["status"]["conditions"].as_array().is_some_and(|c| {
            c.iter()
                .any(|c| matches!(c["type"].as_str(), Some("Approved" | "Denied" | "Failed")))
        })
}

/// The apiserver addresses a serving-cert IP SAN must avoid for `node_name`. The node
/// co-located with the apiserver legitimately owns that address (single-node installs run
/// the kubelet on the apiserver's own IP) and already shares the CA key's host, so the
/// guard does not apply to it; every other node, which could be a worker claiming the
/// apiserver's address to impersonate it, keeps the full list.
fn forbidden_apiserver_ips<'a>(
    apiserver_ips: &'a [IpAddr],
    node_name: &str,
    local_node_name: Option<&str>,
) -> &'a [IpAddr] {
    if !node_name.is_empty() && local_node_name == Some(node_name) {
        &[]
    } else {
        apiserver_ips
    }
}

/// One sweep: approve every undecided kubelet-serving CSR that passes [`evaluate`].
pub(crate) async fn approve_kubelet_serving_csrs<S: Store>(
    state: &AppState<S>,
    apiserver_ips: &[IpAddr],
    local_node_name: Option<&str>,
) {
    let prefix = group_list_prefix(GROUP, PLURAL, None);
    let Ok(resp) = state.store.list(&prefix, ListOptions::default()).await else {
        return;
    };
    for item in &resp.items {
        let Ok(mut csr) = serde_json::from_slice::<serde_json::Value>(&item.value) else {
            continue;
        };
        if !is_undecided(&csr) {
            continue;
        }
        let name = csr["metadata"]["name"].as_str().unwrap_or("").to_string();
        let node_name = csr["spec"]["username"]
            .as_str()
            .and_then(|u| u.strip_prefix(NODE_USER_PREFIX))
            .unwrap_or("");
        let Ok(nodes) = state
            .store
            .list(&cluster_list_prefix("nodes"), ListOptions::default())
            .await
        else {
            return;
        };
        let mut node = None;
        let mut ctx = IpContext {
            service_cidrs: state
                .service_ip_allocators()
                .iter()
                .map(|a| (a.base, a.size))
                .collect(),
            apiserver_ips: forbidden_apiserver_ips(apiserver_ips, node_name, local_node_name)
                .to_vec(),
            ..Default::default()
        };
        for n in &nodes.items {
            let Ok(n) = serde_json::from_slice::<serde_json::Value>(&n.value) else {
                continue;
            };
            ctx.add_pod_cidrs(&n);
            if n["metadata"]["name"].as_str() == Some(node_name) {
                node = Some(n);
                continue;
            }
            for a in n["status"]["addresses"].as_array().into_iter().flatten() {
                if let Some(ip) = a["address"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) {
                    ctx.other_node_ips.insert(ip.to_canonical());
                }
            }
        }
        if let Err(reason) = evaluate(&csr, node.as_ref(), &ctx) {
            tracing::debug!("kubelet-serving CSR {name} left pending: {reason}");
            continue;
        }
        let now = crate::util::utc_now_rfc3339();
        let mut conditions = csr["status"]["conditions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        conditions.push(serde_json::json!({
            "type": "Approved",
            "status": "True",
            "reason": "AutoApproved",
            "message": "Auto approving kubelet serving certificate: requestor, subject, usages and SANs match the requesting node",
            "lastUpdateTime": now,
            "lastTransitionTime": now,
        }));
        csr["status"]["conditions"] = serde_json::Value::Array(conditions);
        if let Err(e) = state
            .store
            .put(
                &item.key,
                bytes::Bytes::from(csr.to_string()),
                Some(item.revision),
            )
            .await
        {
            tracing::debug!("kubelet-serving CSR {name}: approve put failed: {e}");
        } else {
            tracing::info!("auto-approved kubelet-serving CSR {name}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_support::make_state;
    use crate::keys::cluster_object_key;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    const NODE_IP: &str = "192.168.5.15";

    fn request(cn: &str, orgs: &[&str], sans: Vec<SanType>) -> String {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, cn);
        for o in orgs {
            params.distinguished_name.push(DnType::OrganizationName, *o);
        }
        params.subject_alt_names = sans;
        let pem = params
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(pem)
    }

    fn dns(n: &str) -> SanType {
        SanType::DnsName(n.try_into().unwrap())
    }

    fn ip(a: &str) -> SanType {
        SanType::IpAddress(a.parse().unwrap())
    }

    fn csr_json(
        username: &str,
        groups: &[&str],
        usages: &[&str],
        request: String,
    ) -> serde_json::Value {
        serde_json::json!({
            "metadata": {"name": "csr-1"},
            "spec": {
                "request": request,
                "signerName": KUBELET_SERVING_SIGNER,
                "username": username,
                "groups": groups,
                "usages": usages,
            }
        })
    }

    fn refused(csr: &serde_json::Value, needle: &str) {
        let why =
            evaluate(csr, Some(&node()), &IpContext::default()).expect_err("CSR must stay pending");
        assert!(why.contains(needle), "refused for the wrong reason: {why}");
    }

    fn good_csr() -> serde_json::Value {
        csr_json(
            "system:node:n1",
            &["system:nodes", "system:authenticated"],
            &["digital signature", "server auth"],
            request(
                "system:node:n1",
                &["system:nodes"],
                vec![dns("n1"), ip(NODE_IP)],
            ),
        )
    }

    fn node() -> serde_json::Value {
        serde_json::json!({
            "metadata": {"name": "n1"},
            "status": {"addresses": [
                {"type": "InternalIP", "address": NODE_IP},
                {"type": "Hostname", "address": "n1.internal"},
            ]}
        })
    }

    #[test]
    fn approves_a_csr_whose_identity_and_sans_all_belong_to_the_requesting_node() {
        evaluate(&good_csr(), Some(&node()), &IpContext::default())
            .expect("a node's own serving CSR must be auto-approved");
        let mut csr = good_csr();
        csr["spec"]["usages"] =
            serde_json::json!(["digital signature", "key encipherment", "server auth"]);
        evaluate(&csr, Some(&node()), &IpContext::default())
            .expect("RSA usage set must be accepted");
        let mut csr = good_csr();
        csr["spec"]["request"] = request(
            "system:node:n1",
            &["system:nodes"],
            vec![dns("n1.internal")],
        )
        .into();
        evaluate(&csr, Some(&node()), &IpContext::default())
            .expect("a hostname the Node reports is the node's own");
    }

    #[test]
    fn requestor_that_is_not_a_node_cannot_get_a_serving_cert_even_for_a_matching_subject() {
        let mut csr = good_csr();
        csr["spec"]["username"] = "alice".into();
        refused(&csr, "is not system:node");
        let mut csr = good_csr();
        csr["spec"]["groups"] = serde_json::json!(["system:authenticated"]);
        refused(&csr, "not in group");
    }

    #[test]
    fn node_cannot_request_a_serving_cert_with_another_nodes_cn_or_extra_subject_data() {
        let mut csr = good_csr();
        csr["spec"]["request"] =
            request("system:node:n2", &["system:nodes"], vec![dns("n1")]).into();
        refused(&csr, "CN");
        let mut csr = good_csr();
        csr["spec"]["request"] =
            request("system:node:n1", &["system:masters"], vec![dns("n1")]).into();
        refused(&csr, "subject O");
        let mut csr = good_csr();
        csr["spec"]["request"] = request(
            "system:node:n1",
            &["system:nodes", "system:masters"],
            vec![dns("n1")],
        )
        .into();
        refused(&csr, "subject O");
    }

    #[test]
    fn extra_usage_such_as_client_auth_is_refused_so_a_serving_cert_cannot_double_as_a_client_cert()
    {
        let mut csr = good_csr();
        csr["spec"]["usages"] =
            serde_json::json!(["digital signature", "server auth", "client auth"]);
        refused(&csr, "usages");
    }

    #[test]
    fn foreign_dns_san_is_refused_because_it_would_let_a_node_impersonate_another_node() {
        let mut csr = good_csr();
        csr["spec"]["request"] = request(
            "system:node:n1",
            &["system:nodes"],
            vec![dns("n1"), dns("n2")],
        )
        .into();
        refused(&csr, "DNS SAN");
    }

    #[test]
    fn ip_san_outside_the_nodes_addresses_is_refused_because_it_would_let_a_node_impersonate_another_nodes_ip(
    ) {
        let mut csr = good_csr();
        csr["spec"]["request"] = request(
            "system:node:n1",
            &["system:nodes"],
            vec![dns("n1"), ip("192.168.5.99")],
        )
        .into();
        refused(&csr, "IP SAN");
    }

    #[test]
    fn uri_san_is_refused_because_it_could_name_a_non_node_identity() {
        let mut csr = good_csr();
        csr["spec"]["request"] = request(
            "system:node:n1",
            &["system:nodes"],
            vec![
                dns("n1"),
                SanType::URI("spiffe://cluster/other".try_into().unwrap()),
            ],
        )
        .into();
        refused(&csr, "SAN of a type");
    }

    #[test]
    fn csr_without_any_dns_or_ip_san_stays_pending() {
        let mut csr = good_csr();
        csr["spec"]["request"] = request("system:node:n1", &["system:nodes"], vec![]).into();
        refused(&csr, "no DNS or IP SAN");
    }

    #[test]
    fn missing_node_leaves_the_csr_pending_so_the_kubelet_retries_after_registering() {
        let why = evaluate(&good_csr(), None, &IpContext::default()).unwrap_err();
        assert!(why.contains("does not exist"), "{why}");
    }

    async fn seed(state: &AppState, key: &str, v: &serde_json::Value) {
        state
            .store
            .put(key, bytes::Bytes::from(v.to_string()), None)
            .await
            .unwrap();
    }

    async fn conditions(state: &AppState, name: &str) -> serde_json::Value {
        let key = crate::keys::group_object_key(GROUP, PLURAL, None, name);
        let got = state.store.get(&key).await.unwrap().unwrap();
        serde_json::from_slice::<serde_json::Value>(&got.value).unwrap()["status"]["conditions"]
            .clone()
    }

    #[tokio::test]
    async fn sweep_approves_the_matching_csr_and_leaves_the_foreign_one_pending() {
        let state = make_state();
        seed(&state, &cluster_object_key("nodes", "n1"), &node()).await;
        let mut ok = good_csr();
        ok["metadata"]["name"] = "ok".into();
        let mut bad = good_csr();
        bad["metadata"]["name"] = "bad".into();
        bad["spec"]["request"] = request(
            "system:node:n1",
            &["system:nodes"],
            vec![dns("n1"), ip("10.9.9.9")],
        )
        .into();
        for c in [&ok, &bad] {
            let name = c["metadata"]["name"].as_str().unwrap();
            seed(
                &state,
                &crate::keys::group_object_key(GROUP, PLURAL, None, name),
                c,
            )
            .await;
        }
        approve_kubelet_serving_csrs(&state, &[], None).await;
        assert_eq!(conditions(&state, "ok").await[0]["type"], "Approved");
        assert!(
            conditions(&state, "bad").await.is_null(),
            "a CSR with a foreign IP SAN must never be approved or denied"
        );
        approve_kubelet_serving_csrs(&state, &[], None).await;
        assert_eq!(
            conditions(&state, "ok").await.as_array().unwrap().len(),
            1,
            "an already-approved CSR must not collect duplicate conditions"
        );
    }

    fn node_named(name: &str, ips: &[&str]) -> serde_json::Value {
        let addrs: Vec<_> = ips
            .iter()
            .map(|a| serde_json::json!({"type": "InternalIP", "address": a}))
            .collect();
        serde_json::json!({"metadata": {"name": name}, "status": {"addresses": addrs}})
    }

    fn serving_csr_for(node: &str, ips: &[&str]) -> serde_json::Value {
        let mut sans = vec![dns(node)];
        sans.extend(ips.iter().map(|a| ip(a)));
        let mut csr = csr_json(
            &format!("system:node:{node}"),
            &["system:nodes"],
            &["digital signature", "server auth"],
            request(&format!("system:node:{node}"), &["system:nodes"], sans),
        );
        csr["metadata"]["name"] = format!("csr-{node}").into();
        csr
    }

    #[tokio::test]
    async fn node_that_writes_another_nodes_ip_into_its_own_status_cannot_get_a_serving_cert_for_it(
    ) {
        // Nodes may write their own status.addresses, so a compromised n2 can claim n1's IP
        // and would otherwise be issued a cert that impersonates n1 for logs/exec.
        let state = make_state();
        seed(
            &state,
            &cluster_object_key("nodes", "n1"),
            &node_named("n1", &["192.168.5.15"]),
        )
        .await;
        seed(
            &state,
            &cluster_object_key("nodes", "n2"),
            &node_named("n2", &["192.168.5.16", "192.168.5.15"]),
        )
        .await;
        let attack = serving_csr_for("n2", &["192.168.5.15"]);
        seed(
            &state,
            &crate::keys::group_object_key(GROUP, PLURAL, None, "csr-n2"),
            &attack,
        )
        .await;
        approve_kubelet_serving_csrs(&state, &[], None).await;
        assert!(
            conditions(&state, "csr-n2").await.is_null(),
            "an IP reported by two Nodes must not be approved for either"
        );
    }

    #[tokio::test]
    async fn node_with_a_unique_ip_is_approved_alongside_other_nodes() {
        let state = make_state();
        seed(
            &state,
            &cluster_object_key("nodes", "n1"),
            &node_named("n1", &["192.168.5.15"]),
        )
        .await;
        seed(
            &state,
            &cluster_object_key("nodes", "n2"),
            &node_named("n2", &["192.168.5.16"]),
        )
        .await;
        let csr = serving_csr_for("n2", &["192.168.5.16"]);
        seed(
            &state,
            &crate::keys::group_object_key(GROUP, PLURAL, None, "csr-n2"),
            &csr,
        )
        .await;
        approve_kubelet_serving_csrs(&state, &[], None).await;
        assert_eq!(conditions(&state, "csr-n2").await[0]["type"], "Approved");
    }

    async fn sweep_for_apiserver_address(csr_node: &str, local_node_name: Option<&str>) -> bool {
        let state = make_state();
        let apiserver: IpAddr = "192.168.5.15".parse().unwrap();
        seed(
            &state,
            &cluster_object_key("nodes", csr_node),
            &node_named(csr_node, &["192.168.5.15"]),
        )
        .await;
        let key = crate::keys::group_object_key(GROUP, PLURAL, None, &format!("csr-{csr_node}"));
        seed(&state, &key, &serving_csr_for(csr_node, &["192.168.5.15"])).await;
        approve_kubelet_serving_csrs(&state, &[apiserver], local_node_name).await;
        !conditions(&state, &format!("csr-{csr_node}"))
            .await
            .is_null()
    }

    #[tokio::test]
    async fn single_node_kubelet_gets_a_serving_cert_for_the_apiserver_address_it_runs_on() {
        // Otherwise the only node of an install.sh cluster has no serving cert and
        // logs/exec fail until an operator approves by hand.
        assert!(sweep_for_apiserver_address("cp", Some("cp")).await);
    }

    #[tokio::test]
    async fn any_other_node_claiming_the_apiserver_address_stays_pending_so_it_cannot_impersonate_the_apiserver(
    ) {
        assert!(
            !sweep_for_apiserver_address("worker", Some("cp")).await,
            "a non-local node must not get the apiserver's IP in a CA-signed serving cert"
        );
        assert!(
            !sweep_for_apiserver_address("cp", None).await,
            "without a configured local node name the guard stays on for every node"
        );
    }

    #[tokio::test]
    async fn join_token_requestor_gets_no_apiserver_ip_serving_cert_even_under_the_local_node_name()
    {
        // Residual of the node-name exemption: a bootstrap-token identity (the only thing a
        // joiner holds once it cannot enroll as the control-plane node) must never be
        // approved for the apiserver's IP, whatever name it puts in the CSR.
        let state = make_state();
        let apiserver: IpAddr = "192.168.5.15".parse().unwrap();
        seed(
            &state,
            &cluster_object_key("nodes", "cp"),
            &node_named("cp", &["192.168.5.15"]),
        )
        .await;
        let mut csr = serving_csr_for("cp", &["192.168.5.15"]);
        csr["spec"]["username"] = "system:bootstrap:abcdef".into();
        csr["spec"]["groups"] = serde_json::json!(["system:bootstrappers"]);
        let key = crate::keys::group_object_key(GROUP, PLURAL, None, "csr-cp");
        seed(&state, &key, &csr).await;
        approve_kubelet_serving_csrs(&state, &[apiserver], Some("cp")).await;
        assert!(conditions(&state, "csr-cp").await.is_null());
    }

    #[test]
    fn forbidden_apiserver_ips_is_lifted_only_for_the_exact_local_node_name() {
        let ips: Vec<IpAddr> = vec!["192.168.5.15".parse().unwrap()];
        assert!(forbidden_apiserver_ips(&ips, "cp", Some("cp")).is_empty());
        assert_eq!(forbidden_apiserver_ips(&ips, "worker", Some("cp")), ips);
        assert_eq!(forbidden_apiserver_ips(&ips, "cp", None), ips);
        assert_eq!(
            forbidden_apiserver_ips(&ips, "", Some("")),
            ips,
            "a CSR whose requestor is not a node has an empty node name and must not match an empty flag"
        );
    }

    fn with_pod_cidrs(mut node: serde_json::Value, cidrs: &[&str]) -> serde_json::Value {
        node["spec"] = serde_json::json!({"podCIDR": cidrs[0], "podCIDRs": cidrs});
        node
    }

    async fn sweep_decision(nodes: &[serde_json::Value], csr_node: &str, ip: &str) -> bool {
        let state = make_state();
        for n in nodes {
            let name = n["metadata"]["name"].as_str().unwrap();
            seed(&state, &cluster_object_key("nodes", name), n).await;
        }
        let csr = serving_csr_for(csr_node, &[ip]);
        let key = crate::keys::group_object_key(GROUP, PLURAL, None, &format!("csr-{csr_node}"));
        seed(&state, &key, &csr).await;
        approve_kubelet_serving_csrs(&state, &[], None).await;
        !conditions(&state, &format!("csr-{csr_node}"))
            .await
            .is_null()
    }

    #[tokio::test]
    async fn serving_cert_for_an_ip_in_another_nodes_pod_range_stays_pending_so_a_pod_ip_cannot_be_impersonated(
    ) {
        let n1 = with_pod_cidrs(node_named("n1", &["192.168.5.15"]), &["10.244.1.0/24"]);
        // n2 claims a pod IP of n1's range as its own address.
        let n2 = with_pod_cidrs(node_named("n2", &["10.244.1.7"]), &["10.244.2.0/24"]);
        assert!(!sweep_decision(&[n1, n2], "n2", "10.244.1.7").await);
    }

    #[tokio::test]
    async fn serving_cert_for_an_ip_in_the_nodes_own_pod_range_stays_pending() {
        let n1 = with_pod_cidrs(node_named("n1", &["10.244.1.9"]), &["10.244.1.0/24"]);
        assert!(!sweep_decision(&[n1], "n1", "10.244.1.9").await);
    }

    #[tokio::test]
    async fn ipv6_pod_range_is_excluded_too_including_the_legacy_single_podcidr_field() {
        let mut n1 = node_named("n1", &["fd00:1::5"]);
        n1["spec"] = serde_json::json!({"podCIDR": "fd00:1::/64"});
        assert!(!sweep_decision(&[n1], "n1", "fd00:1::5").await);
        let n2 = with_pod_cidrs(
            node_named("n2", &["fd00:2::5"]),
            &["10.244.2.0/24", "fd00:2::/64"],
        );
        assert!(!sweep_decision(&[n2], "n2", "fd00:2::5").await);
    }

    #[tokio::test]
    async fn ip_just_outside_every_pod_range_is_still_approved() {
        let n1 = with_pod_cidrs(
            node_named("n1", &["10.244.3.0"]),
            &["10.244.1.0/24", "fd00:1::/64"],
        );
        let n2 = with_pod_cidrs(node_named("n2", &["10.244.0.255"]), &["10.244.2.0/24"]);
        assert!(sweep_decision(&[n1.clone(), n2.clone()], "n1", "10.244.3.0").await);
        assert!(sweep_decision(&[n1, n2], "n2", "10.244.0.255").await);
    }

    #[tokio::test]
    async fn node_without_a_pod_cidr_yet_neither_blocks_nor_breaks_approval() {
        let n1 = node_named("n1", &["192.168.5.15"]);
        let mut n2 = node_named("n2", &["192.168.5.16"]);
        n2["spec"] = serde_json::json!({"podCIDRs": []});
        assert!(sweep_decision(&[n1, n2], "n1", "192.168.5.15").await);
    }

    #[test]
    fn ips_that_name_the_cluster_rather_than_a_node_are_refused_even_when_the_node_claims_them() {
        let ctx = IpContext {
            service_cidrs: vec![("10.96.0.0".parse().unwrap(), 1 << 20)],
            apiserver_ips: vec!["192.168.5.1".parse().unwrap()],
            ..Default::default()
        };
        for (addr, needle) in [
            ("10.96.0.1", "service CIDR"),
            ("10.100.3.4", "service CIDR"),
            ("192.168.5.1", "apiserver"),
            ("127.0.0.1", "loopback"),
            ("169.254.1.2", "link-local"),
            ("224.0.0.1", "multicast"),
            ("0.0.0.0", "unspecified"),
            ("fe80::1", "link-local"),
        ] {
            let node = node_named("n1", &[addr]);
            let csr = serving_csr_for("n1", &[addr]);
            let why = evaluate(&csr, Some(&node), &ctx).expect_err(addr);
            assert!(why.contains(needle), "{addr}: {why}");
        }
        let node = node_named("n1", &["10.112.0.0"]);
        let csr = serving_csr_for("n1", &["10.112.0.0"]);
        evaluate(&csr, Some(&node), &ctx).expect("an IP just outside the service CIDR is fine");
    }
}
