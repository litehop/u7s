//! Read-only discovery of a source cluster over its API.

use std::collections::BTreeSet;

use anyhow::{bail, Context};
use hyper::Method;
use politeia::HyperApiClient;
use serde_json::Value;

/// Never listed: these are classified as not migrated regardless of content,
/// and listing events or an aggregated API is slow or can fail on its own.
const NOT_LISTED: &[(&str, &str)] = &[
    ("metrics.k8s.io", ""),
    ("", "Event"),
    ("events.k8s.io", "Event"),
    ("", "ComponentStatus"),
];

const PAGE: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceType {
    pub group: String,
    pub version: String,
    pub plural: String,
    pub kind: String,
    pub namespaced: bool,
}

impl ResourceType {
    pub fn api_version(&self) -> String {
        if self.group.is_empty() {
            self.version.clone()
        } else {
            format!("{}/{}", self.group, self.version)
        }
    }

    fn base_path(&self) -> String {
        if self.group.is_empty() {
            format!("/api/{}/{}", self.version, self.plural)
        } else {
            format!("/apis/{}/{}/{}", self.group, self.version, self.plural)
        }
    }

    fn listed(&self) -> bool {
        !NOT_LISTED
            .iter()
            .any(|(g, k)| *g == self.group && (k.is_empty() || *k == self.kind))
    }
}

/// Resource types in one group-version's discovery document that support
/// `list`; subresources (`pods/log`) are never top-level objects.
pub fn parse_resources(group: &str, version: &str, doc: &Value) -> Vec<ResourceType> {
    doc["resources"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| {
            let n = r["name"].as_str().unwrap_or_default();
            !n.contains('/')
                && r["verbs"]
                    .as_array()
                    .is_some_and(|v| v.iter().any(|v| v == "list"))
        })
        .filter_map(|r| {
            Some(ResourceType {
                group: group.to_string(),
                version: version.to_string(),
                plural: r["name"].as_str()?.to_string(),
                kind: r["kind"].as_str()?.to_string(),
                namespaced: r["namespaced"].as_bool().unwrap_or(false),
            })
        })
        .collect()
}

/// Union of every Node's `spec.podCIDRs`.
pub fn pod_cidrs(nodes: &[Value]) -> Vec<String> {
    let set: BTreeSet<&str> = nodes
        .iter()
        .flat_map(|n| n["spec"]["podCIDRs"].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .collect();
    set.into_iter().map(str::to_string).collect()
}

/// `spec.cidrs` of the `kubernetes` ServiceCIDR among `objs`.
pub fn service_cidrs(objs: &[Value]) -> Vec<String> {
    objs.iter()
        .find(|o| o["kind"] == "ServiceCIDR" && o["metadata"]["name"] == "kubernetes")
        .and_then(|o| o["spec"]["cidrs"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|c| c.as_str().map(str::to_string))
        .collect()
}

/// ClusterIP of `kube-system/kube-dns` among `objs`.
pub fn kube_dns_cluster_ip(objs: &[Value]) -> Option<String> {
    objs.iter()
        .find(|o| {
            o["kind"] == "Service"
                && o["apiVersion"] == "v1"
                && o["metadata"]["namespace"] == "kube-system"
                && o["metadata"]["name"] == "kube-dns"
        })
        .and_then(|o| o["spec"]["clusterIP"].as_str())
        .map(str::to_string)
}

/// The source's k3s version from its single Node's kubelet version.
pub fn k3s_version(nodes: &[Value]) -> anyhow::Result<String> {
    match nodes {
        [] => bail!("source cluster has no Node"),
        [n] => {
            let v = n["status"]["nodeInfo"]["kubeletVersion"]
                .as_str()
                .context("Node has no status.nodeInfo.kubeletVersion")?;
            if !v.contains("+k3s") {
                bail!("source kubelet version {v} is not k3s; only k3s is supported");
            }
            Ok(v.to_string())
        }
        _ => bail!(
            "source has {} Nodes; only single-node k3s clusters are supported",
            nodes.len()
        ),
    }
}

pub struct Source {
    pub(crate) client: HyperApiClient,
}

pub struct Listing {
    pub objects: Vec<Value>,
    /// `resource: error` for every list that failed; the plan is incomplete
    /// when this is non-empty.
    pub failures: Vec<String>,
}

impl Source {
    pub fn connect(kubeconfig: &str) -> anyhow::Result<Self> {
        // Presents the whole client certificate chain: u7s admin leaves are
        // signed by an intermediate the apiserver does not trust directly.
        Ok(Self {
            client: politeia::kubeconfig_client_with_reload(kubeconfig, None)?,
        })
    }

    async fn get(&self, path: &str) -> anyhow::Result<Value> {
        let (status, body) = self.client.request(Method::GET, path, None).await?;
        if !status.is_success() {
            bail!(
                "GET {path}: {status}: {}",
                body.chars().take(200).collect::<String>()
            );
        }
        serde_json::from_str(&body).with_context(|| format!("GET {path}: invalid JSON"))
    }

    /// Every listable resource type, preferred version per group.
    pub async fn resource_types(&self) -> anyhow::Result<(Vec<ResourceType>, Vec<String>)> {
        let mut gvs: Vec<(String, String)> = vec![];
        for v in self.get("/api").await?["versions"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if let Some(v) = v.as_str() {
                gvs.push((String::new(), v.to_string()));
            }
        }
        for g in self.get("/apis").await?["groups"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let group = g["name"].as_str().unwrap_or_default();
            if let Some(v) = g["preferredVersion"]["version"].as_str() {
                gvs.push((group.to_string(), v.to_string()));
            }
        }
        let mut types = vec![];
        let mut failures = vec![];
        for (g, v) in gvs {
            if g == "metrics.k8s.io" {
                continue;
            }
            let path = if g.is_empty() {
                format!("/api/{v}")
            } else {
                format!("/apis/{g}/{v}")
            };
            match self.get(&path).await {
                Ok(doc) => types.extend(parse_resources(&g, &v, &doc)),
                Err(e) => failures.push(format!("discovery {path}: {e:#}")),
            }
        }
        Ok((types, failures))
    }

    /// Lists all objects of every type in `types`, cluster-wide, paginated.
    pub async fn list_all(&self, types: &[ResourceType]) -> Listing {
        let mut objects = vec![];
        let mut failures = vec![];
        for t in types.iter().filter(|t| t.listed()) {
            match self.list(t).await {
                Ok(items) => objects.extend(items),
                Err(e) => failures.push(format!("{}: {e:#}", t.plural)),
            }
        }
        Listing { objects, failures }
    }

    async fn list(&self, t: &ResourceType) -> anyhow::Result<Vec<Value>> {
        let mut items = self.list_path(&t.base_path()).await?;
        for item in &mut items {
            item["apiVersion"] = t.api_version().into();
            item["kind"] = t.kind.clone().into();
        }
        Ok(items)
    }

    /// Every item under the collection path `base`, paginated.
    pub(crate) async fn list_path(&self, base: &str) -> anyhow::Result<Vec<Value>> {
        let mut out = vec![];
        let mut cont = String::new();
        loop {
            let mut path = format!("{base}?limit={PAGE}");
            if !cont.is_empty() {
                path.push_str(&format!("&continue={}", encode(&cont)));
            }
            let mut page = self.get(&path).await?;
            out.extend(page["items"].take().as_array().cloned().unwrap_or_default());
            cont = page["metadata"]["continue"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if cont.is_empty() {
                return Ok(out);
            }
        }
    }
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn source_connects_with_kubeconfig_referencing_relative_cert_files() {
        let dir = std::env::temp_dir().join(format!("u7s-migrate-filepath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("pki")).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.join("pki/ca.crt"), cert.pem()).unwrap();
        std::fs::write(dir.join("pki/client.crt"), cert.pem()).unwrap();
        std::fs::write(dir.join("pki/client.key"), key.serialize_pem()).unwrap();
        let kc = dir.join("kubeconfig");
        std::fs::write(
            &kc,
            "apiVersion: v1\nkind: Config\ncurrent-context: c\n\
             clusters:\n- name: c\n  cluster:\n    server: https://127.0.0.1:6443\n    certificate-authority: pki/ca.crt\n\
             users:\n- name: u\n  user:\n    client-certificate: pki/client.crt\n    client-key: pki/client.key\n\
             contexts:\n- name: c\n  context: {cluster: c, user: u}\n",
        )
        .unwrap();
        let connected = Source::connect(kc.to_str().unwrap()).map(|_| ());
        let _ = std::fs::remove_dir_all(&dir);
        connected.expect(
            "k3s/kubeadm kubeconfigs reference cert files by path; migrate must accept them",
        );
    }

    #[test]
    fn only_listable_top_level_resources_are_enumerated() {
        let doc = json!({"resources": [
            {"name": "pods", "kind": "Pod", "verbs": ["get", "list"]},
            {"name": "pods/log", "kind": "Pod", "verbs": ["get", "list"]},
            {"name": "bindings", "kind": "Binding", "verbs": ["create"]},
        ]});
        let r = parse_resources("", "v1", &doc);
        assert_eq!(
            r.iter().map(|r| r.plural.as_str()).collect::<Vec<_>>(),
            ["pods"],
            "subresources and non-list resources would be fetched as objects that do not exist"
        );
    }

    #[test]
    fn pod_cidr_is_the_deduplicated_union_over_nodes() {
        let nodes = [
            json!({"spec": {"podCIDRs": ["10.42.0.0/24"]}}),
            json!({"spec": {"podCIDRs": ["10.42.0.0/24", "fd00::/64"]}}),
            json!({"spec": {}}),
        ];
        assert_eq!(pod_cidrs(&nodes), ["10.42.0.0/24", "fd00::/64"]);
    }

    #[test]
    fn source_must_be_one_k3s_node() {
        let node = |v: &str| json!({"status": {"nodeInfo": {"kubeletVersion": v}}});
        assert_eq!(
            k3s_version(&[node("v1.36.5+k3s1")]).unwrap(),
            "v1.36.5+k3s1"
        );
        assert!(
            k3s_version(&[node("v1.36.5")]).is_err(),
            "k0s/kubeadm sources are unverified"
        );
        assert!(k3s_version(&[node("v1.36.5+k3s1"), node("v1.36.5+k3s1")]).is_err());
        assert!(k3s_version(&[]).is_err());
    }

    #[test]
    fn continue_token_is_percent_encoded() {
        assert_eq!(encode("a+b/c=="), "a%2Bb%2Fc%3D%3D");
    }
}
