use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// API wire types — v1 discovery
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ServerAddressByClientCIDR {
    #[serde(rename = "clientCIDR")]
    pub client_cidr: &'static str,
    #[serde(rename = "serverAddress")]
    pub server_address: &'static str,
}

/// Wire representation of `/api` response.
#[derive(Debug, Serialize)]
pub struct APIVersions {
    pub kind: &'static str,
    #[serde(rename = "apiVersion")]
    pub api_version: &'static str,
    pub versions: &'static [&'static str],
    #[serde(rename = "serverAddressByClientCIDRs")]
    pub server_address_by_client_cidrs: &'static [ServerAddressByClientCIDR],
}

static SERVER_ADDRESS_BY_CLIENT_CIDRS: &[ServerAddressByClientCIDR] = &[
    ServerAddressByClientCIDR {
        client_cidr: "0.0.0.0/0",
        server_address: "https://127.0.0.1:6443",
    },
];

impl APIVersions {
    pub fn v1() -> Self {
        APIVersions {
            kind: "APIVersions",
            api_version: "v1",
            versions: &["v1"],
            server_address_by_client_cidrs: SERVER_ADDRESS_BY_CLIENT_CIDRS,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApiResource {
    pub name: &'static str,
    #[serde(rename = "singularName")]
    pub singular_name: &'static str,
    pub namespaced: bool,
    pub kind: &'static str,
    pub verbs: &'static [&'static str],
    #[serde(rename = "shortNames", skip_serializing_if = "Option::is_none")]
    pub short_names: Option<&'static [&'static str]>,
}

/// Wire representation of `/api/v1` response.
#[derive(Debug, Serialize)]
pub struct ApiResourceList {
    pub kind: &'static str,
    #[serde(rename = "apiVersion")]
    pub api_version: &'static str,
    #[serde(rename = "groupVersion")]
    pub group_version: &'static str,
    pub resources: &'static [ApiResource],
}

static CORE_VERBS: &[&str] = &["create", "delete", "get", "list", "patch", "update"];
static PODS_SHORT_NAMES: &[&str] = &["po"];
static NODES_SHORT_NAMES: &[&str] = &["no"];
static SERVICES_SHORT_NAMES: &[&str] = &["svc"];
static SERVICE_ACCOUNTS_SHORT_NAMES: &[&str] = &["sa"];
static CONFIG_MAPS_SHORT_NAMES: &[&str] = &["cm"];

static V1_RESOURCES: &[ApiResource] = &[
    ApiResource {
        name: "configmaps",
        singular_name: "configmap",
        namespaced: true,
        kind: "ConfigMap",
        verbs: CORE_VERBS,
        short_names: Some(CONFIG_MAPS_SHORT_NAMES),
    },
    ApiResource {
        name: "events",
        singular_name: "event",
        namespaced: true,
        kind: "Event",
        verbs: CORE_VERBS,
        short_names: None,
    },
    ApiResource {
        name: "nodes",
        singular_name: "node",
        namespaced: false,
        kind: "Node",
        verbs: CORE_VERBS,
        short_names: Some(NODES_SHORT_NAMES),
    },
    ApiResource {
        name: "pods",
        singular_name: "pod",
        namespaced: true,
        kind: "Pod",
        verbs: CORE_VERBS,
        short_names: Some(PODS_SHORT_NAMES),
    },
    ApiResource {
        name: "secrets",
        singular_name: "secret",
        namespaced: true,
        kind: "Secret",
        verbs: CORE_VERBS,
        short_names: None,
    },
    ApiResource {
        name: "serviceaccounts",
        singular_name: "serviceaccount",
        namespaced: true,
        kind: "ServiceAccount",
        verbs: CORE_VERBS,
        short_names: Some(SERVICE_ACCOUNTS_SHORT_NAMES),
    },
    ApiResource {
        name: "services",
        singular_name: "service",
        namespaced: true,
        kind: "Service",
        verbs: CORE_VERBS,
        short_names: Some(SERVICES_SHORT_NAMES),
    },
];

impl ApiResourceList {
    pub fn v1() -> Self {
        ApiResourceList {
            kind: "APIResourceList",
            api_version: "v1",
            group_version: "v1",
            resources: V1_RESOURCES,
        }
    }
}

// ---------------------------------------------------------------------------
// Resource registry types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceKey {
    pub group: String,   // "" for core group
    pub version: String,
    pub plural: String,
}

#[derive(Debug, Clone)]
pub struct ResourceMeta {
    pub kind: String,
    #[allow(dead_code)]
    pub namespaced: bool,
    pub has_status_subresource: bool,
    /// If true, POST behaves as createOrUpdate: if the object already exists, replace it.
    pub create_or_update: bool,
}

// ---------------------------------------------------------------------------
// Non-core group discovery wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct GroupVersionForDiscovery {
    #[serde(rename = "groupVersion")]
    pub group_version: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct APIGroup {
    pub name: String,
    pub versions: Vec<GroupVersionForDiscovery>,
    #[serde(rename = "preferredVersion")]
    pub preferred_version: GroupVersionForDiscovery,
}

#[derive(Debug, Serialize)]
pub struct APIGroupList {
    pub kind: &'static str,
    #[serde(rename = "apiVersion")]
    pub api_version: &'static str,
    pub groups: Vec<APIGroup>,
}

// ---------------------------------------------------------------------------
// Namespace domain type
// ---------------------------------------------------------------------------

/// Validated namespace name. Only `[a-z0-9-]+` is accepted.
/// In Phase 1, only `"default"` is a valid namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace(pub String);

impl Namespace {
    /// Parse and validate a raw namespace string.
    /// Returns `Err` with a human-readable message on failure.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.is_empty() || !raw.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(format!("invalid namespace name '{raw}': must match [a-z0-9-]+"));
        }
        Ok(Namespace(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Kubernetes object store type
// ---------------------------------------------------------------------------

/// Every Kubernetes object in memory.
/// Body is kept as a serde_json::Value for cheap pass-through.
/// Accessors parse individual fields on demand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    #[serde(flatten)]
    pub body: Value,
}

impl Object {
    pub fn name(&self) -> Option<&str> {
        self.body["metadata"]["name"].as_str()
    }

    #[allow(dead_code)]
    pub fn namespace(&self) -> Option<&str> {
        self.body["metadata"]["namespace"].as_str()
    }

    pub fn resource_version(&self) -> Option<&str> {
        self.body["metadata"]["resourceVersion"].as_str()
    }

    #[allow(dead_code)]
    pub fn resource_version_u64(&self) -> Option<u64> {
        self.resource_version()?.parse().ok()
    }

    pub fn set_resource_version(&mut self, rv: u64) {
        self.body["metadata"]["resourceVersion"] = Value::String(rv.to_string());
    }

    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(serde_json::to_vec(&self.body).unwrap())
    }

    pub fn from_bytes(bytes: &Bytes) -> Result<Self, serde_json::Error> {
        let body: Value = serde_json::from_slice(bytes)?;
        Ok(Self { body })
    }
}
