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
    pub server_address: String,
}

/// Wire representation of `/api` response.
#[derive(Debug, Serialize)]
pub struct APIVersions {
    pub kind: &'static str,
    #[serde(rename = "apiVersion")]
    pub api_version: &'static str,
    pub versions: &'static [&'static str],
    #[serde(rename = "serverAddressByClientCIDRs")]
    pub server_address_by_client_cidrs: Vec<ServerAddressByClientCIDR>,
}

impl APIVersions {
    pub fn v1(server_address: String) -> Self {
        APIVersions {
            kind: "APIVersions",
            api_version: "v1",
            versions: &["v1"],
            server_address_by_client_cidrs: vec![ServerAddressByClientCIDR {
                client_cidr: "0.0.0.0/0",
                server_address,
            }],
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

static CORE_VERBS: &[&str] = &[
    "create", "delete", "get", "list", "patch", "update", "watch",
];
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
        name: "namespaces",
        singular_name: "namespace",
        namespaced: false,
        kind: "Namespace",
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
    pub group: String, // "" for core group
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
        if raw.is_empty()
            || !raw
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(format!(
                "invalid namespace name '{raw}': must match [a-z0-9-]+"
            ));
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
// ObjectMeta — typed metadata struct
// ---------------------------------------------------------------------------

/// Typed representation of Kubernetes `metadata`. Used to access metadata
/// fields at a boundary rather than via raw string-keyed JSON indexing,
/// which is invisible to the compiler and prone to silent typos.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        rename = "generateName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub generate_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(
        rename = "resourceVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_version: Option<String>,
    #[serde(
        rename = "creationTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub creation_timestamp: Option<String>,
    #[serde(
        rename = "deletionTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deletion_timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalizers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::BTreeMap<String, String>>,
}

// ---------------------------------------------------------------------------
// PodSpec — typed pod spec (fields accessed by handlers and scheduler)
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

/// Typed representation of the fields in a Pod's `spec` that are read by
/// handlers. Parsing at the handler boundary catches typos the compiler
/// cannot see in raw `["nodeName"]` indexing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default = "default_true")]
    pub enable_service_links: bool,
}

// ---------------------------------------------------------------------------
// Binding — typed Binding subresource body
// ---------------------------------------------------------------------------

/// The `target` field of a Binding object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingTarget {
    pub name: String,
}

/// Typed representation of the Binding subresource body POSTed by the
/// scheduler. Using this instead of raw `binding["target"]["name"]` indexing
/// means a typo in the field path is a compile error, not a silent None.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub target: BindingTarget,
}

// NamespaceStatus — typed status for Namespace objects
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceStatus {
    pub phase: String,
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

    pub fn resource_version(&self) -> Option<&str> {
        self.body["metadata"]["resourceVersion"].as_str()
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

#[cfg(test)]
mod namespace_status_tests {
    use super::*;

    /// NamespaceStatus must serialize to {"phase":"<value>"} so that a Namespace stored
    /// with typed construction matches what clients (kubectl) expect to read back.
    /// A field rename regression would silently produce wrong JSON without this test.
    #[test]
    fn namespace_status_serializes_to_phase_key() {
        let s = NamespaceStatus {
            phase: "Active".to_owned(),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["phase"], "Active");
        // Must not emit any extra or renamed keys
        assert_eq!(
            v.as_object().unwrap().len(),
            1,
            "NamespaceStatus must only emit 'phase'"
        );
    }

    /// NamespaceStatus must round-trip through JSON so stored values can be read back.
    #[test]
    fn namespace_status_round_trips() {
        let original = NamespaceStatus {
            phase: "Terminating".to_owned(),
        };
        let v = serde_json::to_value(&original).unwrap();
        let restored: NamespaceStatus = serde_json::from_value(v).unwrap();
        assert_eq!(restored.phase, "Terminating");
    }
}

#[cfg(test)]
mod object_meta_tests {
    use super::*;

    /// ObjectMeta must deserialize all fields from a fully-populated JSON object.
    /// Missing any field means the typed API cannot enforce correctness at the
    /// conversion site — a typo in a raw string key is a silent data-loss path.
    #[test]
    fn object_meta_deserializes_all_fields() {
        let json = serde_json::json!({
            "name": "my-pod",
            "generateName": "my-",
            "namespace": "default",
            "uid": "abc-123",
            "resourceVersion": "42",
            "creationTimestamp": "2024-01-01T00:00:00Z",
            "deletionTimestamp": "2024-01-02T00:00:00Z",
            "finalizers": ["my.io/cleanup"],
            "labels": {"app": "nginx"},
            "annotations": {"note": "val"}
        });
        let meta: ObjectMeta = serde_json::from_value(json).unwrap();
        assert_eq!(meta.name.as_deref(), Some("my-pod"));
        assert_eq!(meta.generate_name.as_deref(), Some("my-"));
        assert_eq!(meta.namespace.as_deref(), Some("default"));
        assert_eq!(meta.uid.as_deref(), Some("abc-123"));
        assert_eq!(meta.resource_version.as_deref(), Some("42"));
        assert_eq!(
            meta.creation_timestamp.as_deref(),
            Some("2024-01-01T00:00:00Z")
        );
        assert_eq!(
            meta.deletion_timestamp.as_deref(),
            Some("2024-01-02T00:00:00Z")
        );
        assert_eq!(
            meta.finalizers.as_deref(),
            Some(["my.io/cleanup".to_string()].as_slice())
        );
        assert_eq!(
            meta.labels
                .as_ref()
                .and_then(|l| l.get("app"))
                .map(|s| s.as_str()),
            Some("nginx")
        );
        assert_eq!(
            meta.annotations
                .as_ref()
                .and_then(|a| a.get("note"))
                .map(|s| s.as_str()),
            Some("val")
        );
    }

    /// ObjectMeta must use Option::None for every field when the JSON object is empty.
    /// This is the parse-at-boundary default: missing fields are absent, not panic-inducing.
    #[test]
    fn object_meta_defaults_missing_optional_fields() {
        let meta: ObjectMeta = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(meta.name.is_none());
        assert!(meta.generate_name.is_none());
        assert!(meta.namespace.is_none());
        assert!(meta.uid.is_none());
        assert!(meta.resource_version.is_none());
        assert!(meta.creation_timestamp.is_none());
        assert!(meta.deletion_timestamp.is_none());
        assert!(meta.finalizers.is_none());
        assert!(meta.labels.is_none());
        assert!(meta.annotations.is_none());
    }

    /// generateName and deletionTimestamp use Kubernetes camelCase names in the wire format.
    /// A wrong rename annotation silently produces snake_case JSON, breaking all clients.
    #[test]
    fn object_meta_camel_case_round_trips() {
        let original = serde_json::json!({
            "generateName": "job-",
            "deletionTimestamp": "2024-06-01T12:00:00Z"
        });
        let meta: ObjectMeta = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(meta.generate_name.as_deref(), Some("job-"));
        assert_eq!(
            meta.deletion_timestamp.as_deref(),
            Some("2024-06-01T12:00:00Z")
        );

        let serialized = serde_json::to_value(&meta).unwrap();
        assert_eq!(serialized["generateName"], "job-");
        assert_eq!(serialized["deletionTimestamp"], "2024-06-01T12:00:00Z");
        // Snake_case variants must be absent — they would not be understood by kubectl
        assert!(serialized.get("generate_name").is_none());
        assert!(serialized.get("deletion_timestamp").is_none());
    }

    /// ObjectMeta must omit None fields from serialization.
    /// Emitting null for absent optional fields wastes bytes and confuses clients
    /// that check for key presence to determine whether a field is set.
    #[test]
    fn object_meta_serialization_omits_none_fields() {
        let meta = ObjectMeta {
            name: Some("my-obj".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["name"], "my-obj");
        // All other None fields must not appear in the serialized output
        assert!(json.get("generateName").is_none());
        assert!(json.get("namespace").is_none());
        assert!(json.get("uid").is_none());
        assert!(json.get("resourceVersion").is_none());
        assert!(json.get("creationTimestamp").is_none());
        assert!(json.get("deletionTimestamp").is_none());
        assert!(json.get("finalizers").is_none());
        assert!(json.get("labels").is_none());
        assert!(json.get("annotations").is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use serde_json::json;

    // APIVersions::v1 must set the correct kind, apiVersion, and embed the server address
    #[test]
    fn api_versions_v1_fields() {
        let av = APIVersions::v1("192.168.1.1:6443".to_string());
        assert_eq!(av.kind, "APIVersions");
        assert_eq!(av.api_version, "v1");
        assert_eq!(av.versions, &["v1"]);
        assert_eq!(av.server_address_by_client_cidrs.len(), 1);
        assert_eq!(
            av.server_address_by_client_cidrs[0].server_address,
            "192.168.1.1:6443"
        );
        assert_eq!(
            av.server_address_by_client_cidrs[0].client_cidr,
            "0.0.0.0/0"
        );
    }

    // APIVersions::v1 must serialize to valid JSON with the correct field names kubectl expects
    #[test]
    fn api_versions_v1_serializes() {
        let av = APIVersions::v1("localhost:6443".to_string());
        let json = serde_json::to_value(&av).unwrap();
        assert_eq!(json["kind"], "APIVersions");
        assert_eq!(json["apiVersion"], "v1");
        assert!(json["serverAddressByClientCIDRs"].is_array());
        assert_eq!(
            json["serverAddressByClientCIDRs"][0]["serverAddress"],
            "localhost:6443"
        );
    }

    // ApiResourceList::v1 must contain all expected core resources
    #[test]
    fn api_resource_list_v1_contains_core_resources() {
        let list = ApiResourceList::v1();
        assert_eq!(list.kind, "APIResourceList");
        assert_eq!(list.api_version, "v1");
        assert_eq!(list.group_version, "v1");
        let names: Vec<&str> = list.resources.iter().map(|r| r.name).collect();
        assert!(names.contains(&"pods"));
        assert!(names.contains(&"nodes"));
        assert!(names.contains(&"namespaces"));
        assert!(names.contains(&"services"));
        assert!(names.contains(&"secrets"));
        assert!(names.contains(&"serviceaccounts"));
        assert!(names.contains(&"configmaps"));
        assert!(names.contains(&"events"));
    }

    // ApiResourceList::v1 must serialize with the correct camelCase field names
    #[test]
    fn api_resource_list_v1_serializes() {
        let list = ApiResourceList::v1();
        let json = serde_json::to_value(&list).unwrap();
        assert_eq!(json["kind"], "APIResourceList");
        assert_eq!(json["groupVersion"], "v1");
        // shortNames must be omitted when None (events has no shortNames)
        let resources = json["resources"].as_array().unwrap();
        let events = resources.iter().find(|r| r["name"] == "events").unwrap();
        assert!(events.get("shortNames").is_none());
        // pods must have shortNames
        let pods = resources.iter().find(|r| r["name"] == "pods").unwrap();
        assert_eq!(pods["shortNames"][0], "po");
    }

    // Namespace::parse must accept valid lowercase-alphanumeric-hyphen names
    #[test]
    fn namespace_parse_valid() {
        let ns = Namespace::parse("default").unwrap();
        assert_eq!(ns.as_str(), "default");
        let ns2 = Namespace::parse("kube-system").unwrap();
        assert_eq!(ns2.as_str(), "kube-system");
        let ns3 = Namespace::parse("ns123").unwrap();
        assert_eq!(ns3.as_str(), "ns123");
    }

    // Namespace::parse must reject empty string — empty is not a valid namespace
    #[test]
    fn namespace_parse_empty_is_error() {
        assert!(Namespace::parse("").is_err());
    }

    // Namespace::parse must reject names with uppercase letters
    #[test]
    fn namespace_parse_uppercase_is_error() {
        let err = Namespace::parse("Default").unwrap_err();
        assert!(err.contains("invalid namespace name"));
    }

    // Namespace::parse must reject names with special characters like underscores or dots
    #[test]
    fn namespace_parse_special_chars_is_error() {
        assert!(Namespace::parse("my_ns").is_err());
        assert!(Namespace::parse("my.ns").is_err());
        assert!(Namespace::parse("my ns").is_err());
    }

    // Namespace::fmt must produce the bare string (used in log messages and error text)
    #[test]
    fn namespace_display() {
        let ns = Namespace::parse("default").unwrap();
        assert_eq!(format!("{ns}"), "default");
    }

    // Object::name must return the metadata.name field when present
    #[test]
    fn object_name_present() {
        let obj = Object {
            body: json!({"metadata": {"name": "my-pod"}}),
        };
        assert_eq!(obj.name(), Some("my-pod"));
    }

    // Object::name must return None when metadata.name is absent
    #[test]
    fn object_name_absent() {
        let obj = Object {
            body: json!({"metadata": {}}),
        };
        assert_eq!(obj.name(), None);
    }

    // Object::resource_version must return the metadata.resourceVersion string when present
    #[test]
    fn object_resource_version_present() {
        let obj = Object {
            body: json!({"metadata": {"resourceVersion": "42"}}),
        };
        assert_eq!(obj.resource_version(), Some("42"));
    }

    // Object::resource_version must return None when absent
    #[test]
    fn object_resource_version_absent() {
        let obj = Object {
            body: json!({"metadata": {}}),
        };
        assert_eq!(obj.resource_version(), None);
    }

    // Object::set_resource_version must overwrite the resourceVersion field
    #[test]
    fn object_set_resource_version() {
        let mut obj = Object {
            body: json!({"metadata": {"resourceVersion": "1"}}),
        };
        obj.set_resource_version(99);
        assert_eq!(obj.resource_version(), Some("99"));
    }

    // Object::to_bytes / from_bytes round-trip must preserve the body exactly
    #[test]
    fn object_bytes_round_trip() {
        let original = Object {
            body: json!({"metadata": {"name": "pod-a", "resourceVersion": "7"}, "spec": {}}),
        };
        let bytes = original.to_bytes();
        let restored = Object::from_bytes(&bytes).unwrap();
        assert_eq!(restored.name(), Some("pod-a"));
        assert_eq!(restored.resource_version(), Some("7"));
    }

    // Object::from_bytes must return an error on malformed JSON
    #[test]
    fn object_from_bytes_invalid_json() {
        let bad = Bytes::from_static(b"not json");
        assert!(Object::from_bytes(&bad).is_err());
    }
}

#[cfg(test)]
mod pod_spec_tests {
    use super::*;

    /// PodSpec must deserialize `nodeName` from camelCase JSON.
    /// The scheduler and field-selector handler read `node_name` to route pods;
    /// a wrong rename annotation silently leaves all pods unscheduled.
    #[test]
    fn pod_spec_deserializes_node_name() {
        let json = serde_json::json!({"nodeName": "worker-1"});
        let spec: PodSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.node_name.as_deref(), Some("worker-1"));
    }

    /// PodSpec must default `node_name` to None when the field is absent.
    /// An unscheduled pod has no nodeName; None must not be confused with "".
    #[test]
    fn pod_spec_node_name_defaults_to_none() {
        let spec: PodSpec = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(spec.node_name.is_none());
    }

    /// PodSpec must default `enable_service_links` to true when absent.
    /// Kubernetes always defaults this field on create; the kubelet panics if it
    /// is nil (CreateContainerConfigError). Defaulting here ensures typed structs
    /// match the wire behaviour.
    #[test]
    fn pod_spec_enable_service_links_defaults_to_true() {
        let spec: PodSpec = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(
            spec.enable_service_links,
            "enableServiceLinks must default to true to match real kube-apiserver behaviour"
        );
    }

    /// PodSpec must respect an explicit `enableServiceLinks: false`.
    #[test]
    fn pod_spec_enable_service_links_false_is_preserved() {
        let json = serde_json::json!({"enableServiceLinks": false});
        let spec: PodSpec = serde_json::from_value(json).unwrap();
        assert!(!spec.enable_service_links);
    }

    /// PodSpec must not emit `nodeName` in serialized output when it is None.
    /// Emitting null would confuse clients that check for key presence.
    #[test]
    fn pod_spec_serialization_omits_absent_node_name() {
        let spec = PodSpec {
            node_name: None,
            enable_service_links: true,
        };
        let v = serde_json::to_value(&spec).unwrap();
        assert!(v.get("nodeName").is_none());
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;

    /// Binding must deserialize `target.name` from a full Kubernetes Binding body.
    /// The scheduler POSTs this shape to bind a pod to a node; a wrong field
    /// path silently leaves pods unscheduled.
    #[test]
    fn binding_deserializes_target_name() {
        let json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Binding",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "target": {"kind": "Node", "name": "worker-1"}
        });
        let binding: Binding = serde_json::from_value(json).unwrap();
        assert_eq!(binding.target.name, "worker-1");
    }

    /// Binding deserialization must fail when `target` is absent.
    /// An absent target cannot produce a valid node name; the handler must
    /// reject the request with 400, not silently bind to an empty node name.
    #[test]
    fn binding_fails_without_target() {
        let json = serde_json::json!({"apiVersion": "v1", "kind": "Binding"});
        let result = serde_json::from_value::<Binding>(json);
        assert!(
            result.is_err(),
            "Binding without target must fail deserialization"
        );
    }

    /// Binding deserialization must fail when `target.name` is absent.
    /// BindingTarget.name is a required String field; missing it means the
    /// scheduler sent a malformed request that must not proceed.
    #[test]
    fn binding_target_fails_without_name() {
        let json = serde_json::json!({"target": {}});
        let result = serde_json::from_value::<Binding>(json);
        assert!(
            result.is_err(),
            "Binding with empty target must fail deserialization — name is required"
        );
    }
}
