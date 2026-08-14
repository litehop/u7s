use bytes::Bytes;
use schemars::JsonSchema;
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
    "create",
    "delete",
    "deletecollection",
    "get",
    "list",
    "patch",
    "update",
    "watch",
];
static PODS_SHORT_NAMES: &[&str] = &["po"];
static NODES_SHORT_NAMES: &[&str] = &["no"];
static SERVICES_SHORT_NAMES: &[&str] = &["svc"];
static ENDPOINTS_SHORT_NAMES: &[&str] = &["ep"];
static NAMESPACES_SHORT_NAMES: &[&str] = &["ns"];
static SERVICE_ACCOUNTS_SHORT_NAMES: &[&str] = &["sa"];
static CONFIG_MAPS_SHORT_NAMES: &[&str] = &["cm"];
static PVC_SHORT_NAMES: &[&str] = &["pvc"];
static PV_SHORT_NAMES: &[&str] = &["pv"];
static RC_SHORT_NAMES: &[&str] = &["rc"];
static RESOURCE_QUOTAS_SHORT_NAMES: &[&str] = &["quota"];
static LIMIT_RANGES_SHORT_NAMES: &[&str] = &["limits"];

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
        name: "endpoints",
        singular_name: "endpoints",
        namespaced: true,
        kind: "Endpoints",
        verbs: CORE_VERBS,
        short_names: Some(ENDPOINTS_SHORT_NAMES),
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
        name: "limitranges",
        singular_name: "limitrange",
        namespaced: true,
        kind: "LimitRange",
        verbs: CORE_VERBS,
        short_names: Some(LIMIT_RANGES_SHORT_NAMES),
    },
    ApiResource {
        name: "namespaces",
        singular_name: "namespace",
        namespaced: false,
        kind: "Namespace",
        verbs: CORE_VERBS,
        short_names: Some(NAMESPACES_SHORT_NAMES),
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
        name: "persistentvolumeclaims",
        singular_name: "persistentvolumeclaim",
        namespaced: true,
        kind: "PersistentVolumeClaim",
        verbs: CORE_VERBS,
        short_names: Some(PVC_SHORT_NAMES),
    },
    ApiResource {
        name: "persistentvolumes",
        singular_name: "persistentvolume",
        namespaced: false,
        kind: "PersistentVolume",
        verbs: CORE_VERBS,
        short_names: Some(PV_SHORT_NAMES),
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
        name: "pods/binding",
        singular_name: "",
        namespaced: true,
        kind: "Binding",
        verbs: &["create"],
        short_names: None,
    },
    ApiResource {
        name: "pods/ephemeralcontainers",
        singular_name: "",
        namespaced: true,
        kind: "EphemeralContainers",
        verbs: &["get", "patch", "update"],
        short_names: None,
    },
    ApiResource {
        name: "pods/eviction",
        singular_name: "",
        namespaced: true,
        kind: "Eviction",
        verbs: &["create"],
        short_names: None,
    },
    ApiResource {
        name: "pods/log",
        singular_name: "",
        namespaced: true,
        kind: "Pod",
        verbs: &["get"],
        short_names: None,
    },
    ApiResource {
        name: "pods/resize",
        singular_name: "",
        namespaced: true,
        kind: "PodResizeBody",
        verbs: &["get", "patch", "update"],
        short_names: None,
    },
    ApiResource {
        name: "pods/status",
        singular_name: "",
        namespaced: true,
        kind: "Pod",
        verbs: &["get", "patch", "update"],
        short_names: None,
    },
    ApiResource {
        name: "podtemplates",
        singular_name: "podtemplate",
        namespaced: true,
        kind: "PodTemplate",
        verbs: CORE_VERBS,
        short_names: None,
    },
    ApiResource {
        name: "replicationcontrollers",
        singular_name: "replicationcontroller",
        namespaced: true,
        kind: "ReplicationController",
        verbs: CORE_VERBS,
        short_names: Some(RC_SHORT_NAMES),
    },
    ApiResource {
        name: "resourcequotas",
        singular_name: "resourcequota",
        namespaced: true,
        kind: "ResourceQuota",
        verbs: CORE_VERBS,
        short_names: Some(RESOURCE_QUOTAS_SHORT_NAMES),
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
    /// Whether this resource is namespace-scoped. Set at registration time; read in tests
    /// to verify the registry is wired correctly. Production routing is determined by the
    /// URL pattern, not this field.
    #[cfg(test)]
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
// Aggregated discovery (v2/v2beta1) wire types — `APIGroupDiscoveryList`
//
// Field declaration order matches ascending key order deliberately: without the
// `preserve_order` serde_json feature (not enabled anywhere in this workspace,
// see Cargo.lock), `serde_json::Value`'s Map is a `BTreeMap`, so the pre-migration
// `serde_json::json!`-built response always serialized object keys in ascending
// order regardless of literal insertion order. A `#[derive(Serialize)]` struct,
// by contrast, serializes fields in declaration order — so these fields are
// declared alphabetically to reproduce that same wire order byte-for-byte.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct APIGroupDiscoveryList {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub items: Vec<APIGroupDiscovery>,
    pub kind: &'static str,
    pub metadata: APIGroupDiscoveryListMeta,
}

#[derive(Debug, Serialize)]
pub struct APIGroupDiscoveryListMeta {
    #[serde(rename = "resourceVersion")]
    pub resource_version: String,
}

#[derive(Debug, Serialize)]
pub struct APIGroupDiscovery {
    pub metadata: APIGroupDiscoveryMeta,
    pub versions: Vec<APIVersionDiscovery>,
}

#[derive(Debug, Serialize)]
pub struct APIGroupDiscoveryMeta {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct APIVersionDiscovery {
    pub freshness: &'static str,
    pub resources: Vec<APIResourceDiscovery>,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct APIResourceDiscovery {
    pub resource: String,
    #[serde(rename = "responseKind")]
    pub response_kind: DiscoveryResponseKind,
    pub scope: &'static str,
    #[serde(rename = "shortNames", skip_serializing_if = "Vec::is_empty")]
    pub short_names: Vec<String>,
    #[serde(rename = "singularResource")]
    pub singular_resource: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subresources: Vec<APISubresourceDiscovery>,
    pub verbs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryResponseKind {
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct APISubresourceDiscovery {
    #[serde(rename = "responseKind")]
    pub response_kind: DiscoveryResponseKind,
    pub subresource: String,
    pub verbs: Vec<String>,
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

/// Typed representation of a Kubernetes `ownerReferences` entry. Read by the
/// garbage-collector cascade-delete path to decide whether a dependent object
/// still has a live owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OwnerReference {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_owner_deletion: Option<bool>,
}

/// Typed representation of a Kubernetes `managedFields` entry (server-side apply's
/// per-manager field ownership record). Modeled so a full `ObjectMeta` round-trip
/// (e.g. serve-from-store, watch-event encode) does not silently drop it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedFieldsEntry {
    pub manager: String,
    pub operation: String,
    pub api_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields_type: Option<String>,
    /// The SSA field-set (`FieldsV1.raw` upstream) is `map[string]interface{}` in
    /// Go — a structurally arbitrary tree with no fixed schema, so it stays raw
    /// JSON rather than a typed struct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields_v1: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subresource: Option<String>,
}

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
    #[serde(
        rename = "ownerReferences",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_references: Option<Vec<OwnerReference>>,
    #[serde(
        rename = "managedFields",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub managed_fields: Option<Vec<ManagedFieldsEntry>>,
    /// Populated by defaults.rs::initialize_workload_generation for every workload
    /// resource; null generation makes KCM's controllers skip reconciliation entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    /// Populated by handlers/pods.rs and handlers/resource.rs during graceful
    /// termination; kubelet and controllers need it to know how long to wait before
    /// force-removing.
    #[serde(
        rename = "deletionGracePeriodSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deletion_grace_period_seconds: Option<i64>,
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default = "default_true")]
    pub enable_service_links: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<Volume>>,
}

/// Typed representation of a Pod volume entry (fields accessed by handlers).
/// The `rest` field captures all other volume-type fields (emptyDir, hostPath,
/// etc.) opaquely so they survive a round-trip without loss.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_map: Option<VolumeProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<VolumeProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projected: Option<VolumeProjection>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "downwardAPI"
    )]
    pub downward_api: Option<VolumeProjection>,
    /// All other fields in this volume entry (e.g. emptyDir, hostPath).
    #[serde(flatten)]
    #[schemars(skip)]
    pub rest: serde_json::Value,
}

/// Typed representation of the subset of configMap/secret/projected/downwardAPI volume
/// source fields that the apiserver reads (defaultMode stamping).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VolumeProjection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<i32>,
    /// All other fields in this volume source.
    #[serde(flatten)]
    #[schemars(skip)]
    pub rest: serde_json::Value,
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

/// The two valid phases for a Namespace. Using an enum makes exhaustive matching
/// explicit — the apiserver pattern-matches on "Terminating" to gate operations,
/// so a typo in a string literal would be a silent logic error.
///
/// Kubernetes wire format uses PascalCase ("Active", "Terminating") so no
/// rename_all is needed — the variant names are already the correct wire names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum NamespacePhase {
    Active,
    Terminating,
}

/// Typed status for a Namespace object. Only `phase` is pattern-matched by
/// apiserver logic; all other status fields survive round-trips via `rest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceStatus {
    pub phase: Option<NamespacePhase>,
    /// All other status fields preserved opaquely.
    #[serde(flatten)]
    #[schemars(skip)]
    pub rest: serde_json::Value,
}

/// Typed spec for a Namespace object. In Kubernetes, namespace finalizers live
/// in `spec.finalizers`, not `metadata.finalizers`. The upstream KCM namespace
/// controller reads `spec.finalizers` to decide whether to drain a namespace.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalizers: Option<Vec<String>>,
    /// All other spec fields preserved opaquely.
    #[serde(flatten)]
    #[schemars(skip)]
    pub rest: serde_json::Value,
}

// ---------------------------------------------------------------------------
// DeleteOptions
// ---------------------------------------------------------------------------

/// Typed body for DELETE requests.
///
/// The apiserver reasons about propagationPolicy to gate cascade vs orphan
/// behaviour, so it must flow through a typed struct rather than raw JSON map access.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOptions {
    /// "Orphan", "Background", or "Foreground". Absent/nil means: do not cascade synchronously.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagation_policy: Option<String>,
    /// Legacy field. True maps to "Orphan". Nil/absent means "use propagationPolicy".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orphan_dependents: Option<bool>,
    /// Seconds to wait before hard-deleting after deletionTimestamp is stamped.
    /// Absent/nil means: fall back to the object's own grace period (e.g. a pod's
    /// spec.terminationGracePeriodSeconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_period_seconds: Option<i64>,
}

impl DeleteOptions {
    /// Returns true when the caller has explicitly requested Orphan propagation.
    /// `orphanDependents: true` is the legacy spelling; `propagationPolicy: Orphan` is current.
    pub fn is_orphan(&self) -> bool {
        if let Some(true) = self.orphan_dependents {
            return true;
        }
        self.propagation_policy.as_deref() == Some("Orphan")
    }

    /// Returns true when the caller has explicitly requested cascade (Background or Foreground).
    ///
    /// This is the gate for synchronous cascade-delete on the apiserver.  When both
    /// `propagationPolicy` and `orphanDependents` are absent/nil the request carries no
    /// explicit propagation intent and we do NOT cascade immediately — the GC controller
    /// is expected to clean up orphaned dependants asynchronously.  This matches upstream
    /// Kubernetes: k8s GC conformance spec "should orphan pods created by rc if
    /// deleteOptions.OrphanDependents is nil" deletes with empty DeleteOptions and asserts
    /// pods survive for at least 30 seconds, which only holds if we do not synchronously
    /// cascade them here.
    pub fn is_explicit_cascade(&self) -> bool {
        // Legacy spelling: orphanDependents=false is the old way to request Background.
        if let Some(false) = self.orphan_dependents {
            return true;
        }
        matches!(
            self.propagation_policy.as_deref(),
            Some("Background") | Some("Foreground")
        )
    }
}

// ---------------------------------------------------------------------------
// CertificateSigningRequest typed fields
// ---------------------------------------------------------------------------

/// Typed `spec` for a CertificateSigningRequest.
///
/// Only the fields the apiserver dereferences are typed; everything else is
/// captured in `rest` so callers never lose unknown fields on round-trip.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSigningRequestSpec {
    /// Base64-encoded PEM CSR bytes (PKCS#10 DER).
    pub request: String,
    /// Identifies which signer controller should handle this CSR.
    pub signer_name: String,
    /// Remaining fields preserved opaquely.
    #[serde(flatten)]
    #[schemars(skip)]
    pub rest: serde_json::Value,
}

/// Typed `status` for a CertificateSigningRequest.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSigningRequestStatus {
    /// Base64-encoded signed certificate, written by the signer controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// Approval/denial/failure conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<CsrCondition>>,
    /// Remaining fields preserved opaquely.
    #[serde(flatten)]
    #[schemars(skip)]
    pub rest: serde_json::Value,
}

/// A single condition entry in `status.conditions` of a CSR.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CsrCondition {
    /// "Approved", "Denied", or "Failed".
    #[serde(rename = "type")]
    pub condition_type: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update_time: Option<String>,
    /// Remaining fields preserved opaquely.
    #[serde(flatten)]
    #[schemars(skip)]
    pub rest: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Defaulting typed structs — handlers/defaults.rs
//
// Each struct types only the fields a `default_X` function in
// handlers/defaults.rs reads or writes; every other field round-trips
// opaquely via `rest`. This is the same minimal-field pattern as `PodSpec`/
// `NamespaceStatus` above, applied to the defaulting surface: the direct
// motivation is PR #1024 (mayor-xv1pk), where a field the apiserver was
// supposed to default was missing entirely from a Value-tree-based codebase
// with no compiler-checked inventory of "which fields does this function
// reason about" to catch the gap during review.
// ---------------------------------------------------------------------------

/// Shared `status` shape for PersistentVolume and PersistentVolumeClaim —
/// only `phase` is defaulted by either resource's `default_X` function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistentVolumeStatusFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(flatten)]
    pub rest: Value,
}

/// Shared `spec` shape for PersistentVolume and PersistentVolumeClaim — only
/// `volumeMode` is defaulted by either resource's `default_X` function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistentVolumeSpecFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_mode: Option<String>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `spec` of a CSIDriver — the pointer-typed fields upstream's
/// `SetDefaults_CSIDriver` defaults when a client omits them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsiDriverSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attach_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_info_on_mount: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_capacity: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_group_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_lifecycle_modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_republish: Option<bool>,
    #[serde(flatten)]
    pub rest: Value,
}

/// Top-level fields of a StorageClass — `reclaimPolicy`/`volumeBindingMode` sit
/// directly on the object, not under a `.spec` wrapper.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageClassFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reclaim_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_binding_mode: Option<String>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `spec` of a Lease — only `leaseTransitions` is defaulted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_transitions: Option<i32>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `roleRef` of a RoleBinding/ClusterRoleBinding — only `apiGroup` is defaulted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleRefFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_group: Option<String>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `spec` of a ReplicationController.
///
/// `selector` is a flat equality-based map<string,string> — NOT the set-based
/// `{matchLabels: {...}}` shape used by ReplicaSet/StatefulSet/Deployment.
/// Encoding that distinction in the type itself (rather than a shared `Value`
/// field) makes it impossible to accidentally wrap an RC selector in
/// `matchLabels`, which would make KCM fail to parse it as an RC selector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationControllerSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    #[serde(flatten)]
    pub rest: Value,
}

/// Read-only peek at a pod template's `metadata.labels`, used by ReplicaSet,
/// StatefulSet, Deployment, and ReplicationController to default
/// `spec.selector` from `spec.template.metadata.labels` when the caller omits
/// an explicit selector. Never serialized back — the underlying template
/// Value is only read, so no `rest` catch-all is needed here.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TemplateLabelsPeek {
    #[serde(default)]
    pub metadata: TemplateMetaLabelsPeek,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TemplateMetaLabelsPeek {
    #[serde(default)]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
}

/// `spec` of a ReplicaSet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicaSetSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `spec` of a StatefulSet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatefulSetSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_management_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_strategy: Option<StatefulSetUpdateStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_history_limit: Option<i32>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatefulSetUpdateStrategy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<StatefulSetRollingUpdate>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatefulSetRollingUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition: Option<i32>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `spec` of a DaemonSet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonSetSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_strategy: Option<DaemonSetUpdateStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_history_limit: Option<i32>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonSetUpdateStrategy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<DaemonSetRollingUpdate>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonSetRollingUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_surge: Option<Value>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `spec` of a Deployment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_history_limit: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_deadline_seconds: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DeploymentStrategy>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentStrategy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<DeploymentRollingUpdate>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentRollingUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_surge: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<Value>,
    #[serde(flatten)]
    pub rest: Value,
}

/// A pod template that gets *written back* by defaulting (Job's
/// `spec.template`, CronJob's `spec.jobTemplate.spec.template`). Unlike
/// `TemplateLabelsPeek` (read-only), this type must preserve every field the
/// template already has on round-trip — `metadata`/`spec` each carry their
/// own `rest` so that e.g. `containers` (on `spec`) or `ownerReferences` (on
/// `metadata`, in principle) are never dropped when the template is
/// re-serialized after defaulting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultingPodTemplate {
    #[serde(default)]
    pub metadata: DefaultingPodTemplateMeta,
    #[serde(default)]
    pub spec: DefaultingPodTemplateSpec,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultingPodTemplateMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<serde_json::Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Map<String, Value>>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultingPodTemplateSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_service_links: Option<bool>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `spec` of a Job. `template` is intentionally NOT included here:
/// `default_job` defaults it via a separate `DefaultingPodTemplate`
/// round-trip scoped to `spec.template` alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff_limit: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_selector: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<Value>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `spec` of a Service.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_affinity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_affinity_config: Option<SessionAffinityConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<ServicePort>>,
    #[serde(default, rename = "clusterIP", skip_serializing_if = "Option::is_none")]
    pub cluster_ip: Option<String>,
    #[serde(
        default,
        rename = "clusterIPs",
        skip_serializing_if = "Option::is_none"
    )]
    pub cluster_ips: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_family_policy: Option<String>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionAffinityConfig {
    #[serde(default, rename = "clientIP", skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<ClientIpConfig>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientIpConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i64>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePort {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    /// `IntOrString` upstream (may be a named container port) — kept opaque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_port: Option<Value>,
    #[serde(flatten)]
    pub rest: Value,
}

/// `spec.behavior` of a HorizontalPodAutoscaler.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HpaBehavior {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_up: Option<HpaScalingRules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_down: Option<HpaScalingRules>,
    #[serde(flatten)]
    pub rest: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HpaScalingRules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stabilization_window_seconds: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub select_policy: Option<String>,
    /// Kept opaque: `default_hpa` only ever checks presence and overwrites
    /// the whole array with a literal default; it never reads individual
    /// policy entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Value>,
    #[serde(flatten)]
    pub rest: Value,
}

/// Upstream `metav1.Condition` — the {type, status, reason, message,
/// lastTransitionTime, observedGeneration} shape upstream reuses byte-for-byte
/// across many resources (APIService availability, and future condition-bearing
/// kinds). Hand-rolled once here so each such consumer shares one struct instead
/// of each reimplementing a near-identical one. CSR approval keeps its own
/// `CsrCondition` rather than this type because its wire shape genuinely
/// diverges: `lastUpdateTime` in addition to `lastTransitionTime`, and no
/// `observedGeneration`.
///
/// First consumer: `handlers/aggregation.rs`'s `upsert_available_condition`
/// (APIService's `status.conditions[type=Available]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
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
        // serde_json::Value always serializes to a Vec<u8>: the writer
        // (Vec<u8>) never produces I/O errors and Value holds only
        // JSON-representable data.
        Bytes::from(
            serde_json::to_vec(&self.body).expect("serde_json::Value is always serializable"),
        )
    }

    pub fn from_bytes(bytes: &Bytes) -> Result<Self, serde_json::Error> {
        let body: Value = serde_json::from_slice(bytes)?;
        Ok(Self { body })
    }
}

#[cfg(test)]
mod namespace_status_tests {
    use super::*;

    /// NamespacePhase::Active must serialize to the string "Active".
    /// kubectl displays the phase string directly; a wrong serialization would
    /// show garbage in `kubectl get ns` output.
    #[test]
    fn namespace_phase_active_serializes_correctly() {
        let v = serde_json::to_value(&NamespacePhase::Active).unwrap();
        assert_eq!(v, "Active");
    }

    /// NamespacePhase::Terminating must serialize to the string "Terminating".
    /// The apiserver pattern-matches this value to gate namespace deletion;
    /// a wrong string would silently allow operations on a terminating namespace.
    #[test]
    fn namespace_phase_terminating_serializes_correctly() {
        let v = serde_json::to_value(&NamespacePhase::Terminating).unwrap();
        assert_eq!(v, "Terminating");
    }

    /// NamespaceStatus must serialize to {"phase":"Active"} so that a Namespace stored
    /// with typed construction matches what clients (kubectl) expect to read back.
    /// A field rename regression would silently produce wrong JSON without this test.
    #[test]
    fn namespace_status_serializes_to_phase_key() {
        let s = NamespaceStatus {
            phase: Some(NamespacePhase::Active),
            rest: serde_json::Value::Object(Default::default()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["phase"], "Active");
    }

    /// NamespaceStatus must round-trip through JSON so stored values can be read back.
    #[test]
    fn namespace_status_round_trips() {
        let original = NamespaceStatus {
            phase: Some(NamespacePhase::Terminating),
            rest: serde_json::Value::Object(Default::default()),
        };
        let v = serde_json::to_value(&original).unwrap();
        let restored: NamespaceStatus = serde_json::from_value(v).unwrap();
        assert_eq!(restored.phase, Some(NamespacePhase::Terminating));
    }

    /// NamespaceStatus with unknown status fields must preserve them on round-trip.
    /// Kubernetes controllers may write arbitrary extra fields into status; dropping
    /// them on a read-modify-write cycle would silently corrupt the stored object.
    #[test]
    fn namespace_status_round_trips_with_unknown_fields() {
        let json = serde_json::json!({
            "phase": "Active",
            "conditions": [{"type": "NamespaceDeletionContentFailure", "status": "False"}],
            "unknownFutureField": "preserved"
        });
        let status: NamespaceStatus = serde_json::from_value(json).unwrap();
        assert_eq!(status.phase, Some(NamespacePhase::Active));

        // Re-serialize and verify all fields survive
        let out = serde_json::to_value(&status).unwrap();
        assert_eq!(out["phase"], "Active");
        assert_eq!(
            out["conditions"][0]["type"],
            "NamespaceDeletionContentFailure"
        );
        assert_eq!(
            out["unknownFutureField"], "preserved",
            "unknown status fields must survive round-trip via rest — \
             losing them corrupts objects that other controllers wrote"
        );
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
        assert!(meta.owner_references.is_none());
        assert!(meta.managed_fields.is_none());
        assert!(meta.generation.is_none());
        assert!(meta.deletion_grace_period_seconds.is_none());
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
        assert!(json.get("ownerReferences").is_none());
        assert!(json.get("managedFields").is_none());
        assert!(json.get("generation").is_none());
        assert!(json.get("deletionGracePeriodSeconds").is_none());
    }

    /// A metadata object with two ownerReferences (Job + ReplicaSet, one marked as the
    /// controller, one carrying blockOwnerDeletion) must round-trip through ObjectMeta
    /// byte-identically. The GC cascade-delete path only reasons about reference identity
    /// after this round-trip; if any of the six upstream fields were silently dropped or
    /// renamed on the way through the typed struct, a live-owner check could pass or fail
    /// depending on which fields survived, corrupting cascade-delete decisions.
    #[test]
    fn object_meta_owner_references_round_trip_byte_identical() {
        let meta = ObjectMeta {
            owner_references: Some(vec![
                OwnerReference {
                    api_version: "batch/v1".to_string(),
                    kind: "Job".to_string(),
                    name: "my-job".to_string(),
                    uid: "job-uid-1".to_string(),
                    controller: Some(true),
                    block_owner_deletion: None,
                },
                OwnerReference {
                    api_version: "apps/v1".to_string(),
                    kind: "ReplicaSet".to_string(),
                    name: "my-rs".to_string(),
                    uid: "rs-uid-2".to_string(),
                    controller: None,
                    block_owner_deletion: Some(true),
                },
            ]),
            ..Default::default()
        };
        let first_pass = serde_json::to_vec(&serde_json::to_value(&meta).unwrap()).unwrap();
        let restored: ObjectMeta = serde_json::from_slice(&first_pass).unwrap();
        let second_pass = serde_json::to_vec(&serde_json::to_value(&restored).unwrap()).unwrap();
        assert_eq!(
            first_pass, second_pass,
            "ownerReferences must survive a serialize/deserialize round-trip byte-for-byte — \
             a dropped or reordered field here would corrupt the GC cascade-delete's \
             live-owner check"
        );
        assert_eq!(restored.owner_references, meta.owner_references);
    }

    /// ObjectMeta must not add an `ownerReferences: null` key when the source metadata never
    /// had one. Every object stored before this field existed lacks the key entirely; if the
    /// round-trip through ObjectMeta introduced an explicit null, every subsequent
    /// read-modify-write of such an object would grow an extra key, and clients that check
    /// for key presence to detect "has owners" would start seeing false positives.
    #[test]
    fn object_meta_without_owner_references_wire_format_unchanged() {
        let original = serde_json::json!({
            "name": "my-pod",
            "namespace": "default",
            "uid": "abc-123"
        });
        let original_bytes = serde_json::to_vec(&original).unwrap();
        let meta: ObjectMeta = serde_json::from_value(original).unwrap();
        let round_tripped_bytes =
            serde_json::to_vec(&serde_json::to_value(&meta).unwrap()).unwrap();
        assert_eq!(
            round_tripped_bytes, original_bytes,
            "ObjectMeta without ownerReferences must serialize back byte-identical; an \
             ownerReferences:null key would silently appear on every object never touched \
             by an owner"
        );
    }

    /// A metadata object with two managedFields entries (one fully populated server-side-apply
    /// record with a fieldsV1 tree, one minimal update record with only the required manager/
    /// operation) must round-trip through ObjectMeta byte-identically. mayor-7p767 depends on
    /// this: tightening watch/PartialObjectMetadata handling to a full ObjectMeta round-trip is
    /// only safe once managedFields survives it — before this field existed, any object with
    /// server-side-apply history would silently lose its field-ownership record on that path.
    #[test]
    fn object_meta_managed_fields_round_trip_byte_identical() {
        let meta = ObjectMeta {
            managed_fields: Some(vec![
                ManagedFieldsEntry {
                    manager: "kubectl".to_string(),
                    operation: "Apply".to_string(),
                    api_version: "v1".to_string(),
                    time: Some("2024-06-01T12:00:00Z".to_string()),
                    fields_type: Some("FieldsV1".to_string()),
                    fields_v1: Some(serde_json::json!({"f:metadata": {"f:labels": {}}})),
                    subresource: Some("status".to_string()),
                },
                ManagedFieldsEntry {
                    manager: "kube-controller-manager".to_string(),
                    operation: "Update".to_string(),
                    api_version: "v1".to_string(),
                    time: None,
                    fields_type: None,
                    fields_v1: None,
                    subresource: None,
                },
            ]),
            ..Default::default()
        };
        let first_pass = serde_json::to_vec(&serde_json::to_value(&meta).unwrap()).unwrap();
        let restored: ObjectMeta = serde_json::from_slice(&first_pass).unwrap();
        let second_pass = serde_json::to_vec(&serde_json::to_value(&restored).unwrap()).unwrap();
        assert_eq!(
            first_pass, second_pass,
            "managedFields must survive a serialize/deserialize round-trip byte-for-byte — a \
             dropped or reordered field here would corrupt server-side-apply's field-ownership \
             record for every subsequent apply"
        );
        assert_eq!(restored.managed_fields, meta.managed_fields);
    }

    /// ObjectMeta must not add a `managedFields: null` key when the source metadata never had
    /// one. Every object never touched by server-side apply lacks the key entirely; if the
    /// round-trip through ObjectMeta introduced an explicit null, clients that check for key
    /// presence to detect "has been server-side-applied" would start seeing false positives,
    /// and every such read-modify-write would grow an extra key.
    #[test]
    fn object_meta_without_managed_fields_wire_format_unchanged() {
        let original = serde_json::json!({
            "name": "my-pod",
            "namespace": "default",
            "uid": "abc-123"
        });
        let original_bytes = serde_json::to_vec(&original).unwrap();
        let meta: ObjectMeta = serde_json::from_value(original).unwrap();
        let round_tripped_bytes =
            serde_json::to_vec(&serde_json::to_value(&meta).unwrap()).unwrap();
        assert_eq!(
            round_tripped_bytes, original_bytes,
            "ObjectMeta without managedFields must serialize back byte-identical; a \
             managedFields:null key would silently appear on every object never touched by \
             server-side apply"
        );
    }

    /// A metadata object with generation and deletionGracePeriodSeconds set (the state of a
    /// workload mid-graceful-termination) must round-trip through ObjectMeta byte-identically.
    /// mayor-7p767 depends on this: tightening watch/PartialObjectMetadata handling to a full
    /// ObjectMeta round-trip is only safe once these fields survive it — before they existed,
    /// KCM's controllers would see a null generation on the projected object and silently skip
    /// reconciling it, and the kubelet would lose the grace period needed to know when to
    /// force-remove a terminating pod.
    #[test]
    fn object_meta_generation_and_deletion_grace_period_round_trip_byte_identical() {
        let meta = ObjectMeta {
            generation: Some(7),
            deletion_grace_period_seconds: Some(30),
            ..Default::default()
        };
        let first_pass = serde_json::to_vec(&serde_json::to_value(&meta).unwrap()).unwrap();
        let restored: ObjectMeta = serde_json::from_slice(&first_pass).unwrap();
        let second_pass = serde_json::to_vec(&serde_json::to_value(&restored).unwrap()).unwrap();
        assert_eq!(
            first_pass, second_pass,
            "generation and deletionGracePeriodSeconds must survive a serialize/deserialize \
             round-trip byte-for-byte — a dropped field here would reproduce the exact \
             'generation=null causes controllers to stop reconciling' bug defaults.rs warns \
             about"
        );
        assert_eq!(restored.generation, meta.generation);
        assert_eq!(
            restored.deletion_grace_period_seconds,
            meta.deletion_grace_period_seconds
        );
    }

    /// ObjectMeta must not add `generation: null` or `deletionGracePeriodSeconds: null` keys
    /// when the source metadata never had them. Every object written before these fields
    /// existed lacks the keys entirely; if the round-trip through ObjectMeta introduced
    /// explicit nulls, KCM's controllers reading metadata.generation would see a present-but-
    /// null value rather than an absent field, and every such read-modify-write would grow two
    /// extra keys.
    #[test]
    fn object_meta_without_generation_or_deletion_grace_period_wire_format_unchanged() {
        let original = serde_json::json!({
            "name": "my-pod",
            "namespace": "default",
            "uid": "abc-123"
        });
        let original_bytes = serde_json::to_vec(&original).unwrap();
        let meta: ObjectMeta = serde_json::from_value(original).unwrap();
        let round_tripped_bytes =
            serde_json::to_vec(&serde_json::to_value(&meta).unwrap()).unwrap();
        assert_eq!(
            round_tripped_bytes, original_bytes,
            "ObjectMeta without generation/deletionGracePeriodSeconds must serialize back \
             byte-identical; a generation:null or deletionGracePeriodSeconds:null key would \
             silently appear on every object never touched by these fields"
        );
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
        // core v1 resources required for network and storage functionality
        assert!(
            names.contains(&"endpoints"),
            "endpoints must be in /api/v1 — kube-proxy and service routing depend on it"
        );
        assert!(
            names.contains(&"persistentvolumes"),
            "persistentvolumes must be in /api/v1 — cluster-scoped storage lifecycle requires it"
        );
        assert!(
            names.contains(&"persistentvolumeclaims"),
            "persistentvolumeclaims must be in /api/v1 — workloads request storage through PVCs"
        );
        assert!(
            names.contains(&"replicationcontrollers"),
            "replicationcontrollers must be in /api/v1 — legacy but required for API conformance"
        );
    }

    /// podtemplates must be advertised in /api/v1 discovery. kubectl resolves Kind -> resource
    /// name via client-side discovery (RESTMapper) before issuing any request, so without this
    /// entry `kubectl get/apply/describe podtemplates` fails locally with "the server doesn't
    /// have a resource type" — even though the registry (state.rs::build_registry) and the
    /// generic core-resource handlers already serve podtemplates correctly.
    #[test]
    fn podtemplates_advertised_in_v1_discovery() {
        let list = ApiResourceList::v1();
        let podtemplates = list
            .resources
            .iter()
            .find(|r| r.name == "podtemplates")
            .expect(
                "podtemplates absent from /api/v1 discovery — kubectl get/apply/describe \
                 podtemplates fails client-side before ever reaching the apiserver",
            );
        assert_eq!(
            podtemplates.singular_name, "podtemplate",
            "singularName must be 'podtemplate' so `kubectl get podtemplate <name>` resolves"
        );
        assert_eq!(
            podtemplates.kind, "PodTemplate",
            "kind must be 'PodTemplate' so kubectl maps the resource to the correct type"
        );
        assert!(
            podtemplates.namespaced,
            "podtemplates are namespaced — build_registry stores them per-namespace, \
             and mismatched discovery would send kubectl to the wrong URL shape"
        );
    }

    /// pods/resize must be advertised in /api/v1 discovery or client-go falls back
    /// to the regular replace endpoint, bypassing the resize-specific validation
    /// and generation-bump logic.
    ///
    /// All pod subresources (binding, ephemeralcontainers, eviction, log, resize, status)
    /// must be present so that discovery-aware clients can correctly route subresource requests.
    #[test]
    fn pod_subresources_advertised_in_v1_discovery() {
        let list = ApiResourceList::v1();
        let names: Vec<&str> = list.resources.iter().map(|r| r.name).collect();

        assert!(
            names.contains(&"pods/resize"),
            "pods/resize must be in /api/v1 — without it client-go falls back \
             to the replace endpoint and bypasses resize-specific handling"
        );
        assert!(
            names.contains(&"pods/status"),
            "pods/status must be in /api/v1 — kubelet and controllers patch pod status via this subresource"
        );
        assert!(
            names.contains(&"pods/log"),
            "pods/log must be in /api/v1 — kubectl logs depends on this subresource"
        );
        assert!(
            names.contains(&"pods/binding"),
            "pods/binding must be in /api/v1 — scheduler uses this to bind pods to nodes"
        );
        assert!(
            names.contains(&"pods/eviction"),
            "pods/eviction must be in /api/v1 — kubectl drain and PodDisruptionBudget enforcement use this"
        );
        assert!(
            names.contains(&"pods/ephemeralcontainers"),
            "pods/ephemeralcontainers must be in /api/v1 — kubectl debug uses this subresource"
        );

        // Verify pods/resize has the correct verbs for the resize protocol.
        let resize = list
            .resources
            .iter()
            .find(|r| r.name == "pods/resize")
            .expect("pods/resize must be in /api/v1");
        assert!(
            resize.verbs.contains(&"patch"),
            "pods/resize must advertise 'patch' verb — in-place resize uses PATCH"
        );
        assert!(
            resize.verbs.contains(&"update"),
            "pods/resize must advertise 'update' verb — in-place resize uses PUT"
        );
    }

    /// Core v1 resources must advertise "deletecollection" in their verbs list.
    ///
    /// The KCM namespace controller reads the API discovery and only calls
    /// deleteCollection on resources that include "deletecollection" in verbs.
    /// If the verb is missing, services linger after namespace deletion and the
    /// "kubernetes" finalizer is never removed, blocking namespace cleanup forever.
    #[test]
    fn core_resources_advertise_deletecollection_verb() {
        let list = ApiResourceList::v1();
        let services = list
            .resources
            .iter()
            .find(|r| r.name == "services")
            .expect("services must be in /api/v1");
        assert!(
            services.verbs.contains(&"deletecollection"),
            "services must advertise 'deletecollection' — without it the KCM \
             namespace controller skips deleteCollection and services linger \
             after namespace deletion"
        );
        let configmaps = list
            .resources
            .iter()
            .find(|r| r.name == "configmaps")
            .expect("configmaps must be in /api/v1");
        assert!(
            configmaps.verbs.contains(&"deletecollection"),
            "configmaps must advertise 'deletecollection' — namespace cleanup \
             requires deleteCollection for all namespaced resource types"
        );
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
            volumes: None,
        };
        let v = serde_json::to_value(&spec).unwrap();
        assert!(v.get("nodeName").is_none());
    }
}

#[cfg(test)]
mod pod_typed_fields_tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Round-trip: a full Pod JSON fixture is deserialized into typed structs
    // and re-serialized. No fields must be dropped (the `rest` flatten must
    // capture everything the typed fields don't claim).
    // -----------------------------------------------------------------------

    /// Volume must deserialize configMap.defaultMode and preserve untyped fields.
    ///
    /// The apiserver defaults defaultMode on create; if the typed struct drops
    /// other configMap fields (e.g. `name`, `items`) on round-trip, the pod's
    /// volume spec is silently corrupted.
    #[test]
    fn volume_config_map_round_trips_without_dropping_fields() {
        let json = serde_json::json!({
            "name": "my-cfg",
            "configMap": {
                "name": "app-config",
                "defaultMode": 420,
                "items": [{"key": "app.conf", "path": "app.conf"}]
            }
        });
        let vol: Volume = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(vol.name, "my-cfg");
        let cm = vol.config_map.as_ref().unwrap();
        assert_eq!(cm.default_mode, Some(420));
        // Re-serialize and verify nothing was dropped
        let out = serde_json::to_value(&vol).unwrap();
        assert_eq!(out["configMap"]["name"], "app-config");
        assert_eq!(out["configMap"]["defaultMode"], 420);
        assert_eq!(out["configMap"]["items"][0]["key"], "app.conf");
    }

    /// Volume must deserialize secret.defaultMode and preserve untyped fields.
    #[test]
    fn volume_secret_round_trips_without_dropping_fields() {
        let json = serde_json::json!({
            "name": "my-sec",
            "secret": {
                "secretName": "app-secret",
                "defaultMode": 256
            }
        });
        let vol: Volume = serde_json::from_value(json).unwrap();
        let sec = vol.secret.as_ref().unwrap();
        assert_eq!(sec.default_mode, Some(256));
        let out = serde_json::to_value(&vol).unwrap();
        assert_eq!(out["secret"]["secretName"], "app-secret");
        assert_eq!(out["secret"]["defaultMode"], 256);
    }

    /// Volume with an untyped source (emptyDir) must round-trip through `rest`.
    ///
    /// Volumes that are not configMap/secret/projected must not be silently
    /// dropped. The `rest` field on Volume must capture them.
    #[test]
    fn volume_untyped_source_survives_round_trip() {
        let json = serde_json::json!({
            "name": "scratch",
            "emptyDir": {"medium": "Memory", "sizeLimit": "128Mi"}
        });
        let vol: Volume = serde_json::from_value(json).unwrap();
        assert_eq!(vol.name, "scratch");
        assert!(vol.config_map.is_none());
        assert!(vol.secret.is_none());
        let out = serde_json::to_value(&vol).unwrap();
        assert_eq!(out["emptyDir"]["medium"], "Memory");
        assert_eq!(out["emptyDir"]["sizeLimit"], "128Mi");
    }

    /// PodSpec with volumes round-trips: volumes survive deserialization and
    /// re-serialization intact.
    #[test]
    fn pod_spec_with_volumes_round_trips() {
        let json = serde_json::json!({
            "nodeName": "worker-1",
            "enableServiceLinks": true,
            "volumes": [
                {"name": "cfg", "configMap": {"name": "my-cm", "defaultMode": 420}},
                {"name": "scratch", "emptyDir": {}}
            ],
            "containers": [{"name": "app", "image": "nginx"}]
        });
        let spec: PodSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.node_name.as_deref(), Some("worker-1"));
        let vols = spec.volumes.as_ref().unwrap();
        assert_eq!(vols.len(), 2);
        assert_eq!(vols[0].name, "cfg");
        assert_eq!(vols[0].config_map.as_ref().unwrap().default_mode, Some(420));
        assert_eq!(vols[1].name, "scratch");
        // containers must survive in rest (untyped field)
        let out = serde_json::to_value(&spec).unwrap();
        assert_eq!(out["nodeName"], "worker-1");
        assert_eq!(out["volumes"][0]["name"], "cfg");
        assert_eq!(out["volumes"][1]["emptyDir"], serde_json::json!({}));
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

#[cfg(test)]
mod csr_types_tests {
    use super::*;

    /// A minimal CSR JSON fixture exercising all typed fields and extra unknown fields.
    ///
    /// This test verifies the parse-at-boundary contract: typed fields are accessible
    /// with compiler-checked names, and unknown fields are preserved in `rest` so a
    /// round-trip through serde does not silently drop fields the apiserver does not
    /// yet type.
    #[test]
    fn csr_spec_round_trips_all_typed_fields() {
        let json = serde_json::json!({
            "request": "dGVzdA==",
            "signerName": "kubernetes.io/kube-apiserver-client",
            "usages": ["client auth"],
            "expirationSeconds": 86400
        });

        let spec: CertificateSigningRequestSpec = serde_json::from_value(json.clone()).unwrap();

        // Typed fields are accessible without map indexing.
        assert_eq!(
            spec.request, "dGVzdA==",
            "request must deserialize to typed field — map lookup has no compile-time safety"
        );
        assert_eq!(spec.signer_name, "kubernetes.io/kube-apiserver-client",
            "signerName must deserialize to signer_name — wrong camelCase mapping silently routes to wrong signer");

        // Unknown fields must survive in rest — no data loss on round-trip.
        let round_tripped = serde_json::to_value(&spec).unwrap();
        assert_eq!(round_tripped["request"], "dGVzdA==");
        assert_eq!(
            round_tripped["signerName"],
            "kubernetes.io/kube-apiserver-client"
        );
        assert_eq!(
            round_tripped["usages"][0], "client auth",
            "usages must be preserved in rest — losing unknown fields corrupts the stored object"
        );
        assert_eq!(
            round_tripped["expirationSeconds"], 86400,
            "expirationSeconds must be preserved in rest"
        );
    }

    /// CertificateSigningRequestStatus must deserialize certificate and conditions,
    /// and preserve unknown fields.
    ///
    /// The signer writes status.certificate; the approver writes status.conditions.
    /// Both fields must be accessible via typed structs, and a round-trip must not
    /// drop other status fields (e.g. observedGeneration).
    #[test]
    fn csr_status_round_trips_all_typed_fields() {
        let json = serde_json::json!({
            "certificate": "Q0VSVF9EQVRB",
            "conditions": [
                {
                    "type": "Approved",
                    "status": "True",
                    "reason": "KubectlApprove",
                    "message": "approved by test",
                    "lastUpdateTime": "2024-01-01T00:00:00Z",
                    "extraField": "preserved"
                }
            ],
            "observedGeneration": 1
        });

        let status: CertificateSigningRequestStatus = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(status.certificate.as_deref(), Some("Q0VSVF9EQVRB"),
            "certificate must deserialize to typed Option<String> — map lookup returns Value::Null on absent, not None");
        let conds = status.conditions.as_ref().expect("conditions must be Some");
        assert_eq!(conds.len(), 1);
        assert_eq!(
            conds[0].condition_type, "Approved",
            "condition_type must map from 'type' — wrong rename silently hides approval state"
        );
        assert_eq!(conds[0].status, "True");
        assert_eq!(conds[0].reason.as_deref(), Some("KubectlApprove"));
        assert_eq!(conds[0].message.as_deref(), Some("approved by test"));
        assert_eq!(
            conds[0].last_update_time.as_deref(),
            Some("2024-01-01T00:00:00Z")
        );

        // Round-trip: all fields must survive serialization.
        let round_tripped = serde_json::to_value(&status).unwrap();
        assert_eq!(round_tripped["certificate"], "Q0VSVF9EQVRB");
        assert_eq!(round_tripped["conditions"][0]["type"], "Approved");
        assert_eq!(
            round_tripped["conditions"][0]["extraField"], "preserved",
            "extra fields in a condition must survive round-trip via rest"
        );
        assert_eq!(
            round_tripped["observedGeneration"], 1,
            "status.observedGeneration must survive via rest — losing it corrupts status history"
        );
    }

    /// CertificateSigningRequestStatus with no certificate must deserialize as None.
    ///
    /// A pending CSR has no certificate yet. None must not be confused with an
    /// empty string — a signer that checks for empty string would wrongly think
    /// a cert was issued.
    #[test]
    fn csr_status_certificate_absent_is_none() {
        let json = serde_json::json!({
            "conditions": []
        });
        let status: CertificateSigningRequestStatus = serde_json::from_value(json).unwrap();
        assert!(
            status.certificate.is_none(),
            "absent certificate must be None — only the signer may set it; None != empty string"
        );
    }

    /// CsrCondition 'type' field must serialize as 'type', not 'conditionType'.
    ///
    /// The wire name is 'type' (a reserved word in Rust). The rename annotation must
    /// be present; without it the field would serialize as 'condition_type', breaking
    /// kubectl certificate approve.
    #[test]
    fn csr_condition_type_serializes_as_wire_name_type() {
        let cond = CsrCondition {
            condition_type: "Denied".to_owned(),
            status: "True".to_owned(),
            reason: None,
            message: None,
            last_update_time: None,
            rest: serde_json::Value::Object(Default::default()),
        };
        let v = serde_json::to_value(&cond).unwrap();
        assert_eq!(v["type"], "Denied",
            "CsrCondition must serialize condition_type as 'type' — wrong key breaks kubectl certificate deny");
        assert!(
            v.get("conditionType").is_none(),
            "'conditionType' must not appear — only 'type' is understood by kubectl"
        );
    }
}

#[cfg(test)]
mod condition_tests {
    use super::*;

    /// `Condition` must round-trip all six upstream `metav1.Condition` fields
    /// byte-identically. Every future consumer (e.g. APIService availability)
    /// relies on this shape being wire-exact; a dropped or misnamed field here
    /// would silently corrupt condition reporting for every resource that reuses
    /// this struct, not just one call site.
    #[test]
    fn condition_round_trips_all_fields_byte_identical() {
        let original = serde_json::json!({
            "type": "Available",
            "status": "True",
            "reason": "AllBackendsReachable",
            "message": "all backends healthy",
            "lastTransitionTime": "2024-01-01T00:00:00Z",
            "observedGeneration": 3
        });

        let cond: Condition = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(cond.type_, "Available");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("AllBackendsReachable"));
        assert_eq!(cond.message.as_deref(), Some("all backends healthy"));
        assert_eq!(
            cond.last_transition_time.as_deref(),
            Some("2024-01-01T00:00:00Z")
        );
        assert_eq!(cond.observed_generation, Some(3));

        let round_tripped = serde_json::to_value(&cond).unwrap();
        assert_eq!(
            round_tripped, original,
            "Condition must serialize back byte-identical to the wire form it was \
             parsed from — e.g. dropping #[serde(rename_all = \"camelCase\")] would emit \
             `last_transition_time`/`observed_generation` instead of the camelCase wire \
             names every client (kubectl, controllers) actually reads"
        );
    }

    /// `Condition` fields absent on the wire must round-trip as absent, not as
    /// explicit nulls — controllers that check for key presence (e.g. "has this
    /// resource ever reported a reason") must not see false positives.
    #[test]
    fn condition_without_optional_fields_wire_format_unchanged() {
        let original = serde_json::json!({
            "type": "Available",
            "status": "Unknown"
        });
        let cond: Condition = serde_json::from_value(original.clone()).unwrap();
        let round_tripped = serde_json::to_value(&cond).unwrap();
        assert_eq!(
            round_tripped, original,
            "Condition without reason/message/lastTransitionTime/observedGeneration \
             must not grow explicit null keys on round-trip"
        );
    }
}
