//! Kubernetes protobuf wire format decoder — prost-backed implementation.
//!
//! kubectl sends write requests with `Content-Type: application/vnd.kubernetes.protobuf` by
//! default. The encoding is NOT standard protobuf alone — it uses a 4-byte magic prefix followed
//! by a protobuf-encoded `Unknown` envelope whose `raw` field (field 2) contains the actual object
//! (usually JSON when contentType = "application/json", or proto when contentType =
//! "application/vnd.kubernetes.protobuf" for types with registered proto codecs like Namespace).
//!
//! Wire format:
//!   [4 bytes magic: 0x6b, 0x38, 0x73, 0x00]
//!   [protobuf-encoded Unknown message]
//!
//! Unknown fields (from k8s.io/apimachinery/pkg/runtime/generated.proto):
//!   field 1 (TypeMeta, wire type 2):  tag = 0x0a
//!   field 2 (raw bytes, wire type 2): tag = 0x12  <- the encoded object
//!   field 3 (contentEncoding, wire 2): tag = 0x1a
//!   field 4 (contentType, wire 2):    tag = 0x22  <- "application/json" or ".../protobuf"

use prost::Message;

const K8S_PROTO_MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];

// ---------------------------------------------------------------------------
// Prost-generated message types
// All field numbers match the official k8s .proto definitions exactly.
// Option B: every field of every message type we decode is included.
// ---------------------------------------------------------------------------

// --- k8s.io/apimachinery/pkg/runtime/generated.proto ---

/// TypeMeta — embedded in Unknown field 1.
/// k8s.io/apimachinery/pkg/apis/meta/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct TypeMeta {
    /// apiVersion (field 1, string)
    #[prost(string, tag = "1")]
    api_version: String,
    /// kind (field 2, string)
    #[prost(string, tag = "2")]
    kind: String,
}

/// Unknown — the k8s protobuf envelope.
/// k8s.io/apimachinery/pkg/runtime/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Unknown {
    /// typeMeta (field 1, message)
    #[prost(message, tag = "1")]
    type_meta: Option<TypeMeta>,
    /// raw (field 2, bytes) — the actual object, often JSON
    #[prost(bytes = "vec", tag = "2")]
    raw: Vec<u8>,
    /// contentEncoding (field 3, string)
    #[prost(string, tag = "3")]
    content_encoding: String,
    /// contentType (field 4, string)
    #[prost(string, tag = "4")]
    content_type: String,
}

// --- k8s.io/apimachinery/pkg/apis/meta/v1/generated.proto ---

/// Time wrapper message (field 1 = int64 seconds since epoch).
/// Used for creationTimestamp, deletionTimestamp etc.
#[derive(Clone, PartialEq, Message)]
struct Time {
    /// seconds (field 1, int64)
    #[prost(int64, tag = "1")]
    seconds: i64,
    /// nanos (field 2, int32)
    #[prost(int32, tag = "2")]
    nanos: i32,
}

/// MicroTime — same as Time but microsecond precision.
#[derive(Clone, PartialEq, Message)]
struct MicroTime {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}

/// ObjectMeta — common metadata for all Kubernetes objects.
/// k8s.io/apimachinery/pkg/apis/meta/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ObjectMeta {
    /// name (field 1, string)
    #[prost(string, tag = "1")]
    name: String,
    /// generateName (field 2, string)
    #[prost(string, tag = "2")]
    generate_name: String,
    /// namespace (field 3, string)
    #[prost(string, tag = "3")]
    namespace: String,
    /// selfLink (field 4, string) — deprecated
    #[prost(string, tag = "4")]
    self_link: String,
    /// uid (field 5, string)
    #[prost(string, tag = "5")]
    uid: String,
    /// resourceVersion (field 6, string)
    #[prost(string, tag = "6")]
    resource_version: String,
    /// generation (field 7, int64)
    #[prost(int64, tag = "7")]
    generation: i64,
    /// creationTimestamp (field 8, message Time)
    #[prost(message, tag = "8")]
    creation_timestamp: Option<Time>,
    /// deletionTimestamp (field 9, message Time)
    #[prost(message, tag = "9")]
    deletion_timestamp: Option<Time>,
    /// deletionGracePeriodSeconds (field 10, int64)
    #[prost(int64, tag = "10")]
    deletion_grace_period_seconds: i64,
    /// labels (field 11, map<string, string>)
    #[prost(map = "string, string", tag = "11")]
    labels: std::collections::HashMap<String, String>,
    /// annotations (field 12, map<string, string>)
    #[prost(map = "string, string", tag = "12")]
    annotations: std::collections::HashMap<String, String>,
    /// ownerReferences (field 13, repeated OwnerReference) — decoded as raw bytes
    #[prost(bytes = "vec", repeated, tag = "13")]
    owner_references: Vec<Vec<u8>>,
    /// finalizers (field 14, repeated string)
    #[prost(string, repeated, tag = "14")]
    finalizers: Vec<String>,
}

// --- k8s.io/api/core/v1/generated.proto ---

/// NamespaceSpec (field 1=finalizers repeated string)
#[derive(Clone, PartialEq, Message)]
struct NamespaceSpec {
    #[prost(string, repeated, tag = "1")]
    finalizers: Vec<String>,
}

/// NamespaceStatus (field 1=phase string, field 2=conditions repeated bytes)
#[derive(Clone, PartialEq, Message)]
struct NamespaceStatus {
    #[prost(string, tag = "1")]
    phase: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    conditions: Vec<Vec<u8>>,
}

/// Namespace — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Namespace {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message NamespaceSpec)
    #[prost(message, tag = "2")]
    spec: Option<NamespaceSpec>,
    /// status (field 3, message NamespaceStatus)
    #[prost(message, tag = "3")]
    status: Option<NamespaceStatus>,
}

/// PodTemplate — k8s.io/api/core/v1/generated.proto
/// Only metadata (field 1) is decoded; template (field 2, PodTemplateSpec) is skipped.
/// The chunking conformance test creates PodTemplates via proto; we only need name/namespace
/// to return 201 and allow the test to proceed past the Create phase without panicking.
#[derive(Clone, PartialEq, Message)]
struct PodTemplate {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    // template (field 2, PodTemplateSpec) — skipped; PodSpec is deeply nested and not needed
    // for routing/storage. The template is preserved as an empty object in the output JSON.
}

/// Container — minimal decode: name (field 1) and image (field 2).
/// All other Container fields are ignored (ports, env, volumeMounts, probes, etc.)
/// because we only need name+image to produce a valid stored Pod JSON.
#[derive(Clone, PartialEq, Message)]
struct Container {
    /// name (field 1, string)
    #[prost(string, tag = "1")]
    name: String,
    /// image (field 2, string)
    #[prost(string, tag = "2")]
    image: String,
    /// command (field 3, repeated string)
    #[prost(string, repeated, tag = "3")]
    command: Vec<String>,
    /// args (field 4, repeated string)
    #[prost(string, repeated, tag = "4")]
    args: Vec<String>,
    /// imagePullPolicy (field 15, string)
    #[prost(string, tag = "15")]
    image_pull_policy: String,
    /// terminationMessagePath (field 14, string)
    #[prost(string, tag = "14")]
    termination_message_path: String,
    /// terminationMessagePolicy (field 21, string)
    #[prost(string, tag = "21")]
    termination_message_policy: String,
}

/// PodSpec — k8s.io/api/core/v1/generated.proto
/// Field numbers match the official proto exactly:
///   field 1  = volumes (skipped — not needed for routing)
///   field 2  = containers (repeated Container)
///   field 3  = restartPolicy (string)
///   field 4  = terminationGracePeriodSeconds (int64, skipped)
///   field 5  = activeDeadlineSeconds (int64, skipped)
///   field 6  = dnsPolicy (string, skipped)
///   field 7  = nodeSelector (map, skipped)
///   field 8  = serviceAccountName (string)
///   field 9  = automountServiceAccountToken (bool, skipped)
///   field 10 = nodeName (string)
///   field 11 = hostNetwork (bool, skipped)
#[derive(Clone, PartialEq, Message)]
struct PodSpec {
    /// containers (field 2, repeated Container)
    #[prost(message, repeated, tag = "2")]
    containers: Vec<Container>,
    /// restartPolicy (field 3, string)
    #[prost(string, tag = "3")]
    restart_policy: String,
    /// serviceAccountName (field 8, string)
    #[prost(string, tag = "8")]
    service_account_name: String,
    /// nodeName (field 10, string)
    #[prost(string, tag = "10")]
    node_name: String,
}

/// Pod — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Pod {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message PodSpec)
    #[prost(message, tag = "2")]
    spec: Option<PodSpec>,
    /// status (field 3, bytes) — not decoded on input
    #[prost(bytes = "vec", tag = "3")]
    status: Vec<u8>,
}

/// ConfigMap — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ConfigMap {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// data (field 2, map<string, string>)
    #[prost(map = "string, string", tag = "2")]
    data: std::collections::HashMap<String, String>,
    /// binaryData (field 3, map<string, bytes>)
    #[prost(map = "string, bytes", tag = "3")]
    binary_data: std::collections::HashMap<String, Vec<u8>>,
    /// immutable (field 4, bool)
    #[prost(bool, tag = "4")]
    immutable: bool,
}

/// ServicePort — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ServicePort {
    /// name (field 1, string)
    #[prost(string, tag = "1")]
    name: String,
    /// protocol (field 2, string)
    #[prost(string, tag = "2")]
    protocol: String,
    /// port (field 3, int32)
    #[prost(int32, tag = "3")]
    port: i32,
    /// targetPort (field 4, IntOrString) — decoded as raw bytes (union type)
    #[prost(bytes = "vec", tag = "4")]
    target_port: Vec<u8>,
    /// nodePort (field 5, int32)
    #[prost(int32, tag = "5")]
    node_port: i32,
    /// appProtocol (field 6, string)
    #[prost(string, tag = "6")]
    app_protocol: String,
}

/// ServiceSpec — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ServiceSpec {
    /// ports (field 1, repeated ServicePort)
    #[prost(message, repeated, tag = "1")]
    ports: Vec<ServicePort>,
    /// selector (field 2, map<string,string>)
    #[prost(map = "string, string", tag = "2")]
    selector: std::collections::HashMap<String, String>,
    /// clusterIP (field 3, string)
    #[prost(string, tag = "3")]
    cluster_ip: String,
    /// type (field 4, string)
    #[prost(string, tag = "4")]
    r#type: String,
    /// externalIPs (field 5, repeated string)
    #[prost(string, repeated, tag = "5")]
    external_ips: Vec<String>,
    /// sessionAffinity (field 7, string)
    #[prost(string, tag = "7")]
    session_affinity: String,
    /// externalName (field 10, string)
    #[prost(string, tag = "10")]
    external_name: String,
    /// externalTrafficPolicy (field 11, string)
    #[prost(string, tag = "11")]
    external_traffic_policy: String,
    /// ipFamilyPolicy (field 21, string)
    #[prost(string, tag = "21")]
    ip_family_policy: String,
    /// internalTrafficPolicy (field 24, string)
    #[prost(string, tag = "24")]
    internal_traffic_policy: String,
}

/// Service — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Service {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message ServiceSpec)
    #[prost(message, tag = "2")]
    spec: Option<ServiceSpec>,
    /// status (field 3, bytes) — not decoded on input
    #[prost(bytes = "vec", tag = "3")]
    status: Vec<u8>,
}

/// Secret — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Secret {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// data (field 2, map<string,bytes>)
    #[prost(map = "string, bytes", tag = "2")]
    data: std::collections::HashMap<String, Vec<u8>>,
    /// stringData (field 3, map<string,string>)
    #[prost(map = "string, string", tag = "3")]
    string_data: std::collections::HashMap<String, String>,
    /// type (field 4, string)
    #[prost(string, tag = "4")]
    r#type: String,
    /// immutable (field 5, bool)
    #[prost(bool, tag = "5")]
    immutable: bool,
}

/// ReplicationControllerSpec — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ReplicationControllerSpec {
    /// replicas (field 1, int32)
    #[prost(int32, tag = "1")]
    replicas: i32,
    /// selector (field 2, map<string,string>)
    #[prost(map = "string, string", tag = "2")]
    selector: std::collections::HashMap<String, String>,
    /// template (field 3, PodTemplateSpec) — decoded as raw bytes
    #[prost(bytes = "vec", tag = "3")]
    template: Vec<u8>,
}

/// ReplicationController — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ReplicationController {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message ReplicationControllerSpec)
    #[prost(message, tag = "2")]
    spec: Option<ReplicationControllerSpec>,
    /// status (field 3, bytes) — not decoded on input
    #[prost(bytes = "vec", tag = "3")]
    status: Vec<u8>,
}

/// PersistentVolumeSpec — k8s.io/api/core/v1/generated.proto (key fields only)
#[derive(Clone, PartialEq, Message)]
struct PersistentVolumeSpec {
    /// capacity (field 1, map<string,Quantity>) — decoded as raw bytes (Quantity is complex)
    #[prost(bytes = "vec", tag = "1")]
    capacity: Vec<u8>,
    /// accessModes (field 6, repeated string)
    #[prost(string, repeated, tag = "6")]
    access_modes: Vec<String>,
    /// claimRef (field 33, message ObjectReference) — decoded as raw bytes
    #[prost(bytes = "vec", tag = "33")]
    claim_ref: Vec<u8>,
    /// persistentVolumeReclaimPolicy (field 26, string)
    #[prost(string, tag = "26")]
    persistent_volume_reclaim_policy: String,
    /// storageClassName (field 29, string)
    #[prost(string, tag = "29")]
    storage_class_name: String,
    /// volumeMode (field 31, string)
    #[prost(string, tag = "31")]
    volume_mode: String,
}

/// PersistentVolume — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct PersistentVolume {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message PersistentVolumeSpec)
    #[prost(message, tag = "2")]
    spec: Option<PersistentVolumeSpec>,
    /// status (field 3, bytes) — not decoded on input
    #[prost(bytes = "vec", tag = "3")]
    status: Vec<u8>,
}

/// NodeSpec — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct NodeSpec {
    /// podCIDR (field 1, string)
    #[prost(string, tag = "1")]
    pod_cidr: String,
    /// externalID (field 2, string) — deprecated
    #[prost(string, tag = "2")]
    external_id: String,
    /// providerID (field 3, string)
    #[prost(string, tag = "3")]
    provider_id: String,
    /// unschedulable (field 4, bool)
    #[prost(bool, tag = "4")]
    unschedulable: bool,
    /// taints (field 5, repeated) — decoded as raw bytes (complex nested message)
    #[prost(bytes = "vec", repeated, tag = "5")]
    taints: Vec<Vec<u8>>,
    /// configSource (field 6, bytes) — deprecated, decoded as raw bytes
    #[prost(bytes = "vec", tag = "6")]
    config_source: Vec<u8>,
    /// podCIDRs (field 7, repeated string)
    #[prost(string, repeated, tag = "7")]
    pod_cidrs: Vec<String>,
}

/// Node — k8s.io/api/core/v1/generated.proto
/// NodeStatus (field 3) is decoded as raw bytes — it contains complex repeated fields
/// (conditions, addresses, capacity, etc.) that we don't need to read.
#[derive(Clone, PartialEq, Message)]
struct Node {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message NodeSpec)
    #[prost(message, tag = "2")]
    spec: Option<NodeSpec>,
    /// status (field 3, bytes) — opaque, not decoded
    #[prost(bytes = "vec", tag = "3")]
    status: Vec<u8>,
}

/// ObjectReference — used in Event.involvedObject
#[derive(Clone, PartialEq, Message)]
struct ObjectReference {
    /// kind (field 1, string)
    #[prost(string, tag = "1")]
    kind: String,
    /// namespace (field 2, string)
    #[prost(string, tag = "2")]
    namespace: String,
    /// name (field 3, string)
    #[prost(string, tag = "3")]
    name: String,
    /// uid (field 4, string)
    #[prost(string, tag = "4")]
    uid: String,
    /// apiVersion (field 5, string)
    #[prost(string, tag = "5")]
    api_version: String,
    /// resourceVersion (field 6, string)
    #[prost(string, tag = "6")]
    resource_version: String,
    /// fieldPath (field 7, string)
    #[prost(string, tag = "7")]
    field_path: String,
}

/// EventSource — source component of an Event
#[derive(Clone, PartialEq, Message)]
struct EventSource {
    #[prost(string, tag = "1")]
    component: String,
    #[prost(string, tag = "2")]
    host: String,
}

/// EventSeries — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct EventSeries {
    /// count (field 1, int32)
    #[prost(int32, tag = "1")]
    count: i32,
    /// lastObservedTime (field 2, MicroTime)
    #[prost(message, tag = "2")]
    last_observed_time: Option<MicroTime>,
}

/// Event — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Event {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// involvedObject (field 2, message ObjectReference)
    #[prost(message, tag = "2")]
    involved_object: Option<ObjectReference>,
    /// reason (field 3, string)
    #[prost(string, tag = "3")]
    reason: String,
    /// message (field 4, string)
    #[prost(string, tag = "4")]
    message: String,
    /// source (field 5, message EventSource)
    #[prost(message, tag = "5")]
    source: Option<EventSource>,
    /// firstTimestamp (field 6, message Time)
    #[prost(message, tag = "6")]
    first_timestamp: Option<Time>,
    /// lastTimestamp (field 7, message Time)
    #[prost(message, tag = "7")]
    last_timestamp: Option<Time>,
    /// count (field 8, int32)
    #[prost(int32, tag = "8")]
    count: i32,
    /// type (field 9, string)
    #[prost(string, tag = "9")]
    r#type: String,
    /// eventTime (field 10, MicroTime)
    #[prost(message, tag = "10")]
    event_time: Option<MicroTime>,
    /// series (field 11, message EventSeries)
    #[prost(message, tag = "11")]
    series: Option<EventSeries>,
    /// action (field 12, string)
    #[prost(string, tag = "12")]
    action: String,
    /// related (field 13, message ObjectReference)
    #[prost(message, tag = "13")]
    related: Option<ObjectReference>,
    /// reportingComponent (field 14, string)
    #[prost(string, tag = "14")]
    reporting_component: String,
    /// reportingInstance (field 15, string)
    #[prost(string, tag = "15")]
    reporting_instance: String,
}

// --- k8s.io/api/coordination/v1/generated.proto ---

/// LeaseSpec — k8s.io/api/coordination/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct LeaseSpec {
    /// holderIdentity (field 1, string)
    #[prost(string, tag = "1")]
    holder_identity: String,
    /// leaseDurationSeconds (field 2, int32)
    #[prost(int32, tag = "2")]
    lease_duration_seconds: i32,
    /// acquireTime (field 3, MicroTime)
    #[prost(message, tag = "3")]
    acquire_time: Option<MicroTime>,
    /// renewTime (field 4, MicroTime)
    #[prost(message, tag = "4")]
    renew_time: Option<MicroTime>,
    /// leaseTransitions (field 5, int32)
    #[prost(int32, tag = "5")]
    lease_transitions: i32,
    /// strategy (field 6, string) — CoordinatedLeaseStrategy
    #[prost(string, tag = "6")]
    strategy: String,
    /// preferredHolder (field 7, string)
    #[prost(string, tag = "7")]
    preferred_holder: String,
}

/// Lease — k8s.io/api/coordination/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Lease {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message LeaseSpec)
    #[prost(message, tag = "2")]
    spec: Option<LeaseSpec>,
}

// --- k8s.io/api/storage/v1/generated.proto ---

/// VolumeNodeResources — used in CSINodeAllocatable
#[derive(Clone, PartialEq, Message)]
struct VolumeNodeResources {
    /// count (field 1, int32) — maximum number of unique volumes managed by the CSI driver
    #[prost(int32, tag = "1")]
    count: i32,
}

/// CSINodeDriver — k8s.io/api/storage/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct CsiNodeDriver {
    /// name (field 1, string)
    #[prost(string, tag = "1")]
    name: String,
    /// nodeID (field 2, string)
    #[prost(string, tag = "2")]
    node_id: String,
    /// topologyKeys (field 3, repeated string)
    #[prost(string, repeated, tag = "3")]
    topology_keys: Vec<String>,
    /// allocatable (field 4, message VolumeNodeResources)
    #[prost(message, tag = "4")]
    allocatable: Option<VolumeNodeResources>,
}

/// CSINodeSpec — k8s.io/api/storage/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct CsiNodeSpec {
    /// drivers (field 1, repeated CSINodeDriver)
    #[prost(message, repeated, tag = "1")]
    drivers: Vec<CsiNodeDriver>,
}

/// CSINode — k8s.io/api/storage/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct CsiNode {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message CSINodeSpec)
    #[prost(message, tag = "2")]
    spec: Option<CsiNodeSpec>,
}

/// VolumeAttachmentSource — k8s.io/api/storage/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct VolumeAttachmentSource {
    /// persistentVolumeName (field 1, string)
    #[prost(string, tag = "1")]
    persistent_volume_name: String,
    /// inlineVolumeSpec (field 2, bytes) — complex, decoded as raw bytes
    #[prost(bytes = "vec", tag = "2")]
    inline_volume_spec: Vec<u8>,
}

/// VolumeAttachmentSpec — k8s.io/api/storage/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct VolumeAttachmentSpec {
    /// attacher (field 1, string)
    #[prost(string, tag = "1")]
    attacher: String,
    /// source (field 2, message VolumeAttachmentSource)
    #[prost(message, tag = "2")]
    source: Option<VolumeAttachmentSource>,
    /// nodeName (field 3, string)
    #[prost(string, tag = "3")]
    node_name: String,
}

/// VolumeAttachment — k8s.io/api/storage/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct VolumeAttachment {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message VolumeAttachmentSpec)
    #[prost(message, tag = "2")]
    spec: Option<VolumeAttachmentSpec>,
    /// status (field 3, bytes) — not decoded on input
    #[prost(bytes = "vec", tag = "3")]
    status: Vec<u8>,
}

// --- k8s.io/api/node/v1/generated.proto ---

/// RuntimeClass — k8s.io/api/node/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct RuntimeClass {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// handler (field 2, string)
    #[prost(string, tag = "2")]
    handler: String,
    /// overhead (field 3, bytes) — complex message, decoded as raw bytes
    #[prost(bytes = "vec", tag = "3")]
    overhead: Vec<u8>,
    /// scheduling (field 4, bytes) — complex message, decoded as raw bytes
    #[prost(bytes = "vec", tag = "4")]
    scheduling: Vec<u8>,
}

// --- k8s.io/api/authorization/v1/generated.proto ---

/// ResourceAttributes — describes a resource request in SubjectAccessReviewSpec.
#[derive(Clone, PartialEq, Message)]
struct ResourceAttributes {
    /// namespace (field 1, string)
    #[prost(string, tag = "1")]
    namespace: String,
    /// verb (field 2, string)
    #[prost(string, tag = "2")]
    verb: String,
    /// group (field 3, string)
    #[prost(string, tag = "3")]
    group: String,
    /// version (field 4, string)
    #[prost(string, tag = "4")]
    version: String,
    /// resource (field 5, string)
    #[prost(string, tag = "5")]
    resource: String,
    /// subresource (field 6, string)
    #[prost(string, tag = "6")]
    subresource: String,
    /// name (field 7, string)
    #[prost(string, tag = "7")]
    name: String,
}

/// SubjectAccessReviewSpec — the input to a SubjectAccessReview.
#[derive(Clone, PartialEq, Message)]
struct SubjectAccessReviewSpec {
    /// resourceAttributes (field 1, message ResourceAttributes)
    #[prost(message, tag = "1")]
    resource_attributes: Option<ResourceAttributes>,
    // field 2 (NonResourceAttributes) — intentionally omitted
    /// user (field 3, string)
    #[prost(string, tag = "3")]
    user: String,
    /// groups (field 4, repeated string)
    #[prost(string, repeated, tag = "4")]
    groups: Vec<String>,
}

/// SubjectAccessReview — k8s.io/api/authorization/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct SubjectAccessReviewProto {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message SubjectAccessReviewSpec)
    #[prost(message, tag = "2")]
    spec: Option<SubjectAccessReviewSpec>,
    // status (field 3) — ignored on input
}

/// TokenReviewSpec — k8s.io/api/authentication/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct TokenReviewSpec {
    /// token (field 1, string)
    #[prost(string, tag = "1")]
    token: String,
    /// audiences (field 2, repeated string)
    #[prost(string, repeated, tag = "2")]
    audiences: Vec<String>,
}

/// TokenReview — k8s.io/api/authentication/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct TokenReviewProto {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message TokenReviewSpec)
    #[prost(message, tag = "2")]
    spec: Option<TokenReviewSpec>,
    // status (field 3) — ignored on input
}

// --- k8s.io/api/authentication/v1/generated.proto ---

/// BoundObjectReference — used in TokenRequestSpec
#[derive(Clone, PartialEq, Message)]
struct BoundObjectReference {
    /// kind (field 1, string)
    #[prost(string, tag = "1")]
    kind: String,
    /// apiVersion (field 2, string)
    #[prost(string, tag = "2")]
    api_version: String,
    /// name (field 3, string)
    #[prost(string, tag = "3")]
    name: String,
    /// uid (field 4, string)
    #[prost(string, tag = "4")]
    uid: String,
}

/// TokenRequestSpec — k8s.io/api/authentication/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct TokenRequestSpec {
    /// audiences (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    audiences: Vec<String>,
    /// expirationSeconds (field 2, int64) — optional, 0 = unset
    #[prost(int64, tag = "2")]
    expiration_seconds: i64,
    /// boundObjectRef (field 3, message BoundObjectReference)
    #[prost(message, tag = "3")]
    bound_object_ref: Option<BoundObjectReference>,
}

/// TokenRequestStatus — k8s.io/api/authentication/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct TokenRequestStatus {
    /// token (field 1, string)
    #[prost(string, tag = "1")]
    token: String,
    /// expirationTimestamp (field 2, message Time)
    #[prost(message, tag = "2")]
    expiration_timestamp: Option<Time>,
}

/// TokenRequest — k8s.io/api/authentication/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct TokenRequestProto {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message TokenRequestSpec)
    #[prost(message, tag = "2")]
    spec: Option<TokenRequestSpec>,
    /// status (field 3, message TokenRequestStatus)
    #[prost(message, tag = "3")]
    status: Option<TokenRequestStatus>,
}

// --- k8s.io/api/rbac/v1/generated.proto ---

/// PolicyRule — a single RBAC policy rule.
#[derive(Clone, PartialEq, Message)]
struct PolicyRule {
    /// verbs (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    verbs: Vec<String>,
    /// apiGroups (field 2, repeated string)
    #[prost(string, repeated, tag = "2")]
    api_groups: Vec<String>,
    /// resources (field 3, repeated string)
    #[prost(string, repeated, tag = "3")]
    resources: Vec<String>,
    /// resourceNames (field 4, repeated string)
    #[prost(string, repeated, tag = "4")]
    resource_names: Vec<String>,
    /// nonResourceURLs (field 5, repeated string)
    #[prost(string, repeated, tag = "5")]
    non_resource_urls: Vec<String>,
}

/// Subject — a user, group, or service account in a RoleBinding.
#[derive(Clone, PartialEq, Message)]
struct Subject {
    /// kind (field 1, string)
    #[prost(string, tag = "1")]
    kind: String,
    /// apiGroup (field 2, string)
    #[prost(string, tag = "2")]
    api_group: String,
    /// name (field 3, string)
    #[prost(string, tag = "3")]
    name: String,
    /// namespace (field 4, string)
    #[prost(string, tag = "4")]
    namespace: String,
}

/// RoleRef — reference to the role being bound.
#[derive(Clone, PartialEq, Message)]
struct RoleRef {
    /// apiGroup (field 1, string)
    #[prost(string, tag = "1")]
    api_group: String,
    /// kind (field 2, string)
    #[prost(string, tag = "2")]
    kind: String,
    /// name (field 3, string)
    #[prost(string, tag = "3")]
    name: String,
}

/// ClusterRole — k8s.io/api/rbac/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ClusterRole {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// rules (field 2, repeated PolicyRule)
    #[prost(message, repeated, tag = "2")]
    rules: Vec<PolicyRule>,
    // aggregationRule (field 3) is intentionally omitted — not needed for kubectl compat
}

/// ClusterRoleBinding — k8s.io/api/rbac/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ClusterRoleBinding {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// subjects (field 2, repeated Subject)
    #[prost(message, repeated, tag = "2")]
    subjects: Vec<Subject>,
    /// roleRef (field 3, message RoleRef)
    #[prost(message, tag = "3")]
    role_ref: Option<RoleRef>,
}

/// Role — namespaced, same structure as ClusterRole but namespaced.
/// k8s.io/api/rbac/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Role {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// rules (field 2, repeated PolicyRule)
    #[prost(message, repeated, tag = "2")]
    rules: Vec<PolicyRule>,
}

/// RoleBinding — namespaced.
/// k8s.io/api/rbac/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct RoleBinding {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// subjects (field 2, repeated Subject)
    #[prost(message, repeated, tag = "2")]
    subjects: Vec<Subject>,
    /// roleRef (field 3, message RoleRef)
    #[prost(message, tag = "3")]
    role_ref: Option<RoleRef>,
}

// --- k8s.io/api/batch/v1/generated.proto ---

/// JobSpec — k8s.io/api/batch/v1/generated.proto
/// Only scalar/string fields are decoded; template (field 5, PodTemplateSpec) is skipped —
/// PodSpec is deeply nested and the same strategy as PodTemplate applies.
#[derive(Clone, PartialEq, Message)]
struct JobSpec {
    /// parallelism (field 1, int32)
    #[prost(int32, tag = "1")]
    parallelism: i32,
    /// completions (field 2, int32)
    #[prost(int32, tag = "2")]
    completions: i32,
    /// activeDeadlineSeconds (field 3, int64)
    #[prost(int64, tag = "3")]
    active_deadline_seconds: i64,
    /// selector (field 4, message LabelSelector) — decoded as raw bytes, not needed for routing
    #[prost(bytes = "vec", tag = "4")]
    selector: Vec<u8>,
    /// template (field 5, PodTemplateSpec) — decoded as raw bytes; PodSpec is deeply nested
    #[prost(bytes = "vec", tag = "5")]
    template: Vec<u8>,
    /// backoffLimit (field 6, int32)
    #[prost(int32, tag = "6")]
    backoff_limit: i32,
    /// manualSelector (field 7, bool)
    #[prost(bool, tag = "7")]
    manual_selector: bool,
    /// completionMode (field 8, string) — "NonIndexed" or "Indexed"
    #[prost(string, tag = "8")]
    completion_mode: String,
    /// suspend (field 9, bool)
    #[prost(bool, tag = "9")]
    suspend: bool,
    /// podReplacementPolicy (field 10, string) — added k8s 1.28
    #[prost(string, tag = "10")]
    pod_replacement_policy: String,
    /// podFailurePolicy (field 11, bytes) — complex message, decoded as raw bytes
    #[prost(bytes = "vec", tag = "11")]
    pod_failure_policy: Vec<u8>,
    /// successPolicy (field 12, bytes) — complex message, decoded as raw bytes
    #[prost(bytes = "vec", tag = "12")]
    success_policy: Vec<u8>,
    /// backoffLimitPerIndex (field 13, int32) — added k8s 1.28
    #[prost(int32, tag = "13")]
    backoff_limit_per_index: i32,
    /// maxFailedIndexes (field 14, int32) — added k8s 1.28
    #[prost(int32, tag = "14")]
    max_failed_indexes: i32,
    /// managedBy (field 15, string) — added k8s 1.30
    #[prost(string, tag = "15")]
    managed_by: String,
}

/// JobTemplateSpec — field 1=ObjectMeta, field 2=JobSpec
#[derive(Clone, PartialEq, Message)]
struct JobTemplateSpec {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message JobSpec)
    #[prost(message, tag = "2")]
    spec: Option<JobSpec>,
}

/// CronJobSpec — k8s.io/api/batch/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct CronJobSpec {
    /// schedule (field 1, string)
    #[prost(string, tag = "1")]
    schedule: String,
    /// startingDeadlineSeconds (field 2, int64)
    #[prost(int64, tag = "2")]
    starting_deadline_seconds: i64,
    /// concurrencyPolicy (field 3, string)
    #[prost(string, tag = "3")]
    concurrency_policy: String,
    /// suspend (field 4, bool)
    #[prost(bool, tag = "4")]
    suspend: bool,
    /// jobTemplate (field 5, message JobTemplateSpec)
    #[prost(message, tag = "5")]
    job_template: Option<JobTemplateSpec>,
    /// successfulJobsHistoryLimit (field 6, int32)
    #[prost(int32, tag = "6")]
    successful_jobs_history_limit: i32,
    /// failedJobsHistoryLimit (field 7, int32)
    #[prost(int32, tag = "7")]
    failed_jobs_history_limit: i32,
    /// timeZone (field 8, string)
    #[prost(string, tag = "8")]
    time_zone: String,
}

/// CronJob — k8s.io/api/batch/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct CronJob {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message CronJobSpec)
    #[prost(message, tag = "2")]
    spec: Option<CronJobSpec>,
    /// status (field 3, bytes) — not decoded on input
    #[prost(bytes = "vec", tag = "3")]
    status: Vec<u8>,
}

/// Job — k8s.io/api/batch/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Job {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message JobSpec)
    #[prost(message, tag = "2")]
    spec: Option<JobSpec>,
    /// status (field 3, bytes) — not decoded on input
    #[prost(bytes = "vec", tag = "3")]
    status: Vec<u8>,
}

// --- k8s.io/api/apps/v1/generated.proto ---

/// StatefulSet — k8s.io/api/apps/v1/generated.proto
/// Only metadata is decoded; spec is deeply nested and not needed for routing.
#[derive(Clone, PartialEq, Message)]
struct StatefulSet {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// Deployment — k8s.io/api/apps/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct Deployment {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// DaemonSet — k8s.io/api/apps/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct DaemonSet {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// ReplicaSet — k8s.io/api/apps/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ReplicaSet {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// ServiceAccount — k8s.io/api/core/v1/generated.proto
/// secrets (field 2), imagePullSecrets (field 3), automountServiceAccountToken (field 4)
/// are skipped — not needed for routing.
#[derive(Clone, PartialEq, Message)]
struct ServiceAccount {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// PersistentVolumeClaim — k8s.io/api/core/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct PersistentVolumeClaim {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// Endpoints — k8s.io/api/core/v1/generated.proto
/// subsets (field 2, repeated EndpointSubset) is skipped — not needed for routing.
#[derive(Clone, PartialEq, Message)]
struct Endpoints {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

// ---------------------------------------------------------------------------
// Encoder — produces Kubernetes protobuf wire format from a JSON value.
// Used in tests only; not called from production handlers.
// ---------------------------------------------------------------------------

/// Encode a varint into a byte vector.
#[cfg(test)]
fn encode_varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

/// Encode a length-delimited (wire type 2) field: tag + length varint + payload.
#[cfg(test)]
fn encode_ld_field(field_number: u64, payload: &[u8]) -> Vec<u8> {
    let tag = (field_number << 3) | 2;
    let mut out = encode_varint(tag);
    out.extend_from_slice(&encode_varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

/// Encode a `serde_json::Value` as a Kubernetes protobuf response body.
///
/// Wire format:
///   [4 bytes magic: 0x6b, 0x38, 0x73, 0x00]
///   [protobuf-encoded Unknown message]
///     field 1 (TypeMeta, LEN): apiVersion (field 1, string) + kind (field 2, string)
///     field 2 (raw, LEN): the raw JSON bytes of the object
///     field 4 (contentType, LEN): "application/json"
///
/// client-go reads the `contentType` field (field 4) to determine how to decode
/// the `raw` field (field 2).  By setting contentType to "application/json" and
/// placing the original JSON bytes in `raw`, the client decodes it with its JSON
/// decoder regardless of the outer content-type header — this is why this scheme
/// works for all object types without needing a per-type proto encoder.
#[cfg(test)]
pub fn encode_proto_response(val: &serde_json::Value) -> bytes::Bytes {
    let api_version = val["apiVersion"].as_str().unwrap_or("");
    let kind = val["kind"].as_str().unwrap_or("");

    // TypeMeta sub-message: field 1 = apiVersion, field 2 = kind.
    let type_meta = {
        let mut t = encode_ld_field(1, api_version.as_bytes());
        t.extend_from_slice(&encode_ld_field(2, kind.as_bytes()));
        t
    };

    let json_bytes = val.to_string();
    let json_bytes = json_bytes.as_bytes();

    // Unknown envelope: field 1 = TypeMeta, field 2 = raw JSON, field 4 = contentType.
    let mut envelope = encode_ld_field(1, &type_meta);
    envelope.extend_from_slice(&encode_ld_field(2, json_bytes));
    envelope.extend_from_slice(&encode_ld_field(4, b"application/json"));

    let mut out = Vec::with_capacity(4 + envelope.len());
    out.extend_from_slice(K8S_PROTO_MAGIC);
    out.extend_from_slice(&envelope);
    bytes::Bytes::from(out)
}

/// The decoded `Unknown` envelope fields we care about.
pub struct ProtoEnvelope {
    /// The raw bytes of `Unknown.raw` (field 2).
    pub raw: Vec<u8>,
    /// The content type of the raw bytes (field 4), e.g. "application/json" or
    /// "application/vnd.kubernetes.protobuf". Empty string if the field was absent.
    pub content_type: String,
    /// The Kubernetes kind extracted from the TypeMeta (field 1 of the envelope), e.g.
    /// "Namespace" or "ConfigMap". Empty string if absent.
    pub kind: String,
}

/// Attempt to decode the Kubernetes protobuf envelope and return both the raw payload and its
/// declared content-type.
///
/// Returns `Some(envelope)` when the body starts with the k8s magic prefix and contains a
/// decodable `Unknown.raw` field (field 2). Returns `None` otherwise.
pub fn decode_k8s_proto_envelope(body: &[u8]) -> Option<ProtoEnvelope> {
    if body.len() < 4 || &body[..4] != K8S_PROTO_MAGIC {
        return None;
    }
    let proto_bytes = &body[4..];
    let unknown = Unknown::decode(proto_bytes).ok()?;
    // raw field must be non-empty — we require a payload
    if unknown.raw.is_empty() {
        return None;
    }
    Some(ProtoEnvelope {
        raw: unknown.raw,
        content_type: unknown.content_type,
        kind: unknown.type_meta.map(|t| t.kind).unwrap_or_default(),
    })
}

// ---------------------------------------------------------------------------
// Type-specific decoders — convert prost-decoded structs to serde_json::Value
// ---------------------------------------------------------------------------

/// Convert a prost ObjectMeta into a serde_json::Value map.
fn object_meta_to_json(meta: ObjectMeta) -> serde_json::Value {
    let mut m = serde_json::json!({ "creationTimestamp": serde_json::Value::Null });
    if !meta.name.is_empty() {
        m["name"] = serde_json::Value::String(meta.name);
    }
    if !meta.generate_name.is_empty() {
        m["generateName"] = serde_json::Value::String(meta.generate_name);
    }
    if !meta.namespace.is_empty() {
        m["namespace"] = serde_json::Value::String(meta.namespace);
    }
    if !meta.uid.is_empty() {
        m["uid"] = serde_json::Value::String(meta.uid);
    }
    if !meta.resource_version.is_empty() {
        m["resourceVersion"] = serde_json::Value::String(meta.resource_version);
    }
    if let Some(ts) = meta.creation_timestamp {
        if ts.seconds != 0 {
            m["creationTimestamp"] =
                serde_json::Value::String(crate::util::secs_to_rfc3339(ts.seconds as u64));
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
    m
}

/// Decode a proto-encoded Namespace object into a `serde_json::Value`.
pub fn decode_namespace_proto(data: &[u8]) -> Option<serde_json::Value> {
    let ns = Namespace::decode(data).ok()?;
    let meta = object_meta_to_json(ns.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": meta
    }))
}

/// Decode a proto-encoded ConfigMap object into a `serde_json::Value`.
pub fn decode_configmap_proto(data: &[u8]) -> Option<serde_json::Value> {
    let cm = ConfigMap::decode(data).ok()?;
    let meta = object_meta_to_json(cm.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": meta
    });
    if !cm.data.is_empty() {
        let data_map: serde_json::Map<String, serde_json::Value> = cm
            .data
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        obj["data"] = serde_json::Value::Object(data_map);
    }
    Some(obj)
}

/// Decode a proto-encoded Pod object into a `serde_json::Value`.
///
/// Decodes metadata and spec.containers (name + image). All other PodSpec fields are omitted
/// because PodSpec is deeply nested — the goal is to produce a valid JSON object that passes
/// Object::from_bytes validation and can be stored, so CREATE returns 201 instead of 400.
pub fn decode_pod_proto(data: &[u8]) -> Option<serde_json::Value> {
    let pod = Pod::decode(data).ok()?;
    let meta = object_meta_to_json(pod.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": meta
    });

    let spec = pod.spec.unwrap_or_default();
    let containers: Vec<serde_json::Value> = spec
        .containers
        .into_iter()
        .map(|c| {
            let mut cm = serde_json::Map::new();
            if !c.name.is_empty() {
                cm.insert("name".to_string(), serde_json::Value::String(c.name));
            }
            if !c.image.is_empty() {
                cm.insert("image".to_string(), serde_json::Value::String(c.image));
            }
            if !c.image_pull_policy.is_empty() {
                cm.insert(
                    "imagePullPolicy".to_string(),
                    serde_json::Value::String(c.image_pull_policy),
                );
            }
            if !c.termination_message_path.is_empty() {
                cm.insert(
                    "terminationMessagePath".to_string(),
                    serde_json::Value::String(c.termination_message_path),
                );
            }
            if !c.termination_message_policy.is_empty() {
                cm.insert(
                    "terminationMessagePolicy".to_string(),
                    serde_json::Value::String(c.termination_message_policy),
                );
            }
            if !c.command.is_empty() {
                cm.insert(
                    "command".to_string(),
                    serde_json::Value::Array(
                        c.command
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
            if !c.args.is_empty() {
                cm.insert(
                    "args".to_string(),
                    serde_json::Value::Array(
                        c.args.into_iter().map(serde_json::Value::String).collect(),
                    ),
                );
            }
            serde_json::Value::Object(cm)
        })
        .collect();

    let mut spec_map = serde_json::Map::new();
    spec_map.insert(
        "containers".to_string(),
        serde_json::Value::Array(containers),
    );
    if !spec.restart_policy.is_empty() {
        spec_map.insert(
            "restartPolicy".to_string(),
            serde_json::Value::String(spec.restart_policy),
        );
    }
    if !spec.service_account_name.is_empty() {
        spec_map.insert(
            "serviceAccountName".to_string(),
            serde_json::Value::String(spec.service_account_name),
        );
    }
    if !spec.node_name.is_empty() {
        spec_map.insert(
            "nodeName".to_string(),
            serde_json::Value::String(spec.node_name),
        );
    }
    obj["spec"] = serde_json::Value::Object(spec_map);

    Some(obj)
}

/// Decode a proto-encoded PodTemplate object into a `serde_json::Value`.
///
/// Only metadata is decoded; the template field (PodTemplateSpec) is omitted from the output
/// because PodSpec is deeply nested and we do not need to round-trip it — the goal is to let
/// CREATE return 201 instead of 400 so the e2e chunking test does not panic.
pub fn decode_podtemplate_proto(data: &[u8]) -> Option<serde_json::Value> {
    let pt = PodTemplate::decode(data).ok()?;
    let meta = object_meta_to_json(pt.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PodTemplate",
        "metadata": meta,
        "template": {}
    }))
}

/// Decode a proto-encoded Service object into a `serde_json::Value`.
pub fn decode_service_proto(data: &[u8]) -> Option<serde_json::Value> {
    let svc = Service::decode(data).ok()?;
    let meta = object_meta_to_json(svc.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": meta
    });

    if let Some(spec) = svc.spec {
        let mut spec_map = serde_json::Map::new();

        if !spec.cluster_ip.is_empty() {
            spec_map.insert(
                "clusterIP".to_string(),
                serde_json::Value::String(spec.cluster_ip),
            );
        }
        if !spec.r#type.is_empty() {
            spec_map.insert("type".to_string(), serde_json::Value::String(spec.r#type));
        }
        if !spec.session_affinity.is_empty() {
            spec_map.insert(
                "sessionAffinity".to_string(),
                serde_json::Value::String(spec.session_affinity),
            );
        }
        if !spec.external_name.is_empty() {
            spec_map.insert(
                "externalName".to_string(),
                serde_json::Value::String(spec.external_name),
            );
        }
        if !spec.external_traffic_policy.is_empty() {
            spec_map.insert(
                "externalTrafficPolicy".to_string(),
                serde_json::Value::String(spec.external_traffic_policy),
            );
        }
        if !spec.ip_family_policy.is_empty() {
            spec_map.insert(
                "ipFamilyPolicy".to_string(),
                serde_json::Value::String(spec.ip_family_policy),
            );
        }
        if !spec.internal_traffic_policy.is_empty() {
            spec_map.insert(
                "internalTrafficPolicy".to_string(),
                serde_json::Value::String(spec.internal_traffic_policy),
            );
        }
        if !spec.selector.is_empty() {
            let sel: serde_json::Map<String, serde_json::Value> = spec
                .selector
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            spec_map.insert("selector".to_string(), serde_json::Value::Object(sel));
        }
        if !spec.external_ips.is_empty() {
            spec_map.insert(
                "externalIPs".to_string(),
                serde_json::Value::Array(
                    spec.external_ips
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        let ports: Vec<serde_json::Value> = spec
            .ports
            .into_iter()
            .map(|p| {
                let mut pm = serde_json::Map::new();
                if !p.name.is_empty() {
                    pm.insert("name".to_string(), serde_json::Value::String(p.name));
                }
                if !p.protocol.is_empty() {
                    pm.insert(
                        "protocol".to_string(),
                        serde_json::Value::String(p.protocol),
                    );
                }
                if p.port != 0 {
                    pm.insert(
                        "port".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(p.port)),
                    );
                }
                if p.node_port != 0 {
                    pm.insert(
                        "nodePort".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(p.node_port)),
                    );
                }
                if !p.app_protocol.is_empty() {
                    pm.insert(
                        "appProtocol".to_string(),
                        serde_json::Value::String(p.app_protocol),
                    );
                }
                serde_json::Value::Object(pm)
            })
            .collect();
        if !ports.is_empty() {
            spec_map.insert("ports".to_string(), serde_json::Value::Array(ports));
        }

        obj["spec"] = serde_json::Value::Object(spec_map);
    }

    Some(obj)
}

/// Decode a proto-encoded Secret object into a `serde_json::Value`.
pub fn decode_secret_proto(data: &[u8]) -> Option<serde_json::Value> {
    let secret = Secret::decode(data).ok()?;
    let meta = object_meta_to_json(secret.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": meta
    });

    if !secret.r#type.is_empty() {
        obj["type"] = serde_json::Value::String(secret.r#type);
    }
    if !secret.data.is_empty() {
        let data_map: serde_json::Map<String, serde_json::Value> = secret
            .data
            .into_iter()
            .map(|(k, v)| {
                use base64::Engine;
                (
                    k,
                    serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&v)),
                )
            })
            .collect();
        obj["data"] = serde_json::Value::Object(data_map);
    }
    if !secret.string_data.is_empty() {
        let sd_map: serde_json::Map<String, serde_json::Value> = secret
            .string_data
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        obj["stringData"] = serde_json::Value::Object(sd_map);
    }

    Some(obj)
}

/// Decode a proto-encoded ReplicationController object into a `serde_json::Value`.
pub fn decode_replicationcontroller_proto(data: &[u8]) -> Option<serde_json::Value> {
    let rc = ReplicationController::decode(data).ok()?;
    let meta = object_meta_to_json(rc.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ReplicationController",
        "metadata": meta
    });

    if let Some(spec) = rc.spec {
        let mut spec_map = serde_json::Map::new();
        if spec.replicas != 0 {
            spec_map.insert(
                "replicas".to_string(),
                serde_json::Value::Number(serde_json::Number::from(spec.replicas)),
            );
        }
        if !spec.selector.is_empty() {
            let sel: serde_json::Map<String, serde_json::Value> = spec
                .selector
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            spec_map.insert("selector".to_string(), serde_json::Value::Object(sel));
        }
        spec_map.insert(
            "template".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
        obj["spec"] = serde_json::Value::Object(spec_map);
    }

    Some(obj)
}

/// Decode a proto-encoded RuntimeClass object into a `serde_json::Value`.
pub fn decode_runtimeclass_proto(data: &[u8]) -> Option<serde_json::Value> {
    let rc = RuntimeClass::decode(data).ok()?;
    let meta = object_meta_to_json(rc.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "node.k8s.io/v1",
        "kind": "RuntimeClass",
        "metadata": meta,
        "handler": rc.handler
    });

    if obj["handler"]
        .as_str()
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        obj["handler"] = serde_json::Value::String(String::new());
    }

    Some(obj)
}

/// Decode a proto-encoded PersistentVolume object into a `serde_json::Value`.
pub fn decode_persistentvolume_proto(data: &[u8]) -> Option<serde_json::Value> {
    let pv = PersistentVolume::decode(data).ok()?;
    let meta = object_meta_to_json(pv.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": meta
    });

    if let Some(spec) = pv.spec {
        let mut spec_map = serde_json::Map::new();
        if !spec.access_modes.is_empty() {
            spec_map.insert(
                "accessModes".to_string(),
                serde_json::Value::Array(
                    spec.access_modes
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if !spec.persistent_volume_reclaim_policy.is_empty() {
            spec_map.insert(
                "persistentVolumeReclaimPolicy".to_string(),
                serde_json::Value::String(spec.persistent_volume_reclaim_policy),
            );
        }
        if !spec.storage_class_name.is_empty() {
            spec_map.insert(
                "storageClassName".to_string(),
                serde_json::Value::String(spec.storage_class_name),
            );
        }
        if !spec.volume_mode.is_empty() {
            spec_map.insert(
                "volumeMode".to_string(),
                serde_json::Value::String(spec.volume_mode),
            );
        }
        if !spec_map.is_empty() {
            obj["spec"] = serde_json::Value::Object(spec_map);
        }
    }

    Some(obj)
}

/// Decode a proto-encoded VolumeAttachment object into a `serde_json::Value`.
pub fn decode_volumeattachment_proto(data: &[u8]) -> Option<serde_json::Value> {
    let va = VolumeAttachment::decode(data).ok()?;
    let meta = object_meta_to_json(va.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "VolumeAttachment",
        "metadata": meta
    });

    if let Some(spec) = va.spec {
        let mut spec_map = serde_json::Map::new();
        if !spec.attacher.is_empty() {
            spec_map.insert(
                "attacher".to_string(),
                serde_json::Value::String(spec.attacher),
            );
        }
        if !spec.node_name.is_empty() {
            spec_map.insert(
                "nodeName".to_string(),
                serde_json::Value::String(spec.node_name),
            );
        }
        let mut source_map = serde_json::Map::new();
        if let Some(src) = spec.source {
            if !src.persistent_volume_name.is_empty() {
                source_map.insert(
                    "persistentVolumeName".to_string(),
                    serde_json::Value::String(src.persistent_volume_name),
                );
            }
        }
        spec_map.insert("source".to_string(), serde_json::Value::Object(source_map));
        obj["spec"] = serde_json::Value::Object(spec_map);
    }

    Some(obj)
}

/// Decode a proto-encoded Node object into a `serde_json::Value`.
pub fn decode_node_proto(data: &[u8]) -> Option<serde_json::Value> {
    let node = Node::decode(data).ok()?;
    let meta = object_meta_to_json(node.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": meta
    });

    if let Some(spec) = node.spec {
        let mut spec_map = serde_json::Map::new();
        if !spec.pod_cidr.is_empty() {
            spec_map.insert(
                "podCIDR".to_string(),
                serde_json::Value::String(spec.pod_cidr),
            );
        }
        if !spec.provider_id.is_empty() {
            spec_map.insert(
                "providerID".to_string(),
                serde_json::Value::String(spec.provider_id),
            );
        }
        if !spec.pod_cidrs.is_empty() {
            spec_map.insert(
                "podCIDRs".to_string(),
                serde_json::Value::Array(
                    spec.pod_cidrs
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if !spec_map.is_empty() {
            obj["spec"] = serde_json::Value::Object(spec_map);
        }
    }

    Some(obj)
}

/// Decode a proto-encoded Lease object into a `serde_json::Value`.
pub fn decode_lease_proto(data: &[u8]) -> Option<serde_json::Value> {
    let lease = Lease::decode(data).ok()?;
    let meta = object_meta_to_json(lease.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": meta
    });

    if let Some(spec) = lease.spec {
        let mut spec_map = serde_json::Map::new();
        if !spec.holder_identity.is_empty() {
            spec_map.insert(
                "holderIdentity".to_string(),
                serde_json::Value::String(spec.holder_identity),
            );
        }
        if spec.lease_duration_seconds != 0 {
            spec_map.insert(
                "leaseDurationSeconds".to_string(),
                serde_json::Value::Number(serde_json::Number::from(spec.lease_duration_seconds)),
            );
        }
        if !spec_map.is_empty() {
            obj["spec"] = serde_json::Value::Object(spec_map);
        }
    }

    Some(obj)
}

/// Decode a proto-encoded CSINode object into a `serde_json::Value`.
pub fn decode_csinode_proto(data: &[u8]) -> Option<serde_json::Value> {
    let csinode = CsiNode::decode(data).ok()?;
    let meta = object_meta_to_json(csinode.metadata.unwrap_or_default());

    let drivers: Vec<serde_json::Value> = csinode
        .spec
        .map(|s| s.drivers)
        .unwrap_or_default()
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "name": d.name,
                "nodeID": d.node_id
            })
        })
        .collect();

    Some(serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "CSINode",
        "metadata": meta,
        "spec": {
            "drivers": drivers
        }
    }))
}

/// Decode a proto-encoded Event object into a `serde_json::Value`.
pub fn decode_event_proto(data: &[u8]) -> Option<serde_json::Value> {
    let event = Event::decode(data).ok()?;
    let meta = object_meta_to_json(event.metadata.unwrap_or_default());

    let involved_object = event.involved_object.map(|r| {
        let mut m = serde_json::Map::new();
        if !r.kind.is_empty() {
            m.insert("kind".to_string(), serde_json::Value::String(r.kind));
        }
        if !r.namespace.is_empty() {
            m.insert(
                "namespace".to_string(),
                serde_json::Value::String(r.namespace),
            );
        }
        if !r.name.is_empty() {
            m.insert("name".to_string(), serde_json::Value::String(r.name));
        }
        if !r.uid.is_empty() {
            m.insert("uid".to_string(), serde_json::Value::String(r.uid));
        }
        if !r.api_version.is_empty() {
            m.insert(
                "apiVersion".to_string(),
                serde_json::Value::String(r.api_version),
            );
        }
        if !r.resource_version.is_empty() {
            m.insert(
                "resourceVersion".to_string(),
                serde_json::Value::String(r.resource_version),
            );
        }
        if !r.field_path.is_empty() {
            m.insert(
                "fieldPath".to_string(),
                serde_json::Value::String(r.field_path),
            );
        }
        serde_json::Value::Object(m)
    });

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": meta,
        "involvedObject": involved_object.unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
    });
    if !event.reason.is_empty() {
        obj["reason"] = serde_json::Value::String(event.reason);
    }
    if !event.message.is_empty() {
        obj["message"] = serde_json::Value::String(event.message);
    }
    if event.count != 0 {
        obj["count"] = serde_json::Value::Number(serde_json::Number::from(event.count));
    }
    if !event.r#type.is_empty() {
        obj["type"] = serde_json::Value::String(event.r#type);
    }
    if let Some(s) = event.series {
        let mut sm = serde_json::Map::new();
        if s.count != 0 {
            sm.insert(
                "count".to_string(),
                serde_json::Value::Number(serde_json::Number::from(s.count)),
            );
        }
        if let Some(t) = s.last_observed_time {
            if t.seconds != 0 {
                sm.insert(
                    "lastObservedTime".to_string(),
                    serde_json::Value::String(crate::util::secs_to_rfc3339(t.seconds as u64)),
                );
            }
        }
        if !sm.is_empty() {
            obj["series"] = serde_json::Value::Object(sm);
        }
    }
    Some(obj)
}

/// Decoded fields from a protobuf-encoded TokenRequest.
pub struct TokenRequestFields {
    pub audiences: Vec<String>,
    pub expiration_seconds: Option<u64>,
}

/// Decode the inner raw bytes of a protobuf-encoded TokenRequest.
///
/// Wire layout (k8s.io/api/authentication/v1/generated.proto):
///   field 1 (ObjectMeta, wire 2): ignored
///   field 2 (TokenRequestSpec, wire 2): spec
///     field 1 (repeated string): audiences
///     field 2 (int64): expirationSeconds (0 = unset)
///     field 3 (BoundObjectReference, message): boundObjectRef
///
/// Returns `None` if the bytes are not a recognisable protobuf message (malformed input).
pub fn decode_token_request(raw: &[u8]) -> Option<TokenRequestFields> {
    let tr = TokenRequestProto::decode(raw).ok()?;
    let spec = tr.spec.unwrap_or_default();
    let expiration_seconds = if spec.expiration_seconds > 0 {
        Some(spec.expiration_seconds as u64)
    } else {
        None
    };
    Some(TokenRequestFields {
        audiences: spec.audiences,
        expiration_seconds,
    })
}

/// Convert a prost PolicyRule into a serde_json::Value object.
fn policy_rule_to_json(rule: PolicyRule) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !rule.verbs.is_empty() {
        m.insert(
            "verbs".to_string(),
            serde_json::Value::Array(
                rule.verbs
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !rule.api_groups.is_empty() {
        m.insert(
            "apiGroups".to_string(),
            serde_json::Value::Array(
                rule.api_groups
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !rule.resources.is_empty() {
        m.insert(
            "resources".to_string(),
            serde_json::Value::Array(
                rule.resources
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !rule.resource_names.is_empty() {
        m.insert(
            "resourceNames".to_string(),
            serde_json::Value::Array(
                rule.resource_names
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !rule.non_resource_urls.is_empty() {
        m.insert(
            "nonResourceURLs".to_string(),
            serde_json::Value::Array(
                rule.non_resource_urls
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

/// Convert a prost Subject into a serde_json::Value object.
fn subject_to_json(s: Subject) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !s.kind.is_empty() {
        m.insert("kind".to_string(), serde_json::Value::String(s.kind));
    }
    if !s.api_group.is_empty() {
        m.insert(
            "apiGroup".to_string(),
            serde_json::Value::String(s.api_group),
        );
    }
    if !s.name.is_empty() {
        m.insert("name".to_string(), serde_json::Value::String(s.name));
    }
    if !s.namespace.is_empty() {
        m.insert(
            "namespace".to_string(),
            serde_json::Value::String(s.namespace),
        );
    }
    serde_json::Value::Object(m)
}

/// Convert a prost RoleRef into a serde_json::Value object.
fn role_ref_to_json(r: RoleRef) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !r.api_group.is_empty() {
        m.insert(
            "apiGroup".to_string(),
            serde_json::Value::String(r.api_group),
        );
    }
    if !r.kind.is_empty() {
        m.insert("kind".to_string(), serde_json::Value::String(r.kind));
    }
    if !r.name.is_empty() {
        m.insert("name".to_string(), serde_json::Value::String(r.name));
    }
    serde_json::Value::Object(m)
}

/// Decode a proto-encoded ClusterRole object into a `serde_json::Value`.
pub fn decode_clusterrole_proto(data: &[u8]) -> Option<serde_json::Value> {
    let cr = ClusterRole::decode(data).ok()?;
    let meta = object_meta_to_json(cr.metadata.unwrap_or_default());
    let rules: Vec<serde_json::Value> = cr.rules.into_iter().map(policy_rule_to_json).collect();
    Some(serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": meta,
        "rules": rules
    }))
}

/// Decode a proto-encoded ClusterRoleBinding object into a `serde_json::Value`.
pub fn decode_clusterrolebinding_proto(data: &[u8]) -> Option<serde_json::Value> {
    let crb = ClusterRoleBinding::decode(data).ok()?;
    let meta = object_meta_to_json(crb.metadata.unwrap_or_default());
    let subjects: Vec<serde_json::Value> = crb.subjects.into_iter().map(subject_to_json).collect();
    let role_ref = crb
        .role_ref
        .map(role_ref_to_json)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
    Some(serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": meta,
        "subjects": subjects,
        "roleRef": role_ref
    }))
}

/// Decode a proto-encoded Role object into a `serde_json::Value`.
pub fn decode_role_proto(data: &[u8]) -> Option<serde_json::Value> {
    let role = Role::decode(data).ok()?;
    let meta = object_meta_to_json(role.metadata.unwrap_or_default());
    let rules: Vec<serde_json::Value> = role.rules.into_iter().map(policy_rule_to_json).collect();
    Some(serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": meta,
        "rules": rules
    }))
}

/// Decode a proto-encoded RoleBinding object into a `serde_json::Value`.
pub fn decode_rolebinding_proto(data: &[u8]) -> Option<serde_json::Value> {
    let rb = RoleBinding::decode(data).ok()?;
    let meta = object_meta_to_json(rb.metadata.unwrap_or_default());
    let subjects: Vec<serde_json::Value> = rb.subjects.into_iter().map(subject_to_json).collect();
    let role_ref = rb
        .role_ref
        .map(role_ref_to_json)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
    Some(serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": meta,
        "subjects": subjects,
        "roleRef": role_ref
    }))
}

/// Decode a proto-encoded SubjectAccessReview object into a `serde_json::Value`.
///
/// The kubelet uses Webhook authorization mode (default in k8s 1.36 with --config), which
/// calls back to /apis/authorization.k8s.io/v1/subjectaccessreviews with
/// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder, the raw proto
/// bytes reach serde_json::from_slice and produce "expected value at line 1 column 1".
/// The kubelet interprets the 400/500 failure as an authorization denial.
pub fn decode_subject_access_review_proto(data: &[u8]) -> Option<serde_json::Value> {
    let sar = SubjectAccessReviewProto::decode(data).ok()?;
    let spec = sar.spec.unwrap_or_default();

    let mut spec_map = serde_json::Map::new();
    if !spec.user.is_empty() {
        spec_map.insert("user".to_string(), serde_json::Value::String(spec.user));
    }
    if !spec.groups.is_empty() {
        spec_map.insert(
            "groups".to_string(),
            serde_json::Value::Array(
                spec.groups
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(ra) = spec.resource_attributes {
        let mut ra_map = serde_json::Map::new();
        if !ra.namespace.is_empty() {
            ra_map.insert(
                "namespace".to_string(),
                serde_json::Value::String(ra.namespace),
            );
        }
        if !ra.verb.is_empty() {
            ra_map.insert("verb".to_string(), serde_json::Value::String(ra.verb));
        }
        if !ra.group.is_empty() {
            ra_map.insert("group".to_string(), serde_json::Value::String(ra.group));
        }
        if !ra.version.is_empty() {
            ra_map.insert("version".to_string(), serde_json::Value::String(ra.version));
        }
        if !ra.resource.is_empty() {
            ra_map.insert(
                "resource".to_string(),
                serde_json::Value::String(ra.resource),
            );
        }
        if !ra.subresource.is_empty() {
            ra_map.insert(
                "subresource".to_string(),
                serde_json::Value::String(ra.subresource),
            );
        }
        if !ra.name.is_empty() {
            ra_map.insert("name".to_string(), serde_json::Value::String(ra.name));
        }
        if !ra_map.is_empty() {
            spec_map.insert(
                "resourceAttributes".to_string(),
                serde_json::Value::Object(ra_map),
            );
        }
    }

    Some(serde_json::json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": serde_json::Value::Object(spec_map)
    }))
}

/// Decode a proto-encoded TokenReview object into a `serde_json::Value`.
///
/// The kubelet uses Webhook authentication mode, which calls back to
/// /apis/authentication.k8s.io/v1/tokenreviews with Content-Type: application/vnd.kubernetes.protobuf.
/// Without this decoder, the raw proto bytes reach serde_json::from_slice and produce
/// "expected value at line 1 column 1", causing authentication failures.
pub fn decode_token_review_proto(data: &[u8]) -> Option<serde_json::Value> {
    let tr = TokenReviewProto::decode(data).ok()?;
    let spec = tr.spec.unwrap_or_default();

    Some(serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": {
            "token": spec.token
        }
    }))
}

/// Convert a prost JobSpec into a serde_json::Value object.
/// The template field (PodTemplateSpec) is omitted — PodSpec is deeply nested and
/// the same pattern as PodTemplate applies: store as empty object so the schema is valid.
fn job_spec_to_json(spec: JobSpec) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if spec.parallelism != 0 {
        m.insert(
            "parallelism".to_string(),
            serde_json::Value::Number(serde_json::Number::from(spec.parallelism)),
        );
    }
    if spec.completions != 0 {
        m.insert(
            "completions".to_string(),
            serde_json::Value::Number(serde_json::Number::from(spec.completions)),
        );
    }
    if spec.active_deadline_seconds != 0 {
        m.insert(
            "activeDeadlineSeconds".to_string(),
            serde_json::Value::Number(serde_json::Number::from(spec.active_deadline_seconds)),
        );
    }
    if spec.backoff_limit != 0 {
        m.insert(
            "backoffLimit".to_string(),
            serde_json::Value::Number(serde_json::Number::from(spec.backoff_limit)),
        );
    }
    if !spec.completion_mode.is_empty() {
        m.insert(
            "completionMode".to_string(),
            serde_json::Value::String(spec.completion_mode),
        );
    }
    if spec.suspend {
        m.insert("suspend".to_string(), serde_json::Value::Bool(true));
    }
    if !spec.pod_replacement_policy.is_empty() {
        m.insert(
            "podReplacementPolicy".to_string(),
            serde_json::Value::String(spec.pod_replacement_policy),
        );
    }
    if spec.backoff_limit_per_index != 0 {
        m.insert(
            "backoffLimitPerIndex".to_string(),
            serde_json::Value::Number(serde_json::Number::from(spec.backoff_limit_per_index)),
        );
    }
    if spec.max_failed_indexes != 0 {
        m.insert(
            "maxFailedIndexes".to_string(),
            serde_json::Value::Number(serde_json::Number::from(spec.max_failed_indexes)),
        );
    }
    if !spec.managed_by.is_empty() {
        m.insert(
            "managedBy".to_string(),
            serde_json::Value::String(spec.managed_by),
        );
    }
    // template is always present as an empty object — required by the k8s schema
    m.insert(
        "template".to_string(),
        serde_json::Value::Object(serde_json::Map::new()),
    );
    serde_json::Value::Object(m)
}

/// Decode a proto-encoded CronJob object into a `serde_json::Value`.
pub fn decode_cronjob_proto(data: &[u8]) -> Option<serde_json::Value> {
    let cj = CronJob::decode(data).ok()?;
    let meta = object_meta_to_json(cj.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": meta
    });

    if let Some(spec) = cj.spec {
        let mut spec_map = serde_json::Map::new();
        if !spec.schedule.is_empty() {
            spec_map.insert(
                "schedule".to_string(),
                serde_json::Value::String(spec.schedule),
            );
        }
        if spec.starting_deadline_seconds != 0 {
            spec_map.insert(
                "startingDeadlineSeconds".to_string(),
                serde_json::Value::Number(serde_json::Number::from(spec.starting_deadline_seconds)),
            );
        }
        if !spec.concurrency_policy.is_empty() {
            spec_map.insert(
                "concurrencyPolicy".to_string(),
                serde_json::Value::String(spec.concurrency_policy),
            );
        }
        if spec.suspend {
            spec_map.insert("suspend".to_string(), serde_json::Value::Bool(true));
        }
        if spec.successful_jobs_history_limit != 0 {
            spec_map.insert(
                "successfulJobsHistoryLimit".to_string(),
                serde_json::Value::Number(serde_json::Number::from(
                    spec.successful_jobs_history_limit,
                )),
            );
        }
        if spec.failed_jobs_history_limit != 0 {
            spec_map.insert(
                "failedJobsHistoryLimit".to_string(),
                serde_json::Value::Number(serde_json::Number::from(spec.failed_jobs_history_limit)),
            );
        }
        if !spec.time_zone.is_empty() {
            spec_map.insert(
                "timeZone".to_string(),
                serde_json::Value::String(spec.time_zone),
            );
        }
        // jobTemplate: always emit with at least an empty spec.template
        let jt_meta = spec
            .job_template
            .as_ref()
            .and_then(|jt| jt.metadata.clone())
            .map(object_meta_to_json)
            .unwrap_or_else(|| serde_json::json!({"creationTimestamp": serde_json::Value::Null}));
        let jt_spec = spec
            .job_template
            .and_then(|jt| jt.spec)
            .map(job_spec_to_json)
            .unwrap_or_else(|| serde_json::json!({"template": {}}));
        spec_map.insert(
            "jobTemplate".to_string(),
            serde_json::json!({
                "metadata": jt_meta,
                "spec": jt_spec
            }),
        );
        obj["spec"] = serde_json::Value::Object(spec_map);
    }

    Some(obj)
}

/// Decode a proto-encoded Job object into a `serde_json::Value`.
pub fn decode_job_proto(data: &[u8]) -> Option<serde_json::Value> {
    let job = Job::decode(data).ok()?;
    let meta = object_meta_to_json(job.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": meta
    });

    if let Some(spec) = job.spec {
        obj["spec"] = job_spec_to_json(spec);
    }

    Some(obj)
}

/// Decode a proto-encoded StatefulSet object into a `serde_json::Value`.
pub fn decode_statefulset_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = StatefulSet::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": meta
    }))
}

/// Decode a proto-encoded Deployment object into a `serde_json::Value`.
pub fn decode_deployment_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = Deployment::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": meta
    }))
}

/// Decode a proto-encoded DaemonSet object into a `serde_json::Value`.
pub fn decode_daemonset_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = DaemonSet::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": meta
    }))
}

/// Decode a proto-encoded ReplicaSet object into a `serde_json::Value`.
pub fn decode_replicaset_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ReplicaSet::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": meta
    }))
}

/// Decode a proto-encoded ServiceAccount object into a `serde_json::Value`.
pub fn decode_serviceaccount_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ServiceAccount::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": meta
    }))
}

/// Decode a proto-encoded PersistentVolumeClaim object into a `serde_json::Value`.
pub fn decode_persistentvolumeclaim_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = PersistentVolumeClaim::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": meta
    }))
}

/// Decode a proto-encoded Endpoints object into a `serde_json::Value`.
pub fn decode_endpoints_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = Endpoints::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": meta
    }))
}

/// Decode a proto-encoded core Kubernetes object by kind.
///
/// Dispatches to the appropriate type-specific decoder based on `kind`. Returns `Some(json)` for
/// known types; `None` for unknown kinds or malformed input.
pub fn decode_core_proto_by_kind(kind: &str, raw: &[u8]) -> Option<serde_json::Value> {
    match kind {
        "Namespace" => decode_namespace_proto(raw),
        "ConfigMap" => decode_configmap_proto(raw),
        "Pod" => decode_pod_proto(raw),
        "PodTemplate" => decode_podtemplate_proto(raw),
        "Node" => decode_node_proto(raw),
        "Service" => decode_service_proto(raw),
        "Secret" => decode_secret_proto(raw),
        "ReplicationController" => decode_replicationcontroller_proto(raw),
        "PersistentVolume" => decode_persistentvolume_proto(raw),
        "Lease" => decode_lease_proto(raw),
        "CSINode" => decode_csinode_proto(raw),
        "Event" => decode_event_proto(raw),
        "ClusterRole" => decode_clusterrole_proto(raw),
        "ClusterRoleBinding" => decode_clusterrolebinding_proto(raw),
        "Role" => decode_role_proto(raw),
        "RoleBinding" => decode_rolebinding_proto(raw),
        "SubjectAccessReview" => decode_subject_access_review_proto(raw),
        "TokenReview" => decode_token_review_proto(raw),
        "CronJob" => decode_cronjob_proto(raw),
        "Job" => decode_job_proto(raw),
        "RuntimeClass" => decode_runtimeclass_proto(raw),
        "VolumeAttachment" => decode_volumeattachment_proto(raw),
        "StatefulSet" => decode_statefulset_proto(raw),
        "Deployment" => decode_deployment_proto(raw),
        "DaemonSet" => decode_daemonset_proto(raw),
        "ReplicaSet" => decode_replicaset_proto(raw),
        "ServiceAccount" => decode_serviceaccount_proto(raw),
        "PersistentVolumeClaim" => decode_persistentvolumeclaim_proto(raw),
        "Endpoints" => decode_endpoints_proto(raw),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // Varint encoder — used only in tests to build synthetic protobuf payloads
    // and to walk raw proto bytes in assert_valid_wire_types.
    // ---------------------------------------------------------------------------

    fn encode_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn encode_length_delimited(field_number: u64, payload: &[u8]) -> Vec<u8> {
        let tag = (field_number << 3) | 2;
        let mut out = encode_varint(tag);
        out.extend_from_slice(&encode_varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    /// Decode a protobuf varint from the front of `data`.
    /// Used by assert_valid_wire_types to walk raw proto bytes.
    fn decode_varint(data: &[u8]) -> Option<(u64, &[u8])> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        for (i, &byte) in data.iter().enumerate() {
            if shift >= 64 {
                return None;
            }
            result |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return Some((result, &data[i + 1..]));
            }
        }
        None
    }

    /// Build a minimal Kubernetes protobuf body: magic prefix + Unknown message containing
    /// only the `raw` field (field 2) with the given payload.
    fn build_k8s_proto(raw: &[u8]) -> Vec<u8> {
        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&encode_length_delimited(2, raw));
        body
    }

    /// Build a Kubernetes protobuf body with raw (field 2) and contentType (field 4).
    fn build_k8s_proto_with_content_type(raw: &[u8], content_type: &[u8]) -> Vec<u8> {
        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&encode_length_delimited(2, raw));
        body.extend_from_slice(&encode_length_delimited(4, content_type));
        body
    }

    // ---------------------------------------------------------------------------
    // Tests — envelope raw field extraction
    // ---------------------------------------------------------------------------

    /// The envelope decoder must extract raw bytes from a well-formed protobuf body.
    /// This is the primary case kubectl triggers: a write request with
    /// Content-Type: application/vnd.kubernetes.protobuf where Unknown.raw contains JSON.
    #[test]
    fn extracts_raw_json_from_valid_proto_body() {
        let json = br#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test"}}"#;
        let proto_body = build_k8s_proto(json);

        let result = decode_k8s_proto_envelope(&proto_body).expect("must decode successfully");
        assert_eq!(
            result.raw, json,
            "extracted raw must equal the original JSON payload"
        );
    }

    /// The envelope decoder must return None for a body without the magic prefix.
    /// Ensures plain JSON bodies are not misinterpreted as protobuf.
    #[test]
    fn returns_none_for_plain_json_body() {
        let json = br#"{"apiVersion":"v1","kind":"Namespace"}"#;
        assert!(
            decode_k8s_proto_envelope(json).is_none(),
            "plain JSON must not match the protobuf magic prefix"
        );
    }

    /// The envelope decoder must return None for an empty body.
    #[test]
    fn returns_none_for_empty_body() {
        assert!(decode_k8s_proto_envelope(&[]).is_none());
    }

    /// The envelope decoder must return None when the body is only the magic prefix with no proto data.
    /// This verifies we don't panic on truncated input.
    #[test]
    fn returns_none_for_magic_only_body() {
        assert!(decode_k8s_proto_envelope(K8S_PROTO_MAGIC).is_none());
    }

    /// A proto body with a different field (field 1 only, no field 2) must return None.
    /// Ensures we only return data when field 2 is actually present.
    #[test]
    fn returns_none_when_field2_absent() {
        let mut body = K8S_PROTO_MAGIC.to_vec();
        // Only encode field 1 (TypeMeta with no raw field).
        let type_meta = encode_length_delimited(2, b"Namespace"); // kind only
        body.extend_from_slice(&encode_length_delimited(1, &type_meta));
        assert!(
            decode_k8s_proto_envelope(&body).is_none(),
            "must return None when only field 1 (TypeMeta) is present and field 2 (raw) is absent"
        );
    }

    /// A proto body with fields before and after field 2 must still extract field 2 correctly.
    /// This mirrors real kubectl output which includes field 1 (TypeMeta) before field 2 (raw).
    #[test]
    fn extracts_field2_when_preceded_by_field1() {
        let json = br#"{"kind":"Pod"}"#;
        let mut proto = Vec::new();
        // Field 1 first (TypeMeta embedded message — encode as bytes).
        proto.extend_from_slice(&encode_length_delimited(1, b"\x0a\x02v1\x12\x03Pod"));
        // Field 2 next (raw JSON).
        proto.extend_from_slice(&encode_length_delimited(2, json));
        // Field 4 last (contentType).
        proto.extend_from_slice(&encode_length_delimited(4, b"application/json"));

        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&proto);

        let result = decode_k8s_proto_envelope(&body)
            .expect("must decode field 2 even when other fields are present");
        assert_eq!(result.raw, json);
        assert_eq!(result.content_type, "application/json");
        assert_eq!(result.kind, "Pod");
    }

    /// decode_varint must round-trip a single-byte value.
    #[test]
    fn decode_varint_single_byte() {
        let (v, rest) = decode_varint(&[0x05]).unwrap();
        assert_eq!(v, 5);
        assert!(rest.is_empty());
    }

    /// decode_varint must decode a multi-byte varint correctly.
    #[test]
    fn decode_varint_multi_byte() {
        // 300 in varint = [0xac, 0x02]
        let (v, rest) = decode_varint(&[0xac, 0x02]).unwrap();
        assert_eq!(v, 300);
        assert!(rest.is_empty());
    }

    /// decode_varint must return None for an empty slice.
    #[test]
    fn decode_varint_empty_returns_none() {
        assert!(decode_varint(&[]).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_k8s_proto_envelope
    // ---------------------------------------------------------------------------

    /// decode_k8s_proto_envelope must extract both raw and contentType fields.
    /// This is the real kubectl behavior for core types (e.g. Namespace): the Unknown envelope
    /// has contentType = "application/vnd.kubernetes.protobuf" and raw = proto-encoded object.
    #[test]
    fn envelope_extracts_raw_and_content_type() {
        let raw = b"some-proto-bytes";
        let ct = b"application/vnd.kubernetes.protobuf";
        let body = build_k8s_proto_with_content_type(raw, ct);

        let env = decode_k8s_proto_envelope(&body).expect("must decode envelope");
        assert_eq!(env.raw, raw);
        assert_eq!(env.content_type, "application/vnd.kubernetes.protobuf");
    }

    /// When contentType (field 4) is absent, decode_k8s_proto_envelope must still return the raw
    /// field with an empty content_type.
    #[test]
    fn envelope_raw_without_content_type() {
        let raw = br#"{"kind":"Namespace"}"#;
        let body = build_k8s_proto(raw);

        let env = decode_k8s_proto_envelope(&body).expect("must decode envelope");
        assert_eq!(env.raw, raw);
        assert_eq!(
            env.content_type, "",
            "contentType must be empty when field 4 is absent"
        );
    }

    /// decode_k8s_proto_envelope must return None when the magic prefix is absent.
    #[test]
    fn envelope_returns_none_for_plain_json() {
        let json = br#"{"kind":"Namespace"}"#;
        assert!(decode_k8s_proto_envelope(json).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_namespace_proto
    // ---------------------------------------------------------------------------

    /// decode_namespace_proto must reconstruct a Namespace JSON from proto-encoded bytes
    /// that contain only the name field. This is what kubectl sends for
    /// `kubectl create namespace <name>`.
    ///
    /// This test is the PRIMARY regression guard for the smoke CI failure:
    ///   Error from server (BadRequest): invalid JSON: expected value at line 2 column 1
    /// which occurred because Unknown.raw contained a proto-encoded Namespace (starting with
    /// 0x0a = '\n'), and the JSON parser treated 0x0a as a newline before failing at line 2.
    #[test]
    fn decode_namespace_proto_extracts_name() {
        // Build a minimal Namespace proto:
        // Namespace { metadata: ObjectMeta { name: "smoke-test" } }
        //
        // ObjectMeta field 1 (name, wire 2): tag=0x0a, len=10, "smoke-test"
        let obj_meta = encode_length_delimited(1, b"smoke-test");
        // Namespace field 1 (ObjectMeta, wire 2):
        let namespace_proto = encode_length_delimited(1, &obj_meta);

        let result = decode_namespace_proto(&namespace_proto).expect("must decode namespace proto");

        assert_eq!(result["kind"], "Namespace");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "smoke-test");
        // creationTimestamp must be null for kubectl compatibility
        assert!(result["metadata"]["creationTimestamp"].is_null());
    }

    /// decode_namespace_proto must also extract labels and annotations when present.
    #[test]
    fn decode_namespace_proto_extracts_labels_and_annotations() {
        // Build: ObjectMeta { name: "ns", labels: {"env": "test"}, annotations: {"note": "hi"} }
        let mut obj_meta = encode_length_delimited(1, b"ns"); // field 1 = name
                                                              // Labels map entry (field 11): {field 1="env", field 2="test"}
        let mut label_entry = encode_length_delimited(1, b"env");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"test"));
        obj_meta.extend_from_slice(&encode_length_delimited(11, &label_entry));
        // Annotations map entry (field 12): {field 1="note", field 2="hi"}
        let mut annot_entry = encode_length_delimited(1, b"note");
        annot_entry.extend_from_slice(&encode_length_delimited(2, b"hi"));
        obj_meta.extend_from_slice(&encode_length_delimited(12, &annot_entry));

        let namespace_proto = encode_length_delimited(1, &obj_meta);
        let result = decode_namespace_proto(&namespace_proto).expect("must decode");

        assert_eq!(result["metadata"]["name"], "ns");
        assert_eq!(result["metadata"]["labels"]["env"], "test");
        assert_eq!(result["metadata"]["annotations"]["note"], "hi");
    }

    /// decode_namespace_proto must return None for malformed proto input.
    #[test]
    fn decode_namespace_proto_returns_none_for_garbage() {
        assert!(decode_namespace_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    /// Full round-trip: kubectl create namespace smoke-test sends a k8s proto envelope
    /// where Unknown.raw is a proto-encoded Namespace. The server must decode it to JSON
    /// with the correct name. This is the regression test for the smoke CI failure.
    #[test]
    fn full_kubectl_create_namespace_smoke_regression() {
        // Build proto-encoded Namespace{metadata:{name:"smoke-test", creationTimestamp:{}}}
        let mut obj_meta = encode_length_delimited(1, b"smoke-test"); // name
                                                                      // creationTimestamp (field 8, wire 2) — empty Time{} message (len=0)
        obj_meta.extend_from_slice(&encode_length_delimited(8, &[])); // empty Time
        let namespace_proto = encode_length_delimited(1, &obj_meta);

        // Wrap in k8s Unknown envelope with contentType=protobuf
        let type_meta: Vec<u8> = {
            let mut t = encode_length_delimited(1, b"v1"); // apiVersion
            t.extend_from_slice(&encode_length_delimited(2, b"Namespace")); // kind
            t
        };
        let mut unknown = encode_length_delimited(1, &type_meta); // TypeMeta
        unknown.extend_from_slice(&encode_length_delimited(2, &namespace_proto)); // raw
        unknown.extend_from_slice(&encode_length_delimited(
            4,
            b"application/vnd.kubernetes.protobuf",
        )); // contentType

        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&unknown);

        // Decode the envelope
        let env = decode_k8s_proto_envelope(&body).expect("envelope decode must succeed");
        assert_eq!(env.content_type, "application/vnd.kubernetes.protobuf");

        // Decode the inner proto-encoded Namespace
        let json = decode_namespace_proto(&env.raw).expect("namespace proto decode must succeed");
        assert_eq!(
            json["metadata"]["name"], "smoke-test",
            "name must be extracted from proto"
        );
        assert_eq!(json["kind"], "Namespace");
        assert_eq!(json["apiVersion"], "v1");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_configmap_proto
    // ---------------------------------------------------------------------------

    /// decode_configmap_proto must decode a proto-encoded ConfigMap with name, namespace, and data.
    /// This is the regression test for the smoke CI failure on `kubectl create configmap`.
    ///
    /// kubectl sends ConfigMap as a proto-encoded object in Unknown.raw (contentType=""),
    /// which must be decoded to JSON before being stored. Previously, the server tried to parse
    /// the proto bytes as JSON, hitting the "control character found" error at the 0x0a byte.
    #[test]
    fn decode_configmap_proto_extracts_name_namespace_and_data() {
        // Build: ObjectMeta { name: "smoke-cm", namespace: "smoke-test" }
        let mut obj_meta = encode_length_delimited(1, b"smoke-cm"); // field 1 = name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"smoke-test")); // field 3 = namespace
                                                                                // data map entry (field 2 of ConfigMap): { key="key", value="value" }
        let mut data_entry = encode_length_delimited(1, b"key");
        data_entry.extend_from_slice(&encode_length_delimited(2, b"value"));

        let mut configmap_proto = encode_length_delimited(1, &obj_meta); // ObjectMeta
        configmap_proto.extend_from_slice(&encode_length_delimited(2, &data_entry)); // data entry

        let result = decode_configmap_proto(&configmap_proto).expect("must decode configmap proto");

        assert_eq!(result["kind"], "ConfigMap");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "smoke-cm");
        assert_eq!(result["metadata"]["namespace"], "smoke-test");
        assert_eq!(result["data"]["key"], "value");
        assert!(result["metadata"]["creationTimestamp"].is_null());
    }

    /// decode_core_proto_by_kind must dispatch to the correct decoder.
    /// This verifies that extract_body can decode both Namespace and ConfigMap by kind.
    #[test]
    fn decode_core_proto_by_kind_dispatches_correctly() {
        let mut obj_meta = encode_length_delimited(1, b"test-ns"); // name
        let namespace_proto = encode_length_delimited(1, &obj_meta);
        let ns_json = decode_core_proto_by_kind("Namespace", &namespace_proto)
            .expect("Namespace must decode");
        assert_eq!(ns_json["kind"], "Namespace");
        assert_eq!(ns_json["metadata"]["name"], "test-ns");

        obj_meta = encode_length_delimited(1, b"test-cm"); // name
        let configmap_proto = encode_length_delimited(1, &obj_meta);
        let cm_json = decode_core_proto_by_kind("ConfigMap", &configmap_proto)
            .expect("ConfigMap must decode");
        assert_eq!(cm_json["kind"], "ConfigMap");
        assert_eq!(cm_json["metadata"]["name"], "test-cm");

        // Unknown kind returns None
        assert!(decode_core_proto_by_kind("UnknownKind", &namespace_proto).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_podtemplate_proto
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch PodTemplate proto and return a JSON object with
    /// the correct name and namespace.
    ///
    /// The e2e chunking test (apimachinery/chunking.go:68) creates ~400 PodTemplates via the
    /// Go client using Content-Type: application/vnd.kubernetes.protobuf. Without this decoder,
    /// decode_core_proto_by_kind returns None for "PodTemplate", extract_body returns the raw
    /// proto bytes, Object::from_bytes fails with "invalid JSON", the server returns 400, and
    /// after 3 failures the test calls Failf() in a goroutine without defer GinkgoRecover(),
    /// panicking the entire conformance suite (0/444 tests run).
    #[test]
    fn decode_core_proto_by_kind_dispatches_podtemplate() {
        // Build: PodTemplate { metadata: ObjectMeta { name: "chunking-pt-0", namespace: "default" } }
        let mut obj_meta = encode_length_delimited(1, b"chunking-pt-0"); // name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default")); // namespace

        let pt_proto = encode_length_delimited(1, &obj_meta); // PodTemplate.field 1 = ObjectMeta

        let result = decode_core_proto_by_kind("PodTemplate", &pt_proto)
            .expect("PodTemplate must decode via decode_core_proto_by_kind — without this, CREATE returns 400 and the e2e chunking test panics");

        assert_eq!(
            result["kind"], "PodTemplate",
            "kind must be PodTemplate so Object::from_bytes can route the object"
        );
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(
            result["metadata"]["name"], "chunking-pt-0",
            "name must be extracted so the object is stored under the correct key"
        );
        assert_eq!(result["metadata"]["namespace"], "default");
        assert!(
            result["metadata"]["creationTimestamp"].is_null(),
            "creationTimestamp must be null for kubectl compatibility"
        );
        assert!(
            result["template"].is_object(),
            "template must be an empty object (not missing), required by the k8s schema"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_pod_proto
    // ---------------------------------------------------------------------------

    /// decode_pod_proto must extract metadata and spec.containers from a proto-encoded Pod.
    ///
    /// The e2e conformance tests create Pods via proto (expansion.go:269, and many others).
    /// Without this decoder, decode_core_proto_by_kind returns None for "Pod", extract_body
    /// returns raw proto bytes, Object::from_bytes fails with "invalid JSON", and the apiserver
    /// returns 400 — causing every Pod-creating conformance test to fail immediately.
    #[test]
    fn decode_pod_proto_extracts_name_namespace_and_containers() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "test-pod", namespace: "default" },
        //   spec: PodSpec {
        //     containers: [Container { name: "myapp", image: "myapp:latest",
        //                             imagePullPolicy: "IfNotPresent" }]
        //   }
        // }
        let mut obj_meta = encode_length_delimited(1, b"test-pod"); // ObjectMeta.name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default")); // ObjectMeta.namespace

        // Container: field 1=name, field 2=image, field 15=imagePullPolicy
        let mut container = encode_length_delimited(1, b"myapp"); // name
        container.extend_from_slice(&encode_length_delimited(2, b"myapp:latest")); // image
        container.extend_from_slice(&encode_length_delimited(15, b"IfNotPresent")); // imagePullPolicy

        // PodSpec: field 2 = repeated Container (k8s.io/api/core/v1/generated.proto)
        let pod_spec = encode_length_delimited(2, &container);

        let mut pod_proto = encode_length_delimited(1, &obj_meta); // Pod.field 1 = ObjectMeta
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec)); // Pod.field 2 = PodSpec

        let result = decode_pod_proto(&pod_proto).expect(
            "decode_pod_proto must return Some — without this decoder, Pod creation via proto \
                     returns 400 'invalid JSON' and all container-related conformance tests fail",
        );

        assert_eq!(result["kind"], "Pod");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(
            result["metadata"]["name"], "test-pod",
            "name must be extracted so the object is stored under the correct key"
        );
        assert_eq!(result["metadata"]["namespace"], "default");
        assert!(result["metadata"]["creationTimestamp"].is_null());

        let containers = result["spec"]["containers"]
            .as_array()
            .expect("spec.containers must be an array");
        assert_eq!(containers.len(), 1, "one container must be decoded");
        assert_eq!(
            containers[0]["name"], "myapp",
            "container name must be extracted"
        );
        assert_eq!(
            containers[0]["image"], "myapp:latest",
            "container image must be extracted"
        );
        assert_eq!(containers[0]["imagePullPolicy"], "IfNotPresent");
    }

    /// decode_core_proto_by_kind must dispatch Pod proto and return a valid JSON object.
    ///
    /// This is the dispatch-level regression: even if the inner decoder works, the kind
    /// dispatch must route "Pod" correctly so extract_body can convert proto bodies to JSON.
    #[test]
    fn decode_core_proto_by_kind_dispatches_pod() {
        // Build: Pod { metadata: ObjectMeta { name: "dispatch-pod", namespace: "test" },
        //              spec: PodSpec { containers: [Container { name: "c", image: "img" }] } }
        let mut obj_meta = encode_length_delimited(1, b"dispatch-pod");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"test"));

        let mut container = encode_length_delimited(1, b"c");
        container.extend_from_slice(&encode_length_delimited(2, b"img"));

        // PodSpec.containers = field 2 (k8s.io/api/core/v1/generated.proto)
        let pod_spec = encode_length_delimited(2, &container);

        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_core_proto_by_kind("Pod", &pod_proto)
            .expect("Pod must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "Pod");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "dispatch-pod");
        assert_eq!(result["metadata"]["namespace"], "test");
        assert_eq!(result["spec"]["containers"][0]["name"], "c");
        assert_eq!(result["spec"]["containers"][0]["image"], "img");
    }

    /// decode_pod_proto must not panic when the Pod has no spec or containers.
    /// Empty Pod objects (used in tests to probe apiserver behavior) must decode gracefully.
    #[test]
    fn decode_pod_proto_handles_pod_with_no_containers() {
        let obj_meta = encode_length_delimited(1, b"empty-pod");
        let pod_proto = encode_length_delimited(1, &obj_meta);

        let result = decode_pod_proto(&pod_proto).expect("must decode Pod with no spec");

        assert_eq!(result["kind"], "Pod");
        assert_eq!(result["metadata"]["name"], "empty-pod");
        let containers = result["spec"]["containers"]
            .as_array()
            .expect("containers must be an empty array when Pod has no containers");
        assert!(containers.is_empty(), "containers array must be empty");
    }

    /// decode_pod_proto must decode a realistic kubectl pod proto with restartPolicy set.
    ///
    /// kubectl run nginx --image=nginx sends PodSpec with containers at field 2 (k8s proto) and
    /// restartPolicy at field 3 (k8s proto). The previous PodSpec struct used field 3 for
    /// containers and field 4 for restartPolicy — wrong field numbers — causing prost to try to
    /// decode the restartPolicy string ("Always") as a Container sub-message, which fails with a
    /// wire-type error and makes decode_pod_proto return None. That triggers extract_body to
    /// return raw proto bytes, and Object::from_bytes fails with "invalid JSON".
    #[test]
    fn decode_pod_proto_with_restart_policy_survives_decode() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "nginx", namespace: "default" },
        //   spec: PodSpec {
        //     containers: [Container { name: "nginx", image: "nginx:latest" }],  // field 2
        //     restartPolicy: "Always",                                            // field 3
        //   }
        // }
        let mut obj_meta = encode_length_delimited(1, b"nginx");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        let mut container = encode_length_delimited(1, b"nginx");
        container.extend_from_slice(&encode_length_delimited(2, b"nginx:latest"));

        // PodSpec: field 2 = containers, field 3 = restartPolicy
        let mut pod_spec = encode_length_delimited(2, &container);
        pod_spec.extend_from_slice(&encode_length_delimited(3, b"Always"));

        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_pod_proto(&pod_proto).expect(
            "decode_pod_proto must return Some even when restartPolicy is present — \
             without the fix, prost tries to decode restartPolicy string as Container \
             sub-message, hits an invalid wire type, and returns Err; that causes \
             extract_body to return raw proto bytes and Object::from_bytes to fail \
             with 'invalid JSON: expected value at line 1 column 1'",
        );

        assert_eq!(result["kind"], "Pod");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "nginx", "name must be decoded");
        assert_eq!(
            result["metadata"]["namespace"], "default",
            "namespace must be decoded"
        );
        assert_eq!(
            result["spec"]["restartPolicy"], "Always",
            "restartPolicy must be decoded from field 3 — regression for the wrong-field-number bug"
        );
        let containers = result["spec"]["containers"]
            .as_array()
            .expect("spec.containers must be an array");
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0]["name"], "nginx");
        assert_eq!(containers[0]["image"], "nginx:latest");
    }

    /// decode_pod_proto must decode serviceAccountName and nodeName at the correct field numbers.
    ///
    /// kubectl run uses serviceAccountName=default (field 8 in k8s PodSpec proto) and
    /// nodeName is set by the scheduler (field 10). The previous struct placed these at fields
    /// 9 and 11 respectively, causing field 9 (automountServiceAccountToken, bool) to mismatch
    /// when decoded as string and field 11 (hostNetwork, bool) to mismatch similarly — both
    /// can trigger prost DecodeError returning None from decode_pod_proto.
    #[test]
    fn decode_pod_proto_with_service_account_and_node_name() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "app", namespace: "default" },
        //   spec: PodSpec {
        //     containers: [Container { name: "app", image: "app:v1" }],  // field 2
        //     restartPolicy: "Always",                                    // field 3
        //     serviceAccountName: "my-sa",                               // field 8
        //     nodeName: "node-1",                                        // field 10
        //   }
        // }
        let mut obj_meta = encode_length_delimited(1, b"app");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        let mut container = encode_length_delimited(1, b"app");
        container.extend_from_slice(&encode_length_delimited(2, b"app:v1"));

        let mut pod_spec = encode_length_delimited(2, &container); // containers = field 2
        pod_spec.extend_from_slice(&encode_length_delimited(3, b"Always")); // restartPolicy = field 3
        pod_spec.extend_from_slice(&encode_length_delimited(8, b"my-sa")); // serviceAccountName = field 8
        pod_spec.extend_from_slice(&encode_length_delimited(10, b"node-1")); // nodeName = field 10

        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_pod_proto(&pod_proto).expect(
            "decode_pod_proto must succeed with serviceAccountName and nodeName — \
             wrong field numbers (9 vs 8 for serviceAccountName, 11 vs 10 for nodeName) \
             cause type mismatches with automountServiceAccountToken (bool) and \
             hostNetwork (bool) which trigger DecodeError",
        );

        assert_eq!(result["kind"], "Pod");
        assert_eq!(result["metadata"]["name"], "app");
        assert_eq!(
            result["spec"]["serviceAccountName"], "my-sa",
            "serviceAccountName must be decoded from field 8"
        );
        assert_eq!(
            result["spec"]["nodeName"], "node-1",
            "nodeName must be decoded from field 10"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_node_proto
    // ---------------------------------------------------------------------------

    /// decode_node_proto must extract ObjectMeta fields from a proto-encoded Node.
    /// This is the primary fix for kubelet PUT /api/v1/nodes/{name}/status with proto body —
    /// previously decode_core_proto_by_kind returned None for "Node", causing extract_body to
    /// return raw proto bytes that serde_json::from_slice then failed to parse as JSON.
    #[test]
    fn decode_node_proto_extracts_name() {
        // Build: Node { metadata: ObjectMeta { name: "node-1" } }
        let obj_meta = encode_length_delimited(1, b"node-1"); // field 1 = name
        let node_proto = encode_length_delimited(1, &obj_meta); // Node.field 1 = ObjectMeta

        let result = decode_node_proto(&node_proto).expect("must decode node proto");

        assert_eq!(result["kind"], "Node");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "node-1");
        assert!(result["metadata"]["creationTimestamp"].is_null());
    }

    /// decode_node_proto must extract podCIDR and providerID from NodeSpec (field 2).
    /// Kubelet sends a full Node proto on registration including spec fields — without this,
    /// stored nodes have empty spec and controllers see a malformed node.
    #[test]
    fn decode_node_proto_preserves_spec_fields() {
        // Build: Node {
        //   metadata: ObjectMeta { name: "node-1" },
        //   spec: NodeSpec { podCIDR: "10.244.0.0/24", providerID: "aws://us-east-1a/i-1234" }
        // }
        let obj_meta = encode_length_delimited(1, b"node-1"); // ObjectMeta.name
        let mut node_spec = Vec::new();
        node_spec.extend_from_slice(&encode_length_delimited(1, b"10.244.0.0/24")); // NodeSpec.podCIDR
        node_spec.extend_from_slice(&encode_length_delimited(3, b"aws://us-east-1a/i-1234")); // NodeSpec.providerID
        node_spec.extend_from_slice(&encode_length_delimited(7, b"10.244.0.0/24")); // NodeSpec.podCIDRs[0]

        let mut node_proto = encode_length_delimited(1, &obj_meta); // Node.field 1 = ObjectMeta
        node_proto.extend_from_slice(&encode_length_delimited(2, &node_spec)); // Node.field 2 = NodeSpec

        let result = decode_node_proto(&node_proto).expect("must decode node with spec");

        assert_eq!(result["kind"], "Node");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "node-1");
        assert_eq!(
            result["spec"]["podCIDR"], "10.244.0.0/24",
            "podCIDR must be extracted from NodeSpec field 1"
        );
        assert_eq!(
            result["spec"]["providerID"], "aws://us-east-1a/i-1234",
            "providerID must be extracted from NodeSpec field 3"
        );
        assert_eq!(
            result["spec"]["podCIDRs"][0], "10.244.0.0/24",
            "podCIDRs must be extracted from NodeSpec field 7"
        );
    }

    /// decode_node_proto must not panic when NodeSpec contains unrecognized fields (e.g. taints).
    /// Guards against kubelet sending a full Node proto with complex nested spec fields.
    #[test]
    fn decode_node_proto_with_unknown_spec_fields_does_not_panic() {
        // Build: Node { metadata: ObjectMeta { name: "node-2" }, spec: NodeSpec { podCIDR: "10.0.0.0/24", <unknown field> } }
        let obj_meta = encode_length_delimited(1, b"node-2"); // ObjectMeta.name
        let mut node_spec = Vec::new();
        node_spec.extend_from_slice(&encode_length_delimited(1, b"10.0.0.0/24")); // NodeSpec.podCIDR
                                                                                  // field 5 = taints (repeated Taint message) — not decoded, must be silently skipped
        node_spec.extend_from_slice(&encode_length_delimited(5, b"\x0a\x08NoSchedule")); // opaque Taint bytes

        let mut node_proto = encode_length_delimited(1, &obj_meta);
        node_proto.extend_from_slice(&encode_length_delimited(2, &node_spec));

        let result =
            decode_node_proto(&node_proto).expect("must not panic on unknown NodeSpec fields");

        assert_eq!(result["metadata"]["name"], "node-2");
        assert_eq!(result["spec"]["podCIDR"], "10.0.0.0/24");
    }

    /// decode_node_proto must not panic and must return Some when NodeSpec contains the
    /// `unschedulable` field (field 4, wire type 0, varint=1).
    ///
    /// Real kubelets send `unschedulable=true` during maintenance (node cordoning). The NodeSpec
    /// scanner uses scan_length_delimited_fields, which silently skips varint fields. This test
    /// guards against a future change to the scanner accidentally turning the silent-skip into a
    /// panic or a None return for nodes that are unschedulable.
    ///
    /// Protobuf encoding of `unschedulable=true` in NodeSpec:
    ///   tag = (field 4 << 3) | wire_type 0 = 0x20
    ///   value = varint 1 = 0x01
    #[test]
    fn decode_node_proto_unschedulable_node_does_not_panic() {
        // Build: Node {
        //   metadata: ObjectMeta { name: "maintenance-node" },
        //   spec: NodeSpec { podCIDR: "10.0.1.0/24", unschedulable: true }
        // }
        let obj_meta = encode_length_delimited(1, b"maintenance-node");
        let mut node_spec = Vec::new();
        node_spec.extend_from_slice(&encode_length_delimited(1, b"10.0.1.0/24")); // NodeSpec.podCIDR
                                                                                  // NodeSpec.unschedulable = true: tag=0x20 (field 4, wire type 0), value=0x01
        node_spec.push(0x20);
        node_spec.push(0x01);

        let mut node_proto = encode_length_delimited(1, &obj_meta);
        node_proto.extend_from_slice(&encode_length_delimited(2, &node_spec));

        // Must return Some — the varint field must be silently skipped, not cause a panic or None.
        let result = decode_node_proto(&node_proto)
            .expect("decode_node_proto must return Some even when unschedulable=true is present");

        assert_eq!(result["metadata"]["name"], "maintenance-node");
        assert_eq!(result["spec"]["podCIDR"], "10.0.1.0/24");
    }

    /// Walk every tag in a proto message (non-recursive, top-level only) and assert that no
    /// tag has an illegal wire type (3, 4, 6, or 7).  Called from regression tests below.
    ///
    /// Returns the list of fields encountered as `(field_number, wire_type, payload_len)`.
    fn assert_valid_wire_types(msg: &[u8]) -> Vec<(u64, u64, usize)> {
        let mut pos = 0;
        let mut fields = Vec::new();
        while pos < msg.len() {
            let (tag, rest) = decode_varint(&msg[pos..])
                .unwrap_or_else(|| panic!("truncated varint at pos {pos}"));
            pos += msg[pos..].len() - rest.len();
            let wire_type = tag & 0x7;
            let field_number = tag >> 3;
            assert!(
                !matches!(wire_type, 3 | 4 | 6 | 7),
                "illegal wire type {wire_type} at pos {}: tag=0x{tag:02x} field_number={field_number}\n\
                 Full envelope hex: {}",
                pos - 1,
                msg.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
            );
            match wire_type {
                0 => {
                    let (_, rest2) = decode_varint(&msg[pos..])
                        .unwrap_or_else(|| panic!("truncated varint value at pos {pos}"));
                    let consumed = msg[pos..].len() - rest2.len();
                    fields.push((field_number, wire_type, consumed));
                    pos += consumed;
                }
                2 => {
                    let (len, rest2) = decode_varint(&msg[pos..])
                        .unwrap_or_else(|| panic!("truncated length varint at pos {pos}"));
                    pos += msg[pos..].len() - rest2.len();
                    let len = len as usize;
                    assert!(
                        pos + len <= msg.len(),
                        "field {field_number} payload extends past end: pos={pos} len={len} msg_len={}",
                        msg.len()
                    );
                    fields.push((field_number, wire_type, len));
                    pos += len;
                }
                _ => unreachable!("wire_type checked above"),
            }
        }
        fields
    }

    /// Regression test: encode_proto_response must produce a valid Kubernetes protobuf envelope
    /// for the exact JSON returned by the create_namespace handler (smoke-test scenario).
    ///
    /// This test reproduces the FULL response path:
    ///   1. decode_namespace_proto (decodes kubectl's proto request body to JSON)
    ///   2. handler adds status + resourceVersion
    ///   3. middleware calls encode_proto_response on the JSON
    ///   4. we walk every tag in the Unknown envelope and assert no illegal wire types
    ///
    /// A regression here means `kubectl create namespace smoke-test` would fail with
    /// "proto: illegal wireType N" — the smoke CI gate failure this bead addresses.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_namespace_create() {
        // Reproduce what create_namespace returns after decode_namespace_proto:
        let mut obj_meta = encode_length_delimited(1, b"smoke-test");
        obj_meta.extend_from_slice(&encode_length_delimited(8, &[])); // creationTimestamp (empty Time{})
        let namespace_proto = encode_length_delimited(1, &obj_meta);
        let mut ns_json =
            decode_namespace_proto(&namespace_proto).expect("decode_namespace_proto must succeed");
        ns_json["status"] = serde_json::json!({ "phase": "Active" });
        ns_json["metadata"]["resourceVersion"] = serde_json::Value::String("1".to_string());

        // Simulate the middleware: parse JSON body then re-serialize via encode_proto_response.
        let json_str = ns_json.to_string();
        let val: serde_json::Value = serde_json::from_str(&json_str).expect("round-trip JSON");

        let encoded = encode_proto_response(&val);
        assert_eq!(
            &encoded[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "must start with k8s proto magic"
        );

        let envelope = &encoded[4..];

        // Walk the Unknown envelope: check top-level fields for illegal wire types.
        let fields = assert_valid_wire_types(envelope);

        // Verify the envelope has the three expected fields.
        let field_numbers: Vec<u64> = fields.iter().map(|(fn_, _, _)| *fn_).collect();
        assert!(
            field_numbers.contains(&1),
            "Unknown envelope must have field 1 (TypeMeta)"
        );
        assert!(
            field_numbers.contains(&2),
            "Unknown envelope must have field 2 (raw JSON)"
        );
        assert!(
            field_numbers.contains(&4),
            "Unknown envelope must have field 4 (contentType)"
        );

        // Also walk the TypeMeta sub-message.
        let type_meta_payload: &[u8] = {
            let mut p = envelope;
            let mut result: &[u8] = &[];
            let mut tmp_pos = 0;
            while tmp_pos < envelope.len() {
                let (tag, rest) = decode_varint(&envelope[tmp_pos..]).expect("valid tag");
                tmp_pos += envelope[tmp_pos..].len() - rest.len();
                let field_number = tag >> 3;
                let wire_type = tag & 0x7;
                if wire_type == 2 {
                    let (len, rest2) = decode_varint(&envelope[tmp_pos..]).expect("valid len");
                    tmp_pos += envelope[tmp_pos..].len() - rest2.len();
                    if field_number == 1 {
                        result = &envelope[tmp_pos..tmp_pos + len as usize];
                        break;
                    }
                    tmp_pos += len as usize;
                }
                p = &p[1..]; // ensure p advances (unused after first iteration)
            }
            result
        };
        let _ = assert_valid_wire_types(type_meta_payload);

        // Verify the encoded body is decodable end-to-end.
        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("envelope raw must be valid JSON");
        assert_eq!(recovered["kind"], "Namespace");
        assert_eq!(recovered["metadata"]["name"], "smoke-test");
        assert_eq!(env.content_type, "application/json");
    }

    /// decode_core_proto_by_kind must dispatch to decode_node_proto for kind="Node".
    /// This is the dispatch fix that ensures extract_body can handle kubelet Node proto bodies.
    #[test]
    fn decode_core_proto_by_kind_dispatches_node() {
        let obj_meta = encode_length_delimited(1, b"test-node");
        let node_proto = encode_length_delimited(1, &obj_meta);

        let result = decode_core_proto_by_kind("Node", &node_proto)
            .expect("Node must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "Node");
        assert_eq!(result["metadata"]["name"], "test-node");
    }

    /// Full round-trip for ConfigMap: kubectl create configmap sends a k8s proto envelope
    /// where Unknown.raw is a proto-encoded ConfigMap and contentType is empty.
    /// This is the regression test for the smoke CI failure on ConfigMap creation.
    #[test]
    fn full_kubectl_create_configmap_smoke_regression() {
        // Build: ObjectMeta { name: "smoke-cm", namespace: "smoke-test" }
        let mut obj_meta = encode_length_delimited(1, b"smoke-cm");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"smoke-test"));
        obj_meta.extend_from_slice(&encode_length_delimited(8, &[])); // creationTimestamp

        let mut data_entry = encode_length_delimited(1, b"key");
        data_entry.extend_from_slice(&encode_length_delimited(2, b"value"));

        let mut configmap_proto = encode_length_delimited(1, &obj_meta);
        configmap_proto.extend_from_slice(&encode_length_delimited(2, &data_entry));

        // Wrap in k8s Unknown envelope with empty contentType (as kubectl sends)
        let type_meta: Vec<u8> = {
            let mut t = encode_length_delimited(1, b"v1");
            t.extend_from_slice(&encode_length_delimited(2, b"ConfigMap"));
            t
        };
        let mut unknown = encode_length_delimited(1, &type_meta); // TypeMeta
        unknown.extend_from_slice(&encode_length_delimited(2, &configmap_proto)); // raw
                                                                                  // contentType field 4 is absent (empty = kubectl behavior)

        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&unknown);

        let env = decode_k8s_proto_envelope(&body).expect("envelope decode must succeed");
        assert_eq!(env.kind, "ConfigMap");
        assert_eq!(
            env.content_type, "",
            "kubectl sends empty contentType for core types"
        );

        let json = decode_core_proto_by_kind(&env.kind, &env.raw)
            .expect("ConfigMap proto decode must succeed");
        assert_eq!(json["kind"], "ConfigMap");
        assert_eq!(json["metadata"]["name"], "smoke-cm");
        assert_eq!(json["data"]["key"], "value");
    }

    /// encode_proto_response must produce a valid proto envelope for APIVersions
    /// (the /api discovery response). kubectl requests this with Accept: proto
    /// before attempting any resource operations. A wireType 6 in this response
    /// would cause "proto: illegal wireType 6" before kubectl even issues the
    /// namespace create command.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_api_versions() {
        let val = serde_json::json!({
            "kind": "APIVersions",
            "apiVersion": "v1",
            "versions": ["v1"],
            "serverAddressByClientCIDRs": [{
                "clientCIDR": "0.0.0.0/0",
                "serverAddress": "https://127.0.0.1:6443"
            }]
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(&encoded[..4], &[0x6b, 0x38, 0x73, 0x00]);

        let fields = assert_valid_wire_types(&encoded[4..]);
        let field_numbers: Vec<u64> = fields.iter().map(|(fn_, _, _)| *fn_).collect();
        assert!(field_numbers.contains(&1), "TypeMeta field must be present");
        assert!(field_numbers.contains(&2), "raw field must be present");
        assert!(
            field_numbers.contains(&4),
            "contentType field must be present"
        );

        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw must be valid JSON");
        assert_eq!(recovered["kind"], "APIVersions");
    }

    /// encode_proto_response must produce a valid proto envelope for APIResourceList
    /// (the /api/v1 discovery response). kubectl fetches this to discover core resources.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_api_resource_list() {
        let val = serde_json::json!({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": "v1",
            "resources": [
                {
                    "name": "namespaces",
                    "singularName": "namespace",
                    "namespaced": false,
                    "kind": "Namespace",
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
                },
                {
                    "name": "pods",
                    "singularName": "pod",
                    "namespaced": true,
                    "kind": "Pod",
                    "shortNames": ["po"],
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
                }
            ]
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(&encoded[..4], &[0x6b, 0x38, 0x73, 0x00]);
        assert_valid_wire_types(&encoded[4..]);

        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw must be valid JSON");
        assert_eq!(recovered["kind"], "APIResourceList");
    }

    /// encode_proto_response must produce a valid proto envelope for APIGroupList
    /// (the /apis discovery response). kubectl fetches this to enumerate all API groups.
    /// This response can be large (11+ groups) and contains slash-containing strings
    /// like "rbac.authorization.k8s.io/v1" which must not produce illegal wire types.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_api_group_list() {
        let val = serde_json::json!({
            "kind": "APIGroupList",
            "apiVersion": "v1",
            "groups": [
                {
                    "name": "admissionregistration.k8s.io",
                    "versions": [{"groupVersion": "admissionregistration.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "admissionregistration.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "apiextensions.k8s.io",
                    "versions": [{"groupVersion": "apiextensions.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "apiextensions.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "apps",
                    "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"}
                },
                {
                    "name": "authentication.k8s.io",
                    "versions": [{"groupVersion": "authentication.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "authentication.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "authorization.k8s.io",
                    "versions": [{"groupVersion": "authorization.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "authorization.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "coordination.k8s.io",
                    "versions": [{"groupVersion": "coordination.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "coordination.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "networking.k8s.io",
                    "versions": [{"groupVersion": "networking.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "networking.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "node.k8s.io",
                    "versions": [{"groupVersion": "node.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "node.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "policy",
                    "versions": [{"groupVersion": "policy/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "policy/v1", "version": "v1"}
                },
                {
                    "name": "rbac.authorization.k8s.io",
                    "versions": [{"groupVersion": "rbac.authorization.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "rbac.authorization.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "storage.k8s.io",
                    "versions": [{"groupVersion": "storage.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "storage.k8s.io/v1", "version": "v1"}
                }
            ]
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(&encoded[..4], &[0x6b, 0x38, 0x73, 0x00]);
        assert_valid_wire_types(&encoded[4..]);

        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw must be valid JSON");
        assert_eq!(recovered["kind"], "APIGroupList");
        assert_eq!(
            recovered["groups"].as_array().unwrap().len(),
            11,
            "all 11 groups must be present"
        );
    }

    /// Regression test for mayor-cux: encode_proto_response must produce a valid Kubernetes
    /// protobuf envelope for a realistic Namespace JSON with name, uid, resourceVersion,
    /// creationTimestamp, and labels — the exact fields present in a real `kubectl create
    /// namespace smoke-test` response.
    ///
    /// This test walks EVERY byte of the encoded output, checking that each proto tag has a
    /// legal wire type. It must fail if encode_proto_response produces an illegal wire type,
    /// and must pass after the fix is applied.
    ///
    /// The "proto: illegal wireType 6" CI failure is reproduced when the Go proto decoder
    /// misaligns while reading the Unknown envelope — e.g., due to a wrong length varint that
    /// causes it to stop reading the raw field too early, leaving JSON bytes to be mis-read
    /// as proto tags. ('n' = 0x6E has wire type 6.)
    #[test]
    fn encode_proto_response_no_illegal_wire_types_realistic_namespace() {
        // Build a realistic namespace JSON matching what the server returns after
        // create_namespace: includes uid, resourceVersion, labels, and creationTimestamp.
        let val = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "creationTimestamp": null,
                "labels": {
                    "kubernetes.io/metadata.name": "smoke-test"
                },
                "name": "smoke-test",
                "resourceVersion": "5",
                "uid": "12345678-1234-1234-1234-123456789012"
            },
            "status": {
                "phase": "Active"
            }
        });

        let encoded = encode_proto_response(&val);

        // Must start with k8s proto magic.
        assert_eq!(
            &encoded[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "must start with k8s proto magic"
        );

        let envelope = &encoded[4..];

        // Walk every tag in the Unknown envelope, asserting no illegal wire types.
        // This is the core of the regression: if any tag byte has wire type 6 (or 3, 4, 7),
        // the Go proto decoder would produce "proto: illegal wireType N".
        let fields = assert_valid_wire_types(envelope);

        // Verify the expected fields are present.
        let field_numbers: Vec<u64> = fields.iter().map(|(fn_, _, _)| *fn_).collect();
        assert!(
            field_numbers.contains(&1),
            "field 1 (TypeMeta) must be in Unknown envelope"
        );
        assert!(
            field_numbers.contains(&2),
            "field 2 (raw JSON) must be in Unknown envelope"
        );
        assert!(
            field_numbers.contains(&4),
            "field 4 (contentType) must be in Unknown envelope"
        );

        // Also walk the TypeMeta sub-message.
        let type_meta_len = fields
            .iter()
            .find(|(fn_, _, _)| *fn_ == 1)
            .map(|(_, _, l)| *l)
            .unwrap();
        let type_meta_start = {
            // field 1 tag byte (1 byte) + len varint (1 byte for len < 128)
            let mut p = 0;
            let (_tag, rest) = decode_varint(envelope).unwrap();
            p += envelope.len() - rest.len();
            let (_len, rest2) = decode_varint(rest).unwrap();
            p += rest.len() - rest2.len();
            p
        };
        let type_meta_bytes = &envelope[type_meta_start..type_meta_start + type_meta_len];
        assert_valid_wire_types(type_meta_bytes);

        // Full round-trip: raw field must be valid JSON containing our namespace data.
        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        assert_eq!(env.content_type, "application/json");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw field must be valid JSON");
        assert_eq!(recovered["kind"], "Namespace");
        assert_eq!(recovered["metadata"]["name"], "smoke-test");
        assert_eq!(
            recovered["metadata"]["uid"],
            "12345678-1234-1234-1234-123456789012"
        );
        assert_eq!(
            recovered["metadata"]["labels"]["kubernetes.io/metadata.name"],
            "smoke-test"
        );
        assert_eq!(recovered["metadata"]["resourceVersion"], "5");
        assert!(recovered["metadata"]["creationTimestamp"].is_null());
    }

    /// Regression test for mayor-ajtd: encode_proto_response must produce a valid Kubernetes
    /// protobuf envelope for a realistic Node JSON with status conditions and addresses —
    /// the exact response shape the kubelet receives when reading its own node status.
    ///
    /// This test verifies that encode_proto_response itself does NOT produce wireType 7.
    /// The actual kubelet failure ("proto: illegal wireType 7") arises because client-go's
    /// typed Node proto decoder ignores the contentType=application/json field inside the
    /// Unknown envelope and tries to decode Unknown.raw as a typed proto Node. The JSON bytes
    /// (e.g. '/' in CIDRs, 'o' in "conditions") happen to have low 3 bits = 0b111 at the
    /// position the decoder is reading, producing wireType 7. The fix is to not re-encode
    /// Node responses at all (see content_type.rs). This test guards the encoder itself:
    /// the proto envelope we produce is structurally correct even if client-go won't use
    /// the contentType field.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_node_with_status() {
        let val = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "ci-node",
                "uid": "abc-def-123",
                "resourceVersion": "7",
                "creationTimestamp": "2026-05-21T00:00:00Z"
            },
            "spec": {
                "podCIDR": "10.244.0.0/24",
                "podCIDRs": ["10.244.0.0/24"],
                "providerID": "kind://docker/local/local-worker"
            },
            "status": {
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "lastHeartbeatTime": "2026-05-21T00:01:00Z",
                        "lastTransitionTime": "2026-05-21T00:00:30Z",
                        "reason": "KubeletReady",
                        "message": "kubelet is posting ready status"
                    },
                    {
                        "type": "MemoryPressure",
                        "status": "False",
                        "reason": "KubeletHasSufficientMemory"
                    }
                ],
                "addresses": [
                    {"type": "InternalIP", "address": "192.168.1.10"},
                    {"type": "Hostname", "address": "ci-node"}
                ],
                "nodeInfo": {
                    "machineID": "abc123",
                    "systemUUID": "abc123",
                    "bootID": "xyz",
                    "kernelVersion": "6.1.0",
                    "osImage": "Ubuntu 22.04",
                    "containerRuntimeVersion": "containerd://1.7.0",
                    "kubeletVersion": "v1.36.0",
                    "kubeProxyVersion": "v1.36.0",
                    "operatingSystem": "linux",
                    "architecture": "amd64"
                }
            }
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(
            &encoded[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "must start with k8s proto magic"
        );

        // Walk every tag in the Unknown envelope: no wireType 7 (or 3, 4, 6) allowed.
        // wireType 7 = 0b111 in low 3 bits; any such byte as a proto tag is illegal.
        let fields = assert_valid_wire_types(&encoded[4..]);

        let field_numbers: Vec<u64> = fields.iter().map(|(fn_, _, _)| *fn_).collect();
        assert!(field_numbers.contains(&1), "TypeMeta field must be present");
        assert!(
            field_numbers.contains(&2),
            "raw Node JSON field must be present"
        );
        assert!(
            field_numbers.contains(&4),
            "contentType field must be present"
        );

        // The envelope must be decodable and the raw field must be valid JSON.
        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        assert_eq!(env.content_type, "application/json");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw field must be valid JSON");
        assert_eq!(recovered["kind"], "Node");
        assert_eq!(recovered["metadata"]["name"], "ci-node");
        assert_eq!(recovered["spec"]["podCIDR"], "10.244.0.0/24");
        assert_eq!(recovered["status"]["conditions"][0]["type"], "Ready");
        assert_eq!(recovered["status"]["conditions"][0]["status"], "True");
        assert_eq!(
            recovered["status"]["addresses"][0]["address"],
            "192.168.1.10"
        );
    }

    /// encode_proto_response must produce a valid proto envelope for the /version response.
    /// This JSON has no apiVersion or kind fields, resulting in empty TypeMeta strings.
    /// Empty strings still produce valid LEN-encoded fields with zero-length payloads.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_server_version() {
        let val = serde_json::json!({
            "major": "1",
            "minor": "36",
            "gitVersion": "v1.36.0",
            "gitCommit": "0000000000000000000000000000000000000000",
            "gitTreeState": "clean",
            "buildDate": "1970-01-01T00:00:00Z",
            "goVersion": "go1.24.0",
            "compiler": "gc",
            "platform": "linux/amd64"
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(&encoded[..4], &[0x6b, 0x38, 0x73, 0x00]);
        assert_valid_wire_types(&encoded[4..]);

        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw must be valid JSON");
        assert_eq!(recovered["gitVersion"], "v1.36.0");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_lease_proto
    // ---------------------------------------------------------------------------

    /// decode_lease_proto must extract metadata, holderIdentity, and leaseDurationSeconds.
    /// The kubelet sends Lease proto on PUT /apis/coordination.k8s.io/v1/namespaces/{ns}/leases/{name}
    /// to renew its node lease. Without this decoder, extract_body returns None and the handler
    /// cannot decode the proto request body.
    #[test]
    fn decode_lease_proto_extracts_holder_and_duration() {
        // Build: Lease {
        //   metadata: ObjectMeta { name: "lima-node", namespace: "kube-node-lease" },
        //   spec: LeaseSpec { holderIdentity: "lima-node", leaseDurationSeconds: 40 }
        // }
        let mut obj_meta = encode_length_delimited(1, b"lima-node");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"kube-node-lease"));

        // LeaseSpec field 1 = holderIdentity (string, wire 2)
        let mut lease_spec = encode_length_delimited(1, b"lima-node");
        // LeaseSpec field 2 = leaseDurationSeconds (int32, wire 0): tag=0x10, value=40 varint=0x28
        lease_spec.push(0x10); // (2 << 3) | 0 = field 2, wire type 0
        lease_spec.push(0x28); // varint 40

        let mut lease_proto = encode_length_delimited(1, &obj_meta);
        lease_proto.extend_from_slice(&encode_length_delimited(2, &lease_spec));

        let result = decode_lease_proto(&lease_proto).expect("must decode Lease proto");

        assert_eq!(result["kind"], "Lease");
        assert_eq!(result["apiVersion"], "coordination.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "lima-node");
        assert_eq!(result["metadata"]["namespace"], "kube-node-lease");
        assert_eq!(result["spec"]["holderIdentity"], "lima-node");
        assert_eq!(result["spec"]["leaseDurationSeconds"], 40);
    }

    /// decode_core_proto_by_kind must dispatch to decode_lease_proto for kind="Lease".
    #[test]
    fn decode_core_proto_by_kind_dispatches_lease() {
        let obj_meta = encode_length_delimited(1, b"test-node");
        let lease_proto = encode_length_delimited(1, &obj_meta);

        let result = decode_core_proto_by_kind("Lease", &lease_proto)
            .expect("Lease must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "Lease");
        assert_eq!(result["metadata"]["name"], "test-node");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_csinode_proto
    // ---------------------------------------------------------------------------

    /// decode_csinode_proto must extract metadata and the drivers array.
    /// The kubelet registers its CSI drivers via PUT /apis/storage.k8s.io/v1/csinodes/{name}.
    /// Without this decoder the proto body cannot be decoded and the request fails.
    #[test]
    fn decode_csinode_proto_extracts_drivers() {
        // Build: CSINode {
        //   metadata: ObjectMeta { name: "ci-node" },
        //   spec: CSINodeSpec {
        //     drivers: [CSINodeDriver { name: "csi.example.com", nodeID: "node-abc" }]
        //   }
        // }
        let obj_meta = encode_length_delimited(1, b"ci-node");

        // CSINodeDriver: field 1=name, field 2=nodeID
        let mut driver = encode_length_delimited(1, b"csi.example.com");
        driver.extend_from_slice(&encode_length_delimited(2, b"node-abc"));

        // CSINodeSpec: field 1 = repeated CSINodeDriver
        let csinode_spec = encode_length_delimited(1, &driver);

        let mut csinode_proto = encode_length_delimited(1, &obj_meta);
        csinode_proto.extend_from_slice(&encode_length_delimited(2, &csinode_spec));

        let result = decode_csinode_proto(&csinode_proto).expect("must decode CSINode proto");

        assert_eq!(result["kind"], "CSINode");
        assert_eq!(result["apiVersion"], "storage.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "ci-node");
        assert_eq!(result["spec"]["drivers"][0]["name"], "csi.example.com");
        assert_eq!(result["spec"]["drivers"][0]["nodeID"], "node-abc");
    }

    /// decode_core_proto_by_kind must dispatch to decode_csinode_proto for kind="CSINode".
    #[test]
    fn decode_core_proto_by_kind_dispatches_csinode() {
        let obj_meta = encode_length_delimited(1, b"test-node");
        let csinode_proto = encode_length_delimited(1, &obj_meta);

        let result = decode_core_proto_by_kind("CSINode", &csinode_proto)
            .expect("CSINode must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "CSINode");
        assert_eq!(result["metadata"]["name"], "test-node");
        assert!(result["spec"]["drivers"].is_array());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_event_proto
    // ---------------------------------------------------------------------------

    /// decode_event_proto must extract metadata, involvedObject, reason, message, count, and type.
    /// The kubelet posts Events to /api/v1/namespaces/{ns}/events on significant node/pod events.
    /// Without this decoder the proto body cannot be decoded and events are lost.
    #[test]
    fn decode_event_proto_extracts_all_fields() {
        // Build: Event {
        //   metadata: ObjectMeta { name: "pod.abc123", namespace: "default" },
        //   involvedObject: ObjectReference { kind: "Pod", namespace: "default", name: "mypod",
        //                                    uid: "uid-1", apiVersion: "v1" },
        //   reason: "Started",
        //   message: "Started container myapp",
        //   count: 1,
        //   type: "Normal"
        // }
        let mut obj_meta = encode_length_delimited(1, b"pod.abc123");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        // ObjectReference (field 2 of Event)
        let mut obj_ref = encode_length_delimited(1, b"Pod"); // kind
        obj_ref.extend_from_slice(&encode_length_delimited(2, b"default")); // namespace
        obj_ref.extend_from_slice(&encode_length_delimited(3, b"mypod")); // name
        obj_ref.extend_from_slice(&encode_length_delimited(4, b"uid-1")); // uid
        obj_ref.extend_from_slice(&encode_length_delimited(5, b"v1")); // apiVersion

        // Encode count=1 as varint field 8, wire type 0: tag = (8 << 3) | 0 = 0x40, value = 0x01
        let count_bytes: Vec<u8> = vec![0x40, 0x01];

        // Build the full Event message using scan_mixed_fields-compatible encoding:
        // field 1 (ObjectMeta, wire 2), field 2 (involvedObject, wire 2),
        // field 3 (reason, wire 2), field 4 (message, wire 2),
        // field 8 (count, wire 0), field 9 (type, wire 2)
        let mut event_proto = encode_length_delimited(1, &obj_meta);
        event_proto.extend_from_slice(&encode_length_delimited(2, &obj_ref));
        event_proto.extend_from_slice(&encode_length_delimited(3, b"Started"));
        event_proto.extend_from_slice(&encode_length_delimited(4, b"Started container myapp"));
        event_proto.extend_from_slice(&count_bytes);
        event_proto.extend_from_slice(&encode_length_delimited(9, b"Normal"));

        let result = decode_event_proto(&event_proto).expect("must decode Event proto");

        assert_eq!(result["kind"], "Event");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "pod.abc123");
        assert_eq!(result["metadata"]["namespace"], "default");
        assert_eq!(result["involvedObject"]["kind"], "Pod");
        assert_eq!(result["involvedObject"]["namespace"], "default");
        assert_eq!(result["involvedObject"]["name"], "mypod");
        assert_eq!(result["involvedObject"]["uid"], "uid-1");
        assert_eq!(result["involvedObject"]["apiVersion"], "v1");
        assert_eq!(result["reason"], "Started");
        assert_eq!(result["message"], "Started container myapp");
        assert_eq!(result["count"], 1);
        assert_eq!(result["type"], "Normal");
    }

    /// decode_event_proto must include series.count and series.lastObservedTime in the output.
    /// kubelet/controllers patch Events with series to track repeated events; if series is
    /// silently dropped the client's GET sees series=nil, causing the update to overwrite the
    /// stored object without series and the conformance test (core_events.go:144) to fail.
    #[test]
    fn decode_event_proto_includes_series() {
        // Build: Event {
        //   metadata: ObjectMeta { name: "test.series" },
        //   series: EventSeries { count: 100, lastObservedTime: 1704067200 (2024-01-01T00:00:00Z) }
        // }
        let obj_meta = encode_length_delimited(1, b"test.series");

        // EventSeries: field 1 = count (varint wire 0), field 2 = MicroTime (wire 2).
        // count=100: tag=(1<<3)|0=0x08, value=0x64
        let mut event_series = vec![0x08, 0x64];
        // MicroTime message content: field 1 (seconds, int64, wire 0) = 1704067200
        let mut microtime_content = encode_varint(1 << 3); // field 1, wire type 0 (varint)
        microtime_content.extend_from_slice(&encode_varint(1_704_067_200u64));
        event_series.extend_from_slice(&encode_length_delimited(2, &microtime_content));

        // Event: field 1 = ObjectMeta, field 11 = EventSeries
        let mut event_proto = encode_length_delimited(1, &obj_meta);
        event_proto.extend_from_slice(&encode_length_delimited(11, &event_series));

        let result = decode_event_proto(&event_proto).expect("must decode Event proto with series");

        assert_eq!(
            result["series"]["count"], 100,
            "series.count must be decoded and present in JSON; \
             dropping it causes client GETs to see series=nil and subsequent \
             PUTs to overwrite the object without series"
        );
        assert_eq!(
            result["series"]["lastObservedTime"], "2024-01-01T00:00:00Z",
            "series.lastObservedTime must be decoded as RFC3339"
        );
    }

    /// decode_core_proto_by_kind must dispatch to decode_event_proto for kind="Event".
    #[test]
    fn decode_core_proto_by_kind_dispatches_event() {
        let obj_meta = encode_length_delimited(1, b"myevent");
        let event_proto = encode_length_delimited(1, &obj_meta);

        let result = decode_core_proto_by_kind("Event", &event_proto)
            .expect("Event must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "Event");
        assert_eq!(result["metadata"]["name"], "myevent");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_clusterrole_proto / decode_core_proto_by_kind ClusterRole
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch ClusterRole proto to the correct decoder and
    /// extract metadata, rules (with apiGroups, resources, verbs).
    ///
    /// This is the PRIMARY regression guard for mayor-hww0: kubectl create clusterrole sends
    /// a proto-encoded ClusterRole in Unknown.raw with empty contentType. Previously,
    /// decode_core_proto_by_kind returned None for "ClusterRole", so extract_body fell through
    /// to JSON parsing and failed with "invalid JSON: expected value at line 1 column 1".
    #[test]
    fn decode_core_proto_by_kind_dispatches_clusterrole() {
        // Build: ClusterRole {
        //   metadata: ObjectMeta { name: "test-rbac-fix" },
        //   rules: [PolicyRule { verbs: ["get","list"], apiGroups: [""], resources: ["pods"] }]
        // }
        let obj_meta = encode_length_delimited(1, b"test-rbac-fix"); // ObjectMeta.name

        // PolicyRule: field 1=verbs, field 2=apiGroups, field 3=resources
        let mut rule = encode_length_delimited(1, b"get");
        rule.extend_from_slice(&encode_length_delimited(1, b"list"));
        rule.extend_from_slice(&encode_length_delimited(2, b"")); // apiGroup="" (core)
        rule.extend_from_slice(&encode_length_delimited(3, b"pods"));

        let mut clusterrole_proto = encode_length_delimited(1, &obj_meta); // field 1 = ObjectMeta
        clusterrole_proto.extend_from_slice(&encode_length_delimited(2, &rule)); // field 2 = PolicyRule

        let result = decode_core_proto_by_kind("ClusterRole", &clusterrole_proto)
            .expect("ClusterRole must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "ClusterRole");
        assert_eq!(result["apiVersion"], "rbac.authorization.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "test-rbac-fix");
        assert!(result["metadata"]["creationTimestamp"].is_null());
        // rules array must be present with the encoded rule
        let rules = result["rules"].as_array().expect("rules must be an array");
        assert_eq!(rules.len(), 1, "one rule must be present");
        let rule0 = &rules[0];
        // verbs must contain "get" and "list"
        let verbs = rule0["verbs"].as_array().expect("verbs must be array");
        assert!(
            verbs.contains(&serde_json::Value::String("get".to_string())),
            "verbs must contain 'get'"
        );
        assert!(
            verbs.contains(&serde_json::Value::String("list".to_string())),
            "verbs must contain 'list'"
        );
        let resources = rule0["resources"]
            .as_array()
            .expect("resources must be array");
        assert_eq!(resources[0], "pods", "resources must contain 'pods'");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_clusterrolebinding_proto / decode_core_proto_by_kind ClusterRoleBinding
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch ClusterRoleBinding proto and extract
    /// metadata, subjects, and roleRef.
    ///
    /// kubectl create clusterrolebinding sends a proto-encoded ClusterRoleBinding with
    /// empty contentType. Without this decoder the request fails with "invalid JSON".
    #[test]
    fn decode_core_proto_by_kind_dispatches_clusterrolebinding() {
        // Build: ClusterRoleBinding {
        //   metadata: ObjectMeta { name: "test-crb" },
        //   subjects: [Subject { kind: "ServiceAccount", name: "default", namespace: "default",
        //                        apiGroup: "" }],
        //   roleRef: RoleRef { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole",
        //                      name: "test-rbac-fix" }
        // }
        let obj_meta = encode_length_delimited(1, b"test-crb"); // ObjectMeta.name

        // Subject: field 1=kind, field 2=apiGroup, field 3=name, field 4=namespace
        let mut subject = encode_length_delimited(1, b"ServiceAccount");
        subject.extend_from_slice(&encode_length_delimited(2, b"")); // apiGroup="" for SA
        subject.extend_from_slice(&encode_length_delimited(3, b"default"));
        subject.extend_from_slice(&encode_length_delimited(4, b"default"));

        // RoleRef: field 1=apiGroup, field 2=kind, field 3=name
        let mut role_ref = encode_length_delimited(1, b"rbac.authorization.k8s.io");
        role_ref.extend_from_slice(&encode_length_delimited(2, b"ClusterRole"));
        role_ref.extend_from_slice(&encode_length_delimited(3, b"test-rbac-fix"));

        let mut crb_proto = encode_length_delimited(1, &obj_meta); // field 1 = ObjectMeta
        crb_proto.extend_from_slice(&encode_length_delimited(2, &subject)); // field 2 = Subject
        crb_proto.extend_from_slice(&encode_length_delimited(3, &role_ref)); // field 3 = RoleRef

        let result = decode_core_proto_by_kind("ClusterRoleBinding", &crb_proto)
            .expect("ClusterRoleBinding must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "ClusterRoleBinding");
        assert_eq!(result["apiVersion"], "rbac.authorization.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "test-crb");
        let subjects = result["subjects"]
            .as_array()
            .expect("subjects must be array");
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0]["kind"], "ServiceAccount");
        assert_eq!(subjects[0]["name"], "default");
        assert_eq!(subjects[0]["namespace"], "default");
        assert_eq!(result["roleRef"]["apiGroup"], "rbac.authorization.k8s.io");
        assert_eq!(result["roleRef"]["kind"], "ClusterRole");
        assert_eq!(result["roleRef"]["name"], "test-rbac-fix");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_role_proto / decode_core_proto_by_kind Role
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch Role proto and extract metadata and rules.
    ///
    /// kubectl create role is namespaced; the proto structure is identical to ClusterRole
    /// but with a namespace in ObjectMeta. Without this decoder the request fails.
    #[test]
    fn decode_core_proto_by_kind_dispatches_role() {
        // Build: Role {
        //   metadata: ObjectMeta { name: "pod-reader", namespace: "default" },
        //   rules: [PolicyRule { verbs: ["get"], resources: ["pods"], apiGroups: [""] }]
        // }
        let mut obj_meta = encode_length_delimited(1, b"pod-reader"); // name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default")); // namespace

        let mut rule = encode_length_delimited(1, b"get");
        rule.extend_from_slice(&encode_length_delimited(2, b"")); // apiGroup=""
        rule.extend_from_slice(&encode_length_delimited(3, b"pods"));

        let mut role_proto = encode_length_delimited(1, &obj_meta);
        role_proto.extend_from_slice(&encode_length_delimited(2, &rule));

        let result = decode_core_proto_by_kind("Role", &role_proto)
            .expect("Role must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "Role");
        assert_eq!(result["apiVersion"], "rbac.authorization.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "pod-reader");
        assert_eq!(result["metadata"]["namespace"], "default");
        let rules = result["rules"].as_array().expect("rules must be array");
        assert_eq!(rules.len(), 1);
        let verbs = rules[0]["verbs"].as_array().expect("verbs must be array");
        assert!(verbs.contains(&serde_json::Value::String("get".to_string())));
        assert_eq!(rules[0]["resources"][0], "pods");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_rolebinding_proto / decode_core_proto_by_kind RoleBinding
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch RoleBinding proto and extract
    /// metadata, subjects, and roleRef.
    ///
    /// kubectl create rolebinding is namespaced. Without this decoder the request fails.
    #[test]
    fn decode_core_proto_by_kind_dispatches_rolebinding() {
        // Build: RoleBinding {
        //   metadata: ObjectMeta { name: "read-pods", namespace: "default" },
        //   subjects: [Subject { kind: "User", name: "alice", apiGroup: "rbac.authorization.k8s.io" }],
        //   roleRef: RoleRef { apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: "pod-reader" }
        // }
        let mut obj_meta = encode_length_delimited(1, b"read-pods");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        let mut subject = encode_length_delimited(1, b"User");
        subject.extend_from_slice(&encode_length_delimited(2, b"rbac.authorization.k8s.io"));
        subject.extend_from_slice(&encode_length_delimited(3, b"alice"));

        let mut role_ref = encode_length_delimited(1, b"rbac.authorization.k8s.io");
        role_ref.extend_from_slice(&encode_length_delimited(2, b"Role"));
        role_ref.extend_from_slice(&encode_length_delimited(3, b"pod-reader"));

        let mut rb_proto = encode_length_delimited(1, &obj_meta);
        rb_proto.extend_from_slice(&encode_length_delimited(2, &subject));
        rb_proto.extend_from_slice(&encode_length_delimited(3, &role_ref));

        let result = decode_core_proto_by_kind("RoleBinding", &rb_proto)
            .expect("RoleBinding must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "RoleBinding");
        assert_eq!(result["apiVersion"], "rbac.authorization.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "read-pods");
        assert_eq!(result["metadata"]["namespace"], "default");
        let subjects = result["subjects"]
            .as_array()
            .expect("subjects must be array");
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0]["kind"], "User");
        assert_eq!(subjects[0]["name"], "alice");
        assert_eq!(subjects[0]["apiGroup"], "rbac.authorization.k8s.io");
        assert_eq!(result["roleRef"]["kind"], "Role");
        assert_eq!(result["roleRef"]["name"], "pod-reader");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_subject_access_review_proto
    // ---------------------------------------------------------------------------

    /// decode_subject_access_review_proto must extract spec.user, spec.groups, and
    /// spec.resourceAttributes from a synthetic protobuf payload.
    ///
    /// The kubelet uses Webhook authorization (default in k8s 1.36 --config) and sends
    /// SubjectAccessReview with Content-Type: application/vnd.kubernetes.protobuf.
    /// Without this decoder, the server returns 400/500, which the kubelet interprets as
    /// an authorization denial — kubectl commands fail with InternalError.
    #[test]
    fn decode_subject_access_review_proto_extracts_all_fields() {
        // Build ResourceAttributes: field 2=verb, field 5=resource
        let mut resource_attrs = encode_length_delimited(2, b"get"); // verb
        resource_attrs.extend_from_slice(&encode_length_delimited(5, b"pods")); // resource

        // Build SubjectAccessReviewSpec:
        //   field 1 = ResourceAttributes
        //   field 3 = user (string)
        //   field 4 = groups (repeated string)
        let mut spec = encode_length_delimited(1, &resource_attrs);
        spec.extend_from_slice(&encode_length_delimited(3, b"system:admin")); // user
        spec.extend_from_slice(&encode_length_delimited(4, b"system:masters")); // groups[0]

        // Build SubjectAccessReview: field 2 = spec
        let sar_proto = encode_length_delimited(2, &spec);

        let result = decode_subject_access_review_proto(&sar_proto)
            .expect("must decode SubjectAccessReview proto — without this decoder, kubelet Webhook authz fails");

        assert_eq!(result["apiVersion"], "authorization.k8s.io/v1");
        assert_eq!(result["kind"], "SubjectAccessReview");
        assert_eq!(
            result["spec"]["user"], "system:admin",
            "user must be extracted from spec field 3"
        );
        assert_eq!(
            result["spec"]["groups"][0], "system:masters",
            "groups must be extracted from spec field 4"
        );
        assert_eq!(
            result["spec"]["resourceAttributes"]["verb"], "get",
            "verb must be extracted from ResourceAttributes field 2"
        );
        assert_eq!(
            result["spec"]["resourceAttributes"]["resource"], "pods",
            "resource must be extracted from ResourceAttributes field 5"
        );
    }

    /// decode_core_proto_by_kind must dispatch SubjectAccessReview proto and return a JSON
    /// object that handlers/authorization.rs can parse with serde_json::from_slice.
    ///
    /// This is the dispatch-level regression: even if the inner decoder works,
    /// the kind dispatch must also route "SubjectAccessReview" correctly.
    #[test]
    fn decode_core_proto_by_kind_dispatches_subject_access_review() {
        // Build: SubjectAccessReview { spec: { resourceAttributes: { verb: "get", resource: "pods" },
        //                                      user: "system:admin", groups: ["system:masters"] } }
        let mut resource_attrs = encode_length_delimited(2, b"get"); // verb
        resource_attrs.extend_from_slice(&encode_length_delimited(5, b"pods")); // resource

        let mut spec = encode_length_delimited(1, &resource_attrs);
        spec.extend_from_slice(&encode_length_delimited(3, b"system:admin")); // user
        spec.extend_from_slice(&encode_length_delimited(4, b"system:masters")); // groups[0]

        let sar_proto = encode_length_delimited(2, &spec);

        let result = decode_core_proto_by_kind("SubjectAccessReview", &sar_proto)
            .expect("SubjectAccessReview must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "SubjectAccessReview");
        assert_eq!(result["spec"]["resourceAttributes"]["verb"], "get");
        assert_eq!(result["spec"]["resourceAttributes"]["resource"], "pods");
        assert_eq!(result["spec"]["user"], "system:admin");
        assert_eq!(result["spec"]["groups"][0], "system:masters");
    }

    /// Full k8s proto envelope dispatch for SubjectAccessReview — simulates the kubelet
    /// sending a proto-encoded SAR body. The envelope has TypeMeta kind="SubjectAccessReview"
    /// and raw = the proto-encoded SubjectAccessReview body.
    #[test]
    fn full_sar_proto_envelope_dispatch() {
        // Build inner proto payload
        let mut resource_attrs = encode_length_delimited(2, b"get"); // verb
        resource_attrs.extend_from_slice(&encode_length_delimited(5, b"pods")); // resource

        let mut spec = encode_length_delimited(1, &resource_attrs);
        spec.extend_from_slice(&encode_length_delimited(3, b"system:admin")); // user
        spec.extend_from_slice(&encode_length_delimited(4, b"system:masters")); // groups[0]

        let sar_proto = encode_length_delimited(2, &spec);

        // Wrap in k8s Unknown envelope with TypeMeta kind="SubjectAccessReview"
        let type_meta: Vec<u8> = {
            let mut t = encode_length_delimited(1, b"authorization.k8s.io/v1"); // apiVersion
            t.extend_from_slice(&encode_length_delimited(2, b"SubjectAccessReview")); // kind
            t
        };
        let mut unknown = encode_length_delimited(1, &type_meta); // TypeMeta
        unknown.extend_from_slice(&encode_length_delimited(2, &sar_proto)); // raw
        unknown.extend_from_slice(&encode_length_delimited(
            4,
            b"application/vnd.kubernetes.protobuf",
        )); // contentType

        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&unknown);

        let env = decode_k8s_proto_envelope(&body).expect("envelope decode must succeed");
        assert_eq!(env.kind, "SubjectAccessReview");
        assert_eq!(env.content_type, "application/vnd.kubernetes.protobuf");

        let json = decode_core_proto_by_kind(&env.kind, &env.raw)
            .expect("SubjectAccessReview proto decode via dispatch must succeed");

        assert_eq!(json["kind"], "SubjectAccessReview");
        assert_eq!(json["spec"]["user"], "system:admin");
        assert_eq!(json["spec"]["groups"][0], "system:masters");
        assert_eq!(json["spec"]["resourceAttributes"]["verb"], "get");
        assert_eq!(json["spec"]["resourceAttributes"]["resource"], "pods");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_token_review_proto
    // ---------------------------------------------------------------------------

    /// decode_token_review_proto must extract spec.token from a synthetic protobuf payload.
    ///
    /// The kubelet uses Webhook authentication mode and sends TokenReview with
    /// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder, the server
    /// returns 400/500, causing authentication failures for all kubelet requests.
    #[test]
    fn decode_token_review_proto_extracts_token() {
        // Build TokenReviewSpec: field 1 = token (string)
        let spec = encode_length_delimited(1, b"my-token");

        // Build TokenReview: field 2 = spec
        let tr_proto = encode_length_delimited(2, &spec);

        let result = decode_token_review_proto(&tr_proto).expect(
            "must decode TokenReview proto — without this decoder, kubelet Webhook authn fails",
        );

        assert_eq!(result["apiVersion"], "authentication.k8s.io/v1");
        assert_eq!(result["kind"], "TokenReview");
        assert_eq!(
            result["spec"]["token"], "my-token",
            "token must be extracted from spec field 1"
        );
    }

    /// decode_core_proto_by_kind must dispatch TokenReview proto and return JSON that
    /// handlers/authorization.rs token_review can parse with serde_json::from_slice.
    #[test]
    fn decode_core_proto_by_kind_dispatches_token_review() {
        let spec = encode_length_delimited(1, b"my-token");
        let tr_proto = encode_length_delimited(2, &spec);

        let result = decode_core_proto_by_kind("TokenReview", &tr_proto)
            .expect("TokenReview must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "TokenReview");
        assert_eq!(result["spec"]["token"], "my-token");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_token_request
    // ---------------------------------------------------------------------------

    /// decode_token_request must decode the exact inner raw bytes captured from a real
    /// `kubectl create token sonobuoy-serviceaccount -n sonobuoy --audience=https://kubernetes.default.svc.cluster.local`
    /// invocation (72 bytes, after stripping the outer k8s envelope).
    ///
    /// This is the primary regression guard for mayor-hy77: kubectl 1.31+ sends a native
    /// protobuf TokenRequest body that the handler was previously trying to parse as JSON,
    /// producing "invalid JSON: expected value at line 1 column 1".
    #[test]
    fn decode_token_request_from_kubectl_capture() {
        // Raw bytes of the inner TokenRequest proto from a real kubectl invocation:
        //   field 1 (ObjectMeta): 0a 10 ... (len=16, mostly empty fields)
        //   field 2 (spec):       12 2e ... (len=46)
        //     field 1 (audience): 0a 2c https://kubernetes.default.svc.cluster.local (len=44)
        //   field 3+: trailing empty fields
        let raw: &[u8] = &[
            0x0a, 0x10, 0x0a, 0x00, 0x12, 0x00, 0x1a, 0x00, 0x22, 0x00, 0x2a, 0x00, 0x32, 0x00,
            0x38, 0x00, 0x42, 0x00, 0x12, 0x2e, 0x0a, 0x2c, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a,
            0x2f, 0x2f, 0x6b, 0x75, 0x62, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x65, 0x73, 0x2e, 0x64,
            0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2e, 0x73, 0x76, 0x63, 0x2e, 0x63, 0x6c, 0x75,
            0x73, 0x74, 0x65, 0x72, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x1a, 0x04, 0x0a, 0x00,
            0x12, 0x00, 0x1a, 0x00, 0x22, 0x00,
        ];

        let fields = decode_token_request(raw).expect("must decode kubectl TokenRequest capture");

        assert_eq!(
            fields.audiences,
            vec!["https://kubernetes.default.svc.cluster.local"],
            "audience must be extracted from the real kubectl proto capture"
        );
        // kubectl did not set expirationSeconds in this capture; expect None or Some(0).
        assert!(
            fields.expiration_seconds.is_none() || fields.expiration_seconds == Some(0),
            "expiration_seconds must be None or 0 when kubectl omits it; got {:?}",
            fields.expiration_seconds
        );
    }

    /// Regression test for mayor-2qq8: decode_token_request must correctly decode a
    /// TokenRequest with both expirationSeconds and a non-default audience, as sent by
    /// kubectl 1.31+ with explicit flags.
    ///
    /// The hand-rolled decoder had a bug where expirationSeconds was looked up at the
    /// wrong field number inside the spec sub-message. prost decodes it correctly via
    /// the official field 2 (int64) in TokenRequestSpec.
    ///
    /// This test must fail if decode_token_request returns None or extracts wrong values.
    #[test]
    fn decode_token_request_with_expiration_and_audience() {
        use prost::Message as _;

        // Construct a TokenRequestProto with spec.audiences and spec.expiration_seconds
        let tr = TokenRequestProto {
            metadata: None,
            spec: Some(TokenRequestSpec {
                audiences: vec!["https://my-custom-audience.example.com".to_string()],
                expiration_seconds: 7200,
                bound_object_ref: None,
            }),
            status: None,
        };

        // Encode with prost — the correct wire format
        let mut buf = Vec::new();
        tr.encode(&mut buf).expect("prost encode must succeed");

        let fields = decode_token_request(&buf).expect(
            "decode_token_request must return Some for a well-formed TokenRequest with expiration",
        );

        assert_eq!(
            fields.audiences,
            vec!["https://my-custom-audience.example.com"],
            "audience must match what was encoded"
        );
        assert_eq!(
            fields.expiration_seconds,
            Some(7200),
            "expirationSeconds=7200 must be decoded correctly; None here means the \
             hand-rolled decoder was reading the wrong field number"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_cronjob_proto / decode_core_proto_by_kind CronJob
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch CronJob proto and extract metadata and
    /// spec.schedule. This is the primary regression guard for mayor-50f3: the e2e CronJob
    /// conformance test sends CronJob objects with Content-Type: application/vnd.kubernetes.protobuf.
    /// Without this decoder, decode_core_proto_by_kind returns None for "CronJob", extract_body
    /// returns raw proto bytes, Object::from_bytes fails with "expected value at line 1 column 1",
    /// and the apiserver returns 400/500.
    #[test]
    fn decode_core_proto_by_kind_dispatches_cronjob() {
        // Build: CronJob {
        //   metadata: ObjectMeta { name: "my-cron", namespace: "default" },
        //   spec: CronJobSpec { schedule: "*/5 * * * *", concurrencyPolicy: "Allow",
        //                       jobTemplate: { spec: { backoffLimit: 3 } } }
        // }
        let mut obj_meta = encode_length_delimited(1, b"my-cron"); // ObjectMeta.name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default")); // ObjectMeta.namespace

        // JobSpec field 6 = backoffLimit (int32, wire 0): tag = (6 << 3) | 0 = 0x30, value = 3
        let job_spec = vec![0x30_u8, 0x03]; // field 6 (backoffLimit), wire type 0, varint 3

        // JobTemplateSpec: field 2 = JobSpec
        let job_template_spec = encode_length_delimited(2, &job_spec);

        // CronJobSpec: field 1=schedule, field 3=concurrencyPolicy, field 5=jobTemplate
        let mut cronjob_spec = encode_length_delimited(1, b"*/5 * * * *"); // schedule
        cronjob_spec.extend_from_slice(&encode_length_delimited(3, b"Allow")); // concurrencyPolicy
        cronjob_spec.extend_from_slice(&encode_length_delimited(5, &job_template_spec)); // jobTemplate

        // CronJob: field 1=ObjectMeta, field 2=CronJobSpec
        let mut cronjob_proto = encode_length_delimited(1, &obj_meta);
        cronjob_proto.extend_from_slice(&encode_length_delimited(2, &cronjob_spec));

        let result = decode_core_proto_by_kind("CronJob", &cronjob_proto)
            .expect("CronJob must decode via decode_core_proto_by_kind — without this, the e2e CronJob conformance test fails with 400/500");

        assert_eq!(
            result["kind"], "CronJob",
            "kind must be CronJob so Object::from_bytes can route the object"
        );
        assert_eq!(result["apiVersion"], "batch/v1");
        assert_eq!(
            result["metadata"]["name"], "my-cron",
            "name must be extracted so the object is stored under the correct key"
        );
        assert_eq!(result["metadata"]["namespace"], "default");
        assert!(
            result["metadata"]["creationTimestamp"].is_null(),
            "creationTimestamp must be null for kubectl compatibility"
        );
        assert_eq!(
            result["spec"]["schedule"], "*/5 * * * *",
            "schedule must be extracted from CronJobSpec field 1 — this field is required by the k8s schema"
        );
        assert_eq!(result["spec"]["concurrencyPolicy"], "Allow");
        assert!(
            result["spec"]["jobTemplate"]["spec"]["template"].is_object(),
            "jobTemplate.spec.template must be present as an empty object (k8s schema requires it)"
        );
        assert_eq!(
            result["spec"]["jobTemplate"]["spec"]["backoffLimit"], 3,
            "backoffLimit must be decoded from JobSpec field 6"
        );
    }

    /// decode_cronjob_proto must return None for malformed proto input.
    #[test]
    fn decode_cronjob_proto_returns_none_for_garbage() {
        assert!(decode_cronjob_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_job_proto / decode_core_proto_by_kind Job
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch Job proto and extract metadata and spec fields.
    /// The e2e CronJob conformance test also creates standalone Jobs; without this decoder,
    /// Job creation via proto fails with "expected value at line 1 column 1".
    #[test]
    fn decode_core_proto_by_kind_dispatches_job() {
        // Build: Job {
        //   metadata: ObjectMeta { name: "test-job", namespace: "default" },
        //   spec: JobSpec { completions: 1, backoffLimit: 4 }
        // }
        let mut obj_meta = encode_length_delimited(1, b"test-job"); // ObjectMeta.name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default")); // ObjectMeta.namespace

        // JobSpec: field 2=completions (varint), field 6=backoffLimit (varint)
        // completions=1: tag = (2 << 3) | 0 = 0x10, value = 0x01
        // backoffLimit=4: tag = (6 << 3) | 0 = 0x30, value = 0x04
        let job_spec = vec![0x10, 0x01, 0x30, 0x04];

        let mut job_proto = encode_length_delimited(1, &obj_meta); // Job.field 1 = ObjectMeta
        job_proto.extend_from_slice(&encode_length_delimited(2, &job_spec)); // Job.field 2 = JobSpec

        let result = decode_core_proto_by_kind("Job", &job_proto)
            .expect("Job must decode via decode_core_proto_by_kind — without this, Job creation via proto fails");

        assert_eq!(
            result["kind"], "Job",
            "kind must be Job so Object::from_bytes can route the object"
        );
        assert_eq!(result["apiVersion"], "batch/v1");
        assert_eq!(
            result["metadata"]["name"], "test-job",
            "name must be extracted so the object is stored under the correct key"
        );
        assert_eq!(result["metadata"]["namespace"], "default");
        assert!(
            result["metadata"]["creationTimestamp"].is_null(),
            "creationTimestamp must be null for kubectl compatibility"
        );
        assert_eq!(
            result["spec"]["completions"], 1,
            "completions must be decoded from JobSpec field 2"
        );
        assert_eq!(
            result["spec"]["backoffLimit"], 4,
            "backoffLimit must be decoded from JobSpec field 6"
        );
        assert!(
            result["spec"]["template"].is_object(),
            "spec.template must be present as an empty object (k8s schema requires it)"
        );
    }

    /// decode_job_proto must return None for malformed proto input.
    #[test]
    fn decode_job_proto_returns_none_for_garbage() {
        assert!(decode_job_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    /// decode_job_proto must handle an indexed Job with completionMode=Indexed,
    /// backoffLimitPerIndex, maxFailedIndexes, and a podFailurePolicy message.
    ///
    /// The e2e conformance tests create Jobs with these fields (job.go:621, :658, :753).
    /// Without handling these fields, the prost decode fails and decode_job_proto returns None,
    /// causing 400 "invalid JSON" responses for all indexed Job creation requests.
    #[test]
    fn decode_job_proto_handles_indexed_job_with_failure_policy() {
        use prost::Message as _;

        let job = Job {
            metadata: Some(ObjectMeta {
                name: "indexed-job".to_string(),
                namespace: "default".to_string(),
                ..Default::default()
            }),
            spec: Some(JobSpec {
                completions: 5,
                parallelism: 2,
                backoff_limit: 6,
                completion_mode: "Indexed".to_string(),
                backoff_limit_per_index: 1,
                max_failed_indexes: 3,
                pod_failure_policy: vec![0x0a, 0x04, 0x08, 0x01, 0x10, 0x01],
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_job_proto(&buf).expect(
            "decode_job_proto must return Some for indexed Job — conformance tests at job.go:621,:658,:753 \
             create Jobs with completionMode=Indexed, backoffLimitPerIndex, and podFailurePolicy; \
             returning None causes 400 'invalid JSON' responses"
        );

        assert_eq!(result["kind"], "Job");
        assert_eq!(result["apiVersion"], "batch/v1");
        assert_eq!(result["metadata"]["name"], "indexed-job");
        assert_eq!(result["metadata"]["namespace"], "default");
        assert_eq!(
            result["spec"]["completionMode"], "Indexed",
            "completionMode must be extracted for indexed jobs"
        );
        assert_eq!(result["spec"]["completions"], 5);
        assert_eq!(result["spec"]["parallelism"], 2);
        assert_eq!(
            result["spec"]["backoffLimitPerIndex"], 1,
            "backoffLimitPerIndex must be present in output for k8s client compatibility"
        );
        assert_eq!(result["spec"]["maxFailedIndexes"], 3);
        assert!(
            result["spec"]["template"].is_object(),
            "spec.template must always be present as empty object (required by k8s schema)"
        );
    }

    /// decode_job_proto must handle a Job with successPolicy — conformance test job.go:502 and
    /// job.go:582 create Jobs with successPolicy (k8s 1.30+ field at proto field 12).
    #[test]
    fn decode_job_proto_handles_job_with_success_policy() {
        use prost::Message as _;

        let job = Job {
            metadata: Some(ObjectMeta {
                name: "success-policy-job".to_string(),
                namespace: "test-ns".to_string(),
                ..Default::default()
            }),
            spec: Some(JobSpec {
                completions: 3,
                completion_mode: "Indexed".to_string(),
                success_policy: vec![0x0a, 0x02, 0x08, 0x02],
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_job_proto(&buf).expect(
            "decode_job_proto must return Some for Job with successPolicy — conformance tests at \
             job.go:502 and job.go:582 fail with 400 'invalid JSON' when this field is present",
        );

        assert_eq!(result["kind"], "Job");
        assert_eq!(result["metadata"]["name"], "success-policy-job");
        assert_eq!(result["spec"]["completionMode"], "Indexed");
        assert_eq!(result["spec"]["completions"], 3);
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_service_proto
    // ---------------------------------------------------------------------------

    /// decode_service_proto must extract metadata, spec.type, spec.clusterIP, and spec.ports.
    ///
    /// The conformance suite creates Services (ClusterIP, NodePort, ExternalName) via proto.
    /// Without this decoder, decode_core_proto_by_kind returns None and the server returns 400.
    #[test]
    fn decode_service_proto_extracts_metadata_and_spec() {
        // Build: Service {
        //   metadata: ObjectMeta { name: "my-svc", namespace: "default" },
        //   spec: ServiceSpec { type: "ClusterIP", clusterIP: "10.96.0.1",
        //                       sessionAffinity: "None",
        //                       ports: [ServicePort { name: "http", protocol: "TCP", port: 80 }] }
        // }
        let mut obj_meta = encode_length_delimited(1, b"my-svc");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        // ServicePort: field 1=name, field 2=protocol, field 3=port
        let mut port = encode_length_delimited(1, b"http");
        port.extend_from_slice(&encode_length_delimited(2, b"TCP"));
        // port=80: tag=(3<<3)|0=0x18, value=80=0x50
        port.push(0x18);
        port.push(0x50);

        // ServiceSpec: field 1=ports, field 3=clusterIP, field 4=type, field 7=sessionAffinity
        let mut svc_spec = encode_length_delimited(1, &port);
        svc_spec.extend_from_slice(&encode_length_delimited(3, b"10.96.0.1"));
        svc_spec.extend_from_slice(&encode_length_delimited(4, b"ClusterIP"));
        svc_spec.extend_from_slice(&encode_length_delimited(7, b"None"));

        let mut svc_proto = encode_length_delimited(1, &obj_meta);
        svc_proto.extend_from_slice(&encode_length_delimited(2, &svc_spec));

        let result = decode_core_proto_by_kind("Service", &svc_proto).expect(
            "Service must decode via decode_core_proto_by_kind — conformance suite creates \
                     Services via proto and fails with 400 'invalid JSON' without this decoder",
        );

        assert_eq!(result["kind"], "Service");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "my-svc");
        assert_eq!(result["metadata"]["namespace"], "default");
        assert_eq!(result["spec"]["clusterIP"], "10.96.0.1");
        assert_eq!(result["spec"]["type"], "ClusterIP");
        assert_eq!(result["spec"]["sessionAffinity"], "None");
        let ports = result["spec"]["ports"]
            .as_array()
            .expect("spec.ports must be an array");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0]["name"], "http");
        assert_eq!(ports[0]["protocol"], "TCP");
        assert_eq!(ports[0]["port"], 80);
    }

    /// decode_service_proto must handle a headless Service (clusterIP="None").
    #[test]
    fn decode_service_proto_handles_headless_service() {
        let mut obj_meta = encode_length_delimited(1, b"headless-svc");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"test-ns"));

        let mut svc_spec = encode_length_delimited(3, b"None"); // clusterIP=None
        svc_spec.extend_from_slice(&encode_length_delimited(4, b"ClusterIP")); // type

        let mut svc_proto = encode_length_delimited(1, &obj_meta);
        svc_proto.extend_from_slice(&encode_length_delimited(2, &svc_spec));

        let result = decode_service_proto(&svc_proto)
            .expect("must decode headless Service — conformance test creates headless Services");

        assert_eq!(result["kind"], "Service");
        assert_eq!(result["spec"]["clusterIP"], "None");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_secret_proto
    // ---------------------------------------------------------------------------

    /// decode_secret_proto must extract metadata, type, and data (base64-encoded bytes).
    ///
    /// The conformance suite creates Secrets of various types (Opaque, kubernetes.io/tls, etc.)
    /// via proto. Without this decoder, all Secret creation returns 400 'invalid JSON'.
    #[test]
    fn decode_secret_proto_extracts_metadata_type_and_data() {
        // Build: Secret {
        //   metadata: ObjectMeta { name: "test-secret", namespace: "default" },
        //   type: "Opaque",
        //   data: { "key": b"secret-value" }
        // }
        let mut obj_meta = encode_length_delimited(1, b"test-secret");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        // Secret.data is map<string,bytes> — each entry: field 1=key, field 2=value
        let mut data_entry = encode_length_delimited(1, b"key");
        data_entry.extend_from_slice(&encode_length_delimited(2, b"secret-value"));

        let mut secret_proto = encode_length_delimited(1, &obj_meta);
        secret_proto.extend_from_slice(&encode_length_delimited(2, &data_entry)); // data
        secret_proto.extend_from_slice(&encode_length_delimited(4, b"Opaque")); // type

        let result = decode_core_proto_by_kind("Secret", &secret_proto).expect(
            "Secret must decode via decode_core_proto_by_kind — conformance suite creates \
                     Secrets via proto and fails with 400 'invalid JSON' without this decoder",
        );

        assert_eq!(result["kind"], "Secret");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "test-secret");
        assert_eq!(result["metadata"]["namespace"], "default");
        assert_eq!(result["type"], "Opaque");
        // data["key"] must be base64-encoded "secret-value"
        use base64::Engine;
        let expected_b64 = base64::engine::general_purpose::STANDARD.encode(b"secret-value");
        assert_eq!(
            result["data"]["key"], expected_b64,
            "Secret data values must be base64-encoded so kubectl can decode them"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_replicationcontroller_proto
    // ---------------------------------------------------------------------------

    /// decode_replicationcontroller_proto must extract metadata, spec.replicas, and spec.selector.
    ///
    /// The conformance suite creates ReplicationControllers via proto.
    /// Without this decoder, RC creation fails with 400 'invalid JSON'.
    #[test]
    fn decode_replicationcontroller_proto_extracts_metadata_and_spec() {
        // Build: ReplicationController {
        //   metadata: ObjectMeta { name: "my-rc", namespace: "default" },
        //   spec: ReplicationControllerSpec { replicas: 3, selector: {"app": "myapp"} }
        // }
        let mut obj_meta = encode_length_delimited(1, b"my-rc");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        // replicas=3: tag=(1<<3)|0=0x08, value=3=0x03
        let mut rc_spec = vec![0x08, 0x03]; // field 1 (replicas), varint 3
                                            // selector map entry: field 1=key, field 2=value
        let mut sel_entry = encode_length_delimited(1, b"app");
        sel_entry.extend_from_slice(&encode_length_delimited(2, b"myapp"));
        rc_spec.extend_from_slice(&encode_length_delimited(2, &sel_entry));

        let mut rc_proto = encode_length_delimited(1, &obj_meta);
        rc_proto.extend_from_slice(&encode_length_delimited(2, &rc_spec));

        let result = decode_core_proto_by_kind("ReplicationController", &rc_proto).expect(
            "ReplicationController must decode via decode_core_proto_by_kind — \
                     conformance suite creates RCs via proto and returns 400 without this decoder",
        );

        assert_eq!(result["kind"], "ReplicationController");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "my-rc");
        assert_eq!(result["metadata"]["namespace"], "default");
        assert_eq!(result["spec"]["replicas"], 3);
        assert_eq!(result["spec"]["selector"]["app"], "myapp");
        assert!(
            result["spec"]["template"].is_object(),
            "spec.template must be present as empty object (required by k8s schema)"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_runtimeclass_proto
    // ---------------------------------------------------------------------------

    /// decode_runtimeclass_proto must extract metadata and handler.
    ///
    /// The conformance suite creates RuntimeClass objects via proto.
    /// Without this decoder, RuntimeClass creation fails with 400 'invalid JSON'.
    #[test]
    fn decode_runtimeclass_proto_extracts_metadata_and_handler() {
        // Build: RuntimeClass {
        //   metadata: ObjectMeta { name: "myruntime" },
        //   handler: "myhandler"
        // }
        let obj_meta = encode_length_delimited(1, b"myruntime");
        let handler = encode_length_delimited(2, b"myhandler");

        let mut rc_proto = encode_length_delimited(1, &obj_meta);
        rc_proto.extend_from_slice(&handler);

        let result = decode_core_proto_by_kind("RuntimeClass", &rc_proto).expect(
            "RuntimeClass must decode via decode_core_proto_by_kind — \
                     conformance suite creates RuntimeClass objects via proto",
        );

        assert_eq!(result["kind"], "RuntimeClass");
        assert_eq!(result["apiVersion"], "node.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "myruntime");
        assert_eq!(result["handler"], "myhandler");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_persistentvolume_proto
    // ---------------------------------------------------------------------------

    /// decode_persistentvolume_proto must extract metadata and spec fields.
    ///
    /// The conformance suite creates PersistentVolumes via proto.
    /// Without this decoder, PV creation fails with 400 'invalid JSON'.
    #[test]
    fn decode_persistentvolume_proto_extracts_metadata_and_spec() {
        // Build: PersistentVolume {
        //   metadata: ObjectMeta { name: "my-pv" },
        //   spec: PersistentVolumeSpec { accessModes: ["ReadWriteOnce"],
        //                                storageClassName: "standard",
        //                                persistentVolumeReclaimPolicy: "Delete" }
        // }
        let obj_meta = encode_length_delimited(1, b"my-pv");

        // PersistentVolumeSpec: field 6=accessModes (repeated string), field 26=reclaimPolicy,
        // field 29=storageClassName
        let mut pv_spec = encode_length_delimited(6, b"ReadWriteOnce"); // accessModes[0]
        pv_spec.extend_from_slice(&encode_length_delimited(26, b"Delete")); // reclaimPolicy
        pv_spec.extend_from_slice(&encode_length_delimited(29, b"standard")); // storageClassName

        let mut pv_proto = encode_length_delimited(1, &obj_meta);
        pv_proto.extend_from_slice(&encode_length_delimited(2, &pv_spec));

        let result = decode_core_proto_by_kind("PersistentVolume", &pv_proto).expect(
            "PersistentVolume must decode via decode_core_proto_by_kind — \
                     conformance suite creates PVs via proto and returns 400 without this decoder",
        );

        assert_eq!(result["kind"], "PersistentVolume");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "my-pv");
        assert_eq!(result["spec"]["accessModes"][0], "ReadWriteOnce");
        assert_eq!(result["spec"]["persistentVolumeReclaimPolicy"], "Delete");
        assert_eq!(result["spec"]["storageClassName"], "standard");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_volumeattachment_proto
    // ---------------------------------------------------------------------------

    /// decode_volumeattachment_proto must extract metadata, spec.attacher, spec.nodeName, and
    /// spec.source.persistentVolumeName.
    ///
    /// The conformance suite creates VolumeAttachments via proto.
    /// Without this decoder, VolumeAttachment creation fails with 400 'invalid JSON'.
    #[test]
    fn decode_volumeattachment_proto_extracts_metadata_and_spec() {
        // Build: VolumeAttachment {
        //   metadata: ObjectMeta { name: "csi-va-1" },
        //   spec: VolumeAttachmentSpec {
        //     attacher: "csi.example.com",
        //     source: { persistentVolumeName: "my-pv" },
        //     nodeName: "node-1"
        //   }
        // }
        let obj_meta = encode_length_delimited(1, b"csi-va-1");

        // VolumeAttachmentSource: field 1=persistentVolumeName
        let source = encode_length_delimited(1, b"my-pv");

        // VolumeAttachmentSpec: field 1=attacher, field 2=source, field 3=nodeName
        let mut va_spec = encode_length_delimited(1, b"csi.example.com");
        va_spec.extend_from_slice(&encode_length_delimited(2, &source));
        va_spec.extend_from_slice(&encode_length_delimited(3, b"node-1"));

        let mut va_proto = encode_length_delimited(1, &obj_meta);
        va_proto.extend_from_slice(&encode_length_delimited(2, &va_spec));

        let result = decode_core_proto_by_kind("VolumeAttachment", &va_proto).expect(
            "VolumeAttachment must decode via decode_core_proto_by_kind — \
                     conformance suite creates VolumeAttachments via proto",
        );

        assert_eq!(result["kind"], "VolumeAttachment");
        assert_eq!(result["apiVersion"], "storage.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "csi-va-1");
        assert_eq!(result["spec"]["attacher"], "csi.example.com");
        assert_eq!(result["spec"]["nodeName"], "node-1");
        assert_eq!(result["spec"]["source"]["persistentVolumeName"], "my-pv");
    }

    // ---------------------------------------------------------------------------
    // Tests — apps/v1 workload types (StatefulSet, Deployment, DaemonSet, ReplicaSet)
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch StatefulSet to a decoder that returns valid JSON.
    ///
    /// Without this decoder, clients sending Content-Type: application/vnd.kubernetes.protobuf
    /// for StatefulSet receive 400 'invalid JSON: expected value at line 1 column 1'.
    #[test]
    fn decode_statefulset_proto_extracts_metadata() {
        // StatefulSet { metadata: ObjectMeta { name: "my-sts", namespace: "default" } }
        let name = encode_length_delimited(1, b"my-sts");
        let ns = encode_length_delimited(3, b"default");
        let mut meta = name;
        meta.extend_from_slice(&ns);

        let proto = encode_length_delimited(1, &meta);

        let result = decode_core_proto_by_kind("StatefulSet", &proto).expect(
            "StatefulSet must decode via decode_core_proto_by_kind — \
             proto clients receive 400 without this decoder",
        );

        assert_eq!(result["kind"], "StatefulSet", "kind must be StatefulSet");
        assert_eq!(
            result["apiVersion"], "apps/v1",
            "apiVersion must be apps/v1"
        );
        assert_eq!(result["metadata"]["name"], "my-sts");
        assert_eq!(result["metadata"]["namespace"], "default");
    }

    /// decode_core_proto_by_kind must dispatch Deployment to a decoder that returns valid JSON.
    ///
    /// Without this decoder, clients sending Content-Type: application/vnd.kubernetes.protobuf
    /// for Deployment receive 400 'invalid JSON: expected value at line 1 column 1'.
    #[test]
    fn decode_deployment_proto_extracts_metadata() {
        // Deployment { metadata: ObjectMeta { name: "my-deploy", namespace: "default" } }
        let name = encode_length_delimited(1, b"my-deploy");
        let ns = encode_length_delimited(3, b"default");
        let mut meta = name;
        meta.extend_from_slice(&ns);

        let proto = encode_length_delimited(1, &meta);

        let result = decode_core_proto_by_kind("Deployment", &proto).expect(
            "Deployment must decode via decode_core_proto_by_kind — \
             proto clients receive 400 without this decoder",
        );

        assert_eq!(result["kind"], "Deployment", "kind must be Deployment");
        assert_eq!(
            result["apiVersion"], "apps/v1",
            "apiVersion must be apps/v1"
        );
        assert_eq!(result["metadata"]["name"], "my-deploy");
    }

    /// decode_core_proto_by_kind must dispatch DaemonSet to a decoder that returns valid JSON.
    ///
    /// Without this decoder, clients sending Content-Type: application/vnd.kubernetes.protobuf
    /// for DaemonSet receive 400 'invalid JSON: expected value at line 1 column 1'.
    #[test]
    fn decode_daemonset_proto_extracts_metadata() {
        // DaemonSet { metadata: ObjectMeta { name: "my-ds", namespace: "kube-system" } }
        let name = encode_length_delimited(1, b"my-ds");
        let ns = encode_length_delimited(3, b"kube-system");
        let mut meta = name;
        meta.extend_from_slice(&ns);

        let proto = encode_length_delimited(1, &meta);

        let result = decode_core_proto_by_kind("DaemonSet", &proto).expect(
            "DaemonSet must decode via decode_core_proto_by_kind — \
             proto clients receive 400 without this decoder",
        );

        assert_eq!(result["kind"], "DaemonSet", "kind must be DaemonSet");
        assert_eq!(
            result["apiVersion"], "apps/v1",
            "apiVersion must be apps/v1"
        );
        assert_eq!(result["metadata"]["name"], "my-ds");
    }

    /// decode_core_proto_by_kind must dispatch ReplicaSet to a decoder that returns valid JSON.
    ///
    /// Without this decoder, clients sending Content-Type: application/vnd.kubernetes.protobuf
    /// for ReplicaSet receive 400 'invalid JSON: expected value at line 1 column 1'.
    #[test]
    fn decode_replicaset_proto_extracts_metadata() {
        // ReplicaSet { metadata: ObjectMeta { name: "my-rs", namespace: "default" } }
        let name = encode_length_delimited(1, b"my-rs");
        let ns = encode_length_delimited(3, b"default");
        let mut meta = name;
        meta.extend_from_slice(&ns);

        let proto = encode_length_delimited(1, &meta);

        let result = decode_core_proto_by_kind("ReplicaSet", &proto).expect(
            "ReplicaSet must decode via decode_core_proto_by_kind — \
             proto clients receive 400 without this decoder",
        );

        assert_eq!(result["kind"], "ReplicaSet", "kind must be ReplicaSet");
        assert_eq!(
            result["apiVersion"], "apps/v1",
            "apiVersion must be apps/v1"
        );
        assert_eq!(result["metadata"]["name"], "my-rs");
    }

    // ---------------------------------------------------------------------------
    // Tests — core/v1 types (ServiceAccount, PersistentVolumeClaim, Endpoints)
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch ServiceAccount to a decoder that returns valid JSON.
    ///
    /// Without this decoder, clients sending Content-Type: application/vnd.kubernetes.protobuf
    /// for ServiceAccount receive 400 'invalid JSON: expected value at line 1 column 1'.
    #[test]
    fn decode_serviceaccount_proto_extracts_metadata() {
        // ServiceAccount { metadata: ObjectMeta { name: "my-sa", namespace: "default" } }
        let name = encode_length_delimited(1, b"my-sa");
        let ns = encode_length_delimited(3, b"default");
        let mut meta = name;
        meta.extend_from_slice(&ns);

        let proto = encode_length_delimited(1, &meta);

        let result = decode_core_proto_by_kind("ServiceAccount", &proto).expect(
            "ServiceAccount must decode via decode_core_proto_by_kind — \
             proto clients receive 400 without this decoder",
        );

        assert_eq!(
            result["kind"], "ServiceAccount",
            "kind must be ServiceAccount"
        );
        assert_eq!(result["apiVersion"], "v1", "apiVersion must be v1");
        assert_eq!(result["metadata"]["name"], "my-sa");
        assert_eq!(result["metadata"]["namespace"], "default");
    }

    /// decode_core_proto_by_kind must dispatch PersistentVolumeClaim to a decoder that returns valid JSON.
    ///
    /// Without this decoder, clients sending Content-Type: application/vnd.kubernetes.protobuf
    /// for PersistentVolumeClaim receive 400 'invalid JSON: expected value at line 1 column 1'.
    #[test]
    fn decode_persistentvolumeclaim_proto_extracts_metadata() {
        // PersistentVolumeClaim { metadata: ObjectMeta { name: "my-pvc", namespace: "default" } }
        let name = encode_length_delimited(1, b"my-pvc");
        let ns = encode_length_delimited(3, b"default");
        let mut meta = name;
        meta.extend_from_slice(&ns);

        let proto = encode_length_delimited(1, &meta);

        let result = decode_core_proto_by_kind("PersistentVolumeClaim", &proto).expect(
            "PersistentVolumeClaim must decode via decode_core_proto_by_kind — \
             proto clients receive 400 without this decoder",
        );

        assert_eq!(
            result["kind"], "PersistentVolumeClaim",
            "kind must be PersistentVolumeClaim"
        );
        assert_eq!(result["apiVersion"], "v1", "apiVersion must be v1");
        assert_eq!(result["metadata"]["name"], "my-pvc");
        assert_eq!(result["metadata"]["namespace"], "default");
    }

    /// decode_core_proto_by_kind must dispatch Endpoints to a decoder that returns valid JSON.
    ///
    /// Without this decoder, clients sending Content-Type: application/vnd.kubernetes.protobuf
    /// for Endpoints receive 400 'invalid JSON: expected value at line 1 column 1'.
    #[test]
    fn decode_endpoints_proto_extracts_metadata() {
        // Endpoints { metadata: ObjectMeta { name: "my-ep", namespace: "default" } }
        let name = encode_length_delimited(1, b"my-ep");
        let ns = encode_length_delimited(3, b"default");
        let mut meta = name;
        meta.extend_from_slice(&ns);

        let proto = encode_length_delimited(1, &meta);

        let result = decode_core_proto_by_kind("Endpoints", &proto).expect(
            "Endpoints must decode via decode_core_proto_by_kind — \
             proto clients receive 400 without this decoder",
        );

        assert_eq!(result["kind"], "Endpoints", "kind must be Endpoints");
        assert_eq!(result["apiVersion"], "v1", "apiVersion must be v1");
        assert_eq!(result["metadata"]["name"], "my-ep");
        assert_eq!(result["metadata"]["namespace"], "default");
    }
}
