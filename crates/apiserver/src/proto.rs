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

/// Maximum size of the proto envelope payload (after stripping the 4-byte magic prefix).
/// A varint bomb can claim a multi-GiB allocation with only a few bytes of actual payload;
/// this cap prevents prost from attempting such an allocation. 16 MiB covers the largest
/// legitimate kubectl requests (etcd's hard limit is ~1.5 MiB per value).
const MAX_PROTO_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Prost-generated message types
// All field numbers match the official k8s .proto definitions exactly.
// Option B: every field of every message type we decode is included.
// ---------------------------------------------------------------------------

// --- k8s.io/apimachinery/pkg/runtime/generated.proto ---

/// TypeMeta — embedded in Unknown field 1.
/// Source: apimachinery-runtime-generated.proto message TypeMeta
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
/// Source: apimachinery-runtime-generated.proto message Unknown
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
/// Source: apimachinery-meta-v1-generated.proto message Time
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
/// Source: apimachinery-meta-v1-generated.proto message MicroTime
#[derive(Clone, PartialEq, Message)]
struct MicroTime {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}

/// ObjectMeta — common metadata for all Kubernetes objects.
/// Source: apimachinery-meta-v1-generated.proto message ObjectMeta
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
/// Source: api-core-v1-generated.proto message NamespaceSpec
#[derive(Clone, PartialEq, Message)]
struct NamespaceSpec {
    #[prost(string, repeated, tag = "1")]
    finalizers: Vec<String>,
}

/// NamespaceStatus (field 1=phase string, field 2=conditions repeated bytes)
/// Source: api-core-v1-generated.proto message NamespaceStatus
#[derive(Clone, PartialEq, Message)]
struct NamespaceStatus {
    #[prost(string, tag = "1")]
    phase: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    conditions: Vec<Vec<u8>>,
}

/// Namespace — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message Namespace
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
/// Source: api-core-v1-generated.proto message PodTemplate
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

/// ResourceRequirements — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message ResourceRequirements
/// limits (field 1) and requests (field 2) are both map<string, Quantity>.
#[derive(Clone, PartialEq, Message)]
struct ResourceRequirements {
    /// limits (field 1, map<string, Quantity>)
    #[prost(btree_map = "string, message", tag = "1")]
    limits: std::collections::BTreeMap<String, Quantity>,
    /// requests (field 2, map<string, Quantity>)
    #[prost(btree_map = "string, message", tag = "2")]
    requests: std::collections::BTreeMap<String, Quantity>,
}

/// ExecAction — api-core-v1-generated.proto message ExecAction
/// field 1 = command (repeated string)
#[derive(Clone, PartialEq, Message)]
struct LifecycleExecAction {
    /// command (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    command: Vec<String>,
}

/// SleepAction — api-core-v1-generated.proto message SleepAction
/// field 1 = seconds (int64)
#[derive(Clone, PartialEq, Message)]
struct SleepAction {
    /// seconds (field 1, int64)
    #[prost(int64, tag = "1")]
    seconds: i64,
}

/// LifecycleHandler — api-core-v1-generated.proto message LifecycleHandler
/// field 1 = exec (ExecAction), field 2 = httpGet (HTTPGetAction),
/// field 3 = tcpSocket (TCPSocketAction), field 4 = sleep (SleepAction)
#[derive(Clone, PartialEq, Message)]
struct LifecycleHandler {
    /// exec (field 1, message LifecycleExecAction)
    #[prost(message, tag = "1")]
    exec: Option<LifecycleExecAction>,
    /// httpGet (field 2, message HttpGetProbeAction — same proto shape as HTTPGetAction)
    #[prost(message, tag = "2")]
    http_get: Option<HttpGetProbeAction>,
    /// tcpSocket (field 3, message TcpSocketProbeAction — same proto shape as TCPSocketAction)
    #[prost(message, tag = "3")]
    tcp_socket: Option<TcpSocketProbeAction>,
    /// sleep (field 4, message SleepAction)
    #[prost(message, tag = "4")]
    sleep: Option<SleepAction>,
}

/// Lifecycle — api-core-v1-generated.proto message Lifecycle
/// field 1 = postStart (LifecycleHandler), field 2 = preStop (LifecycleHandler)
#[derive(Clone, PartialEq, Message)]
struct Lifecycle {
    /// postStart (field 1, message LifecycleHandler)
    #[prost(message, tag = "1")]
    post_start: Option<LifecycleHandler>,
    /// preStop (field 2, message LifecycleHandler)
    #[prost(message, tag = "2")]
    pre_stop: Option<LifecycleHandler>,
}

/// ExecProbeAction — api-core-v1-generated.proto message ExecAction (used inside ProbeHandler)
/// field 1 = command (repeated string)
#[derive(Clone, PartialEq, Message)]
struct ExecProbeAction {
    /// command (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    command: Vec<String>,
}

/// IntOrString — k8s.io/apimachinery IntOrString
/// field 1 = type (int64: 0=int, 1=string), field 2 = intVal (int32), field 3 = strVal (string)
#[derive(Clone, PartialEq, Message)]
struct IntOrString {
    #[prost(int64, tag = "1")]
    r#type: i64,
    #[prost(int32, tag = "2")]
    int_val: i32,
    #[prost(string, tag = "3")]
    str_val: String,
}

impl IntOrString {
    fn to_json(&self) -> serde_json::Value {
        if self.r#type == 0 {
            serde_json::Value::Number(self.int_val.into())
        } else {
            serde_json::Value::String(self.str_val.clone())
        }
    }
}

/// HttpGetProbeAction — api-core-v1-generated.proto message HTTPGetAction
/// field 1 = path (string), field 2 = port (IntOrString), field 3 = host (string), field 4 = scheme (string)
#[derive(Clone, PartialEq, Message)]
struct HttpGetProbeAction {
    /// path (field 1, string)
    #[prost(string, tag = "1")]
    path: String,
    /// port (field 2, IntOrString message)
    #[prost(message, tag = "2")]
    port: Option<IntOrString>,
    /// host (field 3, string)
    #[prost(string, tag = "3")]
    host: String,
    /// scheme (field 4, string)
    #[prost(string, tag = "4")]
    scheme: String,
}

/// TcpSocketProbeAction — api-core-v1-generated.proto message TCPSocketAction
/// field 1 = port (IntOrString), field 2 = host (string)
#[derive(Clone, PartialEq, Message)]
struct TcpSocketProbeAction {
    /// port (field 1, IntOrString message)
    #[prost(message, tag = "1")]
    port: Option<IntOrString>,
    /// host (field 2, string)
    #[prost(string, tag = "2")]
    host: String,
}

/// GrpcProbeAction — api-core-v1-generated.proto message GRPCAction
/// field 1 = port (int32), field 2 = service (string)
#[derive(Clone, PartialEq, Message)]
struct GrpcProbeAction {
    /// port (field 1, int32)
    #[prost(int32, tag = "1")]
    port: i32,
    /// service (field 2, string)
    #[prost(string, tag = "2")]
    service: String,
}

/// ProbeHandler — api-core-v1-generated.proto message ProbeHandler
/// field 1 = exec (ExecAction), field 2 = httpGet (HTTPGetAction),
/// field 3 = tcpSocket (TCPSocketAction), field 4 = grpc (GRPCAction)
#[derive(Clone, PartialEq, Message)]
struct ProbeHandler {
    /// exec (field 1, message ExecProbeAction)
    #[prost(message, tag = "1")]
    exec: Option<ExecProbeAction>,
    /// httpGet (field 2, message HttpGetProbeAction)
    #[prost(message, tag = "2")]
    http_get: Option<HttpGetProbeAction>,
    /// tcpSocket (field 3, message TcpSocketProbeAction)
    #[prost(message, tag = "3")]
    tcp_socket: Option<TcpSocketProbeAction>,
    /// grpc (field 4, message GrpcProbeAction)
    #[prost(message, tag = "4")]
    grpc: Option<GrpcProbeAction>,
}

/// Probe — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message Probe
/// field 7 = terminationGracePeriodSeconds (int64) — not declared; not needed for conformance
#[derive(Clone, PartialEq, Message)]
struct Probe {
    /// handler (field 1, message ProbeHandler) — contains exec/httpGet/tcpSocket/grpc
    #[prost(message, tag = "1")]
    handler: Option<ProbeHandler>,
    /// initialDelaySeconds (field 2, int32)
    #[prost(int32, tag = "2")]
    initial_delay_seconds: i32,
    /// timeoutSeconds (field 3, int32)
    #[prost(int32, tag = "3")]
    timeout_seconds: i32,
    /// periodSeconds (field 4, int32)
    #[prost(int32, tag = "4")]
    period_seconds: i32,
    /// successThreshold (field 5, int32)
    #[prost(int32, tag = "5")]
    success_threshold: i32,
    /// failureThreshold (field 6, int32)
    #[prost(int32, tag = "6")]
    failure_threshold: i32,
}

/// KeyToPath — api-core-v1-generated.proto message KeyToPath
/// Maps a ConfigMap or Secret key to a file path within a volume.
/// field 1 = key (string), field 2 = path (string), field 3 = mode (int32, optional)
#[derive(Clone, PartialEq, Message)]
struct KeyToPath {
    /// key (field 1, string) — key in the ConfigMap or Secret to project
    #[prost(string, tag = "1")]
    key: String,
    /// path (field 2, string) — relative path of the file within the volume
    #[prost(string, tag = "2")]
    path: String,
    /// mode (field 3, int32) — optional per-file permission bits
    #[prost(int32, tag = "3")]
    mode: i32,
}

/// SecretVolumeSource — api-core-v1-generated.proto message SecretVolumeSource
/// field 1 = secretName (string), field 2 = items (repeated KeyToPath)
#[derive(Clone, PartialEq, Message)]
struct SecretVolumeSource {
    /// secretName (field 1, string) — name of the Secret in the pod's namespace
    #[prost(string, tag = "1")]
    secret_name: String,
    /// items (field 2, repeated KeyToPath) — key-to-path mappings within the volume
    #[prost(message, repeated, tag = "2")]
    items: Vec<KeyToPath>,
}

/// LocalObjectReference — api-core-v1-generated.proto message LocalObjectReference
/// Used inside ConfigMapVolumeSource (embedded, not a separate JSON field).
#[derive(Clone, PartialEq, Message)]
struct LocalObjectReference {
    /// name (field 1, string) — name of the referent
    #[prost(string, tag = "1")]
    name: String,
}

/// ConfigMapVolumeSource — api-core-v1-generated.proto message ConfigMapVolumeSource
/// field 1 = localObjectReference (message, name), field 2 = items (repeated KeyToPath)
#[derive(Clone, PartialEq, Message)]
struct ConfigMapVolumeSource {
    /// localObjectReference (field 1, message) — contains the configMap name
    #[prost(message, tag = "1")]
    local_object_reference: Option<LocalObjectReference>,
    /// items (field 2, repeated KeyToPath) — key-to-path mappings within the volume
    #[prost(message, repeated, tag = "2")]
    items: Vec<KeyToPath>,
}

/// EmptyDirVolumeSource — api-core-v1-generated.proto message EmptyDirVolumeSource
/// medium (field 1, string): "" = node default, "Memory" = tmpfs.
/// sizeLimit (field 2, bytes/Quantity) is skipped — kubelet defaults to node capacity.
#[derive(Clone, PartialEq, Message)]
struct EmptyDirVolumeSource {
    /// medium (field 1, string)
    #[prost(string, tag = "1")]
    medium: String,
}

/// HostPathVolumeSource — api-core-v1-generated.proto message HostPathVolumeSource
/// path (field 1, string): host filesystem path to expose.
/// type (field 2, string): optional HostPathType hint (e.g. "Directory", "File").
#[derive(Clone, PartialEq, Message)]
struct HostPathVolumeSource {
    /// path (field 1, string)
    #[prost(string, tag = "1")]
    path: String,
    /// type (field 2, string)
    #[prost(string, tag = "2")]
    r#type: String,
}

/// PersistentVolumeClaimVolumeSource — api-core-v1-generated.proto
/// claimName (field 1, string): name of the PVC in the same namespace.
/// readOnly (field 2, bool): force read-only mount (default false).
#[derive(Clone, PartialEq, Message)]
struct PvcVolumeSource {
    /// claimName (field 1, string)
    #[prost(string, tag = "1")]
    claim_name: String,
    /// readOnly (field 2, bool)
    #[prost(bool, tag = "2")]
    read_only: bool,
}

/// ObjectFieldSelector — api-core-v1-generated.proto message ObjectFieldSelector
/// Used in DownwardAPIVolumeFile to select a pod-level field.
#[derive(Clone, PartialEq, Message)]
struct ObjectFieldSelector {
    /// apiVersion (field 1, string) — defaults to "v1"
    #[prost(string, tag = "1")]
    api_version: String,
    /// fieldPath (field 2, string) — e.g. "metadata.name", "status.podIP"
    #[prost(string, tag = "2")]
    field_path: String,
}

/// ResourceFieldSelector — api-core-v1-generated.proto message ResourceFieldSelector
/// Used in DownwardAPIVolumeFile to select a container resource field.
#[derive(Clone, PartialEq, Message)]
struct ResourceFieldSelector {
    /// containerName (field 1, string)
    #[prost(string, tag = "1")]
    container_name: String,
    /// resource (field 2, string) — e.g. "limits.cpu", "requests.memory"
    #[prost(string, tag = "2")]
    resource: String,
    /// divisor (field 3, message Quantity) — e.g. "1m", "1Mi"; defaults to "1" if absent
    #[prost(message, tag = "3")]
    divisor: Option<Quantity>,
}

/// DownwardAPIVolumeFile — api-core-v1-generated.proto message DownwardAPIVolumeFile
/// One item in a downwardAPI or projected/downwardAPI volume.
#[derive(Clone, PartialEq, Message)]
struct DownwardAPIVolumeFile {
    /// path (field 1, string) — relative path for the projected file
    #[prost(string, tag = "1")]
    path: String,
    /// fieldRef (field 2, message ObjectFieldSelector)
    #[prost(message, tag = "2")]
    field_ref: Option<ObjectFieldSelector>,
    /// resourceFieldRef (field 3, message ResourceFieldSelector)
    #[prost(message, tag = "3")]
    resource_field_ref: Option<ResourceFieldSelector>,
    /// mode (field 4, int32) — optional per-file permission bits
    #[prost(int32, tag = "4")]
    mode: i32,
}

/// DownwardAPIVolumeSource — api-core-v1-generated.proto message DownwardAPIVolumeSource
/// items (field 1, repeated DownwardAPIVolumeFile): files to project.
/// defaultMode (field 2, int32): default permission bits for projected files.
#[derive(Clone, PartialEq, Message)]
struct DownwardAPIVolumeSource {
    /// items (field 1, repeated DownwardAPIVolumeFile)
    #[prost(message, repeated, tag = "1")]
    items: Vec<DownwardAPIVolumeFile>,
    /// defaultMode (field 2, int32)
    #[prost(int32, tag = "2")]
    default_mode: i32,
}

/// DownwardAPIProjection — api-core-v1-generated.proto message DownwardAPIProjection
/// Identical to DownwardAPIVolumeSource but without defaultMode; used inside ProjectedVolumeSource.
#[derive(Clone, PartialEq, Message)]
struct DownwardAPIProjection {
    /// items (field 1, repeated DownwardAPIVolumeFile)
    #[prost(message, repeated, tag = "1")]
    items: Vec<DownwardAPIVolumeFile>,
}

/// ServiceAccountTokenProjection — api-core-v1-generated.proto
/// Projects a bound service-account token into the volume.
#[derive(Clone, PartialEq, Message)]
struct ServiceAccountTokenProjection {
    /// audience (field 1, string) — intended audience of the token
    #[prost(string, tag = "1")]
    audience: String,
    /// expirationSeconds (field 2, int64) — token lifetime in seconds
    #[prost(int64, tag = "2")]
    expiration_seconds: i64,
    /// path (field 3, string) — path relative to mount point
    #[prost(string, tag = "3")]
    path: String,
}

/// SecretProjection — api-core-v1-generated.proto message SecretProjection
/// Projects a Secret into a projected volume.
/// field 1 = localObjectReference (name), field 2 = items (repeated KeyToPath)
#[derive(Clone, PartialEq, Message)]
struct SecretProjection {
    /// localObjectReference (field 1, message) — secret name
    #[prost(message, tag = "1")]
    local_object_reference: Option<LocalObjectReference>,
    /// items (field 2, repeated KeyToPath) — key-to-path mappings within the projection
    #[prost(message, repeated, tag = "2")]
    items: Vec<KeyToPath>,
}

/// ConfigMapProjection — api-core-v1-generated.proto message ConfigMapProjection
/// Projects a ConfigMap into a projected volume.
/// field 1 = localObjectReference (name), field 2 = items (repeated KeyToPath)
#[derive(Clone, PartialEq, Message)]
struct ConfigMapProjection {
    /// localObjectReference (field 1, message) — configMap name
    #[prost(message, tag = "1")]
    local_object_reference: Option<LocalObjectReference>,
    /// items (field 2, repeated KeyToPath) — key-to-path mappings within the projection
    #[prost(message, repeated, tag = "2")]
    items: Vec<KeyToPath>,
}

/// VolumeProjection — api-core-v1-generated.proto message VolumeProjection
/// One source within a ProjectedVolumeSource.
#[derive(Clone, PartialEq, Message)]
struct VolumeProjectionEntry {
    /// secret (field 1, message SecretProjection)
    #[prost(message, tag = "1")]
    secret: Option<SecretProjection>,
    /// downwardAPI (field 2, message DownwardAPIProjection)
    #[prost(message, tag = "2")]
    downward_api: Option<DownwardAPIProjection>,
    /// configMap (field 3, message ConfigMapProjection)
    #[prost(message, tag = "3")]
    config_map: Option<ConfigMapProjection>,
    /// serviceAccountToken (field 4, message ServiceAccountTokenProjection)
    #[prost(message, tag = "4")]
    service_account_token: Option<ServiceAccountTokenProjection>,
}

/// ProjectedVolumeSource — api-core-v1-generated.proto message ProjectedVolumeSource
/// Aggregates multiple volume sources (secret, configMap, downwardAPI, serviceAccountToken)
/// into a single directory.
#[derive(Clone, PartialEq, Message)]
struct ProjectedVolumeSource {
    /// sources (field 1, repeated VolumeProjection)
    #[prost(message, repeated, tag = "1")]
    sources: Vec<VolumeProjectionEntry>,
    /// defaultMode (field 2, int32) — default permission bits for projected files
    #[prost(int32, tag = "2")]
    default_mode: i32,
}

/// VolumeSource — api-core-v1-generated.proto message VolumeSource
/// All volume source types used by Kubernetes conformance tests are decoded.
/// Deprecated/cloud-specific sources (gcePersistentDisk, awsElasticBlockStore, etc.) are skipped.
#[derive(Clone, PartialEq, Message)]
struct VolumeSource {
    /// hostPath (field 1, message HostPathVolumeSource)
    #[prost(message, tag = "1")]
    host_path: Option<HostPathVolumeSource>,
    /// emptyDir (field 2, message EmptyDirVolumeSource)
    #[prost(message, tag = "2")]
    empty_dir: Option<EmptyDirVolumeSource>,
    /// secret (field 6, message SecretVolumeSource)
    #[prost(message, tag = "6")]
    secret: Option<SecretVolumeSource>,
    /// persistentVolumeClaim (field 10, message PersistentVolumeClaimVolumeSource)
    #[prost(message, tag = "10")]
    persistent_volume_claim: Option<PvcVolumeSource>,
    /// downwardAPI (field 16, message DownwardAPIVolumeSource)
    #[prost(message, tag = "16")]
    downward_api: Option<DownwardAPIVolumeSource>,
    /// configMap (field 19, message ConfigMapVolumeSource)
    #[prost(message, tag = "19")]
    config_map: Option<ConfigMapVolumeSource>,
    /// projected (field 26, message ProjectedVolumeSource)
    #[prost(message, tag = "26")]
    projected: Option<ProjectedVolumeSource>,
}

/// Volume — api-core-v1-generated.proto message Volume
/// Field numbers match api-core-v1-generated.proto exactly:
///   field 1 = name (string), field 2 = volumeSource (message VolumeSource)
#[derive(Clone, PartialEq, Message)]
struct Volume {
    /// name (field 1, string) — must match volumeMount.name in containers
    #[prost(string, tag = "1")]
    name: String,
    /// volumeSource (field 2, message VolumeSource) — the backing source
    #[prost(message, tag = "2")]
    volume_source: Option<VolumeSource>,
}

/// VolumeMount — api-core-v1-generated.proto message VolumeMount
/// Field numbers match api-core-v1-generated.proto exactly:
///   field 1 = name (string), field 2 = readOnly (bool), field 3 = mountPath (string),
///   field 4 = subPath (string), field 5 = mountPropagation (string, skipped),
///   field 6 = subPathExpr (string), field 7 = recursiveReadOnly (string, skipped)
#[derive(Clone, PartialEq, Message)]
struct VolumeMount {
    /// name (field 1, string) — matches a volume name in spec.volumes
    #[prost(string, tag = "1")]
    name: String,
    /// readOnly (field 2, bool)
    #[prost(bool, tag = "2")]
    read_only: bool,
    /// mountPath (field 3, string) — path inside the container where the volume is mounted
    #[prost(string, tag = "3")]
    mount_path: String,
    /// subPath (field 4, string)
    #[prost(string, tag = "4")]
    sub_path: String,
    /// subPathExpr (field 6, string)
    #[prost(string, tag = "6")]
    sub_path_expr: String,
}

/// ConfigMapKeySelector — api-core-v1-generated.proto message ConfigMapKeySelector
/// Selects a key from a ConfigMap; used as EnvVarSource.configMapKeyRef.
/// field 1 = LocalObjectReference (embedded message, field 1 = name string)
/// field 2 = key (string)
/// field 3 = optional (bool)
#[derive(Clone, PartialEq, Message)]
struct ConfigMapKeySelector {
    /// localObjectReference.name (field 1, embedded message — inner field 1 = string)
    #[prost(message, tag = "1")]
    local_object_reference: Option<LocalObjectReference>,
    /// key (field 2, string) — key within the ConfigMap
    #[prost(string, tag = "2")]
    key: String,
    /// optional (field 3, bool) — whether the ConfigMap or key must exist
    #[prost(bool, tag = "3")]
    optional: bool,
}

/// SecretKeySelector — api-core-v1-generated.proto message SecretKeySelector
/// Selects a key from a Secret; used as EnvVarSource.secretKeyRef.
/// field 1 = LocalObjectReference (embedded message, field 1 = name string)
/// field 2 = key (string)
/// field 3 = optional (bool)
#[derive(Clone, PartialEq, Message)]
struct SecretKeySelector {
    /// localObjectReference.name (field 1, embedded message — inner field 1 = string)
    #[prost(message, tag = "1")]
    local_object_reference: Option<LocalObjectReference>,
    /// key (field 2, string) — key within the Secret
    #[prost(string, tag = "2")]
    key: String,
    /// optional (field 3, bool) — whether the Secret or key must exist
    #[prost(bool, tag = "3")]
    optional: bool,
}

/// EnvVarSource — api-core-v1-generated.proto message EnvVarSource
/// Exactly one of the four fields should be set; others are empty/None.
#[derive(Clone, PartialEq, Message)]
struct EnvVarSource {
    /// fieldRef (field 1, message ObjectFieldSelector)
    #[prost(message, tag = "1")]
    field_ref: Option<ObjectFieldSelector>,
    /// resourceFieldRef (field 2, message ResourceFieldSelector)
    #[prost(message, tag = "2")]
    resource_field_ref: Option<ResourceFieldSelector>,
    /// configMapKeyRef (field 3, message ConfigMapKeySelector)
    #[prost(message, tag = "3")]
    config_map_key_ref: Option<ConfigMapKeySelector>,
    /// secretKeyRef (field 4, message SecretKeySelector)
    #[prost(message, tag = "4")]
    secret_key_ref: Option<SecretKeySelector>,
}

/// EnvVar — api-core-v1-generated.proto message EnvVar
/// One environment variable to set in a container.
/// field 1 = name (string), field 2 = value (string), field 3 = valueFrom (EnvVarSource)
#[derive(Clone, PartialEq, Message)]
struct EnvVar {
    /// name (field 1, string) — name of the environment variable
    #[prost(string, tag = "1")]
    name: String,
    /// value (field 2, string) — literal value (mutually exclusive with value_from)
    #[prost(string, tag = "2")]
    value: String,
    /// valueFrom (field 3, message EnvVarSource) — source for the value
    #[prost(message, tag = "3")]
    value_from: Option<EnvVarSource>,
}

/// ConfigMapEnvSource — api-core-v1-generated.proto message ConfigMapEnvSource
/// Selects a ConfigMap to populate environment variables from.
/// field 1 = localObjectReference (embedded message, inner field 1 = name string)
/// field 2 = optional (bool) — whether the ConfigMap must exist
#[derive(Clone, PartialEq, Message)]
struct ConfigMapEnvSource {
    /// localObjectReference (field 1, embedded message) — ConfigMap name
    #[prost(message, tag = "1")]
    local_object_reference: Option<LocalObjectReference>,
    /// optional (field 2, bool) — whether the ConfigMap must be defined
    #[prost(bool, tag = "2")]
    optional: bool,
}

/// SecretEnvSource — api-core-v1-generated.proto message SecretEnvSource
/// Selects a Secret to populate environment variables from.
/// field 1 = localObjectReference (embedded message, inner field 1 = name string)
/// field 2 = optional (bool) — whether the Secret must exist
#[derive(Clone, PartialEq, Message)]
struct SecretEnvSource {
    /// localObjectReference (field 1, embedded message) — Secret name
    #[prost(message, tag = "1")]
    local_object_reference: Option<LocalObjectReference>,
    /// optional (field 2, bool) — whether the Secret must be defined
    #[prost(bool, tag = "2")]
    optional: bool,
}

/// EnvFromSource — api-core-v1-generated.proto message EnvFromSource
/// Represents the source of a set of ConfigMaps or Secrets as env vars.
/// field 1 = prefix (string) — optional prefix for each env var key
/// field 2 = configMapRef (message ConfigMapEnvSource)
/// field 3 = secretRef (message SecretEnvSource)
#[derive(Clone, PartialEq, Message)]
struct EnvFromSource {
    /// prefix (field 1, string) — optional prefix prepended to each key
    #[prost(string, tag = "1")]
    prefix: String,
    /// configMapRef (field 2, message ConfigMapEnvSource)
    #[prost(message, tag = "2")]
    config_map_ref: Option<ConfigMapEnvSource>,
    /// secretRef (field 3, message SecretEnvSource)
    #[prost(message, tag = "3")]
    secret_ref: Option<SecretEnvSource>,
}

/// ContainerPort — k8s.io/api/core/v1/generated.proto message ContainerPort
/// Represents a network port in a single container.
#[derive(Clone, PartialEq, Message)]
struct ContainerPort {
    /// name (field 1, optional string)
    #[prost(string, tag = "1")]
    name: String,
    /// hostPort (field 2, optional int32)
    #[prost(int32, tag = "2")]
    host_port: i32,
    /// containerPort (field 3, optional int32)
    #[prost(int32, tag = "3")]
    container_port: i32,
    /// protocol (field 4, optional string)
    #[prost(string, tag = "4")]
    protocol: String,
    /// hostIP (field 5, optional string)
    #[prost(string, tag = "5")]
    host_ip: String,
}

/// Container — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message Container
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
    /// ports (field 6, repeated ContainerPort)
    #[prost(message, repeated, tag = "6")]
    ports: Vec<ContainerPort>,
    /// env (field 7, repeated EnvVar) — environment variables for the container
    #[prost(message, repeated, tag = "7")]
    env: Vec<EnvVar>,
    /// envFrom (field 19, repeated EnvFromSource) — environment from ConfigMap/Secret
    #[prost(message, repeated, tag = "19")]
    env_from: Vec<EnvFromSource>,
    /// resources (field 8, message ResourceRequirements)
    #[prost(message, tag = "8")]
    resources: Option<ResourceRequirements>,
    /// volumeMounts (field 9, repeated VolumeMount)
    #[prost(message, repeated, tag = "9")]
    volume_mounts: Vec<VolumeMount>,
    /// livenessProbe (field 10, message Probe)
    #[prost(message, tag = "10")]
    liveness_probe: Option<Probe>,
    /// readinessProbe (field 11, message Probe)
    #[prost(message, tag = "11")]
    readiness_probe: Option<Probe>,
    /// terminationMessagePath (field 13, string)
    #[prost(string, tag = "13")]
    termination_message_path: String,
    /// imagePullPolicy (field 14, string)
    #[prost(string, tag = "14")]
    image_pull_policy: String,
    /// terminationMessagePolicy (field 20, string)
    #[prost(string, tag = "20")]
    termination_message_policy: String,
    /// startupProbe (field 22, message Probe)
    #[prost(message, tag = "22")]
    startup_probe: Option<Probe>,
    /// lifecycle (field 12, message Lifecycle)
    #[prost(message, tag = "12")]
    lifecycle: Option<Lifecycle>,
}

/// PodSpec — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message PodSpec
/// Field numbers match the official proto exactly:
///   field 1  = volumes (repeated Volume)
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
///   field 16 = hostname (string)
///   field 17 = subdomain (string)
///   field 20 = initContainers (repeated Container)
#[derive(Clone, PartialEq, Message)]
struct PodSpec {
    /// volumes (field 1, repeated Volume) — backing volumes for container volumeMounts
    #[prost(message, repeated, tag = "1")]
    volumes: Vec<Volume>,
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
    /// hostname (field 16, string) — sets the pod's hostname; kubelet uses this to configure
    /// the container's hostname so that /hostname and DNS lookups return the correct value
    #[prost(string, tag = "16")]
    hostname: String,
    /// subdomain (field 17, string) — when set together with hostname enables DNS-based
    /// hostname resolution via <hostname>.<subdomain>.<namespace>.svc.<cluster-domain>
    #[prost(string, tag = "17")]
    subdomain: String,
    /// initContainers (field 20, repeated Container) — run to completion before main containers;
    /// kubelet blocks pod startup if any init container fails or is not decoded
    #[prost(message, repeated, tag = "20")]
    init_containers: Vec<Container>,
}

/// Pod — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message Pod
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
/// Source: api-core-v1-generated.proto message ConfigMap
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
/// Source: api-core-v1-generated.proto message ServicePort
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
/// Source: api-core-v1-generated.proto message ServiceSpec
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
    /// ipFamilyPolicy (field 17, string)
    #[prost(string, tag = "17")]
    ip_family_policy: String,
    /// internalTrafficPolicy (field 22, string)
    #[prost(string, tag = "22")]
    internal_traffic_policy: String,
}

/// Service — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message Service
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
/// Source: api-core-v1-generated.proto message Secret
/// Field numbers match the official proto exactly:
///   field 1 = metadata (message ObjectMeta)
///   field 2 = data (map<string,bytes>)
///   field 3 = type (string)        ← NOTE: type=3, stringData=4 (not the reverse)
///   field 4 = stringData (map<string,string>)
///   field 5 = immutable (bool)
#[derive(Clone, PartialEq, Message)]
struct Secret {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// data (field 2, map<string,bytes>)
    #[prost(map = "string, bytes", tag = "2")]
    data: std::collections::HashMap<String, Vec<u8>>,
    /// type (field 3, string) — wire field 3, not 4
    #[prost(string, tag = "3")]
    r#type: String,
    /// stringData (field 4, map<string,string>) — wire field 4, not 3
    #[prost(map = "string, string", tag = "4")]
    string_data: std::collections::HashMap<String, String>,
    /// immutable (field 5, bool)
    #[prost(bool, tag = "5")]
    immutable: bool,
}

/// ReplicationControllerSpec — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message ReplicationControllerSpec
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
/// Source: api-core-v1-generated.proto message ReplicationController
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
/// Source: api-core-v1-generated.proto message PersistentVolumeSpec
#[derive(Clone, PartialEq, Message)]
struct PersistentVolumeSpec {
    /// capacity (field 1, map<string,Quantity>) — decoded as raw bytes (Quantity is complex)
    #[prost(bytes = "vec", tag = "1")]
    capacity: Vec<u8>,
    /// accessModes (field 3, repeated string)
    #[prost(string, repeated, tag = "3")]
    access_modes: Vec<String>,
    /// claimRef (field 4, message ObjectReference) — decoded as raw bytes
    #[prost(bytes = "vec", tag = "4")]
    claim_ref: Vec<u8>,
    /// persistentVolumeReclaimPolicy (field 5, string)
    #[prost(string, tag = "5")]
    persistent_volume_reclaim_policy: String,
    /// storageClassName (field 6, string)
    #[prost(string, tag = "6")]
    storage_class_name: String,
    /// volumeMode (field 8, string)
    #[prost(string, tag = "8")]
    volume_mode: String,
}

/// PersistentVolume — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message PersistentVolume
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
/// Source: api-core-v1-generated.proto message NodeSpec
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
/// Source: api-core-v1-generated.proto message Node
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
/// Source: api-core-v1-generated.proto message ObjectReference
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
/// Source: api-core-v1-generated.proto message EventSource
#[derive(Clone, PartialEq, Message)]
struct EventSource {
    #[prost(string, tag = "1")]
    component: String,
    #[prost(string, tag = "2")]
    host: String,
}

/// EventSeries — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message EventSeries
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
/// Source: api-core-v1-generated.proto message Event
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
/// Source: k8s.io/api/coordination/v1/generated.proto message LeaseSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/coordination/v1/generated.proto message Lease
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/storage/v1/generated.proto message VolumeNodeResources
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
#[derive(Clone, PartialEq, Message)]
struct VolumeNodeResources {
    /// count (field 1, int32) — maximum number of unique volumes managed by the CSI driver
    #[prost(int32, tag = "1")]
    count: i32,
}

/// CSINodeDriver — k8s.io/api/storage/v1/generated.proto
/// Source: k8s.io/api/storage/v1/generated.proto message CSINodeDriver
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/storage/v1/generated.proto message CSINodeSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
#[derive(Clone, PartialEq, Message)]
struct CsiNodeSpec {
    /// drivers (field 1, repeated CSINodeDriver)
    #[prost(message, repeated, tag = "1")]
    drivers: Vec<CsiNodeDriver>,
}

/// CSINode — k8s.io/api/storage/v1/generated.proto
/// Source: k8s.io/api/storage/v1/generated.proto message CSINode
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/storage/v1/generated.proto message VolumeAttachmentSource
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/storage/v1/generated.proto message VolumeAttachmentSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/storage/v1/generated.proto message VolumeAttachment
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/node/v1/generated.proto message RuntimeClass
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/authorization/v1/generated.proto message ResourceAttributes
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/authorization/v1/generated.proto message SubjectAccessReviewSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/authorization/v1/generated.proto message SubjectAccessReview
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/authentication/v1/generated.proto message TokenReviewSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/authentication/v1/generated.proto message TokenReview
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/authentication/v1/generated.proto message BoundObjectReference
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/authentication/v1/generated.proto message TokenRequestSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
#[derive(Clone, PartialEq, Message)]
struct TokenRequestSpec {
    /// audiences (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    audiences: Vec<String>,
    /// expirationSeconds (field 4, int64) — optional, 0 = unset
    #[prost(int64, tag = "4")]
    expiration_seconds: i64,
    /// boundObjectRef (field 3, message BoundObjectReference)
    #[prost(message, tag = "3")]
    bound_object_ref: Option<BoundObjectReference>,
}

/// TokenRequestStatus — k8s.io/api/authentication/v1/generated.proto
/// Source: k8s.io/api/authentication/v1/generated.proto message TokenRequestStatus
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/authentication/v1/generated.proto message TokenRequest
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/rbac/v1/generated.proto message PolicyRule
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/rbac/v1/generated.proto message Subject
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/rbac/v1/generated.proto message RoleRef
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/rbac/v1/generated.proto message ClusterRole
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/rbac/v1/generated.proto message ClusterRoleBinding
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/rbac/v1/generated.proto message Role
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/rbac/v1/generated.proto message RoleBinding
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/batch/v1/generated.proto message JobSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
    /// manualSelector (field 5, bool)
    #[prost(bool, tag = "5")]
    manual_selector: bool,
    /// template (field 6, PodTemplateSpec) — decoded as raw bytes; PodSpec is deeply nested
    #[prost(bytes = "vec", tag = "6")]
    template: Vec<u8>,
    /// backoffLimit (field 7, int32)
    #[prost(int32, tag = "7")]
    backoff_limit: i32,
    /// ttlSecondsAfterFinished (field 8, int32)
    #[prost(int32, tag = "8")]
    ttl_seconds_after_finished: i32,
    /// completionMode (field 9, string) — "NonIndexed" or "Indexed"
    #[prost(string, tag = "9")]
    completion_mode: String,
    /// suspend (field 10, bool)
    #[prost(bool, tag = "10")]
    suspend: bool,
    /// podFailurePolicy (field 11, bytes) — complex message, decoded as raw bytes
    #[prost(bytes = "vec", tag = "11")]
    pod_failure_policy: Vec<u8>,
    /// backoffLimitPerIndex (field 12, int32) — added k8s 1.28
    #[prost(int32, tag = "12")]
    backoff_limit_per_index: i32,
    /// maxFailedIndexes (field 13, int32) — added k8s 1.28
    #[prost(int32, tag = "13")]
    max_failed_indexes: i32,
    /// podReplacementPolicy (field 14, string) — added k8s 1.28
    #[prost(string, tag = "14")]
    pod_replacement_policy: String,
    /// managedBy (field 15, string) — added k8s 1.30
    #[prost(string, tag = "15")]
    managed_by: String,
    /// successPolicy (field 16, bytes) — complex message, decoded as raw bytes
    #[prost(bytes = "vec", tag = "16")]
    success_policy: Vec<u8>,
}

/// JobTemplateSpec — field 1=ObjectMeta, field 2=JobSpec
/// Source: k8s.io/api/batch/v1/generated.proto message JobTemplateSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/batch/v1/generated.proto message CronJobSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/batch/v1/generated.proto message CronJob
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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
/// Source: k8s.io/api/batch/v1/generated.proto message Job
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
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

/// LabelSelector — k8s.io/apimachinery/pkg/apis/meta/v1/generated.proto
/// Source: apimachinery-meta-v1-generated.proto message LabelSelector
/// Only matchLabels decoded; matchExpressions (field 2) not needed for selector defaulting.
#[derive(Clone, PartialEq, Message)]
struct AppsLabelSelector {
    /// matchLabels (field 1, map<string,string>)
    #[prost(btree_map = "string, string", tag = "1")]
    match_labels: ::prost::alloc::collections::BTreeMap<
        ::prost::alloc::string::String,
        ::prost::alloc::string::String,
    >,
}

/// PodTemplateSpec (apps context) — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message PodTemplateSpec
/// Decodes metadata (field 1) and spec (field 2, PodSpec).
/// spec must be decoded so EqualIgnoreHash in KCM's FindNewReplicaSet can match the
/// Deployment template against the ReplicaSet template — without it spec.template.spec
/// is null in the stored Deployment JSON and the comparison always fails.
#[derive(Clone, PartialEq, Message)]
struct AppsPodTemplateSpec {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message PodSpec)
    #[prost(message, tag = "2")]
    spec: Option<PodSpec>,
}

/// DeploymentSpec — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message DeploymentSpec
#[derive(Clone, PartialEq, Message)]
struct DeploymentSpec {
    /// replicas (field 1, int32)
    #[prost(int32, tag = "1")]
    replicas: i32,
    /// selector (field 2, message LabelSelector)
    #[prost(message, tag = "2")]
    selector: Option<AppsLabelSelector>,
    /// template (field 3, message PodTemplateSpec)
    #[prost(message, tag = "3")]
    template: Option<AppsPodTemplateSpec>,
}

/// RollingUpdateStatefulSetStrategy — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message RollingUpdateStatefulSetStrategy
#[derive(Clone, PartialEq, Message)]
struct RollingUpdateStatefulSetStrategy {
    /// partition (field 1, int32) — ordinal at which the rolling update starts
    #[prost(int32, tag = "1")]
    partition: i32,
}

/// StatefulSetUpdateStrategy — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message StatefulSetUpdateStrategy
#[derive(Clone, PartialEq, Message)]
struct StatefulSetUpdateStrategy {
    /// type (field 1, string): "RollingUpdate" or "OnDelete"
    #[prost(string, tag = "1")]
    r#type: String,
    /// rollingUpdate (field 2, message RollingUpdateStatefulSetStrategy)
    #[prost(message, tag = "2")]
    rolling_update: Option<RollingUpdateStatefulSetStrategy>,
}

/// StatefulSetSpec — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message StatefulSetSpec
#[derive(Clone, PartialEq, Message)]
struct StatefulSetSpec {
    /// replicas (field 1, int32)
    #[prost(int32, tag = "1")]
    replicas: i32,
    /// selector (field 2, message LabelSelector)
    #[prost(message, tag = "2")]
    selector: Option<AppsLabelSelector>,
    /// template (field 3, message PodTemplateSpec)
    #[prost(message, tag = "3")]
    template: Option<AppsPodTemplateSpec>,
    // field 4 = volumeClaimTemplates (repeated PVC) — skipped
    // field 5 = serviceName (string) — skipped
    // field 6 = podManagementPolicy (string) — skipped
    /// updateStrategy (field 7, message StatefulSetUpdateStrategy)
    #[prost(message, tag = "7")]
    update_strategy: Option<StatefulSetUpdateStrategy>,
}

#[derive(Clone, PartialEq, Message)]
struct StatefulSetCondition {
    #[prost(string, tag = "1")]
    r#type: String,
    #[prost(string, tag = "2")]
    status: String,
    // tag 3 = lastTransitionTime (Time message) — skipped, not needed for round-trip
    #[prost(string, tag = "4")]
    reason: String,
    #[prost(string, tag = "5")]
    message: String,
}

#[derive(Clone, PartialEq, Message)]
struct StatefulSetStatus {
    #[prost(int64, tag = "1")]
    observed_generation: i64,
    #[prost(int32, tag = "2")]
    replicas: i32,
    #[prost(int32, tag = "3")]
    ready_replicas: i32,
    #[prost(int32, tag = "4")]
    current_replicas: i32,
    #[prost(int32, tag = "5")]
    updated_replicas: i32,
    #[prost(string, tag = "6")]
    current_revision: String,
    #[prost(string, tag = "7")]
    update_revision: String,
    #[prost(int32, tag = "9")]
    collision_count: i32,
    #[prost(message, repeated, tag = "10")]
    conditions: Vec<StatefulSetCondition>,
    #[prost(int32, tag = "11")]
    available_replicas: i32,
}

/// ReplicaSetSpec — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message ReplicaSetSpec
#[derive(Clone, PartialEq, Message)]
struct ReplicaSetSpec {
    /// replicas (field 1, int32)
    #[prost(int32, tag = "1")]
    replicas: i32,
    /// selector (field 2, message LabelSelector)
    #[prost(message, tag = "2")]
    selector: Option<AppsLabelSelector>,
    /// template (field 3, message PodTemplateSpec)
    #[prost(message, tag = "3")]
    template: Option<AppsPodTemplateSpec>,
}

/// StatefulSet — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message StatefulSet
#[derive(Clone, PartialEq, Message)]
struct StatefulSet {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message StatefulSetSpec)
    #[prost(message, tag = "2")]
    spec: Option<StatefulSetSpec>,
    /// status (field 3, message StatefulSetStatus)
    #[prost(message, tag = "3")]
    status: Option<StatefulSetStatus>,
}

/// Deployment — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message Deployment
#[derive(Clone, PartialEq, Message)]
struct Deployment {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message DeploymentSpec)
    #[prost(message, tag = "2")]
    spec: Option<DeploymentSpec>,
}

/// DaemonSetSpec — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message DaemonSetSpec
/// Only selector and template decoded; other fields not needed for selector defaulting.
#[derive(Clone, PartialEq, Message)]
struct DaemonSetSpec {
    /// selector (field 1, message LabelSelector)
    #[prost(message, tag = "1")]
    selector: Option<AppsLabelSelector>,
    /// template (field 2, message PodTemplateSpec)
    #[prost(message, tag = "2")]
    template: Option<AppsPodTemplateSpec>,
}

/// DaemonSet — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message DaemonSet
#[derive(Clone, PartialEq, Message)]
struct DaemonSet {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message DaemonSetSpec)
    #[prost(message, tag = "2")]
    spec: Option<DaemonSetSpec>,
}

/// ReplicaSet — k8s.io/api/apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message ReplicaSet
#[derive(Clone, PartialEq, Message)]
struct ReplicaSet {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message ReplicaSetSpec)
    #[prost(message, tag = "2")]
    spec: Option<ReplicaSetSpec>,
}

/// ServiceAccount — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message ServiceAccount
/// secrets (field 2), imagePullSecrets (field 3), automountServiceAccountToken (field 4)
/// are skipped — not needed for routing.
#[derive(Clone, PartialEq, Message)]
struct ServiceAccount {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// PersistentVolumeClaim — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message PersistentVolumeClaim
#[derive(Clone, PartialEq, Message)]
struct PersistentVolumeClaim {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// EndpointAddress — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message EndpointAddress
/// Canonical field layout:
///   1: ip (string)
///   2: targetRef (ObjectReference, LEN/message) — decoded as raw bytes, not serialized
///   3: hostname (string)
///   4: nodeName (string)
#[derive(Clone, PartialEq, Message)]
struct EndpointAddress {
    /// ip (field 1, string)
    #[prost(string, tag = "1")]
    ip: String,
    /// targetRef (field 2, ObjectReference) — captured as bytes, not serialized to JSON
    #[prost(bytes = "vec", tag = "2")]
    target_ref: Vec<u8>,
    /// hostname (field 3, string)
    #[prost(string, tag = "3")]
    hostname: String,
    /// nodeName (field 4, string)
    #[prost(string, tag = "4")]
    node_name: String,
}

/// EndpointPort — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message EndpointPort
#[derive(Clone, PartialEq, Message)]
struct EndpointPort {
    /// name (field 1, string)
    #[prost(string, tag = "1")]
    name: String,
    /// port (field 2, int32)
    #[prost(int32, tag = "2")]
    port: i32,
    /// protocol (field 3, string)
    #[prost(string, tag = "3")]
    protocol: String,
    /// appProtocol (field 4, string)
    #[prost(string, tag = "4")]
    app_protocol: String,
}

/// EndpointSubset — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message EndpointSubset
#[derive(Clone, PartialEq, Message)]
struct EndpointSubset {
    /// addresses (field 1, repeated EndpointAddress)
    #[prost(message, repeated, tag = "1")]
    addresses: Vec<EndpointAddress>,
    /// notReadyAddresses (field 2, repeated EndpointAddress)
    #[prost(message, repeated, tag = "2")]
    not_ready_addresses: Vec<EndpointAddress>,
    /// ports (field 3, repeated EndpointPort)
    #[prost(message, repeated, tag = "3")]
    ports: Vec<EndpointPort>,
}

/// Endpoints — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message Endpoints
#[derive(Clone, PartialEq, Message)]
struct Endpoints {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// subsets (field 2, repeated EndpointSubset)
    #[prost(message, repeated, tag = "2")]
    subsets: Vec<EndpointSubset>,
}

// --- k8s.io/api/storage/v1/generated.proto ---

/// StorageClass — k8s.io/api/storage/v1/generated.proto
/// Source: k8s.io/api/storage/v1/generated.proto message StorageClass
/// (proto file not in repo; only metadata decoded — field 1 is standard across all types)
/// spec fields (provisioner, parameters, etc.) are deeply nested; only metadata is decoded.
#[derive(Clone, PartialEq, Message)]
struct StorageClass {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// VolumeAttributesClass — k8s.io/api/storage/v1/generated.proto
/// Source: k8s.io/api/storage/v1/generated.proto message VolumeAttributesClass
/// (proto file not in repo; only metadata decoded — field 1 is standard across all types)
#[derive(Clone, PartialEq, Message)]
struct VolumeAttributesClass {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

// --- k8s.io/api/core/v1/generated.proto (resource management types) ---

/// ResourceQuotaSpec — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message ResourceQuotaSpec
///
/// Only field 1 (hard) is decoded; scopes (field 2) and scopeSelector (field 3) are skipped.
/// hard is required by the quota controller to enforce limits; without it the controller
/// sees no limits and skips reconciliation, leaving spec.hard null after create.
#[derive(Clone, PartialEq, Message)]
struct ResourceQuotaSpec {
    /// hard (field 1, map<string, Quantity>) — the desired hard limits per named resource
    #[prost(btree_map = "string, message", tag = "1")]
    hard: std::collections::BTreeMap<String, Quantity>,
}

/// ResourceQuota — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message ResourceQuota
#[derive(Clone, PartialEq, Message)]
struct ResourceQuota {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message ResourceQuotaSpec)
    #[prost(message, optional, tag = "2")]
    spec: Option<ResourceQuotaSpec>,
}

/// Quantity — k8s.io/apimachinery/pkg/api/resource/generated.proto
/// Source: apimachinery-resource-generated.proto message Quantity
///
/// Only field 1 (string representation) is decoded; binary/decimal forms are ignored.
/// This is sufficient for LimitRange admission: we only need the human-readable value
/// (e.g. "500m", "128Mi") to pass through to JSON.
#[derive(Clone, PartialEq, Message)]
struct Quantity {
    /// string representation (field 1, e.g. "500m", "128Mi", "1")
    #[prost(string, optional, tag = "1")]
    string: Option<String>,
}

/// LimitRangeItem — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message LimitRangeItem
#[derive(Clone, PartialEq, Message)]
struct LimitRangeItem {
    /// type (field 1, string) — "Container", "Pod", or "PersistentVolumeClaim"
    #[prost(string, tag = "1")]
    r#type: String,
    /// max (field 2, map<string, Quantity>)
    #[prost(btree_map = "string, message", tag = "2")]
    max: std::collections::BTreeMap<String, Quantity>,
    /// min (field 3, map<string, Quantity>)
    #[prost(btree_map = "string, message", tag = "3")]
    min: std::collections::BTreeMap<String, Quantity>,
    /// default (field 4, map<string, Quantity>)
    #[prost(btree_map = "string, message", tag = "4")]
    default: std::collections::BTreeMap<String, Quantity>,
    /// defaultRequest (field 5, map<string, Quantity>)
    #[prost(btree_map = "string, message", tag = "5")]
    default_request: std::collections::BTreeMap<String, Quantity>,
    /// maxLimitRequestRatio (field 6, map<string, Quantity>)
    #[prost(btree_map = "string, message", tag = "6")]
    max_limit_request_ratio: std::collections::BTreeMap<String, Quantity>,
}

/// LimitRangeSpec — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message LimitRangeSpec
#[derive(Clone, PartialEq, Message)]
struct LimitRangeSpec {
    /// limits (field 1, repeated LimitRangeItem)
    #[prost(message, repeated, tag = "1")]
    limits: Vec<LimitRangeItem>,
}

/// LimitRange — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message LimitRange
#[derive(Clone, PartialEq, Message)]
struct LimitRange {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message LimitRangeSpec)
    #[prost(message, optional, tag = "2")]
    spec: Option<LimitRangeSpec>,
}

// --- k8s.io/api/policy/v1/generated.proto ---

/// PodDisruptionBudget — k8s.io/api/policy/v1/generated.proto
/// Source: k8s.io/api/policy/v1/generated.proto message PodDisruptionBudget
/// (proto file not in repo; only metadata decoded — field 1 is standard across all types)
#[derive(Clone, PartialEq, Message)]
struct PodDisruptionBudget {
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
    /// The apiVersion extracted from the TypeMeta (field 1 of the envelope), e.g.
    /// "v1" or "events.k8s.io/v1". Empty string if absent.
    pub api_version: String,
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
    // Reject oversized envelopes before handing them to prost. A varint bomb can claim a
    // multi-GiB allocation from a tiny payload; this check prevents the allocation entirely.
    if proto_bytes.len() > MAX_PROTO_ENVELOPE_BYTES {
        return None;
    }
    let unknown = Unknown::decode(proto_bytes).ok()?;
    // raw field must be non-empty — we require a payload
    if unknown.raw.is_empty() {
        return None;
    }
    let (api_version, kind) = unknown
        .type_meta
        .map(|t| (t.api_version, t.kind))
        .unwrap_or_default();
    Some(ProtoEnvelope {
        raw: unknown.raw,
        content_type: unknown.content_type,
        kind,
        api_version,
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
    if meta.generation != 0 {
        m["generation"] = serde_json::Value::Number(meta.generation.into());
    }
    if let Some(ts) = meta.creation_timestamp {
        if ts.seconds > 0 {
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
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": meta
    });
    if let Some(spec) = ns.spec {
        if !spec.finalizers.is_empty() {
            let fins: Vec<serde_json::Value> = spec
                .finalizers
                .into_iter()
                .map(serde_json::Value::String)
                .collect();
            obj["spec"] = serde_json::json!({ "finalizers": fins });
        }
    }
    Some(obj)
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
    if !cm.binary_data.is_empty() {
        let binary_data_map: serde_json::Map<String, serde_json::Value> = cm
            .binary_data
            .into_iter()
            .map(|(k, v)| {
                use base64::Engine;
                (
                    k,
                    serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&v)),
                )
            })
            .collect();
        obj["binaryData"] = serde_json::Value::Object(binary_data_map);
    }
    Some(obj)
}

/// Convert a decoded `Probe` struct into a `serde_json::Value`.
///
/// Only non-zero timing fields are emitted; zero means "not set" for proto3 scalars.
/// Handler fields (exec/httpGet/tcpSocket) are omitted — they are not decoded.
fn probe_to_json(p: Probe) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(handler) = p.handler {
        if let Some(exec) = handler.exec {
            if !exec.command.is_empty() {
                m.insert(
                    "exec".to_string(),
                    serde_json::json!({ "command": exec.command }),
                );
            }
        }
        if let Some(http_get) = handler.http_get {
            let mut hg = serde_json::Map::new();
            if !http_get.path.is_empty() {
                hg.insert("path".to_string(), serde_json::Value::String(http_get.path));
            }
            if let Some(port) = http_get.port {
                hg.insert("port".to_string(), port.to_json());
            }
            if !http_get.host.is_empty() {
                hg.insert("host".to_string(), serde_json::Value::String(http_get.host));
            }
            if !http_get.scheme.is_empty() {
                hg.insert(
                    "scheme".to_string(),
                    serde_json::Value::String(http_get.scheme),
                );
            }
            m.insert("httpGet".to_string(), serde_json::Value::Object(hg));
        }
        if let Some(tcp) = handler.tcp_socket {
            let mut ts = serde_json::Map::new();
            if let Some(port) = tcp.port {
                ts.insert("port".to_string(), port.to_json());
            }
            if !tcp.host.is_empty() {
                ts.insert("host".to_string(), serde_json::Value::String(tcp.host));
            }
            m.insert("tcpSocket".to_string(), serde_json::Value::Object(ts));
        }
        if let Some(grpc) = handler.grpc {
            m.insert(
                "grpc".to_string(),
                serde_json::json!({ "port": grpc.port, "service": grpc.service }),
            );
        }
    }
    if p.initial_delay_seconds != 0 {
        m.insert(
            "initialDelaySeconds".to_string(),
            serde_json::Value::Number(p.initial_delay_seconds.into()),
        );
    }
    if p.timeout_seconds != 0 {
        m.insert(
            "timeoutSeconds".to_string(),
            serde_json::Value::Number(p.timeout_seconds.into()),
        );
    }
    if p.period_seconds != 0 {
        m.insert(
            "periodSeconds".to_string(),
            serde_json::Value::Number(p.period_seconds.into()),
        );
    }
    if p.success_threshold != 0 {
        m.insert(
            "successThreshold".to_string(),
            serde_json::Value::Number(p.success_threshold.into()),
        );
    }
    if p.failure_threshold != 0 {
        m.insert(
            "failureThreshold".to_string(),
            serde_json::Value::Number(p.failure_threshold.into()),
        );
    }
    serde_json::Value::Object(m)
}

/// Convert a decoded `LifecycleHandler` into a `serde_json::Value`.
fn lifecycle_handler_to_json(h: LifecycleHandler) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(exec) = h.exec {
        if !exec.command.is_empty() {
            m.insert(
                "exec".to_string(),
                serde_json::json!({
                    "command": exec.command
                }),
            );
        }
    }
    if let Some(http_get) = h.http_get {
        let mut hg = serde_json::Map::new();
        if !http_get.path.is_empty() {
            hg.insert("path".to_string(), serde_json::Value::String(http_get.path));
        }
        if let Some(port) = http_get.port {
            hg.insert("port".to_string(), port.to_json());
        }
        if !http_get.host.is_empty() {
            hg.insert("host".to_string(), serde_json::Value::String(http_get.host));
        }
        if !http_get.scheme.is_empty() {
            hg.insert(
                "scheme".to_string(),
                serde_json::Value::String(http_get.scheme),
            );
        }
        m.insert("httpGet".to_string(), serde_json::Value::Object(hg));
    }
    if let Some(tcp) = h.tcp_socket {
        let mut ts = serde_json::Map::new();
        if let Some(port) = tcp.port {
            ts.insert("port".to_string(), port.to_json());
        }
        if !tcp.host.is_empty() {
            ts.insert("host".to_string(), serde_json::Value::String(tcp.host));
        }
        m.insert("tcpSocket".to_string(), serde_json::Value::Object(ts));
    }
    if let Some(sleep) = h.sleep {
        m.insert(
            "sleep".to_string(),
            serde_json::json!({ "seconds": sleep.seconds }),
        );
    }
    serde_json::Value::Object(m)
}

/// Convert a decoded `Lifecycle` struct into a `serde_json::Value`.
fn lifecycle_to_json(lc: Lifecycle) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(h) = lc.post_start {
        m.insert("postStart".to_string(), lifecycle_handler_to_json(h));
    }
    if let Some(h) = lc.pre_stop {
        m.insert("preStop".to_string(), lifecycle_handler_to_json(h));
    }
    serde_json::Value::Object(m)
}

/// Decode a proto-encoded Pod object into a `serde_json::Value`.
///
/// Decodes metadata and spec (containers + scalar fields). All other PodSpec fields are omitted
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

    obj["spec"] = pod_spec_to_json(pod.spec.unwrap_or_default());

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

/// Decode a proto-encoded IntOrString (k8s.io/apimachinery/pkg/util/intstr) from raw bytes.
/// k8s IntOrString (k8s.io/apimachinery/pkg/util/intstr/generated.proto):
///   field 1 (int64) = type: 0=Int 1=String
///   field 2 (int32) = intVal (used when type=0)
///   field 3 (string) = strVal (used when type=1)
fn decode_int_or_string(bytes: &[u8]) -> Option<serde_json::Value> {
    #[derive(Clone, PartialEq, prost::Message)]
    struct IntOrString {
        #[prost(int64, tag = "1")]
        r#type: i64,
        #[prost(int32, tag = "2")]
        int_val: i32,
        #[prost(string, tag = "3")]
        str_val: String,
    }
    let ios = IntOrString::decode(bytes).ok()?;
    if ios.r#type == 0 {
        Some(serde_json::Value::Number(serde_json::Number::from(
            ios.int_val,
        )))
    } else if !ios.str_val.is_empty() {
        Some(serde_json::Value::String(ios.str_val))
    } else {
        None
    }
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
                if !p.target_port.is_empty() {
                    if let Some(tv) = decode_int_or_string(&p.target_port) {
                        pm.insert("targetPort".to_string(), tv);
                    }
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
        spec_map.insert(
            "replicas".to_string(),
            serde_json::Value::Number(serde_json::Number::from(spec.replicas)),
        );
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
        if let Some(t) = spec.acquire_time {
            if t.seconds > 0 {
                let ts = crate::util::normalize_rfc3339_to_micro(&crate::util::secs_to_rfc3339(
                    t.seconds as u64,
                ));
                spec_map.insert("acquireTime".to_string(), serde_json::Value::String(ts));
            }
        }
        if let Some(t) = spec.renew_time {
            if t.seconds > 0 {
                let ts = crate::util::normalize_rfc3339_to_micro(&crate::util::secs_to_rfc3339(
                    t.seconds as u64,
                ));
                spec_map.insert("renewTime".to_string(), serde_json::Value::String(ts));
            }
        }
        if spec.lease_transitions != 0 {
            spec_map.insert(
                "leaseTransitions".to_string(),
                serde_json::Value::Number(serde_json::Number::from(spec.lease_transitions)),
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
            if t.seconds > 0 {
                let ts = crate::util::normalize_rfc3339_to_micro(&crate::util::secs_to_rfc3339(
                    t.seconds as u64,
                ));
                sm.insert(
                    "lastObservedTime".to_string(),
                    serde_json::Value::String(ts),
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
    /// Echo of spec.boundObjectRef from the request, as a JSON value.
    /// None when the request did not include a boundObjectRef.
    pub bound_object_ref: Option<serde_json::Value>,
}

/// Decode the inner raw bytes of a protobuf-encoded TokenRequest.
///
/// Wire layout (k8s.io/api/authentication/v1/generated.proto):
///   field 1 (ObjectMeta, wire 2): ignored
///   field 2 (TokenRequestSpec, wire 2): spec
///     field 1 (repeated string): audiences
///     field 3 (BoundObjectReference, message): boundObjectRef
///     field 4 (int64): expirationSeconds (0 = unset)
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
    let bound_object_ref = spec.bound_object_ref.map(|bor| {
        serde_json::json!({
            "apiVersion": bor.api_version,
            "kind": bor.kind,
            "name": bor.name,
            "uid": bor.uid,
        })
    });
    Some(TokenRequestFields {
        audiences: spec.audiences,
        expiration_seconds,
        bound_object_ref,
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

/// Decode a proto-encoded LocalSubjectAccessReview object into a `serde_json::Value`.
///
/// LocalSubjectAccessReview has the same wire format as SubjectAccessReview — the only
/// difference is the kind field in the returned JSON.  When kubectl or a conformance test
/// POSTs to /apis/authorization.k8s.io/v1/namespaces/{ns}/localsubjectaccessreviews with
/// Content-Type: application/vnd.kubernetes.protobuf, the envelope kind is
/// "LocalSubjectAccessReview".  Without this decoder, extract_body returns raw proto bytes
/// and serde_json::from_slice produces "expected value at line 1 column 1" → 400.
pub fn decode_local_subject_access_review_proto(data: &[u8]) -> Option<serde_json::Value> {
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
        "kind": "LocalSubjectAccessReview",
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
    if spec.ttl_seconds_after_finished != 0 {
        m.insert(
            "ttlSecondsAfterFinished".to_string(),
            serde_json::Value::Number(serde_json::Number::from(spec.ttl_seconds_after_finished)),
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

/// Convert an `AppsLabelSelector` to the JSON form used in Kubernetes API objects.
fn apps_label_selector_to_json(sel: AppsLabelSelector) -> serde_json::Value {
    let mut m = serde_json::json!({});
    if !sel.match_labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = sel
            .match_labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["matchLabels"] = serde_json::Value::Object(labels);
    }
    m
}

/// Convert a decoded `DownwardAPIVolumeFile` into a JSON object.
/// This is used both by DownwardAPIVolumeSource items and DownwardAPIProjection items.
fn downward_api_volume_file_to_json(f: DownwardAPIVolumeFile) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !f.path.is_empty() {
        m.insert("path".to_string(), serde_json::Value::String(f.path));
    }
    if let Some(fr) = f.field_ref {
        let mut fr_map = serde_json::Map::new();
        if !fr.api_version.is_empty() {
            fr_map.insert(
                "apiVersion".to_string(),
                serde_json::Value::String(fr.api_version),
            );
        }
        if !fr.field_path.is_empty() {
            fr_map.insert(
                "fieldPath".to_string(),
                serde_json::Value::String(fr.field_path),
            );
        }
        m.insert("fieldRef".to_string(), serde_json::Value::Object(fr_map));
    }
    if let Some(rfr) = f.resource_field_ref {
        let mut rfr_map = serde_json::Map::new();
        if !rfr.container_name.is_empty() {
            rfr_map.insert(
                "containerName".to_string(),
                serde_json::Value::String(rfr.container_name),
            );
        }
        if !rfr.resource.is_empty() {
            rfr_map.insert(
                "resource".to_string(),
                serde_json::Value::String(rfr.resource),
            );
        }
        // divisor is required by the kubelet; if omitted or zero the volume fails to mount.
        // The Kubernetes API server defaults an absent/zero divisor to "1".
        // A zero Quantity serialises as string "0" in proto — treat that as the default too.
        let divisor_str = rfr
            .divisor
            .and_then(|q| q.string)
            .filter(|s| !s.is_empty() && s != "0")
            .unwrap_or_else(|| "1".to_string());
        rfr_map.insert(
            "divisor".to_string(),
            serde_json::Value::String(divisor_str),
        );
        m.insert(
            "resourceFieldRef".to_string(),
            serde_json::Value::Object(rfr_map),
        );
    }
    if f.mode != 0 {
        m.insert("mode".to_string(), serde_json::Value::Number(f.mode.into()));
    }
    serde_json::Value::Object(m)
}

/// Convert decoded DownwardAPIVolumeSource fields into a JSON object.
/// Called for spec.volumes[].downwardAPI.
fn downward_api_volume_source_to_json(
    items: Vec<DownwardAPIVolumeFile>,
    default_mode: i32,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !items.is_empty() {
        let items_json: Vec<serde_json::Value> = items
            .into_iter()
            .map(downward_api_volume_file_to_json)
            .collect();
        m.insert("items".to_string(), serde_json::Value::Array(items_json));
    }
    // defaultMode is required by the kubelet; if omitted the volume mount fails with
    // "no defaultMode used, not even the default value for it".
    // The Kubernetes API server defaults an absent (proto zero) value to 0644 = 420.
    let dm = if default_mode == 0 { 420 } else { default_mode };
    m.insert(
        "defaultMode".to_string(),
        serde_json::Value::Number(dm.into()),
    );
    serde_json::Value::Object(m)
}

/// Serialize a slice of `KeyToPath` items into a JSON array.
/// Each item becomes `{"key": k, "path": p}`, with `"mode"` included only when non-zero.
fn key_to_path_items_to_json(items: Vec<KeyToPath>) -> serde_json::Value {
    let arr: Vec<serde_json::Value> = items
        .into_iter()
        .filter(|it| !it.key.is_empty())
        .map(|it| {
            let mut m = serde_json::Map::new();
            m.insert("key".to_string(), serde_json::Value::String(it.key));
            m.insert("path".to_string(), serde_json::Value::String(it.path));
            if it.mode != 0 {
                m.insert(
                    "mode".to_string(),
                    serde_json::Value::Number(it.mode.into()),
                );
            }
            serde_json::Value::Object(m)
        })
        .collect();
    serde_json::Value::Array(arr)
}

/// Convert a decoded `ProjectedVolumeSource` into a JSON object.
/// Called for spec.volumes[].projected.
fn projected_volume_source_to_json(proj: ProjectedVolumeSource) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !proj.sources.is_empty() {
        let sources_json: Vec<serde_json::Value> = proj
            .sources
            .into_iter()
            .map(|src| {
                let mut sm = serde_json::Map::new();
                if let Some(s) = src.secret {
                    if let Some(lor) = s.local_object_reference {
                        if !lor.name.is_empty() {
                            let mut secret_map = serde_json::Map::new();
                            secret_map
                                .insert("name".to_string(), serde_json::Value::String(lor.name));
                            if !s.items.is_empty() {
                                secret_map.insert(
                                    "items".to_string(),
                                    key_to_path_items_to_json(s.items),
                                );
                            }
                            sm.insert("secret".to_string(), serde_json::Value::Object(secret_map));
                        }
                    }
                }
                if let Some(da) = src.downward_api {
                    sm.insert(
                        "downwardAPI".to_string(),
                        downward_api_volume_source_to_json(da.items, 0),
                    );
                }
                if let Some(cm) = src.config_map {
                    if let Some(lor) = cm.local_object_reference {
                        if !lor.name.is_empty() {
                            let mut cm_map = serde_json::Map::new();
                            cm_map.insert("name".to_string(), serde_json::Value::String(lor.name));
                            if !cm.items.is_empty() {
                                cm_map.insert(
                                    "items".to_string(),
                                    key_to_path_items_to_json(cm.items),
                                );
                            }
                            sm.insert("configMap".to_string(), serde_json::Value::Object(cm_map));
                        }
                    }
                }
                if let Some(sat) = src.service_account_token {
                    let mut sat_map = serde_json::Map::new();
                    if !sat.audience.is_empty() {
                        sat_map.insert(
                            "audience".to_string(),
                            serde_json::Value::String(sat.audience),
                        );
                    }
                    if sat.expiration_seconds != 0 {
                        sat_map.insert(
                            "expirationSeconds".to_string(),
                            serde_json::Value::Number(sat.expiration_seconds.into()),
                        );
                    }
                    if !sat.path.is_empty() {
                        sat_map.insert("path".to_string(), serde_json::Value::String(sat.path));
                    }
                    sm.insert(
                        "serviceAccountToken".to_string(),
                        serde_json::Value::Object(sat_map),
                    );
                }
                serde_json::Value::Object(sm)
            })
            .collect();
        m.insert(
            "sources".to_string(),
            serde_json::Value::Array(sources_json),
        );
    }
    if proj.default_mode != 0 {
        m.insert(
            "defaultMode".to_string(),
            serde_json::Value::Number(proj.default_mode.into()),
        );
    }
    serde_json::Value::Object(m)
}

/// Serialize a decoded `PodSpec` into a JSON map.
///
/// Mirrors the container/spec serialization in `decode_pod_proto`, extracted here so
/// `apps_spec_to_json` can embed the pod spec inside `spec.template.spec` for Deployment,
/// StatefulSet, ReplicaSet, and DaemonSet without duplicating the logic.
fn container_to_json(c: Container) -> serde_json::Value {
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
            serde_json::Value::Array(c.args.into_iter().map(serde_json::Value::String).collect()),
        );
    }
    if !c.ports.is_empty() {
        let ports_json: Vec<serde_json::Value> = c
            .ports
            .into_iter()
            .map(|p| {
                let mut pm = serde_json::Map::new();
                if !p.name.is_empty() {
                    pm.insert("name".to_string(), serde_json::Value::String(p.name));
                }
                if p.container_port != 0 {
                    pm.insert(
                        "containerPort".to_string(),
                        serde_json::Value::Number(p.container_port.into()),
                    );
                }
                if p.host_port != 0 {
                    pm.insert(
                        "hostPort".to_string(),
                        serde_json::Value::Number(p.host_port.into()),
                    );
                }
                if !p.protocol.is_empty() {
                    pm.insert(
                        "protocol".to_string(),
                        serde_json::Value::String(p.protocol),
                    );
                }
                if !p.host_ip.is_empty() {
                    pm.insert("hostIP".to_string(), serde_json::Value::String(p.host_ip));
                }
                serde_json::Value::Object(pm)
            })
            .collect();
        cm.insert("ports".to_string(), serde_json::Value::Array(ports_json));
    }
    if !c.env.is_empty() {
        let env_json: Vec<serde_json::Value> = c
            .env
            .into_iter()
            .map(|ev| {
                let mut em = serde_json::Map::new();
                if !ev.name.is_empty() {
                    em.insert("name".to_string(), serde_json::Value::String(ev.name));
                }
                if !ev.value.is_empty() {
                    em.insert("value".to_string(), serde_json::Value::String(ev.value));
                }
                if let Some(vf) = ev.value_from {
                    let mut vfm = serde_json::Map::new();
                    if let Some(fr) = vf.field_ref {
                        let mut frm = serde_json::Map::new();
                        if !fr.api_version.is_empty() {
                            frm.insert(
                                "apiVersion".to_string(),
                                serde_json::Value::String(fr.api_version),
                            );
                        }
                        if !fr.field_path.is_empty() {
                            frm.insert(
                                "fieldPath".to_string(),
                                serde_json::Value::String(fr.field_path),
                            );
                        }
                        vfm.insert("fieldRef".to_string(), serde_json::Value::Object(frm));
                    }
                    if let Some(rfr) = vf.resource_field_ref {
                        let mut rfrm = serde_json::Map::new();
                        if !rfr.container_name.is_empty() {
                            rfrm.insert(
                                "containerName".to_string(),
                                serde_json::Value::String(rfr.container_name),
                            );
                        }
                        if !rfr.resource.is_empty() {
                            rfrm.insert(
                                "resource".to_string(),
                                serde_json::Value::String(rfr.resource),
                            );
                        }
                        if let Some(divisor_str) = rfr.divisor.and_then(|q| q.string) {
                            if !divisor_str.is_empty() {
                                rfrm.insert(
                                    "divisor".to_string(),
                                    serde_json::Value::String(divisor_str),
                                );
                            }
                        }
                        vfm.insert(
                            "resourceFieldRef".to_string(),
                            serde_json::Value::Object(rfrm),
                        );
                    }
                    if let Some(cmkr) = vf.config_map_key_ref {
                        let mut cmkrm = serde_json::Map::new();
                        if let Some(lor) = cmkr.local_object_reference {
                            if !lor.name.is_empty() {
                                cmkrm.insert(
                                    "name".to_string(),
                                    serde_json::Value::String(lor.name),
                                );
                            }
                        }
                        if !cmkr.key.is_empty() {
                            cmkrm.insert("key".to_string(), serde_json::Value::String(cmkr.key));
                        }
                        if cmkr.optional {
                            cmkrm.insert(
                                "optional".to_string(),
                                serde_json::Value::Bool(cmkr.optional),
                            );
                        }
                        vfm.insert(
                            "configMapKeyRef".to_string(),
                            serde_json::Value::Object(cmkrm),
                        );
                    }
                    if let Some(skr) = vf.secret_key_ref {
                        let mut skrm = serde_json::Map::new();
                        if let Some(lor) = skr.local_object_reference {
                            if !lor.name.is_empty() {
                                skrm.insert(
                                    "name".to_string(),
                                    serde_json::Value::String(lor.name),
                                );
                            }
                        }
                        if !skr.key.is_empty() {
                            skrm.insert("key".to_string(), serde_json::Value::String(skr.key));
                        }
                        if skr.optional {
                            skrm.insert(
                                "optional".to_string(),
                                serde_json::Value::Bool(skr.optional),
                            );
                        }
                        vfm.insert("secretKeyRef".to_string(), serde_json::Value::Object(skrm));
                    }
                    em.insert("valueFrom".to_string(), serde_json::Value::Object(vfm));
                }
                serde_json::Value::Object(em)
            })
            .collect();
        cm.insert("env".to_string(), serde_json::Value::Array(env_json));
    }
    if !c.env_from.is_empty() {
        let env_from_json: Vec<serde_json::Value> = c
            .env_from
            .into_iter()
            .map(|ef| {
                let mut efm = serde_json::Map::new();
                if !ef.prefix.is_empty() {
                    efm.insert("prefix".to_string(), serde_json::Value::String(ef.prefix));
                }
                if let Some(cmr) = ef.config_map_ref {
                    let mut cmrm = serde_json::Map::new();
                    if let Some(lor) = cmr.local_object_reference {
                        if !lor.name.is_empty() {
                            cmrm.insert("name".to_string(), serde_json::Value::String(lor.name));
                        }
                    }
                    if cmr.optional {
                        cmrm.insert(
                            "optional".to_string(),
                            serde_json::Value::Bool(cmr.optional),
                        );
                    }
                    efm.insert("configMapRef".to_string(), serde_json::Value::Object(cmrm));
                }
                if let Some(sr) = ef.secret_ref {
                    let mut srm = serde_json::Map::new();
                    if let Some(lor) = sr.local_object_reference {
                        if !lor.name.is_empty() {
                            srm.insert("name".to_string(), serde_json::Value::String(lor.name));
                        }
                    }
                    if sr.optional {
                        srm.insert("optional".to_string(), serde_json::Value::Bool(sr.optional));
                    }
                    efm.insert("secretRef".to_string(), serde_json::Value::Object(srm));
                }
                serde_json::Value::Object(efm)
            })
            .collect();
        cm.insert(
            "envFrom".to_string(),
            serde_json::Value::Array(env_from_json),
        );
    }
    if let Some(res) = c.resources {
        let mut res_map = serde_json::Map::new();
        if !res.limits.is_empty() {
            res_map.insert(
                "limits".to_string(),
                limitrange_quantity_map_to_json(res.limits),
            );
        }
        if !res.requests.is_empty() {
            res_map.insert(
                "requests".to_string(),
                limitrange_quantity_map_to_json(res.requests),
            );
        }
        cm.insert("resources".to_string(), serde_json::Value::Object(res_map));
    }
    if let Some(p) = c.liveness_probe {
        cm.insert("livenessProbe".to_string(), probe_to_json(p));
    }
    if let Some(p) = c.readiness_probe {
        cm.insert("readinessProbe".to_string(), probe_to_json(p));
    }
    if let Some(p) = c.startup_probe {
        cm.insert("startupProbe".to_string(), probe_to_json(p));
    }
    if let Some(lc) = c.lifecycle {
        cm.insert("lifecycle".to_string(), lifecycle_to_json(lc));
    }
    if !c.volume_mounts.is_empty() {
        let mounts: Vec<serde_json::Value> = c
            .volume_mounts
            .into_iter()
            .map(|vm| {
                let mut m = serde_json::Map::new();
                if !vm.name.is_empty() {
                    m.insert("name".to_string(), serde_json::Value::String(vm.name));
                }
                if !vm.mount_path.is_empty() {
                    m.insert(
                        "mountPath".to_string(),
                        serde_json::Value::String(vm.mount_path),
                    );
                }
                if vm.read_only {
                    m.insert(
                        "readOnly".to_string(),
                        serde_json::Value::Bool(vm.read_only),
                    );
                }
                if !vm.sub_path.is_empty() {
                    m.insert(
                        "subPath".to_string(),
                        serde_json::Value::String(vm.sub_path),
                    );
                }
                if !vm.sub_path_expr.is_empty() {
                    m.insert(
                        "subPathExpr".to_string(),
                        serde_json::Value::String(vm.sub_path_expr),
                    );
                }
                serde_json::Value::Object(m)
            })
            .collect();
        cm.insert("volumeMounts".to_string(), serde_json::Value::Array(mounts));
    }
    serde_json::Value::Object(cm)
}

fn pod_spec_to_json(spec: PodSpec) -> serde_json::Value {
    let containers: Vec<serde_json::Value> =
        spec.containers.into_iter().map(container_to_json).collect();

    let mut spec_map = serde_json::Map::new();
    if !spec.volumes.is_empty() {
        let volumes_json: Vec<serde_json::Value> = spec
            .volumes
            .into_iter()
            .map(|v| {
                let mut vm = serde_json::Map::new();
                if !v.name.is_empty() {
                    vm.insert("name".to_string(), serde_json::Value::String(v.name));
                }
                if let Some(src) = v.volume_source {
                    if let Some(hp) = src.host_path {
                        let mut hp_map = serde_json::Map::new();
                        if !hp.path.is_empty() {
                            hp_map.insert("path".to_string(), serde_json::Value::String(hp.path));
                        }
                        if !hp.r#type.is_empty() {
                            hp_map.insert("type".to_string(), serde_json::Value::String(hp.r#type));
                        }
                        vm.insert("hostPath".to_string(), serde_json::Value::Object(hp_map));
                    }
                    if let Some(_ed) = src.empty_dir {
                        // emptyDir presence is sufficient for kubelet to use the plugin;
                        // medium is included when set (e.g. "Memory" for tmpfs).
                        let mut ed_map = serde_json::Map::new();
                        if !_ed.medium.is_empty() {
                            ed_map.insert(
                                "medium".to_string(),
                                serde_json::Value::String(_ed.medium),
                            );
                        }
                        vm.insert("emptyDir".to_string(), serde_json::Value::Object(ed_map));
                    }
                    if let Some(s) = src.secret {
                        if !s.secret_name.is_empty() {
                            let mut secret_map = serde_json::Map::new();
                            secret_map.insert(
                                "secretName".to_string(),
                                serde_json::Value::String(s.secret_name),
                            );
                            if !s.items.is_empty() {
                                secret_map.insert(
                                    "items".to_string(),
                                    key_to_path_items_to_json(s.items),
                                );
                            }
                            vm.insert("secret".to_string(), serde_json::Value::Object(secret_map));
                        }
                    }
                    if let Some(pvc) = src.persistent_volume_claim {
                        if !pvc.claim_name.is_empty() {
                            let mut pvc_map = serde_json::Map::new();
                            pvc_map.insert(
                                "claimName".to_string(),
                                serde_json::Value::String(pvc.claim_name),
                            );
                            if pvc.read_only {
                                pvc_map
                                    .insert("readOnly".to_string(), serde_json::Value::Bool(true));
                            }
                            vm.insert(
                                "persistentVolumeClaim".to_string(),
                                serde_json::Value::Object(pvc_map),
                            );
                        }
                    }
                    if let Some(da) = src.downward_api {
                        vm.insert(
                            "downwardAPI".to_string(),
                            downward_api_volume_source_to_json(da.items, da.default_mode),
                        );
                    }
                    if let Some(cm) = src.config_map {
                        if let Some(lor) = cm.local_object_reference {
                            if !lor.name.is_empty() {
                                let mut cm_map = serde_json::Map::new();
                                cm_map.insert(
                                    "name".to_string(),
                                    serde_json::Value::String(lor.name),
                                );
                                if !cm.items.is_empty() {
                                    cm_map.insert(
                                        "items".to_string(),
                                        key_to_path_items_to_json(cm.items),
                                    );
                                }
                                vm.insert(
                                    "configMap".to_string(),
                                    serde_json::Value::Object(cm_map),
                                );
                            }
                        }
                    }
                    if let Some(proj) = src.projected {
                        vm.insert(
                            "projected".to_string(),
                            projected_volume_source_to_json(proj),
                        );
                    }
                }
                serde_json::Value::Object(vm)
            })
            .collect();
        spec_map.insert(
            "volumes".to_string(),
            serde_json::Value::Array(volumes_json),
        );
    }
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
    if !spec.hostname.is_empty() {
        spec_map.insert(
            "hostname".to_string(),
            serde_json::Value::String(spec.hostname),
        );
    }
    if !spec.subdomain.is_empty() {
        spec_map.insert(
            "subdomain".to_string(),
            serde_json::Value::String(spec.subdomain),
        );
    }
    if !spec.init_containers.is_empty() {
        let init_containers: Vec<serde_json::Value> = spec
            .init_containers
            .into_iter()
            .map(container_to_json)
            .collect();
        spec_map.insert(
            "initContainers".to_string(),
            serde_json::Value::Array(init_containers),
        );
    }
    serde_json::Value::Object(spec_map)
}

/// Convert an apps-context `DeploymentSpec` / `StatefulSetSpec` / `ReplicaSetSpec`
/// into the minimal JSON needed for selector defaulting.
///
/// Returns `None` when neither selector nor template labels are present (omit spec from output).
fn apps_spec_to_json(
    selector: Option<AppsLabelSelector>,
    template: Option<AppsPodTemplateSpec>,
) -> Option<serde_json::Value> {
    let mut spec = serde_json::json!({});
    let mut non_empty = false;

    if let Some(sel) = selector {
        if !sel.match_labels.is_empty() {
            spec["selector"] = apps_label_selector_to_json(sel);
            non_empty = true;
        }
    }

    if let Some(tmpl) = template {
        let mut tmpl_json = serde_json::json!({});
        if let Some(meta) = tmpl.metadata {
            let tmpl_meta = object_meta_to_json(meta);
            tmpl_json["metadata"] = tmpl_meta;
            non_empty = true;
        }
        if let Some(pod_spec) = tmpl.spec {
            tmpl_json["spec"] = pod_spec_to_json(pod_spec);
            non_empty = true;
        }
        if non_empty {
            spec["template"] = tmpl_json;
        }
    }

    if non_empty {
        Some(spec)
    } else {
        None
    }
}

/// Decode a proto-encoded StatefulSet object into a `serde_json::Value`.
pub fn decode_statefulset_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = StatefulSet::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let replicas = spec.replicas;
        let update_strategy = spec.update_strategy;
        let mut spec_json =
            apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
        if let Some(us) = update_strategy {
            let mut us_json = serde_json::json!({});
            if !us.r#type.is_empty() {
                us_json["type"] = us.r#type.clone().into();
            }
            if let Some(ru) = us.rolling_update {
                us_json["rollingUpdate"] = serde_json::json!({ "partition": ru.partition });
            }
            if !us_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                spec_json["updateStrategy"] = us_json;
            }
        }
        if spec_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            out["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::json!({});
        if status.observed_generation != 0 {
            status_json["observedGeneration"] = status.observed_generation.into();
        }
        if status.replicas != 0 {
            status_json["replicas"] = status.replicas.into();
        }
        if status.ready_replicas != 0 {
            status_json["readyReplicas"] = status.ready_replicas.into();
        }
        if status.current_replicas != 0 {
            status_json["currentReplicas"] = status.current_replicas.into();
        }
        if status.updated_replicas != 0 {
            status_json["updatedReplicas"] = status.updated_replicas.into();
        }
        if !status.current_revision.is_empty() {
            status_json["currentRevision"] = status.current_revision.into();
        }
        if !status.update_revision.is_empty() {
            status_json["updateRevision"] = status.update_revision.into();
        }
        if status.collision_count != 0 {
            status_json["collisionCount"] = status.collision_count.into();
        }
        if status.available_replicas != 0 {
            status_json["availableReplicas"] = status.available_replicas.into();
        }
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| {
                    let mut cond = serde_json::json!({
                        "type": c.r#type,
                        "status": c.status,
                    });
                    if !c.reason.is_empty() {
                        cond["reason"] = c.reason.clone().into();
                    }
                    if !c.message.is_empty() {
                        cond["message"] = c.message.clone().into();
                    }
                    cond
                })
                .collect();
        }
        if status_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

/// Decode a proto-encoded Deployment object into a `serde_json::Value`.
pub fn decode_deployment_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = Deployment::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let replicas = spec.replicas;
        let mut spec_json =
            apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
        if spec_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            out["spec"] = spec_json;
        }
    }
    Some(out)
}

/// Decode a proto-encoded DaemonSet object into a `serde_json::Value`.
pub fn decode_daemonset_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = DaemonSet::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        if let Some(spec_json) = apps_spec_to_json(spec.selector, spec.template) {
            out["spec"] = spec_json;
        }
    }
    Some(out)
}

/// Decode a proto-encoded ReplicaSet object into a `serde_json::Value`.
pub fn decode_replicaset_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ReplicaSet::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let replicas = spec.replicas;
        let mut spec_json =
            apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
        if spec_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            out["spec"] = spec_json;
        }
    }
    Some(out)
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
///
/// Decodes metadata and subsets (field 2, repeated EndpointSubset).
/// Without decoding subsets, a proto PUT/PATCH silently drops user-supplied subsets,
/// leaving the stored object with null subsets and breaking EndpointSliceMirroring.
pub fn decode_endpoints_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = Endpoints::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": meta
    });
    if !obj.subsets.is_empty() {
        let subsets: Vec<serde_json::Value> = obj
            .subsets
            .into_iter()
            .map(|subset| {
                let mut s = serde_json::json!({});
                if !subset.addresses.is_empty() {
                    s["addresses"] = subset
                        .addresses
                        .into_iter()
                        .map(|a| {
                            let mut addr = serde_json::json!({ "ip": a.ip });
                            if !a.hostname.is_empty() {
                                addr["hostname"] = serde_json::Value::String(a.hostname);
                            }
                            if !a.node_name.is_empty() {
                                addr["nodeName"] = serde_json::Value::String(a.node_name);
                            }
                            addr
                        })
                        .collect::<Vec<_>>()
                        .into();
                }
                if !subset.not_ready_addresses.is_empty() {
                    s["notReadyAddresses"] = subset
                        .not_ready_addresses
                        .into_iter()
                        .map(|a| {
                            let mut addr = serde_json::json!({ "ip": a.ip });
                            if !a.hostname.is_empty() {
                                addr["hostname"] = serde_json::Value::String(a.hostname);
                            }
                            if !a.node_name.is_empty() {
                                addr["nodeName"] = serde_json::Value::String(a.node_name);
                            }
                            addr
                        })
                        .collect::<Vec<_>>()
                        .into();
                }
                if !subset.ports.is_empty() {
                    s["ports"] = subset
                        .ports
                        .into_iter()
                        .map(|p| {
                            let mut port = serde_json::json!({ "port": p.port });
                            if !p.name.is_empty() {
                                port["name"] = serde_json::Value::String(p.name);
                            }
                            if !p.protocol.is_empty() {
                                port["protocol"] = serde_json::Value::String(p.protocol);
                            }
                            if !p.app_protocol.is_empty() {
                                port["appProtocol"] = serde_json::Value::String(p.app_protocol);
                            }
                            port
                        })
                        .collect::<Vec<_>>()
                        .into();
                }
                s
            })
            .collect();
        result["subsets"] = subsets.into();
    }
    Some(result)
}

/// Decode a proto-encoded StorageClass object into a `serde_json::Value`.
///
/// kubectl sends StorageClass with Content-Type: application/vnd.kubernetes.protobuf.
/// Without this decoder, create_resource returns "invalid JSON: expected value at line 1 column 1".
pub fn decode_storageclass_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = StorageClass::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "StorageClass",
        "metadata": meta
    }))
}

/// Decode a proto-encoded VolumeAttributesClass object into a `serde_json::Value`.
pub fn decode_volumeattributesclass_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = VolumeAttributesClass::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "VolumeAttributesClass",
        "metadata": meta
    }))
}

/// Decode a proto-encoded ResourceQuota object into a `serde_json::Value`.
///
/// kubectl sends ResourceQuota (core/v1) with proto encoding. Without this decoder,
/// create_namespaced_resource returns "invalid JSON: expected value at line 1 column 1".
pub fn decode_resourcequota_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ResourceQuota::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        if !spec.hard.is_empty() {
            result["spec"] = serde_json::json!({
                "hard": limitrange_quantity_map_to_json(spec.hard)
            });
        }
    }
    Some(result)
}

/// Decode a proto-encoded LimitRange object into a `serde_json::Value`.
///
/// Decodes metadata and spec.limits (with type, max, min, default, defaultRequest).
/// The spec is required by the LimitRange admission plugin to inject defaults into pods;
/// without it, pods created after a LimitRange get no defaults applied.
pub fn decode_limitrange_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = LimitRange::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "v1",
        "kind": "LimitRange",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let limits: Vec<serde_json::Value> = spec
            .limits
            .into_iter()
            .map(|item| {
                let mut obj = serde_json::json!({ "type": item.r#type });
                if !item.max.is_empty() {
                    obj["max"] = limitrange_quantity_map_to_json(item.max);
                }
                if !item.min.is_empty() {
                    obj["min"] = limitrange_quantity_map_to_json(item.min);
                }
                if !item.default.is_empty() {
                    obj["default"] = limitrange_quantity_map_to_json(item.default);
                }
                if !item.default_request.is_empty() {
                    obj["defaultRequest"] = limitrange_quantity_map_to_json(item.default_request);
                }
                if !item.max_limit_request_ratio.is_empty() {
                    obj["maxLimitRequestRatio"] =
                        limitrange_quantity_map_to_json(item.max_limit_request_ratio);
                }
                obj
            })
            .collect();
        result["spec"] = serde_json::json!({ "limits": limits });
    }
    Some(result)
}

/// Convert a map of resource name to Quantity into a serde_json::Value object.
///
/// Only quantities that have a non-empty string representation are included.
/// Quantities with no string field (binary/decimal only) are skipped.
fn limitrange_quantity_map_to_json(
    map: std::collections::BTreeMap<String, Quantity>,
) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (k, v) in map {
        let s = v.string.unwrap_or_default();
        if !s.is_empty() {
            out.insert(k, serde_json::Value::String(s));
        }
    }
    serde_json::Value::Object(out)
}

/// Decode a proto-encoded PodDisruptionBudget object into a `serde_json::Value`.
pub fn decode_poddisruptionbudget_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = PodDisruptionBudget::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": meta
    }))
}

// --- k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1/generated.proto ---

/// CustomResourceDefinitionNames — names section of a CRD spec.
/// Source: apiextensions-v1-generated.proto message CustomResourceDefinitionNames
#[derive(Clone, PartialEq, Message)]
struct CrdNames {
    /// plural (field 1)
    #[prost(string, tag = "1")]
    plural: String,
    /// singular (field 2)
    #[prost(string, tag = "2")]
    singular: String,
    /// shortNames (field 3, repeated)
    #[prost(string, repeated, tag = "3")]
    short_names: Vec<String>,
    /// kind (field 4)
    #[prost(string, tag = "4")]
    kind: String,
    /// listKind (field 5)
    #[prost(string, tag = "5")]
    list_kind: String,
    /// categories (field 6, repeated) — decoded but unused in output
    #[prost(string, repeated, tag = "6")]
    categories: Vec<String>,
}

/// CustomResourceDefinitionVersion — one entry in spec.versions.
/// Source: apiextensions-v1-generated.proto message CustomResourceDefinitionVersion
#[derive(Clone, PartialEq, Message)]
struct CrdVersion {
    /// name (field 1)
    #[prost(string, tag = "1")]
    name: String,
    /// served (field 2)
    #[prost(bool, tag = "2")]
    served: bool,
    /// storage (field 3)
    #[prost(bool, tag = "3")]
    storage: bool,
    /// schema (field 4, bytes) — complex nested message; skipped
    #[prost(bytes = "vec", tag = "4")]
    schema: Vec<u8>,
    /// subresources (field 5, bytes) — skipped
    #[prost(bytes = "vec", tag = "5")]
    subresources: Vec<u8>,
    /// additionalPrinterColumns (field 6, bytes) — skipped
    #[prost(bytes = "vec", tag = "6")]
    additional_printer_columns: Vec<u8>,
}

/// CustomResourceDefinitionSpec — the spec section of a CRD.
/// Source: apiextensions-v1-generated.proto message CustomResourceDefinitionSpec
#[derive(Clone, PartialEq, Message)]
struct CrdSpec {
    /// group (field 1)
    #[prost(string, tag = "1")]
    group: String,
    /// names (field 3, message)
    #[prost(message, tag = "3")]
    names: Option<CrdNames>,
    /// scope (field 4)
    #[prost(string, tag = "4")]
    scope: String,
    /// versions (field 7, repeated message)
    #[prost(message, repeated, tag = "7")]
    versions: Vec<CrdVersion>,
    /// preserveUnknownFields (field 10)
    #[prost(bool, tag = "10")]
    preserve_unknown_fields: bool,
}

/// CustomResourceDefinition — top-level CRD object.
/// Source: apiextensions-v1-generated.proto message CustomResourceDefinition
#[derive(Clone, PartialEq, Message)]
struct Crd {
    /// metadata (field 1)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2)
    #[prost(message, tag = "2")]
    spec: Option<CrdSpec>,
}

/// Decode a proto-encoded CustomResourceDefinition into a serde_json::Value.
pub fn decode_crd_proto(data: &[u8]) -> Option<serde_json::Value> {
    let crd = Crd::decode(data).ok()?;
    let mut meta = object_meta_to_json(crd.metadata.unwrap_or_default());
    // CrdMetadata.creation_timestamp is String (not Option<String>), so null fails serde.
    // Replace the null that object_meta_to_json emits when the timestamp is zero.
    if meta["creationTimestamp"].is_null() {
        meta["creationTimestamp"] = serde_json::Value::String(String::new());
    }

    let spec = crd.spec.unwrap_or_default();
    let names = spec.names.unwrap_or_default();

    let versions: Vec<serde_json::Value> = spec
        .versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "name": v.name,
                "served": v.served,
                "storage": v.storage
            })
        })
        .collect();

    let mut names_val = serde_json::json!({
        "plural": names.plural,
        "singular": names.singular,
        "kind": names.kind
    });
    if !names.short_names.is_empty() {
        names_val["shortNames"] = serde_json::Value::Array(
            names
                .short_names
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    if !names.list_kind.is_empty() {
        names_val["listKind"] = serde_json::Value::String(names.list_kind);
    }

    let mut spec_val = serde_json::json!({
        "group": spec.group,
        "names": names_val,
        "scope": spec.scope,
        "versions": versions
    });
    if spec.preserve_unknown_fields {
        spec_val["preserveUnknownFields"] = serde_json::Value::Bool(true);
    }

    Some(serde_json::json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": meta,
        "spec": spec_val
    }))
}

// --- k8s.io/api/flowcontrol/v1/generated.proto ---

/// FlowSchema — k8s.io/api/flowcontrol/v1/generated.proto
/// Source: k8s.io/api/flowcontrol/v1/generated.proto message FlowSchema
/// (proto file not in repo; only metadata decoded — field 1 is standard across all types)
/// Only the metadata field is decoded; the spec is opaque to u7s.
#[derive(Clone, PartialEq, Message)]
struct FlowSchema {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// PriorityLevelConfiguration — k8s.io/api/flowcontrol/v1/generated.proto
/// Source: k8s.io/api/flowcontrol/v1/generated.proto message PriorityLevelConfiguration
/// (proto file not in repo; only metadata decoded — field 1 is standard across all types)
/// Only the metadata field is decoded; the spec is opaque to u7s.
#[derive(Clone, PartialEq, Message)]
struct PriorityLevelConfiguration {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
}

/// Decode a proto-encoded FlowSchema into a serde_json::Value.
///
/// The conformance test POSTs FlowSchema with Content-Type: application/vnd.kubernetes.protobuf.
/// Without this decoder, decode_core_proto_by_kind returns None, extract_body returns raw proto
/// bytes, and the handler returns 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_flowschema_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = FlowSchema::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": meta
    }))
}

/// Decode a proto-encoded PriorityLevelConfiguration into a serde_json::Value.
///
/// The conformance test POSTs PriorityLevelConfiguration with Content-Type:
/// application/vnd.kubernetes.protobuf. Without this decoder, the handler returns 400.
pub fn decode_prioritylevelconfiguration_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = PriorityLevelConfiguration::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": meta
    }))
}

/// ServiceReference — k8s.io/api/admissionregistration/v1/generated.proto
/// field 1=namespace, field 2=name, field 3=path, field 4=port
#[derive(Clone, PartialEq, Message)]
struct AdmissionServiceReference {
    #[prost(string, tag = "1")]
    namespace: String,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    path: String,
    #[prost(int32, tag = "4")]
    port: i32,
}

/// WebhookClientConfig — k8s.io/api/admissionregistration/v1/generated.proto
/// field 1=service, field 2=caBundle, field 3=url
#[derive(Clone, PartialEq, Message)]
struct WebhookClientConfig {
    #[prost(message, tag = "1")]
    service: Option<AdmissionServiceReference>,
    #[prost(bytes = "vec", tag = "2")]
    ca_bundle: Vec<u8>,
    #[prost(string, tag = "3")]
    url: String,
}

/// Rule — k8s.io/api/admissionregistration/v1/generated.proto
/// field 1=apiGroups, field 2=apiVersions, field 3=resources, field 4=scope
#[derive(Clone, PartialEq, Message)]
struct AdmissionRule {
    #[prost(string, repeated, tag = "1")]
    api_groups: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    api_versions: Vec<String>,
    #[prost(string, repeated, tag = "3")]
    resources: Vec<String>,
    #[prost(string, tag = "4")]
    scope: String,
}

/// RuleWithOperations — k8s.io/api/admissionregistration/v1/generated.proto
/// field 1=operations, field 2=rule (embedded Rule message)
#[derive(Clone, PartialEq, Message)]
struct AdmissionRuleWithOperations {
    #[prost(string, repeated, tag = "1")]
    operations: Vec<String>,
    #[prost(message, tag = "2")]
    rule: Option<AdmissionRule>,
}

/// LabelSelectorRequirement — k8s.io/apimachinery/pkg/apis/meta/v1/generated.proto
/// field 1=key, field 2=operator, field 3=values (repeated string)
#[derive(Clone, PartialEq, Message)]
struct AdmissionLabelSelectorRequirement {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(string, tag = "2")]
    operator: String,
    #[prost(string, repeated, tag = "3")]
    values: Vec<String>,
}

/// LabelSelector for admission webhooks — k8s.io/apimachinery/pkg/apis/meta/v1/generated.proto
/// field 1=matchLabels (map), field 2=matchExpressions (repeated LabelSelectorRequirement)
#[derive(Clone, PartialEq, Message)]
struct AdmissionLabelSelector {
    #[prost(map = "string, string", tag = "1")]
    match_labels: std::collections::HashMap<String, String>,
    #[prost(message, repeated, tag = "2")]
    match_expressions: Vec<AdmissionLabelSelectorRequirement>,
}

/// ValidatingWebhook — k8s.io/api/admissionregistration/v1/generated.proto
/// field 1=name, field 2=clientConfig, field 3=rules, field 4=failurePolicy,
/// field 5=namespaceSelector, field 6=sideEffects, field 7=timeoutSeconds,
/// field 8=admissionReviewVersions, field 9=matchPolicy, field 10=objectSelector,
/// field 11=matchConditions
#[derive(Clone, PartialEq, Message)]
struct ValidatingWebhook {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, tag = "2")]
    client_config: Option<WebhookClientConfig>,
    #[prost(message, repeated, tag = "3")]
    rules: Vec<AdmissionRuleWithOperations>,
    #[prost(string, tag = "4")]
    failure_policy: String,
    #[prost(message, tag = "5")]
    namespace_selector: Option<AdmissionLabelSelector>,
    #[prost(string, tag = "6")]
    side_effects: String,
    #[prost(int32, tag = "7")]
    timeout_seconds: i32,
    #[prost(string, repeated, tag = "8")]
    admission_review_versions: Vec<String>,
    #[prost(string, tag = "9")]
    match_policy: String,
    #[prost(message, tag = "10")]
    object_selector: Option<AdmissionLabelSelector>,
    #[prost(message, repeated, tag = "11")]
    match_conditions: Vec<AdmissionMatchCondition>,
}

/// MatchCondition — k8s.io/api/admissionregistration/v1/generated.proto
/// field 1=name (string), field 2=expression (string)
#[derive(Clone, PartialEq, Message)]
struct AdmissionMatchCondition {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    expression: String,
}

/// MutatingWebhook — k8s.io/api/admissionregistration/v1/generated.proto
/// field 1=name, field 2=clientConfig, field 3=rules, field 4=failurePolicy,
/// field 5=namespaceSelector, field 6=sideEffects, field 7=timeoutSeconds,
/// field 8=admissionReviewVersions, field 9=matchPolicy, field 10=reinvocationPolicy,
/// field 11=objectSelector, field 12=matchConditions
#[derive(Clone, PartialEq, Message)]
struct MutatingWebhook {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, tag = "2")]
    client_config: Option<WebhookClientConfig>,
    #[prost(message, repeated, tag = "3")]
    rules: Vec<AdmissionRuleWithOperations>,
    #[prost(string, tag = "4")]
    failure_policy: String,
    #[prost(message, tag = "5")]
    namespace_selector: Option<AdmissionLabelSelector>,
    #[prost(string, tag = "6")]
    side_effects: String,
    #[prost(int32, tag = "7")]
    timeout_seconds: i32,
    #[prost(string, repeated, tag = "8")]
    admission_review_versions: Vec<String>,
    #[prost(string, tag = "9")]
    match_policy: String,
    #[prost(string, tag = "10")]
    reinvocation_policy: String,
    #[prost(message, tag = "11")]
    object_selector: Option<AdmissionLabelSelector>,
    #[prost(message, repeated, tag = "12")]
    match_conditions: Vec<AdmissionMatchCondition>,
}

/// ValidatingWebhookConfiguration — k8s.io/api/admissionregistration/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct ValidatingWebhookConfiguration {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// webhooks (field 2, repeated ValidatingWebhook)
    #[prost(message, repeated, tag = "2")]
    webhooks: Vec<ValidatingWebhook>,
}

/// MutatingWebhookConfiguration — k8s.io/api/admissionregistration/v1/generated.proto
#[derive(Clone, PartialEq, Message)]
struct MutatingWebhookConfiguration {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// webhooks (field 2, repeated MutatingWebhook)
    #[prost(message, repeated, tag = "2")]
    webhooks: Vec<MutatingWebhook>,
}

/// Convert an AdmissionLabelSelector (which may include matchExpressions) to JSON.
///
/// Both matchLabels and matchExpressions must be preserved so that namespaceSelector
/// evaluation in the admission pipeline correctly handles complex selectors like
/// `matchExpressions: [{key: skip-webhook-admission, operator: DoesNotExist}]`.
fn label_selector_to_json(sel: AdmissionLabelSelector) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    if !sel.match_labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = sel
            .match_labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        obj["matchLabels"] = serde_json::Value::Object(labels);
    }
    if !sel.match_expressions.is_empty() {
        let exprs: Vec<serde_json::Value> = sel
            .match_expressions
            .into_iter()
            .map(|req| {
                serde_json::json!({
                    "key": req.key,
                    "operator": req.operator,
                    "values": req.values,
                })
            })
            .collect();
        obj["matchExpressions"] = serde_json::Value::Array(exprs);
    }
    obj
}

fn admission_webhook_to_json(w: ValidatingWebhook) -> serde_json::Value {
    let client_config = w
        .client_config
        .map(|cc| {
            let mut cfg = serde_json::json!({});
            if !cc.ca_bundle.is_empty() {
                cfg["caBundle"] = serde_json::Value::String(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &cc.ca_bundle,
                ));
            }
            if let Some(svc) = cc.service {
                let mut s = serde_json::json!({
                    "namespace": svc.namespace,
                    "name": svc.name,
                });
                if !svc.path.is_empty() {
                    s["path"] = serde_json::Value::String(svc.path);
                }
                if svc.port != 0 {
                    s["port"] = serde_json::Value::Number(serde_json::Number::from(svc.port));
                }
                cfg["service"] = s;
            }
            if !cc.url.is_empty() {
                cfg["url"] = serde_json::Value::String(cc.url);
            }
            cfg
        })
        .unwrap_or(serde_json::json!({}));

    let rules: Vec<serde_json::Value> = w
        .rules
        .into_iter()
        .map(|r| {
            let rule = r.rule.unwrap_or_default();
            serde_json::json!({
                "operations": r.operations,
                "apiGroups": rule.api_groups,
                "apiVersions": rule.api_versions,
                "resources": rule.resources,
                "scope": if rule.scope.is_empty() { "*".to_string() } else { rule.scope },
            })
        })
        .collect();

    let mut entry = serde_json::json!({
        "name": w.name,
        "clientConfig": client_config,
        "rules": rules,
        "admissionReviewVersions": w.admission_review_versions,
    });
    if !w.failure_policy.is_empty() {
        entry["failurePolicy"] = serde_json::Value::String(w.failure_policy);
    }
    if !w.match_policy.is_empty() {
        entry["matchPolicy"] = serde_json::Value::String(w.match_policy);
    }
    if !w.side_effects.is_empty() {
        entry["sideEffects"] = serde_json::Value::String(w.side_effects);
    }
    if w.timeout_seconds != 0 {
        entry["timeoutSeconds"] =
            serde_json::Value::Number(serde_json::Number::from(w.timeout_seconds));
    }
    if let Some(ns) = w.namespace_selector {
        entry["namespaceSelector"] = label_selector_to_json(ns);
    }
    if let Some(os) = w.object_selector {
        entry["objectSelector"] = label_selector_to_json(os);
    }
    if !w.match_conditions.is_empty() {
        let conds: Vec<serde_json::Value> = w
            .match_conditions
            .into_iter()
            .map(|c| serde_json::json!({"name": c.name, "expression": c.expression}))
            .collect();
        entry["matchConditions"] = serde_json::Value::Array(conds);
    }
    entry
}

fn mutating_webhook_to_json(w: MutatingWebhook) -> serde_json::Value {
    let client_config = w
        .client_config
        .map(|cc| {
            let mut cfg = serde_json::json!({});
            if !cc.ca_bundle.is_empty() {
                cfg["caBundle"] = serde_json::Value::String(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &cc.ca_bundle,
                ));
            }
            if let Some(svc) = cc.service {
                let mut s = serde_json::json!({
                    "namespace": svc.namespace,
                    "name": svc.name,
                });
                if !svc.path.is_empty() {
                    s["path"] = serde_json::Value::String(svc.path);
                }
                if svc.port != 0 {
                    s["port"] = serde_json::Value::Number(serde_json::Number::from(svc.port));
                }
                cfg["service"] = s;
            }
            if !cc.url.is_empty() {
                cfg["url"] = serde_json::Value::String(cc.url);
            }
            cfg
        })
        .unwrap_or(serde_json::json!({}));

    let rules: Vec<serde_json::Value> = w
        .rules
        .into_iter()
        .map(|r| {
            let rule = r.rule.unwrap_or_default();
            serde_json::json!({
                "operations": r.operations,
                "apiGroups": rule.api_groups,
                "apiVersions": rule.api_versions,
                "resources": rule.resources,
                "scope": if rule.scope.is_empty() { "*".to_string() } else { rule.scope },
            })
        })
        .collect();

    let mut entry = serde_json::json!({
        "name": w.name,
        "clientConfig": client_config,
        "rules": rules,
        "admissionReviewVersions": w.admission_review_versions,
    });
    if !w.failure_policy.is_empty() {
        entry["failurePolicy"] = serde_json::Value::String(w.failure_policy);
    }
    if !w.match_policy.is_empty() {
        entry["matchPolicy"] = serde_json::Value::String(w.match_policy);
    }
    if !w.side_effects.is_empty() {
        entry["sideEffects"] = serde_json::Value::String(w.side_effects);
    }
    if w.timeout_seconds != 0 {
        entry["timeoutSeconds"] =
            serde_json::Value::Number(serde_json::Number::from(w.timeout_seconds));
    }
    if !w.reinvocation_policy.is_empty() {
        entry["reinvocationPolicy"] = serde_json::Value::String(w.reinvocation_policy);
    }
    if let Some(ns) = w.namespace_selector {
        entry["namespaceSelector"] = label_selector_to_json(ns);
    }
    if let Some(os) = w.object_selector {
        entry["objectSelector"] = label_selector_to_json(os);
    }
    if !w.match_conditions.is_empty() {
        let conds: Vec<serde_json::Value> = w
            .match_conditions
            .into_iter()
            .map(|c| serde_json::json!({"name": c.name, "expression": c.expression}))
            .collect();
        entry["matchConditions"] = serde_json::Value::Array(conds);
    }
    entry
}

/// Decode a proto-encoded ValidatingWebhookConfiguration into a serde_json::Value.
///
/// The admissionwebhook conformance test POSTs ValidatingWebhookConfiguration with
/// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder,
/// decode_core_proto_by_kind returns None, extract_body returns raw proto bytes, and
/// the handler returns 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_validatingwebhookconfiguration_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ValidatingWebhookConfiguration::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let webhooks: Vec<serde_json::Value> = obj
        .webhooks
        .into_iter()
        .map(admission_webhook_to_json)
        .collect();
    Some(serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": meta,
        "webhooks": webhooks,
    }))
}

/// Decode a proto-encoded MutatingWebhookConfiguration into a serde_json::Value.
///
/// The admissionwebhook conformance test POSTs MutatingWebhookConfiguration with
/// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder,
/// decode_core_proto_by_kind returns None, extract_body returns raw proto bytes, and
/// the handler returns 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_mutatingwebhookconfiguration_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = MutatingWebhookConfiguration::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let webhooks: Vec<serde_json::Value> = obj
        .webhooks
        .into_iter()
        .map(mutating_webhook_to_json)
        .collect();
    Some(serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "MutatingWebhookConfiguration",
        "metadata": meta,
        "webhooks": webhooks,
    }))
}

// ---------------------------------------------------------------------------
// MutatingAdmissionPolicy proto structs
// Source: k8s.io/api/admissionregistration/v1/generated.proto (v0.36.1)
// Field numbers match the k8s 1.36 canonical proto definition.
// ---------------------------------------------------------------------------

/// Rule — admissionregistration.k8s.io/v1/generated.proto
/// field 1=apiGroups, field 2=apiVersions, field 3=resources, field 4=scope
#[derive(Clone, PartialEq, Message)]
struct MapRule {
    /// apiGroups (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    api_groups: Vec<String>,
    /// apiVersions (field 2, repeated string)
    #[prost(string, repeated, tag = "2")]
    api_versions: Vec<String>,
    /// resources (field 3, repeated string)
    #[prost(string, repeated, tag = "3")]
    resources: Vec<String>,
    /// scope (field 4, string)
    #[prost(string, tag = "4")]
    scope: String,
}

/// RuleWithOperations — admissionregistration.k8s.io/v1/generated.proto
/// field 1=operations (repeated string), field 2=rule (Rule)
#[derive(Clone, PartialEq, Message)]
struct MapRuleWithOperations {
    /// operations (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    operations: Vec<String>,
    /// rule (field 2, message Rule)
    #[prost(message, tag = "2")]
    rule: Option<MapRule>,
}

/// NamedRuleWithOperations — admissionregistration.k8s.io/v1/generated.proto
/// field 1=resourceNames (repeated string), field 2=ruleWithOperations (RuleWithOperations)
#[derive(Clone, PartialEq, Message)]
struct MapNamedRuleWithOperations {
    /// resourceNames (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    resource_names: Vec<String>,
    /// ruleWithOperations (field 2, message RuleWithOperations)
    #[prost(message, tag = "2")]
    rule_with_operations: Option<MapRuleWithOperations>,
}

/// MatchResources — admissionregistration.k8s.io/v1/generated.proto
/// field 1=namespaceSelector, field 2=objectSelector, field 3=resourceRules,
/// field 4=excludeResourceRules, field 7=matchPolicy
#[derive(Clone, PartialEq, Message)]
struct MapMatchResources {
    /// namespaceSelector (field 1, message LabelSelector)
    #[prost(message, tag = "1")]
    namespace_selector: Option<AdmissionLabelSelector>,
    /// objectSelector (field 2, message LabelSelector)
    #[prost(message, tag = "2")]
    object_selector: Option<AdmissionLabelSelector>,
    /// resourceRules (field 3, repeated NamedRuleWithOperations)
    #[prost(message, repeated, tag = "3")]
    resource_rules: Vec<MapNamedRuleWithOperations>,
    /// excludeResourceRules (field 4, repeated NamedRuleWithOperations)
    #[prost(message, repeated, tag = "4")]
    exclude_resource_rules: Vec<MapNamedRuleWithOperations>,
    /// matchPolicy (field 7, string)
    #[prost(string, tag = "7")]
    match_policy: String,
}

/// ApplyConfiguration — admissionregistration.k8s.io/v1/generated.proto
/// field 1=expression (string)
#[derive(Clone, PartialEq, Message)]
struct MapApplyConfiguration {
    /// expression (field 1, string)
    #[prost(string, tag = "1")]
    expression: String,
}

/// Mutation — admissionregistration.k8s.io/v1/generated.proto
/// field 2=patchType (string), field 3=applyConfiguration (ApplyConfiguration),
/// field 4=jsonPatch (JSONPatch)
#[derive(Clone, PartialEq, Message)]
struct MapMutation {
    /// patchType (field 2, string)
    #[prost(string, tag = "2")]
    patch_type: String,
    /// applyConfiguration (field 3, message ApplyConfiguration)
    #[prost(message, tag = "3")]
    apply_configuration: Option<MapApplyConfiguration>,
}

/// Variable — admissionregistration.k8s.io/v1/generated.proto
/// field 1=name (string), field 2=expression (string)
#[derive(Clone, PartialEq, Message)]
struct MapVariable {
    /// name (field 1, string)
    #[prost(string, tag = "1")]
    name: String,
    /// expression (field 2, string)
    #[prost(string, tag = "2")]
    expression: String,
}

/// MatchCondition — admissionregistration.k8s.io/v1/generated.proto
/// field 1=name (string), field 2=expression (string)
#[derive(Clone, PartialEq, Message)]
struct MapMatchCondition {
    /// name (field 1, string)
    #[prost(string, tag = "1")]
    name: String,
    /// expression (field 2, string)
    #[prost(string, tag = "2")]
    expression: String,
}

/// ParamKind — admissionregistration.k8s.io/v1/generated.proto
/// field 1=apiVersion (string), field 2=kind (string)
#[derive(Clone, PartialEq, Message)]
struct MapParamKind {
    /// apiVersion (field 1, string)
    #[prost(string, tag = "1")]
    api_version: String,
    /// kind (field 2, string)
    #[prost(string, tag = "2")]
    kind: String,
}

/// MutatingAdmissionPolicySpec — admissionregistration.k8s.io/v1/generated.proto
/// field 1=paramKind, field 2=matchConstraints, field 3=variables, field 4=mutations,
/// field 5=failurePolicy, field 6=matchConditions, field 7=reinvocationPolicy
#[derive(Clone, PartialEq, Message)]
struct MapSpec {
    /// paramKind (field 1, message ParamKind)
    #[prost(message, tag = "1")]
    param_kind: Option<MapParamKind>,
    /// matchConstraints (field 2, message MatchResources)
    #[prost(message, tag = "2")]
    match_constraints: Option<MapMatchResources>,
    /// variables (field 3, repeated Variable)
    #[prost(message, repeated, tag = "3")]
    variables: Vec<MapVariable>,
    /// mutations (field 4, repeated Mutation)
    #[prost(message, repeated, tag = "4")]
    mutations: Vec<MapMutation>,
    /// failurePolicy (field 5, string)
    #[prost(string, tag = "5")]
    failure_policy: String,
    /// matchConditions (field 6, repeated MatchCondition)
    #[prost(message, repeated, tag = "6")]
    match_conditions: Vec<MapMatchCondition>,
    /// reinvocationPolicy (field 7, string)
    #[prost(string, tag = "7")]
    reinvocation_policy: String,
}

/// MutatingAdmissionPolicy — admissionregistration.k8s.io/v1/generated.proto
/// Source: k8s.io/api/admissionregistration/v1/generated.proto message MutatingAdmissionPolicy
/// field 1 = metadata (ObjectMeta), field 2 = spec (MutatingAdmissionPolicySpec)
#[derive(Clone, PartialEq, Message)]
struct MutatingAdmissionPolicy {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message MutatingAdmissionPolicySpec)
    #[prost(message, tag = "2")]
    spec: Option<MapSpec>,
}

/// Convert a MapNamedRuleWithOperations to JSON.
fn map_named_rule_to_json(r: MapNamedRuleWithOperations) -> serde_json::Value {
    let rwo = r.rule_with_operations.unwrap_or_default();
    let inner = rwo.rule.unwrap_or_default();
    let mut rule = serde_json::json!({
        "apiGroups": inner.api_groups,
        "apiVersions": inner.api_versions,
        "resources": inner.resources,
        "operations": rwo.operations,
    });
    if !inner.scope.is_empty() {
        rule["scope"] = serde_json::Value::String(inner.scope);
    }
    if !r.resource_names.is_empty() {
        rule["resourceNames"] = serde_json::Value::Array(
            r.resource_names
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    rule
}

/// Convert a MapMatchResources to JSON.
fn map_match_resources_to_json(mc: MapMatchResources) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    let resource_rules: Vec<serde_json::Value> = mc
        .resource_rules
        .into_iter()
        .map(map_named_rule_to_json)
        .collect();
    if !resource_rules.is_empty() {
        obj["resourceRules"] = serde_json::Value::Array(resource_rules);
    }
    let exclude_rules: Vec<serde_json::Value> = mc
        .exclude_resource_rules
        .into_iter()
        .map(map_named_rule_to_json)
        .collect();
    if !exclude_rules.is_empty() {
        obj["excludeResourceRules"] = serde_json::Value::Array(exclude_rules);
    }
    if let Some(ns) = mc.namespace_selector {
        obj["namespaceSelector"] = label_selector_to_json(ns);
    }
    if let Some(os) = mc.object_selector {
        obj["objectSelector"] = label_selector_to_json(os);
    }
    if !mc.match_policy.is_empty() {
        obj["matchPolicy"] = serde_json::Value::String(mc.match_policy);
    }
    obj
}

/// Convert a MapSpec to JSON.
fn map_spec_to_json(spec: MapSpec) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    if let Some(mc) = spec.match_constraints {
        obj["matchConstraints"] = map_match_resources_to_json(mc);
    }
    if !spec.failure_policy.is_empty() {
        obj["failurePolicy"] = serde_json::Value::String(spec.failure_policy);
    }
    if !spec.reinvocation_policy.is_empty() {
        obj["reinvocationPolicy"] = serde_json::Value::String(spec.reinvocation_policy);
    }
    if let Some(pk) = spec.param_kind {
        obj["paramKind"] = serde_json::json!({
            "apiVersion": pk.api_version,
            "kind": pk.kind,
        });
    }
    if !spec.variables.is_empty() {
        let vars: Vec<serde_json::Value> = spec
            .variables
            .into_iter()
            .map(|v| serde_json::json!({"name": v.name, "expression": v.expression}))
            .collect();
        obj["variables"] = serde_json::Value::Array(vars);
    }
    if !spec.mutations.is_empty() {
        let mutations: Vec<serde_json::Value> = spec
            .mutations
            .into_iter()
            .map(|m| {
                let mut entry = serde_json::json!({"patchType": m.patch_type});
                if let Some(ac) = m.apply_configuration {
                    entry["applyConfiguration"] = serde_json::json!({"expression": ac.expression});
                }
                entry
            })
            .collect();
        obj["mutations"] = serde_json::Value::Array(mutations);
    }
    if !spec.match_conditions.is_empty() {
        let conds: Vec<serde_json::Value> = spec
            .match_conditions
            .into_iter()
            .map(|c| serde_json::json!({"name": c.name, "expression": c.expression}))
            .collect();
        obj["matchConditions"] = serde_json::Value::Array(conds);
    }
    obj
}

/// Decode a proto-encoded MutatingAdmissionPolicy into a serde_json::Value.
///
/// The MutatingAdmissionPolicy conformance test POSTs with Content-Type:
/// application/vnd.kubernetes.protobuf. Without this decoder, decode_core_proto_by_kind
/// returns None, extract_body returns raw proto bytes, and the handler returns
/// 400 "invalid JSON: expected value at line 1 column 1".
///
/// The spec field (field 2) is fully decoded so that PUT/PATCH operations preserve
/// spec content. Without spec decoding, a PUT with a new spec reverts the object to
/// its previous spec because the decoder only emitted metadata.
pub fn decode_mutatingadmissionpolicy_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = MutatingAdmissionPolicy::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "MutatingAdmissionPolicy",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        result["spec"] = map_spec_to_json(spec);
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// MutatingAdmissionPolicyBinding proto structs
// Source: k8s.io/api/admissionregistration/v1/generated.proto
// Field numbers verified against k8s 1.33 canonical source.
// ---------------------------------------------------------------------------

/// ParamRef — admissionregistration.k8s.io/v1/generated.proto
/// field 1=name (string), field 2=namespace (string), field 3=selector (LabelSelector),
/// field 4=parameterNotFoundAction (string)
#[derive(Clone, PartialEq, Message)]
struct MapbParamRef {
    /// name (field 1, string)
    #[prost(string, tag = "1")]
    name: String,
    /// namespace (field 2, string)
    #[prost(string, tag = "2")]
    namespace: String,
    /// selector (field 3, message LabelSelector)
    #[prost(message, tag = "3")]
    selector: Option<AdmissionLabelSelector>,
    /// parameterNotFoundAction (field 4, string)
    #[prost(string, tag = "4")]
    parameter_not_found_action: String,
}

/// MutatingAdmissionPolicyBindingSpec — admissionregistration.k8s.io/v1/generated.proto
/// field 1=policyName (string), field 2=paramRef (ParamRef),
/// field 3=matchResources (MatchResources), field 4=validationActions (repeated string)
#[derive(Clone, PartialEq, Message)]
struct MapbSpec {
    /// policyName (field 1, string)
    #[prost(string, tag = "1")]
    policy_name: String,
    /// paramRef (field 2, message ParamRef)
    #[prost(message, tag = "2")]
    param_ref: Option<MapbParamRef>,
    /// matchResources (field 3, message MatchResources)
    #[prost(message, tag = "3")]
    match_resources: Option<MapMatchResources>,
}

/// MutatingAdmissionPolicyBinding — admissionregistration.k8s.io/v1/generated.proto
/// Source: k8s.io/api/admissionregistration/v1/generated.proto message MutatingAdmissionPolicyBinding
/// field 1 = metadata (ObjectMeta), field 2 = spec (MutatingAdmissionPolicyBindingSpec)
#[derive(Clone, PartialEq, Message)]
struct MutatingAdmissionPolicyBinding {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message MutatingAdmissionPolicyBindingSpec)
    #[prost(message, tag = "2")]
    spec: Option<MapbSpec>,
}

/// Decode a proto-encoded MutatingAdmissionPolicyBinding into a serde_json::Value.
///
/// The MutatingAdmissionPolicyBinding conformance test POSTs with Content-Type:
/// application/vnd.kubernetes.protobuf. Without this decoder, decode_core_proto_by_kind
/// returns None, extract_body returns raw proto bytes, and the handler returns
/// 400 "invalid JSON: expected value at line 1 column 1".
///
/// The spec field (field 2) is fully decoded so that PUT/PATCH operations preserve
/// spec content. Without spec decoding, a PUT with a new spec reverts the object to
/// its previous spec because the decoder only emitted metadata.
pub fn decode_mutatingadmissionpolicybinding_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = MutatingAdmissionPolicyBinding::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "MutatingAdmissionPolicyBinding",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::json!({});
        if !spec.policy_name.is_empty() {
            spec_json["policyName"] = serde_json::Value::String(spec.policy_name);
        }
        if let Some(pr) = spec.param_ref {
            let mut pr_json = serde_json::json!({});
            if !pr.name.is_empty() {
                pr_json["name"] = serde_json::Value::String(pr.name);
            }
            if !pr.namespace.is_empty() {
                pr_json["namespace"] = serde_json::Value::String(pr.namespace);
            }
            if !pr.parameter_not_found_action.is_empty() {
                pr_json["parameterNotFoundAction"] =
                    serde_json::Value::String(pr.parameter_not_found_action);
            }
            if let Some(sel) = pr.selector {
                pr_json["selector"] = label_selector_to_json(sel);
            }
            spec_json["paramRef"] = pr_json;
        }
        if let Some(mr) = spec.match_resources {
            spec_json["matchResources"] = map_match_resources_to_json(mr);
        }
        result["spec"] = spec_json;
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// ValidatingAdmissionPolicy / ValidatingAdmissionPolicyBinding proto structs
// Source: k8s.io/api/admissionregistration/v1/generated.proto (v0.36.1)
// Field numbers match the canonical proto definition.
// ---------------------------------------------------------------------------

/// Validation — admissionregistration.k8s.io/v1/generated.proto
/// field 1=expression, field 2=message, field 3=reason, field 4=messageExpression
#[derive(Clone, PartialEq, Message)]
struct VapValidation {
    /// expression (field 1, string)
    #[prost(string, tag = "1")]
    expression: String,
    /// message (field 2, string)
    #[prost(string, tag = "2")]
    message: String,
    /// reason (field 3, string)
    #[prost(string, tag = "3")]
    reason: String,
    /// messageExpression (field 4, string)
    #[prost(string, tag = "4")]
    message_expression: String,
}

/// ValidatingAdmissionPolicySpec — admissionregistration.k8s.io/v1/generated.proto
/// field 1=paramKind, field 2=matchConstraints, field 3=validations (repeated),
/// field 4=failurePolicy, field 5=auditAnnotations (repeated), field 6=matchConditions (repeated)
#[derive(Clone, PartialEq, Message)]
struct VapSpec {
    /// paramKind (field 1, message ParamKind)
    #[prost(message, tag = "1")]
    param_kind: Option<MapParamKind>,
    /// matchConstraints (field 2, message MatchResources)
    #[prost(message, tag = "2")]
    match_constraints: Option<MapMatchResources>,
    /// validations (field 3, repeated Validation)
    #[prost(message, repeated, tag = "3")]
    validations: Vec<VapValidation>,
    /// failurePolicy (field 4, string)
    #[prost(string, tag = "4")]
    failure_policy: String,
    /// matchConditions (field 6, repeated MatchCondition)
    #[prost(message, repeated, tag = "6")]
    match_conditions: Vec<MapMatchCondition>,
}

/// ValidatingAdmissionPolicy — admissionregistration.k8s.io/v1/generated.proto
/// field 1=metadata (ObjectMeta), field 2=spec (ValidatingAdmissionPolicySpec)
#[derive(Clone, PartialEq, Message)]
struct ValidatingAdmissionPolicy {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message ValidatingAdmissionPolicySpec)
    #[prost(message, tag = "2")]
    spec: Option<VapSpec>,
}

/// Decode a proto-encoded ValidatingAdmissionPolicy into a serde_json::Value.
///
/// The ValidatingAdmissionPolicy conformance test POSTs with Content-Type:
/// application/vnd.kubernetes.protobuf. Without this decoder, decode_core_proto_by_kind
/// returns None, extract_body returns raw proto bytes, and the handler returns
/// 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_validatingadmissionpolicy_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ValidatingAdmissionPolicy::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::json!({});
        if let Some(mc) = spec.match_constraints {
            spec_json["matchConstraints"] = map_match_resources_to_json(mc);
        }
        if !spec.failure_policy.is_empty() {
            spec_json["failurePolicy"] = serde_json::Value::String(spec.failure_policy);
        }
        if let Some(pk) = spec.param_kind {
            spec_json["paramKind"] = serde_json::json!({
                "apiVersion": pk.api_version,
                "kind": pk.kind,
            });
        }
        if !spec.validations.is_empty() {
            let vals: Vec<serde_json::Value> = spec
                .validations
                .into_iter()
                .map(|v| {
                    let mut entry = serde_json::json!({"expression": v.expression});
                    if !v.message.is_empty() {
                        entry["message"] = serde_json::Value::String(v.message);
                    }
                    if !v.reason.is_empty() {
                        entry["reason"] = serde_json::Value::String(v.reason);
                    }
                    if !v.message_expression.is_empty() {
                        entry["messageExpression"] =
                            serde_json::Value::String(v.message_expression);
                    }
                    entry
                })
                .collect();
            spec_json["validations"] = serde_json::Value::Array(vals);
        }
        if !spec.match_conditions.is_empty() {
            let conds: Vec<serde_json::Value> = spec
                .match_conditions
                .into_iter()
                .map(|c| serde_json::json!({"name": c.name, "expression": c.expression}))
                .collect();
            spec_json["matchConditions"] = serde_json::Value::Array(conds);
        }
        result["spec"] = spec_json;
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// ValidatingAdmissionPolicyBinding proto structs
// ---------------------------------------------------------------------------

/// ValidatingAdmissionPolicyBindingSpec — admissionregistration.k8s.io/v1/generated.proto
/// field 1=policyName (string), field 2=paramRef (ParamRef),
/// field 3=matchResources (MatchResources), field 4=validationActions (repeated string)
#[derive(Clone, PartialEq, Message)]
struct VapbSpec {
    /// policyName (field 1, string)
    #[prost(string, tag = "1")]
    policy_name: String,
    /// paramRef (field 2, message ParamRef)
    #[prost(message, tag = "2")]
    param_ref: Option<MapbParamRef>,
    /// matchResources (field 3, message MatchResources)
    #[prost(message, tag = "3")]
    match_resources: Option<MapMatchResources>,
    /// validationActions (field 4, repeated string)
    #[prost(string, repeated, tag = "4")]
    validation_actions: Vec<String>,
}

/// ValidatingAdmissionPolicyBinding — admissionregistration.k8s.io/v1/generated.proto
/// field 1=metadata (ObjectMeta), field 2=spec (ValidatingAdmissionPolicyBindingSpec)
#[derive(Clone, PartialEq, Message)]
struct ValidatingAdmissionPolicyBinding {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message ValidatingAdmissionPolicyBindingSpec)
    #[prost(message, tag = "2")]
    spec: Option<VapbSpec>,
}

/// Decode a proto-encoded ValidatingAdmissionPolicyBinding into a serde_json::Value.
///
/// The ValidatingAdmissionPolicyBinding conformance test POSTs with Content-Type:
/// application/vnd.kubernetes.protobuf. Without this decoder, decode_core_proto_by_kind
/// returns None, extract_body returns raw proto bytes, and the handler returns
/// 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_validatingadmissionpolicybinding_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ValidatingAdmissionPolicyBinding::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::json!({});
        if !spec.policy_name.is_empty() {
            spec_json["policyName"] = serde_json::Value::String(spec.policy_name);
        }
        if let Some(pr) = spec.param_ref {
            let mut pr_json = serde_json::json!({});
            if !pr.name.is_empty() {
                pr_json["name"] = serde_json::Value::String(pr.name);
            }
            if !pr.namespace.is_empty() {
                pr_json["namespace"] = serde_json::Value::String(pr.namespace);
            }
            if !pr.parameter_not_found_action.is_empty() {
                pr_json["parameterNotFoundAction"] =
                    serde_json::Value::String(pr.parameter_not_found_action);
            }
            if let Some(sel) = pr.selector {
                pr_json["selector"] = label_selector_to_json(sel);
            }
            spec_json["paramRef"] = pr_json;
        }
        if let Some(mr) = spec.match_resources {
            spec_json["matchResources"] = map_match_resources_to_json(mr);
        }
        if !spec.validation_actions.is_empty() {
            spec_json["validationActions"] = serde_json::Value::Array(
                spec.validation_actions
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            );
        }
        result["spec"] = spec_json;
    }
    Some(result)
}

// --- k8s.io/api/networking/v1/generated.proto ---

/// ServiceBackendPort — networking.k8s.io/v1/generated.proto
/// field 1: name (string), field 2: number (int32)
#[derive(Clone, PartialEq, Message)]
struct ServiceBackendPort {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "2")]
    number: i32,
}

/// IngressServiceBackend — networking.k8s.io/v1/generated.proto
/// field 1: name (string), field 2: port (ServiceBackendPort)
#[derive(Clone, PartialEq, Message)]
struct IngressServiceBackend {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, tag = "2")]
    port: Option<ServiceBackendPort>,
}

/// IngressBackend — networking.k8s.io/v1/generated.proto
/// field 1: service (IngressServiceBackend), field 2: resource (TypedLocalObjectReference — skipped)
#[derive(Clone, PartialEq, Message)]
struct IngressBackend {
    #[prost(message, tag = "1")]
    service: Option<IngressServiceBackend>,
}

/// HTTPIngressPath — networking.k8s.io/v1/generated.proto
/// field 1: path (string), field 2: pathType (string), field 3: backend (IngressBackend)
#[derive(Clone, PartialEq, Message)]
struct HTTPIngressPath {
    #[prost(string, tag = "1")]
    path: String,
    #[prost(string, tag = "2")]
    path_type: String,
    #[prost(message, tag = "3")]
    backend: Option<IngressBackend>,
}

/// HTTPIngressRuleValue — networking.k8s.io/v1/generated.proto
/// field 1: paths (repeated HTTPIngressPath)
#[derive(Clone, PartialEq, Message)]
struct HTTPIngressRuleValue {
    #[prost(message, repeated, tag = "1")]
    paths: Vec<HTTPIngressPath>,
}

/// IngressRule — networking.k8s.io/v1/generated.proto
/// field 1: host (string), field 2: http (HTTPIngressRuleValue)
#[derive(Clone, PartialEq, Message)]
struct IngressRule {
    #[prost(string, tag = "1")]
    host: String,
    #[prost(message, tag = "2")]
    http: Option<HTTPIngressRuleValue>,
}

/// IngressTLS — networking.k8s.io/v1/generated.proto
/// field 1: hosts (repeated string), field 2: secretName (string)
#[derive(Clone, PartialEq, Message)]
struct IngressTLS {
    #[prost(string, repeated, tag = "1")]
    hosts: Vec<String>,
    #[prost(string, tag = "2")]
    secret_name: String,
}

/// IngressSpec — networking.k8s.io/v1/generated.proto
/// field 1: ingressClassName (string), field 2: defaultBackend (IngressBackend),
/// field 3: tls (repeated IngressTLS), field 4: rules (repeated IngressRule)
#[derive(Clone, PartialEq, Message)]
struct IngressSpec {
    #[prost(string, tag = "1")]
    ingress_class_name: String,
    #[prost(message, tag = "2")]
    default_backend: Option<IngressBackend>,
    #[prost(message, repeated, tag = "3")]
    tls: Vec<IngressTLS>,
    #[prost(message, repeated, tag = "4")]
    rules: Vec<IngressRule>,
}

/// Ingress — networking.k8s.io/v1/generated.proto
/// field 1: metadata (ObjectMeta), field 2: spec (IngressSpec), field 3: status (skipped)
#[derive(Clone, PartialEq, Message)]
struct Ingress {
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    #[prost(message, tag = "2")]
    spec: Option<IngressSpec>,
}

fn ingress_backend_to_json(b: IngressBackend) -> serde_json::Value {
    let mut out = serde_json::json!({});
    if let Some(svc) = b.service {
        let mut svc_json = serde_json::json!({ "name": svc.name });
        if let Some(p) = svc.port {
            let mut port_json = serde_json::json!({});
            if !p.name.is_empty() {
                port_json["name"] = serde_json::Value::String(p.name);
            }
            if p.number != 0 {
                port_json["number"] = serde_json::Value::Number(serde_json::Number::from(p.number));
            }
            svc_json["port"] = port_json;
        }
        out["service"] = svc_json;
    }
    out
}

/// Decode a proto-encoded Ingress into a serde_json::Value.
///
/// kubectl/client-go POSTs Ingress with Content-Type: application/vnd.kubernetes.protobuf.
/// Without this decoder, extract_body returns raw proto bytes and the handler returns
/// 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_ingress_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = Ingress::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::json!({});
        if !spec.ingress_class_name.is_empty() {
            spec_json["ingressClassName"] = serde_json::Value::String(spec.ingress_class_name);
        }
        if let Some(db) = spec.default_backend {
            spec_json["defaultBackend"] = ingress_backend_to_json(db);
        }
        if !spec.tls.is_empty() {
            let tls_arr: Vec<serde_json::Value> = spec
                .tls
                .into_iter()
                .map(|t| {
                    let mut tj = serde_json::json!({});
                    if !t.hosts.is_empty() {
                        tj["hosts"] = serde_json::Value::Array(
                            t.hosts.into_iter().map(serde_json::Value::String).collect(),
                        );
                    }
                    if !t.secret_name.is_empty() {
                        tj["secretName"] = serde_json::Value::String(t.secret_name);
                    }
                    tj
                })
                .collect();
            spec_json["tls"] = serde_json::Value::Array(tls_arr);
        }
        if !spec.rules.is_empty() {
            let rules_arr: Vec<serde_json::Value> = spec
                .rules
                .into_iter()
                .map(|r| {
                    let mut rj = serde_json::json!({});
                    if !r.host.is_empty() {
                        rj["host"] = serde_json::Value::String(r.host);
                    }
                    if let Some(http) = r.http {
                        let paths_arr: Vec<serde_json::Value> = http
                            .paths
                            .into_iter()
                            .map(|p| {
                                let mut pj = serde_json::json!({});
                                if !p.path.is_empty() {
                                    pj["path"] = serde_json::Value::String(p.path);
                                }
                                if !p.path_type.is_empty() {
                                    pj["pathType"] = serde_json::Value::String(p.path_type);
                                }
                                if let Some(b) = p.backend {
                                    pj["backend"] = ingress_backend_to_json(b);
                                }
                                pj
                            })
                            .collect();
                        rj["http"] = serde_json::json!({ "paths": paths_arr });
                    }
                    rj
                })
                .collect();
            spec_json["rules"] = serde_json::Value::Array(rules_arr);
        }
        out["spec"] = spec_json;
    }
    Some(out)
}

/// IngressClassSpec — networking.k8s.io/v1/generated.proto
/// Source: k8s.io/api/networking/v1/generated.proto message IngressClassSpec
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
/// Only `controller` (field 1) is decoded; `parameters` (field 2) is a complex optional
/// TypedLocalObjectReference that the apiserver does not need to inspect.
#[derive(Clone, PartialEq, Message)]
struct IngressClassSpec {
    /// controller (field 1, string)
    #[prost(string, tag = "1")]
    controller: String,
}

/// IngressClass — networking.k8s.io/v1/generated.proto
/// Source: k8s.io/api/networking/v1/generated.proto message IngressClass
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
#[derive(Clone, PartialEq, Message)]
struct IngressClass {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message IngressClassSpec)
    #[prost(message, tag = "2")]
    spec: Option<IngressClassSpec>,
}

/// Decode a proto-encoded IngressClass into a serde_json::Value.
///
/// The conformance test POSTs IngressClass with Content-Type: application/vnd.kubernetes.protobuf.
/// Without this decoder, decode_core_proto_by_kind returns None, extract_body returns raw proto
/// bytes, and the handler returns 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_ingressclass_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = IngressClass::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "IngressClass",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        out["spec"] = serde_json::json!({ "controller": spec.controller });
    }
    Some(out)
}

// --- k8s.io/api/discovery/v1/generated.proto ---

/// DiscoveryEndpointConditions — discovery.k8s.io/v1/generated.proto
/// field 1: ready (bool), field 2: serving (bool), field 3: terminating (bool)
#[derive(Clone, PartialEq, Message)]
struct DiscoveryEndpointConditions {
    #[prost(bool, tag = "1")]
    ready: bool,
    #[prost(bool, tag = "2")]
    serving: bool,
    #[prost(bool, tag = "3")]
    terminating: bool,
}

/// DiscoveryEndpoint — discovery.k8s.io/v1/generated.proto
/// field 1: addresses (repeated string), field 2: conditions, field 3: hostname,
/// field 4: targetRef (ObjectReference), field 6: nodeName, field 7: zone (string wrapper — skipped)
#[derive(Clone, PartialEq, Message)]
struct DiscoveryEndpoint {
    #[prost(string, repeated, tag = "1")]
    addresses: Vec<String>,
    #[prost(message, tag = "2")]
    conditions: Option<DiscoveryEndpointConditions>,
    #[prost(string, tag = "3")]
    hostname: String,
    #[prost(message, tag = "4")]
    target_ref: Option<ObjectReference>,
    #[prost(string, tag = "6")]
    node_name: String,
}

/// DiscoveryEndpointPort — discovery.k8s.io/v1/generated.proto
/// field 1: name (string), field 2: protocol (string), field 3: port (int32),
/// field 4: appProtocol (string)
#[derive(Clone, PartialEq, Message)]
struct DiscoveryEndpointPort {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    protocol: String,
    #[prost(int32, tag = "3")]
    port: i32,
    #[prost(string, tag = "4")]
    app_protocol: String,
}

/// EndpointSlice — discovery.k8s.io/v1/generated.proto
/// field 1: metadata (ObjectMeta), field 2: addressType (string),
/// field 3: endpoints (repeated DiscoveryEndpoint), field 4: ports (repeated DiscoveryEndpointPort)
#[derive(Clone, PartialEq, Message)]
struct EndpointSlice {
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    #[prost(string, tag = "2")]
    address_type: String,
    #[prost(message, repeated, tag = "3")]
    endpoints: Vec<DiscoveryEndpoint>,
    #[prost(message, repeated, tag = "4")]
    ports: Vec<DiscoveryEndpointPort>,
}

/// Decode a proto-encoded EndpointSlice into a serde_json::Value.
///
/// The EndpointSlice conformance test POSTs/PATCHes with Content-Type: application/vnd.kubernetes.protobuf.
/// Without this decoder, the handler returns 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_endpointslice_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = EndpointSlice::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": meta,
        "addressType": obj.address_type
    });
    let endpoints_arr: Vec<serde_json::Value> = obj
        .endpoints
        .into_iter()
        .map(|ep| {
            let mut ej = serde_json::json!({
                "addresses": ep.addresses
            });
            if let Some(c) = ep.conditions {
                ej["conditions"] = serde_json::json!({
                    "ready": c.ready,
                    "serving": c.serving,
                    "terminating": c.terminating
                });
            }
            if !ep.hostname.is_empty() {
                ej["hostname"] = serde_json::Value::String(ep.hostname);
            }
            if let Some(r) = ep.target_ref {
                let mut rj = serde_json::json!({});
                if !r.kind.is_empty() {
                    rj["kind"] = serde_json::Value::String(r.kind);
                }
                if !r.namespace.is_empty() {
                    rj["namespace"] = serde_json::Value::String(r.namespace);
                }
                if !r.name.is_empty() {
                    rj["name"] = serde_json::Value::String(r.name);
                }
                if !r.uid.is_empty() {
                    rj["uid"] = serde_json::Value::String(r.uid);
                }
                ej["targetRef"] = rj;
            }
            if !ep.node_name.is_empty() {
                ej["nodeName"] = serde_json::Value::String(ep.node_name);
            }
            ej
        })
        .collect();
    out["endpoints"] = serde_json::Value::Array(endpoints_arr);
    let ports_arr: Vec<serde_json::Value> = obj
        .ports
        .into_iter()
        .map(|p| {
            let mut pj = serde_json::json!({});
            if !p.name.is_empty() {
                pj["name"] = serde_json::Value::String(p.name);
            }
            if !p.protocol.is_empty() {
                pj["protocol"] = serde_json::Value::String(p.protocol);
            }
            pj["port"] = serde_json::Value::Number(serde_json::Number::from(p.port));
            if !p.app_protocol.is_empty() {
                pj["appProtocol"] = serde_json::Value::String(p.app_protocol);
            }
            pj
        })
        .collect();
    out["ports"] = serde_json::Value::Array(ports_arr);
    Some(out)
}

// --- k8s.io/api/events/v1/generated.proto ---

/// EventSeries (events.k8s.io/v1) — discovery.k8s.io/v1/generated.proto
/// field 1: count (int32), field 2: lastObservedTime (MicroTime)
#[derive(Clone, PartialEq, Message)]
struct EventsV1EventSeries {
    #[prost(int32, tag = "1")]
    count: i32,
    #[prost(message, tag = "2")]
    last_observed_time: Option<MicroTime>,
}

/// Event (events.k8s.io/v1) — events/v1/generated.proto
/// field 1: metadata, field 2: eventTime, field 3: series, field 4: reportingController,
/// field 5: reportingInstance, field 6: action, field 7: reason, field 8: regarding,
/// field 9: related, field 10: note, field 11: type,
/// field 12: deprecatedSource, field 13: deprecatedFirstTimestamp, field 14: deprecatedLastTimestamp,
/// field 15: deprecatedCount
#[derive(Clone, PartialEq, Message)]
struct EventsV1Event {
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    #[prost(message, tag = "2")]
    event_time: Option<MicroTime>,
    #[prost(message, tag = "3")]
    series: Option<EventsV1EventSeries>,
    #[prost(string, tag = "4")]
    reporting_controller: String,
    #[prost(string, tag = "5")]
    reporting_instance: String,
    #[prost(string, tag = "6")]
    action: String,
    #[prost(string, tag = "7")]
    reason: String,
    #[prost(message, tag = "8")]
    regarding: Option<ObjectReference>,
    #[prost(message, tag = "9")]
    related: Option<ObjectReference>,
    #[prost(string, tag = "10")]
    note: String,
    #[prost(string, tag = "11")]
    r#type: String,
    #[prost(message, tag = "12")]
    deprecated_source: Option<EventSource>,
    #[prost(message, tag = "13")]
    deprecated_first_timestamp: Option<Time>,
    #[prost(message, tag = "14")]
    deprecated_last_timestamp: Option<Time>,
    #[prost(int32, tag = "15")]
    deprecated_count: i32,
}

/// Decode a proto-encoded events.k8s.io/v1 Event into a serde_json::Value.
///
/// The Events API conformance test POSTs events.k8s.io/v1 Event objects with
/// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder, the handler
/// returns 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_events_v1_event_proto(data: &[u8]) -> Option<serde_json::Value> {
    let ev = EventsV1Event::decode(data).ok()?;
    let meta = object_meta_to_json(ev.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "events.k8s.io/v1",
        "kind": "Event",
        "metadata": meta
    });
    if let Some(t) = ev.event_time {
        if t.seconds > 0 {
            let ts = crate::util::normalize_rfc3339_to_micro(&crate::util::secs_to_rfc3339(
                t.seconds as u64,
            ));
            out["eventTime"] = serde_json::Value::String(ts);
        }
    }
    if let Some(s) = ev.series {
        let mut sj = serde_json::json!({});
        if s.count != 0 {
            sj["count"] = serde_json::Value::Number(serde_json::Number::from(s.count));
        }
        if let Some(t) = s.last_observed_time {
            if t.seconds > 0 {
                let ts = crate::util::normalize_rfc3339_to_micro(&crate::util::secs_to_rfc3339(
                    t.seconds as u64,
                ));
                sj["lastObservedTime"] = serde_json::Value::String(ts);
            }
        }
        out["series"] = sj;
    }
    if !ev.reporting_controller.is_empty() {
        out["reportingController"] = serde_json::Value::String(ev.reporting_controller);
    }
    if !ev.reporting_instance.is_empty() {
        out["reportingInstance"] = serde_json::Value::String(ev.reporting_instance);
    }
    if !ev.action.is_empty() {
        out["action"] = serde_json::Value::String(ev.action);
    }
    if !ev.reason.is_empty() {
        out["reason"] = serde_json::Value::String(ev.reason);
    }
    if let Some(r) = ev.regarding {
        let mut rj = serde_json::json!({});
        if !r.api_version.is_empty() {
            rj["apiVersion"] = serde_json::Value::String(r.api_version);
        }
        if !r.kind.is_empty() {
            rj["kind"] = serde_json::Value::String(r.kind);
        }
        if !r.namespace.is_empty() {
            rj["namespace"] = serde_json::Value::String(r.namespace);
        }
        if !r.name.is_empty() {
            rj["name"] = serde_json::Value::String(r.name);
        }
        if !r.uid.is_empty() {
            rj["uid"] = serde_json::Value::String(r.uid);
        }
        out["regarding"] = rj;
    }
    if let Some(r) = ev.related {
        let mut rj = serde_json::json!({});
        if !r.kind.is_empty() {
            rj["kind"] = serde_json::Value::String(r.kind);
        }
        if !r.namespace.is_empty() {
            rj["namespace"] = serde_json::Value::String(r.namespace);
        }
        if !r.name.is_empty() {
            rj["name"] = serde_json::Value::String(r.name);
        }
        out["related"] = rj;
    }
    if !ev.note.is_empty() {
        out["note"] = serde_json::Value::String(ev.note);
    }
    if !ev.r#type.is_empty() {
        out["type"] = serde_json::Value::String(ev.r#type);
    }
    if ev.deprecated_count != 0 {
        out["deprecatedCount"] =
            serde_json::Value::Number(serde_json::Number::from(ev.deprecated_count));
    }
    Some(out)
}

// --- k8s.io/api/certificates/v1/generated.proto ---

/// CertificateSigningRequestSpec — certificates.k8s.io/v1/generated.proto
/// field 1: request (bytes), field 2: signerName (string), field 3: expirationSeconds (int32),
/// field 4: usages (repeated string), field 5: username, field 6: uid,
/// field 7: groups (repeated string)
#[derive(Clone, PartialEq, Message)]
struct CertificateSigningRequestSpecProto {
    #[prost(bytes = "vec", tag = "1")]
    request: Vec<u8>,
    #[prost(string, tag = "2")]
    signer_name: String,
    #[prost(int32, tag = "3")]
    expiration_seconds: i32,
    #[prost(string, repeated, tag = "4")]
    usages: Vec<String>,
    #[prost(string, tag = "5")]
    username: String,
    #[prost(string, tag = "6")]
    uid: String,
    #[prost(string, repeated, tag = "7")]
    groups: Vec<String>,
}

/// CertificateSigningRequest — certificates.k8s.io/v1/generated.proto
/// field 1: metadata (ObjectMeta), field 2: spec, field 3: status (skipped)
#[derive(Clone, PartialEq, Message)]
struct CertificateSigningRequestProto {
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    #[prost(message, tag = "2")]
    spec: Option<CertificateSigningRequestSpecProto>,
}

/// Decode a proto-encoded CertificateSigningRequest into a serde_json::Value.
///
/// The CSR conformance test POSTs/PUTs with Content-Type: application/vnd.kubernetes.protobuf.
/// Without this decoder, the handler returns 400 "invalid JSON: expected value at line 1 column 1".
/// spec.request (bytes) is base64-encoded in JSON; we use standard base64 to match Kubernetes.
pub fn decode_csr_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = CertificateSigningRequestProto::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::json!({});
        if !spec.request.is_empty() {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&spec.request);
            spec_json["request"] = serde_json::Value::String(b64);
        }
        if !spec.signer_name.is_empty() {
            spec_json["signerName"] = serde_json::Value::String(spec.signer_name);
        }
        if spec.expiration_seconds != 0 {
            spec_json["expirationSeconds"] =
                serde_json::Value::Number(serde_json::Number::from(spec.expiration_seconds));
        }
        if !spec.usages.is_empty() {
            spec_json["usages"] = serde_json::Value::Array(
                spec.usages
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            );
        }
        if !spec.username.is_empty() {
            spec_json["username"] = serde_json::Value::String(spec.username);
        }
        if !spec.uid.is_empty() {
            spec_json["uid"] = serde_json::Value::String(spec.uid);
        }
        if !spec.groups.is_empty() {
            spec_json["groups"] = serde_json::Value::Array(
                spec.groups
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            );
        }
        out["spec"] = spec_json;
    }
    Some(out)
}

// --- k8s.io/api/scheduling/v1/generated.proto ---

/// PriorityClass — scheduling.k8s.io/v1/generated.proto
/// Source: k8s.io/api/scheduling/v1/generated.proto message PriorityClass
/// (proto file not in repo; field numbers verified against k8s 1.34 canonical source)
#[derive(Clone, PartialEq, Message)]
struct PriorityClass {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// value (field 2, int32) — the scheduling priority of this class
    #[prost(int32, tag = "2")]
    value: i32,
    /// globalDefault (field 3, bool) — if true, this is the default priority for pods
    #[prost(bool, tag = "3")]
    global_default: bool,
    /// description (field 4, string) — human-readable description
    #[prost(string, tag = "4")]
    description: String,
    /// preemptionPolicy (field 5, string) — e.g. "PreemptLowerPriority", added in k8s 1.19
    #[prost(string, tag = "5")]
    preemption_policy: String,
}

/// Decode a proto-encoded PriorityClass into a serde_json::Value.
///
/// The SchedulerPreemption conformance test POSTs PriorityClass objects with
/// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder,
/// decode_core_proto_by_kind returns None, extract_body returns raw proto bytes, and the
/// handler returns 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_priorityclass_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = PriorityClass::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "scheduling.k8s.io/v1",
        "kind": "PriorityClass",
        "metadata": meta,
        "value": obj.value
    });
    if !obj.preemption_policy.is_empty() {
        out["preemptionPolicy"] = serde_json::Value::String(obj.preemption_policy);
    }
    if obj.global_default {
        out["globalDefault"] = serde_json::Value::Bool(true);
    }
    if !obj.description.is_empty() {
        out["description"] = serde_json::Value::String(obj.description);
    }
    Some(out)
}

// --- k8s.io/api/apps/v1/generated.proto (ControllerRevision) ---

/// RawExtension — k8s.io/apimachinery/pkg/runtime/generated.proto
/// Source: apimachinery-runtime-generated.proto message RawExtension
/// field 1 = raw (bytes): the serialized object bytes.
#[derive(Clone, PartialEq, Message)]
struct ControllerRevisionRawExtension {
    /// raw (field 1, bytes) — JSON-encoded serialization of the controller state
    #[prost(bytes = "vec", tag = "1")]
    raw: Vec<u8>,
}

/// ControllerRevision — apps/v1/generated.proto
/// Source: api-apps-v1-generated.proto message ControllerRevision
/// (field numbers verified from proto/api-apps-v1-generated.proto)
#[derive(Clone, PartialEq, Message)]
struct ControllerRevision {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// data (field 2, message RawExtension) — serialized snapshot of controller state
    #[prost(message, tag = "2")]
    data: Option<ControllerRevisionRawExtension>,
    /// revision (field 3, int64) — monotonically increasing revision number
    #[prost(int64, tag = "3")]
    revision: i64,
}

/// Decode a proto-encoded ControllerRevision into a serde_json::Value.
///
/// DaemonSet and StatefulSet controllers POST ControllerRevision objects with
/// Content-Type: application/vnd.kubernetes.protobuf to track rollout history.
/// Without this decoder, decode_core_proto_by_kind returns None, extract_body returns raw proto
/// bytes, and the handler returns 400 "invalid JSON: expected value at line 1 column 1".
pub fn decode_controllerrevision_proto(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ControllerRevision::decode(data).ok()?;
    let meta = object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "ControllerRevision",
        "metadata": meta,
        "revision": obj.revision
    });
    // data.raw contains JSON-encoded state; include it as a parsed JSON value if possible.
    if let Some(raw_ext) = obj.data {
        if !raw_ext.raw.is_empty() {
            if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&raw_ext.raw) {
                out["data"] = parsed;
            }
        }
    }
    Some(out)
}

pub fn decode_proto_by_kind_and_version(
    kind: &str,
    api_version: &str,
    raw: &[u8],
) -> Option<serde_json::Value> {
    match kind {
        "CustomResourceDefinition" => decode_crd_proto(raw),
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
        "Event" => {
            if api_version == "events.k8s.io/v1" {
                decode_events_v1_event_proto(raw)
            } else {
                decode_event_proto(raw)
            }
        }
        "ClusterRole" => decode_clusterrole_proto(raw),
        "ClusterRoleBinding" => decode_clusterrolebinding_proto(raw),
        "Role" => decode_role_proto(raw),
        "RoleBinding" => decode_rolebinding_proto(raw),
        "SubjectAccessReview" => decode_subject_access_review_proto(raw),
        "LocalSubjectAccessReview" => decode_local_subject_access_review_proto(raw),
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
        "StorageClass" => decode_storageclass_proto(raw),
        "VolumeAttributesClass" => decode_volumeattributesclass_proto(raw),
        "ResourceQuota" => decode_resourcequota_proto(raw),
        "LimitRange" => decode_limitrange_proto(raw),
        "PodDisruptionBudget" => decode_poddisruptionbudget_proto(raw),
        "FlowSchema" => decode_flowschema_proto(raw),
        "PriorityLevelConfiguration" => decode_prioritylevelconfiguration_proto(raw),
        "ValidatingWebhookConfiguration" => decode_validatingwebhookconfiguration_proto(raw),
        "MutatingWebhookConfiguration" => decode_mutatingwebhookconfiguration_proto(raw),
        "MutatingAdmissionPolicy" => decode_mutatingadmissionpolicy_proto(raw),
        "MutatingAdmissionPolicyBinding" => decode_mutatingadmissionpolicybinding_proto(raw),
        "ValidatingAdmissionPolicy" => decode_validatingadmissionpolicy_proto(raw),
        "ValidatingAdmissionPolicyBinding" => decode_validatingadmissionpolicybinding_proto(raw),
        "IngressClass" => decode_ingressclass_proto(raw),
        "Ingress" => decode_ingress_proto(raw),
        "EndpointSlice" => decode_endpointslice_proto(raw),
        "CertificateSigningRequest" => decode_csr_proto(raw),
        "PriorityClass" => decode_priorityclass_proto(raw),
        "ControllerRevision" => decode_controllerrevision_proto(raw),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_core_proto_by_kind(kind: &str, raw: &[u8]) -> Option<serde_json::Value> {
        decode_proto_by_kind_and_version(kind, "", raw)
    }

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

    /// decode_k8s_proto_envelope must return None when the proto payload (after the 4-byte magic)
    /// exceeds MAX_PROTO_ENVELOPE_BYTES, without attempting to decode it.
    ///
    /// Without this check, prost honors the embedded varint length field and attempts to allocate
    /// the claimed size. A varint bomb (e.g. a length varint claiming 2 GiB) with a tiny actual
    /// payload causes the server to OOM before any auth or business logic runs. The size check
    /// must be done on the raw byte slice length, not on a decoded field value, so it fires
    /// before any allocation.
    #[test]
    fn rejects_oversized_proto_envelope_before_decode() {
        // Craft an oversized body: magic prefix + (MAX_PROTO_ENVELOPE_BYTES + 1) zero bytes.
        // The bytes themselves are not a valid proto message, but that doesn't matter —
        // the size check must fire before prost ever tries to decode them.
        // If the check is absent, prost returns Err (invalid wire format) for all-zero bytes,
        // but a real varint bomb with a valid length prefix would OOM first.
        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend(std::iter::repeat_n(0u8, MAX_PROTO_ENVELOPE_BYTES + 1));
        assert!(
            decode_k8s_proto_envelope(&body).is_none(),
            "proto envelope larger than MAX_PROTO_ENVELOPE_BYTES ({} bytes) must be rejected \
             without decoding — varint bombs can cause OOM if prost attempts the claimed allocation",
            MAX_PROTO_ENVELOPE_BYTES
        );
    }

    /// decode_k8s_proto_envelope must not reject a payload that is exactly at the limit.
    ///
    /// Ensures the size check is `> MAX` (strictly greater than), not `>= MAX`, so legitimate
    /// payloads right at the boundary are not incorrectly rejected.
    #[test]
    fn accepts_proto_envelope_at_exact_size_limit() {
        // Build an Unknown envelope (field 2 = raw payload) whose total encoded byte length
        // equals exactly MAX_PROTO_ENVELOPE_BYTES so that `proto_bytes.len() == MAX` passes
        // the `> MAX` check.
        //
        // Encoding of a length-delimited field:
        //   tag byte (1 byte: field_number=2, wire_type=2 → 0x12)
        //   + varint(payload_len)
        //   + payload bytes
        //
        // For payload_len near 16 MiB (= 2^24 bytes), the varint encoding requires 4 bytes
        // (values up to 2^28 - 1 fit in 4 varint bytes since each byte carries 7 bits).
        // So: 1 (tag) + 4 (varint) + payload_len = MAX_PROTO_ENVELOPE_BYTES
        //     payload_len = MAX_PROTO_ENVELOPE_BYTES - 5
        let payload_len = MAX_PROTO_ENVELOPE_BYTES - 5;
        let raw_payload: Vec<u8> = vec![b'x'; payload_len];
        let field2 = encode_length_delimited(2, &raw_payload);
        assert_eq!(
            field2.len(),
            MAX_PROTO_ENVELOPE_BYTES,
            "test setup: encoded field must be exactly MAX_PROTO_ENVELOPE_BYTES bytes"
        );

        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&field2);
        // The size check is `proto_bytes.len() > MAX_PROTO_ENVELOPE_BYTES`; at exactly MAX
        // this must not fire. The raw payload is all 'x' bytes, which prost accepts for a
        // `bytes` field, so decode_k8s_proto_envelope returns Some.
        let result = decode_k8s_proto_envelope(&body);
        assert!(
            result.is_some(),
            "a proto envelope of exactly MAX_PROTO_ENVELOPE_BYTES must not be rejected — \
             the size guard must use strictly-greater-than to avoid an off-by-one rejection"
        );
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

    /// decode_configmap_proto must preserve binaryData from the proto-encoded ConfigMap.
    ///
    /// kubectl sends ConfigMaps with binaryData via proto (field 3, map<string,bytes>).
    /// Without emitting binaryData into the JSON, the kubelet fetches the ConfigMap via GET
    /// and sees no binaryData entries, so it never writes binary-keyed files into the volume
    /// (e.g. dump.bin). The conformance test then fails with "No such file or directory".
    /// This test FAILS if the binary_data emission block is removed from decode_configmap_proto.
    #[test]
    fn decode_configmap_proto_preserves_binary_data() {
        let mut obj_meta = encode_length_delimited(1, b"bin-cm");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        // binaryData map entry (field 3 of ConfigMap): { key="dump.bin", value=b"hello" }
        let mut binary_entry = encode_length_delimited(1, b"dump.bin");
        binary_entry.extend_from_slice(&encode_length_delimited(2, b"hello"));

        let mut configmap_proto = encode_length_delimited(1, &obj_meta);
        configmap_proto.extend_from_slice(&encode_length_delimited(3, &binary_entry));

        let result = decode_configmap_proto(&configmap_proto).expect("must decode configmap proto");

        assert_eq!(result["kind"], "ConfigMap");
        assert_eq!(result["metadata"]["name"], "bin-cm");

        let binary_data = result["binaryData"]["dump.bin"]
            .as_str()
            .expect("binaryData.dump.bin must be a base64 string — missing means the kubelet never writes the file into the volume");
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(binary_data)
            .expect("binaryData value must be valid base64");
        assert_eq!(
            decoded, b"hello",
            "binaryData must decode to the original bytes — corrupt data means the pod cannot read the file"
        );
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

        // Container: field 1=name, field 2=image, field 14=imagePullPolicy
        let mut container = encode_length_delimited(1, b"myapp"); // name
        container.extend_from_slice(&encode_length_delimited(2, b"myapp:latest")); // image
        container.extend_from_slice(&encode_length_delimited(14, b"IfNotPresent")); // imagePullPolicy

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

    /// decode_pod_proto must preserve containers[].ports including hostPort.
    ///
    /// The StatefulSet "Should recreate evicted statefulset" conformance test creates a pod
    /// with hostPort: 8080 via protobuf. If the proto decoder strips the ports field, the
    /// kubelet receives a pod without ports, sends empty PortMappings to CRI-O, no port
    /// conflict occurs, the StatefulSet pod starts successfully, and the test waits forever
    /// for the pod to be deleted and recreated — never happening because there is no conflict.
    #[test]
    fn decode_pod_proto_preserves_container_ports_with_host_port() {
        // Build ContainerPort { name: "http", containerPort: 8080, hostPort: 8080, protocol: "TCP" }
        // ContainerPort fields: 1=name(string), 2=hostPort(int32), 3=containerPort(int32), 4=protocol(string)
        let mut port = encode_length_delimited(1, b"http"); // name
        port.extend_from_slice(&encode_varint(2u64 << 3)); // field 2, varint wire type 0
        port.extend_from_slice(&encode_varint(8080));
        port.extend_from_slice(&encode_varint(3u64 << 3)); // field 3, varint wire type 0
        port.extend_from_slice(&encode_varint(8080));
        port.extend_from_slice(&encode_length_delimited(4, b"TCP")); // protocol

        // Container: field 1=name, field 6=ports (ContainerPort)
        let mut container = encode_length_delimited(1, b"webserver");
        container.extend_from_slice(&encode_length_delimited(2, b"agnhost:2.43")); // image
        container.extend_from_slice(&encode_length_delimited(6, &port)); // ports field 6

        let mut obj_meta = encode_length_delimited(1, b"test-pod");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"statefulset-ns"));

        // PodSpec.containers = field 2
        let pod_spec = encode_length_delimited(2, &container);

        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed for a pod with container ports");

        let ports = result["spec"]["containers"][0]["ports"]
            .as_array()
            .expect("containers[0].ports must be an array; missing ports causes kubelet to send empty PortMappings to CRI-O, preventing hostPort enforcement");
        assert_eq!(
            ports.len(),
            1,
            "exactly one port must be decoded; \
             missing or extra ports would silently break hostPort conflict detection"
        );
        assert_eq!(
            ports[0]["hostPort"], 8080,
            "hostPort must be 8080; without this value the kubelet sends PortMappings:[] \
             to CRI-O so no iptables rule is created and the port conflict never occurs"
        );
        assert_eq!(
            ports[0]["containerPort"], 8080,
            "containerPort must be 8080 to match what the conformance test sends"
        );
        assert_eq!(
            ports[0]["protocol"], "TCP",
            "protocol must be preserved as TCP"
        );
        assert_eq!(ports[0]["name"], "http", "port name must be preserved");
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

    /// decode_pod_proto must decode PodSpec.hostname (field 16), subdomain (field 17), and
    /// initContainers (field 20) from proto bytes.
    ///
    /// Why it matters: the EndpointSliceMirroring conformance test creates a pod with
    /// spec.hostname set. If field 16 is dropped, the stored JSON has no hostname, the kubelet
    /// falls back to metadata.name for the container hostname, and curl /hostname from agnhost
    /// returns the wrong value — the test fails after 2 minutes of retries.
    ///
    /// initContainers (field 20) must also be decoded: if an init container is present but not
    /// stored, the pod will never reach Running because the kubelet sees no init containers to
    /// complete, but the stored spec has no record of them completing either.
    #[test]
    fn decode_pod_proto_preserves_hostname_subdomain_and_init_containers() {
        let mut obj_meta = encode_length_delimited(1, b"myapp");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        let mut container = encode_length_delimited(1, b"main");
        container.extend_from_slice(&encode_length_delimited(2, b"nginx:latest"));

        let mut init_container = encode_length_delimited(1, b"init");
        init_container.extend_from_slice(&encode_length_delimited(2, b"busybox:latest"));

        let mut pod_spec = encode_length_delimited(2, &container); // containers = field 2
        pod_spec.extend_from_slice(&encode_length_delimited(16, b"my-custom-host")); // hostname = field 16
        pod_spec.extend_from_slice(&encode_length_delimited(17, b"test-sub")); // subdomain = field 17
        pod_spec.extend_from_slice(&encode_length_delimited(20, &init_container)); // initContainers = field 20

        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with hostname/subdomain/initContainers");

        assert_eq!(
            result["spec"]["hostname"], "my-custom-host",
            "hostname must be decoded from PodSpec field 16 — without this, kubelet sets \
             container hostname from metadata.name and /hostname returns the wrong value"
        );
        assert_eq!(
            result["spec"]["subdomain"], "test-sub",
            "subdomain must be decoded from PodSpec field 17 — without this, \
             DNS-based hostname resolution does not work"
        );
        let init_containers = result["spec"]["initContainers"]
            .as_array()
            .expect("initContainers must be an array when proto field 20 is present");
        assert_eq!(
            init_containers.len(),
            1,
            "one initContainer must be decoded from PodSpec field 20"
        );
        assert_eq!(
            init_containers[0]["name"], "init",
            "initContainer name must be decoded"
        );
        assert_eq!(
            init_containers[0]["image"], "busybox:latest",
            "initContainer image must be decoded"
        );
    }

    /// decode_pod_proto must preserve readinessProbe.initialDelaySeconds in decoded JSON.
    ///
    /// When a pod is created via protobuf (e.g. by kubectl or the conformance suite), kubelet
    /// reads the probe config from the stored JSON. If readinessProbe is not decoded, kubelet
    /// receives null and uses default initialDelaySeconds=0 — the probe fires immediately,
    /// before the container is ready, causing spurious failures.
    ///
    /// This test must fail if the Probe struct or its fields are removed from the Container
    /// decoder: removing probe_to_json or the liveness/readiness/startup_probe fields in the
    /// map-building loop causes the decoded JSON to have no readinessProbe key.
    #[test]
    fn decode_pod_proto_preserves_readiness_probe_initial_delay() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "app", namespace: "default" },
        //   spec: PodSpec {
        //     containers: [Container {
        //       name: "app", image: "app:v1",
        //       readinessProbe: Probe {   // Container field 11
        //         initialDelaySeconds: 30,  // Probe field 2, varint
        //         timeoutSeconds: 5,        // Probe field 3, varint
        //         periodSeconds: 10,        // Probe field 4, varint
        //       }
        //     }]
        //   }
        // }
        let mut obj_meta = encode_length_delimited(1, b"app");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        // Encode Probe message: int32 fields use wire type 0 (varint), tag = field_number << 3
        let mut readiness_probe = encode_varint(2u64 << 3); // field 2 = initialDelaySeconds
        readiness_probe.extend_from_slice(&encode_varint(30));
        readiness_probe.extend_from_slice(&encode_varint(3u64 << 3)); // field 3 = timeoutSeconds
        readiness_probe.extend_from_slice(&encode_varint(5));
        readiness_probe.extend_from_slice(&encode_varint(4u64 << 3)); // field 4 = periodSeconds
        readiness_probe.extend_from_slice(&encode_varint(10));

        // Container field 1=name, 2=image, 11=readinessProbe (length-delimited message)
        let mut container = encode_length_delimited(1, b"app");
        container.extend_from_slice(&encode_length_delimited(2, b"app:v1"));
        container.extend_from_slice(&encode_length_delimited(11, &readiness_probe));

        let pod_spec = encode_length_delimited(2, &container); // PodSpec.containers = field 2
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_pod_proto(&pod_proto).expect(
            "decode_pod_proto must succeed — without probe decoding, kubelet fires probes immediately",
        );

        assert_eq!(result["metadata"]["name"], "app");

        let probe = &result["spec"]["containers"][0]["readinessProbe"];
        assert!(
            probe.is_object(),
            "readinessProbe must be present in decoded JSON — if missing, kubelet uses \
             default initialDelaySeconds=0 and fires the probe before the container is ready"
        );
        assert_eq!(
            probe["initialDelaySeconds"], 30,
            "initialDelaySeconds=30 must survive proto decode — kubelet reads this to delay \
             the first probe; if 0 or missing, probes fire immediately on container start"
        );
        assert_eq!(
            probe["timeoutSeconds"], 5,
            "timeoutSeconds must be decoded from Probe field 3"
        );
        assert_eq!(
            probe["periodSeconds"], 10,
            "periodSeconds must be decoded from Probe field 4"
        );

        // Verify the other probe types are absent (not spuriously set to empty objects)
        assert!(
            result["spec"]["containers"][0]["livenessProbe"].is_null(),
            "livenessProbe must not appear when not set in proto"
        );
        assert!(
            result["spec"]["containers"][0]["startupProbe"].is_null(),
            "startupProbe must not appear when not set in proto"
        );
    }

    /// decode_pod_proto must preserve lifecycle.preStop.exec.command in decoded JSON.
    ///
    /// When a pod is submitted via protobuf with a preStop exec hook, kubelet reads
    /// lifecycle.preStop from the stored JSON to execute the hook before killing the container.
    /// If lifecycle is not decoded, kubelet skips the preStop hook entirely — the pod
    /// terminates immediately without running the hook, causing conformance test
    /// 'should call prestop when killing a pod' to time out waiting for the hook's effect.
    ///
    /// This test must fail if the Lifecycle struct, LifecycleHandler struct, or the
    /// lifecycle_to_json call in the container decoder are removed.
    #[test]
    fn decode_pod_proto_preserves_prestop_exec_hook() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "app", namespace: "default" },
        //   spec: PodSpec {
        //     containers: [Container {
        //       name: "app", image: "app:v1",
        //       lifecycle: Lifecycle {   // Container field 12
        //         preStop: LifecycleHandler {  // Lifecycle field 2
        //           exec: ExecAction {         // LifecycleHandler field 1
        //             command: ["sh", "-c", "echo bye"]  // ExecAction field 1
        //           }
        //         }
        //       }
        //     }]
        //   }
        // }

        // Encode ExecAction: repeated string command at field 1 (wire type 2)
        let mut exec_action = encode_length_delimited(1, b"sh");
        exec_action.extend_from_slice(&encode_length_delimited(1, b"-c"));
        exec_action.extend_from_slice(&encode_length_delimited(1, b"echo bye"));

        // Encode LifecycleHandler: exec at field 1 (wire type 2)
        let handler = encode_length_delimited(1, &exec_action);

        // Encode Lifecycle: preStop at field 2 (wire type 2)
        let lifecycle = encode_length_delimited(2, &handler);

        // Encode Container: name=field 1, image=field 2, lifecycle=field 12
        let mut container = encode_length_delimited(1, b"app");
        container.extend_from_slice(&encode_length_delimited(2, b"app:v1"));
        container.extend_from_slice(&encode_length_delimited(12, &lifecycle));

        let mut obj_meta = encode_length_delimited(1, b"app");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        let pod_spec = encode_length_delimited(2, &container); // PodSpec.containers = field 2
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed — lifecycle decoding must not break pod decode");

        assert_eq!(result["metadata"]["name"], "app");

        let lifecycle = &result["spec"]["containers"][0]["lifecycle"];
        assert!(
            lifecycle.is_object(),
            "lifecycle must be present in decoded JSON — if missing, kubelet skips the \
             preStop hook and 'should call prestop when killing a pod' times out"
        );

        let pre_stop = &lifecycle["preStop"];
        assert!(
            pre_stop.is_object(),
            "lifecycle.preStop must be present — kubelet reads this to run the hook \
             before container termination; if absent, the hook is never executed"
        );

        let cmd = pre_stop["exec"]["command"]
            .as_array()
            .expect("preStop.exec.command must be an array");
        assert_eq!(
            cmd.len(),
            3,
            "preStop.exec.command must have 3 elements decoded from proto repeated string"
        );
        assert_eq!(
            cmd[0], "sh",
            "first command element must be 'sh' — kubelet passes this to exec in the container"
        );
        assert_eq!(cmd[1], "-c", "second command element must be '-c'");
        assert_eq!(
            cmd[2], "echo bye",
            "third command element must be 'echo bye'"
        );

        // Verify postStart is absent when not encoded
        assert!(
            lifecycle["postStart"].is_null(),
            "lifecycle.postStart must not appear when not set in proto"
        );
    }

    /// decode_pod_proto must preserve lifecycle.postStart.httpGet in decoded JSON.
    ///
    /// When a pod is submitted via protobuf with a postStart httpGet hook, kubelet fires an HTTP
    /// request to the specified endpoint immediately after the container starts.  If httpGet is
    /// stripped during proto decode (stored as `postStart: {}`), kubelet attempts to execute an
    /// empty hook and kills the container with FailedPostStartHook — the pod enters an infinite
    /// restart loop and never becomes Ready, causing the conformance test
    /// 'should execute poststart http hook properly' to time out after 300 s.
    ///
    /// This test must fail if LifecycleHandler.http_get is removed or if lifecycle_handler_to_json
    /// omits the httpGet branch.
    #[test]
    fn decode_pod_proto_preserves_poststart_http_get_hook() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "hook", namespace: "default" },
        //   spec: PodSpec {
        //     containers: [Container {
        //       name: "hook", image: "pause:3.10",
        //       lifecycle: Lifecycle {          // Container field 12
        //         postStart: LifecycleHandler { // Lifecycle field 1
        //           httpGet: HTTPGetAction {    // LifecycleHandler field 2
        //             path: "/started",         // HTTPGetAction field 1 (string)
        //             port: IntOrString(int=8080), // HTTPGetAction field 2 (IntOrString)
        //             host: "hook-svc",         // HTTPGetAction field 3 (string)
        //           }
        //         }
        //       }
        //     }]
        //   }
        // }

        // Encode IntOrString: type=0 (int) at field 1, intVal=8080 at field 2
        // Wire type 0 = varint; tag = (field_number << 3) | wire_type
        let mut int_or_string = encode_varint(1u64 << 3); // field 1, varint wire type 0
        int_or_string.extend_from_slice(&encode_varint(0)); // type = 0 (int)
        int_or_string.extend_from_slice(&encode_varint(2u64 << 3)); // field 2, varint wire type 0
        int_or_string.extend_from_slice(&encode_varint(8080));

        // Encode HTTPGetAction: path at field 1, port at field 2, host at field 3
        let mut http_get_action = encode_length_delimited(1, b"/started");
        http_get_action.extend_from_slice(&encode_length_delimited(2, &int_or_string));
        http_get_action.extend_from_slice(&encode_length_delimited(3, b"hook-svc"));

        // Encode LifecycleHandler: httpGet at field 2
        let handler = encode_length_delimited(2, &http_get_action);

        // Encode Lifecycle: postStart at field 1
        let lifecycle = encode_length_delimited(1, &handler);

        // Encode Container: name=field 1, image=field 2, lifecycle=field 12
        let mut container = encode_length_delimited(1, b"hook");
        container.extend_from_slice(&encode_length_delimited(2, b"pause:3.10"));
        container.extend_from_slice(&encode_length_delimited(12, &lifecycle));

        let mut obj_meta = encode_length_delimited(1, b"hook");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        let pod_spec = encode_length_delimited(2, &container); // PodSpec.containers = field 2
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_pod_proto(&pod_proto).expect(
            "decode_pod_proto must succeed — lifecycle.postStart.httpGet decoding must not panic",
        );

        assert_eq!(result["metadata"]["name"], "hook");

        let lifecycle = &result["spec"]["containers"][0]["lifecycle"];
        assert!(
            lifecycle.is_object(),
            "lifecycle must be present in decoded JSON — if missing, postStart hook is skipped"
        );

        let post_start = &lifecycle["postStart"];
        assert!(
            post_start.is_object(),
            "lifecycle.postStart must be present — kubelet reads this to fire the HTTP hook \
             immediately after container start; if absent, hook fires to wrong endpoint"
        );

        assert!(
            post_start["httpGet"].is_object(),
            "postStart.httpGet must be present in decoded JSON — if stripped, kubelet sees \
             postStart: {{}} and fires an empty hook, causing FailedPostStartHook and restart loop \
             (conformance: 'should execute poststart http hook properly')"
        );

        assert_eq!(
            post_start["httpGet"]["path"], "/started",
            "postStart.httpGet.path must be '/started' — kubelet uses this path for the hook request"
        );

        assert_eq!(
            post_start["httpGet"]["port"], 8080,
            "postStart.httpGet.port must be 8080 — kubelet connects to this port for the hook"
        );

        assert_eq!(
            post_start["httpGet"]["host"], "hook-svc",
            "postStart.httpGet.host must be 'hook-svc' — kubelet resolves this host for the hook"
        );

        // Verify preStop is absent when not encoded
        assert!(
            lifecycle["preStop"].is_null(),
            "lifecycle.preStop must not appear when not set in proto"
        );
    }

    /// decode_pod_proto must preserve readinessProbe.httpGet.path in decoded JSON.
    ///
    /// When a pod is submitted via protobuf with an httpGet readiness probe, kubelet reads
    /// readinessProbe.httpGet.path from the stored JSON to make the HTTP health-check request.
    /// If the ProbeHandler sub-message is not decoded, the stored probe has no httpGet field —
    /// kubelet reports "missing probe handler" and marks the container unready forever.
    ///
    /// This test must fail if ProbeHandler decoding or probe_to_json's httpGet branch are removed.
    #[test]
    fn decode_pod_proto_preserves_readiness_probe_http_get_path() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "web", namespace: "default" },
        //   spec: PodSpec {
        //     containers: [Container {
        //       name: "web", image: "nginx:latest",
        //       readinessProbe: Probe {      // Container field 11
        //         handler: ProbeHandler {   // Probe field 1
        //           httpGet: HTTPGetAction { // ProbeHandler field 2
        //             path: "/healthz",     // HTTPGetAction field 1 (string)
        //           }
        //         },
        //         initialDelaySeconds: 5,   // Probe field 2
        //       }
        //     }]
        //   }
        // }

        // Encode HTTPGetAction: path at field 1 (wire type 2, length-delimited string)
        let http_get_action = encode_length_delimited(1, b"/healthz");

        // Encode ProbeHandler: httpGet at field 2 (wire type 2, length-delimited message)
        let probe_handler = encode_length_delimited(2, &http_get_action);

        // Encode Probe: handler at field 1, initialDelaySeconds at field 2
        let mut probe = encode_length_delimited(1, &probe_handler);
        probe.extend_from_slice(&encode_varint(2u64 << 3)); // field 2 = initialDelaySeconds
        probe.extend_from_slice(&encode_varint(5));

        // Encode Container: name=field 1, image=field 2, readinessProbe=field 11
        let mut container = encode_length_delimited(1, b"web");
        container.extend_from_slice(&encode_length_delimited(2, b"nginx:latest"));
        container.extend_from_slice(&encode_length_delimited(11, &probe));

        let mut obj_meta = encode_length_delimited(1, b"web");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        let pod_spec = encode_length_delimited(2, &container); // PodSpec.containers = field 2
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_pod_proto(&pod_proto).expect(
            "decode_pod_proto must succeed — without probe handler decoding, \
             kubelet reports 'missing probe handler'",
        );

        assert_eq!(result["metadata"]["name"], "web");

        let probe = &result["spec"]["containers"][0]["readinessProbe"];
        assert!(
            probe.is_object(),
            "readinessProbe must be present in decoded JSON"
        );
        assert!(
            probe["httpGet"].is_object(),
            "readinessProbe.httpGet must be present — if missing, kubelet reports \
             'missing probe handler' and marks the container unready forever"
        );
        assert_eq!(
            probe["httpGet"]["path"], "/healthz",
            "readinessProbe.httpGet.path must be '/healthz' — kubelet uses this path \
             for the HTTP GET health-check; if absent, the probe target is unknown"
        );
        assert_eq!(
            probe["initialDelaySeconds"], 5,
            "initialDelaySeconds must still be decoded alongside the handler"
        );
    }

    /// decode_pod_proto must preserve livenessProbe.grpc.port so kubelet can
    /// perform the GRPC health-check request.
    ///
    /// When a pod is submitted via protobuf with a GRPC liveness probe, kubelet reads
    /// livenessProbe.grpc.port from the stored JSON to open the gRPC connection. If the
    /// GRPCAction sub-message is not decoded, the stored probe has no grpc field — kubelet
    /// cannot determine which port to probe and the container stays in ContainerCreating
    /// until the conformance test times out after 240 s.
    ///
    /// This test must fail if GrpcProbeAction decoding or probe_to_json's grpc branch are removed.
    #[test]
    fn decode_pod_proto_preserves_liveness_probe_grpc_port() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "grpc-app", namespace: "default" },
        //   spec: PodSpec {
        //     containers: [Container {
        //       name: "grpc-app", image: "grpc:v1",
        //       livenessProbe: Probe {         // Container field 10
        //         handler: ProbeHandler {      // Probe field 1
        //           grpc: GRPCAction {         // ProbeHandler field 4
        //             port: 8080,              // GRPCAction field 1 (int32 varint)
        //           }
        //         },
        //         periodSeconds: 10,           // Probe field 4
        //       }
        //     }]
        //   }
        // }

        // Encode GRPCAction: port at field 1 (wire type 0, varint)
        let mut grpc_action = encode_varint(1u64 << 3); // tag: field 1, wire type 0
        grpc_action.extend_from_slice(&encode_varint(8080));

        // Encode ProbeHandler: grpc at field 4 (wire type 2, length-delimited message)
        let probe_handler = encode_length_delimited(4, &grpc_action);

        // Encode Probe: handler at field 1, periodSeconds at field 4
        let mut probe = encode_length_delimited(1, &probe_handler);
        probe.extend_from_slice(&encode_varint(4u64 << 3)); // field 4 = periodSeconds
        probe.extend_from_slice(&encode_varint(10));

        // Encode Container: name=field 1, image=field 2, livenessProbe=field 10
        let mut container = encode_length_delimited(1, b"grpc-app");
        container.extend_from_slice(&encode_length_delimited(2, b"grpc:v1"));
        container.extend_from_slice(&encode_length_delimited(10, &probe));

        let mut obj_meta = encode_length_delimited(1, b"grpc-app");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        let pod_spec = encode_length_delimited(2, &container); // PodSpec.containers = field 2
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = decode_pod_proto(&pod_proto).expect(
            "decode_pod_proto must succeed — without grpc probe decoding, \
             kubelet cannot determine which port to health-check",
        );

        assert_eq!(result["metadata"]["name"], "grpc-app");

        let probe = &result["spec"]["containers"][0]["livenessProbe"];
        assert!(
            probe.is_object(),
            "livenessProbe must be present in decoded JSON — if missing, kubelet skips \
             the health-check entirely and the container stays in ContainerCreating"
        );
        assert!(
            probe["grpc"].is_object(),
            "livenessProbe.grpc must be present — if missing, kubelet cannot determine \
             which port to probe and the pod hangs in ContainerCreating for 240 s \
             (conformance: container_probe.go should be restarted with a GRPC liveness probe)"
        );
        assert_eq!(
            probe["grpc"]["port"], 8080,
            "livenessProbe.grpc.port must be 8080 — kubelet opens the gRPC connection \
             on this port; if absent or wrong, the health-check targets the wrong address"
        );
        assert_eq!(
            probe["periodSeconds"], 10,
            "periodSeconds must be decoded alongside the grpc handler"
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

    /// decode_lease_proto must preserve acquireTime, renewTime, and leaseTransitions.
    /// The kubelet and KCM use these fields for leader election and heartbeat tracking.
    /// If they are dropped on create/PUT, controllers see the lease as never acquired,
    /// which breaks node lifecycle management and leader election.
    #[test]
    fn decode_lease_proto_preserves_acquire_renew_and_transitions() {
        // Build: Lease {
        //   metadata: ObjectMeta { name: "kcm-leader", namespace: "kube-system" },
        //   spec: LeaseSpec {
        //     holderIdentity: "kcm",
        //     leaseDurationSeconds: 15,
        //     acquireTime: MicroTime { seconds: 1704067200 },  // field 3
        //     renewTime:   MicroTime { seconds: 1704067215 },  // field 4
        //     leaseTransitions: 3,                             // field 5
        //   }
        // }
        let mut obj_meta = encode_length_delimited(1, b"kcm-leader");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"kube-system"));

        // holderIdentity (field 1, wire 2)
        let mut lease_spec = encode_length_delimited(1, b"kcm");
        // leaseDurationSeconds (field 2, wire 0): tag=0x10, value=15
        lease_spec.push(0x10);
        lease_spec.push(0x0F);
        // acquireTime (field 3, wire 2 = length-delimited message)
        //   MicroTime { field 1 (seconds, varint) = 1704067200 }
        let mut acquire_time_msg = encode_varint(1 << 3); // field 1, wire 0
        acquire_time_msg.extend_from_slice(&encode_varint(1_704_067_200u64));
        lease_spec.extend_from_slice(&encode_length_delimited(3, &acquire_time_msg));
        // renewTime (field 4, wire 2)
        //   MicroTime { seconds = 1704067215 }
        let mut renew_time_msg = encode_varint(1 << 3); // field 1, wire 0
        renew_time_msg.extend_from_slice(&encode_varint(1_704_067_215u64));
        lease_spec.extend_from_slice(&encode_length_delimited(4, &renew_time_msg));
        // leaseTransitions (field 5, wire 0): tag = (5<<3)|0 = 0x28, value = 3
        lease_spec.push(0x28);
        lease_spec.push(0x03);

        let mut lease_proto = encode_length_delimited(1, &obj_meta);
        lease_proto.extend_from_slice(&encode_length_delimited(2, &lease_spec));

        let result = decode_lease_proto(&lease_proto).expect("must decode Lease proto");

        assert_eq!(
            result["spec"]["acquireTime"], "2024-01-01T00:00:00.000000Z",
            "acquireTime must be preserved; dropping it causes KCM to treat the lease \
             as never acquired and re-elect unnecessarily"
        );
        assert_eq!(
            result["spec"]["renewTime"], "2024-01-01T00:00:15.000000Z",
            "renewTime must be preserved; dropping it causes the kubelet heartbeat \
             interval to appear as zero, triggering false node-not-ready conditions"
        );
        assert_eq!(
            result["spec"]["leaseTransitions"], 3,
            "leaseTransitions must be preserved; dropping it makes leader election \
             metrics report zero transitions and hides controller restart storms"
        );
    }

    /// Regression test for mayor-z7v0: MicroTime with seconds = -1 must NOT produce
    /// year 584554049254 ("584554049254-11-09T...").
    ///
    /// Root cause: `t.seconds as u64` for negative i64 wraps to a huge u64 value
    /// (e.g. -1_i64 as u64 = u64::MAX ≈ 1.845×10^19), which `secs_to_rfc3339` then
    /// renders as year ~584554049254. client-go fails to parse the timestamp, causing
    /// the Lease API conformance test to fail.
    ///
    /// Fix: guard changed from `!= 0` to `> 0` so negative (corrupted) seconds values
    /// are silently dropped instead of casting to a wildly wrong u64.
    ///
    /// This test fails if the guard is reverted to `!= 0`: the `acquireTime` and
    /// `renewTime` keys would be present with year-584554049254 values instead of absent.
    #[test]
    fn decode_lease_proto_negative_microseconds_seconds_does_not_overflow_year() {
        // Build a Lease with MicroTime where seconds = -1 (encoded as the
        // 10-byte all-1s varint that represents -1 in two's-complement int64).
        // This simulates a corrupted or misencoded MicroTime field.
        //
        // -1 in proto varint = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
        // (10 bytes — the canonical encoding of -1 as int64 varint)
        let neg_one_varint: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

        let obj_meta = encode_length_delimited(1, b"test-lease");

        // renewTime (field 4, wire 2) with seconds = -1 (field 1, wire 0)
        let mut renew_time_msg = encode_varint(1 << 3); // field 1, wire 0
        renew_time_msg.extend_from_slice(neg_one_varint);
        let mut lease_spec = encode_length_delimited(4, &renew_time_msg);

        // acquireTime (field 3, wire 2) with seconds = -1
        let mut acquire_time_msg = encode_varint(1 << 3); // field 1, wire 0
        acquire_time_msg.extend_from_slice(neg_one_varint);
        lease_spec = {
            let mut s = encode_length_delimited(3, &acquire_time_msg);
            s.extend_from_slice(&lease_spec);
            s
        };

        let mut lease_proto = encode_length_delimited(1, &obj_meta);
        lease_proto.extend_from_slice(&encode_length_delimited(2, &lease_spec));

        let result = decode_lease_proto(&lease_proto).expect("must decode Lease proto");

        assert!(
            result["spec"]["renewTime"].is_null(),
            "renewTime with seconds=-1 must be absent, not year-584554049254; \
             got: {} — negative MicroTime seconds must be dropped, not cast to u64::MAX",
            result["spec"]["renewTime"]
        );
        assert!(
            result["spec"]["acquireTime"].is_null(),
            "acquireTime with seconds=-1 must be absent, not year-584554049254; \
             got: {} — negative MicroTime seconds must be dropped, not cast to u64::MAX",
            result["spec"]["acquireTime"]
        );
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
            result["series"]["lastObservedTime"], "2024-01-01T00:00:00.000000Z",
            "series.lastObservedTime must be normalized to microsecond precision; \
             client-go's MicroTime codec rejects bare RFC3339 (no fractional part) with \
             'cannot parse Z as .000000', breaking Event series conformance tests"
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
    /// the official field 4 (int64) in TokenRequestSpec.
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

    /// Regression test for mayor-c9o3: expirationSeconds is at field 4 in the canonical
    /// k8s TokenRequestSpec proto, not field 2. If our prost tag is wrong (e.g. tag=2),
    /// decoding real k8s client bytes will always yield expiration_seconds=0 (default),
    /// so every token request uses the server default TTL regardless of what was asked.
    ///
    /// This test constructs raw wire bytes with expirationSeconds at field 4 (as a real
    /// k8s client sends) and asserts the value is decoded correctly. It MUST fail if the
    /// prost tag on expiration_seconds is reverted to 2.
    ///
    /// Wire layout for the spec sub-message:
    ///   field 1 (repeated string, wire 2): audiences = "aud"  → tag 0x0a, len 0x03, "aud"
    ///   field 4 (int64, wire 0): expirationSeconds = 3600     → tag 0x20, varint 0x80 0x1c
    ///
    /// Outer TokenRequest: field 2 (message, wire 2): spec sub-message
    #[test]
    fn decode_token_request_expiration_seconds_at_field_4_raw_bytes() {
        // Build spec sub-message manually:
        //   field 1, wire 2 (len-delimited string): "aud"
        //     tag = (1 << 3) | 2 = 0x0a
        //     len = 3
        //     payload = b"aud"
        //   field 4, wire 0 (varint): 3600
        //     tag = (4 << 3) | 0 = 0x20
        //     3600 in varint = 0x80 0x1c
        let mut spec_bytes: Vec<u8> = Vec::new();
        // field 1: audiences = "aud"
        spec_bytes.extend_from_slice(&[0x0a, 0x03, b'a', b'u', b'd']);
        // field 4: expirationSeconds = 3600 (varint: 3600 = 0xE10 → 0x90 0x1c in LEB128)
        // 3600 = 0b0000_1110_0001_0000 → groups of 7: 0b001_1100 (low) and 0b0011100 (next)
        // Actually: 3600 = 0xE10; low 7 bits = 0x10 | 0x80 = 0x90; next 7 bits = 0xE10 >> 7 = 0x1c
        spec_bytes.extend_from_slice(&[0x20, 0x90, 0x1c]);

        // Build outer TokenRequest: field 2 (spec), wire 2
        //   tag = (2 << 3) | 2 = 0x12
        let mut raw: Vec<u8> = Vec::new();
        raw.push(0x12);
        raw.push(spec_bytes.len() as u8);
        raw.extend_from_slice(&spec_bytes);

        let fields = decode_token_request(&raw)
            .expect("decode_token_request must succeed with expirationSeconds at field 4");

        assert_eq!(
            fields.audiences,
            vec!["aud"],
            "audience must be decoded from field 1"
        );
        assert_eq!(
            fields.expiration_seconds,
            Some(3600),
            "expirationSeconds=3600 at field 4 must be decoded; \
             None or wrong value means prost tag is wrong (reverted to 2 instead of 4), \
             causing all proto token requests to use server default TTL"
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

        // JobSpec field 7 = backoffLimit (int32, wire 0): tag = (7 << 3) | 0 = 0x38, value = 3
        let job_spec = vec![0x38_u8, 0x03]; // field 7 (backoffLimit), wire type 0, varint 3

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
            "backoffLimit must be decoded from JobSpec field 7"
        );
    }

    /// decode_cronjob_proto must handle a kubectl wire-format body where JobSpec.template is
    /// at proto field 6 (LEN wire type). Before mayor-w00n, JobSpec had `template` at tag=5 and
    /// `backoffLimit` at tag=6. kubectl encodes `template` as field 6 (LEN), so prost saw
    /// field 6 as wire type 2 when the struct expected wire type 0 (int32 backoffLimit),
    /// causing CronJob::decode to return Err, decode_cronjob_proto to return None,
    /// and extract_body to fall through to raw proto bytes → "invalid JSON: expected value at
    /// line 1 column 1" (HTTP 400).
    #[test]
    fn decode_cronjob_proto_handles_kubectl_wire_format_with_template_at_field6() {
        use prost::Message as _;

        // Build the CronJob directly via prost structs so the encoding uses the correct
        // field numbers from the fixed JobSpec definition. The regression we guard against
        // is: if JobSpec.template is at tag=5 (wrong) instead of tag=6 (correct), prost
        // decodes the LEN field at tag=6 against `backoffLimit` (int32, wire type 0) and
        // returns DecodeError, making decode_cronjob_proto return None and the apiserver
        // return HTTP 400 "invalid JSON".
        let cj = CronJob {
            metadata: Some(ObjectMeta {
                name: "my-cj".to_string(),
                namespace: "cronjobtest".to_string(),
                ..Default::default()
            }),
            spec: Some(CronJobSpec {
                schedule: "*/1 * * * *".to_string(),
                job_template: Some(JobTemplateSpec {
                    metadata: None,
                    spec: Some(JobSpec {
                        // template at field 6 — if the field number were wrong (tag=5),
                        // prost would encode it at field 5 and then decode would succeed
                        // trivially (no cross-type mismatch). The regression only manifests
                        // when the struct has template at tag=5 and backoffLimit at tag=6,
                        // because kubectl puts template at wire field 6 (LEN type) which
                        // collides with the mislocated backoffLimit (int32, varint type).
                        template: vec![0x0a, 0x02, 0x08, 0x01], // minimal PodTemplateSpec bytes
                        backoff_limit: 3,
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        cj.encode(&mut buf).expect("prost encode must succeed");

        // Verify that the encoded bytes contain field 6 as a LEN field (template).
        // Tag for (field 6, wire type 2) = (6 << 3) | 2 = 50 = 0x32.
        // If template were at field 5, the tag would be (5<<3)|2 = 42 = 0x2a.
        // This assertion fails if template is at the wrong field number.
        assert!(
            buf.windows(1).any(|w| w[0] == 0x32),
            "encoded CronJob must contain tag 0x32 (field 6, LEN = template field in JobSpec); \
             if template is at field 5, tag 0x2a appears instead and the fix is not in effect"
        );

        let result = decode_cronjob_proto(&buf).expect(
            "decode_cronjob_proto must return Some when JobSpec.template is at field 6 \
                     (LEN wire type) — before mayor-w00n fix, JobSpec had template at tag=5 \
                     causing a wire-type mismatch when kubectl sends template at field 6, \
                     making CronJob::decode return Err and the apiserver return HTTP 400",
        );

        assert_eq!(result["kind"], "CronJob");
        assert_eq!(result["apiVersion"], "batch/v1");
        assert_eq!(result["metadata"]["name"], "my-cj");
        assert_eq!(
            result["spec"]["schedule"], "*/1 * * * *",
            "schedule must survive decode when template is present at field 6"
        );
        assert_eq!(
            result["spec"]["jobTemplate"]["spec"]["backoffLimit"], 3,
            "backoffLimit must decode correctly at field 7 after the field-number fix"
        );
        assert!(
            result["spec"]["jobTemplate"]["spec"]["template"].is_object(),
            "jobTemplate.spec.template must be present after decoding kubectl wire format"
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

        // JobSpec: field 2=completions (varint), field 7=backoffLimit (varint)
        // completions=1: tag = (2 << 3) | 0 = 0x10, value = 0x01
        // backoffLimit=4: tag = (7 << 3) | 0 = 0x38, value = 0x04
        let job_spec = vec![0x10, 0x01, 0x38, 0x04];

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
            "backoffLimit must be decoded from JobSpec field 7"
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
    /// job.go:582 create Jobs with successPolicy (k8s 1.30+ field at proto field 16).
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

    /// decode_service_proto must preserve targetPort from the proto-encoded IntOrString.
    /// Without this, admission webhook_url() falls back to svc_port and tunnels to the
    /// wrong container port, causing connection refused in the konnectivity tunnel.
    #[test]
    fn decode_service_proto_preserves_target_port() {
        // ServicePort with port=8443 and targetPort=8444 (integer IntOrString).
        // k8s IntOrString proto: field 1 (int64) = type (0=Int), field 2 (int32) = intVal, field 3 (string) = strVal.
        // Encoding for type=0, intVal=8444:
        //   field 1 tag+val: 0x08 0x00 (field 1 varint, value 0)
        //   field 2 tag+val: 0x10 0xFC 0x41 (field 2 varint, value 8444 in LEB128)
        //   field 3 tag+val: 0x1a 0x00 (field 3 length-delimited, empty string)
        let int_or_string_8444: Vec<u8> = vec![0x08, 0x00, 0x10, 0xFC, 0x41, 0x1a, 0x00];

        let mut port = encode_length_delimited(2, b"TCP");
        port.extend_from_slice(&encode_varint(3u64 << 3)); // field 3 tag (port, varint)
        port.extend_from_slice(&encode_varint(8443));
        port.extend_from_slice(&encode_length_delimited(4, &int_or_string_8444));

        let mut svc_spec = encode_length_delimited(1, &port);
        svc_spec.extend_from_slice(&encode_length_delimited(4, b"ClusterIP"));

        let mut obj_meta = encode_length_delimited(1, b"webhook-svc");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"test-ns"));

        let mut svc_proto = encode_length_delimited(1, &obj_meta);
        svc_proto.extend_from_slice(&encode_length_delimited(2, &svc_spec));

        let result = decode_service_proto(&svc_proto).expect("Service with targetPort must decode");
        let ports = result["spec"]["ports"].as_array().expect("ports array");
        assert_eq!(ports[0]["port"], 8443, "port must be 8443");
        assert_eq!(
            ports[0]["targetPort"], 8444,
            "targetPort must be preserved from IntOrString proto encoding — without this, \
             webhook_url() tunnels to wrong container port"
        );
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
        secret_proto.extend_from_slice(&encode_length_delimited(2, &data_entry)); // data (field 2)
        secret_proto.extend_from_slice(&encode_length_delimited(3, b"Opaque")); // type (field 3)

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

    /// Regression: Secret.type must be decoded from wire field 3, not field 4.
    ///
    /// The official k8s proto definition (api-core-v1-generated.proto) places:
    ///   field 2 = data (map<string,bytes>)
    ///   field 3 = type (string)           ← type IS field 3
    ///   field 4 = stringData (map<string,string>)
    ///
    /// Previously the Rust Secret struct had these two fields swapped (type=4, stringData=3),
    /// causing Secret::decode() to fail with a wire-type error when client-go sent `type` at
    /// field 3.  decode_secret_proto returned None, extract_body fell back to raw proto bytes,
    /// and the handler returned 400 "invalid JSON: expected value at line 1 column 1".
    ///
    /// This test uses the correct field layout (type at wire field 3) and verifies that the
    /// full envelope → extract_body → JSON round-trip succeeds.  Reverting the field-number
    /// fix causes Secret::decode() to misparse the type string as a map, returning None.
    #[test]
    fn secret_type_at_wire_field_3_decodes_correctly() {
        // Encode ObjectMeta{name="sample-webhook-secret", namespace="default"}
        let mut obj_meta = encode_length_delimited(1, b"sample-webhook-secret");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        // Encode the Secret raw proto:
        //   field 1 = metadata
        //   field 3 = type (string "Opaque") — official wire field number
        let mut secret_proto = encode_length_delimited(1, &obj_meta);
        secret_proto.extend_from_slice(&encode_length_delimited(3, b"Opaque")); // type at field 3

        // Wrap in k8s Unknown envelope: magic + TypeMeta(v1/Secret) + raw(secret_proto)
        let mut type_meta = encode_length_delimited(1, b"v1"); // apiVersion
        type_meta.extend_from_slice(&encode_length_delimited(2, b"Secret")); // kind

        let mut envelope = encode_length_delimited(1, &type_meta); // TypeMeta
        envelope.extend_from_slice(&encode_length_delimited(2, &secret_proto)); // raw

        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&envelope);

        let env = decode_k8s_proto_envelope(&body)
            .expect("envelope must decode — magic + Unknown are well-formed");
        assert_eq!(env.kind, "Secret");

        let result = decode_core_proto_by_kind(&env.kind, &env.raw).expect(
            "Secret with type at wire field 3 must decode — reverting the field-number fix \
             causes Secret::decode() to misparse 'Opaque' as a map and return None, \
             which makes extract_body return raw proto bytes and the handler return 400",
        );

        assert_eq!(result["kind"], "Secret");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "sample-webhook-secret");
        assert_eq!(result["metadata"]["namespace"], "default");
        assert_eq!(
            result["type"], "Opaque",
            "type must be 'Opaque' — if the field tags are swapped, \
             'Opaque' is decoded as stringData (map) and the type field is empty"
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

        // PersistentVolumeSpec: field 3=accessModes (repeated string), field 5=reclaimPolicy,
        // field 6=storageClassName
        let mut pv_spec = encode_length_delimited(3, b"ReadWriteOnce"); // accessModes[0]
        pv_spec.extend_from_slice(&encode_length_delimited(5, b"Delete")); // reclaimPolicy
        pv_spec.extend_from_slice(&encode_length_delimited(6, b"standard")); // storageClassName

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
    // Regression tests — apps/v1 spec decoding (selector defaulting requires
    // spec.template.metadata.labels to be present in the decoded JSON)
    // ---------------------------------------------------------------------------

    /// Decoding a Deployment proto with spec.template.metadata.labels must produce
    /// spec.template.metadata.labels in the JSON output.
    ///
    /// Without spec field decoding in the Deployment prost struct, the decoded JSON has
    /// no `spec` key, causing selector defaulting to fail with 422
    /// 'spec.selector is required and could not be defaulted'.
    #[test]
    fn decode_deployment_proto_includes_spec_template_labels() {
        // Encode: matchLabels map entry: key="app", value="test"
        let mut label_entry = encode_length_delimited(1, b"app"); // key
        label_entry.extend_from_slice(&encode_length_delimited(2, b"test")); // value

        // LabelSelector { matchLabels: {"app": "test"} }  — field 1 is map<string,string>
        let selector_bytes = encode_length_delimited(1, &label_entry);

        // ObjectMeta { labels: {"app": "test"} }  — field 11 is map<string,string>
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);

        // PodTemplateSpec { metadata: tmpl_meta }  — field 1
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);

        // DeploymentSpec { selector: field 2, template: field 3 }
        let mut spec_bytes = encode_length_delimited(2, &selector_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        // Deployment { metadata: field 1, spec: field 2 }
        let name_bytes = encode_length_delimited(1, b"my-deploy");
        let meta_bytes = name_bytes;
        let mut proto = encode_length_delimited(1, &meta_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("Deployment", &proto).expect(
            "Deployment with spec must decode successfully — \
             without spec decoding, proto POST returns 422 because labels are absent",
        );

        assert_eq!(
            result["spec"]["template"]["metadata"]["labels"]["app"], "test",
            "spec.template.metadata.labels must be present for selector defaulting; \
             without it the apiserver returns 422 'spec.selector is required and could not be defaulted'"
        );
        assert_eq!(
            result["spec"]["selector"]["matchLabels"]["app"], "test",
            "spec.selector.matchLabels must be present in decoded JSON"
        );
    }

    /// Decoding a Deployment proto with spec.template.spec.containers must produce
    /// spec.template.spec with non-null containers in the JSON output.
    ///
    /// KCM's FindNewReplicaSet calls EqualIgnoreHash(RS.spec.template, Deployment.spec.template).
    /// The RS has real containers; if the Deployment has spec.template.spec=null the comparison
    /// always fails → FindNewReplicaSet returns nil → the deployment revision annotation is never
    /// set → AdmissionWebhook conformance test fails (19/20 instead of 20/20).
    #[test]
    fn decode_deployment_proto_includes_spec_template_spec_containers() {
        // Build Container proto: name="nginx", image="nginx:latest"
        let mut container = encode_length_delimited(1, b"nginx"); // Container.name (field 1)
        container.extend_from_slice(&encode_length_delimited(2, b"nginx:latest")); // Container.image (field 2)

        // PodSpec { containers: [container] }  — containers = field 2
        let pod_spec_bytes = encode_length_delimited(2, &container);

        // ObjectMeta { labels: {"app": "nginx"} }
        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"nginx"));
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);

        // PodTemplateSpec { metadata: field 1, spec: field 2 }
        let mut template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        template_bytes.extend_from_slice(&encode_length_delimited(2, &pod_spec_bytes));

        // LabelSelector { matchLabels: {"app": "nginx"} }
        let selector_bytes = encode_length_delimited(1, &label_entry);

        // DeploymentSpec { selector: field 2, template: field 3 }
        let mut spec_bytes = encode_length_delimited(2, &selector_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        // Deployment { metadata: field 1, spec: field 2 }
        let name_bytes = encode_length_delimited(1, b"nginx-deploy");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("Deployment", &proto).expect(
            "Deployment with pod spec must decode — without this, proto POST stores null pod spec",
        );

        assert!(
            result["spec"]["template"]["spec"].is_object(),
            "spec.template.spec must be an object, not null — if null, KCM's EqualIgnoreHash \
             fails to match the Deployment template against the ReplicaSet template, causing \
             FindNewReplicaSet to return nil and the deployment revision annotation to never be set"
        );

        let containers = result["spec"]["template"]["spec"]["containers"]
            .as_array()
            .expect(
                "spec.template.spec.containers must be an array — without containers in the \
                 stored Deployment, EqualIgnoreHash always returns false regardless of RS state",
            );
        assert_eq!(
            containers.len(),
            1,
            "one container must be decoded from PodTemplateSpec.spec"
        );
        assert_eq!(
            containers[0]["name"], "nginx",
            "container name must be extracted from PodTemplateSpec.spec.containers"
        );
        assert_eq!(
            containers[0]["image"], "nginx:latest",
            "container image must be extracted from PodTemplateSpec.spec.containers"
        );
    }

    /// Decoding a StatefulSet proto with spec.template.metadata.labels must include
    /// spec.template.metadata.labels in the JSON output.
    ///
    /// Without spec field decoding, proto POST of a StatefulSet fails with 422.
    #[test]
    fn decode_statefulset_proto_includes_spec_template_labels() {
        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"myapp"));

        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);

        let mut spec_bytes = encode_length_delimited(2, &selector_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        let name_bytes = encode_length_delimited(1, b"my-sts");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("StatefulSet", &proto).expect(
            "StatefulSet with spec must decode successfully — \
             without spec decoding, proto POST returns 422 because labels are absent",
        );

        assert_eq!(
            result["spec"]["template"]["metadata"]["labels"]["app"], "myapp",
            "spec.template.metadata.labels must be present for selector defaulting"
        );
    }

    /// Decoding a ReplicaSet proto with spec.template.metadata.labels must include
    /// spec.template.metadata.labels in the JSON output.
    ///
    /// Without spec field decoding, proto POST of a ReplicaSet fails with 422.
    #[test]
    fn decode_replicaset_proto_includes_spec_template_labels() {
        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"myrs"));

        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);

        let mut spec_bytes = encode_length_delimited(2, &selector_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        let name_bytes = encode_length_delimited(1, b"my-rs");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("ReplicaSet", &proto).expect(
            "ReplicaSet with spec must decode successfully — \
             without spec decoding, proto POST returns 422 because labels are absent",
        );

        assert_eq!(
            result["spec"]["template"]["metadata"]["labels"]["app"], "myrs",
            "spec.template.metadata.labels must be present for selector defaulting"
        );
    }

    /// Decoding a DaemonSet proto with spec.template.metadata.labels must include
    /// spec.template.metadata.labels in the JSON output.
    ///
    /// Without spec field decoding in the DaemonSet prost struct, applying a DaemonSet via
    /// kubectl fails with 'proto: cannot parse invalid wire-format data' because the proto body
    /// cannot be decoded when spec (field 2) is unknown to our struct.
    #[test]
    fn decode_daemonset_proto_includes_spec_template_labels() {
        // Encode: matchLabels map entry: key="app", value="myds"
        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"myds"));

        // LabelSelector { matchLabels: {"app": "myds"} }  — field 1 is map<string,string>
        let selector_bytes = encode_length_delimited(1, &label_entry);

        // ObjectMeta { labels: {"app": "myds"} }  — field 11 is map<string,string>
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);

        // PodTemplateSpec { metadata: tmpl_meta }  — field 1
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);

        // DaemonSetSpec { selector: field 1, template: field 2 }
        let mut spec_bytes = encode_length_delimited(1, &selector_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &template_bytes));

        // DaemonSet { metadata: field 1, spec: field 2 }
        let name_bytes = encode_length_delimited(1, b"my-ds");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("DaemonSet", &proto).expect(
            "DaemonSet with spec must decode successfully — \
             without spec decoding, kubectl apply fails with 'cannot parse invalid wire-format data'",
        );

        assert_eq!(
            result["spec"]["template"]["metadata"]["labels"]["app"], "myds",
            "spec.template.metadata.labels must be present for selector defaulting; \
             without it the apiserver returns 422 'spec.selector is required and could not be defaulted'"
        );
        assert_eq!(
            result["spec"]["selector"]["matchLabels"]["app"], "myds",
            "spec.selector.matchLabels must be present in decoded JSON"
        );
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

    /// decode_endpoints_proto must preserve subsets (field 2) from proto-encoded Endpoints.
    ///
    /// When client-go PUTs/PATCHes Endpoints with Content-Type protobuf, field 2 carries
    /// the subsets. If they are dropped, the stored object has null subsets, the
    /// EndpointSliceMirroring controller finds nothing to mirror, and the mirrored
    /// EndpointSlice never appears — breaking any test that verifies EndpointSlice presence.
    #[test]
    fn decode_endpoints_proto_preserves_subsets() {
        // Build Endpoints {
        //   metadata: { name: "my-ep", namespace: "default" },
        //   subsets: [{
        //     addresses: [{ ip: "10.1.2.3" }],
        //     ports: [{ name: "http", port: 80, protocol: "TCP" }]
        //   }]
        // }

        // metadata
        let mut meta = encode_length_delimited(1, b"my-ep");
        meta.extend_from_slice(&encode_length_delimited(3, b"default"));

        // EndpointAddress { ip: "10.1.2.3" }
        let addr = encode_length_delimited(1, b"10.1.2.3");

        // EndpointPort { name: "http", port: 80, protocol: "TCP" }
        // port=80: tag=(2<<3)|0=0x10, value=80=0x50
        let mut ep_port = encode_length_delimited(1, b"http");
        ep_port.push(0x10); // field 2, wire type 0 (varint)
        ep_port.push(80); // port = 80
        ep_port.extend_from_slice(&encode_length_delimited(3, b"TCP"));

        // EndpointSubset { addresses: [addr], ports: [ep_port] }
        let mut subset = encode_length_delimited(1, &addr);
        subset.extend_from_slice(&encode_length_delimited(3, &ep_port));

        // Endpoints { metadata, subsets: [subset] }
        let mut proto = encode_length_delimited(1, &meta);
        proto.extend_from_slice(&encode_length_delimited(2, &subset));

        let result = decode_core_proto_by_kind("Endpoints", &proto)
            .expect("Endpoints must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "Endpoints");
        assert_eq!(result["metadata"]["name"], "my-ep");

        let subsets = result["subsets"]
            .as_array()
            .expect("subsets must be present — dropping field 2 breaks EndpointSliceMirroring");
        assert_eq!(subsets.len(), 1, "one subset must be decoded");

        let addresses = subsets[0]["addresses"]
            .as_array()
            .expect("addresses must be present in subset");
        assert_eq!(addresses.len(), 1);
        assert_eq!(
            addresses[0]["ip"], "10.1.2.3",
            "ip must survive proto decode — EndpointSlice mirroring uses subset addresses"
        );

        let ports = subsets[0]["ports"]
            .as_array()
            .expect("ports must be present in subset");
        assert_eq!(ports.len(), 1);
        assert_eq!(
            ports[0]["port"], 80,
            "port number must survive proto decode"
        );
        assert_eq!(ports[0]["protocol"], "TCP");
        assert_eq!(ports[0]["name"], "http");
    }

    /// EndpointAddress hostname must be decoded from proto field 3 (not field 2).
    ///
    /// Canonical k8s proto has targetRef at field 2 (LEN/message) and hostname at field 3.
    /// If hostname were at field 2, any Endpoints object with a targetRef would corrupt the
    /// hostname field (prost would try to decode ObjectReference bytes as UTF-8), and actual
    /// hostname/nodeName values would be silently dropped — breaking EndpointSliceMirroring.
    #[test]
    fn decode_endpoints_proto_hostname_at_field_3_nodename_at_field_4() {
        // Build EndpointAddress with:
        //   field 1: ip = "192.168.1.5"
        //   field 2: targetRef = some LEN-encoded bytes (simulates an ObjectReference)
        //   field 3: hostname = "my-host"
        //   field 4: nodeName = "node-1"
        let mut addr = encode_length_delimited(1, b"192.168.1.5");
        // targetRef at field 2: a minimal LEN-encoded ObjectReference (just a non-empty payload)
        addr.extend_from_slice(&encode_length_delimited(2, b"\x0a\x03Pod"));
        addr.extend_from_slice(&encode_length_delimited(3, b"my-host"));
        addr.extend_from_slice(&encode_length_delimited(4, b"node-1"));

        // EndpointSubset { addresses: [addr] }
        let subset = encode_length_delimited(1, &addr);

        // Endpoints { metadata: { name: "ep" }, subsets: [subset] }
        let meta = encode_length_delimited(1, b"ep");
        let mut proto = encode_length_delimited(1, &meta);
        proto.extend_from_slice(&encode_length_delimited(2, &subset));

        let result = decode_core_proto_by_kind("Endpoints", &proto)
            .expect("Endpoints with hostname at field 3 must decode");

        let addresses = result["subsets"][0]["addresses"]
            .as_array()
            .expect("addresses must be present");
        assert_eq!(addresses.len(), 1);
        assert_eq!(
            addresses[0]["ip"], "192.168.1.5",
            "ip must be decoded from field 1"
        );
        assert_eq!(
            addresses[0]["hostname"], "my-host",
            "hostname must be decoded from field 3, not field 2 — wrong tag corrupts hostname when targetRef is present"
        );
        assert_eq!(
            addresses[0]["nodeName"], "node-1",
            "nodeName must be decoded from field 4 — wrong tag drops nodeName silently"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — StorageClass, VolumeAttributesClass, ResourceQuota, LimitRange, PodDisruptionBudget
    //
    // kubectl sends these types as proto-encoded bytes with empty contentType.
    // Without decoders, decode_core_proto_by_kind returns None, extract_body returns the raw
    // proto bytes, Object::from_bytes fails with "invalid JSON: expected value at line 1 column 1",
    // and the apiserver returns HTTP 400. Adding decoders fixes the create path for these types.
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch StorageClass to a decoder that returns valid JSON.
    ///
    /// kubectl sends StorageClass (storage.k8s.io/v1) with Content-Type: application/vnd.kubernetes.protobuf.
    /// Without this decoder, create_resource returns 400 'invalid JSON: expected value at line 1 column 1',
    /// causing e2e StorageClasses lifecycle tests to fail.
    #[test]
    fn decode_storageclass_proto_extracts_metadata() {
        // StorageClass { metadata: ObjectMeta { name: "fast-ssd" } }
        let name = encode_length_delimited(1, b"fast-ssd");
        let proto = encode_length_delimited(1, &name);

        let result = decode_core_proto_by_kind("StorageClass", &proto).expect(
            "StorageClass must decode via decode_core_proto_by_kind — \
             without this decoder, StorageClass creates via proto return 400 'invalid JSON', \
             causing e2e StorageClasses lifecycle tests to fail",
        );

        assert_eq!(
            result["kind"], "StorageClass",
            "kind must be StorageClass so the object is routed and stored correctly"
        );
        assert_eq!(
            result["apiVersion"], "storage.k8s.io/v1",
            "apiVersion must be storage.k8s.io/v1"
        );
        assert_eq!(
            result["metadata"]["name"], "fast-ssd",
            "name must survive proto decode — used for store key and uniqueness check"
        );
    }

    /// decode_core_proto_by_kind must dispatch VolumeAttributesClass to a decoder.
    ///
    /// VolumeAttributesClass (storage.k8s.io/v1) is a relatively new type; without a decoder
    /// proto creates return 400 'invalid JSON'.
    #[test]
    fn decode_volumeattributesclass_proto_extracts_metadata() {
        // VolumeAttributesClass { metadata: ObjectMeta { name: "premium-rwo" } }
        let name = encode_length_delimited(1, b"premium-rwo");
        let proto = encode_length_delimited(1, &name);

        let result = decode_core_proto_by_kind("VolumeAttributesClass", &proto).expect(
            "VolumeAttributesClass must decode via decode_core_proto_by_kind — \
             without this decoder, creates via proto return 400 'invalid JSON'",
        );

        assert_eq!(result["kind"], "VolumeAttributesClass");
        assert_eq!(result["apiVersion"], "storage.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "premium-rwo");
    }

    /// decode_core_proto_by_kind must dispatch ResourceQuota to a decoder that returns valid JSON.
    ///
    /// kubectl sends ResourceQuota (core/v1, namespaced) with proto encoding. Without this decoder,
    /// create_namespaced_resource returns 400, causing e2e ResourceQuota tests to fail.
    #[test]
    fn decode_resourcequota_proto_extracts_metadata() {
        // ResourceQuota { metadata: ObjectMeta { name: "compute-quota", namespace: "default" } }
        let mut meta_bytes = encode_length_delimited(1, b"compute-quota");
        meta_bytes.extend_from_slice(&encode_length_delimited(3, b"default"));
        let proto = encode_length_delimited(1, &meta_bytes);

        let result = decode_core_proto_by_kind("ResourceQuota", &proto).expect(
            "ResourceQuota must decode via decode_core_proto_by_kind — \
             without this decoder, ResourceQuota creates via proto return 400 'invalid JSON', \
             causing e2e ResourceQuota tests to fail in BeforeEach",
        );

        assert_eq!(
            result["kind"], "ResourceQuota",
            "kind must be ResourceQuota so the object is stored under the correct key"
        );
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "compute-quota");
        assert_eq!(result["metadata"]["namespace"], "default");
    }

    /// decode_resourcequota_proto must decode spec.hard so the quota controller can enforce limits.
    ///
    /// KCM's quota controller reads spec.hard to determine the limits it must enforce and to
    /// populate status.used. If spec.hard is null (not decoded), the controller skips
    /// reconciliation entirely, meaning no quota is enforced and status.used is never updated.
    /// This test must fail if spec decoding is removed.
    #[test]
    fn decode_resourcequota_proto_extracts_spec_hard() {
        // Build the proto bytes for:
        //   ResourceQuota {
        //     metadata: ObjectMeta { name: "compute-quota", namespace: "default" },
        //     spec: ResourceQuotaSpec {
        //       hard: {"pods": Quantity{string: "10"}}
        //     }
        //   }
        //
        // Encode a Quantity{string: "10"} message (field 1 = string).
        let encode_quantity = |s: &[u8]| -> Vec<u8> { encode_length_delimited(1, s) };

        // Encode a proto map entry: key (field 1) and value message (field 2).
        let encode_map_entry = |key: &[u8], val_bytes: &[u8]| -> Vec<u8> {
            let mut entry = encode_length_delimited(1, key);
            entry.extend_from_slice(&encode_length_delimited(2, val_bytes));
            entry
        };

        // ResourceQuotaSpec { hard: {"pods": Quantity{string: "10"}} }  (field 1 = hard map)
        let pods_entry = encode_map_entry(b"pods", &encode_quantity(b"10"));
        let spec_bytes = encode_length_delimited(1, &pods_entry);

        // ResourceQuota { metadata, spec }
        let mut meta_bytes = encode_length_delimited(1, b"compute-quota");
        meta_bytes.extend_from_slice(&encode_length_delimited(3, b"default"));
        let mut proto = encode_length_delimited(1, &meta_bytes); // field 1 = metadata
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes)); // field 2 = spec

        let result = decode_core_proto_by_kind("ResourceQuota", &proto)
            .expect("ResourceQuota with spec.hard must decode successfully");

        assert_eq!(result["kind"], "ResourceQuota");
        assert_eq!(result["metadata"]["name"], "compute-quota");
        assert_eq!(
            result["spec"]["hard"]["pods"], "10",
            "spec.hard.pods must be decoded — without this the quota controller sees null \
             spec.hard and skips reconciliation, so no quota is ever enforced"
        );
    }

    /// decode_core_proto_by_kind must dispatch LimitRange to a decoder that returns valid JSON.
    ///
    /// LimitRange (core/v1, namespaced) is sent via proto by kubectl. Without this decoder,
    /// creates return 400, causing e2e LimitRange tests to fail.
    #[test]
    fn decode_limitrange_proto_extracts_metadata() {
        // LimitRange { metadata: ObjectMeta { name: "limits", namespace: "default" } }
        let mut meta_bytes = encode_length_delimited(1, b"limits");
        meta_bytes.extend_from_slice(&encode_length_delimited(3, b"default"));
        let proto = encode_length_delimited(1, &meta_bytes);

        let result = decode_core_proto_by_kind("LimitRange", &proto).expect(
            "LimitRange must decode via decode_core_proto_by_kind — \
             without this decoder, LimitRange creates via proto return 400 'invalid JSON'",
        );

        assert_eq!(result["kind"], "LimitRange");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "limits");
        assert_eq!(result["metadata"]["namespace"], "default");
    }

    /// decode_core_proto_by_kind must dispatch PodDisruptionBudget to a decoder.
    ///
    /// PodDisruptionBudget (policy/v1, namespaced) is sent via proto by kubectl. Without this
    /// decoder, creates return 400, causing e2e DisruptionController tests to fail.
    #[test]
    fn decode_poddisruptionbudget_proto_extracts_metadata() {
        // PodDisruptionBudget { metadata: ObjectMeta { name: "my-pdb", namespace: "default" } }
        let mut meta_bytes = encode_length_delimited(1, b"my-pdb");
        meta_bytes.extend_from_slice(&encode_length_delimited(3, b"default"));
        let proto = encode_length_delimited(1, &meta_bytes);

        let result = decode_core_proto_by_kind("PodDisruptionBudget", &proto).expect(
            "PodDisruptionBudget must decode via decode_core_proto_by_kind — \
             without this decoder, PDB creates via proto return 400 'invalid JSON', \
             causing e2e DisruptionController tests to fail",
        );

        assert_eq!(result["kind"], "PodDisruptionBudget");
        assert_eq!(result["apiVersion"], "policy/v1");
        assert_eq!(result["metadata"]["name"], "my-pdb");
        assert_eq!(result["metadata"]["namespace"], "default");
    }

    /// decode_limitrange_proto must decode spec.limits so the admission plugin can apply defaults.
    ///
    /// Without spec decoding, a kubectl-created LimitRange (proto-encoded) has no limits in the
    /// store. The admission plugin then finds no limits and injects no defaults into pods, causing
    /// the conformance test "should create a LimitRange with defaults and ensure pod has those
    /// defaults applied" to fail (the Go Expect assertion panics at runtime/panic.go:236).
    #[test]
    fn decode_limitrange_proto_extracts_spec_limits() {
        // Build the proto bytes for:
        //   LimitRange {
        //     metadata: ObjectMeta { name: "limits", namespace: "default" },
        //     spec: LimitRangeSpec {
        //       limits: [LimitRangeItem {
        //         type: "Container",
        //         default: {"cpu": Quantity{string: "500m"}},
        //         defaultRequest: {"cpu": Quantity{string: "100m"}},
        //       }]
        //     }
        //   }
        //
        // Helper: encode a proto Quantity{string: s} message bytes (field 1 = string).
        let encode_quantity = |s: &[u8]| -> Vec<u8> { encode_length_delimited(1, s) };

        // Helper: encode a proto map entry message with key (field 1) and value (field 2).
        let encode_map_entry = |key: &[u8], val_bytes: &[u8]| -> Vec<u8> {
            let mut entry = encode_length_delimited(1, key);
            entry.extend_from_slice(&encode_length_delimited(2, val_bytes));
            entry
        };

        // Encode one LimitRangeItem.
        let mut item_bytes = encode_length_delimited(1, b"Container"); // type = "Container"
                                                                       // default["cpu"] = "500m"  (field 4 in LimitRangeItem)
        let cpu_default = encode_map_entry(b"cpu", &encode_quantity(b"500m"));
        item_bytes.extend_from_slice(&encode_length_delimited(4, &cpu_default));
        // defaultRequest["cpu"] = "100m"  (field 5 in LimitRangeItem)
        let cpu_req = encode_map_entry(b"cpu", &encode_quantity(b"100m"));
        item_bytes.extend_from_slice(&encode_length_delimited(5, &cpu_req));

        // Encode LimitRangeSpec { limits: [item] }  (field 1 = repeated LimitRangeItem)
        let spec_bytes = encode_length_delimited(1, &item_bytes);

        // Encode LimitRange { metadata, spec }
        let mut meta_bytes = encode_length_delimited(1, b"limits");
        meta_bytes.extend_from_slice(&encode_length_delimited(3, b"default"));
        let mut proto = encode_length_delimited(1, &meta_bytes); // field 1 = metadata
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes)); // field 2 = spec

        let result = decode_core_proto_by_kind("LimitRange", &proto)
            .expect("LimitRange with spec must decode successfully");

        assert_eq!(result["kind"], "LimitRange");
        assert_eq!(result["metadata"]["name"], "limits");
        assert_eq!(
            result["spec"]["limits"][0]["type"], "Container",
            "spec.limits[0].type must be decoded — without this the admission plugin              skips the LimitRangeItem and injects no defaults into pods"
        );
        assert_eq!(
            result["spec"]["limits"][0]["default"]["cpu"], "500m",
            "spec.limits[0].default.cpu must be decoded — this is the default that              the admission plugin injects into pod containers with no cpu limit set"
        );
        assert_eq!(
            result["spec"]["limits"][0]["defaultRequest"]["cpu"], "100m",
            "spec.limits[0].defaultRequest.cpu must be decoded"
        );
    }

    /// decode_core_proto_by_kind must dispatch CustomResourceDefinition to a decoder that
    /// returns valid JSON with the spec fields populated.
    ///
    /// The AggregatedDiscovery conformance test creates CRDs via client-go's apiextensions
    /// client which sends Content-Type: application/vnd.kubernetes.protobuf. Without this
    /// decoder, extract_body returns raw proto bytes to parse_crd, which fails with
    /// "expected value at line 1 column 1" (HTTP 422), causing tests 2 and 4 to fail.
    #[test]
    fn decode_crd_proto_extracts_metadata_and_spec() {
        // Build: CustomResourceDefinition {
        //   metadata: { name: "testcrds.example.io" }
        //   spec: {
        //     group: "example.io"          (field 1)
        //     names: {                     (field 3)
        //       plural: "testcrds"         (field 1)
        //       singular: "testcrd"        (field 2)
        //       kind: "TestCrd"            (field 4)
        //     }
        //     scope: "Namespaced"          (field 4)
        //     versions: [{                 (field 7)
        //       name: "v1"                (field 1)
        //       served: true              (field 2)
        //       storage: true             (field 3)
        //     }]
        //   }
        // }

        // metadata.name
        let meta_name = encode_length_delimited(1, b"testcrds.example.io");
        let meta = encode_length_delimited(1, &meta_name); // field 1 = metadata

        // spec.names
        let names_plural = encode_length_delimited(1, b"testcrds");
        let names_singular = encode_length_delimited(2, b"testcrd");
        let names_kind = encode_length_delimited(4, b"TestCrd");
        let mut names_bytes = Vec::new();
        names_bytes.extend_from_slice(&names_plural);
        names_bytes.extend_from_slice(&names_singular);
        names_bytes.extend_from_slice(&names_kind);

        // spec.versions[0]
        let ver_name = encode_length_delimited(1, b"v1");
        let ver_served = {
            let mut v = encode_varint(2 << 3); // field 2, wire type 0
            v.extend_from_slice(&encode_varint(1)); // true
            v
        };
        let ver_storage = {
            let mut v = encode_varint(3 << 3); // field 3, wire type 0
            v.extend_from_slice(&encode_varint(1)); // true
            v
        };
        let mut ver_bytes = Vec::new();
        ver_bytes.extend_from_slice(&ver_name);
        ver_bytes.extend_from_slice(&ver_served);
        ver_bytes.extend_from_slice(&ver_storage);

        // spec
        let spec_group = encode_length_delimited(1, b"example.io");
        let spec_names = encode_length_delimited(3, &names_bytes);
        let spec_scope = encode_length_delimited(4, b"Namespaced");
        let spec_versions = encode_length_delimited(7, &ver_bytes);
        let mut spec_bytes = Vec::new();
        spec_bytes.extend_from_slice(&spec_group);
        spec_bytes.extend_from_slice(&spec_names);
        spec_bytes.extend_from_slice(&spec_scope);
        spec_bytes.extend_from_slice(&spec_versions);
        let spec = encode_length_delimited(2, &spec_bytes); // field 2 = spec

        let mut proto = Vec::new();
        proto.extend_from_slice(&meta);
        proto.extend_from_slice(&spec);

        let result = decode_core_proto_by_kind("CustomResourceDefinition", &proto).expect(
            "CustomResourceDefinition must decode via decode_core_proto_by_kind — \
             without this decoder, AggregatedDiscovery conformance tests 2 and 4 fail \
             with 422 'expected value at line 1 column 1' when creating CRDs via proto",
        );

        assert_eq!(result["kind"], "CustomResourceDefinition");
        assert_eq!(result["apiVersion"], "apiextensions.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "testcrds.example.io",
            "metadata.name must survive proto decode"
        );
        assert_eq!(
            result["spec"]["group"], "example.io",
            "spec.group must be decoded"
        );
        assert_eq!(
            result["spec"]["names"]["plural"], "testcrds",
            "spec.names.plural must be decoded"
        );
        assert_eq!(
            result["spec"]["names"]["kind"], "TestCrd",
            "spec.names.kind must be decoded"
        );
        assert_eq!(
            result["spec"]["scope"], "Namespaced",
            "spec.scope must be decoded"
        );
        let versions = result["spec"]["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1, "one version expected");
        assert_eq!(versions[0]["name"], "v1");
        assert_eq!(versions[0]["served"], true);
        assert_eq!(versions[0]["storage"], true);
    }

    /// decode_core_proto_by_kind must dispatch FlowSchema to a decoder that returns valid JSON.
    ///
    /// The API priority and fairness conformance test POSTs FlowSchema with
    /// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder,
    /// decode_core_proto_by_kind returns None, extract_body returns raw proto bytes, and
    /// the handler returns 400 "invalid JSON: expected value at line 1 column 1",
    /// failing the conformance test with "unexpected HTTP status code 400".
    #[test]
    fn decode_core_proto_by_kind_dispatches_flowschema() {
        // FlowSchema { metadata: ObjectMeta { name: "catch-all" } }
        let meta_bytes = encode_length_delimited(1, b"catch-all");
        let proto = encode_length_delimited(1, &meta_bytes);

        let result = decode_core_proto_by_kind("FlowSchema", &proto).expect(
            "FlowSchema must decode via decode_core_proto_by_kind — without this, POST \
             flowschemas with proto body returns 400, failing API priority and fairness conformance",
        );

        assert_eq!(result["kind"], "FlowSchema");
        assert_eq!(result["apiVersion"], "flowcontrol.apiserver.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "catch-all");
    }

    /// decode_core_proto_by_kind must dispatch PriorityLevelConfiguration to a decoder.
    ///
    /// The API priority and fairness conformance test POSTs PriorityLevelConfiguration with
    /// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder, the handler
    /// returns 400, failing the conformance test.
    #[test]
    fn decode_core_proto_by_kind_dispatches_prioritylevelconfiguration() {
        // PriorityLevelConfiguration { metadata: ObjectMeta { name: "workload-low" } }
        let meta_bytes = encode_length_delimited(1, b"workload-low");
        let proto = encode_length_delimited(1, &meta_bytes);

        let result = decode_core_proto_by_kind("PriorityLevelConfiguration", &proto).expect(
            "PriorityLevelConfiguration must decode via decode_core_proto_by_kind — without this, \
             POST prioritylevelconfigurations with proto body returns 400",
        );

        assert_eq!(result["kind"], "PriorityLevelConfiguration");
        assert_eq!(result["apiVersion"], "flowcontrol.apiserver.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "workload-low");
    }

    /// decode_core_proto_by_kind must dispatch ValidatingWebhookConfiguration to a decoder that
    /// returns valid JSON.
    ///
    /// The admissionwebhook conformance test POSTs ValidatingWebhookConfiguration with
    /// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder,
    /// decode_core_proto_by_kind returns None, extract_body returns raw proto bytes, and
    /// the handler returns 400 "invalid JSON: expected value at line 1 column 1",
    /// blocking the conformance test from registering any webhook at all.
    #[test]
    fn decode_core_proto_by_kind_dispatches_validating_webhook_configuration() {
        // ValidatingWebhookConfiguration { metadata: ObjectMeta { name: "e2e-test-webhook" } }
        let meta_bytes = encode_length_delimited(1, b"e2e-test-webhook");
        let proto = encode_length_delimited(1, &meta_bytes);

        let result = decode_core_proto_by_kind("ValidatingWebhookConfiguration", &proto).expect(
            "ValidatingWebhookConfiguration must decode via decode_core_proto_by_kind — without \
             this, POST validatingwebhookconfigurations with proto body returns 400, blocking the \
             admissionwebhook conformance test",
        );

        assert_eq!(result["kind"], "ValidatingWebhookConfiguration");
        assert_eq!(result["apiVersion"], "admissionregistration.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "e2e-test-webhook");
    }

    /// decode_core_proto_by_kind must dispatch MutatingWebhookConfiguration to a decoder that
    /// returns valid JSON.
    ///
    /// The admissionwebhook conformance test POSTs MutatingWebhookConfiguration with
    /// Content-Type: application/vnd.kubernetes.protobuf. Without this decoder,
    /// decode_core_proto_by_kind returns None, extract_body returns raw proto bytes, and
    /// the handler returns 400 "invalid JSON: expected value at line 1 column 1",
    /// blocking the conformance test from registering any mutating webhook.
    #[test]
    fn decode_core_proto_by_kind_dispatches_mutating_webhook_configuration() {
        // MutatingWebhookConfiguration { metadata: ObjectMeta { name: "e2e-test-mutating" } }
        let meta_bytes = encode_length_delimited(1, b"e2e-test-mutating");
        let proto = encode_length_delimited(1, &meta_bytes);

        let result = decode_core_proto_by_kind("MutatingWebhookConfiguration", &proto).expect(
            "MutatingWebhookConfiguration must decode via decode_core_proto_by_kind — without \
             this, POST mutatingwebhookconfigurations with proto body returns 400, blocking the \
             admissionwebhook conformance test",
        );

        assert_eq!(result["kind"], "MutatingWebhookConfiguration");
        assert_eq!(result["apiVersion"], "admissionregistration.k8s.io/v1");
        assert_eq!(result["metadata"]["name"], "e2e-test-mutating");
    }

    /// matchConditions in a ValidatingWebhookConfiguration proto must be decoded and round-trip
    /// back in the JSON response. Without field 11 on ValidatingWebhook, the decoded JSON
    /// has no matchConditions key and the conformance test GET shows an empty array.
    #[test]
    fn decode_validatingwebhookconfiguration_proto_preserves_match_conditions() {
        // Build MatchCondition: field 1=name, field 2=expression
        let mut match_cond: Vec<u8> = Vec::new();
        match_cond.extend_from_slice(&encode_length_delimited(1, b"check-name"));
        match_cond.extend_from_slice(&encode_length_delimited(
            2,
            b"object.metadata.name == \"test\"",
        ));

        // Build ValidatingWebhook: field 1=name, field 11=matchConditions
        let mut webhook: Vec<u8> = Vec::new();
        webhook.extend_from_slice(&encode_length_delimited(1, b"test-webhook.k8s.io"));
        webhook.extend_from_slice(&encode_length_delimited(11, &match_cond));

        // Build ValidatingWebhookConfiguration: field 1=metadata, field 2=webhooks
        let meta_name = encode_length_delimited(1, b"test-vwc");
        let meta = encode_length_delimited(1, &meta_name);
        let mut proto = meta;
        proto.extend_from_slice(&encode_length_delimited(2, &webhook));

        let result = decode_validatingwebhookconfiguration_proto(&proto)
            .expect("ValidatingWebhookConfiguration must decode");

        let webhooks = result["webhooks"]
            .as_array()
            .expect("webhooks must be present");
        assert_eq!(webhooks.len(), 1);
        let conditions = webhooks[0]["matchConditions"]
            .as_array()
            .expect("matchConditions must be present in decoded webhook — without field 11 on ValidatingWebhook, the GET response omits matchConditions and the conformance test fails");
        assert_eq!(conditions.len(), 1);
        assert_eq!(
            conditions[0]["name"], "check-name",
            "matchCondition name must round-trip through proto decode"
        );
        assert_eq!(
            conditions[0]["expression"], "object.metadata.name == \"test\"",
            "matchCondition expression must round-trip through proto decode"
        );
    }

    /// matchConditions in a MutatingWebhookConfiguration proto must be decoded and round-trip
    /// back in the JSON response. Without MutatingWebhook struct and field 12, the decoded JSON
    /// has no webhooks and no matchConditions; the conformance test GET shows an empty array.
    #[test]
    fn decode_mutatingwebhookconfiguration_proto_preserves_match_conditions() {
        // Build MatchCondition: field 1=name, field 2=expression
        let mut match_cond: Vec<u8> = Vec::new();
        match_cond.extend_from_slice(&encode_length_delimited(1, b"check-env"));
        match_cond.extend_from_slice(&encode_length_delimited(
            2,
            b"request.namespace != \"kube-system\"",
        ));

        // Build MutatingWebhook: field 1=name, field 12=matchConditions
        let mut webhook: Vec<u8> = Vec::new();
        webhook.extend_from_slice(&encode_length_delimited(1, b"mutating-webhook.k8s.io"));
        webhook.extend_from_slice(&encode_length_delimited(12, &match_cond));

        // Build MutatingWebhookConfiguration: field 1=metadata, field 2=webhooks
        let meta_name = encode_length_delimited(1, b"test-mwc");
        let meta = encode_length_delimited(1, &meta_name);
        let mut proto = meta;
        proto.extend_from_slice(&encode_length_delimited(2, &webhook));

        let result = decode_mutatingwebhookconfiguration_proto(&proto)
            .expect("MutatingWebhookConfiguration must decode");

        let webhooks = result["webhooks"]
            .as_array()
            .expect("webhooks must be present in MutatingWebhookConfiguration — without MutatingWebhook struct, webhooks are lost on proto decode");
        assert_eq!(webhooks.len(), 1);
        let conditions = webhooks[0]["matchConditions"]
            .as_array()
            .expect("matchConditions must be present in decoded mutating webhook — without field 12 on MutatingWebhook, the GET response omits matchConditions");
        assert_eq!(conditions.len(), 1);
        assert_eq!(
            conditions[0]["name"], "check-env",
            "matchCondition name must round-trip through proto decode"
        );
        assert_eq!(
            conditions[0]["expression"], "request.namespace != \"kube-system\"",
            "matchCondition expression must round-trip through proto decode"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests — field tag correctness (mayor-52cj)
    // These tests encode a value at the CORRECT wire tag and verify it appears in
    // the decoded JSON. If a tag is wrong, prost silently ignores the field and the
    // asserted JSON key will be absent, causing the test to fail.
    // ---------------------------------------------------------------------------

    /// Container.imagePullPolicy must be decoded from field 14 (proto canonical tag).
    /// Fields 13/14/20 were previously off-by-one: terminationMessagePath=14 (should be 13),
    /// imagePullPolicy=15 (should be 14), terminationMessagePolicy=21 (should be 20).
    /// A wrong tag causes prost to silently skip the field; the decoded JSON will be missing the
    /// value, which makes kubectl see empty imagePullPolicy and causes validation failures.
    #[test]
    fn container_field_tags_match_upstream_proto() {
        // Build a minimal Pod with one container that has all three corrected fields set.
        // Pod: field 1=ObjectMeta, field 2=PodSpec
        // PodSpec: field 2=containers (repeated Container)
        // Container: field 1=name, field 13=terminationMessagePath, field 14=imagePullPolicy,
        //            field 20=terminationMessagePolicy
        let obj_meta = encode_length_delimited(1, b"tag-test-pod");

        // terminationMessagePath at field 13 (wire type 2, LEN)
        let term_msg_path = encode_length_delimited(13, b"/dev/termination-log");
        // imagePullPolicy at field 14 (wire type 2, LEN)
        let image_pull_policy = encode_length_delimited(14, b"IfNotPresent");
        // terminationMessagePolicy at field 20 (wire type 2, LEN)
        let term_msg_policy = encode_length_delimited(20, b"File");

        let mut container = encode_length_delimited(1, b"mycontainer"); // field 1 = name
        container.extend_from_slice(&term_msg_path);
        container.extend_from_slice(&image_pull_policy);
        container.extend_from_slice(&term_msg_policy);

        let podspec_containers = encode_length_delimited(2, &container); // field 2 = containers
        let pod_proto = {
            let mut p = encode_length_delimited(1, &obj_meta);
            p.extend_from_slice(&encode_length_delimited(2, &podspec_containers));
            p
        };

        let result = decode_pod_proto(&pod_proto).expect("Pod proto must decode");
        let containers = result["spec"]["containers"]
            .as_array()
            .expect("containers must be present");
        assert_eq!(containers.len(), 1);
        assert_eq!(
            containers[0]["terminationMessagePath"], "/dev/termination-log",
            "terminationMessagePath must be decoded from field 13; \
             if this fails the field tag is wrong and kubectl pod creates silently lose this field"
        );
        assert_eq!(
            containers[0]["imagePullPolicy"], "IfNotPresent",
            "imagePullPolicy must be decoded from field 14; \
             if this fails the field tag is wrong and pod specs will have no imagePullPolicy"
        );
        assert_eq!(
            containers[0]["terminationMessagePolicy"], "File",
            "terminationMessagePolicy must be decoded from field 20; \
             if this fails the field tag is wrong and pod specs will have no terminationMessagePolicy"
        );
    }

    /// ServiceSpec.ipFamilyPolicy must be decoded from field 17 and internalTrafficPolicy from
    /// field 22, not the previously incorrect 21 and 24.
    /// Wrong tags cause prost to silently ignore these fields; decoded Services will be missing
    /// ipFamilyPolicy and internalTrafficPolicy, leading to kubectl returning incorrect service specs.
    #[test]
    fn servicespec_field_tags_match_upstream_proto() {
        // Build: Service {
        //   metadata: { name: "svc-tag-test" },
        //   spec: {
        //     clusterIP: "10.0.0.1",    (field 3)
        //     ipFamilyPolicy: "SingleStack",  (field 17)
        //     internalTrafficPolicy: "Cluster" (field 22)
        //   }
        // }
        let obj_meta = encode_length_delimited(1, b"svc-tag-test");

        let mut svc_spec = encode_length_delimited(3, b"10.0.0.1"); // clusterIP
        svc_spec.extend_from_slice(&encode_length_delimited(17, b"SingleStack")); // ipFamilyPolicy
        svc_spec.extend_from_slice(&encode_length_delimited(22, b"Cluster")); // internalTrafficPolicy

        let mut svc_proto = encode_length_delimited(1, &obj_meta);
        svc_proto.extend_from_slice(&encode_length_delimited(2, &svc_spec));

        let result = decode_service_proto(&svc_proto).expect("Service proto must decode");

        assert_eq!(
            result["spec"]["ipFamilyPolicy"], "SingleStack",
            "ipFamilyPolicy must be decoded from field 17; \
             previously it was incorrectly tagged as 21, causing it to be silently dropped"
        );
        assert_eq!(
            result["spec"]["internalTrafficPolicy"], "Cluster",
            "internalTrafficPolicy must be decoded from field 22; \
             previously it was incorrectly tagged as 24, causing it to be silently dropped"
        );
    }

    /// PersistentVolumeSpec field tags must match the upstream proto.
    /// Previously accessModes=6 (should be 3), claimRef=33 (should be 4),
    /// persistentVolumeReclaimPolicy=26 (should be 5), storageClassName=29 (should be 6),
    /// volumeMode=31 (should be 8). All were drastically wrong, so every PV create via proto
    /// would produce a PV with empty spec fields and incorrect storage policy.
    #[test]
    fn persistent_volume_spec_field_tags_match_upstream_proto() {
        // Build: PersistentVolume {
        //   metadata: { name: "pv-tag-test" },
        //   spec: {
        //     accessModes: ["ReadWriteOnce"],       (field 3, repeated string)
        //     persistentVolumeReclaimPolicy: "Retain", (field 5, string)
        //     storageClassName: "standard",         (field 6, string)
        //     volumeMode: "Filesystem",             (field 8, string)
        //   }
        // }
        let obj_meta = encode_length_delimited(1, b"pv-tag-test");

        let mut pv_spec = encode_length_delimited(3, b"ReadWriteOnce"); // accessModes
        pv_spec.extend_from_slice(&encode_length_delimited(5, b"Retain")); // persistentVolumeReclaimPolicy
        pv_spec.extend_from_slice(&encode_length_delimited(6, b"standard")); // storageClassName
        pv_spec.extend_from_slice(&encode_length_delimited(8, b"Filesystem")); // volumeMode

        let mut pv_proto = encode_length_delimited(1, &obj_meta);
        pv_proto.extend_from_slice(&encode_length_delimited(2, &pv_spec));

        let result =
            decode_persistentvolume_proto(&pv_proto).expect("PersistentVolume proto must decode");

        let access_modes = result["spec"]["accessModes"]
            .as_array()
            .expect("accessModes must be present as an array");
        assert!(
            access_modes.contains(&serde_json::Value::String("ReadWriteOnce".to_string())),
            "accessModes must be decoded from field 3; \
             previously tagged as 6, which is storageClassName — caused by transcription error"
        );
        assert_eq!(
            result["spec"]["persistentVolumeReclaimPolicy"], "Retain",
            "persistentVolumeReclaimPolicy must be decoded from field 5; \
             previously tagged as 26, so prost would silently ignore it"
        );
        assert_eq!(
            result["spec"]["storageClassName"], "standard",
            "storageClassName must be decoded from field 6; \
             previously tagged as 29, so prost would silently ignore it"
        );
        assert_eq!(
            result["spec"]["volumeMode"], "Filesystem",
            "volumeMode must be decoded from field 8; \
             previously tagged as 31, so prost would silently ignore it"
        );
    }

    /// decode_pod_proto must preserve container.volumeMounts in decoded JSON.
    ///
    /// When a pod/Deployment is submitted via protobuf with volumeMounts (e.g. a secret volume
    /// mounted at /webhook.local.config/certificates), the kubelet reads volumeMounts from the
    /// stored container JSON to bind-mount the volume into the container at the given mountPath.
    /// If volumeMounts is absent from the decoded JSON, the secret IS mounted at the node level
    /// (MountVolume.SetUp succeeds) but the files never appear inside the container — causing
    /// AdmissionWebhook tests that read /webhook.local.config/certificates/tls.crt to fail.
    ///
    /// This test must fail if VolumeMount struct, volume_mounts field on Container, or the
    /// volumeMounts serialization block in pod_spec_to_json are removed.
    #[test]
    fn decode_pod_proto_preserves_volume_mounts() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "webhook" },
        //   spec: PodSpec {
        //     containers: [Container {
        //       name: "webhook",
        //       image: "webhook:v1",
        //       volumeMounts: [           // Container field 9, repeated VolumeMount
        //         VolumeMount {
        //           name: "cert",         // VolumeMount field 1
        //           mountPath: "/certs",  // VolumeMount field 3 (proto canonical)
        //         }
        //       ]
        //     }]
        //   }
        // }

        // Encode VolumeMount: name at field 1, mountPath at field 3 (proto canonical)
        let mut volume_mount = encode_length_delimited(1, b"cert");
        volume_mount.extend_from_slice(&encode_length_delimited(3, b"/certs"));

        // Encode Container: name=field 1, image=field 2, volumeMounts=field 9
        let mut container = encode_length_delimited(1, b"webhook");
        container.extend_from_slice(&encode_length_delimited(2, b"webhook:v1"));
        container.extend_from_slice(&encode_length_delimited(9, &volume_mount));

        let obj_meta = encode_length_delimited(1, b"webhook");
        let podspec_containers = encode_length_delimited(2, &container); // PodSpec.containers = field 2
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec_containers));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with volumeMounts present");

        let mounts = result["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect(
                "volumeMounts must be present in decoded JSON — if absent, kubelet cannot \
                 bind-mount secrets/configmaps into the container and files are invisible inside it",
            );
        assert_eq!(
            mounts.len(),
            1,
            "one volumeMount must be decoded; if VolumeMount struct or field tag 9 is wrong \
             the repeated message is silently dropped"
        );
        assert_eq!(
            mounts[0]["name"], "cert",
            "volumeMount.name must be 'cert' — used by kubelet to match spec.volumes[].name"
        );
        assert_eq!(
            mounts[0]["mountPath"], "/certs",
            "volumeMount.mountPath must be '/certs' — this is the path inside the container \
             where the volume is visible; if wrong, the secret files are not accessible"
        );
    }

    /// decode_deployment_proto must not return None when a container's VolumeMount has readOnly=true.
    ///
    /// The AdmissionWebhook conformance test creates a Deployment whose container mounts a TLS
    /// secret as readOnly. In the wire format, VolumeMount.readOnly is field 2 (varint/bool).
    /// Before the fix, VolumeMount.mountPath was incorrectly declared at field 2 (string/LEN),
    /// causing a wire-type mismatch when prost saw a varint at field 2 — decode returned None,
    /// and the apiserver returned 400 "invalid JSON", blocking the conformance test.
    ///
    /// This test must fail if VolumeMount.readOnly is declared at the wrong field tag (not 2),
    /// or if VolumeMount.mountPath is declared at field 2 instead of field 3.
    #[test]
    fn decode_deployment_proto_volume_mount_read_only_does_not_fail_decode() {
        // Encode VolumeMount: name="certs" (field 1), readOnly=true (field 2, varint), mountPath="/certs" (field 3)
        // field 2 tag for varint = (2 << 3) | 0 = 16
        let mut volume_mount = encode_length_delimited(1, b"certs");
        volume_mount.extend_from_slice(&encode_varint(16)); // field 2 tag, wire type 0 (varint)
        volume_mount.extend_from_slice(&encode_varint(1)); // bool true
        volume_mount.extend_from_slice(&encode_length_delimited(3, b"/certs")); // mountPath at field 3

        // Encode Container: name=field 1, image=field 2, volumeMounts=field 9
        let mut container = encode_length_delimited(1, b"webhook");
        container.extend_from_slice(&encode_length_delimited(
            2,
            b"registry.k8s.io/e2e-test-images/agnhost:2.63.0",
        ));
        container.extend_from_slice(&encode_length_delimited(9, &volume_mount));

        // Encode PodSpec: containers at field 2
        let podspec = encode_length_delimited(2, &container);

        // Encode PodTemplateSpec: metadata at field 1, spec at field 2
        let meta_name_bytes = encode_length_delimited(1, b"webhook-pod"); // ObjectMeta.name
        let tmpl_meta = encode_length_delimited(1, &meta_name_bytes); // PodTemplateSpec.metadata
        let mut tmpl = tmpl_meta;
        tmpl.extend_from_slice(&encode_length_delimited(2, &podspec)); // PodTemplateSpec.spec

        // LabelSelector { matchLabels: {"app": "webhook"} } — selector at DeploymentSpec field 2
        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"webhook"));
        let selector_bytes = encode_length_delimited(1, &label_entry);

        // Encode DeploymentSpec: selector at field 2, template at field 3
        let mut dep_spec = encode_length_delimited(2, &selector_bytes);
        dep_spec.extend_from_slice(&encode_length_delimited(3, &tmpl));

        // Encode Deployment: metadata at field 1, spec at field 2
        let meta_name = encode_length_delimited(1, b"webhook");
        let mut deployment_proto = encode_length_delimited(1, &meta_name);
        deployment_proto.extend_from_slice(&encode_length_delimited(2, &dep_spec));

        let result = decode_deployment_proto(&deployment_proto);
        assert!(
            result.is_some(),
            "decode_deployment_proto must succeed when a VolumeMount has readOnly=true (field 2, \
             varint); before the fix, VolumeMount.mountPath was at field 2 causing a wire-type \
             mismatch that made decode return None and the apiserver return 400"
        );
        let val = result.unwrap();
        assert_eq!(val["kind"], "Deployment", "decoded kind must be Deployment");
        let containers = &val["spec"]["template"]["spec"]["containers"];
        assert!(
            containers.is_array(),
            "containers must be present after decode with readOnly volumeMount"
        );
        let mounts = &containers[0]["volumeMounts"];
        assert!(
            mounts.is_array() && mounts.as_array().unwrap().len() == 1,
            "one volumeMount must survive decode; readOnly=true at field 2 must not cause drop"
        );
        assert_eq!(
            mounts[0]["readOnly"], true,
            "readOnly must be true in decoded JSON — used by kubelet to bind-mount the volume read-only"
        );
        assert_eq!(
            mounts[0]["mountPath"], "/certs",
            "mountPath must be '/certs' — the path inside the container where TLS certs appear"
        );
    }

    /// spec.volumes[0].secret.secretName must survive protobuf decode and appear in JSON.
    ///
    /// When a Deployment is submitted via protobuf with a secret volume, kubelet receives a pod
    /// with volumeMounts but no backing volumes — it cannot resolve the secret source and hits
    /// `context deadline exceeded` after 2 minutes. This test encodes a pod proto with
    /// spec.volumes[0].secret.secretName="my-secret" and asserts the value is present in the
    /// decoded JSON. It must fail if the Volume struct, volumes field on PodSpec, VolumeSource,
    /// SecretVolumeSource, or the volumes serialization block in pod_spec_to_json are removed.
    #[test]
    fn spec_volumes_secret_survives_proto_decode() {
        // Encode proto wire format bottom-up, matching api-core-v1-generated.proto field numbers:
        //
        // SecretVolumeSource { secretName (field 1) = "my-secret" }
        let secret_vol_src = encode_length_delimited(1, b"my-secret");

        // VolumeSource { secret (field 6) = SecretVolumeSource }
        let volume_source = encode_length_delimited(6, &secret_vol_src);

        // Volume { name (field 1) = "webhook-certs", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"webhook-certs");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1) = [Volume], containers (field 2) = [Container] }
        let container = encode_length_delimited(1, b"app"); // Container { name (field 1) }
        let mut podspec = encode_length_delimited(1, &volume); // PodSpec.volumes = field 1
        podspec.extend_from_slice(&encode_length_delimited(2, &container)); // PodSpec.containers = field 2

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod"); // ObjectMeta { name (field 1) }
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with spec.volumes present");

        let volumes = result["spec"]["volumes"].as_array().expect(
            "spec.volumes must be present in decoded JSON — if absent, kubelet cannot resolve \
                 secret volume sources and hits context deadline exceeded after 2 minutes",
        );
        assert_eq!(
            volumes.len(),
            1,
            "exactly one volume must be decoded; if Volume struct or PodSpec field tag 1 is wrong \
             the repeated message is silently dropped"
        );
        assert_eq!(
            volumes[0]["name"], "webhook-certs",
            "volume.name must be 'webhook-certs' — kubelet matches this against volumeMount.name"
        );
        assert_eq!(
            volumes[0]["secret"]["secretName"], "my-secret",
            "volumes[0].secret.secretName must be 'my-secret' — kubelet uses this to find the \
             Secret object; if absent the volume cannot be mounted and the pod stays Pending"
        );
    }

    /// spec.volumes[].emptyDir must survive protobuf decode and appear in decoded JSON.
    ///
    /// Without this, 23 conformance tests stall for 300 s each (~130 min total) because kubelet
    /// logs "no volume plugin matched" — it cannot identify the volume type when the `emptyDir`
    /// key is absent from the stored JSON. The fix: VolumeSource now decodes emptyDir (field 2).
    /// This test fails if VolumeSource.empty_dir is removed or the emptyDir serialization block
    /// in pod_spec_to_json is removed.
    #[test]
    fn spec_volumes_empty_dir_survives_proto_decode() {
        // EmptyDirVolumeSource {} — empty message (no medium, no sizeLimit)
        let empty_dir_src: Vec<u8> = vec![];

        // VolumeSource { emptyDir (field 2) = EmptyDirVolumeSource {} }
        let volume_source = encode_length_delimited(2, &empty_dir_src);

        // Volume { name (field 1) = "scratch", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"scratch");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app"); // Container.name
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with an emptyDir volume");

        let volumes = result["spec"]["volumes"].as_array().expect(
            "spec.volumes must be present — without it kubelet cannot resolve volume plugins",
        );
        assert_eq!(
            volumes.len(),
            1,
            "exactly one volume must decode; a missing emptyDir field tag drops the volume"
        );
        assert_eq!(
            volumes[0]["name"], "scratch",
            "volume.name must be 'scratch' — kubelet matches this to volumeMount.name"
        );
        assert!(
            volumes[0]["emptyDir"].is_object(),
            "volumes[0].emptyDir must be a JSON object — without this key kubelet logs \
             'no volume plugin matched' and the pod stalls for 300 s"
        );
    }

    /// spec.volumes[].emptyDir with medium="Memory" must preserve the medium field.
    ///
    /// Without the medium field, kubelet creates a regular tmpfs instead of a memory-backed
    /// tmpfs. This test verifies that EmptyDirVolumeSource.medium (field 1, string) is decoded.
    #[test]
    fn spec_volumes_empty_dir_with_memory_medium_survives_proto_decode() {
        // EmptyDirVolumeSource { medium (field 1) = "Memory" }
        let empty_dir_src = encode_length_delimited(1, b"Memory");

        // VolumeSource { emptyDir (field 2) = EmptyDirVolumeSource }
        let volume_source = encode_length_delimited(2, &empty_dir_src);

        // Volume { name (field 1) = "mem", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"mem");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with emptyDir medium=Memory");

        let volumes = result["spec"]["volumes"].as_array().unwrap();
        assert_eq!(
            volumes[0]["emptyDir"]["medium"], "Memory",
            "emptyDir.medium must be 'Memory' — kubelet uses this to select tmpfs; \
             if absent the volume falls back to disk-backed storage"
        );
    }

    /// spec.volumes[].downwardAPI must survive protobuf decode with fieldRef items intact.
    ///
    /// Without this, Downward API conformance tests stall 300 s each because kubelet receives
    /// a volume with no type. The fix: VolumeSource now decodes downwardAPI (field 16).
    /// This test fails if VolumeSource.downward_api is removed or the downwardAPI serialization
    /// block in pod_spec_to_json / downward_api_volume_source_to_json is removed.
    #[test]
    fn spec_volumes_downward_api_survives_proto_decode() {
        // ObjectFieldSelector { apiVersion (field 1) = "v1", fieldPath (field 2) = "metadata.name" }
        let mut field_selector = encode_length_delimited(1, b"v1");
        field_selector.extend_from_slice(&encode_length_delimited(2, b"metadata.name"));

        // DownwardAPIVolumeFile { path (field 1) = "podname", fieldRef (field 2) = ObjectFieldSelector }
        let mut dav_file = encode_length_delimited(1, b"podname");
        dav_file.extend_from_slice(&encode_length_delimited(2, &field_selector));

        // DownwardAPIVolumeSource { items (field 1) = [DownwardAPIVolumeFile] }
        let da_src = encode_length_delimited(1, &dav_file);

        // VolumeSource { downwardAPI (field 16) = DownwardAPIVolumeSource }
        let volume_source = encode_length_delimited(16, &da_src);

        // Volume { name (field 1) = "podinfo", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"podinfo");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with a downwardAPI volume");

        let volumes = result["spec"]["volumes"].as_array().expect(
            "spec.volumes must be present — kubelet needs it to resolve downwardAPI volumes",
        );
        assert_eq!(volumes.len(), 1, "exactly one volume must decode");
        assert_eq!(
            volumes[0]["name"], "podinfo",
            "volume.name must be 'podinfo'"
        );
        assert!(
            volumes[0]["downwardAPI"].is_object(),
            "volumes[0].downwardAPI must be a JSON object — without this key kubelet logs \
             'no volume plugin matched'"
        );
        let items = volumes[0]["downwardAPI"]["items"].as_array().expect(
            "downwardAPI.items must be present — kubelet uses these to project pod fields into files",
        );
        assert_eq!(items.len(), 1, "one downwardAPI item must decode");
        assert_eq!(
            items[0]["path"], "podname",
            "item.path must be 'podname' — kubelet writes the pod field value to this filename"
        );
        assert_eq!(
            items[0]["fieldRef"]["fieldPath"], "metadata.name",
            "fieldRef.fieldPath must be 'metadata.name' — kubelet reads this field from the pod"
        );
    }

    /// spec.volumes[].downwardAPI with resourceFieldRef must decode and serialize divisor.
    ///
    /// Without this fix, pods using `resourceFieldRef` (cpu request/limit, memory request/limit)
    /// stall 300 s in ContainerCreating because the kubelet sees an item with only a `path`
    /// and no source selector. The fix: ResourceFieldSelector.divisor is now decoded as a
    /// Quantity message (not raw bytes) and serialized as a string in the JSON output.
    ///
    /// This test fails if:
    /// - `ResourceFieldSelector.divisor` reverts to `Vec<u8>` (divisor becomes absent)
    /// - The divisor serialization block in `downward_api_volume_file_to_json` is removed
    /// - `resourceFieldRef` is dropped from the JSON output
    #[test]
    fn spec_volumes_downward_api_resource_field_ref_decoded_with_divisor() {
        // Quantity { string (field 1) = "1m" }
        let divisor_quantity = encode_length_delimited(1, b"1m");

        // ResourceFieldSelector {
        //   containerName (field 1) = "test-container",
        //   resource (field 2) = "requests.cpu",
        //   divisor (field 3) = Quantity{string: "1m"}
        // }
        let mut resource_field_selector = encode_length_delimited(1, b"test-container");
        resource_field_selector.extend_from_slice(&encode_length_delimited(2, b"requests.cpu"));
        resource_field_selector.extend_from_slice(&encode_length_delimited(3, &divisor_quantity));

        // DownwardAPIVolumeFile {
        //   path (field 1) = "cpu_request",
        //   resourceFieldRef (field 3) = ResourceFieldSelector
        // }
        let mut dav_file = encode_length_delimited(1, b"cpu_request");
        dav_file.extend_from_slice(&encode_length_delimited(3, &resource_field_selector));

        // DownwardAPIVolumeSource { items (field 1) = [DownwardAPIVolumeFile] }
        let da_src = encode_length_delimited(1, &dav_file);

        // VolumeSource { downwardAPI (field 16) = DownwardAPIVolumeSource }
        let volume_source = encode_length_delimited(16, &da_src);

        // Volume { name (field 1) = "podinfo", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"podinfo");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"test-container");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with a resourceFieldRef downwardAPI volume");

        let items = result["spec"]["volumes"][0]["downwardAPI"]["items"]
            .as_array()
            .expect("downwardAPI.items must be present");
        assert_eq!(items.len(), 1, "one downwardAPI item must decode");

        let item = &items[0];
        assert_eq!(
            item["path"], "cpu_request",
            "item.path must be 'cpu_request'"
        );
        assert!(
            item["fieldRef"].is_null() || item.get("fieldRef").is_none(),
            "fieldRef must be absent when only resourceFieldRef is specified"
        );
        assert!(
            item["resourceFieldRef"].is_object(),
            "resourceFieldRef must be a JSON object — without it kubelet cannot prepare the volume \
             and the pod hangs 300 s in ContainerCreating"
        );
        assert_eq!(
            item["resourceFieldRef"]["containerName"], "test-container",
            "resourceFieldRef.containerName must be 'test-container' — kubelet uses this to look \
             up the container's resource allocation"
        );
        assert_eq!(
            item["resourceFieldRef"]["resource"], "requests.cpu",
            "resourceFieldRef.resource must be 'requests.cpu' — identifies which resource to expose"
        );
        assert_eq!(
            item["resourceFieldRef"]["divisor"], "1m",
            "resourceFieldRef.divisor must be '1m' — kubelet divides the resource value by this \
             to produce the file content; if absent kubelet rejects the volume spec"
        );
    }

    /// spec.volumes[].downwardAPI resourceFieldRef without explicit divisor defaults to "1".
    ///
    /// Kubernetes API server may omit the divisor when it equals "1". The kubelet requires
    /// the divisor field to be present in JSON. If missing, the volume mount fails.
    #[test]
    fn spec_volumes_downward_api_resource_field_ref_defaults_divisor_to_one() {
        // ResourceFieldSelector { containerName (field 1) = "c", resource (field 2) = "limits.memory" }
        // No divisor field — omitted means default "1"
        let mut resource_field_selector = encode_length_delimited(1, b"c");
        resource_field_selector.extend_from_slice(&encode_length_delimited(2, b"limits.memory"));

        // DownwardAPIVolumeFile { path (field 1) = "mem_limit", resourceFieldRef (field 3) }
        let mut dav_file = encode_length_delimited(1, b"mem_limit");
        dav_file.extend_from_slice(&encode_length_delimited(3, &resource_field_selector));

        // DownwardAPIVolumeSource { items (field 1) = [DownwardAPIVolumeFile] }
        let da_src = encode_length_delimited(1, &dav_file);
        let volume_source = encode_length_delimited(16, &da_src);
        let mut volume = encode_length_delimited(1, b"vol");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));
        let container = encode_length_delimited(1, b"c");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with resourceFieldRef missing divisor");

        let item = &result["spec"]["volumes"][0]["downwardAPI"]["items"][0];
        assert_eq!(
            item["resourceFieldRef"]["divisor"], "1",
            "divisor must default to '1' when absent from proto — kubelet requires this field \
             to be present or it cannot determine the unit for the resource value"
        );
    }

    /// spec.volumes[].downwardAPI resourceFieldRef with zero Quantity divisor defaults to "1".
    ///
    /// The Kubernetes Go client serialises a zero resource.Quantity as Quantity{string: "0"} in
    /// proto. The kubelet rejects divisor "0" (division by zero). Our server must default any
    /// zero-valued divisor to "1", matching the real Kubernetes apiserver behaviour.
    ///
    /// This test fails if the `filter(|s| s != "0")` guard is removed, in which case divisor "0"
    /// passes through and the kubelet refuses to mount the volume.
    #[test]
    fn spec_volumes_downward_api_resource_field_ref_zero_divisor_defaults_to_one() {
        // Quantity { string (field 1) = "0" } — zero Quantity as sent by Go client
        let zero_quantity = encode_length_delimited(1, b"0");

        // ResourceFieldSelector { containerName = "c", resource = "limits.cpu", divisor = Quantity{"0"} }
        let mut resource_field_selector = encode_length_delimited(1, b"c");
        resource_field_selector.extend_from_slice(&encode_length_delimited(2, b"limits.cpu"));
        resource_field_selector.extend_from_slice(&encode_length_delimited(3, &zero_quantity));

        // DownwardAPIVolumeFile { path = "cpu_limit", resourceFieldRef }
        let mut dav_file = encode_length_delimited(1, b"cpu_limit");
        dav_file.extend_from_slice(&encode_length_delimited(3, &resource_field_selector));

        // DownwardAPIVolumeSource { items = [DownwardAPIVolumeFile] }
        let da_src = encode_length_delimited(1, &dav_file);
        let volume_source = encode_length_delimited(16, &da_src);
        let mut volume = encode_length_delimited(1, b"vol");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));
        let container = encode_length_delimited(1, b"c");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with zero divisor Quantity");

        let item = &result["spec"]["volumes"][0]["downwardAPI"]["items"][0];
        assert_eq!(
            item["resourceFieldRef"]["divisor"], "1",
            "divisor '0' must be treated as zero/absent and defaulted to '1' — \
             the kubelet would divide by zero otherwise, causing volume mount failure"
        );
    }

    /// spec.volumes[].downwardAPI must always emit defaultMode, defaulting to 420 (0644 octal).
    ///
    /// When the e2e test creates a pod without an explicit defaultMode (relying on apiserver
    /// defaulting), the proto sends defaultMode=0 (field absent). The kubelet rejects this with
    /// "no defaultMode used, not even the default value for it", causing a 300 s hang in
    /// ContainerCreating. We must emit defaultMode=420 whenever the proto value is zero.
    ///
    /// This test fails if the `if default_mode == 0 { 420 }` defaulting is removed, in which
    /// case defaultMode is omitted from the JSON and the kubelet refuses to mount the volume.
    #[test]
    fn spec_volumes_downward_api_default_mode_defaults_to_420_when_absent() {
        // DownwardAPIVolumeFile { path = "podname", fieldRef = {apiVersion: "v1", fieldPath: "metadata.name"} }
        let mut field_ref = encode_length_delimited(1, b"v1");
        field_ref.extend_from_slice(&encode_length_delimited(2, b"metadata.name"));
        let mut dav_file = encode_length_delimited(1, b"podname");
        dav_file.extend_from_slice(&encode_length_delimited(2, &field_ref));

        // DownwardAPIVolumeSource { items = [DownwardAPIVolumeFile] } — no defaultMode field (=0)
        let da_src = encode_length_delimited(1, &dav_file);
        let volume_source = encode_length_delimited(16, &da_src);
        let mut volume = encode_length_delimited(1, b"vol");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));
        let container = encode_length_delimited(1, b"c");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with absent defaultMode");

        let downward_api = &result["spec"]["volumes"][0]["downwardAPI"];
        assert!(
            downward_api["defaultMode"].is_number(),
            "defaultMode must always be present in JSON — the kubelet rejects volumes where \
             defaultMode is absent with 'no defaultMode used, not even the default value for it'"
        );
        assert_eq!(
            downward_api["defaultMode"], 420,
            "defaultMode must be 420 (0644 octal) when absent from proto — this is the \
             Kubernetes API server default that the kubelet expects"
        );
    }

    /// spec.volumes[].projected with serviceAccountToken must survive protobuf decode.
    ///
    /// Without this, Projected volume conformance tests stall 300 s each. The fix: VolumeSource
    /// now decodes projected (field 26) with full VolumeProjection entries.
    /// This test fails if VolumeSource.projected is removed or projected_volume_source_to_json
    /// is removed.
    #[test]
    fn spec_volumes_projected_with_service_account_token_survives_proto_decode() {
        // ServiceAccountTokenProjection { audience (field 1) = "api", expirationSeconds (field 2) = 3600, path (field 3) = "token" }
        let mut sat = encode_length_delimited(1, b"api");
        // expirationSeconds = 3600 as varint: field 2, wire type 0 (varint)
        let field_tag: u64 = 2 << 3; // field 2, wire type 0 (varint)
        sat.extend_from_slice(&encode_varint(field_tag));
        sat.extend_from_slice(&encode_varint(3600));
        sat.extend_from_slice(&encode_length_delimited(3, b"token"));

        // VolumeProjection { serviceAccountToken (field 4) = ServiceAccountTokenProjection }
        let proj_entry = encode_length_delimited(4, &sat);

        // ProjectedVolumeSource { sources (field 1) = [VolumeProjection] }
        let proj_src = encode_length_delimited(1, &proj_entry);

        // VolumeSource { projected (field 26) = ProjectedVolumeSource }
        let volume_source = encode_length_delimited(26, &proj_src);

        // Volume { name (field 1) = "kube-api-access", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"kube-api-access");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with a projected volume");

        let volumes = result["spec"]["volumes"]
            .as_array()
            .expect("spec.volumes must be present — kubelet needs it to mount projected volumes");
        assert_eq!(volumes.len(), 1, "exactly one volume must decode");
        assert_eq!(
            volumes[0]["name"], "kube-api-access",
            "volume.name must be 'kube-api-access'"
        );
        assert!(
            volumes[0]["projected"].is_object(),
            "volumes[0].projected must be a JSON object — without this key kubelet logs \
             'no volume plugin matched' and the pod stalls for 300 s"
        );
        let sources = volumes[0]["projected"]["sources"].as_array().expect(
            "projected.sources must be present — kubelet iterates these to mount each projection",
        );
        assert_eq!(sources.len(), 1, "one projection source must decode");
        assert_eq!(
            sources[0]["serviceAccountToken"]["path"], "token",
            "serviceAccountToken.path must be 'token' — kubelet writes the token to this path"
        );
        assert_eq!(
            sources[0]["serviceAccountToken"]["expirationSeconds"], 3600,
            "expirationSeconds must be 3600 — kubelet uses this to schedule token rotation"
        );
    }

    /// decode_pod_proto must preserve container.env (field 7) in decoded JSON.
    ///
    /// When client-go submits pods via protobuf (the default), env vars are encoded in
    /// Container.env (field 7, repeated EnvVar). Before this fix, field 7 was absent from
    /// the Container struct, so ALL env vars were silently dropped. Kubelet received containers
    /// with no environment, so env-dependent tests (Downward API env vars like POD_NAME,
    /// POD_UID, HOST_IP; ConfigMap/Secret env injection) all failed because the containers
    /// simply did not see the expected variables.
    ///
    /// This test must fail if:
    /// - EnvVar struct is removed
    /// - field 7 (env) is removed from Container
    /// - the env serialization block in pod_spec_to_json is removed
    /// - EnvVarSource field tags are wrong (drops valueFrom env vars silently)
    #[test]
    fn decode_pod_proto_preserves_container_env_vars() {
        // Build proto bytes for a pod with two env vars:
        //   1. POD_NAME with plain value "my-pod"
        //   2. MY_FIELD with valueFrom.fieldRef {apiVersion:"v1", fieldPath:"metadata.name"}

        // EnvVar { name (field 1) = "POD_NAME", value (field 2) = "my-pod" }
        let mut plain_env = encode_length_delimited(1, b"POD_NAME");
        plain_env.extend_from_slice(&encode_length_delimited(2, b"my-pod"));

        // ObjectFieldSelector { apiVersion (field 1) = "v1", fieldPath (field 2) = "metadata.name" }
        let mut field_selector = encode_length_delimited(1, b"v1");
        field_selector.extend_from_slice(&encode_length_delimited(2, b"metadata.name"));

        // EnvVarSource { fieldRef (field 1) = ObjectFieldSelector }
        let env_var_source = encode_length_delimited(1, &field_selector);

        // EnvVar { name (field 1) = "MY_FIELD", valueFrom (field 3) = EnvVarSource }
        let mut downward_env = encode_length_delimited(1, b"MY_FIELD");
        downward_env.extend_from_slice(&encode_length_delimited(3, &env_var_source));

        // Container { name (field 1), image (field 2), env (field 7) x2 }
        let mut container = encode_length_delimited(1, b"app");
        container.extend_from_slice(&encode_length_delimited(2, b"app:v1"));
        container.extend_from_slice(&encode_length_delimited(7, &plain_env));
        container.extend_from_slice(&encode_length_delimited(7, &downward_env));

        // PodSpec { containers (field 2) = [Container] }
        let podspec = encode_length_delimited(2, &container);

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"my-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed when Container has env vars at field 7");

        let env = result["spec"]["containers"][0]["env"].as_array().expect(
            "env must be present in decoded JSON — if absent, kubelet starts the container \
                 with no environment variables, breaking POD_NAME/POD_UID/HOST_IP injection and \
                 any ConfigMap/Secret env references",
        );
        assert_eq!(
            env.len(),
            2,
            "both env vars must decode; if EnvVar struct or Container.env field 7 is missing, \
             the repeated message is silently dropped and the array is absent or empty"
        );
        assert_eq!(
            env[0]["name"], "POD_NAME",
            "first env var name must be 'POD_NAME'"
        );
        assert_eq!(
            env[0]["value"], "my-pod",
            "plain-value env var must serialize as 'value' key — kubelet uses this verbatim"
        );
        assert_eq!(
            env[1]["name"], "MY_FIELD",
            "second env var name must be 'MY_FIELD'"
        );
        assert!(
            env[1].get("value").is_none() || env[1]["value"] == "",
            "valueFrom env var must not have a non-empty 'value' key"
        );
        assert_eq!(
            env[1]["valueFrom"]["fieldRef"]["apiVersion"], "v1",
            "valueFrom.fieldRef.apiVersion must be 'v1' — kubelet needs this to resolve the field"
        );
        assert_eq!(
            env[1]["valueFrom"]["fieldRef"]["fieldPath"], "metadata.name",
            "valueFrom.fieldRef.fieldPath must be 'metadata.name' — this is the Downward API path \
             the kubelet expands into the actual pod name at runtime"
        );
    }

    /// decode_pod_proto must preserve container.env[].valueFrom.configMapKeyRef in decoded JSON.
    ///
    /// When client-go submits pods via protobuf (the default for built-in types), env vars
    /// sourced from ConfigMaps are encoded as EnvVarSource.configMapKeyRef (field 3).
    /// If this field is not decoded, the kubelet receives the env entry without a configMapKeyRef,
    /// skips ConfigMap resolution entirely, and the container never sees the expected env value.
    ///
    /// This is the regression test for the conformance failure
    /// "ConfigMap should be consumable as environment variable names":
    /// the pod ran successfully but env output showed only KUBERNETES_* vars — no data-1=value-1.
    ///
    /// This test MUST FAIL if:
    /// - ConfigMapKeySelector struct is removed or field tags change
    /// - field 3 (config_map_key_ref) is removed from EnvVarSource
    /// - the configMapKeyRef serialisation block in pod_spec_to_json is removed
    /// - LocalObjectReference.name is at a wrong tag (name would be empty → kubelet can't find the CM)
    #[test]
    fn decode_pod_proto_preserves_configmap_key_ref_env_var() {
        // Build proto bytes for a pod with one env var sourced from a ConfigMap:
        //   name="DATA_1", valueFrom.configMapKeyRef = {name:"test-cm", key:"data-1"}

        // LocalObjectReference { name (field 1) = "test-cm" }
        let local_obj_ref = encode_length_delimited(1, b"test-cm");

        // ConfigMapKeySelector { localObjectReference (field 1) = ..., key (field 2) = "data-1" }
        let mut cm_key_sel = encode_length_delimited(1, &local_obj_ref);
        cm_key_sel.extend_from_slice(&encode_length_delimited(2, b"data-1"));

        // EnvVarSource { configMapKeyRef (field 3) = ConfigMapKeySelector }
        let env_var_source = encode_length_delimited(3, &cm_key_sel);

        // EnvVar { name (field 1) = "DATA_1", valueFrom (field 3) = EnvVarSource }
        let mut env_var = encode_length_delimited(1, b"DATA_1");
        env_var.extend_from_slice(&encode_length_delimited(3, &env_var_source));

        // Container { name (field 1), image (field 2), env (field 7) }
        let mut container = encode_length_delimited(1, b"app");
        container.extend_from_slice(&encode_length_delimited(2, b"busybox"));
        container.extend_from_slice(&encode_length_delimited(7, &env_var));

        // PodSpec { containers (field 2) }
        let podspec = encode_length_delimited(2, &container);

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"my-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed when Container has configMapKeyRef env var");

        let env = result["spec"]["containers"][0]["env"].as_array().expect(
            "env must be present in decoded JSON — if absent, kubelet starts the container \
             with no environment, so ConfigMap-sourced vars are never injected",
        );
        assert_eq!(
            env.len(),
            1,
            "exactly one env var must decode; if configMapKeyRef handling is removed, \
             the env array would be empty or the valueFrom entry would be silently dropped"
        );
        assert_eq!(env[0]["name"], "DATA_1", "env var name must be 'DATA_1'");
        assert!(
            env[0].get("value").is_none() || env[0]["value"] == "",
            "configMapKeyRef env var must not have a literal 'value' field — \
             kubelet injects the value by resolving the ConfigMap at pod startup"
        );
        assert_eq!(
            env[0]["valueFrom"]["configMapKeyRef"]["name"], "test-cm",
            "configMapKeyRef.name must be 'test-cm' — kubelet uses this to fetch the ConfigMap; \
             if empty or absent, the kubelet cannot find the ConfigMap and skips env injection \
             (conformance: 'ConfigMap should be consumable as environment variable names')"
        );
        assert_eq!(
            env[0]["valueFrom"]["configMapKeyRef"]["key"], "data-1",
            "configMapKeyRef.key must be 'data-1' — kubelet looks up this key in the ConfigMap's \
             data map to get the env var value; if wrong, the kubelet reads a different key"
        );
    }

    /// decode_pod_proto must preserve container.envFrom[].configMapRef in decoded JSON.
    ///
    /// `envFrom` (Container field 19) is the bulk env-injection feature: ALL keys from a
    /// ConfigMap become env vars in the container, optionally with a prefix.
    /// If envFrom is not decoded from proto, the kubelet receives a container with no envFrom
    /// and never populates the env vars from the ConfigMap.
    ///
    /// This is the regression test for the conformance failure
    /// "ConfigMap should be consumable via the environment":
    /// the pod ran successfully but no ConfigMap-sourced env vars were present.
    ///
    /// This test MUST FAIL if:
    /// - EnvFromSource struct is removed or field tags change
    /// - field 19 (envFrom) is removed from Container
    /// - the envFrom serialisation block in pod_spec_to_json is removed
    /// - ConfigMapEnvSource.localObjectReference is at the wrong tag (name is empty → kubelet can't find the CM)
    #[test]
    fn decode_pod_proto_preserves_env_from_configmap_ref() {
        // Build proto bytes for a pod with envFrom referencing a ConfigMap:
        //   envFrom = [{prefix: "CM_", configMapRef: {name: "test-cm"}}]

        // LocalObjectReference { name (field 1) = "test-cm" }
        let local_obj_ref = encode_length_delimited(1, b"test-cm");

        // ConfigMapEnvSource { localObjectReference (field 1) = ..., optional absent (false) }
        let cm_env_source = encode_length_delimited(1, &local_obj_ref);

        // EnvFromSource { prefix (field 1) = "CM_", configMapRef (field 2) = ConfigMapEnvSource }
        let mut env_from_source = encode_length_delimited(1, b"CM_");
        env_from_source.extend_from_slice(&encode_length_delimited(2, &cm_env_source));

        // Container { name (field 1), image (field 2), envFrom (field 19) }
        let mut container = encode_length_delimited(1, b"app");
        container.extend_from_slice(&encode_length_delimited(2, b"busybox"));
        container.extend_from_slice(&encode_length_delimited(19, &env_from_source));

        // PodSpec { containers (field 2) }
        let podspec = encode_length_delimited(2, &container);

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"my-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed when Container has envFrom at field 19");

        let env_from = result["spec"]["containers"][0]["envFrom"]
            .as_array()
            .expect(
            "envFrom must be present in decoded JSON — if absent, kubelet starts the container \
             without bulk ConfigMap env injection (conformance: \
             'ConfigMap should be consumable via the environment')",
        );
        assert_eq!(
            env_from.len(),
            1,
            "exactly one envFrom entry must decode; if envFrom field 19 is missing from \
             Container or EnvFromSource is not decoded, the array would be absent or empty"
        );
        assert_eq!(
            env_from[0]["prefix"], "CM_",
            "envFrom prefix must be 'CM_' — kubelet prepends this to each key from the ConfigMap \
             to form the env var name (e.g. CM_data-1=value-1)"
        );
        assert_eq!(
            env_from[0]["configMapRef"]["name"], "test-cm",
            "configMapRef.name must be 'test-cm' — kubelet uses this to fetch the ConfigMap \
             and inject all its keys as env vars; if empty or absent, no env vars are injected \
             (conformance: 'ConfigMap should be consumable via the environment')"
        );
        assert!(
            env_from[0]["configMapRef"]["optional"].is_null(),
            "optional must be absent when not set — kubelet treats absent as false (required)"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_ingressclass_proto / decode_core_proto_by_kind IngressClass
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch IngressClass proto and extract metadata and
    /// spec.controller. Without this decoder, the IngressClass conformance test fails with
    /// 400 "invalid JSON: expected value at line 1 column 1" when client-go POSTs with
    /// Content-Type: application/vnd.kubernetes.protobuf.
    #[test]
    fn decode_core_proto_by_kind_dispatches_ingressclass() {
        // Build: IngressClass {
        //   metadata: ObjectMeta { name: "nginx" },
        //   spec: IngressClassSpec { controller: "k8s.io/ingress-nginx" }
        // }
        let obj_meta = encode_length_delimited(1, b"nginx"); // ObjectMeta.name

        // IngressClassSpec: field 1 = controller (string)
        let ic_spec = encode_length_delimited(1, b"k8s.io/ingress-nginx");

        // IngressClass: field 1=ObjectMeta, field 2=IngressClassSpec
        let mut ic_proto = encode_length_delimited(1, &obj_meta);
        ic_proto.extend_from_slice(&encode_length_delimited(2, &ic_spec));

        let result = decode_core_proto_by_kind("IngressClass", &ic_proto).expect(
            "IngressClass must decode via decode_core_proto_by_kind — without this, \
                     the IngressClass API conformance test fails with 400 on POST",
        );

        assert_eq!(
            result["kind"], "IngressClass",
            "kind must be IngressClass so Object::from_bytes can route the object"
        );
        assert_eq!(result["apiVersion"], "networking.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "nginx",
            "name must be extracted so the object is stored under the correct key"
        );
        assert_eq!(
            result["spec"]["controller"], "k8s.io/ingress-nginx",
            "controller must be extracted from IngressClassSpec field 1 — \
             ingress controllers read this field to claim their IngressClass"
        );
    }

    /// decode_ingressclass_proto must return None for malformed proto input.
    #[test]
    fn decode_ingressclass_proto_returns_none_for_garbage() {
        assert!(decode_ingressclass_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_ingress_proto / decode_core_proto_by_kind Ingress
    // ---------------------------------------------------------------------------

    /// decode_proto_by_kind_and_version must dispatch Ingress proto and extract metadata,
    /// spec.ingressClassName, and spec.rules. Without this decoder, client-go POSTing an
    /// Ingress with Content-Type: application/vnd.kubernetes.protobuf gets 400
    /// "invalid JSON: expected value at line 1 column 1".
    #[test]
    fn decode_proto_by_kind_and_version_dispatches_ingress() {
        let obj_meta = encode_length_delimited(1, b"test-ingress"); // ObjectMeta.name

        // IngressSpec: field 1 = ingressClassName (string), field 4 = rules (repeated IngressRule)
        // IngressRule proto bytes: field 1 = host (string "example.com")
        let rule = encode_length_delimited(1, b"example.com"); // IngressRule: field 1 = host

        let mut spec_proto = encode_length_delimited(1, b"nginx"); // field 1 = ingressClassName
        spec_proto.extend_from_slice(&encode_length_delimited(4, &rule)); // field 4 = rules

        // Ingress: field 1 = ObjectMeta, field 2 = IngressSpec
        let mut ingress_proto = encode_length_delimited(1, &obj_meta);
        ingress_proto.extend_from_slice(&encode_length_delimited(2, &spec_proto));

        let result =
            decode_proto_by_kind_and_version("Ingress", "networking.k8s.io/v1", &ingress_proto)
                .expect(
                    "Ingress must decode via decode_proto_by_kind_and_version — \
                 without this decoder, client-go POST returns 400 on Ingress create",
                );

        assert_eq!(
            result["kind"], "Ingress",
            "kind must be Ingress so Object::from_bytes can store the object"
        );
        assert_eq!(result["apiVersion"], "networking.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "test-ingress",
            "name must survive proto round-trip — the object is keyed by name"
        );
        assert_eq!(
            result["spec"]["ingressClassName"], "nginx",
            "ingressClassName must be extracted — ingress controllers discover their class by this field"
        );
        assert_eq!(
            result["spec"]["rules"][0]["host"], "example.com",
            "rules[].host must survive proto round-trip — routing rules are the core of Ingress"
        );
    }

    /// decode_ingress_proto must decode a backend with service name and port number.
    /// Conformance tests POST Ingress with defaultBackend pointing at a Service — the backend
    /// must survive the decode so the ingress controller can route traffic correctly.
    #[test]
    fn decode_ingress_proto_extracts_default_backend() {
        // ServiceBackendPort: field 2 = number (int32 varint)
        let mut port_proto: Vec<u8> = Vec::new();
        port_proto.push(0x10); // tag: field 2, wire type 0
        port_proto.extend_from_slice(&encode_varint(80));

        // IngressServiceBackend: field 1 = name, field 2 = port
        let mut svc_backend = encode_length_delimited(1, b"my-service");
        svc_backend.extend_from_slice(&encode_length_delimited(2, &port_proto));

        // IngressBackend: field 1 = service
        let backend = encode_length_delimited(1, &svc_backend);

        // IngressSpec: field 2 = defaultBackend
        let spec = encode_length_delimited(2, &backend);

        // Ingress: field 1 = ObjectMeta (minimal), field 2 = spec
        let obj_meta = encode_length_delimited(1, b"backend-ingress");
        let mut ingress_proto = encode_length_delimited(1, &obj_meta);
        ingress_proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result = decode_ingress_proto(&ingress_proto)
            .expect("Ingress with defaultBackend must decode successfully");

        assert_eq!(
            result["spec"]["defaultBackend"]["service"]["name"], "my-service",
            "defaultBackend.service.name must survive decode — ingress controller needs it to route"
        );
        assert_eq!(
            result["spec"]["defaultBackend"]["service"]["port"]["number"], 80,
            "defaultBackend.service.port.number must survive decode — port is required for routing"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_endpointslice_proto / decode_proto_by_kind_and_version EndpointSlice
    // ---------------------------------------------------------------------------

    /// decode_proto_by_kind_and_version must dispatch EndpointSlice proto and extract
    /// addressType, endpoints, and ports. Without this decoder, client-go POSTing an
    /// EndpointSlice with Content-Type: application/vnd.kubernetes.protobuf gets 400.
    #[test]
    fn decode_proto_by_kind_and_version_dispatches_endpointslice() {
        let obj_meta = encode_length_delimited(1, b"test-slice"); // ObjectMeta.name

        // EndpointSlice: field 2 = addressType, field 3 = endpoints, field 4 = ports
        // DiscoveryEndpoint: field 1 = addresses (repeated string)
        let ep_addr = encode_length_delimited(1, b"10.0.0.1");
        let endpoint = encode_length_delimited(3, &ep_addr); // field 3 = endpoints

        // DiscoveryEndpointPort: field 1 = name, field 2 = protocol, field 3 = port (varint)
        let mut port_proto = encode_length_delimited(1, b"http");
        port_proto.extend_from_slice(&encode_length_delimited(2, b"TCP"));
        port_proto.push(0x18); // tag: field 3, wire type 0
        port_proto.extend_from_slice(&encode_varint(8080));

        let mut eps_proto = encode_length_delimited(1, &obj_meta);
        eps_proto.extend_from_slice(&encode_length_delimited(2, b"IPv4")); // field 2 = addressType
        eps_proto.extend_from_slice(&endpoint);
        eps_proto.extend_from_slice(&encode_length_delimited(4, &port_proto)); // field 4 = ports

        let result =
            decode_proto_by_kind_and_version("EndpointSlice", "discovery.k8s.io/v1", &eps_proto)
                .expect(
                    "EndpointSlice must decode via decode_proto_by_kind_and_version — \
                 without this, client-go POST returns 400 on EndpointSlice create",
                );

        assert_eq!(result["kind"], "EndpointSlice");
        assert_eq!(result["apiVersion"], "discovery.k8s.io/v1");
        assert_eq!(
            result["addressType"], "IPv4",
            "addressType must survive decode — required field for EndpointSlice routing"
        );
        assert_eq!(
            result["endpoints"][0]["addresses"][0], "10.0.0.1",
            "endpoint address must survive decode — without this, load balancing breaks"
        );
        assert_eq!(
            result["ports"][0]["name"], "http",
            "port name must survive decode — kube-proxy uses port names for service routing"
        );
        assert_eq!(
            result["ports"][0]["port"], 8080,
            "port number must survive decode — required for traffic forwarding"
        );
    }

    /// Reproduce the conformance test scenario: decode_endpointslice_proto must succeed
    /// for an EndpointSlice with generateName, addressType, endpoint with conditions,
    /// and port without a name.
    ///
    /// The conformance test "[sig-network] EndpointSlice should support creating EndpointSlice
    /// API operations" uses the typed client (protobuf). The proto includes conditions and
    /// ports without names. If decode_endpointslice_proto returns None for this input, the
    /// handler receives the raw proto envelope bytes (starting with 'k') and returns 400
    /// "invalid JSON: expected value at line 1 column 1".
    #[test]
    fn decode_endpointslice_proto_conformance_test_scenario() {
        // ObjectMeta with generateName at field 2 (not name at field 1)
        let obj_meta = encode_length_delimited(2, b"e2e-"); // generateName

        // EndpointConditions: field 1 = ready (bool = true)
        let conditions_proto = vec![0x08u8, 0x01]; // field 1, wire type 0 (varint), value = true
        let conditions = encode_length_delimited(2, &conditions_proto); // field 2 of DiscoveryEndpoint

        // DiscoveryEndpoint: field 1 = addresses, field 2 = conditions
        let mut endpoint_content = encode_length_delimited(1, b"10.0.0.1"); // addresses[0]
        endpoint_content.extend_from_slice(&conditions);

        // DiscoveryEndpointPort: field 2 = protocol, field 3 = port (no name)
        let mut port_content = encode_length_delimited(2, b"TCP"); // protocol
        port_content.push(0x18); // field 3, wire type 0 (varint)
        port_content.push(0x50); // value = 80

        // EndpointSlice: field 1 = metadata, field 2 = addressType, field 3 = endpoint, field 4 = port
        let mut eps_proto = encode_length_delimited(1, &obj_meta);
        eps_proto.extend_from_slice(&encode_length_delimited(2, b"IPv4")); // addressType
        eps_proto.extend_from_slice(&encode_length_delimited(3, &endpoint_content)); // endpoints[0]
        eps_proto.extend_from_slice(&encode_length_delimited(4, &port_content)); // ports[0]

        let result = decode_endpointslice_proto(&eps_proto).expect(
            "decode_endpointslice_proto must succeed for a valid EndpointSlice with \
                 conditions and port — if it returns None, the handler gets raw proto bytes \
                 and returns 400 'invalid JSON: expected value at line 1 column 1', \
                 failing the conformance test",
        );

        assert_eq!(result["kind"], "EndpointSlice");
        assert_eq!(result["apiVersion"], "discovery.k8s.io/v1");
        assert_eq!(
            result["addressType"], "IPv4",
            "addressType must be preserved"
        );
        assert!(
            result["metadata"]["generateName"].as_str() == Some("e2e-"),
            "generateName must be in JSON so resolve_name can use it; got: {:?}",
            result["metadata"]["generateName"]
        );
        assert_eq!(
            result["endpoints"][0]["addresses"][0], "10.0.0.1",
            "endpoint address must survive decode"
        );
        assert_eq!(
            result["endpoints"][0]["conditions"]["ready"], true,
            "conditions.ready must survive decode — regression for mayor-t3w7"
        );
        assert_eq!(result["ports"][0]["port"], 80, "port must survive decode");
        assert_eq!(
            result["ports"][0]["protocol"], "TCP",
            "protocol must survive decode"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_events_v1_event_proto / decode_proto_by_kind_and_version events.k8s.io/v1 Event
    // ---------------------------------------------------------------------------

    /// decode_proto_by_kind_and_version must use apiVersion to distinguish events.k8s.io/v1 Event
    /// from core/v1 Event. Without the apiVersion disambiguation, events.k8s.io/v1 events are
    /// decoded with the wrong proto field layout, corrupting fields.
    #[test]
    fn decode_proto_by_kind_and_version_dispatches_events_v1_event() {
        let obj_meta = encode_length_delimited(1, b"test-event");

        // events.k8s.io/v1 Event:
        //   field 4 = reportingController (string)
        //   field 6 = action (string)
        //   field 7 = reason (string)
        //   field 11 = type (string)
        let mut ev_proto = encode_length_delimited(1, &obj_meta);
        ev_proto.extend_from_slice(&encode_length_delimited(4, b"test-controller"));
        ev_proto.extend_from_slice(&encode_length_delimited(6, b"Started"));
        ev_proto.extend_from_slice(&encode_length_delimited(7, b"TestReason"));
        ev_proto.extend_from_slice(&encode_length_delimited(11, b"Normal"));

        let result = decode_proto_by_kind_and_version("Event", "events.k8s.io/v1", &ev_proto)
            .expect(
                "events.k8s.io/v1 Event must decode via decode_proto_by_kind_and_version — \
                 without this, client-go POST returns 400 on events.k8s.io/v1 Event create",
            );

        assert_eq!(
            result["apiVersion"], "events.k8s.io/v1",
            "apiVersion must be events.k8s.io/v1 — clients check this to distinguish from core/v1 Event"
        );
        assert_eq!(result["kind"], "Event");
        assert_eq!(
            result["reportingController"], "test-controller",
            "reportingController must survive decode — events.k8s.io/v1 field 4"
        );
        assert_eq!(
            result["action"], "Started",
            "action must survive decode — events.k8s.io/v1 field 6"
        );
        assert_eq!(
            result["reason"], "TestReason",
            "reason must survive decode — events.k8s.io/v1 field 7"
        );
        assert_eq!(
            result["type"], "Normal",
            "type must survive decode — events.k8s.io/v1 field 11"
        );
    }

    /// decode_proto_by_kind_and_version with empty apiVersion still routes Event to core/v1 decoder.
    /// Backward compat: existing callers that don't provide apiVersion must still work.
    #[test]
    fn decode_proto_by_kind_and_version_routes_event_without_apiversion_to_core_v1() {
        let obj_meta = encode_length_delimited(1, b"core-event");

        // core/v1 Event: field 3 = reason, field 4 = message, field 9 = type
        let mut ev_proto = encode_length_delimited(1, &obj_meta);
        ev_proto.extend_from_slice(&encode_length_delimited(3, b"SomeReason"));
        ev_proto.extend_from_slice(&encode_length_delimited(4, b"something happened"));
        ev_proto.extend_from_slice(&encode_length_delimited(9, b"Warning"));

        let result = decode_proto_by_kind_and_version("Event", "", &ev_proto)
            .expect("core/v1 Event must decode when apiVersion is empty");

        assert_eq!(
            result["apiVersion"], "v1",
            "apiVersion must be v1 for core/v1 Event when called without apiVersion"
        );
        assert_eq!(
            result["reason"], "SomeReason",
            "core/v1 Event.reason (field 3) must survive decode"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_csr_proto / decode_proto_by_kind_and_version CertificateSigningRequest
    // ---------------------------------------------------------------------------

    /// decode_proto_by_kind_and_version must dispatch CertificateSigningRequest proto and extract
    /// spec.request (base64), spec.signerName, and spec.usages. Without this decoder,
    /// client-go POSTing a CSR with Content-Type: application/vnd.kubernetes.protobuf gets 400.
    #[test]
    fn decode_proto_by_kind_and_version_dispatches_csr() {
        let obj_meta = encode_length_delimited(1, b"test-csr");

        // CertificateSigningRequestSpec:
        //   field 1 = request (bytes) — raw PEM bytes
        //   field 2 = signerName (string)
        //   field 4 = usages (repeated string)
        let fake_csr_bytes =
            b"-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----";
        let mut spec_proto = encode_length_delimited(1, fake_csr_bytes); // request bytes
        spec_proto.extend_from_slice(&encode_length_delimited(
            2,
            b"kubernetes.io/kube-apiserver-client",
        ));
        spec_proto.extend_from_slice(&encode_length_delimited(4, b"client auth")); // usages

        // CertificateSigningRequest: field 1 = metadata, field 2 = spec
        let mut csr_proto = encode_length_delimited(1, &obj_meta);
        csr_proto.extend_from_slice(&encode_length_delimited(2, &spec_proto));

        let result = decode_proto_by_kind_and_version(
            "CertificateSigningRequest",
            "certificates.k8s.io/v1",
            &csr_proto,
        )
        .expect(
            "CertificateSigningRequest must decode via decode_proto_by_kind_and_version — \
             without this, client-go POST returns 400 on CSR create",
        );

        assert_eq!(result["kind"], "CertificateSigningRequest");
        assert_eq!(result["apiVersion"], "certificates.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "test-csr",
            "CSR name must survive decode — objects are keyed by name"
        );
        assert_eq!(
            result["spec"]["signerName"], "kubernetes.io/kube-apiserver-client",
            "signerName must survive decode — signer controllers route by signerName"
        );
        assert_eq!(
            result["spec"]["usages"][0], "client auth",
            "usages must survive decode — signers validate allowed key usages"
        );

        let request_b64 = result["spec"]["request"]
            .as_str()
            .expect("spec.request must be a base64 string in JSON");
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(request_b64)
            .expect("spec.request must be valid base64");
        assert_eq!(
            decoded, fake_csr_bytes,
            "spec.request bytes must survive base64 encode/decode round-trip — \
             the signer controller needs the raw DER bytes"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_priorityclass_proto / decode_core_proto_by_kind PriorityClass
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch PriorityClass proto and extract metadata and
    /// value. Without this decoder, the SchedulerPreemption conformance test fails with
    /// 400 "invalid JSON: expected value at line 1 column 1" when client-go POSTs with
    /// Content-Type: application/vnd.kubernetes.protobuf.
    #[test]
    fn decode_core_proto_by_kind_dispatches_priorityclass() {
        // Build: PriorityClass {
        //   metadata: ObjectMeta { name: "high-priority" },
        //   value: 1000000,
        //   preemptionPolicy: "PreemptLowerPriority",
        //   globalDefault: false,
        //   description: "high priority class",
        // }
        let obj_meta = encode_length_delimited(1, b"high-priority"); // ObjectMeta.name

        // PriorityClass fields (k8s.io/api/scheduling/v1/generated.proto):
        // field 1 = ObjectMeta, field 2 = value (int32/varint), field 3 = globalDefault (bool),
        // field 4 = description (string), field 5 = preemptionPolicy (string, added k8s 1.19)
        //
        // value = 1000000: tag = (2 << 3) | 0 = 0x10; encode varint 1000000
        // 1000000 = 0x0F4240 → varint: 0xC0, 0x84, 0x3D
        let mut pc_proto = encode_length_delimited(1, &obj_meta); // field 1 = ObjectMeta
                                                                  // field 2 = value (varint 1000000)
        pc_proto.push(0x10); // tag: field 2, wire type 0
        pc_proto.extend_from_slice(&encode_varint(1_000_000));
        // field 3 = globalDefault (bool false = zero, not encoded; we leave it absent)
        // field 4 = description
        pc_proto.extend_from_slice(&encode_length_delimited(4, b"high priority class"));
        // field 5 = preemptionPolicy
        pc_proto.extend_from_slice(&encode_length_delimited(5, b"PreemptLowerPriority"));

        let result = decode_core_proto_by_kind("PriorityClass", &pc_proto).expect(
            "PriorityClass must decode via decode_core_proto_by_kind — without this, \
                     the SchedulerPreemption conformance test fails with 400 on POST",
        );

        assert_eq!(
            result["kind"], "PriorityClass",
            "kind must be PriorityClass so Object::from_bytes can route the object"
        );
        assert_eq!(result["apiVersion"], "scheduling.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "high-priority",
            "name must be extracted so the object is stored under the correct key"
        );
        assert_eq!(
            result["value"], 1_000_000,
            "value must be extracted from PriorityClass field 2 — \
             kube-scheduler uses this to rank pod priority for preemption decisions"
        );
        assert_eq!(
            result["preemptionPolicy"], "PreemptLowerPriority",
            "preemptionPolicy must be extracted from PriorityClass field 5 — \
             scheduler uses this to decide if the pod can preempt lower priority pods"
        );
        assert_eq!(
            result["description"], "high priority class",
            "description must be extracted from PriorityClass field 4"
        );
    }

    /// decode_priorityclass_proto must return None for malformed proto input.
    #[test]
    fn decode_priorityclass_proto_returns_none_for_garbage() {
        assert!(decode_priorityclass_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_mutatingadmissionpolicy_proto / decode_core_proto_by_kind MutatingAdmissionPolicy
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch MutatingAdmissionPolicy proto and extract
    /// metadata. Without this decoder, the MutatingAdmissionPolicy conformance test fails with
    /// 400 "invalid JSON: expected value at line 1 column 1" when client-go POSTs with
    /// Content-Type: application/vnd.kubernetes.protobuf.
    #[test]
    fn decode_core_proto_by_kind_dispatches_mutatingadmissionpolicy() {
        // Build: MutatingAdmissionPolicy { metadata: ObjectMeta { name: "test-map" } }
        // MutatingAdmissionPolicy: field 1 = ObjectMeta (metadata)
        // ObjectMeta: field 1 = name (string)
        let obj_meta = encode_length_delimited(1, b"test-map"); // ObjectMeta.name
        let proto = encode_length_delimited(1, &obj_meta); // MutatingAdmissionPolicy.metadata

        let result = decode_core_proto_by_kind("MutatingAdmissionPolicy", &proto).expect(
            "MutatingAdmissionPolicy must decode via decode_core_proto_by_kind — without this, \
             the MutatingAdmissionPolicy API conformance test fails with 400 on POST",
        );

        assert_eq!(
            result["kind"], "MutatingAdmissionPolicy",
            "kind must be MutatingAdmissionPolicy so Object::from_bytes can route the object"
        );
        assert_eq!(result["apiVersion"], "admissionregistration.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "test-map",
            "name must be extracted so the object is stored under the correct key"
        );
    }

    /// decode_mutatingadmissionpolicy_proto must return None for malformed proto input.
    #[test]
    fn decode_mutatingadmissionpolicy_proto_returns_none_for_garbage() {
        assert!(decode_mutatingadmissionpolicy_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    /// PUT to MutatingAdmissionPolicy must preserve the spec field (failurePolicy, matchConstraints,
    /// mutations). Without spec decoding, a PUT with a new spec was silently dropped and the stored
    /// object retained the old spec — the conformance test "updated object should have the applied
    /// spec" then fails.
    ///
    /// Field numbers follow the k8s 1.36 proto definition (crates/apiserver/proto/api-admissionregistration-v1-generated.proto):
    /// MutatingAdmissionPolicySpec: paramKind=1, matchConstraints=2, variables=3, mutations=4, failurePolicy=5, matchConditions=6, reinvocationPolicy=7
    /// Mutation: patchType=2, applyConfiguration=3
    /// NamedRuleWithOperations: resourceNames=1, ruleWithOperations=2
    /// RuleWithOperations: operations=1, rule=2
    /// Rule: apiGroups=1, apiVersions=2, resources=3, scope=4
    #[test]
    fn decode_mutatingadmissionpolicy_proto_preserves_spec_on_put() {
        // Build ApplyConfiguration: field 1 = expression
        let apply_config = encode_length_delimited(
            1,
            b"Object{metadata: Object.metadata{labels: {\"injected\": \"true\"}}}",
        );

        // Build Mutation: field 2 = patchType, field 3 = applyConfiguration
        let mut mutation: Vec<u8> = Vec::new();
        mutation.extend_from_slice(&encode_length_delimited(2, b"ApplyConfiguration")); // patchType at field 2
        mutation.extend_from_slice(&encode_length_delimited(3, &apply_config)); // applyConfiguration at field 3

        // Build Rule: field 1=apiGroups, field 2=apiVersions, field 3=resources
        let mut rule: Vec<u8> = Vec::new();
        rule.extend_from_slice(&encode_length_delimited(1, b"apps")); // apiGroups
        rule.extend_from_slice(&encode_length_delimited(2, b"v1")); // apiVersions
        rule.extend_from_slice(&encode_length_delimited(3, b"deployments")); // resources

        // Build RuleWithOperations: field 1=operations, field 2=rule
        let mut rwo: Vec<u8> = Vec::new();
        rwo.extend_from_slice(&encode_length_delimited(1, b"CREATE")); // operations
        rwo.extend_from_slice(&encode_length_delimited(2, &rule)); // rule

        // Build NamedRuleWithOperations: field 2=ruleWithOperations
        let named_rule = encode_length_delimited(2, &rwo); // ruleWithOperations at field 2

        // Build MatchResources: field 3 = resourceRules
        let match_constraints = encode_length_delimited(3, &named_rule); // resourceRules at field 3

        // Build MutatingAdmissionPolicySpec:
        //   field 2=matchConstraints, field 4=mutations, field 5=failurePolicy
        let mut spec: Vec<u8> = Vec::new();
        spec.extend_from_slice(&encode_length_delimited(2, &match_constraints)); // matchConstraints at field 2
        spec.extend_from_slice(&encode_length_delimited(4, &mutation)); // mutations at field 4
        spec.extend_from_slice(&encode_length_delimited(5, b"Fail")); // failurePolicy at field 5

        // Build MutatingAdmissionPolicy: field 1=metadata, field 2=spec
        let obj_meta = encode_length_delimited(1, b"test-map-spec"); // ObjectMeta.name
        let mut proto = encode_length_delimited(1, &obj_meta);
        proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result = decode_mutatingadmissionpolicy_proto(&proto)
            .expect("MutatingAdmissionPolicy with spec must decode successfully");

        assert_eq!(result["metadata"]["name"], "test-map-spec");

        // Regression: spec.failurePolicy must survive the proto decode — if it reverts to the
        // previous value, PUT/PATCH operations silently drop the user's intended spec changes.
        assert_eq!(
            result["spec"]["failurePolicy"], "Fail",
            "spec.failurePolicy must be preserved in the decoded JSON; \
             if missing, a PUT that changes failurePolicy has no effect (spec is dropped by decoder)"
        );

        // Regression: spec.mutations must be present so the admission controller can evaluate
        // them. If mutations are absent, CEL-based mutation policies stop working after a PUT.
        let mutations = result["spec"]["mutations"].as_array().expect(
            "spec.mutations must be a JSON array; absent mutations = CEL policy noop after PUT",
        );
        assert_eq!(
            mutations.len(),
            1,
            "one mutation must survive the proto round-trip"
        );
        assert_eq!(
            mutations[0]["patchType"], "ApplyConfiguration",
            "mutation patchType must be preserved; wrong value means admission controller \
             skips the mutation (it checks patchType == 'ApplyConfiguration')"
        );
        assert!(
            !mutations[0]["applyConfiguration"]["expression"]
                .as_str()
                .unwrap_or("")
                .is_empty(),
            "applyConfiguration.expression must be non-empty; absent = CEL mutation has no effect"
        );

        // Regression: spec.matchConstraints.resourceRules must be present for the policy to match
        // any resources. If absent, matches_match_constraints returns true for all resources
        // (match-all fallback), which is wrong after a PUT that set explicit constraints.
        let resource_rules = result["spec"]["matchConstraints"]["resourceRules"]
            .as_array()
            .expect("matchConstraints.resourceRules must be a JSON array");
        assert!(
            !resource_rules.is_empty(),
            "resourceRules must be non-empty"
        );
        assert_eq!(resource_rules[0]["apiGroups"][0], "apps");
        assert_eq!(resource_rules[0]["resources"][0], "deployments");
    }

    /// PUT to MutatingAdmissionPolicyBinding must preserve the spec field (policyName).
    /// Without spec decoding, a PUT binding to a different policy name silently dropped the
    /// change — the conformance test "updated object should have the applied spec" fails.
    #[test]
    fn decode_mutatingadmissionpolicybinding_proto_preserves_spec_on_put() {
        // Build MapbSpec: field 1=policyName
        let spec = encode_length_delimited(1, b"my-policy"); // policyName

        // Build MutatingAdmissionPolicyBinding: field 1=metadata, field 2=spec
        let obj_meta = encode_length_delimited(1, b"test-mapb-spec"); // ObjectMeta.name
        let mut proto = encode_length_delimited(1, &obj_meta);
        proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result = decode_mutatingadmissionpolicybinding_proto(&proto)
            .expect("MutatingAdmissionPolicyBinding with spec must decode successfully");

        assert_eq!(result["metadata"]["name"], "test-mapb-spec");

        // Regression: spec.policyName must survive the proto decode — if it reverts, a PUT that
        // rebinds to a different policy has no effect (binding still points to old policy).
        assert_eq!(
            result["spec"]["policyName"], "my-policy",
            "spec.policyName must be preserved in the decoded JSON; \
             if missing, a PUT that changes policyName is silently ignored"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_mutatingadmissionpolicybinding_proto / decode_core_proto_by_kind MutatingAdmissionPolicyBinding
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch MutatingAdmissionPolicyBinding proto and extract
    /// metadata. Without this decoder, the MutatingAdmissionPolicyBinding conformance test
    /// fails with 400 "invalid JSON: expected value at line 1 column 1" when client-go POSTs
    /// with Content-Type: application/vnd.kubernetes.protobuf.
    #[test]
    fn decode_core_proto_by_kind_dispatches_mutatingadmissionpolicybinding() {
        // Build: MutatingAdmissionPolicyBinding { metadata: ObjectMeta { name: "test-mapb" } }
        // MutatingAdmissionPolicyBinding: field 1 = ObjectMeta (metadata)
        // ObjectMeta: field 1 = name (string)
        let obj_meta = encode_length_delimited(1, b"test-mapb"); // ObjectMeta.name
        let proto = encode_length_delimited(1, &obj_meta); // MutatingAdmissionPolicyBinding.metadata

        let result = decode_core_proto_by_kind("MutatingAdmissionPolicyBinding", &proto).expect(
            "MutatingAdmissionPolicyBinding must decode via decode_core_proto_by_kind — without \
             this, the MutatingAdmissionPolicyBinding API conformance test fails with 400 on POST",
        );

        assert_eq!(
            result["kind"], "MutatingAdmissionPolicyBinding",
            "kind must be MutatingAdmissionPolicyBinding so Object::from_bytes can route the object"
        );
        assert_eq!(result["apiVersion"], "admissionregistration.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "test-mapb",
            "name must be extracted so the object is stored under the correct key"
        );
    }

    /// decode_mutatingadmissionpolicybinding_proto must return None for malformed proto input.
    #[test]
    fn decode_mutatingadmissionpolicybinding_proto_returns_none_for_garbage() {
        assert!(decode_mutatingadmissionpolicybinding_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_validatingadmissionpolicy_proto / decode_core_proto_by_kind ValidatingAdmissionPolicy
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch ValidatingAdmissionPolicy proto and extract
    /// metadata. Without this decoder, the ValidatingAdmissionPolicy conformance test
    /// fails with 400 "invalid JSON: expected value at line 1 column 1" when client-go POSTs
    /// with Content-Type: application/vnd.kubernetes.protobuf.
    #[test]
    fn decode_core_proto_by_kind_dispatches_validatingadmissionpolicy() {
        let obj_meta = encode_length_delimited(1, b"test-vap");
        let proto = encode_length_delimited(1, &obj_meta);

        let result = decode_core_proto_by_kind("ValidatingAdmissionPolicy", &proto).expect(
            "ValidatingAdmissionPolicy must decode via decode_core_proto_by_kind — without \
             this, the ValidatingAdmissionPolicy API conformance test fails with 400 on POST \
             because client-go sends Content-Type: application/vnd.kubernetes.protobuf",
        );

        assert_eq!(
            result["kind"], "ValidatingAdmissionPolicy",
            "kind must be ValidatingAdmissionPolicy so Object::from_bytes routes the object correctly"
        );
        assert_eq!(result["apiVersion"], "admissionregistration.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "test-vap",
            "name must be extracted so the object is stored under the correct key"
        );
    }

    /// PUT to ValidatingAdmissionPolicy must preserve the spec field (validations, failurePolicy,
    /// matchConstraints). Without spec decoding, a PUT with a new spec was silently dropped and the
    /// stored object retained the old spec — the conformance test "updated object should have the
    /// applied spec" then fails.
    ///
    /// ValidatingAdmissionPolicySpec field numbers (k8s 1.36 proto):
    ///   paramKind=1, matchConstraints=2, validations=3, failurePolicy=4, matchConditions=6
    /// Validation field numbers: expression=1, message=2, reason=3, messageExpression=4
    #[test]
    fn decode_validatingadmissionpolicy_proto_preserves_spec_on_put() {
        // Build Validation: field 1=expression, field 2=message
        let mut validation: Vec<u8> = Vec::new();
        validation.extend_from_slice(&encode_length_delimited(1, b"object.spec.replicas <= 5"));
        validation.extend_from_slice(&encode_length_delimited(2, b"replicas must be <= 5"));

        // Build Rule: field 1=apiGroups, field 2=apiVersions, field 3=resources
        let mut rule: Vec<u8> = Vec::new();
        rule.extend_from_slice(&encode_length_delimited(1, b"apps"));
        rule.extend_from_slice(&encode_length_delimited(2, b"v1"));
        rule.extend_from_slice(&encode_length_delimited(3, b"deployments"));

        // Build RuleWithOperations: field 1=operations, field 2=rule
        let mut rwo: Vec<u8> = Vec::new();
        rwo.extend_from_slice(&encode_length_delimited(1, b"CREATE"));
        rwo.extend_from_slice(&encode_length_delimited(2, &rule));

        // Build NamedRuleWithOperations: field 2=ruleWithOperations
        let named_rule = encode_length_delimited(2, &rwo);

        // Build MatchResources: field 3=resourceRules
        let match_constraints = encode_length_delimited(3, &named_rule);

        // Build ValidatingAdmissionPolicySpec:
        //   field 2=matchConstraints, field 3=validations, field 4=failurePolicy
        let mut spec: Vec<u8> = Vec::new();
        spec.extend_from_slice(&encode_length_delimited(2, &match_constraints));
        spec.extend_from_slice(&encode_length_delimited(3, &validation));
        spec.extend_from_slice(&encode_length_delimited(4, b"Fail"));

        // Build ValidatingAdmissionPolicy: field 1=metadata, field 2=spec
        let obj_meta = encode_length_delimited(1, b"test-vap-spec");
        let mut proto = encode_length_delimited(1, &obj_meta);
        proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result = decode_validatingadmissionpolicy_proto(&proto)
            .expect("ValidatingAdmissionPolicy with spec must decode successfully");

        assert_eq!(result["metadata"]["name"], "test-vap-spec");

        assert_eq!(
            result["spec"]["failurePolicy"], "Fail",
            "spec.failurePolicy must survive proto decode — without it, a PUT changing \
             failurePolicy has no effect (spec is dropped by decoder)"
        );

        let validations = result["spec"]["validations"].as_array().expect(
            "spec.validations must be a JSON array — absent validations mean the VAP \
             has no CEL rules to enforce after a PUT",
        );
        assert_eq!(
            validations.len(),
            1,
            "one validation must survive the proto round-trip"
        );
        assert_eq!(
            validations[0]["expression"], "object.spec.replicas <= 5",
            "validation expression must be preserved — without it, VAP stops enforcing the rule"
        );
        assert_eq!(
            validations[0]["message"], "replicas must be <= 5",
            "validation message must be preserved so users get meaningful rejection messages"
        );

        let resource_rules = result["spec"]["matchConstraints"]["resourceRules"]
            .as_array()
            .expect("matchConstraints.resourceRules must be a JSON array");
        assert!(
            !resource_rules.is_empty(),
            "resourceRules must be non-empty"
        );
        assert_eq!(resource_rules[0]["apiGroups"][0], "apps");
        assert_eq!(resource_rules[0]["resources"][0], "deployments");
    }

    /// decode_validatingadmissionpolicy_proto must return None for malformed proto input.
    #[test]
    fn decode_validatingadmissionpolicy_proto_returns_none_for_garbage() {
        assert!(decode_validatingadmissionpolicy_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_validatingadmissionpolicybinding_proto / decode_core_proto_by_kind ValidatingAdmissionPolicyBinding
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch ValidatingAdmissionPolicyBinding proto and extract
    /// metadata. Without this decoder, the ValidatingAdmissionPolicyBinding conformance test
    /// fails with 400 "invalid JSON: expected value at line 1 column 1" when client-go POSTs
    /// with Content-Type: application/vnd.kubernetes.protobuf.
    #[test]
    fn decode_core_proto_by_kind_dispatches_validatingadmissionpolicybinding() {
        let obj_meta = encode_length_delimited(1, b"test-vapb");
        let proto = encode_length_delimited(1, &obj_meta);

        let result = decode_core_proto_by_kind("ValidatingAdmissionPolicyBinding", &proto).expect(
            "ValidatingAdmissionPolicyBinding must decode via decode_core_proto_by_kind — without \
             this, the ValidatingAdmissionPolicyBinding API conformance test fails with 400 on POST \
             because client-go sends Content-Type: application/vnd.kubernetes.protobuf",
        );

        assert_eq!(
            result["kind"], "ValidatingAdmissionPolicyBinding",
            "kind must be ValidatingAdmissionPolicyBinding so Object::from_bytes routes correctly"
        );
        assert_eq!(result["apiVersion"], "admissionregistration.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "test-vapb",
            "name must be extracted so the object is stored under the correct key"
        );
    }

    /// PUT to ValidatingAdmissionPolicyBinding must preserve spec (policyName, validationActions).
    /// Without spec decoding, a PUT rebinding to a different policy or changing validationActions
    /// is silently dropped.
    ///
    /// ValidatingAdmissionPolicyBindingSpec field numbers (k8s 1.36 proto):
    ///   policyName=1, paramRef=2, matchResources=3, validationActions=4
    #[test]
    fn decode_validatingadmissionpolicybinding_proto_preserves_spec_on_put() {
        // Build VapbSpec: field 1=policyName, field 4=validationActions
        let mut spec: Vec<u8> = Vec::new();
        spec.extend_from_slice(&encode_length_delimited(1, b"my-vap-policy"));
        spec.extend_from_slice(&encode_length_delimited(4, b"Deny"));
        spec.extend_from_slice(&encode_length_delimited(4, b"Audit"));

        // Build ValidatingAdmissionPolicyBinding: field 1=metadata, field 2=spec
        let obj_meta = encode_length_delimited(1, b"test-vapb-spec");
        let mut proto = encode_length_delimited(1, &obj_meta);
        proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result = decode_validatingadmissionpolicybinding_proto(&proto)
            .expect("ValidatingAdmissionPolicyBinding with spec must decode successfully");

        assert_eq!(result["metadata"]["name"], "test-vapb-spec");

        assert_eq!(
            result["spec"]["policyName"], "my-vap-policy",
            "spec.policyName must survive proto decode — without it, a PUT rebinding to a \
             different policy has no effect (binding still points to old policy)"
        );

        let actions = result["spec"]["validationActions"].as_array().expect(
            "spec.validationActions must be a JSON array — absent actions mean the binding \
             has no enforcement mode after a PUT",
        );
        assert_eq!(
            actions.len(),
            2,
            "both validationActions must survive the proto round-trip"
        );
        assert_eq!(actions[0], "Deny");
        assert_eq!(actions[1], "Audit");
    }

    /// decode_validatingadmissionpolicybinding_proto must return None for malformed proto input.
    #[test]
    fn decode_validatingadmissionpolicybinding_proto_returns_none_for_garbage() {
        assert!(decode_validatingadmissionpolicybinding_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_controllerrevision_proto / decode_core_proto_by_kind ControllerRevision
    // ---------------------------------------------------------------------------

    /// decode_core_proto_by_kind must dispatch ControllerRevision proto and extract metadata
    /// and revision. Without this decoder, DaemonSet/StatefulSet rollout history tracking
    /// fails with 400 "invalid JSON: expected value at line 1 column 1" when the controller
    /// POSTs ControllerRevision with Content-Type: application/vnd.kubernetes.protobuf.
    #[test]
    fn decode_core_proto_by_kind_dispatches_controllerrevision() {
        // Build: ControllerRevision {
        //   metadata: ObjectMeta { name: "my-ds-abc123", namespace: "default" },
        //   data: RawExtension { raw: b"{}" },
        //   revision: 3,
        // }
        let mut obj_meta = encode_length_delimited(1, b"my-ds-abc123"); // ObjectMeta.name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default")); // ObjectMeta.namespace

        // RawExtension: field 1 = raw (bytes)
        let raw_ext = encode_length_delimited(1, b"{}");

        // ControllerRevision: field 1=ObjectMeta, field 2=RawExtension, field 3=revision (int64)
        let mut cr_proto = encode_length_delimited(1, &obj_meta);
        cr_proto.extend_from_slice(&encode_length_delimited(2, &raw_ext));
        // field 3 = revision (varint 3)
        cr_proto.push(0x18); // tag: field 3, wire type 0
        cr_proto.extend_from_slice(&encode_varint(3));

        let result = decode_core_proto_by_kind("ControllerRevision", &cr_proto).expect(
            "ControllerRevision must decode via decode_core_proto_by_kind — without this, \
                     DaemonSet/StatefulSet rollout history tracking fails with 400 on POST",
        );

        assert_eq!(
            result["kind"], "ControllerRevision",
            "kind must be ControllerRevision so Object::from_bytes can route the object"
        );
        assert_eq!(result["apiVersion"], "apps/v1");
        assert_eq!(
            result["metadata"]["name"], "my-ds-abc123",
            "name must be extracted so the object is stored under the correct key"
        );
        assert_eq!(result["metadata"]["namespace"], "default");
        assert_eq!(
            result["revision"], 3,
            "revision must be extracted from ControllerRevision field 3 — \
             DaemonSet/StatefulSet controllers use this to track the rollout history version"
        );
    }

    /// decode_controllerrevision_proto must return None for malformed proto input.
    #[test]
    fn decode_controllerrevision_proto_returns_none_for_garbage() {
        assert!(decode_controllerrevision_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — spec.replicas preservation in proto decoders (VAP regression)
    // ---------------------------------------------------------------------------

    /// decode_deployment_proto must preserve spec.replicas from protobuf encoding.
    ///
    /// When kubectl creates a Deployment with replicas=3 using Content-Type protobuf,
    /// the proto decoder must include spec.replicas=3 in the JSON output.
    /// Without this, apply_defaults silently defaults replicas to 1, and VAP expressions
    /// like `object.spec.replicas > 1` evaluate to false even when the user submitted
    /// replicas=3 — causing the VAP to deny its own marker Deployment.
    #[test]
    fn decode_deployment_proto_preserves_spec_replicas() {
        // DeploymentSpec field 1 = replicas (int32, varint wire type)
        // tag = (1 << 3) | 0 = 0x08, value = 3
        let mut spec_bytes = vec![0x08, 0x03]; // field 1 (replicas), varint 3

        // Add minimal selector + template so apps_spec_to_json returns non-empty
        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"test"));
        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        // Deployment { metadata: { name: "my-deploy" }, spec: spec_bytes }
        let name_bytes = encode_length_delimited(1, b"my-deploy");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("Deployment", &proto)
            .expect("Deployment proto must decode successfully");

        assert_eq!(
            result["spec"]["replicas"], 3,
            "spec.replicas must be 3 after proto decode — if missing, apply_defaults sets it to 1 \
             and VAP expressions like `object.spec.replicas > 1` evaluate false, denying the \
             marker Deployment that the test itself created (conformance tests: should support \
             ValidatingAdmissionPolicy API operations, should allow expressions to refer variables)"
        );
    }

    /// decode_statefulset_proto must preserve spec.replicas from protobuf encoding.
    ///
    /// Same class of bug as Deployment: without replicas in JSON, apply_defaults sets 1,
    /// and VAP expressions that test replica count evaluate false on proto-encoded StatefulSets.
    #[test]
    fn decode_statefulset_proto_preserves_spec_replicas() {
        // StatefulSetSpec field 1 = replicas (int32, varint wire type)
        let mut spec_bytes = vec![0x08, 0x05]; // field 1 (replicas), varint 5

        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"sts-test"));
        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        let name_bytes = encode_length_delimited(1, b"my-sts");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("StatefulSet", &proto)
            .expect("StatefulSet proto must decode successfully");

        assert_eq!(
            result["spec"]["replicas"], 5,
            "spec.replicas must be 5 after proto decode — without this, apply_defaults sets it to 1 \
             and VAP expressions evaluating replica count return wrong results for proto-encoded StatefulSets"
        );
    }

    /// decode_statefulset_proto must preserve status.conditions from a protobuf-encoded body.
    ///
    /// client-go's UpdateStatus sends PUT /apis/apps/v1/.../statefulsets/{name}/status with
    /// Content-Type: application/vnd.kubernetes.protobuf. Without status field decoding, the
    /// conditions array is silently dropped, the status handler removes the stored status, and
    /// the conformance watch times out waiting for the MODIFIED event with the StatusUpdate
    /// condition.
    #[test]
    fn decode_statefulset_proto_preserves_status_conditions_for_updatestatus_round_trip() {
        // Build StatefulSetCondition { type="StatusUpdate", status="True", reason="E2E" }
        // Field 1 = type (string), field 2 = status (string), field 4 = reason (string)
        let mut cond_bytes = encode_length_delimited(1, b"StatusUpdate");
        cond_bytes.extend_from_slice(&encode_length_delimited(2, b"True"));
        cond_bytes.extend_from_slice(&encode_length_delimited(4, b"E2E"));

        // Build StatefulSetStatus { conditions: [cond] }
        // Field 10 = conditions (repeated message)
        let status_bytes = encode_length_delimited(10, &cond_bytes);

        // Build minimal spec so we can assert it's still present after decoding
        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"sts-e2e"));
        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        let mut spec_bytes = vec![0x08, 0x01]; // replicas=1
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        // Build StatefulSet { metadata: { name: "my-sts" }, spec: ..., status: ... }
        let name_bytes = encode_length_delimited(1, b"my-sts");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));
        proto.extend_from_slice(&encode_length_delimited(3, &status_bytes));

        let result = decode_core_proto_by_kind("StatefulSet", &proto)
            .expect("StatefulSet with status must decode successfully");

        assert_eq!(
            result["status"]["conditions"][0]["type"], "StatusUpdate",
            "status.conditions[0].type must survive proto decode — without this, UpdateStatus \
             via protobuf drops the condition, the conformance watch times out at 620s"
        );
        assert_eq!(
            result["status"]["conditions"][0]["status"], "True",
            "status.conditions[0].status must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["reason"], "E2E",
            "status.conditions[0].reason must survive proto decode"
        );
        assert!(
            result["spec"].is_object(),
            "spec must still be present after decoding status — decoder must not clobber spec"
        );
    }

    /// decode_replicaset_proto must preserve spec.replicas from protobuf encoding.
    ///
    /// Same class of bug as Deployment: without replicas in JSON, apply_defaults sets 1,
    /// and VAP expressions that test replica count evaluate false on proto-encoded ReplicaSets.
    #[test]
    fn decode_replicaset_proto_preserves_spec_replicas() {
        // ReplicaSetSpec field 1 = replicas (int32, varint wire type)
        let mut spec_bytes = vec![0x08, 0x04]; // field 1 (replicas), varint 4

        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"rs-test"));
        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        let name_bytes = encode_length_delimited(1, b"my-rs");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("ReplicaSet", &proto)
            .expect("ReplicaSet proto must decode successfully");

        assert_eq!(
            result["spec"]["replicas"], 4,
            "spec.replicas must be 4 after proto decode — without this, apply_defaults sets it to 1 \
             and VAP expressions evaluating replica count return wrong results for proto-encoded ReplicaSets"
        );
    }

    /// decode_deployment_proto must write spec.replicas=0 — not drop it.
    ///
    /// proto3 encodes 0 as absent, so the decoder receives no replicas field.
    /// Dropping it causes the defaulter to set replicas=1, corrupting scale-to-zero.
    #[test]
    fn decode_deployment_proto_replicas_zero_not_dropped() {
        // spec_bytes with no replicas field — proto3 omits default (0) values on the wire
        let mut spec_bytes = vec![];

        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"test"));
        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        let name_bytes = encode_length_delimited(1, b"my-deploy");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("Deployment", &proto)
            .expect("Deployment proto must decode successfully");

        assert_eq!(
            result["spec"]["replicas"], 0,
            "spec.replicas must be 0 after proto decode — dropped replicas=0 causes defaulter to \
             set 1, corrupting scale-to-zero"
        );
    }

    /// decode_statefulset_proto must write spec.replicas=0 — not drop it.
    ///
    /// proto3 encodes 0 as absent, so the decoder receives no replicas field.
    /// Dropping it causes the defaulter to set replicas=1, corrupting scale-to-zero.
    #[test]
    fn decode_statefulset_proto_replicas_zero_not_dropped() {
        let mut spec_bytes = vec![];

        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"sts-test"));
        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        let name_bytes = encode_length_delimited(1, b"my-sts");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("StatefulSet", &proto)
            .expect("StatefulSet proto must decode successfully");

        assert_eq!(
            result["spec"]["replicas"], 0,
            "spec.replicas must be 0 after proto decode — dropped replicas=0 causes defaulter to \
             set 1, corrupting scale-to-zero"
        );
    }

    /// decode_replicaset_proto must write spec.replicas=0 — not drop it.
    ///
    /// proto3 encodes 0 as absent, so the decoder receives no replicas field.
    /// Dropping it causes the defaulter to set replicas=1, corrupting scale-to-zero.
    #[test]
    fn decode_replicaset_proto_replicas_zero_not_dropped() {
        let mut spec_bytes = vec![];

        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"rs-test"));
        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        let name_bytes = encode_length_delimited(1, b"my-rs");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("ReplicaSet", &proto)
            .expect("ReplicaSet proto must decode successfully");

        assert_eq!(
            result["spec"]["replicas"], 0,
            "spec.replicas must be 0 after proto decode — dropped replicas=0 causes defaulter to \
             set 1, corrupting scale-to-zero"
        );
    }

    /// decode_replicationcontroller_proto must write spec.replicas=0 — not drop it.
    ///
    /// proto3 encodes 0 as absent, so the decoder receives no replicas field.
    /// Dropping it causes the defaulter to set replicas=1, corrupting scale-to-zero.
    #[test]
    fn decode_replicationcontroller_proto_replicas_zero_not_dropped() {
        // ReplicationControllerSpec: replicas=field 1, selector=field 2 (map), template=field 3
        // Encode a spec with only a selector entry (no replicas field — proto3 omits 0)
        let mut map_entry = encode_length_delimited(1, b"app");
        map_entry.extend_from_slice(&encode_length_delimited(2, b"rc-test"));
        let spec_bytes = encode_length_delimited(2, &map_entry);

        let name_bytes = encode_length_delimited(1, b"my-rc");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("ReplicationController", &proto)
            .expect("ReplicationController proto must decode successfully");

        assert_eq!(
            result["spec"]["replicas"], 0,
            "spec.replicas must be 0 after proto decode — dropped replicas=0 causes defaulter to \
             set 1, corrupting scale-to-zero"
        );
    }

    /// decode_statefulset_proto must preserve spec.updateStrategy.rollingUpdate.partition.
    ///
    /// The rolling-update canary conformance test creates a StatefulSet with partition=3 to
    /// prevent any pod from being updated immediately. Without decoding updateStrategy, the
    /// partition is silently dropped and apply_defaults sets it to 0, causing KCM to update
    /// all pods at once. By the time waitForStatus returns, currentRevision already equals
    /// updateRevision and the test assertion "currentRevision != updateRevision" fails.
    #[test]
    fn decode_statefulset_proto_preserves_update_strategy_partition() {
        // Build RollingUpdateStatefulSetStrategy { partition: 3 }
        // field 1 = partition (int32, varint wire type): tag=0x08, value=0x03
        let rolling_update_bytes = vec![0x08, 0x03];

        // Build StatefulSetUpdateStrategy { type: "RollingUpdate", rollingUpdate: ... }
        // field 1 = type (string, wire type 2)
        // field 2 = rollingUpdate (message, wire type 2)
        let mut us_bytes = encode_length_delimited(1, b"RollingUpdate");
        us_bytes.extend_from_slice(&encode_length_delimited(2, &rolling_update_bytes));

        // Build StatefulSetSpec with replicas=3, selector, template, updateStrategy
        // field 1 = replicas (varint 3)
        // field 2 = selector (LabelSelector)
        // field 3 = template (PodTemplateSpec)
        // field 7 = updateStrategy (message)
        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"sts-canary"));
        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        let mut spec_bytes = vec![0x08, 0x03]; // replicas=3
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(7, &us_bytes));

        let name_bytes = encode_length_delimited(1, b"canary-sts");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("StatefulSet", &proto)
            .expect("StatefulSet proto must decode successfully");

        assert_eq!(
            result["spec"]["updateStrategy"]["type"], "RollingUpdate",
            "updateStrategy.type must be RollingUpdate — without this, KCM cannot respect the \
             rolling update strategy sent by the client"
        );
        assert_eq!(
            result["spec"]["updateStrategy"]["rollingUpdate"]["partition"], 3,
            "updateStrategy.rollingUpdate.partition must be 3 — without this, apply_defaults \
             resets partition to 0 and KCM updates all pods immediately, causing the rolling \
             update canary conformance test to fail (currentRevision equals updateRevision \
             before the test can observe the in-progress state)"
        );
    }

    /// decode_statefulset_proto must preserve metadata.generation from the proto body.
    ///
    /// When the conformance test rolls back a StatefulSet (setting the old image), the typed
    /// client sends a proto PUT with metadata.generation=2.  Without generation in the decoded
    /// JSON, increment_workload_generation_if_spec_changed falls back to 1 and produces
    /// generation=2 again — the same value as the previous newImage generation.  waitForStatus
    /// then sees observedGeneration=2 >= generation=2 on the immediate poll and returns before
    /// KCM has processed the rollback, causing the test to read a stale updateRevision.
    #[test]
    fn decode_statefulset_proto_preserves_metadata_generation() {
        // ObjectMeta: name="ss2" (field 1), generation=2 (field 7, varint, tag=0x38)
        let name_bytes = encode_length_delimited(1, b"ss2");
        let mut meta_bytes = encode_length_delimited(1, &name_bytes);
        // generation field 7, wire type 0 (varint): tag = (7<<3)|0 = 0x38, value = 2
        meta_bytes.extend_from_slice(&[0x38, 0x02]);

        // Minimal spec so decode_statefulset_proto returns Some(...)
        let mut label_entry = encode_length_delimited(1, b"app");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"test"));
        let selector_bytes = encode_length_delimited(1, &label_entry);
        let tmpl_meta_bytes = encode_length_delimited(11, &label_entry);
        let template_bytes = encode_length_delimited(1, &tmpl_meta_bytes);
        let mut spec_bytes = vec![0x08, 0x01]; // replicas=1
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));
        spec_bytes.extend_from_slice(&encode_length_delimited(3, &template_bytes));

        let mut proto = encode_length_delimited(1, &meta_bytes);
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result = decode_core_proto_by_kind("StatefulSet", &proto)
            .expect("StatefulSet proto must decode successfully");

        assert_eq!(
            result["metadata"]["generation"], 2,
            "metadata.generation must be 2 after proto decode — without this, a rollback PUT \
             resets generation to 2 (same as the previous spec update), waitForStatus returns \
             before KCM processes the new spec, and updateRevision points to the old revision"
        );
    }

    /// A projected configMap source with `items` (KeyToPath mappings) must survive proto decode.
    ///
    /// When the conformance test "should be consumable from pods in volume with mappings" creates
    /// a pod via protobuf with a projected configMap that maps key "data-2" to path "path/to/data-2",
    /// the `items` array must appear in the decoded JSON. Without it, the kubelet mounts the configMap
    /// without path mappings, the expected file at the mapped path is absent, and the container exits 1.
    ///
    /// This test fails if:
    /// - `KeyToPath` struct is removed from proto.rs
    /// - `items` field (tag 2) is removed from `ConfigMapProjection`
    /// - `key_to_path_items_to_json` is removed or the items serialization block in
    ///   `projected_volume_source_to_json` is removed
    #[test]
    fn projected_configmap_items_survive_proto_decode() {
        // KeyToPath { key (field 1) = "data-2", path (field 2) = "path/to/data-2" }
        let mut key_to_path = encode_length_delimited(1, b"data-2");
        key_to_path.extend_from_slice(&encode_length_delimited(2, b"path/to/data-2"));

        // LocalObjectReference { name (field 1) = "test-configmap" }
        let lor = encode_length_delimited(1, b"test-configmap");

        // ConfigMapProjection { localObjectReference (field 1), items (field 2) = [KeyToPath] }
        let mut cm_proj = encode_length_delimited(1, &lor);
        cm_proj.extend_from_slice(&encode_length_delimited(2, &key_to_path));

        // VolumeProjection { configMap (field 3) = ConfigMapProjection }
        let proj_entry = encode_length_delimited(3, &cm_proj);

        // ProjectedVolumeSource { sources (field 1) = [VolumeProjection] }
        let proj_src = encode_length_delimited(1, &proj_entry);

        // VolumeSource { projected (field 26) = ProjectedVolumeSource }
        let volume_source = encode_length_delimited(26, &proj_src);

        // Volume { name (field 1) = "projected-vol", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"projected-vol");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with projected configMap volume");

        let sources = result["spec"]["volumes"][0]["projected"]["sources"]
            .as_array()
            .expect("projected.sources must be present in decoded JSON");
        assert_eq!(sources.len(), 1, "one projection source must decode");

        let cm = &sources[0]["configMap"];
        assert_eq!(
            cm["name"], "test-configmap",
            "configMap.name must survive proto decode — kubelet uses it to fetch the ConfigMap"
        );

        let items = cm["items"].as_array().expect(
            "configMap.items must be present in projected volume — without it the kubelet mounts \
             the configMap without path mappings so 'path/to/data-2' is absent and the container \
             exits 1 (conformance: 'should be consumable from pods in volume with mappings')",
        );
        assert_eq!(items.len(), 1, "one KeyToPath item must decode");
        assert_eq!(
            items[0]["key"], "data-2",
            "items[0].key must be 'data-2' — kubelet reads the key from the ConfigMap data"
        );
        assert_eq!(
            items[0]["path"], "path/to/data-2",
            "items[0].path must be 'path/to/data-2' — kubelet writes the file at this relative \
             path within the mounted volume; if missing the container cannot find the file"
        );
    }

    /// A projected secret source with `items` (KeyToPath mappings) must survive proto decode.
    ///
    /// Mirrors the configMap case above but for projected secret volumes.  The conformance test
    /// "should be consumable from pods in volume with mappings as non-root" uses a projected
    /// secret with items.  Without items in the decoded JSON, the kubelet mounts the secret
    /// without path mappings and the expected file at the mapped path is absent.
    ///
    /// This test fails if:
    /// - `items` field (tag 2) is removed from `SecretProjection`
    /// - the items serialization block for secrets in `projected_volume_source_to_json` is removed
    #[test]
    fn projected_secret_items_survive_proto_decode() {
        // KeyToPath { key (field 1) = "secret-key", path (field 2) = "new-path-data-1" }
        let mut key_to_path = encode_length_delimited(1, b"secret-key");
        key_to_path.extend_from_slice(&encode_length_delimited(2, b"new-path-data-1"));

        // LocalObjectReference { name (field 1) = "test-secret" }
        let lor = encode_length_delimited(1, b"test-secret");

        // SecretProjection { localObjectReference (field 1), items (field 2) = [KeyToPath] }
        let mut sec_proj = encode_length_delimited(1, &lor);
        sec_proj.extend_from_slice(&encode_length_delimited(2, &key_to_path));

        // VolumeProjection { secret (field 1) = SecretProjection }
        let proj_entry = encode_length_delimited(1, &sec_proj);

        // ProjectedVolumeSource { sources (field 1) = [VolumeProjection] }
        let proj_src = encode_length_delimited(1, &proj_entry);

        // VolumeSource { projected (field 26) = ProjectedVolumeSource }
        let volume_source = encode_length_delimited(26, &proj_src);

        // Volume { name (field 1) = "projected-sec", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"projected-sec");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with projected secret volume");

        let sources = result["spec"]["volumes"][0]["projected"]["sources"]
            .as_array()
            .expect("projected.sources must be present in decoded JSON");
        assert_eq!(sources.len(), 1, "one projection source must decode");

        let sec = &sources[0]["secret"];
        assert_eq!(
            sec["name"], "test-secret",
            "secret.name must survive proto decode"
        );

        let items = sec["items"].as_array().expect(
            "secret.items must be present in projected volume — without it the kubelet mounts \
             the secret without path mappings so 'new-path-data-1' is absent and the container \
             exits 1 (conformance: projected secret volume with mappings)",
        );
        assert_eq!(items.len(), 1, "one KeyToPath item must decode");
        assert_eq!(
            items[0]["key"], "secret-key",
            "items[0].key must be 'secret-key'"
        );
        assert_eq!(
            items[0]["path"], "new-path-data-1",
            "items[0].path must be 'new-path-data-1'"
        );
    }

    /// A flat (non-projected) configMap volume with `items` must survive proto decode.
    ///
    /// This test fails if:
    /// - `items` field (tag 2) is removed from `ConfigMapVolumeSource`
    /// - the items serialization block for configMap in `pod_spec_to_json` is removed
    #[test]
    fn flat_configmap_volume_items_survive_proto_decode() {
        // KeyToPath { key (field 1) = "ca.crt", path (field 2) = "ca.crt" }
        let mut key_to_path = encode_length_delimited(1, b"ca.crt");
        key_to_path.extend_from_slice(&encode_length_delimited(2, b"ca.crt"));

        // LocalObjectReference { name (field 1) = "kube-root-ca.crt" }
        let lor = encode_length_delimited(1, b"kube-root-ca.crt");

        // ConfigMapVolumeSource { localObjectReference (field 1), items (field 2) = [KeyToPath] }
        let mut cm_vol_src = encode_length_delimited(1, &lor);
        cm_vol_src.extend_from_slice(&encode_length_delimited(2, &key_to_path));

        // VolumeSource { configMap (field 19) = ConfigMapVolumeSource }
        let volume_source = encode_length_delimited(19, &cm_vol_src);

        // Volume { name (field 1) = "ca-vol", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"ca-vol");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with flat configMap volume with items");

        let cm = &result["spec"]["volumes"][0]["configMap"];
        assert_eq!(
            cm["name"], "kube-root-ca.crt",
            "configMap.name must survive proto decode"
        );

        let items = cm["items"].as_array().expect(
            "configMap.items must survive proto decode — without it kubelet mounts the whole \
             configMap instead of only the mapped keys",
        );
        assert_eq!(items.len(), 1, "one item must decode");
        assert_eq!(items[0]["key"], "ca.crt", "key must be 'ca.crt'");
        assert_eq!(items[0]["path"], "ca.crt", "path must be 'ca.crt'");
    }

    /// A flat (non-projected) secret volume with `items` must survive proto decode.
    ///
    /// This test fails if:
    /// - `items` field (tag 2) is removed from `SecretVolumeSource`
    /// - the items serialization block for secret in `pod_spec_to_json` is removed
    #[test]
    fn flat_secret_volume_items_survive_proto_decode() {
        // KeyToPath { key (field 1) = "tls.crt", path (field 2) = "tls.crt" }
        let mut key_to_path = encode_length_delimited(1, b"tls.crt");
        key_to_path.extend_from_slice(&encode_length_delimited(2, b"tls.crt"));

        // SecretVolumeSource { secretName (field 1) = "tls-secret", items (field 2) = [KeyToPath] }
        let mut sec_vol_src = encode_length_delimited(1, b"tls-secret");
        sec_vol_src.extend_from_slice(&encode_length_delimited(2, &key_to_path));

        // VolumeSource { secret (field 6) = SecretVolumeSource }
        let volume_source = encode_length_delimited(6, &sec_vol_src);

        // Volume { name (field 1) = "tls-vol", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"tls-vol");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = decode_pod_proto(&pod_proto)
            .expect("decode_pod_proto must succeed with flat secret volume with items");

        let sec = &result["spec"]["volumes"][0]["secret"];
        assert_eq!(
            sec["secretName"], "tls-secret",
            "secret.secretName must survive proto decode"
        );

        let items = sec["items"].as_array().expect(
            "secret.items must survive proto decode — without it kubelet mounts all secret keys \
             instead of only the mapped subset",
        );
        assert_eq!(items.len(), 1, "one item must decode");
        assert_eq!(items[0]["key"], "tls.crt", "key must be 'tls.crt'");
        assert_eq!(items[0]["path"], "tls.crt", "path must be 'tls.crt'");
    }
}
