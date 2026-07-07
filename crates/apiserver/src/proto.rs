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

// ---------------------------------------------------------------------------
// Dead-in-production, test-only wire-format fixture structs.
//
// Every struct from here down to `Quantity` is reachable only from
// `#[cfg(test)]` code. Real production decoding for these Kubernetes
// resources goes through the protoc-compiled *_gen.rs types and their
// *_gen_adapter.rs decode_*_proto_gen() functions (e.g.
// core_gen_adapter::decode_pod_proto_gen for Pod/Container/PodSpec/Probe/
// VolumeSource/EnvVar). These hand-rolled structs exist only so tests can
// hand-assemble wire-format bytes without depending on the protoc-generated
// types. `#[derive(Message)]` self-constructs each type inside its
// Default/Message impls, so rustc's dead_code lint cannot see that nothing
// else ever builds one — gating them documents the truth explicitly (see
// PersistentVolumeClaim* below for the original precedent).
// ---------------------------------------------------------------------------

/// OwnerReference — one entry in ObjectMeta.ownerReferences.
/// Source: apimachinery-meta-v1-generated.proto message OwnerReference
/// Field numbers match the official proto definition exactly.
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct OwnerReference {
    /// kind (field 1, string)
    #[prost(string, tag = "1")]
    kind: String,
    /// name (field 3, string)
    #[prost(string, tag = "3")]
    name: String,
    /// uid (field 4, string)
    #[prost(string, tag = "4")]
    uid: String,
    /// apiVersion (field 5, string)
    #[prost(string, tag = "5")]
    api_version: String,
    /// controller (field 6, optional bool)
    #[prost(bool, optional, tag = "6")]
    controller: Option<bool>,
    /// blockOwnerDeletion (field 7, optional bool)
    #[prost(bool, optional, tag = "7")]
    block_owner_deletion: Option<bool>,
}

// --- k8s.io/api/core/v1/generated.proto ---

/// ResourceRequirements — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message ResourceRequirements
/// limits (field 1) and requests (field 2) are both map<string, Quantity>.
#[cfg(test)]
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
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct LifecycleExecAction {
    /// command (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    command: Vec<String>,
}

/// SleepAction — api-core-v1-generated.proto message SleepAction
/// field 1 = seconds (int64)
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct SleepAction {
    /// seconds (field 1, int64)
    #[prost(int64, tag = "1")]
    seconds: i64,
}

/// LifecycleHandler — api-core-v1-generated.proto message LifecycleHandler
/// field 1 = exec (ExecAction), field 2 = httpGet (HTTPGetAction),
/// field 3 = tcpSocket (TCPSocketAction), field 4 = sleep (SleepAction)
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct ExecProbeAction {
    /// command (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    command: Vec<String>,
}

/// IntOrString — k8s.io/apimachinery IntOrString
/// field 1 = type (int64: 0=int, 1=string), field 2 = intVal (int32), field 3 = strVal (string)
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct IntOrString {
    #[prost(int64, tag = "1")]
    r#type: i64,
    #[prost(int32, tag = "2")]
    int_val: i32,
    #[prost(string, tag = "3")]
    str_val: String,
}

/// HttpGetProbeAction — api-core-v1-generated.proto message HTTPGetAction
/// field 1 = path (string), field 2 = port (IntOrString), field 3 = host (string), field 4 = scheme (string)
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
/// field 1 = secretName (string), field 2 = items (repeated KeyToPath),
/// field 3 = defaultMode (int32)
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct SecretVolumeSource {
    /// secretName (field 1, string) — name of the Secret in the pod's namespace
    #[prost(string, tag = "1")]
    secret_name: String,
    /// items (field 2, repeated KeyToPath) — key-to-path mappings within the volume
    #[prost(message, repeated, tag = "2")]
    items: Vec<KeyToPath>,
    /// defaultMode (field 3, int32) — default permission bits for files in the volume
    #[prost(int32, tag = "3")]
    default_mode: i32,
}

/// LocalObjectReference — api-core-v1-generated.proto message LocalObjectReference
/// Used inside ConfigMapVolumeSource (embedded, not a separate JSON field).
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct LocalObjectReference {
    /// name (field 1, string) — name of the referent
    #[prost(string, tag = "1")]
    name: String,
}

/// ConfigMapVolumeSource — api-core-v1-generated.proto message ConfigMapVolumeSource
/// field 1 = localObjectReference (message, name), field 2 = items (repeated KeyToPath),
/// field 3 = defaultMode (int32)
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct ConfigMapVolumeSource {
    /// localObjectReference (field 1, message) — contains the configMap name
    #[prost(message, tag = "1")]
    local_object_reference: Option<LocalObjectReference>,
    /// items (field 2, repeated KeyToPath) — key-to-path mappings within the volume
    #[prost(message, repeated, tag = "2")]
    items: Vec<KeyToPath>,
    /// defaultMode (field 3, int32) — default permission bits for files in the volume
    #[prost(int32, tag = "3")]
    default_mode: i32,
}

/// EmptyDirVolumeSource — api-core-v1-generated.proto message EmptyDirVolumeSource
/// medium (field 1, string): "" = node default, "Memory" = tmpfs.
/// sizeLimit (field 2, bytes/Quantity) is skipped — kubelet defaults to node capacity.
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct EmptyDirVolumeSource {
    /// medium (field 1, string)
    #[prost(string, tag = "1")]
    medium: String,
}

/// HostPathVolumeSource — api-core-v1-generated.proto message HostPathVolumeSource
/// path (field 1, string): host filesystem path to expose.
/// type (field 2, string): optional HostPathType hint (e.g. "Directory", "File").
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct DownwardAPIProjection {
    /// items (field 1, repeated DownwardAPIVolumeFile)
    #[prost(message, repeated, tag = "1")]
    items: Vec<DownwardAPIVolumeFile>,
}

/// ServiceAccountTokenProjection — api-core-v1-generated.proto
/// Projects a bound service-account token into the volume.
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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

/// ContainerResizePolicy — k8s.io/api/core/v1/generated.proto message ContainerResizePolicy
/// Specifies the resize policy for a resource (cpu/memory) in a container.
/// Field numbers: resourceName (field 1), restartPolicy (field 2).
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct ContainerResizePolicy {
    /// resourceName (field 1, string) — "cpu" or "memory"
    #[prost(string, tag = "1")]
    resource_name: String,
    /// restartPolicy (field 2, string) — "NotRequired" or "RestartContainer"
    #[prost(string, tag = "2")]
    restart_policy: String,
}

/// ContainerPort — k8s.io/api/core/v1/generated.proto message ContainerPort
/// Represents a network port in a single container.
#[cfg(test)]
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
#[cfg(test)]
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
    /// resizePolicy (field 23, repeated ContainerResizePolicy) — per-resource resize restart policy;
    /// used by kubelet and apiserver for in-place pod resize (KEP-1287). Silently dropped before
    /// this fix, causing resize conformance tests to fail post-PATCH verification.
    #[prost(message, repeated, tag = "23")]
    resize_policy: Vec<ContainerResizePolicy>,
    /// restartPolicy (field 24, optional string) — KEP-3939 sidecar containers. When set to
    /// "Always", the init container runs as a sidecar (non-blocking). Silently dropped before
    /// this fix, converting sidecar init containers into traditional blocking init containers
    /// (sleep 1d never exits → pod stuck Pending → resize conformance tests time out after 300s).
    #[prost(string, optional, tag = "24")]
    restart_policy: Option<String>,
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
///   field 5  = activeDeadlineSeconds (int64)
///   field 6  = dnsPolicy (string, skipped)
///   field 7  = nodeSelector (map, skipped)
///   field 8  = serviceAccountName (string)
///   field 9  = automountServiceAccountToken (bool, skipped)
///   field 10 = nodeName (string)
///   field 11 = hostNetwork (bool, skipped)
///   field 16 = hostname (string)
///   field 17 = subdomain (string)
///   field 20 = initContainers (repeated Container)
///   field 29 = runtimeClassName (optional string)
#[cfg(test)]
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
    /// activeDeadlineSeconds (field 5, optional int64) — when set, the pod will be forcibly
    /// terminated after this many seconds. Required for Terminating-scope ResourceQuota
    /// accounting: pod_is_terminating() checks this field to decide whether a pod counts
    /// against a Terminating-scoped quota. Without this field, all pods look non-terminating
    /// and the Terminating quota never counts any pod (conformance test :803 fails with 5-min
    /// timeout waiting for status.used to reflect the terminating pod).
    #[prost(int64, optional, tag = "5")]
    active_deadline_seconds: Option<i64>,
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
    /// enableServiceLinks (field 26, optional bool) — controls whether service env vars are
    /// injected into the pod; the kubelet reads this to build container env; an explicit false
    /// must survive decode or the kubelet injects vars the user explicitly suppressed.
    #[prost(bool, optional, tag = "26")]
    enable_service_links: Option<bool>,
    /// runtimeClassName (field 29, optional string) — references a RuntimeClass object in the
    /// node.k8s.io group; the apiserver uses this at admission to inject spec.overhead from the
    /// RuntimeClass.overhead.podFixed field into the pod.
    #[prost(string, optional, tag = "29")]
    runtime_class_name: Option<String>,
}

/// ObjectReference — used in ServiceAccount.secrets
/// Source: api-core-v1-generated.proto message ObjectReference
#[cfg(test)]
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

// --- k8s.io/api/authorization/v1/generated.proto ---

#[derive(Clone, PartialEq, Message)]
struct BoundObjectReference {
    #[prost(string, tag = "1")]
    kind: String,
    #[prost(string, tag = "2")]
    api_version: String,
    #[prost(string, tag = "3")]
    name: String,
    #[prost(string, tag = "4")]
    uid: String,
}

#[derive(Clone, PartialEq, Message)]
struct TokenRequestSpec {
    #[prost(string, repeated, tag = "1")]
    audiences: Vec<String>,
    #[prost(int64, tag = "4")]
    expiration_seconds: i64,
    #[prost(message, tag = "3")]
    bound_object_ref: Option<BoundObjectReference>,
}

#[derive(Clone, PartialEq, Message)]
struct TokenRequestStatus {
    #[prost(string, tag = "1")]
    token: String,
}

#[derive(Clone, PartialEq, Message)]
struct TokenRequestProto {
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    #[prost(message, tag = "2")]
    spec: Option<TokenRequestSpec>,
    #[prost(message, tag = "3")]
    status: Option<TokenRequestStatus>,
}

/// ServiceAccount — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message ServiceAccount
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct ServiceAccount {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// secrets (field 2, repeated ObjectReference)
    #[prost(message, repeated, tag = "2")]
    secrets: Vec<ObjectReference>,
    /// imagePullSecrets (field 3, repeated LocalObjectReference)
    #[prost(message, repeated, tag = "3")]
    image_pull_secrets: Vec<LocalObjectReference>,
    /// automountServiceAccountToken (field 4, bool)
    #[prost(bool, optional, tag = "4")]
    automount_service_account_token: Option<bool>,
}

/// PersistentVolumeClaimSpec — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message PersistentVolumeClaimSpec
/// Test-only encoder: builds wire-format-correct bytes for decode tests; the live
/// decode path is `core_gen_adapter::decode_persistentvolumeclaim_proto_gen`.
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct PersistentVolumeClaimSpec {
    /// accessModes (field 1, repeated string)
    #[prost(string, repeated, tag = "1")]
    access_modes: Vec<String>,
    /// resources (field 2, message VolumeResourceRequirements — same wire layout as ResourceRequirements)
    #[prost(message, optional, tag = "2")]
    resources: Option<ResourceRequirements>,
    /// volumeName (field 3, string)
    #[prost(string, tag = "3")]
    volume_name: String,
    /// storageClassName (field 5, string)
    #[prost(string, tag = "5")]
    storage_class_name: String,
    /// volumeMode (field 6, string)
    #[prost(string, tag = "6")]
    volume_mode: String,
}

/// PersistentVolumeClaimCondition — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message PersistentVolumeClaimCondition
/// Fields: type(1), status(2), lastProbeTime(3), lastTransitionTime(4), reason(5), message(6)
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct PersistentVolumeClaimCondition {
    /// type (field 1, string)
    #[prost(string, tag = "1")]
    r#type: String,
    /// status (field 2, string — ConditionStatus: "True"/"False"/"Unknown")
    #[prost(string, tag = "2")]
    status: String,
    /// lastProbeTime (field 3, Time) — decoded as raw bytes, not serialized
    #[prost(bytes = "vec", tag = "3")]
    last_probe_time: Vec<u8>,
    /// lastTransitionTime (field 4, Time) — decoded as raw bytes, not serialized
    #[prost(bytes = "vec", tag = "4")]
    last_transition_time: Vec<u8>,
    /// reason (field 5, string)
    #[prost(string, tag = "5")]
    reason: String,
    /// message (field 6, string)
    #[prost(string, tag = "6")]
    message: String,
}

/// PersistentVolumeClaimStatus — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message PersistentVolumeClaimStatus
/// Fields: phase(1), accessModes(2), capacity(3), conditions(4), ...
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct PersistentVolumeClaimStatus {
    /// phase (field 1, string — PersistentVolumeClaimPhase)
    #[prost(string, tag = "1")]
    phase: String,
    /// accessModes (field 2, repeated string) — not typically set on status writes
    #[prost(string, repeated, tag = "2")]
    access_modes: Vec<String>,
    /// capacity (field 3, ResourceList = map<string, Quantity>) — skip (complex)
    #[prost(bytes = "vec", tag = "3")]
    capacity: Vec<u8>,
    /// conditions (field 4, repeated PersistentVolumeClaimCondition)
    #[prost(message, repeated, tag = "4")]
    conditions: Vec<PersistentVolumeClaimCondition>,
}

/// PersistentVolumeClaim — k8s.io/api/core/v1/generated.proto
/// Source: api-core-v1-generated.proto message PersistentVolumeClaim
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct PersistentVolumeClaim {
    /// metadata (field 1, message ObjectMeta)
    #[prost(message, tag = "1")]
    metadata: Option<ObjectMeta>,
    /// spec (field 2, message PersistentVolumeClaimSpec)
    #[prost(message, optional, tag = "2")]
    spec: Option<PersistentVolumeClaimSpec>,
    /// status (field 3, message PersistentVolumeClaimStatus)
    #[prost(message, optional, tag = "3")]
    status: Option<PersistentVolumeClaimStatus>,
}

/// Quantity — k8s.io/apimachinery/pkg/api/resource/generated.proto
/// Source: apimachinery-resource-generated.proto message Quantity
///
/// Only field 1 (string representation) is decoded; binary/decimal forms are ignored.
/// This is sufficient for LimitRange admission: we only need the human-readable value
/// (e.g. "500m", "128Mi") to pass through to JSON.
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct Quantity {
    /// string representation (field 1, e.g. "500m", "128Mi", "1")
    #[prost(string, optional, tag = "1")]
    string: Option<String>,
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

pub fn decode_proto_by_kind_and_version(
    kind: &str,
    api_version: &str,
    raw: &[u8],
) -> Option<serde_json::Value> {
    match kind {
        "CustomResourceDefinition" => crate::apiextensions_gen_adapter::decode_crd_proto_gen(raw),
        "Namespace" => crate::core_gen_adapter::decode_namespace_proto_gen(raw),
        "ConfigMap" => crate::core_gen_adapter::decode_configmap_proto_gen(raw),
        "Pod" => crate::core_gen_adapter::decode_pod_proto_gen(raw),
        "PodTemplate" => crate::core_gen_adapter::decode_podtemplate_proto_gen(raw),
        "Node" => crate::core_gen_adapter::decode_node_proto_gen(raw),
        "Service" => crate::core_gen_adapter::decode_service_proto_gen(raw),
        "Secret" => crate::core_gen_adapter::decode_secret_proto_gen(raw),
        "ReplicationController" => {
            crate::core_gen_adapter::decode_replicationcontroller_proto_gen(raw)
        }
        "PersistentVolume" => crate::core_gen_adapter::decode_persistentvolume_proto_gen(raw),
        "Lease" => crate::coord_gen_adapter::decode_lease_proto_gen_a(raw),
        "IPAddress" => {
            crate::net_disc_cert_policy_events_gen_adapter::decode_ipaddress_proto_gen(raw)
        }
        "ServiceCIDR" => {
            crate::net_disc_cert_policy_events_gen_adapter::decode_servicecidr_proto_gen(raw)
        }
        "CSINode" => crate::storage_node_flow_gen_adapter::decode_csinode_proto_gen(raw),
        "CSIDriver" => crate::storage_node_flow_gen_adapter::decode_csidriver_proto_gen(raw),
        "CSIStorageCapacity" => {
            crate::storage_node_flow_gen_adapter::decode_csistoragecapacity_proto_gen(raw)
        }
        "Event" => {
            if api_version == "events.k8s.io/v1" {
                crate::net_disc_cert_policy_events_gen_adapter::decode_events_v1_event_proto_gen(
                    raw,
                )
            } else {
                crate::core_gen_adapter::decode_event_proto_gen(raw)
            }
        }
        "ClusterRole" => crate::rbac_gen_adapter::decode_clusterrole_proto_gen(raw),
        "ClusterRoleBinding" => crate::rbac_gen_adapter::decode_clusterrolebinding_proto_gen(raw),
        "Role" => crate::rbac_gen_adapter::decode_role_proto_gen(raw),
        "RoleBinding" => crate::rbac_gen_adapter::decode_rolebinding_proto_gen(raw),
        "SubjectAccessReview" => {
            crate::rbac_gen_adapter::decode_subject_access_review_proto_gen(raw)
        }
        "LocalSubjectAccessReview" => {
            crate::rbac_gen_adapter::decode_local_subject_access_review_proto_gen(raw)
        }
        "TokenReview" => crate::rbac_gen_adapter::decode_token_review_proto_gen(raw),
        "CronJob" => crate::batch_gen_adapter::decode_cronjob_proto_gen(raw),
        "Job" => crate::batch_gen_adapter::decode_job_proto_gen(raw),
        "RuntimeClass" => crate::storage_node_flow_gen_adapter::decode_runtimeclass_proto_gen(raw),
        "VolumeAttachment" => {
            crate::storage_node_flow_gen_adapter::decode_volumeattachment_proto_gen(raw)
        }
        "StatefulSet" => crate::apps_gen_adapter::decode_statefulset_proto_gen(raw),
        "Deployment" => crate::apps_gen_adapter::decode_deployment_proto_gen(raw),
        "DaemonSet" => crate::apps_gen_adapter::decode_daemonset_proto_gen(raw),
        "ReplicaSet" => crate::apps_gen_adapter::decode_replicaset_proto_gen(raw),
        "ServiceAccount" => crate::core_gen_adapter::decode_serviceaccount_proto_gen(raw),
        "PersistentVolumeClaim" => {
            crate::core_gen_adapter::decode_persistentvolumeclaim_proto_gen(raw)
        }
        "Endpoints" => crate::core_gen_adapter::decode_endpoints_proto_gen(raw),
        "StorageClass" => crate::storage_node_flow_gen_adapter::decode_storageclass_proto_gen(raw),
        "VolumeAttributesClass" => {
            crate::storage_node_flow_gen_adapter::decode_volumeattributesclass_proto_gen(raw)
        }
        "ResourceQuota" => crate::core_gen_adapter::decode_resourcequota_proto_gen(raw),
        "LimitRange" => crate::core_gen_adapter::decode_limitrange_proto_gen(raw),
        "PodDisruptionBudget" => {
            crate::net_disc_cert_policy_events_gen_adapter::decode_poddisruptionbudget_proto_gen(
                raw,
            )
        }
        "FlowSchema" => crate::storage_node_flow_gen_adapter::decode_flowschema_proto_gen(raw),
        "PriorityLevelConfiguration" => {
            crate::storage_node_flow_gen_adapter::decode_prioritylevelconfiguration_proto_gen(raw)
        }
        "ValidatingWebhookConfiguration" => {
            crate::admissionreg_gen_adapter::decode_validatingwebhookconfiguration_proto_gen(raw)
        }
        "MutatingWebhookConfiguration" => {
            crate::admissionreg_gen_adapter::decode_mutatingwebhookconfiguration_proto_gen(raw)
        }
        "MutatingAdmissionPolicy" => {
            crate::admissionreg_gen_adapter::decode_mutatingadmissionpolicy_proto_gen(raw)
        }
        "MutatingAdmissionPolicyBinding" => {
            crate::admissionreg_gen_adapter::decode_mutatingadmissionpolicybinding_proto_gen(raw)
        }
        "ValidatingAdmissionPolicy" => {
            crate::admissionreg_gen_adapter::decode_validatingadmissionpolicy_proto_gen(raw)
        }
        "ValidatingAdmissionPolicyBinding" => {
            crate::admissionreg_gen_adapter::decode_validatingadmissionpolicybinding_proto_gen(raw)
        }
        "IngressClass" => {
            crate::net_disc_cert_policy_events_gen_adapter::decode_ingressclass_proto_gen(raw)
        }
        "Ingress" => crate::net_disc_cert_policy_events_gen_adapter::decode_ingress_proto_gen(raw),
        "EndpointSlice" => {
            crate::net_disc_cert_policy_events_gen_adapter::decode_endpointslice_proto_gen(raw)
        }
        "CertificateSigningRequest" => {
            crate::net_disc_cert_policy_events_gen_adapter::decode_csr_proto_gen(raw)
        }
        "PriorityClass" => {
            crate::storage_node_flow_gen_adapter::decode_priorityclass_proto_gen(raw)
        }
        "ControllerRevision" => crate::apps_gen_adapter::decode_controllerrevision_proto_gen(raw),
        "DeleteOptions" => crate::apiextensions_gen_adapter::decode_delete_options_proto_gen(raw),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Gnostic OpenAPI v2 proto encoder
// ---------------------------------------------------------------------------
//
// kubectl 1.36's validation code path sends a proto-only Accept header:
//   Accept: application/com.github.proto-openapi.spec.v2@v1.0+protobuf
// and unconditionally decodes the response body as a gnostic openapi_v2.Document
// protobuf message, ignoring the response Content-Type. Returning JSON triggers
// "proto: cannot parse invalid wire-format data".
//
// This encoder produces a minimal but wire-valid gnostic Document. Field numbers
// match github.com/google/gnostic/openapiv2/OpenAPIv2.proto:
//   Document field 1 = swagger (string)
//   Document field 2 = info (Info message)
//     Info field 1 = title (string)
//     Info field 2 = description (string)  [version is field 6]
// Definitions (field 14 in gnostic proto) is omitted — an empty/absent
// definitions map is valid; kubectl skips schema validation for types it
// has no definition for. Encoding CRD definitions in proto is deferred to
// mayor-52wo (embedding upstream OpenAPI v2 schema).

fn gnostic_varint(mut v: u64) -> Vec<u8> {
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

fn gnostic_ld_field(field_number: u64, payload: &[u8]) -> Vec<u8> {
    let tag = (field_number << 3) | 2; // wire type 2 = length-delimited
    let mut out = gnostic_varint(tag);
    out.extend_from_slice(&gnostic_varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

/// Encode a minimal gnostic `openapi_v2.Document` protobuf that kubectl accepts.
///
/// Returns raw proto bytes (no k8s magic prefix — the gnostic proto is NOT wrapped
/// in a Kubernetes Unknown envelope; it is the raw Document message bytes).
pub fn encode_gnostic_openapi_v2_document() -> Vec<u8> {
    // Info sub-message: field 1 = title, field 2 = description.
    // (gnostic Info.version is field 6; omitting it produces empty string which
    // is accepted by kubectl's gnostic decoder even though Swagger 2.0 requires it.)
    let mut info = gnostic_ld_field(1, b"u7s");
    info.extend_from_slice(&gnostic_ld_field(2, b"v1"));

    // Document: field 1 = swagger "2.0", field 2 = info.
    let mut doc = gnostic_ld_field(1, b"2.0");
    doc.extend_from_slice(&gnostic_ld_field(2, &info));
    doc
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

        let result = decode_core_proto_by_kind("Namespace", &namespace_proto)
            .expect("must decode namespace proto");

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
        let result = decode_core_proto_by_kind("Namespace", &namespace_proto).expect("must decode");

        assert_eq!(result["metadata"]["name"], "ns");
        assert_eq!(result["metadata"]["labels"]["env"], "test");
        assert_eq!(result["metadata"]["annotations"]["note"], "hi");
    }

    /// The gen-path Namespace decoder must return None for malformed proto input.
    #[test]
    fn decode_namespace_proto_returns_none_for_garbage() {
        assert!(decode_core_proto_by_kind("Namespace", &[0xff, 0xff, 0xff]).is_none());
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

        // Decode the inner proto-encoded Namespace via the live dispatch path
        let json = decode_core_proto_by_kind("Namespace", &env.raw)
            .expect("namespace proto decode must succeed");
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

        let result = decode_core_proto_by_kind("ConfigMap", &configmap_proto)
            .expect("must decode configmap proto");

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

        let result = decode_core_proto_by_kind("ConfigMap", &configmap_proto)
            .expect("must decode configmap proto");

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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto).expect(
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

    /// decode_pod_proto must preserve spec.runtimeClassName from field 29 of PodSpec.
    ///
    /// The conformance test '[sig-node] RuntimeClass should schedule a Pod requesting a
    /// RuntimeClass and initialize its Overhead' creates a pod via the typed Go client which
    /// sends protobuf. The pod body contains spec.runtimeClassName. Without decoding field 29,
    /// runtimeClassName is dropped from the JSON, the overhead injection block in create_pod
    /// is never entered, and spec.overhead remains absent — failing the assertion that
    /// pod.Spec.Overhead equals rc.Overhead.PodFixed in the CREATE response.
    #[test]
    fn decode_pod_proto_preserves_runtime_class_name() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "rc-pod", namespace: "test-ns" },
        //   spec: PodSpec {
        //     containers: [Container { name: "c", image: "img" }],
        //     runtimeClassName: "my-runtime-class",   // field 29
        //   }
        // }
        let mut obj_meta = encode_length_delimited(1, b"rc-pod");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"test-ns"));

        let mut container = encode_length_delimited(1, b"c");
        container.extend_from_slice(&encode_length_delimited(2, b"img"));

        let mut pod_spec = encode_length_delimited(2, &container); // containers at field 2
        pod_spec.extend_from_slice(&encode_length_delimited(29, b"my-runtime-class")); // runtimeClassName at field 29

        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
            .expect("decode_pod_proto must succeed for a pod with runtimeClassName");

        assert_eq!(
            result["spec"]["runtimeClassName"], "my-runtime-class",
            "spec.runtimeClassName must survive proto decode — without it the overhead \
             injection block in create_pod is never entered and spec.overhead stays absent, \
             causing the RuntimeClass conformance test to fail"
        );
    }

    /// decode_pod_proto must preserve spec.activeDeadlineSeconds from field 5 of PodSpec.
    ///
    /// The ResourceQuota conformance test "should verify ResourceQuota with terminating scopes"
    /// ([sig-api-machinery] resource_quota.go:803) creates a terminating pod (activeDeadlineSeconds=600)
    /// via the typed Go client which sends protobuf. Without decoding PodSpec field 5, the stored
    /// JSON lacks activeDeadlineSeconds, pod_is_terminating() always returns false, and the
    /// reconciler never counts the pod against the Terminating-scoped quota. The test then
    /// times out (5 minutes) waiting for status.used.pods to reach "1". This test must fail
    /// if the field 5 decode is removed.
    #[test]
    fn decode_pod_proto_preserves_active_deadline_seconds_for_terminating_scope_quota() {
        // Build: Pod {
        //   metadata: ObjectMeta { name: "terminating-pod", namespace: "test-ns" },
        //   spec: PodSpec {
        //     containers: [Container { name: "c", image: "img" }],
        //     activeDeadlineSeconds: 600,   // field 5, varint
        //   }
        // }
        fn encode_varint_field(field_number: u64, value: u64) -> Vec<u8> {
            let tag = field_number << 3; // wire type 0 = varint
            let mut out = Vec::new();
            let mut t = tag;
            loop {
                let byte = (t & 0x7f) as u8;
                t >>= 7;
                if t == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            let mut v = value;
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

        let mut obj_meta = encode_length_delimited(1, b"terminating-pod");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"test-ns"));

        let mut container = encode_length_delimited(1, b"c");
        container.extend_from_slice(&encode_length_delimited(2, b"img"));

        let mut pod_spec = encode_length_delimited(2, &container); // containers at field 2
        pod_spec.extend_from_slice(&encode_varint_field(5, 600)); // activeDeadlineSeconds = 600

        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
            .expect("decode_pod_proto must succeed for a pod with activeDeadlineSeconds");

        assert_eq!(
            result["spec"]["activeDeadlineSeconds"], 600,
            "spec.activeDeadlineSeconds must survive proto decode — without it pod_is_terminating \
             always returns false, the reconciler never counts the terminating pod against a \
             Terminating-scoped ResourceQuota, and the conformance test times out after 5 minutes \
             waiting for status.used.pods to reach '1'"
        );
    }

    /// decode_pod_proto must carry enableServiceLinks (field 26) through proto decode.
    ///
    /// The conformance var-expansion test creates pods via the typed Go client (protobuf).
    /// An explicit enableServiceLinks=false must survive the proto path unchanged — if
    /// field 26 is dropped the field goes absent, the create defaulting stamps it true,
    /// and service env vars are injected into pods that explicitly suppressed them.
    /// An absent field must remain absent so the create-path defaulting stamps it true
    /// (the kubelet requires a non-nil value to build the container env).
    #[test]
    fn enable_service_links_survives_proto_decode_so_kubelet_can_build_pod_env() {
        // Helper: encode a varint field (wire type 0) — used for bool fields.
        let encode_varint_field = |field_number: u64, value: u64| -> Vec<u8> {
            let tag = field_number << 3; // wire type 0 = varint
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(value));
            out
        };

        // --- case 1: enableServiceLinks = false (explicit, must survive) ---
        let mut obj_meta = encode_length_delimited(1, b"esl-pod");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"test-ns"));

        let mut container = encode_length_delimited(1, b"c");
        container.extend_from_slice(&encode_length_delimited(2, b"img"));

        // PodSpec: containers at field 2, enableServiceLinks=false at field 30
        // (canonical proto field number from k8s.io/api/core/v1/generated.proto)
        let mut pod_spec = encode_length_delimited(2, &container);
        pod_spec.extend_from_slice(&encode_varint_field(30, 0)); // false

        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
            .expect("decode_pod_proto must succeed for a pod with enableServiceLinks=false");

        assert_eq!(
            result["spec"]["enableServiceLinks"], false,
            "enableServiceLinks=false must survive proto decode — if dropped, \
             create defaulting stamps it true and service vars are injected into pods \
             that explicitly suppressed them (var-expansion conformance)"
        );

        // --- case 2: enableServiceLinks absent — must be absent in decoded JSON ---
        // The create defaulting (apply_pod_create_defaults) reads the typed PodSpec which
        // defaults the field to true when absent, then writes it back only if null in JSON.
        // If we emit false when the proto field is absent, apply_pod_create_defaults would
        // see false and skip writing, leaving it false — incorrect for pods that never set it.
        let mut container2 = encode_length_delimited(1, b"c");
        container2.extend_from_slice(&encode_length_delimited(2, b"img"));

        let pod_spec2 = encode_length_delimited(2, &container2); // no field 26

        let mut obj_meta2 = encode_length_delimited(1, b"esl-pod-absent");
        obj_meta2.extend_from_slice(&encode_length_delimited(3, b"test-ns"));

        let mut pod_proto2 = encode_length_delimited(1, &obj_meta2);
        pod_proto2.extend_from_slice(&encode_length_delimited(2, &pod_spec2));

        let result2 = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto2)
            .expect("decode_pod_proto must succeed for a pod without enableServiceLinks");

        assert!(
            result2["spec"]["enableServiceLinks"].is_null(),
            "absent enableServiceLinks must stay absent in decoded JSON so apply_pod_create_defaults \
             can default it to true — if we emit false here the field stays false for all \
             proto-created pods that never set it, causing incorrect kubelet env"
        );
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
            .expect("must decode Pod with no spec");

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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto).expect(
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto).expect(
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto).expect(
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto).expect(
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto).expect(
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto).expect(
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

        let result =
            decode_core_proto_by_kind("Node", &node_proto).expect("must decode node proto");

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

        let result =
            decode_core_proto_by_kind("Node", &node_proto).expect("must decode node with spec");

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

    /// decode_node_proto must not panic when NodeSpec contains taints (nested Taint messages).
    /// Guards against kubelet sending a full Node proto with complex nested spec fields.
    #[test]
    fn decode_node_proto_with_unknown_spec_fields_does_not_panic() {
        // Build: Node { metadata: ObjectMeta { name: "node-2" }, spec: NodeSpec { podCIDR: "10.0.0.0/24", taints: [Taint{effect:"NoSchedule"}] } }
        let obj_meta = encode_length_delimited(1, b"node-2"); // ObjectMeta.name
        let mut node_spec = Vec::new();
        node_spec.extend_from_slice(&encode_length_delimited(1, b"10.0.0.0/24")); // NodeSpec.podCIDR
                                                                                  // field 5 = taints (repeated Taint message); Taint.effect is field 3 (string)
        let taint_bytes = encode_length_delimited(3, b"NoSchedule"); // Taint { effect: "NoSchedule" }
        node_spec.extend_from_slice(&encode_length_delimited(5, &taint_bytes)); // NodeSpec.taints[0]

        let mut node_proto = encode_length_delimited(1, &obj_meta);
        node_proto.extend_from_slice(&encode_length_delimited(2, &node_spec));

        let result = decode_core_proto_by_kind("Node", &node_proto)
            .expect("gen path must handle valid Node proto with taint fields without panicking");

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
        let result = decode_core_proto_by_kind("Node", &node_proto)
            .expect("Node proto decoder must return Some even when unschedulable=true is present");

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
        // Reproduce what create_namespace returns after decoding the Namespace proto:
        let mut obj_meta = encode_length_delimited(1, b"smoke-test");
        obj_meta.extend_from_slice(&encode_length_delimited(8, &[])); // creationTimestamp (empty Time{})
        let namespace_proto = encode_length_delimited(1, &obj_meta);
        let mut ns_json = decode_core_proto_by_kind("Namespace", &namespace_proto)
            .expect("Namespace proto decode must succeed");
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

        let result = crate::coord_gen_adapter::decode_lease_proto_gen_a(&lease_proto)
            .expect("must decode Lease proto");

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

        let result = crate::coord_gen_adapter::decode_lease_proto_gen_a(&lease_proto)
            .expect("must decode Lease proto");

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

    /// Regression test for mayor-z7v0 and mayor-ttx3: MicroTime with seconds = -1 must
    /// decode to the real pre-1970 date (1969-12-31T23:59:59Z), not year 584554049254
    /// ("584554049254-11-09T...") and not be dropped entirely.
    ///
    /// Original root cause (mayor-z7v0): `t.seconds as u64` for negative i64 wraps to a huge
    /// u64 value (e.g. -1_i64 as u64 = u64::MAX ≈ 1.845×10^19), which `secs_to_rfc3339` then
    /// rendered as year ~584554049254. The interim fix dropped any non-positive seconds
    /// instead — but negative Unix seconds are a legitimate pre-1970 date (Lease conformance
    /// uses Go's zero-value time.Time{}, which is year 0001), so dropping them made every
    /// pre-1970 Lease acquire/renew time look never-acquired. mayor-ttx3 fixed the root cause:
    /// `secs_to_rfc3339`/`secs_nanos_to_rfc3339_micro` now take `i64` and use
    /// `div_euclid`/`rem_euclid` so negative seconds decode to the correct calendar date.
    ///
    /// This test fails if the u64 cast is reintroduced (year 584554049254) or if a
    /// `secs <= 0` guard is reintroduced (acquireTime/renewTime silently absent).
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

        let result = crate::coord_gen_adapter::decode_lease_proto_gen_a(&lease_proto)
            .expect("must decode Lease proto");

        assert_eq!(
            result["spec"]["renewTime"], "1969-12-31T23:59:59.000000Z",
            "renewTime with seconds=-1 must decode to the real pre-1970 instant, not \
             year-584554049254 (u64 wraparound) and not be dropped"
        );
        assert_eq!(
            result["spec"]["acquireTime"], "1969-12-31T23:59:59.000000Z",
            "acquireTime with seconds=-1 must decode to the real pre-1970 instant, not \
             year-584554049254 (u64 wraparound) and not be dropped"
        );
    }

    /// Lease.renewTime nanoseconds must be preserved in the decoded timestamp.
    ///
    /// The kubelet sends MicroTime (seconds + nanoseconds) on every heartbeat. If nanoseconds
    /// are silently discarded, the stored renewTime is second-level precision while the kubelet's
    /// in-memory value has sub-second precision. The lease conformance test compares the GET
    /// response renewTime against the value the kubelet PUT — if nanos are dropped the comparison
    /// fails because `2024-01-01T00:00:15.000000Z` != `2024-01-01T00:00:15.123456Z`.
    ///
    /// This test fails if secs_nanos_to_rfc3339_micro is reverted to normalize_rfc3339_to_micro
    /// (which zeroes out the fractional seconds, producing .000000 regardless of nanos).
    #[test]
    fn decode_lease_proto_preserves_renew_time_nanoseconds() {
        // Build: LeaseSpec { renewTime: MicroTime { seconds: 1704067215, nanos: 123456000 } }
        // 123456000 nanos = 123456 microseconds → .123456 in the formatted string.
        let mut obj_meta = encode_length_delimited(1, b"test-node");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"kube-node-lease"));

        // MicroTime for renewTime: field 1 (seconds, varint) + field 2 (nanos, varint)
        let mut renew_time_msg = encode_varint(1 << 3); // field 1, wire 0
        renew_time_msg.extend_from_slice(&encode_varint(1_704_067_215u64));
        // nanos field: tag = (2 << 3) | 0 = 0x10
        renew_time_msg.push(0x10);
        renew_time_msg.extend_from_slice(&encode_varint(123_456_000u64)); // 123456 µs

        // LeaseSpec { renewTime (field 4) }
        let lease_spec = encode_length_delimited(4, &renew_time_msg);

        let mut lease_proto = encode_length_delimited(1, &obj_meta);
        lease_proto.extend_from_slice(&encode_length_delimited(2, &lease_spec));

        let result = crate::coord_gen_adapter::decode_lease_proto_gen_a(&lease_proto)
            .expect("must decode Lease proto");

        assert_eq!(
            result["spec"]["renewTime"], "2024-01-01T00:00:15.123456Z",
            "renewTime must include microsecond precision from MicroTime.nanos; \
             if nanos are dropped the kubelet's heartbeat timestamp is rounded to \
             second precision and the lease conformance comparison fails"
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

        let result = crate::storage_node_flow_gen_adapter::decode_csinode_proto_gen(&csinode_proto)
            .expect("must decode CSINode proto");

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
    // Tests — decode_csidriver_proto
    // ---------------------------------------------------------------------------

    /// decode_csidriver_proto must extract metadata and spec fields.
    /// POST /apis/storage.k8s.io/v1/csidrivers from the typed Go client sends proto.
    /// Without this decoder the server returns 400 and CSI lifecycle conformance tests fail.
    #[test]
    fn decode_csidriver_proto_extracts_metadata_and_spec() {
        // Build: CSIDriver {
        //   metadata: ObjectMeta { name: "csi.example.com" },
        //   spec: CSIDriverSpec {
        //     attachRequired: false (field 1, varint 0),
        //     podInfoOnMount: true (field 2, varint 1),
        //     volumeLifecycleModes: ["Ephemeral"] (field 3, string),
        //   }
        // }
        let obj_meta = encode_length_delimited(1, b"csi.example.com");

        // attachRequired = false: field 1, wire type 0 (varint), value 0
        // podInfoOnMount = true: field 2, wire type 0 (varint), value 1
        let mut spec = vec![1u8 << 3, 0u8, 2u8 << 3, 1u8];
        // volumeLifecycleModes = ["Ephemeral"]: field 3, length-delimited
        spec.extend_from_slice(&encode_length_delimited(3, b"Ephemeral"));

        let mut csidriver_proto = encode_length_delimited(1, &obj_meta);
        csidriver_proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result =
            crate::storage_node_flow_gen_adapter::decode_csidriver_proto_gen(&csidriver_proto)
                .expect("must decode CSIDriver proto");

        assert_eq!(result["kind"], "CSIDriver");
        assert_eq!(result["apiVersion"], "storage.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "csi.example.com",
            "CSIDriver name must survive proto decode — used as the driver identifier in the cluster"
        );
        assert_eq!(
            result["spec"]["attachRequired"], false,
            "attachRequired must be decoded — scheduler uses it to decide attach/detach"
        );
        assert_eq!(
            result["spec"]["podInfoOnMount"], true,
            "podInfoOnMount must be decoded — kubelet uses it to pass pod info to the driver"
        );
        assert_eq!(
            result["spec"]["volumeLifecycleModes"][0], "Ephemeral",
            "volumeLifecycleModes must be decoded — required for CSI inline volume conformance test"
        );
    }

    /// decode_csidriver_proto_gen must decode spec.tokenRequests — a field that the old hand
    /// struct silently dropped because it was not declared.
    ///
    /// Without tokenRequests, a CSI driver that requires bound service-account tokens cannot be
    /// registered: the kubelet reads tokenRequests from the stored CSIDriver to know which
    /// audiences to request tokens for when mounting volumes. Silent drop means the field is
    /// missing on read-back even though the POST/PUT returned 200 OK.
    ///
    /// This test fails if tokenRequests handling is removed from decode_csidriver_proto_gen.
    #[test]
    fn decode_csidriver_proto_gen_decodes_tokenrequests_which_old_hand_struct_dropped() {
        // Build: CSIDriver {
        //   metadata: { name: "token-driver" },
        //   spec: CSIDriverSpec {
        //     tokenRequests: [TokenRequest { audience: "my-audience", expirationSeconds: 3600 }]
        //   }
        // }
        // CSIDriverSpec.tokenRequests = field 6 (repeated message TokenRequest)
        // TokenRequest: field 1=audience (string), field 2=expirationSeconds (int64 varint)
        let obj_meta = encode_length_delimited(1, b"token-driver");

        // TokenRequest { audience: "my-audience", expirationSeconds: 3600 }
        let mut token_request = encode_length_delimited(1, b"my-audience");
        // expirationSeconds = 3600: field 2, wire type 0 (varint)
        token_request.push(2 << 3); // field 2, wire type 0 (varint)
        token_request.extend_from_slice(&encode_varint(3600));

        // CSIDriverSpec: field 6 = repeated TokenRequest (length-delimited)
        let spec = encode_length_delimited(6, &token_request);

        let mut csidriver_proto = encode_length_delimited(1, &obj_meta);
        csidriver_proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result =
            crate::storage_node_flow_gen_adapter::decode_csidriver_proto_gen(&csidriver_proto)
                .expect("must decode CSIDriver proto with tokenRequests");

        let token_requests = result["spec"]["tokenRequests"]
            .as_array()
            .expect("tokenRequests must be an array — old hand struct silently dropped this field");
        assert_eq!(
            token_requests.len(),
            1,
            "tokenRequests must have one entry — protobuf typegen migration now decodes this field"
        );
        assert_eq!(
            token_requests[0]["audience"], "my-audience",
            "tokenRequest.audience must survive proto decode — kubelet uses it to request the \
             correct service account token for CSI volume mounts"
        );
        assert_eq!(
            token_requests[0]["expirationSeconds"], 3600,
            "tokenRequest.expirationSeconds must survive proto decode — kubelet uses it to set \
             the token TTL"
        );
    }

    /// decode_proto_by_kind_and_version must dispatch to decode_csidriver_proto for kind="CSIDriver".
    #[test]
    fn decode_proto_by_kind_dispatches_csidriver() {
        let obj_meta = encode_length_delimited(1, b"driver.test.com");
        let csidriver_proto = encode_length_delimited(1, &obj_meta);

        let result = decode_proto_by_kind_and_version("CSIDriver", "", &csidriver_proto)
            .expect("CSIDriver must decode via decode_proto_by_kind_and_version");

        assert_eq!(
            result["kind"], "CSIDriver",
            "dispatch must route CSIDriver kind to decode_csidriver_proto — \
             without registration the server cannot decode proto POST bodies"
        );
        assert_eq!(result["metadata"]["name"], "driver.test.com");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_csistoragecapacity_proto
    // ---------------------------------------------------------------------------

    /// decode_csistoragecapacity_proto must extract metadata, storageClassName and capacity.
    /// The CSIStorageCapacity controller POSTs/PATCHes capacity objects with proto encoding.
    /// Without this decoder the server returns 400 and capacity-aware scheduling is broken.
    #[test]
    fn decode_csistoragecapacity_proto_extracts_metadata_and_fields() {
        // Build: CSIStorageCapacity {
        //   metadata: ObjectMeta { name: "csisc-abc", namespace: "kube-system" },
        //   storageClassName: "fast-ssd" (field 3, string),
        //   capacity: Quantity { string: "100Gi" } (field 4, message),
        // }
        let mut obj_meta = encode_length_delimited(1, b"csisc-abc");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"kube-system"));

        // Quantity.string = "100Gi": field 1, length-delimited
        let capacity_quantity = encode_length_delimited(1, b"100Gi");

        let mut csc_proto = encode_length_delimited(1, &obj_meta);
        csc_proto.extend_from_slice(&encode_length_delimited(3, b"fast-ssd"));
        csc_proto.extend_from_slice(&encode_length_delimited(4, &capacity_quantity));

        let result =
            crate::storage_node_flow_gen_adapter::decode_csistoragecapacity_proto_gen(&csc_proto)
                .expect("must decode CSIStorageCapacity proto");

        assert_eq!(result["kind"], "CSIStorageCapacity");
        assert_eq!(result["apiVersion"], "storage.k8s.io/v1");
        assert_eq!(
            result["metadata"]["name"], "csisc-abc",
            "CSIStorageCapacity name must survive proto decode"
        );
        assert_eq!(
            result["metadata"]["namespace"], "kube-system",
            "CSIStorageCapacity namespace must survive proto decode — it is a namespaced resource"
        );
        assert_eq!(
            result["storageClassName"], "fast-ssd",
            "storageClassName must be decoded — scheduler uses it to match capacity to StorageClass"
        );
        assert_eq!(
            result["capacity"], "100Gi",
            "capacity must be decoded — scheduler uses it to filter nodes with insufficient capacity"
        );
    }

    /// decode_proto_by_kind_and_version must dispatch to decode_csistoragecapacity_proto.
    #[test]
    fn decode_proto_by_kind_dispatches_csistoragecapacity() {
        let mut obj_meta = encode_length_delimited(1, b"csisc-xyz");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default"));
        let mut csc_proto = encode_length_delimited(1, &obj_meta);
        csc_proto.extend_from_slice(&encode_length_delimited(3, b"my-class"));

        let result = decode_proto_by_kind_and_version("CSIStorageCapacity", "", &csc_proto)
            .expect("CSIStorageCapacity must decode via dispatch");

        assert_eq!(
            result["kind"], "CSIStorageCapacity",
            "dispatch must route CSIStorageCapacity to its decoder — \
             without registration proto POST bodies return 400"
        );
        assert_eq!(result["storageClassName"], "my-class");
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

        let result =
            decode_core_proto_by_kind("Event", &event_proto).expect("must decode Event proto");

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

        let result = decode_core_proto_by_kind("Event", &event_proto)
            .expect("must decode Event proto with series");

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

        let result = decode_core_proto_by_kind("SubjectAccessReview", &sar_proto)
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

        let result = decode_core_proto_by_kind("TokenReview", &tr_proto).expect(
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
        use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        // Build the CronJob directly via prost structs so the encoding uses the correct
        // field numbers from the fixed JobSpec definition. The regression we guard against
        // is: if JobSpec.template is at tag=5 (wrong) instead of tag=6 (correct), prost
        // decodes the LEN field at tag=6 against `backoffLimit` (int32, wire type 0) and
        // returns DecodeError, making decode_cronjob_proto return None and the apiserver
        // return HTTP 400 "invalid JSON".
        let cj = batch_v1::CronJob {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("my-cj".to_string()),
                namespace: Some("cronjobtest".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::CronJobSpec {
                schedule: Some("*/1 * * * *".to_string()),
                job_template: Some(batch_v1::JobTemplateSpec {
                    metadata: None,
                    spec: Some(batch_v1::JobSpec {
                        // template at field 6 — if the field number were wrong (tag=5),
                        // prost would encode it at field 5 and then decode would succeed
                        // trivially (no cross-type mismatch). The regression only manifests
                        // when the struct has template at tag=5 and backoffLimit at tag=6,
                        // because kubectl puts template at wire field 6 (LEN type) which
                        // collides with the mislocated backoffLimit (int32, varint type).
                        template: Some(crate::apps_gen::k8s::io::api::core::v1::PodTemplateSpec {
                            metadata: None,
                            spec: None,
                        }),
                        backoff_limit: Some(3),
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

        let result = crate::batch_gen_adapter::decode_cronjob_proto_gen(&buf).expect(
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
        assert!(crate::batch_gen_adapter::decode_cronjob_proto_gen(&[0xff, 0xff, 0xff]).is_none());
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
        assert!(crate::batch_gen_adapter::decode_job_proto_gen(&[0xff, 0xff, 0xff]).is_none());
    }

    /// decode_job_proto must handle an indexed Job with completionMode=Indexed,
    /// backoffLimitPerIndex, maxFailedIndexes, and a podFailurePolicy message.
    ///
    /// The e2e conformance tests create Jobs with these fields (job.go:621, :658, :753).
    /// Without handling these fields, the prost decode fails and decode_job_proto returns None,
    /// causing 400 "invalid JSON" responses for all indexed Job creation requests.
    /// Also verifies podFailurePolicy survives the round-trip: dropped podFailurePolicy means
    /// the kcm job controller cannot honor failure rules, so pods that should be ignored or
    /// counted toward backoffLimit are handled with default behavior instead.
    #[test]
    fn decode_job_proto_handles_indexed_job_with_failure_policy() {
        use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let job = batch_v1::Job {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("indexed-job".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::JobSpec {
                completions: Some(5),
                parallelism: Some(2),
                backoff_limit: Some(6),
                completion_mode: Some("Indexed".to_string()),
                backoff_limit_per_index: Some(1),
                max_failed_indexes: Some(3),
                pod_failure_policy: Some(batch_v1::PodFailurePolicy {
                    rules: vec![batch_v1::PodFailurePolicyRule {
                        action: Some("Ignore".to_string()),
                        on_exit_codes: Some(batch_v1::PodFailurePolicyOnExitCodesRequirement {
                            operator: Some("In".to_string()),
                            values: vec![42],
                            container_name: None,
                        }),
                        on_pod_conditions: vec![],
                    }],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");

        let result = crate::batch_gen_adapter::decode_job_proto_gen(&buf).expect(
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
        assert_eq!(
            result["spec"]["podFailurePolicy"]["rules"][0]["action"], "Ignore",
            "podFailurePolicy dropped on proto decode → kcm job controller never sees failure rules → \
             pods that should be ignored count toward backoffLimit, conformance Job tests fail"
        );
        assert_eq!(
            result["spec"]["podFailurePolicy"]["rules"][0]["onExitCodes"]["operator"], "In",
            "podFailurePolicy.onExitCodes must survive round-trip so kcm can apply exit-code-based rules"
        );
        assert_eq!(
            result["spec"]["podFailurePolicy"]["rules"][0]["onExitCodes"]["values"][0],
            42,
        );
    }

    /// decode_job_proto must handle a Job with successPolicy — conformance test job.go:502 and
    /// job.go:582 create Jobs with successPolicy (k8s 1.30+ field at proto field 16).
    /// successPolicy dropped → kcm job controller never sees it → Job never reaches its
    /// terminal condition via success criteria, conformance test hangs until timeout.
    #[test]
    fn decode_job_proto_handles_job_with_success_policy() {
        use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let job = batch_v1::Job {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("success-policy-job".to_string()),
                namespace: Some("test-ns".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::JobSpec {
                completions: Some(3),
                completion_mode: Some("Indexed".to_string()),
                success_policy: Some(batch_v1::SuccessPolicy {
                    rules: vec![batch_v1::SuccessPolicyRule {
                        succeeded_indexes: Some("0-1".to_string()),
                        succeeded_count: Some(2),
                    }],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");

        let result = crate::batch_gen_adapter::decode_job_proto_gen(&buf).expect(
            "decode_job_proto must return Some for Job with successPolicy — conformance tests at \
             job.go:502 and job.go:582 fail with 400 'invalid JSON' when this field is present",
        );

        assert_eq!(result["kind"], "Job");
        assert_eq!(result["metadata"]["name"], "success-policy-job");
        assert_eq!(result["spec"]["completionMode"], "Indexed");
        assert_eq!(result["spec"]["completions"], 3);
        assert_eq!(
            result["spec"]["successPolicy"]["rules"][0]["succeededIndexes"], "0-1",
            "successPolicy dropped on proto decode → kcm job controller never sees it → \
             Job never reaches its terminal condition, conformance test hangs 5min"
        );
        assert_eq!(
            result["spec"]["successPolicy"]["rules"][0]["succeededCount"], 2,
            "successPolicy.succeededCount must survive round-trip so kcm can evaluate success criteria"
        );
    }

    /// decode_job_proto must preserve backoffLimitPerIndex=0 and maxFailedIndexes=0.
    /// Proto3 zero-value suppression would drop these (both are valid user-supplied zeroes):
    /// backoffLimitPerIndex=0 means "no retries per index"; maxFailedIndexes=0 means
    /// "fail immediately when any index fails". Losing either changes Job failure semantics.
    #[test]
    fn decode_job_proto_preserves_zero_valued_per_index_limits() {
        use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let job = batch_v1::Job {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("zero-limits-job".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::JobSpec {
                completions: Some(4),
                completion_mode: Some("Indexed".to_string()),
                backoff_limit_per_index: Some(0),
                max_failed_indexes: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");

        let result = crate::batch_gen_adapter::decode_job_proto_gen(&buf)
            .expect("zero-valued per-index limits must decode");

        assert_eq!(
            result["spec"]["backoffLimitPerIndex"], 0,
            "backoffLimitPerIndex=0 must be preserved; losing it changes Job failure semantics \
             (0 means no retries per index, not 'field absent')"
        );
        assert_eq!(
            result["spec"]["maxFailedIndexes"], 0,
            "maxFailedIndexes=0 must be preserved; losing it changes Job failure semantics \
             (0 means fail immediately when any index fails, not 'field absent')"
        );
    }

    /// decode_job_proto must preserve spec.template.spec.containers from the proto body.
    ///
    /// Before this fix, job_spec_to_json stored `template` as an empty `{}` object,
    /// discarding containers. KCM then created Job pods with `containers: null` (because
    /// the job template had no containers), preventing pods from ever reaching Running phase
    /// and causing `[sig-apps] Job should delete a job [Conformance]` to time out.
    #[test]
    fn decode_job_proto_preserves_template_containers() {
        use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
        use crate::apps_gen::k8s::io::api::core::v1 as core_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let job = batch_v1::Job {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("pi".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::JobSpec {
                completions: Some(1),
                template: Some(core_v1::PodTemplateSpec {
                    metadata: None,
                    spec: Some(core_v1::PodSpec {
                        containers: vec![core_v1::Container {
                            name: Some("pi".to_string()),
                            image: Some("perl:5.34".to_string()),
                            ..Default::default()
                        }],
                        restart_policy: Some("Never".to_string()),
                        ..Default::default()
                    }),
                }),
                backoff_limit: Some(4),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");

        let result = crate::batch_gen_adapter::decode_job_proto_gen(&buf).expect(
            "decode_job_proto must return Some for Job with template containing containers — \
             if None is returned, Job creation via proto fails with 400",
        );

        assert_eq!(result["kind"], "Job");
        assert_eq!(result["metadata"]["name"], "pi");
        assert!(
            result["spec"]["template"]["spec"]["containers"].is_array(),
            "spec.template.spec.containers must be an array — if this is null/absent, \
             KCM creates Job pods with containers:null and pods can never reach Running phase, \
             causing [sig-apps] Job should delete a job [Conformance] to time out"
        );
        let containers = result["spec"]["template"]["spec"]["containers"]
            .as_array()
            .unwrap();
        assert_eq!(
            containers.len(),
            1,
            "one container must survive proto decode — KCM uses this to create pod specs"
        );
        assert_eq!(
            containers[0]["name"], "pi",
            "container name must be preserved — KCM uses container names to construct pod specs"
        );
        assert_eq!(
            containers[0]["image"], "perl:5.34",
            "container image must be preserved — without it pods run nothing"
        );
        assert_eq!(
            result["spec"]["template"]["spec"]["restartPolicy"], "Never",
            "restartPolicy must be preserved from the template spec"
        );
    }

    /// decode_job_proto must preserve ownerReferences from the proto ObjectMeta.
    ///
    /// KCM's cronjob-controller creates Jobs with ownerReferences pointing to the CronJob.
    /// Before this fix, object_meta_to_json silently dropped ownerReferences, so the stored
    /// Job had no ownerReferences, and the CronJob→Jobs cascade could not match Jobs to their
    /// CronJob owner — causing the GC conformance spec "should delete jobs and pods created by
    /// cronjob" to fail (the cascade enumerated Jobs but found none owned by the deleted CronJob).
    #[test]
    fn decode_job_proto_preserves_owner_references() {
        use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let cj_uid = "cj-uid-1234-5678-abcd";

        let job = batch_v1::Job {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("my-cj-job".to_string()),
                namespace: Some("default".to_string()),
                uid: Some("job-uid-abcd".to_string()),
                owner_references: vec![gen_meta_v1::OwnerReference {
                    kind: Some("CronJob".to_string()),
                    name: Some("my-cj".to_string()),
                    uid: Some(cj_uid.to_string()),
                    api_version: Some("batch/v1".to_string()),
                    controller: Some(true),
                    block_owner_deletion: Some(true),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("Job encode must succeed");

        let result = crate::batch_gen_adapter::decode_job_proto_gen(&buf)
            .expect("decode_job_proto must return Some for Job with ownerReferences");

        let refs = result["metadata"]["ownerReferences"].as_array().expect(
            "ownerReferences must be present in decoded Job — without this, the \
                 CronJob->Jobs cascade in delete_namespaced_resource cannot match Jobs to their \
                 CronJob owner and the GC conformance spec fails",
        );
        assert_eq!(
            refs.len(),
            1,
            "one ownerReference must survive proto decode"
        );
        assert_eq!(
            refs[0]["kind"], "CronJob",
            "ownerReference kind must be CronJob — this is how the cascade identifies owned Jobs"
        );
        assert_eq!(
            refs[0]["uid"], cj_uid,
            "ownerReference uid must match the CronJob UID — the cascade checks uid equality"
        );
        assert_eq!(
            refs[0]["apiVersion"], "batch/v1",
            "ownerReference apiVersion must be preserved"
        );
        assert_eq!(
            refs[0]["name"], "my-cj",
            "ownerReference name must be preserved"
        );
        assert_eq!(
            refs[0]["controller"], true,
            "controller field must be preserved from ownerReference"
        );
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

        let result = decode_core_proto_by_kind("Service", &svc_proto)
            .expect("Service with targetPort must decode");
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

        let result = decode_core_proto_by_kind("Service", &svc_proto)
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

    /// decode_runtimeclass_proto must decode overhead.podFixed so that
    /// apply_runtime_class_overhead can inject it into pod.spec.overhead at create time.
    ///
    /// Conformance test '[sig-node] RuntimeClass should schedule a Pod requesting a RuntimeClass
    /// and initialize its Overhead' creates a RuntimeClass via proto, then creates a pod using
    /// it and asserts pod.spec.overhead.cpu == 10m. Without overhead decode, the stored RC has
    /// no overhead field, so apply_runtime_class_overhead is a no-op and the test fails with
    /// "Expected {value:0} to equal {value:10 scale:-3}".
    #[test]
    fn decode_runtimeclass_proto_includes_overhead_pod_fixed_so_pod_overhead_injection_works() {
        // Build: RuntimeClass {
        //   metadata: { name: "test-rc" },
        //   handler: "test-rc",
        //   overhead: Overhead { podFixed: {"cpu": Quantity{string: "10m"}} }
        // }
        let encode_quantity = |s: &[u8]| -> Vec<u8> { encode_length_delimited(1, s) };
        let encode_map_entry = |key: &[u8], val_bytes: &[u8]| -> Vec<u8> {
            let mut entry = encode_length_delimited(1, key);
            entry.extend_from_slice(&encode_length_delimited(2, val_bytes));
            entry
        };

        // Overhead { podFixed: {"cpu": "10m"} }  — field 1 = podFixed map entry
        let cpu_entry = encode_map_entry(b"cpu", &encode_quantity(b"10m"));
        let overhead_bytes = encode_length_delimited(1, &cpu_entry);

        let obj_meta = encode_length_delimited(1, b"test-rc");
        let handler = encode_length_delimited(2, b"test-rc");
        let mut rc_proto = encode_length_delimited(1, &obj_meta);
        rc_proto.extend_from_slice(&handler);
        rc_proto.extend_from_slice(&encode_length_delimited(3, &overhead_bytes)); // field 3 = overhead

        let result = decode_core_proto_by_kind("RuntimeClass", &rc_proto).expect(
            "RuntimeClass with overhead must decode — conformance creates RuntimeClass via proto \
             and expects overhead to be present in the stored object",
        );

        assert_eq!(
            result["overhead"]["podFixed"]["cpu"], "10m",
            "overhead.podFixed.cpu must survive proto decode so apply_runtime_class_overhead \
             can inject it into pod.spec.overhead at pod create time"
        );
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

    /// decode_resourcequota_proto must decode spec.scopes so KCM scope-filters pod usage correctly.
    ///
    /// When a ResourceQuota is created with spec.scopes (e.g. ["Terminating"]) via proto encoding
    /// (as the e2e test binary does via client-go), the scopes field must survive decoding.
    /// Without it, KCM's quota controller sees a scope-less quota and counts ALL pods against it,
    /// causing a Terminating-scoped quota to show pods="1" when a non-terminating pod exists.
    /// The conformance test "should verify ResourceQuota with terminating scopes" then fails
    /// because it expects the terminating-scope quota's used.pods to remain "0".
    /// This test must fail if spec.scopes decoding is removed.
    #[test]
    fn decode_resourcequota_proto_extracts_spec_scopes() {
        // Build the proto bytes for:
        //   ResourceQuota {
        //     metadata: ObjectMeta { name: "terminating-quota", namespace: "default" },
        //     spec: ResourceQuotaSpec {
        //       hard: {"pods": Quantity{string: "5"}},
        //       scopes: ["Terminating"]
        //     }
        //   }

        let encode_quantity = |s: &[u8]| -> Vec<u8> { encode_length_delimited(1, s) };

        let encode_map_entry = |key: &[u8], val_bytes: &[u8]| -> Vec<u8> {
            let mut entry = encode_length_delimited(1, key);
            entry.extend_from_slice(&encode_length_delimited(2, val_bytes));
            entry
        };

        // ResourceQuotaSpec { hard: {"pods": Quantity{string: "5"}}, scopes: ["Terminating"] }
        let pods_entry = encode_map_entry(b"pods", &encode_quantity(b"5"));
        let mut spec_bytes = encode_length_delimited(1, &pods_entry); // field 1 = hard
        spec_bytes.extend_from_slice(&encode_length_delimited(2, b"Terminating")); // field 2 = scopes[0]

        // ResourceQuota { metadata, spec }
        let mut meta_bytes = encode_length_delimited(1, b"terminating-quota"); // name
        meta_bytes.extend_from_slice(&encode_length_delimited(3, b"default")); // namespace
        let mut proto = encode_length_delimited(1, &meta_bytes); // field 1 = metadata
        proto.extend_from_slice(&encode_length_delimited(2, &spec_bytes)); // field 2 = spec

        let result = decode_core_proto_by_kind("ResourceQuota", &proto)
            .expect("ResourceQuota with spec.scopes must decode successfully");

        assert_eq!(result["kind"], "ResourceQuota");
        assert_eq!(result["metadata"]["name"], "terminating-quota");
        assert_eq!(result["spec"]["hard"]["pods"], "5");
        assert_eq!(
            result["spec"]["scopes"],
            serde_json::json!(["Terminating"]),
            "spec.scopes must be decoded from proto field 2 — without it KCM sees a scope-less \
             quota and counts non-terminating pods against Terminating-scoped quotas, causing the \
             conformance test 'verify ResourceQuota with terminating scopes' to fail"
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

    /// decode_poddisruptionbudget_proto must preserve status.disruptedPods from a proto
    /// /status write body.
    ///
    /// The DisruptionController sends proto-encoded PUT or PATCH /poddisruptionbudgets/*/status
    /// bodies with status.disruptedPods to record which pods are being disrupted and when
    /// disruption was allowed.  Without decoding status (field 3) and disruptedPods (field 2 of
    /// PodDisruptionBudgetStatus), the put_namespaced_resource_status handler receives an incoming
    /// object where status is null, then REMOVES status from the stored PDB, so disruptedPods
    /// disappears on read-back.
    ///
    /// The conformance spec '[sig-apps] DisruptionController should update/patch PodDisruptionBudget
    /// status [Conformance]' fails with `<map[string]v1.Time | len:0>: nil, expected key 'pod-0'`
    /// when this decode path is missing.
    ///
    /// This test fails if `PodDisruptionBudgetStatus` or `disrupted_pods` is removed from the
    /// proto struct, or if the status serialization block is removed from
    /// `decode_poddisruptionbudget_proto`.
    #[test]
    fn decode_poddisruptionbudget_proto_preserves_status_disrupted_pods() {
        use crate::net_disc_cert_policy_events_gen::k8s::io::api::policy::v1 as gen_policy_v1;
        use crate::net_disc_cert_policy_events_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let pdb = gen_policy_v1::PodDisruptionBudget {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("status-pdb".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(gen_policy_v1::PodDisruptionBudgetStatus {
                observed_generation: Some(1),
                disrupted_pods: {
                    let mut m = std::collections::HashMap::new();
                    m.insert(
                        "pod-0".to_string(),
                        gen_meta_v1::Time {
                            seconds: Some(1_700_000_000),
                            nanos: Some(0),
                        },
                    );
                    m
                },
                disruptions_allowed: Some(2),
                current_healthy: Some(3),
                desired_healthy: Some(2),
                expected_pods: Some(3),
                conditions: vec![],
            }),
        };

        let mut buf = Vec::new();
        pdb.encode(&mut buf).expect("prost encode must succeed");

        let result =
            crate::net_disc_cert_policy_events_gen_adapter::decode_poddisruptionbudget_proto_gen(
                &buf,
            )
            .expect(
                "decode_poddisruptionbudget_proto must return Some for a proto /status body — \
             the DisruptionController sends proto-encoded PUT /status writes",
            );

        assert_eq!(result["kind"], "PodDisruptionBudget");
        assert_eq!(result["metadata"]["name"], "status-pdb");

        assert!(
            result["status"].is_object(),
            "status must be present after proto decode — without it, the /status handler \
             receives null status and wipes status from the stored PDB"
        );

        let disrupted_pods = result["status"]["disruptedPods"].as_object().expect(
            "status.disruptedPods must survive proto decode — the DisruptionController \
             conformance test '[sig-apps] DisruptionController should update/patch \
             PodDisruptionBudget status' fails with `len:0` when this field is lost",
        );
        assert!(
            disrupted_pods.contains_key("pod-0"),
            "pod-0 must be in disruptedPods — the conformance test writes pod-0 and reads \
             it back; if it is missing the test fails with `expected key 'pod-0'`"
        );

        assert_eq!(
            result["status"]["disruptionsAllowed"], 2,
            "disruptionsAllowed must survive proto decode"
        );
        assert_eq!(
            result["status"]["currentHealthy"], 3,
            "currentHealthy must survive proto decode"
        );
        assert_eq!(
            result["status"]["desiredHealthy"], 2,
            "desiredHealthy must survive proto decode"
        );
        assert_eq!(
            result["status"]["expectedPods"], 3,
            "expectedPods must survive proto decode"
        );
    }

    /// decode_poddisruptionbudget_proto must decode spec.selector and spec.minAvailable from a
    /// proto-encoded PDB create body.
    ///
    /// The e2e client (and client-go generally) sends PDB creates protobuf-encoded. The KCM
    /// disruption controller reads spec.selector to find the pods a PDB covers. If the apiserver
    /// drops spec on decode, the stored PDB has no selector, so getPdbForPod matches nothing, the
    /// controller computes expectedPods=0, and buildDisruptedPodMap clears status.disruptedPods.
    ///
    /// The conformance spec '[sig-apps] DisruptionController should update/patch PodDisruptionBudget
    /// status' then fails: the test writes disruptedPods={pod-0} and reads it back empty
    /// (`<map[string]v1.Time | len:0>: nil, expected key 'pod-0'`), because the controller wiped it.
    ///
    /// This test fails if `spec` is decoded as opaque bytes (the old behavior) or if the spec
    /// serialization block is removed from `decode_poddisruptionbudget_proto`.
    #[test]
    fn decode_poddisruptionbudget_proto_preserves_spec_selector() {
        // spec.selector.matchLabels = {"foo": "bar"} — LabelSelector.matchLabels is field 1
        // (map<string,string>); each map entry is key (field 1) + value (field 2).
        let mut label_entry = encode_length_delimited(1, b"foo"); // key
        label_entry.extend_from_slice(&encode_length_delimited(2, b"bar")); // value
        let selector_bytes = encode_length_delimited(1, &label_entry);

        // spec.minAvailable = 1 — IntOrString{type=0 (Int), intVal=1}; both are varint fields
        // (tag (field<<3)|0), NOT length-delimited.
        let int_or_string_bytes = vec![0x08, 0x00, 0x10, 0x01];

        // PodDisruptionBudgetSpec{ minAvailable: field 1, selector: field 2 }
        let mut spec_bytes = encode_length_delimited(1, &int_or_string_bytes);
        spec_bytes.extend_from_slice(&encode_length_delimited(2, &selector_bytes));

        // PodDisruptionBudget{ metadata: field 1, spec: field 2 } — ObjectMeta name=field 1.
        let meta_bytes = encode_length_delimited(1, b"foo");
        let mut pdb_bytes = encode_length_delimited(1, &meta_bytes);
        pdb_bytes.extend_from_slice(&encode_length_delimited(2, &spec_bytes));

        let result =
            crate::net_disc_cert_policy_events_gen_adapter::decode_poddisruptionbudget_proto_gen(
                &pdb_bytes,
            )
            .expect("decode_poddisruptionbudget_proto must return Some for a proto create body");

        assert_eq!(
            result["spec"]["selector"]["matchLabels"]["foo"], "bar",
            "spec.selector.matchLabels must survive proto decode — without it the KCM disruption \
             controller matches no pods (expectedPods=0) and wipes disruptedPods, failing the \
             conformance spec 'DisruptionController should update/patch PodDisruptionBudget status'"
        );
        assert_eq!(
            result["spec"]["minAvailable"], 1,
            "spec.minAvailable must survive proto decode — the disruption controller uses it to \
             compute desiredHealthy/expectedPods"
        );
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

        let result =
            crate::admissionreg_gen_adapter::decode_validatingwebhookconfiguration_proto_gen(
                &proto,
            )
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

        let result =
            crate::admissionreg_gen_adapter::decode_mutatingwebhookconfiguration_proto_gen(&proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
            .expect("Pod proto must decode");
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

        let result =
            decode_core_proto_by_kind("Service", &svc_proto).expect("Service proto must decode");

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

        let result = decode_core_proto_by_kind("PersistentVolume", &pv_proto)
            .expect("PersistentVolume proto must decode");

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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = decode_core_proto_by_kind("Deployment", &deployment_proto);
        assert!(
            result.is_some(),
            "Deployment proto decoder must succeed when a VolumeMount has readOnly=true (field 2, \
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

    /// spec.volumes[].secret.defaultMode must survive proto decode and appear in decoded JSON.
    ///
    /// The kubelet applies defaultMode as the permission bits for all files in the mounted
    /// secret volume. If defaultMode is dropped, the kubelet falls back to 0644, so a pod
    /// requesting 0400 (read-only) gets 0644 files — the conformance test
    /// "should be consumable from pods in volume with defaultMode set" then fails because
    /// the actual file mode does not match what the pod spec requested.
    ///
    /// This test fails if SecretVolumeSource.default_mode (field 3) is removed from the
    /// prost struct or the defaultMode emit block in pod_spec_to_json is removed.
    #[test]
    fn decode_pod_proto_preserves_secret_volume_default_mode() {
        // SecretVolumeSource { secretName (field 1) = "my-secret", defaultMode (field 3) = 256 }
        // 256 decimal = 0o400 octal (read-only by owner) — same value the conformance test uses.
        let mut secret_vol_src = encode_length_delimited(1, b"my-secret");
        // field 3 (defaultMode), wire type 0 (varint): tag = (3 << 3) | 0 = 0x18
        secret_vol_src.push(0x18);
        secret_vol_src.extend_from_slice(&encode_varint(256));

        // VolumeSource { secret (field 6) = SecretVolumeSource }
        let volume_source = encode_length_delimited(6, &secret_vol_src);

        // Volume { name (field 1) = "sec-vol", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"sec-vol");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
            .expect("decode_pod_proto must succeed with a secret volume with defaultMode");

        let volumes = result["spec"]["volumes"]
            .as_array()
            .expect("spec.volumes must be present");
        assert_eq!(
            volumes[0]["secret"]["defaultMode"], 256,
            "secret.defaultMode must be 256 (0o400); if dropped the kubelet uses 0644 instead \
             of the requested mode, causing the conformance test \
             'should be consumable from pods in volume with defaultMode set' to fail"
        );
    }

    /// spec.volumes[].configMap.defaultMode must survive proto decode and appear in decoded JSON.
    ///
    /// Same bug class as SecretVolumeSource.defaultMode: the kubelet applies defaultMode to all
    /// files in the mounted configMap volume. If dropped, files get 0644 instead of the
    /// requested mode, and the conformance test fails.
    ///
    /// This test fails if ConfigMapVolumeSource.default_mode (field 3) is removed from the
    /// prost struct or the defaultMode emit block in pod_spec_to_json is removed.
    #[test]
    fn decode_pod_proto_preserves_configmap_volume_default_mode() {
        // ConfigMapVolumeSource {
        //   localObjectReference (field 1) = { name (field 1) = "my-cm" },
        //   defaultMode (field 3) = 256  (0o400)
        // }
        let local_ref = encode_length_delimited(1, b"my-cm");
        let mut cm_vol_src = encode_length_delimited(1, &local_ref);
        // field 3 (defaultMode), wire type 0: tag = (3 << 3) | 0 = 0x18
        cm_vol_src.push(0x18);
        cm_vol_src.extend_from_slice(&encode_varint(256));

        // VolumeSource { configMap (field 19) = ConfigMapVolumeSource }
        let volume_source = encode_length_delimited(19, &cm_vol_src);

        // Volume { name (field 1) = "cm-vol", volumeSource (field 2) = VolumeSource }
        let mut volume = encode_length_delimited(1, b"cm-vol");
        volume.extend_from_slice(&encode_length_delimited(2, &volume_source));

        // PodSpec { volumes (field 1), containers (field 2) }
        let container = encode_length_delimited(1, b"app");
        let mut podspec = encode_length_delimited(1, &volume);
        podspec.extend_from_slice(&encode_length_delimited(2, &container));

        // Pod { metadata (field 1), spec (field 2) }
        let obj_meta = encode_length_delimited(1, b"test-pod");
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &podspec));

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
            .expect("decode_pod_proto must succeed with a configMap volume with defaultMode");

        let volumes = result["spec"]["volumes"]
            .as_array()
            .expect("spec.volumes must be present");
        assert_eq!(
            volumes[0]["configMap"]["defaultMode"], 256,
            "configMap.defaultMode must be 256 (0o400); if dropped the kubelet uses 0644 instead \
             of the requested mode, causing the conformance test \
             'should be consumable from pods in volume with defaultMode set' to fail"
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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
        assert!(
            crate::net_disc_cert_policy_events_gen_adapter::decode_ingressclass_proto_gen(&[
                0xff, 0xff, 0xff
            ])
            .is_none()
        );
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

        // IngressSpec (networking.k8s.io/v1/generated.proto):
        //   field 1 = defaultBackend, field 2 = tls, field 3 = rules, field 4 = ingressClassName
        // IngressRule: field 1 = host (string)
        let rule = encode_length_delimited(1, b"example.com"); // IngressRule: field 1 = host

        let mut spec_proto = encode_length_delimited(4, b"nginx"); // field 4 = ingressClassName
        spec_proto.extend_from_slice(&encode_length_delimited(3, &rule)); // field 3 = rules

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

        // IngressBackend (networking.k8s.io/v1/generated.proto): field 4 = service
        let backend = encode_length_delimited(4, &svc_backend);

        // IngressSpec (networking.k8s.io/v1/generated.proto): field 1 = defaultBackend
        let spec = encode_length_delimited(1, &backend);

        // Ingress: field 1 = ObjectMeta (minimal), field 2 = spec
        let obj_meta = encode_length_delimited(1, b"backend-ingress");
        let mut ingress_proto = encode_length_delimited(1, &obj_meta);
        ingress_proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result = crate::net_disc_cert_policy_events_gen_adapter::decode_ingress_proto_gen(
            &ingress_proto,
        )
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
    // Tests — decode_proto_by_kind_and_version IPAddress / ServiceCIDR
    // ---------------------------------------------------------------------------

    /// decode_proto_by_kind_and_version must dispatch IPAddress proto. Before adding this
    /// dispatch arm, the "IPAddress" kind had no decoder, so extract_body fell through to
    /// raw bytes and serde_json failed with "invalid JSON: expected value at line 1 column
    /// 1" — every typed-client Create() got 400 instead of 201.
    #[test]
    fn decode_proto_by_kind_and_version_dispatches_ipaddress() {
        let obj_meta = encode_length_delimited(1, b"192.168.1.5"); // ObjectMeta.name

        // ParentReference (networking.k8s.io/v1/generated.proto): field 2 = resource, field 4 = name
        let mut parent_ref = encode_length_delimited(2, b"services");
        parent_ref.extend_from_slice(&encode_length_delimited(4, b"my-svc"));

        // IPAddressSpec: field 1 = parentRef
        let spec = encode_length_delimited(1, &parent_ref);

        // IPAddress: field 1 = metadata, field 2 = spec
        let mut ip_proto = encode_length_delimited(1, &obj_meta);
        ip_proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result =
            decode_proto_by_kind_and_version("IPAddress", "networking.k8s.io/v1", &ip_proto)
                .expect(
                    "IPAddress must decode via decode_proto_by_kind_and_version — without this, \
                 client-go POST returns 400 on IPAddress create",
                );

        assert_eq!(result["kind"], "IPAddress");
        assert_eq!(result["metadata"]["name"], "192.168.1.5");
        assert_eq!(
            result["spec"]["parentRef"]["resource"], "services",
            "spec.parentRef.resource must survive dispatch decode"
        );
    }

    /// decode_proto_by_kind_and_version must dispatch ServiceCIDR proto — same root cause
    /// as IPAddress: no dispatch arm meant every protobuf Create() returned 400.
    #[test]
    fn decode_proto_by_kind_and_version_dispatches_servicecidr() {
        let obj_meta = encode_length_delimited(1, b"my-cidr"); // ObjectMeta.name

        // ServiceCIDRSpec: field 1 = cidrs (repeated string)
        let spec = encode_length_delimited(1, b"10.0.0.0/24");

        // ServiceCIDR: field 1 = metadata, field 2 = spec
        let mut cidr_proto = encode_length_delimited(1, &obj_meta);
        cidr_proto.extend_from_slice(&encode_length_delimited(2, &spec));

        let result =
            decode_proto_by_kind_and_version("ServiceCIDR", "networking.k8s.io/v1", &cidr_proto)
                .expect(
                    "ServiceCIDR must decode via decode_proto_by_kind_and_version — without \
                     this, client-go POST returns 400 on ServiceCIDR create",
                );

        assert_eq!(result["kind"], "ServiceCIDR");
        assert_eq!(result["metadata"]["name"], "my-cidr");
        assert_eq!(
            result["spec"]["cidrs"][0], "10.0.0.0/24",
            "spec.cidrs must survive dispatch decode"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_endpointslice_proto / decode_proto_by_kind_and_version EndpointSlice
    // ---------------------------------------------------------------------------

    /// decode_proto_by_kind_and_version must dispatch EndpointSlice proto and extract
    /// addressType, endpoints, and ports. Without this decoder, client-go POSTing an
    /// EndpointSlice with Content-Type: application/vnd.kubernetes.protobuf gets 400.
    ///
    /// Field layout per discovery.k8s.io/v1/generated.proto:
    ///   EndpointSlice: field 1=metadata, field 2=endpoints, field 3=ports, field 4=addressType
    #[test]
    fn decode_proto_by_kind_and_version_dispatches_endpointslice() {
        let obj_meta = encode_length_delimited(1, b"test-slice"); // ObjectMeta.name

        // DiscoveryEndpoint: field 1 = addresses (repeated string)
        let ep_addr = encode_length_delimited(1, b"10.0.0.1");
        let endpoint = encode_length_delimited(2, &ep_addr); // field 2 = endpoints

        // DiscoveryEndpointPort: field 1 = name, field 2 = protocol, field 3 = port (varint)
        let mut port_proto = encode_length_delimited(1, b"http");
        port_proto.extend_from_slice(&encode_length_delimited(2, b"TCP"));
        port_proto.push(0x18); // tag: field 3, wire type 0
        port_proto.extend_from_slice(&encode_varint(8080));

        let mut eps_proto = encode_length_delimited(1, &obj_meta);
        eps_proto.extend_from_slice(&endpoint);
        eps_proto.extend_from_slice(&encode_length_delimited(3, &port_proto)); // field 3 = ports
        eps_proto.extend_from_slice(&encode_length_delimited(4, b"IPv4")); // field 4 = addressType

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
    ///
    /// Field layout per discovery.k8s.io/v1/generated.proto:
    ///   EndpointSlice: field 1=metadata, field 2=endpoints, field 3=ports, field 4=addressType
    ///   Endpoint: field 1=addresses, field 2=conditions, field 3=hostname, field 4=targetRef,
    ///             field 5=deprecatedTopology (map), field 6=nodeName, field 7=zone, field 8=hints
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

        // EndpointSlice: field 1=metadata, field 2=endpoints, field 3=ports, field 4=addressType
        let mut eps_proto = encode_length_delimited(1, &obj_meta);
        eps_proto.extend_from_slice(&encode_length_delimited(2, &endpoint_content)); // endpoints[0]
        eps_proto.extend_from_slice(&encode_length_delimited(3, &port_content)); // ports[0]
        eps_proto.extend_from_slice(&encode_length_delimited(4, b"IPv4")); // addressType

        let result =
            crate::net_disc_cert_policy_events_gen_adapter::decode_endpointslice_proto_gen(
                &eps_proto,
            )
            .expect(
                "decode_endpointslice_proto must succeed for a valid EndpointSlice with \
                 conditions and port — if it returns None, the handler gets raw proto bytes \
                 and returns 400 'invalid JSON: expected value at line 1 column 1', \
                 failing the conformance test",
            );

        assert_eq!(result["kind"], "EndpointSlice");
        assert_eq!(result["apiVersion"], "discovery.k8s.io/v1");
        assert_eq!(
            result["addressType"], "IPv4",
            "addressType must be preserved — wrong field tag (2 vs 4) causes wrong field to be decoded"
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
            "conditions.ready must survive decode — EndpointSlice POST returns 400 if this field is dropped"
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

        // CertificateSigningRequestSpec (certificates.k8s.io/v1/generated.proto):
        //   field 1 = request (bytes), field 7 = signerName (string), field 5 = usages (repeated string)
        let fake_csr_bytes =
            b"-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----";
        let mut spec_proto = encode_length_delimited(1, fake_csr_bytes); // request bytes
        spec_proto.extend_from_slice(&encode_length_delimited(
            7,
            b"kubernetes.io/kube-apiserver-client",
        ));
        spec_proto.extend_from_slice(&encode_length_delimited(5, b"client auth")); // usages

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
    // By-construction tests: previously-dropped fields now decoded via generated structs
    // ---------------------------------------------------------------------------

    /// EndpointSlice endpoints[].hints.forZones was silently dropped by the hand decoder because
    /// EndpointHints was not represented in the hand struct. The generated decoder must preserve it
    /// so that topology-aware routing works (the kube-proxy reads hints to select zone-local endpoints).
    #[test]
    fn decode_endpointslice_hints_for_zones_previously_dropped_now_preserved() {
        // ForZone: field 1 = name (string)
        let for_zone = encode_length_delimited(1, b"us-east-1a");
        // EndpointHints: field 1 = forZones (repeated ForZone)
        let hints = encode_length_delimited(1, &for_zone);
        // Endpoint: field 1 = addresses, field 8 = hints
        let mut ep = encode_length_delimited(1, b"10.0.0.5");
        ep.extend_from_slice(&encode_length_delimited(8, &hints));
        // EndpointSlice: field 1 = metadata, field 2 = endpoints, field 4 = addressType
        let meta = encode_length_delimited(1, b"my-slice");
        let mut eps = encode_length_delimited(1, &meta);
        eps.extend_from_slice(&encode_length_delimited(2, &ep));
        eps.extend_from_slice(&encode_length_delimited(4, b"IPv4"));

        let result =
            crate::net_disc_cert_policy_events_gen_adapter::decode_endpointslice_proto_gen(&eps)
                .expect(
                "EndpointSlice with hints must decode — hints.forZones enables zone-local routing",
            );

        assert_eq!(
            result["endpoints"][0]["hints"]["forZones"][0]["name"], "us-east-1a",
            "hints.forZones[0].name must be preserved — kube-proxy uses this for topology-aware routing; \
             the hand decoder silently dropped all hints because EndpointHints was absent from the hand struct"
        );
    }

    /// PDB spec.unhealthyPodEvictionPolicy was absent from the hand decoder struct and therefore
    /// silently dropped. The generated decoder must preserve it so that eviction controllers can
    /// enforce the correct policy (AlwaysAllow vs IfHealthyBudget).
    #[test]
    fn decode_pdb_unhealthy_pod_eviction_policy_previously_dropped_now_preserved() {
        // PodDisruptionBudgetSpec: field 4 = unhealthyPodEvictionPolicy (string)
        let spec = encode_length_delimited(4, b"AlwaysAllow");
        // PodDisruptionBudget: field 1 = metadata, field 2 = spec
        let meta = encode_length_delimited(1, b"my-pdb");
        let mut pdb = encode_length_delimited(1, &meta);
        pdb.extend_from_slice(&encode_length_delimited(2, &spec));

        let result =
            crate::net_disc_cert_policy_events_gen_adapter::decode_poddisruptionbudget_proto_gen(
                &pdb,
            )
            .expect("PDB with unhealthyPodEvictionPolicy must decode");

        assert_eq!(
            result["spec"]["unhealthyPodEvictionPolicy"], "AlwaysAllow",
            "unhealthyPodEvictionPolicy must be preserved — eviction controllers route by this field; \
             the hand decoder silently dropped it because the field was absent from the hand struct"
        );
    }

    /// Ingress spec.ingressClassName was decoded from wrong proto field 1 (now correct field 4)
    /// by the hand decoder. The generated decoder uses the real upstream field number so
    /// the value survives encode/decode without silent corruption.
    #[test]
    fn decode_ingress_ingress_class_name_correct_field_number_now_preserved() {
        // IngressSpec: field 4 = ingressClassName (string) — real upstream field number
        let spec = encode_length_delimited(4, b"nginx");
        // Ingress: field 1 = metadata, field 2 = spec
        let meta = encode_length_delimited(1, b"my-ingress");
        let mut ingress = encode_length_delimited(1, &meta);
        ingress.extend_from_slice(&encode_length_delimited(2, &spec));

        let result =
            crate::net_disc_cert_policy_events_gen_adapter::decode_ingress_proto_gen(&ingress)
                .expect("Ingress with ingressClassName must decode");

        assert_eq!(
            result["spec"]["ingressClassName"], "nginx",
            "ingressClassName must survive decode at proto field 4 — the hand decoder used wrong \
             field 1, causing silent field corruption when real upstream protos encode it at field 4"
        );
    }

    /// CSR spec.expirationSeconds was missing from the hand decoder and therefore silently dropped.
    /// The generated decoder must preserve it so that short-lived certificates can be issued
    /// (the signer reads expirationSeconds to cap certificate lifetime).
    #[test]
    fn decode_csr_expiration_seconds_previously_dropped_now_preserved() {
        // CertificateSigningRequestSpec: field 1 = request, field 7 = signerName, field 8 = expirationSeconds
        let mut spec = encode_length_delimited(1, b"fakecertrequest");
        spec.extend_from_slice(&encode_length_delimited(
            7,
            b"kubernetes.io/kube-apiserver-client",
        ));
        // expirationSeconds = 3600: tag = (8 << 3) | 0 = 0x40; varint 3600 = 0xB0, 0x1C
        spec.push(0x40); // field 8, wire type 0
        spec.extend_from_slice(&encode_varint(3600));

        // CertificateSigningRequest: field 1 = metadata, field 2 = spec
        let meta = encode_length_delimited(1, b"my-csr");
        let mut csr = encode_length_delimited(1, &meta);
        csr.extend_from_slice(&encode_length_delimited(2, &spec));

        let result = crate::net_disc_cert_policy_events_gen_adapter::decode_csr_proto_gen(&csr)
            .expect("CSR with expirationSeconds must decode");

        assert_eq!(
            result["spec"]["expirationSeconds"], 3600,
            "expirationSeconds must be preserved — signers use this to cap certificate lifetime; \
             the hand decoder silently dropped it because the field was absent from the hand struct"
        );
    }

    /// CSR status.conditions and status.certificate were entirely absent from
    /// decode_csr_proto_gen — the decoder only read metadata and spec. The sig-auth
    /// "CSR API operations" conformance test PUTs/PATCHes the /approval and /status
    /// subresources with a protobuf-encoded body (client-go's default content-type for
    /// built-in types); with status dropped, the approver's and signer's writes were
    /// silently discarded and the object round-tripped with its *old* conditions.
    #[test]
    fn decode_csr_status_conditions_previously_dropped_now_preserved() {
        // CertificateSigningRequestCondition: field 1 = type, field 6 = status, field 2 = reason
        let mut cond = encode_length_delimited(1, b"Approved");
        cond.extend_from_slice(&encode_length_delimited(6, b"True"));
        cond.extend_from_slice(&encode_length_delimited(2, b"KubectlApprove"));

        // CertificateSigningRequestStatus: field 1 = conditions (repeated), field 2 = certificate (bytes)
        let mut status = encode_length_delimited(1, &cond);
        status.extend_from_slice(&encode_length_delimited(2, b"fake-cert-bytes"));

        // CertificateSigningRequest: field 1 = metadata, field 3 = status
        let meta = encode_length_delimited(1, b"my-csr");
        let mut csr = encode_length_delimited(1, &meta);
        csr.extend_from_slice(&encode_length_delimited(3, &status));

        let result = crate::net_disc_cert_policy_events_gen_adapter::decode_csr_proto_gen(&csr)
            .expect("CSR with status must decode");

        assert_eq!(
            result["status"]["conditions"][0]["type"], "Approved",
            "status.conditions[0].type must survive decode — the /approval subresource writes \
             this field, and dropping it silently un-approves the request on every proto write"
        );
        assert_eq!(result["status"]["conditions"][0]["status"], "True");
        assert_eq!(
            result["status"]["conditions"][0]["reason"], "KubectlApprove",
            "status.conditions[0].reason must survive decode"
        );

        use base64::Engine as _;
        let cert_b64 = result["status"]["certificate"]
            .as_str()
            .expect("status.certificate must be a base64 string in JSON");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(cert_b64)
            .expect("status.certificate must be valid base64");
        assert_eq!(
            decoded, b"fake-cert-bytes",
            "status.certificate must survive decode — the /status subresource writes the \
             issued certificate, and dropping it forces every signer write to be silently lost"
        );
    }

    /// events.k8s.io/v1 Event.series was absent from the hand decoder and therefore silently
    /// dropped. The generated decoder must preserve series.count and series.lastObservedTime
    /// so that event aggregation metadata survives the round-trip.
    #[test]
    fn decode_events_v1_event_series_previously_dropped_now_preserved() {
        // EventSeries: field 1 = count (int32), field 2 = lastObservedTime (MicroTime)
        // MicroTime is a message with field 1 = seconds (int64), field 2 = nanos (int32)
        let mut micro_time = Vec::new();
        micro_time.push(0x08); // field 1, wire type 0
        micro_time.extend_from_slice(&encode_varint(1_700_000_000u64));
        micro_time.push(0x10); // field 2, wire type 0
        micro_time.extend_from_slice(&encode_varint(0u64));

        let mut series = Vec::new();
        series.push(0x08); // field 1 (count), wire type 0
        series.extend_from_slice(&encode_varint(5u64));
        series.extend_from_slice(&encode_length_delimited(2, &micro_time));

        // events.k8s.io/v1 Event: field 1 = metadata, field 3 = series
        let meta = encode_length_delimited(1, b"test-event-series");
        let mut ev = encode_length_delimited(1, &meta);
        ev.extend_from_slice(&encode_length_delimited(3, &series));

        let result =
            crate::net_disc_cert_policy_events_gen_adapter::decode_events_v1_event_proto_gen(&ev)
                .expect("events.k8s.io/v1 Event with series must decode");

        assert_eq!(
            result["series"]["count"], 5,
            "series.count must be preserved — event aggregation UI shows the repeat count; \
             the hand decoder silently dropped series because the field was absent from the hand struct"
        );
        assert!(
            result["series"]["lastObservedTime"].as_str().is_some(),
            "series.lastObservedTime must be preserved as RFC3339 string — \
             the hand decoder silently dropped it because series was absent from the hand struct"
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

    /// decode_priorityclass_proto_gen must return None for malformed proto input.
    #[test]
    fn decode_priorityclass_proto_returns_none_for_garbage() {
        assert!(
            crate::storage_node_flow_gen_adapter::decode_priorityclass_proto_gen(&[
                0xff, 0xff, 0xff
            ])
            .is_none()
        );
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
        assert!(
            crate::admissionreg_gen_adapter::decode_mutatingadmissionpolicy_proto_gen(&[
                0xff, 0xff, 0xff
            ])
            .is_none()
        );
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

        let result =
            crate::admissionreg_gen_adapter::decode_mutatingadmissionpolicy_proto_gen(&proto)
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

        let result =
            crate::admissionreg_gen_adapter::decode_mutatingadmissionpolicybinding_proto_gen(
                &proto,
            )
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
        assert!(
            crate::admissionreg_gen_adapter::decode_mutatingadmissionpolicybinding_proto_gen(&[
                0xff, 0xff, 0xff
            ])
            .is_none()
        );
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

        let result =
            crate::admissionreg_gen_adapter::decode_validatingadmissionpolicy_proto_gen(&proto)
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
        assert!(
            crate::admissionreg_gen_adapter::decode_validatingadmissionpolicy_proto_gen(&[
                0xff, 0xff, 0xff
            ])
            .is_none()
        );
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

        let result =
            crate::admissionreg_gen_adapter::decode_validatingadmissionpolicybinding_proto_gen(
                &proto,
            )
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
        assert!(
            crate::admissionreg_gen_adapter::decode_validatingadmissionpolicybinding_proto_gen(&[
                0xff, 0xff, 0xff
            ])
            .is_none()
        );
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

    /// The gen-path ControllerRevision decoder must return None for malformed proto input.
    #[test]
    fn decode_controllerrevision_proto_returns_none_for_garbage() {
        assert!(decode_core_proto_by_kind("ControllerRevision", &[0xff, 0xff, 0xff]).is_none());
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
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

    /// decode_serviceaccount_proto must preserve imagePullSecrets from the proto body.
    ///
    /// Without decoding imagePullSecrets (field 3), a proto write returns 200 OK but the stored
    /// ServiceAccount has no imagePullSecrets, so pods that reference this SA cannot pull images
    /// from private registries (same silent-drop bug class as #583).
    ///
    /// This test fails if the `image_pull_secrets` field is removed from `ServiceAccount` or if
    /// the imagePullSecrets serialization block is removed from `decode_serviceaccount_proto`.
    #[test]
    fn decode_serviceaccount_proto_preserves_image_pull_secrets() {
        use prost::Message as _;

        let sa = ServiceAccount {
            metadata: Some(ObjectMeta {
                name: "my-sa".to_string(),
                namespace: "default".to_string(),
                ..Default::default()
            }),
            secrets: vec![],
            image_pull_secrets: vec![LocalObjectReference {
                name: "my-registry-secret".to_string(),
            }],
            automount_service_account_token: Some(false),
        };

        let mut buf = Vec::new();
        sa.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_core_proto_by_kind("ServiceAccount", &buf).expect(
            "ServiceAccount proto decoder must return Some — proto write returns 200 OK but \
             caller reads back a spec-less object if decoding fails",
        );

        assert_eq!(result["kind"], "ServiceAccount");
        assert_eq!(result["metadata"]["name"], "my-sa");

        let ips = result["imagePullSecrets"].as_array().expect(
            "imagePullSecrets must survive proto decode — a proto write that drops imagePullSecrets \
             returns 200 OK but the stored ServiceAccount has no imagePullSecrets, so pods cannot \
             pull images from private registries",
        );
        assert_eq!(ips.len(), 1, "one imagePullSecret must survive");
        assert_eq!(
            ips[0]["name"], "my-registry-secret",
            "imagePullSecret name must be preserved — kubelet uses it to authenticate image pulls"
        );

        assert_eq!(
            result["automountServiceAccountToken"], false,
            "automountServiceAccountToken must survive proto decode — without it pods get an \
             unwanted token mounted even when the SA explicitly opts out"
        );
    }

    /// decode_persistentvolumeclaim_proto must preserve spec fields from the proto body.
    ///
    /// Without decoding spec (field 2), a proto write returns 200 OK but the stored PVC has no
    /// accessModes, resources, or storageClassName, causing the PV controller to skip binding
    /// (same silent-drop bug class as #583).
    ///
    /// This test fails if the `spec` field is removed from `PersistentVolumeClaim`, or if the
    /// spec serialization block is removed from `decode_persistentvolumeclaim_proto`.
    #[test]
    fn decode_persistentvolumeclaim_proto_preserves_spec() {
        use prost::Message as _;

        let pvc = PersistentVolumeClaim {
            metadata: Some(ObjectMeta {
                name: "my-pvc".to_string(),
                namespace: "default".to_string(),
                ..Default::default()
            }),
            spec: Some(PersistentVolumeClaimSpec {
                access_modes: vec!["ReadWriteOnce".to_string()],
                storage_class_name: "standard".to_string(),
                volume_mode: "Filesystem".to_string(),
                resources: Some(ResourceRequirements {
                    requests: {
                        let mut m = std::collections::BTreeMap::new();
                        m.insert(
                            "storage".to_string(),
                            Quantity {
                                string: Some("1Gi".to_string()),
                            },
                        );
                        m
                    },
                    limits: Default::default(),
                }),
                ..Default::default()
            }),
            status: None,
        };

        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_core_proto_by_kind("PersistentVolumeClaim", &buf).expect(
            "PVC proto decoder must return Some — proto write returns 200 OK but \
             caller reads back a spec-less PVC if decoding fails",
        );

        assert_eq!(result["kind"], "PersistentVolumeClaim");
        assert_eq!(result["metadata"]["name"], "my-pvc");

        let access_modes = result["spec"]["accessModes"].as_array().expect(
            "spec.accessModes must survive proto decode — a proto write that drops accessModes \
             returns 200 OK but the stored PVC has no accessModes, so the PV controller cannot \
             bind a matching volume",
        );
        assert_eq!(access_modes.len(), 1, "one accessMode must survive");
        assert_eq!(
            access_modes[0], "ReadWriteOnce",
            "accessMode must be ReadWriteOnce"
        );

        assert_eq!(
            result["spec"]["storageClassName"], "standard",
            "spec.storageClassName must survive proto decode — without it the PV controller \
             cannot select the correct StorageClass for dynamic provisioning"
        );

        assert_eq!(
            result["spec"]["resources"]["requests"]["storage"], "1Gi",
            "spec.resources.requests.storage must survive proto decode — without it the PV \
             controller cannot determine the required volume size"
        );
    }

    /// decode_persistentvolumeclaim_proto must preserve status.conditions from a proto
    /// /status write body.
    ///
    /// The CSI external-provisioner may send proto-encoded PUT /pvc/status bodies with
    /// status.conditions to report binding state.  Without decoding status (field 3), the
    /// put_resource_status handler receives an incoming object where status is null, and then
    /// REMOVES status from the stored PVC (its null-status branch), causing conditions written
    /// by the controller to disappear on read-back.
    ///
    /// The conformance spec '[sig-storage] PersistentVolumes CSI Conformance should apply
    /// changes to a pv/pvc status' fails with "got conditions=nil, expected StatusUpdated"
    /// when proto-encoded status writes lose conditions.
    ///
    /// This test fails if the `status` field is removed from `PersistentVolumeClaim`, or if
    /// the status serialization block is removed from `decode_persistentvolumeclaim_proto`.
    #[test]
    fn decode_persistentvolumeclaim_proto_preserves_status_conditions() {
        use prost::Message as _;

        let pvc = PersistentVolumeClaim {
            metadata: Some(ObjectMeta {
                name: "status-pvc".to_string(),
                namespace: "default".to_string(),
                ..Default::default()
            }),
            spec: None,
            status: Some(PersistentVolumeClaimStatus {
                phase: "Bound".to_string(),
                conditions: vec![PersistentVolumeClaimCondition {
                    r#type: "StatusUpdated".to_string(),
                    status: "True".to_string(),
                    reason: "CSITest".to_string(),
                    message: "applied by conformance test".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };

        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_core_proto_by_kind("PersistentVolumeClaim", &buf)
            .expect("PVC proto decoder must return Some for a proto /status body");

        assert_eq!(result["kind"], "PersistentVolumeClaim");
        assert_eq!(result["metadata"]["name"], "status-pvc");

        assert_eq!(
            result["status"]["phase"], "Bound",
            "status.phase must survive proto decode of /pvc/status body — without this, a \
             proto PUT /status that sets phase=Bound is silently ignored and the PVC stays Pending"
        );

        let conditions = result["status"]["conditions"].as_array().expect(
            "status.conditions must survive proto decode — a proto PUT /pvc/status that drops \
             conditions means the conformance test 'should apply changes to a pv/pvc status' \
             reads back conditions=nil instead of the expected StatusUpdated condition",
        );
        assert_eq!(
            conditions.len(),
            1,
            "one condition must survive proto decode"
        );
        assert_eq!(
            conditions[0]["type"], "StatusUpdated",
            "condition.type must be StatusUpdated after proto decode"
        );
        assert_eq!(
            conditions[0]["status"], "True",
            "condition.status must be True after proto decode"
        );
        assert_eq!(
            conditions[0]["reason"], "CSITest",
            "condition.reason must survive proto decode"
        );
    }

    /// decode_storageclass_proto_gen must preserve top-level fields from the proto body.
    ///
    /// Without decoding provisioner, parameters, and reclaimPolicy, a proto write returns 200 OK
    /// but the stored StorageClass has no provisioner, breaking dynamic provisioning for any PVC
    /// that references this StorageClass (same silent-drop bug class as #583).
    #[test]
    fn decode_storageclass_proto_preserves_provisioner_and_parameters() {
        // StorageClass: field 1=metadata, 2=provisioner, 3=parameters(map), 4=reclaimPolicy,
        // 6=allowVolumeExpansion(bool), 7=volumeBindingMode
        // ObjectMeta bytes: field 1 = name (string "fast")
        let obj_meta = encode_length_delimited(1, b"fast");

        // map entry: field 1=key, field 2=value
        let mut param_entry = encode_length_delimited(1, b"type");
        param_entry.extend_from_slice(&encode_length_delimited(2, b"gp2"));

        let mut buf = encode_length_delimited(1, &obj_meta);
        buf.extend_from_slice(&encode_length_delimited(2, b"kubernetes.io/no-provisioner"));
        buf.extend_from_slice(&encode_length_delimited(3, &param_entry));
        buf.extend_from_slice(&encode_length_delimited(4, b"Retain"));
        // allowVolumeExpansion = true: field 6, wire type 0, value 1
        buf.push(6 << 3); // field 6, wire type 0 (varint), value follows
        buf.push(1);
        buf.extend_from_slice(&encode_length_delimited(7, b"WaitForFirstConsumer"));

        let result = crate::storage_node_flow_gen_adapter::decode_storageclass_proto_gen(&buf)
            .expect(
                "decode_storageclass_proto_gen must return Some — proto write returns 200 OK but \
                 caller reads back a provisioner-less StorageClass if decoding fails",
            );

        assert_eq!(result["kind"], "StorageClass");
        assert_eq!(result["metadata"]["name"], "fast");

        assert_eq!(
            result["provisioner"], "kubernetes.io/no-provisioner",
            "provisioner must survive proto decode — a proto write that drops provisioner returns \
             200 OK but the stored StorageClass has no provisioner, breaking dynamic provisioning \
             for any PVC that references this StorageClass"
        );
        assert_eq!(
            result["parameters"]["type"], "gp2",
            "parameters must survive proto decode — CSI drivers use parameters to configure volumes"
        );
        assert_eq!(
            result["reclaimPolicy"], "Retain",
            "reclaimPolicy must survive proto decode — without it dynamically provisioned PVs \
             default to Delete, causing unexpected data loss"
        );
        assert_eq!(
            result["volumeBindingMode"], "WaitForFirstConsumer",
            "volumeBindingMode must survive proto decode"
        );
        assert_eq!(
            result["allowVolumeExpansion"], true,
            "allowVolumeExpansion must survive proto decode"
        );
    }

    /// decode_volumeattributesclass_proto_gen must preserve driverName and parameters.
    ///
    /// Without decoding driverName (field 2) and parameters (field 3), a proto write returns
    /// 200 OK but the stored VolumeAttributesClass has no driverName, so the CSI driver cannot
    /// apply the attributes to the volume (same silent-drop bug class as #583).
    #[test]
    fn decode_volumeattributesclass_proto_preserves_driver_name_and_parameters() {
        // VolumeAttributesClass: field 1=metadata, 2=driverName, 3=parameters(map)
        // ObjectMeta bytes: field 1 = name (string "silver")
        let obj_meta = encode_length_delimited(1, b"silver");

        let mut param_entry = encode_length_delimited(1, b"iops");
        param_entry.extend_from_slice(&encode_length_delimited(2, b"3000"));

        let mut buf = encode_length_delimited(1, &obj_meta);
        buf.extend_from_slice(&encode_length_delimited(2, b"pd.csi.storage.gke.io"));
        buf.extend_from_slice(&encode_length_delimited(3, &param_entry));

        let result =
            crate::storage_node_flow_gen_adapter::decode_volumeattributesclass_proto_gen(&buf)
                .expect(
                "decode_volumeattributesclass_proto_gen must return Some — proto write returns \
                     200 OK but caller reads back a driverName-less VolumeAttributesClass if \
                     decoding fails",
            );

        assert_eq!(result["kind"], "VolumeAttributesClass");
        assert_eq!(result["metadata"]["name"], "silver");

        assert_eq!(
            result["driverName"], "pd.csi.storage.gke.io",
            "driverName must survive proto decode — a proto write that drops driverName returns \
             200 OK but the stored VolumeAttributesClass has no driverName, so the CSI driver \
             cannot apply the attributes to the volume"
        );
        assert_eq!(
            result["parameters"]["iops"], "3000",
            "parameters must survive proto decode — CSI driver uses them to configure the volume"
        );
    }

    /// decode_replicationcontroller_proto must preserve spec.template.spec.containers.
    ///
    /// Without decoding the template (field 3 of ReplicationControllerSpec), a proto write
    /// returns 200 OK but the stored RC has an empty template, so the RC controller creates
    /// pods with no containers — they can never reach Running phase (same silent-drop bug
    /// class as #583 for Jobs).
    ///
    /// This test fails if the `template` field of `ReplicationControllerSpec` is changed back
    /// to raw bytes, or if the template decoding block is removed from
    /// `decode_replicationcontroller_proto`.
    #[test]
    fn decode_replicationcontroller_proto_preserves_template_containers() {
        use crate::apps_gen::k8s::io::api::core::v1 as core_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let rc = core_v1::ReplicationController {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("my-rc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::ReplicationControllerSpec {
                replicas: Some(2),
                selector: {
                    let mut m = std::collections::HashMap::new();
                    m.insert("app".to_string(), "web".to_string());
                    m
                },
                template: Some(core_v1::PodTemplateSpec {
                    metadata: None,
                    spec: Some(core_v1::PodSpec {
                        containers: vec![core_v1::Container {
                            name: Some("web".to_string()),
                            image: Some("nginx:latest".to_string()),
                            ..Default::default()
                        }],
                        restart_policy: Some("Always".to_string()),
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            }),
            status: None,
        };

        let mut buf = Vec::new();
        rc.encode(&mut buf).expect("prost encode must succeed");

        let result = crate::core_gen_adapter::decode_replicationcontroller_proto_gen(&buf).expect(
            "decode_replicationcontroller_proto must return Some for RC with template — \
             proto write returns 200 OK but RC has no containers if template is not decoded",
        );

        assert_eq!(result["kind"], "ReplicationController");
        assert_eq!(result["metadata"]["name"], "my-rc");
        assert_eq!(result["spec"]["replicas"], 2);

        let containers = result["spec"]["template"]["spec"]["containers"]
            .as_array()
            .expect(
                "spec.template.spec.containers must be an array — without it the RC controller \
                 creates pods with no containers and they can never reach Running phase (same \
                 silent-drop bug class as #583 for Jobs)",
            );
        assert_eq!(
            containers.len(),
            1,
            "one container must survive proto decode"
        );
        assert_eq!(
            containers[0]["name"], "web",
            "container name must survive proto decode — RC controller uses it to create pod specs"
        );
        assert_eq!(
            containers[0]["image"], "nginx:latest",
            "container image must survive proto decode — without it pods run nothing"
        );
    }

    /// decode_service_proto must preserve status.conditions from a protobuf-encoded body so that
    /// service status lifecycle watchers converge.
    ///
    /// client-go's UpdateStatus (PUT /api/v1/namespaces/{ns}/services/{name}/status) sends
    /// Content-Type: application/vnd.kubernetes.protobuf. Before this fix, Service.status was
    /// decoded as raw bytes and silently dropped, so incoming.body["status"] was Null in the
    /// handler — which then removed the status field from the stored object entirely. The
    /// conformance watch predicate (svc.Status.Conditions with Type=="StatusUpdate") never matched
    /// and the test timed out after 60s.
    #[test]
    fn service_status_update_preserves_conditions_so_status_lifecycle_watchers_converge() {
        // Build metav1.Condition { type="StatusUpdate", status="True", reason="E2E", message="Set from e2e test" }
        // Field 1 = type (string), field 2 = status (string), field 5 = reason (string), field 6 = message (string)
        let mut cond_bytes = encode_length_delimited(1, b"StatusUpdate");
        cond_bytes.extend_from_slice(&encode_length_delimited(2, b"True"));
        cond_bytes.extend_from_slice(&encode_length_delimited(5, b"E2E"));
        cond_bytes.extend_from_slice(&encode_length_delimited(6, b"Set from e2e test"));

        // Build ServiceStatus { conditions: [cond] }
        // Field 2 = conditions (repeated message)
        let status_bytes = encode_length_delimited(2, &cond_bytes);

        // Build Service { metadata: { name: "svc-lifecycle" }, status: ... }
        let name_bytes = encode_length_delimited(1, b"svc-lifecycle");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(3, &status_bytes));

        let result = decode_core_proto_by_kind("Service", &proto)
            .expect("Service with status must decode successfully");

        assert_eq!(
            result["status"]["conditions"][0]["type"], "StatusUpdate",
            "status.conditions[0].type must survive proto decode — without this, UpdateStatus via \
             protobuf drops the condition, the conformance watch times out at 60s (service status \
             lifecycle conformance test)"
        );
        assert_eq!(
            result["status"]["conditions"][0]["status"], "True",
            "status.conditions[0].status must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["reason"], "E2E",
            "status.conditions[0].reason must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["message"], "Set from e2e test",
            "status.conditions[0].message must survive proto decode"
        );
    }

    /// decode_service_proto must preserve lastTransitionTime on a status condition so that
    /// metav1.Condition round-trips through protobuf UpdateStatus with a valid API object.
    /// lastTransitionTime is a required field on metav1.Condition; dropping it produces an
    /// invalid object that clients may reject or that may fail server-side validation.
    #[test]
    fn condition_last_transition_time_survives_proto_decode_so_status_conditions_are_api_valid() {
        // metav1.Time { seconds: 1704067200 } — 2024-01-01T00:00:00Z
        // Wire: field 1, varint wire type (tag = 1<<3|0 = 0x08), then the seconds value.
        let mut time_bytes = encode_varint(0x08); // field 1, wire type 0
        time_bytes.extend_from_slice(&encode_varint(1_704_067_200u64));

        // metav1.Condition { type="Ready", status="True", lastTransitionTime=<above> }
        let mut cond_bytes = encode_length_delimited(1, b"Ready");
        cond_bytes.extend_from_slice(&encode_length_delimited(2, b"True"));
        cond_bytes.extend_from_slice(&encode_length_delimited(4, &time_bytes));

        // ServiceStatus { conditions: [cond] }
        let status_bytes = encode_length_delimited(2, &cond_bytes);

        // Service { metadata: { name: "svc-ltt" }, status: ... }
        let name_bytes = encode_length_delimited(1, b"svc-ltt");
        let mut proto = encode_length_delimited(1, &name_bytes);
        proto.extend_from_slice(&encode_length_delimited(3, &status_bytes));

        let result = decode_core_proto_by_kind("Service", &proto)
            .expect("Service with lastTransitionTime must decode successfully");

        assert_eq!(
            result["status"]["conditions"][0]["lastTransitionTime"], "2024-01-01T00:00:00Z",
            "lastTransitionTime must survive proto decode — without it, metav1.Condition is \
             missing a required field and API clients may reject or misinterpret the object"
        );
    }

    /// decode_delete_options_proto_gen must extract propagationPolicy=Orphan from proto-encoded body.
    ///
    /// The Kubernetes Go client sends DELETE request bodies as protobuf-encoded DeleteOptions.
    /// Without this decoder, extract_body returns raw proto bytes, serde_json::from_slice fails
    /// silently (unwrap_or_default → Background), and propagationPolicy=Orphan is never honored.
    /// If this test fails (reverted), GC conformance specs for Orphan cascading will fail.
    #[test]
    fn decode_delete_options_proto_extracts_propagation_policy_orphan() {
        // Build a proto-encoded DeleteOptions with propagationPolicy = "Orphan"
        // field 4 (propagationPolicy) = string, wire type 2 (length-delimited)
        let policy_bytes = b"Orphan";
        let proto = encode_length_delimited(4, policy_bytes);

        let result = crate::apiextensions_gen_adapter::decode_delete_options_proto_gen(&proto)
            .expect("proto-encoded DeleteOptions with propagationPolicy must decode");

        assert_eq!(
            result["propagationPolicy"], "Orphan",
            "propagationPolicy=Orphan must survive proto decode — without this, \
             the GC conformance spec 'should orphan RS created by deployment when \
             deleteOptions.PropagationPolicy is Orphan' will fail because the Kubernetes \
             client sends DeleteOptions as protobuf and the orphan gate never fires"
        );
    }

    /// decode_pod_proto must preserve Container.resizePolicy (proto field 23) through the decode.
    ///
    /// resizePolicy is a repeated ContainerResizePolicy specifying how the kubelet should handle
    /// in-place CPU/memory resize (KEP-1287). kubectl/client-go send pods as protobuf; if field 23
    /// is absent from the Container prost struct it is SILENTLY DROPPED — the GET response after a
    /// PATCH /resize will be missing resizePolicy, causing the resize conformance tests
    /// "Pod InPlace Resize Container 6 containers various operations" and
    /// "increase CPU/mem multi-container" to fail on their post-PATCH verification step.
    /// This test MUST fail if the ContainerResizePolicy struct or the resize_policy field (tag=23)
    /// on Container is removed.
    #[test]
    fn decode_container_proto_preserves_resize_policy() {
        // Build ContainerResizePolicy{resourceName="cpu", restartPolicy="NotRequired"}
        let mut crp_cpu = encode_length_delimited(1, b"cpu"); // resourceName (field 1)
        crp_cpu.extend_from_slice(&encode_length_delimited(2, b"NotRequired")); // restartPolicy (field 2)

        // Build ContainerResizePolicy{resourceName="memory", restartPolicy="RestartContainer"}
        let mut crp_mem = encode_length_delimited(1, b"memory"); // resourceName (field 1)
        crp_mem.extend_from_slice(&encode_length_delimited(2, b"RestartContainer")); // restartPolicy (field 2)

        // Container: name (field 1), image (field 2), resizePolicy repeated (field 23)
        let mut container = encode_length_delimited(1, b"app"); // name
        container.extend_from_slice(&encode_length_delimited(2, b"app:latest")); // image
        container.extend_from_slice(&encode_length_delimited(23, &crp_cpu)); // resizePolicy[0]
        container.extend_from_slice(&encode_length_delimited(23, &crp_mem)); // resizePolicy[1]

        // PodSpec: containers (field 2)
        let pod_spec = encode_length_delimited(2, &container);

        // Pod: metadata (field 1), spec (field 2)
        let mut obj_meta = encode_length_delimited(1, b"resize-test"); // ObjectMeta.name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default")); // ObjectMeta.namespace
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto)
            .expect("pod with resizePolicy must decode — proto field 23 is ContainerResizePolicy");

        let containers = result["spec"]["containers"]
            .as_array()
            .expect("spec.containers must be an array");
        assert_eq!(containers.len(), 1);

        let resize_policy = containers[0]["resizePolicy"]
            .as_array()
            .expect("resizePolicy must be present — without field 23 in Container prost struct it is silently dropped, breaking resize conformance tests");
        assert_eq!(
            resize_policy.len(),
            2,
            "both resizePolicy entries must survive proto decode"
        );
        assert_eq!(
            resize_policy[0]["resourceName"], "cpu",
            "resizePolicy[0].resourceName must be 'cpu'"
        );
        assert_eq!(
            resize_policy[0]["restartPolicy"], "NotRequired",
            "resizePolicy[0].restartPolicy must be 'NotRequired'"
        );
        assert_eq!(
            resize_policy[1]["resourceName"], "memory",
            "resizePolicy[1].resourceName must be 'memory'"
        );
        assert_eq!(
            resize_policy[1]["restartPolicy"], "RestartContainer",
            "resizePolicy[1].restartPolicy must be 'RestartContainer' — if this fails, \
             resize conformance tests will fail on post-PATCH GET verification because \
             the returned pod is missing resizePolicy"
        );
    }

    /// decode_delete_options_proto_gen must extract orphanDependents=true from proto-encoded body.
    ///
    /// The legacy orphanDependents boolean field (field 3) must also be decoded correctly,
    /// since some older clients use it instead of propagationPolicy.
    #[test]
    fn decode_delete_options_proto_extracts_orphan_dependents_true() {
        // Build a proto-encoded DeleteOptions with orphanDependents = true
        // field 3 (orphanDependents) = bool, wire type 0 (varint)
        let tag = encode_varint(3 << 3); // field 3, wire type 0 (varint)
        let mut proto = tag;
        proto.push(1); // true

        let result = crate::apiextensions_gen_adapter::decode_delete_options_proto_gen(&proto)
            .expect("proto-encoded DeleteOptions with orphanDependents must decode");

        assert_eq!(
            result["orphanDependents"], true,
            "orphanDependents=true must survive proto decode — without this, \
             legacy clients using orphanDependents instead of propagationPolicy \
             will not get Orphan semantics"
        );
    }

    /// decode_replicationcontroller_proto must preserve status.replicas and status.readyReplicas.
    ///
    /// Without status decoding, a proto-path RC status write silently discards the status object.
    /// Any client that GETs the RC via proto sees replicas=0 and readyReplicas=0, and controllers
    /// that compute desired-vs-actual replica counts will loop trying to scale up an already-full RC.
    #[test]
    fn decode_replicationcontroller_proto_preserves_status_else_controllers_see_zero_and_loop() {
        use crate::apps_gen::k8s::io::api::core::v1 as core_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let status = core_v1::ReplicationControllerStatus {
            replicas: Some(3),
            fully_labeled_replicas: Some(3),
            observed_generation: Some(7),
            ready_replicas: Some(2),
            available_replicas: Some(2),
            conditions: vec![core_v1::ReplicationControllerCondition {
                r#type: Some("ReplicaFailure".to_string()),
                status: Some("False".to_string()),
                reason: None,
                message: None,
                last_transition_time: None,
            }],
        };

        let rc = core_v1::ReplicationController {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("my-rc".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(status),
        };
        let mut proto = Vec::new();
        rc.encode(&mut proto).expect("prost encode must succeed");

        let result = decode_core_proto_by_kind("ReplicationController", &proto)
            .expect("RC with status must decode successfully");

        assert_eq!(
            result["status"]["replicas"], 3,
            "status.replicas must survive proto decode — without this, controllers \
             computing desired-vs-actual replica counts see 0 and loop"
        );
        assert_eq!(
            result["status"]["readyReplicas"], 2,
            "status.readyReplicas must survive proto decode — without this, readiness \
             checks always see 0 and incorrectly report the RC as not ready"
        );
        assert_eq!(
            result["status"]["fullyLabeledReplicas"], 3,
            "status.fullyLabeledReplicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["observedGeneration"], 7,
            "status.observedGeneration must survive proto decode"
        );
        assert_eq!(
            result["status"]["availableReplicas"], 2,
            "status.availableReplicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "ReplicaFailure",
            "status.conditions must survive proto decode"
        );
    }

    /// decode_daemonset_proto must preserve status fields.
    ///
    /// Without status decoding, proto-path DaemonSet status writes silently discard the status.
    /// Controllers that observe DaemonSet status (e.g., node readiness checks) will always see
    /// zero scheduled/ready counts and never progress past initial state.
    #[test]
    fn decode_daemonset_proto_preserves_status_else_node_readiness_checks_see_zero_and_stall() {
        use crate::apps_gen::k8s::io::api::apps::v1 as apps_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        let status = apps_v1::DaemonSetStatus {
            current_number_scheduled: Some(5),
            number_misscheduled: Some(1),
            desired_number_scheduled: Some(5),
            number_ready: Some(4),
            observed_generation: Some(2),
            updated_number_scheduled: Some(5),
            number_available: Some(4),
            number_unavailable: Some(1),
            collision_count: None,
            conditions: vec![apps_v1::DaemonSetCondition {
                r#type: Some("Available".to_string()),
                status: Some("True".to_string()),
                reason: None,
                message: None,
                last_transition_time: None,
            }],
        };
        let ds = apps_v1::DaemonSet {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("my-ds".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(status),
        };
        let mut proto = Vec::new();
        ds.encode(&mut proto).expect("prost encode must succeed");

        let result = decode_core_proto_by_kind("DaemonSet", &proto)
            .expect("DaemonSet with status must decode successfully");

        assert_eq!(
            result["status"]["currentNumberScheduled"], 5,
            "status.currentNumberScheduled must survive proto decode — without this, \
             node readiness checks always see 0 scheduled and stall"
        );
        assert_eq!(
            result["status"]["numberReady"], 4,
            "status.numberReady must survive proto decode"
        );
        assert_eq!(
            result["status"]["desiredNumberScheduled"], 5,
            "status.desiredNumberScheduled must survive proto decode"
        );
        assert_eq!(
            result["status"]["numberAvailable"], 4,
            "status.numberAvailable must survive proto decode"
        );
        assert_eq!(
            result["status"]["observedGeneration"], 2,
            "status.observedGeneration must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "Available",
            "status.conditions must survive proto decode"
        );
    }

    /// decode_job_proto must preserve status.succeeded and status.conditions.
    ///
    /// Without status decoding, a proto-path Job status write silently discards the status.
    /// The CronJob controller and the job garbage collector both observe Job status to decide
    /// whether to clean up finished Jobs; if status is invisible they keep running and filling
    /// the history limit.
    #[test]
    fn decode_job_proto_preserves_status_else_cronjob_gc_cannot_see_completion_and_loops() {
        use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;
        let status = batch_v1::JobStatus {
            conditions: vec![batch_v1::JobCondition {
                r#type: Some("Complete".to_string()),
                status: Some("True".to_string()),
                reason: None,
                message: None,
                ..Default::default()
            }],
            succeeded: Some(3),
            failed: Some(1),
            completed_indexes: Some("0-2".to_string()),
            ..Default::default()
        };
        let job = batch_v1::Job {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("my-job".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(status),
        };
        let mut proto = Vec::new();
        job.encode(&mut proto).expect("prost encode must succeed");

        let result = decode_core_proto_by_kind("Job", &proto)
            .expect("Job with status must decode successfully");

        assert_eq!(
            result["status"]["succeeded"], 3,
            "status.succeeded must survive proto decode — without this, the CronJob \
             GC cannot see job completion and keeps creating new jobs past the history limit"
        );
        assert_eq!(
            result["status"]["failed"], 1,
            "status.failed must survive proto decode"
        );
        assert_eq!(
            result["status"]["completedIndexes"], "0-2",
            "status.completedIndexes must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "Complete",
            "status.conditions[0].type must survive proto decode — without this, \
             the Job completion condition is invisible and GC never cleans up finished Jobs"
        );
        assert_eq!(
            result["status"]["conditions"][0]["status"], "True",
            "status.conditions[0].status must survive proto decode"
        );
    }

    /// decode_cronjob_proto must preserve status.active job references.
    ///
    /// Without status decoding, a proto-path CronJob status write discards the active job list.
    /// The CronJob controller uses status.active to track concurrency; if it's invisible, the
    /// controller can fire multiple overlapping Jobs when ConcurrencyPolicy=Forbid/Replace.
    #[test]
    fn decode_cronjob_proto_preserves_status_active_else_concurrency_control_is_blind() {
        use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
        use crate::apps_gen::k8s::io::api::core::v1 as core_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;
        let status = batch_v1::CronJobStatus {
            active: vec![core_v1::ObjectReference {
                kind: Some("Job".to_string()),
                namespace: Some("default".to_string()),
                name: Some("my-cronjob-abc".to_string()),
                uid: Some("uid-123".to_string()),
                api_version: Some("batch/v1".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let cj = batch_v1::CronJob {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("my-cronjob".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::CronJobSpec {
                schedule: Some("*/5 * * * *".to_string()),
                concurrency_policy: Some("Forbid".to_string()),
                successful_jobs_history_limit: Some(3),
                failed_jobs_history_limit: Some(1),
                job_template: None,
                ..Default::default()
            }),
            status: Some(status),
        };
        let mut proto = Vec::new();
        cj.encode(&mut proto).expect("prost encode must succeed");

        let result = decode_core_proto_by_kind("CronJob", &proto)
            .expect("CronJob with status must decode successfully");

        assert_eq!(
            result["status"]["active"][0]["name"], "my-cronjob-abc",
            "status.active[0].name must survive proto decode — without this, the CronJob \
             controller cannot see running jobs and fires extra Jobs violating ConcurrencyPolicy"
        );
        assert_eq!(
            result["status"]["active"][0]["namespace"], "default",
            "status.active[0].namespace must survive proto decode"
        );
        assert_eq!(
            result["status"]["active"][0]["kind"], "Job",
            "status.active[0].kind must survive proto decode"
        );
    }

    /// decode_pod_proto must preserve Container.restartPolicy (proto field 24) for sidecar init containers.
    ///
    /// Field 24 of Container is `optional string restartPolicy` (KEP-3939, k8s release-1.34
    /// core/v1/generated.proto). When set to "Always" on an init container, the kubelet treats it
    /// as a sidecar that runs concurrently (non-blocking). Without field 24 in the Container prost
    /// struct, u7s SILENTLY DROPS the field — the init container is stored without restartPolicy,
    /// the kubelet sees a traditional blocking init container, sleep-1d never exits, and the pod
    /// stays Pending forever. This causes ~23 of the 54 resize conformance specs to time out after
    /// 300s waiting for Running+Ready. This test MUST fail if restart_policy (tag=24) is removed
    /// from the Container prost struct or the emission in container_to_json is removed.
    #[test]
    fn decode_container_proto_preserves_restart_policy_else_sidecar_becomes_blocking_init() {
        // Build Container: name (field 1), image (field 2), restartPolicy (field 24) = "Always"
        // This simulates a sidecar init container as sent by the e2e test binary.
        let mut container = encode_length_delimited(1, b"sidecar"); // name
        container.extend_from_slice(&encode_length_delimited(2, b"busybox:latest")); // image
                                                                                     // field 24, wire type 2 (length-delimited string) — the "optional string" proto field
        container.extend_from_slice(&encode_length_delimited(24, b"Always")); // restartPolicy

        // PodSpec: initContainers (field 20), containers (field 2) — put sidecar as init container
        // Use containers field (field 2) for simplicity; the decoder path is the same.
        let pod_spec = encode_length_delimited(2, &container);

        // Pod: metadata (field 1), spec (field 2)
        let mut obj_meta = encode_length_delimited(1, b"sidecar-pod"); // ObjectMeta.name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"default")); // ObjectMeta.namespace
        let mut pod_proto = encode_length_delimited(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_length_delimited(2, &pod_spec));

        let result = crate::core_gen_adapter::decode_pod_proto_gen(&pod_proto).expect(
            "pod with sidecar init container (restartPolicy=Always) must decode — \
             proto field 24 is Container.restartPolicy",
        );

        let containers = result["spec"]["containers"]
            .as_array()
            .expect("spec.containers must be an array");
        assert_eq!(containers.len(), 1);

        assert_eq!(
            containers[0]["restartPolicy"], "Always",
            "Container.restartPolicy must be 'Always' — without field 24 in the Container prost \
             struct it is silently dropped, converting the sidecar init container into a blocking \
             init container that never exits, leaving the pod Pending and causing resize \
             conformance specs to time out after 300s"
        );
    }

    /// decode_deployment_proto must preserve status on proto round-trip.
    ///
    /// Without status decoding, a proto-path UpdateStatus on a Deployment silently drops the
    /// status. Controllers and kubectl see empty status; conformance status tests hang waiting
    /// for conditions that are never stored.
    #[test]
    fn decode_deployment_proto_preserves_status_else_controllers_see_empty_status_and_hang() {
        use crate::apps_gen::k8s::io::api::apps::v1 as apps_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        let status = apps_v1::DeploymentStatus {
            observed_generation: Some(3),
            replicas: Some(5),
            updated_replicas: Some(5),
            ready_replicas: Some(4),
            available_replicas: Some(4),
            unavailable_replicas: Some(1),
            terminating_replicas: None,
            collision_count: None,
            conditions: vec![apps_v1::DeploymentCondition {
                r#type: Some("Available".to_string()),
                status: Some("True".to_string()),
                reason: Some("MinimumReplicasAvailable".to_string()),
                message: Some("Deployment has minimum availability.".to_string()),
                last_update_time: None,
                last_transition_time: None,
            }],
        };
        let deploy = apps_v1::Deployment {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("my-deploy".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(status),
        };
        let mut proto = Vec::new();
        deploy
            .encode(&mut proto)
            .expect("prost encode must succeed");

        let result = decode_core_proto_by_kind("Deployment", &proto)
            .expect("Deployment with status must decode successfully");

        assert_eq!(
            result["status"]["observedGeneration"], 3,
            "status.observedGeneration must survive proto decode — dropped status causes \
             controllers and kubectl to see empty status; conformance status tests hang"
        );
        assert_eq!(
            result["status"]["replicas"], 5,
            "status.replicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["readyReplicas"], 4,
            "status.readyReplicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["availableReplicas"], 4,
            "status.availableReplicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["unavailableReplicas"], 1,
            "status.unavailableReplicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["updatedReplicas"], 5,
            "status.updatedReplicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "Available",
            "status.conditions[0].type must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["status"], "True",
            "status.conditions[0].status must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["reason"], "MinimumReplicasAvailable",
            "status.conditions[0].reason must survive proto decode"
        );
    }

    /// decode_replicaset_proto must preserve status on proto round-trip.
    ///
    /// Without status decoding, a proto-path UpdateStatus on a ReplicaSet silently drops the
    /// status. The Deployment controller reads ReplicaSet status to compute its own status;
    /// if RS status is invisible the Deployment status never converges and conformance tests hang.
    #[test]
    fn decode_replicaset_proto_preserves_status_else_deployment_controller_cannot_compute_status() {
        use crate::apps_gen::k8s::io::api::apps::v1 as apps_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        let status = apps_v1::ReplicaSetStatus {
            replicas: Some(3),
            fully_labeled_replicas: Some(3),
            observed_generation: Some(2),
            ready_replicas: Some(2),
            available_replicas: Some(2),
            terminating_replicas: None,
            conditions: vec![apps_v1::ReplicaSetCondition {
                r#type: Some("ReplicaFailure".to_string()),
                status: Some("False".to_string()),
                reason: None,
                message: None,
                last_transition_time: None,
            }],
        };
        let rs = apps_v1::ReplicaSet {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("my-rs".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(status),
        };
        let mut proto = Vec::new();
        rs.encode(&mut proto).expect("prost encode must succeed");

        let result = decode_core_proto_by_kind("ReplicaSet", &proto)
            .expect("ReplicaSet with status must decode successfully");

        assert_eq!(
            result["status"]["replicas"], 3,
            "status.replicas must survive proto decode — dropped RS status makes the Deployment \
             controller unable to compute its own status; conformance status tests hang"
        );
        assert_eq!(
            result["status"]["readyReplicas"], 2,
            "status.readyReplicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["availableReplicas"], 2,
            "status.availableReplicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["observedGeneration"], 2,
            "status.observedGeneration must survive proto decode"
        );
        assert_eq!(
            result["status"]["fullyLabeledReplicas"], 3,
            "status.fullyLabeledReplicas must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "ReplicaFailure",
            "status.conditions[0].type must survive proto decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["status"], "False",
            "status.conditions[0].status must survive proto decode"
        );
    }

    /// decode_crd_proto_gen must carry openAPIV3Schema and additionalPrinterColumns into the output.
    ///
    /// The hand CrdVersion struct skipped spec.versions[].schema (decoded as raw bytes) and
    /// spec.versions[].additionalPrinterColumns (raw bytes). Without openAPIV3Schema, CR admission
    /// validation never fires — the apiserver accepts CRs with invalid fields, silently breaking
    /// spec contracts. Without additionalPrinterColumns, `kubectl get` shows only the Age column
    /// for custom resources, hiding operator-defined status columns. This test MUST fail if
    /// decode_crd_proto_gen reverts to the hand decoder that drops those fields.
    #[test]
    fn decode_crd_gen_carries_openapiv3schema_and_printer_columns_previously_dropped() {
        use crate::apiextensions_gen::k8s::io::apiextensions_apiserver::pkg::apis::apiextensions::v1 as apiext_v1;
        use crate::apiextensions_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let schema_props = apiext_v1::JsonSchemaProps {
            r#type: Some("object".to_string()),
            description: Some("A test CRD schema".to_string()),
            properties: {
                let mut p = std::collections::HashMap::new();
                p.insert(
                    "spec".to_string(),
                    apiext_v1::JsonSchemaProps {
                        r#type: Some("object".to_string()),
                        ..Default::default()
                    },
                );
                p
            },
            required: vec!["spec".to_string()],
            ..Default::default()
        };

        let version = apiext_v1::CustomResourceDefinitionVersion {
            name: Some("v1".to_string()),
            served: Some(true),
            storage: Some(true),
            schema: Some(apiext_v1::CustomResourceValidation {
                open_apiv3_schema: Some(schema_props),
            }),
            additional_printer_columns: vec![apiext_v1::CustomResourceColumnDefinition {
                name: Some("Phase".to_string()),
                r#type: Some("string".to_string()),
                json_path: Some(".status.phase".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };

        let crd = apiext_v1::CustomResourceDefinition {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("widgets.example.io".to_string()),
                ..Default::default()
            }),
            spec: Some(apiext_v1::CustomResourceDefinitionSpec {
                group: Some("example.io".to_string()),
                scope: Some("Namespaced".to_string()),
                names: Some(apiext_v1::CustomResourceDefinitionNames {
                    plural: Some("widgets".to_string()),
                    singular: Some("widget".to_string()),
                    kind: Some("Widget".to_string()),
                    ..Default::default()
                }),
                versions: vec![version],
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        crd.encode(&mut buf).expect("prost encode must succeed");

        let result = crate::apiextensions_gen_adapter::decode_crd_proto_gen(&buf).expect(
            "CRD with openAPIV3Schema must decode — generated adapter must not drop schema",
        );

        let versions = result["spec"]["versions"]
            .as_array()
            .expect("spec.versions must be an array");
        assert_eq!(versions.len(), 1);

        let schema_type = &versions[0]["schema"]["openAPIV3Schema"]["type"];
        assert_eq!(
            schema_type, "object",
            "spec.versions[0].schema.openAPIV3Schema.type must survive proto decode — \
             without openAPIV3Schema the apiserver accepts CRs with any field, silently \
             bypassing validation that the CRD author declared"
        );

        let required = versions[0]["schema"]["openAPIV3Schema"]["required"]
            .as_array()
            .expect("openAPIV3Schema.required must be present — hand CrdVersion dropped it");
        assert!(
            required.iter().any(|v| v == "spec"),
            "openAPIV3Schema.required must contain 'spec' — without this, required-field \
             enforcement never fires for this CRD"
        );

        let props = &versions[0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["type"];
        assert_eq!(
            props, "object",
            "openAPIV3Schema.properties.spec.type must survive — nested schema properties \
             are needed for recursive field validation"
        );

        let cols = versions[0]["additionalPrinterColumns"].as_array().expect(
            "additionalPrinterColumns must be present — hand CrdVersion dropped them, \
                 causing `kubectl get` to show only Age for custom resources",
        );
        assert_eq!(
            cols[0]["name"], "Phase",
            "additionalPrinterColumns[0].name must be 'Phase'"
        );
        assert_eq!(
            cols[0]["jsonPath"], ".status.phase",
            "additionalPrinterColumns[0].jsonPath must survive proto decode"
        );
    }

    /// decode_crd_proto_gen must carry status.conditions into the output.
    ///
    /// The typed apiextensions clientset's UpdateStatus/Patch on the CRD status
    /// subresource sends a protobuf-encoded body. Before this fix, decode_crd_proto_gen
    /// dropped `crd.status` entirely, so extract_body handed the status-subresource PUT
    /// handler a body with no "status" key at all — which the handler then interpreted
    /// as "clear the status", wiping out the very conditions the client just appended.
    /// This is exactly the conformance failure: "Condition {Message:"updated"} not found
    /// in conditions []" — the response came back with status.conditions == nil.
    #[test]
    fn decode_crd_gen_carries_status_conditions_previously_dropped() {
        use crate::apiextensions_gen::k8s::io::apiextensions_apiserver::pkg::apis::apiextensions::v1 as apiext_v1;
        use crate::apiextensions_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as gen_meta_v1;
        use prost::Message as _;

        let crd = apiext_v1::CustomResourceDefinition {
            metadata: Some(gen_meta_v1::ObjectMeta {
                name: Some("widgets.example.io".to_string()),
                ..Default::default()
            }),
            spec: Some(apiext_v1::CustomResourceDefinitionSpec {
                group: Some("example.io".to_string()),
                scope: Some("Namespaced".to_string()),
                names: Some(apiext_v1::CustomResourceDefinitionNames {
                    plural: Some("widgets".to_string()),
                    singular: Some("widget".to_string()),
                    kind: Some("Widget".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: Some(apiext_v1::CustomResourceDefinitionStatus {
                conditions: vec![
                    apiext_v1::CustomResourceDefinitionCondition {
                        r#type: Some("Established".to_string()),
                        status: Some("True".to_string()),
                        reason: Some("InitialNamesAccepted".to_string()),
                        message: Some("the initial names have been accepted".to_string()),
                        ..Default::default()
                    },
                    // The conformance test appends a condition with only Message set —
                    // Type and Status remain empty strings but ARE present on the wire
                    // (they are required, non-omitempty fields in the k8s API).
                    apiext_v1::CustomResourceDefinitionCondition {
                        r#type: Some(String::new()),
                        status: Some(String::new()),
                        message: Some("updated".to_string()),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
        };

        let mut buf = Vec::new();
        crd.encode(&mut buf).expect("prost encode must succeed");

        let result = crate::apiextensions_gen_adapter::decode_crd_proto_gen(&buf)
            .expect("CRD with status must decode");

        let conditions = result["status"]["conditions"].as_array().expect(
            "status.conditions must be present — without it, a protobuf status \
                     subresource PUT/PATCH silently wipes the CRD's conditions",
        );
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0]["type"], "Established");
        assert_eq!(conditions[0]["reason"], "InitialNamesAccepted");
        assert_eq!(
            conditions[1]["message"], "updated",
            "a condition with empty type/status but a message must still survive proto \
             decode — this is exactly the client-appended condition the conformance test \
             looks for in the response"
        );
        assert_eq!(
            conditions[1]["type"], "",
            "type must be present as an empty string, not omitted, matching the \
             non-omitempty wire contract of CustomResourceDefinitionCondition"
        );
    }
}
