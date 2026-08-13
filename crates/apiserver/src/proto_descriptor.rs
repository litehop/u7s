//! Test-only: derives the set of JSON keys a decoder must emit for a protobuf message directly
//! from the compiled `FileDescriptorSet`, instead of from a hand-written string list.
//!
//! Why this exists: the sentinel completeness tests (see `util::sentinel_test_util`) check a
//! decoder's output against an `expected` array that a human typed by reading the very
//! `gen_*_to_json` function under test. That makes the oracle a second copy of the same
//! enumeration — if a field is forgotten in both places the test passes green. `PodStatus` is the
//! worked example (mayor-y0pcm): `gen_pod_status_to_json` was itself written to fix an earlier
//! drop of the whole `.status` subtree, shipped a regression test asserting `phase`/`podIP`/
//! `conditions`, and left `containerStatuses` out of both the emitter and the expected list — so a
//! protobuf `UpdateStatus` deleted it from the stored pod, under a green suite, for as long as the
//! test existed. Deriving the list from the schema removes the human from the oracle: a field
//! added upstream shows up in the expected set automatically, whether anyone remembers it or not.
//!
//! Scope limit worth knowing before trusting a green result: `assert_fields_present` matches a key
//! against *any* path segment anywhere in the decoded tree, so a nested struct counts as covered
//! the moment one of its leaves survives (mayor-66qj6). This module fixes the *list*, not the
//! *matcher* — until 66qj6 lands, counts produced here are lower bounds on what is really missing.
//!
//! In this schema the proto field name *is* the JSON key — verified across all 2466 fields of the
//! vendored protos, `json_name` never differs from `name`. Only two mechanical adjustments and a
//! short list of type-level exceptions are needed; both are encoded below.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use prost::Message;
use prost_types::{field_descriptor_proto::Type, DescriptorProto, FileDescriptorSet};

/// The descriptor set protoc emits next to the generated structs (see `build.rs`).
const DESCRIPTOR_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/k8s_descriptors.bin"));

/// Messages whose Kubernetes JSON form is a scalar or an inlined document rather than an object
/// mirroring their proto fields. Their *own* field names (`string`, `intVal`, `seconds`, `raw`,
/// ...) must never appear in decoded JSON, so the walk stops here and contributes nothing.
const OPAQUE_MESSAGES: &[&str] = &[
    // `{string: "100m"}` on the wire, a bare string in JSON.
    ".k8s.io.apimachinery.pkg.api.resource.Quantity",
    ".k8s.io.apimachinery.pkg.api.resource.QuantityValue",
    // `{type, intVal, strVal}` on the wire, a bare int or string in JSON.
    ".k8s.io.apimachinery.pkg.util.intstr.IntOrString",
    // `{seconds, nanos}` on the wire, an RFC3339 string in JSON.
    ".k8s.io.apimachinery.pkg.apis.meta.v1.Time",
    ".k8s.io.apimachinery.pkg.apis.meta.v1.MicroTime",
    // `{raw: bytes}` on the wire, the embedded document inlined in JSON.
    ".k8s.io.apimachinery.pkg.runtime.RawExtension",
    ".k8s.io.apimachinery.pkg.apis.meta.v1.FieldsV1",
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSON",
    // `{items: repeated string}` on the wire — protobuf's only way to put a repeated scalar in a
    // map value — but Go's `type ExtraValue []string` marshals as a bare JSON string array, not
    // `{"items": [...]}`. Two separate proto messages share this exact shape and Go type,
    // confirmed against `gen_certificate_signing_request_spec_to_json`
    // (net_disc_cert_policy_events_gen_adapter.rs) and `gen_sar_spec_to_json`
    // (rbac_gen_adapter.rs), both of which assign `v.items` directly as the map entry's value.
    ".k8s.io.api.certificates.v1.ExtraValue",
    ".k8s.io.api.authorization.v1.ExtraValue",
];

/// Fields whose JSON key is not derivable from the proto field name at all.
const RENAMES: &[(&str, &str, &str)] = &[
    (
        ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        "ref",
        "$ref",
    ),
    (
        ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        "schema",
        "$schema",
    ),
    // JSONSchemaProps' x-kubernetes-* fields mirror the upstream OpenAPI/CRD schema's own
    // kebab-case JSON keys (see the .proto field comments, e.g. "x-kubernetes-preserve-unknown-
    // fields stops the API server..."), not the mechanical camelCase `json_name` protoc derives
    // from the Go-style field name — confirmed against `gen_json_schema_props_to_json`
    // (apiextensions_gen_adapter.rs), which emits these exact kebab-case keys.
    (
        ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        "xKubernetesPreserveUnknownFields",
        "x-kubernetes-preserve-unknown-fields",
    ),
    (
        ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        "xKubernetesEmbeddedResource",
        "x-kubernetes-embedded-resource",
    ),
    (
        ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        "xKubernetesIntOrString",
        "x-kubernetes-int-or-string",
    ),
    (
        ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        "xKubernetesListMapKeys",
        "x-kubernetes-list-map-keys",
    ),
    (
        ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        "xKubernetesListType",
        "x-kubernetes-list-type",
    ),
    (
        ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        "xKubernetesMapType",
        "x-kubernetes-map-type",
    ),
    (
        ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        "xKubernetesValidations",
        "x-kubernetes-validations",
    ),
];

/// Fields that hold a Go `json:",inline"` embed: the embedded message's fields appear directly on
/// the parent in JSON, and the proto field name used for the embed (e.g. `localObjectReference`)
/// never appears as a JSON key at all. `walk()` must still descend into the embedded message —
/// only the field's own name is suppressed — which is why this is a separate table from
/// `DELIBERATE_OMISSIONS`: an omission stops the walk, an inline embed redirects it.
const INLINE_EMBEDS: &[(&str, &str)] = &[
    (
        ".k8s.io.api.core.v1.ConfigMapEnvSource",
        "localObjectReference",
    ),
    (
        ".k8s.io.api.core.v1.ConfigMapKeySelector",
        "localObjectReference",
    ),
    (
        ".k8s.io.api.core.v1.ConfigMapProjection",
        "localObjectReference",
    ),
    (
        ".k8s.io.api.core.v1.ConfigMapVolumeSource",
        "localObjectReference",
    ),
    (
        ".k8s.io.api.core.v1.SecretEnvSource",
        "localObjectReference",
    ),
    (
        ".k8s.io.api.core.v1.SecretKeySelector",
        "localObjectReference",
    ),
    (
        ".k8s.io.api.core.v1.SecretProjection",
        "localObjectReference",
    ),
    (
        ".k8s.io.api.core.v1.EphemeralContainer",
        "ephemeralContainerCommon",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSpec",
        "persistentVolumeSource",
    ),
    (".k8s.io.api.core.v1.Volume", "volumeSource"),
    // `Probe` Go-embeds `ProbeHandler` inline via a field literally named `handler` — the
    // generated.proto comment has no `Deprecated:` marker at all, so this is not a
    // DELIBERATE_OMISSIONS case (there's no deprecation to cite, and `core_gen_adapter.rs`'s
    // `gen_probe_to_json` already inserts exec/httpGet/tcpSocket/grpc directly onto the
    // Probe's own JSON object, matching upstream's inline serialization exactly). Without this
    // entry the walk demanded a literal `handler` key no correct decoder can ever produce,
    // which would have permanently blocked a zero-KNOWN_GAPS sentinel test on every decoder
    // reaching a livenessProbe/readinessProbe/startupProbe.
    (".k8s.io.api.core.v1.Probe", "handler"),
    // `RuleWithOperations` Go-embeds `Rule` inline via a field literally named `rule` ("Rule is
    // embedded, it describes other criteria of the rule, like APIGroups, APIVersions,
    // Resources, etc." per the .proto comment); `gen_rule_with_operations_to_json`
    // (admissionreg_gen_adapter.rs) already inserts apiGroups/apiVersions/resources/scope
    // directly onto the RuleWithOperations object, matching upstream's inline serialization.
    (
        ".k8s.io.api.admissionregistration.v1.RuleWithOperations",
        "rule",
    ),
    // `NamedRuleWithOperations` Go-embeds `RuleWithOperations` inline via a field literally
    // named `ruleWithOperations`, the same pattern one level up.
    (
        ".k8s.io.api.admissionregistration.v1.NamedRuleWithOperations",
        "ruleWithOperations",
    ),
];

/// Fields the decoders deliberately do not emit. Each entry is a decision, not an oversight;
/// anything that is merely *not yet implemented* belongs in `KNOWN_GAPS` instead so the two stay
/// distinguishable in review.
///
/// All four ObjectMeta entries are dropped by the single shared `gen_object_meta_to_json`, which
/// every adapter delegates to rather than reimplementing. That is safe only because something
/// downstream compensates, and the compensating control is named per entry — an entry whose
/// control is removed becomes a bug, so the note is the thing to check, not the omission itself.
const DELIBERATE_OMISSIONS: &[(&str, &str, &str)] = &[
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "selfLink",
        "upstream `Deprecated: selfLink is a legacy read-only field that is no longer \
         populated by the system.` — genuinely deprecation-driven, the only one of the \
         four ObjectMeta omissions that is; no release-note traceable, comment-only \
         upstream change",
    ),
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "deletionTimestamp",
        "NOT marked `Deprecated:` upstream (plain `optional Time deletionTimestamp = 9`) — \
         omitted for a compensating-control reason, not deprecation: restored from the \
         stored object by replace_resource/replace_namespaced_resource and listed in \
         handlers::status::merge_incoming_metadata's PROTECTED set (mayor-2mi3e, #888)",
    ),
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "deletionGracePeriodSeconds",
        "NOT marked `Deprecated:` upstream — omitted for the same compensating-control \
         reason as deletionTimestamp: restored from the stored object alongside it \
         (mayor-2mi3e, #888)",
    ),
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "managedFields",
        "NOT marked `Deprecated:` upstream — omitted for a compensating-control reason, not \
         deprecation: stripped/synthesized server-side on every path, so a client-supplied \
         value is never honoured (mayor-2mi3e); revisit if full Server-Side Apply lands \
         (mayor-u6ju)",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "awsElasticBlockStore",
        "legacy in-tree volume plugin; upstream `Deprecated: AWSElasticBlockStore is \
         deprecated. All operations for the in-tree awsElasticBlockStore type are \
         redirected to the ebs.csi.aws.com CSI driver.` (ebs.csi.aws.com is the named CSI \
         replacement; no release-note traceable, comment-only upstream change). u7s policy: \
         defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "azureDisk",
        "legacy in-tree volume plugin; upstream `Deprecated: AzureDisk is deprecated. All \
         operations for the in-tree azureDisk type are redirected to the disk.csi.azure.com \
         CSI driver.` (disk.csi.azure.com is the named CSI replacement; no release-note \
         traceable, comment-only upstream change). u7s policy: defer to CSI migration path, \
         no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "azureFile",
        "legacy in-tree volume plugin; upstream `Deprecated: AzureFile is deprecated. All \
         operations for the in-tree azureFile type are redirected to the file.csi.azure.com \
         CSI driver.` (file.csi.azure.com is the named CSI replacement; plugin-code removal \
         release-noted in CHANGELOG-1.28, kubernetes/kubernetes#118236, and the in-tree \
         cloud-provider deprecation release-noted separately in CHANGELOG-1.30, \
         kubernetes/kubernetes#122576 — two distinct events, neither is this API field's \
         own comment). u7s policy: defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "cephfs",
        "legacy in-tree volume plugin; upstream `Deprecated: CephFS is deprecated and the \
         in-tree cephfs type is no longer supported.` (CephFS CSI driver is the \
         replacement; deprecation release-noted in CHANGELOG-1.28, \
         kubernetes/kubernetes#118143). u7s policy: defer to CSI migration path, no plan to \
         implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "cinder",
        "legacy in-tree volume plugin; upstream `Deprecated: Cinder is deprecated. All \
         operations for the in-tree cinder type are redirected to the \
         cinder.csi.openstack.org CSI driver.` (cinder.csi.openstack.org is the named CSI \
         replacement; no release-note traceable, comment-only upstream change). u7s policy: \
         defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "fc",
        "legacy in-tree volume plugin; NOT marked `Deprecated:` upstream as of the vendored \
         proto snapshot — omitted on its own merits as a protocol-specific block-storage \
         plugin with no CSI-agnostic value to this control plane, not because upstream has \
         deprecated it. Revisit if upstream formally deprecates/removes it.",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "flexVolume",
        "legacy in-tree volume plugin; upstream `Deprecated: FlexVolume is deprecated. \
         Consider using a CSIDriver instead.` (no specific CSI driver named upstream; no \
         release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "flocker",
        "legacy in-tree volume plugin; upstream `Deprecated: Flocker is deprecated and the \
         in-tree flocker type is no longer supported.` (no CSI replacement named upstream — \
         Flocker itself is defunct; no release-note traceable, comment-only upstream \
         change). u7s policy: defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "gcePersistentDisk",
        "legacy in-tree volume plugin; upstream `Deprecated: GCEPersistentDisk is \
         deprecated. All operations for the in-tree gcePersistentDisk type are redirected \
         to the pd.csi.storage.gke.io CSI driver.` (pd.csi.storage.gke.io is the named CSI \
         replacement; no release-note traceable, comment-only upstream change). u7s policy: \
         defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "gitRepo",
        "legacy in-tree volume plugin; upstream `Deprecated: GitRepo is deprecated. To \
         provision a container with a git repo, mount an EmptyDir into an InitContainer \
         that clones the repo using git, then mount the EmptyDir into the Pod's \
         container.` (no CSI angle — upstream's own suggested replacement is an \
         EmptyDir + InitContainer pattern, not a CSI driver; no release-note traceable, \
         comment-only upstream change). u7s policy: defer to the upstream-recommended \
         EmptyDir/InitContainer pattern, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "glusterfs",
        "legacy in-tree volume plugin; upstream `Deprecated: Glusterfs is deprecated and \
         the in-tree glusterfs type is no longer supported.` (no CSI replacement named \
         upstream; no release-note traceable, comment-only upstream change). u7s policy: \
         defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "iscsi",
        "legacy in-tree volume plugin; NOT marked `Deprecated:` upstream as of the vendored \
         proto snapshot — omitted on its own merits as a protocol-specific block-storage \
         plugin with no CSI-agnostic value to this control plane, not because upstream has \
         deprecated it. Revisit if upstream formally deprecates/removes it.",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "photonPersistentDisk",
        "legacy in-tree volume plugin; upstream `Deprecated: PhotonPersistentDisk is \
         deprecated and the in-tree photonPersistentDisk type is no longer supported.` (no \
         CSI replacement named upstream — Photon Controller itself is defunct; no \
         release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "portworxVolume",
        "legacy in-tree volume plugin; upstream `Deprecated: PortworxVolume is deprecated. \
         All operations for the in-tree portworxVolume type are redirected to the \
         pxd.portworx.com CSI driver.` (pxd.portworx.com is the named CSI replacement; no \
         release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "quobyte",
        "legacy in-tree volume plugin; upstream `Deprecated: Quobyte is deprecated and the \
         in-tree quobyte type is no longer supported.` (no CSI replacement named upstream; \
         no release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "rbd",
        "legacy in-tree volume plugin; upstream `Deprecated: RBD is deprecated and the \
         in-tree rbd type is no longer supported.` (RBD CSI driver is the replacement; \
         deprecation release-noted in CHANGELOG-1.28, kubernetes/kubernetes#118552). u7s \
         policy: defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "scaleIO",
        "legacy in-tree volume plugin; upstream `Deprecated: ScaleIO is deprecated and the \
         in-tree scaleIO type is no longer supported.` (no CSI replacement named upstream; \
         no release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "storageos",
        "legacy in-tree volume plugin; upstream `Deprecated: StorageOS is deprecated and \
         the in-tree storageos type is no longer supported.` (no CSI replacement named \
         upstream — StorageOS itself is defunct; no release-note traceable, comment-only \
         upstream change). u7s policy: defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.VolumeSource",
        "vsphereVolume",
        "legacy in-tree volume plugin; upstream `Deprecated: VsphereVolume is deprecated. \
         All operations for the in-tree vsphereVolume type are redirected to the \
         csi.vsphere.vmware.com CSI driver.` (csi.vsphere.vmware.com is the named CSI \
         replacement; the adjacent in-tree vSphere cloud provider — not this API field \
         itself — was deprecated/removed and release-noted in CHANGELOG-1.30, \
         kubernetes/kubernetes#122937). u7s policy: defer to CSI migration path, no plan to \
         implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "awsElasticBlockStore",
        "legacy in-tree volume plugin; upstream `Deprecated: AWSElasticBlockStore is \
         deprecated. All operations for the in-tree awsElasticBlockStore type are \
         redirected to the ebs.csi.aws.com CSI driver.` (ebs.csi.aws.com is the named CSI \
         replacement; no release-note traceable, comment-only upstream change). u7s policy: \
         defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "azureDisk",
        "legacy in-tree volume plugin; upstream `Deprecated: AzureDisk is deprecated. All \
         operations for the in-tree azureDisk type are redirected to the disk.csi.azure.com \
         CSI driver.` (disk.csi.azure.com is the named CSI replacement; no release-note \
         traceable, comment-only upstream change). u7s policy: defer to CSI migration path, \
         no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "azureFile",
        "legacy in-tree volume plugin; upstream `Deprecated: AzureFile is deprecated. All \
         operations for the in-tree azureFile type are redirected to the file.csi.azure.com \
         CSI driver.` (file.csi.azure.com is the named CSI replacement; plugin-code removal \
         release-noted in CHANGELOG-1.28, kubernetes/kubernetes#118236, and the in-tree \
         cloud-provider deprecation release-noted separately in CHANGELOG-1.30, \
         kubernetes/kubernetes#122576 — two distinct events, neither is this API field's \
         own comment). u7s policy: defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "cephfs",
        "legacy in-tree volume plugin; upstream `Deprecated: CephFS is deprecated and the \
         in-tree cephfs type is no longer supported.` (CephFS CSI driver is the \
         replacement; deprecation release-noted in CHANGELOG-1.28, \
         kubernetes/kubernetes#118143). u7s policy: defer to CSI migration path, no plan to \
         implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "cinder",
        "legacy in-tree volume plugin; upstream `Deprecated: Cinder is deprecated. All \
         operations for the in-tree cinder type are redirected to the \
         cinder.csi.openstack.org CSI driver.` (cinder.csi.openstack.org is the named CSI \
         replacement; no release-note traceable, comment-only upstream change). u7s policy: \
         defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "fc",
        "legacy in-tree volume plugin; NOT marked `Deprecated:` upstream as of the vendored \
         proto snapshot — omitted on its own merits as a protocol-specific block-storage \
         plugin with no CSI-agnostic value to this control plane, not because upstream has \
         deprecated it. Revisit if upstream formally deprecates/removes it.",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "flexVolume",
        "legacy in-tree volume plugin; upstream `Deprecated: FlexVolume is deprecated. \
         Consider using a CSIDriver instead.` (no specific CSI driver named upstream; no \
         release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "flocker",
        "legacy in-tree volume plugin; upstream `Deprecated: Flocker is deprecated and the \
         in-tree flocker type is no longer supported.` (no CSI replacement named upstream — \
         Flocker itself is defunct; no release-note traceable, comment-only upstream \
         change). u7s policy: defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "gcePersistentDisk",
        "legacy in-tree volume plugin; upstream `Deprecated: GCEPersistentDisk is \
         deprecated. All operations for the in-tree gcePersistentDisk type are redirected \
         to the pd.csi.storage.gke.io CSI driver.` (pd.csi.storage.gke.io is the named CSI \
         replacement; no release-note traceable, comment-only upstream change). u7s policy: \
         defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "glusterfs",
        "legacy in-tree volume plugin; upstream `Deprecated: Glusterfs is deprecated and \
         the in-tree glusterfs type is no longer supported.` (no CSI replacement named \
         upstream; no release-note traceable, comment-only upstream change). u7s policy: \
         defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "iscsi",
        "legacy in-tree volume plugin; NOT marked `Deprecated:` upstream as of the vendored \
         proto snapshot — omitted on its own merits as a protocol-specific block-storage \
         plugin with no CSI-agnostic value to this control plane, not because upstream has \
         deprecated it. Revisit if upstream formally deprecates/removes it.",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "photonPersistentDisk",
        "legacy in-tree volume plugin; upstream `Deprecated: PhotonPersistentDisk is \
         deprecated and the in-tree photonPersistentDisk type is no longer supported.` (no \
         CSI replacement named upstream — Photon Controller itself is defunct; no \
         release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "portworxVolume",
        "legacy in-tree volume plugin; upstream `Deprecated: PortworxVolume is deprecated. \
         All operations for the in-tree portworxVolume type are redirected to the \
         pxd.portworx.com CSI driver.` (pxd.portworx.com is the named CSI replacement; no \
         release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "quobyte",
        "legacy in-tree volume plugin; upstream `Deprecated: Quobyte is deprecated and the \
         in-tree quobyte type is no longer supported.` (no CSI replacement named upstream; \
         no release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "rbd",
        "legacy in-tree volume plugin; upstream `Deprecated: RBD is deprecated and the \
         in-tree rbd type is no longer supported.` (RBD CSI driver is the replacement; \
         deprecation release-noted in CHANGELOG-1.28, kubernetes/kubernetes#118552). u7s \
         policy: defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "scaleIO",
        "legacy in-tree volume plugin; upstream `Deprecated: ScaleIO is deprecated and the \
         in-tree scaleIO type is no longer supported.` (no CSI replacement named upstream; \
         no release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "storageos",
        "legacy in-tree volume plugin; upstream `Deprecated: StorageOS is deprecated and \
         the in-tree storageos type is no longer supported.` (no CSI replacement named \
         upstream — StorageOS itself is defunct; no release-note traceable, comment-only \
         upstream change). u7s policy: defer to CSI migration path, no plan to implement",
    ),
    (
        ".k8s.io.api.core.v1.PersistentVolumeSource",
        "vsphereVolume",
        "legacy in-tree volume plugin; upstream `Deprecated: VsphereVolume is deprecated. \
         All operations for the in-tree vsphereVolume type are redirected to the \
         csi.vsphere.vmware.com CSI driver.` (csi.vsphere.vmware.com is the named CSI \
         replacement; the adjacent in-tree vSphere cloud provider — not this API field \
         itself — was deprecated/removed and release-noted in CHANGELOG-1.30, \
         kubernetes/kubernetes#122937). u7s policy: defer to CSI migration path, no plan to \
         implement",
    ),
];

/// Real drops that are tolerated so this oracle can be adopted without turning the suite red in
/// the same change. Every entry here is a live bug with a bead. Empty today: the rollout in
/// mayor-j430l is expected to fill it as the ~110 surveyed candidates are triaged, and each entry
/// should leave with a fix rather than be edited to stay.
const KNOWN_GAPS: &[(&str, &str, &str)] = &[];

/// Every message in the vendored schema, indexed by fully-qualified name with a leading dot so
/// lookups can use `FieldDescriptorProto::type_name` verbatim.
fn message_index() -> &'static HashMap<String, DescriptorProto> {
    static INDEX: OnceLock<HashMap<String, DescriptorProto>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let set = FileDescriptorSet::decode(DESCRIPTOR_BYTES)
            .expect("descriptor set emitted by build.rs must decode");
        let mut index = HashMap::new();
        for file in &set.file {
            let package = file.package().to_string();
            for message in &file.message_type {
                insert_message(&mut index, &format!(".{package}"), message);
            }
        }
        index
    })
}

/// Registers `message` and, recursively, its nested types (which include the synthetic `*Entry`
/// messages protoc generates for `map<K, V>` fields).
fn insert_message(
    index: &mut HashMap<String, DescriptorProto>,
    prefix: &str,
    message: &DescriptorProto,
) {
    let full_name = format!("{prefix}.{}", message.name());
    for nested in &message.nested_type {
        insert_message(index, &full_name, nested);
    }
    index.insert(full_name, message.clone());
}

/// The JSON key for a field, applying the two mechanical adjustments this schema needs.
fn json_key(owner: &str, field_name: &str, json_name: &str) -> String {
    if let Some((_, _, renamed)) = RENAMES
        .iter()
        .find(|(msg, field, _)| *msg == owner && *field == field_name)
    {
        return (*renamed).to_string();
    }
    // protoc's json_name only strips underscores; it leaves a leading capital alone. Six fields
    // in this schema are declared with a Go-style capitalised name (DaemonEndpoint.Port,
    // {Mutating,Validating}WebhookConfiguration.Webhooks, MatchCondition.Expression,
    // Variable.Name/Expression) while their Kubernetes JSON key is lowerCamel.
    let mut chars = json_name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {
            first.to_ascii_lowercase().to_string() + chars.as_str()
        }
        _ => json_name.to_string(),
    }
}

fn is_excluded(owner: &str, field_name: &str) -> bool {
    DELIBERATE_OMISSIONS
        .iter()
        .chain(KNOWN_GAPS.iter())
        .any(|(msg, field, _)| *msg == owner && *field == field_name)
}

fn is_inline_embed(owner: &str, field_name: &str) -> bool {
    INLINE_EMBEDS
        .iter()
        .any(|(msg, field)| *msg == owner && *field == field_name)
}

/// The JSON keys a fully-populated `root` must produce, following message-typed fields
/// transitively.
///
/// A message type is expanded at most once per recursion *stack*, not once ever: that matches
/// `u7s_sentinel::sentinel_guard`, which only short-circuits to `Default::default()` when `T` is
/// already being built further up the SAME call stack (it pushes on entry and pops on exit, so
/// sibling fields of the same type each get their own turn). A truly self-referential type like
/// `JSONSchemaProps` still bottoms out (it re-enters itself on the same stack), but two sibling
/// fields of an ordinary type — e.g. `PodSpec.containers` and `PodSpec.initContainers`, both
/// `Container` — must each contribute their own dotted leaves (`containers.name` AND
/// `initContainers.name`), because the sentinel populates both independently. A set keyed only by
/// type name (visited-once-ever) would silently expand just whichever field the descriptor
/// happens to declare first and leave the other with no leaves at all — worse than the coarse
/// bare-name output it replaces, since that field's whole subtree would go unchecked.
pub(crate) fn expected_json_keys(root: &str) -> BTreeSet<String> {
    let index = message_index();
    let mut keys = BTreeSet::new();
    let mut stack = Vec::new();
    walk(index, root, "", &mut keys, &mut stack);
    keys
}

/// Union of `expected_json_keys` over several roots, for decoders whose output combines more than
/// one top-level message (typically `ObjectMeta` plus a spec and/or status).
pub(crate) fn expected_json_keys_for(roots: &[&str]) -> BTreeSet<String> {
    roots.iter().flat_map(|r| expected_json_keys(r)).collect()
}

/// If `type_name` is protoc's synthetic message for a `map<K, V>` field, describes what the
/// map's value contributes: `Some(None)` for a scalar value (nothing further to walk — the
/// field's own path is the only thing worth demanding), `Some(Some(value_type))` for a
/// message-typed value (walk `value_type` to find its leaves), or `None` if `type_name` is not a
/// map entry at all.
fn map_value_type<'a>(
    index: &'a HashMap<String, DescriptorProto>,
    type_name: &str,
) -> Option<Option<&'a str>> {
    let entry = index.get(type_name)?;
    if !entry.options.as_ref().is_some_and(|o| o.map_entry()) {
        return None;
    }
    let value_field = entry.field.iter().find(|f| f.name() == "value")?;
    Some(match value_field.r#type() {
        Type::Message | Type::Group => Some(value_field.type_name()),
        _ => None,
    })
}

fn walk(
    index: &HashMap<String, DescriptorProto>,
    message_name: &str,
    parent: &str,
    keys: &mut BTreeSet<String>,
    stack: &mut Vec<String>,
) {
    if OPAQUE_MESSAGES.contains(&message_name) || stack.iter().any(|m| m == message_name) {
        return;
    }
    let Some(message) = index.get(message_name) else {
        panic!("message {message_name} is not present in the descriptor set");
    };

    let is_map_entry = message.options.as_ref().is_some_and(|o| o.map_entry());

    stack.push(message_name.to_string());

    for field in &message.field {
        // A field that is never emitted cannot contribute its children either, so an excluded
        // message-typed field stops the walk rather than demanding sub-keys that can only appear
        // if the parent does.
        if !is_map_entry && is_excluded(message_name, field.name()) {
            continue;
        }
        // A Go `json:",inline"` embed never contributes its own JSON key, but (unlike an
        // exclusion) the walk must still descend, at the SAME path, because the embedded
        // message's fields land directly on the parent rather than nesting under the embed's
        // own field name.
        if !is_map_entry && is_inline_embed(message_name, field.name()) {
            if matches!(field.r#type(), Type::Message | Type::Group) {
                walk(index, field.type_name(), parent, keys, stack);
            }
            continue;
        }
        if is_map_entry {
            // Inside a map-entry message the synthetic `key`/`value` fields are an encoding
            // detail; they are handled by the map-field branch below, in the PARENT's loop,
            // before `walk` ever recurses into an entry message directly.
            continue;
        }

        let key = json_key(message_name, field.name(), field.json_name());
        let path = if parent.is_empty() {
            key
        } else {
            format!("{parent}.{key}")
        };

        if !matches!(field.r#type(), Type::Message | Type::Group) {
            // A genuine scalar/enum leaf: its own path IS a real decoded leaf.
            keys.insert(path);
            continue;
        }

        // A map<K, V> is one JSON object keyed by the map's own field name, but everything
        // reachable *through* it sits under a data-dependent key the schema cannot know.
        // `u7s_sentinel`'s blanket `Sentinel for String` always returns the literal
        // `"__sentinel__"` for map keys, and every map key in this schema is a string
        // (protobuf disallows anything else, and every Kubernetes map in the vendored API is
        // `map[string]V`) — so a sentinel-populated map's one entry is deterministically keyed
        // `"__sentinel__"`, and that literal stands in for the real (arbitrary) data key.
        if let Some(value_type) = map_value_type(index, field.type_name()) {
            let map_entry_path = format!("{path}.__sentinel__");
            match value_type {
                None => {
                    keys.insert(map_entry_path);
                }
                Some(value_type_name) => {
                    let before = keys.len();
                    walk(index, value_type_name, &map_entry_path, keys, stack);
                    if keys.len() == before {
                        keys.insert(map_entry_path);
                    }
                }
            }
            continue;
        }

        // A message-typed field that is itself always emitted non-empty once its own leaves
        // are decoded (i.e. every struct-shaped field a Sentinel populates) is never itself a
        // JSON *leaf* — only its descendants are. Demanding the field's own name here as well
        // would be un-satisfiable by construction against real decoded JSON: only if the type
        // contributes zero leaves of its own (excluded down to nothing, or a genuinely
        // self-referential re-entry bottoming out) does the field's own name serve as the
        // leaf-level stand-in for "this substructure exists."
        let before = keys.len();
        walk(index, field.type_name(), &path, keys, stack);
        if keys.len() == before {
            keys.insert(path);
        }
    }

    stack.pop();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The oracle is only trustworthy if it agrees with a hand-written list that is already known
    /// to be correct. `LeaseSpec` is small enough to verify by eye against the .proto and has no
    /// exceptions of its own, so a mismatch here means the derivation itself is wrong rather than
    /// a decoder being incomplete.
    #[test]
    fn derives_lease_spec_keys_matching_the_proto() {
        let keys = expected_json_keys(".k8s.io.api.coordination.v1.LeaseSpec");
        let expected: BTreeSet<String> = [
            "holderIdentity",
            "leaseDurationSeconds",
            "acquireTime",
            "renewTime",
            "leaseTransitions",
            "strategy",
            "preferredHolder",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            keys, expected,
            "LeaseSpec's derived JSON keys must match its .proto fields exactly — a difference \
             means json_key()/walk() mis-derives keys, which would make every test using this \
             oracle unreliable"
        );
    }

    /// `metav1.Time` is `{seconds, nanos}` on the wire but an RFC3339 string in JSON. If the walk
    /// descended into it, every decoder test would demand `seconds`/`nanos` keys that must never
    /// appear, so the opaque-type list would be silently load-bearing without a test.
    #[test]
    fn does_not_descend_into_scalar_wrapper_messages() {
        let keys = expected_json_keys(".k8s.io.api.coordination.v1.LeaseSpec");
        assert!(
            !keys.contains("seconds") && !keys.contains("nanos"),
            "acquireTime/renewTime are metav1.Time, which serializes as an RFC3339 string — \
             its proto fields must not be expected as JSON keys, got {keys:?}"
        );
    }

    /// A map<string,string>'s own field name is never itself a decoded *leaf* once populated —
    /// real JSON is `{"labels": {"<data-key>": "<data-value>"}}`, and the data key is something
    /// only the sentinel (not the schema) knows. `walk()` stands in the deterministic
    /// `u7s_sentinel` map key literal (`"__sentinel__"`, from its blanket `Sentinel for String`)
    /// so the oracle demands a leaf that a real sentinel-populated decode can actually produce.
    /// Without the map_entry guard the oracle would additionally demand literal `key`/`value`
    /// keys in every object carrying labels.
    #[test]
    fn treats_map_fields_as_a_single_key() {
        let keys = expected_json_keys(".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta");
        assert!(
            keys.contains("labels.__sentinel__") && keys.contains("annotations.__sentinel__"),
            "got {keys:?}"
        );
        assert!(
            !keys.contains("key") && !keys.contains("value"),
            "protoc's synthetic map-entry key/value fields are an encoding detail and must not be \
             expected as JSON keys"
        );
    }

    /// Go embeds `LocalObjectReference` inline via a field literally named `localObjectReference`
    /// on all four of these types. Without `INLINE_EMBEDS`, the oracle would demand a
    /// `localObjectReference` JSON key that a real ConfigMap-referencing decoder can never
    /// produce (only `name` is ever emitted), permanently blocking a zero-`KNOWN_GAPS` sentinel
    /// test for any decoder that reaches one of them.
    #[test]
    fn inlines_localobjectreference_embeds_in_configmap_sources() {
        for msg in [
            ".k8s.io.api.core.v1.ConfigMapEnvSource",
            ".k8s.io.api.core.v1.ConfigMapKeySelector",
            ".k8s.io.api.core.v1.ConfigMapProjection",
            ".k8s.io.api.core.v1.ConfigMapVolumeSource",
        ] {
            let keys = expected_json_keys(msg);
            assert!(
                keys.contains("name"),
                "{msg} embeds LocalObjectReference inline, so its `name` field must be reachable, got {keys:?}"
            );
            assert!(
                !keys.contains("localObjectReference"),
                "{msg}'s `localObjectReference` field is a Go inline embed, not a real JSON \
                 object — expecting it as a key would make a correct decoder look incomplete, \
                 got {keys:?}"
            );
        }
    }

    /// Same Go `json:",inline"` embed as the ConfigMap family, on the Secret family instead:
    /// `SecretVolumeSource` is excluded because it uses `secretName` directly and has no
    /// `LocalObjectReference` field at all (verified against generated.proto). Without these
    /// three entries, `localObjectReference` kept surfacing as a missing key everywhere a
    /// Secret-referencing field reaches Pod/PodTemplate/ReplicationController, even though no
    /// decoder can ever emit it.
    #[test]
    fn inlines_localobjectreference_embeds_in_secret_sources() {
        for msg in [
            ".k8s.io.api.core.v1.SecretEnvSource",
            ".k8s.io.api.core.v1.SecretKeySelector",
            ".k8s.io.api.core.v1.SecretProjection",
        ] {
            let keys = expected_json_keys(msg);
            assert!(
                keys.contains("name"),
                "{msg} embeds LocalObjectReference inline, so its `name` field must be reachable, got {keys:?}"
            );
            assert!(
                !keys.contains("localObjectReference"),
                "{msg}'s `localObjectReference` field is a Go inline embed, not a real JSON \
                 object — expecting it as a key would make a correct decoder look incomplete, \
                 got {keys:?}"
            );
        }
    }

    /// `EphemeralContainer` embeds `EphemeralContainerCommon` inline: `name`/`image` land
    /// directly on each `ephemeralContainers[]` entry, and `ephemeralContainerCommon` never
    /// appears as a JSON key.
    #[test]
    fn inlines_ephemeralcontainercommon_fields_onto_ephemeralcontainer() {
        let keys = expected_json_keys(".k8s.io.api.core.v1.EphemeralContainer");
        assert!(keys.contains("name") && keys.contains("image"));
        assert!(
            !keys.contains("ephemeralContainerCommon"),
            "ephemeralContainerCommon is a Go inline embed, not a JSON key a decoder can ever \
             emit, got {keys:?}"
        );
    }

    /// `PersistentVolumeSpec` embeds `PersistentVolumeSource` inline: plugin fields like `nfs`
    /// land directly under `spec`, and `persistentVolumeSource` never appears as a JSON key. `nfs`
    /// and `hostPath` are themselves non-empty structs once populated, so — like `metadata` or
    /// `spec` anywhere else — their OWN bare name is never a real decoded leaf; only their
    /// dotted-path descendants (`nfs.path`, `hostPath.path`) are.
    #[test]
    fn inlines_persistentvolumesource_fields_onto_persistentvolumespec() {
        let keys = expected_json_keys(".k8s.io.api.core.v1.PersistentVolumeSpec");
        assert!(
            keys.contains("nfs.path") && keys.contains("hostPath.path"),
            "got {keys:?}"
        );
        assert!(
            !keys.contains("persistentVolumeSource"),
            "persistentVolumeSource is a Go inline embed, not a JSON key a decoder can ever \
             emit, got {keys:?}"
        );
    }

    /// `Volume` embeds `VolumeSource` inline: plugin fields like `hostPath` land directly on each
    /// `volumes[]` entry, and `volumeSource` never appears as a JSON key. Same non-leaf-container
    /// reasoning as `PersistentVolumeSpec` above: only the dotted descendants are real leaves.
    #[test]
    fn inlines_volumesource_fields_onto_volume() {
        let keys = expected_json_keys(".k8s.io.api.core.v1.Volume");
        assert!(
            keys.contains("hostPath.path") && keys.contains("emptyDir.medium"),
            "got {keys:?}"
        );
        assert!(
            !keys.contains("volumeSource"),
            "volumeSource is a Go inline embed, not a JSON key a decoder can ever emit, got {keys:?}"
        );
    }

    /// `Probe` embeds `ProbeHandler` inline: `exec`/`httpGet`/`tcpSocket`/`grpc` land directly
    /// on each livenessProbe/readinessProbe/startupProbe, and `handler` never appears as a JSON
    /// key. Unlike the other `INLINE_EMBEDS` entries this one has no accompanying
    /// `DELIBERATE_OMISSIONS`-shaped deprecation story — `Probe.handler`'s .proto comment
    /// carries no `Deprecated:` marker, it is simply Go's inline-embed idiom. `exec`/`httpGet`
    /// are themselves non-empty structs once populated, so their dotted descendants
    /// (`exec.command`, `httpGet.path`) are the real leaves, not their own bare names.
    #[test]
    fn inlines_probehandler_fields_onto_probe() {
        let keys = expected_json_keys(".k8s.io.api.core.v1.Probe");
        assert!(
            keys.contains("exec.command") && keys.contains("httpGet.path"),
            "got {keys:?}"
        );
        assert!(
            !keys.contains("handler"),
            "handler is a Go inline embed, not a JSON key a decoder can ever emit, got {keys:?}"
        );
    }

    /// The self-referential branches of JSONSchemaProps must not make the walk diverge. `allOf`
    /// (`repeated JSONSchemaProps`) re-enters the same type on the same recursion stack, which
    /// bottoms out with zero descendant keys, so `allOf`'s own bare name is kept as the
    /// leaf-level stand-in. `properties` is a `map<string, JSONSchemaProps>`, so it additionally
    /// gets the deterministic sentinel map-key literal.
    #[test]
    fn terminates_on_self_referential_messages() {
        let keys = expected_json_keys(
            ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        );
        assert!(keys.contains("$ref") && keys.contains("$schema"));
        assert!(
            keys.contains("allOf") && keys.contains("properties.__sentinel__"),
            "recursive fields must still be expected once, got {keys:?}"
        );
    }

    /// Exploratory survey, not a gate: decodes a fully-populated sentinel through every decoder
    /// that currently has no sentinel completeness test and reports which schema fields never
    /// reach the JSON. Ignored by default because its job is to produce a work-list, not to pass
    /// or fail. Run with:
    ///   cargo test -p u7s-apiserver --lib -- --ignored --nocapture unprotected_decoder_survey
    #[test]
    #[ignore]
    fn unprotected_decoder_survey() {
        use crate::util::sentinel_test_util::collect_leaf_paths;
        use prost::Message as _;
        use u7s_sentinel::Sentinel;

        let mut rows: Vec<(String, usize, usize, String)> = Vec::new();

        macro_rules! survey {
            ($label:literal, $ty:ty, $msg:literal, $decoder:path) => {{
                let mut buf = Vec::new();
                <$ty>::sentinel().encode(&mut buf).unwrap();
                match $decoder(&buf) {
                    Some(decoded) => {
                        let mut paths = BTreeSet::new();
                        collect_leaf_paths(&decoded, "", &mut paths);
                        let expected = expected_json_keys($msg);
                        let missing: Vec<&str> = expected
                            .iter()
                            .filter(|f| {
                                !paths
                                    .iter()
                                    .any(|p| p == f.as_str() || p.ends_with(&format!(".{f}")))
                            })
                            .map(String::as_str)
                            .collect();
                        rows.push((
                            $label.to_string(),
                            expected.len(),
                            missing.len(),
                            missing.join(", "),
                        ));
                    }
                    None => rows.push(($label.to_string(), 0, 0, "DECODER RETURNED None".into())),
                }
            }};
        }

        use crate::apps_gen::k8s::io::api::autoscaling::v1 as as_v1;
        use crate::apps_gen::k8s::io::api::autoscaling::v2 as as_v2;
        use crate::apps_gen::k8s::io::api::core::v1 as cv1;
        use crate::apps_gen::k8s::io::api::resource::v1 as rv1;

        survey!(
            "core/Namespace",
            cv1::Namespace,
            ".k8s.io.api.core.v1.Namespace",
            crate::core_gen_adapter::decode_namespace_proto_gen
        );
        survey!(
            "core/ConfigMap",
            cv1::ConfigMap,
            ".k8s.io.api.core.v1.ConfigMap",
            crate::core_gen_adapter::decode_configmap_proto_gen
        );
        survey!(
            "core/PodTemplate",
            cv1::PodTemplate,
            ".k8s.io.api.core.v1.PodTemplate",
            crate::core_gen_adapter::decode_podtemplate_proto_gen
        );
        survey!(
            "core/Service",
            cv1::Service,
            ".k8s.io.api.core.v1.Service",
            crate::core_gen_adapter::decode_service_proto_gen
        );
        survey!(
            "core/Secret",
            cv1::Secret,
            ".k8s.io.api.core.v1.Secret",
            crate::core_gen_adapter::decode_secret_proto_gen
        );
        survey!(
            "core/Node",
            cv1::Node,
            ".k8s.io.api.core.v1.Node",
            crate::core_gen_adapter::decode_node_proto_gen
        );
        survey!(
            "core/PersistentVolume",
            cv1::PersistentVolume,
            ".k8s.io.api.core.v1.PersistentVolume",
            crate::core_gen_adapter::decode_persistentvolume_proto_gen
        );
        survey!(
            "core/ServiceAccount",
            cv1::ServiceAccount,
            ".k8s.io.api.core.v1.ServiceAccount",
            crate::core_gen_adapter::decode_serviceaccount_proto_gen
        );
        survey!(
            "core/Endpoints",
            cv1::Endpoints,
            ".k8s.io.api.core.v1.Endpoints",
            crate::core_gen_adapter::decode_endpoints_proto_gen
        );
        survey!(
            "core/ResourceQuota",
            cv1::ResourceQuota,
            ".k8s.io.api.core.v1.ResourceQuota",
            crate::core_gen_adapter::decode_resourcequota_proto_gen
        );
        survey!(
            "core/LimitRange",
            cv1::LimitRange,
            ".k8s.io.api.core.v1.LimitRange",
            crate::core_gen_adapter::decode_limitrange_proto_gen
        );
        survey!(
            "core/ReplicationController",
            cv1::ReplicationController,
            ".k8s.io.api.core.v1.ReplicationController",
            crate::core_gen_adapter::decode_replicationcontroller_proto_gen
        );
        survey!(
            "core/Event",
            cv1::Event,
            ".k8s.io.api.core.v1.Event",
            crate::core_gen_adapter::decode_event_proto_gen
        );
        survey!(
            "core/Pod",
            cv1::Pod,
            ".k8s.io.api.core.v1.Pod",
            crate::core_gen_adapter::decode_pod_proto_gen
        );
        survey!(
            "core/PersistentVolumeClaim",
            cv1::PersistentVolumeClaim,
            ".k8s.io.api.core.v1.PersistentVolumeClaim",
            crate::core_gen_adapter::decode_persistentvolumeclaim_proto_gen
        );
        survey!(
            "autoscaling/HPA v1",
            as_v1::HorizontalPodAutoscaler,
            ".k8s.io.api.autoscaling.v1.HorizontalPodAutoscaler",
            crate::autoscaling_gen_adapter::decode_hpa_v1_proto_gen
        );
        survey!(
            "autoscaling/HPA v2",
            as_v2::HorizontalPodAutoscaler,
            ".k8s.io.api.autoscaling.v2.HorizontalPodAutoscaler",
            crate::autoscaling_gen_adapter::decode_hpa_v2_proto_gen
        );
        survey!(
            "resource/DeviceClass",
            rv1::DeviceClass,
            ".k8s.io.api.resource.v1.DeviceClass",
            crate::resource_gen_adapter::decode_deviceclass_proto_gen
        );
        survey!(
            "resource/ResourceClaim",
            rv1::ResourceClaim,
            ".k8s.io.api.resource.v1.ResourceClaim",
            crate::resource_gen_adapter::decode_resourceclaim_proto_gen
        );
        survey!(
            "resource/ResourceClaimTemplate",
            rv1::ResourceClaimTemplate,
            ".k8s.io.api.resource.v1.ResourceClaimTemplate",
            crate::resource_gen_adapter::decode_resourceclaimtemplate_proto_gen
        );
        survey!(
            "resource/ResourceSlice",
            rv1::ResourceSlice,
            ".k8s.io.api.resource.v1.ResourceSlice",
            crate::resource_gen_adapter::decode_resourceslice_proto_gen
        );

        let total_expected: usize = rows.iter().map(|r| r.1).sum();
        let total_missing: usize = rows.iter().map(|r| r.2).sum();
        println!(
            "\n{:<32} {:>8} {:>8}  DROPPED",
            "DECODER", "FIELDS", "MISSING"
        );
        for (label, expected, missing, names) in &rows {
            println!("{label:<32} {expected:>8} {missing:>8}  {names}");
        }
        println!(
            "\nTOTAL: {total_missing} of {total_expected} schema fields never reach JSON across {} decoders",
            rows.len()
        );
    }

    /// The oracle's keys must be full dotted leaf paths, not bare field names — a bare `name`
    /// would satisfy `assert_fields_present` the moment ANY struct's `name` field anywhere in
    /// the decoded tree survives (the any-segment bug this oracle exists to avoid), so a dropped
    /// `Container.name` could hide behind `ObjectMeta.name` or any other unrelated `name`. The
    /// walk must instead emit `spec.containers.name`, which only a genuinely-decoded
    /// `PodSpec.containers[].name` can satisfy.
    #[test]
    fn walk_emits_dotted_leaf_paths_not_bare_field_names() {
        let keys = expected_json_keys(".k8s.io.api.core.v1.Pod");
        assert!(
            keys.contains("spec.containers.name"),
            "Pod's containers[].name must be expected as the dotted path spec.containers.name, \
             got {keys:?}"
        );
        assert!(
            !keys.contains("name"),
            "a bare \"name\" key must not appear in Pod's expected set — Pod has no top-level \
             \"name\" field of its own (only nested ones like metadata.name and \
             spec.containers.name), so a bare \"name\" here would mean the walk regressed to \
             any-segment-shaped output, got {keys:?}"
        );
    }

    /// Guards the leading-capital rule against the six Go-style field names in this schema.
    #[test]
    fn lowercases_go_style_capitalised_field_names() {
        let keys = expected_json_keys(".k8s.io.api.core.v1.DaemonEndpoint");
        assert!(
            keys.contains("port") && !keys.contains("Port"),
            "DaemonEndpoint declares `optional int32 Port` but Kubernetes JSON uses `port`; \
             expecting the capitalised form would make the test unfalsifiable, got {keys:?}"
        );
    }
}
