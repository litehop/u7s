// Shared exception-table data for the vendored `k8s.io` protobuf schema: which messages are
// opaque scalars on the wire, which fields are renamed/inline-embedded/deliberately omitted in
// JSON, and the mechanical JSON-key derivation rule. Spliced (via `include!`) into two separate
// compilation units that both need this same data without either depending on the other:
// `src/proto_descriptor.rs`'s `#[cfg(test)]` sentinel-completeness oracle, and
// `build/codegen.rs`'s VolumeSource codegen (a build script, which cannot `use` anything from
// the crate it is building). Plain data/functions only — no `#[cfg(test)]` in this file itself,
// since `build/codegen.rs` needs it unconditionally on every build, not just under `cargo test`.
//
// In this schema the proto field name *is* the JSON key — verified across all 2466 fields of the
// vendored protos, `json_name` never differs from `name`. Only two mechanical adjustments and a
// short list of type-level exceptions are needed; both are encoded below.

/// Messages whose Kubernetes JSON form is a scalar or an inlined document rather than an object
/// mirroring their proto fields. Their *own* field names (`string`, `intVal`, `seconds`, `raw`,
/// ...) must never appear in decoded JSON, so the walk stops here and contributes nothing.
///
/// Only `proto_descriptor.rs`'s `walk()` consults this table by name (`build/codegen.rs`'s
/// VolumeSource codegen checks its one relevant entry, `Quantity`, directly by FQN instead) —
/// `#[allow(dead_code)]` because that makes it unused dead code in the build-script compilation
/// this file is also spliced into.
#[allow(dead_code)]
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
         handlers::status::merge_incoming_metadata's PROTECTED set (#888)",
    ),
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "deletionGracePeriodSeconds",
        "NOT marked `Deprecated:` upstream — omitted for the same compensating-control \
         reason as deletionTimestamp: restored from the stored object alongside it \
         (#888)",
    ),
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "managedFields",
        "NOT marked `Deprecated:` upstream — omitted for a compensating-control reason, not \
         deprecation: stripped/synthesized server-side on every path, so a client-supplied \
         value is never honoured; revisit if full Server-Side Apply lands",
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
        "fc",
        "legacy in-tree volume plugin; NOT marked `Deprecated:` upstream as of the vendored \
         proto snapshot — omitted on its own merits as a protocol-specific block-storage \
         plugin with no CSI-agnostic value to this control plane, not because upstream has \
         deprecated it. Revisit if upstream formally deprecates/removes it.",
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
        "photonPersistentDisk",
        "legacy in-tree volume plugin; upstream `Deprecated: PhotonPersistentDisk is \
         deprecated and the in-tree photonPersistentDisk type is no longer supported.` (no \
         CSI replacement named upstream — Photon Controller itself is defunct; no \
         release-note traceable, comment-only upstream change). u7s policy: defer to CSI \
         migration path, no plan to implement",
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
/// the same change. Every entry here is a live bug with a bead. Empty today: the rollout is
/// expected to fill it as the ~110 surveyed candidates are triaged, and each entry
/// should leave with a fix rather than be edited to stay.
const KNOWN_GAPS: &[(&str, &str, &str)] = &[];

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
