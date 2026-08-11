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
];

/// Fields the decoders deliberately do not emit. Each entry is a decision, not an oversight;
/// anything that is merely *not yet implemented* belongs in `KNOWN_GAPS` instead so the two stay
/// distinguishable in review.
///
/// All four ObjectMeta entries are dropped by every one of the twelve `gen_object_meta_to_json`
/// copies. That is safe only because something downstream compensates, and the compensating
/// control is named per entry — an entry whose control is removed becomes a bug, so the note is
/// the thing to check, not the omission itself.
const DELIBERATE_OMISSIONS: &[(&str, &str, &str)] = &[
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "selfLink",
        "legacy field upstream no longer populates; see the .proto's own Deprecated comment",
    ),
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "deletionTimestamp",
        "restored from the stored object by replace_resource/replace_namespaced_resource and \
         listed in handlers::status::merge_incoming_metadata's PROTECTED set (mayor-2mi3e, #888)",
    ),
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "deletionGracePeriodSeconds",
        "restored from the stored object alongside deletionTimestamp (mayor-2mi3e, #888)",
    ),
    (
        ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        "managedFields",
        "stripped/synthesized server-side on every path, so a client-supplied value is never \
         honoured (mayor-2mi3e); revisit if full Server-Side Apply lands (mayor-u6ju)",
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

/// The JSON keys a fully-populated `root` must produce, following message-typed fields
/// transitively.
///
/// Each message type is expanded at most once. That matches `u7s_sentinel::sentinel_guard`, which
/// returns `Default::default()` when a type is re-entered while already being built — so a
/// recursive type like `JSONSchemaProps` contributes its field names once and its self-referential
/// branches bottom out, exactly as the sentinel instance does.
pub(crate) fn expected_json_keys(root: &str) -> BTreeSet<String> {
    let index = message_index();
    let mut keys = BTreeSet::new();
    let mut expanded = BTreeSet::new();
    walk(index, root, &mut keys, &mut expanded);
    keys
}

/// Union of `expected_json_keys` over several roots, for decoders whose output combines more than
/// one top-level message (typically `ObjectMeta` plus a spec and/or status).
pub(crate) fn expected_json_keys_for(roots: &[&str]) -> BTreeSet<String> {
    roots.iter().flat_map(|r| expected_json_keys(r)).collect()
}

fn walk(
    index: &HashMap<String, DescriptorProto>,
    message_name: &str,
    keys: &mut BTreeSet<String>,
    expanded: &mut BTreeSet<String>,
) {
    if OPAQUE_MESSAGES.contains(&message_name) || !expanded.insert(message_name.to_string()) {
        return;
    }
    let Some(message) = index.get(message_name) else {
        panic!("message {message_name} is not present in the descriptor set");
    };

    let is_map_entry = message.options.as_ref().is_some_and(|o| o.map_entry());

    for field in &message.field {
        // A field that is never emitted cannot contribute its children either, so an excluded
        // message-typed field stops the walk rather than demanding sub-keys that can only appear
        // if the parent does.
        if !is_map_entry && is_excluded(message_name, field.name()) {
            continue;
        }
        // A map<K, V> is one JSON object keyed by the map's own field name; protoc's synthetic
        // `key`/`value` fields are an encoding detail and never appear as JSON keys. The value
        // type is still walked so a message-valued map contributes its fields.
        if !is_map_entry {
            keys.insert(json_key(message_name, field.name(), field.json_name()));
        }
        if matches!(field.r#type(), Type::Message | Type::Group) {
            walk(index, field.type_name(), keys, expanded);
        }
    }
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

    /// A map<string,string> contributes only its own field name. Without the map_entry guard the
    /// oracle would demand literal `key`/`value` keys in every object carrying labels.
    #[test]
    fn treats_map_fields_as_a_single_key() {
        let keys = expected_json_keys(".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta");
        assert!(keys.contains("labels") && keys.contains("annotations"));
        assert!(
            !keys.contains("key") && !keys.contains("value"),
            "protoc's synthetic map-entry key/value fields are an encoding detail and must not be \
             expected as JSON keys"
        );
    }

    /// The self-referential branches of JSONSchemaProps must not make the walk diverge.
    #[test]
    fn terminates_on_self_referential_messages() {
        let keys = expected_json_keys(
            ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
        );
        assert!(keys.contains("$ref") && keys.contains("$schema"));
        assert!(
            keys.contains("allOf") && keys.contains("properties"),
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
                                !paths.iter().any(|p| p.split('.').any(|s| s == f.as_str()))
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
