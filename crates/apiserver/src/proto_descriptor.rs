//! Test-only: derives the set of JSON keys a decoder must emit for a protobuf message directly
//! from the compiled `FileDescriptorSet`, instead of from a hand-written string list.
//!
//! Why this exists: the sentinel completeness tests (see `util::sentinel_test_util`) check a
//! decoder's output against an `expected` array that a human typed by reading the very
//! `gen_*_to_json` function under test. That makes the oracle a second copy of the same
//! enumeration — if a field is forgotten in both places the test passes green. `PodStatus` is the
//! worked example: `gen_pod_status_to_json` was itself written to fix an earlier
//! drop of the whole `.status` subtree, shipped a regression test asserting `phase`/`podIP`/
//! `conditions`, and left `containerStatuses` out of both the emitter and the expected list — so a
//! protobuf `UpdateStatus` deleted it from the stored pod, under a green suite, for as long as the
//! test existed. Deriving the list from the schema removes the human from the oracle: a field
//! added upstream shows up in the expected set automatically, whether anyone remembers it or not.
//!
//! Scope limit worth knowing before trusting a green result: `assert_fields_present` matches a key
//! against *any* path segment anywhere in the decoded tree, so a nested struct counts as covered
//! the moment one of its leaves survives. This module fixes the *list*, not the
//! *matcher* — until that gap closes, counts produced here are lower bounds on what is really missing.
//!
//! In this schema the proto field name *is* the JSON key — verified across all 2466 fields of the
//! vendored protos, `json_name` never differs from `name`. Only two mechanical adjustments and a
//! short list of type-level exceptions are needed; both are encoded below.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use prost::Message;
use prost_types::{field_descriptor_proto::Type, DescriptorProto, FileDescriptorSet};

/// The descriptor set protoc emits, owned by `u7s-proto-generated` now that the prost invocation
/// lives there (see that crate's `build.rs`) rather than being re-emitted into this crate's own
/// `OUT_DIR`.
use u7s_proto_generated::DESCRIPTOR_BYTES;

// `OPAQUE_MESSAGES`/`RENAMES`/`INLINE_EMBEDS`/`DELIBERATE_OMISSIONS`/`KNOWN_GAPS` and the
// `json_key`/`is_excluded`/`is_inline_embed` helpers built on them live in `proto_exceptions.rs`,
// shared verbatim (via `include!`, not `mod`) with `build/codegen.rs` — a build script cannot
// `use` anything from the crate it is building, so textual inclusion is the only way both this
// test-oracle module and the VolumeSource codegen can consume the same exception data without
// one duplicating the other.
include!("proto_exceptions.rs");

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

        use crate::apps_gen::k8s::io::api::admissionregistration::v1 as ar_v1;
        use crate::apps_gen::k8s::io::api::apps::v1 as apps_v1;
        use crate::apps_gen::k8s::io::api::authentication::v1 as authn_v1;
        use crate::apps_gen::k8s::io::api::authorization::v1 as authz_v1;
        use crate::apps_gen::k8s::io::api::autoscaling::v1 as as_v1;
        use crate::apps_gen::k8s::io::api::autoscaling::v2 as as_v2;
        use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
        use crate::apps_gen::k8s::io::api::certificates::v1 as certs_v1;
        use crate::apps_gen::k8s::io::api::coordination::v1 as coord_v1;
        use crate::apps_gen::k8s::io::api::coordination::v1alpha2 as coord_v1alpha2;
        use crate::apps_gen::k8s::io::api::core::v1 as cv1;
        use crate::apps_gen::k8s::io::api::discovery::v1 as discovery_v1;
        use crate::apps_gen::k8s::io::api::events::v1 as events_v1;
        use crate::apps_gen::k8s::io::api::flowcontrol::v1 as flowcontrol_v1;
        use crate::apps_gen::k8s::io::api::networking::v1 as networking_v1;
        use crate::apps_gen::k8s::io::api::node::v1 as node_v1;
        use crate::apps_gen::k8s::io::api::policy::v1 as policy_v1;
        use crate::apps_gen::k8s::io::api::rbac::v1 as rbac_v1;
        use crate::apps_gen::k8s::io::api::resource::v1 as rv1;
        use crate::apps_gen::k8s::io::api::scheduling::v1 as scheduling_v1;
        use crate::apps_gen::k8s::io::api::storage::v1 as storage_v1;
        use crate::apps_gen::k8s::io::apiextensions_apiserver::pkg::apis::apiextensions::v1 as apiext_v1;
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;
        use crate::apps_gen::k8s::io::kube_aggregator::pkg::apis::apiregistration::v1 as apiregistration_v1;

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

        // The 9 groups below had never been run through this oracle before —
        // only core/autoscaling/resource had survey! entries. Each row is one *_gen_adapter.rs
        // decoder; the (label, sentinel type, proto FQN, decoder fn) shape matches the rows
        // above exactly, just pointed at a different crate module per api group.
        survey!(
            "apps/StatefulSet",
            apps_v1::StatefulSet,
            ".k8s.io.api.apps.v1.StatefulSet",
            crate::apps_gen_adapter::decode_statefulset_proto_gen
        );
        survey!(
            "apps/Deployment",
            apps_v1::Deployment,
            ".k8s.io.api.apps.v1.Deployment",
            crate::apps_gen_adapter::decode_deployment_proto_gen
        );
        survey!(
            "apps/DaemonSet",
            apps_v1::DaemonSet,
            ".k8s.io.api.apps.v1.DaemonSet",
            crate::apps_gen_adapter::decode_daemonset_proto_gen
        );
        survey!(
            "apps/ReplicaSet",
            apps_v1::ReplicaSet,
            ".k8s.io.api.apps.v1.ReplicaSet",
            crate::apps_gen_adapter::decode_replicaset_proto_gen
        );
        survey!(
            "apps/ControllerRevision",
            apps_v1::ControllerRevision,
            ".k8s.io.api.apps.v1.ControllerRevision",
            crate::apps_gen_adapter::decode_controllerrevision_proto_gen
        );
        survey!(
            "rbac/ClusterRole",
            rbac_v1::ClusterRole,
            ".k8s.io.api.rbac.v1.ClusterRole",
            crate::rbac_gen_adapter::decode_clusterrole_proto_gen
        );
        survey!(
            "rbac/ClusterRoleBinding",
            rbac_v1::ClusterRoleBinding,
            ".k8s.io.api.rbac.v1.ClusterRoleBinding",
            crate::rbac_gen_adapter::decode_clusterrolebinding_proto_gen
        );
        survey!(
            "rbac/Role",
            rbac_v1::Role,
            ".k8s.io.api.rbac.v1.Role",
            crate::rbac_gen_adapter::decode_role_proto_gen
        );
        survey!(
            "rbac/RoleBinding",
            rbac_v1::RoleBinding,
            ".k8s.io.api.rbac.v1.RoleBinding",
            crate::rbac_gen_adapter::decode_rolebinding_proto_gen
        );
        survey!(
            "rbac/SubjectAccessReview",
            authz_v1::SubjectAccessReview,
            ".k8s.io.api.authorization.v1.SubjectAccessReview",
            crate::rbac_gen_adapter::decode_subject_access_review_proto_gen
        );
        survey!(
            "rbac/LocalSubjectAccessReview",
            authz_v1::LocalSubjectAccessReview,
            ".k8s.io.api.authorization.v1.LocalSubjectAccessReview",
            crate::rbac_gen_adapter::decode_local_subject_access_review_proto_gen
        );
        survey!(
            "rbac/SelfSubjectAccessReview",
            authz_v1::SelfSubjectAccessReview,
            ".k8s.io.api.authorization.v1.SelfSubjectAccessReview",
            crate::rbac_gen_adapter::decode_selfsubjectaccessreview_proto_gen
        );
        survey!(
            "rbac/SelfSubjectRulesReview",
            authz_v1::SelfSubjectRulesReview,
            ".k8s.io.api.authorization.v1.SelfSubjectRulesReview",
            crate::rbac_gen_adapter::decode_selfsubjectrulesreview_proto_gen
        );
        survey!(
            "rbac/TokenReview",
            authn_v1::TokenReview,
            ".k8s.io.api.authentication.v1.TokenReview",
            crate::rbac_gen_adapter::decode_token_review_proto_gen
        );
        survey!(
            "apiextensions/CustomResourceDefinition",
            apiext_v1::CustomResourceDefinition,
            ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition",
            crate::apiextensions_gen_adapter::decode_crd_proto_gen
        );
        survey!(
            "apiextensions/DeleteOptions",
            meta_v1::DeleteOptions,
            ".k8s.io.apimachinery.pkg.apis.meta.v1.DeleteOptions",
            crate::apiextensions_gen_adapter::decode_delete_options_proto_gen
        );
        survey!(
            "admissionreg/ValidatingWebhookConfiguration",
            ar_v1::ValidatingWebhookConfiguration,
            ".k8s.io.api.admissionregistration.v1.ValidatingWebhookConfiguration",
            crate::admissionreg_gen_adapter::decode_validatingwebhookconfiguration_proto_gen
        );
        survey!(
            "admissionreg/MutatingWebhookConfiguration",
            ar_v1::MutatingWebhookConfiguration,
            ".k8s.io.api.admissionregistration.v1.MutatingWebhookConfiguration",
            crate::admissionreg_gen_adapter::decode_mutatingwebhookconfiguration_proto_gen
        );
        survey!(
            "admissionreg/ValidatingAdmissionPolicy",
            ar_v1::ValidatingAdmissionPolicy,
            ".k8s.io.api.admissionregistration.v1.ValidatingAdmissionPolicy",
            crate::admissionreg_gen_adapter::decode_validatingadmissionpolicy_proto_gen
        );
        survey!(
            "admissionreg/ValidatingAdmissionPolicyBinding",
            ar_v1::ValidatingAdmissionPolicyBinding,
            ".k8s.io.api.admissionregistration.v1.ValidatingAdmissionPolicyBinding",
            crate::admissionreg_gen_adapter::decode_validatingadmissionpolicybinding_proto_gen
        );
        survey!(
            "admissionreg/MutatingAdmissionPolicy",
            ar_v1::MutatingAdmissionPolicy,
            ".k8s.io.api.admissionregistration.v1.MutatingAdmissionPolicy",
            crate::admissionreg_gen_adapter::decode_mutatingadmissionpolicy_proto_gen
        );
        survey!(
            "admissionreg/MutatingAdmissionPolicyBinding",
            ar_v1::MutatingAdmissionPolicyBinding,
            ".k8s.io.api.admissionregistration.v1.MutatingAdmissionPolicyBinding",
            crate::admissionreg_gen_adapter::decode_mutatingadmissionpolicybinding_proto_gen
        );
        survey!(
            "net_disc/Ingress",
            networking_v1::Ingress,
            ".k8s.io.api.networking.v1.Ingress",
            crate::net_disc_cert_policy_events_gen_adapter::decode_ingress_proto_gen
        );
        survey!(
            "net_disc/IngressClass",
            networking_v1::IngressClass,
            ".k8s.io.api.networking.v1.IngressClass",
            crate::net_disc_cert_policy_events_gen_adapter::decode_ingressclass_proto_gen
        );
        survey!(
            "net_disc/NetworkPolicy",
            networking_v1::NetworkPolicy,
            ".k8s.io.api.networking.v1.NetworkPolicy",
            crate::net_disc_cert_policy_events_gen_adapter::decode_networkpolicy_proto_gen
        );
        survey!(
            "net_disc/IPAddress",
            networking_v1::IpAddress,
            ".k8s.io.api.networking.v1.IPAddress",
            crate::net_disc_cert_policy_events_gen_adapter::decode_ipaddress_proto_gen
        );
        survey!(
            "net_disc/ServiceCIDR",
            networking_v1::ServiceCidr,
            ".k8s.io.api.networking.v1.ServiceCIDR",
            crate::net_disc_cert_policy_events_gen_adapter::decode_servicecidr_proto_gen
        );
        survey!(
            "net_disc/EndpointSlice",
            discovery_v1::EndpointSlice,
            ".k8s.io.api.discovery.v1.EndpointSlice",
            crate::net_disc_cert_policy_events_gen_adapter::decode_endpointslice_proto_gen
        );
        survey!(
            "net_disc/CertificateSigningRequest",
            certs_v1::CertificateSigningRequest,
            ".k8s.io.api.certificates.v1.CertificateSigningRequest",
            crate::net_disc_cert_policy_events_gen_adapter::decode_csr_proto_gen
        );
        survey!(
            "net_disc/PodDisruptionBudget",
            policy_v1::PodDisruptionBudget,
            ".k8s.io.api.policy.v1.PodDisruptionBudget",
            crate::net_disc_cert_policy_events_gen_adapter::decode_poddisruptionbudget_proto_gen
        );
        survey!(
            "net_disc/events.k8s.io Event",
            events_v1::Event,
            ".k8s.io.api.events.v1.Event",
            crate::net_disc_cert_policy_events_gen_adapter::decode_events_v1_event_proto_gen
        );
        survey!(
            "storage/CSINode",
            storage_v1::CsiNode,
            ".k8s.io.api.storage.v1.CSINode",
            crate::storage_node_flow_gen_adapter::decode_csinode_proto_gen
        );
        survey!(
            "storage/CSIDriver",
            storage_v1::CsiDriver,
            ".k8s.io.api.storage.v1.CSIDriver",
            crate::storage_node_flow_gen_adapter::decode_csidriver_proto_gen
        );
        survey!(
            "storage/CSIStorageCapacity",
            storage_v1::CsiStorageCapacity,
            ".k8s.io.api.storage.v1.CSIStorageCapacity",
            crate::storage_node_flow_gen_adapter::decode_csistoragecapacity_proto_gen
        );
        survey!(
            "storage/VolumeAttachment",
            storage_v1::VolumeAttachment,
            ".k8s.io.api.storage.v1.VolumeAttachment",
            crate::storage_node_flow_gen_adapter::decode_volumeattachment_proto_gen
        );
        survey!(
            "storage/StorageClass",
            storage_v1::StorageClass,
            ".k8s.io.api.storage.v1.StorageClass",
            crate::storage_node_flow_gen_adapter::decode_storageclass_proto_gen
        );
        survey!(
            "storage/VolumeAttributesClass",
            storage_v1::VolumeAttributesClass,
            ".k8s.io.api.storage.v1.VolumeAttributesClass",
            crate::storage_node_flow_gen_adapter::decode_volumeattributesclass_proto_gen
        );
        survey!(
            "storage/RuntimeClass",
            node_v1::RuntimeClass,
            ".k8s.io.api.node.v1.RuntimeClass",
            crate::storage_node_flow_gen_adapter::decode_runtimeclass_proto_gen
        );
        survey!(
            "storage/PriorityClass",
            scheduling_v1::PriorityClass,
            ".k8s.io.api.scheduling.v1.PriorityClass",
            crate::storage_node_flow_gen_adapter::decode_priorityclass_proto_gen
        );
        survey!(
            "storage/FlowSchema",
            flowcontrol_v1::FlowSchema,
            ".k8s.io.api.flowcontrol.v1.FlowSchema",
            crate::storage_node_flow_gen_adapter::decode_flowschema_proto_gen
        );
        survey!(
            "storage/PriorityLevelConfiguration",
            flowcontrol_v1::PriorityLevelConfiguration,
            ".k8s.io.api.flowcontrol.v1.PriorityLevelConfiguration",
            crate::storage_node_flow_gen_adapter::decode_prioritylevelconfiguration_proto_gen
        );
        survey!(
            "batch/Job",
            batch_v1::Job,
            ".k8s.io.api.batch.v1.Job",
            crate::batch_gen_adapter::decode_job_proto_gen
        );
        survey!(
            "batch/CronJob",
            batch_v1::CronJob,
            ".k8s.io.api.batch.v1.CronJob",
            crate::batch_gen_adapter::decode_cronjob_proto_gen
        );
        survey!(
            "coord/Lease",
            coord_v1::Lease,
            ".k8s.io.api.coordination.v1.Lease",
            crate::coord_gen_adapter::decode_lease_proto_gen_a
        );
        survey!(
            "coord/LeaseCandidate",
            coord_v1alpha2::LeaseCandidate,
            ".k8s.io.api.coordination.v1alpha2.LeaseCandidate",
            crate::coord_gen_adapter::decode_leasecandidate_proto_gen
        );
        survey!(
            "apiregistration/APIService",
            apiregistration_v1::ApiService,
            ".k8s.io.kube_aggregator.pkg.apis.apiregistration.v1.APIService",
            crate::apiregistration_gen_adapter::decode_apiservice_proto_gen
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
