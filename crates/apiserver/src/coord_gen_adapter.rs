use prost::Message;

use crate::coord_gen::k8s::io::api::coordination::v1 as coord_v1;
use crate::coord_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

// ---- shared helpers --------------------------------------------------------

fn gen_microtime_to_rfc3339(t: &meta_v1::MicroTime) -> Option<String> {
    Some(crate::core_gen_adapter::gen_microtime_fields_to_rfc3339(
        t.seconds?,
        t.nanos.unwrap_or(0),
    ))
}

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    crate::core_gen_adapter::gen_object_meta_to_json(meta)
}

// ---- Adapter A: hand-written struct→JSON map, mirrors decode_lease_proto ----
//
// Fed by the prost-build-GENERATED Lease struct instead of the hand struct.
// Preserves the same omit-if-zero / omit-if-empty semantics as the original.
// Additionally emits strategy/preferredHolder which the original skipped.

pub fn decode_lease_proto_gen_a(data: &[u8]) -> Option<serde_json::Value> {
    let lease = coord_v1::Lease::decode(data).ok()?;
    let meta = gen_object_meta_to_json(lease.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": meta
    });

    if let Some(spec) = lease.spec {
        let mut spec_map = serde_json::Map::new();
        if let Some(v) = spec.holder_identity.filter(|s| !s.is_empty()) {
            spec_map.insert("holderIdentity".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.lease_duration_seconds.filter(|&n| n != 0) {
            spec_map.insert(
                "leaseDurationSeconds".to_string(),
                serde_json::Value::Number(v.into()),
            );
        }
        if let Some(t) = spec.acquire_time.as_ref() {
            if let Some(ts) = gen_microtime_to_rfc3339(t) {
                spec_map.insert("acquireTime".to_string(), serde_json::Value::String(ts));
            }
        }
        if let Some(t) = spec.renew_time.as_ref() {
            if let Some(ts) = gen_microtime_to_rfc3339(t) {
                spec_map.insert("renewTime".to_string(), serde_json::Value::String(ts));
            }
        }
        if let Some(v) = spec.lease_transitions.filter(|&n| n != 0) {
            spec_map.insert(
                "leaseTransitions".to_string(),
                serde_json::Value::Number(v.into()),
            );
        }
        if let Some(v) = spec.strategy.filter(|s| !s.is_empty()) {
            spec_map.insert("strategy".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.preferred_holder.filter(|s| !s.is_empty()) {
            spec_map.insert("preferredHolder".to_string(), serde_json::Value::String(v));
        }
        if !spec_map.is_empty() {
            obj["spec"] = serde_json::Value::Object(spec_map);
        }
    }

    Some(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_lease_bytes() -> Vec<u8> {
        use crate::coord_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;
        let lease = coord_v1::Lease {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("test-lease".to_string()),
                namespace: Some("kube-system".to_string()),
                resource_version: Some("12345".to_string()),
                uid: Some("abc-123".to_string()),
                ..Default::default()
            }),
            spec: Some(coord_v1::LeaseSpec {
                holder_identity: Some("node-1".to_string()),
                lease_duration_seconds: Some(15),
                renew_time: Some(meta_v1::MicroTime {
                    seconds: Some(1_700_000_000),
                    nanos: Some(123_456_000),
                }),
                lease_transitions: Some(3),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        lease.encode(&mut buf).unwrap();
        buf
    }

    fn make_test_lease_bytes_with_alpha_fields() -> Vec<u8> {
        use crate::coord_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;
        let lease = coord_v1::Lease {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("coordinated-lease".to_string()),
                namespace: Some("kube-system".to_string()),
                ..Default::default()
            }),
            spec: Some(coord_v1::LeaseSpec {
                holder_identity: Some("candidate-a".to_string()),
                lease_duration_seconds: Some(10),
                strategy: Some("OldestEmulationVersion".to_string()),
                preferred_holder: Some("candidate-b".to_string()),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        lease.encode(&mut buf).unwrap();
        buf
    }

    #[test]
    fn decode_lease_proto_gen_a_emits_required_fields_for_leader_election() {
        let bytes = make_test_lease_bytes();
        let gen_a = decode_lease_proto_gen_a(&bytes).expect("Lease decode must succeed");

        assert_eq!(
            gen_a["apiVersion"], "coordination.k8s.io/v1",
            "apiVersion must be coordination.k8s.io/v1: kubectl uses this to route the object"
        );
        assert_eq!(
            gen_a["kind"], "Lease",
            "kind must be Lease: missing kind breaks server-side apply"
        );
        assert_eq!(
            gen_a["metadata"]["name"], "test-lease",
            "metadata.name must survive: name is the primary object identifier"
        );
        assert_eq!(
            gen_a["metadata"]["namespace"], "kube-system",
            "metadata.namespace must survive: wrong namespace routes to wrong store"
        );
        assert_eq!(
            gen_a["spec"]["holderIdentity"], "node-1",
            "holderIdentity must survive: Lease holder is the core semantics"
        );
        assert_eq!(
            gen_a["spec"]["leaseDurationSeconds"], 15,
            "leaseDurationSeconds must survive: governs leader election timeout"
        );
        assert!(
            gen_a["spec"]["renewTime"].is_string(),
            "renewTime MicroTime must be emitted: nanos precision required for leader election"
        );
        assert_eq!(
            gen_a["spec"]["leaseTransitions"], 3,
            "leaseTransitions must survive: clients use this to detect leader churn"
        );
    }

    #[test]
    fn decode_lease_proto_gen_a_emits_alpha_fields_strategy_and_preferred_holder() {
        let bytes = make_test_lease_bytes_with_alpha_fields();
        let gen_a = decode_lease_proto_gen_a(&bytes).expect("Lease decode must succeed");

        assert_eq!(
            gen_a["spec"]["strategy"], "OldestEmulationVersion",
            "strategy must be emitted: generated struct covers all fields by construction, \
             hand struct silently dropped this field causing coordinated leader election to break"
        );
        assert_eq!(
            gen_a["spec"]["preferredHolder"], "candidate-b",
            "preferredHolder must be emitted: generated struct covers all fields by construction"
        );
    }

    #[test]
    fn generated_lease_spec_covers_all_proto_fields_by_construction() {
        use crate::coord_gen::k8s::io::api::coordination::v1::LeaseSpec;
        let spec = LeaseSpec {
            holder_identity: Some("x".to_string()),
            lease_duration_seconds: Some(1),
            acquire_time: None,
            renew_time: None,
            lease_transitions: Some(0),
            strategy: Some("y".to_string()),
            preferred_holder: Some("z".to_string()),
        };
        let mut buf = Vec::new();
        spec.encode(&mut buf).unwrap();
        let decoded = LeaseSpec::decode(buf.as_slice()).unwrap();
        assert_eq!(
            decoded.strategy.as_deref(),
            Some("y"),
            "strategy field must survive round-trip: it's present in generated struct by \
             construction, not by authoring discipline"
        );
        assert_eq!(
            decoded.preferred_holder.as_deref(),
            Some("z"),
            "preferredHolder field must survive round-trip: present in generated struct by \
             construction"
        );
    }

    // ---- Sentinel completeness: decode_lease_proto_gen_a ----
    //
    // Builds a Lease with every metadata/spec field set to a value no zero/empty-elision check
    // in gen_object_meta_to_json or decode_lease_proto_gen_a could mistake for "unset" (see
    // u7s_sentinel::Sentinel), decodes it through the real decode_lease_proto_gen_a entry point,
    // and asserts every field name shows up somewhere in the resulting JSON. A name that never
    // appears means this file's gen_object_meta_to_json (a near-duplicate of
    // core_gen_adapter's, not shared code) or decode_lease_proto_gen_a never reads that field
    // from the decoded protobuf struct at all.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    #[test]
    fn sentinel_completeness_decode_lease_proto_gen_a() {
        use crate::coord_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;
        let lease = coord_v1::Lease {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(coord_v1::LeaseSpec::sentinel()),
        };
        let mut buf = Vec::new();
        lease.encode(&mut buf).unwrap();
        let decoded = decode_lease_proto_gen_a(&buf)
            .expect("sentinel Lease must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        // Derived from the .proto schema rather than hand-listed, so a field added upstream is
        // demanded here automatically instead of when someone remembers to type it. The
        // deliberate omissions (selfLink) and the currently-tolerated real drops
        // (deletionTimestamp/deletionGracePeriodSeconds/managedFields) live in one reviewed table
        // in `proto_descriptor`, not in a comment in each of the twelve adapter test modules.
        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ".k8s.io.api.coordination.v1.LeaseSpec",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    // ---- Field-omission: decode_lease_proto_gen_a with an all-default Lease ----
    //
    // A Lease with every optional field unset must decode to a `spec`-less object, and
    // metadata must carry no explicit nulls besides `creationTimestamp` (which upstream
    // `metav1.Time` always marshals as `null` when zero). A stray `"holderIdentity": null` or a
    // `"spec": null` would make a leader-election client think a lease was actively released by
    // some holder instead of never having been acquired at all — those are different states.

    use crate::util::sentinel_test_util::assert_no_stray_nulls;

    #[test]
    fn decode_lease_proto_gen_a_omits_unset_fields_instead_of_emitting_null() {
        let lease = coord_v1::Lease::default();
        let mut buf = Vec::new();
        lease.encode(&mut buf).unwrap();
        let decoded = decode_lease_proto_gen_a(&buf).expect("all-default Lease must still decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none(),
            "an unset LeaseSpec must omit `spec` entirely, not emit `spec: null` or `spec: {{}}` \
             — a present-but-empty spec could be misread as \"lease held with no identity\""
        );
    }
}
