use prost::Message;

use crate::coord_gen::k8s::io::api::coordination::v1 as coord_v1;
use crate::coord_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

// ---- shared helpers --------------------------------------------------------

fn gen_microtime_to_rfc3339(t: &meta_v1::MicroTime) -> Option<String> {
    let secs = t.seconds?;
    if secs <= 0 {
        return None;
    }
    let nanos = t.nanos.unwrap_or(0);
    Some(crate::util::secs_nanos_to_rfc3339_micro(secs as u64, nanos))
}

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    let mut m = serde_json::json!({ "creationTimestamp": serde_json::Value::Null });
    if let Some(n) = meta.name.filter(|s| !s.is_empty()) {
        m["name"] = serde_json::Value::String(n);
    }
    if let Some(n) = meta.generate_name.filter(|s| !s.is_empty()) {
        m["generateName"] = serde_json::Value::String(n);
    }
    if let Some(n) = meta.namespace.filter(|s| !s.is_empty()) {
        m["namespace"] = serde_json::Value::String(n);
    }
    if let Some(u) = meta.uid.filter(|s| !s.is_empty()) {
        m["uid"] = serde_json::Value::String(u);
    }
    if let Some(rv) = meta.resource_version.filter(|s| !s.is_empty()) {
        m["resourceVersion"] = serde_json::Value::String(rv);
    }
    if let Some(g) = meta.generation.filter(|&v| v != 0) {
        m["generation"] = serde_json::Value::Number(g.into());
    }
    if let Some(ts) = meta.creation_timestamp {
        if let Some(secs) = ts.seconds {
            if secs > 0 {
                m["creationTimestamp"] =
                    serde_json::Value::String(crate::util::secs_to_rfc3339(secs as u64));
            }
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
    if !meta.owner_references.is_empty() {
        let refs: Vec<serde_json::Value> = meta
            .owner_references
            .into_iter()
            .map(|r| {
                let mut entry = serde_json::json!({});
                if let Some(v) = r.api_version.filter(|s| !s.is_empty()) {
                    entry["apiVersion"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
                    entry["kind"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.name.filter(|s| !s.is_empty()) {
                    entry["name"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.uid.filter(|s| !s.is_empty()) {
                    entry["uid"] = serde_json::Value::String(v);
                }
                if let Some(ctrl) = r.controller {
                    entry["controller"] = serde_json::Value::Bool(ctrl);
                }
                if let Some(bod) = r.block_owner_deletion {
                    entry["blockOwnerDeletion"] = serde_json::Value::Bool(bod);
                }
                entry
            })
            .collect();
        if !refs.is_empty() {
            m["ownerReferences"] = serde_json::Value::Array(refs);
        }
    }
    if !meta.finalizers.is_empty() {
        let fins: Vec<serde_json::Value> = meta
            .finalizers
            .into_iter()
            .map(serde_json::Value::String)
            .collect();
        m["finalizers"] = serde_json::Value::Array(fins);
    }
    m
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

// ---- Adapter B: serde-derive on generated structs --------------------------
//
// serde::Serialize is derived on Lease/LeaseSpec/ObjectMeta/MicroTime via
// prost-build type_attribute in build.rs. serde_json::to_value gives "free"
// JSON — but with k8s-fidelity problems documented below.
//
// Known fidelity gaps (proven by the diff test below):
//
// 1. FIELD NAMING: prost-build uses snake_case field names. serde's default
//    is to output as-is, so "holder_identity" not "holderIdentity". Fix would
//    require #[serde(rename_all = "camelCase")] but that can only be added via
//    type_attribute at the struct level — and then ALL fields camelCase, which
//    conflicts with some that should not be renamed.
//
// 2. OMIT-IF-ZERO: serde emits Some(0) as JSON `0`. k8s convention is to omit
//    numeric zero. No built-in serde mechanism for this without a custom
//    serializer per field.
//
// 3. MICROTIME: serde emits MicroTime as {"seconds":N,"nanos":M} object.
//    k8s JSON wire format expects RFC3339+microseconds string.
//    Fix requires a custom serialize impl for MicroTime — not automatic.
//
// 4. CREATIONTIMESTAMP: k8s always emits `"creationTimestamp": null` even when
//    not set. serde with skip_serializing_if="is_none" would omit it entirely.
//
// These four gaps mean adapter B (naive serde-derive) CANNOT produce k8s-wire-
// compatible JSON without additional per-field customization that effectively
// reaches adapter-A territory in total code. See findings doc for full cost
// projection.

pub fn decode_lease_proto_gen_b_naive(data: &[u8]) -> Option<serde_json::Value> {
    let lease = coord_v1::Lease::decode(data).ok()?;
    serde_json::to_value(lease).ok()
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
    fn adapter_a_matches_original_decode_for_common_lease_fields() {
        let bytes = make_test_lease_bytes();
        let original = crate::proto::decode_lease_proto(&bytes)
            .expect("original decode_lease_proto must succeed");
        let gen_a = decode_lease_proto_gen_a(&bytes).expect("adapter A must succeed on same bytes");

        assert_eq!(
            original["apiVersion"], gen_a["apiVersion"],
            "apiVersion must match: kubectl uses this to route the object"
        );
        assert_eq!(
            original["kind"], gen_a["kind"],
            "kind must match: missing kind breaks server-side apply"
        );
        assert_eq!(
            original["metadata"]["name"], gen_a["metadata"]["name"],
            "metadata.name must match: name is the primary object identifier"
        );
        assert_eq!(
            original["metadata"]["namespace"], gen_a["metadata"]["namespace"],
            "metadata.namespace must match: wrong namespace routes to wrong store"
        );
        assert_eq!(
            original["spec"]["holderIdentity"], gen_a["spec"]["holderIdentity"],
            "holderIdentity must match: Lease holder is the core semantics"
        );
        assert_eq!(
            original["spec"]["leaseDurationSeconds"], gen_a["spec"]["leaseDurationSeconds"],
            "leaseDurationSeconds must match: governs leader election timeout"
        );
        assert_eq!(
            original["spec"]["renewTime"], gen_a["spec"]["renewTime"],
            "renewTime MicroTime must match including nanoseconds: nanos bug caused real outages"
        );
        assert_eq!(
            original["spec"]["leaseTransitions"], gen_a["spec"]["leaseTransitions"],
            "leaseTransitions must match: clients use this to detect leader churn"
        );
    }

    #[test]
    fn adapter_a_emits_alpha_fields_strategy_and_preferred_holder_that_original_silently_dropped() {
        let bytes = make_test_lease_bytes_with_alpha_fields();

        let original = crate::proto::decode_lease_proto(&bytes)
            .expect("original decode_lease_proto must succeed");
        let gen_a = decode_lease_proto_gen_a(&bytes).expect("adapter A must succeed");

        assert!(
            original["spec"]["strategy"].is_null(),
            "original adapter silently drops strategy: confirms the silent-drop bug class"
        );
        assert!(
            original["spec"]["preferredHolder"].is_null(),
            "original adapter silently drops preferredHolder: confirms the silent-drop bug class"
        );

        assert_eq!(
            gen_a["spec"]["strategy"], "OldestEmulationVersion",
            "adapter A must emit strategy: generated struct covers all fields, none dropped"
        );
        assert_eq!(
            gen_a["spec"]["preferredHolder"], "candidate-b",
            "adapter A must emit preferredHolder: generated struct covers all fields, none dropped"
        );
    }

    #[test]
    fn adapter_b_naive_serde_diverges_from_k8s_wire_format() {
        let bytes = make_test_lease_bytes();

        let gen_b = decode_lease_proto_gen_b_naive(&bytes).expect("adapter B must produce a value");

        assert!(
            gen_b["spec"]["holder_identity"].is_string(),
            "adapter B emits snake_case 'holder_identity' not camelCase 'holderIdentity': \
             this diverges from k8s JSON wire format and breaks kubectl"
        );
        assert!(
            gen_b["spec"]["holderIdentity"].is_null(),
            "adapter B must NOT produce camelCase holderIdentity: \
             proving naming mismatch with k8s wire format"
        );

        assert!(
            gen_b["spec"]["renew_time"].is_object(),
            "adapter B emits MicroTime as object {{seconds, nanos}} not RFC3339 string: \
             this breaks any client that parses the time field"
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
        assert_eq!(decoded.strategy.as_deref(), Some("y"),
            "strategy field must survive round-trip: it's present in generated struct by construction, \
             not by authoring discipline");
        assert_eq!(decoded.preferred_holder.as_deref(), Some("z"),
            "preferredHolder field must survive round-trip: present in generated struct by construction");
    }
}
