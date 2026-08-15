use prost::Message;

use u7s_proto_generated::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;
use u7s_proto_generated::k8s::io::kube_aggregator::pkg::apis::apiregistration::v1 as apiregistration_v1;

// ---- shared helpers --------------------------------------------------------

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    crate::core_gen_adapter::gen_object_meta_to_json(meta)
}

/// Decode a protobuf-encoded `APIService` (apiregistration.k8s.io/v1) into JSON.
///
/// client-go's aggregator clientset (used by e.g. the sample-apiserver conformance test and
/// any real APIService-registering client) sends APIService creates/updates as native protobuf,
/// not JSON-in-envelope, because APIService has a registered generated protobuf marshaller
/// upstream. Without this decoder, `decode_proto_by_kind_and_version` returns `None` for
/// kind="APIService", `extract_body` falls through to returning the undecoded k8s-magic-prefixed
/// envelope bytes, and the generic create/replace handlers fail with
/// "invalid JSON: expected value at line 1 column 1" trying to JSON-parse them.
pub fn decode_apiservice_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let svc = apiregistration_v1::ApiService::decode(data).ok()?;
    let meta = gen_object_meta_to_json(svc.metadata.unwrap_or_default());

    let mut obj = serde_json::json!({
        "apiVersion": "apiregistration.k8s.io/v1",
        "kind": "APIService",
        "metadata": meta
    });

    if let Some(spec) = svc.spec {
        let mut spec_map = serde_json::Map::new();
        if let Some(svc_ref) = spec.service {
            let mut svc_map = serde_json::Map::new();
            if let Some(v) = svc_ref.namespace.filter(|s| !s.is_empty()) {
                svc_map.insert("namespace".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = svc_ref.name.filter(|s| !s.is_empty()) {
                svc_map.insert("name".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = svc_ref.port {
                svc_map.insert("port".to_string(), serde_json::Value::Number(v.into()));
            }
            if !svc_map.is_empty() {
                spec_map.insert("service".to_string(), serde_json::Value::Object(svc_map));
            }
        }
        if let Some(v) = spec.group.filter(|s| !s.is_empty()) {
            spec_map.insert("group".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.version.filter(|s| !s.is_empty()) {
            spec_map.insert("version".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.insecure_skip_tls_verify {
            spec_map.insert(
                "insecureSkipTLSVerify".to_string(),
                serde_json::Value::Bool(v),
            );
        }
        if let Some(v) = spec.ca_bundle.filter(|b| !b.is_empty()) {
            use base64::Engine as _;
            spec_map.insert(
                "caBundle".to_string(),
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(v)),
            );
        }
        if let Some(v) = spec.group_priority_minimum {
            spec_map.insert(
                "groupPriorityMinimum".to_string(),
                serde_json::Value::Number(v.into()),
            );
        }
        if let Some(v) = spec.version_priority {
            spec_map.insert(
                "versionPriority".to_string(),
                serde_json::Value::Number(v.into()),
            );
        }
        if !spec_map.is_empty() {
            obj["spec"] = serde_json::Value::Object(spec_map);
        }
    }

    if let Some(status) = svc.status {
        if !status.conditions.is_empty() {
            let conditions: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(|c| {
                    let mut cond = serde_json::json!({});
                    if let Some(v) = c.r#type.filter(|s| !s.is_empty()) {
                        cond["type"] = serde_json::Value::String(v);
                    }
                    if let Some(v) = c.status.filter(|s| !s.is_empty()) {
                        cond["status"] = serde_json::Value::String(v);
                    }
                    if let Some(t) = c.last_transition_time.as_ref() {
                        if let Some(secs) = t.seconds {
                            if secs != 0 {
                                cond["lastTransitionTime"] =
                                    serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                            }
                        }
                    }
                    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                        cond["reason"] = serde_json::Value::String(v);
                    }
                    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                        cond["message"] = serde_json::Value::String(v);
                    }
                    cond
                })
                .collect();
            obj["status"] = serde_json::json!({ "conditions": conditions });
        }
    }

    Some(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_apiservice_bytes() -> Vec<u8> {
        let svc = apiregistration_v1::ApiService {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("v1alpha1.wardle.example.com".to_string()),
                resource_version: Some("42".to_string()),
                uid: Some("abc-123".to_string()),
                ..Default::default()
            }),
            spec: Some(apiregistration_v1::ApiServiceSpec {
                service: Some(apiregistration_v1::ServiceReference {
                    namespace: Some("wardle".to_string()),
                    name: Some("api".to_string()),
                    port: Some(443),
                }),
                group: Some("wardle.example.com".to_string()),
                version: Some("v1alpha1".to_string()),
                insecure_skip_tls_verify: Some(true),
                group_priority_minimum: Some(1000),
                version_priority: Some(15),
                ..Default::default()
            }),
            status: None,
        };
        let mut buf = Vec::new();
        svc.encode(&mut buf).unwrap();
        buf
    }

    /// The 1.17 Sample API Server aggregator conformance test creates exactly this shape of
    /// object via client-go's aggregator clientset (protobuf by default). If this decode
    /// regresses, the test fails at APIService creation with
    /// "invalid JSON: expected value at line 1 column 1" — this test fails first, at the unit
    /// level, before that e2e symptom would reappear.
    #[test]
    fn decode_apiservice_proto_gen_round_trips_sample_apiserver_registration() {
        let bytes = make_test_apiservice_bytes();
        let json = decode_apiservice_proto_gen(&bytes).expect("APIService decode must succeed");

        assert_eq!(
            json["apiVersion"], "apiregistration.k8s.io/v1",
            "apiVersion must be apiregistration.k8s.io/v1 so the generic create handler routes \
             the object to the apiservices registry entry"
        );
        assert_eq!(json["kind"], "APIService");
        assert_eq!(
            json["metadata"]["name"], "v1alpha1.wardle.example.com",
            "name must survive proto decode — apiregistration validates name == version.group"
        );
        assert_eq!(
            json["spec"]["service"]["namespace"], "wardle",
            "spec.service.namespace must survive: the aggregator uses it to route requests"
        );
        assert_eq!(json["spec"]["service"]["name"], "api");
        assert_eq!(json["spec"]["service"]["port"], 443);
        assert_eq!(json["spec"]["group"], "wardle.example.com");
        assert_eq!(json["spec"]["version"], "v1alpha1");
        assert_eq!(
            json["spec"]["insecureSkipTLSVerify"], true,
            "insecureSkipTLSVerify must survive: sample-apiserver conformance sets this true"
        );
        assert_eq!(json["spec"]["groupPriorityMinimum"], 1000);
        assert_eq!(json["spec"]["versionPriority"], 15);
    }

    /// caBundle is a `bytes` field — it must round-trip as base64 in JSON (the Kubernetes API
    /// convention for byte fields), not raw bytes or a decode error.
    #[test]
    fn decode_apiservice_proto_gen_encodes_ca_bundle_as_base64() {
        let svc = apiregistration_v1::ApiService {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("v1.example.com".to_string()),
                ..Default::default()
            }),
            spec: Some(apiregistration_v1::ApiServiceSpec {
                ca_bundle: Some(b"fake-ca-cert-bytes".to_vec()),
                ..Default::default()
            }),
            status: None,
        };
        let mut buf = Vec::new();
        svc.encode(&mut buf).unwrap();

        let json = decode_apiservice_proto_gen(&buf).expect("decode must succeed");
        use base64::Engine as _;
        let expected = base64::engine::general_purpose::STANDARD.encode(b"fake-ca-cert-bytes");
        assert_eq!(
            json["spec"]["caBundle"], expected,
            "caBundle bytes must be base64-encoded in JSON, matching kubectl/client-go's wire \
             convention for []byte fields"
        );
    }

    /// status.conditions must survive decode — the aggregator's availability controller polls
    /// this field via GET/WATCH (proto-decoded on the way in from a controller that PUTs status).
    #[test]
    fn decode_apiservice_proto_gen_decodes_status_conditions() {
        let svc = apiregistration_v1::ApiService {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("v1alpha1.wardle.example.com".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(apiregistration_v1::ApiServiceStatus {
                conditions: vec![apiregistration_v1::ApiServiceCondition {
                    r#type: Some("Available".to_string()),
                    status: Some("True".to_string()),
                    reason: Some("Passed".to_string()),
                    message: Some("all checks passed".to_string()),
                    ..Default::default()
                }],
            }),
        };
        let mut buf = Vec::new();
        svc.encode(&mut buf).unwrap();

        let json = decode_apiservice_proto_gen(&buf).expect("decode must succeed");
        let conditions = json["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be an array");
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0]["type"], "Available");
        assert_eq!(conditions[0]["status"], "True");
        assert_eq!(conditions[0]["reason"], "Passed");
        assert_eq!(conditions[0]["message"], "all checks passed");
    }

    /// Malformed/truncated protobuf bytes must return None, not panic — a decode failure must
    /// fall through to extract_body's other fallback paths, never crash the request handler.
    #[test]
    fn decode_apiservice_proto_gen_returns_none_for_garbage_bytes() {
        assert!(decode_apiservice_proto_gen(&[0xff, 0xff, 0xff]).is_none());
    }

    // ---- Sentinel completeness: decode_apiservice_proto_gen ----
    //
    // Builds an APIService with every metadata/spec/status field set to a value no
    // zero/empty-elision check in gen_object_meta_to_json or decode_apiservice_proto_gen could
    // mistake for "unset" (see u7s_sentinel::Sentinel), decodes it through the real
    // decode_apiservice_proto_gen entry point, and asserts every field name shows up somewhere
    // in the resulting JSON. A name that never appears means this file's gen_object_meta_to_json
    // (a near-duplicate of core_gen_adapter's, not shared code) or decode_apiservice_proto_gen
    // never reads that field from the decoded protobuf struct at all.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    #[test]
    fn sentinel_completeness_decode_apiservice_proto_gen() {
        let svc = apiregistration_v1::ApiService {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(apiregistration_v1::ApiServiceSpec::sentinel()),
            status: Some(apiregistration_v1::ApiServiceStatus::sentinel()),
        };
        let mut buf = Vec::new();
        svc.encode(&mut buf).unwrap();
        let decoded = decode_apiservice_proto_gen(&buf)
            .expect("sentinel APIService must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.kube_aggregator.pkg.apis.apiregistration.v1.APIService",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }
}
