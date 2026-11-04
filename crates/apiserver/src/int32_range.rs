//! Write-time range validation for int32 fields, plus pod port ranges.
//!
//! Upstream decodes request bodies into typed structs, so a JSON number outside int32 for an
//! int32 field is rejected with 400 before admission ever sees it, and a stored object can never
//! hold one. u7s keeps request bodies as `serde_json::Value`, so without this check an
//! out-of-range number reaches admission policies as the large number while the protobuf
//! encoders (which narrow to int32) hand clients a different one.
//!
//! The int32 field set is not hand-listed: it is derived from the compiled protobuf descriptor
//! for the object's kind, so every int32 field of every built-in kind is covered, including
//! ones added by a schema bump.

use std::collections::HashMap;
use std::sync::OnceLock;

use prost::Message;
use prost_types::{field_descriptor_proto::Label, field_descriptor_proto::Type};
use prost_types::{DescriptorProto, FileDescriptorSet};
use serde_json::Value;
use u7s_proto_generated::DESCRIPTOR_BYTES;

use crate::admission::AdmissionContext;
use crate::state::AppState;
use crate::status::{Status, StatusError};
use u7s_store::Store;

include!("proto_exceptions.rs");

// Only the shared tables' json_key/is_inline_embed/OPAQUE_MESSAGES are used here; the rest of the
// file is spliced in whole.
#[allow(dead_code)]
fn unused_exception_tables() {
    let _ = (
        DELIBERATE_OMISSIONS,
        KNOWN_GAPS,
        is_excluded as fn(&str, &str) -> bool,
    );
}

const INT_OR_STRING: &str = ".k8s.io.apimachinery.pkg.util.intstr.IntOrString";

fn descriptor_set() -> &'static FileDescriptorSet {
    static SET: OnceLock<FileDescriptorSet> = OnceLock::new();
    SET.get_or_init(|| {
        FileDescriptorSet::decode(DESCRIPTOR_BYTES)
            .expect("descriptor set emitted by build.rs must decode")
    })
}

fn message_index() -> &'static HashMap<String, &'static DescriptorProto> {
    static INDEX: OnceLock<HashMap<String, &'static DescriptorProto>> = OnceLock::new();
    INDEX.get_or_init(|| {
        fn insert(
            index: &mut HashMap<String, &'static DescriptorProto>,
            prefix: &str,
            message: &'static DescriptorProto,
        ) {
            let full = format!("{prefix}.{}", message.name());
            for nested in &message.nested_type {
                insert(index, &full, nested);
            }
            index.insert(full, message);
        }
        let mut index = HashMap::new();
        for file in &descriptor_set().file {
            for message in &file.message_type {
                insert(&mut index, &format!(".{}", file.package()), message);
            }
        }
        index
    })
}

/// A JSON number outside int32 where the schema says int32.
#[derive(Debug, PartialEq)]
pub(crate) struct Int32Violation {
    pub value: String,
    pub owner: String,
    pub path: String,
}

impl Int32Violation {
    /// Upstream's wording for a body whose number does not fit the typed field.
    fn message(&self, kind: &str, api_version: &str) -> String {
        format!(
            "{kind} in version \"{api_version}\" cannot be handled as a {kind}: json: cannot \
             unmarshal number {} into Go struct field {}.{} of type int32",
            self.value, self.owner, self.path
        )
    }
}

fn out_of_range(n: &serde_json::Number) -> bool {
    match n.as_i64() {
        Some(i) => i32::try_from(i).is_err(),
        None => n.is_u64(),
    }
}

/// Cheap pre-filter: most writes carry no integer outside int32 anywhere, and only those need
/// the schema walk.
fn has_out_of_range_number(v: &Value) -> bool {
    match v {
        Value::Number(n) => out_of_range(n),
        Value::Array(a) => a.iter().any(has_out_of_range_number),
        Value::Object(o) => o.values().any(has_out_of_range_number),
        _ => false,
    }
}

fn message_name(group: &str, version: &str, kind: &str) -> String {
    let package = if group.is_empty() {
        "core"
    } else {
        group.split('.').next().unwrap_or(group)
    };
    format!(".k8s.io.api.{package}.{version}.{kind}")
}

/// First int32 field of `kind` in `object` whose value does not fit in int32, or `None` if the
/// kind is not a built-in schema type or every int32 field fits.
pub(crate) fn find_int32_violation(
    group: &str,
    version: &str,
    kind: &str,
    object: &Value,
) -> Option<Int32Violation> {
    if !has_out_of_range_number(object) {
        return None;
    }
    let name = message_name(group, version, kind);
    message_index().get(&name)?;
    walk_message(&name, object, &mut Vec::new())
}

fn violation(n: &Value, owner: &str, keys: &[String], key: &str) -> Option<Int32Violation> {
    let Value::Number(num) = n else { return None };
    if !out_of_range(num) {
        return None;
    }
    let mut path = keys.to_vec();
    path.push(key.to_string());
    Some(Int32Violation {
        value: num.to_string(),
        owner: owner.rsplit('.').next().unwrap_or(owner).to_string(),
        path: path.join("."),
    })
}

fn walk_message(name: &str, value: &Value, keys: &mut Vec<String>) -> Option<Int32Violation> {
    let index = message_index();
    if OPAQUE_MESSAGES.contains(&name) {
        return None;
    }
    let message = index.get(name)?;
    let object = value.as_object()?;
    for field in &message.field {
        if is_inline_embed(name, field.name()) {
            if let Some(v) = walk_message(field.type_name(), value, keys) {
                return Some(v);
            }
            continue;
        }
        let key = json_key(name, field.name(), field.json_name());
        let Some(child) = object.get(&key) else {
            continue;
        };
        let items: Vec<&Value> = if field.label() == Label::Repeated {
            match child {
                Value::Array(a) => a.iter().collect(),
                Value::Object(o) => o.values().collect(),
                _ => continue,
            }
        } else {
            vec![child]
        };
        for item in items {
            let found = match field.r#type() {
                Type::Int32 => violation(item, name, keys, &key),
                Type::Message if field.type_name() == INT_OR_STRING => {
                    violation(item, name, keys, &key)
                }
                Type::Message => {
                    keys.push(key.clone());
                    let nested = match map_entry_value(field.type_name()) {
                        Some(MapValue::Int32) => item
                            .as_object()
                            .and_then(|o| o.iter().find_map(|(k, v)| violation(v, name, keys, k))),
                        Some(MapValue::Message(ty)) => item
                            .as_object()
                            .and_then(|o| o.values().find_map(|v| walk_message(ty, v, keys))),
                        Some(MapValue::Other) => None,
                        None => walk_message(field.type_name(), item, keys),
                    };
                    keys.pop();
                    nested
                }
                _ => None,
            };
            if found.is_some() {
                return found;
            }
        }
    }
    None
}

enum MapValue {
    Int32,
    Message(&'static str),
    Other,
}

/// For protoc's synthetic `map<K, V>` entry message, what `V` is; `None` for ordinary messages.
fn map_entry_value(type_name: &str) -> Option<MapValue> {
    let entry = message_index().get(type_name)?;
    if !entry.options.as_ref().is_some_and(|o| o.map_entry()) {
        return None;
    }
    let value = entry.field.iter().find(|f| f.name() == "value")?;
    Some(match value.r#type() {
        Type::Int32 => MapValue::Int32,
        Type::Message => MapValue::Message(value.type_name()),
        _ => MapValue::Other,
    })
}

/// Upstream `ValidatePodSpec` port checks: `containerPort` is required and every non-zero
/// `hostPort` and each `containerPort` must be a valid port number.
fn pod_port_error(pod: &Value) -> Option<String> {
    let spec = &pod["spec"];
    for list in ["containers", "initContainers"] {
        let Some(containers) = spec[list].as_array() else {
            continue;
        };
        for (ci, container) in containers.iter().enumerate() {
            let Some(ports) = container["ports"].as_array() else {
                continue;
            };
            for (pi, port) in ports.iter().enumerate() {
                let at = format!("spec.{list}[{ci}].ports[{pi}]");
                let container_port = port["containerPort"].as_i64().unwrap_or(0);
                if container_port == 0 {
                    return Some(format!("{at}.containerPort: Required value"));
                }
                for (field, n) in [
                    ("containerPort", container_port),
                    ("hostPort", port["hostPort"].as_i64().unwrap_or(0)),
                ] {
                    if (field == "hostPort" && n == 0) || (1..=65535).contains(&n) {
                        continue;
                    }
                    return Some(format!(
                        "{at}.{field}: Invalid value: {n}: must be between 1 and 65535, inclusive"
                    ));
                }
            }
        }
    }
    None
}

/// Rejects a CREATE/UPDATE body that upstream's typed decode or validation would refuse for an
/// int32 field or pod port. Runs ahead of every admission plugin and policy so none of them
/// evaluates a value the object can never be stored with.
pub(crate) fn validate_write<S: Store>(
    state: &AppState<S>,
    ctx: &AdmissionContext<'_>,
    object: &Value,
) -> Result<(), StatusError> {
    if ctx.operation != "CREATE" && ctx.operation != "UPDATE" {
        return Ok(());
    }
    let (resource, sub) = ctx.resource.split_once('/').unwrap_or((ctx.resource, ""));
    if !matches!(sub, "" | "status" | "ephemeralcontainers") {
        return Ok(());
    }
    let kind = if ctx.group.is_empty() {
        crate::types::ApiResourceList::v1()
            .resources
            .iter()
            .find(|r| r.name == resource)
            .map(|r| r.kind.to_string())
    } else {
        let key = crate::types::ResourceKey {
            group: ctx.group.to_string(),
            version: ctx.version.to_string(),
            plural: resource.to_string(),
        };
        state
            .resource_registry
            .get(&key)
            .map(|m| m.kind.to_string())
    };
    let Some(kind) = kind else {
        return Ok(());
    };
    if let Some(v) = find_int32_violation(ctx.group, ctx.version, &kind, object) {
        let api_version = if ctx.group.is_empty() {
            ctx.version.to_string()
        } else {
            format!("{}/{}", ctx.group, ctx.version)
        };
        return Err(Status::bad_request(v.message(&kind, &api_version)));
    }
    if ctx.group.is_empty() && resource == "pods" && sub.is_empty() {
        if let Some(e) = pod_port_error(object) {
            let name = object["metadata"]["name"].as_str().unwrap_or(ctx.name);
            return Err(Status::unprocessable_entity(format!(
                "Pod \"{name}\" is invalid: {e}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pod_with_port(port: Value) -> Value {
        json!({"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "ports": [port]}]}})
    }

    /// The audited reproduction: 4294967318 wraps to 22 in the protobuf encoder, so a range
    /// policy admitted a "hostPort >= 1024" pod that protobuf clients saw on port 22.
    #[test]
    fn host_port_that_wraps_to_a_privileged_port_is_rejected() {
        let pod = pod_with_port(json!({"containerPort": 80, "hostPort": 4294967318u64}));
        let v = find_int32_violation("", "v1", "Pod", &pod).expect("must be rejected");
        assert_eq!(v.path, "spec.containers.ports.hostPort");
        assert_eq!(v.owner, "ContainerPort");
        assert_eq!(
            v.message("Pod", "v1"),
            "Pod in version \"v1\" cannot be handled as a Pod: json: cannot unmarshal number \
             4294967318 into Go struct field ContainerPort.spec.containers.ports.hostPort of \
             type int32"
        );
    }

    /// Values at the int32 edges are valid objects upstream; rejecting them would break clients.
    #[test]
    fn int32_boundaries_are_accepted_and_one_past_is_rejected() {
        let ok = json!({"spec": {"activeDeadlineSeconds": 4294967296u64, "priority": 2147483647}});
        assert_eq!(find_int32_violation("", "v1", "Pod", &ok), None);
        let high = json!({"spec": {"priority": 2147483648u64}});
        assert!(find_int32_violation("", "v1", "Pod", &high).is_some());
        let low = json!({"spec": {"priority": -2147483649i64}});
        assert!(find_int32_violation("", "v1", "Pod", &low).is_some());
    }

    /// int64 fields legitimately exceed int32; flagging them would reject valid objects.
    #[test]
    fn int64_fields_beyond_int32_are_not_flagged() {
        let pod = json!({"spec": {"activeDeadlineSeconds": 5000000000i64,
            "securityContext": {"runAsUser": 5000000000i64}}});
        assert_eq!(find_int32_violation("", "v1", "Pod", &pod), None);
    }

    /// Fields beyond hostPort: probes, security-context-free scalars, nested init containers,
    /// service ports, node daemon endpoints, EndpointSlice ports and IntOrString all narrow to
    /// int32 in the encoders and must be guarded by the same check.
    #[test]
    fn every_int32_family_the_encoders_narrow_is_guarded() {
        let big = 4294967318u64;
        let cases = [
            (
                "Pod",
                "",
                "v1",
                json!({"spec": {"containers": [{"livenessProbe": {"periodSeconds": big}}]}}),
                "spec.containers.livenessProbe.periodSeconds",
            ),
            (
                "Pod",
                "",
                "v1",
                json!({"spec": {"initContainers": [{"ports": [{"containerPort": big}]}]}}),
                "spec.initContainers.ports.containerPort",
            ),
            (
                "Pod",
                "",
                "v1",
                json!({"spec": {"volumes": [{"secret": {"defaultMode": big}}]}}),
                "spec.volumes.secret.defaultMode",
            ),
            (
                "Pod",
                "",
                "v1",
                json!({"status": {"containerStatuses": [{"restartCount": big}]}}),
                "status.containerStatuses.restartCount",
            ),
            (
                "Service",
                "",
                "v1",
                json!({"spec": {"ports": [{"port": big}]}}),
                "spec.ports.port",
            ),
            (
                "Service",
                "",
                "v1",
                json!({"spec": {"ports": [{"port": 80, "nodePort": big}]}}),
                "spec.ports.nodePort",
            ),
            (
                "Service",
                "",
                "v1",
                json!({"spec": {"healthCheckNodePort": big}}),
                "spec.healthCheckNodePort",
            ),
            (
                "Service",
                "",
                "v1",
                json!({"spec": {"ports": [{"port": 80, "targetPort": big}]}}),
                "spec.ports.targetPort",
            ),
            (
                "Node",
                "",
                "v1",
                json!({"status": {"daemonEndpoints": {"kubeletEndpoint": {"port": big}}}}),
                "status.daemonEndpoints.kubeletEndpoint.port",
            ),
            (
                "Endpoints",
                "",
                "v1",
                json!({"subsets": [{"ports": [{"port": big}]}]}),
                "subsets.ports.port",
            ),
            (
                "EndpointSlice",
                "discovery.k8s.io",
                "v1",
                json!({"ports": [{"port": big}]}),
                "ports.port",
            ),
            ("Event", "", "v1", json!({"count": big}), "count"),
        ];
        for (kind, group, version, obj, path) in cases {
            let v = find_int32_violation(group, version, kind, &obj)
                .unwrap_or_else(|| panic!("{kind} {path} out of int32 must be rejected"));
            assert_eq!(v.path, path, "{kind}");
        }
    }

    /// Defense in depth: a stored out-of-range value must vanish from the protobuf form rather
    /// than wrap into a different valid-looking port (4294967318 wraps to 22).
    #[test]
    fn encoder_never_wraps_out_of_range_int32() {
        use crate::core_gen_adapter::ji32;
        assert_eq!(ji32(&json!({"p": 4294967318u64}), "p"), None);
        assert_eq!(ji32(&json!({"p": -4294967318i64}), "p"), None);
        assert_eq!(ji32(&json!({"p": 2147483647}), "p"), Some(i32::MAX));
        let pod = pod_with_port(json!({"containerPort": 80, "hostPort": 4294967318u64}));
        let encoded = crate::core_gen_adapter::encode_pod_proto_gen(&pod);
        let decoded = crate::core_gen_adapter::decode_pod_proto_gen(&encoded).unwrap();
        assert!(
            decoded["spec"]["containers"][0]["ports"][0]
                .get("hostPort")
                .is_none(),
            "hostPort must be absent, not wrapped: {decoded}"
        );
    }

    /// Same wraparound class for negatives: -4294967318 wraps to a positive value.
    #[test]
    fn negative_overflow_is_rejected() {
        let pod = pod_with_port(json!({"containerPort": -4294967318i64}));
        assert!(find_int32_violation("", "v1", "Pod", &pod).is_some());
    }

    #[test]
    fn host_port_outside_port_range_gets_upstream_text() {
        let pod = pod_with_port(json!({"containerPort": 80, "hostPort": 70000}));
        assert_eq!(
            pod_port_error(&pod).as_deref(),
            Some(
                "spec.containers[0].ports[0].hostPort: Invalid value: 70000: must be between 1 \
                 and 65535, inclusive"
            )
        );
    }

    #[test]
    fn container_port_zero_is_required_and_valid_ports_pass() {
        let zero = pod_with_port(json!({"hostPort": 8080}));
        assert_eq!(
            pod_port_error(&zero).as_deref(),
            Some("spec.containers[0].ports[0].containerPort: Required value")
        );
        let ok = pod_with_port(json!({"containerPort": 80, "hostPort": 65535}));
        assert_eq!(pod_port_error(&ok), None);
        let unset_host = pod_with_port(json!({"containerPort": 80}));
        assert_eq!(pod_port_error(&unset_host), None);
    }

    /// Create and update (including subresource) writes reach the shared admission entry, so an
    /// out-of-range body must be refused on each: guarding only create would let a later update
    /// reintroduce the JSON/protobuf divergence on a stored object.
    #[tokio::test]
    async fn create_and_update_reject_out_of_range_int32() {
        use crate::handlers::pods::create_pod;
        use axum::extract::{Path, Query, State};
        use bytes::Bytes;
        use u7s_store::SqliteStore;

        let store = std::sync::Arc::new(SqliteStore::new(":memory:").unwrap());
        let state = crate::handlers::test_support::make_state_with_store(store.clone());
        store
            .put(
                "/registry/namespaces/default",
                Bytes::from(
                    json!({"kind": "Namespace", "metadata": {"name": "default"}}).to_string(),
                ),
                None,
            )
            .await
            .unwrap();
        let user = || {
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            })
        };
        let headers = |ct: &str| {
            let mut h = axum::http::HeaderMap::new();
            h.insert(axum::http::header::CONTENT_TYPE, ct.parse().unwrap());
            h
        };
        let pod = |host_port: Value| {
            json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "p", "namespace": "default"},
                "spec": {"containers": [{"name": "c", "image": "nginx",
                    "ports": [{"containerPort": 80, "hostPort": host_port}]}]}
            })
        };
        let create = |p: Value| {
            create_pod(
                State(state.clone()),
                Path(("default".to_string(),)),
                Query(crate::handlers::json_patch::CreateQuery::default()),
                user(),
                headers("application/json"),
                Bytes::from(p.to_string()),
            )
        };

        let err = create(pod(json!(4294967318u64)))
            .await
            .err()
            .expect("create must reject");
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
        assert!(
            err.1.message.contains("hostPort of type int32"),
            "{}",
            err.1.message
        );
        let err = create(pod(json!(70000)))
            .await
            .err()
            .expect("range must reject");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            err.1.message.contains("must be between 1 and 65535"),
            "{}",
            err.1.message
        );

        assert!(
            create(pod(json!(8080))).await.is_ok(),
            "valid pod must be admitted"
        );

        // Updates reach the same entry. A pod PUT/PATCH with a changed spec is stopped earlier
        // by immutability, so the UPDATE arm is exercised on kinds whose spec is mutable.
        let update_ctx = |resource: &'static str| AdmissionContext {
            group: "",
            version: "v1",
            resource,
            name: "x",
            namespace: Some("default"),
            operation: "UPDATE",
            user_info: None,
            dry_run: false,
        };
        let svc = json!({"spec": {"ports": [{"port": 4294967318u64}]}});
        let err = validate_write(&state, &update_ctx("services"), &svc)
            .expect_err("Service UPDATE must reject");
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
        let status = json!({"status": {"containerStatuses": [{"restartCount": 4294967318u64}]}});
        assert!(
            validate_write(&state, &update_ctx("pods/status"), &status).is_err(),
            "kubelet status writes must not store a count the protobuf encoder would wrap"
        );
        let delete_ctx = AdmissionContext {
            operation: "DELETE",
            ..update_ctx("services")
        };
        assert!(
            validate_write(&state, &delete_ctx, &svc).is_ok(),
            "DELETE of a legacy object must not be blocked by write validation"
        );
    }
}
