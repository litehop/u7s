use prost::Message;

use u7s_proto_generated::k8s::io::api::storagemigration::v1 as svm_v1;

/// Decodes a protobuf-encoded `storagemigration.k8s.io/v1` StorageVersionMigration into the
/// JSON shape the generic handlers store, so typed clients that speak protobuf can create it.
pub fn decode_storageversionmigration_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = svm_v1::StorageVersionMigration::decode(data).ok()?;
    let mut out = serde_json::Map::new();
    out.insert("apiVersion".into(), "storagemigration.k8s.io/v1".into());
    out.insert("kind".into(), "StorageVersionMigration".into());
    out.insert(
        "metadata".into(),
        crate::core_gen_adapter::gen_object_meta_to_json(obj.metadata.unwrap_or_default()),
    );
    if let Some(spec) = obj.spec {
        let mut resource = serde_json::Map::new();
        if let Some(r) = spec.resource {
            if let Some(g) = r.group.filter(|g| !g.is_empty()) {
                resource.insert("group".into(), g.into());
            }
            if let Some(name) = r.resource {
                resource.insert("resource".into(), name.into());
            }
        }
        out.insert(
            "spec".into(),
            serde_json::json!({ "resource": serde_json::Value::Object(resource) }),
        );
    }
    if let Some(status) = obj.status {
        let mut s = serde_json::Map::new();
        if !status.conditions.is_empty() {
            s.insert(
                "conditions".into(),
                status
                    .conditions
                    .into_iter()
                    .map(crate::core_gen_adapter::gen_meta_condition_to_json)
                    .collect(),
            );
        }
        if let Some(rv) = status.resource_version.filter(|v| !v.is_empty()) {
            s.insert("resourceVersion".into(), rv.into());
        }
        out.insert("status".into(), serde_json::Value::Object(s));
    }
    Some(serde_json::Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use u7s_proto_generated::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

    /// A typed protobuf client creating a migration must not lose the target resource, or
    /// the stored object would fail the spec's required-resource validation after decode.
    #[test]
    fn decode_keeps_spec_resource_and_status_fields_from_protobuf_clients() {
        let obj = svm_v1::StorageVersionMigration {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("m".into()),
                ..Default::default()
            }),
            spec: Some(svm_v1::StorageVersionMigrationSpec {
                resource: Some(meta_v1::GroupResource {
                    group: Some("apps".into()),
                    resource: Some("deployments".into()),
                }),
            }),
            status: Some(svm_v1::StorageVersionMigrationStatus {
                conditions: vec![meta_v1::Condition {
                    r#type: Some("Running".into()),
                    status: Some("True".into()),
                    ..Default::default()
                }],
                resource_version: Some("42".into()),
            }),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let v = decode_storageversionmigration_proto_gen(&buf).expect("must decode");
        assert_eq!(v["kind"], "StorageVersionMigration");
        assert_eq!(v["apiVersion"], "storagemigration.k8s.io/v1");
        assert_eq!(v["metadata"]["name"], "m");
        assert_eq!(v["spec"]["resource"]["group"], "apps");
        assert_eq!(v["spec"]["resource"]["resource"], "deployments");
        assert_eq!(v["status"]["conditions"][0]["type"], "Running");
        assert_eq!(v["status"]["resourceVersion"], "42");
    }
}
