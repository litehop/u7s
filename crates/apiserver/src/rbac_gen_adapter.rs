use prost::Message;

use crate::rbac_authz_authn_gen::k8s::io::api::authentication::v1 as authn_v1;
use crate::rbac_authz_authn_gen::k8s::io::api::authorization::v1 as authz_v1;
use crate::rbac_authz_authn_gen::k8s::io::api::rbac::v1 as rbac_v1;
use crate::rbac_authz_authn_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

// ---- shared helpers --------------------------------------------------------

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
                    serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
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

fn gen_policy_rule_to_json(rule: rbac_v1::PolicyRule) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !rule.verbs.is_empty() {
        m.insert(
            "verbs".to_string(),
            serde_json::Value::Array(
                rule.verbs
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !rule.api_groups.is_empty() {
        m.insert(
            "apiGroups".to_string(),
            serde_json::Value::Array(
                rule.api_groups
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !rule.resources.is_empty() {
        m.insert(
            "resources".to_string(),
            serde_json::Value::Array(
                rule.resources
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !rule.resource_names.is_empty() {
        m.insert(
            "resourceNames".to_string(),
            serde_json::Value::Array(
                rule.resource_names
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !rule.non_resource_ur_ls.is_empty() {
        m.insert(
            "nonResourceURLs".to_string(),
            serde_json::Value::Array(
                rule.non_resource_ur_ls
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_subject_to_json(s: rbac_v1::Subject) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(k) = s.kind.filter(|s| !s.is_empty()) {
        m.insert("kind".to_string(), serde_json::Value::String(k));
    }
    if let Some(ag) = s.api_group {
        m.insert("apiGroup".to_string(), serde_json::Value::String(ag));
    }
    if let Some(n) = s.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(n));
    }
    if let Some(ns) = s.namespace.filter(|s| !s.is_empty()) {
        m.insert("namespace".to_string(), serde_json::Value::String(ns));
    }
    serde_json::Value::Object(m)
}

fn gen_role_ref_to_json(rr: rbac_v1::RoleRef) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(ag) = rr.api_group.filter(|s| !s.is_empty()) {
        m.insert("apiGroup".to_string(), serde_json::Value::String(ag));
    }
    if let Some(k) = rr.kind.filter(|s| !s.is_empty()) {
        m.insert("kind".to_string(), serde_json::Value::String(k));
    }
    if let Some(n) = rr.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(n));
    }
    serde_json::Value::Object(m)
}

fn gen_resource_attributes_to_json(ra: authz_v1::ResourceAttributes) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = ra.namespace.filter(|s| !s.is_empty()) {
        m.insert("namespace".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = ra.verb.filter(|s| !s.is_empty()) {
        m.insert("verb".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = ra.group.filter(|s| !s.is_empty()) {
        m.insert("group".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = ra.version.filter(|s| !s.is_empty()) {
        m.insert("version".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = ra.resource.filter(|s| !s.is_empty()) {
        m.insert("resource".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = ra.subresource.filter(|s| !s.is_empty()) {
        m.insert("subresource".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = ra.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

fn gen_non_resource_attributes_to_json(nra: authz_v1::NonResourceAttributes) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = nra.path.filter(|s| !s.is_empty()) {
        m.insert("path".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = nra.verb.filter(|s| !s.is_empty()) {
        m.insert("verb".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

fn gen_sar_spec_to_json(spec: authz_v1::SubjectAccessReviewSpec) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(ra) = spec.resource_attributes {
        let ra_json = gen_resource_attributes_to_json(ra);
        if !ra_json.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            m.insert("resourceAttributes".to_string(), ra_json);
        }
    }
    if let Some(nra) = spec.non_resource_attributes {
        let nra_json = gen_non_resource_attributes_to_json(nra);
        if !nra_json.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            m.insert("nonResourceAttributes".to_string(), nra_json);
        }
    }
    if let Some(u) = spec.user.filter(|s| !s.is_empty()) {
        m.insert("user".to_string(), serde_json::Value::String(u));
    }
    if !spec.groups.is_empty() {
        m.insert(
            "groups".to_string(),
            serde_json::Value::Array(
                spec.groups
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(uid) = spec.uid.filter(|s| !s.is_empty()) {
        m.insert("uid".to_string(), serde_json::Value::String(uid));
    }
    serde_json::Value::Object(m)
}

// ---- rbac/v1 decoders ------------------------------------------------------

pub fn decode_clusterrole_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let cr = rbac_v1::ClusterRole::decode(data).ok()?;
    let meta = gen_object_meta_to_json(cr.metadata.unwrap_or_default());
    let rules: Vec<serde_json::Value> = cr.rules.into_iter().map(gen_policy_rule_to_json).collect();
    Some(serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": meta,
        "rules": rules
    }))
}

pub fn decode_clusterrolebinding_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let crb = rbac_v1::ClusterRoleBinding::decode(data).ok()?;
    let meta = gen_object_meta_to_json(crb.metadata.unwrap_or_default());
    let subjects: Vec<serde_json::Value> =
        crb.subjects.into_iter().map(gen_subject_to_json).collect();
    let role_ref = crb
        .role_ref
        .map(gen_role_ref_to_json)
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
    Some(serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": meta,
        "subjects": subjects,
        "roleRef": role_ref
    }))
}

pub fn decode_role_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let role = rbac_v1::Role::decode(data).ok()?;
    let meta = gen_object_meta_to_json(role.metadata.unwrap_or_default());
    let rules: Vec<serde_json::Value> = role
        .rules
        .into_iter()
        .map(gen_policy_rule_to_json)
        .collect();
    Some(serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": meta,
        "rules": rules
    }))
}

pub fn decode_rolebinding_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let rb = rbac_v1::RoleBinding::decode(data).ok()?;
    let meta = gen_object_meta_to_json(rb.metadata.unwrap_or_default());
    let subjects: Vec<serde_json::Value> =
        rb.subjects.into_iter().map(gen_subject_to_json).collect();
    let role_ref = rb
        .role_ref
        .map(gen_role_ref_to_json)
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
    Some(serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": meta,
        "subjects": subjects,
        "roleRef": role_ref
    }))
}

// ---- authorization/v1 decoders ---------------------------------------------

pub fn decode_subject_access_review_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let sar = authz_v1::SubjectAccessReview::decode(data).ok()?;
    let spec = gen_sar_spec_to_json(sar.spec.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": spec
    }))
}

pub fn decode_local_subject_access_review_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let lsar = authz_v1::LocalSubjectAccessReview::decode(data).ok()?;
    let spec = gen_sar_spec_to_json(lsar.spec.unwrap_or_default());
    Some(serde_json::json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "LocalSubjectAccessReview",
        "spec": spec
    }))
}

// ---- authentication/v1 decoders --------------------------------------------

pub fn decode_token_review_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let tr = authn_v1::TokenReview::decode(data).ok()?;
    let spec = tr.spec.unwrap_or_default();
    Some(serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": {
            "token": spec.token.unwrap_or_default()
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// By-construction test: the generated SubjectAccessReviewSpec includes uid (field 6)
    /// which the hand-written SubjectAccessReviewSpec silently dropped. Without protobuf
    /// typegen, a SAR from a client that sets uid would lose that field, breaking
    /// authorization audit trails that depend on requestor identity.
    #[test]
    fn generated_sar_spec_preserves_uid_by_construction() {
        let spec = authz_v1::SubjectAccessReviewSpec {
            user: Some("alice".to_string()),
            uid: Some("uid-1234".to_string()),
            groups: vec!["system:authenticated".to_string()],
            resource_attributes: Some(authz_v1::ResourceAttributes {
                verb: Some("get".to_string()),
                resource: Some("pods".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let sar = authz_v1::SubjectAccessReview {
            spec: Some(spec),
            ..Default::default()
        };
        let mut buf = Vec::new();
        sar.encode(&mut buf).unwrap();

        let result = decode_subject_access_review_proto_gen(&buf)
            .expect("SubjectAccessReview with uid must decode");

        assert_eq!(
            result["spec"]["uid"], "uid-1234",
            "uid field (tag 6) must survive round-trip — the hand struct dropped it, breaking audit trails"
        );
        assert_eq!(result["spec"]["user"], "alice");
        assert_eq!(result["spec"]["resourceAttributes"]["verb"], "get");
    }

    /// ClusterRole nonResourceURLs are preserved end-to-end via the generated struct.
    /// The hand PolicyRule struct had nonResourceURLs but the field name was non_resource_urls;
    /// the generated name is non_resource_ur_ls (prost camelCase conversion). This test
    /// verifies the correct field survives the round-trip.
    #[test]
    fn generated_clusterrole_preserves_non_resource_urls() {
        let rule = rbac_v1::PolicyRule {
            verbs: vec!["get".to_string()],
            non_resource_ur_ls: vec!["/healthz".to_string()],
            ..Default::default()
        };
        let cr = rbac_v1::ClusterRole {
            rules: vec![rule],
            ..Default::default()
        };
        let mut buf = Vec::new();
        cr.encode(&mut buf).unwrap();

        let result = decode_clusterrole_proto_gen(&buf)
            .expect("ClusterRole must decode via generated adapter");

        let rules = result["rules"].as_array().expect("rules must be array");
        assert_eq!(
            rules[0]["nonResourceURLs"][0], "/healthz",
            "nonResourceURLs must survive round-trip through generated PolicyRule"
        );
    }
}
