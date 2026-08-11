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

// Not delegated to core_gen_adapter's copy: this module's meta_v1::LabelSelector is generated
// into its own private OUT_DIR include, so it is a nominally distinct Rust type — same reason
// gen_object_meta_to_json above is its own copy rather than a shared call.
fn gen_label_selector_requirement_to_json(
    req: meta_v1::LabelSelectorRequirement,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(k) = req.key.filter(|s| !s.is_empty()) {
        m.insert("key".to_string(), serde_json::Value::String(k));
    }
    if let Some(op) = req.operator.filter(|s| !s.is_empty()) {
        m.insert("operator".to_string(), serde_json::Value::String(op));
    }
    if !req.values.is_empty() {
        m.insert(
            "values".to_string(),
            serde_json::Value::Array(
                req.values
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_label_selector_to_json(sel: meta_v1::LabelSelector) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !sel.match_labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = sel
            .match_labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m.insert("matchLabels".to_string(), serde_json::Value::Object(labels));
    }
    if !sel.match_expressions.is_empty() {
        m.insert(
            "matchExpressions".to_string(),
            serde_json::Value::Array(
                sel.match_expressions
                    .into_iter()
                    .map(gen_label_selector_requirement_to_json)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
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

fn gen_field_selector_requirement_to_json(
    req: meta_v1::FieldSelectorRequirement,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(k) = req.key.filter(|s| !s.is_empty()) {
        m.insert("key".to_string(), serde_json::Value::String(k));
    }
    if let Some(op) = req.operator.filter(|s| !s.is_empty()) {
        m.insert("operator".to_string(), serde_json::Value::String(op));
    }
    if !req.values.is_empty() {
        m.insert(
            "values".to_string(),
            serde_json::Value::Array(
                req.values
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_field_selector_attributes_to_json(
    fsa: authz_v1::FieldSelectorAttributes,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = fsa.raw_selector.filter(|s| !s.is_empty()) {
        m.insert("rawSelector".to_string(), serde_json::Value::String(v));
    }
    if !fsa.requirements.is_empty() {
        m.insert(
            "requirements".to_string(),
            serde_json::Value::Array(
                fsa.requirements
                    .into_iter()
                    .map(gen_field_selector_requirement_to_json)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_label_selector_attributes_to_json(
    lsa: authz_v1::LabelSelectorAttributes,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = lsa.raw_selector.filter(|s| !s.is_empty()) {
        m.insert("rawSelector".to_string(), serde_json::Value::String(v));
    }
    if !lsa.requirements.is_empty() {
        m.insert(
            "requirements".to_string(),
            serde_json::Value::Array(
                lsa.requirements
                    .into_iter()
                    .map(gen_label_selector_requirement_to_json)
                    .collect(),
            ),
        );
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
    // fieldSelector/labelSelector narrow a SubjectAccessReview to a field/label-limited request
    // (AuthorizeWithSelectors); dropping them makes the authorizer evaluate an unlimited
    // request instead of the narrower one the client actually asked about.
    if let Some(fs) = ra.field_selector {
        let fs_json = gen_field_selector_attributes_to_json(fs);
        if !fs_json.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            m.insert("fieldSelector".to_string(), fs_json);
        }
    }
    if let Some(ls) = ra.label_selector {
        let ls_json = gen_label_selector_attributes_to_json(ls);
        if !ls_json.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            m.insert("labelSelector".to_string(), ls_json);
        }
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
    // extra carries authenticator-supplied attributes (e.g. impersonation extras) that a
    // webhook authorizer or RBAC extra-based binding may key its decision on; dropping it
    // silently strips that context from every SubjectAccessReview.
    if !spec.extra.is_empty() {
        let extra: serde_json::Map<String, serde_json::Value> = spec
            .extra
            .into_iter()
            .map(|(k, v)| {
                let items: Vec<serde_json::Value> =
                    v.items.into_iter().map(serde_json::Value::String).collect();
                (k, serde_json::Value::Array(items))
            })
            .collect();
        m.insert("extra".to_string(), serde_json::Value::Object(extra));
    }
    serde_json::Value::Object(m)
}

// ---- rbac/v1 decoders ------------------------------------------------------

pub fn decode_clusterrole_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let cr = rbac_v1::ClusterRole::decode(data).ok()?;
    let meta = gen_object_meta_to_json(cr.metadata.unwrap_or_default());
    let rules: Vec<serde_json::Value> = cr.rules.into_iter().map(gen_policy_rule_to_json).collect();
    let mut obj = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": meta,
        "rules": rules
    });
    // aggregationRule drives the built-in admin/edit/view ClusterRole aggregation controller
    // (rbac.authorization.k8s.io/aggregate-to-* labels); dropping it here would silently turn
    // an aggregated ClusterRole into a plain, controller-unmanaged one on every re-decode.
    if let Some(ar) = cr.aggregation_rule {
        if !ar.cluster_role_selectors.is_empty() {
            let selectors: Vec<serde_json::Value> = ar
                .cluster_role_selectors
                .into_iter()
                .map(gen_label_selector_to_json)
                .collect();
            obj["aggregationRule"] = serde_json::json!({ "clusterRoleSelectors": selectors });
        }
    }
    Some(obj)
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

// Without a dispatch arm + decoder for SelfSubjectAccessReview/SelfSubjectRulesReview, a
// client-go authorization/v1 typed clientset call (default protobuf content-type) hits
// extract_body's undecodable fallback and handlers/authorization.rs's serde_json::from_slice
// fails to parse binary protobuf as JSON — every such call gets a hard 400, not just a
// dropped field. Argo CD calls SelfSubjectAccessReview on startup to discover its own
// permissions, so this blocked that workflow outright.

pub fn decode_selfsubjectaccessreview_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let ssar = authz_v1::SelfSubjectAccessReview::decode(data).ok()?;
    let self_spec = ssar.spec.unwrap_or_default();
    // SelfSubjectAccessReviewSpec carries only resourceAttributes/nonResourceAttributes (user
    // and groups must be empty — the server fills those in from the caller's identity), so
    // gen_sar_spec_to_json's handling of those two fields is reused via a SubjectAccessReviewSpec
    // built from them rather than duplicating that logic.
    let spec = gen_sar_spec_to_json(authz_v1::SubjectAccessReviewSpec {
        resource_attributes: self_spec.resource_attributes,
        non_resource_attributes: self_spec.non_resource_attributes,
        ..Default::default()
    });
    Some(serde_json::json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectAccessReview",
        "spec": spec
    }))
}

pub fn decode_selfsubjectrulesreview_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let ssrr = authz_v1::SelfSubjectRulesReview::decode(data).ok()?;
    let spec = ssrr.spec.unwrap_or_default();
    Some(serde_json::json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectRulesReview",
        "spec": {
            "namespace": spec.namespace.unwrap_or_default()
        }
    }))
}

// ---- authentication/v1 decoders --------------------------------------------

pub fn decode_token_review_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let tr = authn_v1::TokenReview::decode(data).ok()?;
    let spec = tr.spec.unwrap_or_default();
    let mut spec_json = serde_json::json!({
        "token": spec.token.unwrap_or_default()
    });
    // audiences lets an audience-aware caller (e.g. a projected service account token
    // consumer) scope the review to specific audiences; dropping it silently widens every
    // TokenReview to "any audience", defeating the audience check entirely.
    if !spec.audiences.is_empty() {
        spec_json["audiences"] = serde_json::Value::Array(
            spec.audiences
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    Some(serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": spec_json
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
        assert!(
            result["spec"]["resourceAttributes"]["namespace"].is_null(),
            "resourceAttributes.namespace must stay absent when unset — a spurious empty string \
             would make the authorizer evaluate this as a namespaced check instead of cluster-wide"
        );
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

    /// decode_clusterrolebinding_proto_gen must preserve roleRef and subjects.
    ///
    /// roleRef is what actually grants permissions; a dropped roleRef silently turns a
    /// ClusterRoleBinding into a binding that grants nothing to anyone.
    #[test]
    fn decode_clusterrolebinding_proto_gen_preserves_role_ref_and_subjects() {
        let crb = rbac_v1::ClusterRoleBinding {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-crb".to_string()),
                ..Default::default()
            }),
            subjects: vec![rbac_v1::Subject {
                kind: Some("User".to_string()),
                name: Some("alice".to_string()),
                api_group: Some("rbac.authorization.k8s.io".to_string()),
                ..Default::default()
            }],
            role_ref: Some(rbac_v1::RoleRef {
                api_group: Some("rbac.authorization.k8s.io".to_string()),
                kind: Some("ClusterRole".to_string()),
                name: Some("cluster-admin".to_string()),
            }),
        };
        let mut buf = Vec::new();
        crb.encode(&mut buf).unwrap();

        let result =
            decode_clusterrolebinding_proto_gen(&buf).expect("ClusterRoleBinding must decode");

        assert_eq!(
            result["roleRef"]["name"], "cluster-admin",
            "roleRef must survive decode — without it this binding grants no permissions to \
             anyone even though it appears to exist"
        );
        assert_eq!(
            result["subjects"][0]["name"], "alice",
            "subjects must survive decode — without them the binding has no one to grant \
             access to"
        );
    }

    /// decode_role_proto_gen must preserve rules.
    ///
    /// rules is the entire authorization contract of a Role; dropping it turns a
    /// least-privilege Role into one that grants nothing, breaking every ServiceAccount that
    /// depends on it.
    #[test]
    fn decode_role_proto_gen_preserves_rules() {
        let role = rbac_v1::Role {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("pod-reader".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            rules: vec![rbac_v1::PolicyRule {
                verbs: vec!["get".to_string(), "list".to_string()],
                api_groups: vec!["".to_string()],
                resources: vec!["pods".to_string()],
                ..Default::default()
            }],
        };
        let mut buf = Vec::new();
        role.encode(&mut buf).unwrap();

        let result = decode_role_proto_gen(&buf).expect("Role must decode");

        assert_eq!(
            result["rules"][0]["resources"][0], "pods",
            "rules must survive decode — without them every ServiceAccount bound to this Role \
             loses all access it was granted"
        );
        assert_eq!(
            result["rules"][0]["verbs"][0], "get",
            "rules[].verbs must survive decode"
        );
    }

    /// decode_rolebinding_proto_gen must preserve roleRef and subjects.
    ///
    /// Same failure mode as ClusterRoleBinding but namespace-scoped: a dropped roleRef or
    /// subject silently revokes access a namespace owner explicitly granted.
    #[test]
    fn decode_rolebinding_proto_gen_preserves_role_ref_and_subjects() {
        let rb = rbac_v1::RoleBinding {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-rb".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            subjects: vec![rbac_v1::Subject {
                kind: Some("ServiceAccount".to_string()),
                name: Some("my-sa".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }],
            role_ref: Some(rbac_v1::RoleRef {
                api_group: Some("rbac.authorization.k8s.io".to_string()),
                kind: Some("Role".to_string()),
                name: Some("pod-reader".to_string()),
            }),
        };
        let mut buf = Vec::new();
        rb.encode(&mut buf).unwrap();

        let result = decode_rolebinding_proto_gen(&buf).expect("RoleBinding must decode");

        assert_eq!(
            result["roleRef"]["name"], "pod-reader",
            "roleRef must survive decode — without it this binding grants no permissions"
        );
        assert_eq!(
            result["subjects"][0]["name"], "my-sa",
            "subjects must survive decode — without them the bound Role's permissions reach \
             no one"
        );
    }

    /// decode_local_subject_access_review_proto_gen must preserve spec.resourceAttributes.
    ///
    /// A namespaced authorization check (e.g. `kubectl auth can-i --namespace=foo`) sends this
    /// request; dropping resourceAttributes.namespace would make the check evaluate against
    /// the wrong (or no) namespace scope.
    #[test]
    fn decode_local_subject_access_review_proto_gen_preserves_resource_attributes() {
        let lsar = authz_v1::LocalSubjectAccessReview {
            spec: Some(authz_v1::SubjectAccessReviewSpec {
                user: Some("bob".to_string()),
                resource_attributes: Some(authz_v1::ResourceAttributes {
                    namespace: Some("dev".to_string()),
                    verb: Some("delete".to_string()),
                    resource: Some("pods".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        lsar.encode(&mut buf).unwrap();

        let result = decode_local_subject_access_review_proto_gen(&buf)
            .expect("LocalSubjectAccessReview must decode");

        assert_eq!(
            result["spec"]["resourceAttributes"]["namespace"], "dev",
            "resourceAttributes.namespace must survive decode — without it a namespaced \
             `kubectl auth can-i` check silently evaluates against the wrong scope"
        );
        assert_eq!(
            result["spec"]["resourceAttributes"]["verb"], "delete",
            "resourceAttributes.verb must survive decode"
        );
    }

    /// decode_token_review_proto_gen must preserve spec.token.
    ///
    /// The webhook/OIDC authenticator has only this token to authenticate the caller with; a
    /// dropped token turns every TokenReview into an unauthenticated request that the
    /// authenticator must reject, silently locking out an entire auth path.
    #[test]
    fn decode_token_review_proto_gen_preserves_token() {
        let tr = authn_v1::TokenReview {
            spec: Some(authn_v1::TokenReviewSpec {
                token: Some("opaque-bearer-token-abc123".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        tr.encode(&mut buf).unwrap();

        let result = decode_token_review_proto_gen(&buf).expect("TokenReview must decode");

        assert_eq!(
            result["spec"]["token"], "opaque-bearer-token-abc123",
            "spec.token must survive decode — the authenticator has nothing else to \
             authenticate the caller with, so a dropped token fails every request behind this \
             auth path"
        );
    }

    /// decode_token_review_proto_gen must preserve spec.audiences.
    ///
    /// An audience-aware authenticator rejects a token whose audiences don't intersect the
    /// review's spec.audiences; dropping this field silently disables that check for every
    /// TokenReview, widening it to "any audience".
    #[test]
    fn decode_token_review_proto_gen_preserves_audiences() {
        let tr = authn_v1::TokenReview {
            spec: Some(authn_v1::TokenReviewSpec {
                token: Some("opaque-bearer-token-abc123".to_string()),
                audiences: vec!["api".to_string(), "vault".to_string()],
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        tr.encode(&mut buf).unwrap();

        let result = decode_token_review_proto_gen(&buf).expect("TokenReview must decode");

        assert_eq!(
            result["spec"]["audiences"][0], "api",
            "spec.audiences must survive decode — without it an audience-aware authenticator \
             cannot tell which audiences the caller actually asked to be validated for"
        );
        assert_eq!(result["spec"]["audiences"][1], "vault");
    }

    /// decode_clusterrole_proto_gen must preserve aggregationRule.
    ///
    /// The built-in admin/edit/view ClusterRoles (and any custom aggregated ClusterRole) rely
    /// on this field to let the aggregation controller find and fold in matching ClusterRoles;
    /// dropping it silently turns an aggregated role into an inert, controller-unmanaged one.
    #[test]
    fn decode_clusterrole_proto_gen_preserves_aggregation_rule() {
        let cr = rbac_v1::ClusterRole {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("admin".to_string()),
                ..Default::default()
            }),
            aggregation_rule: Some(rbac_v1::AggregationRule {
                cluster_role_selectors: vec![meta_v1::LabelSelector {
                    match_labels: std::collections::HashMap::from([(
                        "rbac.authorization.k8s.io/aggregate-to-admin".to_string(),
                        "true".to_string(),
                    )]),
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        cr.encode(&mut buf).unwrap();

        let result = decode_clusterrole_proto_gen(&buf)
            .expect("ClusterRole with aggregationRule must decode");

        assert_eq!(
            result["aggregationRule"]["clusterRoleSelectors"][0]["matchLabels"]
                ["rbac.authorization.k8s.io/aggregate-to-admin"],
            "true",
            "aggregationRule.clusterRoleSelectors must survive decode — without it the \
             aggregation controller never folds matching ClusterRoles' rules into this one"
        );
    }

    /// decode_subject_access_review_proto_gen must preserve spec.extra.
    ///
    /// extra carries authenticator context (e.g. impersonation extras) that a webhook
    /// authorizer or extras-keyed RBAC binding may condition its decision on; dropping it
    /// silently strips that context from the authorization check.
    #[test]
    fn decode_subject_access_review_proto_gen_preserves_extra() {
        let sar = authz_v1::SubjectAccessReview {
            spec: Some(authz_v1::SubjectAccessReviewSpec {
                user: Some("alice".to_string()),
                extra: std::collections::HashMap::from([(
                    "authentication.kubernetes.io/pod-name".to_string(),
                    authz_v1::ExtraValue {
                        items: vec!["my-pod".to_string()],
                    },
                )]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        sar.encode(&mut buf).unwrap();

        let result = decode_subject_access_review_proto_gen(&buf)
            .expect("SubjectAccessReview with extra must decode");

        assert_eq!(
            result["spec"]["extra"]["authentication.kubernetes.io/pod-name"][0], "my-pod",
            "spec.extra must survive decode — without it a webhook authorizer or extras-keyed \
             RBAC binding loses the authenticator context it needs to make its decision"
        );
    }

    /// decode_subject_access_review_proto_gen must preserve resourceAttributes.fieldSelector
    /// and .labelSelector.
    ///
    /// AuthorizeWithSelectors narrows the check to a field/label-limited request; dropping
    /// these silently widens the authorizer's evaluation to an unlimited request, which can
    /// make a narrowly-scoped `kubectl auth can-i` check report an incorrect answer.
    #[test]
    fn decode_subject_access_review_proto_gen_preserves_field_and_label_selectors() {
        let sar = authz_v1::SubjectAccessReview {
            spec: Some(authz_v1::SubjectAccessReviewSpec {
                resource_attributes: Some(authz_v1::ResourceAttributes {
                    resource: Some("pods".to_string()),
                    field_selector: Some(authz_v1::FieldSelectorAttributes {
                        raw_selector: Some("spec.nodeName=node-1".to_string()),
                        ..Default::default()
                    }),
                    label_selector: Some(authz_v1::LabelSelectorAttributes {
                        raw_selector: Some("app=web".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        sar.encode(&mut buf).unwrap();

        let result = decode_subject_access_review_proto_gen(&buf)
            .expect("SubjectAccessReview with selectors must decode");

        assert_eq!(
            result["spec"]["resourceAttributes"]["fieldSelector"]["rawSelector"],
            "spec.nodeName=node-1",
            "resourceAttributes.fieldSelector must survive decode"
        );
        assert_eq!(
            result["spec"]["resourceAttributes"]["labelSelector"]["rawSelector"], "app=web",
            "resourceAttributes.labelSelector must survive decode"
        );
    }

    // ---- Sentinel completeness ----
    //
    // Each test below builds a message with every field set to a value no zero/empty-elision
    // check in this file's gen_*_to_json functions could mistake for "unset" (see
    // u7s_sentinel::Sentinel), decodes it through the real decode_*_proto_gen entry point, and
    // asserts every field name shows up somewhere in the resulting JSON. A name that never
    // appears means some gen_*_to_json function never reads that field from the decoded
    // protobuf struct at all — this is exactly how aggregationRule, extra, fieldSelector,
    // labelSelector, and TokenReviewSpec.audiences were found missing from this file.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    // selfLink is a legacy field the system no longer populates — permanently omitted.
    // deletionTimestamp/deletionGracePeriodSeconds/managedFields are left off `expected`
    // pending a separate investigation into gen_object_meta_to_json's correct handling of
    // them; do not guess at the fix here.
    // labels/annotations are maps: their own field name is never a real leaf once populated,
    // only their sentinel-populated entry is (the deterministic "__sentinel__" map-key literal
    // u7s_sentinel's blanket `Sentinel for String` always produces). ownerReferences is an array
    // of a real struct (OwnerReference), so its own field name is likewise never a leaf; `uid`
    // pins the check to ownerReferences specifically rather than colliding with ObjectMeta's own
    // (separately checked) `uid`.
    const OBJECT_META_EXPECTED: &[&str] = &[
        "name",
        "generateName",
        "namespace",
        "uid",
        "resourceVersion",
        "generation",
        "creationTimestamp",
        "labels.__sentinel__",
        "annotations.__sentinel__",
        "ownerReferences.uid",
        "finalizers",
    ];

    #[test]
    fn sentinel_completeness_decode_clusterrole_proto_gen() {
        let cr = rbac_v1::ClusterRole {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            rules: vec![rbac_v1::PolicyRule::sentinel()],
            aggregation_rule: Some(rbac_v1::AggregationRule::sentinel()),
        };
        let mut buf = Vec::new();
        cr.encode(&mut buf).unwrap();
        let decoded = decode_clusterrole_proto_gen(&buf)
            .expect("sentinel ClusterRole must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // "clusterRoleSelectors" is an array of LabelSelector; its own field name and its
        // matchLabels (a map)/matchExpressions (an array of struct) children are all containers
        // whose own field name is never itself a leaf once populated.
        expected.extend([
            "verbs",
            "apiGroups",
            "resources",
            "resourceNames",
            "nonResourceURLs",
            "clusterRoleSelectors.matchLabels.__sentinel__",
            "clusterRoleSelectors.matchExpressions.key",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_clusterrolebinding_proto_gen() {
        let crb = rbac_v1::ClusterRoleBinding {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            subjects: vec![rbac_v1::Subject::sentinel()],
            role_ref: Some(rbac_v1::RoleRef::sentinel()),
        };
        let mut buf = Vec::new();
        crb.encode(&mut buf).unwrap();
        let decoded = decode_clusterrolebinding_proto_gen(&buf)
            .expect("sentinel ClusterRoleBinding must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // roleRef.apiGroup and subjects[].apiGroup collide by name with metadata's own
        // apiVersion-adjacent fields only in spelling, not value — no masking risk here.
        expected.extend(["apiGroup", "kind", "name", "namespace"]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_role_proto_gen() {
        let role = rbac_v1::Role {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            rules: vec![rbac_v1::PolicyRule::sentinel()],
        };
        let mut buf = Vec::new();
        role.encode(&mut buf).unwrap();
        let decoded =
            decode_role_proto_gen(&buf).expect("sentinel Role must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "verbs",
            "apiGroups",
            "resources",
            "resourceNames",
            "nonResourceURLs",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_rolebinding_proto_gen() {
        let rb = rbac_v1::RoleBinding {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            subjects: vec![rbac_v1::Subject::sentinel()],
            role_ref: Some(rbac_v1::RoleRef::sentinel()),
        };
        let mut buf = Vec::new();
        rb.encode(&mut buf).unwrap();
        let decoded = decode_rolebinding_proto_gen(&buf)
            .expect("sentinel RoleBinding must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(["apiGroup", "kind", "name", "namespace"]);
        assert_fields_present(&paths, &expected);
    }

    /// decode_local_subject_access_review_proto_gen calls this exact same gen_sar_spec_to_json,
    /// so its own completeness is covered by this test too; a separate hand-written test
    /// (decode_local_subject_access_review_proto_gen_preserves_resource_attributes) already
    /// checks that its dispatch path actually reaches that shared function.
    #[test]
    fn sentinel_completeness_decode_subject_access_review_proto_gen() {
        let sar = authz_v1::SubjectAccessReview {
            // metadata/status are left at their zero value: SubjectAccessReview is a virtual,
            // non-persisted resource — real clients never set metadata, and status is always
            // server-computed, never client-supplied on the request this decoder handles.
            spec: Some(authz_v1::SubjectAccessReviewSpec::sentinel()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        sar.encode(&mut buf).unwrap();
        let decoded = decode_subject_access_review_proto_gen(&buf)
            .expect("sentinel SubjectAccessReview must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        // "requirements" is a container (array of a real struct) whose own field name is never
        // itself a leaf once populated; key/operator/values below already prove it survived.
        // "extra" is a map<string, ExtraValue>, but ExtraValue (Go `[]string`) marshals as a
        // bare JSON array — the sentinel-populated map entry itself is the leaf.
        let expected = [
            "namespace",
            "verb",
            "group",
            "version",
            "resource",
            "subresource",
            "name",
            "rawSelector",
            "key",
            "operator",
            "values",
            "path",
            "user",
            "groups",
            "extra.__sentinel__",
            "uid",
        ];
        assert_fields_present(&paths, &expected);
    }

    /// Derived from the .proto schema (rather than hand-listed) so a field added upstream to
    /// SelfSubjectAccessReviewSpec is demanded automatically. Scoped to the Spec message, not
    /// SubjectAccessReviewSpec, because user/groups/uid/extra are not part of this type at all
    /// (the server fills identity in from the caller) — expecting them here would make the test
    /// unfalsifiable for a decoder that reused gen_sar_spec_to_json incorrectly.
    #[test]
    fn sentinel_completeness_decode_selfsubjectaccessreview_proto_gen() {
        let ssar = authz_v1::SelfSubjectAccessReview {
            // metadata/status: same reasoning as SubjectAccessReview above — not a persisted
            // resource, and status is always server-computed.
            spec: Some(authz_v1::SelfSubjectAccessReviewSpec::sentinel()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ssar.encode(&mut buf).unwrap();
        let decoded = decode_selfsubjectaccessreview_proto_gen(&buf)
            .expect("sentinel SelfSubjectAccessReview must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.authorization.v1.SelfSubjectAccessReviewSpec",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_selfsubjectrulesreview_proto_gen() {
        let ssrr = authz_v1::SelfSubjectRulesReview {
            // metadata/status: not a persisted resource; status is always server-computed.
            spec: Some(authz_v1::SelfSubjectRulesReviewSpec::sentinel()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ssrr.encode(&mut buf).unwrap();
        let decoded = decode_selfsubjectrulesreview_proto_gen(&buf)
            .expect("sentinel SelfSubjectRulesReview must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.authorization.v1.SelfSubjectRulesReviewSpec",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_token_review_proto_gen() {
        let tr = authn_v1::TokenReview {
            // metadata/status: same reasoning as SubjectAccessReview above — not a persisted
            // resource, and status is always server-computed.
            spec: Some(authn_v1::TokenReviewSpec::sentinel()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        tr.encode(&mut buf).unwrap();
        let decoded = decode_token_review_proto_gen(&buf)
            .expect("sentinel TokenReview must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let expected = ["token", "audiences"];
        assert_fields_present(&paths, &expected);
    }

    // ---- Field-omission: all-default proto must decode with no stray nulls ----
    //
    // Each test below builds a message with every optional field unset (`Default::default()`),
    // decodes it through the real entry point, and asserts no key survives as an explicit JSON
    // `null` (other than ObjectMeta's `creationTimestamp`, which upstream always nulls when
    // zero). `indexing["missing_key"]` returns a static `Value::Null` for both an absent key and
    // a genuinely-null one, which is exactly how earlier tests in this file (see
    // `resourceAttributes.namespace` above) could pass even if a gen_*_to_json function started
    // inserting `null` unconditionally — these tests inspect the actual JSON object map instead.

    use crate::util::sentinel_test_util::assert_no_stray_nulls;

    #[test]
    fn decode_clusterrole_proto_gen_omits_unset_aggregation_rule_instead_of_emitting_null() {
        let cr = rbac_v1::ClusterRole::default();
        let mut buf = Vec::new();
        cr.encode(&mut buf).unwrap();
        let decoded =
            decode_clusterrole_proto_gen(&buf).expect("all-default ClusterRole must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("aggregationRule").is_none(),
            "an unset aggregationRule must be absent, not `null` — a client that checks \
             `if aggregationRule != null` to decide whether the aggregation controller manages \
             this role would misclassify a plain role as aggregated"
        );
    }

    #[test]
    fn decode_clusterrolebinding_proto_gen_omits_unset_role_ref_fields_instead_of_emitting_null() {
        let crb = rbac_v1::ClusterRoleBinding::default();
        let mut buf = Vec::new();
        crb.encode(&mut buf).unwrap();
        let decoded = decode_clusterrolebinding_proto_gen(&buf)
            .expect("all-default ClusterRoleBinding must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded["roleRef"].as_object().is_some_and(|m| m.is_empty()),
            "an unset RoleRef must decode to an empty object, not one with null apiGroup/kind/name \
             keys — a client that iterates roleRef's keys to detect \"which fields were set\" \
             would otherwise see three phantom fields"
        );
    }

    #[test]
    fn decode_role_proto_gen_omits_no_nulls_on_all_default_input() {
        let role = rbac_v1::Role::default();
        let mut buf = Vec::new();
        role.encode(&mut buf).unwrap();
        let decoded = decode_role_proto_gen(&buf).expect("all-default Role must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert_eq!(
            decoded["rules"].as_array().map(|a| a.len()),
            Some(0),
            "rules must decode to an empty array (matching upstream Role.rules, which has no \
             omitempty), not a null or missing key"
        );
    }

    #[test]
    fn decode_rolebinding_proto_gen_omits_unset_role_ref_fields_instead_of_emitting_null() {
        let rb = rbac_v1::RoleBinding::default();
        let mut buf = Vec::new();
        rb.encode(&mut buf).unwrap();
        let decoded =
            decode_rolebinding_proto_gen(&buf).expect("all-default RoleBinding must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded["roleRef"].as_object().is_some_and(|m| m.is_empty()),
            "an unset RoleRef must decode to an empty object, not null-valued keys"
        );
    }

    #[test]
    fn decode_subject_access_review_proto_gen_omits_unset_spec_fields_instead_of_emitting_null() {
        let sar = authz_v1::SubjectAccessReview::default();
        let mut buf = Vec::new();
        sar.encode(&mut buf).unwrap();
        let decoded = decode_subject_access_review_proto_gen(&buf)
            .expect("all-default SubjectAccessReview must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded["spec"].as_object().is_some_and(|m| {
                !m.contains_key("resourceAttributes") && !m.contains_key("nonResourceAttributes")
            }),
            "unset resourceAttributes/nonResourceAttributes must be absent, not null — a webhook \
             authorizer that branches on `spec.resourceAttributes != null` would otherwise treat \
             every review as a resource-scoped check even when none was requested"
        );
    }

    #[test]
    fn decode_local_subject_access_review_proto_gen_omits_no_nulls_on_all_default_input() {
        let lsar = authz_v1::LocalSubjectAccessReview::default();
        let mut buf = Vec::new();
        lsar.encode(&mut buf).unwrap();
        let decoded = decode_local_subject_access_review_proto_gen(&buf)
            .expect("all-default LocalSubjectAccessReview must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
    }

    #[test]
    fn decode_token_review_proto_gen_omits_unset_audiences_instead_of_emitting_null() {
        let tr = authn_v1::TokenReview::default();
        let mut buf = Vec::new();
        tr.encode(&mut buf).unwrap();
        let decoded =
            decode_token_review_proto_gen(&buf).expect("all-default TokenReview must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            !decoded["spec"]
                .as_object()
                .is_some_and(|m| m.contains_key("audiences")),
            "unset audiences must be absent, not null — an audience-aware authenticator that \
             checks `spec.audiences == null` to mean \"any audience\" happens to be safe here, \
             but the array must still be omitted rather than emitted as an empty/null value so \
             every authenticator agrees on the encoding"
        );
    }
}
