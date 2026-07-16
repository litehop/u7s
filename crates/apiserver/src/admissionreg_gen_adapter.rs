use prost::Message;

use crate::admissionreg_gen::k8s::io::api::admissionregistration::v1 as ar_v1;
use crate::admissionreg_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

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

fn gen_label_selector_requirement_to_json(
    req: meta_v1::LabelSelectorRequirement,
) -> serde_json::Value {
    let mut m = serde_json::json!({});
    if let Some(k) = req.key.filter(|s| !s.is_empty()) {
        m["key"] = serde_json::Value::String(k);
    }
    if let Some(op) = req.operator.filter(|s| !s.is_empty()) {
        m["operator"] = serde_json::Value::String(op);
    }
    if !req.values.is_empty() {
        m["values"] = serde_json::Value::Array(
            req.values
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    m
}

fn gen_label_selector_to_json(sel: meta_v1::LabelSelector) -> serde_json::Value {
    let mut m = serde_json::json!({});
    if !sel.match_labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = sel
            .match_labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["matchLabels"] = serde_json::Value::Object(labels);
    }
    if !sel.match_expressions.is_empty() {
        m["matchExpressions"] = serde_json::Value::Array(
            sel.match_expressions
                .into_iter()
                .map(gen_label_selector_requirement_to_json)
                .collect(),
        );
    }
    m
}

fn gen_rule_with_operations_to_json(r: ar_v1::RuleWithOperations) -> serde_json::Value {
    let rule = r.rule.unwrap_or_default();
    serde_json::json!({
        "operations": r.operations,
        "apiGroups": rule.api_groups,
        "apiVersions": rule.api_versions,
        "resources": rule.resources,
        "scope": rule.scope.filter(|s| !s.is_empty()).unwrap_or_else(|| "*".to_string()),
    })
}

fn gen_named_rule_with_operations_to_json(r: ar_v1::NamedRuleWithOperations) -> serde_json::Value {
    let rwo = r.rule_with_operations.unwrap_or_default();
    let inner = rwo.rule.unwrap_or_default();
    let mut rule = serde_json::json!({
        "apiGroups": inner.api_groups,
        "apiVersions": inner.api_versions,
        "resources": inner.resources,
        "operations": rwo.operations,
    });
    if let Some(scope) = inner.scope.filter(|s| !s.is_empty()) {
        rule["scope"] = serde_json::Value::String(scope);
    }
    if !r.resource_names.is_empty() {
        rule["resourceNames"] = serde_json::Value::Array(
            r.resource_names
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    rule
}

fn gen_match_resources_to_json(mc: ar_v1::MatchResources) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    let resource_rules: Vec<serde_json::Value> = mc
        .resource_rules
        .into_iter()
        .map(gen_named_rule_with_operations_to_json)
        .collect();
    if !resource_rules.is_empty() {
        obj["resourceRules"] = serde_json::Value::Array(resource_rules);
    }
    let exclude_rules: Vec<serde_json::Value> = mc
        .exclude_resource_rules
        .into_iter()
        .map(gen_named_rule_with_operations_to_json)
        .collect();
    if !exclude_rules.is_empty() {
        obj["excludeResourceRules"] = serde_json::Value::Array(exclude_rules);
    }
    if let Some(ns) = mc.namespace_selector {
        obj["namespaceSelector"] = gen_label_selector_to_json(ns);
    }
    if let Some(os) = mc.object_selector {
        obj["objectSelector"] = gen_label_selector_to_json(os);
    }
    if let Some(mp) = mc.match_policy.filter(|s| !s.is_empty()) {
        obj["matchPolicy"] = serde_json::Value::String(mp);
    }
    obj
}

fn gen_param_ref_to_json(pr: ar_v1::ParamRef) -> serde_json::Value {
    let mut m = serde_json::json!({});
    if let Some(v) = pr.name.filter(|s| !s.is_empty()) {
        m["name"] = serde_json::Value::String(v);
    }
    if let Some(v) = pr.namespace.filter(|s| !s.is_empty()) {
        m["namespace"] = serde_json::Value::String(v);
    }
    if let Some(v) = pr.parameter_not_found_action.filter(|s| !s.is_empty()) {
        m["parameterNotFoundAction"] = serde_json::Value::String(v);
    }
    if let Some(sel) = pr.selector {
        m["selector"] = gen_label_selector_to_json(sel);
    }
    m
}

fn gen_match_conditions_to_json(conds: Vec<ar_v1::MatchCondition>) -> serde_json::Value {
    serde_json::Value::Array(
        conds
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name.unwrap_or_default(),
                    "expression": c.expression.unwrap_or_default(),
                })
            })
            .collect(),
    )
}

fn gen_webhook_client_config_to_json(cc: ar_v1::WebhookClientConfig) -> serde_json::Value {
    let mut cfg = serde_json::json!({});
    if let Some(ca) = cc.ca_bundle.filter(|b| !b.is_empty()) {
        cfg["caBundle"] = serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &ca,
        ));
    }
    if let Some(svc) = cc.service {
        let mut s = serde_json::json!({
            "namespace": svc.namespace.unwrap_or_default(),
            "name": svc.name.unwrap_or_default(),
        });
        if let Some(path) = svc.path.filter(|s| !s.is_empty()) {
            s["path"] = serde_json::Value::String(path);
        }
        if let Some(port) = svc.port.filter(|&v| v != 0) {
            s["port"] = serde_json::Value::Number(serde_json::Number::from(port));
        }
        cfg["service"] = s;
    }
    if let Some(url) = cc.url.filter(|s| !s.is_empty()) {
        cfg["url"] = serde_json::Value::String(url);
    }
    cfg
}

fn gen_validating_webhook_to_json(w: ar_v1::ValidatingWebhook) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = w
        .rules
        .into_iter()
        .map(gen_rule_with_operations_to_json)
        .collect();
    let client_config = w
        .client_config
        .map(gen_webhook_client_config_to_json)
        .unwrap_or(serde_json::json!({}));
    let mut entry = serde_json::json!({
        "name": w.name.unwrap_or_default(),
        "clientConfig": client_config,
        "rules": rules,
        "admissionReviewVersions": w.admission_review_versions,
    });
    if let Some(v) = w.failure_policy.filter(|s| !s.is_empty()) {
        entry["failurePolicy"] = serde_json::Value::String(v);
    }
    if let Some(v) = w.match_policy.filter(|s| !s.is_empty()) {
        entry["matchPolicy"] = serde_json::Value::String(v);
    }
    if let Some(v) = w.side_effects.filter(|s| !s.is_empty()) {
        entry["sideEffects"] = serde_json::Value::String(v);
    }
    if let Some(v) = w.timeout_seconds.filter(|&v| v != 0) {
        entry["timeoutSeconds"] = serde_json::Value::Number(serde_json::Number::from(v));
    }
    if let Some(ns) = w.namespace_selector {
        entry["namespaceSelector"] = gen_label_selector_to_json(ns);
    }
    if let Some(os) = w.object_selector {
        entry["objectSelector"] = gen_label_selector_to_json(os);
    }
    if !w.match_conditions.is_empty() {
        entry["matchConditions"] = gen_match_conditions_to_json(w.match_conditions);
    }
    entry
}

fn gen_mutating_webhook_to_json(w: ar_v1::MutatingWebhook) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = w
        .rules
        .into_iter()
        .map(gen_rule_with_operations_to_json)
        .collect();
    let client_config = w
        .client_config
        .map(gen_webhook_client_config_to_json)
        .unwrap_or(serde_json::json!({}));
    let mut entry = serde_json::json!({
        "name": w.name.unwrap_or_default(),
        "clientConfig": client_config,
        "rules": rules,
        "admissionReviewVersions": w.admission_review_versions,
    });
    if let Some(v) = w.failure_policy.filter(|s| !s.is_empty()) {
        entry["failurePolicy"] = serde_json::Value::String(v);
    }
    if let Some(v) = w.match_policy.filter(|s| !s.is_empty()) {
        entry["matchPolicy"] = serde_json::Value::String(v);
    }
    if let Some(v) = w.side_effects.filter(|s| !s.is_empty()) {
        entry["sideEffects"] = serde_json::Value::String(v);
    }
    if let Some(v) = w.timeout_seconds.filter(|&v| v != 0) {
        entry["timeoutSeconds"] = serde_json::Value::Number(serde_json::Number::from(v));
    }
    if let Some(v) = w.reinvocation_policy.filter(|s| !s.is_empty()) {
        entry["reinvocationPolicy"] = serde_json::Value::String(v);
    }
    if let Some(ns) = w.namespace_selector {
        entry["namespaceSelector"] = gen_label_selector_to_json(ns);
    }
    if let Some(os) = w.object_selector {
        entry["objectSelector"] = gen_label_selector_to_json(os);
    }
    if !w.match_conditions.is_empty() {
        entry["matchConditions"] = gen_match_conditions_to_json(w.match_conditions);
    }
    entry
}

pub fn decode_validatingwebhookconfiguration_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ar_v1::ValidatingWebhookConfiguration::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let webhooks: Vec<serde_json::Value> = obj
        .webhooks
        .into_iter()
        .map(gen_validating_webhook_to_json)
        .collect();
    Some(serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": meta,
        "webhooks": webhooks,
    }))
}

pub fn decode_mutatingwebhookconfiguration_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ar_v1::MutatingWebhookConfiguration::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let webhooks: Vec<serde_json::Value> = obj
        .webhooks
        .into_iter()
        .map(gen_mutating_webhook_to_json)
        .collect();
    Some(serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "MutatingWebhookConfiguration",
        "metadata": meta,
        "webhooks": webhooks,
    }))
}

fn gen_vap_spec_to_json(spec: ar_v1::ValidatingAdmissionPolicySpec) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    if let Some(mc) = spec.match_constraints {
        obj["matchConstraints"] = gen_match_resources_to_json(mc);
    }
    if let Some(fp) = spec.failure_policy.filter(|s| !s.is_empty()) {
        obj["failurePolicy"] = serde_json::Value::String(fp);
    }
    if let Some(pk) = spec.param_kind {
        obj["paramKind"] = serde_json::json!({
            "apiVersion": pk.api_version.unwrap_or_default(),
            "kind": pk.kind.unwrap_or_default(),
        });
    }
    if !spec.validations.is_empty() {
        let vals: Vec<serde_json::Value> = spec
            .validations
            .into_iter()
            .map(|v| {
                let mut entry = serde_json::json!({"expression": v.expression.unwrap_or_default()});
                if let Some(msg) = v.message.filter(|s| !s.is_empty()) {
                    entry["message"] = serde_json::Value::String(msg);
                }
                if let Some(r) = v.reason.filter(|s| !s.is_empty()) {
                    entry["reason"] = serde_json::Value::String(r);
                }
                if let Some(me) = v.message_expression.filter(|s| !s.is_empty()) {
                    entry["messageExpression"] = serde_json::Value::String(me);
                }
                entry
            })
            .collect();
        obj["validations"] = serde_json::Value::Array(vals);
    }
    if !spec.audit_annotations.is_empty() {
        let anns: Vec<serde_json::Value> = spec
            .audit_annotations
            .into_iter()
            .map(|a| {
                serde_json::json!({
                    "key": a.key.unwrap_or_default(),
                    "valueExpression": a.value_expression.unwrap_or_default(),
                })
            })
            .collect();
        obj["auditAnnotations"] = serde_json::Value::Array(anns);
    }
    if !spec.match_conditions.is_empty() {
        obj["matchConditions"] = gen_match_conditions_to_json(spec.match_conditions);
    }
    if !spec.variables.is_empty() {
        let vars: Vec<serde_json::Value> = spec
            .variables
            .into_iter()
            .map(|v| {
                serde_json::json!({
                    "name": v.name.unwrap_or_default(),
                    "expression": v.expression.unwrap_or_default(),
                })
            })
            .collect();
        obj["variables"] = serde_json::Value::Array(vars);
    }
    obj
}

fn gen_vap_status_to_json(status: ar_v1::ValidatingAdmissionPolicyStatus) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    if let Some(og) = status.observed_generation.filter(|&v| v != 0) {
        obj["observedGeneration"] = serde_json::Value::Number(og.into());
    }
    if let Some(tc) = status.type_checking {
        if !tc.expression_warnings.is_empty() {
            let warns: Vec<serde_json::Value> = tc
                .expression_warnings
                .into_iter()
                .map(|w| {
                    serde_json::json!({
                        "fieldRef": w.field_ref.unwrap_or_default(),
                        "warning": w.warning.unwrap_or_default(),
                    })
                })
                .collect();
            obj["typeChecking"] = serde_json::json!({ "expressionWarnings": warns });
        }
    }
    if !status.conditions.is_empty() {
        let conds: Vec<serde_json::Value> = status
            .conditions
            .into_iter()
            .map(|c| {
                let mut cm = serde_json::json!({
                    "type": c.r#type.unwrap_or_default(),
                    "status": c.status.unwrap_or_default(),
                });
                if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                    cm["reason"] = v.into();
                }
                if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                    cm["message"] = v.into();
                }
                if let Some(t) = c.last_transition_time {
                    if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                        cm["lastTransitionTime"] =
                            serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                    }
                }
                if let Some(og) = c.observed_generation.filter(|&g| g != 0) {
                    cm["observedGeneration"] = og.into();
                }
                cm
            })
            .collect();
        obj["conditions"] = serde_json::Value::Array(conds);
    }
    obj
}

pub fn decode_validatingadmissionpolicy_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ar_v1::ValidatingAdmissionPolicy::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        result["spec"] = gen_vap_spec_to_json(spec);
    }
    if let Some(status) = obj.status {
        let status_json = gen_vap_status_to_json(status);
        if status_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            result["status"] = status_json;
        }
    }
    Some(result)
}

pub fn decode_validatingadmissionpolicybinding_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ar_v1::ValidatingAdmissionPolicyBinding::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::json!({});
        if let Some(v) = spec.policy_name.filter(|s| !s.is_empty()) {
            spec_json["policyName"] = serde_json::Value::String(v);
        }
        if let Some(pr) = spec.param_ref {
            spec_json["paramRef"] = gen_param_ref_to_json(pr);
        }
        if let Some(mr) = spec.match_resources {
            spec_json["matchResources"] = gen_match_resources_to_json(mr);
        }
        if !spec.validation_actions.is_empty() {
            spec_json["validationActions"] = serde_json::Value::Array(
                spec.validation_actions
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            );
        }
        result["spec"] = spec_json;
    }
    Some(result)
}

fn gen_map_spec_to_json(spec: ar_v1::MutatingAdmissionPolicySpec) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    if let Some(mc) = spec.match_constraints {
        obj["matchConstraints"] = gen_match_resources_to_json(mc);
    }
    if let Some(fp) = spec.failure_policy.filter(|s| !s.is_empty()) {
        obj["failurePolicy"] = serde_json::Value::String(fp);
    }
    if let Some(rp) = spec.reinvocation_policy.filter(|s| !s.is_empty()) {
        obj["reinvocationPolicy"] = serde_json::Value::String(rp);
    }
    if let Some(pk) = spec.param_kind {
        obj["paramKind"] = serde_json::json!({
            "apiVersion": pk.api_version.unwrap_or_default(),
            "kind": pk.kind.unwrap_or_default(),
        });
    }
    if !spec.variables.is_empty() {
        let vars: Vec<serde_json::Value> = spec
            .variables
            .into_iter()
            .map(|v| {
                serde_json::json!({
                    "name": v.name.unwrap_or_default(),
                    "expression": v.expression.unwrap_or_default(),
                })
            })
            .collect();
        obj["variables"] = serde_json::Value::Array(vars);
    }
    if !spec.mutations.is_empty() {
        let mutations: Vec<serde_json::Value> = spec
            .mutations
            .into_iter()
            .map(|m| {
                let mut entry = serde_json::json!({"patchType": m.patch_type.unwrap_or_default()});
                if let Some(ac) = m.apply_configuration {
                    entry["applyConfiguration"] = serde_json::json!({
                        "expression": ac.expression.unwrap_or_default(),
                    });
                }
                if let Some(jp) = m.json_patch {
                    entry["jsonPatch"] = serde_json::json!({
                        "expression": jp.expression.unwrap_or_default(),
                    });
                }
                entry
            })
            .collect();
        obj["mutations"] = serde_json::Value::Array(mutations);
    }
    if !spec.match_conditions.is_empty() {
        obj["matchConditions"] = gen_match_conditions_to_json(spec.match_conditions);
    }
    obj
}

pub fn decode_mutatingadmissionpolicy_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ar_v1::MutatingAdmissionPolicy::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "MutatingAdmissionPolicy",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        result["spec"] = gen_map_spec_to_json(spec);
    }
    Some(result)
}

pub fn decode_mutatingadmissionpolicybinding_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = ar_v1::MutatingAdmissionPolicyBinding::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "MutatingAdmissionPolicyBinding",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::json!({});
        if let Some(v) = spec.policy_name.filter(|s| !s.is_empty()) {
            spec_json["policyName"] = serde_json::Value::String(v);
        }
        if let Some(pr) = spec.param_ref {
            spec_json["paramRef"] = gen_param_ref_to_json(pr);
        }
        if let Some(mr) = spec.match_resources {
            spec_json["matchResources"] = gen_match_resources_to_json(mr);
        }
        result["spec"] = spec_json;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_lv(field: u32, data: &[u8]) -> Vec<u8> {
        let tag = (field << 3) | 2;
        let mut out = Vec::new();
        let mut t = tag;
        loop {
            let b = (t & 0x7f) as u8;
            t >>= 7;
            if t == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
        let mut l = data.len();
        loop {
            let b = (l & 0x7f) as u8;
            l >>= 7;
            if l == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
        out.extend_from_slice(data);
        out
    }

    fn encode_string(field: u32, s: &str) -> Vec<u8> {
        encode_lv(field, s.as_bytes())
    }

    /// auditAnnotations in ValidatingAdmissionPolicySpec was silently dropped by the hand
    /// struct VapSpec (field 5 was missing). Without emitting auditAnnotations in the decoded
    /// JSON, kubectl describe shows no auditAnnotations and the VAP audit log misses entries.
    #[test]
    fn vap_audit_annotations_previously_dropped_now_appear() {
        // AuditAnnotation: field 1=key, field 2=valueExpression
        let mut ann = Vec::new();
        ann.extend_from_slice(&encode_string(1, "cost-center"));
        ann.extend_from_slice(&encode_string(2, "object.metadata.labels['cost-center']"));

        // ValidatingAdmissionPolicySpec: field 5=auditAnnotations
        let spec = encode_lv(5, &ann);

        // ValidatingAdmissionPolicy: field 1=metadata (empty), field 2=spec
        let meta = encode_lv(1, &[]);
        let mut proto = meta;
        proto.extend_from_slice(&encode_lv(2, &spec));

        let result = decode_validatingadmissionpolicy_proto_gen(&proto).expect("VAP must decode");
        let audit_anns = result["spec"]["auditAnnotations"]
            .as_array()
            .expect("auditAnnotations must appear in decoded VAP spec — the hand VapSpec struct dropped field 5, causing audit annotation data loss on proto decode");
        assert_eq!(audit_anns.len(), 1);
        assert_eq!(
            audit_anns[0]["key"], "cost-center",
            "auditAnnotation key must round-trip through proto decode"
        );
        assert_eq!(
            audit_anns[0]["valueExpression"], "object.metadata.labels['cost-center']",
            "auditAnnotation valueExpression must round-trip through proto decode"
        );
    }

    /// matchConditions in ValidatingWebhookConfiguration must round-trip through generated decode.
    /// Regression: if gen adapter breaks the field 11 path, conformance tests fail.
    #[test]
    fn decode_vwc_gen_preserves_match_conditions() {
        let mut match_cond = Vec::new();
        match_cond.extend_from_slice(&encode_string(1, "gen-check"));
        match_cond.extend_from_slice(&encode_string(2, "object.metadata.name == \"test\""));

        let mut webhook = Vec::new();
        webhook.extend_from_slice(&encode_string(1, "gen-webhook.k8s.io"));
        webhook.extend_from_slice(&encode_lv(11, &match_cond));

        let meta_name = encode_string(1, "test-vwc-gen");
        let meta = encode_lv(1, &meta_name);
        let mut proto = meta;
        proto.extend_from_slice(&encode_lv(2, &webhook));

        let result = decode_validatingwebhookconfiguration_proto_gen(&proto)
            .expect("ValidatingWebhookConfiguration must decode with generated adapter");
        let conds = result["webhooks"][0]["matchConditions"]
            .as_array()
            .expect("matchConditions must be present — gen adapter must preserve field 11");
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0]["name"], "gen-check");
    }

    /// variables in ValidatingAdmissionPolicySpec (field 7) was absent from hand struct.
    #[test]
    fn vap_variables_field_now_decoded() {
        // Variable: field 1=name, field 2=expression
        let mut var = Vec::new();
        var.extend_from_slice(&encode_string(1, "myVar"));
        var.extend_from_slice(&encode_string(2, "object.spec.replicas"));

        // ValidatingAdmissionPolicySpec: field 7=variables
        let spec = encode_lv(7, &var);

        let meta = encode_lv(1, &[]);
        let mut proto = meta;
        proto.extend_from_slice(&encode_lv(2, &spec));

        let result = decode_validatingadmissionpolicy_proto_gen(&proto)
            .expect("VAP with variables must decode");
        let vars = result["spec"]["variables"]
            .as_array()
            .expect("variables must appear in decoded VAP spec — hand VapSpec dropped field 7");
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0]["name"], "myVar");
        assert_eq!(vars[0]["expression"], "object.spec.replicas");
    }

    /// ValidatingAdmissionPolicy status.observedGeneration/typeChecking/conditions must
    /// survive proto decode.
    ///
    /// The VAP controller reports CEL compile-time type warnings and policy readiness through
    /// `.status`; gen_vap_status_to_json existed but no test ever exercised it end-to-end, so a
    /// regression that broke the status branch (e.g. wiring conditions but not typeChecking)
    /// would go unnoticed.
    #[test]
    fn decode_validatingadmissionpolicy_proto_gen_preserves_status() {
        let vap = ar_v1::ValidatingAdmissionPolicy {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-policy.example.com".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(ar_v1::ValidatingAdmissionPolicyStatus {
                observed_generation: Some(3),
                type_checking: Some(ar_v1::TypeChecking {
                    expression_warnings: vec![ar_v1::ExpressionWarning {
                        field_ref: Some("spec.validations[0].expression".to_string()),
                        warning: Some("undefined field 'foo'".to_string()),
                    }],
                }),
                conditions: vec![meta_v1::Condition {
                    r#type: Some("TypeChecked".to_string()),
                    status: Some("True".to_string()),
                    ..Default::default()
                }],
            }),
        };
        let mut buf = Vec::new();
        vap.encode(&mut buf).unwrap();

        let result = decode_validatingadmissionpolicy_proto_gen(&buf)
            .expect("ValidatingAdmissionPolicy with status must decode");

        assert_eq!(
            result["status"]["observedGeneration"], 3,
            "status.observedGeneration must survive decode — without it clients cannot tell \
             whether the reported status reflects the latest spec edit"
        );
        assert_eq!(
            result["status"]["typeChecking"]["expressionWarnings"][0]["warning"],
            "undefined field 'foo'",
            "status.typeChecking must survive decode — dropping it hides CEL compile-time \
             warnings from kubectl describe"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "TypeChecked",
            "status.conditions must survive decode alongside typeChecking"
        );
    }

    /// decode_mutatingwebhookconfiguration_proto_gen must preserve webhook rules and
    /// reinvocationPolicy.
    ///
    /// reinvocationPolicy controls whether the apiserver re-runs this webhook after another
    /// mutating webhook changes the object; dropping it silently falls back to "Never",
    /// breaking webhooks that depend on seeing other webhooks' mutations.
    #[test]
    fn decode_mutatingwebhookconfiguration_proto_gen_preserves_webhooks_and_reinvocation_policy() {
        let mwc = ar_v1::MutatingWebhookConfiguration {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-mwc".to_string()),
                ..Default::default()
            }),
            webhooks: vec![ar_v1::MutatingWebhook {
                name: Some("mutate.example.com".to_string()),
                client_config: Some(ar_v1::WebhookClientConfig {
                    service: Some(ar_v1::ServiceReference {
                        namespace: Some("default".to_string()),
                        name: Some("webhook-svc".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                rules: vec![ar_v1::RuleWithOperations {
                    operations: vec!["CREATE".to_string()],
                    rule: Some(ar_v1::Rule {
                        api_groups: vec!["".to_string()],
                        api_versions: vec!["v1".to_string()],
                        resources: vec!["pods".to_string()],
                        ..Default::default()
                    }),
                }],
                reinvocation_policy: Some("IfNeeded".to_string()),
                ..Default::default()
            }],
        };
        let mut buf = Vec::new();
        mwc.encode(&mut buf).unwrap();

        let result = decode_mutatingwebhookconfiguration_proto_gen(&buf)
            .expect("MutatingWebhookConfiguration must decode");

        assert_eq!(
            result["webhooks"][0]["rules"][0]["resources"][0], "pods",
            "webhooks[].rules must survive decode — without them the apiserver never invokes \
             this webhook for any request"
        );
        assert_eq!(
            result["webhooks"][0]["reinvocationPolicy"], "IfNeeded",
            "reinvocationPolicy must survive decode — dropping it silently falls back to \
             \"Never\", so this webhook stops seeing other webhooks' mutations"
        );
    }

    /// decode_validatingadmissionpolicybinding_proto_gen must preserve policyName and
    /// validationActions.
    ///
    /// validationActions decides whether a policy violation Denies the request, only Audits
    /// it, or Warns the caller; dropping it silently changes enforcement behavior for every
    /// request the bound policy matches.
    #[test]
    fn decode_validatingadmissionpolicybinding_proto_gen_preserves_policy_name_and_actions() {
        let binding = ar_v1::ValidatingAdmissionPolicyBinding {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-binding".to_string()),
                ..Default::default()
            }),
            spec: Some(ar_v1::ValidatingAdmissionPolicyBindingSpec {
                policy_name: Some("my-policy.example.com".to_string()),
                param_ref: Some(ar_v1::ParamRef {
                    name: Some("my-params".to_string()),
                    ..Default::default()
                }),
                validation_actions: vec!["Deny".to_string(), "Audit".to_string()],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        binding.encode(&mut buf).unwrap();

        let result = decode_validatingadmissionpolicybinding_proto_gen(&buf)
            .expect("ValidatingAdmissionPolicyBinding must decode");

        assert_eq!(
            result["spec"]["policyName"], "my-policy.example.com",
            "policyName must survive decode — without it the binding does not attach to any \
             policy and the policy never actually runs"
        );
        assert_eq!(
            result["spec"]["validationActions"][0], "Deny",
            "validationActions must survive decode — dropping it silently changes whether a \
             violation denies the request, only audits it, or just warns the caller"
        );
        assert_eq!(
            result["spec"]["paramRef"]["name"], "my-params",
            "paramRef must survive decode — without it the policy's CEL expressions evaluate \
             against no params instead of the caller's configured object"
        );
    }

    /// decode_mutatingadmissionpolicy_proto_gen must preserve spec.mutations.
    ///
    /// mutations is the actual patch/apply-configuration logic this policy runs; dropping it
    /// makes the policy a no-op that matches requests but changes nothing.
    #[test]
    fn decode_mutatingadmissionpolicy_proto_gen_preserves_mutations() {
        let map_obj = ar_v1::MutatingAdmissionPolicy {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-map".to_string()),
                ..Default::default()
            }),
            spec: Some(ar_v1::MutatingAdmissionPolicySpec {
                failure_policy: Some("Fail".to_string()),
                reinvocation_policy: Some("IfNeeded".to_string()),
                mutations: vec![ar_v1::Mutation {
                    patch_type: Some("ApplyConfiguration".to_string()),
                    apply_configuration: Some(ar_v1::ApplyConfiguration {
                        expression: Some("Object{spec: Object.spec{replicas: 3}}".to_string()),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        map_obj.encode(&mut buf).unwrap();

        let result = decode_mutatingadmissionpolicy_proto_gen(&buf)
            .expect("MutatingAdmissionPolicy must decode");

        assert_eq!(
            result["spec"]["mutations"][0]["applyConfiguration"]["expression"],
            "Object{spec: Object.spec{replicas: 3}}",
            "mutations must survive decode — without them this policy matches requests but \
             changes nothing, silently defeating its purpose"
        );
        assert_eq!(
            result["spec"]["reinvocationPolicy"], "IfNeeded",
            "reinvocationPolicy must survive decode"
        );
    }

    /// decode_mutatingadmissionpolicybinding_proto_gen must preserve policyName and paramRef.
    ///
    /// Without policyName the binding never attaches to any MutatingAdmissionPolicy, so the
    /// mutation the policy author configured silently never runs for any request.
    #[test]
    fn decode_mutatingadmissionpolicybinding_proto_gen_preserves_policy_name_and_param_ref() {
        let binding = ar_v1::MutatingAdmissionPolicyBinding {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-map-binding".to_string()),
                ..Default::default()
            }),
            spec: Some(ar_v1::MutatingAdmissionPolicyBindingSpec {
                policy_name: Some("my-map.example.com".to_string()),
                param_ref: Some(ar_v1::ParamRef {
                    name: Some("my-params".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        binding.encode(&mut buf).unwrap();

        let result = decode_mutatingadmissionpolicybinding_proto_gen(&buf)
            .expect("MutatingAdmissionPolicyBinding must decode");

        assert_eq!(
            result["spec"]["policyName"], "my-map.example.com",
            "policyName must survive decode — without it the binding does not attach to any \
             MutatingAdmissionPolicy and the configured mutation never runs"
        );
        assert_eq!(
            result["spec"]["paramRef"]["name"], "my-params",
            "paramRef must survive decode — without it the policy's mutation expression \
             evaluates against no params"
        );
    }

    /// A namespaceSelector expressed purely via matchExpressions must survive decode, and an
    /// Exists requirement (which has no values) must omit "values" rather than emit "values":
    /// [] unconditionally.
    ///
    /// This admissionreg copy of gen_label_selector_to_json had drifted from the canonical
    /// omit-empty semantics in core_gen_adapter.rs (it used unwrap_or_default() for every
    /// matchExpressions field). If a matchExpressions-only selector were dropped entirely, an
    /// empty/absent namespaceSelector matches every namespace instead of only the ones
    /// satisfying `env Exists`, silently widening which namespaces the webhook fires for.
    #[test]
    fn decode_validatingwebhookconfiguration_proto_gen_preserves_matchexpressions_selector() {
        let vwc = ar_v1::ValidatingWebhookConfiguration {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("ns-selector-vwc".to_string()),
                ..Default::default()
            }),
            webhooks: vec![ar_v1::ValidatingWebhook {
                name: Some("select.example.com".to_string()),
                namespace_selector: Some(meta_v1::LabelSelector {
                    match_labels: Default::default(),
                    match_expressions: vec![meta_v1::LabelSelectorRequirement {
                        key: Some("env".to_string()),
                        operator: Some("Exists".to_string()),
                        values: vec![],
                    }],
                }),
                ..Default::default()
            }],
        };
        let mut buf = Vec::new();
        vwc.encode(&mut buf).unwrap();

        let result = decode_validatingwebhookconfiguration_proto_gen(&buf)
            .expect("ValidatingWebhookConfiguration must decode");

        let sel = &result["webhooks"][0]["namespaceSelector"];
        assert_ne!(
            *sel,
            serde_json::json!({}),
            "a matchExpressions-only namespaceSelector must not collapse to {{}} — an empty \
             selector matches every namespace instead of only namespaces satisfying `env Exists`"
        );
        assert_eq!(sel["matchExpressions"][0]["key"], "env");
        assert_eq!(sel["matchExpressions"][0]["operator"], "Exists");
        assert!(
            sel["matchExpressions"][0].get("values").is_none(),
            "an Exists requirement has no values — emitting \"values\": [] unconditionally \
             (the pre-fix unwrap_or_default() behavior) diverges from the canonical omit-empty \
             semantics in core_gen_adapter.rs and misrepresents what the client actually sent"
        );
    }

    // ---- Sentinel completeness ----
    //
    // Each test below builds a message with every field set to a value no zero/empty-elision
    // check in this file's gen_*_to_json functions could mistake for "unset" (see
    // u7s_sentinel::Sentinel), decodes it through the real decode_*_proto_gen entry point, and
    // asserts every field name shows up somewhere in the resulting JSON. A name that never
    // appears means some gen_*_to_json function never reads that field from the decoded
    // protobuf struct at all — this is exactly how the per-condition observedGeneration on
    // ValidatingAdmissionPolicyStatus.conditions was found missing from this file.
    //
    // This file's gen_object_meta_to_json and gen_label_selector_to_json/
    // gen_label_selector_requirement_to_json were independently verified (by direct diff
    // against core_gen_adapter.rs's canonical copies) to already match canonical omit-empty
    // semantics as of this pass — the historical drift in gen_label_selector_to_json (see
    // decode_validatingwebhookconfiguration_proto_gen_preserves_matchexpressions_selector
    // above) was already fixed before this test was added. Do not assume that stays true after
    // future edits to this file; that is exactly why this gets its own completeness check
    // instead of trusting the other adapters' coverage.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    fn collect_leaf_paths(value: &serde_json::Value, prefix: &str, out: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(map) if !map.is_empty() => {
                for (k, v) in map {
                    let path = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    collect_leaf_paths(v, &path, out);
                }
            }
            serde_json::Value::Array(items) if !items.is_empty() => {
                for item in items {
                    collect_leaf_paths(item, prefix, out);
                }
            }
            _ => {
                out.insert(prefix.to_string());
            }
        }
    }

    fn has_field(leaf_paths: &BTreeSet<String>, field: &str) -> bool {
        leaf_paths
            .iter()
            .any(|p| p.split('.').any(|seg| seg == field))
    }

    fn assert_fields_present(leaf_paths: &BTreeSet<String>, expected: &[&str]) {
        let missing: Vec<&str> = expected
            .iter()
            .filter(|f| !has_field(leaf_paths, f))
            .copied()
            .collect();
        assert!(
            missing.is_empty(),
            "sentinel completeness: field(s) {missing:?} never appear in the decoded JSON — \
             add handling in the corresponding gen_*_to_json/decode_*_proto_gen function (or, if \
             the omission is deliberate, document why and drop the field from this test's \
             `expected` list)"
        );
    }

    // selfLink is a legacy field the system no longer populates — permanently omitted.
    // deletionTimestamp/deletionGracePeriodSeconds/managedFields are left off `expected`
    // pending a separate investigation into gen_object_meta_to_json's correct handling of
    // them (this file's copy has the same omissions as every other gen_adapter's); do not
    // guess at the fix here.
    const OBJECT_META_EXPECTED: &[&str] = &[
        "name",
        "generateName",
        "namespace",
        "uid",
        "resourceVersion",
        "generation",
        "creationTimestamp",
        "labels",
        "annotations",
        "ownerReferences",
        "finalizers",
    ];

    const LABEL_SELECTOR_EXPECTED: &[&str] = &[
        "matchLabels",
        "matchExpressions",
        "key",
        "operator",
        "values",
    ];

    const MATCH_RESOURCES_EXPECTED: &[&str] = &[
        "resourceRules",
        "excludeResourceRules",
        "resourceNames",
        "apiGroups",
        "apiVersions",
        "resources",
        "operations",
        "scope",
        "namespaceSelector",
        "objectSelector",
        "matchPolicy",
    ];

    const PARAM_REF_EXPECTED: &[&str] =
        &["name", "namespace", "parameterNotFoundAction", "selector"];

    #[test]
    fn sentinel_completeness_decode_validatingwebhookconfiguration_proto_gen() {
        let vwc = ar_v1::ValidatingWebhookConfiguration {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            webhooks: vec![ar_v1::ValidatingWebhook::sentinel()],
        };
        let mut buf = Vec::new();
        vwc.encode(&mut buf).unwrap();
        let result = decode_validatingwebhookconfiguration_proto_gen(&buf)
            .expect("sentinel ValidatingWebhookConfiguration must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(LABEL_SELECTOR_EXPECTED);
        expected.extend([
            "webhooks",
            "clientConfig",
            "caBundle",
            "service",
            "path",
            "port",
            "url",
            "rules",
            "operations",
            "apiGroups",
            "apiVersions",
            "resources",
            "scope",
            "admissionReviewVersions",
            "failurePolicy",
            "matchPolicy",
            "sideEffects",
            "timeoutSeconds",
            "namespaceSelector",
            "objectSelector",
            "matchConditions",
            "expression",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_mutatingwebhookconfiguration_proto_gen() {
        let mwc = ar_v1::MutatingWebhookConfiguration {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            webhooks: vec![ar_v1::MutatingWebhook::sentinel()],
        };
        let mut buf = Vec::new();
        mwc.encode(&mut buf).unwrap();
        let result = decode_mutatingwebhookconfiguration_proto_gen(&buf)
            .expect("sentinel MutatingWebhookConfiguration must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(LABEL_SELECTOR_EXPECTED);
        expected.extend([
            "webhooks",
            "clientConfig",
            "caBundle",
            "service",
            "path",
            "port",
            "url",
            "rules",
            "operations",
            "apiGroups",
            "apiVersions",
            "resources",
            "scope",
            "admissionReviewVersions",
            "failurePolicy",
            "matchPolicy",
            "sideEffects",
            "timeoutSeconds",
            "reinvocationPolicy",
            "namespaceSelector",
            "objectSelector",
            "matchConditions",
            "expression",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_validatingadmissionpolicy_proto_gen() {
        let vap = ar_v1::ValidatingAdmissionPolicy {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(ar_v1::ValidatingAdmissionPolicySpec::sentinel()),
            status: Some(ar_v1::ValidatingAdmissionPolicyStatus::sentinel()),
        };
        let mut buf = Vec::new();
        vap.encode(&mut buf).unwrap();
        let result = decode_validatingadmissionpolicy_proto_gen(&buf)
            .expect("sentinel ValidatingAdmissionPolicy must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(LABEL_SELECTOR_EXPECTED);
        expected.extend(MATCH_RESOURCES_EXPECTED);
        expected.extend([
            "spec",
            "matchConstraints",
            "failurePolicy",
            // paramKind.apiVersion/kind deliberately excluded: both would be masked by the
            // envelope's own top-level "apiVersion"/"kind" literals, so a dropped
            // paramKind.apiVersion or paramKind.kind could never fail this check.
            "paramKind",
            "validations",
            "expression",
            "message",
            "reason",
            "messageExpression",
            "auditAnnotations",
            "key",
            "valueExpression",
            "matchConditions",
            "name",
            "variables",
            "status",
            "observedGeneration",
            "typeChecking",
            "expressionWarnings",
            "fieldRef",
            "warning",
            "conditions",
            "type",
            "lastTransitionTime",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_validatingadmissionpolicybinding_proto_gen() {
        let binding = ar_v1::ValidatingAdmissionPolicyBinding {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(ar_v1::ValidatingAdmissionPolicyBindingSpec::sentinel()),
        };
        let mut buf = Vec::new();
        binding.encode(&mut buf).unwrap();
        let result = decode_validatingadmissionpolicybinding_proto_gen(&buf)
            .expect("sentinel ValidatingAdmissionPolicyBinding must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(LABEL_SELECTOR_EXPECTED);
        expected.extend(MATCH_RESOURCES_EXPECTED);
        expected.extend(PARAM_REF_EXPECTED);
        expected.extend([
            "spec",
            "policyName",
            "paramRef",
            "matchResources",
            "validationActions",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_mutatingadmissionpolicy_proto_gen() {
        let map_obj = ar_v1::MutatingAdmissionPolicy {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(ar_v1::MutatingAdmissionPolicySpec::sentinel()),
        };
        let mut buf = Vec::new();
        map_obj.encode(&mut buf).unwrap();
        let result = decode_mutatingadmissionpolicy_proto_gen(&buf)
            .expect("sentinel MutatingAdmissionPolicy must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(MATCH_RESOURCES_EXPECTED);
        expected.extend([
            "spec",
            "matchConstraints",
            "failurePolicy",
            "reinvocationPolicy",
            // paramKind.apiVersion/kind deliberately excluded — see the same note in
            // sentinel_completeness_decode_validatingadmissionpolicy_proto_gen above.
            "paramKind",
            "variables",
            "name",
            "expression",
            "mutations",
            "patchType",
            "applyConfiguration",
            "jsonPatch",
            "matchConditions",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_mutatingadmissionpolicybinding_proto_gen() {
        let binding = ar_v1::MutatingAdmissionPolicyBinding {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(ar_v1::MutatingAdmissionPolicyBindingSpec::sentinel()),
        };
        let mut buf = Vec::new();
        binding.encode(&mut buf).unwrap();
        let result = decode_mutatingadmissionpolicybinding_proto_gen(&buf)
            .expect("sentinel MutatingAdmissionPolicyBinding must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(LABEL_SELECTOR_EXPECTED);
        expected.extend(MATCH_RESOURCES_EXPECTED);
        expected.extend(PARAM_REF_EXPECTED);
        expected.extend(["spec", "policyName", "paramRef", "matchResources"]);
        assert_fields_present(&paths, &expected);
    }
}
