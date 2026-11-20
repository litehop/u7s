//! Router-level proof that `excludeResourceRules` carves resources out of a policy: an author
//! who excludes ConfigMaps must not see them denied or mutated, whether the exclusion sits in
//! the policy's `matchConstraints` or in a binding's `matchResources`.

use axum::http::StatusCode;
use bytes::Bytes;
use serde_json::{json, Value};
use u7s_store::Store;

use super::subresource_admission_tests::cases::Cluster;

const REG: &str = "/registry/admissionregistration.k8s.io";
const CMS: &str = "/api/v1/namespaces/default/configmaps";
const SECRETS: &str = "/api/v1/namespaces/default/secrets";

fn all_rules() -> Value {
    json!([{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"],
        "operations": ["CREATE", "UPDATE"]}])
}

fn exclude_configmaps() -> Value {
    json!([{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["configmaps"],
        "operations": ["*"]}])
}

mod fixtures {
    use super::*;

    pub(super) async fn seed_registry(c: &Cluster, path: &str, v: Value) {
        c.store
            .put(&format!("{REG}/{path}"), Bytes::from(v.to_string()), None)
            .await
            .unwrap();
    }
}
use fixtures::seed_registry;

async fn deny_policy(c: &Cluster, policy_exclude: Option<Value>, binding_exclude: Option<Value>) {
    let mut mc = json!({"resourceRules": all_rules()});
    if let Some(e) = policy_exclude {
        mc["excludeResourceRules"] = e;
    }
    seed_registry(
        c,
        "validatingadmissionpolicies/deny",
        json!({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "deny"},
            "spec": {"matchConstraints": mc,
                "validations": [{"expression": "false", "message": "denied by policy"}]}}),
    )
    .await;
    let mut spec = json!({"policyName": "deny", "validationActions": ["Deny"]});
    if let Some(e) = binding_exclude {
        spec["matchResources"] = json!({"excludeResourceRules": e});
    }
    seed_registry(
        c,
        "validatingadmissionpolicybindings/deny",
        json!({"apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "deny"}, "spec": spec}),
    )
    .await;
}

async fn create(c: &Cluster, collection: &str, kind: &str) -> (StatusCode, Value) {
    c.call(
        "POST",
        collection,
        "application/json",
        json!({"apiVersion": "v1", "kind": kind, "metadata": {"name": "x"}}),
    )
    .await
}

async fn assert_excluded_only(c: &Cluster, what: &str) {
    let (st, resp) = create(c, CMS, "ConfigMap").await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "{what}: a ConfigMap the policy excludes must not be denied: {resp}"
    );
    let (st, resp) = create(c, SECRETS, "Secret").await;
    assert_eq!(
        st,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{what}: control: a non-excluded Secret must still be denied: {resp}"
    );
}

#[tokio::test]
async fn vap_policy_exclude_resource_rules_exempts_matching_requests() {
    let c = Cluster::new().await;
    deny_policy(&c, Some(exclude_configmaps()), None).await;
    assert_excluded_only(&c, "policy matchConstraints").await;
}

#[tokio::test]
async fn vap_binding_exclude_resource_rules_exempts_matching_requests() {
    let c = Cluster::new().await;
    deny_policy(&c, None, Some(exclude_configmaps())).await;
    assert_excluded_only(&c, "binding matchResources").await;
}

async fn mutate_policy(c: &Cluster, policy_exclude: Option<Value>, binding_exclude: Option<Value>) {
    let mut mc = json!({"resourceRules": all_rules()});
    if let Some(e) = policy_exclude {
        mc["excludeResourceRules"] = e;
    }
    seed_registry(
        c,
        "mutatingadmissionpolicies/label",
        json!({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "MutatingAdmissionPolicy",
            "metadata": {"name": "label"},
            "spec": {"matchConstraints": mc,
                "mutations": [{"patchType": "ApplyConfiguration", "applyConfiguration": {
                    "expression": "Object{metadata: Object.metadata{labels: {\"mutated\": \"true\"}}}"}}]}}),
    )
    .await;
    let mut spec = json!({"policyName": "label"});
    if let Some(e) = binding_exclude {
        spec["matchResources"] = json!({"excludeResourceRules": e});
    }
    seed_registry(
        c,
        "mutatingadmissionpolicybindings/label",
        json!({"apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingAdmissionPolicyBinding",
            "metadata": {"name": "label"}, "spec": spec}),
    )
    .await;
}

async fn assert_mutates_only_non_excluded(c: &Cluster, what: &str) {
    let (st, cm) = create(c, CMS, "ConfigMap").await;
    assert_eq!(st, StatusCode::CREATED, "{what}: {cm}");
    assert!(
        cm["metadata"]["labels"]["mutated"].is_null(),
        "{what}: an excluded ConfigMap must not be mutated: {cm}"
    );
    let (st, secret) = create(c, SECRETS, "Secret").await;
    assert_eq!(st, StatusCode::CREATED, "{what}: {secret}");
    assert_eq!(
        secret["metadata"]["labels"]["mutated"], "true",
        "{what}: control: a non-excluded Secret must still be mutated: {secret}"
    );
}

#[tokio::test]
async fn map_policy_exclude_resource_rules_exempts_matching_requests() {
    let c = Cluster::new().await;
    mutate_policy(&c, Some(exclude_configmaps()), None).await;
    assert_mutates_only_non_excluded(&c, "policy matchConstraints").await;
}

#[tokio::test]
async fn map_binding_exclude_resource_rules_exempts_matching_requests() {
    let c = Cluster::new().await;
    mutate_policy(&c, None, Some(exclude_configmaps())).await;
    assert_mutates_only_non_excluded(&c, "binding matchResources").await;
}
