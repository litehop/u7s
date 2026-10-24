use std::sync::Arc;

use serde_json::{json, Value};
use u7s_store::{SqliteStore, Store};

use crate::admission::{
    run_cel_mutating_policies, run_validating_admission_policies, AdmissionContext,
};
use crate::state::AppState;
use crate::status::StatusError;

const VAP: &str = "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/p";
const VAPB: &str = "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/b";
const MAP: &str = "/registry/admissionregistration.k8s.io/mutatingadmissionpolicies/p";
const MAPB: &str = "/registry/admissionregistration.k8s.io/mutatingadmissionpolicybindings/b";

fn state() -> (Arc<SqliteStore>, AppState) {
    let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
    let state = AppState::new(
        store.clone(),
        None,
        std::collections::HashMap::new(),
        "https://localhost:6443".into(),
    );
    (store, state)
}

async fn put(store: &SqliteStore, key: &str, doc: Value) {
    store
        .put(
            key,
            bytes::Bytes::from(serde_json::to_vec(&doc).unwrap()),
            None,
        )
        .await
        .unwrap();
}

fn config_map(ns: &str, name: &str, labels: Value, max: &str) -> Value {
    json!({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": ns, "labels": labels},
        "data": {"maxReplicas": max}
    })
}

fn deployment(replicas: i64) -> Value {
    json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "d", "namespace": "default"},
        "spec": {"replicas": replicas}
    })
}

fn ctx(user: Option<Value>) -> AdmissionContext<'static> {
    AdmissionContext {
        group: "apps",
        version: "v1",
        resource: "deployments",
        name: "d",
        namespace: Some("default"),
        operation: "CREATE",
        user_info: user,
        dry_run: false,
    }
}

fn policy_spec(extra: Value) -> Value {
    let mut spec = json!({
        "matchConstraints": {"resourceRules": [{
            "apiGroups": ["apps"], "apiVersions": ["v1"],
            "resources": ["deployments"], "operations": ["CREATE"]
        }]}
    });
    for (k, v) in extra.as_object().unwrap() {
        spec[k] = v.clone();
    }
    json!({"metadata": {"name": "p"}, "spec": spec})
}

/// A VAP with a ConfigMap paramKind capping `spec.replicas`, bound with `param_ref`.
async fn param_policy(store: &SqliteStore, param_ref: Value, failure_policy: &str) {
    put(
        store,
        VAP,
        policy_spec(json!({
            "failurePolicy": failure_policy,
            "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
            "validations": [{
                "expression": "object.spec.replicas <= int(params.data.maxReplicas)",
                "messageExpression": "'replicas exceed ' + params.metadata.name"
            }]
        })),
    )
    .await;
    put(
        store,
        VAPB,
        json!({"metadata": {"name": "b"},
               "spec": {"policyName": "p", "validationActions": ["Deny"], "paramRef": param_ref}}),
    )
    .await;
}

async fn validate(state: &AppState, replicas: i64) -> Result<(), StatusError> {
    run_validating_admission_policies(state, &deployment(replicas), None, &ctx(None)).await
}

fn denial(r: Result<(), StatusError>) -> String {
    format!("{:?}", r.expect_err("request must be denied"))
}

/// A parameterised policy is the only way to share one policy across tenants with different
/// limits: the cap must come from the param named by the binding.
#[tokio::test]
async fn param_named_by_paramref_drives_the_validation() {
    let (store, state) = state();
    put(
        &store,
        "/registry/configmaps/default/limits",
        config_map("default", "limits", json!({}), "3"),
    )
    .await;
    param_policy(
        &store,
        json!({"name": "limits", "parameterNotFoundAction": "Deny"}),
        "Fail",
    )
    .await;

    validate(&state, 3)
        .await
        .expect("3 replicas is within the param's cap of 3");
    let msg = denial(validate(&state, 4).await);
    assert!(msg.contains("replicas exceed limits"), "{msg}");
}

/// A selector must evaluate every matching param: if only the first were used, a stricter
/// second param would be silently ignored.
#[tokio::test]
async fn selector_evaluates_every_matched_param_and_any_failure_denies() {
    let (store, state) = state();
    for (name, app, max) in [
        ("a-loose", "x", "10"),
        ("b-strict", "x", "2"),
        ("c-other", "y", "0"),
    ] {
        put(
            &store,
            &format!("/registry/configmaps/default/{name}"),
            config_map("default", name, json!({"app": app}), max),
        )
        .await;
    }
    param_policy(
        &store,
        json!({"selector": {"matchLabels": {"app": "x"}}, "parameterNotFoundAction": "Deny"}),
        "Fail",
    )
    .await;

    validate(&state, 2)
        .await
        .expect("within both matched params; the unmatched cap of 0 must not apply");
    let msg = denial(validate(&state, 5).await);
    assert!(
        msg.contains("replicas exceed b-strict"),
        "the second matched param must be evaluated and deny: {msg}"
    );
}

/// `parameterNotFoundAction` decides whether a missing param blocks the request (Deny) or
/// lets the binding be skipped (Allow).
#[tokio::test]
async fn parameter_not_found_action_deny_blocks_and_allow_skips() {
    let (store, state) = state();
    param_policy(
        &store,
        json!({"name": "absent", "parameterNotFoundAction": "Deny"}),
        "Fail",
    )
    .await;
    let msg = denial(validate(&state, 99).await);
    assert!(
        msg.contains(
            "policy 'p' with binding 'b' denied request: failed to configure binding: \
             no params found for policy binding with `Deny` parameterNotFoundAction"
        ),
        "{msg}"
    );
    assert!(
        msg.contains("403"),
        "a configuration error is Forbidden: {msg}"
    );

    param_policy(
        &store,
        json!({"name": "absent", "parameterNotFoundAction": "Allow"}),
        "Fail",
    )
    .await;
    validate(&state, 99)
        .await
        .expect("Allow skips a binding whose param is absent");

    param_policy(
        &store,
        json!({"name": "absent", "parameterNotFoundAction": "Deny"}),
        "Ignore",
    )
    .await;
    validate(&state, 99)
        .await
        .expect("failurePolicy=Ignore drops the configuration error");
}

/// A namespaced param resolves in the request's namespace unless the binding names one;
/// otherwise a same-named param in another namespace would leak across tenants.
#[tokio::test]
async fn namespaced_param_resolves_in_request_namespace_or_paramref_namespace() {
    let (store, state) = state();
    put(
        &store,
        "/registry/configmaps/other/limits",
        config_map("other", "limits", json!({}), "1"),
    )
    .await;
    param_policy(
        &store,
        json!({"name": "limits", "parameterNotFoundAction": "Deny"}),
        "Fail",
    )
    .await;
    let msg = denial(validate(&state, 1).await);
    assert!(
        msg.contains("no params found"),
        "other/limits must not satisfy a default/ request: {msg}"
    );

    param_policy(
        &store,
        json!({"name": "limits", "namespace": "other", "parameterNotFoundAction": "Deny"}),
        "Fail",
    )
    .await;
    validate(&state, 1)
        .await
        .expect("paramRef.namespace selects the other namespace");
    denial(validate(&state, 2).await);
}

/// A paramKind naming an unknown kind cannot be evaluated: it must fail the request instead of
/// running the expressions with no params.
#[tokio::test]
async fn unknown_param_kind_is_a_configuration_error() {
    let (store, state) = state();
    let mut policy = policy_spec(json!({
        "paramKind": {"apiVersion": "example.com/v1", "kind": "Nope"},
        "validations": [{"expression": "true"}]
    }));
    policy["spec"]["failurePolicy"] = json!("Fail");
    put(&store, VAP, policy).await;
    put(
        &store,
        VAPB,
        json!({"metadata": {"name": "b"}, "spec": {"policyName": "p", "validationActions": ["Deny"],
               "paramRef": {"name": "x", "parameterNotFoundAction": "Allow"}}}),
    )
    .await;
    let msg = denial(validate(&state, 1).await);
    assert!(
        msg.contains("paramKind kind `&ParamKind{APIVersion:example.com/v1,Kind:Nope,}` not known"),
        "{msg}"
    );
}

/// Without a paramRef the policy runs with `params` null, as upstream does.
#[tokio::test]
async fn binding_without_paramref_evaluates_with_null_params() {
    let (store, state) = state();
    put(
        &store,
        VAP,
        policy_spec(json!({
            "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
            "validations": [{"expression": "params == null"}]
        })),
    )
    .await;
    put(
        &store,
        VAPB,
        json!({"metadata": {"name": "b"}, "spec": {"policyName": "p", "validationActions": ["Deny"]}}),
    )
    .await;
    validate(&state, 1)
        .await
        .expect("params is null when the binding has no paramRef");
}

fn rbac_allow(state: &AppState, name: &str, rule: Value, subject: Value, namespace: Option<&str>) {
    let (role_key, binding_key, role_kind) = match namespace {
        Some(ns) => (
            format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles/{name}"),
            format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{name}"),
            "Role",
        ),
        None => (
            format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}"),
            format!("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{name}"),
            "ClusterRole",
        ),
    };
    state.rbac_index.apply_object(
        &role_key,
        &json!({"metadata": {"name": name}, "rules": [rule]}),
    );
    state.rbac_index.apply_object(
        &binding_key,
        &json!({
            "metadata": {"name": name},
            "subjects": [subject],
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": role_kind, "name": name}
        }),
    );
}

async fn authz_policy(store: &SqliteStore, expression: &str) {
    put(
        store,
        VAP,
        policy_spec(json!({"validations": [{"expression": expression}]})),
    )
    .await;
    put(
        store,
        VAPB,
        json!({"metadata": {"name": "b"}, "spec": {"policyName": "p", "validationActions": ["Deny"]}}),
    )
    .await;
}

async fn validate_as_alice(state: &AppState) -> Result<(), StatusError> {
    let alice = json!({"username": "alice", "groups": ["system:authenticated"]});
    run_validating_admission_policies(state, &deployment(1), None, &ctx(Some(alice))).await
}

/// `authorizer` must answer from the same RBAC that gates requests, for the requesting user:
/// a policy that requires a permission denies users without it and admits those with.
#[tokio::test]
async fn authorizer_check_follows_rbac_for_the_request_user() {
    let (store, state) = state();
    authz_policy(
        &store,
        "authorizer.group('').resource('secrets').namespace('default').check('get').allowed()",
    )
    .await;
    denial(validate_as_alice(&state).await);

    rbac_allow(
        &state,
        "read-secrets",
        json!({"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}),
        json!({"kind": "User", "name": "alice"}),
        Some("default"),
    );
    validate_as_alice(&state)
        .await
        .expect("a Role in default grants get secrets");

    authz_policy(
        &store,
        "authorizer.group('').resource('secrets').namespace('kube-system').check('get').allowed()",
    )
    .await;
    denial(validate_as_alice(&state).await);
}

/// `authorizer.requestResource` must reflect the resource being admitted, so a policy can ask
/// "may this user do X to what they are touching" without restating it.
#[tokio::test]
async fn authorizer_request_resource_is_the_admitted_resource() {
    let (store, state) = state();
    authz_policy(
        &store,
        "authorizer.requestResource.check('delete').allowed()",
    )
    .await;
    rbac_allow(
        &state,
        "del-deploy",
        json!({"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["delete"]}),
        json!({"kind": "User", "name": "alice"}),
        None,
    );
    validate_as_alice(&state)
        .await
        .expect("delete on apps/deployments is granted");

    authz_policy(
        &store,
        "authorizer.requestResource.check('patch').allowed()",
    )
    .await;
    denial(validate_as_alice(&state).await);
}

/// `authorizer.serviceAccount` checks another principal, not the request user.
#[tokio::test]
async fn authorizer_service_account_checks_that_account_not_the_requester() {
    let (store, state) = state();
    rbac_allow(
        &state,
        "sa-pods",
        json!({"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}),
        json!({"kind": "ServiceAccount", "name": "sa1", "namespace": "default"}),
        None,
    );
    authz_policy(
        &store,
        "authorizer.serviceAccount('default', 'sa1').group('').resource('pods').check('get').allowed()",
    )
    .await;
    validate_as_alice(&state).await.expect("sa1 may get pods");

    authz_policy(
        &store,
        "authorizer.group('').resource('pods').check('get').allowed()",
    )
    .await;
    denial(validate_as_alice(&state).await);
}

/// MAP evaluates per param too: the patch must be built from the param the binding names.
#[tokio::test]
async fn mutating_policy_reads_its_param() {
    let (store, state) = state();
    put(
        &store,
        "/registry/configmaps/default/limits",
        config_map("default", "limits", json!({}), "7"),
    )
    .await;
    put(
        &store,
        MAP,
        policy_spec(json!({
            "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
            "mutations": [{
                "patchType": "ApplyConfiguration",
                "applyConfiguration": {"expression":
                    "Object{metadata: Object.metadata{labels: {\"cap\": params.data.maxReplicas}}}"}
            }]
        })),
    )
    .await;
    put(
        &store,
        MAPB,
        json!({"metadata": {"name": "b"}, "spec": {"policyName": "p",
               "paramRef": {"name": "limits", "parameterNotFoundAction": "Deny"}}}),
    )
    .await;
    let out = run_cel_mutating_policies(&state, deployment(1), None, &ctx(None))
        .await
        .unwrap();
    assert_eq!(out["metadata"]["labels"]["cap"], "7");
}
