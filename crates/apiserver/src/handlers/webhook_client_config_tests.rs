//! Router-level proof that an invalid webhook `clientConfig` is refused when the configuration
//! is written, instead of being stored and failing every admitted request.

use axum::http::StatusCode;
use serde_json::{json, Value};

use super::subresource_admission_tests::cases::Cluster;

const MERGE: &str = "application/merge-patch+json";
const VWC: &str = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations";
const MWC: &str = "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations";

fn config(kind: &str, name: &str, client_config: Value) -> Value {
    json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": kind,
        "metadata": {"name": name},
        "webhooks": [{
            "name": "h.example.com",
            "clientConfig": client_config,
            "sideEffects": "None",
            "admissionReviewVersions": ["v1"],
        }],
    })
}

/// A credentialed URL on create and on a later PATCH must be a 422 for both webhook kinds.
#[tokio::test]
async fn invalid_webhook_url_is_rejected_on_create_and_update_for_both_kinds() {
    let c = Cluster::new().await;
    for (kind, base) in [
        ("ValidatingWebhookConfiguration", VWC),
        ("MutatingWebhookConfiguration", MWC),
    ] {
        let (st, resp) = c
            .call(
                "POST",
                base,
                "application/json",
                config(kind, "bad", json!({"url": "https://user:pass@h/?token=x"})),
            )
            .await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{kind}: {resp}");
        let msg = resp["message"].as_str().unwrap();
        assert!(
            msg.contains("webhooks[0].clientConfig.url: Invalid value:")
                && !msg.contains("pass")
                && !msg.contains("token"),
            "{kind}: {msg}"
        );

        let ok = config(kind, "ok", json!({"url": "https://h.example.com/hook"}));
        let (st, resp) = c.call("POST", base, "application/json", ok).await;
        assert_eq!(st, StatusCode::CREATED, "{kind}: {resp}");

        let (st, resp) = c
            .call(
                "PATCH",
                &format!("{base}/ok"),
                MERGE,
                json!({"webhooks": [{"name": "h.example.com",
                    "clientConfig": {"url": "http://h.example.com/hook"}}]}),
            )
            .await;
        assert_eq!(
            st,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{kind}: update must be validated too: {resp}"
        );
    }
}

#[tokio::test]
async fn webhook_service_with_bad_port_is_rejected_on_create() {
    let c = Cluster::new().await;
    let (st, resp) = c
        .call(
            "POST",
            VWC,
            "application/json",
            config(
                "ValidatingWebhookConfiguration",
                "svc",
                json!({"service": {"name": "s", "namespace": "n", "port": 0}}),
            ),
        )
        .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{resp}");
    assert!(
        resp["message"]
            .as_str()
            .unwrap()
            .contains("webhooks[0].clientConfig.service.port: Invalid value: 0"),
        "{resp}"
    );
}

/// A CRD whose conversion webhook can never be called must not be accepted.
#[tokio::test]
async fn crd_conversion_webhook_url_is_validated_on_create() {
    let c = Cluster::new().await;
    let mut crd = json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "gadgets.example.com"},
        "spec": {
            "group": "example.com",
            "names": {"plural": "gadgets", "singular": "gadget", "kind": "Gadget", "listKind": "GadgetList"},
            "scope": "Namespaced",
            "conversion": {"strategy": "Webhook", "webhook": {
                "conversionReviewVersions": ["v1"],
                "clientConfig": {"url": "http://h.example.com/convert"}}},
            "versions": [{"name": "v1", "served": true, "storage": true,
                "schema": {"openAPIV3Schema": {"type": "object"}}}],
        },
    });
    let uri = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";
    let (st, resp) = c.call("POST", uri, "application/json", crd.clone()).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{resp}");
    assert!(
        resp["message"]
            .as_str()
            .unwrap()
            .contains("spec.conversion.webhookClientConfig.url: Invalid value: \"http\""),
        "{resp}"
    );
    crd["spec"]["conversion"]["webhook"]["clientConfig"]["url"] = json!("https://h.example.com/c");
    let (st, resp) = c.call("POST", uri, "application/json", crd).await;
    assert_eq!(st, StatusCode::CREATED, "{resp}");
}
