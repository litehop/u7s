/// Pure, testable logic extracted from u7s-controller-manager.
///
/// All async I/O stays in main.rs. This module contains only functions
/// that can be exercised without a live API server.
use serde_json::Value;

// ---------------------------------------------------------------------------
// Secret construction
// ---------------------------------------------------------------------------

/// Build the Secret object that holds a service-account token.
///
/// The Secret type and annotation are required by the Kubernetes SA token
/// controller contract; tools like kubectl rely on the `<sa-name>-token`
/// naming convention.
pub fn build_sa_token_secret(namespace: &str, sa_name: &str, token_b64: &str) -> Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": format!("{sa_name}-token"),
            "namespace": namespace,
            "annotations": {
                "kubernetes.io/service-account.name": sa_name
            }
        },
        "type": "kubernetes.io/service-account-token",
        "data": {
            "token": token_b64
        }
    })
}

// ---------------------------------------------------------------------------
// Watch event parsing
// ---------------------------------------------------------------------------

/// Extract (namespace, sa_name) from a ServiceAccount ADDED watch event.
///
/// Returns `None` if:
/// - the event type is not "ADDED", or
/// - the SA name is missing/empty.
///
/// Namespace defaults to "default" when missing, matching Kubernetes behaviour.
pub fn parse_sa_added_event(event: &Value) -> Option<(String, String)> {
    let event_type = event["type"].as_str().unwrap_or("");
    if event_type != "ADDED" {
        return None;
    }
    let sa_name = event["object"]["metadata"]["name"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    if sa_name.is_empty() {
        return None;
    }
    let namespace = event["object"]["metadata"]["namespace"]
        .as_str()
        .unwrap_or("default")
        .to_owned();
    Some((namespace, sa_name))
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Path for the TokenRequest sub-resource of a ServiceAccount.
pub fn token_request_path(namespace: &str, sa_name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/serviceaccounts/{sa_name}/token")
}

/// Path for the Secrets collection in a namespace.
pub fn secrets_path(namespace: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/secrets")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- build_sa_token_secret ---

    #[test]
    fn secret_has_correct_kind_and_type() {
        // The API server relies on kind=Secret and the SA token type to
        // route the object to the right storage backend.
        let s = build_sa_token_secret("default", "my-sa", "dG9rZW4=");
        assert_eq!(s["kind"], "Secret");
        assert_eq!(s["type"], "kubernetes.io/service-account-token");
    }

    #[test]
    fn secret_name_follows_convention() {
        // kubectl and tooling expect "<sa-name>-token" naming.
        let s = build_sa_token_secret("kube-system", "coredns", "abc");
        assert_eq!(s["metadata"]["name"], "coredns-token");
    }

    #[test]
    fn secret_namespace_is_set() {
        let s = build_sa_token_secret("kube-system", "coredns", "abc");
        assert_eq!(s["metadata"]["namespace"], "kube-system");
    }

    #[test]
    fn secret_annotation_links_to_sa() {
        // The annotation is the machine-readable link back to the owning SA.
        let s = build_sa_token_secret("default", "my-sa", "dG9rZW4=");
        assert_eq!(
            s["metadata"]["annotations"]["kubernetes.io/service-account.name"],
            "my-sa"
        );
    }

    #[test]
    fn secret_data_token_field_set() {
        // The token must be stored under the "token" key in data.
        let s = build_sa_token_secret("default", "my-sa", "dG9rZW4=");
        assert_eq!(s["data"]["token"], "dG9rZW4=");
    }

    #[test]
    fn secret_api_version_is_v1() {
        let s = build_sa_token_secret("default", "svc", "x");
        assert_eq!(s["apiVersion"], "v1");
    }

    // --- parse_sa_added_event ---

    #[test]
    fn parse_added_event_returns_namespace_and_name() {
        // Happy path: ADDED event with both fields populated.
        let event = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "my-sa", "namespace": "production" }
            }
        });
        assert_eq!(
            parse_sa_added_event(&event),
            Some(("production".to_owned(), "my-sa".to_owned()))
        );
    }

    #[test]
    fn parse_added_event_ignores_non_added_types() {
        // MODIFIED and DELETED events must not trigger provisioning — doing so
        // would cause duplicate or spurious secret creation.
        for event_type in &["MODIFIED", "DELETED", "BOOKMARK", "ERROR"] {
            let event = serde_json::json!({
                "type": event_type,
                "object": {
                    "metadata": { "name": "my-sa", "namespace": "default" }
                }
            });
            assert_eq!(
                parse_sa_added_event(&event),
                None,
                "expected None for event type {event_type}"
            );
        }
    }

    #[test]
    fn parse_added_event_returns_none_for_empty_name() {
        // An SA with no name is malformed; skip to avoid creating
        // a secret named "-token".
        let event = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "", "namespace": "default" }
            }
        });
        assert_eq!(parse_sa_added_event(&event), None);
    }

    #[test]
    fn parse_added_event_returns_none_for_missing_name() {
        let event = serde_json::json!({
            "type": "ADDED",
            "object": { "metadata": { "namespace": "default" } }
        });
        assert_eq!(parse_sa_added_event(&event), None);
    }

    #[test]
    fn parse_added_event_defaults_namespace_to_default() {
        // Kubernetes defaults namespace to "default" when not specified.
        let event = serde_json::json!({
            "type": "ADDED",
            "object": { "metadata": { "name": "my-sa" } }
        });
        assert_eq!(
            parse_sa_added_event(&event),
            Some(("default".to_owned(), "my-sa".to_owned()))
        );
    }

    #[test]
    fn parse_added_event_returns_none_for_missing_type() {
        // An event with no type field must not be treated as ADDED.
        let event = serde_json::json!({
            "object": { "metadata": { "name": "my-sa", "namespace": "default" } }
        });
        assert_eq!(parse_sa_added_event(&event), None);
    }

    // --- URL helpers ---

    #[test]
    fn token_request_path_format() {
        // The path must match the Kubernetes API exactly — wrong paths return 404.
        assert_eq!(
            token_request_path("production", "my-sa"),
            "/api/v1/namespaces/production/serviceaccounts/my-sa/token"
        );
    }

    #[test]
    fn secrets_path_format() {
        assert_eq!(
            secrets_path("kube-system"),
            "/api/v1/namespaces/kube-system/secrets"
        );
    }
}
