/// Pure, testable logic extracted from u7s-controller-manager.
///
/// All async I/O stays in main.rs. This module contains only functions
/// that can be exercised without a live API server.
use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Secret construction
// ---------------------------------------------------------------------------

/// Typed `data` field for a `kubernetes.io/service-account-token` Secret.
///
/// Using a struct rather than a raw `json!` literal ensures that field names
/// are checked at compile time — a typo like `"tokne"` would silently produce
/// a wrong Secret that no client can consume.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SecretData {
    pub token: String,
}

/// Build the Secret object that holds a service-account token.
///
/// The Secret type and annotation are required by the Kubernetes SA token
/// controller contract; tools like kubectl rely on the `<sa-name>-token`
/// naming convention.
pub fn build_sa_token_secret(namespace: &str, sa_name: &str, token_b64: &str) -> Value {
    let data = SecretData {
        token: token_b64.to_owned(),
    };
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
        "data": serde_json::to_value(data).expect("SecretData serializes")
    })
}

// ---------------------------------------------------------------------------
// Watch event parsing
// ---------------------------------------------------------------------------

/// Typed envelope for a Kubernetes watch event.
///
/// Using a struct rather than raw `event["type"]` / `event["object"][...]`
/// indexing means a missing or mistyped field is a deserialization error,
/// not a silent empty string that causes service accounts to be skipped.
#[derive(Debug, Deserialize)]
struct WatchEvent<T> {
    #[serde(rename = "type")]
    event_type: String,
    object: T,
}

/// Minimal typed view of a ServiceAccount's metadata in a watch event.
#[derive(Debug, Default, Deserialize)]
struct SaMetadata {
    name: Option<String>,
    namespace: Option<String>,
}

/// Minimal typed view of a ServiceAccount object in a watch event.
#[derive(Debug, Default, Deserialize)]
struct SaObject {
    metadata: SaMetadata,
}

/// Extract (namespace, sa_name) from a ServiceAccount ADDED watch event.
///
/// Returns `None` if:
/// - the event type is not "ADDED", or
/// - the SA name is missing/empty.
///
/// Namespace defaults to "default" when missing, matching Kubernetes behaviour.
pub fn parse_sa_added_event(event: &Value) -> Option<(String, String)> {
    let watch_event: WatchEvent<SaObject> =
        serde_json::from_value(event.clone()).unwrap_or_else(|_| WatchEvent {
            event_type: String::new(),
            object: SaObject::default(),
        });
    if watch_event.event_type != "ADDED" {
        return None;
    }
    let sa_name = watch_event.object.metadata.name.as_deref().unwrap_or("");
    if sa_name.is_empty() {
        return None;
    }
    let namespace = watch_event
        .object
        .metadata
        .namespace
        .unwrap_or_else(|| "default".to_owned());
    Some((namespace, sa_name.to_owned()))
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

    // --- SecretData ---

    /// SecretData must serialize to {"token":"<value>"} so that the SA token
    /// controller stores data the kubelet and clients can read back.
    /// A field rename regression ("tokne", "Token") silently breaks all SA auth.
    #[test]
    fn secret_data_serializes_token_field() {
        let d = SecretData {
            token: "dG9rZW4=".to_owned(),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["token"], "dG9rZW4=");
        assert_eq!(
            v.as_object().unwrap().len(),
            1,
            "SecretData must only emit 'token'"
        );
    }

    /// SecretData must round-trip through JSON so stored values can be read back.
    #[test]
    fn secret_data_round_trips() {
        let original = SecretData {
            token: "abc123".to_owned(),
        };
        let v = serde_json::to_value(&original).unwrap();
        let restored: SecretData = serde_json::from_value(v).unwrap();
        assert_eq!(restored.token, "abc123");
    }

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

    // --- WatchEvent deserialization ---

    // Verifies that the typed envelope correctly maps "type" → event_type and
    // "object" → object. A rename or missing field would cause every watch event
    // to be silently ignored (parse failure falls back to empty event_type).
    #[test]
    fn watch_event_deserializes_type_and_object() {
        let json = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "my-sa", "namespace": "production" }
            }
        });
        let we: WatchEvent<SaObject> =
            serde_json::from_value(json).expect("WatchEvent should deserialize");
        assert_eq!(we.event_type, "ADDED");
        assert_eq!(we.object.metadata.name.as_deref(), Some("my-sa"));
        assert_eq!(we.object.metadata.namespace.as_deref(), Some("production"));
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
