//! Typed-status GVK dispatch table.
//!
//! Root cause this closes: generic status handlers
//! manipulate `status` as raw `serde_json::Value`, so a scalar status silently
//! coerces (e.g. `NamespaceStatus::deserialize(v).unwrap_or_default()` turning
//! `"status": "oops"` into a stored `{}`) instead of being rejected. A typed decode
//! makes that a decode error by construction.
//!
//! Keyed on full GVK (`apiVersion`, `kind`), not `kind` alone — a kind can have
//! multiple wire shapes across versions (e.g. HorizontalPodAutoscaler v1 vs v2),
//! so matching only `kind` would silently apply the wrong codec to a same-named,
//! differently-shaped status. Every entry here has exactly one apiVersion, but the
//! lookup checks both so a future differently-versioned kind can't collide.
//!
//! Both wrappers are `Option`-returning: `None` means the (apiVersion, kind) pair
//! isn't registered yet, and the caller falls through to the existing dynamic
//! guard (`replace_status_field_dynamic` / `reject_non_object_status`) UNCHANGED.
//! This is what makes a non-migrated kind's behavior provably untouched, and lets
//! a future kind be added with one table entry, never touching a call site again.
//!
//! `null` is not handled here: RFC 7396 field-deletion (`{"status": null}`) is
//! legal for every kind regardless of typed shape, so callers check `is_null()`
//! before invoking either wrapper, same convention as
//! `handlers::status::apply_status_replacement`.

use crate::status::{Status, StatusError};
use crate::types::{ApiServiceStatus, CertificateSigningRequestStatus, NamespaceStatus};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

type StatusCodec = fn(&Value) -> Result<Value, serde_json::Error>;

/// Deserializes into `T` then re-serializes, so every registered kind's status is
/// canonicalized the same way regardless of its concrete struct — mirrors
/// `proto.rs`'s per-kind decoder table, generic instead of hand-written per kind
/// because every entry here does the identical decode-then-reencode.
fn codec<T: serde::Serialize + serde::de::DeserializeOwned>(
    v: &Value,
) -> Result<Value, serde_json::Error> {
    let typed: T = serde_json::from_value(v.clone())?;
    serde_json::to_value(typed)
}

struct CodecEntry {
    api_version: &'static str,
    codec: StatusCodec,
}

fn status_codecs() -> &'static HashMap<&'static str, CodecEntry> {
    static CODECS: OnceLock<HashMap<&'static str, CodecEntry>> = OnceLock::new();
    CODECS.get_or_init(|| {
        let mut m: HashMap<&'static str, CodecEntry> = HashMap::new();
        m.insert(
            "Namespace",
            CodecEntry {
                api_version: "v1",
                codec: codec::<NamespaceStatus>,
            },
        );
        m.insert(
            "CertificateSigningRequest",
            CodecEntry {
                api_version: "certificates.k8s.io/v1",
                codec: codec::<CertificateSigningRequestStatus>,
            },
        );
        m.insert(
            "APIService",
            CodecEntry {
                api_version: "apiregistration.k8s.io/v1",
                codec: codec::<ApiServiceStatus>,
            },
        );
        m
    })
}

fn lookup(api_version: &str, kind: &str) -> Option<StatusCodec> {
    status_codecs()
        .get(kind)
        .filter(|entry| entry.api_version == api_version)
        .map(|entry| entry.codec)
}

/// PUT /status: a present-but-non-decodable status is upstream's whole-body typed-decode
/// failure (`transformDecodeError` -> `NewBadRequest`) -> 400.
pub(crate) fn decode_status_put(
    api_version: &str,
    kind: &str,
    incoming: &Value,
) -> Option<Result<Value, StatusError>> {
    lookup(api_version, kind)
        .map(|f| f(incoming).map_err(|e| Status::bad_request(format!("status: {e}"))))
}

/// PATCH (merge-PATCH / JSON-Patch / strategic-merge) post-merge convergence point: a
/// merged status that fails the same typed decode is upstream's post-merge validation
/// failure (`DecodeInto` -> `NewInvalid`) -> 422.
pub(crate) fn decode_status_patch(
    api_version: &str,
    kind: &str,
    merged: &Value,
) -> Option<Result<Value, StatusError>> {
    lookup(api_version, kind)
        .map(|f| f(merged).map_err(|e| Status::unprocessable_entity(format!("status: {e}"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A kind not in the table must fall through (`None`), not be silently accepted or
    /// rejected — this is the property that keeps every non-migrated kind's behavior
    /// untouched by Phase-1.
    #[test]
    fn unregistered_kind_returns_none() {
        assert!(decode_status_put("example.com/v1", "Widget", &json!({})).is_none());
        assert!(decode_status_patch("example.com/v1", "Widget", &json!({})).is_none());
    }

    /// A registered kind whose apiVersion doesn't match must also fall through — GVK
    /// keying, not kind-alone keying, is the whole point: a same-named kind at a
    /// different apiVersion must not be forced through the wrong codec.
    #[test]
    fn registered_kind_wrong_api_version_returns_none() {
        assert!(decode_status_put("v2", "Namespace", &json!({})).is_none());
    }

    /// Fail-on-revert test for the silent-coercion bug: a scalar status
    /// must decode to `Err`, never to a defaulted value. Reverting the typed `codec::<T>`
    /// call back to `.unwrap_or_default()`-style handling makes this test fail because
    /// `Ok(Value::Object({}))` would compare unequal to nothing — the test only passes
    /// if the call site actually observes an `Err`.
    #[test]
    fn scalar_status_is_rejected_not_defaulted() {
        let put_result = decode_status_put("v1", "Namespace", &json!("oops"))
            .expect("Namespace is registered")
            .expect_err("a scalar status must not decode into a default NamespaceStatus");
        assert_eq!(put_result.0, axum::http::StatusCode::BAD_REQUEST);

        let patch_result = decode_status_patch("v1", "Namespace", &json!("oops"))
            .expect("Namespace is registered")
            .expect_err("a scalar status must not decode into a default NamespaceStatus");
        assert_eq!(patch_result.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// An array status must be rejected the same way a scalar is — both are "not an
    /// object", the same upstream typed-decode failure.
    #[test]
    fn array_status_is_rejected() {
        assert!(decode_status_put("v1", "Namespace", &json!([1, 2, 3]))
            .expect("Namespace is registered")
            .is_err());
    }

    /// Round-trip: every enumerated field set decodes and re-encodes losslessly for each
    /// of the three Phase-1 kinds — proves the dispatch table actually reaches the typed
    /// struct for all three entries, not just the one exercised by the scalar test above.
    #[test]
    fn round_trips_enumerated_fields_for_all_three_kinds() {
        let ns = json!({"phase": "Terminating"});
        let decoded = decode_status_put("v1", "Namespace", &ns)
            .expect("Namespace is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["phase"], "Terminating");

        let csr =
            json!({"certificate": "abc==", "conditions": [{"type": "Approved", "status": "True"}]});
        let decoded =
            decode_status_put("certificates.k8s.io/v1", "CertificateSigningRequest", &csr)
                .expect("CertificateSigningRequest is registered")
                .expect("valid status must decode");
        assert_eq!(decoded["certificate"], "abc==");
        assert_eq!(decoded["conditions"][0]["type"], "Approved");

        let apisvc = json!({"conditions": [{"type": "Available", "status": "True"}]});
        let decoded = decode_status_put("apiregistration.k8s.io/v1", "APIService", &apisvc)
            .expect("APIService is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["conditions"][0]["type"], "Available");
    }

    /// The flatten-rest lossless-passthrough property: a field no enumerated struct
    /// field names must survive verbatim, not be dropped. This is the safety property
    /// that makes hand-written minimal-field structs acceptable instead of a lossy
    /// codegen struct — under-enumerating a field must cost "not validated yet", never
    /// data loss.
    #[test]
    fn unrecognized_field_survives_via_rest() {
        let ns = json!({"phase": "Active", "someFutureField": {"nested": 1}});
        let decoded = decode_status_put("v1", "Namespace", &ns)
            .expect("Namespace is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["someFutureField"]["nested"], 1);

        let apisvc = json!({"conditions": [], "someFutureField": "x"});
        let decoded = decode_status_put("apiregistration.k8s.io/v1", "APIService", &apisvc)
            .expect("APIService is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["someFutureField"], "x");
    }
}
