use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use u7s_store::StoreError;

use crate::{proto, status::Status};

/// Validates a filesystem path supplied at the CLI boundary.
/// Rejects paths containing `..` components to prevent traversal.
/// Returns the path unchanged if valid.
pub fn validate_cli_path(path: &std::path::Path) -> anyhow::Result<&std::path::Path> {
    for component in path.components() {
        if component == std::path::Component::ParentDir {
            return Err(anyhow::anyhow!(
                "path '{}' contains '..' which is not allowed",
                path.display()
            ));
        }
    }
    Ok(path)
}

/// Map a `StoreError` to the corresponding HTTP `StatusCode`.
///
/// Handlers that need a richer error message (including resource name/kind) call
/// the local `store_err(err, name, kind)` wrapper in their own module.  This
/// function covers the status-code portion and is shared via `util`.
pub(crate) fn store_err_to_status(e: &StoreError) -> StatusCode {
    match e {
        StoreError::NotFound { .. } => StatusCode::NOT_FOUND,
        StoreError::AlreadyExists { .. } => StatusCode::CONFLICT,
        StoreError::RevisionMismatch { .. } => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Extract the `Content-Type` header value as a `&str`.
/// Returns `""` when the header is absent or not valid UTF-8.
pub(crate) fn content_type(headers: &HeaderMap) -> &str {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// If the request body uses the Kubernetes protobuf encoding, decode it and return the embedded
/// raw payload as JSON bytes. Otherwise return the bytes unchanged.
///
/// kubectl sends core types (Namespace, ConfigMap, …) with contentType="" in the proto envelope
/// and a proto-encoded object in Unknown.raw. We decode those using type-specific decoders keyed
/// on the Kind from the envelope TypeMeta. For non-core types (CRDs, CRs), kubectl sends JSON
/// inside the envelope (or as plain JSON), which passes through unchanged.
///
/// This allows all write handlers to support both `application/json` and
/// `application/vnd.kubernetes.protobuf` without duplicating decode logic.
pub fn extract_body(bytes: &Bytes, content_type: &str) -> Bytes {
    if !content_type.starts_with("application/vnd.kubernetes.protobuf") {
        return bytes.clone();
    }
    let env = match proto::decode_k8s_proto_envelope(bytes) {
        Some(e) => e,
        None => return bytes.clone(),
    };
    // When contentType is explicitly JSON, raw is JSON — return as-is.
    if env.content_type == "application/json" {
        return Bytes::from(env.raw);
    }
    // For all other cases (empty or explicit protobuf contentType), raw bytes are proto-encoded.
    // Try type-specific decoders first.
    if !env.kind.is_empty() {
        if let Some(json_val) = proto::decode_core_proto_by_kind(&env.kind, &env.raw) {
            if let Ok(json_bytes) = serde_json::to_vec(&json_val) {
                return Bytes::from(json_bytes);
            }
        }
    }
    // Fallback: if raw bytes look like JSON (start with '{'), return them directly.
    // This handles non-core types that send JSON with empty contentType.
    if env.raw.first() == Some(&b'{') {
        return Bytes::from(env.raw);
    }
    // Cannot decode — return original bytes so the handler reports a meaningful error.
    bytes.clone()
}

/// Parse an optional `resourceVersion` string into an optional `u64`.
///
/// - `None` or `""` → `Ok(None)` (unconditional write)
/// - `"0"`          → `Ok(Some(0))` (write only if key doesn't exist)
/// - any other      → parse as `u64`, error on failure
pub fn parse_resource_version(rv: Option<&str>) -> Result<Option<u64>, crate::status::StatusError> {
    match rv {
        None | Some("") => Ok(None),
        Some("0") => Ok(Some(0)),
        Some(s) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|_| Status::bad_request(format!("invalid resourceVersion: {s}"))),
    }
}

/// Returns the current UTC time formatted as RFC3339 (`YYYY-MM-DDThh:mm:ssZ`).
/// Uses only `std::time` — no chrono dependency.
pub fn utc_now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs_to_rfc3339(secs)
}

/// Convert a Unix timestamp (seconds since epoch) to an RFC3339 string (`YYYY-MM-DDThh:mm:ssZ`).
/// Uses only `std::time` — no chrono dependency.
pub fn secs_to_rfc3339(secs: u64) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400; // days since 1970-01-01

    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Normalize an RFC3339 timestamp string to include microsecond precision.
///
/// client-go's `metav1.MicroTime` (used for `Event.eventTime`) and some Event
/// time field codecs require the fractional-seconds component to be present, e.g.
/// `2017-09-20T13:49:16.000000Z`.  Timestamps produced without sub-second parts
/// (`2017-09-20T13:49:16Z`) cause a parse error in client-go:
///   `parsing time "…Z" as "…000000Z07:00": cannot parse "Z" as ".000000"`.
///
/// This function appends `.000000` when the string is a bare RFC3339 timestamp
/// (19-char date-time part ending with `Z` or `+HH:MM`/`-HH:MM`) with no
/// fractional-seconds component already present.  Already-precise strings are
/// returned unchanged.  Non-timestamp strings (null, empty) are returned as-is.
pub fn normalize_rfc3339_to_micro(s: &str) -> String {
    // A bare second-precision RFC3339 with Z suffix looks like:
    //   "2017-09-20T13:49:16Z"  (20 chars, ends with 'Z', 'T' at index 10)
    // With +HH:MM offset:
    //   "2017-09-20T13:49:16+00:00"  (25 chars)
    // Already has fractional seconds if a '.' appears after the 'T'.
    if let Some(t_pos) = s.find('T') {
        let after_t = &s[t_pos + 1..];
        if !after_t.contains('.') {
            // No fractional seconds — insert `.000000` before the timezone suffix.
            // Find where the timezone starts: 'Z' or '+'/'-' after the time digits.
            if let Some(tz_pos) = after_t.find(['Z', '+', '-']) {
                let (date_time, tz) = s.split_at(t_pos + 1 + tz_pos);
                return format!("{date_time}.000000{tz}");
            }
        }
    }
    s.to_string()
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // 400-year cycle = 146097 days
    let n400 = days / 146097;
    days %= 146097;
    let n100 = (days / 36524).min(3);
    days -= n100 * 36524;
    let n4 = days / 1461;
    days %= 1461;
    let n1 = (days / 365).min(3);
    days -= n1 * 365;

    let year = n400 * 400 + n100 * 100 + n4 * 4 + n1 + 1970;
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let month_days: &[u64] = if leap {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0u64;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i as u64 + 1;
            break;
        }
        days -= md;
    }
    (year, month, days + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- store_err_to_status --

    /// NotFound → 404. Any handler mapping StoreError to an HTTP status must use this
    /// so the code is in one place and cannot drift between handlers.
    #[test]
    fn store_err_to_status_not_found_is_404() {
        let e = StoreError::NotFound { key: "k".into() };
        assert_eq!(store_err_to_status(&e), StatusCode::NOT_FOUND);
    }

    #[test]
    fn store_err_to_status_already_exists_is_409() {
        let e = StoreError::AlreadyExists { key: "k".into() };
        assert_eq!(store_err_to_status(&e), StatusCode::CONFLICT);
    }

    #[test]
    fn store_err_to_status_revision_mismatch_is_409() {
        let e = StoreError::RevisionMismatch {
            expected: 1,
            current: 2,
        };
        assert_eq!(store_err_to_status(&e), StatusCode::CONFLICT);
    }

    /// StoreError::NotFound must NOT expose the internal registry key path to clients.
    ///
    /// The internal key format ("/registry/pods/default/nginx") is an implementation
    /// detail that must not appear in client-facing error messages. Exposing it would
    /// help attackers understand the internal key structure and could aid path
    /// traversal or enumeration attacks.
    ///
    /// Handlers must use Status::not_found(name, kind) which produces the Kubernetes-
    /// standard format `pods "nginx" not found` instead of forwarding e.to_string().
    #[test]
    fn store_not_found_to_string_contains_internal_key() {
        // Confirm the raw StoreError message does contain the internal key — this is
        // intentional for logging. The test below verifies the handler-layer translation.
        let internal_key = "/registry/pods/default/nginx";
        let e = StoreError::NotFound {
            key: internal_key.to_owned(),
        };
        assert!(
            e.to_string().contains(internal_key),
            "StoreError::NotFound must include key for internal logging: {e}"
        );
    }

    /// The Kubernetes-compatible 404 message must NOT include the internal store key.
    ///
    /// This test enforces the conversion contract: handlers must call
    /// `Status::not_found(name, kind)` to produce the standard
    /// `pods "nginx" not found` format, not forward `e.to_string()`.
    #[test]
    fn status_not_found_does_not_leak_internal_key() {
        let internal_key = "/registry/pods/default/nginx";
        let resource_name = "nginx";
        let kind = "Pod";

        let status_error = Status::not_found(resource_name, kind);
        let message = &status_error.1.message;

        // Must produce the Kubernetes-standard format.
        assert_eq!(
            message, "Pod \"nginx\" not found",
            "not_found message must match Kubernetes format"
        );
        // Must NOT contain the internal store key path.
        assert!(
            !message.contains(internal_key),
            "client-facing 404 message must not expose internal store key '{internal_key}', got: {message}"
        );
        assert!(
            !message.contains("/registry/"),
            "client-facing 404 must not expose /registry/ prefix, got: {message}"
        );
    }

    // -- content_type --

    /// content_type returns the header value as a &str when present.
    /// All write handlers call this; if the header is missing an empty str must be returned
    /// (not a panic) so extract_body and detect_patch_type get a safe default.
    #[test]
    fn content_type_present() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        assert_eq!(content_type(&h), "application/json");
    }

    #[test]
    fn content_type_absent_returns_empty() {
        let h = HeaderMap::new();
        assert_eq!(content_type(&h), "");
    }

    /// secs_to_rfc3339 must produce correct date for a known epoch offset.
    /// 2024-01-01T00:00:00Z = 1704067200 seconds since epoch.
    #[test]
    fn rfc3339_known_date() {
        assert_eq!(secs_to_rfc3339(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    /// secs_to_rfc3339 must handle the Unix epoch itself.
    #[test]
    fn rfc3339_epoch() {
        assert_eq!(secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    /// secs_to_rfc3339 must handle a leap year correctly (2000 is a leap year).
    /// 2000-02-29T00:00:00Z = 951782400 seconds since epoch.
    #[test]
    fn rfc3339_leap_year_feb29() {
        assert_eq!(secs_to_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    // -- validate_cli_path --

    /// A normal absolute path without any `..` must be accepted unchanged.
    /// This is the common case: operator supplies a concrete path at startup.
    #[test]
    fn validate_cli_path_accepts_absolute() {
        let p = std::path::Path::new("/var/lib/u7s/ca.key");
        let result = validate_cli_path(p);
        assert!(
            result.is_ok(),
            "absolute path without '..' must be accepted"
        );
        assert_eq!(result.unwrap(), p);
    }

    /// A relative path without `..` must be accepted unchanged.
    /// Operators commonly supply relative paths like `./sa.key`.
    #[test]
    fn validate_cli_path_accepts_relative_without_dotdot() {
        let p = std::path::Path::new("./sa.key");
        let result = validate_cli_path(p);
        assert!(
            result.is_ok(),
            "relative path without '..' must be accepted"
        );
        assert_eq!(result.unwrap(), p);
    }

    /// A path with a `..` component must be rejected.
    /// This is the path-traversal attack vector CodeQL flagged: an operator (or
    /// attacker who controls CLI args) could supply `../../etc/passwd` to read
    /// outside the intended directory.
    #[test]
    fn validate_cli_path_rejects_dotdot() {
        let p = std::path::Path::new("/var/lib/u7s/../../etc/passwd");
        let result = validate_cli_path(p);
        assert!(
            result.is_err(),
            "path with '..' component must be rejected to prevent traversal"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains(".."),
            "error message must mention the traversal component, got: {msg}"
        );
    }

    /// utc_now_rfc3339 must return a plausible timestamp (after 2024-01-01).
    #[test]
    fn utc_now_is_recent() {
        let now = utc_now_rfc3339();
        // Must start with "20" for any year 2000+.
        assert!(now.starts_with("20"), "unexpected prefix: {now}");
        // Must be after 2024.
        assert!(
            now.as_str() >= "2024-01-01T00:00:00Z",
            "implausibly old: {now}"
        );
    }

    // -- normalize_rfc3339_to_micro --

    /// Bare RFC3339 (no fractional seconds) must gain `.000000` suffix.
    ///
    /// client-go's MicroTime codec requires the fractional part; without it,
    /// Event lifecycle conformance tests fail with "cannot parse Z as .000000".
    #[test]
    fn normalize_rfc3339_to_micro_appends_zeros_for_bare_z() {
        assert_eq!(
            normalize_rfc3339_to_micro("2017-09-20T13:49:16Z"),
            "2017-09-20T13:49:16.000000Z",
            "bare RFC3339 with Z suffix must gain .000000"
        );
    }

    /// Already-precise timestamps must be returned unchanged.
    ///
    /// Sub-microsecond precision from client-go must not be silently truncated.
    #[test]
    fn normalize_rfc3339_to_micro_leaves_precise_unchanged() {
        assert_eq!(
            normalize_rfc3339_to_micro("2017-09-20T13:49:16.123456Z"),
            "2017-09-20T13:49:16.123456Z",
            "timestamp with fractional seconds must not be modified"
        );
    }

    /// Zero-precision suffix (`.000000`) must be left unchanged (idempotent).
    #[test]
    fn normalize_rfc3339_to_micro_idempotent_on_zeros() {
        assert_eq!(
            normalize_rfc3339_to_micro("2017-09-20T13:49:16.000000Z"),
            "2017-09-20T13:49:16.000000Z",
            "already-normalized timestamp must not be double-suffixed"
        );
    }

    /// Timezone-offset variant must also gain `.000000` before the offset.
    #[test]
    fn normalize_rfc3339_to_micro_handles_tz_offset() {
        assert_eq!(
            normalize_rfc3339_to_micro("2017-09-20T13:49:16+05:30"),
            "2017-09-20T13:49:16.000000+05:30",
            "bare RFC3339 with numeric TZ offset must gain .000000 before offset"
        );
    }

    // ---------------------------------------------------------------------------
    // Wire-level integration tests — extract_body against kubectl wire fixtures
    //
    // These tests replicate the exact byte layout kubectl sends over the wire so
    // that the class of proto-decode bug that broke the smoke test (empty
    // contentType field in the Unknown envelope, raw bytes being proto-encoded
    // rather than JSON) cannot regress silently through unit tests.
    //
    // Fixture construction follows the documented wire format in proto.rs:
    //   magic[4] | Unknown{ field1=TypeMeta, field2=raw, field4=contentType }
    //
    // The helpers below duplicate the varint/length-delimited encoder that lives
    // in proto::tests so that these tests are self-contained with no non-test
    // code changes.
    // ---------------------------------------------------------------------------

    fn encode_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn encode_ld(field_number: u64, payload: &[u8]) -> Vec<u8> {
        let tag = (field_number << 3) | 2;
        let mut out = encode_varint(tag);
        out.extend_from_slice(&encode_varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    /// Build a k8s Unknown envelope with TypeMeta (field 1), raw (field 2), and optional
    /// contentType (field 4). Pass `content_type=None` to omit field 4, which is what kubectl
    /// does for core types like Namespace and ConfigMap (the smoke-test bug scenario).
    fn build_kubectl_proto_body(
        api_version: &[u8],
        kind: &[u8],
        raw: &[u8],
        content_type: Option<&[u8]>,
    ) -> Vec<u8> {
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];

        let mut type_meta = encode_ld(1, api_version); // field 1 = apiVersion
        type_meta.extend_from_slice(&encode_ld(2, kind)); // field 2 = kind

        let mut unknown = encode_ld(1, &type_meta); // TypeMeta
        unknown.extend_from_slice(&encode_ld(2, raw)); // raw
        if let Some(ct) = content_type {
            unknown.extend_from_slice(&encode_ld(4, ct)); // contentType
        }

        let mut body = MAGIC.to_vec();
        body.extend_from_slice(&unknown);
        body
    }

    /// Build a proto-encoded ObjectMeta with name and optional namespace.
    fn build_object_meta(name: &[u8], namespace: Option<&[u8]>) -> Vec<u8> {
        let mut meta = encode_ld(1, name); // field 1 = name
        if let Some(ns) = namespace {
            meta.extend_from_slice(&encode_ld(3, ns)); // field 3 = namespace
        }
        meta.extend_from_slice(&encode_ld(8, &[])); // field 8 = creationTimestamp (empty Time{})
        meta
    }

    /// test_namespace_create_kubectl_wire_format
    ///
    /// kubectl create namespace test-ns sends:
    ///   Content-Type: application/vnd.kubernetes.protobuf
    ///   Body: magic + Unknown{ TypeMeta{v1/Namespace}, raw=proto(Namespace), contentType="" (absent) }
    ///
    /// extract_body must decode the nested proto-encoded Namespace and return JSON with the correct
    /// name. This is the exact wire pattern that caused the smoke CI failure — the server previously
    /// tried to JSON-parse the proto bytes (starting with 0x0a) and got "invalid JSON".
    #[test]
    fn test_namespace_create_kubectl_wire_format() {
        let obj_meta = build_object_meta(b"test-ns", None);
        let namespace_proto = encode_ld(1, &obj_meta); // Namespace.metadata = ObjectMeta

        // kubectl omits field 4 (contentType) for core types
        let body = build_kubectl_proto_body(b"v1", b"Namespace", &namespace_proto, None);
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");
        let json: serde_json::Value =
            serde_json::from_slice(&decoded).expect("extract_body must produce valid JSON");

        assert_eq!(json["kind"], "Namespace", "kind must be Namespace");
        assert_eq!(json["apiVersion"], "v1", "apiVersion must be v1");
        assert_eq!(
            json["metadata"]["name"], "test-ns",
            "name must survive proto decode — regression for smoke-test 'invalid JSON' failure"
        );
        assert!(
            json["metadata"]["creationTimestamp"].is_null(),
            "creationTimestamp must be null for kubectl compatibility"
        );
    }

    /// test_configmap_create_kubectl_wire_format
    ///
    /// kubectl create configmap test-cm --from-literal=key=value --namespace=test-ns sends:
    ///   Content-Type: application/vnd.kubernetes.protobuf
    ///   Body: magic + Unknown{ TypeMeta{v1/ConfigMap}, raw=proto(ConfigMap), contentType="" (absent) }
    ///
    /// extract_body must decode the nested proto-encoded ConfigMap and return JSON with name,
    /// namespace, and data intact. This exercises the same empty-contentType path as the Namespace
    /// test — a regression guard for the smoke CI failure on configmap creation.
    #[test]
    fn test_configmap_create_kubectl_wire_format() {
        let obj_meta = build_object_meta(b"test-cm", Some(b"test-ns"));

        // ConfigMap.data map entry: { key="key", value="value" }
        let mut data_entry = encode_ld(1, b"key");
        data_entry.extend_from_slice(&encode_ld(2, b"value"));

        let mut configmap_proto = encode_ld(1, &obj_meta); // field 1 = ObjectMeta
        configmap_proto.extend_from_slice(&encode_ld(2, &data_entry)); // field 2 = data entry

        // kubectl omits field 4 (contentType) for core types
        let body = build_kubectl_proto_body(b"v1", b"ConfigMap", &configmap_proto, None);
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");
        let json: serde_json::Value =
            serde_json::from_slice(&decoded).expect("extract_body must produce valid JSON");

        assert_eq!(json["kind"], "ConfigMap", "kind must be ConfigMap");
        assert_eq!(json["apiVersion"], "v1", "apiVersion must be v1");
        assert_eq!(
            json["metadata"]["name"], "test-cm",
            "name must survive proto decode"
        );
        assert_eq!(
            json["metadata"]["namespace"], "test-ns",
            "namespace must survive proto decode"
        );
        assert_eq!(
            json["data"]["key"], "value",
            "configmap data must survive proto decode"
        );
    }

    /// test_crd_apply_kubectl_wire_format
    ///
    /// kubectl apply --validate=false -f crd.yaml sends:
    ///   Content-Type: application/json
    ///   Body: plain JSON (kubectl uses JSON for apply, not proto)
    ///
    /// extract_body must pass the JSON body through unchanged when Content-Type is not protobuf.
    /// This verifies the apply path does not accidentally strip or corrupt CRD JSON.
    #[test]
    fn test_crd_apply_kubectl_wire_format() {
        let crd_json = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "spec": {
                "group": "example.com",
                "names": { "kind": "Widget", "plural": "widgets" },
                "scope": "Namespaced",
                "versions": [{ "name": "v1", "served": true, "storage": true }]
            }
        });
        let body_bytes = serde_json::to_vec(&crd_json).unwrap();
        let bytes = Bytes::from(body_bytes.clone());

        let decoded = extract_body(&bytes, "application/json");
        assert_eq!(
            decoded.as_ref(),
            body_bytes.as_slice(),
            "CRD JSON body must pass through extract_body unchanged"
        );

        // Confirm the JSON is still parseable and correct
        let parsed: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(parsed["kind"], "CustomResourceDefinition");
        assert_eq!(parsed["metadata"]["name"], "widgets.example.com");
    }

    /// test_cr_apply_kubectl_wire_format
    ///
    /// kubectl apply --validate=false -f cr.yaml sends:
    ///   Content-Type: application/json
    ///   Body: plain JSON (kubectl uses JSON for apply of custom resources, not proto)
    ///
    /// extract_body must pass the CR JSON through unchanged. This verifies that custom resource
    /// instances — which have no registered proto decoder — are handled correctly via the JSON
    /// passthrough path, not corrupted by a proto decode attempt.
    #[test]
    fn test_cr_apply_kubectl_wire_format() {
        let cr_json = serde_json::json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "my-widget", "namespace": "default" },
            "spec": { "color": "blue", "count": 3 }
        });
        let body_bytes = serde_json::to_vec(&cr_json).unwrap();
        let bytes = Bytes::from(body_bytes.clone());

        let decoded = extract_body(&bytes, "application/json");
        assert_eq!(
            decoded.as_ref(),
            body_bytes.as_slice(),
            "CR JSON body must pass through extract_body unchanged"
        );

        let parsed: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(parsed["kind"], "Widget");
        assert_eq!(parsed["spec"]["color"], "blue");
    }

    /// test_extract_body_proto_with_explicit_json_content_type
    ///
    /// When kubectl sends a protobuf envelope but Unknown.contentType is "application/json",
    /// extract_body must return the raw bytes directly (they are already JSON). This path is
    /// taken for non-core types sent via protobuf where the inner encoding is JSON.
    #[test]
    fn test_extract_body_proto_with_explicit_json_content_type() {
        let inner_json =
            br#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-via-json"}}"#;

        // Build envelope with explicit contentType=application/json
        let body =
            build_kubectl_proto_body(b"v1", b"Namespace", inner_json, Some(b"application/json"));
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");
        let json: serde_json::Value = serde_json::from_slice(&decoded).expect("must be valid JSON");
        assert_eq!(
            json["metadata"]["name"], "ns-via-json",
            "inner JSON must be returned as-is when contentType=application/json"
        );
    }
}
