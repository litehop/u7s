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
    // Try type-specific decoders first, using apiVersion to disambiguate kinds like "Event"
    // that exist in multiple API groups (core/v1 vs events.k8s.io/v1).
    if !env.kind.is_empty() {
        if let Some(json_val) =
            proto::decode_proto_by_kind_and_version(&env.kind, &env.api_version, &env.raw)
        {
            if let Ok(json_bytes) = serde_json::to_vec(&json_val) {
                return Bytes::from(json_bytes);
            }
        }
    }
    // Fallback: if raw bytes look like JSON (start with '{'), return them directly.
    // This handles non-core types that send JSON with empty contentType.
    // Reject if the JSON kind field contradicts the envelope kind (both non-empty and differ).
    if env.raw.first() == Some(&b'{') {
        if !env.kind.is_empty() {
            if let Ok(obj) = serde_json::from_slice::<serde_json::Value>(&env.raw) {
                if let Some(json_kind) = obj["kind"].as_str() {
                    if !json_kind.is_empty() && json_kind != env.kind {
                        return bytes.clone();
                    }
                }
            }
        }
        return Bytes::from(env.raw);
    }
    // Cannot decode — return original bytes so the handler reports a meaningful error.
    bytes.clone()
}

/// Parse an optional `resourceVersion` string into an optional `u64`.
///
/// - `None`, `""`, or `"0"` → `Ok(None)` (unconditional write)
/// - any other              → parse as `u64`, error on failure
///
/// Only ever called from update/replace/patch handlers (create paths pass a hardcoded
/// `Some(0)` to `Store::put` directly, bypassing this function entirely). That split
/// matters: `Store::put`'s `Some(0)` means "create-only, must not exist", but a client
/// submitting `resourceVersion: "0"` on an Update means the opposite — real kube-apiserver
/// treats resourceVersion 0 on Update as "unconditional write", used by controllers/tests
/// that hold a possibly-stale object and want to force the write through regardless of the
/// current stored revision (e.g. sig-scheduling's node-status BeforeEach/AfterEach, which
/// sets `nodeCopy.ResourceVersion = "0"` before `UpdateStatus` specifically to bypass
/// conflict detection). So "0" must map to the same `None` (unconditional) as an absent
/// resourceVersion, not to `Some(0)` — mapping it to `Some(0)` made every such update
/// against an already-existing object fail with a spurious 409 AlreadyExists.
pub fn parse_resource_version(rv: Option<&str>) -> Result<Option<u64>, crate::status::StatusError> {
    match rv {
        None | Some("") | Some("0") => Ok(None),
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
    secs_to_rfc3339(secs as i64)
}

/// Convert a Unix timestamp (seconds since epoch, may be negative for pre-1970 dates) to an
/// RFC3339 string (`YYYY-MM-DDThh:mm:ssZ`). Uses only `std::time` — no chrono dependency.
///
/// The Kubernetes `metav1.Time`/`MicroTime` wire format allows any date from
/// `0001-01-01T00:00:00Z` onward (see proto comment), which is a negative Unix timestamp.
/// Must use `div_euclid`/`rem_euclid` rather than `/`/`%` — those truncate toward zero and
/// produce the wrong calendar day for negative `secs` (e.g. -1 would wrongly land on
/// 1970-01-01 instead of 1969-12-31).
pub fn secs_to_rfc3339(secs: i64) -> String {
    let secs_of_day = secs.rem_euclid(86400);
    let s = secs_of_day % 60;
    let m = (secs_of_day / 60) % 60;
    let h = (secs_of_day / 3600) % 24;
    let days = secs.div_euclid(86400); // days since 1970-01-01, may be negative

    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert a Unix timestamp (seconds + nanoseconds) to an RFC3339 string with microsecond
/// precision (`YYYY-MM-DDThh:mm:ss.ffffffZ`).
///
/// Used for MicroTime fields (acquireTime, renewTime on Lease; eventTime on Event).
/// MicroTime carries nanoseconds in the proto wire but the Kubernetes API truncates to
/// microseconds — nanos / 1000. `secs` may be negative (pre-1970 dates are valid per the
/// MicroTime wire format).
pub fn secs_nanos_to_rfc3339_micro(secs: i64, nanos: i32) -> String {
    let date_time = secs_to_rfc3339(secs);
    // Truncate nanos to microseconds (6 decimal digits). nanos is 0..=999_999_999.
    let micros = nanos.max(0) / 1000;
    // date_time ends with 'Z'; insert the fractional part before it.
    let base = &date_time[..date_time.len() - 1]; // strip trailing 'Z'
    format!("{base}.{micros:06}Z")
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

/// Parse an RFC3339 timestamp of the exact shape produced by `secs_to_rfc3339`/
/// `utc_now_rfc3339` (`YYYY-MM-DDThh:mm:ss[.ffffff]Z`) back into Unix seconds.
/// Returns `None` if the string doesn't match that shape. Uses only `std::time` — no
/// chrono dependency, mirroring `secs_to_rfc3339`.
///
/// Needed by the SA-token bound-object liveness check (auth.rs): comparing "now" against a
/// stored `metadata.deletionTimestamp` requires converting that RFC3339 string back to a
/// Unix offset so the 60s grace-period leeway can be computed as plain integer arithmetic.
pub fn rfc3339_to_unix_secs(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let time = time.split('.').next()?; // drop fractional seconds if present
    let mut date_parts = date.splitn(3, '-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    let mut time_parts = time.splitn(3, ':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    let days = ymd_to_days(year, month, day);
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

/// Inverse of `days_to_ymd`: proleptic-Gregorian year/month/day to days since 1970-01-01.
/// Howard Hinnant's `days_from_civil` (public domain) — see `days_to_ymd` for the matching
/// forward transform and the shared March-based-year rationale.
fn ymd_to_days(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Shift epoch from 1970-01-01 to 0000-03-01 so that the leap day (Feb 29)
    // falls at the end of each year in the shifted representation, eliminating
    // off-by-one errors when the leap year is not the first year of a 4-year block.
    // Algorithm: Howard Hinnant's civil_from_days (public domain).
    //
    // Days from 0000-03-01 proleptic Gregorian to 1970-01-01:
    //   = 719468
    let z = days + 719468;
    // `era` uses floor division (not `/`, which truncates toward zero) so dates before
    // 0000-03-01 proleptic Gregorian still resolve to the correct 400-year block. Not
    // reachable via the Kubernetes Time/MicroTime wire format (min year is 0001), but
    // keeping the canonical algorithm's negative-z branch avoids a silent trap door.
    let era = if z >= 0 {
        z / 146097
    } else {
        (z - 146096) / 146097
    };
    let doe = z - era * 146097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe + era * 400; // year in proleptic calendar (March-based)
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month of year [0, 11] (March=0 .. February=11)
    let day = doy - (153 * mp + 2) / 5 + 1; // day of month [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // convert to Jan=1..Dec=12
    let year = if month <= 2 { y + 1 } else { y }; // adjust year for Jan/Feb
    (year, month, day)
}

/// Shared helpers for the Sentinel protobuf-decode completeness tests duplicated across every
/// `*_gen_adapter.rs` module: each one builds a message with every field set to a value no
/// zero/empty-elision check in a `gen_*_to_json`/`decode_*_proto_gen` function could mistake for
/// "unset" (see `u7s_sentinel::Sentinel`), decodes it through the real entry point, and asserts
/// every field name shows up somewhere in the resulting JSON. A name that never appears means
/// some function never reads that field from the decoded protobuf struct at all.
#[cfg(test)]
pub(crate) mod sentinel_test_util {
    use std::collections::BTreeSet;

    /// Recursively collects every leaf key path in a JSON value tree, joining nested object
    /// keys with '.'. Arrays contribute their elements' own leaf paths without an index: an
    /// array's length and content depend on how many synthetic elements a sentinel produced,
    /// so indexing would make the expected path set depend on that count instead of just on
    /// which fields exist.
    pub(crate) fn collect_leaf_paths(
        value: &serde_json::Value,
        prefix: &str,
        out: &mut BTreeSet<String>,
    ) {
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

    /// True if `field` appears as a whole path segment somewhere in `leaf_paths` — i.e. it was
    /// decoded at some level, regardless of nesting depth. Segment (not full-path) matching is
    /// deliberate: this only cares whether a field survived decode at all, matching the
    /// historical bug shape of a field dropped entirely from a gen_*_to_json function.
    fn has_field(leaf_paths: &BTreeSet<String>, field: &str) -> bool {
        leaf_paths
            .iter()
            .any(|p| p.split('.').any(|seg| seg == field))
    }

    pub(crate) fn assert_fields_present(leaf_paths: &BTreeSet<String>, expected: &[&str]) {
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

    // -- parse_resource_version --

    /// Explicit resourceVersion: "0" on an update must mean "unconditional write",
    /// the same as an absent resourceVersion — NOT `Some(0)`.
    ///
    /// `Store::put`'s `Some(0)` sentinel means "create-only, key must not exist". If
    /// this function mapped "0" to `Some(0)`, then a client update carrying an existing
    /// node's status with `resourceVersion: "0"` (the real-world pattern used by
    /// sig-scheduling's node-status e2e test to force a write past a possibly-stale
    /// local copy) would be rejected with a spurious 409 AlreadyExists against the node
    /// that plainly already exists.
    #[test]
    fn parse_resource_version_zero_is_unconditional_not_create_only() {
        assert_eq!(
            parse_resource_version(Some("0")).unwrap(),
            None,
            "resourceVersion \"0\" must parse the same as absent (unconditional update), \
             not as Some(0) (create-only) — else updates to existing objects wrongly 409"
        );
        assert_eq!(
            parse_resource_version(Some("0")).unwrap(),
            parse_resource_version(None).unwrap(),
            "\"0\" and absent resourceVersion must produce identical Store::put semantics"
        );
    }

    /// A real (non-zero) resourceVersion still enforces optimistic concurrency.
    #[test]
    fn parse_resource_version_nonzero_is_conditional() {
        assert_eq!(parse_resource_version(Some("42")).unwrap(), Some(42));
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

    /// rfc3339_to_unix_secs must invert secs_to_rfc3339 exactly — the SA-token bound-object
    /// liveness check (auth.rs) parses a stored `deletionTimestamp` this way to compute how
    /// long ago an object was deleted; a wrong offset would make the 60s grace-period leeway
    /// either reject a token too early (breaking graceful pod shutdown) or accept a token
    /// long after it should have been invalidated.
    #[test]
    fn rfc3339_to_unix_secs_round_trips_with_secs_to_rfc3339() {
        for secs in [0i64, 1, 59, 3600, 86_399, 1_704_067_200, 951_782_400] {
            let s = secs_to_rfc3339(secs);
            assert_eq!(
                rfc3339_to_unix_secs(&s),
                Some(secs),
                "round-trip through secs_to_rfc3339({secs}) = {s:?} must recover {secs}"
            );
        }
    }

    /// rfc3339_to_unix_secs must reject strings that don't match the expected shape rather
    /// than panicking or silently returning a wrong value — a malformed or corrupted
    /// deletionTimestamp must not crash the auth path for every request.
    #[test]
    fn rfc3339_to_unix_secs_rejects_malformed_input() {
        assert_eq!(rfc3339_to_unix_secs(""), None);
        assert_eq!(rfc3339_to_unix_secs("not-a-timestamp"), None);
        assert_eq!(rfc3339_to_unix_secs("2024-01-01T00:00:00"), None); // missing 'Z'
    }

    /// secs_to_rfc3339 must render pre-1970 (negative Unix seconds) dates correctly instead
    /// of dropping or corrupting them.
    ///
    /// Lease acquire/renew times and Job/CronJob condition times are legitimately any instant,
    /// including instants before the Unix epoch (e.g. the Go zero-value time.Time{} used by
    /// [sig-node] Lease conformance is year 0001, which is a large negative Unix timestamp).
    /// A naive `secs / 86400` / `secs % 86400` truncates toward zero and lands on the wrong
    /// calendar day for negative `secs` — this test fails if that regression is reintroduced.
    #[test]
    fn secs_to_rfc3339_negative_seconds_render_correct_pre_1970_date() {
        // -1 second is 1969-12-31T23:59:59Z, not 1970-01-01T00:00:00Z (which truncating
        // division toward zero would incorrectly produce).
        assert_eq!(
            secs_to_rfc3339(-1),
            "1969-12-31T23:59:59Z",
            "seconds=-1 must be one second before the epoch, not the epoch itself"
        );
        // Go's time.Time{}.Add(2s) (used by Lease conformance) is 0001-01-01T00:00:02Z,
        // which is -62135596798 as a Unix timestamp.
        assert_eq!(
            secs_to_rfc3339(-62_135_596_798),
            "0001-01-01T00:00:02Z",
            "pre-1970 MicroTime seconds must decode to the real calendar date, not be dropped \
             or wrap around to a nonsensical year"
        );
    }

    /// secs_to_rfc3339 must produce the correct calendar date across all leap-year boundary
    /// cases so that every emitted timestamp (creationTimestamp, lastTransitionTime, token expiry,
    /// table cells) is correct. Before the fix, dates in non-leap years that follow a leap year
    /// within a 4-year block were off by one day: e.g. 2001-09-09 was emitted as 2001-09-10,
    /// corrupting client-side timestamp comparisons and validation.
    #[test]
    fn secs_to_rfc3339_correct_across_leap_year_boundaries_so_emitted_timestamps_are_valid() {
        let cases: &[(&str, i64)] = &[
            // Unix epoch
            ("1970-01-01T00:00:00Z", 0),
            // Normal year mid-date (1970 is not a leap year)
            ("1970-06-15T00:00:00Z", 14_256_000),
            // Leap day: 2000-02-29 (2000 is a 400-yr leap year)
            ("2000-02-29T00:00:00Z", 951_782_400),
            // Mar 1 of a leap year (day after the leap day)
            ("2000-03-01T00:00:00Z", 951_868_800),
            // Jan 1 immediately after a leap year
            ("2001-01-01T00:00:00Z", 978_307_200),
            // The known-failing case: 2001-09-09 was decoded as 2001-09-10 before the fix.
            // Any timestamp emitted after a leap year within a 4-year block was wrong.
            ("2001-09-09T00:00:00Z", 999_993_600),
            // Another post-leap-year date (2001-12-31, last day of the year after 2000)
            ("2001-12-31T00:00:00Z", 1_009_756_800),
            // Leap day in a common-era century year (2024 is a regular leap year)
            ("2024-02-29T00:00:00Z", 1_709_164_800),
            // Mar 1 after 2024 leap day
            ("2024-03-01T00:00:00Z", 1_709_251_200),
            // Jan 1 of the year after 2024 leap year
            ("2025-01-01T00:00:00Z", 1_735_689_600),
            // 2024-01-01 (existing test value, kept for non-regression)
            ("2024-01-01T00:00:00Z", 1_704_067_200),
            // Far-future date: 2100-01-01 (2100 is NOT a leap year — divisible by 100 but not 400)
            ("2100-01-01T00:00:00Z", 4_102_444_800),
        ];
        for &(expected, secs) in cases {
            let got = secs_to_rfc3339(secs);
            assert_eq!(
                got, expected,
                "secs_to_rfc3339({secs}) = {got:?}, want {expected:?} — wrong date corrupts \
                 all apiserver-emitted timestamps (creationTimestamp/lastTransitionTime/token-expiry)"
            );
        }
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

    // -- secs_nanos_to_rfc3339_micro --

    /// secs_nanos_to_rfc3339_micro must produce microsecond precision from nanos.
    ///
    /// MicroTime carries nanoseconds in the proto wire; if nanos are discarded the
    /// Lease renewTime comparison in the conformance test fails because the stored
    /// timestamp has .000000 while the kubelet's value has actual sub-second precision.
    #[test]
    fn secs_nanos_to_rfc3339_micro_includes_nanos_as_microseconds() {
        assert_eq!(
            secs_nanos_to_rfc3339_micro(1_704_067_215, 123_456_000),
            "2024-01-01T00:00:15.123456Z",
            "nanos must be truncated to microseconds and included in the timestamp; \
             if absent, Lease renewTime precision is lost and conformance comparison fails"
        );
    }

    /// Zero nanos must produce .000000 suffix (not be dropped).
    #[test]
    fn secs_nanos_to_rfc3339_micro_zero_nanos_produces_zeros() {
        assert_eq!(
            secs_nanos_to_rfc3339_micro(1_704_067_200, 0),
            "2024-01-01T00:00:00.000000Z",
            "zero nanos must produce .000000 suffix — required by client-go MicroTime codec"
        );
    }

    /// A MicroTime with negative Unix seconds must decode to the correct pre-1970 RFC3339
    /// string, not be dropped (returning None/empty) and not silently truncated.
    ///
    /// [sig-node] Lease conformance sets AcquireTime/RenewTime using Go's zero-value
    /// time.Time{}.Add(2s), which is year 0001 — a large negative Unix timestamp. Dropping
    /// non-positive MicroTime seconds makes leader-election/heartbeat leases look never
    /// acquired, which is exactly the bug this guards against.
    #[test]
    fn secs_nanos_to_rfc3339_micro_negative_seconds_decode_not_drop() {
        assert_eq!(
            secs_nanos_to_rfc3339_micro(-62_135_596_798, 0),
            "0001-01-01T00:00:02.000000Z",
            "negative MicroTime seconds must produce the real pre-1970 timestamp; dropping it \
             makes the Lease look never-acquired"
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

    /// Encode a wire-type-0 (varint) field: bools and int32s in proto2 (e.g.
    /// APIServiceSpec.insecureSkipTLSVerify, .groupPriorityMinimum, .versionPriority).
    fn encode_varint_field(field_number: u64, value: u64) -> Vec<u8> {
        let tag = field_number << 3; // wire type 0
        let mut out = encode_varint(tag);
        out.extend_from_slice(&encode_varint(value));
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

    /// test_pod_create_kubectl_wire_format
    ///
    /// kubectl run nginx --image=nginx sends a proto-encoded Pod in the k8s protobuf envelope
    /// with empty contentType (no field 4 in the Unknown). The Pod proto uses k8s field numbers:
    ///   PodSpec.containers = field 2 (NOT field 3 as was incorrectly assumed)
    ///   PodSpec.restartPolicy = field 3 (NOT field 4)
    ///
    /// With the wrong field numbers, prost tried to decode the restartPolicy string "Always" as
    /// a repeated Container sub-message, hit an invalid wire type in the string bytes, returned
    /// DecodeError, decode_pod_proto returned None, extract_body returned raw proto bytes, and
    /// Object::from_bytes failed with "invalid JSON: expected value at line 1 column 1".
    /// This caused ~175 pod creation failures in sonobuoy e2e.
    #[test]
    fn test_pod_create_kubectl_wire_format() {
        // Build ObjectMeta { name: "nginx", namespace: "default" }
        let obj_meta = build_object_meta(b"nginx", Some(b"default"));

        // Build Container { name: "nginx", image: "nginx:latest" }
        let mut container = encode_ld(1, b"nginx"); // name
        container.extend_from_slice(&encode_ld(2, b"nginx:latest")); // image

        // PodSpec { containers (field 2) = [container], restartPolicy (field 3) = "Always" }
        let mut pod_spec = encode_ld(2, &container); // containers = field 2 in k8s proto
        pod_spec.extend_from_slice(&encode_ld(3, b"Always")); // restartPolicy = field 3

        // Pod { metadata (field 1), spec (field 2) }
        let mut pod_proto = encode_ld(1, &obj_meta); // metadata
        pod_proto.extend_from_slice(&encode_ld(2, &pod_spec)); // spec

        // kubectl omits contentType field 4 for core types
        let body = build_kubectl_proto_body(b"v1", b"Pod", &pod_proto, None);
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");
        let json: serde_json::Value = serde_json::from_slice(&decoded).expect(
            "extract_body must produce valid JSON for a kubectl pod proto — \
             before the fix, PodSpec used wrong field numbers (containers at field 3 instead \
             of 2, restartPolicy at field 4 instead of 3), causing decode_pod_proto to return \
             None when restartPolicy 'Always' was misinterpreted as Container bytes, \
             triggering 'invalid JSON' on all Pod creations (sonobuoy: ~175 failures)",
        );

        assert_eq!(json["kind"], "Pod", "kind must be Pod");
        assert_eq!(json["apiVersion"], "v1", "apiVersion must be v1");
        assert_eq!(
            json["metadata"]["name"], "nginx",
            "name must survive proto decode"
        );
        assert_eq!(
            json["metadata"]["namespace"], "default",
            "namespace must survive proto decode"
        );
        assert_eq!(
            json["spec"]["restartPolicy"], "Always",
            "restartPolicy must be decoded from field 3 in PodSpec"
        );
        let containers = json["spec"]["containers"]
            .as_array()
            .expect("spec.containers must be an array");
        assert_eq!(containers.len(), 1, "one container must be decoded");
        assert_eq!(
            containers[0]["name"], "nginx",
            "container name must survive"
        );
        assert_eq!(
            containers[0]["image"], "nginx:latest",
            "container image must survive"
        );
    }

    /// test_extract_body_kind_mismatch_rejects_json_fallback
    ///
    /// When the proto envelope declares kind="Foo" but the raw JSON body contains kind="Secret",
    /// extract_body must return the original proto bytes (reject), not the mismatched JSON.
    ///
    /// This prevents a spoofing vector where a client crafts a proto envelope whose TypeMeta says
    /// one kind but whose JSON payload claims another. Without this check, the JSON would be
    /// accepted and the wrong kind would be persisted under the Foo resource endpoint.
    #[test]
    fn test_extract_body_kind_mismatch_rejects_json_fallback() {
        // Inner JSON claims kind="Secret" but the envelope says kind="Foo"
        let inner_json = br#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"tricky"}}"#;

        // No contentType in envelope (empty), so we fall through to the JSON fallback path
        let body = build_kubectl_proto_body(b"v1", b"Foo", inner_json, None);
        let bytes = Bytes::from(body.clone());

        let result = extract_body(&bytes, "application/vnd.kubernetes.protobuf");
        // Must return the original proto bytes, not the inner JSON
        assert_eq!(
            result.as_ref(),
            bytes.as_ref(),
            "proto envelope with kind='Foo' but JSON body kind='Secret' must be rejected: \
             returning original bytes prevents the mismatched JSON from being stored as Foo"
        );

        // Confirm the returned bytes are NOT the inner JSON
        assert!(
            serde_json::from_slice::<serde_json::Value>(&result).is_err()
                || serde_json::from_slice::<serde_json::Value>(&result)
                    .map(|v| v["kind"] != "Secret")
                    .unwrap_or(true),
            "rejected body must not be the mismatched Secret JSON"
        );
    }

    /// test_extract_body_kind_match_allows_json_fallback
    ///
    /// When the proto envelope kind and the JSON body kind match, the JSON fallback path must
    /// still work correctly (non-core types send JSON with empty contentType and matching kind).
    #[test]
    fn test_extract_body_kind_match_allows_json_fallback() {
        let inner_json =
            br#"{"apiVersion":"example.com/v1","kind":"Widget","metadata":{"name":"w1"}}"#;
        let body = build_kubectl_proto_body(b"example.com/v1", b"Widget", inner_json, None);
        let bytes = Bytes::from(body);

        let result = extract_body(&bytes, "application/vnd.kubernetes.protobuf");
        let json: serde_json::Value =
            serde_json::from_slice(&result).expect("matching kind must allow JSON fallback");
        assert_eq!(
            json["kind"], "Widget",
            "JSON with matching kind must pass through the fallback path"
        );
    }

    /// test_crd_create_proto_envelope_json_body
    ///
    /// kubectl create -f crd.yaml with Content-Type: application/vnd.kubernetes.protobuf sends
    /// a k8s proto envelope with contentType="application/json" and the CRD JSON as raw bytes.
    /// kubectl does this because CustomResourceDefinition is not a core type — it has no
    /// registered proto codec in client-go, so it falls back to JSON-inside-proto-envelope.
    ///
    /// extract_body must return the inner JSON unchanged via the contentType="application/json"
    /// path. Previously there was no test for this path with CRDs, so the sonobuoy failures
    /// (~18 cases with "invalid JSON") were invisible until e2e.
    #[test]
    fn test_crd_create_proto_envelope_json_body() {
        let crd_json = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "spec": {
                "group": "example.com",
                "names": { "kind": "Widget", "plural": "widgets", "singular": "widget" },
                "scope": "Namespaced",
                "versions": [{ "name": "v1", "served": true, "storage": true, "schema": {
                    "openAPIV3Schema": { "type": "object" }
                }}]
            }
        });
        let crd_json_bytes = serde_json::to_vec(&crd_json).unwrap();

        // kubectl sends CRDs as JSON inside the protobuf envelope with contentType=application/json
        let body = build_kubectl_proto_body(
            b"apiextensions.k8s.io/v1",
            b"CustomResourceDefinition",
            &crd_json_bytes,
            Some(b"application/json"),
        );
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");
        let json: serde_json::Value = serde_json::from_slice(&decoded).expect(
            "extract_body must return the inner JSON for CRD proto envelope — \
             CRD has no proto codec so kubectl wraps JSON in the proto envelope with \
             contentType=application/json; extract_body must return it via the \
             env.content_type == 'application/json' path",
        );

        assert_eq!(json["kind"], "CustomResourceDefinition");
        assert_eq!(json["apiVersion"], "apiextensions.k8s.io/v1");
        assert_eq!(json["metadata"]["name"], "widgets.example.com");
        assert_eq!(json["spec"]["group"], "example.com");
    }

    /// test_storageclass_create_kubectl_wire_format
    ///
    /// kubectl create storageclass fast-ssd --provisioner=kubernetes.io/no-provisioner sends:
    ///   Content-Type: application/vnd.kubernetes.protobuf
    ///   Body: magic + Unknown{ TypeMeta{storage.k8s.io/v1/StorageClass}, raw=proto(StorageClass), contentType="" (absent) }
    ///
    /// extract_body must produce valid JSON from the proto-encoded body. Previously,
    /// decode_core_proto_by_kind returned None for "StorageClass" because no decoder was registered.
    /// extract_body then returned the original proto bytes, Object::from_bytes failed with
    /// "invalid JSON: expected value at line 1 column 1", and the apiserver returned HTTP 400
    /// causing e2e StorageClasses lifecycle tests to fail.
    ///
    /// This test fails if the StorageClass decoder is removed from decode_core_proto_by_kind.
    #[test]
    fn test_storageclass_create_kubectl_wire_format() {
        // Build ObjectMeta { name: "fast-ssd" }
        let obj_meta = build_object_meta(b"fast-ssd", None);

        // StorageClass { metadata (field 1) = ObjectMeta }
        let storageclass_proto = encode_ld(1, &obj_meta);

        // kubectl sends with empty contentType (absent field 4) — native proto encoding
        let body = build_kubectl_proto_body(
            b"storage.k8s.io/v1",
            b"StorageClass",
            &storageclass_proto,
            None,
        );
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");

        // The key assertion: response must be non-empty valid JSON.
        // If the StorageClass decoder is removed, extract_body returns the raw proto bytes,
        // serde_json::from_slice fails with "expected value at line 1 column 1", and the
        // handler returns HTTP 400 instead of HTTP 201.
        assert!(
            !decoded.is_empty(),
            "extract_body must NOT return empty bytes for proto-encoded StorageClass — \
             empty bytes cause Object::from_bytes to fail with 'invalid JSON: expected value \
             at line 1 column 1', making the apiserver return HTTP 400 instead of 201"
        );

        let json: serde_json::Value = serde_json::from_slice(&decoded).expect(
            "extract_body must produce valid JSON for proto-encoded StorageClass — \
             before the fix, decode_core_proto_by_kind returned None for 'StorageClass', \
             extract_body returned raw proto bytes, and the handler returned HTTP 400 \
             'invalid JSON: expected value at line 1 column 1'",
        );

        assert_eq!(
            json["kind"], "StorageClass",
            "kind must be StorageClass so the handler routes and stores the object correctly"
        );
        assert_eq!(json["apiVersion"], "storage.k8s.io/v1");
        assert_eq!(
            json["metadata"]["name"], "fast-ssd",
            "name must survive proto decode — used for store key and uniqueness check"
        );
    }

    /// test_resourcequota_create_kubectl_wire_format
    ///
    /// kubectl create quota compute-quota --hard=pods=10 sends proto-encoded ResourceQuota.
    /// Without a decoder, the server returns HTTP 400 causing e2e ResourceQuota tests to fail.
    ///
    /// This test fails if the ResourceQuota decoder is removed from decode_core_proto_by_kind.
    #[test]
    fn test_resourcequota_create_kubectl_wire_format() {
        // Build ObjectMeta { name: "compute-quota", namespace: "default" }
        let obj_meta = build_object_meta(b"compute-quota", Some(b"default"));

        // ResourceQuota { metadata (field 1) = ObjectMeta }
        let resourcequota_proto = encode_ld(1, &obj_meta);

        let body = build_kubectl_proto_body(b"v1", b"ResourceQuota", &resourcequota_proto, None);
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");

        assert!(
            !decoded.is_empty(),
            "extract_body must NOT return empty bytes for proto-encoded ResourceQuota"
        );

        let json: serde_json::Value = serde_json::from_slice(&decoded).expect(
            "extract_body must produce valid JSON for proto-encoded ResourceQuota — \
             without the decoder, proto creates return HTTP 400 'invalid JSON'",
        );

        assert_eq!(json["kind"], "ResourceQuota");
        assert_eq!(json["apiVersion"], "v1");
        assert_eq!(json["metadata"]["name"], "compute-quota");
        assert_eq!(json["metadata"]["namespace"], "default");
    }

    /// test_limitrange_create_kubectl_wire_format
    ///
    /// kubectl create limitrange limits sends proto-encoded LimitRange.
    /// Without a decoder, the server returns HTTP 400 causing e2e LimitRange tests to fail.
    ///
    /// This test fails if the LimitRange decoder is removed from decode_core_proto_by_kind.
    #[test]
    fn test_limitrange_create_kubectl_wire_format() {
        let obj_meta = build_object_meta(b"limits", Some(b"default"));
        let limitrange_proto = encode_ld(1, &obj_meta);
        let body = build_kubectl_proto_body(b"v1", b"LimitRange", &limitrange_proto, None);
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");

        assert!(
            !decoded.is_empty(),
            "extract_body must NOT return empty bytes for proto-encoded LimitRange"
        );

        let json: serde_json::Value = serde_json::from_slice(&decoded)
            .expect("extract_body must produce valid JSON for proto-encoded LimitRange");

        assert_eq!(json["kind"], "LimitRange");
        assert_eq!(json["apiVersion"], "v1");
        assert_eq!(json["metadata"]["name"], "limits");
    }

    /// test_poddisruptionbudget_create_kubectl_wire_format
    ///
    /// kubectl create pdb my-pdb sends proto-encoded PodDisruptionBudget.
    /// Without a decoder, the server returns HTTP 400 causing e2e DisruptionController tests to fail.
    ///
    /// This test fails if the PodDisruptionBudget decoder is removed from decode_core_proto_by_kind.
    #[test]
    fn test_poddisruptionbudget_create_kubectl_wire_format() {
        let obj_meta = build_object_meta(b"my-pdb", Some(b"default"));
        let pdb_proto = encode_ld(1, &obj_meta);
        let body = build_kubectl_proto_body(b"policy/v1", b"PodDisruptionBudget", &pdb_proto, None);
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");

        assert!(
            !decoded.is_empty(),
            "extract_body must NOT return empty bytes for proto-encoded PodDisruptionBudget"
        );

        let json: serde_json::Value = serde_json::from_slice(&decoded).expect(
            "extract_body must produce valid JSON for proto-encoded PodDisruptionBudget — \
             without the decoder, proto creates return HTTP 400, causing DisruptionController \
             e2e tests to fail",
        );

        assert_eq!(json["kind"], "PodDisruptionBudget");
        assert_eq!(json["apiVersion"], "policy/v1");
        assert_eq!(json["metadata"]["name"], "my-pdb");
    }

    /// test_apiservice_create_kubectl_wire_format
    ///
    /// The aggregator's client-go clientset (used by the sig-api-machinery "1.17 Sample API
    /// Server" conformance test, and any real client registering an APIService) sends:
    ///   Content-Type: application/vnd.kubernetes.protobuf
    ///   Body: magic + Unknown{ TypeMeta{apiregistration.k8s.io/v1/APIService},
    ///                          raw=proto(APIService), contentType="" (absent) }
    ///
    /// Before decode_proto_by_kind_and_version registered "APIService", extract_body fell
    /// through every branch (raw bytes are proto, not JSON, so the '{' fallback doesn't match
    /// either) and returned the original magic-prefixed bytes unchanged. The generic create
    /// handler then tried to serde_json::from_slice those bytes and failed with exactly
    /// "invalid JSON: expected value at line 1 column 1", the observed conformance failure
    /// (POST /apis/apiregistration.k8s.io/v1/apiservices -> 400).
    #[test]
    fn test_apiservice_create_kubectl_wire_format() {
        let obj_meta = build_object_meta(b"v1alpha1.wardle.example.com", None);

        let mut service_ref = encode_ld(1, b"wardle"); // ServiceReference.namespace = field 1
        service_ref.extend_from_slice(&encode_ld(2, b"api")); // .name = field 2
        service_ref.extend_from_slice(&encode_varint_field(3, 443)); // .port = field 3

        let mut spec_proto = encode_ld(1, &service_ref); // APIServiceSpec.service = field 1
        spec_proto.extend_from_slice(&encode_ld(2, b"wardle.example.com")); // .group = field 2
        spec_proto.extend_from_slice(&encode_ld(3, b"v1alpha1")); // .version = field 3
        spec_proto.extend_from_slice(&encode_varint_field(4, 1)); // .insecureSkipTLSVerify = field 4
        spec_proto.extend_from_slice(&encode_varint_field(7, 1000)); // .groupPriorityMinimum = field 7
        spec_proto.extend_from_slice(&encode_varint_field(8, 15)); // .versionPriority = field 8

        let mut apiservice_proto = encode_ld(1, &obj_meta); // APIService.metadata = field 1
        apiservice_proto.extend_from_slice(&encode_ld(2, &spec_proto)); // .spec = field 2

        // client-go omits contentType (field 4) for types with a registered proto codec.
        let body = build_kubectl_proto_body(
            b"apiregistration.k8s.io/v1",
            b"APIService",
            &apiservice_proto,
            None,
        );
        let bytes = Bytes::from(body);

        let decoded = extract_body(&bytes, "application/vnd.kubernetes.protobuf");

        assert!(
            !decoded.is_empty(),
            "extract_body must NOT return empty bytes for proto-encoded APIService"
        );

        let json: serde_json::Value = serde_json::from_slice(&decoded).expect(
            "extract_body must produce valid JSON for a proto-encoded APIService — before the \
             fix, kind=\"APIService\" had no registered decoder, extract_body returned the raw \
             magic-prefixed envelope, and the handler returned HTTP 400 'invalid JSON: expected \
             value at line 1 column 1', blocking the sig-api-machinery aggregator conformance test",
        );

        assert_eq!(json["kind"], "APIService");
        assert_eq!(json["apiVersion"], "apiregistration.k8s.io/v1");
        assert_eq!(
            json["metadata"]["name"], "v1alpha1.wardle.example.com",
            "name must survive proto decode — apiregistration's registry keys off this name"
        );
        assert_eq!(json["spec"]["service"]["namespace"], "wardle");
        assert_eq!(json["spec"]["service"]["name"], "api");
        assert_eq!(json["spec"]["service"]["port"], 443);
        assert_eq!(json["spec"]["group"], "wardle.example.com");
        assert_eq!(json["spec"]["version"], "v1alpha1");
        assert_eq!(
            json["spec"]["groupPriorityMinimum"], 1000,
            "groupPriorityMinimum must survive: the aggregator uses it to order competing groups"
        );
        assert_eq!(json["spec"]["versionPriority"], 15);
    }
}
