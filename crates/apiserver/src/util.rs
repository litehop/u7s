use bytes::Bytes;

use crate::proto;

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

    /// utc_now_rfc3339 must return a plausible timestamp (after 2024-01-01).
    #[test]
    fn utc_now_is_recent() {
        let now = utc_now_rfc3339();
        // Must start with "20" for any year 2000+.
        assert!(now.starts_with("20"), "unexpected prefix: {now}");
        // Must be after 2024.
        assert!(now.as_str() >= "2024-01-01T00:00:00Z", "implausibly old: {now}");
    }
}
