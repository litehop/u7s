//! resource.k8s.io/v1 DeviceTaintRule write-path rules (upstream
//! `ValidateDeviceTaintRule` and the `deviceTaintRuleStrategy` update hooks).
//!
//! A rule taints every device its selector matches, and the DRA scheduler/eviction logic
//! trusts the taint verbatim — so a malformed key or an unknown effect must be rejected at
//! write time rather than silently treated as "no taint" by every consumer.

use serde_json::Value;

use super::certificates::{is_dns1123_label, is_dns1123_subdomain};

const VALID_EFFECTS: [&str; 3] = ["None", "NoSchedule", "NoExecute"];

fn is_name_part(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

/// Upstream `ValidateLabelName` (a qualified name: optional DNS-subdomain prefix + `/` + name).
fn is_label_name(s: &str) -> bool {
    match s.split_once('/') {
        Some((prefix, name)) => {
            prefix.len() <= 253 && is_dns1123_subdomain(prefix) && is_name_part(name)
        }
        None => is_name_part(s),
    }
}

fn is_label_value(s: &str) -> bool {
    s.is_empty() || is_name_part(s)
}

fn invalid(path: &str, value: &str, msg: &str) -> String {
    format!("{path}: Invalid value: \"{value}\": {msg}")
}

pub(crate) fn validate_device_taint_rule(obj: &Value) -> Result<(), String> {
    let taint = &obj["spec"]["taint"];
    let key = taint["key"].as_str().unwrap_or("");
    if key.is_empty() {
        return Err("spec.taint.key: Required value".to_string());
    }
    if !is_label_name(key) {
        return Err(invalid(
            "spec.taint.key",
            key,
            "must be a valid label name (optional DNS-subdomain prefix, '/', then at most 63 alphanumerics, '-', '_' or '.')",
        ));
    }
    if let Some(value) = taint["value"].as_str() {
        if !is_label_value(value) {
            return Err(invalid(
                "spec.taint.value",
                value,
                "must be a valid label value",
            ));
        }
    }
    match taint["effect"].as_str().unwrap_or("") {
        "" => return Err("spec.taint.effect: Required value".to_string()),
        e if !VALID_EFFECTS.contains(&e) => {
            return Err(format!(
                "spec.taint.effect: Unsupported value: \"{e}\": supported values: \"None\", \"NoExecute\", \"NoSchedule\""
            ))
        }
        _ => {}
    }

    let selector = &obj["spec"]["deviceSelector"];
    if let Some(driver) = selector["driver"].as_str() {
        if driver.len() > 63 || !is_dns1123_subdomain(driver) {
            return Err(invalid(
                "spec.deviceSelector.driver",
                driver,
                "must be a DNS subdomain of at most 63 characters",
            ));
        }
    }
    if let Some(pool) = selector["pool"].as_str() {
        if pool.is_empty() {
            return Err("spec.deviceSelector.pool: Required value".to_string());
        }
        if pool.len() > 253 || !pool.split('/').all(is_dns1123_subdomain) {
            return Err(invalid(
                "spec.deviceSelector.pool",
                pool,
                "must be '/'-separated DNS subdomains of at most 253 characters in total",
            ));
        }
    }
    if let Some(device) = selector["device"].as_str() {
        if !is_dns1123_label(device) {
            return Err(invalid(
                "spec.deviceSelector.device",
                device,
                "must be a DNS label",
            ));
        }
    }
    Ok(())
}

/// Upstream `deviceTaintRuleStrategy.PrepareForUpdate`: `taint.timeAdded` tracks when the
/// *effect* was set (toleration durations are computed from it), so it is refreshed when the
/// effect changes and the client did not move it itself; `metadata.generation` is
/// server-owned and advances only when `spec` changes.
pub(crate) fn prepare_device_taint_rule_update(old: &Value, new: &mut Value) {
    if new["spec"]["taint"]["effect"] != old["spec"]["taint"]["effect"]
        && new["spec"]["taint"]["timeAdded"] == old["spec"]["taint"]["timeAdded"]
    {
        new["spec"]["taint"]["timeAdded"] = Value::String(crate::util::utc_now_rfc3339());
    }
    let stored = old["metadata"]["generation"].as_i64().unwrap_or(1);
    let generation = if new["spec"] != old["spec"] {
        stored.saturating_add(1)
    } else {
        stored
    };
    new["metadata"]["generation"] = Value::from(generation);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(taint: Value, selector: Value) -> Value {
        json!({"metadata": {"name": "r", "generation": 1}, "spec": {"taint": taint, "deviceSelector": selector}})
    }

    fn ok_taint() -> Value {
        json!({"key": "example.com/unhealthy", "effect": "NoSchedule"})
    }

    #[test]
    fn conformance_shape_with_empty_selector_is_accepted() {
        let r = json!({"spec": {"taint": {"key": "testing", "effect": "None"}}});
        assert_eq!(validate_device_taint_rule(&r), Ok(()));
    }

    #[test]
    fn missing_or_unknown_effect_is_rejected_because_consumers_treat_unknown_as_none() {
        let missing = rule(json!({"key": "k"}), json!({}));
        assert!(validate_device_taint_rule(&missing)
            .unwrap_err()
            .starts_with("spec.taint.effect: Required"));
        let unknown = rule(json!({"key": "k", "effect": "PreferNoSchedule"}), json!({}));
        assert!(validate_device_taint_rule(&unknown)
            .unwrap_err()
            .contains("Unsupported value"));
    }

    #[test]
    fn taint_key_must_be_present_and_a_valid_label_name() {
        for key in [
            "",
            "-bad",
            "a/b/c",
            "UPPER.example.com/x/y",
            &"x".repeat(64),
        ] {
            let r = rule(json!({"key": key, "effect": "NoExecute"}), json!({}));
            assert!(
                validate_device_taint_rule(&r).is_err(),
                "key {key:?} must be rejected"
            );
        }
        let r = rule(json!({"effect": "NoExecute"}), json!({}));
        assert!(validate_device_taint_rule(&r).is_err(), "missing taint key");
    }

    #[test]
    fn taint_value_must_be_a_valid_label_value() {
        let r = rule(
            json!({"key": "k", "value": "has space", "effect": "NoExecute"}),
            json!({}),
        );
        assert!(validate_device_taint_rule(&r)
            .unwrap_err()
            .starts_with("spec.taint.value"));
    }

    #[test]
    fn selector_names_are_validated_so_a_typo_cannot_silently_match_nothing() {
        let bad_driver = rule(ok_taint(), json!({"driver": "Not_DNS"}));
        assert!(validate_device_taint_rule(&bad_driver).is_err());
        let empty_pool = rule(ok_taint(), json!({"pool": ""}));
        assert!(validate_device_taint_rule(&empty_pool).is_err());
        let bad_pool = rule(ok_taint(), json!({"pool": "node-1//x"}));
        assert!(validate_device_taint_rule(&bad_pool).is_err());
        let bad_device = rule(ok_taint(), json!({"device": "gpu.0"}));
        assert!(validate_device_taint_rule(&bad_device).is_err());
        let good = rule(
            ok_taint(),
            json!({"driver": "gpu.example.com", "pool": "node-1/pool.a", "device": "gpu-0"}),
        );
        assert_eq!(validate_device_taint_rule(&good), Ok(()));
    }

    #[test]
    fn shared_validate_resource_rejects_bad_rule_so_every_write_path_is_covered() {
        let bad = rule(json!({"key": "k", "effect": "Bogus"}), json!({}));
        assert!(
            super::super::defaults::validate_resource("resource.k8s.io", "devicetaintrules", &bad)
                .is_err(),
            "create/PUT/PATCH all converge on validate_resource"
        );
    }

    #[test]
    fn create_defaults_stamp_generation_one_for_observers() {
        let mut r = json!({"metadata": {"name": "r"}, "spec": {"taint": ok_taint()}});
        super::super::defaults::apply_defaults("resource.k8s.io", "devicetaintrules", &mut r);
        assert_eq!(r["metadata"]["generation"], 1);
    }

    #[test]
    fn effect_change_refreshes_time_added_so_toleration_durations_restart() {
        let mut old = rule(ok_taint(), json!({}));
        old["spec"]["taint"]["timeAdded"] = json!("2020-01-01T00:00:00Z");
        let mut new = old.clone();
        new["spec"]["taint"]["effect"] = json!("NoExecute");
        prepare_device_taint_rule_update(&old, &mut new);
        assert_ne!(
            new["spec"]["taint"]["timeAdded"],
            json!("2020-01-01T00:00:00Z")
        );
    }

    #[test]
    fn client_supplied_time_added_survives_an_effect_change() {
        let mut old = rule(ok_taint(), json!({}));
        old["spec"]["taint"]["timeAdded"] = json!("2020-01-01T00:00:00Z");
        let mut new = old.clone();
        new["spec"]["taint"]["effect"] = json!("NoExecute");
        new["spec"]["taint"]["timeAdded"] = json!("2021-01-01T00:00:00Z");
        prepare_device_taint_rule_update(&old, &mut new);
        assert_eq!(
            new["spec"]["taint"]["timeAdded"],
            json!("2021-01-01T00:00:00Z")
        );
    }

    #[test]
    fn time_added_untouched_when_effect_unchanged() {
        let old = rule(ok_taint(), json!({}));
        let mut new = old.clone();
        new["spec"]["taint"]["value"] = json!("v");
        prepare_device_taint_rule_update(&old, &mut new);
        assert!(new["spec"]["taint"]["timeAdded"].is_null());
    }

    #[test]
    fn generation_advances_only_on_spec_change_and_ignores_client_value() {
        let old = rule(ok_taint(), json!({}));
        let mut spec_changed = old.clone();
        spec_changed["spec"]["taint"]["effect"] = json!("NoExecute");
        spec_changed["metadata"]["generation"] = json!(99);
        prepare_device_taint_rule_update(&old, &mut spec_changed);
        assert_eq!(spec_changed["metadata"]["generation"], 2);

        let mut label_only = old.clone();
        label_only["metadata"]["labels"] = json!({"a": "b"});
        label_only["metadata"]["generation"] = json!(99);
        prepare_device_taint_rule_update(&old, &mut label_only);
        assert_eq!(
            label_only["metadata"]["generation"], 1,
            "a metadata-only update must not look like a spec change to observers"
        );
    }
}
