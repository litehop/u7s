use serde_json::{json, Value};

use super::*;

const V4: IpFamily = IpFamily::V4;
const V6: IpFamily = IpFamily::V6;

fn init(configured: &[IpFamily], old: Option<Value>, spec: Value) -> Result<Value, String> {
    let mut spec = spec;
    init_ip_family_fields(configured, old.as_ref(), &mut spec, "s")
        .map(|()| spec)
        .map_err(|e| e.1.message)
}

fn dual_old(policy: &str) -> Value {
    json!({
        "type": "ClusterIP",
        "ipFamilyPolicy": policy,
        "ipFamilies": ["IPv4", "IPv6"],
        "clusterIP": "10.96.0.5",
        "clusterIPs": ["10.96.0.5", "fd00:96::5"],
    })
}

#[test]
fn single_stack_default_picks_the_primary_family_even_on_a_dual_stack_cluster() {
    let out = init(&[V6, V4], None, json!({})).unwrap();
    assert_eq!(out["ipFamilyPolicy"], "SingleStack");
    assert_eq!(
        out["ipFamilies"],
        json!(["IPv6"]),
        "an unconfigured Service must take the cluster's primary family, or every existing \
         manifest silently becomes dual-stack"
    );
}

#[test]
fn prefer_dual_stack_gets_both_families_in_cluster_order() {
    for (cluster, want) in [
        ([V4, V6], json!(["IPv4", "IPv6"])),
        ([V6, V4], json!(["IPv6", "IPv4"])),
    ] {
        let out = init(&cluster, None, json!({"ipFamilyPolicy": "PreferDualStack"})).unwrap();
        assert_eq!(
            out["ipFamilies"], want,
            "families follow the primary family"
        );
    }
}

#[test]
fn prefer_dual_stack_falls_back_to_one_family_on_a_single_stack_cluster() {
    let out = init(&[V4], None, json!({"ipFamilyPolicy": "PreferDualStack"})).unwrap();
    assert_eq!(out["ipFamilies"], json!(["IPv4"]));
}

#[test]
fn prefer_dual_stack_keeps_an_explicit_first_family_and_appends_the_other() {
    let out = init(
        &[V4, V6],
        None,
        json!({"ipFamilyPolicy": "PreferDualStack", "ipFamilies": ["IPv6"]}),
    )
    .unwrap();
    assert_eq!(out["ipFamilies"], json!(["IPv6", "IPv4"]));
}

#[test]
fn require_dual_stack_on_a_single_stack_cluster_is_rejected_with_the_upstream_text() {
    let err = init(&[V4], None, json!({"ipFamilyPolicy": "RequireDualStack"})).unwrap_err();
    assert_eq!(
        err,
        "Service \"s\" is invalid: spec.ipFamilyPolicy: Invalid value: \"RequireDualStack\": \
         this cluster is not configured for dual-stack services"
    );
}

#[test]
fn a_family_the_cluster_lacks_is_rejected_with_the_upstream_text() {
    let err = init(&[V4], None, json!({"ipFamilies": ["IPv6"]})).unwrap_err();
    assert_eq!(
        err,
        "Service \"s\" is invalid: spec.ipFamilies[0]: Invalid value: \"IPv6\": not configured on this cluster"
    );
}

#[test]
fn an_explicit_cluster_ip_of_an_unconfigured_family_names_the_ip() {
    let err = init(&[V4], None, json!({"clusterIP": "fd00::5"})).unwrap_err();
    assert_eq!(
        err,
        "Service \"s\" is invalid: spec.clusterIPs[0]: Invalid value: []string{\"fd00::5\"}: \
         IPv6 is not configured on this cluster"
    );
}

#[test]
fn families_are_inferred_from_explicit_cluster_ips_in_their_order() {
    let out = init(
        &[V4, V6],
        None,
        json!({"ipFamilyPolicy": "RequireDualStack", "clusterIPs": ["fd00:96::7", "10.96.0.7"]}),
    )
    .unwrap();
    assert_eq!(out["ipFamilies"], json!(["IPv6", "IPv4"]));
    assert_eq!(
        out["clusterIP"], "fd00:96::7",
        "clusterIP mirrors clusterIPs[0]"
    );
}

#[test]
fn single_stack_with_two_families_is_rejected() {
    let err = init(
        &[V4, V6],
        None,
        json!({"ipFamilyPolicy": "SingleStack", "ipFamilies": ["IPv4", "IPv6"]}),
    )
    .unwrap_err();
    assert!(
        err.contains(
            "spec.ipFamilyPolicy: Invalid value: \"SingleStack\": must be 'RequireDualStack' \
             or 'PreferDualStack' when multiple IP families are specified"
        ),
        "{err}"
    );
}

#[test]
fn family_and_cluster_ip_mismatch_is_rejected() {
    let err = init(
        &[V4, V6],
        None,
        json!({"ipFamilies": ["IPv4"], "clusterIP": "fd00::5"}),
    )
    .unwrap_err();
    assert!(
        err.contains("expected an IPv4 value as indicated by `ipFamilies[0]`"),
        "{err}"
    );
}

#[test]
fn malformed_and_non_canonical_cluster_ips_are_rejected() {
    let err = init(&[V4], None, json!({"clusterIP": "10.96.0"})).unwrap_err();
    assert!(
        err.contains("must be a valid IP address, (e.g. 10.9.8.7 or 2001:db8::ffff)"),
        "{err}"
    );
    let err = init(&[V4, V6], None, json!({"clusterIP": "FD00:0:0::5"})).unwrap_err();
    assert!(
        err.contains("must be in canonical form (\"fd00::5\")"),
        "{err}"
    );
}

#[test]
fn headless_with_selector_is_single_stack_on_the_primary_family() {
    let out = init(
        &[V4, V6],
        None,
        json!({"clusterIP": "None", "selector": {"a": "b"}}),
    )
    .unwrap();
    assert_eq!(out["ipFamilyPolicy"], "SingleStack");
    assert_eq!(out["ipFamilies"], json!(["IPv4"]));
    assert_eq!(out["clusterIPs"], json!(["None"]));
}

#[test]
fn selectorless_headless_defaults_to_both_families_like_upstream() {
    let out = init(&[V4, V6], None, json!({"clusterIP": "None"})).unwrap();
    assert_eq!(out["ipFamilyPolicy"], "RequireDualStack");
    assert_eq!(out["ipFamilies"], json!(["IPv4", "IPv6"]));
}

#[test]
fn a_prefer_dual_stack_service_is_not_rewritten_when_the_cluster_becomes_dual_stack() {
    let old = json!({
        "type": "ClusterIP", "ipFamilyPolicy": "PreferDualStack",
        "ipFamilies": ["IPv4"], "clusterIP": "10.96.0.5", "clusterIPs": ["10.96.0.5"],
    });
    let out = init(&[V4, V6], Some(old.clone()), old.clone()).unwrap();
    assert_eq!(
        out["ipFamilies"],
        json!(["IPv4"]),
        "upstream never auto-upgrades an untouched PreferDualStack Service when the \
         cluster gains a family; doing so would hand out a secondary IP nobody asked for"
    );
    assert!(unallocated_slots(&out).is_empty());
}

#[test]
fn raising_policy_on_a_single_stack_service_adds_the_secondary_family_slot() {
    let old = json!({
        "type": "ClusterIP", "ipFamilyPolicy": "SingleStack",
        "ipFamilies": ["IPv4"], "clusterIP": "10.96.0.5", "clusterIPs": ["10.96.0.5"],
    });
    let mut new = old.clone();
    new["ipFamilyPolicy"] = json!("RequireDualStack");
    let out = init(&[V4, V6], Some(old), new).unwrap();
    assert_eq!(out["ipFamilies"], json!(["IPv4", "IPv6"]));
    assert_eq!(unallocated_slots(&out), vec![(1, V6)]);
}

#[test]
fn an_update_omitting_allocated_addresses_keeps_them_all() {
    let old = dual_old("RequireDualStack");
    let out = init(
        &[V4, V6],
        Some(old),
        json!({"type": "ClusterIP", "ipFamilyPolicy": "RequireDualStack"}),
    )
    .unwrap();
    assert_eq!(out["clusterIPs"], json!(["10.96.0.5", "fd00:96::5"]));
    assert!(
        unallocated_slots(&out).is_empty(),
        "a PUT that leaves out clusterIPs must not re-allocate and churn the VIPs"
    );
}

#[test]
fn downgrade_to_single_stack_trims_the_secondary_without_further_edits() {
    let old = dual_old("RequireDualStack");
    let mut new = old.clone();
    new["ipFamilyPolicy"] = json!("SingleStack");
    let out = init(&[V4, V6], Some(old.clone()), new).unwrap();
    assert_eq!(out["ipFamilies"], json!(["IPv4"]));
    assert_eq!(out["clusterIPs"], json!(["10.96.0.5"]));
    validate_ip_fields_update(&old, &out, "s").expect("a clean downgrade is allowed");
}

#[test]
fn releasing_the_secondary_without_single_stack_is_rejected() {
    let old = dual_old("RequireDualStack");
    let mut new = old.clone();
    new["clusterIPs"] = json!(["10.96.0.5"]);
    new["clusterIP"] = json!("10.96.0.5");
    let err = init(&[V4, V6], Some(old), new).unwrap_err();
    assert!(
        err.contains("must be 'SingleStack' to release the secondary cluster IP"),
        "{err}"
    );
}

#[test]
fn the_primary_cluster_ip_and_family_are_immutable() {
    let old = dual_old("RequireDualStack");
    let mut new = old.clone();
    new["clusterIPs"] = json!(["10.96.0.9", "fd00:96::5"]);
    new["clusterIP"] = json!("10.96.0.9");
    let err = validate_ip_fields_update(&old, &new, "s")
        .unwrap_err()
        .1
        .message;
    assert!(
        err.contains("spec.clusterIPs[0]: Invalid value: []string{\"10.96.0.9\", \"fd00:96::5\"}: may not change once set"),
        "{err}"
    );

    let mut flipped = old.clone();
    flipped["ipFamilies"] = json!(["IPv6", "IPv4"]);
    let err = validate_ip_fields_update(&old, &flipped, "s")
        .unwrap_err()
        .1
        .message;
    assert!(err.contains("spec.ipFamilies[0]"), "{err}");
    assert!(err.contains("may not change once set"), "{err}");
}

#[test]
fn external_name_is_left_alone_and_exempt_from_immutability() {
    let out = init(&[V4], None, json!({"type": "ExternalName"})).unwrap();
    assert!(out["ipFamilies"].is_null() && out["ipFamilyPolicy"].is_null());
    let old = dual_old("RequireDualStack");
    validate_ip_fields_update(&old, &json!({"type": "ExternalName"}), "s").unwrap();
}

#[test]
fn unallocated_slots_skip_headless_and_filled_slots() {
    assert_eq!(
        unallocated_slots(&json!({
            "type": "ClusterIP", "ipFamilies": ["IPv4", "IPv6"], "clusterIPs": ["10.96.0.5"],
        })),
        vec![(1, V6)]
    );
    assert!(unallocated_slots(&json!({
        "clusterIP": "None", "ipFamilies": ["IPv4", "IPv6"],
    }))
    .is_empty());
}
