//! Golden test for the classifier: one object per rule branch, the full
//! report compared against a reviewed file. A rule that changes behaviour
//! changes a line, so the test fails; review the `.actual` file it writes and
//! move it over `report.txt` only when the new decision is intended.

use serde_json::Value;
use u7s_apiserver::migrate_tables::{shipped_addons, strippable_finalizers};
use u7s_migrate::plan::{build, render_report, Source};

const TAG: &str = "v1.36.5+k3s1";

fn golden_report() -> String {
    let objs: Vec<Value> =
        serde_json::from_str(include_str!("golden/objects.json")).expect("fixture is JSON");
    let shipped = shipped_addons(TAG, false).unwrap();
    let source = Source {
        k3s_version: TAG.into(),
        shipped_table: shipped.table_tag.into(),
        service_cidrs: vec!["10.43.0.0/16".into()],
        pod_cidrs: vec!["10.42.0.0/24".into()],
        kube_dns_cluster_ip: Some("10.43.0.10".into()),
    };
    let (plan, warnings) = build(&objs, source, shipped.addons, strippable_finalizers(TAG));
    plan.validate()
        .expect("generated plan strips only allowlisted finalizers");
    render_report(&plan, &warnings)
}

#[test]
fn classifier_report_matches_golden_file() {
    let actual = golden_report();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let expected = std::fs::read_to_string(dir.join("report.txt")).unwrap_or_default();
    if actual != expected {
        std::fs::write(dir.join("report.actual.txt"), &actual).unwrap();
        panic!(
            "classification changed: a migrated user object may now be skipped (data loss) or a distro object migrated. Diff tests/golden/report.actual.txt against report.txt"
        );
    }
}
