//! Diffs the seeded ClusterRoles against upstream release-1.37 `bootstrappolicy` testdata
//! (`testdata/rbac-upstream-1.37/`, copied verbatim from
//! `plugin/pkg/auth/authorizer/rbac/bootstrappolicy/testdata/`). Every difference must be
//! listed in a deviation table below with the reason, so drift in either direction fails.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use u7s_store::{ListOptions, Store};
use yaml_rust2::{Yaml, YamlLoader};

use crate::bootstrap_rbac::rules_cover;
use crate::SqliteStore;

const GROUP: &str = "rbac.authorization.k8s.io";

fn to_json(y: &Yaml) -> Value {
    match y {
        Yaml::Hash(h) => Value::Object(
            h.iter()
                .map(|(k, v)| (k.as_str().unwrap_or_default().to_string(), to_json(v)))
                .collect(),
        ),
        Yaml::Array(a) => Value::Array(a.iter().map(to_json).collect()),
        Yaml::String(s) => json!(s),
        Yaml::Boolean(b) => json!(b),
        Yaml::Integer(i) => json!(i),
        _ => Value::Null,
    }
}

fn upstream_roles(yaml: &str) -> BTreeMap<String, Vec<Value>> {
    let doc = &YamlLoader::load_from_str(yaml).unwrap()[0];
    to_json(doc)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["metadata"]["name"].as_str().unwrap().to_string(),
                r["rules"].as_array().cloned().unwrap_or_default(),
            )
        })
        .collect()
}

async fn seeded_roles() -> BTreeMap<String, Vec<Value>> {
    let store = SqliteStore::new(":memory:").unwrap();
    crate::seed_rbac(&store).await.unwrap();
    let prefix = crate::keys::group_list_prefix(GROUP, "clusterroles", None);
    let all = store.list(&prefix, ListOptions::default()).await.unwrap();
    all.items
        .iter()
        .map(|o| {
            let v: Value = serde_json::from_slice(&o.value).unwrap();
            (
                v["metadata"]["name"].as_str().unwrap().to_string(),
                v["rules"].as_array().cloned().unwrap_or_default(),
            )
        })
        .collect()
}

fn strs(v: &Value, f: &str) -> Vec<String> {
    v[f].as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Splits every rule into single (group, resource, verb) / (url, verb) rules so that
/// coverage is judged per permission rather than per upstream rule shape.
fn atoms(rules: &[Value]) -> Vec<Value> {
    let mut out = vec![];
    for r in rules {
        let verbs = strs(r, "verbs");
        for url in strs(r, "nonResourceURLs") {
            for v in &verbs {
                out.push(json!({ "nonResourceURLs": [url], "verbs": [v] }));
            }
        }
        for g in strs(r, "apiGroups") {
            for res in strs(r, "resources") {
                for v in &verbs {
                    out.push(json!({
                        "apiGroups": [g], "resources": [res], "verbs": [v],
                        "resourceNames": strs(r, "resourceNames"),
                    }));
                }
            }
        }
    }
    out
}

/// "group/resource[names]: verb,verb" lines for every permission in `want` that `by` lacks.
fn uncovered(want: &[Value], by: &[Value]) -> BTreeSet<String> {
    let mut targets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for a in atoms(want).iter().filter(|a| !rules_cover(by, a)) {
        let target = match a["nonResourceURLs"].get(0).and_then(Value::as_str) {
            Some(url) => url.to_string(),
            None => {
                let names = strs(a, "resourceNames");
                let names = if names.is_empty() {
                    String::new()
                } else {
                    format!("[{}]", names.join(","))
                };
                format!(
                    "{}/{}{names}",
                    a["apiGroups"][0].as_str().unwrap(),
                    a["resources"][0].as_str().unwrap()
                )
            }
        };
        targets
            .entry(target)
            .or_default()
            .insert(a["verbs"][0].as_str().unwrap().to_string());
    }
    targets
        .into_iter()
        .map(|(t, v)| format!("{t}: {}", v.into_iter().collect::<Vec<_>>().join(",")))
        .collect()
}

/// u7s does not serve the long-removed `extensions` API group, so upstream's rules for it cannot
/// be granted.
fn without_extensions(rules: &[Value]) -> Vec<Value> {
    rules
        .iter()
        .filter_map(|r| {
            let groups: Vec<String> = strs(r, "apiGroups")
                .into_iter()
                .filter(|g| g != "extensions")
                .collect();
            let had_groups = r.get("apiGroups").is_some();
            if had_groups && groups.is_empty() {
                return None;
            }
            let mut r = r.clone();
            if had_groups {
                r["apiGroups"] = json!(groups);
            }
            Some(r)
        })
        .collect()
}

fn rules_of(roles: &BTreeMap<String, Vec<Value>>, names: &[&str]) -> Vec<Value> {
    without_extensions(
        &names
            .iter()
            .flat_map(|n| roles[*n].clone())
            .collect::<Vec<_>>(),
    )
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn seeded_view_edit_admin_grant_exactly_what_upstream_aggregation_resolves_to() {
    // The aggregation controller is disabled in u7s, so view/edit/admin are seeded already
    // resolved. Over-grants (e.g. nodes on view, endpoints writes on edit) widen what a
    // namespace role binding reaches; under-grants break kubectl rollout/logs/events for users.
    let seeded = seeded_roles().await;
    let cr = upstream_roles(include_str!(
        "../testdata/rbac-upstream-1.37/cluster-roles.yaml"
    ));
    let to_view = ["system:aggregate-to-view"];
    let to_edit = ["system:aggregate-to-edit", "system:aggregate-to-view"];
    let to_admin = [
        "system:aggregate-to-admin",
        "system:aggregate-to-edit",
        "system:aggregate-to-view",
    ];
    for (name, parts) in [
        ("view", &to_view[..]),
        ("edit", &to_edit[..]),
        ("admin", &to_admin[..]),
    ] {
        let upstream = rules_of(&cr, parts);
        let have = without_extensions(&seeded[name]);
        assert_eq!(
            uncovered(&upstream, &have),
            set(&[]),
            "{name} lacks permissions upstream grants"
        );
        assert_eq!(
            uncovered(&have, &upstream),
            set(&[]),
            "{name} grants permissions upstream does not"
        );
    }
}

#[tokio::test]
async fn seeded_controller_roles_are_all_upstream_default_roles() {
    // Roles for alpha-gated controllers (e.g. storage-version-garbage-collector) are not
    // created by a default upstream cluster; seeding them advertises a controller u7s doesn't run.
    let seeded = seeded_roles().await;
    let ctl = upstream_roles(include_str!(
        "../testdata/rbac-upstream-1.37/controller-roles.yaml"
    ));
    let extra: Vec<&String> = seeded
        .keys()
        .filter(|n| n.starts_with("system:controller:") && !ctl.contains_key(*n))
        .collect();
    assert!(extra.is_empty(), "non-upstream controller roles: {extra:?}");
}

#[tokio::test]
async fn seeded_kcm_identity_holds_exactly_the_union_of_upstream_controller_permissions() {
    // With --use-service-account-credentials=false one identity runs every controller, so it
    // must hold the union of upstream's per-controller roles -- missing a create stalls that
    // controller (e.g. daemonset pods never bind), and any surplus is blast radius for a
    // compromised KCM.
    let seeded = seeded_roles().await;
    let cr = upstream_roles(include_str!(
        "../testdata/rbac-upstream-1.37/cluster-roles.yaml"
    ));
    let ctl = upstream_roles(include_str!(
        "../testdata/rbac-upstream-1.37/controller-roles.yaml"
    ));
    let mut upstream = cr["system:kube-controller-manager"].clone();
    for (name, rules) in &ctl {
        if name.starts_with("system:controller:") {
            upstream.extend(rules.clone());
        }
    }
    let upstream = without_extensions(&upstream);
    let have = &seeded["system:kube-controller-manager"];
    assert_eq!(
        uncovered(&upstream, have),
        // clusterrole-aggregation-controller is the only consumer and the u7s KCM runs with it
        // disabled (the seeded admin/edit/view are pre-resolved).
        set(&["rbac.authorization.k8s.io/clusterroles: escalate"]),
        "KCM lacks permissions its controllers need"
    );
    assert_eq!(
        uncovered(have, &upstream),
        set(&[]),
        "KCM holds permissions no upstream controller needs"
    );
}
