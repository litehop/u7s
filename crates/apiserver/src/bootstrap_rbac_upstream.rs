//! Diffs the seeded ClusterRoles against upstream release-1.37 `bootstrappolicy` testdata
//! (`testdata/rbac-upstream-1.37/`, copied verbatim from
//! `plugin/pkg/auth/authorizer/rbac/bootstrappolicy/testdata/`). Every difference must be
//! listed in a deviation table below with the reason, so drift in either direction fails.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use u7s_store::{ListOptions, Store};

use crate::bootstrap_rbac::{rules_cover, yaml_items};
use crate::SqliteStore;

const GROUP: &str = "rbac.authorization.k8s.io";

fn upstream_roles(yaml: &str) -> BTreeMap<String, Vec<Value>> {
    yaml_items(yaml)
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

fn upstream_cluster_objects(yamls: &[&str]) -> BTreeMap<String, Value> {
    yamls
        .iter()
        .flat_map(|y| yaml_items(y))
        .map(|v| (v["metadata"]["name"].as_str().unwrap().to_string(), v))
        .collect()
}

async fn seeded_cluster_scoped(plural: &str) -> BTreeMap<String, Value> {
    let store = SqliteStore::new(":memory:").unwrap();
    crate::seed_rbac(&store).await.unwrap();
    let prefix = crate::keys::group_list_prefix(GROUP, plural, None);
    let all = store.list(&prefix, ListOptions::default()).await.unwrap();
    all.items
        .iter()
        .map(|o| serde_json::from_slice::<Value>(&o.value).unwrap())
        .filter(|v| v["metadata"]["namespace"].is_null())
        .map(|v| (v["metadata"]["name"].as_str().unwrap().to_string(), v))
        .collect()
}

const CLUSTER_ROLES: &str = include_str!("../testdata/rbac-upstream-1.37/cluster-roles.yaml");
const CONTROLLER_ROLES: &str = include_str!("../testdata/rbac-upstream-1.37/controller-roles.yaml");
const CLUSTER_ROLE_BINDINGS: &str =
    include_str!("../testdata/rbac-upstream-1.37/cluster-role-bindings.yaml");
const CONTROLLER_ROLE_BINDINGS: &str =
    include_str!("../testdata/rbac-upstream-1.37/controller-role-bindings.yaml");

#[tokio::test]
async fn seeded_cluster_roles_match_upstream_except_listed_deviations() {
    // Every seeded ClusterRole is live for some identity (kubelet = system:node, scheduler,
    // kube-proxy, per-controller service accounts), so an under-grant stalls that component
    // (a kubelet without clustertrustbundles get/list/watch hangs every projected-volume pod)
    // and an over-grant is blast radius. Roles for alpha-gated controllers upstream does not
    // create by default must not be seeded either: they advertise a controller u7s doesn't run.
    let seeded = seeded_cluster_scoped("clusterroles").await;
    let upstream = upstream_cluster_objects(&[CLUSTER_ROLES, CONTROLLER_ROLES]);

    assert_eq!(
        id_diff(&upstream, &seeded),
        set(&[
            // The aggregation controller is disabled; admin/edit/view are seeded pre-resolved
            // (see the view/edit/admin test).
            "system:aggregate-to-admin",
            "system:aggregate-to-edit",
            "system:aggregate-to-view",
            // Optional add-ons u7s neither ships nor binds: kube-dns/coredns carry their own
            // role, there is no kube-aggregator or node-problem-detector, and the CSR approver
            // roles are only ever bound by an operator.
            "system:certificates.k8s.io:kube-apiserver-client-approver",
            "system:certificates.k8s.io:kube-apiserver-client-kubelet-approver",
            "system:certificates.k8s.io:kubelet-serving-approver",
            "system:certificates.k8s.io:legacy-unknown-approver",
            "system:kube-aggregator",
            "system:kube-dns",
            "system:kubelet-api-admin",
            "system:node-problem-detector",
        ]),
        "upstream ClusterRoles dropped or newly seeded"
    );
    assert_eq!(
        id_diff(&seeded, &upstream),
        // Identity for the in-process manifest applier; has no upstream counterpart.
        set(&["system:bootstrap-installer"]),
        "seeded ClusterRoles with no upstream counterpart"
    );

    // role -> (permissions upstream grants that u7s lacks, permissions u7s grants that
    // upstream does not)
    let deviations: BTreeMap<&str, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::from([
        // No route serves these paths; advertising them in RBAC would turn a 404 into a 403/200
        // mismatch for monitoring clients.
        (
            "system:monitoring",
            (
                set(&[
                    "/flagz: get",
                    "/metrics/slis: get",
                    "/nodes/metrics: get",
                    "/statusz: get",
                ]),
                set(&[]),
            ),
        ),
    ]);
    // admin/edit/view: aggregation test. KCM: union test.
    let covered_elsewhere = ["admin", "edit", "view", "system:kube-controller-manager"];
    for (name, up) in upstream.iter().filter(|(n, _)| seeded.contains_key(*n)) {
        if covered_elsewhere.contains(&name.as_str()) {
            continue;
        }
        let want = without_extensions(up["rules"].as_array().unwrap_or(&vec![]));
        let have = without_extensions(seeded[name]["rules"].as_array().unwrap_or(&vec![]));
        let (under, over) = deviations.get(name.as_str()).cloned().unwrap_or_default();
        assert_eq!(uncovered(&want, &have), under, "{name} under-grants");
        assert_eq!(uncovered(&have, &want), over, "{name} over-grants");
    }
}

#[tokio::test]
async fn seeded_cluster_role_bindings_match_upstream_except_listed_deviations() {
    // Bindings decide who holds the roles above: a missing per-controller binding leaves that
    // controller's service account with nothing; a stray subject hands a role to the wrong
    // identity.
    let seeded = seeded_cluster_scoped("clusterrolebindings").await;
    let upstream = upstream_cluster_objects(&[CLUSTER_ROLE_BINDINGS, CONTROLLER_ROLE_BINDINGS]);

    assert_eq!(
        id_diff(&upstream, &seeded),
        set(&[
            // u7s names the cluster-admin binding after its subject group, system:masters.
            "cluster-admin",
            // system:kube-dns role is not seeded (see above).
            "system:kube-dns",
        ]),
        "upstream ClusterRoleBindings dropped or newly seeded"
    );
    assert_eq!(
        id_diff(&seeded, &upstream),
        set(&[
            // See the cluster-admin note above.
            "system:masters",
            // Upstream leaves these roles unbound (kubeadm binds them); u7s binds them so
            // TLS bootstrap and kubelet client-cert renewal work out of the box.
            "system:node-bootstrapper",
            "system:certificates.k8s.io:certificatesigningrequests:nodeclient",
            "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient",
            // Binding for the in-process manifest applier's identity.
            "system:bootstrap-installer",
            // Lets the kube-system/monitoring ServiceAccount mint a scrape token.
            "u7s:monitoring",
        ]),
        "seeded ClusterRoleBindings with no upstream counterpart"
    );

    let deviations: BTreeMap<&str, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::from([]);
    for (name, up) in upstream.iter().filter(|(n, _)| seeded.contains_key(*n)) {
        assert_eq!(
            seeded[name]["roleRef"]["name"], up["roleRef"]["name"],
            "{name} roleRef"
        );
        let (missing, extra) = deviations.get(name.as_str()).cloned().unwrap_or_default();
        let (want, have) = (subject_set(up), subject_set(&seeded[name]));
        assert_eq!(
            want.difference(&have).cloned().collect::<BTreeSet<_>>(),
            missing,
            "{name} lacks upstream subjects"
        );
        assert_eq!(
            have.difference(&want).cloned().collect::<BTreeSet<_>>(),
            extra,
            "{name} has non-upstream subjects"
        );
    }
}

async fn seeded_namespaced(plural: &str) -> BTreeMap<String, Value> {
    let store = SqliteStore::new(":memory:").unwrap();
    crate::seed_rbac(&store).await.unwrap();
    let prefix = crate::keys::group_list_prefix(GROUP, plural, None);
    let all = store.list(&prefix, ListOptions::default()).await.unwrap();
    all.items
        .iter()
        .map(|o| serde_json::from_slice::<Value>(&o.value).unwrap())
        .filter(|v| v["metadata"]["namespace"].is_string())
        .map(|v| {
            let id = format!(
                "{}/{}",
                v["metadata"]["namespace"].as_str().unwrap(),
                v["metadata"]["name"].as_str().unwrap()
            );
            (id, v)
        })
        .collect()
}

fn upstream_namespaced(yaml: &str) -> BTreeMap<String, Value> {
    yaml_items(yaml)
        .into_iter()
        .map(|v| {
            let id = format!(
                "{}/{}",
                v["metadata"]["namespace"].as_str().unwrap(),
                v["metadata"]["name"].as_str().unwrap()
            );
            (id, v)
        })
        .collect()
}

fn subject_set(v: &Value) -> BTreeSet<String> {
    v["subjects"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| {
            format!(
                "{}:{}/{}",
                s["kind"].as_str().unwrap(),
                s["namespace"].as_str().unwrap_or(""),
                s["name"].as_str().unwrap()
            )
        })
        .collect()
}

fn id_diff(a: &BTreeMap<String, Value>, b: &BTreeMap<String, Value>) -> BTreeSet<String> {
    a.keys().filter(|k| !b.contains_key(*k)).cloned().collect()
}

#[tokio::test]
async fn seeded_namespace_roles_match_upstream_except_listed_deviations() {
    // bootstrap-signer and token-cleaner run as their own service accounts when KCM uses
    // per-controller credentials; an under-granted Role silently stops token cleanup and
    // cluster-info signing.
    let seeded = seeded_namespaced("roles").await;
    let upstream = upstream_namespaced(include_str!(
        "../testdata/rbac-upstream-1.37/namespace-roles.yaml"
    ));

    // Leader election uses the cluster-wide lease grants in the KCM/scheduler ClusterRoles, and
    // there is no cloud-controller-manager.
    assert_eq!(
        id_diff(&upstream, &seeded),
        set(&[
            "kube-system/system::leader-locking-kube-controller-manager",
            "kube-system/system::leader-locking-kube-scheduler",
            "kube-system/system:controller:cloud-provider",
        ]),
        "upstream namespaced Roles dropped or newly seeded"
    );
    // kubeadm's anonymous read of the discovery document a joining node fetches pre-credential.
    assert_eq!(
        id_diff(&seeded, &upstream),
        set(&["kube-public/kubeadm:bootstrap-signer-clusterinfo"])
    );

    for (id, up) in upstream.iter().filter(|(k, _)| seeded.contains_key(*k)) {
        let want = without_extensions(up["rules"].as_array().unwrap());
        let have = seeded[id]["rules"].as_array().unwrap();
        assert_eq!(uncovered(&want, have), set(&[]), "{id} under-grants");
        assert_eq!(uncovered(have, &want), set(&[]), "{id} over-grants");
    }
}

#[tokio::test]
async fn seeded_namespace_rolebindings_match_upstream_except_listed_deviations() {
    let seeded = seeded_namespaced("rolebindings").await;
    let upstream = upstream_namespaced(include_str!(
        "../testdata/rbac-upstream-1.37/namespace-role-bindings.yaml"
    ));

    // Same unseeded Roles as above, plus the extension-apiserver-authentication-reader binding:
    // the u7s KCM holds cluster-wide configmap read, the u7s scheduler never reads that
    // ConfigMap, and extension servers bind the Role themselves.
    assert_eq!(
        id_diff(&upstream, &seeded),
        set(&[
            "kube-system/system::extension-apiserver-authentication-reader",
            "kube-system/system::leader-locking-kube-controller-manager",
            "kube-system/system::leader-locking-kube-scheduler",
            "kube-system/system:controller:cloud-provider",
        ]),
        "upstream namespaced RoleBindings dropped or newly seeded"
    );
    assert_eq!(
        id_diff(&seeded, &upstream),
        set(&["kube-public/kubeadm:bootstrap-signer-clusterinfo"])
    );

    for (id, up) in upstream.iter().filter(|(k, _)| seeded.contains_key(*k)) {
        assert_eq!(seeded[id]["roleRef"]["name"], up["roleRef"]["name"], "{id}");
        assert_eq!(seeded[id]["roleRef"]["kind"], up["roleRef"]["kind"], "{id}");
        assert_eq!(subject_set(&seeded[id]), subject_set(up), "{id} subjects");
    }
}
