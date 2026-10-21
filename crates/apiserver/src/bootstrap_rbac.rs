//! Upstream-style reconciliation of bootstrap RBAC objects at startup.
//!
//! Mirrors `ensureRBACPolicy` / `ReconcileRoleOptions` / `ReconcileRoleBindingOptions`: a missing
//! object is created; an existing one is brought up to the bootstrap policy by *adding* missing
//! rules, subjects, labels and annotations, never removing anything an operator added (except
//! exact copies of rules earlier u7s releases seeded, see `legacy_rules`); an
//! object annotated `rbac.authorization.kubernetes.io/autoupdate: "false"` is left alone.

use bytes::Bytes;
use serde_json::{json, Value};
use u7s_store::{Store, StoreError};
use yaml_rust2::{Yaml, YamlLoader};

use crate::SqliteStore;

const AUTOUPDATE_ANNOTATION: &str = "rbac.authorization.kubernetes.io/autoupdate";
const BOOTSTRAP_LABEL: &str = "kubernetes.io/bootstrapping";
const BOOTSTRAP_LABEL_VALUE: &str = "rbac-defaults";
const MAX_ATTEMPTS: usize = 5;
const GROUP: &str = "rbac.authorization.k8s.io";

#[derive(Debug, PartialEq)]
pub(crate) enum Reconciled {
    Unchanged,
    /// Replacement object plus a human-readable list of what was added.
    Update(Value, String),
    /// roleRef is immutable: the binding must be deleted and recreated.
    Recreate,
}

/// Stamps the markers upstream puts on every bootstrap object.
pub(crate) fn stamp_bootstrap_markers(obj: &mut Value) {
    obj["metadata"]["annotations"][AUTOUPDATE_ANNOTATION] = json!("true");
    obj["metadata"]["labels"][BOOTSTRAP_LABEL] = json!(BOOTSTRAP_LABEL_VALUE);
}

pub(crate) fn yaml_to_json(y: &Yaml) -> Value {
    match y {
        Yaml::Hash(h) => Value::Object(
            h.iter()
                .map(|(k, v)| (k.as_str().unwrap_or_default().to_string(), yaml_to_json(v)))
                .collect(),
        ),
        Yaml::Array(a) => Value::Array(a.iter().map(yaml_to_json).collect()),
        Yaml::String(s) => json!(s),
        Yaml::Boolean(b) => json!(b),
        Yaml::Integer(i) => json!(i),
        _ => Value::Null,
    }
}

/// The `items` of an upstream `bootstrappolicy` testdata list.
pub(crate) fn yaml_items(yaml: &str) -> Vec<Value> {
    let docs = YamlLoader::load_from_str(yaml).expect("embedded upstream RBAC YAML parses");
    yaml_to_json(&docs[0])["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The per-controller `system:controller:*` ClusterRoles and their ClusterRoleBindings, verbatim
/// from upstream release-1.37 (the vendored golden files are the single source), as
/// `(plural, object)` with a stable uid.
pub(crate) fn upstream_controller_objects() -> Vec<(&'static str, Value)> {
    let roles = yaml_items(include_str!(
        "../testdata/rbac-upstream-1.37/controller-roles.yaml"
    ));
    let bindings = yaml_items(include_str!(
        "../testdata/rbac-upstream-1.37/controller-role-bindings.yaml"
    ));
    let tagged = |plural, series: u8, items: Vec<Value>| {
        items
            .into_iter()
            .enumerate()
            .map(move |(i, mut o)| {
                o["metadata"]["uid"] =
                    json!(format!("00000000-0000-0000-000{series}-{:012x}", i + 1));
                (plural, o)
            })
            .collect::<Vec<_>>()
    };
    let mut out = tagged("clusterroles", 1, roles);
    out.extend(tagged("clusterrolebindings", 2, bindings));
    out
}

fn strs<'a>(v: &'a Value, field: &str) -> Vec<&'a str> {
    v[field]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn list<'a>(v: &'a Value, field: &str) -> &'a [Value] {
    v[field].as_array().map(Vec::as_slice).unwrap_or_default()
}

fn wildcard_or_eq(have: &[&str], want: &str) -> bool {
    have.iter().any(|h| *h == "*" || *h == want)
}

fn resource_matches(have: &[&str], want: &str) -> bool {
    have.iter().any(|h| {
        *h == "*"
            || *h == want
            || h.strip_prefix("*/")
                .is_some_and(|sub| want.rsplit_once('/').is_some_and(|(_, s)| s == sub))
    })
}

fn url_matches(have: &[&str], want: &str) -> bool {
    have.iter()
        .any(|h| *h == want || h.strip_suffix('*').is_some_and(|p| want.starts_with(p)))
}

/// True when every (group, resource, verb[, name]) and every (url, verb) tuple granted by `rule`
/// is granted by some single rule in `have`. Like upstream's `Covers`, a rule carrying both
/// resources and nonResourceURLs is split into both kinds of tuples and all must be covered.
pub(crate) fn rules_cover(have: &[Value], rule: &Value) -> bool {
    let verbs = strs(rule, "verbs");
    let urls = strs(rule, "nonResourceURLs");
    let urls_covered = urls.iter().all(|url| {
        verbs.iter().all(|verb| {
            have.iter().any(|h| {
                url_matches(&strs(h, "nonResourceURLs"), url)
                    && wildcard_or_eq(&strs(h, "verbs"), verb)
                    && strs(h, "resourceNames").is_empty()
            })
        })
    });
    if !urls_covered {
        return false;
    }
    let groups = strs(rule, "apiGroups");
    let resources = strs(rule, "resources");
    let names = strs(rule, "resourceNames");
    let names: Vec<Option<&str>> = if names.is_empty() {
        vec![None]
    } else {
        names.into_iter().map(Some).collect()
    };
    groups.iter().all(|group| {
        resources.iter().all(|res| {
            verbs.iter().all(|verb| {
                names.iter().all(|name| {
                    have.iter().any(|h| {
                        let hn = strs(h, "resourceNames");
                        wildcard_or_eq(&strs(h, "apiGroups"), group)
                            && resource_matches(&strs(h, "resources"), res)
                            && wildcard_or_eq(&strs(h, "verbs"), verb)
                            && (hn.is_empty() || name.is_some_and(|n| hn.contains(&n)))
                    })
                })
            })
        })
    })
}

fn subject_key(s: &Value) -> (&str, &str, &str, &str) {
    let api_group = s["apiGroup"].as_str().unwrap_or(match s["kind"].as_str() {
        Some("ServiceAccount") => "",
        _ => "rbac.authorization.k8s.io",
    });
    (
        s["kind"].as_str().unwrap_or(""),
        api_group,
        s["name"].as_str().unwrap_or(""),
        s["namespace"].as_str().unwrap_or(""),
    )
}

/// Adds `expected` entries missing from `existing` (existing values win). Returns the added keys.
fn merge_string_map(obj: &mut Value, field: &str, expected: &Value) -> Vec<String> {
    let mut added = vec![];
    let Some(exp) = expected["metadata"][field].as_object() else {
        return added;
    };
    for (k, v) in exp {
        if obj["metadata"][field].get(k).is_none() {
            obj["metadata"][field][k] = v.clone();
            added.push(format!("{field}[{k}]"));
        }
    }
    added
}

const WRITE: [&str; 5] = ["create", "update", "patch", "delete", "deletecollection"];

fn crud() -> Vec<&'static str> {
    ["get", "list", "watch"].into_iter().chain(WRITE).collect()
}

/// Rules earlier u7s releases seeded that are broader than the current policy.
///
/// Upstream's bootstrap reconcile only ever adds permissions (`RemoveExtraPermissions` is never
/// set in `ensureRBACPolicy`), so a rule dropped from the policy survives on every cluster that
/// already stored it. u7s is pre-release and owns what it seeded, so these exact rules are
/// removed from stored bootstrap roles. Matching is by full equality: a rule an operator edited
/// or wrote themselves is left alone.
fn legacy_rules(role: &str) -> Vec<Value> {
    let read = ["get", "list", "watch"];
    let core_crud_with_endpoints = json!({
        "apiGroups": [""],
        "resources": ["pods","services","endpoints","persistentvolumeclaims","configmaps","secrets","serviceaccounts","events","replicationcontrollers"],
        "verbs": crud()
    });
    let apps_crud_with_revisions = json!({
        "apiGroups": ["apps"],
        "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"],
        "verbs": crud()
    });
    match role {
        "admin" => vec![
            core_crud_with_endpoints,
            apps_crud_with_revisions,
            json!({
                "apiGroups": [GROUP],
                "resources": ["roles", "rolebindings"],
                "verbs": crud().into_iter().chain(["bind", "escalate"]).collect::<Vec<_>>()
            }),
        ],
        "edit" => vec![core_crud_with_endpoints, apps_crud_with_revisions],
        "view" => vec![json!({
            "apiGroups": [""],
            "resources": ["pods","services","endpoints","persistentvolumeclaims","configmaps","serviceaccounts","events","replicationcontrollers","namespaces","nodes","resourcequotas","limitranges"],
            "verbs": read
        })],
        "system:kube-controller-manager" => {
            let write_no_collection = [
                "get", "list", "watch", "create", "update", "patch", "delete",
            ];
            vec![
                json!({
                    "apiGroups": [""],
                    "resources": ["endpoints","pods","replicationcontrollers","serviceaccounts","configmaps","secrets","services","namespaces","nodes","persistentvolumes","persistentvolumeclaims","resourcequotas"],
                    "verbs": write_no_collection
                }),
                json!({
                    "apiGroups": ["apps"],
                    "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"],
                    "verbs": write_no_collection
                }),
                json!({
                    "apiGroups": ["batch"],
                    "resources": ["jobs", "cronjobs"],
                    "verbs": write_no_collection
                }),
                json!({
                    "apiGroups": [GROUP],
                    "resources": ["clusterroles","clusterrolebindings","roles","rolebindings"],
                    "verbs": ["get","list","watch","create","update","patch","escalate","bind"]
                }),
            ]
        }
        "system:node" => {
            let rule = |group: &str, resource: &str, verbs: &[&str]| json!({ "apiGroups": [group], "resources": [resource], "verbs": verbs });
            let all_verbs = [
                "get", "list", "watch", "create", "update", "patch", "delete",
            ];
            vec![
                rule("", "nodes/status", &["get", "update", "patch"]),
                rule("", "pods/status", &["get", "update", "patch"]),
                rule("", "pods/log", &["get"]),
                rule("coordination.k8s.io", "leases", &all_verbs),
                rule("storage.k8s.io", "csinodes", &all_verbs),
            ]
        }
        _ => vec![],
    }
}

/// Bootstrap ClusterRoles earlier releases seeded that the current policy no longer has.
pub(crate) const LEGACY_CLUSTER_ROLES: &[&str] =
    &["system:controller:storage-version-garbage-collector"];

/// Computes what must change on `existing` to satisfy `expected`, without ever removing
/// operator additions (only the exact rules listed by `legacy_rules`).
pub(crate) fn reconcile(existing: &Value, expected: &Value) -> Reconciled {
    if existing["metadata"]["annotations"][AUTOUPDATE_ANNOTATION].as_str() == Some("false") {
        return Reconciled::Unchanged;
    }
    if expected.get("roleRef").is_some() && expected["roleRef"] != existing["roleRef"] {
        return Reconciled::Recreate;
    }

    let mut obj = existing.clone();
    let mut changes = vec![];
    changes.extend(merge_string_map(&mut obj, "annotations", expected));
    changes.extend(merge_string_map(&mut obj, "labels", expected));

    if expected.get("roleRef").is_some() {
        let have: Vec<_> = list(existing, "subjects").iter().map(subject_key).collect();
        let mut subjects = list(existing, "subjects").to_vec();
        for s in list(expected, "subjects") {
            if !have.contains(&subject_key(s)) {
                changes.push(format!("subject {}", s["name"].as_str().unwrap_or("?")));
                subjects.push(s.clone());
            }
        }
        if subjects.len() != have.len() {
            obj["subjects"] = Value::Array(subjects);
        }
    } else if let Some(agg) = expected.get("aggregationRule") {
        // Aggregated roles' rules are computed by the aggregation controller; only the
        // selectors are reconciled.
        let mut selectors = existing["aggregationRule"]["clusterRoleSelectors"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let before = selectors.len();
        for sel in list(agg, "clusterRoleSelectors") {
            if !selectors.contains(sel) {
                changes.push("aggregationRule selector".to_string());
                selectors.push(sel.clone());
            }
        }
        if selectors.len() != before {
            obj["aggregationRule"] = json!({ "clusterRoleSelectors": selectors });
        }
    } else {
        if existing
            .get("aggregationRule")
            .is_some_and(|a| !a.is_null())
        {
            obj.as_object_mut().map(|m| m.remove("aggregationRule"));
            changes.push("aggregationRule removed".to_string());
        }
        let bootstrap = existing["metadata"]["labels"][BOOTSTRAP_LABEL] == BOOTSTRAP_LABEL_VALUE;
        let legacy = if bootstrap && expected["kind"] == "ClusterRole" {
            legacy_rules(expected["metadata"]["name"].as_str().unwrap_or_default())
        } else {
            vec![]
        };
        let have: Vec<Value> = list(existing, "rules")
            .iter()
            .filter(|r| !legacy.contains(r))
            .cloned()
            .collect();
        let removed = list(existing, "rules").len() - have.len();
        if removed > 0 {
            changes.push(format!("removed {removed} legacy rule(s)"));
        }
        let mut rules = have.clone();
        for r in list(expected, "rules") {
            if !rules_cover(&have, r) {
                changes.push(format!(
                    "rule {}/{}",
                    strs(r, "apiGroups").join(","),
                    strs(r, "resources").join(",")
                ));
                rules.push(r.clone());
            }
        }
        if removed > 0 || rules.len() != have.len() {
            obj["rules"] = Value::Array(rules);
        }
    }

    if changes.is_empty() {
        Reconciled::Unchanged
    } else {
        Reconciled::Update(obj, changes.join(", "))
    }
}

/// Deletes the `LEGACY_CLUSTER_ROLES` still stored. Operator-owned roles (no bootstrap label) and
/// opted-out ones (`autoupdate: "false"`) are kept.
pub(crate) async fn remove_legacy_cluster_roles(store: &SqliteStore) -> anyhow::Result<()> {
    for name in LEGACY_CLUSTER_ROLES {
        let key = crate::keys::group_object_key(GROUP, "clusterroles", None, name);
        for _ in 0..MAX_ATTEMPTS {
            let Some(stored) = store.get(&key).await? else {
                break;
            };
            let obj: Value = serde_json::from_slice(&stored.value)?;
            let bootstrap = obj["metadata"]["labels"][BOOTSTRAP_LABEL] == BOOTSTRAP_LABEL_VALUE;
            let opted_out =
                obj["metadata"]["annotations"][AUTOUPDATE_ANNOTATION].as_str() == Some("false");
            if !bootstrap || opted_out {
                break;
            }
            match store.delete(&key, Some(stored.revision)).await {
                Ok(_) => {
                    tracing::info!("removed legacy ClusterRole {name}");
                    break;
                }
                Err(StoreError::RevisionMismatch { .. }) => {}
                Err(e) => return Err(anyhow::anyhow!("remove legacy ClusterRole {name}: {e}")),
            }
        }
    }
    Ok(())
}

/// Creates the bootstrap object at `key`, or reconciles the stored one towards `expected`.
/// Writes nothing when the stored object already satisfies the policy.
pub(crate) async fn reconcile_object(
    store: &SqliteStore,
    key: &str,
    mut expected: Value,
) -> anyhow::Result<()> {
    stamp_bootstrap_markers(&mut expected);
    let kind = expected["kind"].as_str().unwrap_or("object").to_string();
    let name = expected["metadata"]["name"]
        .as_str()
        .unwrap_or("?")
        .to_string();
    for _ in 0..MAX_ATTEMPTS {
        let res = match store.get(key).await? {
            None => store
                .put(key, Bytes::from(expected.to_string()), Some(0))
                .await
                .map(|_| tracing::info!("seeded {kind}: {name}")),
            Some(stored) => match reconcile(&serde_json::from_slice(&stored.value)?, &expected) {
                Reconciled::Unchanged => return Ok(()),
                Reconciled::Update(obj, what) => store
                    .put(key, Bytes::from(obj.to_string()), Some(stored.revision))
                    .await
                    .map(|_| tracing::info!("reconciled {kind} {name}: {what}")),
                Reconciled::Recreate => match store.delete(key, Some(stored.revision)).await {
                    Ok(_) => store
                        .put(key, Bytes::from(expected.to_string()), Some(0))
                        .await
                        .map(|_| tracing::info!("recreated {kind} {name}: roleRef changed")),
                    Err(e) => Err(e),
                },
            },
        };
        match res {
            Ok(()) => return Ok(()),
            Err(StoreError::AlreadyExists { .. } | StoreError::RevisionMismatch { .. }) => {}
            Err(e) => return Err(anyhow::anyhow!("reconcile {kind} {name}: {e}")),
        }
    }
    Err(anyhow::anyhow!(
        "reconcile {kind} {name}: gave up after {MAX_ATTEMPTS} conflicting attempts"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &str = "rbac.authorization.k8s.io";

    fn role(rules: Value) -> Value {
        json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": { "name": "r", "uid": "u" },
            "rules": rules
        })
    }

    fn binding(subjects: Value) -> Value {
        json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": { "name": "b", "uid": "u" },
            "subjects": subjects,
            "roleRef": { "apiGroup": GROUP, "kind": "ClusterRole", "name": "r" }
        })
    }

    fn pods_get() -> Value {
        json!({ "apiGroups": [""], "resources": ["pods"], "verbs": ["get"] })
    }

    fn secrets_get() -> Value {
        json!({ "apiGroups": [""], "resources": ["secrets"], "verbs": ["get"] })
    }

    fn stamped(mut v: Value) -> Value {
        stamp_bootstrap_markers(&mut v);
        v
    }

    async fn stored(store: &SqliteStore, key: &str) -> (Value, u64) {
        let o = store.get(key).await.unwrap().expect("object must exist");
        (serde_json::from_slice(&o.value).unwrap(), o.revision)
    }

    fn key(plural: &str, name: &str) -> String {
        crate::keys::group_object_key(GROUP, plural, None, name)
    }

    #[tokio::test]
    async fn missing_object_is_created_with_autoupdate_marker() {
        let store = SqliteStore::new(":memory:").unwrap();
        reconcile_object(&store, &key("clusterroles", "r"), role(json!([pods_get()])))
            .await
            .unwrap();
        let (obj, _) = stored(&store, &key("clusterroles", "r")).await;
        assert_eq!(
            obj["metadata"]["annotations"][AUTOUPDATE_ANNOTATION], "true",
            "bootstrap objects must carry autoupdate=true so later upgrades keep reconciling them"
        );
        assert_eq!(
            obj["metadata"]["labels"][BOOTSTRAP_LABEL],
            BOOTSTRAP_LABEL_VALUE
        );
    }

    #[tokio::test]
    async fn role_missing_a_rule_gains_it_and_keeps_user_added_rules() {
        let store = SqliteStore::new(":memory:").unwrap();
        let k = key("clusterroles", "r");
        let user_rule = json!({ "apiGroups": ["x.io"], "resources": ["widgets"], "verbs": ["*"] });
        store
            .put(
                &k,
                Bytes::from(role(json!([pods_get(), user_rule])).to_string()),
                Some(0),
            )
            .await
            .unwrap();
        reconcile_object(&store, &k, role(json!([pods_get(), secrets_get()])))
            .await
            .unwrap();
        let (obj, _) = stored(&store, &k).await;
        let rules = obj["rules"].as_array().unwrap();
        assert!(
            rules.contains(&secrets_get()),
            "an upgraded bootstrap role must gain rules added in a newer release, else fixes never reach existing clusters"
        );
        assert!(
            rules.contains(&user_rule),
            "reconcile must be additive: an operator's extra rule must survive a restart"
        );
    }

    #[tokio::test]
    async fn autoupdate_false_role_is_left_untouched() {
        let store = SqliteStore::new(":memory:").unwrap();
        let k = key("clusterroles", "r");
        let mut old = role(json!([pods_get()]));
        old["metadata"]["annotations"] = json!({ AUTOUPDATE_ANNOTATION: "false" });
        store
            .put(&k, Bytes::from(old.to_string()), Some(0))
            .await
            .unwrap();
        let (_, rev) = stored(&store, &k).await;
        reconcile_object(&store, &k, role(json!([pods_get(), secrets_get()])))
            .await
            .unwrap();
        let (obj, rev_after) = stored(&store, &k).await;
        assert_eq!(
            rev, rev_after,
            "an operator who opted out with autoupdate=false must not be written to"
        );
        assert_eq!(obj["rules"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn up_to_date_store_is_not_written_on_restart() {
        let store = SqliteStore::new(":memory:").unwrap();
        let k = key("clusterroles", "r");
        let expected = role(json!([pods_get(), secrets_get()]));
        reconcile_object(&store, &k, expected.clone())
            .await
            .unwrap();
        let (_, rev) = stored(&store, &k).await;
        reconcile_object(&store, &k, expected).await.unwrap();
        let (_, rev_after) = stored(&store, &k).await;
        assert_eq!(
            rev, rev_after,
            "restarts must not bump resourceVersion of unchanged bootstrap objects"
        );
    }

    #[tokio::test]
    async fn binding_missing_a_subject_gains_it_and_keeps_user_subjects() {
        let store = SqliteStore::new(":memory:").unwrap();
        let k = key("clusterrolebindings", "b");
        let user = json!({ "kind": "User", "apiGroup": GROUP, "name": "alice" });
        let want =
            json!({ "kind": "User", "apiGroup": GROUP, "name": "system:kube-controller-manager" });
        store
            .put(&k, Bytes::from(binding(json!([user])).to_string()), Some(0))
            .await
            .unwrap();
        reconcile_object(&store, &k, binding(json!([want])))
            .await
            .unwrap();
        let (obj, _) = stored(&store, &k).await;
        let subjects = obj["subjects"].as_array().unwrap();
        assert!(
            subjects.contains(&want),
            "bootstrap subject must be restored"
        );
        assert!(
            subjects.contains(&user),
            "operator-added subjects must survive"
        );
    }

    #[test]
    fn binding_with_different_roleref_is_recreated() {
        let mut existing = binding(json!([]));
        existing["roleRef"]["name"] = json!("other");
        assert_eq!(
            reconcile(&existing, &binding(json!([]))),
            Reconciled::Recreate
        );
    }

    #[test]
    fn broader_existing_rule_covers_narrower_expected_rule() {
        let existing = stamped(role(
            json!([{ "apiGroups": ["*"], "resources": ["*"], "verbs": ["get","list"] }]),
        ));
        let expected = stamped(role(json!([pods_get()])));
        assert_eq!(
            reconcile(&existing, &expected),
            Reconciled::Unchanged,
            "a wildcard grant already covers pods/get so no duplicate rule may be appended"
        );
    }

    #[test]
    fn owner_resource_slash_star_does_not_cover_its_subresource() {
        // Upstream's resourceCoversAll accepts only '*', exact and '*/sub'; honouring 'pods/*'
        // would skip appending a bootstrap grant that the authorizer does not treat as covered.
        let log_get = json!({ "apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"] });
        let owner_star =
            role(json!([{ "apiGroups": [""], "resources": ["pods/*"], "verbs": ["get"] }]));
        assert!(matches!(
            reconcile(&owner_star, &role(json!([log_get.clone()]))),
            Reconciled::Update(..)
        ));
        let any_owner = stamped(role(
            json!([{ "apiGroups": [""], "resources": ["*/log"], "verbs": ["get"] }]),
        ));
        assert_eq!(
            reconcile(&any_owner, &stamped(role(json!([log_get])))),
            Reconciled::Unchanged
        );
    }

    #[test]
    fn resource_names_restricted_rule_does_not_cover_unrestricted_one() {
        let existing = role(
            json!([{ "apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["a"], "verbs": ["get"] }]),
        );
        let expected =
            role(json!([{ "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"] }]));
        assert!(matches!(
            reconcile(&existing, &expected),
            Reconciled::Update(..)
        ));
    }

    #[test]
    fn mixed_resource_and_url_rule_is_not_covered_by_url_grant_alone() {
        let url_only = json!({ "nonResourceURLs": ["/healthz"], "verbs": ["get"] });
        let mixed = json!({
            "apiGroups": [""], "resources": ["pods"], "nonResourceURLs": ["/healthz"], "verbs": ["get"]
        });
        let existing = stamped(role(json!([url_only])));
        let expected = stamped(role(json!([mixed])));
        let Reconciled::Update(obj, _) = reconcile(&existing, &expected) else {
            panic!("pods/get is ungranted, so the role must be updated");
        };
        assert!(
            obj["rules"].as_array().unwrap().contains(&mixed),
            "checking only the URL half would silently skip adding a bootstrap role's resource grant on upgrade"
        );
    }

    #[test]
    fn mixed_rule_is_covered_when_each_half_is_granted() {
        let mixed = json!({
            "apiGroups": [""], "resources": ["pods"], "nonResourceURLs": ["/healthz"], "verbs": ["get"]
        });
        let existing = stamped(role(json!([
            pods_get(),
            { "nonResourceURLs": ["/healthz*"], "verbs": ["*"] }
        ])));
        assert_eq!(
            reconcile(&existing, &stamped(role(json!([mixed])))),
            Reconciled::Unchanged,
            "fully granted halves must not append a duplicate rule on every restart"
        );
    }

    #[test]
    fn aggregated_role_reconciles_selectors_not_rules() {
        let sel = json!({ "matchLabels": { "a": "b" } });
        let mut expected = role(json!([]));
        expected["aggregationRule"] = json!({ "clusterRoleSelectors": [sel] });
        let mut existing = role(json!([pods_get()]));
        existing["aggregationRule"] = json!({ "clusterRoleSelectors": [] });
        let Reconciled::Update(obj, _) = reconcile(&existing, &expected) else {
            panic!("missing selector must trigger an update");
        };
        assert_eq!(obj["aggregationRule"]["clusterRoleSelectors"], json!([sel]));
        assert_eq!(
            obj["rules"],
            json!([pods_get()]),
            "computed rules of an aggregated role are the controller's, not ours"
        );
    }

    fn grants(rules: &Value, verb: &str) -> bool {
        rules
            .as_array()
            .unwrap()
            .iter()
            .any(|r| strs(r, "verbs").contains(&verb))
    }

    async fn rewrite_role(store: &SqliteStore, name: &str, f: impl FnOnce(&mut Value)) {
        let k = key("clusterroles", name);
        let (mut obj, rev) = stored(store, &k).await;
        f(&mut obj);
        store
            .put(&k, Bytes::from(obj.to_string()), Some(rev))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upgraded_node_role_loses_pre_upstream_grants_so_kubelet_cannot_read_every_pods_logs() {
        // Reconcile only adds rules, so a cluster seeded before system:node was aligned with
        // upstream keeps these grants forever: every node identity could read any pod's logs
        // and status, rewrite any node's lease and list/watch every CSINode.
        let old = [
            json!({"apiGroups": [""], "resources": ["nodes/status"], "verbs": ["get","update","patch"]}),
            json!({"apiGroups": [""], "resources": ["pods/status"], "verbs": ["get","update","patch"]}),
            json!({"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]}),
            json!({"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch","delete"]}),
            json!({"apiGroups": ["storage.k8s.io"], "resources": ["csinodes"], "verbs": ["get","list","watch","create","update","patch","delete"]}),
        ];
        let store = SqliteStore::new(":memory:").unwrap();
        crate::seed_rbac(&store).await.unwrap();
        let (fresh, _) = stored(&store, &key("clusterroles", "system:node")).await;
        rewrite_role(&store, "system:node", |o| {
            o["rules"].as_array_mut().unwrap().extend(old.clone());
        })
        .await;

        crate::seed_rbac(&store).await.unwrap();

        let (obj, _) = stored(&store, &key("clusterroles", "system:node")).await;
        let got = obj["rules"].as_array().unwrap();
        for rule in &old {
            assert!(!got.contains(rule), "system:node still carries {rule}");
        }
        assert_eq!(got, fresh["rules"].as_array().unwrap());
    }

    #[tokio::test]
    async fn upgraded_cluster_loses_legacy_rules_so_admin_can_no_longer_escalate() {
        // Reconcile only adds permissions, so without legacy removal a cluster seeded before
        // bind/escalate was dropped keeps letting a namespace admin mint and bind a wildcard Role.
        for name in ["admin", "edit", "view", "system:kube-controller-manager"] {
            let store = SqliteStore::new(":memory:").unwrap();
            crate::seed_rbac(&store).await.unwrap();
            let (fresh, _) = stored(&store, &key("clusterroles", name)).await;
            rewrite_role(&store, name, |o| o["rules"] = json!(legacy_rules(name))).await;

            crate::seed_rbac(&store).await.unwrap();

            let (obj, _) = stored(&store, &key("clusterroles", name)).await;
            for legacy in legacy_rules(name) {
                assert!(
                    !obj["rules"].as_array().unwrap().contains(&legacy),
                    "{name} still carries legacy rule {legacy}"
                );
            }
            let mut got = obj["rules"].as_array().unwrap().clone();
            let mut want = fresh["rules"].as_array().unwrap().clone();
            got.sort_by_key(Value::to_string);
            want.sort_by_key(Value::to_string);
            assert_eq!(got, want, "{name} must converge to the current policy");
            if name != "system:kube-controller-manager" {
                assert!(!grants(&obj["rules"], "bind") && !grants(&obj["rules"], "escalate"));
            }
        }
    }

    #[tokio::test]
    async fn legacy_removal_keeps_operator_edited_rules_and_honors_opt_out() {
        let store = SqliteStore::new(":memory:").unwrap();
        crate::seed_rbac(&store).await.unwrap();
        let mut edited = legacy_rules("admin")[2].clone();
        edited["verbs"]
            .as_array_mut()
            .unwrap()
            .push(json!("impersonate"));
        let edited_copy = edited.clone();
        rewrite_role(&store, "admin", |o| {
            o["rules"] = json!([legacy_rules("admin")[0].clone(), edited]);
        })
        .await;
        rewrite_role(&store, "edit", |o| {
            o["metadata"]["annotations"][AUTOUPDATE_ANNOTATION] = json!("false");
            o["rules"] = json!(legacy_rules("edit"));
        })
        .await;

        crate::seed_rbac(&store).await.unwrap();

        let (admin, _) = stored(&store, &key("clusterroles", "admin")).await;
        assert!(
            admin["rules"].as_array().unwrap().contains(&edited_copy),
            "a rule that differs from the seeded legacy one is the operator's and must survive"
        );
        let (edit, _) = stored(&store, &key("clusterroles", "edit")).await;
        assert_eq!(edit["rules"], json!(legacy_rules("edit")));
    }

    #[tokio::test]
    async fn unlabelled_role_keeps_legacy_rules_since_operator_owned_roles_are_never_rewritten() {
        let store = SqliteStore::new(":memory:").unwrap();
        crate::seed_rbac(&store).await.unwrap();
        rewrite_role(&store, "admin", |o| {
            o["metadata"]["labels"]
                .as_object_mut()
                .unwrap()
                .remove(BOOTSTRAP_LABEL);
            o["rules"] = json!(legacy_rules("admin"));
        })
        .await;

        crate::seed_rbac(&store).await.unwrap();

        let (admin, _) = stored(&store, &key("clusterroles", "admin")).await;
        for legacy in legacy_rules("admin") {
            assert!(
                admin["rules"].as_array().unwrap().contains(&legacy),
                "an operator-owned role lost rule {legacy}"
            );
        }
    }

    #[tokio::test]
    async fn legacy_clusterrole_is_deleted_unless_operator_owned() {
        let store = SqliteStore::new(":memory:").unwrap();
        let name = "system:controller:storage-version-garbage-collector";
        let k = key("clusterroles", name);
        let mut obj = role(json!([pods_get()]));
        obj["metadata"]["name"] = json!(name);
        obj["metadata"]["labels"][BOOTSTRAP_LABEL] = json!(BOOTSTRAP_LABEL_VALUE);
        store
            .put(&k, Bytes::from(obj.to_string()), Some(0))
            .await
            .unwrap();

        crate::seed_rbac(&store).await.unwrap();
        assert!(
            store.get(&k).await.unwrap().is_none(),
            "a bootstrap-labelled legacy role must be removed on upgrade"
        );

        let mut mine = role(json!([pods_get()]));
        mine["metadata"]["name"] = json!(name);
        store
            .put(&k, Bytes::from(mine.to_string()), Some(0))
            .await
            .unwrap();
        crate::seed_rbac(&store).await.unwrap();
        assert!(
            store.get(&k).await.unwrap().is_some(),
            "a role without the bootstrap label belongs to the operator"
        );
    }
}
