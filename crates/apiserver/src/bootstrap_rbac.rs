//! Upstream-style reconciliation of bootstrap RBAC objects at startup.
//!
//! Mirrors `ensureRBACPolicy` / `ReconcileRoleOptions` / `ReconcileRoleBindingOptions`: a missing
//! object is created; an existing one is brought up to the bootstrap policy by *adding* missing
//! rules, subjects, labels and annotations, never removing anything an operator added; an
//! object annotated `rbac.authorization.kubernetes.io/autoupdate: "false"` is left alone.

use bytes::Bytes;
use serde_json::{json, Value};
use u7s_store::{Store, StoreError};

use crate::SqliteStore;

const AUTOUPDATE_ANNOTATION: &str = "rbac.authorization.kubernetes.io/autoupdate";
const BOOTSTRAP_LABEL: &str = "kubernetes.io/bootstrapping";
const BOOTSTRAP_LABEL_VALUE: &str = "rbac-defaults";
const MAX_ATTEMPTS: usize = 5;

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
            || h.strip_suffix("/*")
                .is_some_and(|res| want.split_once('/').is_some_and(|(r, _)| r == res))
    })
}

fn url_matches(have: &[&str], want: &str) -> bool {
    have.iter()
        .any(|h| *h == want || h.strip_suffix('*').is_some_and(|p| want.starts_with(p)))
}

/// True when every (group, resource, verb[, name]) and every (url, verb) tuple granted by `rule`
/// is granted by some single rule in `have`. Like upstream's `Covers`, a rule carrying both
/// resources and nonResourceURLs is split into both kinds of tuples and all must be covered.
fn rules_cover(have: &[Value], rule: &Value) -> bool {
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

/// Computes what must change on `existing` to satisfy `expected`, without ever removing
/// operator additions.
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
        let have = list(existing, "rules");
        let mut rules = have.to_vec();
        for r in list(expected, "rules") {
            if !rules_cover(have, r) {
                changes.push(format!(
                    "rule {}/{}",
                    strs(r, "apiGroups").join(","),
                    strs(r, "resources").join(",")
                ));
                rules.push(r.clone());
            }
        }
        if rules.len() != have.len() {
            obj["rules"] = Value::Array(rules);
        }
    }

    if changes.is_empty() {
        Reconciled::Unchanged
    } else {
        Reconciled::Update(obj, changes.join(", "))
    }
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
                    .map(|_| tracing::info!("reconciled {kind} {name}: added {what}")),
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
}
