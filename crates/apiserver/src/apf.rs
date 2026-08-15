// API Priority and Fairness (APF) request-classification engine.
//
// Matches an incoming request against the cluster's FlowSchemas (ordered by
// `matchingPrecedence`, ties broken alphabetically by name — mirrors upstream
// `k8s.io/apiserver/pkg/util/apihelpers.FlowSchemaSequence`) to find the first
// FlowSchema whose rules match, then resolves the PriorityLevelConfiguration it
// references. `auth.rs` uses this to set the `X-Kubernetes-PF-FlowSchema-UID` /
// `X-Kubernetes-PF-PriorityLevel-UID` response headers real kube-apiserver always
// sets — see `staging/.../apiserver/pkg/server/filters/priority-and-fairness.go`'s
// `setResponseHeaders` upstream. This module is classification-only: it does not
// implement queuing/concurrency-limiting, so the upstream flow-distinguisher hash
// (used only to pick a fair-queuing shard) is deliberately not ported here — it
// would have no caller until a concurrency-limiting follow-on adds the queue it
// feeds. Note also that upstream never surfaces the distinguisher as a response
// header either way — only the two UIDs above are, per
// `ResponseHeaderMatchedFlowSchemaUID` / `ResponseHeaderMatchedPriorityLevelConfigurationUID`
// in `k8s.io/api/flowcontrol/v1/types.go`.

// ---------------------------------------------------------------------------
// Typed FlowSchema / PriorityLevelConfiguration shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ObjectMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uid: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct FlowSchemaObj {
    #[serde(default)]
    pub metadata: ObjectMeta,
    pub spec: FlowSchemaSpec,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct FlowSchemaSpec {
    #[serde(rename = "matchingPrecedence", default)]
    pub matching_precedence: i64,
    #[serde(rename = "priorityLevelConfiguration")]
    pub priority_level_configuration: PriorityLevelRef,
    #[serde(default)]
    pub rules: Vec<PolicyRulesWithSubjects>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PriorityLevelRef {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyRulesWithSubjects {
    #[serde(default)]
    pub subjects: Vec<Subject>,
    #[serde(rename = "resourceRules", default)]
    pub resource_rules: Vec<ResourcePolicyRule>,
    #[serde(rename = "nonResourceRules", default)]
    pub non_resource_rules: Vec<NonResourcePolicyRule>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Subject {
    pub kind: String,
    #[serde(default)]
    pub user: Option<NamedSubject>,
    #[serde(default)]
    pub group: Option<NamedSubject>,
    #[serde(rename = "serviceAccount", default)]
    pub service_account: Option<ServiceAccountSubject>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct NamedSubject {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServiceAccountSubject {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ResourcePolicyRule {
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(rename = "apiGroups", default)]
    pub api_groups: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(rename = "clusterScope", default)]
    pub cluster_scope: bool,
    #[serde(default)]
    pub namespaces: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct NonResourcePolicyRule {
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(rename = "nonResourceURLs", default)]
    pub non_resource_urls: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PriorityLevelObj {
    #[serde(default)]
    pub metadata: ObjectMeta,
}

// ---------------------------------------------------------------------------
// RequestDigest — the request-shaped facts classification matches against
// ---------------------------------------------------------------------------

/// Everything `classify` needs to know about one request. Mirrors upstream's
/// `RequestDigest` (RequestInfo + user.Info), built from the same
/// group/version/resource/verb/namespace facts `auth.rs` already computed for
/// RBAC authorization — never re-derived from the raw path.
pub struct RequestDigest<'a> {
    pub username: &'a str,
    pub groups: &'a [String],
    pub verb: &'a str,
    pub api_group: &'a str,
    pub resource: &'a str,
    pub subresource: &'a str,
    pub namespace: Option<&'a str>,
    pub is_resource_request: bool,
    /// Raw request path — only consulted for non-resource requests.
    pub path: &'a str,
}

/// The two UIDs surfaced as response headers once a request has been classified.
pub struct Classification {
    pub flow_schema_uid: String,
    pub priority_level_uid: String,
}

const WILDCARD: &str = "*";

fn contains_or_wildcard(list: &[String], value: &str, wildcard: &str) -> bool {
    if list.len() == 1 && list[0] == wildcard {
        return true;
    }
    list.iter().any(|v| v == value)
}

fn matches_subject(subject: &Subject, username: &str, groups: &[String]) -> bool {
    match subject.kind.as_str() {
        "User" => subject
            .user
            .as_ref()
            .is_some_and(|u| u.name == WILDCARD || u.name == username),
        "Group" => match &subject.group {
            Some(g) if g.name == WILDCARD => true,
            Some(g) => groups.iter().any(|grp| grp == &g.name),
            None => false,
        },
        "ServiceAccount" => match &subject.service_account {
            Some(sa) if sa.name == WILDCARD => {
                service_account_matches_namespace(&sa.namespace, username)
            }
            Some(sa) => username == format!("system:serviceaccount:{}:{}", sa.namespace, sa.name),
            None => false,
        },
        _ => false,
    }
}

/// Port of upstream's `serviceAccountMatchesNamespace`: true when `username` is a
/// service-account identity (`system:serviceaccount:<ns>:<name>`) whose namespace
/// segment is exactly `namespace`, for any service-account name.
fn service_account_matches_namespace(namespace: &str, username: &str) -> bool {
    const PREFIX: &str = "system:serviceaccount:";
    let Some(rest) = username.strip_prefix(PREFIX) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(namespace) else {
        return false;
    };
    rest.starts_with(':')
}

fn matches_resource_rule(rule: &ResourcePolicyRule, digest: &RequestDigest) -> bool {
    if !contains_or_wildcard(&rule.verbs, digest.verb, WILDCARD) {
        return false;
    }
    let joined = if digest.subresource.is_empty() {
        digest.resource.to_owned()
    } else {
        format!("{}/{}", digest.resource, digest.subresource)
    };
    if !contains_or_wildcard(&rule.resources, &joined, WILDCARD) {
        return false;
    }
    if !contains_or_wildcard(&rule.api_groups, digest.api_group, WILDCARD) {
        return false;
    }
    match digest.namespace {
        None => rule.cluster_scope,
        Some(ns) => contains_or_wildcard(&rule.namespaces, ns, WILDCARD),
    }
}

fn matches_non_resource_rule(rule: &NonResourcePolicyRule, digest: &RequestDigest) -> bool {
    if !contains_or_wildcard(&rule.verbs, digest.verb, WILDCARD) {
        return false;
    }
    rule.non_resource_urls.iter().any(|rule_path| {
        if rule_path == WILDCARD || rule_path == digest.path {
            return true;
        }
        let mut prefix = rule_path.trim_end_matches('*').to_owned();
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        digest.path.starts_with(&prefix)
    })
}

fn matches_policy_rule(rule: &PolicyRulesWithSubjects, digest: &RequestDigest) -> bool {
    if !rule
        .subjects
        .iter()
        .any(|s| matches_subject(s, digest.username, digest.groups))
    {
        return false;
    }
    if digest.is_resource_request {
        rule.resource_rules
            .iter()
            .any(|r| matches_resource_rule(r, digest))
    } else {
        rule.non_resource_rules
            .iter()
            .any(|r| matches_non_resource_rule(r, digest))
    }
}

fn matches_flow_schema(fs: &FlowSchemaObj, digest: &RequestDigest) -> bool {
    fs.spec.rules.iter().any(|r| matches_policy_rule(r, digest))
}

/// Classify `digest` against `flow_schemas` (evaluated in `matchingPrecedence`
/// order, first match wins — see upstream `configController.startRequest`) and
/// resolve the matched FlowSchema's `priorityLevelConfiguration.name` against
/// `priority_levels`. Returns `None` when no FlowSchema matches (should not
/// happen once the mandatory catch-all/exempt FlowSchemas exist) or the matched
/// FlowSchema references a PriorityLevelConfiguration that does not exist
/// (a "dangling" reference — see `handlers::resource::write_flowcontrol_status`
/// for how that is surfaced on the FlowSchema object itself).
pub fn classify(
    flow_schemas: &[FlowSchemaObj],
    priority_levels: &[PriorityLevelObj],
    digest: &RequestDigest,
) -> Option<Classification> {
    let mut ordered: Vec<&FlowSchemaObj> = flow_schemas.iter().collect();
    ordered.sort_by(|a, b| {
        a.spec
            .matching_precedence
            .cmp(&b.spec.matching_precedence)
            .then_with(|| a.metadata.name.cmp(&b.metadata.name))
    });
    let matched = ordered
        .into_iter()
        .find(|fs| matches_flow_schema(fs, digest))?;
    let pl = priority_levels
        .iter()
        .find(|pl| pl.metadata.name == matched.spec.priority_level_configuration.name)?;
    Some(Classification {
        flow_schema_uid: matched.metadata.uid.clone(),
        priority_level_uid: pl.metadata.uid.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs(
        name: &str,
        precedence: i64,
        pl_name: &str,
        rules: Vec<PolicyRulesWithSubjects>,
    ) -> FlowSchemaObj {
        FlowSchemaObj {
            metadata: ObjectMeta {
                name: name.to_owned(),
                uid: format!("{name}-uid"),
            },
            spec: FlowSchemaSpec {
                matching_precedence: precedence,
                priority_level_configuration: PriorityLevelRef {
                    name: pl_name.to_owned(),
                },
                rules,
            },
        }
    }

    fn pl(name: &str) -> PriorityLevelObj {
        PriorityLevelObj {
            metadata: ObjectMeta {
                name: name.to_owned(),
                uid: format!("{name}-uid"),
            },
        }
    }

    fn user_rule(username: &str) -> PolicyRulesWithSubjects {
        PolicyRulesWithSubjects {
            subjects: vec![Subject {
                kind: "User".to_owned(),
                user: Some(NamedSubject {
                    name: username.to_owned(),
                }),
                group: None,
                service_account: None,
            }],
            resource_rules: vec![ResourcePolicyRule {
                verbs: vec![WILDCARD.to_owned()],
                api_groups: vec![WILDCARD.to_owned()],
                resources: vec![WILDCARD.to_owned()],
                cluster_scope: true,
                namespaces: vec![],
            }],
            non_resource_rules: vec![NonResourcePolicyRule {
                verbs: vec![WILDCARD.to_owned()],
                non_resource_urls: vec![WILDCARD.to_owned()],
            }],
        }
    }

    fn digest<'a>(username: &'a str, groups: &'a [String], path: &'a str) -> RequestDigest<'a> {
        RequestDigest {
            username,
            groups,
            verb: "get",
            api_group: "",
            resource: "",
            subresource: "",
            namespace: None,
            is_resource_request: false,
            path,
        }
    }

    // A FlowSchema can list several rules; upstream semantics are "the first FlowSchema
    // (in matchingPrecedence order) whose subjects+resource/non-resource rules match wins" —
    // not "whichever FlowSchema is somehow 'best'". If classify ignored matchingPrecedence
    // ordering and just picked whichever FlowSchema happened to be iterated first, a
    // low-precedence catch-all could silently steal traffic meant for a more specific,
    // higher-precedence FlowSchema — which is exactly the bug class matchingPrecedence
    // exists to prevent.
    #[test]
    fn flowschema_matcher_selects_first_matching_rule_because_upstream_semantics_are_first_match_wins_not_all_match(
    ) {
        let groups = vec!["system:authenticated".to_owned()];
        let schemas = vec![
            fs(
                "low-precedence",
                9000,
                "global-default",
                vec![user_rule("*")],
            ),
            fs("high-precedence", 100, "custom", vec![user_rule("noxu")]),
        ];
        let pls = vec![pl("global-default"), pl("custom")];

        let d = digest("noxu", &groups, "/version");
        let got = classify(&schemas, &pls, &d).expect("catch-all rule always matches");
        assert_eq!(
            got.priority_level_uid, "custom-uid",
            "the lower matchingPrecedence FlowSchema ('high-precedence'=100) must win over \
             the higher one (9000) even though both match — first-match-wins by ascending \
             precedence is the whole point of matchingPrecedence existing"
        );
    }

    // Without a working fallback, any user not covered by a name-specific rule would get no
    // classification at all (empty response headers), which is exactly the conformance-test
    // assertion this fixes: "non-empty UID... for a non-matching user".
    #[test]
    fn classify_falls_back_to_catch_all_rule_for_a_user_the_specific_flowschema_does_not_name() {
        let groups = vec!["system:authenticated".to_owned()];
        let schemas = vec![
            fs("specific", 1000, "specific-pl", vec![user_rule("noxu")]),
            fs("catch-all", 10000, "catch-all-pl", vec![user_rule("*")]),
        ];
        let pls = vec![pl("specific-pl"), pl("catch-all-pl")];

        let d = digest("foo", &groups, "/version");
        let got = classify(&schemas, &pls, &d).expect("catch-all must match every user");
        assert_eq!(got.priority_level_uid, "catch-all-pl-uid");
    }

    // A FlowSchema that references a PriorityLevelConfiguration which does not exist (a
    // "dangling" reference) must not be treated as classified — surfacing a UID for a
    // priority level that was never created would be worse than surfacing nothing, since a
    // caller correlating the header against `kubectl get prioritylevelconfigurations` would
    // never find it.
    #[test]
    fn classify_returns_none_when_matched_flowschema_references_a_dangling_priority_level() {
        let groups = vec!["system:authenticated".to_owned()];
        let schemas = vec![fs("dangling", 100, "does-not-exist", vec![user_rule("*")])];
        let pls = vec![pl("some-other-pl")];

        let d = digest("noxu", &groups, "/version");
        assert!(
            classify(&schemas, &pls, &d).is_none(),
            "a FlowSchema referencing a nonexistent PriorityLevelConfiguration must not \
             produce a classification"
        );
    }

    #[test]
    fn matches_subject_group_wildcard_matches_any_group_because_star_means_all_groups() {
        let subject = Subject {
            kind: "Group".to_owned(),
            user: None,
            group: Some(NamedSubject {
                name: WILDCARD.to_owned(),
            }),
            service_account: None,
        };
        assert!(matches_subject(
            &subject,
            "anyone",
            &["some-random-group".to_owned()]
        ));
    }

    #[test]
    fn matches_subject_service_account_wildcard_name_requires_matching_namespace_only() {
        let subject = Subject {
            kind: "ServiceAccount".to_owned(),
            user: None,
            group: None,
            service_account: Some(ServiceAccountSubject {
                name: WILDCARD.to_owned(),
                namespace: "kube-system".to_owned(),
            }),
        };
        assert!(
            matches_subject(
                &subject,
                "system:serviceaccount:kube-system:endpoint-controller",
                &[]
            ),
            "wildcard SA name must match any SA name within the specified namespace"
        );
        assert!(
            !matches_subject(
                &subject,
                "system:serviceaccount:default:endpoint-controller",
                &[]
            ),
            "wildcard SA name must not match a different namespace"
        );
    }

    // Resource-rule matching is AND across verb/resource/apiGroup/scope, not OR — a rule
    // naming the right verb but wrong resource must not match. If this degraded to OR, RBAC-
    // adjacent FlowSchema rules meant to scope narrowly (e.g. "get/list on pods only") would
    // instead match every verb on every resource, defeating the whole point of narrow rules.
    #[test]
    fn matches_resource_rule_requires_verb_and_resource_and_api_group_all_to_match() {
        let rule = ResourcePolicyRule {
            verbs: vec!["get".to_owned()],
            api_groups: vec!["".to_owned()],
            resources: vec!["pods".to_owned()],
            cluster_scope: true,
            namespaces: vec![],
        };
        let groups = vec![];
        let mut d = digest("u", &groups, "");
        d.is_resource_request = true;
        d.verb = "get";
        d.resource = "pods";
        d.api_group = "";
        assert!(matches_resource_rule(&rule, &d), "exact match must pass");

        d.resource = "secrets";
        assert!(
            !matches_resource_rule(&rule, &d),
            "verb matches but resource differs — must not match"
        );
    }

    // A non-resource rule's URL entries can be exact paths, "*", or a "/prefix/*" glob.
    // Getting the prefix boundary wrong (e.g. matching "/healthzevil" against rule
    // "/healthz*") would let a FlowSchema meant to scope health-check probes narrowly also
    // classify unrelated paths that merely share a string prefix. Per upstream
    // `matchPolicyRuleNonResourceURL`, the glob only covers paths *under* the prefix
    // (a trailing '/'-delimited segment) — the bare prefix itself is not covered unless
    // it is also listed as its own exact entry, which is why real FlowSchemas list both
    // "/healthz" and "/healthz*"-style entries when they need both.
    #[test]
    fn matches_non_resource_rule_prefix_glob_respects_path_segment_boundary() {
        let rule = NonResourcePolicyRule {
            verbs: vec![WILDCARD.to_owned()],
            non_resource_urls: vec!["/healthz*".to_owned()],
        };
        let groups = vec![];
        let mut d = digest("u", &groups, "/healthz/etcd");
        assert!(
            matches_non_resource_rule(&rule, &d),
            "a path nested under the glob's prefix must match"
        );
        d.path = "/healthzevil";
        assert!(
            !matches_non_resource_rule(&rule, &d),
            "a path that merely shares the string prefix (not a '/'-delimited segment) \
             must not match"
        );
    }
}
