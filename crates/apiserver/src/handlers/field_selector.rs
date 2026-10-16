//! The single source of truth for field selectors: one per-kind table of selectable fields,
//! consulted by every LIST, DELETE-collection, WATCH and the watch projection pre-filter.
//!
//! Upstream rejects any field label a kind does not declare with a 400 (the per-kind
//! `AddFieldLabelConversionFunc` in `pkg/apis/**/conversion.go`, or
//! `runtime.DefaultMetaV1FieldSelectorConversion` for kinds that register none) and evaluates
//! the accepted ones against that kind's `ToSelectableFields` set, where an absent key reads as
//! `""`. Silently ignoring an unknown label instead lets a controller's narrowed informer see
//! every object, which is how a ClusterTrustBundle publisher once deleted bundles it never owned.

use std::borrow::Cow;

use serde_json::Value;

use crate::status::{Status, StatusError};

type Func = for<'a> fn(&'a Value) -> Cow<'a, str>;

#[derive(Clone, Copy)]
enum Source {
    /// String/number/bool at a JSON path; absent reads as `""`.
    Path(&'static [&'static str]),
    /// Go `strconv.FormatBool`: absent reads as `"false"`.
    Bool(&'static [&'static str]),
    /// Go `strconv.Itoa`: absent reads as `"0"`.
    Int(&'static [&'static str]),
    Func(Func),
}

fn walk<'a>(obj: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = obj;
    for part in path {
        cur = cur.get(*part)?;
    }
    Some(cur)
}

fn str_at<'a>(obj: &'a Value, path: &[&str]) -> &'a str {
    walk(obj, path).and_then(Value::as_str).unwrap_or("")
}

impl Source {
    fn get<'a>(&self, obj: &'a Value) -> Cow<'a, str> {
        match self {
            Source::Path(path) => match walk(obj, path) {
                Some(Value::String(s)) => Cow::Borrowed(s.as_str()),
                Some(Value::Bool(b)) => Cow::Borrowed(if *b { "true" } else { "false" }),
                Some(Value::Number(n)) => Cow::Owned(n.to_string()),
                _ => Cow::Borrowed(""),
            },
            Source::Bool(path) => match walk(obj, path) {
                Some(Value::Bool(true)) => Cow::Borrowed("true"),
                _ => Cow::Borrowed("false"),
            },
            Source::Int(path) => match walk(obj, path) {
                Some(Value::Number(n)) => Cow::Owned(n.to_string()),
                _ => Cow::Borrowed("0"),
            },
            Source::Func(f) => f(obj),
        }
    }
}

/// `status.podIPs[0].ip`, falling back to the v1 `status.podIP` the internal conversion derives
/// it from.
fn pod_ip(obj: &Value) -> Cow<'_, str> {
    let first = obj["status"]["podIPs"][0]["ip"].as_str().unwrap_or("");
    Cow::Borrowed(if first.is_empty() {
        str_at(obj, &["status", "podIP"])
    } else {
        first
    })
}

/// Accepted by the Pod label conversion but absent from `ToSelectableFields`, so it always
/// reads as `""`.
fn always_empty(_: &Value) -> Cow<'_, str> {
    Cow::Borrowed("")
}

/// The core `reportingComponent` / events.k8s.io `reportingController` are one internal field.
fn event_reporting_controller(obj: &Value) -> Cow<'_, str> {
    let controller = str_at(obj, &["reportingController"]);
    Cow::Borrowed(if controller.is_empty() {
        str_at(obj, &["reportingComponent"])
    } else {
        controller
    })
}

/// `source.component`, falling back to the reporting controller (upstream's
/// `event.ToSelectableFields`).
fn event_source(obj: &Value) -> Cow<'_, str> {
    let component = str_at(obj, &["source", "component"]);
    if component.is_empty() {
        event_reporting_controller(obj)
    } else {
        Cow::Borrowed(component)
    }
}

type Def = (&'static str, Source);

const NAME: Def = ("metadata.name", Source::Path(&["metadata", "name"]));
const NAMESPACE: Def = (
    "metadata.namespace",
    Source::Path(&["metadata", "namespace"]),
);
const SIGNER_NAME: Def = ("spec.signerName", Source::Path(&["spec", "signerName"]));
const SPEC_NODE_NAME: Def = ("spec.nodeName", Source::Path(&["spec", "nodeName"]));

const INVOLVED_KIND: Source = Source::Path(&["involvedObject", "kind"]);
const INVOLVED_NAMESPACE: Source = Source::Path(&["involvedObject", "namespace"]);
const INVOLVED_NAME: Source = Source::Path(&["involvedObject", "name"]);
const INVOLVED_UID: Source = Source::Path(&["involvedObject", "uid"]);
const INVOLVED_API_VERSION: Source = Source::Path(&["involvedObject", "apiVersion"]);
const INVOLVED_RESOURCE_VERSION: Source = Source::Path(&["involvedObject", "resourceVersion"]);
const INVOLVED_FIELD_PATH: Source = Source::Path(&["involvedObject", "fieldPath"]);

static DEFAULT: &[Def] = &[NAME, NAMESPACE];

static POD: &[Def] = &[
    NAME,
    NAMESPACE,
    SPEC_NODE_NAME,
    // Old v1 clients send spec.host; upstream maps it to spec.nodeName.
    ("spec.host", Source::Path(&["spec", "nodeName"])),
    (
        "spec.restartPolicy",
        Source::Path(&["spec", "restartPolicy"]),
    ),
    (
        "spec.schedulerName",
        Source::Path(&["spec", "schedulerName"]),
    ),
    (
        "spec.serviceAccountName",
        Source::Path(&["spec", "serviceAccountName"]),
    ),
    ("spec.hostNetwork", Source::Bool(&["spec", "hostNetwork"])),
    ("status.phase", Source::Path(&["status", "phase"])),
    ("status.podIP", Source::Func(pod_ip)),
    ("status.podIPs", Source::Func(always_empty)),
    (
        "status.nominatedNodeName",
        Source::Path(&["status", "nominatedNodeName"]),
    ),
];

static NODE: &[Def] = &[
    NAME,
    (
        "spec.unschedulable",
        Source::Bool(&["spec", "unschedulable"]),
    ),
];

static REPLICATION_CONTROLLER: &[Def] = &[
    NAME,
    NAMESPACE,
    ("status.replicas", Source::Int(&["status", "replicas"])),
];

static EVENT: &[Def] = &[
    NAME,
    NAMESPACE,
    ("involvedObject.kind", INVOLVED_KIND),
    ("involvedObject.namespace", INVOLVED_NAMESPACE),
    ("involvedObject.name", INVOLVED_NAME),
    ("involvedObject.uid", INVOLVED_UID),
    ("involvedObject.apiVersion", INVOLVED_API_VERSION),
    ("involvedObject.resourceVersion", INVOLVED_RESOURCE_VERSION),
    ("involvedObject.fieldPath", INVOLVED_FIELD_PATH),
    ("reason", Source::Path(&["reason"])),
    (
        "reportingComponent",
        Source::Func(event_reporting_controller),
    ),
    ("source", Source::Func(event_source)),
    ("type", Source::Path(&["type"])),
];

static EVENTS_K8S_IO_EVENT: &[Def] = &[
    NAME,
    NAMESPACE,
    ("regarding.kind", INVOLVED_KIND),
    ("regarding.namespace", INVOLVED_NAMESPACE),
    ("regarding.name", INVOLVED_NAME),
    ("regarding.uid", INVOLVED_UID),
    ("regarding.apiVersion", INVOLVED_API_VERSION),
    ("regarding.resourceVersion", INVOLVED_RESOURCE_VERSION),
    ("regarding.fieldPath", INVOLVED_FIELD_PATH),
    ("reason", Source::Path(&["reason"])),
    (
        "reportingController",
        Source::Func(event_reporting_controller),
    ),
    ("type", Source::Path(&["type"])),
];

static NAMESPACE_KIND: &[Def] = &[NAME, ("status.phase", Source::Path(&["status", "phase"]))];

static SECRET: &[Def] = &[NAME, NAMESPACE, ("type", Source::Path(&["type"]))];

static SERVICE: &[Def] = &[
    NAME,
    NAMESPACE,
    ("spec.clusterIP", Source::Path(&["spec", "clusterIP"])),
    ("spec.type", Source::Path(&["spec", "type"])),
];

static JOB: &[Def] = &[
    NAME,
    NAMESPACE,
    ("status.successful", Source::Int(&["status", "succeeded"])),
];

static CSR_OR_CTB: &[Def] = &[NAME, SIGNER_NAME];

static POD_CERTIFICATE_REQUEST: &[Def] = &[
    NAME,
    SIGNER_NAME,
    ("spec.podName", Source::Path(&["spec", "podName"])),
    SPEC_NODE_NAME,
];

static RESOURCE_SLICE: &[Def] = &[
    NAME,
    SPEC_NODE_NAME,
    ("spec.driver", Source::Path(&["spec", "driver"])),
    ("spec.pool.name", Source::Path(&["spec", "pool", "name"])),
];

/// How upstream words the 400 for a label the kind does not accept; the three phrasings are
/// the ones each registration site hard-codes.
#[derive(Clone, Copy)]
enum Reject {
    /// `runtime.DefaultMetaV1FieldSelectorConversion`, for kinds with no conversion func.
    MetaDefault,
    Label,
    Job,
    ResourceSlice,
}

impl Reject {
    fn message(self, label: &str) -> String {
        match self {
            Reject::MetaDefault => format!(
                "\"{label}\" is not a known field selector: only \"metadata.name\", \
                 \"metadata.namespace\""
            ),
            Reject::Label => format!("field label not supported: {label}"),
            Reject::Job => format!("field label \"{label}\" not supported for Job"),
            Reject::ResourceSlice => format!(
                "field label not supported for resource.k8s.io/v1, Kind=ResourceSlice: {label}"
            ),
        }
    }
}

struct KindFields {
    fields: &'static [Def],
    reject: Reject,
}

fn kind_fields(group: &str, plural: &str) -> KindFields {
    let (fields, reject) = match (group, plural) {
        ("", "pods") => (POD, Reject::Label),
        ("", "nodes") => (NODE, Reject::Label),
        ("", "replicationcontrollers") => (REPLICATION_CONTROLLER, Reject::Label),
        ("", "events") => (EVENT, Reject::Label),
        ("events.k8s.io", "events") => (EVENTS_K8S_IO_EVENT, Reject::Label),
        ("", "namespaces") => (NAMESPACE_KIND, Reject::Label),
        ("", "secrets") => (SECRET, Reject::Label),
        ("", "services") => (SERVICE, Reject::Label),
        ("batch", "jobs") => (JOB, Reject::Job),
        ("certificates.k8s.io", "certificatesigningrequests" | "clustertrustbundles") => {
            (CSR_OR_CTB, Reject::Label)
        }
        ("certificates.k8s.io", "podcertificaterequests") => {
            (POD_CERTIFICATE_REQUEST, Reject::Label)
        }
        ("resource.k8s.io", "resourceslices") => (RESOURCE_SLICE, Reject::ResourceSlice),
        _ => (DEFAULT, Reject::MetaDefault),
    };
    KindFields { fields, reject }
}

enum Getter {
    Static(Source),
    /// A CRD-declared selectable field: arbitrary dotted JSON path, compared with the store's
    /// shared `json_path_equals` so CR LIST/WATCH and the store's own scan resolve identically.
    Json(String),
}

struct Term {
    label: String,
    getter: Getter,
    value: String,
    negated: bool,
}

impl Term {
    fn matches(&self, obj: &Value) -> bool {
        let equal = match &self.getter {
            Getter::Static(source) => source.get(obj) == self.value,
            Getter::Json(path) => u7s_store::json_path_equals(obj, path, &self.value),
        };
        equal != self.negated
    }
}

/// A parsed, kind-validated field selector. Constructed only through `parse`/`parse_cr`, so
/// holding one proves every label in it is selectable for the kind it was parsed for.
#[derive(Default)]
pub struct FieldSelector {
    terms: Vec<Term>,
}

fn split_terms(selector: &str) -> Vec<&str> {
    let mut terms = Vec::new();
    let mut start = 0;
    let mut in_slash = false;
    for (i, c) in selector.char_indices() {
        if in_slash {
            in_slash = false;
        } else if c == ',' {
            terms.push(&selector[start..i]);
            start = i + 1;
        } else if c == '\\' {
            in_slash = true;
        }
    }
    terms.push(&selector[start..]);
    terms
}

/// `fields.splitTerm`: the first position where `!=`, `==` or `=` starts.
fn split_term(term: &str) -> Option<(&str, bool, &str)> {
    for (i, _) in term.char_indices() {
        let rest = &term[i..];
        if let Some(value) = rest.strip_prefix("!=") {
            return Some((&term[..i], true, value));
        }
        if let Some(value) = rest.strip_prefix("==") {
            return Some((&term[..i], false, value));
        }
        if let Some(value) = rest.strip_prefix('=') {
            return Some((&term[..i], false, value));
        }
    }
    None
}

fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next()? {
                n @ ('\\' | ',' | '=') => out.push(n),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn parse_with(
    raw: Option<&str>,
    resolve: impl Fn(&str) -> Result<Getter, String>,
) -> Result<FieldSelector, StatusError> {
    let Some(raw) = raw else {
        return Ok(FieldSelector::default());
    };
    let mut terms = Vec::new();
    for part in split_terms(raw) {
        if part.is_empty() {
            continue;
        }
        let invalid = || {
            Status::bad_request(format!(
                "invalid selector: '{raw}'; can't understand '{part}'"
            ))
        };
        let (lhs, negated, rhs) = split_term(part).ok_or_else(invalid)?;
        let label = unescape(lhs).ok_or_else(invalid)?;
        let value = unescape(rhs).ok_or_else(invalid)?;
        let getter = resolve(&label).map_err(Status::bad_request)?;
        terms.push(Term {
            label,
            getter,
            value,
            negated,
        });
    }
    Ok(FieldSelector { terms })
}

impl FieldSelector {
    /// Parse `raw` for a built-in kind, 400 on a malformed term or a label the kind does not
    /// declare selectable. `None`/empty yields the match-everything selector.
    pub fn parse(raw: Option<&str>, group: &str, plural: &str) -> Result<Self, StatusError> {
        let kind = kind_fields(group, plural);
        parse_with(raw, |label| {
            kind.fields
                .iter()
                .find(|(l, _)| *l == label)
                .map(|(_, source)| Getter::Static(*source))
                .ok_or_else(|| kind.reject.message(label))
        })
    }

    /// Parse `raw` for a custom resource: `metadata.name`, `metadata.namespace` when namespaced,
    /// plus the CRD's declared `selectableFields` for the served version.
    pub fn parse_cr(
        raw: Option<&str>,
        namespaced: bool,
        selectable_fields: &[String],
    ) -> Result<Self, StatusError> {
        parse_with(raw, |label| {
            let selectable = label == "metadata.name"
                || (namespaced && label == "metadata.namespace")
                || selectable_fields.iter().any(|f| f == label);
            if selectable {
                Ok(Getter::Json(label.to_string()))
            } else {
                Err(format!("field label not supported: {label}"))
            }
        })
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// Every term must hold (upstream `andTerm`); absent fields read as the kind's zero value.
    pub fn matches(&self, obj: &Value) -> bool {
        self.terms.iter().all(|t| t.matches(obj))
    }

    /// `matches` as LIST sees the object: after read-time defaulting, which can fill in or
    /// alias selectable fields. For callers holding raw stored bytes they must leave unmodified.
    pub fn matches_defaulted(&self, group: &str, plural: &str, raw: &Value) -> bool {
        if self.is_empty() {
            return true;
        }
        let mut defaulted = raw.clone();
        super::defaults::apply_defaults(group, plural, &mut defaulted);
        self.matches(&defaulted)
    }

    pub fn filter(&self, items: Vec<Value>) -> Vec<Value> {
        if self.is_empty() {
            return items;
        }
        items.into_iter().filter(|i| self.matches(i)).collect()
    }

    /// True if some term pins `label` to exactly `value` (`=`/`==`, not `!=`). Terms are ANDed,
    /// so every match of this selector has `label == value`.
    pub fn requires_equal(&self, label: &str, value: &str) -> bool {
        self.terms
            .iter()
            .any(|t| !t.negated && t.label == label && t.value == value)
    }

    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.terms.iter().map(|t| t.label.as_str())
    }

    /// A store-level narrowing for LIST: the first `=` term over `metadata.name`,
    /// `metadata.namespace` or `spec.nodeName`, the indexed fields. The store sees raw stored
    /// bytes, so it may only ever return a superset of what `matches` accepts on the defaulted
    /// object (the caller still filters); read-time defaulting never rewrites these three
    /// fields, while it can fill in others (a Namespace's `status.phase`).
    pub fn store_selector(&self) -> Option<u7s_store::FieldSelector> {
        self.terms.iter().find_map(|t| {
            let indexed = matches!(
                t.label.as_str(),
                "metadata.name" | "metadata.namespace" | "spec.nodeName"
            );
            (indexed && !t.negated).then(|| u7s_store::FieldSelector {
                field: t.label.clone(),
                value: t.value.clone(),
                negated: false,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sel(raw: &str, group: &str, plural: &str) -> FieldSelector {
        FieldSelector::parse(Some(raw), group, plural)
            .unwrap_or_else(|e| panic!("{raw:?} must parse for {group}/{plural}: {}", e.1.message))
    }

    fn rejected(raw: &str, group: &str, plural: &str) -> String {
        match FieldSelector::parse(Some(raw), group, plural) {
            Ok(_) => panic!("{raw:?} must be rejected for {group}/{plural}"),
            Err(e) => {
                assert_eq!(e.0, axum::http::StatusCode::BAD_REQUEST);
                assert_eq!(e.1.reason, "BadRequest");
                assert_eq!(e.1.code, 400);
                e.1.message
            }
        }
    }

    /// The label sets upstream release-1.37 accepts per kind (`AddFieldLabelConversionFunc` in
    /// `pkg/apis/**/conversion.go`, or the metadata.name/namespace default). A kind losing or
    /// gaining a label silently changes which objects a controller's informer receives.
    #[test]
    fn table_matches_upstream_label_sets() {
        let cases: &[(&str, &str, &[&str])] = &[
            (
                "",
                "pods",
                &[
                    "metadata.name",
                    "metadata.namespace",
                    "spec.nodeName",
                    "spec.host",
                    "spec.restartPolicy",
                    "spec.schedulerName",
                    "spec.serviceAccountName",
                    "spec.hostNetwork",
                    "status.phase",
                    "status.podIP",
                    "status.podIPs",
                    "status.nominatedNodeName",
                ],
            ),
            ("", "nodes", &["metadata.name", "spec.unschedulable"]),
            (
                "",
                "replicationcontrollers",
                &["metadata.name", "metadata.namespace", "status.replicas"],
            ),
            (
                "",
                "events",
                &[
                    "metadata.name",
                    "metadata.namespace",
                    "involvedObject.kind",
                    "involvedObject.namespace",
                    "involvedObject.name",
                    "involvedObject.uid",
                    "involvedObject.apiVersion",
                    "involvedObject.resourceVersion",
                    "involvedObject.fieldPath",
                    "reason",
                    "reportingComponent",
                    "source",
                    "type",
                ],
            ),
            (
                "events.k8s.io",
                "events",
                &[
                    "metadata.name",
                    "metadata.namespace",
                    "regarding.kind",
                    "regarding.namespace",
                    "regarding.name",
                    "regarding.uid",
                    "regarding.apiVersion",
                    "regarding.resourceVersion",
                    "regarding.fieldPath",
                    "reason",
                    "reportingController",
                    "type",
                ],
            ),
            ("", "namespaces", &["metadata.name", "status.phase"]),
            (
                "",
                "secrets",
                &["metadata.name", "metadata.namespace", "type"],
            ),
            (
                "",
                "services",
                &[
                    "metadata.name",
                    "metadata.namespace",
                    "spec.clusterIP",
                    "spec.type",
                ],
            ),
            (
                "batch",
                "jobs",
                &["metadata.name", "metadata.namespace", "status.successful"],
            ),
            (
                "certificates.k8s.io",
                "certificatesigningrequests",
                &["metadata.name", "spec.signerName"],
            ),
            (
                "certificates.k8s.io",
                "clustertrustbundles",
                &["metadata.name", "spec.signerName"],
            ),
            (
                "certificates.k8s.io",
                "podcertificaterequests",
                &[
                    "metadata.name",
                    "spec.signerName",
                    "spec.podName",
                    "spec.nodeName",
                ],
            ),
            (
                "resource.k8s.io",
                "resourceslices",
                &[
                    "metadata.name",
                    "spec.nodeName",
                    "spec.driver",
                    "spec.pool.name",
                ],
            ),
            (
                "apps",
                "replicasets",
                &["metadata.name", "metadata.namespace"],
            ),
            ("", "configmaps", &["metadata.name", "metadata.namespace"]),
            (
                "storage.k8s.io",
                "volumeattachments",
                &["metadata.name", "metadata.namespace"],
            ),
        ];
        for (group, plural, labels) in cases {
            let table: Vec<&str> = kind_fields(group, plural)
                .fields
                .iter()
                .map(|(l, _)| *l)
                .collect();
            assert_eq!(&table, labels, "{group}/{plural} selectable labels");
        }
    }

    /// A label accepted with a wrong JSON path parses fine and then matches the wrong objects, so
    /// a controller's informer silently receives (or misses) objects. Each label gets a distinct
    /// value at its own path: `=value` must match and `!=value` must not.
    #[test]
    fn every_table_field_reads_its_value_from_the_right_path() {
        let involved = json!({
            "kind": "Pod", "namespace": "ev-ns", "name": "ev-pod", "uid": "ev-uid",
            "apiVersion": "ev/v9", "resourceVersion": "4711", "fieldPath": "spec.containers{c}"
        });
        #[allow(clippy::type_complexity)]
        let cases: Vec<(&str, &str, Value, Vec<(&str, &str)>)> = vec![
            (
                "",
                "pods",
                json!({
                    "metadata": {"name": "p-name", "namespace": "p-ns"},
                    "spec": {
                        "nodeName": "p-node", "restartPolicy": "OnFailure",
                        "schedulerName": "p-sched", "serviceAccountName": "p-sa",
                        "hostNetwork": true
                    },
                    "status": {
                        "phase": "Running", "podIP": "10.1.2.3",
                        "nominatedNodeName": "p-nominated"
                    }
                }),
                vec![
                    ("metadata.name", "p-name"),
                    ("metadata.namespace", "p-ns"),
                    ("spec.nodeName", "p-node"),
                    ("spec.host", "p-node"),
                    ("spec.restartPolicy", "OnFailure"),
                    ("spec.schedulerName", "p-sched"),
                    ("spec.serviceAccountName", "p-sa"),
                    ("spec.hostNetwork", "true"),
                    ("status.phase", "Running"),
                    ("status.podIP", "10.1.2.3"),
                    ("status.podIPs", ""),
                    ("status.nominatedNodeName", "p-nominated"),
                ],
            ),
            (
                "",
                "nodes",
                json!({"metadata": {"name": "n-name"}, "spec": {"unschedulable": true}}),
                vec![("metadata.name", "n-name"), ("spec.unschedulable", "true")],
            ),
            (
                "",
                "replicationcontrollers",
                json!({
                    "metadata": {"name": "rc-name", "namespace": "rc-ns"},
                    "status": {"replicas": 7}
                }),
                vec![
                    ("metadata.name", "rc-name"),
                    ("metadata.namespace", "rc-ns"),
                    ("status.replicas", "7"),
                ],
            ),
            (
                "",
                "events",
                json!({
                    "metadata": {"name": "e-name", "namespace": "e-ns"},
                    "involvedObject": involved,
                    "reason": "Scheduled", "type": "Warning",
                    "reportingComponent": "e-reporter",
                    "source": {"component": "e-source"}
                }),
                vec![
                    ("metadata.name", "e-name"),
                    ("metadata.namespace", "e-ns"),
                    ("involvedObject.kind", "Pod"),
                    ("involvedObject.namespace", "ev-ns"),
                    ("involvedObject.name", "ev-pod"),
                    ("involvedObject.uid", "ev-uid"),
                    ("involvedObject.apiVersion", "ev/v9"),
                    ("involvedObject.resourceVersion", "4711"),
                    ("involvedObject.fieldPath", "spec.containers{c}"),
                    ("reason", "Scheduled"),
                    ("reportingComponent", "e-reporter"),
                    ("source", "e-source"),
                    ("type", "Warning"),
                ],
            ),
            (
                "events.k8s.io",
                "events",
                json!({
                    "metadata": {"name": "e-name", "namespace": "e-ns"},
                    "involvedObject": involved,
                    "reason": "Scheduled", "type": "Warning",
                    "reportingController": "e-controller"
                }),
                vec![
                    ("metadata.name", "e-name"),
                    ("metadata.namespace", "e-ns"),
                    ("regarding.kind", "Pod"),
                    ("regarding.namespace", "ev-ns"),
                    ("regarding.name", "ev-pod"),
                    ("regarding.uid", "ev-uid"),
                    ("regarding.apiVersion", "ev/v9"),
                    ("regarding.resourceVersion", "4711"),
                    ("regarding.fieldPath", "spec.containers{c}"),
                    ("reason", "Scheduled"),
                    ("reportingController", "e-controller"),
                    ("type", "Warning"),
                ],
            ),
            (
                "",
                "namespaces",
                json!({"metadata": {"name": "ns-name"}, "status": {"phase": "Terminating"}}),
                vec![
                    ("metadata.name", "ns-name"),
                    ("status.phase", "Terminating"),
                ],
            ),
            (
                "",
                "secrets",
                json!({
                    "metadata": {"name": "s-name", "namespace": "s-ns"},
                    "type": "kubernetes.io/tls"
                }),
                vec![
                    ("metadata.name", "s-name"),
                    ("metadata.namespace", "s-ns"),
                    ("type", "kubernetes.io/tls"),
                ],
            ),
            (
                "",
                "services",
                json!({
                    "metadata": {"name": "svc-name", "namespace": "svc-ns"},
                    "spec": {"clusterIP": "10.96.0.9", "type": "NodePort"}
                }),
                vec![
                    ("metadata.name", "svc-name"),
                    ("metadata.namespace", "svc-ns"),
                    ("spec.clusterIP", "10.96.0.9"),
                    ("spec.type", "NodePort"),
                ],
            ),
            (
                "batch",
                "jobs",
                json!({
                    "metadata": {"name": "j-name", "namespace": "j-ns"},
                    "status": {"succeeded": 3}
                }),
                vec![
                    ("metadata.name", "j-name"),
                    ("metadata.namespace", "j-ns"),
                    ("status.successful", "3"),
                ],
            ),
            (
                "certificates.k8s.io",
                "certificatesigningrequests",
                json!({"metadata": {"name": "csr-name"}, "spec": {"signerName": "x.io/csr"}}),
                vec![
                    ("metadata.name", "csr-name"),
                    ("spec.signerName", "x.io/csr"),
                ],
            ),
            (
                "certificates.k8s.io",
                "clustertrustbundles",
                json!({"metadata": {"name": "ctb-name"}, "spec": {"signerName": "x.io/ctb"}}),
                vec![
                    ("metadata.name", "ctb-name"),
                    ("spec.signerName", "x.io/ctb"),
                ],
            ),
            (
                "certificates.k8s.io",
                "podcertificaterequests",
                json!({
                    "metadata": {"name": "pcr-name"},
                    "spec": {
                        "signerName": "x.io/pcr", "podName": "pcr-pod", "nodeName": "pcr-node"
                    }
                }),
                vec![
                    ("metadata.name", "pcr-name"),
                    ("spec.signerName", "x.io/pcr"),
                    ("spec.podName", "pcr-pod"),
                    ("spec.nodeName", "pcr-node"),
                ],
            ),
            (
                "resource.k8s.io",
                "resourceslices",
                json!({
                    "metadata": {"name": "rs-name"},
                    "spec": {"nodeName": "rs-node", "driver": "rs.driver", "pool": {"name": "rs-pool"}}
                }),
                vec![
                    ("metadata.name", "rs-name"),
                    ("spec.nodeName", "rs-node"),
                    ("spec.driver", "rs.driver"),
                    ("spec.pool.name", "rs-pool"),
                ],
            ),
        ];
        for (group, plural, obj, expected) in &cases {
            let mut covered: Vec<&str> = expected.iter().map(|(l, _)| *l).collect();
            let mut table: Vec<&str> = kind_fields(group, plural)
                .fields
                .iter()
                .map(|(l, _)| *l)
                .collect();
            covered.sort_unstable();
            table.sort_unstable();
            assert_eq!(
                covered, table,
                "{group}/{plural}: every table field needs a value assertion"
            );
            for (label, value) in expected {
                assert!(
                    sel(&format!("{label}={value}"), group, plural).matches(obj),
                    "{group}/{plural} {label}={value} must match — wrong JSON path for this field"
                );
                assert!(
                    !sel(&format!("{label}!={value}"), group, plural).matches(obj),
                    "{group}/{plural} {label}!={value} must not match"
                );
            }
        }
    }

    /// Every kind the registry serves resolves to a table that accepts `metadata.name` and
    /// rejects an undeclared label, so no served kind can fall through to "ignore everything".
    #[test]
    fn every_served_kind_resolves_to_a_table_that_rejects_unknown_labels() {
        let registry = crate::state::build_registry();
        assert!(registry.len() >= 60, "registry unexpectedly small");
        for key in registry.keys() {
            sel("metadata.name=x", &key.group, &key.plural);
            rejected("bogus.field=x", &key.group, &key.plural);
        }
        for (group, plural) in [
            ("", "pods"),
            ("", "namespaces"),
            ("apiextensions.k8s.io", "customresourcedefinitions"),
        ] {
            sel("metadata.name=x", group, plural);
            rejected("bogus.field=x", group, plural);
        }
    }

    #[test]
    fn unsupported_label_is_400_with_upstream_wording_per_registration_site() {
        assert_eq!(
            rejected("bogus.field=x", "", "pods"),
            "field label not supported: bogus.field"
        );
        assert_eq!(
            rejected("bogus.field=x", "apps", "deployments"),
            "\"bogus.field\" is not a known field selector: only \"metadata.name\", \
             \"metadata.namespace\""
        );
        assert_eq!(
            rejected("bogus=x", "batch", "jobs"),
            "field label \"bogus\" not supported for Job"
        );
        assert_eq!(
            rejected("bogus=x", "resource.k8s.io", "resourceslices"),
            "field label not supported for resource.k8s.io/v1, Kind=ResourceSlice: bogus"
        );
    }

    /// A ClusterTrustBundle/CSR publisher watching `spec.signerName` must keep working, and the
    /// same label on a kind that does not declare it must fail instead of widening to "all".
    #[test]
    fn signer_name_is_selectable_only_where_upstream_declares_it() {
        sel(
            "spec.signerName=x",
            "certificates.k8s.io",
            "clustertrustbundles",
        );
        sel(
            "spec.signerName=x",
            "certificates.k8s.io",
            "certificatesigningrequests",
        );
        rejected("spec.signerName=x", "", "configmaps");
    }

    /// Upstream's per-kind conversion funcs differ on `metadata.namespace`: Node, Namespace,
    /// CSR, CTB and PodCertificateRequest do not accept it, so sending it must be a 400, not a
    /// silently empty or silently full result.
    #[test]
    fn metadata_namespace_rejected_where_upstream_conversion_omits_it() {
        for (group, plural) in [
            ("", "nodes"),
            ("", "namespaces"),
            ("certificates.k8s.io", "certificatesigningrequests"),
            ("certificates.k8s.io", "clustertrustbundles"),
            ("certificates.k8s.io", "podcertificaterequests"),
            ("resource.k8s.io", "resourceslices"),
        ] {
            rejected("metadata.namespace=x", group, plural);
        }
        sel("metadata.namespace=x", "", "pods");
        sel("metadata.namespace=x", "storage.k8s.io", "storageclasses");
    }

    #[test]
    fn empty_and_absent_selectors_match_everything() {
        let obj = json!({"metadata": {"name": "a"}});
        for raw in [None, Some(""), Some(",")] {
            let s = FieldSelector::parse(raw, "", "pods").unwrap_or_else(|e| {
                panic!("{raw:?} must parse: {}", e.1.message);
            });
            assert!(s.is_empty());
            assert!(s.matches(&obj));
        }
    }

    /// `=`, `==` and `!=` per `fields.ParseSelector`; terms AND together.
    #[test]
    fn operators_follow_upstream_parse_selector() {
        let pod = json!({"metadata": {"name": "p"}, "status": {"phase": "Running"}});
        assert!(sel("status.phase=Running", "", "pods").matches(&pod));
        assert!(sel("status.phase==Running", "", "pods").matches(&pod));
        assert!(!sel("status.phase!=Running", "", "pods").matches(&pod));
        assert!(sel("status.phase!=Failed,status.phase!=Succeeded", "", "pods").matches(&pod));
        assert!(!sel("status.phase=Running,metadata.name=q", "", "pods").matches(&pod));
    }

    /// Un-scheduled pods have no `spec.nodeName` key; `spec.nodeName=` is how the scheduler
    /// selects them, so an absent field must read as "".
    #[test]
    fn absent_field_reads_as_empty_string() {
        let unscheduled = json!({"metadata": {"name": "p"}});
        assert!(sel("spec.nodeName=", "", "pods").matches(&unscheduled));
        assert!(!sel("spec.nodeName!=", "", "pods").matches(&unscheduled));
        assert!(!sel("spec.nodeName=n1", "", "pods").matches(&unscheduled));
        assert!(sel("spec.nodeName!=n1", "", "pods").matches(&unscheduled));
    }

    #[test]
    fn bool_and_int_fields_use_go_zero_values() {
        let node = json!({"metadata": {"name": "n"}, "spec": {}});
        assert!(sel("spec.unschedulable=false", "", "nodes").matches(&node));
        let cordoned = json!({"metadata": {"name": "n"}, "spec": {"unschedulable": true}});
        assert!(sel("spec.unschedulable=true", "", "nodes").matches(&cordoned));
        assert!(!sel("spec.unschedulable=false", "", "nodes").matches(&cordoned));
        let job = json!({"metadata": {"name": "j"}});
        assert!(sel("status.successful=0", "batch", "jobs").matches(&job));
        let done = json!({"metadata": {"name": "j"}, "status": {"succeeded": 3}});
        assert!(sel("status.successful=3", "batch", "jobs").matches(&done));
    }

    #[test]
    fn pod_ip_prefers_pod_ips_and_spec_host_aliases_node_name() {
        let pod = json!({
            "spec": {"nodeName": "n1"},
            "status": {"podIP": "10.0.0.9", "podIPs": [{"ip": "10.0.0.1"}]}
        });
        assert!(sel("status.podIP=10.0.0.1", "", "pods").matches(&pod));
        let v1_only = json!({"status": {"podIP": "10.0.0.9"}});
        assert!(sel("status.podIP=10.0.0.9", "", "pods").matches(&v1_only));
        assert!(sel("spec.host=n1", "", "pods").matches(&pod));
    }

    /// kubectl describe and client-go send both core and events.k8s.io spellings; they must
    /// read the same stored event.
    #[test]
    fn event_aliases_read_the_same_object() {
        let ev = json!({
            "involvedObject": {"name": "web", "kind": "Pod"},
            "reportingController": "kubelet",
            "reason": "Pulled"
        });
        assert!(sel("involvedObject.name=web", "", "events").matches(&ev));
        assert!(sel("regarding.name=web", "events.k8s.io", "events").matches(&ev));
        assert!(sel("source=kubelet", "", "events").matches(&ev));
        assert!(sel("reportingComponent=kubelet", "", "events").matches(&ev));
        assert!(sel("reportingController=kubelet", "events.k8s.io", "events").matches(&ev));
        let with_source = json!({"source": {"component": "scheduler"}, "reportingController": "x"});
        assert!(sel("source=scheduler", "", "events").matches(&with_source));
        rejected("source=kubelet", "events.k8s.io", "events");
        rejected("reportingController=kubelet", "", "events");
    }

    #[test]
    fn malformed_terms_are_400() {
        assert!(rejected("metadata.name", "", "pods").starts_with("invalid selector"));
        assert!(rejected("spec.nodeName!n", "", "pods").starts_with("invalid selector"));
        rejected("=foo", "", "pods");
    }

    #[test]
    fn escaped_comma_and_equals_in_values_survive_parsing() {
        let obj = json!({"metadata": {"name": "a,b=c"}});
        assert!(sel(r"metadata.name=a\,b\=c", "", "pods").matches(&obj));
    }

    #[test]
    fn requires_equal_reads_escapes_like_upstream_so_authz_cannot_be_smuggled_past() {
        let s = |raw| sel(raw, "", "pods");
        assert!(s("spec.nodeName=a,status.phase!=x").requires_equal("spec.nodeName", "a"));
        assert!(s("spec.nodeName==a").requires_equal("spec.nodeName", "a"));
        assert!(!s("spec.nodeName!=a").requires_equal("spec.nodeName", "a"));
        // `\,` stays inside the status.phase value: there is no spec.nodeName term at all.
        assert!(!s(r"status.phase!=Foo\,spec.nodeName=a").requires_equal("spec.nodeName", "a"));
        // `\=` is a literal `=` in the value; `\\` a literal backslash that does not escape `,`.
        assert!(s(r"spec.nodeName=a\=b").requires_equal("spec.nodeName", "a=b"));
        assert!(s(r"status.phase=x\\,spec.nodeName=a").requires_equal("spec.nodeName", "a"));
        assert!(s(r"status.phase=x\\").requires_equal("status.phase", r"x\"));
    }

    #[test]
    fn cr_selector_allows_only_name_namespace_and_declared_fields() {
        let declared = vec!["spec.host".to_string()];
        let obj = json!({"metadata": {"name": "a", "namespace": "ns"}, "spec": {"host": "h1"}});
        let ok =
            FieldSelector::parse_cr(Some("spec.host=h1,metadata.namespace=ns"), true, &declared)
                .unwrap_or_else(|e| panic!("declared fields must parse: {}", e.1.message));
        assert!(ok.matches(&obj));
        assert!(FieldSelector::parse_cr(Some("spec.secret=x"), true, &declared).is_err());
        assert!(
            FieldSelector::parse_cr(Some("metadata.namespace=ns"), false, &declared).is_err(),
            "cluster-scoped CRs have no selectable metadata.namespace"
        );
    }

    #[test]
    fn store_selector_pushes_only_fields_defaulting_never_rewrites() {
        let fs = sel("status.phase!=Failed,spec.nodeName=n1", "", "pods")
            .store_selector()
            .expect("an = term over an indexed field narrows the store scan");
        assert_eq!(
            (fs.field.as_str(), fs.value.as_str(), fs.negated),
            ("spec.nodeName", "n1", false)
        );
        assert!(sel("spec.nodeName!=n1", "", "pods")
            .store_selector()
            .is_none());
        for (raw, group, plural, why) in [
            (
                "status.phase=Active",
                "",
                "namespaces",
                "read-time defaulting fills status.phase, so the raw-bytes store scan would drop it",
            ),
            (
                "spec.unschedulable=false",
                "",
                "nodes",
                "a bool field reads absent as false; the store's path compare must not pre-filter it",
            ),
            (
                "status.podIP=1.2.3.4",
                "",
                "pods",
                "podIP comes from podIPs[0]; a plain status.podIP scan would drop matching pods",
            ),
        ] {
            assert!(sel(raw, group, plural).store_selector().is_none(), "{raw}: {why}");
        }
    }
}
