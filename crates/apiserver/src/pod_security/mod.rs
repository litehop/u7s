//! PodSecurity admission: a port of k8s.io/pod-security-admission (release-1.37) and the
//! kube-apiserver `PodSecurity` plugin.
//!
//! Namespace labels `pod-security.kubernetes.io/{enforce,audit,warn}[-version]` select a
//! (level, version) per mode. `enforce` rejects pods, `warn` adds `Warning` headers, and
//! `audit` records what upstream would put on the audit event (see [`crate::warnings`]; there
//! is no audit log to receive them yet). Pod-template-bearing workloads are evaluated for
//! warn/audit only. Namespace creates/updates validate the labels, and raising the enforce
//! level warns about existing pods that would now violate it.

mod checks;
mod config;

use std::collections::BTreeMap;

use serde_json::Value;
use u7s_store::{ListOptions, Store};

use crate::admission::AdmissionContext;
use crate::keys::{cluster_object_key, list_prefix, object_key};
use crate::state::AppState;
use crate::status::{Status, StatusError};
use crate::warnings;

pub use checks::AggregateResult;
pub use config::{load_config_file, Config};

const ENFORCE_LEVEL_LABEL: &str = "pod-security.kubernetes.io/enforce";
const ENFORCE_VERSION_LABEL: &str = "pod-security.kubernetes.io/enforce-version";
const AUDIT_LEVEL_LABEL: &str = "pod-security.kubernetes.io/audit";
const AUDIT_VERSION_LABEL: &str = "pod-security.kubernetes.io/audit-version";
const WARN_LEVEL_LABEL: &str = "pod-security.kubernetes.io/warn";
const WARN_VERSION_LABEL: &str = "pod-security.kubernetes.io/warn-version";

const ENFORCED_POLICY_ANNOTATION: &str = "enforce-policy";
const AUDIT_VIOLATIONS_ANNOTATION: &str = "audit-violations";
const EXEMPTION_REASON_ANNOTATION: &str = "exempt";

const NAMESPACE_MAX_PODS_TO_CHECK: usize = 3000;
const NAMESPACE_POD_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Privileged,
    Baseline,
    Restricted,
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Level::Privileged => "privileged",
            Level::Baseline => "baseline",
            Level::Restricted => "restricted",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Latest,
    Minor(u32),
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Version::Latest => f.write_str("latest"),
            Version::Minor(m) => write!(f, "v1.{m}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LevelVersion {
    pub level: Level,
    pub version: Version,
}

impl LevelVersion {
    pub const PRIVILEGED_LATEST: LevelVersion = LevelVersion {
        level: Level::Privileged,
        version: Version::Latest,
    };

    /// Two privileged policies are equivalent regardless of version.
    fn equivalent(&self, other: &LevelVersion) -> bool {
        (self.level == Level::Privileged && other.level == Level::Privileged) || self == other
    }
}

impl std::fmt::Display for LevelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.level, self.version)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub enforce: LevelVersion,
    pub audit: LevelVersion,
    pub warn: LevelVersion,
}

impl Policy {
    pub const PRIVILEGED: Policy = Policy {
        enforce: LevelVersion::PRIVILEGED_LATEST,
        audit: LevelVersion::PRIVILEGED_LATEST,
        warn: LevelVersion::PRIVILEGED_LATEST,
    };

    fn fully_privileged(&self) -> bool {
        self.enforce.level == Level::Privileged
            && self.audit.level == Level::Privileged
            && self.warn.level == Level::Privileged
    }

    fn equivalent(&self, other: &Policy) -> bool {
        self.enforce.equivalent(&other.enforce)
            && self.audit.equivalent(&other.audit)
            && self.warn.equivalent(&other.warn)
    }
}

fn parse_level(s: &str) -> Result<Level, &'static str> {
    match s {
        "privileged" => Ok(Level::Privileged),
        "baseline" => Ok(Level::Baseline),
        "restricted" => Ok(Level::Restricted),
        _ => Err("must be one of privileged, baseline, restricted"),
    }
}

/// `latest` or `v1.N` (no leading zeros).
fn parse_version(s: &str) -> Result<Version, &'static str> {
    const ERR: &str = "must be \"latest\" or \"v1.x\"";
    if s == "latest" {
        return Ok(Version::Latest);
    }
    let minor = s.strip_prefix("v1.").ok_or(ERR)?;
    let valid = !minor.is_empty()
        && minor.bytes().all(|b| b.is_ascii_digit())
        && (minor == "0" || !minor.starts_with('0'));
    if !valid {
        return Err(ERR);
    }
    minor.parse::<u32>().map(Version::Minor).map_err(|_| ERR)
}

/// An invalid pod-security label on a Namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelError {
    label: &'static str,
    value: String,
    detail: &'static str,
}

impl LabelError {
    fn field(&self) -> String {
        format!("metadata.labels[{}]", self.label)
    }

    fn message(&self) -> String {
        format!("Invalid value: {}: {}", go_quote(&self.value), self.detail)
    }
}

impl std::fmt::Display for LabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field(), self.message())
    }
}

/// Go's aggregate error text: the lone message, or `[a, b]`.
fn aggregate(errs: &[LabelError]) -> String {
    let msgs: Vec<String> = errs.iter().map(ToString::to_string).collect();
    if msgs.len() == 1 {
        msgs[0].clone()
    } else {
        format!("[{}]", msgs.join(", "))
    }
}

fn go_quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""))
}

/// The policy a namespace's labels select, falling back to `defaults` per unset label. A
/// usable policy is always returned: an unparseable enforce level means `restricted` (fail
/// closed), an unparseable audit/warn level means `privileged` (fail open), an unparseable
/// version means `latest`.
fn policy_to_evaluate(
    labels: &BTreeMap<String, String>,
    defaults: &Policy,
) -> (Policy, Vec<LabelError>) {
    let mut p = *defaults;
    let mut errs = Vec::new();
    if labels.is_empty() {
        return (p, errs);
    }

    let mut has_enforce_level = false;
    let mut has_warn_level = false;
    let mut has_warn_version = false;

    let level =
        |label: &'static str, value: &str, errs: &mut Vec<LabelError>| match parse_level(value) {
            Ok(l) => Some(l),
            Err(detail) => {
                errs.push(LabelError {
                    label,
                    value: value.to_owned(),
                    detail,
                });
                None
            }
        };
    let version =
        |label: &'static str, value: &str, errs: &mut Vec<LabelError>| match parse_version(value) {
            Ok(v) => v,
            Err(detail) => {
                errs.push(LabelError {
                    label,
                    value: value.to_owned(),
                    detail,
                });
                Version::Latest
            }
        };

    if let Some(v) = labels.get(ENFORCE_LEVEL_LABEL) {
        let parsed = level(ENFORCE_LEVEL_LABEL, v, &mut errs);
        has_enforce_level = parsed.is_some();
        p.enforce.level = parsed.unwrap_or(Level::Restricted);
    }
    if let Some(v) = labels.get(ENFORCE_VERSION_LABEL) {
        p.enforce.version = version(ENFORCE_VERSION_LABEL, v, &mut errs);
    }
    if let Some(v) = labels.get(AUDIT_LEVEL_LABEL) {
        p.audit.level = level(AUDIT_LEVEL_LABEL, v, &mut errs).unwrap_or(Level::Privileged);
    }
    if let Some(v) = labels.get(AUDIT_VERSION_LABEL) {
        p.audit.version = version(AUDIT_VERSION_LABEL, v, &mut errs);
    }
    if let Some(v) = labels.get(WARN_LEVEL_LABEL) {
        has_warn_level = true;
        p.warn.level = level(WARN_LEVEL_LABEL, v, &mut errs).unwrap_or(Level::Privileged);
    }
    if let Some(v) = labels.get(WARN_VERSION_LABEL) {
        has_warn_version = true;
        p.warn.version = version(WARN_VERSION_LABEL, v, &mut errs);
    }

    // A namespace enforcing a stricter level than it warns at warns at the enforce level too.
    if !has_warn_level && has_enforce_level && p.enforce.level > p.warn.level {
        p.warn.level = p.enforce.level;
        if !has_warn_version {
            p.warn.version = p.enforce.version;
        }
    }
    (p, errs)
}

fn labels_of(obj: &Value) -> BTreeMap<String, String> {
    obj["metadata"]["labels"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Pure evaluation
// ---------------------------------------------------------------------------

/// What evaluating one pod (or pod template) against a namespace policy produced.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PodEvaluation {
    /// `violates PodSecurity "<level:version>": <detail>` when enforcement rejects the pod.
    pub forbidden: Option<String>,
    pub warnings: Vec<String>,
    pub audit_annotations: Vec<(String, String)>,
}

fn run_checks(lv: LevelVersion, metadata: &Value, spec: &Value) -> AggregateResult {
    AggregateResult::from_results(checks::evaluate_pod(lv.level, lv.version, metadata, spec))
}

/// Upstream `Admission.EvaluatePod`. Enforcement applies only when `enforce` is set (pods,
/// not templates); warn is skipped for a request that is already rejected.
fn evaluate_pod_policy(
    policy: &Policy,
    policy_errs: &[LabelError],
    metadata: &Value,
    spec: &Value,
    enforce: bool,
) -> PodEvaluation {
    let mut out = PodEvaluation::default();
    if !policy_errs.is_empty() {
        out.audit_annotations.push((
            "error".to_owned(),
            format!("Failed to parse policy: {}", aggregate(policy_errs)),
        ));
    }

    let mut cache: Vec<(LevelVersion, AggregateResult)> = Vec::new();
    let evaluate = |lv: LevelVersion, cache: &mut Vec<(LevelVersion, AggregateResult)>| {
        if let Some((_, r)) = cache.iter().find(|(k, _)| *k == lv) {
            return r.clone();
        }
        let r = run_checks(lv, metadata, spec);
        cache.push((lv, r.clone()));
        r
    };

    if enforce {
        out.audit_annotations.push((
            ENFORCED_POLICY_ANNOTATION.to_owned(),
            policy.enforce.to_string(),
        ));
        let result = evaluate(policy.enforce, &mut cache);
        if !result.allowed() {
            out.forbidden = Some(format!(
                "violates PodSecurity \"{}\": {}",
                policy.enforce,
                result.forbidden_detail()
            ));
        }
    }

    let audit = evaluate(policy.audit, &mut cache);
    if !audit.allowed() {
        out.audit_annotations.push((
            AUDIT_VIOLATIONS_ANNOTATION.to_owned(),
            format!(
                "would violate PodSecurity \"{}\": {}",
                policy.audit,
                audit.forbidden_detail()
            ),
        ));
    }

    if out.forbidden.is_none() {
        let warn = evaluate(policy.warn, &mut cache);
        if !warn.allowed() {
            out.warnings.push(format!(
                "would violate PodSecurity \"{}\": {}",
                policy.warn,
                warn.forbidden_detail()
            ));
        }
    }
    out
}

/// Pod updates are only re-evaluated when a container image was added or changed — the only
/// pod fields that may change after creation.
fn is_significant_pod_update(pod: &Value, old: &Value) -> bool {
    let list =
        |p: &Value, k: &str| -> Vec<Value> { p["spec"][k].as_array().cloned().unwrap_or_default() };
    for k in ["containers", "initContainers"] {
        let (new, old) = (list(pod, k), list(old, k));
        if new.len() != old.len() {
            return true;
        }
        if new
            .iter()
            .zip(old.iter())
            .any(|(n, o)| n["image"] != o["image"])
        {
            return true;
        }
    }
    let old_eph = list(old, "ephemeralContainers");
    list(pod, "ephemeralContainers").iter().any(|c| {
        match old_eph.iter().find(|oc| oc["name"] == c["name"]) {
            None => true,
            Some(oc) => c["image"] != oc["image"],
        }
    })
}

/// Pods, grouped as upstream does: exempt runtime classes are dropped; pods from a controller
/// not yet represented go first so a 3000-pod cap still sees one pod per controller.
fn prioritize_pods<'a>(cfg: &Config, pods: &'a [Value]) -> Vec<&'a Value> {
    let mut prioritized = Vec::new();
    let mut duplicates = Vec::new();
    let mut seen_controllers = std::collections::HashSet::new();
    for pod in pods {
        if cfg.exempt_runtime_class(pod["spec"]["runtimeClassName"].as_str()) {
            continue;
        }
        let controller = pod["metadata"]["ownerReferences"]
            .as_array()
            .and_then(|refs| refs.iter().find(|r| r["controller"] == Value::Bool(true)));
        match controller {
            None => prioritized.push(pod),
            Some(r) => {
                let uid = r["uid"].as_str().unwrap_or("");
                if seen_controllers.insert(uid) {
                    prioritized.push(pod);
                } else {
                    duplicates.push(pod);
                }
            }
        }
    }
    prioritized.extend(duplicates);
    prioritized
}

/// Warnings for existing pods that violate a newly raised enforce level (upstream
/// `EvaluatePodsInNamespace`): one line per distinct violation, naming the
/// lexically-first pod and how many others share it.
fn evaluate_existing_pods(
    cfg: &Config,
    namespace: &str,
    enforce: LevelVersion,
    pods: &[Value],
) -> Vec<String> {
    let deadline = std::time::Instant::now() + NAMESPACE_POD_CHECK_TIMEOUT;
    let mut prioritized = prioritize_pods(cfg, pods);
    let total = prioritized.len();
    prioritized.truncate(NAMESPACE_MAX_PODS_TO_CHECK);

    let mut checked = prioritized.len();
    let mut order: Vec<String> = Vec::new();
    let mut counts: BTreeMap<String, (String, usize)> = BTreeMap::new();
    for (i, pod) in prioritized.iter().enumerate() {
        let result = run_checks(enforce, &pod["metadata"], &pod["spec"]);
        if !result.allowed() {
            let reason = result.forbidden_reason();
            let name = pod["metadata"]["name"].as_str().unwrap_or("").to_owned();
            match counts.get_mut(&reason) {
                None => {
                    order.push(reason.clone());
                    counts.insert(reason, (name, 1));
                }
                Some((first, n)) => {
                    if name < *first {
                        *first = name;
                    }
                    *n += 1;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            checked = i + 1;
            break;
        }
    }

    let mut warnings = Vec::new();
    if checked < total {
        warnings.push(format!(
            "new PodSecurity enforce level only checked against the first {checked} of {total} existing pods"
        ));
    }
    if !order.is_empty() {
        warnings.push(format!(
            "existing pods in namespace \"{namespace}\" violate the new PodSecurity enforce level \"{enforce}\""
        ));
    }
    let mut pod_warnings: Vec<String> = order
        .iter()
        .map(|reason| {
            let (name, n) = &counts[reason];
            match n {
                1 => format!("{name}: {reason}"),
                2 => format!("{name} (and 1 other pod): {reason}"),
                n => format!("{name} (and {} other pods): {reason}", n - 1),
            }
        })
        .collect();
    pod_warnings.sort();
    warnings.extend(pod_warnings);
    warnings
}

/// What a Namespace create/update means for pod-security.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NamespaceVerdict {
    /// Labels rejected on create, or changed to an invalid value on update.
    pub invalid: Vec<LabelError>,
    pub warnings: Vec<String>,
    /// Set when existing pods must be checked against this (newly raised) enforce policy.
    pub check_existing_pods: Option<LevelVersion>,
}

fn namespace_verdict(
    cfg: &Config,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    old_labels: Option<&BTreeMap<String, String>>,
) -> NamespaceVerdict {
    let (new_policy, new_errs) = policy_to_evaluate(labels, &cfg.defaults);
    let mut verdict = NamespaceVerdict::default();

    let Some(old_labels) = old_labels else {
        if !new_errs.is_empty() {
            verdict.invalid = new_errs;
            return verdict;
        }
        if cfg.exempt_namespace(namespace) {
            verdict
                .warnings
                .extend(cfg.exempt_namespace_warning(namespace, &new_policy, labels));
        }
        return verdict;
    };

    let (old_policy, old_errs) = policy_to_evaluate(old_labels, &cfg.defaults);
    if !new_errs.is_empty() && (old_errs.is_empty() || new_errs != old_errs) {
        verdict.invalid = new_errs;
        return verdict;
    }

    if new_policy.enforce == old_policy.enforce
        || new_policy.enforce.level == Level::Privileged
        || (new_policy.enforce.version == old_policy.enforce.version
            && new_policy.enforce.level <= old_policy.enforce.level)
    {
        return verdict;
    }
    if cfg.exempt_namespace(namespace) {
        verdict
            .warnings
            .extend(cfg.exempt_namespace_warning(namespace, &new_policy, labels));
        return verdict;
    }
    verdict.check_existing_pods = Some(new_policy.enforce);
    verdict
}

// ---------------------------------------------------------------------------
// Pod-template extraction
// ---------------------------------------------------------------------------

/// The pod template inside a workload, for the resources upstream evaluates. `None` when the
/// resource carries no pod spec (or an optional template is absent).
fn pod_template<'a>(group: &str, resource: &str, obj: &'a Value) -> Option<(&'a Value, &'a Value)> {
    let template = match (group, resource) {
        ("", "podtemplates") => &obj["template"],
        ("", "replicationcontrollers") => &obj["spec"]["template"],
        ("apps", "replicasets" | "deployments" | "statefulsets" | "daemonsets")
        | ("batch", "jobs") => &obj["spec"]["template"],
        ("batch", "cronjobs") => &obj["spec"]["jobTemplate"]["spec"]["template"],
        _ => return None,
    };
    if template.is_null() {
        return None;
    }
    Some((&template["metadata"], &template["spec"]))
}

// ---------------------------------------------------------------------------
// Admission entry point
// ---------------------------------------------------------------------------

fn qualified(group: &str, resource: &str) -> String {
    if group.is_empty() {
        resource.to_owned()
    } else {
        format!("{resource}.{group}")
    }
}

fn forbidden_status(group: &str, resource: &str, name: &str, msg: &str) -> StatusError {
    let mut e = Status::forbidden(format!(
        "{} {} is forbidden: {msg}",
        qualified(group, resource),
        go_quote(name)
    ));
    e.1.details = Some(Box::new(
        serde_json::json!({ "name": name, "group": group, "kind": resource }),
    ));
    e
}

fn invalid_namespace_status(name: &str, errs: &[LabelError]) -> StatusError {
    let mut e = Status::unprocessable_entity(format!(
        "Namespace {} is invalid: {}",
        go_quote(name),
        aggregate(errs)
    ));
    let causes: Vec<Value> = errs
        .iter()
        .map(|err| {
            serde_json::json!({
                "reason": "FieldValueInvalid",
                "message": err.message(),
                "field": err.field(),
            })
        })
        .collect();
    e.1.details = Some(Box::new(serde_json::json!({
        "name": name,
        "group": "",
        "kind": "Namespace",
        "causes": causes,
    })));
    e
}

fn record(evaluation: &PodEvaluation) {
    for w in &evaluation.warnings {
        warnings::warn(w.clone());
    }
    for (k, v) in &evaluation.audit_annotations {
        warnings::audit_annotation(k.clone(), v.clone());
    }
}

fn user_name<'a>(ctx: &'a AdmissionContext<'_>) -> &'a str {
    ctx.user_info
        .as_ref()
        .and_then(|u| u["username"].as_str())
        .unwrap_or("")
}

async fn namespace_labels<S: Store>(
    state: &AppState<S>,
    namespace: &str,
) -> Result<BTreeMap<String, String>, StatusError> {
    match state
        .store
        .get(cluster_object_key("namespaces", namespace))
        .await
    {
        Ok(Some(obj)) => Ok(serde_json::from_slice::<Value>(&obj.value)
            .map(|v| labels_of(&v))
            .unwrap_or_default()),
        // A missing namespace fails the create itself; nothing to enforce against.
        Ok(None) => Ok(BTreeMap::new()),
        Err(e) => {
            tracing::error!(namespace, err = %e, "PodSecurity: failed to fetch pod namespace");
            Err(Status::internal(format!(
                "failed to lookup namespace {}",
                go_quote(namespace)
            )))
        }
    }
}

/// Run PodSecurity admission for a validating-admission request. Pushes warnings and audit
/// annotations into the request sink and returns the rejection, if any.
pub async fn admit<S: Store>(
    state: &AppState<S>,
    ctx: &AdmissionContext<'_>,
    object: &Value,
    old_object: Option<&Value>,
) -> Result<(), StatusError> {
    if ctx.operation != "CREATE" && ctx.operation != "UPDATE" {
        return Ok(());
    }
    match (ctx.group, ctx.resource) {
        ("", "namespaces") => validate_namespace(state, ctx, object, old_object).await,
        ("", "pods" | "pods/ephemeralcontainers") => {
            validate_pod(state, ctx, object, old_object).await
        }
        (group, resource) => match pod_template(group, resource, object) {
            Some((metadata, spec)) => {
                validate_pod_controller(state, ctx, metadata, spec).await;
                Ok(())
            }
            None => Ok(()),
        },
    }
}

async fn validate_namespace<S: Store>(
    state: &AppState<S>,
    ctx: &AdmissionContext<'_>,
    object: &Value,
    old_object: Option<&Value>,
) -> Result<(), StatusError> {
    let cfg = &state.pod_security;
    let name = if ctx.name.is_empty() {
        object["metadata"]["name"].as_str().unwrap_or("")
    } else {
        ctx.name
    };
    let labels = labels_of(object);

    let old_labels = if ctx.operation == "UPDATE" {
        match old_object {
            Some(o) => Some(labels_of(o)),
            None => Some(namespace_labels(state, name).await?),
        }
    } else {
        None
    };

    let verdict = namespace_verdict(cfg, name, &labels, old_labels.as_ref());
    if !verdict.invalid.is_empty() {
        return Err(invalid_namespace_status(name, &verdict.invalid));
    }
    for w in &verdict.warnings {
        warnings::warn(w.clone());
    }
    if let Some(enforce) = verdict.check_existing_pods {
        let pods = list_pods(state, name).await;
        let ws = match pods {
            Ok(pods) => evaluate_existing_pods(cfg, name, enforce, &pods),
            Err(()) => {
                vec!["failed to list pods while checking new PodSecurity enforce level".to_owned()]
            }
        };
        for w in ws {
            warnings::warn(w);
        }
    }
    Ok(())
}

async fn list_pods<S: Store>(state: &AppState<S>, namespace: &str) -> Result<Vec<Value>, ()> {
    match state
        .store
        .list(list_prefix("pods", namespace), ListOptions::default())
        .await
    {
        Ok(resp) => Ok(resp
            .items
            .iter()
            .filter_map(|o| serde_json::from_slice::<Value>(&o.value).ok())
            .collect()),
        Err(e) => {
            tracing::error!(namespace, err = %e, "PodSecurity: failed to list pods");
            Err(())
        }
    }
}

async fn validate_pod<S: Store>(
    state: &AppState<S>,
    ctx: &AdmissionContext<'_>,
    pod: &Value,
    old_object: Option<&Value>,
) -> Result<(), StatusError> {
    let cfg = &state.pod_security;
    let namespace = ctx.namespace.unwrap_or("");

    if cfg.exempt_namespace(namespace) {
        warnings::audit_annotation(EXEMPTION_REASON_ANNOTATION, "namespace");
        return Ok(());
    }
    if cfg.exempt_user(user_name(ctx)) {
        warnings::audit_annotation(EXEMPTION_REASON_ANNOTATION, "user");
        return Ok(());
    }

    let labels = namespace_labels(state, namespace).await?;
    let (policy, errs) = policy_to_evaluate(&labels, &cfg.defaults);
    if errs.is_empty() && policy.fully_privileged() {
        warnings::audit_annotation(
            ENFORCED_POLICY_ANNOTATION,
            LevelVersion::PRIVILEGED_LATEST.to_string(),
        );
        return Ok(());
    }

    if ctx.operation == "UPDATE" {
        let fetched;
        let old = match old_object {
            Some(o) => Some(o),
            None => {
                fetched = state
                    .store
                    .get(object_key("pods", namespace, ctx.name))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|o| serde_json::from_slice::<Value>(&o.value).ok());
                fetched.as_ref()
            }
        };
        if let Some(old) = old {
            if !is_significant_pod_update(pod, old) {
                return Ok(());
            }
        }
    }

    if cfg.exempt_runtime_class(pod["spec"]["runtimeClassName"].as_str()) {
        warnings::audit_annotation(EXEMPTION_REASON_ANNOTATION, "runtimeClass");
        return Ok(());
    }

    let evaluation = evaluate_pod_policy(&policy, &errs, &pod["metadata"], &pod["spec"], true);
    record(&evaluation);
    if let Some(msg) = evaluation.forbidden {
        return Err(forbidden_status("", "pods", ctx.name, &msg));
    }
    Ok(())
}

async fn validate_pod_controller<S: Store>(
    state: &AppState<S>,
    ctx: &AdmissionContext<'_>,
    metadata: &Value,
    spec: &Value,
) {
    let cfg = &state.pod_security;
    let namespace = ctx.namespace.unwrap_or("");
    if cfg.exempt_namespace(namespace) {
        warnings::audit_annotation(EXEMPTION_REASON_ANNOTATION, "namespace");
        return;
    }
    if cfg.exempt_user(user_name(ctx)) {
        warnings::audit_annotation(EXEMPTION_REASON_ANNOTATION, "user");
        return;
    }

    let labels = match namespace_labels(state, namespace).await {
        Ok(l) => l,
        Err(e) => {
            warnings::audit_annotation(
                "error",
                format!(
                    "failed to lookup namespace {}: {}",
                    go_quote(namespace),
                    e.1.message
                ),
            );
            return;
        }
    };
    let (policy, errs) = policy_to_evaluate(&labels, &cfg.defaults);
    if errs.is_empty()
        && policy.warn.level == Level::Privileged
        && policy.audit.level == Level::Privileged
    {
        return;
    }
    if cfg.exempt_runtime_class(spec["runtimeClassName"].as_str()) {
        warnings::audit_annotation(EXEMPTION_REASON_ANNOTATION, "runtimeClass");
        return;
    }
    record(&evaluate_pod_policy(&policy, &errs, metadata, spec, false));
}

#[cfg(test)]
mod tests;
