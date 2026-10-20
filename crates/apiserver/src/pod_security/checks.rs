//! Baseline and restricted Pod Security Standards checks and the versioned registry that
//! selects which of them apply to a (level, version) pair. Check logic, versions, override
//! relationships and forbidden-reason/detail wording follow
//! k8s.io/pod-security-admission/policy (release-1.37).

use serde_json::Value;
use std::collections::BTreeSet;

use super::{Level, Version};

/// Highest policy minor version any check is registered for; `latest` and any newer
/// `v1.N` evaluate as this version.
pub const MAX_MINOR: u32 = 37;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub allowed: bool,
    pub reason: String,
    pub detail: String,
}

impl CheckResult {
    fn ok() -> Self {
        CheckResult {
            allowed: true,
            reason: String::new(),
            detail: String::new(),
        }
    }

    fn forbidden(reason: &str, detail: String) -> Self {
        CheckResult {
            allowed: false,
            reason: reason.to_owned(),
            detail,
        }
    }
}

/// Aggregate of all failed checks, in registry order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AggregateResult {
    pub reasons: Vec<String>,
    pub details: Vec<String>,
}

impl AggregateResult {
    pub fn from_results(results: Vec<CheckResult>) -> Self {
        let mut agg = AggregateResult::default();
        for r in results.into_iter().filter(|r| !r.allowed) {
            agg.reasons.push(if r.reason.is_empty() {
                "unknown forbidden reason".to_owned()
            } else {
                r.reason
            });
            agg.details.push(r.detail);
        }
        agg
    }

    pub fn allowed(&self) -> bool {
        self.reasons.is_empty()
    }

    /// `host ports, privileged containers`
    pub fn forbidden_reason(&self) -> String {
        self.reasons.join(", ")
    }

    /// `host ports (8080, 9090), privileged containers`
    pub fn forbidden_detail(&self) -> String {
        let mut out = String::new();
        for (i, reason) in self.reasons.iter().enumerate() {
            out.push_str(reason);
            if !self.details[i].is_empty() {
                out.push_str(" (");
                out.push_str(&self.details[i]);
                out.push(')');
            }
            if i + 1 != self.reasons.len() {
                out.push_str(", ");
            }
        }
        out
    }
}

type CheckFn = fn(&Value, &Value) -> CheckResult;

struct VersionedCheck {
    min_minor: u32,
    check: CheckFn,
    overrides: &'static [&'static str],
}

struct Check {
    id: &'static str,
    level: Level,
    versions: &'static [VersionedCheck],
}

const fn vc(min_minor: u32, check: CheckFn) -> VersionedCheck {
    VersionedCheck {
        min_minor,
        check,
        overrides: &[],
    }
}

const fn vc_over(
    min_minor: u32,
    check: CheckFn,
    overrides: &'static [&'static str],
) -> VersionedCheck {
    VersionedCheck {
        min_minor,
        check,
        overrides,
    }
}

static CHECKS: &[Check] = &[
    Check {
        id: "appArmorProfile",
        level: Level::Baseline,
        versions: &[vc(0, app_armor_profile)],
    },
    Check {
        id: "capabilities_baseline",
        level: Level::Baseline,
        versions: &[vc(0, capabilities_baseline)],
    },
    Check {
        id: "hostNamespaces",
        level: Level::Baseline,
        versions: &[vc(0, host_namespaces)],
    },
    Check {
        id: "hostPathVolumes",
        level: Level::Baseline,
        versions: &[vc(0, host_path_volumes)],
    },
    Check {
        id: "hostPorts",
        level: Level::Baseline,
        versions: &[vc(0, host_ports)],
    },
    Check {
        id: "hostProbesAndHostLifecycle",
        level: Level::Baseline,
        versions: &[vc(34, host_probes_and_lifecycle)],
    },
    Check {
        id: "privileged",
        level: Level::Baseline,
        versions: &[vc(0, privileged)],
    },
    Check {
        id: "procMount",
        level: Level::Baseline,
        versions: &[vc(0, proc_mount_1_0), vc(35, proc_mount_1_35_baseline)],
    },
    Check {
        id: "seLinuxOptions",
        level: Level::Baseline,
        versions: &[vc(0, se_linux_options_1_0), vc(31, se_linux_options_1_31)],
    },
    Check {
        id: "seccompProfile_baseline",
        level: Level::Baseline,
        versions: &[vc(0, seccomp_baseline_1_0), vc(19, seccomp_baseline_1_19)],
    },
    Check {
        id: "sysctls",
        level: Level::Baseline,
        versions: &[
            vc(0, sysctls_1_0),
            vc(27, sysctls_1_27),
            vc(29, sysctls_1_29),
            vc(32, sysctls_1_32),
            vc(37, sysctls_1_37),
        ],
    },
    Check {
        id: "windowsHostProcess",
        level: Level::Baseline,
        versions: &[vc(0, windows_host_process)],
    },
    Check {
        id: "allowPrivilegeEscalation",
        level: Level::Restricted,
        versions: &[
            vc(8, allow_privilege_escalation_1_8),
            vc(25, allow_privilege_escalation_1_25),
        ],
    },
    Check {
        id: "capabilities_restricted",
        level: Level::Restricted,
        versions: &[
            vc_over(22, capabilities_restricted_1_22, &["capabilities_baseline"]),
            vc_over(25, capabilities_restricted_1_25, &["capabilities_baseline"]),
        ],
    },
    Check {
        id: "procMount_restricted",
        level: Level::Restricted,
        versions: &[vc_over(35, proc_mount_1_0, &["procMount"])],
    },
    Check {
        id: "restrictedVolumes",
        level: Level::Restricted,
        versions: &[vc_over(0, restricted_volumes, &["hostPathVolumes"])],
    },
    Check {
        id: "runAsNonRoot",
        level: Level::Restricted,
        versions: &[vc(0, run_as_non_root_1_0), vc(35, run_as_non_root_1_35)],
    },
    Check {
        id: "runAsUser",
        level: Level::Restricted,
        versions: &[vc(23, run_as_user_1_23), vc(35, run_as_user_1_35)],
    },
    Check {
        id: "seccompProfile_restricted",
        level: Level::Restricted,
        versions: &[
            vc_over(19, seccomp_restricted_1_19, &["seccompProfile_baseline"]),
            vc_over(25, seccomp_restricted_1_25, &["seccompProfile_baseline"]),
        ],
    },
];

/// The check set for `level` at `version`, ordered like upstream: baseline IDs sorted, then
/// restricted IDs sorted. Restricted includes the baseline checks no restricted check
/// overrides at that version. Privileged has none.
fn checks_for(level: Level, version: Version) -> Vec<CheckFn> {
    if level == Level::Privileged {
        return Vec::new();
    }
    let minor = match version {
        Version::Latest => MAX_MINOR,
        Version::Minor(m) => m.min(MAX_MINOR),
    };
    let mut picked: Vec<(&'static Check, &'static VersionedCheck)> = CHECKS
        .iter()
        .filter(|c| c.level == Level::Baseline || level == Level::Restricted)
        .filter_map(|c| {
            c.versions
                .iter()
                .rev()
                .find(|v| v.min_minor <= minor)
                .map(|v| (c, v))
        })
        .collect();
    if level == Level::Restricted {
        let overridden: BTreeSet<&str> = picked
            .iter()
            .filter(|(c, _)| c.level == Level::Restricted)
            .flat_map(|(_, v)| v.overrides.iter().copied())
            .collect();
        picked.retain(|(c, _)| !overridden.contains(c.id));
    }
    picked.sort_by_key(|(c, _)| (c.level != Level::Baseline, c.id));
    picked.into_iter().map(|(_, v)| v.check).collect()
}

/// Evaluate a pod (metadata + spec) against `level` at `version`.
pub fn evaluate_pod(
    level: Level,
    version: Version,
    metadata: &Value,
    spec: &Value,
) -> Vec<CheckResult> {
    checks_for(level, version)
        .into_iter()
        .map(|check| check(metadata, spec))
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn join_quote(items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    format!("\"{}\"", items.join("\", \""))
}

fn pluralize<'a>(singular: &'a str, plural: &'a str, count: usize) -> &'a str {
    if count == 1 {
        singular
    } else {
        plural
    }
}

/// Go `%q` for the strings that reach these messages.
fn go_quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""))
}

fn non_null<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key).filter(|x| !x.is_null())
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn bool_field(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

fn array_field<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// initContainers, containers, ephemeralContainers — the order upstream's visitor uses.
fn containers(spec: &Value) -> Vec<&Value> {
    ["initContainers", "containers", "ephemeralContainers"]
        .iter()
        .flat_map(|k| array_field(spec, k).iter())
        .collect()
}

fn container_name(c: &Value) -> String {
    str_field(c, "name").to_owned()
}

fn container_security_context(c: &Value) -> Option<&Value> {
    non_null(c, "securityContext")
}

fn pod_security_context(spec: &Value) -> Option<&Value> {
    non_null(spec, "securityContext")
}

fn is_windows_pod(spec: &Value) -> bool {
    non_null(spec, "os").is_some_and(|os| str_field(os, "name") == "windows")
}

/// `hostUsers: false` — the pod runs in a user namespace, which relaxes some checks.
fn relax_for_user_namespace(spec: &Value) -> bool {
    bool_field(spec, "hostUsers") == Some(false)
}

fn annotations(metadata: &Value) -> Vec<(&str, &str)> {
    metadata
        .get("annotations")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.as_str(), s)))
                .collect()
        })
        .unwrap_or_default()
}

fn annotation<'a>(metadata: &'a Value, key: &str) -> Option<&'a str> {
    metadata
        .get("annotations")
        .and_then(|a| a.get(key))
        .and_then(Value::as_str)
}

// ---------------------------------------------------------------------------
// Baseline checks
// ---------------------------------------------------------------------------

const APPARMOR_ANNOTATION_PREFIX: &str = "container.apparmor.security.beta.kubernetes.io/";

fn allowed_apparmor_annotation_value(profile: &str) -> bool {
    profile.is_empty() || profile == "runtime/default" || profile.starts_with("localhost/")
}

fn allowed_apparmor_type(profile: &Value) -> bool {
    matches!(str_field(profile, "type"), "RuntimeDefault" | "Localhost")
}

fn app_armor_profile(metadata: &Value, spec: &Value) -> CheckResult {
    let mut bad_setters: Vec<String> = Vec::new();
    let mut bad_values: BTreeSet<String> = BTreeSet::new();

    if let Some(profile) = pod_security_context(spec).and_then(|sc| non_null(sc, "appArmorProfile"))
    {
        if !allowed_apparmor_type(profile) {
            bad_setters.push("pod".to_owned());
            bad_values.insert(str_field(profile, "type").to_owned());
        }
    }

    let mut bad_containers: Vec<String> = Vec::new();
    for c in containers(spec) {
        if let Some(profile) =
            container_security_context(c).and_then(|sc| non_null(sc, "appArmorProfile"))
        {
            if !allowed_apparmor_type(profile) {
                bad_containers.push(container_name(c));
                bad_values.insert(str_field(profile, "type").to_owned());
            }
        }
    }
    if !bad_containers.is_empty() {
        bad_setters.push(format!(
            "{} {}",
            pluralize("container", "containers", bad_containers.len()),
            join_quote(&bad_containers)
        ));
    }

    let mut forbidden_annotations: Vec<String> = annotations(metadata)
        .into_iter()
        .filter(|(k, v)| {
            k.starts_with(APPARMOR_ANNOTATION_PREFIX) && !allowed_apparmor_annotation_value(v)
        })
        .map(|(k, v)| format!("{k}={}", go_quote(v)))
        .collect();

    let mut bad_value_list: Vec<String> = bad_values.into_iter().collect();
    if !forbidden_annotations.is_empty() {
        forbidden_annotations.sort();
        bad_setters
            .push(pluralize("annotation", "annotations", forbidden_annotations.len()).to_owned());
        bad_value_list.extend(forbidden_annotations);
    }

    if !bad_setters.is_empty() {
        return CheckResult::forbidden(
            pluralize(
                "forbidden AppArmor profile",
                "forbidden AppArmor profiles",
                bad_value_list.len(),
            ),
            format!(
                "{} must not set AppArmor profile type to {}",
                bad_setters.join(" and "),
                join_quote(&bad_value_list)
            ),
        );
    }
    CheckResult::ok()
}

const CAPABILITIES_ALLOWED: &[&str] = &[
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
];

fn capabilities_baseline(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut bad_containers: Vec<String> = Vec::new();
    let mut non_default: BTreeSet<String> = BTreeSet::new();
    for c in containers(spec) {
        let Some(caps) = container_security_context(c).and_then(|sc| non_null(sc, "capabilities"))
        else {
            continue;
        };
        let mut valid = true;
        for cap in array_field(caps, "add").iter().filter_map(Value::as_str) {
            if !CAPABILITIES_ALLOWED.contains(&cap) {
                valid = false;
                non_default.insert(cap.to_owned());
            }
        }
        if !valid {
            bad_containers.push(container_name(c));
        }
    }
    if !bad_containers.is_empty() {
        let caps: Vec<String> = non_default.into_iter().collect();
        return CheckResult::forbidden(
            "non-default capabilities",
            format!(
                "{} {} must not include {} in securityContext.capabilities.add",
                pluralize("container", "containers", bad_containers.len()),
                join_quote(&bad_containers),
                join_quote(&caps)
            ),
        );
    }
    CheckResult::ok()
}

fn host_namespaces(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut host: Vec<&str> = Vec::new();
    if bool_field(spec, "hostNetwork") == Some(true) {
        host.push("hostNetwork=true");
    }
    if bool_field(spec, "hostPID") == Some(true) {
        host.push("hostPID=true");
    }
    if bool_field(spec, "hostIPC") == Some(true) {
        host.push("hostIPC=true");
    }
    if host.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden("host namespaces", host.join(", "))
}

fn host_path_volumes(_metadata: &Value, spec: &Value) -> CheckResult {
    let host_volumes: Vec<String> = array_field(spec, "volumes")
        .iter()
        .filter(|v| non_null(v, "hostPath").is_some())
        .map(|v| str_field(v, "name").to_owned())
        .collect();
    if host_volumes.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden(
        "hostPath volumes",
        format!(
            "{} {}",
            pluralize("volume", "volumes", host_volumes.len()),
            join_quote(&host_volumes)
        ),
    )
}

fn host_ports(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut bad_containers: Vec<String> = Vec::new();
    let mut ports: BTreeSet<String> = BTreeSet::new();
    for c in containers(spec) {
        let mut valid = true;
        for p in array_field(c, "ports") {
            let host_port = p.get("hostPort").and_then(Value::as_i64).unwrap_or(0);
            if host_port != 0 {
                valid = false;
                ports.insert(host_port.to_string());
            }
        }
        if !valid {
            bad_containers.push(container_name(c));
        }
    }
    if bad_containers.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden(
        "hostPort",
        format!(
            "{} {} {} {} {}",
            pluralize("container", "containers", bad_containers.len()),
            join_quote(&bad_containers),
            pluralize("uses", "use", bad_containers.len()),
            pluralize("hostPort", "hostPorts", ports.len()),
            ports.into_iter().collect::<Vec<_>>().join(", ")
        ),
    )
}

fn forbidden_probe_hosts(handler: Option<&Value>) -> Vec<String> {
    let Some(h) = handler else {
        return Vec::new();
    };
    ["httpGet", "tcpSocket"]
        .iter()
        .filter_map(|k| non_null(h, k))
        .map(|a| str_field(a, "host"))
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect()
}

fn host_probes_and_lifecycle(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut bad_containers: BTreeSet<String> = BTreeSet::new();
    let mut forbidden: BTreeSet<String> = BTreeSet::new();
    for c in containers(spec) {
        let mut hosts: Vec<String> = Vec::new();
        for probe in ["livenessProbe", "readinessProbe", "startupProbe"] {
            hosts.extend(forbidden_probe_hosts(non_null(c, probe)));
        }
        if let Some(lifecycle) = non_null(c, "lifecycle") {
            for hook in ["postStart", "preStop"] {
                hosts.extend(forbidden_probe_hosts(non_null(lifecycle, hook)));
            }
        }
        if !hosts.is_empty() {
            bad_containers.insert(container_name(c));
            forbidden.extend(hosts);
        }
    }
    if bad_containers.is_empty() {
        return CheckResult::ok();
    }
    let names: Vec<String> = bad_containers.into_iter().collect();
    let hosts: Vec<String> = forbidden.into_iter().collect();
    CheckResult::forbidden(
        "probe or lifecycle host",
        format!(
            "{} {} {} {} {}",
            pluralize("container", "containers", names.len()),
            join_quote(&names),
            pluralize("uses", "use", names.len()),
            pluralize(
                "probe or lifecycle host",
                "probe or lifecycle hosts",
                hosts.len()
            ),
            join_quote(&hosts)
        ),
    )
}

fn privileged(_metadata: &Value, spec: &Value) -> CheckResult {
    let bad: Vec<String> = containers(spec)
        .into_iter()
        .filter(|c| {
            container_security_context(c)
                .is_some_and(|sc| bool_field(sc, "privileged") == Some(true))
        })
        .map(container_name)
        .collect();
    if bad.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden(
        "privileged",
        format!(
            "{} {} must not set securityContext.privileged=true",
            pluralize("container", "containers", bad.len()),
            join_quote(&bad)
        ),
    )
}

fn proc_mount_1_0(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut bad_containers: Vec<String> = Vec::new();
    let mut types: BTreeSet<String> = BTreeSet::new();
    for c in containers(spec) {
        let Some(pm) = container_security_context(c).and_then(|sc| non_null(sc, "procMount"))
        else {
            continue;
        };
        let value = pm.as_str().unwrap_or("");
        if value != "Default" {
            bad_containers.push(container_name(c));
            types.insert(value.to_owned());
        }
    }
    if bad_containers.is_empty() {
        return CheckResult::ok();
    }
    let types: Vec<String> = types.into_iter().collect();
    CheckResult::forbidden(
        "procMount",
        format!(
            "{} {} must not set securityContext.procMount to {}",
            pluralize("container", "containers", bad_containers.len()),
            join_quote(&bad_containers),
            join_quote(&types)
        ),
    )
}

fn proc_mount_1_35_baseline(metadata: &Value, spec: &Value) -> CheckResult {
    if relax_for_user_namespace(spec) {
        return CheckResult::ok();
    }
    proc_mount_1_0(metadata, spec)
}

const SELINUX_TYPES_1_0: &[&str] = &["", "container_t", "container_init_t", "container_kvm_t"];
const SELINUX_TYPES_1_31: &[&str] = &[
    "",
    "container_t",
    "container_init_t",
    "container_kvm_t",
    "container_engine_t",
];

fn se_linux_options_1_0(metadata: &Value, spec: &Value) -> CheckResult {
    se_linux_options(metadata, spec, SELINUX_TYPES_1_0)
}

fn se_linux_options_1_31(metadata: &Value, spec: &Value) -> CheckResult {
    se_linux_options(metadata, spec, SELINUX_TYPES_1_31)
}

fn se_linux_options(_metadata: &Value, spec: &Value, allowed_types: &[&str]) -> CheckResult {
    let mut bad_types: BTreeSet<String> = BTreeSet::new();
    let mut set_user = false;
    let mut set_role = false;

    let mut valid = |opts: &Value| -> bool {
        let mut valid = true;
        let t = str_field(opts, "type");
        if !allowed_types.contains(&t) {
            valid = false;
            bad_types.insert(t.to_owned());
        }
        if !str_field(opts, "user").is_empty() {
            valid = false;
            set_user = true;
        }
        if !str_field(opts, "role").is_empty() {
            valid = false;
            set_role = true;
        }
        valid
    };

    let mut bad_setters: Vec<String> = Vec::new();
    if let Some(opts) = pod_security_context(spec).and_then(|sc| non_null(sc, "seLinuxOptions")) {
        if !valid(opts) {
            bad_setters.push("pod".to_owned());
        }
    }
    let mut bad_containers: Vec<String> = Vec::new();
    for c in containers(spec) {
        if let Some(opts) =
            container_security_context(c).and_then(|sc| non_null(sc, "seLinuxOptions"))
        {
            if !valid(opts) {
                bad_containers.push(container_name(c));
            }
        }
    }
    if !bad_containers.is_empty() {
        bad_setters.push(format!(
            "{} {}",
            pluralize("container", "containers", bad_containers.len()),
            join_quote(&bad_containers)
        ));
    }
    if bad_setters.is_empty() {
        return CheckResult::ok();
    }

    let mut bad_data: Vec<String> = Vec::new();
    if !bad_types.is_empty() {
        let types: Vec<String> = bad_types.iter().cloned().collect();
        bad_data.push(format!(
            "{} {}",
            pluralize("type", "types", types.len()),
            join_quote(&types)
        ));
    }
    if set_user {
        bad_data.push("user may not be set".to_owned());
    }
    if set_role {
        bad_data.push("role may not be set".to_owned());
    }
    CheckResult::forbidden(
        "seLinuxOptions",
        format!(
            "{} set forbidden securityContext.seLinuxOptions: {}",
            bad_setters.join(" and "),
            bad_data.join("; ")
        ),
    )
}

const SECCOMP_ANNOTATION_POD: &str = "seccomp.security.alpha.kubernetes.io/pod";
const SECCOMP_ANNOTATION_CONTAINER_PREFIX: &str = "container.seccomp.security.alpha.kubernetes.io/";

fn valid_seccomp_annotation_value(v: &str) -> bool {
    v == "runtime/default" || v == "docker/default" || v.starts_with("localhost/")
}

fn valid_seccomp_type(profile: &Value) -> bool {
    matches!(str_field(profile, "type"), "Localhost" | "RuntimeDefault")
}

fn seccomp_baseline_1_0(metadata: &Value, spec: &Value) -> CheckResult {
    let mut forbidden: BTreeSet<String> = BTreeSet::new();
    if let Some(val) = annotation(metadata, SECCOMP_ANNOTATION_POD) {
        if !valid_seccomp_annotation_value(val) {
            forbidden.insert(format!("{SECCOMP_ANNOTATION_POD}={}", go_quote(val)));
        }
    }
    for c in containers(spec) {
        let key = format!(
            "{SECCOMP_ANNOTATION_CONTAINER_PREFIX}{}",
            str_field(c, "name")
        );
        if let Some(val) = annotation(metadata, &key) {
            if !valid_seccomp_annotation_value(val) {
                forbidden.insert(format!("{key}={}", go_quote(val)));
            }
        }
    }
    if forbidden.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden(
        "seccompProfile",
        format!(
            "forbidden {} {}",
            pluralize("annotation", "annotations", forbidden.len()),
            forbidden.into_iter().collect::<Vec<_>>().join(", ")
        ),
    )
}

fn seccomp_baseline_1_19(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut bad_setters: Vec<String> = Vec::new();
    let mut bad_values: BTreeSet<String> = BTreeSet::new();

    if let Some(p) = pod_security_context(spec).and_then(|sc| non_null(sc, "seccompProfile")) {
        if !valid_seccomp_type(p) {
            bad_setters.push("pod".to_owned());
            bad_values.insert(str_field(p, "type").to_owned());
        }
    }
    let mut bad_containers: Vec<String> = Vec::new();
    for c in containers(spec) {
        if let Some(p) = container_security_context(c).and_then(|sc| non_null(sc, "seccompProfile"))
        {
            if !valid_seccomp_type(p) {
                bad_containers.push(container_name(c));
                bad_values.insert(str_field(p, "type").to_owned());
            }
        }
    }
    if !bad_containers.is_empty() {
        bad_setters.push(format!(
            "{} {}",
            pluralize("container", "containers", bad_containers.len()),
            join_quote(&bad_containers)
        ));
    }
    if bad_setters.is_empty() {
        return CheckResult::ok();
    }
    let values: Vec<String> = bad_values.into_iter().collect();
    CheckResult::forbidden(
        "seccompProfile",
        format!(
            "{} must not set securityContext.seccompProfile.type to {}",
            bad_setters.join(" and "),
            join_quote(&values)
        ),
    )
}

const SYSCTLS_1_0: &[&str] = &[
    "kernel.shm_rmid_forced",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range",
    "net.ipv4.ip_unprivileged_port_start",
];
const SYSCTLS_ADDED_1_27: &[&str] = &["net.ipv4.ip_local_reserved_ports"];
const SYSCTLS_ADDED_1_29: &[&str] = &[
    "net.ipv4.tcp_keepalive_time",
    "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_intvl",
    "net.ipv4.tcp_keepalive_probes",
];
const SYSCTLS_ADDED_1_32: &[&str] = &["net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem"];
const SYSCTLS_ADDED_1_37: &[&str] = &[
    "net.ipv4.tcp_slow_start_after_idle",
    "net.ipv4.tcp_notsent_lowat",
];

fn sysctls(spec: &Value, allowed: &[&[&str]]) -> CheckResult {
    let forbidden: Vec<String> = pod_security_context(spec)
        .map(|sc| array_field(sc, "sysctls"))
        .unwrap_or(&[])
        .iter()
        .map(|s| str_field(s, "name"))
        .filter(|name| !allowed.iter().any(|set| set.contains(name)))
        .map(str::to_owned)
        .collect();
    if forbidden.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden("forbidden sysctls", forbidden.join(", "))
}

fn sysctls_1_0(_m: &Value, spec: &Value) -> CheckResult {
    sysctls(spec, &[SYSCTLS_1_0])
}

fn sysctls_1_27(_m: &Value, spec: &Value) -> CheckResult {
    sysctls(spec, &[SYSCTLS_1_0, SYSCTLS_ADDED_1_27])
}

fn sysctls_1_29(_m: &Value, spec: &Value) -> CheckResult {
    sysctls(spec, &[SYSCTLS_1_0, SYSCTLS_ADDED_1_27, SYSCTLS_ADDED_1_29])
}

fn sysctls_1_32(_m: &Value, spec: &Value) -> CheckResult {
    sysctls(
        spec,
        &[
            SYSCTLS_1_0,
            SYSCTLS_ADDED_1_27,
            SYSCTLS_ADDED_1_29,
            SYSCTLS_ADDED_1_32,
        ],
    )
}

fn sysctls_1_37(_m: &Value, spec: &Value) -> CheckResult {
    sysctls(
        spec,
        &[
            SYSCTLS_1_0,
            SYSCTLS_ADDED_1_27,
            SYSCTLS_ADDED_1_29,
            SYSCTLS_ADDED_1_32,
            SYSCTLS_ADDED_1_37,
        ],
    )
}

fn host_process(sc: Option<&Value>) -> bool {
    sc.and_then(|sc| non_null(sc, "windowsOptions"))
        .is_some_and(|w| bool_field(w, "hostProcess") == Some(true))
}

fn windows_host_process(_metadata: &Value, spec: &Value) -> CheckResult {
    let bad_containers: Vec<String> = containers(spec)
        .into_iter()
        .filter(|c| host_process(container_security_context(c)))
        .map(container_name)
        .collect();
    let mut setters: Vec<String> = Vec::new();
    if host_process(pod_security_context(spec)) {
        setters.push("pod".to_owned());
    }
    if !bad_containers.is_empty() {
        setters.push(format!(
            "{} {}",
            pluralize("container", "containers", bad_containers.len()),
            join_quote(&bad_containers)
        ));
    }
    if setters.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden(
        "hostProcess",
        format!(
            "{} must not set securityContext.windowsOptions.hostProcess=true",
            setters.join(" and ")
        ),
    )
}

// ---------------------------------------------------------------------------
// Restricted checks
// ---------------------------------------------------------------------------

fn allow_privilege_escalation_1_8(_metadata: &Value, spec: &Value) -> CheckResult {
    let bad: Vec<String> = containers(spec)
        .into_iter()
        .filter(|c| {
            container_security_context(c)
                .and_then(|sc| bool_field(sc, "allowPrivilegeEscalation"))
                .unwrap_or(true)
        })
        .map(container_name)
        .collect();
    if bad.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden(
        "allowPrivilegeEscalation != false",
        format!(
            "{} {} must set securityContext.allowPrivilegeEscalation=false",
            pluralize("container", "containers", bad.len()),
            join_quote(&bad)
        ),
    )
}

fn allow_privilege_escalation_1_25(metadata: &Value, spec: &Value) -> CheckResult {
    if is_windows_pod(spec) {
        return CheckResult::ok();
    }
    allow_privilege_escalation_1_8(metadata, spec)
}

fn capabilities_restricted_1_22(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut missing_drop_all: Vec<String> = Vec::new();
    let mut adding_forbidden: Vec<String> = Vec::new();
    let mut forbidden_caps: BTreeSet<String> = BTreeSet::new();

    for c in containers(spec) {
        let Some(caps) = container_security_context(c).and_then(|sc| non_null(sc, "capabilities"))
        else {
            missing_drop_all.push(container_name(c));
            continue;
        };
        if !array_field(caps, "drop")
            .iter()
            .any(|d| d.as_str() == Some("ALL"))
        {
            missing_drop_all.push(container_name(c));
        }
        let mut added_forbidden = false;
        for cap in array_field(caps, "add").iter().filter_map(Value::as_str) {
            if cap != "NET_BIND_SERVICE" {
                added_forbidden = true;
                forbidden_caps.insert(cap.to_owned());
            }
        }
        if added_forbidden {
            adding_forbidden.push(container_name(c));
        }
    }

    let mut details: Vec<String> = Vec::new();
    if !missing_drop_all.is_empty() {
        details.push(format!(
            "{} {} must set securityContext.capabilities.drop=[\"ALL\"]",
            pluralize("container", "containers", missing_drop_all.len()),
            join_quote(&missing_drop_all)
        ));
    }
    if !adding_forbidden.is_empty() {
        let caps: Vec<String> = forbidden_caps.into_iter().collect();
        details.push(format!(
            "{} {} must not include {} in securityContext.capabilities.add",
            pluralize("container", "containers", adding_forbidden.len()),
            join_quote(&adding_forbidden),
            join_quote(&caps)
        ));
    }
    if details.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden("unrestricted capabilities", details.join("; "))
}

fn capabilities_restricted_1_25(metadata: &Value, spec: &Value) -> CheckResult {
    if is_windows_pod(spec) {
        return CheckResult::ok();
    }
    capabilities_restricted_1_22(metadata, spec)
}

fn restricted_volumes(_metadata: &Value, spec: &Value) -> CheckResult {
    const ALLOWED: &[&str] = &[
        "configMap",
        "csi",
        "downwardAPI",
        "emptyDir",
        "ephemeral",
        "image",
        "persistentVolumeClaim",
        "projected",
        "secret",
    ];
    // Typed-struct field order of the forbidden sources; the first one set names the type.
    const RESTRICTED: &[&str] = &[
        "hostPath",
        "gcePersistentDisk",
        "awsElasticBlockStore",
        "gitRepo",
        "nfs",
        "iscsi",
        "glusterfs",
        "rbd",
        "flexVolume",
        "cinder",
        "cephfs",
        "flocker",
        "fc",
        "azureFile",
        "vsphereVolume",
        "quobyte",
        "azureDisk",
        "photonPersistentDisk",
        "portworxVolume",
        "scaleIO",
        "storageos",
    ];

    let mut bad_volumes: Vec<String> = Vec::new();
    let mut bad_types: BTreeSet<String> = BTreeSet::new();
    for v in array_field(spec, "volumes") {
        if ALLOWED.iter().any(|k| non_null(v, k).is_some()) {
            continue;
        }
        bad_volumes.push(str_field(v, "name").to_owned());
        let kind = RESTRICTED
            .iter()
            .find(|k| non_null(v, k).is_some())
            .copied()
            .unwrap_or("unknown");
        bad_types.insert(kind.to_owned());
    }
    if bad_volumes.is_empty() {
        return CheckResult::ok();
    }
    let types: Vec<String> = bad_types.into_iter().collect();
    CheckResult::forbidden(
        "restricted volume types",
        format!(
            "{} {} {} {} {}",
            pluralize("volume", "volumes", bad_volumes.len()),
            join_quote(&bad_volumes),
            pluralize("uses", "use", bad_volumes.len()),
            pluralize(
                "restricted volume type",
                "restricted volume types",
                types.len()
            ),
            join_quote(&types)
        ),
    )
}

fn run_as_non_root_1_35(metadata: &Value, spec: &Value) -> CheckResult {
    if relax_for_user_namespace(spec) {
        return CheckResult::ok();
    }
    run_as_non_root_1_0(metadata, spec)
}

fn run_as_non_root_1_0(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut bad_setters: Vec<String> = Vec::new();
    let mut pod_run_as_non_root = false;
    if let Some(v) = pod_security_context(spec).and_then(|sc| bool_field(sc, "runAsNonRoot")) {
        if v {
            pod_run_as_non_root = true;
        } else {
            bad_setters.push("pod".to_owned());
        }
    }

    let mut explicitly_bad: Vec<String> = Vec::new();
    let mut implicitly_bad: Vec<String> = Vec::new();
    for c in containers(spec) {
        match container_security_context(c).and_then(|sc| bool_field(sc, "runAsNonRoot")) {
            Some(false) => explicitly_bad.push(container_name(c)),
            Some(true) => {}
            None => {
                if !pod_run_as_non_root {
                    implicitly_bad.push(container_name(c));
                }
            }
        }
    }
    if !explicitly_bad.is_empty() {
        bad_setters.push(format!(
            "{} {}",
            pluralize("container", "containers", explicitly_bad.len()),
            join_quote(&explicitly_bad)
        ));
    }
    if !bad_setters.is_empty() {
        return CheckResult::forbidden(
            "runAsNonRoot != true",
            format!(
                "{} must not set securityContext.runAsNonRoot=false",
                bad_setters.join(" and ")
            ),
        );
    }
    if !implicitly_bad.is_empty() {
        return CheckResult::forbidden(
            "runAsNonRoot != true",
            format!(
                "pod or {} {} must set securityContext.runAsNonRoot=true",
                pluralize("container", "containers", implicitly_bad.len()),
                join_quote(&implicitly_bad)
            ),
        );
    }
    CheckResult::ok()
}

fn run_as_user_1_35(metadata: &Value, spec: &Value) -> CheckResult {
    if relax_for_user_namespace(spec) {
        return CheckResult::ok();
    }
    run_as_user_1_23(metadata, spec)
}

fn runs_as_root(sc: Option<&Value>) -> bool {
    sc.and_then(|sc| sc.get("runAsUser"))
        .and_then(Value::as_i64)
        == Some(0)
}

fn run_as_user_1_23(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut bad_setters: Vec<String> = Vec::new();
    if runs_as_root(pod_security_context(spec)) {
        bad_setters.push("pod".to_owned());
    }
    let bad_containers: Vec<String> = containers(spec)
        .into_iter()
        .filter(|c| runs_as_root(container_security_context(c)))
        .map(container_name)
        .collect();
    if !bad_containers.is_empty() {
        bad_setters.push(format!(
            "{} {}",
            pluralize("container", "containers", bad_containers.len()),
            join_quote(&bad_containers)
        ));
    }
    if bad_setters.is_empty() {
        return CheckResult::ok();
    }
    CheckResult::forbidden(
        "runAsUser=0",
        format!("{} must not set runAsUser=0", bad_setters.join(" and ")),
    )
}

fn seccomp_restricted_1_19(_metadata: &Value, spec: &Value) -> CheckResult {
    let mut bad_setters: Vec<String> = Vec::new();
    let mut bad_values: BTreeSet<String> = BTreeSet::new();
    let mut pod_seccomp_set = false;

    if let Some(p) = pod_security_context(spec).and_then(|sc| non_null(sc, "seccompProfile")) {
        if valid_seccomp_type(p) {
            pod_seccomp_set = true;
        } else {
            bad_setters.push("pod".to_owned());
            bad_values.insert(str_field(p, "type").to_owned());
        }
    }

    let mut explicitly_bad: Vec<String> = Vec::new();
    let mut implicitly_bad: Vec<String> = Vec::new();
    for c in containers(spec) {
        match container_security_context(c).and_then(|sc| non_null(sc, "seccompProfile")) {
            Some(p) => {
                if !valid_seccomp_type(p) {
                    explicitly_bad.push(container_name(c));
                    bad_values.insert(str_field(p, "type").to_owned());
                }
            }
            None => {
                if !pod_seccomp_set {
                    implicitly_bad.push(container_name(c));
                }
            }
        }
    }
    if !explicitly_bad.is_empty() {
        bad_setters.push(format!(
            "{} {}",
            pluralize("container", "containers", explicitly_bad.len()),
            join_quote(&explicitly_bad)
        ));
    }
    if !bad_setters.is_empty() {
        let values: Vec<String> = bad_values.into_iter().collect();
        return CheckResult::forbidden(
            "seccompProfile",
            format!(
                "{} must not set securityContext.seccompProfile.type to {}",
                bad_setters.join(" and "),
                join_quote(&values)
            ),
        );
    }
    if !implicitly_bad.is_empty() {
        return CheckResult::forbidden(
            "seccompProfile",
            format!(
                "pod or {} {} must set securityContext.seccompProfile.type to \"RuntimeDefault\" or \"Localhost\"",
                pluralize("container", "containers", implicitly_bad.len()),
                join_quote(&implicitly_bad)
            ),
        );
    }
    CheckResult::ok()
}

fn seccomp_restricted_1_25(metadata: &Value, spec: &Value) -> CheckResult {
    if is_windows_pod(spec) {
        return CheckResult::ok();
    }
    seccomp_restricted_1_19(metadata, spec)
}
