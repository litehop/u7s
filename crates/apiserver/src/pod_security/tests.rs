use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use tower_service::Service as _;
use u7s_store::{SqliteStore, Store};

use super::config::Exemptions;
use super::*;

const LATEST: Version = Version::Latest;

fn lv(level: Level, version: Version) -> LevelVersion {
    LevelVersion { level, version }
}

fn eval_meta(level: Level, version: Version, metadata: Value, spec: Value) -> AggregateResult {
    run_checks(lv(level, version), &metadata, &spec)
}

fn eval(level: Level, version: Version, spec: Value) -> AggregateResult {
    eval_meta(level, version, json!({}), spec)
}

fn minor(m: u32) -> Version {
    Version::Minor(m)
}

/// A container that satisfies every restricted check.
fn hardened(name: &str) -> Value {
    json!({
        "name": name,
        "image": "nginx",
        "securityContext": {
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": true,
            "seccompProfile": {"type": "RuntimeDefault"}
        }
    })
}

fn plain(name: &str) -> Value {
    json!({"name": name, "image": "nginx"})
}

fn with_sc(name: &str, sc: Value) -> Value {
    json!({"name": name, "image": "nginx", "securityContext": sc})
}

fn assert_denied(r: &AggregateResult, reason: &str, detail: &str, why: &str) {
    assert!(
        !r.allowed(),
        "{why}: expected a violation but pod was allowed"
    );
    assert_eq!(r.reasons, vec![reason.to_owned()], "{why}: reasons");
    assert_eq!(r.details, vec![detail.to_owned()], "{why}: details");
}

fn assert_allowed(r: &AggregateResult, why: &str) {
    assert!(
        r.allowed(),
        "{why}: expected pod to be allowed but got {}",
        r.forbidden_detail()
    );
}

// ---------------------------------------------------------------------------
// Baseline checks
// ---------------------------------------------------------------------------

#[test]
fn privileged_container_is_denied_at_baseline_so_a_namespace_cannot_run_root_equivalent_workloads()
{
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"containers": [with_sc("c", json!({"privileged": true}))]}),
    );
    assert_denied(
        &r,
        "privileged",
        "container \"c\" must not set securityContext.privileged=true",
        "privileged=true",
    );
}

#[test]
fn unprivileged_container_passes_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"containers": [with_sc("c", json!({"privileged": false})), plain("d")]}),
    );
    assert_allowed(&r, "privileged=false and unset");
}

#[test]
fn privileged_init_and_ephemeral_containers_are_checked_too_so_they_cannot_smuggle_privilege() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({
            "initContainers": [with_sc("i", json!({"privileged": true}))],
            "containers": [plain("c")],
            "ephemeralContainers": [with_sc("e", json!({"privileged": true}))]
        }),
    );
    assert_denied(
        &r,
        "privileged",
        "containers \"i\", \"e\" must not set securityContext.privileged=true",
        "init and ephemeral containers",
    );
}

#[test]
fn host_namespaces_are_denied_at_baseline_so_pods_cannot_see_host_network_pids_or_ipc() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"hostNetwork": true, "hostPID": true, "hostIPC": true, "containers": [plain("c")]}),
    );
    assert_denied(
        &r,
        "host namespaces",
        "hostNetwork=true, hostPID=true, hostIPC=true",
        "all host namespaces",
    );
}

#[test]
fn pods_without_host_namespaces_pass_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"hostNetwork": false, "containers": [plain("c")]}),
    );
    assert_allowed(&r, "hostNetwork=false");
}

#[test]
fn host_path_volumes_are_denied_at_baseline_so_pods_cannot_mount_the_node_filesystem() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({
            "containers": [plain("c")],
            "volumes": [{"name": "root", "hostPath": {"path": "/"}}, {"name": "ok", "emptyDir": {}}]
        }),
    );
    assert_denied(&r, "hostPath volumes", "volume \"root\"", "hostPath volume");
}

#[test]
fn non_hostpath_volumes_pass_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"containers": [plain("c")], "volumes": [{"name": "nfs", "nfs": {"server": "s", "path": "/"}}]}),
    );
    assert_allowed(&r, "nfs is only restricted, not baseline");
}

#[test]
fn host_ports_are_denied_at_baseline_so_pods_cannot_bind_node_ports() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"containers": [{"name": "c", "ports": [{"hostPort": 9090}, {"hostPort": 8080}]}]}),
    );
    assert_denied(
        &r,
        "hostPort",
        "container \"c\" uses hostPorts 8080, 9090",
        "host ports",
    );
}

#[test]
fn host_port_zero_passes_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"containers": [{"name": "c", "ports": [{"containerPort": 80, "hostPort": 0}]}]}),
    );
    assert_allowed(&r, "hostPort 0");
}

#[test]
fn capabilities_beyond_the_default_set_are_denied_at_baseline() {
    let r = eval(
        Level::Baseline,
        minor(21),
        json!({"containers": [with_sc("c", json!({"capabilities": {"add": ["NET_RAW", "CHOWN", "SYS_ADMIN"]}}))]}),
    );
    assert_denied(
        &r,
        "non-default capabilities",
        "container \"c\" must not include \"NET_RAW\", \"SYS_ADMIN\" in securityContext.capabilities.add",
        "non-default capability add",
    );
}

#[test]
fn default_capability_adds_pass_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"containers": [with_sc("c", json!({"capabilities": {"add": ["CHOWN", "NET_BIND_SERVICE"]}}))]}),
    );
    assert_allowed(&r, "default capability set");
}

#[test]
fn restricted_capabilities_check_replaces_the_baseline_one_from_v1_22() {
    let spec = json!({"containers": [with_sc("c", json!({"capabilities": {"add": ["NET_RAW"], "drop": ["ALL"]}}))]});
    let new = eval(Level::Restricted, LATEST, spec.clone());
    assert!(
        new.reasons
            .contains(&"unrestricted capabilities".to_owned())
            && !new.reasons.contains(&"non-default capabilities".to_owned()),
        "from v1.22 the restricted capabilities check overrides the baseline one, got {:?}",
        new.reasons
    );
    let old = eval(Level::Restricted, minor(21), spec);
    assert!(
        old.reasons.contains(&"non-default capabilities".to_owned()),
        "before v1.22 restricted still relies on the baseline capabilities check, got {:?}",
        old.reasons
    );
}

#[test]
fn host_probe_and_lifecycle_hosts_are_denied_from_v1_34_so_probes_cannot_target_other_pods() {
    let spec = json!({"containers": [{
        "name": "c",
        "livenessProbe": {"httpGet": {"host": "10.0.0.5", "port": 80}},
        "lifecycle": {"preStop": {"tcpSocket": {"host": "10.0.0.6", "port": 80}}}
    }]});
    let r = eval(Level::Baseline, minor(34), spec.clone());
    assert_denied(
        &r,
        "probe or lifecycle host",
        "container \"c\" uses probe or lifecycle hosts \"10.0.0.5\", \"10.0.0.6\"",
        "probe+lifecycle hosts at v1.34",
    );
    assert_allowed(
        &eval(Level::Baseline, minor(33), spec),
        "check does not exist before v1.34, so pinned older policies keep admitting it",
    );
}

#[test]
fn probes_without_host_pass_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"containers": [{"name": "c", "readinessProbe": {"httpGet": {"port": 80}}, "startupProbe": {"tcpSocket": {"host": "", "port": 80}}}]}),
    );
    assert_allowed(&r, "no host on probes");
}

#[test]
fn unmasked_proc_mount_is_denied_at_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"containers": [with_sc("c", json!({"procMount": "Unmasked"}))]}),
    );
    assert_denied(
        &r,
        "procMount",
        "container \"c\" must not set securityContext.procMount to \"Unmasked\"",
        "procMount Unmasked",
    );
}

#[test]
fn default_proc_mount_passes_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({"containers": [with_sc("c", json!({"procMount": "Default"}))]}),
    );
    assert_allowed(&r, "procMount Default");
}

#[test]
fn user_namespace_pods_may_unmask_proc_at_baseline_from_v1_35_but_not_before() {
    let spec =
        json!({"hostUsers": false, "containers": [with_sc("c", json!({"procMount": "Unmasked"}))]});
    assert_allowed(
        &eval(Level::Baseline, minor(35), spec.clone()),
        "hostUsers=false relaxes procMount from v1.35",
    );
    assert!(
        !eval(Level::Baseline, minor(34), spec.clone()).allowed(),
        "v1.34 policy never relaxed procMount for user namespaces"
    );
    assert!(
        !eval(Level::Restricted, LATEST, spec).allowed(),
        "restricted keeps blocking unmasked procMount even in a user namespace"
    );
}

#[test]
fn custom_selinux_user_and_role_are_denied_at_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({
            "securityContext": {"seLinuxOptions": {"type": "spc_t", "user": "u", "role": "r"}},
            "containers": [with_sc("c", json!({"seLinuxOptions": {"user": "x"}}))]
        }),
    );
    assert_denied(
        &r,
        "seLinuxOptions",
        "pod and container \"c\" set forbidden securityContext.seLinuxOptions: type \"spc_t\"; user may not be set; role may not be set",
        "selinux options",
    );
}

#[test]
fn allowed_selinux_types_pass_and_container_engine_t_needs_v1_31() {
    let spec = json!({"containers": [with_sc("c", json!({"seLinuxOptions": {"type": "container_engine_t"}}))]});
    assert_allowed(
        &eval(Level::Baseline, minor(31), spec.clone()),
        "container_engine_t added in v1.31",
    );
    assert_denied(
        &eval(Level::Baseline, minor(30), spec),
        "seLinuxOptions",
        "container \"c\" set forbidden securityContext.seLinuxOptions: type \"container_engine_t\"",
        "container_engine_t before v1.31",
    );
    assert_allowed(
        &eval(
            Level::Baseline,
            LATEST,
            json!({"containers": [with_sc("c", json!({"seLinuxOptions": {"type": "container_t", "level": "s0"}}))]}),
        ),
        "container_t with a level",
    );
}

#[test]
fn unconfined_seccomp_annotation_is_denied_before_v1_19() {
    let meta = json!({"annotations": {"seccomp.security.alpha.kubernetes.io/pod": "unconfined"}});
    let spec = json!({"containers": [plain("c")]});
    assert_denied(
        &eval_meta(Level::Baseline, minor(18), meta.clone(), spec.clone()),
        "seccompProfile",
        "forbidden annotation seccomp.security.alpha.kubernetes.io/pod=\"unconfined\"",
        "seccomp annotation at v1.18",
    );
    assert_allowed(
        &eval_meta(Level::Baseline, minor(19), meta, spec),
        "annotations stop being evaluated from v1.19 (field-based since then)",
    );
}

#[test]
fn unconfined_seccomp_profile_field_is_denied_at_baseline_from_v1_19() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({
            "securityContext": {"seccompProfile": {"type": "Unconfined"}},
            "containers": [with_sc("c", json!({"seccompProfile": {"type": "Unconfined"}}))]
        }),
    );
    assert_denied(
        &r,
        "seccompProfile",
        "pod and container \"c\" must not set securityContext.seccompProfile.type to \"Unconfined\"",
        "seccomp Unconfined",
    );
    assert_allowed(
        &eval(
            Level::Baseline,
            LATEST,
            json!({"containers": [with_sc("c", json!({"seccompProfile": {"type": "Localhost", "localhostProfile": "p"}})), plain("d")]}),
        ),
        "Localhost/unset at baseline",
    );
}

#[test]
fn unsafe_sysctls_are_denied_at_baseline_and_the_safe_set_grows_with_the_version() {
    let sc = |name: &str| json!({"securityContext": {"sysctls": [{"name": name, "value": "1"}]}, "containers": [plain("c")]});
    assert_denied(
        &eval(Level::Baseline, LATEST, sc("kernel.msgmax")),
        "forbidden sysctls",
        "kernel.msgmax",
        "unsafe sysctl",
    );
    for (name, first_allowed) in [
        ("net.ipv4.ip_local_port_range", 0),
        ("net.ipv4.ip_local_reserved_ports", 27),
        ("net.ipv4.tcp_keepalive_time", 29),
        ("net.ipv4.tcp_rmem", 32),
        ("net.ipv4.tcp_notsent_lowat", 37),
    ] {
        assert_allowed(
            &eval(Level::Baseline, minor(first_allowed), sc(name)),
            &format!("{name} is safe from v1.{first_allowed}"),
        );
        if first_allowed > 0 {
            assert!(
                !eval(Level::Baseline, minor(first_allowed - 1), sc(name)).allowed(),
                "{name} must still be forbidden at v1.{}",
                first_allowed - 1
            );
        }
    }
}

#[test]
fn windows_host_process_is_denied_at_baseline() {
    let r = eval(
        Level::Baseline,
        LATEST,
        json!({
            "securityContext": {"windowsOptions": {"hostProcess": true}},
            "containers": [with_sc("c", json!({"windowsOptions": {"hostProcess": true}}))]
        }),
    );
    assert_denied(
        &r,
        "hostProcess",
        "pod and container \"c\" must not set securityContext.windowsOptions.hostProcess=true",
        "hostProcess",
    );
    assert_allowed(
        &eval(
            Level::Baseline,
            LATEST,
            json!({"containers": [with_sc("c", json!({"windowsOptions": {"hostProcess": false}}))]}),
        ),
        "hostProcess=false",
    );
}

#[test]
fn custom_apparmor_profiles_are_denied_at_baseline_via_field_and_annotation() {
    let r = eval_meta(
        Level::Baseline,
        LATEST,
        json!({"annotations": {"container.apparmor.security.beta.kubernetes.io/c": "unconfined"}}),
        json!({
            "securityContext": {"appArmorProfile": {"type": "Unconfined"}},
            "containers": [with_sc("c", json!({"appArmorProfile": {"type": "Unconfined"}}))]
        }),
    );
    assert_denied(
        &r,
        "forbidden AppArmor profiles",
        "pod and container \"c\" and annotation must not set AppArmor profile type to \"Unconfined\", \"container.apparmor.security.beta.kubernetes.io/c=\"unconfined\"\"",
        "apparmor",
    );
    assert_allowed(
        &eval_meta(
            Level::Baseline,
            LATEST,
            json!({"annotations": {"container.apparmor.security.beta.kubernetes.io/c": "localhost/p"}}),
            json!({"containers": [with_sc("c", json!({"appArmorProfile": {"type": "RuntimeDefault"}}))]}),
        ),
        "runtime/default, localhost/* and RuntimeDefault are allowed",
    );
}

// ---------------------------------------------------------------------------
// Restricted checks
// ---------------------------------------------------------------------------

#[test]
fn hardened_pod_passes_restricted() {
    assert_allowed(
        &eval(
            Level::Restricted,
            LATEST,
            json!({"containers": [hardened("c")]}),
        ),
        "fully hardened pod",
    );
}

#[test]
fn missing_allow_privilege_escalation_false_is_denied_at_restricted() {
    let spec = json!({"containers": [with_sc("c", json!({
        "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}
    }))]});
    assert_denied(
        &eval(Level::Restricted, LATEST, spec.clone()),
        "allowPrivilegeEscalation != false",
        "container \"c\" must set securityContext.allowPrivilegeEscalation=false",
        "allowPrivilegeEscalation unset",
    );
    assert_allowed(
        &eval(Level::Restricted, minor(7), spec),
        "field did not exist before v1.8 so the check is not applied",
    );
}

#[test]
fn windows_pods_are_exempt_from_escalation_capability_and_seccomp_checks_from_v1_25() {
    let spec = json!({"os": {"name": "windows"}, "containers": [plain("c")]});
    assert_eq!(
        eval(Level::Restricted, minor(25), spec.clone()).reasons,
        vec!["runAsNonRoot != true"],
        "windows pods cannot set the exempted fields, so only runAsNonRoot is left to report"
    );
    assert_eq!(
        eval(Level::Restricted, minor(24), spec).reasons,
        vec![
            "allowPrivilegeEscalation != false",
            "unrestricted capabilities",
            "runAsNonRoot != true",
            "seccompProfile"
        ],
        "before v1.25 windows pods were not exempt"
    );
}

#[test]
fn restricted_requires_dropping_all_capabilities_and_allows_only_net_bind_service() {
    let r = eval(
        Level::Restricted,
        LATEST,
        json!({"containers": [with_sc("c", json!({
            "allowPrivilegeEscalation": false, "runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"},
            "capabilities": {"add": ["NET_BIND_SERVICE", "NET_RAW"]}
        })), plain("d")]}),
    );
    assert!(
        r.reasons.contains(&"unrestricted capabilities".to_owned()),
        "got {:?}",
        r.reasons
    );
    let idx = r
        .reasons
        .iter()
        .position(|x| x == "unrestricted capabilities")
        .unwrap();
    assert_eq!(
        r.details[idx],
        "containers \"c\", \"d\" must set securityContext.capabilities.drop=[\"ALL\"]; container \"c\" must not include \"NET_RAW\" in securityContext.capabilities.add"
    );
    assert_allowed(
        &eval(
            Level::Restricted,
            LATEST,
            json!({"containers": [{"name": "c", "securityContext": {
                "allowPrivilegeEscalation": false, "runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"},
                "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}}}]}),
        ),
        "drop ALL + add NET_BIND_SERVICE",
    );
}

#[test]
fn restricted_volumes_allow_only_the_safe_inline_sources() {
    let r = eval(
        Level::Restricted,
        LATEST,
        json!({"containers": [hardened("c")], "volumes": [
            {"name": "h", "hostPath": {"path": "/"}},
            {"name": "n", "nfs": {"server": "s", "path": "/"}},
            {"name": "empty"},
            {"name": "ok", "configMap": {"name": "x"}}
        ]}),
    );
    assert_denied(
        &r,
        "restricted volume types",
        "volumes \"h\", \"n\", \"empty\" use restricted volume types \"hostPath\", \"nfs\", \"unknown\"",
        "restricted volumes",
    );
    assert_allowed(
        &eval(
            Level::Restricted,
            LATEST,
            json!({"containers": [hardened("c")], "volumes": [
                {"name": "a", "configMap": {"name": "x"}}, {"name": "b", "csi": {"driver": "d"}},
                {"name": "c", "downwardAPI": {}}, {"name": "d", "emptyDir": {}},
                {"name": "e", "ephemeral": {}}, {"name": "f", "image": {"reference": "r"}},
                {"name": "g", "persistentVolumeClaim": {"claimName": "p"}}, {"name": "h", "projected": {"sources": []}},
                {"name": "i", "secret": {"secretName": "s"}}]}),
        ),
        "every allowed volume source",
    );
}

#[test]
fn restricted_volumes_replace_the_hostpath_check_so_hostpath_is_reported_once() {
    let r = eval(
        Level::Restricted,
        LATEST,
        json!({"containers": [hardened("c")], "volumes": [{"name": "h", "hostPath": {"path": "/"}}]}),
    );
    assert_eq!(
        r.reasons,
        vec!["restricted volume types".to_owned()],
        "restrictedVolumes overrides hostPathVolumes, so the user sees one reason"
    );
}

#[test]
fn run_as_non_root_must_be_true_at_pod_or_container_level_at_restricted() {
    let missing = eval(
        Level::Restricted,
        LATEST,
        json!({"containers": [with_sc("c", json!({
            "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}))]}),
    );
    assert_denied(
        &missing,
        "runAsNonRoot != true",
        "pod or container \"c\" must set securityContext.runAsNonRoot=true",
        "runAsNonRoot unset",
    );

    let explicit = eval(
        Level::Restricted,
        LATEST,
        json!({"securityContext": {"runAsNonRoot": false}, "containers": [with_sc("c", json!({
            "runAsNonRoot": false, "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"}}))]}),
    );
    assert_denied(
        &explicit,
        "runAsNonRoot != true",
        "pod and container \"c\" must not set securityContext.runAsNonRoot=false",
        "runAsNonRoot=false",
    );

    let pod_level = eval(
        Level::Restricted,
        LATEST,
        json!({"securityContext": {"runAsNonRoot": true}, "containers": [with_sc("c", json!({
            "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}))]}),
    );
    assert_allowed(
        &pod_level,
        "pod-level runAsNonRoot=true covers the container",
    );
}

#[test]
fn user_namespace_pods_are_relaxed_on_run_as_non_root_and_run_as_user_from_v1_35() {
    let spec = json!({"hostUsers": false, "containers": [with_sc("c", json!({
        "runAsNonRoot": false, "runAsUser": 0, "allowPrivilegeEscalation": false,
        "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}))]});
    assert_allowed(
        &eval(Level::Restricted, minor(35), spec.clone()),
        "root inside a user namespace is not host root",
    );
    assert!(
        !eval(Level::Restricted, minor(34), spec).allowed(),
        "v1.34 policy has no user-namespace relaxation"
    );
}

#[test]
fn run_as_user_zero_is_denied_at_restricted_from_v1_23() {
    let spec = json!({"securityContext": {"runAsUser": 0, "runAsNonRoot": true}, "containers": [with_sc("c", json!({
        "runAsUser": 0, "runAsNonRoot": true, "allowPrivilegeEscalation": false,
        "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}))]});
    assert_denied(
        &eval(Level::Restricted, LATEST, spec.clone()),
        "runAsUser=0",
        "pod and container \"c\" must not set runAsUser=0",
        "runAsUser=0",
    );
    assert_allowed(
        &eval(Level::Restricted, minor(22), spec),
        "check starts at v1.23",
    );
    assert_allowed(
        &eval(
            Level::Restricted,
            LATEST,
            json!({"containers": [with_sc("c", json!({
                "runAsUser": 1000, "runAsNonRoot": true, "allowPrivilegeEscalation": false,
                "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}))]}),
        ),
        "non-zero runAsUser",
    );
}

#[test]
fn restricted_requires_a_seccomp_profile_on_pod_or_every_container() {
    let missing = eval(
        Level::Restricted,
        LATEST,
        json!({"containers": [with_sc("c", json!({
            "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": true}))]}),
    );
    assert_denied(
        &missing,
        "seccompProfile",
        "pod or container \"c\" must set securityContext.seccompProfile.type to \"RuntimeDefault\" or \"Localhost\"",
        "seccomp unset",
    );

    let pod_level = eval(
        Level::Restricted,
        LATEST,
        json!({"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}, "containers": [with_sc("c", json!({
            "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": true}))]}),
    );
    assert_allowed(&pod_level, "pod-level seccomp covers containers");

    let unconfined = eval(
        Level::Restricted,
        LATEST,
        json!({"containers": [with_sc("c", json!({
            "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": true,
            "seccompProfile": {"type": "Unconfined"}}))]}),
    );
    assert_denied(
        &unconfined,
        "seccompProfile",
        "container \"c\" must not set securityContext.seccompProfile.type to \"Unconfined\"",
        "seccomp Unconfined at restricted",
    );
}

#[test]
fn restricted_seccomp_requirement_starts_at_v1_19() {
    let spec = json!({"containers": [with_sc("c", json!({
        "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": true}))]});
    assert_allowed(
        &eval(Level::Restricted, minor(18), spec),
        "seccompProfile field did not exist before v1.19",
    );
}

#[test]
fn restricted_proc_mount_stays_unconditional_while_baseline_relaxes_it() {
    let spec = json!({"containers": [with_sc("c", json!({
        "procMount": "Unmasked", "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]},
        "runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}}))]});
    let r = eval(Level::Restricted, LATEST, spec.clone());
    assert_eq!(
        r.reasons,
        vec!["procMount".to_owned()],
        "procMount_restricted overrides the baseline copy from v1.35: reported exactly once"
    );
    assert_allowed(
        &eval(
            Level::Restricted,
            LATEST,
            json!({"containers": [hardened("c")]}),
        ),
        "default procMount",
    );
}

#[test]
fn latest_and_future_versions_evaluate_as_the_newest_known_policy() {
    let spec = json!({"securityContext": {"sysctls": [{"name": "net.ipv4.tcp_notsent_lowat", "value": "1"}]}, "containers": [plain("c")]});
    assert_allowed(&eval(Level::Baseline, LATEST, spec.clone()), "latest");
    assert_allowed(
        &eval(Level::Baseline, minor(99), spec.clone()),
        "a version newer than any known check clamps to the newest policy",
    );
    assert!(!eval(Level::Baseline, minor(36), spec).allowed());
}

#[test]
fn privileged_level_runs_no_checks() {
    assert_allowed(
        &eval(
            Level::Privileged,
            LATEST,
            json!({"hostNetwork": true, "containers": [with_sc("c", json!({"privileged": true}))]}),
        ),
        "privileged level",
    );
}

#[test]
fn violations_are_reported_baseline_checks_first_then_restricted_in_id_order() {
    let r = eval(
        Level::Restricted,
        LATEST,
        json!({"hostNetwork": true, "containers": [with_sc("c", json!({"privileged": true}))]}),
    );
    assert_eq!(
        r.reasons,
        vec![
            "host namespaces",
            "privileged",
            "allowPrivilegeEscalation != false",
            "unrestricted capabilities",
            "runAsNonRoot != true",
            "seccompProfile"
        ],
        "message order must be stable and match upstream so users and docs see identical text"
    );
    assert_eq!(
        r.forbidden_detail(),
        "host namespaces (hostNetwork=true), privileged (container \"c\" must not set securityContext.privileged=true), allowPrivilegeEscalation != false (container \"c\" must set securityContext.allowPrivilegeEscalation=false), unrestricted capabilities (container \"c\" must set securityContext.capabilities.drop=[\"ALL\"]), runAsNonRoot != true (pod or container \"c\" must set securityContext.runAsNonRoot=true), seccompProfile (pod or container \"c\" must set securityContext.seccompProfile.type to \"RuntimeDefault\" or \"Localhost\")"
    );
}

// ---------------------------------------------------------------------------
// Labels and versions
// ---------------------------------------------------------------------------

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (format!("pod-security.kubernetes.io/{k}"), (*v).to_owned()))
        .collect()
}

#[test]
fn version_labels_accept_only_latest_or_v1_n_without_leading_zeros() {
    assert_eq!(parse_version("latest"), Ok(Version::Latest));
    assert_eq!(parse_version("v1.0"), Ok(Version::Minor(0)));
    assert_eq!(parse_version("v1.30"), Ok(Version::Minor(30)));
    for bad in [
        "", "v1", "v1.", "v1.01", "v2.0", "1.30", "v1.x", "V1.30", "v1.-1", "v1.30.1",
    ] {
        assert!(
            parse_version(bad).is_err(),
            "{bad:?} must be rejected like upstream"
        );
    }
}

#[test]
fn level_labels_accept_only_the_three_standard_levels() {
    assert_eq!(parse_level("restricted"), Ok(Level::Restricted));
    assert!(parse_level("Restricted").is_err());
    assert!(parse_level("").is_err());
}

#[test]
fn enforce_label_alone_also_warns_at_that_level_so_users_see_violations_before_rejection() {
    let (p, errs) = policy_to_evaluate(
        &labels(&[("enforce", "baseline"), ("enforce-version", "v1.30")]),
        &Policy::PRIVILEGED,
    );
    assert!(errs.is_empty());
    assert_eq!(p.enforce, lv(Level::Baseline, minor(30)));
    assert_eq!(
        p.warn,
        lv(Level::Baseline, minor(30)),
        "warn follows enforce level and version"
    );
    assert_eq!(
        p.audit.level,
        Level::Privileged,
        "audit does not follow enforce"
    );
}

#[test]
fn explicit_warn_label_is_not_overridden_by_enforce() {
    let (p, _) = policy_to_evaluate(
        &labels(&[("enforce", "restricted"), ("warn", "privileged")]),
        &Policy::PRIVILEGED,
    );
    assert_eq!(p.warn.level, Level::Privileged);
}

#[test]
fn invalid_enforce_level_fails_closed_to_restricted_but_invalid_warn_and_audit_fail_open() {
    let (p, errs) = policy_to_evaluate(
        &labels(&[("enforce", "bogus"), ("warn", "bogus"), ("audit", "bogus")]),
        &Policy::PRIVILEGED,
    );
    assert_eq!(errs.len(), 3);
    assert_eq!(
        p.enforce.level,
        Level::Restricted,
        "a typo in enforce must not silently disable enforcement"
    );
    assert_eq!(p.warn.level, Level::Privileged);
    assert_eq!(p.audit.level, Level::Privileged);
}

#[test]
fn invalid_version_falls_back_to_latest_with_an_error() {
    let (p, errs) = policy_to_evaluate(
        &labels(&[("enforce", "baseline"), ("enforce-version", "1.30")]),
        &Policy::PRIVILEGED,
    );
    assert_eq!(p.enforce.version, Version::Latest);
    assert_eq!(
        errs[0].to_string(),
        "metadata.labels[pod-security.kubernetes.io/enforce-version]: Invalid value: \"1.30\": must be \"latest\" or \"v1.x\""
    );
}

#[test]
fn unlabelled_namespace_uses_the_configured_defaults() {
    let defaults = Policy {
        enforce: lv(Level::Baseline, Version::Latest),
        audit: lv(Level::Privileged, Version::Latest),
        warn: lv(Level::Baseline, Version::Latest),
    };
    let (p, errs) = policy_to_evaluate(&BTreeMap::new(), &defaults);
    assert!(errs.is_empty());
    assert_eq!(p, defaults);
}

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

fn violating_spec() -> Value {
    json!({"hostNetwork": true, "containers": [plain("c")]})
}

#[test]
fn enforce_rejects_with_upstreams_message_so_users_can_fix_the_pod() {
    let (policy, errs) =
        policy_to_evaluate(&labels(&[("enforce", "baseline")]), &Policy::PRIVILEGED);
    let out = evaluate_pod_policy(&policy, &errs, &json!({}), &violating_spec(), true);
    assert_eq!(
        out.forbidden.as_deref(),
        Some("violates PodSecurity \"baseline:latest\": host namespaces (hostNetwork=true)")
    );
    assert!(
        out.warnings.is_empty(),
        "no warning on a request that is already rejected"
    );
    assert!(out
        .audit_annotations
        .contains(&("enforce-policy".to_owned(), "baseline:latest".to_owned())));
}

#[test]
fn warn_admits_but_returns_a_warning_so_violations_surface_before_enforcement_is_turned_on() {
    let (policy, errs) = policy_to_evaluate(&labels(&[("warn", "baseline")]), &Policy::PRIVILEGED);
    let out = evaluate_pod_policy(&policy, &errs, &json!({}), &violating_spec(), true);
    assert!(out.forbidden.is_none());
    assert_eq!(
        out.warnings,
        vec!["would violate PodSecurity \"baseline:latest\": host namespaces (hostNetwork=true)"]
    );
}

#[test]
fn audit_records_would_violate_annotation_without_rejecting_or_warning() {
    let (policy, errs) = policy_to_evaluate(&labels(&[("audit", "baseline")]), &Policy::PRIVILEGED);
    let out = evaluate_pod_policy(&policy, &errs, &json!({}), &violating_spec(), true);
    assert!(out.forbidden.is_none());
    assert!(out.warnings.is_empty());
    assert!(out.audit_annotations.contains(&(
        "audit-violations".to_owned(),
        "would violate PodSecurity \"baseline:latest\": host namespaces (hostNetwork=true)"
            .to_owned()
    )));
}

#[test]
fn template_evaluation_never_enforces_so_controllers_are_not_blocked_at_the_workload_object() {
    let (policy, errs) =
        policy_to_evaluate(&labels(&[("enforce", "restricted")]), &Policy::PRIVILEGED);
    let out = evaluate_pod_policy(&policy, &errs, &json!({}), &violating_spec(), false);
    assert!(out.forbidden.is_none(), "enforce applies to pods only");
    assert_eq!(
        out.warnings.len(),
        1,
        "warn follows enforce, so the template still warns"
    );
    assert!(
        !out.audit_annotations
            .iter()
            .any(|(k, _)| k == "enforce-policy"),
        "no enforce-policy annotation for templates"
    );
}

#[test]
fn unparseable_labels_are_surfaced_as_an_audit_error_annotation() {
    let (policy, errs) = policy_to_evaluate(&labels(&[("warn", "nope")]), &Policy::PRIVILEGED);
    let out = evaluate_pod_policy(&policy, &errs, &json!({}), &json!({"containers": []}), true);
    assert!(out.audit_annotations.iter().any(|(k, v)| k == "error"
        && v.starts_with(
            "Failed to parse policy: metadata.labels[pod-security.kubernetes.io/warn]"
        )));
}

// ---------------------------------------------------------------------------
// Namespace label changes
// ---------------------------------------------------------------------------

fn cfg() -> Config {
    Config::default()
}

#[test]
fn invalid_labels_are_rejected_on_namespace_create() {
    let v = namespace_verdict(&cfg(), "ns", &labels(&[("enforce", "strict")]), None);
    assert_eq!(v.invalid.len(), 1);
    let status = invalid_namespace_status("ns", &v.invalid);
    assert_eq!(status.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        status.1.message,
        "Namespace \"ns\" is invalid: metadata.labels[pod-security.kubernetes.io/enforce]: Invalid value: \"strict\": must be one of privileged, baseline, restricted"
    );
}

#[test]
fn unchanged_invalid_labels_do_not_block_unrelated_namespace_updates() {
    let bad = labels(&[("enforce", "strict")]);
    let v = namespace_verdict(&cfg(), "ns", &bad, Some(&bad));
    assert!(
        v.invalid.is_empty(),
        "a pre-existing bad label must not make the namespace un-editable"
    );
    let changed = labels(&[("enforce", "stricter")]);
    assert!(
        !namespace_verdict(&cfg(), "ns", &changed, Some(&bad))
            .invalid
            .is_empty(),
        "changing it to another bad value is rejected"
    );
}

#[test]
fn raising_enforce_level_triggers_a_check_of_existing_pods() {
    let v = namespace_verdict(
        &cfg(),
        "ns",
        &labels(&[("enforce", "restricted")]),
        Some(&BTreeMap::new()),
    );
    assert_eq!(
        v.check_existing_pods,
        Some(lv(Level::Restricted, Version::Latest))
    );
}

#[test]
fn lowering_or_keeping_enforce_does_not_rescan_pods() {
    let restricted = labels(&[("enforce", "restricted")]);
    let baseline = labels(&[("enforce", "baseline")]);
    assert_eq!(
        namespace_verdict(&cfg(), "ns", &baseline, Some(&restricted)).check_existing_pods,
        None,
        "relaxing at the same version cannot create new violations"
    );
    assert_eq!(
        namespace_verdict(&cfg(), "ns", &restricted, Some(&restricted)).check_existing_pods,
        None
    );
    assert_eq!(
        namespace_verdict(
            &cfg(),
            "ns",
            &labels(&[("enforce", "privileged")]),
            Some(&baseline)
        )
        .check_existing_pods,
        None,
        "privileged accepts everything"
    );
    assert_eq!(
        namespace_verdict(
            &cfg(),
            "ns",
            &labels(&[("enforce", "baseline"), ("enforce-version", "v1.25")]),
            Some(&labels(&[("enforce", "baseline")])),
        )
        .check_existing_pods,
        Some(lv(Level::Baseline, minor(25))),
        "pinning an older version at the same level is a version change and is rechecked"
    );
}

fn pod(name: &str, spec: Value) -> Value {
    json!({"metadata": {"name": name}, "spec": spec})
}

#[test]
fn existing_pod_warnings_name_the_first_pod_and_count_the_rest() {
    let enforce = lv(Level::Restricted, Version::Latest);
    let pods = vec![
        pod(
            "b",
            json!({"containers": [with_sc("c", json!({"privileged": true}))]}),
        ),
        pod(
            "a",
            json!({"containers": [with_sc("c", json!({"privileged": true}))]}),
        ),
        pod("ok", json!({"containers": [hardened("c")]})),
        pod(
            "z",
            json!({"hostNetwork": true, "containers": [hardened("c")]}),
        ),
    ];
    let w = evaluate_existing_pods(&cfg(), "prod", enforce, &pods);
    assert_eq!(w[0], "existing pods in namespace \"prod\" violate the new PodSecurity enforce level \"restricted:latest\"");
    assert_eq!(w.len(), 3, "{w:?}");
    assert!(
        w.contains(&"a (and 1 other pod): privileged, allowPrivilegeEscalation != false, unrestricted capabilities, runAsNonRoot != true, seccompProfile".to_owned()),
        "{w:?}"
    );
    assert!(w.contains(&"z: host namespaces".to_owned()), "{w:?}");
}

#[test]
fn existing_pod_warnings_pluralise_for_three_or_more_pods() {
    let pods: Vec<Value> = ["p1", "p2", "p3"]
        .iter()
        .map(|n| pod(n, json!({"hostNetwork": true, "containers": [plain("c")]})))
        .collect();
    let w = evaluate_existing_pods(&cfg(), "n", lv(Level::Baseline, Version::Latest), &pods);
    assert_eq!(w[1], "p1 (and 2 other pods): host namespaces");
}

#[test]
fn existing_pod_scan_is_capped_and_says_so() {
    let pods: Vec<Value> = (0..NAMESPACE_MAX_PODS_TO_CHECK + 5)
        .map(|i| pod(&format!("p{i}"), json!({"containers": [plain("c")]})))
        .collect();
    let w = evaluate_existing_pods(&cfg(), "n", lv(Level::Baseline, Version::Latest), &pods);
    assert_eq!(
        w,
        vec![format!(
            "new PodSecurity enforce level only checked against the first {} of {} existing pods",
            NAMESPACE_MAX_PODS_TO_CHECK,
            NAMESPACE_MAX_PODS_TO_CHECK + 5
        )]
    );
}

#[test]
fn exempt_runtime_class_pods_are_not_reported_when_raising_enforce() {
    let mut config = cfg();
    config.exemptions.runtime_classes = vec!["kata".to_owned()];
    let mut p = pod(
        "kata-pod",
        json!({"hostNetwork": true, "containers": [plain("c")]}),
    );
    p["spec"]["runtimeClassName"] = json!("kata");
    let w = evaluate_existing_pods(&config, "n", lv(Level::Baseline, Version::Latest), &[p]);
    assert!(w.is_empty(), "{w:?}");
}

#[test]
fn labelling_an_exempt_namespace_warns_that_the_policy_is_ignored() {
    let mut config = cfg();
    config.exemptions.namespaces = vec!["kube-system".to_owned()];
    let v = namespace_verdict(
        &config,
        "kube-system",
        &labels(&[
            ("enforce", "baseline"),
            ("warn", "restricted"),
            ("warn-version", "v1.30"),
        ]),
        None,
    );
    assert_eq!(
        v.warnings,
        vec!["namespace \"kube-system\" is exempt from Pod Security, and the policy (enforce=baseline:latest, warn=restricted:v1.30) will be ignored"]
    );
    let fully_privileged = namespace_verdict(
        &config,
        "kube-system",
        &labels(&[("enforce", "privileged")]),
        None,
    );
    assert!(fully_privileged.warnings.is_empty());
}

// ---------------------------------------------------------------------------
// Pod significance
// ---------------------------------------------------------------------------

#[test]
fn only_image_changes_re_trigger_pod_evaluation_so_status_and_finalizer_updates_never_break() {
    let old = json!({"spec": {"containers": [{"name": "a", "image": "x"}]}});
    let same = json!({"spec": {"containers": [{"name": "a", "image": "x"}]}, "metadata": {"finalizers": []}});
    assert!(!is_significant_pod_update(&same, &old));
    let new_image = json!({"spec": {"containers": [{"name": "a", "image": "y"}]}});
    assert!(is_significant_pod_update(&new_image, &old));
    let ephemeral = json!({"spec": {"containers": [{"name": "a", "image": "x"}], "ephemeralContainers": [{"name": "dbg", "image": "b"}]}});
    assert!(is_significant_pod_update(&ephemeral, &old));
}

// ---------------------------------------------------------------------------
// Pod templates
// ---------------------------------------------------------------------------

#[test]
fn every_pod_template_bearing_resource_is_extracted() {
    let tmpl = json!({"metadata": {"labels": {"a": "b"}}, "spec": {"containers": []}});
    let cases = [
        ("", "podtemplates", json!({"template": tmpl})),
        (
            "",
            "replicationcontrollers",
            json!({"spec": {"template": tmpl}}),
        ),
        ("apps", "replicasets", json!({"spec": {"template": tmpl}})),
        ("apps", "deployments", json!({"spec": {"template": tmpl}})),
        ("apps", "statefulsets", json!({"spec": {"template": tmpl}})),
        ("apps", "daemonsets", json!({"spec": {"template": tmpl}})),
        ("batch", "jobs", json!({"spec": {"template": tmpl}})),
        (
            "batch",
            "cronjobs",
            json!({"spec": {"jobTemplate": {"spec": {"template": tmpl}}}}),
        ),
    ];
    for (group, resource, obj) in &cases {
        let (meta, spec) = pod_template(group, resource, obj)
            .unwrap_or_else(|| panic!("{resource} template must be evaluated"));
        assert_eq!(meta["labels"]["a"], "b", "{resource}");
        assert!(spec["containers"].is_array(), "{resource}");
    }
    assert!(pod_template(
        "apps",
        "controllerrevisions",
        &json!({"spec": {"template": tmpl}})
    )
    .is_none());
    assert!(
        pod_template("", "replicationcontrollers", &json!({"spec": {}})).is_none(),
        "an RC without a template has nothing to evaluate"
    );
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn default_config_is_privileged_latest_for_every_mode_with_no_exemptions() {
    let c = Config::default();
    assert_eq!(c.defaults, Policy::PRIVILEGED);
    assert_eq!(c.exemptions, Exemptions::default());
}

#[test]
fn admission_configuration_sets_defaults_and_exemptions() {
    let text = r#"
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: baseline
      enforce-version: v1.30
      warn: restricted
    exemptions:
      usernames: [alice]
      runtimeClasses: [kata]
      namespaces: [kube-system]
"#;
    let c = config::parse_admission_configuration_for_test(text).unwrap();
    assert_eq!(c.defaults.enforce, lv(Level::Baseline, minor(30)));
    assert_eq!(c.defaults.warn, lv(Level::Restricted, Version::Latest));
    assert_eq!(c.defaults.audit, lv(Level::Privileged, Version::Latest));
    assert!(c.exempt_user("alice") && !c.exempt_user("bob"));
    assert!(c.exempt_runtime_class(Some("kata")) && !c.exempt_runtime_class(None));
    assert!(c.exempt_namespace("kube-system") && !c.exempt_namespace("default"));
}

#[test]
fn invalid_config_is_a_startup_error_instead_of_silently_disabling_enforcement() {
    let bad_level = "kind: AdmissionConfiguration\nplugins:\n- name: PodSecurity\n  configuration:\n    kind: PodSecurityConfiguration\n    defaults: {enforce: strict}\n";
    let err = config::parse_admission_configuration_for_test(bad_level).unwrap_err();
    assert!(err.contains("defaults.enforce"), "{err}");
    let dup = "kind: AdmissionConfiguration\nplugins:\n- name: PodSecurity\n  configuration:\n    kind: PodSecurityConfiguration\n    exemptions: {namespaces: [a, a, Bad_Name]}\n";
    let err = config::parse_admission_configuration_for_test(dup).unwrap_err();
    assert!(
        err.contains("Duplicate") && err.contains("exemptions.namespaces[2]"),
        "{err}"
    );
    let other =
        "kind: AdmissionConfiguration\nplugins:\n- name: EventRateLimit\n  configuration: {}\n";
    assert!(config::parse_admission_configuration_for_test(other).is_err());
}

// ---------------------------------------------------------------------------
// End to end through the real router
// ---------------------------------------------------------------------------

fn test_state() -> AppState {
    let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
    AppState::new(
        store,
        None,
        None,
        std::collections::HashMap::new(),
        "https://localhost:6443".into(),
    )
}

struct Reply {
    status: StatusCode,
    warnings: Vec<String>,
    body: Value,
}

async fn call(
    router: &mut axum::Router,
    method: Method,
    uri: &str,
    content_type: &str,
    body: Value,
) -> Reply {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", content_type)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(crate::auth::UserInfo {
        username: "tester".into(),
        uid: String::new(),
        groups: vec![],
        extra: Default::default(),
    });
    let resp = router.call(req).await.expect("router is infallible");
    let status = resp.status();
    let warnings = resp
        .headers()
        .get_all("warning")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    Reply {
        status,
        warnings,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

async fn create_namespace(router: &mut axum::Router, name: &str, labels: Value) -> Reply {
    call(
        router,
        Method::POST,
        "/api/v1/namespaces",
        "application/json",
        json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}}),
    )
    .await
}

async fn label_namespace(router: &mut axum::Router, name: &str, labels: Value) -> Reply {
    call(
        router,
        Method::PATCH,
        &format!("/api/v1/namespaces/{name}"),
        "application/merge-patch+json",
        json!({"metadata": {"labels": labels}}),
    )
    .await
}

async fn create_pod(router: &mut axum::Router, ns: &str, name: &str, spec: Value) -> Reply {
    call(
        router,
        Method::POST,
        &format!("/api/v1/namespaces/{ns}/pods"),
        "application/json",
        json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}),
    )
    .await
}

fn privileged_pod_spec() -> Value {
    json!({"containers": [with_sc("c", json!({"privileged": true}))]})
}

#[tokio::test]
async fn privileged_pod_is_admitted_until_the_namespace_is_labelled_enforce_restricted() {
    let mut router = crate::build_router(test_state());
    assert_eq!(
        create_namespace(&mut router, "psa", json!({})).await.status,
        StatusCode::CREATED
    );

    let before = create_pod(&mut router, "psa", "before", privileged_pod_spec()).await;
    assert_eq!(
        before.status,
        StatusCode::CREATED,
        "default policy is privileged, so an unlabelled namespace admits anything"
    );

    let labelled = label_namespace(
        &mut router,
        "psa",
        json!({"pod-security.kubernetes.io/enforce": "restricted"}),
    )
    .await;
    assert_eq!(labelled.status, StatusCode::OK);

    let after = create_pod(&mut router, "psa", "after", privileged_pod_spec()).await;
    assert_eq!(
        after.status,
        StatusCode::FORBIDDEN,
        "enforce=restricted must reject a privileged pod: {:?}",
        after.body
    );
    let message = after.body["message"].as_str().unwrap();
    assert!(
        message.starts_with("pods \"after\" is forbidden: violates PodSecurity \"restricted:latest\": privileged (container \"c\" must not set securityContext.privileged=true)"),
        "{message}"
    );
    assert_eq!(after.body["reason"], "Forbidden");
    assert_eq!(after.body["details"]["kind"], "pods");

    let ok = create_pod(
        &mut router,
        "psa",
        "hardened",
        json!({"containers": [hardened("c")]}),
    )
    .await;
    assert_eq!(
        ok.status,
        StatusCode::CREATED,
        "compliant pods still run: {:?}",
        ok.body
    );
}

#[tokio::test]
async fn warn_label_returns_a_warning_header_and_still_admits_a_hostpath_pod() {
    let mut router = crate::build_router(test_state());
    create_namespace(
        &mut router,
        "w",
        json!({"pod-security.kubernetes.io/warn": "baseline"}),
    )
    .await;
    let r = create_pod(
        &mut router,
        "w",
        "hp",
        json!({"containers": [plain("c")], "volumes": [{"name": "root", "hostPath": {"path": "/"}}]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(
        r.warnings,
        vec!["299 - \"would violate PodSecurity \\\"baseline:latest\\\": hostPath volumes (volume \\\"root\\\")\"".to_owned()]
    );
}

#[tokio::test]
async fn labelling_a_namespace_with_violating_pods_warns_about_them() {
    let mut router = crate::build_router(test_state());
    create_namespace(&mut router, "legacy", json!({})).await;
    create_pod(&mut router, "legacy", "old-priv", privileged_pod_spec()).await;
    create_pod(
        &mut router,
        "legacy",
        "fine",
        json!({"containers": [hardened("c")]}),
    )
    .await;

    let r = label_namespace(
        &mut router,
        "legacy",
        json!({"pod-security.kubernetes.io/enforce": "baseline"}),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "existing pods never block the label change"
    );
    assert_eq!(r.warnings.len(), 2, "{:?}", r.warnings);
    assert_eq!(
        r.warnings[0],
        "299 - \"existing pods in namespace \\\"legacy\\\" violate the new PodSecurity enforce level \\\"baseline:latest\\\"\""
    );
    assert_eq!(r.warnings[1], "299 - \"old-priv: privileged\"");
}

#[tokio::test]
async fn invalid_pod_security_label_is_rejected_on_namespace_create_and_update() {
    let mut router = crate::build_router(test_state());
    let created = create_namespace(
        &mut router,
        "bad",
        json!({"pod-security.kubernetes.io/enforce": "nope"}),
    )
    .await;
    assert_eq!(created.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(created.body["reason"], "Invalid");

    create_namespace(&mut router, "good", json!({})).await;
    let updated = label_namespace(
        &mut router,
        "good",
        json!({"pod-security.kubernetes.io/warn-version": "v1.030"}),
    )
    .await;
    assert_eq!(updated.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        updated.body["details"]["causes"][0]["field"],
        "metadata.labels[pod-security.kubernetes.io/warn-version]"
    );
}

#[tokio::test]
async fn deployments_only_warn_because_enforcement_happens_on_the_pods_they_create() {
    let mut router = crate::build_router(test_state());
    create_namespace(
        &mut router,
        "dep",
        json!({"pod-security.kubernetes.io/enforce": "restricted"}),
    )
    .await;
    let r = call(
        &mut router,
        Method::POST,
        "/apis/apps/v1/namespaces/dep/deployments",
        "application/json",
        json!({
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d"},
            "spec": {
                "selector": {"matchLabels": {"a": "b"}},
                "template": {"metadata": {"labels": {"a": "b"}}, "spec": privileged_pod_spec()}
            }
        }),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
    assert!(
        r.warnings[0].starts_with("299 - \"would violate PodSecurity \\\"restricted:latest\\\": privileged (container \\\"c\\\""),
        "{:?}",
        r.warnings
    );
}

#[tokio::test]
async fn exempt_namespaces_users_and_runtime_classes_bypass_enforcement() {
    let mut state = test_state();
    state.pod_security = Arc::new(Config {
        defaults: Policy {
            enforce: lv(Level::Restricted, Version::Latest),
            ..Policy::PRIVILEGED
        },
        exemptions: Exemptions {
            usernames: vec!["tester".into()],
            runtime_classes: vec![],
            namespaces: vec![],
        },
    });
    let mut router = crate::build_router(state.clone());
    create_namespace(&mut router, "ex", json!({})).await;
    assert_eq!(
        create_pod(&mut router, "ex", "p", privileged_pod_spec())
            .await
            .status,
        StatusCode::CREATED,
        "exempt user"
    );

    let mut strict = state;
    strict.pod_security = Arc::new(Config {
        defaults: strict.pod_security.defaults,
        exemptions: Exemptions::default(),
    });
    let mut router = crate::build_router(strict);
    assert_eq!(
        create_pod(&mut router, "ex", "p2", privileged_pod_spec())
            .await
            .status,
        StatusCode::FORBIDDEN,
        "cluster default enforce=restricted applies to unlabelled namespaces when no one is exempt"
    );
}

#[tokio::test]
async fn namespace_labels_override_the_cluster_default() {
    let mut state = test_state();
    state.pod_security = Arc::new(Config {
        defaults: Policy {
            enforce: lv(Level::Restricted, Version::Latest),
            ..Policy::PRIVILEGED
        },
        exemptions: Exemptions::default(),
    });
    let mut router = crate::build_router(state);
    create_namespace(
        &mut router,
        "open",
        json!({"pod-security.kubernetes.io/enforce": "privileged"}),
    )
    .await;
    assert_eq!(
        create_pod(&mut router, "open", "p", privileged_pod_spec())
            .await
            .status,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn ephemeral_containers_cannot_add_a_privileged_debug_container_to_a_restricted_namespace() {
    let mut router = crate::build_router(test_state());
    create_namespace(&mut router, "dbg", json!({})).await;
    let pod = create_pod(
        &mut router,
        "dbg",
        "target",
        json!({"containers": [hardened("c")]}),
    )
    .await;
    assert_eq!(pod.status, StatusCode::CREATED);
    label_namespace(
        &mut router,
        "dbg",
        json!({"pod-security.kubernetes.io/enforce": "restricted"}),
    )
    .await;

    let r = call(
        &mut router,
        Method::PATCH,
        "/api/v1/namespaces/dbg/pods/target/ephemeralcontainers",
        "application/strategic-merge-patch+json",
        json!({"spec": {"ephemeralContainers": [{"name": "dbg", "image": "busybox", "securityContext": {"privileged": true}}]}}),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
}

#[tokio::test]
async fn finalizer_and_status_style_pod_updates_are_not_re_evaluated_in_a_restricted_namespace() {
    let state = test_state();
    let store = state.store.clone();
    let mut router = crate::build_router(state);
    create_namespace(&mut router, "upd", json!({})).await;
    create_pod(&mut router, "upd", "legacy", privileged_pod_spec()).await;
    label_namespace(
        &mut router,
        "upd",
        json!({"pod-security.kubernetes.io/enforce": "restricted"}),
    )
    .await;

    let r = call(
        &mut router,
        Method::PATCH,
        "/api/v1/namespaces/upd/pods/legacy",
        "application/merge-patch+json",
        json!({"metadata": {"labels": {"touched": "yes"}}}),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "a grandfathered pod must stay editable (labels, finalizers) even though it no longer complies: {:?}",
        r.body
    );
    let stored = store
        .get("/registry/pods/upd/legacy")
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&stored.value).contains("touched"));
}
