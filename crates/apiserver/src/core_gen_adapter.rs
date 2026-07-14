use prost::Message;

use crate::apps_gen::k8s::io::api::core::v1 as core_v1;
use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;
use crate::apps_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString;

// ---- shared helpers --------------------------------------------------------

// Pre-1970 (negative) seconds are valid on the wire — MicroTime/Time support any date from
// 0001-01-01T00:00:00Z onward, which predates the Unix epoch. Do not reintroduce a
// `secs <= 0` guard here: [sig-node] Lease conformance sets AcquireTime/RenewTime to Go's
// zero-value time.Time{}.Add(2s), which is a large negative Unix timestamp.
pub(crate) fn gen_microtime_fields_to_rfc3339(secs: i64, nanos: i32) -> String {
    crate::util::secs_nanos_to_rfc3339_micro(secs, nanos)
}

fn gen_int_or_string_to_json(ios: &IntOrString) -> serde_json::Value {
    if ios.r#type.unwrap_or(0) == 0 {
        serde_json::Value::Number(ios.int_val.unwrap_or(0).into())
    } else {
        serde_json::Value::String(ios.str_val.clone().unwrap_or_default())
    }
}

fn gen_quantity_map_to_json(
    map: std::collections::HashMap<
        String,
        super::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity,
    >,
) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (k, v) in map {
        let s = v.string.unwrap_or_default();
        if !s.is_empty() {
            out.insert(k, serde_json::Value::String(s));
        }
    }
    serde_json::Value::Object(out)
}

fn gen_key_to_path_to_json(items: Vec<core_v1::KeyToPath>) -> serde_json::Value {
    let arr: Vec<serde_json::Value> = items
        .into_iter()
        .filter(|it| it.key.as_deref().is_some_and(|k| !k.is_empty()))
        .map(|it| {
            let mut m = serde_json::Map::new();
            if let Some(k) = it.key.filter(|s| !s.is_empty()) {
                m.insert("key".to_string(), serde_json::Value::String(k));
            }
            if let Some(p) = it.path.filter(|s| !s.is_empty()) {
                m.insert("path".to_string(), serde_json::Value::String(p));
            }
            if let Some(mode) = it.mode.filter(|&v| v != 0) {
                m.insert("mode".to_string(), serde_json::Value::Number(mode.into()));
            }
            serde_json::Value::Object(m)
        })
        .collect();
    serde_json::Value::Array(arr)
}

fn gen_downward_api_volume_file_to_json(f: core_v1::DownwardApiVolumeFile) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(p) = f.path.filter(|s| !s.is_empty()) {
        m.insert("path".to_string(), serde_json::Value::String(p));
    }
    if let Some(fr) = f.field_ref {
        let mut fr_map = serde_json::Map::new();
        if let Some(v) = fr.api_version.filter(|s| !s.is_empty()) {
            fr_map.insert("apiVersion".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = fr.field_path.filter(|s| !s.is_empty()) {
            fr_map.insert("fieldPath".to_string(), serde_json::Value::String(v));
        }
        m.insert("fieldRef".to_string(), serde_json::Value::Object(fr_map));
    }
    if let Some(rfr) = f.resource_field_ref {
        let mut rfr_map = serde_json::Map::new();
        if let Some(v) = rfr.container_name.filter(|s| !s.is_empty()) {
            rfr_map.insert("containerName".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = rfr.resource.filter(|s| !s.is_empty()) {
            rfr_map.insert("resource".to_string(), serde_json::Value::String(v));
        }
        let divisor_str = rfr
            .divisor
            .and_then(|q| q.string)
            .filter(|s| !s.is_empty() && s != "0")
            .unwrap_or_else(|| "1".to_string());
        rfr_map.insert(
            "divisor".to_string(),
            serde_json::Value::String(divisor_str),
        );
        m.insert(
            "resourceFieldRef".to_string(),
            serde_json::Value::Object(rfr_map),
        );
    }
    if let Some(mode) = f.mode.filter(|&v| v != 0) {
        m.insert("mode".to_string(), serde_json::Value::Number(mode.into()));
    }
    serde_json::Value::Object(m)
}

fn gen_downward_api_volume_source_to_json(
    items: Vec<core_v1::DownwardApiVolumeFile>,
    default_mode: Option<i32>,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !items.is_empty() {
        let items_json: Vec<serde_json::Value> = items
            .into_iter()
            .map(gen_downward_api_volume_file_to_json)
            .collect();
        m.insert("items".to_string(), serde_json::Value::Array(items_json));
    }
    // Unlike configMap/secret/projected volumes, a top-level DownwardAPIVolumeSource never
    // gets a later defaulting pass in handlers/pods.rs::apply_pod_spec_defaults — this decode
    // step is the only place that stamps defaultMode, and the kubelet refuses to mount the
    // volume at all without one ("no defaultMode used, not even the default value for it").
    // So always emit a value here, unlike the other volume sources below.
    let dm = match default_mode.unwrap_or(0) {
        0 => 420,
        v => v,
    };
    m.insert(
        "defaultMode".to_string(),
        serde_json::Value::Number(dm.into()),
    );
    serde_json::Value::Object(m)
}

fn gen_projected_volume_source_to_json(proj: core_v1::ProjectedVolumeSource) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !proj.sources.is_empty() {
        let sources_json: Vec<serde_json::Value> = proj
            .sources
            .into_iter()
            .map(|src| {
                let mut sm = serde_json::Map::new();
                if let Some(s) = src.secret {
                    let optional = s.optional;
                    if let Some(lor) = s.local_object_reference {
                        if let Some(name) = lor.name.filter(|s| !s.is_empty()) {
                            let mut secret_map = serde_json::Map::new();
                            secret_map.insert("name".to_string(), serde_json::Value::String(name));
                            if !s.items.is_empty() {
                                secret_map
                                    .insert("items".to_string(), gen_key_to_path_to_json(s.items));
                            }
                            if let Some(true) = optional {
                                secret_map
                                    .insert("optional".to_string(), serde_json::Value::Bool(true));
                            }
                            sm.insert("secret".to_string(), serde_json::Value::Object(secret_map));
                        }
                    }
                }
                if let Some(da) = src.downward_api {
                    sm.insert(
                        "downwardAPI".to_string(),
                        gen_downward_api_volume_source_to_json(da.items, None),
                    );
                }
                if let Some(cm) = src.config_map {
                    let optional = cm.optional;
                    if let Some(lor) = cm.local_object_reference {
                        if let Some(name) = lor.name.filter(|s| !s.is_empty()) {
                            let mut cm_map = serde_json::Map::new();
                            cm_map.insert("name".to_string(), serde_json::Value::String(name));
                            if !cm.items.is_empty() {
                                cm_map
                                    .insert("items".to_string(), gen_key_to_path_to_json(cm.items));
                            }
                            if let Some(true) = optional {
                                cm_map
                                    .insert("optional".to_string(), serde_json::Value::Bool(true));
                            }
                            sm.insert("configMap".to_string(), serde_json::Value::Object(cm_map));
                        }
                    }
                }
                if let Some(sat) = src.service_account_token {
                    let mut sat_map = serde_json::Map::new();
                    if let Some(v) = sat.audience.filter(|s| !s.is_empty()) {
                        sat_map.insert("audience".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(exp) = sat.expiration_seconds.filter(|&v| v != 0) {
                        sat_map.insert(
                            "expirationSeconds".to_string(),
                            serde_json::Value::Number(exp.into()),
                        );
                    }
                    if let Some(p) = sat.path.filter(|s| !s.is_empty()) {
                        sat_map.insert("path".to_string(), serde_json::Value::String(p));
                    }
                    sm.insert(
                        "serviceAccountToken".to_string(),
                        serde_json::Value::Object(sat_map),
                    );
                }
                serde_json::Value::Object(sm)
            })
            .collect();
        m.insert(
            "sources".to_string(),
            serde_json::Value::Array(sources_json),
        );
    }
    if let Some(dm) = proj.default_mode.filter(|&v| v != 0) {
        m.insert(
            "defaultMode".to_string(),
            serde_json::Value::Number(dm.into()),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_http_get_to_json(http_get: core_v1::HttpGetAction) -> serde_json::Value {
    let mut hg = serde_json::Map::new();
    if let Some(p) = http_get.path.filter(|s| !s.is_empty()) {
        hg.insert("path".to_string(), serde_json::Value::String(p));
    }
    if let Some(port) = http_get.port {
        hg.insert("port".to_string(), gen_int_or_string_to_json(&port));
    }
    if let Some(h) = http_get.host.filter(|s| !s.is_empty()) {
        hg.insert("host".to_string(), serde_json::Value::String(h));
    }
    if let Some(s) = http_get.scheme.filter(|s| !s.is_empty()) {
        hg.insert("scheme".to_string(), serde_json::Value::String(s));
    }
    serde_json::Value::Object(hg)
}

fn gen_tcp_socket_to_json(tcp: core_v1::TcpSocketAction) -> serde_json::Value {
    let mut ts = serde_json::Map::new();
    if let Some(port) = tcp.port {
        ts.insert("port".to_string(), gen_int_or_string_to_json(&port));
    }
    if let Some(h) = tcp.host.filter(|s| !s.is_empty()) {
        ts.insert("host".to_string(), serde_json::Value::String(h));
    }
    serde_json::Value::Object(ts)
}

fn gen_probe_handler_to_json(
    handler: core_v1::ProbeHandler,
    m: &mut serde_json::Map<String, serde_json::Value>,
) {
    if let Some(exec) = handler.exec {
        if !exec.command.is_empty() {
            m.insert(
                "exec".to_string(),
                serde_json::json!({ "command": exec.command }),
            );
        }
    }
    if let Some(http_get) = handler.http_get {
        m.insert("httpGet".to_string(), gen_http_get_to_json(http_get));
    }
    if let Some(tcp) = handler.tcp_socket {
        m.insert("tcpSocket".to_string(), gen_tcp_socket_to_json(tcp));
    }
    if let Some(grpc) = handler.grpc {
        m.insert(
            "grpc".to_string(),
            serde_json::json!({ "port": grpc.port, "service": grpc.service }),
        );
    }
}

fn gen_probe_to_json(p: core_v1::Probe) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(handler) = p.handler {
        gen_probe_handler_to_json(handler, &mut m);
    }
    if let Some(v) = p.initial_delay_seconds.filter(|&v| v != 0) {
        m.insert(
            "initialDelaySeconds".to_string(),
            serde_json::Value::Number(v.into()),
        );
    }
    if let Some(v) = p.timeout_seconds.filter(|&v| v != 0) {
        m.insert(
            "timeoutSeconds".to_string(),
            serde_json::Value::Number(v.into()),
        );
    }
    if let Some(v) = p.period_seconds.filter(|&v| v != 0) {
        m.insert(
            "periodSeconds".to_string(),
            serde_json::Value::Number(v.into()),
        );
    }
    if let Some(v) = p.success_threshold.filter(|&v| v != 0) {
        m.insert(
            "successThreshold".to_string(),
            serde_json::Value::Number(v.into()),
        );
    }
    if let Some(v) = p.failure_threshold.filter(|&v| v != 0) {
        m.insert(
            "failureThreshold".to_string(),
            serde_json::Value::Number(v.into()),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_lifecycle_handler_to_json(h: core_v1::LifecycleHandler) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(exec) = h.exec {
        if !exec.command.is_empty() {
            m.insert(
                "exec".to_string(),
                serde_json::json!({ "command": exec.command }),
            );
        }
    }
    if let Some(http_get) = h.http_get {
        m.insert("httpGet".to_string(), gen_http_get_to_json(http_get));
    }
    if let Some(tcp) = h.tcp_socket {
        m.insert("tcpSocket".to_string(), gen_tcp_socket_to_json(tcp));
    }
    if let Some(sleep) = h.sleep {
        m.insert(
            "sleep".to_string(),
            serde_json::json!({ "seconds": sleep.seconds }),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_lifecycle_to_json(lc: core_v1::Lifecycle) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(h) = lc.post_start {
        m.insert("postStart".to_string(), gen_lifecycle_handler_to_json(h));
    }
    if let Some(h) = lc.pre_stop {
        m.insert("preStop".to_string(), gen_lifecycle_handler_to_json(h));
    }
    serde_json::Value::Object(m)
}

fn gen_capabilities_to_json(caps: core_v1::Capabilities) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !caps.add.is_empty() {
        m.insert(
            "add".to_string(),
            serde_json::Value::Array(
                caps.add
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !caps.drop.is_empty() {
        m.insert(
            "drop".to_string(),
            serde_json::Value::Array(
                caps.drop
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_seccomp_profile_to_json(sp: core_v1::SeccompProfile) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = sp.r#type.filter(|s| !s.is_empty()) {
        m.insert("type".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = sp.localhost_profile.filter(|s| !s.is_empty()) {
        m.insert("localhostProfile".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

/// Container-level SecurityContext (Container.securityContext, proto field 15).
///
/// Without this, containers run as whatever UID/GID the image defaults to regardless of
/// runAsUser/runAsGroup, allowPrivilegeEscalation=false is silently ignored (containers can
/// escalate privileges even when the pod spec explicitly forbids it), and
/// readOnlyRootFilesystem is dropped (containers get a writable root fs against the spec).
fn gen_security_context_to_json(sc: core_v1::SecurityContext) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(caps) = sc.capabilities {
        m.insert("capabilities".to_string(), gen_capabilities_to_json(caps));
    }
    if let Some(v) = sc.privileged {
        m.insert("privileged".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = sc.run_as_user {
        m.insert("runAsUser".to_string(), serde_json::Value::Number(v.into()));
    }
    if let Some(v) = sc.run_as_group {
        m.insert(
            "runAsGroup".to_string(),
            serde_json::Value::Number(v.into()),
        );
    }
    if let Some(v) = sc.run_as_non_root {
        m.insert("runAsNonRoot".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = sc.read_only_root_filesystem {
        m.insert(
            "readOnlyRootFilesystem".to_string(),
            serde_json::Value::Bool(v),
        );
    }
    if let Some(v) = sc.allow_privilege_escalation {
        m.insert(
            "allowPrivilegeEscalation".to_string(),
            serde_json::Value::Bool(v),
        );
    }
    if let Some(sp) = sc.seccomp_profile {
        m.insert(
            "seccompProfile".to_string(),
            gen_seccomp_profile_to_json(sp),
        );
    }
    serde_json::Value::Object(m)
}

/// Pod-level SecurityContext (PodSpec.securityContext, proto field 14), including sysctls.
///
/// Without this, pod.Spec.SecurityContext.RunAsUser/RunAsGroup are silently dropped for every
/// protobuf-created pod, and sysctls never reach validate_pod_sysctls or the kubelet — a pod
/// requesting `kernel.shm_rmid_forced=1` boots with the node default instead.
fn gen_pod_security_context_to_json(sc: core_v1::PodSecurityContext) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = sc.run_as_user {
        m.insert("runAsUser".to_string(), serde_json::Value::Number(v.into()));
    }
    if let Some(v) = sc.run_as_group {
        m.insert(
            "runAsGroup".to_string(),
            serde_json::Value::Number(v.into()),
        );
    }
    if let Some(v) = sc.run_as_non_root {
        m.insert("runAsNonRoot".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = sc.fs_group {
        m.insert("fsGroup".to_string(), serde_json::Value::Number(v.into()));
    }
    if !sc.supplemental_groups.is_empty() {
        m.insert(
            "supplementalGroups".to_string(),
            serde_json::Value::Array(
                sc.supplemental_groups
                    .into_iter()
                    .map(|g| serde_json::Value::Number(g.into()))
                    .collect(),
            ),
        );
    }
    if !sc.sysctls.is_empty() {
        let sysctls: Vec<serde_json::Value> = sc
            .sysctls
            .into_iter()
            .map(|s| {
                let mut sm = serde_json::Map::new();
                if let Some(n) = s.name.filter(|s| !s.is_empty()) {
                    sm.insert("name".to_string(), serde_json::Value::String(n));
                }
                if let Some(v) = s.value.filter(|s| !s.is_empty()) {
                    sm.insert("value".to_string(), serde_json::Value::String(v));
                }
                serde_json::Value::Object(sm)
            })
            .collect();
        m.insert("sysctls".to_string(), serde_json::Value::Array(sysctls));
    }
    if let Some(sp) = sc.seccomp_profile {
        m.insert(
            "seccompProfile".to_string(),
            gen_seccomp_profile_to_json(sp),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_container_to_json(c: core_v1::Container) -> serde_json::Value {
    let mut cm = serde_json::Map::with_capacity(18);
    if let Some(v) = c.name.filter(|s| !s.is_empty()) {
        cm.insert("name".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = c.image.filter(|s| !s.is_empty()) {
        cm.insert("image".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = c.image_pull_policy.filter(|s| !s.is_empty()) {
        cm.insert("imagePullPolicy".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = c.termination_message_path.filter(|s| !s.is_empty()) {
        cm.insert(
            "terminationMessagePath".to_string(),
            serde_json::Value::String(v),
        );
    }
    if let Some(v) = c.termination_message_policy.filter(|s| !s.is_empty()) {
        cm.insert(
            "terminationMessagePolicy".to_string(),
            serde_json::Value::String(v),
        );
    }
    if !c.command.is_empty() {
        cm.insert(
            "command".to_string(),
            serde_json::Value::Array(
                c.command
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !c.args.is_empty() {
        cm.insert(
            "args".to_string(),
            serde_json::Value::Array(c.args.into_iter().map(serde_json::Value::String).collect()),
        );
    }
    if !c.ports.is_empty() {
        let ports_json: Vec<serde_json::Value> = c
            .ports
            .into_iter()
            .map(|p| {
                let mut pm = serde_json::Map::new();
                if let Some(v) = p.name.filter(|s| !s.is_empty()) {
                    pm.insert("name".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = p.container_port.filter(|&n| n != 0) {
                    pm.insert(
                        "containerPort".to_string(),
                        serde_json::Value::Number(v.into()),
                    );
                }
                if let Some(v) = p.host_port.filter(|&n| n != 0) {
                    pm.insert("hostPort".to_string(), serde_json::Value::Number(v.into()));
                }
                if let Some(v) = p.protocol.filter(|s| !s.is_empty()) {
                    pm.insert("protocol".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = p.host_ip.filter(|s| !s.is_empty()) {
                    pm.insert("hostIP".to_string(), serde_json::Value::String(v));
                }
                serde_json::Value::Object(pm)
            })
            .collect();
        cm.insert("ports".to_string(), serde_json::Value::Array(ports_json));
    }
    if !c.env.is_empty() {
        let env_json: Vec<serde_json::Value> = c
            .env
            .into_iter()
            .map(|ev| {
                let mut em = serde_json::Map::new();
                if let Some(v) = ev.name.filter(|s| !s.is_empty()) {
                    em.insert("name".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = ev.value.filter(|s| !s.is_empty()) {
                    em.insert("value".to_string(), serde_json::Value::String(v));
                }
                if let Some(vf) = ev.value_from {
                    let mut vfm = serde_json::Map::new();
                    if let Some(fr) = vf.field_ref {
                        let mut frm = serde_json::Map::new();
                        if let Some(v) = fr.api_version.filter(|s| !s.is_empty()) {
                            frm.insert("apiVersion".to_string(), serde_json::Value::String(v));
                        }
                        if let Some(v) = fr.field_path.filter(|s| !s.is_empty()) {
                            frm.insert("fieldPath".to_string(), serde_json::Value::String(v));
                        }
                        vfm.insert("fieldRef".to_string(), serde_json::Value::Object(frm));
                    }
                    if let Some(rfr) = vf.resource_field_ref {
                        let mut rfrm = serde_json::Map::new();
                        if let Some(v) = rfr.container_name.filter(|s| !s.is_empty()) {
                            rfrm.insert("containerName".to_string(), serde_json::Value::String(v));
                        }
                        if let Some(v) = rfr.resource.filter(|s| !s.is_empty()) {
                            rfrm.insert("resource".to_string(), serde_json::Value::String(v));
                        }
                        if let Some(divisor_str) = rfr.divisor.and_then(|q| q.string) {
                            if !divisor_str.is_empty() {
                                rfrm.insert(
                                    "divisor".to_string(),
                                    serde_json::Value::String(divisor_str),
                                );
                            }
                        }
                        vfm.insert(
                            "resourceFieldRef".to_string(),
                            serde_json::Value::Object(rfrm),
                        );
                    }
                    if let Some(cmkr) = vf.config_map_key_ref {
                        let mut cmkrm = serde_json::Map::new();
                        if let Some(lor) = cmkr.local_object_reference {
                            if let Some(v) = lor.name.filter(|s| !s.is_empty()) {
                                cmkrm.insert("name".to_string(), serde_json::Value::String(v));
                            }
                        }
                        if let Some(v) = cmkr.key.filter(|s| !s.is_empty()) {
                            cmkrm.insert("key".to_string(), serde_json::Value::String(v));
                        }
                        if let Some(true) = cmkr.optional {
                            cmkrm.insert("optional".to_string(), serde_json::Value::Bool(true));
                        }
                        vfm.insert(
                            "configMapKeyRef".to_string(),
                            serde_json::Value::Object(cmkrm),
                        );
                    }
                    if let Some(skr) = vf.secret_key_ref {
                        let mut skrm = serde_json::Map::new();
                        if let Some(lor) = skr.local_object_reference {
                            if let Some(v) = lor.name.filter(|s| !s.is_empty()) {
                                skrm.insert("name".to_string(), serde_json::Value::String(v));
                            }
                        }
                        if let Some(v) = skr.key.filter(|s| !s.is_empty()) {
                            skrm.insert("key".to_string(), serde_json::Value::String(v));
                        }
                        if let Some(true) = skr.optional {
                            skrm.insert("optional".to_string(), serde_json::Value::Bool(true));
                        }
                        vfm.insert("secretKeyRef".to_string(), serde_json::Value::Object(skrm));
                    }
                    em.insert("valueFrom".to_string(), serde_json::Value::Object(vfm));
                }
                serde_json::Value::Object(em)
            })
            .collect();
        cm.insert("env".to_string(), serde_json::Value::Array(env_json));
    }
    if !c.env_from.is_empty() {
        let env_from_json: Vec<serde_json::Value> = c
            .env_from
            .into_iter()
            .map(|ef| {
                let mut efm = serde_json::Map::new();
                if let Some(v) = ef.prefix.filter(|s| !s.is_empty()) {
                    efm.insert("prefix".to_string(), serde_json::Value::String(v));
                }
                if let Some(cmr) = ef.config_map_ref {
                    let mut cmrm = serde_json::Map::new();
                    if let Some(lor) = cmr.local_object_reference {
                        if let Some(v) = lor.name.filter(|s| !s.is_empty()) {
                            cmrm.insert("name".to_string(), serde_json::Value::String(v));
                        }
                    }
                    if let Some(true) = cmr.optional {
                        cmrm.insert("optional".to_string(), serde_json::Value::Bool(true));
                    }
                    efm.insert("configMapRef".to_string(), serde_json::Value::Object(cmrm));
                }
                if let Some(sr) = ef.secret_ref {
                    let mut srm = serde_json::Map::new();
                    if let Some(lor) = sr.local_object_reference {
                        if let Some(v) = lor.name.filter(|s| !s.is_empty()) {
                            srm.insert("name".to_string(), serde_json::Value::String(v));
                        }
                    }
                    if let Some(true) = sr.optional {
                        srm.insert("optional".to_string(), serde_json::Value::Bool(true));
                    }
                    efm.insert("secretRef".to_string(), serde_json::Value::Object(srm));
                }
                serde_json::Value::Object(efm)
            })
            .collect();
        cm.insert(
            "envFrom".to_string(),
            serde_json::Value::Array(env_from_json),
        );
    }
    if let Some(res) = c.resources {
        let mut res_map = serde_json::Map::new();
        if !res.limits.is_empty() {
            res_map.insert("limits".to_string(), gen_quantity_map_to_json(res.limits));
        }
        if !res.requests.is_empty() {
            res_map.insert(
                "requests".to_string(),
                gen_quantity_map_to_json(res.requests),
            );
        }
        // Only emit "resources" when non-empty — see gen_downward_api_volume_source_to_json
        // for why materializing a wire-absent value breaks workload-template hash-collision
        // equality checks. k8s.io/api's Container.Resources is a value (not pointer) type, so
        // it is always present after protobuf decode even when the client set nothing.
        if !res_map.is_empty() {
            cm.insert("resources".to_string(), serde_json::Value::Object(res_map));
        }
    }
    if let Some(p) = c.liveness_probe {
        cm.insert("livenessProbe".to_string(), gen_probe_to_json(p));
    }
    if let Some(p) = c.readiness_probe {
        cm.insert("readinessProbe".to_string(), gen_probe_to_json(p));
    }
    if let Some(p) = c.startup_probe {
        cm.insert("startupProbe".to_string(), gen_probe_to_json(p));
    }
    if let Some(lc) = c.lifecycle {
        cm.insert("lifecycle".to_string(), gen_lifecycle_to_json(lc));
    }
    if let Some(sc) = c.security_context {
        cm.insert(
            "securityContext".to_string(),
            gen_security_context_to_json(sc),
        );
    }
    if !c.resize_policy.is_empty() {
        let rp_json: Vec<serde_json::Value> = c
            .resize_policy
            .into_iter()
            .map(|rp| {
                let mut rpm = serde_json::Map::new();
                if let Some(v) = rp.resource_name.filter(|s| !s.is_empty()) {
                    rpm.insert("resourceName".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = rp.restart_policy.filter(|s| !s.is_empty()) {
                    rpm.insert("restartPolicy".to_string(), serde_json::Value::String(v));
                }
                serde_json::Value::Object(rpm)
            })
            .collect();
        cm.insert(
            "resizePolicy".to_string(),
            serde_json::Value::Array(rp_json),
        );
    }
    if let Some(rp) = c.restart_policy.filter(|s| !s.is_empty()) {
        cm.insert("restartPolicy".to_string(), serde_json::Value::String(rp));
    }
    if !c.volume_mounts.is_empty() {
        let mounts: Vec<serde_json::Value> = c
            .volume_mounts
            .into_iter()
            .map(|vm| {
                let mut m = serde_json::Map::new();
                if let Some(v) = vm.name.filter(|s| !s.is_empty()) {
                    m.insert("name".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = vm.mount_path.filter(|s| !s.is_empty()) {
                    m.insert("mountPath".to_string(), serde_json::Value::String(v));
                }
                if let Some(true) = vm.read_only {
                    m.insert("readOnly".to_string(), serde_json::Value::Bool(true));
                }
                if let Some(v) = vm.sub_path.filter(|s| !s.is_empty()) {
                    m.insert("subPath".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = vm.sub_path_expr.filter(|s| !s.is_empty()) {
                    m.insert("subPathExpr".to_string(), serde_json::Value::String(v));
                }
                serde_json::Value::Object(m)
            })
            .collect();
        cm.insert("volumeMounts".to_string(), serde_json::Value::Array(mounts));
    }
    serde_json::Value::Object(cm)
}

/// EphemeralContainer (PodSpec.ephemeralContainers, proto field 34) — decoded so that
/// UpdateEphemeralContainers (which client-go sends as protobuf) round-trips the debug
/// container a user attaches via `kubectl debug`/the ephemeralcontainers subresource.
/// apply_ephemeral_containers_patch (pods.rs) merges on "name", so name/image/command are
/// the fields conformance actually asserts on; env/volumeMounts are included for parity
/// with the regular container decode.
fn gen_ephemeral_container_to_json(ec: core_v1::EphemeralContainer) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(tcn) = ec.target_container_name.filter(|s| !s.is_empty()) {
        m.insert(
            "targetContainerName".to_string(),
            serde_json::Value::String(tcn),
        );
    }
    let Some(c) = ec.ephemeral_container_common else {
        return serde_json::Value::Object(m);
    };
    if let Some(v) = c.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = c.image.filter(|s| !s.is_empty()) {
        m.insert("image".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = c.image_pull_policy.filter(|s| !s.is_empty()) {
        m.insert("imagePullPolicy".to_string(), serde_json::Value::String(v));
    }
    if !c.command.is_empty() {
        m.insert(
            "command".to_string(),
            serde_json::Value::Array(
                c.command
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !c.args.is_empty() {
        m.insert(
            "args".to_string(),
            serde_json::Value::Array(c.args.into_iter().map(serde_json::Value::String).collect()),
        );
    }
    if !c.env.is_empty() {
        let env_json: Vec<serde_json::Value> = c
            .env
            .into_iter()
            .map(|ev| {
                let mut em = serde_json::Map::new();
                if let Some(v) = ev.name.filter(|s| !s.is_empty()) {
                    em.insert("name".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = ev.value.filter(|s| !s.is_empty()) {
                    em.insert("value".to_string(), serde_json::Value::String(v));
                }
                serde_json::Value::Object(em)
            })
            .collect();
        m.insert("env".to_string(), serde_json::Value::Array(env_json));
    }
    if !c.volume_mounts.is_empty() {
        let mounts: Vec<serde_json::Value> = c
            .volume_mounts
            .into_iter()
            .map(|vm| {
                let mut vmm = serde_json::Map::new();
                if let Some(v) = vm.name.filter(|s| !s.is_empty()) {
                    vmm.insert("name".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = vm.mount_path.filter(|s| !s.is_empty()) {
                    vmm.insert("mountPath".to_string(), serde_json::Value::String(v));
                }
                if let Some(true) = vm.read_only {
                    vmm.insert("readOnly".to_string(), serde_json::Value::Bool(true));
                }
                serde_json::Value::Object(vmm)
            })
            .collect();
        m.insert("volumeMounts".to_string(), serde_json::Value::Array(mounts));
    }
    if let Some(sc) = c.security_context {
        m.insert(
            "securityContext".to_string(),
            gen_security_context_to_json(sc),
        );
    }
    serde_json::Value::Object(m)
}

pub(crate) fn gen_pod_spec_to_json(spec: core_v1::PodSpec) -> serde_json::Value {
    let containers: Vec<serde_json::Value> = spec
        .containers
        .into_iter()
        .map(gen_container_to_json)
        .collect();

    let mut spec_map = serde_json::Map::with_capacity(14);
    if !spec.volumes.is_empty() {
        let volumes_json: Vec<serde_json::Value> = spec
            .volumes
            .into_iter()
            .map(|v| {
                let mut vm = serde_json::Map::new();
                if let Some(n) = v.name.filter(|s| !s.is_empty()) {
                    vm.insert("name".to_string(), serde_json::Value::String(n));
                }
                if let Some(src) = v.volume_source {
                    if let Some(hp) = src.host_path {
                        let mut hp_map = serde_json::Map::new();
                        if let Some(p) = hp.path.filter(|s| !s.is_empty()) {
                            hp_map.insert("path".to_string(), serde_json::Value::String(p));
                        }
                        if let Some(t) = hp.r#type.filter(|s| !s.is_empty()) {
                            hp_map.insert("type".to_string(), serde_json::Value::String(t));
                        }
                        vm.insert("hostPath".to_string(), serde_json::Value::Object(hp_map));
                    }
                    if let Some(ed) = src.empty_dir {
                        let mut ed_map = serde_json::Map::new();
                        if let Some(medium) = ed.medium.filter(|s| !s.is_empty()) {
                            ed_map.insert("medium".to_string(), serde_json::Value::String(medium));
                        }
                        vm.insert("emptyDir".to_string(), serde_json::Value::Object(ed_map));
                    }
                    if let Some(s) = src.secret {
                        let optional = s.optional;
                        if let Some(secret_name) = s.secret_name.filter(|s| !s.is_empty()) {
                            let mut secret_map = serde_json::Map::new();
                            secret_map.insert(
                                "secretName".to_string(),
                                serde_json::Value::String(secret_name),
                            );
                            if !s.items.is_empty() {
                                secret_map
                                    .insert("items".to_string(), gen_key_to_path_to_json(s.items));
                            }
                            // See gen_downward_api_volume_source_to_json: omit rather than
                            // default to 420 when unset.
                            if let Some(dm) = s.default_mode.filter(|&v| v != 0) {
                                secret_map.insert(
                                    "defaultMode".to_string(),
                                    serde_json::Value::Number(dm.into()),
                                );
                            }
                            if let Some(true) = optional {
                                secret_map
                                    .insert("optional".to_string(), serde_json::Value::Bool(true));
                            }
                            vm.insert("secret".to_string(), serde_json::Value::Object(secret_map));
                        }
                    }
                    if let Some(pvc) = src.persistent_volume_claim {
                        if let Some(claim_name) = pvc.claim_name.filter(|s| !s.is_empty()) {
                            let mut pvc_map = serde_json::Map::new();
                            pvc_map.insert(
                                "claimName".to_string(),
                                serde_json::Value::String(claim_name),
                            );
                            if let Some(true) = pvc.read_only {
                                pvc_map
                                    .insert("readOnly".to_string(), serde_json::Value::Bool(true));
                            }
                            vm.insert(
                                "persistentVolumeClaim".to_string(),
                                serde_json::Value::Object(pvc_map),
                            );
                        }
                    }
                    if let Some(da) = src.downward_api {
                        vm.insert(
                            "downwardAPI".to_string(),
                            gen_downward_api_volume_source_to_json(da.items, da.default_mode),
                        );
                    }
                    if let Some(cm) = src.config_map {
                        let optional = cm.optional;
                        if let Some(lor) = cm.local_object_reference {
                            if let Some(name) = lor.name.filter(|s| !s.is_empty()) {
                                let mut cm_map = serde_json::Map::new();
                                cm_map.insert("name".to_string(), serde_json::Value::String(name));
                                if !cm.items.is_empty() {
                                    cm_map.insert(
                                        "items".to_string(),
                                        gen_key_to_path_to_json(cm.items),
                                    );
                                }
                                // See gen_downward_api_volume_source_to_json: omit rather
                                // than default to 420 when unset.
                                if let Some(dm) = cm.default_mode.filter(|&v| v != 0) {
                                    cm_map.insert(
                                        "defaultMode".to_string(),
                                        serde_json::Value::Number(dm.into()),
                                    );
                                }
                                if let Some(true) = optional {
                                    cm_map.insert(
                                        "optional".to_string(),
                                        serde_json::Value::Bool(true),
                                    );
                                }
                                vm.insert(
                                    "configMap".to_string(),
                                    serde_json::Value::Object(cm_map),
                                );
                            }
                        }
                    }
                    if let Some(proj) = src.projected {
                        vm.insert(
                            "projected".to_string(),
                            gen_projected_volume_source_to_json(proj),
                        );
                    }
                    if let Some(img) = src.image {
                        let mut img_map = serde_json::Map::new();
                        if let Some(r) = img.reference.filter(|s| !s.is_empty()) {
                            img_map.insert("reference".to_string(), serde_json::Value::String(r));
                        }
                        if let Some(pp) = img.pull_policy.filter(|s| !s.is_empty()) {
                            img_map.insert("pullPolicy".to_string(), serde_json::Value::String(pp));
                        }
                        vm.insert("image".to_string(), serde_json::Value::Object(img_map));
                    }
                }
                serde_json::Value::Object(vm)
            })
            .collect();
        spec_map.insert(
            "volumes".to_string(),
            serde_json::Value::Array(volumes_json),
        );
    }
    spec_map.insert(
        "containers".to_string(),
        serde_json::Value::Array(containers),
    );
    if let Some(rp) = spec.restart_policy.filter(|s| !s.is_empty()) {
        spec_map.insert("restartPolicy".to_string(), serde_json::Value::String(rp));
    }
    // dnsPolicy — without this, an explicit "None" (required to make dnsConfig authoritative
    // instead of merged/appended) is silently dropped, create-defaulting stamps "ClusterFirst"
    // instead, and the kubelet ignores dnsConfig.nameservers because ClusterFirst's own
    // resolv.conf generation takes precedence — live-verified: "should support configurable
    // pod DNS nameservers" fails this way even though dnsConfig itself decodes correctly.
    if let Some(dp) = spec.dns_policy.filter(|s| !s.is_empty()) {
        spec_map.insert("dnsPolicy".to_string(), serde_json::Value::String(dp));
    }
    if let Some(ads) = spec.active_deadline_seconds {
        if ads > 0 {
            spec_map.insert(
                "activeDeadlineSeconds".to_string(),
                serde_json::Value::Number(serde_json::Number::from(ads)),
            );
        }
    }
    // terminationGracePeriodSeconds — a Go *int64 pointer field upstream. Unlike
    // activeDeadlineSeconds, 0 is a legitimate "kill immediately" value a client can set on
    // purpose, not noise, so it must be emitted whenever the wire carried any value at all.
    // Dropping it makes KCM's Deployment controller see nil here vs its own cached &N, which
    // EqualIgnoreHash treats as unequal — triggering an unbounded ReplicaSet collision storm.
    if let Some(tgps) = spec.termination_grace_period_seconds {
        spec_map.insert(
            "terminationGracePeriodSeconds".to_string(),
            serde_json::Value::Number(serde_json::Number::from(tgps)),
        );
    }
    if let Some(san) = spec.service_account_name.filter(|s| !s.is_empty()) {
        spec_map.insert(
            "serviceAccountName".to_string(),
            serde_json::Value::String(san),
        );
    }
    if let Some(nn) = spec.node_name.filter(|s| !s.is_empty()) {
        spec_map.insert("nodeName".to_string(), serde_json::Value::String(nn));
    }
    if let Some(hn) = spec.hostname.filter(|s| !s.is_empty()) {
        spec_map.insert("hostname".to_string(), serde_json::Value::String(hn));
    }
    if let Some(sd) = spec.subdomain.filter(|s| !s.is_empty()) {
        spec_map.insert("subdomain".to_string(), serde_json::Value::String(sd));
    }
    if !spec.init_containers.is_empty() {
        let init_containers: Vec<serde_json::Value> = spec
            .init_containers
            .into_iter()
            .map(gen_container_to_json)
            .collect();
        spec_map.insert(
            "initContainers".to_string(),
            serde_json::Value::Array(init_containers),
        );
    }
    if let Some(esl) = spec.enable_service_links {
        spec_map.insert(
            "enableServiceLinks".to_string(),
            serde_json::Value::Bool(esl),
        );
    }
    if let Some(rcn) = spec.runtime_class_name.filter(|s| !s.is_empty()) {
        spec_map.insert(
            "runtimeClassName".to_string(),
            serde_json::Value::String(rcn),
        );
    }
    // tolerations — required for taint-based eviction and scheduling constraints.
    // Without this field, pods that tolerate taints are treated as if they have no
    // tolerations, causing the scheduler to reject them on tainted nodes.
    if !spec.tolerations.is_empty() {
        let tols: Vec<serde_json::Value> = spec
            .tolerations
            .into_iter()
            .map(|t| {
                let mut m = serde_json::Map::new();
                if let Some(k) = t.key.filter(|s| !s.is_empty()) {
                    m.insert("key".to_string(), serde_json::Value::String(k));
                }
                if let Some(op) = t.operator.filter(|s| !s.is_empty()) {
                    m.insert("operator".to_string(), serde_json::Value::String(op));
                }
                if let Some(v) = t.value.filter(|s| !s.is_empty()) {
                    m.insert("value".to_string(), serde_json::Value::String(v));
                }
                if let Some(eff) = t.effect.filter(|s| !s.is_empty()) {
                    m.insert("effect".to_string(), serde_json::Value::String(eff));
                }
                if let Some(ts) = t.toleration_seconds {
                    m.insert(
                        "tolerationSeconds".to_string(),
                        serde_json::Value::Number(ts.into()),
                    );
                }
                serde_json::Value::Object(m)
            })
            .collect();
        spec_map.insert("tolerations".to_string(), serde_json::Value::Array(tols));
    }
    // schedulingGates — client-go/kube-controller-manager's typed Pod client (used by e.g.
    // the ReplicaSet controller to create pods from a template) sends protobuf by default,
    // not JSON. Without this field, a gated pod created via a controller (as opposed to a
    // raw `kubectl apply`/JSON POST) silently loses its schedulingGates on decode, so
    // needs_scheduling never sees them non-empty and schedules the pod immediately —
    // failing "validates Pods with non-empty schedulingGates are blocked on scheduling".
    if !spec.scheduling_gates.is_empty() {
        let gates: Vec<serde_json::Value> = spec
            .scheduling_gates
            .into_iter()
            .filter_map(|g| g.name.filter(|s| !s.is_empty()))
            .map(|name| serde_json::json!({ "name": name }))
            .collect();
        spec_map.insert(
            "schedulingGates".to_string(),
            serde_json::Value::Array(gates),
        );
    }
    // priorityClassName — used by PriorityAdmission to look up the integer priority value.
    // Without this field, pods are treated as having no priority class, which can result in
    // them being preempted by lower-priority pods that happen to have a class set.
    if let Some(pcn) = spec.priority_class_name.filter(|s| !s.is_empty()) {
        spec_map.insert(
            "priorityClassName".to_string(),
            serde_json::Value::String(pcn),
        );
    }
    // priority — the integer priority value resolved by the scheduler from priorityClassName.
    // Without this field, the scheduler cannot perform preemption ordering correctly.
    if let Some(p) = spec.priority.filter(|&v| v != 0) {
        spec_map.insert("priority".to_string(), serde_json::Value::Number(p.into()));
    }
    // hostNetwork — the kubelet reads this to decide whether to share the host network
    // namespace; dropping it makes KubeletManagedEtcHosts and hostPort-on-hostNetwork
    // behavior silently wrong for every protobuf-created pod.
    if let Some(hn) = spec.host_network {
        spec_map.insert("hostNetwork".to_string(), serde_json::Value::Bool(hn));
    }
    // automountServiceAccountToken — pod-level override of the ServiceAccount default;
    // dropping it means a pod that explicitly opted out of token automount gets one anyway.
    if let Some(v) = spec.automount_service_account_token {
        spec_map.insert(
            "automountServiceAccountToken".to_string(),
            serde_json::Value::Bool(v),
        );
    }
    // hostAliases — injected into the pod's /etc/hosts by the kubelet; dropping this means
    // the extra host entries a pod asked for silently never appear.
    if !spec.host_aliases.is_empty() {
        let aliases: Vec<serde_json::Value> = spec
            .host_aliases
            .into_iter()
            .map(|ha| {
                let mut m = serde_json::Map::new();
                if let Some(ip) = ha.ip.filter(|s| !s.is_empty()) {
                    m.insert("ip".to_string(), serde_json::Value::String(ip));
                }
                if !ha.hostnames.is_empty() {
                    m.insert(
                        "hostnames".to_string(),
                        serde_json::Value::Array(
                            ha.hostnames
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                }
                serde_json::Value::Object(m)
            })
            .collect();
        spec_map.insert("hostAliases".to_string(), serde_json::Value::Array(aliases));
    }
    // dnsConfig — merged with dnsPolicy by the kubelet to build the pod's resolv.conf;
    // dropping this silently discards user-specified nameservers/search/options.
    if let Some(dc) = spec.dns_config {
        let mut m = serde_json::Map::new();
        if !dc.nameservers.is_empty() {
            m.insert(
                "nameservers".to_string(),
                serde_json::Value::Array(
                    dc.nameservers
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if !dc.searches.is_empty() {
            m.insert(
                "searches".to_string(),
                serde_json::Value::Array(
                    dc.searches
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if !dc.options.is_empty() {
            let opts: Vec<serde_json::Value> = dc
                .options
                .into_iter()
                .map(|o| {
                    let mut om = serde_json::Map::new();
                    if let Some(n) = o.name.filter(|s| !s.is_empty()) {
                        om.insert("name".to_string(), serde_json::Value::String(n));
                    }
                    if let Some(v) = o.value.filter(|s| !s.is_empty()) {
                        om.insert("value".to_string(), serde_json::Value::String(v));
                    }
                    serde_json::Value::Object(om)
                })
                .collect();
            m.insert("options".to_string(), serde_json::Value::Array(opts));
        }
        spec_map.insert("dnsConfig".to_string(), serde_json::Value::Object(m));
    }
    // ephemeralContainers — needed so UpdateEphemeralContainers (protobuf by default in
    // client-go) round-trips the debug container through apply_ephemeral_containers_patch.
    if !spec.ephemeral_containers.is_empty() {
        let ecs: Vec<serde_json::Value> = spec
            .ephemeral_containers
            .into_iter()
            .map(gen_ephemeral_container_to_json)
            .collect();
        spec_map.insert(
            "ephemeralContainers".to_string(),
            serde_json::Value::Array(ecs),
        );
    }
    // securityContext — pod-level RunAsUser/RunAsGroup/fsGroup/sysctls; dropping this is a
    // P1 data-loss bug (containers run as whatever the image defaults to, sysctls never
    // reach the kubelet or validate_pod_sysctls).
    if let Some(sc) = spec.security_context {
        spec_map.insert(
            "securityContext".to_string(),
            gen_pod_security_context_to_json(sc),
        );
    }
    serde_json::Value::Object(spec_map)
}

pub(crate) fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    let mut m = serde_json::json!({ "creationTimestamp": serde_json::Value::Null });
    if let Some(n) = meta.name.filter(|s| !s.is_empty()) {
        m["name"] = serde_json::Value::String(n);
    }
    if let Some(n) = meta.generate_name.filter(|s| !s.is_empty()) {
        m["generateName"] = serde_json::Value::String(n);
    }
    if let Some(n) = meta.namespace.filter(|s| !s.is_empty()) {
        m["namespace"] = serde_json::Value::String(n);
    }
    if let Some(u) = meta.uid.filter(|s| !s.is_empty()) {
        m["uid"] = serde_json::Value::String(u);
    }
    if let Some(rv) = meta.resource_version.filter(|s| !s.is_empty()) {
        m["resourceVersion"] = serde_json::Value::String(rv);
    }
    if let Some(g) = meta.generation.filter(|&v| v != 0) {
        m["generation"] = serde_json::Value::Number(g.into());
    }
    if let Some(ts) = meta.creation_timestamp {
        if let Some(secs) = ts.seconds {
            if secs > 0 {
                m["creationTimestamp"] =
                    serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
            }
        }
    }
    if !meta.labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = meta
            .labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["labels"] = serde_json::Value::Object(labels);
    }
    if !meta.annotations.is_empty() {
        let annotations: serde_json::Map<String, serde_json::Value> = meta
            .annotations
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["annotations"] = serde_json::Value::Object(annotations);
    }
    if !meta.owner_references.is_empty() {
        let refs: Vec<serde_json::Value> = meta
            .owner_references
            .into_iter()
            .map(|r| {
                let mut entry = serde_json::json!({});
                if let Some(v) = r.api_version.filter(|s| !s.is_empty()) {
                    entry["apiVersion"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
                    entry["kind"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.name.filter(|s| !s.is_empty()) {
                    entry["name"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.uid.filter(|s| !s.is_empty()) {
                    entry["uid"] = serde_json::Value::String(v);
                }
                if let Some(ctrl) = r.controller {
                    entry["controller"] = serde_json::Value::Bool(ctrl);
                }
                if let Some(bod) = r.block_owner_deletion {
                    entry["blockOwnerDeletion"] = serde_json::Value::Bool(bod);
                }
                entry
            })
            .collect();
        if !refs.is_empty() {
            m["ownerReferences"] = serde_json::Value::Array(refs);
        }
    }
    if !meta.finalizers.is_empty() {
        let fins: Vec<serde_json::Value> = meta
            .finalizers
            .into_iter()
            .map(serde_json::Value::String)
            .collect();
        m["finalizers"] = serde_json::Value::Array(fins);
    }
    m
}

pub(crate) fn gen_pod_template_spec_to_json(tmpl: core_v1::PodTemplateSpec) -> serde_json::Value {
    let mut t = serde_json::json!({});
    if let Some(meta) = tmpl.metadata {
        t["metadata"] = gen_object_meta_to_json(meta);
    }
    if let Some(pod_spec) = tmpl.spec {
        t["spec"] = gen_pod_spec_to_json(pod_spec);
    }
    t
}

fn gen_quantity_map_btree_to_json(
    map: std::collections::HashMap<
        String,
        super::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity,
    >,
) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (k, v) in map {
        let s = v.string.unwrap_or_default();
        if !s.is_empty() {
            out.insert(k, serde_json::Value::String(s));
        }
    }
    serde_json::Value::Object(out)
}

fn gen_object_reference_to_json(r: core_v1::ObjectReference) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
        m.insert("kind".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.namespace.filter(|s| !s.is_empty()) {
        m.insert("namespace".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.uid.filter(|s| !s.is_empty()) {
        m.insert("uid".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.api_version.filter(|s| !s.is_empty()) {
        m.insert("apiVersion".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.resource_version.filter(|s| !s.is_empty()) {
        m.insert("resourceVersion".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.field_path.filter(|s| !s.is_empty()) {
        m.insert("fieldPath".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

// ---- Decoder A: Namespace --------------------------------------------------

pub fn decode_namespace_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let ns = core_v1::Namespace::decode(data).ok()?;
    let meta = gen_object_meta_to_json(ns.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": meta
    });
    if let Some(spec) = ns.spec {
        if !spec.finalizers.is_empty() {
            let fins: Vec<serde_json::Value> = spec
                .finalizers
                .into_iter()
                .map(serde_json::Value::String)
                .collect();
            obj["spec"] = serde_json::json!({ "finalizers": fins });
        }
    }
    // (mayor-oww6 — this IS the mayor-ftkl PANIC-1 fix, see below) This decoder never
    // read `ns.status` at all, so any protobuf-encoded Namespace write (Content-Type:
    // application/vnd.kubernetes.protobuf) silently lost status.phase and
    // status.conditions together — put_namespace_status wholesale-replaces stored status
    // with whatever this decoder returns, which was nothing.
    //
    // A previous version of this comment claimed this was unrelated to the mayor-ftkl
    // "should apply changes to a namespace status" conformance panic (namespace.go:365,
    // `index out of range [-1]`), reasoning that "that test's client uses plain JSON"
    // because this stack's kube-controller-manager is started with
    // --kube-api-content-type=application/json. That reasoning conflated KCM's own
    // client (a separate process) with the e2e test binary's client: the upstream e2e
    // framework defaults EVERY typed clientset's ContentType to
    // application/vnd.kubernetes.protobuf (test/e2e/framework/test_context.go's
    // --kube-api-content-type flag, unset by our sonobuoy invocation), so
    // `f.ClientSet.CoreV1().Namespaces().UpdateStatus(...)` — the exact call the failing
    // test makes after appending a condition — sends protobuf and hits this decoder.
    // Verified live (mayor-ftkl worker, 2026-07-07): the real upstream conformance spec,
    // run via `sonobuoy --e2e-focus="should apply changes to a namespace status"` against
    // a build with this fix, passed twice in a row (~0.02s, no panic); reverting this `if
    // let Some(status) = ns.status` block reproduces the empty status.conditions the
    // panic depends on via a hand-built protobuf PUT to .../namespaces/{name}/status.
    if let Some(status) = ns.status {
        let mut status_map = serde_json::Map::new();
        if let Some(phase) = status.phase.filter(|s| !s.is_empty()) {
            status_map.insert("phase".to_string(), serde_json::Value::String(phase));
        }
        if !status.conditions.is_empty() {
            let conds: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(|c| {
                    let mut cm = serde_json::json!({
                        "type": c.r#type.unwrap_or_default(),
                        "status": c.status.unwrap_or_default(),
                    });
                    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                        cm["reason"] = v.into();
                    }
                    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                        cm["message"] = v.into();
                    }
                    if let Some(t) = c.last_transition_time {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            cm["lastTransitionTime"] =
                                serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                        }
                    }
                    cm
                })
                .collect();
            status_map.insert("conditions".to_string(), serde_json::Value::Array(conds));
        }
        if !status_map.is_empty() {
            obj["status"] = serde_json::Value::Object(status_map);
        }
    }
    Some(obj)
}

// ---- Decoder A: ConfigMap --------------------------------------------------

pub fn decode_configmap_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let cm = core_v1::ConfigMap::decode(data).ok()?;
    let meta = gen_object_meta_to_json(cm.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": meta
    });
    // immutable — the PATCH/PUT checks (resource.rs) that reject mutating an immutable
    // ConfigMap are correct but never fire if this field is dropped on decode.
    if let Some(v) = cm.immutable {
        obj["immutable"] = serde_json::Value::Bool(v);
    }
    if !cm.data.is_empty() {
        let data_map: serde_json::Map<String, serde_json::Value> = cm
            .data
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        obj["data"] = serde_json::Value::Object(data_map);
    }
    if !cm.binary_data.is_empty() {
        let binary_data_map: serde_json::Map<String, serde_json::Value> = cm
            .binary_data
            .into_iter()
            .map(|(k, v)| {
                use base64::Engine;
                (
                    k,
                    serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&v)),
                )
            })
            .collect();
        obj["binaryData"] = serde_json::Value::Object(binary_data_map);
    }
    Some(obj)
}

// ---- Decoder A: Pod --------------------------------------------------------

/// Convert a decoded `PodStatus` protobuf message to the JSON shape stored/served by u7s.
///
/// A protobuf-encoded write to the `/status` subresource (e.g. client-go typed clients'
/// `UpdateStatus`, which defaults to protobuf content-type) carries the full `PodStatus`
/// on the wire. Without this, `decode_pod_proto_gen` silently dropped `.status` entirely,
/// so `replace_pod_status` treated the incoming status as absent and overwrote the stored
/// status with `null` — a protobuf PUT to a pod's status subresource wiped the pod's phase,
/// conditions and IPs instead of replacing them with the caller's values.
fn gen_pod_status_to_json(status: core_v1::PodStatus) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = status.phase.filter(|s| !s.is_empty()) {
        m.insert("phase".to_string(), serde_json::Value::String(v));
    }
    if !status.conditions.is_empty() {
        let conditions: Vec<serde_json::Value> = status
            .conditions
            .into_iter()
            .map(|c| {
                let mut cond = serde_json::json!({
                    "type": c.r#type.unwrap_or_default(),
                    "status": c.status.unwrap_or_default(),
                });
                if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                    cond["reason"] = serde_json::Value::String(v);
                }
                if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                    cond["message"] = serde_json::Value::String(v);
                }
                if let Some(secs) = c.last_transition_time.and_then(|t| t.seconds) {
                    cond["lastTransitionTime"] =
                        serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                }
                if let Some(secs) = c.last_probe_time.and_then(|t| t.seconds) {
                    cond["lastProbeTime"] =
                        serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                }
                if let Some(v) = c.observed_generation.filter(|&v| v != 0) {
                    cond["observedGeneration"] = v.into();
                }
                cond
            })
            .collect();
        m.insert(
            "conditions".to_string(),
            serde_json::Value::Array(conditions),
        );
    }
    if let Some(v) = status.message.filter(|s| !s.is_empty()) {
        m.insert("message".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = status.reason.filter(|s| !s.is_empty()) {
        m.insert("reason".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = status.nominated_node_name.filter(|s| !s.is_empty()) {
        m.insert(
            "nominatedNodeName".to_string(),
            serde_json::Value::String(v),
        );
    }
    if let Some(v) = status.host_ip.filter(|s| !s.is_empty()) {
        m.insert("hostIP".to_string(), serde_json::Value::String(v));
    }
    if !status.host_i_ps.is_empty() {
        let ips: Vec<serde_json::Value> = status
            .host_i_ps
            .into_iter()
            .filter_map(|h| h.ip.filter(|s| !s.is_empty()))
            .map(|ip| serde_json::json!({ "ip": ip }))
            .collect();
        if !ips.is_empty() {
            m.insert("hostIPs".to_string(), serde_json::Value::Array(ips));
        }
    }
    if let Some(v) = status.pod_ip.filter(|s| !s.is_empty()) {
        m.insert("podIP".to_string(), serde_json::Value::String(v));
    }
    if !status.pod_i_ps.is_empty() {
        let ips: Vec<serde_json::Value> = status
            .pod_i_ps
            .into_iter()
            .filter_map(|p| p.ip.filter(|s| !s.is_empty()))
            .map(|ip| serde_json::json!({ "ip": ip }))
            .collect();
        if !ips.is_empty() {
            m.insert("podIPs".to_string(), serde_json::Value::Array(ips));
        }
    }
    if let Some(secs) = status.start_time.and_then(|t| t.seconds) {
        m.insert(
            "startTime".to_string(),
            serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
        );
    }
    if let Some(v) = status.qos_class.filter(|s| !s.is_empty()) {
        m.insert("qosClass".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

pub fn decode_pod_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let pod = core_v1::Pod::decode(data).ok()?;
    let meta = gen_object_meta_to_json(pod.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": meta
    });
    obj["spec"] = gen_pod_spec_to_json(pod.spec.unwrap_or_default());
    if let Some(status) = pod.status {
        obj["status"] = gen_pod_status_to_json(status);
    }
    Some(obj)
}

// ---- Decoder A: PodTemplate ------------------------------------------------

pub fn decode_podtemplate_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let pt = core_v1::PodTemplate::decode(data).ok()?;
    let meta = gen_object_meta_to_json(pt.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PodTemplate",
        "metadata": meta
    });
    if let Some(tmpl) = pt.template {
        obj["template"] = gen_pod_template_spec_to_json(tmpl);
    } else {
        obj["template"] = serde_json::json!({});
    }
    Some(obj)
}

// ---- Decoder A: Service ----------------------------------------------------

pub fn decode_service_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let svc = core_v1::Service::decode(data).ok()?;
    let meta = gen_object_meta_to_json(svc.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": meta
    });

    if let Some(spec) = svc.spec {
        let mut spec_map = serde_json::Map::with_capacity(10);
        if let Some(v) = spec.cluster_ip.filter(|s| !s.is_empty()) {
            spec_map.insert("clusterIP".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.r#type.filter(|s| !s.is_empty()) {
            spec_map.insert("type".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.session_affinity.filter(|s| !s.is_empty()) {
            spec_map.insert("sessionAffinity".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.external_name.filter(|s| !s.is_empty()) {
            spec_map.insert("externalName".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.external_traffic_policy.filter(|s| !s.is_empty()) {
            spec_map.insert(
                "externalTrafficPolicy".to_string(),
                serde_json::Value::String(v),
            );
        }
        if let Some(v) = spec.ip_family_policy.filter(|s| !s.is_empty()) {
            spec_map.insert("ipFamilyPolicy".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.internal_traffic_policy.filter(|s| !s.is_empty()) {
            spec_map.insert(
                "internalTrafficPolicy".to_string(),
                serde_json::Value::String(v),
            );
        }
        if !spec.external_i_ps.is_empty() {
            spec_map.insert(
                "externalIPs".to_string(),
                serde_json::Value::Array(
                    spec.external_i_ps
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if !spec.selector.is_empty() {
            let sel: serde_json::Map<String, serde_json::Value> = spec
                .selector
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            spec_map.insert("selector".to_string(), serde_json::Value::Object(sel));
        }
        if !spec.ports.is_empty() {
            let ports_json: Vec<serde_json::Value> = spec
                .ports
                .into_iter()
                .map(|p| {
                    let mut pm = serde_json::Map::new();
                    if let Some(v) = p.name.filter(|s| !s.is_empty()) {
                        pm.insert("name".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(v) = p.protocol.filter(|s| !s.is_empty()) {
                        pm.insert("protocol".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(v) = p.port.filter(|&n| n != 0) {
                        pm.insert("port".to_string(), serde_json::Value::Number(v.into()));
                    }
                    if let Some(tp) = p.target_port {
                        pm.insert("targetPort".to_string(), gen_int_or_string_to_json(&tp));
                    }
                    if let Some(v) = p.node_port.filter(|&n| n != 0) {
                        pm.insert("nodePort".to_string(), serde_json::Value::Number(v.into()));
                    }
                    if let Some(v) = p.app_protocol.filter(|s| !s.is_empty()) {
                        pm.insert("appProtocol".to_string(), serde_json::Value::String(v));
                    }
                    serde_json::Value::Object(pm)
                })
                .collect();
            spec_map.insert("ports".to_string(), serde_json::Value::Array(ports_json));
        }
        if !spec_map.is_empty() {
            obj["spec"] = serde_json::Value::Object(spec_map);
        }
    }

    if let Some(status) = svc.status {
        let mut status_json = serde_json::json!({});
        if let Some(lb) = status.load_balancer {
            if !lb.ingress.is_empty() {
                let ingress: Vec<serde_json::Value> = lb
                    .ingress
                    .into_iter()
                    .map(|i| {
                        let mut im = serde_json::Map::new();
                        if let Some(v) = i.ip.filter(|s| !s.is_empty()) {
                            im.insert("ip".to_string(), serde_json::Value::String(v));
                        }
                        if let Some(v) = i.hostname.filter(|s| !s.is_empty()) {
                            im.insert("hostname".to_string(), serde_json::Value::String(v));
                        }
                        serde_json::Value::Object(im)
                    })
                    .collect();
                status_json["loadBalancer"] = serde_json::json!({ "ingress": ingress });
            }
        }
        if !status.conditions.is_empty() {
            let conds: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(|c| {
                    let mut cm = serde_json::json!({
                        "type": c.r#type.unwrap_or_default(),
                        "status": c.status.unwrap_or_default(),
                    });
                    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                        cm["reason"] = v.into();
                    }
                    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                        cm["message"] = v.into();
                    }
                    if let Some(t) = c.last_transition_time {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            cm["lastTransitionTime"] =
                                serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                        }
                    }
                    cm
                })
                .collect();
            status_json["conditions"] = serde_json::Value::Array(conds);
        }
        if status_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            obj["status"] = status_json;
        }
    }

    Some(obj)
}

// ---- Decoder A: Secret -----------------------------------------------------

pub fn decode_secret_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let secret = core_v1::Secret::decode(data).ok()?;
    let meta = gen_object_meta_to_json(secret.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": meta
    });
    // immutable — same data-integrity gap as ConfigMap: the checks are correct but never
    // fire if this field is dropped on decode.
    if let Some(v) = secret.immutable {
        obj["immutable"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = secret.r#type.filter(|s| !s.is_empty()) {
        obj["type"] = serde_json::Value::String(v);
    }
    if !secret.data.is_empty() {
        let data_map: serde_json::Map<String, serde_json::Value> = secret
            .data
            .into_iter()
            .map(|(k, v)| {
                use base64::Engine;
                (
                    k,
                    serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&v)),
                )
            })
            .collect();
        obj["data"] = serde_json::Value::Object(data_map);
    }
    if !secret.string_data.is_empty() {
        let sd_map: serde_json::Map<String, serde_json::Value> = secret
            .string_data
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        obj["stringData"] = serde_json::Value::Object(sd_map);
    }
    Some(obj)
}

// ---- Decoder A: Node -------------------------------------------------------

/// Convert a decoded `NodeStatus` protobuf message to the JSON shape stored/served by u7s.
///
/// The kubelet (and any other typed client's `Nodes().UpdateStatus(...)`) PUTs the full
/// Node using protobuf content-type by default, carrying the full `NodeStatus` on the wire.
/// Without this, `decode_node_proto_gen` silently dropped `.status` entirely, so that PUT
/// overwrote the stored status with `null` instead of the caller's values — wiping phase,
/// conditions (Ready/MemoryPressure/DiskPressure/PIDPressure), addresses, capacity,
/// allocatable and nodeInfo, on which all sig-node conformance depends.
fn gen_node_status_to_json(status: core_v1::NodeStatus) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !status.capacity.is_empty() {
        m.insert(
            "capacity".to_string(),
            gen_quantity_map_btree_to_json(status.capacity),
        );
    }
    if !status.allocatable.is_empty() {
        m.insert(
            "allocatable".to_string(),
            gen_quantity_map_btree_to_json(status.allocatable),
        );
    }
    if let Some(v) = status.phase.filter(|s| !s.is_empty()) {
        m.insert("phase".to_string(), serde_json::Value::String(v));
    }
    if !status.conditions.is_empty() {
        let conditions: Vec<serde_json::Value> = status
            .conditions
            .into_iter()
            .map(|c| {
                let mut cond = serde_json::json!({
                    "type": c.r#type.unwrap_or_default(),
                    "status": c.status.unwrap_or_default(),
                });
                if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                    cond["reason"] = serde_json::Value::String(v);
                }
                if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                    cond["message"] = serde_json::Value::String(v);
                }
                if let Some(secs) = c.last_heartbeat_time.and_then(|t| t.seconds) {
                    cond["lastHeartbeatTime"] =
                        serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                }
                if let Some(secs) = c.last_transition_time.and_then(|t| t.seconds) {
                    cond["lastTransitionTime"] =
                        serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                }
                cond
            })
            .collect();
        m.insert(
            "conditions".to_string(),
            serde_json::Value::Array(conditions),
        );
    }
    if !status.addresses.is_empty() {
        let addrs: Vec<serde_json::Value> = status
            .addresses
            .into_iter()
            .map(|a| {
                serde_json::json!({
                    "type": a.r#type.unwrap_or_default(),
                    "address": a.address.unwrap_or_default(),
                })
            })
            .collect();
        m.insert("addresses".to_string(), serde_json::Value::Array(addrs));
    }
    if let Some(port) = status
        .daemon_endpoints
        .and_then(|de| de.kubelet_endpoint)
        .and_then(|ke| ke.port)
    {
        m.insert(
            "daemonEndpoints".to_string(),
            serde_json::json!({ "kubeletEndpoint": { "Port": port } }),
        );
    }
    if let Some(info) = status.node_info {
        let mut ni = serde_json::Map::new();
        if let Some(v) = info.machine_id.filter(|s| !s.is_empty()) {
            ni.insert("machineID".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = info.system_uuid.filter(|s| !s.is_empty()) {
            ni.insert("systemUUID".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = info.boot_id.filter(|s| !s.is_empty()) {
            ni.insert("bootID".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = info.kernel_version.filter(|s| !s.is_empty()) {
            ni.insert("kernelVersion".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = info.os_image.filter(|s| !s.is_empty()) {
            ni.insert("osImage".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = info.container_runtime_version.filter(|s| !s.is_empty()) {
            ni.insert(
                "containerRuntimeVersion".to_string(),
                serde_json::Value::String(v),
            );
        }
        if let Some(v) = info.kubelet_version.filter(|s| !s.is_empty()) {
            ni.insert("kubeletVersion".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = info.kube_proxy_version.filter(|s| !s.is_empty()) {
            ni.insert("kubeProxyVersion".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = info.operating_system.filter(|s| !s.is_empty()) {
            ni.insert("operatingSystem".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = info.architecture.filter(|s| !s.is_empty()) {
            ni.insert("architecture".to_string(), serde_json::Value::String(v));
        }
        if !ni.is_empty() {
            m.insert("nodeInfo".to_string(), serde_json::Value::Object(ni));
        }
    }
    if !status.images.is_empty() {
        let images: Vec<serde_json::Value> = status
            .images
            .into_iter()
            .map(|img| {
                let mut o = serde_json::json!({});
                if !img.names.is_empty() {
                    o["names"] = serde_json::Value::Array(
                        img.names
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    );
                }
                if let Some(v) = img.size_bytes.filter(|&v| v != 0) {
                    o["sizeBytes"] = v.into();
                }
                o
            })
            .collect();
        m.insert("images".to_string(), serde_json::Value::Array(images));
    }
    if !status.volumes_in_use.is_empty() {
        m.insert(
            "volumesInUse".to_string(),
            serde_json::Value::Array(
                status
                    .volumes_in_use
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !status.volumes_attached.is_empty() {
        let vols: Vec<serde_json::Value> = status
            .volumes_attached
            .into_iter()
            .map(|v| {
                serde_json::json!({
                    "name": v.name.unwrap_or_default(),
                    "devicePath": v.device_path.unwrap_or_default(),
                })
            })
            .collect();
        m.insert(
            "volumesAttached".to_string(),
            serde_json::Value::Array(vols),
        );
    }
    serde_json::Value::Object(m)
}

pub fn decode_node_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let node = core_v1::Node::decode(data).ok()?;
    let meta = gen_object_meta_to_json(node.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": meta
    });
    if let Some(spec) = node.spec {
        let mut spec_map = serde_json::Map::new();
        if let Some(v) = spec.pod_cidr.filter(|s| !s.is_empty()) {
            spec_map.insert("podCIDR".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.provider_id.filter(|s| !s.is_empty()) {
            spec_map.insert("providerID".to_string(), serde_json::Value::String(v));
        }
        if !spec.pod_cid_rs.is_empty() {
            spec_map.insert(
                "podCIDRs".to_string(),
                serde_json::Value::Array(
                    spec.pod_cid_rs
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if !spec_map.is_empty() {
            obj["spec"] = serde_json::Value::Object(spec_map);
        }
    }
    if let Some(status) = node.status {
        obj["status"] = gen_node_status_to_json(status);
    }
    Some(obj)
}

// ---- Decoder A: PersistentVolume -------------------------------------------

pub fn decode_persistentvolume_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let pv = core_v1::PersistentVolume::decode(data).ok()?;
    let meta = gen_object_meta_to_json(pv.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": meta
    });
    if let Some(spec) = pv.spec {
        let mut spec_map = serde_json::Map::new();
        if !spec.access_modes.is_empty() {
            spec_map.insert(
                "accessModes".to_string(),
                serde_json::Value::Array(
                    spec.access_modes
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if let Some(v) = spec
            .persistent_volume_reclaim_policy
            .filter(|s| !s.is_empty())
        {
            spec_map.insert(
                "persistentVolumeReclaimPolicy".to_string(),
                serde_json::Value::String(v),
            );
        }
        if let Some(v) = spec.storage_class_name.filter(|s| !s.is_empty()) {
            spec_map.insert("storageClassName".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.volume_mode.filter(|s| !s.is_empty()) {
            spec_map.insert("volumeMode".to_string(), serde_json::Value::String(v));
        }
        if !spec_map.is_empty() {
            obj["spec"] = serde_json::Value::Object(spec_map);
        }
    }
    if let Some(status) = pv.status {
        let mut status_map = serde_json::Map::new();
        if let Some(v) = status.phase.filter(|s| !s.is_empty()) {
            status_map.insert("phase".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = status.message.filter(|s| !s.is_empty()) {
            status_map.insert("message".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = status.reason.filter(|s| !s.is_empty()) {
            status_map.insert("reason".to_string(), serde_json::Value::String(v));
        }
        if !status_map.is_empty() {
            obj["status"] = serde_json::Value::Object(status_map);
        }
    }
    Some(obj)
}

// ---- Decoder A: ServiceAccount ---------------------------------------------

pub fn decode_serviceaccount_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = core_v1::ServiceAccount::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": meta
    });
    if !obj.secrets.is_empty() {
        result["secrets"] = obj
            .secrets
            .into_iter()
            .filter_map(|r| {
                r.name
                    .filter(|s| !s.is_empty())
                    .map(|n| serde_json::json!({ "name": n }))
            })
            .collect::<Vec<_>>()
            .into();
    }
    if !obj.image_pull_secrets.is_empty() {
        result["imagePullSecrets"] = obj
            .image_pull_secrets
            .into_iter()
            .filter_map(|r| {
                r.name
                    .filter(|s| !s.is_empty())
                    .map(|n| serde_json::json!({ "name": n }))
            })
            .collect::<Vec<_>>()
            .into();
    }
    if let Some(v) = obj.automount_service_account_token {
        result["automountServiceAccountToken"] = v.into();
    }
    Some(result)
}

// ---- Decoder A: PersistentVolumeClaim --------------------------------------

pub fn decode_persistentvolumeclaim_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = core_v1::PersistentVolumeClaim::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::json!({});
        if !spec.access_modes.is_empty() {
            spec_json["accessModes"] = spec.access_modes.into();
        }
        if let Some(v) = spec.volume_name.filter(|s| !s.is_empty()) {
            spec_json["volumeName"] = v.into();
        }
        if let Some(v) = spec.storage_class_name.filter(|s| !s.is_empty()) {
            spec_json["storageClassName"] = v.into();
        }
        if let Some(v) = spec.volume_mode.filter(|s| !s.is_empty()) {
            spec_json["volumeMode"] = v.into();
        }
        if let Some(res) = spec.resources {
            let mut res_json = serde_json::json!({});
            if !res.requests.is_empty() {
                res_json["requests"] = gen_quantity_map_btree_to_json(res.requests);
            }
            if !res.limits.is_empty() {
                res_json["limits"] = gen_quantity_map_btree_to_json(res.limits);
            }
            if res_json.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
                spec_json["resources"] = res_json;
            }
        }
        if spec_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            result["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::json!({});
        if let Some(v) = status.phase.filter(|s| !s.is_empty()) {
            status_json["phase"] = serde_json::Value::String(v);
        }
        if !status.conditions.is_empty() {
            let conditions: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(|c| {
                    let mut cond = serde_json::json!({
                        "type": c.r#type.unwrap_or_default(),
                        "status": c.status.unwrap_or_default()
                    });
                    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                        cond["reason"] = serde_json::Value::String(v);
                    }
                    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                        cond["message"] = serde_json::Value::String(v);
                    }
                    cond
                })
                .collect();
            status_json["conditions"] = serde_json::Value::Array(conditions);
        }
        if status_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            result["status"] = status_json;
        }
    }
    Some(result)
}

// ---- Decoder A: Endpoints --------------------------------------------------

pub fn decode_endpoints_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = core_v1::Endpoints::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": meta
    });
    if !obj.subsets.is_empty() {
        let subsets: Vec<serde_json::Value> = obj
            .subsets
            .into_iter()
            .map(|subset| {
                let mut s = serde_json::json!({});
                if !subset.addresses.is_empty() {
                    s["addresses"] = subset
                        .addresses
                        .into_iter()
                        .map(|a| {
                            let mut addr = serde_json::json!({
                                "ip": a.ip.unwrap_or_default()
                            });
                            if let Some(v) = a.hostname.filter(|s| !s.is_empty()) {
                                addr["hostname"] = serde_json::Value::String(v);
                            }
                            if let Some(v) = a.node_name.filter(|s| !s.is_empty()) {
                                addr["nodeName"] = serde_json::Value::String(v);
                            }
                            addr
                        })
                        .collect::<Vec<_>>()
                        .into();
                }
                if !subset.not_ready_addresses.is_empty() {
                    s["notReadyAddresses"] = subset
                        .not_ready_addresses
                        .into_iter()
                        .map(|a| {
                            let mut addr = serde_json::json!({
                                "ip": a.ip.unwrap_or_default()
                            });
                            if let Some(v) = a.hostname.filter(|s| !s.is_empty()) {
                                addr["hostname"] = serde_json::Value::String(v);
                            }
                            if let Some(v) = a.node_name.filter(|s| !s.is_empty()) {
                                addr["nodeName"] = serde_json::Value::String(v);
                            }
                            addr
                        })
                        .collect::<Vec<_>>()
                        .into();
                }
                if !subset.ports.is_empty() {
                    s["ports"] = subset
                        .ports
                        .into_iter()
                        .map(|p| {
                            let mut port = serde_json::json!({
                                "port": p.port.unwrap_or(0)
                            });
                            if let Some(v) = p.name.filter(|s| !s.is_empty()) {
                                port["name"] = serde_json::Value::String(v);
                            }
                            if let Some(v) = p.protocol.filter(|s| !s.is_empty()) {
                                port["protocol"] = serde_json::Value::String(v);
                            }
                            if let Some(v) = p.app_protocol.filter(|s| !s.is_empty()) {
                                port["appProtocol"] = serde_json::Value::String(v);
                            }
                            port
                        })
                        .collect::<Vec<_>>()
                        .into();
                }
                s
            })
            .collect();
        result["subsets"] = subsets.into();
    }
    Some(result)
}

// ---- Decoder A: ResourceQuota ----------------------------------------------

/// Convert a decoded `ResourceQuotaStatus` protobuf message to the JSON shape stored/served
/// by u7s.
///
/// Upstream's quota controller (`pkg/controller/resourcequota`) calls
/// `ResourceQuotas(ns).UpdateStatus(...)` every reconcile, which PUTs the full ResourceQuota
/// using protobuf content-type by default. Without this, `decode_resourcequota_proto_gen`
/// silently dropped `.status` entirely, so that PUT wiped `status.hard`/`status.used`
/// (including CPU/memory accounting) instead of replacing them with the caller's values.
fn gen_resourcequota_status_to_json(status: core_v1::ResourceQuotaStatus) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !status.hard.is_empty() {
        m.insert(
            "hard".to_string(),
            gen_quantity_map_btree_to_json(status.hard),
        );
    }
    if !status.used.is_empty() {
        m.insert(
            "used".to_string(),
            gen_quantity_map_btree_to_json(status.used),
        );
    }
    serde_json::Value::Object(m)
}

pub fn decode_resourcequota_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = core_v1::ResourceQuota::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        if !spec.hard.is_empty() || !spec.scopes.is_empty() || spec.scope_selector.is_some() {
            let mut spec_json = serde_json::json!({});
            if !spec.hard.is_empty() {
                spec_json["hard"] = gen_quantity_map_btree_to_json(spec.hard);
            }
            if !spec.scopes.is_empty() {
                spec_json["scopes"] =
                    serde_json::Value::Array(spec.scopes.into_iter().map(Into::into).collect());
            }
            if let Some(ss) = spec.scope_selector {
                if !ss.match_expressions.is_empty() {
                    let exprs: Vec<serde_json::Value> = ss
                        .match_expressions
                        .into_iter()
                        .map(|expr| {
                            let mut m = serde_json::json!({
                                "scopeName": expr.scope_name.unwrap_or_default(),
                                "operator": expr.operator.unwrap_or_default(),
                            });
                            if !expr.values.is_empty() {
                                m["values"] = serde_json::Value::Array(
                                    expr.values.into_iter().map(Into::into).collect(),
                                );
                            }
                            m
                        })
                        .collect();
                    spec_json["scopeSelector"] = serde_json::json!({ "matchExpressions": exprs });
                }
            }
            result["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        result["status"] = gen_resourcequota_status_to_json(status);
    }
    Some(result)
}

// ---- Decoder A: LimitRange -------------------------------------------------

pub fn decode_limitrange_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = core_v1::LimitRange::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({
        "apiVersion": "v1",
        "kind": "LimitRange",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let limits: Vec<serde_json::Value> = spec
            .limits
            .into_iter()
            .map(|item| {
                let mut o = serde_json::json!({
                    "type": item.r#type.unwrap_or_default()
                });
                if !item.max.is_empty() {
                    o["max"] = gen_quantity_map_btree_to_json(item.max);
                }
                if !item.min.is_empty() {
                    o["min"] = gen_quantity_map_btree_to_json(item.min);
                }
                if !item.default.is_empty() {
                    o["default"] = gen_quantity_map_btree_to_json(item.default);
                }
                if !item.default_request.is_empty() {
                    o["defaultRequest"] = gen_quantity_map_btree_to_json(item.default_request);
                }
                if !item.max_limit_request_ratio.is_empty() {
                    o["maxLimitRequestRatio"] =
                        gen_quantity_map_btree_to_json(item.max_limit_request_ratio);
                }
                o
            })
            .collect();
        result["spec"] = serde_json::json!({ "limits": limits });
    }
    Some(result)
}

// ---- Decoder A: ReplicationController --------------------------------------

pub fn decode_replicationcontroller_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let rc = core_v1::ReplicationController::decode(data).ok()?;
    let meta = gen_object_meta_to_json(rc.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ReplicationController",
        "metadata": meta
    });
    if let Some(spec) = rc.spec {
        let mut spec_map = serde_json::Map::new();
        // replicas=0 must be emitted (not dropped) so the RC controller knows to scale to zero
        spec_map.insert(
            "replicas".to_string(),
            serde_json::Value::Number(spec.replicas.unwrap_or(0).into()),
        );
        if !spec.selector.is_empty() {
            let sel: serde_json::Map<String, serde_json::Value> = spec
                .selector
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            spec_map.insert("selector".to_string(), serde_json::Value::Object(sel));
        }
        if let Some(tmpl) = spec.template {
            spec_map.insert("template".to_string(), gen_pod_template_spec_to_json(tmpl));
        }
        obj["spec"] = serde_json::Value::Object(spec_map);
    }
    if let Some(status) = rc.status {
        let mut status_json = serde_json::json!({});
        if let Some(v) = status.replicas.filter(|&v| v != 0) {
            status_json["replicas"] = v.into();
        }
        if let Some(v) = status.fully_labeled_replicas.filter(|&v| v != 0) {
            status_json["fullyLabeledReplicas"] = v.into();
        }
        if let Some(v) = status.observed_generation.filter(|&v| v != 0) {
            status_json["observedGeneration"] = v.into();
        }
        if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {
            status_json["readyReplicas"] = v.into();
        }
        if let Some(v) = status.available_replicas.filter(|&v| v != 0) {
            status_json["availableReplicas"] = v.into();
        }
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| {
                    let mut cond = serde_json::json!({
                        "type": c.r#type.clone().unwrap_or_default(),
                        "status": c.status.clone().unwrap_or_default(),
                    });
                    if let Some(ref r) = c.reason {
                        if !r.is_empty() {
                            cond["reason"] = r.clone().into();
                        }
                    }
                    if let Some(ref msg) = c.message {
                        if !msg.is_empty() {
                            cond["message"] = msg.clone().into();
                        }
                    }
                    cond
                })
                .collect();
        }
        if status_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            obj["status"] = status_json;
        }
    }
    Some(obj)
}

// ---- Decoder A: Event (core/v1) --------------------------------------------

pub fn decode_event_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let event = core_v1::Event::decode(data).ok()?;
    let meta = gen_object_meta_to_json(event.metadata.unwrap_or_default());

    let involved_object = event
        .involved_object
        .map(gen_object_reference_to_json)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": meta,
        "involvedObject": involved_object
    });
    if let Some(v) = event.reason.filter(|s| !s.is_empty()) {
        obj["reason"] = serde_json::Value::String(v);
    }
    if let Some(v) = event.message.filter(|s| !s.is_empty()) {
        obj["message"] = serde_json::Value::String(v);
    }
    if let Some(v) = event.count.filter(|&n| n != 0) {
        obj["count"] = serde_json::Value::Number(serde_json::Number::from(v));
    }
    if let Some(v) = event.r#type.filter(|s| !s.is_empty()) {
        obj["type"] = serde_json::Value::String(v);
    }
    if let Some(s) = event.series {
        let mut sm = serde_json::Map::new();
        if let Some(v) = s.count.filter(|&n| n != 0) {
            sm.insert(
                "count".to_string(),
                serde_json::Value::Number(serde_json::Number::from(v)),
            );
        }
        if let Some(t) = s.last_observed_time {
            if let Some(secs) = t.seconds {
                let ts = gen_microtime_fields_to_rfc3339(secs, t.nanos.unwrap_or(0));
                sm.insert(
                    "lastObservedTime".to_string(),
                    serde_json::Value::String(ts),
                );
            }
        }
        if !sm.is_empty() {
            obj["series"] = serde_json::Value::Object(sm);
        }
    }
    Some(obj)
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Pod spec tolerations survive proto decode via the generated path.
    ///
    /// Without tolerations in gen_pod_spec_to_json, pods that tolerate node taints
    /// (e.g. node.kubernetes.io/not-ready:NoExecute) are treated by the scheduler
    /// as if they have no tolerations. This causes them to be evicted from tainted
    /// nodes immediately rather than after the tolerationSeconds window, breaking
    /// taint-based eviction conformance tests. This test subsumes mayor-40cj (tolerations
    /// dropped by hand pod_spec_to_json) and mayor-osuq (priorityClassName dropped).
    #[test]
    fn generated_pod_spec_preserves_tolerations_by_construction() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("toleration-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                tolerations: vec![core_v1::Toleration {
                    key: Some("node.kubernetes.io/not-ready".to_string()),
                    operator: Some("Exists".to_string()),
                    effect: Some("NoExecute".to_string()),
                    toleration_seconds: Some(300),
                    ..Default::default()
                }],
                priority_class_name: Some("system-cluster-critical".to_string()),
                priority: Some(2000000000),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf)
            .expect("Pod with tolerations must decode via generated path");

        let tols = result["spec"]["tolerations"].as_array().expect(
            "spec.tolerations must be present — without it, the scheduler ignores taint \
                 tolerations and immediately evicts pods from tainted nodes, breaking \
                 taint-based eviction conformance (mayor-40cj)",
        );
        assert_eq!(tols.len(), 1, "one toleration must survive decode");
        assert_eq!(
            tols[0]["key"], "node.kubernetes.io/not-ready",
            "toleration key must survive decode"
        );
        assert_eq!(
            tols[0]["operator"], "Exists",
            "toleration operator must survive decode"
        );
        assert_eq!(
            tols[0]["effect"], "NoExecute",
            "toleration effect must survive decode"
        );
        assert_eq!(
            tols[0]["tolerationSeconds"], 300,
            "tolerationSeconds must survive — without it pods are evicted immediately \
             instead of after the grace period"
        );
        assert_eq!(
            result["spec"]["priorityClassName"], "system-cluster-critical",
            "priorityClassName must survive decode — without it the scheduler cannot \
             enforce preemption priority ordering (mayor-osuq)"
        );
        assert_eq!(
            result["spec"]["priority"], 2000000000,
            "priority integer must survive decode"
        );
    }

    /// Pod status fields, especially conditions, survive the generated-path decode.
    ///
    /// client-go typed clients (`CoreV1().Pods(ns).UpdateStatus(...)`) PUT the full Pod,
    /// including `.status`, using protobuf content-type by default. Before this fix,
    /// decode_pod_proto_gen never read `pod.status` at all, so replace_pod_status treated
    /// the incoming status as absent and overwrote the stored status with `null` — a caller
    /// flipping PodReady/ContainersReady to False via the status subresource got back a
    /// response with an empty conditions list instead of its own values, exactly the
    /// "[sig-node] Pods ... PodStatus" conformance failure this guards against.
    #[test]
    fn generated_pod_preserves_status_conditions_for_status_subresource_replace() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("pod-test".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(core_v1::PodStatus {
                phase: Some("Running".to_string()),
                pod_ip: Some("10.1.2.3".to_string()),
                host_ip: Some("192.168.5.15".to_string()),
                conditions: vec![
                    core_v1::PodCondition {
                        r#type: Some("Ready".to_string()),
                        status: Some("False".to_string()),
                        ..Default::default()
                    },
                    core_v1::PodCondition {
                        r#type: Some("ContainersReady".to_string()),
                        status: Some("False".to_string()),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).expect("prost encode must succeed");

        let result =
            decode_pod_proto_gen(&buf).expect("Pod with status must decode via generated path");

        assert_eq!(
            result["status"]["phase"], "Running",
            "status.phase must survive decode — without it a protobuf status PUT looks Pending"
        );
        assert_eq!(
            result["status"]["podIP"], "10.1.2.3",
            "status.podIP must survive decode"
        );
        let conds = result["status"]["conditions"].as_array().expect(
            "status.conditions must be present — without it a protobuf UpdateStatus call \
             that flips PodReady/ContainersReady to False reports back zero changed \
             conditions instead of two",
        );
        assert_eq!(conds.len(), 2, "both conditions must survive decode");
        let false_count = conds
            .iter()
            .filter(|c| {
                (c["type"] == "Ready" || c["type"] == "ContainersReady") && c["status"] == "False"
            })
            .count();
        assert_eq!(
            false_count, 2,
            "both Ready and ContainersReady must decode with status=False — a caller \
             replacing pod status via protobuf must see its own write reflected back"
        );
    }

    /// RC status fields survive the generated-path decode.
    ///
    /// RC controllers compute desired-vs-actual replica counts from status.replicas.
    /// Without status decode, controllers see 0 and loop creating excess pods.
    #[test]
    fn generated_rc_preserves_status_fields() {
        let rc = core_v1::ReplicationController {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-rc".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(core_v1::ReplicationControllerStatus {
                replicas: Some(3),
                fully_labeled_replicas: Some(3),
                observed_generation: Some(7),
                ready_replicas: Some(2),
                available_replicas: Some(2),
                conditions: vec![core_v1::ReplicationControllerCondition {
                    r#type: Some("ReplicaFailure".to_string()),
                    status: Some("False".to_string()),
                    ..Default::default()
                }],
            }),
        };
        let mut buf = Vec::new();
        rc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_replicationcontroller_proto_gen(&buf)
            .expect("RC with status must decode successfully");

        assert_eq!(
            result["status"]["replicas"], 3,
            "status.replicas must survive — without it, controllers computing desired-vs-actual \
             counts see 0 and loop"
        );
        assert_eq!(
            result["status"]["readyReplicas"], 2,
            "status.readyReplicas must survive — readiness checks always return 0 without it"
        );
        assert_eq!(
            result["status"]["observedGeneration"], 7,
            "status.observedGeneration must survive"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "ReplicaFailure",
            "status.conditions must survive"
        );
    }

    /// RC with template containers survives decode via the generated path.
    ///
    /// Without decoding the template, the RC controller creates pods with no containers
    /// and they can never reach Running phase (same silent-drop bug class as #583 for Jobs).
    #[test]
    fn generated_rc_preserves_template_containers() {
        let rc = core_v1::ReplicationController {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-rc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::ReplicationControllerSpec {
                replicas: Some(2),
                selector: [("app".to_string(), "web".to_string())]
                    .into_iter()
                    .collect(),
                template: Some(core_v1::PodTemplateSpec {
                    metadata: None,
                    spec: Some(core_v1::PodSpec {
                        containers: vec![core_v1::Container {
                            name: Some("web".to_string()),
                            image: Some("nginx:latest".to_string()),
                            ..Default::default()
                        }],
                        restart_policy: Some("Always".to_string()),
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            }),
            status: None,
        };
        let mut buf = Vec::new();
        rc.encode(&mut buf).expect("prost encode must succeed");

        let result =
            decode_replicationcontroller_proto_gen(&buf).expect("RC with template must decode");

        assert_eq!(result["spec"]["replicas"], 2);
        let containers = result["spec"]["template"]["spec"]["containers"]
            .as_array()
            .expect(
                "spec.template.spec.containers must survive — without it RC controller creates \
                 pods with no containers and they never reach Running phase",
            );
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0]["name"], "web");
        assert_eq!(containers[0]["image"], "nginx:latest");
    }

    /// Namespace status.phase and status.conditions must survive proto decode
    /// (mayor-oww6 — this is also the mayor-ftkl PANIC-1 fix).
    ///
    /// Before this fix, decode_namespace_proto_gen never read `ns.status` at all, so any
    /// protobuf-encoded Namespace write (Content-Type: application/vnd.kubernetes.protobuf)
    /// silently lost its entire status — put_namespace_status wholesale-replaces stored
    /// status with whatever this decoder returns, which was nothing. This is exactly the
    /// mayor-ftkl "should apply changes to a namespace status" conformance panic
    /// (namespace.go:365, `index out of range [-1]`): the e2e test's typed clientset
    /// defaults to protobuf content-type (upstream test/e2e/framework/test_context.go's
    /// --kube-api-content-type, unset by our sonobuoy invocation) for
    /// `UpdateStatus(...)`, unlike this stack's kube-controller-manager which is started
    /// with --kube-api-content-type=application/json — a separate process/client that a
    /// previous version of this comment mistakenly conflated with the e2e test binary,
    /// concluding (wrongly) that the two were unrelated. See the decoder's own comment
    /// above for the live-verification note (re-run of the actual upstream conformance
    /// spec via sonobuoy).
    #[test]
    fn namespace_status_proto_decode_preserves_phase_and_conditions() {
        let ns = core_v1::Namespace {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-ns".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(core_v1::NamespaceStatus {
                phase: Some("Active".to_string()),
                conditions: vec![core_v1::NamespaceCondition {
                    r#type: Some("StatusUpdate".to_string()),
                    status: Some("True".to_string()),
                    reason: Some("E2E".to_string()),
                    message: Some("Updated by an e2e test".to_string()),
                    ..Default::default()
                }],
            }),
        };
        let mut buf = Vec::new();
        ns.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_namespace_proto_gen(&buf).expect("Namespace with status must decode");

        assert_eq!(
            result["status"]["phase"], "Active",
            "status.phase must survive proto decode — without it, any protobuf-content-type \
             client's status write (e.g. a kube-controller-manager run without the JSON \
             content-type override) silently drops phase from the stored Namespace"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "StatusUpdate",
            "status.conditions must survive proto decode alongside phase — losing either \
             one corrupts the status object for any protobuf-content-type client's \
             GET-modify-PUT round trip through /status"
        );
    }

    /// decode_persistentvolume_proto_gen must preserve status.phase/message/reason.
    ///
    /// The PV/PVC binding lifecycle is driven by status.phase (Available/Bound/Released/
    /// Failed); decode_persistentvolume_proto_gen never read `.status` at all, so
    /// "should apply changes to a pv/pvc status" conformance saw an empty status after the
    /// controller updated it, as if the volume were never bound.
    #[test]
    fn decode_persistentvolume_proto_gen_preserves_status_phase_message_reason() {
        let pv = core_v1::PersistentVolume {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-pv".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::PersistentVolumeStatus {
                phase: Some("Bound".to_string()),
                message: Some("bound by e2e test".to_string()),
                reason: Some("E2E".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pv.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolume_proto_gen(&buf).expect("PV with status must decode");

        assert_eq!(
            result["status"]["phase"], "Bound",
            "status.phase must survive proto decode; before the fix .status was never read, \
             so the PV/PVC binding lifecycle (which is driven by phase) looked frozen"
        );
        assert_eq!(
            result["status"]["message"], "bound by e2e test",
            "status.message must survive proto decode"
        );
        assert_eq!(
            result["status"]["reason"], "E2E",
            "status.reason must survive proto decode"
        );
    }

    /// The `optional` bool on ConfigMap/Secret volume sources (and their projected
    /// variants) must survive proto decode.
    ///
    /// Without it, the kubelet treats an optional configmap/secret mount as required:
    /// when the source is absent it reports FailedMount and blocks the pod from ever
    /// starting, instead of tolerating the missing source as the spec requested.
    #[test]
    fn generated_pod_spec_preserves_optional_on_configmap_and_secret_volumes() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("optional-vol-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                volumes: vec![
                    core_v1::Volume {
                        name: Some("cm-vol".to_string()),
                        volume_source: Some(core_v1::VolumeSource {
                            config_map: Some(core_v1::ConfigMapVolumeSource {
                                local_object_reference: Some(core_v1::LocalObjectReference {
                                    name: Some("maybe-missing-cm".to_string()),
                                }),
                                optional: Some(true),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    },
                    core_v1::Volume {
                        name: Some("secret-vol".to_string()),
                        volume_source: Some(core_v1::VolumeSource {
                            secret: Some(core_v1::SecretVolumeSource {
                                secret_name: Some("maybe-missing-secret".to_string()),
                                optional: Some(true),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    },
                    core_v1::Volume {
                        name: Some("projected-vol".to_string()),
                        volume_source: Some(core_v1::VolumeSource {
                            projected: Some(core_v1::ProjectedVolumeSource {
                                sources: vec![
                                    core_v1::VolumeProjection {
                                        config_map: Some(core_v1::ConfigMapProjection {
                                            local_object_reference: Some(
                                                core_v1::LocalObjectReference {
                                                    name: Some("proj-cm".to_string()),
                                                },
                                            ),
                                            optional: Some(true),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    },
                                    core_v1::VolumeProjection {
                                        secret: Some(core_v1::SecretProjection {
                                            local_object_reference: Some(
                                                core_v1::LocalObjectReference {
                                                    name: Some("proj-secret".to_string()),
                                                },
                                            ),
                                            optional: Some(true),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    },
                                ],
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod with volumes must decode");

        let volumes = result["spec"]["volumes"].as_array().unwrap();
        assert_eq!(
            volumes[0]["configMap"]["optional"], true,
            "configMap volume source's optional flag must survive decode — without it the \
             kubelet treats an absent configmap as a hard requirement and the pod never starts"
        );
        assert_eq!(
            volumes[1]["secret"]["optional"], true,
            "secret volume source's optional flag must survive decode — same failure mode as \
             configMap: an absent secret blocks pod startup instead of being tolerated"
        );
        let proj_sources = volumes[2]["projected"]["sources"].as_array().unwrap();
        assert_eq!(
            proj_sources[0]["configMap"]["optional"], true,
            "projected configMap source's optional flag must survive decode"
        );
        assert_eq!(
            proj_sources[1]["secret"]["optional"], true,
            "projected secret source's optional flag must survive decode"
        );
    }

    /// A Container's `resources` must be omitted from decoded JSON when the wire carried no
    /// limits/requests, not materialized as `resources: {}`.
    ///
    /// k8s.io/api's Container.Resources is a Go value (not pointer) field, so upstream's
    /// protobuf marshaler always writes the sub-message even when the caller set nothing —
    /// any protobuf-encoded write (e.g. from client-go) decodes to `Some(<empty>)` here. A
    /// workload controller (e.g. the Deployment controller) compares a freshly-created
    /// ReplicaSet's pod template against its own cached template using a full structural
    /// equality check; if this decoder inserts `resources: {}` where the client sent nothing,
    /// the two templates never match and the controller recreates the ReplicaSet forever.
    #[test]
    fn generated_container_omits_empty_resources() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-resources-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    resources: Some(core_v1::ResourceRequirements::default()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert!(
            result["spec"]["containers"][0].get("resources").is_none(),
            "an empty ResourceRequirements (the wire shape a protobuf client always sends, \
             even with no limits/requests configured) must be omitted, not materialized as \
             resources: {{}} — otherwise a protobuf-decoded template never structurally \
             matches an equivalent JSON-created one"
        );
    }

    /// decode_pod_proto_gen must preserve spec.schedulingGates (PodSpec field 38) through
    /// protobuf decode.
    ///
    /// client-go's typed Pod client — used by e.g. kube-controller-manager's ReplicaSet
    /// controller to create pods from a template — sends protobuf, not JSON, by default.
    /// Without this field, a gated pod created that way (as opposed to a raw `kubectl
    /// apply`/JSON POST) silently loses its schedulingGates on decode: needs_scheduling
    /// then never sees them as non-empty and schedules the pod immediately, failing
    /// "validates Pods with non-empty schedulingGates are blocked on scheduling" even
    /// though the scheduler's own gate-checking logic is correct.
    #[test]
    fn decode_pod_proto_gen_preserves_scheduling_gates() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("gated-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                scheduling_gates: vec![
                    core_v1::PodSchedulingGate {
                        name: Some("foo".to_string()),
                    },
                    core_v1::PodSchedulingGate {
                        name: Some("bar".to_string()),
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod with schedulingGates must decode");

        let gates = result["spec"]["schedulingGates"]
            .as_array()
            .expect("schedulingGates must survive protobuf decode as an array");
        assert_eq!(
            gates,
            &vec![
                serde_json::json!({"name": "foo"}),
                serde_json::json!({"name": "bar"}),
            ],
            "both gate names must survive decode in order — losing either one changes \
             whether the pod is considered gated at all"
        );
    }

    /// A Pod with no schedulingGates must decode with the key entirely absent, not an
    /// empty array — mirrors the `resources: {}` omission above. A controller that
    /// structurally compares a freshly protobuf-decoded pod template against its own
    /// cached (JSON-built, key-absent) template would otherwise never see them as equal.
    #[test]
    fn decode_pod_proto_gen_omits_scheduling_gates_when_empty() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("ungated-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert!(
            result["spec"].get("schedulingGates").is_none(),
            "schedulingGates must be omitted (not an empty array) when the wire carried none"
        );
    }

    /// Non-empty container resources must still survive decode — the omit-when-empty fix
    /// above must not turn into "always drop resources".
    #[test]
    fn generated_container_preserves_non_empty_resources() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("with-resources-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    resources: Some(core_v1::ResourceRequirements {
                        limits: std::collections::HashMap::from([(
                            "cpu".to_string(),
                            crate::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
                                string: Some("100m".to_string()),
                            },
                        )]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["cpu"], "100m",
            "an explicitly-set resource limit must survive decode unchanged"
        );
    }

    /// `terminationGracePeriodSeconds` is a Go `*int64` pointer field upstream. Dropping it
    /// during decode leaves the Deployment controller comparing a freshly-decoded ReplicaSet
    /// template (nil) against its own cached copy (`&1`); `apiequality.Semantic.DeepEqual`
    /// treats these as unequal, which drives `EqualIgnoreHash` to conclude the ReplicaSet it
    /// just created isn't its own and triggers an unbounded collision-count/recreate storm.
    #[test]
    fn generated_pod_spec_preserves_termination_grace_period_seconds() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("grace-period-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                termination_grace_period_seconds: Some(1),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["terminationGracePeriodSeconds"], 1,
            "an explicit terminationGracePeriodSeconds must survive protobuf decode — if it's \
             dropped, KCM sees nil where its cached Deployment template has &1, and \
             EqualIgnoreHash's DeepEqual treats that as a template mismatch, causing an \
             unbounded ReplicaSet hash-collision storm"
        );
    }

    /// `terminationGracePeriodSeconds: 0` ("kill immediately") is a legitimate value a client
    /// can set on purpose — unlike `activeDeadlineSeconds`, it must NOT be treated as
    /// unset-vs-zero noise and suppressed.
    #[test]
    fn generated_pod_spec_preserves_zero_termination_grace_period_seconds() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("zero-grace-period-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                termination_grace_period_seconds: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["terminationGracePeriodSeconds"], 0,
            "an explicit terminationGracePeriodSeconds of 0 (kill immediately) must survive \
             decode — treating it like activeDeadlineSeconds's unset-vs-zero-is-noise case \
             would silently give the pod the kubelet's default grace period instead"
        );
    }

    /// ConfigMap/Secret volume `defaultMode` must be omitted when the client never set it,
    /// not stamped to 420 (0644) during decode.
    ///
    /// k8s.io/api's DefaultMode is a Go pointer (*int32), so protobuf legitimately omits it
    /// from the wire when unset — the decoder must preserve that "unset" as an absent JSON
    /// key, not invent a value. Unlike a real Pod (which gets 420 stamped uniformly for any
    /// encoding by apply_pod_create_defaults after this decode step), a ReplicaSet/
    /// Deployment/etc. pod template goes straight from this decoder into storage with no
    /// further defaulting pass. Stamping 420 here made every protobuf-decoded workload
    /// template permanently differ from the un-stamped template a controller already has
    /// cached from watching the owning Deployment, so the Deployment controller's
    /// hash-collision equality check never matched and it recreated the ReplicaSet forever.
    #[test]
    fn generated_pod_spec_omits_default_mode_when_absent_on_configmap_and_secret_volumes() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-default-mode-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                volumes: vec![
                    core_v1::Volume {
                        name: Some("cm-vol".to_string()),
                        volume_source: Some(core_v1::VolumeSource {
                            config_map: Some(core_v1::ConfigMapVolumeSource {
                                local_object_reference: Some(core_v1::LocalObjectReference {
                                    name: Some("my-cm".to_string()),
                                }),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    },
                    core_v1::Volume {
                        name: Some("secret-vol".to_string()),
                        volume_source: Some(core_v1::VolumeSource {
                            secret: Some(core_v1::SecretVolumeSource {
                                secret_name: Some("my-secret".to_string()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod with volumes must decode");
        let volumes = result["spec"]["volumes"].as_array().unwrap();

        assert!(
            volumes[0]["configMap"].get("defaultMode").is_none(),
            "configMap volume defaultMode must be omitted when the client never set it, not \
             stamped to 420 — a workload-template pod spec never goes through Pod-create \
             defaulting, so stamping it here permanently breaks hash-collision equality \
             checks against the un-stamped template a controller already has cached"
        );
        assert!(
            volumes[1]["secret"].get("defaultMode").is_none(),
            "secret volume defaultMode must be omitted when the client never set it, not \
             stamped to 420, for the same reason as the configMap case"
        );
    }

    /// An explicitly-set, non-default defaultMode must survive decode unchanged — the
    /// omit-when-absent fix above must not turn into "always drop defaultMode".
    #[test]
    fn generated_pod_spec_preserves_explicit_non_default_default_mode() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("explicit-default-mode-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                volumes: vec![core_v1::Volume {
                    name: Some("cm-vol".to_string()),
                    volume_source: Some(core_v1::VolumeSource {
                        config_map: Some(core_v1::ConfigMapVolumeSource {
                            local_object_reference: Some(core_v1::LocalObjectReference {
                                name: Some("my-cm".to_string()),
                            }),
                            default_mode: Some(256),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod with volumes must decode");

        assert_eq!(
            result["spec"]["volumes"][0]["configMap"]["defaultMode"], 256,
            "an explicit, non-default defaultMode set by the client must survive decode \
             unchanged"
        );
    }

    /// ImageVolumeSource (spec.volumes[].image) must survive proto decode.
    ///
    /// ImageVolume mounts an OCI image/artifact as a read-only volume; the volume-source
    /// match had no branch for it at all, so the volume was silently dropped and the
    /// container started without the content it expected.
    #[test]
    fn generated_pod_spec_preserves_image_volume_source() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("image-vol-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                volumes: vec![core_v1::Volume {
                    name: Some("image-vol".to_string()),
                    volume_source: Some(core_v1::VolumeSource {
                        image: Some(core_v1::ImageVolumeSource {
                            reference: Some("registry.example/artifact:v1".to_string()),
                            pull_policy: Some("Always".to_string()),
                        }),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod with image volume must decode");

        let volumes = result["spec"]["volumes"].as_array().unwrap();
        assert_eq!(
            volumes[0]["image"]["reference"], "registry.example/artifact:v1",
            "spec.volumes[].image.reference must survive decode — without it the container \
             never gets the OCI image/artifact content it was mounted to receive"
        );
        assert_eq!(
            volumes[0]["image"]["pullPolicy"], "Always",
            "spec.volumes[].image.pullPolicy must survive decode"
        );
    }

    /// PodSpec hostNetwork/hostAliases/dnsConfig/dnsPolicy/ephemeralContainers/
    /// automountServiceAccountToken all survive protobuf decode, and enableServiceLinks
    /// (field 30) does not collide with dnsConfig (field 26) — both must decode correctly
    /// when set together.
    ///
    /// Without this, DNS 'configurable pod DNS nameservers', hostAliases '/etc/hosts entries',
    /// KubeletManagedEtcHosts (hostNetwork), ephemeral-containers update, and ServiceAccount
    /// 'opting out of API token automount' all silently fail for every protobuf client
    /// (client-go typed clientsets + the e2e suite), even though kubectl (JSON) looks fine.
    #[test]
    fn generated_pod_spec_preserves_dns_hostaliases_ephemeral_and_automount_fields() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("full-spec-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                host_network: Some(true),
                automount_service_account_token: Some(false),
                enable_service_links: Some(false),
                dns_policy: Some("None".to_string()),
                host_aliases: vec![core_v1::HostAlias {
                    ip: Some("127.0.0.1".to_string()),
                    hostnames: vec!["foo.local".to_string(), "bar.local".to_string()],
                }],
                dns_config: Some(core_v1::PodDnsConfig {
                    nameservers: vec!["1.2.3.4".to_string()],
                    searches: vec!["ns1.svc.cluster.local".to_string()],
                    options: vec![core_v1::PodDnsConfigOption {
                        name: Some("ndots".to_string()),
                        value: Some("2".to_string()),
                    }],
                }),
                ephemeral_containers: vec![core_v1::EphemeralContainer {
                    ephemeral_container_common: Some(core_v1::EphemeralContainerCommon {
                        name: Some("debugger".to_string()),
                        image: Some("busybox".to_string()),
                        ..Default::default()
                    }),
                    target_container_name: Some("c".to_string()),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod with full spec must decode");

        assert_eq!(
            result["spec"]["hostNetwork"], true,
            "hostNetwork must survive decode — without it KubeletManagedEtcHosts and \
             hostPort-on-hostNetwork behavior is silently wrong"
        );
        assert_eq!(
            result["spec"]["automountServiceAccountToken"], false,
            "pod-level automountServiceAccountToken=false must survive decode — otherwise a \
             pod that explicitly opted out of token automount gets one anyway"
        );
        assert_eq!(
            result["spec"]["enableServiceLinks"], false,
            "enableServiceLinks must survive decode unaffected by dnsConfig sharing no tag \
             with it (26 vs 30) — a regression here would mean either field corrupts the other"
        );
        assert_eq!(
            result["spec"]["dnsPolicy"], "None",
            "dnsPolicy=\"None\" must survive decode — without it, create-defaulting stamps \
             \"ClusterFirst\" instead, and the kubelet then ignores dnsConfig.nameservers \
             entirely because ClusterFirst's own resolv.conf generation takes precedence \
             (live-verified: this is why 'configurable pod DNS nameservers' fails even when \
             dnsConfig itself decodes correctly)"
        );
        assert_eq!(
            result["spec"]["hostAliases"][0]["ip"], "127.0.0.1",
            "hostAliases[].ip must survive decode — otherwise requested /etc/hosts entries \
             never reach the kubelet"
        );
        assert_eq!(
            result["spec"]["hostAliases"][0]["hostnames"][1], "bar.local",
            "hostAliases[].hostnames must survive decode in full"
        );
        assert_eq!(
            result["spec"]["dnsConfig"]["nameservers"][0], "1.2.3.4",
            "dnsConfig.nameservers must survive decode — without it, user-specified DNS \
             nameservers are silently dropped and the kubelet falls back to cluster defaults"
        );
        assert_eq!(
            result["spec"]["dnsConfig"]["searches"][0], "ns1.svc.cluster.local",
            "dnsConfig.searches must survive decode"
        );
        assert_eq!(
            result["spec"]["dnsConfig"]["options"][0]["name"], "ndots",
            "dnsConfig.options must survive decode"
        );
        assert_eq!(
            result["spec"]["ephemeralContainers"][0]["name"], "debugger",
            "ephemeralContainers must survive decode — apply_ephemeral_containers_patch's \
             merge logic is correct but never runs if the field is dropped on decode"
        );
        assert_eq!(
            result["spec"]["ephemeralContainers"][0]["image"], "busybox",
            "ephemeralContainers[].image must survive decode"
        );
        assert_eq!(
            result["spec"]["ephemeralContainers"][0]["targetContainerName"], "c",
            "ephemeralContainers[].targetContainerName must survive decode"
        );
    }

    /// Container-level securityContext survives protobuf decode.
    ///
    /// P1 security bug: without this, gen_container_to_json silently drops the entire
    /// securityContext, so every protobuf-created container runs as whatever UID the image
    /// defaults to (usually root) regardless of runAsUser, and allowPrivilegeEscalation=false
    /// / readOnlyRootFilesystem=true are both ignored — a container that explicitly asked to
    /// be locked down runs unlocked.
    #[test]
    fn generated_container_preserves_security_context() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("sc-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    security_context: Some(core_v1::SecurityContext {
                        run_as_user: Some(1002),
                        run_as_group: Some(2000),
                        allow_privilege_escalation: Some(false),
                        read_only_root_filesystem: Some(true),
                        capabilities: Some(core_v1::Capabilities {
                            add: vec!["NET_ADMIN".to_string()],
                            drop: vec!["ALL".to_string()],
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result =
            decode_pod_proto_gen(&buf).expect("Pod with container securityContext must decode");
        let sc = &result["spec"]["containers"][0]["securityContext"];

        assert_eq!(
            sc["runAsUser"], 1002,
            "container securityContext.runAsUser must survive decode — reverting this fix \
             means containers run as root (uid 0) regardless of the requested UID"
        );
        assert_eq!(
            sc["runAsGroup"], 2000,
            "container securityContext.runAsGroup must survive decode"
        );
        assert_eq!(
            sc["allowPrivilegeEscalation"], false,
            "allowPrivilegeEscalation=false must survive decode — otherwise a container that \
             explicitly forbade privilege escalation can still escalate"
        );
        assert_eq!(
            sc["readOnlyRootFilesystem"], true,
            "readOnlyRootFilesystem=true must survive decode (sig-node 'read only busybox')"
        );
        assert_eq!(
            sc["capabilities"]["add"][0], "NET_ADMIN",
            "capabilities.add must survive decode"
        );
        assert_eq!(
            sc["capabilities"]["drop"][0], "ALL",
            "capabilities.drop must survive decode"
        );
        assert!(
            sc["runAsNonRoot"].is_null(),
            "runAsNonRoot must stay absent when the client never set it — emitting a spurious \
             false would mask an unset field as an explicit opt-out of the non-root check"
        );
        assert!(
            sc["privileged"].is_null(),
            "privileged must stay absent when unset — a spurious false looks identical to an \
             explicit non-privileged request, hiding the decode-drop bug this field is prone to"
        );
    }

    /// Pod-level securityContext, including sysctls, survives protobuf decode.
    ///
    /// P1 security bug: without this, pod.Spec.SecurityContext.RunAsUser/RunAsGroup are
    /// dropped for every protobuf-created pod, and sysctls never reach the kubelet or
    /// validate_pod_sysctls — making sysctl validation a no-op on the protobuf path even
    /// after it's implemented, because the validator never sees the field it should reject.
    #[test]
    fn generated_pod_spec_preserves_security_context_and_sysctls() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("pod-sc-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                security_context: Some(core_v1::PodSecurityContext {
                    run_as_user: Some(1001),
                    run_as_group: Some(3000),
                    fs_group: Some(4000),
                    sysctls: vec![core_v1::Sysctl {
                        name: Some("kernel.shm_rmid_forced".to_string()),
                        value: Some("1".to_string()),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result =
            decode_pod_proto_gen(&buf).expect("Pod with pod-level securityContext must decode");
        let sc = &result["spec"]["securityContext"];

        assert_eq!(
            sc["runAsUser"], 1001,
            "pod.Spec.SecurityContext.RunAsUser must survive decode"
        );
        assert_eq!(
            sc["runAsGroup"], 3000,
            "pod.Spec.SecurityContext.RunAsGroup must survive decode"
        );
        assert_eq!(
            sc["fsGroup"], 4000,
            "pod.Spec.SecurityContext.FSGroup must survive decode"
        );
        assert_eq!(
            sc["sysctls"][0]["name"], "kernel.shm_rmid_forced",
            "sysctls must survive decode — without it, 'should support sysctls' fails because \
             the kubelet never receives the sysctl, and 'should reject invalid sysctls' is a \
             no-op because validate_pod_sysctls never sees the field to reject"
        );
        assert_eq!(
            sc["sysctls"][0]["value"], "1",
            "sysctl value must survive decode"
        );
    }

    /// ConfigMap/Secret immutable:true survives protobuf decode.
    ///
    /// The immutability enforcement checks (resource.rs PATCH/PUT) are correct but never
    /// fire if decode drops the field first — a protobuf Update() that sets immutable:true
    /// would otherwise leave the stored object mutable forever, defeating the guarantee.
    #[test]
    fn generated_configmap_and_secret_preserve_immutable_flag() {
        let cm = core_v1::ConfigMap {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("immutable-cm".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            immutable: Some(true),
            ..Default::default()
        };
        let mut cm_buf = Vec::new();
        cm.encode(&mut cm_buf).unwrap();
        let cm_result = decode_configmap_proto_gen(&cm_buf).expect("ConfigMap must decode");
        assert_eq!(
            cm_result["immutable"], true,
            "ConfigMap.immutable must survive decode — without it, an immutable ConfigMap can \
             still be mutated because the stored object never has immutable:true set"
        );

        let secret = core_v1::Secret {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("immutable-secret".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            immutable: Some(true),
            ..Default::default()
        };
        let mut secret_buf = Vec::new();
        secret.encode(&mut secret_buf).unwrap();
        let secret_result = decode_secret_proto_gen(&secret_buf).expect("Secret must decode");
        assert_eq!(
            secret_result["immutable"], true,
            "Secret.immutable must survive decode — same data-integrity gap as ConfigMap"
        );
    }

    /// ResourceQuota status.hard/status.used survive the generated-path decode.
    ///
    /// Upstream's quota controller calls `ResourceQuotas(ns).UpdateStatus(...)` every
    /// reconcile, using protobuf content-type by default. Before this fix,
    /// decode_resourcequota_proto_gen never read `.status` at all, so that PUT overwrote
    /// the stored status with `null` — a namespace's CPU/memory quota usage would read back
    /// permanently empty even while pods consuming the quota exist, because u7s's own
    /// internal reconciler only heals the count-based subset it computes itself.
    #[test]
    fn generated_resourcequota_preserves_status_hard_and_used_for_status_subresource_replace() {
        fn quantity(
            s: &str,
        ) -> crate::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
            crate::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
                string: Some(s.to_string()),
            }
        }
        let rq = core_v1::ResourceQuota {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("compute-quota".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(core_v1::ResourceQuotaStatus {
                hard: [("cpu".to_string(), quantity("4"))].into_iter().collect(),
                used: [("cpu".to_string(), quantity("1500m"))]
                    .into_iter()
                    .collect(),
            }),
        };
        let mut buf = Vec::new();
        rq.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_resourcequota_proto_gen(&buf)
            .expect("ResourceQuota with status must decode via generated path");

        assert_eq!(
            result["status"]["hard"]["cpu"], "4",
            "status.hard must survive decode"
        );
        assert_eq!(
            result["status"]["used"]["cpu"], "1500m",
            "status.used must survive decode — without it, a KCM protobuf UpdateStatus call \
             wipes CPU/memory quota accounting and it reads back permanently empty even \
             though pods consuming the quota exist"
        );
    }

    /// Node status (conditions/addresses/capacity/allocatable/nodeInfo) survives the
    /// generated-path decode.
    ///
    /// The kubelet's `Nodes().UpdateStatus(...)` PUTs the full Node using protobuf
    /// content-type by default. Before this fix, decode_node_proto_gen never read
    /// `.status` at all, so that PUT overwrote the stored status with `null` — a node
    /// would read back with no Ready condition and no capacity/allocatable, and every
    /// sig-node test that waits on node readiness or schedules against capacity would fail.
    #[test]
    fn generated_node_preserves_status_for_status_subresource_replace() {
        fn quantity(
            s: &str,
        ) -> crate::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
            crate::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
                string: Some(s.to_string()),
            }
        }
        let node = core_v1::Node {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("node-1".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(core_v1::NodeStatus {
                phase: Some("Running".to_string()),
                capacity: [("cpu".to_string(), quantity("4"))].into_iter().collect(),
                allocatable: [("cpu".to_string(), quantity("3800m"))]
                    .into_iter()
                    .collect(),
                conditions: vec![
                    core_v1::NodeCondition {
                        r#type: Some("Ready".to_string()),
                        status: Some("True".to_string()),
                        reason: Some("KubeletReady".to_string()),
                        ..Default::default()
                    },
                    core_v1::NodeCondition {
                        r#type: Some("MemoryPressure".to_string()),
                        status: Some("False".to_string()),
                        ..Default::default()
                    },
                ],
                addresses: vec![core_v1::NodeAddress {
                    r#type: Some("InternalIP".to_string()),
                    address: Some("192.168.1.10".to_string()),
                }],
                daemon_endpoints: Some(core_v1::NodeDaemonEndpoints {
                    kubelet_endpoint: Some(core_v1::DaemonEndpoint { port: Some(10250) }),
                }),
                node_info: Some(core_v1::NodeSystemInfo {
                    kubelet_version: Some("v1.36.0".to_string()),
                    architecture: Some("amd64".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        node.encode(&mut buf).expect("prost encode must succeed");

        let result =
            decode_node_proto_gen(&buf).expect("Node with status must decode via generated path");

        assert_eq!(
            result["status"]["capacity"]["cpu"], "4",
            "status.capacity must survive decode — without it the scheduler sees a node \
             with no capacity and never schedules pods onto it"
        );
        assert_eq!(
            result["status"]["allocatable"]["cpu"], "3800m",
            "status.allocatable must survive decode"
        );
        let conds = result["status"]["conditions"].as_array().expect(
            "status.conditions must be present — without it a kubelet's protobuf \
             UpdateStatus call reports no Ready condition at all, so every sig-node test \
             that waits for Node Ready hangs forever",
        );
        assert_eq!(conds.len(), 2, "both conditions must survive decode");
        assert_eq!(
            conds[0]["type"], "Ready",
            "condition type must survive decode"
        );
        assert_eq!(
            conds[0]["status"], "True",
            "condition status must survive decode"
        );
        assert_eq!(
            result["status"]["addresses"][0]["address"], "192.168.1.10",
            "status.addresses must survive decode — without it kubectl get nodes -o wide \
             and downward-API status.hostIP consumers see no address"
        );
        assert_eq!(
            result["status"]["daemonEndpoints"]["kubeletEndpoint"]["Port"], 10250,
            "status.daemonEndpoints.kubeletEndpoint.Port must survive decode — the API \
             server's own log/exec/proxy subresources dial this port to reach the kubelet"
        );
        assert_eq!(
            result["status"]["nodeInfo"]["kubeletVersion"], "v1.36.0",
            "status.nodeInfo must survive decode — version skew checks depend on it"
        );
    }

    /// Service status.loadBalancer and status.conditions must survive proto decode.
    ///
    /// `kubectl get svc` and any client waiting on external connectivity read
    /// status.loadBalancer.ingress to learn the IP/hostname a cloud provider assigned. The
    /// service controller's protobuf-content-type UpdateStatus call is the only way that
    /// value ever reaches the stored object; losing it here would leave every LoadBalancer
    /// Service looking permanently unprovisioned even after the cloud LB exists.
    #[test]
    fn service_status_proto_decode_preserves_load_balancer_and_conditions() {
        let svc = core_v1::Service {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-svc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(core_v1::ServiceStatus {
                load_balancer: Some(core_v1::LoadBalancerStatus {
                    ingress: vec![core_v1::LoadBalancerIngress {
                        ip: Some("203.0.113.20".to_string()),
                        hostname: Some("lb.example.com".to_string()),
                        ..Default::default()
                    }],
                }),
                conditions: vec![meta_v1::Condition {
                    r#type: Some("LoadBalancerAttached".to_string()),
                    status: Some("True".to_string()),
                    reason: Some("Provisioned".to_string()),
                    ..Default::default()
                }],
            }),
        };
        let mut buf = Vec::new();
        svc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_service_proto_gen(&buf).expect("Service with status must decode");

        assert_eq!(
            result["status"]["loadBalancer"]["ingress"][0]["ip"], "203.0.113.20",
            "status.loadBalancer.ingress[0].ip must survive decode — without it a protobuf \
             UpdateStatus call from the service controller makes a provisioned LoadBalancer \
             Service look permanently pending to every client"
        );
        assert_eq!(
            result["status"]["loadBalancer"]["ingress"][0]["hostname"], "lb.example.com",
            "status.loadBalancer.ingress[0].hostname must survive decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "LoadBalancerAttached",
            "status.conditions must survive decode alongside loadBalancer — losing either one \
             corrupts a caller's GET-modify-PUT round trip through /status"
        );
    }

    /// PersistentVolumeClaim status.phase and status.conditions must survive proto decode.
    ///
    /// The PV/PVC binding lifecycle and volume-resize workflow are driven entirely by
    /// status.phase/conditions; the PVC/expansion controllers PUT status updates using
    /// protobuf content-type by default, so a decoder that drops `.status` here would freeze
    /// both flows — callers would see a claim stuck at "Pending" forever even once bound.
    #[test]
    fn persistentvolumeclaim_status_proto_decode_preserves_phase_and_conditions() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(core_v1::PersistentVolumeClaimStatus {
                phase: Some("Bound".to_string()),
                conditions: vec![core_v1::PersistentVolumeClaimCondition {
                    r#type: Some("Resizing".to_string()),
                    status: Some("True".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result =
            decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC with status must decode");

        assert_eq!(
            result["status"]["phase"], "Bound",
            "status.phase must survive decode — without it the PV/PVC binding lifecycle looks \
             frozen at Pending to every client watching a protobuf UpdateStatus call"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "Resizing",
            "status.conditions must survive decode — without it a caller waiting on the \
             FileSystemResizePending condition never sees the resize controller's progress"
        );
    }

    /// decode_podtemplate_proto_gen must preserve the embedded pod template's spec and
    /// metadata, not just the PodTemplate's own metadata.
    ///
    /// ReplicationControllers and other legacy templating callers create pods straight from
    /// this decoded value; if template.spec is dropped, every pod created from the template
    /// has no containers and never reaches Running.
    #[test]
    fn decode_podtemplate_proto_gen_preserves_template_pod_spec() {
        let pt = core_v1::PodTemplate {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-template".to_string()),
                ..Default::default()
            }),
            template: Some(core_v1::PodTemplateSpec {
                metadata: Some(meta_v1::ObjectMeta {
                    labels: [("app".to_string(), "demo".to_string())]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                }),
                spec: Some(core_v1::PodSpec {
                    containers: vec![core_v1::Container {
                        name: Some("demo".to_string()),
                        image: Some("demo:1.0".to_string()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            }),
        };
        let mut buf = Vec::new();
        pt.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_podtemplate_proto_gen(&buf).expect("PodTemplate must decode");

        assert_eq!(
            result["template"]["spec"]["containers"][0]["image"], "demo:1.0",
            "template.spec.containers must survive decode — without it, every workload created \
             from this PodTemplate gets pods with no containers"
        );
        assert_eq!(
            result["template"]["metadata"]["labels"]["app"], "demo",
            "template.metadata.labels must survive decode — controllers select pods by these labels"
        );
    }

    /// decode_serviceaccount_proto_gen must preserve secrets, imagePullSecrets and the
    /// automountServiceAccountToken override.
    ///
    /// Dropping imagePullSecrets breaks private-registry pulls for every pod using this
    /// ServiceAccount; dropping an explicit automountServiceAccountToken=false re-enables
    /// automatic API token mounting the caller opted out of for security reasons.
    #[test]
    fn decode_serviceaccount_proto_gen_preserves_secrets_and_automount() {
        let sa = core_v1::ServiceAccount {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-sa".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            secrets: vec![core_v1::ObjectReference {
                name: Some("my-sa-token".to_string()),
                ..Default::default()
            }],
            image_pull_secrets: vec![core_v1::LocalObjectReference {
                name: Some("registry-cred".to_string()),
            }],
            automount_service_account_token: Some(false),
        };
        let mut buf = Vec::new();
        sa.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_serviceaccount_proto_gen(&buf).expect("ServiceAccount must decode");

        assert_eq!(
            result["secrets"][0]["name"], "my-sa-token",
            "secrets must survive decode — without it, pods using this ServiceAccount lose \
             access to the mountable secret list"
        );
        assert_eq!(
            result["imagePullSecrets"][0]["name"], "registry-cred",
            "imagePullSecrets must survive decode — without it the kubelet cannot pull private \
             registry images for pods using this ServiceAccount"
        );
        assert_eq!(
            result["automountServiceAccountToken"], false,
            "automountServiceAccountToken=false must survive decode — dropping it re-enables \
             automatic API token mounting the caller explicitly opted out of"
        );
    }

    /// decode_endpoints_proto_gen must preserve subsets[].addresses and subsets[].ports.
    ///
    /// kube-proxy programs Service load-balancing rules directly from this data; a dropped
    /// address or port means traffic to the Service black-holes even though the backing pods
    /// are healthy.
    #[test]
    fn decode_endpoints_proto_gen_preserves_subsets_addresses_and_ports() {
        let ep = core_v1::Endpoints {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-svc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            subsets: vec![core_v1::EndpointSubset {
                addresses: vec![core_v1::EndpointAddress {
                    ip: Some("10.0.0.5".to_string()),
                    hostname: Some("pod-a".to_string()),
                    ..Default::default()
                }],
                not_ready_addresses: vec![],
                ports: vec![core_v1::EndpointPort {
                    name: Some("http".to_string()),
                    port: Some(8080),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                }],
            }],
        };
        let mut buf = Vec::new();
        ep.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_endpoints_proto_gen(&buf).expect("Endpoints must decode");

        assert_eq!(
            result["subsets"][0]["addresses"][0]["ip"], "10.0.0.5",
            "subsets[].addresses must survive decode — without it kube-proxy programs no \
             backend for the Service and traffic black-holes"
        );
        assert_eq!(
            result["subsets"][0]["ports"][0]["port"], 8080,
            "subsets[].ports must survive decode — without it kube-proxy has no port to forward to"
        );
    }

    /// decode_limitrange_proto_gen must preserve spec.limits[].max and spec.limits[].default.
    ///
    /// LimitRanger admission reads these to cap and default container resource requests; a
    /// dropped max/default silently disables the enforcement the namespace owner configured.
    #[test]
    fn decode_limitrange_proto_gen_preserves_max_and_default_limits() {
        fn quantity(
            s: &str,
        ) -> crate::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
            crate::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
                string: Some(s.to_string()),
            }
        }
        let lr = core_v1::LimitRange {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("cpu-limits".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::LimitRangeSpec {
                limits: vec![core_v1::LimitRangeItem {
                    r#type: Some("Container".to_string()),
                    max: [("cpu".to_string(), quantity("2"))].into_iter().collect(),
                    default: [("cpu".to_string(), quantity("500m"))]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                }],
            }),
        };
        let mut buf = Vec::new();
        lr.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_limitrange_proto_gen(&buf).expect("LimitRange must decode");

        assert_eq!(
            result["spec"]["limits"][0]["max"]["cpu"], "2",
            "spec.limits[].max must survive decode — without it LimitRanger admission enforces \
             no per-container CPU ceiling at all"
        );
        assert_eq!(
            result["spec"]["limits"][0]["default"]["cpu"], "500m",
            "spec.limits[].default must survive decode — without it containers that omit \
             resources.limits.cpu get no default applied"
        );
    }

    /// decode_event_proto_gen must preserve reason/message/involvedObject/series.
    ///
    /// `kubectl describe` and event-based alerting read these fields directly; a dropped
    /// involvedObject makes an event impossible to correlate back to the object it reports on,
    /// and a dropped series.count hides how many times an event actually recurred.
    #[test]
    fn decode_event_proto_gen_preserves_reason_involved_object_and_series() {
        let ev = core_v1::Event {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-pod.17abc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            involved_object: Some(core_v1::ObjectReference {
                kind: Some("Pod".to_string()),
                name: Some("my-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            reason: Some("Started".to_string()),
            message: Some("Started container demo".to_string()),
            r#type: Some("Normal".to_string()),
            series: Some(core_v1::EventSeries {
                count: Some(3),
                last_observed_time: Some(meta_v1::MicroTime {
                    seconds: Some(1_700_000_000),
                    nanos: Some(0),
                }),
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ev.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_event_proto_gen(&buf).expect("Event must decode");

        assert_eq!(
            result["reason"], "Started",
            "reason must survive decode — without it `kubectl describe` shows a blank reason \
             for every reported event"
        );
        assert_eq!(
            result["involvedObject"]["name"], "my-pod",
            "involvedObject must survive decode — without it the event cannot be correlated \
             back to the pod it describes"
        );
        assert_eq!(
            result["series"]["count"], 3,
            "series.count must survive decode — without it repeated identical events collapse \
             to a count of zero instead of the real occurrence count"
        );
    }

    /// ConfigMap.data/binaryData and Secret.data/stringData/type must survive proto decode.
    ///
    /// The existing immutable-flag test above never populates the actual payload fields; a
    /// decoder that dropped `.data` here would silently turn every pod's mounted ConfigMap or
    /// Secret volume into an empty directory, since data/binaryData/stringData are these
    /// resources' entire reason to exist.
    #[test]
    fn decode_configmap_and_secret_proto_gen_preserve_data_payloads() {
        let cm = core_v1::ConfigMap {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-cm".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            data: [("config.yaml".to_string(), "key: value".to_string())]
                .into_iter()
                .collect(),
            binary_data: [("blob".to_string(), vec![1, 2, 3])].into_iter().collect(),
            ..Default::default()
        };
        let mut cm_buf = Vec::new();
        cm.encode(&mut cm_buf).unwrap();
        let cm_result = decode_configmap_proto_gen(&cm_buf).expect("ConfigMap must decode");
        assert_eq!(
            cm_result["data"]["config.yaml"], "key: value",
            "ConfigMap.data must survive decode — without it a mounted ConfigMap volume is \
             silently empty for every pod using it"
        );
        assert!(
            cm_result["binaryData"]["blob"].is_string(),
            "ConfigMap.binaryData must survive decode as base64"
        );

        let secret = core_v1::Secret {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-secret".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            r#type: Some("Opaque".to_string()),
            data: [("password".to_string(), b"hunter2".to_vec())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let mut secret_buf = Vec::new();
        secret.encode(&mut secret_buf).unwrap();
        let secret_result = decode_secret_proto_gen(&secret_buf).expect("Secret must decode");
        assert_eq!(
            secret_result["type"], "Opaque",
            "Secret.type must survive decode — controllers branch on this (e.g. \
             kubernetes.io/service-account-token vs Opaque)"
        );
        use base64::Engine as _;
        assert_eq!(
            secret_result["data"]["password"],
            base64::engine::general_purpose::STANDARD.encode(b"hunter2"),
            "Secret.data must survive decode — without it a mounted Secret volume or env var \
             is silently empty for every pod using it"
        );
    }
}
