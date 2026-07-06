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
        cm.insert("resources".to_string(), serde_json::Value::Object(res_map));
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
                            let dm = match s.default_mode.unwrap_or(0) {
                                0 => 420,
                                v => v,
                            };
                            secret_map.insert(
                                "defaultMode".to_string(),
                                serde_json::Value::Number(dm.into()),
                            );
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
                                let dm = match cm.default_mode.unwrap_or(0) {
                                    0 => 420,
                                    v => v,
                                };
                                cm_map.insert(
                                    "defaultMode".to_string(),
                                    serde_json::Value::Number(dm.into()),
                                );
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
    if let Some(ads) = spec.active_deadline_seconds {
        if ads > 0 {
            spec_map.insert(
                "activeDeadlineSeconds".to_string(),
                serde_json::Value::Number(serde_json::Number::from(ads)),
            );
        }
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

pub fn decode_pod_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let pod = core_v1::Pod::decode(data).ok()?;
    let meta = gen_object_meta_to_json(pod.metadata.unwrap_or_default());
    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": meta
    });
    obj["spec"] = gen_pod_spec_to_json(pod.spec.unwrap_or_default());
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
}
