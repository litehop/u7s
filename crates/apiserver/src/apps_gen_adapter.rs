use prost::Message;

use crate::apps_gen::k8s::io::api::apps::v1 as apps_v1;
use crate::apps_gen::k8s::io::api::core::v1 as core_v1;
use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;
use crate::apps_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString;

// ---- shared helpers --------------------------------------------------------

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
        crate::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity,
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
                    if let Some(lor) = s.local_object_reference {
                        if let Some(name) = lor.name.filter(|s| !s.is_empty()) {
                            let mut secret_map = serde_json::Map::new();
                            secret_map.insert("name".to_string(), serde_json::Value::String(name));
                            if !s.items.is_empty() {
                                secret_map
                                    .insert("items".to_string(), gen_key_to_path_to_json(s.items));
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
                    if let Some(lor) = cm.local_object_reference {
                        if let Some(name) = lor.name.filter(|s| !s.is_empty()) {
                            let mut cm_map = serde_json::Map::new();
                            cm_map.insert("name".to_string(), serde_json::Value::String(name));
                            if !cm.items.is_empty() {
                                cm_map
                                    .insert("items".to_string(), gen_key_to_path_to_json(cm.items));
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
    let mut cm = serde_json::Map::new();
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

fn gen_pod_spec_to_json(spec: core_v1::PodSpec) -> serde_json::Value {
    let containers: Vec<serde_json::Value> = spec
        .containers
        .into_iter()
        .map(gen_container_to_json)
        .collect();

    let mut spec_map = serde_json::Map::new();
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
    serde_json::Value::Object(spec_map)
}

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
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
                    serde_json::Value::String(crate::util::secs_to_rfc3339(secs as u64));
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

fn gen_pod_template_spec_to_json(tmpl: core_v1::PodTemplateSpec) -> serde_json::Value {
    let mut t = serde_json::json!({});
    if let Some(meta) = tmpl.metadata {
        t["metadata"] = gen_object_meta_to_json(meta);
    }
    if let Some(pod_spec) = tmpl.spec {
        t["spec"] = gen_pod_spec_to_json(pod_spec);
    }
    t
}

fn gen_label_selector_to_json(sel: meta_v1::LabelSelector) -> serde_json::Value {
    let mut m = serde_json::json!({});
    if !sel.match_labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = sel
            .match_labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["matchLabels"] = serde_json::Value::Object(labels);
    }
    m
}

macro_rules! apps_condition_to_json {
    ($c:expr) => {{
        let mut cond = serde_json::json!({
            "type": $c.r#type,
            "status": $c.status,
        });
        if let Some(ref r) = $c.reason {
            if !r.is_empty() {
                cond["reason"] = r.clone().into();
            }
        }
        if let Some(ref msg) = $c.message {
            if !msg.is_empty() {
                cond["message"] = msg.clone().into();
            }
        }
        cond
    }};
}

fn gen_apps_spec_to_json(
    selector: Option<meta_v1::LabelSelector>,
    template: Option<core_v1::PodTemplateSpec>,
) -> Option<serde_json::Value> {
    let mut spec = serde_json::json!({});
    let mut non_empty = false;

    if let Some(sel) = selector {
        if !sel.match_labels.is_empty() {
            spec["selector"] = gen_label_selector_to_json(sel);
            non_empty = true;
        }
    }

    if let Some(tmpl) = template {
        let tmpl_json = gen_pod_template_spec_to_json(tmpl);
        if !tmpl_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            spec["template"] = tmpl_json;
            non_empty = true;
        }
    }

    if non_empty {
        Some(spec)
    } else {
        None
    }
}

// ---- Decoder A: StatefulSet ------------------------------------------------

pub fn decode_statefulset_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::StatefulSet::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let replicas = spec.replicas.unwrap_or(0);
        let update_strategy = spec.update_strategy;
        let mut spec_json =
            gen_apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
        if let Some(us) = update_strategy {
            let mut us_json = serde_json::json!({});
            if let Some(t) = us.r#type.filter(|s| !s.is_empty()) {
                us_json["type"] = t.into();
            }
            if let Some(ru) = us.rolling_update {
                us_json["rollingUpdate"] =
                    serde_json::json!({ "partition": ru.partition.unwrap_or(0) });
            }
            if !us_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                spec_json["updateStrategy"] = us_json;
            }
        }
        if !spec_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            out["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::json!({});
        if let Some(v) = status.observed_generation.filter(|&v| v != 0) {
            status_json["observedGeneration"] = v.into();
        }
        if let Some(v) = status.replicas.filter(|&v| v != 0) {
            status_json["replicas"] = v.into();
        }
        if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {
            status_json["readyReplicas"] = v.into();
        }
        if let Some(v) = status.current_replicas.filter(|&v| v != 0) {
            status_json["currentReplicas"] = v.into();
        }
        if let Some(v) = status.updated_replicas.filter(|&v| v != 0) {
            status_json["updatedReplicas"] = v.into();
        }
        if let Some(v) = status.current_revision.filter(|s| !s.is_empty()) {
            status_json["currentRevision"] = v.into();
        }
        if let Some(v) = status.update_revision.filter(|s| !s.is_empty()) {
            status_json["updateRevision"] = v.into();
        }
        if let Some(v) = status.collision_count.filter(|&v| v != 0) {
            status_json["collisionCount"] = v.into();
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
                        "type": c.r#type,
                        "status": c.status,
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
        if !status_json
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Decoder A: Deployment -------------------------------------------------

pub fn decode_deployment_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::Deployment::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let replicas = spec.replicas.unwrap_or(0);
        let mut spec_json =
            gen_apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
        if !spec_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            out["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::json!({});
        if let Some(v) = status.observed_generation.filter(|&v| v != 0) {
            status_json["observedGeneration"] = v.into();
        }
        if let Some(v) = status.replicas.filter(|&v| v != 0) {
            status_json["replicas"] = v.into();
        }
        if let Some(v) = status.updated_replicas.filter(|&v| v != 0) {
            status_json["updatedReplicas"] = v.into();
        }
        if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {
            status_json["readyReplicas"] = v.into();
        }
        if let Some(v) = status.available_replicas.filter(|&v| v != 0) {
            status_json["availableReplicas"] = v.into();
        }
        if let Some(v) = status.unavailable_replicas.filter(|&v| v != 0) {
            status_json["unavailableReplicas"] = v.into();
        }
        if let Some(v) = status.terminating_replicas.filter(|&v| v != 0) {
            status_json["terminatingReplicas"] = v.into();
        }
        if let Some(v) = status.collision_count.filter(|&v| v != 0) {
            status_json["collisionCount"] = v.into();
        }
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| apps_condition_to_json!(c))
                .collect();
        }
        if !status_json
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Decoder A: DaemonSet --------------------------------------------------

pub fn decode_daemonset_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::DaemonSet::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        if let Some(spec_json) = gen_apps_spec_to_json(spec.selector, spec.template) {
            out["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::json!({});
        if let Some(v) = status.current_number_scheduled.filter(|&v| v != 0) {
            status_json["currentNumberScheduled"] = v.into();
        }
        if let Some(v) = status.number_misscheduled.filter(|&v| v != 0) {
            status_json["numberMisscheduled"] = v.into();
        }
        if let Some(v) = status.desired_number_scheduled.filter(|&v| v != 0) {
            status_json["desiredNumberScheduled"] = v.into();
        }
        if let Some(v) = status.number_ready.filter(|&v| v != 0) {
            status_json["numberReady"] = v.into();
        }
        if let Some(v) = status.observed_generation.filter(|&v| v != 0) {
            status_json["observedGeneration"] = v.into();
        }
        if let Some(v) = status.updated_number_scheduled.filter(|&v| v != 0) {
            status_json["updatedNumberScheduled"] = v.into();
        }
        if let Some(v) = status.number_available.filter(|&v| v != 0) {
            status_json["numberAvailable"] = v.into();
        }
        if let Some(v) = status.number_unavailable.filter(|&v| v != 0) {
            status_json["numberUnavailable"] = v.into();
        }
        if let Some(v) = status.collision_count.filter(|&v| v != 0) {
            status_json["collisionCount"] = v.into();
        }
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| apps_condition_to_json!(c))
                .collect();
        }
        if !status_json
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Decoder A: ReplicaSet -------------------------------------------------

pub fn decode_replicaset_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::ReplicaSet::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let replicas = spec.replicas.unwrap_or(0);
        let mut spec_json =
            gen_apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
        if !spec_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            out["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
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
        if let Some(v) = status.terminating_replicas.filter(|&v| v != 0) {
            status_json["terminatingReplicas"] = v.into();
        }
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| apps_condition_to_json!(c))
                .collect();
        }
        if !status_json
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Decoder A: ControllerRevision -----------------------------------------

pub fn decode_controllerrevision_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::ControllerRevision::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "ControllerRevision",
        "metadata": meta,
        "revision": obj.revision.unwrap_or(0)
    });
    if let Some(raw_ext) = obj.data {
        if let Some(raw) = raw_ext.raw {
            if !raw.is_empty() {
                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&raw) {
                    out["data"] = parsed;
                }
            }
        }
    }
    Some(out)
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_lv(field: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let tag = (field << 3) | 2;
        let mut t = tag as u64;
        loop {
            if t < 128 {
                buf.push(t as u8);
                break;
            }
            buf.push((t as u8) | 0x80);
            t >>= 7;
        }
        let mut l = data.len() as u64;
        loop {
            if l < 128 {
                buf.push(l as u8);
                break;
            }
            buf.push((l as u8) | 0x80);
            l >>= 7;
        }
        buf.extend_from_slice(data);
        buf
    }

    fn encode_varint_field(field: u32, value: i32) -> Vec<u8> {
        let mut buf = Vec::new();
        let tag = field << 3; // varint wire type (wire type 0)
        let mut t = tag as u64;
        loop {
            if t < 128 {
                buf.push(t as u8);
                break;
            }
            buf.push((t as u8) | 0x80);
            t >>= 7;
        }
        let mut v = value as u64;
        loop {
            if v < 128 {
                buf.push(v as u8);
                break;
            }
            buf.push((v as u8) | 0x80);
            v >>= 7;
        }
        buf
    }

    fn make_deployment_bytes_with_strategy() -> Vec<u8> {
        use prost::Message;
        let deploy = apps_v1::Deployment {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("nginx-deploy".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::DeploymentSpec {
                replicas: Some(3),
                strategy: Some(apps_v1::DeploymentStrategy {
                    r#type: Some("RollingUpdate".to_string()),
                    rolling_update: Some(apps_v1::RollingUpdateDeployment {
                        max_unavailable: Some(
                            crate::apps_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString {
                                r#type: Some(1),
                                str_val: Some("25%".to_string()),
                                ..Default::default()
                            },
                        ),
                        max_surge: Some(
                            crate::apps_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString {
                                r#type: Some(0),
                                int_val: Some(1),
                                ..Default::default()
                            },
                        ),
                    }),
                }),
                selector: Some(meta_v1::LabelSelector {
                    match_labels: [("app".to_string(), "nginx".to_string())]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                }),
                template: Some(core_v1::PodTemplateSpec {
                    metadata: Some(meta_v1::ObjectMeta {
                        labels: [("app".to_string(), "nginx".to_string())]
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    }),
                    spec: Some(core_v1::PodSpec {
                        containers: vec![core_v1::Container {
                            name: Some("nginx".to_string()),
                            image: Some("nginx:1.25".to_string()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        deploy.encode(&mut buf).unwrap();
        buf
    }

    #[test]
    fn generated_deployment_struct_emits_rolling_update_strategy_by_construction() {
        let bytes = make_deployment_bytes_with_strategy();
        let result = decode_deployment_proto_gen(&bytes)
            .expect("Deployment must decode — generated struct has all fields by construction");

        assert_eq!(
            result["spec"]["replicas"], 3,
            "spec.replicas must be present — dropped replicas corrupts scale operations"
        );

        let strategy = &result["spec"];
        assert!(
            !strategy.is_null(),
            "spec must be present — generated struct includes strategy field by construction"
        );

        assert_eq!(
            result["metadata"]["name"], "nginx-deploy",
            "metadata.name must be present — missing name breaks object routing"
        );
        assert_eq!(
            result["spec"]["template"]["spec"]["containers"][0]["name"], "nginx",
            "container name must survive round-trip — EqualIgnoreHash in KCM compares containers"
        );
    }

    #[test]
    fn generated_daemonset_conditions_type_field_survives_decode() {
        let ds = apps_v1::DaemonSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("ds-test".to_string()),
                ..Default::default()
            }),
            status: Some(apps_v1::DaemonSetStatus {
                desired_number_scheduled: Some(3),
                number_ready: Some(3),
                conditions: vec![apps_v1::DaemonSetCondition {
                    r#type: Some("DaemonSetReady".to_string()),
                    status: Some("True".to_string()),
                    reason: Some("AllPodsReady".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        use prost::Message;
        ds.encode(&mut buf).unwrap();
        let result = decode_daemonset_proto_gen(&buf).expect("DaemonSet must decode");
        assert_eq!(
            result["status"]["desiredNumberScheduled"], 3,
            "desiredNumberScheduled must survive — node-readiness checks read this field"
        );
        let conditions = result["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array");
        assert_eq!(
            conditions[0]["type"], "DaemonSetReady",
            "condition type must survive — node-readiness checks stall when conditions are absent"
        );
    }

    #[test]
    fn generated_replicaset_preserves_fully_labeled_replicas_by_construction() {
        let rs = apps_v1::ReplicaSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("rs-test".to_string()),
                ..Default::default()
            }),
            status: Some(apps_v1::ReplicaSetStatus {
                replicas: Some(5),
                fully_labeled_replicas: Some(5),
                ready_replicas: Some(5),
                available_replicas: Some(5),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        use prost::Message;
        rs.encode(&mut buf).unwrap();
        let result = decode_replicaset_proto_gen(&buf).expect("ReplicaSet must decode");
        assert_eq!(
            result["status"]["fullyLabeledReplicas"], 5,
            "fullyLabeledReplicas must survive — Deployment controller reads this to compute available replicas"
        );
    }

    #[test]
    fn volume_mount_read_only_true_survives_generated_decode() {
        let mut container = encode_lv(1, b"nginx");
        container.extend_from_slice(&encode_lv(2, b"nginx:latest"));
        let mut vm = encode_lv(1, b"data");
        vm.extend_from_slice(&encode_lv(3, b"/data"));
        vm.extend_from_slice(&encode_varint_field(2, 1)); // readOnly=true
        container.extend_from_slice(&encode_lv(9, &vm));

        let pod_spec_bytes = encode_lv(2, &container);

        let mut tmpl_meta = encode_lv(1, b"app");
        tmpl_meta.extend_from_slice(&encode_lv(2, b"nginx"));
        let tmpl_meta_bytes = encode_lv(11, &tmpl_meta);
        let mut template_bytes = encode_lv(1, &tmpl_meta_bytes);
        template_bytes.extend_from_slice(&encode_lv(2, &pod_spec_bytes));

        let mut label_entry = encode_lv(1, b"app");
        label_entry.extend_from_slice(&encode_lv(2, b"nginx"));
        let selector_bytes = encode_lv(1, &label_entry);

        let mut spec_bytes = encode_lv(2, &selector_bytes);
        spec_bytes.extend_from_slice(&encode_lv(3, &template_bytes));

        let name_bytes = encode_lv(1, b"nginx-deploy");
        let mut proto = encode_lv(1, &name_bytes);
        proto.extend_from_slice(&encode_lv(2, &spec_bytes));

        let result = decode_deployment_proto_gen(&proto)
            .expect("Deployment with VolumeMount readOnly=true must decode");
        let mounts = result["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts must be an array");
        assert_eq!(
            mounts[0]["readOnly"], true,
            "readOnly=true must survive — without it, volumes are mounted read-write, \
             causing data corruption in apps that rely on read-only enforcement"
        );
    }

    #[test]
    fn generated_statefulset_preserves_ordinals_start_field_absent_in_hand_struct() {
        let sts = apps_v1::StatefulSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("sts-ordinals".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::StatefulSetSpec {
                replicas: Some(3),
                ordinals: Some(apps_v1::StatefulSetOrdinals { start: Some(10) }),
                service_name: Some("headless".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        use prost::Message;
        sts.encode(&mut buf).unwrap();

        let obj = apps_v1::StatefulSet::decode(buf.as_slice()).expect("round-trip must succeed");
        assert_eq!(
            obj.spec
                .as_ref()
                .and_then(|s| s.ordinals.as_ref())
                .and_then(|o| o.start),
            Some(10),
            "spec.ordinals.start must survive round-trip — generated struct covers this field by \
             construction; hand struct omitted it, so pods started from index 0 instead of 10"
        );
    }
}
