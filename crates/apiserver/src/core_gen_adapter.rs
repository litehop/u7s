use prost::Message;

use u7s_proto_generated::k8s::io::api::core::v1 as core_v1;
use u7s_proto_generated::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;
use u7s_proto_generated::k8s::io::apimachinery::pkg::util::intstr::IntOrString;

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
                if let Some(pc) = src.pod_certificate {
                    let mut pc_map = serde_json::Map::new();
                    if let Some(v) = pc.signer_name.filter(|s| !s.is_empty()) {
                        pc_map.insert("signerName".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(v) = pc.key_type.filter(|s| !s.is_empty()) {
                        pc_map.insert("keyType".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(v) = pc.max_expiration_seconds.filter(|&v| v != 0) {
                        pc_map.insert(
                            "maxExpirationSeconds".to_string(),
                            serde_json::Value::Number(v.into()),
                        );
                    }
                    if let Some(v) = pc.credential_bundle_path.filter(|s| !s.is_empty()) {
                        pc_map.insert(
                            "credentialBundlePath".to_string(),
                            serde_json::Value::String(v),
                        );
                    }
                    if let Some(v) = pc.key_path.filter(|s| !s.is_empty()) {
                        pc_map.insert("keyPath".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(v) = pc.certificate_chain_path.filter(|s| !s.is_empty()) {
                        pc_map.insert(
                            "certificateChainPath".to_string(),
                            serde_json::Value::String(v),
                        );
                    }
                    sm.insert(
                        "podCertificate".to_string(),
                        serde_json::Value::Object(pc_map),
                    );
                }
                if let Some(ctb) = src.cluster_trust_bundle {
                    let mut ctb_map = serde_json::Map::new();
                    if let Some(v) = ctb.name.filter(|s| !s.is_empty()) {
                        ctb_map.insert("name".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(v) = ctb.signer_name.filter(|s| !s.is_empty()) {
                        ctb_map.insert("signerName".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(sel) = ctb.label_selector {
                        ctb_map
                            .insert("labelSelector".to_string(), gen_label_selector_to_json(sel));
                    }
                    if let Some(true) = ctb.optional {
                        ctb_map.insert("optional".to_string(), serde_json::Value::Bool(true));
                    }
                    if let Some(v) = ctb.path.filter(|s| !s.is_empty()) {
                        ctb_map.insert("path".to_string(), serde_json::Value::String(v));
                    }
                    sm.insert(
                        "clusterTrustBundle".to_string(),
                        serde_json::Value::Object(ctb_map),
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

// The five VolumeSource plugin encoders below are called by `build/codegen.rs`'s generated
// `gen_volume_to_json` (see `volume_source_gen.rs`, included further down this file) rather than
// walked mechanically: each only emits its JSON key when a specific identifying sub-field
// survives (secretName / the embedded LocalObjectReference's name / claimName / driver /
// volumeClaimTemplate), a business rule the schema gives no signal for. Extracted verbatim from
// the inline closures the generated dispatcher replaces — no behaviour change.

fn gen_secret_volume_source_to_json(s: core_v1::SecretVolumeSource) -> Option<serde_json::Value> {
    let optional = s.optional;
    let secret_name = s.secret_name.filter(|s| !s.is_empty())?;
    let mut secret_map = serde_json::Map::new();
    secret_map.insert(
        "secretName".to_string(),
        serde_json::Value::String(secret_name),
    );
    if !s.items.is_empty() {
        secret_map.insert("items".to_string(), gen_key_to_path_to_json(s.items));
    }
    // See gen_downward_api_volume_source_to_json: omit rather than default to 420 when unset.
    if let Some(dm) = s.default_mode.filter(|&v| v != 0) {
        secret_map.insert(
            "defaultMode".to_string(),
            serde_json::Value::Number(dm.into()),
        );
    }
    if let Some(true) = optional {
        secret_map.insert("optional".to_string(), serde_json::Value::Bool(true));
    }
    Some(serde_json::Value::Object(secret_map))
}

fn gen_config_map_volume_source_to_json(
    cm: core_v1::ConfigMapVolumeSource,
) -> Option<serde_json::Value> {
    let optional = cm.optional;
    let name = cm
        .local_object_reference
        .and_then(|lor| lor.name)
        .filter(|s| !s.is_empty())?;
    let mut cm_map = serde_json::Map::new();
    cm_map.insert("name".to_string(), serde_json::Value::String(name));
    if !cm.items.is_empty() {
        cm_map.insert("items".to_string(), gen_key_to_path_to_json(cm.items));
    }
    // See gen_downward_api_volume_source_to_json: omit rather than default to 420 when unset.
    if let Some(dm) = cm.default_mode.filter(|&v| v != 0) {
        cm_map.insert(
            "defaultMode".to_string(),
            serde_json::Value::Number(dm.into()),
        );
    }
    if let Some(true) = optional {
        cm_map.insert("optional".to_string(), serde_json::Value::Bool(true));
    }
    Some(serde_json::Value::Object(cm_map))
}

fn gen_persistent_volume_claim_volume_source_to_json(
    pvc: core_v1::PersistentVolumeClaimVolumeSource,
) -> Option<serde_json::Value> {
    let claim_name = pvc.claim_name.filter(|s| !s.is_empty())?;
    let mut pvc_map = serde_json::Map::new();
    pvc_map.insert(
        "claimName".to_string(),
        serde_json::Value::String(claim_name),
    );
    if let Some(true) = pvc.read_only {
        pvc_map.insert("readOnly".to_string(), serde_json::Value::Bool(true));
    }
    Some(serde_json::Value::Object(pvc_map))
}

fn gen_ephemeral_volume_source_to_json(
    eph: core_v1::EphemeralVolumeSource,
) -> Option<serde_json::Value> {
    let tmpl = eph.volume_claim_template?;
    let claim = gen_persistent_volume_claim_to_json(core_v1::PersistentVolumeClaim {
        metadata: tmpl.metadata,
        spec: tmpl.spec,
        ..Default::default()
    });
    Some(serde_json::json!({ "volumeClaimTemplate": claim }))
}

fn gen_csi_volume_source_to_json(csi: core_v1::CsiVolumeSource) -> Option<serde_json::Value> {
    let driver = csi.driver.filter(|s| !s.is_empty())?;
    let mut csi_map = serde_json::Map::new();
    csi_map.insert("driver".to_string(), serde_json::Value::String(driver));
    if let Some(ro) = csi.read_only {
        csi_map.insert("readOnly".to_string(), serde_json::Value::Bool(ro));
    }
    if let Some(fs) = csi.fs_type.filter(|s| !s.is_empty()) {
        csi_map.insert("fsType".to_string(), serde_json::Value::String(fs));
    }
    if !csi.volume_attributes.is_empty() {
        let attrs: serde_json::Map<String, serde_json::Value> = csi
            .volume_attributes
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        csi_map.insert(
            "volumeAttributes".to_string(),
            serde_json::Value::Object(attrs),
        );
    }
    if let Some(lor) = csi.node_publish_secret_ref {
        if let Some(name) = lor.name.filter(|s| !s.is_empty()) {
            csi_map.insert(
                "nodePublishSecretRef".to_string(),
                serde_json::json!({ "name": name }),
            );
        }
    }
    Some(serde_json::Value::Object(csi_map))
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
    // httpHeaders — custom headers for auth-gated health checks (e.g. a bearer token or
    // signed request header the target expects). Dropping them makes a probe that relies on
    // one indistinguishable from an anonymous request, so the endpoint answers 401/403 and
    // the probe fails even though the container is healthy.
    if !http_get.http_headers.is_empty() {
        let headers: Vec<serde_json::Value> = http_get
            .http_headers
            .into_iter()
            .map(|h| {
                serde_json::json!({
                    "name": h.name.unwrap_or_default(),
                    "value": h.value.unwrap_or_default(),
                })
            })
            .collect();
        hg.insert("httpHeaders".to_string(), serde_json::Value::Array(headers));
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
    // stopSignal — a container-supplied custom stop signal; without it the runtime falls back
    // to its own default (usually SIGTERM), which can kill a process that only handles a
    // different signal for graceful shutdown instead of terminating cleanly.
    if let Some(v) = lc.stop_signal.filter(|s| !s.is_empty()) {
        m.insert("stopSignal".to_string(), serde_json::Value::String(v));
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

fn gen_selinux_options_to_json(o: core_v1::SeLinuxOptions) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = o.user.filter(|s| !s.is_empty()) {
        m.insert("user".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = o.role.filter(|s| !s.is_empty()) {
        m.insert("role".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = o.r#type.filter(|s| !s.is_empty()) {
        m.insert("type".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = o.level.filter(|s| !s.is_empty()) {
        m.insert("level".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

fn gen_windows_security_context_options_to_json(
    o: core_v1::WindowsSecurityContextOptions,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = o.gmsa_credential_spec_name.filter(|s| !s.is_empty()) {
        m.insert(
            "gmsaCredentialSpecName".to_string(),
            serde_json::Value::String(v),
        );
    }
    if let Some(v) = o.gmsa_credential_spec.filter(|s| !s.is_empty()) {
        m.insert(
            "gmsaCredentialSpec".to_string(),
            serde_json::Value::String(v),
        );
    }
    if let Some(v) = o.run_as_user_name.filter(|s| !s.is_empty()) {
        m.insert("runAsUserName".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = o.host_process {
        m.insert("hostProcess".to_string(), serde_json::Value::Bool(v));
    }
    serde_json::Value::Object(m)
}

fn gen_apparmor_profile_to_json(p: core_v1::AppArmorProfile) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = p.r#type.filter(|s| !s.is_empty()) {
        m.insert("type".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = p.localhost_profile.filter(|s| !s.is_empty()) {
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
/// seLinuxOptions/windowsOptions/procMount/appArmorProfile are hardening controls a client
/// believes it applied — dropping them silently lets the container run less confined than the
/// spec requested, with no error anywhere.
fn gen_security_context_to_json(sc: core_v1::SecurityContext) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(caps) = sc.capabilities {
        m.insert("capabilities".to_string(), gen_capabilities_to_json(caps));
    }
    if let Some(v) = sc.privileged {
        m.insert("privileged".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(o) = sc.se_linux_options {
        m.insert("seLinuxOptions".to_string(), gen_selinux_options_to_json(o));
    }
    if let Some(o) = sc.windows_options {
        m.insert(
            "windowsOptions".to_string(),
            gen_windows_security_context_options_to_json(o),
        );
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
    if let Some(v) = sc.proc_mount.filter(|s| !s.is_empty()) {
        m.insert("procMount".to_string(), serde_json::Value::String(v));
    }
    if let Some(sp) = sc.seccomp_profile {
        m.insert(
            "seccompProfile".to_string(),
            gen_seccomp_profile_to_json(sp),
        );
    }
    if let Some(p) = sc.app_armor_profile {
        m.insert(
            "appArmorProfile".to_string(),
            gen_apparmor_profile_to_json(p),
        );
    }
    serde_json::Value::Object(m)
}

/// Pod-level SecurityContext (PodSpec.securityContext, proto field 14), including sysctls.
///
/// Without this, pod.Spec.SecurityContext.RunAsUser/RunAsGroup are silently dropped for every
/// protobuf-created pod, and sysctls never reach validate_pod_sysctls or the kubelet — a pod
/// requesting `kernel.shm_rmid_forced=1` boots with the node default instead.
/// seLinuxOptions/windowsOptions/seLinuxChangePolicy/fsGroupChangePolicy/
/// supplementalGroupsPolicy are hardening controls a client believes it applied — dropping them
/// silently lets containers run less confined than the spec requested, with no error anywhere.
fn gen_pod_security_context_to_json(sc: core_v1::PodSecurityContext) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(o) = sc.se_linux_options {
        m.insert("seLinuxOptions".to_string(), gen_selinux_options_to_json(o));
    }
    if let Some(o) = sc.windows_options {
        m.insert(
            "windowsOptions".to_string(),
            gen_windows_security_context_options_to_json(o),
        );
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
    if let Some(v) = sc.supplemental_groups_policy.filter(|s| !s.is_empty()) {
        m.insert(
            "supplementalGroupsPolicy".to_string(),
            serde_json::Value::String(v),
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
    if let Some(v) = sc.fs_group_change_policy.filter(|s| !s.is_empty()) {
        m.insert(
            "fsGroupChangePolicy".to_string(),
            serde_json::Value::String(v),
        );
    }
    if let Some(sp) = sc.seccomp_profile {
        m.insert(
            "seccompProfile".to_string(),
            gen_seccomp_profile_to_json(sp),
        );
    }
    if let Some(p) = sc.app_armor_profile {
        m.insert(
            "appArmorProfile".to_string(),
            gen_apparmor_profile_to_json(p),
        );
    }
    if let Some(v) = sc.se_linux_change_policy.filter(|s| !s.is_empty()) {
        m.insert(
            "seLinuxChangePolicy".to_string(),
            serde_json::Value::String(v),
        );
    }
    serde_json::Value::Object(m)
}

/// Container.ports item encoder. Extracted so `build/codegen.rs`'s generated
/// `gen_container_to_json` can delegate the one field (`containerPort`/`hostPort` treat 0 as
/// unset, a business rule the schema gives no signal for) it can't derive mechanically.
fn gen_container_port_to_json(p: core_v1::ContainerPort) -> serde_json::Value {
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
}

/// EnvVar.valueFrom's union of reference kinds has no schema-derivable mapping (each variant
/// needs its own field-by-field JSON shape), so `build/codegen.rs`'s generated
/// `gen_container_to_json` delegates the whole `env` field here.
fn gen_env_var_to_json(ev: core_v1::EnvVar) -> serde_json::Value {
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
        // fileKeyRef (EnvFiles alpha feature) selects an env var from a file
        // mounted via another volume. Dropping it makes the container start with
        // that variable entirely unset instead of the value the file provided.
        if let Some(fkr) = vf.file_key_ref {
            let mut fkrm = serde_json::Map::new();
            if let Some(v) = fkr.volume_name.filter(|s| !s.is_empty()) {
                fkrm.insert("volumeName".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = fkr.path.filter(|s| !s.is_empty()) {
                fkrm.insert("path".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = fkr.key.filter(|s| !s.is_empty()) {
                fkrm.insert("key".to_string(), serde_json::Value::String(v));
            }
            if let Some(true) = fkr.optional {
                fkrm.insert("optional".to_string(), serde_json::Value::Bool(true));
            }
            vfm.insert("fileKeyRef".to_string(), serde_json::Value::Object(fkrm));
        }
        em.insert("valueFrom".to_string(), serde_json::Value::Object(vfm));
    }
    serde_json::Value::Object(em)
}

/// `build/codegen.rs`'s generated `gen_container_to_json` delegates the `envFrom` field here for
/// the same reason as `gen_env_var_to_json`: `ConfigMapEnvSource`/`SecretEnvSource` are
/// `INLINE_EMBEDS` (`LocalObjectReference`), not a mechanically-walkable nested message.
fn gen_env_from_source_to_json(ef: core_v1::EnvFromSource) -> serde_json::Value {
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
}

/// Container.volumeMounts item encoder. Extracted so `build/codegen.rs`'s generated
/// `gen_container_to_json` can delegate the one field (`readOnly` only ever emits `true` — see
/// `gen_pod_spec_to_json`'s `hostNetwork` for why a plain-value bool field needs this) it can't
/// derive mechanically.
fn gen_volume_mount_to_json(vm: core_v1::VolumeMount) -> serde_json::Value {
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
    if let Some(v) = vm.mount_propagation.filter(|s| !s.is_empty()) {
        m.insert("mountPropagation".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = vm.recursive_read_only.filter(|s| !s.is_empty()) {
        m.insert(
            "recursiveReadOnly".to_string(),
            serde_json::Value::String(v),
        );
    }
    serde_json::Value::Object(m)
}

// `gen_container_to_json`/`json_to_container_proto` are generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.Container` descriptor. They call the hand-written encoders above/decoders
// below for the handful of fields (env/envFrom/ports/volumeMounts/resources/probes/lifecycle/
// securityContext) whose JSON shape isn't a mechanical per-field walk — see
// `build/codegen.rs::container_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/container_gen.rs"));

// `gen_ephemeral_container_to_json`/`json_to_ephemeral_container_proto` are generated by
// `build/codegen.rs` from the `.k8s.io.api.core.v1.EphemeralContainerCommon` descriptor (mayor-
// nxr7j) — replacing a hand-written pair that had drifted to cover only 9 of its 24 fields,
// silently dropping stdin/stdinOnce/tty (and 14 others) from every protobuf-encoded `kubectl
// debug -it` ephemeral-container update. They share `container_gen.rs`'s delegation table (see
// `build/codegen.rs::container_delegated_field`) since `EphemeralContainerCommon` declares the
// exact same field set as `Container`.
include!(concat!(env!("OUT_DIR"), "/ephemeral_container_gen.rs"));

fn gen_node_selector_requirement_to_json(
    req: core_v1::NodeSelectorRequirement,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(k) = req.key.filter(|s| !s.is_empty()) {
        m.insert("key".to_string(), serde_json::Value::String(k));
    }
    if let Some(op) = req.operator.filter(|s| !s.is_empty()) {
        m.insert("operator".to_string(), serde_json::Value::String(op));
    }
    if !req.values.is_empty() {
        m.insert(
            "values".to_string(),
            serde_json::Value::Array(
                req.values
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_node_selector_term_to_json(term: core_v1::NodeSelectorTerm) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !term.match_expressions.is_empty() {
        m.insert(
            "matchExpressions".to_string(),
            serde_json::Value::Array(
                term.match_expressions
                    .into_iter()
                    .map(gen_node_selector_requirement_to_json)
                    .collect(),
            ),
        );
    }
    if !term.match_fields.is_empty() {
        m.insert(
            "matchFields".to_string(),
            serde_json::Value::Array(
                term.match_fields
                    .into_iter()
                    .map(gen_node_selector_requirement_to_json)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

/// Only `nodeAffinity` is decoded here — `podAffinity`/`podAntiAffinity` live in
/// `gen_pod_affinity_to_json`/`gen_pod_anti_affinity_to_json` below. crates/scheduler still does
/// not enforce pod (anti-)affinity, but the fields do round-trip.
fn gen_node_affinity_to_json(na: core_v1::NodeAffinity) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(req) = na.required_during_scheduling_ignored_during_execution {
        m.insert(
            "requiredDuringSchedulingIgnoredDuringExecution".to_string(),
            serde_json::json!({
                "nodeSelectorTerms": req
                    .node_selector_terms
                    .into_iter()
                    .map(gen_node_selector_term_to_json)
                    .collect::<Vec<_>>(),
            }),
        );
    }
    if !na
        .preferred_during_scheduling_ignored_during_execution
        .is_empty()
    {
        let preferred: Vec<serde_json::Value> = na
            .preferred_during_scheduling_ignored_during_execution
            .into_iter()
            .map(|p| {
                let mut pm = serde_json::Map::new();
                if let Some(w) = p.weight {
                    pm.insert("weight".to_string(), serde_json::Value::Number(w.into()));
                }
                if let Some(pref) = p.preference {
                    pm.insert(
                        "preference".to_string(),
                        gen_node_selector_term_to_json(pref),
                    );
                }
                serde_json::Value::Object(pm)
            })
            .collect();
        m.insert(
            "preferredDuringSchedulingIgnoredDuringExecution".to_string(),
            serde_json::Value::Array(preferred),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_pod_affinity_term_to_json(term: core_v1::PodAffinityTerm) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(sel) = term.label_selector {
        m.insert("labelSelector".to_string(), gen_label_selector_to_json(sel));
    }
    if !term.namespaces.is_empty() {
        m.insert(
            "namespaces".to_string(),
            serde_json::Value::Array(
                term.namespaces
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(v) = term.topology_key.filter(|s| !s.is_empty()) {
        m.insert("topologyKey".to_string(), serde_json::Value::String(v));
    }
    if let Some(sel) = term.namespace_selector {
        m.insert(
            "namespaceSelector".to_string(),
            gen_label_selector_to_json(sel),
        );
    }
    if !term.match_label_keys.is_empty() {
        m.insert(
            "matchLabelKeys".to_string(),
            serde_json::Value::Array(
                term.match_label_keys
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !term.mismatch_label_keys.is_empty() {
        m.insert(
            "mismatchLabelKeys".to_string(),
            serde_json::Value::Array(
                term.mismatch_label_keys
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

/// `PodAffinity` and `PodAntiAffinity` are structurally identical on the wire (the same two
/// fields, the same element types) — they only differ in which key they land under on the
/// parent `Affinity` object, so `gen_pod_affinity_to_json`/`gen_pod_anti_affinity_to_json` both
/// delegate here rather than duplicating the required/preferred handling twice.
fn gen_pod_affinity_terms_pair_to_json(
    required: Vec<core_v1::PodAffinityTerm>,
    preferred: Vec<core_v1::WeightedPodAffinityTerm>,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !required.is_empty() {
        m.insert(
            "requiredDuringSchedulingIgnoredDuringExecution".to_string(),
            serde_json::Value::Array(
                required
                    .into_iter()
                    .map(gen_pod_affinity_term_to_json)
                    .collect(),
            ),
        );
    }
    if !preferred.is_empty() {
        m.insert(
            "preferredDuringSchedulingIgnoredDuringExecution".to_string(),
            serde_json::Value::Array(
                preferred
                    .into_iter()
                    .map(|w| {
                        let mut wm = serde_json::Map::new();
                        if let Some(weight) = w.weight {
                            wm.insert(
                                "weight".to_string(),
                                serde_json::Value::Number(weight.into()),
                            );
                        }
                        if let Some(term) = w.pod_affinity_term {
                            wm.insert(
                                "podAffinityTerm".to_string(),
                                gen_pod_affinity_term_to_json(term),
                            );
                        }
                        serde_json::Value::Object(wm)
                    })
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_pod_affinity_to_json(pa: core_v1::PodAffinity) -> serde_json::Value {
    gen_pod_affinity_terms_pair_to_json(
        pa.required_during_scheduling_ignored_during_execution,
        pa.preferred_during_scheduling_ignored_during_execution,
    )
}

fn gen_pod_anti_affinity_to_json(paa: core_v1::PodAntiAffinity) -> serde_json::Value {
    gen_pod_affinity_terms_pair_to_json(
        paa.required_during_scheduling_ignored_during_execution,
        paa.preferred_during_scheduling_ignored_during_execution,
    )
}

pub(crate) fn gen_label_selector_requirement_to_json(
    req: meta_v1::LabelSelectorRequirement,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(k) = req.key.filter(|s| !s.is_empty()) {
        m.insert("key".to_string(), serde_json::Value::String(k));
    }
    if let Some(op) = req.operator.filter(|s| !s.is_empty()) {
        m.insert("operator".to_string(), serde_json::Value::String(op));
    }
    if !req.values.is_empty() {
        m.insert(
            "values".to_string(),
            serde_json::Value::Array(
                req.values
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

/// Used by topologySpreadConstraints.labelSelector. matchLabels-only decode would silently
/// drop a constraint expressed purely via matchExpressions (e.g. `key In [a,b]`), making the
/// scheduler treat the spread constraint as matching zero/all pods instead of the intended set.
pub(crate) fn gen_label_selector_to_json(sel: meta_v1::LabelSelector) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !sel.match_labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = sel
            .match_labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m.insert("matchLabels".to_string(), serde_json::Value::Object(labels));
    }
    if !sel.match_expressions.is_empty() {
        m.insert(
            "matchExpressions".to_string(),
            serde_json::Value::Array(
                sel.match_expressions
                    .into_iter()
                    .map(gen_label_selector_requirement_to_json)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

// `gen_pod_spec_to_json`/`json_to_pod_spec_proto` are generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.PodSpec` descriptor. They call the hand-written/generated encoders and
// decoders above/below for the fields (volumes, containers/initContainers, ephemeralContainers,
// affinity, securityContext, resources, activeDeadlineSeconds, hostNetwork, imagePullSecrets,
// readinessGates/schedulingGates, os, schedulingGroup) whose JSON shape isn't a mechanical
// per-field walk — see `build/codegen.rs::pod_spec_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/pod_spec_gen.rs"));

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

// `gen_object_reference_to_json`/`json_to_object_reference_proto` (the latter defined further
// down, near the other `json_to_*_proto` encoders) are generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.ObjectReference` descriptor rather than hand-written.
include!(concat!(env!("OUT_DIR"), "/object_reference_gen.rs"));

// `gen_volume_to_json`/`json_to_volume_proto` are generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.VolumeSource` descriptor (VolumeSource is INLINE_EMBEDS'd onto `Volume`,
// so both functions operate on the whole `Volume` JSON object rather than a nested
// "volumeSource" key). They call the hand-written `gen_*_volume_source_to_json`/
// `json_to_*_volume_source_proto` functions above/below for the handful of fields that need
// more than a mechanical per-field walk (see build/codegen.rs's DELEGATED_FIELDS doc).
include!(concat!(env!("OUT_DIR"), "/volume_source_gen.rs"));

/// Used by `PersistentVolumeClaimSpec.dataSource` — the clone-from-PVC / restore-from-
/// VolumeSnapshot pointer. Narrower than `ObjectReference`: dataSource always targets an
/// object in the claim's own namespace, so it only ever carries apiGroup/kind/name.
fn gen_typed_local_object_reference_to_json(
    r: core_v1::TypedLocalObjectReference,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = r.api_group.filter(|s| !s.is_empty()) {
        m.insert("apiGroup".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
        m.insert("kind".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

/// Used by `PersistentVolumeClaimSpec.dataSourceRef` — the cross-namespace-capable successor
/// to dataSource. Same apiGroup/kind/name as `TypedLocalObjectReference` plus `namespace`.
fn gen_typed_object_reference_to_json(r: core_v1::TypedObjectReference) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = r.api_group.filter(|s| !s.is_empty()) {
        m.insert("apiGroup".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
        m.insert("kind".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = r.namespace.filter(|s| !s.is_empty()) {
        m.insert("namespace".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

/// Used by `PersistentVolumeClaimStatus.modifyVolumeStatus` — the VAC modify controller's
/// in-progress-operation record: which VolumeAttributesClass it's reconciling toward and
/// whether that reconciliation is Pending/InProgress/Infeasible.
fn gen_modify_volume_status_to_json(s: core_v1::ModifyVolumeStatus) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = s
        .target_volume_attributes_class_name
        .filter(|s| !s.is_empty())
    {
        m.insert(
            "targetVolumeAttributesClassName".to_string(),
            serde_json::Value::String(v),
        );
    }
    if let Some(v) = s.status.filter(|s| !s.is_empty()) {
        m.insert("status".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

// ---- Decoder A: Namespace --------------------------------------------------

/// `NamespaceCondition`'s `type`/`status` are unconditionally emitted (even empty) — matching
/// upstream's non-`omitempty` JSON tags for those two fields specifically, the same reason
/// `gen_pod_condition_to_json` stays hand-written rather than a mechanical per-field walk — and
/// `lastTransitionTime` is a bare `metav1.Time` (RFC3339 string, only emitted once `seconds > 0`,
/// matching the Go zero-value-time convention every other condition type in this file uses).
///
/// This is also the PANIC-1 fix (`gen_namespace_status_to_json`'s `conditions` delegate is what
/// makes this function reachable at all from `decode_namespace_proto_gen`): before it existed,
/// `decode_namespace_proto_gen` never read `ns.status` at all, so any protobuf-encoded Namespace
/// write (Content-Type: application/vnd.kubernetes.protobuf) silently lost status.phase and
/// status.conditions together — put_namespace_status wholesale-replaces stored status with
/// whatever the decoder returns, which was nothing. This is exactly the "should apply changes to
/// a namespace status" conformance panic (namespace.go:365, `index out of range [-1]`): the
/// upstream e2e framework defaults EVERY typed clientset's ContentType to
/// application/vnd.kubernetes.protobuf (test/e2e/framework/test_context.go's
/// --kube-api-content-type flag, unset by our sonobuoy invocation), so
/// `f.ClientSet.CoreV1().Namespaces().UpdateStatus(...)` — the exact call the failing test makes
/// after appending a condition — sends protobuf and hits this code path. Verified live in a
/// worker session (2026-07-07, before this Phase 3.1 codegen migration): the real upstream
/// conformance spec, run via `sonobuoy --e2e-focus="should apply changes to a namespace status"`
/// against a build with the original hand-rolled fix, passed twice in a row (~0.02s, no panic);
/// see `namespace_status_proto_decode_preserves_phase_and_conditions` for the byte-level
/// regression test that pins this behavior across the hand-rolled -> generated migration.
fn gen_namespace_condition_to_json(c: core_v1::NamespaceCondition) -> serde_json::Value {
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
    if let Some(secs) = c
        .last_transition_time
        .and_then(|t| t.seconds)
        .filter(|&s| s > 0)
    {
        cond["lastTransitionTime"] = serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
    }
    cond
}

// `gen_namespace_status_to_json` is generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.NamespaceStatus` descriptor. It calls the hand-written
// `gen_namespace_condition_to_json` above for `conditions` — see
// `build/codegen.rs::namespace_status_delegated_field` for why that field can't be a mechanical
// per-field walk.
include!(concat!(env!("OUT_DIR"), "/namespace_status_gen.rs"));

// `gen_namespace_to_json` is generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.Namespace` descriptor. `metadata` delegates to the hand-written
// `gen_object_meta_to_json` and `status` delegates to `gen_namespace_status_to_json` above — see
// `build/codegen.rs::namespace_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/namespace_gen.rs"));

pub fn decode_namespace_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let ns = core_v1::Namespace::decode(data).ok()?;
    let mut obj = gen_namespace_to_json(ns);
    obj["apiVersion"] = "v1".into();
    obj["kind"] = "Namespace".into();
    Some(obj)
}

// ---- Decoder A: ConfigMap --------------------------------------------------

// `gen_configmap_to_json` is generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.ConfigMap` descriptor — `metadata` delegates to the hand-written
// `gen_object_meta_to_json` and `binaryData` (a `map<string, bytes>`) delegates to an inline
// base64 encode; see `build/codegen.rs::configmap_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/configmap_gen.rs"));

pub fn decode_configmap_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let cm = core_v1::ConfigMap::decode(data).ok()?;
    let mut obj = gen_configmap_to_json(cm);
    obj["apiVersion"] = "v1".into();
    obj["kind"] = "ConfigMap".into();
    Some(obj)
}

// ---- Decoder A: Pod --------------------------------------------------------

/// `ResourceRequirements` as it appears inside `PodStatus`/`ContainerStatus` (pod- and
/// container-level resize/DRA reporting), not the incomplete inline handling used for
/// `PodSpec`/`Container` elsewhere in this file.
fn gen_resource_requirements_to_json(res: core_v1::ResourceRequirements) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !res.limits.is_empty() {
        m.insert("limits".to_string(), gen_quantity_map_to_json(res.limits));
    }
    if !res.requests.is_empty() {
        m.insert(
            "requests".to_string(),
            gen_quantity_map_to_json(res.requests),
        );
    }
    if !res.claims.is_empty() {
        let claims: Vec<serde_json::Value> = res
            .claims
            .into_iter()
            .map(|c| {
                let mut cm = serde_json::Map::new();
                if let Some(v) = c.name.filter(|s| !s.is_empty()) {
                    cm.insert("name".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = c.request.filter(|s| !s.is_empty()) {
                    cm.insert("request".to_string(), serde_json::Value::String(v));
                }
                serde_json::Value::Object(cm)
            })
            .collect();
        m.insert("claims".to_string(), serde_json::Value::Array(claims));
    }
    serde_json::Value::Object(m)
}

fn gen_container_state_to_json(state: core_v1::ContainerState) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(w) = state.waiting {
        let mut wm = serde_json::Map::new();
        if let Some(v) = w.reason.filter(|s| !s.is_empty()) {
            wm.insert("reason".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = w.message.filter(|s| !s.is_empty()) {
            wm.insert("message".to_string(), serde_json::Value::String(v));
        }
        m.insert("waiting".to_string(), serde_json::Value::Object(wm));
    }
    if let Some(r) = state.running {
        let mut rm = serde_json::Map::new();
        if let Some(secs) = r.started_at.and_then(|t| t.seconds) {
            rm.insert(
                "startedAt".to_string(),
                serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
            );
        }
        m.insert("running".to_string(), serde_json::Value::Object(rm));
    }
    if let Some(t) = state.terminated {
        let mut tm = serde_json::Map::new();
        tm.insert(
            "exitCode".to_string(),
            serde_json::Value::Number(t.exit_code.unwrap_or(0).into()),
        );
        if let Some(v) = t.signal.filter(|&v| v != 0) {
            tm.insert("signal".to_string(), serde_json::Value::Number(v.into()));
        }
        if let Some(v) = t.reason.filter(|s| !s.is_empty()) {
            tm.insert("reason".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = t.message.filter(|s| !s.is_empty()) {
            tm.insert("message".to_string(), serde_json::Value::String(v));
        }
        if let Some(secs) = t.started_at.and_then(|ts| ts.seconds) {
            tm.insert(
                "startedAt".to_string(),
                serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
            );
        }
        if let Some(secs) = t.finished_at.and_then(|ts| ts.seconds) {
            tm.insert(
                "finishedAt".to_string(),
                serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
            );
        }
        if let Some(v) = t.container_id.filter(|s| !s.is_empty()) {
            tm.insert("containerID".to_string(), serde_json::Value::String(v));
        }
        m.insert("terminated".to_string(), serde_json::Value::Object(tm));
    }
    serde_json::Value::Object(m)
}

/// ContainerStatus.user's Linux identity sub-object has no schema-derivable mapping distinct
/// from a mechanical walk of `ContainerUser`/`LinuxContainerUser` themselves (upstream flattens
/// nothing here) — it's delegated purely because the field is only ever emitted when
/// `linux` is present, dropping the `user` key entirely otherwise, which
/// `build/codegen.rs`'s generated `gen_container_status_to_json` expresses via this `Option`
/// return rather than a mechanical nested-message walk.
fn gen_container_user_to_json(user: core_v1::ContainerUser) -> Option<serde_json::Value> {
    let linux = user.linux?;
    let mut lm = serde_json::Map::new();
    if let Some(v) = linux.uid {
        lm.insert("uid".to_string(), serde_json::Value::Number(v.into()));
    }
    if let Some(v) = linux.gid {
        lm.insert("gid".to_string(), serde_json::Value::Number(v.into()));
    }
    if !linux.supplemental_groups.is_empty() {
        lm.insert(
            "supplementalGroups".to_string(),
            serde_json::Value::Array(
                linux
                    .supplemental_groups
                    .into_iter()
                    .map(|g| serde_json::Value::Number(g.into()))
                    .collect(),
            ),
        );
    }
    Some(serde_json::json!({ "linux": lm }))
}

// `gen_container_status_to_json`/`json_to_container_status_proto` are generated by
// `build/codegen.rs` from the `.k8s.io.api.core.v1.ContainerStatus` descriptor. They call the
// hand-written/generated encoders and decoders above/below for the fields (state/lastState,
// ready/restartCount's plain-value unconditional emission, resources, user) whose JSON shape
// isn't a mechanical per-field walk — see `build/codegen.rs::container_status_delegated_field`.
//
// Missing this subtree (as `gen_pod_status_to_json`'s hand-rolled predecessor once did) is what
// makes a whole-array omission catastrophic rather than merely incomplete: `replace_pod_status`
// replaces the stored `status` subtree wholesale with the decoder's output, so a
// `containerStatuses` entry that never reaches JSON here means `kubectl get pods`
// READY/RESTARTS falls back to the spec container count and crash-loop/exec/log tooling that
// reads `state`/`containerID` sees nothing.
include!(concat!(env!("OUT_DIR"), "/container_status_gen.rs"));

/// PodCondition's `type`/`status` are unconditionally emitted (even empty) rather than gated on
/// `Option::is_some` like every other field here — matching upstream's non-`omitempty` JSON tags
/// for those two fields specifically — which is why this stays a hand-written delegate rather
/// than a mechanical per-field walk (the schema gives no signal for "always emit this one, but
/// not that one"). `lastTransitionTime`/`lastProbeTime` are `metav1.Time` (RFC3339 string, not
/// the `{seconds, nanos}` wire shape), the same opaque-scalar handling `emit_field_encode` already
/// gives `Quantity`.
fn gen_pod_condition_to_json(c: core_v1::PodCondition) -> serde_json::Value {
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
        cond["lastTransitionTime"] = serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
    }
    if let Some(secs) = c.last_probe_time.and_then(|t| t.seconds) {
        cond["lastProbeTime"] = serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
    }
    if let Some(v) = c.observed_generation.filter(|&v| v != 0) {
        cond["observedGeneration"] = v.into();
    }
    cond
}

// `gen_pod_status_to_json`/`json_to_pod_status_proto` are generated by `build/codegen.rs` from
// the `.k8s.io.api.core.v1.PodStatus` descriptor. They call the hand-written/generated encoders
// and decoders above/below for the fields (observedGeneration's non-zero guard, conditions,
// hostIPs/podIPs, startTime, container/init/ephemeral statuses, resources) whose JSON shape
// isn't a mechanical per-field walk — see `build/codegen.rs::pod_status_delegated_field`.
//
// A protobuf-encoded write to the `/status` subresource (e.g. client-go typed clients'
// `UpdateStatus`, which defaults to protobuf content-type) carries the full `PodStatus`
// on the wire. Before this was schema-driven, `decode_pod_proto_gen` silently dropped `.status`
// entirely, so `replace_pod_status` treated the incoming status as absent and overwrote the
// stored status with `null` — a protobuf PUT to a pod's status subresource wiped the pod's
// phase, conditions and IPs instead of replacing them with the caller's values.
//
// `containerStatuses`/`initContainerStatuses`/`ephemeralContainerStatuses` and the DRA
// resource-claim-status fields were themselves missing in exactly the same way: since
// `replace_pod_status` replaces the whole stored `status` subtree with this function's output
// rather than merging into it, an omitted array does not just fail to update — it deletes
// whatever the stored pod already had.
include!(concat!(env!("OUT_DIR"), "/pod_status_gen.rs"));

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

/// `ServiceSpec.sessionAffinityConfig`'s `clientIP.timeoutSeconds` is zero-filtered on encode —
/// a genuinely-0-second timeout is indistinguishable from unset on the wire, the same reasoning
/// `gen_container_image_to_json`'s `sizeBytes` guard documents — so the whole field is
/// delegated wholesale rather than walked mechanically. Used by `gen_service_spec_to_json`'s
/// `sessionAffinityConfig` delegate; see `build/codegen.rs::service_spec_delegated_field`.
fn gen_session_affinity_config_to_json(sac: core_v1::SessionAffinityConfig) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = sac
        .client_ip
        .and_then(|c| c.timeout_seconds)
        .filter(|&v| v != 0)
    {
        m.insert(
            "clientIP".to_string(),
            serde_json::json!({ "timeoutSeconds": v }),
        );
    }
    serde_json::Value::Object(m)
}

fn json_to_session_affinity_config_proto(v: &serde_json::Value) -> core_v1::SessionAffinityConfig {
    core_v1::SessionAffinityConfig {
        client_ip: v.get("clientIP").map(|c| core_v1::ClientIpConfig {
            timeout_seconds: ji32(c, "timeoutSeconds"),
        }),
    }
}

/// `ServicePort.port`/`.nodePort` are zero-filtered on encode — a genuinely-0 port number is
/// invalid per the Kubernetes API and indistinguishable from unset on the wire, the same
/// reasoning `gen_container_image_to_json`'s `sizeBytes` guard documents — so `ports` is
/// delegated wholesale rather than walked mechanically. Used by `gen_service_spec_to_json`'s
/// `ports` delegate; see `build/codegen.rs::service_spec_delegated_field`.
fn gen_service_port_to_json(p: core_v1::ServicePort) -> serde_json::Value {
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
}

fn json_to_service_port_proto(v: &serde_json::Value) -> core_v1::ServicePort {
    core_v1::ServicePort {
        name: jstr(v, "name"),
        protocol: jstr(v, "protocol"),
        app_protocol: jstr(v, "appProtocol"),
        port: ji32(v, "port"),
        target_port: v.get("targetPort").map(json_to_int_or_string_proto),
        node_port: ji32(v, "nodePort"),
    }
}

// `gen_service_spec_to_json`/`json_to_service_spec_proto` are generated by `build/codegen.rs`
// from the `.k8s.io.api.core.v1.ServiceSpec` descriptor — `ports`/`healthCheckNodePort`/
// `sessionAffinityConfig` delegate to the hand-written helpers above; see
// `build/codegen.rs::service_spec_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/service_spec_gen.rs"));

/// `LoadBalancerIngress.ports[].port` is zero-filtered on encode, the same reasoning
/// `gen_service_port_to_json`'s own `port`/`nodePort` guard documents. Used by
/// `gen_load_balancer_status_to_json`'s per-ingress `ports` assembly.
fn gen_port_status_to_json(p: core_v1::PortStatus) -> serde_json::Value {
    let mut pm = serde_json::Map::new();
    if let Some(v) = p.port.filter(|&n| n != 0) {
        pm.insert("port".to_string(), serde_json::Value::Number(v.into()));
    }
    if let Some(v) = p.protocol.filter(|s| !s.is_empty()) {
        pm.insert("protocol".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = p.error.filter(|s| !s.is_empty()) {
        pm.insert("error".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(pm)
}

fn json_to_port_status_proto(v: &serde_json::Value) -> core_v1::PortStatus {
    core_v1::PortStatus {
        port: ji32(v, "port"),
        protocol: jstr(v, "protocol"),
        error: jstr(v, "error"),
    }
}

/// `LoadBalancerIngress.ports[].port` is zero-filtered two levels below `ServiceStatus` itself
/// — past the mechanical codegen walker's one-level override hook — so the whole `loadBalancer`
/// field is delegated wholesale rather than walked mechanically. Used by
/// `gen_service_status_to_json`'s `loadBalancer` delegate; see
/// `build/codegen.rs::service_status_delegated_field`.
fn gen_load_balancer_status_to_json(lb: core_v1::LoadBalancerStatus) -> serde_json::Value {
    if lb.ingress.is_empty() {
        return serde_json::Value::Object(serde_json::Map::new());
    }
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
            if let Some(v) = i.ip_mode.filter(|s| !s.is_empty()) {
                im.insert("ipMode".to_string(), serde_json::Value::String(v));
            }
            if !i.ports.is_empty() {
                let ports: Vec<serde_json::Value> =
                    i.ports.into_iter().map(gen_port_status_to_json).collect();
                im.insert("ports".to_string(), serde_json::Value::Array(ports));
            }
            serde_json::Value::Object(im)
        })
        .collect();
    serde_json::json!({ "ingress": ingress })
}

fn json_to_load_balancer_status_proto(v: &serde_json::Value) -> core_v1::LoadBalancerStatus {
    core_v1::LoadBalancerStatus {
        ingress: v
            .get("ingress")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .map(|i| core_v1::LoadBalancerIngress {
                        ip: jstr(i, "ip"),
                        hostname: jstr(i, "hostname"),
                        ip_mode: jstr(i, "ipMode"),
                        ports: i
                            .get("ports")
                            .and_then(|a| a.as_array())
                            .map(|a| a.iter().map(json_to_port_status_proto).collect())
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// `Condition.type`/`.status` are unconditionally emitted (matching upstream's non-`omitempty`
/// JSON tags), the same class of override `gen_namespace_condition_to_json` documents at
/// length; `observedGeneration` is zero-filtered. This is the generic
/// `k8s.io.apimachinery.pkg.apis.meta.v1.Condition`, not a resource-specific condition type —
/// `ServiceStatus.conditions` is the only core/v1 user of it. Used by
/// `gen_service_status_to_json`'s `conditions` delegate; see
/// `build/codegen.rs::service_status_delegated_field`.
fn gen_meta_condition_to_json(c: meta_v1::Condition) -> serde_json::Value {
    let mut cond = serde_json::json!({
        "type": c.r#type.unwrap_or_default(),
        "status": c.status.unwrap_or_default(),
    });
    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
        cond["reason"] = v.into();
    }
    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
        cond["message"] = v.into();
    }
    if let Some(v) = c.observed_generation.filter(|&v| v != 0) {
        cond["observedGeneration"] = v.into();
    }
    if let Some(secs) = c
        .last_transition_time
        .and_then(|t| t.seconds)
        .filter(|&s| s > 0)
    {
        cond["lastTransitionTime"] = serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
    }
    cond
}

fn json_to_meta_condition_proto(v: &serde_json::Value) -> meta_v1::Condition {
    meta_v1::Condition {
        r#type: jstr(v, "type"),
        status: jstr(v, "status"),
        observed_generation: ji64(v, "observedGeneration"),
        last_transition_time: jtime(v, "lastTransitionTime"),
        reason: jstr(v, "reason"),
        message: jstr(v, "message"),
    }
}

// `gen_service_status_to_json`/`json_to_service_status_proto` are generated by
// `build/codegen.rs` from the `.k8s.io.api.core.v1.ServiceStatus` descriptor — `loadBalancer`/
// `conditions` delegate to the hand-written helpers above; see
// `build/codegen.rs::service_status_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/service_status_gen.rs"));

// `gen_service_to_json`/`json_to_service_proto` are generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.Service` descriptor — `metadata` delegates to the hand-written
// `gen_object_meta_to_json` and `spec`/`status` delegate to the separately generated
// `gen_service_spec_to_json`/`gen_service_status_to_json` above; see
// `build/codegen.rs::service_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/service_gen.rs"));

pub fn decode_service_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let svc = core_v1::Service::decode(data).ok()?;
    let mut obj = gen_service_to_json(svc);
    obj["apiVersion"] = "v1".into();
    obj["kind"] = "Service".into();
    Some(obj)
}

// ---- Decoder A: Secret -----------------------------------------------------

// `gen_secret_to_json` is generated by `build/codegen.rs` from the `.k8s.io.api.core.v1.Secret`
// descriptor — `metadata` delegates to the hand-written `gen_object_meta_to_json` and `data` (a
// `map<string, bytes>`) delegates to an inline base64 encode; see
// `build/codegen.rs::secret_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/secret_gen.rs"));

pub fn decode_secret_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let secret = core_v1::Secret::decode(data).ok()?;
    let mut obj = gen_secret_to_json(secret);
    obj["apiVersion"] = "v1".into();
    obj["kind"] = "Secret".into();
    Some(obj)
}

// ---- Decoder A: Node -------------------------------------------------------

/// The kubelet (and any other typed client's `Nodes().UpdateStatus(...)`) PUTs the full Node
/// using protobuf content-type by default, carrying the full `NodeStatus` on the wire. The
/// generated `gen_node_status_to_json`/`json_to_node_status_proto` pair below (see
/// `build/codegen.rs::generate_node_status`) is what makes `.status` (phase, conditions —
/// Ready/MemoryPressure/DiskPressure/PIDPressure —, addresses, capacity, allocatable and
/// nodeInfo, on which all sig-node conformance depends) survive a decode at all.
fn gen_node_config_source_to_json(cs: core_v1::NodeConfigSource) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(cm) = cs.config_map {
        let mut cm_json = serde_json::Map::new();
        if let Some(v) = cm.namespace.filter(|s| !s.is_empty()) {
            cm_json.insert("namespace".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = cm.name.filter(|s| !s.is_empty()) {
            cm_json.insert("name".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = cm.uid.filter(|s| !s.is_empty()) {
            cm_json.insert("uid".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = cm.resource_version.filter(|s| !s.is_empty()) {
            cm_json.insert("resourceVersion".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = cm.kubelet_config_key.filter(|s| !s.is_empty()) {
            cm_json.insert("kubeletConfigKey".to_string(), serde_json::Value::String(v));
        }
        m.insert("configMap".to_string(), serde_json::Value::Object(cm_json));
    }
    serde_json::Value::Object(m)
}

fn json_to_node_config_source_proto(v: &serde_json::Value) -> core_v1::NodeConfigSource {
    core_v1::NodeConfigSource {
        config_map: v
            .get("configMap")
            .map(|cm| core_v1::ConfigMapNodeConfigSource {
                namespace: jstr(cm, "namespace"),
                name: jstr(cm, "name"),
                uid: jstr(cm, "uid"),
                resource_version: jstr(cm, "resourceVersion"),
                kubelet_config_key: jstr(cm, "kubeletConfigKey"),
            }),
    }
}

fn gen_node_config_status_to_json(cs: core_v1::NodeConfigStatus) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = cs.assigned {
        m.insert("assigned".to_string(), gen_node_config_source_to_json(v));
    }
    if let Some(v) = cs.active {
        m.insert("active".to_string(), gen_node_config_source_to_json(v));
    }
    if let Some(v) = cs.last_known_good {
        m.insert(
            "lastKnownGood".to_string(),
            gen_node_config_source_to_json(v),
        );
    }
    if let Some(v) = cs.error.filter(|s| !s.is_empty()) {
        m.insert("error".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

fn json_to_node_config_status_proto(v: &serde_json::Value) -> core_v1::NodeConfigStatus {
    core_v1::NodeConfigStatus {
        assigned: v.get("assigned").map(json_to_node_config_source_proto),
        active: v.get("active").map(json_to_node_config_source_proto),
        last_known_good: v.get("lastKnownGood").map(json_to_node_config_source_proto),
        error: jstr(v, "error"),
    }
}

/// `NodeCondition.type`/`.status` are unconditionally emitted (matching upstream's non-
/// `omitempty` JSON tags), the same class of override `gen_namespace_condition_to_json`
/// documents at length. Used by `gen_node_status_to_json`'s `conditions` delegate; see
/// `build/codegen.rs::node_status_delegated_field`.
fn gen_node_condition_to_json(c: core_v1::NodeCondition) -> serde_json::Value {
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
        cond["lastHeartbeatTime"] = serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
    }
    if let Some(secs) = c.last_transition_time.and_then(|t| t.seconds) {
        cond["lastTransitionTime"] = serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
    }
    cond
}

fn json_to_node_condition_proto(v: &serde_json::Value) -> core_v1::NodeCondition {
    core_v1::NodeCondition {
        r#type: jstr(v, "type"),
        status: jstr(v, "status"),
        last_heartbeat_time: jtime(v, "lastHeartbeatTime"),
        last_transition_time: jtime(v, "lastTransitionTime"),
        reason: jstr(v, "reason"),
        message: jstr(v, "message"),
    }
}

/// `NodeAddress.type`/`.address` are both unconditionally emitted (matching upstream's non-
/// `omitempty` JSON tags on both fields). Used by `gen_node_status_to_json`'s `addresses`
/// delegate; see `build/codegen.rs::node_status_delegated_field`.
fn gen_node_address_to_json(a: core_v1::NodeAddress) -> serde_json::Value {
    serde_json::json!({
        "type": a.r#type.unwrap_or_default(),
        "address": a.address.unwrap_or_default(),
    })
}

fn json_to_node_address_proto(v: &serde_json::Value) -> core_v1::NodeAddress {
    core_v1::NodeAddress {
        r#type: jstr(v, "type"),
        address: jstr(v, "address"),
    }
}

/// `swap.capacity` is zero-filtered on encode — a node genuinely reporting 0 bytes of swap is
/// indistinguishable on the wire from one that never set `swap` at all, so this keeps the
/// pre-migration decoder's behavior rather than emitting `"swap": {"capacity": 0}`. Used by
/// `gen_node_status_to_json`'s `nodeInfo` delegate; see
/// `build/codegen.rs::node_status_delegated_field`.
fn gen_node_system_info_to_json(info: core_v1::NodeSystemInfo) -> serde_json::Value {
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
    if let Some(v) = info.swap.and_then(|s| s.capacity).filter(|&c| c != 0) {
        ni.insert("swap".to_string(), serde_json::json!({ "capacity": v }));
    }
    serde_json::Value::Object(ni)
}

fn json_to_node_system_info_proto(v: &serde_json::Value) -> core_v1::NodeSystemInfo {
    core_v1::NodeSystemInfo {
        machine_id: jstr(v, "machineID"),
        system_uuid: jstr(v, "systemUUID"),
        boot_id: jstr(v, "bootID"),
        kernel_version: jstr(v, "kernelVersion"),
        os_image: jstr(v, "osImage"),
        container_runtime_version: jstr(v, "containerRuntimeVersion"),
        kubelet_version: jstr(v, "kubeletVersion"),
        kube_proxy_version: jstr(v, "kubeProxyVersion"),
        operating_system: jstr(v, "operatingSystem"),
        architecture: jstr(v, "architecture"),
        ..Default::default()
    }
}

/// `sizeBytes` is zero-filtered on encode (a genuinely-0-byte image is indistinguishable from an
/// unset one on the wire, the same reasoning as `gen_node_system_info_to_json`'s `swap.capacity`
/// guard). Used by `gen_node_status_to_json`'s `images` delegate; see
/// `build/codegen.rs::node_status_delegated_field`.
fn gen_container_image_to_json(img: core_v1::ContainerImage) -> serde_json::Value {
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
}

fn json_to_container_image_proto(v: &serde_json::Value) -> core_v1::ContainerImage {
    core_v1::ContainerImage {
        names: jstrs(v, "names"),
        size_bytes: ji64(v, "sizeBytes"),
    }
}

/// `AttachedVolume.name`/`.devicePath` are both unconditionally emitted (matching upstream's
/// non-`omitempty` JSON tags on both fields). Used by `gen_node_status_to_json`'s
/// `volumesAttached` delegate; see `build/codegen.rs::node_status_delegated_field`.
fn gen_attached_volume_to_json(v: core_v1::AttachedVolume) -> serde_json::Value {
    serde_json::json!({
        "name": v.name.unwrap_or_default(),
        "devicePath": v.device_path.unwrap_or_default(),
    })
}

fn json_to_attached_volume_proto(v: &serde_json::Value) -> core_v1::AttachedVolume {
    core_v1::AttachedVolume {
        name: jstr(v, "name"),
        device_path: jstr(v, "devicePath"),
    }
}

// `gen_node_status_to_json`/`json_to_node_status_proto` are generated by `build/codegen.rs` from
// the `.k8s.io.api.core.v1.NodeStatus` descriptor — `conditions`/`addresses`/`nodeInfo`/`images`/
// `volumesAttached`/`config` delegate to the hand-written helpers above; see
// `build/codegen.rs::node_status_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/node_status_gen.rs"));

fn gen_taint_to_json(t: core_v1::Taint) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "key".to_string(),
        serde_json::Value::String(t.key.unwrap_or_default()),
    );
    if let Some(v) = t.value.filter(|s| !s.is_empty()) {
        m.insert("value".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = t.effect.filter(|s| !s.is_empty()) {
        m.insert("effect".to_string(), serde_json::Value::String(v));
    }
    if let Some(ts) = t.time_added {
        if let Some(secs) = ts.seconds.filter(|&s| s > 0) {
            m.insert(
                "timeAdded".to_string(),
                serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
            );
        }
    }
    serde_json::Value::Object(m)
}

fn gen_taints_to_json(ts: Vec<core_v1::Taint>) -> serde_json::Value {
    serde_json::Value::Array(ts.into_iter().map(gen_taint_to_json).collect())
}

fn json_to_taint_proto(v: &serde_json::Value) -> core_v1::Taint {
    core_v1::Taint {
        key: jstr(v, "key"),
        value: jstr(v, "value"),
        effect: jstr(v, "effect"),
        time_added: jtime(v, "timeAdded"),
    }
}

// `gen_node_spec_to_json`/`json_to_node_spec_proto` are generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.NodeSpec` descriptor — `taints`/`configSource` delegate to the
// hand-written helpers above; see `build/codegen.rs::node_spec_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/node_spec_gen.rs"));

// `gen_node_to_json`/`json_to_node_proto` are generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.Node` descriptor; see `build/codegen.rs::node_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/node_gen.rs"));

pub fn decode_node_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let node = core_v1::Node::decode(data).ok()?;
    let mut obj = gen_node_to_json(node);
    obj["apiVersion"] = "v1".into();
    obj["kind"] = "Node".into();
    Some(obj)
}

// ---- Decoder A: PersistentVolume -------------------------------------------
//
// `gen_persistentvolume_spec_to_json`/`gen_persistentvolume_status_to_json`/
// `gen_persistentvolume_to_json` are generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.PersistentVolumeSpec`/`PersistentVolumeStatus`/`PersistentVolume`
// descriptors. `capacity` drives kube-controller-manager's static PV/PVC matching
// (findBestMatchForClaim compares requested size against volume.Spec.Capacity): without it,
// every PV looks like it has zero capacity and is skipped as "too small" for any claim, so the
// claim falls through to dynamic provisioning and fails with "storageclass ... not found" even
// though a matching PV exists. `claimRef` is how a test pre-binds a PV to a not-yet-created PVC
// by name; without it, kube-controller-manager sees the PV as unclaimed and routes the PVC
// through normal (capacity/class) matching instead of completing the pre-bind. `nodeAffinity` is
// required for local volumes: it is how kubelet learns which node may mount this PV. `local`/
// `hostPath`/`nfs`/`csi` are the only `persistentVolumeSource` volume plugins with a live
// consumer — `csi` in particular is how every CSI driver (e.g. csi-hostpath, the
// conformance-suite's dynamic-provisioning exemplar) backs a PersistentVolume; without it, the
// stored PV round-trips with no volume source at all, and kubelet's volume plugin manager
// rejects the pod with "no volume plugin matched" even though the PVC is already genuinely
// Bound. See `build/codegen.rs::generate_persistentvolume_spec`'s doc for the excluded-plugin
// policy and `persistentvolume_spec_delegated_field`/`persistentvolume_status_delegated_field`
// for the per-field overrides (`claimRef`/`nodeAffinity`/`lastPhaseTransitionTime`).
include!(concat!(env!("OUT_DIR"), "/persistentvolume_spec_gen.rs"));
include!(concat!(env!("OUT_DIR"), "/persistentvolume_status_gen.rs"));
include!(concat!(env!("OUT_DIR"), "/persistentvolume_gen.rs"));

pub fn decode_persistentvolume_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let pv = core_v1::PersistentVolume::decode(data).ok()?;
    let mut obj = gen_persistentvolume_to_json(pv);
    obj["apiVersion"] = "v1".into();
    obj["kind"] = "PersistentVolume".into();
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
                let name = r.name.filter(|s| !s.is_empty())?;
                let mut m = serde_json::json!({ "name": name });
                // kind/namespace/uid/apiVersion/resourceVersion are real ObjectReference fields
                // a client is entitled to set on a secrets[] entry (matching every other
                // ObjectReference decoder in this codebase, e.g.
                // net_disc_cert_policy_events_gen_adapter's gen_object_reference_to_json) —
                // dropping them would silently corrupt a GET-modify-PUT round trip.
                if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
                    m["kind"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.namespace.filter(|s| !s.is_empty()) {
                    m["namespace"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.uid.filter(|s| !s.is_empty()) {
                    m["uid"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.api_version.filter(|s| !s.is_empty()) {
                    m["apiVersion"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.resource_version.filter(|s| !s.is_empty()) {
                    m["resourceVersion"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.field_path.filter(|s| !s.is_empty()) {
                    m["fieldPath"] = serde_json::Value::String(v);
                }
                Some(m)
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

/// `PersistentVolumeClaimCondition.type`/`.status` are unconditionally emitted (matching
/// upstream's non-`omitempty` JSON tags), the same class of override
/// `gen_namespace_condition_to_json` documents at length. Used by
/// `gen_persistentvolumeclaim_status_to_json`'s `conditions` delegate; see
/// `build/codegen.rs::persistentvolumeclaim_status_delegated_field`.
fn gen_persistentvolumeclaim_condition_to_json(
    c: core_v1::PersistentVolumeClaimCondition,
) -> serde_json::Value {
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
    if let Some(secs) = c.last_probe_time.and_then(|t| t.seconds) {
        cond["lastProbeTime"] = serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
    }
    if let Some(secs) = c.last_transition_time.and_then(|t| t.seconds) {
        cond["lastTransitionTime"] = serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
    }
    cond
}

// `gen_persistentvolumeclaim_spec_to_json`/`gen_persistentvolumeclaim_status_to_json` are
// generated by `build/codegen.rs` from the `.k8s.io.api.core.v1.PersistentVolumeClaimSpec`/
// `PersistentVolumeClaimStatus` descriptors — `selector`/`storageClassName`/`dataSource`/
// `dataSourceRef`/`volumeAttributesClassName` delegate to hand-written helpers (see
// `persistentvolumeclaim_spec_delegated_field`'s doc) and `conditions`/`modifyVolumeStatus`
// likewise (see `persistentvolumeclaim_status_delegated_field`'s doc).
include!(concat!(
    env!("OUT_DIR"),
    "/persistentvolumeclaim_spec_gen.rs"
));
include!(concat!(
    env!("OUT_DIR"),
    "/persistentvolumeclaim_status_gen.rs"
));

/// Shared by decode_persistentvolumeclaim_proto_gen and StatefulSetSpec.volumeClaimTemplates
/// (apps_gen_adapter.rs) — a VolumeClaimTemplate entry is a full embedded PersistentVolumeClaim,
/// so both call sites need the exact same metadata/spec/status mapping. Stays hand-written
/// (rather than itself being generated, unlike every other top-level Kind's own entry point):
/// this function has no `apiVersion`/`kind` stamping and is called directly from
/// `apps_gen_adapter.rs`, a calling convention `generate_message_encode_only`'s own callers don't
/// need.
pub(crate) fn gen_persistent_volume_claim_to_json(
    obj: core_v1::PersistentVolumeClaim,
) -> serde_json::Value {
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut result = serde_json::json!({ "metadata": meta });
    if let Some(spec) = obj.spec {
        let spec_json = gen_persistentvolumeclaim_spec_to_json(spec);
        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {
            result["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let status_json = gen_persistentvolumeclaim_status_to_json(status);
        if status_json.as_object().is_some_and(|m| !m.is_empty()) {
            result["status"] = status_json;
        }
    }
    result
}

pub fn decode_persistentvolumeclaim_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = core_v1::PersistentVolumeClaim::decode(data).ok()?;
    let mut result = gen_persistent_volume_claim_to_json(obj);
    result["apiVersion"] = "v1".into();
    result["kind"] = "PersistentVolumeClaim".into();
    Some(result)
}

// ---- Decoder A: Endpoints --------------------------------------------------

/// `EndpointAddress.ip` is unconditionally emitted (matching upstream's non-`omitempty` JSON
/// tag), the same class of override `gen_node_address_to_json` documents for
/// `NodeAddress.type`/`.address`. `addresses` and `notReadyAddresses` share this exact per-item
/// shape — the pre-migration decoder duplicated the same closure for both — so this is now a
/// single named function both call. Used by `gen_endpoint_subset_to_json` below.
fn gen_endpoint_address_to_json(a: core_v1::EndpointAddress) -> serde_json::Value {
    let mut addr = serde_json::json!({
        "ip": a.ip.unwrap_or_default()
    });
    if let Some(v) = a.hostname.filter(|s| !s.is_empty()) {
        addr["hostname"] = serde_json::Value::String(v);
    }
    if let Some(v) = a.node_name.filter(|s| !s.is_empty()) {
        addr["nodeName"] = serde_json::Value::String(v);
    }
    if let Some(v) = a.target_ref {
        addr["targetRef"] = gen_object_reference_to_json(v);
    }
    addr
}

fn json_to_endpoint_address_proto(v: &serde_json::Value) -> core_v1::EndpointAddress {
    core_v1::EndpointAddress {
        ip: jstr(v, "ip"),
        hostname: jstr(v, "hostname"),
        node_name: jstr(v, "nodeName"),
        target_ref: v.get("targetRef").map(json_to_object_reference_proto),
    }
}

/// `EndpointPort.port` is unconditionally emitted (matching upstream's non-`omitempty` JSON
/// tag) with no zero-filter guard, matching the pre-migration decoder's own
/// `p.port.unwrap_or(0)` — unlike `ServicePort.port`/`gen_service_port_to_json`, which does
/// filter zero. Used by `gen_endpoint_subset_to_json` below.
fn gen_endpoint_port_to_json(p: core_v1::EndpointPort) -> serde_json::Value {
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
}

fn json_to_endpoint_port_proto(v: &serde_json::Value) -> core_v1::EndpointPort {
    core_v1::EndpointPort {
        name: jstr(v, "name"),
        port: ji32(v, "port"),
        protocol: jstr(v, "protocol"),
        app_protocol: jstr(v, "appProtocol"),
    }
}

/// `addresses`/`notReadyAddresses`/`ports` are each unconditionally-emitted-per-item message
/// types (see `gen_endpoint_address_to_json`/`gen_endpoint_port_to_json` above) that the
/// mechanical codegen walker has no per-field override hook for one level below `Endpoints`
/// itself, so `EndpointSubset` stays a hand-written whole-message function delegated to
/// wholesale by `endpoints_delegated_field`'s own `subsets` entry.
fn gen_endpoint_subset_to_json(subset: core_v1::EndpointSubset) -> serde_json::Value {
    let mut s = serde_json::json!({});
    if !subset.addresses.is_empty() {
        s["addresses"] = subset
            .addresses
            .into_iter()
            .map(gen_endpoint_address_to_json)
            .collect::<Vec<_>>()
            .into();
    }
    if !subset.not_ready_addresses.is_empty() {
        s["notReadyAddresses"] = subset
            .not_ready_addresses
            .into_iter()
            .map(gen_endpoint_address_to_json)
            .collect::<Vec<_>>()
            .into();
    }
    if !subset.ports.is_empty() {
        s["ports"] = subset
            .ports
            .into_iter()
            .map(gen_endpoint_port_to_json)
            .collect::<Vec<_>>()
            .into();
    }
    s
}

fn json_to_endpoint_subset_proto(v: &serde_json::Value) -> core_v1::EndpointSubset {
    core_v1::EndpointSubset {
        addresses: v
            .get("addresses")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().map(json_to_endpoint_address_proto).collect())
            .unwrap_or_default(),
        not_ready_addresses: v
            .get("notReadyAddresses")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().map(json_to_endpoint_address_proto).collect())
            .unwrap_or_default(),
        ports: v
            .get("ports")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().map(json_to_endpoint_port_proto).collect())
            .unwrap_or_default(),
    }
}

// `gen_endpoints_to_json`/`json_to_endpoints_proto` are generated by `build/codegen.rs` from
// the `.k8s.io.api.core.v1.Endpoints` descriptor — `metadata` delegates to the hand-written
// `gen_object_meta_to_json` and `subsets` delegates to the hand-written helpers above; see
// `build/codegen.rs::endpoints_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/endpoints_gen.rs"));

pub fn decode_endpoints_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let eps = core_v1::Endpoints::decode(data).ok()?;
    let mut obj = gen_endpoints_to_json(eps);
    obj["apiVersion"] = "v1".into();
    obj["kind"] = "Endpoints".into();
    Some(obj)
}

// ---- Decoder A: ResourceQuota ----------------------------------------------

/// `ScopedResourceSelectorRequirement`'s per-item `scopeName`/`operator` fields are
/// unconditionally emitted (matching upstream's non-`omitempty` JSON tags for those two fields
/// specifically) — the same class of per-item override `gen_namespace_condition_to_json`
/// documents at length — so `scopeSelector` delegates wholesale here rather than being walked
/// mechanically; see `build/codegen.rs::resourcequota_spec_delegated_field`.
fn gen_scope_selector_to_json(ss: core_v1::ScopeSelector) -> serde_json::Value {
    if ss.match_expressions.is_empty() {
        return serde_json::Value::Object(serde_json::Map::new());
    }
    let exprs: Vec<serde_json::Value> = ss
        .match_expressions
        .into_iter()
        .map(|expr| {
            let mut m = serde_json::json!({
                "scopeName": expr.scope_name.unwrap_or_default(),
                "operator": expr.operator.unwrap_or_default(),
            });
            if !expr.values.is_empty() {
                m["values"] =
                    serde_json::Value::Array(expr.values.into_iter().map(Into::into).collect());
            }
            m
        })
        .collect();
    serde_json::json!({ "matchExpressions": exprs })
}

// `gen_resourcequota_spec_to_json` is generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.ResourceQuotaSpec` descriptor — `scopeSelector` delegates to the
// hand-written `gen_scope_selector_to_json` above; see
// `build/codegen.rs::resourcequota_spec_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/resourcequota_spec_gen.rs"));

// `gen_resourcequota_to_json` is generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.ResourceQuota` descriptor. `metadata` delegates to the hand-written
// `gen_object_meta_to_json` and `spec` delegates to `gen_resourcequota_spec_to_json` above;
// `status` (upstream's quota controller PUTs it via protobuf on every reconcile) needs no
// delegate — see `build/codegen.rs::resourcequota_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/resourcequota_gen.rs"));

pub fn decode_resourcequota_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let rq = core_v1::ResourceQuota::decode(data).ok()?;
    let mut result = gen_resourcequota_to_json(rq);
    result["apiVersion"] = "v1".into();
    result["kind"] = "ResourceQuota".into();
    Some(result)
}

// ---- Decoder A: LimitRange -------------------------------------------------

/// `LimitRangeItem.type` is unconditionally emitted (matching upstream's non-`omitempty` JSON
/// tag) — the same class of per-item override as `gen_scope_selector_to_json` above — so `limits`
/// delegates wholesale here; see `build/codegen.rs::limitrange_spec_delegated_field`.
fn gen_limit_range_item_to_json(item: core_v1::LimitRangeItem) -> serde_json::Value {
    let mut o = serde_json::json!({
        "type": item.r#type.unwrap_or_default()
    });
    if !item.max.is_empty() {
        o["max"] = gen_quantity_map_to_json(item.max);
    }
    if !item.min.is_empty() {
        o["min"] = gen_quantity_map_to_json(item.min);
    }
    if !item.default.is_empty() {
        o["default"] = gen_quantity_map_to_json(item.default);
    }
    if !item.default_request.is_empty() {
        o["defaultRequest"] = gen_quantity_map_to_json(item.default_request);
    }
    if !item.max_limit_request_ratio.is_empty() {
        o["maxLimitRequestRatio"] = gen_quantity_map_to_json(item.max_limit_request_ratio);
    }
    o
}

// `gen_limitrange_spec_to_json` is generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.LimitRangeSpec` descriptor — `limits` delegates to the hand-written
// `gen_limit_range_item_to_json` above; see `build/codegen.rs::limitrange_spec_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/limitrange_spec_gen.rs"));

// `gen_limitrange_to_json` is generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.LimitRange` descriptor — `metadata` delegates to the hand-written
// `gen_object_meta_to_json` and `spec` delegates to `gen_limitrange_spec_to_json` above; see
// `build/codegen.rs::limitrange_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/limitrange_gen.rs"));

pub fn decode_limitrange_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let lr = core_v1::LimitRange::decode(data).ok()?;
    let mut result = gen_limitrange_to_json(lr);
    result["apiVersion"] = "v1".into();
    result["kind"] = "LimitRange".into();
    Some(result)
}

// ---- Decoder A: ReplicationController --------------------------------------

/// `ReplicationControllerCondition.type`/`.status` are unconditionally emitted (matching
/// upstream's non-`omitempty` JSON tags), the same class of override as
/// `gen_namespace_condition_to_json` — unlike that one, `lastTransitionTime` here has no
/// `seconds > 0` guard (matches the hand-rolled body this migration replaces exactly). Used by
/// `gen_replicationcontroller_status_to_json`'s `conditions` delegate; see
/// `build/codegen.rs::replicationcontroller_status_delegated_field`.
fn gen_replicationcontroller_condition_to_json(
    c: core_v1::ReplicationControllerCondition,
) -> serde_json::Value {
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
        cond["lastTransitionTime"] = serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
    }
    cond
}

// `gen_replicationcontroller_spec_to_json`/`gen_replicationcontroller_status_to_json` are
// generated by `build/codegen.rs` from the `.k8s.io.api.core.v1.ReplicationControllerSpec`/
// `ReplicationControllerStatus` descriptors — `template` delegates to the existing hand-written
// `gen_pod_template_spec_to_json` and `conditions` delegates to
// `gen_replicationcontroller_condition_to_json` above; see
// `build/codegen.rs::replicationcontroller_spec_delegated_field`/
// `replicationcontroller_status_delegated_field`.
include!(concat!(
    env!("OUT_DIR"),
    "/replicationcontroller_spec_gen.rs"
));
include!(concat!(
    env!("OUT_DIR"),
    "/replicationcontroller_status_gen.rs"
));

// `gen_replicationcontroller_to_json` is generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.ReplicationController` descriptor; see
// `build/codegen.rs::replicationcontroller_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/replicationcontroller_gen.rs"));

pub fn decode_replicationcontroller_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let rc = core_v1::ReplicationController::decode(data).ok()?;
    let mut obj = gen_replicationcontroller_to_json(rc);
    obj["apiVersion"] = "v1".into();
    obj["kind"] = "ReplicationController".into();
    Some(obj)
}

// ---- Decoder A: Event (core/v1) --------------------------------------------

/// `EventSeries.count` needs the same zero-filtering guard as `Event.count` itself, and
/// `lastObservedTime` is a bare `MicroTime` needing RFC3339 conversion — neither of which the
/// mechanical walker's generic branches know how to do, so `series` delegates wholesale here (see
/// `build/codegen.rs::event_delegated_field`). Paired on decode with the existing hand-written
/// `json_to_event_series_proto` further down.
fn gen_event_series_to_json(s: core_v1::EventSeries) -> serde_json::Value {
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
    serde_json::Value::Object(sm)
}

// `gen_event_to_json`/`json_to_event_proto` are generated by `build/codegen.rs` from the
// `.k8s.io.api.core.v1.Event` descriptor — the first top-level Kind in this codegen module with
// both a decode and an encode direction (see `generate_event`'s doc). `metadata`/`involvedObject`/
// `count`/`firstTimestamp`/`lastTimestamp`/`eventTime`/`series` delegate to hand-written helpers;
// see `build/codegen.rs::event_delegated_field`.
include!(concat!(env!("OUT_DIR"), "/event_gen.rs"));

pub fn decode_event_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let event = core_v1::Event::decode(data).ok()?;
    let mut obj = gen_event_to_json(event);
    obj["apiVersion"] = "v1".into();
    obj["kind"] = "Event".into();
    Some(obj)
}

// ---------------------------------------------------------------------------
// Encoders — JSON (u7s's own already-validated stored representation) -> Kubernetes
// protobuf wire format, for hot-path GET/LIST responses (see content_type.rs).
// Unlike the decoders above, the input here is never untrusted wire data, so no
// defensive wire-type/size checking is needed. Field coverage is scoped to what
// matters for kube-proxy/kubelet/scheduler consumers of these types rather than
// full 1:1 parity with the corresponding decode_*_proto_gen's field surface.
// ---------------------------------------------------------------------------

fn jstr(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn ji64(v: &serde_json::Value, key: &str) -> Option<i64> {
    v.get(key).and_then(|x| x.as_i64())
}

fn ji32(v: &serde_json::Value, key: &str) -> Option<i32> {
    v.get(key).and_then(|x| x.as_i64()).map(|n| n as i32)
}

fn jbool(v: &serde_json::Value, key: &str) -> Option<bool> {
    v.get(key).and_then(|x| x.as_bool())
}

fn jtime(v: &serde_json::Value, key: &str) -> Option<meta_v1::Time> {
    v.get(key)
        .and_then(|x| x.as_str())
        .and_then(crate::util::rfc3339_to_unix_secs)
        .map(|secs| meta_v1::Time {
            seconds: Some(secs),
            ..Default::default()
        })
}

fn json_to_microtime_proto(v: &serde_json::Value, key: &str) -> Option<meta_v1::MicroTime> {
    v.get(key)
        .and_then(|x| x.as_str())
        .and_then(crate::util::rfc3339_to_unix_secs)
        .map(|secs| meta_v1::MicroTime {
            seconds: Some(secs),
            ..Default::default()
        })
}

fn jstrs(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn jstrmap(v: &serde_json::Value, key: &str) -> std::collections::HashMap<String, String> {
    v.get(key)
        .and_then(|m| m.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn json_quantity_map_to_proto(
    v: &serde_json::Value,
    key: &str,
) -> std::collections::HashMap<
    String,
    super::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity,
> {
    v.get(key)
        .and_then(|m| m.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(k, val)| {
                    val.as_str().map(|s| {
                        (
                            k.clone(),
                            super::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
                                string: Some(s.to_string()),
                            },
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn json_to_object_meta_proto(obj: &serde_json::Value) -> meta_v1::ObjectMeta {
    let meta = obj
        .get("metadata")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let owner_references = meta
        .get("ownerReferences")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .map(|r| meta_v1::OwnerReference {
                    api_version: jstr(r, "apiVersion"),
                    kind: jstr(r, "kind"),
                    name: jstr(r, "name"),
                    uid: jstr(r, "uid"),
                    controller: jbool(r, "controller"),
                    block_owner_deletion: jbool(r, "blockOwnerDeletion"),
                })
                .collect()
        })
        .unwrap_or_default();
    meta_v1::ObjectMeta {
        name: jstr(&meta, "name"),
        generate_name: jstr(&meta, "generateName"),
        namespace: jstr(&meta, "namespace"),
        uid: jstr(&meta, "uid"),
        resource_version: jstr(&meta, "resourceVersion"),
        generation: ji64(&meta, "generation"),
        creation_timestamp: jtime(&meta, "creationTimestamp"),
        deletion_timestamp: jtime(&meta, "deletionTimestamp"),
        deletion_grace_period_seconds: ji64(&meta, "deletionGracePeriodSeconds"),
        labels: jstrmap(&meta, "labels"),
        annotations: jstrmap(&meta, "annotations"),
        owner_references,
        finalizers: jstrs(&meta, "finalizers"),
        ..Default::default()
    }
}

fn json_to_list_meta_proto(v: &serde_json::Value) -> meta_v1::ListMeta {
    let meta = v
        .get("metadata")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    meta_v1::ListMeta {
        resource_version: jstr(&meta, "resourceVersion"),
        r#continue: jstr(&meta, "continue"),
        ..Default::default()
    }
}

// `gen_meta_condition_to_json`/`json_to_meta_condition_proto` are defined above, next to
// `gen_service_status_to_json` — see `build/codegen.rs::service_status_delegated_field`'s doc
// for why this generic apimachinery `Condition` type needs its own hand-written pair rather
// than a mechanical per-field walk.

// ---- Encoder: Pod / PodList -------------------------------------------------

/// EnvVar.valueFrom. Without this, `$(FOO)` container-command/subPathExpr expansion and the
/// kubelet's own env var construction both silently see an env var with neither `value` nor
/// `valueFrom` set — the kubelet then hard-fails with "missing value for <name>" instead of
/// resolving the field/resource/configMap/secret reference the client actually configured.
fn json_to_env_var_source_proto(v: &serde_json::Value) -> core_v1::EnvVarSource {
    core_v1::EnvVarSource {
        field_ref: v.get("fieldRef").map(json_to_object_field_selector_proto),
        resource_field_ref: v
            .get("resourceFieldRef")
            .map(json_to_resource_field_selector_proto),
        config_map_key_ref: v
            .get("configMapKeyRef")
            .map(|cmkr| core_v1::ConfigMapKeySelector {
                local_object_reference: jstr(cmkr, "name")
                    .map(|name| core_v1::LocalObjectReference { name: Some(name) }),
                key: jstr(cmkr, "key"),
                optional: jbool(cmkr, "optional"),
            }),
        secret_key_ref: v.get("secretKeyRef").map(|skr| core_v1::SecretKeySelector {
            local_object_reference: jstr(skr, "name")
                .map(|name| core_v1::LocalObjectReference { name: Some(name) }),
            key: jstr(skr, "key"),
            optional: jbool(skr, "optional"),
        }),
        file_key_ref: v.get("fileKeyRef").map(|fkr| core_v1::FileKeySelector {
            volume_name: jstr(fkr, "volumeName"),
            path: jstr(fkr, "path"),
            key: jstr(fkr, "key"),
            optional: jbool(fkr, "optional"),
        }),
    }
}

fn json_to_env_var_proto(v: &serde_json::Value) -> core_v1::EnvVar {
    core_v1::EnvVar {
        name: jstr(v, "name"),
        value: jstr(v, "value"),
        value_from: v.get("valueFrom").map(json_to_env_var_source_proto),
    }
}

fn json_to_container_port_proto(v: &serde_json::Value) -> core_v1::ContainerPort {
    core_v1::ContainerPort {
        name: jstr(v, "name"),
        host_port: ji32(v, "hostPort"),
        container_port: ji32(v, "containerPort"),
        protocol: jstr(v, "protocol"),
        host_ip: jstr(v, "hostIP"),
    }
}

fn json_to_resource_requirements_proto(v: &serde_json::Value) -> core_v1::ResourceRequirements {
    core_v1::ResourceRequirements {
        limits: json_quantity_map_to_proto(v, "limits"),
        requests: json_quantity_map_to_proto(v, "requests"),
        // claims — DRA resource-claim references by name; dropping this makes a container's
        // resources.claims[].name resolve to nothing, so the pod starts without ever reserving
        // the device/resource the client asked for.
        claims: v
            .get("claims")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .map(|c| core_v1::ResourceClaim {
                        name: jstr(c, "name"),
                        request: jstr(c, "request"),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn json_to_volume_mount_proto(v: &serde_json::Value) -> core_v1::VolumeMount {
    core_v1::VolumeMount {
        name: jstr(v, "name"),
        read_only: jbool(v, "readOnly"),
        mount_path: jstr(v, "mountPath"),
        sub_path: jstr(v, "subPath"),
        sub_path_expr: jstr(v, "subPathExpr"),
        ..Default::default()
    }
}

fn json_to_seccomp_profile_proto(v: &serde_json::Value) -> core_v1::SeccompProfile {
    core_v1::SeccompProfile {
        r#type: jstr(v, "type"),
        localhost_profile: jstr(v, "localhostProfile"),
    }
}

fn json_to_apparmor_profile_proto(v: &serde_json::Value) -> core_v1::AppArmorProfile {
    core_v1::AppArmorProfile {
        r#type: jstr(v, "type"),
        localhost_profile: jstr(v, "localhostProfile"),
    }
}

fn json_to_selinux_options_proto(v: &serde_json::Value) -> core_v1::SeLinuxOptions {
    core_v1::SeLinuxOptions {
        user: jstr(v, "user"),
        role: jstr(v, "role"),
        r#type: jstr(v, "type"),
        level: jstr(v, "level"),
    }
}

fn json_to_windows_security_context_options_proto(
    v: &serde_json::Value,
) -> core_v1::WindowsSecurityContextOptions {
    core_v1::WindowsSecurityContextOptions {
        gmsa_credential_spec_name: jstr(v, "gmsaCredentialSpecName"),
        gmsa_credential_spec: jstr(v, "gmsaCredentialSpec"),
        run_as_user_name: jstr(v, "runAsUserName"),
        host_process: jbool(v, "hostProcess"),
    }
}

fn json_to_capabilities_proto(v: &serde_json::Value) -> core_v1::Capabilities {
    core_v1::Capabilities {
        add: jstrs(v, "add"),
        drop: jstrs(v, "drop"),
    }
}

/// Container-level SecurityContext (Container.securityContext, proto field 15).
///
/// Without this, every protobuf-encoded response silently drops runAsUser/runAsGroup,
/// privileged, capabilities, allowPrivilegeEscalation and readOnlyRootFilesystem: a kubelet
/// watching over protobuf would run the container less confined than the pod spec requested,
/// with no error reported anywhere.
fn json_to_security_context_proto(v: &serde_json::Value) -> core_v1::SecurityContext {
    core_v1::SecurityContext {
        capabilities: v.get("capabilities").map(json_to_capabilities_proto),
        privileged: jbool(v, "privileged"),
        se_linux_options: v.get("seLinuxOptions").map(json_to_selinux_options_proto),
        windows_options: v
            .get("windowsOptions")
            .map(json_to_windows_security_context_options_proto),
        run_as_user: v.get("runAsUser").and_then(|x| x.as_i64()),
        run_as_group: v.get("runAsGroup").and_then(|x| x.as_i64()),
        run_as_non_root: jbool(v, "runAsNonRoot"),
        read_only_root_filesystem: jbool(v, "readOnlyRootFilesystem"),
        allow_privilege_escalation: jbool(v, "allowPrivilegeEscalation"),
        proc_mount: jstr(v, "procMount"),
        seccomp_profile: v.get("seccompProfile").map(json_to_seccomp_profile_proto),
        app_armor_profile: v.get("appArmorProfile").map(json_to_apparmor_profile_proto),
    }
}

fn json_to_env_from_source_proto(v: &serde_json::Value) -> core_v1::EnvFromSource {
    core_v1::EnvFromSource {
        prefix: jstr(v, "prefix"),
        config_map_ref: v
            .get("configMapRef")
            .map(|cmr| core_v1::ConfigMapEnvSource {
                local_object_reference: jstr(cmr, "name")
                    .map(|name| core_v1::LocalObjectReference { name: Some(name) }),
                optional: jbool(cmr, "optional"),
            }),
        secret_ref: v.get("secretRef").map(|sr| core_v1::SecretEnvSource {
            local_object_reference: jstr(sr, "name")
                .map(|name| core_v1::LocalObjectReference { name: Some(name) }),
            optional: jbool(sr, "optional"),
        }),
    }
}

fn json_to_http_get_action_proto(v: &serde_json::Value) -> core_v1::HttpGetAction {
    core_v1::HttpGetAction {
        path: jstr(v, "path"),
        port: v.get("port").map(json_to_int_or_string_proto),
        host: jstr(v, "host"),
        scheme: jstr(v, "scheme"),
        http_headers: v
            .get("httpHeaders")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .map(|h| core_v1::HttpHeader {
                        name: jstr(h, "name"),
                        value: jstr(h, "value"),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn json_to_tcp_socket_action_proto(v: &serde_json::Value) -> core_v1::TcpSocketAction {
    core_v1::TcpSocketAction {
        port: v.get("port").map(json_to_int_or_string_proto),
        host: jstr(v, "host"),
    }
}

fn json_to_probe_handler_proto(v: &serde_json::Value) -> core_v1::ProbeHandler {
    core_v1::ProbeHandler {
        exec: v.get("exec").map(|e| core_v1::ExecAction {
            command: jstrs(e, "command"),
        }),
        http_get: v.get("httpGet").map(json_to_http_get_action_proto),
        tcp_socket: v.get("tcpSocket").map(json_to_tcp_socket_action_proto),
        grpc: v.get("grpc").map(|g| core_v1::GrpcAction {
            port: ji32(g, "port"),
            service: jstr(g, "service"),
        }),
    }
}

/// Probe (Container.livenessProbe/readinessProbe/startupProbe). Without this, every
/// protobuf-encoded pod loses its health checks: kubelet always sees "no probe configured"
/// and treats the container as immediately healthy/ready regardless of the spec.
fn json_to_probe_proto(v: &serde_json::Value) -> core_v1::Probe {
    core_v1::Probe {
        handler: Some(json_to_probe_handler_proto(v)),
        initial_delay_seconds: ji32(v, "initialDelaySeconds"),
        timeout_seconds: ji32(v, "timeoutSeconds"),
        period_seconds: ji32(v, "periodSeconds"),
        success_threshold: ji32(v, "successThreshold"),
        failure_threshold: ji32(v, "failureThreshold"),
        termination_grace_period_seconds: ji64(v, "terminationGracePeriodSeconds"),
    }
}

fn json_to_lifecycle_handler_proto(v: &serde_json::Value) -> core_v1::LifecycleHandler {
    core_v1::LifecycleHandler {
        exec: v.get("exec").map(|e| core_v1::ExecAction {
            command: jstrs(e, "command"),
        }),
        http_get: v.get("httpGet").map(json_to_http_get_action_proto),
        tcp_socket: v.get("tcpSocket").map(json_to_tcp_socket_action_proto),
        sleep: v.get("sleep").map(|s| core_v1::SleepAction {
            seconds: ji64(s, "seconds"),
        }),
    }
}

fn json_to_lifecycle_proto(v: &serde_json::Value) -> core_v1::Lifecycle {
    core_v1::Lifecycle {
        post_start: v.get("postStart").map(json_to_lifecycle_handler_proto),
        pre_stop: v.get("preStop").map(json_to_lifecycle_handler_proto),
        stop_signal: jstr(v, "stopSignal"),
    }
}

fn json_to_key_to_path_proto(v: &serde_json::Value) -> core_v1::KeyToPath {
    core_v1::KeyToPath {
        key: jstr(v, "key"),
        path: jstr(v, "path"),
        mode: ji32(v, "mode"),
    }
}

fn json_to_object_field_selector_proto(v: &serde_json::Value) -> core_v1::ObjectFieldSelector {
    core_v1::ObjectFieldSelector {
        api_version: jstr(v, "apiVersion"),
        field_path: jstr(v, "fieldPath"),
    }
}

fn json_to_resource_field_selector_proto(v: &serde_json::Value) -> core_v1::ResourceFieldSelector {
    core_v1::ResourceFieldSelector {
        container_name: jstr(v, "containerName"),
        resource: jstr(v, "resource"),
        divisor: jstr(v, "divisor").map(|s| {
            super::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity { string: Some(s) }
        }),
    }
}

fn json_to_downward_api_volume_file_proto(v: &serde_json::Value) -> core_v1::DownwardApiVolumeFile {
    core_v1::DownwardApiVolumeFile {
        path: jstr(v, "path"),
        field_ref: v.get("fieldRef").map(json_to_object_field_selector_proto),
        resource_field_ref: v
            .get("resourceFieldRef")
            .map(json_to_resource_field_selector_proto),
        mode: ji32(v, "mode"),
    }
}

fn json_to_downward_api_items_proto(v: &serde_json::Value) -> Vec<core_v1::DownwardApiVolumeFile> {
    v.get("items")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .map(json_to_downward_api_volume_file_proto)
                .collect()
        })
        .unwrap_or_default()
}

/// downwardAPI volume source. Without this, a pod requesting labels/annotations mounted as
/// files gets a Volume with no volume_source at all over protobuf, and the real kubelet
/// refuses to mount it: "FailedMount ... no defaultMode used, not even the default value".
///
/// Unlike configMap/secret/projected volumes, a top-level DownwardAPIVolumeSource never gets
/// a later defaulting pass in handlers/pods.rs::apply_pod_spec_defaults (see the matching
/// comment on the decode-side gen_downward_api_volume_source_to_json) — this encoder is the
/// only place that stamps defaultMode when the stored JSON never had one, and the kubelet
/// refuses to mount the volume at all without one, even on the write path.
fn json_to_downward_api_volume_source_proto(
    v: &serde_json::Value,
) -> core_v1::DownwardApiVolumeSource {
    core_v1::DownwardApiVolumeSource {
        items: json_to_downward_api_items_proto(v),
        default_mode: Some(match ji32(v, "defaultMode") {
            Some(m) if m != 0 => m,
            _ => 420,
        }),
    }
}

fn json_to_volume_projection_proto(v: &serde_json::Value) -> core_v1::VolumeProjection {
    core_v1::VolumeProjection {
        secret: v.get("secret").map(|s| core_v1::SecretProjection {
            local_object_reference: jstr(s, "name")
                .map(|name| core_v1::LocalObjectReference { name: Some(name) }),
            items: s
                .get("items")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().map(json_to_key_to_path_proto).collect())
                .unwrap_or_default(),
            optional: jbool(s, "optional"),
        }),
        downward_api: v
            .get("downwardAPI")
            .map(|d| core_v1::DownwardApiProjection {
                items: json_to_downward_api_items_proto(d),
            }),
        config_map: v.get("configMap").map(|cm| core_v1::ConfigMapProjection {
            local_object_reference: jstr(cm, "name")
                .map(|name| core_v1::LocalObjectReference { name: Some(name) }),
            items: cm
                .get("items")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().map(json_to_key_to_path_proto).collect())
                .unwrap_or_default(),
            optional: jbool(cm, "optional"),
        }),
        service_account_token: v.get("serviceAccountToken").map(|sat| {
            core_v1::ServiceAccountTokenProjection {
                audience: jstr(sat, "audience"),
                expiration_seconds: ji64(sat, "expirationSeconds"),
                path: jstr(sat, "path"),
            }
        }),
        // podCertificate/clusterTrustBundle: supported on decode
        // (gen_projected_volume_source_to_json) but missing here, so a protobuf-negotiating
        // client reading back a pod that mounts either one would see the projected volume's
        // sources[] entry silently vanish.
        pod_certificate: v
            .get("podCertificate")
            .map(|pc| core_v1::PodCertificateProjection {
                signer_name: jstr(pc, "signerName"),
                key_type: jstr(pc, "keyType"),
                max_expiration_seconds: ji32(pc, "maxExpirationSeconds"),
                credential_bundle_path: jstr(pc, "credentialBundlePath"),
                key_path: jstr(pc, "keyPath"),
                certificate_chain_path: jstr(pc, "certificateChainPath"),
                ..Default::default()
            }),
        cluster_trust_bundle: v.get("clusterTrustBundle").map(|ctb| {
            core_v1::ClusterTrustBundleProjection {
                name: jstr(ctb, "name"),
                signer_name: jstr(ctb, "signerName"),
                label_selector: ctb.get("labelSelector").map(json_to_label_selector_proto),
                optional: jbool(ctb, "optional"),
                path: jstr(ctb, "path"),
            }
        }),
    }
}

/// projected volume source (sources[]: downwardAPI/configMap/secret/serviceAccountToken).
/// Without this, a projected volume decodes to an empty source over protobuf and the kubelet
/// mounts nothing, the same failure mode as a missing downwardAPI volume.
fn json_to_projected_volume_source_proto(v: &serde_json::Value) -> core_v1::ProjectedVolumeSource {
    core_v1::ProjectedVolumeSource {
        sources: v
            .get("sources")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().map(json_to_volume_projection_proto).collect())
            .unwrap_or_default(),
        default_mode: ji32(v, "defaultMode"),
    }
}

/// Minimal JSON -> proto mirror of `gen_persistent_volume_claim_to_json`'s spec section, scoped
/// to `EphemeralVolumeSource.volumeClaimTemplate.spec` — access modes and resource requests are
/// what every real ephemeral-volume claim sets. selector/dataSource/dataSourceRef have no live
/// consumer here, matching this file's existing PersistentVolumeSource decode precedent of
/// covering what's actually exercised rather than the full upstream field set.
fn json_to_persistent_volume_claim_spec_proto(
    v: &serde_json::Value,
) -> core_v1::PersistentVolumeClaimSpec {
    core_v1::PersistentVolumeClaimSpec {
        access_modes: jstrs(v, "accessModes"),
        resources: v
            .get("resources")
            .map(|r| core_v1::VolumeResourceRequirements {
                requests: json_quantity_map_to_proto(r, "requests"),
                limits: json_quantity_map_to_proto(r, "limits"),
            }),
        volume_name: jstr(v, "volumeName"),
        storage_class_name: jstr(v, "storageClassName"),
        volume_mode: jstr(v, "volumeMode"),
        ..Default::default()
    }
}

// The five VolumeSource plugin decoders below are called by `build/codegen.rs`'s generated
// `json_to_volume_proto` (see volume_source_gen.rs, included further down this file) rather than
// walked mechanically, for the same reasons as their encode-side counterparts above. Extracted
// verbatim from the inline branches the generated function replaces — no behaviour change.

fn json_to_secret_volume_source_proto(v: &serde_json::Value) -> core_v1::SecretVolumeSource {
    core_v1::SecretVolumeSource {
        secret_name: jstr(v, "secretName"),
        ..Default::default()
    }
}

fn json_to_config_map_volume_source_proto(v: &serde_json::Value) -> core_v1::ConfigMapVolumeSource {
    core_v1::ConfigMapVolumeSource {
        local_object_reference: jstr(v, "name")
            .map(|name| core_v1::LocalObjectReference { name: Some(name) }),
        ..Default::default()
    }
}

fn json_to_persistent_volume_claim_volume_source_proto(
    v: &serde_json::Value,
) -> core_v1::PersistentVolumeClaimVolumeSource {
    core_v1::PersistentVolumeClaimVolumeSource {
        claim_name: jstr(v, "claimName"),
        read_only: jbool(v, "readOnly"),
    }
}

fn json_to_ephemeral_volume_source_proto(
    v: &serde_json::Value,
) -> Option<core_v1::EphemeralVolumeSource> {
    let tmpl = v.get("volumeClaimTemplate")?;
    Some(core_v1::EphemeralVolumeSource {
        volume_claim_template: Some(core_v1::PersistentVolumeClaimTemplate {
            metadata: Some(json_to_object_meta_proto(tmpl)),
            spec: tmpl
                .get("spec")
                .map(json_to_persistent_volume_claim_spec_proto),
        }),
    })
}

fn json_to_csi_volume_source_proto(v: &serde_json::Value) -> core_v1::CsiVolumeSource {
    core_v1::CsiVolumeSource {
        driver: jstr(v, "driver"),
        read_only: jbool(v, "readOnly"),
        fs_type: jstr(v, "fsType"),
        volume_attributes: jstrmap(v, "volumeAttributes"),
        node_publish_secret_ref: v
            .get("nodePublishSecretRef")
            .map(json_to_local_object_reference_proto),
    }
}

fn json_to_scheduling_gate_proto(v: &serde_json::Value) -> core_v1::PodSchedulingGate {
    core_v1::PodSchedulingGate {
        name: jstr(v, "name"),
    }
}

fn json_to_pod_condition_proto(v: &serde_json::Value) -> core_v1::PodCondition {
    core_v1::PodCondition {
        r#type: jstr(v, "type"),
        status: jstr(v, "status"),
        reason: jstr(v, "reason"),
        message: jstr(v, "message"),
        last_transition_time: jtime(v, "lastTransitionTime"),
        last_probe_time: jtime(v, "lastProbeTime"),
        // observedGeneration — WaitForPodConditionObservedGeneration polls this per-condition
        // field over protobuf; without it a client can never observe a specific condition's
        // (e.g. PodReadyToStartContainers) convergence and times out the same way a missing
        // status-level observedGeneration does.
        observed_generation: ji64(v, "observedGeneration"),
    }
}

fn json_to_container_state_proto(v: &serde_json::Value) -> core_v1::ContainerState {
    let mut state = core_v1::ContainerState::default();
    if let Some(w) = v.get("waiting") {
        state.waiting = Some(core_v1::ContainerStateWaiting {
            reason: jstr(w, "reason"),
            message: jstr(w, "message"),
        });
    }
    if let Some(r) = v.get("running") {
        state.running = Some(core_v1::ContainerStateRunning {
            started_at: jtime(r, "startedAt"),
        });
    }
    if let Some(t) = v.get("terminated") {
        state.terminated = Some(core_v1::ContainerStateTerminated {
            exit_code: ji32(t, "exitCode"),
            signal: ji32(t, "signal"),
            reason: jstr(t, "reason"),
            message: jstr(t, "message"),
            started_at: jtime(t, "startedAt"),
            finished_at: jtime(t, "finishedAt"),
            container_id: jstr(t, "containerID"),
        });
    }
    state
}

fn json_to_container_user_proto(v: &serde_json::Value) -> core_v1::ContainerUser {
    core_v1::ContainerUser {
        linux: v.get("linux").map(|l| core_v1::LinuxContainerUser {
            uid: ji64(l, "uid"),
            gid: ji64(l, "gid"),
            supplemental_groups: l
                .get("supplementalGroups")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|n| n.as_i64()).collect())
                .unwrap_or_default(),
        }),
    }
}

fn json_to_local_object_reference_proto(v: &serde_json::Value) -> core_v1::LocalObjectReference {
    core_v1::LocalObjectReference {
        name: jstr(v, "name"),
    }
}

fn json_to_pod_readiness_gate_proto(v: &serde_json::Value) -> core_v1::PodReadinessGate {
    core_v1::PodReadinessGate {
        condition_type: jstr(v, "conditionType"),
    }
}

/// Pod-level SecurityContext (PodSpec.securityContext, proto field 14).
///
/// Without this, runAsUser/runAsGroup/fsGroup/supplementalGroups/seccompProfile set at the
/// pod level never reach a protobuf-watching kubelet, which then runs every container in the
/// pod under the image's default identity instead of the one the spec requested.
fn json_to_pod_security_context_proto(v: &serde_json::Value) -> core_v1::PodSecurityContext {
    core_v1::PodSecurityContext {
        se_linux_options: v.get("seLinuxOptions").map(json_to_selinux_options_proto),
        windows_options: v
            .get("windowsOptions")
            .map(json_to_windows_security_context_options_proto),
        run_as_user: v.get("runAsUser").and_then(|x| x.as_i64()),
        run_as_group: v.get("runAsGroup").and_then(|x| x.as_i64()),
        run_as_non_root: jbool(v, "runAsNonRoot"),
        fs_group: v.get("fsGroup").and_then(|x| x.as_i64()),
        supplemental_groups: v
            .get("supplementalGroups")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|n| n.as_i64()).collect())
            .unwrap_or_default(),
        supplemental_groups_policy: jstr(v, "supplementalGroupsPolicy"),
        sysctls: v
            .get("sysctls")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .map(|s| core_v1::Sysctl {
                        name: jstr(s, "name"),
                        value: jstr(s, "value"),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        fs_group_change_policy: jstr(v, "fsGroupChangePolicy"),
        seccomp_profile: v.get("seccompProfile").map(json_to_seccomp_profile_proto),
        app_armor_profile: v.get("appArmorProfile").map(json_to_apparmor_profile_proto),
        se_linux_change_policy: jstr(v, "seLinuxChangePolicy"),
    }
}

fn json_to_label_selector_requirement_proto(
    v: &serde_json::Value,
) -> meta_v1::LabelSelectorRequirement {
    meta_v1::LabelSelectorRequirement {
        key: jstr(v, "key"),
        operator: jstr(v, "operator"),
        values: jstrs(v, "values"),
    }
}

fn json_to_label_selector_proto(v: &serde_json::Value) -> meta_v1::LabelSelector {
    meta_v1::LabelSelector {
        match_labels: jstrmap(v, "matchLabels"),
        match_expressions: v
            .get("matchExpressions")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .map(json_to_label_selector_requirement_proto)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn json_to_node_selector_requirement_proto(
    v: &serde_json::Value,
) -> core_v1::NodeSelectorRequirement {
    core_v1::NodeSelectorRequirement {
        key: jstr(v, "key"),
        operator: jstr(v, "operator"),
        values: jstrs(v, "values"),
    }
}

fn json_to_node_selector_term_proto(v: &serde_json::Value) -> core_v1::NodeSelectorTerm {
    core_v1::NodeSelectorTerm {
        match_expressions: v
            .get("matchExpressions")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .map(json_to_node_selector_requirement_proto)
                    .collect()
            })
            .unwrap_or_default(),
        match_fields: v
            .get("matchFields")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .map(json_to_node_selector_requirement_proto)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn json_to_node_affinity_proto(v: &serde_json::Value) -> core_v1::NodeAffinity {
    core_v1::NodeAffinity {
        required_during_scheduling_ignored_during_execution: v
            .get("requiredDuringSchedulingIgnoredDuringExecution")
            .map(|req| core_v1::NodeSelector {
                node_selector_terms: req
                    .get("nodeSelectorTerms")
                    .and_then(|a| a.as_array())
                    .map(|a| a.iter().map(json_to_node_selector_term_proto).collect())
                    .unwrap_or_default(),
            }),
        preferred_during_scheduling_ignored_during_execution: v
            .get("preferredDuringSchedulingIgnoredDuringExecution")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .map(|p| core_v1::PreferredSchedulingTerm {
                        weight: ji32(p, "weight"),
                        preference: p.get("preference").map(json_to_node_selector_term_proto),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn json_to_pod_affinity_term_proto(v: &serde_json::Value) -> core_v1::PodAffinityTerm {
    core_v1::PodAffinityTerm {
        label_selector: v.get("labelSelector").map(json_to_label_selector_proto),
        namespaces: jstrs(v, "namespaces"),
        topology_key: jstr(v, "topologyKey"),
        namespace_selector: v.get("namespaceSelector").map(json_to_label_selector_proto),
        match_label_keys: jstrs(v, "matchLabelKeys"),
        mismatch_label_keys: jstrs(v, "mismatchLabelKeys"),
    }
}

/// `PodAffinity` and `PodAntiAffinity` are structurally identical on the wire — see
/// `gen_pod_affinity_terms_pair_to_json` for the decode-side counterpart of this split.
fn json_to_pod_affinity_terms_pair_proto(
    v: &serde_json::Value,
) -> (
    Vec<core_v1::PodAffinityTerm>,
    Vec<core_v1::WeightedPodAffinityTerm>,
) {
    let required = v
        .get("requiredDuringSchedulingIgnoredDuringExecution")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().map(json_to_pod_affinity_term_proto).collect())
        .unwrap_or_default();
    let preferred = v
        .get("preferredDuringSchedulingIgnoredDuringExecution")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .map(|w| core_v1::WeightedPodAffinityTerm {
                    weight: ji32(w, "weight"),
                    pod_affinity_term: w
                        .get("podAffinityTerm")
                        .map(json_to_pod_affinity_term_proto),
                })
                .collect()
        })
        .unwrap_or_default();
    (required, preferred)
}

/// Pod scheduling affinity (PodSpec.affinity, proto field 18). Without this, a pod created
/// with node/pod affinity or anti-affinity rules loses them entirely over protobuf: the
/// scheduler (which reads pods via the same watch path) schedules as if no constraint had
/// ever been requested.
fn json_to_affinity_proto(v: &serde_json::Value) -> core_v1::Affinity {
    core_v1::Affinity {
        node_affinity: v.get("nodeAffinity").map(json_to_node_affinity_proto),
        pod_affinity: v.get("podAffinity").map(|pa| {
            let (required, preferred) = json_to_pod_affinity_terms_pair_proto(pa);
            core_v1::PodAffinity {
                required_during_scheduling_ignored_during_execution: required,
                preferred_during_scheduling_ignored_during_execution: preferred,
            }
        }),
        pod_anti_affinity: v.get("podAntiAffinity").map(|paa| {
            let (required, preferred) = json_to_pod_affinity_terms_pair_proto(paa);
            core_v1::PodAntiAffinity {
                required_during_scheduling_ignored_during_execution: required,
                preferred_during_scheduling_ignored_during_execution: preferred,
            }
        }),
    }
}

fn json_to_pod_proto(v: &serde_json::Value) -> core_v1::Pod {
    core_v1::Pod {
        metadata: Some(json_to_object_meta_proto(v)),
        spec: Some(json_to_pod_spec_proto(
            v.get("spec").unwrap_or(&serde_json::Value::Null),
        )),
        status: v.get("status").map(json_to_pod_status_proto),
    }
}

pub fn encode_pod_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    json_to_pod_proto(v).encode_to_vec()
}

pub fn encode_podlist_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    let items = v
        .get("items")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().map(json_to_pod_proto).collect())
        .unwrap_or_default();
    core_v1::PodList {
        metadata: Some(json_to_list_meta_proto(v)),
        items,
    }
    .encode_to_vec()
}

// ---- Encoder: Service / ServiceList -----------------------------------------
//
// `json_to_service_proto`/`json_to_service_spec_proto`/`json_to_service_status_proto`/
// `json_to_service_port_proto`/`json_to_load_balancer_status_proto`/
// `json_to_port_status_proto`/`json_to_meta_condition_proto`/
// `json_to_session_affinity_config_proto` are generated/hand-written pairs included above (next
// to `gen_service_to_json`/`gen_service_spec_to_json`/`gen_service_status_to_json`/... — see
// `build/codegen.rs::generate_service`'s doc).

fn json_to_int_or_string_proto(v: &serde_json::Value) -> IntOrString {
    match v {
        serde_json::Value::String(s) => IntOrString {
            r#type: Some(1),
            str_val: Some(s.clone()),
            ..Default::default()
        },
        _ => IntOrString {
            r#type: Some(0),
            int_val: v.as_i64().map(|n| n as i32),
            ..Default::default()
        },
    }
}

pub fn encode_service_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    json_to_service_proto(v).encode_to_vec()
}

pub fn encode_servicelist_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    let items = v
        .get("items")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().map(json_to_service_proto).collect())
        .unwrap_or_default();
    core_v1::ServiceList {
        metadata: Some(json_to_list_meta_proto(v)),
        items,
    }
    .encode_to_vec()
}

// ---- Encoder: Node / NodeList ------------------------------------------------
//
// `json_to_node_proto`/`json_to_node_spec_proto`/`json_to_node_status_proto`/`json_to_taint_proto`
// are generated/hand-written pairs included above (next to `gen_node_to_json`/
// `gen_node_spec_to_json`/`gen_node_status_to_json`/`gen_taint_to_json` — see `generate_node`'s
// doc). `json_to_node_condition_proto`/`json_to_node_address_proto` stay hand-written there too
// (`NodeCondition.type`/`.status` and `NodeAddress.type`/`.address` are unconditionally emitted on
// encode, so their decode mirrors can't be derived mechanically). `json_to_node_daemon_endpoints_proto`
// is gone: the mechanical walker's generic nested-message branch produces the identical
// `NodeDaemonEndpoints{kubelet_endpoint: Some(DaemonEndpoint{port})}` walk inline now — see
// `build/codegen.rs::node_status_delegated_field`'s doc for why `daemonEndpoints` needs no
// delegate.

pub fn encode_node_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    json_to_node_proto(v).encode_to_vec()
}

pub fn encode_nodelist_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    let items = v
        .get("items")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().map(json_to_node_proto).collect())
        .unwrap_or_default();
    core_v1::NodeList {
        metadata: Some(json_to_list_meta_proto(v)),
        items,
    }
    .encode_to_vec()
}

// ---- Encoder: Endpoints / EndpointsList -------------------------------------
//
// `json_to_endpoints_proto`/`json_to_endpoint_subset_proto`/`json_to_endpoint_address_proto`/
// `json_to_endpoint_port_proto` are generated/hand-written pairs included above (next to
// `gen_endpoints_to_json`/`gen_endpoint_subset_to_json`/... — see
// `build/codegen.rs::generate_endpoints`'s doc).

pub fn encode_endpoints_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    json_to_endpoints_proto(v).encode_to_vec()
}

pub fn encode_endpointslist_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    let items = v
        .get("items")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().map(json_to_endpoints_proto).collect())
        .unwrap_or_default();
    core_v1::EndpointsList {
        metadata: Some(json_to_list_meta_proto(v)),
        items,
    }
    .encode_to_vec()
}

// ---- Encoder: Event / EventList (core/v1) -----------------------------------
//
// `json_to_event_proto` itself is generated by `build/codegen.rs` (included above, next to
// `gen_event_to_json` — see `generate_event`'s doc). `json_to_event_source_proto` (a former
// hand-written helper for `source`) is gone: the mechanical walker's generic nested-message
// branch produces the identical `EventSource{component, host}` walk inline now — see
// `build/codegen.rs::event_delegated_field`'s doc for why `source` needs no delegate.
// `json_to_event_series_proto` stays hand-written, called by `json_to_event_proto`'s `series`
// delegate (`EventSeries.count`'s zero-filter and `lastObservedTime`'s opaque-scalar handling
// can't be derived mechanically — see `gen_event_series_to_json`'s doc for the decode-direction
// mirror).

fn json_to_event_series_proto(v: &serde_json::Value) -> core_v1::EventSeries {
    core_v1::EventSeries {
        count: ji32(v, "count"),
        last_observed_time: json_to_microtime_proto(v, "lastObservedTime"),
    }
}

pub fn encode_event_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    json_to_event_proto(v).encode_to_vec()
}

pub fn encode_eventlist_proto_gen(v: &serde_json::Value) -> Vec<u8> {
    let items = v
        .get("items")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().map(json_to_event_proto).collect())
        .unwrap_or_default();
    core_v1::EventList {
        metadata: Some(json_to_list_meta_proto(v)),
        items,
    }
    .encode_to_vec()
}

// ---- Tests -----------------------------------------------------------------

/// Most tests below guard against the same protobuf decode gap class: a `decode_*_proto_gen`
/// function that only reads a subset of its message's fields, silently dropping the rest on
/// every protobuf-encoded write (the default content-type for client-go's typed clientsets).
#[cfg(test)]
mod tests {
    use super::*;

    /// Pod spec tolerations survive proto decode via the generated path.
    ///
    /// Without tolerations in gen_pod_spec_to_json, pods that tolerate node taints
    /// (e.g. node.kubernetes.io/not-ready:NoExecute) are treated by the scheduler
    /// as if they have no tolerations. This causes them to be evicted from tainted
    /// nodes immediately rather than after the tolerationSeconds window, breaking
    /// taint-based eviction conformance tests. This test subsumes two prior regressions:
    /// tolerations dropped by hand pod_spec_to_json, and priorityClassName dropped.
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
                 taint-based eviction conformance",
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
             enforce preemption priority ordering"
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

    /// Pod status.observedGeneration (top-level, distinct from the per-condition field)
    /// survives the generated-path decode.
    ///
    /// Controllers watching PodStatus use this to tell whether a status reflects the
    /// latest spec generation. Without it, a protobuf `UpdateStatus` call always reports
    /// back observedGeneration=0, so callers can never confirm their status write was
    /// based on the generation they intended.
    #[test]
    fn generated_pod_preserves_status_observed_generation() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("pod-test".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(core_v1::PodStatus {
                phase: Some("Running".to_string()),
                observed_generation: Some(7),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).expect("prost encode must succeed");

        let result =
            decode_pod_proto_gen(&buf).expect("Pod with status must decode via generated path");

        assert_eq!(
            result["status"]["observedGeneration"], 7,
            "status.observedGeneration must survive"
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

    /// RC's `status.conditions[].lastTransitionTime` and `spec.minReadySeconds` survive the
    /// generated-path decode.
    ///
    /// Without lastTransitionTime, a client can't tell how long an RC has been stuck
    /// ReplicaFailure vs. just having started failing. Without minReadySeconds, every pod
    /// counts as available the instant it's Ready, defeating a rollout's flake-tolerance
    /// window.
    #[test]
    fn generated_rc_preserves_condition_timestamp_and_min_ready_seconds() {
        let rc = core_v1::ReplicationController {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-rc".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::ReplicationControllerSpec {
                replicas: Some(3),
                min_ready_seconds: Some(30),
                ..Default::default()
            }),
            status: Some(core_v1::ReplicationControllerStatus {
                conditions: vec![core_v1::ReplicationControllerCondition {
                    r#type: Some("ReplicaFailure".to_string()),
                    status: Some("True".to_string()),
                    last_transition_time: Some(meta_v1::Time {
                        seconds: Some(1_700_000_000),
                        nanos: Some(0),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        rc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_replicationcontroller_proto_gen(&buf)
            .expect("RC with condition timestamp must decode successfully");

        assert_eq!(
            result["status"]["conditions"][0]["lastTransitionTime"], "2023-11-14T22:13:20Z",
            "status.conditions[].lastTransitionTime must survive decode — without it a client \
             can't tell how long an RC has been stuck ReplicaFailure vs. just having started"
        );
        assert_eq!(
            result["spec"]["minReadySeconds"], 30,
            "spec.minReadySeconds must survive decode — without it every pod counts as \
             available the instant it's Ready, defeating a rollout's flake-tolerance window"
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
    /// (this is also the PANIC-1 fix).
    ///
    /// Before this fix, decode_namespace_proto_gen never read `ns.status` at all, so any
    /// protobuf-encoded Namespace write (Content-Type: application/vnd.kubernetes.protobuf)
    /// silently lost its entire status — put_namespace_status wholesale-replaces stored
    /// status with whatever this decoder returns, which was nothing. This is exactly the
    /// the "should apply changes to a namespace status" conformance panic
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
                    last_transition_time: Some(meta_v1::Time {
                        seconds: Some(1_700_000_000),
                        nanos: None,
                    }),
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
        assert_eq!(
            result["status"]["conditions"][0]["lastTransitionTime"], "2023-11-14T22:13:20Z",
            "conditions[].lastTransitionTime must survive proto decode as an RFC3339 string — \
             without it a client can't tell how long a namespace has been stuck in a given \
             lifecycle condition (e.g. Terminating)"
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

    /// decode_persistentvolume_proto_gen must preserve status.lastPhaseTransitionTime
    /// (PersistentVolumeStatus field 4).
    ///
    /// This is the only signal a client has for how long a PV has sat in its current phase
    /// (e.g. stuck Released instead of being reclaimed); without it, a controller polling PV
    /// phase can't distinguish "just transitioned" from "stuck for hours".
    #[test]
    fn decode_persistentvolume_proto_gen_preserves_last_phase_transition_time() {
        let pv = core_v1::PersistentVolume {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-pv".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::PersistentVolumeStatus {
                phase: Some("Released".to_string()),
                last_phase_transition_time: Some(meta_v1::Time {
                    seconds: Some(1_700_000_000),
                    nanos: Some(0),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pv.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolume_proto_gen(&buf).expect("PV with status must decode");

        assert_eq!(
            result["status"]["lastPhaseTransitionTime"], "2023-11-14T22:13:20Z",
            "status.lastPhaseTransitionTime must survive proto decode — without it a client \
             polling PV phase can't tell 'just transitioned' from 'stuck for hours'"
        );
    }

    /// decode_persistentvolume_proto_gen must preserve spec.capacity, spec.claimRef,
    /// spec.nodeAffinity, and the spec.local volume source.
    ///
    /// Before this fix, a protobuf-encoded PersistentVolume create (the default wire format
    /// for any client-go client, including e2e.test and any real CSI/local-volume-provisioning
    /// workload) silently lost these fields. With capacity dropped, the stored PV's capacity
    /// was implicitly zero, so kube-controller-manager's static PV/PVC matching
    /// (findBestMatchForClaim, which skips any PV smaller than the claim's request) rejected
    /// every PV as "too small" and fell through to dynamic provisioning, which then failed with
    /// "storageclass ... not found" even though a matching PV existed — this was the dominant
    /// cause of PVC/PV bind-timeout conformance failures for the "local" storage driver. With
    /// claimRef dropped, a test's explicit PV-to-PVC pre-bind was silently undone. With
    /// nodeAffinity/local dropped, a pod that did bind could never learn which node/path to
    /// actually mount.
    #[test]
    fn decode_persistentvolume_proto_gen_preserves_capacity_claim_ref_affinity_and_local_source() {
        let pv = core_v1::PersistentVolume {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("local-pv".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PersistentVolumeSpec {
                capacity: std::collections::HashMap::from([(
                    "storage".to_string(),
                    u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                        string: Some("5Gi".to_string()),
                    },
                )]),
                claim_ref: Some(core_v1::ObjectReference {
                    name: Some("my-pvc".to_string()),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                }),
                node_affinity: Some(core_v1::VolumeNodeAffinity {
                    required: Some(core_v1::NodeSelector {
                        node_selector_terms: vec![core_v1::NodeSelectorTerm {
                            match_expressions: vec![core_v1::NodeSelectorRequirement {
                                key: Some("kubernetes.io/hostname".to_string()),
                                operator: Some("In".to_string()),
                                values: vec!["node-1".to_string()],
                            }],
                            ..Default::default()
                        }],
                    }),
                }),
                persistent_volume_source: Some(core_v1::PersistentVolumeSource {
                    local: Some(core_v1::LocalVolumeSource {
                        path: Some("/mnt/disks/vol1".to_string()),
                        fs_type: Some("ext4".to_string()),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pv.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolume_proto_gen(&buf).expect("PV with spec must decode");

        assert_eq!(
            result["spec"]["capacity"]["storage"], "5Gi",
            "spec.capacity must survive proto decode — without it every PV looks like it has \
             zero storage, so static PV/PVC matching always rejects it as too small"
        );
        assert_eq!(
            result["spec"]["claimRef"]["name"], "my-pvc",
            "spec.claimRef must survive proto decode — without it a test's explicit PV-to-PVC \
             pre-bind is silently lost"
        );
        assert_eq!(
            result["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"]
                [0]["key"],
            "kubernetes.io/hostname",
            "spec.nodeAffinity must survive proto decode — without it kubelet has no way to \
             know which node a local PV may be mounted from"
        );
        assert_eq!(
            result["spec"]["local"]["path"], "/mnt/disks/vol1",
            "spec.local (the local volume source) must survive proto decode — without it \
             kubelet has no path to bind-mount for a local PV"
        );
    }

    /// decode_persistentvolume_proto_gen must preserve the `csi` (CSIPersistentVolumeSource)
    /// volume source.
    ///
    /// Before this fix, a protobuf-encoded PV create (client-go's default wire format, used
    /// by external-provisioner for every dynamically-provisioned CSI volume) silently lost
    /// spec.csi entirely — the decoder handled local/hostPath/nfs but not csi. A live
    /// conformance repro against csi-hostpath showed the PVC actually reaching Bound (the
    /// binder itself works), but the pod then failed to start with kubelet event
    /// "failed to get Plugin from volumeSpec ... no volume plugin matched", because the
    /// stored PV had no volume source at all for kubelet's CSI plugin to recognize.
    #[test]
    fn decode_persistentvolume_proto_gen_preserves_csi_source() {
        let pv = core_v1::PersistentVolume {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("csi-pv".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PersistentVolumeSpec {
                persistent_volume_source: Some(core_v1::PersistentVolumeSource {
                    csi: Some(core_v1::CsiPersistentVolumeSource {
                        driver: Some("hostpath.csi.k8s.io".to_string()),
                        volume_handle: Some("pvc-1234".to_string()),
                        read_only: Some(false),
                        fs_type: Some("ext4".to_string()),
                        volume_attributes: std::collections::HashMap::from([(
                            "storage.kubernetes.io/csiProvisionerIdentity".to_string(),
                            "1234-hostpath".to_string(),
                        )]),
                        node_publish_secret_ref: Some(core_v1::SecretReference {
                            name: Some("node-publish-secret".to_string()),
                            namespace: Some("default".to_string()),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pv.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolume_proto_gen(&buf).expect("PV with csi must decode");

        assert_eq!(
            result["spec"]["csi"]["driver"], "hostpath.csi.k8s.io",
            "spec.csi.driver must survive proto decode — kubelet's volume plugin manager \
             selects the CSI plugin by checking this field is non-nil; without it the pod \
             fails admission with \"no volume plugin matched\" even though the PVC is Bound"
        );
        assert_eq!(
            result["spec"]["csi"]["volumeHandle"], "pvc-1234",
            "spec.csi.volumeHandle must survive proto decode — it is the only identifier \
             the CSI driver has to locate the actual backing volume on NodeStageVolume/\
             NodePublishVolume"
        );
        assert_eq!(
            result["spec"]["csi"]["fsType"], "ext4",
            "spec.csi.fsType must survive proto decode"
        );
        assert_eq!(
            result["spec"]["csi"]["volumeAttributes"]
                ["storage.kubernetes.io/csiProvisionerIdentity"],
            "1234-hostpath",
            "spec.csi.volumeAttributes must survive proto decode — CSI drivers rely on these \
             to make correct NodeStageVolume/NodePublishVolume calls"
        );
        assert_eq!(
            result["spec"]["csi"]["nodePublishSecretRef"]["name"], "node-publish-secret",
            "spec.csi.nodePublishSecretRef must survive proto decode for drivers that require \
             credentials on NodePublishVolume"
        );
    }

    /// decode_persistentvolume_proto_gen must survive PersistentVolume::sentinel() producing
    /// exactly the keys the .proto schema defines, not a hand-typed subset that could go stale
    /// the same way PodStatus's did (mayor-y0pcm).
    ///
    /// This reaches zero KNOWN_GAPS only because mayor-hfoid (legacy-volume
    /// DELIBERATE_OMISSIONS) and mayor-p0dyr (persistentVolumeSource INLINE_EMBEDS) already
    /// landed; lastPhaseTransitionTime was PersistentVolume's last real gap.
    #[test]
    fn sentinel_completeness_decode_persistentvolume_proto_gen() {
        let pv = core_v1::PersistentVolume::sentinel();
        let mut buf = Vec::new();
        pv.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_persistentvolume_proto_gen(&buf).expect("sentinel PV must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.core.v1.PersistentVolume",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
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

    /// A projected volume's `sources[].podCertificate` (PodCertificateProjection) must survive
    /// proto decode.
    ///
    /// Before this fix, the whole `sources[]` entry was silently dropped: a pod using this
    /// (1.34+ alpha) auto-rotating TLS credential projection would mount an empty projected
    /// volume with no error, leaving the workload with no key/certificate at the path it
    /// expected.
    #[test]
    fn generated_pod_spec_preserves_projected_pod_certificate_source() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("podcert-pod".to_string()),
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
                    name: Some("podcert-vol".to_string()),
                    volume_source: Some(core_v1::VolumeSource {
                        projected: Some(core_v1::ProjectedVolumeSource {
                            sources: vec![core_v1::VolumeProjection {
                                pod_certificate: Some(core_v1::PodCertificateProjection {
                                    signer_name: Some("example.com/signer".to_string()),
                                    key_type: Some("ECDSAP256".to_string()),
                                    max_expiration_seconds: Some(86400),
                                    credential_bundle_path: Some("bundle.pem".to_string()),
                                    key_path: Some("key.pem".to_string()),
                                    certificate_chain_path: Some("chain.pem".to_string()),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }],
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

        let result = decode_pod_proto_gen(&buf).expect("Pod with podCertificate must decode");

        let pc = &result["spec"]["volumes"][0]["projected"]["sources"][0]["podCertificate"];
        assert_eq!(
            pc["signerName"], "example.com/signer",
            "podCertificate.signerName must survive decode — before this fix the whole \
             sources[] entry was dropped, leaving the workload with no credential at all"
        );
        assert_eq!(
            pc["keyType"], "ECDSAP256",
            "podCertificate.keyType must survive decode"
        );
        assert_eq!(
            pc["maxExpirationSeconds"], 86400,
            "podCertificate.maxExpirationSeconds must survive decode"
        );
        assert_eq!(
            pc["credentialBundlePath"], "bundle.pem",
            "podCertificate.credentialBundlePath must survive decode"
        );
        assert_eq!(
            pc["keyPath"], "key.pem",
            "podCertificate.keyPath must survive decode"
        );
        assert_eq!(
            pc["certificateChainPath"], "chain.pem",
            "podCertificate.certificateChainPath must survive decode"
        );
    }

    /// A projected volume's `sources[].clusterTrustBundle` (ClusterTrustBundleProjection) must
    /// survive proto decode.
    ///
    /// Before this fix, the whole `sources[]` entry was silently dropped: a pod that projected
    /// a CA trust bundle by signer name/label selector would mount an empty projected volume,
    /// so TLS verification against that bundle would fail with no indication why.
    #[test]
    fn generated_pod_spec_preserves_projected_cluster_trust_bundle_source() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("ctb-pod".to_string()),
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
                    name: Some("ctb-vol".to_string()),
                    volume_source: Some(core_v1::VolumeSource {
                        projected: Some(core_v1::ProjectedVolumeSource {
                            sources: vec![core_v1::VolumeProjection {
                                cluster_trust_bundle: Some(core_v1::ClusterTrustBundleProjection {
                                    signer_name: Some("example.com/signer".to_string()),
                                    label_selector: Some(meta_v1::LabelSelector {
                                        match_labels: [(
                                            "release".to_string(),
                                            "stable".to_string(),
                                        )]
                                        .into_iter()
                                        .collect(),
                                        ..Default::default()
                                    }),
                                    optional: Some(true),
                                    path: Some("trust.pem".to_string()),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }],
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

        let result = decode_pod_proto_gen(&buf).expect("Pod with clusterTrustBundle must decode");

        let ctb = &result["spec"]["volumes"][0]["projected"]["sources"][0]["clusterTrustBundle"];
        assert_eq!(
            ctb["signerName"], "example.com/signer",
            "clusterTrustBundle.signerName must survive decode — before this fix the whole \
             sources[] entry was dropped, so TLS verification against the bundle would fail \
             with no indication why"
        );
        assert_eq!(
            ctb["labelSelector"]["matchLabels"]["release"], "stable",
            "clusterTrustBundle.labelSelector must survive decode"
        );
        assert_eq!(
            ctb["optional"], true,
            "clusterTrustBundle.optional must survive decode"
        );
        assert_eq!(
            ctb["path"], "trust.pem",
            "clusterTrustBundle.path must survive decode"
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

    /// decode_pod_proto_gen must preserve spec.volumes[i].nfs (VolumeSource field 7).
    ///
    /// client-go's typed Pod client sends protobuf by default. Without this branch,
    /// a Pod created with an NFS-backed volume (e.g. by a controller that mounts a shared
    /// NFS export into a pod template) would decode with the volume source silently
    /// dropped, leaving kubelet unable to resolve the mount and the container stuck
    /// waiting on a volume that, per the stored object, was never even requested.
    #[test]
    fn pod_volume_nfs_survives_protobuf_decode_or_nfs_mount_silently_dropped_from_pod_spec() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("nfs-pod".to_string()),
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
                    name: Some("nfs-vol".to_string()),
                    volume_source: Some(core_v1::VolumeSource {
                        nfs: Some(core_v1::NfsVolumeSource {
                            server: Some("nfs.example.com".to_string()),
                            path: Some("/exports/data".to_string()),
                            read_only: Some(true),
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

        let result = decode_pod_proto_gen(&buf).expect("Pod with an nfs volume must decode");

        let nfs = &result["spec"]["volumes"][0]["nfs"];
        assert_eq!(
            nfs["server"], "nfs.example.com",
            "nfs.server must survive protobuf decode — without it kubelet has no host to mount from"
        );
        assert_eq!(
            nfs["path"], "/exports/data",
            "nfs.path must survive protobuf decode — without it kubelet has no export to mount"
        );
        assert_eq!(
            nfs["readOnly"], true,
            "nfs.readOnly must survive protobuf decode — losing it silently turns a read-only \
             mount into a writable one"
        );
    }

    /// decode_pod_proto_gen must preserve spec.schedulerName (PodSpec field 19).
    ///
    /// client-go's typed Pod client sends protobuf by default, unlike kubectl (JSON). A pod
    /// that asks for a non-default scheduler (e.g. a batch/GPU scheduler) but has this field
    /// dropped on decode is silently left for the built-in scheduler to pick up instead,
    /// changing which component binds it and defeating the workload's scheduling setup.
    #[test]
    fn generated_pod_spec_preserves_scheduler_name() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("custom-scheduler-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                scheduler_name: Some("my-scheduler".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["schedulerName"], "my-scheduler",
            "schedulerName must survive protobuf decode — without it a pod requesting a \
             non-default scheduler is silently handled by the built-in scheduler instead"
        );
    }

    /// decode_pod_proto_gen must preserve VolumeMount.mountPropagation (field 5).
    ///
    /// client-go's typed Clientset (used by e.g. the Kubernetes CSI e2e storage-test
    /// framework to create a fresh driver StatefulSet per test) sends protobuf by default.
    /// Dropping mountPropagation: Bidirectional on decode silently downgrades the driver's
    /// volumeMount to None, so bind mounts the driver later performs under that tree can
    /// never propagate into kubelet's mount namespace — kubelet then reads a stale
    /// placeholder and EBUSYs forever trying to unmount it.
    #[test]
    fn generated_pod_spec_preserves_volume_mount_propagation() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("bidirectional-mount-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    volume_mounts: vec![core_v1::VolumeMount {
                        name: Some("plugins-dir".to_string()),
                        mount_path: Some("/var/lib/kubelet/plugins".to_string()),
                        mount_propagation: Some("Bidirectional".to_string()),
                        ..Default::default()
                    }],
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
            result["spec"]["containers"][0]["volumeMounts"][0]["mountPropagation"], "Bidirectional",
            "mountPropagation=Bidirectional must survive protobuf decode — without it a CSI \
             driver's own bind mounts under the volume never propagate into kubelet's mount \
             namespace, causing kubelet to EBUSY forever unmounting a stale placeholder"
        );
    }

    /// decode_pod_proto_gen must preserve VolumeMount.recursiveReadOnly (field 7).
    ///
    /// Dropping this on decode silently reverts a container that required a recursively
    /// read-only mount to the default (non-recursive) behavior, letting it write through
    /// nested mounts the client explicitly asked to lock down.
    #[test]
    fn generated_pod_spec_preserves_volume_mount_recursive_read_only() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("recursive-ro-mount-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    volume_mounts: vec![core_v1::VolumeMount {
                        name: Some("secret-dir".to_string()),
                        mount_path: Some("/etc/secret".to_string()),
                        read_only: Some(true),
                        recursive_read_only: Some("Enabled".to_string()),
                        ..Default::default()
                    }],
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
            result["spec"]["containers"][0]["volumeMounts"][0]["recursiveReadOnly"], "Enabled",
            "recursiveReadOnly=Enabled must survive protobuf decode — without it a container \
             that required a recursively read-only mount silently gets a non-recursive one, \
             leaving nested mounts writable despite the client's explicit request"
        );
    }

    /// decode_pod_proto_gen must preserve spec.hostPID/hostIPC/shareProcessNamespace
    /// (PodSpec fields 12, 13, 27).
    ///
    /// These are namespace-sharing toggles the kubelet reads when starting containers.
    /// Dropping hostPID/hostIPC on decode silently re-isolates a pod that asked to observe
    /// the host's process/IPC namespace (breaking debug/monitoring pods that rely on it);
    /// dropping shareProcessNamespace silently re-isolates sibling containers from each
    /// other, breaking sidecar patterns that signal or trace another container's PID 1.
    #[test]
    fn generated_pod_spec_preserves_host_pid_host_ipc_and_share_process_namespace() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("host-namespaces-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                host_pid: Some(true),
                host_ipc: Some(true),
                share_process_namespace: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["hostPID"], true,
            "hostPID must survive decode — without it a pod that needs the host's process \
             namespace for debugging silently runs isolated instead"
        );
        assert_eq!(
            result["spec"]["hostIPC"], true,
            "hostIPC must survive decode — without it a pod that needs the host's IPC \
             namespace silently runs isolated instead"
        );
        assert_eq!(
            result["spec"]["shareProcessNamespace"], true,
            "shareProcessNamespace must survive decode — without it sidecar containers that \
             expect to see/signal each other's processes silently cannot"
        );
    }

    /// decode_pod_proto_gen must preserve spec.imagePullSecrets (PodSpec field 15) — distinct
    /// from ServiceAccount.imagePullSecrets, which is already covered elsewhere.
    ///
    /// Dropping the pod's own explicit list on decode makes the kubelet attempt an
    /// unauthenticated pull against a private registry and ImagePullBackOff the pod even
    /// though the client supplied working credentials.
    #[test]
    fn generated_pod_spec_preserves_image_pull_secrets() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("private-image-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("private.example.com/img".to_string()),
                    ..Default::default()
                }],
                image_pull_secrets: vec![core_v1::LocalObjectReference {
                    name: Some("registry-cred".to_string()),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["imagePullSecrets"][0]["name"], "registry-cred",
            "spec.imagePullSecrets must survive decode — without it the kubelet cannot \
             authenticate the private-registry pull and the pod gets stuck in \
             ImagePullBackOff despite the client supplying credentials"
        );
    }

    /// decode_pod_proto_gen must preserve the deprecated spec.serviceAccount alias (PodSpec
    /// field 9), separate from spec.serviceAccountName.
    ///
    /// A legacy client that only ever sets this deprecated field (never serviceAccountName)
    /// has its ServiceAccount choice silently discarded on decode if this field is dropped.
    #[test]
    fn generated_pod_spec_preserves_deprecated_service_account_alias() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("legacy-sa-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                service_account: Some("legacy-sa".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["serviceAccount"], "legacy-sa",
            "the deprecated spec.serviceAccount alias must survive decode — a legacy client \
             that only sets this field (not serviceAccountName) must not silently lose its \
             ServiceAccount choice"
        );
    }

    /// decode_pod_proto_gen must preserve spec.preemptionPolicy (PodSpec field 31).
    ///
    /// Dropping an explicit "Never" on decode silently reverts the pod to the cluster
    /// default (PreemptLowerPriority), letting it preempt other pods despite the client
    /// explicitly opting out of preemption.
    #[test]
    fn generated_pod_spec_preserves_preemption_policy() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-preempt-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                preemption_policy: Some("Never".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["preemptionPolicy"], "Never",
            "preemptionPolicy=Never must survive decode — dropping it silently reverts to \
             the cluster default of allowing this pod to preempt lower-priority pods"
        );
    }

    /// decode_pod_proto_gen must preserve spec.topologySpreadConstraints (PodSpec field 33),
    /// including the nested labelSelector's matchLabels and matchExpressions.
    ///
    /// Dropping this makes the scheduler treat a pod that asked to be spread across zones as
    /// unconstrained, letting every replica land in the same zone/node and silently
    /// defeating the availability guarantee pod-topology-spread conformance tests assert on.
    #[test]
    fn generated_pod_spec_preserves_topology_spread_constraints() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("spread-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                topology_spread_constraints: vec![core_v1::TopologySpreadConstraint {
                    max_skew: Some(1),
                    topology_key: Some("topology.kubernetes.io/zone".to_string()),
                    when_unsatisfiable: Some("DoNotSchedule".to_string()),
                    label_selector: Some(meta_v1::LabelSelector {
                        match_labels: [("app".to_string(), "demo".to_string())]
                            .into_iter()
                            .collect(),
                        match_expressions: vec![meta_v1::LabelSelectorRequirement {
                            key: Some("tier".to_string()),
                            operator: Some("In".to_string()),
                            values: vec!["frontend".to_string()],
                        }],
                    }),
                    min_domains: Some(2),
                    node_affinity_policy: Some("Honor".to_string()),
                    node_taints_policy: Some("Ignore".to_string()),
                    match_label_keys: vec!["pod-template-hash".to_string()],
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        let c = &result["spec"]["topologySpreadConstraints"][0];
        assert_eq!(
            c["maxSkew"], 1,
            "maxSkew must survive decode — the scheduler needs it to compute the allowed skew"
        );
        assert_eq!(
            c["topologyKey"], "topology.kubernetes.io/zone",
            "topologyKey must survive decode — without it the scheduler doesn't know which \
             domain to spread across"
        );
        assert_eq!(
            c["whenUnsatisfiable"], "DoNotSchedule",
            "whenUnsatisfiable must survive decode — dropping it silently turns a hard \
             spreading requirement into no constraint at all"
        );
        assert_eq!(
            c["labelSelector"]["matchLabels"]["app"], "demo",
            "labelSelector.matchLabels must survive decode — without it the scheduler counts \
             the wrong set of pods when computing skew"
        );
        assert_eq!(
            c["labelSelector"]["matchExpressions"][0],
            serde_json::json!({"key": "tier", "operator": "In", "values": ["frontend"]}),
            "labelSelector.matchExpressions must survive decode — a spread constraint \
             expressed purely via matchExpressions must not be silently treated as an \
             empty (matches-everything) selector"
        );
        assert_eq!(c["minDomains"], 2, "minDomains must survive decode");
        assert_eq!(
            c["nodeAffinityPolicy"], "Honor",
            "nodeAffinityPolicy must survive decode"
        );
        assert_eq!(
            c["nodeTaintsPolicy"], "Ignore",
            "nodeTaintsPolicy must survive decode"
        );
        assert_eq!(
            c["matchLabelKeys"][0], "pod-template-hash",
            "matchLabelKeys must survive decode"
        );
    }

    /// decode_pod_proto_gen must preserve spec.affinity.podAffinity/podAntiAffinity
    /// (Affinity fields 2 and 3), not just nodeAffinity.
    ///
    /// This is a JSON round-trip fix only — crates/scheduler does not enforce pod
    /// (anti-)affinity yet, so this test does not claim scheduling behavior changed. Before
    /// this fix, a client that set only podAffinity/podAntiAffinity (no nodeAffinity) on a
    /// protobuf-encoded pod create got back `spec.affinity: {}` on a subsequent GET — the
    /// value it wrote was silently gone.
    #[test]
    fn generated_pod_spec_preserves_pod_affinity_and_anti_affinity() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("colocate-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                affinity: Some(core_v1::Affinity {
                    pod_affinity: Some(core_v1::PodAffinity {
                        required_during_scheduling_ignored_during_execution: vec![
                            core_v1::PodAffinityTerm {
                                label_selector: Some(meta_v1::LabelSelector {
                                    match_labels: [("app".to_string(), "cache".to_string())]
                                        .into_iter()
                                        .collect(),
                                    ..Default::default()
                                }),
                                namespaces: vec!["shared".to_string()],
                                topology_key: Some("kubernetes.io/hostname".to_string()),
                                namespace_selector: Some(meta_v1::LabelSelector {
                                    match_labels: [(
                                        "kubernetes.io/metadata.name".to_string(),
                                        "shared".to_string(),
                                    )]
                                    .into_iter()
                                    .collect(),
                                    ..Default::default()
                                }),
                                mismatch_label_keys: vec!["pod-template-hash".to_string()],
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    }),
                    pod_anti_affinity: Some(core_v1::PodAntiAffinity {
                        preferred_during_scheduling_ignored_during_execution: vec![
                            core_v1::WeightedPodAffinityTerm {
                                weight: Some(50),
                                pod_affinity_term: Some(core_v1::PodAffinityTerm {
                                    topology_key: Some("topology.kubernetes.io/zone".to_string()),
                                    ..Default::default()
                                }),
                            },
                        ],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        let required = &result["spec"]["affinity"]["podAffinity"]
            ["requiredDuringSchedulingIgnoredDuringExecution"][0];
        assert_eq!(
            required["labelSelector"]["matchLabels"]["app"], "cache",
            "podAffinity.requiredDuringSchedulingIgnoredDuringExecution[].labelSelector must \
             survive decode — before this fix the whole podAffinity key was dropped"
        );
        assert_eq!(
            required["namespaces"][0], "shared",
            "podAffinityTerm.namespaces must survive decode"
        );
        assert_eq!(
            required["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"], "shared",
            "podAffinityTerm.namespaceSelector must survive decode"
        );
        assert_eq!(
            required["mismatchLabelKeys"][0], "pod-template-hash",
            "podAffinityTerm.mismatchLabelKeys must survive decode"
        );

        let preferred = &result["spec"]["affinity"]["podAntiAffinity"]
            ["preferredDuringSchedulingIgnoredDuringExecution"][0];
        assert_eq!(
            preferred["weight"], 50,
            "podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[].weight must \
             survive decode — before this fix the whole podAntiAffinity key was dropped"
        );
        assert_eq!(
            preferred["podAffinityTerm"]["topologyKey"], "topology.kubernetes.io/zone",
            "podAntiAffinity's nested podAffinityTerm must survive decode"
        );
    }

    /// decode_pod_proto_gen must preserve spec.readinessGates (PodSpec field 28).
    ///
    /// Dropping this makes the pod report Ready as soon as its containers are, ignoring an
    /// extra condition a workload controller (e.g. one injecting a sidecar) depends on being
    /// evaluated before the pod is considered Ready.
    #[test]
    fn generated_pod_spec_preserves_readiness_gates() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("readiness-gated-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                readiness_gates: vec![core_v1::PodReadinessGate {
                    condition_type: Some("www.example.com/feature-1".to_string()),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["readinessGates"][0]["conditionType"], "www.example.com/feature-1",
            "readinessGates must survive decode — without it the pod is marked Ready before \
             the extra condition the workload controller depends on is ever evaluated"
        );
    }

    /// decode_pod_proto_gen must preserve spec.overhead (PodSpec field 32) exactly as sent by
    /// the client — distinct from the value apply_runtime_class_overhead injects from the
    /// RuntimeClass object at admission time (see proto.rs/pods.rs tests for that path).
    ///
    /// Dropping the client-supplied value here erases scheduling accounting the client
    /// already computed and sent before admission ever runs.
    #[test]
    fn generated_pod_spec_preserves_overhead() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("overhead-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                overhead: std::collections::HashMap::from([(
                    "cpu".to_string(),
                    u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                        string: Some("250m".to_string()),
                    },
                )]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["overhead"]["cpu"], "250m",
            "spec.overhead must survive decode — dropping a client-supplied value here \
             erases scheduling accounting the client already computed before admission runs"
        );
    }

    /// decode_pod_proto_gen must preserve spec.os (PodSpec field 36, PodOS.name).
    ///
    /// Dropping it makes OS-conditional validation (which fields are legal on Linux vs
    /// Windows pods) silently permissive for the OS the client actually declared.
    #[test]
    fn generated_pod_spec_preserves_os() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("windows-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                os: Some(core_v1::PodOs {
                    name: Some("windows".to_string()),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["os"]["name"], "windows",
            "spec.os.name must survive decode — without it OS-conditional field validation \
             silently applies the wrong OS's rules to this pod"
        );
    }

    /// decode_pod_proto_gen must preserve spec.resourceClaims (PodSpec field 39).
    ///
    /// Dropping this means a container's `resources.claims[].name` reference resolves to
    /// nothing, so the pod starts without ever reserving the DRA device/resource the client
    /// asked for.
    #[test]
    fn generated_pod_spec_preserves_resource_claims() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("dra-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                resource_claims: vec![core_v1::PodResourceClaim {
                    name: Some("gpu".to_string()),
                    resource_claim_name: Some("shared-gpu-claim".to_string()),
                    resource_claim_template_name: None,
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["resourceClaims"][0]["name"], "gpu",
            "resourceClaims[].name must survive decode — without it a container's \
             resources.claims[].name reference resolves to nothing"
        );
        assert_eq!(
            result["spec"]["resourceClaims"][0]["resourceClaimName"], "shared-gpu-claim",
            "resourceClaims[].resourceClaimName must survive decode — without it the pod \
             never reserves the DRA resource the client asked for"
        );
    }

    /// decode_pod_proto_gen must preserve an explicit spec.hostUsers=false (PodSpec field 37).
    ///
    /// hostUsers defaults to true upstream, so false is the only value that changes behavior:
    /// dropping it on decode silently puts the pod back in the host user namespace, undoing a
    /// client's explicit userns-isolation opt-in used to mitigate container breakout.
    #[test]
    fn generated_pod_spec_preserves_host_users_false() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("userns-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                host_users: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["hostUsers"], false,
            "hostUsers=false must survive decode — without it the pod silently runs in the \
             host user namespace despite the client explicitly isolating it"
        );
    }

    /// decode_pod_proto_gen must omit spec.hostUsers when the client never set it.
    ///
    /// hostUsers is a genuine `*bool` upstream (unlike hostNetwork's plain bool), so unlike
    /// the hostNetwork zero-value case, prost only produces `Some` here when the wire actually
    /// carried the field — a regression that always emits the key (e.g. defaulting to `false`)
    /// would fabricate a userns opt-in the client never asked for.
    #[test]
    fn generated_pod_spec_omits_host_users_when_unset() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-userns-opinion-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                host_users: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert!(
            result["spec"].get("hostUsers").is_none(),
            "hostUsers must be omitted when the client never set it — materializing a key \
             here fabricates an opinion the client never expressed"
        );
    }

    /// decode_pod_proto_gen must preserve an explicit spec.setHostnameAsFQDN=true (PodSpec
    /// field 35).
    ///
    /// setHostnameAsFQDN defaults to false upstream, so true is the value that changes kernel
    /// behavior: dropping it on decode silently keeps the leaf hostname instead of the FQDN
    /// the client asked the kubelet to set in the container's kernel hostname.
    #[test]
    fn generated_pod_spec_preserves_set_hostname_as_fqdn() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("fqdn-hostname-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                set_hostname_as_fqdn: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["setHostnameAsFQDN"], true,
            "setHostnameAsFQDN=true must survive decode — without it the kubelet silently \
             sets the kernel hostname to the leaf name instead of the FQDN the client asked for"
        );
    }

    /// decode_pod_proto_gen must omit spec.setHostnameAsFQDN when the client never set it —
    /// same genuine-`*bool` reasoning as the hostUsers omission test above.
    #[test]
    fn generated_pod_spec_omits_set_hostname_as_fqdn_when_unset() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-fqdn-opinion-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                set_hostname_as_fqdn: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert!(
            result["spec"].get("setHostnameAsFQDN").is_none(),
            "setHostnameAsFQDN must be omitted when the client never set it — materializing a \
             key here fabricates an opinion the client never expressed"
        );
    }

    /// decode_pod_proto_gen must preserve spec.hostnameOverride (PodSpec field 41, alpha
    /// HostnameOverride feature gate).
    ///
    /// This field takes precedence over hostname/subdomain for what the pod perceives as its
    /// own hostname; dropping it on decode silently falls back to the name the client
    /// explicitly asked to override.
    #[test]
    fn generated_pod_spec_preserves_hostname_override() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("hostname-override-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                hostname_override: Some("worker-1.example.com".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["hostnameOverride"], "worker-1.example.com",
            "hostnameOverride must survive decode — without it the pod silently keeps the \
             name the client explicitly asked to override"
        );
    }

    /// decode_pod_proto_gen must omit spec.hostnameOverride when the client never set it.
    #[test]
    fn generated_pod_spec_omits_hostname_override_when_unset() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-hostname-override-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                hostname_override: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert!(
            result["spec"].get("hostnameOverride").is_none(),
            "hostnameOverride must be omitted when the client never set it — materializing an \
             empty override key could be mistaken for an explicit override to nothing"
        );
    }

    /// decode_pod_proto_gen must preserve spec.resources (PodSpec field 40, pod-level
    /// ResourceRequirements, alpha PodLevelResources feature gate).
    ///
    /// Unlike Container.Resources (a value type upstream, handled by the omit-when-empty
    /// container-resources decoder above), PodSpec.Resources is a genuine `*ResourceRequirements`
    /// pointer, so dropping it on decode silently discards resource sharing the client
    /// configured across every container in the pod, not just one container's own limits.
    #[test]
    fn generated_pod_spec_preserves_pod_level_resources() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("pod-level-resources-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                resources: Some(core_v1::ResourceRequirements {
                    limits: std::collections::HashMap::from([(
                        "cpu".to_string(),
                        u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                            string: Some("500m".to_string()),
                        },
                    )]),
                    requests: std::collections::HashMap::from([(
                        "cpu".to_string(),
                        u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                            string: Some("250m".to_string()),
                        },
                    )]),
                    claims: vec![],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["resources"]["limits"]["cpu"], "500m",
            "spec.resources.limits must survive decode — without it pod-level CPU sharing \
             across all containers is silently discarded"
        );
        assert_eq!(
            result["spec"]["resources"]["requests"]["cpu"], "250m",
            "spec.resources.requests must survive decode — without it pod-level CPU sharing \
             across all containers is silently discarded"
        );
    }

    /// decode_pod_proto_gen must omit spec.resources when the client never set it — a
    /// regression that materializes `resources: {}` here would make a protobuf-decoded pod
    /// template fail a structural-equality diff against an equivalent JSON-decoded one, the
    /// same hash-collision hazard documented on the container-resources omit-when-empty test.
    #[test]
    fn generated_pod_spec_omits_pod_level_resources_when_unset() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-pod-level-resources-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                resources: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert!(
            result["spec"].get("resources").is_none(),
            "spec.resources must be omitted when the client never set it — materializing an \
             empty object here breaks structural-equality diffs against a JSON-created \
             equivalent template"
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
                            u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
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

    /// `priority` is a proto3 `optional int32` upstream (a real `Option<i32>` on the wire, not
    /// a plain non-nullable field like `hostNetwork`), so an explicit 0 (the lowest possible
    /// priority) is real client intent, not noise from an unset field. Filtering it out by
    /// value — as this code used to do — made an explicitly-zero-priority pod indistinguishable
    /// from a pod that never set priority at all, which would let the scheduler's preemption
    /// ordering silently fall back to "no priority" instead of "priority zero".
    #[test]
    fn generated_pod_spec_preserves_zero_priority() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("zero-priority-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                priority: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert_eq!(
            result["spec"]["priority"], 0,
            "an explicit priority of 0 must survive protobuf decode — treating it like an \
             unset value would make the scheduler's preemption ordering silently ignore the \
             client's explicit choice"
        );
    }

    /// A pod that never sets `priority` at all must decode with the field absent, not with a
    /// fabricated 0 — otherwise every priority-unset pod would look identical to one that
    /// explicitly asked for priority 0, which is the exact ambiguity this fix removes.
    #[test]
    fn generated_pod_spec_omits_priority_when_never_set() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-priority-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                priority: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod must decode");

        assert!(
            result["spec"].get("priority").is_none(),
            "priority must be omitted when the client never set it — fabricating a value here \
             would make an unset priority indistinguishable from an explicit 0"
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

    /// EphemeralVolumeSource (spec.volumes[].ephemeral, the GenericEphemeralVolume feature)
    /// must survive proto decode.
    ///
    /// The volume-source match had no branch for it at all, so a pod created via a protobuf
    /// client (client-go typed clientsets default to protobuf, which is what the e2e test
    /// framework and kube-controller-manager itself use) silently lost the
    /// volumeClaimTemplate on decode. Real kube-controller-manager's ephemeral-volume-
    /// controller only enqueues a pod when it observes `vol.Ephemeral != nil` on the stored
    /// Pod object — with the field missing, it never fires, the derived PVC
    /// (`<pod>-<volume>`) is never created, and the pod is stuck ContainerCreating forever
    /// waiting on a PVC that will never exist.
    #[test]
    fn generated_pod_spec_preserves_ephemeral_volume_source() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("ephemeral-vol-pod".to_string()),
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
                    name: Some("my-volume".to_string()),
                    volume_source: Some(core_v1::VolumeSource {
                        ephemeral: Some(core_v1::EphemeralVolumeSource {
                            volume_claim_template: Some(core_v1::PersistentVolumeClaimTemplate {
                                spec: Some(core_v1::PersistentVolumeClaimSpec {
                                    access_modes: vec!["ReadWriteOnce".to_string()],
                                    resources: Some(core_v1::VolumeResourceRequirements {
                                        requests: std::collections::HashMap::from([(
                                            "storage".to_string(),
                                            u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                                                string: Some("1Gi".to_string()),
                                            },
                                        )]),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
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

        let result = decode_pod_proto_gen(&buf).expect("Pod with ephemeral volume must decode");

        let volumes = result["spec"]["volumes"].as_array().unwrap();
        assert_eq!(
            volumes[0]["ephemeral"]["volumeClaimTemplate"]["spec"]["accessModes"][0],
            "ReadWriteOnce",
            "spec.volumes[].ephemeral.volumeClaimTemplate must survive decode — without it \
             KCM's ephemeral-volume-controller never sees a reason to auto-create the pod's \
             derived PersistentVolumeClaim, and the pod is stuck ContainerCreating forever"
        );
        assert_eq!(
            volumes[0]["ephemeral"]["volumeClaimTemplate"]["spec"]["resources"]["requests"]
                ["storage"],
            "1Gi",
            "the volumeClaimTemplate's storage request must survive decode unchanged so the \
             generated PVC asks for the size the pod author specified"
        );
    }

    /// CSIVolumeSource (spec.volumes[].csi, the CSI Ephemeral-volume feature) must survive
    /// proto decode.
    ///
    /// The volume-source match had no branch for it at all, so a pod created via a
    /// protobuf client (client-go typed clientsets default to protobuf, which is what the
    /// e2e test framework uses) silently lost the entire inline CSI volume source on
    /// decode. The stored Pod ends up with no volume source at all, so the kubelet's
    /// volume plugin manager can never resolve the mount the container is waiting on, and
    /// the pod is stuck at ContainerCreating until the PodStart timeout.
    #[test]
    fn generated_pod_spec_preserves_csi_volume_source() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("csi-vol-pod".to_string()),
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
                    name: Some("my-csi-volume".to_string()),
                    volume_source: Some(core_v1::VolumeSource {
                        csi: Some(core_v1::CsiVolumeSource {
                            driver: Some("csi-hostpath".to_string()),
                            read_only: Some(true),
                            fs_type: Some("ext4".to_string()),
                            volume_attributes: std::collections::HashMap::from([(
                                "foo".to_string(),
                                "bar".to_string(),
                            )]),
                            node_publish_secret_ref: Some(core_v1::LocalObjectReference {
                                name: Some("csi-secret".to_string()),
                            }),
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

        let result = decode_pod_proto_gen(&buf).expect("Pod with csi volume must decode");

        let volumes = result["spec"]["volumes"].as_array().unwrap();
        assert_eq!(
            volumes[0]["csi"]["driver"], "csi-hostpath",
            "spec.volumes[].csi.driver must survive decode — without it the kubelet's \
             volume plugin manager has no driver name to dispatch NodePublishVolume to, \
             and the pod is stuck ContainerCreating forever"
        );
        assert_eq!(
            volumes[0]["csi"]["readOnly"], true,
            "spec.volumes[].csi.readOnly must survive decode — losing it would silently \
             mount a volume read-write that the pod author explicitly asked to be read-only"
        );
        assert_eq!(
            volumes[0]["csi"]["fsType"], "ext4",
            "spec.volumes[].csi.fsType must survive decode — without it the driver falls \
             back to its own default filesystem instead of the one the pod author requested"
        );
        assert_eq!(
            volumes[0]["csi"]["volumeAttributes"]["foo"], "bar",
            "spec.volumes[].csi.volumeAttributes must survive decode — these are the only \
             way to pass driver-specific parameters, and losing them breaks NodePublishVolume \
             for any driver that requires them"
        );
        assert_eq!(
            volumes[0]["csi"]["nodePublishSecretRef"]["name"], "csi-secret",
            "spec.volumes[].csi.nodePublishSecretRef must survive decode — without it the \
             CSI driver's NodePublishVolume call is missing the secret reference it needs \
             and mount authentication fails"
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

    /// `kubectl debug -it`'s stdin/tty flags must survive protobuf decode of the ephemeral
    /// container spec (mayor-nxr7j). Before this fix, `gen_ephemeral_container_to_json` was a
    /// hand-written function that never emitted `stdin`/`stdinOnce`/`tty` at all, so `PUT
    /// .../ephemeralcontainers` (client-go's `UpdateEphemeralContainers`, which negotiates
    /// protobuf by default) silently stripped the interactive-terminal request before it ever
    /// reached storage — the kubelet then never sees `stdin`/`tty: true` and never allocates a
    /// pseudo-terminal for the debug container, so `kubectl debug -it` attaches to a container
    /// that can't actually take interactive input.
    #[test]
    fn generated_pod_spec_preserves_ephemeral_container_stdin_and_tty() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("debug-stdin-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                ephemeral_containers: vec![core_v1::EphemeralContainer {
                    ephemeral_container_common: Some(core_v1::EphemeralContainerCommon {
                        name: Some("debugger".to_string()),
                        image: Some("busybox".to_string()),
                        stdin: Some(true),
                        stdin_once: Some(true),
                        tty: Some(true),
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

        let result =
            decode_pod_proto_gen(&buf).expect("Pod with debug ephemeral container must decode");

        let ec = &result["spec"]["ephemeralContainers"][0];
        assert_eq!(
            ec["stdin"], true,
            "ephemeralContainers[].stdin must survive decode — otherwise `kubectl debug -it` \
             attaches to a debug container the kubelet never allocated a stdin stream for"
        );
        assert_eq!(
            ec["stdinOnce"], true,
            "ephemeralContainers[].stdinOnce must survive decode"
        );
        assert_eq!(
            ec["tty"], true,
            "ephemeralContainers[].tty must survive decode — without it `kubectl debug -it` \
             gets a debug container with no allocated pseudo-terminal, breaking interactive use"
        );
    }

    /// An ephemeral container's probes must survive protobuf decode, same as a regular
    /// container's (mayor-nxr7j: the hand-written `gen_ephemeral_container_to_json` dropped
    /// `livenessProbe`/`readinessProbe`/`startupProbe`/`lifecycle` entirely, even though the
    /// underlying `EphemeralContainerCommon` proto message carries them).
    #[test]
    fn generated_pod_spec_preserves_ephemeral_container_probes() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("debug-probe-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                ephemeral_containers: vec![core_v1::EphemeralContainer {
                    ephemeral_container_common: Some(core_v1::EphemeralContainerCommon {
                        name: Some("debugger".to_string()),
                        image: Some("busybox".to_string()),
                        liveness_probe: Some(core_v1::Probe {
                            initial_delay_seconds: Some(5),
                            ..Default::default()
                        }),
                        readiness_probe: Some(core_v1::Probe {
                            initial_delay_seconds: Some(7),
                            ..Default::default()
                        }),
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

        let result =
            decode_pod_proto_gen(&buf).expect("Pod with ephemeral container probes must decode");

        let ec = &result["spec"]["ephemeralContainers"][0];
        assert_eq!(
            ec["livenessProbe"]["initialDelaySeconds"], 5,
            "ephemeralContainers[].livenessProbe must survive decode"
        );
        assert_eq!(
            ec["readinessProbe"]["initialDelaySeconds"], 7,
            "ephemeralContainers[].readinessProbe must survive decode"
        );
    }

    /// An ephemeral container's `workingDir` (a plain string field) and `resources` (a nested
    /// message field) must also survive decode (mayor-nxr7j) — these are two of the 17 fields
    /// the previous hand-written encoder silently dropped, alongside stdin/tty and the probes
    /// covered by the two tests above.
    #[test]
    fn generated_pod_spec_preserves_ephemeral_container_working_dir_and_resources() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("debug-resources-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                ephemeral_containers: vec![core_v1::EphemeralContainer {
                    ephemeral_container_common: Some(core_v1::EphemeralContainerCommon {
                        name: Some("debugger".to_string()),
                        image: Some("busybox".to_string()),
                        working_dir: Some("/debug".to_string()),
                        resources: Some(core_v1::ResourceRequirements {
                            limits: std::collections::HashMap::from([(
                                "cpu".to_string(),
                                u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                                    string: Some("100m".to_string()),
                                },
                            )]),
                            ..Default::default()
                        }),
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

        let result = decode_pod_proto_gen(&buf)
            .expect("Pod with ephemeral container workingDir/resources must decode");

        let ec = &result["spec"]["ephemeralContainers"][0];
        assert_eq!(
            ec["workingDir"], "/debug",
            "ephemeralContainers[].workingDir must survive decode"
        );
        assert_eq!(
            ec["resources"]["limits"]["cpu"], "100m",
            "ephemeralContainers[].resources must survive decode — ephemeral containers only \
             use spare resources already allocated to the pod, but a client that set an \
             explicit limit must still be able to read it back"
        );
    }

    /// Sentinel completeness for `gen_ephemeral_container_to_json`, gated against the schema
    /// itself the same way `sentinel_completeness_gen_container_to_json` gates `Container` —
    /// `EphemeralContainerCommon` declares the exact same field set as `Container` (mayor-nxr7j).
    /// Before this bead's fix, the hand-written encoder covered only 9 of these 24 fields; this
    /// test pins all of them so any future regression on any one of them fails loudly instead of
    /// hiding behind whichever fields still happened to survive.
    #[test]
    fn sentinel_completeness_gen_ephemeral_container_to_json() {
        let pod = core_v1::Pod {
            spec: Some(core_v1::PodSpec {
                ephemeral_containers: vec![core_v1::EphemeralContainer::sentinel()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();
        let result =
            decode_pod_proto_gen(&buf).expect("sentinel Pod must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result["spec"]["ephemeralContainers"], "", &mut paths);

        let expected = [
            "name",
            "image",
            "command",
            "args",
            "workingDir",
            "ports.containerPort",
            "envFrom.prefix",
            "env.name",
            "resources.claims.name",
            "resizePolicy.resourceName",
            "restartPolicy",
            "restartPolicyRules.action",
            "volumeMounts.mountPropagation",
            "volumeDevices.devicePath",
            "livenessProbe.initialDelaySeconds",
            "readinessProbe.initialDelaySeconds",
            "startupProbe.initialDelaySeconds",
            "lifecycle.postStart.sleep.seconds",
            "terminationMessagePath",
            "terminationMessagePolicy",
            "imagePullPolicy",
            "securityContext.privileged",
            "stdin",
            "stdinOnce",
            "tty",
            "targetContainerName",
        ];
        assert_fields_present(&paths, &expected);
    }

    /// hostNetwork is a plain (non-pointer) bool upstream, unlike the genuine *bool tri-state
    /// fields (automountServiceAccountToken, enableServiceLinks). gogoproto's marshaler for a
    /// non-nullable field can't check "was this set" and always writes it, so every real
    /// protobuf sender (KCM, kubelet, scheduler) puts hostNetwork=false on the wire for pods
    /// that never touched the field at all — decoding that to "hostNetwork": false fabricates
    /// a key the JSON-decoded source object never had. Live-verified via KCM's own
    /// protobuf-encoded ReplicaSet POST: it decoded spec.template.spec to "hostNetwork":
    /// false even though the source Deployment's JSON template had no such key, which throws
    /// off any spec-equality diff downstream.
    #[test]
    fn generated_pod_spec_omits_host_network_when_wire_carries_the_zero_value() {
        let unset_pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("host-network-unset-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                host_network: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        unset_pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod with host_network=false must decode");

        assert!(
            result["spec"].get("hostNetwork").is_none(),
            "hostNetwork must be omitted when the wire only carries the zero value — real \
             protobuf senders always write false for pods that never asked for host \
             networking, so emitting the key here fabricates an explicit false the source \
             object never had"
        );

        let true_pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("host-network-true-pod".to_string()),
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
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf2 = Vec::new();
        true_pod.encode(&mut buf2).unwrap();

        let result2 = decode_pod_proto_gen(&buf2).expect("Pod with host_network=true must decode");

        assert_eq!(
            result2["spec"]["hostNetwork"], true,
            "an explicit hostNetwork=true must still survive decode — true is the only value \
             a plain bool can carry that unambiguously reflects real user intent, and the \
             kubelet needs it to decide whether to share the host network namespace"
        );
    }

    /// hostPID/hostIPC are the same plain (non-pointer), gogoproto-`nullable=false` bool class
    /// as hostNetwork just above, and — until mayor-swxjj — were the one pair in that class
    /// still missing the true-only guard. A real client-go protobuf write (e.g. the
    /// controller-manager's ReplicationController controller resubmitting a pod after only
    /// changing its labels) always puts an explicit `false` for both on the wire even when the
    /// pod never touched them, because the real upstream Go type has no way to represent
    /// "unset" for a non-pointer bool. Without this guard, decoding that PUT body fabricates
    /// `"hostPID": false`/`"hostIPC": false` on a pod stored without either key, and
    /// `validate_pod_spec_immutable`'s whole-spec deep-equal (crates/apiserver/src/handlers/
    /// pods.rs) rejects it as a spec change that never happened — this was the 3rd recurrence
    /// of the RC/Job label-only-PUT immutability regression (mayor-y6gtg / mayor-swxjj).
    #[test]
    fn generated_pod_spec_omits_host_pid_and_host_ipc_when_wire_carries_the_zero_value() {
        let untouched_pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("host-pid-ipc-unset-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                host_pid: Some(false),
                host_ipc: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        untouched_pod.encode(&mut buf).unwrap();

        let result =
            decode_pod_proto_gen(&buf).expect("Pod with host_pid/host_ipc=false must decode");

        assert!(
            result["spec"].get("hostPID").is_none(),
            "hostPID must be omitted when the wire only carries the zero value — a real \
             protobuf sender always writes false for a pod that never asked for the host PID \
             namespace, so emitting the key here fabricates an explicit false the source \
             object never had"
        );
        assert!(
            result["spec"].get("hostIPC").is_none(),
            "hostIPC must be omitted when the wire only carries the zero value — same \
             fabrication risk as hostPID/hostNetwork"
        );

        let true_pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("host-pid-ipc-true-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    ..Default::default()
                }],
                host_pid: Some(true),
                host_ipc: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf2 = Vec::new();
        true_pod.encode(&mut buf2).unwrap();

        let result2 =
            decode_pod_proto_gen(&buf2).expect("Pod with host_pid/host_ipc=true must decode");

        assert_eq!(
            result2["spec"]["hostPID"], true,
            "an explicit hostPID=true must still survive decode — true is the only value a \
             plain bool can carry that unambiguously reflects real user intent"
        );
        assert_eq!(
            result2["spec"]["hostIPC"], true,
            "an explicit hostIPC=true must still survive decode — same as hostPID"
        );
    }

    /// Container.stdin/stdinOnce/tty are the same plain (non-pointer), gogoproto-
    /// `nullable=false` bool class as PodSpec.hostNetwork/hostPID/hostIPC, and were also
    /// missing the true-only guard until mayor-swxjj. `kubectl attach`/`kubectl run -it`
    /// aside, the practical consequence mirrors the PodSpec-level fields: any real protobuf
    /// PUT of a container that never touched these fields fabricates an explicit `false`,
    /// which a stored pod created without them (e.g. via a JSON-writing client) then compares
    /// unequal against under validate_pod_spec_immutable's whole-spec deep-equal.
    #[test]
    fn generated_container_omits_stdin_stdin_once_tty_when_wire_carries_the_zero_value() {
        let untouched_pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("stdin-tty-unset-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    stdin: Some(false),
                    stdin_once: Some(false),
                    tty: Some(false),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        untouched_pod.encode(&mut buf).unwrap();

        let result =
            decode_pod_proto_gen(&buf).expect("Pod with stdin/stdinOnce/tty=false must decode");

        for key in ["stdin", "stdinOnce", "tty"] {
            assert!(
                result["spec"]["containers"][0].get(key).is_none(),
                "containers[0].{key} must be omitted when the wire only carries the zero \
                 value — a real protobuf sender always writes false for a container that \
                 never asked for it, so emitting the key here fabricates an explicit false \
                 the source object never had"
            );
        }

        let true_pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("stdin-tty-true-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    stdin: Some(true),
                    stdin_once: Some(true),
                    tty: Some(true),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf2 = Vec::new();
        true_pod.encode(&mut buf2).unwrap();

        let result2 =
            decode_pod_proto_gen(&buf2).expect("Pod with stdin/stdinOnce/tty=true must decode");

        for key in ["stdin", "stdinOnce", "tty"] {
            assert_eq!(
                result2["spec"]["containers"][0][key], true,
                "an explicit containers[0].{key}=true must still survive decode — true is the \
                 only value a plain bool can carry that unambiguously reflects real user intent"
            );
        }
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

    /// A probe's `httpGet.httpHeaders` must survive protobuf decode.
    ///
    /// Without it, a health check that relies on a custom header (e.g. an auth token the
    /// target expects) is silently sent without that header, so the endpoint answers
    /// 401/403 and the probe reports the container unhealthy even though it's fine.
    #[test]
    fn generated_container_preserves_liveness_probe_http_headers() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("probe-headers-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    liveness_probe: Some(core_v1::Probe {
                        handler: Some(core_v1::ProbeHandler {
                            http_get: Some(core_v1::HttpGetAction {
                                path: Some("/healthz".to_string()),
                                http_headers: vec![core_v1::HttpHeader {
                                    name: Some("X-Auth-Token".to_string()),
                                    value: Some("secret".to_string()),
                                }],
                                ..Default::default()
                            }),
                            ..Default::default()
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

        let result = decode_pod_proto_gen(&buf).expect("Pod with liveness probe must decode");

        let header = &result["spec"]["containers"][0]["livenessProbe"]["httpGet"]["httpHeaders"][0];
        assert_eq!(
            header["name"], "X-Auth-Token",
            "httpGet.httpHeaders must survive decode — without it an auth-gated health check \
             silently loses its credential and the probe fails even though the container is \
             healthy"
        );
        assert_eq!(
            header["value"], "secret",
            "httpHeaders[].value must survive decode"
        );
    }

    /// A container's `lifecycle.stopSignal` must survive protobuf decode.
    ///
    /// Without it, the container runtime falls back to its own default stop signal (usually
    /// SIGTERM) instead of the one the client requested, which can kill a process that only
    /// handles a different signal for graceful shutdown, dropping in-flight work.
    #[test]
    fn generated_container_preserves_lifecycle_stop_signal() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("stopsignal-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                os: Some(core_v1::PodOs {
                    name: Some("linux".to_string()),
                }),
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    lifecycle: Some(core_v1::Lifecycle {
                        stop_signal: Some("SIGUSR1".to_string()),
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

        let result = decode_pod_proto_gen(&buf).expect("Pod with lifecycle.stopSignal must decode");

        assert_eq!(
            result["spec"]["containers"][0]["lifecycle"]["stopSignal"], "SIGUSR1",
            "lifecycle.stopSignal must survive decode — without it the runtime falls back to \
             its default signal (usually SIGTERM), which can kill a process that only handles \
             a different signal for graceful shutdown"
        );
    }

    /// A volume's `emptyDir.sizeLimit` must survive protobuf decode.
    ///
    /// Without it, an emptyDir the client capped at a specific size round-trips as
    /// uncapped, letting a runaway writer exhaust node disk/memory instead of being
    /// evicted at the limit the client set.
    #[test]
    fn generated_pod_spec_preserves_empty_dir_size_limit() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("emptydir-pod".to_string()),
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
                    name: Some("scratch".to_string()),
                    volume_source: Some(core_v1::VolumeSource {
                        empty_dir: Some(core_v1::EmptyDirVolumeSource {
                            medium: Some("Memory".to_string()),
                            size_limit: Some(
                                u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                                    string: Some("1Gi".to_string()),
                                },
                            ),
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

        let result = decode_pod_proto_gen(&buf).expect("Pod with emptyDir must decode");

        assert_eq!(
            result["spec"]["volumes"][0]["emptyDir"]["sizeLimit"], "1Gi",
            "emptyDir.sizeLimit must survive decode — without it a capped emptyDir round-trips \
             as uncapped, letting a runaway writer exhaust node disk/memory instead of being \
             evicted at the limit the client set"
        );
    }

    /// An env var's `valueFrom.fileKeyRef` must survive protobuf decode.
    ///
    /// Without it, a container relying on this (alpha EnvFiles) feature starts with that
    /// environment variable entirely unset instead of the value the referenced file provided.
    #[test]
    fn generated_container_preserves_env_file_key_ref() {
        let pod = core_v1::Pod {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("envfile-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    name: Some("c".to_string()),
                    image: Some("img".to_string()),
                    env: vec![core_v1::EnvVar {
                        name: Some("FROM_FILE".to_string()),
                        value_from: Some(core_v1::EnvVarSource {
                            file_key_ref: Some(core_v1::FileKeySelector {
                                volume_name: Some("envfile-vol".to_string()),
                                path: Some("app.env".to_string()),
                                key: Some("SOME_KEY".to_string()),
                                optional: Some(true),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();

        let result = decode_pod_proto_gen(&buf).expect("Pod with fileKeyRef env var must decode");

        let fkr = &result["spec"]["containers"][0]["env"][0]["valueFrom"]["fileKeyRef"];
        assert_eq!(
            fkr["volumeName"], "envfile-vol",
            "valueFrom.fileKeyRef must survive decode — without it a container relying on \
             this env-from-file feature starts with the variable entirely unset instead of \
             the value the referenced file provided"
        );
        assert_eq!(
            fkr["path"], "app.env",
            "fileKeyRef.path must survive decode"
        );
        assert_eq!(fkr["key"], "SOME_KEY", "fileKeyRef.key must survive decode");
        assert_eq!(
            fkr["optional"], true,
            "fileKeyRef.optional must survive decode"
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
        ) -> u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
            u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
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
        ) -> u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
            u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
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
            result["status"]["daemonEndpoints"]["kubeletEndpoint"]["port"], 10250,
            "status.daemonEndpoints.kubeletEndpoint.port must survive decode under its \
             lowerCamel JSON key — the API server's own log/exec/proxy subresources dial \
             this port to reach the kubelet, and a client reading the real Kubernetes JSON \
             key (\"port\", not the .proto's Go-style \"Port\") would see nothing"
        );
        assert_eq!(
            result["status"]["nodeInfo"]["kubeletVersion"], "v1.36.0",
            "status.nodeInfo must survive decode — version skew checks depend on it"
        );
    }

    /// status.config and status.runtimeHandlers survive the generated-path decode.
    ///
    /// runtimeHandlers backs the RecursiveReadOnlyMounts/UserNamespaces feature-detection
    /// paths CRI-aware schedulers/admission use; before this fix, both fields were absent
    /// from gen_node_status_to_json entirely, so every node looked like it supported neither
    /// feature and had no dynamic-kubelet-config status, regardless of what the runtime or
    /// kubelet actually reported.
    #[test]
    fn generated_node_preserves_config_status_and_runtime_handlers() {
        let node = core_v1::Node {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("node-1".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::NodeStatus {
                config: Some(core_v1::NodeConfigStatus {
                    assigned: Some(core_v1::NodeConfigSource {
                        config_map: Some(core_v1::ConfigMapNodeConfigSource {
                            name: Some("kubelet-config".to_string()),
                            namespace: Some("kube-system".to_string()),
                            kubelet_config_key: Some("kubelet".to_string()),
                            ..Default::default()
                        }),
                    }),
                    error: Some("failed to load checkpoint".to_string()),
                    ..Default::default()
                }),
                runtime_handlers: vec![core_v1::NodeRuntimeHandler {
                    name: Some("runc".to_string()),
                    features: Some(core_v1::NodeRuntimeHandlerFeatures {
                        recursive_read_only_mounts: Some(true),
                        user_namespaces: Some(true),
                    }),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        node.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_node_proto_gen(&buf)
            .expect("Node with config/runtimeHandlers status must decode via generated path");

        assert_eq!(
            result["status"]["config"]["assigned"]["configMap"]["name"], "kubelet-config",
            "status.config.assigned.configMap.name must survive decode"
        );
        assert_eq!(
            result["status"]["config"]["error"], "failed to load checkpoint",
            "status.config.error must survive decode — without it a client cannot see why \
             the assigned config failed to apply"
        );
        assert_eq!(
            result["status"]["runtimeHandlers"][0]["name"], "runc",
            "status.runtimeHandlers[].name must survive decode"
        );
        assert_eq!(
            result["status"]["runtimeHandlers"][0]["features"]["recursiveReadOnlyMounts"], true,
            "status.runtimeHandlers[].features.recursiveReadOnlyMounts must survive decode — \
             without it every node looks like it does not support RecursiveReadOnlyMounts \
             regardless of what the runtime actually reports"
        );
        assert_eq!(
            result["status"]["runtimeHandlers"][0]["features"]["userNamespaces"], true,
            "status.runtimeHandlers[].features.userNamespaces must survive decode"
        );
    }

    /// spec.externalID and spec.configSource survive the generated-path decode.
    ///
    /// Both fields are deprecated upstream, but a client that sets either still expects it
    /// to round-trip through a protobuf write rather than silently vanish.
    #[test]
    fn generated_node_preserves_spec_external_id_and_config_source() {
        let node = core_v1::Node {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("node-1".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::NodeSpec {
                external_id: Some("aws:///us-east-1a/i-0123456789".to_string()),
                config_source: Some(core_v1::NodeConfigSource {
                    config_map: Some(core_v1::ConfigMapNodeConfigSource {
                        name: Some("kubelet-config".to_string()),
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            }),
            status: None,
        };
        let mut buf = Vec::new();
        node.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_node_proto_gen(&buf)
            .expect("Node with deprecated spec fields must decode via generated path");

        assert_eq!(
            result["spec"]["externalID"], "aws:///us-east-1a/i-0123456789",
            "spec.externalID must survive decode"
        );
        assert_eq!(
            result["spec"]["configSource"]["configMap"]["name"], "kubelet-config",
            "spec.configSource must survive decode"
        );
    }

    // ---- Node.spec.unschedulable / spec.taints: protobuf decode gap class ----
    //
    // Same shape as the Job/CronJob spec-scalar decode gaps fixed elsewhere in this crate:
    // decode_node_proto_gen only read podCIDR/providerID/podCIDRs off the decoded NodeSpec,
    // silently dropping unschedulable and taints. client-go's typed clientset defaults to
    // protobuf content-type for Node, so every Node created via the typed API lost both
    // fields before storage.

    /// spec.unschedulable=true must survive decode — the scheduler's NodeUnschedulable
    /// filter reads this field to keep pods off cordoned/not-yet-ready nodes. If it's
    /// dropped, `Unschedulable: true` silently becomes `None`/absent and the filter passes
    /// every node, letting pods bind to nodes that explicitly asked not to be scheduled onto.
    #[test]
    fn decode_node_proto_gen_preserves_spec_unschedulable_true() {
        let node = core_v1::Node {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("cordoned-node".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::NodeSpec {
                unschedulable: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        node.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_node_proto_gen(&buf).expect("Node must decode");

        assert_eq!(
            result["spec"]["unschedulable"],
            serde_json::json!(true),
            "spec.unschedulable must survive decode — without it the scheduler's \
             NodeUnschedulable filter never sees the cordon and binds pods to a node that \
             explicitly asked not to be scheduled onto"
        );
    }

    /// spec.unschedulable must be omitted (not emitted as `false`) when absent from the wire,
    /// matching upstream's `omitempty` JSON shape for this field.
    #[test]
    fn decode_node_proto_gen_omits_unschedulable_when_absent() {
        let node = core_v1::Node {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("schedulable-node".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::NodeSpec {
                unschedulable: None,
                pod_cidr: Some("10.0.0.0/24".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        node.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_node_proto_gen(&buf).expect("Node must decode");

        assert!(
            result["spec"].get("unschedulable").is_none(),
            "spec.unschedulable must be absent (not `false`) when the field was never set on \
             the wire — matching upstream's omitempty shape so a client that never touched \
             schedulability can't be told it explicitly requested `false`"
        );
    }

    /// spec.taints must survive decode — TaintToleration scheduling predicates and the
    /// eviction controller both key off this field to know which pods must move off (or
    /// never land on) a tainted node.
    #[test]
    fn decode_node_proto_gen_preserves_spec_taints() {
        let node = core_v1::Node {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("tainted-node".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::NodeSpec {
                taints: vec![core_v1::Taint {
                    key: Some("node.kubernetes.io/not-ready".to_string()),
                    value: Some(String::new()),
                    effect: Some("NoSchedule".to_string()),
                    time_added: None,
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        node.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_node_proto_gen(&buf).expect("Node must decode");

        let taints = result["spec"]["taints"].as_array().expect(
            "spec.taints must be present — without it a node's NoSchedule/NoExecute taints \
             vanish on decode and pods that should be evicted or blocked from scheduling \
             there are neither",
        );
        assert_eq!(taints.len(), 1, "one taint must survive decode");
        assert_eq!(
            taints[0]["key"], "node.kubernetes.io/not-ready",
            "taint key must survive decode — the scheduler and toleration matching both key \
             off this field"
        );
        assert_eq!(
            taints[0]["effect"], "NoSchedule",
            "taint effect must survive decode — without it the scheduler cannot tell \
             NoSchedule from PreferNoSchedule from NoExecute"
        );
    }

    /// NodeStatus.features.supplementalGroupsPolicy and NodeStatus.declaredFeatures must
    /// survive decode alongside the spec fields above — same decoder, same silent-drop gap
    /// found while auditing every field this function reads off the wire.
    #[test]
    fn decode_node_proto_gen_preserves_status_features_and_declared_features() {
        let node = core_v1::Node {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("feature-node".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::NodeStatus {
                features: Some(core_v1::NodeFeatures {
                    supplemental_groups_policy: Some(true),
                }),
                declared_features: vec!["SupplementalGroupsPolicy".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        node.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_node_proto_gen(&buf).expect("Node must decode");

        assert_eq!(
            result["status"]["features"]["supplementalGroupsPolicy"],
            serde_json::json!(true),
            "status.features.supplementalGroupsPolicy must survive decode — without it a \
             client can't tell whether the node's runtime actually supports \
             SupplementalGroupsPolicy/ContainerUser"
        );
        assert_eq!(
            result["status"]["declaredFeatures"][0], "SupplementalGroupsPolicy",
            "status.declaredFeatures must survive decode"
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

    /// decode_persistentvolumeclaim_proto_gen must preserve spec.selector (PVCSpec field 4).
    ///
    /// Pre-provisioned-binding workflows set a label selector so the PVC only binds to a PV
    /// carrying matching labels; dropping it on decode makes the PVC bind to any PV that
    /// satisfies capacity/accessModes alone, silently attaching a claim to the wrong volume.
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_selector() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PersistentVolumeClaimSpec {
                selector: Some(meta_v1::LabelSelector {
                    match_labels: [("release".to_string(), "stable".to_string())]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["spec"]["selector"]["matchLabels"]["release"], "stable",
            "spec.selector must survive decode — without it a pre-provisioned-binding PVC \
             loses its label constraint and can bind to any PV that merely matches capacity \
             and accessModes, attaching the claim to the wrong volume"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve spec.dataSource (PVCSpec field 7).
    ///
    /// dataSource is how a user clones an existing PVC or restores a VolumeSnapshot into a new
    /// claim; dropping it on decode makes the CSI provisioner see a claim with no data source
    /// and provision an empty volume instead of the clone/restore the user asked for.
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_data_source() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("clone-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PersistentVolumeClaimSpec {
                data_source: Some(core_v1::TypedLocalObjectReference {
                    kind: Some("PersistentVolumeClaim".to_string()),
                    name: Some("source-pvc".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["spec"]["dataSource"]["name"], "source-pvc",
            "spec.dataSource must survive decode — clone-from-PVC breaks silently without it: \
             the CSI provisioner sees no data source and provisions an empty volume instead of \
             a clone of source-pvc"
        );
        assert_eq!(
            result["spec"]["dataSource"]["kind"], "PersistentVolumeClaim",
            "spec.dataSource.kind must survive decode alongside name — losing it makes the \
             provisioner unable to tell a PVC clone request from a VolumeSnapshot restore"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve spec.dataSourceRef (PVCSpec field 8).
    ///
    /// dataSourceRef is the cross-namespace-capable successor to dataSource, required by
    /// external volume populators; dropping it on decode leaves the populator controller with
    /// nothing to reconcile, so the claim never gets populated and stays pending forever.
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_data_source_ref() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("populated-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PersistentVolumeClaimSpec {
                data_source_ref: Some(core_v1::TypedObjectReference {
                    api_group: Some("populator.example.com".to_string()),
                    kind: Some("VolumePopulator".to_string()),
                    name: Some("my-populator".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["spec"]["dataSourceRef"]["name"], "my-populator",
            "spec.dataSourceRef must survive decode — without it an external volume populator \
             has nothing to reconcile against and the claim never gets populated, staying \
             Pending forever"
        );
        assert_eq!(
            result["spec"]["dataSourceRef"]["apiGroup"], "populator.example.com",
            "spec.dataSourceRef.apiGroup must survive decode — without it the populator \
             controller cannot resolve which non-core object type to look up"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve spec.volumeAttributesClassName
    /// (PVCSpec field 9).
    ///
    /// The VAC modify controller reconciles a claim's volume attributes against this field;
    /// dropping it on decode means a user's request to apply a VolumeAttributesClass is
    /// silently ignored and the underlying volume never gets the requested attributes.
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_volume_attributes_class_name() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("vac-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PersistentVolumeClaimSpec {
                volume_attributes_class_name: Some("gold-tier".to_string()),
                ..Default::default()
            }),
            status: None,
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["spec"]["volumeAttributesClassName"], "gold-tier",
            "spec.volumeAttributesClassName must survive decode — without it the VAC modify \
             controller has nothing to reconcile and a user's request to apply gold-tier \
             attributes to the volume is silently ignored"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve status.accessModes (PVCStatus
    /// field 2).
    ///
    /// accessModes here reflects what the underlying PV actually offers; without it a client
    /// can't distinguish "my request is RWX" from "my PV happens to also allow RWX".
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_status_access_modes() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("bound-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::PersistentVolumeClaimStatus {
                access_modes: vec!["ReadWriteMany".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["status"]["accessModes"][0], "ReadWriteMany",
            "status.accessModes must survive decode — it reflects what the underlying PV \
             actually offers; without it a client can't distinguish 'my request is RWX' from \
             'my PV happens to also allow RWX'"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve status.capacity (PVCStatus field 3).
    ///
    /// capacity is the actual size of the backing volume, which can exceed the requested size;
    /// without it clients can't see the real backing volume size vs. what they requested (e.g.
    /// a 10Gi request may satisfy against a 100Gi PV; that's the field that surfaces the
    /// difference).
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_status_capacity() {
        fn quantity(
            s: &str,
        ) -> u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
            u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                string: Some(s.to_string()),
            }
        }
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("bound-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::PersistentVolumeClaimStatus {
                capacity: [("storage".to_string(), quantity("100Gi"))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["status"]["capacity"]["storage"], "100Gi",
            "status.capacity must survive decode — clients can't see the real backing volume \
             size vs. what they requested (e.g. a 10Gi request may satisfy against a 100Gi PV; \
             that's the field that surfaces the difference)"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve status.conditions[].lastProbeTime and
    /// .lastTransitionTime (PVCStatus field 4's condition timestamps).
    ///
    /// These are how a client tells "resize probed 5 minutes ago and still Resizing" from
    /// "resize just started" — without them, the FileSystemResizePending/Resizing condition has
    /// a type/status/reason but no way to tell how long the claim has been stuck there.
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_status_condition_timestamps() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("resizing-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::PersistentVolumeClaimStatus {
                conditions: vec![core_v1::PersistentVolumeClaimCondition {
                    r#type: Some("Resizing".to_string()),
                    status: Some("True".to_string()),
                    last_probe_time: Some(meta_v1::Time {
                        seconds: Some(1_700_000_000),
                        nanos: Some(0),
                    }),
                    last_transition_time: Some(meta_v1::Time {
                        seconds: Some(1_700_000_100),
                        nanos: Some(0),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["status"]["conditions"][0]["lastProbeTime"], "2023-11-14T22:13:20Z",
            "status.conditions[].lastProbeTime must survive decode — without it a client can't \
             tell how long ago a resize condition was last probed"
        );
        assert_eq!(
            result["status"]["conditions"][0]["lastTransitionTime"], "2023-11-14T22:15:00Z",
            "status.conditions[].lastTransitionTime must survive decode — without it a client \
             can't tell how long a claim has been stuck Resizing vs. just having started"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must survive PersistentVolumeClaim::sentinel()
    /// producing exactly the keys the .proto schema defines, not a hand-typed subset that could
    /// go stale the same way PodStatus's did (mayor-y0pcm).
    #[test]
    fn sentinel_completeness_decode_persistentvolumeclaim_proto_gen() {
        let pvc = core_v1::PersistentVolumeClaim::sentinel();
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");
        let result =
            decode_persistentvolumeclaim_proto_gen(&buf).expect("sentinel PVC must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.core.v1.PersistentVolumeClaim",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve status.allocatedResources
    /// (PVCStatus field 5).
    ///
    /// allocatedResources tracks resize-in-progress capacity separately from spec.resources;
    /// without it, volume-expansion progress is invisible during resize — clients see the
    /// request but not the actual allocated capacity in-flight.
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_status_allocated_resources() {
        fn quantity(
            s: &str,
        ) -> u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
            u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                string: Some(s.to_string()),
            }
        }
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("resizing-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::PersistentVolumeClaimStatus {
                allocated_resources: [("storage".to_string(), quantity("50Gi"))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["status"]["allocatedResources"]["storage"], "50Gi",
            "status.allocatedResources must survive decode — volume-expansion progress is \
             invisible during resize; clients see the request but not the actual allocated \
             capacity in-flight"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve status.allocatedResourceStatuses
    /// (PVCStatus field 7).
    ///
    /// allocatedResourceStatuses is the per-resource resize state machine's status map; without
    /// it, per-resource resize state (which resource keys are Resizing / NodeResizePending /
    /// NodeResizeFailed) is invisible and controllers can't drive the resize state machine.
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_status_allocated_resource_statuses() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("resizing-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::PersistentVolumeClaimStatus {
                allocated_resource_statuses: [(
                    "storage".to_string(),
                    "NodeResizePending".to_string(),
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["status"]["allocatedResourceStatuses"]["storage"], "NodeResizePending",
            "status.allocatedResourceStatuses must survive decode — per-resource resize state \
             (which resource keys are Resizing / NodeResizePending / NodeResizeFailed) is \
             invisible; controllers can't drive the resize state machine"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve
    /// status.currentVolumeAttributesClassName (PVCStatus field 8).
    ///
    /// This is the VAC modify controller's current-state field; without it the controller has
    /// nothing to reconcile against and the entire modify state machine breaks.
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_status_current_volume_attributes_class_name(
    ) {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("vac-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::PersistentVolumeClaimStatus {
                current_volume_attributes_class_name: Some("silver-tier".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["status"]["currentVolumeAttributesClassName"], "silver-tier",
            "status.currentVolumeAttributesClassName must survive decode — the VAC modify \
             controller has no current-state field to reconcile against — the entire modify \
             state machine breaks"
        );
    }

    /// decode_persistentvolumeclaim_proto_gen must preserve status.modifyVolumeStatus
    /// (PVCStatus field 9).
    ///
    /// modifyVolumeStatus carries the in-progress VAC modification state (target class plus
    /// Pending/InProgress/Infeasible); without it, clients see 'name changed' but not
    /// 'stuck InProgress'.
    #[test]
    fn decode_persistentvolumeclaim_proto_gen_preserves_status_modify_volume_status() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("vac-pvc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            status: Some(core_v1::PersistentVolumeClaimStatus {
                modify_volume_status: Some(core_v1::ModifyVolumeStatus {
                    target_volume_attributes_class_name: Some("gold-tier".to_string()),
                    status: Some("InProgress".to_string()),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        assert_eq!(
            result["status"]["modifyVolumeStatus"]["targetVolumeAttributesClassName"], "gold-tier",
            "status.modifyVolumeStatus.targetVolumeAttributesClassName must survive decode — \
             in-progress VAC modification state (target class + Pending/InProgress/Infeasible) \
             is invisible; clients see 'name changed' but not 'stuck InProgress'"
        );
        assert_eq!(
            result["status"]["modifyVolumeStatus"]["status"], "InProgress",
            "status.modifyVolumeStatus.status must survive decode alongside the target class — \
             without it a client can tell a modify was requested but not whether it's stuck \
             InProgress or has failed as Infeasible"
        );
    }

    /// gen_persistent_volume_claim_to_json must preserve a present-but-empty
    /// `spec.storageClassName`, not collapse it to an absent key.
    ///
    /// `PersistentVolumeClaimSpec.StorageClassName` is `*string` upstream: `nil` means "eligible
    /// for DefaultStorageClass admission — apply whatever class the cluster considers default",
    /// while `Some("")` means the claim explicitly opted OUT of dynamic provisioning and must
    /// bind only to a pre-existing, unclassified PV. Collapsing `Some("")` to a missing key
    /// makes the PV binding controller and any client-go informer that re-reads the stored JSON
    /// treat the claim as if it never set the field — i.e. default-StorageClass admission and
    /// dynamic provisioning get applied when the user's intent was the opposite.
    #[test]
    fn gen_persistent_volume_claim_to_json_preserves_present_but_empty_storage_class_name() {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-dynamic-provisioning".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PersistentVolumeClaimSpec {
                storage_class_name: Some(String::new()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        let spec = result["spec"]
            .as_object()
            .expect("spec must decode to a JSON object");
        assert!(
            spec.contains_key("storageClassName"),
            "spec must have a \"storageClassName\" key even when its value is the empty string \
             — a PVC with StorageClassName=Some(\"\") must serialize as \
             \"storageClassName\":\"\" in JSON; collapsing to absent would make the PVC \
             eligible for default-StorageClass admission when the user's intent was the \
             opposite"
        );
        assert_eq!(
            spec["storageClassName"], "",
            "the present-but-empty storageClassName's value must round-trip as \"\", not be \
             replaced or coerced"
        );
    }

    /// gen_persistent_volume_claim_to_json must preserve a present-but-empty
    /// `spec.volumeAttributesClassName`, not collapse it to an absent key.
    ///
    /// `PersistentVolumeClaimSpec.VolumeAttributesClassName` is `*string` upstream: `nil` means
    /// "unspecified — the persistentvolume controller will apply the default VolumeAttributesClass
    /// if one exists", while `Some("")` is the documented (types.go:616-621) immutable opt-out
    /// state — the claim explicitly declines any VolumeAttributesClass. A PVC with
    /// `VolumeAttributesClassName=Some("")` must serialize as `"volumeAttributesClassName":""` in
    /// JSON — collapsing to absent would make the PVC eligible for default-VAC provisioning when
    /// the user's intent was the immutable opt-out state documented in upstream types.go:616-621.
    #[test]
    fn gen_persistent_volume_claim_to_json_preserves_present_but_empty_volume_attributes_class_name(
    ) {
        let pvc = core_v1::PersistentVolumeClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("no-vac".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(core_v1::PersistentVolumeClaimSpec {
                volume_attributes_class_name: Some(String::new()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_persistentvolumeclaim_proto_gen(&buf).expect("PVC must decode");

        let spec = result["spec"]
            .as_object()
            .expect("spec must decode to a JSON object");
        assert!(
            spec.contains_key("volumeAttributesClassName"),
            "spec must have a \"volumeAttributesClassName\" key even when its value is the \
             empty string — a PVC with VolumeAttributesClassName=Some(\"\") must serialize as \
             \"volumeAttributesClassName\":\"\" in JSON — collapsing to absent would make the \
             PVC eligible for default-VAC provisioning when the user's intent was the immutable \
             opt-out state documented in upstream types.go:616-621"
        );
        assert_eq!(
            spec["volumeAttributesClassName"], "",
            "the present-but-empty volumeAttributesClassName's value must round-trip as \"\", \
             not be replaced or coerced"
        );
    }

    /// Sentinel completeness test for `gen_persistent_volume_claim_to_json`: catches whichever
    /// PersistentVolumeClaimSpec or PersistentVolumeClaimStatus field gets missed next, the way
    /// the targeted tests above only catch the fields known to be dropped at the time they were
    /// written.
    #[test]
    fn sentinel_completeness_gen_persistent_volume_claim_to_json() {
        let pvc = core_v1::PersistentVolumeClaim {
            spec: Some(core_v1::PersistentVolumeClaimSpec::sentinel()),
            status: Some(core_v1::PersistentVolumeClaimStatus::sentinel()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pvc.encode(&mut buf).expect("prost encode must succeed");
        let result =
            decode_persistentvolumeclaim_proto_gen(&buf).expect("sentinel PVC must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result["spec"], "", &mut paths);
        collect_leaf_paths(&result["status"], "", &mut paths);

        // Every container field below (selector/resources/dataSource/etc.) is never itself a
        // real leaf once populated; each gets a dotted entry pointing at a genuine leaf child.
        let expected = [
            "accessModes",
            "selector.matchLabels.__sentinel__",
            "resources.limits.__sentinel__",
            "volumeName",
            "storageClassName",
            "volumeMode",
            "dataSource.apiGroup",
            "dataSourceRef.apiGroup",
            "volumeAttributesClassName",
            "phase",
            "capacity.__sentinel__",
            "conditions.status",
            "allocatedResources.__sentinel__",
            "allocatedResourceStatuses.__sentinel__",
            "currentVolumeAttributesClassName",
            "modifyVolumeStatus.status",
        ];
        assert_fields_present(&paths, &expected);
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

    /// decode_serviceaccount_proto_gen must preserve secrets[].fieldPath (ObjectReference field
    /// 7), reachable via ServiceAccount.secrets[].
    ///
    /// This is a schema field on ObjectReference that a client is entitled to set on any
    /// secrets[] entry; dropping it silently would corrupt a GET-modify-PUT round trip through
    /// a protobuf-content-type client even though this particular reference use is unusual.
    #[test]
    fn decode_serviceaccount_proto_gen_preserves_secrets_field_path() {
        let sa = core_v1::ServiceAccount {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-sa".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            secrets: vec![core_v1::ObjectReference {
                name: Some("my-sa-token".to_string()),
                field_path: Some("data.token".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut buf = Vec::new();
        sa.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_serviceaccount_proto_gen(&buf).expect("ServiceAccount must decode");

        assert_eq!(
            result["secrets"][0]["fieldPath"], "data.token",
            "secrets[].fieldPath must survive decode alongside name — a client that set it on \
             a GET-modify-PUT round trip through a protobuf-content-type client would otherwise \
             see it silently vanish"
        );
    }

    /// decode_serviceaccount_proto_gen must survive ServiceAccount::sentinel() producing exactly
    /// the keys the .proto schema defines, not a hand-typed subset that could go stale the same
    /// way PodStatus's did (mayor-y0pcm).
    #[test]
    fn sentinel_completeness_decode_serviceaccount_proto_gen() {
        let sa = core_v1::ServiceAccount::sentinel();
        let mut buf = Vec::new();
        sa.encode(&mut buf).expect("prost encode must succeed");
        let result =
            decode_serviceaccount_proto_gen(&buf).expect("sentinel ServiceAccount must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.core.v1.ServiceAccount",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
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

    /// decode_endpoints_proto_gen must preserve addresses[].targetRef — found while auditing
    /// this file's decoders for the same silent-field-drop shape as Node.spec.unschedulable.
    ///
    /// targetRef points back at the Pod backing an address; consumers reading Endpoints
    /// directly (rather than via EndpointSlice) use it to resolve which pod owns a given IP.
    #[test]
    fn decode_endpoints_proto_gen_preserves_address_target_ref() {
        let ep = core_v1::Endpoints {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-svc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            subsets: vec![core_v1::EndpointSubset {
                addresses: vec![core_v1::EndpointAddress {
                    ip: Some("10.0.0.5".to_string()),
                    target_ref: Some(core_v1::ObjectReference {
                        kind: Some("Pod".to_string()),
                        name: Some("pod-a".to_string()),
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                not_ready_addresses: vec![],
                ports: vec![],
            }],
        };
        let mut buf = Vec::new();
        ep.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_endpoints_proto_gen(&buf).expect("Endpoints must decode");

        assert_eq!(
            result["subsets"][0]["addresses"][0]["targetRef"]["name"], "pod-a",
            "addresses[].targetRef must survive decode — without it a consumer reading \
             Endpoints directly cannot tell which Pod backs a given address"
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
        ) -> u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
            u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
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

    /// decode_event_proto_gen must preserve source/firstTimestamp/lastTimestamp — the exact
    /// shape real kubelet sends for a core/v1 Event (kubelet's `record.EventRecorder` always
    /// sets Source and both timestamps, and posts over protobuf by default).
    ///
    /// Before this fix, this decoder never read `event.source`, `event.first_timestamp`, or
    /// `event.last_timestamp` off the decoded proto message at all — every kubelet-sourced
    /// Event was stored with those fields entirely absent, so any core/v1 reader (kubectl,
    /// the upstream e2e test's DumpEventsInNamespace) rendered the Go zero-value
    /// "0001-01-01 00:00:00 +0000 UTC" instead of the real time kubelet recorded, making it
    /// impossible to reconstruct an incident timeline from kubelet events sitting right next
    /// to correctly-timestamped controller events in the same dump.
    #[test]
    fn decode_event_proto_gen_preserves_source_and_first_last_timestamp() {
        let ev = core_v1::Event {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-node.17abc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            involved_object: Some(core_v1::ObjectReference {
                kind: Some("Node".to_string()),
                name: Some("my-node".to_string()),
                ..Default::default()
            }),
            reason: Some("Starting".to_string()),
            message: Some("Starting kubelet.".to_string()),
            source: Some(core_v1::EventSource {
                component: Some("kubelet".to_string()),
                host: Some("my-node".to_string()),
            }),
            first_timestamp: Some(meta_v1::Time {
                seconds: Some(1_700_000_000),
                nanos: Some(0),
            }),
            last_timestamp: Some(meta_v1::Time {
                seconds: Some(1_700_000_000),
                nanos: Some(0),
            }),
            r#type: Some("Normal".to_string()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ev.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_event_proto_gen(&buf).expect("Event must decode");

        assert_eq!(
            result["source"]["component"], "kubelet",
            "source.component must survive decode — without it a kubelet-sourced Event is \
             indistinguishable from one with no reporter at all"
        );
        assert_eq!(
            result["firstTimestamp"], "2023-11-14T22:13:20Z",
            "firstTimestamp must survive decode as a real timestamp — a dropped firstTimestamp \
             renders as the Go zero-value 0001-01-01, making timeline reconstruction from \
             kubelet events impossible"
        );
        assert_eq!(
            result["lastTimestamp"], "2023-11-14T22:13:20Z",
            "lastTimestamp must survive decode as a real timestamp for the same reason as \
             firstTimestamp"
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

    // ---- Sentinel completeness: gen_pod_spec_to_json / gen_container_to_json ----
    //
    // Each test below builds a message with every field set to a value no zero/empty-elision
    // check in these hand-written gen_*_to_json functions could mistake for "unset" (see
    // u7s_sentinel::Sentinel), decodes it through the real decode_pod_proto_gen entry point,
    // and asserts every field name shows up somewhere in the resulting JSON. A name that never
    // appears means some gen_*_to_json function never reads that field from the decoded
    // protobuf struct at all — this is exactly how hostUsers/setHostnameAsFQDN previously went
    // missing, and how workingDir/stdin/stdinOnce/tty/volumeDevices/restartPolicyRules/
    // schedulingGroup were found missing from this file while building this test.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    /// Builds a Pod whose spec is a fully sentinel-populated PodSpec (which recursively
    /// sentinel-populates its `containers: Vec<Container>` too), and decodes it through the
    /// real decode_pod_proto_gen entry point — the same function every protobuf-encoded Pod
    /// create/update actually goes through in production (client-go's typed clientsets, used
    /// by every controller and kube-scheduler, default to protobuf).
    fn sentinel_pod_json() -> serde_json::Value {
        let pod = core_v1::Pod {
            spec: Some(core_v1::PodSpec::sentinel()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();
        decode_pod_proto_gen(&buf).expect("sentinel Pod must decode via the generated path")
    }

    #[test]
    fn sentinel_completeness_gen_pod_spec_to_json() {
        let pod = sentinel_pod_json();
        let mut spec_only = pod["spec"].clone();
        // Blank out (but keep the keys of) nested Container/EphemeralContainer output: both
        // share field names with PodSpec itself (resources, restartPolicy, securityContext),
        // so without this a dropped PodSpec-level field could hide behind its Container-level
        // namesake still being present somewhere in the tree.
        if let Some(obj) = spec_only.as_object_mut() {
            for key in ["containers", "initContainers", "ephemeralContainers"] {
                obj.insert(key.to_string(), serde_json::Value::Array(Vec::new()));
            }
        }
        let mut paths = BTreeSet::new();
        collect_leaf_paths(&spec_only, "", &mut paths);

        // Every container field below (volumes/nodeSelector/securityContext/etc.) is never
        // itself a real leaf once populated — only a genuine descendant leaf can survive strict
        // leaf-path matching, so each gets a dotted entry pointing at one of its own fields
        // instead of relying on its bare (never-a-leaf) name. PodSecurityContext's own
        // completeness is covered separately by sentinel_completeness_gen_pod_security_context_to_json;
        // this only needs one leaf proving it survives at all.
        let expected = [
            "volumes.name",
            "initContainers",
            "containers",
            "ephemeralContainers",
            "restartPolicy",
            "terminationGracePeriodSeconds",
            "activeDeadlineSeconds",
            "dnsPolicy",
            "nodeSelector.__sentinel__",
            "serviceAccountName",
            "serviceAccount",
            "automountServiceAccountToken",
            "nodeName",
            "hostNetwork",
            "hostPID",
            "hostIPC",
            "shareProcessNamespace",
            "securityContext.runAsUser",
            "imagePullSecrets.name",
            "hostname",
            "subdomain",
            "affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution.weight",
            "schedulerName",
            "tolerations.key",
            "hostAliases.ip",
            "priorityClassName",
            "priority",
            "dnsConfig.nameservers",
            "readinessGates.conditionType",
            "runtimeClassName",
            "enableServiceLinks",
            "preemptionPolicy",
            "overhead.__sentinel__",
            "topologySpreadConstraints.maxSkew",
            "setHostnameAsFQDN",
            "os.name",
            "hostUsers",
            "schedulingGates.name",
            "resourceClaims.name",
            "resources.claims.name",
            "hostnameOverride",
            "schedulingGroup.podGroupName",
        ];
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_gen_container_to_json() {
        let pod = sentinel_pod_json();
        let mut paths = BTreeSet::new();
        collect_leaf_paths(&pod["spec"]["containers"], "", &mut paths);

        // Every container field below (ports/envFrom/env/resources/etc.) is never itself a real
        // leaf once populated — this is the exact shape of bug that originally motivated this
        // sentinel test: "volumeMounts" alone passed even though VolumeMount.mountPropagation
        // was silently dropped, because some *other* field of the same VolumeMount (e.g.
        // mountPath) surviving was enough. Each entry below now pins the check to a genuine leaf
        // child; "volumeMounts.mountPropagation" specifically re-checks that original finding.
        let expected = [
            "name",
            "image",
            "command",
            "args",
            "workingDir",
            "ports.containerPort",
            "envFrom.prefix",
            "env.name",
            "resources.claims.name",
            "resizePolicy.resourceName",
            "restartPolicy",
            "restartPolicyRules.action",
            "volumeMounts.mountPropagation",
            "volumeDevices.devicePath",
            "livenessProbe.initialDelaySeconds",
            "readinessProbe.initialDelaySeconds",
            "startupProbe.initialDelaySeconds",
            "lifecycle.postStart.sleep.seconds",
            "terminationMessagePath",
            "terminationMessagePolicy",
            "imagePullPolicy",
            "securityContext.privileged",
            "stdin",
            "stdinOnce",
            "tty",
        ];
        assert_fields_present(&paths, &expected);
    }

    /// Sentinel completeness for `gen_security_context_to_json`, gated against the schema
    /// itself.
    ///
    /// seLinuxOptions, windowsOptions, procMount and appArmorProfile had no handling at all in
    /// this function: a container requesting SELinux/Windows hardening, a non-default
    /// procMount, or an AppArmor profile via a protobuf-encoded create (client-go's default
    /// wire format) had every one of those controls silently stripped before the object ever
    /// reached storage, with no error anywhere — the container then runs less confined than
    /// the client believes it configured.
    #[test]
    fn sentinel_completeness_gen_security_context_to_json() {
        let pod = core_v1::Pod {
            spec: Some(core_v1::PodSpec {
                containers: vec![core_v1::Container {
                    security_context: Some(core_v1::SecurityContext::sentinel()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();
        let result = decode_pod_proto_gen(&buf)
            .expect("sentinel container SecurityContext must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(
            &result["spec"]["containers"][0]["securityContext"],
            "",
            &mut paths,
        );

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.core.v1.SecurityContext",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// Sentinel completeness for `gen_pod_security_context_to_json`, gated against the schema
    /// itself.
    ///
    /// seLinuxOptions, windowsOptions, seLinuxChangePolicy, fsGroupChangePolicy and
    /// supplementalGroupsPolicy had no handling at all in this function: a pod-wide SELinux
    /// relabeling policy, fsGroup ownership-change policy, or supplemental-groups merge policy
    /// set via a protobuf-encoded create was silently stripped before the object ever reached
    /// storage, with no error anywhere — every container in the pod then runs less confined
    /// than the client believes it configured.
    #[test]
    fn sentinel_completeness_gen_pod_security_context_to_json() {
        let pod = core_v1::Pod {
            spec: Some(core_v1::PodSpec {
                security_context: Some(core_v1::PodSecurityContext::sentinel()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();
        let result = decode_pod_proto_gen(&buf)
            .expect("sentinel PodSecurityContext must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result["spec"]["securityContext"], "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.core.v1.PodSecurityContext",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// Sentinel completeness for `gen_pod_status_to_json`, gated against the schema itself
    /// rather than a hand-typed list.
    ///
    /// `gen_pod_status_to_json` was originally shipped with a hand-listed regression test
    /// asserting only `phase`/`podIP`/`conditions` — a test that stayed green while
    /// `containerStatuses` and five other top-level `PodStatus` fields (and everything
    /// reachable through them) were absent from the emitter, because the same human who
    /// wrote the emitter also wrote the list of fields it was checked against. Deriving
    /// `expected` from the compiled `FileDescriptorSet` instead means a field this function
    /// forgets shows up here automatically, whether or not anyone remembers to add it to a
    /// list by hand.
    #[test]
    fn sentinel_completeness_gen_pod_status_to_json() {
        let pod = core_v1::Pod {
            status: Some(core_v1::PodStatus::sentinel()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();
        let result = decode_pod_proto_gen(&buf)
            .expect("sentinel PodStatus must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result["status"], "", &mut paths);

        let expected =
            crate::proto_descriptor::expected_json_keys_for(&[".k8s.io.api.core.v1.PodStatus"]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// Sentinel completeness for `gen_node_status_to_json`, gated against the schema itself.
    ///
    /// `config`/`runtimeHandlers` (and the features they gate scheduling/admission decisions
    /// on, like RecursiveReadOnlyMounts/UserNamespaces support) were absent from this function
    /// entirely, and `daemonEndpoints.kubeletEndpoint.port` was emitted under the .proto's
    /// Go-style capitalised `Port` instead of the real Kubernetes JSON key — a hand-typed
    /// expected list would have needed a human to notice both. Deriving `expected` from the
    /// compiled `FileDescriptorSet` makes a field this function forgets show up automatically.
    #[test]
    fn sentinel_completeness_gen_node_status_to_json() {
        let node = core_v1::Node {
            status: Some(core_v1::NodeStatus::sentinel()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        node.encode(&mut buf).unwrap();
        let result = decode_node_proto_gen(&buf)
            .expect("sentinel NodeStatus must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result["status"], "", &mut paths);

        let expected =
            crate::proto_descriptor::expected_json_keys_for(&[".k8s.io.api.core.v1.NodeStatus"]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// Sentinel completeness for `decode_service_proto_gen`, gated against the schema itself.
    ///
    /// Fifteen ServiceSpec/ServiceStatus.loadBalancer.ingress fields (clusterIPs,
    /// loadBalancerSourceRanges, publishNotReadyAddresses, sessionAffinityConfig, ipMode on
    /// LoadBalancerIngress, ...) were absent from this decoder entirely — a hand-typed
    /// expected list, written by the same person who wrote the emitter, would have needed to
    /// remember all fifteen. Deriving `expected` from the compiled `FileDescriptorSet` instead
    /// means a field this function forgets shows up here automatically.
    #[test]
    fn sentinel_completeness_gen_service_to_json() {
        let svc = core_v1::Service::sentinel();
        let mut buf = Vec::new();
        svc.encode(&mut buf).unwrap();
        let result = decode_service_proto_gen(&buf)
            .expect("sentinel Service must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let expected =
            crate::proto_descriptor::expected_json_keys_for(&[".k8s.io.api.core.v1.Service"]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// Round-trips a fully sentinel-populated Service through `encode_service_proto_gen`
    /// (JSON -> proto), symmetric to `sentinel_completeness_gen_service_to_json` above (proto
    /// -> JSON). A field present in the decode-side JSON but missing after re-encoding is a
    /// field `json_to_service_spec_proto`/`json_to_service_status_proto` never reads at all.
    #[test]
    fn sentinel_completeness_encode_service_proto_gen() {
        let svc = core_v1::Service::sentinel();
        let mut buf = Vec::new();
        svc.encode(&mut buf).unwrap();
        let json = decode_service_proto_gen(&buf)
            .expect("sentinel Service must decode via generated path");

        let raw = encode_service_proto_gen(&json);
        let redecoded =
            decode_service_proto_gen(&raw).expect("encoded sentinel Service bytes must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&redecoded, "", &mut paths);

        let expected =
            crate::proto_descriptor::expected_json_keys_for(&[".k8s.io.api.core.v1.Service"]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// `encode_servicelist_proto_gen` delegates per-item encoding to `json_to_service_proto`
    /// (already covered field-by-field above), so this only needs to confirm the list wrapper
    /// itself doesn't drop an item or its own `metadata.resourceVersion` — the same shape as
    /// `encode_podlist_proto_gen_round_trips_all_items_and_resource_version` below.
    #[test]
    fn sentinel_completeness_encode_servicelist_proto_gen() {
        let svc = core_v1::Service::sentinel();
        let mut buf = Vec::new();
        svc.encode(&mut buf).unwrap();
        let item = decode_service_proto_gen(&buf)
            .expect("sentinel Service must decode via generated path");
        let list = serde_json::json!({ "metadata": { "resourceVersion": "99" }, "items": [item] });

        let raw = encode_servicelist_proto_gen(&list);
        let decoded_list =
            core_v1::ServiceList::decode(raw.as_slice()).expect("encoded ServiceList must decode");
        assert_eq!(
            decoded_list.items.len(),
            1,
            "the sentinel item must survive the list wrapper"
        );
        assert_eq!(
            decoded_list.metadata.unwrap().resource_version.as_deref(),
            Some("99"),
            "list resourceVersion must survive"
        );

        let mut item_buf = Vec::new();
        decoded_list.items[0].encode(&mut item_buf).unwrap();
        let redecoded_item =
            decode_service_proto_gen(&item_buf).expect("re-encoded sentinel item must decode");
        let mut paths = BTreeSet::new();
        collect_leaf_paths(&redecoded_item, "", &mut paths);
        let expected =
            crate::proto_descriptor::expected_json_keys_for(&[".k8s.io.api.core.v1.Service"]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// Round-trips a fully sentinel-populated Node through `encode_node_proto_gen`, symmetric
    /// to the existing `decode_node_proto_gen_preserves_*` tests above.
    #[test]
    fn sentinel_completeness_encode_node_proto_gen() {
        let node = core_v1::Node::sentinel();
        let mut buf = Vec::new();
        node.encode(&mut buf).unwrap();
        let json =
            decode_node_proto_gen(&buf).expect("sentinel Node must decode via generated path");

        let raw = encode_node_proto_gen(&json);
        let redecoded =
            decode_node_proto_gen(&raw).expect("encoded sentinel Node bytes must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&redecoded, "", &mut paths);

        // The codegen migration (build/codegen.rs::generate_node_status) completed
        // `json_to_node_status_proto`'s JSON->proto direction for every field that previously
        // fell through a trailing `..Default::default()` — spec.configSource, status.config,
        // status.images/volumesAttached/volumesInUse/runtimeHandlers/declaredFeatures/features
        // all now round-trip and are no longer excluded below. `status.nodeInfo.swap` stays
        // excluded on purpose: `gen_node_system_info_to_json`'s `swap.capacity` zero-filter
        // guard (preserved verbatim from the pre-migration decoder) makes a genuinely-zero
        // capacity indistinguishable from unset, so it is deliberately not round-tripped.
        let excluded = ["status.nodeInfo.swap"];
        let all = crate::proto_descriptor::expected_json_keys_for(&[".k8s.io.api.core.v1.Node"]);
        let expected: Vec<&str> = all
            .iter()
            .map(String::as_str)
            .filter(|f| {
                !excluded
                    .iter()
                    .any(|ex| *f == *ex || f.starts_with(&format!("{ex}.")))
            })
            .collect();
        assert_fields_present(&paths, &expected);
    }

    /// `encode_nodelist_proto_gen` list-wrapper coverage; per-item field coverage is the test
    /// above.
    #[test]
    fn sentinel_completeness_encode_nodelist_proto_gen() {
        let node = core_v1::Node::sentinel();
        let mut buf = Vec::new();
        node.encode(&mut buf).unwrap();
        let item =
            decode_node_proto_gen(&buf).expect("sentinel Node must decode via generated path");
        let list = serde_json::json!({ "metadata": { "resourceVersion": "99" }, "items": [item] });

        let raw = encode_nodelist_proto_gen(&list);
        let decoded_list =
            core_v1::NodeList::decode(raw.as_slice()).expect("encoded NodeList must decode");
        assert_eq!(
            decoded_list.items.len(),
            1,
            "the sentinel item must survive the list wrapper"
        );
        assert_eq!(
            decoded_list.metadata.unwrap().resource_version.as_deref(),
            Some("99"),
            "list resourceVersion must survive"
        );
    }

    /// Round-trips a fully sentinel-populated Endpoints through `encode_endpoints_proto_gen`.
    #[test]
    fn sentinel_completeness_encode_endpoints_proto_gen() {
        let eps = core_v1::Endpoints::sentinel();
        let mut buf = Vec::new();
        eps.encode(&mut buf).unwrap();
        let json = decode_endpoints_proto_gen(&buf)
            .expect("sentinel Endpoints must decode via generated path");

        let raw = encode_endpoints_proto_gen(&json);
        let redecoded =
            decode_endpoints_proto_gen(&raw).expect("encoded sentinel Endpoints bytes must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&redecoded, "", &mut paths);

        let expected =
            crate::proto_descriptor::expected_json_keys_for(&[".k8s.io.api.core.v1.Endpoints"]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// `encode_endpointslist_proto_gen` list-wrapper coverage; per-item field coverage is the
    /// test above.
    #[test]
    fn sentinel_completeness_encode_endpointslist_proto_gen() {
        let eps = core_v1::Endpoints::sentinel();
        let mut buf = Vec::new();
        eps.encode(&mut buf).unwrap();
        let item = decode_endpoints_proto_gen(&buf)
            .expect("sentinel Endpoints must decode via generated path");
        let list = serde_json::json!({ "metadata": { "resourceVersion": "99" }, "items": [item] });

        let raw = encode_endpointslist_proto_gen(&list);
        let decoded_list = core_v1::EndpointsList::decode(raw.as_slice())
            .expect("encoded EndpointsList must decode");
        assert_eq!(
            decoded_list.items.len(),
            1,
            "the sentinel item must survive the list wrapper"
        );
        assert_eq!(
            decoded_list.metadata.unwrap().resource_version.as_deref(),
            Some("99"),
            "list resourceVersion must survive"
        );
    }

    /// Round-trips a fully sentinel-populated Event through `encode_event_proto_gen`.
    #[test]
    fn sentinel_completeness_encode_event_proto_gen() {
        let event = core_v1::Event::sentinel();
        let mut buf = Vec::new();
        event.encode(&mut buf).unwrap();
        let json =
            decode_event_proto_gen(&buf).expect("sentinel Event must decode via generated path");

        let raw = encode_event_proto_gen(&json);
        let redecoded =
            decode_event_proto_gen(&raw).expect("encoded sentinel Event bytes must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&redecoded, "", &mut paths);

        let expected =
            crate::proto_descriptor::expected_json_keys_for(&[".k8s.io.api.core.v1.Event"]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// `encode_eventlist_proto_gen` list-wrapper coverage; per-item field coverage is the test
    /// above.
    #[test]
    fn sentinel_completeness_encode_eventlist_proto_gen() {
        let event = core_v1::Event::sentinel();
        let mut buf = Vec::new();
        event.encode(&mut buf).unwrap();
        let item =
            decode_event_proto_gen(&buf).expect("sentinel Event must decode via generated path");
        let list = serde_json::json!({ "metadata": { "resourceVersion": "99" }, "items": [item] });

        let raw = encode_eventlist_proto_gen(&list);
        let decoded_list =
            core_v1::EventList::decode(raw.as_slice()).expect("encoded EventList must decode");
        assert_eq!(
            decoded_list.items.len(),
            1,
            "the sentinel item must survive the list wrapper"
        );
        assert_eq!(
            decoded_list.metadata.unwrap().resource_version.as_deref(),
            Some("99"),
            "list resourceVersion must survive"
        );
    }

    // ---- Sentinel completeness: encode_pod_proto_gen (JSON -> proto direction) -----------
    //
    // Symmetric to `sentinel_completeness_gen_pod_spec_to_json`/`gen_container_to_json` above,
    // but for the opposite direction: those decode a sentinel-populated proto message and check
    // every field reaches JSON; these start from that same decoded JSON (already known to carry
    // every field the decode path supports) and check that `encode_pod_proto_gen` puts every one
    // of those JSON fields back on the wire. A field present here but missing after the
    // encode-then-decode round trip is a field `json_to_pod_spec_proto`/`json_to_container_proto`
    // never reads from JSON at all — this is exactly the class of bug PR #1130 introduced and
    // this bead's fix plugs: a client that negotiates protobuf (every real client-go typed
    // clientset, by default) silently loses that field on every GET/LIST/WATCH.
    //
    // `expected` intentionally excludes fields this bead's scope explicitly defers (see the
    // bead's follow-on beads): DRA pod-level resourceClaims / PodLevelResources-alpha `resources`
    // / HostnameOverride-alpha `hostnameOverride` / GenericWorkload-alpha `schedulingGroup` (none
    // of which are exercised by certified-conformance today). It also can't cover the ~15
    // rarely-used/deprecated VolumeSource variants (iscsi/glusterfs/rbd/gitRepo/cinder/cephfs/
    // flexVolume/flocker/azureFile/vsphereVolume/quobyte/azureDisk/portworxVolume/scaleIO/
    // storageos) even though json_to_volume_proto now encodes them: decode_pod_proto_gen itself
    // never produces those keys in `sentinel_pod_json()`'s input, so there is nothing here for
    // the encoder to round-trip. See
    // `encode_pod_proto_gen_round_trips_rare_deprecated_volume_sources` below, which tests
    // json_to_volume_proto for those variants directly against the raw protobuf struct instead.
    #[test]
    fn sentinel_completeness_encode_pod_proto_gen() {
        let json = sentinel_pod_json();
        let raw = encode_pod_proto_gen(&json);
        let redecoded = decode_pod_proto_gen(&raw)
            .expect("encoded sentinel Pod bytes must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&redecoded, "", &mut paths);

        let expected = [
            "volumes.name",
            "volumes.hostPath.path",
            "volumes.emptyDir.medium",
            "volumes.secret.secretName",
            "volumes.configMap.name",
            "volumes.persistentVolumeClaim.claimName",
            "volumes.downwardAPI.items.path",
            "volumes.projected.sources.secret.name",
            // nfs/ephemeral/csi and the projected podCertificate/clusterTrustBundle
            // sub-variants: decode_pod_proto_gen already produces these keys (unlike the ~15
            // variants excluded above), so this is a genuine round-trip check of the encoder
            // branches added for them.
            "volumes.nfs.server",
            "volumes.ephemeral.volumeClaimTemplate.spec.accessModes",
            "volumes.csi.driver",
            "volumes.projected.sources.podCertificate.signerName",
            "volumes.projected.sources.clusterTrustBundle.signerName",
            "containers.name",
            "containers.image",
            "containers.command",
            "containers.args",
            "containers.workingDir",
            "containers.ports.containerPort",
            "containers.envFrom.prefix",
            "containers.env.name",
            "containers.resources.limits.__sentinel__",
            "containers.resizePolicy.resourceName",
            "containers.volumeMounts.subPathExpr",
            "containers.livenessProbe.initialDelaySeconds",
            "containers.readinessProbe.initialDelaySeconds",
            "containers.startupProbe.initialDelaySeconds",
            "containers.lifecycle.postStart.sleep.seconds",
            "containers.terminationMessagePath",
            "containers.terminationMessagePolicy",
            "containers.imagePullPolicy",
            "containers.securityContext.privileged",
            "initContainers.name",
            "ephemeralContainers.targetContainerName",
            "restartPolicy",
            "terminationGracePeriodSeconds",
            "activeDeadlineSeconds",
            "dnsPolicy",
            "nodeSelector.__sentinel__",
            "serviceAccountName",
            "serviceAccount",
            "automountServiceAccountToken",
            "nodeName",
            "hostNetwork",
            "hostPID",
            "hostIPC",
            "shareProcessNamespace",
            "securityContext.runAsUser",
            "imagePullSecrets.name",
            "hostname",
            "subdomain",
            "affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution.weight",
            "schedulerName",
            "tolerations.key",
            "hostAliases.ip",
            "priorityClassName",
            "priority",
            "dnsConfig.nameservers",
            "readinessGates.conditionType",
            "runtimeClassName",
            "enableServiceLinks",
            "preemptionPolicy",
            "overhead.__sentinel__",
            "topologySpreadConstraints.maxSkew",
            "setHostnameAsFQDN",
            "os.name",
            "schedulingGates.name",
        ];
        assert_fields_present(&paths, &expected);
    }

    /// Container.securityContext specifically, gated the same way `sentinel_completeness_gen_
    /// security_context_to_json` gates the decode direction: seLinuxOptions/windowsOptions/
    /// procMount/appArmorProfile are exactly the fields that class of bug hid previously.
    #[test]
    fn sentinel_completeness_encode_container_security_context() {
        let json = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "img",
                    "securityContext": {
                        "capabilities": { "add": ["NET_ADMIN"], "drop": ["ALL"] },
                        "privileged": true,
                        "seLinuxOptions": { "user": "u", "role": "r", "type": "t", "level": "l" },
                        "windowsOptions": { "runAsUserName": "ContainerAdministrator" },
                        "runAsUser": 1000,
                        "runAsGroup": 2000,
                        "runAsNonRoot": true,
                        "readOnlyRootFilesystem": true,
                        "allowPrivilegeEscalation": false,
                        "procMount": "Unmasked",
                        "seccompProfile": { "type": "Localhost", "localhostProfile": "p.json" },
                        "appArmorProfile": { "type": "Localhost", "localhostProfile": "k8s-apparmor-example-deny-write" }
                    }
                }]
            }
        });
        let raw = encode_pod_proto_gen(&json);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded sentinel Pod bytes must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(
            &decoded["spec"]["containers"][0]["securityContext"],
            "",
            &mut paths,
        );

        let expected = [
            "capabilities.add",
            "capabilities.drop",
            "privileged",
            "seLinuxOptions.user",
            "windowsOptions.runAsUserName",
            "runAsUser",
            "runAsGroup",
            "runAsNonRoot",
            "readOnlyRootFilesystem",
            "allowPrivilegeEscalation",
            "procMount",
            "seccompProfile.type",
            "appArmorProfile.type",
        ];
        assert_fields_present(&paths, &expected);
    }

    /// Round-trips a fully sentinel-populated PodStatus through `encode_pod_proto_gen`,
    /// symmetric to `sentinel_completeness_gen_pod_status_to_json` (proto -> JSON) above. This
    /// is the test that would have caught `status.observedGeneration` being silently dropped by
    /// `json_to_pod_status_proto`: the exact bug behind the live `[sig-node] Pods Extended (pod
    /// generation) issue 500 podspec updates` failure, where a protobuf-polling client
    /// (`WaitForPodObservedGeneration`) read back `observedGeneration: 0` forever regardless of
    /// what the real kubelet had actually written to the stored JSON.
    #[test]
    fn sentinel_completeness_encode_pod_status_proto_gen() {
        let pod = core_v1::Pod {
            status: Some(core_v1::PodStatus::sentinel()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        pod.encode(&mut buf).unwrap();
        let json =
            decode_pod_proto_gen(&buf).expect("sentinel PodStatus must decode via generated path");

        let raw = encode_pod_proto_gen(&json);
        let redecoded =
            decode_pod_proto_gen(&raw).expect("encoded sentinel PodStatus bytes must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&redecoded["status"], "", &mut paths);

        // Excluded, all alpha/feature-gated and outside this test's scope — tracked as a P3
        // follow-on rather than expanded here: resizeStatus (legacy alias, superseded by
        // `resize`), containerStatuses[].stopSignal (ContainerStopSignals),
        // containerStatuses[].allocatedResourcesStatus (ResourceHealth, ResourceHealthStatus),
        // and the DRA claim-status fields (resourceClaimStatuses, extendedResourceClaimStatus,
        // nodeAllocatableResourceClaimStatuses), plus volumeMounts[].volumeStatus
        // (ImageVolumeWithDigest, alpha). `resize`, containerStatuses[].volumeMounts (aside from
        // volumeStatus) and containerStatuses[].user are now handled by json_to_pod_status_proto
        // / json_to_container_status_proto — the in-place-resize conformance test's DeepEqual
        // compares a protobuf-negotiated Get against the /resize subresource's JSON Get, and
        // these fields must round-trip identically or the two never match.
        let excluded_prefixes = ["resizeStatus"];
        let excluded_substrings = [".stopSignal", ".allocatedResourcesStatus", ".volumeStatus"];
        let excluded_top_level = [
            "resourceClaimStatuses",
            "extendedResourceClaimStatus",
            "nodeAllocatableResourceClaimStatuses",
        ];
        let all =
            crate::proto_descriptor::expected_json_keys_for(&[".k8s.io.api.core.v1.PodStatus"]);
        let expected: Vec<&str> = all
            .iter()
            .map(String::as_str)
            .filter(|f| {
                let top_level = f.split('.').next().unwrap_or(f);
                !excluded_prefixes
                    .iter()
                    .any(|ex| *f == *ex || f.starts_with(&format!("{ex}.")))
                    && !excluded_substrings.iter().any(|ex| f.contains(ex))
                    && !excluded_top_level.contains(&top_level)
            })
            .collect();
        assert_fields_present(&paths, &expected);
    }

    /// PodSpec.securityContext, gated the same way `sentinel_completeness_gen_pod_security_
    /// context_to_json` gates the decode direction.
    #[test]
    fn sentinel_completeness_encode_pod_security_context() {
        let json = serde_json::json!({
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "securityContext": {
                    "seLinuxOptions": { "user": "u" },
                    "windowsOptions": { "runAsUserName": "ContainerAdministrator" },
                    "runAsUser": 1000,
                    "runAsGroup": 2000,
                    "runAsNonRoot": true,
                    "fsGroup": 3000,
                    "supplementalGroups": [4000],
                    "supplementalGroupsPolicy": "Merge",
                    "sysctls": [{ "name": "kernel.shm_rmid_forced", "value": "1" }],
                    "fsGroupChangePolicy": "OnRootMismatch",
                    "seccompProfile": { "type": "RuntimeDefault" },
                    "appArmorProfile": { "type": "RuntimeDefault" },
                    "seLinuxChangePolicy": "Recursive"
                }
            }
        });
        let raw = encode_pod_proto_gen(&json);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded sentinel Pod bytes must decode");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded["spec"]["securityContext"], "", &mut paths);

        let expected = [
            "seLinuxOptions.user",
            "windowsOptions.runAsUserName",
            "runAsUser",
            "runAsGroup",
            "runAsNonRoot",
            "fsGroup",
            "supplementalGroups",
            "supplementalGroupsPolicy",
            "sysctls.name",
            "fsGroupChangePolicy",
            "seccompProfile.type",
            "appArmorProfile.type",
            "seLinuxChangePolicy",
        ];
        assert_fields_present(&paths, &expected);
    }

    // ---- Response-side protobuf encoder round-trip tests ------------------
    //
    // Each test round-trips JSON -> encode_*_proto_gen -> decode_*_proto_gen -> JSON.
    // A regression here means a kubelet/kube-proxy/scheduler client that negotiated
    // Accept: application/vnd.kubernetes.protobuf on a GET/LIST would receive a
    // response with the asserted field silently missing or wrong, even though the
    // same field is present in u7s's own JSON representation of the object.

    /// Pod round-trips through the protobuf encoder: a kubelet that watches Pods over
    /// protobuf (client-go's default when the server offers it) needs spec.containers,
    /// spec.nodeName and status.phase/podIP to actually run and report on the pod: if any
    /// of these vanish on the wire, the kubelet either can't start the container or reports
    /// stale/empty status back to the control plane.
    #[test]
    fn encode_pod_proto_gen_round_trips_container_and_status_fields() {
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "web-1", "namespace": "default", "uid": "abc-123" },
            "spec": {
                "containers": [{
                    "name": "web",
                    "image": "nginx:1.27",
                    "ports": [{ "containerPort": 80, "protocol": "TCP" }],
                    "resources": { "requests": { "cpu": "100m" } }
                }],
                "nodeName": "worker-1",
                "restartPolicy": "Always"
            },
            "status": {
                "phase": "Running",
                "podIP": "10.0.0.5",
                "containerStatuses": [{ "name": "web", "ready": true, "restartCount": 0 }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(decoded["metadata"]["name"], "web-1");
        assert_eq!(decoded["spec"]["containers"][0]["image"], "nginx:1.27");
        assert_eq!(
            decoded["spec"]["containers"][0]["ports"][0]["containerPort"],
            80
        );
        assert_eq!(decoded["spec"]["nodeName"], "worker-1");
        assert_eq!(decoded["status"]["phase"], "Running");
        assert_eq!(decoded["status"]["podIP"], "10.0.0.5");
        assert_eq!(
            decoded["status"]["containerStatuses"][0]["ready"], true,
            "containerStatuses[].ready must survive the round trip — kube-proxy/kubectl's \
             READY column and readiness-gated traffic routing both depend on it"
        );
    }

    /// `Container.stdin`/`stdinOnce`/`tty`/`restartPolicy`/`restartPolicyRules`/`volumeDevices`
    /// used to be silently dropped by `json_to_container_proto` on the JSON->proto direction
    /// (the hand-rolled decoder built a `Container` literal covering only ~18 of Container's 25
    /// fields and fell back to `..Default::default()` for the rest) even though the proto->JSON
    /// direction (`gen_container_to_json`) already emitted them — so a client that read a pod
    /// back over protobuf (e.g. a controller's typed clientset) would see these fields, but a
    /// protobuf-negotiating client's *write* of the same fields (e.g. `kubectl replace
    /// --raw`-style flows via a protobuf-speaking proxy) silently lost them. `build/codegen.rs`'s
    /// schema-driven walker derives both directions from the same field enumeration, so this
    /// asymmetry cannot recur field-by-field the way it did by hand. `restartPolicyRules[].
    /// exitCodes.values` additionally exercises the new `repeated int32` mechanical shape nested
    /// two levels deep — the first field in this migration needing it.
    #[test]
    fn encode_pod_proto_gen_round_trips_container_lifecycle_and_restart_fields() {
        let pod = serde_json::json!({
            "metadata": { "name": "interactive-pod", "namespace": "default" },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "img",
                    "stdin": true,
                    "stdinOnce": true,
                    "tty": true,
                    "restartPolicy": "Always",
                    "restartPolicyRules": [{
                        "action": "Restart",
                        "exitCodes": { "operator": "In", "values": [42, 137] }
                    }],
                    "volumeDevices": [{ "name": "block0", "devicePath": "/dev/xvda" }]
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");
        let c = &decoded["spec"]["containers"][0];

        assert_eq!(
            c["stdin"], true,
            "stdin must survive the round trip — a pod created for `kubectl run -it`-style \
             interactive use silently becomes non-interactive without it"
        );
        assert_eq!(
            c["stdinOnce"], true,
            "stdinOnce must survive the round trip"
        );
        assert_eq!(c["tty"], true, "tty must survive the round trip");
        assert_eq!(
            c["restartPolicy"], "Always",
            "container-level restartPolicy must survive the round trip — it overrides the \
             pod-level policy for sidecar-style init containers"
        );
        assert_eq!(
            c["restartPolicyRules"][0]["action"], "Restart",
            "restartPolicyRules must survive the round trip — without it an exit-code-specific \
             restart exception silently falls back to the container's blanket restartPolicy"
        );
        assert_eq!(
            c["restartPolicyRules"][0]["exitCodes"]["values"],
            serde_json::json!([42, 137]),
            "exitCodes.values (repeated int32, nested two levels inside restartPolicyRules) must \
             survive the round trip byte-for-byte, not just as an empty/truncated array"
        );
        assert_eq!(
            c["volumeDevices"][0]["devicePath"], "/dev/xvda",
            "volumeDevices must survive the round trip — without it a container asking for a \
             raw block device mapping silently starts without one"
        );
    }

    /// A Job's per-pod `activeDeadlineSeconds` and a RuntimeClass-scheduled pod's
    /// `runtimeClassName`/`overhead` must survive protobuf encoding: without
    /// activeDeadlineSeconds a kubelet watching over protobuf (client-go's default) never
    /// kills a pod that overruns its deadline; without runtimeClassName/overhead the
    /// scheduler under-accounts for the sandbox's real resource footprint.
    #[test]
    fn encode_pod_proto_gen_round_trips_active_deadline_runtime_class_and_overhead() {
        let pod = serde_json::json!({
            "metadata": { "name": "deadline-pod", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "activeDeadlineSeconds": 5000,
                "runtimeClassName": "gvisor",
                "overhead": { "cpu": "250m", "memory": "120Mi" }
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["spec"]["activeDeadlineSeconds"], 5000,
            "activeDeadlineSeconds must survive the round trip — before this fix the field \
             was never read from JSON, so a Job's per-pod deadline was silently unenforceable \
             for any protobuf-watching kubelet"
        );
        assert_eq!(
            decoded["spec"]["runtimeClassName"], "gvisor",
            "runtimeClassName must survive — otherwise the kubelet doesn't know which \
             runtime handler to use and RuntimeClass scheduling is silently ignored"
        );
        assert_eq!(
            decoded["spec"]["overhead"]["cpu"], "250m",
            "overhead must survive — without it the scheduler doesn't reserve the sandbox's \
             resource overhead, over-committing the node"
        );
    }

    /// `kubectl debug`'s ephemeral container (and its terminal status) must survive protobuf
    /// encoding: client-go's UpdateEphemeralContainers/pod-watch calls negotiate protobuf by
    /// default, so before this fix the debug container was silently dropped before the
    /// kubelet — or a status poller — ever saw it.
    #[test]
    fn encode_pod_proto_gen_round_trips_ephemeral_containers_and_statuses() {
        let pod = serde_json::json!({
            "metadata": { "name": "debug-pod", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "ephemeralContainers": [{
                    "name": "debugger",
                    "image": "busybox",
                    "targetContainerName": "c"
                }]
            },
            "status": {
                "ephemeralContainerStatuses": [{
                    "name": "debugger",
                    "state": { "terminated": { "exitCode": 0 } }
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["spec"]["ephemeralContainers"][0]["name"], "debugger",
            "ephemeralContainers[].name must survive — before this fix the whole \
             ephemeralContainers list was dropped by the encoder, so 'debugger' never \
             appeared in the protobuf a kubelet watch decodes"
        );
        assert_eq!(
            decoded["spec"]["ephemeralContainers"][0]["targetContainerName"], "c",
            "targetContainerName must survive — the kubelet needs it to run the ephemeral \
             container in the target container's namespaces"
        );
        assert_eq!(
            decoded["status"]["ephemeralContainerStatuses"][0]["name"], "debugger",
            "ephemeralContainerStatuses must survive — without it a client polling for the \
             debug container's exit code over protobuf never observes it terminate"
        );
    }

    /// `status.observedGeneration` must survive protobuf encoding on its own, independent of
    /// `PodCondition.observedGeneration` (a same-named field nested under `conditions`, which
    /// this test deliberately omits — see `sentinel_completeness_encode_pod_status_proto_gen`'s
    /// note on suffix-matching masking one for the other). Before this fix, a protobuf-polling
    /// client (e2e's `WaitForPodObservedGeneration`, used by `[sig-node] Pods Extended (pod
    /// generation) issue 500 podspec updates`) always read back 0 regardless of what the real
    /// kubelet had written, so it could never observe convergence and timed out.
    #[test]
    fn encode_pod_proto_gen_round_trips_status_observed_generation_without_conditions() {
        let pod = serde_json::json!({
            "metadata": { "name": "gen-pod", "namespace": "default" },
            "spec": { "containers": [{ "name": "c", "image": "img" }] },
            "status": { "phase": "Running", "observedGeneration": 500 }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["status"]["observedGeneration"], 500,
            "status.observedGeneration must survive the round trip on its own — before this \
             fix json_to_pod_status_proto never read this key from JSON at all, so every \
             protobuf-negotiating GET returned observedGeneration=0"
        );
    }

    /// `conditions[].observedGeneration` must survive protobuf encoding: e2e's
    /// `WaitForPodConditionObservedGeneration` polls a specific condition's own
    /// `observedGeneration` (distinct from the status-level field tested above) over protobuf,
    /// and would time out the same way if this per-condition field were dropped.
    #[test]
    fn encode_pod_proto_gen_round_trips_condition_observed_generation() {
        let pod = serde_json::json!({
            "metadata": { "name": "cond-gen-pod", "namespace": "default" },
            "spec": { "containers": [{ "name": "c", "image": "img" }] },
            "status": {
                "conditions": [{
                    "type": "PodReadyToStartContainers",
                    "status": "True",
                    "observedGeneration": 3
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["status"]["conditions"][0]["observedGeneration"], 3,
            "conditions[].observedGeneration must survive — before this fix \
             json_to_pod_condition_proto never read this key, so WaitForPodConditionObserved\
             Generation could never observe a specific condition's convergence"
        );
    }

    /// In-place pod resize actuals (`containerStatuses[].resources`/`allocatedResources`) and
    /// the per-container `resizePolicy` must survive protobuf encoding: without them, a
    /// kubelet watching over protobuf reports every container as never-resized even after a
    /// successful resize, and never learns whether a resize should restart the container.
    #[test]
    fn encode_pod_proto_gen_round_trips_resize_policy_and_actuals() {
        let pod = serde_json::json!({
            "metadata": { "name": "resize-pod", "namespace": "default" },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "img",
                    "resizePolicy": [{ "resourceName": "memory", "restartPolicy": "RestartContainer" }]
                }]
            },
            "status": {
                "containerStatuses": [{
                    "name": "c",
                    "resources": { "requests": { "memory": "256Mi" } },
                    "allocatedResources": { "memory": "256Mi" }
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["spec"]["containers"][0]["resizePolicy"][0]["restartPolicy"],
            "RestartContainer",
            "containers[].resizePolicy must survive — without it the kubelet doesn't know \
             whether resizing memory requires restarting the container"
        );
        assert_eq!(
            decoded["status"]["containerStatuses"][0]["resources"]["requests"]["memory"], "256Mi",
            "containerStatuses[].resources must survive — this is the resize actual, not the \
             desired spec; dropping it makes every resize look unactuated"
        );
        assert_eq!(
            decoded["status"]["containerStatuses"][0]["allocatedResources"]["memory"], "256Mi",
            "containerStatuses[].allocatedResources must survive — the kubelet compares this \
             against the container's requests to admit further resizes"
        );
    }

    /// The in-place-resize conformance test ("resize pod via the replace endpoint") issues a
    /// resize, then compares a protobuf-negotiated `Pods.Get` against a JSON `Get` on the
    /// `/resize` subresource via `apiequality.Semantic.DeepEqual`. The `/resize` handler always
    /// returns the stored JSON verbatim, so any field this encoder drops on the protobuf side
    /// makes the two permanently unequal — the poll never converges and the test fails at
    /// pod_resize.go:823 ("pod from resize subresource not equivalent to pod"), even though the
    /// underlying stored pod is identical on both sides.
    #[test]
    fn encode_pod_proto_gen_round_trips_resize_subresource_comparison_fields() {
        let pod = serde_json::json!({
            "metadata": { "name": "resize-pod", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }]
            },
            "status": {
                "resize": "Proposed",
                "resources": { "requests": { "cpu": "150m" } },
                "allocatedResources": { "cpu": "150m" },
                "containerStatuses": [{
                    "name": "c",
                    "volumeMounts": [{
                        "name": "kube-api-access",
                        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                        "readOnly": true,
                        "recursiveReadOnly": "Disabled"
                    }],
                    "user": {
                        "linux": { "uid": 65535, "gid": 0, "supplementalGroups": [0] }
                    }
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["status"]["resize"], "Proposed",
            "status.resize must survive — the conformance test's kubelet-side poll observes \
             this field transition, and dropping it makes a protobuf Get diverge from the \
             /resize subresource's JSON Get for a pod with an in-progress resize"
        );
        assert_eq!(
            decoded["status"]["resources"]["requests"]["cpu"], "150m",
            "pod-level status.resources must survive — distinct from the per-container \
             containerStatuses[].resources already covered above"
        );
        assert_eq!(
            decoded["status"]["allocatedResources"]["cpu"], "150m",
            "pod-level status.allocatedResources must survive — distinct from the per-container \
             containerStatuses[].allocatedResources already covered above"
        );
        assert_eq!(
            decoded["status"]["containerStatuses"][0]["volumeMounts"][0]["mountPath"],
            "/var/run/secrets/kubernetes.io/serviceaccount",
            "containerStatuses[].volumeMounts must survive — every pod has a projected \
             service-account token mount, so dropping this field breaks the DeepEqual \
             comparison for essentially every real pod, not just resized ones"
        );
        assert_eq!(
            decoded["status"]["containerStatuses"][0]["user"]["linux"]["uid"], 65535,
            "containerStatuses[].user must survive — the kubelet reports the container's \
             actual running identity here, and every running container has one"
        );
    }

    /// `volumeMounts[].subPathExpr` (used by the Downward API to expand `$(NODE_NAME)`-style
    /// references into a mount subpath) must survive protobuf encoding, or the kubelet mounts
    /// the volume's root instead of the expanded subpath the pod spec actually requested.
    #[test]
    fn encode_pod_proto_gen_round_trips_volume_mount_sub_path_expr() {
        let pod = serde_json::json!({
            "metadata": { "name": "subpath-pod", "namespace": "default" },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "img",
                    "volumeMounts": [{
                        "name": "vol",
                        "mountPath": "/etc/podinfo",
                        "subPathExpr": "$(POD_NAME)"
                    }]
                }],
                "volumes": [{ "name": "vol", "emptyDir": {} }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["spec"]["containers"][0]["volumeMounts"][0]["subPathExpr"], "$(POD_NAME)",
            "subPathExpr must survive the round trip — before this fix it was never read \
             from JSON, so the kubelet mounted the volume's root instead of the pod's \
             requested expanded subpath, breaking the Variable Expansion conformance test"
        );
    }

    /// `env[].valueFrom.fieldRef` (and the sibling resourceFieldRef/configMapKeyRef/
    /// secretKeyRef refs) must survive protobuf encoding. Before this fix
    /// `json_to_env_var_proto` only ever read `name`/`value`, dropping `valueFrom` entirely —
    /// a container whose env var comes from `metadata.annotations['x']` ends up with an env
    /// var that has neither `value` nor `valueFrom` on the wire, and the real kubelet
    /// hard-fails with "missing value for <name>" instead of resolving the annotation. This is
    /// the root cause the live `[sig-node] Variable Expansion should verify that a failing
    /// subpath expansion can be modified` conformance failure traced back to: the test updates
    /// a pod's annotations, and the updated container's `$(ANNOTATION)` env var must resolve
    /// via its `fieldRef` for the subPathExpr mount to succeed.
    #[test]
    fn encode_pod_proto_gen_round_trips_env_var_value_from_field_ref() {
        let pod = serde_json::json!({
            "metadata": { "name": "envvar-pod", "namespace": "default" },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "img",
                    "env": [{
                        "name": "ANNOTATION",
                        "valueFrom": {
                            "fieldRef": { "fieldPath": "metadata.annotations['notmysubpath']" }
                        }
                    }]
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["spec"]["containers"][0]["env"][0]["valueFrom"]["fieldRef"]["fieldPath"],
            "metadata.annotations['notmysubpath']",
            "env[].valueFrom.fieldRef.fieldPath must survive the round trip — without it the \
             kubelet cannot resolve the env var at all and refuses to start the container \
             ('missing value for ANNOTATION'), even though value/valueFrom are mutually \
             exclusive by design and dropping valueFrom leaves nothing to fall back to"
        );
    }

    /// A `downwardAPI` volume (labels/annotations mounted as files) must survive protobuf
    /// encoding, or the real kubelet — which only sees the pod via a protobuf watch — refuses
    /// to mount it at all: "FailedMount ... no defaultMode used, not even the default value".
    #[test]
    fn encode_pod_proto_gen_round_trips_downward_api_volume() {
        let pod = serde_json::json!({
            "metadata": { "name": "downward-pod", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "volumes": [{
                    "name": "podinfo",
                    "downwardAPI": {
                        "items": [{
                            "path": "labels",
                            "fieldRef": { "fieldPath": "metadata.labels" }
                        }],
                        "defaultMode": 256
                    }
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        let volume = &decoded["spec"]["volumes"][0]["downwardAPI"];
        assert_eq!(
            volume["items"][0]["path"], "labels",
            "downwardAPI.items[].path must survive — before this fix the whole downwardAPI \
             volume source was dropped, so the real kubelet's protobuf watch saw a Volume \
             with no source at all and refused to mount it"
        );
        assert_eq!(
            volume["items"][0]["fieldRef"]["fieldPath"], "metadata.labels",
            "downwardAPI.items[].fieldRef.fieldPath must survive — this is what tells the \
             kubelet which pod field to write into the file"
        );
        assert_eq!(
            volume["defaultMode"], 256,
            "downwardAPI.defaultMode must survive as the caller's explicit value, not fall \
             back to the decoder's always-stamped default of 420 (0644)"
        );
    }

    /// u7s never runs a defaulting pass over a stored Pod's `downwardAPI` volume (there is no
    /// admission-time equivalent of upstream's `SetDefaults_PodSpec`), so a pod applied via
    /// plain JSON — the common case, e.g. `kubectl apply` — has no `defaultMode` key in the
    /// stored spec at all. This is the exact shape that broke live on lima-node-4: the
    /// encoder must still stamp `defaultMode = 420` on the wire, or the real kubelet's
    /// downwardAPI volume plugin refuses to mount it: "FailedMount ... no defaultMode used,
    /// not even the default value for it" — even though the encoder now includes the
    /// downwardAPI key at all (the fix verified by the test above).
    #[test]
    fn encode_pod_proto_gen_stamps_default_mode_when_stored_json_omits_it() {
        let pod = serde_json::json!({
            "metadata": { "name": "downward-pod-no-mode", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "volumes": [{
                    "name": "podinfo",
                    "downwardAPI": {
                        "items": [{ "path": "labels", "fieldRef": { "fieldPath": "metadata.labels" } }]
                    }
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["spec"]["volumes"][0]["downwardAPI"]["defaultMode"], 420,
            "defaultMode must be stamped to 420 (0644) even when the stored JSON never set \
             one — the real kubelet's downwardAPI volume plugin hard-fails the mount \
             (FailedMount: 'no defaultMode used, not even the default value for it') if the \
             wire field is absent, and nothing else in u7s ever defaults this field"
        );
    }

    /// A `projected` volume's `sources[]` (downwardAPI/configMap/secret/serviceAccountToken)
    /// must survive protobuf encoding, or the mounted volume ends up empty — the same
    /// FailedMount failure mode as a missing downwardAPI volume, just for the projected case.
    #[test]
    fn encode_pod_proto_gen_round_trips_projected_volume_sources() {
        let pod = serde_json::json!({
            "metadata": { "name": "projected-pod", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "volumes": [{
                    "name": "proj",
                    "projected": {
                        "sources": [
                            { "downwardAPI": { "items": [{ "path": "labels", "fieldRef": { "fieldPath": "metadata.labels" } }] } },
                            { "configMap": { "name": "cm1", "optional": true } },
                            { "secret": { "name": "sec1" } },
                            { "serviceAccountToken": { "audience": "aud1", "path": "token" } }
                        ],
                        "defaultMode": 256
                    }
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        let sources = decoded["spec"]["volumes"][0]["projected"]["sources"]
            .as_array()
            .expect(
                "projected.sources must be present — before this fix the whole projected \
                 volume source was dropped, mounting an empty directory instead",
            );
        assert_eq!(sources.len(), 4, "all four projection sources must survive");
        assert_eq!(
            sources[0]["downwardAPI"]["items"][0]["path"], "labels",
            "projected downwardAPI source must survive"
        );
        assert_eq!(
            sources[1]["configMap"]["name"], "cm1",
            "projected configMap source must survive"
        );
        assert_eq!(
            sources[1]["configMap"]["optional"], true,
            "projected configMap source's optional flag must survive"
        );
        assert_eq!(
            sources[2]["secret"]["name"], "sec1",
            "projected secret source must survive"
        );
        assert_eq!(
            sources[3]["serviceAccountToken"]["audience"], "aud1",
            "projected serviceAccountToken source must survive"
        );
    }

    /// The ~15 rare/deprecated in-tree VolumeSource variants (iscsi/glusterfs/rbd/gitRepo/
    /// cinder/cephfs/flexVolume/flocker/azureFile/vsphereVolume/quobyte/azureDisk/
    /// portworxVolume/scaleIO/storageos) json_to_volume_proto now encodes.
    ///
    /// `decode_pod_proto_gen` has no JSON-generation branch for any of these (they were never
    /// exercised on the decode side either — see the sentinel_completeness_encode_pod_proto_gen
    /// comment above), so this test can't round-trip through it like the other
    /// `encode_pod_proto_gen_round_trips_*` tests do. Instead it decodes the raw encoded bytes
    /// straight through prost's own generated `Pod::decode`, which — unlike our hand-written
    /// JSON layer — needs no per-field mapping to read back a field that's really on the wire.
    /// This isolates exactly what's under test: whether `json_to_volume_proto` puts each field
    /// on the wire at all. Before this fix, every one of these volumes silently encoded as an
    /// empty `VolumeSource` on any protobuf-negotiating GET/LIST.
    #[test]
    fn encode_pod_proto_gen_round_trips_rare_deprecated_volume_sources() {
        let pod = serde_json::json!({
            "metadata": { "name": "rare-volumes-pod", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "volumes": [
                    { "name": "v-iscsi", "iscsi": {
                        "targetPortal": "10.0.0.1:3260", "iqn": "iqn.2000-01.com.example:vol",
                        "lun": 1, "fsType": "ext4", "readOnly": true
                    }},
                    { "name": "v-glusterfs", "glusterfs": {
                        "endpoints": "glusterfs-cluster", "path": "myvol", "readOnly": true
                    }},
                    { "name": "v-rbd", "rbd": {
                        "monitors": ["10.0.0.1:6789"], "image": "foo", "pool": "rbd",
                        "user": "admin", "secretRef": { "name": "rbd-secret" }
                    }},
                    { "name": "v-gitrepo", "gitRepo": {
                        "repository": "https://example.com/repo.git", "revision": "abc123",
                        "directory": "src"
                    }},
                    { "name": "v-cinder", "cinder": {
                        "volumeID": "vol-1", "fsType": "ext4",
                        "secretRef": { "name": "cinder-secret" }
                    }},
                    { "name": "v-cephfs", "cephfs": {
                        "monitors": ["10.0.0.1:6789"], "path": "/", "user": "admin",
                        "secretRef": { "name": "cephfs-secret" }
                    }},
                    { "name": "v-flex", "flexVolume": {
                        "driver": "example/flex", "fsType": "ext4",
                        "secretRef": { "name": "flex-secret" },
                        "options": { "foo": "bar" }
                    }},
                    { "name": "v-flocker", "flocker": { "datasetName": "my-dataset" }},
                    { "name": "v-azurefile", "azureFile": {
                        "secretName": "azure-secret", "shareName": "share1", "readOnly": true
                    }},
                    { "name": "v-vsphere", "vsphereVolume": {
                        "volumePath": "[datastore1] volumes/myDisk", "fsType": "ext4"
                    }},
                    { "name": "v-quobyte", "quobyte": {
                        "registry": "quobyte-registry:7861", "volume": "myvol", "user": "root"
                    }},
                    { "name": "v-azuredisk", "azureDisk": {
                        "diskName": "mydisk", "diskURI": "https://example.blob/mydisk.vhd"
                    }},
                    { "name": "v-portworx", "portworxVolume": {
                        "volumeID": "vol-1", "fsType": "ext4"
                    }},
                    { "name": "v-scaleio", "scaleIO": {
                        "gateway": "https://scaleio", "system": "scaleio-sys",
                        "secretRef": { "name": "scaleio-secret" }, "volumeName": "vol-1"
                    }},
                    { "name": "v-storageos", "storageos": {
                        "volumeName": "vol-1", "secretRef": { "name": "storageos-secret" }
                    }}
                ]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = core_v1::Pod::decode(raw.as_slice()).expect("encoded Pod bytes must decode");
        let volumes = decoded.spec.expect("spec must survive").volumes;
        let src = |i: usize| {
            volumes[i]
                .volume_source
                .clone()
                .expect("volume_source must be set")
        };

        assert_eq!(
            src(0).iscsi.unwrap().target_portal.as_deref(),
            Some("10.0.0.1:3260"),
            "iscsi.targetPortal must survive protobuf encoding — before this fix the whole \
             VolumeSource silently encoded empty and the kubelet had no target to attach to"
        );
        assert_eq!(
            src(1).glusterfs.unwrap().endpoints.as_deref(),
            Some("glusterfs-cluster"),
            "glusterfs.endpoints must survive protobuf encoding"
        );
        assert_eq!(
            src(2).rbd.unwrap().secret_ref.unwrap().name.as_deref(),
            Some("rbd-secret"),
            "rbd.secretRef must survive protobuf encoding"
        );
        assert_eq!(
            src(3).git_repo.unwrap().repository.as_deref(),
            Some("https://example.com/repo.git"),
            "gitRepo.repository must survive protobuf encoding"
        );
        assert_eq!(
            src(4).cinder.unwrap().volume_id.as_deref(),
            Some("vol-1"),
            "cinder.volumeID must survive protobuf encoding"
        );
        assert_eq!(
            src(5).cephfs.unwrap().secret_ref.unwrap().name.as_deref(),
            Some("cephfs-secret"),
            "cephfs.secretRef must survive protobuf encoding"
        );
        assert_eq!(
            src(6)
                .flex_volume
                .unwrap()
                .options
                .get("foo")
                .map(String::as_str),
            Some("bar"),
            "flexVolume.options must survive protobuf encoding"
        );
        assert_eq!(
            src(7).flocker.unwrap().dataset_name.as_deref(),
            Some("my-dataset"),
            "flocker.datasetName must survive protobuf encoding"
        );
        assert_eq!(
            src(8).azure_file.unwrap().share_name.as_deref(),
            Some("share1"),
            "azureFile.shareName must survive protobuf encoding"
        );
        assert_eq!(
            src(9).vsphere_volume.unwrap().volume_path.as_deref(),
            Some("[datastore1] volumes/myDisk"),
            "vsphereVolume.volumePath must survive protobuf encoding"
        );
        assert_eq!(
            src(10).quobyte.unwrap().volume.as_deref(),
            Some("myvol"),
            "quobyte.volume must survive protobuf encoding"
        );
        assert_eq!(
            src(11).azure_disk.unwrap().disk_name.as_deref(),
            Some("mydisk"),
            "azureDisk.diskName must survive protobuf encoding"
        );
        assert_eq!(
            src(12).portworx_volume.unwrap().volume_id.as_deref(),
            Some("vol-1"),
            "portworxVolume.volumeID must survive protobuf encoding"
        );
        assert_eq!(
            src(13).scale_io.unwrap().volume_name.as_deref(),
            Some("vol-1"),
            "scaleIO.volumeName must survive protobuf encoding"
        );
        assert_eq!(
            src(14)
                .storageos
                .unwrap()
                .secret_ref
                .unwrap()
                .name
                .as_deref(),
            Some("storageos-secret"),
            "storageos.secretRef must survive protobuf encoding"
        );
    }

    /// Mirrors `encode_pod_proto_gen_round_trips_rare_deprecated_volume_sources` but drives it
    /// through the full `encode_pod_proto_gen` -> `decode_pod_proto_gen` round trip that a
    /// protobuf-negotiating client (kubelet, controllers) actually gets when it PUTs/POSTs a
    /// Pod: the apiserver decodes the wire bytes back into stored JSON. Before this fix, each
    /// of these 15 rare/deprecated volume types would decode to a Volume with no source at
    /// all, so a client writing e.g. an iscsi-backed Pod over protobuf would have it silently
    /// vanish from the stored object and the kubelet could never resolve the mount.
    #[test]
    fn decode_pod_proto_gen_round_trips_rare_deprecated_volume_sources() {
        let pod = serde_json::json!({
            "metadata": { "name": "rare-volumes-pod", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "volumes": [
                    { "name": "v-iscsi", "iscsi": {
                        "targetPortal": "10.0.0.1:3260", "iqn": "iqn.2000-01.com.example:vol",
                        "lun": 1, "iscsiInterface": "default", "fsType": "ext4",
                        "readOnly": true, "portals": ["10.0.0.2:3260"],
                        "chapAuthDiscovery": true, "chapAuthSession": true,
                        "secretRef": { "name": "iscsi-secret" }, "initiatorName": "iqn.initiator"
                    }},
                    { "name": "v-glusterfs", "glusterfs": {
                        "endpoints": "glusterfs-cluster", "path": "myvol", "readOnly": true
                    }},
                    { "name": "v-rbd", "rbd": {
                        "monitors": ["10.0.0.1:6789"], "image": "foo", "fsType": "ext4",
                        "pool": "rbd", "user": "admin", "keyring": "/etc/ceph/keyring",
                        "secretRef": { "name": "rbd-secret" }, "readOnly": true
                    }},
                    { "name": "v-gitrepo", "gitRepo": {
                        "repository": "https://example.com/repo.git", "revision": "abc123",
                        "directory": "src"
                    }},
                    { "name": "v-cinder", "cinder": {
                        "volumeID": "vol-1", "fsType": "ext4", "readOnly": true,
                        "secretRef": { "name": "cinder-secret" }
                    }},
                    { "name": "v-cephfs", "cephfs": {
                        "monitors": ["10.0.0.1:6789"], "path": "/", "user": "admin",
                        "secretFile": "/etc/ceph/user.secret",
                        "secretRef": { "name": "cephfs-secret" }, "readOnly": true
                    }},
                    { "name": "v-flex", "flexVolume": {
                        "driver": "example/flex", "fsType": "ext4",
                        "secretRef": { "name": "flex-secret" }, "readOnly": true,
                        "options": { "foo": "bar" }
                    }},
                    { "name": "v-flocker", "flocker": {
                        "datasetName": "my-dataset", "datasetUUID": "uuid-1"
                    }},
                    { "name": "v-azurefile", "azureFile": {
                        "secretName": "azure-secret", "shareName": "share1", "readOnly": true
                    }},
                    { "name": "v-vsphere", "vsphereVolume": {
                        "volumePath": "[datastore1] volumes/myDisk", "fsType": "ext4",
                        "storagePolicyName": "gold", "storagePolicyID": "policy-1"
                    }},
                    { "name": "v-quobyte", "quobyte": {
                        "registry": "quobyte-registry:7861", "volume": "myvol",
                        "readOnly": true, "user": "root", "group": "wheel", "tenant": "tenant-1"
                    }},
                    { "name": "v-azuredisk", "azureDisk": {
                        "diskName": "mydisk", "diskURI": "https://example.blob/mydisk.vhd",
                        "cachingMode": "ReadWrite", "fsType": "ext4", "readOnly": true,
                        "kind": "Managed"
                    }},
                    { "name": "v-portworx", "portworxVolume": {
                        "volumeID": "vol-1", "fsType": "ext4", "readOnly": true
                    }},
                    { "name": "v-scaleio", "scaleIO": {
                        "gateway": "https://scaleio", "system": "scaleio-sys",
                        "secretRef": { "name": "scaleio-secret" }, "sslEnabled": true,
                        "protectionDomain": "pd1", "storagePool": "pool1",
                        "storageMode": "ThickProvisioned", "volumeName": "vol-1",
                        "fsType": "xfs", "readOnly": true
                    }},
                    { "name": "v-storageos", "storageos": {
                        "volumeName": "vol-1", "volumeNamespace": "ns1", "fsType": "ext4",
                        "readOnly": true, "secretRef": { "name": "storageos-secret" }
                    }}
                ]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");
        let volumes = &decoded["spec"]["volumes"];

        assert_eq!(
            volumes[0]["iscsi"]["targetPortal"], "10.0.0.1:3260",
            "kubelet writes an iscsi volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[0]["iscsi"]["lun"], 1,
            "iscsi.lun must survive decode"
        );
        assert_eq!(
            volumes[0]["iscsi"]["portals"][0], "10.0.0.2:3260",
            "iscsi.portals must survive decode"
        );
        assert_eq!(
            volumes[0]["iscsi"]["secretRef"]["name"], "iscsi-secret",
            "iscsi.secretRef must survive decode"
        );
        assert_eq!(
            volumes[0]["iscsi"]["initiatorName"], "iqn.initiator",
            "iscsi.initiatorName must survive decode"
        );
        assert_eq!(
            volumes[1]["glusterfs"]["endpoints"], "glusterfs-cluster",
            "kubelet writes a glusterfs volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[2]["rbd"]["secretRef"]["name"], "rbd-secret",
            "kubelet writes an rbd volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[2]["rbd"]["monitors"][0], "10.0.0.1:6789",
            "rbd.monitors must survive decode"
        );
        assert_eq!(
            volumes[3]["gitRepo"]["repository"], "https://example.com/repo.git",
            "kubelet writes a gitRepo volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[4]["cinder"]["volumeID"], "vol-1",
            "kubelet writes a cinder volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[4]["cinder"]["secretRef"]["name"], "cinder-secret",
            "cinder.secretRef must survive decode"
        );
        assert_eq!(
            volumes[5]["cephfs"]["secretRef"]["name"], "cephfs-secret",
            "kubelet writes a cephfs volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[5]["cephfs"]["secretFile"], "/etc/ceph/user.secret",
            "cephfs.secretFile must survive decode"
        );
        assert_eq!(
            volumes[6]["flexVolume"]["options"]["foo"], "bar",
            "kubelet writes a flexVolume via protobuf; if this regresses, the volume vanishes \
             from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[6]["flexVolume"]["secretRef"]["name"], "flex-secret",
            "flexVolume.secretRef must survive decode"
        );
        assert_eq!(
            volumes[7]["flocker"]["datasetUUID"], "uuid-1",
            "kubelet writes a flocker volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[8]["azureFile"]["shareName"], "share1",
            "kubelet writes an azureFile volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[9]["vsphereVolume"]["storagePolicyID"], "policy-1",
            "kubelet writes a vsphereVolume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[10]["quobyte"]["tenant"], "tenant-1",
            "kubelet writes a quobyte volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[11]["azureDisk"]["diskURI"], "https://example.blob/mydisk.vhd",
            "kubelet writes an azureDisk volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[11]["azureDisk"]["kind"], "Managed",
            "azureDisk.kind must survive decode"
        );
        assert_eq!(
            volumes[12]["portworxVolume"]["volumeID"], "vol-1",
            "kubelet writes a portworxVolume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[13]["scaleIO"]["secretRef"]["name"], "scaleio-secret",
            "kubelet writes a scaleIO volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[13]["scaleIO"]["storageMode"], "ThickProvisioned",
            "scaleIO.storageMode must survive decode"
        );
        assert_eq!(
            volumes[14]["storageos"]["secretRef"]["name"], "storageos-secret",
            "kubelet writes a storageos volume via protobuf; if this regresses, the volume \
             vanishes from the apiserver's stored JSON and the pod can't mount"
        );
        assert_eq!(
            volumes[14]["storageos"]["volumeNamespace"], "ns1",
            "storageos.volumeNamespace must survive decode"
        );
    }

    /// `enableServiceLinks` is a tri-state `*bool` upstream that the kubelet's
    /// `makeEnvironmentVariables` reads directly: a nil value is a hard failure
    /// ("nil pod.spec.enableServiceLinks encountered, cannot construct envvars"), not a
    /// silently-defaulted false. A protobuf-negotiating client's read-modify-write update
    /// loop (e.g. patching an annotation) does a GET first — if the encoder drops this field,
    /// the client's local copy has it unset, and its follow-up PUT permanently bricks the
    /// pod's env var construction on the next kubelet sync. This exact failure was caught
    /// live by `[sig-node] Variable Expansion should verify that a failing subpath expansion
    /// can be modified` timing out because the updated pod's container config could never be
    /// constructed at all.
    #[test]
    fn encode_pod_proto_gen_round_trips_enable_service_links_and_automount_service_account_token() {
        let pod = serde_json::json!({
            "metadata": { "name": "esl-pod", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "enableServiceLinks": false,
                "automountServiceAccountToken": false,
                "priority": 1000,
                "preemptionPolicy": "Never",
                "shareProcessNamespace": true,
                "serviceAccount": "legacy-alias",
                "setHostnameAsFQDN": true,
                "os": { "name": "linux" },
                "hostAliases": [{ "ip": "127.0.0.1", "hostnames": ["foo.local"] }],
                "topologySpreadConstraints": [{
                    "maxSkew": 1,
                    "topologyKey": "kubernetes.io/hostname",
                    "whenUnsatisfiable": "DoNotSchedule"
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        assert_eq!(
            decoded["spec"]["enableServiceLinks"], false,
            "enableServiceLinks=false must survive as an explicit value, not vanish and leave \
             the kubelet with a nil pointer it hard-fails on"
        );
        assert_eq!(
            decoded["spec"]["automountServiceAccountToken"], false,
            "automountServiceAccountToken must survive — without it a pod that explicitly \
             opted out of token automount gets one anyway"
        );
        assert_eq!(decoded["spec"]["priority"], 1000, "priority must survive");
        assert_eq!(
            decoded["spec"]["preemptionPolicy"], "Never",
            "preemptionPolicy must survive"
        );
        assert_eq!(
            decoded["spec"]["shareProcessNamespace"], true,
            "shareProcessNamespace must survive"
        );
        assert_eq!(
            decoded["spec"]["serviceAccount"], "legacy-alias",
            "the deprecated serviceAccount alias must survive for legacy clients"
        );
        assert_eq!(
            decoded["spec"]["setHostnameAsFQDN"], true,
            "setHostnameAsFQDN must survive"
        );
        assert_eq!(
            decoded["spec"]["os"]["name"], "linux",
            "os.name must survive"
        );
        assert_eq!(
            decoded["spec"]["hostAliases"][0]["ip"], "127.0.0.1",
            "hostAliases must survive — without them the extra /etc/hosts entries a pod \
             asked for silently never appear"
        );
        assert_eq!(
            decoded["spec"]["topologySpreadConstraints"][0]["topologyKey"],
            "kubernetes.io/hostname",
            "topologySpreadConstraints must survive — without them the scheduler treats a pod \
             that asked to be spread across topology domains as unconstrained"
        );
    }

    /// Pod-level SecurityContext/affinity/imagePullSecrets/hostPID/hostIPC/dnsConfig/
    /// readinessGates must survive protobuf encoding, or a protobuf-watching kubelet and
    /// scheduler run/schedule the pod as if none of these were ever requested.
    #[test]
    fn encode_pod_proto_gen_round_trips_pod_security_context_affinity_and_scheduling_fields() {
        let pod = serde_json::json!({
            "metadata": { "name": "hardened-pod", "namespace": "default" },
            "spec": {
                "containers": [{ "name": "c", "image": "img" }],
                "securityContext": {
                    "runAsUser": 1000,
                    "runAsGroup": 2000,
                    "runAsNonRoot": true,
                    "fsGroup": 3000,
                    "supplementalGroups": [4000],
                    "seccompProfile": { "type": "RuntimeDefault" }
                },
                "affinity": {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [{
                                "matchExpressions": [{ "key": "disktype", "operator": "In", "values": ["ssd"] }]
                            }]
                        }
                    }
                },
                "imagePullSecrets": [{ "name": "registry-cred" }],
                "hostPID": true,
                "hostIPC": true,
                "dnsConfig": {
                    "nameservers": ["1.2.3.4"],
                    "searches": ["ns1.svc.cluster.local"],
                    "options": [{ "name": "ndots", "value": "5" }]
                },
                "readinessGates": [{ "conditionType": "www.example.com/feature-1" }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        let sc = &decoded["spec"]["securityContext"];
        assert_eq!(
            sc["runAsUser"], 1000,
            "securityContext.runAsUser must survive"
        );
        assert_eq!(sc["fsGroup"], 3000, "securityContext.fsGroup must survive");
        assert_eq!(
            sc["seccompProfile"]["type"], "RuntimeDefault",
            "securityContext.seccompProfile must survive"
        );
        assert_eq!(
            decoded["spec"]["affinity"]["nodeAffinity"]
                ["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"][0]
                ["matchExpressions"][0]["key"],
            "disktype",
            "affinity.nodeAffinity must survive — before this fix the scheduler's node \
             affinity constraint was silently dropped for any protobuf-encoded pod"
        );
        assert_eq!(
            decoded["spec"]["imagePullSecrets"][0]["name"], "registry-cred",
            "imagePullSecrets must survive — without it image pulls from a private registry \
             fail with no credentials attached"
        );
        assert_eq!(decoded["spec"]["hostPID"], true, "hostPID must survive");
        assert_eq!(decoded["spec"]["hostIPC"], true, "hostIPC must survive");
        assert_eq!(
            decoded["spec"]["dnsConfig"]["nameservers"][0], "1.2.3.4",
            "dnsConfig.nameservers must survive"
        );
        assert_eq!(
            decoded["spec"]["readinessGates"][0]["conditionType"], "www.example.com/feature-1",
            "readinessGates must survive — without it the pod reports Ready before a \
             controller-managed condition it depends on is ever evaluated"
        );
    }

    /// Container-level SecurityContext/envFrom/probes/lifecycle/terminationMessage* must
    /// survive protobuf encoding: without them a protobuf-watching kubelet runs the container
    /// unconfined, without its ConfigMap-sourced env vars, and without any health checks or
    /// lifecycle hooks the spec requested.
    #[test]
    fn encode_pod_proto_gen_round_trips_container_security_context_probes_and_lifecycle() {
        let pod = serde_json::json!({
            "metadata": { "name": "probed-pod", "namespace": "default" },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "img",
                    "securityContext": {
                        "privileged": false,
                        "allowPrivilegeEscalation": false,
                        "readOnlyRootFilesystem": true,
                        "capabilities": { "add": ["NET_ADMIN"], "drop": ["ALL"] }
                    },
                    "envFrom": [{ "configMapRef": { "name": "cm-env" } }],
                    "livenessProbe": {
                        "httpGet": { "path": "/healthz", "port": 8080 },
                        "initialDelaySeconds": 5
                    },
                    "readinessProbe": { "tcpSocket": { "port": 8081 } },
                    "startupProbe": { "exec": { "command": ["cat", "/tmp/ready"] } },
                    "lifecycle": { "preStop": { "exec": { "command": ["sleep", "5"] } } },
                    "terminationMessagePath": "/dev/termination-log2",
                    "terminationMessagePolicy": "FallbackToLogsOnError"
                }]
            }
        });

        let raw = encode_pod_proto_gen(&pod);
        let decoded = decode_pod_proto_gen(&raw).expect("encoded Pod bytes must decode");

        let c = &decoded["spec"]["containers"][0];
        assert_eq!(
            c["securityContext"]["readOnlyRootFilesystem"], true,
            "container securityContext must survive — without it a container the spec \
             requested a read-only root filesystem for boots with a writable one instead"
        );
        assert_eq!(
            c["securityContext"]["capabilities"]["add"][0], "NET_ADMIN",
            "container securityContext.capabilities must survive"
        );
        assert_eq!(
            c["envFrom"][0]["configMapRef"]["name"], "cm-env",
            "envFrom must survive — without it the container starts without the ConfigMap's \
             environment variables"
        );
        assert_eq!(
            c["livenessProbe"]["httpGet"]["path"], "/healthz",
            "livenessProbe must survive — without it a crashed/hung container is never \
             restarted by the kubelet"
        );
        assert_eq!(
            c["readinessProbe"]["tcpSocket"]["port"], 8081,
            "readinessProbe must survive — without it the container is always considered \
             ready for traffic regardless of its actual state"
        );
        assert_eq!(
            c["startupProbe"]["exec"]["command"][0], "cat",
            "startupProbe must survive"
        );
        assert_eq!(
            c["lifecycle"]["preStop"]["exec"]["command"][0], "sleep",
            "lifecycle.preStop must survive — without it the container is killed immediately \
             instead of running its graceful-shutdown hook"
        );
        assert_eq!(
            c["terminationMessagePath"], "/dev/termination-log2",
            "terminationMessagePath must survive"
        );
        assert_eq!(
            c["terminationMessagePolicy"], "FallbackToLogsOnError",
            "terminationMessagePolicy must survive"
        );
    }

    /// PodList wraps each item through the same per-Pod encoder; a LIST response must carry
    /// every item, not just the first, and must carry the list's resourceVersion so a watcher
    /// that lists-then-watches knows where to resume from.
    #[test]
    fn encode_podlist_proto_gen_round_trips_all_items_and_resource_version() {
        let list = serde_json::json!({
            "kind": "PodList",
            "apiVersion": "v1",
            "metadata": { "resourceVersion": "42" },
            "items": [
                { "metadata": { "name": "a" }, "spec": { "containers": [] } },
                { "metadata": { "name": "b" }, "spec": { "containers": [] } }
            ]
        });

        let raw = encode_podlist_proto_gen(&list);
        let podlist =
            core_v1::PodList::decode(raw.as_slice()).expect("encoded PodList bytes must decode");

        assert_eq!(
            podlist.items.len(),
            2,
            "both list items must survive the round trip"
        );
        assert_eq!(
            podlist.metadata.unwrap().resource_version.as_deref(),
            Some("42"),
            "list resourceVersion must survive — a watcher that lists-then-watches uses it \
             as the watch's starting point"
        );
    }

    /// Service round-trips ClusterIP/ports/selector: kube-proxy programs iptables/ipvs rules
    /// directly from these fields, so a silent drop here means traffic for that Service is
    /// never routed to any backend.
    #[test]
    fn encode_service_proto_gen_round_trips_cluster_ip_and_ports() {
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "web", "namespace": "default" },
            "spec": {
                "clusterIP": "10.96.0.1",
                "type": "ClusterIP",
                "selector": { "app": "web" },
                "ports": [{ "name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP" }]
            }
        });

        let raw = encode_service_proto_gen(&svc);
        let decoded = decode_service_proto_gen(&raw).expect("encoded Service bytes must decode");

        assert_eq!(decoded["spec"]["clusterIP"], "10.96.0.1");
        assert_eq!(decoded["spec"]["selector"]["app"], "web");
        assert_eq!(decoded["spec"]["ports"][0]["port"], 80);
        assert_eq!(
            decoded["spec"]["ports"][0]["targetPort"], 8080,
            "targetPort must round-trip through IntOrString — kube-proxy dials this port on \
             the pod, not the Service's own `port`"
        );
    }

    /// Node round-trips capacity/allocatable/conditions: the scheduler's resource-fit
    /// predicate reads capacity/allocatable directly, and kubelet's own NodeReady gate reads
    /// conditions — either silently dropping means pods get scheduled onto (or kept off of)
    /// nodes based on wrong information.
    #[test]
    fn encode_node_proto_gen_round_trips_capacity_and_conditions() {
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": { "name": "worker-1" },
            "spec": { "podCIDR": "10.244.0.0/24", "unschedulable": false },
            "status": {
                "capacity": { "cpu": "4", "memory": "8Gi" },
                "allocatable": { "cpu": "3800m", "memory": "7Gi" },
                "conditions": [{ "type": "Ready", "status": "True" }],
                "addresses": [{ "type": "InternalIP", "address": "192.168.1.10" }]
            }
        });

        let raw = encode_node_proto_gen(&node);
        let decoded = decode_node_proto_gen(&raw).expect("encoded Node bytes must decode");

        assert_eq!(decoded["spec"]["podCIDR"], "10.244.0.0/24");
        assert_eq!(decoded["status"]["capacity"]["cpu"], "4");
        assert_eq!(decoded["status"]["allocatable"]["memory"], "7Gi");
        assert_eq!(decoded["status"]["conditions"][0]["type"], "Ready");
        assert_eq!(decoded["status"]["addresses"][0]["address"], "192.168.1.10");
    }

    /// A client-go typed clientset's `CoreV1().Nodes().Get()` negotiates protobuf by default
    /// for this built-in kind, so every read of a Node's `status.daemonEndpoints.kubeletEndpoint
    /// .port` goes through this encode path. Before this fix, `json_to_node_status_proto` never
    /// populated `daemon_endpoints` at all, so the field decoded back as absent (Port 0) on
    /// EVERY such Get — not just after an apiserver restart. This is the exact failure behind
    /// `[sig-instrumentation] MetricsGrabber should grab all metrics from a Kubelet`: the test
    /// reads this field via its typed client, sees Port=0, and aborts before ever reaching
    /// metrics-server.
    #[test]
    fn encode_node_proto_gen_round_trips_daemon_endpoints() {
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": { "name": "worker-1" },
            "status": {
                "daemonEndpoints": { "kubeletEndpoint": { "port": 10250 } }
            }
        });

        let raw = encode_node_proto_gen(&node);
        let decoded = decode_node_proto_gen(&raw).expect("encoded Node bytes must decode");

        assert_eq!(
            decoded["status"]["daemonEndpoints"]["kubeletEndpoint"]["port"], 10250,
            "kubeletEndpoint.port must survive the JSON->protobuf->JSON round trip a typed \
             clientset's protobuf-negotiated Get() performs, otherwise every such client sees \
             Port=0 and any port-dependent kubelet interaction (e.g. metrics scraping) breaks; \
             got: {decoded:#?}"
        );
    }

    /// Endpoints (legacy API) round-trips subset addresses/ports: kube-proxy's legacy
    /// (non-EndpointSlice) code path programs backend rules straight from these fields.
    #[test]
    fn encode_endpoints_proto_gen_round_trips_subset_addresses_and_ports() {
        let eps = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Endpoints",
            "metadata": { "name": "web", "namespace": "default" },
            "subsets": [{
                "addresses": [{ "ip": "10.244.0.5", "nodeName": "worker-1" }],
                "ports": [{ "name": "http", "port": 8080, "protocol": "TCP" }]
            }]
        });

        let raw = encode_endpoints_proto_gen(&eps);
        let decoded =
            decode_endpoints_proto_gen(&raw).expect("encoded Endpoints bytes must decode");

        assert_eq!(decoded["subsets"][0]["addresses"][0]["ip"], "10.244.0.5");
        assert_eq!(decoded["subsets"][0]["ports"][0]["port"], 8080);
    }

    /// Event round-trips involvedObject/reason/message/count: `kubectl describe`'s Events
    /// table and any controller reading Events for diagnostics depend on all four fields
    /// pointing at the correct object and carrying the correct occurrence count.
    #[test]
    fn encode_event_proto_gen_round_trips_involved_object_and_count() {
        let event = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "web-1.abc", "namespace": "default" },
            "involvedObject": { "kind": "Pod", "name": "web-1", "namespace": "default" },
            "reason": "Started",
            "message": "Started container web",
            "type": "Normal",
            "count": 3
        });

        let raw = encode_event_proto_gen(&event);
        let decoded = decode_event_proto_gen(&raw).expect("encoded Event bytes must decode");

        assert_eq!(decoded["involvedObject"]["name"], "web-1");
        assert_eq!(decoded["reason"], "Started");
        assert_eq!(decoded["count"], 3);
    }

    /// Falsifiability check for the encoder-dispatch/round-trip machinery itself: reverting
    /// any one encoder's field mapping (e.g. dropping `image` from `json_to_container_proto`)
    /// makes `encode_pod_proto_gen_round_trips_container_and_status_fields` fail, since the
    /// decoded image would come back `Value::Null` instead of `"nginx:1.27"`. This is not a
    /// separate test — it documents why the round-trip tests above are load-bearing rather
    /// than tautological: they compare an encoder-specific field the decoder does not
    /// synthesize on its own.
    #[test]
    fn round_trip_tests_are_falsifiable_by_construction() {
        let empty_container = serde_json::json!({});
        let container = json_to_container_proto(&empty_container);
        assert_eq!(
            container.image, None,
            "an encoder that defaulted `image` instead of reading it from JSON would make \
             this assertion (and the Pod round-trip test above) fail on revert"
        );
    }
}
