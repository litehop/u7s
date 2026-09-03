use crate::types::ObjectMeta;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn wants_table(accept: &str) -> bool {
    accept.contains("as=Table")
}

/// Extract the Table version from an Accept header, e.g.
/// `application/json;as=Table;g=meta.k8s.io;v=v1beta1,application/json` → `Some("v1beta1")`.
/// Returns None when no Table preference is present.
///
/// Only the first `as=Table` media-type in the header is inspected (clients list
/// preferences in priority order; the first match is authoritative).
pub fn table_accept_version(accept: &str) -> Option<&str> {
    for part in accept.split(',') {
        let part = part.trim();
        if !part.contains("as=Table") {
            continue;
        }
        for param in part.split(';') {
            let param = param.trim();
            if let Some(version) = param.strip_prefix("v=") {
                return Some(version);
            }
        }
        // as=Table present but no v= param — treat as v1.
        return Some("v1");
    }
    None
}

pub fn build_table(
    group: &str,
    plural: &str,
    objects: Vec<serde_json::Value>,
) -> serde_json::Value {
    match (group, plural) {
        ("", "pods") => build_pod_table(objects),
        ("", "nodes") => build_node_table(objects),
        ("apps", "deployments") => build_deployment_table(objects),
        ("", "services") => build_service_table(objects),
        ("apps", "replicasets") => build_replicaset_table(objects),
        ("apps", "statefulsets") => build_statefulset_table(objects),
        ("apps", "daemonsets") => build_daemonset_table(objects),
        ("", "namespaces") => build_namespace_table(objects),
        ("", "configmaps") => build_configmap_table(objects),
        ("", "secrets") => build_secret_table(objects),
        ("", "serviceaccounts") => build_serviceaccount_table(objects),
        ("batch", "jobs") => build_job_table(objects),
        ("batch", "cronjobs") => build_cronjob_table(objects),
        ("", "persistentvolumeclaims") => build_pvc_table(objects),
        ("", "persistentvolumes") => build_pv_table(objects),
        _ => build_generic_table(objects),
    }
}

fn col(name: &str, description: &str, typ: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "type": typ,
        "description": description,
        "priority": 0
    })
}

fn wide_col(name: &str, description: &str, typ: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "type": typ,
        "description": description,
        "priority": 1
    })
}

// ── Pods ──────────────────────────────────────────────────────────────────────

fn build_pod_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the pod", "string"),
        col("Ready", "Fraction of containers that are ready", "string"),
        col("Status", "Phase of the pod", "string"),
        col(
            "Restarts",
            "Total restarts across all containers",
            "integer",
        ),
        col("Age", "Time since creation", "string"),
        col("IP", "Pod IP address", "string"),
        col("Node", "Node the pod is assigned to", "string"),
        col("Nominated Node", "Node nominated for preemption", "string"),
        col("Readiness Gates", "Readiness gate conditions", "string"),
    ];

    let rows: Vec<serde_json::Value> = objects.into_iter().map(pod_row).collect();

    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PodStatusView {
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    container_statuses: Option<Vec<ContainerStatusView>>,
    #[serde(rename = "podIP", default)]
    pod_ip: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ContainerStatusView {
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    restart_count: i64,
    #[serde(default)]
    state: Option<ContainerStateView>,
}

#[derive(Deserialize, Default)]
struct ContainerStateView {
    #[serde(default)]
    waiting: Option<ContainerStateReasonView>,
    #[serde(default)]
    terminated: Option<ContainerStateReasonView>,
}

#[derive(Deserialize, Default)]
struct ContainerStateReasonView {
    reason: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PodSpecView {
    /// Only the count matters here (fallback total when containerStatuses is absent);
    /// per-container fields are never read, so shape beyond array length is ignored.
    #[serde(default)]
    containers: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    node_name: Option<String>,
}

fn pod_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let status: PodStatusView = serde_json::from_value(obj["status"].clone()).unwrap_or_default();
    let spec: PodSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();

    let phase = status.phase.as_deref().unwrap_or("Unknown");

    let total = status
        .container_statuses
        .as_ref()
        .map(|cs| cs.len())
        .unwrap_or(spec.containers.len());

    let ready_count = status
        .container_statuses
        .as_ref()
        .map(|cs| cs.iter().filter(|c| c.ready).count())
        .unwrap_or(0);

    let restarts: i64 = status
        .container_statuses
        .as_ref()
        .map(|cs| cs.iter().map(|c| c.restart_count).sum())
        .unwrap_or(0);

    let display_status = pod_display_status(
        meta.deletion_timestamp.as_deref(),
        phase,
        status.container_statuses.as_deref(),
    );

    let pod_ip = status.pod_ip.unwrap_or_else(|| "<none>".to_string());
    let node_name = spec.node_name.unwrap_or_else(|| "<none>".to_string());

    let ready_str = format!("{ready_count}/{total}");

    let object_ref = make_object_ref(&obj, "Pod");

    serde_json::json!({
        "cells": [
            name,
            ready_str,
            display_status,
            restarts,
            age,
            pod_ip,
            node_name,
            "<none>",
            "<none>"
        ],
        "object": object_ref
    })
}

fn pod_display_status(
    deletion_timestamp: Option<&str>,
    phase: &str,
    container_statuses: Option<&[ContainerStatusView]>,
) -> String {
    if deletion_timestamp.is_some() {
        return "Terminating".to_string();
    }

    if let Some(cs) = container_statuses {
        for c in cs {
            let Some(state) = &c.state else { continue };
            if let Some(reason) = state.waiting.as_ref().and_then(|w| w.reason.as_deref()) {
                if reason != "Completed" {
                    return reason.to_string();
                }
            }
            if let Some(reason) = state.terminated.as_ref().and_then(|t| t.reason.as_deref()) {
                if reason != "Completed" {
                    return reason.to_string();
                }
            }
        }
    }

    phase.to_string()
}

// ── Nodes ─────────────────────────────────────────────────────────────────────

fn build_node_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the node", "string"),
        col("Status", "Node readiness status", "string"),
        col("Roles", "Node roles", "string"),
        col("Age", "Time since creation", "string"),
        col("Version", "Kubelet version", "string"),
        wide_col("Internal-IP", "Internal IP address", "string"),
        wide_col("External-IP", "External IP address", "string"),
        wide_col("OS-Image", "OS image", "string"),
        wide_col("Kernel-Version", "Kernel version", "string"),
        wide_col("Container-Runtime", "Container runtime version", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(node_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NodeStatusView {
    #[serde(default)]
    conditions: Option<Vec<NodeConditionView>>,
    #[serde(default)]
    node_info: Option<NodeInfoView>,
    #[serde(default)]
    addresses: Option<Vec<NodeAddressView>>,
}

#[derive(Deserialize, Default)]
struct NodeConditionView {
    #[serde(rename = "type")]
    type_: Option<String>,
    status: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NodeInfoView {
    kubelet_version: Option<String>,
    os_image: Option<String>,
    kernel_version: Option<String>,
    container_runtime_version: Option<String>,
}

#[derive(Deserialize, Default)]
struct NodeAddressView {
    #[serde(rename = "type")]
    type_: Option<String>,
    address: Option<String>,
}

#[derive(Deserialize, Default)]
struct NodeSpecView {
    #[serde(default)]
    unschedulable: bool,
}

fn node_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let status: NodeStatusView = serde_json::from_value(obj["status"].clone()).unwrap_or_default();
    let spec: NodeSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();

    // STATUS
    let ready_condition = status
        .conditions
        .as_ref()
        .and_then(|conds| conds.iter().find(|c| c.type_.as_deref() == Some("Ready")));
    let ready_str = ready_condition
        .and_then(|c| c.status.as_deref())
        .map(|s| if s == "True" { "Ready" } else { "NotReady" })
        .unwrap_or("NotReady");
    let node_status = if spec.unschedulable {
        format!("{ready_str},SchedulingDisabled")
    } else {
        ready_str.to_string()
    };

    // ROLES
    let roles = meta
        .labels
        .as_ref()
        .map(|labels| {
            let prefix = "node-role.kubernetes.io/";
            let mut roles: Vec<&str> = labels
                .keys()
                .filter_map(|k| k.strip_prefix(prefix))
                .collect();
            roles.sort();
            if roles.is_empty() {
                "<none>".to_string()
            } else {
                roles.join(",")
            }
        })
        .unwrap_or_else(|| "<none>".to_string());

    let internal_ip = status
        .addresses
        .as_ref()
        .and_then(|addrs| {
            addrs
                .iter()
                .find(|a| a.type_.as_deref() == Some("InternalIP"))
        })
        .and_then(|a| a.address.clone())
        .unwrap_or_else(|| "<none>".to_string());
    let external_ip = status
        .addresses
        .as_ref()
        .and_then(|addrs| {
            addrs
                .iter()
                .find(|a| a.type_.as_deref() == Some("ExternalIP"))
        })
        .and_then(|a| a.address.clone())
        .unwrap_or_else(|| "<none>".to_string());

    let node_info = status.node_info.unwrap_or_default();
    let version = node_info
        .kubelet_version
        .unwrap_or_else(|| "<none>".to_string());
    let os_image = node_info.os_image.unwrap_or_else(|| "<none>".to_string());
    let kernel_version = node_info
        .kernel_version
        .unwrap_or_else(|| "<none>".to_string());
    let container_runtime = node_info
        .container_runtime_version
        .unwrap_or_else(|| "<none>".to_string());

    let object_ref = make_object_ref(&obj, "Node");
    serde_json::json!({
        "cells": [name, node_status, roles, age, version, internal_ip, external_ip, os_image, kernel_version, container_runtime],
        "object": object_ref
    })
}

// ── Deployments ───────────────────────────────────────────────────────────────

fn build_deployment_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the deployment", "string"),
        col("Ready", "Ready/desired replicas", "string"),
        col("Up-To-Date", "Updated replicas", "integer"),
        col("Available", "Available replicas", "integer"),
        col("Age", "Time since creation", "string"),
        wide_col("Containers", "Container names", "string"),
        wide_col("Images", "Container images", "string"),
        wide_col("Selector", "Label selector", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(deployment_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

/// Shared by Deployment/ReplicaSet/StatefulSet/DaemonSet: all four model
/// `spec.template.spec.containers` (and DaemonSet additionally `.nodeSelector`)
/// with the identical PodTemplateSpec shape.
#[derive(Deserialize, Default, Clone)]
struct ContainerView {
    name: Option<String>,
    image: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PodTemplateSpecView {
    #[serde(default)]
    containers: Vec<ContainerView>,
    #[serde(default)]
    node_selector: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize, Default)]
struct PodTemplateView {
    #[serde(default)]
    spec: PodTemplateSpecView,
}

/// CONTAINERS/IMAGES columns must preserve declaration order (not sort) so a
/// container's name at index N still lines up with its image at index N.
fn container_names_and_images(containers: &[ContainerView]) -> (String, String) {
    let names = containers
        .iter()
        .filter_map(|c| c.name.as_deref())
        .collect::<Vec<_>>()
        .join(",");
    let images = containers
        .iter()
        .filter_map(|c| c.image.as_deref())
        .collect::<Vec<_>>()
        .join(",");
    (names, images)
}

/// Shared by Deployment/ReplicaSet/StatefulSet: all three expose `spec.replicas`
/// and `spec.selector.matchLabels` with identical shape.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct WorkloadSpecView {
    #[serde(default)]
    replicas: Option<i64>,
    #[serde(default)]
    selector: Option<LabelSelectorView>,
    #[serde(default)]
    template: PodTemplateView,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LabelSelectorView {
    #[serde(default)]
    match_labels: Option<BTreeMap<String, String>>,
}

/// Shared by Deployment/ReplicaSet/StatefulSet: the real Kubernetes API models
/// all three kinds' status with this same `replicas`/`readyReplicas`/
/// `updatedReplicas`/`availableReplicas` field set (each kind just uses a subset).
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ReplicaStatusView {
    #[serde(default)]
    replicas: Option<i64>,
    #[serde(default)]
    ready_replicas: Option<i64>,
    #[serde(default)]
    updated_replicas: Option<i64>,
    #[serde(default)]
    available_replicas: Option<i64>,
}

fn deployment_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let spec: WorkloadSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let status: ReplicaStatusView =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();

    let desired = spec.replicas.unwrap_or(0);
    let ready = status.ready_replicas.unwrap_or(0);
    let up_to_date = status.updated_replicas.unwrap_or(0);
    let available = status.available_replicas.unwrap_or(0);
    let ready_str = format!("{ready}/{desired}");

    let (containers, images) = container_names_and_images(&spec.template.spec.containers);
    let selector = label_map_to_string(spec.selector.and_then(|s| s.match_labels).as_ref());

    let object_ref = make_object_ref(&obj, "Deployment");
    serde_json::json!({
        "cells": [name, ready_str, up_to_date, available, age, containers, images, selector],
        "object": object_ref
    })
}

// ── Services ──────────────────────────────────────────────────────────────────

fn build_service_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the service", "string"),
        col("Type", "Service type", "string"),
        col("Cluster-IP", "Cluster IP", "string"),
        col("External-IP", "External IPs", "string"),
        col("Port(s)", "Ports", "string"),
        col("Age", "Time since creation", "string"),
        wide_col("Selector", "Label selector", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(service_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ServiceSpecView {
    #[serde(rename = "type", default)]
    type_: Option<String>,
    #[serde(rename = "clusterIP", default)]
    cluster_ip: Option<String>,
    #[serde(rename = "externalIPs", default)]
    external_ips: Option<Vec<String>>,
    #[serde(default)]
    ports: Option<Vec<ServicePortView>>,
    #[serde(default)]
    selector: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize, Default)]
struct ServicePortView {
    #[serde(default)]
    port: i64,
    protocol: Option<String>,
    #[serde(rename = "nodePort", default)]
    node_port: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ServiceStatusView {
    #[serde(default)]
    load_balancer: Option<LoadBalancerStatusView>,
}

#[derive(Deserialize, Default)]
struct LoadBalancerStatusView {
    #[serde(default)]
    ingress: Option<Vec<LoadBalancerIngressView>>,
}

#[derive(Deserialize, Default)]
struct LoadBalancerIngressView {
    ip: Option<String>,
    hostname: Option<String>,
}

fn service_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let spec: ServiceSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let status: ServiceStatusView =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();

    let svc_type = spec.type_.unwrap_or_else(|| "<none>".to_string());
    let cluster_ip = spec.cluster_ip.unwrap_or_else(|| "<none>".to_string());

    // External IP: externalIPs[0] → loadBalancer.ingress[0].ip → .hostname → <none>
    let external_ip = spec
        .external_ips
        .as_ref()
        .and_then(|ips| ips.first())
        .cloned()
        .or_else(|| {
            status
                .load_balancer
                .as_ref()
                .and_then(|lb| lb.ingress.as_ref())
                .and_then(|ing| ing.first())
                .and_then(|i| i.ip.clone().or_else(|| i.hostname.clone()))
        })
        .unwrap_or_else(|| "<none>".to_string());

    // PORT(S)
    let ports = spec
        .ports
        .as_ref()
        .map(|ps| {
            ps.iter()
                .map(|p| {
                    let proto = p.protocol.as_deref().unwrap_or("TCP");
                    match p.node_port {
                        Some(np) => format!("{}:{np}/{proto}", p.port),
                        None => format!("{}/{proto}", p.port),
                    }
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();

    let selector = label_map_to_string(spec.selector.as_ref());

    let object_ref = make_object_ref(&obj, "Service");
    serde_json::json!({
        "cells": [name, svc_type, cluster_ip, external_ip, ports, age, selector],
        "object": object_ref
    })
}

// ── ReplicaSets ───────────────────────────────────────────────────────────────

fn build_replicaset_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the replicaset", "string"),
        col("Desired", "Desired replicas", "integer"),
        col("Current", "Current replicas", "integer"),
        col("Ready", "Ready replicas", "integer"),
        col("Age", "Time since creation", "string"),
        wide_col("Containers", "Container names", "string"),
        wide_col("Images", "Container images", "string"),
        wide_col("Selector", "Label selector", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(replicaset_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

fn replicaset_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let spec: WorkloadSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let status: ReplicaStatusView =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();

    let desired = spec.replicas.unwrap_or(0);
    let current = status.replicas.unwrap_or(0);
    let ready = status.ready_replicas.unwrap_or(0);

    let (containers, images) = container_names_and_images(&spec.template.spec.containers);
    let selector = label_map_to_string(spec.selector.and_then(|s| s.match_labels).as_ref());

    let object_ref = make_object_ref(&obj, "ReplicaSet");
    serde_json::json!({
        "cells": [name, desired, current, ready, age, containers, images, selector],
        "object": object_ref
    })
}

// ── StatefulSets ──────────────────────────────────────────────────────────────

fn build_statefulset_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the statefulset", "string"),
        col("Ready", "Ready/desired replicas", "string"),
        col("Age", "Time since creation", "string"),
        wide_col("Containers", "Container names", "string"),
        wide_col("Images", "Container images", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(statefulset_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

fn statefulset_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let spec: WorkloadSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let status: ReplicaStatusView =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();

    let desired = spec.replicas.unwrap_or(0);
    let ready = status.ready_replicas.unwrap_or(0);
    let ready_str = format!("{ready}/{desired}");

    let (containers, images) = container_names_and_images(&spec.template.spec.containers);

    let object_ref = make_object_ref(&obj, "StatefulSet");
    serde_json::json!({
        "cells": [name, ready_str, age, containers, images],
        "object": object_ref
    })
}

// ── DaemonSets ────────────────────────────────────────────────────────────────

fn build_daemonset_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the daemonset", "string"),
        col("Desired", "Desired number scheduled", "integer"),
        col("Current", "Current number scheduled", "integer"),
        col("Ready", "Number ready", "integer"),
        col("Up-To-Date", "Updated number scheduled", "integer"),
        col("Available", "Number available", "integer"),
        col("Node Selector", "Node selector", "string"),
        col("Age", "Time since creation", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(daemonset_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DaemonSetStatusView {
    #[serde(default)]
    desired_number_scheduled: i64,
    #[serde(default)]
    current_number_scheduled: i64,
    #[serde(default)]
    number_ready: i64,
    #[serde(default)]
    updated_number_scheduled: i64,
    #[serde(default)]
    number_available: i64,
}

#[derive(Deserialize, Default)]
struct DaemonSetSpecView {
    #[serde(default)]
    template: PodTemplateView,
}

fn daemonset_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let status: DaemonSetStatusView =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();
    let spec: DaemonSetSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let node_selector = label_map_to_string(spec.template.spec.node_selector.as_ref());

    let object_ref = make_object_ref(&obj, "DaemonSet");
    serde_json::json!({
        "cells": [
            name,
            status.desired_number_scheduled,
            status.current_number_scheduled,
            status.number_ready,
            status.updated_number_scheduled,
            status.number_available,
            node_selector,
            age
        ],
        "object": object_ref
    })
}

// ── Namespaces ────────────────────────────────────────────────────────────────

fn build_namespace_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the namespace", "string"),
        col("Status", "Phase of the namespace", "string"),
        col("Age", "Time since creation", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(namespace_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
struct NamespaceStatusView {
    phase: Option<String>,
}

fn namespace_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));
    let status: NamespaceStatusView =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();
    let status = status.phase.unwrap_or_else(|| "<none>".to_string());
    let object_ref = make_object_ref(&obj, "Namespace");
    serde_json::json!({
        "cells": [name, status, age],
        "object": object_ref
    })
}

// ── ConfigMaps ────────────────────────────────────────────────────────────────

fn build_configmap_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the configmap", "string"),
        col("Data", "Number of data keys", "integer"),
        col("Age", "Time since creation", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(configmap_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ConfigMapDataView {
    #[serde(default)]
    data: Option<BTreeMap<String, String>>,
    #[serde(default)]
    binary_data: Option<BTreeMap<String, String>>,
}

fn configmap_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));
    let fields: ConfigMapDataView = serde_json::from_value(obj.clone()).unwrap_or_default();
    let data_count = fields.data.map(|m| m.len()).unwrap_or(0)
        + fields.binary_data.map(|m| m.len()).unwrap_or(0);
    let object_ref = make_object_ref(&obj, "ConfigMap");
    serde_json::json!({
        "cells": [name, data_count as i64, age],
        "object": object_ref
    })
}

// ── Secrets ───────────────────────────────────────────────────────────────────

fn build_secret_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the secret", "string"),
        col("Type", "Secret type", "string"),
        col("Data", "Number of data keys", "integer"),
        col("Age", "Time since creation", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(secret_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
struct SecretDataView {
    #[serde(rename = "type", default)]
    type_: Option<String>,
    #[serde(default)]
    data: Option<BTreeMap<String, String>>,
}

fn secret_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));
    let fields: SecretDataView = serde_json::from_value(obj.clone()).unwrap_or_default();
    let secret_type = fields.type_.unwrap_or_else(|| "<none>".to_string());
    let data_count = fields.data.map(|m| m.len()).unwrap_or(0);
    let object_ref = make_object_ref(&obj, "Secret");
    serde_json::json!({
        "cells": [name, secret_type, data_count as i64, age],
        "object": object_ref
    })
}

// ── ServiceAccounts ───────────────────────────────────────────────────────────

fn build_serviceaccount_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the serviceaccount", "string"),
        col("Secrets", "Number of secrets", "integer"),
        col("Age", "Time since creation", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(serviceaccount_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
struct ServiceAccountView {
    /// Only the count matters here; individual secret-reference fields are never read.
    #[serde(default)]
    secrets: Vec<serde::de::IgnoredAny>,
}

fn serviceaccount_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));
    let fields: ServiceAccountView = serde_json::from_value(obj.clone()).unwrap_or_default();
    let object_ref = make_object_ref(&obj, "ServiceAccount");
    serde_json::json!({
        "cells": [name, fields.secrets.len() as i64, age],
        "object": object_ref
    })
}

// ── Jobs ──────────────────────────────────────────────────────────────────────

fn build_job_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the job", "string"),
        col("Status", "Job status", "string"),
        col("Completions", "Completions", "string"),
        col("Duration", "Duration of the job", "string"),
        col("Age", "Time since creation", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(job_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct JobStatusView {
    completion_time: Option<String>,
    start_time: Option<String>,
    #[serde(default)]
    active: i64,
    #[serde(default)]
    succeeded: i64,
}

#[derive(Deserialize, Default)]
struct JobSpecView {
    completions: Option<i64>,
}

fn job_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let job_status: JobStatusView =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();
    let job_spec: JobSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();

    let completion_time = job_status.completion_time.as_deref();
    let start_time = job_status.start_time.as_deref();
    let active = job_status.active;

    let status = if completion_time.is_some() {
        "Complete"
    } else if active > 0 {
        "Running"
    } else {
        "Failed"
    };

    let succeeded = job_status.succeeded;
    let total_completions = job_spec.completions.unwrap_or(1);
    let completions = format!("{succeeded}/{total_completions}");

    let duration = match (start_time, completion_time) {
        (Some(start), Some(end)) => {
            match (parse_rfc3339_to_secs(start), parse_rfc3339_to_secs(end)) {
                (Some(s), Some(e)) => {
                    let elapsed = e.saturating_sub(s);
                    let mins = elapsed / 60;
                    let hours = mins / 60;
                    let days = hours / 24;
                    if days >= 1 {
                        format!("{days}d")
                    } else if hours >= 1 {
                        format!("{hours}h")
                    } else if mins >= 1 {
                        format!("{mins}m")
                    } else {
                        format!("{elapsed}s")
                    }
                }
                _ => "<none>".to_string(),
            }
        }
        _ => "<none>".to_string(),
    };

    let object_ref = make_object_ref(&obj, "Job");
    serde_json::json!({
        "cells": [name, status, completions, duration, age],
        "object": object_ref
    })
}

// ── CronJobs ──────────────────────────────────────────────────────────────────

fn build_cronjob_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the cronjob", "string"),
        col("Schedule", "Cron schedule", "string"),
        col("Timezone", "Timezone", "string"),
        col("Suspend", "Suspended", "string"),
        col("Active", "Active jobs", "integer"),
        col("Last Schedule", "Last schedule time", "string"),
        col("Age", "Time since creation", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(cronjob_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CronJobSpecView {
    schedule: Option<String>,
    time_zone: Option<String>,
    #[serde(default)]
    suspend: bool,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CronJobStatusView {
    /// Only the count matters here; individual active-job-reference fields are never read.
    #[serde(default)]
    active: Vec<serde::de::IgnoredAny>,
    last_schedule_time: Option<String>,
}

fn cronjob_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let spec: CronJobSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let status: CronJobStatusView =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();

    let schedule = spec.schedule.unwrap_or_else(|| "<none>".to_string());
    let timezone = spec.time_zone.unwrap_or_else(|| "<none>".to_string());
    let suspend = if spec.suspend { "True" } else { "False" };
    let active = status.active.len() as i64;
    let last_schedule = status
        .last_schedule_time
        .as_deref()
        .map(age_string)
        .unwrap_or_else(|| "<none>".to_string());

    let object_ref = make_object_ref(&obj, "CronJob");
    serde_json::json!({
        "cells": [name, schedule, timezone, suspend, active, last_schedule, age],
        "object": object_ref
    })
}

// ── PersistentVolumeClaims ───────────────────────────────────────────────────

fn build_pvc_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the persistentvolumeclaim", "string"),
        col("Status", "Phase the claim is in", "string"),
        col("Volume", "Name of the bound persistentvolume", "string"),
        col("Capacity", "Size of the bound volume", "string"),
        col("Access Modes", "Access modes of the bound volume", "string"),
        col(
            "StorageClass",
            "Name of the requested storage class",
            "string",
        ),
        col(
            "VolumeAttributesClass",
            "Name of the requested volume attributes class",
            "string",
        ),
        col("Age", "Time since creation", "string"),
        wide_col("VolumeMode", "Filesystem or Block mode", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(pvc_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PvcSpecView {
    #[serde(default)]
    volume_name: Option<String>,
    #[serde(default)]
    storage_class_name: Option<String>,
    #[serde(default)]
    volume_attributes_class_name: Option<String>,
    #[serde(default)]
    volume_mode: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PvcStatusView {
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    access_modes: Option<Vec<String>>,
    #[serde(default)]
    capacity: Option<BTreeMap<String, String>>,
}

fn pvc_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let spec: PvcSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let status: PvcStatusView = serde_json::from_value(obj["status"].clone()).unwrap_or_default();

    // Upstream only reports the bound volume's actual capacity/access modes once
    // spec.volumeName is set; before binding it must stay blank, not the request size.
    let (capacity, access_modes) = if spec.volume_name.as_deref().unwrap_or("").is_empty() {
        (String::new(), String::new())
    } else {
        let capacity = status
            .capacity
            .as_ref()
            .and_then(|c| c.get("storage"))
            .cloned()
            .unwrap_or_default();
        let modes = access_modes_short_string(status.access_modes.as_deref().unwrap_or(&[]));
        (capacity, modes)
    };

    let status_phase = if meta.deletion_timestamp.is_some() {
        "Terminating".to_string()
    } else {
        status.phase.unwrap_or_default()
    };
    let volume = spec.volume_name.unwrap_or_default();
    let storage_class = spec.storage_class_name.unwrap_or_default();
    let volume_attributes_class = spec
        .volume_attributes_class_name
        .unwrap_or_else(|| "<unset>".to_string());
    let volume_mode = spec.volume_mode.unwrap_or_else(|| "<unset>".to_string());

    let object_ref = make_object_ref(&obj, "PersistentVolumeClaim");
    serde_json::json!({
        "cells": [
            name,
            status_phase,
            volume,
            capacity,
            access_modes,
            storage_class,
            volume_attributes_class,
            age,
            volume_mode
        ],
        "object": object_ref
    })
}

// ── PersistentVolumes ─────────────────────────────────────────────────────────

fn build_pv_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the persistentvolume", "string"),
        col("Capacity", "Size of the volume", "string"),
        col("Access Modes", "Access modes of the volume", "string"),
        col(
            "Reclaim Policy",
            "What happens to the volume when its claim is deleted",
            "string",
        ),
        col("Status", "Phase the volume is in", "string"),
        col(
            "Claim",
            "Bound persistentvolumeclaim, as namespace/name",
            "string",
        ),
        col("StorageClass", "Name of the storage class", "string"),
        col(
            "VolumeAttributesClass",
            "Name of the volume attributes class",
            "string",
        ),
        col(
            "Reason",
            "Reason the volume is in its current status",
            "string",
        ),
        col("Age", "Time since creation", "string"),
        wide_col("VolumeMode", "Filesystem or Block mode", "string"),
    ];
    let rows: Vec<serde_json::Value> = objects.into_iter().map(pv_row).collect();
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

#[derive(Deserialize, Default)]
struct PvClaimRefView {
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PvSpecView {
    #[serde(default)]
    capacity: Option<BTreeMap<String, String>>,
    #[serde(default)]
    access_modes: Option<Vec<String>>,
    #[serde(default)]
    persistent_volume_reclaim_policy: Option<String>,
    #[serde(default)]
    claim_ref: Option<PvClaimRefView>,
    #[serde(default)]
    storage_class_name: Option<String>,
    #[serde(default)]
    volume_attributes_class_name: Option<String>,
    #[serde(default)]
    volume_mode: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PvStatusView {
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn pv_row(obj: serde_json::Value) -> serde_json::Value {
    let meta = parse_metadata(&obj);
    let name = meta.name.clone().unwrap_or_default();
    let age = age_string(meta.creation_timestamp.as_deref().unwrap_or(""));

    let spec: PvSpecView = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let status: PvStatusView = serde_json::from_value(obj["status"].clone()).unwrap_or_default();

    let capacity = spec
        .capacity
        .as_ref()
        .and_then(|c| c.get("storage"))
        .cloned()
        .unwrap_or_default();
    let access_modes = access_modes_short_string(spec.access_modes.as_deref().unwrap_or(&[]));
    let reclaim_policy = spec.persistent_volume_reclaim_policy.unwrap_or_default();
    let status_phase = if meta.deletion_timestamp.is_some() {
        "Terminating".to_string()
    } else {
        status.phase.unwrap_or_default()
    };
    let claim = spec
        .claim_ref
        .map(|c| {
            format!(
                "{}/{}",
                c.namespace.unwrap_or_default(),
                c.name.unwrap_or_default()
            )
        })
        .unwrap_or_default();
    let storage_class = spec.storage_class_name.unwrap_or_default();
    let volume_attributes_class = spec
        .volume_attributes_class_name
        .unwrap_or_else(|| "<unset>".to_string());
    let reason = status.reason.unwrap_or_default();
    let volume_mode = spec.volume_mode.unwrap_or_else(|| "<unset>".to_string());

    let object_ref = make_object_ref(&obj, "PersistentVolume");
    serde_json::json!({
        "cells": [
            name,
            capacity,
            access_modes,
            reclaim_policy,
            status_phase,
            claim,
            storage_class,
            volume_attributes_class,
            reason,
            age,
            volume_mode
        ],
        "object": object_ref
    })
}

/// Mirrors upstream `helper.GetAccessModesAsString`: modes are always rendered
/// in this fixed order (RWO,ROX,RWX,RWOP), not the order they appear in the spec.
fn access_modes_short_string(modes: &[String]) -> String {
    let mut parts = Vec::new();
    if modes.iter().any(|m| m == "ReadWriteOnce") {
        parts.push("RWO");
    }
    if modes.iter().any(|m| m == "ReadOnlyMany") {
        parts.push("ROX");
    }
    if modes.iter().any(|m| m == "ReadWriteMany") {
        parts.push("RWX");
    }
    if modes.iter().any(|m| m == "ReadWriteOncePod") {
        parts.push("RWOP");
    }
    parts.join(",")
}

// ── Generic ───────────────────────────────────────────────────────────────────

fn build_generic_table(objects: Vec<serde_json::Value>) -> serde_json::Value {
    let columns = vec![
        col("Name", "Name of the resource", "string"),
        col("Age", "Time since creation", "string"),
    ];

    let rows: Vec<serde_json::Value> = objects.into_iter().map(generic_row).collect();

    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "Table",
        "columnDefinitions": columns,
        "rows": rows
    })
}

fn generic_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let creation_ts = obj["metadata"]["creationTimestamp"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let age = age_string(&creation_ts);
    let object_ref = make_object_ref(&obj, "");
    serde_json::json!({
        "cells": [name, age],
        "object": object_ref
    })
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Deserialize `obj.metadata` once per row via the shared `ObjectMeta` type instead of
/// every kind repeating its own raw `obj["metadata"]["name"]`/`["creationTimestamp"]` walk.
fn parse_metadata(obj: &serde_json::Value) -> ObjectMeta {
    serde_json::from_value(obj["metadata"].clone()).unwrap_or_default()
}

fn label_map_to_string(labels: Option<&BTreeMap<String, String>>) -> String {
    match labels {
        None => "<none>".to_string(),
        Some(m) if m.is_empty() => "<none>".to_string(),
        Some(m) => {
            let mut pairs: Vec<String> = m.iter().map(|(k, v)| format!("{k}={v}")).collect();
            pairs.sort();
            pairs.join(",")
        }
    }
}

fn make_object_ref(obj: &serde_json::Value, default_kind: &str) -> serde_json::Value {
    let api_version = obj["apiVersion"].as_str().unwrap_or("v1");
    let kind = obj["kind"].as_str().unwrap_or(default_kind);
    let metadata = &obj["metadata"];
    serde_json::json!({
        "apiVersion": api_version,
        "kind": kind,
        "metadata": metadata
    })
}

fn parse_rfc3339_to_secs(ts: &str) -> Option<u64> {
    // Minimal RFC3339 parse: YYYY-MM-DDTHH:MM:SSZ (the format secs_to_rfc3339 produces)
    if ts.len() < 19 {
        return None;
    }
    let year: u64 = ts[0..4].parse().ok()?;
    let month: u64 = ts[5..7].parse().ok()?;
    let day: u64 = ts[8..10].parse().ok()?;
    let hour: u64 = ts[11..13].parse().ok()?;
    let minute: u64 = ts[14..16].parse().ok()?;
    let second: u64 = ts[17..19].parse().ok()?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Days from epoch to start of year
    let days_to_year = days_from_epoch_to_year(year);
    // Days within the year up to this month
    let days_in_year = days_in_year_before_month(year, month) + day - 1;

    let total_days = days_to_year + days_in_year;
    let secs = total_days * 86400 + hour * 3600 + minute * 60 + second;
    Some(secs)
}

fn is_leap(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_from_epoch_to_year(year: u64) -> u64 {
    if year <= 1970 {
        return 0;
    }
    let y = year - 1970;
    // Full years from 1970 to year-1
    let y4 = (1970 + y - 1) / 4 - 1970 / 4;
    let y100 = (1970 + y - 1) / 100 - 1970 / 100;
    let y400 = (1970 + y - 1) / 400 - 1970 / 400;
    y * 365 + y4 - y100 + y400
}

fn days_in_year_before_month(year: u64, month: u64) -> u64 {
    let leap = is_leap(year);
    let month_days: [u64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    month_days[..(month as usize - 1)].iter().sum()
}

fn age_string(creation_ts: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let created = match parse_rfc3339_to_secs(creation_ts) {
        Some(s) => s,
        None => return "<unknown>".to_string(),
    };

    let elapsed = now.saturating_sub(created);
    let secs = elapsed;
    let mins = secs / 60;
    let hours = mins / 60;
    let days = hours / 24;

    if days >= 1 {
        format!("{days}d")
    } else if hours >= 1 {
        format!("{hours}h")
    } else if mins >= 1 {
        format!("{mins}m")
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wants_table_detects_table_accept_header() {
        assert!(
            wants_table("application/json;as=Table;g=meta.k8s.io;v=v1"),
            "kubectl sends as=Table in Accept — server must detect it to show full pod columns"
        );
        assert!(
            wants_table("application/json;as=Table;g=meta.k8s.io;v=v1,application/json"),
            "kubectl sends comma-separated Accept with as=Table"
        );
        assert!(
            !wants_table("application/json"),
            "plain JSON request must not be treated as Table request"
        );
        assert!(
            !wants_table("application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"),
            "PartialObjectMetadata must not be detected as Table"
        );
    }

    #[test]
    fn build_table_for_pods_returns_pod_columns() {
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod",
                "namespace": "default",
                "creationTimestamp": "2020-01-01T00:00:00Z"
            },
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app"}]
            },
            "status": {
                "phase": "Running",
                "podIP": "10.0.0.5",
                "containerStatuses": [
                    {
                        "name": "app",
                        "ready": true,
                        "restartCount": 3,
                        "state": {"running": {"startedAt": "2020-01-01T00:01:00Z"}}
                    }
                ]
            }
        });

        let table = build_table("", "pods", vec![pod]);

        assert_eq!(table["kind"], "Table");
        assert_eq!(table["apiVersion"], "meta.k8s.io/v1");

        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            [
                "Name",
                "Ready",
                "Status",
                "Restarts",
                "Age",
                "IP",
                "Node",
                "Nominated Node",
                "Readiness Gates"
            ],
            "kubectl get pods -o wide requires these exact columns to display correctly"
        );

        let rows = table["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "one pod must produce one row");

        let cells = rows[0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "my-pod", "NAME column must be metadata.name");
        assert_eq!(cells[1], "1/1", "READY must be ready/total container count");
        assert_eq!(cells[2], "Running", "STATUS must be pod phase");
        assert_eq!(
            cells[3], 3,
            "RESTARTS must sum restartCount across all containers"
        );
        assert_eq!(cells[5], "10.0.0.5", "IP must be status.podIP");
        assert_eq!(cells[6], "node-1", "NODE must be spec.nodeName");
        assert_eq!(cells[7], "<none>", "NOMINATED NODE is always <none>");
        assert_eq!(cells[8], "<none>", "READINESS GATES is always <none>");
    }

    #[test]
    fn build_table_for_pods_no_container_statuses_shows_zero_ready() {
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pending-pod",
                "creationTimestamp": "2020-01-01T00:00:00Z"
            },
            "spec": {
                "containers": [{"name": "app"}, {"name": "sidecar"}]
            },
            "status": {
                "phase": "Pending"
            }
        });

        let table = build_table("", "pods", vec![pod]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[1], "0/2",
            "pods with no containerStatuses must show 0/N using spec.containers count"
        );
        assert_eq!(cells[2], "Pending");
        assert_eq!(cells[3], 0);
    }

    #[test]
    fn build_table_for_unknown_resource_returns_name_and_age_only() {
        let obj = serde_json::json!({
            "apiVersion": "custom.io/v1",
            "kind": "Widget",
            "metadata": {
                "name": "my-widget",
                "creationTimestamp": "2020-01-01T00:00:00Z"
            }
        });

        let table = build_table("custom.io", "widgets", vec![obj]);

        assert_eq!(table["kind"], "Table");
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            ["Name", "Age"],
            "unknown resources must fall back to Name+Age — typed columns only for known resources"
        );
    }

    #[test]
    fn age_string_formats_durations_correctly() {
        let future = "2099-01-01T00:00:00Z";
        assert_eq!(
            age_string(future),
            "0s",
            "future timestamps (clock skew) must show 0s not negative"
        );

        assert_eq!(
            age_string(""),
            "<unknown>",
            "missing creationTimestamp must display as <unknown> not panic"
        );

        let epoch = "1970-01-01T00:00:00Z";
        let a = age_string(epoch);
        assert!(
            a.ends_with('d'),
            "old timestamp must format as days: got {a}"
        );
    }

    #[test]
    fn pod_terminating_status_overrides_phase() {
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "dying-pod",
                "creationTimestamp": "2020-01-01T00:00:00Z",
                "deletionTimestamp": "2020-01-02T00:00:00Z"
            },
            "spec": { "containers": [{"name": "app"}] },
            "status": { "phase": "Running" }
        });

        let table = build_table("", "pods", vec![pod]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[2], "Terminating",
            "pod with deletionTimestamp must show Terminating regardless of phase"
        );
    }

    #[test]
    fn table_row_includes_object_metadata() {
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "worker-1",
                "creationTimestamp": "2020-01-01T00:00:00Z"
            }
        });

        let table = build_table("", "nodes", vec![node]);
        let row = &table["rows"][0];
        assert!(
            row["object"].is_object(),
            "each row must include an object field so kubectl can display resource details"
        );
        assert_eq!(row["object"]["metadata"]["name"], "worker-1");
    }

    // ── Node tests ────────────────────────────────────────────────────────────

    #[test]
    fn build_table_for_nodes_returns_correct_columns_and_status() {
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "worker-1",
                "creationTimestamp": "2020-01-01T00:00:00Z",
                "labels": {
                    "node-role.kubernetes.io/worker": "",
                    "node-role.kubernetes.io/control-plane": ""
                }
            },
            "spec": {},
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "nodeInfo": {
                    "kubeletVersion": "v1.28.0",
                    "osImage": "Ubuntu 22.04",
                    "kernelVersion": "5.15.0",
                    "containerRuntimeVersion": "containerd://1.7.0"
                },
                "addresses": [
                    {"type": "InternalIP", "address": "192.168.1.10"},
                    {"type": "ExternalIP", "address": "203.0.113.5"}
                ]
            }
        });

        let table = build_table("", "nodes", vec![node]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            [
                "Name",
                "Status",
                "Roles",
                "Age",
                "Version",
                "Internal-IP",
                "External-IP",
                "OS-Image",
                "Kernel-Version",
                "Container-Runtime"
            ],
            "kubectl get nodes must show typed node columns not just Name+Age"
        );

        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "worker-1", "NAME must be metadata.name");
        assert_eq!(cells[1], "Ready", "STATUS must reflect Ready condition");
        assert_eq!(
            cells[2], "control-plane,worker",
            "ROLES must join node-role labels sorted alphabetically"
        );
        assert_eq!(cells[4], "v1.28.0", "VERSION must be kubeletVersion");
        assert_eq!(
            cells[5], "192.168.1.10",
            "INTERNAL-IP must come from addresses"
        );
        assert_eq!(
            cells[6], "203.0.113.5",
            "EXTERNAL-IP must come from addresses"
        );
    }

    #[test]
    fn node_unschedulable_appends_scheduling_disabled() {
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "n1", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {"unschedulable": true},
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "nodeInfo": {}
            }
        });
        let table = build_table("", "nodes", vec![node]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[1], "Ready,SchedulingDisabled",
            "cordoned node must show SchedulingDisabled so operators know it won't accept workloads"
        );
    }

    #[test]
    fn node_no_role_labels_shows_none() {
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "n1", "creationTimestamp": "2020-01-01T00:00:00Z", "labels": {}},
            "spec": {},
            "status": {"conditions": [], "nodeInfo": {}}
        });
        let table = build_table("", "nodes", vec![node]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[2], "<none>",
            "node with no role labels must display <none> not empty string"
        );
    }

    // ── Deployment tests ──────────────────────────────────────────────────────

    #[test]
    fn build_table_for_deployments_returns_correct_columns_and_ready() {
        let dep = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-dep", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "replicas": 3,
                "selector": {"matchLabels": {"app": "myapp"}},
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "web", "image": "nginx:latest"},
                            {"name": "sidecar", "image": "envoy:v1"}
                        ]
                    }
                }
            },
            "status": {"readyReplicas": 2, "updatedReplicas": 3, "availableReplicas": 2}
        });

        let table = build_table("apps", "deployments", vec![dep]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            [
                "Name",
                "Ready",
                "Up-To-Date",
                "Available",
                "Age",
                "Containers",
                "Images",
                "Selector"
            ],
            "kubectl get deployments must show typed deployment columns"
        );

        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "my-dep");
        assert_eq!(cells[1], "2/3", "READY must be readyReplicas/spec.replicas");
        assert_eq!(cells[2], 3, "UP-TO-DATE must be status.updatedReplicas");
        assert_eq!(cells[3], 2, "AVAILABLE must be status.availableReplicas");
        assert_eq!(
            cells[5], "web,sidecar",
            "CONTAINERS must preserve declaration order so names match their images"
        );
        assert_eq!(
            cells[7], "app=myapp",
            "SELECTOR must render matchLabels as k=v"
        );
    }

    // ── Service tests ─────────────────────────────────────────────────────────

    #[test]
    fn build_table_for_services_returns_correct_columns() {
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "type": "NodePort",
                "clusterIP": "10.96.0.1",
                "ports": [{"port": 80, "protocol": "TCP", "nodePort": 30080}],
                "selector": {"app": "web"}
            }
        });

        let table = build_table("", "services", vec![svc]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            [
                "Name",
                "Type",
                "Cluster-IP",
                "External-IP",
                "Port(s)",
                "Age",
                "Selector"
            ],
            "kubectl get services must show typed service columns"
        );

        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "my-svc");
        assert_eq!(cells[1], "NodePort", "TYPE must be spec.type");
        assert_eq!(cells[2], "10.96.0.1", "CLUSTER-IP must be spec.clusterIP");
        assert_eq!(cells[3], "<none>", "EXTERNAL-IP must be <none> when absent");
        assert_eq!(cells[4], "80:30080/TCP", "PORT(S) must include nodePort");
        assert_eq!(
            cells[6], "app=web",
            "SELECTOR must render spec.selector as k=v"
        );
    }

    #[test]
    fn service_external_ip_from_loadbalancer_ingress() {
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "lb-svc", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {"type": "LoadBalancer", "clusterIP": "10.96.0.2", "ports": []},
            "status": {"loadBalancer": {"ingress": [{"ip": "1.2.3.4"}]}}
        });
        let table = build_table("", "services", vec![svc]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[3], "1.2.3.4",
            "LoadBalancer service must show ingress IP as EXTERNAL-IP"
        );
    }

    // ── ReplicaSet tests ──────────────────────────────────────────────────────

    #[test]
    fn build_table_for_replicasets_returns_correct_columns() {
        let rs = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {"name": "my-rs", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "replicas": 3,
                "selector": {"matchLabels": {"app": "x"}},
                "template": {"spec": {"containers": [{"name": "app", "image": "img:v1"}]}}
            },
            "status": {"replicas": 3, "readyReplicas": 2}
        });

        let table = build_table("apps", "replicasets", vec![rs]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            [
                "Name",
                "Desired",
                "Current",
                "Ready",
                "Age",
                "Containers",
                "Images",
                "Selector"
            ],
            "kubectl get replicasets must show typed columns"
        );
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[1], 3, "DESIRED must be spec.replicas");
        assert_eq!(cells[2], 3, "CURRENT must be status.replicas");
        assert_eq!(cells[3], 2, "READY must be status.readyReplicas");
    }

    // ── StatefulSet tests ─────────────────────────────────────────────────────

    #[test]
    fn build_table_for_statefulsets_returns_correct_columns() {
        let sts = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "my-sts", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "replicas": 3,
                "template": {"spec": {"containers": [{"name": "db", "image": "pg:15"}]}}
            },
            "status": {"readyReplicas": 3}
        });

        let table = build_table("apps", "statefulsets", vec![sts]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            ["Name", "Ready", "Age", "Containers", "Images"],
            "kubectl get statefulsets must show typed columns"
        );
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "my-sts");
        assert_eq!(cells[1], "3/3", "READY must be readyReplicas/spec.replicas");
        assert_eq!(cells[3], "db", "CONTAINERS must list container names");
    }

    // ── DaemonSet tests ───────────────────────────────────────────────────────

    #[test]
    fn build_table_for_daemonsets_returns_correct_columns() {
        let ds = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {"name": "my-ds", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "template": {
                    "spec": {"nodeSelector": {"disktype": "ssd"}, "containers": []}
                }
            },
            "status": {
                "desiredNumberScheduled": 5,
                "currentNumberScheduled": 5,
                "numberReady": 4,
                "updatedNumberScheduled": 5,
                "numberAvailable": 4
            }
        });

        let table = build_table("apps", "daemonsets", vec![ds]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            [
                "Name",
                "Desired",
                "Current",
                "Ready",
                "Up-To-Date",
                "Available",
                "Node Selector",
                "Age"
            ],
            "kubectl get daemonsets must show typed columns"
        );
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[1], 5, "DESIRED must be status.desiredNumberScheduled");
        assert_eq!(cells[3], 4, "READY must be status.numberReady");
        assert_eq!(cells[6], "disktype=ssd", "NODE SELECTOR must render as k=v");
    }

    // ── Namespace tests ───────────────────────────────────────────────────────

    #[test]
    fn build_table_for_namespaces_returns_correct_columns() {
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "production", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "status": {"phase": "Active"}
        });

        let table = build_table("", "namespaces", vec![ns]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            ["Name", "Status", "Age"],
            "kubectl get namespaces must show Name, Status, Age"
        );
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "production");
        assert_eq!(cells[1], "Active", "STATUS must be status.phase");
    }

    // ── ConfigMap tests ───────────────────────────────────────────────────────

    #[test]
    fn build_table_for_configmaps_returns_data_count() {
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "my-cm", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "data": {"key1": "v1", "key2": "v2"},
            "binaryData": {"bin1": "YQ=="}
        });

        let table = build_table("", "configmaps", vec![cm]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            ["Name", "Data", "Age"],
            "kubectl get configmaps must show Name, Data count, Age"
        );
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[1], 3,
            "DATA must count keys in both data and binaryData so operators know total entries"
        );
    }

    // ── Secret tests ──────────────────────────────────────────────────────────

    #[test]
    fn build_table_for_secrets_returns_type_and_data_count() {
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "my-secret", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "type": "kubernetes.io/tls",
            "data": {"tls.crt": "...", "tls.key": "..."}
        });

        let table = build_table("", "secrets", vec![secret]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            ["Name", "Type", "Data", "Age"],
            "kubectl get secrets must show Name, Type, Data count, Age"
        );
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[1], "kubernetes.io/tls",
            "TYPE must be secret type field"
        );
        assert_eq!(cells[2], 2, "DATA must count keys in data map");
    }

    // ── ServiceAccount tests ──────────────────────────────────────────────────

    #[test]
    fn build_table_for_serviceaccounts_returns_secrets_count() {
        let sa = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "my-sa", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "secrets": [{"name": "my-sa-token-abc"}]
        });

        let table = build_table("", "serviceaccounts", vec![sa]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            ["Name", "Secrets", "Age"],
            "kubectl get serviceaccounts must show Name, Secrets count, Age"
        );
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[1], 1, "SECRETS must count entries in secrets array");
    }

    // ── Job tests ─────────────────────────────────────────────────────────────

    #[test]
    fn build_table_for_jobs_returns_correct_columns_and_status() {
        let job = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": "my-job", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {"completions": 5},
            "status": {
                "startTime": "2020-01-01T00:00:00Z",
                "completionTime": "2020-01-01T00:05:00Z",
                "succeeded": 5
            }
        });

        let table = build_table("batch", "jobs", vec![job]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            ["Name", "Status", "Completions", "Duration", "Age"],
            "kubectl get jobs must show typed job columns"
        );
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "my-job");
        assert_eq!(
            cells[1], "Complete",
            "STATUS must be Complete when completionTime is set"
        );
        assert_eq!(
            cells[2], "5/5",
            "COMPLETIONS must be succeeded/spec.completions"
        );
        assert_eq!(
            cells[3], "5m",
            "DURATION must be delta between startTime and completionTime"
        );
    }

    #[test]
    fn job_running_status_when_active_nonzero() {
        let job = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": "running-job", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {"completions": 1},
            "status": {"startTime": "2020-01-01T00:00:00Z", "active": 1}
        });
        let table = build_table("batch", "jobs", vec![job]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[1], "Running",
            "job with active > 0 and no completionTime must show Running"
        );
        assert_eq!(
            cells[3], "<none>",
            "DURATION must be <none> while job is running"
        );
    }

    // ── CronJob tests ─────────────────────────────────────────────────────────

    #[test]
    fn build_table_for_cronjobs_returns_correct_columns() {
        let cj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "my-cron", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "schedule": "0 * * * *",
                "timeZone": "UTC",
                "suspend": false
            },
            "status": {
                "active": [{"name": "job-1"}],
                "lastScheduleTime": "2020-01-01T00:00:00Z"
            }
        });

        let table = build_table("batch", "cronjobs", vec![cj]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            [
                "Name",
                "Schedule",
                "Timezone",
                "Suspend",
                "Active",
                "Last Schedule",
                "Age"
            ],
            "kubectl get cronjobs must show typed cronjob columns"
        );
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "my-cron");
        assert_eq!(cells[1], "0 * * * *", "SCHEDULE must be spec.schedule");
        assert_eq!(cells[2], "UTC", "TIMEZONE must be spec.timeZone");
        assert_eq!(
            cells[3], "False",
            "SUSPEND must be False when spec.suspend=false"
        );
        assert_eq!(cells[4], 1, "ACTIVE must count status.active array entries");
    }

    #[test]
    fn cronjob_suspend_true_shows_true() {
        let cj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "paused-cron", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {"schedule": "*/5 * * * *", "suspend": true},
            "status": {}
        });
        let table = build_table("batch", "cronjobs", vec![cj]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[3], "True",
            "suspended cronjob must show True so operators know it won't fire"
        );
        assert_eq!(cells[4], 0, "ACTIVE must be 0 when status.active is absent");
        assert_eq!(
            cells[5], "<none>",
            "LAST SCHEDULE must be <none> when lastScheduleTime is absent"
        );
    }

    #[test]
    fn deployment_containers_and_images_sorted_correctly() {
        let dep = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "d", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {}},
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "web", "image": "nginx:latest"},
                            {"name": "sidecar", "image": "envoy:v1"}
                        ]
                    }
                }
            },
            "status": {}
        });
        let table = build_table("apps", "deployments", vec![dep]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        // containers keep declaration order (not sorted), images same
        assert_eq!(
            cells[5], "web,sidecar",
            "CONTAINERS must preserve container declaration order"
        );
        assert_eq!(
            cells[6], "nginx:latest,envoy:v1",
            "IMAGES must match container order so they correspond to the right container"
        );
    }

    // ── PersistentVolumeClaim tests ──────────────────────────────────────────
    // Storage triage (`kubectl get pvc`) relies on STATUS/CAPACITY/ACCESS MODES
    // being present; a regression here silently drops back to NAME+AGE only.

    #[test]
    fn build_table_for_pvcs_bound_shows_all_columns_from_status() {
        let pvc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": "data-mariadb-0", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "volumeName": "pvc-1234",
                "storageClassName": "csi-hostpath-sc",
                "resources": {"requests": {"storage": "10Gi"}}
            },
            "status": {
                "phase": "Bound",
                "accessModes": ["ReadWriteOnce"],
                "capacity": {"storage": "10Gi"}
            }
        });

        let table = build_table("", "persistentvolumeclaims", vec![pvc]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            [
                "Name",
                "Status",
                "Volume",
                "Capacity",
                "Access Modes",
                "StorageClass",
                "VolumeAttributesClass",
                "Age",
                "VolumeMode"
            ],
            "kubectl get pvc must show the upstream column set, not just NAME/AGE"
        );
        assert_eq!(
            cols[8]["priority"], 1,
            "VolumeMode must be wide-only (priority 1) to match upstream `-o wide` behavior"
        );
        for (i, c) in cols.iter().enumerate().take(8) {
            assert_eq!(
                c["priority"], 0,
                "column {i} must render in plain `kubectl get pvc`"
            );
        }

        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "data-mariadb-0");
        assert_eq!(cells[1], "Bound", "STATUS must be status.phase");
        assert_eq!(cells[2], "pvc-1234", "VOLUME must be spec.volumeName");
        assert_eq!(
            cells[3], "10Gi",
            "CAPACITY must be status.capacity.storage once bound, not the request size"
        );
        assert_eq!(
            cells[4], "RWO",
            "ACCESS MODES must render the upstream short form (RWO), not the raw enum name"
        );
        assert_eq!(
            cells[5], "csi-hostpath-sc",
            "STORAGECLASS must be spec.storageClassName"
        );
        assert_eq!(cells[6], "<unset>");
        assert_eq!(cells[8], "<unset>");
    }

    #[test]
    fn build_table_for_pvcs_pending_hides_capacity_and_access_modes() {
        let pvc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": "unbound-pvc", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "storageClassName": "csi-hostpath-sc",
                "resources": {"requests": {"storage": "5Gi"}}
            },
            "status": {"phase": "Pending"}
        });

        let table = build_table("", "persistentvolumeclaims", vec![pvc]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[1], "Pending");
        assert_eq!(cells[2], "", "VOLUME must be blank before binding");
        assert_eq!(
            cells[3], "",
            "CAPACITY must stay blank pre-binding — showing the request size would mislead \
             an operator into thinking storage is already provisioned"
        );
        assert_eq!(cells[4], "", "ACCESS MODES must stay blank pre-binding");
    }

    #[test]
    fn pvc_terminating_status_overrides_phase() {
        let pvc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": "dying-pvc",
                "creationTimestamp": "2020-01-01T00:00:00Z",
                "deletionTimestamp": "2020-01-02T00:00:00Z"
            },
            "spec": {
                "volumeName": "pvc-1234",
                "storageClassName": "csi-hostpath-sc"
            },
            "status": { "phase": "Bound" }
        });

        let table = build_table("", "persistentvolumeclaims", vec![pvc]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[1], "Terminating",
            "pvc with deletionTimestamp must show Terminating regardless of phase — \
             otherwise `kubectl get pvc` hides an in-progress delete from operators"
        );
    }

    // ── PersistentVolume tests ────────────────────────────────────────────────

    #[test]
    fn build_table_for_pvs_bound_shows_all_columns() {
        let pv = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": {"name": "pvc-1234", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "capacity": {"storage": "10Gi"},
                "accessModes": ["ReadWriteOnce"],
                "persistentVolumeReclaimPolicy": "Delete",
                "claimRef": {"namespace": "default", "name": "data-mariadb-0"},
                "storageClassName": "csi-hostpath-sc"
            },
            "status": {"phase": "Bound"}
        });

        let table = build_table("", "persistentvolumes", vec![pv]);
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            [
                "Name",
                "Capacity",
                "Access Modes",
                "Reclaim Policy",
                "Status",
                "Claim",
                "StorageClass",
                "VolumeAttributesClass",
                "Reason",
                "Age",
                "VolumeMode"
            ],
            "kubectl get pv must show the upstream column set, not just NAME/AGE"
        );
        assert_eq!(
            cols[10]["priority"], 1,
            "VolumeMode must be wide-only (priority 1) to match upstream `-o wide` behavior"
        );

        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "pvc-1234");
        assert_eq!(cells[1], "10Gi", "CAPACITY must be spec.capacity.storage");
        assert_eq!(
            cells[2], "RWO",
            "ACCESS MODES must render the upstream short form (RWO), not the raw enum name"
        );
        assert_eq!(
            cells[3], "Delete",
            "RECLAIM POLICY must be spec.persistentVolumeReclaimPolicy"
        );
        assert_eq!(cells[4], "Bound", "STATUS must be status.phase");
        assert_eq!(
            cells[5], "default/data-mariadb-0",
            "CLAIM must render as namespace/name so operators can find the bound claim"
        );
        assert_eq!(
            cells[6], "csi-hostpath-sc",
            "STORAGECLASS must be spec.storageClassName"
        );
        assert_eq!(cells[7], "<unset>");
        assert_eq!(cells[8], "");
    }

    #[test]
    fn build_table_for_pvs_unbound_has_empty_claim_and_no_capacity_gate() {
        let pv = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": {"name": "pv-standalone", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {
                "capacity": {"storage": "1Gi"},
                "accessModes": ["ReadWriteOnce"],
                "persistentVolumeReclaimPolicy": "Retain"
            },
            "status": {"phase": "Available"}
        });

        let table = build_table("", "persistentvolumes", vec![pv]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[1], "1Gi",
            "PV CAPACITY is always spec.capacity.storage, unlike PVC which gates on binding"
        );
        assert_eq!(cells[4], "Available");
        assert_eq!(
            cells[5], "",
            "CLAIM must be blank when spec.claimRef is unset — no PVC bound yet"
        );
    }

    #[test]
    fn pv_terminating_status_overrides_phase() {
        let pv = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": {
                "name": "dying-pv",
                "creationTimestamp": "2020-01-01T00:00:00Z",
                "deletionTimestamp": "2020-01-02T00:00:00Z"
            },
            "spec": {
                "capacity": {"storage": "10Gi"},
                "persistentVolumeReclaimPolicy": "Delete"
            },
            "status": { "phase": "Bound" }
        });

        let table = build_table("", "persistentvolumes", vec![pv]);
        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(
            cells[4], "Terminating",
            "pv with deletionTimestamp must show Terminating regardless of phase — \
             otherwise `kubectl get pv` hides an in-progress delete from operators"
        );
    }

    // table_accept_version must correctly parse the Table API version from the Accept header
    // so that handlers can reject v1beta1 with 406 rather than serving an incompatible format.
    #[test]
    fn table_accept_version_extracts_version() {
        assert_eq!(
            table_accept_version("application/json;as=Table;g=meta.k8s.io;v=v1"),
            Some("v1"),
            "v1 Table Accept must be recognised — kubectl get relies on v1 Table"
        );
        assert_eq!(
            table_accept_version(
                "application/json;as=Table;g=meta.k8s.io;v=v1beta1,application/json"
            ),
            Some("v1beta1"),
            "v1beta1 Table must be detected so handlers can return 406 instead of wrong format"
        );
        assert_eq!(
            table_accept_version("application/json;as=Table;g=meta.k8s.io;v=v1,application/json"),
            Some("v1"),
            "v1 Table with fallback must still be detected as v1"
        );
        assert_eq!(
            table_accept_version("application/json"),
            None,
            "plain JSON must not be treated as a Table request"
        );
        assert_eq!(
            table_accept_version(
                "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json"
            ),
            None,
            "PartialObjectMetadata must not be detected as Table"
        );
    }

    // table_accept_version must return Some("v1") when as=Table is present but no v= param,
    // so that we don't silently treat versionless requests as unsupported.
    #[test]
    fn table_accept_version_defaults_to_v1_when_no_version_param() {
        assert_eq!(
            table_accept_version("application/json;as=Table;g=meta.k8s.io"),
            Some("v1"),
            "as=Table without v= must default to v1 — some older clients omit the version"
        );
    }
}
