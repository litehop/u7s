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

fn pod_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let creation_ts = obj["metadata"]["creationTimestamp"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let age = age_string(&creation_ts);

    let phase = obj["status"]["phase"].as_str().unwrap_or("Unknown");

    let container_statuses = obj["status"]["containerStatuses"].as_array();
    let spec_containers = obj["spec"]["containers"].as_array();

    let total = container_statuses
        .map(|cs| cs.len())
        .or_else(|| spec_containers.map(|c| c.len()))
        .unwrap_or(0);

    let ready_count = container_statuses
        .map(|cs| {
            cs.iter()
                .filter(|c| c["ready"].as_bool().unwrap_or(false))
                .count()
        })
        .unwrap_or(0);

    let restarts: i64 = container_statuses
        .map(|cs| {
            cs.iter()
                .map(|c| c["restartCount"].as_i64().unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);

    let status = pod_display_status(&obj, phase, container_statuses);

    let pod_ip = obj["status"]["podIP"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();
    let node_name = obj["spec"]["nodeName"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();

    let ready_str = format!("{ready_count}/{total}");

    let object_ref = make_object_ref(&obj, "Pod");

    serde_json::json!({
        "cells": [
            name,
            ready_str,
            status,
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
    obj: &serde_json::Value,
    phase: &str,
    container_statuses: Option<&Vec<serde_json::Value>>,
) -> String {
    if obj["metadata"]["deletionTimestamp"].is_string() {
        return "Terminating".to_string();
    }

    if let Some(cs) = container_statuses {
        for c in cs {
            let waiting_reason = c["state"]["waiting"]["reason"].as_str();
            let terminated_reason = c["state"]["terminated"]["reason"].as_str();
            if let Some(reason) = waiting_reason {
                if reason != "Completed" {
                    return reason.to_string();
                }
            }
            if let Some(reason) = terminated_reason {
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

fn node_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));

    // STATUS
    let ready_condition = obj["status"]["conditions"]
        .as_array()
        .and_then(|conds| conds.iter().find(|c| c["type"].as_str() == Some("Ready")));
    let ready_str = ready_condition
        .and_then(|c| c["status"].as_str())
        .map(|s| if s == "True" { "Ready" } else { "NotReady" })
        .unwrap_or("NotReady");
    let unschedulable = obj["spec"]["unschedulable"].as_bool().unwrap_or(false);
    let status = if unschedulable {
        format!("{ready_str},SchedulingDisabled")
    } else {
        ready_str.to_string()
    };

    // ROLES
    let roles = obj["metadata"]["labels"]
        .as_object()
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

    let version = obj["status"]["nodeInfo"]["kubeletVersion"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();

    let addresses = obj["status"]["addresses"].as_array();
    let internal_ip = addresses
        .and_then(|addrs| {
            addrs
                .iter()
                .find(|a| a["type"].as_str() == Some("InternalIP"))
                .and_then(|a| a["address"].as_str())
        })
        .unwrap_or("<none>")
        .to_string();
    let external_ip = addresses
        .and_then(|addrs| {
            addrs
                .iter()
                .find(|a| a["type"].as_str() == Some("ExternalIP"))
                .and_then(|a| a["address"].as_str())
        })
        .unwrap_or("<none>")
        .to_string();

    let os_image = obj["status"]["nodeInfo"]["osImage"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();
    let kernel_version = obj["status"]["nodeInfo"]["kernelVersion"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();
    let container_runtime = obj["status"]["nodeInfo"]["containerRuntimeVersion"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();

    let object_ref = make_object_ref(&obj, "Node");
    serde_json::json!({
        "cells": [name, status, roles, age, version, internal_ip, external_ip, os_image, kernel_version, container_runtime],
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

fn deployment_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));

    let desired = obj["spec"]["replicas"].as_i64().unwrap_or(0);
    let ready = obj["status"]["readyReplicas"].as_i64().unwrap_or(0);
    let up_to_date = obj["status"]["updatedReplicas"].as_i64().unwrap_or(0);
    let available = obj["status"]["availableReplicas"].as_i64().unwrap_or(0);
    let ready_str = format!("{ready}/{desired}");

    let containers = obj["spec"]["template"]["spec"]["containers"]
        .as_array()
        .map(|cs| {
            cs.iter()
                .filter_map(|c| c["name"].as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let images = obj["spec"]["template"]["spec"]["containers"]
        .as_array()
        .map(|cs| {
            cs.iter()
                .filter_map(|c| c["image"].as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let selector = label_map_to_string(&obj["spec"]["selector"]["matchLabels"]);

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

fn service_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));

    let svc_type = obj["spec"]["type"].as_str().unwrap_or("<none>").to_string();
    let cluster_ip = obj["spec"]["clusterIP"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();

    // External IP: externalIPs[0] → loadBalancer.ingress[0].ip → .hostname → <none>
    let external_ip = obj["spec"]["externalIPs"]
        .as_array()
        .and_then(|ips| ips.first())
        .and_then(|v| v.as_str())
        .or_else(|| {
            obj["status"]["loadBalancer"]["ingress"]
                .as_array()
                .and_then(|ing| ing.first())
                .and_then(|i| i["ip"].as_str().or_else(|| i["hostname"].as_str()))
        })
        .unwrap_or("<none>")
        .to_string();

    // PORT(S)
    let ports = obj["spec"]["ports"]
        .as_array()
        .map(|ps| {
            ps.iter()
                .map(|p| {
                    let port = p["port"].as_i64().unwrap_or(0);
                    let proto = p["protocol"].as_str().unwrap_or("TCP");
                    if let Some(np) = p["nodePort"].as_i64() {
                        format!("{port}:{np}/{proto}")
                    } else {
                        format!("{port}/{proto}")
                    }
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();

    let selector = label_map_to_string(&obj["spec"]["selector"]);

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
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));

    let desired = obj["spec"]["replicas"].as_i64().unwrap_or(0);
    let current = obj["status"]["replicas"].as_i64().unwrap_or(0);
    let ready = obj["status"]["readyReplicas"].as_i64().unwrap_or(0);

    let containers = obj["spec"]["template"]["spec"]["containers"]
        .as_array()
        .map(|cs| {
            cs.iter()
                .filter_map(|c| c["name"].as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let images = obj["spec"]["template"]["spec"]["containers"]
        .as_array()
        .map(|cs| {
            cs.iter()
                .filter_map(|c| c["image"].as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let selector = label_map_to_string(&obj["spec"]["selector"]["matchLabels"]);

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
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));

    let desired = obj["spec"]["replicas"].as_i64().unwrap_or(0);
    let ready = obj["status"]["readyReplicas"].as_i64().unwrap_or(0);
    let ready_str = format!("{ready}/{desired}");

    let containers = obj["spec"]["template"]["spec"]["containers"]
        .as_array()
        .map(|cs| {
            cs.iter()
                .filter_map(|c| c["name"].as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let images = obj["spec"]["template"]["spec"]["containers"]
        .as_array()
        .map(|cs| {
            cs.iter()
                .filter_map(|c| c["image"].as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();

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

fn daemonset_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));

    let desired = obj["status"]["desiredNumberScheduled"]
        .as_i64()
        .unwrap_or(0);
    let current = obj["status"]["currentNumberScheduled"]
        .as_i64()
        .unwrap_or(0);
    let ready = obj["status"]["numberReady"].as_i64().unwrap_or(0);
    let up_to_date = obj["status"]["updatedNumberScheduled"]
        .as_i64()
        .unwrap_or(0);
    let available = obj["status"]["numberAvailable"].as_i64().unwrap_or(0);
    let node_selector = label_map_to_string(&obj["spec"]["template"]["spec"]["nodeSelector"]);

    let object_ref = make_object_ref(&obj, "DaemonSet");
    serde_json::json!({
        "cells": [name, desired, current, ready, up_to_date, available, node_selector, age],
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

fn namespace_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));
    let status = obj["status"]["phase"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();
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

fn configmap_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));
    let data_count = obj["data"].as_object().map(|m| m.len()).unwrap_or(0)
        + obj["binaryData"].as_object().map(|m| m.len()).unwrap_or(0);
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

fn secret_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));
    let secret_type = obj["type"].as_str().unwrap_or("<none>").to_string();
    let data_count = obj["data"].as_object().map(|m| m.len()).unwrap_or(0);
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

fn serviceaccount_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));
    let secrets = obj["secrets"].as_array().map(|a| a.len()).unwrap_or(0);
    let object_ref = make_object_ref(&obj, "ServiceAccount");
    serde_json::json!({
        "cells": [name, secrets as i64, age],
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

fn job_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));

    let completion_time = obj["status"]["completionTime"].as_str();
    let start_time = obj["status"]["startTime"].as_str();
    let active = obj["status"]["active"].as_i64().unwrap_or(0);

    let status = if completion_time.is_some() {
        "Complete"
    } else if active > 0 {
        "Running"
    } else {
        "Failed"
    };

    let succeeded = obj["status"]["succeeded"].as_i64().unwrap_or(0);
    let total_completions = obj["spec"]["completions"].as_i64().unwrap_or(1);
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

fn cronjob_row(obj: serde_json::Value) -> serde_json::Value {
    let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
    let age = age_string(obj["metadata"]["creationTimestamp"].as_str().unwrap_or(""));

    let schedule = obj["spec"]["schedule"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();
    let timezone = obj["spec"]["timeZone"]
        .as_str()
        .unwrap_or("<none>")
        .to_string();
    let suspend = if obj["spec"]["suspend"].as_bool().unwrap_or(false) {
        "True"
    } else {
        "False"
    };
    let active = obj["status"]["active"]
        .as_array()
        .map(|a| a.len() as i64)
        .unwrap_or(0);
    let last_schedule = obj["status"]["lastScheduleTime"]
        .as_str()
        .map(age_string)
        .unwrap_or_else(|| "<none>".to_string());

    let object_ref = make_object_ref(&obj, "CronJob");
    serde_json::json!({
        "cells": [name, schedule, timezone, suspend, active, last_schedule, age],
        "object": object_ref
    })
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

fn label_map_to_string(val: &serde_json::Value) -> String {
    val.as_object()
        .map(|m| {
            if m.is_empty() {
                return "<none>".to_string();
            }
            let mut pairs: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("{}={}", k, v.as_str().unwrap_or("")))
                .collect();
            pairs.sort();
            pairs.join(",")
        })
        .unwrap_or_else(|| "<none>".to_string())
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
