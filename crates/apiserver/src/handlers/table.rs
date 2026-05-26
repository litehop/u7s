use std::time::{SystemTime, UNIX_EPOCH};

pub fn wants_table(accept: &str) -> bool {
    accept.contains("as=Table")
}

pub fn build_table(
    group: &str,
    plural: &str,
    objects: Vec<serde_json::Value>,
) -> serde_json::Value {
    if group.is_empty() && plural == "pods" {
        build_pod_table(objects)
    } else {
        build_generic_table(objects)
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
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
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
    fn build_table_for_non_pods_returns_name_and_age_only() {
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "worker-1",
                "creationTimestamp": "2020-01-01T00:00:00Z"
            }
        });

        let table = build_table("", "nodes", vec![node]);

        assert_eq!(table["kind"], "Table");
        let cols = table["columnDefinitions"].as_array().unwrap();
        let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            col_names,
            ["Name", "Age"],
            "non-pod resources must only have NAME and AGE columns — adding more breaks kubectl display for unknown resources"
        );

        let cells = table["rows"][0]["cells"].as_array().unwrap();
        assert_eq!(cells[0], "worker-1");
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
}
