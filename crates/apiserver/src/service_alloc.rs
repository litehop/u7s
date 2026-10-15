//! Cluster-wide reservation of Service clusterIPs, nodePorts and healthCheckNodePorts.
//!
//! Every reservation is a create-only sentinel key, so two Services can never hold the same
//! VIP or node port. A Service write computes the difference between the stored spec and the
//! spec about to be persisted: values newly present are reserved (a preset value that is
//! out of range or already held yields 422, matching upstream's
//! `pkg/registry/core/service/storage/alloc.go`), values no longer present are released once
//! the write succeeds.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use serde_json::Value;
use u7s_store::{ListOptions, Store, StoreError};

use crate::state::{AppState, SERVICE_IP_PREFIX};
use crate::status::{Status, StatusError};

/// Sentinel key prefix for reserved node ports. Format: /registry/service-nodeports/<port>
pub const NODE_PORT_PREFIX: &str = "/registry/service-nodeports/";

const NODE_PORT_MIN: i64 = 30000;
const NODE_PORT_MAX: i64 = 32767;
const SENTINEL: &[u8] = b"{\"kind\":\"ServiceAllocation\"}";

/// Reservations made for one Service write, pending its outcome.
///
/// Dropping it without `commit` gives back everything it reserved, so every early return
/// and a handler future cancelled by a client disconnect cannot leak a VIP or node port.
pub(crate) struct ServiceAllocTxn<S: Store> {
    store: Arc<S>,
    created: Vec<String>,
    stale: Vec<String>,
}

impl<S: Store> ServiceAllocTxn<S> {
    fn new(store: Arc<S>) -> Self {
        Self {
            store,
            created: Vec::new(),
            stale: Vec::new(),
        }
    }

    /// The write succeeded: keep the reservations, free what the Service no longer holds.
    pub(crate) async fn commit(mut self) {
        self.created.clear();
        for key in std::mem::take(&mut self.stale) {
            delete_sentinel(&*self.store, &key).await;
        }
    }

    /// Give back what this attempt reserved, awaiting completion.
    pub(crate) async fn rollback(mut self) {
        for key in std::mem::take(&mut self.created) {
            delete_sentinel(&*self.store, &key).await;
        }
    }
}

impl<S: Store> Drop for ServiceAllocTxn<S> {
    fn drop(&mut self) {
        if self.created.is_empty() {
            return;
        }
        let store = self.store.clone();
        let created = std::mem::take(&mut self.created);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                for key in created {
                    delete_sentinel(&*store, &key).await;
                }
            });
        }
    }
}

async fn delete_sentinel<S: Store>(store: &S, key: &str) {
    match store.delete(key, None).await {
        Ok(_) | Err(StoreError::NotFound { .. }) => {}
        Err(e) => tracing::warn!("failed to release service allocation {key}: {e}"),
    }
}

fn spec_ips(spec: &Value) -> BTreeSet<String> {
    let mut ips = BTreeSet::new();
    let single = spec["clusterIP"].as_str().into_iter();
    let list = spec["clusterIPs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    for ip in single.chain(list) {
        if !ip.is_empty() && ip != "None" {
            ips.insert(ip.to_string());
        }
    }
    ips
}

fn spec_ports(spec: &Value) -> BTreeSet<i64> {
    let mut ports = BTreeSet::new();
    for p in spec["ports"].as_array().into_iter().flatten() {
        if let Some(np) = p["nodePort"].as_i64().filter(|&n| n != 0) {
            ports.insert(np);
        }
    }
    if let Some(h) = spec["healthCheckNodePort"].as_i64().filter(|&n| n != 0) {
        ports.insert(h);
    }
    ports
}

/// Sentinel body for a clusterIP reserved ahead of its Service's creation: only that
/// Service may later claim it.
pub(crate) fn owned_ip_sentinel(ns: &str, name: &str) -> bytes::Bytes {
    bytes::Bytes::from(
        serde_json::json!({"kind": "ServiceIPAllocation", "owner": format!("{ns}/{name}")})
            .to_string(),
    )
}

fn ip_key(ip: &str) -> String {
    format!("{SERVICE_IP_PREFIX}{ip}")
}

fn port_key(port: i64) -> String {
    format!("{NODE_PORT_PREFIX}{port}")
}

/// Release every reservation held by a deleted Service's `spec`.
pub(crate) async fn release_service_allocations<S: Store>(state: &AppState<S>, spec: &Value) {
    for ip in spec_ips(spec) {
        state.release_service_ip(&ip).await;
    }
    for port in spec_ports(spec) {
        delete_sentinel(&*state.store, &port_key(port)).await;
    }
}

fn invalid(name: &str, field: &str, value: &str, detail: &str) -> StatusError {
    Status::unprocessable_entity(format!(
        "Service \"{name}\" is invalid: {field}: Invalid value: {value}: {detail}"
    ))
}

struct Reserver<'a, S: Store> {
    state: &'a AppState<S>,
    dry_run: bool,
    txn: ServiceAllocTxn<S>,
}

impl<S: Store> Reserver<'_, S> {
    /// `Ok(true)` if the key is now held by the caller, `Ok(false)` if someone else holds it.
    async fn reserve(&mut self, key: String) -> Result<bool, StatusError> {
        if self.dry_run {
            return self
                .state
                .store
                .get(&key)
                .await
                .map(|held| held.is_none())
                .map_err(|e| Status::internal(e.to_string()));
        }
        match self
            .state
            .store
            .put(&key, bytes::Bytes::from_static(SENTINEL), Some(0))
            .await
        {
            Ok(_) => {
                self.txn.created.push(key);
                Ok(true)
            }
            Err(StoreError::AlreadyExists { .. }) => Ok(false),
            Err(e) => Err(Status::internal(format!("service allocation error: {e}"))),
        }
    }

    /// True if the key's sentinel was reserved ahead of time for exactly this Service.
    async fn pre_reserved_for(&self, key: &str, ns: &str, name: &str) -> Result<bool, StatusError> {
        let held = self
            .state
            .store
            .get(key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(held
            .and_then(|o| serde_json::from_slice::<Value>(&o.value).ok())
            .is_some_and(|v| v["owner"].as_str() == Some(&format!("{ns}/{name}"))))
    }

    async fn used_ports(&self) -> Result<BTreeSet<i64>, StatusError> {
        let resp = self
            .state
            .store
            .list(NODE_PORT_PREFIX, ListOptions::default())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(resp
            .items
            .iter()
            .filter_map(|o| o.key.strip_prefix(NODE_PORT_PREFIX)?.parse().ok())
            .collect())
    }

    /// Reserve the lowest free port in the node-port range.
    async fn allocate_next_port(&mut self, taken: &BTreeSet<i64>) -> Result<i64, StatusError> {
        let used = self.used_ports().await?;
        for port in NODE_PORT_MIN..=NODE_PORT_MAX {
            if used.contains(&port) || taken.contains(&port) {
                continue;
            }
            if self.reserve(port_key(port)).await? {
                return Ok(port);
            }
        }
        Err(Status::internal(
            "failed to allocate a nodePort: range is full".to_string(),
        ))
    }
}

/// Drop fields that are meaningless for the Service's type, as upstream's
/// `dropTypeDependentFields` does, so a type change away from NodePort/LoadBalancer frees
/// the node ports.
fn drop_type_dependent_fields(spec: &mut Value) {
    let svc_type = spec["type"].as_str().unwrap_or("ClusterIP").to_string();
    if svc_type != "NodePort" && svc_type != "LoadBalancer" {
        for p in spec["ports"].as_array_mut().into_iter().flatten() {
            if let Some(o) = p.as_object_mut() {
                o.remove("nodePort");
            }
        }
    }
    let needs_health_check =
        svc_type == "LoadBalancer" && spec["externalTrafficPolicy"].as_str() == Some("Local");
    if !needs_health_check {
        if let Some(o) = spec.as_object_mut() {
            o.remove("healthCheckNodePort");
        }
    }
}

/// Reserve what `body` (a defaulted Service about to be persisted) needs beyond what
/// `old_spec` (the stored spec, `None` on create) already holds, auto-assigning node ports
/// that are unset. `auto_ip` is a clusterIP the caller already allocated for this write.
///
/// `dry_run` performs the same validation and picks ports without taking any reservation.
pub(crate) async fn begin<S: Store>(
    state: &AppState<S>,
    ns: &str,
    name: &str,
    old_spec: Option<&Value>,
    body: &mut Value,
    auto_ip: Option<Ipv4Addr>,
    dry_run: bool,
) -> Result<ServiceAllocTxn<S>, StatusError> {
    let mut txn = ServiceAllocTxn::new(state.store.clone());
    if let Some(ip) = auto_ip.filter(|_| !dry_run) {
        txn.created.push(ip_key(&ip.to_string()));
    }
    let mut r = Reserver {
        state,
        dry_run,
        txn,
    };
    r.txn.stale = reserve_all(&mut r, ns, name, old_spec, body, auto_ip).await?;
    Ok(r.txn)
}

async fn reserve_all<S: Store>(
    r: &mut Reserver<'_, S>,
    ns: &str,
    name: &str,
    old_spec: Option<&Value>,
    body: &mut Value,
    auto_ip: Option<Ipv4Addr>,
) -> Result<Vec<String>, StatusError> {
    let null = Value::Null;
    let old_spec = old_spec.unwrap_or(&null);
    drop_type_dependent_fields(&mut body["spec"]);
    let spec = &mut body["spec"];
    let mut stale = Vec::new();

    if let Some(alloc) = r.state.service_ip_allocator.clone() {
        let new_ips = spec_ips(spec);
        let old_ips = spec_ips(old_spec);
        let auto = auto_ip.map(|ip| ip.to_string());
        let listed = format!(
            "[{}]",
            new_ips
                .iter()
                .map(|ip| format!("\"{ip}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for ip in new_ips
            .iter()
            .filter(|ip| !old_ips.contains(*ip) && Some(*ip) != auto.as_ref())
        {
            let in_range = ip.parse::<Ipv4Addr>().ok().filter(|a| {
                let off = u32::from(*a).wrapping_sub(u32::from(alloc.base));
                off >= 1 && off <= alloc.size - 2
            });
            if in_range.is_none() {
                return Err(invalid(
                    name,
                    "spec.clusterIPs",
                    &listed,
                    &format!(
                        "failed to allocate IP {ip}: the provided IP ({ip}) is not in the valid range. The range of valid IPs is {}/{}",
                        alloc.base,
                        32 - alloc.size.trailing_zeros()
                    ),
                ));
            }
            if !r.reserve(ip_key(ip)).await? && !r.pre_reserved_for(&ip_key(ip), ns, name).await? {
                return Err(invalid(
                    name,
                    "spec.clusterIPs",
                    &listed,
                    &format!("failed to allocate IP {ip}: provided IP is already allocated"),
                ));
            }
        }
        stale.extend(old_ips.difference(&new_ips).map(|ip| ip_key(ip)));
    }

    let old_ports = spec_ports(old_spec);
    let mut taken: BTreeSet<i64> = BTreeSet::new();
    let svc_type = spec["type"].as_str().unwrap_or("ClusterIP").to_string();
    let allocate_node_ports = svc_type == "NodePort"
        || (svc_type == "LoadBalancer"
            && spec["allocateLoadBalancerNodePorts"].as_bool() != Some(false));

    let port_count = spec["ports"].as_array().map_or(0, Vec::len);
    for i in 0..port_count {
        let Some(np) = spec["ports"][i]["nodePort"].as_i64().filter(|&n| n != 0) else {
            continue;
        };
        if taken.contains(&np) || old_ports.contains(&np) {
            taken.insert(np);
            continue;
        }
        let field = format!("spec.ports[{i}].nodePort");
        if !(NODE_PORT_MIN..=NODE_PORT_MAX).contains(&np) {
            return Err(invalid(
                name,
                &field,
                &np.to_string(),
                &format!(
                    "provided port is not in the valid range. The range of valid ports is {NODE_PORT_MIN}-{NODE_PORT_MAX}"
                ),
            ));
        }
        if !r.reserve(port_key(np)).await? {
            return Err(invalid(
                name,
                &field,
                &np.to_string(),
                "provided port is already allocated",
            ));
        }
        taken.insert(np);
    }

    if let Some(hc) = spec["healthCheckNodePort"]
        .as_i64()
        .filter(|&n| n != 0 && !old_ports.contains(&n) && !taken.contains(&n))
    {
        let field = "spec.healthCheckNodePort";
        if !(NODE_PORT_MIN..=NODE_PORT_MAX).contains(&hc) {
            return Err(invalid(
                name,
                field,
                &hc.to_string(),
                &format!(
                    "provided port is not in the valid range. The range of valid ports is {NODE_PORT_MIN}-{NODE_PORT_MAX}"
                ),
            ));
        }
        if !r.reserve(port_key(hc)).await? {
            return Err(invalid(
                name,
                field,
                &hc.to_string(),
                "provided port is already allocated",
            ));
        }
    }

    if allocate_node_ports {
        // A Service port number exposed over several protocols shares one nodePort.
        let mut by_port: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
        for i in 0..port_count {
            if let (Some(p), Some(np)) = (
                spec["ports"][i]["port"].as_i64(),
                spec["ports"][i]["nodePort"].as_i64().filter(|&n| n != 0),
            ) {
                by_port.entry(p).or_insert(np);
            }
        }
        for i in 0..port_count {
            if spec["ports"][i]["nodePort"].as_i64().unwrap_or(0) != 0 {
                continue;
            }
            let svc_port = spec["ports"][i]["port"].as_i64().unwrap_or(0);
            let np = match by_port.get(&svc_port) {
                Some(&np) => np,
                None => {
                    let np = r.allocate_next_port(&taken).await?;
                    taken.insert(np);
                    by_port.insert(svc_port, np);
                    np
                }
            };
            spec["ports"][i]["nodePort"] = Value::from(np);
        }
    }

    if svc_type == "LoadBalancer"
        && spec["externalTrafficPolicy"].as_str() == Some("Local")
        && spec["healthCheckNodePort"].as_i64().unwrap_or(0) == 0
    {
        let hc = r.allocate_next_port(&taken).await?;
        spec["healthCheckNodePort"] = Value::from(hc);
    }

    let new_ports = spec_ports(spec);
    stale.extend(old_ports.difference(&new_ports).map(|p| port_key(*p)));
    Ok(stale)
}

/// Outcome of one `repair` pass.
#[derive(Debug, Default)]
pub(crate) struct RepairReport {
    pub seeded: usize,
    pub released: usize,
    pub conflicts: Vec<String>,
}

/// Sentinel key -> owner, for a sentinel reserved ahead of its Service (None: plain).
async fn list_sentinels<S: Store>(
    store: &S,
    prefix: &str,
) -> anyhow::Result<std::collections::BTreeMap<String, Option<String>>> {
    let resp = store.list(prefix, ListOptions::default()).await?;
    Ok(resp
        .items
        .into_iter()
        .map(|o| {
            let owner = serde_json::from_slice::<Value>(&o.value)
                .ok()
                .and_then(|v| v["owner"].as_str().map(str::to_string));
            (o.key, owner)
        })
        .collect())
}

/// Reconcile reservations with stored Services, as upstream's repair controllers do
/// (`ipallocator/controller/repair.go`, `portallocator/controller/repair.go`): reserve what
/// a Service holds but no sentinel records, release plain sentinels no Service holds, and
/// report a value held by several Services or reserved for another owner without changing
/// either. Sentinels reserved ahead of their Service (an `owner`) are never released.
///
/// Must run before the server accepts writes: a concurrent Service write holds a reservation
/// before its object is stored, which this pass would see as an orphan.
pub(crate) async fn repair<S: Store>(store: &S) -> anyhow::Result<RepairReport> {
    let services = store
        .list("/registry/services/", ListOptions::default())
        .await?;
    let mut ip_holders: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut port_holders: std::collections::BTreeMap<i64, Vec<String>> = Default::default();
    for obj in &services.items {
        let Some(id) = obj.key.strip_prefix("/registry/services/") else {
            continue;
        };
        let Ok(svc) = serde_json::from_slice::<Value>(&obj.value) else {
            continue;
        };
        for ip in spec_ips(&svc["spec"]) {
            ip_holders.entry(ip).or_default().push(id.to_string());
        }
        for port in spec_ports(&svc["spec"]) {
            port_holders.entry(port).or_default().push(id.to_string());
        }
    }

    let ip_sentinels = list_sentinels(store, SERVICE_IP_PREFIX).await?;
    let port_sentinels = list_sentinels(store, NODE_PORT_PREFIX).await?;
    let wanted = ip_holders
        .iter()
        .map(|(ip, h)| (ip_key(ip), format!("clusterIP {ip}"), h))
        .chain(
            port_holders
                .iter()
                .map(|(p, h)| (port_key(*p), format!("nodePort {p}"), h)),
        );

    let mut report = RepairReport::default();
    let mut wanted_keys = BTreeSet::new();
    for (key, what, holders) in wanted {
        wanted_keys.insert(key.clone());
        if holders.len() > 1 {
            report
                .conflicts
                .push(format!("{what} is held by several Services: {holders:?}"));
        }
        match ip_sentinels.get(&key).or_else(|| port_sentinels.get(&key)) {
            None => match store
                .put(&key, bytes::Bytes::from_static(SENTINEL), Some(0))
                .await
            {
                Ok(_) => report.seeded += 1,
                Err(StoreError::AlreadyExists { .. }) => {}
                Err(e) => return Err(anyhow::anyhow!("seed reservation {key}: {e}")),
            },
            Some(Some(owner)) if !holders.contains(owner) => report.conflicts.push(format!(
                "{what} is held by {holders:?} but reserved for {owner}"
            )),
            Some(_) => {}
        }
    }

    for (key, owner) in ip_sentinels.iter().chain(port_sentinels.iter()) {
        if owner.is_none() && !wanted_keys.contains(key) {
            delete_sentinel(store, key).await;
            report.released += 1;
        }
    }

    for c in &report.conflicts {
        tracing::warn!("service allocation repair: {c}");
    }
    tracing::info!(
        "service allocation repair: seeded {} reservations, released {} orphans, {} conflicts",
        report.seeded,
        report.released,
        report.conflicts.len()
    );
    Ok(report)
}

#[cfg(test)]
mod tests;
