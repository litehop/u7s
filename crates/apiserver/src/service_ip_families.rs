//! Resolution and validation of a Service's `ipFamilyPolicy`, `ipFamilies` and
//! `clusterIPs`, mirroring upstream's `Allocators.initIPFamilyFields`
//! (`pkg/registry/core/service/storage/alloc.go`), `ValidateServiceClusterIPsRelatedFields`
//! and the upgrade/downgrade immutability rules (`pkg/apis/core/validation/validation.go`,
//! release-1.37).
//!
//! Everything here is a pure function over the Service `spec`; the allocation of the
//! addresses themselves lives in `handlers::resource::maybe_allocate_cluster_ip`.

use std::net::IpAddr;

use serde_json::Value;

use crate::state::IpFamily;
use crate::status::{Status, StatusError};

const NONE: &str = "None";
const SINGLE: &str = "SingleStack";
const PREFER: &str = "PreferDualStack";
const REQUIRE: &str = "RequireDualStack";

#[derive(Clone)]
struct Fields {
    svc_type: String,
    cluster_ip: String,
    cluster_ips: Vec<String>,
    families: Vec<String>,
    policy: Option<String>,
    selectorless: bool,
}

impl Fields {
    fn read(spec: &Value) -> Self {
        let strs = |v: &Value| -> Vec<String> {
            v.as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        };
        let mut f = Fields {
            svc_type: spec["type"].as_str().unwrap_or("ClusterIP").to_string(),
            cluster_ip: spec["clusterIP"].as_str().unwrap_or("").to_string(),
            cluster_ips: strs(&spec["clusterIPs"]),
            families: strs(&spec["ipFamilies"]),
            policy: spec["ipFamilyPolicy"].as_str().map(str::to_string),
            selectorless: spec["selector"].as_object().is_none_or(|s| s.is_empty()),
        };
        if f.cluster_ips.is_empty() && !f.cluster_ip.is_empty() {
            f.cluster_ips = vec![f.cluster_ip.clone()];
        }
        if f.cluster_ip.is_empty() && !f.cluster_ips.is_empty() {
            f.cluster_ip = f.cluster_ips[0].clone();
        }
        f
    }

    fn write(&self, spec: &mut Value) {
        if let Some(p) = &self.policy {
            spec["ipFamilyPolicy"] = Value::from(p.clone());
        }
        if !self.families.is_empty() {
            spec["ipFamilies"] = Value::from(self.families.clone());
        }
        if !self.cluster_ips.is_empty() {
            spec["clusterIPs"] = Value::from(self.cluster_ips.clone());
            spec["clusterIP"] = Value::from(self.cluster_ip.clone());
        }
    }

    fn needs_cluster_ip(&self) -> bool {
        matches!(
            self.svc_type.as_str(),
            "ClusterIP" | "NodePort" | "LoadBalancer"
        )
    }

    fn headless(&self) -> bool {
        self.cluster_ips.len() == 1 && self.cluster_ips[0] == NONE
    }
}

fn go_strings(ty: &str, items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("{s:?}")).collect();
    format!("[]{ty}{{{}}}", quoted.join(", "))
}

fn invalid_list(name: &str, errs: Vec<String>) -> StatusError {
    let body = if errs.len() == 1 {
        errs.into_iter().next().unwrap_or_default()
    } else {
        format!("[{}]", errs.join(", "))
    };
    Status::unprocessable_entity(format!("Service \"{name}\" is invalid: {body}"))
}

fn parse_family(ip: &str) -> Option<IpFamily> {
    ip.parse::<IpAddr>().ok().map(|a| IpFamily::of(&a))
}

/// `ValidateServiceClusterIPsRelatedFields`: standalone checks on the three fields.
fn validate_related_fields(f: &Fields, old: Option<&Fields>, errs: &mut Vec<String>) {
    let ips_val = go_strings("string", &f.cluster_ips);
    if !f.cluster_ip.is_empty() && f.cluster_ips[0] != f.cluster_ip {
        errs.push(format!(
            "spec.clusterIPs: Invalid value: {ips_val}: first value must match `clusterIP`"
        ));
    }

    let mut seen: Vec<&str> = Vec::new();
    for (i, fam) in f.families.iter().enumerate() {
        if IpFamily::parse(fam).is_none() {
            errs.push(format!(
                "spec.ipFamilies[{i}]: Unsupported value: {fam:?}: supported values: \"IPv4\", \"IPv6\""
            ));
        }
        if seen.contains(&fam.as_str()) {
            errs.push(format!("spec.ipFamilies[{i}]: Duplicate value: {fam:?}"));
        }
        seen.push(fam);
    }

    if let Some(p) = &f.policy {
        if ![SINGLE, PREFER, REQUIRE].contains(&p.as_str()) {
            errs.push(format!(
                "spec.ipFamilyPolicy: Unsupported value: {p:?}: supported values: \"PreferDualStack\", \"RequireDualStack\", \"SingleStack\""
            ));
        }
    }

    let existing: &[String] = old.map_or(&[], |o| &o.cluster_ips);
    let mut has_invalid_ips = false;
    for (i, ip) in f.cluster_ips.iter().enumerate() {
        if i == 0 && ip == NONE {
            if f.cluster_ips.len() > 1 {
                has_invalid_ips = true;
                errs.push(format!(
                    "spec.clusterIPs: Invalid value: {ips_val}: 'None' must be the first and only value"
                ));
            }
            continue;
        }
        if existing.contains(ip) {
            continue;
        }
        match ip.parse::<IpAddr>() {
            Err(_) => {
                has_invalid_ips = true;
                errs.push(format!(
                    "spec.clusterIPs[{i}]: Invalid value: {ip:?}: must be a valid IP address, (e.g. 10.9.8.7 or 2001:db8::ffff)"
                ));
            }
            Ok(parsed) if parsed.to_string() != *ip => {
                has_invalid_ips = true;
                errs.push(format!(
                    "spec.clusterIPs[{i}]: Invalid value: {ip:?}: must be in canonical form (\"{parsed}\")"
                ));
            }
            Ok(_) => {}
        }
    }

    if f.cluster_ips.len() > 2 {
        errs.push(format!(
            "spec.clusterIPs: Invalid value: {ips_val}: may only hold up to 2 values"
        ));
    }
    if has_invalid_ips {
        return;
    }

    if f.cluster_ips.len() > 1
        && (f.cluster_ips.len() != 2
            || parse_family(&f.cluster_ips[0]) == parse_family(&f.cluster_ips[1]))
    {
        errs.push(format!(
            "spec.clusterIPs: Invalid value: {ips_val}: may specify no more than one IP for each IP family"
        ));
    }

    if !f.headless() && !f.cluster_ips.is_empty() && !f.families.is_empty() {
        for (i, ip) in f.cluster_ips.iter().enumerate() {
            let Some(fam) = f.families.get(i) else { break };
            let v6 = parse_family(ip) == Some(IpFamily::V6);
            if fam == "IPv4" && v6 {
                errs.push(format!(
                    "spec.clusterIPs[{i}]: Invalid value: {ip:?}: expected an IPv4 value as indicated by `ipFamilies[{i}]`"
                ));
            }
            if fam == "IPv6" && !v6 {
                errs.push(format!(
                    "spec.clusterIPs[{i}]: Invalid value: {ip:?}: expected an IPv6 value as indicated by `ipFamilies[{i}]`"
                ));
            }
        }
    }
}

/// A PreferDualStack Service whose families, clusterIPs and type did not change is left
/// alone, so a cluster turning dual-stack or single-stack never rewrites existing Services.
fn prefer_dual_unchanged(f: &Fields, old: Option<&Fields>) -> bool {
    let Some(old) = old else { return false };
    f.policy.as_deref() == Some(PREFER)
        && old.policy.as_deref().is_none_or(|p| p == PREFER)
        && f.svc_type == old.svc_type
        && f.needs_cluster_ip()
        && f.cluster_ips == old.cluster_ips
        && f.families == old.families
}

fn alt(family: &str) -> &'static str {
    if family == "IPv4" {
        "IPv6"
    } else {
        "IPv4"
    }
}

/// Resolve `ipFamilyPolicy` and `ipFamilies` (and the family-implied `clusterIPs` shape) of
/// a Service spec against the families the cluster is configured for (primary first), as
/// upstream's `initIPFamilyFields` does on create (`old` = `None`) and update. Fills in
/// nothing about the addresses themselves: empty `clusterIPs` slots are for the allocator.
/// ExternalName Services are left untouched.
pub(crate) fn init_ip_family_fields(
    configured: &[IpFamily],
    old: Option<&Value>,
    spec: &mut Value,
    name: &str,
) -> Result<(), StatusError> {
    let mut f = Fields::read(spec);
    if f.svc_type == "ExternalName" {
        return Ok(());
    }
    let old = old.map(Fields::read);

    // PrepareForUpdate's patchAllocatedValues: an update that omits the allocated
    // addresses keeps them.
    if let Some(o) = &old {
        if o.needs_cluster_ip() && f.needs_cluster_ip() {
            if f.cluster_ip.is_empty() {
                f.cluster_ip = o.cluster_ip.clone();
            }
            if f.cluster_ips.is_empty() && o.cluster_ips.contains(&f.cluster_ip) {
                f.cluster_ips = o.cluster_ips.clone();
            }
        }
    }

    if prefer_dual_unchanged(&f, old.as_ref()) {
        f.write(spec);
        return Ok(());
    }

    if f.policy.is_none() {
        f.policy = Some(match old.as_ref().and_then(|o| o.policy.clone()) {
            Some(p) => p,
            None if f.cluster_ip == NONE && f.selectorless => REQUIRE.to_string(),
            None => SINGLE.to_string(),
        });
    }
    let policy = f.policy.clone().unwrap_or_default();
    let policy_val = format!("{policy:?}");

    let mut errs = Vec::new();
    validate_related_fields(&f, old.as_ref(), &mut errs);
    if !errs.is_empty() {
        return Err(invalid_list(name, errs));
    }

    let configured_names: Vec<&str> = configured.iter().map(|c| c.as_str()).collect();
    let default_family = configured_names.first().copied().unwrap_or("IPv4");

    if let Some(o) = &old {
        if policy == SINGLE {
            if f.cluster_ips == o.cluster_ips && f.cluster_ips.len() > 1 {
                f.cluster_ips.truncate(1);
            }
            if f.families == o.families && f.families.len() > 1 {
                f.families.truncate(1);
            }
        } else {
            if !f.cluster_ips.is_empty() && f.cluster_ips.len() < o.cluster_ips.len() {
                errs.push(format!(
                    "spec.ipFamilyPolicy: Invalid value: {policy_val}: must be 'SingleStack' to release the secondary cluster IP"
                ));
            }
            if !f.families.is_empty() && f.families.len() < o.families.len() {
                errs.push(format!(
                    "spec.ipFamilyPolicy: Invalid value: {policy_val}: must be 'SingleStack' to release the secondary IP family"
                ));
            }
        }
    }

    if policy == SINGLE {
        if f.cluster_ips.len() == 2 {
            errs.push(format!(
                "spec.ipFamilyPolicy: Invalid value: {policy_val}: must be 'RequireDualStack' or 'PreferDualStack' when multiple cluster IPs are specified"
            ));
        }
        if f.families.len() == 2 {
            errs.push(format!(
                "spec.ipFamilyPolicy: Invalid value: {policy_val}: must be 'RequireDualStack' or 'PreferDualStack' when multiple IP families are specified"
            ));
        }
    }

    for i in 0..f.cluster_ips.len() {
        if f.cluster_ips[i] == NONE {
            break;
        }
        let Some(fam) = parse_family(&f.cluster_ips[i]) else {
            continue;
        };
        if i >= f.families.len() {
            if configured.contains(&fam) {
                f.families.push(fam.as_str().to_string());
            } else {
                errs.push(format!(
                    "spec.clusterIPs[{i}]: Invalid value: {}: {} is not configured on this cluster",
                    go_strings("string", &f.cluster_ips),
                    fam.as_str()
                ));
            }
        }
    }
    if !errs.is_empty() {
        return Err(invalid_list(name, errs));
    }

    // Headless and selectorless: explicitly allowed combinations that would otherwise be
    // errors (an endpoint-less Service may span both families on a single-stack cluster).
    if f.cluster_ip == NONE && f.selectorless {
        if f.families.is_empty() {
            f.families.push(default_family.to_string());
        }
        if f.families.len() < 2 && policy != SINGLE {
            let other = alt(&f.families[0]);
            f.families.push(other.to_string());
        }
        f.write(spec);
        return Ok(());
    }

    if policy == REQUIRE && configured.len() < 2 {
        errs.push(format!(
            "spec.ipFamilyPolicy: Invalid value: {policy_val}: this cluster is not configured for dual-stack services"
        ));
    }
    for (i, fam) in f.families.iter().enumerate() {
        if !configured_names.contains(&fam.as_str()) {
            errs.push(format!(
                "spec.ipFamilies[{i}]: Invalid value: {fam:?}: not configured on this cluster"
            ));
        }
    }
    if !errs.is_empty() {
        return Err(invalid_list(name, errs));
    }

    if f.families.is_empty() {
        f.families.push(default_family.to_string());
    }
    if policy != SINGLE && f.families.len() == 1 && configured.len() == 2 {
        let other = alt(&f.families[0]);
        f.families.push(other.to_string());
    }

    f.write(spec);
    Ok(())
}

/// Upgrade/downgrade immutability (`validateUpgradeDowngradeClusterIPs` and
/// `validateUpgradeDowngradeIPFamilies`): the primary clusterIP and ipFamily never change,
/// the secondary may be added, and may only be dropped under `SingleStack`.
pub(crate) fn validate_ip_fields_update(
    old: &Value,
    new: &Value,
    name: &str,
) -> Result<(), StatusError> {
    let (o, n) = (Fields::read(old), Fields::read(new));
    if o.svc_type == "ExternalName" || n.svc_type == "ExternalName" {
        return Ok(());
    }
    let mut errs = Vec::new();
    let single = n.policy.as_deref() == Some(SINGLE);
    let policy_val = n
        .policy
        .as_ref()
        .map_or("null".to_string(), |p| format!("{p:?}"));
    let new_ips = go_strings("string", &n.cluster_ips);

    if !(o.headless() && n.headless()) {
        if o.cluster_ips.len() == n.cluster_ips.len() {
            for i in 0..o.cluster_ips.len() {
                if o.cluster_ips[i] != n.cluster_ips[i] {
                    errs.push(format!(
                        "spec.clusterIPs[{i}]: Invalid value: {new_ips}: may not change once set"
                    ));
                }
            }
        } else if o.cluster_ips.len() > n.cluster_ips.len() {
            if n.cluster_ips.is_empty() {
                errs.push(format!(
                    "spec.clusterIPs[0]: Invalid value: {new_ips}: primary clusterIP can not be unset"
                ));
            } else if n.cluster_ips[0] != o.cluster_ips[0] {
                errs.push(format!(
                    "spec.clusterIPs[0]: Invalid value: {new_ips}: may not change once set"
                ));
            }
            if n.cluster_ips.len() == 1 && !single {
                errs.push(format!(
                    "spec.ipFamilyPolicy: Invalid value: {policy_val}: must be set to 'SingleStack' when releasing the secondary clusterIP"
                ));
            }
        } else if !o.cluster_ips.is_empty() && n.cluster_ips[0] != o.cluster_ips[0] {
            errs.push(format!(
                "spec.clusterIPs[0]: Invalid value: {new_ips}: may not change once set"
            ));
        }
    }

    if o.headless() == n.headless() && !n.headless() {
        let new_fams = go_strings("core.IPFamily", &n.families);
        if o.families.len() == n.families.len() {
            if o.families != n.families {
                errs.push(format!(
                    "spec.ipFamilies[0]: Invalid value: {new_fams}: may not change once set"
                ));
            }
        } else if o.families.len() > n.families.len() {
            if n.cluster_ips.is_empty() {
                errs.push(format!(
                    "spec.ipFamilies[0]: Invalid value: {new_fams}: primary ipFamily can not be unset"
                ));
            }
            if !n.families.is_empty() && n.families[0] != o.families[0] {
                errs.push(format!(
                    "spec.ipFamilies[0]: Invalid value: {new_ips}: may not change once set"
                ));
            }
            if n.families.len() == 1 && !single {
                errs.push(format!(
                    "spec.ipFamilyPolicy: Invalid value: {policy_val}: must be set to 'SingleStack' when releasing the secondary ipFamily"
                ));
            }
        } else if !o.families.is_empty() && !n.families.is_empty() && n.families[0] != o.families[0]
        {
            errs.push(format!(
                "spec.ipFamilies[0]: Invalid value: {new_ips}: may not change once set"
            ));
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(invalid_list(name, errs))
    }
}

/// `(index, family)` of each `clusterIPs` slot that still needs an address: none for
/// ExternalName and headless Services.
pub(crate) fn unallocated_slots(spec: &Value) -> Vec<(usize, IpFamily)> {
    let f = Fields::read(spec);
    if !f.needs_cluster_ip() || f.headless() {
        return Vec::new();
    }
    f.families
        .iter()
        .enumerate()
        .filter(|(i, _)| f.cluster_ips.get(*i).is_none_or(String::is_empty))
        .filter_map(|(i, fam)| IpFamily::parse(fam).map(|fam| (i, fam)))
        .collect()
}

/// Store `ip` as the `idx`-th clusterIP (and `clusterIP` when it is the primary).
pub(crate) fn set_cluster_ip(spec: &mut Value, idx: usize, ip: &str) {
    let mut ips: Vec<Value> = spec["clusterIPs"].as_array().cloned().unwrap_or_default();
    while ips.len() <= idx {
        ips.push(Value::from(""));
    }
    ips[idx] = Value::from(ip);
    spec["clusterIPs"] = Value::Array(ips);
    if idx == 0 {
        spec["clusterIP"] = Value::from(ip);
    }
}

#[cfg(test)]
mod tests;
