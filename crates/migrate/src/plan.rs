//! The editable migration plan and its human-readable report.
//!
//! The user edits `action` (include/exclude) per object and `action`
//! (keep/strip) per finalizer. Only finalizers on the per-version allowlist
//! may be set to strip.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use u7s_apiserver::migrate_tables::strippable_finalizers;

use crate::classify::{
    api_version, classify, finalizer_decisions, kind, name, namespace, Action, Context,
    FinalizerAction, FinalizerDecision,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub k3s_version: String,
    /// Tag whose shipped-manifest table classified the source.
    pub shipped_table: String,
    pub service_cidrs: Vec<String>,
    pub pod_cidrs: Vec<String>,
    pub kube_dns_cluster_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub api_version: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
    pub action: Action,
    pub rule: String,
    pub class: String,
    pub reason: String,
    #[serde(default)]
    pub warn: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finalizers: Vec<FinalizerDecision>,
}

impl Entry {
    pub fn object(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{} {ns}/{}", self.kind, self.name),
            None => format!("{} {}", self.kind, self.name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub source: Source,
    pub entries: Vec<Entry>,
}

impl Plan {
    /// Rejects an edited plan that strips a finalizer outside the allowlist
    /// for the source's k3s version: removing a finalizer whose controller we
    /// cannot vouch for can orphan external resources.
    pub fn validate(&self) -> Result<(), String> {
        let allowed = strippable_finalizers(&self.source.k3s_version);
        for e in &self.entries {
            for f in &e.finalizers {
                if f.action == FinalizerAction::Strip && !allowed.contains(&f.name.as_str()) {
                    return Err(format!(
                        "{}: finalizer {} is not on the strip allowlist for k3s {}",
                        e.object(),
                        f.name,
                        self.source.k3s_version
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The workload a k3s Addon file installs, for Addons that run something the
/// user may depend on (RBAC-only and RuntimeClass Addons do not).
fn runnable(addon: &str) -> Option<&'static str> {
    match addon {
        "coredns" => Some("coredns"),
        "traefik" => Some("traefik"),
        "local-storage" => Some("local-path-provisioner"),
        "aggregated-metrics-reader"
        | "auth-delegator"
        | "auth-reader"
        | "resource-reader"
        | "metrics-apiservice"
        | "metrics-server-deployment"
        | "metrics-server-service" => Some("metrics-server"),
        _ => None,
    }
}

/// Classifies every object. Also returns warnings that are not tied to one
/// object (distro components that are not migrated, annotation drift).
pub fn build(
    objs: &[Value],
    source: Source,
    shipped: &[String],
    strippable: Vec<&'static str>,
) -> (Plan, Vec<String>) {
    let ctx = Context::build(objs, shipped, strippable);
    let mut components = BTreeSet::new();
    let mut entries: Vec<Entry> = objs
        .iter()
        .map(|o| {
            let d = classify(o, &ctx);
            if let Some(c) = &d.component {
                components.insert(c.clone());
            }
            let finalizers = if d.action == Action::Include {
                finalizer_decisions(o, &ctx)
            } else {
                vec![]
            };
            Entry {
                api_version: api_version(o).to_string(),
                kind: kind(o).to_string(),
                namespace: namespace(o).map(str::to_string),
                name: name(o).to_string(),
                action: d.action,
                rule: d.rule.to_string(),
                class: d.class.to_string(),
                reason: d.reason,
                warn: d.warn,
                finalizers,
            }
        })
        .collect();
    entries.sort_by(|a, b| {
        (&a.kind, &a.namespace, &a.name, &a.api_version).cmp(&(
            &b.kind,
            &b.namespace,
            &b.name,
            &b.api_version,
        ))
    });

    let mut running: BTreeSet<&str> = components.iter().filter_map(|a| runnable(a)).collect();
    if entries.iter().any(|e| e.rule == "R3") {
        running.insert("servicelb");
    }
    if entries.iter().any(|e| e.class == "user-helmchart") {
        running.insert("helm-controller");
    }
    let mut warnings = vec![];
    for c in running {
        let replacement = if c == "coredns" {
            "u7s installs its own CoreDNS"
        } else {
            "u7s does not ship it; run it yourself if you need it"
        };
        warnings.push(format!(
            "distro component {c} is no longer built in and is not migrated; {replacement}"
        ));
    }
    for a in ctx.unreferenced_addons(objs) {
        warnings.push(format!(
            "Addon {a} exists but no object references it; the k3s annotation format may have changed, distro objects may be misclassified as user data"
        ));
    }
    (Plan { source, entries }, warnings)
}

fn word(e: &Entry) -> &'static str {
    match (e.warn, e.action) {
        (false, Action::Include) => "migrate",
        (false, Action::Exclude) => "skip",
        (true, Action::Include) => "warn:migrate",
        (true, Action::Exclude) => "warn:skip",
    }
}

pub fn render_report(plan: &Plan, warnings: &[String]) -> String {
    use std::fmt::Write;
    let s = &plan.source;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "source: k3s {} (shipped-manifest table {})",
        s.k3s_version, s.shipped_table
    );
    let _ = writeln!(out, "service CIDR: {}", s.service_cidrs.join(", "));
    let _ = writeln!(
        out,
        "pod CIDR (union of Node podCIDRs): {}",
        s.pod_cidrs.join(", ")
    );
    let _ = writeln!(
        out,
        "kube-dns ClusterIP: {}",
        s.kube_dns_cluster_ip.as_deref().unwrap_or("none")
    );
    let _ = writeln!(out, "\nobjects:");
    for e in &plan.entries {
        let _ = writeln!(
            out,
            "{:<3} {:<20} {:<13} {} -- {}",
            e.rule,
            e.class,
            word(e),
            e.object(),
            e.reason
        );
    }
    let _ = writeln!(out, "\nfinalizers:");
    for e in &plan.entries {
        for f in &e.finalizers {
            let (act, why) = match f.action {
                FinalizerAction::Strip => ("strip", "allowlisted distro finalizer"),
                FinalizerAction::Keep => ("keep", f.reason.as_str()),
            };
            let _ = writeln!(
                out,
                "fin {:<5} {:<5} {} {} -- {}",
                act,
                if f.warn { "warn" } else { "" },
                e.object(),
                f.name,
                why
            );
        }
    }
    let _ = writeln!(out, "\nwarnings:");
    for w in warnings {
        let _ = writeln!(out, "warn {w}");
    }
    let migrate = plan
        .entries
        .iter()
        .filter(|e| e.action == Action::Include)
        .count();
    let _ = writeln!(
        out,
        "\nsummary: {} objects, {} migrate, {} skip",
        plan.entries.len(),
        migrate,
        plan.entries.len() - migrate
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_a_plan_cannot_strip_a_finalizer_outside_the_allowlist() {
        let entry = |fin: &str| Entry {
            api_version: "v1".into(),
            kind: "Service".into(),
            namespace: Some("n".into()),
            name: "s".into(),
            action: Action::Include,
            rule: "R7".into(),
            class: "user".into(),
            reason: String::new(),
            warn: false,
            finalizers: vec![FinalizerDecision {
                name: fin.into(),
                action: FinalizerAction::Strip,
                reason: String::new(),
                warn: false,
            }],
        };
        let plan = |fin: &str| Plan {
            source: Source {
                k3s_version: "v1.36.5+k3s1".into(),
                shipped_table: "v1.36.5+k3s1".into(),
                service_cidrs: vec![],
                pod_cidrs: vec![],
                kube_dns_cluster_ip: None,
            },
            entries: vec![entry(fin)],
        };
        assert!(plan("wrangler.cattle.io/node").validate().is_ok());
        for bad in ["kubernetes.io/pvc-protection", "cert-manager.io/finalizer"] {
            assert!(
                plan(bad).validate().is_err(),
                "{bad}: stripping an unvetted finalizer can orphan data or external resources"
            );
        }
    }
}
