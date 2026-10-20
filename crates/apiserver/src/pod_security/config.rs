//! PodSecurity plugin configuration: cluster-wide default policy and exemptions, loaded from
//! an `AdmissionConfiguration` file like upstream's `--admission-control-config-file`.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use super::{go_quote, parse_level, parse_version, Level, LevelVersion, Policy, Version};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exemptions {
    pub usernames: Vec<String>,
    pub runtime_classes: Vec<String>,
    pub namespaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub defaults: Policy,
    pub exemptions: Exemptions,
}

impl Default for Config {
    /// Upstream's defaults: every mode privileged/latest, nothing exempt.
    fn default() -> Self {
        Config {
            defaults: Policy::PRIVILEGED,
            exemptions: Exemptions::default(),
        }
    }
}

impl Config {
    pub fn exempt_namespace(&self, namespace: &str) -> bool {
        !namespace.is_empty() && self.exemptions.namespaces.iter().any(|n| n == namespace)
    }

    pub fn exempt_user(&self, username: &str) -> bool {
        !username.is_empty() && self.exemptions.usernames.iter().any(|u| u == username)
    }

    pub fn exempt_runtime_class(&self, runtime_class: Option<&str>) -> bool {
        runtime_class.is_some_and(|rc| {
            !rc.is_empty() && self.exemptions.runtime_classes.iter().any(|r| r == rc)
        })
    }

    /// Labelling an exempt namespace with a non-trivial policy is a no-op worth telling the
    /// user about: the labels are inert there.
    pub(super) fn exempt_namespace_warning(
        &self,
        namespace: &str,
        policy: &Policy,
        labels: &BTreeMap<String, String>,
    ) -> Option<String> {
        if policy.fully_privileged() || policy.equivalent(&self.defaults) {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        let mut mode = |name: &str, lv: &LevelVersion, level_label: &str, version_label: &str| {
            let set = labels.contains_key(level_label) || labels.contains_key(version_label);
            if lv.level != Level::Privileged && set {
                parts.push(format!("{name}={lv}"));
            }
        };
        mode(
            "enforce",
            &policy.enforce,
            super::ENFORCE_LEVEL_LABEL,
            super::ENFORCE_VERSION_LABEL,
        );
        mode(
            "audit",
            &policy.audit,
            super::AUDIT_LEVEL_LABEL,
            super::AUDIT_VERSION_LABEL,
        );
        mode(
            "warn",
            &policy.warn,
            super::WARN_LEVEL_LABEL,
            super::WARN_VERSION_LABEL,
        );
        Some(format!(
            "namespace {} is exempt from Pod Security, and the policy ({}) will be ignored",
            go_quote(namespace),
            parts.join(", ")
        ))
    }
}

/// Load the PodSecurity plugin configuration from an `AdmissionConfiguration` file.
/// An unreadable or invalid file is a startup error, as upstream.
pub fn load_config_file(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading admission control config {}: {e}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    parse_admission_configuration(&text, base)
        .map_err(|e| format!("admission control config {}: {e}", path.display()))
}

#[cfg(test)]
pub(super) fn parse_admission_configuration_for_test(text: &str) -> Result<Config, String> {
    parse_admission_configuration(text, Path::new("."))
}

fn parse_yaml(text: &str) -> Result<Value, String> {
    crate::handlers::json_patch::ssa_body_to_json(text.as_bytes()).map_err(|e| e.1.message)
}

fn parse_admission_configuration(text: &str, base: &Path) -> Result<Config, String> {
    let doc = parse_yaml(text)?;
    if doc["kind"].as_str() != Some("AdmissionConfiguration") {
        return Err(format!(
            "kind must be AdmissionConfiguration, got {}",
            go_quote(doc["kind"].as_str().unwrap_or(""))
        ));
    }
    let mut config = Config::default();
    for plugin in doc["plugins"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let name = plugin["name"].as_str().unwrap_or("");
        if name != "PodSecurity" {
            return Err(format!(
                "plugin {} cannot be configured: only PodSecurity is configurable",
                go_quote(name)
            ));
        }
        let configuration = if let Some(path) = plugin["path"].as_str().filter(|p| !p.is_empty()) {
            let full = base.join(path);
            let text = std::fs::read_to_string(&full)
                .map_err(|e| format!("reading plugin config {}: {e}", full.display()))?;
            parse_yaml(&text)?
        } else {
            plugin["configuration"].clone()
        };
        if !configuration.is_null() {
            config = parse_pod_security_configuration(&configuration)?;
        }
    }
    Ok(config)
}

fn string_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn dns_label(s: &str) -> bool {
    crate::handlers::certificates::is_dns1123_label(s)
}

fn dns_subdomain(s: &str) -> bool {
    crate::handlers::certificates::is_dns1123_subdomain(s)
}

fn parse_pod_security_configuration(cfg: &Value) -> Result<Config, String> {
    if cfg["kind"].as_str() != Some("PodSecurityConfiguration") {
        return Err(format!(
            "PodSecurity configuration kind must be PodSecurityConfiguration, got {}",
            go_quote(cfg["kind"].as_str().unwrap_or(""))
        ));
    }
    let mut errs: Vec<String> = Vec::new();

    let defaults = &cfg["defaults"];
    let mut level = |key: &str| -> Level {
        let raw = defaults[key].as_str().unwrap_or("");
        if raw.is_empty() {
            return Level::Privileged;
        }
        parse_level(raw).unwrap_or_else(|detail| {
            errs.push(format!(
                "defaults.{key}: Invalid value: {}: {detail}",
                go_quote(raw)
            ));
            Level::Privileged
        })
    };
    let enforce_level = level("enforce");
    let audit_level = level("audit");
    let warn_level = level("warn");
    let mut version = |key: &str| -> Version {
        let raw = defaults[key].as_str().unwrap_or("");
        if raw.is_empty() {
            return Version::Latest;
        }
        parse_version(raw).unwrap_or_else(|detail| {
            errs.push(format!(
                "defaults.{key}: Invalid value: {}: {detail}",
                go_quote(raw)
            ));
            Version::Latest
        })
    };
    let enforce_version = version("enforce-version");
    let audit_version = version("audit-version");
    let warn_version = version("warn-version");

    let exemptions = &cfg["exemptions"];
    let mut list = |key: &str, valid: &dyn Fn(&str) -> bool, rule: &str| -> Vec<String> {
        let items = string_list(&exemptions[key]);
        let mut seen = std::collections::HashSet::new();
        for (i, item) in items.iter().enumerate() {
            if !valid(item) {
                errs.push(format!(
                    "exemptions.{key}[{i}]: Invalid value: {}: {rule}",
                    go_quote(item)
                ));
            } else if !seen.insert(item.clone()) {
                errs.push(format!(
                    "exemptions.{key}[{i}]: Duplicate value: {}",
                    go_quote(item)
                ));
            }
        }
        items
    };
    let namespaces = list("namespaces", &dns_label, "must be a valid DNS label");
    let runtime_classes = list(
        "runtimeClasses",
        &dns_subdomain,
        "must be a valid DNS subdomain",
    );
    let usernames = list(
        "usernames",
        &|u| !u.is_empty(),
        "username must not be empty",
    );

    if !errs.is_empty() {
        return Err(errs.join("; "));
    }
    Ok(Config {
        defaults: Policy {
            enforce: LevelVersion {
                level: enforce_level,
                version: enforce_version,
            },
            audit: LevelVersion {
                level: audit_level,
                version: audit_version,
            },
            warn: LevelVersion {
                level: warn_level,
                version: warn_version,
            },
        },
        exemptions: Exemptions {
            usernames,
            runtime_classes,
            namespaces,
        },
    })
}
