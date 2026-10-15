//! Per-k3s-version tables for `u7s migrate`: the Addons k3s ships itself, and
//! the finalizers that are safe to strip on import.
//!
//! Adding a k3s version: run `scripts/gen-k3s-shipped-manifests.sh <tag>`
//! (rewrites `data/k3s-shipped-manifests.json`), then append the tag to
//! `SUPPORTED_TAGS`. `every_supported_tag_has_a_manifest_entry` fails until
//! both are done.

use std::collections::BTreeMap;
use std::sync::OnceLock;

const SHIPPED_JSON: &str = include_str!("../data/k3s-shipped-manifests.json");

/// Current k3s stable-channel releases for 1.35, 1.36 and 1.37.
pub const SUPPORTED_TAGS: &[&str] = &["v1.35.9+k3s1", "v1.36.5+k3s1", "v1.37.1+k3s1"];

fn shipped() -> &'static BTreeMap<String, Vec<String>> {
    static T: OnceLock<BTreeMap<String, Vec<String>>> = OnceLock::new();
    T.get_or_init(|| {
        serde_json::from_str(SHIPPED_JSON).expect("k3s-shipped-manifests.json is valid")
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum LookupError {
    /// The source's k3s version has no table. Its Addon list could differ, so
    /// classifying by a neighbouring version risks migrating distro objects as
    /// user objects (or skipping user objects as distro).
    UnknownVersion { requested: String },
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let LookupError::UnknownVersion { requested } = self;
        write!(
            f,
            "k3s version {requested} has no shipped-manifest table (supported: {}); \
             pass --allow-unknown-k3s-version to classify with the closest supported version",
            SUPPORTED_TAGS.join(", ")
        )
    }
}

impl std::error::Error for LookupError {}

#[derive(Debug, PartialEq, Eq)]
pub struct ShippedAddons {
    /// The tag whose table was used.
    pub table_tag: &'static str,
    /// True when `table_tag` is not the requested version; the caller must
    /// surface a warning.
    pub approximate: bool,
    pub addons: &'static [String],
}

/// Addon names shipped by `tag`. Unknown versions are refused unless
/// `allow_unknown` is set, in which case the same-minor table (else the newest
/// supported one) is returned with `approximate = true`.
pub fn shipped_addons(tag: &str, allow_unknown: bool) -> Result<ShippedAddons, LookupError> {
    let table = shipped();
    let resolve = |t: &'static str, approximate| ShippedAddons {
        table_tag: t,
        approximate,
        addons: &table[t],
    };
    if let Some(t) = SUPPORTED_TAGS.iter().find(|t| **t == tag) {
        return Ok(resolve(t, false));
    }
    if !allow_unknown {
        return Err(LookupError::UnknownVersion {
            requested: tag.to_string(),
        });
    }
    let minor = |t: &str| t.split('.').take(2).collect::<Vec<_>>().join(".");
    let closest = SUPPORTED_TAGS
        .iter()
        .find(|t| minor(t) == minor(tag))
        .unwrap_or_else(|| SUPPORTED_TAGS.last().expect("at least one supported tag"));
    Ok(resolve(closest, true))
}

pub struct FinalizerEntry {
    pub name: &'static str,
    /// Inclusive k3s minor range (`1.<n>`) the entry applies to.
    pub min_minor: u32,
    pub max_minor: u32,
    /// Why the guarded resource does not exist on u7s.
    pub justification: &'static str,
}

/// Exact finalizer names only; import strips them one named entry at a time,
/// never `finalizers: null`.
pub const FINALIZER_ALLOWLIST: &[FinalizerEntry] = &[
    FinalizerEntry {
        name: "wrangler.cattle.io/on-helm-chart-remove",
        min_minor: 35,
        max_minor: u32::MAX,
        justification: "released by k3s's embedded helm-controller to clean up the chart's Helm release; u7s has no helm-controller, so nothing would ever remove it",
    },
    FinalizerEntry {
        name: "wrangler.cattle.io/node",
        min_minor: 35,
        max_minor: u32::MAX,
        justification: "added by k3s's embedded wrangler node controller; u7s nodes are registered by a real kubelet and no controller removes it",
    },
    FinalizerEntry {
        name: "service.kubernetes.io/load-balancer-cleanup",
        min_minor: 35,
        max_minor: u32::MAX,
        justification: "upstream string, but on k3s the embedded ccm sets and removes it for servicelb; u7s runs no cloud-provider service controller, so the Service would never finish deleting (revisit if one is added)",
    },
];

/// Finalizers safe to strip from objects of k3s `tag`.
pub fn strippable_finalizers(tag: &str) -> Vec<&'static str> {
    let minor: Option<u32> = tag.split('.').nth(1).and_then(|m| m.parse().ok());
    FINALIZER_ALLOWLIST
        .iter()
        .filter(|e| minor.is_some_and(|m| (e.min_minor..=e.max_minor).contains(&m)))
        .map(|e| e.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_tag_has_a_manifest_entry() {
        for t in SUPPORTED_TAGS {
            assert!(
                shipped().contains_key(*t),
                "{t} is supported but missing from k3s-shipped-manifests.json; re-run scripts/gen-k3s-shipped-manifests.sh {t}"
            );
        }
        for t in shipped().keys() {
            assert!(
                SUPPORTED_TAGS.contains(&t.as_str()),
                "{t} has a table but is not in SUPPORTED_TAGS, so lookups would refuse it"
            );
        }
    }

    #[test]
    fn known_tag_returns_its_list() {
        let r = shipped_addons("v1.36.5+k3s1", false).unwrap();
        assert!(!r.approximate);
        for a in [
            "coredns",
            "local-storage",
            "traefik",
            "metrics-server-deployment",
        ] {
            assert!(
                r.addons.iter().any(|x| x == a),
                "shipped Addon {a} missing; it would be migrated as a user object"
            );
        }
        assert!(!r.addons.iter().any(|x| x == "my-app"));
    }

    #[test]
    fn tables_differ_across_versions() {
        let new = shipped_addons("v1.37.1+k3s1", false).unwrap();
        let old = shipped_addons("v1.36.5+k3s1", false).unwrap();
        assert!(new.addons.iter().any(|x| x == "gateway-api-crd"));
        assert!(!old.addons.iter().any(|x| x == "gateway-api-crd"));
    }

    #[test]
    fn unknown_or_newer_version_is_refused_by_default() {
        for v in ["v1.36.3+k3s1", "v1.38.0+k3s1", "v1.34.1+k3s1", ""] {
            assert_eq!(
                shipped_addons(v, false),
                Err(LookupError::UnknownVersion {
                    requested: v.to_string()
                }),
                "{v}: a guessed table could misclassify user data as distro"
            );
        }
    }

    #[test]
    fn override_uses_same_minor_else_newest_and_flags_approximate() {
        let r = shipped_addons("v1.36.3+k3s1", true).unwrap();
        assert_eq!((r.table_tag, r.approximate), ("v1.36.5+k3s1", true));
        let r = shipped_addons("v1.38.0+k3s1", true).unwrap();
        assert_eq!((r.table_tag, r.approximate), ("v1.37.1+k3s1", true));
    }

    #[test]
    fn allowlist_is_exact_names_without_upstream_protection_finalizers() {
        let names: Vec<_> = FINALIZER_ALLOWLIST.iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            [
                "wrangler.cattle.io/on-helm-chart-remove",
                "wrangler.cattle.io/node",
                "service.kubernetes.io/load-balancer-cleanup"
            ]
        );
        for n in &names {
            assert!(
                !n.contains('*') && !n.ends_with('/'),
                "{n}: wildcards would strip unknown third-party finalizers"
            );
        }
        for protected in [
            "kubernetes.io/pvc-protection",
            "kubernetes.io/pv-protection",
            "foregroundDeletion",
            "orphan",
            "networking.k8s.io/service-cidr-finalizer",
        ] {
            assert!(
                !names.contains(&protected),
                "{protected} guards data or deletion semantics that exist on u7s"
            );
        }
        for e in FINALIZER_ALLOWLIST {
            assert!(
                !e.justification.is_empty(),
                "{} needs a justification",
                e.name
            );
        }
    }

    #[test]
    fn strippable_finalizers_follow_the_version_range() {
        assert_eq!(strippable_finalizers("v1.36.5+k3s1").len(), 3);
        assert!(strippable_finalizers("v1.20.0+k3s1").is_empty());
        assert!(strippable_finalizers("garbage").is_empty());
    }
}
