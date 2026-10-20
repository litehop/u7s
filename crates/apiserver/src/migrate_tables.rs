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

/// Table for `tag`, by this policy:
/// - listed tag: its table, `approximate = false`;
/// - unlisted patch of a supported minor: that minor's table with
///   `approximate = true` (file lists are identical within a minor); the
///   caller must warn;
/// - unknown minor: refused unless `allow_unknown`, then the nearest lower
///   supported minor's table with `approximate = true` (the caller must warn);
///   refused when no lower minor is supported or the tag is unparseable.
///
/// `allow_unknown` only widens which Addon table approximates the source; it
/// never affects `strippable_finalizers`.
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
    let refuse = || LookupError::UnknownVersion {
        requested: tag.to_string(),
    };
    let want = k3s_minor(tag).ok_or_else(refuse)?;
    let newest_where = |pred: &dyn Fn(u32) -> bool| {
        SUPPORTED_TAGS
            .iter()
            .filter_map(|t| Some((*t, k3s_minor(t)?)))
            .filter(|(_, m)| pred(*m))
            .max_by_key(|(_, m)| *m)
            .map(|(t, _)| t)
    };
    if let Some(t) = newest_where(&|m| m == want) {
        return Ok(resolve(t, true));
    }
    if !allow_unknown {
        return Err(refuse());
    }
    newest_where(&|m| m < want)
        .map(|t| resolve(t, true))
        .ok_or_else(refuse)
}

fn k3s_minor(tag: &str) -> Option<u32> {
    tag.strip_prefix('v')?.split('.').nth(1)?.parse().ok()
}

pub struct FinalizerEntry {
    pub name: &'static str,
    /// Inclusive k3s minor range (`1.<n>`) whose behaviour was audited. Other
    /// minors strip nothing; extend only after auditing the new minor.
    pub min_minor: u32,
    pub max_minor: u32,
    /// Why the guarded resource does not exist on u7s.
    pub justification: &'static str,
}

const LB_CLEANUP: &str = "service.kubernetes.io/load-balancer-cleanup";

/// Exact finalizer names only; import strips them one named entry at a time,
/// never `finalizers: null`.
pub const FINALIZER_ALLOWLIST: &[FinalizerEntry] = &[
    FinalizerEntry {
        name: "wrangler.cattle.io/on-helm-chart-remove",
        min_minor: 35,
        max_minor: 37,
        justification: "released by k3s's embedded helm-controller to clean up the chart's Helm release; u7s has no helm-controller, so nothing would ever remove it",
    },
    FinalizerEntry {
        name: "wrangler.cattle.io/node",
        min_minor: 35,
        max_minor: 37,
        justification: "added by k3s's embedded wrangler node controller; u7s nodes are registered by a real kubelet and no controller removes it",
    },
    // Safe to strip ONLY while u7s's load-balancer provider (beep) does not
    // implement this finalizer. If beep or any other LB provider starts
    // setting or honouring it, stripping would orphan its load balancers:
    // re-audit this entry whenever an LB provider integrates.
    FinalizerEntry {
        name: LB_CLEANUP,
        min_minor: 35,
        max_minor: 37,
        justification: "upstream string, but on k3s the embedded ccm sets and removes it for servicelb; u7s runs no cloud-provider service controller, so the Service would never finish deleting (revisit if one is added)",
    },
];

/// Finalizers safe to strip from objects of k3s `tag`: empty outside the
/// audited minors, with or without `--allow-unknown-k3s-version`.
pub fn strippable_finalizers(tag: &str) -> Vec<&'static str> {
    let minor = k3s_minor(tag);
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
    fn unknown_minor_is_refused_by_default() {
        for v in ["v1.38.0+k3s1", "v1.34.1+k3s1", "garbage", ""] {
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
    fn unlisted_patch_of_known_minor_uses_that_minors_table_approximately() {
        for allow in [false, true] {
            let r = shipped_addons("v1.36.3+k3s1", allow).unwrap();
            assert_eq!(
                (r.table_tag, r.approximate),
                ("v1.36.5+k3s1", true),
                "file lists are identical within a minor; the caller must still warn"
            );
        }
    }

    #[test]
    fn override_for_unknown_minor_uses_nearest_lower_never_newest() {
        let r = shipped_addons("v1.38.0+k3s1", true).unwrap();
        assert_eq!((r.table_tag, r.approximate), ("v1.37.1+k3s1", true));
        assert!(
            shipped_addons("v1.34.1+k3s1", true).is_err(),
            "no lower supported minor: falling back to a newer table would classify with Addons the source never shipped"
        );
        assert!(shipped_addons("garbage", true).is_err());
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
            assert!(
                e.max_minor != u32::MAX,
                "{}: an unbounded range strips on unaudited k3s minors",
                e.name
            );
        }
    }

    #[test]
    fn strippable_finalizers_follow_the_audited_range() {
        for t in SUPPORTED_TAGS {
            assert_eq!(strippable_finalizers(t).len(), 3, "{t}");
        }
        assert_eq!(strippable_finalizers("v1.36.3+k3s1").len(), 3);
        assert!(strippable_finalizers("v1.20.0+k3s1").is_empty());
        assert!(strippable_finalizers("garbage").is_empty());
    }

    #[test]
    fn unaudited_minor_strips_nothing_with_or_without_the_override() {
        for tag in ["v1.38.0+k3s1", "v1.34.9+k3s1"] {
            assert!(
                strippable_finalizers(tag).is_empty(),
                "{tag}: unaudited minor must not lose finalizers (data loss)"
            );
            // The override only picks an approximate Addon table; the strip
            // decision is keyed on the source tag alone.
            if let Ok(r) = shipped_addons(tag, true) {
                assert!(r.approximate);
                assert!(strippable_finalizers(tag).is_empty(), "{tag}");
            }
        }
    }
}
