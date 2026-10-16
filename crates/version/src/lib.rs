//! Build identity shared by every u7s binary: `--version` output and the
//! apiserver's `/version` document come from the same values.

/// The Kubernetes release u7s claims conformance with and ships kubelet/KCM
/// for. `scripts/test-k8s-version-pins-logic.sh` keeps this equal to the
/// tarball's `K8S_VERSION`.
pub const K8S_VERSION: &str = "1.37.1";

/// Stamped by the release build via `U7S_RELEASE`; dev builds are marked so
/// they are never mistaken for a release.
pub const RELEASE: &str = match option_env!("U7S_RELEASE") {
    Some(r) => r,
    None => "dev",
};

pub const GIT_COMMIT: &str = match option_env!("U7S_GIT_COMMIT") {
    Some(c) => c,
    None => "unknown",
};

/// RFC 3339 UTC.
pub const BUILD_DATE: &str = match option_env!("U7S_BUILD_DATE") {
    Some(d) => d,
    None => "unknown",
};

/// Semver build metadata (`+`), not a pre-release (`-`): a pre-release sorts
/// below the plain k8s version and fails `kubeVersion: ">=1.37.0"` checks.
pub fn git_version() -> String {
    format!("v{}", version_core(K8S_VERSION, RELEASE))
}

fn version_core(k8s: &str, release: &str) -> String {
    format!("{k8s}+u7s-{release}")
}

/// `(major, minor)` of [`K8S_VERSION`].
pub fn major_minor() -> (&'static str, &'static str) {
    let mut parts = K8S_VERSION.split('.');
    (
        parts.next().expect("K8S_VERSION has a major"),
        parts.next().expect("K8S_VERSION has a minor"),
    )
}

/// The `--version` line.
pub fn version_string() -> &'static str {
    static S: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        format!(
            "{} (commit {GIT_COMMIT}, built {BUILD_DATE})",
            git_version()
        )
    })
}

/// Go-style `os/arch` of the running binary.
pub fn platform() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{}/{arch}", std::env::consts::OS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal semver 2.0 split: (core, prerelease, build).
    fn split_semver(v: &str) -> (&str, Option<&str>, Option<&str>) {
        let v = v.strip_prefix('v').expect("leading v");
        let (rest, build) = match v.split_once('+') {
            Some((r, b)) => (r, Some(b)),
            None => (v, None),
        };
        match rest.split_once('-') {
            Some((c, p)) => (c, Some(p), build),
            None => (rest, None, build),
        }
    }

    #[test]
    fn release_goes_in_build_metadata_not_prerelease_so_helm_kube_version_constraints_accept_it() {
        let v = format!("v{}", version_core("1.37.1", "0.4.0-snapshot.1"));
        let (core, pre, build) = split_semver(&v);
        assert_eq!(core, "1.37.1");
        assert_eq!(
            pre, None,
            "a '-' suffix makes {v} a pre-release sorting below 1.37.0; Helm kubeVersion >=1.37.0 rejects the cluster"
        );
        assert_eq!(build, Some("u7s-0.4.0-snapshot.1"));
    }

    #[test]
    fn git_version_core_is_the_k8s_constant_so_client_skew_checks_see_the_real_version() {
        let v = git_version();
        let (core, pre, build) = split_semver(&v);
        assert_eq!(core, K8S_VERSION);
        assert_eq!(pre, None, "{v} must not be a pre-release");
        assert!(build.unwrap().starts_with("u7s-"), "{v}");
    }

    #[test]
    fn major_minor_match_k8s_constant_so_client_go_skew_checks_parse() {
        let (major, minor) = major_minor();
        assert!(
            K8S_VERSION.starts_with(&format!("{major}.{minor}.")),
            "{major}.{minor} vs {K8S_VERSION}"
        );
        assert_eq!((major, minor), ("1", "37"));
    }

    #[test]
    fn unstamped_build_is_marked_dev_so_it_is_never_mistaken_for_a_release() {
        if option_env!("U7S_RELEASE").is_none() {
            assert_eq!(RELEASE, "dev");
            assert_eq!(git_version(), format!("v{K8S_VERSION}+u7s-dev"));
        }
    }

    #[test]
    fn platform_uses_go_arch_names_because_kubectl_prints_it_verbatim() {
        let p = platform();
        let (os, arch) = p.split_once('/').unwrap();
        assert_eq!(os, std::env::consts::OS);
        assert!(!arch.contains("x86_64") && !arch.contains("aarch64"), "{p}");
    }
}
