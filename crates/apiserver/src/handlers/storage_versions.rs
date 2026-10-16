//! Storage version of every built-in resource, mirroring release-1.37 kube-apiserver.
//!
//! Upstream stores each resource at the highest-priority non-alpha version of its group
//! (`DefaultResourceEncodingConfig`), except for the `ResourceEncodingOverrides` in
//! `pkg/kubeapiserver/default_storage_factory_builder.go` that pin resources whose newest
//! served version was introduced in 1.37 to their predecessor for rollback safety.
//! Discovery's `storageVersionHash` derives from this storage GVK, not the served version.

/// `(served group, resource, storage group, storage version)`.
///
/// The storage group differs from the served group for `events.k8s.io` events, which share
/// the core `v1` Event storage.
pub(crate) const STORAGE_VERSIONS: &[(&str, &str, &str, &str)] = &[
    ("", "configmaps", "", "v1"),
    ("", "endpoints", "", "v1"),
    ("", "events", "", "v1"),
    ("", "limitranges", "", "v1"),
    ("", "namespaces", "", "v1"),
    ("", "nodes", "", "v1"),
    ("", "persistentvolumeclaims", "", "v1"),
    ("", "persistentvolumes", "", "v1"),
    ("", "pods", "", "v1"),
    ("", "podtemplates", "", "v1"),
    ("", "replicationcontrollers", "", "v1"),
    ("", "resourcequotas", "", "v1"),
    ("", "secrets", "", "v1"),
    ("", "serviceaccounts", "", "v1"),
    ("", "services", "", "v1"),
    (
        "admissionregistration.k8s.io",
        "mutatingadmissionpolicies",
        "admissionregistration.k8s.io",
        "v1",
    ),
    (
        "admissionregistration.k8s.io",
        "mutatingadmissionpolicybindings",
        "admissionregistration.k8s.io",
        "v1",
    ),
    (
        "admissionregistration.k8s.io",
        "mutatingwebhookconfigurations",
        "admissionregistration.k8s.io",
        "v1",
    ),
    (
        "admissionregistration.k8s.io",
        "validatingadmissionpolicies",
        "admissionregistration.k8s.io",
        "v1",
    ),
    (
        "admissionregistration.k8s.io",
        "validatingadmissionpolicybindings",
        "admissionregistration.k8s.io",
        "v1",
    ),
    (
        "admissionregistration.k8s.io",
        "validatingwebhookconfigurations",
        "admissionregistration.k8s.io",
        "v1",
    ),
    (
        "apiextensions.k8s.io",
        "customresourcedefinitions",
        "apiextensions.k8s.io",
        "v1",
    ),
    (
        "apiregistration.k8s.io",
        "apiservices",
        "apiregistration.k8s.io",
        "v1",
    ),
    ("apps", "daemonsets", "apps", "v1"),
    ("apps", "deployments", "apps", "v1"),
    ("apps", "replicasets", "apps", "v1"),
    ("apps", "statefulsets", "apps", "v1"),
    // autoscaling's version priority is v2 before v1.
    (
        "autoscaling",
        "horizontalpodautoscalers",
        "autoscaling",
        "v2",
    ),
    ("batch", "cronjobs", "batch", "v1"),
    ("batch", "jobs", "batch", "v1"),
    (
        "certificates.k8s.io",
        "certificatesigningrequests",
        "certificates.k8s.io",
        "v1",
    ),
    (
        "certificates.k8s.io",
        "clustertrustbundles",
        "certificates.k8s.io",
        "v1beta1",
    ),
    (
        "certificates.k8s.io",
        "podcertificaterequests",
        "certificates.k8s.io",
        "v1beta1",
    ),
    ("coordination.k8s.io", "leases", "coordination.k8s.io", "v1"),
    (
        "coordination.k8s.io",
        "leasecandidates",
        "coordination.k8s.io",
        "v1beta1",
    ),
    (
        "discovery.k8s.io",
        "endpointslices",
        "discovery.k8s.io",
        "v1",
    ),
    ("events.k8s.io", "events", "", "v1"),
    (
        "flowcontrol.apiserver.k8s.io",
        "flowschemas",
        "flowcontrol.apiserver.k8s.io",
        "v1",
    ),
    (
        "flowcontrol.apiserver.k8s.io",
        "prioritylevelconfigurations",
        "flowcontrol.apiserver.k8s.io",
        "v1",
    ),
    (
        "networking.k8s.io",
        "ingressclasses",
        "networking.k8s.io",
        "v1",
    ),
    ("networking.k8s.io", "ingresses", "networking.k8s.io", "v1"),
    (
        "networking.k8s.io",
        "ipaddresses",
        "networking.k8s.io",
        "v1",
    ),
    (
        "networking.k8s.io",
        "networkpolicies",
        "networking.k8s.io",
        "v1",
    ),
    (
        "networking.k8s.io",
        "servicecidrs",
        "networking.k8s.io",
        "v1",
    ),
    ("node.k8s.io", "runtimeclasses", "node.k8s.io", "v1"),
    ("policy", "poddisruptionbudgets", "policy", "v1"),
    (
        "rbac.authorization.k8s.io",
        "clusterrolebindings",
        "rbac.authorization.k8s.io",
        "v1",
    ),
    (
        "rbac.authorization.k8s.io",
        "clusterroles",
        "rbac.authorization.k8s.io",
        "v1",
    ),
    (
        "rbac.authorization.k8s.io",
        "rolebindings",
        "rbac.authorization.k8s.io",
        "v1",
    ),
    (
        "rbac.authorization.k8s.io",
        "roles",
        "rbac.authorization.k8s.io",
        "v1",
    ),
    ("resource.k8s.io", "deviceclasses", "resource.k8s.io", "v1"),
    (
        "resource.k8s.io",
        "devicetaintrules",
        "resource.k8s.io",
        "v1beta2",
    ),
    ("resource.k8s.io", "resourceclaims", "resource.k8s.io", "v1"),
    (
        "resource.k8s.io",
        "resourceclaimtemplates",
        "resource.k8s.io",
        "v1",
    ),
    ("resource.k8s.io", "resourceslices", "resource.k8s.io", "v1"),
    (
        "scheduling.k8s.io",
        "priorityclasses",
        "scheduling.k8s.io",
        "v1",
    ),
    ("storage.k8s.io", "csidrivers", "storage.k8s.io", "v1"),
    ("storage.k8s.io", "csinodes", "storage.k8s.io", "v1"),
    (
        "storage.k8s.io",
        "csistoragecapacities",
        "storage.k8s.io",
        "v1",
    ),
    ("storage.k8s.io", "storageclasses", "storage.k8s.io", "v1"),
    (
        "storage.k8s.io",
        "volumeattachments",
        "storage.k8s.io",
        "v1",
    ),
    (
        "storage.k8s.io",
        "volumeattributesclasses",
        "storage.k8s.io",
        "v1",
    ),
    (
        "storagemigration.k8s.io",
        "storageversionmigrations",
        "storagemigration.k8s.io",
        "v1beta1",
    ),
];

/// Request-only APIs with no backing storage; upstream publishes no hash for them.
#[cfg(test)]
pub(crate) const NOT_PERSISTED: &[(&str, &str)] = &[
    ("authentication.k8s.io", "selfsubjectreviews"),
    ("authentication.k8s.io", "tokenreviews"),
    ("authorization.k8s.io", "localsubjectaccessreviews"),
    ("authorization.k8s.io", "selfsubjectaccessreviews"),
    ("authorization.k8s.io", "selfsubjectrulesreviews"),
    ("authorization.k8s.io", "subjectaccessreviews"),
];

/// `(storage group, storage version)` for a served built-in resource, or `None` when it has no
/// storage entry.
pub(crate) fn storage_gv(group: &str, resource: &str) -> Option<(&'static str, &'static str)> {
    STORAGE_VERSIONS
        .iter()
        .find(|(g, r, _, _)| *g == group && *r == resource)
        .map(|(_, _, sg, sv)| (*sg, *sv))
}
