use crate::types::{
    CsiDriverSpec, DaemonSetSpec, DefaultingPodTemplate, DeploymentSpec, HpaBehavior, JobSpec,
    LeaseSpec, PersistentVolumeSpecFields, PersistentVolumeStatusFields, ReplicaSetSpec,
    ReplicationControllerSpec, RoleRefFields, ServiceSpec, StatefulSetSpec, StorageClassFields,
    TemplateLabelsPeek,
};

/// Apply upstream-compatible field defaults to a stored object.
///
/// Equivalent to what kube-apiserver does via `scheme.Default()` after decode
/// and before admission. Without this, controllers that expect defaulted fields
/// (e.g. kube-controller-manager reading `spec.strategy.type` on a Deployment)
/// crash with errors like "unexpected deployment strategy type: \"\"".
///
/// All writes are idempotent: existing non-null values are never overwritten.
pub fn apply_defaults(group: &str, plural: &str, obj: &mut serde_json::Value) {
    if let ("apps", "deployments") = (group, plural) {
        default_deployment(obj);
    }
    if let ("apps", "replicasets") = (group, plural) {
        default_replicaset(obj);
    }
    if let ("apps", "statefulsets") = (group, plural) {
        default_statefulset(obj);
    }
    if let ("apps", "daemonsets") = (group, plural) {
        default_daemonset(obj);
    }
    if let ("batch", "jobs") = (group, plural) {
        default_job(obj);
    }
    if let ("batch", "cronjobs") = (group, plural) {
        default_cronjob(obj);
    }
    if let ("", "services") = (group, plural) {
        default_service(obj);
    }
    if plural == "events" && (group.is_empty() || group == "events.k8s.io") {
        translate_event_shape(obj);
        normalize_event_timestamps(obj);
    }
    if let ("", "persistentvolumeclaims") = (group, plural) {
        default_pvc(obj);
    }
    if let ("", "persistentvolumes") = (group, plural) {
        default_pv(obj);
    }
    if let ("storage.k8s.io", "csidrivers") = (group, plural) {
        default_csidriver(obj);
    }
    if let ("storage.k8s.io", "storageclasses") = (group, plural) {
        default_storageclass(obj);
    }
    if let ("", "namespaces") = (group, plural) {
        default_namespace(obj);
    }
    if let ("coordination.k8s.io", "leases") = (group, plural) {
        default_lease(obj);
    }
    if let ("", "replicationcontrollers") = (group, plural) {
        default_replicationcontroller(obj);
    }
    if let ("autoscaling", "horizontalpodautoscalers") = (group, plural) {
        default_hpa(obj);
    }
    if group == "rbac.authorization.k8s.io"
        && (plural == "rolebindings" || plural == "clusterrolebindings")
    {
        default_role_ref_api_group(obj);
    }

    if is_workload_resource(group, plural) || is_endpointslice(group, plural) {
        initialize_workload_generation(obj);
    }

    // Strip null creationTimestamp from pod template metadata on workloads.
    // KCM's FindNewReplicaSet uses EqualIgnoreHash(RS.spec.template, Deployment.spec.template).
    // Our JSON serialization of ObjectMeta emits "creationTimestamp: null" but KCM omits this
    // field when creating the RS — causing EqualIgnoreHash to see different metadata and return
    // false, so FindNewReplicaSet returns nil and the deployment revision annotation is never set.
    if matches!(
        (group, plural),
        ("apps", "deployments")
            | ("apps", "replicasets")
            | ("apps", "statefulsets")
            | ("apps", "daemonsets")
    ) {
        strip_null_template_metadata(obj);
    }
    // For Jobs the pod template is also at spec.template; strip there too.
    if let ("batch", "jobs") = (group, plural) {
        strip_null_template_metadata(obj);
    }
    // For CronJobs the pod template is nested under spec.jobTemplate.spec.template.
    if let ("batch", "cronjobs") = (group, plural) {
        strip_null_cronjob_template_metadata(obj);
    }
}

/// Returns true when the group/plural pair is a workload resource that KCM
/// reconciles via metadata.generation.
///
/// Used to gate generation initialisation and increment so we don't accidentally
/// set generation on non-workload resources (e.g. Services) where it's unused.
///
/// PodDisruptionBudget (policy/poddisruptionbudgets) is included because the
/// disruption controller reads pdb.Generation and writes status.ObservedGeneration.
/// The conformance test `waitForPdbToBeProcessed` polls until ObservedGeneration >=
/// Generation — if Generation is 0 (absent), the wait is a no-op and the test races
/// KCM's reconcile, writing disruptedPods before KCM's informer cache is settled.
/// Real Kubernetes sets Generation=1 at PDB create time (PrepareForCreate strategy).
pub fn is_workload_resource(group: &str, plural: &str) -> bool {
    matches!(
        (group, plural),
        ("apps", "deployments")
            | ("apps", "replicasets")
            | ("apps", "statefulsets")
            | ("apps", "daemonsets")
            | ("batch", "jobs")
            | ("batch", "cronjobs")
            | ("policy", "poddisruptionbudgets")
    )
}

/// Returns true for EndpointSlice, which — unlike the `is_workload_resource` set — tracks
/// `metadata.generation` via bespoke REST-strategy logic upstream
/// (`pkg/registry/discovery/endpointslice/strategy.go`'s `PrepareForUpdate`) instead of a
/// `.spec` comparison: EndpointSlice has no `.spec`, so its generation increments when
/// `endpoints`, `ports`, or `addressType` change (or when labels change).
///
/// KCM's `EndpointSliceTracker.StaleSlices()` reads this field per-UID to detect a stale
/// informer cache; leaving it permanently absent (as the old `is_workload_resource`-only gate
/// did, on the theory that "generation is unused" — true for Services, wrong for
/// EndpointSlice) makes that comparison a no-op (0 is never greater than 0), silently
/// disabling one of its three staleness checks.
pub fn is_endpointslice(group: &str, plural: &str) -> bool {
    matches!((group, plural), ("discovery.k8s.io", "endpointslices"))
}

/// Set `metadata.generation = 1` on a newly created workload object if absent or null.
///
/// KCM's deployment controller reads metadata.generation to decide whether to
/// reconcile: if generation is null the controller skips the object entirely,
/// meaning no ReplicaSet is ever created and no pods are ever scheduled.
///
/// Called from apply_defaults so it runs at both create and update time.
/// The idempotency check (`is_null`) means:
///   • create: generation is absent → set to 1
///   • update: generation already ≥ 1 → leave unchanged (increment is separate)
pub fn initialize_workload_generation(obj: &mut serde_json::Value) {
    if obj["metadata"]["generation"].is_null() {
        obj["metadata"]["generation"] = serde_json::json!(1i64);
    }
}

/// Increment `metadata.generation` by 1 when the workload spec has changed.
///
/// Called after PUT and PATCH operations on workload resources. KCM tracks
/// observedGeneration vs generation to detect pending changes; without this
/// increment the controller can't tell that a spec update hasn't been reconciled.
pub fn increment_workload_generation_if_spec_changed(
    obj: &mut serde_json::Value,
    spec_before: &serde_json::Value,
) {
    if obj["spec"] != *spec_before {
        let current = obj["metadata"]["generation"].as_i64().unwrap_or(1);
        obj["metadata"]["generation"] = serde_json::json!(current + 1);
    }
}

/// Increment `metadata.generation` for an EndpointSlice when its endpoints, ports,
/// addressType, or labels changed relative to `before`.
///
/// Mirrors upstream's `endpointSliceStrategy.PrepareForUpdate`, which bumps generation
/// whenever anything other than (non-label) metadata changed — EndpointSlice has no
/// `.spec`, so `increment_workload_generation_if_spec_changed` can't be reused here.
pub fn increment_endpointslice_generation_if_changed(
    obj: &mut serde_json::Value,
    before: &serde_json::Value,
) {
    let content_changed = obj["endpoints"] != before["endpoints"]
        || obj["ports"] != before["ports"]
        || obj["addressType"] != before["addressType"];
    let labels_changed = obj["metadata"]["labels"] != before["metadata"]["labels"];
    if content_changed || labels_changed {
        let current = obj["metadata"]["generation"].as_i64().unwrap_or(1);
        obj["metadata"]["generation"] = serde_json::json!(current + 1);
    }
}

/// Set status.phase to "Pending" and spec.volumeMode to "Filesystem" for a newly
/// created PersistentVolumeClaim.
///
/// The real kube-apiserver initializes PVC status.phase to "Pending" at create time.
/// Without this, controllers and conformance tests that check `phase == "Pending"` before
/// the volume is bound will fail — they expect the field to be present immediately.
///
/// spec.volumeMode matches upstream `SetDefaults_PersistentVolumeClaimSpec`
/// (pkg/apis/core/v1/defaults.go), which defaults it to "Filesystem" when the client
/// omits it — nearly every hand-written PVC manifest does. Without this default,
/// kubelet's desired_state_of_world_populator fails with "cannot get volumeMode for
/// volume" and the pod mounting the PVC stays Pending forever.
///
/// Idempotent: if a field is already set it is not overwritten.
fn default_pvc(obj: &mut serde_json::Value) {
    let mut status: PersistentVolumeStatusFields =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();
    let mut spec: PersistentVolumeSpecFields =
        serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    default_volume_status_and_mode(&mut status, &mut spec);
    obj["status"] =
        serde_json::to_value(&status).expect("PersistentVolumeStatusFields is always serializable");
    obj["spec"] =
        serde_json::to_value(&spec).expect("PersistentVolumeSpecFields is always serializable");
}

/// The actual reasoning shared by PV and PVC defaulting: `status.phase`
/// defaults to "Pending"; `spec.volumeMode` defaults to "Filesystem".
/// Idempotent: if a field is already set it is not overwritten.
fn default_volume_status_and_mode(
    status: &mut PersistentVolumeStatusFields,
    spec: &mut PersistentVolumeSpecFields,
) {
    if status.phase.is_none() {
        status.phase = Some("Pending".to_string());
    }
    if spec.volume_mode.is_none() {
        spec.volume_mode = Some("Filesystem".to_string());
    }
}

/// Set status.phase to "Pending" and spec.volumeMode to "Filesystem" for a newly
/// created PersistentVolume, matching upstream `SetDefaults_PersistentVolume`
/// (pkg/apis/core/v1/defaults.go).
///
/// Without the volumeMode default, kubelet's desired_state_of_world_populator fails
/// with "cannot get volumeMode for volume: <name>" and the pod mounting a PVC bound
/// to this PV stays Pending forever — the mechanism behind e2e's
/// WaitForPodNotPending timing out for hand-written PV manifests (e.g.
/// e2epv.CreatePVPVC, which omits volumeMode like almost every manifest does).
///
/// Idempotent: if a field is already set it is not overwritten.
fn default_pv(obj: &mut serde_json::Value) {
    let mut status: PersistentVolumeStatusFields =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();
    let mut spec: PersistentVolumeSpecFields =
        serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    default_volume_status_and_mode(&mut status, &mut spec);
    obj["status"] =
        serde_json::to_value(&status).expect("PersistentVolumeStatusFields is always serializable");
    obj["spec"] =
        serde_json::to_value(&spec).expect("PersistentVolumeSpecFields is always serializable");
}

/// Default the pointer-typed fields of `CSIDriver.spec`, matching upstream
/// `SetDefaults_CSIDriver` (pkg/apis/storage/v1/defaults.go).
///
/// A real CSI driver's install manifest (helm charts, kustomize bases, the e2e storage
/// test framework's own `deploy.go`) commonly omits some or all of these fields,
/// relying on the apiserver to default them the way every other typed field is defaulted.
/// Without `requiresRepublish` specifically defaulted, a live repro against csi-hostpath
/// showed kubelet's (unmodified upstream) volume manager panicking with a nil-pointer
/// dereference in `csiPlugin.RequiresRemount` (`pkg/volume/csi/csi_plugin.go`, which
/// unconditionally dereferences `*csiDriver.Spec.RequiresRepublish`), crash-looping
/// kubelet on every node running a pod with a CSI volume and permanently blocking that
/// pod (and the whole node's pod churn) from progressing. The other fields default here
/// too because they are the same upstream function's peer fields on the same object,
/// each read the same way by kubelet/kube-controller-manager's CSI code paths.
///
/// Idempotent: if a field is already set it is not overwritten. `seLinuxMount` and
/// `preventPodSchedulingIfMissing` are intentionally not defaulted here — upstream only
/// sets them when their alpha/beta feature gates are enabled, which this codebase does
/// not model.
fn default_csidriver(obj: &mut serde_json::Value) {
    let mut spec: CsiDriverSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    default_csidriver_spec(&mut spec);
    obj["spec"] = serde_json::to_value(&spec).expect("CsiDriverSpec is always serializable");
}

fn default_csidriver_spec(spec: &mut CsiDriverSpec) {
    if spec.attach_required.is_none() {
        spec.attach_required = Some(true);
    }
    if spec.pod_info_on_mount.is_none() {
        spec.pod_info_on_mount = Some(false);
    }
    if spec.storage_capacity.is_none() {
        spec.storage_capacity = Some(false);
    }
    if spec.fs_group_policy.is_none() {
        spec.fs_group_policy = Some("ReadWriteOnceWithFSTypeFSGroupPolicy".to_string());
    }
    if spec
        .volume_lifecycle_modes
        .as_ref()
        .map(|m| m.is_empty())
        .unwrap_or(true)
    {
        spec.volume_lifecycle_modes = Some(vec!["Persistent".to_string()]);
    }
    if spec.requires_republish.is_none() {
        spec.requires_republish = Some(false);
    }
}

/// Default `reclaimPolicy` and `volumeBindingMode` on a StorageClass, matching upstream
/// `SetDefaults_StorageClass` (pkg/apis/storage/v1/defaults.go). Unlike CSIDriver these
/// two fields sit directly on the object, not under `.spec` — StorageClass has no spec
/// wrapper.
///
/// The e2e storage test framework's own StorageClass helper (and most hand-written
/// manifests) omits both fields, relying on apiserver defaulting. Without
/// `reclaimPolicy` defaulted, a live repro against the nfs3 in-tree driver showed the
/// external `nfs-provisioner` sidecar (unmodified upstream,
/// `pkg/volume/provision.go`) panic with a nil-pointer dereference on
/// `*options.StorageClass.ReclaimPolicy`, crashing the provisioner pod every time it
/// tried to provision a volume — so no PV was ever created and the PVC stayed Pending
/// until the test's bind-wait timed out.
///
/// Idempotent: if a field is already set it is not overwritten.
fn default_storageclass(obj: &mut serde_json::Value) {
    let mut fields: StorageClassFields = serde_json::from_value(obj.clone()).unwrap_or_default();
    if fields.reclaim_policy.is_none() {
        fields.reclaim_policy = Some("Delete".to_string());
    }
    if fields.volume_binding_mode.is_none() {
        fields.volume_binding_mode = Some("Immediate".to_string());
    }
    *obj = serde_json::to_value(&fields).expect("StorageClassFields is always serializable");
}

/// Set status.phase to "Active" for a newly created Namespace, matching upstream
/// `NamespaceStrategy.PrepareForCreate` (pkg/registry/core/namespace/strategy.go), which
/// the real kube-apiserver runs for both plain `POST` create AND `PATCH`-based
/// server-side-apply create — u7s previously only ran the equivalent of this in the
/// plain-create handler, so an SSA-created (`kubectl apply`) namespace was persisted
/// with `status: {}`. KCM's ServiceAccount controller skips reconciling the `default`
/// ServiceAccount for any namespace whose `status.phase != Active`, so a pod created in
/// such a namespace with the pod-spec default `automountServiceAccountToken: true`
/// sticks in ContainerCreating forever.
///
/// Idempotent: an existing status.phase (e.g. "Terminating", stamped by delete) is
/// never overwritten.
fn default_namespace(obj: &mut serde_json::Value) {
    let mut status: crate::types::NamespaceStatus =
        serde_json::from_value(obj["status"].clone()).unwrap_or_default();
    if status.phase.is_none() {
        status.phase = Some(crate::types::NamespacePhase::Active);
    }
    obj["status"] = serde_json::to_value(&status).expect("NamespaceStatus is always serializable");
}

/// Default `spec.selector` and `spec.replicas` on a ReplicationController when absent.
///
/// Upstream kube-apiserver defaults RC's `spec.selector` from `spec.template.metadata.labels`
/// at create time when the caller omits it. The conformance helper `newRC` (test/e2e/apps/rc.go)
/// creates RCs without an explicit selector, relying on this defaulting. Without it our apiserver
/// stores an empty selector; the KCM RC controller with an empty selector cannot match the pods it
/// creates (empty set matches nothing) → always sees active=0/desired=N → creates pods without
/// bound (verified: nil-selector RC created 179 pods in 8 s).
///
/// IMPORTANT: RC uses a flat equality-based label selector (`map<string,string>`), NOT the
/// set-based `{matchLabels: {...}}` format used by ReplicaSet/StatefulSet/Deployment.
/// Wrapping in `matchLabels` would produce a JSON structure that KCM cannot parse as an RC
/// selector and would re-introduce the empty-match runaway.
///
/// Idempotent: an existing non-null selector is never overwritten.
fn default_replicationcontroller(obj: &mut serde_json::Value) {
    let mut spec: ReplicationControllerSpec =
        serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let template_labels: TemplateLabelsPeek =
        serde_json::from_value(obj["spec"]["template"].clone()).unwrap_or_default();

    // Default spec.selector from template labels when absent.
    // RC selector is a flat map<string,string> — NOT wrapped in matchLabels.
    if spec.selector.is_none() {
        if let Some(labels) = template_labels.metadata.labels {
            spec.selector = Some(labels);
        }
    }

    // Default spec.replicas to 1 when absent.
    if spec.replicas.is_none() {
        spec.replicas = Some(1);
    }

    obj["spec"] =
        serde_json::to_value(&spec).expect("ReplicationControllerSpec is always serializable");
}

/// Default `spec.leaseTransitions` to `0` on a Lease when absent.
///
/// Real Kubernetes represents leaseTransitions as `*int32` (pointer-to-zero).
/// When omitted by the client the field is null in JSON, but the Lease conformance
/// test reads it back and expects `0`. Without this default, the field stays null
/// and the test fails with "unexpected leaseTransitions: <nil>".
fn default_lease(obj: &mut serde_json::Value) {
    let mut spec: LeaseSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    if spec.lease_transitions.is_none() {
        spec.lease_transitions = Some(0);
    }
    obj["spec"] = serde_json::to_value(&spec).expect("LeaseSpec is always serializable");
}

/// Default `roleRef.apiGroup` to `"rbac.authorization.k8s.io"` when absent or empty on a
/// RoleBinding or ClusterRoleBinding, matching real Kubernetes'
/// `SetDefaults_RoleBinding`/`SetDefaults_ClusterRoleBinding` (pkg/apis/rbac/v1/defaults.go).
///
/// Clients (including the upstream aggregator conformance test, which builds
/// `RoleRef{APIGroup: ""}` directly and relies on server-side defaulting) commonly omit
/// this field. Without defaulting it here, the stored roleRef.apiGroup stays "", and the
/// RBAC engine's `resolve_role_rules`/`resolve_cluster_role_rules` — which require an exact
/// `"rbac.authorization.k8s.io"` match — silently resolve to zero rules. The binding then
/// never grants anything, no matter how correct its subjects are, and no matter how long it
/// has existed — exactly the permanently-Forbidden failure mode that made the
/// extension-apiserver-authentication-reader RoleBinding never take effect for the sample
/// API server conformance test.
fn default_role_ref_api_group(obj: &mut serde_json::Value) {
    let mut role_ref: RoleRefFields =
        serde_json::from_value(obj["roleRef"].clone()).unwrap_or_default();
    if role_ref.api_group.as_deref().is_none_or(str::is_empty) {
        role_ref.api_group = Some("rbac.authorization.k8s.io".to_string());
    }
    obj["roleRef"] = serde_json::to_value(&role_ref).expect("RoleRefFields is always serializable");
}

/// Apply all Service defaults in the correct order.
///
/// 1. Default spec.type to "ClusterIP" when absent — conformance tests check that a
///    Service with no explicit type comes back as ClusterIP.
/// 2. Default spec.sessionAffinity to "None" — `kubectl describe svc` prints the raw
///    field value, so an absent sessionAffinity renders as an empty "Session Affinity:"
///    line and fails the sig-cli describe conformance test.
/// 3. Allocate NodePorts for NodePort/LoadBalancer services — ports without a nodePort
///    get one assigned from the standard 30000-32767 range.
/// 4. Skip ClusterIP-family defaults for ExternalName — ExternalName services must not
///    have ipFamilies/ipFamilyPolicy/clusterIPs set (they have no cluster IP at all).
fn default_service(obj: &mut serde_json::Value) {
    let mut spec: ServiceSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    default_service_spec(&mut spec);
    obj["spec"] = serde_json::to_value(&spec).expect("ServiceSpec is always serializable");
}

fn default_service_spec(spec: &mut ServiceSpec) {
    // 1. Default spec.type to "ClusterIP".
    if spec.r#type.is_none() {
        spec.r#type = Some("ClusterIP".to_string());
    }

    // 2. Default spec.sessionAffinity to "None" (matches upstream SetDefaults_Service).
    if spec.session_affinity.is_none() {
        spec.session_affinity = Some("None".to_string());
    }

    // When sessionAffinity is ClientIP, default the timeout to 10800s (3h) unless set.
    if spec.session_affinity.as_deref() == Some("ClientIP") {
        let affinity_cfg = spec
            .session_affinity_config
            .get_or_insert_with(Default::default);
        let client_ip = affinity_cfg.client_ip.get_or_insert_with(Default::default);
        if client_ip.timeout_seconds.is_none() {
            client_ip.timeout_seconds = Some(10800);
        }
    }

    let svc_type = spec
        .r#type
        .clone()
        .unwrap_or_else(|| "ClusterIP".to_string());

    // 3. Allocate NodePorts for NodePort and LoadBalancer services.
    if svc_type == "NodePort" || svc_type == "LoadBalancer" {
        default_node_ports(spec);
    }

    if let Some(ports) = spec.ports.as_mut() {
        for port_entry in ports.iter_mut() {
            let needs_target_port = port_entry.target_port.is_none()
                || port_entry.target_port.as_ref().and_then(|v| v.as_i64()) == Some(0);
            if needs_target_port {
                if let Some(port_num) = port_entry.port {
                    port_entry.target_port = Some(serde_json::Value::Number(port_num.into()));
                }
            }
            if port_entry.protocol.is_none() {
                port_entry.protocol = Some("TCP".to_string());
            }
        }
    }

    // 4. ExternalName services must not have ClusterIP-family fields or NodePorts.
    // When a service changes type to ExternalName (e.g. NodePort → ExternalName),
    // any previously assigned clusterIP, clusterIPs, and nodePort fields must be cleared.
    // Without this, GET after the type-change PATCH still returns the old IP/nodePort.
    if svc_type == "ExternalName" {
        spec.cluster_ip = Some(String::new());
        spec.cluster_ips = Some(vec![]);
        if let Some(ports) = spec.ports.as_mut() {
            for port in ports.iter_mut() {
                port.node_port = Some(serde_json::Value::Number(0.into()));
            }
        }
        return;
    }

    default_service_ip_fields_spec(spec);
}

/// Assign NodePorts to ports that don't have one yet.
///
/// Scans spec.ports for any port with protocol TCP/UDP/SCTP that lacks a nodePort.
/// Assigns ports sequentially from 30000, skipping values already in use within this
/// object. The range 30000-32767 matches the Kubernetes default nodePort range.
///
/// Idempotent: ports that already have a nodePort are not modified.
fn default_node_ports(spec: &mut ServiceSpec) {
    let ports = match spec.ports.as_mut() {
        Some(p) => p,
        None => return,
    };

    // Collect already-assigned NodePorts so we don't re-use them.
    let mut used: std::collections::HashSet<u16> = ports
        .iter()
        .filter_map(|p| p.node_port.as_ref().and_then(|v| v.as_u64()))
        .filter(|&n| (30000..=32767).contains(&n))
        .map(|n| n as u16)
        .collect();

    let mut next_candidate: u16 = 30000;

    for port in ports.iter_mut() {
        // Skip ports that already have a nodePort.
        if port.node_port.is_some() {
            continue;
        }

        // Find the next unused port in the range.
        while used.contains(&next_candidate) || next_candidate > 32767 {
            next_candidate = next_candidate.saturating_add(1);
            if next_candidate > 32767 {
                // Range exhausted — leave remaining ports without a nodePort.
                return;
            }
        }

        port.node_port = Some(serde_json::Value::Number(next_candidate.into()));
        used.insert(next_candidate);
        next_candidate += 1;
    }
}

/// Normalize Event timestamp fields to include microsecond precision.
///
/// client-go's MicroTime codec (used for `eventTime` and `series.lastObservedTime`)
/// and some Event field parsers require fractional seconds:
/// `2017-09-20T13:49:16.000000Z`.
/// Without the `.000000` suffix, client-go raises:
///   `parsing time "…Z" as "…000000Z07:00": cannot parse "Z" as ".000000"`.
///
/// This function normalizes `lastTimestamp`, `firstTimestamp`, `eventTime`, and
/// `series.lastObservedTime` in-place by appending `.000000` to any
/// second-precision RFC3339 string.
///
/// `series.lastObservedTime` must be normalized here because the Kubernetes
/// Event controller patches it via merge-patch; if stored without microsecond
/// precision, client-go sees it as a zero MicroTime on re-read, causing event
/// deduplication to break (every occurrence appears as a new event).
pub fn normalize_event_timestamps(obj: &mut serde_json::Value) {
    for field in &["lastTimestamp", "firstTimestamp", "eventTime"] {
        if let Some(s) = obj[field].as_str() {
            let normalized = crate::util::normalize_rfc3339_to_micro(s);
            obj[*field] = serde_json::Value::String(normalized);
        }
    }
    if let Some(s) = obj["series"]["lastObservedTime"].as_str() {
        let normalized = crate::util::normalize_rfc3339_to_micro(s);
        obj["series"]["lastObservedTime"] = serde_json::Value::String(normalized);
    }
}

/// Translate an Event's fields between the core/v1 shape (`involvedObject`,
/// `message`, `source`, `firstTimestamp`, `lastTimestamp`, `count`) and the
/// events.k8s.io/v1 shape (`regarding`, `note`, `deprecatedSource`,
/// `deprecatedFirstTimestamp`, `deprecatedLastTimestamp`, `deprecatedCount`).
///
/// Matches upstream's `Convert_v1_Event_To_core_Event` /
/// `Convert_core_Event_To_v1_Event` (pkg/apis/events/v1/conversion.go), which
/// rename these fields unconditionally on every read/write regardless of which
/// group the request came through — `reportingController`, `reportingInstance`,
/// `eventTime`, and `series` are NOT renamed by that conversion (both group's
/// Event types carry them under the same names already) and `source` is never
/// backfilled from `reportingController` in the object body (only in field
/// selector matching, see `event_matches_field_selector`) — inventing that
/// mapping here would fabricate data upstream does not produce.
///
/// Each pair is a straight alias: whichever side is set wins and is copied to
/// the side that is absent. Never overwrites a value the client set.
pub fn translate_event_shape(obj: &mut serde_json::Value) {
    alias_event_field(obj, "involvedObject", "regarding");
    alias_event_field(obj, "message", "note");
    alias_event_field(obj, "source", "deprecatedSource");
    alias_event_field(obj, "firstTimestamp", "deprecatedFirstTimestamp");
    alias_event_field(obj, "lastTimestamp", "deprecatedLastTimestamp");
    alias_event_field(obj, "count", "deprecatedCount");
}

fn alias_event_field(obj: &mut serde_json::Value, core_field: &str, events_v1_field: &str) {
    match (
        obj.get(core_field).cloned(),
        obj.get(events_v1_field).cloned(),
    ) {
        (None, Some(v)) => {
            obj[core_field] = v;
        }
        (Some(v), None) => {
            obj[events_v1_field] = v;
        }
        _ => {}
    }
}

/// Set ipFamilies, ipFamilyPolicy, and clusterIPs on a Service if they are absent.
///
/// KCM's endpoints-controller indexes `svc.Spec.IPFamilies[0]` and panics if the
/// slice is nil.  kube-apiserver populates these in write-time defaulting
/// (`initIPFamilyFields`).  We replicate that minimal subset here so that every
/// Service stored in u7s has the fields KCM requires.
///
/// Rules (matching upstream SingleStack defaults):
/// - ipFamilyPolicy → "SingleStack" (always safe for pre-alpha single-stack clusters)
/// - ipFamilies    → ["IPv6"] if clusterIP contains ':', else ["IPv4"]
/// - clusterIPs    → [clusterIP] if clusterIP is non-empty and not "None"
///
/// Only sets fields that are absent or null; never overwrites existing values.
///
/// Must NOT be called for ExternalName services (they have no ClusterIP family).
pub fn default_service_ip_fields(obj: &mut serde_json::Value) {
    let mut spec: ServiceSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    default_service_ip_fields_spec(&mut spec);
    obj["spec"] = serde_json::to_value(&spec).expect("ServiceSpec is always serializable");
}

fn default_service_ip_fields_spec(spec: &mut ServiceSpec) {
    let cluster_ip = spec.cluster_ip.clone().unwrap_or_default();

    // ipFamilyPolicy
    if spec.ip_family_policy.is_none() {
        spec.ip_family_policy = Some("SingleStack".to_string());
    }

    // ipFamilies
    if spec.ip_families.is_none() {
        let family = if cluster_ip.contains(':') {
            "IPv6"
        } else {
            "IPv4"
        };
        spec.ip_families = Some(vec![family.to_string()]);
    }

    // clusterIPs
    if spec.cluster_ips.is_none() && !cluster_ip.is_empty() && cluster_ip != "None" {
        spec.cluster_ips = Some(vec![cluster_ip]);
    }
}

/// Validate a resource after defaults have been applied. Returns an error string
/// suitable for a 400 Bad Request if required fields are missing.
///
/// Must be called after `apply_defaults` so that fields defaultable from other
/// fields (e.g. spec.selector from template labels) have already been filled in.
pub fn validate_resource(group: &str, plural: &str, obj: &serde_json::Value) -> Result<(), String> {
    if let ("apps", "deployments") = (group, plural) {
        validate_deployment(obj)?;
    }
    if let ("apps", "replicasets") = (group, plural) {
        validate_selector(obj, "ReplicaSet")?;
    }
    if let ("apps", "statefulsets") = (group, plural) {
        validate_selector(obj, "StatefulSet")?;
    }
    if group == "admissionregistration.k8s.io"
        && (plural == "validatingwebhookconfigurations"
            || plural == "mutatingwebhookconfigurations")
    {
        crate::admission::validate_webhook_match_conditions_cel(obj)?;
    }
    if group.is_empty() && (plural == "configmaps" || plural == "secrets") {
        validate_data_keys(obj, plural)?;
    }
    Ok(())
}

fn validate_data_keys(obj: &serde_json::Value, plural: &str) -> Result<(), String> {
    let kind = if plural == "configmaps" {
        "ConfigMap"
    } else {
        "Secret"
    };
    for field in &["data", "binaryData"] {
        if let Some(map) = obj[field].as_object() {
            if map.contains_key("") {
                return Err(format!(
                    "{kind}.{field}: Invalid value: \"\": a valid config key must consist of alphanumeric characters, '-', '_' or '.'"
                ));
            }
        }
    }
    Ok(())
}

fn validate_deployment(obj: &serde_json::Value) -> Result<(), String> {
    if obj["spec"]["selector"].is_null() {
        return Err(
            "Deployment.spec.selector is required and could not be defaulted \
             (spec.template.metadata.labels is also missing)"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_selector(obj: &serde_json::Value, kind: &str) -> Result<(), String> {
    if obj["spec"]["selector"].is_null() {
        return Err(format!("{kind}.spec.selector is required"));
    }
    Ok(())
}

/// Default `selector` to `{matchLabels: <template labels>}` when absent, by peeking
/// (read-only) at the pod template's `metadata.labels`. Shared by ReplicaSet,
/// StatefulSet, and Deployment — all three use the same set-based selector shape,
/// unlike ReplicationController's flat equality selector (see `default_replicationcontroller`).
fn default_selector_from_template_labels(
    selector: &mut Option<serde_json::Value>,
    template: &serde_json::Value,
) {
    if selector.is_none() {
        let peek: TemplateLabelsPeek = serde_json::from_value(template.clone()).unwrap_or_default();
        if let Some(labels) = peek.metadata.labels {
            *selector = Some(serde_json::json!({ "matchLabels": labels }));
        }
    }
}

fn default_replicaset(obj: &mut serde_json::Value) {
    let mut spec: ReplicaSetSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    // spec.selector defaults to matchLabels from spec.template.metadata.labels.
    // Real kube-apiserver rejects ReplicaSets without spec.selector. Without
    // defaulting, validate_resource rejects objects that omit selector when
    // template labels are present (conformance pattern used by workload tests).
    default_selector_from_template_labels(&mut spec.selector, &obj["spec"]["template"]);

    if spec.replicas.is_none() {
        spec.replicas = Some(1);
    }
    obj["spec"] = serde_json::to_value(&spec).expect("ReplicaSetSpec is always serializable");
}

fn default_statefulset(obj: &mut serde_json::Value) {
    let mut spec: StatefulSetSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    // spec.selector defaults to matchLabels from spec.template.metadata.labels.
    // Real kube-apiserver rejects StatefulSets without spec.selector. Without
    // defaulting, validate_resource rejects objects that omit selector when
    // template labels are present (conformance pattern used by workload tests).
    default_selector_from_template_labels(&mut spec.selector, &obj["spec"]["template"]);

    if spec.replicas.is_none() {
        spec.replicas = Some(1);
    }
    if spec.pod_management_policy.is_none() {
        spec.pod_management_policy = Some("OrderedReady".to_string());
    }
    let strategy = spec.update_strategy.get_or_insert_with(Default::default);
    if strategy.r#type.is_none() {
        strategy.r#type = Some("RollingUpdate".to_string());
    }
    if strategy.r#type.as_deref() == Some("RollingUpdate") {
        let rolling_update = strategy.rolling_update.get_or_insert_with(Default::default);
        if rolling_update.partition.is_none() {
            rolling_update.partition = Some(0);
        }
    }
    if spec.revision_history_limit.is_none() {
        spec.revision_history_limit = Some(10);
    }
    obj["spec"] = serde_json::to_value(&spec).expect("StatefulSetSpec is always serializable");
}

fn default_daemonset(obj: &mut serde_json::Value) {
    let mut spec: DaemonSetSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();
    let strategy = spec.update_strategy.get_or_insert_with(Default::default);
    if strategy.r#type.is_none() {
        strategy.r#type = Some("RollingUpdate".to_string());
    }
    if strategy.r#type.as_deref() == Some("RollingUpdate") {
        let rolling_update = strategy.rolling_update.get_or_insert_with(Default::default);
        if rolling_update.max_unavailable.is_none() {
            rolling_update.max_unavailable = Some(serde_json::Value::Number(1.into()));
        }
        if rolling_update.max_surge.is_none() {
            rolling_update.max_surge = Some(serde_json::Value::Number(0.into()));
        }
    }
    if spec.revision_history_limit.is_none() {
        spec.revision_history_limit = Some(10);
    }
    obj["spec"] = serde_json::to_value(&spec).expect("DaemonSetSpec is always serializable");
}

/// Remove null-valued fields from `spec.template.metadata` on workload objects.
///
/// Our JSON serialization of `ObjectMeta` always emits `"creationTimestamp": null`.
/// KCM omits this field when creating a ReplicaSet from a Deployment template.
/// `EqualIgnoreHash` (used by `FindNewReplicaSet`) does a deep equality check on
/// the pod template: Deployment template has `creationTimestamp: null`, RS template
/// does not → templates are unequal → `FindNewReplicaSet` returns nil → the
/// deployment revision annotation is never set and reconciliation stalls.
///
/// Only strips keys whose value is `null`; non-null fields are left untouched.
/// Only operates on `spec.template.metadata`; no other part of the object is changed.
fn strip_null_template_metadata(obj: &mut serde_json::Value) {
    if let Some(meta) = obj["spec"]["template"]["metadata"].as_object_mut() {
        meta.retain(|_, v| !v.is_null());
    }
}

fn default_pod_template(template: &mut serde_json::Value) {
    let mut typed: DefaultingPodTemplate =
        serde_json::from_value(template.clone()).unwrap_or_default();
    default_pod_template_fields(&mut typed);
    *template = serde_json::to_value(&typed).expect("DefaultingPodTemplate is always serializable");
}

fn default_pod_template_fields(template: &mut DefaultingPodTemplate) {
    if template.metadata.labels.is_none() {
        template.metadata.labels = Some(serde_json::Map::new());
    }
    if template.metadata.annotations.is_none() {
        template.metadata.annotations = Some(serde_json::Map::new());
    }
    if template.spec.enable_service_links.is_none() {
        template.spec.enable_service_links = Some(true);
    }
}

fn default_job(obj: &mut serde_json::Value) {
    let mut spec: JobSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();

    let mut template: DefaultingPodTemplate =
        serde_json::from_value(spec.rest["template"].clone()).unwrap_or_default();
    default_pod_template_fields(&mut template);

    if spec.backoff_limit.is_none() {
        spec.backoff_limit = Some(6);
    }
    if spec.parallelism.is_none() {
        spec.parallelism = Some(1);
    }

    // Generate selector and inject controller-uid/job-name labels into the pod template
    // when the client did not supply a selector and did not opt in to manualSelector.
    //
    // Upstream kube-apiserver does this in pkg/registry/batch/job/strategy.go
    // (generateSelector). Without it, spec.template.metadata.labels is empty and
    // KCM's RealPodControl.createPods returns "unable to create pods, no labels",
    // so Job pods are never created and every Job conformance test times out.
    //
    // Guard: idempotent on GET/LIST/WATCH paths (selector already populated after create).
    let manual_selector = spec.manual_selector == Some(true);
    if spec.selector.is_none() && !manual_selector {
        let uid = obj["metadata"]["uid"].as_str().unwrap_or("").to_string();
        let name = obj["metadata"]["name"].as_str().unwrap_or("").to_string();
        // Only generate when uid is present (create path always has uid via stamp_metadata).
        if !uid.is_empty() {
            // Inject 4 labels into the pod template (prefixed + legacy, matching upstream).
            let labels = template
                .metadata
                .labels
                .get_or_insert_with(Default::default);
            labels.insert(
                "batch.kubernetes.io/controller-uid".to_string(),
                serde_json::Value::String(uid.clone()),
            );
            labels.insert(
                "batch.kubernetes.io/job-name".to_string(),
                serde_json::Value::String(name.clone()),
            );
            labels.insert(
                "controller-uid".to_string(),
                serde_json::Value::String(uid.clone()),
            );
            labels.insert("job-name".to_string(), serde_json::Value::String(name));

            // Set spec.selector.matchLabels to the prefixed controller-uid label.
            spec.selector = Some(serde_json::json!({
                "matchLabels": {
                    "batch.kubernetes.io/controller-uid": uid
                }
            }));
        }
    }

    spec.rest["template"] =
        serde_json::to_value(&template).expect("DefaultingPodTemplate is always serializable");
    obj["spec"] = serde_json::to_value(&spec).expect("JobSpec is always serializable");
}

fn default_cronjob(obj: &mut serde_json::Value) {
    default_pod_template(&mut obj["spec"]["jobTemplate"]["spec"]["template"]);
}

fn strip_null_cronjob_template_metadata(obj: &mut serde_json::Value) {
    if let Some(meta) = obj["spec"]["jobTemplate"]["spec"]["template"]["metadata"].as_object_mut() {
        meta.retain(|_, v| !v.is_null());
    }
}

fn default_deployment(obj: &mut serde_json::Value) {
    let mut spec: DeploymentSpec = serde_json::from_value(obj["spec"].clone()).unwrap_or_default();

    // spec.selector defaults to matchLabels from spec.template.metadata.labels.
    // Upstream kube-apiserver rejects Deployments without spec.selector; u7s stores
    // them as-is, so the KCM deployment-controller hits a nil selector and panics.
    default_selector_from_template_labels(&mut spec.selector, &obj["spec"]["template"]);

    // spec.replicas defaults to 1
    if spec.replicas.is_none() {
        spec.replicas = Some(1);
    }

    // spec.revisionHistoryLimit defaults to 10
    if spec.revision_history_limit.is_none() {
        spec.revision_history_limit = Some(10);
    }

    // spec.progressDeadlineSeconds defaults to 600
    if spec.progress_deadline_seconds.is_none() {
        spec.progress_deadline_seconds = Some(600);
    }

    // spec.strategy.type defaults to "RollingUpdate"
    let strategy = spec.strategy.get_or_insert_with(Default::default);
    if strategy.r#type.is_none() {
        strategy.r#type = Some("RollingUpdate".to_string());
    }

    // spec.strategy.rollingUpdate defaults only when strategy type is RollingUpdate.
    if strategy.r#type.as_deref() == Some("RollingUpdate") {
        let rolling_update = strategy.rolling_update.get_or_insert_with(Default::default);
        if rolling_update.max_surge.is_none() {
            rolling_update.max_surge = Some(serde_json::Value::String("25%".to_string()));
        }
        if rolling_update.max_unavailable.is_none() {
            rolling_update.max_unavailable = Some(serde_json::Value::String("25%".to_string()));
        }
    }

    obj["spec"] = serde_json::to_value(&spec).expect("DeploymentSpec is always serializable");
}

/// Default `spec.behavior.scaleUp`/`scaleDown` scaling rules on a HorizontalPodAutoscaler,
/// matching upstream `SetDefaults_HorizontalPodAutoscalerBehavior`
/// (pkg/apis/autoscaling/v2/defaults.go).
///
/// Vendored kube-controller-manager's `stabilizeRecommendationWithBehaviors`
/// (pkg/controller/podautoscaler/horizontal.go) unconditionally dereferences
/// `*Behavior.ScaleUp.StabilizationWindowSeconds` once `spec.behavior != nil`, relying entirely
/// on the apiserver to have already defaulted it — there is no runtime nil-guard for ScaleUp
/// (unlike ScaleDown, which kcm patches up itself). Without this defaulting, an HPA created
/// with e.g. `behavior.scaleUp = {tolerance: "20m"}` and no explicit `stabilizationWindowSeconds`
/// stores exactly that shape, and kcm nil-derefs and crashes the entire controller-manager
/// process the first time it reconciles that HPA.
///
/// Per-field overlay (matches upstream `copyHPAScalingRules`): only fields the caller left
/// unset get a default; fields the caller set are left untouched. `scaleDown`'s
/// `stabilizationWindowSeconds` is intentionally never defaulted here — upstream's own default
/// leaves it nil too ("we cannot rewrite the command line option from here"); kcm initializes it
/// itself at reconcile time via `maybeInitScaleDownStabilizationWindow`.
///
/// Idempotent: only null/absent fields are defaulted, so re-running on update never clobbers a
/// value the client (or a previous defaulting pass) already set.
fn default_hpa(obj: &mut serde_json::Value) {
    if !obj["spec"]["behavior"].is_object() {
        return;
    }

    let mut behavior: HpaBehavior =
        serde_json::from_value(obj["spec"]["behavior"].clone()).unwrap_or_default();
    default_hpa_behavior(&mut behavior);
    obj["spec"]["behavior"] =
        serde_json::to_value(&behavior).expect("HpaBehavior is always serializable");
}

fn default_hpa_behavior(behavior: &mut HpaBehavior) {
    if let Some(scale_up) = behavior.scale_up.as_mut() {
        if scale_up.stabilization_window_seconds.is_none() {
            scale_up.stabilization_window_seconds = Some(0);
        }
        if scale_up.select_policy.is_none() {
            scale_up.select_policy = Some("Max".to_string());
        }
        if scale_up.policies.is_none() {
            scale_up.policies = Some(serde_json::json!([
                { "type": "Pods", "value": 4, "periodSeconds": 15 },
                { "type": "Percent", "value": 100, "periodSeconds": 15 }
            ]));
        }
    }

    if let Some(scale_down) = behavior.scale_down.as_mut() {
        if scale_down.select_policy.is_none() {
            scale_down.select_policy = Some("Max".to_string());
        }
        if scale_down.policies.is_none() {
            scale_down.policies = Some(serde_json::json!([
                { "type": "Percent", "value": 100, "periodSeconds": 15 }
            ]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deployment with no strategy/replicas must have all 6 defaults applied.
    /// This is the bug that caused kcm to crash: "unexpected deployment strategy type: \"\"".
    /// If apply_defaults is not called, these fields are absent and controllers fail.
    #[test]
    fn deployment_defaults_applied() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {}
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(1.into()),
            "spec.replicas must default to 1"
        );
        assert_eq!(
            obj["spec"]["revisionHistoryLimit"],
            serde_json::Value::Number(10.into()),
            "spec.revisionHistoryLimit must default to 10"
        );
        assert_eq!(
            obj["spec"]["progressDeadlineSeconds"],
            serde_json::Value::Number(600.into()),
            "spec.progressDeadlineSeconds must default to 600"
        );
        assert_eq!(
            obj["spec"]["strategy"]["type"], "RollingUpdate",
            "spec.strategy.type must default to RollingUpdate"
        );
        assert_eq!(
            obj["spec"]["strategy"]["rollingUpdate"]["maxSurge"], "25%",
            "spec.strategy.rollingUpdate.maxSurge must default to 25%"
        );
        assert_eq!(
            obj["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"], "25%",
            "spec.strategy.rollingUpdate.maxUnavailable must default to 25%"
        );
    }

    /// Existing values must not be overwritten — apply_defaults is idempotent.
    /// If this test fails after reverting the idempotency guards, controllers that
    /// set Recreate strategy would silently have it overwritten to RollingUpdate.
    #[test]
    fn deployment_defaults_idempotent() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test" },
            "spec": {
                "replicas": 3,
                "strategy": { "type": "Recreate" }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(3.into()),
            "spec.replicas must not be overwritten when already set"
        );
        assert_eq!(
            obj["spec"]["strategy"]["type"], "Recreate",
            "spec.strategy.type must not be overwritten when already set"
        );
        // Recreate strategy: rollingUpdate sub-object must not be injected
        assert!(
            obj["spec"]["strategy"]["rollingUpdate"].is_null(),
            "rollingUpdate must not be added when strategy is Recreate"
        );
    }

    /// Deployment without spec.selector must have it defaulted from template labels.
    ///
    /// Upstream kube-apiserver rejects Deployments without spec.selector; u7s doesn't
    /// validate this. The KCM deployment-controller calls CloneSelectorAndAddLabel on
    /// spec.selector and panics with a nil-pointer dereference, killing the entire KCM
    /// process (including the serviceaccount-controller). This causes all new namespaces
    /// to never get a default ServiceAccount, breaking sonobuoy job tests.
    #[test]
    fn deployment_without_selector_gets_default_from_template_labels() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "test", "version": "v1" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "test", "version": "v1" } }),
            "spec.selector must be defaulted from template labels — nil selector panics the KCM deployment-controller"
        );
    }

    /// A Deployment with neither spec.selector nor template labels must be rejected.
    ///
    /// Upstream kube-apiserver returns 422 for this case. Without rejection, u7s stores
    /// the object, KCM reads it, CloneSelectorAndAddLabel(nil) panics, and the entire
    /// KCM process dies — taking the serviceaccount-controller with it.
    #[test]
    fn deployment_without_selector_or_labels_rejected() {
        let obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "bad", "namespace": "test" },
            "spec": {
                "template": { "spec": { "containers": [] } }
            }
        });

        let result = validate_resource("apps", "deployments", &obj);
        assert!(
            result.is_err(),
            "Deployment with no selector and no template labels must be rejected — \
             nil selector panics KCM deployment-controller"
        );
        assert!(
            result.unwrap_err().contains("spec.selector"),
            "error message must mention spec.selector"
        );
    }

    /// A Deployment with an explicit spec.selector must pass validation.
    #[test]
    fn deployment_with_valid_selector_passes_validation() {
        let obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "ok", "namespace": "test" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": { "spec": { "containers": [] } }
            }
        });

        assert!(
            validate_resource("apps", "deployments", &obj).is_ok(),
            "Deployment with explicit spec.selector must pass validation"
        );
    }

    /// apply_defaults + validate_resource must succeed for Deployments with template labels.
    ///
    /// Verifies the full write-path pipeline: selector is defaulted from template labels,
    /// then validation confirms the selector is present.
    #[test]
    fn deployment_selector_defaulted_then_passes_validation() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "test" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);
        assert!(
            validate_resource("apps", "deployments", &obj).is_ok(),
            "Deployment with template labels must pass validation after selector is defaulted"
        );
    }

    /// Existing spec.selector must not be overwritten.
    ///
    /// A Deployment may use a selector that's a strict subset of the template labels.
    /// Overwriting it would break the controller's ability to identify owned ReplicaSets.
    #[test]
    fn deployment_existing_selector_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test" },
            "spec": {
                "selector": { "matchLabels": { "app": "my-app" } },
                "template": {
                    "metadata": { "labels": { "app": "my-app", "extra": "label" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "my-app" } }),
            "existing spec.selector must not be overwritten — changing it breaks ReplicaSet ownership"
        );
    }

    /// Unknown resources must be passed through unchanged.
    /// If apply_defaults modifies unknown resources, it would corrupt arbitrary objects.
    #[test]
    fn unknown_resource_noop() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "test" },
            "data": { "key": "value" }
        });
        let original = obj.clone();

        apply_defaults("", "configmaps", &mut obj);

        assert_eq!(obj, original, "unknown resources must not be modified");
    }

    // ---------------------------------------------------------------------------
    // Service IP field defaulting
    // ---------------------------------------------------------------------------

    /// Service with clusterIP set must get ipFamilies=["IPv4"], ipFamilyPolicy="SingleStack",
    /// and clusterIPs=[clusterIP].
    ///
    /// Without these defaults, KCM's endpoints-controller panics at IPFamilies[0]
    /// (index into nil slice).  This test fails if default_service_ip_fields is removed
    /// or if it stops populating the required fields.
    #[test]
    fn service_ipv4_cluster_ip_gets_defaults() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "my-svc", "namespace": "default" },
            "spec": { "clusterIP": "10.96.0.1" }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ipFamilyPolicy"], "SingleStack",
            "ipFamilyPolicy must default to SingleStack"
        );
        assert_eq!(
            obj["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "ipFamilies must default to [IPv4] for an IPv4 clusterIP"
        );
        assert_eq!(
            obj["spec"]["clusterIPs"],
            serde_json::json!(["10.96.0.1"]),
            "clusterIPs must default to [clusterIP]"
        );
    }

    /// Headless Service (clusterIP="None") must get ipFamilies=["IPv4"] but no clusterIPs.
    ///
    /// "None" is a sentinel value meaning headless; it must not appear in clusterIPs.
    #[test]
    fn service_headless_gets_ip_family_but_no_cluster_ips() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "headless", "namespace": "default" },
            "spec": { "clusterIP": "None" }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ipFamilyPolicy"], "SingleStack",
            "ipFamilyPolicy must default to SingleStack for headless service"
        );
        assert_eq!(
            obj["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "ipFamilies must default to [IPv4] for headless service"
        );
        assert!(
            obj["spec"]["clusterIPs"].is_null(),
            "clusterIPs must not be set for headless service (clusterIP=None)"
        );
    }

    /// IPv6 Service must get ipFamilies=["IPv6"].
    #[test]
    fn service_ipv6_cluster_ip_gets_ipv6_family() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "ipv6-svc", "namespace": "default" },
            "spec": { "clusterIP": "fd00::1" }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ipFamilies"],
            serde_json::json!(["IPv6"]),
            "ipFamilies must be [IPv6] for an IPv6 clusterIP (contains ':')"
        );
        assert_eq!(
            obj["spec"]["clusterIPs"],
            serde_json::json!(["fd00::1"]),
            "clusterIPs must be set to [clusterIP] for IPv6"
        );
    }

    /// Service with no clusterIP must still get ipFamilies=["IPv4"] and ipFamilyPolicy.
    #[test]
    fn service_no_cluster_ip_gets_ipv4_defaults() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "no-ip-svc", "namespace": "default" },
            "spec": { "selector": { "app": "foo" } }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(obj["spec"]["ipFamilyPolicy"], "SingleStack");
        assert_eq!(obj["spec"]["ipFamilies"], serde_json::json!(["IPv4"]));
        assert!(
            obj["spec"]["clusterIPs"].is_null(),
            "clusterIPs must not be set when clusterIP is absent"
        );
    }

    /// Existing Service fields must not be overwritten (idempotency).
    ///
    /// If idempotency breaks, a DualStack Service would have its ipFamilies
    /// overwritten to SingleStack on every update.
    #[test]
    fn service_existing_fields_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "dual-svc", "namespace": "default" },
            "spec": {
                "clusterIP": "10.96.0.1",
                "ipFamilyPolicy": "PreferDualStack",
                "ipFamilies": ["IPv4", "IPv6"],
                "clusterIPs": ["10.96.0.1", "fd00::1"]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ipFamilyPolicy"], "PreferDualStack",
            "existing ipFamilyPolicy must not be overwritten"
        );
        assert_eq!(
            obj["spec"]["ipFamilies"],
            serde_json::json!(["IPv4", "IPv6"]),
            "existing ipFamilies must not be overwritten"
        );
        assert_eq!(
            obj["spec"]["clusterIPs"],
            serde_json::json!(["10.96.0.1", "fd00::1"]),
            "existing clusterIPs must not be overwritten"
        );
    }

    // ---------------------------------------------------------------------------
    // Service port protocol defaulting
    // ---------------------------------------------------------------------------

    /// Service port with no protocol must have protocol defaulted to TCP.
    ///
    /// The endpointslice controller (KCM) reads svc.Spec.Ports[i].Protocol to fill
    /// the EndpointSlice port's Protocol field.  When Protocol is absent the slice port
    /// comes back as protocol:"" and the conformance assertion
    /// `len(endpointSlice.Ports) == len(svc.Spec.Ports)` fails because the controller
    /// drops zero-value ports.  Reverting this default will cause named-targetPort
    /// EndpointSlice tests to fail with empty slice ports.
    #[test]
    fn service_port_protocol_defaults_to_tcp_when_omitted() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "svc", "namespace": "default" },
            "spec": {
                "ports": [{ "name": "http", "port": 80, "targetPort": "example-name" }]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ports"][0]["protocol"], "TCP",
            "spec.ports[].protocol must default to TCP — absent protocol causes \
             endpointslice controller to emit protocol:'' and the slice port is dropped"
        );
    }

    /// Service port with explicit protocol must not be overwritten.
    ///
    /// A port with protocol: UDP must stay UDP; silently overwriting it to TCP would
    /// break UDP services (their EndpointSlices would advertise TCP).
    #[test]
    fn service_port_existing_protocol_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "svc", "namespace": "default" },
            "spec": {
                "ports": [{ "name": "dns", "port": 53, "protocol": "UDP" }]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ports"][0]["protocol"], "UDP",
            "existing spec.ports[].protocol must not be overwritten — changing UDP to TCP \
             breaks UDP services"
        );
    }

    // ---------------------------------------------------------------------------
    // Event timestamp normalization
    // ---------------------------------------------------------------------------

    /// Event timestamps without microseconds must be normalized to include `.000000`.
    ///
    /// client-go's MicroTime codec uses format `2006-01-02T15:04:05.000000Z07:00`
    /// and fails to parse `2017-09-20T13:49:16Z` with:
    ///   `cannot parse "Z" as ".000000"`
    /// If this normalization is removed, conformance Event lifecycle tests will fail.
    #[test]
    fn event_timestamps_normalized_to_microsecond_precision() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "lastTimestamp": "2017-09-20T13:49:16Z",
            "firstTimestamp": "2017-09-20T13:49:10Z",
            "eventTime": "2017-09-20T13:49:16Z"
        });

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj["lastTimestamp"], "2017-09-20T13:49:16.000000Z",
            "lastTimestamp must have .000000 suffix so client-go MicroTime parses it"
        );
        assert_eq!(
            obj["firstTimestamp"], "2017-09-20T13:49:10.000000Z",
            "firstTimestamp must have .000000 suffix so client-go MicroTime parses it"
        );
        assert_eq!(
            obj["eventTime"], "2017-09-20T13:49:16.000000Z",
            "eventTime must have .000000 suffix so client-go MicroTime parses it"
        );
    }

    /// Already-precise timestamps must not be modified (idempotent).
    ///
    /// If already-precise timestamps were overwritten, sub-microsecond precision
    /// from client-go (e.g. `.123456`) would be silently truncated.
    #[test]
    fn event_timestamps_already_precise_are_unchanged() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "lastTimestamp": "2017-09-20T13:49:16.123456Z",
            "firstTimestamp": "2017-09-20T13:49:10.000001Z",
            "eventTime": "2017-09-20T13:49:16.999999Z"
        });

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj["lastTimestamp"], "2017-09-20T13:49:16.123456Z",
            "existing sub-second precision must not be overwritten"
        );
        assert_eq!(
            obj["firstTimestamp"], "2017-09-20T13:49:10.000001Z",
            "existing sub-second precision must not be overwritten"
        );
        assert_eq!(
            obj["eventTime"], "2017-09-20T13:49:16.999999Z",
            "existing sub-second precision must not be overwritten"
        );
    }

    /// events.k8s.io/v1 Event eventTime without microseconds must be normalized.
    ///
    /// client-go sends eventTime in RFC3339 second precision (e.g. "2024-01-15T10:00:00Z").
    /// Without normalization to microsecond precision, client-go's MicroTime codec parses
    /// it as the zero time (0001-01-01T00:00:00Z), making every event appear to have no time.
    /// This test fails when the group check in apply_defaults excludes "events.k8s.io".
    #[test]
    fn events_k8s_io_v1_event_time_normalized_to_microsecond_precision() {
        let mut obj = serde_json::json!({
            "apiVersion": "events.k8s.io/v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "eventTime": "2024-01-15T10:00:00Z",
            "action": "Started",
            "reason": "TestReason"
        });

        apply_defaults("events.k8s.io", "events", &mut obj);

        assert_eq!(
            obj["eventTime"], "2024-01-15T10:00:00.000000Z",
            "eventTime must have .000000 suffix so client-go MicroTime parses it; \
             without normalization events.k8s.io/v1 events show 0001-01-01 as their timestamp"
        );
    }

    /// events.k8s.io/v1 Event with already-precise eventTime must not be modified.
    #[test]
    fn events_k8s_io_v1_event_time_already_precise_is_unchanged() {
        let mut obj = serde_json::json!({
            "apiVersion": "events.k8s.io/v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "eventTime": "2024-01-15T10:00:00.123456Z"
        });

        apply_defaults("events.k8s.io", "events", &mut obj);

        assert_eq!(
            obj["eventTime"], "2024-01-15T10:00:00.123456Z",
            "already-precise eventTime must not be overwritten"
        );
    }

    // ---------------------------------------------------------------------------
    // ReplicaSet defaults
    // ---------------------------------------------------------------------------

    /// A ReplicaSet with no spec.replicas must have it defaulted to 1.
    ///
    /// KCM's replicaset-controller dereferences *rs.Spec.Replicas unconditionally.
    /// Nil causes a nil-pointer panic that kills the entire KCM process.
    #[test]
    fn replicaset_replicas_defaults_to_1() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {}
            }
        });

        apply_defaults("apps", "replicasets", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(1.into()),
            "spec.replicas must default to 1 — nil replicas panics KCM replicaset-controller"
        );
    }

    /// Existing spec.replicas on a ReplicaSet must not be overwritten.
    #[test]
    fn replicaset_existing_replicas_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": { "replicas": 3 }
        });

        apply_defaults("apps", "replicasets", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(3.into()),
            "existing spec.replicas must not be overwritten"
        );
    }

    /// ReplicaSet without spec.selector must have it defaulted from template labels.
    ///
    /// Conformance workload tests create ReplicaSets without spec.selector, relying
    /// on the apiserver to default it from spec.template.metadata.labels (matching
    /// real kube behavior). Without this default, validate_resource rejects the
    /// object with 'spec.selector is required', blocking all RS-based workload tests.
    #[test]
    fn replicaset_without_selector_gets_default_from_template_labels() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "test", "version": "v1" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "replicasets", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "test", "version": "v1" } }),
            "spec.selector must be defaulted from template labels — missing selector causes \
             validate_resource to reject the object with 'spec.selector is required'"
        );
    }

    /// ReplicaSet: existing spec.selector must not be overwritten.
    ///
    /// A ReplicaSet may specify a selector that is a strict subset of template labels.
    /// Overwriting it would change which Pods the RS considers owned.
    #[test]
    fn replicaset_existing_selector_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "my-app" } },
                "template": {
                    "metadata": { "labels": { "app": "my-app", "extra": "label" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "replicasets", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "my-app" } }),
            "existing spec.selector must not be overwritten — changing it breaks Pod ownership"
        );
    }

    /// ReplicaSet with template labels passes validation after selector is defaulted.
    ///
    /// Verifies the full write-path pipeline: selector is defaulted then validation passes.
    #[test]
    fn replicaset_selector_defaulted_then_passes_validation() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "test" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "replicasets", &mut obj);
        assert!(
            validate_resource("apps", "replicasets", &obj).is_ok(),
            "ReplicaSet with template labels must pass validation after selector is defaulted"
        );
    }

    // ---------------------------------------------------------------------------
    // StatefulSet defaults
    // ---------------------------------------------------------------------------

    /// A StatefulSet with no spec fields must have all four defaults applied.
    ///
    /// KCM's statefulset-controller dereferences *ss.Spec.Replicas and indexes
    /// UpdateStrategy fields without nil checks.
    #[test]
    fn statefulset_defaults_applied() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {}
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(1.into()),
            "spec.replicas must default to 1"
        );
        assert_eq!(
            obj["spec"]["podManagementPolicy"], "OrderedReady",
            "spec.podManagementPolicy must default to OrderedReady"
        );
        assert_eq!(
            obj["spec"]["updateStrategy"]["type"], "RollingUpdate",
            "spec.updateStrategy.type must default to RollingUpdate"
        );
        assert_eq!(
            obj["spec"]["revisionHistoryLimit"],
            serde_json::Value::Number(10.into()),
            "spec.revisionHistoryLimit must default to 10"
        );
    }

    /// StatefulSet without spec.selector must have it defaulted from template labels.
    ///
    /// Conformance workload tests create StatefulSets without spec.selector, relying
    /// on the apiserver to default it from spec.template.metadata.labels (matching
    /// real kube behavior). Without this default, validate_resource rejects the
    /// object with 'spec.selector is required', blocking all SS-based workload tests.
    #[test]
    fn statefulset_without_selector_gets_default_from_template_labels() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "test", "tier": "db" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "test", "tier": "db" } }),
            "spec.selector must be defaulted from template labels — missing selector causes \
             validate_resource to reject the object with 'spec.selector is required'"
        );
    }

    /// StatefulSet: existing spec.selector must not be overwritten.
    ///
    /// A StatefulSet may specify a selector that is a strict subset of template labels.
    /// Overwriting it would change which Pods the SS considers owned.
    #[test]
    fn statefulset_existing_selector_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "my-db" } },
                "template": {
                    "metadata": { "labels": { "app": "my-db", "extra": "label" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "app": "my-db" } }),
            "existing spec.selector must not be overwritten — changing it breaks Pod ownership"
        );
    }

    /// StatefulSet with template labels passes validation after selector is defaulted.
    ///
    /// Verifies the full write-path pipeline: selector is defaulted then validation passes.
    #[test]
    fn statefulset_selector_defaulted_then_passes_validation() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "test" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);
        assert!(
            validate_resource("apps", "statefulsets", &obj).is_ok(),
            "StatefulSet with template labels must pass validation after selector is defaulted"
        );
    }

    /// Existing StatefulSet fields must not be overwritten.
    #[test]
    fn statefulset_existing_values_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "replicas": 5,
                "podManagementPolicy": "Parallel",
                "updateStrategy": { "type": "OnDelete" },
                "revisionHistoryLimit": 3
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);

        assert_eq!(obj["spec"]["replicas"], serde_json::Value::Number(5.into()));
        assert_eq!(obj["spec"]["podManagementPolicy"], "Parallel");
        assert_eq!(obj["spec"]["updateStrategy"]["type"], "OnDelete");
        assert_eq!(
            obj["spec"]["revisionHistoryLimit"],
            serde_json::Value::Number(3.into())
        );
    }

    /// StatefulSet with RollingUpdate strategy must have rollingUpdate.partition defaulted to 0.
    ///
    /// The e2e Scale() function reads ss.Spec.UpdateStrategy.RollingUpdate.Partition and
    /// nil-derefs when RollingUpdate is nil, causing a PANIC in AfterEach. Real kube-apiserver
    /// always injects partition=0 via its defaulting admission plugin. Without this default,
    /// any e2e test that calls Scale() on a StatefulSet will PANIC and abort the test process.
    #[test]
    fn rollingupdate_partition_default_prevents_nil_deref_in_scale() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {}
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);

        assert_eq!(
            obj["spec"]["updateStrategy"]["rollingUpdate"]["partition"],
            serde_json::Value::Number(0.into()),
            "spec.updateStrategy.rollingUpdate.partition must default to 0 — \
             Scale() nil-derefs RollingUpdate when the field is absent, \
             causing a PANIC that aborts the test process"
        );
    }

    /// StatefulSet with OnDelete strategy must NOT get rollingUpdate.partition injected.
    ///
    /// partition only applies to RollingUpdate; injecting it for OnDelete would be wrong.
    #[test]
    fn statefulset_ondelete_strategy_does_not_get_rolling_update_partition() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "updateStrategy": { "type": "OnDelete" }
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);

        assert!(
            obj["spec"]["updateStrategy"]["rollingUpdate"].is_null(),
            "rollingUpdate must not be injected for OnDelete strategy — \
             OnDelete has no rolling-update semantics"
        );
    }

    /// Existing rollingUpdate.partition on a StatefulSet must not be overwritten.
    ///
    /// A canary update sets partition=N to hold back pods. Overwriting it to 0
    /// would release all pods at once, defeating the canary rollout strategy.
    #[test]
    fn statefulset_existing_rolling_update_partition_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "updateStrategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": { "partition": 3 }
                }
            }
        });

        apply_defaults("apps", "statefulsets", &mut obj);

        assert_eq!(
            obj["spec"]["updateStrategy"]["rollingUpdate"]["partition"],
            serde_json::Value::Number(3.into()),
            "existing partition must not be overwritten — resetting a canary partition \
             to 0 would release all pods at once, defeating the staged rollout"
        );
    }

    // ---------------------------------------------------------------------------
    // ReplicationController defaults
    // ---------------------------------------------------------------------------

    /// A nil RC selector must default to the template labels; otherwise the RC controller
    /// cannot match its own pods and creates them without bound (conformance RC runaway).
    ///
    /// The conformance helper `newRC` (test/e2e/apps/rc.go) creates an RC with spec.selector=nil,
    /// relying on this defaulting. Without it the apiserver stores an empty selector; KCM sees
    /// active=0 forever and created 179 pods in 8 s on the live stack before the node saturated.
    ///
    /// RC selector is a FLAT map (not matchLabels) — wrapping would break KCM's selector parse.
    #[test]
    fn rc_selector_defaults_from_template_labels_else_kcm_runaway() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": {
                    "metadata": { "labels": { "name": "my-hostname-basic" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("", "replicationcontrollers", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "name": "my-hostname-basic" }),
            "spec.selector must be a flat map defaulted from template labels — \
             an empty RC selector causes KCM to see active=0 forever and create \
             pods without bound (conformance RC runaway)"
        );
        // Must NOT be wrapped in matchLabels (RC uses equality-based selector).
        assert!(
            obj["spec"]["selector"]["matchLabels"].is_null(),
            "RC selector must be flat, not wrapped in matchLabels — \
             matchLabels wrapping makes KCM fail to parse the selector as an RC equality selector"
        );
    }

    /// RC spec.replicas must default to 1 when absent.
    ///
    /// KCM's RC controller dereferences *rc.Spec.Replicas; nil causes a nil-pointer panic.
    #[test]
    fn rc_replicas_defaults_to_1() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "app": "test" },
                "template": {}
            }
        });

        apply_defaults("", "replicationcontrollers", &mut obj);

        assert_eq!(
            obj["spec"]["replicas"],
            serde_json::Value::Number(1.into()),
            "spec.replicas must default to 1 — nil replicas panics KCM RC controller"
        );
    }

    /// An existing RC spec.selector must not be overwritten.
    ///
    /// Overwriting a user-supplied selector would change which pods the RC considers owned,
    /// causing it to orphan existing pods and create new ones — effectively a runaway.
    #[test]
    fn rc_existing_selector_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "app": "my-explicit-selector" },
                "template": {
                    "metadata": { "labels": { "app": "my-explicit-selector", "extra": "label" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("", "replicationcontrollers", &mut obj);

        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "app": "my-explicit-selector" }),
            "existing RC spec.selector must not be overwritten — \
             changing it would cause the RC controller to orphan owned pods"
        );
    }

    // ---------------------------------------------------------------------------
    // DaemonSet defaults
    // ---------------------------------------------------------------------------

    /// A DaemonSet with no updateStrategy must have type, maxUnavailable, and maxSurge defaulted.
    #[test]
    fn daemonset_defaults_applied() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {}
        });

        apply_defaults("apps", "daemonsets", &mut obj);

        assert_eq!(
            obj["spec"]["updateStrategy"]["type"], "RollingUpdate",
            "spec.updateStrategy.type must default to RollingUpdate"
        );
        assert_eq!(
            obj["spec"]["updateStrategy"]["rollingUpdate"]["maxUnavailable"],
            serde_json::Value::Number(1.into()),
            "rollingUpdate.maxUnavailable must default to 1"
        );
        assert_eq!(
            obj["spec"]["updateStrategy"]["rollingUpdate"]["maxSurge"],
            serde_json::Value::Number(0.into()),
            "rollingUpdate.maxSurge must default to 0"
        );
        assert_eq!(
            obj["spec"]["revisionHistoryLimit"],
            serde_json::Value::Number(10.into()),
            "spec.revisionHistoryLimit must default to 10"
        );
    }

    /// Existing DaemonSet updateStrategy must not be overwritten.
    #[test]
    fn daemonset_existing_values_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "updateStrategy": { "type": "OnDelete" },
                "revisionHistoryLimit": 5
            }
        });

        apply_defaults("apps", "daemonsets", &mut obj);

        assert_eq!(obj["spec"]["updateStrategy"]["type"], "OnDelete");
        assert!(
            obj["spec"]["updateStrategy"]["rollingUpdate"].is_null(),
            "rollingUpdate must not be injected for OnDelete strategy"
        );
        assert_eq!(
            obj["spec"]["revisionHistoryLimit"],
            serde_json::Value::Number(5.into())
        );
    }

    /// series.lastObservedTime without microseconds must be normalized.
    ///
    /// The Kubernetes Event controller PATCHes series.lastObservedTime via merge-patch.
    /// If the timestamp is stored without microsecond precision (e.g. "2024-01-01T00:00:01Z"),
    /// client-go's MicroTime codec fails to parse it on re-read with
    ///   "cannot parse Z as .000000"
    /// and treats it as a zero MicroTime.  This makes every event occurrence appear as a
    /// new event (deduplication breaks) — exactly what core_events.go:144 detects.
    #[test]
    fn event_series_last_observed_time_normalized_to_microsecond_precision() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "series": {
                "count": 5,
                "lastObservedTime": "2024-01-01T00:00:01Z"
            }
        });

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj["series"]["lastObservedTime"], "2024-01-01T00:00:01.000000Z",
            "series.lastObservedTime must have .000000 suffix so client-go MicroTime \
             can parse it; without this the Event controller sees a zero lastObservedTime \
             and treats every occurrence as a new event (deduplication breaks)"
        );
        assert_eq!(
            obj["series"]["count"], 5,
            "series.count must be unchanged by timestamp normalization"
        );
    }

    /// series.lastObservedTime with microsecond precision must not be modified.
    ///
    /// Idempotent: already-precise values must survive repeated apply_defaults calls.
    #[test]
    fn event_series_last_observed_time_already_precise_is_unchanged() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "series": {
                "count": 3,
                "lastObservedTime": "2024-01-01T00:00:01.123456Z"
            }
        });

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj["series"]["lastObservedTime"], "2024-01-01T00:00:01.123456Z",
            "already-precise series.lastObservedTime must not be overwritten"
        );
    }

    /// Events with no dual-shape fields at all (no timestamps, message/note,
    /// involvedObject/regarding, source/deprecatedSource, count/deprecatedCount) must not be
    /// modified. Prevents panics when optional fields are absent.
    #[test]
    fn event_without_timestamps_is_unchanged() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "reason": "Started"
        });
        let original = obj.clone();

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj, original,
            "Event without timestamp fields must not be modified"
        );
    }

    // ---------------------------------------------------------------------------
    // Event core/v1 <-> events.k8s.io/v1 field-shape translation
    // ---------------------------------------------------------------------------

    /// An Event created via events.k8s.io/v1 (which sets `regarding`/`note`, never the
    /// core/v1-only `involvedObject`/`message`) must be readable via core/v1 with the
    /// core/v1 field names populated — matching upstream's Convert_v1_Event_To_core_Event.
    ///
    /// Without this, a core/v1 client (e.g. `kubectl get events`, or the sig-instrumentation
    /// Events API conformance test's coreClient) sees an empty involvedObject/message for
    /// any Event written via client-go's newer EventsV1 recorder.
    #[test]
    fn events_k8s_io_event_readable_via_core_v1_shape() {
        let mut obj = serde_json::json!({
            "apiVersion": "events.k8s.io/v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "regarding": { "kind": "Pod", "namespace": "default", "name": "my-pod" },
            "note": "This is my-event",
            "reportingController": "test-controller",
            "reportingInstance": "test-node"
        });

        apply_defaults("events.k8s.io", "events", &mut obj);

        assert_eq!(
            obj["involvedObject"]["name"], "my-pod",
            "involvedObject must be populated from regarding — a core/v1 client reading an \
             events.k8s.io/v1-written Event must still see which object the event is about"
        );
        assert_eq!(
            obj["message"], "This is my-event",
            "message must be populated from note — a core/v1 client must see the same \
             human-readable description an events.k8s.io/v1 client wrote"
        );
    }

    /// The reverse direction: an Event created via core/v1 (which sets `involvedObject`/
    /// `message`, never `regarding`/`note`) must be readable via events.k8s.io/v1 with its
    /// field names populated — matching upstream's Convert_core_Event_To_v1_Event.
    #[test]
    fn core_v1_event_readable_via_events_k8s_io_shape() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "involvedObject": { "kind": "Pod", "namespace": "default", "name": "my-pod" },
            "message": "This is my-event"
        });

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj["regarding"]["name"], "my-pod",
            "regarding must be populated from involvedObject — an events.k8s.io/v1 client \
             reading a core/v1-written Event must still see which object the event is about"
        );
        assert_eq!(
            obj["note"], "This is my-event",
            "note must be populated from message — an events.k8s.io/v1 client must see the \
             same human-readable description a core/v1 client wrote"
        );
    }

    /// translate_event_shape must never invent a `source` from `reportingController` in the
    /// object body — upstream's Convert_v1_Event_To_core_Event maps `source` from the
    /// separate `deprecatedSource` field only, never from `reportingController`. Fabricating
    /// that mapping here would make an Event's `source` differ from what real kube-apiserver
    /// would ever produce for the same input.
    ///
    /// (The `source=` field *selector* still matches via `reportingController` as a
    /// selector-only fallback — see `event_matches_field_selector` in handlers/pods.rs — but
    /// that must not be confused with populating the field in the served object body.)
    #[test]
    fn translate_event_shape_does_not_fabricate_source_from_reporting_controller() {
        let mut obj = serde_json::json!({
            "apiVersion": "events.k8s.io/v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "reportingController": "test-controller",
            "reportingInstance": "test-node"
        });

        apply_defaults("events.k8s.io", "events", &mut obj);

        assert!(
            obj.get("source").is_none(),
            "source must stay absent unless deprecatedSource was explicitly set — upstream \
             never backfills source from reportingController in the object body"
        );
    }

    /// Existing dual-shape values must never be overwritten by translation — idempotent
    /// across repeated apply_defaults calls (e.g. GET then PATCH then GET again).
    #[test]
    fn translate_event_shape_does_not_overwrite_existing_values() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-event", "namespace": "default" },
            "involvedObject": { "name": "core-pod" },
            "regarding": { "name": "events-pod" },
            "message": "core message",
            "note": "events note"
        });

        apply_defaults("", "events", &mut obj);

        assert_eq!(
            obj["involvedObject"]["name"], "core-pod",
            "an explicitly-set involvedObject must not be overwritten by regarding"
        );
        assert_eq!(
            obj["regarding"]["name"], "events-pod",
            "an explicitly-set regarding must not be overwritten by involvedObject"
        );
        assert_eq!(obj["message"], "core message");
        assert_eq!(obj["note"], "events note");
    }

    // ---------------------------------------------------------------------------
    // Regression tests: spec.type defaulting
    // ---------------------------------------------------------------------------

    /// A Service with no spec.type must have spec.type defaulted to "ClusterIP".
    ///
    /// Sonobuoy conformance tests create Services without a type and assert the
    /// response carries type=ClusterIP. Without this default, the field comes back
    /// empty and the tests fail with "unexpected Spec.Type () for service, expected ClusterIP".
    #[test]
    fn service_without_type_defaults_to_cluster_ip() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "my-svc", "namespace": "default" },
            "spec": { "selector": { "app": "foo" }, "ports": [{ "port": 80 }] }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["type"], "ClusterIP",
            "spec.type must default to ClusterIP — sonobuoy checks the field and fails if empty"
        );
    }

    /// An existing spec.type must not be overwritten by defaulting.
    ///
    /// If idempotency breaks here, a NodePort service would be silently downgraded
    /// to ClusterIP on every read, breaking external traffic routing.
    #[test]
    fn service_existing_type_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "np-svc", "namespace": "default" },
            "spec": {
                "type": "NodePort",
                "ports": [{ "port": 80, "nodePort": 31000 }]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["type"], "NodePort",
            "existing spec.type must not be overwritten — changing NodePort to ClusterIP breaks external access"
        );
        // NodePort must not be re-allocated when already set.
        assert_eq!(
            obj["spec"]["ports"][0]["nodePort"], 31000,
            "existing nodePort must not be overwritten"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: NodePort allocation
    // ---------------------------------------------------------------------------

    /// A NodePort Service with no nodePort on its ports must have one assigned.
    ///
    /// Sonobuoy tests create NodePort services and assert Spec.Ports[0].NodePort != 0.
    /// Without allocation, NodePort comes back as 0 and the tests fail.
    #[test]
    fn nodeport_service_gets_node_port_assigned() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "np-svc", "namespace": "default" },
            "spec": {
                "type": "NodePort",
                "ports": [{ "port": 80, "protocol": "TCP" }]
            }
        });

        apply_defaults("", "services", &mut obj);

        let node_port = obj["spec"]["ports"][0]["nodePort"]
            .as_u64()
            .expect("nodePort must be a number after defaulting");
        assert!(
            (30000..=32767).contains(&node_port),
            "nodePort must be in [30000, 32767], got {node_port} — sonobuoy checks for non-zero nodePort"
        );
    }

    /// Two ports on a NodePort service must each get a distinct nodePort.
    ///
    /// If both ports share the same nodePort, the OS will reject one bind and
    /// kube-proxy cannot set up the iptables rule for the second port.
    #[test]
    fn nodeport_service_multiple_ports_get_distinct_node_ports() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "np-multi", "namespace": "default" },
            "spec": {
                "type": "NodePort",
                "ports": [
                    { "port": 80, "protocol": "TCP" },
                    { "port": 443, "protocol": "TCP" }
                ]
            }
        });

        apply_defaults("", "services", &mut obj);

        let np0 = obj["spec"]["ports"][0]["nodePort"]
            .as_u64()
            .expect("port 0 must have nodePort");
        let np1 = obj["spec"]["ports"][1]["nodePort"]
            .as_u64()
            .expect("port 1 must have nodePort");
        assert_ne!(np0, np1, "each port must receive a distinct nodePort — duplicates break kube-proxy iptables rules");
        assert!((30000..=32767).contains(&np0));
        assert!((30000..=32767).contains(&np1));
    }

    /// LoadBalancer services also need NodePorts (cloud LBs route via nodePort internally).
    #[test]
    fn loadbalancer_service_gets_node_port_assigned() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "lb-svc", "namespace": "default" },
            "spec": {
                "type": "LoadBalancer",
                "ports": [{ "port": 80 }]
            }
        });

        apply_defaults("", "services", &mut obj);

        let node_port = obj["spec"]["ports"][0]["nodePort"]
            .as_u64()
            .expect("LoadBalancer port must have nodePort after defaulting");
        assert!(
            (30000..=32767).contains(&node_port),
            "LoadBalancer nodePort must be in [30000, 32767], got {node_port}"
        );
    }

    /// ClusterIP service must NOT get a nodePort injected.
    ///
    /// ClusterIP services have no node-level port mapping. Injecting a nodePort
    /// would confuse clients and waste ports from the NodePort range.
    #[test]
    fn clusterip_service_does_not_get_node_port() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "ci-svc", "namespace": "default" },
            "spec": {
                "type": "ClusterIP",
                "ports": [{ "port": 80 }]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert!(
            obj["spec"]["ports"][0]["nodePort"].is_null(),
            "ClusterIP service must not have a nodePort — injecting one wastes ports and confuses clients"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: ExternalName ClusterIP
    // ---------------------------------------------------------------------------

    /// An ExternalName service must NOT get ipFamilies, ipFamilyPolicy, or clusterIPs.
    ///
    /// ExternalName services resolve to an external DNS name; they have no ClusterIP.
    /// Conformance tests fail with "unexpected Spec.ClusterIP (10.96.x.x) for ExternalName service"
    /// if we apply ClusterIP-family defaults to ExternalName.
    #[test]
    fn external_name_service_gets_no_ip_family_defaults() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "ext-svc", "namespace": "default" },
            "spec": {
                "type": "ExternalName",
                "externalName": "example.com"
            }
        });

        apply_defaults("", "services", &mut obj);

        assert!(
            obj["spec"]["ipFamilyPolicy"].is_null(),
            "ExternalName service must not have ipFamilyPolicy — it has no cluster IP"
        );
        assert!(
            obj["spec"]["ipFamilies"].is_null(),
            "ExternalName service must not have ipFamilies — it has no cluster IP"
        );
        assert_eq!(
            obj["spec"]["clusterIPs"],
            serde_json::json!([]),
            "ExternalName service must have clusterIPs cleared to [] — it has no cluster IP"
        );
        assert_eq!(
            obj["spec"]["clusterIP"],
            serde_json::Value::String(String::new()),
            "ExternalName service must have clusterIP cleared to empty string — it has no cluster IP"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: PVC status.phase defaulting
    // ---------------------------------------------------------------------------

    /// A PVC created without status.phase must have it initialized to "Pending".
    ///
    /// The real kube-apiserver initializes PVC status.phase to "Pending" on create.
    /// Without this default, controllers and conformance tests that check
    /// `phase == "Pending"` before binding will fail — they expect the field immediately
    /// after create. If this test fails after reverting the fix, phase will be absent
    /// and those controller checks will fail.
    #[test]
    fn pvc_status_phase_defaults_to_pending() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "my-pvc", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "1Gi" } }
            }
        });

        apply_defaults("", "persistentvolumeclaims", &mut obj);

        assert_eq!(
            obj["status"]["phase"], "Pending",
            "status.phase must be initialized to Pending on create — \
             controllers that check phase == Pending before binding will fail if absent"
        );
    }

    /// A PVC whose status.phase is already set must not have it overwritten.
    ///
    /// apply_defaults must be idempotent: a Bound PVC that goes through the write
    /// path again (e.g. on update) must not have its phase reset to Pending.
    #[test]
    fn pvc_existing_status_phase_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "my-pvc", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "1Gi" } }
            },
            "status": { "phase": "Bound" }
        });

        apply_defaults("", "persistentvolumeclaims", &mut obj);

        assert_eq!(
            obj["status"]["phase"], "Bound",
            "existing status.phase must not be overwritten — resetting Bound to Pending \
             would break controllers that track binding state"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: PV/PVC spec.volumeMode defaulting
    // ---------------------------------------------------------------------------

    /// A PVC created without spec.volumeMode must have it defaulted to "Filesystem".
    ///
    /// kubelet cannot mount a PV/PVC without volumeMode set — this default protects
    /// nearly every hand-written manifest from FailedMount. Without it, kubelet's
    /// desired_state_of_world_populator rejects the volume with "cannot get
    /// volumeMode for volume", and the pod mounting it stays Pending forever.
    #[test]
    fn pvc_volume_mode_defaults_to_filesystem() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "my-pvc", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "1Gi" } }
            }
        });

        apply_defaults("", "persistentvolumeclaims", &mut obj);

        assert_eq!(
            obj["spec"]["volumeMode"], "Filesystem",
            "spec.volumeMode must default to Filesystem — kubelet cannot mount a PVC \
             without volumeMode set, and the pod mounting it stays Pending forever"
        );
    }

    /// A PVC whose spec.volumeMode is already set must not have it overwritten.
    ///
    /// A raw-block PVC (volumeMode: Block) silently defaulted to Filesystem would
    /// fail to mount as a block device.
    #[test]
    fn pvc_existing_volume_mode_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "my-pvc", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "1Gi" } },
                "volumeMode": "Block"
            }
        });

        apply_defaults("", "persistentvolumeclaims", &mut obj);

        assert_eq!(
            obj["spec"]["volumeMode"], "Block",
            "existing spec.volumeMode must not be overwritten — a raw-block PVC \
             defaulted to Filesystem would fail to mount as a block device"
        );
    }

    /// A PV created without spec.volumeMode must have it defaulted to "Filesystem",
    /// and status.phase defaulted to "Pending" (matching upstream
    /// SetDefaults_PersistentVolume).
    ///
    /// kubelet cannot mount a PV/PVC without volumeMode set — this default protects
    /// nearly every hand-written manifest from FailedMount. Before this fix,
    /// apply_defaults had zero dispatch arm for persistentvolumes, so this field was
    /// never defaulted; kubelet's desired_state_of_world_populator failed with
    /// "cannot get volumeMode for volume", leaving the mounting pod Pending forever.
    #[test]
    fn pv_volume_mode_defaults_to_filesystem() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": { "name": "my-pv" },
            "spec": {
                "capacity": { "storage": "1Gi" },
                "accessModes": ["ReadWriteOnce"],
                "local": { "path": "/mnt/data" }
            }
        });

        apply_defaults("", "persistentvolumes", &mut obj);

        assert_eq!(
            obj["spec"]["volumeMode"], "Filesystem",
            "spec.volumeMode must default to Filesystem — kubelet cannot mount a PV \
             without volumeMode set, and the pod mounting it stays Pending forever"
        );
        assert_eq!(
            obj["status"]["phase"], "Pending",
            "status.phase must default to Pending on create, matching upstream \
             SetDefaults_PersistentVolume"
        );
    }

    /// A PV whose spec.volumeMode and status.phase are already set must not have
    /// them overwritten.
    #[test]
    fn pv_existing_volume_mode_and_phase_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": { "name": "my-pv" },
            "spec": {
                "capacity": { "storage": "1Gi" },
                "accessModes": ["ReadWriteOnce"],
                "local": { "path": "/mnt/data" },
                "volumeMode": "Block"
            },
            "status": { "phase": "Bound" }
        });

        apply_defaults("", "persistentvolumes", &mut obj);

        assert_eq!(
            obj["spec"]["volumeMode"], "Block",
            "existing spec.volumeMode must not be overwritten"
        );
        assert_eq!(
            obj["status"]["phase"], "Bound",
            "existing status.phase must not be overwritten — resetting Bound to \
             Pending would break controllers that track binding state"
        );
    }

    /// A CSIDriver whose manifest omits spec.requiresRepublish (as most real-world
    /// installs do, relying on apiserver defaulting) must have it defaulted to false,
    /// along with the rest of upstream `SetDefaults_CSIDriver`'s pointer-typed fields.
    ///
    /// Before this fix, apply_defaults had zero dispatch arm for csidrivers, so
    /// requiresRepublish stayed null. A live repro against csi-hostpath showed this
    /// crash kubelet: `pkg/volume/csi/csi_plugin.go`'s `RequiresRemount` unconditionally
    /// dereferences `*csiDriver.Spec.RequiresRepublish`, so a nil value SIGSEGVs the
    /// whole kubelet process (goroutine panic, `status=2/INVALIDARGUMENT` exit) every
    /// time it processes a pod using that CSI volume — crash-looping kubelet and
    /// blocking every pod on the node, not just the one using the CSI volume.
    #[test]
    fn csidriver_pointer_fields_default_when_absent() {
        let mut obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSIDriver",
            "metadata": { "name": "csi-hostpath.example.com" },
            "spec": {}
        });

        apply_defaults("storage.k8s.io", "csidrivers", &mut obj);

        assert_eq!(
            obj["spec"]["requiresRepublish"],
            serde_json::Value::Bool(false),
            "spec.requiresRepublish must default to false — left null, kubelet's \
             csiPlugin.RequiresRemount panics on an unconditional pointer dereference \
             and crash-loops"
        );
        assert_eq!(
            obj["spec"]["attachRequired"],
            serde_json::Value::Bool(true),
            "spec.attachRequired must default to true, matching upstream SetDefaults_CSIDriver"
        );
        assert_eq!(
            obj["spec"]["podInfoOnMount"],
            serde_json::Value::Bool(false),
            "spec.podInfoOnMount must default to false, matching upstream SetDefaults_CSIDriver"
        );
        assert_eq!(
            obj["spec"]["storageCapacity"],
            serde_json::Value::Bool(false),
            "spec.storageCapacity must default to false, matching upstream SetDefaults_CSIDriver"
        );
        assert_eq!(
            obj["spec"]["fsGroupPolicy"], "ReadWriteOnceWithFSTypeFSGroupPolicy",
            "spec.fsGroupPolicy must default to ReadWriteOnceWithFSTypeFSGroupPolicy, \
             matching upstream SetDefaults_CSIDriver"
        );
        assert_eq!(
            obj["spec"]["volumeLifecycleModes"],
            serde_json::json!(["Persistent"]),
            "spec.volumeLifecycleModes must default to [\"Persistent\"], matching upstream \
             SetDefaults_CSIDriver"
        );
    }

    /// A CSIDriver with explicit values for these fields must not have them overwritten.
    #[test]
    fn csidriver_existing_pointer_fields_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSIDriver",
            "metadata": { "name": "csi-hostpath.example.com" },
            "spec": {
                "requiresRepublish": true,
                "attachRequired": false,
                "podInfoOnMount": true,
                "storageCapacity": true,
                "fsGroupPolicy": "None",
                "volumeLifecycleModes": ["Ephemeral"]
            }
        });

        apply_defaults("storage.k8s.io", "csidrivers", &mut obj);

        assert_eq!(
            obj["spec"]["requiresRepublish"],
            serde_json::Value::Bool(true),
            "existing spec.requiresRepublish must not be overwritten"
        );
        assert_eq!(
            obj["spec"]["attachRequired"],
            serde_json::Value::Bool(false),
            "existing spec.attachRequired must not be overwritten"
        );
        assert_eq!(
            obj["spec"]["fsGroupPolicy"], "None",
            "existing spec.fsGroupPolicy must not be overwritten"
        );
        assert_eq!(
            obj["spec"]["volumeLifecycleModes"],
            serde_json::json!(["Ephemeral"]),
            "existing non-empty spec.volumeLifecycleModes must not be overwritten"
        );
    }

    /// A StorageClass whose manifest omits reclaimPolicy/volumeBindingMode (as the e2e
    /// storage test framework's own helper and most hand-written manifests do) must have
    /// both defaulted.
    ///
    /// Before this fix, apply_defaults had zero dispatch arm for storageclasses, so
    /// reclaimPolicy stayed null. A live repro against the nfs3 in-tree driver showed
    /// this crash the external `nfs-provisioner` sidecar (unmodified upstream,
    /// `pkg/volume/provision.go`) with a nil-pointer dereference on
    /// `*options.StorageClass.ReclaimPolicy` on every single provision attempt — no PV
    /// was ever created, and every PVC using that StorageClass stayed Pending until the
    /// test's bind-wait timed out.
    #[test]
    fn storageclass_reclaim_policy_and_binding_mode_default_when_absent() {
        let mut obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": { "name": "nfs3-sc" },
            "provisioner": "example.com/nfs"
        });

        apply_defaults("storage.k8s.io", "storageclasses", &mut obj);

        assert_eq!(
            obj["reclaimPolicy"], "Delete",
            "reclaimPolicy must default to Delete — left null, the nfs-provisioner \
             sidecar (and any other external provisioner following the same upstream \
             library) panics on an unconditional pointer dereference and crashes \
             instead of ever creating a PV"
        );
        assert_eq!(
            obj["volumeBindingMode"], "Immediate",
            "volumeBindingMode must default to Immediate, matching upstream \
             SetDefaults_StorageClass"
        );
    }

    /// A StorageClass with explicit reclaimPolicy/volumeBindingMode must not have them
    /// overwritten.
    #[test]
    fn storageclass_existing_reclaim_policy_and_binding_mode_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": { "name": "nfs3-sc" },
            "provisioner": "example.com/nfs",
            "reclaimPolicy": "Retain",
            "volumeBindingMode": "WaitForFirstConsumer"
        });

        apply_defaults("storage.k8s.io", "storageclasses", &mut obj);

        assert_eq!(
            obj["reclaimPolicy"], "Retain",
            "existing reclaimPolicy must not be overwritten"
        );
        assert_eq!(
            obj["volumeBindingMode"], "WaitForFirstConsumer",
            "existing volumeBindingMode must not be overwritten"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: NodePort clearing on ExternalName transition
    // ---------------------------------------------------------------------------

    /// A service patched from NodePort to ExternalName must have nodePort zeroed on all ports.
    ///
    /// Conformance test [sig-network] Services should be able to change the type from NodePort
    /// to ExternalName checks that ports[].nodePort == 0 after the type transition.
    /// Without clearing, GET returns the old nodePort value and the conformance test fails
    /// with "expected nodePort to be 0".
    ///
    /// This test fails on revert: removing the nodePort clearing from default_service means
    /// nodePort=30000 is retained after the type change.
    #[test]
    fn nodeport_to_external_name_clears_node_ports() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "svc", "namespace": "default"},
            "spec": {
                "type": "ExternalName",
                "externalName": "example.com",
                "clusterIP": "10.96.0.8",
                "clusterIPs": ["10.96.0.8"],
                "ports": [{"port": 80, "protocol": "TCP", "nodePort": 30000}]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["ports"][0]["nodePort"],
            serde_json::Value::Number(0.into()),
            "nodePort must be 0 after type transitions to ExternalName — conformance test \
             [sig-network] Services should be able to change the type from NodePort to \
             ExternalName checks nodePort==0 and fails if the old value is retained"
        );
    }

    /// ExternalName service must get spec.type defaulted correctly when type is explicit.
    ///
    /// spec.type="ExternalName" is preserved (not overwritten to ClusterIP).
    #[test]
    fn external_name_type_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "ext2", "namespace": "default" },
            "spec": {
                "type": "ExternalName",
                "externalName": "db.example.com"
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["type"], "ExternalName",
            "spec.type=ExternalName must not be overwritten to ClusterIP"
        );
    }

    /// A Service patched from NodePort to ExternalName must have clusterIP and clusterIPs cleared.
    ///
    /// When a NodePort service (with an allocated clusterIP) is PATCHed to type=ExternalName,
    /// the conformance test expects GET to return an empty clusterIP.
    /// Without clearing, GET returns the old allocated IP and the test fails with
    /// "unexpected Spec.ClusterIP (10.96.x.x) for ExternalName service, expected empty".
    #[test]
    fn service_type_change_to_external_name_clears_cluster_ip() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "svc", "namespace": "default" },
            "spec": {
                "type": "ExternalName",
                "externalName": "db.example.com",
                "clusterIP": "10.96.0.8",
                "clusterIPs": ["10.96.0.8"],
                "ipFamilies": ["IPv4"],
                "ipFamilyPolicy": "SingleStack"
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["clusterIP"],
            serde_json::Value::String(String::new()),
            "clusterIP must be cleared when type changes to ExternalName — \
             conformance test fails with 'unexpected Spec.ClusterIP' if old IP is retained"
        );
        assert_eq!(
            obj["spec"]["clusterIPs"],
            serde_json::json!([]),
            "clusterIPs must be cleared when type changes to ExternalName — \
             retaining old IPs would leave stale routing entries for a service with no cluster IP"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: workload metadata.generation initialisation
    // ---------------------------------------------------------------------------

    /// A newly created Deployment must have metadata.generation=1 set by apply_defaults.
    ///
    /// KCM's deployment controller reads metadata.generation to decide whether to
    /// reconcile. If generation is null the controller skips the Deployment entirely,
    /// meaning no ReplicaSet is ever created and no pods are ever scheduled.
    /// Removing the initialize_workload_generation call from apply_defaults must make
    /// this test fail, proving it is a true regression guard.
    #[test]
    fn deployment_create_sets_generation_1() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test-dep", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {
                    "metadata": { "labels": { "app": "test" } },
                    "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["metadata"]["generation"], 1,
            "metadata.generation must be 1 on create — KCM skips Deployments with null generation, \
             causing ReplicaSets and pods to never be created"
        );
    }

    /// metadata.generation must not be overwritten when already set on a Deployment.
    ///
    /// apply_defaults runs at both create and update time. A Deployment that already
    /// has generation=3 (after spec changes) must not be reset to 1 on each defaults pass.
    #[test]
    fn deployment_existing_generation_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test-dep", "namespace": "default", "generation": 3 },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {
                    "metadata": { "labels": { "app": "test" } },
                    "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["metadata"]["generation"], 3,
            "existing metadata.generation must not be overwritten — resetting a running \
             Deployment's generation would confuse KCM's observedGeneration tracking"
        );
    }

    /// StatefulSet, ReplicaSet, DaemonSet, Job, CronJob, and PodDisruptionBudget must also get generation=1.
    ///
    /// All workload resources managed by KCM use generation for reconciliation gating.
    /// Missing generation on any of these causes the same skip-reconcile bug as Deployments.
    /// PDB in particular: the disruption conformance test `waitForPdbToBeProcessed` polls
    /// until status.observedGeneration >= metadata.generation — if generation is absent (0),
    /// the check passes immediately without KCM ever reconciling, causing a race where
    /// disruptedPods written by the test is overwritten by KCM before the test reads it back.
    #[test]
    fn all_workload_kinds_get_generation_1() {
        let cases = [
            ("apps", "statefulsets"),
            ("apps", "replicasets"),
            ("apps", "daemonsets"),
            ("batch", "jobs"),
            ("batch", "cronjobs"),
            ("policy", "poddisruptionbudgets"),
        ];

        for (group, plural) in cases {
            let mut obj = serde_json::json!({
                "metadata": { "name": "test", "namespace": "default" },
                "spec": {}
            });

            apply_defaults(group, plural, &mut obj);

            assert_eq!(
                obj["metadata"]["generation"], 1,
                "metadata.generation must be 1 after apply_defaults for {group}/{plural} — \
                 KCM skips workload resources with null generation"
            );
        }
    }

    /// PodDisruptionBudget must get metadata.generation=1 on creation.
    ///
    /// The disruption controller conformance test `waitForPdbToBeProcessed` polls until
    /// status.observedGeneration >= metadata.generation. Without generation=1, the check
    /// is `0 >= 0` which returns immediately without KCM reconciling — the test then writes
    /// disruptedPods and immediately reads it back, but KCM may concurrently reconcile
    /// from a stale cache (without disruptedPods) and overwrite the entry, causing a flaky
    /// FAIL. Real Kubernetes sets Generation=1 in PrepareForCreate (policy/poddisruptionbudget
    /// strategy), so the test waits for a real KCM reconcile before proceeding.
    ///
    /// This test fails if is_workload_resource no longer includes ("policy", "poddisruptionbudgets").
    #[test]
    fn pdb_create_sets_generation_1_to_anchor_kcm_reconcile_guard() {
        let mut obj = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "foo", "namespace": "default" },
            "spec": {
                "minAvailable": 1,
                "selector": { "matchLabels": { "foo": "bar" } }
            }
        });

        apply_defaults("policy", "poddisruptionbudgets", &mut obj);

        assert_eq!(
            obj["metadata"]["generation"], 1,
            "PodDisruptionBudget must have metadata.generation=1 after creation — without it, \
             waitForPdbToBeProcessed (which checks observedGeneration >= generation) is a no-op \
             (0 >= 0 always true), removing the barrier that ensures KCM has reconciled before \
             the conformance test writes disruptedPods; this causes a race where KCM clears the \
             entry from a stale cache, making the test flaky"
        );
    }

    /// Non-workload resources must NOT have metadata.generation set by apply_defaults.
    ///
    /// Generation is a workload-controller concept; setting it on Services or PVCs
    /// would be a spurious field that could confuse controllers.
    #[test]
    fn non_workload_resources_do_not_get_generation() {
        let cases = [
            ("", "services"),
            ("", "persistentvolumeclaims"),
            ("", "events"),
        ];

        for (group, plural) in cases {
            let mut obj = serde_json::json!({
                "metadata": { "name": "test", "namespace": "default" },
                "spec": {}
            });

            apply_defaults(group, plural, &mut obj);

            assert!(
                obj["metadata"]["generation"].is_null(),
                "metadata.generation must not be set for {group}/{plural} — \
                 generation is only meaningful for workload resources reconciled by KCM"
            );
        }
    }

    /// increment_workload_generation_if_spec_changed must bump generation when spec changes.
    ///
    /// KCM tracks observedGeneration vs generation to detect spec updates that need
    /// reconciliation. Without increment, KCM can't tell a spec change happened.
    #[test]
    fn workload_generation_incremented_on_spec_change() {
        let spec_before = serde_json::json!({ "replicas": 1 });
        let mut obj = serde_json::json!({
            "metadata": { "name": "test", "generation": 1 },
            "spec": { "replicas": 3 }
        });

        increment_workload_generation_if_spec_changed(&mut obj, &spec_before);

        assert_eq!(
            obj["metadata"]["generation"], 2,
            "generation must increment from 1 to 2 when spec changes — KCM uses \
             generation vs observedGeneration to detect pending reconciliation"
        );
    }

    /// increment_workload_generation_if_spec_changed must not change generation when spec is unchanged.
    ///
    /// A metadata-only patch (e.g. adding a label) must not increment generation.
    /// Unnecessary increments would cause spurious KCM reconcile loops.
    #[test]
    fn workload_generation_not_incremented_on_unchanged_spec() {
        let spec = serde_json::json!({ "replicas": 1 });
        let mut obj = serde_json::json!({
            "metadata": { "name": "test", "generation": 1 },
            "spec": { "replicas": 1 }
        });

        increment_workload_generation_if_spec_changed(&mut obj, &spec);

        assert_eq!(
            obj["metadata"]["generation"], 1,
            "generation must not increment when spec is unchanged — spurious increments \
             cause unnecessary KCM reconcile loops"
        );
    }

    /// EndpointSlice must get metadata.generation=1 on creation, like real kube-apiserver's
    /// endpointSliceStrategy.PrepareForCreate.
    ///
    /// KCM's EndpointSliceTracker.StaleSlices() compares this field per-UID to detect a stale
    /// informer cache. Leaving it permanently absent makes that comparison a no-op (0 is never
    /// greater than 0), silently disabling one of the tracker's three staleness checks.
    #[test]
    fn endpointslice_create_sets_generation_1() {
        let mut obj = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": { "name": "svc-abcde", "namespace": "default" },
            "addressType": "IPv4",
            "endpoints": [],
            "ports": []
        });

        apply_defaults("discovery.k8s.io", "endpointslices", &mut obj);

        assert_eq!(
            obj["metadata"]["generation"], 1,
            "EndpointSlice must have metadata.generation=1 after creation, matching real \
             kube-apiserver — a permanently-absent generation defeats StaleSlices()'s \
             per-UID generation comparison"
        );
    }

    /// increment_endpointslice_generation_if_changed must bump generation when endpoints change.
    ///
    /// This is the actual content mutation the EndpointSlice controller performs when a second
    /// pod becomes Ready: the slice already exists, and its endpoints array grows. Real
    /// kube-apiserver's endpointSliceStrategy.PrepareForUpdate increments generation for this;
    /// without it, KCM's EndpointSliceTracker can't distinguish "informer has today's content"
    /// from "informer has yesterday's content" once a Service has multiple EndpointSlice UIDs.
    #[test]
    fn endpointslice_generation_incremented_when_endpoints_change() {
        let before = serde_json::json!({
            "endpoints": [{"addresses": ["10.0.0.1"]}],
            "ports": [{"port": 80}],
            "addressType": "IPv4",
            "metadata": { "labels": {} }
        });
        let mut obj = serde_json::json!({
            "metadata": { "name": "svc-abcde", "generation": 1, "labels": {} },
            "endpoints": [{"addresses": ["10.0.0.1"]}, {"addresses": ["10.0.0.2"]}],
            "ports": [{"port": 80}],
            "addressType": "IPv4"
        });

        increment_endpointslice_generation_if_changed(&mut obj, &before);

        assert_eq!(
            obj["metadata"]["generation"], 2,
            "generation must increment from 1 to 2 when endpoints change — this is exactly \
             the second-write case (a second pod becoming Ready) that KCM's \
             EndpointSliceTracker must be able to detect via generation"
        );
    }

    /// increment_endpointslice_generation_if_changed must not change generation for a no-op
    /// resync (identical endpoints/ports/addressType/labels).
    #[test]
    fn endpointslice_generation_not_incremented_when_content_unchanged() {
        let before = serde_json::json!({
            "endpoints": [{"addresses": ["10.0.0.1"]}],
            "ports": [{"port": 80}],
            "addressType": "IPv4",
            "metadata": { "labels": {} }
        });
        let mut obj = serde_json::json!({
            "metadata": { "name": "svc-abcde", "generation": 1, "labels": {} },
            "endpoints": [{"addresses": ["10.0.0.1"]}],
            "ports": [{"port": 80}],
            "addressType": "IPv4"
        });

        increment_endpointslice_generation_if_changed(&mut obj, &before);

        assert_eq!(
            obj["metadata"]["generation"], 1,
            "generation must not increment on a no-op resync — spurious increments would make \
             KCM's own tracker updates look like external changes"
        );
    }

    /// increment_endpointslice_generation_if_changed must bump generation on a labels-only
    /// change, matching upstream's separate Labels comparison (EndpointSlice has no `.spec`,
    /// so label changes can't be caught by a spec-equality check).
    #[test]
    fn endpointslice_generation_incremented_on_label_only_change() {
        let before = serde_json::json!({
            "endpoints": [],
            "ports": [],
            "addressType": "IPv4",
            "metadata": { "labels": { "app": "old" } }
        });
        let mut obj = serde_json::json!({
            "metadata": { "name": "svc-abcde", "generation": 1, "labels": { "app": "new" } },
            "endpoints": [],
            "ports": [],
            "addressType": "IPv4"
        });

        increment_endpointslice_generation_if_changed(&mut obj, &before);

        assert_eq!(
            obj["metadata"]["generation"], 2,
            "generation must increment when only labels change — EndpointSlice has no .spec, \
             so a labels-only change must be tracked separately from endpoints/ports content"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: null creationTimestamp stripped from pod template metadata
    // ---------------------------------------------------------------------------

    /// Deployment pod template metadata must not contain "creationTimestamp: null" after
    /// apply_defaults.
    ///
    /// KCM's FindNewReplicaSet uses EqualIgnoreHash(RS.spec.template, Deployment.spec.template).
    /// Our JSON serialization of ObjectMeta always emits "creationTimestamp: null", but KCM
    /// omits this field when creating the RS.  The deep-equality check sees different metadata
    /// → returns false → FindNewReplicaSet returns nil → deployment revision annotation is
    /// never set and the Deployment stays permanently unreconciled.
    ///
    /// This test MUST FAIL if strip_null_template_metadata is removed from apply_defaults.
    #[test]
    fn deployment_template_metadata_null_creation_timestamp_stripped() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {
                    "metadata": {
                        "creationTimestamp": null,
                        "labels": { "app": "test" }
                    },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert!(
            obj["spec"]["template"]["metadata"]["creationTimestamp"].is_null(),
            "creationTimestamp key must be absent from stored template metadata — \
             its presence (as null) causes KCM's EqualIgnoreHash to see different \
             metadata between the Deployment and RS templates, making FindNewReplicaSet \
             return nil and leaving the deployment permanently unreconciled"
        );
        // The key must be absent, not merely null-valued.
        assert!(
            !obj["spec"]["template"]["metadata"]
                .as_object()
                .unwrap()
                .contains_key("creationTimestamp"),
            "creationTimestamp must be fully removed from template metadata, not left as null — \
             serde_json represents absent keys and null values differently; EqualIgnoreHash \
             treats an absent key as different from a null key"
        );
        // Non-null fields must survive.
        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"],
            serde_json::json!({ "app": "test" }),
            "non-null template metadata fields must not be stripped"
        );
    }

    /// ReplicaSet, StatefulSet, and DaemonSet also strip null creationTimestamp.
    ///
    /// All four apps workload kinds have pod templates that KCM hashes for ownership
    /// checks. A null creationTimestamp in any of them causes the same EqualIgnoreHash
    /// mismatch as in Deployments.
    #[test]
    fn all_apps_workloads_strip_null_creation_timestamp_from_template() {
        let cases = [
            ("apps", "deployments"),
            ("apps", "replicasets"),
            ("apps", "statefulsets"),
            ("apps", "daemonsets"),
        ];

        for (group, plural) in cases {
            let mut obj = serde_json::json!({
                "metadata": { "name": "test", "namespace": "default" },
                "spec": {
                    "selector": { "matchLabels": { "app": "test" } },
                    "template": {
                        "metadata": {
                            "creationTimestamp": null,
                            "labels": { "app": "test" }
                        }
                    }
                }
            });

            apply_defaults(group, plural, &mut obj);

            assert!(
                !obj["spec"]["template"]["metadata"]
                    .as_object()
                    .unwrap()
                    .contains_key("creationTimestamp"),
                "creationTimestamp must be stripped from {group}/{plural} template metadata — \
                 EqualIgnoreHash mismatch would leave the workload permanently unreconciled"
            );
        }
    }

    /// Service port without targetPort must default targetPort to equal port.
    /// Without this, admission webhook_url() falls back to svc_port and may tunnel
    /// to the wrong container port, causing connection refused.
    #[test]
    fn service_port_defaults_target_port_when_absent() {
        let mut svc = serde_json::json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "my-svc"},
            "spec": {
                "type": "ClusterIP",
                "ports": [{"port": 8443, "protocol": "TCP"}]
            }
        });
        default_service(&mut svc);
        assert_eq!(
            svc["spec"]["ports"][0]["targetPort"], 8443,
            "targetPort must default to port when absent — without this, \
             admission webhook_url() tunnels to the wrong container port"
        );
    }

    /// An explicit targetPort must not be overwritten by defaulting.
    ///
    /// Service ports that explicitly map port 8443 to container port 8444 must
    /// retain the targetPort=8444 value; overwriting it would route traffic to
    /// the wrong container port.
    #[test]
    fn service_port_explicit_target_port_preserved() {
        let mut svc = serde_json::json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "my-svc"},
            "spec": {
                "type": "ClusterIP",
                "ports": [{"port": 8443, "targetPort": 8444, "protocol": "TCP"}]
            }
        });
        default_service(&mut svc);
        assert_eq!(
            svc["spec"]["ports"][0]["targetPort"], 8444,
            "explicit targetPort must not be overwritten by defaulting"
        );
    }

    /// A port with targetPort=0 must be defaulted to the port number.
    ///
    /// Kubernetes client-go serializes an omitted IntOrString targetPort as 0.
    /// Without this, the EndpointSlice controller copies port=0 into the slice,
    /// breaking connectivity to StatefulSet pods (conformance: statefulset tests hang).
    #[test]
    fn service_port_zero_target_port_defaults_to_port() {
        let mut svc = serde_json::json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "my-svc"},
            "spec": {
                "type": "ClusterIP",
                "ports": [{"port": 80, "targetPort": 0, "protocol": "TCP"}]
            }
        });
        default_service(&mut svc);
        assert_eq!(
            svc["spec"]["ports"][0]["targetPort"], 80,
            "targetPort=0 must be defaulted to port — client-go omits targetPort as 0, \
             EndpointSlice controller copies it verbatim and pods become unreachable"
        );
    }

    /// A Service created without spec.sessionAffinity must default to "None".
    ///
    /// kubectl describe svc prints the raw field value; an absent sessionAffinity
    /// renders as an empty "Session Affinity:" line, failing the sig-cli
    /// "kubectl describe" conformance test which asserts the value is "None".
    #[test]
    fn service_defaults_session_affinity_to_none_when_absent() {
        let mut svc = serde_json::json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "my-svc"},
            "spec": {
                "type": "ClusterIP",
                "ports": [{"port": 80, "protocol": "TCP"}]
            }
        });
        default_service(&mut svc);
        assert_eq!(
            svc["spec"]["sessionAffinity"], "None",
            "sessionAffinity must default to \"None\" — otherwise kubectl describe svc \
             prints an empty Session Affinity line and the sig-cli describe conformance \
             test fails"
        );
    }

    /// An explicit sessionAffinity must not be overwritten by defaulting.
    #[test]
    fn service_explicit_session_affinity_preserved() {
        let mut svc = serde_json::json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "my-svc"},
            "spec": {
                "type": "ClusterIP",
                "sessionAffinity": "ClientIP",
                "ports": [{"port": 80, "protocol": "TCP"}]
            }
        });
        default_service(&mut svc);
        assert_eq!(
            svc["spec"]["sessionAffinity"], "ClientIP",
            "explicit sessionAffinity must not be overwritten by defaulting"
        );
    }

    /// A ClientIP-affinity Service without an explicit timeout must default to 10800s.
    ///
    /// Matches upstream SetDefaults_Service: clients that request ClientIP affinity
    /// but omit the timeout rely on the 3-hour default; without it the field is
    /// absent and session stickiness has no defined duration.
    #[test]
    fn service_client_ip_session_affinity_defaults_timeout_seconds() {
        let mut svc = serde_json::json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "my-svc"},
            "spec": {
                "type": "ClusterIP",
                "sessionAffinity": "ClientIP",
                "ports": [{"port": 80, "protocol": "TCP"}]
            }
        });
        default_service(&mut svc);
        assert_eq!(
            svc["spec"]["sessionAffinityConfig"]["clientIP"]["timeoutSeconds"], 10800,
            "ClientIP sessionAffinityConfig.clientIP.timeoutSeconds must default to 10800s \
             (upstream SetDefaults_Service) — without it, session stickiness duration is \
             undefined for clients that didn't set it explicitly"
        );
    }

    /// Template metadata without creationTimestamp must pass through unchanged.
    ///
    /// Ensures strip_null_template_metadata is a no-op when the field is absent,
    /// so existing Deployments that never had null creationTimestamp are unaffected.
    #[test]
    fn template_metadata_without_null_creation_timestamp_unchanged() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "test" } },
                "template": {
                    "metadata": { "labels": { "app": "test" } }
                }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"],
            serde_json::json!({ "app": "test" }),
            "labels must be preserved when no null keys are present"
        );
        assert!(
            !obj["spec"]["template"]["metadata"]
                .as_object()
                .unwrap()
                .contains_key("creationTimestamp"),
            "creationTimestamp must not appear when it was never in the input"
        );
    }

    /// A ValidatingWebhookConfiguration with an empty matchConditions expression must be
    /// rejected. The conformance test POSTs a webhook configuration with an invalid CEL
    /// expression and expects a 422 — without this check the apiserver returns 200 OK.
    #[test]
    fn validating_webhook_configuration_rejects_empty_cel_expression() {
        let obj = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test"},
            "webhooks": [{
                "name": "test.example.com",
                "matchConditions": [{"name": "check", "expression": ""}]
            }]
        });
        let result = validate_resource(
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            &obj,
        );
        assert!(
            result.is_err(),
            "ValidatingWebhookConfiguration with empty matchConditions expression must be rejected; \
             without this check the apiserver returns 200 OK and the conformance test fails"
        );
    }

    /// A ValidatingWebhookConfiguration with a valid CEL expression must be accepted.
    #[test]
    fn validating_webhook_configuration_accepts_valid_cel_expression() {
        let obj = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test"},
            "webhooks": [{
                "name": "test.example.com",
                "matchConditions": [{"name": "check", "expression": "object.metadata.name == \"test\""}]
            }]
        });
        let result = validate_resource(
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            &obj,
        );
        assert!(
            result.is_ok(),
            "ValidatingWebhookConfiguration with a valid CEL expression must pass validation"
        );
    }

    /// A MutatingWebhookConfiguration with an empty matchConditions expression must be
    /// rejected for the same reason as the validating variant.
    #[test]
    fn mutating_webhook_configuration_rejects_empty_cel_expression() {
        let obj = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test"},
            "webhooks": [{
                "name": "test.example.com",
                "matchConditions": [{"name": "check", "expression": ""}]
            }]
        });
        let result = validate_resource(
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
            &obj,
        );
        assert!(
            result.is_err(),
            "MutatingWebhookConfiguration with empty matchConditions expression must be rejected"
        );
    }

    /// A MutatingWebhookConfiguration with a valid CEL expression must be accepted.
    /// Rejecting a valid expression would block legitimate webhook configurations.
    #[test]
    fn mutating_webhook_configuration_accepts_valid_cel_expression() {
        let obj = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test"},
            "webhooks": [{
                "name": "test.example.com",
                "matchConditions": [{"name": "check", "expression": "object.metadata.name == \"test\""}]
            }]
        });
        let result = validate_resource(
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
            &obj,
        );
        assert!(
            result.is_ok(),
            "MutatingWebhookConfiguration with a valid CEL expression must pass validation; \
             invalid CEL in a mutating webhook must be rejected at admission-config time, not silently stored"
        );
    }

    /// A MutatingWebhookConfiguration with the exact expression used by the conformance test
    /// must be rejected. The conformance test uses "... [] bad expression" which tokenizes to
    /// non-empty tokens but starts with Dot — not a valid CEL primary start.
    #[test]
    fn mutating_webhook_configuration_rejects_conformance_test_invalid_expression() {
        let obj = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test"},
            "webhooks": [{
                "name": "test.example.com",
                "matchConditions": [{"name": "invalid-expression-1", "expression": "... [] bad expression"}]
            }]
        });
        let result = validate_resource(
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
            &obj,
        );
        assert!(
            result.is_err(),
            "MutatingWebhookConfiguration with '... [] bad expression' must be rejected; \
             the conformance test 'should reject mutating webhook configurations with invalid match conditions' \
             POSTs this exact expression and expects 422, not 200"
        );
    }

    /// A ValidatingWebhookConfiguration with the exact expression used by the conformance test
    /// must be rejected. Matches the 'should reject validating webhook configurations with invalid
    /// match conditions' conformance test.
    #[test]
    fn validating_webhook_configuration_rejects_conformance_test_invalid_expression() {
        let obj = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test"},
            "webhooks": [{
                "name": "test.example.com",
                "matchConditions": [{"name": "invalid-expression-1", "expression": "... [] bad expression"}]
            }]
        });
        let result = validate_resource(
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            &obj,
        );
        assert!(
            result.is_err(),
            "ValidatingWebhookConfiguration with '... [] bad expression' must be rejected; \
             the conformance test 'should reject validating webhook configurations with invalid match conditions' \
             POSTs this exact expression and expects 422, not 200"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: ConfigMap/Secret empty data key rejection
    // ---------------------------------------------------------------------------

    /// A ConfigMap with an empty string key in data must be rejected with a validation error.
    ///
    /// Kubernetes conformance test [sig-node] ConfigMap should fail to create ConfigMap with
    /// empty key posts data: {"": "value"} and expects HTTP 422. Without this check our
    /// apiserver returns 200 and stores an object that kubectl and conformance tests reject.
    ///
    /// This test fails on revert: removing validate_data_keys makes validate_resource return
    /// Ok(()) for the empty-key ConfigMap, and the test panics on the unwrap_err().
    #[test]
    fn configmap_with_empty_data_key_rejected() {
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "bad", "namespace": "default"},
            "data": {"": "value"}
        });
        let result = validate_resource("", "configmaps", &obj);
        assert!(
            result.is_err(),
            "ConfigMap with empty string data key must be rejected — conformance test \
             [sig-node] ConfigMap should fail to create ConfigMap with empty key expects 422"
        );
        assert!(
            result.unwrap_err().contains("ConfigMap.data"),
            "error must reference ConfigMap.data"
        );
    }

    /// A ConfigMap with valid data keys must pass validation.
    ///
    /// Ensures the empty-key check does not regress on valid ConfigMaps.
    #[test]
    fn configmap_with_valid_data_keys_passes_validation() {
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ok", "namespace": "default"},
            "data": {"key": "value", "another-key": "v2"}
        });
        assert!(
            validate_resource("", "configmaps", &obj).is_ok(),
            "ConfigMap with valid data keys must pass validation"
        );
    }

    /// A Secret with an empty string key in data must be rejected.
    ///
    /// Same rule as ConfigMap: empty keys are invalid in Kubernetes API semantics.
    /// If the check is removed, secrets with invalid keys are accepted and stored,
    /// breaking clients that iterate over data keys.
    #[test]
    fn secret_with_empty_data_key_rejected() {
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "bad", "namespace": "default"},
            "data": {"": "dmFsdWU="}
        });
        let result = validate_resource("", "secrets", &obj);
        assert!(
            result.is_err(),
            "Secret with empty string data key must be rejected — empty keys are invalid \
             in Kubernetes API; storing them breaks clients that iterate over secret data"
        );
        assert!(
            result.unwrap_err().contains("Secret.data"),
            "error must reference Secret.data"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: Lease spec.leaseTransitions defaulting
    // ---------------------------------------------------------------------------

    /// A Lease created without spec.leaseTransitions must have it defaulted to 0.
    ///
    /// Real Kubernetes uses *int32 for this field (pointer-to-zero). The Lease
    /// conformance test reads it back and expects 0; without this default the field
    /// is null and the test fails with "unexpected leaseTransitions: <nil>".
    /// Reverting default_lease makes this test fail.
    #[test]
    fn lease_transitions_defaults_to_zero() {
        let mut obj = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "my-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "node1", "leaseDurationSeconds": 40 }
        });

        apply_defaults("coordination.k8s.io", "leases", &mut obj);

        assert_eq!(
            obj["spec"]["leaseTransitions"],
            serde_json::Value::Number(0.into()),
            "spec.leaseTransitions must default to 0 — the Lease conformance test \
             reads it back and fails when the field is null"
        );
    }

    /// An existing spec.leaseTransitions must not be overwritten.
    ///
    /// A Lease that has been renewed multiple times carries a non-zero
    /// leaseTransitions count. Overwriting it to 0 would break holder-identity
    /// tracking used by the node lease controller.
    #[test]
    fn lease_transitions_existing_value_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": { "name": "my-lease", "namespace": "kube-node-lease" },
            "spec": { "holderIdentity": "node1", "leaseDurationSeconds": 40, "leaseTransitions": 5 }
        });

        apply_defaults("coordination.k8s.io", "leases", &mut obj);

        assert_eq!(
            obj["spec"]["leaseTransitions"],
            serde_json::Value::Number(5.into()),
            "existing spec.leaseTransitions must not be overwritten — \
             resetting the transition count breaks holder-identity tracking"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: RoleBinding/ClusterRoleBinding roleRef.apiGroup defaulting
    // ---------------------------------------------------------------------------

    /// A RoleBinding created with `roleRef.apiGroup: ""` (as the upstream aggregator
    /// conformance test's RoleBinding object literally does, relying on server-side
    /// defaulting) must have apiGroup defaulted to "rbac.authorization.k8s.io".
    ///
    /// Without this, the stored roleRef.apiGroup stays "", and the RBAC engine's
    /// resolve_role_rules — which requires an exact "rbac.authorization.k8s.io" match —
    /// silently resolves to zero rules. The binding then grants nothing no matter how
    /// long it has existed, which is exactly why the sample-apiserver's
    /// extension-apiserver-authentication-reader RoleBinding never took effect and its
    /// pod crash-looped for the whole conformance test timeout.
    #[test]
    fn rolebinding_empty_role_ref_api_group_defaults_to_rbac_group() {
        let mut obj = serde_json::json!({
            "metadata": { "name": "wardler-auth-reader", "namespace": "kube-system" },
            "subjects": [{ "kind": "ServiceAccount", "name": "default", "namespace": "aggregator-1" }],
            "roleRef": { "apiGroup": "", "kind": "Role", "name": "extension-apiserver-authentication-reader" }
        });

        apply_defaults("rbac.authorization.k8s.io", "rolebindings", &mut obj);

        assert_eq!(
            obj["roleRef"]["apiGroup"], "rbac.authorization.k8s.io",
            "empty roleRef.apiGroup must default to \"rbac.authorization.k8s.io\" — \
             leaving it empty means the RBAC engine treats the binding as referencing no \
             role at all, denying access forever regardless of RoleBinding timing"
        );
    }

    /// A ClusterRoleBinding with `roleRef.apiGroup` absent entirely (not present in the
    /// JSON body at all, not merely empty) must also get the default applied.
    #[test]
    fn clusterrolebinding_missing_role_ref_api_group_defaults_to_rbac_group() {
        let mut obj = serde_json::json!({
            "metadata": { "name": "wardler-auth-delegator" },
            "subjects": [{ "kind": "ServiceAccount", "name": "sample-apiserver", "namespace": "aggregator-1" }],
            "roleRef": { "kind": "ClusterRole", "name": "system:auth-delegator" }
        });

        apply_defaults("rbac.authorization.k8s.io", "clusterrolebindings", &mut obj);

        assert_eq!(
            obj["roleRef"]["apiGroup"], "rbac.authorization.k8s.io",
            "absent roleRef.apiGroup must default to \"rbac.authorization.k8s.io\", \
             matching real Kubernetes' SetDefaults_ClusterRoleBinding"
        );
    }

    /// An explicit, correct roleRef.apiGroup must not be overwritten.
    #[test]
    fn rolebinding_explicit_role_ref_api_group_preserved() {
        let mut obj = serde_json::json!({
            "metadata": { "name": "custom-binding", "namespace": "default" },
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "custom-role" }
        });

        apply_defaults("rbac.authorization.k8s.io", "rolebindings", &mut obj);

        assert_eq!(
            obj["roleRef"]["apiGroup"], "rbac.authorization.k8s.io",
            "an already-correct roleRef.apiGroup must be preserved unchanged"
        );
    }

    /// A non-RBAC-group resource with a similarly-shaped `roleRef.apiGroup` field must
    /// not be touched — the defaulting must be scoped to rolebindings/clusterrolebindings.
    #[test]
    fn non_rbac_resource_role_ref_untouched() {
        let mut obj = serde_json::json!({
            "roleRef": { "apiGroup": "" }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["roleRef"]["apiGroup"], "",
            "defaulting must only apply to rbac.authorization.k8s.io rolebindings/\
             clusterrolebindings, not incidentally-similar fields on other resources"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: Job/CronJob defaulting and pod template labels
    // ---------------------------------------------------------------------------

    /// A Job with no spec.template.metadata.labels must have them defaulted to {}.
    ///
    /// KCM's job_controller merges "job-name" and "job-uid" into spec.template.metadata.labels
    /// at job_controller.go:1067. If the map is nil (null in JSON) it panics with a nil pointer
    /// dereference, killing the entire KCM process — so no default ServiceAccounts are created
    /// in any subsequent test namespace, causing 168 cascading [BeforeEach] failures.
    #[test]
    fn job_pod_template_labels_defaults_to_empty_map() {
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": {
                    "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
                }
            }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"],
            serde_json::json!({}),
            "spec.template.metadata.labels must default to {{}} — nil map panics KCM \
             job_controller at job_controller.go:1067, killing the entire KCM process"
        );
    }

    /// A Job must have spec.backoffLimit defaulted to 6.
    ///
    /// Kubernetes default is 6 retries before marking the Job as failed. Without this
    /// default, the field is null and clients reading it get nil instead of the expected integer.
    #[test]
    fn job_backoff_limit_defaults_to_6() {
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": { "spec": { "containers": [] } }
            }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert_eq!(
            obj["spec"]["backoffLimit"],
            serde_json::Value::Number(6.into()),
            "spec.backoffLimit must default to 6 — Kubernetes default for job retry limit"
        );
    }

    /// A Job must have spec.parallelism defaulted to 1.
    #[test]
    fn job_parallelism_defaults_to_1() {
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": { "spec": { "containers": [] } }
            }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert_eq!(
            obj["spec"]["parallelism"],
            serde_json::Value::Number(1.into()),
            "spec.parallelism must default to 1"
        );
    }

    /// Existing Job spec fields must not be overwritten (idempotency).
    #[test]
    fn job_existing_spec_fields_not_overwritten() {
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "backoffLimit": 3,
                "parallelism": 4,
                "template": {
                    "metadata": { "labels": { "app": "my-job" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert_eq!(
            obj["spec"]["backoffLimit"],
            serde_json::Value::Number(3.into()),
            "existing spec.backoffLimit must not be overwritten"
        );
        assert_eq!(
            obj["spec"]["parallelism"],
            serde_json::Value::Number(4.into()),
            "existing spec.parallelism must not be overwritten"
        );
        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"],
            serde_json::json!({ "app": "my-job" }),
            "existing template labels must not be overwritten"
        );
    }

    /// A Job must have spec.template.spec.enableServiceLinks defaulted to true.
    ///
    /// Pod spec enableServiceLinks defaults to true in upstream Kubernetes. Without this
    /// default, conformance tests reading pod.spec.enableServiceLinks get nil instead of true.
    #[test]
    fn job_pod_template_enable_service_links_defaults_to_true() {
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "template": { "spec": { "containers": [] } }
            }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert_eq!(
            obj["spec"]["template"]["spec"]["enableServiceLinks"],
            serde_json::Value::Bool(true),
            "spec.template.spec.enableServiceLinks must default to true — \
             conformance tests read this field and fail when it is nil"
        );
    }

    /// A Job must get metadata.generation=1 set by apply_defaults.
    ///
    /// KCM's job controller uses generation to gate reconciliation; null generation
    /// means the job is never reconciled and pods are never scheduled.
    #[test]
    fn job_create_sets_generation_1() {
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": { "template": { "spec": { "containers": [] } } }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert_eq!(
            obj["metadata"]["generation"], 1,
            "metadata.generation must be 1 on Job create — KCM job controller skips \
             Jobs with null generation, causing pods to never be scheduled"
        );
    }

    /// A CronJob must have its nested pod template labels defaulted to {}.
    ///
    /// CronJobs create Jobs whose pod template is nested at
    /// spec.jobTemplate.spec.template. Without labels defaulted here, KCM's
    /// job_controller nil-panics when merging job-name/job-uid labels.
    #[test]
    fn cronjob_pod_template_labels_defaults_to_empty_map() {
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "schedule": "* * * * *",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
                        }
                    }
                }
            }
        });

        apply_defaults("batch", "cronjobs", &mut obj);

        assert_eq!(
            obj["spec"]["jobTemplate"]["spec"]["template"]["metadata"]["labels"],
            serde_json::json!({}),
            "spec.jobTemplate.spec.template.metadata.labels must default to {{}} — \
             KCM job_controller nil-panics on a null labels map when the CronJob spawns a Job"
        );
    }

    /// A CronJob must get metadata.generation=1 set by apply_defaults.
    #[test]
    fn cronjob_create_sets_generation_1() {
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "schedule": "* * * * *",
                "jobTemplate": { "spec": { "template": { "spec": { "containers": [] } } } }
            }
        });

        apply_defaults("batch", "cronjobs", &mut obj);

        assert_eq!(
            obj["metadata"]["generation"], 1,
            "metadata.generation must be 1 on CronJob create — KCM cronjob controller \
             skips CronJobs with null generation"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: Job selector + controller-uid/job-name label generation
    // ---------------------------------------------------------------------------

    /// A Job without spec.selector and without manualSelector must get auto-generated
    /// selector and controller-uid/job-name labels injected into the pod template.
    ///
    /// KCM's RealPodControl.createPods returns "unable to create pods, no labels" when
    /// len(pod.Labels) == 0. The pod is built from job.spec.template.metadata.labels.
    /// Without the selector/label generation step (upstream generateSelector in
    /// pkg/registry/batch/job/strategy.go), every Job conformance test times out because
    /// KCM never creates pods. This test MUST FAIL if the uid-guarded generation block in
    /// default_job is removed.
    #[test]
    fn job_without_selector_gets_generated_selector_and_labels() {
        let uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let name = "my-job";
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": name, "namespace": "default", "uid": uid },
            "spec": {
                "template": {
                    "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
                }
            }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"]["batch.kubernetes.io/controller-uid"],
            uid,
            "batch.kubernetes.io/controller-uid label must be injected into pod template — \
             KCM RealPodControl.createPods errors 'unable to create pods, no labels' when \
             this label is absent, so Job pods are never created and every Job conformance test times out"
        );
        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"]["batch.kubernetes.io/job-name"], name,
            "batch.kubernetes.io/job-name label must be injected into pod template — \
             KCM uses this label to identify pods belonging to the Job"
        );
        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"]["controller-uid"],
            uid,
            "legacy controller-uid label must be injected for compatibility with older KCM versions"
        );
        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"]["job-name"], name,
            "legacy job-name label must be injected for compatibility with older KCM versions"
        );
        assert_eq!(
            obj["spec"]["selector"]["matchLabels"]["batch.kubernetes.io/controller-uid"], uid,
            "spec.selector.matchLabels must contain batch.kubernetes.io/controller-uid — \
             without the selector, KCM cannot identify which pods belong to the Job"
        );
    }

    /// A Job with manualSelector: true must NOT have selector or labels auto-generated.
    ///
    /// When manualSelector is true the user owns the selector and label set.
    /// Overwriting them would cause the Job controller to match the wrong pods.
    #[test]
    fn job_with_manual_selector_does_not_get_generated_labels() {
        let uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "my-job", "namespace": "default", "uid": uid },
            "spec": {
                "manualSelector": true,
                "selector": { "matchLabels": { "custom": "label" } },
                "template": {
                    "metadata": { "labels": { "custom": "label" } },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert!(
            obj["spec"]["template"]["metadata"]["labels"]["batch.kubernetes.io/controller-uid"]
                .is_null(),
            "batch.kubernetes.io/controller-uid must NOT be injected when manualSelector=true — \
             user owns the selector and label set; overwriting breaks pod ownership"
        );
        assert_eq!(
            obj["spec"]["selector"],
            serde_json::json!({ "matchLabels": { "custom": "label" } }),
            "existing spec.selector must be preserved when manualSelector=true"
        );
    }

    /// A Job that already has spec.selector set must not have it overwritten.
    ///
    /// apply_defaults is called on GET/LIST/WATCH paths in addition to create.
    /// A Job that was already stored with the generated selector must not have
    /// the selector or labels regenerated on subsequent reads (idempotency).
    #[test]
    fn job_with_existing_selector_is_not_modified() {
        let uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "my-job", "namespace": "default", "uid": uid },
            "spec": {
                "selector": { "matchLabels": { "batch.kubernetes.io/controller-uid": uid } },
                "template": {
                    "metadata": {
                        "labels": {
                            "batch.kubernetes.io/controller-uid": uid,
                            "batch.kubernetes.io/job-name": "my-job"
                        }
                    },
                    "spec": { "containers": [] }
                }
            }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert_eq!(
            obj["spec"]["selector"]["matchLabels"]["batch.kubernetes.io/controller-uid"], uid,
            "existing spec.selector must be preserved — apply_defaults is idempotent on \
             GET/LIST paths; overwriting would corrupt already-stored Jobs"
        );
        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"]["batch.kubernetes.io/controller-uid"],
            uid,
            "existing controller-uid label must not be overwritten on re-apply"
        );
    }

    /// A webhook configuration without matchConditions must still be accepted.
    #[test]
    fn webhook_configuration_without_match_conditions_passes_validation() {
        let obj = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test"},
            "webhooks": [{
                "name": "test.example.com",
                "clientConfig": {"url": "https://example.com/webhook"}
            }]
        });
        let result = validate_resource(
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            &obj,
        );
        assert!(
            result.is_ok(),
            "ValidatingWebhookConfiguration without matchConditions must pass validation"
        );
    }

    // ---------------------------------------------------------------------------
    // HorizontalPodAutoscaler behavior defaulting
    // ---------------------------------------------------------------------------

    /// An HPA with no spec.behavior at all must be left untouched.
    ///
    /// Upstream only runs behavior defaulting when spec.behavior is non-nil; if u7s
    /// invented a spec.behavior block for every HPA it would diverge from what most
    /// HPAs (which never set behavior) actually look like on real Kubernetes.
    #[test]
    fn hpa_without_behavior_is_untouched() {
        let mut obj = serde_json::json!({
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "scaleTargetRef": { "kind": "Deployment", "name": "consumer" },
                "minReplicas": 10,
                "maxReplicas": 12
            }
        });
        let original = obj.clone();

        apply_defaults("autoscaling", "horizontalpodautoscalers", &mut obj);

        assert_eq!(
            obj, original,
            "spec.behavior must not be invented out of thin air when the caller never set it"
        );
    }

    /// An HPA with an empty scaleUp object must be fully defaulted.
    ///
    /// empty scaleUp must be fully defaulted or vendored kcm nil-derefs at
    /// horizontal.go:1213 (kubernetes/kubernetes#107038 reproduces).
    #[test]
    fn hpa_empty_scale_up_gets_fully_defaulted() {
        let mut obj = serde_json::json!({
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "scaleTargetRef": { "kind": "Deployment", "name": "consumer" },
                "minReplicas": 10,
                "maxReplicas": 12,
                "behavior": { "scaleUp": {} }
            }
        });

        apply_defaults("autoscaling", "horizontalpodautoscalers", &mut obj);

        assert_eq!(
            obj["spec"]["behavior"]["scaleUp"]["stabilizationWindowSeconds"], 0,
            "empty scaleUp must be fully defaulted or vendored kcm nil-derefs at \
             horizontal.go:1213 (kubernetes/kubernetes#107038 reproduces)"
        );
        assert_eq!(
            obj["spec"]["behavior"]["scaleUp"]["selectPolicy"], "Max",
            "empty scaleUp must be fully defaulted or vendored kcm nil-derefs at \
             horizontal.go:1213 (kubernetes/kubernetes#107038 reproduces)"
        );
        assert_eq!(
            obj["spec"]["behavior"]["scaleUp"]["policies"],
            serde_json::json!([
                { "type": "Pods", "value": 4, "periodSeconds": 15 },
                { "type": "Percent", "value": 100, "periodSeconds": 15 }
            ]),
            "empty scaleUp must be fully defaulted or vendored kcm nil-derefs at \
             horizontal.go:1213 (kubernetes/kubernetes#107038 reproduces)"
        );
    }

    /// An HPA with scaleUp = {tolerance: "20m"} (the exact shape the failing
    /// HPAConfigurableTolerance e2e test constructs) must get tolerance preserved and
    /// every other scaleUp field defaulted.
    ///
    /// Defaulting must be per-field, not object-level: a caller who sets only one field
    /// (tolerance) must not lose the field-level default for stabilizationWindowSeconds
    /// that this whole fix exists to guarantee.
    #[test]
    fn hpa_scale_up_with_only_tolerance_set_keeps_tolerance_and_defaults_rest() {
        let mut obj = serde_json::json!({
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "scaleTargetRef": { "kind": "Deployment", "name": "consumer" },
                "minReplicas": 10,
                "maxReplicas": 12,
                "behavior": { "scaleUp": { "tolerance": "20m" } }
            }
        });

        apply_defaults("autoscaling", "horizontalpodautoscalers", &mut obj);

        assert_eq!(
            obj["spec"]["behavior"]["scaleUp"]["tolerance"], "20m",
            "caller-set tolerance must survive defaulting — overwriting it would silently \
             change the e2e test's requested scale-up tolerance"
        );
        assert_eq!(
            obj["spec"]["behavior"]["scaleUp"]["stabilizationWindowSeconds"], 0,
            "stabilizationWindowSeconds must still be defaulted per-field even though the \
             caller only set tolerance — this exact shape is what crashed kcm at \
             horizontal.go:1213"
        );
        assert_eq!(
            obj["spec"]["behavior"]["scaleUp"]["selectPolicy"], "Max",
            "selectPolicy must be defaulted per-field alongside tolerance"
        );
    }

    /// An HPA with an empty scaleDown object must get selectPolicy/policies defaulted,
    /// but stabilizationWindowSeconds must stay absent.
    ///
    /// Upstream intentionally never defaults scaleDown.stabilizationWindowSeconds at the
    /// apiserver ("we cannot rewrite the command line option from here") — kcm defaults it
    /// itself at reconcile time. If u7s defaulted it here too, that value would silently
    /// override whatever --horizontal-pod-autoscaler-downscale-stabilization flag kcm was
    /// started with.
    #[test]
    fn hpa_empty_scale_down_defaults_policy_but_not_stabilization_window() {
        let mut obj = serde_json::json!({
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "scaleTargetRef": { "kind": "Deployment", "name": "consumer" },
                "minReplicas": 10,
                "maxReplicas": 12,
                "behavior": { "scaleDown": {} }
            }
        });

        apply_defaults("autoscaling", "horizontalpodautoscalers", &mut obj);

        assert_eq!(
            obj["spec"]["behavior"]["scaleDown"]["selectPolicy"], "Max",
            "empty scaleDown must get selectPolicy defaulted, matching upstream \
             defaultHPAScaleDownRules"
        );
        assert_eq!(
            obj["spec"]["behavior"]["scaleDown"]["policies"],
            serde_json::json!([{ "type": "Percent", "value": 100, "periodSeconds": 15 }]),
            "empty scaleDown must get the default Percent policy, matching upstream \
             defaultHPAScaleDownRules"
        );
        assert!(
            obj["spec"]["behavior"]["scaleDown"]["stabilizationWindowSeconds"].is_null(),
            "scaleDown.stabilizationWindowSeconds must stay absent — upstream leaves it \
             for kcm's own maybeInitScaleDownStabilizationWindow runtime default, and \
             defaulting it here would silently override the --horizontal-pod-autoscaler- \
             downscale-stabilization flag kcm was started with"
        );
    }

    /// A caller-set scaleUp.stabilizationWindowSeconds must survive a second apply_defaults
    /// call unchanged.
    ///
    /// apply_defaults runs on every write (create AND update). If re-running it clobbered
    /// an already-defaulted or caller-set value back to the default, a user's explicit
    /// stabilization window would silently reset to 0 on the very next PATCH/PUT.
    #[test]
    fn hpa_scale_up_stabilization_window_survives_second_apply_defaults_call() {
        let mut obj = serde_json::json!({
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": { "name": "test", "namespace": "default" },
            "spec": {
                "scaleTargetRef": { "kind": "Deployment", "name": "consumer" },
                "minReplicas": 10,
                "maxReplicas": 12,
                "behavior": { "scaleUp": { "stabilizationWindowSeconds": 60 } }
            }
        });

        apply_defaults("autoscaling", "horizontalpodautoscalers", &mut obj);
        apply_defaults("autoscaling", "horizontalpodautoscalers", &mut obj);

        assert_eq!(
            obj["spec"]["behavior"]["scaleUp"]["stabilizationWindowSeconds"], 60,
            "caller-set stabilizationWindowSeconds must not be overwritten on a repeat \
             apply_defaults call (e.g. a subsequent update) — that would silently reset a \
             user's explicit scale-up stabilization window back to 0"
        );
    }
}

/// Regression tests for the typed-struct migration itself (mayor-ds8hb).
///
/// These tests exist independently of the behavioral tests above: they exist to
/// verify the *migration's own safety property* — that fields a `default_X`
/// function does not know about survive a defaulting pass unchanged (the
/// `rest: Value` catch-all). PR #1024 (mayor-xv1pk) shipped because a
/// Value-tree-based defaulting path had no structural guarantee that an
/// unlisted-but-real field would survive; a struct with a named field for
/// every reasoned-about value and `rest` for everything else makes that class
/// of silent field loss structurally impossible to reintroduce here.
#[cfg(test)]
mod typed_struct_migration_tests {
    use super::*;
    use crate::types::{CsiDriverSpec, HpaBehavior, HpaScalingRules};

    /// CSIDriver defaulting must preserve a spec field this codebase intentionally
    /// does not model (`seLinuxMount`, gated upstream behind an alpha feature flag —
    /// see the doc comment on `default_csidriver`) alongside applying its own defaults.
    /// If `CsiDriverSpec`'s `rest` flatten were removed or misconfigured, this field
    /// would silently vanish on the very first write after create.
    #[test]
    fn csidriver_defaulting_preserves_unmodeled_spec_field() {
        let mut obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSIDriver",
            "metadata": { "name": "csi.example.com" },
            "spec": { "seLinuxMount": true }
        });

        apply_defaults("storage.k8s.io", "csidrivers", &mut obj);

        assert_eq!(
            obj["spec"]["seLinuxMount"], true,
            "seLinuxMount is not reasoned about by default_csidriver but must survive \
             the defaulting pass via CsiDriverSpec::rest — losing it would silently \
             disable a field the client explicitly set"
        );
        assert_eq!(
            obj["spec"]["attachRequired"], true,
            "known fields must still be defaulted alongside the passthrough field"
        );
    }

    /// Directly exercises the typed core function (no JSON round-trip) to prove the
    /// struct's own field defaulting logic is correct independent of serde wiring.
    #[test]
    fn csidriver_spec_fields_default_reads_and_writes_round_trip_on_the_struct_itself() {
        let mut spec = CsiDriverSpec::default();
        default_csidriver_spec(&mut spec);

        assert_eq!(spec.attach_required, Some(true));
        assert_eq!(spec.pod_info_on_mount, Some(false));
        assert_eq!(spec.storage_capacity, Some(false));
        assert_eq!(
            spec.fs_group_policy.as_deref(),
            Some("ReadWriteOnceWithFSTypeFSGroupPolicy")
        );
        assert_eq!(
            spec.volume_lifecycle_modes.as_deref(),
            Some(["Persistent".to_string()].as_slice())
        );
        assert_eq!(spec.requires_republish, Some(false));
    }

    /// StorageClass defaulting must preserve top-level fields it never reasons about
    /// (`allowVolumeExpansion`, `mountOptions`, `parameters`) — these sit at the same
    /// level as `reclaimPolicy`/`volumeBindingMode` (StorageClass has no `.spec`
    /// wrapper), so a struct missing its `rest` flatten would drop them entirely.
    #[test]
    fn storageclass_defaulting_preserves_unreasoned_top_level_fields() {
        let mut obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": { "name": "custom-sc" },
            "provisioner": "example.com/driver",
            "allowVolumeExpansion": true,
            "mountOptions": ["debug"],
            "parameters": { "type": "gp3" }
        });

        apply_defaults("storage.k8s.io", "storageclasses", &mut obj);

        assert_eq!(
            obj["reclaimPolicy"], "Delete",
            "reclaimPolicy must still be defaulted"
        );
        assert_eq!(
            obj["allowVolumeExpansion"], true,
            "allowVolumeExpansion must survive — StorageClassFields does not name this field"
        );
        assert_eq!(
            obj["mountOptions"],
            serde_json::json!(["debug"]),
            "mountOptions must survive via StorageClassFields::rest"
        );
        assert_eq!(
            obj["parameters"]["type"], "gp3",
            "parameters must survive via StorageClassFields::rest"
        );
        assert_eq!(
            obj["provisioner"], "example.com/driver",
            "provisioner must survive — it is a top-level field StorageClassFields does not name"
        );
    }

    /// PVC defaulting must preserve spec/status fields it never reasons about
    /// (`storageClassName`, `accessModes`, `capacity`) alongside `status.phase`/
    /// `spec.volumeMode` defaulting.
    #[test]
    fn pvc_defaulting_preserves_unreasoned_spec_and_status_fields() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": "data", "namespace": "default" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "fast-ssd",
                "resources": { "requests": { "storage": "5Gi" } }
            },
            "status": {
                "capacity": { "storage": "5Gi" },
                "accessModes": ["ReadWriteOnce"]
            }
        });

        apply_defaults("", "persistentvolumeclaims", &mut obj);

        assert_eq!(
            obj["status"]["phase"], "Pending",
            "phase must still be defaulted"
        );
        assert_eq!(
            obj["spec"]["volumeMode"], "Filesystem",
            "volumeMode must still be defaulted"
        );
        assert_eq!(
            obj["spec"]["storageClassName"], "fast-ssd",
            "storageClassName must survive — PersistentVolumeSpecFields only names volumeMode"
        );
        assert_eq!(
            obj["spec"]["resources"]["requests"]["storage"], "5Gi",
            "resources must survive via PersistentVolumeSpecFields::rest"
        );
        assert_eq!(
            obj["status"]["capacity"]["storage"], "5Gi",
            "status.capacity must survive via PersistentVolumeStatusFields::rest"
        );
    }

    /// Service defaulting must preserve a spec-level field it never reasons about
    /// (`externalTrafficPolicy`) and a per-port field it never reasons about
    /// (`appProtocol`, `name`) alongside type/sessionAffinity/targetPort/protocol
    /// defaulting.
    #[test]
    fn service_defaulting_preserves_unreasoned_spec_and_port_fields() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "web", "namespace": "default" },
            "spec": {
                "externalTrafficPolicy": "Local",
                "selector": { "app": "web" },
                "ports": [{ "name": "https", "port": 443, "appProtocol": "https" }]
            }
        });

        apply_defaults("", "services", &mut obj);

        assert_eq!(
            obj["spec"]["type"], "ClusterIP",
            "type must still be defaulted"
        );
        assert_eq!(
            obj["spec"]["externalTrafficPolicy"], "Local",
            "externalTrafficPolicy must survive — ServiceSpec does not name this field"
        );
        assert_eq!(
            obj["spec"]["selector"]["app"], "web",
            "selector must survive via ServiceSpec::rest"
        );
        assert_eq!(
            obj["spec"]["ports"][0]["name"], "https",
            "port name must survive — ServicePort does not name this field"
        );
        assert_eq!(
            obj["spec"]["ports"][0]["appProtocol"], "https",
            "appProtocol must survive via ServicePort::rest"
        );
        assert_eq!(
            obj["spec"]["ports"][0]["targetPort"], 443,
            "targetPort must still be defaulted from port"
        );
    }

    /// Deployment defaulting must preserve spec fields it never reasons about
    /// (`paused`, `minReadySeconds`) and a strategy.rollingUpdate field it never
    /// reasons about, alongside selector/replicas/strategy defaulting.
    #[test]
    fn deployment_defaulting_preserves_unreasoned_spec_and_strategy_fields() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "web" },
            "spec": {
                "paused": true,
                "minReadySeconds": 5,
                "selector": { "matchLabels": { "app": "web" } },
                "template": {},
                "strategy": { "rollingUpdate": { "maxSurge": 1 } }
            }
        });

        apply_defaults("apps", "deployments", &mut obj);

        assert_eq!(
            obj["spec"]["strategy"]["type"], "RollingUpdate",
            "strategy.type must still default"
        );
        assert_eq!(
            obj["spec"]["paused"], true,
            "paused must survive — DeploymentSpec does not name this field"
        );
        assert_eq!(
            obj["spec"]["minReadySeconds"], 5,
            "minReadySeconds must survive via DeploymentSpec::rest"
        );
        assert_eq!(
            obj["spec"]["strategy"]["rollingUpdate"]["maxSurge"], 1,
            "an explicit maxSurge must not be overwritten by the 25% default"
        );
        assert_eq!(
            obj["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"], "25%",
            "maxUnavailable must still be defaulted per-field, independent of maxSurge"
        );
    }

    /// Job defaulting must preserve pod template fields it never reasons about
    /// (`containers`, `restartPolicy`) alongside the label-injection and
    /// backoffLimit/parallelism defaulting.
    #[test]
    fn job_defaulting_preserves_unreasoned_pod_template_fields() {
        let uid = "11111111-2222-3333-4444-555555555555";
        let mut obj = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "my-job", "namespace": "default", "uid": uid },
            "spec": {
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{ "name": "c", "image": "busybox" }]
                    }
                }
            }
        });

        apply_defaults("batch", "jobs", &mut obj);

        assert_eq!(
            obj["spec"]["backoffLimit"], 6,
            "backoffLimit must still be defaulted"
        );
        assert_eq!(
            obj["spec"]["template"]["spec"]["restartPolicy"], "Never",
            "restartPolicy must survive — DefaultingPodTemplateSpec does not name this field"
        );
        assert_eq!(
            obj["spec"]["template"]["spec"]["containers"][0]["image"], "busybox",
            "containers must survive via DefaultingPodTemplateSpec::rest — losing them \
             would silently empty every Job's pod template"
        );
        assert_eq!(
            obj["spec"]["template"]["metadata"]["labels"]["batch.kubernetes.io/controller-uid"],
            uid,
            "label injection must still happen on the same template object whose \
             unreasoned fields were preserved"
        );
    }

    /// HorizontalPodAutoscaler behavior defaulting must preserve a field on
    /// `scaleUp` it never reasons about (`tolerance`) alongside
    /// stabilizationWindowSeconds/selectPolicy/policies defaulting. Exercises the
    /// typed core function directly, independent of JSON wiring.
    #[test]
    fn hpa_behavior_fields_preserve_unreasoned_tolerance_field() {
        let mut behavior = HpaBehavior {
            scale_up: Some(HpaScalingRules {
                stabilization_window_seconds: None,
                select_policy: None,
                policies: None,
                rest: serde_json::json!({ "tolerance": "20m" }),
            }),
            scale_down: None,
            rest: serde_json::Value::Object(Default::default()),
        };

        default_hpa_behavior(&mut behavior);

        let scale_up = behavior.scale_up.unwrap();
        assert_eq!(scale_up.stabilization_window_seconds, Some(0));
        assert_eq!(scale_up.select_policy.as_deref(), Some("Max"));
        assert!(scale_up.policies.is_some());
        assert_eq!(
            scale_up.rest["tolerance"], "20m",
            "tolerance must survive on the struct itself via HpaScalingRules::rest"
        );
    }

    /// A CSIDriver with `spec` entirely absent must still get every pointer-typed
    /// field defaulted — matching the existing Value-tree behavior, where indexing
    /// into a missing `spec` autovivifies it to `{}` before the field checks run.
    /// This is the "missing field" contract the typed struct must preserve: an
    /// absent `spec` is not a rejection path here (validation, if any, happens
    /// elsewhere in the request pipeline), it is treated identically to `spec: {}`.
    #[test]
    fn csidriver_with_spec_entirely_absent_still_gets_full_defaults() {
        let mut obj = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSIDriver",
            "metadata": { "name": "csi.example.com" }
        });

        apply_defaults("storage.k8s.io", "csidrivers", &mut obj);

        assert_eq!(
            obj["spec"]["attachRequired"], true,
            "an entirely absent spec must be treated as an empty object, not skipped — \
             CsiDriverSpec::default() plus unwrap_or_default() must reproduce the same \
             autovivify-then-default behavior the raw Value indexing had"
        );
        assert_eq!(obj["spec"]["requiresRepublish"], false);
    }

    /// RoleBinding defaulting must preserve `roleRef.kind`/`roleRef.name` — fields
    /// `RoleRefFields` does not name — alongside the `apiGroup` default.
    #[test]
    fn role_ref_defaulting_preserves_kind_and_name() {
        let mut obj = serde_json::json!({
            "metadata": { "name": "b", "namespace": "default" },
            "roleRef": { "kind": "Role", "name": "my-role" }
        });

        apply_defaults("rbac.authorization.k8s.io", "rolebindings", &mut obj);

        assert_eq!(obj["roleRef"]["apiGroup"], "rbac.authorization.k8s.io");
        assert_eq!(
            obj["roleRef"]["kind"], "Role",
            "roleRef.kind must survive — RoleRefFields only names apiGroup"
        );
        assert_eq!(
            obj["roleRef"]["name"], "my-role",
            "roleRef.name must survive via RoleRefFields::rest"
        );
    }
}
