use std::path::PathBuf;

#[path = "build/codegen.rs"]
mod codegen;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    // The prost invocation over the vendored .proto files (and the FileDescriptorSet it emits)
    // now lives in u7s-proto-generated, which u7s-apiserver depends on both normally (for the
    // generated message types themselves) and as a build-dependency (for the descriptor bytes
    // below) — see that crate's build.rs/lib.rs for why the types moved into their own crate.
    let descriptor_bytes = u7s_proto_generated::DESCRIPTOR_BYTES;
    std::fs::write(
        out_dir.join("object_reference_gen.rs"),
        codegen::generate_object_reference(descriptor_bytes),
    )
    .expect("failed to write generated ObjectReference codec");
    std::fs::write(
        out_dir.join("volume_source_gen.rs"),
        codegen::generate_volume_source(descriptor_bytes),
    )
    .expect("failed to write generated VolumeSource codec");
    std::fs::write(
        out_dir.join("container_gen.rs"),
        codegen::generate_container(descriptor_bytes),
    )
    .expect("failed to write generated Container codec");
    std::fs::write(
        out_dir.join("container_status_gen.rs"),
        codegen::generate_container_status(descriptor_bytes),
    )
    .expect("failed to write generated ContainerStatus codec");
    std::fs::write(
        out_dir.join("ephemeral_container_gen.rs"),
        codegen::generate_ephemeral_container(descriptor_bytes),
    )
    .expect("failed to write generated EphemeralContainer codec");
    std::fs::write(
        out_dir.join("pod_spec_gen.rs"),
        codegen::generate_pod_spec(descriptor_bytes),
    )
    .expect("failed to write generated PodSpec codec");
    std::fs::write(
        out_dir.join("pod_status_gen.rs"),
        codegen::generate_pod_status(descriptor_bytes),
    )
    .expect("failed to write generated PodStatus codec");
    std::fs::write(
        out_dir.join("namespace_gen.rs"),
        codegen::generate_namespace(descriptor_bytes),
    )
    .expect("failed to write generated Namespace codec");
    std::fs::write(
        out_dir.join("namespace_status_gen.rs"),
        codegen::generate_namespace_status(descriptor_bytes),
    )
    .expect("failed to write generated NamespaceStatus codec");
    std::fs::write(
        out_dir.join("configmap_gen.rs"),
        codegen::generate_configmap(descriptor_bytes),
    )
    .expect("failed to write generated ConfigMap codec");
    std::fs::write(
        out_dir.join("secret_gen.rs"),
        codegen::generate_secret(descriptor_bytes),
    )
    .expect("failed to write generated Secret codec");
    std::fs::write(
        out_dir.join("resourcequota_spec_gen.rs"),
        codegen::generate_resourcequota_spec(descriptor_bytes),
    )
    .expect("failed to write generated ResourceQuotaSpec codec");
    std::fs::write(
        out_dir.join("resourcequota_gen.rs"),
        codegen::generate_resourcequota(descriptor_bytes),
    )
    .expect("failed to write generated ResourceQuota codec");
    std::fs::write(
        out_dir.join("limitrange_spec_gen.rs"),
        codegen::generate_limitrange_spec(descriptor_bytes),
    )
    .expect("failed to write generated LimitRangeSpec codec");
    std::fs::write(
        out_dir.join("limitrange_gen.rs"),
        codegen::generate_limitrange(descriptor_bytes),
    )
    .expect("failed to write generated LimitRange codec");
    std::fs::write(
        out_dir.join("replicationcontroller_spec_gen.rs"),
        codegen::generate_replicationcontroller_spec(descriptor_bytes),
    )
    .expect("failed to write generated ReplicationControllerSpec codec");
    std::fs::write(
        out_dir.join("replicationcontroller_status_gen.rs"),
        codegen::generate_replicationcontroller_status(descriptor_bytes),
    )
    .expect("failed to write generated ReplicationControllerStatus codec");
    std::fs::write(
        out_dir.join("replicationcontroller_gen.rs"),
        codegen::generate_replicationcontroller(descriptor_bytes),
    )
    .expect("failed to write generated ReplicationController codec");
    std::fs::write(
        out_dir.join("event_gen.rs"),
        codegen::generate_event(descriptor_bytes),
    )
    .expect("failed to write generated Event codec");
    std::fs::write(
        out_dir.join("node_spec_gen.rs"),
        codegen::generate_node_spec(descriptor_bytes),
    )
    .expect("failed to write generated NodeSpec codec");
    std::fs::write(
        out_dir.join("node_status_gen.rs"),
        codegen::generate_node_status(descriptor_bytes),
    )
    .expect("failed to write generated NodeStatus codec");
    std::fs::write(
        out_dir.join("node_gen.rs"),
        codegen::generate_node(descriptor_bytes),
    )
    .expect("failed to write generated Node codec");
    std::fs::write(
        out_dir.join("persistentvolume_spec_gen.rs"),
        codegen::generate_persistentvolume_spec(descriptor_bytes),
    )
    .expect("failed to write generated PersistentVolumeSpec codec");
    std::fs::write(
        out_dir.join("persistentvolume_status_gen.rs"),
        codegen::generate_persistentvolume_status(descriptor_bytes),
    )
    .expect("failed to write generated PersistentVolumeStatus codec");
    std::fs::write(
        out_dir.join("persistentvolume_gen.rs"),
        codegen::generate_persistentvolume(descriptor_bytes),
    )
    .expect("failed to write generated PersistentVolume codec");
    std::fs::write(
        out_dir.join("persistentvolumeclaim_spec_gen.rs"),
        codegen::generate_persistentvolumeclaim_spec(descriptor_bytes),
    )
    .expect("failed to write generated PersistentVolumeClaimSpec codec");
    std::fs::write(
        out_dir.join("persistentvolumeclaim_status_gen.rs"),
        codegen::generate_persistentvolumeclaim_status(descriptor_bytes),
    )
    .expect("failed to write generated PersistentVolumeClaimStatus codec");
    std::fs::write(
        out_dir.join("service_spec_gen.rs"),
        codegen::generate_service_spec(descriptor_bytes),
    )
    .expect("failed to write generated ServiceSpec codec");
    std::fs::write(
        out_dir.join("service_status_gen.rs"),
        codegen::generate_service_status(descriptor_bytes),
    )
    .expect("failed to write generated ServiceStatus codec");
    std::fs::write(
        out_dir.join("service_gen.rs"),
        codegen::generate_service(descriptor_bytes),
    )
    .expect("failed to write generated Service codec");
    std::fs::write(
        out_dir.join("endpoints_gen.rs"),
        codegen::generate_endpoints(descriptor_bytes),
    )
    .expect("failed to write generated Endpoints codec");
    std::fs::write(
        out_dir.join("pod_gen.rs"),
        codegen::generate_pod(descriptor_bytes),
    )
    .expect("failed to write generated Pod codec");
    std::fs::write(
        out_dir.join("pod_template_spec_gen.rs"),
        codegen::generate_pod_template_spec(descriptor_bytes),
    )
    .expect("failed to write generated PodTemplateSpec codec");
    std::fs::write(
        out_dir.join("podtemplate_gen.rs"),
        codegen::generate_podtemplate(descriptor_bytes),
    )
    .expect("failed to write generated PodTemplate codec");
    std::fs::write(
        out_dir.join("serviceaccount_gen.rs"),
        codegen::generate_serviceaccount(descriptor_bytes),
    )
    .expect("failed to write generated ServiceAccount codec");
    std::fs::write(
        out_dir.join("apiservice_spec_gen.rs"),
        codegen::generate_apiservice_spec(descriptor_bytes),
    )
    .expect("failed to write generated APIServiceSpec codec");
    std::fs::write(
        out_dir.join("apiservice_status_gen.rs"),
        codegen::generate_apiservice_status(descriptor_bytes),
    )
    .expect("failed to write generated APIServiceStatus codec");
    std::fs::write(
        out_dir.join("apiservice_gen.rs"),
        codegen::generate_apiservice(descriptor_bytes),
    )
    .expect("failed to write generated APIService codec");
    std::fs::write(
        out_dir.join("lease_spec_gen.rs"),
        codegen::generate_lease_spec(descriptor_bytes),
    )
    .expect("failed to write generated LeaseSpec codec");
    std::fs::write(
        out_dir.join("lease_gen.rs"),
        codegen::generate_lease(descriptor_bytes),
    )
    .expect("failed to write generated Lease codec");
    std::fs::write(
        out_dir.join("leasecandidate_spec_gen.rs"),
        codegen::generate_leasecandidate_spec(descriptor_bytes),
    )
    .expect("failed to write generated LeaseCandidateSpec codec");
    std::fs::write(
        out_dir.join("leasecandidate_gen.rs"),
        codegen::generate_leasecandidate(descriptor_bytes),
    )
    .expect("failed to write generated LeaseCandidate codec");
    std::fs::write(
        out_dir.join("policy_rule_gen.rs"),
        codegen::generate_policy_rule(descriptor_bytes),
    )
    .expect("failed to write generated PolicyRule codec");
    std::fs::write(
        out_dir.join("subject_gen.rs"),
        codegen::generate_subject(descriptor_bytes),
    )
    .expect("failed to write generated Subject codec");
    std::fs::write(
        out_dir.join("role_ref_gen.rs"),
        codegen::generate_role_ref(descriptor_bytes),
    )
    .expect("failed to write generated RoleRef codec");
    std::fs::write(
        out_dir.join("clusterrole_gen.rs"),
        codegen::generate_clusterrole(descriptor_bytes),
    )
    .expect("failed to write generated ClusterRole codec");
    std::fs::write(
        out_dir.join("clusterrolebinding_gen.rs"),
        codegen::generate_clusterrolebinding(descriptor_bytes),
    )
    .expect("failed to write generated ClusterRoleBinding codec");
    std::fs::write(
        out_dir.join("role_gen.rs"),
        codegen::generate_role(descriptor_bytes),
    )
    .expect("failed to write generated Role codec");
    std::fs::write(
        out_dir.join("rolebinding_gen.rs"),
        codegen::generate_rolebinding(descriptor_bytes),
    )
    .expect("failed to write generated RoleBinding codec");
    std::fs::write(
        out_dir.join("deployment_spec_gen.rs"),
        codegen::generate_deployment_spec(descriptor_bytes),
    )
    .expect("failed to write generated DeploymentSpec codec");
    std::fs::write(
        out_dir.join("deployment_status_gen.rs"),
        codegen::generate_deployment_status(descriptor_bytes),
    )
    .expect("failed to write generated DeploymentStatus codec");
    std::fs::write(
        out_dir.join("deployment_gen.rs"),
        codegen::generate_deployment(descriptor_bytes),
    )
    .expect("failed to write generated Deployment codec");
    std::fs::write(
        out_dir.join("statefulset_spec_gen.rs"),
        codegen::generate_statefulset_spec(descriptor_bytes),
    )
    .expect("failed to write generated StatefulSetSpec codec");
    std::fs::write(
        out_dir.join("statefulset_status_gen.rs"),
        codegen::generate_statefulset_status(descriptor_bytes),
    )
    .expect("failed to write generated StatefulSetStatus codec");
    std::fs::write(
        out_dir.join("statefulset_gen.rs"),
        codegen::generate_statefulset(descriptor_bytes),
    )
    .expect("failed to write generated StatefulSet codec");
    std::fs::write(
        out_dir.join("daemonset_spec_gen.rs"),
        codegen::generate_daemonset_spec(descriptor_bytes),
    )
    .expect("failed to write generated DaemonSetSpec codec");
    std::fs::write(
        out_dir.join("daemonset_status_gen.rs"),
        codegen::generate_daemonset_status(descriptor_bytes),
    )
    .expect("failed to write generated DaemonSetStatus codec");
    std::fs::write(
        out_dir.join("daemonset_gen.rs"),
        codegen::generate_daemonset(descriptor_bytes),
    )
    .expect("failed to write generated DaemonSet codec");
    std::fs::write(
        out_dir.join("replicaset_spec_gen.rs"),
        codegen::generate_replicaset_spec(descriptor_bytes),
    )
    .expect("failed to write generated ReplicaSetSpec codec");
    std::fs::write(
        out_dir.join("replicaset_status_gen.rs"),
        codegen::generate_replicaset_status(descriptor_bytes),
    )
    .expect("failed to write generated ReplicaSetStatus codec");
    std::fs::write(
        out_dir.join("replicaset_gen.rs"),
        codegen::generate_replicaset(descriptor_bytes),
    )
    .expect("failed to write generated ReplicaSet codec");
    std::fs::write(
        out_dir.join("controllerrevision_gen.rs"),
        codegen::generate_controllerrevision(descriptor_bytes),
    )
    .expect("failed to write generated ControllerRevision codec");
    std::fs::write(
        out_dir.join("endpoint_gen.rs"),
        codegen::generate_endpoint(descriptor_bytes),
    )
    .expect("failed to write generated Endpoint codec");
    std::fs::write(
        out_dir.join("endpointslice_gen.rs"),
        codegen::generate_endpointslice(descriptor_bytes),
    )
    .expect("failed to write generated EndpointSlice codec");
    std::fs::write(
        out_dir.join("network_policy_spec_gen.rs"),
        codegen::generate_network_policy_spec(descriptor_bytes),
    )
    .expect("failed to write generated NetworkPolicySpec codec");
    std::fs::write(
        out_dir.join("networkpolicy_gen.rs"),
        codegen::generate_networkpolicy(descriptor_bytes),
    )
    .expect("failed to write generated NetworkPolicy codec");
    std::fs::write(
        out_dir.join("ingressclass_gen.rs"),
        codegen::generate_ingressclass(descriptor_bytes),
    )
    .expect("failed to write generated IngressClass codec");
    std::fs::write(
        out_dir.join("ipaddress_gen.rs"),
        codegen::generate_ipaddress(descriptor_bytes),
    )
    .expect("failed to write generated IPAddress codec");
    std::fs::write(
        out_dir.join("servicecidr_status_gen.rs"),
        codegen::generate_servicecidr_status(descriptor_bytes),
    )
    .expect("failed to write generated ServiceCIDRStatus codec");
    std::fs::write(
        out_dir.join("servicecidr_gen.rs"),
        codegen::generate_servicecidr(descriptor_bytes),
    )
    .expect("failed to write generated ServiceCIDR codec");
    std::fs::write(
        out_dir.join("ingress_spec_gen.rs"),
        codegen::generate_ingress_spec(descriptor_bytes),
    )
    .expect("failed to write generated IngressSpec codec");
    std::fs::write(
        out_dir.join("ingress_gen.rs"),
        codegen::generate_ingress(descriptor_bytes),
    )
    .expect("failed to write generated Ingress codec");
    std::fs::write(
        out_dir.join("csr_spec_gen.rs"),
        codegen::generate_certificate_signing_request_spec(descriptor_bytes),
    )
    .expect("failed to write generated CertificateSigningRequestSpec codec");
    std::fs::write(
        out_dir.join("csr_status_gen.rs"),
        codegen::generate_certificate_signing_request_status(descriptor_bytes),
    )
    .expect("failed to write generated CertificateSigningRequestStatus codec");
    std::fs::write(
        out_dir.join("csr_gen.rs"),
        codegen::generate_certificate_signing_request(descriptor_bytes),
    )
    .expect("failed to write generated CertificateSigningRequest codec");
    std::fs::write(
        out_dir.join("poddisruptionbudget_spec_gen.rs"),
        codegen::generate_poddisruptionbudget_spec(descriptor_bytes),
    )
    .expect("failed to write generated PodDisruptionBudgetSpec codec");
    std::fs::write(
        out_dir.join("poddisruptionbudget_status_gen.rs"),
        codegen::generate_poddisruptionbudget_status(descriptor_bytes),
    )
    .expect("failed to write generated PodDisruptionBudgetStatus codec");
    std::fs::write(
        out_dir.join("poddisruptionbudget_gen.rs"),
        codegen::generate_poddisruptionbudget(descriptor_bytes),
    )
    .expect("failed to write generated PodDisruptionBudget codec");
    std::fs::write(
        out_dir.join("events_v1_event_gen.rs"),
        codegen::generate_events_v1_event(descriptor_bytes),
    )
    .expect("failed to write generated events.k8s.io/v1 Event codec");
    std::fs::write(
        out_dir.join("apply_configuration_gen.rs"),
        codegen::generate_apply_configuration(descriptor_bytes),
    )
    .expect("failed to write generated ApplyConfiguration codec");
    std::fs::write(
        out_dir.join("json_patch_gen.rs"),
        codegen::generate_json_patch(descriptor_bytes),
    )
    .expect("failed to write generated JSONPatch codec");
    std::fs::write(
        out_dir.join("audit_annotation_gen.rs"),
        codegen::generate_audit_annotation(descriptor_bytes),
    )
    .expect("failed to write generated AuditAnnotation codec");
    std::fs::write(
        out_dir.join("expression_warning_gen.rs"),
        codegen::generate_expression_warning(descriptor_bytes),
    )
    .expect("failed to write generated ExpressionWarning codec");
    std::fs::write(
        out_dir.join("variable_gen.rs"),
        codegen::generate_variable(descriptor_bytes),
    )
    .expect("failed to write generated Variable codec");
    std::fs::write(
        out_dir.join("match_condition_gen.rs"),
        codegen::generate_match_condition(descriptor_bytes),
    )
    .expect("failed to write generated MatchCondition codec");
    std::fs::write(
        out_dir.join("param_kind_gen.rs"),
        codegen::generate_param_kind(descriptor_bytes),
    )
    .expect("failed to write generated ParamKind codec");
    std::fs::write(
        out_dir.join("service_reference_gen.rs"),
        codegen::generate_service_reference(descriptor_bytes),
    )
    .expect("failed to write generated ServiceReference codec");
    std::fs::write(
        out_dir.join("webhook_client_config_gen.rs"),
        codegen::generate_webhook_client_config(descriptor_bytes),
    )
    .expect("failed to write generated WebhookClientConfig codec");
    std::fs::write(
        out_dir.join("rule_with_operations_gen.rs"),
        codegen::generate_rule_with_operations(descriptor_bytes),
    )
    .expect("failed to write generated RuleWithOperations codec");
    std::fs::write(
        out_dir.join("named_rule_with_operations_gen.rs"),
        codegen::generate_named_rule_with_operations(descriptor_bytes),
    )
    .expect("failed to write generated NamedRuleWithOperations codec");
    std::fs::write(
        out_dir.join("match_resources_gen.rs"),
        codegen::generate_match_resources(descriptor_bytes),
    )
    .expect("failed to write generated MatchResources codec");
    std::fs::write(
        out_dir.join("param_ref_gen.rs"),
        codegen::generate_param_ref(descriptor_bytes),
    )
    .expect("failed to write generated ParamRef codec");
    std::fs::write(
        out_dir.join("validating_webhook_gen.rs"),
        codegen::generate_validating_webhook(descriptor_bytes),
    )
    .expect("failed to write generated ValidatingWebhook codec");
    std::fs::write(
        out_dir.join("mutating_webhook_gen.rs"),
        codegen::generate_mutating_webhook(descriptor_bytes),
    )
    .expect("failed to write generated MutatingWebhook codec");
    std::fs::write(
        out_dir.join("validating_webhook_configuration_gen.rs"),
        codegen::generate_validating_webhook_configuration(descriptor_bytes),
    )
    .expect("failed to write generated ValidatingWebhookConfiguration codec");
    std::fs::write(
        out_dir.join("mutating_webhook_configuration_gen.rs"),
        codegen::generate_mutating_webhook_configuration(descriptor_bytes),
    )
    .expect("failed to write generated MutatingWebhookConfiguration codec");
    std::fs::write(
        out_dir.join("validation_gen.rs"),
        codegen::generate_validation(descriptor_bytes),
    )
    .expect("failed to write generated Validation codec");
    std::fs::write(
        out_dir.join("type_checking_gen.rs"),
        codegen::generate_type_checking(descriptor_bytes),
    )
    .expect("failed to write generated TypeChecking codec");
    std::fs::write(
        out_dir.join("vap_condition_gen.rs"),
        codegen::generate_vap_condition(descriptor_bytes),
    )
    .expect("failed to write generated ValidatingAdmissionPolicyStatus Condition codec");
    std::fs::write(
        out_dir.join("validating_admission_policy_spec_gen.rs"),
        codegen::generate_validating_admission_policy_spec(descriptor_bytes),
    )
    .expect("failed to write generated ValidatingAdmissionPolicySpec codec");
    std::fs::write(
        out_dir.join("validating_admission_policy_status_gen.rs"),
        codegen::generate_validating_admission_policy_status(descriptor_bytes),
    )
    .expect("failed to write generated ValidatingAdmissionPolicyStatus codec");
    std::fs::write(
        out_dir.join("validating_admission_policy_gen.rs"),
        codegen::generate_validating_admission_policy(descriptor_bytes),
    )
    .expect("failed to write generated ValidatingAdmissionPolicy codec");
    std::fs::write(
        out_dir.join("validating_admission_policy_binding_spec_gen.rs"),
        codegen::generate_validating_admission_policy_binding_spec(descriptor_bytes),
    )
    .expect("failed to write generated ValidatingAdmissionPolicyBindingSpec codec");
    std::fs::write(
        out_dir.join("validating_admission_policy_binding_gen.rs"),
        codegen::generate_validating_admission_policy_binding(descriptor_bytes),
    )
    .expect("failed to write generated ValidatingAdmissionPolicyBinding codec");
    std::fs::write(
        out_dir.join("mutation_gen.rs"),
        codegen::generate_mutation(descriptor_bytes),
    )
    .expect("failed to write generated Mutation codec");
    std::fs::write(
        out_dir.join("mutating_admission_policy_spec_gen.rs"),
        codegen::generate_mutating_admission_policy_spec(descriptor_bytes),
    )
    .expect("failed to write generated MutatingAdmissionPolicySpec codec");
    std::fs::write(
        out_dir.join("mutating_admission_policy_gen.rs"),
        codegen::generate_mutating_admission_policy(descriptor_bytes),
    )
    .expect("failed to write generated MutatingAdmissionPolicy codec");
    std::fs::write(
        out_dir.join("mutating_admission_policy_binding_spec_gen.rs"),
        codegen::generate_mutating_admission_policy_binding_spec(descriptor_bytes),
    )
    .expect("failed to write generated MutatingAdmissionPolicyBindingSpec codec");
    std::fs::write(
        out_dir.join("mutating_admission_policy_binding_gen.rs"),
        codegen::generate_mutating_admission_policy_binding(descriptor_bytes),
    )
    .expect("failed to write generated MutatingAdmissionPolicyBinding codec");

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build/codegen.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("src/proto_exceptions.rs").display()
    );
}
