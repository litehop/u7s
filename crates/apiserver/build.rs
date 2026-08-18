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

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build/codegen.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("src/proto_exceptions.rs").display()
    );
}
