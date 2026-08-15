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

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build/codegen.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("src/proto_exceptions.rs").display()
    );
}
