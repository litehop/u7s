use std::path::PathBuf;

#[path = "build/codegen.rs"]
mod codegen;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("proto-include");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");

    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    // Emit the FileDescriptorSet alongside the generated structs so the sentinel completeness
    // tests can derive their expected-JSON-key lists from the .proto schema itself instead of
    // hand-maintaining them (see the test-only `proto_descriptor` module). A hand-written
    // expected list can omit the same field the decoder omits and still pass green; a list
    // derived from the descriptor cannot.
    config.file_descriptor_set_path(out_dir.join("k8s_descriptors.bin"));
    // Blanket-derive Sentinel on every generated message so gen_*_to_json completeness tests
    // (see core_gen_adapter.rs's tests module) can build a fully-populated instance of any
    // message type without hand-listing its fields. Safe as a "." (root) pattern only because
    // the vendored .proto schema has no `oneof`/`enum` types for it to hit (verified by grep);
    // if one is ever added, u7s-sentinel-derive fails the build loudly instead of silently
    // producing an incomplete sentinel.
    config.type_attribute(".", "#[derive(u7s_sentinel::Sentinel)]");

    config
        .compile_protos(
            &[
                include_dir
                    .join("k8s.io/api/coordination/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/apimachinery/pkg/apis/meta/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/apimachinery/pkg/runtime/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/apps/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/core/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/batch/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/storage/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/node/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/flowcontrol/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/scheduling/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/admissionregistration/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/rbac/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/authentication/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/authorization/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join(
                        "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1/generated.proto",
                    )
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/networking/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/discovery/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/certificates/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/policy/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/events/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/kube-aggregator/pkg/apis/apiregistration/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/autoscaling/v1/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/autoscaling/v2/generated.proto")
                    .to_str()
                    .unwrap(),
                include_dir
                    .join("k8s.io/api/resource/v1/generated.proto")
                    .to_str()
                    .unwrap(),
            ],
            &[include_dir.to_str().unwrap()],
        )
        .expect("prost-build failed");

    let descriptor_bytes =
        std::fs::read(out_dir.join("k8s_descriptors.bin")).expect("descriptor set just written");
    std::fs::write(
        out_dir.join("object_reference_gen.rs"),
        codegen::generate_object_reference(&descriptor_bytes),
    )
    .expect("failed to write generated ObjectReference codec");
    std::fs::write(
        out_dir.join("volume_source_gen.rs"),
        codegen::generate_volume_source(&descriptor_bytes),
    )
    .expect("failed to write generated VolumeSource codec");
    std::fs::write(
        out_dir.join("container_gen.rs"),
        codegen::generate_container(&descriptor_bytes),
    )
    .expect("failed to write generated Container codec");
    std::fs::write(
        out_dir.join("container_status_gen.rs"),
        codegen::generate_container_status(&descriptor_bytes),
    )
    .expect("failed to write generated ContainerStatus codec");
    std::fs::write(
        out_dir.join("pod_spec_gen.rs"),
        codegen::generate_pod_spec(&descriptor_bytes),
    )
    .expect("failed to write generated PodSpec codec");
    std::fs::write(
        out_dir.join("pod_status_gen.rs"),
        codegen::generate_pod_status(&descriptor_bytes),
    )
    .expect("failed to write generated PodStatus codec");

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("proto-include").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build/codegen.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("src/proto_exceptions.rs").display()
    );
}
