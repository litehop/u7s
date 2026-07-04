use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("proto-include");

    // Compile coordination/v1 and its transitive dependencies.
    // meta-v1 imports runtime, both are in our include tree.
    // schema/generated is imported but empty (no types referenced from it).
    let mut config = prost_build::Config::new();

    // Adapter B: add serde derives to ALL generated types in these packages.
    // Using "." applies to every type in every compiled proto.
    // This is needed because ObjectMeta transitively references ManagedFieldsEntry,
    // FieldsV1, OwnerReference, Time, etc. — serde requires the full closure.
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

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
            ],
            &[include_dir.to_str().unwrap()],
        )
        .expect("prost-build failed for coordination/v1");

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("proto-include").display()
    );
}
