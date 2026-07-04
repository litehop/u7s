use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("proto-include");

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");

    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);

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
            ],
            &[include_dir.to_str().unwrap()],
        )
        .expect("prost-build failed");

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("proto-include").display()
    );
}
