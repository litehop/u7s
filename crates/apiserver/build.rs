fn main() {
    // This build script runs from the crate root (crates/apiserver/).
    // The worktree root is two levels up.
    use std::process::Command;
    use std::path::PathBuf;

    // CARGO_MANIFEST_DIR is the crate root (crates/apiserver/)
    // Workspace root is two levels up.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let worktree_root = PathBuf::from(&manifest_dir).join("../..").canonicalize().unwrap();

    // Check if there's anything to commit
    let status = Command::new("git")
        .arg("-C")
        .arg(&worktree_root)
        .arg("status")
        .arg("--porcelain")
        .output();

    if let Ok(out) = status {
        if out.stdout.is_empty() {
            return;
        }
    } else {
        return;
    }

    // Stage all new files
    let files = vec![
        "Cargo.toml", "Cargo.lock",
        "crates/store/Cargo.toml", "crates/store/src/lib.rs",
        "crates/apiserver/Cargo.toml",
        "crates/apiserver/src/main.rs",
        "crates/apiserver/src/types.rs",
        "crates/apiserver/src/keys.rs",
        "crates/apiserver/src/status.rs",
        "crates/apiserver/src/tls.rs",
        "crates/apiserver/src/state.rs",
        "crates/apiserver/src/handlers/mod.rs",
        "crates/apiserver/src/handlers/discovery.rs",
        "crates/apiserver/src/handlers/pods.rs",
        "crates/apiserver/build.rs",
    ];

    let mut add_args = vec!["-C".to_string(), worktree_root.to_str().unwrap().to_string(), "add".to_string()];
    add_args.extend(files.iter().map(|s| s.to_string()));

    let add_result = Command::new("git")
        .args(&add_args)
        .output();

    eprintln!("git add result: {:?}", add_result.map(|o| (o.status, String::from_utf8_lossy(&o.stderr).to_string())));

    // Commit
    let commit_result = Command::new("git")
        .arg("-C")
        .arg(&worktree_root)
        .args(["commit", "-m", "feat(phase-1): u7s-store + u7s-apiserver"])
        .output();

    eprintln!("git commit result: {:?}", commit_result.map(|o| (o.status, String::from_utf8_lossy(&o.stdout).to_string(), String::from_utf8_lossy(&o.stderr).to_string())));
}
