//! `u7s migrate`: move a single-node k3s cluster onto u7s through the
//! Kubernetes API.

pub mod classify;
pub mod discover;
pub mod import;
pub mod plan;

/// Writes `data` to a new file readable by the owner only. An existing path is
/// refused, never truncated or reused, so a pre-existing file's looser mode
/// cannot expose the contents; `O_CREAT|O_EXCL` also refuses a symlink (even a
/// dangling one) instead of writing through it.
pub fn write_new_private(path: &str, data: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| {
            format!("creating {path} (it must not exist; remove or rename the old file first)")
        })?;
    f.write_all(data).with_context(|| format!("writing {path}"))
}

#[cfg(test)]
mod tests {
    use super::write_new_private;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("u7s-migrate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn new_objects_file_is_owner_only_because_it_holds_secrets() {
        let d = dir("new");
        let p = d.join("o.json");
        write_new_private(p.to_str().unwrap(), b"[]").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "group/world must not read exported Secrets");
    }

    #[test]
    fn pre_existing_world_readable_objects_file_is_refused_and_left_unchanged() {
        let d = dir("exists");
        let p = d.join("o.json");
        std::fs::write(&p, b"old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(write_new_private(p.to_str().unwrap(), b"secrets").is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"old");
    }

    #[test]
    fn symlinked_objects_path_is_refused_and_target_untouched() {
        let d = dir("link");
        let target = d.join("victim");
        std::fs::write(&target, b"precious").unwrap();
        let link = d.join("o.json");
        symlink(&target, &link).unwrap();
        assert!(write_new_private(link.to_str().unwrap(), b"secrets").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"precious");
    }
}
