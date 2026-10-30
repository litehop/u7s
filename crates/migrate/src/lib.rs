//! `u7s migrate`: move a single-node k3s cluster onto u7s through the
//! Kubernetes API.

pub mod classify;
pub mod cutover;
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

/// Fails if `path` exists (a dangling symlink counts), so a doomed export is
/// refused before any network work or file write.
pub fn refuse_existing(path: &str) -> anyhow::Result<()> {
    if std::fs::symlink_metadata(path).is_ok() {
        anyhow::bail!("{path} already exists; remove or rename the old file first");
    }
    Ok(())
}

/// Writes the export files. The objects file is created first and refused if
/// it exists, so a refused export leaves the plan untouched and the two files
/// always describe the same export. The plan is written to a sibling temp file
/// and renamed into place; if that fails the objects file this run created is
/// removed, so an old plan is never left next to new objects.
pub fn write_export(
    plan_path: &str,
    plan_json: &str,
    objects: Option<(&str, &[u8])>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    if let Some((path, data)) = objects {
        write_new_private(path, data)?;
    }
    let tmp = format!("{plan_path}.tmp");
    let res = std::fs::write(&tmp, plan_json)
        .and_then(|()| std::fs::rename(&tmp, plan_path))
        .with_context(|| format!("writing {plan_path}"));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
        if let Some((path, _)) = objects {
            let _ = std::fs::remove_file(path);
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::{refuse_existing, write_export, write_new_private};
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
    fn refused_export_leaves_plan_and_objects_byte_identical_so_import_never_mixes_exports() {
        let d = dir("refused-export");
        let plan = d.join("plan.json");
        let objs = d.join("o.json");
        std::fs::write(&plan, b"old-plan").unwrap();
        std::fs::write(&objs, b"old-objects").unwrap();
        let r = write_export(
            plan.to_str().unwrap(),
            "new-plan",
            Some((objs.to_str().unwrap(), b"new-objects")),
        );
        assert!(r.is_err());
        assert_eq!(std::fs::read(&plan).unwrap(), b"old-plan");
        assert_eq!(std::fs::read(&objs).unwrap(), b"old-objects");
    }

    #[test]
    fn failed_plan_write_keeps_old_plan_and_leaves_no_new_objects_so_import_never_mixes_exports() {
        let d = dir("plan-write-fails");
        let plan = d.join("plan.json");
        let objs = d.join("o.json");
        std::fs::write(&plan, b"old-plan").unwrap();
        std::fs::create_dir(d.join("plan.json.tmp")).unwrap();
        let r = write_export(
            plan.to_str().unwrap(),
            "new-plan",
            Some((objs.to_str().unwrap(), b"new-objects")),
        );
        assert!(r.is_err());
        assert_eq!(std::fs::read(&plan).unwrap(), b"old-plan");
        assert!(!objs.exists(), "new objects must not outlive a failed plan");
    }

    #[test]
    fn successful_export_writes_both_files() {
        let d = dir("ok-export");
        let plan = d.join("plan.json");
        let objs = d.join("o.json");
        write_export(
            plan.to_str().unwrap(),
            "p",
            Some((objs.to_str().unwrap(), b"o")),
        )
        .unwrap();
        assert_eq!(std::fs::read(&plan).unwrap(), b"p");
        assert_eq!(std::fs::read(&objs).unwrap(), b"o");
    }

    #[test]
    fn existing_path_is_refused_up_front() {
        let d = dir("preflight");
        let p = d.join("o.json");
        assert!(refuse_existing(p.to_str().unwrap()).is_ok());
        std::fs::write(&p, b"x").unwrap();
        assert!(refuse_existing(p.to_str().unwrap()).is_err());
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
