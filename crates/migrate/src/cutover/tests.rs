use super::*;
use crate::plan::{self, Source};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

fn merge(dst: &mut Value, patch: &Value) {
    let Some(p) = patch.as_object() else {
        *dst = patch.clone();
        return;
    };
    if !dst.is_object() {
        *dst = json!({});
    }
    for (k, v) in p {
        if v.is_null() {
            dst.as_object_mut().unwrap().remove(k);
        } else {
            merge(
                dst.as_object_mut().unwrap().entry(k).or_insert(Value::Null),
                v,
            );
        }
    }
}

#[derive(Default)]
struct FakeApi {
    objs: RefCell<BTreeMap<String, Value>>,
    patches: RefCell<Vec<(String, Value)>>,
    /// VolumeAttachments vanish after this many lists; None = never.
    detach_after: Cell<Option<u32>>,
    /// A merge_patch on this path fails once.
    fail_patch_once: RefCell<Option<String>>,
}

impl FakeApi {
    fn put(&self, path: &str, o: Value) {
        self.objs.borrow_mut().insert(path.to_string(), o);
    }
    fn at(&self, path: &str) -> Value {
        self.objs.borrow()[path].clone()
    }
}

impl Api for Rc<FakeApi> {
    async fn list(&self, path: &str) -> anyhow::Result<Vec<Value>> {
        let coll = path.rsplit('/').next().unwrap();
        if coll == "volumeattachments" {
            if let Some(n) = self.detach_after.get() {
                if n == 0 {
                    self.objs
                        .borrow_mut()
                        .retain(|k, _| !k.contains("/volumeattachments/"));
                } else {
                    self.detach_after.set(Some(n - 1));
                }
            }
        }
        Ok(self
            .objs
            .borrow()
            .iter()
            .filter(|(k, _)| {
                let mut it = k.rsplit('/');
                it.next();
                it.next() == Some(coll)
            })
            .map(|(_, v)| v.clone())
            .collect())
    }
    async fn get(&self, path: &str) -> anyhow::Result<Option<Value>> {
        Ok(self.objs.borrow().get(path).cloned())
    }
    async fn merge_patch(&self, path: &str, patch: &Value) -> anyhow::Result<()> {
        if self.fail_patch_once.borrow().as_deref() == Some(path) {
            self.fail_patch_once.take();
            anyhow::bail!("injected patch failure on {path}");
        }
        self.patches
            .borrow_mut()
            .push((path.to_string(), patch.clone()));
        let mut objs = self.objs.borrow_mut();
        let o = objs
            .get_mut(path)
            .ok_or_else(|| anyhow::anyhow!("404 {path}"))?;
        merge(o, patch);
        Ok(())
    }
}

struct FakeHost {
    calls: Vec<String>,
    data_dir: Rc<Cell<bool>>,
    remove_data_dir_on_stop: bool,
    fail_stop_once: bool,
    fail_import: bool,
    ready: bool,
    register_driver: bool,
    u7s_present: bool,
    tgt: Rc<FakeApi>,
    install_args: Vec<String>,
    imported_pv_policy: Option<String>,
    second_pv: bool,
}

impl FakeHost {
    fn new(tgt: &Rc<FakeApi>) -> Self {
        Self {
            calls: vec![],
            data_dir: Rc::new(Cell::new(true)),
            remove_data_dir_on_stop: false,
            fail_stop_once: false,
            fail_import: false,
            ready: true,
            register_driver: true,
            u7s_present: false,
            tgt: tgt.clone(),
            install_args: vec![],
            imported_pv_policy: None,
            second_pv: false,
        }
    }
}

impl Host for FakeHost {
    type Target = Rc<FakeApi>;
    fn k3s_data_dir_exists(&self) -> bool {
        self.data_dir.get()
    }
    fn u7s_installed(&self) -> bool {
        self.u7s_present
    }
    async fn stop_k3s(&mut self) -> anyhow::Result<()> {
        self.calls.push("stop_k3s".into());
        if self.fail_stop_once {
            self.fail_stop_once = false;
            bail!("systemctl failed");
        }
        if self.remove_data_dir_on_stop {
            self.data_dir.set(false);
        }
        Ok(())
    }
    async fn start_k3s(&mut self) -> anyhow::Result<()> {
        self.calls.push("start_k3s".into());
        Ok(())
    }
    async fn install_u7s(&mut self, args: &[String]) -> anyhow::Result<()> {
        self.calls.push("install_u7s".into());
        self.install_args = args.to_vec();
        Ok(())
    }
    async fn stop_u7s(&mut self) -> anyhow::Result<()> {
        self.calls.push("stop_u7s".into());
        Ok(())
    }
    async fn export(&mut self, plan_path: &str, objects: &str) -> anyhow::Result<()> {
        self.calls.push("export".into());
        let mut objs = source_objects();
        if self.second_pv {
            objs.extend(second_pv_objects());
        }
        let (plan, _) = plan::build(&objs, source(), &[], vec![]);
        std::fs::write(plan_path, serde_json::to_string(&plan)?)?;
        crate::write_new_private(objects, serde_json::to_string(&objs)?.as_bytes())
    }
    async fn import(&mut self, _plan: &str, objects: &str) -> anyhow::Result<()> {
        self.calls.push("import".into());
        if self.fail_import {
            bail!("import failed");
        }
        let objs: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(objects)?)?;
        for mut pv in objs.into_iter().filter(|o| o["kind"] == "PersistentVolume") {
            self.imported_pv_policy = pv["spec"]["persistentVolumeReclaimPolicy"]
                .as_str()
                .map(Into::into);
            pv["status"] = json!({"phase": "Bound"});
            let name = pv["metadata"]["name"].as_str().unwrap().to_string();
            self.tgt.put(&pv_path(&name), pv);
        }
        self.tgt.put(
            "/apis/apps/v1/namespaces/app/deployments/db",
            json!({"status": {"readyReplicas": if self.ready { 2 } else { 0 }}}),
        );
        if self.register_driver {
            self.tgt.put(
                "/apis/storage.k8s.io/v1/csinodes/node1",
                json!({"spec": {"drivers": [{"name": "csi.example.com"}]}}),
            );
        }
        Ok(())
    }
    async fn target(&mut self) -> anyhow::Result<Rc<FakeApi>> {
        Ok(self.tgt.clone())
    }
}

fn source() -> Source {
    Source {
        k3s_version: "v1.36.5+k3s1".into(),
        shipped_table: "v1.36.5+k3s1".into(),
        service_cidrs: vec!["10.43.0.0/16".into()],
        pod_cidrs: vec!["10.42.0.0/24".into()],
        kube_dns_cluster_ip: Some("10.43.0.10".into()),
    }
}

fn source_objects() -> Vec<Value> {
    vec![
        json!({"apiVersion": "v1", "kind": "PersistentVolume",
            "metadata": {"name": "pv-data", "uid": "u1"},
            "spec": {"persistentVolumeReclaimPolicy": "Delete", "capacity": {"storage": "1Gi"},
                     "claimRef": {"namespace": "app", "name": "data", "uid": "u2"},
                     "csi": {"driver": "csi.example.com", "volumeHandle": "vol-1"}}}),
        json!({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": "data", "namespace": "app", "uid": "u2"},
            "spec": {"volumeName": "pv-data"}}),
        json!({"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "db", "namespace": "app", "uid": "u3"},
            "spec": {"replicas": 2}}),
        json!({"apiVersion": "storage.k8s.io/v1", "kind": "CSIDriver",
            "metadata": {"name": "csi.example.com", "uid": "u4"}, "spec": {}}),
    ]
}

fn second_pv_objects() -> Vec<Value> {
    vec![
        json!({"apiVersion": "v1", "kind": "PersistentVolume",
            "metadata": {"name": "pv-logs", "uid": "u5"},
            "spec": {"persistentVolumeReclaimPolicy": "Delete", "capacity": {"storage": "1Gi"},
                     "claimRef": {"namespace": "app", "name": "logs", "uid": "u6"},
                     "csi": {"driver": "csi.example.com", "volumeHandle": "vol-2"}}}),
        json!({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": "logs", "namespace": "app", "uid": "u6"},
            "spec": {"volumeName": "pv-logs"}}),
    ]
}

fn source_api() -> Rc<FakeApi> {
    let api = Rc::new(FakeApi::default());
    api.put(
        &pv_path("pv-data"),
        json!({"metadata": {"name": "pv-data"}, "spec": {"persistentVolumeReclaimPolicy": "Delete"}}),
    );
    api.put(
        "/apis/apps/v1/namespaces/app/deployments/db",
        json!({"spec": {"replicas": 2}}),
    );
    api.put(
        "/api/v1/namespaces/app/persistentvolumeclaims/data",
        json!({"metadata": {"name": "data", "namespace": "app"}, "spec": {"volumeName": "pv-data"}}),
    );
    api
}

fn work(tag: &str) -> Paths {
    let d = std::env::temp_dir().join(format!("u7s-cutover-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    Paths::new(d.to_str().unwrap())
}

fn policy(api: &FakeApi, path: &str) -> (String, Option<String>) {
    let o = api.at(path);
    (
        o["spec"]["persistentVolumeReclaimPolicy"]
            .as_str()
            .unwrap()
            .into(),
        o["metadata"]["annotations"][ORIGINAL_POLICY_ANNOTATION]
            .as_str()
            .map(Into::into),
    )
}

fn cleanup(p: &Paths) {
    let _ = std::fs::remove_dir_all(&p.dir);
}

#[tokio::test]
async fn no_pv_is_switched_to_retain_without_confirmation() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    let paths = work("noconfirm");
    let err = run(&src, &mut host, &paths, false, &[]).await.unwrap_err();
    assert!(format!("{err:#}").contains("--confirm-retain"));
    assert!(
        src.patches.borrow().is_empty(),
        "the source must be untouched until the operator confirms"
    );
    assert_eq!(host.calls, ["export"]);
    assert_eq!(load_state(&paths).unwrap().unwrap().stage, Stage::Exported);
    cleanup(&paths);
}

#[tokio::test]
async fn cutover_refuses_a_host_that_already_has_u7s_installed() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    host.u7s_present = true;
    let paths = work("u7s-present");
    let err = run(&src, &mut host, &paths, true, &[]).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("already installed"),
        "importing into a u7s left over from a rolled-back cutover collides with its objects"
    );
    assert!(host.calls.is_empty() && src.patches.borrow().is_empty());
    cleanup(&paths);
}

#[tokio::test]
async fn cutover_records_original_policy_keeps_retain_until_verified_then_restores_it() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    let paths = work("full");
    run(
        &src,
        &mut host,
        &paths,
        true,
        &["--tarball".into(), "t.tgz".into()],
    )
    .await
    .unwrap();
    assert_eq!(
        policy(&src, &pv_path("pv-data")),
        ("Retain".into(), Some("Delete".into())),
        "the source keeps Retain plus the recorded original so k3s can never delete the volume"
    );
    assert_eq!(
        host.imported_pv_policy.as_deref(),
        Some("Retain"),
        "the target must create the PV already protected, or a failed import window could delete data"
    );
    assert_eq!(
        policy(&tgt, &pv_path("pv-data")),
        ("Delete".into(), None),
        "after verification the target PV regains the policy the user chose"
    );
    assert_eq!(
        src.at("/apis/apps/v1/namespaces/app/deployments/db")["spec"]["replicas"],
        0
    );
    assert_eq!(
        host.calls,
        ["export", "stop_k3s", "install_u7s", "import"],
        "k3s must stop before u7s installs (single host) and import must follow install"
    );
    assert_eq!(
        host.install_args,
        [
            "--tarball",
            "t.tgz",
            "--service-cidr",
            "10.43.0.0/16",
            "--cluster-cidr",
            "10.42.0.0/24",
            "--cluster-dns",
            "10.43.0.10"
        ],
        "the target must inherit the source's ranges or preserved ClusterIPs fail validation"
    );
    assert_eq!(
        load_state(&paths).unwrap().unwrap().stage,
        Stage::PoliciesRestored
    );
    cleanup(&paths);
}

#[tokio::test]
async fn resumed_cutover_never_records_retain_as_the_original_policy() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    host.fail_stop_once = true;
    let paths = work("resume");
    assert!(run(&src, &mut host, &paths, true, &[]).await.is_err());
    let mut st = load_state(&paths).unwrap().unwrap();
    assert_eq!(st.stage, Stage::Detached);
    // A crash between patching the source and saving Retained: the state
    // regresses while the source already holds Retain.
    st.stage = Stage::Exported;
    st.pvs.clear();
    save(&paths, &st).unwrap();
    run(&src, &mut host, &paths, true, &[]).await.unwrap();
    assert_eq!(
        load_state(&paths).unwrap().unwrap().pvs[0].original_policy,
        "Delete",
        "recording Retain as the original would make rollback leave the volume permanently Retain"
    );
    assert_eq!(policy(&tgt, &pv_path("pv-data")).0, "Delete");
    assert_eq!(
        host.calls.iter().filter(|c| *c == "export").count(),
        1,
        "resume must not re-export"
    );
    cleanup(&paths);
}

#[tokio::test]
async fn k3s_is_not_stopped_while_a_volume_is_still_attached() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    src.put(
        "/apis/storage.k8s.io/v1/volumeattachments/va1",
        json!({"metadata": {"name": "va1"}, "spec": {"source": {"persistentVolumeName": "pv-data"}}}),
    );
    let mut host = FakeHost::new(&tgt);
    let paths = work("attached");
    let err = run(&src, &mut host, &paths, true, &[]).await.unwrap_err();
    assert!(format!("{err:#}").contains("VolumeAttachment va1"));
    assert!(
        !host.calls.contains(&"stop_k3s".to_string()),
        "stopping k3s with an attached volume lets u7s attach it a second time"
    );
    assert_eq!(
        load_state(&paths).unwrap().unwrap().stage,
        Stage::ScaledDown
    );

    src.detach_after.set(Some(2));
    run(&src, &mut host, &paths, true, &[]).await.unwrap();
    assert!(host.calls.contains(&"stop_k3s".to_string()));
    cleanup(&paths);
}

#[test]
fn running_pods_and_attachments_of_migrated_volumes_block_but_finished_pods_do_not() {
    let pvs = vec!["pv-data".to_string()];
    let pvcs = [
        json!({"metadata": {"name": "data", "namespace": "app"}, "spec": {"volumeName": "pv-data"}}),
    ];
    let pod = |name: &str, phase: &str, claim: &str| {
        json!({"metadata": {"name": name, "namespace": "app"}, "status": {"phase": phase},
               "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": claim}}]}})
    };
    let pods = [
        pod("run", "Running", "data"),
        pod("done", "Succeeded", "data"),
        pod("other", "Running", "scratch"),
    ];
    let vas = [
        json!({"metadata": {"name": "a"}, "spec": {"source": {"persistentVolumeName": "pv-data"}}}),
        json!({"metadata": {"name": "b"}, "spec": {"source": {"persistentVolumeName": "unrelated"}}}),
    ];
    assert_eq!(
        blockers(&pvs, &pvcs, &pods, &vas),
        ["Pod app/run", "VolumeAttachment a (PV pv-data)"]
    );
}

#[tokio::test]
async fn k3s_data_dir_is_never_removed_and_uninstall_is_never_run() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    host.remove_data_dir_on_stop = true;
    let paths = work("datadir");
    let err = run(&src, &mut host, &paths, true, &[]).await.unwrap_err();
    assert!(format!("{err:#}").contains("data directory vanished"));
    assert!(
        !host.calls.contains(&"install_u7s".to_string()),
        "installing over a destroyed source would leave no rollback"
    );
    assert!(guard_command("/usr/local/bin/k3s-uninstall.sh").is_err());
    assert!(guard_command("k3s-agent-uninstall.sh").is_err());
    assert!(guard_command("/usr/local/bin/k3s-killall.sh").is_ok());
    cleanup(&paths);
}

#[tokio::test]
async fn system_host_refuses_to_execute_an_uninstall_script() {
    use std::os::unix::fs::PermissionsExt;
    let d = std::env::temp_dir().join(format!("u7s-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let marker = d.join("ran");
    let script = d.join("k3s-uninstall.sh");
    std::fs::write(&script, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut host = SystemHost {
        source_kubeconfig: String::new(),
        k3s_data_dir: String::new(),
        install_script: script.to_str().unwrap().into(),
    };
    let r = host.install_u7s(&[]).await;
    let ran = marker.exists();
    let _ = std::fs::remove_dir_all(&d);
    assert!(r.is_err());
    assert!(
        !ran,
        "the uninstall script rm -rf's the k3s data dir and local-path volumes"
    );
}

#[tokio::test]
async fn csi_driver_must_register_before_the_cutover_counts_as_verified() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    host.register_driver = false;
    let paths = work("driver");
    let err = run(&src, &mut host, &paths, true, &[]).await.unwrap_err();
    assert!(format!("{err:#}").contains("csi.example.com"));
    assert_eq!(load_state(&paths).unwrap().unwrap().stage, Stage::Imported);
    assert_eq!(
        policy(&tgt, &pv_path("pv-data")).0,
        "Retain",
        "policies must not be restored while the cutover is unverified"
    );
    cleanup(&paths);
}

#[tokio::test]
async fn unready_workloads_keep_retain_on_the_target() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    host.ready = false;
    let paths = work("unready");
    assert!(run(&src, &mut host, &paths, true, &[]).await.is_err());
    assert_eq!(policy(&tgt, &pv_path("pv-data")).0, "Retain");
    assert_eq!(
        load_state(&paths).unwrap().unwrap().stage,
        Stage::DriversReady
    );
    cleanup(&paths);
}

#[tokio::test]
async fn rollback_after_failed_import_restores_policy_replicas_and_k3s() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    host.fail_import = true;
    let paths = work("rb-fail");
    assert!(run(&src, &mut host, &paths, true, &[]).await.is_err());
    host.calls.clear();
    rollback(&src, &mut host, &paths).await.unwrap();
    assert_eq!(host.calls, ["stop_u7s", "start_k3s"]);
    assert_eq!(
        policy(&src, &pv_path("pv-data")),
        ("Delete".into(), None),
        "rollback must give k3s back the policy the user had, annotation removed"
    );
    assert_eq!(
        src.at("/apis/apps/v1/namespaces/app/deployments/db")["spec"]["replicas"],
        2,
        "workloads scaled down for the cutover must run again on k3s"
    );
    assert!(
        run(&src, &mut host, &paths, true, &[]).await.is_err(),
        "a rolled-back cutover is not resumable"
    );
    cleanup(&paths);
}

#[tokio::test]
async fn rollback_is_refused_once_a_migrated_claim_was_deleted_on_u7s() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    let paths = work("rb-window");
    run(&src, &mut host, &paths, true, &[]).await.unwrap();
    host.calls.clear();
    let mut pv = tgt.at(&pv_path("pv-data"));
    pv["status"]["phase"] = "Released".into();
    tgt.put(&pv_path("pv-data"), pv);
    let err = rollback(&src, &mut host, &paths).await.unwrap_err();
    assert!(format!("{err:#}").contains("rollback window closed"));
    assert!(
        host.calls.is_empty(),
        "a refused rollback must change nothing on the host"
    );
    assert_eq!(policy(&src, &pv_path("pv-data")).0, "Retain");
    cleanup(&paths);
}

#[tokio::test]
async fn rollback_after_a_completed_cutover_works_while_volumes_are_bound() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    let paths = work("rb-ok");
    run(&src, &mut host, &paths, true, &[]).await.unwrap();
    rollback(&src, &mut host, &paths).await.unwrap();
    assert_eq!(policy(&src, &pv_path("pv-data")), ("Delete".into(), None));
    assert_eq!(
        load_state(&paths).unwrap().unwrap().stage,
        Stage::RolledBack
    );
    cleanup(&paths);
}

#[tokio::test]
async fn interrupted_rollback_resumes_without_a_reachable_u7s() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    let paths = work("rb-resume");
    run(&src, &mut host, &paths, true, &[]).await.unwrap();
    let mut st = load_state(&paths).unwrap().unwrap();
    st.rolling_back = true;
    save(&paths, &st).unwrap();
    tgt.objs.borrow_mut().clear();
    rollback(&src, &mut host, &paths).await.unwrap();
    assert_eq!(policy(&src, &pv_path("pv-data")).0, "Delete");
    cleanup(&paths);
}

#[test]
fn install_flags_inherit_source_ranges_and_cannot_be_overridden() {
    let mut p: Plan = plan::build(&source_objects(), source(), &[], vec![]).0;
    assert!(install_args(&p, &["--service-cidr=10.0.0.0/16".into()]).is_err());
    assert!(install_args(&p, &["--cluster-dns".into(), "1.2.3.4".into()]).is_err());
    p.source.service_cidrs.push("fd00::/108".into());
    assert!(
        install_args(&p, &[]).is_err(),
        "dual-stack sources cannot be reproduced by install.sh"
    );
}

#[test]
fn export_copy_of_every_migrated_pv_is_retain_with_the_original_recorded() {
    let mut objs = source_objects();
    retain_in_export(
        &mut objs,
        &[PvRecord {
            name: "pv-data".into(),
            original_policy: "Recycle".into(),
        }],
    );
    assert_eq!(objs[0]["spec"]["persistentVolumeReclaimPolicy"], "Retain");
    assert_eq!(
        objs[0]["metadata"]["annotations"][ORIGINAL_POLICY_ANNOTATION],
        "Recycle"
    );
    assert!(
        objs[1]["metadata"]["annotations"].is_null(),
        "only PVs are touched"
    );
}

const DEPLOY: &str = "/apis/apps/v1/namespaces/app/deployments/db";

#[tokio::test]
async fn rollback_restores_the_replicas_live_at_scale_down_not_the_stale_export() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    host.fail_import = true;
    // The export (2 replicas) is taken before an operator scales the app.
    src.put(DEPLOY, json!({"spec": {"replicas": 5}}));
    let paths = work("live-replicas");
    assert!(run(&src, &mut host, &paths, true, &[]).await.is_err());
    rollback(&src, &mut host, &paths).await.unwrap();
    assert_eq!(
        src.at(DEPLOY)["spec"]["replicas"],
        5,
        "rollback must bring back what was running, or the app silently shrinks"
    );
    cleanup(&paths);
}

#[tokio::test]
async fn resumed_scale_down_keeps_the_replica_counts_it_already_recorded() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    host.fail_stop_once = true;
    src.put(DEPLOY, json!({"spec": {"replicas": 5}}));
    let paths = work("replicas-resume");
    assert!(run(&src, &mut host, &paths, true, &[]).await.is_err());
    assert_eq!(src.at(DEPLOY)["spec"]["replicas"], 0);
    let mut st = load_state(&paths).unwrap().unwrap();
    st.stage = Stage::Retained;
    save(&paths, &st).unwrap();
    // The fake target reports 2 ready, so verification times out; only the
    // recorded state matters here.
    let _ = run(&src, &mut host, &paths, true, &[]).await;
    assert_eq!(
        load_state(&paths).unwrap().unwrap().workloads[0].replicas,
        5,
        "re-reading the already-zeroed live value would make rollback restore 0"
    );
    cleanup(&paths);
}

#[tokio::test]
async fn rollback_window_is_enforced_after_a_crash_mid_policy_restore() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    let mut host = FakeHost::new(&tgt);
    let paths = work("rb-window-verified");
    run(&src, &mut host, &paths, true, &[]).await.unwrap();
    let mut st = load_state(&paths).unwrap().unwrap();
    st.stage = Stage::Verified;
    save(&paths, &st).unwrap();
    let mut pv = tgt.at(&pv_path("pv-data"));
    pv["status"]["phase"] = "Released".into();
    tgt.put(&pv_path("pv-data"), pv);
    host.calls.clear();
    let err = rollback(&src, &mut host, &paths).await.unwrap_err();
    assert!(format!("{err:#}").contains("rollback window closed"));
    assert!(
        host.calls.is_empty(),
        "starting k3s over volumes u7s already restored to Delete and released loses data"
    );
    cleanup(&paths);
}

#[tokio::test]
async fn crash_between_the_two_retain_patches_neither_loses_nor_mis_records_policies() {
    let (src, tgt) = (source_api(), Rc::new(FakeApi::default()));
    src.put(
        &pv_path("pv-logs"),
        json!({"metadata": {"name": "pv-logs"}, "spec": {"persistentVolumeReclaimPolicy": "Delete"}}),
    );
    let mut host = FakeHost::new(&tgt);
    host.second_pv = true;
    let paths = work("two-pv-crash");
    *src.fail_patch_once.borrow_mut() = Some(pv_path("pv-logs"));
    assert!(run(&src, &mut host, &paths, true, &[]).await.is_err());
    assert_eq!(
        policy(&src, &pv_path("pv-data")),
        ("Retain".into(), Some("Delete".into())),
        "first PV is already Retain with its original in the annotation"
    );
    assert_eq!(policy(&src, &pv_path("pv-logs")).0, "Delete");
    host.fail_import = true;
    assert!(run(&src, &mut host, &paths, true, &[]).await.is_err());
    let st = load_state(&paths).unwrap().unwrap();
    assert!(
        st.pvs.iter().all(|r| r.original_policy == "Delete") && st.pvs.len() == 2,
        "a resumed run recorded Retain as an original: {:?}",
        st.pvs
    );
    rollback(&src, &mut host, &paths).await.unwrap();
    for pv in ["pv-data", "pv-logs"] {
        assert_eq!(
            policy(&src, &pv_path(pv)),
            ("Delete".into(), None),
            "{pv} must get its original policy back on rollback"
        );
    }
    cleanup(&paths);
}

#[test]
fn k3s_is_stopped_then_killed_with_its_own_killall_and_never_uninstalled() {
    let cmds = stop_k3s_commands();
    assert_eq!(cmds[0].0, "systemctl");
    assert_eq!(cmds[1].0, K3S_KILLALL);
    for (p, _) in &cmds {
        assert!(guard_command(p).is_ok(), "{p} must pass the data-dir guard");
    }
}

#[test]
fn work_dir_is_absolute_so_rollback_works_from_any_directory() {
    assert!(Paths::new("u7s-migrate-cutover").dir.is_absolute());
}

#[test]
fn every_cutover_write_goes_through_the_durable_helper() {
    let src = include_str!("../cutover.rs");
    let prod = src.split("#[cfg(test)]").next().unwrap();
    for banned in ["write_new_private(", "fs::rename(", "fs::write("] {
        assert!(
            !prod.contains(banned),
            "{banned} bypasses fsync-before-rename durability"
        );
    }
}
