//! `u7s migrate cutover` / `rollback`: the single-host sequential cutover.
//!
//! Every stage is recorded in a state file before and after it runs, and each
//! stage is idempotent, so a crash at any point resumes where it stopped or
//! is rolled back. The source k3s data directory is never removed: nothing
//! here runs k3s's uninstall script, which `rm -rf`s it (including the
//! local-path volumes); only `k3s-killall.sh` is run. Source PVs are switched to `Retain` only after the
//! operator confirms, with the original policy recorded in the state file
//! and in an annotation, and put back on whichever cluster ends up serving
//! them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use hyper::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::classify::Action;
use crate::discover;
use crate::plan::Plan;

pub const ORIGINAL_POLICY_ANNOTATION: &str = "migrate.u7s.dev/original-reclaim-policy";
pub const DEFAULT_K3S_DATA_DIR: &str = "/var/lib/rancher/k3s";
pub const U7S_KUBECONFIG: &str = "/var/lib/u7s/kubeconfig";

const POLL_ATTEMPTS: u32 = if cfg!(test) { 20 } else { 300 };
const POLL_DELAY: Duration = if cfg!(test) {
    Duration::ZERO
} else {
    Duration::from_secs(2)
};

/// Progress of a cutover, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Stage {
    /// Objects exported; the source is untouched.
    Exported,
    /// Source PVs are Retain and the export carries Retain.
    Retained,
    ScaledDown,
    /// No pod or VolumeAttachment uses a migrated PV.
    Detached,
    K3sStopped,
    U7sInstalled,
    Imported,
    DriversReady,
    Verified,
    /// Target PVs have their original policies back: deleting a PVC on u7s
    /// may now delete data, so rollback is refused once one is gone.
    PoliciesRestored,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PvRecord {
    pub name: String,
    pub original_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workload {
    /// `deployments` or `statefulsets`.
    pub resource: String,
    pub namespace: String,
    pub name: String,
    pub replicas: i64,
}

impl Workload {
    fn path(&self) -> String {
        format!(
            "/apis/apps/v1/namespaces/{}/{}/{}",
            self.namespace, self.resource, self.name
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub stage: Stage,
    pub pvs: Vec<PvRecord>,
    pub workloads: Vec<Workload>,
    /// Set once a rollback has passed its window check, so an interrupted
    /// rollback resumes without needing u7s.
    #[serde(default)]
    pub rolling_back: bool,
    /// Set once `workloads` holds the live replica counts read just before
    /// scale-down, so a resumed scale-down never records a count it already
    /// zeroed.
    #[serde(default)]
    pub replicas_recorded: bool,
}

pub struct Paths {
    dir: PathBuf,
}

impl Paths {
    pub fn new(dir: &str) -> Self {
        Self {
            dir: std::path::absolute(dir).unwrap_or_else(|_| dir.into()),
        }
    }
    pub fn state(&self) -> PathBuf {
        self.dir.join("state.json")
    }
    pub fn plan(&self) -> PathBuf {
        self.dir.join("plan.json")
    }
    pub fn objects(&self) -> PathBuf {
        self.dir.join("objects.json")
    }
}

fn s(p: &Path) -> &str {
    p.to_str().expect("work dir paths are UTF-8")
}

fn save(paths: &Paths, st: &State) -> anyhow::Result<()> {
    crate::write_durable(
        s(&paths.state()),
        serde_json::to_string_pretty(st)?.as_bytes(),
    )
    .context("recording cutover state")
}

fn load_state(paths: &Paths) -> anyhow::Result<Option<State>> {
    match std::fs::read_to_string(paths.state()) {
        Ok(t) => Ok(Some(
            serde_json::from_str(&t).context("parsing the cutover state file")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading the cutover state file"),
    }
}

/// Fails if running `program` could remove k3s's data directory.
pub fn guard_command(program: &str) -> anyhow::Result<()> {
    let base = program.rsplit('/').next().unwrap_or(program);
    if base.contains("uninstall") {
        bail!(
            "refusing to run {program}: k3s's uninstall script deletes the k3s data directory, \
             including local-path volumes. Cutover stops k3s and leaves its data in place."
        );
    }
    Ok(())
}

/// The reclaim policy a PV had before migration touched it: the recorded
/// annotation wins, so a re-run after Retain was applied never records
/// Retain as the original.
pub fn original_policy(pv: &Value) -> String {
    pv["metadata"]["annotations"][ORIGINAL_POLICY_ANNOTATION]
        .as_str()
        .or_else(|| pv["spec"]["persistentVolumeReclaimPolicy"].as_str())
        .unwrap_or("Delete")
        .to_string()
}

/// Names of the PVs the plan migrates.
pub fn migrated_pvs(plan: &Plan) -> Vec<String> {
    plan.entries
        .iter()
        .filter(|e| e.action == Action::Include && e.kind == "PersistentVolume")
        .map(|e| e.name.clone())
        .collect()
}

/// Deployments and StatefulSets the plan migrates, with their exported
/// replica counts (zero-replica ones need no scaling).
pub fn migrated_workloads(plan: &Plan, objs: &[Value]) -> Vec<Workload> {
    objs.iter()
        .filter(|o| {
            o["apiVersion"] == "apps/v1"
                && matches!(o["kind"].as_str(), Some("Deployment" | "StatefulSet"))
        })
        .filter(|o| {
            plan.entries.iter().any(|e| {
                e.action == Action::Include
                    && e.kind == o["kind"].as_str().unwrap_or_default()
                    && e.name == o["metadata"]["name"].as_str().unwrap_or_default()
                    && e.namespace.as_deref() == o["metadata"]["namespace"].as_str()
            })
        })
        .filter_map(|o| {
            let replicas = o["spec"]["replicas"].as_i64().unwrap_or(1);
            (replicas > 0).then(|| Workload {
                resource: if o["kind"] == "Deployment" {
                    "deployments"
                } else {
                    "statefulsets"
                }
                .to_string(),
                namespace: o["metadata"]["namespace"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
                name: o["metadata"]["name"].as_str().unwrap_or_default().into(),
                replicas,
            })
        })
        .collect()
}

/// Sets Retain and the original-policy annotation on the exported PVs, so
/// the target creates them protected.
pub fn retain_in_export(objs: &mut [Value], pvs: &[PvRecord]) {
    for o in objs.iter_mut() {
        if o["kind"] != "PersistentVolume" || o["apiVersion"] != "v1" {
            continue;
        }
        let Some(rec) = pvs
            .iter()
            .find(|p| o["metadata"]["name"] == p.name.as_str())
        else {
            continue;
        };
        o["spec"]["persistentVolumeReclaimPolicy"] = "Retain".into();
        if !o["metadata"]["annotations"].is_object() {
            o["metadata"]["annotations"] = json!({});
        }
        o["metadata"]["annotations"][ORIGINAL_POLICY_ANNOTATION] =
            rec.original_policy.clone().into();
    }
}

/// What still uses a migrated PV: pods that mount a claim bound to one, and
/// VolumeAttachments for one.
pub fn blockers(pv_names: &[String], pvcs: &[Value], pods: &[Value], vas: &[Value]) -> Vec<String> {
    let bound: Vec<(&str, &str)> = pvcs
        .iter()
        .filter(|c| {
            c["spec"]["volumeName"]
                .as_str()
                .is_some_and(|v| pv_names.iter().any(|p| p == v))
        })
        .filter_map(|c| {
            Some((
                c["metadata"]["namespace"].as_str()?,
                c["metadata"]["name"].as_str()?,
            ))
        })
        .collect();
    let mut out = vec![];
    for p in pods {
        if matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed")) {
            continue;
        }
        let ns = p["metadata"]["namespace"].as_str().unwrap_or_default();
        let mounts = p["spec"]["volumes"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|v| {
                v["persistentVolumeClaim"]["claimName"]
                    .as_str()
                    .is_some_and(|c| bound.contains(&(ns, c)))
            });
        if mounts {
            out.push(format!(
                "Pod {ns}/{}",
                p["metadata"]["name"].as_str().unwrap_or_default()
            ));
        }
    }
    for va in vas {
        if let Some(pv) = va["spec"]["source"]["persistentVolumeName"].as_str() {
            if pv_names.iter().any(|p| p == pv) {
                out.push(format!(
                    "VolumeAttachment {} (PV {pv})",
                    va["metadata"]["name"].as_str().unwrap_or_default()
                ));
            }
        }
    }
    out
}

/// Ok while every recorded PV still exists on the target and none has lost
/// its claim; Err names the evidence that the user has started deleting.
pub fn rollback_window_open(st: &State, target_pvs: &[Value]) -> Result<(), String> {
    for rec in &st.pvs {
        let Some(pv) = target_pvs
            .iter()
            .find(|p| p["metadata"]["name"] == rec.name.as_str())
        else {
            return Err(format!("PV {} no longer exists on u7s", rec.name));
        };
        if pv["metadata"]["deletionTimestamp"].is_string() {
            return Err(format!("PV {} is being deleted on u7s", rec.name));
        }
        if matches!(pv["status"]["phase"].as_str(), Some("Released" | "Failed")) {
            return Err(format!(
                "PV {} on u7s is {}: its claim was deleted",
                rec.name,
                pv["status"]["phase"].as_str().unwrap_or_default()
            ));
        }
    }
    Ok(())
}

/// The CSI driver names the plan migrates.
fn csi_drivers(plan: &Plan) -> Vec<String> {
    plan.entries
        .iter()
        .filter(|e| e.action == Action::Include && e.kind == "CSIDriver")
        .map(|e| e.name.clone())
        .collect()
}

fn drivers_registered(drivers: &[String], csinodes: &[Value]) -> Vec<String> {
    drivers
        .iter()
        .filter(|d| {
            !csinodes.iter().any(|n| {
                n["spec"]["drivers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|x| x["name"] == d.as_str())
            })
        })
        .cloned()
        .collect()
}

/// CIDR flags that make the target inherit the source's ranges. Errors on a
/// source this single-stack tool cannot describe, and on caller flags that
/// would override the inherited ones.
pub fn install_args(plan: &Plan, user: &[String]) -> anyhow::Result<Vec<String>> {
    for a in user {
        let flag = a.split('=').next().unwrap_or(a);
        if matches!(flag, "--service-cidr" | "--cluster-cidr" | "--cluster-dns") {
            bail!("{flag} is inherited from the source cluster and cannot be passed through");
        }
    }
    let src = &plan.source;
    let (service, pod, dns) = match (
        src.service_cidrs.as_slice(),
        src.pod_cidrs.as_slice(),
        &src.kube_dns_cluster_ip,
    ) {
        ([s], [p], Some(d)) => (s, p, d),
        _ => bail!(
            "the source must have exactly one service CIDR, one pod CIDR and a kube-dns ClusterIP \
             (found service {:?}, pod {:?}, dns {:?}); dual-stack and multi-node sources are not supported",
            src.service_cidrs,
            src.pod_cidrs,
            src.kube_dns_cluster_ip
        ),
    };
    let mut args = user.to_vec();
    args.extend([
        "--service-cidr".into(),
        service.clone(),
        "--cluster-cidr".into(),
        pod.clone(),
        "--cluster-dns".into(),
        dns.clone(),
    ]);
    Ok(args)
}

/// JSON access to one apiserver.
#[allow(async_fn_in_trait)]
pub trait Api {
    async fn list(&self, path: &str) -> anyhow::Result<Vec<Value>>;
    async fn get(&self, path: &str) -> anyhow::Result<Option<Value>>;
    async fn merge_patch(&self, path: &str, patch: &Value) -> anyhow::Result<()>;
}

/// The machine the cutover runs on.
#[allow(async_fn_in_trait)]
pub trait Host {
    type Target: Api;
    fn k3s_data_dir_exists(&self) -> bool;
    /// Verifies every local file a later step needs (k3s-killall.sh, the
    /// install script and a local `--tarball`) before anything is changed.
    fn preflight(&self, install_args: &[String]) -> anyhow::Result<()>;
    fn u7s_installed(&self) -> bool;
    /// Stops and disables k3s, leaving its data in place.
    async fn stop_k3s(&mut self) -> anyhow::Result<()>;
    async fn start_k3s(&mut self) -> anyhow::Result<()>;
    async fn install_u7s(&mut self, args: &[String]) -> anyhow::Result<()>;
    async fn stop_u7s(&mut self) -> anyhow::Result<()>;
    async fn export(&mut self, plan: &str, objects: &str) -> anyhow::Result<()>;
    async fn import(&mut self, plan: &str, objects: &str) -> anyhow::Result<()>;
    async fn target(&mut self) -> anyhow::Result<Self::Target>;
}

async fn poll<F, Fut>(what: &str, mut check: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Option<String>>>,
{
    let mut last = String::new();
    for _ in 0..POLL_ATTEMPTS {
        match check().await {
            Ok(None) => return Ok(()),
            Ok(Some(pending)) => last = pending,
            Err(e) => last = format!("{e:#}"),
        }
        tokio::time::sleep(POLL_DELAY).await;
    }
    bail!("timed out waiting for {what}: {last}")
}

fn pv_path(name: &str) -> String {
    format!("/api/v1/persistentvolumes/{name}")
}

async fn set_policy<A: Api>(
    api: &A,
    name: &str,
    policy: &str,
    annotation: Option<&str>,
) -> anyhow::Result<()> {
    let patch = json!({
        "metadata": {"annotations": {ORIGINAL_POLICY_ANNOTATION: annotation}},
        "spec": {"persistentVolumeReclaimPolicy": policy},
    });
    api.merge_patch(&pv_path(name), &patch)
        .await
        .with_context(|| format!("setting reclaim policy {policy} on PV {name}"))
}

fn step(st: &mut State, paths: &Paths, stage: Stage) -> anyhow::Result<()> {
    st.stage = stage;
    save(paths, st)
}

/// Runs (or resumes) the cutover. Without `confirm_retain` it exports and
/// stops, having changed nothing on the source.
pub async fn run<S: Api, H: Host>(
    src: &S,
    host: &mut H,
    paths: &Paths,
    confirm_retain: bool,
    user_install_args: &[String],
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&paths.dir)?;
    eprintln!(
        "cutover work dir: {0} (to undo, run `u7s migrate rollback --work-dir {0}`)",
        paths.dir.display()
    );
    let mut st = match load_state(paths)? {
        Some(st) if st.stage == Stage::RolledBack => bail!(
            "this cutover was rolled back; remove {} and start a new one",
            paths.dir.display()
        ),
        Some(st) => st,
        None => {
            if !host.k3s_data_dir_exists() {
                bail!("k3s data directory not found: is this the k3s host?");
            }
            host.preflight(user_install_args)
                .context("pre-flight failed, nothing was changed")?;
            if host.u7s_installed() {
                bail!(
                    "u7s is already installed on this host ({U7S_KUBECONFIG} exists), so the import \
                     would meet objects of an earlier cutover. If it is left over from a rolled-back \
                     cutover, stop the u7s units and remove /var/lib/u7s first."
                );
            }
            for f in [paths.plan(), paths.objects()] {
                let _ = std::fs::remove_file(f);
            }
            host.export(s(&paths.plan()), s(&paths.objects())).await?;
            let st = State {
                stage: Stage::Exported,
                pvs: vec![],
                workloads: vec![],
                rolling_back: false,
                replicas_recorded: false,
            };
            save(paths, &st)?;
            st
        }
    };
    let (plan, mut objs) = crate::import::load(s(&paths.plan()), s(&paths.objects()))?;
    let pv_names = migrated_pvs(&plan);
    install_args(&plan, user_install_args)?;

    if st.stage < Stage::Retained {
        if !confirm_retain {
            bail!(
                "nothing on the source was changed. To continue, cutover must set reclaim policy \
                 Retain on {} PV(s) {:?} (their current policies are recorded and restored), \
                 scale workloads down and stop k3s. Re-run with --confirm-retain; remove {} to \
                 re-export first. {} contains Secrets in clear text.",
                pv_names.len(),
                pv_names,
                paths.dir.display(),
                paths.objects().display()
            );
        }
        let mut recs = vec![];
        for n in &pv_names {
            let pv = src
                .get(&pv_path(n))
                .await?
                .with_context(|| format!("PV {n} disappeared from the source"))?;
            recs.push(PvRecord {
                name: n.clone(),
                original_policy: original_policy(&pv),
            });
        }
        st.pvs = recs;
        st.workloads = migrated_workloads(&plan, &objs);
        save(paths, &st)?;
        for r in &st.pvs {
            set_policy(src, &r.name, "Retain", Some(&r.original_policy)).await?;
        }
        retain_in_export(&mut objs, &st.pvs);
        crate::write_durable(
            s(&paths.objects()),
            serde_json::to_string(&objs)?.as_bytes(),
        )?;
        step(&mut st, paths, Stage::Retained)?;
    }

    if st.stage < Stage::ScaledDown {
        if !st.replicas_recorded {
            for w in &mut st.workloads {
                if let Some(live) = src.get(&w.path()).await? {
                    w.replicas = live["spec"]["replicas"].as_i64().unwrap_or(1);
                }
            }
            st.replicas_recorded = true;
            save(paths, &st)?;
        }
        for w in &st.workloads {
            src.merge_patch(&w.path(), &json!({"spec": {"replicas": 0}}))
                .await
                .with_context(|| format!("scaling down {}", w.path()))?;
        }
        step(&mut st, paths, Stage::ScaledDown)?;
    }

    if st.stage < Stage::Detached {
        poll("migrated volumes to be unused and detached", || async {
            let pvcs = src.list("/api/v1/persistentvolumeclaims").await?;
            let pods = src.list("/api/v1/pods").await?;
            let vas = src.list("/apis/storage.k8s.io/v1/volumeattachments").await?;
            let b = blockers(&pv_names, &pvcs, &pods, &vas);
            Ok((!b.is_empty()).then(|| b.join(", ")))
        })
        .await
        .context("k3s was not stopped; run `u7s migrate rollback` to undo, or stop the remaining users and re-run")?;
        step(&mut st, paths, Stage::Detached)?;
    }

    if st.stage < Stage::K3sStopped {
        if !host.k3s_data_dir_exists() {
            bail!("k3s data directory is missing before stopping k3s; refusing to continue");
        }
        host.stop_k3s().await?;
        if !host.k3s_data_dir_exists() {
            bail!("k3s data directory vanished while stopping k3s; do not continue");
        }
        step(&mut st, paths, Stage::K3sStopped)?;
    }

    if st.stage < Stage::U7sInstalled {
        host.install_u7s(&install_args(&plan, user_install_args)?)
            .await?;
        step(&mut st, paths, Stage::U7sInstalled)?;
    }

    if st.stage < Stage::Imported {
        host.import(s(&paths.plan()), s(&paths.objects())).await?;
        step(&mut st, paths, Stage::Imported)?;
    }

    let target = host.target().await?;
    if st.stage < Stage::DriversReady {
        let drivers = csi_drivers(&plan);
        poll(
            "imported CSI drivers to register with the kubelet",
            || async {
                let nodes = target.list("/apis/storage.k8s.io/v1/csinodes").await?;
                let missing = drivers_registered(&drivers, &nodes);
                Ok((!missing.is_empty()).then(|| format!("not registered: {missing:?}")))
            },
        )
        .await?;
        step(&mut st, paths, Stage::DriversReady)?;
    }

    if st.stage < Stage::Verified {
        poll("migrated workloads and volumes to be ready on u7s", || async {
            let mut pending = vec![];
            for r in &st.pvs {
                let phase = target.get(&pv_path(&r.name)).await?.map(|p| {
                    p["status"]["phase"].as_str().unwrap_or_default().to_string()
                });
                if !matches!(phase.as_deref(), Some("Bound" | "Available")) {
                    pending.push(format!("PV {} is {phase:?}", r.name));
                }
            }
            for w in &st.workloads {
                let ready = target
                    .get(&w.path())
                    .await?
                    .map_or(0, |o| o["status"]["readyReplicas"].as_i64().unwrap_or(0));
                if ready < w.replicas {
                    pending.push(format!("{} ready {ready}/{}", w.path(), w.replicas));
                }
            }
            Ok((!pending.is_empty()).then(|| pending.join(", ")))
        })
        .await
        .context("u7s is installed with Retain still set on every PV; `u7s migrate rollback` is available")?;
        step(&mut st, paths, Stage::Verified)?;
    }

    if st.stage < Stage::PoliciesRestored {
        for r in &st.pvs {
            set_policy(&target, &r.name, &r.original_policy, None).await?;
        }
        step(&mut st, paths, Stage::PoliciesRestored)?;
    }
    Ok(())
}

/// Returns the host to the source k3s cluster: stops u7s, starts k3s, and puts
/// back the source's reclaim policies and replica counts. Refused once the
/// user has deleted a migrated PVC on u7s.
pub async fn rollback<S: Api, H: Host>(src: &S, host: &mut H, paths: &Paths) -> anyhow::Result<()> {
    let mut st = load_state(paths).context("reading cutover state")?.with_context(|| {
        format!(
            "no cutover state in {} (pass the --work-dir the cutover printed); nothing to roll back",
            paths.dir.display()
        )
    })?;
    if st.stage >= Stage::Verified && !st.rolling_back {
        let unreachable = "cannot check whether u7s data was deleted: start u7s and retry";
        let target = host.target().await.context(unreachable)?;
        let pvs = target
            .list("/api/v1/persistentvolumes")
            .await
            .context(unreachable)?;
        if let Err(why) = rollback_window_open(&st, &pvs) {
            bail!(
                "rollback window closed: {why}. Rolling back now would start k3s against \
                 volumes u7s already deleted. The k3s data directory is untouched."
            );
        }
    }
    if !st.rolling_back {
        st.rolling_back = true;
        save(paths, &st)?;
    }
    if st.stage >= Stage::K3sStopped {
        host.stop_u7s().await?;
    }
    host.start_k3s().await?;
    poll("the k3s API to answer", || async {
        src.list("/api/v1/persistentvolumes").await.map(|_| None)
    })
    .await?;
    for r in &st.pvs {
        if src.get(&pv_path(&r.name)).await?.is_some() {
            set_policy(src, &r.name, &r.original_policy, None).await?;
        }
    }
    for w in &st.workloads {
        if src.get(&w.path()).await?.is_some() {
            src.merge_patch(&w.path(), &json!({"spec": {"replicas": w.replicas}}))
                .await?;
        }
    }
    step(&mut st, paths, Stage::RolledBack)
}

/// The k3s host driven through systemd and this binary.
pub struct SystemHost {
    pub source_kubeconfig: String,
    pub k3s_data_dir: String,
    pub install_script: String,
}

const U7S_UNITS: [&str; 4] = [
    "kubelet.service",
    "u7s-kcm-restart.path",
    "u7s-kcm.service",
    "u7s-apiserver.service",
];

pub const K3S_KILLALL: &str = "/usr/local/bin/k3s-killall.sh";

/// Stopping k3s: the service first, then k3s's own killall script, which
/// kills the leftover containerd shims, unmounts pod mounts and removes
/// cni0/flannel.1 and k3s's iptables rules (u7s would otherwise clash with
/// them on the same CIDRs). It never deletes the data directory.
pub fn stop_k3s_commands() -> [(&'static str, Vec<&'static str>); 2] {
    [
        ("systemctl", vec!["disable", "--now", "k3s"]),
        (K3S_KILLALL, vec![]),
    ]
}

/// `path` must be a regular file with an execute bit.
pub fn check_executable(path: &str, what: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::metadata(path).with_context(|| format!("{what}: cannot stat {path}"))?;
    if !m.is_file() || m.permissions().mode() & 0o111 == 0 {
        bail!("{what}: {path} is not an executable regular file");
    }
    Ok(())
}

/// `path` must be a regular file this process can open for reading.
pub fn check_readable_file(path: &str, what: &str) -> anyhow::Result<()> {
    let m = std::fs::metadata(path).with_context(|| format!("{what}: cannot stat {path}"))?;
    if !m.is_file() {
        bail!("{what}: {path} is not a regular file");
    }
    std::fs::File::open(path).with_context(|| format!("{what}: cannot read {path}"))?;
    Ok(())
}

/// The install script and a local `--tarball PATH` are run/read only after
/// k3s has been stopped; a bad one then leaves the host without a cluster.
pub fn check_install_inputs(install_script: &str, install_args: &[String]) -> anyhow::Result<()> {
    guard_command(install_script)?;
    check_readable_file(install_script, "--install-script")?;
    if let Some(i) = install_args.iter().position(|a| a == "--tarball") {
        let path = install_args
            .get(i + 1)
            .context("--tarball needs a path argument")?;
        check_readable_file(path, "--tarball")?;
    }
    Ok(())
}

async fn run_cmd(program: &str, args: &[&str]) -> anyhow::Result<()> {
    guard_command(program)?;
    let status = tokio::process::Command::new(program)
        .args(args)
        .status()
        .await
        .with_context(|| format!("running {program}"))?;
    if !status.success() {
        bail!("{program} {args:?} failed: {status}");
    }
    Ok(())
}

impl Host for SystemHost {
    type Target = Live;

    fn k3s_data_dir_exists(&self) -> bool {
        Path::new(&self.k3s_data_dir).is_dir()
    }

    fn preflight(&self, install_args: &[String]) -> anyhow::Result<()> {
        check_executable(K3S_KILLALL, "k3s-killall.sh (needed to stop k3s)")?;
        check_install_inputs(&self.install_script, install_args)
    }

    fn u7s_installed(&self) -> bool {
        Path::new(U7S_KUBECONFIG).exists()
    }

    async fn stop_k3s(&mut self) -> anyhow::Result<()> {
        for (program, args) in stop_k3s_commands() {
            run_cmd(program, &args).await?;
        }
        Ok(())
    }

    async fn start_k3s(&mut self) -> anyhow::Result<()> {
        run_cmd("systemctl", &["enable", "--now", "k3s"]).await
    }

    async fn install_u7s(&mut self, args: &[String]) -> anyhow::Result<()> {
        guard_command(&self.install_script)?;
        let mut a: Vec<&str> = vec![&self.install_script];
        a.extend(args.iter().map(String::as_str));
        run_cmd("bash", &a).await
    }

    async fn stop_u7s(&mut self) -> anyhow::Result<()> {
        for u in U7S_UNITS {
            let known = tokio::process::Command::new("systemctl")
                .args(["cat", u])
                .output()
                .await?
                .status
                .success();
            if known {
                run_cmd("systemctl", &["disable", "--now", u]).await?;
            }
        }
        Ok(())
    }

    async fn export(&mut self, plan: &str, objects: &str) -> anyhow::Result<()> {
        let exe = std::env::current_exe()?;
        run_cmd(
            s(&exe),
            &[
                "migrate",
                "export",
                "--kubeconfig",
                &self.source_kubeconfig,
                "--plan",
                plan,
                "--objects",
                objects,
            ],
        )
        .await
    }

    async fn import(&mut self, plan: &str, objects: &str) -> anyhow::Result<()> {
        let exe = std::env::current_exe()?;
        run_cmd(
            s(&exe),
            &[
                "migrate",
                "import",
                "--kubeconfig",
                U7S_KUBECONFIG,
                "--plan",
                plan,
                "--objects",
                objects,
            ],
        )
        .await
    }

    async fn target(&mut self) -> anyhow::Result<Live> {
        Live::connect(U7S_KUBECONFIG)
    }
}

#[cfg(test)]
mod tests;

/// An apiserver reached with a kubeconfig.
pub struct Live(discover::Source);

impl Live {
    pub fn connect(kubeconfig: &str) -> anyhow::Result<Self> {
        Ok(Self(discover::Source::connect(kubeconfig)?))
    }
}

impl Api for Live {
    async fn list(&self, path: &str) -> anyhow::Result<Vec<Value>> {
        self.0.list_path(path).await
    }

    async fn get(&self, path: &str) -> anyhow::Result<Option<Value>> {
        let (status, body) = self.0.client.request(Method::GET, path, None).await?;
        match status.as_u16() {
            200 => Ok(Some(serde_json::from_str(&body)?)),
            404 => Ok(None),
            c => bail!(
                "GET {path}: {c}: {}",
                body.chars().take(300).collect::<String>()
            ),
        }
    }

    async fn merge_patch(&self, path: &str, patch: &Value) -> anyhow::Result<()> {
        let (status, body) = self
            .0
            .client
            .request_with_content_type(
                Method::PATCH,
                path,
                Some(patch.to_string()),
                "application/merge-patch+json",
            )
            .await?;
        if status.as_u16() != 200 {
            bail!(
                "PATCH {path}: {status}: {}",
                body.chars().take(300).collect::<String>()
            );
        }
        Ok(())
    }
}
