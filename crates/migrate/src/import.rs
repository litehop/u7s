//! `u7s migrate import`: recreates the included objects of an export on a
//! u7s apiserver through its API.
//!
//! Pass 1 creates every object without ownerReferences, without the claim and
//! snapshot UIDs, and without allowlisted finalizers. Pass 2 runs once all new
//! UIDs are known and patches the references back with the old->new UID map, so
//! ownership cycles need no special case and nothing the garbage collector
//! could reap exists before its owners do.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use hyper::Method;
use serde_json::{json, Value};

use crate::classify::{api_version, group_of, kind, name, namespace, Action, FinalizerAction};
use crate::discover;
use crate::plan::{Entry, Plan};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjId {
    pub api_version: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
}

impl ObjId {
    pub fn of(o: &Value) -> Self {
        Self {
            api_version: api_version(o).to_string(),
            kind: kind(o).to_string(),
            namespace: namespace(o).map(str::to_string),
            name: name(o).to_string(),
        }
    }

    fn of_entry(e: &Entry) -> Self {
        Self {
            api_version: e.api_version.clone(),
            kind: e.kind.clone(),
            namespace: e.namespace.clone(),
            name: e.name.clone(),
        }
    }

    fn group(&self) -> &str {
        self.api_version.split_once('/').map_or("", |(g, _)| g)
    }
}

impl std::fmt::Display for ObjId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.namespace {
            Some(ns) => write!(f, "{} {ns}/{}", self.kind, self.name),
            None => write!(f, "{} {}", self.kind, self.name),
        }
    }
}

/// The target apiserver.
#[allow(async_fn_in_trait)]
pub trait Cluster {
    async fn get(&self, id: &ObjId) -> anyhow::Result<Option<Value>>;
    /// Returns the stored object.
    async fn create(&self, id: &ObjId, body: &Value) -> anyhow::Result<Value>;
    async fn merge_patch(&self, id: &ObjId, patch: &Value) -> anyhow::Result<()>;
    /// Blocks until the just-created CRDs are Established and served, so
    /// their instances can be created.
    async fn settle(&mut self, crds: &[ServedCrd]) -> anyhow::Result<()>;
    /// One attempt to reach the webhook's backend through the target
    /// apiserver. True only when the backend answered over TLS at the
    /// webhook's port: a ready Endpoints address does not prove that, and a
    /// `failurePolicy: Fail` configuration created earlier would reject
    /// every later create.
    async fn backend_serving(&self, b: &Backend) -> anyhow::Result<bool>;
}

/// The Service a webhook configuration calls.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Backend {
    pub namespace: String,
    pub service: String,
    pub port: u16,
    pub path: String,
    /// `<configuration>/<webhook>`, for error messages.
    pub webhook: String,
}

const BACKEND_ATTEMPTS: u32 = 90;
/// Zero under test so the bounded retry runs instantly.
const BACKEND_DELAY: Duration = if cfg!(test) {
    Duration::ZERO
} else {
    Duration::from_secs(1)
};

async fn await_backends<C: Cluster>(
    c: &C,
    backends: &[Backend],
    attempts: u32,
    delay: Duration,
) -> anyhow::Result<()> {
    for b in backends {
        let mut serving = false;
        for n in 0..attempts {
            if n > 0 {
                tokio::time::sleep(delay).await;
            }
            if c.backend_serving(b).await? {
                serving = true;
                break;
            }
        }
        if !serving {
            bail!(
                "webhook {} is not serving: Service {}/{} port {} did not answer after {attempts} attempts; \
                 the configuration was not created, re-run import once its workload is running",
                b.webhook,
                b.namespace,
                b.service,
                b.port
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedCrd {
    pub name: String,
    pub group: String,
    pub kind: String,
}

/// Annotation written in pass 1 holding the source object's UID. It is the
/// only proof that a same-named object on the target was created by this
/// import rather than being someone else's.
pub const SOURCE_UID_ANNOTATION: &str = "migrate.u7s.dev/source-uid";

/// Creation order: what other objects need must exist first. Instances of
/// custom resources and workloads come next, after the CRDs are served.
/// Admission configuration is last: a webhook that exists before its backend
/// rejects every later create.
fn rank(id: &ObjId) -> u8 {
    match (id.group(), id.kind.as_str()) {
        ("admissionregistration.k8s.io", _) => 9,
        ("apiextensions.k8s.io", "CustomResourceDefinition") => 0,
        ("", "Namespace") => 1,
        ("", "ServiceAccount") | ("rbac.authorization.k8s.io", _) => 2,
        ("", "Secret" | "ConfigMap") => 3,
        ("storage.k8s.io", "CSIDriver" | "StorageClass") => 4,
        ("", "PersistentVolume") => 5,
        ("", "PersistentVolumeClaim") => 6,
        ("", "Service") => 7,
        _ => 8,
    }
}

const SERVER_OWNED_METADATA: &[&str] = &[
    "uid",
    "resourceVersion",
    "creationTimestamp",
    "generation",
    "managedFields",
    "selfLink",
    "ownerReferences",
    "deletionTimestamp",
    "deletionGracePeriodSeconds",
];

fn source_uid(o: &Value) -> &str {
    o["metadata"]["uid"].as_str().unwrap_or_default()
}

pub struct Pass1 {
    pub body: Value,
    pub removed_finalizers: Vec<String>,
    /// PV pre-bound to a claim that is not imported; the pre-bind was dropped.
    pub dropped_claim: Option<String>,
}

/// The create body for pass 1. `claims` are the (namespace, name) of every PVC
/// that will be imported.
///
/// A PV's claimRef keeps namespace/name but loses its UID: the volume
/// controller treats a claimRef with a UID whose claim does not exist as a
/// released volume, and with reclaimPolicy Delete that deletes the data. A
/// claimRef without UID is a pre-bind that waits for the claim. Everything
/// else, including Service clusterIP and nodePorts, is sent as exported.
pub fn pass1_body(obj: &Value, entry: &Entry, claims: &HashSet<(String, String)>) -> Pass1 {
    let mut body = obj.clone();
    body.as_object_mut().map(|o| o.remove("status"));
    let mut removed = vec![];
    let source_uid = source_uid(obj).to_string();
    if let Some(meta) = body["metadata"].as_object_mut() {
        meta.entry("annotations")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .map(|a| a.insert(SOURCE_UID_ANNOTATION.into(), source_uid.into()));
        for k in SERVER_OWNED_METADATA {
            meta.remove(*k);
        }
        if let Some(fins) = meta.get("finalizers").and_then(Value::as_array) {
            let kept: Vec<Value> = fins
                .iter()
                .filter(|f| {
                    let strip = entry.finalizers.iter().any(|d| {
                        d.action == FinalizerAction::Strip && Some(d.name.as_str()) == f.as_str()
                    });
                    if strip {
                        removed.push(f.as_str().unwrap_or_default().to_string());
                    }
                    !strip
                })
                .cloned()
                .collect();
            if kept.is_empty() {
                meta.remove("finalizers");
            } else {
                meta.insert("finalizers".into(), Value::Array(kept));
            }
        }
    }
    let mut dropped_claim = None;
    let (group, k) = (group_of(obj), kind(obj));
    if group.is_empty() && k == "PersistentVolume" {
        if let Some(cr) = body["spec"]["claimRef"].as_object_mut() {
            cr.remove("uid");
            cr.remove("resourceVersion");
            let key = (
                cr.get("namespace")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                cr.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            );
            if !claims.contains(&key) {
                dropped_claim = Some(format!("{}/{}", key.0, key.1));
            }
        }
        if dropped_claim.is_some() {
            body["spec"].as_object_mut().map(|s| s.remove("claimRef"));
        }
    }
    if group == "snapshot.storage.k8s.io" && k == "VolumeSnapshotContent" {
        body["spec"]["volumeSnapshotRef"]
            .as_object_mut()
            .map(|r| r.remove("uid"));
    }
    Pass1 {
        body,
        removed_finalizers: removed,
        dropped_claim,
    }
}

/// Where new UIDs are looked up in pass 2.
#[derive(Default)]
pub struct Remap {
    by_old_uid: HashMap<String, String>,
    by_key: HashMap<(String, Option<String>, String), String>,
}

impl Remap {
    fn record(&mut self, src: &Value, new_uid: &str) {
        if let Some(old) = src["metadata"]["uid"].as_str() {
            self.by_old_uid.insert(old.to_string(), new_uid.to_string());
        }
        self.by_key.insert(
            (
                kind(src).to_string(),
                namespace(src).map(str::to_string),
                name(src).to_string(),
            ),
            new_uid.to_string(),
        );
    }

    fn lookup(&self, kind: &str, ns: Option<&str>, name: &str) -> Option<&String> {
        self.by_key
            .get(&(kind.to_string(), ns.map(str::to_string), name.to_string()))
    }
}

#[derive(Debug, Default)]
pub struct Pass2 {
    pub patch: Option<Value>,
    pub owner_refs_remapped: usize,
    /// ownerReferences whose owner was not imported. Keeping one would make
    /// the garbage collector delete this object.
    pub owner_refs_dropped: Vec<String>,
    pub claim_ref_remapped: bool,
    /// The target object's reference points somewhere other than the
    /// export's; nothing is patched.
    pub conflict: Option<String>,
}

/// The patch that moves `current` (what the target stores now) to the
/// references `src` has, expressed in new UIDs. `None` when already there.
pub fn pass2(src: &Value, current: &Value, remap: &Remap) -> Pass2 {
    let mut out = Pass2::default();
    let mut patch = json!({});

    let mut desired = vec![];
    for r in src["metadata"]["ownerReferences"]
        .as_array()
        .into_iter()
        .flatten()
    {
        match r["uid"].as_str().and_then(|u| remap.by_old_uid.get(u)) {
            Some(new) => {
                let mut r = r.clone();
                r["uid"] = new.clone().into();
                desired.push(r);
            }
            None => out.owner_refs_dropped.push(format!(
                "{}/{}",
                r["kind"].as_str().unwrap_or_default(),
                r["name"].as_str().unwrap_or_default()
            )),
        }
    }
    // Merge-patch replaces lists wholesale, so keep every reference already on
    // the object and add only the ones from the export.
    let existing = current["metadata"]["ownerReferences"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut merged = existing.clone();
    for d in desired {
        match merged.iter().position(|e| e["uid"] == d["uid"]) {
            Some(i) if merged[i] == d => {}
            Some(i) => {
                merged[i] = d;
                out.owner_refs_remapped += 1;
            }
            None => {
                merged.push(d);
                out.owner_refs_remapped += 1;
            }
        }
    }
    if merged != existing {
        patch["metadata"] = json!({ "ownerReferences": merged });
    }

    let (group, k) = (group_of(src), kind(src));
    let (section, field, owner_kind) = if group.is_empty() && k == "PersistentVolume" {
        ("claimRef", "claimRef", "PersistentVolumeClaim")
    } else if group == "snapshot.storage.k8s.io" && k == "VolumeSnapshotContent" {
        ("volumeSnapshotRef", "volumeSnapshotRef", "VolumeSnapshot")
    } else {
        ("", "", "")
    };
    if !section.is_empty() {
        let r = &src["spec"][field];
        let new = r["name"]
            .as_str()
            .and_then(|n| remap.lookup(owner_kind, r["namespace"].as_str(), n));
        if let Some(new) = new {
            let cur = &current["spec"][field];
            if cur["name"] != r["name"] || cur["namespace"] != r["namespace"] {
                out.conflict = Some(format!(
                    "{field} is {}/{} on the target but {}/{} in the export",
                    cur["namespace"].as_str().unwrap_or_default(),
                    cur["name"].as_str().unwrap_or_default(),
                    r["namespace"].as_str().unwrap_or_default(),
                    r["name"].as_str().unwrap_or_default()
                ));
                out.patch = None;
                return out;
            }
            if cur["uid"].as_str() != Some(new.as_str()) {
                patch["spec"] = json!({ field: { "uid": new } });
                out.claim_ref_remapped = true;
            }
        }
    }
    if patch != json!({}) {
        out.patch = Some(patch);
    }
    out
}

#[derive(Debug, Default)]
pub struct Report {
    pub skipped: Vec<String>,
    pub created: Vec<String>,
    /// Already on the target; left unchanged.
    pub existing: Vec<String>,
    pub finalizers_removed: Vec<String>,
    pub owner_refs_remapped: Vec<String>,
    pub owner_refs_dropped: Vec<String>,
    pub claim_refs_remapped: Vec<String>,
    pub claims_dropped: Vec<String>,
    pub failures: Vec<String>,
    /// Pass 1 failed somewhere; references were not touched.
    pub pass2_skipped: bool,
}

impl Report {
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let mut section = |title: &str, lines: &[String]| {
            let _ = writeln!(out, "{title} ({}):", lines.len());
            for l in lines {
                let _ = writeln!(out, "  {l}");
            }
        };
        section("skipped by plan", &self.skipped);
        section("created", &self.created);
        section("already present, unchanged", &self.existing);
        section("finalizers removed (allowlisted)", &self.finalizers_removed);
        section(
            "ownerReferences remapped to new UIDs",
            &self.owner_refs_remapped,
        );
        section(
            "ownerReferences dropped, owner not imported",
            &self.owner_refs_dropped,
        );
        section("PV claimRef UID remapped", &self.claim_refs_remapped);
        section(
            "PV claimRef dropped, claim not imported",
            &self.claims_dropped,
        );
        section("FAILED", &self.failures);
        if self.pass2_skipped {
            let _ = writeln!(
                out,
                "pass 2 not run because pass 1 had failures; fix them and re-run, import resumes"
            );
        }
        out
    }
}

struct Item<'a> {
    id: ObjId,
    entry: &'a Entry,
    src: &'a Value,
    current: Option<Value>,
}

/// Imports every included object of `plan` from `objs`. Safe to re-run: objects
/// already on the target are adopted unchanged and pass 2 only patches what
/// differs.
pub async fn run<C: Cluster>(c: &mut C, plan: &Plan, objs: &[Value]) -> anyhow::Result<Report> {
    plan.validate().map_err(anyhow::Error::msg)?;
    let by_id: HashMap<ObjId, &Value> = objs.iter().map(|o| (ObjId::of(o), o)).collect();
    let mut report = Report::default();
    let mut items = vec![];
    for e in &plan.entries {
        let id = ObjId::of_entry(e);
        if e.action == Action::Exclude {
            report.skipped.push(format!("{id} -- {}", e.reason));
            continue;
        }
        let src = by_id
            .get(&id)
            .copied()
            .ok_or_else(|| anyhow!("plan includes {id} but the export does not contain it"))?;
        items.push(Item {
            id,
            entry: e,
            src,
            current: None,
        });
    }
    items.sort_by_key(|i| rank(&i.id));
    let claims: HashSet<(String, String)> = items
        .iter()
        .filter(|i| i.id.group().is_empty() && i.id.kind == "PersistentVolumeClaim")
        .map(|i| {
            (
                i.id.namespace.clone().unwrap_or_default(),
                i.id.name.clone(),
            )
        })
        .collect();

    let mut remap = Remap::default();
    let crds = items.iter().take_while(|i| rank(&i.id) == 0).count();
    let served: Vec<ServedCrd> = items[..crds]
        .iter()
        .filter_map(|i| {
            Some(ServedCrd {
                name: i.id.name.clone(),
                group: i.src["spec"]["group"].as_str()?.to_string(),
                kind: i.src["spec"]["names"]["kind"].as_str()?.to_string(),
            })
        })
        .collect();
    let admission_start = items.iter().position(|i| rank(&i.id) == 9);
    let imported_services: HashSet<(String, String)> = items
        .iter()
        .filter(|i| i.id.group().is_empty() && i.id.kind == "Service")
        .map(|i| {
            (
                i.id.namespace.clone().unwrap_or_default(),
                i.id.name.clone(),
            )
        })
        .collect();
    let backends = webhook_backends(items.iter().map(|i| i.src), &imported_services);
    for (n, item) in items.iter_mut().enumerate() {
        if n == crds && crds > 0 {
            c.settle(&served).await?;
        }
        if Some(n) == admission_start {
            if let Err(e) = await_backends(c, &backends, BACKEND_ATTEMPTS, BACKEND_DELAY).await {
                report
                    .failures
                    .push(format!("admission configuration: {e:#}"));
                report.pass2_skipped = true;
                return Ok(report);
            }
        }
        match import_one(c, item, &claims, &mut report).await {
            Ok(uid) => remap.record(item.src, &uid),
            Err(e) => report.failures.push(format!("{}: {e:#}", item.id)),
        }
    }

    if !report.failures.is_empty() {
        report.pass2_skipped = true;
        return Ok(report);
    }
    for item in &items {
        let Some(current) = &item.current else {
            continue;
        };
        let p = pass2(item.src, current, &remap);
        if let Some(why) = &p.conflict {
            report.failures.push(format!("{}: {why}", item.id));
            continue;
        }
        for d in &p.owner_refs_dropped {
            report
                .owner_refs_dropped
                .push(format!("{} -> {d}", item.id));
        }
        if let Some(patch) = &p.patch {
            match c.merge_patch(&item.id, patch).await {
                Ok(()) => {
                    if p.owner_refs_remapped > 0 {
                        report.owner_refs_remapped.push(format!(
                            "{} ({} reference(s))",
                            item.id, p.owner_refs_remapped
                        ));
                    }
                    if p.claim_ref_remapped {
                        report.claim_refs_remapped.push(item.id.to_string());
                    }
                }
                Err(e) => report.failures.push(format!("{} pass 2: {e:#}", item.id)),
            }
        }
    }
    Ok(report)
}

/// Backends of the webhooks in `objs` whose Service this import creates,
/// sorted. Webhooks pointing elsewhere (URL, or a Service not imported) are
/// not waited for.
fn webhook_backends<'a>(
    objs: impl Iterator<Item = &'a Value>,
    imported: &HashSet<(String, String)>,
) -> Vec<Backend> {
    let mut out: Vec<Backend> = objs
        .filter(|o| {
            group_of(o) == "admissionregistration.k8s.io"
                && matches!(
                    kind(o),
                    "ValidatingWebhookConfiguration" | "MutatingWebhookConfiguration"
                )
        })
        .flat_map(|o| {
            let cfg = name(o).to_string();
            o["webhooks"]
                .as_array()
                .into_iter()
                .flatten()
                .map(move |w| (cfg.clone(), w))
        })
        .filter_map(|(cfg, w)| {
            let s = &w["clientConfig"]["service"];
            Some(Backend {
                namespace: s["namespace"].as_str()?.to_string(),
                service: s["name"].as_str()?.to_string(),
                port: s["port"].as_u64().map_or(443, |p| p as u16),
                path: s["path"].as_str().unwrap_or("/").to_string(),
                webhook: format!("{cfg}/{}", w["name"].as_str().unwrap_or("?")),
            })
        })
        .filter(|b| imported.contains(&(b.namespace.clone(), b.service.clone())))
        .collect();
    out.sort();
    out.dedup_by(|a, b| {
        (&a.namespace, &a.service, a.port, &a.path) == (&b.namespace, &b.service, b.port, &b.path)
    });
    out
}

async fn import_one<C: Cluster>(
    c: &C,
    item: &mut Item<'_>,
    claims: &HashSet<(String, String)>,
    report: &mut Report,
) -> anyhow::Result<String> {
    let cur = match c.get(&item.id).await? {
        Some(cur) => {
            let marker = cur["metadata"]["annotations"][SOURCE_UID_ANNOTATION].as_str();
            if marker != Some(source_uid(item.src)) {
                bail!(
                    "already exists on the target and was not created by this import \
                     (no matching {SOURCE_UID_ANNOTATION} annotation); not touching it"
                );
            }
            report.existing.push(item.id.to_string());
            cur
        }
        None => {
            let p1 = pass1_body(item.src, item.entry, claims);
            let cur = c.create(&item.id, &p1.body).await?;
            report.created.push(item.id.to_string());
            for f in p1.removed_finalizers {
                report.finalizers_removed.push(format!("{} {f}", item.id));
            }
            if let Some(cl) = p1.dropped_claim {
                report.claims_dropped.push(format!("{} -> {cl}", item.id));
            }
            cur
        }
    };
    let uid = cur["metadata"]["uid"]
        .as_str()
        .context("target returned an object without metadata.uid")?
        .to_string();
    item.current = Some(cur);
    Ok(uid)
}

/// Reads the plan and the exported objects, as written by `export`.
pub fn load(plan: &str, objects: &str) -> anyhow::Result<(Plan, Vec<Value>)> {
    let plan: Plan = serde_json::from_str(
        &std::fs::read_to_string(plan).with_context(|| format!("reading {plan}"))?,
    )
    .with_context(|| format!("parsing {plan}"))?;
    let objs: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(objects).with_context(|| {
            format!("reading {objects} (re-run `u7s migrate export` to produce it)")
        })?)
        .with_context(|| format!("parsing {objects}"))?;
    Ok((plan, objs))
}

fn crd_established(crd: &Value) -> bool {
    crd["status"]["conditions"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|c| c["type"] == "Established" && c["status"] == "True")
}

/// The apiserver service proxy resolves the URL port against the Endpoints
/// ports, which carry the target port, not the Service port; address the
/// port by name when it has one, else by its numeric target.
fn proxy_port(svc: &Value, port: u16) -> String {
    let p = svc["spec"]["ports"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["port"].as_u64() == Some(u64::from(port)));
    match p {
        Some(p) => match (p["name"].as_str(), p["targetPort"].as_u64()) {
            (Some(n), _) if !n.is_empty() => n.to_string(),
            (_, Some(t)) => t.to_string(),
            _ => port.to_string(),
        },
        None => port.to_string(),
    }
}

/// Any answer from the backend proves its TLS port serves; the proxy's own
/// 502/503/504 mean it could not reach one.
fn proxied_backend_answered(status: u16) -> bool {
    !matches!(status, 502..=504)
}

/// A u7s apiserver reached over the Kubernetes API.
pub struct Live {
    src: discover::Source,
    /// (group, kind) -> (plural, namespaced)
    types: HashMap<(String, String), (String, bool)>,
}

impl Live {
    pub async fn connect(kubeconfig: &str) -> anyhow::Result<Self> {
        let mut l = Self {
            src: discover::Source::connect(kubeconfig)?,
            types: HashMap::new(),
        };
        l.refresh().await?;
        Ok(l)
    }

    async fn refresh(&mut self) -> anyhow::Result<()> {
        let (types, failures) = self.src.resource_types().await?;
        if !failures.is_empty() {
            bail!("target discovery failed: {}", failures.join("; "));
        }
        self.types = types
            .into_iter()
            .map(|t| ((t.group, t.kind), (t.plural, t.namespaced)))
            .collect();
        Ok(())
    }

    fn path(&self, id: &ObjId, named: bool) -> anyhow::Result<String> {
        let (plural, namespaced) = self
            .types
            .get(&(id.group().to_string(), id.kind.clone()))
            .ok_or_else(|| anyhow!("target does not serve {}", id.kind))?;
        let root = if id.group().is_empty() {
            format!("/api/{}", id.api_version)
        } else {
            format!("/apis/{}", id.api_version)
        };
        let mut p = root;
        match (namespaced, &id.namespace) {
            (true, Some(ns)) => p.push_str(&format!("/namespaces/{ns}")),
            (false, None) => {}
            _ => bail!(
                "{id}: namespace does not match the target's scope for {}",
                id.kind
            ),
        }
        p.push_str(&format!("/{plural}"));
        if named {
            p.push_str(&format!("/{}", id.name));
        }
        Ok(p)
    }

    async fn all_established(&self, crds: &[ServedCrd]) -> anyhow::Result<bool> {
        for c in crds {
            let path = format!(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{}",
                c.name
            );
            let (status, body) = self.src.client.request(Method::GET, &path, None).await?;
            if status.as_u16() != 200 || !crd_established(&serde_json::from_str(&body)?) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn call(
        &self,
        m: Method,
        path: &str,
        body: &Value,
        ct: &str,
    ) -> anyhow::Result<(u16, String)> {
        let (status, text) = self
            .src
            .client
            .request_with_content_type(m, path, Some(body.to_string()), ct)
            .await?;
        Ok((status.as_u16(), text))
    }
}

impl Cluster for Live {
    async fn get(&self, id: &ObjId) -> anyhow::Result<Option<Value>> {
        let path = self.path(id, true)?;
        let (status, body) = self.src.client.request(Method::GET, &path, None).await?;
        match status.as_u16() {
            200 => Ok(Some(serde_json::from_str(&body)?)),
            404 => Ok(None),
            s => bail!(
                "GET {path}: {s}: {}",
                body.chars().take(300).collect::<String>()
            ),
        }
    }

    async fn create(&self, id: &ObjId, body: &Value) -> anyhow::Result<Value> {
        let path = self.path(id, false)?;
        let (s, text) = self
            .call(Method::POST, &path, body, "application/json")
            .await?;
        if s != 201 && s != 200 {
            bail!(
                "POST {path}: {s}: {}",
                text.chars().take(300).collect::<String>()
            );
        }
        Ok(serde_json::from_str(&text)?)
    }

    async fn merge_patch(&self, id: &ObjId, patch: &Value) -> anyhow::Result<()> {
        let path = self.path(id, true)?;
        let (s, text) = self
            .call(Method::PATCH, &path, patch, "application/merge-patch+json")
            .await?;
        if s != 200 {
            bail!(
                "PATCH {path}: {s}: {}",
                text.chars().take(300).collect::<String>()
            );
        }
        Ok(())
    }

    async fn settle(&mut self, crds: &[ServedCrd]) -> anyhow::Result<()> {
        for _ in 0..60 {
            self.refresh().await?;
            let served = crds
                .iter()
                .all(|c| self.types.contains_key(&(c.group.clone(), c.kind.clone())));
            if served && self.all_established(crds).await? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("target did not establish and serve the imported CRDs within 60s")
    }

    async fn backend_serving(&self, b: &Backend) -> anyhow::Result<bool> {
        let svc_path = format!("/api/v1/namespaces/{}/services/{}", b.namespace, b.service);
        let (status, body) = self
            .src
            .client
            .request(Method::GET, &svc_path, None)
            .await?;
        if status.as_u16() != 200 {
            return Ok(false);
        }
        let port = proxy_port(&serde_json::from_str(&body)?, b.port);
        let path = format!(
            "/api/v1/namespaces/{}/services/https:{}:{port}/proxy/{}",
            b.namespace,
            b.service,
            b.path.trim_start_matches('/')
        );
        let (status, _) = self.src.client.request(Method::GET, &path, None).await?;
        Ok(proxied_backend_answered(status.as_u16()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::FinalizerDecision;
    use crate::plan::Source;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        store: RefCell<HashMap<ObjId, Value>>,
        next: RefCell<u32>,
        creates: RefCell<Vec<ObjId>>,
        patches: RefCell<Vec<(ObjId, Value)>>,
        settled: Vec<Vec<ServedCrd>>,
        /// (number of creates so far, backend probed) per probe
        probes: RefCell<Vec<(usize, Backend)>>,
        /// The backend answers from this probe number on (1-based); 0 = never.
        serves_from_probe: usize,
        fail_create_kind: Option<&'static str>,
    }

    fn merge(dst: &mut Value, patch: &Value) {
        match (dst, patch) {
            (Value::Object(d), Value::Object(p)) => {
                for (k, v) in p {
                    merge(d.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
            (d, p) => *d = p.clone(),
        }
    }

    impl Cluster for Fake {
        async fn get(&self, id: &ObjId) -> anyhow::Result<Option<Value>> {
            Ok(self.store.borrow().get(id).cloned())
        }
        async fn create(&self, id: &ObjId, body: &Value) -> anyhow::Result<Value> {
            if self.fail_create_kind == Some(id.kind.as_str()) {
                bail!("injected create failure");
            }
            let mut b = body.clone();
            *self.next.borrow_mut() += 1;
            b["metadata"]["uid"] = format!("new-{}", self.next.borrow()).into();
            self.store.borrow_mut().insert(id.clone(), b.clone());
            self.creates.borrow_mut().push(id.clone());
            Ok(b)
        }
        async fn merge_patch(&self, id: &ObjId, patch: &Value) -> anyhow::Result<()> {
            self.patches.borrow_mut().push((id.clone(), patch.clone()));
            merge(self.store.borrow_mut().get_mut(id).unwrap(), patch);
            Ok(())
        }
        async fn settle(&mut self, crds: &[ServedCrd]) -> anyhow::Result<()> {
            self.settled.push(crds.to_vec());
            Ok(())
        }
        async fn backend_serving(&self, b: &Backend) -> anyhow::Result<bool> {
            let mut p = self.probes.borrow_mut();
            p.push((self.creates.borrow().len(), b.clone()));
            Ok(self.serves_from_probe != 0 && p.len() >= self.serves_from_probe)
        }
    }

    fn plan_for(objs: &[Value]) -> Plan {
        let fins = |o: &Value| -> Vec<FinalizerDecision> {
            o["metadata"]["finalizers"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|f| FinalizerDecision {
                    name: f.as_str().unwrap().into(),
                    action: if f == "wrangler.cattle.io/node" {
                        FinalizerAction::Strip
                    } else {
                        FinalizerAction::Keep
                    },
                    reason: String::new(),
                    warn: false,
                })
                .collect()
        };
        Plan {
            source: Source {
                k3s_version: "v1.36.5+k3s1".into(),
                shipped_table: "v1.36.5+k3s1".into(),
                service_cidrs: vec![],
                pod_cidrs: vec![],
                kube_dns_cluster_ip: None,
            },
            entries: objs
                .iter()
                .map(|o| Entry {
                    api_version: api_version(o).into(),
                    kind: kind(o).into(),
                    namespace: namespace(o).map(str::to_string),
                    name: name(o).into(),
                    action: Action::Include,
                    rule: "R7".into(),
                    class: "user".into(),
                    reason: String::new(),
                    warn: false,
                    finalizers: fins(o),
                })
                .collect(),
        }
    }

    fn app() -> Vec<Value> {
        vec![
            // a cycle: a and b own each other
            json!({"apiVersion":"example.com/v1","kind":"Widget","metadata":{"name":"a","namespace":"app","uid":"old-a","resourceVersion":"9",
                "ownerReferences":[{"apiVersion":"example.com/v1","kind":"Widget","name":"b","uid":"old-b"}]}}),
            json!({"apiVersion":"example.com/v1","kind":"Widget","metadata":{"name":"b","namespace":"app","uid":"old-b",
                "ownerReferences":[{"apiVersion":"example.com/v1","kind":"Widget","name":"a","uid":"old-a","blockOwnerDeletion":true},
                                   {"apiVersion":"v1","kind":"ConfigMap","name":"gone","uid":"old-gone"}]}}),
            json!({"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.com","uid":"old-crd"},
                "spec":{"group":"example.com","names":{"kind":"Widget"}}}),
            json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"pv1","uid":"old-pv"},
                "spec":{"persistentVolumeReclaimPolicy":"Delete","claimRef":{"namespace":"app","name":"data","uid":"old-pvc","resourceVersion":"5"}},
                "status":{"phase":"Bound"}}),
            json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"app","uid":"old-pvc"},
                "spec":{"volumeName":"pv1"}}),
            json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"web","namespace":"app","uid":"old-svc"},
                "spec":{"clusterIP":"10.43.7.7","clusterIPs":["10.43.7.7"],"ports":[{"port":80,"nodePort":30080}],"type":"NodePort"}}),
            json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm","namespace":"app","uid":"old-cm","finalizers":["wrangler.cattle.io/node","example.com/keep"]}}),
        ]
    }

    fn id(kind: &str, ns: Option<&str>, name: &str) -> ObjId {
        let api_version = match kind {
            "Widget" => "example.com/v1",
            "CustomResourceDefinition" => "apiextensions.k8s.io/v1",
            _ => "v1",
        };
        ObjId {
            api_version: api_version.into(),
            kind: kind.into(),
            namespace: ns.map(str::to_string),
            name: name.into(),
        }
    }

    async fn import(c: &mut Fake) -> Report {
        let objs = app();
        run(c, &plan_for(&objs), &objs).await.unwrap()
    }

    #[tokio::test]
    async fn ownership_cycle_is_restored_with_new_uids_and_stale_owner_is_dropped() {
        let mut c = Fake::default();
        let r = import(&mut c).await;
        let store = c.store.borrow();
        let a = &store[&id("Widget", Some("app"), "a")];
        let b = &store[&id("Widget", Some("app"), "b")];
        let (ua, ub) = (a["metadata"]["uid"].clone(), b["metadata"]["uid"].clone());
        assert_eq!(
            a["metadata"]["ownerReferences"][0]["uid"], ub,
            "a stale old UID makes the garbage collector delete the dependent"
        );
        assert_eq!(b["metadata"]["ownerReferences"][0]["uid"], ua);
        assert_eq!(
            b["metadata"]["ownerReferences"][0]["blockOwnerDeletion"],
            true
        );
        assert_eq!(
            b["metadata"]["ownerReferences"].as_array().unwrap().len(),
            1,
            "a reference to an owner that was not imported must not survive"
        );
        assert_eq!(r.owner_refs_dropped.len(), 1, "the drop is reported");
    }

    #[tokio::test]
    async fn pass_one_body_carries_no_old_uids_or_server_state() {
        let b = pass1_body(&app()[0], &plan_for(&app()).entries[0], &HashSet::new());
        assert!(
            b.body["metadata"]["ownerReferences"].is_null()
                && b.body["metadata"]["uid"].is_null()
                && b.body["metadata"]["resourceVersion"].is_null(),
            "owner refs carry old UIDs and must only be set in pass 2"
        );
    }

    #[tokio::test]
    async fn pv_is_prebound_without_uid_and_claim_uid_is_remapped() {
        let objs = app();
        let claims: HashSet<_> = [("app".to_string(), "data".to_string())].into();
        let p1 = pass1_body(&objs[3], &plan_for(&objs).entries[3], &claims);
        assert!(
            p1.body["spec"]["claimRef"]["uid"].is_null()
                && p1.body["spec"]["claimRef"]["name"] == "data",
            "a claimRef UID with no such claim makes the PV Released, and Delete then destroys the data"
        );
        assert_eq!(p1.body["spec"]["persistentVolumeReclaimPolicy"], "Delete");
        assert!(p1.body["status"].is_null());

        let mut c = Fake::default();
        let r = import(&mut c).await;
        let store = c.store.borrow();
        let pvc_uid = &store[&id("PersistentVolumeClaim", Some("app"), "data")]["metadata"]["uid"];
        assert_eq!(
            &store[&id("PersistentVolume", None, "pv1")]["spec"]["claimRef"]["uid"],
            pvc_uid
        );
        assert_eq!(r.claim_refs_remapped.len(), 1);
        assert_eq!(
            store[&id("PersistentVolumeClaim", Some("app"), "data")]["spec"]["volumeName"],
            "pv1"
        );
    }

    #[test]
    fn pv_claim_that_is_not_imported_loses_its_prebind_instead_of_pointing_at_nothing() {
        let objs = app();
        let p1 = pass1_body(&objs[3], &plan_for(&objs).entries[3], &HashSet::new());
        assert!(p1.body["spec"]["claimRef"].is_null());
        assert_eq!(p1.dropped_claim.as_deref(), Some("app/data"));
    }

    #[test]
    fn volume_snapshot_content_ref_uid_is_stripped_then_remapped() {
        let src = json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotContent","metadata":{"name":"c"},
            "spec":{"volumeSnapshotRef":{"namespace":"app","name":"snap","uid":"old-snap"}}});
        let entry = plan_for(std::slice::from_ref(&src)).entries.remove(0);
        let p1 = pass1_body(&src, &entry, &HashSet::new());
        assert!(p1.body["spec"]["volumeSnapshotRef"]["uid"].is_null());
        let mut remap = Remap::default();
        remap.record(
            &json!({"kind":"VolumeSnapshot","metadata":{"name":"snap","namespace":"app","uid":"old-snap"}}),
            "new-snap",
        );
        let p2 = pass2(&src, &p1.body, &remap);
        assert_eq!(
            p2.patch.unwrap()["spec"]["volumeSnapshotRef"]["uid"],
            "new-snap"
        );
    }

    #[tokio::test]
    async fn service_ip_and_node_port_are_sent_exactly_as_exported() {
        let mut c = Fake::default();
        import(&mut c).await;
        let svc = &c.store.borrow()[&id("Service", Some("app"), "web")];
        assert_eq!(
            svc["spec"]["clusterIP"], "10.43.7.7",
            "clients and DNS hold this IP"
        );
        assert_eq!(svc["spec"]["ports"][0]["nodePort"], 30080);
    }

    #[tokio::test]
    async fn only_the_plans_allowlisted_finalizer_is_removed_and_it_is_reported() {
        let mut c = Fake::default();
        let r = import(&mut c).await;
        assert_eq!(
            c.store.borrow()[&id("ConfigMap", Some("app"), "cm")]["metadata"]["finalizers"],
            json!(["example.com/keep"]),
            "stripping anything but the named entry can orphan external resources"
        );
        assert_eq!(
            r.finalizers_removed,
            ["ConfigMap app/cm wrangler.cattle.io/node"]
        );
    }

    #[tokio::test]
    async fn plan_that_strips_an_unlisted_finalizer_is_refused_before_anything_is_created() {
        let objs = app();
        let mut plan = plan_for(&objs);
        plan.entries[6].finalizers[1].action = FinalizerAction::Strip;
        let mut c = Fake::default();
        assert!(run(&mut c, &plan, &objs).await.is_err());
        assert!(c.creates.borrow().is_empty());
    }

    #[tokio::test]
    async fn rerun_creates_and_patches_nothing() {
        let mut c = Fake::default();
        import(&mut c).await;
        let (creates, patches) = (c.creates.borrow().len(), c.patches.borrow().len());
        assert_eq!(creates, 7);
        let r = import(&mut c).await;
        assert_eq!(
            c.creates.borrow().len(),
            creates,
            "re-run must not duplicate or fail"
        );
        assert_eq!(
            c.patches.borrow().len(),
            patches,
            "re-run must not rewrite references"
        );
        assert_eq!(r.existing.len(), 7);
        assert!(r.failures.is_empty());
    }

    #[tokio::test]
    async fn rerun_after_a_crash_between_passes_restores_the_references() {
        let mut c = Fake::default();
        import(&mut c).await;
        for o in c.store.borrow_mut().values_mut() {
            o["metadata"]
                .as_object_mut()
                .unwrap()
                .remove("ownerReferences");
        }
        import(&mut c).await;
        let b = &c.store.borrow()[&id("Widget", Some("app"), "b")];
        assert_eq!(
            b["metadata"]["ownerReferences"].as_array().unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn crds_are_created_and_served_before_their_instances() {
        let mut c = Fake::default();
        import(&mut c).await;
        let order = c.creates.borrow();
        let pos = |k: &str| order.iter().position(|i| i.kind == k).unwrap();
        assert!(pos("CustomResourceDefinition") < pos("Widget"));
        assert!(pos("PersistentVolume") < pos("PersistentVolumeClaim"));
        assert_eq!(
            c.settled,
            [vec![ServedCrd {
                name: "widgets.example.com".into(),
                group: "example.com".into(),
                kind: "Widget".into()
            }]],
            "instances created before the CRD is served get 404"
        );
    }

    #[tokio::test]
    async fn excluded_entries_are_reported_and_never_created() {
        let objs = app();
        let mut plan = plan_for(&objs);
        plan.entries[6].action = Action::Exclude;
        plan.entries[6].reason = "distro".into();
        let mut c = Fake::default();
        let r = run(&mut c, &plan, &objs).await.unwrap();
        assert_eq!(r.skipped, ["ConfigMap app/cm -- distro"]);
        assert!(!c
            .store
            .borrow()
            .contains_key(&id("ConfigMap", Some("app"), "cm")));
    }

    fn webhook_app() -> Vec<Value> {
        vec![
            // listed first on purpose: ordering must not depend on export order
            json!({"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","metadata":{"name":"vwc","uid":"old-vwc"},
                "webhooks":[{"name":"x.example.com","clientConfig":{"service":{"namespace":"app","name":"hook"}}},
                            {"name":"y.example.com","clientConfig":{"url":"https://external/"}}]}),
            json!({"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingWebhookConfiguration","metadata":{"name":"mwc","uid":"old-mwc"},
                "webhooks":[{"name":"m.example.com","clientConfig":{"service":{"namespace":"app","name":"hook"}}}]}),
            json!({"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"hook","namespace":"app","uid":"old-dep"}}),
            json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"hook","namespace":"app","uid":"old-hsvc"}}),
        ]
    }

    #[tokio::test]
    async fn webhook_configs_are_created_last_after_waiting_for_their_backends() {
        let objs = webhook_app();
        let mut c = Fake {
            serves_from_probe: 4,
            ..Fake::default()
        };
        let r = run(&mut c, &plan_for(&objs), &objs).await.unwrap();
        assert!(r.failures.is_empty());
        let order = c.creates.borrow();
        let kinds: Vec<&str> = order.iter().map(|i| i.kind.as_str()).collect();
        assert!(
            kinds[2..]
                .iter()
                .all(|k| k.ends_with("WebhookConfiguration"))
                && kinds[..2]
                    .iter()
                    .all(|k| !k.ends_with("WebhookConfiguration")),
            "a webhook created before its backend rejects every later create: {kinds:?}"
        );
        let probes = c.probes.borrow();
        assert_eq!(
            probes.len(),
            4,
            "a backend whose port is not serving yet must be probed again, not trusted after one ready Endpoints address"
        );
        assert!(
            probes.iter().all(|(n, b)| *n == 2
                && b.namespace == "app"
                && b.service == "hook"
                && b.port == 443),
            "probes must come after the Deployment and Service exist, before any webhook is created, and only for the imported Service: {probes:?}"
        );
    }

    #[tokio::test]
    async fn webhook_that_never_serves_is_reported_by_name_and_its_configuration_is_not_created() {
        let objs = webhook_app();
        let mut c = Fake::default();
        let r = run(&mut c, &plan_for(&objs), &objs).await.unwrap();
        assert!(
            c.creates
                .borrow()
                .iter()
                .all(|i| !i.kind.ends_with("WebhookConfiguration")),
            "a Fail webhook created over a dead backend would deny every later create in the cluster"
        );
        assert_eq!(r.failures.len(), 1);
        assert!(
            r.failures[0].contains("mwc/m.example.com") && r.failures[0].contains("app/hook"),
            "the operator must be told which webhook and Service to look at: {:?}",
            r.failures[0]
        );
        assert_eq!(
            c.probes.borrow().len(),
            BACKEND_ATTEMPTS as usize,
            "the wait must be bounded"
        );
    }

    #[test]
    fn proxy_port_addresses_the_target_port_because_the_proxy_matches_endpoint_ports() {
        let svc = json!({"spec":{"ports":[
            {"port":443,"targetPort":8443},
            {"name":"metrics","port":9090,"targetPort":9091}]}});
        assert_eq!(proxy_port(&svc, 443), "8443");
        assert_eq!(proxy_port(&svc, 9090), "metrics");
        assert_eq!(proxy_port(&svc, 1), "1");
    }

    #[test]
    fn proxy_gateway_errors_mean_not_serving_but_any_backend_answer_means_serving() {
        for s in [502, 503, 504] {
            assert!(!proxied_backend_answered(s));
        }
        for s in [200, 400, 404, 405] {
            assert!(
                proxied_backend_answered(s),
                "a webhook server answers GET with 4xx; that still proves its TLS port is up"
            );
        }
    }

    #[tokio::test]
    async fn pass_one_failure_skips_pass_two_so_no_reference_is_patched() {
        let objs = app();
        let mut c = Fake {
            fail_create_kind: Some("Service"),
            ..Fake::default()
        };
        let r = run(&mut c, &plan_for(&objs), &objs).await.unwrap();
        assert_eq!(r.failures.len(), 1);
        assert!(
            r.pass2_skipped,
            "patching references while objects are missing would point them at nothing"
        );
        assert!(c.patches.borrow().is_empty());
        assert!(r.render().contains("pass 2 not run"));
    }

    #[tokio::test]
    async fn created_objects_carry_the_source_uid_marker() {
        let mut c = Fake::default();
        import(&mut c).await;
        assert_eq!(
            c.store.borrow()[&id("ConfigMap", Some("app"), "cm")]["metadata"]["annotations"]
                [SOURCE_UID_ANNOTATION],
            "old-cm",
            "the marker is how a re-run proves it created the object"
        );
    }

    #[tokio::test]
    async fn same_named_object_not_created_by_this_import_is_a_conflict_and_untouched() {
        let objs = app();
        let mut c = Fake::default();
        let foreign = json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"pv1","uid":"theirs"},
            "spec":{"claimRef":{"namespace":"other","name":"db","uid":"their-pvc"}}});
        c.store
            .borrow_mut()
            .insert(id("PersistentVolume", None, "pv1"), foreign.clone());
        let r = run(&mut c, &plan_for(&objs), &objs).await.unwrap();
        assert!(
            r.failures
                .iter()
                .any(|f| f.starts_with("PersistentVolume pv1")),
            "{:?}",
            r.failures
        );
        assert!(r.pass2_skipped);
        assert_eq!(
            c.store.borrow()[&id("PersistentVolume", None, "pv1")],
            foreign,
            "patching a stranger's PV claimRef can hand its data to the wrong claim"
        );
        assert!(c.patches.borrow().is_empty());
    }

    #[test]
    fn pv_whose_claimref_names_a_different_claim_is_never_patched() {
        let objs = app();
        let mut remap = Remap::default();
        remap.record(&objs[4], "new-pvc");
        let current = json!({"metadata":{"name":"pv1"},"spec":{"claimRef":{"namespace":"app","name":"other-claim","uid":"u"}}});
        let p = pass2(&objs[3], &current, &remap);
        assert!(p.patch.is_none());
        assert!(p.conflict.unwrap().contains("app/other-claim"));
    }

    #[test]
    fn owner_refs_merge_keeps_references_already_on_the_target_object() {
        let objs = app();
        let mut remap = Remap::default();
        remap.record(&objs[1], "new-b");
        let current = json!({"metadata":{"ownerReferences":[{"kind":"Deployment","name":"mine","uid":"theirs"}]}});
        let p = pass2(&objs[0], &current, &remap);
        let refs = p.patch.unwrap()["metadata"]["ownerReferences"].clone();
        assert_eq!(
            refs.as_array().unwrap().len(),
            2,
            "replacing the list drops the existing owner and lets the garbage collector delete the object"
        );
        assert_eq!(refs[0]["uid"], "theirs");
        assert_eq!(refs[1]["uid"], "new-b");
    }

    #[test]
    fn crd_is_ready_only_when_established_condition_is_true() {
        assert!(!crd_established(&json!({})));
        assert!(!crd_established(
            &json!({"status":{"conditions":[{"type":"Established","status":"False"}]}})
        ));
        assert!(crd_established(
            &json!({"status":{"conditions":[{"type":"NamesAccepted","status":"True"},{"type":"Established","status":"True"}]}})
        ));
    }
}
