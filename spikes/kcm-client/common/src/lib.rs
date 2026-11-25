use serde::Deserialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

pub struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() {
            LIVE.fetch_sub(l.size(), Relaxed);
            LIVE.fetch_add(n, Relaxed);
        }
        q
    }
}

pub fn live_bytes() -> usize {
    LIVE.load(Relaxed)
}

pub fn pss_anon_kb() -> u64 {
    std::fs::read_to_string("/proc/self/smaps_rollup")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Pss_Anon:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

pub struct Args {
    pub kubeconfig: String,
    pub server: Option<String>,
    pub settle: u64,
    pub events_wait: u64,
    pub trim: bool,
}

pub fn args() -> Args {
    let mut a = Args {
        kubeconfig: "kubeconfig".into(),
        server: None,
        settle: 20,
        events_wait: 45,
        trim: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let v = it.next().expect("value");
        match k.as_str() {
            "--kubeconfig" => a.kubeconfig = v,
            "--server" => a.server = Some(v),
            "--settle" => a.settle = v.parse().unwrap(),
            "--events-wait" => a.events_wait = v.parse().unwrap(),
            "--trim" => a.trim = v == "1",
            _ => panic!("unknown arg {k}"),
        }
    }
    a
}

pub struct Baseline {
    pss_kb: u64,
    live: usize,
}

impl Baseline {
    pub fn take() -> Self {
        Baseline {
            pss_kb: pss_anon_kb(),
            live: live_bytes(),
        }
    }
}

pub static APPLIES: AtomicU64 = AtomicU64::new(0);
pub static DELETES: AtomicU64 = AtomicU64::new(0);

pub fn note_event(name: &str, delete: bool) {
    if name.starts_with("evt-") {
        if delete { &DELETES } else { &APPLIES }.fetch_add(1, Relaxed);
    }
}

pub fn report(label: &str, base: &Baseline, pods: usize, rs: usize) {
    let pss = pss_anon_kb();
    let live = live_bytes();
    let dpss = (pss.saturating_sub(base.pss_kb)) * 1024;
    let dlive = live.saturating_sub(base.live);
    println!(
        "METRICS {label} pods={pods} rs={rs} pss_anon_kb={pss} base_pss_anon_kb={} pss_bytes_per_pod={} live_bytes_per_pod={}",
        base.pss_kb,
        dpss / pods.max(1) as u64,
        dlive / pods.max(1)
    );
}

pub fn report_events(label: &str, v1: Option<String>, v2: Option<String>, evt3_present: bool) {
    println!(
        "EVENTS {label} applies={} deletes={} evt1_v={:?} evt2_v={:?} evt3_present={evt3_present}",
        APPLIES.load(Relaxed),
        DELETES.load(Relaxed),
        v1,
        v2
    );
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerRef {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub controller: Option<bool>,
    pub block_owner_deletion: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub name: String,
    pub namespace: Option<String>,
    pub uid: Option<String>,
    pub resource_version: Option<String>,
    pub labels: Option<BTreeMap<String, String>>,
    pub owner_references: Option<Vec<OwnerRef>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Cond {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PodStatus {
    pub phase: Option<String>,
    pub conditions: Option<Vec<Cond>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NarrowPod {
    pub metadata: Meta,
    pub status: Option<PodStatus>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RsSpec {
    pub replicas: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NarrowRs {
    pub metadata: Meta,
    pub spec: Option<RsSpec>,
}

pub fn key(m: &Meta) -> String {
    format!("{}/{}", m.namespace.as_deref().unwrap_or(""), m.name)
}
