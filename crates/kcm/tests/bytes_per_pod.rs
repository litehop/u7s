//! Heap cost of one cached Pod must stay within the KCM per-pod budget
//! (scripts/conformance/kcm-pod-bytes.txt): a 10k-pod cluster multiplies any
//! regression here straight into the 1 GiB control-plane memory target.
//!
//! Runs the informer's real LIST decode path over apiserver-shaped Pod JSON
//! and counts live allocator bytes. That is a lower bound of the Pss_Anon
//! figure the budget derives from (no socket buffers, allocator slack), so the
//! authoritative check remains the VM spike; this guards against regressions.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
};
use u7s_kcm::{
    informer::{decode_page, Map},
    narrow::NarrowPod,
};

struct Counting;
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

#[global_allocator]
static ALLOC: Counting = Counting;

fn budget() -> usize {
    include_str!("../../../scripts/conformance/kcm-pod-bytes.txt")
        .lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn pod(i: usize) -> serde_json::Value {
    let ns = format!("bench-{}", i % 10);
    let rs = format!("web-{}-{}", i % 10, i / 10 % 100);
    serde_json::json!({
        "metadata": {
            "name": format!("{rs}-{i:05}"), "namespace": ns,
            "uid": format!("0b8e3f5a-7d1c-4c55-9b0e-{i:012}"),
            "resourceVersion": (1000 + i).to_string(),
            "creationTimestamp": "2026-11-26T00:00:00Z",
            "labels": {"app": "web", "pod-template-hash": "5d8f7c9b6d"},
            "ownerReferences": [{
                "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": rs,
                "uid": format!("1c9e3f5a-7d1c-4c55-9b0e-{:012}", i / 10),
                "controller": true, "blockOwnerDeletion": true
            }],
            "managedFields": [{"manager": "kube-controller-manager", "operation": "Update",
                "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": {"f:metadata": {"f:labels": {}}}}]
        },
        "spec": {
            "nodeName": "bench-node",
            "containers": [
                {"name": "app", "image": "registry.k8s.io/pause:3.10",
                 "env": [{"name": "A", "value": "1"}, {"name": "B", "value": "2"}],
                 "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}}},
                {"name": "sidecar", "image": "registry.k8s.io/pause:3.10"}
            ],
            "volumes": [{"name": "scratch", "emptyDir": {}}]
        },
        "status": {"phase": "Running", "conditions": [
            {"type": "Initialized", "status": "True"}, {"type": "Ready", "status": "True"},
            {"type": "ContainersReady", "status": "True"}, {"type": "PodScheduled", "status": "True"}]}
    })
}

#[test]
fn cached_pod_fits_kcm_per_pod_budget() {
    const PODS: usize = 5000;
    let base = LIVE.load(Relaxed);
    let mut m: Map<NarrowPod> = Map::new();
    for page in 0..PODS / 500 {
        let items: Vec<_> = (page * 500..(page + 1) * 500).map(pod).collect();
        let body = serde_json::json!({"metadata": {"resourceVersion": "9999"}, "items": items})
            .to_string();
        decode_page(&body, &mut m).unwrap();
    }
    assert_eq!(m.len(), PODS);
    let per_pod = LIVE.load(Relaxed).saturating_sub(base) / PODS;
    eprintln!("BYTES_PER_POD live={per_pod} budget={}", budget());
    assert!(
        per_pod < budget(),
        "{per_pod} live bytes/pod exceeds the {} B/pod budget",
        budget()
    );
}
