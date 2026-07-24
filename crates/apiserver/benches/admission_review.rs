use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;
use u7s_apiserver::{build_review, AdmissionContext};

/// A ~10 KB ConfigMap-shaped object — representative of the objects a
/// MutatingWebhookConfiguration/ValidatingWebhookConfiguration chain reviews on a
/// typical admitted write (Secrets and CRDs can run much larger; small conformance
/// objects run much smaller).
fn configmap_object() -> serde_json::Value {
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "bench-cm",
            "namespace": "default",
            "resourceVersion": "42",
        },
        "data": {
            "payload": "x".repeat(10_000),
        },
    })
}

fn admission_context() -> AdmissionContext<'static> {
    AdmissionContext {
        group: "",
        version: "v1",
        resource: "configmaps",
        name: "bench-cm",
        namespace: Some("default"),
        operation: "UPDATE",
        user_info: None,
        dry_run: false,
    }
}

/// Cost of N configured webhooks on one admitted write before object/oldObject were
/// `Arc<Value>`: every call deep-cloned the object and oldObject into its own
/// AdmissionRequest before serializing. Reproduced here (rather than via a checked-out
/// pre-fix commit) by re-deriving a fresh Arc from a deep clone on every iteration —
/// the exact cost `build_review` paid when its `object`/`old_object` parameters were
/// plain `serde_json::Value`.
fn bench_deep_clone_per_webhook(c: &mut Criterion) {
    let object = configmap_object();
    let old_object = configmap_object();
    let ctx = admission_context();
    let mut group = c.benchmark_group("admission_review_deep_clone_per_webhook");
    for webhooks in [3usize, 5, 10] {
        group.bench_with_input(BenchmarkId::from_parameter(webhooks), &webhooks, |b, &n| {
            b.iter(|| {
                for i in 0..n {
                    let object_arc = Arc::new(object.clone());
                    let old_object_arc = Arc::new(old_object.clone());
                    let uid = format!("uid-{i}");
                    let review = build_review(&uid, &ctx, &object_arc, Some(&old_object_arc));
                    black_box(serde_json::to_vec(&review).unwrap());
                }
            });
        });
    }
    group.finish();
}

/// Cost of the same N webhook calls after the fix: object/oldObject are wrapped in an
/// Arc once outside the loop (as `run_mutating_webhooks`/`run_validating_webhooks` do),
/// so each `build_review` call only bumps a refcount instead of deep-cloning the JSON
/// tree it was just handed.
fn bench_share_via_arc(c: &mut Criterion) {
    let object = Arc::new(configmap_object());
    let old_object = Arc::new(configmap_object());
    let ctx = admission_context();
    let mut group = c.benchmark_group("admission_review_share_via_arc");
    for webhooks in [3usize, 5, 10] {
        group.bench_with_input(BenchmarkId::from_parameter(webhooks), &webhooks, |b, &n| {
            b.iter(|| {
                for i in 0..n {
                    let uid = format!("uid-{i}");
                    let review = build_review(&uid, &ctx, &object, Some(&old_object));
                    black_box(serde_json::to_vec(&review).unwrap());
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_deep_clone_per_webhook, bench_share_via_arc);
criterion_main!(benches);
