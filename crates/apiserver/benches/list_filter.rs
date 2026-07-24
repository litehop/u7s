use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use serde_json::json;
use u7s_apiserver::handlers::generic::{apply_label_selector, LabelSelectorTerm};

/// A ConfigMap-shaped item with a small, realistic label set (3 keys) — the
/// shape whose `metadata` gets reparsed into an `ObjectMeta` on every item,
/// every call (generic.rs:355-356).
fn configmap_item(i: usize) -> serde_json::Value {
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": format!("cm-{i}"),
            "namespace": "default",
            "labels": {
                "app": "bench",
                "tier": "backend",
                "env": "prod",
            },
        },
        "data": {},
    })
}

fn items(n: usize) -> Vec<serde_json::Value> {
    (0..n).map(configmap_item).collect()
}

fn bench_apply_label_selector(c: &mut Criterion) {
    // Matches every item — the worst case for the redundant per-item
    // ObjectMeta reparse: a selector that excludes some items would let
    // those short-circuit out of the `terms.iter().all(...)` early, but a
    // full match means every item pays the full reparse cost.
    let terms = [LabelSelectorTerm::Equality {
        key: "app",
        value: "bench",
    }];
    let mut group = c.benchmark_group("apply_label_selector");
    for size in [100usize, 1000, 5000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || items(size),
                |list| apply_label_selector(black_box(list), black_box(&terms)),
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_apply_label_selector);
criterion_main!(benches);
