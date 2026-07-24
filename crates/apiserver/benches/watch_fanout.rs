use std::hint::black_box;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;
use u7s_apiserver::handlers::watch::prepare_live_event;

/// A ConfigMap-shaped ADDED event body — the same parse+filter+default+serialize cost profile
/// as every other builtin-resource live watch event.
fn event_bytes() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "cm-shared",
            "namespace": "default",
            "resourceVersion": "42",
        },
        "data": { "key": "value" },
    }))
    .unwrap()
}

/// Cost of N watchers on the same resource each independently parsing, filtering, defaulting,
/// and re-serializing the identical event. This is what production actually does today for N
/// concurrently open watch streams: each is its own tokio task subscribed to the store's
/// broadcast channel, with no computation shared between tasks — `prepare_live_event` is
/// called once per watcher, not once per event, so this is the honest per-event fan-out cost
/// at the process level.
fn bench_recompute_per_watcher(c: &mut Criterion) {
    let raw = event_bytes();
    let mut group = c.benchmark_group("watch_fanout_recompute_per_watcher");
    for watchers in [5usize, 10, 20] {
        group.bench_with_input(BenchmarkId::from_parameter(watchers), &watchers, |b, &n| {
            b.iter(|| {
                for _ in 0..n {
                    black_box(prepare_live_event(
                        black_box(&raw),
                        "ADDED",
                        "",
                        "configmaps",
                        "v1",
                        "ConfigMap",
                        false,
                        "",
                        "",
                    ));
                }
            });
        });
    }
    group.finish();
}

/// Cost of preparing the event once and handing every watcher a `Bytes::clone` of the same
/// allocation (an `Arc` refcount bump, not a reparse). `prepare_live_event`'s doc contract
/// ("sharing the returned `Bytes` across callers... is safe") makes this the headroom
/// available IF a future cache shared one prepared event across the concurrently-open watch
/// streams that want the identical bytes (same api_version/kind/as_partial_object_metadata,
/// selector match) instead of each recomputing it — not what today's per-task wiring does on
/// its own, since nothing currently caches across the independent tokio tasks each open watch
/// stream runs as.
fn bench_prepare_once_share_bytes(c: &mut Criterion) {
    let raw = event_bytes();
    let mut group = c.benchmark_group("watch_fanout_prepare_once_share_bytes");
    for watchers in [5usize, 10, 20] {
        group.bench_with_input(BenchmarkId::from_parameter(watchers), &watchers, |b, &n| {
            b.iter(|| {
                let prepared: Bytes = prepare_live_event(
                    black_box(&raw),
                    "ADDED",
                    "",
                    "configmaps",
                    "v1",
                    "ConfigMap",
                    false,
                    "",
                    "",
                )
                .unwrap();
                for _ in 0..n {
                    black_box(prepared.clone());
                }
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_recompute_per_watcher,
    bench_prepare_once_share_bytes
);
criterion_main!(benches);
