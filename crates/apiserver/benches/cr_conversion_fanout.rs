use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::{json, Value};
use tokio::runtime::Runtime;
use tokio::sync::Barrier;

/// Mirrors `u7s_apiserver::state::CrConversionCache`'s exact shape. That type (and the
/// `AppState` it lives on) is crate-private, so it cannot be named from this external
/// bench binary; this is a faithful stand-in (same key, same value type, same
/// `RwLock<HashMap>` backing) used only to measure the caching mechanism's effect on
/// wall-clock time under a slow webhook, not to duplicate its production logic.
type ConversionCacheKey = (String, String);

struct ConversionCache {
    inner: RwLock<HashMap<ConversionCacheKey, Arc<Value>>>,
}

impl ConversionCache {
    fn new() -> Self {
        ConversionCache {
            inner: RwLock::new(HashMap::new()),
        }
    }

    fn get(&self, key: &ConversionCacheKey) -> Option<Arc<Value>> {
        self.inner.read().unwrap().get(key).cloned()
    }

    fn insert(&self, key: ConversionCacheKey, value: Arc<Value>) {
        self.inner.write().unwrap().insert(key, value);
    }
}

/// A real conversion webhook call is dominated by network round-trip latency to a
/// service the apiserver doesn't control, not by CPU work — seconds of the JSON payload
/// itself, but milliseconds of TLS handshake/queueing/transit. `delay_ms` (5-20ms here)
/// stands in for that round trip; see `crates/apiserver/src/handlers/cr.rs`'s
/// `call_conversion_webhook`, the real function this models.
async fn simulated_webhook_call(source: &Value, target_api_version: &str, delay_ms: u64) -> Value {
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    let mut converted = source.clone();
    converted["apiVersion"] = json!(target_api_version);
    converted
}

fn source_object(rv: &str) -> Value {
    json!({
        "apiVersion": "example.io/v1",
        "kind": "Widget",
        "metadata": { "name": "w", "resourceVersion": rv },
        "spec": { "color": "blue" },
    })
}

/// Today's behavior (no `CrConversionCache`): each of N watchers/LIST requests observing
/// the identical write independently calls the conversion webhook — `convert_cr_list_items`
/// has no cache to check, so every caller pays the full round trip. Models N callers
/// arriving with enough separation to each be its own webhook call (the common case for
/// unrelated LIST requests, and for watchers whose async task scheduling doesn't let them
/// race the very first cache-population window — see the module doc for what this does
/// NOT model).
fn bench_without_cache(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("cr_conversion_fanout_without_cache");
    group.sample_size(10);
    group.measurement_time(Duration::from_millis(1500));
    group.warm_up_time(Duration::from_millis(300));
    for delay_ms in [5u64, 20u64] {
        for watchers in [1usize, 5, 10, 20] {
            let label = format!("{delay_ms}ms_delay/{watchers}_watchers");
            group.bench_with_input(
                BenchmarkId::from_parameter(label),
                &(delay_ms, watchers),
                |b, &(delay_ms, watchers)| {
                    b.iter(|| {
                        rt.block_on(async {
                            let source = source_object("5");
                            for _ in 0..watchers {
                                let converted = simulated_webhook_call(
                                    black_box(&source),
                                    "example.io/v2",
                                    delay_ms,
                                )
                                .await;
                                black_box(converted);
                            }
                        });
                    });
                },
            );
        }
    }
    group.finish();
}

/// This bead's fix: the first caller's conversion is cached under (source
/// resourceVersion, target apiVersion); every later caller observing the identical write
/// hits the cache instead of re-invoking the webhook — "one call amortized across N
/// watchers" (mayor-n8bkc). Models N successive callers, matching
/// `convert_cr_list_items`'s cache-check-before-webhook path.
///
/// NOT modeled: N callers racing the SAME cold key perfectly concurrently (a thundering
/// herd where every one of them misses before any insert lands) — that scenario gets zero
/// benefit from this cache and is exactly what a future single-flight-coalescing sub-bead
/// would address; this benchmark measures sub-bead 1's actual claimed win, not that one.
fn bench_with_cache(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("cr_conversion_fanout_with_cache");
    group.sample_size(10);
    group.measurement_time(Duration::from_millis(1500));
    group.warm_up_time(Duration::from_millis(300));
    for delay_ms in [5u64, 20u64] {
        for watchers in [1usize, 5, 10, 20] {
            let label = format!("{delay_ms}ms_delay/{watchers}_watchers");
            group.bench_with_input(
                BenchmarkId::from_parameter(label),
                &(delay_ms, watchers),
                |b, &(delay_ms, watchers)| {
                    b.iter(|| {
                        let cache = ConversionCache::new();
                        rt.block_on(async {
                            let source = source_object("5");
                            let key: ConversionCacheKey =
                                ("5".to_string(), "example.io/v2".to_string());
                            for _ in 0..watchers {
                                if let Some(cached) = cache.get(&key) {
                                    black_box((*cached).clone());
                                    continue;
                                }
                                let converted = simulated_webhook_call(
                                    black_box(&source),
                                    "example.io/v2",
                                    delay_ms,
                                )
                                .await;
                                cache.insert(key.clone(), Arc::new(converted.clone()));
                                black_box(converted);
                            }
                        });
                    });
                },
            );
        }
    }
    group.finish();
}

/// `bench_with_cache` models STAGGERED arrival: one caller populates the cache before the
/// next one checks it, which is realistic for a LIST request racing a slower watcher, but
/// says nothing about N callers who all observe the write at once. This group models the
/// opposite extreme — a THUNDERING HERD: N tokio tasks block on a `Barrier` and are
/// released together, so every one of them runs its `cache.get()` check before any of them
/// can possibly have finished the webhook call and inserted (the webhook is milliseconds;
/// the check-then-maybe-call sequence up to the first `.await` is not). This is the exact
/// scenario a single-flight-coalescing primitive (sub-bead 4 of the zw0ou EPIC) would
/// exist to fix, and this bench exists to tell us whether that scenario is pathological
/// enough in practice to justify building it.
///
/// Two metrics are reported per (delay, N) combination: wall-clock (via criterion's normal
/// timing) and the webhook call count (via a shared `AtomicUsize`, printed to stderr since
/// criterion has no native "count an external side effect" metric). The two can diverge:
/// `simulated_webhook_call`'s `tokio::time::sleep` is cheap to run N-in-parallel on tokio's
/// timer wheel, so wall-clock alone can look fine (close to one round trip) even when every
/// task independently missed the cache and called the mock webhook. The call count is what
/// actually reveals whether the herd stampeded through the miss path.
fn bench_thundering_herd(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("cr_conversion_fanout_thundering_herd");
    group.sample_size(10);
    group.measurement_time(Duration::from_millis(1500));
    group.warm_up_time(Duration::from_millis(300));
    for delay_ms in [5u64, 20u64] {
        for watchers in [1usize, 5, 10, 20, 50, 100] {
            let label = format!("{delay_ms}ms_delay/{watchers}_watchers");
            let rt = &rt;
            group.bench_with_input(
                BenchmarkId::from_parameter(label.clone()),
                &(delay_ms, watchers),
                move |b, &(delay_ms, watchers)| {
                    let total_calls = AtomicUsize::new(0);
                    let total_iters = AtomicUsize::new(0);
                    b.iter_custom(|iters| {
                        rt.block_on(async {
                            let mut elapsed = Duration::ZERO;
                            for _ in 0..iters {
                                let cache = Arc::new(ConversionCache::new());
                                let barrier = Arc::new(Barrier::new(watchers));
                                let call_count = Arc::new(AtomicUsize::new(0));
                                let key: ConversionCacheKey =
                                    ("5".to_string(), "example.io/v2".to_string());
                                let source = Arc::new(source_object("5"));

                                let mut handles = Vec::with_capacity(watchers);
                                for _ in 0..watchers {
                                    let cache = cache.clone();
                                    let barrier = barrier.clone();
                                    let call_count = call_count.clone();
                                    let key = key.clone();
                                    let source = source.clone();
                                    handles.push(tokio::spawn(async move {
                                        barrier.wait().await;
                                        if let Some(cached) = cache.get(&key) {
                                            black_box((*cached).clone());
                                            return;
                                        }
                                        call_count.fetch_add(1, Ordering::SeqCst);
                                        let converted = simulated_webhook_call(
                                            black_box(&source),
                                            "example.io/v2",
                                            delay_ms,
                                        )
                                        .await;
                                        cache.insert(key.clone(), Arc::new(converted.clone()));
                                        black_box(converted);
                                    }));
                                }

                                let start = Instant::now();
                                for handle in handles {
                                    handle.await.unwrap();
                                }
                                elapsed += start.elapsed();
                                total_calls
                                    .fetch_add(call_count.load(Ordering::SeqCst), Ordering::SeqCst);
                                total_iters.fetch_add(1, Ordering::SeqCst);
                            }
                            elapsed
                        })
                    });
                    let iters = total_iters.load(Ordering::SeqCst);
                    if iters > 0 {
                        let avg_calls = total_calls.load(Ordering::SeqCst) as f64 / iters as f64;
                        eprintln!(
                            "{label}: avg webhook_calls = {avg_calls:.2} (of {watchers} watchers) over {iters} sample iterations"
                        );
                    }
                },
            );
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_without_cache,
    bench_with_cache,
    bench_thundering_herd
);
criterion_main!(benches);
