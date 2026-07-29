use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::{json, Value};
use tokio::runtime::Runtime;

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

criterion_group!(benches, bench_without_cache, bench_with_cache);
criterion_main!(benches);
