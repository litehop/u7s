use std::hint::black_box;
use std::thread;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use u7s_apiserver::record_request_total;

/// Number of concurrent threads hammering the same label combo — matches the plan's stated
/// concern (sub-bead 2 will call this from every request, so N simultaneous requests for the
/// same resource/verb/code is the realistic worst case for contention, not N distinct series).
const CONCURRENT_THREADS: usize = 8;

/// Increments performed by each spawned thread per sample. A single increment per spawn would
/// measure OS thread-spawn/join cost, not counter contention (thread spawn is microseconds;
/// the increment itself is nanoseconds) — this amortizes spawn overhead down to a small
/// fraction of the measured time so the reported ns/op reflects the counter, not the OS.
const INCREMENTS_PER_THREAD: u64 = 100_000;

/// Steady-state cost of a single `apiserver_request_total` increment on one thread — the
/// baseline sub-bead 2's AuthLayer wiring will add to every non-exempt request. Measured here,
/// before any request-path call site exists, so that number is verified rather than assumed
/// (the postmortem's lesson: verify instrumentation exists on both sides of a comparison
/// before trusting it).
fn bench_single_threaded(c: &mut Criterion) {
    c.bench_function("record_request_total_single_threaded", |b| {
        b.iter(|| {
            record_request_total(
                black_box("get"),
                black_box("core"),
                black_box("v1"),
                black_box("pods"),
                black_box("namespace"),
                black_box("200"),
            );
        });
    });
}

/// The operator's core concern: does incrementing the SAME already-registered label combo
/// from multiple threads at once degrade versus the single-threaded case? `IntCounterVec`'s
/// increment path is documented (by source read) as a lock-free `AtomicU64::fetch_add` once a
/// series exists, guarded only by an unlimited-concurrent-reader `RwLock` for the lookup — this
/// bench empirically confirms that claim under real concurrent load rather than trusting the
/// source read alone. All `CONCURRENT_THREADS` threads increment the exact same
/// (verb, group, version, resource, scope, code) tuple every iteration, the worst case for
/// contention (per-thread-distinct labels would let each thread touch an independent series
/// instead of racing the same one).
fn bench_concurrent_same_label_combo(c: &mut Criterion) {
    // Prime the series once outside the timed loop so every sample measures steady-state
    // fetch_add contention, not the one-time write-lock cost of first-touch registration.
    record_request_total("get", "core", "v1", "pods", "namespace", "200");

    let elements_per_iter = CONCURRENT_THREADS as u64 * INCREMENTS_PER_THREAD;
    let mut group = c.benchmark_group("record_request_total_concurrent");
    group.throughput(Throughput::Elements(elements_per_iter));
    group.bench_function(
        format!(
            "{CONCURRENT_THREADS}_threads_x_{INCREMENTS_PER_THREAD}_increments_same_label_combo"
        ),
        |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    thread::scope(|s| {
                        for _ in 0..CONCURRENT_THREADS {
                            s.spawn(|| {
                                for _ in 0..INCREMENTS_PER_THREAD {
                                    record_request_total(
                                        black_box("get"),
                                        black_box("core"),
                                        black_box("v1"),
                                        black_box("pods"),
                                        black_box("namespace"),
                                        black_box("200"),
                                    );
                                }
                            });
                        }
                    });
                    total += start.elapsed();
                }
                total
            });
        },
    );
    group.finish();
}

criterion_group!(
    benches,
    bench_single_threaded,
    bench_concurrent_same_label_combo
);
criterion_main!(benches);
