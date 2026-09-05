use clap::Parser;
use u7s_apiserver::{run, Args};

/// Overrides the process-wide allocator so dhat can instrument every
/// allocation. Only compiled in behind `--features dhat`, so a default build
/// keeps the system allocator untouched (no size/perf cost, no dhat symbols
/// in the binary).
#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Bounds glibc's per-thread malloc-arena growth before any other thread
/// exists in the process.
///
/// The only `#[global_allocator]` in this binary is the `dhat` one above, and
/// that's compiled in only behind `--features dhat` -- a default build uses
/// the system allocator, which on the project's `x86_64-unknown-linux-gnu`
/// production target is glibc's ptmalloc2. Without a cap, ptmalloc2 lets
/// contending threads create up to `8 * ncores` independent arenas, and this
/// binary's tokio runtime alone puts dozens of threads in flight (worker
/// threads plus blocking-pool threads). Each extra arena keeps its own
/// free-list segments and rarely returns them to the OS (the interleaved
/// small-allocation lifetimes typical of serde_json tree construction
/// reliably prevent the top chunk from shrinking past `M_TRIM_THRESHOLD`),
/// so arena count becomes a standing RSS multiplier that never shrinks back
/// down. Capping it at `2` bounds that multiplier at the cost of some malloc
/// lock contention on the request path.
///
/// The env var `MALLOC_ARENA_MAX` looks like the obvious lever (it's what
/// glibc's own docs mention), but setting it from Rust is a no-op: ptmalloc
/// reads it exactly once, inside `ptmalloc_init`, which glibc runs during
/// the process's FIRST heap allocation -- itself triggered by Rust/std's own
/// startup machinery before `main` is ever called. By the time any statement
/// in `main` runs, `mp_.arena_max` is already cached and no later
/// `std::env::set_var` call can change it (measured directly: a process that
/// calls `set_var` as `main`'s first statement then contends 16 threads on
/// malloc still grows to 17 arenas, identical to not calling it at all).
/// `mallopt(M_ARENA_MAX, ...)` is the mechanism glibc actually honors at
/// runtime -- it writes `mp_.arena_max` directly and takes effect for every
/// secondary-arena creation from that point on (same 16-thread contention
/// test: capped at exactly 2). It must still run before any contending
/// thread exists, though: called after threads have already created
/// secondary arenas, it caps further growth but doesn't undo arenas already
/// created.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn bound_glibc_malloc_arenas() {
    // SAFETY: `mallopt` takes a plain `i32` and copies it into glibc's
    // internal state; it has no pointer/lifetime/aliasing requirements and
    // is documented as safe to call from any thread at any time (unlike the
    // `MALLOC_ARENA_MAX` env var it replaces, which would race with a
    // concurrent `getenv` from another thread).
    let ok = unsafe { libc::mallopt(libc::M_ARENA_MAX, 2) };
    assert_eq!(
        ok, 1,
        "mallopt(M_ARENA_MAX, 2) returned failure -- glibc rejected the arena \
         cap, so ptmalloc2 is free to grow one arena per contending thread"
    );
}

/// No-op on non-glibc-Linux targets: `libc::mallopt`/`M_ARENA_MAX` are glibc
/// (ptmalloc2) specifics with no equivalent on macOS's allocator or musl's
/// dlmalloc, and this binary's production target is
/// `x86_64-unknown-linux-gnu` (see the glibc-Linux version's doc comment).
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn bound_glibc_malloc_arenas() {}

/// Worker-thread count for the apiserver's tokio runtime.
///
/// `ai/prompts/api-server.md`'s "Tokio worker threads" section deliberately pins this
/// to `2` for the project's minimal-footprint target deployment ("1 shared vCPU"). That
/// floor is preserved here via `.max(2)` -- but the value was previously hardcoded to
/// exactly `2` on EVERY host the binary runs on, including the many-core machines used
/// for local dev and conformance testing, where it silently became a self-imposed
/// bottleneck rather than a footprint budget. Live-load evidence: under `--all-e2e`'s
/// sustained watch-stream + write volume, short-lived probes against an endpoint whose
/// own in-handler tracing showed it resolving in low double-digit milliseconds were
/// measured by the client taking hundreds of ms to over a second end-to-end, and in
/// production runs, minutes with zero apiserver.log trace at all -- classic queueing
/// delay upstream of the handler (accept/TLS-handshake/task-scheduling), not slow
/// request processing, caused by offered load exceeding a 2-thread runtime's total
/// capacity while idle host CPU cores sat unused. Scaling to the host's actual
/// parallelism (falling back to the documented floor only on a genuinely
/// single/few-core host, or if the OS can't report parallelism at all) fixes that
/// without abandoning the footprint-conscious floor for the target deployment.
fn runtime_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(2)
}

/// Cap on the tokio runtime's blocking-thread pool, replacing tokio's default
/// of 512.
///
/// Sqlite alone would only need 2: every store call is `spawn_blocking`, and
/// the sqlite connection mutex is acquired INSIDE that closure (see
/// sqlite.rs) -- there is exactly one read and one write connection, so at
/// most 2 blocking threads ever do useful sqlite work at a time. But sqlite
/// is not the only blocking-pool consumer: reqwest's default resolver
/// (hyper-util's `GaiResolver`, used by both `webhook_client` and
/// `kubelet_client` in state.rs) resolves every hostname-based outbound call
/// -- admission webhooks, the aggregation-API proxy, kubelet log/exec
/// proxying -- via `spawn_blocking`, not the async reactor. Those calls are
/// bounded by `MAX_INFLIGHT` (200, inflight.rs), the apiserver's real total
/// concurrency ceiling: in the worst case every one of those 200 in-flight
/// requests is simultaneously blocked resolving DNS. An earlier version of
/// this cap (`24`) accounted only for sqlite's 2 connections and starved
/// exactly that case -- outbound webhook/proxy/kubelet calls queue behind a
/// saturated blocking pool instead of running, and the resulting stall looks
/// like a hung backend rather than a resource cap. `202` is `MAX_INFLIGHT`
/// (200) plus sqlite's 2 connections -- the actual peak demand -- while
/// staying far below tokio's 512 default, so the RSS/thread-count win from
/// capping this at all is preserved without reintroducing DNS starvation.
const MAX_BLOCKING_THREADS: usize = 202;

// Compile-time guards, not `#[test]`s: a wrong value here defeats the whole
// point of the cap before any test even runs, so catch it at build time
// instead of relying on someone remembering to run the test suite.
const _: () = assert!(
    MAX_BLOCKING_THREADS >= 202,
    "MAX_BLOCKING_THREADS shrank back below MAX_INFLIGHT (200, inflight.rs) \
     + sqlite's 2 connections -- reqwest's GaiResolver runs DNS lookups for \
     every webhook/aggregation-proxy/kubelet-client call on this SAME \
     blocking pool, so a smaller cap starves outbound DNS under load even \
     though a DNS-free benchmark would show no regression"
);
const _: () = assert!(
    MAX_BLOCKING_THREADS < 512,
    "MAX_BLOCKING_THREADS grew back to (or past) tokio's unbounded 512 \
     default, eating back into the virtual-memory and thread-count budget \
     this cap exists to bound"
);

/// Builds the apiserver's tokio runtime with the footprint-bounding tunables
/// shared by both the `dhat` and default `main` entry points, so the two
/// binaries can't drift apart on `worker_threads`, `max_blocking_threads` or
/// stack size.
fn configure_runtime() -> tokio::runtime::Builder {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(runtime_worker_threads())
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .thread_stack_size(512 * 1024)
        .enable_all();
    builder
}

#[cfg(feature = "dhat")]
fn main() -> anyhow::Result<()> {
    bound_glibc_malloc_arenas();
    configure_runtime().build()?.block_on(dhat_main())
}

#[cfg(feature = "dhat")]
async fn dhat_main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Backtrace depth is env-var-driven (see scripts/conformance/run-all.sh's
    // --dhat-depth flag), defaulting to 10 -- dhat's own crate default. A
    // deeper depth attributes allocations in this codebase's async/serde call
    // chains more precisely (dhat's default otherwise collapses many of them
    // into an anonymous "depth-truncated" bucket), but isn't free: at depth
    // 50 a full-suite Conformance run measured +82% wall-clock and +318%
    // peak apiserver RSS versus un-profiled, almost entirely profiler
    // overhead rather than real allocation growth. Deep-stack profiling for
    // a focused investigation is therefore an operator opt-in via the env
    // var, not something every profiled run pays for by default.
    let depth = u7s_apiserver::resolve_dhat_backtrace_depth(
        std::env::var("U7S_DHAT_BACKTRACE_DEPTH").ok().as_deref(),
    );
    let mut profiler_builder = dhat::Profiler::builder().trim_backtraces(Some(depth));
    if let Ok(heap_file) = std::env::var("U7S_DHAT_HEAP_FILE") {
        profiler_builder = profiler_builder.file_name(heap_file);
    }
    let _profiler = profiler_builder.build();
    // dhat writes dhat-heap.json from the Profiler's Drop impl, which only
    // runs on a normal return from main. A bare SIGTERM (the usual way to
    // stop a backgrounded apiserver) terminates the process immediately and
    // never runs destructors, so race the server against an explicit SIGTERM
    // listener and return as soon as either one completes.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = run(args) => result,
        _ = sigterm.recv() => Ok(()),
    }
}

#[cfg(not(feature = "dhat"))]
fn main() -> anyhow::Result<()> {
    bound_glibc_malloc_arenas();
    configure_runtime().build()?.block_on(async {
        let args = Args::parse();
        run(args).await
    })
}

#[cfg(test)]
mod tests {
    use super::{configure_runtime, runtime_worker_threads, MAX_BLOCKING_THREADS};

    /// Guards against the apiserver reverting to an unbounded glibc process:
    /// without `M_ARENA_MAX` capped, ptmalloc2 can grow to `8 * ncores`
    /// independent arenas under this binary's many worker/blocking threads,
    /// and each extra arena is a standing RSS multiplier that rarely shrinks
    /// back down (see `bound_glibc_malloc_arenas`'s doc comment). This does
    /// not just assert the `mallopt` call was MADE (round 1's mistake --
    /// `std::env::set_var` would have passed this same style of assertion
    /// while doing nothing, since the env var is read too late to matter):
    /// it forces genuine multi-thread allocation contention and reads
    /// glibc's own `malloc_info` arena count back out, so a `mallopt` call
    /// that silently fails to take effect fails this test. Measured directly
    /// (16 contending threads, x86_64 Linux glibc): uncapped grows to 17
    /// arenas, capped stays at 2.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn bound_glibc_malloc_arenas_caps_actual_arena_count_under_thread_contention() {
        super::bound_glibc_malloc_arenas();

        // More contending threads than the cap, all allocating at once (a
        // barrier forces genuinely overlapping starts) -- without the cap
        // taking effect, ptmalloc2 hands each one its own arena.
        const N_THREADS: usize = 16;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N_THREADS));
        let handles: Vec<_> = (0..N_THREADS)
            .map(|_| {
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut chunks: Vec<Vec<u8>> = Vec::new();
                    for _ in 0..50_000 {
                        chunks.push(vec![0xAB; 64]);
                    }
                    std::hint::black_box(&chunks);
                })
            })
            .collect();
        for h in handles {
            h.join().expect("allocator-contention thread panicked");
        }

        let arenas = glibc_arena_count();
        assert!(
            arenas <= 2,
            "mallopt(M_ARENA_MAX, 2) did not bound ptmalloc2's real arena \
             count: glibc reported {arenas} arenas after {N_THREADS} threads \
             contended on malloc concurrently -- the cap this function exists \
             to enforce is not taking effect"
        );
    }

    /// Parses glibc's `malloc_info(3)` XML report (captured via
    /// `open_memstream` so no temp file is needed) and counts `<heap nr=...>`
    /// elements, each of which is one ptmalloc2 arena.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn glibc_arena_count() -> usize {
        let mut buf_ptr: *mut libc::c_char = std::ptr::null_mut();
        let mut buf_len: libc::size_t = 0;
        // SAFETY: `open_memstream` writes a valid `FILE*` and updates
        // `buf_ptr`/`buf_len` on flush/close; both out-params are live local
        // variables for the duration of the call.
        let stream = unsafe { libc::open_memstream(&mut buf_ptr, &mut buf_len) };
        assert!(!stream.is_null(), "open_memstream failed");
        // SAFETY: `stream` was just checked non-null and is a valid,
        // writable `FILE*` opened above.
        let rc = unsafe { libc::malloc_info(0, stream) };
        assert_eq!(rc, 0, "malloc_info failed");
        // SAFETY: closing flushes and finalizes `buf_ptr`/`buf_len` per
        // `open_memstream(3)`; `stream` is not used again afterward.
        unsafe {
            libc::fclose(stream);
        }
        // SAFETY: `fclose` above finalized `buf_ptr` as a valid buffer of
        // exactly `buf_len` initialized bytes, owned by this function until
        // freed below.
        let xml = unsafe { std::slice::from_raw_parts(buf_ptr as *const u8, buf_len) };
        let count = String::from_utf8_lossy(xml).matches("<heap nr=").count();
        // SAFETY: `buf_ptr` was allocated by `open_memstream` and is freed
        // exactly once here, after its last use above.
        unsafe {
            libc::free(buf_ptr as *mut libc::c_void);
        }
        count
    }

    /// Guards against tokio's default `max_blocking_threads` of 512 coming
    /// back, and against `configure_runtime()` drifting from the
    /// `MAX_BLOCKING_THREADS` constant it's supposed to apply. See that
    /// constant's doc comment for why `202` (not tokio's 512, and not an
    /// arbitrarily small number) is the right peak: sqlite's 2 connections
    /// plus every one of `MAX_INFLIGHT`'s 200 in-flight requests potentially
    /// blocked resolving DNS for an outbound webhook/proxy/kubelet call.
    #[test]
    fn configure_runtime_caps_blocking_pool_well_below_tokios_default_of_512() {
        let debug = format!("{:?}", configure_runtime());
        assert!(
            debug.contains(&format!("max_blocking_threads: {MAX_BLOCKING_THREADS}")),
            "configure_runtime() must actually apply MAX_BLOCKING_THREADS to the \
             tokio Builder, not just declare the constant -- got: {debug}"
        );
    }

    /// Guards against re-introducing the hardcoded `worker_threads = 2` cap this
    /// function replaced. That cap silently limited the ENTIRE apiserver -- TCP
    /// accept loop, TLS handshakes, and every request handler -- to 2 OS threads
    /// regardless of how many CPU cores the host actually has. Under sustained
    /// concurrent load (thousands of watch streams + real write volume), that
    /// starved new short-lived connections behind already-scheduled work for
    /// seconds to minutes even with idle host cores sitting unused: the same
    /// class of failure this test would have caught, since dev machines and CI
    /// runners alike have well over 2 logical CPUs.
    #[test]
    fn runtime_worker_threads_scales_with_host_cpus_not_hardcoded_to_two() {
        let available = std::thread::available_parallelism()
            .expect("host must report available parallelism")
            .get();
        // `.max(2)` preserves the documented footprint-conscious floor for the
        // project's target 1-shared-vCPU deployment (see `ai/prompts/api-server.md`)
        // -- only the "always exactly 2, no matter the host" behavior is the bug.
        let expected = available.max(2);
        assert_eq!(
            runtime_worker_threads(),
            expected,
            "apiserver's tokio runtime must use all {available} available host CPUs \
             (floored at 2 for the minimal-footprint target), not a fixed low cap that \
             starves the accept/TLS-handshake path under load on larger hosts"
        );
    }
}
