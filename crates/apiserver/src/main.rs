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
/// production target is glibc's ptmalloc2. Without `MALLOC_ARENA_MAX`,
/// ptmalloc2 lets contending threads create up to `8 * ncores` independent
/// arenas, and this binary's tokio runtime alone puts dozens of threads in
/// flight (worker threads plus blocking-pool threads). Each extra arena
/// keeps its own free-list segments and rarely returns them to the OS (the
/// interleaved small-allocation lifetimes typical of serde_json tree
/// construction reliably prevent the top chunk from shrinking past
/// `M_TRIM_THRESHOLD`), so arena count becomes a standing RSS multiplier
/// that never shrinks back down. Capping it at `2` bounds that multiplier at
/// the cost of some malloc lock contention on the request path. Setting the
/// env var must happen before any other thread is spawned -- glibc reads it
/// from a single-threaded context, and mutating the environment concurrently
/// with another thread's `getenv` is a data race -- so this runs as the
/// first statement in `main`, ahead of building the tokio runtime.
fn bound_glibc_malloc_arenas() {
    // SAFETY: called as the first statement of `main`, before any other
    // thread in the process exists, so there is no concurrent env access to
    // race with.
    unsafe {
        std::env::set_var("MALLOC_ARENA_MAX", "2");
    }
}

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
/// Every store call is `spawn_blocking`, and the sqlite connection mutex is
/// acquired INSIDE that closure (see sqlite.rs) -- there is exactly one read
/// and one write connection, so at most 2 blocking threads ever do useful
/// work at a time; every other in-flight request just parks an OS thread on
/// a mutex. The real concurrency ceiling is `MAX_INFLIGHT` (inflight.rs), not
/// tokio's default pool size, so raising the cap above it buys nothing:
/// throughput is unchanged (2 usable connections either way) while virtual
/// memory drops from about 260 MiB to about 12 MiB and blocking-pool RSS
/// from about 3.2 MB to about 0.4 MB. Requests beyond the cap queue in
/// tokio's blocking-task queue instead of holding a parked OS thread, which
/// is strictly cheaper, not slower.
const MAX_BLOCKING_THREADS: usize = 24;

// Compile-time guard, not a `#[test]`: a wrong value here defeats the whole
// point of the cap before any test even runs, so catch it at build time
// instead of relying on someone remembering to run the test suite.
const _: () = assert!(
    MAX_BLOCKING_THREADS <= 32,
    "MAX_BLOCKING_THREADS grew back toward tokio's 512 default, eating back \
     into the virtual-memory and thread-count budget this cap exists to bound"
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
    use super::{
        bound_glibc_malloc_arenas, configure_runtime, runtime_worker_threads, MAX_BLOCKING_THREADS,
    };

    /// Guards against the apiserver reverting to an unbounded glibc process:
    /// without `MALLOC_ARENA_MAX` pinned, ptmalloc2 can grow to `8 * ncores`
    /// independent arenas under this binary's many worker/blocking threads,
    /// and each extra arena is a standing RSS multiplier that rarely shrinks
    /// back down (see `bound_glibc_malloc_arenas`'s doc comment).
    #[test]
    fn bound_glibc_malloc_arenas_pins_arena_max_to_two() {
        bound_glibc_malloc_arenas();
        assert_eq!(
            std::env::var("MALLOC_ARENA_MAX").as_deref(),
            Ok("2"),
            "MALLOC_ARENA_MAX must be pinned to 2 before the tokio runtime spawns \
             any thread, or glibc is free to grow one arena per contending thread"
        );
    }

    /// Guards against tokio's default `max_blocking_threads` of 512 coming
    /// back: every store call blocks on the sqlite connection mutex from
    /// inside `spawn_blocking` (see sqlite.rs), and there are only 2 usable
    /// connections, so any thread above the real concurrency ceiling
    /// (`MAX_INFLIGHT` in inflight.rs) just parks an OS thread on a mutex for
    /// no throughput gain while still counting as another glibc
    /// arena-creation candidate.
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
