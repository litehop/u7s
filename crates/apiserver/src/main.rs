use clap::Parser;
use u7s_apiserver::{run, Args};

/// Overrides the process-wide allocator so dhat can instrument every
/// allocation. Only compiled in behind `--features dhat`, so a default build
/// keeps the system allocator untouched (no size/perf cost, no dhat symbols
/// in the binary).
#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(feature = "dhat")]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
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
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    run(args).await
}
