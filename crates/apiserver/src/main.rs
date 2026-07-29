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
    // Defaults to "dhat-heap.json" in the process's CWD (dhat's own default)
    // unless overridden, so callers that need a stable, workdir-relative
    // location (e.g. scripts/conformance/run-all.sh --profile) can set it.
    let mut profiler_builder = dhat::Profiler::builder();
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
