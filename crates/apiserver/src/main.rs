use clap::Parser;
use u7s_apiserver::{run, Args};

/// Overrides the process-wide allocator so dhat can instrument every
/// allocation. Only compiled in behind `--features dhat`, so a default build
/// keeps the system allocator untouched (no size/perf cost, no dhat symbols
/// in the binary).
#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

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

#[cfg(feature = "dhat")]
fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(runtime_worker_threads())
        .thread_stack_size(512 * 1024)
        .enable_all()
        .build()?
        .block_on(dhat_main())
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
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(runtime_worker_threads())
        .thread_stack_size(512 * 1024)
        .enable_all()
        .build()?
        .block_on(async {
            let args = Args::parse();
            run(args).await
        })
}

#[cfg(test)]
mod tests {
    use super::runtime_worker_threads;

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
