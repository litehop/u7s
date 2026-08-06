use std::sync::LazyLock;

use prometheus::{
    HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
};

/// Identifies this apiserver in the `component` label of upstream-named metrics — mirrors
/// real kube-apiserver's `component="apiserver"` self-identification so a client scraping
/// both binaries can tell u7s's series apart from the scheduler's.
pub const COMPONENT: &str = "u7s";

/// Gauge of active long-running (streaming) apiserver requests, broken out by verb, group,
/// version, resource, subresource, scope and component — matches upstream
/// `apiserver_longrunning_requests` exactly. Today the only long-running verb this apiserver
/// brackets is `watch` (see `handlers::watch`); `subresource` is always empty since no watch
/// targets a subresource.
pub static LONGRUNNING_REQUESTS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let gauge = IntGaugeVec::new(
        Opts::new(
            "apiserver_longrunning_requests",
            "Gauge of all active long-running apiserver requests over unit of time broken out \
             by verb, group, version, resource, subresource, scope and component.",
        ),
        &[
            "verb",
            "group",
            "version",
            "resource",
            "subresource",
            "scope",
            "component",
        ],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(gauge.clone()))
        .expect("apiserver_longrunning_requests is registered exactly once per process");
    gauge
});

/// Counter of watch events actually written to a client's HTTP body, broken out by group,
/// version and resource — matches upstream `apiserver_watch_events_total`.
pub static WATCH_EVENTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "apiserver_watch_events_total",
            "Total number of watch events sent to watchers, broken out by group, version and \
             resource.",
        ),
        &["group", "version", "resource"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("apiserver_watch_events_total is registered exactly once per process");
    counter
});

/// Counter of apiserver requests, broken out by verb, group, version, resource, scope and
/// HTTP status code — matches upstream `apiserver_request_total`. Instrumented today at the
/// watch handler only (open attempts, 410 expiry, and the per-client 429 rejection); extending
/// this to every non-watch verb is tracked as a follow-on.
pub static REQUEST_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "apiserver_request_total",
            "Counter of apiserver requests broken out by verb, group, version, resource, \
             scope and HTTP status code.",
        ),
        &["verb", "group", "version", "resource", "scope", "code"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("apiserver_request_total is registered exactly once per process");
    counter
});

/// Compile-time-args-checked wrapper for REQUEST_TOTAL increments.
/// The 6-parameter signature prevents label-order drift and count-mismatch
/// panics if a future edit changes REQUEST_TOTAL's registered labels — the
/// helper must be updated in lockstep, forcing every call site to update too.
pub fn record_request_total(
    verb: &str,
    group: &str,
    version: &str,
    resource: &str,
    scope: &str,
    code: &str,
) {
    REQUEST_TOTAL
        .with_label_values(&[verb, group, version, resource, scope, code])
        .inc();
}

/// Snapshot of `Store::watch_receiver_count` — the number of watch streams currently open
/// across every resource type. Set at scrape time in `handlers::metrics::metrics` rather than
/// bookkept incrementally: `tokio::sync::broadcast::Sender::receiver_count` already tracks
/// this lock-free, so there is nothing to accumulate here.
pub static WATCH_BROADCAST_RECEIVERS: LazyLock<IntGauge> = LazyLock::new(|| {
    let gauge = IntGauge::new(
        "u7s_watch_broadcast_receivers",
        "Current number of active subscribers on the store's shared watch broadcast channel.",
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(gauge.clone()))
        .expect("u7s_watch_broadcast_receivers is registered exactly once per process");
    gauge
});

/// Time spent inside `Store::watch()`'s initial-connect call, labeled by the exact resource
/// identity (`group`, `resource`) already in scope at the call site via `WatchConfig`. This
/// call synchronously performs the ring-buffer replay scan before the returned stream is even
/// constructed, so timing the outer call captures that scan's real cost. Named without the
/// `u7s_` prefix, matching this file's other `apiserver_*` siblings (`apiserver_watch_events_total`
/// etc.): this measures a request-lifecycle event squarely in upstream's naming territory, even
/// though no literal upstream metric of this exact name exists.
pub static WATCH_OPEN_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "apiserver_watch_open_duration_seconds",
            "Time spent opening a watch stream (including the initial ring-buffer replay \
             scan), by group and resource.",
        )
        // 5us..82ms exponential (factor 2, 15 buckets) — brackets the measured O(ring) scan-cost
        // range (10.9us at 1k ring occupancy to 670.8us at 100k occupancy, per a throwaway
        // microbenchmark). Shared bucket shape with the store crate's sibling
        // u7s_watch_lag_recovery_duration_seconds so the two are directly comparable.
        .buckets(
            prometheus::exponential_buckets(5e-6, 2.0, 15)
                .expect("static bucket definition is valid"),
        ),
        &["group", "resource"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(histogram.clone()))
        .expect("apiserver_watch_open_duration_seconds is registered exactly once per process");
    histogram
});

/// Counter of SA JWT authentications accepted past their `kubernetes.io.warnafter` claim —
/// i.e. tokens that are only still valid because of the pod-bound-token expiration-extension
/// safety net (see `handlers::tokens::POD_BOUND_TOKEN_EXTENSION_SECS`), well past the window
/// the caller actually requested. A steady non-zero rate means real workloads are relying on
/// the extension rather than refreshing tokens on schedule — mirrors upstream Kubernetes'
/// stale-projected-token audit-annotation/metric pattern, which exists so operators can decide
/// whether the safety net is still needed before ever considering narrowing or removing it.
pub static STALE_SA_TOKENS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    let counter = IntCounter::new(
        "u7s_stale_sa_tokens_total",
        "Total number of SA JWT authentications accepted after the token's kubernetes.io.warnafter \
         timestamp has passed, indicating reliance on the pod-bound-token expiration extension.",
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("u7s_stale_sa_tokens_total is registered exactly once per process");
    counter
});

/// Counter of SA-JWT signature-verify cache hits — a hit means the RSA modexp
/// (`num_bigint_dig::biguint::monty::montgomery`, 4.4% apiserver self-time per the
/// 2026-08-06 samply triage) was skipped because this exact token's signature bytes were
/// already verified valid and the cached result hasn't reached the token's `exp` yet. See
/// `sa_sig_cache` module doc for the cache-key and TTL invariants.
pub static SA_SIG_CACHE_HITS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    let counter = IntCounter::new(
        "u7s_sa_sig_cache_hits_total",
        "Total number of SA JWT authentications that skipped RSA signature verification via \
         the signature-verify cache.",
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("u7s_sa_sig_cache_hits_total is registered exactly once per process");
    counter
});

/// Counter of SA-JWT signature-verify cache misses (new token, expired entry, or entry
/// evicted under load) — every miss falls through to a full RSA modexp. Compared against
/// `u7s_sa_sig_cache_hits_total`, a persistently low hit rate signals the cache cap
/// (`--sa-sig-cache-size` / `U7S_SA_SIG_CACHE_SIZE`) is too small for the deployment's
/// unique-token cardinality.
pub static SA_SIG_CACHE_MISSES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    let counter = IntCounter::new(
        "u7s_sa_sig_cache_misses_total",
        "Total number of SA JWT authentications that missed the signature-verify cache and \
         ran a full RSA signature verification.",
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("u7s_sa_sig_cache_misses_total is registered exactly once per process");
    counter
});

/// Current number of entries held in the SA-JWT signature-verify cache. Set on every insert
/// and eviction (`sa_sig_cache::SigCache::insert`) rather than derived at scrape time, since
/// the cache is behind a `std::sync::RwLock` shared across request-handling tasks.
pub static SA_SIG_CACHE_SIZE: LazyLock<IntGauge> = LazyLock::new(|| {
    let gauge = IntGauge::new(
        "u7s_sa_sig_cache_size",
        "Current number of entries in the SA JWT signature-verify cache.",
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(gauge.clone()))
        .expect("u7s_sa_sig_cache_size is registered exactly once per process");
    gauge
});

#[cfg(test)]
mod tests {
    use prometheus::core::Collector;
    use prometheus::{IntCounterVec, Opts};

    /// record_request_total's compile-time-checked signature only protects against label-order
    /// drift; it says nothing about whether the underlying IntCounterVec actually keeps series
    /// accounting proportional to the number of distinct label combos rather than, say,
    /// silently collapsing or exploding them. A THROWAWAY vector (never registered against any
    /// registry) is used here so this test can run any number of times without permanently
    /// growing the process-global `apiserver_request_total` series count across the test suite.
    #[test]
    fn record_request_total_cardinality_ceiling_is_bounded_and_proportional_to_label_combos() {
        let local_vec = IntCounterVec::new(
            Opts::new("test_request_total_local", "Test-only, do not use"),
            &["verb", "group", "version", "resource", "scope", "code"],
        )
        .expect("static metric definition is valid");

        for i in 0..500 {
            local_vec
                .with_label_values(&[
                    "get",
                    "core",
                    "v1",
                    &format!("resource-{i}"),
                    "namespace",
                    "200",
                ])
                .inc();
        }

        let series_count = local_vec.collect()[0].get_metric().len();
        assert_eq!(
            series_count, 500,
            "IntCounterVec should hold exactly N=500 series for N=500 unique label combos — \
             if this fails, the crate's series-count semantics have changed"
        );
    }
}
