use std::sync::LazyLock;

use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts};

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
