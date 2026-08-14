use std::sync::LazyLock;

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts};

/// Total watch events dropped because a watcher fell behind the shared broadcast channel
/// (`tokio::sync::broadcast::error::RecvError::Lagged`), by store key prefix.
///
/// `Lagged(n)` tells us exactly how many events that specific watcher missed — this counter
/// sums those `n`s, so a non-zero rate is the literal "events that should have been delivered
/// but weren't" signal. Most lags are transiently recovered from the ring buffer (see
/// `watch`'s lag-recovery path); this counter fires regardless of whether recovery succeeds,
/// so it is the leading indicator that a watcher is too slow, even before recovery fails and
/// forces a client relist.
pub static WATCH_BROADCAST_LAGGED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "u7s_watch_broadcast_lagged_total",
            "Total number of watch events dropped because a watcher fell behind the shared \
             broadcast channel, by store key prefix.",
        ),
        &["prefix"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("u7s_watch_broadcast_lagged_total is registered exactly once per process");
    counter
});

/// Total watch streams closed, broken out by reason.
///
/// All three reasons (`timeout`, `compacted`, `client_limit_exceeded`) are observed and
/// incremented by the apiserver crate; this crate only defines and registers the metric so
/// both crates share one `u7s_watch_closed_total` series instead of two independently
/// registered ones. This crate does not increment it itself: a live watch stream's `Receiver`
/// always shares a channel with a `Sender` clone that stream holds for its own entire
/// lifetime (see `watch()`'s `RecvError::Closed` match arm), so a store shutting down can never
/// be observed as a distinct "closed" reason from in here.
pub static WATCH_CLOSED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "u7s_watch_closed_total",
            "Total number of watch streams closed, by reason.",
        ),
        &["reason"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("u7s_watch_closed_total is registered exactly once per process");
    counter
});

/// Pre-populate `u7s_watch_closed_total` with all three known `reason` values at zero.
///
/// `reason` is a small, fixed set (unlike `u7s_watch_broadcast_lagged_total`'s open-ended
/// `prefix`, which cannot be usefully pre-populated), so doing this is both possible and
/// correct Prometheus practice: without it, a freshly started process that hasn't yet had a
/// watch close for a given reason would omit that series entirely, which looks identical to
/// "this metric doesn't exist" to a scraper or alerting rule — indistinguishable from zero.
///
/// `store_closed` is deliberately not in this list: it would prime a label that can never be
/// incremented (see `WATCH_CLOSED_TOTAL`'s doc), which is worse than omitting it outright — an
/// operator would see a permanent zero and could mistake "this failure mode never happens" for
/// "this failure mode is being checked for and is fine," when in truth it's never checked at all.
pub fn prime_watch_closed_total() {
    for reason in ["timeout", "compacted", "client_limit_exceeded"] {
        WATCH_CLOSED_TOTAL.with_label_values(&[reason]).inc_by(0);
    }
}

/// Current length of each per-resource-type shard's watch replay ring buffer — the direct
/// answer to "how full is each shard's buffer during a run," needed to see whether a busy
/// resource type's shard is approaching `RING_CAPACITY` while a quiet one stays empty.
///
/// Labeled by shard (its resource-type root prefix, e.g. `/registry/pods/`) now that the ring
/// is sharded — previously a bare gauge, since a per-prefix breakdown of one global ring would
/// have been fake precision (only one series would ever populate).
pub static WATCH_RING_OCCUPANCY: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let gauge = IntGaugeVec::new(
        Opts::new(
            "u7s_watch_ring_occupancy",
            "Current number of events held in the watch replay ring buffer, by shard.",
        ),
        &["shard"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(gauge.clone()))
        .expect("u7s_watch_ring_occupancy is registered exactly once per process");
    gauge
});

/// 1..1024s exponential (factor 2, 11 buckets). Chosen from measurement, not guesswork: a
/// `RING_CAPACITY=512` production run polled every 30s reported span min=2s, p10=13s,
/// median=83s, max=511s — a 250x range — so these buckets bracket that with headroom on both
/// ends. Deliberately starts at 1s rather than 0s: every bucket boundary is an inclusive `<=`
/// upper bound, so a span of exactly 0 (see the metric's own doc) still falls inside the first
/// (`le="1"`) bucket rather than needing its own boundary.
fn watch_ring_span_seconds_buckets() -> Vec<f64> {
    prometheus::exponential_buckets(1.0, 2.0, 11).expect("static bucket definition is valid")
}

/// Wall-clock SPAN covered by the events a shard's ring retains at each push: that push's newest
/// retained event's push time minus the oldest's, observed into a histogram rather than held as
/// a single "current" gauge value.
///
/// READ THIS BEFORE INTERPRETING THE NUMBER. This is deliberately NOT "how long ago was the
/// oldest event." Both ends of the subtraction are push times, so while a shard is being
/// actively written, newest ~= now, and the span is also, in effect, the age of the oldest
/// retained event. A shard holding one event, or several pushed within the same second, observes
/// 0. That means "spans no measurable time," not "empty" — cross-check `u7s_watch_ring_occupancy`.
///
/// THIS IS A HISTOGRAM, NOT A GAUGE, BECAUSE THE DECISION-RELEVANT STATISTIC IS THE MINIMUM, AND
/// A POLLED GAUGE CANNOT SEE IT. An earlier gauge version of this metric was `.set()` on every
/// push and read by external Prometheus polling; measurement showed the true worst case lives in
/// windows as narrow as one push (~2s at RING_CAPACITY=512's write rate) between long stretches
/// where a hot shard's span sits far higher, so a 30s-cadence poller caught it on 3 of 51 samples
/// and, at RING_CAPACITY=1500, likely never caught it at all — reporting a reassuringly high
/// "minimum" that was actually an order of magnitude off, in the dangerous direction, for a
/// metric whose entire purpose is sizing `RING_CAPACITY` safely. Observing every push into a
/// histogram instead means the narrow low window is recorded permanently in the low buckets
/// regardless of when, or whether, anything ever polls — nothing for a sampler to miss. This
/// also gives percentiles (`histogram_quantile`) beyond the single number a gauge could ever
/// hold, for the same one-set-per-push instrumentation cost.
///
/// Span, not age-relative-to-now, is the quantity worth having: the ring is read exactly once,
/// at watch open, to bridge `from_revision -> now`, so what a reconnecting client needs is that
/// the ring still reaches back past where it left off. What costs correctness is a hot shard
/// whose span has shrunk below one list-and-reestablish round trip: the client relists,
/// re-watches, is expired again because the ring churned meanwhile, and never reaches a
/// streaming steady state — a relist loop rather than a graceful degradation. Occupancy alone
/// cannot see any of this: whether 9,670 retained events is 8 seconds or 8 minutes of cover
/// depends entirely on that shard's write rate.
///
/// Upstream kube-apiserver sizes its equivalent buffer against exactly this quantity: it holds
/// a 75s window (`DefaultEventFreshDuration`) and resizes the underlying capacity between 100
/// and 102,400 entries to keep that window constant as rate varies. This histogram is the
/// measurement that would let us do the same instead of guessing at a fixed `RING_CAPACITY`.
pub static WATCH_RING_SPAN_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "u7s_watch_ring_span_seconds",
            "Wall-clock span in seconds covered by the events retained in the watch replay ring \
             buffer at each push, by shard: newest retained event's push time minus the oldest's, \
             observed on every push. NOT the age of the oldest event relative to now. The low \
             buckets are the decision-relevant reading — they capture the worst-case (minimum) \
             replay cover this shard has ever produced, which a polled gauge cannot reliably see.",
        )
        .buckets(watch_ring_span_seconds_buckets()),
        &["shard"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(histogram.clone()))
        .expect("u7s_watch_ring_span_seconds is registered exactly once per process");
    histogram
});

/// Current length of each per-resource-type shard's deletion-tombstone log — same class of
/// blind spot as the ring buffer above (a capped structure whose length was previously only
/// ever logged on its own eviction path, at `debug!` level).
pub static DELETION_LOG_LEN: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let gauge = IntGaugeVec::new(
        Opts::new(
            "u7s_deletion_log_len",
            "Current number of tombstones held in the deletion log, by shard.",
        ),
        &["shard"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(gauge.clone()))
        .expect("u7s_deletion_log_len is registered exactly once per process");
    gauge
});

/// Total watch ring shards torn down by idle-GC after `RING_SHARD_IDLE_GRACE` — the direct
/// measure of the eviction pressure this lifecycle (create-on-first-watch, reclaim once every
/// watcher disconnects) actually produces. A near-zero rate on a long-running process with many
/// short-lived watches would say the grace period is too generous for the memory it is meant to
/// bound; a high rate paired with watch-reconnect complaints would say it is too short.
///
/// Labeled by `prefix_bucket`, not the shard's raw key — a shard's own key is already
/// resource-type-scoped (never per-object), but bucketing keeps this consistent with its
/// siblings (`u7s_watch_lag_recovery_duration_seconds`, `u7s_watch_replay_depth`) on one
/// dashboard without minting a namespace-scoped shard's full key as its own series.
pub static WATCH_RING_SHARD_EVICTIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "u7s_watch_ring_shard_evictions_total",
            "Total number of watch ring shards torn down after their idle grace period, by \
             coarse prefix bucket.",
        ),
        &["prefix_bucket"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("u7s_watch_ring_shard_evictions_total is registered exactly once per process");
    counter
});

/// 5us..82ms exponential (factor 2, 15 buckets). Brackets the measured O(ring) scan-cost range
/// (10.9us at 1k ring occupancy to 670.8us at 100k occupancy, per a throwaway microbenchmark)
/// with headroom on both ends for lock-contention cases worse than an isolated benchmark.
/// Shared with the apiserver crate's `apiserver_watch_open_duration_seconds` so the two
/// histograms — same underlying scan cost, different call sites — are directly comparable on
/// one dashboard.
fn watch_scan_duration_buckets() -> Vec<f64> {
    prometheus::exponential_buckets(5e-6, 2.0, 15).expect("static bucket definition is valid")
}

/// Time spent re-scanning the ring buffer to recover from a `RecvError::Lagged` watch event — the
/// literal signal for the hypothesized compounding mechanism: a filling ring makes each
/// Lagged-recovery scan more expensive, which blocks a tokio worker longer, which makes the next
/// watcher more likely to lag too.
///
/// Labeled by `prefix_bucket`, not the raw watch prefix — see `prefix_bucket`'s own doc for why.
pub static WATCH_LAG_RECOVERY_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "u7s_watch_lag_recovery_duration_seconds",
            "Time spent re-scanning the ring buffer to recover from a watch broadcast Lagged \
             event, by coarse prefix bucket.",
        )
        .buckets(watch_scan_duration_buckets()),
        &["prefix_bucket"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(histogram.clone()))
        .expect("u7s_watch_lag_recovery_duration_seconds is registered exactly once per process");
    histogram
});

/// 1..25_000 explicit buckets. Resolution is deliberately densest from tens to low thousands,
/// which is where a `RING_CAPACITY` decision actually gets made, and the top bucket sits above
/// any capacity we would plausibly run so the overflow bucket stays a genuine anomaly signal
/// rather than a routine catch-all.
fn watch_replay_depth_buckets() -> Vec<f64> {
    vec![
        1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
        25000.0,
    ]
}

/// How many events each watch open had to replay from the ring to bridge
/// `from_revision -> now` — i.e. how far behind the client actually was when it (re)connected.
///
/// This is the REQUIREMENT side of ring sizing, and the only one measured from real client
/// behaviour rather than derived. `u7s_watch_ring_span_seconds` says how much history a shard
/// holds; this says how much history anyone actually asked for. Sizing follows directly:
/// `RING_CAPACITY >= p99.9(replay depth) x margin`.
///
/// CENSORING — READ BEFORE SIZING FROM THIS. The observation is bounded by what the ring can
/// still produce. Once a shard is evicting, a client that needed more than the ring holds is
/// recorded as whatever the ring did have (or gets `Compacted` and contributes nothing), so the
/// upper tail silently under-reports exactly where the decision is made. The distribution is
/// only complete at a capacity where the shard never fills — capture it there. Cross-check
/// `u7s_watch_ring_occupancy` against `RING_CAPACITY`, and `u7s_watch_closed_total{reason=
/// "compacted"}` against 0, before trusting a percentile from this.
///
/// Doubles as a watch-open latency signal: replay depth is what drives the O(shard-occupancy)
/// scan that mayor-nlkyd measured at 61x scaling from 1k to 100k.
///
/// Labeled by `prefix_bucket`, not the raw watch prefix — see `prefix_bucket`'s own doc for why.
pub static WATCH_REPLAY_DEPTH: LazyLock<HistogramVec> = LazyLock::new(|| {
    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "u7s_watch_replay_depth",
            "Number of ring-buffer events replayed to a watch at open, by coarse prefix bucket. \
             Measures how far behind clients actually are when they reconnect. Upper tail is \
             censored once the shard evicts — see the metric's source doc.",
        )
        .buckets(watch_replay_depth_buckets()),
        &["prefix_bucket"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(histogram.clone()))
        .expect("u7s_watch_replay_depth is registered exactly once per process");
    histogram
});

/// Collapse a watch key/prefix down to its first two `/`-delimited path segments (e.g.
/// `/registry/configmaps/default/name` -> `/registry/configmaps/`), to bound
/// `u7s_watch_lag_recovery_duration_seconds`'s cardinality by resource-type-ish grouping instead
/// of by every namespace a long conformance run ever creates.
///
/// Approximation, not exact resource identity: a non-core group whose plural is its own path
/// segment (e.g. `/registry/apps/deployments/...` vs. `/registry/apps/statefulsets/...`)
/// collapses both to `/registry/apps/`. Accepted for Phase 1 because the investigated pathology
/// (KCM's serviceaccount/token/root-ca controllers) is entirely core-group resources, which are
/// single-segment and bucket exactly. Threading the handler layer's exact `{group, plural}`
/// identity through here instead would require changing `Store::watch()`'s signature across
/// every impl for a metrics-only change — not worth it before it's known whether sharding is
/// actually needed.
pub fn prefix_bucket(prefix: &str) -> &str {
    let mut slashes = 0;
    for (idx, ch) in prefix.char_indices() {
        if ch == '/' {
            slashes += 1;
            if slashes == 3 {
                return &prefix[..=idx];
            }
        }
    }
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without priming, a Prometheus CounterVec with zero children is indistinguishable from
    /// an unregistered metric in gathered output — this test fails on revert because it checks
    /// the *gathered* metric family, not just that `WATCH_CLOSED_TOTAL` compiles and has three
    /// label values reachable via `with_label_values`.
    #[test]
    fn prime_watch_closed_total_makes_all_three_reasons_visible_in_gather() {
        prime_watch_closed_total();

        let families = prometheus::gather();
        let family = families
            .iter()
            .find(|f| f.name() == "u7s_watch_closed_total")
            .expect(
                "u7s_watch_closed_total must appear in gathered metric families after priming — \
                 otherwise a scraper sees no such metric at all on a freshly started process \
                 that has not yet closed a watch for any reason",
            );

        let seen_reasons: std::collections::HashSet<&str> = family
            .get_metric()
            .iter()
            .flat_map(|m| m.get_label())
            .filter(|l| l.name() == "reason")
            .map(|l| l.value())
            .collect();

        for reason in ["timeout", "compacted", "client_limit_exceeded"] {
            assert!(
                seen_reasons.contains(reason),
                "priming must pre-populate reason={reason} at zero so it is visible before the \
                 first watch ever closes for that reason; seen reasons: {seen_reasons:?}"
            );
        }

        // `store_closed` must stay un-primed: it is structurally unreachable (see
        // WATCH_CLOSED_TOTAL's doc), so priming it at zero would look to an operator like a
        // failure mode that is monitored and healthy, when it is actually never checked at all.
        assert!(
            !seen_reasons.contains("store_closed"),
            "store_closed must never be primed — it can never be incremented, so a zero for it \
             would misrepresent an unmonitored condition as a monitored-and-healthy one; seen \
             reasons: {seen_reasons:?}"
        );
    }

    /// An `IntGaugeVec` only shows a label's series in `prometheus::gather()` once that label
    /// has been set at least once — this test fails on revert (e.g. if `WATCH_RING_OCCUPANCY`'s
    /// `.set()` call site in `push_event_locked` were deleted, or if it stopped labeling by
    /// shard) because it asserts the *gathered* value for a specific shard label, not just that
    /// the static compiles and `.set()`/`.get()` round-trip in isolation. Without this wired up,
    /// an operator scraping a freshly started process could not tell "this shard's ring
    /// occupancy is zero" from "this metric was never registered for this shard."
    #[test]
    fn watch_ring_occupancy_reflects_the_value_it_was_set_to_in_gather() {
        WATCH_RING_OCCUPANCY
            .with_label_values(&["/registry/metrics-test-ring/"])
            .set(42);

        let families = prometheus::gather();
        let family = families
            .iter()
            .find(|f| f.name() == "u7s_watch_ring_occupancy")
            .expect("u7s_watch_ring_occupancy must appear in gathered metric families once set");
        let metric = family
            .get_metric()
            .iter()
            .find(|m| {
                m.get_label()
                    .iter()
                    .any(|l| l.name() == "shard" && l.value() == "/registry/metrics-test-ring/")
            })
            .expect("gathered output must carry a series for the shard label that was set");
        assert_eq!(
            metric.get_gauge().get_value(),
            42.0,
            "gathered value must match the last .set() call — a mismatch here means the \
             registered Collector is not the same instance push_event_locked is setting"
        );
    }

    /// Same reasoning as `watch_ring_occupancy_reflects_the_value_it_was_set_to_in_gather`,
    /// for the deletion-tombstone-log gauge.
    #[test]
    fn deletion_log_len_reflects_the_value_it_was_set_to_in_gather() {
        DELETION_LOG_LEN
            .with_label_values(&["/registry/metrics-test-deletion-log/"])
            .set(7);

        let families = prometheus::gather();
        let family = families
            .iter()
            .find(|f| f.name() == "u7s_deletion_log_len")
            .expect("u7s_deletion_log_len must appear in gathered metric families once set");
        let metric = family
            .get_metric()
            .iter()
            .find(|m| {
                m.get_label().iter().any(|l| {
                    l.name() == "shard" && l.value() == "/registry/metrics-test-deletion-log/"
                })
            })
            .expect("gathered output must carry a series for the shard label that was set");
        assert_eq!(
            metric.get_gauge().get_value(),
            7.0,
            "gathered value must match the last .set() call — a mismatch here means the \
             registered Collector is not the same instance push_event_locked is setting"
        );
    }

    /// A `HistogramVec` only shows a `prefix_bucket` series once that bucket has been observed
    /// at least once — this test fails on revert if the Lagged-recovery instrumentation stopped
    /// calling `.observe()`, which is exactly the scenario an operator needs to detect (a
    /// silently-broken smoking-gun metric looks identical to "no lag has ever occurred," the
    /// deliberately-desired absent state for buckets that truly never lagged).
    #[test]
    fn watch_lag_recovery_duration_seconds_records_an_observation_for_its_bucket_label() {
        let bucket = "/registry/metrics-test-lag-recovery/";
        WATCH_LAG_RECOVERY_DURATION_SECONDS
            .with_label_values(&[bucket])
            .observe(0.001);

        let families = prometheus::gather();
        let family = families
            .iter()
            .find(|f| f.name() == "u7s_watch_lag_recovery_duration_seconds")
            .expect(
                "u7s_watch_lag_recovery_duration_seconds must appear in gathered metric families \
                 once a bucket has been observed",
            );
        let has_bucket_label = family
            .get_metric()
            .iter()
            .flat_map(|m| m.get_label())
            .any(|l| l.name() == "prefix_bucket" && l.value() == bucket);
        assert!(
            has_bucket_label,
            "gathered output must carry a series labeled prefix_bucket={bucket:?} after \
             observing it — without this, a Lagged-recovery scan on that resource type would be \
             invisible to a scraper even though it happened"
        );
    }

    /// `prefix_bucket` must collapse a namespace-scoped watch prefix down to its resource-type
    /// root — this is the entire cardinality-bounding mechanism `u7s_watch_lag_recovery_
    /// duration_seconds` relies on. If this regressed to passing the raw prefix through
    /// unchanged, a long conformance run's thousands of ephemeral namespaces would each mint
    /// their own time series, exactly the unbounded-cardinality footgun this helper exists to
    /// avoid.
    #[test]
    fn prefix_bucket_collapses_to_first_two_path_segments() {
        assert_eq!(
            prefix_bucket("/registry/pods/namespace-x/name-y"),
            "/registry/pods/",
            "a namespace-scoped core-resource prefix must bucket to its resource-type root, \
             dropping the namespace and name segments that would otherwise explode cardinality"
        );
        assert_eq!(
            prefix_bucket("/registry/apps.v1.deployments/foo/bar"),
            "/registry/apps.v1.deployments/",
            "the second path segment is kept verbatim regardless of its own internal shape \
             (dots included) — bucketing only ever counts '/' delimiters, not group syntax"
        );
        assert_eq!(
            prefix_bucket(""),
            "",
            "an empty prefix has no path segments to collapse — must return unchanged rather \
             than panicking on out-of-bounds indexing"
        );
        assert_eq!(
            prefix_bucket("/registry/"),
            "/registry/",
            "a prefix with fewer than two path segments has nothing further to collapse — must \
             return unchanged rather than panicking when the third '/' never appears"
        );
    }
}
