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

/// Wall-clock age of the OLDEST event still retained in each shard's ring buffer.
///
/// Occupancy (above) answers "how many events" but not "how much history," and history is the
/// property that actually matters: the ring is read once at watch open to bridge
/// `from_revision -> now`, so a watch survives iff the ring still covers the gap since the
/// client last saw an event. Whether 9,670 retained events is 8 seconds or 8 minutes of cover
/// depends entirely on that shard's write rate, and those two cases have completely different
/// risk. Below roughly one list-and-reestablish round trip, a client relists, re-watches, gets
/// expired again because the ring churned meanwhile, and never reaches a streaming steady
/// state — a relist loop rather than a graceful degradation.
///
/// Upstream kube-apiserver sizes its equivalent buffer against exactly this quantity: it holds
/// a 75s window (`DefaultEventFreshDuration`) and resizes the underlying capacity between 100
/// and 102,400 entries to keep that window constant as rate varies. This gauge is the
/// measurement that would let us do the same instead of guessing at a fixed `RING_CAPACITY`.
pub static WATCH_RING_OLDEST_AGE_SECONDS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let gauge = IntGaugeVec::new(
        Opts::new(
            "u7s_watch_ring_oldest_age_seconds",
            "Age in seconds of the oldest event retained in the watch replay ring buffer, by \
             shard. This is the watch-replay history window actually available to a \
             reconnecting client. 0 when the shard is empty.",
        ),
        &["shard"],
    )
    .expect("static metric definition is valid");
    prometheus::default_registry()
        .register(Box::new(gauge.clone()))
        .expect("u7s_watch_ring_oldest_age_seconds is registered exactly once per process");
    gauge
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
