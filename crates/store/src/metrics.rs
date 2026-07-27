use std::sync::LazyLock;

use prometheus::{IntCounterVec, Opts};

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
}
