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
/// This crate can only observe one closure reason directly: `store_closed`, when the shared
/// broadcast sender is torn down (store shutdown) and every subscriber gets
/// `RecvError::Closed`. The apiserver crate increments the same counter for the reasons it
/// alone can see (`timeout`, `compacted`, `client_limit_exceeded`) — both crates share this
/// definition so `u7s_watch_closed_total` is one metric with all reasons, not two.
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

/// Pre-populate `u7s_watch_closed_total` with all four known `reason` values at zero.
///
/// `reason` is a small, fixed set (unlike `u7s_watch_broadcast_lagged_total`'s open-ended
/// `prefix`, which cannot be usefully pre-populated), so doing this is both possible and
/// correct Prometheus practice: without it, a freshly started process that hasn't yet had a
/// watch close for a given reason would omit that series entirely, which looks identical to
/// "this metric doesn't exist" to a scraper or alerting rule — indistinguishable from zero.
pub fn prime_watch_closed_total() {
    for reason in [
        "timeout",
        "compacted",
        "store_closed",
        "client_limit_exceeded",
    ] {
        WATCH_CLOSED_TOTAL.with_label_values(&[reason]).inc_by(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without priming, a Prometheus CounterVec with zero children is indistinguishable from
    /// an unregistered metric in gathered output — this test fails on revert because it checks
    /// the *gathered* metric family, not just that `WATCH_CLOSED_TOTAL` compiles and has four
    /// label values reachable via `with_label_values`.
    #[test]
    fn prime_watch_closed_total_makes_all_four_reasons_visible_in_gather() {
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

        for reason in [
            "timeout",
            "compacted",
            "store_closed",
            "client_limit_exceeded",
        ] {
            assert!(
                seen_reasons.contains(reason),
                "priming must pre-populate reason={reason} at zero so it is visible before the \
                 first watch ever closes for that reason; seen reasons: {seen_reasons:?}"
            );
        }
    }
}
