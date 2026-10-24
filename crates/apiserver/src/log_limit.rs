//! Per-(kind, peer IP) rate limit for rejection log lines. Only logs are limited; the
//! counters that record every rejection are incremented by the callers unconditionally.
//!
//! Each (kind, peer) gets `BURST` lines per `WINDOW`; the rest are counted, and the first
//! line of the next window is preceded by one "suppressed N" summary. The tracked-peer
//! table is capped; once full, unknown peers (and requests without a peer address) share
//! one bucket per kind, so a spray from many source IPs cannot grow memory or bypass the
//! limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

const BURST: u32 = 5;
const WINDOW: Duration = Duration::from_secs(10);
const MAX_TRACKED: usize = 4096;

type Key = (&'static str, Option<IpAddr>);

struct Bucket {
    window_start: Instant,
    logged: u32,
    suppressed: u64,
}

pub(crate) struct LogLimiter {
    burst: u32,
    window: Duration,
    max_tracked: usize,
    buckets: Mutex<HashMap<Key, Bucket>>,
}

impl LogLimiter {
    fn new(burst: u32, window: Duration, max_tracked: usize) -> Self {
        Self {
            burst,
            window,
            max_tracked,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// `None`: suppress this line. `Some(n)`: log it, after a summary if `n > 0` lines
    /// were suppressed in the previous window.
    fn check_at(&self, kind: &'static str, peer: Option<IpAddr>, now: Instant) -> Option<u64> {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = (kind, peer);
        if !buckets.contains_key(&key) && buckets.len() >= self.max_tracked {
            let window = self.window;
            buckets.retain(|_, b| now.saturating_duration_since(b.window_start) < window);
            if buckets.len() >= self.max_tracked {
                key = (kind, None);
            }
        }
        let b = buckets.entry(key).or_insert(Bucket {
            window_start: now,
            logged: 0,
            suppressed: 0,
        });
        if now.saturating_duration_since(b.window_start) >= self.window {
            let carried = std::mem::take(&mut b.suppressed);
            b.window_start = now;
            b.logged = 1;
            return Some(carried);
        }
        if b.logged < self.burst {
            b.logged += 1;
            return Some(0);
        }
        b.suppressed += 1;
        None
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

static LIMITER: LazyLock<LogLimiter> =
    LazyLock::new(|| LogLimiter::new(BURST, WINDOW, MAX_TRACKED));

/// True if the caller should emit its log line for this rejection. Emits the
/// "suppressed N" summary itself when a window that dropped lines rolls over.
pub(crate) fn admit(kind: &'static str, peer: Option<IpAddr>) -> bool {
    match LIMITER.check_at(kind, peer, Instant::now()) {
        None => false,
        Some(0) => true,
        Some(n) => {
            tracing::info!(
                "suppressed {n} {kind} rejections from {} in the last {}s",
                peer.map_or_else(|| "unknown peer".to_owned(), |p| p.to_string()),
                WINDOW.as_secs()
            );
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> Option<IpAddr> {
        Some(IpAddr::from([10, 0, 0, n]))
    }

    #[test]
    fn burst_from_one_peer_logs_at_most_burst_lines_then_one_summary_with_exact_count() {
        let l = LogLimiter::new(5, Duration::from_secs(10), 100);
        let t0 = Instant::now();
        let logged = (0..1000)
            .filter(|_| l.check_at("authn_busy", ip(1), t0).is_some())
            .count();
        assert_eq!(
            logged, 5,
            "a scanner must not get more than BURST lines per window"
        );
        assert_eq!(
            l.check_at("authn_busy", ip(1), t0 + Duration::from_secs(10)),
            Some(995),
            "the summary must report every suppressed rejection so operators see the true volume"
        );
        assert_eq!(
            l.check_at("authn_busy", ip(1), t0 + Duration::from_secs(10)),
            Some(0),
            "the summary is emitted once, not on every line"
        );
    }

    #[test]
    fn peers_and_kinds_are_limited_independently() {
        let l = LogLimiter::new(2, Duration::from_secs(10), 100);
        let t0 = Instant::now();
        for _ in 0..10 {
            l.check_at("forbidden", ip(1), t0);
        }
        assert!(
            l.check_at("forbidden", ip(2), t0).is_some(),
            "a noisy peer must not silence another peer's rejections"
        );
        assert!(
            l.check_at("unauthorized", ip(1), t0).is_some(),
            "a flood of one kind must not hide a different kind from the same peer"
        );
    }

    #[test]
    fn peer_table_stays_bounded_and_overflow_peers_share_a_limit() {
        let l = LogLimiter::new(2, Duration::from_secs(10), 8);
        let t0 = Instant::now();
        let logged = (0..200u8)
            .filter(|i| l.check_at("forbidden", ip(*i), t0).is_some())
            .count();
        assert!(
            l.tracked() <= 9,
            "tracked peers must be capped, got {}",
            l.tracked()
        );
        assert!(
            logged <= 8 * 2 + 2,
            "a spray across many IPs must hit the shared fallback limit, logged {logged}"
        );
    }

    #[test]
    fn expired_buckets_are_evicted_so_new_peers_get_their_own_slot() {
        let l = LogLimiter::new(1, Duration::from_secs(10), 2);
        let t0 = Instant::now();
        l.check_at("forbidden", ip(1), t0);
        l.check_at("forbidden", ip(2), t0);
        let later = t0 + Duration::from_secs(11);
        assert_eq!(l.check_at("forbidden", ip(3), later), Some(0));
        assert!(l.tracked() <= 2);
    }
}
