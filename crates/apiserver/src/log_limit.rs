//! Per-(kind, peer) rate limit for rejection log lines. Only logs are limited; the
//! counters that record every rejection are incremented by the callers unconditionally.
//!
//! Each (kind, peer) gets `BURST` lines per `WINDOW`; the rest are counted together with
//! the first few distinct details (user/target) of what was dropped, and one "suppressed N"
//! summary is emitted when the window rolls over, when the bucket is swept, or by the
//! periodic flush, so a burst that stops dead still reports its volume.
//!
//! IPv4 peers are keyed by full address, IPv6 peers by /64 (a single host routinely owns
//! a whole /64, so per-address keys would let one machine mint unlimited buckets). The
//! tracked-peer table is capped; once full, new peers share one overflow bucket per kind.
//! A spray can exhaust that bucket, so a never-seen peer rejected during a spray may go
//! unlogged for the window (its rejections are still counted and summarised); peers
//! already tracked are unaffected. Expired-entry sweeps run at most once per window so a
//! full table does not cost O(table) under the lock on every new-peer request.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

const BURST: u32 = 5;
const WINDOW: Duration = Duration::from_secs(10);
const MAX_TRACKED: usize = 4096;
const MAX_DETAILS: usize = 5;
const MAX_DETAIL_LEN: usize = 64;
const MAX_OVERFLOW_PEERS: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum PeerKey {
    None,
    V4(Ipv4Addr),
    V6Prefix64([u16; 4]),
    Overflow,
}

impl PeerKey {
    fn from_ip(ip: Option<IpAddr>) -> Self {
        match ip.map(|ip| ip.to_canonical()) {
            None => PeerKey::None,
            Some(IpAddr::V4(a)) => PeerKey::V4(a),
            Some(IpAddr::V6(a)) => {
                let s = a.segments();
                PeerKey::V6Prefix64([s[0], s[1], s[2], s[3]])
            }
        }
    }
}

type Key = (&'static str, PeerKey);

struct Bucket {
    window_start: Instant,
    logged: u32,
    suppressed: u64,
    details: Vec<(String, u64)>,
    overflow_peers: HashSet<PeerKey>,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            logged: 0,
            suppressed: 0,
            details: Vec::new(),
            overflow_peers: HashSet::new(),
        }
    }

    fn record_suppressed(&mut self, detail: &str) {
        self.suppressed += 1;
        if let Some(d) = self.details.iter_mut().find(|(d, _)| d == detail) {
            d.1 += 1;
        } else if self.details.len() < MAX_DETAILS {
            self.details.push((detail.to_owned(), 1));
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    kind: &'static str,
    peer: PeerKey,
    count: u64,
    details: Vec<(String, u64)>,
    overflow_peers: usize,
}

impl Summary {
    fn emit(&self, window: Duration) {
        let who = match self.peer {
            PeerKey::None => "unknown peer".to_owned(),
            PeerKey::V4(a) => a.to_string(),
            PeerKey::V6Prefix64([a, b, c, d]) => format!("{a:x}:{b:x}:{c:x}:{d:x}::/64"),
            PeerKey::Overflow => format!("{} peers (table full)", self.overflow_peers),
        };
        tracing::info!(
            "suppressed {} {} rejections from {who} in the last {}s; first distinct: {:?}",
            self.count,
            self.kind,
            window.as_secs(),
            self.details
        );
    }
}

fn take_summary(key: Key, b: &mut Bucket) -> Option<Summary> {
    (b.suppressed > 0).then(|| Summary {
        kind: key.0,
        peer: key.1,
        count: std::mem::take(&mut b.suppressed),
        details: std::mem::take(&mut b.details),
        overflow_peers: b.overflow_peers.len(),
    })
}

struct Inner {
    buckets: HashMap<Key, Bucket>,
    last_sweep: Option<Instant>,
    #[cfg(test)]
    sweeps: u64,
}

pub(crate) struct LogLimiter {
    burst: u32,
    window: Duration,
    max_tracked: usize,
    inner: Mutex<Inner>,
}

impl LogLimiter {
    fn new(burst: u32, window: Duration, max_tracked: usize) -> Self {
        Self {
            burst,
            window,
            max_tracked,
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                last_sweep: None,
                #[cfg(test)]
                sweeps: 0,
            }),
        }
    }

    /// Drops expired buckets, collecting summaries for those that suppressed lines.
    fn sweep(&self, inner: &mut Inner, now: Instant, out: &mut Vec<Summary>) {
        inner.last_sweep = Some(now);
        #[cfg(test)]
        {
            inner.sweeps += 1;
        }
        let window = self.window;
        inner.buckets.retain(|k, b| {
            if now.saturating_duration_since(b.window_start) < window {
                return true;
            }
            out.extend(take_summary(*k, b));
            false
        });
    }

    /// Whether to log this line, plus summaries the caller must emit (outside the lock).
    /// `detail` identifies what was rejected (user/target); it is kept, truncated, only
    /// for suppressed lines.
    fn check_at(
        &self,
        kind: &'static str,
        peer: Option<IpAddr>,
        detail: &str,
        now: Instant,
    ) -> (bool, Vec<Summary>) {
        let mut summaries = Vec::new();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let inner = &mut *guard;
        let peer = PeerKey::from_ip(peer);
        let mut key = (kind, peer);
        if !inner.buckets.contains_key(&key) && inner.buckets.len() >= self.max_tracked {
            let due = inner
                .last_sweep
                .is_none_or(|t| now.saturating_duration_since(t) >= self.window);
            if due {
                self.sweep(inner, now, &mut summaries);
            }
            if inner.buckets.len() >= self.max_tracked {
                key = (kind, PeerKey::Overflow);
            }
        }
        let b = inner.buckets.entry(key).or_insert_with(|| Bucket::new(now));
        if key.1 == PeerKey::Overflow && b.overflow_peers.len() < MAX_OVERFLOW_PEERS {
            b.overflow_peers.insert(peer);
        }
        let admit = if now.saturating_duration_since(b.window_start) >= self.window {
            summaries.extend(take_summary(key, b));
            b.window_start = now;
            b.logged = 1;
            b.overflow_peers.clear();
            if key.1 == PeerKey::Overflow {
                b.overflow_peers.insert(peer);
            }
            true
        } else if b.logged < self.burst {
            b.logged += 1;
            true
        } else {
            let detail: String = detail.chars().take(MAX_DETAIL_LEN).collect();
            b.record_suppressed(&detail);
            false
        };
        (admit, summaries)
    }

    /// Summaries for every expired bucket; driven by the periodic tick.
    fn flush_at(&self, now: Instant) -> Vec<Summary> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        self.sweep(&mut guard, now, &mut out);
        out
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.inner.lock().unwrap().buckets.len()
    }

    #[cfg(test)]
    fn sweeps(&self) -> u64 {
        self.inner.lock().unwrap().sweeps
    }
}

static LIMITER: LazyLock<LogLimiter> =
    LazyLock::new(|| LogLimiter::new(BURST, WINDOW, MAX_TRACKED));

/// True if the caller should emit its log line for this rejection. Emits any
/// "suppressed N" summaries the call made due.
pub(crate) fn admit(kind: &'static str, peer: Option<IpAddr>, detail: &str) -> bool {
    let (admit, summaries) = LIMITER.check_at(kind, peer, detail, Instant::now());
    for s in summaries {
        s.emit(WINDOW);
    }
    admit
}

/// Background tick so a burst that stops dead still gets its summary.
pub(crate) fn spawn_flush() {
    tokio::spawn(async {
        let mut tick = tokio::time::interval(WINDOW);
        loop {
            tick.tick().await;
            for s in LIMITER.flush_at(Instant::now()) {
                s.emit(WINDOW);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> Option<IpAddr> {
        Some(IpAddr::from([10, 0, 0, n]))
    }

    fn ip_n(n: u32) -> Option<IpAddr> {
        Some(IpAddr::from(n.to_be_bytes()))
    }

    fn logged(
        l: &LogLimiter,
        kind: &'static str,
        peer: Option<IpAddr>,
        n: usize,
        t: Instant,
    ) -> usize {
        (0..n).filter(|_| l.check_at(kind, peer, "x", t).0).count()
    }

    #[test]
    fn burst_from_one_peer_logs_at_most_burst_lines_then_one_summary_with_exact_count() {
        let l = LogLimiter::new(5, Duration::from_secs(10), 100);
        let t0 = Instant::now();
        assert_eq!(
            logged(&l, "authn_busy", ip(1), 1000, t0),
            5,
            "a scanner must not get more than BURST lines per window"
        );
        let (admit, s) = l.check_at("authn_busy", ip(1), "x", t0 + Duration::from_secs(10));
        assert!(admit);
        assert_eq!(
            s.iter().map(|s| s.count).collect::<Vec<_>>(),
            vec![995],
            "the summary must report every suppressed rejection so operators see the true volume"
        );
        let (_, s) = l.check_at("authn_busy", ip(1), "x", t0 + Duration::from_secs(10));
        assert!(
            s.is_empty(),
            "the summary is emitted once, not on every line"
        );
    }

    #[test]
    fn peers_and_kinds_are_limited_independently() {
        let l = LogLimiter::new(2, Duration::from_secs(10), 100);
        let t0 = Instant::now();
        assert_eq!(logged(&l, "forbidden", ip(1), 10, t0), 2);
        assert_eq!(
            logged(&l, "forbidden", ip(2), 10, t0),
            2,
            "a noisy peer must not silence another peer's rejections"
        );
        assert_eq!(
            logged(&l, "unauthorized", ip(1), 10, t0),
            2,
            "a flood of one kind must not hide a different kind from the same peer"
        );
    }

    #[test]
    fn ipv6_peers_in_one_slash_64_share_one_bucket() {
        let l = LogLimiter::new(2, Duration::from_secs(10), 100);
        let t0 = Instant::now();
        let base = 0x2001_0db8_0000_0001_0000_0000_0000_0000u128;
        let n = (0..10_000u128)
            .filter(|i| {
                l.check_at(
                    "forbidden",
                    Some(IpAddr::from((base + i).to_be_bytes())),
                    "x",
                    t0,
                )
                .0
            })
            .count();
        assert_eq!(
            n, 2,
            "one host rotating addresses in its /64 must not mint buckets"
        );
        assert_eq!(l.tracked(), 1);
    }

    #[test]
    fn ipv4_mapped_ipv6_is_the_same_peer_as_ipv4() {
        let l = LogLimiter::new(1, Duration::from_secs(10), 100);
        let t0 = Instant::now();
        assert!(l.check_at("forbidden", ip(1), "x", t0).0);
        let mapped = Some(IpAddr::from(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped()));
        assert!(!l.check_at("forbidden", mapped, "x", t0).0);
    }

    #[test]
    fn peer_table_stays_bounded_and_overflow_peers_share_a_limit() {
        let l = LogLimiter::new(2, Duration::from_secs(10), 8);
        let t0 = Instant::now();
        let n = (0..200u32)
            .filter(|i| l.check_at("forbidden", ip_n(0x0a00_0000 + i), "x", t0).0)
            .count();
        assert!(
            l.tracked() <= 9,
            "tracked peers must be capped, got {}",
            l.tracked()
        );
        assert!(
            n <= 8 * 2 + 2,
            "a spray across many IPs must hit the shared fallback limit, logged {n}"
        );
    }

    #[test]
    fn overflow_summary_names_peer_count_and_table_full() {
        let l = LogLimiter::new(1, Duration::from_secs(10), 2);
        let t0 = Instant::now();
        for i in 0..50 {
            l.check_at("forbidden", ip_n(0x0a00_0000 + i), "x", t0);
        }
        let s = l.flush_at(t0 + Duration::from_secs(11));
        let o = s
            .iter()
            .find(|s| s.peer == PeerKey::Overflow)
            .expect("overflow bucket summary");
        assert_eq!(o.overflow_peers, 48, "N in 'from N peers (table full)'");
        assert_eq!(o.count, 47);
    }

    #[test]
    fn expired_buckets_are_evicted_so_new_peers_get_their_own_slot() {
        let l = LogLimiter::new(1, Duration::from_secs(10), 2);
        let t0 = Instant::now();
        l.check_at("forbidden", ip(1), "x", t0);
        l.check_at("forbidden", ip(2), "x", t0);
        let later = t0 + Duration::from_secs(11);
        assert!(l.check_at("forbidden", ip(3), "x", later).0);
        assert!(l.tracked() <= 2);
    }

    #[test]
    fn full_table_sweeps_at_most_once_per_window_under_new_peer_spray() {
        let l = LogLimiter::new(1, Duration::from_secs(10), 4);
        let t0 = Instant::now();
        for i in 0..4 {
            l.check_at("forbidden", ip_n(0x0a00_0000 + i), "x", t0);
        }
        for i in 100..10_100 {
            l.check_at(
                "forbidden",
                ip_n(0x0a00_0000 + i),
                "x",
                t0 + Duration::from_secs(1),
            );
        }
        assert_eq!(
            l.sweeps(),
            1,
            "an O(table) retain under the global lock on every new-peer request is a DoS amplifier"
        );
        for i in 10_100..10_200 {
            l.check_at(
                "forbidden",
                ip_n(0x0a00_0000 + i),
                "x",
                t0 + Duration::from_secs(12),
            );
        }
        assert_eq!(l.sweeps(), 2, "the next window may sweep again");
    }

    #[test]
    fn spray_cannot_starve_tracked_peers_and_overflow_is_bounded_per_window() {
        let l = LogLimiter::new(2, Duration::from_secs(10), 4);
        let t0 = Instant::now();
        l.check_at("forbidden", ip(1), "x", t0);
        for i in 0..3 {
            l.check_at("forbidden", ip_n(0x0b00_0000 + i), "x", t0);
        }
        let sprayed = (0..1000u32)
            .filter(|i| l.check_at("forbidden", ip_n(0x0c00_0000 + i), "x", t0).0)
            .count();
        assert_eq!(
            sprayed, 2,
            "all untracked peers together get BURST lines per window"
        );
        assert!(
            l.check_at("forbidden", ip(1), "x", t0).0,
            "a peer already tracked keeps its own budget during a spray"
        );
        let (admit, s) = l.check_at(
            "forbidden",
            ip_n(0x0d00_0001),
            "x",
            t0 + Duration::from_secs(11),
        );
        assert!(admit, "the overflow bucket recovers at the next window");
        assert_eq!(s[0].count, 998);
    }

    #[test]
    fn suppressed_details_keep_first_distinct_values_with_counts_bounded() {
        let l = LogLimiter::new(1, Duration::from_secs(10), 100);
        let t0 = Instant::now();
        l.check_at("forbidden", ip(1), "first", t0);
        for i in 0..100 {
            l.check_at("forbidden", ip(1), &format!("user{}", i % 20), t0);
        }
        let (_, s) = l.check_at("forbidden", ip(1), "x", t0 + Duration::from_secs(10));
        assert_eq!(s[0].count, 100);
        assert_eq!(
            s[0].details.len(),
            MAX_DETAILS,
            "detail list must stay bounded"
        );
        assert_eq!(s[0].details[0], ("user0".to_owned(), 5));
        let long = "a".repeat(1000);
        l.check_at("forbidden", ip(2), "x", t0);
        l.check_at("forbidden", ip(2), &long, t0);
        let s = l.flush_at(t0 + Duration::from_secs(10));
        let s = s
            .iter()
            .find(|s| s.peer == PeerKey::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .unwrap();
        assert_eq!(s.details[0].0.len(), MAX_DETAIL_LEN);
    }

    #[test]
    fn flush_reports_a_burst_that_stopped_dead_without_further_requests() {
        let l = LogLimiter::new(2, Duration::from_secs(10), 100);
        let t0 = Instant::now();
        for _ in 0..50 {
            l.check_at("authn_busy", ip(1), "x", t0);
        }
        assert!(
            l.flush_at(t0 + Duration::from_secs(5)).is_empty(),
            "window not over yet"
        );
        let s = l.flush_at(t0 + Duration::from_secs(10));
        assert_eq!(s.len(), 1);
        assert_eq!(
            s[0].count, 48,
            "a burst that stops must still report its volume"
        );
        assert!(
            l.flush_at(t0 + Duration::from_secs(20)).is_empty(),
            "reported once"
        );
        assert_eq!(l.tracked(), 0, "flushed buckets are dropped");
    }

    #[test]
    fn eviction_sweep_emits_summaries_instead_of_losing_them() {
        let l = LogLimiter::new(1, Duration::from_secs(10), 2);
        let t0 = Instant::now();
        for _ in 0..10 {
            l.check_at("forbidden", ip(1), "x", t0);
        }
        l.check_at("forbidden", ip(2), "x", t0);
        let (_, s) = l.check_at("forbidden", ip(3), "x", t0 + Duration::from_secs(11));
        assert_eq!(s.iter().map(|s| s.count).collect::<Vec<_>>(), vec![9]);
    }
}
