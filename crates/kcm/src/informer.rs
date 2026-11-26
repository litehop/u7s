//! List+watch informer over the politeia hyper client.
//!
//! Lifecycle: paged LIST -> WATCH from the list's resourceVersion. A dropped
//! watch resumes from the last resourceVersion seen (events, bookmarks); only
//! HTTP 410 or an in-stream 410 ERROR (compaction, lagging consumer) forces a
//! relist. Every failure is retried with exponential backoff plus jitter.
//! A relist briefly holds the old and new maps at once.

use hyper::Method;
use politeia::HyperApiClient;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{
    collections::{hash_map::RandomState, HashMap},
    hash::{BuildHasher, Hasher},
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{watch, Notify};

pub trait Object: DeserializeOwned + Send + 'static {
    fn key(&self) -> String;
}

/// Key-only change notification (workqueue style); read the object from the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Applied(String),
    Deleted(String),
}

#[derive(Default, Debug)]
pub struct Stats {
    pub lists: AtomicU64,
    pub watches: AtomicU64,
    pub gone: AtomicU64,
    pub errors: AtomicU64,
    pub bookmarks: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    cur: Duration,
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration) -> Self {
        Backoff {
            initial,
            max,
            cur: initial,
        }
    }

    pub fn reset(&mut self) {
        self.cur = self.initial;
    }

    /// Next sleep: the current base plus up to 100% jitter, then double the base up to `max`.
    pub fn next_delay(&mut self) -> Duration {
        self.next_with(random_unit())
    }

    pub fn next_with(&mut self, unit: f64) -> Duration {
        let base = self.cur;
        self.cur = (self.cur * 2).min(self.max);
        base + base.mul_f64(unit.clamp(0.0, 1.0))
    }
}

fn random_unit() -> f64 {
    let n = RandomState::new().build_hasher().finish();
    (n >> 11) as f64 / (1u64 << 53) as f64
}

#[derive(Clone, Debug)]
pub struct Config {
    pub path: String,
    pub page_limit: u32,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
}

impl Config {
    pub fn new(path: impl Into<String>) -> Self {
        Config {
            path: path.into(),
            page_limit: 500,
            backoff_initial: Duration::from_millis(800),
            backoff_max: Duration::from_secs(30),
        }
    }
}

pub type Map<T> = HashMap<String, T>;

pub struct Informer<T> {
    store: Arc<Mutex<Map<T>>>,
    stats: Arc<Stats>,
    synced: watch::Receiver<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl<T: Object> Informer<T> {
    pub fn spawn(
        client: Arc<HyperApiClient>,
        cfg: Config,
        on_event: impl Fn(Event) + Send + Sync + 'static,
    ) -> Self {
        let store = Arc::new(Mutex::new(Map::new()));
        let stats = Arc::new(Stats::default());
        let (tx, synced) = watch::channel(false);
        let task = tokio::spawn(run(client, cfg, store.clone(), stats.clone(), tx, on_event));
        Informer {
            store,
            stats,
            synced,
            task,
        }
    }

    pub async fn wait_synced(&self) {
        let mut rx = self.synced.clone();
        let _ = rx.wait_for(|s| *s).await;
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn len(&self) -> usize {
        self.store.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn with<R>(&self, f: impl FnOnce(&Map<T>) -> R) -> R {
        f(&self.store.lock().unwrap())
    }
}

impl<T> Drop for Informer<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum End {
    Gone,
    Bad,
}

struct WatchState<'a, T, F> {
    rv: String,
    progressed: bool,
    end: Option<End>,
    store: &'a Mutex<Map<T>>,
    stats: &'a Stats,
    on_event: &'a F,
}

impl<T: Object, F: Fn(Event)> WatchState<'_, T, F> {
    fn handle(&mut self, mut ev: Value) {
        if self.end.is_some() {
            return;
        }
        let rv = ev["object"]["metadata"]["resourceVersion"]
            .as_str()
            .map(str::to_owned);
        let typ = ev["type"].as_str().unwrap_or("").to_owned();
        match typ.as_str() {
            typ @ ("ADDED" | "MODIFIED" | "DELETED") => {
                let Ok(o) = serde_json::from_value::<T>(ev["object"].take()) else {
                    tracing::warn!("undecodable {typ} event; relisting");
                    self.end = Some(End::Gone);
                    return;
                };
                let k = o.key();
                {
                    let mut s = self.store.lock().unwrap();
                    if typ == "DELETED" {
                        s.remove(&k);
                    } else {
                        s.insert(k.clone(), o);
                    }
                }
                (self.on_event)(if typ == "DELETED" {
                    Event::Deleted(k)
                } else {
                    Event::Applied(k)
                });
                self.advance(rv);
            }
            "BOOKMARK" => {
                self.stats.bookmarks.fetch_add(1, Relaxed);
                self.advance(rv);
            }
            "ERROR" => {
                self.end = Some(if ev["object"]["code"].as_u64() == Some(410) {
                    End::Gone
                } else {
                    End::Bad
                });
            }
            _ => {}
        }
    }

    fn advance(&mut self, rv: Option<String>) {
        if let Some(rv) = rv {
            self.rv = rv;
        }
        self.progressed = true;
    }
}

fn enc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

async fn list<T: Object>(
    client: &HyperApiClient,
    cfg: &Config,
) -> Result<(Map<T>, String), String> {
    let mut m = Map::new();
    let mut cont = String::new();
    loop {
        let url = if cont.is_empty() {
            format!("{}?limit={}", cfg.path, cfg.page_limit)
        } else {
            format!(
                "{}?limit={}&continue={}",
                cfg.path,
                cfg.page_limit,
                enc(&cont)
            )
        };
        let (st, body) = client
            .request(Method::GET, &url, None)
            .await
            .map_err(|e| format!("{e:#}"))?;
        if !st.is_success() {
            return Err(format!("list {}: HTTP {st}", cfg.path));
        }
        let (next, rv) = decode_page(&body, &mut m)?;
        drop(body);
        if next.is_empty() {
            return Ok((m, rv));
        }
        cont = next;
    }
}

/// Decodes one LIST page into `m`; returns (continue token, list resourceVersion).
pub fn decode_page<T: Object>(body: &str, m: &mut Map<T>) -> Result<(String, String), String> {
    let mut page: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    if let Some(items) = page["items"].as_array_mut() {
        for it in items {
            let o: T = serde_json::from_value(it.take()).map_err(|e| e.to_string())?;
            m.insert(o.key(), o);
        }
    }
    let s = |v: &Value| v.as_str().unwrap_or("").to_owned();
    Ok((
        s(&page["metadata"]["continue"]),
        s(&page["metadata"]["resourceVersion"]),
    ))
}

async fn run<T: Object>(
    client: Arc<HyperApiClient>,
    cfg: Config,
    store: Arc<Mutex<Map<T>>>,
    stats: Arc<Stats>,
    synced: watch::Sender<bool>,
    on_event: impl Fn(Event) + Send + Sync + 'static,
) {
    let mut backoff = Backoff::new(cfg.backoff_initial, cfg.backoff_max);
    let mut rv: Option<String> = None;
    loop {
        let from = match rv.take() {
            Some(r) => r,
            None => {
                stats.lists.fetch_add(1, Relaxed);
                match list::<T>(&client, &cfg).await {
                    Ok((new, r)) => {
                        let old = std::mem::replace(&mut *store.lock().unwrap(), new);
                        {
                            let s = store.lock().unwrap();
                            for k in old.keys().filter(|k| !s.contains_key(*k)) {
                                on_event(Event::Deleted(k.clone()));
                            }
                            for k in s.keys() {
                                on_event(Event::Applied(k.clone()));
                            }
                        }
                        synced.send_replace(true);
                        r
                    }
                    Err(e) => {
                        stats.errors.fetch_add(1, Relaxed);
                        tracing::warn!("list {} failed: {e}", cfg.path);
                        tokio::time::sleep(backoff.next_delay()).await;
                        continue;
                    }
                }
            }
        };

        stats.watches.fetch_add(1, Relaxed);
        let opened = std::time::Instant::now();
        let url = format!(
            "{}?watch=true&allowWatchBookmarks=true&resourceVersion={}",
            cfg.path,
            enc(&from)
        );
        let cancel = Notify::new();
        let mut st = WatchState {
            rv: from,
            progressed: false,
            end: None,
            store: &store,
            stats: &stats,
            on_event: &on_event,
        };
        let res = {
            let watch = client.watch_stream(&url, |ev| {
                st.handle(ev);
                if st.end.is_some() {
                    cancel.notify_one();
                }
            });
            tokio::select! {
                r = watch => r,
                () = cancel.notified() => Ok(()),
            }
        };

        let gone = match (&res, st.end) {
            (_, Some(End::Gone)) => true,
            (Err(e), _) => is_gone_error(e),
            _ => false,
        };
        let failed = res.is_err() || st.end.is_some();
        let delay = after_watch(&mut backoff, failed, st.progressed, opened.elapsed());
        if gone {
            stats.gone.fetch_add(1, Relaxed);
            rv = None;
        } else {
            rv = Some(st.rv);
        }
        if failed {
            stats.errors.fetch_add(1, Relaxed);
            tracing::warn!("watch {} ended: {res:?}; end={:?}", cfg.path, st.end);
        }
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
    }
}

/// A watch that ended cleanly after at least this long was healthy (the server
/// timed it out); anything shorter without progress is treated as a flapping
/// endpoint and backed off.
const HEALTHY_WATCH: Duration = Duration::from_secs(1);

/// Updates `backoff` after a watch ends and returns the delay before reconnecting, if any.
/// A quiet resource's watch is closed by the server timeout with no event or bookmark;
/// that must reconnect immediately without growing the delay.
fn after_watch(
    backoff: &mut Backoff,
    failed: bool,
    progressed: bool,
    lived: Duration,
) -> Option<Duration> {
    let healthy_close = !failed && lived >= HEALTHY_WATCH;
    if progressed || healthy_close {
        backoff.reset();
    }
    (failed || !(progressed || healthy_close)).then(|| backoff.next_delay())
}

/// politeia reports a non-2xx watch response as `watch returned HTTP <status>`.
pub fn is_gone_error(e: &impl std::fmt::Display) -> bool {
    format!("{e:#}").contains("HTTP 410")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narrow::NarrowPod;

    fn state<'a>(
        store: &'a Mutex<Map<NarrowPod>>,
        stats: &'a Stats,
        on_event: &'a impl Fn(Event),
    ) -> WatchState<'a, NarrowPod, impl Fn(Event)> {
        WatchState {
            rv: "10".into(),
            progressed: false,
            end: None,
            store,
            stats,
            on_event,
        }
    }

    fn pod(typ: &str, name: &str, rv: &str) -> Value {
        serde_json::json!({"type": typ, "object": {"metadata": {"name": name, "namespace": "d", "resourceVersion": rv}}})
    }

    #[test]
    fn bookmark_advances_rv_without_touching_store() {
        let (store, stats) = (Mutex::new(Map::new()), Stats::default());
        let cb = |_| panic!("bookmark must not notify controllers");
        let mut s = state(&store, &stats, &cb);
        s.handle(
            serde_json::json!({"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"99"}}}),
        );
        assert_eq!(
            s.rv, "99",
            "a quiet resource must still move the resume point forward"
        );
        assert!(s.progressed);
        assert!(store.lock().unwrap().is_empty());
        assert_eq!(stats.bookmarks.load(Relaxed), 1);
    }

    #[test]
    fn events_update_store_and_resume_point() {
        let (store, stats) = (Mutex::new(Map::new()), Stats::default());
        let seen = Mutex::new(vec![]);
        let cb = |e| seen.lock().unwrap().push(e);
        let mut s = state(&store, &stats, &cb);
        s.handle(pod("ADDED", "a", "11"));
        s.handle(pod("MODIFIED", "a", "12"));
        s.handle(pod("DELETED", "a", "13"));
        assert_eq!(
            s.rv, "13",
            "reconnect must resume after the last applied event"
        );
        assert!(store.lock().unwrap().is_empty());
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                Event::Applied("d/a".into()),
                Event::Applied("d/a".into()),
                Event::Deleted("d/a".into())
            ]
        );
    }

    #[test]
    fn error_410_forces_relist_and_ignores_trailing_events() {
        let (store, stats) = (Mutex::new(Map::new()), Stats::default());
        let cb = |_| {};
        let mut s = state(&store, &stats, &cb);
        s.handle(serde_json::json!({"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}));
        assert_eq!(
            s.end,
            Some(End::Gone),
            "an expired RV can never be resumed; only a relist recovers"
        );
        s.handle(pod("ADDED", "late", "50"));
        assert!(store.lock().unwrap().is_empty());
        assert_eq!(s.rv, "10");
    }

    #[test]
    fn non_410_error_keeps_resume_point() {
        let (store, stats) = (Mutex::new(Map::new()), Stats::default());
        let cb = |_| {};
        let mut s = state(&store, &stats, &cb);
        s.handle(serde_json::json!({"type":"ERROR","object":{"kind":"Status","code":500}}));
        assert_eq!(
            s.end,
            Some(End::Bad),
            "a transient server error must not trigger an expensive relist"
        );
    }

    #[test]
    fn backoff_doubles_caps_jitters_and_resets() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_millis(400));
        assert_eq!(b.next_with(0.0), Duration::from_millis(100));
        assert_eq!(b.next_with(0.0), Duration::from_millis(200));
        assert_eq!(b.next_with(0.0), Duration::from_millis(400));
        assert_eq!(
            b.next_with(0.0),
            Duration::from_millis(400),
            "cap bounds worst-case recovery delay"
        );
        assert_eq!(
            b.next_with(1.0),
            Duration::from_millis(800),
            "full jitter doubles the sleep"
        );
        b.reset();
        assert_eq!(b.next_with(0.5), Duration::from_millis(150));
        let j = Backoff::new(Duration::from_secs(1), Duration::from_secs(1)).next_delay();
        assert!(j >= Duration::from_secs(1) && j <= Duration::from_secs(2));
    }

    #[test]
    fn repeated_clean_timeouts_on_a_quiet_resource_never_grow_the_delay() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(30));
        for _ in 0..10 {
            assert_eq!(
                after_watch(&mut b, false, false, Duration::from_secs(300)),
                None,
                "a server-timed-out watch must re-watch immediately, as client-go does"
            );
        }
        assert_eq!(
            b.next_with(0.0),
            Duration::from_millis(100),
            "clean closes must not have inflated the backoff for the next real failure"
        );
    }

    #[test]
    fn instantly_closed_clean_watches_still_back_off() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(30));
        assert!(after_watch(&mut b, false, false, Duration::ZERO).is_some());
        let second = after_watch(&mut b, false, false, Duration::ZERO).unwrap();
        assert!(
            second >= Duration::from_millis(200),
            "a server that closes every watch at once must not be hammered in a tight loop"
        );
    }

    #[test]
    fn failure_after_progress_restarts_backoff_from_initial() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(30));
        b.next_with(0.0);
        b.next_with(0.0);
        let d = after_watch(&mut b, true, true, Duration::from_secs(5)).unwrap();
        assert!(d <= Duration::from_millis(200), "got {d:?}");
    }

    #[test]
    fn http_410_text_is_recognised_as_gone() {
        assert!(is_gone_error(&"watch returned HTTP 410 Gone"));
        assert!(!is_gone_error(
            &"watch returned HTTP 500 Internal Server Error"
        ));
    }

    #[test]
    fn continue_token_is_percent_encoded() {
        assert_eq!(enc("a=b/c+d"), "a%3Db%2Fc%2Bd");
    }
}
