//! Fault injection against a real u7s-apiserver process. Every test ends by
//! asserting the informer cache equals the store's true state (keys and
//! resourceVersions), because a controller acting on a diverged cache is the
//! failure these mechanisms exist to prevent.

mod common;

use common::*;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};
use u7s_kcm::informer::{Config, Informer};

const CONVERGE: Duration = Duration::from_secs(30);

fn cfg() -> Config {
    let mut c = Config::new(CM_PATH);
    c.backoff_initial = Duration::from_millis(50);
    c.backoff_max = Duration::from_millis(400);
    c
}

async fn rig(name: &str) -> (Apiserver, Admin, Proxy) {
    let api = Apiserver::start(name).await;
    let admin = api.admin();
    let proxy = Proxy::start(api.port).await;
    (api, admin, proxy)
}

/// A dropped watch must resume from the last resourceVersion: writes made
/// while disconnected (including a delete) arrive as events, with no relist.
/// A relist-on-every-reconnect informer would hammer the apiserver at 10k pods.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_watch_resumes_from_rv_without_relist() {
    let (api, admin, proxy) = rig("drop").await;
    admin.create_cm("keep", 10).await;
    admin.create_cm("doomed", 10).await;
    let inf = Informer::<Cm>::spawn(api.client_via(proxy.port), cfg(), |_| {});
    inf.wait_synced().await;
    converge(&inf, &admin, CONVERGE).await;

    proxy.block(true);
    proxy.sever();
    admin.create_cm("born-offline", 10).await;
    admin.touch_cm("keep", "2").await;
    admin.delete_cm("doomed").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    proxy.block(false);

    converge(&inf, &admin, CONVERGE).await;
    assert_eq!(
        inf.stats().lists.load(Relaxed),
        1,
        "reconnect relisted instead of resuming from the last resourceVersion"
    );
}

/// A resume point older than the store's retained history (HTTP 410) must
/// trigger a full relist; resuming forever would leave the cache missing
/// every event in the gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_rv_410_relists_and_converges() {
    let (api, admin, proxy) = rig("gone").await;
    admin.create_cm("victim", 10).await;
    // Another watcher on the same resource (as other controllers are in a real
    // cluster) keeps the apiserver's retained history alive during the outage.
    let other = api.client_via(api.port);
    let other_watch = tokio::spawn(async move {
        let _ = other
            .watch_stream(&format!("{CM_PATH}?watch=true"), |_| {})
            .await;
    });
    let inf = Informer::<Cm>::spawn(api.client_via(proxy.port), cfg(), |_| {});
    inf.wait_synced().await;
    admin.create_cm("probe", 10).await;
    converge(&inf, &admin, CONVERGE).await;

    proxy.block(true);
    proxy.sever();
    for i in 0..700 {
        admin.create_cm(&format!("fill-{i}"), 10).await;
    }
    admin.delete_cm("victim").await;
    proxy.block(false);

    converge(&inf, &admin, CONVERGE).await;
    assert!(
        inf.stats().gone.load(Relaxed) >= 1 && inf.stats().lists.load(Relaxed) >= 2,
        "expected a 410 and a relist, got {:?}",
        inf.stats()
    );
    other_watch.abort();
}

/// After an apiserver restart the informer must reconnect on its own and see
/// writes made after the restart; a dead informer task would freeze the KCM's
/// view of the cluster until the process is restarted by hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apiserver_restart_converges() {
    let (mut api, admin, proxy) = rig("restart").await;
    admin.create_cm("before", 10).await;
    let inf = Informer::<Cm>::spawn(api.client_via(proxy.port), cfg(), |_| {});
    inf.wait_synced().await;
    converge(&inf, &admin, CONVERGE).await;

    api.restart().await;
    let admin = api.admin();
    admin.create_cm("after", 10).await;
    admin.delete_cm("before").await;
    admin.touch_cm("after", "2").await;

    converge(&inf, &admin, CONVERGE).await;
}

/// While the apiserver is unreachable the informer must back off. A tight
/// retry loop would burn a core and flood the apiserver the moment it returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_apiserver_is_retried_with_backoff() {
    let (api, admin, proxy) = rig("backoff").await;
    let mut c = cfg();
    c.backoff_initial = Duration::from_millis(100);
    c.backoff_max = Duration::from_millis(800);
    proxy.block(true);
    let inf = Informer::<Cm>::spawn(api.client_via(proxy.port), c, |_| {});
    tokio::time::sleep(Duration::from_secs(3)).await;
    let attempts = proxy.attempts.load(Relaxed);
    assert!(
        (3..=14).contains(&attempts),
        "{attempts} connection attempts in 3s: retrying without exponential backoff (or not retrying)"
    );
    proxy.block(false);
    inf.wait_synced().await;
    admin.create_cm("probe", 10).await;
    converge(&inf, &admin, CONVERGE).await;

    let before = proxy.attempts.load(Relaxed);
    proxy.block(true);
    proxy.sever();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let watch_attempts = proxy.attempts.load(Relaxed) - before;
    assert!(
        (3..=14).contains(&watch_attempts),
        "{watch_attempts} reconnects in 3s: watch retried without exponential backoff (or not retried)"
    );
    proxy.block(false);
    admin.create_cm("after-outage", 10).await;
    converge(&inf, &admin, CONVERGE).await;
}

/// A consumer stalled while the store churns past its retained history must
/// recover to the true state, not silently skip the events it missed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_consumer_converges() {
    let (api, admin, proxy) = rig("slow").await;
    let paused = Arc::new(AtomicBool::new(false));
    let p = paused.clone();
    let inf = Informer::<Cm>::spawn(api.client_via(proxy.port), cfg(), move |_| {
        tokio::task::block_in_place(|| {
            while p.load(Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
            }
        });
    });
    inf.wait_synced().await;
    admin.create_cm("seed", 10).await;
    converge(&inf, &admin, CONVERGE).await;

    paused.store(true, Relaxed);
    admin.create_cm("trigger", 10).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    for i in 0..1300 {
        admin.create_cm(&format!("burst-{i}"), 40_000).await;
    }
    admin.delete_cm("seed").await;
    paused.store(false, Relaxed);

    converge(&inf, &admin, CONVERGE).await;
    assert!(
        inf.stats().gone.load(Relaxed) >= 1,
        "burst never outran the server's retained history, so the lag path was not exercised: {:?}",
        inf.stats()
    );
}
