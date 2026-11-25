use hyper::Method;
use serde::{de::DeserializeOwned, Deserialize};
use spike_common as sc;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::Notify;

#[global_allocator]
static ALLOC: sc::Counting = sc::Counting;

trait Obj: DeserializeOwned + Send + 'static {
    fn meta(&self) -> &sc::Meta;
}
impl Obj for sc::NarrowPod {
    fn meta(&self) -> &sc::Meta { &self.metadata }
}
impl Obj for sc::NarrowRs {
    fn meta(&self) -> &sc::Meta { &self.metadata }
}

#[derive(Deserialize)]
struct ListMeta {
    #[serde(rename = "resourceVersion")]
    resource_version: Option<String>,
    #[serde(rename = "continue")]
    cont: Option<String>,
}
#[derive(Deserialize)]
struct List<T> {
    metadata: ListMeta,
    items: Vec<T>,
}

type Store<T> = Arc<Mutex<HashMap<String, T>>>;

async fn informer<T: Obj>(
    client: Arc<politeia::HyperApiClient>,
    path: &'static str,
    store: Store<T>,
    ready: Arc<Notify>,
) {
    loop {
        let mut m: HashMap<String, T> = HashMap::new();
        let mut cont = String::new();
        let rv = loop {
            let url = if cont.is_empty() {
                format!("{path}?limit=500")
            } else {
                format!("{path}?limit=500&continue={cont}")
            };
            let (st, body) = client.request(Method::GET, &url, None).await.unwrap();
            assert!(st.is_success(), "list {path}: {st}");
            let page: List<T> = serde_json::from_str(&body).unwrap();
            drop(body);
            for o in page.items {
                m.insert(sc::key(o.meta()), o);
            }
            cont = page.metadata.cont.unwrap_or_default();
            if cont.is_empty() {
                break page.metadata.resource_version.unwrap_or_default();
            }
        };
        *store.lock().unwrap() = m;
        ready.notify_one();
        let wurl = format!("{path}?watch=true&allowWatchBookmarks=true&resourceVersion={rv}");
        let r = client
            .watch_stream(&wurl, |mut ev| {
                let typ = ev["type"].as_str().unwrap_or("").to_owned();
                if typ != "ADDED" && typ != "MODIFIED" && typ != "DELETED" {
                    return;
                }
                let Ok(o) = serde_json::from_value::<T>(ev["object"].take()) else { return };
                let k = sc::key(o.meta());
                sc::note_event(&o.meta().name, typ == "DELETED");
                let mut s = store.lock().unwrap();
                if typ == "DELETED" {
                    s.remove(&k);
                } else {
                    s.insert(k, o);
                }
            })
            .await;
        eprintln!("watch {path} ended: {r:?}; relisting");
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let a = sc::args();
    let mut client = politeia::kubeconfig_client(&a.kubeconfig).unwrap();
    if let Some(s) = &a.server {
        client.server = s.clone();
    }
    let client = Arc::new(client);
    let base = sc::Baseline::take();

    let pods: Store<sc::NarrowPod> = Default::default();
    let rss: Store<sc::NarrowRs> = Default::default();
    let (pr, rr) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    tokio::spawn(informer(client.clone(), "/api/v1/pods", pods.clone(), pr.clone()));
    tokio::spawn(informer(client, "/apis/apps/v1/replicasets", rss.clone(), rr.clone()));
    pr.notified().await;
    rr.notified().await;
    println!("SYNCED");

    tokio::time::sleep(std::time::Duration::from_secs(a.settle)).await;
    sc::report("C", &base, pods.lock().unwrap().len(), rss.lock().unwrap().len());
    tokio::time::sleep(std::time::Duration::from_secs(a.events_wait)).await;

    let s = pods.lock().unwrap();
    let v = |n: &str| {
        s.get(&format!("bench-1/{n}"))
            .and_then(|p| p.metadata.labels.as_ref()?.get("v").cloned())
    };
    sc::report_events("C", v("evt-1"), v("evt-2"), s.contains_key("bench-1/evt-3"));
}
