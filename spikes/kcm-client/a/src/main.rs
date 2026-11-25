use futures::StreamExt;
use k8s_openapi::api::{apps::v1::ReplicaSet, core::v1::Pod};
use kube::{
    config::{Kubeconfig, KubeConfigOptions},
    runtime::{reflector, reflector::ObjectRef, watcher, watcher::Event, WatchStreamExt},
    Api, Client, Config,
};
use spike_common as sc;

#[global_allocator]
static ALLOC: sc::Counting = sc::Counting;

async fn drive<K>(stream: impl futures::Stream<Item = Result<Event<K>, watcher::Error>>)
where
    K: kube::Resource<DynamicType = ()>,
{
    futures::pin_mut!(stream);
    while let Some(ev) = stream.next().await {
        match ev {
            Ok(Event::Apply(o)) => sc::note_event(&o.meta().name.clone().unwrap_or_default(), false),
            Ok(Event::Delete(o)) => sc::note_event(&o.meta().name.clone().unwrap_or_default(), true),
            Ok(_) => {}
            Err(e) => eprintln!("watch error: {e}"),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let a = sc::args();
    let kc = Kubeconfig::read_from(&a.kubeconfig).unwrap();
    let mut cfg = Config::from_custom_kubeconfig(kc, &KubeConfigOptions::default())
        .await
        .unwrap();
    if let Some(s) = &a.server {
        cfg.cluster_url = s.parse().unwrap();
    }
    let client = Client::try_from(cfg).unwrap();
    let base = sc::Baseline::take();

    let (pstore, pw) = reflector::store::<Pod>();
    let (rstore, rw) = reflector::store::<ReplicaSet>();
    let trim = a.trim;
    let ps = reflector(
        pw,
        watcher(Api::<Pod>::all(client.clone()), watcher::Config::default()).modify(move |o| {
            if trim {
                o.metadata.managed_fields = None;
            }
        }),
    );
    let rs = reflector(
        rw,
        watcher(Api::<ReplicaSet>::all(client), watcher::Config::default()).modify(move |o| {
            if trim {
                o.metadata.managed_fields = None;
            }
        }),
    );
    tokio::spawn(drive(ps));
    tokio::spawn(drive(rs));
    pstore.wait_until_ready().await.unwrap();
    rstore.wait_until_ready().await.unwrap();
    println!("SYNCED");

    tokio::time::sleep(std::time::Duration::from_secs(a.settle)).await;
    sc::report(if a.trim { "A-trim" } else { "A" }, &base, pstore.len(), rstore.len());
    tokio::time::sleep(std::time::Duration::from_secs(a.events_wait)).await;

    let v = |n: &str| {
        pstore
            .get(&ObjectRef::<Pod>::new(n).within("bench-1"))
            .and_then(|p| p.metadata.labels.as_ref()?.get("v").cloned())
    };
    let present = pstore
        .get(&ObjectRef::<Pod>::new("evt-3").within("bench-1"))
        .is_some();
    sc::report_events(if a.trim { "A-trim" } else { "A" }, v("evt-1"), v("evt-2"), present);
}
