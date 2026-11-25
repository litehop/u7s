use futures::StreamExt;
use k8s_openapi::{
    api::core::v1::Pod as _P,
    apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference},
    NamespaceResourceScope,
};
use kube::{
    config::{KubeConfigOptions, Kubeconfig},
    runtime::{reflector, reflector::ObjectRef, watcher, watcher::Event},
    Api, Client, Config, Resource,
};
use serde::Deserialize;
use spike_common as sc;
use std::borrow::Cow;

#[global_allocator]
static ALLOC: sc::Counting = sc::Counting;

fn meta(m: sc::Meta) -> ObjectMeta {
    ObjectMeta {
        name: Some(m.name),
        namespace: m.namespace,
        uid: m.uid,
        resource_version: m.resource_version,
        labels: m.labels,
        owner_references: m.owner_references.map(|v| {
            v.into_iter()
                .map(|o| OwnerReference {
                    api_version: o.api_version,
                    kind: o.kind,
                    name: o.name,
                    uid: o.uid,
                    controller: o.controller,
                    block_owner_deletion: o.block_owner_deletion,
                })
                .collect()
        }),
        ..Default::default()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(from = "sc::NarrowPod")]
struct NPod {
    metadata: ObjectMeta,
    #[allow(dead_code)]
    status: Option<sc::PodStatus>,
}
impl From<sc::NarrowPod> for NPod {
    fn from(p: sc::NarrowPod) -> Self {
        NPod { metadata: meta(p.metadata), status: p.status }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(from = "sc::NarrowRs")]
struct NRs {
    metadata: ObjectMeta,
    #[allow(dead_code)]
    replicas: Option<i32>,
}
impl From<sc::NarrowRs> for NRs {
    fn from(r: sc::NarrowRs) -> Self {
        NRs { metadata: meta(r.metadata), replicas: r.spec.and_then(|s| s.replicas) }
    }
}

macro_rules! resource {
    ($t:ty, $kind:literal, $group:literal, $ver:literal, $api:literal, $plural:literal) => {
        impl Resource for $t {
            type DynamicType = ();
            type Scope = NamespaceResourceScope;
            fn kind(_: &()) -> Cow<'_, str> { $kind.into() }
            fn group(_: &()) -> Cow<'_, str> { $group.into() }
            fn version(_: &()) -> Cow<'_, str> { $ver.into() }
            fn api_version(_: &()) -> Cow<'_, str> { $api.into() }
            fn plural(_: &()) -> Cow<'_, str> { $plural.into() }
            fn meta(&self) -> &ObjectMeta { &self.metadata }
            fn meta_mut(&mut self) -> &mut ObjectMeta { &mut self.metadata }
        }
    };
}
resource!(NPod, "Pod", "", "v1", "v1", "pods");
resource!(NRs, "ReplicaSet", "apps", "v1", "apps/v1", "replicasets");

async fn drive<K>(stream: impl futures::Stream<Item = Result<Event<K>, watcher::Error>>)
where
    K: Resource<DynamicType = ()>,
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
    let _ = std::marker::PhantomData::<_P>;
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

    let (pstore, pw) = reflector::store::<NPod>();
    let (rstore, rw) = reflector::store::<NRs>();
    let ps = reflector(pw, watcher(Api::<NPod>::all(client.clone()), watcher::Config::default()));
    let rs = reflector(rw, watcher(Api::<NRs>::all(client), watcher::Config::default()));
    tokio::spawn(drive(ps));
    tokio::spawn(drive(rs));
    pstore.wait_until_ready().await.unwrap();
    rstore.wait_until_ready().await.unwrap();
    println!("SYNCED");

    tokio::time::sleep(std::time::Duration::from_secs(a.settle)).await;
    sc::report("B", &base, pstore.len(), rstore.len());
    tokio::time::sleep(std::time::Duration::from_secs(a.events_wait)).await;

    let v = |n: &str| {
        pstore
            .get(&ObjectRef::<NPod>::new(n).within("bench-1"))
            .and_then(|p| p.metadata.labels.as_ref()?.get("v").cloned())
    };
    let present = pstore
        .get(&ObjectRef::<NPod>::new("evt-3").within("bench-1"))
        .is_some();
    sc::report_events("B", v("evt-1"), v("evt-2"), present);
}
