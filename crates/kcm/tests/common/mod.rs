#![allow(dead_code)]

use hyper::Method;
use politeia::HyperApiClient;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::watch};
use u7s_kcm::{
    informer::{Informer, Object},
    narrow::Meta,
};

pub const CM_PATH: &str = "/api/v1/namespaces/default/configmaps";

#[derive(Deserialize)]
pub struct Cm {
    pub metadata: Meta,
}

impl Object for Cm {
    fn key(&self) -> String {
        self.metadata.key()
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn apiserver_bin() -> PathBuf {
    static BIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args([
                "build",
                "--locked",
                "--quiet",
                "-p",
                "u7s-apiserver",
                "--message-format=json",
            ])
            .stderr(Stdio::inherit())
            .output()
            .unwrap();
        assert!(out.status.success(), "building u7s-apiserver failed");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|m| {
                m["reason"] == "compiler-artifact" && m["target"]["name"] == "u7s-apiserver"
            })
            .filter_map(|m| m["executable"].as_str().map(PathBuf::from))
            .next_back()
            .expect("cargo reported no u7s-apiserver executable")
    })
    .clone()
}

pub struct Apiserver {
    pub dir: PathBuf,
    pub port: u16,
    child: Option<Child>,
    bin: PathBuf,
}

impl Apiserver {
    pub async fn start(name: &str) -> Apiserver {
        let dir = std::env::temp_dir().join(format!("u7s-kcm-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = Apiserver {
            dir,
            port: free_port(),
            child: None,
            bin: apiserver_bin(),
        };
        s.boot().await;
        s
    }

    async fn boot(&mut self) {
        let d = |f: &str| self.dir.join(f).to_string_lossy().into_owned();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("apiserver.log"))
            .unwrap();
        let child = Command::new(&self.bin)
            .args([
                "--db",
                &d("state.db"),
                "--listen",
                &format!("127.0.0.1:{}", self.port),
                "--kubeconfig",
                &d("kubeconfig"),
                "--sa-key",
                &d("sa.key"),
                "--sa-pub",
                &d("sa.pub"),
                "--ca-key",
                &d("ca.key"),
                "--ca-cert",
                &d("ca.crt"),
                "--proxy-client-ca-key",
                &d("pk.key"),
                "--proxy-client-ca-cert",
                &d("pk.crt"),
            ])
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Ok(c) = self.admin_at(self.port) {
                if let Ok((st, _)) = c.request(Method::GET, "/readyz", None).await {
                    if st.is_success() {
                        return;
                    }
                }
            }
            assert!(Instant::now() < deadline, "apiserver not ready");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            c.kill().unwrap();
            c.wait().unwrap();
        }
    }

    pub async fn restart(&mut self) {
        self.stop();
        self.boot().await;
    }

    fn admin_at(&self, port: u16) -> anyhow_free::Result<HyperApiClient> {
        let mut c = politeia::kubeconfig_client(self.dir.join("kubeconfig").to_str().unwrap())
            .map_err(|e| e.to_string())?;
        c.server = format!("https://127.0.0.1:{port}");
        Ok(c)
    }

    /// Admin client straight to the apiserver (writes and ground truth).
    pub fn admin(&self) -> Admin {
        Admin(self.admin_at(self.port).unwrap())
    }

    /// Client that dials `port` (a proxy) instead of the apiserver.
    pub fn client_via(&self, port: u16) -> Arc<HyperApiClient> {
        Arc::new(self.admin_at(port).unwrap())
    }
}

mod anyhow_free {
    pub type Result<T> = std::result::Result<T, String>;
}

impl Drop for Apiserver {
    fn drop(&mut self) {
        self.stop();
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

pub struct Admin(pub HyperApiClient);

impl Admin {
    async fn call(&self, m: Method, path: &str, body: Option<String>, ct: &str) {
        let (st, b) = self
            .0
            .request_with_content_type(m, path, body, ct)
            .await
            .unwrap_or_else(|e| panic!("{path}: {e:#}"));
        assert!(st.is_success(), "{path}: {st} {b}");
    }

    pub async fn create_cm(&self, name: &str, pad: usize) {
        let body = serde_json::json!({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name},
            "data": {"pad": "x".repeat(pad)},
        });
        self.call(
            Method::POST,
            CM_PATH,
            Some(body.to_string()),
            "application/json",
        )
        .await;
    }

    pub async fn touch_cm(&self, name: &str, v: &str) {
        self.call(
            Method::PUT,
            &format!("{CM_PATH}/{name}"),
            Some(
                serde_json::json!({"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": name}, "data": {"v": v}})
                .to_string(),
            ),
            "application/json",
        )
        .await;
    }

    pub async fn delete_cm(&self, name: &str) {
        self.call(
            Method::DELETE,
            &format!("{CM_PATH}/{name}"),
            None,
            "application/json",
        )
        .await;
    }

    /// name -> resourceVersion as the store sees it right now.
    pub async fn truth(&self) -> BTreeMap<String, String> {
        let (st, body) = self.0.request(Method::GET, CM_PATH, None).await.unwrap();
        assert!(st.is_success(), "{st}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    format!("default/{}", i["metadata"]["name"].as_str().unwrap()),
                    i["metadata"]["resourceVersion"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                )
            })
            .collect()
    }
}

pub fn cache(inf: &Informer<Cm>) -> BTreeMap<String, String> {
    inf.with(|m| {
        m.iter()
            .map(|(k, v)| (k.clone(), v.metadata.resource_version.clone().unwrap()))
            .collect()
    })
}

/// Waits until the informer's cache equals the store's current state exactly
/// (same keys, same resourceVersions); panics with both sides otherwise.
pub async fn converge(inf: &Informer<Cm>, admin: &Admin, within: Duration) {
    let deadline = Instant::now() + within;
    loop {
        let (truth, got) = (admin.truth().await, cache(inf));
        if truth == got {
            return;
        }
        if Instant::now() > deadline {
            let missing: Vec<_> = truth
                .keys()
                .filter(|k| !got.contains_key(*k))
                .take(5)
                .collect();
            let extra: Vec<_> = got
                .keys()
                .filter(|k| !truth.contains_key(*k))
                .take(5)
                .collect();
            let stale: Vec<_> = truth
                .iter()
                .filter(|(k, v)| got.get(*k).is_some_and(|g| g != *v))
                .map(|(k, _)| k)
                .take(5)
                .collect();
            panic!(
                "cache never converged: store has {} cache has {}; missing {missing:?} extra {extra:?} stale {stale:?}; {:?}",
                truth.len(),
                got.len(),
                inf.stats()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// TCP proxy that can sever live connections or refuse new ones, counting
/// every connection attempt.
pub struct Proxy {
    pub port: u16,
    blocked: Arc<AtomicBool>,
    pub attempts: Arc<AtomicU64>,
    epoch: watch::Sender<u64>,
}

impl Proxy {
    pub async fn start(target: u16) -> Proxy {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let blocked = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicU64::new(0));
        let (epoch, _) = watch::channel(0u64);
        let (b, a, e) = (blocked.clone(), attempts.clone(), epoch.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut down, _)) = l.accept().await else {
                    return;
                };
                a.fetch_add(1, Relaxed);
                if b.load(Relaxed) {
                    continue;
                }
                let mut rx = e.subscribe();
                tokio::spawn(async move {
                    let Ok(mut up) = tokio::net::TcpStream::connect(("127.0.0.1", target)).await
                    else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut down, &mut up) => {}
                        _ = rx.changed() => {}
                    }
                });
            }
        });
        Proxy {
            port,
            blocked,
            attempts,
            epoch,
        }
    }

    pub fn block(&self, on: bool) {
        self.blocked.store(on, Relaxed);
    }

    pub fn sever(&self) {
        self.epoch.send_modify(|e| *e += 1);
    }
}
