use super::*;
use crate::pki::{Clock, CLIENT_CERT_LIFETIME, ROOT_CA_LIFETIME};
use crate::tls::leaf_cert_chain_validates_at;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SERVING: Duration = Duration::from_secs(3000);

struct Harness {
    pki: Pki,
    skew: Arc<AtomicI64>,
    dir: std::path::PathBuf,
    cluster_key_pem: String,
}

impl Harness {
    fn new(tag: &str) -> Self {
        rustls_post_quantum::provider().install_default().ok();
        let skew = Arc::new(AtomicI64::new(0));
        let base = OffsetDateTime::now_utc();
        let s = Arc::clone(&skew);
        let pki = Pki {
            clock: Clock::new(move || base + time::Duration::seconds(s.load(Ordering::SeqCst))),
            ..Pki::default()
        };
        let dir = std::env::temp_dir().join(format!(
            "u7s-rot-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
        std::fs::create_dir_all(&dir).unwrap(); // lgtm[rust/path-injection]
        let cluster_key_pem = pki.generate_key().unwrap().serialize_pem();
        let h = Self {
            pki,
            skew,
            dir,
            cluster_key_pem,
        };
        // First "boot" mints the CA cert once and pins it, as ca.crt does on disk.
        let ca = h.signer_for(&h.cluster_key_pem, None);
        std::fs::write(h.dir.join("ca.crt"), &ca.cert_der).unwrap();
        h
    }

    fn advance(&self, secs: i64) {
        self.skew.fetch_add(secs, Ordering::SeqCst);
    }

    fn ca_spec(cn: &'static str) -> CertSpec<'static> {
        CertSpec {
            name: "ca",
            common_name: cn,
            organization: None,
            role: CertRole::Root,
            lifetime: ROOT_CA_LIFETIME,
            usages: &["cert sign"],
            sans: vec![],
        }
    }

    /// A CA over `key_pem`; `existing_der` reuses a cert already "on disk" so the CA is
    /// stable across simulated restarts.
    fn signer_for(&self, key_pem: &str, existing_der: Option<Vec<u8>>) -> CaSigner {
        let key = rcgen::KeyPair::from_pem(key_pem).unwrap();
        let spec = Self::ca_spec("test-ca");
        let cert_der = existing_der.unwrap_or_else(|| {
            let nb = self.pki.clock.now() - time::Duration::minutes(5);
            let params = self.pki.params(&spec, nb, nb + ROOT_CA_LIFETIME);
            params.self_signed(&key).unwrap().der().to_vec()
        });
        let (nb, na) = cert_validity(&cert_der).unwrap();
        CaSigner {
            issuer: Issuer::new(self.pki.params(&spec, nb, na), key),
            cert_der,
            not_after: na,
        }
    }

    fn cluster_ca(&self) -> CaSigner {
        self.signer_for(
            &self.cluster_key_pem,
            Some(std::fs::read(self.dir.join("ca.crt")).unwrap()),
        )
    }

    fn other_ca(&self) -> CaSigner {
        let key = self.pki.generate_key().unwrap().serialize_pem();
        self.signer_for(&key, None)
    }

    fn plans(&self, admin: Duration) -> Vec<LeafPlan> {
        vec![
            LeafPlan {
                name: SERVING_LEAF,
                common_name: "u7s-apiserver",
                organization: None,
                lifetime: SERVING,
                usages: &["server auth"],
                sans: vec![SanType::DnsName("localhost".try_into().unwrap())],
                ca: CaKind::Cluster,
                files: None,
            },
            self.admin_plan(admin),
        ]
    }

    fn admin_plan(&self, lifetime: Duration) -> LeafPlan {
        LeafPlan {
            name: "admin",
            common_name: "admin",
            organization: Some("system:masters"),
            lifetime,
            usages: &["client auth"],
            sans: vec![],
            ca: CaKind::Cluster,
            files: Some(LeafFiles {
                cert: self.dir.join("admin.crt"),
                key: self.dir.join("admin.key"),
            }),
        }
    }

    fn start(&self, admin: Duration) -> anyhow::Result<Rotator> {
        Rotator::new(
            self.pki.clone(),
            crate::pki::RENEW_FRACTION,
            self.cluster_ca(),
            self.other_ca(),
            self.plans(admin),
        )
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir); // lgtm[rust/path-injection]
    }
}

fn connector(ca_der: &[u8], identity: Option<&Leaf>) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))
        .unwrap();
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let cfg = match identity {
        None => builder.with_no_client_auth(),
        Some(leaf) => {
            let key =
                rcgen::KeyPair::from_pem(std::str::from_utf8(&leaf.key_pem).unwrap()).unwrap();
            builder
                .with_client_auth_cert(
                    vec![rustls::pki_types::CertificateDer::from(
                        leaf.cert_der.clone(),
                    )],
                    rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
                )
                .unwrap()
        }
    };
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

/// One handshake against `config`; true if the server accepted the client.
async fn server_accepts(config: Arc<ServerConfig>, connector: &tokio_rustls::TlsConnector) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(config).accept(tcp).await else {
            return false;
        };
        let _ = tls.write_all(b"x").await;
        let _ = tls.shutdown().await;
        true
    });
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    if let Ok(mut c) = connector.connect(name, tcp).await {
        let mut b = [0u8; 1];
        let _ = c.read(&mut b).await;
    }
    server.await.unwrap()
}

#[test]
fn leaves_rotate_at_two_thirds_of_lifetime_and_not_before() {
    let h = Harness::new("two-thirds");
    let r = h.start(CLIENT_CERT_LIFETIME).unwrap();
    let old = r.leaf(SERVING_LEAF);
    let rotated = Mutex::new(Vec::new());
    let note = |n: &'static str, _: &Leaf| rotated.lock().unwrap().push(n);

    // 2/3 of the 3000s window, counted from the (backdated) not_before.
    let due = old.not_before + time::Duration::seconds(2000);
    h.advance((due - h.pki.clock.now()).whole_seconds() - 1);
    r.rotate_due(&note).unwrap();
    assert!(
        rotated.lock().unwrap().is_empty(),
        "rotating before 2/3 of the lifetime churns every consumer for nothing"
    );

    h.advance(2);
    r.rotate_due(&note).unwrap();
    assert_eq!(
        *rotated.lock().unwrap(),
        vec![SERVING_LEAF],
        "only the leaf that is due may rotate; the 1y admin leaf is nowhere near due"
    );
    let new = r.leaf(SERVING_LEAF);
    assert_ne!(new.cert_der, old.cert_der);
    assert!(
        leaf_cert_chain_validates_at(&new.cert_der, &h.cluster_ca().cert_der, h.pki.clock.now()),
        "the rotated serving cert must chain to the CA clients already trust"
    );
}

#[tokio::test]
async fn next_connection_gets_rotated_cert_and_open_connection_survives() {
    let h = Harness::new("swap-serving");
    // Start in the past so the rotated cert (issued at "now") is valid for the real clocks
    // of the clients below.
    h.advance(-2500);
    let r = h.start(CLIENT_CERT_LIFETIME).unwrap();
    let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(crate::serve::serve_tls_with(
        listener,
        app,
        r.server_config(),
        crate::serve::ServeLimits::default(),
    ));
    let connector = connector(&h.cluster_ca().cert_der, None);
    let connect = || async {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        connector.connect(name, tcp).await.unwrap()
    };
    let presented = |c: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>| {
        c.get_ref().1.peer_certificates().unwrap()[0]
            .as_ref()
            .to_vec()
    };

    let mut open = connect().await;
    let before = presented(&open);
    assert_eq!(before, r.leaf(SERVING_LEAF).cert_der);

    h.advance(2500);
    r.rotate_due(&|_, _| {}).unwrap();

    let fresh = connect().await;
    assert_eq!(
        presented(&fresh),
        r.leaf(SERVING_LEAF).cert_der,
        "a connection opened after rotation must present the new cert"
    );
    assert_ne!(presented(&fresh), before);

    open.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let n = open.read(&mut buf).await.unwrap();
    assert!(
        buf[..n].starts_with(b"HTTP/1.1 200"),
        "a long-lived connection (watch, exec) must outlive the rotation"
    );
}

#[tokio::test]
async fn client_ca_store_swap_admits_new_ca_and_rejects_removed_one() {
    let h = Harness::new("swap-client-ca");
    let r = h.start(CLIENT_CERT_LIFETIME).unwrap();
    let trust_server = h.cluster_ca().cert_der;

    // The rotator's own admin leaf is signed by the cluster CA; mint one from another CA.
    let successor = h.other_ca();
    let from_old = connector(&trust_server, Some(&r.leaf("admin")));
    let from_new = connector(
        &trust_server,
        Some(&issue_leaf(&h.pki, &successor, &h.admin_plan(CLIENT_CERT_LIFETIME)).unwrap()),
    );

    let cfg = r.server_config();
    assert!(server_accepts(cfg.get(), &from_old).await);
    assert!(
        !server_accepts(cfg.get(), &from_new).await,
        "a client cert from a CA that is not trusted yet must be rejected"
    );

    r.set_client_cas(vec![successor.cert_der.clone()]).unwrap();
    assert!(
        server_accepts(cfg.get(), &from_new).await,
        "after the swap, a client cert from the new CA must be accepted with no restart"
    );
    assert!(
        !server_accepts(cfg.get(), &from_old).await,
        "after the swap, a client cert from the removed CA must be rejected"
    );
}

#[test]
fn crash_mid_rotation_restarts_into_the_new_pair_and_never_regenerates() {
    let h = Harness::new("crash");
    let admin_life = Duration::from_secs(3000);
    let r = h.start(admin_life).unwrap();
    let (cert_path, key_path) = (h.dir.join("admin.crt"), h.dir.join("admin.key"));
    let key_tmp = h.dir.join("admin.key.tmp");
    let old = (
        std::fs::read(&cert_path).unwrap(),
        std::fs::read(&key_path).unwrap(),
    );

    h.advance(2500);
    r.rotate_due(&|_, _| {}).unwrap();
    let new = (
        std::fs::read(&cert_path).unwrap(),
        std::fs::read(&key_path).unwrap(),
    );
    assert_ne!(old.0, new.0);
    assert_eq!(
        new.0,
        r.leaf("admin").cert_der,
        "what is served is what is on disk"
    );

    // Killed after the cert rename, before the key rename.
    std::fs::write(&key_path, &old.1).unwrap();
    std::fs::write(&key_tmp, &new.1).unwrap();
    let restarted = h
        .start(admin_life)
        .expect("a half-finished rotation must be loadable");
    assert_eq!(
        restarted.leaf("admin").cert_der,
        new.0,
        "restart must continue to the new pair, not re-mint a third credential"
    );
    assert_eq!(std::fs::read(&key_path).unwrap(), new.1);
    assert!(!key_tmp.exists());

    // Killed before any rename: the old pair is intact next to stray tmp files.
    std::fs::write(&cert_path, &old.0).unwrap();
    std::fs::write(&key_path, &old.1).unwrap();
    std::fs::write(&key_tmp, &new.1).unwrap();
    std::fs::write(h.dir.join("admin.crt.tmp"), &new.0).unwrap();
    h.advance(-2500);
    let restarted = h.start(admin_life).unwrap();
    assert_eq!(restarted.leaf("admin").cert_der, old.0);

    // A key that belongs to no cert is refused loudly instead of silently replaced.
    std::fs::write(&key_path, &new.1).unwrap();
    std::fs::remove_file(&key_tmp).unwrap();
    let err = h
        .start(admin_life)
        .err()
        .expect("mismatch must fail")
        .to_string();
    assert!(err.contains("do not belong together"), "{err}");
    assert_eq!(
        std::fs::read(&cert_path).unwrap(),
        old.0,
        "nothing is rewritten on refusal"
    );
}
