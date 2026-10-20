use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RELOAD: Duration = Duration::from_millis(50);

fn write_atomic(path: &std::path::Path, contents: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

/// Rotating the client cert on disk must end the scheduler's open watch and the
/// reconnect must present the new cert through the SAME client. A scheduler
/// that built its client from embedded `-data`, or a fresh client per call,
/// would keep authenticating as the rotated-out identity until it expired.
#[tokio::test]
async fn one_shared_client_reconnects_watch_with_rotated_client_cert() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::default();
    server_params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let issue_client = || {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::default()
            .signed_by(&key, &issuer)
            .unwrap();
        (cert, key)
    };
    let (client_v1, key_v1) = issue_client();
    let (client_v2, key_v2) = issue_client();

    let dir = std::env::temp_dir().join(format!("u7s-sched-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
    std::fs::write(dir.join("client.pem"), client_v1.pem()).unwrap();
    std::fs::write(dir.join("client.key"), key_v1.serialize_pem()).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen_certs: Arc<Mutex<Vec<CertificateDer<'static>>>> = Arc::default();
    let seen = seen_certs.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.expect("server TLS accept");
                let peer = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
                seen.lock().unwrap().push(peer.into_owned());
                let mut buf = vec![0u8; 4096];
                let mut total = 0;
                while !buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = tls.read(&mut buf[total..]).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    total += n;
                }
                tls.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .await
                    .unwrap();
                tls.flush().await.unwrap();
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
        }
    });

    std::fs::write(
        dir.join("kubeconfig"),
        format!(
            "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://127.0.0.1:{port}\n    \
             certificate-authority: ca.pem\n  name: u7s\nusers:\n- name: scheduler\n  user:\n    \
             client-certificate: client.pem\n    client-key: client.key\n"
        ),
    )
    .unwrap();
    let client =
        u7s_scheduler::build_client(dir.join("kubeconfig").to_str().unwrap(), None, Some(RELOAD))
            .expect("file-path kubeconfig builds a reloading client");

    let first = {
        let client = client.clone();
        tokio::spawn(async move { u7s_scheduler::stream_watch_events(&client, "/w", |_| {}).await })
    };
    tokio::time::sleep(RELOAD * 6).await;
    assert!(!first.is_finished(), "watch must stay open until rotation");

    write_atomic(&dir.join("client.key"), &key_v2.serialize_pem());
    write_atomic(&dir.join("client.pem"), &client_v2.pem());

    let ended = tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .expect("rotation must end the open watch so the reconnect loop reopens it")
        .unwrap();
    assert!(ended.is_ok(), "watch ends cleanly on rotation: {ended:?}");

    let second = {
        let client = client.clone();
        tokio::spawn(async move { u7s_scheduler::stream_watch_events(&client, "/w", |_| {}).await })
    };
    tokio::time::sleep(RELOAD * 10).await;
    assert!(
        !second.is_finished(),
        "reconnect on the same client must not be torn down again: reload state has to survive reconnects"
    );
    second.abort();

    let seen = seen_certs.lock().unwrap();
    assert_eq!(seen.len(), 2, "one connection per watch");
    assert_eq!(seen[0].as_ref(), client_v1.der().as_ref());
    assert_eq!(
        seen[1].as_ref(),
        client_v2.der().as_ref(),
        "the reconnect must present the rotated client cert"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
