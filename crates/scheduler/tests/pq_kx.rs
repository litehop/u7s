use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::pki_types::PrivateKeyDer;

/// Harvest-now-decrypt-later: the scheduler's mTLS session to the apiserver must be keyed
/// with hybrid X25519MLKEM768. The server here supports no other group, so the handshake
/// only completes if the client built by `build_client` (politeia underneath) offers it;
/// a client left on a classical-only provider would fail the handshake and the scheduler
/// would be unable to reach the apiserver at all.
#[tokio::test]
async fn scheduler_client_negotiates_x25519mlkem768() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::default();
    server_params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_cert = CertificateParams::default()
        .signed_by(&client_key, &issuer)
        .unwrap();

    let dir = std::env::temp_dir().join(format!("u7s-sched-pq-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
    std::fs::write(dir.join("client.pem"), client_cert.pem()).unwrap();
    std::fs::write(dir.join("client.key"), client_key.serialize_pem()).unwrap();

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .kx_groups
        .retain(|g| g.name() == rustls::NamedGroup::X25519MLKEM768);
    assert_eq!(provider.kx_groups.len(), 1);
    let provider = Arc::new(provider);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
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
    let (group_tx, group_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.expect("server TLS accept");
        let group = tls
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .unwrap()
            .name();
        let _ = group_tx.send(group);
        tokio::time::sleep(Duration::from_secs(5)).await;
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
    let client = u7s_scheduler::build_client(dir.join("kubeconfig").to_str().unwrap(), None, None)
        .expect("file-path kubeconfig builds a client");
    tokio::spawn(async move { u7s_scheduler::stream_watch_events(&client, "/w", |_| {}).await });

    let group = tokio::time::timeout(Duration::from_secs(10), group_rx)
        .await
        .expect("scheduler client must complete a TLS handshake with a PQ-only server")
        .unwrap();
    assert_eq!(group, rustls::NamedGroup::X25519MLKEM768);
    let _ = std::fs::remove_dir_all(&dir);
}
