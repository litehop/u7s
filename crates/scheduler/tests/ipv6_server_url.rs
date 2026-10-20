use std::sync::Arc;

use base64::Engine;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// An apiserver reachable only at an IPv6 literal (dual-stack / IPv6-only
/// control plane) presents a cert with just an IP SAN. The scheduler's
/// kubeconfig -> connector -> GET path must verify against that SAN; treating
/// the bracketed host as a DNS name fails every request with "invalid DNS name"
/// and the scheduler can never reach the API.
#[tokio::test]
async fn scheduler_get_reaches_apiserver_at_ipv6_literal_with_ip_san_cert() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::default();
    server_params.subject_alt_names = vec![SanType::IpAddress("::1".parse().unwrap())];
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let client_cert = CertificateParams::default()
        .signed_by(&client_key, &issuer)
        .unwrap();

    // Installs the process-default crypto provider the test server below uses.
    politeia::build_tls_connector(&politeia::ClientCreds {
        server: String::new(),
        ca_cert: ca_cert.der().clone(),
        client_cert: client_cert.der().clone(),
        client_key: PrivateKeyDer::Pkcs8(client_key.serialize_der().into()),
    })
    .unwrap();
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = tokio::net::TcpListener::bind("[::1]:0")
        .await
        .expect("IPv6 loopback must be available");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server TLS accept");
        let mut buf = vec![0u8; 4096];
        let mut total = 0;
        while !buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tls.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    });

    let b64 = base64::engine::general_purpose::STANDARD;
    let yaml = format!(
        "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://[::1]:{port}\n    \
         certificate-authority-data: {}\n  name: u7s\nusers:\n- name: admin\n  user:\n    \
         client-certificate-data: {}\n    client-key-data: {}\n",
        b64.encode(pem("CERTIFICATE", ca_cert.der())),
        b64.encode(pem("CERTIFICATE", client_cert.der())),
        b64.encode(pem("PRIVATE KEY", &client_key.serialize_der())),
    );
    let path = std::env::temp_dir().join(format!("u7s-sched-ipv6-{}.yaml", std::process::id()));
    std::fs::write(&path, yaml).unwrap();
    let client = politeia::kubeconfig_client(path.to_str().unwrap()).expect("build client");
    let _ = std::fs::remove_file(&path);

    let (status, body) = u7s_scheduler::http_get(&client, "/healthz")
        .await
        .expect("GET to an IPv6-literal server URL must verify against the IP SAN");
    assert_eq!(status, hyper::StatusCode::OK);
    assert_eq!(body, "ok");
}
