//! In-memory TLS handshakes for tests that need to know whether a verifier accepts a peer.

use std::sync::Arc;

/// True if a client using `client` and a server using `server` complete a handshake.
pub(crate) fn handshake_completes(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> bool {
    handshake(client, server).is_some()
}

/// The certificate chain the server presented, when the handshake completes.
pub(crate) fn server_chain(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> Option<Vec<Vec<u8>>> {
    let [client, _] = handshake(client, server)?;
    Some(
        client
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|c| c.as_ref().to_vec())
            .collect(),
    )
}

/// The key-exchange group the two sides agreed on, when the handshake completes.
pub(crate) fn negotiated_group(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> Option<rustls::NamedGroup> {
    let [client, server] = handshake(client, server)?;
    let (c, s) = (
        client.negotiated_key_exchange_group()?.name(),
        server.negotiated_key_exchange_group()?.name(),
    );
    assert_eq!(c, s, "both ends must report the same group");
    Some(c)
}

fn handshake(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> Option<[rustls::Connection; 2]> {
    let mut conns = [
        rustls::Connection::Client(
            rustls::ClientConnection::new(client, "localhost".try_into().unwrap()).unwrap(),
        ),
        rustls::Connection::Server(rustls::ServerConnection::new(server).unwrap()),
    ];
    for _ in 0..16 {
        for from in 0..2 {
            let mut buf = Vec::new();
            while conns[from].wants_write() {
                conns[from].write_tls(&mut buf).unwrap();
            }
            let to = &mut conns[1 - from];
            let mut rest = buf.as_slice();
            while !rest.is_empty() {
                to.read_tls(&mut rest).unwrap();
                if to.process_new_packets().is_err() {
                    return None;
                }
            }
        }
        if conns.iter().all(|c| !c.is_handshaking()) {
            return Some(conns);
        }
    }
    None
}

/// A loopback HTTPS server that accepts only the hybrid X25519MLKEM768 group, so a client
/// completes a request only if the provider it keys TLS from offers that group.
pub(crate) struct PqOnlyServer {
    pub port: u16,
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
    /// Handshakes that completed with X25519MLKEM768.
    pub pq_handshakes: Arc<std::sync::atomic::AtomicUsize>,
}

pub(crate) async fn pq_only_server(dns_name: &str) -> PqOnlyServer {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let key = rcgen::generate_simple_self_signed(vec![dns_name.to_owned()]).unwrap();
    let cert = key.cert.der().clone();
    let mut provider = (*crate::tls::pq_provider()).clone();
    provider
        .kx_groups
        .retain(|g| g.name() == rustls::NamedGroup::X25519MLKEM768);
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.clone()],
            rustls::pki_types::PrivateKeyDer::try_from(key.signing_key.serialize_der()).unwrap(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let pq_handshakes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&pq_handshakes);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                // A hello-retry means the client's first key share was not the hybrid: it only
                // listed the group instead of preferring it.
                let conn = tls.get_ref().1;
                if conn.negotiated_key_exchange_group().map(|g| g.name())
                    == Some(rustls::NamedGroup::X25519MLKEM768)
                    && conn.handshake_kind() == Some(rustls::HandshakeKind::Full)
                {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    PqOnlyServer {
        port,
        cert_der: cert.as_ref().to_vec(),
        cert_pem: key.cert.pem(),
        key_pem: key.signing_key.serialize_pem(),
        pq_handshakes,
    }
}

/// One GET with `client` must complete a hybrid handshake with `server`.
pub(crate) async fn assert_pq_request(
    link: &str,
    client: &reqwest::Client,
    url: &str,
    server: &PqOnlyServer,
) {
    let resp = client.get(url).send().await.unwrap_or_else(|e| {
        panic!(
            "{link}: request to a hybrid-only server failed, so this link would fall back to \
             classical key exchange: {e:?}"
        )
    });
    assert_eq!(resp.status(), 200, "{link}");
    assert_eq!(
        server
            .pq_handshakes
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "{link}: handshake must negotiate X25519MLKEM768"
    );
}
