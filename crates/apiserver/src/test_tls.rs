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
