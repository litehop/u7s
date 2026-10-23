//! In-memory TLS handshakes for tests that need to know whether a verifier accepts a peer.

use std::sync::Arc;

/// True if a client using `client` and a server using `server` complete a handshake.
pub(crate) fn handshake_completes(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> bool {
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
                    return false;
                }
            }
        }
        if conns.iter().all(|c| !c.is_handshaking()) {
            return true;
        }
    }
    false
}
