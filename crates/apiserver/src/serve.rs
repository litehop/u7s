//! TLS accept loop and the connection-level limits that keep an unauthenticated
//! flood from exhausting or killing the apiserver.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower_service::Service as _;

use crate::auth::PeerCertificate;

/// Limits that apply to the pre-request phases of a connection. Once a request is
/// being served (watch, exec, log streams) none of the timeouts apply.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ServeLimits {
    /// Accepted connections in flight, including those still handshaking. Above this
    /// the loop stops calling `accept()` so the kernel backlog absorbs the burst.
    /// 1024 connections at roughly 50-100 KiB each (rustls + hyper buffers) is
    /// ~50-100 MiB on a 1 GiB host, and stays under the raised RLIMIT_NOFILE.
    pub max_connections: usize,
    /// Upper bound on the TLS handshake (Go's net/http has no default; 10 s is
    /// generous for the slowest legitimate client).
    pub tls_handshake_timeout: Duration,
    /// Upper bound on receiving a request's headers (net/http ReadHeaderTimeout).
    pub header_read_timeout: Duration,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            tls_handshake_timeout: Duration::from_secs(10),
            header_read_timeout: Duration::from_secs(10),
        }
    }
}

pub(crate) trait AcceptTcp {
    fn accept_tcp(&self) -> impl Future<Output = std::io::Result<TcpStream>> + Send;
}

impl AcceptTcp for TcpListener {
    async fn accept_tcp(&self) -> std::io::Result<TcpStream> {
        self.accept().await.map(|(s, _)| s)
    }
}

/// How long to pause after a failed `accept()`. Descriptor/memory exhaustion leaves the
/// pending connection in the backlog, so retrying immediately would spin a core.
fn accept_error_backoff(e: &std::io::Error) -> Duration {
    match e.raw_os_error() {
        Some(c)
            if c == libc::EMFILE
                || c == libc::ENFILE
                || c == libc::ENOBUFS
                || c == libc::ENOMEM =>
        {
            Duration::from_millis(100)
        }
        _ => Duration::from_millis(10),
    }
}

pub(crate) async fn serve_tls_with<L: AcceptTcp>(
    listener: L,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
    limits: ServeLimits,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    // Auto-negotiating builder: dispatches each connection to HTTP/1.1 or HTTP/2 by
    // peeking at the first bytes for the HTTP/2 connection preface. Clients that
    // saw h2 win ALPN (rustls ServerConfig.alpn_protocols in tls.rs) send that
    // preface immediately, so in practice ALPN is what steers this — but the
    // dispatch itself works from the wire, independent of the ALPN result.
    let mut conn_builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    conn_builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    conn_builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new());

    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut last_error_log: Option<Instant> = None;

    loop {
        // Take the permit before accepting: at the cap, connections wait in the kernel
        // backlog instead of costing a descriptor and a task.
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .expect("semaphore is never closed");
        let tcp_stream = match listener.accept_tcp().await {
            Ok(s) => s,
            Err(e) => {
                if last_error_log.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                    tracing::warn!("accept error (continuing): {e}");
                    last_error_log = Some(Instant::now());
                }
                tokio::time::sleep(accept_error_backoff(&e)).await;
                continue;
            }
        };
        crate::configure_accepted_socket(&tcp_stream);
        let acceptor = acceptor.clone();
        let app = app.clone();
        let conn_builder = conn_builder.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let tls_stream = match tokio::time::timeout(
                limits.tls_handshake_timeout,
                acceptor.accept(tcp_stream),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::warn!("TLS accept error: {e}");
                    return;
                }
                Err(_) => {
                    tracing::debug!("TLS handshake timed out");
                    return;
                }
            };

            // Extract the peer certificate once per connection, then share it
            // across all requests on this connection via an Arc.
            let peer_cert: Arc<Option<PeerCertificate>> = Arc::new(
                tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map(|c| PeerCertificate(c.as_ref().to_vec())),
            );

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let request_seen = Arc::new(AtomicBool::new(false));
            let seen = Arc::clone(&request_seen);
            let service = hyper::service::service_fn(move |mut req: axum::http::Request<_>| {
                seen.store(true, Ordering::Relaxed);
                let peer_cert = Arc::clone(&peer_cert);
                let mut app = app.clone();
                async move {
                    if let Some(cert) = peer_cert.as_ref().as_ref() {
                        req.extensions_mut().insert(cert.clone());
                    }
                    Ok::<_, std::convert::Infallible>(app.call(req).await.unwrap())
                }
            });
            // serve_connection_with_upgrades() preserves WebSocket-upgrade support for
            // connections that negotiate HTTP/1.1 (exec/attach/portforward use
            // `Connection: Upgrade`, which has no HTTP/2 equivalent wired up here).
            // Without it, hyper sends the 101 Switching Protocols response but never
            // hands the connection off to the upgrade handler — the on_upgrade callback
            // never runs, the splice never starts, and kubectl times out with
            // "unexpected output from server". Connections that negotiate HTTP/2
            // (kubelet's watch reflectors) skip this path entirely and get hyper's
            // native h2 stream multiplexing instead of one TCP connection per watch.
            let conn = conn_builder.serve_connection_with_upgrades(io, service);
            tokio::pin!(conn);
            // hyper's header_read_timeout only starts once it has chosen HTTP/1; a
            // client that completes TLS and then sends nothing would sit in protocol
            // detection forever. Bound the time to the first request only.
            let first_request_deadline = async {
                tokio::time::sleep(limits.header_read_timeout).await;
                if request_seen.load(Ordering::Relaxed) {
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! {
                res = &mut conn => {
                    if let Err(e) = res {
                        tracing::debug!("connection error: {e}");
                    }
                }
                () = first_request_deadline => {
                    tracing::debug!("no request received within header read timeout");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SHORT: Duration = Duration::from_millis(200);

    fn test_limits() -> ServeLimits {
        ServeLimits {
            max_connections: 1024,
            tls_handshake_timeout: SHORT,
            header_read_timeout: SHORT,
        }
    }

    struct TestTls {
        server: Arc<rustls::ServerConfig>,
        connector: tokio_rustls::TlsConnector,
    }

    fn test_tls() -> TestTls {
        rustls_post_quantum::provider().install_default().ok();
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = key.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()),
        );
        let mut server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key_der)
            .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        TestTls {
            server: Arc::new(server),
            connector: tokio_rustls::TlsConnector::from(Arc::new(client)),
        }
    }

    async fn start<L: AcceptTcp + Send + 'static>(
        listener: L,
        app: Router,
        tls: &TestTls,
        limits: ServeLimits,
    ) {
        tokio::spawn(serve_tls_with(listener, app, tls.server.clone(), limits));
    }

    async fn tls_connect(
        tls: &TestTls,
        addr: std::net::SocketAddr,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        tls.connector.connect(name, tcp).await.unwrap()
    }

    fn ok_app() -> Router {
        Router::new().route("/", axum::routing::get(|| async { "ok" }))
    }

    /// True when the peer closes (EOF/reset) within `within`; false when it is still open.
    async fn closed_within<S: AsyncReadExt + Unpin>(s: &mut S, within: Duration) -> bool {
        let mut buf = [0u8; 256];
        match tokio::time::timeout(within, s.read(&mut buf)).await {
            Err(_) => false,
            Ok(Ok(0)) | Ok(Err(_)) => true,
            Ok(Ok(_)) => false,
        }
    }

    const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

    async fn get_ok(tls: &TestTls, addr: std::net::SocketAddr) -> bool {
        let mut s = tls_connect(tls, addr).await;
        s.write_all(GET).await.unwrap();
        let mut buf = [0u8; 512];
        let n = s.read(&mut buf).await.unwrap();
        std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("HTTP/1.1 200")
    }

    struct FlakyListener {
        inner: TcpListener,
        remaining_errors: AtomicUsize,
    }

    impl AcceptTcp for FlakyListener {
        async fn accept_tcp(&self) -> std::io::Result<TcpStream> {
            if self
                .remaining_errors
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
            }
            self.inner.accept_tcp().await
        }
    }

    #[test]
    fn descriptor_exhaustion_backs_off_longer_than_other_accept_errors() {
        let emfile = accept_error_backoff(&std::io::Error::from_raw_os_error(libc::EMFILE));
        let other = accept_error_backoff(&std::io::Error::from_raw_os_error(libc::ECONNABORTED));
        assert!(
            emfile > other && !other.is_zero(),
            "EMFILE leaves the connection queued so it needs the longer pause, and no accept \
             error may retry without any pause or the loop spins a core"
        );
    }

    #[tokio::test]
    async fn accept_errors_do_not_stop_the_listener() {
        let tls = test_tls();
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inner.local_addr().unwrap();
        let listener = FlakyListener {
            inner,
            remaining_errors: AtomicUsize::new(3),
        };
        start(listener, ok_app(), &tls, test_limits()).await;

        assert!(
            get_ok(&tls, addr).await,
            "an EMFILE from accept() must not take the whole API down; the loop must keep serving"
        );
    }

    #[tokio::test]
    async fn stalled_tls_handshake_is_dropped() {
        let tls = test_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        start(listener, ok_app(), &tls, test_limits()).await;

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        assert!(
            !closed_within(&mut tcp, SHORT / 4).await,
            "must still be open before the handshake deadline"
        );
        assert!(
            closed_within(&mut tcp, SHORT * 10).await,
            "a client that never finishes the TLS handshake must not hold a connection slot forever"
        );
    }

    #[tokio::test]
    async fn client_that_never_sends_a_request_is_dropped() {
        let tls = test_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        start(listener, ok_app(), &tls, test_limits()).await;

        let mut s = tls_connect(&tls, addr).await;
        assert!(
            closed_within(&mut s, SHORT * 10).await,
            "a client that completes TLS and then goes silent must be dropped (slowloris)"
        );
    }

    #[tokio::test]
    async fn stalled_headers_on_a_reused_connection_are_dropped() {
        let tls = test_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        start(listener, ok_app(), &tls, test_limits()).await;

        let mut s = tls_connect(&tls, addr).await;
        s.write_all(GET).await.unwrap();
        let mut buf = [0u8; 512];
        assert!(s.read(&mut buf).await.unwrap() > 0);
        // Second request on the keep-alive connection: headers never complete.
        s.write_all(b"GET / HTTP/1.1\r\nHost: loc").await.unwrap();
        assert!(
            closed_within(&mut s, SHORT * 10).await,
            "header_read_timeout must also bound headers of later requests on a kept-alive connection"
        );
    }

    #[tokio::test]
    async fn connections_above_the_cap_wait_for_a_free_slot() {
        let tls = test_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limits = ServeLimits {
            max_connections: 1,
            tls_handshake_timeout: Duration::from_secs(30),
            header_read_timeout: Duration::from_secs(30),
        };
        start(listener, ok_app(), &tls, limits).await;

        let first = tls_connect(&tls, addr).await;

        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let second = tls.connector.connect(name, tcp);
        tokio::pin!(second);
        assert!(
            tokio::time::timeout(SHORT, &mut second).await.is_err(),
            "with the cap full the second connection must not be served (backpressure)"
        );

        drop(first);
        let mut second = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .expect("freeing a slot must let the waiting connection through")
            .unwrap();
        second.write_all(GET).await.unwrap();
        let mut buf = [0u8; 512];
        assert!(second.read(&mut buf).await.unwrap() > 0);
    }

    #[tokio::test]
    async fn streaming_response_outlives_handshake_and_header_timeouts() {
        let tls = test_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/watch",
            axum::routing::get(|| async {
                let stream = futures_util::stream::unfold(0u32, |i| async move {
                    if i == 6 {
                        return None;
                    }
                    tokio::time::sleep(SHORT / 2).await;
                    Some((
                        Ok::<_, std::convert::Infallible>(format!("event{i}\n")),
                        i + 1,
                    ))
                });
                axum::body::Body::from_stream(stream)
            }),
        );
        start(listener, app, &tls, test_limits()).await;

        let mut s = tls_connect(&tls, addr).await;
        s.write_all(b"GET /watch HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let started = Instant::now();
        let mut body = Vec::new();
        s.read_to_end(&mut body).await.unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(
            started.elapsed() > SHORT * 2,
            "stream must have lasted past the timeouts"
        );
        assert!(
            text.contains("event5"),
            "a watch/log stream must not be cut by handshake or header timeouts; got {text:?}"
        );
    }
}
