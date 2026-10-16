//! TLS accept loop and the connection-level limits that keep an unauthenticated
//! flood from exhausting or killing the apiserver.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use http_body_util::BodyExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower_service::Service as _;

use crate::auth::PeerCertificate;

/// Limits that apply outside of request processing. A request being served (watch,
/// exec, log streams) is never cut by the handshake, header or idle timeouts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ServeLimits {
    /// Accepted connections in flight, including those still handshaking. Above this
    /// the loop stops calling `accept()` so the kernel backlog absorbs the burst.
    /// 1024 connections at an unmeasured 50-100 KiB each (rustls + hyper buffers) is
    /// ~50-100 MiB on a 1 GiB host, and stays under the raised RLIMIT_NOFILE.
    pub max_connections: usize,
    /// Connections one non-loopback source may hold (per IPv4 address, per IPv6 /64),
    /// so a single client or slowloris burst cannot take every slot. Loopback is
    /// exempt: the control-plane components and the VM port-forward all arrive from
    /// 127.0.0.1. Trade-off: nodes behind one NAT address (or in one IPv6 /64) share
    /// this budget; there is no override.
    pub max_connections_per_ip: usize,
    /// Upper bound on the TLS handshake (Go's net/http has no default; 10 s is
    /// generous for the slowest legitimate client).
    pub tls_handshake_timeout: Duration,
    /// Upper bound on receiving a request's headers (net/http ReadHeaderTimeout).
    /// For HTTP/1 hyper restarts this timer after every response, so a kept-alive
    /// connection that stays idle is also closed after this long (Go's net/http
    /// keeps it until IdleTimeout).
    pub header_read_timeout: Duration,
    /// An HTTP/2 connection with no request or open stream for this long is sent
    /// GOAWAY and closed. Matches kube-apiserver's `http2.Server.IdleTimeout` of 90 s.
    pub h2_idle_timeout: Duration,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_connections_per_ip: 256,
            tls_handshake_timeout: Duration::from_secs(10),
            header_read_timeout: Duration::from_secs(10),
            h2_idle_timeout: Duration::from_secs(90),
        }
    }
}

pub(crate) trait AcceptTcp {
    fn accept_tcp(&self) -> impl Future<Output = std::io::Result<(TcpStream, SocketAddr)>> + Send;
}

impl AcceptTcp for TcpListener {
    async fn accept_tcp(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        self.accept().await
    }
}

/// Counts connections per source IP. Loopback is never counted.
#[derive(Clone)]
struct PerIpLimiter {
    max: usize,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

struct IpSlot {
    ip: IpAddr,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl PerIpLimiter {
    fn new(max: usize) -> Self {
        Self {
            max,
            counts: Arc::default(),
        }
    }

    /// `Ok(None)` for exempt (loopback) peers, `Err` when `ip` is at its cap.
    fn acquire(&self, ip: IpAddr) -> Result<Option<IpSlot>, ()> {
        let ip = ip.to_canonical();
        if ip.is_loopback() {
            return Ok(None);
        }
        // A single IPv6 host controls a whole /64, so per-address counting is no limit.
        let ip = match ip {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & (u128::MAX << 64)).into()),
            v4 => v4,
        };
        let mut counts = self.counts.lock().unwrap();
        let n = counts.entry(ip).or_insert(0);
        if *n >= self.max {
            return Err(());
        }
        *n += 1;
        Ok(Some(IpSlot {
            ip,
            counts: Arc::clone(&self.counts),
        }))
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap();
        if let Some(n) = counts.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// Requests (and their response bodies) currently open on one connection.
struct InFlight(tokio::sync::watch::Sender<usize>);

struct InFlightGuard(Arc<InFlight>);

impl InFlight {
    fn start(self: &Arc<Self>) -> InFlightGuard {
        self.0.send_modify(|n| *n += 1);
        InFlightGuard(Arc::clone(self))
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        (self.0).0.send_modify(|n| *n -= 1);
    }
}

/// Waits for a connection that was sent GOAWAY to finish. Streams that raced the idle
/// deadline run to completion (as in Go's http2); only a connection that has had
/// nothing in flight for `window` is abandoned, so an unresponsive peer cannot hold
/// the slot.
async fn drain_after_goaway(
    conn: impl Future + Unpin,
    in_flight: tokio::sync::watch::Receiver<usize>,
    window: Duration,
) {
    tokio::select! {
        _ = conn => {}
        () = idle_for(in_flight, window) => {}
    }
}

/// Resolves once nothing has been in flight for `window`.
async fn idle_for(mut in_flight: tokio::sync::watch::Receiver<usize>, window: Duration) {
    loop {
        while *in_flight.borrow_and_update() != 0 {
            if in_flight.changed().await.is_err() {
                return;
            }
        }
        tokio::select! {
            () = tokio::time::sleep(window) => return,
            r = in_flight.changed() => if r.is_err() { return },
        }
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
    let per_ip = PerIpLimiter::new(limits.max_connections_per_ip);
    let mut last_error_log: Option<Instant> = None;
    let mut last_ip_log: Option<Instant> = None;

    loop {
        // Take the permit before accepting: at the cap, connections wait in the kernel
        // backlog instead of costing a descriptor and a task.
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .expect("semaphore is never closed");
        let (tcp_stream, peer_addr) = match listener.accept_tcp().await {
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
        let ip_slot = match per_ip.acquire(peer_addr.ip()) {
            Ok(slot) => slot,
            Err(()) => {
                if last_ip_log.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                    tracing::warn!(
                        "rejecting connection from {}: per-IP limit of {} reached",
                        peer_addr.ip(),
                        limits.max_connections_per_ip
                    );
                    last_ip_log = Some(Instant::now());
                }
                continue;
            }
        };
        crate::configure_accepted_socket(&tcp_stream);
        let acceptor = acceptor.clone();
        let app = app.clone();
        let conn_builder = conn_builder.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let _ip_slot = ip_slot;
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

            let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let request_seen = Arc::new(AtomicBool::new(false));
            let seen = Arc::clone(&request_seen);
            let (in_flight_tx, in_flight_rx) = tokio::sync::watch::channel(0usize);
            let in_flight = Arc::new(InFlight(in_flight_tx));
            let service = hyper::service::service_fn(move |mut req: axum::http::Request<_>| {
                seen.store(true, Ordering::Relaxed);
                let guard = in_flight.start();
                let peer_cert = Arc::clone(&peer_cert);
                let mut app = app.clone();
                async move {
                    if let Some(cert) = peer_cert.as_ref().as_ref() {
                        req.extensions_mut().insert(cert.clone());
                    }
                    let (parts, body) = app.call(req).await.unwrap().into_parts();
                    // The guard lives as long as the response body, so a watch or log
                    // stream keeps the connection out of the idle window.
                    let body = body.map_frame(move |frame| {
                        let _ = &guard;
                        frame
                    });
                    Ok::<_, std::convert::Infallible>(axum::http::Response::from_parts(parts, body))
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
            let drain_rx = in_flight_rx.clone();
            // HTTP/1 idleness is already bounded by header_read_timeout.
            let idle_deadline = async {
                if is_h2 {
                    idle_for(in_flight_rx, limits.h2_idle_timeout).await;
                } else {
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
                () = idle_deadline => {
                    tracing::debug!("closing idle HTTP/2 connection");
                    conn.as_mut().graceful_shutdown();
                    drain_after_goaway(&mut conn, drain_rx, limits.header_read_timeout).await;
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
            max_connections_per_ip: 1024,
            tls_handshake_timeout: SHORT,
            header_read_timeout: SHORT,
            h2_idle_timeout: SHORT,
        }
    }

    struct TestTls {
        server: Arc<rustls::ServerConfig>,
        connector: tokio_rustls::TlsConnector,
        h2_connector: tokio_rustls::TlsConnector,
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
        let mut h2_client = client.clone();
        h2_client.alpn_protocols = vec![b"h2".to_vec()];
        TestTls {
            server: Arc::new(server),
            connector: tokio_rustls::TlsConnector::from(Arc::new(client)),
            h2_connector: tokio_rustls::TlsConnector::from(Arc::new(h2_client)),
        }
    }

    type H2Sender = hyper::client::conn::http2::SendRequest<axum::body::Body>;

    /// Opens an h2 connection; the receiver resolves when the server side closes it.
    async fn h2_connect(
        tls: &TestTls,
        addr: SocketAddr,
    ) -> (H2Sender, tokio::sync::oneshot::Receiver<()>) {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let stream = tls.h2_connector.connect(name, tcp).await.unwrap();
        let (sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(stream),
        )
        .await
        .unwrap();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = conn.await;
            let _ = closed_tx.send(());
        });
        (sender, closed_rx)
    }

    fn h2_get(path: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::get(format!("https://localhost{path}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    async fn is_closed_within(
        rx: &mut tokio::sync::oneshot::Receiver<()>,
        within: Duration,
    ) -> bool {
        tokio::time::timeout(within, rx).await.is_ok()
    }

    /// Reports each accepted connection as coming from the next queued address
    /// (then `fallback`), so per-IP behaviour can be tested without extra local IPs.
    struct FakePeerListener {
        inner: TcpListener,
        peers: Mutex<std::collections::VecDeque<IpAddr>>,
        fallback: IpAddr,
    }

    impl AcceptTcp for FakePeerListener {
        async fn accept_tcp(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
            let (s, real) = self.inner.accept().await?;
            let ip = self
                .peers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(self.fallback);
            Ok((s, SocketAddr::new(ip, real.port())))
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

    async fn get_ok_on<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S) -> bool {
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
        async fn accept_tcp(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
            if self
                .remaining_errors
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
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
            ..test_limits()
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

    #[tokio::test]
    async fn idle_h2_connection_is_closed_so_it_cannot_pin_a_slot_forever() {
        let tls = test_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        start(listener, ok_app(), &tls, test_limits()).await;

        let (mut sender, mut closed) = h2_connect(&tls, addr).await;
        let resp = sender.send_request(h2_get("/")).await.unwrap();
        assert_eq!(resp.status(), 200);
        resp.into_body().collect().await.unwrap();

        assert!(
            is_closed_within(&mut closed, SHORT * 10).await,
            "an h2 connection that served one request and went quiet must be closed after the \
             idle window, otherwise 1024 such clients lock every other client out"
        );
    }

    #[tokio::test]
    async fn h2_connection_with_open_stream_is_not_closed_by_idle_policy() {
        let tls = test_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/watch",
            axum::routing::get(|| async {
                let stream = futures_util::stream::unfold(0u32, |i| async move {
                    if i == 8 {
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

        let (mut sender, mut closed) = h2_connect(&tls, addr).await;
        let started = Instant::now();
        let resp = sender.send_request(h2_get("/watch")).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            started.elapsed() > SHORT * 3,
            "stream must outlast several idle windows for this test to mean anything"
        );
        assert!(
            String::from_utf8_lossy(&body).contains("event7"),
            "a watch/exec/log stream on an otherwise quiet h2 connection must not be cut by the \
             idle policy; got {body:?}"
        );
        assert!(
            is_closed_within(&mut closed, SHORT * 10).await,
            "once the stream ends the connection is idle and must be closed"
        );
    }

    #[tokio::test]
    async fn one_ip_cannot_take_every_slot_but_other_ips_and_loopback_still_connect() {
        let tls = test_tls();
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inner.local_addr().unwrap();
        let abuser: IpAddr = "203.0.113.7".parse().unwrap();
        let kubelet: IpAddr = "198.51.100.9".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let listener = FakePeerListener {
            inner,
            peers: Mutex::new(
                [
                    abuser, abuser, abuser, kubelet, loopback, loopback, loopback,
                ]
                .into(),
            ),
            fallback: abuser,
        };
        let limits = ServeLimits {
            max_connections_per_ip: 2,
            tls_handshake_timeout: Duration::from_secs(30),
            header_read_timeout: Duration::from_secs(30),
            ..test_limits()
        };
        start(listener, ok_app(), &tls, limits).await;

        let first = tls_connect(&tls, addr).await;
        let _second = tls_connect(&tls, addr).await;

        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        assert!(
            tls.connector.connect(name, tcp).await.is_err(),
            "the 3rd connection from one IP must be refused so one client cannot exhaust the cap"
        );

        let mut others = vec![tls_connect(&tls, addr).await];
        for _ in 0..3 {
            others.push(tls_connect(&tls, addr).await);
        }
        assert!(
            get_ok_on(others.last_mut().unwrap()).await,
            "loopback is exempt: control-plane components share 127.0.0.1 and must not be capped"
        );

        drop(first);
        let mut served = false;
        for _ in 0..50 {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            if tls.connector.connect(name, tcp).await.is_ok() {
                served = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            served,
            "closing a connection must free its per-IP slot or the client is locked out for good"
        );
    }

    #[test]
    fn ipv6_hosts_in_one_slash_64_share_a_cap_so_address_rotation_cannot_evade_it() {
        let limiter = PerIpLimiter::new(2);
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other_prefix: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        let _s1 = limiter.acquire(a).unwrap();
        let _s2 = limiter.acquire(b).unwrap();
        assert!(
            limiter
                .acquire("2001:db8:1:2::77".parse().unwrap())
                .is_err(),
            "a client with a /64 can rotate addresses; the cap must count the whole prefix"
        );
        assert!(
            limiter.acquire(other_prefix).is_ok(),
            "a different /64 is a different client"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_that_raced_the_idle_deadline_survives_goaway_drain() {
        let window = Duration::from_secs(10);
        let (tx, rx) = tokio::sync::watch::channel(1usize);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let mut drain = tokio::spawn(drain_after_goaway(done_rx, rx, window));

        tokio::time::sleep(window * 5).await;
        assert!(
            !drain.is_finished(),
            "a watch that raced the idle deadline must not be cut once GOAWAY is sent"
        );

        tx.send_modify(|n| *n = 0);
        tokio::time::sleep(window + Duration::from_millis(1)).await;
        assert!(
            drain.is_finished(),
            "once nothing is in flight an unresponsive peer must not hold the slot past the window"
        );
        let _ = (&mut drain).await;
        drop(done_tx);
    }

    #[tokio::test(start_paused = true)]
    async fn connection_closing_ends_the_drain_immediately() {
        let (_tx, rx) = tokio::sync::watch::channel(1usize);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let drain = tokio::spawn(drain_after_goaway(done_rx, rx, Duration::from_secs(10)));
        done_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_millis(1), drain)
            .await
            .expect("drain must end as soon as the connection does")
            .unwrap();
    }

    #[test]
    fn v4_mapped_loopback_is_exempt_from_the_per_ip_cap() {
        let limiter = PerIpLimiter::new(1);
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let held: Vec<_> = (0..3).map(|_| limiter.acquire(mapped).unwrap()).collect();
        assert!(
            held.iter().all(Option::is_none),
            "a dual-stack listener reports IPv4 loopback as ::ffff:127.0.0.1; it must stay exempt"
        );
    }
}
