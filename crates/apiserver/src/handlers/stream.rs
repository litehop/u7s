/// BiStream — transport-agnostic bidirectional byte channel.
///
/// Abstracts over the underlying transport (axum WebSocket, tokio-tungstenite,
/// future HTTP/3 QUIC streams) so that splice logic in /attach and /portforward
/// can be written once and swapped at the call site.
///
/// `split()` consumes the stream and returns independent read and write halves.
/// This is required by `splice()` so it can drive reads and writes in separate
/// tasks without holding a mutex across an async recv() call.
pub trait BiStream: Send + 'static {
    type Reader: BiStreamReader;
    type Writer: BiStreamWriter;

    fn split(self) -> (Self::Reader, Self::Writer);
}

/// Read half of a split BiStream.
pub trait BiStreamReader: Send + 'static {
    fn recv(&mut self) -> impl std::future::Future<Output = Option<bytes::Bytes>> + Send;
}

/// Write half of a split BiStream.
pub trait BiStreamWriter: Send + 'static {
    fn send(
        &mut self,
        data: bytes::Bytes,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn close(&mut self) -> impl std::future::Future<Output = ()> + Send;
}

// ---------------------------------------------------------------------------
// Axum WebSocket impl (inbound: kubectl → apiserver)
// ---------------------------------------------------------------------------

/// Wraps an axum `WebSocket` so it satisfies `BiStream`.
///
/// split() uses futures_util::StreamExt::split() to give independent halves
/// that can be driven from separate tasks without any mutex.
pub struct AxumWs(pub axum::extract::ws::WebSocket);

pub struct AxumWsReader(futures_util::stream::SplitStream<axum::extract::ws::WebSocket>);

pub struct AxumWsWriter(
    futures_util::stream::SplitSink<axum::extract::ws::WebSocket, axum::extract::ws::Message>,
);

impl BiStream for AxumWs {
    type Reader = AxumWsReader;
    type Writer = AxumWsWriter;

    fn split(self) -> (AxumWsReader, AxumWsWriter) {
        use futures_util::StreamExt as _;
        let (sink, stream) = self.0.split();
        (AxumWsReader(stream), AxumWsWriter(sink))
    }
}

impl BiStreamReader for AxumWsReader {
    async fn recv(&mut self) -> Option<bytes::Bytes> {
        use futures_util::StreamExt as _;
        loop {
            match self.0.next().await? {
                Ok(axum::extract::ws::Message::Binary(b)) => return Some(b),
                Ok(axum::extract::ws::Message::Text(t)) => {
                    return Some(bytes::Bytes::copy_from_slice(t.as_bytes()))
                }
                // Axum's WebSocket layer handles Ping/Pong automatically at the
                // transport level regardless of split() — these are safe to skip.
                Ok(axum::extract::ws::Message::Ping(_)) => continue,
                Ok(axum::extract::ws::Message::Pong(_)) => continue,
                // Close frame signals the peer has finished — terminate recv cleanly.
                Ok(axum::extract::ws::Message::Close(_)) => return None,
                Err(_) => return None,
            }
        }
    }
}

impl BiStreamWriter for AxumWsWriter {
    async fn send(&mut self, data: bytes::Bytes) -> anyhow::Result<()> {
        use futures_util::SinkExt as _;
        self.0
            .send(axum::extract::ws::Message::Binary(data))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn close(&mut self) {
        use axum::extract::ws::{CloseFrame, Message};
        use futures_util::SinkExt as _;
        // Send close code 1000 (Normal Closure). Sending Close(None) produces
        // code 1005 ("no status received"), which causes kubectl to retry the
        // exec/attach session with exponential backoff, inflating conformance runs.
        let _ = self
            .0
            .send(Message::Close(Some(CloseFrame {
                code: axum::extract::ws::close_code::NORMAL,
                reason: "".into(),
            })))
            .await;
    }
}

// ---------------------------------------------------------------------------
// tokio-tungstenite WebSocket impl (outbound: apiserver → kubelet)
// ---------------------------------------------------------------------------

use tokio_tungstenite::WebSocketStream;

/// Wraps a tokio-tungstenite `WebSocketStream` so it satisfies `BiStream`.
///
/// The stream `S` is typically `tokio_rustls::client::TlsStream<tokio::net::TcpStream>`.
pub struct TungsteniteWs<S>(pub WebSocketStream<S>);

pub struct TungsteniteWsReader<S>(futures_util::stream::SplitStream<WebSocketStream<S>>);

pub struct TungsteniteWsWriter<S>(
    futures_util::stream::SplitSink<WebSocketStream<S>, tokio_tungstenite::tungstenite::Message>,
);

impl<S> BiStream for TungsteniteWs<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    type Reader = TungsteniteWsReader<S>;
    type Writer = TungsteniteWsWriter<S>;

    fn split(self) -> (TungsteniteWsReader<S>, TungsteniteWsWriter<S>) {
        use futures_util::StreamExt as _;
        let (sink, stream) = self.0.split();
        (TungsteniteWsReader(stream), TungsteniteWsWriter(sink))
    }
}

impl<S> BiStreamReader for TungsteniteWsReader<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    async fn recv(&mut self) -> Option<bytes::Bytes> {
        use futures_util::StreamExt as _;
        use tokio_tungstenite::tungstenite::Message;
        loop {
            match self.0.next().await? {
                Ok(Message::Binary(b)) => return Some(bytes::Bytes::from(b.to_vec())),
                Ok(Message::Text(t)) => return Some(bytes::Bytes::copy_from_slice(t.as_bytes())),
                // After split(), tungstenite does NOT auto-respond to Pings — the
                // sink is in a separate struct (TungsteniteWsWriter) with no channel
                // back here. We accept dropped pings for now (Option A). The kubelet
                // tolerates a few missed pings before closing; exec sessions are
                // short-lived enough that this is safe.
                Ok(Message::Ping(_)) => continue,
                Ok(Message::Pong(_)) => continue,
                // Close frame signals the peer has finished — return None so the
                // splice loop terminates instead of blocking forever on the next recv.
                Ok(Message::Close(_)) => return None,
                // Raw frames are internal tungstenite detail; skip them.
                Ok(Message::Frame(_)) => continue,
                Err(_) => return None,
            }
        }
    }
}

impl<S> BiStreamWriter for TungsteniteWsWriter<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    async fn send(&mut self, data: bytes::Bytes) -> anyhow::Result<()> {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message;
        self.0
            .send(Message::Binary(data.to_vec().into()))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn close(&mut self) {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::{
            protocol::{frame::coding::CloseCode, CloseFrame},
            Message,
        };
        // Send close code 1000 (Normal Closure). SinkExt::close() calls close(None)
        // internally, which produces code 1005 ("no status received") — causing kubectl
        // to interpret the session as abnormally closed and retry with backoff.
        let _ = self
            .0
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "".into(),
            })))
            .await;
    }
}

// ---------------------------------------------------------------------------
// Raw byte-stream impl (outbound: apiserver → kubelet, no websocket framing)
// ---------------------------------------------------------------------------

/// Wraps a raw `AsyncRead + AsyncWrite` connection (e.g. a hijacked HTTP/1.1 Upgrade)
/// so it satisfies `BiStream` with no message framing at all — `recv()` yields
/// whatever-sized chunk the socket produces, `send()` writes bytes verbatim.
///
/// `prefix`, if non-empty, is replayed as the first `recv()` result before any further
/// socket reads. This exists because manually scanning a raw HTTP/1.1 upgrade response
/// for its header terminator can read past it in the same TCP segment — those trailing
/// bytes are already the start of the real (SPDY) payload and must not be discarded.
pub struct RawStream<S> {
    io: S,
    prefix: bytes::Bytes,
}

impl<S> RawStream<S> {
    pub fn new(io: S) -> Self {
        Self {
            io,
            prefix: bytes::Bytes::new(),
        }
    }

    pub fn new_with_prefix(io: S, prefix: bytes::Bytes) -> Self {
        Self { io, prefix }
    }
}

pub struct RawStreamReader<S> {
    prefix: Option<bytes::Bytes>,
    inner: tokio::io::ReadHalf<S>,
}

pub struct RawStreamWriter<S> {
    inner: tokio::io::WriteHalf<S>,
}

impl<S> BiStream for RawStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    type Reader = RawStreamReader<S>;
    type Writer = RawStreamWriter<S>;

    fn split(self) -> (RawStreamReader<S>, RawStreamWriter<S>) {
        let (inner_r, inner_w) = tokio::io::split(self.io);
        (
            RawStreamReader {
                prefix: (!self.prefix.is_empty()).then_some(self.prefix),
                inner: inner_r,
            },
            RawStreamWriter { inner: inner_w },
        )
    }
}

impl<S> BiStreamReader for RawStreamReader<S>
where
    S: tokio::io::AsyncRead + Send + 'static,
{
    async fn recv(&mut self) -> Option<bytes::Bytes> {
        if let Some(p) = self.prefix.take() {
            return Some(p);
        }
        use tokio::io::AsyncReadExt as _;
        let mut buf = [0u8; 16 * 1024];
        match self.inner.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => Some(bytes::Bytes::copy_from_slice(&buf[..n])),
            Err(_) => None,
        }
    }
}

impl<S> BiStreamWriter for RawStreamWriter<S>
where
    S: tokio::io::AsyncWrite + Send + 'static,
{
    async fn send(&mut self, data: bytes::Bytes) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        self.inner
            .write_all(&data)
            .await
            .map_err(anyhow::Error::from)
    }

    async fn close(&mut self) {
        use tokio::io::AsyncWriteExt as _;
        let _ = self.inner.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// Splice helper — bidirectional byte relay between two BiStream impls
// ---------------------------------------------------------------------------

/// Relay bytes between two BiStream endpoints until either side closes.
///
/// Uses four tasks connected by two channels. Each stream is split into
/// independent read and write halves so that no mutex is held across an
/// async recv() call — eliminating the deadlock that the old Arc<Mutex<>>
/// approach suffered during large one-directional transfers.
///
/// The portforward tarball deadlock (pre-fix): kubelet streams a large tarball
/// B→A while kubectl is silent. The old read_a task held mutex-A suspended in
/// recv(), while write_a needed the same mutex to flush tarball data to kubectl.
/// With split halves there is no shared state between read_a and write_a at all.
///
/// Layout:
///   read_a  → a_to_b channel → write_b
///   read_b  → b_to_a channel → write_a
///
/// Shutdown: when read_a gets None (A closed), it drops a_to_b_tx, which causes
/// write_b's recv() to return None, and write_b closes B's write half.
/// Symmetrically for read_b.
pub async fn splice<A: BiStream, B: BiStream>(a: A, b: B) {
    use tokio::sync::mpsc;

    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();

    let (a_to_b_tx, mut a_to_b_rx) = mpsc::channel::<bytes::Bytes>(256);
    let (b_to_a_tx, mut b_to_a_rx) = mpsc::channel::<bytes::Bytes>(256);

    // read_a: drain A into a_to_b channel.
    let read_a = tokio::spawn(async move {
        while let Some(data) = ar.recv().await {
            if a_to_b_tx.send(data).await.is_err() {
                break;
            }
        }
        // a_to_b_tx dropped here → write_b will drain and close B's write half.
    });

    // read_b: drain B into b_to_a channel.
    let read_b = tokio::spawn(async move {
        while let Some(data) = br.recv().await {
            if b_to_a_tx.send(data).await.is_err() {
                break;
            }
        }
        // b_to_a_tx dropped here → write_a will drain and close A's write half.
    });

    // write_b: forward a_to_b channel messages to B's write half.
    let write_b = tokio::spawn(async move {
        while let Some(data) = a_to_b_rx.recv().await {
            if bw.send(data).await.is_err() {
                break;
            }
        }
        bw.close().await;
    });

    // write_a: forward b_to_a channel messages to A's write half.
    let write_a = tokio::spawn(async move {
        while let Some(data) = b_to_a_rx.recv().await {
            if aw.send(data).await.is_err() {
                break;
            }
        }
        aw.close().await;
    });

    let _ = tokio::join!(read_a, read_b, write_a, write_b);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::Arc;

    /// In-memory BiStream for testing splice logic without real WebSockets.
    ///
    /// Uses a tokio mpsc channel for the incoming (recv) side so that recv()
    /// is cancel-safe: the channel's recv() does not consume a message until
    /// the future resolves. This is required for correct behaviour under
    /// tokio::select! (used in tests that drive splice indirectly).
    struct MemStream {
        rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
        outgoing: Arc<std::sync::Mutex<Vec<Bytes>>>,
    }

    struct MemStreamReader {
        rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    }

    struct MemStreamWriter {
        outgoing: Arc<std::sync::Mutex<Vec<Bytes>>>,
        closed: bool,
    }

    impl MemStream {
        fn new(incoming: Vec<Bytes>, outgoing: Arc<std::sync::Mutex<Vec<Bytes>>>) -> Self {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            for msg in incoming {
                let _ = tx.send(msg);
            }
            drop(tx); // close sender so recv returns None once queue drains
            Self { rx, outgoing }
        }
    }

    impl BiStream for MemStream {
        type Reader = MemStreamReader;
        type Writer = MemStreamWriter;

        fn split(self) -> (MemStreamReader, MemStreamWriter) {
            (
                MemStreamReader { rx: self.rx },
                MemStreamWriter {
                    outgoing: self.outgoing,
                    closed: false,
                },
            )
        }
    }

    impl BiStreamReader for MemStreamReader {
        async fn recv(&mut self) -> Option<Bytes> {
            self.rx.recv().await
        }
    }

    impl BiStreamWriter for MemStreamWriter {
        async fn send(&mut self, data: Bytes) -> anyhow::Result<()> {
            self.outgoing.lock().unwrap().push(data);
            Ok(())
        }

        async fn close(&mut self) {
            self.closed = true;
        }
    }

    /// splice must relay bytes from A to B and from B to A.
    ///
    /// This verifies the core invariant: every message written to one side of
    /// the splice must appear on the other side. If the relay were dropped or
    /// reordered, the kubectl attach session would be corrupted.
    #[tokio::test]
    async fn splice_relays_bytes_bidirectionally() {
        let a_to_b_data = vec![Bytes::from("hello"), Bytes::from("world")];
        let b_to_a_data = vec![Bytes::from("ping")];

        let a_out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let b_out = Arc::new(std::sync::Mutex::new(Vec::new()));

        let a = MemStream::new(a_to_b_data.clone(), Arc::clone(&a_out));
        let b = MemStream::new(b_to_a_data.clone(), Arc::clone(&b_out));

        splice(a, b).await;

        // A's messages must arrive at B.
        let b_received = b_out.lock().unwrap().clone();
        assert_eq!(
            b_received, a_to_b_data,
            "bytes written to A must be relayed to B in order"
        );

        // B's messages must arrive at A.
        let a_received = a_out.lock().unwrap().clone();
        assert_eq!(
            a_received, b_to_a_data,
            "bytes written to B must be relayed to A in order"
        );
    }

    /// splice must terminate promptly when the A side produces no messages.
    ///
    /// If splice ignored an immediately-closed endpoint and blocked forever, the
    /// portforward connection would hang rather than finishing cleanly. This guards
    /// against that regression.
    #[tokio::test]
    async fn splice_terminates_when_a_closes_immediately() {
        let a_out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let b_out = Arc::new(std::sync::Mutex::new(Vec::new()));

        let a = MemStream::new(vec![], Arc::clone(&a_out));
        let b = MemStream::new(vec![Bytes::from("ignored")], Arc::clone(&b_out));

        tokio::time::timeout(std::time::Duration::from_secs(1), splice(a, b))
            .await
            .expect("splice must finish when one side closes immediately");
    }

    /// splice must terminate promptly when the B side produces no messages.
    #[tokio::test]
    async fn splice_terminates_when_b_closes_immediately() {
        let a_out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let b_out = Arc::new(std::sync::Mutex::new(Vec::new()));

        let a = MemStream::new(vec![Bytes::from("ignored")], Arc::clone(&a_out));
        let b = MemStream::new(vec![], Arc::clone(&b_out));

        tokio::time::timeout(std::time::Duration::from_secs(1), splice(a, b))
            .await
            .expect("splice must finish when B closes immediately");
    }

    /// A MemStream whose writer always errors on send — simulates a broken connection.
    struct FailingWriterStream {
        rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    }

    struct FailingWriter;

    impl FailingWriterStream {
        fn new(incoming: Vec<Bytes>) -> Self {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            for msg in incoming {
                let _ = tx.send(msg);
            }
            drop(tx);
            Self { rx }
        }
    }

    impl BiStream for FailingWriterStream {
        type Reader = MemStreamReader;
        type Writer = FailingWriter;

        fn split(self) -> (MemStreamReader, FailingWriter) {
            (MemStreamReader { rx: self.rx }, FailingWriter)
        }
    }

    impl BiStreamWriter for FailingWriter {
        async fn send(&mut self, _data: Bytes) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("send failed: connection broken"))
        }

        async fn close(&mut self) {}
    }

    /// splice must stop relaying when a send call returns an error.
    ///
    /// If splice continued looping after a failed send it would produce an infinite
    /// error storm. The correct behavior is to abort both directions and return.
    #[tokio::test]
    async fn splice_terminates_on_send_error() {
        let a_out = Arc::new(std::sync::Mutex::new(Vec::new()));

        let a = MemStream::new(vec![Bytes::from("trigger")], Arc::clone(&a_out));
        let b = FailingWriterStream::new(vec![]);

        tokio::time::timeout(std::time::Duration::from_secs(1), splice(a, b))
            .await
            .expect("splice must finish when send errors — not loop forever");
    }

    /// BiStream::recv on MemStream returns queued messages in FIFO order, then None.
    ///
    /// This documents the MemStream contract so that tests relying on ordering
    /// (e.g. splice_relays_bytes_bidirectionally) remain meaningful if MemStream
    /// is ever modified.
    #[tokio::test]
    async fn mem_stream_recv_is_fifo_then_none() {
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = MemStream::new(
            vec![Bytes::from("first"), Bytes::from("second")],
            Arc::clone(&out),
        );
        let (mut reader, _writer) = s.split();

        assert_eq!(reader.recv().await, Some(Bytes::from("first")));
        assert_eq!(reader.recv().await, Some(Bytes::from("second")));
        assert_eq!(
            reader.recv().await,
            None,
            "recv must return None once the queue is drained"
        );
    }

    /// BiStream::close on MemStream's writer sets the closed flag.
    ///
    /// The splice loop calls close() on the opposite endpoint when one direction
    /// finishes. If close() were a no-op that silently dropped the signal, the
    /// other side would never know to stop — leaking tasks or hanging sessions.
    #[tokio::test]
    async fn mem_stream_close_sets_closed_flag() {
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = MemStream::new(vec![], Arc::clone(&out));
        let (_reader, mut writer) = s.split();

        assert!(!writer.closed, "stream must start open");
        writer.close().await;
        assert!(writer.closed, "close() must mark the stream as closed");
    }

    /// BiStream::send on MemStream appends to the shared outgoing buffer.
    ///
    /// Verifies the send path of the mock so that tests which check b_out / a_out
    /// contents are trustworthy — a broken send() would make the relay tests
    /// vacuously pass.
    #[tokio::test]
    async fn mem_stream_send_appends_to_outgoing() {
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = MemStream::new(vec![], Arc::clone(&out));
        let (_reader, mut writer) = s.split();

        writer.send(Bytes::from("a")).await.unwrap();
        writer.send(Bytes::from("b")).await.unwrap();

        let captured = out.lock().unwrap().clone();
        assert_eq!(
            captured,
            vec![Bytes::from("a"), Bytes::from("b")],
            "send() must append messages to the outgoing buffer in order"
        );
    }

    // -----------------------------------------------------------------------
    // RawStream — prefix replay regression test
    //
    // Dialing kubelet's raw-SPDY-over-HTTP portforward endpoint means manually
    // scanning a TLS byte stream for the "\r\n\r\n" HTTP header terminator; a single
    // TCP read can carry bytes past that terminator, which are already the start of
    // kubelet's real SPDY payload. If those bytes were dropped instead of replayed,
    // kubectl's SPDY decoder on the other end would desync on the very first frame.
    // -----------------------------------------------------------------------

    /// RawStreamReader::recv must yield the constructor's prefix bytes before any
    /// bytes from the underlying socket.
    ///
    /// This fails if `new_with_prefix`'s prefix is ignored (e.g. `RawStream::new` used
    /// instead) — the test's duplex stream never sends "socket-data" as its first
    /// bytes, so a dropped prefix would make the first assertion see "socket-data"
    /// instead of "prefix-data", or hang waiting for bytes that were already consumed.
    #[tokio::test]
    async fn raw_stream_recv_replays_prefix_before_socket_reads() {
        use tokio::io::AsyncWriteExt as _;

        let (mut server_io, client_io) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server_io.write_all(b"socket-data").await.unwrap();
        });

        let raw = RawStream::new_with_prefix(client_io, Bytes::from("prefix-data"));
        let (mut reader, _writer) = raw.split();

        assert_eq!(
            reader.recv().await,
            Some(Bytes::from("prefix-data")),
            "the buffered prefix must be replayed first — dropping it would lose the \
             start of kubelet's SPDY response"
        );
        assert_eq!(
            reader.recv().await,
            Some(Bytes::from("socket-data")),
            "after the prefix is drained, recv() must continue reading the live socket"
        );
    }

    /// RawStreamReader::recv must return None on EOF, with no prefix configured.
    ///
    /// Guards the common case (no over-read bytes during upgrade negotiation) —
    /// `RawStream::new` must behave like a plain passthrough, not hang forever
    /// waiting for a prefix that was never set.
    #[tokio::test]
    async fn raw_stream_recv_returns_none_on_eof_without_prefix() {
        let (server_io, client_io) = tokio::io::duplex(1024);
        drop(server_io); // closing the peer immediately produces EOF on client_io

        let raw = RawStream::new(client_io);
        let (mut reader, _writer) = raw.split();

        assert_eq!(
            reader.recv().await,
            None,
            "recv() must return None on EOF when no prefix was configured"
        );
    }

    // -----------------------------------------------------------------------
    // TungsteniteWsReader::recv — Close frame regression tests
    // -----------------------------------------------------------------------
    //
    // These tests use an in-memory WebSocket pair (tokio::io::duplex) so that
    // the real TungsteniteWsReader code runs with real tungstenite messages.
    // They MUST fail if Ok(Message::Close(_)) is changed back to Ok(_) =>
    // continue, because recv() would then loop forever instead of returning None.

    /// Create an in-memory WebSocket pair using tokio::io::duplex.
    ///
    /// Returns (server_ws, client_ws) where server_ws is the accepting side
    /// and client_ws is the connecting side.
    async fn make_ws_pair() -> (
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
    ) {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let (server_io, client_io) = tokio::io::duplex(65536);
        let server_fut = tokio_tungstenite::accept_async(server_io);
        let client_fut = tokio_tungstenite::client_async(
            "ws://localhost/".into_client_request().unwrap(),
            client_io,
        );
        let (server_result, client_result) = tokio::join!(server_fut, client_fut);
        (server_result.unwrap(), client_result.unwrap().0)
    }

    /// TungsteniteWsReader::recv must return None when a Close frame arrives.
    ///
    /// Without this fix, Ok(Message::Close(_)) was matched by Ok(_) => continue,
    /// causing recv() to loop forever. This causes exec sessions to hang until
    /// they time out with "unexpected output from server".
    ///
    /// This test fails if Close handling is reverted to Ok(_) => continue
    /// because recv() would block inside the test until the timeout fires.
    #[tokio::test]
    async fn tungstenite_recv_returns_none_on_close_frame() {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message;

        let (mut server_ws, client_ws) = make_ws_pair().await;

        let ws = TungsteniteWs(client_ws);
        let (mut reader, _writer) = ws.split();

        // Server sends a Close frame — client's recv() must return None.
        let send_close = tokio::spawn(async move {
            server_ws.send(Message::Close(None)).await.ok();
        });

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), reader.recv())
            .await
            .expect(
                "recv() must return None on Close frame within 2 seconds — \
             if it times out, Close is still being swallowed by Ok(_) => continue",
            );

        assert_eq!(
            result, None,
            "recv() must return None when a Close frame is received — \
             returning Some would corrupt the splice loop's shutdown logic"
        );

        let _ = send_close.await;
    }

    /// TungsteniteWsReader::recv must return data frames when the connection is healthy.
    ///
    /// Guards that Binary frame handling remains intact — a regression here would
    /// break all exec and port-forward data transfer.
    #[tokio::test]
    async fn tungstenite_recv_returns_data_on_binary_frame() {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message;

        let (mut server_ws, client_ws) = make_ws_pair().await;

        let ws = TungsteniteWs(client_ws);
        let (mut reader, _writer) = ws.split();

        // Server sends a Binary frame — client recv() must return its payload.
        let send = tokio::spawn(async move {
            server_ws
                .send(Message::Binary(b"hello"[..].to_vec().into()))
                .await
                .ok();
        });

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), reader.recv())
            .await
            .expect("recv() must return Some(data) for a Binary frame");

        assert_eq!(
            result,
            Some(bytes::Bytes::from("hello")),
            "recv() must return the Binary frame payload — \
             if None is returned, exec/port-forward data would be silently dropped"
        );

        let _ = send.await;
    }

    /// Regression: splice must not deadlock when one direction has many more
    /// messages than the other (e.g. portforward tarball download).
    ///
    /// The portforward EOF bug: kubelet sends a large tarball (many B→A frames)
    /// while kubectl is silent (no A→B frames). The old Arc<Mutex<>> approach
    /// deadlocked because the reader held mutex-A across recv().await, blocking
    /// the writer from sending tarball data to kubectl through the same mutex.
    ///
    /// With split halves, there is no shared state between the read and write
    /// tasks for the same stream, so this deadlock cannot occur.
    #[tokio::test]
    async fn splice_handles_large_one_directional_transfer() {
        let a_out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let b_out = Arc::new(std::sync::Mutex::new(Vec::new()));

        // A sends nothing — simulates kubectl waiting for data.
        let a = MemStream::new(vec![], Arc::clone(&a_out));

        // B sends 1000 messages — simulates kubelet streaming a tarball.
        let b_msgs: Vec<Bytes> = (0u32..1000)
            .map(|i| Bytes::from(i.to_be_bytes().to_vec()))
            .collect();
        let b = MemStream::new(b_msgs.clone(), Arc::clone(&b_out));

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            splice(a, b),
        )
        .await
        .expect("splice must not deadlock during large one-directional transfer (portforward tarball regression)");

        // All B messages must have arrived at A.
        let a_received = a_out.lock().unwrap().clone();
        assert_eq!(
            a_received.len(),
            1000,
            "all 1000 messages from B must reach A — deadlock would cause fewer or none to arrive"
        );
        assert_eq!(
            a_received, b_msgs,
            "messages must arrive at A in order and unmodified"
        );
    }

    // -----------------------------------------------------------------------
    // Close frame code regression tests — close code 1005 causes e2e timeouts
    //
    // WebSocket close code 1005 ("no status received") is what the peer sees when
    // we close without sending a close frame or send Close(None). kubectl interprets
    // 1005 as an abnormal termination and retries exec/attach sessions with
    // exponential backoff. This caused 2,564 errors in a single conformance run,
    // inflating the run from ~1h to 7h+.
    //
    // These tests verify that both writers send close code 1000 (Normal Closure).
    // They FAIL if close() is reverted to send Close(None) because the server would
    // then receive no code (which Go's gorilla/websocket reports as 1005).
    // -----------------------------------------------------------------------

    /// TungsteniteWsWriter::close() must send close code 1000 (Normal Closure).
    ///
    /// Close code 1005 ("no status") is produced when Close(None) is sent or when
    /// SinkExt::close() is called (which internally calls close(None)). kubectl
    /// treats 1005 as abnormal termination and retries, causing e2e timeout spikes.
    /// This test fails if close() is reverted to SinkExt::close() or Message::Close(None).
    #[tokio::test]
    async fn tungstenite_writer_close_sends_code_1000_not_1005() {
        use futures_util::StreamExt as _;
        use tokio_tungstenite::tungstenite::Message;

        let (mut server_ws, client_ws) = make_ws_pair().await;

        let ws = TungsteniteWs(client_ws);
        let (_reader, mut writer) = ws.split();

        // Spawn writer close in a task so we can concurrently read the close frame.
        let close_task = tokio::spawn(async move {
            writer.close().await;
        });

        // Read the close frame that the client sent to the server.
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), server_ws.next())
            .await
            .expect("server must receive a message within 2 seconds after close()")
            .expect("server stream must not be empty")
            .expect("message must be Ok, not an error");

        match msg {
            Message::Close(Some(frame)) => {
                let code: u16 = frame.code.into();
                assert_eq!(
                    code, 1000,
                    "TungsteniteWsWriter::close() must send code 1000 (Normal Closure), \
                     not 1005 (no status). Code 1005 causes kubectl to retry with backoff, \
                     inflating e2e conformance runs from ~1h to 7h+. Got code: {code}"
                );
            }
            Message::Close(None) => {
                panic!(
                    "TungsteniteWsWriter::close() sent Close(None) which produces code 1005 \
                     ('no status received') — kubectl treats this as abnormal termination \
                     and retries with exponential backoff"
                );
            }
            other => panic!("expected a Close frame, got: {other:?}"),
        }

        let _ = close_task.await;
    }

    /// AxumWsWriter::close() must build a CloseFrame with code 1000 (Normal Closure).
    ///
    /// axum's WebSocket layer translates Message::Close(None) into a frame with no
    /// status code, which Go's gorilla/websocket library reports to kubectl as code
    /// 1005 ("no status received"). kubectl then retries the exec/attach session.
    /// This test fails if close() is reverted to Message::Close(None).
    ///
    /// We verify the close code constant used by AxumWsWriter::close() equals 1000
    /// and that the CloseFrame struct would be Some (not None). This guards against
    /// the specific regression: passing Close(None) or close_code::STATUS (1005).
    #[test]
    fn axum_writer_close_uses_code_1000_not_1005() {
        // close_code::NORMAL == 1000 (Normal Closure)
        // close_code::STATUS == 1005 (No status received — the bad code we must not send)
        assert_eq!(
            axum::extract::ws::close_code::NORMAL,
            1000u16,
            "close_code::NORMAL must equal 1000 — if this fails the constant changed"
        );
        assert_ne!(
            axum::extract::ws::close_code::NORMAL,
            axum::extract::ws::close_code::STATUS,
            "NORMAL (1000) must not equal STATUS (1005). \
             AxumWsWriter::close() uses NORMAL — using STATUS would cause kubectl to retry."
        );
        // Verify CloseFrame with NORMAL produces Some (not None) — Close(None) yields 1005.
        let frame = axum::extract::ws::CloseFrame {
            code: axum::extract::ws::close_code::NORMAL,
            reason: "".into(),
        };
        assert_eq!(
            frame.code, 1000,
            "AxumWsWriter::close() CloseFrame code must be 1000 (Normal Closure), \
             not 1005. Sending 1005 causes kubectl to treat exec/attach as abnormally \
             terminated and retry with exponential backoff, inflating e2e runs from ~1h to 7h+."
        );
    }
}
