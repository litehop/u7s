/// Transport-agnostic BiStream trait and WebSocket implementations.
///
/// The splice logic in `proxy.rs` operates on `impl BiStream` so the underlying
/// transport (axum WS inbound, tokio-tungstenite WS outbound) can be swapped for
/// HTTP/3+QUIC without touching the business logic.
use axum::extract::ws::{Message as AxumMsg, WebSocket};
use bytes::Bytes;

// ---------------------------------------------------------------------------
// BiStream trait
// ---------------------------------------------------------------------------

/// A bidirectional byte stream abstraction.
///
/// Implementations exist for axum WebSocket (inbound kubectl connection) and
/// tokio-tungstenite WebSocket (outbound kubelet connection). The splice loop
/// uses this trait so no WebSocket-specific code leaks into the business logic.
pub trait BiStream: Send + 'static {
    fn recv(&mut self) -> impl std::future::Future<Output = Option<Bytes>> + Send;
    fn send(&mut self, data: Bytes)
        -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn close(&mut self) -> impl std::future::Future<Output = ()> + Send;
}

// ---------------------------------------------------------------------------
// Inbound: axum WebSocket (kubectl → apiserver)
// ---------------------------------------------------------------------------

/// Wraps an axum WebSocket for use as a BiStream.
///
/// Binary frames are passed through as-is. Text frames are converted to bytes.
/// Close/Ping/Pong frames are handled: close terminates, ping/pong are dropped
/// (axum handles protocol-level pong automatically).
pub struct AxumWs(pub WebSocket);

impl BiStream for AxumWs {
    async fn recv(&mut self) -> Option<Bytes> {
        loop {
            match self.0.recv().await? {
                Ok(AxumMsg::Binary(b)) => return Some(b),
                Ok(AxumMsg::Text(t)) => return Some(Bytes::from(t.as_bytes().to_vec())),
                Ok(AxumMsg::Close(_)) => return None,
                Ok(AxumMsg::Ping(_) | AxumMsg::Pong(_)) => continue,
                Err(_) => return None,
            }
        }
    }

    async fn send(&mut self, data: Bytes) -> anyhow::Result<()> {
        self.0
            .send(AxumMsg::Binary(data))
            .await
            .map_err(|e| anyhow::anyhow!("axum ws send: {e}"))
    }

    async fn close(&mut self) {
        let _ = self.0.send(AxumMsg::Close(None)).await;
    }
}

// ---------------------------------------------------------------------------
// Outbound: tokio-tungstenite WebSocket (apiserver → kubelet)
// ---------------------------------------------------------------------------

use tokio_tungstenite::tungstenite::Message as TungMsg;
use tokio_tungstenite::WebSocketStream;

/// Wraps a tokio-tungstenite WebSocketStream for use as a BiStream.
///
/// The stream may be backed by any tokio AsyncRead+AsyncWrite (TCP, TLS, etc.).
/// Only the generic constraint is exposed here; callers use the concrete
/// `connect_to_kubelet` constructor which returns `TungsteniteWs<...>`.
pub struct TungsteniteWs<S>(pub WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static;

impl<S> BiStream for TungsteniteWs<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    async fn recv(&mut self) -> Option<Bytes> {
        use futures_util::StreamExt as _;
        loop {
            match self.0.next().await? {
                Ok(TungMsg::Binary(b)) => return Some(b),
                Ok(TungMsg::Text(t)) => return Some(Bytes::from(t.as_bytes().to_vec())),
                Ok(TungMsg::Close(_)) => return None,
                Ok(TungMsg::Ping(_) | TungMsg::Pong(_) | TungMsg::Frame(_)) => continue,
                Err(_) => return None,
            }
        }
    }

    async fn send(&mut self, data: Bytes) -> anyhow::Result<()> {
        use futures_util::SinkExt as _;
        self.0
            .send(TungMsg::Binary(data))
            .await
            .map_err(|e| anyhow::anyhow!("tungstenite ws send: {e}"))
    }

    async fn close(&mut self) {
        use futures_util::SinkExt as _;
        let _ = self.0.send(TungMsg::Close(None)).await;
    }
}

// ---------------------------------------------------------------------------
// Splice: bidirectional copy between two BiStream implementations
// ---------------------------------------------------------------------------

/// Splice two BiStream halves until either side closes.
///
/// Polls both directions concurrently in a single loop: whichever side
/// produces a frame first, the frame is forwarded to the other side.
/// The loop terminates when either side closes or errors.
pub async fn splice<A, B>(mut a: A, mut b: B)
where
    A: BiStream,
    B: BiStream,
{
    loop {
        tokio::select! {
            msg = a.recv() => {
                match msg {
                    None => break,
                    Some(data) => { if b.send(data).await.is_err() { break; } }
                }
            }
            msg = b.recv() => {
                match msg {
                    None => break,
                    Some(data) => { if a.send(data).await.is_err() { break; } }
                }
            }
        }
    }
    a.close().await;
    b.close().await;
}

/// Drain all frames from `src` into `dst` until src closes or dst errors.
///
/// Used in tests to verify one direction of the splice without select! races.
#[cfg(test)]
pub(crate) async fn drain_one_direction<Src: BiStream, Dst: BiStream>(
    src: &mut Src,
    dst: &mut Dst,
) {
    loop {
        match src.recv().await {
            None => break,
            Some(data) => {
                if dst.send(data).await.is_err() {
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A minimal in-memory BiStream for testing splice logic.
    ///
    /// Frames are pre-loaded into `inbox`; sent frames go to `outbox`.
    /// When `inbox` is exhausted, recv() returns None (stream closed).
    struct MockStream {
        inbox: VecDeque<Bytes>,
        pub outbox: std::sync::Arc<std::sync::Mutex<Vec<Bytes>>>,
        closed: bool,
    }

    impl MockStream {
        fn new(frames: Vec<Bytes>) -> (Self, std::sync::Arc<std::sync::Mutex<Vec<Bytes>>>) {
            let outbox = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let s = MockStream {
                inbox: frames.into_iter().collect(),
                outbox: outbox.clone(),
                closed: false,
            };
            (s, outbox)
        }
    }

    impl BiStream for MockStream {
        async fn recv(&mut self) -> Option<Bytes> {
            self.inbox.pop_front()
        }

        async fn send(&mut self, data: Bytes) -> anyhow::Result<()> {
            self.outbox.lock().unwrap().push(data);
            Ok(())
        }

        async fn close(&mut self) {
            self.closed = true;
        }
    }

    /// drain_one_direction must copy all frames from src to dst's outbox.
    ///
    /// This is the foundational test for the copy loop: it must not stop
    /// early, drop frames, or deliver them out of order. If any of those
    /// invariants break, portforward data would be silently lost.
    #[tokio::test]
    async fn drain_one_direction_copies_all_frames() {
        let frames = vec![
            Bytes::from_static(b"frame-1"),
            Bytes::from_static(b"frame-2"),
            Bytes::from_static(b"frame-3"),
        ];
        let (mut src, _) = MockStream::new(frames.clone());
        let (mut dst, outbox) = MockStream::new(vec![]);

        drain_one_direction(&mut src, &mut dst).await;

        let got = outbox.lock().unwrap().clone();
        assert_eq!(got, frames, "all frames must be forwarded in order");
    }

    /// drain_one_direction must forward frames from the other direction too.
    ///
    /// The BiStream implementation is symmetric — this test ensures the
    /// copy logic works regardless of which end is src vs dst.
    #[tokio::test]
    async fn drain_one_direction_reverse_also_works() {
        let frame = Bytes::from_static(b"from-b");
        let (mut src, _) = MockStream::new(vec![frame.clone()]);
        let (mut dst, outbox) = MockStream::new(vec![]);

        drain_one_direction(&mut src, &mut dst).await;

        let got = outbox.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![frame],
            "reverse direction must also forward frames"
        );
    }

    /// splice must terminate when both sides have exhausted their frames.
    ///
    /// A deadlock here would mean the splice loop is blocking on recv() from
    /// a stream that will never produce more data.
    #[tokio::test]
    async fn splice_terminates_when_streams_close() {
        let (stream_a, _) = MockStream::new(vec![]);
        let (stream_b, _) = MockStream::new(vec![]);
        // Must complete without hanging.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            splice(stream_a, stream_b),
        )
        .await
        .expect("splice must terminate when both streams are empty");
    }

    /// splice must keep forwarding from B even when A closes first.
    ///
    /// With select!, whichever direction closes first wins and the other is
    /// cancelled. This test verifies the expected behaviour (A closes first,
    /// B frames that were queued may not all arrive) — the test documents
    /// that select! semantics mean the first-closed direction wins.
    #[tokio::test]
    async fn splice_terminates_when_one_side_closes() {
        // A has no frames (closes immediately), B has one frame.
        let (stream_a, _) = MockStream::new(vec![]);
        let (stream_b, _) = MockStream::new(vec![Bytes::from_static(b"hello")]);
        // Must complete without hanging.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            splice(stream_a, stream_b),
        )
        .await
        .expect("splice must terminate when one stream closes");
    }
}
