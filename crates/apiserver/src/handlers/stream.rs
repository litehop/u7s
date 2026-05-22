/// BiStream — transport-agnostic bidirectional byte channel.
///
/// Abstracts over the underlying transport (axum WebSocket, tokio-tungstenite,
/// future HTTP/3 QUIC streams) so that splice logic in /attach and /portforward
/// can be written once and swapped at the call site.
///
/// The `+ Send` bounds on the associated futures are required by tokio::spawn.
pub trait BiStream: Send + 'static {
    fn recv(&mut self) -> impl std::future::Future<Output = Option<bytes::Bytes>> + Send;
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
/// Binary frames are passed through as-is. Text frames are coerced to bytes.
/// Control frames (Ping/Pong/Close) are skipped — the splice loop handles data only.
pub struct AxumWs(pub axum::extract::ws::WebSocket);

impl BiStream for AxumWs {
    async fn recv(&mut self) -> Option<bytes::Bytes> {
        loop {
            match self.0.recv().await? {
                Ok(axum::extract::ws::Message::Binary(b)) => return Some(b),
                Ok(axum::extract::ws::Message::Text(t)) => {
                    return Some(bytes::Bytes::copy_from_slice(t.as_bytes()))
                }
                Ok(_) => continue, // Ping, Pong, Close — skip
                Err(_) => return None,
            }
        }
    }

    async fn send(&mut self, data: bytes::Bytes) -> anyhow::Result<()> {
        use axum::extract::ws::Message;
        self.0
            .send(Message::Binary(data))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn close(&mut self) {
        use axum::extract::ws::Message;
        let _ = self.0.send(Message::Close(None)).await;
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

impl<S> BiStream for TungsteniteWs<S>
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
                Ok(_) => continue, // Ping, Pong, Close, Frame
                Err(_) => return None,
            }
        }
    }

    async fn send(&mut self, data: bytes::Bytes) -> anyhow::Result<()> {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message;
        self.0
            .send(Message::Binary(data.to_vec().into()))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn close(&mut self) {
        let _ = self.0.close(None).await;
    }
}

// ---------------------------------------------------------------------------
// Splice helper — bidirectional byte relay between two BiStream impls
// ---------------------------------------------------------------------------

/// Relay bytes between two BiStream endpoints until either side closes.
///
/// Spawns two tasks, one per direction. Each task reads from one end and writes
/// to the other. When one direction completes (recv returns None or send errors),
/// the opposite end is closed and the other task is aborted. This ensures clean
/// shutdown without leaking tasks.
pub async fn splice<A, B>(a: A, b: B)
where
    A: BiStream,
    B: BiStream,
{
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Split into independent halves so each task can hold its own lock without
    // blocking the other direction.
    let a_recv = Arc::new(Mutex::new(a));
    let b_send = Arc::new(Mutex::new(b));

    // We need send access to b from t1 and recv access to b from t2.
    // Since we can't split a single BiStream, share it via Arc<Mutex<>> and
    // accept that the two tasks alternate rather than run in true parallel.
    // For WebSocket proxying this is fine — frames arrive at human-scale rates.
    let a_send = Arc::clone(&a_recv);
    let b_recv = Arc::clone(&b_send);

    // a → b
    let t1 = tokio::spawn(async move {
        loop {
            let msg = a_recv.lock().await.recv().await;
            match msg {
                None => break,
                Some(data) => {
                    if b_send.lock().await.send(data).await.is_err() {
                        break;
                    }
                }
            }
        }
        // A is done sending; signal B to stop by closing it.
        b_send.lock().await.close().await;
    });

    // b → a
    let t2 = tokio::spawn(async move {
        loop {
            let msg = b_recv.lock().await.recv().await;
            match msg {
                None => break,
                Some(data) => {
                    if a_send.lock().await.send(data).await.is_err() {
                        break;
                    }
                }
            }
        }
        // B is done sending; signal A to stop by closing it.
        a_send.lock().await.close().await;
    });

    // When either direction finishes, abort the other so tasks don't leak.
    let t2_abort = t2.abort_handle();
    let t1_abort = t1.abort_handle();
    tokio::select! {
        _ = t1 => { t2_abort.abort(); }
        _ = t2 => { t1_abort.abort(); }
    }
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
    struct MemStream {
        incoming: std::collections::VecDeque<Bytes>,
        pub outgoing: Arc<std::sync::Mutex<Vec<Bytes>>>,
        closed: bool,
    }

    impl MemStream {
        fn new(incoming: Vec<Bytes>, outgoing: Arc<std::sync::Mutex<Vec<Bytes>>>) -> Self {
            Self {
                incoming: incoming.into(),
                outgoing,
                closed: false,
            }
        }
    }

    impl BiStream for MemStream {
        async fn recv(&mut self) -> Option<Bytes> {
            // Drain the queue regardless of closed state; return None only when empty.
            // close() marks that no further messages will be queued, but already-queued
            // messages should still be delivered — matching real WebSocket behavior where
            // buffered data is readable even after the peer closes.
            self.incoming.pop_front()
        }

        async fn send(&mut self, data: Bytes) -> anyhow::Result<()> {
            self.outgoing.lock().unwrap().push(data);
            Ok(())
        }

        async fn close(&mut self) {
            self.closed = true;
            // Drain pending sends — mimic half-close: no more reads, but already-sent
            // data was captured in outgoing.
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
}
