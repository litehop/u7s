// content_type.rs — Tower middleware for Kubernetes protobuf content negotiation.
//
// Kubelet 1.36+ sends `Accept: application/vnd.kubernetes.protobuf, application/json`
// on every request. The Go client-go library expects the server to honour the Accept
// header: if it sent protobuf in Accept and the server returns JSON, client-go's
// content-negotiation layer fails to route the response to the right decoder and emits
// "invalid JSON: expected value at line 1 column 1".
//
// This middleware intercepts responses: when the original request accepted protobuf
// AND the response is a 2xx JSON body, it re-encodes the body as a Kubernetes protobuf
// envelope and updates the Content-Type header accordingly.
//
// Edge cases that are NOT re-encoded:
//   - 4xx/5xx responses — client-go always expects errors as JSON.
//   - Watch responses (streaming NDJSON) — never re-encoded.
//   - Bodies that are not valid JSON — passed through unchanged.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderMap, Request, Response, StatusCode, header};
use tower::Layer;
use tower_service::Service;

use crate::proto::encode_proto_response;

const PROTO_CONTENT_TYPE: &str = "application/vnd.kubernetes.protobuf";

/// Returns `true` if the Accept header contains `application/vnd.kubernetes.protobuf`.
pub fn prefer_proto(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| s.contains(PROTO_CONTENT_TYPE))
                .unwrap_or(false)
        })
}

// ---------------------------------------------------------------------------
// ContentTypeLayer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ContentTypeLayer;

impl<S> Layer<S> for ContentTypeLayer {
    type Service = ContentTypeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ContentTypeService { inner }
    }
}

// ---------------------------------------------------------------------------
// ContentTypeService
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ContentTypeService<S> {
    inner: S,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S> Service<Request<Body>> for ContentTypeService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let wants_proto = prefer_proto(req.headers());
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let resp = inner.call(req).await?;

            // Only re-encode when client asked for protobuf.
            if !wants_proto {
                return Ok(resp);
            }

            // Only re-encode successful (2xx) responses.
            if !resp.status().is_success() {
                return Ok(resp);
            }

            // Only re-encode when the response is application/json.
            let is_json = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.starts_with("application/json"))
                .unwrap_or(false);

            if !is_json {
                return Ok(resp);
            }

            // Collect the body bytes. Limit to 32 MiB — any larger response is
            // pathological for our API surface.
            let (parts, body) = resp.into_parts();
            let body_bytes = match axum::body::to_bytes(body, 32 * 1024 * 1024).await {
                Ok(b) => b,
                Err(_) => {
                    // Can't collect body — pass through a 500.
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap());
                }
            };

            // Parse as JSON.  If not valid JSON, pass through unchanged.
            let json_val: serde_json::Value = match serde_json::from_slice(&body_bytes) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response::from_parts(parts, Body::from(body_bytes));
                    return Ok(resp);
                }
            };

            // Re-encode as protobuf.
            let proto_bytes = encode_proto_response(&json_val);

            let mut new_parts = parts;
            new_parts.headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static(PROTO_CONTENT_TYPE),
            );

            Ok(Response::from_parts(new_parts, Body::from(proto_bytes)))
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, Response, StatusCode};
    use std::task::{Context, Poll};
    use tower::Layer;
    use tower_service::Service;

    // Minimal inner service that returns a configurable response.
    #[derive(Clone)]
    struct FixedService {
        status: StatusCode,
        content_type: &'static str,
        body: &'static str,
    }

    impl Service<Request<Body>> for FixedService {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            let status = self.status;
            let ct = self.content_type;
            let body = self.body;
            Box::pin(async move {
                Ok(Response::builder()
                    .status(status)
                    .header("content-type", ct)
                    .body(Body::from(body))
                    .unwrap())
            })
        }
    }

    fn proto_accept_request() -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/nodes/my-node")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap()
    }

    fn json_accept_request() -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/nodes/my-node")
            .header("accept", "application/json")
            .body(Body::empty())
            .unwrap()
    }

    const SAMPLE_JSON: &str =
        r#"{"apiVersion":"v1","kind":"Node","metadata":{"name":"my-node"}}"#;

    /// A 2xx JSON response with Accept: protobuf must be re-encoded as protobuf.
    ///
    /// This is the primary regression for the kubelet startup failure: client-go sends
    /// Accept: protobuf on every request; if the server returns JSON, client-go's
    /// content-negotiation emits "invalid JSON: expected value at line 1 column 1".
    #[tokio::test]
    async fn proto_accept_2xx_json_is_re_encoded_as_protobuf() {
        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: SAMPLE_JSON,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let resp = layer_svc.call(proto_accept_request()).await.unwrap();

        // Content-Type must be protobuf.
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert_eq!(
            ct, "application/vnd.kubernetes.protobuf",
            "content-type must be updated to protobuf"
        );

        // Body must start with the k8s magic prefix.
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "response body must start with k8s proto magic"
        );

        // The original JSON must be recoverable from the raw field (field 2) of the envelope.
        // Decode the Unknown envelope and verify the raw field contains our JSON.
        let envelope = crate::proto::decode_k8s_proto_envelope(&body)
            .expect("re-encoded body must be a valid k8s protobuf envelope");
        assert_eq!(
            envelope.content_type, "application/json",
            "envelope contentType must be application/json so client-go uses JSON decoder"
        );
        let recovered: serde_json::Value = serde_json::from_slice(&envelope.raw)
            .expect("raw field must contain valid JSON");
        assert_eq!(
            recovered["metadata"]["name"], "my-node",
            "original object data must survive the proto round-trip"
        );
    }

    /// A 4xx error response must NOT be re-encoded — client-go always reads errors as JSON.
    ///
    /// Re-encoding errors as protobuf would break kubectl error display and controller error
    /// handling, since the Status object is only parsed from JSON by the client error path.
    #[tokio::test]
    async fn proto_accept_4xx_response_is_not_re_encoded() {
        let error_body = r#"{"apiVersion":"v1","kind":"Status","status":"Failure","code":404}"#;
        let svc = FixedService {
            status: StatusCode::NOT_FOUND,
            content_type: "application/json",
            body: error_body,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let resp = layer_svc.call(proto_accept_request()).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert_eq!(
            ct, "application/json",
            "4xx responses must remain JSON even when client accepts protobuf"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(
            !body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "4xx response body must not start with k8s proto magic"
        );
    }

    /// A 2xx JSON response without Accept: protobuf must NOT be re-encoded.
    ///
    /// Plain kubectl or controller clients that use JSON must receive JSON — re-encoding
    /// them unconditionally would break every client that doesn't speak protobuf.
    #[tokio::test]
    async fn json_accept_2xx_response_is_not_re_encoded() {
        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: SAMPLE_JSON,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let resp = layer_svc.call(json_accept_request()).await.unwrap();

        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert_eq!(
            ct, "application/json",
            "response must remain JSON when client does not accept protobuf"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(
            !body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "body must not start with k8s proto magic when client does not accept protobuf"
        );
    }

    /// The encoder function directly: encode_proto_response must produce a valid k8s
    /// protobuf envelope whose raw field (field 2) contains the original JSON bytes.
    ///
    /// This tests the encoder in isolation — if this test fails the middleware test would
    /// also fail, but having both makes root-cause analysis faster.
    #[test]
    fn encode_proto_response_produces_valid_envelope() {
        let val = serde_json::json!({
            "apiVersion": "v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1" }
        });

        let encoded = encode_proto_response(&val);

        // Must start with k8s magic.
        assert_eq!(
            &encoded[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "encoded bytes must start with k8s proto magic"
        );

        // Must be decodable as a k8s protobuf envelope.
        let envelope = crate::proto::decode_k8s_proto_envelope(&encoded)
            .expect("encode_proto_response must produce a decodable k8s envelope");

        // The raw field must contain the JSON.
        let recovered: serde_json::Value = serde_json::from_slice(&envelope.raw)
            .expect("raw field must be valid JSON");
        assert_eq!(recovered["kind"], "CSINode");
        assert_eq!(recovered["metadata"]["name"], "worker-1");

        // contentType must be "application/json" so client-go uses the JSON decoder.
        assert_eq!(
            envelope.content_type, "application/json",
            "contentType field must be 'application/json'"
        );
    }
}
