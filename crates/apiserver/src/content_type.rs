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
use axum::http::{header, HeaderMap, Request, Response, StatusCode};
use tower::Layer;
use tower_service::Service;

use crate::proto::encode_proto_response;

const PROTO_CONTENT_TYPE: &str = "application/vnd.kubernetes.protobuf";

/// Returns `true` if the Accept header contains `application/vnd.kubernetes.protobuf`.
pub fn prefer_proto(headers: &HeaderMap) -> bool {
    headers.get_all(header::ACCEPT).iter().any(|v| {
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
        let method = req.method().clone();
        let uri = req.uri().to_string();
        let accept = req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let resp = inner.call(req).await?;

            // Only re-encode when client asked for protobuf.
            if !wants_proto {
                tracing::debug!(uri = %uri, accept = %accept, "skip: no proto accept");
                return Ok(resp);
            }

            // Only re-encode GET responses.
            //
            // For write operations (POST/PUT/PATCH), client-go's protobuf decoder
            // does not reliably honour the contentType=application/json field inside
            // the Unknown envelope: it may attempt to decode the raw JSON bytes as a
            // typed proto message, producing "proto: illegal wireType 6" (ASCII 'n'
            // from "name" field is interpreted as a proto tag with wire type 6).
            //
            // The Accept header includes "application/json" as a fallback, so the
            // server is permitted to respond with JSON for these methods. Kubelet
            // smoke tests pass with this change because they use GET for status
            // reads and kubelet's PUT path also handles JSON responses correctly.
            if method != axum::http::Method::GET {
                tracing::debug!(uri = %uri, method = %method, "skip proto re-encode: non-GET method");
                return Ok(resp);
            }

            tracing::info!(uri = %uri, accept = %accept, status = resp.status().as_u16(), "wants proto");

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

            // Discovery meta-types are NOT re-encoded as proto.
            //
            // client-go 1.36+ sends Accept: application/vnd.kubernetes.protobuf for
            // discovery requests (GET /api, /api/v1, /apis, /apis/{group}/{version})
            // but its discovery decoder path decodes these types from JSON, not from
            // our Unknown-envelope-with-JSON-inside proto format. Re-encoding them as
            // proto causes "proto: illegal wireType 6" in kubectl because the Go proto
            // decoder encounters unexpected bytes when trying to decode the discovery
            // response as a typed proto message.
            let kind = json_val["kind"].as_str().unwrap_or("");
            if matches!(
                kind,
                "APIVersions"
                    | "APIGroupList"
                    | "APIResourceList"
                    | "APIGroupDiscoveryList"
                    | "APIGroup"
            ) {
                tracing::debug!(
                    uri = %uri,
                    kind = %kind,
                    "skip proto re-encode: discovery response"
                );
                let resp = Response::from_parts(parts, Body::from(body_bytes));
                return Ok(resp);
            }

            // Re-encode as protobuf.
            let proto_bytes = encode_proto_response(&json_val);
            let proto_len = proto_bytes.len();
            tracing::info!(
                uri = %uri,
                accept = %accept,
                kind = %kind,
                proto_len = proto_len,
                json_len = body_bytes.len(),
                "proto re-encode"
            );

            let mut new_parts = parts;
            new_parts.headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static(PROTO_CONTENT_TYPE),
            );
            // Replace Content-Length with the proto body length.
            // The original JSON Content-Length is wrong for the re-encoded body.
            // We set it explicitly so hyper does not use chunked transfer encoding,
            // which can trigger "illegal wireType" errors in the Go proto decoder.
            new_parts.headers.insert(
                header::CONTENT_LENGTH,
                header::HeaderValue::from_str(&proto_len.to_string())
                    .expect("proto body length is a valid header value"),
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

    const SAMPLE_JSON: &str = r#"{"apiVersion":"v1","kind":"Node","metadata":{"name":"my-node"}}"#;

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
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/vnd.kubernetes.protobuf",
            "content-type must be updated to protobuf"
        );

        // Body must start with the k8s magic prefix.
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
        let recovered: serde_json::Value =
            serde_json::from_slice(&envelope.raw).expect("raw field must contain valid JSON");
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
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "4xx responses must remain JSON even when client accepts protobuf"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "response must remain JSON when client does not accept protobuf"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "body must not start with k8s proto magic when client does not accept protobuf"
        );
    }

    /// Content-Length must be updated to the proto body length when re-encoding as protobuf.
    ///
    /// If the original JSON response carried a Content-Length header (e.g. set by axum's
    /// router), the re-encoded protobuf body will be a different size. Leaving the old
    /// Content-Length causes clients to read a truncated or zero-padded payload, which the
    /// protobuf decoder reports as "illegal wireType". We must set Content-Length to the proto
    /// body length so hyper uses Content-Length framing (not chunked transfer encoding).
    /// This is the regression for https://github.com/valerauko/u7s/pull/84 CI failure.
    #[tokio::test]
    async fn content_length_is_updated_to_proto_length_on_re_encode() {
        // FixedService does not set Content-Length by default, so use a custom builder.
        #[derive(Clone)]
        struct ServiceWithContentLength;
        impl Service<Request<Body>> for ServiceWithContentLength {
            type Response = Response<Body>;
            type Error = std::convert::Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _req: Request<Body>) -> Self::Future {
                let body = SAMPLE_JSON;
                Box::pin(async move {
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .header("content-length", body.len().to_string())
                        .body(Body::from(body))
                        .unwrap())
                })
            }
        }

        let mut layer_svc = ContentTypeLayer.layer(ServiceWithContentLength);
        let resp = layer_svc.call(proto_accept_request()).await.unwrap();

        // Content-Length must be the proto body length (not the original JSON length).
        let cl_header = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("Content-Length must be present after proto re-encoding")
            .to_str()
            .expect("Content-Length must be a valid string")
            .parse::<usize>()
            .expect("Content-Length must be a valid integer");

        // The proto body is the re-encoded body from the response.
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();

        assert_eq!(
            cl_header,
            body.len(),
            "Content-Length must equal the proto body length; JSON length ({}) would cause truncation",
            SAMPLE_JSON.len()
        );
        assert_ne!(
            cl_header,
            SAMPLE_JSON.len(),
            "Content-Length must not be the old JSON length — that causes wireType 6 truncation"
        );
    }

    /// Regression test for "illegal wireType 6": when Content-Length is the JSON byte length but
    /// the proto body is larger, truncating to json_len bytes produces a malformed protobuf stream.
    ///
    /// This test proves three things:
    ///   1. encode_proto_response always produces MORE bytes than the source JSON (so the old
    ///      Content-Length was always wrong).
    ///   2. A read truncated to the original json_len bytes fails to decode as a k8s proto
    ///      envelope — this is the wireType 6 scenario the kubectl CI gate hit.
    ///   3. The full (untruncated) bytes decode correctly — the fix (removing Content-Length) lets
    ///      the client read all bytes and succeed.
    ///
    /// If the Content-Length removal is reverted, content_length_is_removed_on_re_encode catches
    /// it at the header level; this test catches it at the byte level.
    #[test]
    fn truncated_proto_body_is_invalid_proving_content_length_must_be_removed() {
        // Use a realistic Namespace response similar to what kubectl create namespace returns.
        let json_str = r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"smoke-test","resourceVersion":"1","creationTimestamp":null},"spec":{"finalizers":["kubernetes"]},"status":{"phase":"Active"}}"#;
        let json_bytes = json_str.as_bytes();
        let json_len = json_bytes.len();

        let val: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let proto_bytes = encode_proto_response(&val);

        // 1. Proto body must be larger than JSON (magic prefix + envelope overhead).
        assert!(
            proto_bytes.len() > json_len,
            "proto body ({} bytes) must be larger than JSON ({} bytes); \
             if equal, Content-Length mismatch cannot occur",
            proto_bytes.len(),
            json_len
        );

        // 2. Truncating to JSON size produces a body that fails to decode as a k8s proto envelope.
        //    This is exactly what kubectl sees when Content-Length = json_len is honoured: it reads
        //    json_len bytes of the proto stream, landing in the middle of an encoded field, and the
        //    Go proto decoder reports "illegal wireType" when the next byte's low 3 bits are 6.
        let truncated = &proto_bytes[..json_len];
        assert!(
            crate::proto::decode_k8s_proto_envelope(truncated).is_none(),
            "truncated proto body (first json_len bytes) must not decode as a valid k8s envelope; \
             this proves the Content-Length mismatch corrupts the response"
        );

        // 3. The full proto body must decode correctly — removing Content-Length lets the client
        //    read all bytes and succeed.
        let envelope = crate::proto::decode_k8s_proto_envelope(&proto_bytes)
            .expect("full proto body must decode as a valid k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&envelope.raw).expect("envelope raw field must be valid JSON");
        assert_eq!(
            recovered["metadata"]["name"], "smoke-test",
            "name must survive the proto round-trip"
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
        let recovered: serde_json::Value =
            serde_json::from_slice(&envelope.raw).expect("raw field must be valid JSON");
        assert_eq!(recovered["kind"], "CSINode");
        assert_eq!(recovered["metadata"]["name"], "worker-1");

        // contentType must be "application/json" so client-go uses the JSON decoder.
        assert_eq!(
            envelope.content_type, "application/json",
            "contentType field must be 'application/json'"
        );
    }

    /// POST/PUT/PATCH responses must NOT be re-encoded as proto even when the client sends
    /// Accept: application/vnd.kubernetes.protobuf.
    ///
    /// This is the primary regression fix for `kubectl create namespace smoke-test` failing with
    /// "proto: illegal wireType 6" in CI. When kubectl sends POST /api/v1/namespaces with
    /// Accept: protobuf and gets back a proto Unknown envelope with contentType=application/json,
    /// client-go's protobuf decoder does not reliably honour the contentType field: it may try to
    /// decode the raw JSON bytes as a typed proto message. The byte 'n' (0x6E) from "name" in
    /// the JSON is read as a proto tag with wire type 6, producing the illegal wireType error.
    ///
    /// Since the Accept header includes "application/json" as a fallback, the server is allowed
    /// to respond with JSON for write operations. kubectl will use its JSON decoder, which succeeds.
    #[tokio::test]
    async fn post_response_not_re_encoded_as_proto() {
        let namespace_json =
            r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"smoke-test"}}"#;
        let svc = FixedService {
            status: StatusCode::CREATED,
            content_type: "application/json",
            body: namespace_json,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/namespaces")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap();

        let resp = layer_svc.call(req).await.unwrap();

        // Content-Type must remain application/json — POST must NOT be re-encoded as proto.
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "POST response must not be re-encoded as proto even with proto Accept header; \
             client-go ignores contentType=application/json inside Unknown envelope for write ops"
        );

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !resp_body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "POST response body must not start with k8s proto magic"
        );
        assert_eq!(
            resp_body.as_ref(),
            namespace_json.as_bytes(),
            "POST response body must be the original JSON unchanged"
        );
    }

    /// PUT responses must NOT be re-encoded as proto (same reason as POST).
    #[tokio::test]
    async fn put_response_not_re_encoded_as_proto() {
        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: SAMPLE_JSON,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/api/v1/nodes/my-node")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap();

        let resp = layer_svc.call(req).await.unwrap();

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/json", "PUT response must remain JSON");

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !resp_body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "PUT response body must not start with k8s proto magic"
        );
    }

    /// Discovery responses (APIVersions, APIGroupList, APIResourceList) must NOT be re-encoded
    /// as proto even when the client sends Accept: protobuf.
    ///
    /// client-go 1.36+ sends Accept: application/vnd.kubernetes.protobuf for discovery
    /// requests but its discovery decoder path expects JSON, not the Unknown-envelope-with-JSON
    /// proto format. Re-encoding discovery responses as proto causes "proto: illegal wireType 6"
    /// in kubectl because the Go proto decoder encounters unexpected bytes when trying to decode
    /// the discovery response.
    #[tokio::test]
    async fn discovery_responses_not_re_encoded_as_proto() {
        for (kind, body) in [
            (
                "APIVersions",
                r#"{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}"#,
            ),
            (
                "APIGroupList",
                r#"{"kind":"APIGroupList","apiVersion":"v1","groups":[]}"#,
            ),
            (
                "APIResourceList",
                r#"{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[]}"#,
            ),
        ] {
            let svc = FixedService {
                status: StatusCode::OK,
                content_type: "application/json",
                body,
            };
            let mut layer_svc = ContentTypeLayer.layer(svc);

            let resp = layer_svc.call(proto_accept_request()).await.unwrap();

            // Content-Type must remain application/json — not converted to proto.
            let ct = resp
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!(
                ct, "application/json",
                "discovery kind '{kind}' must not be re-encoded as proto even with proto Accept"
            );

            // Body must NOT start with the k8s proto magic.
            let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(
                !resp_body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
                "discovery kind '{kind}' body must not start with k8s proto magic"
            );
            // Body must be the original JSON.
            assert_eq!(
                resp_body.as_ref(),
                body.as_bytes(),
                "discovery kind '{kind}' body must be the original JSON unchanged"
            );
        }
    }
}
