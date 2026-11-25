# API server request limits

Limits on request bodies and proxied upstreams, and where they differ from
upstream kube-apiserver.

| Limit | Value | Response |
|---|---|---|
| Request body size | 3 MiB per request (same as upstream) | 413 `RequestEntityTooLarge` Status |
| Shared in-flight body budget | 6 MiB across all concurrent requests | 429 with `Retry-After: 1` |
| Body read deadline | 60 s for the body to finish arriving | 504 `Timeout` Status |
| Proxy response-header timeout | 60 s from request sent to upstream headers; also bounds dialing on direct paths; the tunnel path has two 60 s waits (CONNECT answer, then the pod request) | 504 `Timeout` Status |

The body budget is taken as bytes arrive, not from `Content-Length`, so a slow
client holds only what it has sent. Bytes are returned when the request
finishes. Ordinary requests (a few KiB) never notice it; several concurrent
maximum-size writes can be answered 429, and clients should retry.

Streamed requests (exec, attach, portforward, logs, watch) are not metered.

## Proxy subresources

Upstream treats `pods|services|nodes/{name}/proxy` as long-running and
exempts them from the request timeout. u7s gives proxy requests the same 60 s
limit as every other request, for two waits:

- The request body must finish arriving within 60 s, else 504.
- The upstream (pod, service endpoint, kubelet, or konnectivity-server
  answering the tunnel `CONNECT`) must send its response headers within 60 s
  of the request being sent, else 504. Dialing konnectivity and its TLS
  handshake are bounded at 30 s and 10 s, as in upstream's transport.

Proxy request bodies also count against the shared 6 MiB budget (429 when
exhausted). The budget is returned as soon as the response headers arrive.

Once the headers have arrived the response body is streamed with no time
limit. The one exception is `text/html`: it is buffered (at most 3 MiB) to
rewrite links and must finish within 60 s, else 504.
