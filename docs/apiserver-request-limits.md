# API server request limits

Limits on request bodies and proxied upstreams, and where they differ from
upstream kube-apiserver.

| Limit | Value | Response |
|---|---|---|
| Request body size | 3 MiB per request (same as upstream) | 413 `RequestEntityTooLarge` Status |
| Shared in-flight body budget | 6 MiB across all concurrent requests | 429 with `Retry-After: 1` |
| Body read deadline | 60 s for the body to finish arriving | 504 `Timeout` Status |
| Proxy response-header timeout | 300 s from request sent to upstream headers | 504 `Timeout` Status |

The body budget is taken as bytes arrive, not from `Content-Length`, so a slow
client holds only what it has sent. Bytes are returned when the request
finishes. Ordinary requests (a few KiB) never notice it; several concurrent
maximum-size writes can be answered 429, and clients should retry.

Streamed requests (exec, attach, portforward, logs, watch) are not metered.

## Proxy subresources

Upstream treats `pods|services|nodes/{name}/proxy` as long-running: no body
deadline and no response-header timeout. u7s differs in two ways:

- A proxy request body that has not finished arriving within 60 s is cut with
  504, and proxy bodies count against the shared 6 MiB budget (429 when
  exhausted). Very slow or very long-lived proxy uploads therefore behave
  differently from upstream.
- If the upstream (pod, service endpoint or kubelet) accepts the request but
  sends no response headers within 300 s, the request fails with 504 and its
  body-budget bytes are released.

Downloads and streaming are unaffected: once the response headers arrive the
response body is streamed with no time limit.
