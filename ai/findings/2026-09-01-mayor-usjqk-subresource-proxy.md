Bead: mayor-usjqk

# Phase 1 deep-dive: pod exec/attach/portforward/logs/proxy subresources

## Verdict

Two live, exploitable, previously-untracked vulnerabilities found in
`crates/apiserver/src/handlers/proxy.rs`: a CRITICAL HTTP request-splitting
bug in `/portforward` (mayor-z54ge) that lets a user with rights to
port-forward to a single pod smuggle arbitrary requests to that node's
kubelet as the apiserver's trusted identity, and the previously-flagged
podIP-SSRF lead (mayor-usjqk's own Phase 0 note) confirmed still real and
open post-mayor-tkv6j (mayor-k6m4a). A secondary memory-exhaustion DoS via
unbounded response buffering was also found (mayor-ukmal). RBAC subresource
verb handling for pods/exec, pods/attach, pods/portforward was checked
against upstream 1.36 semantics in detail and found correct — not a bug.

Severity counts: 1 CRITICAL, 1 HIGH, 1 MEDIUM, 0 additional beads (1 addendum
note appended to the existing mayor-c6njm konnectivity boundary bead instead
of a duplicate).

## Scope and method

Read end-to-end: `crates/apiserver/src/handlers/proxy.rs` (2864 lines of
non-test code; ~7200 lines of tests), `crates/apiserver/src/handlers/stream.rs`
(926 lines, all of it), and the RBAC/authorization gate that fronts every
request, `crates/apiserver/src/auth.rs` (the `AuthService` tower middleware,
`parse_path`/`classify_request`/verb computation). Cross-checked upstream
kubernetes/kubernetes @ `release-1.36` (fetched via `gh api ...` into
`temp/research/`, not committed): `requestinfo.go`, `installer.go`,
`endpoints/handlers/rest.go` (`ConnectResource`), bootstrap `policy.go`,
`client-go`'s `remotecommand/websocket.go` and `kubectl/cmd/exec/exec.go`.

## F1 — CRITICAL: HTTP request splitting via `/portforward`'s `ports` query param

`crates/apiserver/src/handlers/proxy.rs:1404-1405` (`validate_portforward`)
builds the kubelet portForward URL by direct string interpolation of the
client's raw `?ports=` query value, with zero character validation:

```
let ports_qs = ports.map(|p| format!("?ports={p}")).unwrap_or_default();
let kubelet_url = format!("https://{node_ip}:{kp}/portForward/{ns}/{pod_name}{ports_qs}");
```

`proxy.rs:1505-1517` (`parse_https_url`) then splits that URL by naive
string ops (`split_once('/')`), carrying any embedded CRLF straight through
into the `path` component. `proxy.rs:1620-1627` (`dial_kubelet_portforward`)
hand-rolls the outbound HTTP/1.1 request as a plain format string and writes
it directly to a TLS socket:

```
let request = format!(
    "POST {path} HTTP/1.1\r\n\
     Host: {host}:{port}\r\n\
     Connection: Upgrade\r\n\
     Upgrade: SPDY/3.1\r\n\
     X-Stream-Protocol-Version: {PORTFORWARD_KUBELET_PROTOCOL}\r\n\
     Content-Length: 0\r\n\r\n"
);
tls.write_all(request.as_bytes()).await?;
```

No URI parser is involved on this leg at all, so nothing rejects CR/LF.
`dial_kubelet_portforward` is called by BOTH `portforward_proxy_tunneled`
(the primary websocket-tunneled-SPDY GET every supported kubectl release
tries first) and `portforward_proxy_raw` (the raw-SPDY-over-HTTP POST
fallback) — this is the default code path, not an edge case.

By contrast, `/exec` and `/attach` (`dial_kubelet_exec`, `dial_kubelet_attach`)
and the v4-websocket portforward leg (`dial_kubelet_portforward_v4`) all
build their outbound URL via `tokio_tungstenite`'s `IntoClientRequest`, which
parses the string as a real `http::Uri` and rejects literal control
characters — those legs fail safe. Only the raw-SPDY portforward leg
hand-rolls its own request text with no such protection.

**Exploit.** A user holding only `create` on `pods/portforward` for one pod
(a common, low-privilege "let developers port-forward to their own pod"
grant) sends a WebSocket-upgrade GET to
`/api/v1/namespaces/<ns>/pods/<pod>/portforward?ports=<payload>` where
`<payload>` percent-decodes to e.g.
`1\r\nHost: x\r\nContent-Length: 0\r\n\r\nGET /runningpods/ HTTP/1.1\r\nHost: x\r\n\r\n`.
The apiserver opens a fresh mTLS connection to that pod's node's kubelet
using its OWN trusted client identity (`kubelet_client_identity_pem`), then
writes the poisoned request text. The injected CRLF sequence terminates the
legitimate `POST /portForward/...` early and smuggles a second, fully
independent HTTP request onto the same persistent, already-authenticated
connection. Kubelet's HTTP server processes it as coming from the
apiserver's trusted certificate — there is no per-request authorization
delegation on a raw hijacked connection — so the attacker reaches ANY
kubelet HTTP endpoint on that node (exec into other pods scheduled there,
`/stats/summary`, `/logs/`, `/runningpods/`, ...), not just the one
pod/port they were granted.

**Fix sketch.** Reject `ports` values containing any C0 control character
before they reach URL-building (`ports` is documented as a comma-separated
list of `port[:port]` pairs, so `^[0-9,:]+$` is correct and sufficient).
Longer-term, build `dial_kubelet_portforward`'s outbound request through a
proper HTTP/1.1 writer instead of a hand-rolled `format!` string, matching
`dial_kubelet_exec`/`dial_kubelet_attach`'s use of `IntoClientRequest`.

Follow-on: **mayor-z54ge** (P0).

## F2 — HIGH: pod/proxy and service/proxy dial `podIP`/endpoint address verbatim (SSRF)

This is the exact lead flagged in mayor-usjqk's own Phase 0 carry-over note,
chased to ground. `crates/apiserver/src/handlers/proxy.rs:2073`
(`resolve_pod_proxy_target`) reads `pod["status"]["podIP"]` with only an
empty-string check — no IP-format validation, no pod-CIDR check anywhere.
`proxy.rs:2449` (`pod_proxy_dispatch`, direct-dial leg) then dials
`format!("{scheme}://{pod_ip}:{port}/{path_with_query}")` straight from the
apiserver process; `proxy.rs:2189` (`pod_proxy_via_connect_tunnel`, the
konnectivity leg) hand-rolls `pod_ip` into a raw `CONNECT` request line with
the same lack of validation, which — since `status.podIP` has no format
check anywhere in `handlers/pods.rs` — compounds into a second CRLF/request-
splitting vector against konnectivity-server itself (addendum appended to
the existing boundary bead **mayor-c6njm** rather than duplicating it).
`proxy.rs:2672` (`resolve_service_proxy_target`) has the identical pattern
for `services/proxy` via an EndpointSlice's `addresses[0]`, though ordinary
edit/admin roles only get read access to EndpointSlices, narrowing that
path's practical blast radius.

mayor-tkv6j's Node-authorizer fix (now CLOSED) means a compromised node can
only rewrite `status.podIP` for pods actually scheduled to itself, not
arbitrary pods cluster-wide — but that is still sufficient: any legitimate
user who later proxies to that pod has their request silently redirected by
the apiserver, from the apiserver's own network position (and own TLS client
identity, when HTTPS-scheme proxying is requested), to whatever host:port
the compromised node chose — including addresses reachable from the
apiserver's host but not from the node itself (loopback debug endpoints,
control-plane-only internal networks, cloud metadata scoped to the
control-plane VM). This matches upstream kube-apiserver's own accepted-risk
shape (verbatim podIP, mitigated only by the Node authorizer bounding whose
pod a given kubelet may retarget) — it is not a regression from upstream,
but it is real, and per this project's hostile-input-paranoid stance, format
validation is cheap and worth doing regardless of upstream parity.

**Fix sketch.** Validate `podIP` / EndpointSlice addresses as syntactically
valid IP addresses before dialing, and reject loopback/link-local/multicast/
cloud-metadata ranges outright; optionally also validate against the
cluster's configured pod CIDR.

Follow-on: **mayor-k6m4a** (P1).

## F3 — MEDIUM: unbounded response buffering in pod/service proxy (memory-exhaustion DoS)

`proxy.rs:2486-2502` (`pod_proxy_dispatch`) and the equivalent block in
`service_proxy_dispatch` call `pod_resp.bytes().await` — fully buffering the
proxied response with no size cap — whenever the backend's response
declares `Content-Type: text/html` (to feed `rewrite_html_body`).
`proxy.rs:2271-2277` (`pod_proxy_via_connect_tunnel`) is worse: it calls
`hyper_resp.into_body().collect().await` unconditionally for every response
proxied through konnectivity, HTML or not — no size cap at all on that leg.
The non-HTML, non-konnectivity path correctly streams
(`Body::from_stream(pod_resp.bytes_stream())`) and is unaffected. Distinct
from (not covered by) the existing 4MiB `DefaultBodyLimit` (`lib.rs:70,611`),
which only caps inbound request bodies, never response bodies read back from
a proxied backend. A backend reachable via `pods/proxy` rights (or via F2's
SSRF) that returns an oversized `text/html` body, or any body over
konnectivity, can exhaust apiserver memory with a small number of concurrent
requests.

**Fix sketch.** Cap the buffered size at both html-rewrite call sites and
the konnectivity `collect()` call (e.g. `http_body_util::Limited`), in line
with `MAX_BODY_BYTES`, returning 502/507 if exceeded.

Follow-on: **mayor-ukmal** (P2).

## Checked, no bug found: RBAC subresource verbs for exec/attach/portforward

The bead's threat model explicitly asked whether `pods/exec` requires the
`create` verb distinct from plain `pods`. Traced end-to-end against upstream
1.36:

- Upstream's `RequestInfoFactory.NewRequestInfo` (verified in
  `temp/research/requestinfo.go:176-191`) derives the RBAC verb purely from
  the HTTP method, with no special-casing for Connecter subresources like
  exec/attach/portforward: `GET → "get"`, `POST → "create"`.
- `ConnectResource` (`temp/research/rest.go:177-227`) performs admission
  (operation `Connect`) but NOT its own authorization check — authorization
  already happened earlier using that method-derived verb.
- kubectl's modern executor tries a WebSocket **GET** first
  (`remotecommand.NewWebSocketExecutor(config, "GET", ...)`,
  `temp/research/exec.go:154`, confirmed via `NewFallbackExecutor`'s
  ordering) and falls back to legacy SPDY **POST** only on upgrade failure.
  So upstream RBAC verb for exec/attach/portforward genuinely differs by
  transport: `"get"` for the new websocket path, `"create"` for the legacy
  SPDY path — which is why upstream's bootstrap `edit`/`admin` ClusterRoles
  grant BOTH `Read` (get/list/watch) and `Write` (create/...) verbs on
  `pods/attach`, `pods/exec`, `pods/portforward`, `pods/proxy`
  (`temp/research/policy.go:158,161`).
- u7s's `auth.rs:1331-1339` computes the verb identically: `get_verb(...)`
  for GET (yielding `"get"` for a named-pod exec/attach/portforward request,
  since no `watch=` param is present), `method_to_verb(POST) = "create"` for
  the SPDY-fallback POST leg (`pod_exec_post`/`pod_attach_post`/POST
  `pod_portforward`). u7s's seeded `edit`/`admin` ClusterRoles
  (`lib.rs:2144,2217`) grant the identical union of verbs
  (`get,list,watch,create,update,patch,delete,deletecollection`) on the
  same five resources, with an explicit comment recording why both are
  needed. This matches upstream's actual (non-obvious) dual-verb
  requirement correctly — not a bug, no follow-on filed.

## Checked, no bug found: `/log` query parameter bounds

`LogQuery` (`proxy.rs:39-51`) and `resolve_log_target` (`proxy.rs:219-249`)
forward `tailLines`/`sinceSeconds`/`limitBytes`/`follow` to kubelet verbatim
with no apiserver-side bound. This matches upstream, which also does not
bound these at the apiserver — kubelet's own `containerLogs` handler is the
sole enforcement point in both. Not a divergence from upstream; no follow-on
filed.

## Checked, no bug found: WebSocket/SPDY upgrade validation, stream splicing, TLS

`is_websocket_upgrade_request`/`is_raw_spdy_upgrade_request` (`proxy.rs:127-141,
1484-1498`) are straightforward `Connection`/`Upgrade` header checks with no
injection surface. `stream.rs`'s `splice()` uses bounded `mpsc::channel(256)`
in both directions — genuine backpressure, not unbounded buffering — and is
covered by a dedicated deadlock-regression test suite (large one-directional
transfer, Close-frame handling, close-code 1000 vs 1005). `build_kubelet_tls_config`
(`proxy.rs:591-635`) is strict, cluster-CA-pinned TLS with no bypass;
`build_insecure_tls_config`'s cert-verification skip is scoped only to
pod/workload TLS targets (matching upstream's documented `InsecureSkipVerify`
for that exact case, since pod certs have no cluster trust anchor to pin to)
and is never used for the kubelet leg. The inbound-request-body
`axum::body::to_bytes(req.into_body(), usize::MAX)` calls in `pod_proxy_dispatch`/
`service_proxy_dispatch`/`node_proxy` looked unbounded at first read, but the
outermost router layer already applies `DefaultBodyLimit::max(MAX_BODY_BYTES)`
(4 MiB, `lib.rs:70,611`) before any handler runs — `usize::MAX` here is just
"no *additional* cap beyond the global one", not an actual DoS gap. Ruled
out, no follow-on filed (see F3 for the real, response-side gap this
initial read led to).

## Follow-on beads filed

- **mayor-z54ge** (P0/bug) — F1, portforward CRLF/HTTP request splitting.
- **mayor-k6m4a** (P1/bug) — F2, podIP/EndpointSlice-address SSRF.
- **mayor-ukmal** (P2/bug) — F3, unbounded proxy-response buffering DoS.
- **mayor-c6njm** — addendum note appended (not a new bead): CRLF-in-podIP
  compounds into request splitting against konnectivity-server via
  `pod_proxy_via_connect_tunnel`'s CONNECT line; closing F2's fix closes this
  too.

All three new beads carry `discovered-from: mayor-usjqk`.
