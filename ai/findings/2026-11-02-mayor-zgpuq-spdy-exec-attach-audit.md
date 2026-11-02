# SPDY exec/attach: reuse of the port-forward SPDY path (audit)

Bead: mayor-zgpuq
Date: 2026-11-02T11:54Z, base db17cb86, upstream refs = `release-1.37`

**Answer: the port-forward raw-upgrade pattern is reusable for exec/attach
(Option A, pass-through to the kubelet's SPDY handler), and the change is NOT
significant -- roughly 150-250 lines of production code in
`crates/apiserver/src/handlers/proxy.rs` plus ~250-350 lines of tests, no new
crates, no SPDY parsing -- but it is not a drop-in: the raw-upgrade handler
hardcodes the port-forward protocol and answers 101 before dialing the
kubelet, and exec/attach need the kubelet's negotiated
`X-Stream-Protocol-Version` relayed to the client.** Upstream does exactly
this pass-through, and the 1.37 kubelet still serves SPDY exec/attach.
Recommendation: Option A, gated on a live rig check (section 5).

Not verified live (no rig used): anything about how the Lima rig behaves.
Everything below is from u7s source and upstream `release-1.37` source,
fetched into `temp/research/k137/` (gitignored).

## 1. Today's paths (u7s, `crates/apiserver/src/handlers/proxy.rs`)

Route table: `crates/apiserver/src/lib.rs:1189-1199` (exec/attach GET + POST
handlers differ; portforward GET and POST share one handler).

| Path | Client leg | Kubelet leg | Translation? |
|---|---|---|---|
| exec GET (`pod_exec`, :1293) | WebSocket, offers `v4`/`v5.channel.k8s.io` (`EXEC_KUBECTL_PROTOCOLS` :1110) | WebSocket `wss://.../exec/ns/pod/container`, subprotocol `v5.channel.k8s.io`, retry `v4` (:1095, :1101, `run_exec_proxy` :1490) | Mostly byte relay, but `run_exec_proxy_spliced` (:1517) absorbs kubelet's Success status frame (not a pure splice) |
| attach GET (`pod_attach`, :717) | WebSocket, `v5.channel.k8s.io` only (`ATTACH_SUBPROTOCOL` :557) | WebSocket, v5 then v4 fallback (`run_attach_proxy` :1026) | Byte relay (BiStream `splice`) |
| exec/attach POST (`pod_exec_post` :1338, `pod_attach_post` :753) | any | none | Runs `resolve_*_target` (pod/node lookup + CONNECT admission webhooks) then returns 501 |
| portforward GET, `SPDY/3.1+portforward.k8s.io` | WebSocket carrying SPDY | raw `POST` + `Upgrade: SPDY/3.1` over TLS (`dial_kubelet_portforward` :1950, `portforward_post_request` :1929) | None: `portforward_proxy_tunneled` (:2014) is `splice(AxumWs, RawStream)`, opaque bytes |
| portforward GET, `v4.channel.k8s.io` | WebSocket | WebSocket v4 | Byte relay (`portforward_proxy_v4` :2101) |
| portforward POST `Upgrade: SPDY/3.1` (`portforward_proxy_raw_upgrade`, :2128) | raw hijacked connection | raw SPDY POST, same dial | None: `splice(RawStream, RawStream)`; no SPDY frame is ever parsed |

So: portforward_proxy_raw_upgrade splices an upgraded client connection to a
kubelet that itself speaks SPDY; SPDY multiplexing happens end to end between
client and kubelet. It parses HTTP only (the kubelet's 101 response, keeping
bytes read past `\r\n\r\n` as a prefix, :1975-:2004).

Other facts relevant to reuse:
- Kubelet reachability: exec, attach and portforward all dial
  `node_ip:kubelet_port` directly (`TcpStream::connect` :1957 /
  `connect_async_tls_with_config` :1446). Konnectivity is used only for
  pod/service proxy (:2864+), so no node-proxy/konnectivity routing applies
  to this change.
- Timeouts: none on the splice (neither exec WS, nor portforward). The kubelet
  enforces its own streaming idle/creation timeouts. Exec/attach/portforward
  are classed long-running by subresource regardless of method
  (`is_long_running_request`, auth.rs:885), so the POST upgrade is exempt
  from the in-flight limits and body deadline.
- HTTP/1.1 upgrade support on the serve loop is already in place for POST
  (`serve_connection_with_upgrades`, serve.rs:317-330).

## 2. What upstream does (1.37.1)

- Authz: `ExecREST/AttachREST/PortForwardREST.Connect` call
  `ensureAuthorizedForVerb(..., "create")` under
  `AuthorizePodWebsocketUpgradeCreatePermission`
  (`pkg/registry/core/pod/rest/subresources.go:118,193,279`).
- Dispatch (:208-232 exec, :134-157 attach): the base handler is
  `UpgradeAwareHandler` (`newThrottledUpgradeAwareProxyHandler`, :309). With
  `TranslateStreamCloseWebsocketRequests`, a `NewTranslatingHandler` routes
  only requests matching `IsWebSocketRequestWithStreamCloseProtocol` (the
  WebSocket/v5 client) to the `StreamTranslator` (WebSocket client -> SPDY
  toward kubelet; skipped when `ExtendWebSocketsToKubelet` and the node
  advertises it). Everything else, including a client's SPDY `POST`, falls
  through to the `UpgradeAwareHandler`.
- `UpgradeAwareHandler.tryUpgrade`
  (`apimachinery/pkg/util/proxy/upgradeaware.go:309-445`): clones the
  client request, dials the backend (`DialForUpgrade`, :342), reads the
  backend's response; if 101 it hijacks the client, writes the backend's
  response (headers included) to the client (:388-407), then `io.Copy`s both
  ways (:421-440). Non-101 backend statuses are written to the client as-is.
  No SPDY parsing. This is the model for Option A.
- The 1.37 kubelet still serves SPDY: `createStreams`
  (`staging/src/k8s.io/cri-streaming/pkg/streaming/remotecommand/httpstream.go:101`)
  uses WebSocket if `IsWebSocketRequest`, else `createHTTPStreamStreams`
  (`httpstream.Handshake` + SPDY upgrade). `SupportedStreamingProtocols` =
  v4, v3, v2, v1 (`constants.go:75`); v5 is WebSocket-only. client-go's SPDY
  executor offers v5,v4,v3,v2,v1 (`client-go/tools/remotecommand/spdy.go:67-72`);
  kubelet's `negotiateProtocol` picks the first client entry the server
  supports, i.e. v4, and returns it in the 101's `X-Stream-Protocol-Version`.
  The client reads that header to pick its stream handler, so it must reach
  the client.
- kubectl: `createExecutor` (`kubectl/pkg/cmd/exec/exec.go:145-165`) builds
  `SPDYExecutor(POST)` and, unless `RemoteCommandWebsockets.IsDisabled()`,
  wraps it in a `FallbackExecutor(WebSocket GET -> SPDY POST)` when
  `httpstream.IsUpgradeFailure`. `KUBECTL_REMOTE_COMMAND_WEBSOCKETS` still
  exists in 1.37; it is removed in 1.38 (CHANGELOG-1.38.md:204, "kubectl
  always uses WebSockets (with SPDY fallback)"). The rig installs kubectl
  from apt pinned to the kubelet minor (scripts/install.sh:2035;
  `K8S_VERSION="1.37.1"` in scripts/build-release-tarball.sh:24), so the env
  var applies to the rig's kubectl (not run to confirm).

## 3. Options

### A. Pass-through POST+SPDY to the kubelet (recommended)

Reuse (as-is): `is_raw_spdy_upgrade_request` (:1814), `RawStream` /
`splice` (stream.rs:208, :313), the hyper `OnUpgrade` hijack in
`portforward_proxy_raw_upgrade`, `parse_https_url` (:1841),
`kubelet_endpoint_url`, `resolve_exec_target` / `resolve_attach_target`
(pod/node lookup, container, kubelet query mapping
`kubelet_stream_params`, CONNECT admission, TLS config), the route-level
AuthLayer create check, and the portforward mock-kubelet test pattern
(:6248, :6700).

Generalise (small):
1. `dial_kubelet_portforward` + `portforward_post_request` take a request
   description (path+query, `X-Stream-Protocol-Version` value) instead of
   the hardcoded `portforward.k8s.io`. `PortforwardParams` (:1604) and
   `ExecTarget`/`AttachTarget` carry the same four fields apart from the URL
   scheme (`wss` vs `https`); either let `parse_https_url` accept `wss`, or
   build `https` in the POST path.
2. `portforward_proxy_raw_upgrade` answers 101 first and dials afterwards,
   with a fixed `X-Stream-Protocol-Version: portforward.k8s.io` (:2150-2160).
   Exec/attach must dial the kubelet FIRST, check it answered 101, and copy
   the kubelet's `X-Stream-Protocol-Version` into the client's 101 (as
   upstream's `tryUpgrade` writes the backend response). That means the
   dial helper returns the parsed response headers, and a kubelet
   non-101 (e.g. 403 "unable to negotiate protocol") surfaces as a Status
   to the client instead of a dropped post-101 connection. This is the
   only non-trivial change; port-forward can adopt it too (its current
   dial-after-101 behaviour makes a kubelet failure an opaque EOF).
3. The client's `X-Stream-Protocol-Version` (possibly multiple header lines,
   comma-separated) must be forwarded to the kubelet. Treat it as untrusted
   text written into a hand-rolled request: positive allowlist
   `[A-Za-z0-9._,+/ -]`, reject otherwise (same reason `validate_ports_param`
   exists, :1623). Never forward other client headers (Authorization etc.);
   the request is built from scratch.

New: `pod_exec_post` / `pod_attach_post` bodies (take `Request<Body>`,
require `is_raw_spdy_upgrade_request`, else keep today's 501-style Status or
400 for plain POST), the header-relay in the dial helper, input validation,
tests.

Size: ~150-250 LoC production (one file, `proxy.rs`; `lib.rs` route table
unchanged because POST handlers already exist), ~250-350 LoC tests.

Authz: every request hits the AuthLayer before the handler; POST maps to verb
`create`, so the `create` check holds with no handler code, and the matrix
{exec,attach,portforward} x {WS GET, plain GET, POST} is already tested
(auth.rs:5098 `pod_stream_subresources_require_create_even_over_get_websocket`).
The new handlers must keep calling `resolve_*_target` so CONNECT admission
webhooks still run on the SPDY path (otherwise the `webhook deny attach`
[Conformance] behaviour would be bypassable by POST).

Resize/stdin/stderr: end to end inside SPDY streams (v4 adds the `resize`
stream, `httpstream.go` v4ProtocolHandler); the apiserver never sees them.
Lower-risk than the WebSocket relay: no frame inspection to get wrong. One
behavioural difference to document: the WebSocket exec path rewrites/absorbs
the kubelet Success status frame (`exec_status_frame_is_success`); SPDY
passes the kubelet's error-stream bytes through verbatim, which matches
upstream.

Timeouts: none added (matches port-forward); kubelet idle/creation timeouts
apply. Bound the kubelet dial + 101 read with a timeout (the portforward dial
has none today; a stuck kubelet would otherwise hold the client's pre-101
request indefinitely once dial moves before the 101).

Risks:
- Header injection into the hand-built kubelet request (mitigated by
  allowlist, see 3).
- Dial-before-101 refactor touches the port-forward path; regression-test
  the existing portforward raw-upgrade tests.
- The raw-POST portforward path has only mock-kubelet unit tests; no live
  evidence in this audit that real kubectl's SPDY POST negotiation works
  end to end through u7s-apiserver's hyper upgrade. This is the main residual
  risk and the reason for the live check below.
- No `MaxBytesPerSec` throttling (upstream
  `PerConnectionBandwidthLimitBytesPerSec`); u7s has none for any streaming
  path today.

### B. Translate SPDY <-> the WebSocket kubelet protocol u7s uses

Requires a SPDY/3.1 framing implementation (SYN_STREAM/SYN_REPLY/DATA/RST,
zlib header compression with the SPDY dictionary, per-stream flow
control), the v4 stream-type header semantics, plus mapping error/resize
streams to channel bytes and back. Estimated 1.5-3k LoC and new crates
(zlib/spdy framing) or a hand-rolled implementation; high conformance risk
(exit-status mapping, half-close). Upstream does not do this (it only
translates WebSocket->SPDY in `StreamTranslator`). Not recommended.

### C. Keep 501 (documented deviation)

Zero cost. Breaks `sonobuoy retrieve` (the original finding), any client that
only speaks SPDY (older kubectl, client-go callers using
`NewSPDYExecutor` directly, `KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false`), and
anything where the WebSocket attempt is rejected for a non-upgrade reason
and the fallback then needs a working POST. Contradicts the "match upstream
1.37.1" stance for kubectl <= 1.37, which keeps SPDY as the fallback.

## 4. Upstream specs (release-1.37; none force SPDY via env var)

(1) Port-forward over SPDY. All are in
`test/e2e/kubectl/portforward.go` ("Kubectl Port forwarding", run through
the `kubectl port-forward` binary, i.e. SPDY-tunneled-over-WebSocket,
falling back to raw SPDY POST) and use `ginkgo.It`, NOT
`framework.ConformanceIt`. `grep -i 'port-forward|portforward|forwarding'` on
`test/conformance/testdata/conformance.yaml` at release-1.37 finds no match,
so there is NO [Conformance]-tagged port-forward spec. Specs: "should support
a client that connects, sends NO DATA, and disconnects" (0.0.0.0, localhost),
"...sends DATA, and disconnects" (x3), "should stop port-forwarding",
"port-forward should keep working after detect broken connection"
(:523-640); "should support forwarding over websockets" (:539, :561) uses the
raw `v4.channel.k8s.io` client, not SPDY; and
`test/e2e/kubectl/kubectl.go:582` "should support port-forward". So the
original approval rested on non-conformance e2e coverage, not Conformance.

(2) Exec/attach over SPDY.
- No upstream e2e spec sets `KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false` or
  calls `NewSPDYExecutor` directly (grep of the fetched kubectl.go,
  portforward.go, pods.go, exec_util.go).
- SPDY is reached only through the fallback (WebSocket GET refused with a
  non-101): `test/e2e/framework/pod/exec_util.go:79` uses
  `exec.DefaultRemoteExecutor` (kubectl's websocket-then-SPDY executor), as
  do all `kubectl exec/attach/run --attach/cp` specs in
  `test/e2e/kubectl/kubectl.go` (e.g. :779 "should support inline execution
  and attach", :837 "should support inline execution and attach with
  websockets or fallback to spdy", :560 exec exit codes). None of these is
  `[Conformance]`; they exercise SPDY only when the GET upgrade fails.
- [Conformance] specs touching the fallback: "Admission webhook, deny
  attach" (conformance.yaml:85): the denied WS GET is retried as SPDY POST and
  must surface the webhook's message, which is the reason the current 501
  handlers run `resolve_*_target` first. Passing today; must still pass
  after the change (denial must stay a 403 Status, never 101).
- [Conformance] "Pods, remote command execution over websocket" /
  "logs from websockets" (conformance.yaml:2796-2808) use the raw
  `channel.k8s.io` WebSocket client, not SPDY.
- Hence a SPDY change cannot be gated on any upstream Conformance spec; it
  can be gated on the live rig tests below (and the non-conformance specs
  that only reach SPDY via fallback).

Acceptance tests to prove it (live rig):
- `KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false kubectl exec` (stdout, stderr,
  stdin `-i`, `-it`/resize if a pty is available, non-zero exit code
  propagation = 42) and `kubectl attach`; `kubectl cp` both directions.
  Check the env var against the rig's installed kubectl first
  (`kubectl version --client`; exists through 1.37, removed in 1.38).
- `sonobuoy retrieve` (the original failure).
- Unit: mock kubelet asserts POST + `Upgrade: SPDY/3.1` + forwarded
  `X-Stream-Protocol-Version` + `input/output/error/tty` query mapping;
  client 101 carries the kubelet's negotiated version; kubelet 403 reaches
  the client as a non-101 Status; CRLF in the protocol header is rejected;
  webhook denial on POST is 403 not 101 (existing behaviour); bytes
  byte-identical both ways.

## 5. Recommendation

Do Option A. u7s already carries the hard part (hyper upgrade hijack, TLS
dial to the kubelet, header-end/prefix handling, an opaque splice), the kubelet
1.37 accepts SPDY exec/attach unconditionally via `createHTTPStreamStreams`,
and upstream's own behaviour for a client SPDY POST is exactly a verbatim
`UpgradeAwareHandler` pass-through, so the amount of new protocol logic is
only "forward the client's protocol list, relay the kubelet's choice". The
create check, admission and kubelet routing are inherited. The one real
design change (dial the kubelet before sending 101) is also an improvement
for the existing port-forward path. Option B is an order of magnitude more
code and risk for no extra conformance; Option C leaves a documented break
against kubectl <= 1.37's own fallback. Size call: NOT significant. Before
building, a 2-minute live check on the Lima rig would settle the one
unverified factual question (whether real kubectl's raw SPDY POST negotiates
through u7s's hyper upgrade today): run
`KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false KUBECTL_PORT_FORWARD_WEBSOCKETS=false
kubectl port-forward pod/<p> 8080:80` and curl it; if that works, the
reuse premise is confirmed end to end.
