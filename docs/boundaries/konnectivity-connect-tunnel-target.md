# Konnectivity CONNECT tunnel target construction

## Where

`pod_proxy_via_connect_tunnel` in `crates/apiserver/src/handlers/proxy.rs`.
When `konnectivity_proxy_addr` is configured, pod/service proxy requests
are dialed through an explicit HTTP CONNECT tunnel to konnectivity-server
instead of directly: the apiserver TLS-connects to konnectivity using its
own client identity (`kubelet_client_identity_pem`) and the cluster CA,
then writes a hand-built request line —
`CONNECT {pod_ip}:{port} HTTP/1.1\r\nHost: {pod_ip}:{port}\r\n\r\n` — naming
the pod's IP as the tunnel target.

## What crosses the boundary

`pod_ip` originates from `status.podIP` (or, on the service-proxy path, an
EndpointSlice address) — both attacker-influenced: a compromised node can
write its own pod's `status.podIP` to an arbitrary string, since the Node
authorizer bounds *which* pods a node may patch, not the field's value.
That string is spliced unescaped into the CONNECT line above, so it reaches
konnectivity-server carrying the apiserver's own trusted TLS identity.

## Current mitigation

`validate_proxy_target_ip` (`proxy.rs`, landed in PR #1513) rejects any
`pod_ip` that does not parse as `std::net::IpAddr`, which rejects an
embedded CRLF as a side effect (a string containing `"\r\n"` can never
parse as an IP literal), and separately rejects
loopback/link-local/multicast/unspecified ranges. `validate_pod_ip_against_node`
(landed in PR #1525) further cross-checks the value against the owning
node's `spec.podCIDR` or `status.hostIP`. The CRLF/request-splitting vector
against konnectivity-server via this CONNECT line is closed as of PR
#1513, not an open issue.

## Out of scope here

The tunnel and agent side of konnectivity itself (the `proxy-agent`
backend, its own auth/registration) is not audited by this note — a
dedicated konnectivity-focused audit is deferred to a future bead. This
note exists only so `pod_proxy_via_connect_tunnel`'s CONNECT request
construction, the one place the apiserver's own threat model unavoidably
touches konnectivity, is recorded as in that future audit's scope.
