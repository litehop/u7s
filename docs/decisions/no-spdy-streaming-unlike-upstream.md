# SPDY streaming is not served: exec and attach are WebSocket-only, unlike upstream

**Status:** Accepted
**Date:** 2026-11-02

## Decision

The apiserver does not implement SPDY for exec, attach or port-forward. A SPDY
upgrade request (`POST .../pods/{name}/exec` or `attach`) runs the same pod
lookup and admission checks as the WebSocket path, then answers 501
`NotImplemented` (`pod_exec_post` in `crates/apiserver/src/handlers/proxy.rs`).
WebSocket (`GET`) is the only client-facing streaming transport.

This deviates from upstream 1.37.1, which still serves SPDY alongside WebSocket.

## Context

Upstream has deprecated SPDY streaming in favour of WebSockets for years. u7s
has no clients that need SPDY, and a client-facing SPDY leg would be a second
streaming protocol to build and keep correct. This is a judgment call on that
principle; nothing was measured.

## Consequences

- kubectl 1.30 and later uses WebSocket for exec, attach and cp, and falls back
  to SPDY only when the WebSocket upgrade fails. In normal operation the 501 is
  never reached.
- Clients that hard-code SPDY fail. Known case: `sonobuoy retrieve`, which
  builds `remotecommand.NewSPDYExecutor` directly and reports "error retrieving
  results: EOF".
- Workarounds for sonobuoy: run `/sonobuoy splat` through WebSocket
  `kubectl exec` (`scripts/e2e-install/cloud-two-node.sh`), or read the tarball
  from the kubelet emptyDir (`scripts/conformance/06-run-sonobuoy.sh`).
- A WebSocket-first fallback executor in sonobuoy is under consideration
  upstream of u7s; that would remove the workaround.

## Alternatives rejected

- Implement SPDY on the client leg, translating to the kubelet leg u7s already
  speaks. Rejected: cost and ongoing surface for clients nobody runs. Revisit
  if a SPDY-only client that matters appears.
