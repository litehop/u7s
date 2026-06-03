# Webhook TLS verification via konnectivity tunnel

**Status:** Accepted
**Date:** 2026-06-03

## Context

u7s routes admission webhook calls through a konnectivity HTTP CONNECT proxy
(no kube-proxy in the dev setup). Webhook pods present TLS certs with the
service DNS name as SAN (e.g. `e2e-test-webhook.webhook-N.svc`), not the pod
IP. Without special handling, connecting via pod IP causes cert hostname
verification to fail.

## Decision

Use the service DNS name as the webhook URL host (correct SNI), and
`reqwest::Client::resolve()` to statically map that hostname to the pod IP
obtained from the Endpoints store. No DNS query is issued; no cluster-domain
configuration is needed.

## Alternatives considered

| Option | Chain verified | Hostname verified | DNS dep |
|--------|---------------|-------------------|---------|
| `danger_accept_invalid_certs` | No | No | No |
| `danger_accept_invalid_hostnames` + caBundle CA | Yes | No | No |
| Service DNS URL + `.resolve()` to pod IP | Yes | Yes | No |
| Service DNS URL + VM DNS resolution | Yes | Yes | Yes |

The chosen approach provides full TLS security (chain + hostname) without any
`danger_*` flags and without a dependency on cluster DNS configuration.

## Consequences

Each service-based webhook call builds a per-call `reqwest::Client` using the
webhook's `caBundle` CA and a static resolver entry mapping the service DNS name
to the pod IP. The fallback (when `caBundle` is absent) uses the shared
cluster-CA-pinned client. Direct-URL webhooks are unaffected.
