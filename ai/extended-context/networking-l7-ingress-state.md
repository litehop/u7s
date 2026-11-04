---
as_of: 2026-10-30
kind: initiative-state
---

# Networking / L7 ingress and TLS: state as of 2026-10-30

Traefik cleartext ingress has landed; TLS comes later via cert-manager, after
the 1 GiB wedge is investigated. Phases 7/8 are undecided.

## Settled

- Traefik (cleartext HTTP) is the ingress controller for example workloads:
  the WordPress example (`mayor-lrqbx`, #2028). Follow-up polish: `mayor-dn1j7`
  (pin image by digest, exercise NodePort 30080 in the smoke test).
- TLS deferral lifted 2026-10-25 (GCP test VPSes have public IPs). The operator
  chose cert-manager over Traefik's built-in ACME (2026-10-30), `mayor-s82zr.2`
  (P3): first reproduce and root-cause the wedge (cert-manager is ~100 MiB and
  wedged a 1 GiB node 4 times; report RSS per component, test trimming), then
  TLS on the Traefik example. A self-signed/CA Issuer can validate the wiring on
  Lima; real ACME needs a DNS name, a Let's Encrypt contact email and a narrow
  80/443 firewall rule from the operator. The ArgoCD deferral still stands.
- No PROXY protocol or TPROXY is needed behind beep: client IP arrives in
  `X-Forwarded-For`. Traefik measured ~45 MiB idle / ~54 MiB loaded on an
  e2-micro. Findings: `git show
  archive/mayor-s82zr.1-findings:ai/findings/2026-10-25-mayor-s82zr.1-ingress-tls-landscape.md`.
- kube-proxy replacement is a separate research bead (`mayor-31bz8`).

## CRD bugs the research surfaced

`mayor-fvh8w` (structural pruning drops `additionalProperties` map fields),
`mayor-jhtep` (`/apis` drops versions when a second CRD shares a group),
`mayor-mqb79` (`additionalPrinterColumns` dropped), `mayor-n88nk` (CEL cost of
`has()`); check bead state. Not started: `mayor-lqu0h`, `mayor-jqdf9`,
`mayor-hkufk`.

## Undecided

Phase 7/8 scope (Gateway API conformance subset; hostNetwork versus
LoadBalancer exposure).
