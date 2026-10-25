---
as_of: 2026-10-25
kind: initiative-state
---

# Networking / L7 ingress and TLS: state as of 2026-10-25

Research recommends Traefik with built-in ACME as the L7/TLS tier, but the
operator has not yet approved that direction; no implementation has started.

## Settled

- The operator lifted the 2026-08-31 TLS deferral on 2026-10-25: GCP test
  VPSes have public IPs, so the stated reason (no bidirectional connectivity)
  no longer holds. TLS/ACME work is allowed when nothing higher-priority is
  queued, research first (epic `mayor-s82zr`). The ArgoCD deferral still
  stands.
- kube-proxy replacement is a separate research bead (`mayor-31bz8`), related
  only as networking.

## Research recommendation (`mayor-s82zr.1`)

Findings (archived): `git show
archive/mayor-s82zr.1-findings:ai/findings/2026-10-25-mayor-s82zr.1-ingress-tls-landscape.md`.

- Traefik: Ingress and Gateway API, built-in ACME; ~45 MiB idle / ~54 MiB
  under load on an e2-micro.
- Terminate TLS at the controller with built-in ACME. cert-manager costs
  ~100 MiB and wedged a 1 GiB node 4 times.
- No PROXY protocol or TPROXY needed behind the front proxy (beep): the
  client IP was verified in `X-Forwarded-For`.

## CRD bugs the research surfaced

`mayor-fvh8w` (structural pruning drops `additionalProperties` map fields),
`mayor-jhtep` (`/apis` drops versions when a second CRD shares a group),
`mayor-mqb79` (`additionalPrinterColumns` dropped), `mayor-n88nk` (CEL cost
of `has()`). Check bead state for status.

Follow-ons, not started: `mayor-lqu0h` (defaulting, CEL rules and patch
schema lookup ignore `additionalProperties`), `mayor-jqdf9` (bound JSONPath
evaluation work for printer columns), `mayor-hkufk` (reject `properties` +
`additionalProperties` together at CRD create).

## Open: operator has not decided

- Adopt the Traefik + built-in ACME direction.
- Phases 5-8: a Traefik example extending `mayor-lrqbx` (plaintext today)
  with EC256 certs and a persistent ACME volume; a cert-manager 1 GiB wedge
  investigation; a Gateway API conformance subset; hostNetwork versus
  LoadBalancer exposure.
- A real DNS name and Let's Encrypt contact email.
- A standing 80/443 VPC firewall rule for test VPSes.
