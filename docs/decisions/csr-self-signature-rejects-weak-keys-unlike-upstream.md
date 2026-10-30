# CSR self-signature verification rejects RSA under 2048 bits, SHA-1/MD5 and P-224

**Status:** Accepted
**Date:** 2026-10-30

## Decision

CSR create verifies the PKCS#10 self-signature like upstream, with aws-lc-rs
only (no in-tree crypto). Deliberate divergence from Go, as a security default:
RSA keys under 2048 bits are rejected for PKCS#1 v1.5 and PSS (Go accepts 1024+),
SHA-1/MD5 signatures are rejected (as Go), and P-224 is rejected (Go accepts).

## Consequences

- Clients enrolling with 1024-bit RSA or P-224 keys fail at create; use RSA 2048+,
  P-256/384/521 or Ed25519.
