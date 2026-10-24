# ServiceAccount tokens are ES256, signed by a key that rotates automatically with overlap

**Status:** Accepted
**Date:** 2026-10-23

## Context

SA tokens were RS256 from one RSA-2048 key with no `kid`, so the key could never
change without invalidating every token, and the RSA private-key operation was
the RUSTSEC-2023-0071 (Marvin) exposure with no upstream fix.

## Decision

- Tokens are ES256 (ECDSA P-256, aws-lc-rs) and carry a `kid`
  (base64url SHA-256 of the SPKI DER). The `rsa` crate is gone from the tree.
- `sa.key` is a JSON keyring (mode 0600, replaced atomically): an ordered list
  of keys, each with a `sign_from` instant. The signer is the last key whose
  `sign_from` has passed; every key in the list verifies. `sa.pub` is a PEM
  bundle of all verification keys.
- A successor is generated and published (verification, `/openid/v1/jwks`) 24 h
  before it signs; keys sign for 90 days. A replaced key is dropped 49 h after
  its successor starts signing: the 48 h TokenRequest maximum plus 1 h margin.
  No token is minted with a lifetime beyond the maximum.
- Verification selects the key by `kid`; a missing or unknown `kid`, or any
  algorithm other than ES256, is rejected before the signature cache is
  consulted, so a retired key stops working even for cached tokens.
- A keyring file that does not parse fails startup instead of being replaced.
- Legacy SA token Secrets (non-expiring JWTs) are unsupported: they have a
  different issuer, no `exp` and no `kid`, and the token controller stays off.
  No 1.37 conformance spec depends on them.

## Rationale

Rotation is a pure function of the persisted list and the clock, so a crash
between any two steps resumes from the file alone. Retirement is tied to the
maximum token lifetime, so a token never outlives its key. This matches
kube-apiserver, which verifies against several keys and signs with one.

## Consequences

- Upgrading from an RSA `sa.key` fails startup; delete it to start a new
  keyring (every issued SA token stops verifying).
- Rotation periods are fixed; only the `pki-test-knobs` build compresses them
  (`U7S_PKI_TEST_SA_ROTATION_SECS`).
- Anything outside u7s that verifies SA tokens must refresh JWKS at least
  daily to see a successor before it signs.
