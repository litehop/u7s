# The cluster CA is a 10-year root that signs only a yearly, auto-rotating intermediate

**Status:** Accepted
**Date:** 2026-10-24

## Context

Clients pin the cluster CA (kubeconfigs, `ca.pem`, `kube-root-ca.crt`,
`clientCAFile`, `--root-ca-file`). One CA that signs every leaf can only be
replaced by redistributing trust to every client.

## Decision

- `ca.crt`/`ca.key` is the root (10 years). It signs only the intermediate and is
  the only anchor clients pin. The key stays on the control-plane host.
- `intermediate.crt` (DER) and `intermediate.key` sit next to it: ECDSA P-256,
  1 year, `pathlen:0`. It signs every cluster leaf, including what KCM issues
  through the CSR API. The front-proxy CA stays single-tier.
- The apiserver re-issues the intermediate at 2/3 of its life, writing the pair
  with the leaf protocol (both temp files fsynced, cert renamed, then key; a
  crash between the renames rolls forward). Every leaf signed by a previous
  intermediate is re-issued in the same pass, and again on resume after a crash.
  A half-present pair refuses startup.
- Leaves are served and written with their intermediate after them
  (`admin.pem`, `kcm.pem`, `scheduler.pem`, the kubelet-client identity, the
  serving chain). The root is never part of a chain.
- KCM's `--cluster-signing-cert-file` is `intermediate-cert.pem` (the same
  certificate, PEM) with `--cluster-signing-key-file=intermediate.key`; KCM
  reloads both files. KCM rejects a signing file with more than one certificate
  and returns the bare leaf, so the apiserver appends the signing intermediate
  to `status.certificate` when the signer writes it.
- An old intermediate keeps verifying every leaf already issued, because each
  leaf presents it; nothing server-side lists intermediates as trust anchors.

## Rationale

Routine rotation then changes only material the apiserver and KCM own; no
kubeconfig, bundle, ConfigMap or kubelet `clientCAFile` changes. Cross-signing
is needed only at root succession. kubeadm and k3s use the same 10-year CA with
1-year leaves.

## Consequences

- A cluster installed before this change has a root-signed leaf set and no
  intermediate; the intermediate is created at the next start and the leaves are
  re-issued under it. KCM must be restarted onto the new signing flags.
- A client presenting an intermediate-signed leaf without the intermediate is
  rejected. Kubelets write `status.certificate` verbatim, so the appended chain
  is what they present; certificates signed directly by the root before this
  change verify without a chain until they renew.
- The `pki-test-knobs` build compresses the intermediate life
  (`U7S_PKI_TEST_INTERMEDIATE_LIFETIME_SECS`).
