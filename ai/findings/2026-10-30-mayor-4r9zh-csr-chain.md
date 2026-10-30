# CSR status.certificate carries leaf + intermediate: deliberate, needs an operator decision

Bead: mayor-4r9zh

Upstream returns the bare leaf, u7s appends the signing intermediate on purpose (ADR
two-tier-cluster-ca-with-rotating-intermediate), and leaf-only cannot be done without
a trust-model change, so nothing was implemented. Operator decision needed.

## Where and why

- `append_signing_chain` in `crates/apiserver/src/handlers/csr.rs` (called from the
  status write path, ~line 908) appends the intermediate that signed the leaf when the
  signer first writes `status.certificate`. KCM itself returns the bare leaf.
- ADR: clients pin only the root; "a client presenting an intermediate-signed leaf
  without the intermediate is rejected. Kubelets write `status.certificate` verbatim,
  so the appended chain is what they present." Also "nothing server-side lists
  intermediates as trust anchors", which is what keeps routine rotation free of
  bundle/ConfigMap/clientCAFile changes.
- Not re-run live on main; the failing archive
  (`temp/e2e/1030-0220--sig-auth-certificates-api-privileged-clusteradmin`) shows
  certificates.go:171 `len 2`, which matches the code path above.

## Upstream (release-1.37)

`pkg/controller/certificates/authority/authority.go`: `CertificateAuthority` holds a
single `Certificate *x509.Certificate`; `Sign` returns the DER of the leaf only. There
is no chain support, so the e2e's "single cert" assertion is upstream behaviour. Fetched
copy: `temp/research/authority.go` (gitignored).

## Options

A. Keep chain-append, accept the divergence. Test is `[Privileged:ClusterAdmin]`, not
   `[Conformance]`. Cost: one permanent e2e failure (or skip entry); users doing
   `kubectl get csr -o jsonpath` and expecting one cert see two (most PEM consumers cope).
B. Leaf-only, and the apiserver trusts intermediates itself: its in-process client-cert
   (and kubelet-CA) verification pool becomes root + current/previous intermediates,
   which the apiserver already tracks (`signing_intermediates`). No on-disk bundle,
   kubeconfig or ConfigMap changes, so rotation stays transparent. Kubelets then present
   a bare leaf and the apiserver verifies it. Cost: a deliberate trust-model change
   (intermediates become anchors, contradicting the ADR bullet; pathlen:0 and the 1-year
   life still bound them); any other verifier of kubelet/CSR-issued certs that pins only
   the root (third-party webhooks, kubelet serving consumers) fails. Needs an ADR update
   and e2e-pki-rotation re-run.
C. Chain-append per signer: leaf-only for `kube-apiserver-client`/custom signers,
   chain for kubelet signers. Likely still fails the upstream test's follow-on step of
   building a client with the cert (a leaf-only client cert against a root-pinned
   verifier), unless combined with B.

## Recommendation

B if conformance parity on this test matters (it is the only option that makes
leaf-only clients work, and it matches upstream's wire format); otherwise A with an
explicit known-divergence entry. Do not pick C alone.
