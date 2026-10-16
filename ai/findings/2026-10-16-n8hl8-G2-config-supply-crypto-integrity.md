G2 found 0 HIGH, 7 MED, 11 LOW and 5 INFO; the most serious is that the whole install trust chain (script, tarball, checksum) comes from one channel with no signature, so one compromised GitHub write credential or proxy yields root on every installing host (G2-1).

Audited 2026-10-16 (UTC) at main aec606e3. Read-only; nothing was run against a live cluster, so every finding is "by reading" unless marked confirmed.

Bead: mayor-n8hl8

Legend: attacker positions are MITM (network), LOCAL (unprivileged user on the node), SUPPLY (upstream dependency or CI compromise), API (authenticated API user), ANON (unauthenticated network client). xdw6u = touches the pending PKI decisions.

## Findings

### G2-1 MED, A08/A03, SUPPLY or MITM-of-proxy: install chain has no authenticity root
- `scripts/install.sh:225-245` (`fetch_tarball`) fetches the tarball and `<url>.sha256` from the same host/path (the u7s.dekiru.tech nginx proxy in `deploy/get-u7s/get-u7s.yaml`, which relays GitHub release assets). The hash only detects corruption. Whoever can publish or replace the release (or control the proxy) controls tarball, checksum and install.sh together, and the tarball becomes root-run binaries (`systemd` units, `/opt/u7s/bin`).
- `.github/workflows/release-tarball.yaml`: no signing, no `actions/attest-build-provenance`, no GitHub Environment with required reviewers. Any `v*` tag push (or `workflow_dispatch`) by anyone with write access publishes; a non-prerelease tag instantly becomes `latest`, i.e. what `https://u7s.dekiru.tech/install.sh` serves. `curl | sudo bash` of `latest` is therefore one write token away from fleet-wide root.
- `workflow_dispatch` runs the build from the dispatching ref, but `gh release create` with no `--target` tags the default-branch HEAD, so published bytes can differ from the tagged source.
- Fix sketch: sign tarball+checksum (cosign keyless, or minisign with the public key committed in README and verified by install.sh when present), publish GitHub build attestations, require a protected Environment (manual approval) for the release job, pass `--target "$GITHUB_SHA"`.
- Evidence: by reading.

### G2-2 MED, A03, SUPPLY: release job runs dependency build scripts next to a write token and a restored cache
- `release-tarball.yaml:28-31`: `permissions: contents: write` plus `actions/checkout` with default `persist-credentials: true`, so the write token sits in `.git/config` while `cargo build` runs ~377 crates' `build.rs`/proc-macros (`scripts/build-release-tarball.sh:46`). A malicious dependency can use it to modify releases.
- `release-tarball.yaml:55` restores `Swatinem/rust-cache` (written by main-branch CI, `test.yaml` `save-if main`) into the release build: a poisoned main cache feeds the release artifacts.
- `dtolnay/rust-toolchain` at "stable" floats; no `--locked` anywhere in the release or CI cargo calls (`grep --locked` finds only `cargo install cargo-llvm-cov`), so a stale lock is silently re-resolved.
- Fix: `persist-credentials: false`; split build (read-only) from publish (write) jobs passing the artifact; no cache in the release build; `cargo build --locked`; pin the toolchain version.
- Evidence: by reading.

### G2-3 MED, A03, ANON (network, pre-auth): vulnerable h2 in the server HTTP/2 stack
- `Cargo.lock:1261` h2 0.4.15; RUSTSEC-2026-0258 (2026-08-17, unbounded empty DATA frames, memory/panic) is patched in >= 0.4.16. `cargo tree -p u7s-apiserver -i h2` confirms it is compiled in via hyper under axum, and the TLS listener negotiates h2 (`tls.rs:613`) with `allow_unauthenticated` client certs, so it is reachable before any authn. The advisory rates it Low; MED here because the apiserver is the single control-plane process.
- Fix: `cargo update -p h2`. Renovate is configured (`.github/renovate.json`) but evidently has not landed it in 2 months; there is no `cargo audit`/`cargo deny` job in CI (`grep audit|deny .github` empty, no `deny.toml`). Add one.
- Evidence: advisory fetched from rustsec/advisory-db (raw copies in `temp/research/`); lock version confirmed.
- Other lock entries checked against 2025-2026 advisories: aws-lc-sys 0.46, rustls 0.23.46, rustls-webpki 0.103.15, time 0.3.47, bytes 1.12.1, rand, tokio 1.53, tracing-subscriber 0.3.23, slab, anyhow, crossbeam-epoch all at or above patched versions. quinn-proto 0.11.14 is vulnerable but not compiled (`cargo tree -i quinn-proto`: nothing to print). `cargo audit` is not installed, so this was a manual cross-check of crate names in Cargo.lock against the advisory-db tree, not a complete scan (pre-2025 advisories were only skimmed by name).

### G2-4 MED, A03/A08, MITM-of-mirror or SUPPLY: CRI-O apt key is fetched from the same mirror it authenticates
- `scripts/install.sh:654-656`: the CRI-O `Release.key` comes over TLS from `slc-mirror.opensuse.org` (a third-party mirror of OBS) and is then trusted via `signed-by` for packages from the same host, so a mirror compromise (or its TLS cert) installs root-run packages with a matching key. The k8s repo key (`:758`, pkgs.k8s.io) is the project's own host, less exposed. Neither key's fingerprint is verified.
- Fix: pin the expected key fingerprint in install.sh (`gpg --show-keys --with-colons` compare), or ship the key in the signed tarball.
- Evidence: by reading.

### G2-5 MED, A04/A02, LOCAL/API (after key theft): every cert is valid 1975-4096, no rotation, no revocation (xdw6u)
- `tls.rs` never sets `not_before`/`not_after`; rcgen 0.14.10 `CertificateParams::default()` is 1975-01-01 to 4096-01-01 (`rcgen-0.14.10/src/certificate.rs:84-85`, confirmed in vendored source). Applies to: CA (`tls.rs:219`, `IsCa::Ca(Unconstrained)`), admin cert CN=admin O=system:masters persisted to `admin.crt/admin.key` and re-embedded in the kubeconfig (`:347-362`), kubelet-client (O=system:masters), KCM, scheduler, bootstrap-installer, front-proxy, server cert. Loaded admin certs are reused as long as they chain to the CA, forever. A leaked `kubeconfig` (the only copy outside the node is whatever the operator scp'd to a laptop) is a permanent cluster-admin credential; there is no CRL/OCSP and rustls `WebPkiClientVerifier` is built with no CRLs.
- Worker serving certs and the control-plane kubelet serving cert are `-days 3650` (`install.sh:361`, `:1093`) and `ExecStartPre` never renews them.
- Key algorithms are fine: `KeyPair::generate()` = ECDSA P-256 (rcgen default), RNG from ring/aws-lc through rcgen; SA key RSA-2048 via `OsRng`.
- Fact for decisions P1-P7: the CA is `Unconstrained` (no pathlen, no name constraints) and one CA signs serving, client-auth, kubelet and KCM CSRs (`--cluster-signing-key-file=ca.key`, `install.sh:1057`); the front-proxy CA is already separate (`tls.rs` proxy_client_ca).
- Fix: explicit short validity per leaf (+ in-process reload), bounded CA lifetime; this is what xdw6u already scopes.
- Evidence: confirmed by reading code and rcgen source.

### G2-6 MED, A02/A07, API/network holder of a join artifact: bootstrap tokens never expire and are reusable
- `install.sh:342` appends `secret,system:bootstrap:<id>,<uid>,system:bootstrappers` to `token-auth-file`; `auth.rs:137-190` `load_token_file` has no expiry field and nothing deletes a used entry, yet comments at `install.sh:38` and `:519-526` say tokens are "single-use". RBAC seeds (`lib.rs:2015, 2071`) grant `system:bootstrappers` the node-bootstrapper and nodeclient rights, so a leaked artifact can repeatedly obtain a client cert for `CN=system:node:<any name>, O=system:nodes` (the nodeclient recognizer checks the CN prefix, not a specific node), usable for Node-authorizer reads of secrets of pods scheduled on that node name. Upstream bootstrap tokens are Secrets with a 24h `expiration`.
- Revocation requires hand-editing the file and restarting the apiserver (token map is read once at startup).
- Fix: add an expiry column to the token file and enforce it; consume/delete on first CSR; correct the "single-use" comments.
- Evidence: by reading (no live join was run).

### G2-7 MED, A02, API (any pod creator): PodSecurity admission is not implemented, PSA labels are inert
- No code reads `pod-security.kubernetes.io/*` (`rg pod-security` hits only tests that guard label edits, `handlers/namespaces.rs:5557-5700`, and `manifests/flannel.yaml:33` sets `enforce: privileged`). Upstream enables the PodSecurity plugin by default. An operator who labels a namespace `enforce: restricted` gets no enforcement and no warning; anyone with `create pods` can run privileged/hostPath/hostNetwork pods.
- Fix: implement PodSecurity (baseline/restricted checks) or at minimum document it prominently, and reject or warn on the labels until it exists. Not in any bead (`bd search PodSecurity` is empty).
- Evidence: by reading; behavior not exercised live.

### G2-8 LOW, A03/A08, SUPPLY: kubelet and kube-controller-manager provenance is only a same-origin checksum
- `scripts/build-release-tarball.sh:55-66`: fetches `dl.k8s.io/release/v1.36.4/bin/linux/amd64/<bin>` and compares to `<url>.sha256` from the same host. Upstream publishes cosign signatures; `.../kubelet.sig` and `.../kubelet.cert` both return HTTP 200 (curl, 2026-10-16), unused. Verify with `cosign verify-blob` in the build script; the shipped tarball then carries them to installers.
- Evidence: confirmed (HTTP 200 for sig/cert), verification absent by reading.

### G2-9 LOW, A02, ANON: discovery and OpenAPI paths skip authn and RBAC entirely
- `auth.rs:723-737` `is_exempt`: `/healthz /readyz /livez /api /apis /discovery/v2 /openapi/v2 /openapi/v3` bypass authentication and authorization (`auth.rs:1206`). Upstream gates `/api`, `/apis`, `/openapi/*` behind `system:discovery` (system:authenticated only); only health and `/version` are public. Anonymous callers can enumerate every API group, CRD and its OpenAPI schema. Cross-note for G1 (A01).
- Fix: route these through authz with the `system:discovery`/`system:public-info-viewer` bindings, as `/version` already is.
- Evidence: by reading.

### G2-10 LOW, A02: CertificateSubjectRestriction admission is missing
- No equivalent of the upstream default-on plugin: `handlers/csr.rs` only validates the request PEM and signerName; `handlers/approval.rs:997` mentions O=system:masters in a comment only. A caller holding `approve`/`sign` for `kubernetes.io/kube-apiserver-client` can obtain an O=system:masters cert signed by the cluster CA (KCM signs with `ca.key`). Requires a privileged RBAC grant already, so defense-in-depth only. (xdw6u relevance: the signing CA is the root CA.)
- Evidence: by reading.

### G2-11 LOW, A04: Secrets are plaintext in sqlite, no EncryptionConfiguration
- No encryption code anywhere in `crates/` (`rg -i encrypt` hits only an unrelated test string in `handlers/certificates.rs`). `state.db` is created via `Connection::open` (`crates/store/src/sqlite.rs:1122`) with umask-default mode (0644); it is protected only by the `/var/lib/u7s` 0700 directory from install.sh. A copy of the DB file (backup, scp, container volume) discloses every Secret and the SA tokens' bound data. Upstream's default is also plaintext etcd but offers EncryptionConfiguration.
- Fix: chmod the DB and WAL files 0600 on open; consider an at-rest key option later.
- Evidence: by reading.

### G2-12 LOW, A02: control plane runs as root, no systemd hardening, and standing admin-equivalent identities
- `install.sh:987-1110`: u7s-apiserver, u7s-kcm and kubelet units run as root with no `NoNewPrivileges`, `ProtectSystem`, `CapabilityBoundingSet` or `User=`. KCM does not need root but reads `ca.key`/`sa.key` as root. An RCE in any of them is full host root and CA theft.
- The control-plane node's kubelet authenticates with the admin kubeconfig (`install.sh:1096`, system:masters), so a kubelet compromise is cluster-admin (the rationale for `system:node:` identities already exists on workers).
- `system:bootstrap-installer` (`lib.rs:1799-1827`) holds `bind` plus create/patch/update on clusterrolebindings, i.e. effectively cluster-admin; its cert is valid to 4096 (G2-5). Anything dropped in `/etc/u7s/manifests` (applied on boot and on SIGHUP, with no ownership/permission check, `bootstrap_apply.rs:115-165`) runs with that power; the directory is root-owned 0755 from install.sh.
- Evidence: by reading.

### G2-13 LOW, A02 (cross-note to G3/A10): raw internal errors in 5xx bodies
- `Status::internal(e.to_string())` and `format!("... {e}")` return store/sqlite/reqwest error text to clients; counts of matching call sites: cr.rs 57, resource.rs 38, proxy.rs 33, pods.rs 33, crd.rs 19, namespaces.rs 15. `proxy.rs:522` returns TLS dial errors including internal addresses. Impact is information disclosure of internals, not credentials (no token logging found: `rg 'tracing.*(token|bearer|authorization)'` only matches a file-path log line).
- Evidence: by reading.

### G2-14 LOW, A04: SA signing key hygiene and `rsa` crate advisory (xdw6u)
- RSA-2048, single key, no `kid` (`handlers/tokens.rs:296`, `sa_sig_cache.rs:83-88` says rotation is future work), so there is no rotation path and no verification overlap. Verification pins RS256 with issuer `https://kubernetes.default.svc`, `leeway = 0`, `exp` required (`auth.rs:515-523`); legacy `kubernetes.io/service-account-token` JWTs (different issuer, no exp) would be rejected, which answers part of the legacy-token decision: they are currently not accepted.
- `rsa` 0.9.10 (RUSTSEC-2023-0071, Marvin timing side channel, no patched version). Token minting performs the private-key operation on request; exposure is a remote timing attack by an API user allowed to create tokens; practical exploitation is hard. Prefer `aws-lc-rs` for signing (already a dependency).
- SA sig cache (`sa_sig_cache.rs`): key is sha256 of the whole token, expiry capped to real `exp` (`capped_expiry`); audience and liveness are re-checked on hits. OK.
- Evidence: by reading.

### G2-15 LOW, A04: CA partial-state handling destroys the CA key; permission-on-create only
- `tls.rs:149-170`: if `ca.key` exists but `ca.crt` does not (or vice versa) the code deletes the survivor and silently generates a new CA, rotating trust for every kubelet, instead of failing loudly. Same pattern for the admin cert (`:296-337`). An accidental `rm ca.crt` becomes an irreversible key loss. xdw6u relevance: CA lifecycle.
- `write_private_key` (`tls.rs:23-35`) applies mode 0600 only when it creates the file; `OpenOptions` does not chmod an existing file, so a pre-existing 0644 `kubeconfig` (rewritten on every start) or key stays 0644. Inside the 0700 state dir this is mitigated; matters for dev runs with `./` default paths.
- `random_ca_suffix` (`tls.rs:121`) is nanos XOR pid, explicitly non-cryptographic (fine for its stated purpose).
- Evidence: by reading.

### G2-16 LOW, A08/A02, LOCAL: join artifact exposure
- `install.sh:371-377` prints `--token '<artifact>'` (base64 JSON with the bootstrap token and the node's serving PRIVATE key) to stdout and the operator must pass it on the joining node's command line, visible in `/proc/<pid>/cmdline`, shell history and CI logs. The token is also passed via `curl -H` (`:426-437`). Prefer reading the artifact from a root-only file or stdin. Combined with G2-6 (no expiry) this makes leaks long-lived.
- Evidence: by reading.

### G2-17 LOW, A08, MITM: curl is not restricted to https
- All `curl -fsSL` calls (`install.sh:233,236,654,758`, README one-liner) follow redirects including https to http, with no `--proto '=https' --tlsv1.2`. install.sh has no `main()` wrapper, so a truncated pipe into `bash` runs a prefix of the script (mostly harmless today; each step is idempotent).
- Evidence: by reading.

### G2-18 LOW, A03: release tarball is not reproducible
- `build-release-tarball.sh:93` plain `tar -czf` (mtime, uid/gid, file order, gzip header time), no `SOURCE_DATE_EPOCH`, no `--remap-path-prefix` (binaries embed build paths via `debug = "line-tables-only"`), floating toolchain, no `--locked` (G2-2). Independent rebuild verification is not possible.
- Evidence: by reading.

### G2-19 INFO, A02: defaults of the bare binary
- `args.rs`: `--listen` defaults to `0.0.0.0:6443`; install.sh passes the NIC IP. Single TLS listener only; no insecure port, no pprof/debug route, no CORS layer, `/metrics` requires auth. KCM `--bind-address=127.0.0.1`. Kubelet is left at upstream defaults (listens on all interfaces :10250; x509 client CA configured; anonymous auth off and authorization Webhook are the config-file defaults, not verified live).
- TLS: rustls with the aws-lc-rs post-quantum provider (`rustls_post_quantum::provider()`), default protocol versions (TLS 1.2 and 1.3, AEAD suites only, no CBC/RSA key exchange). mTLS is optional (`allow_unauthenticated`), then falls through to token/anonymous.

### G2-20 INFO, A03: in-cluster images are tag-pinned, not digest-pinned
- `manifests/flannel.yaml:177,204,215` (ghcr.io flannel v0.28.9, hostNetwork, NET_ADMIN/NET_RAW), `manifests/kube-proxy.yaml:98` (privileged, hostNetwork), `manifests/coredns.yaml:114`. Mutable tags from third-party registries run as privileged host-level workloads on every node at bootstrap. Pin by `@sha256:`. The nginx proxy image in `deploy/get-u7s/get-u7s.yaml` is digest-pinned (good).

### G2-21 INFO, A03/A08: vendored protos and manifests
- `crates/proto-generated/proto-include` (UPSTREAM_VERSION v1.37.1) is fetched with `gh api` at a tag and checked by `PROTO_SHA256SUMS`, which is self-generated by `scripts/vendor-protos.sh`: it detects drift and hand edits, not upstream authenticity. `crates/apiserver/proto/*` are byte-identical duplicates (checked apps/v1 hash); the shipped kubelet/KCM are 1.36.4 while protos are 1.37.1 (version skew, not a security issue). No build-time network fetch exists (`protoc-bin-vendored` crate carries protoc).
- `cargo` source: 452 crates.io packages with checksums plus one git dependency (`politeia`, litehop-owned, tag v0.2.0 resolved to commit `96c33a7e` in the lock). No `[patch]`, no registry replacement.

### G2-22 INFO, A04: hand-rolled RSA-PSS verification
- `handlers/certificates.rs:598-650` implements EMSA-PSS verification manually (any salt length, to interoperate with Go's max-salt signer) for PodCertificateRequest proof of possession. It handles only public data (no timing concern), exponent size is bounded by `rsa`'s key parser and modulus restricted to 3072/4096 bits. Reviewed the padding checks; found no flaw, but custom crypto deserves a vector test against Go output if one does not exist.

### G2-23 INFO, A02: aggregated API TLS behavior matches upstream
- `handlers/aggregation.rs:232-266`: `insecureSkipTLSVerify` honored; the cluster CA is trusted in addition to the APIService `caBundle`; front-proxy identity is presented even when verification is skipped. Same as upstream, noted because the front-proxy cert is sent to an unverified endpoint in that mode. Pod/service proxy `https:` targets skip verification (`proxy.rs:715-730`, `:2385`), as upstream.

## Pending PKI decisions (xdw6u) relevant facts
- All leaf and CA certs 1975-4096 via rcgen default (G2-5); only worker kubelet client certs rotate (CSR).
- One unconstrained CA signs everything including KCM CSR signing; front-proxy CA is already separate (G2-5, G2-10).
- SA key: RSA-2048, single, no `kid`; verifier cannot hold two keys; legacy SA JWTs currently rejected (iss/exp) (G2-14).
- CA partial-state handling regenerates the CA (G2-15), relevant to CA succession design.
- Kubelet serving certs are 10-year, script-minted (G2-5).
- The admin kubeconfig is the control-plane kubelet's identity and is rewritten at every start (G2-12).

## Checked and OK
- GitHub Actions: every `uses:` (workflows and `.github/actions/e2e-focus-run/action.yml`) is pinned to a 40-hex SHA; Renovate configured to pin digests. Workflows have explicit `permissions`, `pull_request` only (no `pull_request_target`), no `secrets.` references.
- Private-key files are created 0600 and the state dir 0700 by install.sh; kubeconfigs (admin, KCM, scheduler, bootstrap-installer) go through `write_private_key`.
- Static token lookup is constant-time (`auth.rs:207-224`, `subtle`), empty token rejected; HMAC check uses `verify_slice`.
- SA JWT: algorithm pinned RS256, issuer and audience enforced, no leeway; cache design sound.
- CSR path verifies proof of possession and request signature with aws-lc-rs.
- `deploy/get-u7s`: TLS verified upstream (`proxy_ssl_verify on`), narrow tag/asset regex (not an open relay), nonroot read-only nginx pinned by digest.
- install.sh refuses unverified URL downloads (`fetch_tarball` fails closed on a missing or mismatched sidecar), `--tarball` path skips verification by design; payload staged in /var/tmp; cluster CA used for `--join` comes from the out-of-band artifact (`curl --cacert`).
- Dependencies: no OpenSSL, TLS stack is rustls/aws-lc; 377 unique crates in the apiserver tree, all registry crates carry lock checksums.

## Not covered
- No `cargo audit`/`cargo deny` run (tools absent); advisory cross-check was manual, 2025-2026 advisories only (G2-3).
- No live cluster test: exempt-path behavior, kubelet defaults, PSA behavior and token reuse (G2-6) not exercised.
- `lima/`, `scripts/gcp/`, `scripts/conformance/` and the e2e scripts; GitHub repository settings (branch protection, tag protection, immutable-release setting, Actions policy) were not inspectable.
- The u7s.dekiru.tech deployment itself (Ingress TLS, DNS, who controls the proxy and the `U7S_DIST_BASE_URL` variable).
- Authz logic (G1), injection/DoS/logging/exception handling (G3) beyond cross-notes: G2-9 (exempt paths), G2-13 (error bodies), G2-6 (bootstrap-token authn), node-name interpolated into sourced `config` and `bash -c` at `install.sh:1093` (operator-supplied, root only, for G3).
