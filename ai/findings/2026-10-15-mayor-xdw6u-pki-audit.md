# PKI inventory and rotation-gap audit

Bead: mayor-xdw6u
Date: 2026-10-15 (main at 50a84ac6)

**Answer: u7s has two CAs and one RSA key that never expire in practice (rcgen default validity 1975-4096) plus a set of equally non-expiring leaves, so nothing is at risk today; but nothing can be rotated either: the apiserver cannot hot-swap its TLS config, every consumer pins a single CA by value, and the only certs that rotate are KCM-signed kubelet client certs (default 1-year signing duration).** Meeting the operator's "rotate every cert, key and CA before expiry" target means first giving every cert a real lifetime, then building the missing hot-swap and trust-bundle machinery. The existing (CA-compromise) hard-cutover path stays manual.

Scope: read-only audit of `scripts/install.sh`, `scripts/u7s-start.sh`, `scripts/conformance/*`, `crates/apiserver/src/{tls,lib,args,handlers/proxy,handlers/aggregation,admission}.rs`. Nothing was run live; claims about runtime behaviour of upstream kubelet/KCM are marked as such.

## 1. Inventory

Key type is ECDSA P-256 for everything rcgen or `openssl ecparam -name prime256v1` makes (`KeyPair::generate()` = `PKCS_ECDSA_P256_SHA256`, rcgen 0.14.10 `key_pair.rs:85`), except the SA signing key (RSA-2048). Lifetime "default" = rcgen `CertificateParams::default()` = `not_before 1975-01-01`, `not_after 4096-01-01` (rcgen 0.14.10 `certificate.rs:84-85`); u7s never overrides it (grep for `not_after` in `crates/apiserver/src` finds only CSR-status plumbing, `types.rs:2023`).

"Regenerated" = created fresh in memory by `generate_tls` on every apiserver start (`tls.rs:472`); the matching kubeconfig is rewritten each start (`lib.rs:~245-262`, `write_kubeconfig`/`write_component_kubeconfig`).

| # | Item | Purpose | Issuer | Lifetime as set | Rotates today? | Stored | Pinned / consumed by |
|---|------|---------|--------|-----------------|----------------|--------|----------------------|
| 1 | Cluster CA (`ca.key` PEM + `ca.crt` DER, CN `u7s-ca-<6hex>`) | Signs serving, all client certs, CSR signing, kubelet serving | self | default 1975-4096 (`tls.rs:218-226`) | No. Loaded from disk if both files exist (`tls.rs:177-207`); a half-present pair is deleted and regenerated (`tls.rs:153-172`) | `$STATE_DIR/ca.{key,crt}`, key 0600 (`tls.rs:230`) | Every kubeconfig (embedded `certificate-authority-data`, `tls.rs:690-700`), apiserver mTLS root store (`tls.rs:597`), apiserver->kubelet verifier (`proxy.rs:612-634`), `kube-root-ca.crt`, `extension-apiserver-authentication` `client-ca-file`, KCM (`--cluster-signing-*`, `--root-ca-file`), kubelet `clientCAFile` |
| 2 | Front-proxy CA (`proxy-client-ca.{key,crt}`) | Signs only the proxy-client leaf | self | default (same fn, `tls.rs:562`) | No | `$STATE_DIR/proxy-client-ca.*` | `requestheader-client-ca-file` in `kube-system/extension-apiserver-authentication` (`lib.rs:3743`, reconciled), rig konnectivity bundle (`u7s-start.sh:215`) |
| 3 | SA signing key `sa.key` (RSA-2048, PKCS#1) + `sa.pub` | JWT signing for ServiceAccount tokens | n/a (key) | no expiry | No. Loaded if present (`tls.rs:59-110`); one verification key only (`lib.rs:301-315`) | `$STATE_DIR/sa.key` 0600 | apiserver (sign+verify), KCM `--service-account-private-key-file` (`install.sh:1047`) |
| 4 | apiserver serving leaf (CN `u7s-apiserver`, SANs localhost, 127.0.0.1, host.lima.internal, 10.96.0.1, kubernetes.default*, advertise host) | TLS :6443 | CA #1 | default | Regenerated each start, never expires | memory only (`tls.rs:487-499`) | Clients verify against CA #1 |
| 5 | admin client (CN `admin`, O `system:masters`) | kubectl, **and the control-plane kubelet** (`install.sh:1086` uses `--kubeconfig=$STATE_DIR/kubeconfig`) | CA #1 | default | Persisted; re-signed only if it no longer chains to the loaded CA (`tls.rs:281-364`) | `admin.{key,crt}`, kubeconfig | user kubeconfigs, CP kubelet |
| 6 | KCM client (`system:kube-controller-manager`) | KCM -> apiserver | CA #1 | default | Regenerated each start | `kcm-kubeconfig` (embedded) | KCM process, read once at start |
| 7 | scheduler client (`system:kube-scheduler`) | scheduler -> apiserver | CA #1 | default | Regenerated each start | `kubeconfig-scheduler` | scheduler |
| 8 | bootstrap-installer client (`system:bootstrap-installer`) | in-process manifest applier | CA #1 | default | Regenerated each start | memory | apiserver itself |
| 9 | kubelet-client (`kube-apiserver-kubelet-client`, O `system:masters`) | apiserver -> kubelet :10250 (logs/exec) | CA #1 | default | Regenerated each start | memory (`tls.rs:513-521`) | kubelet `clientCAFile` (CA #1) |
| 10 | proxy-client (`front-proxy-client`) | apiserver -> aggregated backends / webhooks (identity PEM) | CA #2 | default | Regenerated each start | memory (`lib.rs:376-395`) | backend `requestheader-client-ca-file` |
| 11 | kubelet client (worker, `system:node:<n>`, O `system:nodes`) | worker kubelet -> apiserver | CA #1, signed by **KCM csrsigning** with `--cluster-signing-cert-file=ca.pem --cluster-signing-key-file=ca.key` (`install.sh:1047`) | KCM default (`--cluster-signing-duration` is not passed anywhere; upstream default 1 year, not verified live) | **Yes, by config**: `rotateCertificates: true` (`install.sh:307`), `--cert-dir=$STATE_DIR/kubelet/pki`. No live verification found in the repo | worker `kubeconfig` (initial cert embedded) + kubelet pki dir | apiserver x509 auth |
| 12 | kubelet serving (CP and worker) | kubelet :10250 | CA #1 via `openssl x509 -req` | **3650 days** (`install.sh:354`, `:1083`) | No; minted once, skipped if the file exists (`test -s ...crt ||`). Worker gets it inside the join artifact incl. the private key (`install.sh:358-365`) | `kubelet-serving.{key,crt}` (`tlsCertFile`, `install.sh:303`) | apiserver kubelet verifier (CA #1 only) |
| 13 | rig: kubelet serving (lima) | same | CA #1 | 365 days (`conformance/lima-start.sh:505`) | No, reused if present | `$CERT_DIR/kubelet-serving*.crt` | rig only |
| 14 | rig: konnectivity-server / agent | konnectivity tunnels | CA #1 | 365 days (`u7s-start.sh:232,434`; `lima-start.sh:599`) | No | `$WORKDIR`, agent in a Secret | rig only (not in install.sh) |
| 15 | rig: webhook-smoke throwaway CA+leaf | e2e webhook | self | 1 day (`e2e-workload/webhook-smoke.sh:42,47`) | n/a | tmp | test only |
| 16 | join bootstrap token | worker CSR auth | n/a | no expiry (see 3kp5u audit) | No | `token-auth-file` | out of scope for PKI rotation, noted |

Totals: 2 CAs, 1 SA key, 7 apiserver-side leaves (5 regenerated per start, admin persisted, kubelet-client in memory), per-node kubelet client + serving certs, 3 rig-only leaf families. Longest lifetime: 2121 years (default 1975-4096). Shortest in production paths: kubelet client (1 year, KCM default). Shortest real cert anywhere: 1 day (test-only). The rig `-days 365` certs are the shortest long-lived ones in dev flows and do expire with no replacement.

## 2. Flat CA or separate?

Mostly flat. One CA (#1) is simultaneously:

- the apiserver **serving** trust anchor,
- the apiserver **client-auth** anchor (`WebPkiClientVerifier` root store contains only it, `tls.rs:596-607`; client cert verification is `allow_unauthenticated`),
- the **kubelet serving** issuer and the apiserver's kubelet-verification anchor (`proxy.rs:626`),
- the **CSR signer** (its private key is handed to KCM as `--cluster-signing-key-file`),
- the root published in `kube-root-ca.crt` and `extension-apiserver-authentication.client-ca-file`.

Only the front-proxy CA (#2) is separate. There are no separate serving and client CAs, and no intermediates. A leak of `ca.key` (readable by KCM's user and apiserver) lets the holder forge any identity including `system:masters`.

Flags: the apiserver is not driven by upstream flags. It has `--ca-key/--ca-cert`, `--proxy-client-ca-key/--proxy-client-ca-cert`, `--sa-key/--sa-pub` (`args.rs:25-59`) and no `--client-ca-file`, `--kubelet-certificate-authority`, `--requestheader-client-ca-file` or `--service-account-signing-key-file`; the equivalents are all implied from those paths. Upstream components get: KCM `--cluster-signing-cert-file=ca.pem --cluster-signing-key-file=ca.key --service-account-private-key-file=sa.key --root-ca-file=ca.pem` (`install.sh:1047`, `conformance/04-start-kcm.sh:156-159`); kubelet `clientCAFile: $STATE_DIR/ca.pem`, `tlsCertFile/tlsPrivateKeyFile` (`install.sh:303-306`).

## 3. What rotates today

- **Kubelet client cert (workers): configured to rotate.** `rotateCertificates: true`; signing by KCM at its default duration. KCM runs with `--controllers=*,...` so csrapproving/csrsigning/root-ca-cert-publisher are on (`install.sh:1047`). Not verified live in this audit; whether kubelet rotates a cert that was seeded from kubeconfig-embedded data (join path) rather than its own bootstrap flow is upstream behaviour I did not confirm. The control-plane kubelet does not use this path at all: it authenticates as `admin` via the shared kubeconfig, so it has no rotation and no expiry.
- **Kubelet serving cert: no.** 3650-day openssl cert, skipped if present. `RotateKubeletServerCertificate` is off and there is no serving-CSR approver (mayor-u251u; see `2026-10-15-mayor-3kp5u-gate6-multinode-audit.md`).
- **apiserver serving cert: effectively restart-only, and the restart is also what "rotates" it** (regenerated every start). It cannot be hot-reloaded: `generate_tls` builds one `ServerConfig` with `with_single_cert` (`tls.rs:605-607`), `serve_tls` wraps it once in `TlsAcceptor::from(server_config)` (`lib.rs:4477`), and no `ResolvesServerCert`, `Acceptor`/`LazyConfigAcceptor` or swap cell exists (grep `ResolvesServerCert` in `crates/` is empty). The client-auth root store is also frozen inside that config, so CA succession needs the acceptor swapped, not just the leaf.
- **Restarting the apiserver also rewrites the admin/KCM/scheduler kubeconfigs and re-issues the component leaves while the CA stays** (the admin cert itself is persisted and reused), so leaf refresh-by-restart already exists; there is no way to do it without dropping connections or on a schedule.
- CA, front-proxy CA, SA key, admin cert, kubelet serving: never.

## 4. What each consumer pins

- **kubeconfigs from `tls.rs`**: CA embedded by value (`certificate-authority-data`), client cert+key embedded, server URL fixed. Same for the worker kubeconfig `install.sh:446-470` (CA from the join artifact). No file-referenced CA option. Users' copies of the admin kubeconfig are the hard case: they pin a CA that expires and cannot be updated by the cluster.
- **Join artifact** carries the CA cert and a serving cert+key; worker writes `ca.pem` once (`install.sh:395`).
- **kubelet bootstrap**: `--kubeconfig` only (no bootstrap kubeconfig / `serverTLSBootstrap`).
- **kube-root-ca.crt**: apiserver seeds it per namespace at boot with the single CA, create-only (`AlreadyExists` is ignored, `lib.rs:3832-3841`), so a changed CA is not re-seeded by u7s. KCM's root-ca-cert-publisher also runs, fed from `--root-ca-file=$STATE_DIR/ca.pem`; `ca.pem` is re-derived from `ca.crt` at every start by `ExecStartPre` (`install.sh:1016`), and holds exactly one cert on the production path (the rig appends the front-proxy CA, `u7s-start.sh:215`). Pods read the ConfigMap, so in-cluster trust follows KCM.
- **extension-apiserver-authentication**: reconciled by the apiserver and updates both `client-ca-file` and `requestheader-client-ca-file` when either CA file changes (`lib.rs:3714-3743`, tests at `lib.rs:8444+`), so aggregated backends can learn a new front-proxy CA.
- **Aggregation / webhooks**: `build_backend_client` (`aggregation.rs:205`) and the webhook client (`admission.rs:1136-1198`) trust `spec.caBundle`/`clientConfig.caBundle` plus the cluster CA (konnectivity), and present the startup `proxy_client_identity_pem` (kept in `AppState`, set once at `lib.rs:395`). Backend serving certs are the backend's own business; u7s only needs the bundle to contain every valid CA.
- **Konnectivity**: rig only. Server/agent certs signed by CA #1, `-days 365`, bundle files assembled by shell.

## 5. Warning headers

**Not emitted anywhere.** A search of `crates/apiserver/src` for `Warning` header construction (`header::WARNING`, `"warning"`, `Warning:`) finds only unrelated `tracing::warn!`, a Kubernetes Event type, and `deprecation_warning`/`expressionWarnings` payload fields; no response layer sets `Warning`. The `apiextensions_gen_adapter.rs:211` test message about "the client warning header" refers to a field it carries but nothing converts it to a header. kubectl prints any `Warning: 299 - "..."` it receives.

Feasible hook: `serve_tls` already extracts the peer cert per connection (`lib.rs:4503-4510`), so a response layer can warn the *calling* identity about its own client cert (the common case: a user's admin cert) and every caller about CA expiry.

## 6. k3s comparison (stable tag v1.36.5+k3s1; sources fetched via `gh api`)

- **Leaf lifetime 365 days; CA 10 years.** k3s generates certs with `rancher/dynamiclistener/cert`: `NewSelfSignedCACert` `NotAfter = notBefore + 10*duration365d`, `NewSignedCert` `expiresAt := duration365d` (dynamiclistener `cert/cert.go:84,114`, read on its default branch, not version-pinned).
- **Renewal at startup:** `config.CertificateRenewDays = 120` (`pkg/daemons/config/types.go:30`); `deps.go:757-762` `expired()` returns true when a cert is within 120 days of expiry (`certutil.IsCertExpired(cert, 120)`), and on true the cert is regenerated on k3s start. k3s therefore renews only when restarted inside the last 120 days; there is no live hot-swap rotation.
- **Monitor and Node Events:** `pkg/certmonitor/certmonitor.go`, every 30 min (`certCheckInterval`), after the apiserver is ready, events against the Node:
  - Warning `CertificateExpirationWarning`: "Node certificates require attention - restart k3s on this node to trigger automatic rotation: <errs>" when any node cert is within 120 days (`:93-96`).
  - Warning `CACertificateExpirationWarning`: "Certificate Authority certificates require attention - check k3s documentation and begin planning rotation: <errs>" when a CA is within 365 days (`:98-101`).
  - Normal `CertificateExpirationOK` once after startup if clean (`:105-108`).
  - Prometheus gauge `k3s_certificate_expiration_seconds{subject,usages}` (`:37-40,126`).
- **CA rotation:** `k3s certificate rotate-ca --path <dir>` "Write updated K3s CA certificates to the datastore" (`pkg/cli/cmds/certs.go:81-82`, handled by `pkg/server/handlers/cert.go`), with consistency checks bypassable by `--force`; it is a manual operator step with new CAs supplied (cross-signed generator scripts in `contrib/util/`). `k3s certificate rotate` renews leaf certs on disk.
- k3s separates client-ca, server-ca and request-header-ca, plus `service.key` (`deps.go:103-111`); u7s has one flat CA plus front-proxy.

## 7. Gaps against the operator's target

1. **No cert has a real lifetime.** Nothing can be "approaching expiry" until leaves and CAs get finite `not_before/not_after` (rcgen defaults 1975-4096 mean the first expiry is in the year 4096). Introducing finite lifetimes is itself the trigger for every other gap.
2. **No in-process hot-swap**: single frozen `ServerConfig` and `TlsAcceptor`, including the client-CA store.
3. **No scheduled rotation driver** (no timer, no 2/3-lifetime logic); restart-time regeneration is the only leaf refresh.
4. **Control-plane kubelet shares the admin cert** and so has no rotation; `serverTLSBootstrap`/serving-CSR approver is missing (mayor-u251u), serving cert is 10 years, per-start private-key transport in the join artifact.
5. **Single-CA pinning everywhere by value**: user kubeconfigs, worker kubeconfig, join artifact, apiserver root store, kubelet `clientCAFile`, apiserver->kubelet verifier (single `root_store.add`, `proxy.rs:626`), `kube-root-ca.crt` seeding (create-only), `ca.pem` for KCM (one cert, rig bundles two). None accepts a bundle or a succession.
6. **KCM signs with the CA key and cert files read at startup**; a successor CA needs a KCM restart, and `--cluster-signing-duration` is unset (1-year default for kubelet client certs, bounded by nothing).
7. **SA key**: one signing/verification key, no overlap, no `kid`-based multi-key verification (`lib.rs:301-315` builds a single `DecodingKey`); rotation invalidates every issued token.
8. **No warning/event channel**: no `Warning` header, no Node Events, no expiry metric.
9. Rig certs (365 d) expire with no replacement path; low priority but will bite long-running dev/CI stacks.
10. No u7s-owned verification of which long-lived certs exist (no `check` command like `k3s certificate check`).

## 8. Design options for the operator

**A. Leaf rotation (apiserver-owned).** Give leaves finite lifetimes (suggest 1 year for admin/component clients, 90 days or less for the apiserver serving cert), re-issue at ~2/3 lifetime from a background task, and swap the live config. Hot-swap mechanisms: (i) `ResolvesServerCert` backed by an `ArcSwap`-style cell for the serving leaf only (smallest change; no CA change); (ii) a swappable `TlsAcceptor`/`ServerConfig` holder read per accepted connection, which also handles a new client-CA store. Choose (ii) if CA succession is in scope; (i) alone is a trap because the client verifier would stay frozen. Component kubeconfigs (KCM, scheduler, kubelet on CP) still need a reload story: either have each re-read its kubeconfig (KCM and kubelet re-read client cert files only if given file paths, not embedded data; a restart per component via systemd is the pragmatic choice), or give components file-referenced certs.

**B. Kubelet certs.** Move the CP kubelet to its own `system:node` identity (CSR path) so `rotateCertificates` covers it; enable `serverTLSBootstrap` + a narrow serving-CSR approver (mayor-u251u) and drop the 10-year openssl cert and the transported serving key; set `--cluster-signing-duration` explicitly.

**C. CA succession (no pre-published successor, per the operator's decision).** At ~2/3 CA lifetime generate a successor CA cross-signed by the old one; make all consumers trust a bundle (old + new) for the overlap; flip issuance to the new CA; drop the old CA after the longest leaf lifetime plus margin. Users with pinned kubeconfigs only keep working during overlap if they pin the old CA, which still verifies leaves issued by the new CA only via a cross-signed chain presented by the server. This needs the server to present `leaf + cross-cert` so an old-CA-only client builds a path to the old anchor. The cross-signed path is the mechanism that makes "no user involvement" possible for pinned kubeconfigs at all; it is the riskiest piece. kubectl `Warning` headers during the window are the user-visible fallback. u7s must also (a) bundle-ify `ca.pem`, `kube-root-ca.crt` seeding (update, not create-only), the kubelet verifier, `clientCAFile`, and (b) restart KCM against the new CA key/cert.

**D. SA key rotation.** Keep multiple verification keys (published `sa.pub` bundle, `kid` header), sign with the newest, retire old keys after the max token lifetime (bound projected tokens at 1 h plus legacy non-expiring tokens, which need a policy decision).

**E. Visibility.** Add (1) an HTTP `Warning: 299` response layer (peer-cert aware, plus CA/leaf at-risk state from a shared handle), (2) a 30-minute monitor that emits Node Events using k3s's reasons (`CertificateExpirationWarning`, `CACertificateExpirationWarning`, `CertificateExpirationOK`) and a `u7s_certificate_expiration_seconds` gauge.

**Two-tier (root + intermediate): benefits vs risk, stated concretely.**

- Benefit that does not materialise here: the usual win is an offline root whose key never touches the running system while a short-lived intermediate signs leaves, so a compromise of the online host only costs the intermediate. u7s is single-node and the rotation must be unattended, so the root key must stay online or be accessible to the rotator; it would sit on the same disk as the intermediate. Also, clients pin the *root*; the root still expires, so the hard problem (rotating the pinned root, for users with pinned kubeconfigs) is unchanged.
- Benefit that does materialise: the intermediate can be rotated frequently (say yearly) without touching any pin while the root is valid (10-year), shrinking the number of times user kubeconfigs are stale from "every CA rotation" to "every root rotation".
- New risks: (1) the apiserver must serve `leaf + intermediate`; today it serves the leaf alone because Go's verifier rejects a chain where the intermediate equals the trust anchor (`tls.rs:578-583`) -- fine for a distinct intermediate, but any consumer holding the intermediate as its anchor and the root absent breaks; (2) client certs issued by KCM csrsigning must carry the chain so the apiserver's root-only `WebPkiClientVerifier` can build a path (kubelet client cert files and embedded kubeconfig data must hold the chain; rustls requires clients to send intermediates); (3) CSR signing then needs the intermediate cert+key and the right `--cluster-signing-*` files; (4) every consumer pinned to a single CA today (list in section 7.5) would need chain handling or root-only pinning, and `build_kubelet_tls_config`'s single-cert root store must accept a chain-plus-root.
- **Verdict: do not adopt two tiers in the first iteration.** Benefit is small without an offline root, risk touches every chain-consuming path at once. Revisit only after bundle-tolerance (gap 5) and hot-swap (gap 2) exist: then a two-tier layout adds only the chain-serving change (1)-(2) and can be introduced as a pure issuance change.

## 9. Proposed Phase-3 bead breakdown (dependency order)

1. **Cert lifetimes + expiry model**: finite lifetimes in `tls.rs` for every leaf and a configurable CA lifetime; shared in-memory "cert inventory" with `not_after` per cert. Fix default/rig `-days` values. Prerequisite for everything.
2. **Expiry visibility**: `Warning: 299` response layer (peer-cert aware + CA/leaf at-risk), Node Events (k3s reasons) from a 30-min monitor, `u7s_certificate_expiration_seconds` metric. Depends on 1. Useful before rotation exists (gives the operator cliff warning).
3. **Swappable TLS config in the apiserver**: acceptor/config holder, covering serving leaf and client-CA verifier; leaf rotation task at 2/3 lifetime. Depends on 1.
4. **Component identity reload**: KCM, scheduler, CP kubelet pick up re-issued client certs (file-referenced certs or orchestrated restart); CP kubelet gets its own node identity. Depends on 3. Overlaps mayor-u251u.
5. **Kubelet serving cert via CSR** (`serverTLSBootstrap` + serving-CSR approver, drop `-days 3650` and key transport), explicit `--cluster-signing-duration`. Depends on mayor-u251u, 1.
6. **CA bundle tolerance everywhere**: bundle-aware `kube-root-ca.crt` (update, not create-only), `ca.pem`, kubelet verifier, `clientCAFile`, join artifact, `extension-apiserver-authentication`, webhook/aggregation trust. Depends on none; precondition for 7 and for any two-tier option.
7. **CA succession** (cross-signed successor, overlap, drop old after margin, KCM restart); front-proxy CA follows the same path. Depends on 3, 4, 6.
8. **SA key rotation with verification-key overlap** (`kid`, multi-key `DecodingKey` set, token-lifetime policy). Independent; depends on 1 only for scheduling.
9. Nice-to-have, later: `u7s kubeconfig refresh`, file-referenced CA option for kubeconfigs, `u7s certs check` command, two-tier evaluation redo.

## Evidence index

- rcgen defaults: `~/.cargo/registry/src/*/rcgen-0.14.10/src/certificate.rs:84-85` (`date_time_ymd(1975,1,1)` / `(4096,1,1)`); key default `key_pair.rs:85-86`.
- No hot reload: `lib.rs:4477` `TlsAcceptor::from(server_config)`; no `ResolvesServerCert` match in `crates/`.
- No Warning header: no `header::WARNING`/`"warning"` header construction in `crates/apiserver/src` (only the hits listed in section 5).
- k3s: `certmonitor.go` (`:33,93-108`), `types.go:30`, `deps.go:757-762`, `certs.go:81-82` at tag `v1.36.5+k3s1`; dynamiclistener `cert/cert.go:84,114` (default branch).
- Not verified: live behaviour of kubelet client-cert rotation in u7s; KCM default signing duration is upstream knowledge, not exercised here.
