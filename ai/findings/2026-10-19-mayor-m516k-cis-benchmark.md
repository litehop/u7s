u7s fails CIS in a small number of real ways (no Secrets-at-rest encryption, no audit log, no PodSecurity admission, no `--use-service-account-credentials`, unrestricted Service externalIPs, a few unset hardening knobs); about two thirds of the raw kube-bench FAILs/WARNs (64 of 98) are profile mismatch, not-applicable-by-design or operator-policy, because u7s has no k8s-style apiserver flags and no etcd.

Bead: mayor-m516k

Audited 2026-10-19 at `d1096dd9` (main), u7s stack on `lima-node-smoke` (K8s 1.37.1 kubelet/KCM, u7s-apiserver + scheduler on the macOS host), one node.

## Method

- Benchmark: kube-bench v0.16.0 (2026-08-05, linux/arm64, sha256 `64500561...5d10b` checked against the release `checksums.txt`), CIS Kubernetes Benchmark profile `cis-1.12` — the newest profile in the v0.16.0 release (maps K8s 1.32-1.34). `cis-2.0` (K8s 1.34/1.35) exists only on kube-bench `main`, unreleased; no profile is mapped for 1.37. k3s/RKE2 precedent (`k3s-cis-1.9`, `rke2-cis-1.9`) rewrites the check audits for their binaries; u7s only needed the config overrides below plus manual verification, because the unmodified checks scrape `ps` flags and u7s has few flags.
- Inside the VM only (kube-bench copied in with `limactl copy`; nothing installed on the host). The apiserver runs on the host on the rig, so the VM carries a stub process (a `perl` copy named `u7s-apiserver` whose argv is the real apiserver argv) for kube-bench's `ps -C` scrape; KCM and kubelet are the real in-VM processes. File-mode checks 1.1.x on control-plane files were verified by hand on the host (`temp/u7s`) and against `scripts/install.sh`.
- Run 1: stock `cis-1.12`, all targets: 12 PASS / 53 FAIL / 59 WARN (124 checks; nothing finds a u7s component). Run 2: u7s profile below, targets master+controlplane+node (90 checks): **26 PASS / 40 FAIL / 24 WARN**. Policies (section 5, 34 Manual checks) are all WARN by construction (no kubectl in the VM); each was verified through the API by hand instead.
- Raw output: `temp/e2e/m516k-cis/` in the mayor checkout (`out-cis-1.12.json`, `out-u7s-1.12.json`), if still present.

### u7s profile (config overrides only; reusable)

Copy `cfg/cis-1.12` to `cfg/u7s-cis-1.12`, register `"u7s-cis-1.12": "u7s-cis-1.12"` in `target_mapping` and its five targets in `cfg/config.yaml`, then use this `cfg/u7s-cis-1.12/config.yaml` (production paths from `scripts/install.sh`; rig kubelet paths also listed). Checks are unmodified. Not committed as a repo file: it is 45 lines of config that only makes kube-bench *find* u7s; the verdicts still need the manual mapping below.

```yaml
master:
  components: [apiserver, scheduler, controllermanager, kubelet]
  apiserver:
    bins: ["u7s-apiserver"]
    confs: [/etc/systemd/system/u7s-apiserver.service]
    defaultconf: /etc/systemd/system/u7s-apiserver.service
  scheduler:                      # embedded in u7s-apiserver (--embedded-scheduler true)
    bins: ["u7s-scheduler", "u7s-apiserver"]
    confs: [/etc/systemd/system/u7s-apiserver.service]
    defaultconf: /etc/systemd/system/u7s-apiserver.service
    kubeconfig: [/var/lib/u7s/kubeconfig-scheduler]
    defaultkubeconfig: /var/lib/u7s/kubeconfig-scheduler
  controllermanager:
    bins: ["kube-controller-manager", "kube-controller"]
    confs: [/etc/systemd/system/u7s-kcm.service]
    defaultconf: /etc/systemd/system/u7s-kcm.service
    kubeconfig: [/var/lib/u7s/kcm-kubeconfig]
    defaultkubeconfig: /var/lib/u7s/kcm-kubeconfig
  etcd: {optional: true}
node:
  kubelet:
    cafile: [/var/lib/u7s/ca.pem, /etc/kubelet-ca.crt]
    svc: [/etc/systemd/system/kubelet.service, /etc/systemd/system/kubelet.service.d/u7s.conf]
    kubeconfig: [/var/lib/u7s/kubeconfig, /etc/kubelet-kubeconfig]
    confs: [/var/lib/u7s/kubelet-config.yaml, /etc/kubelet-config.yaml,
            /etc/systemd/system/kubelet.service, /etc/systemd/system/kubelet.service.d/u7s.conf]
```

Gotcha: kube-bench's `ps -C <bin>` matches the process `comm`, and takes the first word of the cmdline as the executable, so a `#!/bin/sh` stub is not found.

## Result summary

| Disposition | FAIL | WARN (sections 1,3,4) | Policies (5.x, all WARN) |
|---|---|---|---|
| Real gap | 9 | 9 | 16 |
| Not applicable by design (no etcd, no static-pod manifests, no scheduler listener) | 11 | 1 | 0 |
| Profile mismatch (u7s satisfies it differently, verified) | 20 | 4 | 3 |
| Deferred / operator-policy manual | 0 | 10 | 15 |

98 non-PASS items (40+24+34); 34 are real gaps (many duplicate one root cause: 12 PSA checks, 6 audit checks), 64 are mismatch / N/A / deferred.

Real gaps by severity (check -> bead; "existing" = bead already open, linked not duplicated):

| Sev | Gap | Checks | Bead |
|---|---|---|---|
| HIGH | PodSecurity admission absent: privileged pod admitted into a namespace labelled `enforce=restricted` (live) | 5.2.1-5.2.12, 5.6.3 | existing mayor-uvou7 (P2; evidence appended) |
| MED | Secrets stored base64-only in SQLite; no EncryptionConfiguration equivalent (live canary found in `state.db-wal`) | 1.2.27, 1.2.28, 5.4.2 | new (see below) |
| MED | No audit log / audit policy | 1.2.16-1.2.19, 3.2.1, 3.2.2 | existing mayor-0qjgc (P3; the requested feature bead already exists) |
| MED | KCM `--use-service-account-credentials=false`: one KCM identity with `*`/`*` update/patch/delete | 1.3.3 | new |
| MED | Service `externalIPs` unrestricted (patch accepted) | 1.2.3 | new |
| MED | NodeRestriction-equivalent scoping incomplete | 1.2.14 | existing mayor-ufcno |
| MED | Credentials valid to year 4096, admin kubeconfig is `system:masters`, control-plane kubelet uses admin kubeconfig, kubelet serving cert 10y/no rotation | 3.1.1, 4.2.11, 5.1.7 | existing mayor-xdw6u.1, mayor-xdw6u.6, mayor-zboqh |
| LOW | Unset hardening knobs: KCM `--profiling` (default on), kubelet explicit authn/authz, `podPidsLimit` (-1), TLS floor | 1.3.2, 4.2.1, 4.2.2, 4.2.12, 4.2.13 | new |
| LOW | File modes: `state.db*` 0644 (holds all Secrets), `kubelet-config.yaml` 0644, unit files 0644 (only the 0700 state dir protects them) | 1.1.1-1.1.6, 1.1.11, 4.1.1, 4.1.9 | new |
| DEFER | seccompDefault=false, EventRateLimit, AlwaysPullImages, no general request timeout, KCM terminated-pod-gc default | 4.2.14, 1.2.9, 1.2.11, 1.2.20, 1.3.1 | new (one tracking bead) |

## Per-check verdicts (every non-PASS from the u7s-profile run)

Legend: RG real gap; NA not applicable by design; PM profile mismatch (u7s satisfies it differently); DF deferred.

### 1.1 Control plane files (FAIL 1.1.1-1.1.7, 1.1.11-1.1.19; WARN 1.1.9, 1.1.20, 1.1.21)

| Check | Verdict | Evidence |
|---|---|---|
| 1.1.1-1.1.6 apiserver/KCM/scheduler pod-spec file perms/owner | NA + LOW | No static-pod manifests: components are systemd units written by `scripts/install.sh:1282,1307,1360` as root, default umask (0644, non-secret). Tightening to 0600 is one `chmod` each (bundled in the LOW file-modes bead). |
| 1.1.7, 1.1.8 etcd spec | NA | No etcd; datastore is embedded SQLite (`--db`). |
| 1.1.11, 1.1.12 etcd data dir | NA + LOW | Equivalent is `state.db`/`-wal`/`-shm`: `-rw-r--r--` on the rig (`stat temp/u7s/state.db*`); `crates/store` sets no mode. Prod: `$STATE_DIR` is `install -d -m 0700` (`install.sh:1043`), so only defence in depth. |
| 1.1.13-1.1.18 admin/scheduler/KCM kubeconfig perms+owner | PM | Files live at `$STATE_DIR/{kubeconfig,kubeconfig-scheduler,kcm-kubeconfig}`, not `/etc/kubernetes/*.conf`; all `-rw-------` (apiserver writes them 0600, `tls.rs:16-32`). |
| 1.1.19-1.1.21 PKI dir/files | PM | `$STATE_DIR` 0700; keys written 0600 by `tls.rs:16`; `ca.key`/`sa.key`/`admin.key` `-rw-------` on the rig. Rig-script-made keys (`konnectivity-*.key`, `kubelet-serving-*.key`) are 0644: rig only, not install.sh. |
| 1.1.9 CNI file perms | DF (info) | Flannel/`kube-network-policies` files under `/etc/cni/net.d`; not reviewed beyond kube-bench's reading (750/600/644 mix). |

### 1.2 API server

| Check | Verdict | Evidence |
|---|---|---|
| 1.2.1 anonymous-auth | PM | Anonymous requests authenticate as `system:anonymous` and are RBAC-confined: `/api`,`/apis`,`/openapi/v2`,`/metrics`,`/debug/pprof/` -> 403; `/healthz /livez /readyz /version` -> 200 (upstream parity). |
| 1.2.2 token-auth-file | PASS | Flag exists (`args.rs:24`) but neither install.sh nor the rig passes it. |
| 1.2.3 DenyServiceExternalIPs | RG MED | `kubectl patch svc ... externalIPs:["1.2.3.4"]` accepted. |
| 1.2.4, 1.2.5 kubelet client cert/CA | PM | `handlers/proxy.rs:679 build_kubelet_tls_config` pins the cluster CA and presents a client identity; no flags. |
| 1.2.6-1.2.8 authorization-mode | PM | No flag; Node authorizer (`node_authz.rs`) + RBAC always on, never AlwaysAllow: scheduler cert -> kubelet `/pods` 403; anonymous -> 403. |
| 1.2.9 EventRateLimit, 1.2.11 AlwaysPullImages | DF | Not implemented; both Manual and opt-in upstream. |
| 1.2.10, 1.2.12, 1.2.13 admission | PASS/PM | No AlwaysAdmit; ServiceAccount + NamespaceLifecycle behaviours implemented in handlers (`handlers/generic.rs:1220`, `pods.rs:4777`). |
| 1.2.14 NodeRestriction | RG MED | Compensating checks in `node_authz.rs:395-405`; per-node scoping missing for csinodes/leases/nodes-create/resourceslices (mayor-ufcno). |
| 1.2.15 profiling | PM | `kubectl get --raw /debug/pprof/` -> NotFound (no pprof surface). |
| 1.2.16-1.2.19 audit-log-* | RG MED | No `--audit-*` args (`u7s-apiserver --help` lists 19 flags), no audit code (`rg -i audit.?log crates` -> none). |
| 1.2.20 request-timeout | DF | Only `header_read_timeout` 10s (`serve.rs:42`); no per-request deadline for non-watch handlers. |
| 1.2.21 service-account-lookup | PM | Live: token minted for SA `probe-sa` authenticates (`SelfSubjectReview` shows `system:serviceaccount:...`); after `delete sa`, same token -> 401. |
| 1.2.22, 1.2.24, 1.2.25 sa-key / tls / client-ca | PM | `--sa-key/--sa-pub`, `--ca-key/--ca-cert`; serving cert minted from the CA at start (`tls.rs`). |
| 1.2.23, 1.2.26 etcd certs/CA | NA | No etcd. |
| 1.2.27, 1.2.28 encryption provider | RG MED | Created Secret with value `PLAINTEXT-CANARY-12345`; its base64 appears verbatim in `temp/u7s/state.db-wal`. No EncryptionConfiguration code. |
| 1.2.29 strong ciphers | PM | rustls: TLS1.2 negotiates `ECDHE-ECDSA-CHACHA20-POLY1305`, TLS1.1 refused (`openssl s_client`). AEAD+PFS only by construction. |
| 1.2.30 extend-token-expiration | PM | `create token --duration=10m` -> `exp - iat = 600`; no extension. |

### 1.3 / 1.4 Controller manager, scheduler

| Check | Verdict | Evidence |
|---|---|---|
| 1.3.1 terminated-pod-gc-threshold | DF | Default 12500; Manual. |
| 1.3.2 KCM profiling | RG LOW | Unset (default true); mitigated by `--bind-address=127.0.0.1` and authz (`/debug/pprof/` -> 403 unauthenticated from the VM). `install.sh:1352`, `scripts/conformance/04-start-kcm.sh`. |
| 1.3.3 use-service-account-credentials | RG MED | `=false` in install.sh and the rig; `system:kube-controller-manager` ClusterRole carries `apiGroups:*, resources:*, verbs:get,list,watch,patch,update,delete,deletecollection`. No rationale found in the repo. |
| 1.3.4-1.3.7 | PASS | |
| 1.4.1 scheduler profiling, 1.4.2 bind | NA/PASS | Scheduler (standalone and embedded) opens no listening socket (`lsof -a -p <scheduler pid> -iTCP -sTCP:LISTEN` empty). |

### 3 Authn, audit

| Check | Verdict | Evidence |
|---|---|---|
| 3.1.1 client certs for users | RG MED | Admin identity is a `system:masters` cert valid 1975-01-01..4096-01-01 (`openssl x509`), no revocation: mayor-xdw6u.1 (finite lifetimes), mayor-zboqh. |
| 3.1.2, 3.1.3 SA / bootstrap tokens for users | DF | Manual policy. |
| 3.2.1, 3.2.2 audit policy | RG MED | As 1.2.16. |

### 4 Worker node

| Check | Verdict | Evidence |
|---|---|---|
| 4.1.1 kubelet service file 600 | RG LOW | 0644 (`/etc/systemd/system/.../u7s.conf`; install.sh writes `kubelet.service` 0644). |
| 4.1.3, 4.1.4 proxy kubeconfig | DF | kube-proxy kubeconfig not at a standard path; not reviewed. |
| 4.1.9 kubelet config.yaml 600 | RG LOW | 0644 (`install.sh:318` heredoc); inside the 0700 state dir. |
| 4.2.1, 4.2.2 anonymous/authorization | PM + LOW | Config sets neither, kube-bench FAILs it, but `/api/v1/nodes/<n>/proxy/configz` shows `anonymous.enabled=false`, `authorization.mode=Webhook`; anonymous `/pods` 401, scheduler-cert `/pods` 403. Relying on binary defaults; make explicit in install.sh. |
| 4.2.7 hostname-override | NA | install.sh sets it deliberately (node identity); k3s does too. |
| 4.2.11 RotateKubeletServerCertificate | RG MED | Worker: `serverTLSBootstrap`; control-plane kubelet serving cert minted once `-days 3650` (`install.sh:1388`): mayor-xdw6u.6. Rig gate explicitly false. |
| 4.2.12 ciphers | RG LOW | `tlsCipherSuites`/`tlsMinVersion` unset (Go defaults, TLS1.2 floor). |
| 4.2.13 podPidsLimit | RG LOW | `-1` in configz. |
| 4.2.14 seccompDefault | DF | `false`; enabling can break workloads, decide per cluster. |

### 5 Policies (all Manual; verified by hand)

| Check | Verdict | Evidence |
|---|---|---|
| 5.1.1, 5.1.7 cluster-admin / system:masters | PM | One CRB `system:masters -> cluster-admin`; admin cert is `system:masters`; control-plane kubelet uses the admin kubeconfig (mayor-zboqh). |
| 5.1.3 wildcards | RG (covered by 1.3.3) | Wildcard rules: `cluster-admin`, three controller roles, `system:kube-controller-manager`. |
| 5.1.2, 5.1.4-5.1.6, 5.1.8-5.1.13 RBAC hygiene | DF / prior audit | RBAC escalation findings G1-1,G1-6,G1-7 etc. live in `ai/findings/2026-10-16-n8hl8-G1-access-authn.md`; not re-verified here. |
| 5.2.1-5.2.12 pod security | RG HIGH | `kubectl label ns cis-psa pod-security.kubernetes.io/enforce=restricted` then `kubectl run priv --privileged` -> `pod/priv created`, `privileged=true`. No PodSecurity code (`rg -i pod.?security crates/apiserver` only SecurityContext conversion and label-edit tests). mayor-uvou7. |
| 5.3.1 CNI supports NetworkPolicy | PASS | flannel + kube-network-policies (`docs/decisions/network-policy-engine.md`). |
| 5.3.2 NetworkPolicy per namespace, 5.4.1, 5.6.1, 5.6.4 | DF | Operator responsibility. |
| 5.4.2 external secret storage | RG | Subsumed by the encryption-at-rest bead. |
| 5.5.1 ImagePolicyWebhook | DF | Not implemented; optional. |
| 5.6.2, 5.6.3 seccomp / SecurityContext | RG | Subsumed by PSA + 4.2.14. |

## Security e2e signal (release-1.37)

Source fetched into `temp/research/e2e-auth/` (pinned `release-1.37`).

E2E_PLACEHOLDER

## Harness recommendation

HARNESS_PLACEHOLDER
