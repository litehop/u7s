#!/usr/bin/env bash
# Reject non-bash invocation (e.g. `sh install.sh`, where Ubuntu's /bin/sh is
# dash) before anything else runs: dash doesn't support `set -o pipefail`
# below and dies with "Illegal option -o pipefail" mid-script, well before
# fetch_tarball's checksum verification -- a confusing crash instead of a
# clear error. This check is plain POSIX so dash can parse it far enough to
# print the message and exit.
if [ -z "${BASH_VERSION:-}" ]; then
  printf 'install.sh requires bash (not sh/dash). Re-run with: sudo bash install.sh %s\n' "$*" >&2
  exit 1
fi

# u7s host-level install bootstrap.
#
# Takes a fresh Ubuntu LTS box to a running control plane + kubelet: installs
# CRI-O + crun via apt, stages u7s-apiserver/u7s-scheduler plus the vendored
# kubelet and kube-controller-manager from a release tarball, and writes
# systemd units for u7s-apiserver, u7s-kcm, and kubelet. u7s-apiserver runs
# with --embedded-scheduler true, so u7s-scheduler gets no unit of its own --
# never run it standalone against the same cluster, since it keeps
# independent preemption dedup state with no coordination against the
# embedded scheduler. Also installs kubectl and applies vendored component
# manifests.
#
# Multi-node join goes through the real certificates.k8s.io CSR API: u7s's
# kube-controller-manager is unmodified upstream, so its builtin
# csrapproving/csrsigning controllers auto-approve and sign join CSRs against
# u7s's CA once the nodeclient/selfnodeclient RBAC grants exist. Two
# additional modes:
#   --mint-join-token   On an existing control-plane node: mint a bootstrap
#                       token plus a pre-signed kubelet serving cert, printed
#                       as one base64(JSON) join artifact.
#   --join <url>        On a fresh node with --token <artifact>: submit a
#                       client CSR, wait for it to be signed, and join as a
#                       kubelet with its own x509 identity. One-shot: refuses
#                       to run against a node already classified as an
#                       existing joined worker (bootstrap tokens are
#                       single-use, and re-running would silently rotate the
#                       node's client identity). Re-running install.sh with
#                       no flags against such a node upgrades kubelet alone,
#                       leaving kubeconfig/kubelet-client.* untouched.
#
# Usage:
#   sudo scripts/install.sh [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>] [--manifest-output-dir <path>]
#   sudo scripts/install.sh --mint-join-token --node-name <name> --node-ip <ip>
#   sudo scripts/install.sh --join <url> --token <artifact> [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>]
#
# Knobs on the zero-argument path are env-settable
# (docs/decisions/install-script-ux.md):
#   --node-name / U7S_NODE_NAME   Node identity (default: hostname).
#   --iface     / U7S_IFACE       Cluster-traffic interface (default: first
#                                 physical non-loopback interface).
#   --manifest-output-dir / U7S_MANIFEST_OUTPUT_DIR
#                                 Where vendored manifest YAMLs from the
#                                 tarball land (default: /etc/u7s/manifests,
#                                 the apiserver's well-known auto-applied
#                                 folder -- docs/decisions/
#                                 well-known-manifest-folder.md).
#
# The default and --join modes need a tarball, from --tarball <path>,
# --tarball-url <url>, or DEFAULT_TARBALL_URL below. It must contain the
# binaries the mode needs (u7s-apiserver, u7s-scheduler, kubelet,
# kube-controller-manager; kubelet alone for --join), findable anywhere in
# its extracted tree.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  install.sh [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>] [--manifest-output-dir <path>]
  install.sh --mint-join-token --node-name <name> --node-ip <ip>
  install.sh --join <url> --token <artifact> [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>]

  --tarball <path>      Path to an already-downloaded u7s release tarball.
                         Overrides the release URL baked into this copy.
  --tarball-url <url>   Fetch the release tarball from <url> instead of the
                         one baked into this copy at release time.
  --node-name <name>    Node identity (default: hostname). For --mint-join-token
                         this is the NAME OF THE JOINING NODE, not this host.
  --iface <iface>       Network interface used for cluster traffic
                         (default: first non-loopback interface).
  --manifest-output-dir <path>
                         Where vendored manifest YAMLs from the tarball land
                         (default: /etc/u7s/manifests, the apiserver's
                         well-known auto-applied folder). An alternate path
                         leaves the well-known folder empty, for GitOps to
                         manage instead.
  --mint-join-token     Run on an existing control-plane node: mint a join
                         artifact for a new node (requires --node-name, --node-ip).
  --node-ip <ip>        IP address of the joining node (--mint-join-token only).
  --join <url>          Join an existing cluster at <url> (e.g. https://1.2.3.4:6443)
                         using the artifact passed via --token.
  --token <artifact>    base64(JSON) join artifact produced by --mint-join-token
                         (--join only).
EOF
}

# Substituted at release time by .github/workflows/release-tarball.yaml, which
# asserts its own substitution took effect. Empty in the repo copy: a checkout
# has no release to point at, so it fails loud instead of fetching an
# unrelated one (docs/decisions/distribution-hosting-shape.md).
DEFAULT_TARBALL_URL=""

NODE_NAME="${U7S_NODE_NAME:-}"
IFACE="${U7S_IFACE:-}"
MANIFEST_OUTPUT_DIR="${U7S_MANIFEST_OUTPUT_DIR:-/etc/u7s/manifests}"
TARBALL=""
TARBALL_URL="$DEFAULT_TARBALL_URL"
# Only an operator-passed --tarball-url conflicts with --tarball; a released
# copy always has a non-empty default, so emptiness cannot distinguish them.
TARBALL_URL_EXPLICIT=0
# Set by fetch_tarball; removed by the same EXIT trap as STAGE_DIR.
DOWNLOAD_DIR=""
MINT_JOIN_TOKEN=0
NODE_IP=""
JOIN_SERVER=""
JOIN_TOKEN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --node-name) NODE_NAME="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --manifest-output-dir) MANIFEST_OUTPUT_DIR="$2"; shift 2 ;;
    --tarball) TARBALL="$2"; shift 2 ;;
    --tarball-url) TARBALL_URL="$2"; TARBALL_URL_EXPLICIT=1; shift 2 ;;
    --mint-join-token) MINT_JOIN_TOKEN=1; shift ;;
    --node-ip) NODE_IP="$2"; shift 2 ;;
    --join) JOIN_SERVER="$2"; shift 2 ;;
    --token) JOIN_TOKEN="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [ -n "$TARBALL" ] && [ "$TARBALL_URL_EXPLICIT" -eq 1 ]; then
  echo "error: --tarball and --tarball-url are mutually exclusive -- pass a local path or a URL to fetch, not both" >&2
  exit 1
fi

if [ "$MINT_JOIN_TOKEN" -eq 1 ] && [ -n "$JOIN_SERVER" ]; then
  echo "error: --mint-join-token and --join are mutually exclusive modes" >&2
  exit 1
fi

# --- Preflight: root, systemd ------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
  echo "error: this script must be run as root (e.g. via sudo)" >&2
  exit 1
fi

# /run/systemd/system exists only when systemd is PID 1 (the same test
# systemd-detect-virt uses). Fail rather than degrade to unsupervised bare
# processes (docs/decisions/systemd-install-contract.md).
if [ ! -d /run/systemd/system ]; then
  echo "error: systemd not detected (no /run/systemd/system) -- u7s requires systemd" >&2
  exit 1
fi

BIN_DIR=/opt/u7s/bin
STATE_DIR=/var/lib/u7s
# Flat sibling of state.db/ca.*/kubeconfig, not a subdirectory -- deleting it
# (the mismatch-refusal escape hatch below) touches no cluster data.
CONFIG_FILE="$STATE_DIR/config"
# Unit file for the standalone scheduler this script retires below in favor
# of --embedded-scheduler true -- a variable (not a literal inline at each
# use) so scripts/test-install-logic.sh can override it and exercise the
# retirement logic against a scratch path instead of the real
# /etc/systemd/system.
SCHEDULER_UNIT_FILE=/etc/systemd/system/u7s-scheduler.service

# --- Shared helpers (used by more than one mode) -----------------------------

# Poll the local apiserver's /healthz via its own admin kubeconfig. Polling
# rather than assuming: apiserver's first-run bootstrap (and the restart that
# picks up a new token-auth-file entry) races its own listener bind, so
# neither the kubeconfig nor a live listener exists when systemctl returns.
#
# /healthz itself only returns 200 once the boot-time bootstrap manifest apply
# (crates/apiserver/src/bootstrap_apply.rs, raced against the listener via
# tokio::select! in run()) has resolved successfully -- a bad manifest is
# fatal and tears the process down via that same tokio::select!, so /healthz
# never flips to 200 in that case and this loop times out instead of
# reporting success on a since-crashed apiserver. No settle-and-recheck is
# needed: the first 200 already means boot is fully done.
wait_for_apiserver() {
  local kubeconfig_path="$1"
  echo "Waiting for u7s-apiserver to become reachable..."
  local ready=0
  for _ in $(seq 1 60); do
    if [ -f "$kubeconfig_path" ] && kubectl --kubeconfig="$kubeconfig_path" get --raw=/healthz >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done
  if [ "$ready" -ne 1 ]; then
    echo "error: u7s-apiserver did not become reachable within 120s (check: systemctl status u7s-apiserver, journalctl -u u7s-apiserver)" >&2
    exit 1
  fi
}

# Only --mint-join-token/--join need jq; not installed unconditionally so the
# default path's apt footprint stays unchanged.
ensure_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y jq
  fi
}

# Download the release tarball and its .sha256 sidecar, verify the sidecar's
# hash against the downloaded bytes, and point $TARBALL at it. The caller
# sets the EXIT trap that removes $DOWNLOAD_DIR. A sidecar fetch failure
# (including a 404, e.g. a pre-checksum release) fails the same as any other
# curl error here: unverified bytes reaching `tar -xzf` become binaries run
# as root, so a URL-based fetch always requires a passing checksum.
fetch_tarball() {
  local url="$1"
  DOWNLOAD_DIR="$(mktemp -d)"
  TARBALL="$DOWNLOAD_DIR/$(basename "$url")"
  local checksum_url="$url.sha256"
  local checksum_file="$TARBALL.sha256"

  echo "Downloading release tarball from $url..."
  curl -fsSL --retry 3 --retry-connrefused -o "$TARBALL" "$url"

  echo "Downloading checksum sidecar from $checksum_url..."
  curl -fsSL --retry 3 --retry-connrefused -o "$checksum_file" "$checksum_url"

  local expected actual
  expected="$(cut -d' ' -f1 "$checksum_file")"
  actual="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
  if [ "$expected" != "$actual" ]; then
    echo "error: checksum mismatch for $url" >&2
    echo "       expected (from $checksum_url): $expected" >&2
    echo "       actual:                        $actual" >&2
    exit 1
  fi
}

# Install each named binary found anywhere in $STAGE_DIR into $BIN_DIR,
# rejecting a found-but-non-executable match rather than installing it (e.g. a
# stray file sharing a required binary's name).
stage_binaries() {
  for bin in "$@"; do
    found="$(find "$STAGE_DIR" -type f -name "$bin" | head -n1)"
    if [ -z "$found" ]; then
      echo "error: tarball is missing required binary: $bin" >&2
      exit 1
    fi
    if [ ! -x "$found" ]; then
      echo "error: $bin was found in the tarball at $found but is not executable (tarball packaging bug?)" >&2
      exit 1
    fi
    install -m 0755 "$found" "$BIN_DIR/$bin"
  done
}

# Minimal KubeletConfiguration: CRI-O's socket, cluster DNS matching
# apiserver's default --service-cluster-ip-range (10.96.0.0/12), and five
# settings that are not obvious:
#
# resolvConf: "" -- Ubuntu's systemd-resolved points /etc/resolv.conf at the
# 127.0.0.53 stub, unreachable from inside a pod netns; passing it through
# would give every pod an unusable resolver.
#
# tlsCertFile/tlsPrivateKeyFile -- a serving cert signed by the cluster CA,
# minted by kubelet.service's ExecStartPre or delivered in the join artifact.
# Without it kubelet self-signs and the apiserver's kubelet-client rejects it,
# breaking kubectl logs/exec.
#
# clientCAFile -- lets kubelet authenticate the apiserver's own client cert
# rather than treating proxied requests as anonymous, which its container-log
# and exec endpoints answer with a bare 401.
#
# rotateCertificates -- kubelet self-renews its client cert over the same CSR
# path; the selfnodeclient RBAC grant it needs is already seeded.
#
# certDir -- kubelet's hardcoded default (/var/lib/kubelet/pki) lives outside
# $STATE_DIR, so it survives the documented reset procedure's `rm -rf
# $STATE_DIR` untouched. A reset that regenerates the CA then leaves kubelet
# presenting a rotated client cert signed by the deleted CA, an infinite
# UnknownIssuer reconnect loop with no node ever registering. Pointing
# certDir under $STATE_DIR makes that single rm -rf actually complete.
write_kubelet_config_yaml() {
  cat > "$STATE_DIR/kubelet-config.yaml" <<EOF
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
containerRuntimeEndpoint: unix:///var/run/crio/crio.sock
registerNode: true
failSwapOn: false
resolvConf: ""
staticPodPath: /etc/u7s/static-pods
clusterDNS:
  - 10.96.0.10
clusterDomain: cluster.local
tlsCertFile: $STATE_DIR/kubelet-serving.crt
tlsPrivateKeyFile: $STATE_DIR/kubelet-serving.key
authentication:
  x509:
    clientCAFile: $STATE_DIR/ca.pem
rotateCertificates: true
certDir: $STATE_DIR/kubelet/pki
EOF
}

# --mint-join-token: run on a control-plane node that already has ca.key/ca.pem
# from its own bootstrap. Mints a bootstrap token authorized (by the
# apiserver's seeded system:node-bootstrapper/nodeclient grants for group
# system:bootstrappers) to submit exactly one join CSR, restarts
# u7s-apiserver.service to load it -- the token map is read once at startup,
# with no hot-reload path -- and signs a kubelet serving cert for the joining
# node. CA cert, token and serving cert+key go into one base64(JSON) artifact.
mint_join_token() {
  if [ -z "$NODE_NAME" ] || [ -z "$NODE_IP" ]; then
    echo "error: --mint-join-token requires --node-name <joining-node-name> and --node-ip <joining-node-ip>" >&2
    exit 1
  fi
  if [ ! -f "$STATE_DIR/ca.pem" ] || [ ! -f "$STATE_DIR/ca.key" ]; then
    echo "error: $STATE_DIR/ca.pem or ca.key not found -- run install.sh's default single-node bootstrap on this control-plane node first" >&2
    exit 1
  fi
  ensure_jq

  local secret bootstrap_id bootstrap_uid token_file
  secret="$(openssl rand -hex 32)"
  bootstrap_id="$(openssl rand -hex 3)"
  bootstrap_uid="$(cat /proc/sys/kernel/random/uuid)"
  token_file="$STATE_DIR/token-auth-file"
  touch "$token_file"
  echo "${secret},system:bootstrap:${bootstrap_id},${bootstrap_uid},system:bootstrappers" >> "$token_file"
  chmod 600 "$token_file"

  echo "Restarting u7s-apiserver.service to load the new bootstrap token..."
  systemctl restart u7s-apiserver.service
  wait_for_apiserver "$STATE_DIR/kubeconfig"

  local mint_dir
  mint_dir="$(mktemp -d)"
  # Double-quoted so $mint_dir is baked in now: it is `local` and out of scope
  # by the time this EXIT trap fires at real process exit, where a
  # single-quoted trap would re-evaluate it against an unset var under `set -u`.
  # shellcheck disable=SC2064 # intentional: see above
  trap "rm -rf '$mint_dir'" EXIT

  openssl ecparam -name prime256v1 -genkey -noout -out "$mint_dir/kubelet-serving.key"
  chmod 600 "$mint_dir/kubelet-serving.key"
  openssl req -new -key "$mint_dir/kubelet-serving.key" -subj "/CN=$NODE_NAME" -out "$mint_dir/kubelet-serving.csr"
  openssl x509 -req -in "$mint_dir/kubelet-serving.csr" -CA "$STATE_DIR/ca.pem" -CAkey "$STATE_DIR/ca.key" \
    -CAcreateserial -days 3650 \
    -extfile <(printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$NODE_IP") \
    -out "$mint_dir/kubelet-serving.crt"

  local artifact
  artifact="$(jq -n -c \
    --arg caCert "$(cat "$STATE_DIR/ca.pem")" \
    --arg bootstrapToken "$secret" \
    --arg servingCert "$(cat "$mint_dir/kubelet-serving.crt")" \
    --arg servingKey "$(cat "$mint_dir/kubelet-serving.key")" \
    '{caCert: $caCert, bootstrapToken: $bootstrapToken, servingCert: $servingCert, servingKey: $servingKey}' \
    | base64 -w0)"

  echo ""
  echo "Join artifact minted for node '$NODE_NAME' ($NODE_IP)."
  echo "On the joining node, run (as root):"
  echo "  install.sh --join <this-control-plane-URL, e.g. https://<this-host-ip>:6443> \\"
  echo "    --token '$artifact' --tarball <path> --node-name $NODE_NAME [--iface <iface>]"
}

# --join: run on a fresh node. Decodes the artifact locally (so CA trust needs
# no network), then builds a PKCS#10 CSR shaped exactly as upstream
# csrapproving's isNodeClientCert recognizer requires (CN=system:node:<name>,
# O=system:nodes, signerName kubernetes.io/kube-apiserver-client-kubelet,
# usages digital signature/key encipherment/client auth) and submits it under
# the bootstrap token. KCM auto-approves and signs it -- no manual step -- and
# the result becomes kubelet's own x509 identity, not a shared admin one.
join_cluster() {
  if [ -z "$JOIN_TOKEN" ]; then
    echo "error: --join requires --token <join-artifact>" >&2
    exit 1
  fi
  ensure_jq

  local artifact_json ca_cert bootstrap_token serving_cert serving_key
  artifact_json="$(printf '%s' "$JOIN_TOKEN" | base64 -d)"
  ca_cert="$(printf '%s' "$artifact_json" | jq -r '.caCert')"
  bootstrap_token="$(printf '%s' "$artifact_json" | jq -r '.bootstrapToken')"
  serving_cert="$(printf '%s' "$artifact_json" | jq -r '.servingCert')"
  serving_key="$(printf '%s' "$artifact_json" | jq -r '.servingKey')"

  printf '%s\n' "$ca_cert" > "$STATE_DIR/ca.pem"
  printf '%s\n' "$serving_cert" > "$STATE_DIR/kubelet-serving.crt"
  printf '%s\n' "$serving_key" > "$STATE_DIR/kubelet-serving.key"
  chmod 600 "$STATE_DIR/kubelet-serving.key"

  openssl ecparam -name prime256v1 -genkey -noout -out "$STATE_DIR/kubelet-client.key"
  chmod 600 "$STATE_DIR/kubelet-client.key"
  openssl req -new -key "$STATE_DIR/kubelet-client.key" \
    -subj "/O=system:nodes/CN=system:node:$NODE_NAME" \
    -out "$STATE_DIR/kubelet-client.csr"

  local csr_b64 csr_name csr_body
  csr_b64="$(base64 -w0 "$STATE_DIR/kubelet-client.csr")"
  csr_name="join-${NODE_NAME}-$(date +%s)"
  csr_body="$(jq -n -c \
    --arg name "$csr_name" \
    --arg request "$csr_b64" \
    '{apiVersion: "certificates.k8s.io/v1", kind: "CertificateSigningRequest",
      metadata: {name: $name},
      spec: {request: $request,
             signerName: "kubernetes.io/kube-apiserver-client-kubelet",
             usages: ["digital signature", "key encipherment", "client auth"]}}')"

  echo "Submitting join CSR '$csr_name' to $JOIN_SERVER..."
  curl -fsSL --cacert "$STATE_DIR/ca.pem" \
    -H "Authorization: Bearer $bootstrap_token" \
    -H "Content-Type: application/json" \
    -X POST "$JOIN_SERVER/apis/certificates.k8s.io/v1/certificatesigningrequests" \
    -d "$csr_body" >/dev/null

  # KCM's csrapproving/csrsigning controllers react to the create event; this
  # loop only waits on them, it approves nothing itself.
  echo "Waiting for kube-controller-manager to auto-approve and sign the CSR..."
  local signed_cert_b64="" resp
  for _ in $(seq 1 60); do
    resp="$(curl -fsSL --cacert "$STATE_DIR/ca.pem" \
      -H "Authorization: Bearer $bootstrap_token" \
      "$JOIN_SERVER/apis/certificates.k8s.io/v1/certificatesigningrequests/$csr_name" 2>/dev/null || true)"
    signed_cert_b64="$(printf '%s' "$resp" | jq -r '.status.certificate // empty' 2>/dev/null || true)"
    if [ -n "$signed_cert_b64" ]; then
      break
    fi
    sleep 2
  done
  if [ -z "$signed_cert_b64" ]; then
    echo "error: CSR '$csr_name' was not approved+signed within 120s (check: kubectl get csr $csr_name, kube-controller-manager logs on the control-plane node)" >&2
    exit 1
  fi
  printf '%s' "$signed_cert_b64" | base64 -d > "$STATE_DIR/kubelet-client.crt"

  local ca_b64 cert_b64 key_b64
  ca_b64="$(base64 -w0 "$STATE_DIR/ca.pem")"
  cert_b64="$(base64 -w0 "$STATE_DIR/kubelet-client.crt")"
  key_b64="$(base64 -w0 "$STATE_DIR/kubelet-client.key")"
  cat > "$STATE_DIR/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: $JOIN_SERVER
    certificate-authority-data: $ca_b64
  name: u7s
contexts:
- context:
    cluster: u7s
    user: system:node:$NODE_NAME
  name: u7s
current-context: u7s
users:
- name: system:node:$NODE_NAME
  user:
    client-certificate-data: $cert_b64
    client-key-data: $key_b64
EOF
  chmod 600 "$STATE_DIR/kubeconfig"
  echo "Join CSR approved and signed -- kubelet's dedicated x509 kubeconfig written to $STATE_DIR/kubeconfig"
}

if [ "$MINT_JOIN_TOKEN" -eq 1 ]; then
  mint_join_token
  exit 0
fi

JOIN_MODE=0
if [ -n "$JOIN_SERVER" ]; then
  JOIN_MODE=1
fi

# --- Existing-install detection -----------------------------------------------
#
# Control-plane node: $STATE_DIR/ca.key exists only once apiserver's own
# load_or_generate_ca has actually run and succeeded (tls.rs) -- not the
# u7s-apiserver.service unit file written below, which install.sh writes
# unconditionally even on a first attempt that never got that far. Worker
# node: ca.key never exists there at all (join_cluster writes only the CA
# cert, never its key), so an existing $STATE_DIR/kubeconfig with no ca.key
# means an already-joined node re-running install.sh.
#
# Nothing downstream wipes $STATE_DIR on either path -- CA persistence is
# apiserver's own job, and the config/unit writes below are already
# idempotent (the restart fix) -- so this only decides what to tell
# the operator, so a re-run reads as an upgrade rather than a silent no-op or
# a fresh install starting from nothing.
EXISTING_INSTALL=0
if [ -f "$STATE_DIR/ca.key" ] || [ -f "$STATE_DIR/kubeconfig" ]; then
  EXISTING_INSTALL=1
  echo "existing u7s install detected -- upgrading in place, preserving cluster state and CA. To wipe and start over instead: stop the u7s services, rm -rf $STATE_DIR, and re-run install.sh." >&2
fi

# EXISTING_WORKER narrows EXISTING_INSTALL to specifically the worker half of
# that detection (kubeconfig present, no local CA key): this node already
# completed join_cluster() at least once.
EXISTING_WORKER=0
if [ "$EXISTING_INSTALL" -eq 1 ] && [ ! -f "$STATE_DIR/ca.key" ]; then
  EXISTING_WORKER=1
fi

# join_cluster() is one-shot: it submits a fresh CSR against a single-use
# bootstrap token and unconditionally overwrites kubeconfig/kubelet-client.*.
# Re-running it here (an operator re-passing --join/--token out of habit
# while upgrading) would silently rotate this node's client identity and
# likely fail outright anyway, since the token was already consumed --
# refuse loudly instead of attempting it.
if [ "$JOIN_MODE" -eq 1 ] && [ "$EXISTING_WORKER" -eq 1 ]; then
  echo "error: this node already joined a cluster ($STATE_DIR/kubeconfig exists with no local CA key) -- refusing to re-run the join CSR flow, which would submit a fresh CSR and overwrite this node's existing kubelet-client.crt/.key and kubeconfig. Bootstrap tokens are single-use, so this would likely fail outright anyway. To upgrade this worker, re-run install.sh with no --join/--token flags. To force a genuine re-join, stop kubelet, rm -rf $STATE_DIR, and re-run install.sh --join <url> --token <artifact>." >&2
  exit 1
fi

# WORKER_MODE covers both a fresh --join and an upgrade re-run against an
# already-joined worker: both stage kubelet alone and, further down, touch
# only kubelet.service -- never the control-plane services or manifests
# (docs/decisions/well-known-manifest-folder.md), and never
# kubeconfig/kubelet-client.* on the already-joined-worker path (join_cluster
# runs only when JOIN_MODE=1, guarded above to exclude EXISTING_WORKER=1).
WORKER_MODE=0
if [ "$JOIN_MODE" -eq 1 ] || [ "$EXISTING_WORKER" -eq 1 ]; then
  WORKER_MODE=1
fi

if [ -z "$TARBALL" ] && [ -z "$TARBALL_URL" ]; then
  # Only a checkout copy reaches this: a released one always has a baked URL,
  # so name that case rather than repeating usage's "one of these is required".
  echo "error: this copy of install.sh has no release URL baked into it (DEFAULT_TARBALL_URL is empty)," >&2
  echo "       which means it came from a git checkout rather than a published release." >&2
  echo "       Pass --tarball <path> (e.g. the output of scripts/build-release-tarball.sh)" >&2
  echo "       or --tarball-url <url>." >&2
  exit 1
fi
if [ -n "$TARBALL" ] && [ ! -f "$TARBALL" ]; then
  echo "error: tarball not found: $TARBALL" >&2
  exit 1
fi

# Download before apt installs and starts CRI-O, so a wrong or unreachable URL
# leaves the host untouched rather than half-configured -- a likely failure
# while the stable /install.sh URL still 404s. --tarball wins over both
# --tarball-url and the baked default, so an operator already holding the bytes
# never triggers a download.
if [ -z "$TARBALL" ]; then
  trap 'rm -rf ${DOWNLOAD_DIR:+"$DOWNLOAD_DIR"}' EXIT
  fetch_tarball "$TARBALL_URL"
fi

# --- Persisted install config ($STATE_DIR/config) ----------------------------
#
# IFACE/NODE_NAME feed into --advertise-address (below), which the apiserver
# embeds into every kubeconfig it rewrites (tls.rs). A --iface that resolves
# to a different IP on a re-run would silently change that address, breaking
# any kubeconfig already distributed off-box (e.g. scp'd to an operator's
# laptop) -- a connection failure that reads as a network problem, not an
# upgrade-changed-the-endpoint one. Persisted as plain KEY=value (not JSON) so
# it can be read back without pulling in jq, which is only installed
# conditionally today (for --mint-join-token/--join).
PERSISTED_NODE_NAME=""
PERSISTED_IFACE=""
if [ -f "$CONFIG_FILE" ]; then
  # Sourced inside a subshell, not the main shell, so this cannot clobber the
  # NODE_NAME/IFACE already resolved from flags/env above.
  # shellcheck disable=SC1090 # dynamic path: this project's own prior-run file
  PERSISTED_NODE_NAME="$(. "$CONFIG_FILE"; printf '%s' "${NODE_NAME:-}")"
  # shellcheck disable=SC1090
  PERSISTED_IFACE="$(. "$CONFIG_FILE"; printf '%s' "${IFACE:-}")"
fi

# On an upgrade, an unset --iface/--node-name defaults to what was persisted
# at install time. An explicit value that disagrees refuses loudly instead of
# silently rebaking a different node identity / advertise-address into a live
# cluster -- deleting $CONFIG_FILE and re-running install.sh is the only
# escape hatch, by design (no separate override flag).
if [ "$EXISTING_INSTALL" -eq 1 ] && [ -n "$PERSISTED_NODE_NAME" ]; then
  if [ -z "$NODE_NAME" ]; then
    NODE_NAME="$PERSISTED_NODE_NAME"
  elif [ "$NODE_NAME" != "$PERSISTED_NODE_NAME" ]; then
    echo "error: --node-name $NODE_NAME conflicts with the node name persisted at install time ($PERSISTED_NODE_NAME, recorded in $CONFIG_FILE). Changing it would rebake a different node identity into kubelet's --hostname-override on a live cluster. To proceed anyway: delete $CONFIG_FILE (a flat sibling file next to state.db/CA/kubeconfig -- this touches no cluster data) and re-run install.sh." >&2
    exit 1
  fi
fi

if [ "$EXISTING_INSTALL" -eq 1 ] && [ -n "$PERSISTED_IFACE" ]; then
  if [ -z "$IFACE" ]; then
    IFACE="$PERSISTED_IFACE"
  elif [ "$IFACE" != "$PERSISTED_IFACE" ]; then
    echo "error: --iface $IFACE conflicts with the interface persisted at install time ($PERSISTED_IFACE, recorded in $CONFIG_FILE). Changing it would rebake a different --advertise-address into every kubeconfig the apiserver rewrites, silently breaking any copy already distributed off this box. To proceed anyway: delete $CONFIG_FILE (a flat sibling file next to state.db/CA/kubeconfig -- this touches no cluster data) and re-run install.sh." >&2
    exit 1
  fi
fi

# --- Defaults: node name, network interface ----------------------------------

if [ -z "$NODE_NAME" ]; then
  NODE_NAME="$(hostname)"
fi

if [ -z "$IFACE" ]; then
  # Whitelist physical-NIC name patterns rather than blacklisting virtual
  # ones: a blacklist only ever covers the names its author thought of, while
  # systemd.net-naming-scheme(7) fixes the physical vocabulary at
  # en/wl/ww<suffix> (Ethernet/WLAN/WWAN). eth[0-9] covers the legacy kernel
  # names, which are not merely a theoretical fallback -- our own 5-VM Ubuntu
  # 26.04 Lima fleet, one template, splits 2/5 enp0s1 vs 3/5 eth0.
  IFACE="$(ip -o link show | awk -F': ' '{print $2}' \
    | grep -E '^(en|wl|ww)[a-zA-Z0-9]+$|^eth[0-9]+$' \
    | head -n1)"
  if [ -z "$IFACE" ]; then
    echo "error: no recognized physical network interface found -- pass --iface explicitly" >&2
    exit 1
  fi
fi

IFACE_IP="$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
if [ -z "$IFACE_IP" ]; then
  echo "error: interface $IFACE has no IPv4 address assigned" >&2
  exit 1
fi

if [ "$EXISTING_INSTALL" -eq 1 ]; then
  echo "Upgrading u7s: node-name=$NODE_NAME iface=$IFACE ($IFACE_IP)"
else
  echo "Installing u7s: node-name=$NODE_NAME iface=$IFACE ($IFACE_IP)"
fi

# --- CRI-O + crun via apt -----------------------------------------------------
#
# Mirrors lima/kubelet.yaml's provisioning, minus two test-harness-only bits:
# its 20-test-handler.conf runtime alias (needed by CRI-O's own CI, not by a
# real deployment) and its containerd-disabling step (a fresh Ubuntu box ships
# no containerd package at all; the unit Lima VMs have is injected by Lima's
# guest agent, so a real install has nothing to conflict with).
apt-get update -qq
apt-get install -y apt-transport-https ca-certificates curl gpg

install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://slc-mirror.opensuse.org/repositories/isv:/cri-o:/stable:/v1.36/deb/Release.key \
  | gpg --batch --yes --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://slc-mirror.opensuse.org/repositories/isv:/cri-o:/stable:/v1.36/deb/ /' \
  > /etc/apt/sources.list.d/cri-o.list
apt-get update -qq
apt-get install -y cri-o crun conmon
# Do NOT add a 10-crun.conf drop-in pointing at /usr/bin/crun: CRI-O ships its
# own crun at /usr/libexec/crio/crun matching the OCI spec version it generates
# (1.2.x), while the system crun accepts only 1.0/1.1 and fails every sandbox
# create with "unknown version specified". The package's own 10-crio.conf
# already sets the correct path.
mkdir -p /etc/crio/crio.conf.d

# br_netfilter isn't loaded by default on a fresh Ubuntu cloud image, and
# Flannel's vxlan backend hard-fails at startup without it (fatal "Failed to
# check br_netfilter: stat /proc/sys/net/bridge/bridge-nf-call-iptables: no
# such file or directory" -- confirmed live). Standard Kubernetes node prep
# (the same "letting iptables see bridged traffic" step kubeadm's own docs
# call out); persisted via modules-load.d/sysctl.d so it survives a reboot,
# not just this run.
modprobe br_netfilter
echo br_netfilter > /etc/modules-load.d/u7s-br-netfilter.conf
cat > /etc/sysctl.d/u7s-br-netfilter.conf <<'SYSCTL_EOF'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
SYSCTL_EOF
sysctl --system >/dev/null

# The cri-o package ships a default 10-crio-bridge.conf(list) that gives every
# node its own independent, uncoordinated subnet with no cross-node routing at
# all. Flannel supplies the real CNI config further down (10-flannel.conflist,
# once the apiserver is up and node-ipam-controller can hand out podCIDRs) and
# must be the only conflist present, since CRI-O picks whichever file sorts
# first alphabetically in this directory -- leaving crio-bridge's active would
# silently keep winning that sort ("10-crio-bridge" < "10-flannel"). Disabling
# both possible bridge config forms up front means kubelet reports
# NetworkPluginNotReady until Flannel's DaemonSet lands, which is expected and
# self-heals, rather than silently keeping the broken bridge default.
CNI_DIR=/etc/cni/net.d
for f in 10-crio-bridge.conf 10-crio-bridge.conflist; do
  if [ -f "$CNI_DIR/$f" ]; then
    mv "$CNI_DIR/$f" "$CNI_DIR/$f.disabled" || true
  fi
done

# crio.service is owned and enabled by the apt package
# (docs/decisions/systemd-install-contract.md); this only starts it.
# restart rather than start: on a re-run against an already-active unit,
# start is a no-op, so a re-run would never pick up a package upgrade.
systemctl enable crio
systemctl restart crio

# --- Stage binaries from the tarball ------------------------------------------
#
# u7s and KCM/kubelet ship in one tarball
# (docs/decisions/upstream-component-shipping-shape.md). Binaries are located
# by name anywhere in the extracted tree rather than at a fixed path, so the
# tarball's internal layout is not load-bearing. --join needs only kubelet.
STAGE_DIR="$(mktemp -d)"
# Replaces the download-only trap above, so it must still cover $DOWNLOAD_DIR.
# ${DOWNLOAD_DIR:+...} expands to nothing when --tarball gave a local path.
trap 'rm -rf "$STAGE_DIR" ${DOWNLOAD_DIR:+"$DOWNLOAD_DIR"}' EXIT

tar -xzf "$TARBALL" -C "$STAGE_DIR"

install -d -m 0755 "$BIN_DIR"
if [ "$WORKER_MODE" -eq 1 ]; then
  stage_binaries kubelet
else
  stage_binaries u7s-apiserver u7s-scheduler kubelet kube-controller-manager
fi

# --- kubectl + CNI plugin binaries (apt, pinned to kubelet's own version) ----
#
# kubectl is not in the release tarball, but a zero-argument install has to
# end at a working `kubectl get nodes`. Pinned to kubelet's own minor version
# for client/server skew safety.
#
# kubernetes-cni supplies the /opt/cni/bin/ plugins (bridge, host-local, ...)
# that CRI-O's 10-crio-bridge.conflist references. CRI-O only Recommends a
# CNI-plugins package and cloud-image apt disables recommends, so without this
# every node sits NotReady forever with "failed to find plugin \"bridge\"".
KUBE_VERSION="$("$BIN_DIR/kubelet" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
if [ -z "$KUBE_VERSION" ]; then
  echo "error: could not determine kubelet version from '$BIN_DIR/kubelet --version'" >&2
  exit 1
fi
KUBE_MINOR="${KUBE_VERSION%.*}"

curl -fsSL "https://pkgs.k8s.io/core:/stable:/v${KUBE_MINOR}/deb/Release.key" \
  | gpg --batch --yes --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v${KUBE_MINOR}/deb/ /" \
  > /etc/apt/sources.list.d/kubernetes.list
apt-get update -qq
apt-get install -y kubectl kubernetes-cni

# apiserver's relative default paths (./state.db, ./kubeconfig, ./ca.key,
# ./ca.crt, ./sa.key, ./sa.pub) resolve here via WorkingDirectory=. 0700
# because it holds the CA and service-account signing keys.
install -d -m 0700 "$STATE_DIR"
install -d -m 0755 /etc/u7s/static-pods

# Persist the resolved node-name/iface for the next run (read back and
# enforced above), so a bare re-run reuses them and an explicit, disagreeing
# flag is caught rather than silently changing this node's advertised
# identity.
cat > "$CONFIG_FILE" <<EOF
NODE_NAME="$NODE_NAME"
IFACE="$IFACE"
EOF

write_kubelet_config_yaml

# Round-2 kubelet tuning, shared by both kubelet.service blocks
# below. --max-pods and ConfigMapAndSecretChangeDetectionStrategy are
# deliberately NOT touched here -- operator scope narrowing keeps
# behavior-changing knobs off the table until other levers are exhausted.
#
# Feature gates: kubelet-consulted Beta gates, default-on in v1.36.4's
# pkg/features/kube_features.go, that no u7s workload or manifest exercises
# (verified per-gate against crates/ + manifests/ for a consumer of the
# capability's wire field). PodReadyToStartContainersCondition was left
# enabled -- whether anything depends on kubelet emitting it is uncertain
# (the closest regression test, crates/apiserver/src/handlers/pods.rs's
# $setElementOrder/conditions reordering, is condition-name-agnostic, so it
# doesn't prove this specific condition is required), and the conservative
# default is to keep an uncertain dependency on rather than prove it's safe
# to cut. Disabling the other 15 drops the corresponding kubelet code paths
# (checkpoint HTTP handler, credential-provider SA-token plumbing, CA/serving
# -cert file watchers, pod/container-level resize bookkeeping, etc.) for zero
# functional loss.
#
# cAdvisor trim: --application-metrics-count-limit=0 drops the
# 100-slot-per-container legacy "application metrics" ring buffer (a
# cadvisor flag mistakenly registered on kubelet, per its own --help
# output) -- u7s has no container exposing that legacy annotation-based
# metrics source, so the buffer is never populated. --housekeeping-interval
# was tried and reverted: pkg/kubelet/kubelet.go's evictionMonitoringPeriod
# is a hardcoded 10s constant with an explicit upstream comment to "keep
# this in sync with internal cadvisor housekeeping" -- raising
# --housekeeping-interval desyncs the two, so the eviction manager can act
# on cAdvisor stats up to (new_interval - 10s) stale under real memory
# pressure. That is a genuine behavior change under load, not the
# zero-impact trim it looked like, and falls under the same
# behavior-changing-knob restriction as --max-pods.
KUBELET_ROUND2_FLAGS="--application-metrics-count-limit=0 --feature-gates=ContainerCheckpoint=false,ContainerRestartRules=false,InPlacePodLevelResourcesVerticalScaling=false,InPlacePodVerticalScalingInitContainers=false,KubeletCrashLoopBackOffMax=false,KubeletEnsureSecretPulledImages=false,KubeletSeparateDiskGC=false,KubeletServiceAccountTokenForCredentialProviders=false,PodLevelResources=false,ReloadKubeletClientCAFile=false,ReloadKubeletServerCertificateFile=false,ResourceHealthStatus=false,ResourceHealthStatusMessage=false,RestartAllContainersOnContainerExits=false,RotateKubeletServerCertificate=false"

if [ "$WORKER_MODE" -eq 1 ]; then
  # --- Join an existing cluster via the CSR API, or upgrade an
  # already-joined worker in place (kubelet binary + kubelet.service only,
  # kubeconfig/kubelet-client.* untouched) -------------------------------
  if [ "$JOIN_MODE" -eq 1 ]; then
    join_cluster
  else
    echo "Existing worker node detected -- upgrading kubelet only; kubeconfig and kubelet-client.crt/.key are left untouched."
  fi

  cat > /etc/systemd/system/kubelet.service <<EOF
[Unit]
Description=Kubernetes kubelet
After=network-online.target crio.service
Wants=network-online.target
Requires=crio.service

[Service]
Type=simple
WorkingDirectory=$STATE_DIR
# Go-runtime memory tuning ported from the conformance dev-loop
# (scripts/conformance/lima-start.sh), proven there: default GOGC=100 +
# unbounded heap let kubelet's RSS sawtooth up to 235MB; this tuple measured
# 167.5MB->104.6MB (and stayed flat, no delayed step-up) on a 31-pod
# create/delete cycle, with pod-actuation timing unchanged. GOMEMLIMIT is a
# soft cap (GC works harder as it's approached, never OOM-kills).
Environment=GOMEMLIMIT=200MiB
Environment=GOGC=50
Environment=GOMAXPROCS=2
ExecStart=$BIN_DIR/kubelet --config=$STATE_DIR/kubelet-config.yaml --kubeconfig=$STATE_DIR/kubeconfig --hostname-override=$NODE_NAME --node-ip=$IFACE_IP $KUBELET_ROUND2_FLAGS
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable kubelet.service
  systemctl restart kubelet.service

  echo ""
  if [ "$JOIN_MODE" -eq 1 ]; then
    echo "u7s join complete. Verify from the control-plane node:"
  else
    echo "u7s worker upgrade complete. Verify from the control-plane node:"
  fi
  echo "  kubectl get nodes"
  exit 0
fi

# --- Retire the standalone u7s-scheduler.service, if present -----------------
#
# u7s-apiserver now runs its own embedded scheduler (--embedded-scheduler true,
# below) instead of a separately launched u7s-scheduler binary+unit. The two
# must never run at once against the same cluster: each keeps its own
# independent per-process preemption dedup state (NodeTally/in_flight in
# crates/scheduler/src/lib.rs), with no shared coordination, so two
# uncoordinated schedulers can each decide to preempt the same node's pods --
# actual double-preemption, not just wasted scheduling work.
#
# A host installed before this change has u7s-scheduler.service enabled and
# running; stop and remove it here, before the apiserver restart below brings
# up the embedded scheduler, so an in-place upgrade never runs both at once.
# A no-op on a genuinely fresh install, where the unit file never existed.
# stop/disable are NOT swallowed with `|| true`: the unit file's existence
# means a prior install.sh run loaded it via daemon-reload, so both should
# always succeed on a healthy host, and silently pressing on past a failed
# stop here is exactly how the standalone scheduler could keep running
# alongside the embedded one this script is about to start.
if [ -f "$SCHEDULER_UNIT_FILE" ]; then
  echo "Retiring standalone u7s-scheduler.service -- scheduling now runs embedded in u7s-apiserver (--embedded-scheduler true)."
  systemctl stop u7s-scheduler.service
  systemctl disable u7s-scheduler.service
  rm -f "$SCHEDULER_UNIT_FILE"
  systemctl daemon-reload
fi

# --- systemd units -------------------------------------------------------------
#
# One unit per host binary, Restart=always, boot-enabled
# (docs/decisions/systemd-install-contract.md); crio.service is the apt
# package's, not authored here.
#
# u7s-apiserver writes ca.key/ca.crt/sa.key/sa.pub/kubeconfig on its first run,
# and Type=simple guarantees only that the process started, not that those
# writes finished -- so each dependent unit's first ExecStart can legitimately
# fail. Restart=always absorbs that race, so no wait-loop is needed.

# Pod CIDR for node-ipam-controller (below) and Flannel's net-conf.json
# (applied further down) -- one variable so the two can never drift apart.
# 10.244.0.0/16 is Flannel's own net-conf.json default, and disjoint from the
# apiserver's fixed 10.96.0.0/12 --service-cluster-ip-range default (install.sh
# passes no override, so that default always holds).
POD_CLUSTER_CIDR="10.244.0.0/16"
POD_NODE_CIDR_MASK_SIZE=24

# --- Vendored manifests from the tarball -------------------------------------
#
# manifests/*.yaml ships in the release tarball alongside the binaries above
# (docs/decisions/well-known-manifest-folder.md). --manifest-output-dir picks
# the destination: the well-known folder (default) for apiserver's own
# boot-time auto-apply scan, or an operator-chosen alternate path for GitOps
# to manage instead -- nothing is ever written into the well-known folder in
# that case, so apiserver's scan finds it empty. Only relevant to a
# control-plane node: a worker (fresh --join or an already-joined worker's
# upgrade re-run) installs kubelet alone, with no apiserver to apply
# anything. A checkout's tarball may not carry a manifests/ dir at all yet
# (the release-pipeline vendoring step lands separately); that is equivalent
# to an empty set, not an error. Placed here (after $POD_CLUSTER_CIDR is
# resolved, before the systemd units below start anything) because
# flannel.yaml and kube-proxy.yaml each carry install-time placeholders a
# byte-for-byte copy would ship unresolved -- see each file's own header for
# what it substitutes to. Every other manifest copies verbatim.
if [ "$WORKER_MODE" -eq 0 ]; then
  TARBALL_MANIFEST_DIR="$(find "$STAGE_DIR" -type d -name manifests | head -n1)"
  if [ -n "$TARBALL_MANIFEST_DIR" ] && [ -n "$(find "$TARBALL_MANIFEST_DIR" -maxdepth 1 -name '*.yaml')" ]; then
    install -d -m 0755 "$MANIFEST_OUTPUT_DIR"
    cp "$TARBALL_MANIFEST_DIR"/*.yaml "$MANIFEST_OUTPUT_DIR/"
    if [ -f "$MANIFEST_OUTPUT_DIR/flannel.yaml" ]; then
      # sed -e ... > tmp && mv, not -i: -i's flag shape differs between GNU and
      # BSD sed, and this redirect-and-replace form works identically on both.
      sed -e "s/__IFACE__/$IFACE/g" -e "s#__POD_CLUSTER_CIDR__#$POD_CLUSTER_CIDR#g" \
        "$MANIFEST_OUTPUT_DIR/flannel.yaml" > "$MANIFEST_OUTPUT_DIR/flannel.yaml.tmp"
      mv "$MANIFEST_OUTPUT_DIR/flannel.yaml.tmp" "$MANIFEST_OUTPUT_DIR/flannel.yaml"
    fi
    if [ -f "$MANIFEST_OUTPUT_DIR/kube-proxy.yaml" ]; then
      sed -e "s/__KUBE_VERSION__/$KUBE_VERSION/g" -e "s#__IFACE_IP__#$IFACE_IP#g" \
        "$MANIFEST_OUTPUT_DIR/kube-proxy.yaml" > "$MANIFEST_OUTPUT_DIR/kube-proxy.yaml.tmp"
      mv "$MANIFEST_OUTPUT_DIR/kube-proxy.yaml.tmp" "$MANIFEST_OUTPUT_DIR/kube-proxy.yaml"
    fi
  fi
fi

# --token-auth-file is always passed so a later --mint-join-token needs no unit
# edit plus extra restart to enable it. An empty file is a valid token map
# (auth::load_token_file skips blank lines), so the default path is unchanged
# until a token is appended.
touch "$STATE_DIR/token-auth-file"
chmod 600 "$STATE_DIR/token-auth-file"

cat > /etc/systemd/system/u7s-apiserver.service <<EOF
[Unit]
Description=u7s API server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$STATE_DIR
# --embedded-scheduler true: production runs scheduling as a task inside this
# process rather than a separate u7s-scheduler binary+unit -- never also
# start u7s-scheduler against this same cluster (see the retirement
# block above this section for why: uncoordinated double-preemption).
ExecStart=$BIN_DIR/u7s-apiserver --listen $IFACE_IP:6443 --advertise-address https://$IFACE_IP:6443 --token-auth-file $STATE_DIR/token-auth-file --embedded-scheduler true
# SIGHUP re-scans /etc/u7s/manifests in place instead of restarting -- 'kill -HUP'
# reports success the instant the signal is delivered, so a failed reload is only visible via
# 'journalctl -u u7s-apiserver', never through this reload job's own exit status.
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/u7s-kcm.service <<EOF
[Unit]
Description=u7s kube-controller-manager
After=u7s-apiserver.service
Requires=u7s-apiserver.service

[Service]
Type=simple
WorkingDirectory=$STATE_DIR
# ca.crt is DER from u7s but KCM needs PEM, converted at start rather than at
# install time because it does not exist until apiserver's first run.
# ExecStartPre rather than a bash -c wrapper so --controllers=*,-... stays a
# literal argv entry: systemd's own line-splitting never globs, but a real
# shell would expand that "*" against WorkingDirectory's contents.
ExecStartPre=/usr/bin/openssl x509 -inform DER -in $STATE_DIR/ca.crt -out $STATE_DIR/ca.pem
# Go-runtime memory tuning ported from the conformance dev-loop
# (scripts/conformance/04-start-kcm.sh), same lever class as kubelet's own
# fix below, measured independently for KCM rather than assumed to
# transfer. GOMEMLIMIT is a soft cap (GC works harder as it's approached,
# never OOM-kills), so this is safe to trial and fully reversible.
# Round-2: 200MiB->128MiB. Two tuned full-conformance samples measured
# KCM peak at 109.2MB/112.8MB (transient 115.48MB) -- 128MiB still clears
# that by 19-25MB while giving GC less headroom to coast on.
Environment=GOMEMLIMIT=128MiB
Environment=GOGC=50
Environment=GOMAXPROCS=2
# -clusterrole-aggregation-controller: u7s never sets ClusterRole.aggregationRule
# (no shipped ClusterRole uses it, no code reads it) so this controller has no
# object to ever act on; the informer it shares (ClusterRoles) is already kept
# warm by RBAC authorization itself.
# -device-taint-eviction-controller: DRA is GA (DynamicResourceAllocation) and
# u7s fully serves resource.k8s.io/v1 (DeviceClass/ResourceClaim/
# ResourceClaimTemplate/ResourceSlice), but the DeviceTaintRule type this
# controller acts on lives at resource.k8s.io/v1beta2, a version u7s does not
# serve at all -- no DeviceTaintRule can ever exist, so device-taint-based
# eviction is structurally unreachable regardless of this flag.
ExecStart=$BIN_DIR/kube-controller-manager --kubeconfig=$STATE_DIR/kcm-kubeconfig --cluster-signing-cert-file=$STATE_DIR/ca.pem --cluster-signing-key-file=$STATE_DIR/ca.key --service-account-private-key-file=$STATE_DIR/sa.key --root-ca-file=$STATE_DIR/ca.pem --controllers=*,-cloud-node-lifecycle-controller,-clusterrole-aggregation-controller,-device-taint-eviction-controller,-node-route-controller,-service-lb-controller,-service-cidr-controller --allocate-node-cidrs=true --cluster-cidr=$POD_CLUSTER_CIDR --node-cidr-mask-size=$POD_NODE_CIDR_MASK_SIZE --use-service-account-credentials=false --leader-elect=false --bind-address=127.0.0.1 --kube-api-content-type=application/json
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/kubelet.service <<EOF
[Unit]
Description=Kubernetes kubelet
After=network-online.target crio.service u7s-apiserver.service
Wants=network-online.target
Requires=crio.service u7s-apiserver.service

[Service]
Type=simple
WorkingDirectory=$STATE_DIR
# Go-runtime memory tuning ported from the conformance dev-loop
# (scripts/conformance/lima-start.sh) -- see the worker-mode kubelet.service
# block above for the measured before/after numbers this tuple is based on.
Environment=GOMEMLIMIT=200MiB
Environment=GOGC=50
Environment=GOMAXPROCS=2
# Without a CA-signed serving cert (wired via kubelet-config.yaml's
# tlsCertFile), kubelet self-signs for :10250, and the apiserver's
# kubelet-client -- pinned to the cluster CA by build_kubelet_tls_config in
# crates/apiserver/src/handlers/proxy.rs, not the system trust store --
# rejects it, surfacing as BadGateway on kubectl logs/exec. KCM has no
# auto-approve path for kubelet-serving CSRs, since approving one blindly
# would let any node claim a cert for any IP or hostname, so the cert is
# minted here from the CA this script already controls.
# ExecStartPre is idempotent: it skips regeneration when the cert exists, so
# Restart=always does not churn it, and the DER->PEM conversion is safe to
# repeat across services.
ExecStartPre=/usr/bin/openssl x509 -inform DER -in $STATE_DIR/ca.crt -out $STATE_DIR/ca.pem
ExecStartPre=/bin/bash -c 'test -s $STATE_DIR/kubelet-serving.crt || { openssl ecparam -name prime256v1 -genkey -noout -out $STATE_DIR/kubelet-serving.key && chmod 600 $STATE_DIR/kubelet-serving.key && openssl req -new -key $STATE_DIR/kubelet-serving.key -subj "/CN=$NODE_NAME" -out $STATE_DIR/kubelet-serving.csr && openssl x509 -req -in $STATE_DIR/kubelet-serving.csr -CA $STATE_DIR/ca.pem -CAkey $STATE_DIR/ca.key -CAcreateserial -days 3650 -extfile <(printf "subjectAltName=IP:$IFACE_IP\nextendedKeyUsage=serverAuth\n") -out $STATE_DIR/kubelet-serving.crt; }'
ExecStart=$BIN_DIR/kubelet --config=$STATE_DIR/kubelet-config.yaml --kubeconfig=$STATE_DIR/kubeconfig --hostname-override=$NODE_NAME --node-ip=$IFACE_IP $KUBELET_ROUND2_FLAGS
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
# restart rather than start: on a re-run against an already-active unit,
# start is a no-op, so the running process would never re-exec against the
# binary just staged above. restart on an enabled-but-inactive unit (fresh
# install) behaves exactly like start.
systemctl enable u7s-apiserver.service
if ! systemctl restart u7s-apiserver.service; then
  echo "error: failed to restart u7s-apiserver.service (check: systemctl status u7s-apiserver, journalctl -u u7s-apiserver)" >&2
  exit 1
fi
systemctl enable u7s-kcm.service
systemctl restart u7s-kcm.service
systemctl enable kubelet.service
systemctl restart kubelet.service

# --- In-cluster bootstrap: kube-proxy + Flannel CNI --------------------------
#
# Both ship as manifests/*.yaml, applied via the well-known-manifest-folder
# mechanism (docs/decisions/well-known-manifest-folder.md) rather than an
# install.sh heredoc: the apiserver SSA-applies every file there in-process
# at every boot, the same way it already applies its own compiled-in CoreDNS
# bundle (bootstrap_apply.rs). The vendored-manifest copy step above already
# templated each file's install-time placeholders (kube-proxy's
# __KUBE_VERSION__/__IFACE_IP__, Flannel's __IFACE__/__POD_CLUSTER_CIDR__)
# into $MANIFEST_OUTPUT_DIR -- see manifests/kube-proxy.yaml and
# manifests/flannel.yaml for what each substitutes to and their departures
# from upstream.
#
# wait_for_apiserver here confirms that boot-time apply actually succeeded --
# a bad manifest is a fatal startup error for u7s-apiserver itself
# (bootstrap_apply.rs), and /healthz doesn't report ready until that apply
# resolves (see wait_for_apiserver's own doc), so a broken kube-proxy/Flannel
# manifest still surfaces as an install failure, not as a separate
# kubectl-apply failure the way it used to.
KUBECONFIG_PATH="$STATE_DIR/kubeconfig"
wait_for_apiserver "$KUBECONFIG_PATH"

echo "u7s bootstrap complete (host-level + in-cluster)."
echo "kubeconfig: $KUBECONFIG_PATH"
echo "Run: kubectl --kubeconfig=$KUBECONFIG_PATH get nodes"
