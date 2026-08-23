#!/usr/bin/env bash
# u7s host-level install bootstrap (Gate 6 MVP, HOST-LEVEL half).
#
# Takes a fresh Ubuntu LTS box to a running control plane + kubelet: installs
# CRI-O + crun via apt, stages u7s's own binaries (apiserver, scheduler) plus
# the vendored kubelet and kube-controller-manager binaries from a locally
# pre-built tarball, and writes/enables systemd units for all four so they
# survive reboots and restart on crash.
#
# Also installs kubectl and applies the in-cluster kube-proxy DaemonSet
# manifest once the apiserver is reachable (CoreDNS needs no equivalent step
# here -- the apiserver applies its own vendored manifest in-process on every
# boot, see crates/apiserver/src/bootstrap_apply.rs).
#
# Multi-node join uses the real certificates.k8s.io CSR API, not a custom
# endpoint -- u7s's kube-controller-manager is the real unmodified upstream
# binary, and its builtin csrapproving/csrsigning controllers already
# auto-approve and sign join/renewal CSRs against u7s's real CA once the
# nodeclient/selfnodeclient RBAC grants exist (seeded by the apiserver
# itself). Two additional modes:
#   --mint-join-token   Run on an existing control-plane node: mints a
#                       bootstrap bearer token plus a pre-signed kubelet
#                       serving cert for a new node, and prints one
#                       base64(JSON) join artifact to hand to that node.
#   --join <url>        Run on a fresh node with --token <artifact>: submits
#                       a client CSR authenticated by the bootstrap token,
#                       waits for kube-controller-manager to auto-approve and
#                       sign it, and joins as a kubelet with its own
#                       dedicated x509 identity.
#
# NOT covered here: HA/multi-apiserver control-plane join, or CA rotation
# tooling. (Fetching a tarball by URL, with sha256 verification against its
# published sidecar, is covered via --tarball-url -- see below.)
#
# Usage:
#   sudo scripts/install.sh --tarball <path> [--node-name <name>] [--iface <iface>]
#   sudo scripts/install.sh --mint-join-token --node-name <name> --node-ip <ip>
#   sudo scripts/install.sh --join <url> --token <artifact> --tarball <path> [--node-name <name>] [--iface <iface>]
#
# Configurable knobs (docs/decisions/install-script-ux.md) -- exactly two,
# both optional, both also settable via env var, for the zero-argument
# single-node path:
#   --node-name / U7S_NODE_NAME   Node identity (default: hostname).
#   --iface     / U7S_IFACE       Interface used for cluster traffic
#                                 (default: first non-loopback interface).
# --mint-join-token/--join/--token/--node-ip are the additive multi-node-join
# surface docs/decisions/install-script-ux.md anticipates; they do not exist
# on the zero-argument default path.
#
# One of --tarball <path> / --tarball-url <url> is required for the default
# and --join modes (docs/decisions/upstream-component-shipping-shape.md + the
# roadmap's Gate 6 MVP scope: building/hosting the tarball is explicitly out
# of scope for this script -- --tarball-url only fetches bytes an operator
# already pointed it at, verified against the checksum sidecar
# .github/workflows/release-tarball.yaml publishes alongside it; it does not
# decide where those bytes are hosted). The tarball is expected to contain
# the binaries each mode needs (u7s-apiserver, u7s-scheduler, kubelet,
# kube-controller-manager for the default control-plane mode; kubelet only
# for --join), findable anywhere in its extracted tree.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  install.sh (--tarball <path> | --tarball-url <url>) [--node-name <name>] [--iface <iface>]
  install.sh --mint-join-token --node-name <name> --node-ip <ip>
  install.sh --join <url> --token <artifact> (--tarball <path> | --tarball-url <url>) [--node-name <name>] [--iface <iface>]

  --tarball <path>      Path to a locally pre-built u7s release tarball.
                         One of --tarball / --tarball-url is required -- see
                         docs/decisions/upstream-component-shipping-shape.md.
  --tarball-url <url>   URL to fetch the release tarball from instead of a
                         local path. Fetches and verifies "<url>.sha256"
                         (raw hex digest) automatically; a checksum mismatch
                         hard-fails the install rather than proceeding with a
                         corrupted or tampered-with download.
  --node-name <name>    Node identity (default: hostname). For --mint-join-token
                         this is the NAME OF THE JOINING NODE, not this host.
  --iface <iface>       Network interface used for cluster traffic
                         (default: first non-loopback interface).
  --mint-join-token     Run on an existing control-plane node: mint a join
                         artifact for a new node (requires --node-name, --node-ip).
  --node-ip <ip>        IP address of the joining node (--mint-join-token only).
  --join <url>          Join an existing cluster at <url> (e.g. https://1.2.3.4:6443)
                         using the artifact passed via --token.
  --token <artifact>    base64(JSON) join artifact produced by --mint-join-token
                         (--join only).
EOF
}

NODE_NAME="${U7S_NODE_NAME:-}"
IFACE="${U7S_IFACE:-}"
TARBALL=""
TARBALL_URL=""
# Set by fetch_tarball_with_checksum (only when --tarball-url is used) so its
# scratch download dir is cleaned up by the same EXIT trap as STAGE_DIR below,
# rather than needing a second trap that would silently clobber the first.
DOWNLOAD_DIR=""
MINT_JOIN_TOKEN=0
NODE_IP=""
JOIN_SERVER=""
JOIN_TOKEN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --node-name) NODE_NAME="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --tarball) TARBALL="$2"; shift 2 ;;
    --tarball-url) TARBALL_URL="$2"; shift 2 ;;
    --mint-join-token) MINT_JOIN_TOKEN=1; shift ;;
    --node-ip) NODE_IP="$2"; shift 2 ;;
    --join) JOIN_SERVER="$2"; shift 2 ;;
    --token) JOIN_TOKEN="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [ -n "$TARBALL" ] && [ -n "$TARBALL_URL" ]; then
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

# Fail loud rather than silently degrading to an unsupervised bare process
# (docs/decisions/systemd-install-contract.md). /run/systemd/system only
# exists when systemd is genuinely running as PID 1 -- the standard,
# widely-used detection check (e.g. systemd-detect-virt uses the same test).
if [ ! -d /run/systemd/system ]; then
  echo "error: systemd not detected (no /run/systemd/system) -- u7s requires systemd" >&2
  exit 1
fi

BIN_DIR=/opt/u7s/bin
STATE_DIR=/var/lib/u7s

# --- Shared helpers (used by more than one mode) -----------------------------

# Poll the local apiserver's /healthz via its own admin kubeconfig. Used both
# after a fresh single-node boot and after --mint-join-token's restart --
# apiserver's first-run bootstrap (or the restart picking up a new
# token-auth-file entry) races its own listener binding, so callers must poll
# rather than assume the kubeconfig file and a live listener both already
# exist right after systemctl returns.
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

# --tarball-url: downloads the tarball itself (rather than trusting an
# already-downloaded local path, --tarball's contract) and verifies it
# against a "<url>.sha256" sidecar -- a raw hex digest with no filename
# column, the same convention scripts/build-release-tarball.sh already
# trusts for kubelet/KCM's own dl.k8s.io sidecars, and the one
# .github/workflows/release-tarball.yaml publishes for this tarball. A
# mismatch means the download is corrupted or was tampered with in transit;
# proceeding to `tar -xzf` (and eventually running the binaries inside as
# root) on unverified bytes silently defeats the entire point of shipping a
# checksum, so this hard-fails rather than logging a warning and continuing.
fetch_tarball_with_checksum() {
  local url="$1" expected actual
  DOWNLOAD_DIR="$(mktemp -d)"
  TARBALL="$DOWNLOAD_DIR/$(basename "$url")"

  echo "Downloading tarball from $url..."
  curl -fsSL --retry 3 --retry-connrefused -o "$TARBALL" "$url"

  echo "Verifying checksum against ${url}.sha256..."
  expected="$(curl -fsSL --retry 3 --retry-connrefused "${url}.sha256")"
  actual="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
  if [ "$expected" != "$actual" ]; then
    echo "error: checksum mismatch for downloaded tarball ($url)" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    echo "  the download is corrupted or was tampered with -- refusing to install it" >&2
    exit 1
  fi
  echo "Checksum OK ($actual)."
}

# jq is only needed by --mint-join-token/--join (building/parsing the join
# artifact and CSR API JSON bodies) -- not installed unconditionally so the
# default single-node path's apt footprint stays unchanged.
ensure_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y jq
  fi
}

# Find each named binary anywhere in $STAGE_DIR and install it into $BIN_DIR,
# rejecting a found-but-non-executable match instead of silently installing
# it (e.g. a stray non-binary file that happens to share a required binary's
# name inside the tarball).
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
# apiserver's default --service-cluster-ip-range (10.96.0.0/12), and
# resolvConf disabled. resolvConf: "" is not a Lima-only workaround -- any
# Ubuntu LTS box running systemd-resolved (the Ubuntu default) has
# /etc/resolv.conf pointing at the 127.0.0.53 stub, which is unreachable from
# inside a pod's network namespace; disabling passthrough avoids kubelet
# propagating that unusable resolver into every pod's /etc/resolv.conf.
#
# tlsCertFile/tlsPrivateKeyFile point at a serving cert signed by the cluster
# CA -- either minted locally by kubelet.service's ExecStartPre (single-node)
# or delivered pre-signed in the join artifact (--join) -- see those call
# sites' comments for why (without it, kubelet falls back to a self-signed
# cert the apiserver's kubelet-client always rejects, breaking kubectl
# logs/exec).
#
# authentication.x509.clientCAFile is the other half of that same fix: it lets
# kubelet authenticate apiserver's own client cert (CN=kube-apiserver-kubelet-
# client, O=system:masters, also signed by this CA) as an identity instead of
# treating the request as anonymous. Without it, kubelet's default anonymous-
# auth+AlwaysAllow combination sounds permissive but is actually not what
# happens here: this real kubelet's own container-log/exec endpoints return a
# bare 401 "Unauthorized" for a request with no clientCAFile configured to
# resolve an identity against, propagated verbatim through the apiserver's
# proxy (see the passthrough comment in handlers/proxy.rs) as the same
# kubectl-logs/exec failure this unit's serving-cert fix alone does not clear.
#
# rotateCertificates: true lets kubelet self-renew its own client cert (the
# one embedded in --kubeconfig) via this same CSR mechanism once it holds a
# real x509 identity -- the selfnodeclient RBAC grant (seeded by the
# apiserver) is the only other piece that needs to exist, and it already
# does. Needs no other install.sh logic: it is kubelet's own standing
# capability.
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
EOF
}

# --mint-join-token: run on an existing control-plane node (which already has
# ca.key/ca.pem on disk from its own single-node bootstrap). Mints a
# bootstrap bearer token authorized (via the apiserver's already-seeded
# system:node-bootstrapper / nodeclient ClusterRoles, bound to group
# system:bootstrappers) to submit exactly one join CSR, restarts
# u7s-apiserver.service to load it (the token map is load-once-at-startup,
# confirmed no hot-reload path -- a brief restart is unavoidable and
# acceptable given u7s's single-apiserver, already-accepted no-HA
# architecture), and locally signs a kubelet serving cert for the joining
# node using the exact same openssl invocation kubelet.service's own
# ExecStartPre uses for single-node, just parameterized by the joining node's
# name/IP instead of this host's own. All three (CA cert, bootstrap token,
# serving cert+key) are bundled into one base64(JSON) artifact for the
# operator to copy to the joining node.
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
  # Double-quoted (not the single-quoted style used for $STAGE_DIR's EXIT trap
  # elsewhere in this script) so $mint_dir's value is baked into the trap
  # command NOW: mint_dir is `local` to this function and goes out of scope
  # once it returns, but this same EXIT trap only actually fires later, at
  # the whole script's real process exit -- a single-quoted trap would
  # re-evaluate "$mint_dir" at that point against an unset local, tripping
  # `set -u`.
  # shellcheck disable=SC2064 # intentional: see the immediate-expansion note above
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

# --join: run on a fresh node. Decodes the join artifact locally (no network
# fetch needed for CA trust), generates a local keypair, builds a PKCS#10 CSR
# shaped exactly as upstream kube-controller-manager's builtin csrapproving
# controller requires for its isNodeClientCert auto-approval recognizer
# (CN=system:node:<name>, O=system:nodes, signerName=kubernetes.io/kube-
# apiserver-client-kubelet, usages digital signature/key encipherment/client
# auth), and submits it authenticated with the bootstrap bearer token. KCM's
# real (unmodified upstream) csrapproving/csrsigning controllers auto-approve
# and sign it -- no manual approval step anywhere in this flow. The signed
# cert becomes kubelet's own dedicated x509 kubeconfig identity, not a shared
# admin kubeconfig and not a bearer-token one.
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

  # kube-controller-manager's builtin csrapproving/csrsigning controllers
  # handle approval and signing automatically (react to the create event,
  # not on a fixed poll interval) -- this loop is waiting on that, not
  # performing any approval itself.
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

if [ -n "$TARBALL_URL" ]; then
  fetch_tarball_with_checksum "$TARBALL_URL"
fi

if [ -z "$TARBALL" ]; then
  echo "error: --tarball <path> or --tarball-url <url> is required" >&2
  usage
  exit 1
fi
if [ ! -f "$TARBALL" ]; then
  echo "error: tarball not found: $TARBALL" >&2
  exit 1
fi

# --- Defaults: node name, network interface ----------------------------------

if [ -z "$NODE_NAME" ]; then
  NODE_NAME="$(hostname)"
fi

if [ -z "$IFACE" ]; then
  # Whitelist of real physical-NIC name patterns, not a blacklist of virtual
  # ones. A blacklist can only ever cover the virtual-interface names its
  # author happened to think of (docker0/veth*/cni*/... today, something
  # else tomorrow); the physical-NIC vocabulary is small, finite, and
  # documented (systemd.net-naming-scheme(7)): predictable names are always
  # en<x>/wl<x>/ww<x> (Ethernet/WLAN/WWAN) followed by an o/s/p/x-prefixed
  # location suffix -- eno1, ens33, enp0s3, enp2s0f1, enx<mac>, wlo1, wlp2s0,
  # wlx<mac>, wwp0s20u4i6 -- so "en"/"wl"/"ww" is the right level of
  # abstraction, not literally "eno"/"wlo" (which are just two instances of
  # the "en"/"wl" prefix, specific to onboard-device naming). The legacy
  # pre-predictable-naming kernel names (eth0, wlan0 -- wlan0 already matches
  # the "wl" prefix, so only eth0/ethN needs its own branch) are also
  # whitelisted: this is not just a theoretical old-kernel fallback -- a live
  # check across this project's own 5-VM Ubuntu 26.04 Lima fleet (identical
  # VM template) found it split 2/5 enp0s1 (predictable) vs 3/5 eth0
  # (fallback), so eth0 has to stay covered, not be treated as obsolete.
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

echo "Installing u7s: node-name=$NODE_NAME iface=$IFACE ($IFACE_IP)"

# --- CRI-O + crun via apt -----------------------------------------------------
#
# Near-direct lift of the proven sequence in lima/kubelet.yaml's provisioning
# (lines 74-115), with two test-harness-specific bits deliberately excluded:
#
#   - The 20-test-handler.conf runtime alias: added only to satisfy upstream
#     CRI-O CI's RuntimeClass e2e suite, not needed by a real deployment.
#   - Disabling containerd: investigated, not carried over. A live check
#     against lima-node-3 (an existing provisioned dev VM) found no `containerd`
#     apt package installed at all (`dpkg -l` returns nothing) -- the
#     containerd.service unit present there is injected by Lima's own guest
#     agent (per lima/kubelet.yaml's own comment: "Lima's builtin default
#     enables a per-USER (rootless) containerd ... unconditionally"), not by
#     anything in Ubuntu's base package set. A genuine fresh Ubuntu LTS box
#     provisioned outside Lima never gets containerd unless something else
#     (docker.io, containerd.io) explicitly installs it, so there is nothing
#     for a real install to conflict with or need to disable.
apt-get update -qq
apt-get install -y apt-transport-https ca-certificates curl gpg

install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://slc-mirror.opensuse.org/repositories/isv:/cri-o:/stable:/v1.36/deb/Release.key \
  | gpg --batch --yes --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://slc-mirror.opensuse.org/repositories/isv:/cri-o:/stable:/v1.36/deb/ /' \
  > /etc/apt/sources.list.d/cri-o.list
apt-get update -qq
apt-get install -y cri-o crun conmon
# Do NOT add a 10-crun.conf drop-in pointing at /usr/bin/crun.
# CRI-O ships its own crun at /usr/libexec/crio/crun that matches the OCI
# spec version it generates (1.2.x). The system crun only accepts 1.0/1.1
# and will fail with "unknown version specified" on every sandbox create.
# The 10-crio.conf shipped by the cri-o package already sets the correct path.
mkdir -p /etc/crio/crio.conf.d

# Enable the CNI 1.0.0 conflist bridge config.
# The cri-o package ships two CNI configs:
#   10-crio-bridge.conf         -- old 0.4.0 single-plugin format (fails with crun 1.26+)
#   10-crio-bridge.conflist     -- new 1.0.0 conflist format (correct)
# Disable the old one and enable the new one.
CNI_DIR=/etc/cni/net.d
if [ -f "$CNI_DIR/10-crio-bridge.conf" ]; then
  mv "$CNI_DIR/10-crio-bridge.conf" "$CNI_DIR/10-crio-bridge.conf.disabled" || true
fi
if [ -f "$CNI_DIR/10-crio-bridge.conflist.disabled" ]; then
  mv "$CNI_DIR/10-crio-bridge.conflist.disabled" "$CNI_DIR/10-crio-bridge.conflist" || true
fi

# crio.service itself is installed and enabled by the cri-o apt package
# (docs/decisions/systemd-install-contract.md) -- no unit is authored here.
# This just starts it, matching the proven sequence.
systemctl enable --now crio

# --- Stage binaries from the tarball ------------------------------------------
#
# u7s and KCM/kubelet ship together in one release tarball
# (docs/decisions/upstream-component-shipping-shape.md); building/hosting that
# tarball is out of scope here. Extract to a scratch dir and locate each
# required binary by name anywhere in the tree, rather than assuming a fixed
# internal layout the tarball-build step hasn't been designed yet. --join only
# needs kubelet (no control-plane binaries on a worker-only node).
STAGE_DIR="$(mktemp -d)"
# DOWNLOAD_DIR is only ever set (by fetch_tarball_with_checksum) when
# --tarball-url was used; cleaning it up here too means --tarball-url's own
# downloaded tarball doesn't need a second, separately-managed EXIT trap
# (bash keeps only the last trap registered for a given signal).
trap 'rm -rf "$STAGE_DIR" "$DOWNLOAD_DIR"' EXIT

tar -xzf "$TARBALL" -C "$STAGE_DIR"

install -d -m 0755 "$BIN_DIR"
if [ "$JOIN_MODE" -eq 1 ]; then
  stage_binaries kubelet
else
  stage_binaries u7s-apiserver u7s-scheduler kubelet kube-controller-manager
fi

# --- kubectl + CNI plugin binaries (apt, pinned to kubelet's own version) ----
#
# kubectl ships in neither the release tarball (out of scope per
# docs/decisions/upstream-component-shipping-shape.md -- that ADR only
# settles kubelet/KCM/kube-proxy/CoreDNS) nor the tarball's binary list this
# script checks above, but a zero-argument install that ends at a working
# `kubectl get nodes` needs kubectl to exist somewhere. Pulled from the
# official Kubernetes apt repo, same signed-apt-repo pattern as CRI-O above,
# pinned to kubelet's own minor version for client/server skew safety.
#
# kubernetes-cni (from the same repo) provides the actual CNI plugin binaries
# (bridge, host-local, loopback, ...) under /opt/cni/bin/ that CRI-O's own
# 10-crio-bridge.conflist references. CRI-O's apt package only Recommends
# (not Depends on) a CNI-plugins package, and cloud-image apt defaults to
# Install-Recommends=false -- so on a genuinely fresh box CRI-O starts with a
# CNI config file that validates against no actual plugin binaries, and every
# node sits NotReady forever with "failed to find plugin \"bridge\" in path
# [/opt/cni/bin/]" (found running this script end to end for the first time).
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

# State dir: apiserver's default relative paths (./state.db, ./kubeconfig,
# ./ca.key, ./ca.crt, ./sa.key, ./sa.pub) resolve here via WorkingDirectory=.
# 0700 because it ends up holding the CA private key and service-account
# signing key.
install -d -m 0700 "$STATE_DIR"
install -d -m 0755 /etc/u7s/static-pods

write_kubelet_config_yaml

if [ "$JOIN_MODE" -eq 1 ]; then
  # --- Join an existing cluster via the CSR API ------------------------------
  join_cluster

  cat > /etc/systemd/system/kubelet.service <<EOF
[Unit]
Description=Kubernetes kubelet
After=network-online.target crio.service
Wants=network-online.target
Requires=crio.service

[Service]
Type=simple
WorkingDirectory=$STATE_DIR
ExecStart=$BIN_DIR/kubelet --config=$STATE_DIR/kubelet-config.yaml --kubeconfig=$STATE_DIR/kubeconfig --hostname-override=$NODE_NAME --node-ip=$IFACE_IP
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now kubelet.service

  echo ""
  echo "u7s join complete. Verify from the control-plane node:"
  echo "  kubectl get nodes"
  exit 0
fi

# --- systemd units -------------------------------------------------------------
#
# Per docs/decisions/systemd-install-contract.md: one unit per host binary,
# Restart=always, boot-enabled. crio.service is intentionally not authored
# here (the apt package already owns it, enabled above).
#
# u7s-apiserver generates ca.key/ca.crt/sa.key/sa.pub/kubeconfig(+variants)
# on its first run inside $STATE_DIR -- u7s-scheduler, u7s-kcm, and kubelet
# all depend on files that do not exist until that first run completes.
# Type=simple only guarantees the *process* has started, not that bootstrap
# writes are done, so each dependent unit's first ExecStart can legitimately
# fail before those files exist. Restart=always (the same mechanism the
# install contract already relies on for crash recovery) absorbs this
# startup race for free -- no extra wait-loop/supervisor script needed.

# --token-auth-file is always passed so a later --mint-join-token on this
# same node never needs a units-file edit + extra restart just to turn the
# flag on -- an empty file here is a valid, always-loadable token map
# (auth::load_token_file skips blank/comment lines), so this default path's
# behavior is unchanged until a token actually gets appended.
touch "$STATE_DIR/token-auth-file"
chmod 600 "$STATE_DIR/token-auth-file"

# No --kubelet-preferred-address here (unlike the dev/conformance Lima harness's own
# apiserver invocation): that flag overrides EVERY node's resolved kubelet address to one
# fixed value, which only makes sense when a single kubelet's real InternalIP is unreachable
# from the apiserver (e.g. Mac host + port-forwarded Lima VM). A real multi-node install has
# one real, directly-routable IP per node already reported via kubelet's own --node-ip flag
# below -- forcing every node's proxy target (logs/exec/attach) to THIS node's own IP instead
# would silently proxy a joined node's log/exec requests to the wrong kubelet entirely
# (confirmed live: a joined node's `kubectl logs` returned "pod ... does not exist" because it
# was asking the control-plane's own kubelet, mayor-yocic's 2-node acceptance test).
cat > /etc/systemd/system/u7s-apiserver.service <<EOF
[Unit]
Description=u7s API server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$STATE_DIR
ExecStart=$BIN_DIR/u7s-apiserver --listen $IFACE_IP:6443 --advertise-address https://$IFACE_IP:6443 --token-auth-file $STATE_DIR/token-auth-file
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/u7s-scheduler.service <<EOF
[Unit]
Description=u7s scheduler
After=u7s-apiserver.service
Requires=u7s-apiserver.service

[Service]
Type=simple
WorkingDirectory=$STATE_DIR
ExecStart=$BIN_DIR/u7s-scheduler --kubeconfig $STATE_DIR/kubeconfig-scheduler
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
# ca.crt is written by u7s in DER form; KCM requires PEM. Converted here
# (not at install time) because ca.crt does not exist until u7s-apiserver's
# first run -- see the Restart=always note above. ExecStartPre (not a
# bash -c wrapper around ExecStart) so the --controllers=*,-... value below
# is passed to kube-controller-manager as a literal argv entry: systemd's
# own ExecStart line-splitting never runs a shell and never globs, but
# wrapping the whole command in bash -c would hand that unquoted "*" to a
# real shell parsing the WorkingDirectory's contents.
ExecStartPre=/usr/bin/openssl x509 -inform DER -in $STATE_DIR/ca.crt -out $STATE_DIR/ca.pem
ExecStart=$BIN_DIR/kube-controller-manager --kubeconfig=$STATE_DIR/kcm-kubeconfig --cluster-signing-cert-file=$STATE_DIR/ca.pem --cluster-signing-key-file=$STATE_DIR/ca.key --service-account-private-key-file=$STATE_DIR/sa.key --root-ca-file=$STATE_DIR/ca.pem --controllers=*,-cloud-node-lifecycle-controller,-node-ipam-controller,-node-route-controller,-service-lb-controller,-service-cidr-controller --use-service-account-credentials=false --leader-elect=false --bind-address=127.0.0.1 --kube-api-content-type=application/json
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
# Without --tls-cert-file/--tls-private-key-file (wired via kubelet-config.yaml's
# tlsCertFile/tlsPrivateKeyFile above), kubelet generates its own self-signed
# serving cert for :10250 (see 'kubelet --help's own --tls-cert-file text) --
# signed by a CA the apiserver's kubelet-client has no way to trust, since that
# client is pinned to the cluster CA (build_kubelet_tls_config in
# crates/apiserver/src/handlers/proxy.rs), not the system trust store. That
# mismatch is exactly what surfaces as "kubectl logs"/"exec" failing with
# BadGateway -- confirmed live via curl -v against the kubelet's own :10250
# showing a TLS "unknown CA" alert against kubelet's self-signed cert.
# kube-controller-manager's built-in CSR approver has no auto-approve path for
# kubernetes.io/kubelet-serving requests (unlike client-cert CSRs) -- blindly
# approving one would let any node claim a cert for any IP/hostname, so real
# clusters require a human or an external approver. Minting the serving cert
# once here from the CA install.sh already controls sidesteps that whole flow,
# which fits this script's current single-node scope.
# ExecStartPre (not a bash -c wrapping ExecStart itself, matching u7s-kcm.service's
# reasoning above): idempotent, skips regeneration if the cert already exists so
# Restart=always crash-restarts do not churn it, and openssl's ca.crt DER->PEM
# conversion is safe to repeat (same input, same output) across services.
ExecStartPre=/usr/bin/openssl x509 -inform DER -in $STATE_DIR/ca.crt -out $STATE_DIR/ca.pem
ExecStartPre=/bin/bash -c 'test -s $STATE_DIR/kubelet-serving.crt || { openssl ecparam -name prime256v1 -genkey -noout -out $STATE_DIR/kubelet-serving.key && chmod 600 $STATE_DIR/kubelet-serving.key && openssl req -new -key $STATE_DIR/kubelet-serving.key -subj "/CN=$NODE_NAME" -out $STATE_DIR/kubelet-serving.csr && openssl x509 -req -in $STATE_DIR/kubelet-serving.csr -CA $STATE_DIR/ca.pem -CAkey $STATE_DIR/ca.key -CAcreateserial -days 3650 -extfile <(printf "subjectAltName=IP:$IFACE_IP\nextendedKeyUsage=serverAuth\n") -out $STATE_DIR/kubelet-serving.crt; }'
ExecStart=$BIN_DIR/kubelet --config=$STATE_DIR/kubelet-config.yaml --kubeconfig=$STATE_DIR/kubeconfig --hostname-override=$NODE_NAME --node-ip=$IFACE_IP
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now u7s-apiserver.service
systemctl enable --now u7s-scheduler.service
systemctl enable --now u7s-kcm.service
systemctl enable --now kubelet.service

# --- In-cluster bootstrap: kube-proxy DaemonSet -------------------------------
#
# CoreDNS needs nothing here: the apiserver server-side-applies its own
# vendored manifest bundle in-process on every boot (bootstrap_apply.rs).
# kube-proxy has no equivalent in-process path (docs/decisions/upstream-
# component-shipping-shape.md scopes bootstrap_apply.rs to CoreDNS only), so
# this script applies it once the apiserver is confirmed reachable. RBAC
# (ClusterRole system:node-proxier) is already seeded by the apiserver
# itself; only the ServiceAccount binding, config, and DaemonSet are new.
KUBECONFIG_PATH="$STATE_DIR/kubeconfig"
wait_for_apiserver "$KUBECONFIG_PATH"

# server: hardcoded to 10.96.0.1 (the "kubernetes" Service's fixed ClusterIP)
# rather than the ${KUBERNETES_SERVICE_HOST} env-var form upstream's own
# kubeadm ConfigMap uses -- same reasoning as coredns.yaml pinning kube-dns's
# ClusterIP: a hardcoded, known-good address beats depending on a Pod-env-var
# substitution path this project hasn't specifically verified.
echo "Applying kube-proxy DaemonSet manifest..."
kubectl --kubeconfig="$KUBECONFIG_PATH" apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-proxy
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubeadm:node-proxier
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:node-proxier
subjects:
- kind: ServiceAccount
  name: kube-proxy
  namespace: kube-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-proxy
  namespace: kube-system
data:
  config.conf: |
    apiVersion: kubeproxy.config.k8s.io/v1alpha1
    kind: KubeProxyConfiguration
    mode: "iptables"
    clientConnection:
      kubeconfig: /var/lib/kube-proxy/kubeconfig.conf
  kubeconfig.conf: |
    apiVersion: v1
    kind: Config
    clusters:
    - cluster:
        certificate-authority: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        server: https://10.96.0.1:443
      name: default
    contexts:
    - context:
        cluster: default
        user: default
      name: default
    current-context: default
    users:
    - name: default
      user:
        tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-proxy
  namespace: kube-system
  labels:
    k8s-app: kube-proxy
spec:
  selector:
    matchLabels:
      k8s-app: kube-proxy
  template:
    metadata:
      labels:
        k8s-app: kube-proxy
    spec:
      serviceAccountName: kube-proxy
      hostNetwork: true
      tolerations:
      - operator: Exists
      containers:
      - name: kube-proxy
        image: registry.k8s.io/kube-proxy:v${KUBE_VERSION}
        command:
        - /usr/local/bin/kube-proxy
        - --config=/var/lib/kube-proxy/config.conf
        - --hostname-override=\$(NODE_NAME)
        securityContext:
          privileged: true
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: kube-proxy
          mountPath: /var/lib/kube-proxy
        - name: xtables-lock
          mountPath: /run/xtables.lock
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
      volumes:
      - name: kube-proxy
        configMap:
          name: kube-proxy
      - name: xtables-lock
        hostPath:
          path: /run/xtables.lock
          type: FileOrCreate
      - name: lib-modules
        hostPath:
          path: /lib/modules
EOF

echo "u7s bootstrap complete (host-level + in-cluster)."
echo "kubeconfig: $KUBECONFIG_PATH"
echo "Run: kubectl --kubeconfig=$KUBECONFIG_PATH get nodes"
