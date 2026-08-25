#!/usr/bin/env bash
# u7s host-level install bootstrap.
#
# Takes a fresh Ubuntu LTS box to a running control plane + kubelet: installs
# CRI-O + crun via apt, stages u7s-apiserver/u7s-scheduler plus the vendored
# kubelet and kube-controller-manager from a release tarball, and writes
# systemd units for all four. Also installs kubectl and applies vendored
# component manifests.
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
#                       kubelet with its own x509 identity.
#
# Usage:
#   sudo scripts/install.sh [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>]
#   sudo scripts/install.sh --mint-join-token --node-name <name> --node-ip <ip>
#   sudo scripts/install.sh --join <url> --token <artifact> [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>]
#
# Knobs on the zero-argument path are exactly two, both env-settable
# (docs/decisions/install-script-ux.md):
#   --node-name / U7S_NODE_NAME   Node identity (default: hostname).
#   --iface     / U7S_IFACE       Cluster-traffic interface (default: first
#                                 physical non-loopback interface).
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
  install.sh [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>]
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

# --- Shared helpers (used by more than one mode) -----------------------------

# Poll the local apiserver's /healthz via its own admin kubeconfig. Polling
# rather than assuming: apiserver's first-run bootstrap (and the restart that
# picks up a new token-auth-file entry) races its own listener bind, so
# neither the kubeconfig nor a live listener exists when systemctl returns.
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
# apiserver's default --service-cluster-ip-range (10.96.0.0/12), and four
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

echo "Installing u7s: node-name=$NODE_NAME iface=$IFACE ($IFACE_IP)"

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
systemctl enable --now crio

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
if [ "$JOIN_MODE" -eq 1 ]; then
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
# ca.crt is DER from u7s but KCM needs PEM, converted at start rather than at
# install time because it does not exist until apiserver's first run.
# ExecStartPre rather than a bash -c wrapper so --controllers=*,-... stays a
# literal argv entry: systemd's own line-splitting never globs, but a real
# shell would expand that "*" against WorkingDirectory's contents.
ExecStartPre=/usr/bin/openssl x509 -inform DER -in $STATE_DIR/ca.crt -out $STATE_DIR/ca.pem
ExecStart=$BIN_DIR/kube-controller-manager --kubeconfig=$STATE_DIR/kcm-kubeconfig --cluster-signing-cert-file=$STATE_DIR/ca.pem --cluster-signing-key-file=$STATE_DIR/ca.key --service-account-private-key-file=$STATE_DIR/sa.key --root-ca-file=$STATE_DIR/ca.pem --controllers=*,-cloud-node-lifecycle-controller,-node-route-controller,-service-lb-controller,-service-cidr-controller --allocate-node-cidrs=true --cluster-cidr=$POD_CLUSTER_CIDR --node-cidr-mask-size=$POD_NODE_CIDR_MASK_SIZE --use-service-account-credentials=false --leader-elect=false --bind-address=127.0.0.1 --kube-api-content-type=application/json
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
# CoreDNS needs nothing here -- the apiserver server-side-applies its own
# vendored manifest in-process on every boot (bootstrap_apply.rs) -- but
# kube-proxy has no equivalent path, so it is applied once the apiserver is
# reachable. Its ClusterRole is already seeded by the apiserver; only the
# ServiceAccount binding, config and DaemonSet are new.
KUBECONFIG_PATH="$STATE_DIR/kubeconfig"
wait_for_apiserver "$KUBECONFIG_PATH"

# server: the "kubernetes" Service's fixed ClusterIP, hardcoded rather than
# kubeadm's ${KUBERNETES_SERVICE_HOST} env form -- same reasoning as
# coredns.yaml pinning kube-dns's ClusterIP, a known-good address over a
# Pod-env-var substitution path this project has not verified.
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

# --- In-cluster bootstrap: Flannel CNI (cross-node pod networking) ----------
#
# node-ipam-controller (enabled above via --cluster-cidr=$POD_CLUSTER_CIDR)
# only stamps Node.spec.podCIDR -- something still has to route pod traffic
# between nodes using it. CRI-O's default bridge plugin (disabled above) has
# no cross-node concept at all: every node would otherwise pick the same
# uncoordinated default subnet with zero routing between hosts, so a
# ClusterIP Service backed by a pod on a different node is unreachable.
# Flannel's vxlan backend closes that gap.
#
# Inlined here rather than a vendored file kubectl -f reads from disk, and
# NOT include_bytes!'d into a Rust binary either: install.sh is published and
# run standalone (curl | sh, see deploy/get-u7s/README.md) with no sibling
# files on disk once fetched -- the same reason kube-proxy's DaemonSet above
# is inline rather than a vendored path.
#
# Adapted from flannel-io/flannel's official kube-flannel.yml (v0.28.9):
#   - net-conf.json's Network is $POD_CLUSTER_CIDR, not a hardcoded literal,
#     so it can never drift from node-ipam-controller's --cluster-cidr above
#     (they already agree today: 10.244.0.0/16 is upstream's own default too).
#   - flanneld gets both --iface and --iface-regex, matching install.sh's own
#     $IFACE resolution rather than flannel's normal "default route" guess.
#     --iface=$IFACE is the literal interface install.sh picked on this node;
#     --iface-regex reuses install.sh's own physical-NIC whitelist regex
#     (used for --iface auto-detection above) as flannel's fallback, since
#     this one DaemonSet spec runs on every node and this project's own Lima
#     fleet has observed non-uniform physical interface naming across
#     otherwise-identical VMs (a literal --iface from one node's resolution
#     can genuinely not exist on another). An operator who instead points
#     --iface at a uniformly-named VPN-mesh interface (e.g. a WireGuard/
#     Tailscale link used for cluster traffic across clouds) gets an exact
#     --iface match on every node instead of falling through to the regex.
echo "Applying Flannel CNI manifest..."
kubectl --kubeconfig="$KUBECONFIG_PATH" apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  labels:
    k8s-app: flannel
    pod-security.kubernetes.io/enforce: privileged
  name: kube-flannel
---
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-app: flannel
  name: flannel
  namespace: kube-flannel
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    k8s-app: flannel
  name: flannel
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - nodes/status
  verbs:
  - patch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    k8s-app: flannel
  name: flannel
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: flannel
subjects:
- kind: ServiceAccount
  name: flannel
  namespace: kube-flannel
---
apiVersion: v1
data:
  cni-conf.json: |
    {
      "name": "cbr0",
      "cniVersion": "0.3.1",
      "plugins": [
        {
          "type": "flannel",
          "delegate": {
            "hairpinMode": true,
            "isDefaultGateway": true
          }
        },
        {
          "type": "portmap",
          "capabilities": {
            "portMappings": true
          }
        }
      ]
    }
  net-conf.json: |
    {
      "Network": "$POD_CLUSTER_CIDR",
      "EnableNFTables": false,
      "Backend": {
        "Type": "vxlan"
      }
    }
kind: ConfigMap
metadata:
  labels:
    app: flannel
    k8s-app: flannel
    tier: node
  name: kube-flannel-cfg
  namespace: kube-flannel
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    app: flannel
    k8s-app: flannel
    tier: node
  name: kube-flannel-ds
  namespace: kube-flannel
spec:
  selector:
    matchLabels:
      app: flannel
      k8s-app: flannel
  template:
    metadata:
      labels:
        app: flannel
        k8s-app: flannel
        tier: node
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/os
                operator: In
                values:
                - linux
      containers:
      - args:
        - --ip-masq
        - --kube-subnet-mgr
        - --iface=$IFACE
        - --iface-regex=^(en|wl|ww)[a-zA-Z0-9]+$|^eth[0-9]+$
        command:
        - /opt/bin/flanneld
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: EVENT_QUEUE_DEPTH
          value: "5000"
        - name: CONT_WHEN_CACHE_NOT_READY
          value: "false"
        image: ghcr.io/flannel-io/flannel:v0.28.9
        name: kube-flannel
        resources:
          requests:
            cpu: 100m
            memory: 50Mi
        securityContext:
          capabilities:
            add:
            - NET_ADMIN
            - NET_RAW
          privileged: false
        volumeMounts:
        - mountPath: /run/flannel
          name: run
        - mountPath: /etc/kube-flannel/
          name: flannel-cfg
        - mountPath: /run/xtables.lock
          name: xtables-lock
      hostNetwork: true
      initContainers:
      - args:
        - -f
        - /flannel
        - /opt/cni/bin/flannel
        command:
        - cp
        image: ghcr.io/flannel-io/flannel-cni-plugin:v1.9.1-flannel3
        name: install-cni-plugin
        volumeMounts:
        - mountPath: /opt/cni/bin
          name: cni-plugin
      - args:
        - -f
        - /etc/kube-flannel/cni-conf.json
        - /etc/cni/net.d/10-flannel.conflist
        command:
        - cp
        image: ghcr.io/flannel-io/flannel:v0.28.9
        name: install-cni
        volumeMounts:
        - mountPath: /etc/cni/net.d
          name: cni
        - mountPath: /etc/kube-flannel/
          name: flannel-cfg
      priorityClassName: system-node-critical
      serviceAccountName: flannel
      tolerations:
      - effect: NoSchedule
        operator: Exists
      volumes:
      - hostPath:
          path: /run/flannel
        name: run
      - hostPath:
          path: /opt/cni/bin
        name: cni-plugin
      - hostPath:
          path: /etc/cni/net.d
        name: cni
      - configMap:
          name: kube-flannel-cfg
        name: flannel-cfg
      - hostPath:
          path: /run/xtables.lock
          type: FileOrCreate
        name: xtables-lock
EOF

echo "u7s bootstrap complete (host-level + in-cluster)."
echo "kubeconfig: $KUBECONFIG_PATH"
echo "Run: kubectl --kubeconfig=$KUBECONFIG_PATH get nodes"
