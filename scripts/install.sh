#!/usr/bin/env bash
# u7s host-level install bootstrap (Gate 6 MVP, HOST-LEVEL half).
#
# Takes a fresh Ubuntu LTS box to a running control plane + kubelet: installs
# CRI-O + crun via apt, stages u7s's own binaries (apiserver, scheduler) plus
# the vendored kubelet and kube-controller-manager binaries from a locally
# pre-built tarball, and writes/enables systemd units for all four so they
# survive reboots and restart on crash.
#
# NOT covered here (see the in-cluster follow-on step): CoreDNS/kube-proxy
# manifest bootstrap, multi-node join, and fetching the tarball from a URL
# (this script only accepts an already-downloaded local path).
#
# Usage:
#   sudo scripts/install.sh --tarball <path> [--node-name <name>] [--iface <iface>]
#
# Configurable knobs (docs/decisions/install-script-ux.md) -- exactly two,
# both optional, both also settable via env var:
#   --node-name / U7S_NODE_NAME   Node identity (default: hostname).
#   --iface     / U7S_IFACE       Interface used for cluster traffic
#                                 (default: first non-loopback interface).
# No other configuration surface exists in the zero-argument default path.
#
# --tarball <path> is required this MVP (docs/decisions/upstream-component-
# shipping-shape.md + the roadmap's Gate 6 MVP scope: building/hosting the
# tarball is explicitly out of scope for this script). The tarball is
# expected to contain four binaries -- u7s-apiserver, u7s-scheduler, kubelet,
# kube-controller-manager -- findable anywhere in its extracted tree.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: install.sh --tarball <path> [--node-name <name>] [--iface <iface>]

  --tarball <path>    Path to a locally pre-built u7s release tarball
                       (required -- see docs/decisions/upstream-component-shipping-shape.md).
  --node-name <name>  Node identity (default: hostname).
  --iface <iface>     Network interface used for cluster traffic
                       (default: first non-loopback interface).
EOF
}

NODE_NAME="${U7S_NODE_NAME:-}"
IFACE="${U7S_IFACE:-}"
TARBALL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --node-name) NODE_NAME="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --tarball) TARBALL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

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
  echo "error: systemd not detected (no /run/systemd/system) -- u7s requires systemd (Ubuntu LTS only, see docs/decisions/systemd-install-contract.md)" >&2
  exit 1
fi

if [ -z "$TARBALL" ]; then
  echo "error: --tarball <path> is required (fetching a tarball by URL is out of scope for this script)" >&2
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
  # First non-loopback interface, in kernel ifindex order (the order `ip link
  # show` lists them) -- matches install-script-ux.md's literal default. Also
  # excludes common virtual/container-runtime interfaces (docker0, veth*,
  # cni*, br-*, virbr*, flannel*, cali*): a genuinely fresh box won't have
  # any of these, but a box that already has some other container runtime
  # installed (or a re-run of this script) would, and picking one of those
  # as "the" cluster-traffic interface would be wrong regardless.
  IFACE="$(ip -o link show | awk -F': ' '{print $2}' \
    | grep -Ev '^(lo|docker[0-9]*|veth.*|cni.*|br-.*|virbr.*|flannel.*|cali.*)$' \
    | head -n1)"
  if [ -z "$IFACE" ]; then
    echo "error: no non-loopback, non-virtual network interface found -- pass --iface explicitly" >&2
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
# internal layout the tarball-build step hasn't been designed yet.
BIN_DIR=/opt/u7s/bin
STATE_DIR=/var/lib/u7s
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

tar -xzf "$TARBALL" -C "$STAGE_DIR"

install -d -m 0755 "$BIN_DIR"
for bin in u7s-apiserver u7s-scheduler kubelet kube-controller-manager; do
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

# State dir: apiserver's default relative paths (./state.db, ./kubeconfig,
# ./ca.key, ./ca.crt, ./sa.key, ./sa.pub) resolve here via WorkingDirectory=.
# 0700 because it ends up holding the CA private key and service-account
# signing key.
install -d -m 0700 "$STATE_DIR"
install -d -m 0755 /etc/u7s/static-pods

# --- kubelet config file -------------------------------------------------------
#
# Minimal KubeletConfiguration: CRI-O's socket, cluster DNS matching
# apiserver's default --service-cluster-ip-range (10.96.0.0/12), and
# resolvConf disabled. resolvConf: "" is not a Lima-only workaround -- any
# Ubuntu LTS box running systemd-resolved (the Ubuntu default) has
# /etc/resolv.conf pointing at the 127.0.0.53 stub, which is unreachable from
# inside a pod's network namespace; disabling passthrough avoids kubelet
# propagating that unusable resolver into every pod's /etc/resolv.conf.
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
EOF

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

cat > /etc/systemd/system/u7s-apiserver.service <<EOF
[Unit]
Description=u7s API server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$STATE_DIR
ExecStart=$BIN_DIR/u7s-apiserver --listen $IFACE_IP:6443 --advertise-address https://$IFACE_IP:6443 --kubelet-preferred-address $IFACE_IP
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

echo "u7s host-level bootstrap complete."
echo "kubeconfig: $STATE_DIR/kubeconfig"
echo "Next: apply CoreDNS/kube-proxy manifests (separate in-cluster bootstrap step), then 'kubectl get nodes'."
