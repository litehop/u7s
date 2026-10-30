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
#   --mint-join-token   On an existing control-plane node: create a 24h,
#                       single-use bootstrap-token Secret via the live
#                       apiserver (no restart) and print the join command.
#   --join <url>        On a fresh node: verify the cluster CA via
#                       kube-public/cluster-info and --ca-cert-hash, submit a
#                       client CSR under the token (from --token, or stdin
#                       when --token is "-" or absent), wait for it to be
#                       signed, and join as a kubelet with its own x509
#                       identity. One-shot: refuses
#                       to run against a node already classified as an
#                       existing joined worker (bootstrap tokens are
#                       single-use, and re-running would silently rotate the
#                       node's client identity). Re-running install.sh with
#                       no flags against such a node needs no token: it
#                       upgrades kubelet alone, leaving kubeconfig/
#                       kubelet-client.* untouched, and waits for the Node to
#                       report Ready again. An expired client identity fails
#                       with instructions to re-join with a fresh token.
#                       Re-running on the control plane upgrades in place and
#                       fails if the CA / service-account keys changed.
#
# Usage:
#   sudo scripts/install.sh [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>] [--manifest-output-dir <path>]
#   sudo scripts/install.sh --mint-join-token
#   sudo scripts/install.sh --join <url> --ca-cert-hash sha256:<hash> [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>]
#
# Knobs on the zero-argument path are env-settable
# (docs/decisions/install-script-ux.md):
#   --node-name / U7S_NODE_NAME   Node identity (default: hostname).
#   --iface     / U7S_IFACE       Cluster-traffic interface (default: first
#                                 physical non-loopback interface).
#   --service-cidr / U7S_SERVICE_CIDR   Service ClusterIP range (default 10.96.0.0/12);
#                                       or two comma-separated ranges of
#                                       different IP families (dual-stack,
#                                       e.g. 10.96.0.0/12,fd00:96::/108).
#   --cluster-cidr / U7S_CLUSTER_CIDR   Pod CIDR (default 10.244.0.0/16); or two
#                                       of different families (e.g.
#                                       10.244.0.0/16,fd00:244::/56).
#   --cluster-dns  / U7S_CLUSTER_DNS    kube-dns ClusterIP (default: tenth host
#                                       of the service range). Persisted at
#                                       first install; a conflicting re-run is
#                                       refused. A migration target inherits
#                                       k3s with 10.43.0.0/16, 10.42.0.0/16 and
#                                       10.43.0.10.
#   --manifest-output-dir / U7S_MANIFEST_OUTPUT_DIR
#                                 Where vendored manifest YAMLs from the
#                                 tarball land (default: /etc/u7s/manifests,
#                                 the apiserver's well-known auto-applied
#                                 folder -- docs/decisions/
#                                 well-known-manifest-folder.md).
#   U7S_READY_TIMEOUT_SECONDS     How long the control-plane install waits for
#                                 the node and the vendored kube-system
#                                 workloads to be Ready before failing
#                                 (default 1200).
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
  install.sh [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>] [--service-cidr <cidr>] [--cluster-cidr <cidr>] [--cluster-dns <ip>] [--manifest-output-dir <path>] [--allow-service-external-ips]
  install.sh --mint-join-token
  install.sh --join <url> [--token <token> | --token -] --ca-cert-hash sha256:<hash> [--tarball <path> | --tarball-url <url>] [--node-name <name>] [--iface <iface>] [--cluster-dns <ip>]

  --tarball <path>     Path to an already-downloaded u7s release tarball. NOT
                         signature-verified: the file is trusted as supplied.
                         Overrides the release URL baked into this copy.
  --tarball-url <url>   Fetch the release tarball from <url> instead of the
                         one baked into this copy at release time.
  --node-name <name>    Node identity (default: hostname).
  --iface <iface>       Network interface used for cluster traffic
                         (default: first non-loopback interface).
  --service-cidr <cidr> Service ClusterIP range (default: 10.96.0.0/12). To inherit
                         a k3s cluster use 10.43.0.0/16. Fixed at first install.
  --cluster-cidr <cidr> Pod CIDR (default: 10.244.0.0/16); k3s uses 10.42.0.0/16.
                         Disjoint from --service-cidr. Fixed at first install.
  --cluster-dns <ip>    ClusterIP of kube-dns, inside --service-cidr (default:
                         its tenth host, e.g. 10.96.0.10; k3s: 10.43.0.10).
                         --join nodes must pass the control plane's value
                         (--mint-join-token prints it when non-default).
  --manifest-output-dir <path>
                         Where vendored manifest YAMLs from the tarball land
                         (default: /etc/u7s/manifests, the apiserver's
                         well-known auto-applied folder). An alternate path
                         leaves the well-known folder empty, for GitOps to
                         manage instead.
  --allow-service-external-ips
                         Omit the apiserver's --deny-service-external-ips, which
                         by default rejects new/changed Service externalIPs.
  --mint-join-token     Run on an existing control-plane node: create a 24h
                         single-use join token and print the join command.
  --join <url>          Join an existing cluster at <url> (e.g. https://1.2.3.4:6443).
                         Topology limit: an apiserver that reaches this node's
                         kubelet through a 127.0.0.1 port forward (a Mac host
                         in front of Lima VMs) cannot verify its serving cert,
                         because the serving-CSR approver refuses 127.0.0.1
                         SANs by design; kubectl logs/exec to such a worker
                         fail. Real installs dial the node InternalIP.
  --token <token>       Join token from --mint-join-token (--join only). "-" or
                         absent prompts with echo off on a terminal, or reads
                         piped stdin; both keep it out of ps and history.
  --ca-cert-hash sha256:<hash>
                         Pin for the cluster CA (--join only), printed by
                         --mint-join-token.
EOF
}

# Substituted at release time by .github/workflows/release-tarball.yaml, which
# asserts its own substitution took effect. Empty in the repo copy: a checkout
# has no release to point at, so it fails loud instead of fetching an
# unrelated one (docs/decisions/distribution-hosting-shape.md).
DEFAULT_TARBALL_URL=""

NODE_NAME="${U7S_NODE_NAME:-}"
IFACE="${U7S_IFACE:-}"
# Empty = not passed; the defaults below apply after the persisted config is
# consulted (an unset flag on a re-run keeps what the first install chose).
DEFAULT_SERVICE_CIDR="10.96.0.0/12"
DEFAULT_POD_CLUSTER_CIDR="10.244.0.0/16"
SERVICE_CIDR="${U7S_SERVICE_CIDR:-}"
POD_CLUSTER_CIDR="${U7S_CLUSTER_CIDR:-}"
CLUSTER_DNS="${U7S_CLUSTER_DNS:-}"
# Per-family entries of the two lists, set by validate_network_config.
SERVICE_CIDR_IPV4=""; SERVICE_CIDR_IPV6=""
POD_CLUSTER_CIDR_IPV4=""; POD_CLUSTER_CIDR_IPV6=""
MANIFEST_OUTPUT_DIR="${U7S_MANIFEST_OUTPUT_DIR:-/etc/u7s/manifests}"
TARBALL=""
TARBALL_URL="$DEFAULT_TARBALL_URL"
# Only an operator-passed --tarball-url conflicts with --tarball; a released
# copy always has a non-empty default, so emptiness cannot distinguish them.
TARBALL_URL_EXPLICIT=0
# Set by fetch_tarball; removed by the same EXIT trap as STAGE_DIR.
DOWNLOAD_DIR=""
MINT_JOIN_TOKEN=0
ALLOW_SERVICE_EXTERNAL_IPS=0
JOIN_SERVER=""
JOIN_TOKEN=""
CA_CERT_HASH=""
# Set by join_cluster to the server-side creationTimestamp of this join's client CSR.
JOIN_STARTED_AT=""

# Everything below runs inside main(), invoked on the last line: bash must
# parse the whole function before executing any of it, so a truncated
# `curl | bash` download is a syntax error that executes nothing. The body is
# deliberately not indented, to keep heredoc contents byte-identical.
main() {
while [ $# -gt 0 ]; do
  case "$1" in
    --node-name) NODE_NAME="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --service-cidr) SERVICE_CIDR="$2"; shift 2 ;;
    --cluster-cidr) POD_CLUSTER_CIDR="$2"; shift 2 ;;
    --cluster-dns) CLUSTER_DNS="$2"; shift 2 ;;
    --manifest-output-dir) MANIFEST_OUTPUT_DIR="$2"; shift 2 ;;
    --tarball) TARBALL="$2"; shift 2 ;;
    --tarball-url) TARBALL_URL="$2"; TARBALL_URL_EXPLICIT=1; shift 2 ;;
    --allow-service-external-ips) ALLOW_SERVICE_EXTERNAL_IPS=1; shift ;;
    --mint-join-token) MINT_JOIN_TOKEN=1; shift ;;
    --join) JOIN_SERVER="$2"; shift 2 ;;
    --token) JOIN_TOKEN="$2"; shift 2 ;;
    --ca-cert-hash) CA_CERT_HASH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done
# "a, b" and "a,b" are one dual-stack value: persist and compare one form.
SERVICE_CIDR="${SERVICE_CIDR//[[:space:]]/}"
POD_CLUSTER_CIDR="${POD_CLUSTER_CIDR//[[:space:]]/}"

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

# beep, the DaemonSet that serves type=LoadBalancer Services, runs on every
# node and needs kernel >= 6.6 (its eBPF dataplane's support floor).
kernel_supports_beep() {
  local major minor
  IFS=. read -r major minor _ <<< "${1%%-*}"
  [ "$major" -gt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -ge 6 ]; }
}
if ! kernel_supports_beep "$(uname -r)"; then
  echo "error: kernel $(uname -r) is older than 6.6 -- u7s's default LoadBalancer provider (beep) requires kernel >= 6.6" >&2
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
# rather than assuming: apiserver's first-run bootstrap races its own listener
# bind, so neither the kubeconfig nor a live listener exists when systemctl
# returns.
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

# Block until u7s-apiserver's first run has written every file the control-plane
# units read at start. systemctl restart returns once the process is spawned,
# and a first boot on a slow core can take well over a second to mint the CA.
wait_for_apiserver_files() {
  local dir="$1" f missing=""
  echo "Waiting for u7s-apiserver to write its CA, keys and kubeconfigs..."
  for _ in $(seq 1 60); do
    missing=""
    for f in ca.crt ca.key intermediate-cert.pem intermediate.key sa.key kubeconfig kcm-kubeconfig; do
      [ -s "$dir/$f" ] || { missing="$dir/$f"; break; }
    done
    [ -z "$missing" ] && return 0
    sleep 2
  done
  echo "error: u7s-apiserver did not write $missing within 120s (check: systemctl status u7s-apiserver, journalctl -u u7s-apiserver)" >&2
  exit 1
}

# KCM's delegated authn/authz treats a missing
# kube-system/extension-apiserver-authentication ConfigMap as fatal at start, and
# the apiserver publishes it from a spawned reconciler after its files exist.
wait_for_authentication_configmap() {
  local kubeconfig_path="$1" ready=0
  echo "Waiting for the apiserver to publish kube-system/extension-apiserver-authentication..."
  for _ in $(seq 1 60); do
    if kubectl --kubeconfig="$kubeconfig_path" -n kube-system get configmap extension-apiserver-authentication >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done
  if [ "$ready" -ne 1 ]; then
    echo "error: kube-system/extension-apiserver-authentication was not published within 120s (check: journalctl -u u7s-apiserver); u7s-kcm needs it for delegated authn/authz" >&2
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

# Scratch dir for the release payload (tarball + extracted tree). /var/tmp is
# disk-backed; the default mktemp location is /tmp, which is tmpfs (RAM) on recent
# Ubuntu and OOMs the 1 GiB hosts u7s targets.
mktemp_disk_dir() {
  mktemp -d /var/tmp/u7s-install.XXXXXX
}

# Ed25519 release-signing public key (PEM). The matching private key lives only
# in the protected `release` GitHub Environment; the same key is published in
# README.md. PLACEHOLDER: empty until the operator generates the key, and the
# release workflow refuses to publish while it is empty.
RELEASE_PUBKEY_PEM="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQyJWAOZX5w4sMHM+w/dKPlR3rIHYzOPalQ2UXVJIK+8=
-----END PUBLIC KEY-----"

# Verify <sig> is a valid Ed25519 signature of <file> under RELEASE_PUBKEY_PEM.
# Exits non-zero with a message on any failure, including a missing or too-old
# openssl: no flag skips it for downloaded tarballs (a local --tarball is
# trusted as supplied and never reaches this function).
verify_release_signature() {
  local file="$1" sig="$2"
  if [ -z "$RELEASE_PUBKEY_PEM" ]; then
    echo "error: this install.sh has no release signing key embedded; refusing to install unverified binaries" >&2
    exit 1
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "error: openssl is required to verify the release signature but was not found (apt-get install openssl)" >&2
    exit 1
  fi
  local ver_line ver major
  ver_line="$(openssl version)"
  ver="$(printf '%s' "$ver_line" | cut -d' ' -f2)"
  major="${ver%%.*}"
  case "$major" in
    ''|*[!0-9]*) major=0 ;;
  esac
  if [ "${ver_line%% *}" != "OpenSSL" ] || [ "$major" -lt 3 ]; then
    echo "error: OpenSSL >= 3.0 is required to verify the Ed25519 release signature (found: $ver_line)" >&2
    exit 1
  fi
  local keydir
  keydir="$(mktemp_disk_dir)"
  printf '%s\n' "$RELEASE_PUBKEY_PEM" > "$keydir/pub.pem"
  if ! openssl pkeyutl -verify -pubin -inkey "$keydir/pub.pem" -rawin -in "$file" -sigfile "$sig" >/dev/null 2>&1; then
    rm -rf "$keydir"
    echo "error: release signature verification FAILED for $(basename "$file") -- refusing to install" >&2
    exit 1
  fi
  rm -rf "$keydir"
}

# Download the release tarball, its .sha256 sidecar and their Ed25519
# signatures, verify both signatures, then the sidecar's
# hash against the downloaded bytes, and point $TARBALL at it. The caller
# sets the EXIT trap that removes $DOWNLOAD_DIR. A sidecar fetch failure
# (including a 404, e.g. a pre-checksum release) fails the same as any other
# curl error here: unverified bytes reaching `tar -xzf` become binaries run
# as root, so a URL-based fetch always requires a passing checksum.
# --proto allows file:// only for local tarballs (release-gate bakes one); redirects must stay https.
fetch_tarball() {
  local url="$1"
  DOWNLOAD_DIR="$(mktemp_disk_dir)"
  TARBALL="$DOWNLOAD_DIR/$(basename "$url")"
  local checksum_url="$url.sha256"
  local checksum_file="$TARBALL.sha256"

  echo "Downloading release tarball from $url..."
  curl --proto '=https,file' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --retry-connrefused -o "$TARBALL" "$url"

  echo "Downloading checksum sidecar from $checksum_url..."
  curl --proto '=https,file' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --retry-connrefused -o "$checksum_file" "$checksum_url"

  echo "Downloading signatures..."
  curl --proto '=https,file' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --retry-connrefused -o "$TARBALL.sig" "$url.sig"
  curl --proto '=https,file' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --retry-connrefused -o "$checksum_file.sig" "$checksum_url.sig"
  verify_release_signature "$TARBALL" "$TARBALL.sig"
  verify_release_signature "$checksum_file" "$checksum_file.sig"

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

# Fetch an apt repo signing key from <url>, require it to be exactly one
# primary key whose fingerprint equals <expected_fpr>, and only then dearmor it
# into <keyring>. The key comes from the same host that serves the packages, so
# without the pin a compromised mirror ships a matching key and packages. A
# second key in the file is rejected too: signed-by would trust it.
install_apt_key() {
  local url="$1" expected="$2" keyring="$3"
  local keyfile fprs
  keyfile="$(mktemp)"
  if ! curl --proto '=https' --tlsv1.2 -fsSL -o "$keyfile" "$url"; then
    rm -f "$keyfile"
    echo "error: could not fetch apt key from $url" >&2
    return 1
  fi
  fprs="$(gpg --batch --show-keys --with-colons "$keyfile" | awk -F: '/^pub:/{p=1} /^fpr:/&&p{print $10; p=0}')"
  if [ "$fprs" != "$expected" ]; then
    rm -f "$keyfile"
    echo "error: apt key from $url has unexpected fingerprint(s)" >&2
    echo "       expected: $expected" >&2
    echo "       actual:   ${fprs:-<none>}" >&2
    echo "       If the vendor rotated its key, verify the new fingerprint out of band and update the pin in install.sh." >&2
    return 1
  fi
  gpg --batch --yes --dearmor -o "$keyring" < "$keyfile"
  rm -f "$keyfile"
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

# --- Network ranges: one source of truth -------------------------------------
#
# $SERVICE_CIDR, $POD_CLUSTER_CIDR and $CLUSTER_DNS feed every consumer: the
# apiserver (--service-cluster-ip-range, --kube-dns-cluster-ip; it derives the
# kubernetes Service VIP and the ServiceCIDR object from them), KCM
# (--cluster-cidr, --service-cluster-ip-range), kubelet clusterDNS, and the
# rendered flannel / kube-proxy / beep / CoreDNS manifests.

# Dotted-quad IPv4 -> integer; fails (no output) on anything else.
ipv4_to_int() {
  local re='^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$' i
  [[ "$1" =~ $re ]] || return 1
  for i in 1 2 3 4; do
    [ "${BASH_REMATCH[$i]}" -le 255 ] || return 1
  done
  echo $(( (BASH_REMATCH[1] << 24) | (BASH_REMATCH[2] << 16) | (BASH_REMATCH[3] << 8) | BASH_REMATCH[4] ))
}

int_to_ipv4() {
  echo "$(( $1 >> 24 & 255 )).$(( $1 >> 16 & 255 )).$(( $1 >> 8 & 255 )).$(( $1 & 255 ))"
}

# IPv6 address -> 32 lowercase hex digits; fails (no output) on anything else
# (zone IDs and embedded IPv4 forms are not accepted).
ip6_to_hex() {
  local a="$1" left right g out="" i nz
  local -a L R
  [[ "$a" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
  case "$a" in *:::*) return 1 ;; esac
  L=(); R=()
  if [[ "$a" == *::* ]]; then
    left="${a%%::*}"; right="${a#*::}"
    case "$right" in *::*) return 1 ;; esac
    IFS=: read -ra L <<< "$left"
    IFS=: read -ra R <<< "$right"
    nz=$(( 8 - ${#L[@]} - ${#R[@]} ))
    [ "$nz" -ge 1 ] || return 1
  else
    IFS=: read -ra L <<< "$a"
    [ "${#L[@]}" -eq 8 ] || return 1
    nz=0
  fi
  for (( i = 0; i < ${#L[@]}; i++ )); do
    g="${L[i]}"; [[ "$g" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    out+="$(printf '%04x' "$(( 16#$g ))")"
  done
  for (( i = 0; i < nz; i++ )); do out="${out}0000"; done
  for (( i = 0; i < ${#R[@]}; i++ )); do
    g="${R[i]}"; [[ "$g" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    out+="$(printf '%04x' "$(( 16#$g ))")"
  done
  echo "$out"
}

# 32 hex digits -> RFC 5952 text (longest zero run of 2+ groups compressed).
ip6_hex_to_str() {
  local h="$1" i s="" best_start=-1 best_len=0 cur_start=-1 cur_len=0
  local -a G
  for (( i = 0; i < 8; i++ )); do
    G[i]="$(printf '%x' "$(( 16#${h:i*4:4} ))")"
    if [ "${G[i]}" = 0 ]; then
      [ "$cur_start" -ge 0 ] || { cur_start=$i; cur_len=0; }
      cur_len=$(( cur_len + 1 ))
      if [ "$cur_len" -gt "$best_len" ]; then best_start=$cur_start; best_len=$cur_len; fi
    else
      cur_start=-1; cur_len=0
    fi
  done
  [ "$best_len" -ge 2 ] || best_start=-1
  i=0
  while [ "$i" -lt 8 ]; do
    if [ "$i" -eq "$best_start" ]; then s+="::"; i=$(( i + best_len )); continue; fi
    case "$s" in ""|*:) ;; *) s+=: ;; esac
    s+="${G[i]}"; i=$(( i + 1 ))
  done
  echo "$s"
}

# Keeps the first <bits> bits of the 32-digit hex address, zeroing the rest.
ip6_mask_hex() {
  local h="$1" bits="$2" q r out n
  q=$(( bits / 4 )); r=$(( bits % 4 ))
  out="${h:0:q}"
  if [ "$q" -lt 32 ]; then
    n=$(( 16#${h:q:1} & ((15 << (4 - r)) & 15) ))
    out+="$(printf '%x' "$n")"
  fi
  while [ "${#out}" -lt 32 ]; do out="${out}0"; done
  echo "${out:0:32}"
}

# True when two 32-digit hex addresses agree on their first <bits> bits.
ip6_prefix_equal() {
  [ "$(ip6_mask_hex "$1" "$3")" = "$(ip6_mask_hex "$2" "$3")" ]
}

# Adds a small <n> to the low 32 bits.
ip6_add_hex() {
  printf '%s%08x\n' "${1:0:24}" "$(( 16#${1:24:8} + $2 ))"
}

# Parses <cidr> (flag <label>), IPv4 or IPv6 by its address, requiring the
# canonical network address and a prefix in [min4,max4] / [min6,max6]. Sets
# CIDR_FAMILY (4|6), CIDR_PREFIX and CIDR_START/CIDR_END (IPv4 integers) or
# CIDR_HEX (IPv6 network).
parse_cidr() {
  local label="$1" cidr="$2" min4="$3" max4="$4" min6="$5" max6="$6" addr prefix start size hex net min max
  case "$cidr" in */*) ;; *) echo "error: $label '$cidr' is not a CIDR (expected a.b.c.d/n or an IPv6 address/n)" >&2; return 1 ;; esac
  addr="${cidr%/*}"; prefix="${cidr#*/}"
  if [[ "$addr" == *:* ]]; then
    CIDR_FAMILY=6; min=$min6; max=$max6
    if ! hex="$(ip6_to_hex "$addr")" || ! [[ "$prefix" =~ ^(0|[1-9][0-9]{0,2})$ ]]; then
      echo "error: $label '$cidr' is not a valid IPv6 CIDR" >&2; return 1
    fi
  else
    CIDR_FAMILY=4; min=$min4; max=$max4
    if ! start="$(ipv4_to_int "$addr")" || ! [[ "$prefix" =~ ^(0|[1-9][0-9]?)$ ]]; then
      echo "error: $label '$cidr' is not a valid IPv4 CIDR" >&2; return 1
    fi
  fi
  if [ "$prefix" -lt "$min" ] || [ "$prefix" -gt "$max" ]; then
    echo "error: $label '$cidr' has prefix /$prefix; it must be between /$min and /$max" >&2; return 1
  fi
  if [ "$CIDR_FAMILY" = 6 ]; then
    net="$(ip6_mask_hex "$hex" "$prefix")"
    if [ "$net" != "$hex" ]; then
      echo "error: $label '$cidr' has host bits set; the network address is $(ip6_hex_to_str "$net")/$prefix" >&2; return 1
    fi
    CIDR_HEX=$net
  else
    size=$(( 1 << (32 - prefix) ))
    if [ $(( start & (size - 1) )) -ne 0 ]; then
      echo "error: $label '$cidr' has host bits set; the network address is $(int_to_ipv4 $(( start & ~(size - 1) )))/$prefix" >&2; return 1
    fi
    CIDR_START=$start
    CIDR_END=$(( start + size - 1 ))
  fi
  CIDR_PREFIX=$prefix
}

# Parses a --service-cidr / --cluster-cidr value: one CIDR, or two of
# different IP families (upstream's dual-stack rule), the first being the
# primary. Sets CIDR_LIST_V4 / CIDR_LIST_V6 to the entry of each family ("" if absent).
parse_cidr_list() {
  local label="$1" list="$2" min4="$3" max4="$4" min6="$5" max6="$6" commas e first_family="" idx=0
  commas="${list//[^,]/}"
  CIDR_LIST_V4=""; CIDR_LIST_V6=""
  if [ "${#commas}" -gt 1 ]; then
    echo "error: $label '$list' must not contain more than two entries" >&2; return 1
  fi
  if [ -z "$commas" ]; then
    parse_cidr "$label" "$list" "$min4" "$max4" "$min6" "$max6" || return 1
    if [ "$CIDR_FAMILY" = 4 ]; then CIDR_LIST_V4="$list"; else CIDR_LIST_V6="$list"; fi
    return 0
  fi
  for e in "${list%%,*}" "${list#*,}"; do
    parse_cidr "${label}[$idx]" "$e" "$min4" "$max4" "$min6" "$max6" || return 1
    if [ "$first_family" = "$CIDR_FAMILY" ]; then
      echo "error: ${label}[0] and ${label}[1] must be of different IP family" >&2; return 1
    fi
    first_family="$CIDR_FAMILY"; idx=1
    if [ "$CIDR_FAMILY" = 4 ]; then CIDR_LIST_V4="$e"; else CIDR_LIST_V6="$e"; fi
  done
}

# True when two CIDRs of the same family share an address.
cidrs_overlap() {
  local s e p h
  parse_cidr range "$1" 0 32 0 128 || return 1
  s=${CIDR_START:-0}; e=${CIDR_END:-0}; p=$CIDR_PREFIX; h=${CIDR_HEX:-}
  parse_cidr range "$2" 0 32 0 128 || return 1
  if [ "$CIDR_FAMILY" = 4 ]; then
    [ "$s" -le "$CIDR_END" ] && [ "$CIDR_START" -le "$e" ]
  else
    [ "$CIDR_PREFIX" -gt "$p" ] || p=$CIDR_PREFIX
    ip6_prefix_equal "$h" "$CIDR_HEX" "$p"
  fi
}

# kubeadm's convention (and the apiserver's default): kube-dns is the tenth
# host of the first service range, in that range's family.
default_cluster_dns() {
  parse_cidr --service-cidr "${1%%,*}" 1 28 1 124 || return 1
  if [ "$CIDR_FAMILY" = 4 ]; then
    int_to_ipv4 $(( CIDR_START + 10 ))
  else
    ip6_hex_to_str "$(ip6_add_hex "$CIDR_HEX" 10)"
  fi
}

# Fails loud on a combination no consumer can serve. $1=1 on a worker, which
# runs only kubelet and so only consumes the DNS address (the ranges are the
# control plane's). Sets SERVICE_CIDR_IPV4/_IPV6 and POD_CLUSTER_CIDR_IPV4/_IPV6
# (the entry of each family, "" if absent) for the manifest placeholders.
validate_network_config() {
  local worker="$1" dns dns_hex dns_family svc
  if dns="$(ipv4_to_int "$CLUSTER_DNS")"; then
    dns_family=4
  elif dns_hex="$(ip6_to_hex "$CLUSTER_DNS")"; then
    dns_family=6
  else
    echo "error: --cluster-dns '$CLUSTER_DNS' is not a valid IPv4 or IPv6 address" >&2; return 1
  fi
  [ "$worker" -eq 1 ] && return 0
  # Upstream 1.37 and the u7s apiserver bound no range size. /28 and /124 leave
  # room for the kubernetes (first) and kube-dns (tenth) VIPs; /0 would span
  # the whole address space and always overlap the node and pod networks.
  parse_cidr_list --service-cidr "$SERVICE_CIDR" 1 28 1 124 || return 1
  SERVICE_CIDR_IPV4="$CIDR_LIST_V4"; SERVICE_CIDR_IPV6="$CIDR_LIST_V6"
  # The per-node masks (/24 IPv4, /64 IPv6) are KCM's; its limit is a 16-bit
  # gap between them and the cluster range.
  parse_cidr_list --cluster-cidr "$POD_CLUSTER_CIDR" 8 24 48 64 || return 1
  POD_CLUSTER_CIDR_IPV4="$CIDR_LIST_V4"; POD_CLUSTER_CIDR_IPV6="$CIDR_LIST_V6"
  if [ -n "$SERVICE_CIDR_IPV4" ] && [ -n "$POD_CLUSTER_CIDR_IPV4" ] && cidrs_overlap "$SERVICE_CIDR_IPV4" "$POD_CLUSTER_CIDR_IPV4"; then
    echo "error: --service-cidr $SERVICE_CIDR_IPV4 and --cluster-cidr $POD_CLUSTER_CIDR_IPV4 overlap; Service VIPs and pod IPs would collide" >&2; return 1
  fi
  if [ -n "$SERVICE_CIDR_IPV6" ] && [ -n "$POD_CLUSTER_CIDR_IPV6" ] && cidrs_overlap "$SERVICE_CIDR_IPV6" "$POD_CLUSTER_CIDR_IPV6"; then
    echo "error: --service-cidr $SERVICE_CIDR_IPV6 and --cluster-cidr $POD_CLUSTER_CIDR_IPV6 overlap; Service VIPs and pod IPs would collide" >&2; return 1
  fi
  if [ "$dns_family" = 4 ]; then svc="$SERVICE_CIDR_IPV4"; else svc="$SERVICE_CIDR_IPV6"; fi
  if [ -z "$svc" ]; then
    echo "error: --cluster-dns $CLUSTER_DNS is an IPv$dns_family address but --service-cidr $SERVICE_CIDR has no IPv$dns_family range" >&2; return 1
  fi
  parse_cidr --service-cidr "$svc" 1 28 1 124 || return 1
  if [ "$dns_family" = 4 ]; then
    if [ "$dns" -le "$CIDR_START" ] || [ "$dns" -ge "$CIDR_END" ] || [ "$dns" -eq $(( CIDR_START + 1 )) ]; then
      echo "error: --cluster-dns $CLUSTER_DNS is not an allocatable host of --service-cidr $svc (network, broadcast and the kubernetes Service VIP $(int_to_ipv4 $(( CIDR_START + 1 ))) are excluded)" >&2; return 1
    fi
  else
    # IPv6 has no broadcast address: the all-ones host is allocatable.
    if ! ip6_prefix_equal "$dns_hex" "$CIDR_HEX" "$CIDR_PREFIX" || [ "$dns_hex" = "$CIDR_HEX" ] || [ "$dns_hex" = "$(ip6_add_hex "$CIDR_HEX" 1)" ]; then
      echo "error: --cluster-dns $CLUSTER_DNS is not an allocatable host of --service-cidr $svc (network and the kubernetes Service VIP $(ip6_hex_to_str "$(ip6_add_hex "$CIDR_HEX" 1)") are excluded)" >&2; return 1
    fi
  fi
}

# Resolves flag variable <var> against what the first install persisted:
# unset keeps the persisted value (or the default for an install that
# predates persistence, which always ran the defaults); an explicit value that
# disagrees on an existing install refuses, because Services, pods and every
# node's kubelet already hold addresses from the old range.
reconcile_network_flag() {
  local flag="$1" var="$2" persisted="$3" default="$4" given effective
  given="${!var}"
  effective="$default"
  if [ "$EXISTING_INSTALL" -eq 1 ] && [ -n "$persisted" ]; then
    effective="$persisted"
  fi
  if [ "$EXISTING_INSTALL" -eq 1 ] && [ -n "$given" ] && [ "$given" != "$effective" ]; then
    if [[ "$effective" != *,* && "$given" == *,* ]]; then
      echo "error: $flag $given requests dual-stack, but this cluster was installed single-stack ($effective, recorded in $CONFIG_FILE). Converting an existing single-stack cluster to dual-stack in place is not supported yet. To get dual-stack now, start over: stop the u7s services, rm -rf $STATE_DIR, and re-run install.sh with the dual-stack flags; otherwise re-run without changing $flag." >&2
      return 1
    fi
    echo "error: $flag $given conflicts with the value in effect since install time ($effective, recorded in $CONFIG_FILE). Existing Services, pods and kubelets already use it; changing it would strand them. To change it, start over: stop the u7s services, rm -rf $STATE_DIR, and re-run install.sh." >&2
    return 1
  fi
  printf -v "$var" '%s' "${given:-$effective}"
}

# Fails when $IFACE_IP (arg 1) sits inside either range: the node's own address
# would be unreachable behind Service/pod routing.
check_node_ip_outside_ranges() {
  local ip hex family range inside
  if ip="$(ipv4_to_int "$1")"; then family=4; elif hex="$(ip6_to_hex "$1")"; then family=6; else return 0; fi
  for range in ${SERVICE_CIDR//,/ } ${POD_CLUSTER_CIDR//,/ }; do
    parse_cidr range "$range" 0 32 0 128 || return 1
    [ "$CIDR_FAMILY" = "$family" ] || continue
    inside=0
    if [ "$family" = 4 ]; then
      if [ "$ip" -ge "$CIDR_START" ] && [ "$ip" -le "$CIDR_END" ]; then inside=1; fi
    elif ip6_prefix_equal "$hex" "$CIDR_HEX" "$CIDR_PREFIX"; then
      inside=1
    fi
    if [ "$inside" -eq 1 ]; then
      echo "error: node address $1 is inside $range; choose --service-cidr/--cluster-cidr ranges that exclude the host network" >&2; return 1
    fi
  done
}

# KCM's per-node CIDR mask flags for $POD_CLUSTER_CIDR. Upstream rejects
# --node-cidr-mask-size with two cluster CIDRs and wants one flag per family
# (kube-controller-manager app/core.go); defaults are /24 IPv4, /64 IPv6.
kcm_node_cidr_mask_flags() {
  case "$POD_CLUSTER_CIDR" in
    *,*) echo "--node-cidr-mask-size-ipv4=24 --node-cidr-mask-size-ipv6=64" ;;
    *:*) echo "--node-cidr-mask-size=64" ;;
    *) echo "--node-cidr-mask-size=24" ;;
  esac
}

# Writes the install-time placeholders into the vendored manifests in $1.
# __POD_CLUSTER_CIDR__ is the primary (first) pod CIDR, so a manifest that
# predates dual-stack keeps a valid single-family value; the full list and
# each family are __POD_CLUSTER_CIDRS__, __POD_CLUSTER_CIDR_IPV4__ and
# __POD_CLUSTER_CIDR_IPV6__ (likewise __SERVICE_CIDRS__, __SERVICE_CIDR_IPV4__,
# __SERVICE_CIDR_IPV6__); an absent family renders empty. Single-stack IPv4
# renders __POD_CLUSTER_CIDR__ exactly as before.
# CoreDNS ships its default VIP literally (the dev rigs apply the file as-is),
# so its clusterIP line is rewritten and then verified.
render_vendored_manifests() {
  local dir="$1"
  local -a cidr_sed=(
    -e "s#__POD_CLUSTER_CIDR__#${POD_CLUSTER_CIDR%%,*}#g"
    -e "s#__POD_CLUSTER_CIDRS__#$POD_CLUSTER_CIDR#g"
    -e "s#__POD_CLUSTER_CIDR_IPV4__#$POD_CLUSTER_CIDR_IPV4#g"
    -e "s#__POD_CLUSTER_CIDR_IPV6__#$POD_CLUSTER_CIDR_IPV6#g"
    -e "s#__SERVICE_CIDRS__#$SERVICE_CIDR#g"
    -e "s#__SERVICE_CIDR_IPV4__#$SERVICE_CIDR_IPV4#g"
    -e "s#__SERVICE_CIDR_IPV6__#$SERVICE_CIDR_IPV6#g"
  )
  if [ -f "$dir/flannel.yaml" ]; then
    # sed -e ... > tmp && mv, not -i: -i's flag shape differs between GNU and
    # BSD sed, and this redirect-and-replace form works identically on both.
    sed -e "s/__IFACE__/$IFACE/g" "${cidr_sed[@]}" \
      "$dir/flannel.yaml" > "$dir/flannel.yaml.tmp"
    mv "$dir/flannel.yaml.tmp" "$dir/flannel.yaml"
  fi
  if [ -f "$dir/kube-proxy.yaml" ]; then
    sed -e "s/__KUBE_VERSION__/$KUBE_VERSION/g" -e "s#__IFACE_IP__#$IFACE_IP#g" "${cidr_sed[@]}" \
      "$dir/kube-proxy.yaml" > "$dir/kube-proxy.yaml.tmp"
    mv "$dir/kube-proxy.yaml.tmp" "$dir/kube-proxy.yaml"
  fi
  if [ -f "$dir/beep.yaml" ]; then
    sed -e "s/__IFACE__/$IFACE/g" "${cidr_sed[@]}" \
      "$dir/beep.yaml" > "$dir/beep.yaml.tmp"
    mv "$dir/beep.yaml.tmp" "$dir/beep.yaml"
  fi
  if [ -f "$dir/coredns.yaml" ]; then
    sed -e "s#^  clusterIP: 10\.96\.0\.10\$#  clusterIP: $CLUSTER_DNS#" \
      "$dir/coredns.yaml" > "$dir/coredns.yaml.tmp"
    mv "$dir/coredns.yaml.tmp" "$dir/coredns.yaml"
    if ! grep -qx "  clusterIP: $CLUSTER_DNS" "$dir/coredns.yaml"; then
      echo "error: $dir/coredns.yaml has no 'clusterIP' line to set to $CLUSTER_DNS (manifest shape changed?)" >&2
      return 1
    fi
  fi
}

# Minimal KubeletConfiguration: CRI-O's socket, cluster DNS from
# --cluster-dns (default: the tenth host of the service range), and four
# settings that are not obvious:
#
# resolvConf -- chosen as kubeadm does: when systemd-resolved is active,
# /run/systemd/resolve/resolv.conf (the real upstreams), because
# /etc/resolv.conf is the 127.0.0.53 stub, unreachable from a pod netns;
# otherwise /etc/resolv.conf. "" is wrong: dnsPolicy Default pods (CoreDNS)
# then get nameserver 127.0.0.1 and CoreDNS forwards to itself.
#
# serverTLSBootstrap -- the kubelet files its own kubelet-serving CSR once its
# Node exists, and the apiserver's approver checks the SANs against that Node.
# Without a CA-signed serving cert kubelet self-signs and the apiserver's
# kubelet-client rejects it, breaking kubectl logs/exec. kubelet rotates the
# cert itself before expiry. No tlsCertFile: a static file is never renewed.
#
# clientCAFile -- lets kubelet authenticate the apiserver's own client cert
# rather than treating proxied requests as anonymous, which its container-log
# and exec endpoints answer with a bare 401.
#
# rotateCertificates -- kubelet self-renews its client cert over the same CSR
# path; the selfnodeclient RBAC grant it needs is already seeded.
#
# The rotated client cert's on-disk location is NOT set here: certDir is not
# a KubeletConfiguration field (kubelet silently ignores it), only the
# --cert-dir CLI flag on kubelet.service's ExecStart -- see the flag there
# for why it must live under $STATE_DIR.
write_kubelet_config_yaml() {
  local worker="${1:-0}" resolv_conf=/etc/resolv.conf
  if systemctl is-active --quiet systemd-resolved; then
    resolv_conf=/run/systemd/resolve/resolv.conf
  fi
  # ca-bundle.pem (every CA the apiserver trusts) on the control plane; the joined
  # bundle on a worker. The kubelet re-reads clientCAFile on change.
  local client_ca="$STATE_DIR/ca-bundle.pem"
  if [ "$worker" -eq 1 ]; then
    client_ca="$STATE_DIR/ca.pem"
  fi
  cat > "$STATE_DIR/kubelet-config.yaml" <<EOF
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
containerRuntimeEndpoint: unix:///var/run/crio/crio.sock
registerNode: true
failSwapOn: false
resolvConf: $resolv_conf
staticPodPath: /etc/u7s/static-pods
clusterDNS:
  - $CLUSTER_DNS
clusterDomain: cluster.local
serverTLSBootstrap: true
authentication:
  x509:
    clientCAFile: $client_ca
rotateCertificates: true
EOF
}

# --mint-join-token: run on a control-plane node. Creates a
# kube-system/bootstrap-token-<id> Secret through the live apiserver (no
# restart) and prints the full join command. The token authenticates as
# system:bootstrap:<id> in group system:bootstrappers, which the seeded RBAC
# allows to submit exactly the kubelet client CSR that KCM auto-approves.
# Single-use: the apiserver deletes the Secret when that CSR's certificate is
# issued; the 24h expiry (reaped by KCM's tokencleaner) is only the backstop
# for a token that was never used. A join that fails after the certificate was
# issued needs a fresh --mint-join-token.
JOIN_TOKEN_TTL_SECONDS=86400

mint_join_token() {
  if [ ! -f "$STATE_DIR/ca.pem" ] || [ ! -f "$STATE_DIR/kubeconfig" ]; then
    echo "error: $STATE_DIR/ca.pem or kubeconfig not found -- run install.sh's default single-node bootstrap on this control-plane node first" >&2
    exit 1
  fi
  ensure_jq

  local token_id token_secret expiration
  token_id="$(openssl rand -hex 3)"
  token_secret="$(openssl rand -hex 8)"
  expiration="$(date -u -d "@$(( $(date +%s) + JOIN_TOKEN_TTL_SECONDS ))" +%Y-%m-%dT%H:%M:%SZ)"

  # The Secret goes to kubectl on stdin: the token secret never appears on argv.
  jq -n -c \
    --arg id "$token_id" --arg secret "$token_secret" --arg expiration "$expiration" \
    '{apiVersion: "v1", kind: "Secret",
      metadata: {name: ("bootstrap-token-" + $id), namespace: "kube-system"},
      type: "bootstrap.kubernetes.io/token",
      stringData: {"token-id": $id, "token-secret": $secret, expiration: $expiration,
                   "usage-bootstrap-authentication": "true", "usage-bootstrap-signing": "true",
                   description: "u7s join token (single-use)"}}' \
    | kubectl --kubeconfig="$STATE_DIR/kubeconfig" create -f - >/dev/null

  local ca_hash server
  ca_hash="$(openssl x509 -in "$STATE_DIR/ca.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 | sed 's/^.* //')"
  server="$(kubectl --kubeconfig="$STATE_DIR/kubeconfig" config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

  echo "Join token created in kube-system, expires $expiration (single-use): ${token_id}.${token_secret}"
  echo "On the joining node, run as root. The command carries no token, so it stays out of shell"
  echo "history; install.sh prompts for the token with echo off (or reads it from piped stdin):"
  echo "  install.sh --join $server \\"
  local dns_flag="" persisted_dns
  # shellcheck disable=SC1090
  persisted_dns="$([ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE" && printf '%s' "${CLUSTER_DNS:-}" || true)"
  if [ -n "$persisted_dns" ] && [ "$persisted_dns" != "$(default_cluster_dns "$DEFAULT_SERVICE_CIDR")" ]; then
    dns_flag=" --cluster-dns $persisted_dns"
  fi
  echo "    --ca-cert-hash sha256:$ca_hash --tarball <path> --node-name <name> [--iface <iface>]$dns_flag"
}

# base64url without padding, from stdin.
b64url() {
  base64 -w0 | tr '+/' '-_' | tr -d '='
}

# Emits $1 (hex key, already zero-padded to the 64-byte SHA-256 block) XOR the
# byte $2 as raw bytes on stdout. Streamed, never held in a shell variable, as
# the result can contain NUL bytes.
hmac_pad() {
  local key_hex="$1" xor="$2" i
  for i in $(seq 0 63); do
    printf "\\x$(printf '%02x' $(( 16#${key_hex:$((i * 2)):2} ^ xor )))"
  done
}

# HMAC-SHA256 (raw bytes on stdout) of the file $2 under the ASCII key $1.
# openssl's own -hmac takes the key on argv, which would expose the token
# secret in ps.
hmac_sha256() {
  local key_hex
  key_hex="$(printf '%s' "$1" | od -An -tx1 | tr -d ' \n')"
  while [ "${#key_hex}" -lt 128 ]; do key_hex="${key_hex}00"; done
  {
    hmac_pad "$key_hex" $(( 0x5c ))
    { hmac_pad "$key_hex" $(( 0x36 )); cat "$2"; } | openssl dgst -sha256 -binary
  } | openssl dgst -sha256 -binary
}

# kubeadm-style discovery: fetch the anonymous kube-public/cluster-info over an
# unverified connection, require the bootstrapsigner's detached HS256 JWS for
# this token's id to verify under the token secret, then pin the CA it carries
# to --ca-cert-hash (sha256 of the CA's SPKI). Writes the CA to $STATE_DIR/ca.pem.
discover_cluster_ca() {
  local token_id="$1" token_secret="$2"
  local work info jws=""
  work="$(mktemp -d)"
  info="$work/info.json"
  # KCM's bootstrapsigner signs a new token's JWS asynchronously after the mint.
  for _ in $(seq 1 30); do
    curl --proto '=https' --tlsv1.2 -fsSk "$JOIN_SERVER/api/v1/namespaces/kube-public/configmaps/cluster-info" > "$info" 2>/dev/null || true
    jws="$(jq -r --arg k "jws-kubeconfig-$token_id" '.data[$k] // empty' "$info" 2>/dev/null || true)"
    [ -n "$jws" ] && break
    sleep 2
  done
  if [ -z "$jws" ]; then
    rm -rf "$work"
    echo "error: kube-public/cluster-info at $JOIN_SERVER carries no signature for token id '$token_id' (token unknown, expired or already used? check that kube-controller-manager's bootstrap-signer-controller is running)" >&2
    exit 1
  fi

  # -j: the signed content is the exact string, trailing newline included.
  jq -j '.data.kubeconfig' "$info" > "$work/kubeconfig.yaml"
  printf '%s.%s' "${jws%%.*}" "$(b64url < "$work/kubeconfig.yaml")" > "$work/signing-input"
  local expected actual
  actual="${jws##*.}"
  expected="$(hmac_sha256 "$token_secret" "$work/signing-input" | b64url)"
  if [ "$expected" != "$actual" ]; then
    rm -rf "$work"
    echo "error: cluster-info signature does not verify under this token -- refusing to trust $JOIN_SERVER (wrong token, or the endpoint is not the cluster that minted it)" >&2
    exit 1
  fi

  # The CA data is a bundle (several CERTIFICATE blocks while a CA is being succeeded):
  # the pin must match one of its certs, and the whole bundle is then trusted.
  local ca_pem pinned=0 hashes=""
  ca_pem="$(sed -n 's/^ *certificate-authority-data: *//p' "$work/kubeconfig.yaml" | head -n1 | base64 -d)"
  rm -rf "$work"
  if ! printf '%s\n' "$ca_pem" | grep -q '^-----BEGIN CERTIFICATE-----$'; then
    echo "error: cluster-info carries no CA certificate -- refusing to join" >&2
    exit 1
  fi
  local pem_file cert_hash
  pem_file="$(mktemp)"
  printf '%s\n' "$ca_pem" | awk -v dir="$pem_file." '/-----BEGIN CERTIFICATE-----/{n++} n{print > (dir n)}'
  for f in "$pem_file".*; do
    cert_hash="sha256:$(openssl x509 -in "$f" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 | sed 's/^.* //')"
    hashes="$hashes $cert_hash"
    [ "$cert_hash" = "$CA_CERT_HASH" ] && pinned=1
  done
  rm -f "$pem_file" "$pem_file".*
  if [ "$pinned" -ne 1 ]; then
    echo "error: none of the cluster CA hashes ($hashes ) matches --ca-cert-hash $CA_CERT_HASH -- refusing to join" >&2
    exit 1
  fi
  printf '%s\n' "$ca_pem" > "$STATE_DIR/ca.pem"
}

# Reads the join token from the --token flag, or from stdin when the flag is
# absent or "-". Stdin keeps it out of argv, /proc/<pid>/cmdline and history.
read_join_token() {
  local token="$JOIN_TOKEN"
  if [ -z "$token" ] || [ "$token" = "-" ]; then
    if [ -t 0 ]; then
      read -rsp "Join token: " token
      echo >&2
    else
      read -r token || true
    fi
    if [ -z "$token" ]; then
      echo "error: no join token on stdin -- pipe it in (echo <token> | install.sh --join ...) or run on a terminal to be prompted" >&2
      exit 1
    fi
  fi
  if ! printf '%s' "$token" | grep -Eq '^[a-z0-9]{6}\.[a-z0-9]{16}$'; then
    echo "error: join token must look like <6 chars>.<16 chars> (as printed by --mint-join-token)" >&2
    exit 1
  fi
  printf '%s' "$token"
}

# --join: run on a fresh node. Verifies the cluster CA via cluster-info and the
# pinned hash, then builds a PKCS#10 CSR shaped exactly as upstream
# csrapproving's isNodeClientCert recognizer requires (CN=system:node:<name>,
# O=system:nodes, signerName kubernetes.io/kube-apiserver-client-kubelet,
# usages digital signature/key encipherment/client auth) and submits it under
# the bootstrap token. KCM auto-approves and signs it -- no manual step -- and
# the result becomes kubelet's own x509 identity, not a shared admin one. All
# private keys are generated here and never leave this node. The kubelet's
# serving cert is requested by the kubelet itself (serverTLSBootstrap) once its
# Node exists; wait_for_joined_node checks it was approved and issued.
join_cluster() {
  if [ -z "$CA_CERT_HASH" ]; then
    echo "error: --join requires --ca-cert-hash sha256:<hash> (printed by --mint-join-token)" >&2
    exit 1
  fi
  ensure_jq

  local bootstrap_token token_id token_secret
  bootstrap_token="$(read_join_token)"
  token_id="${bootstrap_token%%.*}"
  token_secret="${bootstrap_token##*.}"

  discover_cluster_ca "$token_id" "$token_secret"

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

  # The apiserver deletes the token when the certificate is issued, so the
  # wait is a watch opened beforehand: its authentication happened at connect,
  # whereas a later GET with the spent token would 401. The token reaches curl
  # as a config file on a pipe, never argv.
  local watch_out watch_pid
  watch_out="$(mktemp)"
  curl --proto '=https' --tlsv1.2 -fsSN --cacert "$STATE_DIR/ca.pem" \
    -K <(printf 'header = "Authorization: Bearer %s"\n' "$bootstrap_token") \
    "$JOIN_SERVER/apis/certificates.k8s.io/v1/certificatesigningrequests?watch=true&fieldSelector=metadata.name%3D$csr_name&timeoutSeconds=150" \
    > "$watch_out" 2>/dev/null &
  watch_pid=$!
  # Let the watch authenticate before the CSR is created.
  sleep 2

  echo "Submitting join CSR '$csr_name' to $JOIN_SERVER..."
  # The apiserver-stamped creationTimestamp of this join's client CSR is the
  # lower bound for the serving CSR wait_for_joined_node accepts: a serving CSR
  # issued to an earlier incarnation of the same node name is older than it.
  # It is the server's clock on both sides, so node clock skew cannot matter.
  JOIN_STARTED_AT="$(curl --proto '=https' --tlsv1.2 -fsSL --cacert "$STATE_DIR/ca.pem" \
    -K <(printf 'header = "Authorization: Bearer %s"\n' "$bootstrap_token") \
    -H "Content-Type: application/json" \
    -X POST "$JOIN_SERVER/apis/certificates.k8s.io/v1/certificatesigningrequests" \
    -d "$csr_body" | jq -r '.metadata.creationTimestamp // empty')"
  if [ -z "$JOIN_STARTED_AT" ]; then
    echo "error: the apiserver's reply to the join CSR carried no creationTimestamp" >&2
    exit 1
  fi

  # KCM's csrapproving/csrsigning controllers react to the create event; this
  # loop only waits on them, it approves nothing itself.
  echo "Waiting for kube-controller-manager to auto-approve and sign the CSR..."
  local signed_cert_b64=""
  for _ in $(seq 1 60); do
    signed_cert_b64="$(jq -r 'select(.object.status.certificate != null) | .object.status.certificate' "$watch_out" 2>/dev/null | head -n1 || true)"
    if [ -n "$signed_cert_b64" ]; then
      break
    fi
    sleep 2
  done
  kill "$watch_pid" 2>/dev/null || true
  rm -f "$watch_out"
  if [ -z "$signed_cert_b64" ]; then
    echo "error: CSR '$csr_name' was not approved+signed within 120s (check: kubectl get csr $csr_name, kube-controller-manager logs on the control-plane node). The join token is spent once a certificate was issued; mint a new one to retry." >&2
    exit 1
  fi
  printf '%s' "$signed_cert_b64" | base64 -d > "$STATE_DIR/kubelet-client.crt"

  # File paths, not -data: the kubelet re-reads them, so a re-issued client cert or CA
  # reaches it without a rewrite of this file.
  cat > "$STATE_DIR/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: $JOIN_SERVER
    certificate-authority: $STATE_DIR/ca.pem
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
    client-certificate: $STATE_DIR/kubelet-client.crt
    client-key: $STATE_DIR/kubelet-client.key
EOF
  chmod 600 "$STATE_DIR/kubeconfig"
  echo "Join CSR approved and signed -- kubelet's dedicated x509 kubeconfig written to $STATE_DIR/kubeconfig"
}

# Control-plane kubelet identity: system:node:<name> in system:nodes, issued the
# way join_cluster issues a worker's (kubelet-client CSR, signed by KCM), but
# submitted with the operator's admin kubeconfig since no bootstrap token is
# needed on the node that holds the CA. KCM's csrapproving controller approves
# it because the submitter, admin (system:masters), passes the node-client
# SubjectAccessReview. The admin kubeconfig never reaches the kubelet, so the
# Node authorizer and NodeRestriction bind it like any other node; kubelet then
# rotates the cert itself (rotateCertificates). This narrows the kubelet's
# network credential only: it runs as root beside admin.pem and ca.key, so it is
# not a filesystem boundary. Skipped while a valid cert chaining to the current
# CA exists, so a re-run never replaces the identity kubelet already rotated.
issue_cp_kubelet_identity() {
  local kubelet_kubeconfig="$STATE_DIR/kubelet-kubeconfig"
  local cert
  if [ -s "$kubelet_kubeconfig" ] && cert="$(current_client_cert)"; then
    echo "Control-plane kubelet identity present ($cert); not re-issuing."
    return 0
  fi

  ensure_jq
  local admin=(kubectl --kubeconfig="$STATE_DIR/kubeconfig")
  local server
  server="$("${admin[@]}" config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

  openssl ecparam -name prime256v1 -genkey -noout -out "$STATE_DIR/kubelet-client.key"
  chmod 600 "$STATE_DIR/kubelet-client.key"
  openssl req -new -key "$STATE_DIR/kubelet-client.key" \
    -subj "/O=system:nodes/CN=system:node:$NODE_NAME" \
    -out "$STATE_DIR/kubelet-client.csr"

  local csr_name
  csr_name="kubelet-${NODE_NAME}-$(date +%s)"
  jq -n -c \
    --arg name "$csr_name" \
    --arg request "$(base64 -w0 < "$STATE_DIR/kubelet-client.csr")" \
    '{apiVersion: "certificates.k8s.io/v1", kind: "CertificateSigningRequest",
      metadata: {name: $name},
      spec: {request: $request,
             signerName: "kubernetes.io/kube-apiserver-client-kubelet",
             usages: ["digital signature", "key encipherment", "client auth"]}}' \
    | "${admin[@]}" create -f - >/dev/null
  rm -f "$STATE_DIR/kubelet-client.csr"

  echo "Waiting for kube-controller-manager to auto-approve and sign CSR '$csr_name'..."
  local signed_cert_b64=""
  for _ in $(seq 1 60); do
    signed_cert_b64="$("${admin[@]}" get csr "$csr_name" -o jsonpath='{.status.certificate}' 2>/dev/null || true)"
    [ -n "$signed_cert_b64" ] && break
    sleep 2
  done
  if [ -z "$signed_cert_b64" ]; then
    echo "error: CSR '$csr_name' was not approved+signed within 120s (check: kubectl get csr $csr_name, journalctl -u u7s-kcm)" >&2
    exit 1
  fi
  printf '%s' "$signed_cert_b64" | base64 -d > "$STATE_DIR/kubelet-client.crt"

  cat > "$kubelet_kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: $server
    certificate-authority: $STATE_DIR/ca-bundle.pem
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
    client-certificate: $STATE_DIR/kubelet-client.crt
    client-key: $STATE_DIR/kubelet-client.key
EOF
  chmod 600 "$kubelet_kubeconfig"
  echo "Control-plane kubelet identity issued: system:node:$NODE_NAME ($kubelet_kubeconfig)"
}

# kubeadm's mark-control-plane phase labels the control-plane Node
# node-role.kubernetes.io/control-plane="". The kubelet cannot do it itself:
# NodeRestriction forbids a node setting node-role.* labels on its own Node,
# so the admin kubeconfig applies it once the Node has registered. --overwrite
# makes a re-run a no-op. Deliberately not applied: kubeadm's control-plane
# NoSchedule taint (u7s is single-node-first, so workloads must schedule here)
# and the exclude-from-external-load-balancers label (it would drop the only
# node from every LB).
label_control_plane_node() {
  local admin=(kubectl --kubeconfig="$STATE_DIR/kubeconfig") i err=""
  echo "Waiting up to 5 min for node $NODE_NAME to register, then labelling it control-plane..."
  for i in $(seq 1 150); do
    if err="$("${admin[@]}" label node "$NODE_NAME" --overwrite node-role.kubernetes.io/control-plane= 2>&1)"; then
      echo "Node $NODE_NAME labelled node-role.kubernetes.io/control-plane."
      return 0
    fi
    sleep 2
  done
  echo "error: could not label node $NODE_NAME node-role.kubernetes.io/control-plane within 5 min (last error: $err). Tooling that selects control-plane nodes by this label would find none; check 'kubectl get node $NODE_NAME' and journalctl -u kubelet." >&2
  return 1
}

# Control-plane success condition: the node is Ready and every workload this
# script itself ships (CLUSTER_WORKLOADS, "<ns>/<kind>/<name>" entries) is
# fully rolled out and all its selected pods are Ready, so a user's first apply
# does not compete with our own image pulls. All checks read structured fields
# via jsonpath; an error, NotFound or empty field is "not ready". Default
# timeout is 20 min: a fresh 10 GB pd-standard e2-micro measured 4-10 min to
# pull and start everything; 2x headroom. U7S_READY_TIMEOUT_SECONDS overrides
# it. The deadline is wall time ($SECONDS), checked before every kubectl call,
# so it overruns by at most one request timeout. Returns non-zero naming each
# unready item on timeout.
CLUSTER_WORKLOADS=""
READY_POLL_SECONDS=5
READY_PROGRESS_EVERY=6
READY_DEADLINE=0
ready_kubectl() {
  [ "$SECONDS" -lt "$READY_DEADLINE" ] || return 1
  kubectl --kubeconfig="$STATE_DIR/kubeconfig" --request-timeout=10s "$@" 2>/dev/null
}
# Ready iff generation is observed, every replica is updated/ready/available,
# the desired count is > 0, and the pods selected by the object's own
# spec.selector.matchLabels are exactly that many, all Ready, none Terminating.
workload_is_ready() {
  local ns="$1" kind="$2" name="$3" row
  local gen obs desired updated ready avail cond labels sel pods
  case "$kind" in
    deployment)
      row="$(ready_kubectl -n "$ns" get "$kind/$name" -o jsonpath='{.metadata.generation}|{.status.observedGeneration}|{.spec.replicas}|{.status.updatedReplicas}|{.status.readyReplicas}|{.status.availableReplicas}|{.status.conditions[?(@.type=="Available")].status}|{.spec.selector.matchLabels}')" || return 1
      IFS='|' read -r gen obs desired updated ready avail cond labels <<< "$row"
      [ "$cond" = True ] || return 1 ;;
    daemonset)
      row="$(ready_kubectl -n "$ns" get "$kind/$name" -o jsonpath='{.metadata.generation}|{.status.observedGeneration}|{.status.desiredNumberScheduled}|{.status.updatedNumberScheduled}|{.status.numberReady}|{.status.numberAvailable}|{.spec.selector.matchLabels}')" || return 1
      IFS='|' read -r gen obs desired updated ready avail labels <<< "$row" ;;
    *) return 1 ;;
  esac
  case "$gen$obs$desired" in ''|*[!0-9]*) return 1 ;; esac
  [ "$gen" = "$obs" ] && [ "$desired" -gt 0 ] || return 1
  [ "$updated" = "$desired" ] && [ "$ready" = "$desired" ] && [ "$avail" = "$desired" ] || return 1
  sel="$(printf '%s' "$labels" | sed -e 's/^{//' -e 's/}$//' -e 's/"//g' -e 's/:/=/g')"
  [ -n "$sel" ] || return 1
  pods="$(ready_kubectl -n "$ns" get pods -l "$sel" -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}')" || return 1
  [ -n "$pods" ] || return 1
  [ "$(printf '%s\n' "$pods" | wc -l | tr -d ' ')" = "$desired" ] || return 1
  [ "$(printf '%s\n' "$pods" | grep -cxF '|True')" = "$desired" ]
}
wait_for_cluster_ready() {
  local timeout="${U7S_READY_TIMEOUT_SECONDS:-1200}"
  case "$timeout" in
    ''|*[!0-9]*) echo "error: U7S_READY_TIMEOUT_SECONDS must be a whole number of seconds, got '$timeout'" >&2; return 1 ;;
  esac
  local start="$SECONDS" i=0 w ns kind name
  local pending="node/$NODE_NAME $CLUSTER_WORKLOADS"
  READY_DEADLINE=$(( start + timeout ))
  echo "Waiting up to ${timeout}s for node $NODE_NAME and ${CLUSTER_WORKLOADS:-no vendored workloads} to be Ready..."
  while [ "$SECONDS" -lt "$READY_DEADLINE" ]; do
    pending=""
    if [ "$(ready_kubectl get node "$NODE_NAME" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')" != "True" ]; then
      pending="node/$NODE_NAME"
    fi
    for w in $CLUSTER_WORKLOADS; do
      IFS=/ read -r ns kind name <<< "$w"
      if ! workload_is_ready "$ns" "$kind" "$name"; then
        pending="${pending:+$pending }$w"
      fi
    done
    if [ -z "$pending" ]; then
      echo "Node $NODE_NAME and all vendored workloads are Ready."
      return 0
    fi
    if [ $(( i % READY_PROGRESS_EVERY )) -eq 0 ]; then
      echo "  still waiting ($(( SECONDS - start ))s/${timeout}s): $pending"
    fi
    i=$(( i + 1 ))
    sleep "$READY_POLL_SECONDS"
  done
  echo "error: not Ready after ${timeout}s: $pending" >&2
  for w in $pending; do
    case "$w" in
      node/*) echo "  check: kubectl --kubeconfig=$STATE_DIR/kubeconfig describe node $NODE_NAME; journalctl -u kubelet" >&2 ;;
      *) IFS=/ read -r ns kind name <<< "$w"
         echo "  check: kubectl --kubeconfig=$STATE_DIR/kubeconfig -n $ns describe $kind/$name; kubectl --kubeconfig=$STATE_DIR/kubeconfig -n $ns get pods -o wide; df -h /var/lib (image pulls need disk)" >&2 ;;
    esac
  done
  return 1
}

# Success condition of a join, checked as the new node identity after kubelet
# started: the Node is Ready and the kubelet's own kubelet-serving CSR
# (serverTLSBootstrap) is Approved and Issued. The apiserver's approver only
# approves once the Node's addresses exist, so this can only be waited for
# after the kubelet registered -- never requested up front.
wait_for_joined_node() {
  local node_auth=(--cacert "$STATE_DIR/ca.pem" --cert "$STATE_DIR/kubelet-client.crt" --key "$STATE_DIR/kubelet-client.key")
  local ready="" serving="" resp
  echo "Waiting up to 5 min for node $NODE_NAME to be Ready with an issued kubelet serving certificate..."
  for _ in $(seq 1 150); do
    if [ -z "$ready" ]; then
      resp="$(curl --proto '=https' --tlsv1.2 -fsSL "${node_auth[@]}" "$JOIN_SERVER/api/v1/nodes/$NODE_NAME" 2>/dev/null || true)"
      ready="$(printf '%s' "$resp" | jq -r '.status.conditions[]? | select(.type == "Ready" and .status == "True") | .type' 2>/dev/null || true)"
    fi
    if [ -z "$serving" ]; then
      resp="$(curl --proto '=https' --tlsv1.2 -fsSL "${node_auth[@]}" "$JOIN_SERVER/apis/certificates.k8s.io/v1/certificatesigningrequests" 2>/dev/null || true)"
      # RFC3339 UTC timestamps compare correctly as strings.
      serving="$(printf '%s' "$resp" | jq -r --arg u "system:node:$NODE_NAME" --arg since "$JOIN_STARTED_AT" '[.items[]? | select(.spec.signerName == "kubernetes.io/kubelet-serving" and .spec.username == $u and .metadata.creationTimestamp >= $since and ((.status.certificate // "") != "") and any(.status.conditions[]?; .type == "Approved"))] | length' 2>/dev/null || true)"
      [ "${serving:-0}" -ge 1 ] 2>/dev/null || serving=""
    fi
    if [ -n "$ready" ] && [ -n "$serving" ]; then
      echo "Node $NODE_NAME is Ready and its kubelet serving certificate was approved and issued."
      return 0
    fi
    sleep 2
  done
  echo "error: after 5 min node $NODE_NAME Ready=$([ -n "$ready" ] && echo yes || echo no) and its kubelet serving CSR approved+issued=$([ -n "$serving" ] && echo yes || echo no). The join token is already consumed and this node holds a valid client identity; kubelet keeps retrying. Check 'journalctl -u kubelet' here and 'kubectl get csr' on the control plane (a Pending kubelet-serving CSR means the approver rejected its SANs against the Node's addresses; 'kubectl certificate describe' it, or approve it by hand). To start over: on the control plane 'kubectl delete node $NODE_NAME' and mint a new token (install.sh --mint-join-token); here 'systemctl stop kubelet; rm -rf $STATE_DIR' and re-run install.sh --join with the new token." >&2
  return 1
}

# --- Upgrade in place: an already-joined worker, and the control plane --------
#
# A joined worker's identity is, all under $STATE_DIR: kubeconfig (server URL
# and the join-time client cert), ca.pem, kubelet-client.crt/.key (written by
# join_cluster) and kubelet/pki/kubelet-client-current.pem (the kubelet's
# rotated client cert, from --cert-dir). It authenticates with its own client
# cert, so an upgrade needs no token.

# Prints the path of the newest client cert that is unexpired and chains to
# the current CA (ca-bundle.pem on the control plane, else ca.pem), rotated first.
current_client_cert() {
  local c ca="$STATE_DIR/ca.pem"
  [ -s "$STATE_DIR/ca-bundle.pem" ] && ca="$STATE_DIR/ca-bundle.pem"
  for c in "$STATE_DIR/kubelet/pki/kubelet-client-current.pem" "$STATE_DIR/kubelet-client.crt"; do
    if [ -s "$c" ] && openssl x509 -in "$c" -noout -checkend 0 >/dev/null 2>&1 \
      && openssl verify -CAfile "$ca" "$c" >/dev/null 2>&1; then
      printf '%s' "$c"
      return 0
    fi
  done
  return 1
}

# Refuses an upgrade the node cannot authenticate: a missing identity needs a
# join, an expired one (kubelet offline past its cert lifetime) needs a re-join.
verify_worker_identity() {
  local f missing="" checked="$STATE_DIR/kubelet-client.crt"
  for f in ca.pem kubelet-client.crt kubelet-client.key; do
    [ -s "$STATE_DIR/$f" ] || missing="$missing $STATE_DIR/$f"
  done
  [ -s "$STATE_DIR/kubelet/pki/kubelet-client-current.pem" ] && checked="$STATE_DIR/kubelet/pki/kubelet-client-current.pem"
  if [ -n "$missing" ]; then
    echo "error: this worker has no usable join identity (missing:$missing) -- a join is required. Mint a token on the control plane (install.sh --mint-join-token), then here: systemctl stop kubelet; rm -rf $STATE_DIR; re-run install.sh --join <url> --ca-cert-hash <hash> ..." >&2
    return 1
  fi
  if ! current_client_cert >/dev/null; then
    echo "error: this worker's kubelet client certificate has expired ($checked: notAfter $(openssl x509 -in "$checked" -noout -enddate | cut -d= -f2)) -- the node can no longer authenticate, so it must re-join with a fresh token. On the control plane: install.sh --mint-join-token (and 'kubectl delete node $NODE_NAME' if it is still registered). Here: systemctl stop kubelet; rm -rf $STATE_DIR (clears kubeconfig, kubelet-client.*, ca.pem and kubelet/pki); re-run install.sh --join <url> --ca-cert-hash <hash> ... with the new token." >&2
    return 1
  fi
}

# GET $1 on the API server named in the worker's kubeconfig, as the node.
worker_api_get() {
  local path="$1" cert key server
  shift
  cert="$(current_client_cert)" || return 1
  key="$STATE_DIR/kubelet-client.key"
  [ "$cert" = "$STATE_DIR/kubelet/pki/kubelet-client-current.pem" ] && key="$cert"
  server="$(sed -n 's/^ *server: *//p' "$STATE_DIR/kubeconfig" | head -n1)"
  curl --proto '=https' --tlsv1.2 -fsSL --cacert "$STATE_DIR/ca.pem" --cert "$cert" --key "$key" "$@" "$server$path"
}

# lastHeartbeatTime (epoch seconds) of the Node's Ready condition as served by
# the API server; empty when unreachable or absent. The kubelet stamps it with
# the worker's own clock, so it is only comparable with another reading of
# itself, never with a local or server timestamp. $1=any also accepts a
# Ready condition that is not True.
worker_ready_heartbeat() {
  worker_api_get "/api/v1/nodes/$NODE_NAME" 2>/dev/null \
    | jq -r --arg any "${1:-}" '.status.conditions[]? | select(.type == "Ready" and ($any != "" or .status == "True")) | .lastHeartbeatTime | fromdateiso8601' 2>/dev/null || true
}

client_cert_fingerprint() {
  local c
  c="$(current_client_cert)" || return 1
  openssl x509 -in "$c" -noout -fingerprint -sha256 | cut -d= -f2
}

# After the kubelet restart: the Node must report Ready with a heartbeat newer
# than $1 (the pre-restart reading of the same field, so a stale Ready cannot
# pass) and the client cert must still be valid. $2 is the pre-restart cert
# fingerprint.
wait_for_upgraded_worker() {
  local before="$1" fp_before="$2" hb="" fp_after
  echo "Waiting up to 5 min for node $NODE_NAME to report Ready again with its existing client identity..."
  for _ in $(seq 1 150); do
    hb="$(worker_ready_heartbeat)"
    [ -n "$hb" ] && [ "$hb" -gt "$before" ] && break
    hb=""
    sleep 2
  done
  if [ -z "$hb" ]; then
    echo "error: after 5 min node $NODE_NAME has not reported Ready since the kubelet restart (check: journalctl -u kubelet here, kubectl get node $NODE_NAME on the control plane). No token can fix a kubelet that fails to start; the client identity under $STATE_DIR was not modified." >&2
    return 1
  fi
  if ! fp_after="$(client_cert_fingerprint)"; then
    echo "error: node $NODE_NAME is Ready but no client certificate under $STATE_DIR is still valid" >&2
    return 1
  fi
  if [ "$fp_after" = "$fp_before" ]; then
    echo "Node $NODE_NAME is Ready; client certificate unchanged ($fp_after)."
  else
    echo "Node $NODE_NAME is Ready; kubelet rotated its client certificate ($fp_before -> $fp_after)."
  fi
}

# Control-plane upgrades keep the cluster identity: the apiserver only generates
# ca.* when absent. The restart below must leave both files byte-identical, or
# every node's identity is invalid. sa.key is excluded: the apiserver rotates it
# on its own schedule and keeps the previous key verifying until its tokens expire.
cp_identity_fingerprint() {
  local f
  for f in ca.key ca.crt; do
    if [ -f "$STATE_DIR/$f" ]; then
      printf '%s ' "$f"
      openssl dgst -sha256 -r "$STATE_DIR/$f" | cut -d' ' -f1
    fi
  done
}

verify_cp_identity_preserved() {
  local before="$1" after
  after="$(cp_identity_fingerprint)"
  if [ "$before" != "$after" ]; then
    echo "error: the control-plane CA under $STATE_DIR changed during the upgrade -- every node's client identity is now invalid. Restore ca.key and ca.crt from backup." >&2
    return 1
  fi
  echo "Control-plane identity preserved (ca.key, ca.crt unchanged); no CA re-minted."
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
  echo "error: this node already joined a cluster ($STATE_DIR/kubeconfig exists with no local CA key) -- refusing to re-run the join CSR flow, which would submit a fresh CSR and overwrite this node's existing kubelet-client.crt/.key and kubeconfig. Bootstrap tokens are single-use, so this would likely fail outright anyway. To upgrade this worker, re-run install.sh with no --join/--token flags. To force a genuine re-join, stop kubelet, rm -rf $STATE_DIR, and re-run install.sh --join <url> --token - --ca-cert-hash <hash> with a freshly minted token." >&2
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
PERSISTED_SERVICE_CIDR=""
PERSISTED_POD_CLUSTER_CIDR=""
PERSISTED_CLUSTER_DNS=""
normalize_node_name() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]'; }
NODE_NAME="$(normalize_node_name "$NODE_NAME")"
if [ -f "$CONFIG_FILE" ]; then
  # Sourced inside a subshell, not the main shell, so this cannot clobber the
  # NODE_NAME/IFACE already resolved from flags/env above.
  # shellcheck disable=SC1090 # dynamic path: this project's own prior-run file
  PERSISTED_NODE_NAME="$(normalize_node_name "$(. "$CONFIG_FILE"; printf '%s' "${NODE_NAME:-}")")"
  # shellcheck disable=SC1090
  PERSISTED_IFACE="$(. "$CONFIG_FILE"; printf '%s' "${IFACE:-}")"
  # shellcheck disable=SC1090
  PERSISTED_SERVICE_CIDR="$(. "$CONFIG_FILE"; printf '%s' "${SERVICE_CIDR:-}")"
  # shellcheck disable=SC1090
  PERSISTED_POD_CLUSTER_CIDR="$(. "$CONFIG_FILE"; printf '%s' "${POD_CLUSTER_CIDR:-}")"
  # shellcheck disable=SC1090
  PERSISTED_CLUSTER_DNS="$(. "$CONFIG_FILE"; printf '%s' "${CLUSTER_DNS:-}")"
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

# --- Network ranges: defaults, persisted values, validation -------------------
#
# A worker runs only kubelet, which consumes only the DNS address; the ranges
# are control-plane settings, so passing them with --join is refused rather
# than silently ignored.
if [ "$WORKER_MODE" -eq 1 ]; then
  if [ -n "$SERVICE_CIDR" ] || [ -n "$POD_CLUSTER_CIDR" ]; then
    echo "error: --service-cidr/--cluster-cidr are control-plane settings; a joining or already-joined worker takes only --cluster-dns" >&2
    exit 1
  fi
  reconcile_network_flag --cluster-dns CLUSTER_DNS "$PERSISTED_CLUSTER_DNS" "$(default_cluster_dns "$DEFAULT_SERVICE_CIDR")" || exit 1
else
  reconcile_network_flag --service-cidr SERVICE_CIDR "$PERSISTED_SERVICE_CIDR" "$DEFAULT_SERVICE_CIDR" || exit 1
  reconcile_network_flag --cluster-cidr POD_CLUSTER_CIDR "$PERSISTED_POD_CLUSTER_CIDR" "$DEFAULT_POD_CLUSTER_CIDR" || exit 1
  dns_default="$(default_cluster_dns "$SERVICE_CIDR")" || exit 1
  reconcile_network_flag --cluster-dns CLUSTER_DNS "$PERSISTED_CLUSTER_DNS" "$dns_default" || exit 1
fi
validate_network_config "$WORKER_MODE" || exit 1

# --- Defaults: node name, network interface ----------------------------------

if [ -z "$NODE_NAME" ]; then
  # Node names are DNS-1123 (lowercase); upstream kubelet's GetHostname
  # lowercases and trims the hostname the same way.
  NODE_NAME="$(normalize_node_name "$(hostname)")"
fi
if [ -z "$NODE_NAME" ]; then
  echo "error: refusing to continue: empty node name (hostname is empty; pass --node-name)" >&2
  exit 1
fi
# openssl req rejects a Subject CN over X.509
# ub-common-name (64) when building the identity CSR, after packages and state
# are already laid down. "system:node:" is 12 of those 64.
if [ "${#NODE_NAME}" -gt 52 ]; then
  echo "error: node name '$NODE_NAME' is ${#NODE_NAME} chars; the node identity certificate CN 'system:node:<name>' would exceed the X.509 64-char limit that openssl enforces (max node name: 52). Pass a shorter --node-name (e.g. the short hostname instead of the FQDN)." >&2
  exit 1
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
    | sed -n 1p)"
  if [ -z "$IFACE" ]; then
    echo "error: no recognized physical network interface found -- pass --iface explicitly" >&2
    exit 1
  fi
fi

IFACE_IP="$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | sed -n 1p)"
if [ -z "$IFACE_IP" ]; then
  echo "error: interface $IFACE has no IPv4 address assigned" >&2
  exit 1
fi
[ "$WORKER_MODE" -eq 1 ] || check_node_ip_outside_ranges "$IFACE_IP" || exit 1

if [ "$EXISTING_INSTALL" -eq 1 ]; then
  echo "Upgrading u7s: node-name=$NODE_NAME iface=$IFACE ($IFACE_IP)"
else
  echo "Installing u7s: node-name=$NODE_NAME iface=$IFACE ($IFACE_IP)"
fi

# An already-joined worker upgrades with its own identity and no token; refuse
# before touching the host if that identity is missing or expired.
if [ "$EXISTING_WORKER" -eq 1 ]; then
  verify_worker_identity || exit 1
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
# Pinned fingerprint of the isv:cri-o OBS project key (fetched and read with
# `gpg --show-keys --with-colons` on 2026-10-20; expires 2027-04). Rotation: verify the new key
# out of band, then update this value.
install_apt_key https://slc-mirror.opensuse.org/repositories/isv:/cri-o:/stable:/v1.37/deb/Release.key \
  85B67D5C50100B1AC8CEFE49CBA9C85640A2B579 /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://slc-mirror.opensuse.org/repositories/isv:/cri-o:/stable:/v1.37/deb/ /' \
  > /etc/apt/sources.list.d/cri-o.list
apt-get update -qq
apt-get install -y cri-o crun conmon
# Do NOT add a 10-crun.conf drop-in pointing at /usr/bin/crun: CRI-O ships its
# own crun at /usr/libexec/crio/crun matching the OCI spec version it generates
# (1.2.x), while the system crun accepts only 1.0/1.1 and fails every sandbox
# create with "unknown version specified". The package's own 10-crio.conf
# already sets the correct path.
mkdir -p /etc/crio/crio.conf.d

# Reap idle exec/attach/logs/port-forward streaming connections' goroutines and
# buffers instead of holding them open for cri-o's 4h default; reopens on
# demand, so this only affects memory held by connections nobody is using.
# log_size_max and log_level from the original memory-tuning proposal are
# intentionally not here: log_size_max caps the on-disk log file, already
# enforced by kubelet --container-log-max-size (no memory benefit), and
# log_level stays at its current level for debuggability.
cat > /etc/crio/crio.conf.d/10-memory.conf <<'CRIO_MEM_EOF'
[crio.runtime]
stream_idle_timeout = "5m"
CRIO_MEM_EOF

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
# IPv6 pod/Service traffic is routed through the node, which the kernel only
# does with forwarding on; nothing else here sets it.
if [ -n "$SERVICE_CIDR_IPV6$POD_CLUSTER_CIDR_IPV6" ]; then
  printf 'net.ipv6.conf.all.forwarding = 1\n' > /etc/sysctl.d/u7s-ipv6-forwarding.conf
fi
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
STAGE_DIR="$(mktemp_disk_dir)"
# Replaces the download-only trap above, so it must still cover $DOWNLOAD_DIR.
# ${DOWNLOAD_DIR:+...} expands to nothing when --tarball gave a local path.
trap 'rm -rf "$STAGE_DIR" ${DOWNLOAD_DIR:+"$DOWNLOAD_DIR"}' EXIT

if ! tar -xzf "$TARBALL" -C "$STAGE_DIR"; then
  echo "error: failed to extract $TARBALL into $STAGE_DIR -- check free disk space on /var/tmp (df -h /var/tmp)" >&2
  exit 1
fi

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
KUBE_VERSION="$("$BIN_DIR/kubelet" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sed -n 1p)"
if [ -z "$KUBE_VERSION" ]; then
  echo "error: could not determine kubelet version from '$BIN_DIR/kubelet --version'" >&2
  exit 1
fi
KUBE_MINOR="${KUBE_VERSION%.*}"

# Pinned fingerprint of the isv:kubernetes OBS project key, identical for the
# v1.35-v1.37 repos (fetched 2026-10-20; expires 2026-12-29, so expect to
# update this pin when the vendor rotates it).
install_apt_key "https://pkgs.k8s.io/core:/stable:/v${KUBE_MINOR}/deb/Release.key" \
  DE15B14486CD377B9E876E1A234654DA9A296436 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
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
{
  printf 'NODE_NAME="%s"\nIFACE="%s"\nCLUSTER_DNS="%s"\n' "$NODE_NAME" "$IFACE" "$CLUSTER_DNS"
  if [ "$WORKER_MODE" -eq 0 ]; then
    printf 'SERVICE_CIDR="%s"\nPOD_CLUSTER_CIDR="%s"\n' "$SERVICE_CIDR" "$POD_CLUSTER_CIDR"
  fi
} > "$CONFIG_FILE"

write_kubelet_config_yaml "$WORKER_MODE"
# Serving cert minted by an earlier install (10-year, never renewed).
rm -f "$STATE_DIR"/kubelet-serving.crt "$STATE_DIR"/kubelet-serving.key "$STATE_DIR"/kubelet-serving.csr

# Round-2 kubelet tuning, shared by both kubelet.service blocks
# below. --max-pods and ConfigMapAndSecretChangeDetectionStrategy are
# deliberately NOT touched here -- operator scope narrowing keeps
# behavior-changing knobs off the table until other levers are exhausted.
#
# Feature gates: kubelet-consulted Beta gates, default-on in v1.37.1's
# pkg/features/kube_features.go, that no u7s workload or manifest exercises
# (verified per-gate against crates/ + manifests/ for a consumer of the
# capability's wire field). PodReadyToStartContainersCondition was left
# enabled -- whether anything depends on kubelet emitting it is uncertain
# (the closest regression test, crates/apiserver/src/handlers/pods.rs's
# $setElementOrder/conditions reordering, is condition-name-agnostic, so it
# doesn't prove this specific condition is required), and the conservative
# default is to keep an uncertain dependency on rather than prove it's safe
# to cut. Disabling the other 14 (16 on 1.37+) drops the corresponding kubelet code paths
# (checkpoint HTTP handler, credential-provider SA-token plumbing, CA/serving
# -cert file watchers, pod/container-level resize bookkeeping, etc.) for zero
# functional loss.
#
# --application-metrics-count-limit=0 (a cAdvisor trim: dropped the
# 100-slot-per-container legacy "application metrics" ring buffer that u7s
# never populated) used to live here too, but kubelet 1.37 removed the flag
# entirely -- "unknown flag: --application-metrics-count-limit" is a
# crash-loop, not a deprecation warning -- so it is dropped for every
# kubelet version rather than version-gated. --housekeeping-interval was tried and reverted separately:
# pkg/kubelet/kubelet.go's evictionMonitoringPeriod is a hardcoded 10s
# constant with an explicit upstream comment to "keep this in sync with
# internal cadvisor housekeeping" -- raising --housekeeping-interval desyncs
# the two, so the eviction manager can act on cAdvisor stats up to
# (new_interval - 10s) stale under real memory pressure. That is a genuine
# behavior change under load, not a zero-impact trim, and falls under the
# same behavior-changing-knob restriction as --max-pods.
#
# InPlacePodVerticalScalingInitContainers is no longer in this list: kubelet
# 1.37 graduated it to GA + LockToDefault:true, so passing =false is now a
# startup error ("feature is locked to true"), not a no-op; it is dropped for
# every version (default-on Beta in 1.36, so the 1.36 trim is forfeited).
# PodLevelResourcesFixDefaulting/PodLevelResourcesFixKubeletQOSClass are
# added on 1.37+ only: both are new in 1.37, default true, and both hard-depend
# on PodLevelResources per pkg/features/kube_features.go's dependency map, so
# keeping PodLevelResources disabled requires disabling these two as well
# or kubelet refuses to start ("is enabled, but depends on features that are
# disabled").
# Takes the kubelet minor (e.g. "v1.37" or "1.37") and prints the flag string.
kubelet_round2_flags() {
  local minor="${1#*.}"
  local flags="--feature-gates=ContainerCheckpoint=false,ContainerRestartRules=false,InPlacePodLevelResourcesVerticalScaling=false,KubeletCrashLoopBackOffMax=false,KubeletEnsureSecretPulledImages=false,KubeletSeparateDiskGC=false,KubeletServiceAccountTokenForCredentialProviders=false,PodLevelResources=false,ReloadKubeletClientCAFile=false,ReloadKubeletServerCertificateFile=false,ResourceHealthStatus=false,ResourceHealthStatusMessage=false,RestartAllContainersOnContainerExits=false"
  # The two gates below only exist from 1.37; an older kubelet rejects them as
  # unrecognized, so they are appended only when the staged kubelet is >= 1.37.
  if [ "$minor" -ge 37 ]; then
    flags="$flags,PodLevelResourcesFixDefaulting=false,PodLevelResourcesFixKubeletQOSClass=false"
  fi
  printf '%s' "$flags"
}
KUBELET_ROUND2_FLAGS="$(kubelet_round2_flags "$KUBE_MINOR")"

if [ "$WORKER_MODE" -eq 1 ]; then
  # --- Join an existing cluster via the CSR API, or upgrade an
  # already-joined worker in place (kubelet binary + kubelet.service only,
  # kubeconfig/kubelet-client.* untouched) -------------------------------
  if [ "$JOIN_MODE" -eq 1 ]; then
    join_cluster
  else
    echo "Existing worker node detected -- join skipped, no token needed; upgrading kubelet only, kubeconfig and kubelet-client.crt/.key are left untouched."
    ensure_jq
    HEARTBEAT_BEFORE="$(worker_ready_heartbeat any)"
    if [ -z "$HEARTBEAT_BEFORE" ]; then
      echo "error: cannot read node $NODE_NAME's Ready heartbeat from the API server (unreachable with this node's client identity, or the node is not registered) -- refusing to restart kubelet, since a post-restart Ready heartbeat could not be told from a stale one. Nothing was changed." >&2
      exit 1
    fi
    FINGERPRINT_BEFORE="$(client_cert_fingerprint)"
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
# --cert-dir: kubelet's compiled-in default (/var/lib/kubelet/pki) lives
# outside $STATE_DIR, so it survives the documented reset procedure's "rm -rf
# $STATE_DIR" untouched. A reset that regenerates the CA then leaves kubelet
# presenting a rotated client cert signed by the deleted CA, an infinite
# UnknownIssuer reconnect loop with no node ever registering. This is a
# --cert-dir CLI flag, not a KubeletConfiguration yaml field -- kubelet has
# no certDir/certDirectory config-file key, so setting it in
# kubelet-config.yaml is a silent no-op.
ExecStart=$BIN_DIR/kubelet --config=$STATE_DIR/kubelet-config.yaml --kubeconfig=$STATE_DIR/kubeconfig --hostname-override=$NODE_NAME --node-ip=$IFACE_IP --cert-dir=$STATE_DIR/kubelet/pki $KUBELET_ROUND2_FLAGS
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable kubelet.service
  systemctl restart kubelet.service

  if [ "$JOIN_MODE" -eq 1 ]; then
    wait_for_joined_node
  else
    wait_for_upgraded_worker "$HEARTBEAT_BEFORE" "$FINGERPRINT_BEFORE" || exit 1
  fi

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
# writes finished -- so the dependent units are only restarted after
# wait_for_apiserver_files. Restart=always remains for later crashes.

# $POD_CLUSTER_CIDR (resolved and validated above) feeds node-ipam-controller
# and Flannel's net-conf.json -- one variable so the two can never drift apart.
KCM_NODE_CIDR_MASK_FLAGS="$(kcm_node_cidr_mask_flags)"

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
# flannel.yaml, kube-proxy.yaml and beep.yaml each carry install-time placeholders a
# byte-for-byte copy would ship unresolved -- see each file's own header for
# what it substitutes to. Every other manifest copies verbatim.
if [ "$WORKER_MODE" -eq 0 ]; then
  TARBALL_MANIFEST_DIR="$(find "$STAGE_DIR" -type d -name manifests | head -n1)"
  if [ -n "$TARBALL_MANIFEST_DIR" ] && [ -n "$(find "$TARBALL_MANIFEST_DIR" -maxdepth 1 -name '*.yaml')" ]; then
    install -d -m 0755 "$MANIFEST_OUTPUT_DIR"
    cp "$TARBALL_MANIFEST_DIR"/*.yaml "$MANIFEST_OUTPUT_DIR/"
    render_vendored_manifests "$MANIFEST_OUTPUT_DIR" || exit 1
    # Only the well-known folder is auto-applied; a custom dir is GitOps-managed.
    if [ "$MANIFEST_OUTPUT_DIR" = "/etc/u7s/manifests" ]; then
      CLUSTER_WORKLOADS="kube-system/deployment/coredns kube-system/daemonset/kube-proxy kube-system/daemonset/servicelb-controller kube-flannel/daemonset/kube-flannel-ds"
    fi
  fi
fi

# Join tokens are Secrets now; a static token file left by an older install
# would keep authenticating forever, but is no longer passed to the apiserver.
rm -f "$STATE_DIR/token-auth-file"

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
ExecStart=$BIN_DIR/u7s-apiserver --listen $IFACE_IP:6443 --advertise-address https://$IFACE_IP:6443 --local-node-name $NODE_NAME --service-cluster-ip-range $SERVICE_CIDR --kube-dns-cluster-ip $CLUSTER_DNS --embedded-scheduler true$([ "$ALLOW_SERVICE_EXTERNAL_IPS" = 1 ] || echo " --deny-service-external-ips")
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
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$STATE_DIR
# ca.crt is DER from u7s but KCM needs PEM, converted at start rather than at
# install time because it does not exist until apiserver's first run.
# No --service-account-private-key-file: u7s does not support legacy
# service-account token Secrets, so KCM's token controller stays off.
# kcm-kubeconfig references files, so KCM live-reloads a re-issued client cert and
# CA; --root-ca-file is read once, hence the restart hook below.
# --authentication-kubeconfig/--authorization-kubeconfig (same kubeconfig, as
# kubeadm does) delegate authn/authz to the apiserver so :10257/metrics is
# RBAC-gated (system:monitoring) instead of 403 for everyone; /healthz,
# /readyz and /livez stay open by default. KCM treats a failed lookup of
# kube-system/extension-apiserver-authentication as fatal and Restart=always
# retries until the apiserver has published it.
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
# device-taint-eviction-controller stays enabled: u7s serves
# resource.k8s.io/v1 DeviceTaintRule (GA, default-on in 1.37).
# cloud-node-lifecycle-controller / node-route-controller / service-lb-controller
# are deliberately NOT excluded, on any pinned KCM version: without
# --cloud-provider set, KCM 1.35/1.36 already no-op all three at construction
# time (KEP-2395 log line: "no cloud provider functionality is available in
# kube-controller-manager ... will not configure ..."), and KCM 1.37 removed
# them from its known-controllers registry entirely -- excluding a name KCM
# no longer knows about is a hard --controllers validation error ("is not
# in the list of known controllers") that crash-loops kcm before it ever
# reaches its control loops.
ExecStart=$BIN_DIR/kube-controller-manager --kubeconfig=$STATE_DIR/kcm-kubeconfig --authentication-kubeconfig=$STATE_DIR/kcm-kubeconfig --authorization-kubeconfig=$STATE_DIR/kcm-kubeconfig --cluster-signing-cert-file=$STATE_DIR/intermediate-cert.pem --cluster-signing-key-file=$STATE_DIR/intermediate.key --cluster-signing-duration=8760h --root-ca-file=$STATE_DIR/ca-bundle.pem --controllers=*,bootstrap-signer-controller,token-cleaner-controller,-clusterrole-aggregation-controller,-service-cidr-controller --allocate-node-cidrs=true --cluster-cidr=$POD_CLUSTER_CIDR --service-cluster-ip-range=$SERVICE_CIDR $KCM_NODE_CIDR_MASK_FLAGS --use-service-account-credentials=true --leader-elect=false --bind-address=127.0.0.1 --kube-api-content-type=application/json
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# Root CA succession hook: the apiserver rewrites ca-bundle.pem only when cluster trust
# changes, and KCM reads --root-ca-file once, so restart it then and only then. Client
# cert and CA reloads need no restart (kcm-kubeconfig references files).
cat > /etc/systemd/system/u7s-kcm-restart.path <<EOF
[Unit]
Description=Restart u7s-kcm when the cluster CA bundle changes

[Path]
PathChanged=$STATE_DIR/ca-bundle.pem

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/u7s-kcm-restart.service <<EOF
[Unit]
Description=Restart u7s-kcm to re-read --root-ca-file

[Service]
Type=oneshot
ExecStart=/bin/systemctl restart u7s-kcm.service
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
# The kubelet requests its own CA-signed serving cert (serverTLSBootstrap in
# kubelet-config.yaml); the apiserver's kubelet-serving approver admits it and
# KCM signs it. A self-signed one is rejected by the apiserver's kubelet-client
# -- pinned to the cluster CA by build_kubelet_tls_config in
# crates/apiserver/src/handlers/proxy.rs, not the system trust store --
# surfacing as BadGateway on kubectl logs/exec.
# ExecStartPre keeps ca.pem (clientCAFile) current; the DER->PEM conversion is
# safe to repeat across services.
ExecStartPre=/usr/bin/openssl x509 -inform DER -in $STATE_DIR/ca.crt -out $STATE_DIR/ca.pem
# --cert-dir -- see the worker-mode kubelet.service block above for why this
# must be a CLI flag under $STATE_DIR rather than a kubelet-config.yaml key.
ExecStart=$BIN_DIR/kubelet --config=$STATE_DIR/kubelet-config.yaml --kubeconfig=$STATE_DIR/kubelet-kubeconfig --hostname-override=$NODE_NAME --node-ip=$IFACE_IP --cert-dir=$STATE_DIR/kubelet/pki $KUBELET_ROUND2_FLAGS
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

CP_IDENTITY_BEFORE="$(cp_identity_fingerprint)"

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
wait_for_apiserver_files "$STATE_DIR"
wait_for_authentication_configmap "$STATE_DIR/kubeconfig"
systemctl enable u7s-kcm.service
systemctl restart u7s-kcm.service
systemctl enable u7s-kcm-restart.path
systemctl restart u7s-kcm-restart.path
issue_cp_kubelet_identity
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
if [ "$EXISTING_INSTALL" -eq 1 ]; then
  verify_cp_identity_preserved "$CP_IDENTITY_BEFORE" || exit 1
fi
label_control_plane_node || exit 1
wait_for_cluster_ready || exit 1

echo "u7s bootstrap complete (host-level + in-cluster)."
echo "kubeconfig: $KUBECONFIG_PATH"
echo "Run: kubectl --kubeconfig=$KUBECONFIG_PATH get nodes"
echo "It references ca-bundle.pem and admin.pem in $STATE_DIR by path; to use it elsewhere: kubectl --kubeconfig=$KUBECONFIG_PATH config view --raw --flatten > portable-kubeconfig"
}

main "$@"
