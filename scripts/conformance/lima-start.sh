#!/usr/bin/env bash
# Local E2E setup: u7s on Mac host + kubelet inside lima VM.
#
# Architecture:
#   - u7s runs natively on the Mac (fast cargo rebuild loop)
#   - kubelet + CRI-O run inside the lima VM (Linux kernel required)
#   - kubelet reaches u7s via host.lima.internal:<port> (configurable, default 6443)
#   - kubectl runs on the Mac against 127.0.0.1:<port>
#
# Quick start:
#   1. cargo build --release -p u7s-apiserver
#      scripts/u7s-start.sh       # starts server, prints export KUBECONFIG=...
#
#   2. export KUBECONFIG=./temp/u7s/kubeconfig
#      scripts/lima-start.sh
#
#   3. kubectl get nodes        # lima-node should appear within ~30s
#      kubectl get pods -A
#
# Re-running after u7s restart:
#   Just re-run this script — it rewrites the kubeconfig in the VM and
#   restarts kubelet, so the new TLS cert is picked up automatically.
#
# Troubleshooting:
#   kubelet not registering:
#     limactl shell lima-node sudo journalctl -u kubelet --no-pager --utc -n 50
#   CRI-O issues:
#     limactl shell lima-node sudo journalctl -u crio --no-pager --utc -n 30
#     (pass --verbose to raise both kubelet --v and CRI-O's log_level to debug)
#   Container sandbox failures ("unknown version specified"):
#     Two possible causes:
#     1. System crun used instead of CRI-O's bundled one (10-crun.conf drop-in):
#        Fix: limactl shell lima-node sudo rm /etc/crio/crio.conf.d/10-crun.conf
#             limactl shell lima-node sudo systemctl restart crio
#     2. Wrong CNI config format (10-crio-bridge.conf 0.4.0 instead of 1.0.0 conflist):
#        Fix: limactl shell lima-node sudo mv /etc/cni/net.d/10-crio-bridge.conf /etc/cni/net.d/10-crio-bridge.conf.disabled
#             limactl shell lima-node sudo mv /etc/cni/net.d/10-crio-bridge.conflist.disabled /etc/cni/net.d/10-crio-bridge.conflist
#             limactl shell lima-node sudo systemctl restart crio
#     (lima/kubelet.yaml provision now prevents both — delete+reprovision fixes them permanently)
set -euo pipefail

LIMA_YAML="$(dirname "$0")/../../lima/kubelet.yaml"
# shellcheck source=scripts/conformance/_lib.sh
source "$(dirname "$0")/_lib.sh"

_WORKDIR_OVERRIDE=""
_PORT_OVERRIDE=""
_KUBELET_PORT_OVERRIDE=""
_KONNECTIVITY_SERVER_PORT_OVERRIDE=""
_NODE_SUFFIX_OVERRIDE=""
VERBOSE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm) U7S_VM_NAME="$2"; shift 2 ;;
    --kubeconfig) KUBECONFIG="$2"; shift 2 ;;
    --workdir) _WORKDIR_OVERRIDE="$2"; shift 2 ;;
    --port) _PORT_OVERRIDE="$2"; shift 2 ;;
    --kubelet-port) _KUBELET_PORT_OVERRIDE="$2"; shift 2 ;;
    --konnectivity-server-port) _KONNECTIVITY_SERVER_PORT_OVERRIDE="$2"; shift 2 ;;
    --node-suffix) _NODE_SUFFIX_OVERRIDE="$2"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
# Kubelet --v level and CRI-O log_level both derive from this one flag: --v=5 is the
# ceiling that surfaces PLEG relist detail (see the crio.conf.d drop-in below), and
# --v=2 is today's unchanged default so a non-verbose run's log volume never grows.
KUBELET_V=2
[ "$VERBOSE" -eq 1 ] && KUBELET_V=5
# kube-proxy --v=5 additionally logs every EndpointSlice update it processes and every
# IPVS sync completion (this deployment runs kube-proxy in IPVS mode — see config.conf
# below) — the measurement needed to tell whether kube-proxy saw an EndpointSlice event
# late or reprogrammed slowly. --v=2 is the unchanged default.
KUBE_PROXY_V=2
[ "$VERBOSE" -eq 1 ] && KUBE_PROXY_V=5
PORT="${_PORT_OVERRIDE:-6443}"
KUBELET_PORT="${_KUBELET_PORT_OVERRIDE:-10250}"
# Suffixes the per-node resource names below (konnectivity-agent Pod/Secret, kubelet
# serving cert) so a 2nd node can join the same cluster without colliding with — or,
# for the Pod's immutable spec.nodeName, 403'ing against — node 1's.
NODE_SUFFIX="${_NODE_SUFFIX_OVERRIDE:-}"
if [ -n "${_KONNECTIVITY_SERVER_PORT_OVERRIDE:-}" ]; then
  KONNECTIVITY_SERVER_PORT="$_KONNECTIVITY_SERVER_PORT_OVERRIDE"
else
  # Auto-derive: 6443→8135, 6444→8235, 6445→8335 (each port offset of 1 adds 100).
  KONNECTIVITY_SERVER_PORT=$(( 8135 + (PORT - 6443) * 100 ))
fi
# Agent port: server_port-3 (matches the layout 8135/8132 and slot offsets 8235/8232, etc.)
KONNECTIVITY_AGENT_PORT=$(( KONNECTIVITY_SERVER_PORT - 3 ))

# For day-to-day iteration after initial VM provisioning, use scripts/kubelet-reconnect.sh
# instead — it skips VM provisioning and just reconnects the kubelet.
VM_NAME="${U7S_VM_NAME:-lima-node}"

# When a non-default kubelet port is requested, write a patched yaml with the
# correct hostPort into the worktree temp dir so each worker VM uses its own
# host-side port and parallel workers don't collide on 10250.
if [ "$KUBELET_PORT" != "10250" ]; then
  if [ -n "$_WORKDIR_OVERRIDE" ]; then
    _YAML_DIR="$_WORKDIR_OVERRIDE"
  else
    _YAML_DIR="$PWD/temp/u7s"
  fi
  mkdir -p "$_YAML_DIR"
  sed "s/hostPort: 10250/hostPort: ${KUBELET_PORT}/" "$LIMA_YAML" > "$_YAML_DIR/kubelet-patched.yaml"
  LIMA_YAML="$_YAML_DIR/kubelet-patched.yaml"
fi
# --workdir sets the kubeconfig path. Takes priority over ambient $KUBECONFIG so
# that workers on non-default VMs are not silently routed to the mayor's apiserver.
if [ -n "$_WORKDIR_OVERRIDE" ]; then
  KUBECONFIG="$_WORKDIR_OVERRIDE/kubeconfig"
fi

check_deps() {
  local missing=0
  for cmd in limactl kubectl; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "error: $cmd not found" >&2
      case "$cmd" in
        limactl) echo "  install: brew install lima" >&2 ;;
        kubectl)  echo "  install: aqua install" >&2 ;;
      esac
      missing=1
    fi
  done
  [ "$missing" -eq 0 ]
}

find_kubeconfig() {
  if [ -z "${KUBECONFIG:-}" ]; then
    echo "error: KUBECONFIG not set." >&2
    echo "Start u7s first, then export the path it prints:" >&2
    echo "  scripts/u7s-start.sh" >&2
    echo "  export KUBECONFIG=./temp/u7s/kubeconfig" >&2
    exit 1
  fi
  # Poll up to 10s for the apiserver to write the kubeconfig file.
  for i in $(seq 1 10); do
    if [ -f "$KUBECONFIG" ]; then
      echo "$KUBECONFIG"
      return
    fi
    echo "Waiting for kubeconfig at $KUBECONFIG ($i/10) ..." >&2
    sleep 1
  done
  echo "error: kubeconfig not found at $KUBECONFIG after 10s." >&2
  echo "Check that u7s-apiserver started successfully." >&2
  exit 1
}

# Two u7s stacks whose lima-start.sh both bind 127.0.0.1:$KUBELET_PORT race for the
# hostPort forward: whichever hostagent boots first wins the bind silently, and the
# loser's apiserver ends up exec/log/attach-ing to the WINNER's kubelet instead of its
# own — which fails as a cryptic rustls BadSignature (every u7s CA shares the same
# hardcoded CN) rather than an obvious "wrong kubelet" error. check_port_free (_lib.sh)
# hard-fails on this instead of auto-allocating a free port.

check_deps

KUBECONFIG_PATH=$(find_kubeconfig)

# Verify u7s is reachable before touching the VM.
if ! kubectl --kubeconfig="$KUBECONFIG_PATH" get namespaces &>/dev/null; then
  echo "error: cannot reach u7s at the server in $KUBECONFIG_PATH" >&2
  echo "Make sure u7s is running on the host first." >&2
  exit 1
fi
echo "u7s is reachable."

# Start or resume the lima VM.
# Use the instance directory as authoritative existence check — limactl list
# can transiently return empty output if lima is busy, which would otherwise
# cause the provisioning branch to run and hit "instance already exists".
VM_DIR="${HOME}/.lima/${VM_NAME}"
if [ -d "$VM_DIR" ]; then
  STATUS=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk "/^${VM_NAME} / {print \$2}")
  if [ "$STATUS" != "Running" ]; then
    check_port_free "$KUBELET_PORT" "kubelet"
    echo "Starting stopped VM '$VM_NAME'..."
    limactl start "$VM_NAME"
  else
    echo "VM '$VM_NAME' already running."
  fi

  # Lima applies a yaml's `networks:` stanza only at instance CREATION, never on
  # restart/resume — so a VM created before lima/kubelet.yaml declared
  # `networks: - lima: user-v2` stays on its own private default network forever,
  # with no route to any peer. Detect that by comparing against this instance's
  # OWN recorded config (not a hardcoded address — the user-v2 subnet is
  # DHCP-assigned) and fail loud instead of silently reusing a VM that can never
  # reach another node, which otherwise surfaces as a cryptic `ip route` failure
  # much later in this script.
  if grep -q '^networks:' "$LIMA_YAML" && ! grep -q '^networks:' "$VM_DIR/lima.yaml" 2>/dev/null; then
    echo "error: $VM_NAME predates the current lima/kubelet.yaml network config (no 'networks:' recorded at its creation)." >&2
    echo "  Fix: limactl delete $VM_NAME   (or re-run with --reset, which now recreates a named --extra-node too)" >&2
    exit 1
  fi
else
  echo "Provisioning VM '$VM_NAME' (first run, takes ~15-20 min with the e2e-test-image pre-pull)..."
  # lima's own default boot-readiness timeout (10m, DefaultWatchHostAgentEventsTimeout
  # in lima-vm/lima) is tuned for a provision script that doesn't pull ~25 conformance
  # images -- that alone can take longer than 10m, which made a real run fail with
  # "did not receive an event with the running status" partway through the pull loop.
  # 30m matches the value lima's own code already uses as an "extended" timeout for
  # slow-boot cases (WinDefaultWatchHostAgentEventsTimeout).
  check_port_free "$KUBELET_PORT" "kubelet"
  limactl start --tty=false --timeout 30m --name="$VM_NAME" "$LIMA_YAML"
fi

# Give this node its own disjoint pod-CIDR /24 out of the CRI-O default 10.85.0.0/16
# (primary = .0, -2 = .1, -3 = .2, ...). The stock conflist hands every node the
# identical flat /16, so nodes independently allocate overlapping pod IPs and every
# node's route table treats the whole /16 as locally attached, which is why
# cross-node pod traffic fails with "Host is unreachable" (fixed by the inter-node
# routes added near the end of this script). Skip the crio restart + IPAM-lease
# wipe when the subnet is already correct so a plain reconnect never risks
# recycling an IP a live pod still holds.
if [ -z "$NODE_SUFFIX" ]; then
  POD_SUBNET_OCTET=0
else
  POD_SUBNET_OCTET=$(( ${NODE_SUFFIX#-} - 1 ))
fi
POD_SUBNET="10.85.${POD_SUBNET_OCTET}.0/24"
# `|| true` here is safe: a failure to read the current subnet (e.g. a transient
# `limactl shell` hiccup) just falls through to the "unset" branch below, which
# re-asserts the same rewrite this run would have wanted anyway — it never masks
# a failure that leaves the VM in a broken state, only ever costs an extra (idempotent)
# rewrite + crio restart on an already-correct subnet.
CURRENT_POD_SUBNET=$(limactl shell "$VM_NAME" sudo jq -r '.plugins[0].ipam.ranges[0][0].subnet' /etc/cni/net.d/10-crio-bridge.conflist 2>/dev/null || true)
if [ "$CURRENT_POD_SUBNET" != "$POD_SUBNET" ]; then
  echo "Rewriting CNI bridge pod subnet: ${CURRENT_POD_SUBNET:-<unset>} -> ${POD_SUBNET}"
  limactl shell "$VM_NAME" sudo bash -c "
    jq --arg s '${POD_SUBNET}' '.plugins[0].ipam.ranges[0][0].subnet = \$s' /etc/cni/net.d/10-crio-bridge.conflist > /tmp/10-crio-bridge.conflist.new
    mv /tmp/10-crio-bridge.conflist.new /etc/cni/net.d/10-crio-bridge.conflist
    systemctl restart crio
    rm -rf /var/lib/cni/networks/crio/*
  "
else
  echo "CNI bridge pod subnet already ${POD_SUBNET}, skipping rewrite."
fi

# The bridge CNI plugin does not re-address an already-existing cni0 device when
# the conflist's subnet changes underneath it — only a freshly-created bridge
# picks up a new range. So a VM whose conflist file above already says the right
# subnet can still be carrying a live cni0 stuck on a stale one from before that
# rewrite ever took effect. Fail loud rather than let an inter-node route get
# programmed against an address this node's pods were never actually assigned.
CNI0_LIVE=$(limactl shell "$VM_NAME" ip -4 addr show cni0 2>/dev/null | grep -oE 'inet [0-9]+(\.[0-9]+){3}/[0-9]+' | awk '{print $2}' | head -1 || true)
if [ -n "$CNI0_LIVE" ] && [ "$CNI0_LIVE" != "10.85.${POD_SUBNET_OCTET}.1/24" ]; then
  echo "error: $VM_NAME's cni0 bridge is still ${CNI0_LIVE}, not this node's assigned ${POD_SUBNET}." >&2
  echo "  Fix: limactl delete $VM_NAME   (or re-run with --reset, which now recreates a named --extra-node too)" >&2
  exit 1
fi

# Toggle CRI-O debug logging via a crio.conf.d drop-in, controlled by --verbose. A
# PLEG-relist-miss (kubelet never sees ContainerStarted even though CRI-O did start
# the container) is undiagnosable without CRI-O's own log at debug — but debug-level
# CRI-O writes far too much to leave on for every run, so read-detect the drop-in's
# current presence and only touch it (and restart crio) when it doesn't already match
# this invocation's --verbose, so re-running --verbose twice never restarts crio for
# no reason, and a later non-verbose run always removes a stale drop-in rather than
# leaving debug logging on forever.
CRIO_VERBOSE_CONF="/etc/crio/crio.conf.d/99-verbose.conf"
CRIO_VERBOSE_PRESENT=0
if limactl shell "$VM_NAME" test -f "$CRIO_VERBOSE_CONF" 2>/dev/null; then
  CRIO_VERBOSE_PRESENT=1
fi
if [ "$VERBOSE" -eq 1 ] && [ "$CRIO_VERBOSE_PRESENT" -eq 0 ]; then
  echo "Enabling CRI-O debug logging (${CRIO_VERBOSE_CONF})..."
  limactl shell "$VM_NAME" sudo bash -c "cat > $CRIO_VERBOSE_CONF" <<'CRIOEOF'
[crio.runtime]
log_level = "debug"
CRIOEOF
  limactl shell "$VM_NAME" sudo systemctl restart crio
elif [ "$VERBOSE" -eq 0 ] && [ "$CRIO_VERBOSE_PRESENT" -eq 1 ]; then
  echo "Disabling CRI-O debug logging (removing ${CRIO_VERBOSE_CONF})..."
  limactl shell "$VM_NAME" sudo rm -f "$CRIO_VERBOSE_CONF"
  limactl shell "$VM_NAME" sudo systemctl restart crio
fi

# Cap syslog growth: rotate at 2GB (keep 2 rotations = max 6GB) so a long conformance
# run does not exhaust disk. Overwrites the distro rsyslog config to split syslog
# (size-based) from the remaining logs (weekly). Written on every start so it survives
# VM reprovisions.
limactl shell "$VM_NAME" sudo bash -c 'cat > /etc/logrotate.d/rsyslog' <<'LOGROTATEOF'
/var/log/syslog {
    size 2G
    rotate 2
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
/var/log/mail.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/cron.log
{
    rotate 4
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
LOGROTATEOF

# Override the logrotate systemd timer to fire every 2 hours instead of daily.
# The size-based trigger in logrotate.d/rsyslog only acts when logrotate runs;
# with the default daily schedule a 10-hour conformance run can exhaust 2GB before
# midnight and evict the e2e pod. OnCalendar= (empty) clears the inherited value.
limactl shell "$VM_NAME" sudo bash -c 'mkdir -p /etc/systemd/system/logrotate.timer.d && cat > /etc/systemd/system/logrotate.timer.d/override.conf' <<'EOF'
[Timer]
OnCalendar=
OnCalendar=*-*-* *:00/2:00
RandomizedDelaySec=0
EOF
limactl shell "$VM_NAME" sudo systemctl daemon-reload
limactl shell "$VM_NAME" sudo systemctl restart logrotate.timer

# Raise journald's rate-limit and disk retention so a 16-way conformance run's
# kubelet/crio log volume on the busiest node isn't rate-limited or rotated away
# before scripts/conformance/06-run-sonobuoy.sh collects it: the stock
# RateLimitBurst=10000/30s silently drops lines once a unit's log rate exceeds
# it, and the stock SystemMaxUse evicts the oldest segment once total journal
# disk usage crosses a few hundred MB — together these erased the first ~5
# minutes of one node's kubelet.log/crio.log in a real run while an identically
# collected, less-loaded node kept the full window. Written on every start so it
# survives VM reprovisions.
#
# SystemMaxUse=2G (this drop-in's original value) still wasn't enough: the
# 0805-2202 --all-e2e run's collected kubelet.log/crio.log covered only the
# LAST 1h54m of an 11h run (measured directly off that node's timestamps,
# 20:08-22:02) under 16-way load — losing the 09:33-09:35 DiskPressure incident
# entirely. 6G buys a fresh run roughly 5-6x that headroom at the same growth
# rate; going further eats into the 20GiB VM disk conformance tests themselves
# need (~14G free observed with only base images pulled — DiskPressure
# investigations already show that margin gets tight mid-run), so 6G is a
# deliberate compromise, not full 11h coverage.
limactl shell "$VM_NAME" sudo bash -c 'mkdir -p /etc/systemd/journald.conf.d && cat > /etc/systemd/journald.conf.d/conformance.conf' <<'EOF'
[Journal]
RateLimitBurst=100000
RateLimitIntervalSec=30s
SystemMaxUse=6G
SystemKeepFree=100M
Storage=persistent
EOF
limactl shell "$VM_NAME" sudo systemctl restart systemd-journald

# This block re-runs on every invocation, not only --reset ones (reset.sh does
# a full 'limactl delete --force', but a plain re-run against an existing VM
# hits this same code path). On a VM reused across several conformance
# sessions without --reset in between, journal volume from EARLIER sessions
# is still sitting in the budget when a NEW run starts, silently shrinking how
# much of the fresh run's own window that 6G actually covers. --rotate forces
# the currently-active file closed so --vacuum-size can delete it along with
# any older archived segments (a raw --vacuum-size alone leaves the active
# file alone), reclaiming the full budget for THIS run. Safe to discard here
# because any prior run's data that mattered was already evacuated to the
# host by 06-run-sonobuoy.sh's end-of-run collection.
limactl shell "$VM_NAME" sudo journalctl --rotate
limactl shell "$VM_NAME" sudo journalctl --vacuum-size=1M

# Rewrite server address to host.lima.internal for in-VM use.
# Match any loopback alias (127.0.0.1, 127.0.0.2, …) so parallel workers work correctly.
echo "Copying kubeconfig into VM..."
REWRITTEN=$(mktemp)
sed "s|https://127\.[0-9]*\.[0-9]*\.[0-9]*:[0-9]*|https://host.lima.internal:${PORT}|g" "$KUBECONFIG_PATH" > "$REWRITTEN"
limactl copy "$REWRITTEN" "${VM_NAME}:/tmp/kubelet-kubeconfig"
rm "$REWRITTEN"
limactl shell "$VM_NAME" sudo cp /tmp/kubelet-kubeconfig /etc/kubelet-kubeconfig
limactl shell "$VM_NAME" sudo chmod 600 /etc/kubelet-kubeconfig

# Copy cluster CA so the kubelet can authenticate the apiserver's mTLS client cert
# when proxying log/exec/attach requests. Without --client-ca-file the kubelet falls
# back to webhook auth and rejects the apiserver's cert with 401.
# ca.crt is DER-encoded; kubelet requires PEM.
CA_CERT="$(dirname "$KUBECONFIG_PATH")/ca.crt"
CA_PEM=$(mktemp)
trap 'rm -f "$CA_PEM"' EXIT
if [ -f "$CA_CERT" ]; then
  openssl x509 -in "$CA_CERT" -inform DER -out "$CA_PEM" -outform PEM
  limactl copy "$CA_PEM" "${VM_NAME}:/tmp/kubelet-ca.crt"
  limactl shell "$VM_NAME" sudo cp /tmp/kubelet-ca.crt /etc/kubelet-ca.crt
  limactl shell "$VM_NAME" sudo chmod 644 /etc/kubelet-ca.crt

  # Generate a kubelet serving cert signed by the cluster CA so the apiserver can
  # verify the kubelet's TLS cert on exec/log/attach connections (closes the MITM
  # vector that existed when AcceptAnyCert was used).
  CERT_DIR="$(dirname "$KUBECONFIG_PATH")"
  KUBELET_TLS_KEY="$CERT_DIR/kubelet-serving${NODE_SUFFIX}.key"
  KUBELET_TLS_CRT="$CERT_DIR/kubelet-serving${NODE_SUFFIX}.crt"
  KUBELET_TLS_CSR="$CERT_DIR/kubelet-serving${NODE_SUFFIX}.csr"

  # Get the lima VM IP so it can be included as a SAN (needed if kubelet-preferred-address
  # is not set and the apiserver connects via the VM's InternalIP instead of 127.0.0.1).
  # The user-v2 network in lima/kubelet.yaml gives the VM a sole non-loopback interface;
  # select by "scope global" rather than a hardcoded interface name since Ubuntu 26.04's
  # first-boot NIC rename to eth0 can fail (LP: #2136392), leaving it as e.g. enp0s1.
  # Its address is DHCP-assigned per node, so there is no sane hardcoded fallback — fail
  # loud instead of silently signing a cert for an address the node doesn't have.
  LIMA_VM_IP=$(limactl shell "$VM_NAME" ip -4 addr show scope global 2>/dev/null | grep -oE 'inet [0-9]+(\.[0-9]+){3}' | awk '{print $2}' | head -1 || true)
  if [ -z "$LIMA_VM_IP" ]; then
    echo "error: could not determine ${VM_NAME}'s IP for the kubelet serving cert SAN" >&2
    exit 1
  fi

  if [ ! -f "$KUBELET_TLS_KEY" ] || [ ! -f "$KUBELET_TLS_CRT" ]; then
    openssl ecparam -genkey -name prime256v1 -noout -out "$KUBELET_TLS_KEY"
    openssl req -new -key "$KUBELET_TLS_KEY" \
      -subj "/CN=${VM_NAME}" -sha256 \
      -out "$KUBELET_TLS_CSR"
    openssl x509 -req -in "$KUBELET_TLS_CSR" \
      -CA "$CA_PEM" -CAkey "$CERT_DIR/ca.key" \
      -CAcreateserial -CAserial "$CERT_DIR/ca.srl" \
      -days 365 -sha256 \
      -extfile <(printf 'subjectAltName=IP:127.0.0.1,IP:%s\nextendedKeyUsage=serverAuth\n' "$LIMA_VM_IP") \
      -out "$KUBELET_TLS_CRT"
    rm -f "$KUBELET_TLS_CSR"
    echo "Kubelet serving cert generated (SANs: 127.0.0.1, ${LIMA_VM_IP})."
  else
    echo "Kubelet serving cert already exists, reusing."
  fi
  limactl copy "$KUBELET_TLS_CRT" "${VM_NAME}:/tmp/kubelet-tls.crt"
  limactl copy "$KUBELET_TLS_KEY" "${VM_NAME}:/tmp/kubelet-tls.key"
  limactl shell "$VM_NAME" sudo cp /tmp/kubelet-tls.crt /etc/kubelet-tls.crt
  limactl shell "$VM_NAME" sudo cp /tmp/kubelet-tls.key /etc/kubelet-tls.key
  limactl shell "$VM_NAME" sudo chmod 644 /etc/kubelet-tls.crt
  limactl shell "$VM_NAME" sudo chmod 600 /etc/kubelet-tls.key

  # Write --client-ca-file and --tls-cert-file into the kubelet drop-in (idempotent: overwrite each run).
  limactl shell "$VM_NAME" sudo bash -c "mkdir -p /etc/systemd/system/kubelet.service.d && cat > /etc/systemd/system/kubelet.service.d/u7s.conf <<EOF
[Service]
# klog has no --utc flag, so kubelet's embedded klog lines render whatever local
# time the process inherits; force UTC so kubelet.log matches apiserver.log.
Environment=TZ=UTC
ExecStart=
ExecStart=/usr/bin/kubelet \\\\
  --config=/etc/kubelet-config.yaml \\\\
  --kubeconfig=/etc/kubelet-kubeconfig \\\\
  --client-ca-file=/etc/kubelet-ca.crt \\\\
  --tls-cert-file=/etc/kubelet-tls.crt \\\\
  --tls-private-key-file=/etc/kubelet-tls.key \\\\
  --hostname-override=${VM_NAME} \\\\
  --v=${KUBELET_V}
# Matches kube-proxy.service's LimitNOFILE below — sustained conformance load
# (one FD per container log/exec/attach stream) can exceed the systemd default
# well before kube-proxy's own limit would ever be hit.
LimitNOFILE=1048576
EOF"
  limactl shell "$VM_NAME" sudo systemctl daemon-reload
  echo "Kubelet client-ca-file and TLS serving cert configured."
else
  echo "WARNING: $CA_CERT not found — kubelet client auth will not work (logs/exec will return 401)" >&2
fi

# Restart kubelet so it picks up the new kubeconfig/cert/CA.
echo "Starting kubelet inside VM..."
limactl shell "$VM_NAME" sudo systemctl restart kubelet

# Generate a dedicated client cert for the konnectivity-agent (mTLS with server).
# The server trusts certs signed by the cluster CA; the CA key is only on the Mac host.
WORKDIR="$(dirname "$KUBECONFIG_PATH")"
AGENT_CERT_KEY="$WORKDIR/konnectivity-agent.key"
AGENT_CERT_CRT="$WORKDIR/konnectivity-agent.crt"
AGENT_CERT_CSR="$WORKDIR/konnectivity-agent.csr"
if [ ! -f "$WORKDIR/ca.pem" ]; then
  openssl x509 -in "$WORKDIR/ca.crt" -inform DER -out "$WORKDIR/ca.pem" -outform PEM
fi
if [ ! -f "$AGENT_CERT_KEY" ] || [ ! -f "$AGENT_CERT_CRT" ]; then
  openssl ecparam -genkey -name prime256v1 -noout -out "$AGENT_CERT_KEY"
  openssl req -new -key "$AGENT_CERT_KEY" \
    -subj "/CN=konnectivity-agent" -sha256 \
    -out "$AGENT_CERT_CSR"
  openssl x509 -req -in "$AGENT_CERT_CSR" \
    -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" \
    -CAcreateserial -CAserial "$WORKDIR/ca.srl" \
    -days 365 -sha256 \
    -out "$AGENT_CERT_CRT"
  rm -f "$AGENT_CERT_CSR"
fi

# Create cert Secret for konnectivity-agent pod so the pod can mount the mTLS certs
# without copying binaries or tokens into the VM host filesystem.
# shellcheck disable=SC2086
kubectl --kubeconfig="$KUBECONFIG_PATH" create secret generic konnectivity-agent-certs${NODE_SUFFIX} \
  --from-file=ca.crt="$WORKDIR/ca.pem" \
  --from-file=tls.crt="$WORKDIR/konnectivity-agent.crt" \
  --from-file=tls.key="$WORKDIR/konnectivity-agent.key" \
  -n kube-system \
  --dry-run=client -o yaml | \
  kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f -

# Resolve the Mac host IP so the agent pod can reach the konnectivity-server.
# CoreDNS inside the pod does not know host.lima.internal; inject it as a hostAlias.
# 192.168.5.x (Lima's old default network) used to be hardcoded here as a fallback,
# but this deployment's `networks: - lima: user-v2` (lima/kubelet.yaml) gets a
# different DHCP-assigned subnet (observed: 192.168.104.x) — that fallback would
# silently point the agent's hostAlias at an address that isn't even on this VM's
# network. Fail loud instead, matching the LIMA_VM_IP check above.
LIMA_HOST_IP=$(limactl shell "$VM_NAME" getent hosts host.lima.internal 2>/dev/null | awk '{print $1}')
if [ -z "$LIMA_HOST_IP" ]; then
  echo "error: could not resolve host.lima.internal inside ${VM_NAME} for the konnectivity-agent's hostAlias" >&2
  exit 1
fi

# Run the agent as a Pod in kube-system so it uses CoreDNS: service DNS names like
# e2e-test-webhook.webhook-N.svc resolve correctly inside the pod network.
# hostAliases injects host.lima.internal so the pod can dial the Mac-side server.
kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f - <<PODEOF
apiVersion: v1
kind: Pod
metadata:
  name: konnectivity-agent${NODE_SUFFIX}
  namespace: kube-system
  labels:
    app: konnectivity-agent
spec:
  nodeName: ${VM_NAME}
  hostNetwork: false
  restartPolicy: Always
  hostAliases:
  - ip: "$LIMA_HOST_IP"
    hostnames:
    - host.lima.internal
  tolerations:
  - operator: Exists
  containers:
  - name: konnectivity-agent
    image: registry.k8s.io/kas-network-proxy/proxy-agent:v0.35.0
    args:
    - --logtostderr=true
    - --proxy-server-host=host.lima.internal
    - --proxy-server-port=${KONNECTIVITY_AGENT_PORT}
    - --ca-cert=/certs/ca.crt
    - --agent-cert=/certs/tls.crt
    - --agent-key=/certs/tls.key
    - --agent-identifiers=default-route=true
    - --sync-interval=5s
    - --sync-interval-cap=30s
    volumeMounts:
    - name: certs
      mountPath: /certs
      readOnly: true
  volumes:
  - name: certs
    secret:
      secretName: konnectivity-agent-certs${NODE_SUFFIX}
PODEOF

echo "konnectivity-agent pod applied (logs: kubectl logs -n kube-system konnectivity-agent)"

# kube-proxy runs as a systemd service inside the VM using the kube-proxy binary from the
# official container image. This avoids the pod sandbox loop that occurs with hostNetwork
# pods in u7s (strategic-merge-patch accumulation in podIPs causes the kubelet to
# continuously recreate the sandbox). The binary uses IPVS mode because the Lima VM's
# iptables uses nf_tables which lacks the userspace extension library for protocol matching.

# Detect kubelet version to pull the matching kube-proxy binary. A wrong/stale
# fallback version here is safe, not silent: it only feeds the image tag for the
# "still missing" pull path below, and if that pulls the wrong version and the
# binary still never lands at /usr/local/bin/kube-proxy, the KUBE_PROXY_ACTIVE
# check further down (systemd can't exec a nonexistent binary) already fails the
# script loud with a journalctl dump — this fallback can't produce a silently
# broken kube-proxy.
KUBELET_VERSION=$(limactl shell "$VM_NAME" kubelet --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
KUBELET_VERSION="${KUBELET_VERSION:-1.36.2}"

# Create kube-proxy ServiceAccount and RBAC (needed for the kubeconfig token).
kubectl --kubeconfig="$KUBECONFIG_PATH" create serviceaccount kube-proxy -n kube-system \
  --dry-run=client -o yaml | \
  kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f -

kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f - <<RBACEOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-proxy
rules:
- apiGroups: [""]
  resources: [nodes, services, endpoints]
  verbs: [get, list, watch]
- apiGroups: [""]
  resources: [events]
  verbs: [create, patch, update]
- apiGroups: [discovery.k8s.io]
  resources: [endpointslices]
  verbs: [get, list, watch]
- apiGroups: [networking.k8s.io]
  resources: [servicecidrs]
  verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-proxy
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-proxy
subjects:
- kind: ServiceAccount
  name: kube-proxy
  namespace: kube-system
RBACEOF

# Generate a long-lived token for kube-proxy to authenticate with u7s. No output
# suppression / fallback here: an empty token does not crash kube-proxy — it starts,
# systemd reports it "active", and it just spins forever as system:anonymous,
# failing every List/Watch call ("... is not allowed to list nodes") without ever
# programming an IPVS rule. That is indistinguishable from success to the
# KUBE_PROXY_ACTIVE check below, so a `create token` failure must stop the script
# right here instead of surfacing as an unexplained Service-routing failure later.
KUBE_PROXY_TOKEN=$(kubectl --kubeconfig="$KUBECONFIG_PATH" create token kube-proxy \
  -n kube-system --duration=8760h)

# Write config files to the VM filesystem.
limactl shell "$VM_NAME" sudo mkdir -p /etc/kube-proxy
limactl shell "$VM_NAME" sudo bash -c "cat > /etc/kube-proxy/kubeconfig.conf" <<KUBEEOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://host.lima.internal:${PORT}
    certificate-authority-data: $(base64 < "$WORKDIR/ca.pem" | tr -d '\n')
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
    token: ${KUBE_PROXY_TOKEN}
KUBEEOF

limactl shell "$VM_NAME" sudo bash -c 'cat > /etc/kube-proxy/config.conf' <<'CONFEOF'
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
clusterCIDR: 10.85.0.0/16
clientConnection:
  kubeconfig: /etc/kube-proxy/kubeconfig.conf
CONFEOF

# Extract the kube-proxy binary from the container image if not already present.
# The image is pulled by CRI-O when applying the static pod; we reuse it from the overlay.
if ! limactl shell "$VM_NAME" test -x /usr/local/bin/kube-proxy 2>/dev/null; then
  limactl shell "$VM_NAME" sudo bash -c "
    # Pull image via static pod to populate overlay storage, then copy binary out.
    OVERLAY=\$(find /var/lib/containers/storage/overlay -name 'kube-proxy' -path '*/usr/local/bin/*' 2>/dev/null | head -1)
    if [ -n \"\$OVERLAY\" ]; then
      cp \"\$OVERLAY\" /usr/local/bin/kube-proxy
      chmod +x /usr/local/bin/kube-proxy
      echo 'kube-proxy binary installed from overlay'
    else
      echo 'WARNING: kube-proxy binary not found in overlay; pull the image first' >&2
    fi
  " 2>/dev/null
fi

# If binary is still missing, write a static pod manifest to force CRI-O to pull the image,
# wait for the pull, then extract the binary.
if ! limactl shell "$VM_NAME" test -x /usr/local/bin/kube-proxy 2>/dev/null; then
  echo "Pulling kube-proxy image via static pod (first run)..."
  limactl shell "$VM_NAME" sudo bash -c "cat > /tmp/kubelet-pods/kube-proxy-pull.yaml" <<PULLEOF
apiVersion: v1
kind: Pod
metadata:
  name: kube-proxy-pull
  namespace: kube-system
spec:
  nodeName: ${VM_NAME}
  hostNetwork: true
  containers:
  - name: kube-proxy
    image: registry.k8s.io/kube-proxy:v${KUBELET_VERSION}
    command: ["/usr/local/bin/kube-proxy", "--version"]
PULLEOF
  # Wait for image pull (up to 120s)
  for i in $(seq 1 24); do
    OVERLAY=$(limactl shell "$VM_NAME" sudo bash -c "find /var/lib/containers/storage/overlay -name 'kube-proxy' -path '*/usr/local/bin/*' 2>/dev/null | head -1" 2>/dev/null)
    if [ -n "$OVERLAY" ]; then
      limactl shell "$VM_NAME" sudo cp "$OVERLAY" /usr/local/bin/kube-proxy
      limactl shell "$VM_NAME" sudo chmod +x /usr/local/bin/kube-proxy
      echo "kube-proxy binary installed"
      break
    fi
    sleep 5
  done
  limactl shell "$VM_NAME" sudo rm -f /tmp/kubelet-pods/kube-proxy-pull.yaml
fi

# Install ipset (required by kube-proxy IPVS mode), conntrack (network diagnostics), and
# nfs-common (provides the /sbin/mount.nfs helper). All three are load-bearing — without
# ipset/conntrack kube-proxy crashloops silently, making the kubernetes Service VIP
# unreachable for the entire run; without nfs-common, kubelet's `mount -t nfs` fails with
# "bad option; ... need /sbin/mount.<type> helper program" for every nfs/nfs3 driver
# storage conformance test, even once the PV/PVC bind itself succeeds. No output
# suppression / `|| true` here: let `set -euo pipefail` fail the script loudly
# if either command fails, rather than continuing with a half-provisioned VM.
limactl shell "$VM_NAME" sudo apt-get update
limactl shell "$VM_NAME" sudo apt-get install -y ipset conntrack nfs-common

# Load IPVS and bridge netfilter kernel modules.
# br_netfilter is required so that bridge traffic (pod-to-pod) passes through
# netfilter hooks; without it, IPVS DNAT for ClusterIP services never fires for
# traffic originating from pods, breaking in-pod DNS and service connectivity.
# modprobe of an already-loaded module is a documented no-op (exit 0), so this
# does NOT need `|| true` to be safe on repeat runs — but a genuinely missing
# module (wrong kernel, module not built) also exits nonzero with a FATAL
# message, and that case is load-bearing for kube-proxy's ipvs mode. No
# suppression here (nor on the whole block, previously via a trailing
# `2>/dev/null`): let `set -euo pipefail` fail loud with the real modprobe/sysctl
# error text instead of silently leaving IPVS unable to program any rules.
limactl shell "$VM_NAME" sudo bash -c '
  modprobe ip_vs ip_vs_rr ip_vs_wrr ip_vs_sh
  modprobe br_netfilter
  sysctl -w net.bridge.bridge-nf-call-iptables=1 net.bridge.bridge-nf-call-ip6tables=1 >/dev/null
'

# Write the systemd service unit.
limactl shell "$VM_NAME" sudo bash -c "cat > /etc/systemd/system/kube-proxy.service" <<SVCEOF
[Unit]
Description=Kubernetes Kube Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/kube-proxy \\
  --config=/etc/kube-proxy/config.conf \\
  --hostname-override=${VM_NAME} \\
  --v=${KUBE_PROXY_V}
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVCEOF

limactl shell "$VM_NAME" sudo systemctl daemon-reload
# `systemctl enable`'s own confirmation ("Created symlink ...") is written to
# stderr, not stdout, on a real Linux system — 2>/dev/null here only hides that
# noise. It does not hide a real failure: no `|| true` follows, and verified this
# construct's exit code still propagates through `limactl shell` under
# `set -euo pipefail` (tested against a nonexistent unit: exit 1 as expected), so
# a genuine `enable` failure still stops the script.
limactl shell "$VM_NAME" sudo systemctl enable kube-proxy 2>/dev/null
limactl shell "$VM_NAME" sudo systemctl restart kube-proxy

# Verify kube-proxy actually reached the active state (not stuck crashlooping).
# Without this check, any silent failure (missing ipset, missing kernel module,
# bad config) leaves kube-proxy dead and the kubernetes Service VIP unreachable —
# sonobuoy then hangs indefinitely on "dial tcp 10.96.0.1:443: i/o timeout" with
# no actionable signal to the operator.
KUBE_PROXY_ACTIVE=0
for i in $(seq 1 15); do
  STATUS=$(limactl shell "$VM_NAME" sudo systemctl is-active kube-proxy 2>&1 || true)
  if [ "$STATUS" = "active" ]; then
    KUBE_PROXY_ACTIVE=1
    break
  fi
  sleep 1
done

if [ "$KUBE_PROXY_ACTIVE" -eq 0 ]; then
  echo "ERROR: kube-proxy failed to reach active state (last status: $STATUS)" >&2
  echo "--- kube-proxy log (last 30 lines) ---" >&2
  limactl shell "$VM_NAME" sudo journalctl -u kube-proxy --no-pager -n 30 >&2
  exit 1
fi

echo "kube-proxy systemd service started (logs: limactl shell ${VM_NAME} sudo journalctl -u kube-proxy -n 20)"

# Resolve the host gateway IP used to route the kubernetes ClusterIP. This (and the
# patch below) used to only WARN and continue on failure — but skipping either one
# leaves kube-proxy's IPVS rule for 10.96.0.1:443 pointed at 127.0.0.1 (this node's
# own loopback) instead of the host, which silently breaks every in-cluster Service
# call (including sonobuoy's own liveness dial) while the rest of this script still
# reports success. Fail loud instead.
HOST_IP=$(limactl shell "$VM_NAME" getent hosts host.lima.internal 2>/dev/null | awk '{print $1}')
if [ -z "$HOST_IP" ]; then
  echo "error: could not resolve host.lima.internal inside ${VM_NAME} — cannot patch the kubernetes EndpointSlice with the host gateway IP" >&2
  exit 1
fi
limactl shell "$VM_NAME" sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Patch the kubernetes EndpointSlice with the host IP so kube-proxy's IPVS rule
# routes 10.96.0.1:443 → host (not 127.0.0.1 which is the VM's own loopback).
# The apiserver seeds 127.0.0.1 as a safe default; we correct it here once we
# know the host gateway IP.
echo "Patching kubernetes EndpointSlice with host IP ${HOST_IP}..."
if ! kubectl --kubeconfig="$KUBECONFIG_PATH" patch endpointslice kubernetes -n default \
    --type=json \
    -p="[{\"op\":\"replace\",\"path\":\"/endpoints/0/addresses/0\",\"value\":\"${HOST_IP}\"}]"; then
  echo "error: EndpointSlice patch failed — kube-proxy IPVS will keep routing 10.96.0.1:443 to 127.0.0.1 instead of the host, breaking cluster Service routing for every pod" >&2
  exit 1
fi
echo "EndpointSlice patched: 10.96.0.1:443 → ${HOST_IP}:${PORT}"

# Wait for the node to appear.
echo "Waiting for ${VM_NAME} to register (up to 60s)..."
FOUND=0
for i in $(seq 1 60); do
  if kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes -o name 2>/dev/null | grep -Fxq "node/${VM_NAME}"; then
    FOUND=1
    break
  fi
  sleep 1
done

if [ "$FOUND" -eq 0 ]; then
  echo "ERROR: ${VM_NAME} did not appear within 60s." >&2
  echo "--- kubelet log (last 30 lines) ---" >&2
  limactl shell "$VM_NAME" sudo journalctl -u kubelet --no-pager --utc -n 30 >&2
  exit 1
fi

echo ""
echo "Success! Node registered:"
kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes

# Inter-node pod routes: nothing else programs a path to a peer's pod subnet — no
# CNI/BGP here, by design (static routes over the shared user-v2 network). Re-run
# on every invocation, of this node OR a peer's, because routes don't survive a VM
# reboot. A lone primary has no peers yet, so this loop is a no-op until a 2nd node
# joins; whichever node's lima-start.sh runs re-asserts the pairing both ways, so a
# stale route on either side self-heals the next time either node reconnects.
PEERS=$(kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
THIS_NODE_IP=$(limactl shell "$VM_NAME" ip -4 addr show scope global 2>/dev/null | grep -oE 'inet [0-9]+(\.[0-9]+){3}' | awk '{print $2}' | head -1 || true)
for PEER in $PEERS; do
  [ "$PEER" = "$VM_NAME" ] && continue
  PEER_IP=$(limactl shell "$PEER" ip -4 addr show scope global 2>/dev/null | grep -oE 'inet [0-9]+(\.[0-9]+){3}' | awk '{print $2}' | head -1 || true)
  PEER_SUBNET=$(limactl shell "$PEER" sudo jq -r '.plugins[0].ipam.ranges[0][0].subnet' /etc/cni/net.d/10-crio-bridge.conflist 2>/dev/null || true)
  if [ -z "$PEER_IP" ] || [ -z "$PEER_SUBNET" ] || [ -z "$THIS_NODE_IP" ]; then
    echo "WARNING: could not resolve route info for peer '${PEER}' — skipping inter-node route" >&2
    continue
  fi
  echo "Routing ${VM_NAME} -> ${PEER_SUBNET} via ${PEER_IP} (${PEER})"
  limactl shell "$VM_NAME" sudo ip route replace "$PEER_SUBNET" via "$PEER_IP"
  echo "Routing ${PEER} -> ${POD_SUBNET} via ${THIS_NODE_IP} (${VM_NAME})"
  limactl shell "$PEER" sudo ip route replace "$POD_SUBNET" via "$THIS_NODE_IP"
done

echo ""
echo "Run kubectl commands with:"
echo "  export KUBECONFIG=$KUBECONFIG_PATH"
echo "  kubectl get nodes"
echo "  kubectl run test --image=busybox:1.36 --restart=Never --overrides='{\"spec\":{\"nodeName\":\"${VM_NAME}\",\"hostNetwork\":true,\"dnsPolicy\":\"None\",\"dnsConfig\":{}}}' -- sh -c 'echo hello'"
