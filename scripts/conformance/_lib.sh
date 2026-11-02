#!/usr/bin/env bash
# Shared helpers for scripts/conformance/*.sh and scripts/u7s-start.sh.
# Internal (underscore-prefixed): source this, don't run it directly.

# Two u7s stacks binding the same default host port race for it: whichever
# process boots first wins the bind silently, and the loser either misroutes
# (e.g. a kubelet hostPort forward pointed at the WRONG kubelet) or dies
# inside a spawned binary with the real cause buried in that binary's own log
# instead of a clear message at the point of failure. Hard-fail here rather
# than auto-allocate a free port, so the operator stays the source of truth
# for which stack owns which port (see ai/prompts/vm-operations.md for the
# per-worker port-assignment scheme). Fires regardless of whether the port
# came from a default or was explicitly passed by the operator — a collision
# is a bug either way.
check_port_free() {
  local port="$1"
  local label="$2"
  local holder=""
  if command -v lsof &>/dev/null; then
    # lsof exits 1 (not just empty stdout) when it finds no matching
    # process — the expected, happy-path outcome of THIS check (port is
    # free). Under the caller's `set -euo pipefail`, an unguarded pipeline
    # here aborts the whole script on that exit code before the `[ -n
    # "$holder" ]` check below ever runs, so every genuinely free-port case
    # (the common case on a fresh --reset) killed run-all.sh silently right
    # at this line. `|| true` restores the intended semantics: only the
    # `[ -n "$holder" ]` branch below should ever exit non-zero.
    holder=$(lsof -n -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -1) || true
  elif command -v nc &>/dev/null && nc -z 127.0.0.1 "$port" 2>/dev/null; then
    holder="unknown (lsof not installed; nc -z detected a listener)"
  fi
  if [ -n "$holder" ]; then
    echo "error: host port 127.0.0.1:${port} (${label}) is already bound (a previous stack or another VM is using it)." >&2
    echo "  Assign this stack a different ${label} port — see ai/prompts/vm-operations.md for the per-worker port-assignment scheme." >&2
    echo "  Holder: pid ${holder} ($(ps -o command= -p "$holder" 2>/dev/null | cut -c1-200 || true)) -- NOT signalled; it may belong to another project (Lima auto-forwards guest ports to the same host port)." >&2
    echo "  To see what's holding the port: lsof -n -i :${port}" >&2
    exit 1
  fi
}

# True when the rig kubelet's client cert is unexpired and signed by the current
# CA; anything else (a wiped/rotated CA, expiry) needs re-issuing or the kubelet
# is rejected with 401 on an otherwise healthy stack.
node_client_cert_valid() {
  local crt="$1" ca_pem="$2"
  [ -s "$crt" ] \
    && openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1 \
    && openssl verify -CAfile "$ca_pem" "$crt" >/dev/null 2>&1
}

# Derives the per-node resource suffix (konnectivity-agent Pod/Secret, kubelet
# serving cert) for a VM_NAME. Single source of truth for BOTH lima-start.sh
# (the primary/direct-start path) and add-node.sh (the --extra-node join path)
# so the two can never independently drift back out of sync — that drift once
# had add-node.sh hardcode "-2" regardless of which VM it was actually joining,
# colliding with a primary that itself auto-derives a different numbered
# suffix from its own name.
# Only the bare "lima-node" primary keeps the empty default. Every other
# lima-node-* name (numbered slots AND non-numbered ones like lima-node-smoke)
# derives its suffix from whatever follows "lima-node-" in its own name, so
# lima-node-smoke gets "-smoke" instead of falling back to the same empty
# suffix as the primary -- an empty catch-all here made lima-node-smoke
# collide with lima-node's konnectivity-agent Pod/Secret and kubelet serving
# cert names whenever the two are paired via --extra-node. lima-start.sh's
# POD_SUBNET_OCTET can't parse a non-numeric suffix, so it treats any
# non-numeric NODE_SUFFIX (including "-smoke") the same as the empty case.
node_suffix_for() {
  local vm_name="$1" override="${2:-}"
  case "$vm_name" in
    lima-node) echo "${override:-}" ;;
    lima-node-*) echo "${override:-"-${vm_name#lima-node-}"}" ;;
    *) echo "${override:-}" ;;
  esac
}

# Effective konnectivity-server port for an apiserver port: the explicit
# override, else the auto-derived default (6443→8135, 6444→8235, +100 per port).
# lima-start.sh and add-node.sh both resolve through this so the primary's and
# the extra node's konnectivity-agent always target the same server port.
konnectivity_server_port_for() {
  local port="$1" override="${2:-}"
  if [ -n "$override" ]; then
    echo "$override"
  else
    echo $(( 8135 + (port - 6443) * 100 ))
  fi
}

# Fail loud when an EXISTING VM's baked kubelet hostPort forward differs from
# the requested kubelet port. The forward is fixed at VM creation; a mismatch
# leaves watch/list/get working while kubectl exec/logs/attach silently reach
# the wrong (or no) kubelet. A VM that doesn't exist yet is fine: first
# provision bakes the requested port in.
assert_kubelet_port_matches_vm() {
  local vm="$1" requested="$2" live
  [ -d "${LIMA_HOME:-$HOME/.lima}/$vm" ] || return 0
  live=$("$(dirname "${BASH_SOURCE[0]}")/lima-kubelet-port.sh" "$vm") || return 1
  if [ "$live" != "$requested" ]; then
    echo "error: $vm forwards guest 10250 to host $live, but --kubelet-port=$requested was passed; pass --kubelet-port $live or reprovision" >&2
    return 1
  fi
}

# Network name a Lima VM recorded at creation (its live lima.yaml), empty if none.
lima_network_of() {
  awk '/^networks:/{f=1;next} f&&/lima:/{print $NF;exit}' "${LIMA_HOME:-$HOME/.lima}/$1/lima.yaml"
}

# Fail loud when two VMs of one cluster sit on different Lima networks.
# Separate networks are separate L2 segments, so flannel's VXLAN overlay
# (flannel.1) between them can never deliver a packet; without this check the
# misconfiguration only surfaces later as cross-node pod traffic failing.
# Registered Node names are assumed to equal Lima VM names (kubelet runs with
# --hostname-override=<VM name>), so a peer with no local lima.yaml is an
# error: either a stale Node object or a name mismatch that hides a mispairing.
assert_same_lima_network() {
  local vm="$1" kubeconfig="$2" peers peer vm_net peer_net
  peers=$(kubectl --kubeconfig="$kubeconfig" get nodes -o jsonpath='{.items[*].metadata.name}') || {
    echo "error: cannot list cluster nodes to verify '$vm' shares a Lima network with its peers" >&2
    return 1
  }
  vm_net=$(lima_network_of "$vm")
  for peer in $peers; do
    [ "$peer" = "$vm" ] && continue
    if [ ! -f "${LIMA_HOME:-$HOME/.lima}/$peer/lima.yaml" ]; then
      echo "error: registered node '$peer' has no local Lima VM config, so its network cannot be compared with '$vm'; if the node is stale run 'kubectl delete node $peer', otherwise rerun with --reset" >&2
      return 1
    fi
    peer_net=$(lima_network_of "$peer")
    if [ "$vm_net" != "$peer_net" ]; then
      echo "error: $vm is on network '${vm_net:-none}' but peer node '$peer' is on '${peer_net:-none}'; separate Lima networks have no L2 path, so flannel's cross-node overlay would be unreachable. Pair VMs that share a network." >&2
      return 1
    fi
  done
}

# Rig-only SSH credential for the e2e framework's SSH-to-node helpers
# ([Disruptive] kubelet-down specs). Both lima-start.sh (generates + authorizes)
# and 06-run-sonobuoy.sh (ships to the e2e pod) derive the path from the
# kubeconfig's directory so the two can never diverge on --workdir.
e2e_ssh_key_path() {
  echo "$(dirname "$1")/e2e-ssh/id_ed25519"
}

# Shell command, run as the VM user, that leaves ~/.ssh/authorized_keys holding
# exactly one rig key: earlier rig keys (identified by the key comment) are
# dropped so a wiped workdir with a kept VM doesn't accumulate stale entries.
E2E_SSH_KEY_COMMENT="u7s-rig-e2e"
authorized_keys_replace_cmd() {
  local pubkey="$1"
  echo "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && { grep -v ' ${E2E_SSH_KEY_COMMENT}\$' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.new || true; } && echo '${pubkey}' >> ~/.ssh/authorized_keys.new && cat ~/.ssh/authorized_keys.new > ~/.ssh/authorized_keys && rm -f ~/.ssh/authorized_keys.new"
}

# 06-run-sonobuoy.sh exit codes. Spec failures (results retrieved, Failed>0)
# get their own code so callers can tell "the cluster failed specs" from "the
# rig failed to produce results" (1, or the sonobuoy/retrieval code passed
# through).
SONOBUOY_EXIT_SPEC_FAILURES=10

# Overall exit code from the worst child-pass infra exit (0 if none) and the
# total spec failures: an infra error masks spec failures because the results
# those counts came from may be incomplete.
sonobuoy_exit_code() {
  local infra_exit="$1" spec_failures="$2"
  if [ "$infra_exit" -ne 0 ]; then
    echo "$infra_exit"
  elif [ "$spec_failures" -gt 0 ]; then
    echo "$SONOBUOY_EXIT_SPEC_FAILURES"
  else
    echo 0
  fi
}

# File where 06-run-sonobuoy.sh records the results directory of one pass, so
# run-all.sh resolves the parallel pass's directory explicitly instead of
# taking the newest temp/e2e entry (the disruptive pass's dir when the
# parallel pass dies before creating its own).
sonobuoy_results_dir_file() {
  echo "$1/results-dir.$2"
}

# Prints "<ran> <failed>" for a ginkgo junit file, matching the "Ran X of Y
# Specs" line in e2e.txt. The junit also carries one testcase per suite-level
# node execution (one [SynchronizedBeforeSuite]/[SynchronizedAfterSuite] per
# ginkgo process plus the Report*Suite nodes); those are not specs, so passed
# ones are not counted as ran. Failed ones stay in failures so a broken suite
# node still fails the run.
junit_spec_totals() {
  local junit="$1" tests skipped failures suite_nodes
  tests=$(grep -o 'tests="[0-9]*"' "$junit" | head -1 | grep -o '[0-9]*')
  skipped=$(grep -o 'skipped="[0-9]*"' "$junit" | head -1 | grep -o '[0-9]*')
  failures=$(grep -o 'failures="[0-9]*"' "$junit" | head -1 | grep -o '[0-9]*')
  suite_nodes=$(grep -cE '<testcase name="\[(Report(Before|After)Suite|Synchronized(Before|After)Suite|BeforeSuite|AfterSuite)\][^"]*"[^>]*status="passed"' "$junit" || true)
  echo "$(( tests - ${skipped:-0} - suite_nodes )) ${failures:-0}"
}

_ipv4_to_int() {
  local IFS=. a b c d
  read -r a b c d <<<"$1"
  echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

# Pure decision: returns 0 (stale) when an IPv4 address (with or without /len)
# lies outside the IPv4 pod CIDR. The CNI bridge plugin keeps cni0's address
# across sessions, so a node re-assigned a different podCIDR (state wiped with
# reset.sh --host-only, VM kept) leaves cni0 on the old subnet and flannel
# fails with "failed to set bridge addr". Returns 2 (neither stale nor fresh)
# on a malformed address or CIDR, so a garbage read never triggers a delete.
cni0_addr_is_stale() {
  local addr="${1%%/*}" cidr="$2" net len mask octet
  net="${cidr%%/*}"
  len="${cidr##*/}"
  local ip_re='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
  if ! [[ "$addr" =~ $ip_re && "$net" =~ $ip_re && "$cidr" == */* && "$len" =~ ^[0-9]{1,2}$ ]] || [ "$len" -gt 32 ]; then
    echo "cni0_addr_is_stale: malformed input addr='$1' cidr='$cidr'" >&2
    return 2
  fi
  for octet in ${addr//./ } ${net//./ }; do
    if [ "$octet" -gt 255 ]; then
      echo "cni0_addr_is_stale: octet out of range in addr='$1' cidr='$cidr'" >&2
      return 2
    fi
  done
  mask=$(( len == 0 ? 0 : (0xFFFFFFFF << (32 - len)) & 0xFFFFFFFF ))
  [ $(( $(_ipv4_to_int "$addr") & mask )) -ne $(( $(_ipv4_to_int "$net") & mask )) ]
}

# Deletes <vm>'s cni0 when its IPv4 address is outside <node>'s current IPv4
# podCIDR (the next pod create recreates it correctly). A matching or absent
# cni0 is left alone. Fails loud if no podCIDR is allocated.
reconcile_cni0() {
  local vm="$1" kubeconfig="$2" node="$3" cidr="" addr="" i
  for i in $(seq 1 60); do
    cidr=$(kubectl --kubeconfig="$kubeconfig" get node "$node" -o jsonpath='{.spec.podCIDRs}' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1) || true
    [ -n "$cidr" ] && break
    sleep 1
  done
  if [ -z "$cidr" ]; then
    echo "ERROR: node $node has no IPv4 podCIDR after 60s; cannot reconcile cni0 on $vm" >&2
    return 1
  fi
  addr=$(limactl shell "$vm" ip -4 -o addr show dev cni0 2>/dev/null | grep -oE 'inet [0-9.]+/[0-9]+' | head -1 | cut -d' ' -f2) || true
  if [ -z "$addr" ]; then
    echo "cni0 on $vm: absent (node podCIDR $cidr); nothing to reconcile."
  else
    local rc=0
    cni0_addr_is_stale "$addr" "$cidr" || rc=$?
    case $rc in
      0)
        echo "WARNING: cni0 on $vm has stale address $addr outside node $node podCIDR $cidr; deleting cni0 so it is recreated; pods already on $node lose networking (their veths detach) and must be recreated." >&2
        limactl shell "$vm" sudo ip link delete cni0
        ;;
      1)
        echo "cni0 on $vm: $addr matches podCIDR $cidr; leaving it."
        ;;
      *)
        echo "ERROR: cannot judge cni0 address '$addr' on $vm against node $node podCIDR '$cidr'" >&2
        return 1
        ;;
    esac
  fi
}

# Pod args are immutable, so re-applying a Pod whose args changed aborts the
# script. Applies the Pod manifest on stdin, first deleting the live Pod <pod>
# when its container args differ from <desired_args> (newline-separated). A pod
# that exists but renders no args counts as a difference, not as absent. Fails
# loud if the delete or apply fails.
apply_pod_recreating_on_args_change() {
  local kubeconfig="$1" ns="$2" pod="$3" desired="$4" out exists live manifest
  manifest=$(cat)
  out=$(kubectl --kubeconfig="$kubeconfig" get pod "$pod" -n "$ns" --ignore-not-found \
    -o jsonpath='{.metadata.name}{"\n"}{range .spec.containers[0].args[*]}{@}{"\n"}{end}') || {
    echo "ERROR: cannot read live args of pod $ns/$pod" >&2
    return 1
  }
  exists="${out%%$'\n'*}"
  live="${out#"$exists"}"
  live="${live#$'\n'}"
  live="${live%$'\n'}"
  if [ -n "$exists" ] && [ "$desired" != "$live" ]; then
    echo "pod $ns/$pod args changed; deleting it so the new args can be applied (pod args are immutable)."
    kubectl --kubeconfig="$kubeconfig" delete pod "$pod" -n "$ns" --wait=true || {
      echo "ERROR: failed to delete stale pod $ns/$pod" >&2
      return 1
    }
  fi
  printf '%s\n' "$manifest" | kubectl --kubeconfig="$kubeconfig" apply --validate=false -f - || {
    echo "ERROR: failed to apply pod $ns/$pod" >&2
    return 1
  }
}

# --- Opt-in dual-stack rig (--dual-stack) -----------------------------------
# Lima's user-v2 switch forwards IPv6 unicast between VMs but hands out no
# routable v6 address (no RA/DHCPv6) and drops the multicast NDP that would
# resolve neighbours. So every VM gets a static ULA out of ONE shared /64 plus
# a permanent neighbour entry per peer, re-applied at boot by a oneshot unit.

LAN_V6_PREFIX="fd85:0:0:1"

# Host id inside the shared /64, unique per rig VM name. Fails (non-zero) for
# names it cannot place so two VMs never silently share an address.
lan_v6_host_for() {
  case "$1" in
    lima-node) echo 1 ;;
    lima-node-smoke) echo 100 ;;
    lima-node-[0-9]*)
      local n="${1#lima-node-}"
      case "$n" in *[!0-9]*) return 1 ;; esac
      echo "$n" ;;
    *) return 1 ;;
  esac
}

lan_v6_addr_for() {
  local host
  host=$(lan_v6_host_for "$1") || return 1
  echo "${LAN_V6_PREFIX}::${host}"
}

# Script body run at boot: own address plus one permanent neighbour per peer.
# Args: <iface> <self-addr> [<peer-addr> <peer-mac>]...
lan_v6_script() {
  local iface="$1" self="$2"
  shift 2
  echo "#!/bin/sh"
  echo "ip -6 addr replace ${self}/64 dev ${iface} nodad"
  while [ "$#" -ge 2 ]; do
    echo "ip -6 neigh replace $1 lladdr $2 dev ${iface} nud permanent"
    shift 2
  done
}

lan_v6_vm_iface() {
  limactl shell "$1" ip -4 -o addr show scope global 2>/dev/null | awk '{print $2}' | sed -n 1p
}

# Installs the boot unit on <vm> and applies it now. Idempotent: rewrites both
# files and restarts the unit, so a re-run converges on the given peer set.
# Args: <vm> <iface> <self-addr> [<peer-addr> <peer-mac>]...
lan_v6_install() {
  local vm="$1"
  shift
  lan_v6_script "$@" | limactl shell "$vm" sudo tee /usr/local/sbin/u7s-lan-v6 >/dev/null
  limactl shell "$vm" sudo chmod 0755 /usr/local/sbin/u7s-lan-v6
  limactl shell "$vm" sudo tee /etc/systemd/system/u7s-lan-v6.service >/dev/null <<'UNIT'
[Unit]
Description=u7s dual-stack rig: static ULA and neighbour entries on the user-v2 NIC
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/u7s-lan-v6

[Install]
WantedBy=multi-user.target
UNIT
  limactl shell "$vm" sudo systemctl daemon-reload
  limactl shell "$vm" sudo systemctl enable u7s-lan-v6.service >/dev/null 2>&1
  limactl shell "$vm" sudo systemctl restart u7s-lan-v6.service
}

# Full-mesh seeding across the given running VMs (all on one Lima network).
lan_v6_seed_mesh() {
  local vms=("$@") ifaces=() macs=() addrs=() i j args
  for i in "${!vms[@]}"; do
    ifaces[i]=$(lan_v6_vm_iface "${vms[$i]}")
    [ -n "${ifaces[$i]}" ] || { echo "error: no global IPv4 NIC on ${vms[$i]}" >&2; return 1; }
    addrs[i]=$(lan_v6_addr_for "${vms[$i]}") || { echo "error: no dual-stack host id for ${vms[$i]}" >&2; return 1; }
    macs[i]=$(limactl shell "${vms[$i]}" cat "/sys/class/net/${ifaces[$i]}/address")
  done
  for i in "${!vms[@]}"; do
    args=("${vms[$i]}" "${ifaces[$i]}" "${addrs[$i]}")
    for j in "${!vms[@]}"; do
      [ "$i" = "$j" ] && continue
      args+=("${addrs[$j]}" "${macs[$j]}")
    done
    lan_v6_install "${args[@]}"
  done
}
