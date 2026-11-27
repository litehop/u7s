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

# Restarts the kubelet in <vm> so Lima's port-forward watcher sees guest port
# 10250 go away and come back as two separate events. A plain `systemctl
# restart` unbinds and rebinds inside one scan; the hostagent then handles the
# "removed" after the "added" and closes the host listener it just opened,
# leaving the kubelet's host port dead while the node still reports Ready.
restart_kubelet_spaced() {
  local vm="$1" i
  limactl shell "$vm" sudo systemctl stop kubelet
  for i in $(seq 1 15); do
    limactl shell "$vm" sh -c 'ss -Hltn "sport = :10250" | grep -q .' || break
    sleep 1
  done
  sleep "${KUBELET_PORT_SETTLE_SECS:-6}"
  limactl shell "$vm" sudo systemctl start kubelet
}

# Probes the real apiserver->kubelet path (apiserver -> host kubelet port ->
# Lima forward -> kubelet) for <node>. Node Ready does not prove it: the
# kubelet reports to the apiserver over the other direction.
kubelet_path_ok() {
  local kubeconfig="$1" node="$2" i
  for i in $(seq 1 "${3:-30}"); do
    kubectl --kubeconfig="$kubeconfig" get --raw "/api/v1/nodes/${node}/proxy/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# Args: <kubeconfig> <node=hostport>... Fails loud, naming node and host port,
# when any node's kubelet path stays dead after one spaced kubelet restart
# (which makes Lima re-create the host forward). Node name equals VM name.
verify_kubelet_paths() {
  local kubeconfig="$1" pair node port rc=0
  shift
  for pair in "$@"; do
    node="${pair%%=*}"
    port="${pair#*=}"
    if kubelet_path_ok "$kubeconfig" "$node"; then
      echo "kubelet path OK: apiserver -> $node (host port $port)"
      continue
    fi
    echo "WARNING: apiserver cannot reach kubelet on $node via host port $port; restarting the kubelet so Lima re-creates the forward." >&2
    restart_kubelet_spaced "$node" || true
    if kubelet_path_ok "$kubeconfig" "$node" 60; then
      echo "kubelet path OK after re-establishing the forward: apiserver -> $node (host port $port)"
    else
      echo "ERROR: apiserver->kubelet path to node $node is dead (host port 127.0.0.1:$port); logs/exec/attach would fail with 502. Check 'lsof -nP -iTCP:$port -sTCP:LISTEN' and the VM's ha.stderr.log." >&2
      rc=1
    fi
  done
  return "$rc"
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
  local iface="$1" self="$2" svc_v6
  shift 2
  svc_v6=$(rig_service_cidr_v6) || return 1
  echo "#!/bin/sh"
  echo "ip -6 addr replace ${self}/64 dev ${iface} nodad"
  # Lima VMs have no default v6 route (no RA), so locally originated traffic to
  # a v6 ClusterIP dies with ENETUNREACH before kube-proxy's OUTPUT DNAT runs.
  echo "ip -6 route replace ${svc_v6} dev lo"
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
After=network-online.target systemd-networkd.service
Wants=network-online.target
PartOf=systemd-networkd.service

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

# Dual-stack pod/Service ranges, as scripts/install.sh documents them
# (--cluster-cidr 10.244.0.0/16,fd00:244::/56, --service-cidr
# 10.96.0.0/12,fd00:96::/108; kube-dns is the tenth host of each range).
# Single-stack rigs keep the IPv4 values.
RIG_POD_CIDR_V4="${RIG_POD_CIDR_V4:-10.244.0.0/16}"
RIG_POD_CIDR_V6="fd00:244::/56"
RIG_SERVICE_CIDR_DUAL="10.96.0.0/12,fd00:96::/108"
RIG_SERVICE_CIDR_V4="10.96.0.0/12"

# The Service CIDR(s) the apiserver actually runs with, as run-all.sh exports
# them so lima-start.sh/add-node.sh see a custom --service-cidr. Arg: 1 for
# dual-stack.
rig_effective_service_cidr() {
  if [ "$1" -eq 1 ]; then echo "${RIG_SERVICE_CIDR:-$RIG_SERVICE_CIDR_DUAL}"; else echo "${RIG_SERVICE_CIDR:-$RIG_SERVICE_CIDR_V4}"; fi
}

# Prints the IPv6 member of a comma-separated Service CIDR list (either order).
# Args: [<cidr-list>] (default $RIG_SERVICE_CIDR, else the dual default).
# Fails when there is none.
rig_service_cidr_v6() {
  local part list="${1:-${RIG_SERVICE_CIDR:-$RIG_SERVICE_CIDR_DUAL}}"
  local IFS=,
  for part in $list; do
    case "$part" in *:*) echo "$part"; return 0 ;; esac
  done
  echo "error: --dual-stack needs an IPv6 Service CIDR, got '$list'" >&2
  return 1
}

# Prints the tenth host of a CIDR (kube-dns's VIP: upstream/kubeadm
# convention, and what the apiserver derives when --kube-dns-cluster-ip is
# unset). Fails when the range has fewer than 4 host bits, so the tenth host
# would not be allocatable. Arg: <cidr>.
rig_cidr_tenth_host() {
  local cidr="$1" addr="${1%/*}" plen="${1#*/}"
  if [ "$addr" = "$cidr" ] || ! [[ "$plen" =~ ^[0-9]+$ ]]; then
    echo "error: '$cidr' is not a CIDR" >&2; return 1
  fi
  case "$addr" in
    *:*)
      [ "$plen" -le 124 ] || { echo "error: Service CIDR '$cidr' is too small to contain a tenth host" >&2; return 1; }
      local IFS=: h i x nt=0
      local -a w=()
      if [[ "$addr" == *::* ]]; then
        for x in ${addr%%::*}; do w+=("$x"); done
        for x in ${addr#*::}; do nt=$((nt + 1)); done
        while [ "${#w[@]}" -lt $((8 - nt)) ]; do w+=(0); done
        for x in ${addr#*::}; do w+=("$x"); done
      else
        for x in $addr; do w+=("$x"); done
      fi
      [ "${#w[@]}" -eq 8 ] || { echo "error: '$cidr' is not a valid IPv6 CIDR" >&2; return 1; }
      local -a out=()
      for i in 0 1 2 3 4 5 6 7; do
        h=$((16#${w[$i]:-0} & 0xffff))
        local fixed=$((plen - 16 * i)); [ "$fixed" -gt 0 ] || fixed=0; [ "$fixed" -lt 16 ] || fixed=16
        out+=($((h & (0xffff << (16 - fixed) & 0xffff))))
      done
      out[7]=$((out[7] + 10))
      # RFC 5952: compress the longest run (>=2) of zero hextets, leftmost on a tie.
      local best=-1 bestlen=1 run=0 start=0
      for i in 0 1 2 3 4 5 6 7; do
        if [ "${out[$i]}" -eq 0 ]; then
          [ "$run" -gt 0 ] || start=$i
          run=$((run + 1))
          if [ "$run" -gt "$bestlen" ]; then best=$start; bestlen=$run; fi
        else
          run=0
        fi
      done
      local s="" sep=""
      for i in 0 1 2 3 4 5 6 7; do
        if [ "$i" -eq "$best" ]; then s+="::"; sep=""; continue; fi
        if [ "$best" -ge 0 ] && [ "$i" -gt "$best" ] && [ "$i" -lt $((best + bestlen)) ]; then continue; fi
        s+="$sep$(printf '%x' "${out[$i]}")"; sep=":"
      done
      echo "$s" ;;
    *)
      [ "$plen" -le 28 ] || { echo "error: Service CIDR '$cidr' is too small to contain a tenth host" >&2; return 1; }
      local a b c d
      IFS=. read -r a b c d <<< "$addr"
      local n=$(( (a << 24) | (b << 16) | (c << 8) | d ))
      n=$(( (n & ((0xffffffff << (32 - plen)) & 0xffffffff)) + 10 ))
      echo "$(( n >> 24 & 255 )).$(( n >> 16 & 255 )).$(( n >> 8 & 255 )).$(( n & 255 ))" ;;
  esac
}

# Prints the kube-dns VIP of every family in a comma-separated Service CIDR
# list, one per line, in list order (the first is the Service's clusterIP and
# the kubelet's first clusterDNS). Arg: <cidr-list>.
rig_kube_dns_ips() {
  local part ip
  local IFS=,
  for part in $1; do
    ip=$(rig_cidr_tenth_host "$part") || return 1
    echo "$ip"
  done
}

# KCM pod-CIDR flags. Upstream rejects --node-cidr-mask-size with two cluster
# CIDRs and wants one flag per family (install.sh kcm_node_cidr_mask_flags).
# Arg: 1 for dual-stack.
rig_kcm_cidr_flags() {
  if [ "$1" -eq 1 ]; then
    echo "--cluster-cidr=${RIG_POD_CIDR_V4},${RIG_POD_CIDR_V6} --node-cidr-mask-size-ipv4=24 --node-cidr-mask-size-ipv6=64"
  else
    echo "--cluster-cidr=${RIG_POD_CIDR_V4} --node-cidr-mask-size=24"
  fi
}

# Stages every shipped manifests/*.yaml into <dst> through install.sh's own
# renderer. The rig's apiserver runs on the host, so in-cluster clients
# (kube-proxy) reach it as host.lima.internal:<port>, which the apiserver's
# serving cert carries as a SAN. Args: <dst> <iface> <the iface's MTU> <1 if
# dual-stack> <kube version> <apiserver port>.
# shellcheck disable=SC2034 # the locals are the globals install.sh's renderers read
rig_stage_manifests() {
  local dst="$1" IFACE="$2" nic_mtu="$3" dual="$4" KUBE_VERSION="$5" port="$6"
  local IFACE_IP=host.lima.internal POD_MTU CLUSTER_DNS SERVICE_CIDR part root
  local POD_CLUSTER_CIDR="$RIG_POD_CIDR_V4" POD_CLUSTER_CIDR_IPV4="$RIG_POD_CIDR_V4" POD_CLUSTER_CIDR_IPV6=""
  local SERVICE_CIDR_IPV4="" SERVICE_CIDR_IPV6=""
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  # shellcheck source=scripts/lib/flannel-render.sh
  . "$root/scripts/lib/flannel-render.sh"
  if [ "$dual" -eq 1 ]; then
    POD_CLUSTER_CIDR="${RIG_POD_CIDR_V4},${RIG_POD_CIDR_V6}"
    POD_CLUSTER_CIDR_IPV6="$RIG_POD_CIDR_V6"
  fi
  SERVICE_CIDR="$(rig_effective_service_cidr "$dual")"
  for part in ${SERVICE_CIDR//,/ }; do
    case "$part" in *:*) SERVICE_CIDR_IPV6="$part" ;; *) SERVICE_CIDR_IPV4="$part" ;; esac
  done
  CLUSTER_DNS="$(rig_kube_dns_ips "$SERVICE_CIDR" | sed -n 1p)" || return 1
  POD_MTU="$(derive_pod_mtu "$nic_mtu" "$dual")" || return 1
  stage_vendored_manifests "$root/manifests" "$dst" || return 1
  if [ -f "$dst/kube-proxy.yaml" ]; then
    sed -e "s#https://${IFACE_IP}:6443#https://${IFACE_IP}:${port}#g" "$dst/kube-proxy.yaml" > "$dst/kube-proxy.yaml.tmp" || return 1
    mv "$dst/kube-proxy.yaml.tmp" "$dst/kube-proxy.yaml"
  fi
}

# Prints the text of top-level function <name> from <script> (opening line to the closing
# "}" at column 0); empty when absent.
install_sh_function() {
  awk -v f="$1" '$0 == f "() {" {p=1} p {print} p && /^}$/ {exit}' "$2"
}

# Node prep the rig shares with install.sh: CRI-O's memory drop-in, br_netfilter and the
# persisted sysctls (ip_forward, IPv6 forwarding when dual-stack). The block is cut out of
# install.sh between these two lines and replayed in the VM, so the rig cannot drift from it.
RIG_NODE_PREP_FIRST="cat > /etc/crio/crio.conf.d/10-memory.conf <<'CRIO_MEM_EOF'"
RIG_NODE_PREP_LAST='sysctl --system >/dev/null'

# Prints a bash script that applies install.sh's node-prep block and restarts CRI-O when
# its memory drop-in changed. Args: <1 if dual-stack> <install.sh path>. Fails if the block
# markers are gone from install.sh.
rig_node_prep_script() {
  local dual="$1" install_sh="$2" block v6=""
  block="$(awk -v b="$RIG_NODE_PREP_FIRST" -v e="$RIG_NODE_PREP_LAST" '$0 == b {p=1} p {print} p && $0 == e {exit}' "$install_sh")"
  if [ "$(printf '%s\n' "$block" | sed -n '1p;$p')" != "$(printf '%s\n%s' "$RIG_NODE_PREP_FIRST" "$RIG_NODE_PREP_LAST")" ]; then
    echo "error: install.sh's node-prep block ('$RIG_NODE_PREP_FIRST' .. '$RIG_NODE_PREP_LAST') not found; update RIG_NODE_PREP_FIRST/LAST" >&2
    return 1
  fi
  [ "$dual" -eq 1 ] && v6="$RIG_POD_CIDR_V6"
  printf 'set -euo pipefail\nSERVICE_CIDR_IPV6=%q\nPOD_CLUSTER_CIDR_IPV6=%q\nmkdir -p /etc/crio/crio.conf.d\nbefore="$(cat /etc/crio/crio.conf.d/10-memory.conf 2>/dev/null || true)"\n%s\n[ "$before" = "$(cat /etc/crio/crio.conf.d/10-memory.conf)" ] || systemctl restart crio\n' \
    "$v6" "$v6" "$block"
}

# Where the rig keeps the kubelet's config and CA bundle (install.sh keeps them in
# /var/lib/u7s; the rig uses its own directory so an install on the same VM never sees them).
RIG_KUBELET_STATE_DIR=/etc/u7s-rig
# shellcheck disable=SC2034 # used by lima-start.sh
RIG_KUBELET_CONFIG="$RIG_KUBELET_STATE_DIR/kubelet-config.yaml"

# Kubelet settings the rig adds on top of install.sh's KubeletConfiguration, recorded in
# run-meta. Image-pull tuning: HTTP/2 removed the pod-admission pacing that hid the
# single-worker pull queue under 16-way load, and a csi-hostpath focus lands 100+ pulls
# within seconds, which the default registryPullQPS=5 rejects ("pull QPS exceeded", 0 specs
# started); 0 is kubelet's documented "unlimited". AtomicWriteVolumeUserFields is
# default-off alpha; without it projected defaultUser/user are ignored.
RIG_KUBELET_OVERLAY='serializeImagePulls: false
maxParallelImagePulls: 10
registryPullQPS: 0'
RIG_KUBELET_GATE=AtomicWriteVolumeUserFields
RIG_ONLY_KUBELET_CONFIG="serializeImagePulls=false,maxParallelImagePulls=10,registryPullQPS=0,featureGates.${RIG_KUBELET_GATE}=true"

# Prints a bash script that renders the kubelet config with install.sh's own
# write_kubelet_config_yaml (control-plane form: clientCAFile is the CA bundle) into
# RIG_KUBELET_CONFIG and appends RIG_KUBELET_OVERLAY. Args: <first clusterDNS VIP>
# <install.sh path>. The gate is merged separately (set-kubelet-featuregate.sh).
rig_kubelet_config_script() {
  local fn
  fn="$(install_sh_function write_kubelet_config_yaml "$2")"
  [ -n "$fn" ] || { echo "error: write_kubelet_config_yaml not found in $2" >&2; return 1; }
  printf 'set -euo pipefail\nSTATE_DIR=%s\nCLUSTER_DNS=%s\ninstall -d -m 0755 /etc/u7s/static-pods\ninstall -d -m 0700 "$STATE_DIR"\n%s\nwrite_kubelet_config_yaml 0\ncat >> "$STATE_DIR/kubelet-config.yaml" <<'"'"'RIG_KUBELET_EOF'"'"'\n%s\nRIG_KUBELET_EOF\n' \
    "$RIG_KUBELET_STATE_DIR" "$1" "$fn" "$RIG_KUBELET_OVERLAY"
}

# Rig-only additions to the kubelet unit install.sh renders, written as a drop-in and
# recorded in run-meta (RIG_ONLY_SETUP): klog has no --utc flag, so TZ=UTC keeps kubelet.log
# aligned with apiserver.log; sustained load needs more FDs than systemd's default (one per
# log/exec/attach stream).
RIG_KUBELET_DROPIN='[Service]
Environment=TZ=UTC
LimitNOFILE=1048576'

# The rig VM is the control-plane node (the apiserver is started with --local-node-name <VM>),
# so its kubelet gets the identity install.sh gives the control-plane node: a kubelet-client
# CSR submitted with the admin kubeconfig, approved and signed by KCM (a bootstrap-token join
# is refused for the local node's name). The two functions below are install.sh's own.

# Prints a script that exits 0 when the VM already holds a kubelet kubeconfig and an unexpired
# client cert chaining to the current CA (install.sh's current_client_cert, replayed), so a
# re-run keeps the identity the kubelet already rotated. Args: <install.sh path>.
rig_kubelet_identity_script() {
  local fn
  fn="$(install_sh_function current_client_cert "$1")"
  [ -n "$fn" ] || { echo "error: current_client_cert not found in $1" >&2; return 1; }
  printf 'set -euo pipefail\nSTATE_DIR=%s\n%s\n[ -s "$STATE_DIR/kubelet-kubeconfig" ]\ncurrent_client_cert >/dev/null\n' "$RIG_KUBELET_STATE_DIR" "$fn"
}

# Prints a script, run on the host, that issues the node identity with install.sh's own
# issue_cp_kubelet_identity: key and CSR, submission under the admin kubeconfig, wait for
# KCM to sign. It writes <state dir>/kubelet-client.{crt,key} and kubelet-kubeconfig; the
# state dir must already hold the admin kubeconfig as `kubeconfig` and `ca-bundle.pem`.
# Substitutions: generate_node_csr (install.sh's runs the release tarball's u7s-apiserver,
# which is not a Linux binary here) builds the same CSR with openssl (P-256,
# CN=system:node:<name>, O=system:nodes); base64 accepts GNU's -w0 on macOS.
# Args: <install.sh path> <state dir> <node name>.
rig_kubelet_issue_script() {
  local issue current
  issue="$(install_sh_function issue_cp_kubelet_identity "$1")"
  current="$(install_sh_function current_client_cert "$1")"
  if [ -z "$issue" ] || [ -z "$current" ]; then
    echo "error: issue_cp_kubelet_identity or current_client_cert not found in $1" >&2
    return 1
  fi
  printf 'set -euo pipefail\nSTATE_DIR=%q\nNODE_NAME=%q\nensure_jq() { command -v jq >/dev/null; }\nbase64() { if [ "${1:-}" = -w0 ]; then shift; command base64 "$@" | tr -d "\\n"; else command base64 "$@"; fi; }\ngenerate_node_csr() {\n  openssl ecparam -genkey -name prime256v1 -noout -out "$1"\n  chmod 600 "$1"\n  openssl req -new -key "$1" -subj "/O=system:nodes/CN=system:node:$NODE_NAME" -sha256 -out "$2"\n}\n%s\n%s\nissue_cp_kubelet_identity\n' \
    "$2" "$3" "$current" "$issue"
}

# Prints a script that writes install.sh's control-plane kubelet.service (the second
# kubelet.service heredoc, with kubelet_round2_flags for the installed kubelet's minor)
# plus the RIG_KUBELET_DROPIN drop-in, then reloads systemd. Two lines are cut because
# the rig has no u7s-apiserver unit on the VM: Requires/After on it and the ExecStartPre
# that converts its ca.crt. --cert-dir points at $RIG_KUBELET_STATE_DIR, so rotated certs
# never land in /var/lib/kubelet/pki. Args: <install.sh path> <node name> <comma-separated
# node IPs>.
rig_kubelet_unit_script() {
  local flags unit
  flags="$(install_sh_function kubelet_round2_flags "$1")"
  unit="$(awk '/^[[:space:]]*cat > \/etc\/systemd\/system\/kubelet\.service <<EOF$/ {n++} n == 2 {print} n == 2 && /^EOF$/ {exit}' "$1" \
    | sed -e 's/ u7s-apiserver\.service//' -e '/^ExecStartPre=/d')"
  if [ -z "$flags" ] || [ -z "$unit" ]; then
    echo "error: kubelet_round2_flags or the control-plane kubelet.service block not found in $1" >&2
    return 1
  fi
  printf 'set -euo pipefail\nSTATE_DIR=%s\nBIN_DIR=/usr/bin\nNODE_NAME=%q\nNODE_IPS=%q\ninstall -d -m 0700 "$STATE_DIR"\n%s\nKUBE_MINOR="$(/usr/bin/kubelet --version | grep -oE "[0-9]+\\.[0-9]+" | sed -n 1p)"\nKUBELET_ROUND2_FLAGS="$(kubelet_round2_flags "$KUBE_MINOR")"\n%s\nmkdir -p /etc/systemd/system/kubelet.service.d\ncat > /etc/systemd/system/kubelet.service.d/u7s.conf <<'"'"'RIG_DROPIN_EOF'"'"'\n%s\nRIG_DROPIN_EOF\nsystemctl daemon-reload\n' \
    "$RIG_KUBELET_STATE_DIR" "$2" "$3" "$flags" "$unit" "$RIG_KUBELET_DROPIN"
}

# Package pins the rig VMs must run: cri-o and kubelet as pinned in lima/kubelet.yaml's
# provision script, and CNI plugins at the version install tarballs ship
# (scripts/lib/release-fetch.sh). A clone's frozen provision script, or a held package,
# can leave a VM on other versions silently.
# lima_yaml_pin <yaml> <VAR>: the value of VAR="..." in the yaml's provision script.
lima_yaml_pin() {
  sed -n "s/^ *$2=\"\\([^\"]*\\)\".*/\\1/p" "$1" | sed -n 1p
}

# Fails loud, naming each mismatch, when <vm>'s cri-o, kubelet or kubernetes-cni (CNI
# plugins) differ from the pins. Args: <vm> <lima yaml> <release-fetch.sh>.
assert_vm_package_pins() {
  local vm="$1" yaml="$2" fetch="$3" crio_pin kubelet_pin cni_pin have bad=0 pair pkg pin
  crio_pin="$(lima_yaml_pin "$yaml" CRIO_VERSION)"
  kubelet_pin="$(lima_yaml_pin "$yaml" KUBELET_PKG_VERSION)"
  cni_pin="$(sed -n 's/^CNI_PLUGINS_VERSION="\([^"]*\)"$/\1/p' "$fetch")"
  if [ -z "$crio_pin" ] || [ -z "$kubelet_pin" ] || [ -z "$cni_pin" ]; then
    echo "error: could not read CRIO_VERSION/KUBELET_PKG_VERSION from $yaml or CNI_PLUGINS_VERSION from $fetch" >&2
    return 1
  fi
  for pair in "cri-o=$crio_pin" "kubelet=$kubelet_pin" "kubernetes-cni=$cni_pin"; do
    pkg="${pair%%=*}"
    pin="${pair#*=}"
    have="$(limactl shell "$vm" dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
    # The CNI pin is the upstream plugin version; the apt package adds a revision suffix.
    case "$pkg:$have" in
      kubernetes-cni:"$pin"-*) ;;
      "$pkg:$pin") ;;
      *) echo "error: $vm runs $pkg '${have:-not installed}' but the rig pins '$pin'; the provision script that applies pins runs at boot (limactl stop $vm, then re-run), or re-bake lima-golden (scripts/conformance/lima-golden-bake.sh --force)" >&2
         bad=1 ;;
    esac
  done
  return "$bad"
}

# A VM cloned from lima-golden carries the golden's lima.yaml, so it re-runs the golden's
# frozen provision script at every boot, not the current lima/kubelet.yaml's: pin bumps and
# removed steps never reach it. Replaces <vm>'s provision with <yaml>'s when they differ;
# only valid while the VM is stopped. Args: <vm> <lima yaml>.
lima_sync_provision() {
  local vm="$1" yaml="$2" want have
  want="$(limactl template yq "$yaml" '.provision | to_json')" || return 1
  have="$(limactl template yq "$HOME/.lima/$vm/lima.yaml" '.provision | to_json')" || return 1
  [ "$want" != "$have" ] || return 0
  echo "Syncing $vm's provision script with $(basename "$yaml") (it was cloned from an older lima-golden)..."
  limactl edit "$vm" --tty=false --set ".provision = $(printf '%s' "$want" | jq -c .)"
}

# Add-ons applied after install.sh purely so specs that need them can run; u7s does not
# ship them. Comma-separated, in the order install-bringup.sh applies them.
RIG_ONLY_ADDONS="metrics-server,external-snapshotter,kube-network-policies"
# shellcheck disable=SC2034 # used by install-bringup.sh
RIG_ONLY_LABEL="u7s.io/conformance-rig-only=true"

# Rig-only AppArmor rule u7s does not ship: a container process stacked under a host
# dig/nslookup profile is labelled "dig//&u7s-default", which u7s-default's own
# peer=u7s-default//&* does not match, so BIND's self-signal is DENIED (rc 139).
# Both topologies add this rule to u7s-default (install.sh's profile is untouched) plus
# the matching host dig/nslookup overrides below; either layer alone still denies.
RIG_ONLY_SETUP="apparmor-u7s-default-dig-nslookup,apparmor-host-dig-nslookup,apparmor-host-dig-results-write"
# Every other rig-only step, one token each. Both topologies: the CRI-O test-handler
# runtime (lima/kubelet.yaml), the [Disruptive] ssh key, the sonobuoy aggregator LimitRange,
# and the VM packages and log limits of rig_apply_vm_rig_setup.
RIG_ONLY_SETUP="$RIG_ONLY_SETUP,crio-test-handler-runtime,e2e-ssh-key,sonobuoy-aggregator-limitrange,vm-nfs-common,vm-journald-limits,vm-logrotate-interval"
# Host rig only (lima-start.sh): the kubelet unit drop-in.
RIG_ONLY_HOST_SETUP="kubelet-unit-dropin-tz-nofile"
# Host-rig topology differences from install.sh: where the control plane runs and how it
# reaches the node.
RIG_ONLY_HOST_DEVIATIONS="host-side-apiserver,konnectivity-server,konnectivity-agent"
RIG_AA_ANCHOR='  signal (send,receive) peer=u7s-default//&*,'
RIG_AA_RULE='  signal (send,receive) peer={dig,nslookup}//&u7s-default,'

# Filter: u7s-default profile text on stdin -> same text with RIG_AA_RULE after the
# anchor line. An already-present rule passes through unchanged (idempotent); a missing
# or duplicated anchor fails so a profile restructure cannot silently drop the rule.
rig_aa_with_rule() {
  awk -v a="$RIG_AA_ANCHOR" -v r="$RIG_AA_RULE" '
    {buf[NR] = $0; if ($0 == r) have = 1; if ($0 == a) n++}
    END {
      if (!have && n != 1) exit 1
      for (i = 1; i <= NR; i++) { print buf[i]; if (!have && buf[i] == a) print r }
    }'
}

# Rig-only host layer: the host's dig/nslookup profiles (Ubuntu 26.04) also deny the
# stacked peer "dig//&u7s-default", so each gets a local override allowing it. Written
# idempotently and reloaded; a failed reload restores the previous override (or removes
# it) so no half-applied rule is left behind. dig also gets write on /results/**: the
# DNS conformance specs redirect dig's stdout there, and the host profile DENIES
# file_inherit on that fd, so dig aborts (libuv assertion) and the lookup file is empty.
RIG_AA_HOST_SCRIPT='set -euo pipefail
sig="signal (send,receive) peer=@{profile_name}//&u7s-default,"
for p in dig nslookup; do
  [ -f /etc/apparmor.d/$p ] || continue
  want="$sig"
  if [ $p = dig ]; then want="$sig
owner /results/** w,"; fi
  rm -f /etc/apparmor.d/disable/$p
  f=/etc/apparmor.d/local/$p
  if [ "$(cat $f 2>/dev/null || true)" != "$want" ] || ! grep -q "^$p (" /sys/kernel/security/apparmor/profiles; then
    had=0; old=""
    if [ -f $f ]; then had=1; old="$(cat $f)"; fi
    printf "%s\n" "$want" > $f
    if ! apparmor_parser -r /etc/apparmor.d/$p; then
      if [ $had = 1 ]; then printf "%s\n" "$old" > $f; else rm -f $f; fi
      apparmor_parser -r /etc/apparmor.d/$p || true
      exit 1
    fi
  fi
done'

# Both topologies, after u7s-default is installed: applies both rig-only AppArmor layers
# (the u7s-default rule edited in place and reloaded, then the host overrides). A failed
# u7s-default reload, or a failed host layer, restores the previous profile so the step is
# all-or-nothing. Idempotent; fails loud if the anchor
# line is gone. No-op without AppArmor. Args: <vm>.
rig_apply_apparmor_rig_setup() {
  local vm="$1" cur new
  limactl shell "$vm" sh -c '[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ] && command -v apparmor_parser >/dev/null' || return 0
  cur="$(limactl shell "$vm" sudo cat /etc/apparmor.d/u7s-default)" \
    || { echo "FATAL: cannot read installed /etc/apparmor.d/u7s-default on $vm" >&2; return 1; }
  new="$(printf '%s\n' "$cur" | rig_aa_with_rule)" \
    || { echo "FATAL: u7s-default anchor line '$RIG_AA_ANCHOR' not found exactly once in installed profile" >&2; return 1; }
  if [ "$new" != "$cur" ]; then
    printf '%s\n' "$new" | limactl shell "$vm" sudo tee /etc/apparmor.d/u7s-default >/dev/null
    if ! limactl shell "$vm" sudo apparmor_parser -r -W /etc/apparmor.d/u7s-default; then
      printf '%s\n' "$cur" | limactl shell "$vm" sudo tee /etc/apparmor.d/u7s-default >/dev/null
      limactl shell "$vm" sudo apparmor_parser -r -W /etc/apparmor.d/u7s-default || true
      return 1
    fi
  fi
  if ! limactl shell "$vm" sudo bash -c "$RIG_AA_HOST_SCRIPT"; then
    if [ "$new" != "$cur" ]; then
      printf '%s\n' "$cur" | limactl shell "$vm" sudo tee /etc/apparmor.d/u7s-default >/dev/null
      limactl shell "$vm" sudo apparmor_parser -r -W /etc/apparmor.d/u7s-default || true
    fi
    return 1
  fi
}

# Both topologies: VM userspace additions u7s does not ship -- log rotation and journald
# retention sized for a long conformance run, and nfs-common (the /sbin/mount.nfs helper
# every nfs/nfs3 storage spec needs; without it kubelet's `mount -t nfs` fails with "need
# /sbin/mount.<type> helper program"). Idempotent; fails loud on any step. Args: <vm>.
rig_apply_vm_rig_setup() {
  local vm="$1"
  # Cap syslog growth: rotate at 2GB (keep 2 rotations = max 6GB) so a long conformance
  # run does not exhaust disk. Overwrites the distro rsyslog config to split syslog
  # (size-based) from the remaining logs (weekly). Written on every start so it survives
  # VM reprovisions.
  limactl shell "$vm" sudo bash -c 'cat > /etc/logrotate.d/rsyslog' <<'LOGROTATEOF'
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
  limactl shell "$vm" sudo bash -c 'mkdir -p /etc/systemd/system/logrotate.timer.d && cat > /etc/systemd/system/logrotate.timer.d/override.conf' <<'EOF'
[Timer]
OnCalendar=
OnCalendar=*-*-* *:00/2:00
RandomizedDelaySec=0
EOF
  limactl shell "$vm" sudo systemctl daemon-reload
  limactl shell "$vm" sudo systemctl restart logrotate.timer

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
  # rate; going further eats into the VM disk conformance tests themselves need.
  # That margin was the original constraint: at the 20GiB disk ceiling this
  # drop-in was written against, only ~14G was free with base images pulled —
  # tight enough that it's part of what tripped the DiskPressure storm above.
  # The disk ceiling (lima/kubelet.yaml) has since doubled to 40GiB specifically
  # to fix that trigger (~33G free now observed with only base images pulled),
  # so 6G stays a deliberate compromise against overall journal disk usage, not
  # one forced by a tight VM-disk margin anymore.
  limactl shell "$vm" sudo bash -c 'mkdir -p /etc/systemd/journald.conf.d && cat > /etc/systemd/journald.conf.d/conformance.conf' <<'EOF'
[Journal]
RateLimitBurst=100000
RateLimitIntervalSec=30s
SystemMaxUse=5G
SystemMaxFileSize=32M
SystemMaxFiles=160
SystemKeepFree=100M
Storage=persistent
EOF
  limactl shell "$vm" sudo systemctl restart systemd-journald

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
  limactl shell "$vm" sudo journalctl --rotate
  limactl shell "$vm" sudo journalctl --vacuum-size=1M

  limactl shell "$vm" sudo apt-get -o DPkg::Lock::Timeout=300 update
  limactl shell "$vm" sudo apt-get -o DPkg::Lock::Timeout=300 install -y nfs-common
}

# Cargo features of the host-rig apiserver binary. Args: <prebuilt 0|1> <profile 0|1>
# <pki-knobs 0|1>. Every enabled feature is listed; a prebuilt binary's features are unknown.
rig_build_features() {
  if [ "$1" = 1 ]; then echo "prebuilt-binary"; return; fi
  local f="rig-test-knobs"
  [ "$2" != 1 ] || f="$f,dhat"
  [ "$3" != 1 ] || f="$f,pki-test-knobs"
  echo "$f"
}

# Topology a run archive was produced on. "host-rig": apiserver on the Mac, kubelet-only
# VM. "install": the real scripts/install.sh on the VM (the release sign-off path).
# A host-rig PASS is not a delivered-behaviour PASS, so every archive says which it is.
# Args: <run-dir> <host-rig|install>. Install archives also list the rig-only add-ons
# applied on top of what install.sh delivers.
write_run_meta() {
  local run_dir="$1" topology="$2"
  case "$topology" in
    host-rig|install) ;;
    *) echo "write_run_meta: topology must be host-rig or install, got '$topology'" >&2; return 1 ;;
  esac
  mkdir -p "$run_dir"
  {
    echo "topology=$topology"
    echo "rig_only_addons=$RIG_ONLY_ADDONS"
    if [ "$topology" = "host-rig" ]; then
      echo "rig_only_setup=$RIG_ONLY_SETUP,$RIG_ONLY_HOST_SETUP"
      echo "rig_only_deviations=$RIG_ONLY_HOST_DEVIATIONS"
      echo "rig_only_kubelet_config=$RIG_ONLY_KUBELET_CONFIG"
      echo "rig_only_build_features=${U7S_RIG_BUILD_FEATURES:-unknown}"
    else
      echo "rig_only_setup=$RIG_ONLY_SETUP"
    fi
  } > "$run_dir/run-meta"
}

# Appends the cluster's node count to a run archive's run-meta, so a 2-node archive never
# reads as single-node. Args: <run-dir> <node count>.
run_meta_record_nodes() {
  echo "nodes=$2" >> "$1/run-meta"
}

# Prints, one per line, the names of run-all.sh options that only configure the host
# rig and so cannot be honoured by --install mode. Args: <name>=<value> pairs; an
# empty value means "not given".
install_mode_incompatible_flags() {
  local pair
  for pair in "$@"; do
    if [ -n "${pair#*=}" ]; then echo "${pair%%=*}"; fi
  done
}

# Reads install.sh --mint-join-token's output on stdin and prints the join URL, the token
# and the CA hash, one per line. Fails when any is missing.
join_fields_from_mint_output() {
  local out server token hash
  out="$(cat)"
  server="$(sed -n 's/^ *install\.sh --join \([^ ]*\) .*/\1/p' <<<"$out")"
  token="$(sed -n 's/^Join token created.*: //p' <<<"$out")"
  hash="$(grep -oE 'sha256:[0-9a-f]{64}' <<<"$out" | head -1)" || true
  if [ -z "$server" ] || [ -z "$token" ] || [ -z "$hash" ]; then
    echo "error: could not parse the join URL, token and CA hash from --mint-join-token output" >&2
    return 1
  fi
  printf '%s\n%s\n%s\n' "$server" "$token" "$hash"
}

# True when <pid> is an ssh process forwarding exactly 127.0.0.1:<port> (this slot's
# install-mode apiserver tunnel). Guards pidfile-driven kills against a recycled PID,
# including one now owned by another slot's tunnel.
is_install_tunnel_pid() {
  local cmd
  [ -n "${2:-}" ] || return 1
  cmd=$(ps -p "$1" -o command= 2>/dev/null) || return 1
  case "$cmd" in
    *ssh*" -L 127.0.0.1:$2:"*) return 0 ;;
    *) return 1 ;;
  esac
}

# The file install.sh writes first thing in every mode (control plane, worker, partial run)
# and install-teardown.sh removes last; the rig never writes it. Its presence means the VM
# carries install.sh state that fights the host rig ("node has no IPv4 podCIDR").
INSTALL_STATE_MARKER=/etc/u7s-install-started

# vm_install_state_probe <vm>: never starts the VM. Returns 0 marker present, 1 marker absent
# (or the VM does not exist), 2 the probe itself failed (ssh/shell error, unexpected output),
# 3 the VM exists but is not Running.
vm_install_state_probe() {
  local vm="$1" status out
  status=$(limactl list --format '{{.Status}}' "$vm" 2>/dev/null) || return 1
  [ -n "$status" ] || return 1
  [ "$status" = Running ] || return 3
  out=$(limactl shell "$vm" sh -c "if [ -e $INSTALL_STATE_MARKER ]; then echo present; else echo absent; fi") || {
    echo "error: probing $vm for install state failed (limactl shell exited non-zero)" >&2
    return 2
  }
  case "$out" in
    present) return 0 ;;
    absent) return 1 ;;
    *) echo "error: probing $vm for install state returned '$out', expected present|absent" >&2; return 2 ;;
  esac
}

# teardown_if_install_state <dir> <workdir> <vm>=<kubelet port>...: runs install-teardown.sh for
# each VM in install state; returns non-zero if a probe or a teardown fails. A stopped VM is
# started the way lima-start.sh does (port check, provision sync) before it is probed.
teardown_if_install_state() {
  local dir="$1" workdir="$2" spec vm port rc
  shift 2
  for spec in "$@"; do
    vm="${spec%%=*}"; port="${spec#*=}"
    rc=0; vm_install_state_probe "$vm" || rc=$?
    if [ "$rc" -eq 3 ]; then
      echo "[run-all] $vm is stopped; starting it to probe for install state" >&2
      check_port_free "$port" "kubelet" || return 1
      lima_sync_provision "$vm" "$dir/../../lima/kubelet.yaml" || return 1
      limactl start "$vm" >&2 || return 1
      rc=0; vm_install_state_probe "$vm" || rc=$?
    fi
    case "$rc" in
      0) ;;
      1) continue ;;
      *) echo "error: cannot determine whether $vm is in install state; refusing to bring up the host rig" >&2; return 1 ;;
    esac
    echo "[run-all] $vm is in install state; running install-teardown.sh" >&2
    bash "$dir/install-teardown.sh" --vm "$vm" --workdir "$workdir" || {
      echo "error: install-teardown.sh failed for $vm; the host rig cannot run on top of install state" >&2
      return 1
    }
  done
}

# Prints the per-VM default Lima network. Single source for lima-start.sh and
# install-bringup.sh; mirrors the Network column of the Lima VM protocol table in the
# dispatch template doc. VMs outside the known set fall back to the flat "user-v2".
default_network_for_vm() {
  case "$1" in
    lima-node) echo "user-v2-mayor" ;;
    lima-node-2|lima-node-3|lima-node-4) echo "user-v2-workers-a" ;;
    lima-node-5|lima-node-smoke) echo "user-v2-workers-b" ;;
    *) echo "user-v2" ;;
  esac
}
