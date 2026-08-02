#!/usr/bin/env bash
# Live kernel/network-state capture, run INSIDE the guest VM, to catch a VIP
# `i/o timeout` in the act and correlate the failure timestamp against
# per-layer evidence: Mac somaxconn accept-queue overflow (visible only from
# the host side), shared `limactl usernet` capacity (indirect — no direct
# counters, inferred from guest-side symptoms), or guest conntrack/IPVS
# desync (direct — conntrack -S / ipvsadm --stats below).
#
# Appends a timestamped snapshot to $LOG every 2s. Intended to run for the
# duration of a `[Conformance]` sonobuoy run, started before sonobuoy and
# stopped (or just left running, it's append-only) after.
#
# Usage (from inside the guest, or via `limactl shell <vm> -- bash /path/to/this.sh`):
#   instrument-vip-capture.sh [logfile] [vip] [port]
#
# Prerequisite: `conntrack` and `ipvsadm` are not preinstalled on the Lima
# conformance image, and a `--reset` reprovision wipes them again — install
# fresh on every reset before starting this script:
#   limactl shell <vm> sudo apt-get install -y conntrack ipvsadm
#
# Companion capture (run separately, also inside the guest):
#   sudo tcpdump -i any -w /tmp/vip-capture.pcap -s 128 host <vip> or port 6443
set -uo pipefail

LOG="${1:-/tmp/vip-instrumentation.log}"
VIP="${2:-10.96.0.1}"
PORT="${3:-443}"

: > "$LOG"

while true; do
  {
    date -u --iso-8601=ns
    echo "--ss-s--"
    ss -s
    # net-tools (`netstat`) is not installed on this image; `nstat` (iproute2,
    # always present) reads the same /proc/net/netstat TcpExt counters and
    # includes ListenOverflows/ListenDrops/TCPBacklogDrop - the accept-queue
    # overflow signal the bead's `netstat -s | grep overflow` was after.
    echo "--nstat-overflow-drop-listen--"
    nstat -az | grep -iE "overflow|drop|listen"
    echo "--conntrack-S--"
    sudo conntrack -S
    echo "--ipvsadm-L-n-stats--"
    sudo ipvsadm -L -n --stats -t "${VIP}:${PORT}"
    # /proc/net/nf_conntrack (the per-entry listing the bead asked for via
    # `wc -l`) is not exposed on this kernel/netns (CONFIG_NF_CONNTRACK_PROCFS
    # off or hidden) - nf_conntrack_count is the equivalent live entry count.
    echo "--nf_conntrack_count--"
    cat /proc/sys/net/netfilter/nf_conntrack_count
    echo "===="
  } >> "$LOG" 2>&1
  sleep 2
done
