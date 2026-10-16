#!/usr/bin/env bash
# Release gate: does u7s survive a pod burst on a 1 GiB / 1 vCPU node?
#
# Per run: fresh Lima VM from scripts/release-gate/u7s-vps-1g.yaml (arm64, 1 vCPU,
# 1 GiB, no swap) -> zero-argument install.sh from an arm64 tarball built from this
# checkout -> WordPress+MariaDB -> 20-pod burst -> 80-pod burst -> webhook-smoke.sh,
# sampling MemAvailable, per-process PSS/RSS, OOM kills and node Ready throughout.
#
# PASS iff all of (operator-approved criteria; every run must pass):
#   (a) no OOM kill of any control-plane host process or kube-system pod
#   (b) the node stays Ready throughout
#   (c) each burst completes within 5 minutes (hard-killed and recorded as timeout at 10)
#   (d) after the burst settles, the WordPress page still responds
#   (e) scripts/e2e-workload/webhook-smoke.sh passes on the shipped-install VM
# Exits non-zero if any criterion of any run FAILs.
#
# Usage: burst-gate.sh [--runs N] [--keep] [--memory GiB] [--zram-mib N] [--coredns-requests]
#                      [--burst-cap SECS] [--tarball-dir DIR] [--out DIR]
#   --runs N          number of independent fresh-VM runs (default 3)
#   --keep            do not delete the VMs afterwards
#   --memory GiB      override the template's VM memory (forced-failure checks, e.g. 0.625)
#   --coredns-requests experiment: set CoreDNS cpu/memory requests after install
#   --zram-mib N      experiment: give the VM an N MiB zram swap device before install
#   --burst-cap SECS  criterion (c) cap (default 300)
#   --tarball-dir DIR reuse the output of build-arm64-tarball.sh instead of rebuilding
#   --out DIR         results directory (default: ./temp/release-gate/<timestamp>)
# Requires: limactl (vz), cargo-zigbuild + zig (unless --tarball-dir), network access.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COREDNS_REQ=0; ZRAM_MIB=0
RUNS=3; KEEP=0; MEMORY=""; TARBALL_DIR=""; OUT=""
BURST_CAP_SECS=300
RUN_WALL_SECS=3300

while [ $# -gt 0 ]; do
  case "$1" in
    --runs) RUNS="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --coredns-requests) COREDNS_REQ=1; shift ;;
    --zram-mib) ZRAM_MIB="$2"; shift 2 ;;
    --memory) MEMORY="$2"; shift 2 ;;
    --burst-cap) BURST_CAP_SECS="$2"; shift 2 ;;
    --tarball-dir) TARBALL_DIR="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed '$d'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
export BURST_CAP_SECS
case "$ZRAM_MIB" in
  ''|*[!0-9]*) echo "--zram-mib must be a non-negative integer (MiB), got '$ZRAM_MIB'" >&2; exit 2 ;;
esac

# shellcheck source=lib.sh
. "$HERE/lib.sh"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$PWD/temp/release-gate/$STAMP}"
mkdir -p "$OUT"
VMS=""
cleanup() {
  [ "$KEEP" = 1 ] && return
  local vm
  for vm in $VMS; do limactl delete -f "$vm" >/dev/null 2>&1; done
}
trap cleanup EXIT

if [ -z "$TARBALL_DIR" ]; then
  TARBALL_DIR="$OUT/dist"
  "$HERE/build-arm64-tarball.sh" "$TARBALL_DIR" || { echo "tarball build failed" >&2; exit 2; }
fi

STAGE="$OUT/stage"
mkdir -p "$STAGE/wordpress"
cp "$TARBALL_DIR"/u7s-gate-*.tar.gz "$TARBALL_DIR"/u7s-gate-*.tar.gz.sha256 "$TARBALL_DIR/install.sh" "$STAGE/"
cp "$HERE/lib.sh" "$HERE/vm-gate.sh" "$HERE/vm-sampler.sh" "$HERE/vm-capture.sh" "$ROOT/scripts/e2e-workload/webhook-smoke.sh" "$STAGE/"
printf 'COREDNS_REQ=%s\nZRAM_MIB=%s\n' "$COREDNS_REQ" "$ZRAM_MIB" > "$STAGE/gate.env"
cp "$ROOT/examples/e2e/wordpress/wordpress.yaml" "$STAGE/wordpress/"
# MariaDB data on emptyDir: the gate VM has no csi-hostpath, and the PVC is not what is under test.
awk '
  /^  volumeClaimTemplates:/ {skip=1}
  /^  updateStrategy:/ {skip=0}
  /^        - name: temp$/ {print "        - name: data"; print "          emptyDir: {}"}
  !skip {print}
' "$ROOT/examples/e2e/wordpress/mariadb.yaml" > "$STAGE/wordpress/mariadb-emptydir.yaml"
grep -q 'name: data' "$STAGE/wordpress/mariadb-emptydir.yaml" || { echo "mariadb emptyDir rewrite failed" >&2; exit 2; }

overall=0; passed=0
for i in $(seq 1 "$RUNS"); do
  VM="u7s-rg-$STAMP-$i"; VMS="$VMS $VM"
  RUN_OUT="$OUT/run-$i"; mkdir -p "$RUN_OUT"
  echo "==== run $i/$RUNS: VM $VM ===="
  host_state() { echo "$(date -u +%H:%M:%SZ) $1 loadavg=$(sysctl -n vm.loadavg 2>/dev/null || cut -d' ' -f1-3 /proc/loadavg) running-vms=$(limactl list 2>/dev/null | awk '$2 == "Running" {printf "%s ", $1}')"; }
  host_state start | tee "$RUN_OUT/host.txt"
  create_args=(--name "$VM" --tty=false)
  [ -n "$MEMORY" ] && create_args+=(--memory "$MEMORY")
  if limactl create "${create_args[@]}" "$HERE/u7s-vps-1g.yaml" >"$RUN_OUT/lima-create.log" 2>&1 \
     && limactl start "$VM" >"$RUN_OUT/lima-start.log" 2>&1; then
    limactl shell "$VM" sudo install -d -m 0777 /var/tmp/rg
    limactl shell "$VM" grep -E 'MemTotal|SwapTotal' /proc/meminfo | tee "$RUN_OUT/meminfo-total.txt"
    for f in "$STAGE"/*.tar.gz "$STAGE"/*.sha256 "$STAGE"/*.sh "$STAGE"/*.env "$STAGE/wordpress"; do
      limactl copy -r "$f" "$VM:/var/tmp/rg/" >/dev/null
    done
    limactl shell "$VM" sudo bash /var/tmp/rg/vm-gate.sh >"$RUN_OUT/vm-gate.log" 2>&1 &
    gate_pid=$!
    tail -n +1 -f "$RUN_OUT/vm-gate.log" & tail_pid=$!
    ( sleep "$RUN_WALL_SECS"; echo "run wall-clock cap ${RUN_WALL_SECS}s hit; killing" >&2; kill "$gate_pid" 2>/dev/null ) &
    wd_pid=$!
    wait "$gate_pid" 2>/dev/null
    kill "$wd_pid" "$tail_pid" 2>/dev/null
    limactl copy -r "$VM:/var/tmp/rg/out" "$RUN_OUT/out" >/dev/null 2>&1 \
      || echo "warning: could not copy results out of $VM" >&2
  else
    echo "VM $VM failed to create/start (see $RUN_OUT/lima-*.log)" >&2
  fi
  host_state end | tee -a "$RUN_OUT/host.txt"
  mkdir -p "$RUN_OUT/out"; touch "$RUN_OUT/out/results.env"
  echo "---- run $i verdict ----"
  rg_verdict "$RUN_OUT/out/results.env" > "$RUN_OUT/verdict.txt"; rc=$?
  cat "$RUN_OUT/verdict.txt"
  if [ "$rc" -eq 0 ]; then passed=$((passed + 1)); else overall=1; fi
  [ -s "$RUN_OUT/out/samples.tsv" ] && "$HERE/summarize.sh" "$RUN_OUT/out" | tee "$RUN_OUT/summary.md"
  [ "$KEEP" = 1 ] || { limactl delete -f "$VM" >/dev/null 2>&1; VMS="${VMS/ $VM/}"; }
done

echo "==== GATE: $passed/$RUNS runs passed -> $([ "$overall" = 0 ] && echo PASS || echo FAIL) (results in $OUT) ===="
exit "$overall"
