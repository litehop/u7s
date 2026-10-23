#!/usr/bin/env bash
# Release gate: does u7s survive a pod burst on a 1 GiB / 1 vCPU node?
#
# Per run: fresh Lima VM from scripts/release-gate/u7s-vps-1g.yaml (arm64, 1 vCPU,
# 1 GiB, no swap) -> zero-argument install.sh from an arm64 tarball built from this
# checkout -> WordPress+MariaDB -> 20-pod burst -> N-pod burst (--burst-pods, default 50) -> webhook-smoke.sh,
# sampling MemAvailable, per-process PSS/RSS, OOM kills and node Ready throughout.
#
# PASS iff all of (operator-approved criteria; every run must pass):
#   (a) no OOM kill of any control-plane host process or kube-system pod
#   (b) the node stays Ready throughout
#   (c) each burst completes within 5 minutes (hard-killed and recorded as timeout at 10)
#   (d) after the burst settles, the WordPress page still responds and a marker row written to
#       MariaDB before the bursts is still readable (a recreated emptyDir DB must not pass)
#   (e) scripts/e2e-workload/webhook-smoke.sh passes on the shipped-install VM
# Exit status: 0 PASS, 1 a valid run FAILed, 3 INVALID (not enough valid runs).
#
# INVALID: a run that did not pass while the host was not quiet is neither PASS nor FAIL. Quiet
# means no other Lima VM running and host CPU idle >= 70% over 30 s, checked before the VM is
# created and then every ~60 s, plus an in-guest CPU calibration loop at idle phase boundaries
# (slowest > 1.5x fastest). INVALID runs are repeated (up to MAX_INVALID_RUNS, default 3, after
# RG_RETRY_WAIT_SECS, default 300) and never counted; a PASS under contention stays a PASS.
#
# Usage: burst-gate.sh [--confirm] [--burst-pods N] [--runs N] [--ramp LIST] [--probe-kill SECS] [--capture] [--keep] [--memory GiB] [--mem-hog-mib N] [--zram-mib N] [--coredns-requests]
#                      [--burst-cap SECS] [--tarball-dir DIR] [--out DIR]
#   --runs N          number of independent fresh-VM runs (default 3)
#   --burst-pods N    size of the large burst (default 50); the verdict names it
#   --confirm         release-gate mode, run on a QUIET host (~1 h): --runs (default 3) full runs at
#                     50 pods, and only if any fails 3 at 40. Reports the gated no-swap ceiling or FAIL.
#   --keep            do not delete the VMs afterwards
#   --memory GiB      override the template's VM memory (applies from boot, so it can break the install)
#   --mem-hog-mib N   forced-failure check: after install, pin N MiB (tmpfs, no swap) so the burst
#                     is what fails. The run is then judged by whether it failed in the burst,
#                     and exits 0 only if so (e.g. 400)
#   --coredns-requests experiment: set CoreDNS cpu/memory requests after install
#   --zram-mib N      experiment: give the VM an N MiB zram swap device before install
#   --capture         also run vm-capture.sh (PSI/CPU/refault diagnostics; its kubectl probes
#                     cost memory, so off by default)
#   --ramp LIST       one install, then bursts of each size in LIST (e.g. 30,40,50,60,70),
#                     scaling down and settling between sizes, stopping at the first failure.
#                     Prints the largest passing size as an approximate candidate N (single VM,
#                     state carryover). Criteria (a)-(d) per size; implies --runs 1.
#   --probe-kill SECS ramp-mode hard-kill per burst (default 180; deliberately
#                     tighter than the 300 s criterion (c) cap so probes fail fast)
#   --burst-cap SECS  criterion (c) cap (default 300)
#   --tarball-dir DIR reuse the output of build-arm64-tarball.sh instead of rebuilding
#   --out DIR         results directory (default: ./temp/release-gate/<timestamp>)
# Requires: limactl (vz), cargo-zigbuild + zig (unless --tarball-dir), network access.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COREDNS_REQ=0; ZRAM_MIB=0; CAPTURE=0; RAMP=""; PROBE_KILL_SECS=180
BURST_PODS=50; CONFIRM=0; CONFIRM_SIZES="50 40"
RUNS=3; KEEP=0; MEMORY=""; TARBALL_DIR=""; OUT=""; HOG_MIB=0
BURST_CAP_SECS=300
RUN_WALL_SECS=3300
MAX_INVALID_RUNS="${MAX_INVALID_RUNS:-3}"
RG_RETRY_WAIT_SECS="${RG_RETRY_WAIT_SECS:-300}"
QUIET_RECHECK_SECS="${QUIET_RECHECK_SECS:-30}"

while [ $# -gt 0 ]; do
  case "$1" in
    --runs) RUNS="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --coredns-requests) COREDNS_REQ=1; shift ;;
    --zram-mib) ZRAM_MIB="$2"; shift 2 ;;
    --capture) CAPTURE=1; shift ;;
    --ramp) RAMP="$2"; shift 2 ;;
    --burst-pods) BURST_PODS="$2"; shift 2 ;;
    --confirm) CONFIRM=1; shift ;;
    --probe-kill) PROBE_KILL_SECS="$2"; shift 2 ;;
    --memory) MEMORY="$2"; shift 2 ;;
    --mem-hog-mib) HOG_MIB="$2"; shift 2 ;;
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
case "$HOG_MIB" in
  ''|*[!0-9]*) echo "--mem-hog-mib must be a non-negative integer (MiB), got '$HOG_MIB'" >&2; exit 2 ;;
esac
case "$RUNS" in
  ''|*[!0-9]*) echo "--runs must be a positive integer, got '$RUNS'" >&2; exit 2 ;;
esac
[ "$RUNS" -ge 1 ] || { echo "--runs must be a positive integer, got '$RUNS'" >&2; exit 2; }

# shellcheck source=lib.sh
. "$HERE/lib.sh"

case "$PROBE_KILL_SECS" in
  ''|*[!0-9]*|0) echo "--probe-kill must be a positive integer (seconds), got '$PROBE_KILL_SECS'" >&2; exit 2 ;;
esac
case "$BURST_PODS" in
  ''|*[!0-9]*|0) echo "--burst-pods must be a positive integer, got '$BURST_PODS'" >&2; exit 2 ;;
esac
if [ "$CONFIRM" = 1 ] && [ -n "$RAMP" ]; then echo "--confirm and --ramp are mutually exclusive" >&2; exit 2; fi
if [ -n "$RAMP" ]; then
  RAMP_SIZES="$(rg_parse_ramp "$RAMP")" \
    || { echo "--ramp must be strictly increasing positive integers like 30,40,50, got '$RAMP'" >&2; exit 2; }
  RUNS=1
fi

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

# --confirm: full gate (--runs, default 3) at each size in CONFIRM_SIZES, largest first, stopping
# at the first size where every run passes. The passing size is the gated no-swap burst ceiling.
if [ "$CONFIRM" = 1 ]; then
  tried=()
  for size in $CONFIRM_SIZES; do
    "$0" --runs "$RUNS" --burst-pods "$size" --burst-cap "$BURST_CAP_SECS" --tarball-dir "$TARBALL_DIR" --out "$OUT/burst-$size" >&2 || true
    n_passed="$(cat "$OUT/burst-$size/passed" 2>/dev/null || echo 0)"
    n_valid="$(cat "$OUT/burst-$size/valid" 2>/dev/null || echo 0)"
    tried+=("$size:$n_passed:$n_valid:$RUNS")
    [ "$n_passed" = "$RUNS" ] && break
    [ "$n_passed" = "$n_valid" ] && break
  done
  rg_confirm_verdict "${tried[@]}"; exit $?
fi

STAGE="$OUT/stage"
mkdir -p "$STAGE/wordpress"
cp "$TARBALL_DIR"/u7s-gate-*.tar.gz "$TARBALL_DIR"/u7s-gate-*.tar.gz.sha256 "$TARBALL_DIR/install.sh" "$STAGE/"
cp "$HERE/lib.sh" "$HERE/vm-gate.sh" "$HERE/vm-sampler.sh" "$HERE/vm-capture.sh" "$ROOT/scripts/e2e-workload/webhook-smoke.sh" "$STAGE/"
printf 'COREDNS_REQ=%s\nZRAM_MIB=%s\nCAPTURE=%s\nRAMP=%s\nRAMP_KILL_SECS=%s\nBURST_PODS=%s\nHOG_MIB=%s\n' \
  "$COREDNS_REQ" "$ZRAM_MIB" "$CAPTURE" "$RAMP" "$PROBE_KILL_SECS" "$BURST_PODS" "$HOG_MIB" > "$STAGE/gate.env"
cp "$ROOT/examples/e2e/wordpress/wordpress.yaml" "$STAGE/wordpress/"
# MariaDB data on emptyDir: the gate VM has no csi-hostpath, and the PVC is not what is under test.
awk '
  /^  volumeClaimTemplates:/ {skip=1}
  /^  updateStrategy:/ {skip=0}
  /^        - name: temp$/ {print "        - name: data"; print "          emptyDir: {}"}
  !skip {print}
' "$ROOT/examples/e2e/wordpress/mariadb.yaml" > "$STAGE/wordpress/mariadb-emptydir.yaml"
grep -q 'name: data' "$STAGE/wordpress/mariadb-emptydir.yaml" || { echo "mariadb emptyDir rewrite failed" >&2; exit 2; }

# Appends one "<epoch> <host idle %> <other running VMs>" line to $1 (blocks for the CPU sample).
quiet_sample() {
  local idle others list
  idle="$(rg_host_idle_pct)"
  if list="$(limactl list 2>/dev/null)"; then others="$(echo "$list" | rg_other_vms "$VM" | wc -l | tr -d ' ')"; else others="?"; fi
  rg_quiet_line "$(date +%s)" "$idle" "$others" >> "$1"
}
host_state() { echo "$(date -u +%H:%M:%SZ) $1 loadavg=$(sysctl -n vm.loadavg 2>/dev/null || cut -d' ' -f1-3 /proc/loadavg) other-running-vms=$(limactl list 2>/dev/null | rg_other_vms "$VM" | tr '\n' ' ')"; }

overall=0; passed=0; valid=0; invalid=0; attempt=0
while [ "$valid" -lt "$RUNS" ] && [ "$invalid" -lt "$MAX_INVALID_RUNS" ]; do
  attempt=$((attempt + 1))
  VM="u7s-rg-$STAMP-$attempt"
  RUN_OUT="$OUT/run-$attempt"; mkdir -p "$RUN_OUT"
  echo "==== attempt $attempt (valid $valid/$RUNS, invalid $invalid/$MAX_INVALID_RUNS): VM $VM ===="
  host_state start | tee "$RUN_OUT/host.txt"
  status=""
  quiet_sample "$RUN_OUT/quiet.log"
  if [ -n "$(rg_contention_reasons "$RUN_OUT/quiet.log" /dev/null)" ]; then
    status=INVALID
    echo "pre-flight: host not quiet, no VM created:"; rg_contention_reasons "$RUN_OUT/quiet.log" /dev/null
  fi
  create_args=(--name "$VM" --tty=false)
  [ -n "$MEMORY" ] && create_args+=(--memory "$MEMORY")
  if [ -n "$status" ]; then
    :
  elif VMS="$VMS $VM"; limactl create "${create_args[@]}" "$HERE/u7s-vps-1g.yaml" >"$RUN_OUT/lima-create.log" 2>&1 \
     && limactl start "$VM" >"$RUN_OUT/lima-start.log" 2>&1; then
    ( while :; do sleep "$QUIET_RECHECK_SECS"; quiet_sample "$RUN_OUT/quiet.log"; done ) &
    quiet_pid=$!
    limactl shell "$VM" sudo install -d -m 0777 /var/tmp/rg
    limactl shell "$VM" grep -E 'MemTotal|SwapTotal' /proc/meminfo | tee "$RUN_OUT/meminfo-total.txt"
    for f in "$STAGE"/*.tar.gz "$STAGE"/*.sha256 "$STAGE"/*.sh "$STAGE"/*.env "$STAGE/wordpress"; do
      limactl copy -r "$f" "$VM:/var/tmp/rg/" >/dev/null
    done
    limactl shell "$VM" sudo bash /var/tmp/rg/vm-gate.sh >"$RUN_OUT/vm-gate.log" 2>&1 &
    gate_pid=$!
    tail -n +1 -f "$RUN_OUT/vm-gate.log" & tail_pid=$!
    # The host-side client dying leaves the workload running in the VM, so kill it there first.
    ( sleep "$RUN_WALL_SECS"; echo "run wall-clock cap ${RUN_WALL_SECS}s hit; killing" >&2
      limactl shell "$VM" sudo pkill -KILL -f "$RG_VM_KILL_PATTERN" 2>/dev/null
      kill "$gate_pid" 2>/dev/null ) &
    wd_pid=$!
    wait "$gate_pid" 2>/dev/null
    kill "$wd_pid" "$tail_pid" "$quiet_pid" 2>/dev/null
    limactl copy -r "$VM:/var/tmp/rg/out" "$RUN_OUT/out" >/dev/null 2>&1 \
      || echo "warning: could not copy results out of $VM" >&2
  else
    echo "VM $VM failed to create/start (see $RUN_OUT/lima-*.log)" >&2
  fi
  host_state end | tee -a "$RUN_OUT/host.txt"
  mkdir -p "$RUN_OUT/out"; touch "$RUN_OUT/out/results.env"
  if [ -z "$status" ]; then
    echo "---- attempt $attempt verdict ----"
    if [ -n "$RAMP" ]; then
      rg_ramp_verdict "$RUN_OUT/out/results.env" "$RAMP_SIZES" "$RUN_OUT/out/samples.tsv" > "$RUN_OUT/verdict.txt"; rc=$?
    else
      rg_verdict "$RUN_OUT/out/results.env" > "$RUN_OUT/verdict.txt"; rc=$?
    fi
    cat "$RUN_OUT/verdict.txt"
    status="$(rg_run_status "$rc" "$RUN_OUT/quiet.log" "$RUN_OUT/out/results.env")"
    if [ "$status" != INVALID ] && [ "$HOG_MIB" -gt 0 ]; then
      rg_forced_failure_check "$RUN_OUT/out/results.env" "$RUN_OUT/out/phase" | tee -a "$RUN_OUT/verdict.txt"; rc=${PIPESTATUS[0]}
      [ "$rc" -eq 0 ] && status=PASS || status=FAIL
    fi
  fi
  rg_contention_reasons "$RUN_OUT/quiet.log" "$RUN_OUT/out/results.env" > "$RUN_OUT/contention.txt"
  echo "run status: $status"
  [ "$status" = PASS ] || { [ ! -s "$RUN_OUT/contention.txt" ] || { echo "contention observed:"; cat "$RUN_OUT/contention.txt"; }; }
  case "$status" in
    PASS) passed=$((passed + 1)); valid=$((valid + 1)) ;;
    FAIL) overall=1; valid=$((valid + 1)) ;;
    INVALID) invalid=$((invalid + 1)); [ "$invalid" -lt "$MAX_INVALID_RUNS" ] && sleep "$RG_RETRY_WAIT_SECS" ;;
  esac
  [ -s "$RUN_OUT/out/samples.tsv" ] && "$HERE/summarize.sh" "$RUN_OUT/out" | tee "$RUN_OUT/summary.md"
  [ "$KEEP" = 1 ] || { limactl delete -f "$VM" >/dev/null 2>&1; VMS="${VMS/ $VM/}"; }
done

echo "$passed" > "$OUT/passed"
echo "$valid" > "$OUT/valid"
if [ "$overall" != 0 ]; then verdict=FAIL; rc=1
elif [ "$valid" -lt "$RUNS" ]; then verdict="INVALID (only $valid/$RUNS valid runs; host contention)"; rc=3
else verdict=PASS; rc=0; fi
echo "==== GATE: $passed/$RUNS runs passed at $BURST_PODS pods -> $verdict (results in $OUT) ===="
exit "$rc"
