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
# Exit codes: see "Release-gate exit codes" in docs/dev-setup.md (3 = not enough valid runs).
#
# INVALID: a run that did not pass while the host was not quiet is neither PASS nor FAIL. Quiet
# means no other Lima VM running and host CPU idle >= 70% over 30 s (the floor drops by the gate
# VM's own vCPU share once it runs), checked before the VM is created and then every ~60 s, plus
# an in-guest CPU calibration at the idle boundary before the first burst (median > 1.5x the
# pre-install baseline of the same VM; never sampled after a burst, and with fewer than 3
# samples it is unmeasured and judges nothing). A harness error (marker write failing before the
# bursts) is INVALID too. INVALID runs are repeated (up to MAX_INVALID_RUNS, default 3, after
# RG_RETRY_WAIT_SECS, default 300) and never counted; a PASS under contention stays a PASS.
#
# --backend gcp --release <tag> is the RELEASE-AUTHORITATIVE run: a real 1-vCPU shared-core
# Spot e2-micro (x86_64, 1 GiB, no swap) on GCP (docs/dev-setup.md, "GCP test VPSes"), installing
# <tag> from the mirror https://u7s.dekiru.tech/<tag>/install.sh; nothing is built locally. The
# phases, collectors and verdict are the same as on Lima (lib.sh); the Lima arm64 run is an
# advisory pre-check. Contention mapping: on GCP the guest is the host, so the Lima host-side
# checks (host idle CPU, other VMs) are replaced by in-guest steal time over the idle window
# (> RG_STEAL_MAX_PCT, 10%) plus the same in-guest calibration; a non-pass with either is
# INVALID. A non-pass on an instance Google reclaimed (Spot preemption) is PREEMPTED, counted
# apart from FAIL and INVALID and, like INVALID, never a valid run. Exit 3 covers both.
# A leaked VPS (<out>/leaked-vps.txt) turns a PASS into exit 4.
#
# Usage: burst-gate.sh [--backend lima|gcp] [--release TAG] [--confirm] [--burst-pods N] [--runs N] [--ramp LIST] [--probe-kill SECS] [--capture] [--keep] [--memory GiB] [--mem-hog-mib N] [--zram-mib N] [--coredns-requests]
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
#   --backend B       lima (default; local arm64 VM) or gcp (needs --release; rejects --memory and
#                     --tarball-dir)
#   --release TAG     gcp only: mirror release to install, e.g. v0.4.1-snapshot.1
# Requires: lima: limactl (vz), cargo-zigbuild + zig (unless --tarball-dir); gcp: the u7s-gcp
# gcloud configuration and scripts/gcp/setup.sh run once. Both: network access.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COREDNS_REQ=0; ZRAM_MIB=0; CAPTURE=0; RAMP=""; PROBE_KILL_SECS=180
BURST_PODS=50; CONFIRM=0; CONFIRM_SIZES="50 40"
RUNS=3; KEEP=0; MEMORY=""; TARBALL_DIR=""; OUT=""; HOG_MIB=0
BURST_CAP_SECS=300
BACKEND=lima; RELEASE=""
RUN_WALL_SECS="${RG_RUN_WALL_SECS:-3300}"
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
    --backend) BACKEND="$2"; shift 2 ;;
    --release) RELEASE="$2"; shift 2 ;;
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
# shellcheck source=backend.sh
. "$HERE/backend.sh"

case "$BACKEND" in
  lima)
    [ -z "$RELEASE" ] || { echo "--release is only for --backend gcp (lima builds the tarball from this checkout)" >&2; exit 2; } ;;
  gcp)
    [[ "$RELEASE" =~ ^v[0-9][0-9A-Za-z._-]*$ ]] || { echo "--backend gcp needs --release <tag> (e.g. v0.4.1-snapshot.1), got '$RELEASE'" >&2; exit 2; }
    [ -z "$MEMORY" ] || { echo "--memory is not supported with --backend gcp (the e2-micro is fixed at 1 GiB)" >&2; exit 2; }
    [ -z "$TARBALL_DIR" ] || { echo "--tarball-dir is not supported with --backend gcp (the release is installed from the mirror)" >&2; exit 2; }
    # shellcheck source=../gcp/lib.sh
    . "$ROOT/scripts/gcp/lib.sh"
    gcp_require_config
    GCP_PROJECT="$(gcloud config get-value project 2>/dev/null)" ;;
  *) echo "--backend must be lima or gcp, got '$BACKEND'" >&2; exit 2 ;;
esac

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
  for vm in $VMS; do vm_delete "$vm"; done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$BACKEND" = lima ] && [ -z "$TARBALL_DIR" ]; then
  TARBALL_DIR="$OUT/dist"
  "$HERE/build-arm64-tarball.sh" "$TARBALL_DIR" || { echo "tarball build failed" >&2; exit 2; }
fi

# --confirm: full gate (--runs, default 3) at each size in CONFIRM_SIZES, largest first, stopping
# at the first size where every run passes. The passing size is the gated no-swap burst ceiling.
if [ "$CONFIRM" = 1 ]; then
  tried=()
  for size in $CONFIRM_SIZES; do
    sub_args=(--runs "$RUNS" --burst-pods "$size" --burst-cap "$BURST_CAP_SECS" --out "$OUT/burst-$size")
    if [ "$BACKEND" = gcp ]; then sub_args+=(--backend gcp --release "$RELEASE"); else sub_args+=(--tarball-dir "$TARBALL_DIR"); fi
    "$0" "${sub_args[@]}" >&2 || true
    n_passed="$(cat "$OUT/burst-$size/passed" 2>/dev/null || echo 0)"
    n_valid="$(cat "$OUT/burst-$size/valid" 2>/dev/null || echo 0)"
    tried+=("$size:$n_passed:$n_valid:$RUNS")
    [ "$n_passed" = "$RUNS" ] && break
    [ "$n_passed" = "$n_valid" ] && break
  done
  rg_confirm_verdict "${tried[@]}"; rc=$?
  cat "$OUT"/burst-*/leaked-vps.txt > "$OUT/leaked-vps.txt" 2>/dev/null
  if [ -s "$OUT/leaked-vps.txt" ]; then
    echo "WARNING: VPSes may still be running and billing:"; cat "$OUT/leaked-vps.txt"
    [ "$rc" != 0 ] || { rc=4; echo "CONFIRM: PASS but LEAKED VPS: exit 4"; }
  fi
  exit "$rc"
fi

STAGE="$OUT/stage"
mkdir -p "$STAGE/wordpress"
if [ "$BACKEND" = lima ]; then
  cp "$TARBALL_DIR"/u7s-gate-*.tar.gz "$TARBALL_DIR"/u7s-gate-*.tar.gz.sha256 "$TARBALL_DIR/install.sh" "$STAGE/"
fi
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
  rg_quiet_line "$(date +%s)" "$idle" "$others" "$VM_ALLOW_PCT" >> "$1"
}
VM_ALLOW_PCT=0
VM_VCPUS="$(awk '/^cpus:/ {print $2}' "$HERE/u7s-vps-1g.yaml")"
HOST_CORES="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 0)"
# On gcp the guest is the host: its contention shows up as in-guest steal and calibration
# (lib.sh), so the Lima host-side idle / other-VM checks do not apply.
host_state() {
  if [ "$BACKEND" = gcp ]; then echo "$(date -u +%H:%M:%SZ) $1 vm-status=$(vm_running "$VM")"; return; fi
  echo "$(date -u +%H:%M:%SZ) $1 loadavg=$(sysctl -n vm.loadavg 2>/dev/null || cut -d' ' -f1-3 /proc/loadavg) other-running-vms=$(vm_running "$VM")"
}

overall=0; passed=0; valid=0; invalid=0; preempted=0; attempt=0
while [ "$valid" -lt "$RUNS" ] && [ $((invalid + preempted)) -lt "$MAX_INVALID_RUNS" ]; do
  attempt=$((attempt + 1))
  # The guest's hostname is the VPS name plus GCE's ".c.<project>.internal"; the node's
  # certificate CN is "system:node:<hostname>" and openssl rejects a CN over 64 characters, so
  # the gcp name stays short.
  if [ "$BACKEND" = gcp ]; then VM="u7s-rg-${STAMP:4:2}${STAMP:6:2}${STAMP:9:6}-$attempt"; else VM="u7s-rg-$STAMP-$attempt"; fi
  RUN_OUT="$OUT/run-$attempt"; mkdir -p "$RUN_OUT"
  echo "==== attempt $attempt (valid $valid/$RUNS, invalid $invalid, preempted $preempted, cap $MAX_INVALID_RUNS): VM $VM ===="
  host_state start | tee "$RUN_OUT/host.txt"
  status=""
  VM_ALLOW_PCT=0
  : > "$RUN_OUT/quiet.log"
  if [ "$BACKEND" = lima ]; then
    quiet_sample "$RUN_OUT/quiet.log"
    if [ -n "$(rg_contention_reasons "$RUN_OUT/quiet.log" /dev/null)" ]; then
      status=INVALID
      echo "pre-flight: host not quiet, no VM created:"; rg_contention_reasons "$RUN_OUT/quiet.log" /dev/null
    fi
  fi
  if [ -n "$status" ]; then
    :
  elif VMS="$VMS $VM"; vm_create "$VM" "$RUN_OUT"; then
    quiet_pid=""
    if [ "$BACKEND" = lima ]; then
      VM_ALLOW_PCT="$(rg_vm_cpu_allow_pct "$VM_VCPUS" "$HOST_CORES")"
      rm -f "$RUN_OUT/quiet.stop"
      rg_quiet_loop "$RUN_OUT/quiet.stop" "$RUN_OUT/quiet.log" "$QUIET_RECHECK_SECS" quiet_sample &
      quiet_pid=$!
    fi
    vm_shell "$VM" sudo install -d -m 0777 /var/tmp/rg
    vm_shell "$VM" grep -E 'MemTotal|SwapTotal' /proc/meminfo | tee "$RUN_OUT/meminfo-total.txt"
    stage_files=()
    for f in "$STAGE"/*.tar.gz "$STAGE"/*.sha256 "$STAGE"/*.sh "$STAGE"/*.env "$STAGE/wordpress"; do
      [ -e "$f" ] && stage_files+=("$f")
    done
    vm_copy_to "$VM" /var/tmp/rg "${stage_files[@]}" || echo "warning: could not copy the gate scripts to $VM" >&2
    if [ "$BACKEND" = gcp ]; then
      vm_shell "$VM" curl -fsSL "https://u7s.dekiru.tech/$RELEASE/install.sh" -o /var/tmp/rg/install.sh \
        || echo "warning: could not fetch install.sh for $RELEASE from the mirror" >&2
    fi
    if [ "$BACKEND" = gcp ]; then
      # The guest hostname embeds the project id.
      # A fifo, not a pipe: $! must be the ssh side so the watchdog can kill it, and the
      # redactor needs its own PID so it can be waited for (a process substitution outlives wait).
      mkfifo "$RUN_OUT/vm-gate.fifo"
      gcp_redact -u <"$RUN_OUT/vm-gate.fifo" >"$RUN_OUT/vm-gate.log" & redact_pid=$!
      vm_shell "$VM" sudo bash /var/tmp/rg/vm-gate.sh >"$RUN_OUT/vm-gate.fifo" 2>&1 &
    else
      redact_pid=""
      vm_shell "$VM" sudo bash /var/tmp/rg/vm-gate.sh >"$RUN_OUT/vm-gate.log" 2>&1 &
    fi
    gate_pid=$!
    tail -n +1 -f "$RUN_OUT/vm-gate.log" & tail_pid=$!
    # The host-side client dying leaves the workload running in the VM, so kill it there first.
    ( sleep "$RUN_WALL_SECS"; echo "run wall-clock cap ${RUN_WALL_SECS}s hit; killing" >&2
      vm_shell "$VM" sudo pkill -KILL -f "$RG_VM_KILL_PATTERN" 2>/dev/null
      rg_kill_tree "$gate_pid" ) &
    wd_pid=$!
    wait "$gate_pid" 2>/dev/null
    if [ -n "$redact_pid" ]; then wait "$redact_pid" 2>/dev/null; rm -f "$RUN_OUT/vm-gate.fifo"; sleep 1; fi
    kill "$wd_pid" "$tail_pid" 2>/dev/null
    if [ -n "$quiet_pid" ]; then touch "$RUN_OUT/quiet.stop"; wait "$quiet_pid" 2>/dev/null; fi
    vm_copy_from "$VM" /var/tmp/rg/out "$RUN_OUT/out" 2>/dev/null \
      || echo "warning: could not copy results out of $VM" >&2
  else
    echo "VM $VM failed to create/start (see $RUN_OUT/*-create.log)" >&2
    if [ "$BACKEND" = gcp ]; then
      status=INVALID
      echo "INFRASTRUCTURE (run is INVALID, not a u7s FAIL): $VM was never created or never reachable over IAP ssh (stockout, quota, IAP)" | tee "$RUN_OUT/verdict.txt"
    fi
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
  if [ "$BACKEND" = gcp ] && [ "$status" != PASS ]; then
    pre_rc=0; gcp_vps_was_preempted "$VM" || pre_rc=$?
    case "$pre_rc" in
      0) status="$(rg_apply_preemption "$status" 1)" ;;
      1) ;;
      *) if [ "$status" = FAIL ]; then
           status=INVALID
           echo "INFRASTRUCTURE (run is INVALID, not a u7s FAIL): could not tell whether Google reclaimed $VM" | tee -a "$RUN_OUT/verdict.txt"
         fi ;;
    esac
    [ "$status" != PREEMPTED ] || echo "PREEMPTED: Google reclaimed $VM mid-run; the run is not a verdict" | tee -a "$RUN_OUT/verdict.txt"
  fi
  rg_contention_reasons "$RUN_OUT/quiet.log" "$RUN_OUT/out/results.env" > "$RUN_OUT/contention.txt"
  harness_error="$(rg_get "$RUN_OUT/out/results.env" harness_error)"
  [ -z "$harness_error" ] || echo "HARNESS ERROR (run is INVALID, not a u7s FAIL): $harness_error"
  [ ! -s "$RUN_OUT/out/results.env" ] || rg_cal_unmeasured "$RUN_OUT/out/results.env" | sed 's/^/warning: /'
  echo "run status: $status"
  [ "$status" = PASS ] || { [ ! -s "$RUN_OUT/contention.txt" ] || { echo "contention observed:"; cat "$RUN_OUT/contention.txt"; }; }
  case "$status" in
    PASS) passed=$((passed + 1)); valid=$((valid + 1)) ;;
    FAIL) overall=1; valid=$((valid + 1)) ;;
    INVALID) invalid=$((invalid + 1)); [ $((invalid + preempted)) -lt "$MAX_INVALID_RUNS" ] && sleep "$RG_RETRY_WAIT_SECS" ;;
    PREEMPTED) preempted=$((preempted + 1)) ;;
  esac
  [ -s "$RUN_OUT/out/samples.tsv" ] && "$HERE/summarize.sh" "$RUN_OUT/out" | tee "$RUN_OUT/summary.md"
  [ "$KEEP" = 1 ] || { vm_delete "$VM" && VMS="${VMS/ $VM/}"; }
done

echo "$passed" > "$OUT/passed"
echo "$valid" > "$OUT/valid"
if [ "$overall" != 0 ]; then verdict=FAIL; rc=1
elif [ "$valid" -lt "$RUNS" ] && [ "$preempted" -gt 0 ]; then verdict="PREEMPTED (only $valid/$RUNS valid runs; $preempted preempted, $invalid invalid)"; rc=3
elif [ "$valid" -lt "$RUNS" ]; then verdict="INVALID (only $valid/$RUNS valid runs; host contention)"; rc=3
else verdict=PASS; rc=0; fi
if [ "$BACKEND" = gcp ]; then
  echo "backend=gcp release=$RELEASE machine=e2-micro arch=x86_64 release-authoritative=yes preempted=$preempted invalid=$invalid" > "$OUT/backend.txt"
  verdict="$verdict [release-authoritative: x86_64 GCP e2-micro Spot, mirror release $RELEASE]"
fi
if [ -s "$OUT/leaked-vps.txt" ]; then
  echo "WARNING: VPSes may still be running and billing:"; cat "$OUT/leaked-vps.txt"
  [ "$rc" != 0 ] || { rc=4; verdict="$verdict [LEAKED VPS: exit 4]"; }
fi
echo "==== GATE: $passed/$RUNS runs passed at $BURST_PODS pods -> $verdict (results in $OUT) ===="
exit "$rc"
