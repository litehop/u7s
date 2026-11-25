#!/usr/bin/env bash
# One KCM memory run on an install-mode stack that is already up (run-all.sh --install
# --stack-only, or install-bringup.sh): switches KCM to --mode, samples Pss_Anon of the KCM and
# apiserver processes at two stages, and writes <out>/kcm-mem.json and <out>/run-meta.env.
#   idle       after the KCM restart and --settle seconds
#   wordpress  after WordPress + MariaDB (examples/e2e/wordpress, MariaDB on emptyDir as in the
#              release gate) are Ready and --settle seconds have passed
# The cluster is left running; kcm-mem-ab.sh tears it down between runs.
#
# Usage: scripts/bench/kcm-mem-run.sh --vm <name> --mode R|T --out <dir> [--workdir <dir>]
#          [--settle <secs>] [--samples <n>] [--sample-interval <secs>]
# Needs jq, kubectl, limactl.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VM=""; MODE=""; OUT=""; WORKDIR="$PWD/temp/u7s"; SETTLE=60; SAMPLES=3; INTERVAL=10
while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --settle) SETTLE="$2"; shift 2 ;;
    --samples) SAMPLES="$2"; shift 2 ;;
    --sample-interval) INTERVAL="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$VM" ] && [ -n "$OUT" ] || { echo "usage: $0 --vm <name> --mode R|T --out <dir>" >&2; exit 2; }
case "$MODE" in R|T) ;; *) echo "--mode must be R or T, got '$MODE'" >&2; exit 2 ;; esac

# shellcheck source=scripts/bench/kcm-mem-lib.sh
. "$HERE/kcm-mem-lib.sh"
# shellcheck source=scripts/release-gate/lib.sh
. "$ROOT/scripts/release-gate/lib.sh"
# shellcheck source=scripts/release-gate/capacity-lib.sh
. "$ROOT/scripts/release-gate/capacity-lib.sh"

KUBECONFIG_PATH="$WORKDIR/kubeconfig"
k() { kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

sha="$(git -C "$ROOT" rev-parse HEAD)"
dirty=0; [ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] || dirty=1
cap_write_run_meta "$OUT" "$sha" "$dirty" "$(date -u +%Y-%m-%d)" "$(git -C "$ROOT" describe --tags --always)"

echo "kcm-mem: mode $MODE on $VM"
flag="$("$ROOT/scripts/conformance/kcm-mode.sh" --vm "$VM" --mode "$MODE")"
[ -n "$flag" ] || { echo "kcm-mem: could not read the effective --controllers of u7s-kcm" >&2; exit 1; }
if [ "$MODE" = T ]; then
  case "$flag" in *-horizontal-pod-autoscaler-controller*) ;; *) echo "kcm-mem: mode T but the running KCM has no trim: $flag" >&2; exit 1 ;; esac
else
  case "$flag" in *-horizontal-pod-autoscaler-controller*) echo "kcm-mem: mode R but the running KCM is trimmed: $flag" >&2; exit 1 ;; esac
fi
k wait --for=condition=Ready "node/$VM" --timeout=300s >/dev/null

echo "kcm-mem: idle stage (settle ${SETTLE}s)"
sleep "$SETTLE"
idle="$(kcm_stage_sample "$VM" "$SAMPLES" "$INTERVAL")"

echo "kcm-mem: deploying WordPress + MariaDB"
mariadb="$OUT/mariadb-emptydir.yaml"
rg_mariadb_emptydir_rewrite "$ROOT/examples/e2e/wordpress/mariadb.yaml" "$mariadb" \
  || { echo "kcm-mem: mariadb emptyDir rewrite failed" >&2; exit 1; }
k apply -f "$mariadb" -f "$ROOT/examples/e2e/wordpress/wordpress.yaml" >/dev/null
for _ in $(seq 1 60); do k -n default get pod mariadb-0 >/dev/null 2>&1 && break; sleep 2; done
k -n default wait --for=condition=Ready pod/mariadb-0 --timeout=300s >/dev/null \
  || { echo "kcm-mem: mariadb-0 not Ready in 300s" >&2; exit 1; }
k -n default wait --for=condition=Available deployment/pehelypress --timeout=300s >/dev/null \
  || { echo "kcm-mem: pehelypress not Available in 300s" >&2; exit 1; }
echo "kcm-mem: wordpress stage (settle ${SETTLE}s)"
sleep "$SETTLE"
wordpress="$(kcm_stage_sample "$VM" "$SAMPLES" "$INTERVAL")"

restarts="$(limactl shell "$VM" sudo systemctl show -p NRestarts --value u7s-kcm.service | tr -d '[:space:]')"
vm_json="$(limactl shell "$VM" bash -c 'echo "$(uname -r) $(nproc) $(awk "/^MemTotal:/ {print \$2}" /proc/meminfo) $(uname -m)"' \
  | jq -R -c 'split(" ") | {name: "'"$VM"'", kernel: .[0], vcpus: (.[1] | tonumber), mem_total_kb: (.[2] | tonumber), arch: .[3]}')"
host_json="$(jq -n -c --arg os "$(uname -sr)" --argjson ncpu "$(sysctl -n hw.ncpu 2>/dev/null || nproc)" '{os: $os, ncpu: $ncpu}')"
stages="$(jq -n -c --argjson i "$idle" --argjson w "$wordpress" '{idle: $i, wordpress: $w}')"

kcm_mem_json "$MODE" "$flag" "${restarts:-0}" "$sha" "$dirty" "$(date -u +%Y-%m-%d)" "$vm_json" "$host_json" "$stages" \
  > "$OUT/kcm-mem.json"
echo "kcm-mem: wrote $OUT/kcm-mem.json (mode $MODE, restarts ${restarts:-0})"
jq -c '{kcm_mode, idle: .stages.idle.kcm_mib, wordpress: .stages.wordpress.kcm_mib}' "$OUT/kcm-mem.json"
