#!/usr/bin/env bash
# Leave-one-out KCM memory on one Lima VM: one install, WordPress + MariaDB deployed once, then for
# each controller the shipped KCM is restarted with only that controller excluded
# (--controllers=<installed>,-<name>) and its Pss_Anon sampled after --settle seconds. An untrimmed
# baseline (R) is re-measured every --baseline-every controllers so drift and the noise floor show
# in the table. Memory sampling only; no conformance run.
#
# Writes docs/benchmarks/<date>-<sha8>-lima-kcm-loo/{rows.jsonl,table.json,table.md}; never
# overwrites an existing directory. Non-authoritative (Lima VM, one sample set per controller).
#
# Usage: scripts/bench/kcm-mem-loo.sh --vm <name> --port <N> --kubelet-port <N> [--workdir <dir>]
#          [--controllers a,b,c] [--settle <secs>] [--samples <n>] [--baseline-every <n>] [--out-root <dir>]
# Needs jq, kubectl, limactl, and everything run-all.sh --install needs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

# release-1.37 cmd/kube-controller-manager/names/controller_names.go, minus
# serviceaccount-token-controller (without it nothing gets a token, so every later stage is void) and
# the two controllers install.sh already excludes.
ALL_CONTROLLERS="endpoints-controller,endpointslice-controller,endpointslice-mirroring-controller,replicationcontroller-controller,pod-garbage-collector-controller,resourcequota-controller,namespace-controller,serviceaccount-controller,garbage-collector-controller,daemonset-controller,job-controller,deployment-controller,replicaset-controller,horizontal-pod-autoscaler-controller,disruption-controller,statefulset-controller,cronjob-controller,certificatesigningrequest-signing-controller,certificatesigningrequest-approving-controller,certificatesigningrequest-cleaner-controller,podcertificaterequest-cleaner-controller,ttl-controller,bootstrap-signer-controller,token-cleaner-controller,node-ipam-controller,node-lifecycle-controller,taint-eviction-controller,device-taint-eviction-controller,persistentvolume-binder-controller,persistentvolume-attach-detach-controller,persistentvolume-expander-controller,persistentvolumeclaim-protection-controller,persistentvolume-protection-controller,podgroup-protection-controller,ttl-after-finished-controller,root-ca-certificate-publisher-controller,kube-apiserver-serving-clustertrustbundle-publisher-controller,ephemeral-volume-controller,storageversion-garbage-collector-controller,resourceclaim-controller,resourcepoolstatusrequest-controller,legacy-serviceaccount-token-cleaner-controller,validatingadmissionpolicy-status-controller,volumeattributesclass-protection-controller,storage-version-migrator-controller,selinux-warning-controller"

VM=""; PORT=""; KUBELET_PORT=""; WORKDIR="$PWD/temp/u7s"; CONTROLLERS="$ALL_CONTROLLERS"
SETTLE=45; SAMPLES=3; BASELINE_EVERY=8; OUT_ROOT="$ROOT/docs/benchmarks"
while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --kubelet-port) KUBELET_PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --controllers) CONTROLLERS="$2"; shift 2 ;;
    --settle) SETTLE="$2"; shift 2 ;;
    --samples) SAMPLES="$2"; shift 2 ;;
    --baseline-every) BASELINE_EVERY="$2"; shift 2 ;;
    --out-root) OUT_ROOT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$VM" ] && [ -n "$PORT" ] && [ -n "$KUBELET_PORT" ] \
  || { echo "usage: $0 --vm <name> --port <N> --kubelet-port <N>" >&2; exit 2; }

# shellcheck source=scripts/bench/kcm-mem-lib.sh
. "$HERE/kcm-mem-lib.sh"
# shellcheck source=scripts/release-gate/lib.sh
. "$ROOT/scripts/release-gate/lib.sh"
# shellcheck source=scripts/release-gate/capacity-lib.sh
. "$ROOT/scripts/release-gate/capacity-lib.sh"
# shellcheck source=scripts/conformance/kcm-mode.sh
. "$ROOT/scripts/conformance/kcm-mode.sh"

sha="$(git -C "$ROOT" rev-parse HEAD)"
DIR="$OUT_ROOT/$(date -u +%Y-%m-%d)-${sha:0:8}-lima-kcm-loo"
[ ! -e "$DIR" ] || { echo "$DIR already exists; refusing to overwrite (remove it deliberately to rerun)" >&2; exit 1; }
KUBECONFIG_PATH="$WORKDIR/kubeconfig"
k() { kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"; }
RAW="$WORKDIR/kcm-mem-loo"
rm -rf "$RAW"; mkdir -p "$RAW"
ROWS="$RAW/rows.jsonl"; : > "$ROWS"

ARTIFACTS="$WORKDIR/install-artifacts"
bash "$ROOT/scripts/release-gate/build-arm64-tarball.sh" "$ARTIFACTS"
bash "$ROOT/scripts/conformance/install-teardown.sh" --vm "$VM" --workdir "$WORKDIR"
bash "$ROOT/scripts/conformance/install-bringup.sh" --vm "$VM" --port "$PORT" --kubelet-port "$KUBELET_PORT" \
  --workdir "$WORKDIR" --tarball "$ARTIFACTS/u7s-gate-aarch64-unknown-linux-gnu.tar.gz"
kcm_mode_revert_on_exit "$VM"

k wait --for=condition=Ready "node/$VM" --timeout=300s >/dev/null
mariadb="$RAW/mariadb-emptydir.yaml"
rg_mariadb_emptydir_rewrite "$ROOT/examples/e2e/wordpress/mariadb.yaml" "$mariadb"
k apply -f "$mariadb" -f "$ROOT/examples/e2e/wordpress/wordpress.yaml" >/dev/null
for _ in $(seq 1 60); do k -n default get pod mariadb-0 >/dev/null 2>&1 && break; sleep 2; done
k -n default wait --for=condition=Ready pod/mariadb-0 --timeout=300s >/dev/null
k -n default wait --for=condition=Available deployment/pehelypress --timeout=300s >/dev/null

measure() { # label  (KCM_TRIM_EXCLUDE and mode set by the caller)
  local label="$1" mode="$2" flag s kcm
  flag="$(kcm_mode_apply "$VM" "$mode")"
  sleep "$SETTLE"
  s="$(kcm_stage_sample "$VM" "$SAMPLES" 10)"
  kcm="$(jq '.kcm_mib' <<<"$s")"
  jq -n -c --arg c "$label" --argjson m "$kcm" --arg flag "$flag" --argjson s "$(jq -c '.samples_mib.kcm' <<<"$s")" \
    '{controller: $c, kcm_mib: $m, samples_mib: $s, kcm_controllers: $flag}' | tee -a "$ROWS"
}

i=0
measure R R
IFS=',' read -r -a LIST <<<"$CONTROLLERS"
for c in "${LIST[@]}"; do
  i=$((i + 1))
  KCM_TRIM_EXCLUDE="-$c" measure "$c" T
  [ $((i % BASELINE_EVERY)) -ne 0 ] || measure R R
done
measure R R

mkdir -p "$DIR"
cp "$ROWS" "$DIR/rows.jsonl"
kcm_loo_table < "$ROWS" > "$DIR/table.json"
jq -r '
  "# KCM leave-one-out (Pss_Anon MiB, WordPress + MariaDB loaded, one install)\n",
  "Baseline (untrimmed, median of the interleaved R runs): \(.baseline_mib) MiB; baseline spread (noise floor): \(.baseline_spread_mib) MiB.\n",
  "| controller excluded | KCM MiB | saved vs baseline |", "|---|---|---|",
  (.rows[] | "| \(.controller) | \(.kcm_mib) | \(.saved_mib) |")
' "$DIR/table.json" | tee "$DIR/table.md"
echo "artefact: $DIR (raw: $RAW)"
