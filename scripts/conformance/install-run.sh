#!/usr/bin/env bash
# run-all.sh --install: the release sign-off path. Builds an arm64 release tarball from this
# checkout, runs the real scripts/install.sh on the Lima VM, applies the labelled rig-only
# add-ons (install-bringup.sh), then runs sonobuoy (06-run-sonobuoy.sh) against that cluster.
# Not meant to be invoked directly; run-all.sh validates the flags and dispatches here.
#
# Teardown: scripts/conformance/reset.sh --vm <vm> --workdir <workdir>  (deletes the VM and
# the tunnel), or reset.sh --host-only --workdir <workdir>  (tunnel only, VM kept), then
# limactl stop <vm>.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

VM_NAME="${U7S_VM_NAME:-lima-node}"
PORT=6443
KUBELET_PORT=10250
WORKDIR="$PWD/temp/u7s"
NETWORK=""
FOCUS=""
RESET=0
STACK_ONLY=0
SONOBUOY_ARGS=()
RUST_LOG_FILTER=""
KCM_MODE=""
EXTRA_NODE=""
EXTRA_KUBELET_PORT=""
ORIGINAL_ARGV_JSON="[]"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --stack-only) STACK_ONLY=1; shift ;;
    --focus) FOCUS="$2"; shift 2 ;;
    --all-e2e|--unsafe-focus) SONOBUOY_ARGS+=("$1"); shift ;;
    --procs|--k8s-version) SONOBUOY_ARGS+=("$1" "$2"); shift 2 ;;
    --vm) VM_NAME="$2"; shift 2 ;;
    --network) NETWORK="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --kubelet-port) KUBELET_PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --rust-log) RUST_LOG_FILTER="$2"; shift 2 ;;
    --kcm-mode) KCM_MODE="$2"; shift 2 ;;
    --extra-node) EXTRA_NODE="$2"; shift 2 ;;
    --extra-kubelet-port) EXTRA_KUBELET_PORT="$2"; shift 2 ;;
    --argv-json) ORIGINAL_ARGV_JSON="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

banner() {
  echo ""
  echo "============================================================"
  echo " $*"
  echo "============================================================"
}

START=$SECONDS
if [ "$RESET" -eq 1 ]; then
  banner "Reset: tearing down stale state"
  bash "$DIR/reset.sh" --vm "$VM_NAME" --workdir "$WORKDIR" --port "$PORT" ${EXTRA_NODE:+--extra-node "$EXTRA_NODE"}
fi

banner "Install 1/3: build arm64 release tarball from this checkout"
ARTIFACTS="$WORKDIR/install-artifacts"
bash "$REPO/scripts/release-gate/build-arm64-tarball.sh" "$ARTIFACTS"
BUILT=$(( SECONDS - START ))

banner "Install 2/3: real install.sh on $VM_NAME, then labelled rig-only add-ons"
BRINGUP_START=$SECONDS
NETWORK_ARG=()
[ -z "$NETWORK" ] || NETWORK_ARG=(--network "$NETWORK")
bash "$DIR/install-bringup.sh" --vm "$VM_NAME" --port "$PORT" --kubelet-port "$KUBELET_PORT" \
  --workdir "$WORKDIR" ${NETWORK_ARG[@]+"${NETWORK_ARG[@]}"} \
  ${EXTRA_NODE:+--extra-node "$EXTRA_NODE" --extra-kubelet-port "$EXTRA_KUBELET_PORT"} \
  --tarball "$ARTIFACTS/u7s-gate-aarch64-unknown-linux-gnu.tar.gz" --rust-log "$RUST_LOG_FILTER"
echo "install-mode timing: tarball build ${BUILT}s, VM provision + install.sh + add-ons $(( SECONDS - BRINGUP_START ))s"

KCM_FLAG=""
kcm_restarts() { limactl shell "$VM_NAME" sudo systemctl show -p NRestarts --value u7s-kcm.service | tr -d "[:space:]"; }
if [ -n "$KCM_MODE" ]; then
  banner "KCM mode $KCM_MODE on $VM_NAME"
  # shellcheck source=scripts/conformance/kcm-mode.sh
  source "$DIR/kcm-mode.sh"
  [ "$STACK_ONLY" -eq 1 ] || kcm_mode_revert_on_exit "$VM_NAME"
  KCM_FLAG=$(kcm_mode_apply "$VM_NAME" "$KCM_MODE")
  echo "effective KCM flag: $KCM_FLAG"
  KCM_RESTARTS_BEFORE=$(kcm_restarts)
fi

KUBECONFIG="$WORKDIR/kubeconfig"
export KUBECONFIG

if [ "$STACK_ONLY" -eq 1 ]; then
  banner "Install 3/3: Run sonobuoy (skipped — --stack-only)"
  exit 0
fi

banner "Install 3/3: Run sonobuoy"
export SONOBUOY_FOCUS="$FOCUS"
export U7S_TOPOLOGY=install
export U7S_SONOBUOY_VM_KUBECONFIG="/var/lib/u7s/kubeconfig"
export U7S_PORT="$PORT"
export U7S_VM_NAME="$VM_NAME"
rm -f "$(sonobuoy_results_dir_file "$WORKDIR" parallel)"
SONOBUOY_RC=0
bash "$DIR/06-run-sonobuoy.sh" --port "$PORT" --workdir "$WORKDIR" ${EXTRA_NODE:+--extra-node "$EXTRA_NODE"} ${SONOBUOY_ARGS[@]+"${SONOBUOY_ARGS[@]}"} || SONOBUOY_RC=$?

RUN_DIR=$(cat "$(sonobuoy_results_dir_file "$WORKDIR" parallel)" 2>/dev/null) || true
if [ -n "$RUN_DIR" ]; then
  bash "$DIR/write-build-provenance.sh" --run-dir "$RUN_DIR" --vm "$VM_NAME" ${EXTRA_NODE:+--extra-node "$EXTRA_NODE"} --argv-json "$ORIGINAL_ARGV_JSON"
  run_meta_record_nodes "$RUN_DIR" "$(kubectl --kubeconfig "$KUBECONFIG" get nodes --no-headers | wc -l | tr -d ' ')"
  if [ -n "$KCM_MODE" ]; then
    echo "kcm_mode=$KCM_MODE" >> "$RUN_DIR/run-meta"
    printf 'kcm_mode=%s\nkcm_controllers_flag=%s\nkcm_restarts_before=%s\nkcm_restarts_after=%s\nkcm_active=%s\n' \
      "$KCM_MODE" "$KCM_FLAG" "$KCM_RESTARTS_BEFORE" "$(kcm_restarts)" \
      "$(limactl shell "$VM_NAME" sudo systemctl is-active u7s-kcm.service || true)" > "$RUN_DIR/kcm-mode.txt"
  fi
else
  echo "warning: could not resolve this run's temp/e2e/ output dir — build.json not written" >&2
fi

banner "Done"
if [ "$SONOBUOY_RC" -ne 0 ]; then
  if [ "$SONOBUOY_RC" -eq "$SONOBUOY_EXIT_SPEC_FAILURES" ]; then
    echo "ERROR: sonobuoy run had spec failures (exit $SONOBUOY_RC) — see the results summary above" >&2
  else
    echo "ERROR: sonobuoy run failed to produce results (exit $SONOBUOY_RC) — see the output above" >&2
  fi
  exit "$SONOBUOY_RC"
fi
