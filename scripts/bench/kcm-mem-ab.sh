#!/usr/bin/env bash
# KCM memory A/B on one Lima VM: R (shipped Go KCM) and T (trimmed --controllers) interleaved
# R,T,R,T,R,T. Each run starts from a fresh install (install-teardown.sh, then install-bringup.sh
# with one tarball built from this checkout), so every run is a first boot. Prints the per-stage
# medians of Pss_Anon (KCM and apiserver) and the Phase 0 verdict
# `median(R) - median(T) >= 5 MiB` for the KCM process at every stage.
#
# Writes docs/benchmarks/<date>-<sha8>-lima-kcm-mem/ with each run's kcm-mem.json, summary.json
# and summary.md; never overwrites an existing directory. A Lima artefact is non-authoritative:
# the VM is the rig's, not the 1 GiB gate shape.
#
# Usage: scripts/bench/kcm-mem-ab.sh --vm <name> --port <N> --kubelet-port <N> [--workdir <dir>]
#          [--runs <per mode, default 3>] [--settle <secs>] [--out-root <dir>]
# Needs jq, kubectl, limactl, and everything run-all.sh --install needs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VM=""; PORT=""; KUBELET_PORT=""; WORKDIR="$PWD/temp/u7s"; RUNS=3; SETTLE=60; OUT_ROOT="$ROOT/docs/benchmarks"
while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --kubelet-port) KUBELET_PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --settle) SETTLE="$2"; shift 2 ;;
    --out-root) OUT_ROOT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$VM" ] && [ -n "$PORT" ] && [ -n "$KUBELET_PORT" ] \
  || { echo "usage: $0 --vm <name> --port <N> --kubelet-port <N>" >&2; exit 2; }

# shellcheck source=scripts/bench/kcm-mem-lib.sh
. "$HERE/kcm-mem-lib.sh"
# shellcheck source=scripts/conformance/kcm-mode.sh
. "$ROOT/scripts/conformance/kcm-mode.sh"

sha="$(git -C "$ROOT" rev-parse HEAD)"
DIR="$OUT_ROOT/$(date -u +%Y-%m-%d)-${sha:0:8}-lima-kcm-mem"
[ ! -e "$DIR" ] || { echo "$DIR already exists; refusing to overwrite (remove it deliberately to rerun)" >&2; exit 1; }
RAW="$WORKDIR/kcm-mem-ab"
rm -rf "$RAW"; mkdir -p "$RAW"

ARTIFACTS="$WORKDIR/install-artifacts"
bash "$ROOT/scripts/release-gate/build-arm64-tarball.sh" "$ARTIFACTS"

kcm_mode_revert_on_exit "$VM"
for i in $(seq 1 "$RUNS"); do
  for mode in R T; do
    echo "==== run $i/$RUNS mode $mode ===="
    bash "$ROOT/scripts/conformance/install-teardown.sh" --vm "$VM" --workdir "$WORKDIR"
    bash "$ROOT/scripts/conformance/install-bringup.sh" --vm "$VM" --port "$PORT" --kubelet-port "$KUBELET_PORT" \
      --workdir "$WORKDIR" --tarball "$ARTIFACTS/u7s-gate-aarch64-unknown-linux-gnu.tar.gz"
    bash "$HERE/kcm-mem-run.sh" --vm "$VM" --mode "$mode" --workdir "$WORKDIR" --settle "$SETTLE" --out "$RAW/run-$i-$mode"
  done
done

mkdir -p "$DIR"
for r in "$RAW"/run-*; do
  mkdir -p "$DIR/$(basename "$r")"
  cp "$r/kcm-mem.json" "$r/run-meta.env" "$DIR/$(basename "$r")/"
done
kcm_aggregate "$DIR"/run-*/kcm-mem.json > "$DIR/summary.json"
jq -r '
  "# KCM memory A/B (Pss_Anon MiB, medians of \(.runs.R) R and \(.runs.T) T runs, interleaved)\n",
  "| stage | R kcm | T kcm | R - T (kcm) | R apiserver | T apiserver |", "|---|---|---|---|---|---|",
  (.stages | to_entries[] | "| \(.key) | \(.value.R.kcm_mib) | \(.value.T.kcm_mib) | \(.value.kcm_diff_mib) | \(.value.R.apiserver_mib) | \(.value.T.apiserver_mib) |"),
  "\nPhase 0 (`median(R) - median(T) >= \(.min_diff_mib)` at every stage): \(if .phase0_pass then "PASS" else "FAIL" end)"
' "$DIR/summary.json" | tee "$DIR/summary.md"
echo "artefact: $DIR (raw: $RAW)"
