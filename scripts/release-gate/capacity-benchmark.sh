#!/usr/bin/env bash
# Capacity-envelope benchmark: one command that runs the release-gate harness in ramp mode and
# writes a stamped artefact (benchmark.json + benchmark.md) under docs/benchmarks/<date>-<sha8>-<provider>[-contended]/
# (never overwrites an existing artefact).
#
# One install on a 1 vCPU / 1 GiB no-swap VM, WordPress + MariaDB resident, then Ready-bursts of
# each --ramp size (20 is the release gate; larger sizes are documented, not gated). Records the
# idle PSS/RSS per component, per-burst time-to-Ready and MemAvailable headroom, and the largest
# passing burst, plus the VM shape and the u7s version, git SHA and date.
#
# Usage: capacity-benchmark.sh [--backend lima|gcp] [--release TAG] [--ramp LIST] [--memory GiB]
#                              [--allow-contended] [--from-run DIR] [--out-root DIR]
#   --backend B         lima (default; arm64 VM built from this checkout, always labelled
#                       non-authoritative) or gcp (needs --release; the authoritative shape,
#                       n1-custom-1-1024; needs a separate operator approval to create VMs)
#   --release TAG       gcp only: mirror release to benchmark; the stamped SHA is the tag's commit
#   --ramp LIST         burst sizes (default 20,30,40,50,60), strictly increasing
#   --memory GiB        lima only: VM memory (the 2 GiB row of docs/capacity.md); default 1
#   --allow-contended   lima only: do not refuse to start when other Lima VMs run or the host is
#                       busy; the artefact records the contention and the run is not authoritative
#   --from-run DIR      do not run anything: build the artefact from an existing burst-gate.sh
#                       --ramp output directory (its run-1/)
#   --out-root DIR      artefact root (default docs/benchmarks)
# Needs jq, plus everything burst-gate.sh needs. The tree you benchmark must be committed on lima:
# a dirty tree is recorded as dirty in the artefact.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BACKEND=lima; RELEASE=""; RAMP="20,30,40,50,60"; MEMORY=""; ALLOW_CONTENDED=0; FROM_RUN=""; OUT_ROOT="$ROOT/docs/benchmarks"

while [ $# -gt 0 ]; do
  case "$1" in
    --backend) BACKEND="$2"; shift 2 ;;
    --release) RELEASE="$2"; shift 2 ;;
    --ramp) RAMP="$2"; shift 2 ;;
    --memory) MEMORY="$2"; shift 2 ;;
    --allow-contended) ALLOW_CONTENDED=1; shift ;;
    --from-run) FROM_RUN="$2"; shift 2 ;;
    --out-root) OUT_ROOT="$2"; shift 2 ;;
    -h|--help) sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed '$d'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=capacity-lib.sh
. "$HERE/capacity-lib.sh"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
case "$BACKEND" in
  lima) [ -z "$RELEASE" ] || { echo "--release is only for --backend gcp" >&2; exit 2; } ;;
  gcp)
    [ -n "$RELEASE" ] || { echo "--backend gcp needs --release <tag>" >&2; exit 2; }
    [ -z "$MEMORY" ] && [ "$ALLOW_CONTENDED" = 0 ] || { echo "--memory and --allow-contended are lima only: the gcp shape is fixed and must be quiet" >&2; exit 2; } ;;
  *) echo "--backend must be lima or gcp, got '$BACKEND'" >&2; exit 2 ;;
esac
SIZES="$(rg_parse_ramp "$RAMP")" || { echo "--ramp must be strictly increasing positive integers like 20,30,40, got '$RAMP'" >&2; exit 2; }

PAST="$(jq -c . "$ROOT/docs/benchmarks/past-envelope.json")" \
  || { echo "docs/benchmarks/past-envelope.json is missing or not JSON" >&2; exit 2; }

BG_PID=""
# burst-gate.sh deletes its VM from its own EXIT/TERM trap. Run it in the background so this
# shell can react to signals mid-run, forward TERM and wait for that cleanup to finish.
# SIGKILL cannot be trapped: a kill -9 of this script or of burst-gate.sh can leave the VM
# behind, so list and delete leftovers by hand (limactl list / gcloud compute instances list).
forward_to_gate() {
  [ -z "$BG_PID" ] || { kill -TERM "$BG_PID" 2>/dev/null; wait "$BG_PID" 2>/dev/null; BG_PID=""; }
}
trap forward_to_gate EXIT
trap 'forward_to_gate; exit 130' INT
trap 'forward_to_gate; exit 143' TERM
trap 'forward_to_gate; exit 129' HUP

if [ -n "$FROM_RUN" ]; then
  RUN="$FROM_RUN/run-1"
  OUT_DIR_NOTE="$FROM_RUN"
else
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  OUT_DIR_NOTE="$ROOT/temp/release-gate/capacity-$STAMP"
  mkdir -p "$OUT_DIR_NOTE"
  if [ "$BACKEND" = gcp ]; then
    meta_sha="$(git -C "$ROOT" rev-parse --verify "$RELEASE^{commit}" 2>/dev/null)" \
      || { echo "tag $RELEASE is not in this checkout (git fetch --tags)" >&2; exit 1; }
    meta_dirty=0; meta_version="$RELEASE"
  else
    meta_sha="$(git -C "$ROOT" rev-parse HEAD)"
    meta_dirty=0; [ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] || meta_dirty=1
    meta_version="$(git -C "$ROOT" describe --tags --always)"
  fi
  cap_write_run_meta "$OUT_DIR_NOTE" "$meta_sha" "$meta_dirty" "$(date -u +%Y-%m-%d)" "$meta_version"
  args=(--backend "$BACKEND" --runs 1 --ramp "$RAMP" --out "$OUT_DIR_NOTE")
  [ "$BACKEND" != gcp ] || args+=(--release "$RELEASE")
  [ -z "$MEMORY" ] || args+=(--memory "$MEMORY")
  brc=0
  if [ "$ALLOW_CONTENDED" = 1 ]; then
    RG_ALLOW_CONTENDED=1 MAX_INVALID_RUNS=1 RG_RETRY_WAIT_SECS=0 "$HERE/burst-gate.sh" "${args[@]}" &
  else
    "$HERE/burst-gate.sh" "${args[@]}" &
  fi
  BG_PID=$!
  wait "$BG_PID" || brc=$?
  BG_PID=""
  RUN="$OUT_DIR_NOTE/run-1"
  # 0 = a size passed, 1 = none passed (still a measurement). 3 = INVALID: accepted only with
  # --allow-contended and only when host contention alone caused it, never a harness error or
  # a VM that did not come up. Anything else, or no recorded results, is not a benchmark.
  case "$brc" in
    0|1) ;;
    3)
      [ "$ALLOW_CONTENDED" = 1 ] || { echo "benchmark run INVALID (host contention or infrastructure); no artefact written. Raw: $OUT_DIR_NOTE" >&2; exit 3; }
      cap_invalid_is_contention "$RUN" \
        || { echo "benchmark run INVALID for a reason other than host contention (harness error or VM did not come up); no artefact written. Raw: $OUT_DIR_NOTE" >&2; exit 3; } ;;
    *) echo "burst-gate.sh exited $brc; no artefact written. Raw: $OUT_DIR_NOTE" >&2; exit "$brc" ;;
  esac
fi
[ -s "$RUN/out/results.env" ] && [ -s "$RUN/out/samples.tsv" ] \
  || { echo "no results/samples in $RUN/out: the VM produced no benchmark data" >&2; exit 1; }
[ "$(rg_get "$RUN/out/results.env" install_ok)" = 1 ] \
  || { echo "install did not complete in $RUN: no benchmark" >&2; exit 1; }

META="$OUT_DIR_NOTE/run-meta.env"
[ -s "$META" ] || { echo "$META is missing: the run's SHA and date were not recorded, so it cannot be stamped" >&2; exit 1; }
SHA="$(rg_get "$META" git_sha)"; DIRTY="$(rg_get "$META" git_dirty)"; DATE="$(rg_get "$META" date)"; VERSION="$(rg_get "$META" version)"
if [ "$BACKEND" = gcp ]; then
  DETAIL="$(grep -o 'machine=[^ ]*' "$OUT_DIR_NOTE/backend.txt" 2>/dev/null | head -1 | cut -d= -f2) $(grep -o 'disk=[^ ]*' "$OUT_DIR_NOTE/backend.txt" 2>/dev/null | head -1), authoritative"
else
  DETAIL=""
fi
CONTENDED=""; [ ! -s "$RUN/contention.txt" ] || CONTENDED=1
DIR="$OUT_ROOT/$(cap_dir_name "$DATE" "$SHA" "$BACKEND" "$CONTENDED")"
[ ! -e "$DIR" ] || { echo "$DIR already exists; refusing to overwrite a stamped artefact (remove it deliberately to rebuild)" >&2; exit 1; }
mkdir -p "$DIR"
cap_build_json "$RUN" "$SIZES" "$VERSION" "$SHA" "$DIRTY" "$DATE" "$BACKEND" "$DETAIL" "${MEMORY:-1}" "$PAST" > "$DIR/benchmark.json" \
  || { echo "could not build benchmark.json" >&2; rm -rf "$DIR"; exit 1; }
cap_validate_json "$DIR/benchmark.json" || { rm -rf "$DIR"; exit 1; }
cap_render_md "$DIR/benchmark.json" > "$DIR/benchmark.md"
echo "benchmark written: $DIR/benchmark.md and benchmark.json (raw run: $OUT_DIR_NOTE)"
