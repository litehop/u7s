#!/usr/bin/env bash
# Bakes a stopped "lima-golden" template VM carrying the exact package/image
# set lima/kubelet.yaml's provision script installs (apt packages, crictl
# image pulls, sonobuoy). scripts/conformance/lima-start.sh clones this
# template (APFS copy-on-write) for new VMs instead of re-running that ~9min
# provisioning script from scratch every time.
#
# Idempotent: re-running against an already-baked (stopped) golden is a
# no-op. Use --force to delete and re-bake from scratch (e.g. after
# lima/kubelet.yaml's provision script changes -- there is no automatic
# staleness detection yet, that is a separate follow-on).
#
# Usage:
#   scripts/conformance/lima-golden-bake.sh [--force]
set -euo pipefail

LIMA_YAML="$(cd "$(dirname "$0")/../.." && pwd)/lima/kubelet.yaml"
GOLDEN_NAME="lima-golden"
GOLDEN_DIR="${HOME}/.lima/${GOLDEN_NAME}"

FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if ! command -v limactl &>/dev/null; then
  echo "error: limactl not found" >&2
  echo "  install: brew install lima" >&2
  exit 1
fi

if [ "$FORCE" -eq 1 ] && [ -d "$GOLDEN_DIR" ]; then
  echo "Deleting existing ${GOLDEN_NAME} (--force)..."
  limactl delete --force "$GOLDEN_NAME"
fi

# Instance directory, not `limactl list`, is the authoritative existence
# check -- mirrors lima-start.sh's own VM_DIR check (limactl list can
# transiently return empty output while lima is busy).
if [ -d "$GOLDEN_DIR" ]; then
  STATUS=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk "/^${GOLDEN_NAME} / {print \$2}")
  case "$STATUS" in
    Stopped)
      echo "${GOLDEN_NAME} already baked and stopped -- nothing to do."
      exit 0
      ;;
    Running)
      echo "${GOLDEN_NAME} is running; stopping it (golden sits idle between clones)..."
      limactl stop "$GOLDEN_NAME"
      exit 0
      ;;
    *)
      echo "error: ${GOLDEN_NAME} exists but its status ('${STATUS:-unknown}') is neither Running nor Stopped." >&2
      echo "  Inspect manually (limactl list), or re-bake from scratch: $0 --force" >&2
      exit 1
      ;;
  esac
fi

echo "Provisioning ${GOLDEN_NAME} from lima/kubelet.yaml (one-time, ~9min with the e2e-test-image pre-pull)..."

# kubelet.yaml's default kubelet-hostPort forward (10250) may already be
# bound by a live worker's own VM -- irrelevant once cloned (every clone
# overrides hostPort via `limactl clone --set`, see lima-start.sh), so bake
# onto a dedicated out-of-band port instead of colliding with a live session.
BAKE_YAML=$(mktemp)
trap 'rm -f "$BAKE_YAML"' EXIT
sed 's/hostPort: 10250/hostPort: 19250/' "$LIMA_YAML" > "$BAKE_YAML"

# Same extended timeout as lima-start.sh's fresh-provision path, for the same
# reason: the provision script's ~25 crictl image pulls can outlast lima's
# own 10m default boot-readiness timeout.
limactl start --tty=false --timeout 30m --name="$GOLDEN_NAME" "$BAKE_YAML"

echo "Stopping ${GOLDEN_NAME} (golden sits idle -- 0 CPU/RAM -- between clones)..."
limactl stop "$GOLDEN_NAME"

echo ""
echo "${GOLDEN_NAME} baked and stopped. scripts/conformance/lima-start.sh will clone it for new VMs."
