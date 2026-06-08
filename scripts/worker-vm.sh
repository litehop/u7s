#!/usr/bin/env bash
# Manage a named worker VM for isolated conformance testing.
#
# Usage:
#   scripts/worker-vm.sh start <vm-name>   # Provision VM if needed, start it
#   scripts/worker-vm.sh stop <vm-name>    # Stop the VM
#   scripts/worker-vm.sh delete <vm-name>  # Delete the VM entirely
#   scripts/worker-vm.sh list              # List all worker VMs
#
# Worker VMs use the same lima/kubelet.yaml config as the main lima-node.
# Each VM is isolated — workers can run full conformance suites in parallel.
#
# Example (in a worker dispatch brief):
#   export U7S_VM_NAME=lima-node-2
#   scripts/worker-vm.sh start lima-node-2
#   SONOBUOY_FOCUS='...' scripts/conformance/run-all.sh
#   scripts/worker-vm.sh stop lima-node-2
#
# Resource requirements per VM: ~4 GB RAM, ~20 GB disk.
# With a 24 GB host budget, up to 6 parallel VMs are feasible.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LIMA_YAML="$REPO/lima/kubelet.yaml"

usage() {
  echo "Usage:" >&2
  echo "  $0 start <vm-name>   Provision VM if needed, then start it" >&2
  echo "  $0 stop <vm-name>    Stop the VM" >&2
  echo "  $0 delete <vm-name>  Delete the VM (prompts if running)" >&2
  echo "  $0 list              List all worker VMs (excludes lima-node)" >&2
  exit 1
}

if [[ $# -lt 1 ]]; then
  usage
fi

COMMAND="$1"
shift

case "$COMMAND" in
  start)
    if [[ $# -lt 1 ]]; then
      echo "error: 'start' requires a VM name" >&2; exit 1
    fi
    NAME="$1"
    if limactl list --format '{{.Name}}' 2>/dev/null | grep -q "^${NAME}$"; then
      STATUS=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk "/^${NAME} / {print \$2}")
      if [ "$STATUS" = "Running" ]; then
        echo "VM '$NAME' is already running."
      else
        echo "Starting stopped VM '$NAME'..."
        limactl start "$NAME"
        echo "VM '$NAME' started."
      fi
    else
      if [ ! -f "$LIMA_YAML" ]; then
        echo "error: lima config not found at $LIMA_YAML" >&2; exit 1
      fi
      echo "Provisioning VM '$NAME' (first run, takes ~5 min)..."
      limactl start --tty=false --name="$NAME" "$LIMA_YAML"
      echo "VM '$NAME' provisioned and started."
    fi
    ;;

  stop)
    if [[ $# -lt 1 ]]; then
      echo "error: 'stop' requires a VM name" >&2; exit 1
    fi
    NAME="$1"
    echo "Stopping VM '$NAME'..."
    limactl stop "$NAME"
    echo "VM '$NAME' stopped."
    ;;

  delete)
    if [[ $# -lt 1 ]]; then
      echo "error: 'delete' requires a VM name" >&2; exit 1
    fi
    NAME="$1"
    STATUS=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk "/^${NAME} / {print \$2}" || true)
    if [ "$STATUS" = "Running" ]; then
      echo "VM '$NAME' is currently running."
      read -r -p "Stop and delete '$NAME'? [y/N] " CONFIRM
      if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        echo "Aborted." >&2; exit 1
      fi
      limactl stop "$NAME"
    fi
    echo "Deleting VM '$NAME'..."
    limactl delete "$NAME"
    echo "VM '$NAME' deleted."
    ;;

  list)
    echo "Worker VMs (excluding lima-node):"
    limactl list 2>/dev/null | grep -v "^NAME\|^lima-node " || echo "  (none)"
    ;;

  *)
    echo "error: unknown command '$COMMAND'" >&2
    usage
    ;;
esac
