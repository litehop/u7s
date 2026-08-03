#!/usr/bin/env bash
# Manage a named worker VM for isolated conformance testing.
#
# Usage:
#   scripts/worker-vm.sh start <vm-name> [<host-ip> [<kubelet-port>]]  # Provision VM if needed, start it
#   scripts/worker-vm.sh stop <vm-name>                 # Stop the VM
#   scripts/worker-vm.sh delete <vm-name>               # Delete the VM entirely
#   scripts/worker-vm.sh list                           # List all worker VMs with IPs
#
# Worker VMs use the same lima/kubelet.yaml config as the main lima-node.
# Each VM is isolated — workers can run full conformance suites in parallel.
#
# When <host-ip> is provided to start:
#   - A loopback alias is added: sudo ifconfig lo0 alias <host-ip>
#   - The VM's kubelet portForward hostIP is set to <host-ip>
#   - The IP is stored in ~/.config/u7s-workers/<vm-name>.ip for later use
#   - Set U7S_HOST_IP=<host-ip> when running scripts/u7s-start.sh and run-all.sh
#
# When <kubelet-port> is provided to start (default: 10250):
#   - The VM's portForward hostPort for guest 10250 is set to <kubelet-port>
#   - Pass --kubelet-port <kubelet-port> to run-all.sh / u7s-start.sh so the apiserver
#     dials the correct host port for log/exec/attach requests
#
# Example (in a worker dispatch brief):
#   export U7S_VM_NAME=lima-node-2
#   scripts/worker-vm.sh start lima-node-2 127.0.0.1 10251
#   scripts/conformance/run-all.sh --vm lima-node-2 --port 6444 --kubelet-port 10251
#   scripts/worker-vm.sh stop lima-node-2
#
# Resource requirements per VM: ~4 GB RAM, ~20 GB disk.
# With a 24 GB host budget, up to 6 parallel VMs are feasible.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LIMA_YAML="$REPO/lima/kubelet.yaml"
STATE_DIR="${HOME}/.config/u7s-workers"

usage() {
  echo "Usage:" >&2
  echo "  $0 start <vm-name> [<host-ip>]  Provision VM if needed, then start it" >&2
  echo "  $0 stop <vm-name>               Stop the VM" >&2
  echo "  $0 delete <vm-name>             Delete the VM (prompts if running)" >&2
  echo "  $0 list                         List all worker VMs (excludes lima-node)" >&2
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
    IP="${2:-127.0.0.1}"
    KUBELET_PORT="${3:-10250}"

    # Add loopback alias when using a non-default IP.
    if [ "$IP" != "127.0.0.1" ]; then
      echo "Adding loopback alias $IP ..."
      sudo ifconfig lo0 alias "$IP" 2>/dev/null || true
    fi

    # Use the instance directory as authoritative existence check — limactl list
    # can transiently return empty output if lima is busy, which would otherwise
    # cause the provisioning branch to run and hit "instance already exists"
    # (see scripts/conformance/lima-start.sh for the same fix).
    VM_DIR="${HOME}/.lima/${NAME}"
    if [ -d "$VM_DIR" ]; then
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
      SET_ARGS=""
      [ "$IP" != "127.0.0.1" ] && SET_ARGS="$SET_ARGS --set .portForwards[0].hostIP=\"$IP\""
      [ "$KUBELET_PORT" != "10250" ] && SET_ARGS="$SET_ARGS --set .portForwards[0].hostPort=$KUBELET_PORT"
      if [ -n "$SET_ARGS" ]; then
        # shellcheck disable=SC2086
        limactl start --tty=false --name="$NAME" $SET_ARGS "$LIMA_YAML"
      else
        limactl start --tty=false --name="$NAME" "$LIMA_YAML"
      fi
      echo "VM '$NAME' provisioned and started."
    fi

    # Store the IP and kubelet port so other scripts can read them.
    mkdir -p "$STATE_DIR"
    echo "$IP" > "$STATE_DIR/${NAME}.ip"
    echo "$KUBELET_PORT" > "$STATE_DIR/${NAME}.kubelet-port"
    echo "Host IP $IP and kubelet port $KUBELET_PORT stored in $STATE_DIR/${NAME}.*"
    ;;

  stop)
    if [[ $# -lt 1 ]]; then
      echo "error: 'stop' requires a VM name" >&2; exit 1
    fi
    NAME="$1"
    echo "Stopping VM '$NAME'..."
    limactl stop "$NAME"
    echo "VM '$NAME' stopped."
    # Do NOT remove the loopback alias — another worker VM may use it.
    ;;

  delete)
    if [[ $# -lt 1 ]]; then
      echo "error: 'delete' requires a VM name" >&2; exit 1
    fi
    NAME="$1"
    # Use the instance directory as authoritative existence check — limactl list
    # can transiently return empty output if lima is busy, which would otherwise
    # cause the "not Running" branch below to fire even for a live VM
    # (see scripts/conformance/lima-start.sh for the same fix).
    VM_DIR="${HOME}/.lima/${NAME}"
    if [ ! -d "$VM_DIR" ]; then
      echo "error: VM '$NAME' does not exist" >&2; exit 1
    fi
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

    # Remove loopback alias only if no other worker VM uses the same IP.
    IP_FILE="$STATE_DIR/${NAME}.ip"
    if [ -f "$IP_FILE" ]; then
      STORED_IP=$(cat "$IP_FILE")
      if [ "$STORED_IP" != "127.0.0.1" ]; then
        # Check if any other state file references this IP.
        OTHERS=$(grep -rl "^${STORED_IP}$" "$STATE_DIR/" 2>/dev/null | grep -v "${NAME}.ip" || true)
        if [ -z "$OTHERS" ]; then
          echo "Removing loopback alias $STORED_IP ..."
          sudo ifconfig lo0 -alias "$STORED_IP" 2>/dev/null || true
        else
          echo "Loopback alias $STORED_IP retained (still used by another worker VM)."
        fi
      fi
      rm -f "$IP_FILE"
    fi

    echo "VM '$NAME' deleted."
    ;;

  list)
    echo "Worker VMs (excluding lima-node):"
    FOUND=0
    while IFS= read -r line; do
      VM=$(echo "$line" | awk '{print $1}')
      STATUS=$(echo "$line" | awk '{print $2}')
      [ "$VM" = "NAME" ] && continue
      [ "$VM" = "lima-node" ] && continue
      IP=""
      if [ -f "$STATE_DIR/${VM}.ip" ]; then
        IP=$(cat "$STATE_DIR/${VM}.ip")
      fi
      printf "%-20s %-12s %s\n" "$VM" "$STATUS" "$IP"
      FOUND=1
    done < <(limactl list 2>/dev/null)
    [ "$FOUND" -eq 0 ] && echo "  (none)"
    ;;

  *)
    echo "error: unknown command '$COMMAND'" >&2
    usage
    ;;
esac
