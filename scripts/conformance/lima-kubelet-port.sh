#!/usr/bin/env bash
# Print the host port a Lima VM forwards guest 10250 (kubelet) to, read from
# its live ~/.lima/<vm>/lima.yaml (override the root with LIMA_HOME).
#
# Usage: scripts/conformance/lima-kubelet-port.sh <vm-name>
#
# Exits non-zero with a message if the VM dir or the mapping is missing.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <vm-name>" >&2
  exit 2
fi
VM="$1"
YAML="${LIMA_HOME:-$HOME/.lima}/$VM/lima.yaml"

if [ ! -f "$YAML" ]; then
  echo "error: $YAML not found (VM '$VM' does not exist)" >&2
  exit 1
fi

# An entry is a "- " list item under portForwards:; guestPort/hostPort may
# appear in either order within it.
PORT=$(awk '
  /^portForwards:/ { in_pf = 1; next }
  in_pf && /^[A-Za-z]/ { exit }
  in_pf && /^[[:space:]]*#/ { next }
  in_pf && /^[[:space:]]*-[[:space:]]/ { guest = ""; host = "" }
  in_pf && /guestPort:/ { guest = $NF }
  in_pf && /hostPort:/ { host = $NF }
  in_pf && guest == "10250" && host != "" { print host; exit }
' "$YAML")

if [ -z "$PORT" ]; then
  echo "error: $YAML has no portForwards entry mapping guestPort 10250 to a hostPort" >&2
  exit 1
fi
echo "$PORT"
