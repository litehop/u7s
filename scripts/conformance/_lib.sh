#!/usr/bin/env bash
# Shared helpers for scripts/conformance/*.sh and scripts/u7s-start.sh.
# Internal (underscore-prefixed): source this, don't run it directly.

# Two u7s stacks binding the same default host port race for it: whichever
# process boots first wins the bind silently, and the loser either misroutes
# (e.g. a kubelet hostPort forward pointed at the WRONG kubelet) or dies
# inside a spawned binary with the real cause buried in that binary's own log
# instead of a clear message at the point of failure. Hard-fail here rather
# than auto-allocate a free port, so the operator stays the source of truth
# for which stack owns which port (see ai/prompts/vm-operations.md for the
# per-worker port-assignment scheme). Fires regardless of whether the port
# came from a default or was explicitly passed by the operator — a collision
# is a bug either way.
check_port_free() {
  local port="$1"
  local label="$2"
  local holder=""
  if command -v lsof &>/dev/null; then
    # lsof exits 1 (not just empty stdout) when it finds no matching
    # process — the expected, happy-path outcome of THIS check (port is
    # free). Under the caller's `set -euo pipefail`, an unguarded pipeline
    # here aborts the whole script on that exit code before the `[ -n
    # "$holder" ]` check below ever runs, so every genuinely free-port case
    # (the common case on a fresh --reset) killed run-all.sh silently right
    # at this line. `|| true` restores the intended semantics: only the
    # `[ -n "$holder" ]` branch below should ever exit non-zero.
    holder=$(lsof -n -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -1) || true
  elif command -v nc &>/dev/null && nc -z 127.0.0.1 "$port" 2>/dev/null; then
    holder="unknown (lsof not installed; nc -z detected a listener)"
  fi
  if [ -n "$holder" ]; then
    echo "error: host port 127.0.0.1:${port} (${label}) is already bound (a previous stack or another VM is using it)." >&2
    echo "  Assign this stack a different ${label} port — see ai/prompts/vm-operations.md for the per-worker port-assignment scheme." >&2
    echo "  To see what's holding the port: lsof -n -i :${port}" >&2
    exit 1
  fi
}

# Derives the per-node resource suffix (konnectivity-agent Pod/Secret, kubelet
# serving cert) for a VM_NAME. Single source of truth for BOTH lima-start.sh
# (the primary/direct-start path) and add-node.sh (the --extra-node join path)
# so the two can never independently drift back out of sync — that drift once
# had add-node.sh hardcode "-2" regardless of which VM it was actually joining,
# colliding with a primary that itself auto-derives a different numbered
# suffix from its own name.
# lima-node and lima-node-smoke keep the empty default: their names carry no
# slot number (and lima-start.sh's POD_SUBNET_OCTET can't parse a non-numeric
# suffix).
node_suffix_for() {
  local vm_name="$1" override="${2:-}"
  case "$vm_name" in
    lima-node-[0-9]*) echo "${override:-"-${vm_name#lima-node-}"}" ;;
    *) echo "${override:-}" ;;
  esac
}
