#!/usr/bin/env bash
# Unit tests for konnectivity-server port forwarding to the --extra-node agent.
#
# Bug: run-all.sh --konnectivity-server-port N reached the primary's
# lima-start.sh but not add-node.sh, so the extra node's konnectivity-agent
# re-derived its port from --port and dialed a port the server wasn't on:
# kubectl logs/exec to pods on the extra node failed while the primary worked.
#
# add-node.sh runs here from a temp copy with stub lima-start.sh/kubectl, so
# the assertions exercise the real argument-building, not a hand-written mirror.
set -euo pipefail

PASS=0
FAIL=0
assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $label"; PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — expected '${expected}', got '${actual}'"; FAIL=$(( FAIL + 1 ))
  fi
}

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

assert_eq "default port 6443 derives konnectivity 8135" "8135" "$(konnectivity_server_port_for 6443)"
assert_eq "port 6444 derives 8235" "8235" "$(konnectivity_server_port_for 6444 "")"
assert_eq "explicit override wins over the derived default" "8239" "$(konnectivity_server_port_for 6444 8239)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/scripts"
cp "$DIR/add-node.sh" "$DIR/_lib.sh" "$TMP/scripts/"
printf '#!/usr/bin/env bash\necho "$@" > "%s/lima-start.args"\n' "$TMP" > "$TMP/scripts/lima-start.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/kubectl"
chmod +x "$TMP/scripts/lima-start.sh" "$TMP/bin/kubectl"

run_add_node() {
  PATH="$TMP/bin:$PATH" bash "$TMP/scripts/add-node.sh" lima-node-3 10261 "$@" >/dev/null 2>&1
  cat "$TMP/lima-start.args"
}
passed_port() { sed -n 's/.*--konnectivity-server-port \([0-9]*\).*/\1/p' <<<"$1"; }

assert_eq "add-node.sh forwards the override so the extra node's agent dials the server's real port" \
  "8239" "$(passed_port "$(run_add_node --port 6444 --konnectivity-server-port 8239)")"
assert_eq "add-node.sh without an override forwards the --port-derived port (matches the primary)" \
  "8235" "$(passed_port "$(run_add_node --port 6444)")"

RUN_ALL_CALL="$(grep 'add-node.sh" "\$EXTRA_NODE"' "$DIR/run-all.sh")"
assert_eq "run-all.sh passes _KONNECTIVITY_SERVER_PORT_ARG on its add-node.sh call" \
  "1" "$(grep -c '_KONNECTIVITY_SERVER_PORT_ARG' <<<"$RUN_ALL_CALL")"

echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
