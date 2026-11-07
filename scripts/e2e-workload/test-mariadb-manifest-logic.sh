#!/usr/bin/env bash
# Logic test for examples/e2e/wordpress/mariadb.yaml. The image entrypoint gives its temporary
# first-init server a fixed 30 s; on a cold small node a CPU limit throttles that init past it,
# the container exits, the restart skips init and MariaDB never becomes Ready. No cluster needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="${MARIADB_MANIFEST:-$HERE/../../examples/e2e/wordpress/mariadb.yaml}"

PASS=0; FAIL=0
check() {
  local label="$1" ok="$2"
  if [ "$ok" = 1 ]; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label"; FAIL=$((FAIL + 1)); fi
}

# The mariadb container's `resources.limits` block (indented children only).
limits="$(sed -n '/^            limits:$/,/^          securityContext:$/p' "$MANIFEST" | sed '1d;$d')"
args="$(sed -n '/^          args:$/,/^          env:$/p' "$MANIFEST")"

has() { if printf '%s\n' "$1" | grep -qE "$2"; then echo 1; else echo 0; fi; }

check "limits block was found (a moved block must not make the next checks vacuous)" \
  "$(has "$limits" '^ +memory: ')"
check "no cpu limit: a CFS quota throttles first init (and its exec probes) past the entrypoint's 30 s server wait" \
  "$([ "$(has "$limits" '^ +cpu:')" = 0 ] && echo 1 || echo 0)"
check "cpu request kept: scheduling and CPU shares for the pod stay defined" \
  "$(has "$(sed -n '/^            requests:$/,/^            limits:$/p' "$MANIFEST")" '^ +cpu: 250m$')"
check "innodb buffer pool shrunk: the 128M default is a third of the 384Mi limit on a 1 GiB node" \
  "$(has "$args" '^ +- --innodb-buffer-pool-size=')"
check "innodb redo log shrunk: smaller file to create and recover on the first start of a slow disk" \
  "$(has "$args" '^ +- --innodb-log-file-size=')"
check "startupProbe kept: first init may take minutes and must not be killed by liveness" \
  "$(has "$(cat "$MANIFEST")" '^ +startupProbe:$')"

echo "---- $PASS passed, $FAIL failed ----"
[ "$FAIL" = 0 ]
