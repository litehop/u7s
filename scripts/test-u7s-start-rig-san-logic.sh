#!/usr/bin/env bash
# Regression guard: every u7s-apiserver launch in scripts/u7s-start.sh must carry
# --apiserver-cert-extra-sans host.lima.internal. The rig kubelet dials the host as
# host.lima.internal; without the SAN its TLS verification fails and the node never
# registers, while the Rust unit tests stay green.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${1:-$DIR/u7s-start.sh}"

fail=0
check() {
  if [ "$2" = 1 ]; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi
}

san_def="$(grep -c '^RIG_SAN_ARG="--apiserver-cert-extra-sans host\.lima\.internal"$' "$SCRIPT" || true)"
check "RIG_SAN_ARG carries --apiserver-cert-extra-sans host.lima.internal" "$([ "$san_def" -eq 1 ] && echo 1 || echo 0)"

# Each launch is a `"$BINARY" \` line plus its backslash-continued flag lines.
report="$(awk '
  function close_block() { if (inblk) { n++; if (!has) bad++ } inblk = 0; has = 0 }
  /^[ \t]*"\$BINARY"[ \t]*\\$/ { inblk = 1; has = 0; next }
  inblk { if (/\$RIG_SAN_ARG/) has = 1; if ($0 !~ /\\$/) close_block() }
  END { close_block(); print n + 0, bad + 0 }
' "$SCRIPT")"
launches="${report% *}"
missing="${report#* }"
check "script has u7s-apiserver launches (found $launches)" "$([ "$launches" -ge 1 ] && echo 1 || echo 0)"
check "every launch passes \$RIG_SAN_ARG ($missing of $launches missing it)" "$([ "$missing" -eq 0 ] && echo 1 || echo 0)"

exit "$fail"
