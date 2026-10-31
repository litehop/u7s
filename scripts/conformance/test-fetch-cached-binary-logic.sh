#!/usr/bin/env bash
# Regression test for fetch-cached-binary.sh (04-start-kcm.sh's KCM fetch).
#
# A run-all.sh killed mid-download used to leave a truncated, non-executable
# kube-controller-manager in the VM cache; every later run reused it, KCM never
# started and the node never got a podCIDR. curl is stubbed on PATH (no
# network) to serve a fixture binary plus its .sha256 sidecar.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FETCH="$SCRIPT_DIR/fetch-cached-binary.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin" "$WORK/srv"
printf '#!/bin/sh\necho kcm-fixture-binary-with-enough-bytes-to-truncate\n' > "$WORK/srv/kcm"
shasum_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
shasum_of "$WORK/srv/kcm" > "$WORK/srv/kcm.sha256"

# Stub curl: `curl -fsSL URL [-o FILE]`; serves $WORK/srv/<basename URL>, counts binary downloads.
cat > "$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
url="" out=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
done
src="$STUB_SRV/$(basename "$url")"
[ -f "$src" ] || exit 22
if [ -n "$out" ]; then
  echo x >> "$STUB_SRV/downloads"
  cp "$src" "$out"
else
  cat "$src"
fi
STUB
chmod +x "$WORK/bin/curl"
export STUB_SRV="$WORK/srv" PATH="$WORK/bin:$PATH"

PASS=0 FAIL=0
assert() {
  if [ "$2" = 1 ]; then echo "PASS: $1"; PASS=$((PASS + 1)); else echo "FAIL: $1"; FAIL=$((FAIL + 1)); fi
}
downloads() { if [ -f "$WORK/srv/downloads" ]; then wc -l < "$WORK/srv/downloads" | tr -d ' '; else echo 0; fi; }
URL="https://dl.example/kcm"
DEST="$WORK/cache/kcm-bin"

rc=0; out="$("$FETCH" "$URL" "$DEST" 2>&1)" || rc=$?
assert "cold cache downloads once and leaves a verified executable" \
  "$([ "$rc" = 0 ] && [ -x "$DEST" ] && [ "$(shasum_of "$DEST")" = "$(cat "$WORK/srv/kcm.sha256")" ] && [ "$(downloads)" = 1 ] && echo 1 || echo 0)"
assert "no temp file is left beside the binary (a partial file at the final path or beside it is what poisoned the cache)" \
  "$([ "$(ls "$WORK/cache" | wc -l | tr -d ' ')" = 1 ] && echo 1 || echo 0)"

rc=0; out="$("$FETCH" "$URL" "$DEST" 2>&1)" || rc=$?
assert "a valid cache is reused without a download" \
  "$([ "$rc" = 0 ] && [ "$(downloads)" = 1 ] && echo 1 || echo 0)"

head -c 20 "$WORK/srv/kcm" > "$DEST"
chmod -x "$DEST"
rc=0; out="$("$FETCH" "$URL" "$DEST" 2>&1)" || rc=$?
assert "a truncated non-executable cache is re-fetched, so KCM starts instead of 'Permission denied'" \
  "$([ "$rc" = 0 ] && [ -x "$DEST" ] && [ "$(shasum_of "$DEST")" = "$(cat "$WORK/srv/kcm.sha256")" ] && [ "$(downloads)" = 2 ] && echo 1 || echo 0)"
assert "the truncated cache is reported loudly" \
  "$(printf '%s' "$out" | grep -q 'WARNING.*corrupt' && echo 1 || echo 0)"

# Executable but wrong content must also be rejected (mode alone proves nothing).
head -c 20 "$WORK/srv/kcm" > "$DEST"; chmod +x "$DEST"
rc=0; out="$("$FETCH" "$URL" "$DEST" 2>&1)" || rc=$?
assert "a truncated but executable cache is re-fetched" \
  "$([ "$rc" = 0 ] && [ "$(shasum_of "$DEST")" = "$(cat "$WORK/srv/kcm.sha256")" ] && [ "$(downloads)" = 3 ] && echo 1 || echo 0)"

# Server serves bytes that do not match the sidecar: must fail loud, leave nothing at DEST.
rm -f "$DEST"
printf 'corrupted-in-transit' > "$WORK/srv/kcm"
rc=0; out="$("$FETCH" "$URL" "$DEST" 2>&1)" || rc=$?
assert "a checksum mismatch on download fails loudly" \
  "$([ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'sha256 mismatch' && echo 1 || echo 0)"
assert "a mismatched download never reaches the final path or leaves a temp file" \
  "$([ ! -e "$DEST" ] && [ "$(ls "$WORK/cache" | wc -l | tr -d ' ')" = 0 ] && echo 1 || echo 0)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
