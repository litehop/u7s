#!/usr/bin/env bash
# Logic test for the pure helpers in intermediate-rotation.sh. The e2e's verdicts rest on them:
# chain_verifies (a leaf verifies to the root only through its intermediate), leaf_alone_verifies
# (the leaf-only failure that makes the chain mandatory), nth_cert/cert_field (which cert in a
# served chain is the intermediate, and its serial) and poll (a deadline that expires).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/e2e-pki-rotation/intermediate-rotation.sh
source "$HERE/intermediate-rotation.sh"
POLL_INTERVAL=0.2

PASS=0; FAIL=0
check() {
  local label="$1"; shift
  if "$@"; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label"; FAIL=$((FAIL + 1)); fi
}
not() { ! "$@"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Keys come from ecparam (named-curve encoding) and signing uses -sha256: see ca-bundle.sh.
key() { openssl ecparam -genkey -name prime256v1 -noout -out "$TMP/$1.key"; }
ca() { # ca <name> <subject-cn> <pathlen-or-empty> [issuer-name]
  local name="$1" cn="$2" ext="basicConstraints=critical,CA:TRUE${3:+,pathlen:$3}"
  key "$name"
  if [ -z "${4:-}" ]; then
    openssl req -x509 -new -sha256 -key "$TMP/$name.key" -days 2 -subj "/CN=$cn" \
      -addext "$ext" -addext "keyUsage=critical,keyCertSign" -out "$TMP/$name.pem" 2>/dev/null
  else
    openssl req -new -key "$TMP/$name.key" -subj "/CN=$cn" -out "$TMP/$name.csr" 2>/dev/null
    printf '%s\nkeyUsage=critical,keyCertSign\n' "$ext" >"$TMP/$name.ext"
    openssl x509 -req -sha256 -in "$TMP/$name.csr" -CA "$TMP/$4.pem" -CAkey "$TMP/$4.key" \
      -CAcreateserial -days 1 -extfile "$TMP/$name.ext" -out "$TMP/$name.pem" 2>/dev/null
  fi
}
leaf() { # leaf <name> <issuer-name>
  key "$1"
  openssl req -new -key "$TMP/$1.key" -subj "/CN=$1" -out "$TMP/$1.csr" 2>/dev/null
  printf 'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n' >"$TMP/$1.ext"
  openssl x509 -req -sha256 -in "$TMP/$1.csr" -CA "$TMP/$2.pem" -CAkey "$TMP/$2.key" \
    -CAcreateserial -days 1 -extfile "$TMP/$1.ext" -out "$TMP/$1.pem" 2>/dev/null
}

ca root root ""
ca int-a int-a 0 root
ca int-b int-b 0 root
leaf client int-a
cat "$TMP/client.pem" "$TMP/int-a.pem" >"$TMP/chain-a.pem"
cat "$TMP/client.pem" "$TMP/int-b.pem" >"$TMP/chain-wrong.pem"

check "a leaf with its intermediate verifies to the root" chain_verifies "$TMP/root.pem" "$TMP/chain-a.pem"
check "the same leaf alone does not verify: the root never signed it, so a client without the intermediate is locked out" \
  not leaf_alone_verifies "$TMP/root.pem" "$TMP/chain-a.pem"
check "a leaf offered with a different intermediate does not verify, so a swap to the wrong signer is caught" \
  not chain_verifies "$TMP/root.pem" "$TMP/chain-wrong.pem"
check "a chain is counted by its certificates" test "$(cert_count <"$TMP/chain-a.pem")" = 2
check "the second cert of a chain is the intermediate" \
  test "$(cert_field 2 "$TMP/chain-a.pem" -serial)" = "$(openssl x509 -noout -serial -in "$TMP/int-a.pem")"
check "the intermediates have different serials, so a rotation is observable" \
  not test "$(openssl x509 -noout -serial -in "$TMP/int-a.pem")" = "$(openssl x509 -noout -serial -in "$TMP/int-b.pem")"
check "a content hash is stable for an unchanged file, so an untouched root is not reported as rewritten" \
  test "$(sha "$TMP/root.pem")" = "$(sha "$TMP/root.pem")"
check "a content hash differs between files, so a rewritten root is caught" \
  not test "$(sha "$TMP/root.pem")" = "$(sha "$TMP/int-a.pem")"

tries="$TMP/tries"; : >"$tries"
third_try() { echo x >>"$tries"; [ "$(wc -l <"$tries")" -ge 3 ]; }
check "poll returns success once the condition turns true" poll 5 third_try
check "poll gives up after its deadline instead of hanging" not poll 1 false

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
