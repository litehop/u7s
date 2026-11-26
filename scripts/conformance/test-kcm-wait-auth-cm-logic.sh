#!/usr/bin/env bash
# 04-start-kcm.sh must not start a KCM whose fatal delegated-authn lookup will fail: when
# kube-system/extension-apiserver-authentication is never published, wait_for_auth_configmap
# must return non-zero (the caller exits 1) instead of letting the supervisor burn its crash
# budget; when it is published, it must return 0, including after some failed probes.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
# Fake kubectl: succeeds once it has been called more than $TMP/fail_first times.
cat > "$TMP/bin/kubectl" <<EOF
#!/bin/sh
echo "\$*" >> "$TMP/calls"
n=\$(wc -l < "$TMP/calls")
[ "\$n" -gt "\$(cat "$TMP/fail_first")" ]
EOF
chmod +x "$TMP/bin/kubectl"

PASS=0
FAIL=0
assert() {
  if [ "$2" = 1 ]; then echo "PASS: $1"; PASS=$((PASS + 1)); else echo "FAIL: $1"; FAIL=$((FAIL + 1)); fi
}

# shellcheck source=scripts/conformance/kcm-wait-auth-cm.sh
source "$DIR/kcm-wait-auth-cm.sh"
export KCM_AUTH_CM_TRIES=3 KCM_AUTH_CM_INTERVAL=0
run() { : > "$TMP/calls"; echo "$1" > "$TMP/fail_first"; rc=0; PATH="$TMP/bin:$PATH" wait_for_auth_configmap /k/kubeconfig 2>"$TMP/err" || rc=$?; }

run 999
assert "returns non-zero when the ConfigMap is never published (else a crash-looping KCM is started)" \
  "$([ "$rc" != 0 ] && echo 1 || echo 0)"
assert "gives up after exactly the configured tries" "$([ "$(wc -l < "$TMP/calls")" -eq 3 ] && echo 1 || echo 0)"
assert "failure message names the missing ConfigMap" \
  "$(grep -q 'extension-apiserver-authentication' "$TMP/err" && echo 1 || echo 0)"
assert "probes with the given kubeconfig in kube-system" \
  "$(grep -qF -- '--kubeconfig=/k/kubeconfig -n kube-system get configmap extension-apiserver-authentication' "$TMP/calls" && echo 1 || echo 0)"

run 0
assert "returns 0 on the first probe when the ConfigMap exists" \
  "$([ "$rc" = 0 ] && [ "$(wc -l < "$TMP/calls")" -eq 1 ] && echo 1 || echo 0)"

run 2
assert "returns 0 when the ConfigMap appears after failed probes (apiserver still booting)" \
  "$([ "$rc" = 0 ] && [ "$(wc -l < "$TMP/calls")" -eq 3 ] && echo 1 || echo 0)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
