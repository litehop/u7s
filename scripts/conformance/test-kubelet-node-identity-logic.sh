#!/usr/bin/env bash
# Regression test: the conformance rig's kubelet must authenticate as its own
# system:node:<VM> identity, issued the way install.sh issues it (CSR under a bootstrap
# token, signed by KCM), never the admin kubeconfig and never a cert the host signs with the
# CA key. A kubelet running as system:masters bypasses the Node authorizer and
# NodeRestriction, so the rig would not exercise the authorization a real node is bound by;
# a host-signed cert skips the CSR approval/signing path a real node depends on.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_START="$DIR/lima-start.sh"
INSTALL_SH="$DIR/../install.sh"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

assert "lima-start.sh must not install the admin kubeconfig as the kubelet's kubeconfig (it would make the kubelet system:masters)" \
  "$(grep -q 'REWRITTEN' "$LIMA_START" && echo 0 || echo 1)"
assert "lima-start.sh never signs the node cert on the host (the rig would skip the CSR approval and signing path a real node depends on)" \
  "$(grep -qE -- 'O=system:nodes|kubelet-client\$\{NODE_SUFFIX\}' "$LIMA_START" && echo 0 || echo 1)"
assert "lima-start.sh issues the identity through install.sh's issue_cp_kubelet_identity" \
  "$(grep -qF 'rig_kubelet_issue_script' "$LIMA_START" && echo 1 || echo 0)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

source "$DIR/_lib.sh"
mkdir -p "$WORK/bin" "$WORK/etc"
printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/systemctl"
chmod +x "$WORK/bin/systemctl"
rig_kubelet_config_script 10.96.0.10 "$DIR/../install.sh" | sed -e "s#/etc/#$WORK/etc/#g" > "$WORK/render.sh"
PATH="$WORK/bin:$PATH" bash "$WORK/render.sh"
RENDERED="$WORK/etc/u7s-rig/kubelet-config.yaml"
assert "the rig kubelet config rotates its client cert (without it the node cert expires and the node drops off the cluster)" \
  "$(grep -qx 'rotateCertificates: true' "$RENDERED" && echo 1 || echo 0)"
assert "the rig kubelet config bootstraps its serving cert through the CSR API (without it the kubelet serves a self-signed cert the apiserver rejects, breaking kubectl logs/exec)" \
  "$(grep -qx 'serverTLSBootstrap: true' "$RENDERED" && echo 1 || echo 0)"
assert "lima-start.sh no longer pins a static kubelet serving cert (a file nothing renews would expire under a running rig)" \
  "$(grep -qE -- '--tls-cert-file|--tls-private-key-file|kubelet-tls\.crt' "$LIMA_START" && echo 0 || echo 1)"
assert "the kubelet's RotateKubeletServerCertificate gate stays on in the rig (serverTLSBootstrap needs it)" \
  "$(grep -q 'RotateKubeletServerCertificate' "$LIMA_START" && echo 0 || echo 1)"

ca_key() { openssl ecparam -genkey -name prime256v1 -noout -out "$1"; openssl req -x509 -new -key "$1" -subj "/CN=$2" -days 2 -out "$3" 2>/dev/null; }
ca_key "$WORK/ca1.key" ca1 "$WORK/ca1.pem"
ca_key "$WORK/ca2.key" ca2 "$WORK/ca2.pem"
openssl ecparam -genkey -name prime256v1 -noout -out "$WORK/n.key"
openssl req -new -key "$WORK/n.key" -subj "/O=system:nodes/CN=system:node:x" -out "$WORK/n.csr"
openssl x509 -req -in "$WORK/n.csr" -CA "$WORK/ca1.pem" -CAkey "$WORK/ca1.key" -CAcreateserial -days 1 -out "$WORK/good.crt" 2>/dev/null
: > "$WORK/index.txt"
echo 01 > "$WORK/serial"
cat > "$WORK/ca.cnf" <<EOF
[ca]
default_ca = d
[d]
database = $WORK/index.txt
new_certs_dir = $WORK
serial = $WORK/serial
certificate = $WORK/ca1.pem
private_key = $WORK/ca1.key
default_md = sha256
policy = p
unique_subject = no
[p]
commonName = supplied
EOF
openssl ca -config "$WORK/ca.cnf" -in "$WORK/n.csr" -startdate 20200101000000Z -enddate 20200102000000Z -batch -notext -out "$WORK/expired.crt" >/dev/null 2>&1
assert "the expired fixture really is expired (otherwise the expiry check proves nothing)" \
  "$(openssl x509 -in "$WORK/expired.crt" -noout -checkend 0 >/dev/null 2>&1 && echo 0 || echo 1)"

# The VM-side identity check, run locally with the state dir redirected under $WORK.
IDENTITY="$(rig_kubelet_identity_script "$INSTALL_SH" | sed -e "s#/etc/u7s-rig#$WORK/state#g")"
have_identity() {
  rm -rf "$WORK/state"
  mkdir -p "$WORK/state/kubelet/pki"
  cp "$2" "$WORK/state/ca-bundle.pem"
  echo kc > "$WORK/state/kubelet-kubeconfig"
  [ -z "$1" ] || cp "$1" "$WORK/state/kubelet-client.crt"
  [ -z "${3:-}" ] || cp "$3" "$WORK/state/kubelet/pki/kubelet-client-current.pem"
  bash -c "$IDENTITY" >/dev/null 2>&1 && echo 1 || echo 0
}
assert "a cert signed by the current CA is kept (no needless re-issue: it would replace a cert the kubelet already rotated)" \
  "$(have_identity "$WORK/good.crt" "$WORK/ca1.pem")"
assert "a cert signed by a previous CA forces a re-join (a wiped workdir mints a new CA; the kubelet would 401 on a healthy stack)" \
  "$([ "$(have_identity "$WORK/good.crt" "$WORK/ca2.pem")" = 0 ] && echo 1 || echo 0)"
assert "a missing cert forces a join" \
  "$([ "$(have_identity "" "$WORK/ca1.pem")" = 0 ] && echo 1 || echo 0)"
assert "an expired cert forces a re-join even when it chains to the current CA" \
  "$([ "$(have_identity "$WORK/expired.crt" "$WORK/ca1.pem")" = 0 ] && echo 1 || echo 0)"
assert "a rotated cert under kubelet/pki is accepted when the join-time cert has expired (the kubelet renews it over the CSR API)" \
  "$(have_identity "$WORK/expired.crt" "$WORK/ca1.pem" "$WORK/good.crt")"

echo ""
echo "Results:${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
