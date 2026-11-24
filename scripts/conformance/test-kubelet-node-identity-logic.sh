#!/usr/bin/env bash
# Regression test: the conformance rig's kubelet must authenticate as its own
# system:node:<VM> identity, never the admin kubeconfig. A kubelet running as
# system:masters bypasses the Node authorizer and NodeRestriction, so the rig
# would not exercise the authorization a real node is bound by, and a
# compromised kubelet would be cluster-admin.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_START="$DIR/lima-start.sh"

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
assert "lima-start.sh issues the kubelet client cert with CN=system:node:<VM> in O=system:nodes" \
  "$(grep -qF -- '-subj "/O=system:nodes/CN=system:node:${VM_NAME}"' "$LIMA_START" && echo 1 || echo 0)"
assert "the kubelet's kubeconfig user is its client cert files, so kubelet's cert rotation can replace them" \
  "$(grep -qF 'client-certificate: /etc/kubelet-client.crt' "$LIMA_START" && echo 1 || echo 0)"

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
assert "a cert signed by the current CA is reused (no needless re-issue)" \
  "$(node_client_cert_valid "$WORK/good.crt" "$WORK/ca1.pem" && echo 1 || echo 0)"
assert "a cert signed by a previous CA is re-issued (a wiped workdir mints a new ca.key; the kubelet would 401 on a healthy stack)" \
  "$(node_client_cert_valid "$WORK/good.crt" "$WORK/ca2.pem" && echo 0 || echo 1)"
assert "a missing cert is re-issued" \
  "$(node_client_cert_valid "$WORK/absent.crt" "$WORK/ca1.pem" && echo 0 || echo 1)"
assert "the expired fixture really is expired (otherwise the expiry check proves nothing)" \
  "$(openssl x509 -in "$WORK/expired.crt" -noout -checkend 0 >/dev/null 2>&1 && echo 0 || echo 1)"
assert "an expired cert is re-issued even when it chains to the current CA" \
  "$(node_client_cert_valid "$WORK/expired.crt" "$WORK/ca1.pem" && echo 0 || echo 1)"

echo ""
echo "Results:${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
