#!/usr/bin/env bash
# The host rig's kubelet must run install.sh's own control-plane kubelet.service and get its
# identity through install.sh's own CSR flow, so a spec that passes on the rig passes on a
# real install. Covers: the unit is install.sh's heredoc (same ExecStart flags, --cert-dir so
# rotated certs survive a reset, feature gates from kubelet_round2_flags), the rig-only
# additions are a recorded drop-in that never touches ExecStart, the issued CSR has the
# identity KCM's approver requires, KCM is started before the issue, and a rig that drifts
# from install.sh's markers fails loud.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SH="$DIR/../install.sh"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"
# shellcheck source=scripts/lib/drain-grep.sh
source "$DIR/../lib/drain-grep.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
assert() { if [ "$2" = 1 ]; then ok "$1"; else bad "$1"; fi; }
has() { grep -qF -- "$2" "$1" && echo 1 || echo 0; }

mkdir -p "$TMP/bin"
printf '#!/bin/sh\nexit 0\n' > "$TMP/bin/systemctl"
printf '#!/bin/sh\necho "Kubernetes v1.37.1"\n' > "$TMP/bin/kubelet-stub"
chmod +x "$TMP/bin/"*

# Runs a generated in-VM script locally: /etc and the kubelet binary redirected under $TMP.
run_in_fake_vm() {
  sed -e "s#/etc/#$TMP/etc/#g" -e "s#/usr/bin/kubelet#$TMP/bin/kubelet-stub#g" -e "s#BIN_DIR=/usr/bin#BIN_DIR=$TMP/bin#" <<<"$1" > "$TMP/run.sh"
  PATH="$TMP/bin:$PATH" bash "$TMP/run.sh"
}

# --- the unit ---------------------------------------------------------------------------
mkdir -p "$TMP/etc/systemd/system"
run_in_fake_vm "$(rig_kubelet_unit_script "$INSTALL_SH" lima-x 10.0.0.5,fd85:1::1)" >/dev/null
UNIT="$TMP/etc/systemd/system/kubelet.service"
DROPIN="$TMP/etc/systemd/system/kubelet.service.d/u7s.conf"
EXEC="$(grep '^ExecStart=' "$UNIT")"

# The expected line is install.sh's control-plane ExecStart, with its variables filled in.
INSTALL_EXEC="$(awk '/^[[:space:]]*cat > \/etc\/systemd\/system\/kubelet\.service <<EOF$/ {n++} n == 2 && /^ExecStart=/ {print; exit}' "$INSTALL_SH")"
FLAGS="$(bash -c "$(install_sh_function kubelet_round2_flags "$INSTALL_SH"); kubelet_round2_flags 1.37")"
WANT="$(STATE_DIR=$TMP/etc/u7s-rig BIN_DIR=$TMP/bin NODE_NAME=lima-x NODE_IPS=10.0.0.5,fd85:1::1 KUBELET_ROUND2_FLAGS=$FLAGS \
  bash -c "cat <<EOF
$INSTALL_EXEC
EOF")"
assert "the unit's ExecStart is install.sh's control-plane ExecStart exactly (a hand-written rig line drifts: the rig would pass specs a real install cannot)" \
  "$([ -n "$WANT" ] && [ "$EXEC" = "$WANT" ] && echo 1 || echo 0)"
assert "the unit's feature gates come from install.sh's kubelet_round2_flags" \
  "$([ -n "$FLAGS" ] && [[ "$EXEC" == *" $FLAGS" ]] && echo 1 || echo 0)"
assert "the unit passes --cert-dir under the rig state dir (the kubelet default /var/lib/kubelet/pki lets a rotated cert from a deleted CA survive a reset)" \
  "$(has "$UNIT" "--cert-dir=$TMP/etc/u7s-rig/kubelet/pki")"
assert "the unit uses the identity's kubeconfig in the state dir" \
  "$(has "$UNIT" "--kubeconfig=$TMP/etc/u7s-rig/kubelet-kubeconfig ")"
assert "the unit adds no --v (verbosity is a kubelet-config field, so ExecStart stays install.sh's)" \
  "$([[ "$EXEC" == *"--v="* ]] && echo 0 || echo 1)"
assert "the unit does not depend on u7s-apiserver or convert its ca.crt (the rig's apiserver runs on the host)" \
  "$(grep -vE '^[[:space:]]*#' "$UNIT" | drain_grep -qE 'u7s-apiserver|^ExecStartPre' && echo 0 || echo 1)"
assert "the drop-in sets TZ=UTC and LimitNOFILE (the recorded rig-only additions)" \
  "$([ "$(has "$DROPIN" 'Environment=TZ=UTC')" = 1 ] && [ "$(has "$DROPIN" 'LimitNOFILE=1048576')" = 1 ] && echo 1 || echo 0)"
assert "the drop-in never resets ExecStart (it would replace install.sh's kubelet command line)" \
  "$([ "$(has "$DROPIN" 'ExecStart')" = 0 ] && echo 1 || echo 0)"
assert "the drop-in is exactly RIG_KUBELET_DROPIN, the text run-meta records" \
  "$([ "$(cat "$DROPIN")" = "$RIG_KUBELET_DROPIN" ] && echo 1 || echo 0)"
assert "RIG_ONLY_SETUP records the kubelet drop-in so an archive says the rig added it" \
  "$([[ ",$RIG_ONLY_HOST_SETUP," == *",kubelet-unit-dropin-tz-nofile,"* ]] && echo 1 || echo 0)"

BROKEN="$TMP/broken-install.sh"
sed 's/^kubelet_round2_flags() {$/renamed_flags() {/' "$INSTALL_SH" > "$BROKEN"
assert "a renamed kubelet_round2_flags fails loud instead of rendering a unit without its gates" \
  "$(rig_kubelet_unit_script "$BROKEN" n ip >/dev/null 2>&1 && echo 0 || echo 1)"
sed 's/^issue_cp_kubelet_identity() {$/renamed_issue() {/' "$INSTALL_SH" > "$BROKEN"
assert "a renamed issue_cp_kubelet_identity fails loud instead of falling back to a host-signed cert" \
  "$(rig_kubelet_issue_script "$BROKEN" /x n >/dev/null 2>&1 && echo 0 || echo 1)"

# --- the identity -----------------------------------------------------------------------
ISSUE="$(rig_kubelet_issue_script "$INSTALL_SH" "$TMP/state" lima-x)"
assert "the issue script replays install.sh's issue_cp_kubelet_identity (CSR approved by KCM, no host-side signing)" \
  "$(printf '%s\n' "$ISSUE" | drain_grep -qxF "$(install_sh_function issue_cp_kubelet_identity "$INSTALL_SH" | sed -n 1p)" && echo 1 || echo 0)"
assert "the issue script never signs with the CA key" \
  "$(printf '%s\n' "$ISSUE" | drain_grep -qE 'CAkey|ca\.key' && echo 0 || echo 1)"

# The CSR it submits: run only the generate_node_csr substitution.
CSR_SCRIPT="$(printf '%s\n' "$ISSUE" | sed -e '/^issue_cp_kubelet_identity$/d')"
mkdir -p "$TMP/state"
bash -c "$CSR_SCRIPT"$'\ngenerate_node_csr "$STATE_DIR/k.key" "$STATE_DIR/k.csr"'
SUBJ="$(openssl req -in "$TMP/state/k.csr" -noout -subject)"
assert "the CSR is CN=system:node:<name>, O=system:nodes (KCM auto-approves only that identity)" \
  "$([[ "$SUBJ" == *"O=system:nodes"* && "$SUBJ" == *"CN=system:node:lima-x"* ]] && echo 1 || echo 0)"
assert "the CSR is self-signed correctly" \
  "$(openssl req -in "$TMP/state/k.csr" -noout -verify >/dev/null 2>&1 && echo 1 || echo 0)"
assert "the node key is private (0600)" \
  "$([ "$(stat -f %Lp "$TMP/state/k.key" 2>/dev/null || stat -c %a "$TMP/state/k.key")" = 600 ] && echo 1 || echo 0)"
assert "the CSR key is a 256-bit EC key like install.sh's tool (the approver's usage set depends on the key type)" \
  "$(openssl pkey -in "$TMP/state/k.key" -noout -text 2>/dev/null | drain_grep -qF '(256 bit)' && echo 1 || echo 0)"
assert "the base64 shim accepts GNU's -w0 and emits one line (macOS base64 has no -w0)" \
  "$(bash -c "$(printf '%s\n' "$ISSUE" | sed -n '/^base64() /p'); printf 'a%.0s' \$(seq 1 200) | base64 -w0 | wc -l" | tr -d ' ' | { read -r n; [ "$n" = 0 ] && echo 1 || echo 0; })"

SHIM="$(printf '%s\n' "$ISSUE" | sed -n '/^base64() /p')"
assert "the base64 shim leaves decoded output alone (stripping its newlines corrupts the PEM cert and the kubelet cannot start)" \
  "$([ "$(bash -c "$SHIM; printf 'a\nb\n' | base64 | base64 -d | wc -l" | tr -d ' ')" = 2 ] && echo 1 || echo 0)"

# --- ordering: KCM before the issue ------------------------------------------------------
LIMA_START="$DIR/lima-start.sh"
KCM_LINE="$(grep -n '04-start-kcm.sh' "$LIMA_START" | sed -n 1p | cut -d: -f1)"
ISSUE_LINE="$(grep -n 'rig_kubelet_issue_script' "$LIMA_START" | sed -n 1p | cut -d: -f1)"
assert "lima-start.sh starts KCM before issuing the identity (nothing signs the CSR otherwise and the kubelet never registers)" \
  "$([ -n "$KCM_LINE" ] && [ -n "$ISSUE_LINE" ] && [ "$KCM_LINE" -lt "$ISSUE_LINE" ] && echo 1 || echo 0)"
assert "a standalone lima-start.sh that must issue an identity fails fast naming --with-kcm (otherwise it hangs at the CSR wait)" \
  "$(grep -qF 'no KCM is running. Re-run with --with-kcm' "$LIMA_START" && echo 1 || echo 0)"
assert "lima-start.sh checks for host jq up front (install.sh's CSR flow needs it)" \
  "$(grep -qF 'for cmd in limactl kubectl jq' "$LIMA_START" && echo 1 || echo 0)"
assert "lima-start.sh replays install.sh's label_control_plane_node so the rig node carries the control-plane role label like an install" \
  "$(grep -qF 'install_sh_function label_control_plane_node' "$LIMA_START" && echo 1 || echo 0)"
assert "run-all.sh asks lima-start.sh to start KCM" \
  "$(grep -qF 'lima-start.sh" --with-kcm' "$DIR/run-all.sh" && echo 1 || echo 0)"
assert "run-all.sh no longer starts KCM separately (a second KCM would double-write cluster state)" \
  "$(grep -qE '^bash "\$DIR/04-start-kcm.sh"' "$DIR/run-all.sh" && echo 0 || echo 1)"
assert "add-node.sh never starts KCM (the extra node uses the primary's KCM)" \
  "$(grep -vE '^[[:space:]]*#' "$DIR/add-node.sh" | drain_grep -q 'with-kcm\|04-start-kcm' && echo 0 || echo 1)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
