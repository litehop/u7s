#!/usr/bin/env bash
# Logic tests for 2-node conformance on the install path (run-all.sh --install --extra-node).
#
# Why it matters: the ship gate must run on the cluster a user gets. If --extra-node is dropped
# between run-all.sh, install-run.sh and install-bringup.sh, a "2-node" install run silently
# measures one node and its archive claims otherwise; a worker joined by a second mechanism
# would not exercise install.sh's join flow at all.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_BASH="$(command -v bash)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

PASS=0
FAIL=0
check() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $label"; PASS=$((PASS + 1))
  else
    echo "FAIL: $label -- expected '$expected', got '$actual'"; FAIL=$((FAIL + 1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# install.sh --mint-join-token output, as install.sh prints it.
MINT='Join token created in kube-system, expires 2026-11-27T10:00:00Z (single-use): abc123.0123456789abcdef
On the joining node, run as root. The command carries no token, so it stays out of shell
history; install.sh prompts for the token with echo off (or reads it from piped stdin):
  install.sh --join https://192.168.104.5:6443 \
    --ca-cert-hash sha256:0000000000000000000000000000000000000000000000000000000000000abc --tarball <path> --node-name <name> [--iface <iface>]'
check "join URL, token and CA hash are parsed from --mint-join-token output (install.sh --join refuses without all three)" \
  "https://192.168.104.5:6443|abc123.0123456789abcdef|sha256:0000000000000000000000000000000000000000000000000000000000000abc" \
  "$(join_fields_from_mint_output <<<"$MINT" | paste -sd'|' -)"
check "output without a token fails loudly rather than joining with empty fields" \
  "1" "$(join_fields_from_mint_output <<<'error: nothing' >/dev/null 2>&1 && echo 0 || echo 1)"

write_run_meta "$TMP/meta" install
run_meta_record_nodes "$TMP/meta" 2
check "install run-meta records topology and the node count (a 2-node archive must not read as single-node)" \
  "topology=install|nodes=2" "$(grep -e '^topology=' -e '^nodes=' "$TMP/meta/run-meta" | paste -sd'|' -)"
check "install-run.sh stamps the node count from the live cluster, not from the flag it was given" \
  "1" "$(grep -c 'run_meta_record_nodes "\$RUN_DIR" "\$(kubectl --kubeconfig "\$KUBECONFIG" get nodes' "$DIR/install-run.sh" || true)"

# A stub bash that logs argv and succeeds, so the orchestrators run end to end without a VM.
mkdir "$TMP/bin"
cat > "$TMP/bin/bash" <<EOF
#!$REAL_BASH
printf '%s\n' "\$*" >> "$TMP/calls.log"
EOF
chmod +x "$TMP/bin/bash"

: > "$TMP/calls.log"
PATH="$TMP/bin:$PATH" "$REAL_BASH" "$DIR/run-all.sh" --install --reset --stack-only --vm vm-a --port 6444 \
  --kubelet-port 10001 --extra-node vm-b --extra-kubelet-port 10002 --workdir "$TMP/wd" >"$TMP/out.log" 2>&1 && rc=0 || rc=$?
check "run-all.sh --install accepts --extra-node/--extra-kubelet-port (rc)" "0" "$rc"
check "run-all.sh hands both flags to install-run.sh" \
  "1" "$(grep -c 'install-run.sh .*--extra-node vm-b --extra-kubelet-port 10002' "$TMP/calls.log" || true)"

: > "$TMP/calls.log"
mkdir -p "$TMP/wd2"
PATH="$TMP/bin:$PATH" "$REAL_BASH" "$DIR/install-run.sh" --reset --stack-only --vm vm-a --port 6444 \
  --kubelet-port 10001 --extra-node vm-b --extra-kubelet-port 10002 --workdir "$TMP/wd2" >"$TMP/out2.log" 2>&1 && rc=0 || rc=$?
check "install-run.sh accepts the extra-node flags (rc)" "0" "$rc"
check "--reset also deletes the extra VM (else a stale worker identity blocks the next join)" \
  "1" "$(grep -c 'reset.sh --vm vm-a .*--extra-node vm-b' "$TMP/calls.log" || true)"
check "install-bringup.sh receives both extra-node flags" \
  "1" "$(grep -c 'install-bringup.sh .*--extra-node vm-b --extra-kubelet-port 10002' "$TMP/calls.log" || true)"

: > "$TMP/calls.log"
PATH="$TMP/bin:$PATH" "$REAL_BASH" "$DIR/install-run.sh" --stack-only --vm vm-a --workdir "$TMP/wd2" >/dev/null 2>&1 || true
check "a single-node run passes no extra-node flag (default behaviour unchanged)" \
  "0" "$(grep -c -e '--extra-node' "$TMP/calls.log" || true)"

check "install-bringup.sh mints the token with install.sh itself, not a second mechanism" \
  "1" "$(grep -c 'install.sh" --mint-join-token' "$DIR/install-bringup.sh" || true)"
check "install-bringup.sh joins the worker with install.sh --join, token on stdin" \
  "1" "$(grep -c -e '--join "\$join_url" --token -' "$DIR/install-bringup.sh" || true)"
check "a re-run clears the joined worker before --join (install.sh --join is one-shot and refuses a joined node)" \
  "1" "$(grep -c 'rm -rf \$VM_STATE_DIR"' "$DIR/install-bringup.sh" || true)"
check "run-all.sh no longer lists --extra-node as host-rig-only for --install" \
  "0" "$(grep -c '"--extra-node=\$EXTRA_NODE"' "$DIR/run-all.sh" || true)"

echo ""
echo "install two-node logic: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
