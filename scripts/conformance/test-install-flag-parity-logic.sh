#!/usr/bin/env bash
# The host rig must start the apiserver and KCM with the flags install.sh's units carry, and
# run the scheduler embedded as install.sh does. Without them a conformance PASS describes a
# configuration no user runs: Services with externalIPs are admitted, the cluster config
# ConfigMap is empty, and scheduling runs in a separate process.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 — expected '$3' in: $2" ;; esac; }
assert_lacks() { case "$2" in *"$3"*) bad "$1 — unexpected '$3' in: $2" ;; *) ok "$1" ;; esac; }

# shellcheck source=scripts/conformance/_lib.sh
source "$REPO/scripts/conformance/_lib.sh"

# u7s-start.sh: evaluate its install-parity block for both stack types.
block=$(sed -n '/^_POD_CIDR=/,/^INSTALL_PARITY_ARGS=/p' "$REPO/scripts/u7s-start.sh")
[ -n "$block" ] || { echo "FAIL: install-parity block not found in u7s-start.sh"; exit 1; }
parity_args() {
  # shellcheck disable=SC2034 # read by the evaluated block
  ( SERVICE_CIDR="$1" DUAL_STACK="$2" U7S_VM_NAME="${3:-}"; eval "$block"; echo "$INSTALL_PARITY_ARGS" )
}
single=$(parity_args 10.96.0.0/12 0 lima-node-2)
assert_has "apiserver denies Service externalIPs as install does" "$single" "--deny-service-external-ips"
assert_has "apiserver exempts the VM's own node from the CSR SAN rule" "$single" "--local-node-name lima-node-2"
assert_has "apiserver publishes the pod CIDR for joining nodes" "$single" "--cluster-cidr 10.244.0.0/16 "
assert_has "apiserver pins kube-dns to the range's tenth host" "$single" "--kube-dns-cluster-ip 10.96.0.10"
dual=$(parity_args 10.96.0.0/12,fd00:96::/108 1)
assert_has "dual-stack publishes both pod CIDRs" "$dual" "--cluster-cidr 10.244.0.0/16,fd00:244::/56"
assert_has "dual-stack publishes the IPv4 kube-dns VIP first, as install does" "$dual" "--kube-dns-cluster-ip 10.96.0.10"
assert_has "node name defaults to lima-node" "$dual" "--local-node-name lima-node "
custom=$(parity_args 10.200.0.0/16 0)
assert_has "a custom Service CIDR moves the kube-dns VIP with it" "$custom" "--kube-dns-cluster-ip 10.200.0.10"

launches=$(grep -c '^ *\$INSTALL_PARITY_ARGS \\$' "$REPO/scripts/u7s-start.sh")
[ "$launches" -eq 3 ] && ok "all three apiserver launches (foreground, background, post-CA relaunch) pass the flags" \
  || bad "expected 3 apiserver launches passing \$INSTALL_PARITY_ARGS, found $launches; a launch without them runs an undelivered configuration"

grep -q -- '--dual-stack' "$REPO/scripts/conformance/02-start-apiserver.sh" \
  && grep -q '02-start-apiserver.sh.*_DUAL_STACK_ARG' "$REPO/scripts/conformance/run-all.sh" \
  && ok "run-all.sh forwards --dual-stack to the apiserver start" \
  || bad "--dual-stack never reaches u7s-start.sh, so a dual-stack rig publishes a single-stack cluster config"

# run-all.sh: embedded scheduler is the default; an explicit value still wins.
grep -q '^EMBEDDED_SCHEDULER="\${EMBEDDED_SCHEDULER:-true}"$' "$REPO/scripts/conformance/run-all.sh" \
  && ok "run-all.sh defaults to the embedded scheduler" \
  || bad "run-all.sh no longer defaults EMBEDDED_SCHEDULER to true; the rig would schedule in a process install.sh never runs"

# 04-start-kcm.sh: render the script it ships to the VM against a stubbed limactl.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/bin"
cat > "$TMP/bin/limactl" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = shell ] && [[ " $* " == *" bash -s "* ]]; then cat > "$KCM_RENDERED"; fi
exit 0
EOF
chmod +x "$TMP/bin/limactl"
render_kcm() {
  : > "$TMP/kcm.sh"
  KCM_RENDERED="$TMP/kcm.sh" PATH="$TMP/bin:$PATH" bash "$REPO/scripts/conformance/04-start-kcm.sh" --workdir "$TMP/wd" "$@" >/dev/null 2>&1 || true
  cat "$TMP/kcm.sh"
}
kcm=$(render_kcm)
[ -n "$kcm" ] || { echo "FAIL: 04-start-kcm.sh rendered no VM script"; exit 1; }
assert_has "KCM gets the Service CIDR install.sh passes" "$kcm" "--service-cluster-ip-range=10.96.0.0/12"
assert_lacks "KCM drops the rig-only GC concurrency override" "$kcm" "--concurrent-gc-syncs"
kcm_dual=$(render_kcm --dual-stack)
assert_has "dual-stack KCM gets both Service CIDRs" "$kcm_dual" "--service-cluster-ip-range=10.96.0.0/12,fd00:96::/108"

echo ""
echo "install-flag-parity logic: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
