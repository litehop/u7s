#!/usr/bin/env bash
# Regression test for the kubelet/cri-o version pins in lima/kubelet.yaml.
#
# The provision script re-runs on every boot, including every golden clone.
# kubelet is apt-mark held, so an unpinned `apt-get install -y kubelet` aborts
# the whole script (set -e, "Held packages were changed") as soon as
# pkgs.k8s.io publishes a newer patch -- skipping `mkdir -p /tmp/kubelet-pods`
# and failing every run-all.sh --reset at lima-start.sh's kube-proxy-pull.yaml
# write. An unpinned cri-o doesn't abort, but silently upgrades the runtime on
# clones so they no longer match the golden they were cloned from.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_YAML="$DIR/../../lima/kubelet.yaml"

PASS=0
FAIL=0

# Every `apt-get install` line naming <pkg> must name it as <pkg>=<version>.
assert_pinned() {
  local label="$1" pkg="$2" lines
  lines="$(grep -E 'apt-get install' "$LIMA_YAML" | grep -E "(^|[ \"])${pkg}([ \"=]|$)" || true)"
  if [ -z "$lines" ]; then
    echo "FAIL: $label — no apt-get install line for '${pkg}' found in $LIMA_YAML"
    FAIL=$(( FAIL + 1 ))
  elif printf '%s\n' "$lines" | grep -vqE "(^|[ \"])${pkg}="; then
    echo "FAIL: $label — unpinned install: $(printf '%s\n' "$lines" | grep -vE "(^|[ \"])${pkg}=")"
    FAIL=$(( FAIL + 1 ))
  else
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  fi
}

assert_pinned "kubelet install is version-pinned (unpinned install vs apt-mark hold aborts provisioning on every clone boot once upstream ships a newer patch)" \
  kubelet
assert_pinned "cri-o install is version-pinned (unpinned install silently upgrades the runtime on clones away from the golden's version)" \
  cri-o

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
