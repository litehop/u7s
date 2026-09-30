#!/usr/bin/env bash
# Regression test: the kubelet command lines in scripts/conformance/lima-start.sh
# and scripts/install.sh must not pass a flag that kubelet 1.37 removed or a
# feature gate that 1.37 locked to its default.
#
# Both fail kubelet at startup (unknown flag / "feature is locked to true"), and
# systemd's Restart=always turns that into a crash-loop: the node never
# registers and every `run-all.sh --reset` dies at bring-up. Nothing but a live
# VM run would notice, so pin the list here. When the pinned kubelet moves on,
# append newly removed/locked names to the arrays.
#
# Also pins the reverse hazard: PodLevelResources is disabled, and 1.37 added
# two default-on gates that hard-depend on it, which must be disabled with it.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_START="$DIR/lima-start.sh"
INSTALL="$DIR/../install.sh"

REMOVED_FLAGS=(
  --application-metrics-count-limit
)
LOCKED_GATES=(
  InPlacePodVerticalScalingInitContainers
)
# Gates that depend on a gate we disable and so must be disabled with it.
REQUIRED_OFF_IN_LIMA_START=(
  PodLevelResourcesFixDefaulting
  PodLevelResourcesFixKubeletQOSClass
)

PASS=0
FAIL=0

# Comments explain why a name was dropped, so only code lines count.
code_lines() { grep -vE '^[[:space:]]*#' "$1"; }

for f in "$LIMA_START" "$INSTALL"; do
  code="$(code_lines "$f")"
  for name in "${REMOVED_FLAGS[@]}" "${LOCKED_GATES[@]}"; do
    if printf '%s' "$code" | grep -qF -- "$name"; then
      echo "FAIL: $(basename "$f") passes '$name', which kubelet 1.37 rejects at startup (crash-loop)"
      FAIL=$(( FAIL + 1 ))
    else
      echo "PASS: $(basename "$f") does not pass '$name'"
      PASS=$(( PASS + 1 ))
    fi
  done
done

lima_code="$(code_lines "$LIMA_START")"
install_code="$(code_lines "$INSTALL")"
for gate in "${REQUIRED_OFF_IN_LIMA_START[@]}"; do
  if printf '%s' "$lima_code" | grep -qF -- "${gate}=false"; then
    echo "PASS: lima-start.sh disables '$gate' alongside PodLevelResources=false"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: lima-start.sh disables PodLevelResources but not '$gate'; 1.37 kubelet refuses to start"
    FAIL=$(( FAIL + 1 ))
  fi
  # install.sh ships a tarball that may still be <1.37, where these gates are
  # unrecognized, so they must be present but version-guarded.
  if printf '%s' "$install_code" | grep -F -- "${gate}=false" | grep -q .; then
    echo "PASS: install.sh disables '$gate' on 1.37+"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: install.sh never disables '$gate'; a 1.37+ tarball would fail to start kubelet"
    FAIL=$(( FAIL + 1 ))
  fi
done

if printf '%s' "$install_code" | grep -qF 'KUBE_MINOR#*.}" -ge 37'; then
  echo "PASS: install.sh guards the 1.37-only gates on the staged kubelet minor"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: install.sh must guard the 1.37-only gates; a 1.36 kubelet rejects them as unrecognized"
  FAIL=$(( FAIL + 1 ))
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
