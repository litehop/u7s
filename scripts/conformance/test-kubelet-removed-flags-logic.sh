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

# lima-start.sh writes a single literal kubelet command line targeting the
# current (1.37+) kubelet, so its code is checked as text.
lima_code="$(code_lines "$LIMA_START")"
for name in "${REMOVED_FLAGS[@]}" "${LOCKED_GATES[@]}"; do
  if printf '%s' "$lima_code" | grep -qF -- "$name"; then
    echo "FAIL: lima-start.sh passes '$name', which kubelet 1.37 rejects at startup (crash-loop)"
    FAIL=$(( FAIL + 1 ))
  else
    echo "PASS: lima-start.sh does not pass '$name'"
    PASS=$(( PASS + 1 ))
  fi
done
for gate in "${REQUIRED_OFF_IN_LIMA_START[@]}"; do
  if printf '%s' "$lima_code" | grep -qF -- "${gate}=false"; then
    echo "PASS: lima-start.sh disables '$gate' alongside PodLevelResources=false"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: lima-start.sh disables PodLevelResources but not '$gate'; 1.37 kubelet refuses to start"
    FAIL=$(( FAIL + 1 ))
  fi
done

# install.sh ships a tarball that may still be 1.36, so assert the OUTPUT of its
# flag builder per kubelet minor instead of grepping its source.
fn_src="$(sed -n '/^kubelet_round2_flags() {$/,/^}$/p' "$INSTALL")"
if [ -z "$fn_src" ]; then
  echo "FAIL: kubelet_round2_flags not found in install.sh"
  exit 1
fi
eval "$fn_src"

flags_136="$(kubelet_round2_flags 1.36)"
flags_137="$(kubelet_round2_flags 1.37)"

check_absent() { # label flags name why
  if printf '%s' "$2" | grep -qF -- "$3"; then
    echo "FAIL: install.sh flags for $1 contain '$3'; $4"
    FAIL=$(( FAIL + 1 ))
  else
    echo "PASS: install.sh flags for $1 omit '$3'"
    PASS=$(( PASS + 1 ))
  fi
}

for name in "${REMOVED_FLAGS[@]}" "${LOCKED_GATES[@]}"; do
  check_absent "1.36" "$flags_136" "$name" "removed/locked in 1.37 and dropped for every version (crash-loop on 1.37)"
  check_absent "1.37" "$flags_137" "$name" "kubelet 1.37 rejects it at startup (crash-loop)"
done

for gate in "${REQUIRED_OFF_IN_LIMA_START[@]}"; do
  check_absent "1.36" "$flags_136" "${gate}=false" "a 1.36 kubelet rejects 1.37-only gates as unrecognized"
  if printf '%s' "$flags_137" | grep -qF -- "${gate}=false"; then
    echo "PASS: install.sh flags for 1.37 disable '$gate'"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: install.sh flags for 1.37 do not disable '$gate'; PodLevelResources=false makes kubelet refuse to start"
    FAIL=$(( FAIL + 1 ))
  fi
done

if printf '%s' "$flags_136" | grep -qF -- 'PodLevelResources=false'; then
  echo "PASS: install.sh keeps PodLevelResources=false on 1.36"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: install.sh dropped PodLevelResources=false on 1.36"
  FAIL=$(( FAIL + 1 ))
fi

# Anything 1.37 adds beyond 1.36 must be exactly the pinned 1.37-only gates, so
# a new unguarded (or newly guarded) gate shows up as a diff here.
only_137="$(printf '%s' "${flags_137#"$flags_136"}")"
expected_137=""
for gate in "${REQUIRED_OFF_IN_LIMA_START[@]}"; do expected_137="$expected_137,${gate}=false"; done
if [ "$only_137" = "$expected_137" ]; then
  echo "PASS: 1.37 flags differ from 1.36 only by the pinned 1.37-only gates"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: 1.37-only flag delta is '$only_137', expected '$expected_137'; update the pinned lists if intentional"
  FAIL=$(( FAIL + 1 ))
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
