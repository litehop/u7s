#!/usr/bin/env bash
# 04-start-kcm.sh must hand KCM the trimmed --controllers list only in mode T. If the T branch is
# lost, the trim A/B measures the untrimmed KCM and reports a false "no saving"; if R picks it up,
# the baseline is no longer the shipped controller set.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

BASE='*,bootstrap-signer-controller,token-cleaner-controller,-clusterrole-aggregation-controller,-service-cidr-controller'
# shellcheck source=scripts/conformance/kcm-mode.sh
source "$DIR/kcm-mode.sh"

eval "$(sed -n '/^# BEGIN kcm_controllers_for_mode$/,/^# END kcm_controllers_for_mode$/p' "$DIR/04-start-kcm.sh")"
declare -F kcm_controllers_for_mode >/dev/null || { echo "FAIL: kcm_controllers_for_mode not found in 04-start-kcm.sh"; exit 1; }

KCM_CONTROLLERS="$BASE"; kcm_controllers_for_mode T
if [ "$KCM_CONTROLLERS" = "$BASE,$KCM_TRIM_EXCLUDE" ]; then ok "mode T appends KCM_TRIM_EXCLUDE to --controllers"; else bad "mode T gave '$KCM_CONTROLLERS'"; fi

KCM_CONTROLLERS="$BASE"; kcm_controllers_for_mode R
if [ "$KCM_CONTROLLERS" = "$BASE" ]; then ok "mode R leaves --controllers untrimmed"; else bad "mode R gave '$KCM_CONTROLLERS'"; fi

KCM_CONTROLLERS="$BASE"; kcm_controllers_for_mode ""
if [ "$KCM_CONTROLLERS" = "$BASE" ]; then ok "no mode leaves --controllers untrimmed"; else bad "empty mode gave '$KCM_CONTROLLERS'"; fi

echo ""
echo "kcm-controllers-mode logic: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
