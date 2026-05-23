#!/usr/bin/env bash
# Start u7s-scheduler on the host (backgrounded).
#
# u7s-scheduler is a Rust binary — it runs on the host, not inside the Lima VM.
# Delegates to scripts/scheduler-start.sh, mirroring how 02-start-apiserver.sh
# delegates to scripts/u7s-start.sh.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

echo "=== [05] Start u7s-scheduler (on host) ==="

exec "$REPO/scripts/scheduler-start.sh"
