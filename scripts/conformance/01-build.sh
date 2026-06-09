#!/usr/bin/env bash
# Build u7s-apiserver release binary.
#
# Part of the scripts/conformance/ orchestration sequence.
# Run this before starting the apiserver.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

TARGET_DIR_ARGS=()
if [[ -n "${U7S_TARGET_DIR:-}" ]]; then
  TARGET_DIR_ARGS=(--target-dir "$U7S_TARGET_DIR")
fi

echo "=== [01] Build u7s-apiserver ==="
cargo build --release -p u7s-apiserver --manifest-path "$REPO/Cargo.toml" "${TARGET_DIR_ARGS[@]+"${TARGET_DIR_ARGS[@]}"}"
echo "Build complete: ${U7S_TARGET_DIR:-$REPO/target}/release/u7s-apiserver"
