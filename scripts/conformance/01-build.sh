#!/usr/bin/env bash
# Build u7s-apiserver release binary.
#
# Part of the scripts/conformance/ orchestration sequence.
# Run this before starting the apiserver.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

echo "=== [01] Build u7s-apiserver ==="
cargo build --release -p u7s-apiserver --manifest-path "$REPO/Cargo.toml"
echo "Build complete: $REPO/target/release/u7s-apiserver"
