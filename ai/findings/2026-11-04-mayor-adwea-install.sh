#!/usr/bin/env bash
# usage: install.sh TAG   (root on the VM) -- fetch release assets, verify sha256, install --tarball
set -uo pipefail
TAG="$1"; D=/var/tmp/adwea/$TAG; mkdir -p "$D"; cd "$D" || exit 1
B=https://github.com/litehop/u7s/releases/download/$TAG
T=u7s-$TAG-x86_64-unknown-linux-gnu.tar.gz
for f in install.sh "$T" "$T.sha256"; do curl -fsSL -o "$f" "$B/$f" || { echo "FETCH FAIL $f"; exit 1; }; done
[ "$(sha256sum "$T" | cut -d' ' -f1)" = "$(cut -d' ' -f1 "$T.sha256" | tr -d '[:space:]')" ] || { echo "SHA FAIL"; exit 1; }
echo "sha256 OK"
sha256sum "$T" install.sh
date -u +%FT%TZ > install.start
bash install.sh --tarball "$D/$T" > install.log 2>&1
echo "rc=$?" >> install.log
date -u +%FT%TZ > install.end
tail -5 install.log
