#!/usr/bin/env bash
# Sourced by scripts/build-release-tarball.sh (amd64) and
# scripts/release-gate/build-arm64-tarball.sh (arm64) so both architectures pin
# and verify kubectl and the CNI plugins identically. Needs curl, tar, cosign,
# and K8S_VERSION set by the caller.

# Kubernetes signs every release binary keylessly (Sigstore); the signer
# identity and OIDC issuer below are the ones documented at
# https://kubernetes.io/docs/tasks/administer-cluster/verify-signed-artifacts/.
# The same-origin .sha256 only catches corruption, not a compromised dl.k8s.io.
K8S_COSIGN_IDENTITY="krel-staging@k8s-releng-prod.iam.gserviceaccount.com"
K8S_COSIGN_ISSUER="https://accounts.google.com"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Fetch <binary>'s .sig and .cert (from <url>.sig / <url>.cert) next to it and
# verify them against the binary; any failure aborts the build.
verify_k8s_signature() {
  local binary="$1" url="$2"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-connrefused -o "$binary.sig" "${url}.sig"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-connrefused -o "$binary.cert" "${url}.cert"
  if ! cosign verify-blob "$binary" \
    --signature "$binary.sig" \
    --certificate "$binary.cert" \
    --certificate-identity "$K8S_COSIGN_IDENTITY" \
    --certificate-oidc-issuer "$K8S_COSIGN_ISSUER"; then
    echo "error: cosign signature verification failed for $(basename "$binary") (expected identity $K8S_COSIGN_IDENTITY, issuer $K8S_COSIGN_ISSUER)" >&2
    exit 1
  fi
}

# fetch_k8s_binary <dest-dir> <arch> <name>: download from dl.k8s.io, check the
# .sha256 sidecar, then cosign-verify.
fetch_k8s_binary() {
  local dest="$1" arch="$2" bin="$3" url expected actual
  url="https://dl.k8s.io/release/v${K8S_VERSION}/bin/linux/${arch}/${bin}"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-connrefused -o "$dest/$bin" "$url"

  # dl.k8s.io publishes a raw-hex sha256 sidecar alongside every binary --
  # verify it rather than trusting -fL's exit code alone (a proxy could serve
  # a truncated-but-200 response, or a corrupted-in-transit file).
  expected="$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-connrefused "${url}.sha256")"
  actual="$(sha256_of "$dest/$bin")"
  if [ "$expected" != "$actual" ]; then
    echo "error: checksum mismatch for $bin: expected $expected, got $actual" >&2
    exit 1
  fi
  verify_k8s_signature "$dest/$bin" "$url"
  chmod +x "$dest/$bin"
}

# containernetworking/plugins publishes no signature or attestation, only
# same-origin .sha256/.sha512 sidecars, which a compromised release would
# regenerate. The tarball digests are therefore pinned here, so a changed
# artifact needs a reviewed commit. Bump all together; both pins are the
# upstream sidecars:
#   curl -fsSL <release-url>/cni-plugins-linux-<arch>-v<ver>.tgz.sha256
CNI_PLUGINS_VERSION="1.9.1"
CNI_PLUGINS_SHA256_AMD64="b98f74a0f8522f0a83867178729c1aa70f2158f90c45a2ca8fa791db1c76b303"
CNI_PLUGINS_SHA256_ARM64="56171987d3947707c3563db2f4001bccaf50fd63468611b9f3cbecb1375ee7ec"
# bridge + host-local + loopback: CRI-O's default conflists and flannel's
# delegate; portmap: flannel's cni-conf chain.
CNI_PLUGINS="bridge host-local loopback portmap"

fetch_cni_plugins() {
  local dest="$1" url="$2" expected="$3" tgz actual
  tgz="$(mktemp)"
  if ! curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-connrefused -o "$tgz" "$url"; then
    rm -f "$tgz"
    echo "error: failed to download $url" >&2
    exit 1
  fi
  actual="$(sha256_of "$tgz")"
  if [ "$expected" != "$actual" ]; then
    rm -f "$tgz"
    echo "error: checksum mismatch for $(basename "$url"): expected $expected, got $actual" >&2
    exit 1
  fi
  mkdir -p "$dest"
  # shellcheck disable=SC2086 # CNI_PLUGINS is a fixed word list
  tar -xzf "$tgz" -C "$dest" $(printf './%s ' $CNI_PLUGINS)
  rm -f "$tgz"
}

# fetch_cni_plugins_for_arch <dest> <amd64|arm64>
fetch_cni_plugins_for_arch() {
  local dest="$1" arch="$2" pin
  case "$arch" in
    amd64) pin="$CNI_PLUGINS_SHA256_AMD64" ;;
    arm64) pin="$CNI_PLUGINS_SHA256_ARM64" ;;
    *) echo "error: no CNI plugins pin for arch $arch" >&2; exit 1 ;;
  esac
  fetch_cni_plugins "$dest" \
    "https://github.com/containernetworking/plugins/releases/download/v${CNI_PLUGINS_VERSION}/cni-plugins-linux-${arch}-v${CNI_PLUGINS_VERSION}.tgz" \
    "$pin"
}
