#!/usr/bin/env bash
# Unit tests for scripts/install.sh's systemd-unit-authoring logic.
#
# Structural (grep-against-literal-source) tests, following the pattern in
# scripts/conformance/test-network-flag-logic.sh: install.sh runs apt-get,
# writes to /etc/systemd/system, and needs root, so it cannot be executed
# directly by a unit test -- these assertions instead pin down the exact
# source text that a future edit must not silently regress.
#
# Primary regression this file exists for: u7s-kcm.service's ExecStart line
# originally wrapped kube-controller-manager in `bash -c '...'` so a single
# ExecStart could both convert the CA (openssl) and exec the real binary.
# That string contained an UNQUOTED `--controllers=*,-cloud-node-lifecycle-
# controller,...` -- when systemd hands a bash -c string to a real shell,
# that shell glob-expands the bare `*` against WorkingDirectory's contents
# (/var/lib/u7s, which is non-empty by the time KCM actually starts: ca.crt,
# kubeconfig, etc. all exist post-apiserver-bootstrap), silently corrupting
# the --controllers flag into a list of filenames instead of the intended
# "every built-in controller except these five" set. The fix splits this
# into ExecStartPre (cert conversion) + a plain ExecStart (no shell, so
# systemd's own line-splitting never globs).
#
# Also covers two smaller review findings: kubelet.service must depend on
# u7s-apiserver.service exactly like scheduler/kcm (all three read files
# that only exist after apiserver's first run), and binary staging must
# reject a non-executable match instead of silently installing it.
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016 # file-wide: single-quoted grep patterns below
# intentionally match install.sh's literal, unexpanded source text.
set -euo pipefail
# A command dying under set -e must say so: a silent exit before the Results
# line reads as "no output" in CI instead of a failure.
trap 'echo "FAIL: test script aborted at line $LINENO before reaching Results" >&2' ERR

DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL="$DIR/install.sh"
ROOT_DIR="$(cd "$DIR/.." && pwd)"
FLANNEL_MANIFEST="$ROOT_DIR/manifests/flannel.yaml"
KUBE_PROXY_MANIFEST="$ROOT_DIR/manifests/kube-proxy.yaml"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}
assert_true() {
  local label="$1"
  shift
  if "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}
assert_false() {
  local label="$1"
  shift
  if ! "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# Regression guard: the bash -c glob-injection bug. This is the load-bearing
# assertion -- it fails if someone reverts the ExecStartPre+plain-ExecStart
# fix back to wrapping kube-controller-manager's launch in a shell.
# ---------------------------------------------------------------------------
assert_false "(regression guard) install.sh no longer wraps any ExecStart in 'bash -c' (the wrapper that let the unquoted --controllers=* glob-expand against WorkingDirectory's contents at runtime)" \
  grep -qF 'ExecStart=/bin/bash -c' "$INSTALL"

assert_true "u7s-kcm.service converts the CA from DER to PEM via ExecStartPre, separately from the real launch" \
  grep -qF 'ExecStartPre=/usr/bin/openssl x509 -inform DER -in $STATE_DIR/ca.crt -out $STATE_DIR/ca.pem' "$INSTALL"

assert_true "u7s-kcm.service's ExecStart invokes kube-controller-manager directly as argv, not through a shell" \
  grep -qF 'ExecStart=$BIN_DIR/kube-controller-manager --kubeconfig=$STATE_DIR/kcm-kubeconfig' "$INSTALL"

# ---------------------------------------------------------------------------
# File-path kubeconfigs: KCM and the kubelet only live-reload a re-issued client
# cert / CA when the kubeconfig names files, so a worker's kubeconfig must never
# embed -data, and KCM's one-shot inputs must have a restart hook.
# ---------------------------------------------------------------------------
kcm_exec_line="$(grep -F 'ExecStart=$BIN_DIR/kube-controller-manager' "$INSTALL")"
assert_false "u7s-kcm.service passes no --service-account-private-key-file: legacy service-account token Secrets are unsupported, so KCM's token controller must stay off" \
  grep -qF -- '--service-account-private-key-file' <<<"$kcm_exec_line"

assert_true "u7s-kcm.service runs each controller as its own system:controller:* service account, so a stolen KCM credential is not one shared identity (CIS 5.1.3)" \
  grep -qF -- '--use-service-account-credentials=true' <<<"$kcm_exec_line"

assert_true "u7s-kcm.service reads --root-ca-file from the apiserver-published ca-bundle.pem, the file the restart hook watches" \
  grep -qF -- '--root-ca-file=$STATE_DIR/ca-bundle.pem' <<<"$kcm_exec_line"

assert_true "u7s-kcm.service delegates authentication to the apiserver via the file-path kcm-kubeconfig -- without it :10257/metrics is 403 for every caller incl. cluster-admin" \
  grep -qF -- '--authentication-kubeconfig=$STATE_DIR/kcm-kubeconfig' <<<"$kcm_exec_line"
assert_true "u7s-kcm.service delegates authorization to the apiserver (SubjectAccessReview), so /metrics honours system:monitoring RBAC" \
  grep -qF -- '--authorization-kubeconfig=$STATE_DIR/kcm-kubeconfig' <<<"$kcm_exec_line"
kcm_unit="$(awk '/^cat > \/etc\/systemd\/system\/u7s-kcm.service/,/^EOF$/' "$INSTALL")"
assert_true "u7s-kcm.service sets StartLimitIntervalSec=0 -- KCM exits until the apiserver publishes extension-apiserver-authentication, and systemd's default 5 starts/10s would leave it failed for good" \
  grep -qx 'StartLimitIntervalSec=0' <<<"$kcm_unit"
assert_true "install waits for kube-system/extension-apiserver-authentication before restarting u7s-kcm.service, so KCM does not start into its fatal lookup failure" \
  grep -qF 'wait_for_authentication_configmap "$STATE_DIR/kubeconfig"' "$INSTALL"
cm_wait_line="$(grep -n '^wait_for_authentication_configmap "' "$INSTALL" | cut -d: -f1)"
cm_kcm_line="$(grep -n '^systemctl restart u7s-kcm.service' "$INSTALL" | cut -d: -f1)"
assert "the ConfigMap wait precedes the KCM restart (otherwise it guards nothing)" \
  "$([ -n "$cm_wait_line" ] && [ -n "$cm_kcm_line" ] && [ "$cm_wait_line" -lt "$cm_kcm_line" ] && echo 1 || echo 0)"
assert_false "u7s-kcm.service does not set --authentication-tolerate-lookup-failure: a KCM that silently skips delegated authn would serve /metrics unauthenticated-looking" \
  grep -qF -- '--authentication-tolerate-lookup-failure' <<<"$kcm_exec_line"
assert_false "u7s-kcm.service opens no extra anonymous paths: /metrics must stay RBAC-gated" \
  grep -qF -- '--authorization-always-allow-paths' <<<"$kcm_exec_line"

assert_true "KCM restarts when ca-bundle.pem changes (--root-ca-file is read once, so root succession would otherwise leave KCM publishing a stale kube-root-ca.crt)" \
  grep -qF 'PathChanged=$STATE_DIR/ca-bundle.pem' "$INSTALL"
assert_true "the CA-bundle path unit triggers a restart of u7s-kcm.service" \
  grep -qF 'ExecStart=/bin/systemctl restart u7s-kcm.service' "$INSTALL"

join_kc_body="$(sed -n '/^  cat > "\$STATE_DIR\/kubeconfig" <<EOF$/,/^EOF$/p' "$INSTALL" | sed '1d;$d')"
join_kc="$(STATE_DIR=/var/lib/u7s JOIN_SERVER=https://cp.example:6443 NODE_NAME=w1 bash -c "cat <<EOF
$join_kc_body
EOF")"
assert "a joined worker's kubeconfig carries no embedded -data: the kubelet could not see a re-issued client cert or CA" \
  "$(printf '%s' "$join_kc" | grep -q -- '-data:' && echo 0 || echo 1)"
assert "a joined worker's kubeconfig names the CA, client cert and key files the join wrote" \
  "$(printf '%s' "$join_kc" | grep -qF 'certificate-authority: /var/lib/u7s/ca.pem' && printf '%s' "$join_kc" | grep -qF 'client-certificate: /var/lib/u7s/kubelet-client.crt' && printf '%s' "$join_kc" | grep -qF 'client-key: /var/lib/u7s/kubelet-client.key' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Without ExecReload=, systemd has no reload mechanism for a plain unit and
# 'systemctl reload u7s-apiserver' fails outright instead of delivering SIGHUP to the running
# apiserver, which is what re-applies /etc/u7s/manifests without a restart.
# ---------------------------------------------------------------------------
assert_true "u7s-apiserver.service declares ExecReload=/bin/kill -HUP \$MAINPID so 'systemctl reload u7s-apiserver' actually delivers SIGHUP instead of failing outright" \
  grep -qF 'ExecReload=/bin/kill -HUP \$MAINPID' "$INSTALL"

apiserver_exec_tmpl="$(grep -E '^ExecStart=.*u7s-apiserver ' "$INSTALL")"
render_apiserver_exec() {
  ALLOW_SERVICE_EXTERNAL_IPS="$1" BIN_DIR=/usr/local/bin IFACE_IP=10.0.0.1 bash -c "cat <<EOF
$apiserver_exec_tmpl
EOF"
}
assert_true "u7s-apiserver.service's ExecStart passes --deny-service-external-ips by default, so installed nodes reject new/changed Service externalIPs (CVE-2020-8554 traffic hijack)" \
  grep -qF -- ' --deny-service-external-ips' <<<"$(render_apiserver_exec 0)"
assert_false "--allow-service-external-ips omits --deny-service-external-ips: install.sh rewrites the unit on every run, so this is the only durable opt-out" \
  grep -qF -- '--deny-service-external-ips' <<<"$(render_apiserver_exec 1)"
assert_true "install.sh parses --allow-service-external-ips (an unknown flag would abort the install)" \
  grep -qF -- '--allow-service-external-ips) ALLOW_SERVICE_EXTERNAL_IPS=1' "$INSTALL"

# ---------------------------------------------------------------------------
# Consistency: every unit that reads a file u7s-apiserver's first run
# generates (kubeconfig, ca.crt, sa.key, ...) must wait on it the same way.
# Previously kubelet.service was missing this despite the script's own
# comment claiming the race applies uniformly to all three dependents.
# ---------------------------------------------------------------------------
requires_apiserver_count="$(grep -cE '^Requires=.*u7s-apiserver\.service' "$INSTALL")"
assert "both apiserver-dependent units (u7s-kcm, kubelet) declare Requires=u7s-apiserver.service, matching the script's own stated bootstrap-race reasoning -- u7s-scheduler is no longer a separate unit at all" \
  "$([ "$requires_apiserver_count" = "2" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Binary staging must fail loud on a non-executable match instead of
# silently installing it (e.g. a stray non-binary file that happens to share
# a required binary's name inside the tarball).
# ---------------------------------------------------------------------------
assert_true "tarball binary staging rejects a found-but-non-executable match instead of installing it" \
  grep -qF 'if [ ! -x "$found" ]; then' "$INSTALL"

# ---------------------------------------------------------------------------
# iface_filter() -- drives its regex from install.sh's OWN source at test
# time, not a hand-duplicated second copy. An earlier version of this test
# hardcoded the regex literal here; critical review proved that copy was
# decoupled from install.sh's real behavior -- reverting install.sh to the
# exact blacklist this whitelist replaced (docker0/veth*/cni*/br-*/virbr*/
# flannel*/cali*, via grep -Ev) only tripped 1 of 9 assertions (a brittle
# literal-string check), while the "matches physical / excludes virtual"
# assertions below stayed green because they were exercising THIS FILE's
# own untouched copy of the regex, not install.sh's. Extracting the pattern
# here closes that gap: these assertions now fail if install.sh's real
# regex regresses, not just if someone edits this file's copy out of sync.
#
# Physical-NIC names cover both systemd predictable naming (en*/wl*/ww*:
# eno1, ens33, enp0s3, enp2s0f1, enx<mac>, wlo1, wlp2s0, wlx<mac>, wwan0,
# wwp0s20u4i6) and the legacy eth0 kernel fallback -- checking our own 5-VM
# Ubuntu 26.04 Lima fleet (identical template) found it split 2/5 enp0s1 vs
# 3/5 eth0, so eth0 is a real, live case, not just a theoretical old-kernel
# one.
# ---------------------------------------------------------------------------
# `|| true`: grep legitimately exits non-zero if install.sh no longer has a
# line shaped like this at all (e.g. reverted to grep -Ev/-v, neither of
# which contain the literal substring "grep -E '") -- this must produce a
# clear FAIL below, not a silent script-wide abort under set -e/pipefail.
iface_regex_line="$(grep -m1 "grep -E '" "$INSTALL")" || true
IFACE_REGEX="${iface_regex_line#*grep -E \'}"
IFACE_REGEX="${IFACE_REGEX%%\'*}"
assert "install.sh's --iface whitelist regex was successfully extracted from its real source line (if this fails, the tests below are testing nothing -- a change to how/where the regex is written broke extraction)" \
  "$([ -n "$IFACE_REGEX" ] && echo 1 || echo 0)"

iface_filter() {
  grep -E "$IFACE_REGEX"
}

PHYSICAL_NAMES="eno1
ens33
enp0s3
enp2s0f1
enx78e7d1ea46da
wlo1
wlp2s0
wlx0013eff01234
wwan0
wwp0s20u4i6
eth0
eth1
enp0s1"

VIRTUAL_NAMES="lo
docker0
veth9cbe0b5c
cni0
br-abcdef123456
virbr0
flannel.1
cali1234abcd
kube-ipvs0
tun0
tailscale0"

# `|| true` on each: iface_filter (grep) legitimately exits non-zero when it
# finds zero matches (the whole point of the "leaked" case below), and that
# would otherwise trip this script's own `set -e`/pipefail before the
# assertion even runs.
matched="$(printf '%s\n' "$PHYSICAL_NAMES" | iface_filter | wc -l | tr -d ' ')" || true
expected="$(printf '%s\n' "$PHYSICAL_NAMES" | wc -l | tr -d ' ')"
assert "default --iface whitelist matches every real physical-NIC naming variant (systemd predictable en*/wl*/ww* plus the eth0 legacy fallback observed live on our own Lima fleet)" \
  "$([ "$matched" = "$expected" ] && echo 1 || echo 0)"

leaked="$(printf '%s\n' "$VIRTUAL_NAMES" | iface_filter | wc -l | tr -d ' ')" || true
assert "default --iface whitelist excludes every virtual/container-runtime/VPN interface (docker0, veth*, cni*, br-*, virbr*, flannel*, cali*, tun*, tailscale*) -- picking one of these as the cluster-traffic interface would be wrong" \
  "$([ "$leaked" = "0" ] && echo 1 || echo 0)"

assert_false "(regression guard) install.sh's default --iface detection uses no negated blacklist (grep -Ev / grep -v) to exclude virtual interfaces -- BOTH prior designs (the naive 'exclude only lo' and the docker0/veth*/cni*/... list) were negated blacklists; a positive whitelist (plain grep -E, asserted above) is what actually closes the class of bug critical review found, so reintroducing either shape must fail this suite" \
  grep -qE 'grep -Ev|grep -v' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: the CRI-O/CNI-plugins gap found running install.sh end to
# end for the first time against a genuinely fresh box. CRI-O's apt package
# only Recommends (does not Depend on) a CNI-plugins package, and Ubuntu
# cloud-image apt defaults disable installing recommends -- so without an
# explicit install, CRI-O validates its bridge CNI config against a plugin
# directory (/opt/cni/bin/) containing zero actual plugin binaries, and every
# node sits NotReady forever ("failed to find plugin \"bridge\""). This never
# showed up in review because it only reproduces on a box that never had
# recommends installed by anything else first -- a full VM run is what caught
# it, and this assertion is what stops a silent revert from reintroducing it
# without another full VM run to catch it again.
# ---------------------------------------------------------------------------
assert_true "install.sh installs kubernetes-cni (the actual /opt/cni/bin/ plugin binaries CRI-O's bridge config references) alongside kubectl, not just kubectl alone" \
  grep -qF 'apt-get install -y kubectl kubernetes-cni' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: apiserver-to-kubelet proxy (kubectl logs/exec) BadGateway
# on a host-level single-box install. Root cause had two independent halves,
# each with its own live-VM-confirmed failure mode -- both assertions below
# must hold or the specific symptom that was fixed comes back:
#   1. kubelet's default self-signed serving cert on :10250 is untrusted by
#      the apiserver's kubelet-client (pinned to the cluster CA), surfacing
#      as a TLS "unknown CA" alert wrapped in reqwest's opaque "error sending
#      request" -- confirmed via `curl -v https://<node-ip>:10250/`.
#   2. even with a trusted serving cert, kubelet has no clientCAFile to
#      authenticate the apiserver's own client cert against, so it treats
#      the (now-TLS-trusted) request as anonymous and 401s it -- confirmed
#      via a direct unauthenticated curl to kubelet's /containerLogs.
# ---------------------------------------------------------------------------
assert_false "install.sh mints no self-signed-by-script kubelet serving cert: a 10-year file nothing renews outlives the 1-year cluster certs and breaks kubectl logs/exec on expiry" \
  grep -qE 'days 3650|kubelet-serving\.(crt|key)' <(grep -v '^ *#' "$INSTALL" | grep -v 'rm -f')

assert_true "the KCM unit sets --cluster-signing-duration explicitly so kubelet serving and client cert lifetimes are a decision, not upstream's default" \
  grep -qF -- '--cluster-signing-duration=8760h' "$INSTALL"

assert_true "the KCM unit signs with the intermediate (single-certificate PEM + its key), not the root: the root key signs only intermediates and KCM refuses a signing cert file holding more than one certificate" \
  grep -qF -- '--cluster-signing-cert-file=$STATE_DIR/intermediate-cert.pem --cluster-signing-key-file=$STATE_DIR/intermediate.key' "$INSTALL"
assert_false "no KCM flag points the signing key at the root ca.key" \
  grep -qE -- '--cluster-signing-key-file=\$STATE_DIR/ca\.key' "$INSTALL"
assert_true "install.sh waits for the intermediate files the KCM unit reads before starting it" \
  grep -qE 'for f in ca\.crt ca\.key intermediate-cert\.pem intermediate\.key ' "$INSTALL"

assert_true "kubelet-config.yaml sets authentication.x509.clientCAFile to the CA bundle (apiserver-published ca-bundle.pem on the control plane, joined ca.pem on a worker; kubelet live-reloads it), so kubelet can authenticate apiserver's client cert instead of treating proxied requests as anonymous" \
  bash -c 'grep -qF "clientCAFile: \$client_ca" "$1" && grep -qF "local client_ca=\"\$STATE_DIR/ca-bundle.pem\"" "$1" && grep -qF "client_ca=\"\$STATE_DIR/ca.pem\"" "$1"' _ "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: install.sh's own documented reset procedure ("stop the
# u7s services, rm -rf $STATE_DIR, and re-run install.sh", below) is only
# true if everything kubelet caches actually lives under $STATE_DIR. kubelet
# has no certDir/certDirectory KubeletConfiguration yaml field (upstream:
# staging/src/k8s.io/kubelet/config/v1beta1/types.go's TLSCertFile doc
# comment names --cert-dir as a CLI flag, not a config key, and no such
# field exists anywhere on the struct) -- an earlier fix set certDir in
# kubelet-config.yaml, which kubelet silently ignored with no warning,
# leaving it on its compiled-in default (/var/lib/kubelet/pki). That default
# survives `rm -rf $STATE_DIR` untouched: a reset that regenerates the CA
# then leaves kubelet presenting a rotated client cert signed by the deleted
# CA, an infinite UnknownIssuer reconnect loop with no node ever registering
# (reproduced live on a fresh-VM reset). This is a source grep against
# install.sh's literal ExecStart line, not a rendered/executed check, so it
# cannot prove kubelet actually reads the flag at runtime -- but it does
# catch a reverted-to-yaml regression (the exact failure mode above) with no
# live VM required. Both kubelet.service blocks (worker-mode join/upgrade and
# control-plane single-node bootstrap) render this ExecStart line, so each
# block is extracted and checked in isolation below -- a file-wide `grep -c`
# count would stay unchanged (and so keep passing) if the flag were deleted
# from one block while an unrelated second copy (e.g. a comment) were added
# anywhere else in the file, which is not the invariant this test exists to
# guard.
# ---------------------------------------------------------------------------
kubelet_service_block() {
  # Extracts the Nth (1-indexed, $2) `cat > .../kubelet.service <<EOF` ...
  # `EOF` heredoc body from install.sh ($1). Both blocks share the identical
  # header line, so awk's range operator alone can't tell them apart -- a
  # counter picks out the one at index $2.
  local install_script="$1" index="$2"
  awk -v want="$index" '
    /^[[:space:]]*cat > \/etc\/systemd\/system\/kubelet\.service <<EOF$/ { n++ }
    n == want { print; if (/^EOF$/) exit }
  ' "$install_script"
}

kubelet_worker_block="$(kubelet_service_block "$INSTALL" 1)"
kubelet_cp_block="$(kubelet_service_block "$INSTALL" 2)"

# `|| true`: grep -c exits 1 on zero matches, which under this file's
# `set -euo pipefail` would abort the whole suite right here instead of
# failing this one assertion -- a count of 0 is itself a real failure mode
# the -eq 1 check below must catch.
kubelet_worker_cert_dir_count="$(printf '%s\n' "$kubelet_worker_block" | grep -cF -- '--cert-dir=$STATE_DIR/kubelet/pki' || true)"
assert "kubelet's worker-mode ExecStart must carry --cert-dir=\$STATE_DIR/kubelet/pki exactly once -- a file-wide count check doesn't catch someone deleting this from the worker-mode block while duplicating the flag elsewhere in install.sh" \
  "$([ "$kubelet_worker_cert_dir_count" -eq 1 ] && echo 1 || echo 0)"

kubelet_cp_cert_dir_count="$(printf '%s\n' "$kubelet_cp_block" | grep -cF -- '--cert-dir=$STATE_DIR/kubelet/pki' || true)"
assert "kubelet's control-plane-mode ExecStart must carry --cert-dir=\$STATE_DIR/kubelet/pki exactly once -- a file-wide count check doesn't catch someone deleting this from the control-plane-mode block while duplicating the flag elsewhere in install.sh" \
  "$([ "$kubelet_cp_cert_dir_count" -eq 1 ] && echo 1 || echo 0)"

assert_false "kubelet-config.yaml must not set a certDir key -- kubelet has no such KubeletConfiguration field and silently ignores it, so leaving it there would misleadingly suggest the reset-path fix lives in the yaml rather than the ExecStart CLI flag" \
  grep -qF 'certDir:' "$INSTALL"

# ---------------------------------------------------------------------------
# Tarball sourcing: --tarball (local path) / --tarball-url / the URL baked in
# at release time. A script piped into `bash` cannot discover the URL it came
# from, so the published copy carries it as a literal that
# .github/workflows/release-tarball.yaml substitutes in -- these assertions
# pin the two halves of that contract together.
# ---------------------------------------------------------------------------

# The single most damaging way this can regress: someone commits a real URL
# here. Every git checkout would then silently fetch and install THAT
# release's binaries instead of failing loud, and `curl | bash` users of a
# later release would get a script pinned to an older one. This literal is
# also the exact anchor the release workflow's sed matches on, so renaming
# the variable breaks publishing -- caught here at commit time rather than
# mid-release.
assert_true "DEFAULT_TARBALL_URL is empty in the repo copy, so a checkout fails loud instead of silently installing whichever release a committed URL pointed at (and the release workflow's sed anchor still matches)" \
  grep -qxF 'DEFAULT_TARBALL_URL=""' "$INSTALL"

# Asserted on the message, not just a non-zero exit: this check has to run
# BEFORE the root gate, or a non-root operator gets "must be run as root",
# fixes that, and only then learns their flags conflict. Exit-code-only would
# pass either way and so could not fail when that ordering regresses.
conflict_out="$(bash "$INSTALL" --tarball /x --tarball-url http://y 2>&1 || true)"
conflict_ok=0
printf '%s' "$conflict_out" | grep -q 'mutually exclusive' && conflict_ok=1
assert "passing both --tarball and --tarball-url is rejected by name before the root check, so the operator learns their flags conflict on the first run rather than after re-running under sudo" \
  "$conflict_ok"

# A local path the operator already has must never trigger a download, even
# on a released copy where DEFAULT_TARBALL_URL is always non-empty (so an
# unguarded fetch would run on every install).
assert_true "--tarball short-circuits the download entirely, rather than fetching the baked URL and discarding it" \
  grep -qF 'if [ -z "$TARBALL" ]; then' "$INSTALL"

# Ordering guard. The download used to sit next to `tar -xzf`, well after apt
# had installed and started CRI-O -- so a 404 (the expected state until a
# non-prerelease release exists) left the host half-configured. Fetching
# first means a bad URL leaves it untouched.
fetch_line="$(grep -n 'fetch_tarball "$TARBALL_URL"' "$INSTALL" | cut -d: -f1)"
apt_line="$(grep -n '^apt-get update -qq' "$INSTALL" | head -n1 | cut -d: -f1)"
assert "the tarball is downloaded before apt installs anything, so an unreachable or wrong URL aborts with the host untouched instead of half-configured with CRI-O running" \
  "$([ -n "$fetch_line" ] && [ -n "$apt_line" ] && [ "$fetch_line" -lt "$apt_line" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Regression guard: KCM disabled node-ipam-controller with no
# --cluster-cidr, so Node.spec.podCIDR was never allocated and every node's
# CRI-O bridge plugin picked the same uncoordinated default subnet -- a
# cross-node ClusterIP Service was unreachable. Confirmed live on two Lima
# VMs; this is what stops a silent revert from reintroducing that without
# another full 2-node VM run to catch it again.
# ---------------------------------------------------------------------------
assert_false "(regression guard) node-ipam-controller is not in u7s-kcm.service's --controllers disable-list -- disabling it (with no --cluster-cidr) is exactly what left Node.spec.podCIDR unallocated and broke cross-node Service routing" \
  grep -qF -- '-node-ipam-controller' "$INSTALL"

assert_true "u7s-kcm.service enables the off-by-default bootstrap-signer and token-cleaner controllers -- without them expired join tokens are never deleted and cluster-info is never signed" \
  grep -qF -- '--controllers=*,bootstrap-signer-controller,token-cleaner-controller,' "$INSTALL"

assert_true "u7s-kcm.service's ExecStart allocates per-node pod CIDRs (--allocate-node-cidrs=true --cluster-cidr=...), which node-ipam-controller needs to stamp Node.spec.podCIDR at all" \
  grep -qF -- '--allocate-node-cidrs=true --cluster-cidr=$POD_CLUSTER_CIDR' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: the other half -- fixing IPAM allocation alone
# does not fix cross-node routing, since CRI-O's stock bridge plugin never
# consumes Node.spec.podCIDR for cross-node routing at all. Flannel is the
# actual CNI closing that gap; losing this deployment (or the
# crio-bridge-disable pairing below) silently reintroduces the original
# unreachable-cross-node-Service symptom even with podCIDR correctly
# allocated. Flannel's DaemonSet moved from an install.sh heredoc to
# manifests/flannel.yaml -- assert both halves: install.sh no
# longer embeds it, and the vendored file still deploys it.
# ---------------------------------------------------------------------------
assert_false "(regression guard) install.sh no longer embeds Flannel's DaemonSet as an inline heredoc -- it now lives in manifests/flannel.yaml, applied via the well-known-manifest-folder mechanism" \
  grep -qF 'name: kube-flannel-ds' "$INSTALL"

assert_true "manifests/flannel.yaml exists -- the vendored source-of-truth Flannel's DaemonSet moved into" \
  test -f "$FLANNEL_MANIFEST"

assert_true "manifests/flannel.yaml deploys Flannel's DaemonSet (kube-flannel-ds) as the real CNI, not just relying on CRI-O's default bridge plugin" \
  grep -qF 'name: kube-flannel-ds' "$FLANNEL_MANIFEST"

assert_true "manifests/flannel.yaml's --iface is a __IFACE__ placeholder scripts/install.sh substitutes at install time, not a value hardcoded to whichever node it was vendored from" \
  grep -qF -- '--iface=__IFACE__' "$FLANNEL_MANIFEST"

assert_true "manifests/flannel.yaml's net-conf.json Network is a __POD_CLUSTER_CIDR__ placeholder scripts/install.sh substitutes, so it can never drift from kube-controller-manager's own --cluster-cidr" \
  grep -qF '"Network": "__POD_CLUSTER_CIDR__"' "$FLANNEL_MANIFEST"

assert_true "install.sh disables CRI-O's own default bridge CNI conflist(s) once Flannel supplies the real one -- CRI-O picks whichever CNI config file sorts first alphabetically, so leaving 10-crio-bridge.conflist active would silently keep winning over Flannel's 10-flannel.conflist" \
  grep -qF 'mv "$CNI_DIR/$f" "$CNI_DIR/$f.disabled"' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: Flannel's vxlan backend hard-fails at startup ("Failed to
# check br_netfilter: stat /proc/sys/net/bridge/bridge-nf-call-iptables: no
# such file or directory") on a fresh Ubuntu cloud image, which does not load
# br_netfilter by default -- confirmed live. Losing this would leave every
# Flannel pod crash-looping on any host that has not already loaded the
# module some other way.
# ---------------------------------------------------------------------------
assert_true "install.sh loads br_netfilter, a hard prerequisite for Flannel's vxlan backend that a fresh Ubuntu cloud image doesn't enable by default" \
  grep -qF 'modprobe br_netfilter' "$INSTALL"

assert_true "br_netfilter is persisted via modules-load.d so it survives a reboot, not just the install run" \
  grep -qF '/etc/modules-load.d/u7s-br-netfilter.conf' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: kube-proxy's iptables-mode Service NAT (u7s's default,
# manifests/kube-proxy.yaml) relies on br_netfilter's
# net.bridge.bridge-nf-call-iptables{,6}=1 sysctls being set -- without them,
# frames bridged purely at L2 between two pods on the same node's CNI bridge
# never traverse netfilter, so the DNAT rule mapping a ClusterIP to its
# backend pod is never applied and same-node Service traffic silently times
# out (confirmed live: a kube-dns ClusterIP DNS query). This
# extracts and actually runs the real modprobe/sysctl-file-write statements
# (not a hand-copy or a grep for a literal), with modprobe/sysctl themselves
# stubbed out (no root, no real kernel module needed) and the /etc paths
# redirected into a temp dir, so a future edit that drops the module load or
# either sysctl fails here instead of only on a live VM running a real
# workload against a Service.
# ---------------------------------------------------------------------------
br_netfilter_runner() {
  local install_script="$1" runner="$2" workdir="$3"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo "modprobe() { echo \"\$*\" >> \"$workdir/modprobe.log\"; }"
    echo 'sysctl() { :; }'
    awk '/^modprobe br_netfilter$/,/^sysctl --system >\/dev\/null$/' "$install_script" \
      | sed "s#/etc/modules-load.d#$workdir/modules-load.d#; s#/etc/sysctl.d#$workdir/sysctl.d#"
  } > "$runner"
}

BR_NETFILTER_WORK="$(mktemp -d)"
mkdir -p "$BR_NETFILTER_WORK/modules-load.d" "$BR_NETFILTER_WORK/sysctl.d"
BR_NETFILTER_RUNNER="$BR_NETFILTER_WORK/br-netfilter.sh"
br_netfilter_runner "$INSTALL" "$BR_NETFILTER_RUNNER" "$BR_NETFILTER_WORK"
bash "$BR_NETFILTER_RUNNER"

assert_true "install.sh's kernel-module step actually invokes modprobe with br_netfilter (not just mentions it in a comment)" \
  grep -qF 'br_netfilter' "$BR_NETFILTER_WORK/modprobe.log"

BR_NETFILTER_SYSCTL_CONF="$BR_NETFILTER_WORK/sysctl.d/u7s-br-netfilter.conf"
assert_true "the sysctl.d config install.sh writes sets net.bridge.bridge-nf-call-iptables=1, which kube-proxy's iptables NAT relies on to see bridged same-node pod-to-pod traffic at all -- missing this breaks Service-to-pod traffic silently, only noticed when a workload actually uses a Service" \
  grep -qxF 'net.bridge.bridge-nf-call-iptables = 1' "$BR_NETFILTER_SYSCTL_CONF"
assert_true "the sysctl.d config install.sh writes also sets the ip6tables counterpart, so IPv6 Service traffic gets the same bridged-netfilter treatment as IPv4" \
  grep -qxF 'net.bridge.bridge-nf-call-ip6tables = 1' "$BR_NETFILTER_SYSCTL_CONF"
rm -rf "$BR_NETFILTER_WORK"

# ---------------------------------------------------------------------------
# Regression guard: 'systemctl enable --now UNIT' is enable+
# start; start on an already-active unit is a no-op, so a re-run of
# install.sh staged new binaries into place but the running process never
# re-exec'd against them -- an "upgrade" that silently kept the old binary
# running until a manual restart or reboot.
# ---------------------------------------------------------------------------
assert_false "(regression guard) install.sh no longer uses 'systemctl enable --now', which silently no-ops a re-run against an already-active unit instead of restarting it onto the newly staged binary" \
  grep -qF 'enable --now' "$INSTALL"

assert_true "the apiserver restart step fails loud with a systemctl status/journalctl pointer on failure, instead of a bare set -e trace" \
  grep -qF 'error: failed to restart u7s-apiserver.service (check: systemctl status u7s-apiserver, journalctl -u u7s-apiserver)' "$INSTALL"

# ---------------------------------------------------------------------------
# Production defaults to the embedded scheduler instead of a standalone
# u7s-scheduler.service. The double-preemption risk (embedded + standalone
# both running against the same cluster keep independent, uncoordinated
# preemption dedup state) means this is not just a process-count cleanup --
# a fresh install must never provision the standalone unit at all, and an
# in-place upgrade of a host that has one from before this change must have
# it stopped and removed, not left running alongside the newly embedded
# scheduler.
# ---------------------------------------------------------------------------
assert_true "u7s-apiserver.service's ExecStart passes --embedded-scheduler true -- production now schedules inside this process instead of relying on a separate u7s-scheduler binary" \
  grep -qF -- '--embedded-scheduler true' "$INSTALL"

assert_true "u7s-apiserver.service's ExecStart passes --local-node-name \$NODE_NAME -- without it the single-node kubelet's serving CSR (IP SAN == apiserver address) stays Pending and kubectl logs/exec fail" \
  grep -qF -- '--local-node-name $NODE_NAME' "$INSTALL"

line_of() { grep -nF -- "$1" "$INSTALL" | head -1 | cut -d: -f1; }
node_name_defaulted_before_unit_written() {
  local dflt unit
  dflt="$(line_of 'NODE_NAME="$(normalize_node_name "$(hostname)")"')"
  unit="$(line_of '--local-node-name $NODE_NAME')"
  [ -n "$dflt" ] && [ -n "$unit" ] && [ "$dflt" -lt "$unit" ]
}
assert_true "NODE_NAME is defaulted from the hostname before the apiserver unit is written -- an empty --local-node-name would silently disable the single-node serving-CSR exemption" \
  node_name_defaulted_before_unit_written

assert_true "install.sh refuses an empty NODE_NAME after defaulting -- the apiserver must never be started with a blank --local-node-name" \
  grep -qF -- 'refusing to continue: empty node name' "$INSTALL"

assert_false "(regression guard) install.sh no longer writes a u7s-scheduler.service unit file -- running the embedded scheduler AND a standalone u7s-scheduler against the same cluster risks double-preemption, so a fresh install must not provision the standalone unit at all" \
  grep -qF 'cat > /etc/systemd/system/u7s-scheduler.service' "$INSTALL"

assert_false "(regression guard) install.sh no longer enables the standalone u7s-scheduler.service" \
  grep -qF 'systemctl enable u7s-scheduler.service' "$INSTALL"

assert_false "(regression guard) install.sh no longer restarts the standalone u7s-scheduler.service" \
  grep -qF 'systemctl restart u7s-scheduler.service' "$INSTALL"

# Upgrade-path cleanup: extracted verbatim from install.sh's own source (same
# "exercise the real logic" approach as the other extractions in this file).
# SCHEDULER_UNIT_FILE is a variable in install.sh specifically so this test
# can point it at a scratch path instead of the real /etc/systemd/system,
# and systemctl is shimmed via PATH so the real command is never invoked.
write_scheduler_retirement_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'SCHEDULER_UNIT_FILE="$1"'
    awk '/^if \[ -f "\$SCHEDULER_UNIT_FILE" \]; then$/,/^fi$/' "$install_script"
  } > "$runner"
}

SCHED_WORK="$(mktemp -d)"
# Replaces the earlier EXIT traps above (only the latest fires), so it must
# still cover every dir those relied on cleaning up.
trap 'rm -rf "$DETECT_WORK" "$WORKER_MODE_WORK" "$MANIFEST_WORK" "$PERSIST_WORK" "$SCHED_WORK"' EXIT
SCHED_RUNNER="$SCHED_WORK/retire-scheduler.sh"
write_scheduler_retirement_runner "$INSTALL" "$SCHED_RUNNER"

SCHED_FAKE_BIN="$SCHED_WORK/fakebin"
mkdir -p "$SCHED_FAKE_BIN"
SCHED_SYSTEMCTL_LOG="$SCHED_WORK/systemctl.log"
: > "$SCHED_SYSTEMCTL_LOG"
cat > "$SCHED_FAKE_BIN/systemctl" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$SCHED_SYSTEMCTL_LOG"
exit 0
EOF
chmod +x "$SCHED_FAKE_BIN/systemctl"

# Case 1: the realistic accidental-double-run scenario -- a host installed
# before this change has u7s-scheduler.service on disk.
# Re-running install.sh (an in-place upgrade) must stop, disable, and remove
# it, and reload systemd, so the standalone scheduler cannot still be active
# once the apiserver restarts into embedded mode.
sched_existing="$SCHED_WORK/existing/u7s-scheduler.service"
mkdir -p "$(dirname "$sched_existing")"
echo '[Unit]' > "$sched_existing"
sched_out="$(PATH="$SCHED_FAKE_BIN:$PATH" bash "$SCHED_RUNNER" "$sched_existing" 2>&1)"
assert_false "an upgrade of a host with a pre-existing u7s-scheduler.service removes the unit file, so it cannot linger and run alongside the newly embedded scheduler" \
  test -f "$sched_existing"
assert "an upgrade with a pre-existing u7s-scheduler.service stops it via systemctl before removing it, closing the window where both the old standalone and new embedded scheduler could be active at once" \
  "$(grep -qF 'stop u7s-scheduler.service' "$SCHED_SYSTEMCTL_LOG" && echo 1 || echo 0)"
assert "an upgrade with a pre-existing u7s-scheduler.service disables it via systemctl, so it cannot come back on the next reboot" \
  "$(grep -qF 'disable u7s-scheduler.service' "$SCHED_SYSTEMCTL_LOG" && echo 1 || echo 0)"
assert "an upgrade with a pre-existing u7s-scheduler.service reloads the systemd unit cache after removing the unit file" \
  "$(grep -qF 'daemon-reload' "$SCHED_SYSTEMCTL_LOG" && echo 1 || echo 0)"
assert "the retirement step tells the operator why -- scheduling moved into the embedded apiserver task" \
  "$(printf '%s' "$sched_out" | grep -qi 'retiring' && echo 1 || echo 0)"

# Case 2: a genuinely fresh install (no prior u7s-scheduler.service on disk)
# must be a silent no-op -- no systemctl calls, no "retiring" message. A
# false positive here would print a confusing message about retiring
# something that was never installed.
: > "$SCHED_SYSTEMCTL_LOG"
sched_fresh_missing="$SCHED_WORK/fresh/u7s-scheduler.service"
fresh_sched_out="$(PATH="$SCHED_FAKE_BIN:$PATH" bash "$SCHED_RUNNER" "$sched_fresh_missing" 2>&1)"
assert "a fresh install (no pre-existing u7s-scheduler.service) makes no systemctl calls at all -- this step must be a true no-op, not merely idempotent" \
  "$([ ! -s "$SCHED_SYSTEMCTL_LOG" ] && echo 1 || echo 0)"
assert "a fresh install prints no 'retiring' message, since there is nothing to retire" \
  "$(printf '%s' "$fresh_sched_out" | grep -qi 'retiring' && echo 0 || echo 1)"

# Mutation self-check (CLAUDE.md rule 14): prove Case 1 above would actually
# catch a reverted/skipped cleanup, not just document today's behavior.
MUTATED_SCHED_INSTALL="$SCHED_WORK/install-mutated.sh"
sed 's/if \[ -f "\$SCHEDULER_UNIT_FILE" \]; then/if false; then/' "$INSTALL" > "$MUTATED_SCHED_INSTALL"
if diff -q "$INSTALL" "$MUTATED_SCHED_INSTALL" > /dev/null 2>&1; then
  assert "mutation self-check: the scheduler-retirement guard's condition line exists in install.sh to mutate (if this fails, the line was renamed/reshaped and this suite no longer exercises it)" 0
else
  MUTATED_SCHED_RUNNER="$SCHED_WORK/retire-scheduler-mutated.sh"
  write_scheduler_retirement_runner "$MUTATED_SCHED_INSTALL" "$MUTATED_SCHED_RUNNER"
  sched_mutated_existing="$SCHED_WORK/existing-mutated/u7s-scheduler.service"
  mkdir -p "$(dirname "$sched_mutated_existing")"
  echo '[Unit]' > "$sched_mutated_existing"
  : > "$SCHED_SYSTEMCTL_LOG"
  PATH="$SCHED_FAKE_BIN:$PATH" bash "$MUTATED_SCHED_RUNNER" "$sched_mutated_existing" >/dev/null 2>&1 || true
  assert "mutation self-check: with the retirement guard bypassed, a pre-existing u7s-scheduler.service is wrongly left in place -- proving Case 1 above would fail if this upgrade-path cleanup were ever reverted, silently reintroducing the realistic double-run risk" \
    "$([ -f "$sched_mutated_existing" ] && echo 1 || echo 0)"
fi

# ---------------------------------------------------------------------------
# Regression guard: kube-proxy's own kubeconfig pointed at the
# "kubernetes" Service's ClusterIP (10.96.0.1:443) -- reachable only via
# iptables DNAT rules that kube-proxy itself is responsible for installing,
# a bootstrap deadlock that left every ClusterIP unreachable cluster-wide.
# kube-proxy's DaemonSet moved from an install.sh heredoc to
# manifests/kube-proxy.yaml -- assert both halves: install.sh
# no longer embeds it, and the vendored file still avoids the ClusterIP.
# ---------------------------------------------------------------------------
assert_false "(regression guard) install.sh no longer embeds kube-proxy's DaemonSet as an inline heredoc -- it now lives in manifests/kube-proxy.yaml, applied via the well-known-manifest-folder mechanism" \
  grep -qF 'name: kube-proxy' "$INSTALL"

assert_true "manifests/kube-proxy.yaml exists -- the vendored source-of-truth kube-proxy's DaemonSet moved into" \
  test -f "$KUBE_PROXY_MANIFEST"

assert_false "(regression guard) kube-proxy's kubeconfig no longer points at the kubernetes Service's ClusterIP (10.96.0.1:443), which is only reachable via DNAT rules kube-proxy itself has not yet installed at bootstrap" \
  grep -qF '10.96.0.1:443' "$KUBE_PROXY_MANIFEST"

assert_true "manifests/kube-proxy.yaml's kubeconfig server is a __IFACE_IP__ placeholder scripts/install.sh substitutes with the real advertised apiserver address, reachable without depending on kube-proxy's own DNAT rules" \
  grep -qF 'server: https://__IFACE_IP__:6443' "$KUBE_PROXY_MANIFEST"

assert_true "manifests/kube-proxy.yaml's image tag is a __KUBE_VERSION__ placeholder scripts/install.sh substitutes with the bundled kubelet's own version, not a fixed tag Renovate/Dependabot could bump independently and out of lockstep with it" \
  grep -qF 'image: registry.k8s.io/kube-proxy:v__KUBE_VERSION__' "$KUBE_PROXY_MANIFEST"

# ---------------------------------------------------------------------------
# Regression guard: `sh install.sh` on Ubuntu (where /bin/sh is
# dash) used to die on the `set -euo pipefail` line with a bare "Illegal
# option -o pipefail", exit 2, before ever reaching fetch_tarball's checksum
# verification -- undermining the "always require a passing checksum" policy
# on the exact invocation deploy/get-u7s/README.md documents. The guard must
# sit before that `set` line so dash lives long enough to print it.
# ---------------------------------------------------------------------------
bash_version_line="$(grep -n 'BASH_VERSION' "$INSTALL" | head -n1 | cut -d: -f1)"
pipefail_line="$(grep -n '^set -euo pipefail' "$INSTALL" | head -n1 | cut -d: -f1)"
assert "the bash-required guard appears before the 'set -euo pipefail' line dash cannot parse, so dash survives long enough to print it instead of dying first" \
  "$([ -n "$bash_version_line" ] && [ -n "$pipefail_line" ] && [ "$bash_version_line" -lt "$pipefail_line" ] && echo 1 || echo 0)"

if command -v dash >/dev/null 2>&1; then
  dash_out="$(dash "$INSTALL" --help 2>&1)" && dash_status=0 || dash_status=$?
  assert "running install.sh under dash (Ubuntu's /bin/sh) exits non-zero with a clear bash-required message, instead of dash's bare 'Illegal option -o pipefail' parse crash" \
    "$([ "$dash_status" -ne 0 ] && printf '%s' "$dash_out" | grep -qi 'requires bash' && echo 1 || echo 0)"
else
  echo "SKIP: dash not installed on this runner -- cannot exercise the dash-rejection path directly"
fi

bash_out="$(bash "$INSTALL" --help 2>&1)" && bash_status=0 || bash_status=$?
assert "running install.sh under bash (a real invocation) is unaffected by the guard and proceeds past it" \
  "$([ "$bash_status" -eq 0 ] && printf '%s' "$bash_out" | grep -q '^Usage:' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Regression guard: A re-run of install.sh against an existing
# node used to look identical to a fresh install in its own output, giving
# the operator no signal that CA/cluster state was being preserved rather
# than built from scratch. Extracted verbatim from install.sh's own source
# (the same "exercise the real logic, not a hand-copy" approach as
# test-install-checksum.sh's fetch_tarball extraction), so this fails if the
# shipped heuristic regresses, not just a copy of it kept here.
# ---------------------------------------------------------------------------
write_detection_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"'
    awk '/^EXISTING_INSTALL=0$/,/^fi$/' "$install_script"
    echo 'echo "EXISTING_INSTALL=$EXISTING_INSTALL"'
  } > "$runner"
}

DETECT_WORK="$(mktemp -d)"
trap 'rm -rf "$DETECT_WORK"' EXIT
DETECT_RUNNER="$DETECT_WORK/detect.sh"
write_detection_runner "$INSTALL" "$DETECT_RUNNER"

fresh_dir="$DETECT_WORK/fresh"
mkdir -p "$fresh_dir"
fresh_out="$(bash "$DETECT_RUNNER" "$fresh_dir" 2>&1)"
assert "a genuinely fresh node (no ca.key, no kubeconfig on disk yet) is NOT flagged as an existing install -- a false positive here would print a confusing 'upgrading' message on someone's very first run" \
  "$(printf '%s' "$fresh_out" | grep -q '^EXISTING_INSTALL=0$' && ! printf '%s' "$fresh_out" | grep -qi 'existing u7s install detected' && echo 1 || echo 0)"

cp_dir="$DETECT_WORK/control-plane"
mkdir -p "$cp_dir"
touch "$cp_dir/ca.key"
cp_out="$(bash "$DETECT_RUNNER" "$cp_dir" 2>&1)"
assert "a control-plane node with an existing ca.key IS detected as an existing install -- ca.key only exists once apiserver's own load_or_generate_ca has actually run and succeeded, unlike the systemd unit file which install.sh writes even on a failed first attempt" \
  "$(printf '%s' "$cp_out" | grep -q '^EXISTING_INSTALL=1$' && printf '%s' "$cp_out" | grep -qi 'existing u7s install detected' && echo 1 || echo 0)"

worker_dir="$DETECT_WORK/worker"
mkdir -p "$worker_dir"
touch "$worker_dir/kubeconfig"
worker_out="$(bash "$DETECT_RUNNER" "$worker_dir" 2>&1)"
assert "an already-joined worker node (kubeconfig present, ca.key absent -- join_cluster never writes a CA key on a worker) IS detected as an existing install" \
  "$(printf '%s' "$worker_out" | grep -q '^EXISTING_INSTALL=1$' && printf '%s' "$worker_out" | grep -qi 'existing u7s install detected' && echo 1 || echo 0)"

assert_false "(regression guard) the detection message does not reference a --force-reinstall flag, which does not exist in this bead's shipped scope -- mentioning it would send operators looking for a flag install.sh would reject as unknown" \
  grep -qF -- '--force-reinstall' "$INSTALL"

# ---------------------------------------------------------------------------
# Worker-node re-run safety: join_cluster() is one-shot (fresh CSR against a
# single-use bootstrap token, unconditional kubeconfig/kubelet-client.*
# overwrite). Re-running it against an already-joined worker -- an operator
# re-passing --join/--token out of habit, or install.sh naively re-running
# with no flags and guessing wrong -- would silently rotate the node's
# client identity and likely fail outright anyway. Extracted verbatim from
# install.sh's own source, same approach as the EXISTING_INSTALL detection
# test above.
# ---------------------------------------------------------------------------
write_worker_mode_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"'
    echo 'JOIN_SERVER="$2"'
    awk '/^JOIN_MODE=0$/,/^  WORKER_MODE=1$/' "$install_script"
    echo 'fi'
    echo 'echo "JOIN_MODE=$JOIN_MODE"'
    echo 'echo "EXISTING_WORKER=$EXISTING_WORKER"'
    echo 'echo "WORKER_MODE=$WORKER_MODE"'
  } > "$runner"
}

WORKER_MODE_WORK="$(mktemp -d)"
# Replaces the DETECT_WORK-only trap above (only the latest EXIT trap
# fires), so it must still cover DETECT_WORK too.
trap 'rm -rf "$DETECT_WORK" "$WORKER_MODE_WORK"' EXIT
WORKER_MODE_RUNNER="$WORKER_MODE_WORK/worker-mode.sh"
write_worker_mode_runner "$INSTALL" "$WORKER_MODE_RUNNER"

# Case A: the acceptance criterion this bead exists for -- --join against an
# already-joined worker (kubeconfig present, no ca.key) must refuse loudly
# and exit non-zero, rather than re-running the CSR flow and rotating this
# node's identity.
already_joined_dir="$WORKER_MODE_WORK/already-joined"
mkdir -p "$already_joined_dir"
touch "$already_joined_dir/kubeconfig"
rejoin_status=0
rejoin_out="$(bash "$WORKER_MODE_RUNNER" "$already_joined_dir" "https://1.2.3.4:6443" 2>&1)" || rejoin_status=$?
assert "--join against an already-joined worker (kubeconfig present, no ca.key) is refused loudly with a non-zero exit, instead of silently re-running the one-shot CSR flow and rotating the node's client identity" \
  "$([ "$rejoin_status" -ne 0 ] && printf '%s' "$rejoin_out" | grep -qi 'refusing' && echo 1 || echo 0)"

# Case B: --join against a genuinely fresh node (no kubeconfig, no ca.key at
# all) must proceed normally -- the guard must not misfire on the one case
# --join actually exists for.
fresh_join_dir="$WORKER_MODE_WORK/fresh-join"
mkdir -p "$fresh_join_dir"
fresh_join_out="$(bash "$WORKER_MODE_RUNNER" "$fresh_join_dir" "https://1.2.3.4:6443" 2>&1)"
assert "--join against a genuinely fresh node proceeds normally (JOIN_MODE=1, WORKER_MODE=1) -- the refuse-loud guard must not misfire on a real first-time join" \
  "$(printf '%s' "$fresh_join_out" | grep -q '^JOIN_MODE=1$' && printf '%s' "$fresh_join_out" | grep -q '^WORKER_MODE=1$' && echo 1 || echo 0)"

# Case C: a bare re-run (no --join/--token, the "curl | sudo bash" upgrade
# UX) against an already-joined worker must resolve to WORKER_MODE=1 with
# JOIN_MODE=0 -- the upgrade path that stages kubelet alone and never
# re-enters join_cluster(), rather than an operator naively re-running
# install.sh with no flags falling through to the control-plane path.
worker_upgrade_dir="$WORKER_MODE_WORK/worker-upgrade"
mkdir -p "$worker_upgrade_dir"
touch "$worker_upgrade_dir/kubeconfig"
worker_upgrade_out="$(bash "$WORKER_MODE_RUNNER" "$worker_upgrade_dir" "" 2>&1)"
assert "a bare re-run (no --join/--token) against an already-joined worker resolves to WORKER_MODE=1 with JOIN_MODE=0 -- upgrades kubelet in place without ever re-entering join_cluster() or touching kubeconfig/kubelet-client.*" \
  "$(printf '%s' "$worker_upgrade_out" | grep -q '^JOIN_MODE=0$' && printf '%s' "$worker_upgrade_out" | grep -q '^EXISTING_WORKER=1$' && printf '%s' "$worker_upgrade_out" | grep -q '^WORKER_MODE=1$' && echo 1 || echo 0)"

# Case D: a bare re-run against a control-plane node (ca.key present) must
# stay on the full control-plane path (WORKER_MODE=0) -- this guard is
# worker-specific and must not misclassify the other node role.
cp_upgrade_dir="$WORKER_MODE_WORK/cp-upgrade"
mkdir -p "$cp_upgrade_dir"
touch "$cp_upgrade_dir/ca.key"
cp_upgrade_out="$(bash "$WORKER_MODE_RUNNER" "$cp_upgrade_dir" "" 2>&1)"
assert "a bare re-run against a control-plane node (ca.key present) stays on the full control-plane path (WORKER_MODE=0) -- a control-plane upgrade must not be misclassified as a worker one" \
  "$(printf '%s' "$cp_upgrade_out" | grep -q '^WORKER_MODE=0$' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Mutation self-check (CLAUDE.md rule 14): prove the refuse-loud guard
# assertion above would actually catch a reverted fix, not just document
# today's behavior. Bypass the guard in a scratch copy of install.sh and
# rerun the exact already-joined-worker scenario against it -- if the guard
# is gone, --join must instead proceed (WORKER_MODE=1 printed, no refusal).
# ---------------------------------------------------------------------------
MUTATED_INSTALL="$WORKER_MODE_WORK/install-mutated.sh"
sed 's/if \[ "\$JOIN_MODE" -eq 1 \] && \[ "\$EXISTING_WORKER" -eq 1 \]; then/if false; then/' "$INSTALL" > "$MUTATED_INSTALL"
if diff -q "$INSTALL" "$MUTATED_INSTALL" > /dev/null 2>&1; then
  assert "mutation self-check: the refuse-loud guard's condition line exists in install.sh to mutate (if this fails, the line was renamed/reshaped and this suite no longer exercises it)" 0
else
  MUTATED_RUNNER="$WORKER_MODE_WORK/worker-mode-mutated.sh"
  write_worker_mode_runner "$MUTATED_INSTALL" "$MUTATED_RUNNER"
  mutated_status=0
  mutated_out="$(bash "$MUTATED_RUNNER" "$already_joined_dir" "https://1.2.3.4:6443" 2>&1)" || mutated_status=$?
  assert "mutation self-check: with the refuse-loud guard bypassed, a --join re-run against an already-joined worker is wrongly allowed to proceed -- proving the refusal test above would fail if this fix were ever reverted" \
    "$([ "$mutated_status" -eq 0 ] && printf '%s' "$mutated_out" | grep -q '^WORKER_MODE=1$' && echo 1 || echo 0)"
fi

# ---------------------------------------------------------------------------
# --manifest-output-dir: default value, flag parsing, and env-var fallback
# must match the existing --iface/U7S_IFACE convention -- an operator relying
# on that convention for --iface would reasonably expect the same shape here.
# ---------------------------------------------------------------------------
assert_true "MANIFEST_OUTPUT_DIR defaults to /etc/u7s/manifests (the apiserver's well-known auto-applied folder) when neither the flag nor U7S_MANIFEST_OUTPUT_DIR is set" \
  grep -qF 'MANIFEST_OUTPUT_DIR="${U7S_MANIFEST_OUTPUT_DIR:-/etc/u7s/manifests}"' "$INSTALL"

assert_true "--manifest-output-dir is parsed as a flag, overriding the default/env-var value" \
  grep -qF -- '--manifest-output-dir) MANIFEST_OUTPUT_DIR="$2"; shift 2 ;;' "$INSTALL"

# ---------------------------------------------------------------------------
# Vendored-manifest copy step: extracted verbatim from install.sh's own
# source (same approach as fetch_tarball's extraction in
# test-install-checksum.sh), so these assertions fail if the shipped logic
# regresses, not just a hand-copy kept here.
# ---------------------------------------------------------------------------
write_manifest_copy_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STAGE_DIR="$1"'
    echo 'MANIFEST_OUTPUT_DIR="$2"'
    echo 'WORKER_MODE="$3"'
    # $4/$5 (IFACE/POD_CLUSTER_CIDR) and $6/$7 (KUBE_VERSION/IFACE_IP) are
    # only read by flannel.yaml's/kube-proxy.yaml's own substitution branches
    # below -- defaulted so existing callers that don't pass them (no
    # flannel.yaml/kube-proxy.yaml fixture in play) aren't forced to.
    echo 'IFACE="${4:-eth0}"'
    echo 'POD_CLUSTER_CIDR="${5:-10.244.0.0/16}"'
    echo 'KUBE_VERSION="${6:-1.37.1}"'
    echo 'IFACE_IP="${7:-10.0.0.1}"'
    echo 'CLUSTER_DNS="${8:-10.96.0.10}"'
    awk '/^render_vendored_manifests\(\) \{$/,/^\}$/' "$install_script"
    awk '/^if \[ "\$WORKER_MODE" -eq 0 \]; then$/,/^fi$/' "$install_script"
  } > "$runner"
}

MANIFEST_WORK="$(mktemp -d)"
# Replaces the DETECT_WORK-only trap above (only the latest EXIT trap fires),
# so it must still cover DETECT_WORK too.
trap 'rm -rf "$DETECT_WORK" "$MANIFEST_WORK"' EXIT
MANIFEST_RUNNER="$MANIFEST_WORK/manifest-copy.sh"
write_manifest_copy_runner "$INSTALL" "$MANIFEST_RUNNER"

# Case 1: tarball carries manifests/*.yaml, default well-known destination --
# the common case once the release-pipeline vendoring bead lands. Files must
# actually reach the folder apiserver's own boot-time scan reads.
stage1="$MANIFEST_WORK/stage1"
mkdir -p "$stage1/manifests"
printf 'kind: Service\nspec:\n  clusterIP: 10.96.0.10\n' > "$stage1/manifests/coredns.yaml"
dest1="$MANIFEST_WORK/dest1"
bash "$MANIFEST_RUNNER" "$stage1" "$dest1" 0
assert_true "a manifests/*.yaml file found in the extracted tarball is copied into the (default well-known) output directory" \
  test -f "$dest1/coredns.yaml"

# Case 2: operator points --manifest-output-dir elsewhere (GitOps entry
# point) -- the well-known folder must end up with NOTHING, not a partial
# copy, or apiserver's boot-time scan would auto-apply files the operator
# meant to manage themselves.
stage2="$MANIFEST_WORK/stage2"
mkdir -p "$stage2/manifests"
echo 'kind: ConfigMap' > "$stage2/manifests/kube-proxy.yaml"
wellknown2="$MANIFEST_WORK/wellknown2"
altdest2="$MANIFEST_WORK/altdest2"
mkdir -p "$wellknown2"
bash "$MANIFEST_RUNNER" "$stage2" "$altdest2" 0
assert_true "an alternate --manifest-output-dir receives the vendored manifest file" \
  test -f "$altdest2/kube-proxy.yaml"
assert "an alternate --manifest-output-dir leaves the well-known folder untouched (empty) -- the GitOps contract this bead exists for: apiserver's own scan of the well-known folder must find nothing to auto-apply" \
  "$([ -z "$(ls -A "$wellknown2" 2>/dev/null)" ] && echo 1 || echo 0)"

# Case 3: WORKER_MODE=1 (a --join worker install, or an upgrade re-run
# against an already-joined worker -- no apiserver on either to apply
# anything) must skip the copy entirely, even if the tarball happens to
# carry a manifests/ dir.
stage3="$MANIFEST_WORK/stage3"
mkdir -p "$stage3/manifests"
echo 'kind: ConfigMap' > "$stage3/manifests/flannel.yaml"
dest3="$MANIFEST_WORK/dest3"
bash "$MANIFEST_RUNNER" "$stage3" "$dest3" 1
assert_false "a worker node (WORKER_MODE=1: fresh --join or an already-joined worker's upgrade) skips the manifest copy step entirely -- neither runs an apiserver, so there is nothing to auto-apply" \
  test -e "$dest3"

# Case 4: a checkout's tarball with no manifests/ dir at all (true until the
# release-pipeline vendoring bead lands separately) must be a silent no-op,
# not a fatal error that breaks every install in the meantime.
stage4="$MANIFEST_WORK/stage4"
mkdir -p "$stage4"
dest4="$MANIFEST_WORK/dest4"
copy_status=0
bash "$MANIFEST_RUNNER" "$stage4" "$dest4" 0 || copy_status=$?
assert "a tarball with no manifests/ dir at all is treated as an empty set, not an error -- required until the release-pipeline vendoring bead actually lands manifests into the tarball" \
  "$([ "$copy_status" -eq 0 ] && echo 1 || echo 0)"

# Case 5: flannel.yaml's __IFACE__/__POD_CLUSTER_CIDR__
# placeholders must be resolved to install.sh's own real values on the way
# into the well-known folder -- a plain byte-for-byte copy (correct for every
# other manifest) would ship these tokens unresolved, and flanneld would
# fail to find a real --iface or net-conf.json Network.
stage5="$MANIFEST_WORK/stage5"
mkdir -p "$stage5/manifests"
printf '        - --iface=__IFACE__\n      "Network": "__POD_CLUSTER_CIDR__",\n' \
  > "$stage5/manifests/flannel.yaml"
dest5="$MANIFEST_WORK/dest5"
bash "$MANIFEST_RUNNER" "$stage5" "$dest5" 0 "eth7" "10.99.0.0/16"
assert_true "flannel.yaml's __IFACE__ placeholder is substituted with install.sh's own resolved --iface value on the way into the well-known folder" \
  grep -qF -- '--iface=eth7' "$dest5/flannel.yaml"
assert_true "flannel.yaml's __POD_CLUSTER_CIDR__ placeholder is substituted with node-ipam-controller's own --cluster-cidr on the way into the well-known folder" \
  grep -qF '"Network": "10.99.0.0/16"' "$dest5/flannel.yaml"
assert_false "flannel.yaml carries no unresolved __IFACE__/__POD_CLUSTER_CIDR__ token once it reaches the well-known folder apiserver auto-applies at boot" \
  grep -qE '__IFACE__|__POD_CLUSTER_CIDR__' "$dest5/flannel.yaml"

# Mutation self-check (CLAUDE.md rule 14): prove the three assertions above
# would actually catch a reverted substitution step, not just document
# today's behavior.
MUTATED_FLANNEL_SUB_INSTALL="$MANIFEST_WORK/install-mutated-flannel-sub.sh"
sed 's/if \[ -f "\$dir\/flannel.yaml" \]; then/if false; then/' "$INSTALL" \
  > "$MUTATED_FLANNEL_SUB_INSTALL"
if diff -q "$INSTALL" "$MUTATED_FLANNEL_SUB_INSTALL" > /dev/null 2>&1; then
  assert "mutation self-check: flannel.yaml's substitution guard exists in install.sh to mutate (if this fails, the line was renamed/reshaped and this suite no longer exercises it)" 0
else
  MUTATED_FLANNEL_SUB_RUNNER="$MANIFEST_WORK/manifest-copy-mutated-flannel-sub.sh"
  write_manifest_copy_runner "$MUTATED_FLANNEL_SUB_INSTALL" "$MUTATED_FLANNEL_SUB_RUNNER"
  mutated_dest5="$MANIFEST_WORK/dest5-mutated"
  bash "$MUTATED_FLANNEL_SUB_RUNNER" "$stage5" "$mutated_dest5" 0 "eth7" "10.99.0.0/16"
  assert "mutation self-check: with flannel.yaml's substitution step bypassed, __IFACE__ ships unresolved -- proving the resolved-value assertions above would fail if this substitution were ever reverted" \
    "$(grep -qF '__IFACE__' "$mutated_dest5/flannel.yaml" && echo 1 || echo 0)"
fi

# Case 6: kube-proxy.yaml's __KUBE_VERSION__/__IFACE_IP__
# placeholders must be resolved to install.sh's own real values on the way
# into the well-known folder -- a plain byte-for-byte copy (correct for every
# other manifest) would ship these tokens unresolved, and kube-proxy would
# pull a nonexistent image tag and point its kubeconfig at a bogus host.
stage6="$MANIFEST_WORK/stage6"
mkdir -p "$stage6/manifests"
printf '        image: registry.k8s.io/kube-proxy:v__KUBE_VERSION__\n        server: https://__IFACE_IP__:6443\n' \
  > "$stage6/manifests/kube-proxy.yaml"
dest6="$MANIFEST_WORK/dest6"
bash "$MANIFEST_RUNNER" "$stage6" "$dest6" 0 "eth0" "10.244.0.0/16" "1.99.9" "192.0.2.5"
assert_true "kube-proxy.yaml's __KUBE_VERSION__ placeholder is substituted with the bundled kubelet's own resolved version on the way into the well-known folder" \
  grep -qF 'image: registry.k8s.io/kube-proxy:v1.99.9' "$dest6/kube-proxy.yaml"
assert_true "kube-proxy.yaml's __IFACE_IP__ placeholder is substituted with the real advertised apiserver address on the way into the well-known folder" \
  grep -qF 'server: https://192.0.2.5:6443' "$dest6/kube-proxy.yaml"
assert_false "kube-proxy.yaml carries no unresolved __KUBE_VERSION__/__IFACE_IP__ token once it reaches the well-known folder apiserver auto-applies at boot" \
  grep -qE '__KUBE_VERSION__|__IFACE_IP__' "$dest6/kube-proxy.yaml"

# Mutation self-check (CLAUDE.md rule 14): prove the three assertions above
# would actually catch a reverted substitution step, not just document
# today's behavior.
MUTATED_KUBE_PROXY_SUB_INSTALL="$MANIFEST_WORK/install-mutated-kube-proxy-sub.sh"
sed 's/if \[ -f "\$dir\/kube-proxy.yaml" \]; then/if false; then/' "$INSTALL" \
  > "$MUTATED_KUBE_PROXY_SUB_INSTALL"
if diff -q "$INSTALL" "$MUTATED_KUBE_PROXY_SUB_INSTALL" > /dev/null 2>&1; then
  assert "mutation self-check: kube-proxy.yaml's substitution guard exists in install.sh to mutate (if this fails, the line was renamed/reshaped and this suite no longer exercises it)" 0
else
  MUTATED_KUBE_PROXY_SUB_RUNNER="$MANIFEST_WORK/manifest-copy-mutated-kube-proxy-sub.sh"
  write_manifest_copy_runner "$MUTATED_KUBE_PROXY_SUB_INSTALL" "$MUTATED_KUBE_PROXY_SUB_RUNNER"
  mutated_dest6="$MANIFEST_WORK/dest6-mutated"
  bash "$MUTATED_KUBE_PROXY_SUB_RUNNER" "$stage6" "$mutated_dest6" 0 "eth0" "10.244.0.0/16" "1.99.9" "192.0.2.5"
  assert "mutation self-check: with kube-proxy.yaml's substitution step bypassed, __KUBE_VERSION__ ships unresolved -- proving the resolved-value assertions above would fail if this substitution were ever reverted" \
    "$(grep -qF '__KUBE_VERSION__' "$mutated_dest6/kube-proxy.yaml" && echo 1 || echo 0)"
fi

# Case 7: the REAL manifests/beep.yaml run through install.sh's substitution
# must leave no placeholder token behind. An unresolved --pod-cidr makes beep
# reject every backend Pod, and an unresolved --uplink-iface leaves
# LoadBalancer traffic unadmitted -- both ship silently as Pending/dead VIPs.
BEEP_MANIFEST="$ROOT_DIR/manifests/beep.yaml"
stage7="$MANIFEST_WORK/stage7"
mkdir -p "$stage7/manifests"
cp "$BEEP_MANIFEST" "$stage7/manifests/beep.yaml"
dest7="$MANIFEST_WORK/dest7"
bash "$MANIFEST_RUNNER" "$stage7" "$dest7" 0 "enp0s9" "10.99.0.0/16"
assert_true "beep.yaml's --pod-cidr is substituted with install.sh's POD_CLUSTER_CIDR so it cannot drift from KCM's --cluster-cidr" \
  grep -qF -- '--pod-cidr=10.99.0.0/16' "$dest7/beep.yaml"
assert_true "beep.yaml's --uplink-iface is substituted with install.sh's resolved --iface so beep admits LoadBalancer traffic on the node's real NIC" \
  grep -qF -- '--uplink-iface=enp0s9' "$dest7/beep.yaml"
assert_false "beep.yaml carries no unresolved __IFACE__/__POD_CLUSTER_CIDR__ token once it reaches the well-known folder" \
  grep -qE '__[A-Z_]+__' "$dest7/beep.yaml"
assert "beep.yaml's images are all digest-pinned, not a floating tag (:latest would change the privileged node-prep image under a running cluster)" \
  "$([ "$(grep -E '^[[:space:]]+image: ' "$BEEP_MANIFEST" | grep -vc '@sha256:[0-9a-f]\{64\}$' || true)" = 0 ] && echo 1 || echo 0)"
MUTATED_BEEP_SUB_INSTALL="$MANIFEST_WORK/install-mutated-beep-sub.sh"
sed 's/if \[ -f "\$dir\/beep.yaml" \]; then/if false; then/' "$INSTALL" \
  > "$MUTATED_BEEP_SUB_INSTALL"
if diff -q "$INSTALL" "$MUTATED_BEEP_SUB_INSTALL" > /dev/null 2>&1; then
  assert "mutation self-check: beep.yaml's substitution guard exists in install.sh to mutate" 0
else
  MUTATED_BEEP_SUB_RUNNER="$MANIFEST_WORK/manifest-copy-mutated-beep-sub.sh"
  write_manifest_copy_runner "$MUTATED_BEEP_SUB_INSTALL" "$MUTATED_BEEP_SUB_RUNNER"
  bash "$MUTATED_BEEP_SUB_RUNNER" "$stage7" "$MANIFEST_WORK/dest7-mutated" 0 "enp0s9" "10.99.0.0/16"
  assert "mutation self-check: with beep.yaml's substitution bypassed, placeholders ship unresolved -- proving the assertions above fail if the substitution is reverted" \
    "$(grep -qF '__POD_CLUSTER_CIDR__' "$MANIFEST_WORK/dest7-mutated/beep.yaml" && echo 1 || echo 0)"
fi

# beep's eBPF dataplane needs kernel >= 6.6; installing on an older kernel
# would leave every LoadBalancer Service Pending with only a crash-looping
# DaemonSet pod to show for it, so the installer must refuse up front.
KERNEL_FN="$MANIFEST_WORK/kernel-fn.sh"
awk '/^kernel_supports_beep\(\) \{$/,/^\}$/' "$INSTALL" > "$KERNEL_FN"
assert_true "kernel_supports_beep is present in install.sh" test -s "$KERNEL_FN"
kernel_ok() { bash -c '. "$1"; kernel_supports_beep "$2"' _ "$KERNEL_FN" "$1"; }
assert_true "kernel 6.6.0 (the floor) is accepted" kernel_ok "6.6.0"
assert_true "kernel 6.8.0-31-generic is accepted (suffix ignored)" kernel_ok "6.8.0-31-generic"
assert_true "kernel 7.0.0-31 is accepted (a higher major beats a lower minor)" kernel_ok "7.0.0-31"
assert_false "kernel 6.5.13 is rejected" kernel_ok "6.5.13"
assert_false "kernel 5.15.0-100-generic is rejected (a high minor does not beat a lower major)" kernel_ok "5.15.0-100-generic"
assert_true "install.sh refuses to proceed when the kernel check fails" \
  grep -qF 'if ! kernel_supports_beep "$(uname -r)"; then' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: both migrations remove
# install.sh's own kubectl-apply heredocs entirely -- CoreDNS never had one
# (bootstrap_apply.rs applies its compiled-in bundle), and kube-proxy/Flannel
# now go through the same well-known-manifest-folder mechanism. If a future
# addon reintroduces this shape, that's a sign it should be a manifests/*.yaml
# file instead.
# ---------------------------------------------------------------------------
assert_false "(regression guard) install.sh no longer applies any manifest via an inline 'kubectl apply -f - <<EOF' heredoc" \
  grep -qF 'apply -f - <<EOF' "$INSTALL"

# ---------------------------------------------------------------------------
# Persisted install config ($STATE_DIR/config): IFACE/NODE_NAME feed into
# --advertise-address, which the apiserver embeds into every kubeconfig it
# rewrites (tls.rs). Regression this guards: a re-run with a different
# --iface used to silently rebake a different address into a live cluster,
# breaking any kubeconfig already distributed off-box. Operator
# decision (2026-08-26): refuse loudly on a mismatch rather than silently
# override or auto-wipe state -- deleting $CONFIG_FILE is the only escape
# hatch. Both the write step and the read-back+refusal logic are extracted
# verbatim from install.sh's own source, same approach as the other
# extractions in this file.
# ---------------------------------------------------------------------------

write_persist_config_write_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"'
    echo 'CONFIG_FILE="$STATE_DIR/config"'
    echo 'NODE_NAME="$2"'
    echo 'IFACE="$3"'
    echo 'WORKER_MODE=0; CLUSTER_DNS=10.96.0.10; SERVICE_CIDR=10.96.0.0/12; POD_CLUSTER_CIDR=10.244.0.0/16'
    awk 'prev == "{" && /NODE_NAME=/ {p=1; print prev} p {print} p && /^} > "\$CONFIG_FILE"$/ {exit} {prev=$0}' "$install_script"
  } > "$runner"
}

write_persist_config_check_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"'
    echo 'CONFIG_FILE="$STATE_DIR/config"'
    echo 'EXISTING_INSTALL="$2"'
    echo 'NODE_NAME="$3"'
    echo 'IFACE="$4"'
    awk '/^PERSISTED_NODE_NAME=""$/,/^# --- Network ranges: defaults/ { if ($0 !~ /^# --- Network ranges: defaults/) print }' "$install_script"
    echo 'echo "NODE_NAME=$NODE_NAME"'
    echo 'echo "IFACE=$IFACE"'
  } > "$runner"
}

PERSIST_WORK="$(mktemp -d)"
# Replaces the earlier EXIT traps above (only the latest fires), so it must
# still cover every dir those relied on cleaning up.
trap 'rm -rf "$DETECT_WORK" "$WORKER_MODE_WORK" "$MANIFEST_WORK" "$PERSIST_WORK"' EXIT
PERSIST_WRITE_RUNNER="$PERSIST_WORK/persist-write.sh"
PERSIST_CHECK_RUNNER="$PERSIST_WORK/persist-check.sh"
write_persist_config_write_runner "$INSTALL" "$PERSIST_WRITE_RUNNER"
write_persist_config_check_runner "$INSTALL" "$PERSIST_CHECK_RUNNER"

# Case 1: a fresh install writes the resolved node-name/iface to
# $STATE_DIR/config -- the write half of the contract; nothing to read back
# on the very next run without this.
fresh_write_dir="$PERSIST_WORK/fresh-write"
mkdir -p "$fresh_write_dir"
bash "$PERSIST_WRITE_RUNNER" "$fresh_write_dir" "node-a" "eth0"
assert_true "a fresh install persists the resolved node-name to \$STATE_DIR/config" \
  grep -qF 'NODE_NAME="node-a"' "$fresh_write_dir/config"
assert_true "a fresh install persists the resolved iface to \$STATE_DIR/config" \
  grep -qF 'IFACE="eth0"' "$fresh_write_dir/config"

# Case 2: an upgrade re-run with no --iface/--node-name flags (NODE_NAME/IFACE
# arrive empty, exactly as install.sh's own flag-parsing leaves them unset)
# must default to what a prior install persisted, not fall through to
# hostname/auto-detection as if this were a fresh box.
upgrade_no_flags_dir="$PERSIST_WORK/upgrade-no-flags"
mkdir -p "$upgrade_no_flags_dir"
{
  echo 'NODE_NAME="old-node"'
  echo 'IFACE="eth0"'
} > "$upgrade_no_flags_dir/config"
no_flags_out="$(bash "$PERSIST_CHECK_RUNNER" "$upgrade_no_flags_dir" 1 "" "" 2>&1)"
assert "an upgrade re-run with no --iface/--node-name defaults both to the values persisted at install time, instead of recomputing a fresh hostname/auto-detected interface" \
  "$(printf '%s' "$no_flags_out" | grep -q '^NODE_NAME=old-node$' && printf '%s' "$no_flags_out" | grep -q '^IFACE=eth0$' && echo 1 || echo 0)"

# Case 3: an upgrade re-run with an explicit --iface that DISAGREES with the
# persisted value must refuse loudly and exit non-zero, naming $CONFIG_FILE
# as the file to delete -- the acceptance criterion this bead exists for.
# Silently overriding here is exactly what would rebake a different
# --advertise-address into a live cluster, breaking any kubeconfig already
# distributed off-box.
upgrade_mismatch_dir="$PERSIST_WORK/upgrade-mismatch"
mkdir -p "$upgrade_mismatch_dir"
{
  echo 'NODE_NAME="node-a"'
  echo 'IFACE="eth0"'
} > "$upgrade_mismatch_dir/config"
mismatch_status=0
mismatch_out="$(bash "$PERSIST_CHECK_RUNNER" "$upgrade_mismatch_dir" 1 "node-a" "eth1" 2>&1)" || mismatch_status=$?
assert "an upgrade with a --iface that disagrees with the persisted value is refused loudly (non-zero exit, mentions the persisted 'eth0'), instead of silently rebaking a new --advertise-address into a live cluster" \
  "$([ "$mismatch_status" -ne 0 ] && printf '%s' "$mismatch_out" | grep -qi 'conflicts' && printf '%s' "$mismatch_out" | grep -q 'eth0' && echo 1 || echo 0)"
assert "the --iface mismatch refusal names the exact file to delete (\$STATE_DIR/config), per the operator's decision that this is the only escape hatch (no override flag)" \
  "$(printf '%s' "$mismatch_out" | grep -qF "$upgrade_mismatch_dir/config" && echo 1 || echo 0)"

# Case 3b: the same guard on --node-name -- a distinct if-block in
# install.sh, not exercised by the --iface case above.
upgrade_name_mismatch_dir="$PERSIST_WORK/upgrade-name-mismatch"
mkdir -p "$upgrade_name_mismatch_dir"
{
  echo 'NODE_NAME="node-a"'
  echo 'IFACE="eth0"'
} > "$upgrade_name_mismatch_dir/config"
name_mismatch_status=0
name_mismatch_out="$(bash "$PERSIST_CHECK_RUNNER" "$upgrade_name_mismatch_dir" 1 "node-b" "eth0" 2>&1)" || name_mismatch_status=$?
assert "an upgrade with a --node-name that disagrees with the persisted value is refused loudly (non-zero exit, mentions the persisted 'node-a'), instead of silently rebaking a new kubelet --hostname-override into a live cluster" \
  "$([ "$name_mismatch_status" -ne 0 ] && printf '%s' "$name_mismatch_out" | grep -qi 'conflicts' && printf '%s' "$name_mismatch_out" | grep -q 'node-a' && echo 1 || echo 0)"

# Case 4: an upgrade re-run with an explicit --iface that MATCHES the
# persisted value is not a real mismatch -- it must proceed normally, or
# every upgrade script that always passes --iface explicitly (rather than
# relying on the env-var/no-flags convention) would be refused every time.
upgrade_match_dir="$PERSIST_WORK/upgrade-match"
mkdir -p "$upgrade_match_dir"
{
  echo 'NODE_NAME="node-a"'
  echo 'IFACE="eth0"'
} > "$upgrade_match_dir/config"
match_out="$(bash "$PERSIST_CHECK_RUNNER" "$upgrade_match_dir" 1 "node-a" "eth0" 2>&1)"
assert "an upgrade with an explicit --iface/--node-name that MATCHES the persisted value proceeds normally -- the guard only fires on a genuine mismatch, not on any explicit flag" \
  "$(printf '%s' "$match_out" | grep -q '^NODE_NAME=node-a$' && printf '%s' "$match_out" | grep -q '^IFACE=eth0$' && echo 1 || echo 0)"

# Case 5: a genuinely fresh install (EXISTING_INSTALL=0, no persisted config
# file at all) must never trigger the mismatch guard, even with explicit
# flags passed -- this guard is upgrade-only.
fresh_install_dir="$PERSIST_WORK/fresh-install"
mkdir -p "$fresh_install_dir"
fresh_install_out="$(bash "$PERSIST_CHECK_RUNNER" "$fresh_install_dir" 0 "node-a" "eth0" 2>&1)"
assert "a genuinely fresh install (no persisted config, EXISTING_INSTALL=0) never trips the mismatch guard, even with explicit --iface/--node-name flags -- the guard is upgrade-only" \
  "$(printf '%s' "$fresh_install_out" | grep -q '^NODE_NAME=node-a$' && printf '%s' "$fresh_install_out" | grep -q '^IFACE=eth0$' && echo 1 || echo 0)"

# Case 6: a host named with capitals (the release-gate VMs are
# u7s-rg-<stamp with T/Z>) must still install. The kubelet CSR name and the
# CSR subject CN are derived from NODE_NAME and the apiserver rejects any
# uppercase in them, so NODE_NAME must be lowercased like upstream kubelet's
# GetHostname, for both the explicit override and the hostname default.
UPPER_HOST="U7S-RG-20261021T053138Z-1"
LOWER_HOST="u7s-rg-20261021t053138z-1"
upper_runner="$PERSIST_WORK/upper-name.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo 'STATE_DIR="$1"; CONFIG_FILE="$STATE_DIR/config"; EXISTING_INSTALL="${3:-0}"'
  echo 'NODE_NAME="$2"; IFACE=eth0'
  echo "hostname() { echo \"  $UPPER_HOST\"; }"
  awk '/^PERSISTED_NODE_NAME=""$/,/^# --- Network ranges: defaults/ { if ($0 !~ /^# --- Network ranges: defaults/) print }' "$INSTALL"
  awk '/^# --- Defaults: node name/{f=1} f{print} f&&/^fi$/{exit}' "$INSTALL"
  echo 'echo "NODE_NAME=$NODE_NAME"'
} > "$upper_runner"
mkdir -p "$PERSIST_WORK/upper"
upper_default_out="$(bash "$upper_runner" "$PERSIST_WORK/upper" "" 2>&1)"
assert "a host named with capitals still gets a lowercase, trimmed node name from hostname (otherwise the kubelet CSR name is invalid and install fails)" \
  "$(printf '%s' "$upper_default_out" | grep -qx "NODE_NAME=$LOWER_HOST" && echo 1 || echo 0)"
upper_flag_out="$(bash "$upper_runner" "$PERSIST_WORK/upper" "$UPPER_HOST" 2>&1)"
assert "an uppercase --node-name is lowercased too, so an explicit override cannot produce an invalid CSR name" \
  "$(printf '%s' "$upper_flag_out" | grep -qx "NODE_NAME=$LOWER_HOST" && echo 1 || echo 0)"
# A host that already hit the uppercase bug persisted the uppercase name (config
# is written before the kubelet identity CSR fails). It must recover by simply
# re-running install, with or without a lowercase --node-name.
mkdir -p "$PERSIST_WORK/upper-persisted"
printf 'NODE_NAME="%s"\nIFACE="eth0"\n' "$UPPER_HOST" > "$PERSIST_WORK/upper-persisted/config"
recover_noflag_out="$(bash "$upper_runner" "$PERSIST_WORK/upper-persisted" "" 1 2>&1 || true)"
assert "a persisted UPPERCASE node name is lowercased on re-run with no flag (otherwise a host broken by the uppercase bug fails the same way forever)" \
  "$(printf '%s' "$recover_noflag_out" | grep -qx "NODE_NAME=$LOWER_HOST" && echo 1 || echo 0)"
recover_flag_out="$(bash "$upper_runner" "$PERSIST_WORK/upper-persisted" "$LOWER_HOST" 1 2>&1 || true)"
assert "a lowercase --node-name does not conflict with the persisted uppercase spelling of the same name (operator can recover by passing the fix explicitly)" \
  "$(printf '%s' "$recover_flag_out" | grep -qx "NODE_NAME=$LOWER_HOST" && ! printf '%s' "$recover_flag_out" | grep -q 'conflicts with the node name persisted' && echo 1 || echo 0)"
for csr_fmt in 'join-%s-1' 'kubelet-%s-1'; do
  # shellcheck disable=SC2059
  csr_name="$(printf "$csr_fmt" "$(printf '%s' "$upper_default_out" | sed -n 's/^NODE_NAME=//p')")"
  assert "the CSR name $csr_name built from a capitalised host is a valid DNS-1123 name (apiserver rejects uppercase)" \
    "$(printf '%s' "$csr_name" | grep -Eq '^[a-z0-9.-]+$' && echo 1 || echo 0)"
done
assert_true "the join CSR name is built from NODE_NAME (so the lowercasing reaches it)" \
  grep -qF 'csr_name="join-${NODE_NAME}-$(date +%s)"' "$INSTALL"
assert_true "the control-plane kubelet CSR name is built from NODE_NAME (so the lowercasing reaches it)" \
  grep -qF 'csr_name="kubelet-${NODE_NAME}-$(date +%s)"' "$INSTALL"
assert_true "the CSR subject CN uses NODE_NAME, so it is the lowercase system:node:<name> the node authorizer expects" \
  grep -qF -- '-subj "/O=system:nodes/CN=system:node:$NODE_NAME"' "$INSTALL"

# Case 6a: a GCP FQDN hostname (<name>.c.<project>.internal) can push the
# identity CN past X.509's 64 chars, which openssl req refuses mid-install.
# install.sh must refuse up front, at the node-name default, with a clear error.
long_runner="$PERSIST_WORK/long-name.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo 'NODE_NAME="$1"; IFACE=eth0'
  awk '/^# --- Defaults: node name/{f=1} f&&/^if \[ -z "\$IFACE" \]/{exit} f{print}' "$INSTALL"
  echo 'echo "NODE_NAME=$NODE_NAME"'
} > "$long_runner"
LONG_NAME="$(printf 'a%.0s' $(seq 1 53))"
OK_NAME="$(printf 'a%.0s' $(seq 1 52))"
long_rc=0
long_out="$(bash "$long_runner" "$LONG_NAME" 2>&1)" || long_rc=$?
assert "a 53-char node name (CN 65 chars) is refused with a message naming the 64-char limit, instead of failing later inside openssl req" \
  "$([ "$long_rc" -ne 0 ] && printf '%s' "$long_out" | grep -q '64-char' && echo 1 || echo 0)"
ok_out="$(bash "$long_runner" "$OK_NAME" 2>&1 || true)"
assert "a 52-char node name (CN exactly 64 chars) is accepted -- the guard must not reject names openssl can sign" \
  "$(printf '%s' "$ok_out" | grep -qx "NODE_NAME=$OK_NAME" && echo 1 || echo 0)"
cn_ok="$(openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /dev/null -subj "/O=system:nodes/CN=system:node:$OK_NAME" 2>&1 >/dev/null || true)"
assert "openssl really signs a 64-char CN (so the 52-char bound is not needlessly strict)" \
  "$(printf '%s' "$cn_ok" | grep -q 'too long' && echo 0 || echo 1)"

# Case 6b: the control-plane Node must carry node-role.kubernetes.io/control-plane
# (empty value) like kubeadm's mark-control-plane. The kubelet cannot label
# itself under NodeRestriction, so install.sh does it with the admin kubeconfig.
LABEL_WORK="$PERSIST_WORK/label"
mkdir -p "$LABEL_WORK"
label_runner="$LABEL_WORK/label.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo 'STATE_DIR="$1"; NODE_NAME="$2"'
  echo 'sleep() { :; }'
  echo 'kubectl() { echo "$*" >> "$STATE_DIR/kubectl.log"; if [ -f "$STATE_DIR/kubectl-fail" ]; then echo "nodes \"$NODE_NAME\" not found" >&2; return 1; fi; }'
  awk '/^label_control_plane_node\(\) \{/{f=1} f{print} f&&/^}$/{exit}' "$INSTALL"
  echo 'label_control_plane_node'
} > "$label_runner"
label_ok_out="$(bash "$label_runner" "$LABEL_WORK" "$LOWER_HOST" 2>&1 || true)"
assert "install labels the lowercase Node with node-role.kubernetes.io/control-plane= via the admin kubeconfig (otherwise tooling that selects control-plane nodes by this label finds none, and kubectl get nodes shows no ROLES)" \
  "$(grep -qxF -- "--kubeconfig=$LABEL_WORK/kubeconfig label node $LOWER_HOST --overwrite node-role.kubernetes.io/control-plane=" "$LABEL_WORK/kubectl.log" && echo 1 || echo 0)"
assert "labelling uses --overwrite so an install.sh re-run on a labelled Node is a no-op instead of an error" \
  "$(grep -qF -- '--overwrite' "$LABEL_WORK/kubectl.log" && echo 1 || echo 0)"
assert "labelling reports success on the happy path" \
  "$(printf '%s' "$label_ok_out" | grep -q 'labelled node-role.kubernetes.io/control-plane' && echo 1 || echo 0)"
assert_false "install does not add a control-plane NoSchedule taint (u7s is single-node-first; workloads must schedule on the only node)" \
  grep -qE 'kubectl.*taint|NoSchedule' <(awk '/^label_control_plane_node\(\) \{/{f=1} f&&!/^#/{print} f&&/^}$/{exit}' "$INSTALL")
touch "$LABEL_WORK/kubectl-fail"
if bash "$label_runner" "$LABEL_WORK" "$LOWER_HOST" > "$LABEL_WORK/fail.out" 2>&1; then
  assert "a Node that never accepts the label fails the install loudly (silent success would leave no control-plane-labelled Node)" 0
else
  assert "a Node that never accepts the label fails the install loudly (silent success would leave no control-plane-labelled Node)" \
    "$(grep -q 'could not label node' "$LABEL_WORK/fail.out" && echo 1 || echo 0)"
fi
assert "the control-plane install path calls label_control_plane_node exactly once, and join_cluster does not (joined workers must not carry the control-plane role)" \
  "$([ "$(grep -c '^label_control_plane_node || exit 1$' "$INSTALL")" = 1 ] && ! awk '/^join_cluster\(\) \{/{f=1} f{print} f&&/^}$/{exit}' "$INSTALL" | grep -q label_control_plane_node && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Mutation self-check (CLAUDE.md rule 14): prove the --iface refusal assertion
# above would actually catch a reverted fix. Bypass the guard in a scratch
# copy of install.sh and rerun the exact mismatch scenario -- if the guard is
# gone, the mismatched --iface must instead win silently (IFACE=eth1 printed,
# no refusal), which is precisely the silent-override behavior the operator
# rejected in favor of refuse-loud.
# ---------------------------------------------------------------------------
MUTATED_PERSIST_INSTALL="$PERSIST_WORK/install-mutated.sh"
sed 's/elif \[ "\$IFACE" != "\$PERSISTED_IFACE" \]; then/elif false; then/' "$INSTALL" > "$MUTATED_PERSIST_INSTALL"
if diff -q "$INSTALL" "$MUTATED_PERSIST_INSTALL" > /dev/null 2>&1; then
  assert "mutation self-check: the --iface mismatch guard's condition line exists in install.sh to mutate (if this fails, the line was renamed/reshaped and this suite no longer exercises it)" 0
else
  MUTATED_PERSIST_RUNNER="$PERSIST_WORK/persist-check-mutated.sh"
  write_persist_config_check_runner "$MUTATED_PERSIST_INSTALL" "$MUTATED_PERSIST_RUNNER"
  mutated_persist_status=0
  mutated_persist_out="$(bash "$MUTATED_PERSIST_RUNNER" "$upgrade_mismatch_dir" 1 "node-a" "eth1" 2>&1)" || mutated_persist_status=$?
  assert "mutation self-check: with the --iface mismatch guard bypassed, a disagreeing --iface is wrongly allowed to silently win -- proving the refusal test above would fail if this fix were ever reverted" \
    "$([ "$mutated_persist_status" -eq 0 ] && printf '%s' "$mutated_persist_out" | grep -q '^IFACE=eth1$' && echo 1 || echo 0)"
fi

# ---------------------------------------------------------------------------
# kubelet resolvConf: "" gives dnsPolicy Default pods (CoreDNS) nameserver
# 127.0.0.1, so CoreDNS forwards every external query to itself. kubeadm's
# rule: systemd-resolved active -> its non-stub file, else /etc/resolv.conf.
# ---------------------------------------------------------------------------
RESOLV_WORK="$(mktemp -d)"
trap 'rm -rf "$DETECT_WORK" "$WORKER_MODE_WORK" "$MANIFEST_WORK" "$PERSIST_WORK" "$RESOLV_WORK"' EXIT
mkdir -p "$RESOLV_WORK/bin-active" "$RESOLV_WORK/bin-inactive"
printf '#!/bin/sh\nexit 0\n' > "$RESOLV_WORK/bin-active/systemctl"
printf '#!/bin/sh\nexit 3\n' > "$RESOLV_WORK/bin-inactive/systemctl"
chmod +x "$RESOLV_WORK/bin-active/systemctl" "$RESOLV_WORK/bin-inactive/systemctl"
{
  echo 'STATE_DIR="$1"'
  awk '/^write_kubelet_config_yaml\(\) \{$/,/^}$/' "$INSTALL"
  echo 'write_kubelet_config_yaml'
} > "$RESOLV_WORK/runner.sh"
mkdir -p "$RESOLV_WORK/out-active" "$RESOLV_WORK/out-inactive"
PATH="$RESOLV_WORK/bin-active:$PATH" bash "$RESOLV_WORK/runner.sh" "$RESOLV_WORK/out-active"
PATH="$RESOLV_WORK/bin-inactive:$PATH" bash "$RESOLV_WORK/runner.sh" "$RESOLV_WORK/out-inactive"
assert_true "with systemd-resolved active, kubelet resolvConf is its non-stub file so pods (and CoreDNS) get the real upstream, not the 127.0.0.53 stub" \
  grep -qxF 'resolvConf: /run/systemd/resolve/resolv.conf' "$RESOLV_WORK/out-active/kubelet-config.yaml"
assert_true "without systemd-resolved, kubelet resolvConf is /etc/resolv.conf (already the real upstream list)" \
  grep -qxF 'resolvConf: /etc/resolv.conf' "$RESOLV_WORK/out-inactive/kubelet-config.yaml"
assert_false "kubelet resolvConf must never be empty: CoreDNS would get nameserver 127.0.0.1 and forward queries to itself" \
  grep -qxF 'resolvConf: ""' "$RESOLV_WORK/out-active/kubelet-config.yaml" "$RESOLV_WORK/out-inactive/kubelet-config.yaml"

COREDNS_MANIFEST="$ROOT_DIR/manifests/coredns.yaml"
assert_true "CoreDNS forward block caps max_concurrent so a loop or upstream stall cannot spawn unbounded goroutines (OOM)" \
  awk '/forward \. \/etc\/resolv.conf \{/{f=1} f&&/max_concurrent 1000/{ok=1} /\}/{f=0} END{exit !ok}' "$COREDNS_MANIFEST"
assert_true "CoreDNS Corefile keeps the loop plugin (kubeadm default) so a self-forward config fails loudly instead of silently melting down" \
  awk '/^  Corefile: \|/{f=1; next} f&&/^[^ ]|^  [^ ]/{f=0} f&&/^ +loop$/{ok=1} END{exit !ok}' "$COREDNS_MANIFEST"

SET_RC="$ROOT_DIR/scripts/set-kubelet-resolvconf.sh"
printf 'address: 0.0.0.0\nresolvConf: ""\n' > "$RESOLV_WORK/kc-ok.yaml"
printf 'address: 0.0.0.0\n' > "$RESOLV_WORK/kc-missing.yaml"
assert_true "set-kubelet-resolvconf rewrites an existing resolvConf line so a golden image baked with \"\" stops self-forwarding" \
  bash -c 'PATH="$1/bin-inactive:$PATH" "$2" "$1/kc-ok.yaml" && grep -qxF "resolvConf: /etc/resolv.conf" "$1/kc-ok.yaml"' _ "$RESOLV_WORK" "$SET_RC"
assert_false "set-kubelet-resolvconf must exit non-zero when the config has no resolvConf line, else the sed no-ops silently and CoreDNS self-forwards" \
  env PATH="$RESOLV_WORK/bin-inactive:$PATH" "$SET_RC" "$RESOLV_WORK/kc-missing.yaml"

assert_false "install.sh unquoted heredoc bodies must not contain backticks: bash command-substitutes them and prints 'command not found' at install time" \
  awk '/<<-?[A-Za-z_]+$/{h=1; next} /^EOF$/{h=0} h&&/`/{bad=1} END{exit !bad}' "$INSTALL"

# Release payload scratch dirs must be disk-backed: on Ubuntu 26.04 /tmp is
# tmpfs, so extracting the tarball there OOMs the 1 GiB hosts u7s targets.
# Only discover_cluster_ca's small, public cluster-info scratch dir may stay on
# plain mktemp.
assert_true "install.sh payload dirs (download + stage) use mktemp_disk_dir, not tmpfs-backed mktemp -d, or install OOMs on 1 GiB hosts" \
  bash -c 'test "$(grep -c "mktemp -d" "$1")" -eq 2 && grep -q "DOWNLOAD_DIR=\"\$(mktemp_disk_dir)\"" "$1" && grep -q "STAGE_DIR=\"\$(mktemp_disk_dir)\"" "$1"' _ "$INSTALL"
MKDISK_RUNNER="$(mktemp)"
{
  echo 'set -euo pipefail'
  awk '/^mktemp_disk_dir\(\) \{/,/^\}/' "$INSTALL"
  echo 'd="$(mktemp_disk_dir)"; trap "rm -rf $d" EXIT; findmnt -n -o FSTYPE -T "$d"'
} > "$MKDISK_RUNNER"
if command -v findmnt >/dev/null 2>&1 && [ -d /var/tmp ]; then
  assert_false "mktemp_disk_dir must not return a tmpfs/ramfs path (RAM-backed extraction OOMs 1 GiB hosts)" \
    bash -c 'bash "$1" | grep -qE "^(tmpfs|ramfs)$"' _ "$MKDISK_RUNNER"
fi
rm -f "$MKDISK_RUNNER"

# ---------------------------------------------------------------------------
# Join tokens: Secret-backed, 24h, minted without an apiserver restart; the
# joiner discovers the CA through cluster-info (JWS + SPKI hash pin) and never
# receives or sends a private key. Functions are extracted from install.sh's
# own source and run against stubbed kubectl/curl, with GNU-only base64 -w0 and
# date -d shimmed so the logic runs on a macOS host too.
# ---------------------------------------------------------------------------
JOIN_WORK="$(mktemp -d)"
trap 'rm -rf "$DETECT_WORK" "$WORKER_MODE_WORK" "$JOIN_WORK"' EXIT

write_join_runner() {
  local runner="$1" body="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"; JOIN_SERVER="https://cp.example:6443"; CA_CERT_HASH="${CA_CERT_HASH:-}"; JOIN_TOKEN="${JOIN_TOKEN:-}"'
    echo 'base64() { local a=() x; if ! command base64 -w0 </dev/null >/dev/null 2>&1; then for x in "$@"; do [ "$x" = -w0 ] || a+=("$x"); done; set -- ${a[@]+"${a[@]}"}; fi; command base64 "$@"; }'
    echo 'date() { if [ "$1" = -u ] && [ "$2" = -d ] && ! command date -u -d @0 +%s >/dev/null 2>&1; then command date -u -r "${3#@}" "${@:4}"; else command date "$@"; fi; }'
    echo 'sleep() { :; }'
    echo 'ensure_jq() { :; }'
    echo 'CONFIG_FILE="$STATE_DIR/config"; DEFAULT_SERVICE_CIDR=10.96.0.0/12'
    grep '^JOIN_TOKEN_TTL_SECONDS=' "$INSTALL"
    for fn in ipv4_to_int int_to_ipv4 parse_cidr default_cluster_dns issue_cp_kubelet_identity current_client_cert wait_for_joined_node b64url hmac_pad hmac_sha256 discover_cluster_ca read_join_token mint_join_token; do
      awk "/^${fn}\\(\\) \\{/,/^\\}/" "$INSTALL"
    done
    echo "$body"
  } > "$runner"
}

JOIN_CA_DIR="$JOIN_WORK/cp-state"
mkdir -p "$JOIN_CA_DIR"
openssl ecparam -name prime256v1 -genkey -noout -out "$JOIN_WORK/ca.key"
openssl req -x509 -new -key "$JOIN_WORK/ca.key" -subj "/CN=u7s-test-ca" -days 2 -out "$JOIN_CA_DIR/ca.pem" 2>/dev/null
touch "$JOIN_CA_DIR/kubeconfig"
EXPECTED_CA_HASH="sha256:$(openssl x509 -in "$JOIN_CA_DIR/ca.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 | sed 's/^.* //')"

MINT_RUNNER="$JOIN_WORK/mint.sh"
write_join_runner "$MINT_RUNNER" '
kubectl() {
  printf "%s\n" "$*" >> "$STATE_DIR/kubectl-argv"
  case "$*" in
    *"config view"*) printf "https://cp.example:6443" ;;
    *"create -f -"*) cat > "$STATE_DIR/created-secret.json" ;;
  esac
}
systemctl() { echo "$*" >> "$STATE_DIR/systemctl-calls"; }
mint_join_token'
mint_out="$(bash "$MINT_RUNNER" "$JOIN_CA_DIR" 2>&1)" || {
  echo "FAIL: mint runner crashed, so no mint assertion can run: $mint_out"
  exit 1
}
SECRET_JSON="$JOIN_CA_DIR/created-secret.json"
mint_field() { jq -r ".stringData[\"$1\"]" "$SECRET_JSON"; }

assert "a default-DNS cluster's join command carries no --cluster-dns" \
  "$(printf '%s' "$mint_out" | grep -qF -- '--cluster-dns' && echo 0 || echo 1)"
JOIN_CA_DIR_K3S="$JOIN_WORK/cp-state-k3s"
cp -R "$JOIN_CA_DIR" "$JOIN_CA_DIR_K3S"
echo 'CLUSTER_DNS="10.43.0.10"' > "$JOIN_CA_DIR_K3S/config"
mint_k3s_out="$(bash "$MINT_RUNNER" "$JOIN_CA_DIR_K3S" 2>&1)"
assert "a non-default-DNS cluster's join command carries --cluster-dns, else the worker's kubelet would resolve via the default VIP and pods on it lose DNS" \
  "$(printf '%s' "$mint_k3s_out" | grep -qF -- '--cluster-dns 10.43.0.10' && echo 1 || echo 0)"

assert "mint creates a bootstrap.kubernetes.io/token Secret named bootstrap-token-<id> in kube-system -- the type and name are what the apiserver authenticator, tokencleaner and bootstrapsigner key on, so a wrong shape means a minted token no node can use" \
  "$([ "$(jq -r .type "$SECRET_JSON")" = bootstrap.kubernetes.io/token ] && [ "$(jq -r .metadata.namespace "$SECRET_JSON")" = kube-system ] && [ "$(jq -r .metadata.name "$SECRET_JSON")" = "bootstrap-token-$(mint_field token-id)" ] && echo 1 || echo 0)"
assert "mint enables authentication AND signing usage -- without signing the joiner cannot verify cluster-info, without authentication the token is rejected" \
  "$([ "$(mint_field usage-bootstrap-authentication)" = true ] && [ "$(mint_field usage-bootstrap-signing)" = true ] && echo 1 || echo 0)"
exp_epoch="$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$(mint_field expiration)" +%s 2>/dev/null || date -u -d "$(mint_field expiration)" +%s)"
now_epoch="$(date +%s)"
assert "mint sets expiration to now+24h (a leaked, never-used join token must stop working by itself within a day)" \
  "$([ "$exp_epoch" -ge $(( now_epoch + 86400 - 120 )) ] && [ "$exp_epoch" -le $(( now_epoch + 86400 + 120 )) ] && echo 1 || echo 0)"
assert "mint never restarts the apiserver (a restart drops every in-flight request cluster-wide for each node added)" \
  "$([ ! -e "$JOIN_CA_DIR/systemctl-calls" ] && echo 1 || echo 0)"
assert "mint writes no static token-auth-file (a file entry never expires and is never consumed, so a leaked token would join nodes forever)" \
  "$([ ! -e "$JOIN_CA_DIR/token-auth-file" ] && echo 1 || echo 0)"
assert "mint passes the Secret to kubectl on stdin, never argv (token secret visible to every local user via ps otherwise)" \
  "$(grep -qF "$(mint_field token-secret)" "$JOIN_CA_DIR/kubectl-argv" && echo 0 || echo 1)"
mint_token="$(mint_field token-id).$(mint_field token-secret)"
assert "mint prints the CA pin matching the cluster CA's SPKI hash in the join command, so the operator never has to compute it" \
  "$(printf '%s' "$mint_out" | grep -qF -- "--ca-cert-hash $EXPECTED_CA_HASH" && echo 1 || echo 0)"
assert "the printed join command carries no token (a token in the command line lands in shell history and ps); the token is printed once, separately" \
  "$(printf '%s\n' "$mint_out" | grep -F 'install.sh --join' | grep -qF "$mint_token" && echo 0 || { printf '%s' "$mint_out" | grep -qF "$mint_token" && echo 1 || echo 0; })"
assert_false "install.sh no longer passes --token-auth-file to the apiserver unit (static tokens survive restarts forever and cannot be revoked without editing a file)" \
  grep -q -- '--token-auth-file \$STATE_DIR' "$INSTALL"
assert_false "no join artifact exists any more: nothing in install.sh packs a serving private key into a base64(JSON) blob passed on a command line" \
  grep -qE 'servingKey|artifact' "$INSTALL"
assert_false "the join script no longer generates a serving key/CSR or asks an operator to approve one: the approver checks SANs against the Node, which only exists after the kubelet starts, so a pre-start CSR deadlocks the join" \
  grep -qE 'request_serving_cert|join-serving|certificate approve' "$INSTALL"

# Worker kubelet config: serverTLSBootstrap and no static serving cert; the
# control-plane kubelet keeps its minted cert.
WORKER_CFG_RUNNER="$JOIN_WORK/cfg.sh"
{
  echo 'STATE_DIR="$1"'
  echo 'systemctl() { return 3; }'
  awk '/^write_kubelet_config_yaml\(\) \{$/,/^}$/' "$INSTALL"
  echo 'write_kubelet_config_yaml'
} > "$WORKER_CFG_RUNNER"
mkdir -p "$JOIN_WORK/cfg-worker" "$JOIN_WORK/cfg-cp"
bash "$WORKER_CFG_RUNNER" "$JOIN_WORK/cfg-worker" 1
bash "$WORKER_CFG_RUNNER" "$JOIN_WORK/cfg-cp" 0
assert_true "a worker's kubelet sets serverTLSBootstrap so it files its own serving CSR once registered (the join cannot request one before the Node exists)" \
  grep -qxF 'serverTLSBootstrap: true' "$JOIN_WORK/cfg-worker/kubelet-config.yaml"
assert_false "a worker's kubelet config has no tlsCertFile/tlsPrivateKeyFile (a missing file stops the kubelet from starting, and a stale one would be served instead of the issued cert)" \
  grep -qE '^tls(Cert|PrivateKey)File:' "$JOIN_WORK/cfg-worker/kubelet-config.yaml"
assert_true "the control-plane kubelet also requests its serving cert by CSR (a static file is never renewed, so kubectl logs/exec would die when it expires)" \
  grep -qxF 'serverTLSBootstrap: true' "$JOIN_WORK/cfg-cp/kubelet-config.yaml"
assert_false "the control-plane kubelet config has no static tlsCertFile/tlsPrivateKeyFile" \
  grep -qE '^tls(Cert|PrivateKey)File:' "$JOIN_WORK/cfg-cp/kubelet-config.yaml"
assert_true "the control-plane kubelet rotates its own client cert (a node identity that never renews is a time bomb at cert expiry)" \
  grep -qxF 'rotateCertificates: true' "$JOIN_WORK/cfg-cp/kubelet-config.yaml"

# ---------------------------------------------------------------------------
# A compromised control-plane kubelet must not be cluster-admin: it runs on its
# own system:node:<name> client cert, never the admin kubeconfig, so the Node
# authorizer / NodeRestriction apply to it.
# ---------------------------------------------------------------------------
assert_false "the control-plane kubelet.service must not be handed the admin kubeconfig (system:masters would bypass the Node authorizer and NodeRestriction, and the admin cert never rotates)" \
  grep -qF -- '--kubeconfig=$STATE_DIR/kubeconfig' <<<"$kubelet_cp_block"
assert_true "the control-plane kubelet.service uses the dedicated node kubeconfig" \
  grep -qF -- '--kubeconfig=$STATE_DIR/kubelet-kubeconfig' <<<"$kubelet_cp_block"

CPID_DIR="$JOIN_WORK/cp-identity"
mkdir -p "$CPID_DIR"
cp "$JOIN_CA_DIR/ca.pem" "$CPID_DIR/ca.pem"
touch "$CPID_DIR/kubeconfig"
CPID_RUNNER="$JOIN_WORK/cpid.sh"
write_join_runner "$CPID_RUNNER" '
NODE_NAME=cp1
kubectl() {
  printf "%s\n" "$*" >> "$STATE_DIR/kubectl-argv"
  case "$*" in
    *"config view"*) printf "https://cp.example:6443" ;;
    *"create -f -"*) cat > "$STATE_DIR/created-csr.json" ;;
    *"get csr"*)
      jq -r .spec.request "$STATE_DIR/created-csr.json" | command base64 -d > "$STATE_DIR/stub.csr"
      openssl x509 -req -in "$STATE_DIR/stub.csr" -CA "$STATE_DIR/ca.pem" -CAkey "$CPID_CA_KEY" -CAcreateserial -days 1 -out "$STATE_DIR/stub.crt" 2>/dev/null
      command base64 < "$STATE_DIR/stub.crt" | tr -d "\n" ;;
  esac
}
issue_cp_kubelet_identity'
cpid_out="$(CPID_CA_KEY="$JOIN_WORK/ca.key" bash "$CPID_RUNNER" "$CPID_DIR" 2>&1)" || {
  echo "FAIL: control-plane identity runner crashed: $cpid_out"
  exit 1
}
cpid_csr_subject="$(openssl req -in "$CPID_DIR/stub.csr" -noout -subject 2>/dev/null)"
assert "the control-plane kubelet CSR asks for CN=system:node:<name> in O=system:nodes (the identity the Node authorizer recognises)" \
  "$(printf '%s' "$cpid_csr_subject" | grep -q 'system:node:cp1' && printf '%s' "$cpid_csr_subject" | grep -q 'system:nodes' && echo 1 || echo 0)"
assert "the control-plane kubelet CSR uses the kubelet-client signer, the only one csrapproving auto-approves for nodes" \
  "$([ "$(jq -r .spec.signerName "$CPID_DIR/created-csr.json")" = kubernetes.io/kube-apiserver-client-kubelet ] && echo 1 || echo 0)"
assert "the node kubeconfig points at the issued kubelet client cert/key, not the admin cert" \
  "$(grep -qF "client-certificate: $CPID_DIR/kubelet-client.crt" "$CPID_DIR/kubelet-kubeconfig" && ! grep -q 'admin' "$CPID_DIR/kubelet-kubeconfig" && echo 1 || echo 0)"
assert "the node kubeconfig is not world-readable (it holds a node credential)" \
  "$([ "$(stat -c %a "$CPID_DIR/kubelet-kubeconfig" 2>/dev/null || stat -f %Lp "$CPID_DIR/kubelet-kubeconfig")" = 600 ] && echo 1 || echo 0)"
cpid_csr_before="$(grep -c 'create -f -' "$CPID_DIR/kubectl-argv")"
CPID_CA_KEY="$JOIN_WORK/ca.key" bash "$CPID_RUNNER" "$CPID_DIR" >/dev/null 2>&1 || true
assert "a re-run keeps the existing valid identity instead of issuing another CSR (kubelet may already have rotated it)" \
  "$([ "$(grep -c 'create -f -' "$CPID_DIR/kubectl-argv")" -eq "$cpid_csr_before" ] && echo 1 || echo 0)"
openssl req -x509 -new -key "$CPID_DIR/kubelet-client.key" -subj "/CN=old-ca-issued" -days 30 -out "$CPID_DIR/kubelet-client.crt" 2>/dev/null
CPID_CA_KEY="$JOIN_WORK/ca.key" bash "$CPID_RUNNER" "$CPID_DIR" >/dev/null 2>&1 || true
assert "a re-run re-issues the identity when the stored cert does not chain to the current CA (a restored/reset CA would otherwise leave the kubelet on a cert the apiserver rejects)" \
  "$([ "$(grep -c 'create -f -' "$CPID_DIR/kubectl-argv")" -eq $((cpid_csr_before + 1)) ] && echo 1 || echo 0)"
FLAGS_RUNNER="$JOIN_WORK/flags.sh"
{
  awk '/^kubelet_round2_flags\(\) \{$/,/^}$/' "$INSTALL"
  echo 'kubelet_round2_flags "$@"'
} > "$FLAGS_RUNNER"
assert_false "no kubelet may disable RotateKubeletServerCertificate, which serverTLSBootstrap needs to rotate its serving cert" \
  bash -c 'bash "$1" 1.37 | grep -q RotateKubeletServerCertificate' _ "$FLAGS_RUNNER"

# The join succeeds only when the Node is Ready AND the kubelet-filed serving
# CSR is approved and issued.
WAIT_RUNNER="$JOIN_WORK/wait.sh"
write_join_runner "$WAIT_RUNNER" '
NODE_NAME=n1; JOIN_STARTED_AT=2026-10-16T10:00:00Z
sleep() { :; }
curl() {
  case "$*" in
    *"/api/v1/nodes/n1"*) printf "%s" "$NODE_JSON" ;;
    *certificatesigningrequests*) printf "%s" "$CSR_JSON" ;;
  esac
}
wait_for_joined_node'
READY_NODE='{"status":{"conditions":[{"type":"Ready","status":"True"}]}}'
NOTREADY_NODE='{"status":{"conditions":[{"type":"Ready","status":"False"}]}}'
ISSUED_CSR='{"items":[{"spec":{"signerName":"kubernetes.io/kubelet-serving","username":"system:node:n1"},"metadata":{"creationTimestamp":"2026-10-16T10:00:05Z"},"status":{"certificate":"Q0VSVA==","conditions":[{"type":"Approved"}]}}]}'
PENDING_CSR='{"items":[{"spec":{"signerName":"kubernetes.io/kubelet-serving","username":"system:node:n1"},"metadata":{"creationTimestamp":"2026-10-16T10:00:05Z"},"status":{}}]}'
CLIENT_ONLY_CSR='{"items":[{"spec":{"signerName":"kubernetes.io/kube-apiserver-client-kubelet","username":"system:node:n1"},"metadata":{"creationTimestamp":"2026-10-16T10:00:05Z"},"status":{"certificate":"Q0VSVA==","conditions":[{"type":"Approved"}]}}]}'
run_wait() { NODE_JSON="$1" CSR_JSON="$2" bash "$WAIT_RUNNER" "$JOIN_WORK" 2>&1; }
ok_status=0; run_wait "$READY_NODE" "$ISSUED_CSR" >/dev/null || ok_status=$?
assert "join succeeds when the Node is Ready and its kubelet-serving CSR is approved and issued" \
  "$([ "$ok_status" -eq 0 ] && echo 1 || echo 0)"
pend_status=0; pend_out="$(run_wait "$READY_NODE" "$PENDING_CSR")" || pend_status=$?
assert "join fails loud with recovery text when the serving CSR stays Pending (logs/exec would be broken on a node reported as joined)" \
  "$([ "$pend_status" -ne 0 ] && printf '%s' "$pend_out" | grep -q 'mint a new token' && echo 1 || echo 0)"
nr_status=0; run_wait "$NOTREADY_NODE" "$ISSUED_CSR" >/dev/null || nr_status=$?
assert "join fails when the Node never becomes Ready even though the serving cert was issued" \
  "$([ "$nr_status" -ne 0 ] && echo 1 || echo 0)"
cl_status=0; run_wait "$READY_NODE" "$CLIENT_ONLY_CSR" >/dev/null || cl_status=$?
assert "the issued client-cert CSR does not count as the serving certificate" \
  "$([ "$cl_status" -ne 0 ] && echo 1 || echo 0)"
STALE_CSR='{"items":[{"spec":{"signerName":"kubernetes.io/kubelet-serving","username":"system:node:n1"},"metadata":{"creationTimestamp":"2026-10-15T09:00:00Z"},"status":{"certificate":"Q0VSVA==","conditions":[{"type":"Approved"}]}}]}'
stale_status=0; run_wait "$READY_NODE" "$STALE_CSR" >/dev/null || stale_status=$?
assert "a serving CSR issued to an earlier join of the same node name does not satisfy this join (a stale CSR would report a join as successful before the new kubelet's own serving cert exists)" \
  "$([ "$stale_status" -ne 0 ] && echo 1 || echo 0)"
MIXED_CSR='{"items":[{"spec":{"signerName":"kubernetes.io/kubelet-serving","username":"system:node:n1"},"metadata":{"creationTimestamp":"2026-10-15T09:00:00Z"},"status":{"certificate":"Q0VSVA==","conditions":[{"type":"Approved"}]}},{"spec":{"signerName":"kubernetes.io/kubelet-serving","username":"system:node:n1"},"metadata":{"creationTimestamp":"2026-10-16T10:00:05Z"},"status":{"certificate":"Q0VSVA==","conditions":[{"type":"Approved"}]}}]}'
mixed_status=0; run_wait "$READY_NODE" "$MIXED_CSR" >/dev/null || mixed_status=$?
assert "a stale serving CSR beside this join's own issued one does not block the join (a re-joined node name keeps its old CSR objects)" \
  "$([ "$mixed_status" -eq 0 ] && echo 1 || echo 0)"
assert_true "join_cluster records the apiserver's creationTimestamp of its client CSR as the lower bound for the serving CSR wait" \
  grep -qF 'JOIN_STARTED_AT="$(curl' "$INSTALL"

# Token input: flag, "-" and absent all work; stdin keeps the secret off argv.
TOKEN_RUNNER="$JOIN_WORK/token.sh"
write_join_runner "$TOKEN_RUNNER" 'read_join_token'
GOOD_TOKEN="abcdef.0123456789abcdef"
assert "join reads the token from stdin when --token is '-' (keeps it out of ps, /proc/<pid>/cmdline and shell history)" \
  "$([ "$(printf '%s\n' "$GOOD_TOKEN" | JOIN_TOKEN=- bash "$TOKEN_RUNNER" "$JOIN_WORK" 2>&1)" = "$GOOD_TOKEN" ] && echo 1 || echo 0)"
assert "join reads the token from stdin when --token is absent" \
  "$([ "$(printf '%s\n' "$GOOD_TOKEN" | bash "$TOKEN_RUNNER" "$JOIN_WORK" 2>&1)" = "$GOOD_TOKEN" ] && echo 1 || echo 0)"
assert "join accepts the token directly from the --token flag value" \
  "$([ "$(JOIN_TOKEN=$GOOD_TOKEN bash "$TOKEN_RUNNER" "$JOIN_WORK" </dev/null 2>&1)" = "$GOOD_TOKEN" ] && echo 1 || echo 0)"
bad_status=0
printf 'not-a-token\n' | bash "$TOKEN_RUNNER" "$JOIN_WORK" >/dev/null 2>&1 || bad_status=$?
assert "a malformed token is rejected before any network call" \
  "$([ "$bad_status" -ne 0 ] && echo 1 || echo 0)"
empty_status=0
empty_out="$(bash "$TOKEN_RUNNER" "$JOIN_WORK" </dev/null 2>&1)" || empty_status=$?
assert "empty non-TTY stdin fails with a clear 'no join token' message instead of a silent set -e exit (an unattended join otherwise dies with no explanation)" \
  "$([ "$empty_status" -ne 0 ] && printf '%s' "$empty_out" | grep -q 'no join token on stdin' && echo 1 || echo 0)"

# Discovery: the cluster-info JWS must verify under the token and the CA must
# match the pinned hash -- either failing means trusting an impostor endpoint.
b64u() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
DISCOVER_KUBECONFIG="$(printf 'apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: %s\n    server: https://cp.example:6443\n  name: ""\n' "$(openssl base64 -A -in "$JOIN_CA_DIR/ca.pem")")"
sign_cluster_info() {
  local secret="$1" hdr payload
  hdr="$(printf '{"alg":"HS256","kid":"abcdef"}' | b64u)"
  payload="$(printf '%s\n' "$DISCOVER_KUBECONFIG" | b64u)"
  printf '%s..%s' "$hdr" "$(printf '%s.%s' "$hdr" "$payload" | openssl dgst -sha256 -hmac "$secret" -binary | b64u)"
}
write_cluster_info() {
  jq -n --arg kc "$DISCOVER_KUBECONFIG
" --arg jws "$1" '{data: {kubeconfig: $kc, "jws-kubeconfig-abcdef": $jws}}' > "$JOIN_WORK/cluster-info.json"
}
DISCOVER_RUNNER="$JOIN_WORK/discover.sh"
write_join_runner "$DISCOVER_RUNNER" '
curl() { cat "$CLUSTER_INFO"; }
discover_cluster_ca abcdef "$TOKEN_SECRET"'
export CLUSTER_INFO="$JOIN_WORK/cluster-info.json"

write_cluster_info "$(sign_cluster_info 0123456789abcdef)"
worker_state="$JOIN_WORK/worker-ok"; mkdir -p "$worker_state"
ok_status=0
TOKEN_SECRET=0123456789abcdef CA_CERT_HASH="$EXPECTED_CA_HASH" bash "$DISCOVER_RUNNER" "$worker_state" >/dev/null 2>&1 || ok_status=$?
assert "discovery with a validly signed cluster-info and the right CA hash trusts and stores the CA" \
  "$([ "$ok_status" -eq 0 ] && cmp -s "$worker_state/ca.pem" "$JOIN_CA_DIR/ca.pem" && echo 1 || echo 0)"

# CA succession: cluster-info carries a bundle. The pin may match any cert in it
# (kubeadm semantics) and the joiner must store ALL of them, or a node joined during
# the overlap would reject leaves issued by the successor CA.
openssl ecparam -name prime256v1 -genkey -noout -out "$JOIN_WORK/ca2.key"
openssl req -x509 -new -key "$JOIN_WORK/ca2.key" -subj "/CN=u7s-test-ca-2" -days 2 -out "$JOIN_WORK/ca2.pem" 2>/dev/null
cat "$JOIN_CA_DIR/ca.pem" "$JOIN_WORK/ca2.pem" > "$JOIN_WORK/bundle.pem"
CA2_HASH="sha256:$(openssl x509 -in "$JOIN_WORK/ca2.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 | sed 's/^.* //')"
SINGLE_CA_KUBECONFIG="$DISCOVER_KUBECONFIG"
DISCOVER_KUBECONFIG="$(printf 'apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: %s\n    server: https://cp.example:6443\n  name: ""\n' "$(openssl base64 -A -in "$JOIN_WORK/bundle.pem")")"
write_cluster_info "$(sign_cluster_info 0123456789abcdef)"
for pin in "$EXPECTED_CA_HASH" "$CA2_HASH"; do
  bundle_state="$JOIN_WORK/worker-bundle-${pin##*:}"; mkdir -p "$bundle_state"
  bundle_status=0
  TOKEN_SECRET=0123456789abcdef CA_CERT_HASH="$pin" bash "$DISCOVER_RUNNER" "$bundle_state" >/dev/null 2>&1 || bundle_status=$?
  assert "discovery of a two-CA bundle pinned to ${pin:7:12}... stores both CAs, so a joined node verifies leaves from either" \
    "$([ "$bundle_status" -eq 0 ] && cmp -s "$bundle_state/ca.pem" "$JOIN_WORK/bundle.pem" && echo 1 || echo 0)"
done
bundle_wrong_state="$JOIN_WORK/worker-bundle-wrong"; mkdir -p "$bundle_wrong_state"
bundle_wrong_status=0
TOKEN_SECRET=0123456789abcdef CA_CERT_HASH="sha256:$(printf '0%.0s' $(seq 1 64))" bash "$DISCOVER_RUNNER" "$bundle_wrong_state" >/dev/null 2>&1 || bundle_wrong_status=$?
assert "discovery refuses a bundle none of whose certs match --ca-cert-hash" \
  "$([ "$bundle_wrong_status" -ne 0 ] && [ ! -e "$bundle_wrong_state/ca.pem" ] && echo 1 || echo 0)"
DISCOVER_KUBECONFIG="$SINGLE_CA_KUBECONFIG"
write_cluster_info "$(sign_cluster_info 0123456789abcdef)"

wrong_sig_state="$JOIN_WORK/worker-wrong-sig"; mkdir -p "$wrong_sig_state"
wrong_sig_status=0
TOKEN_SECRET=ffffffffffffffff CA_CERT_HASH="$EXPECTED_CA_HASH" bash "$DISCOVER_RUNNER" "$wrong_sig_state" >/dev/null 2>&1 || wrong_sig_status=$?
assert "discovery refuses cluster-info whose JWS does not verify under the token -- an impostor endpoint cannot hand the joiner its own CA (and with it, the token)" \
  "$([ "$wrong_sig_status" -ne 0 ] && [ ! -e "$wrong_sig_state/ca.pem" ] && echo 1 || echo 0)"

wrong_hash_state="$JOIN_WORK/worker-wrong-hash"; mkdir -p "$wrong_hash_state"
wrong_hash_status=0
TOKEN_SECRET=0123456789abcdef CA_CERT_HASH="sha256:$(printf '0%.0s' $(seq 1 64))" bash "$DISCOVER_RUNNER" "$wrong_hash_state" >/dev/null 2>&1 || wrong_hash_status=$?
assert "discovery refuses a CA that does not match --ca-cert-hash even when the signature verifies (a stolen token must not be enough to substitute the CA)" \
  "$([ "$wrong_hash_status" -ne 0 ] && [ ! -e "$wrong_hash_state/ca.pem" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Upgrade in place: a joined worker re-runs install.sh with no token, and the
# control plane re-runs it without re-minting its CA / service-account keys.
# ---------------------------------------------------------------------------
UPG_WORK="$(mktemp -d)"
trap 'rm -rf "$DETECT_WORK" "$WORKER_MODE_WORK" "$JOIN_WORK" "$UPG_WORK"' EXIT

write_upgrade_runner() {
  local runner="$1" body="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"; NODE_NAME=n1'
    echo 'sleep() { :; }'
    for fn in current_client_cert verify_worker_identity worker_api_get worker_ready_heartbeat client_cert_fingerprint wait_for_upgraded_worker cp_identity_fingerprint verify_cp_identity_preserved; do
      awk "/^${fn}\\(\\) \\{/,/^\\}/" "$INSTALL"
    done
    echo "$body"
  } > "$runner"
}

# A cert whose notAfter is in the past, and a valid one, sharing one key.
UPG_KEY="$UPG_WORK/client.key"
openssl ecparam -name prime256v1 -genkey -noout -out "$UPG_KEY"
openssl req -new -key "$UPG_KEY" -subj "/O=system:nodes/CN=system:node:n1" -out "$UPG_WORK/client.csr"
openssl x509 -req -in "$UPG_WORK/client.csr" -CA "$JOIN_CA_DIR/ca.pem" -CAkey "$JOIN_WORK/ca.key" -CAcreateserial -days 1 -out "$UPG_WORK/valid.crt" 2>/dev/null
openssl req -x509 -new -key "$UPG_KEY" -subj "/CN=valid" -days 30 -out "$UPG_WORK/foreign-ca.crt" 2>/dev/null
mkdir -p "$UPG_WORK/ca"
: > "$UPG_WORK/ca/index.txt"
echo 01 > "$UPG_WORK/ca/serial"
cat > "$UPG_WORK/ca.cnf" <<EOF
[ca]
default_ca = d
[d]
database = $UPG_WORK/ca/index.txt
new_certs_dir = $UPG_WORK/ca
serial = $UPG_WORK/ca/serial
default_md = sha256
policy = p
unique_subject = no
[p]
commonName = supplied
EOF
openssl ca -config "$UPG_WORK/ca.cnf" -selfsign -keyfile "$UPG_KEY" -in "$UPG_WORK/client.csr" \
  -startdate 20200101000000Z -enddate 20200102000000Z -batch -notext -out "$UPG_WORK/expired.crt" >/dev/null 2>&1
openssl ca -config "$UPG_WORK/ca.cnf" -selfsign -keyfile "$UPG_KEY" -in "$UPG_WORK/client.csr" \
  -startdate 20210101000000Z -enddate 20210102000000Z -batch -notext -out "$UPG_WORK/expired-rotated.crt" >/dev/null 2>&1
assert "test setup: the fixture client cert really is expired (otherwise the expiry tests below prove nothing)" \
  "$(openssl x509 -in "$UPG_WORK/expired.crt" -noout -checkend 0 >/dev/null 2>&1 && echo 0 || echo 1)"

new_worker_state() {
  local d="$UPG_WORK/$1" cert="$2"
  mkdir -p "$d/kubelet/pki"
  echo 'server: https://cp.example:6443' > "$d/kubeconfig"
  cp "$JOIN_CA_DIR/ca.pem" "$d/ca.pem"
  cp "$UPG_KEY" "$d/kubelet-client.key"
  cp "$cert" "$d/kubelet-client.crt"
  printf '%s' "$d"
}
VERIFY_RUNNER="$UPG_WORK/verify.sh"
write_upgrade_runner "$VERIFY_RUNNER" 'verify_worker_identity'

ok_dir="$(new_worker_state valid "$UPG_WORK/valid.crt")"
ok_status=0; bash "$VERIFY_RUNNER" "$ok_dir" >/dev/null 2>&1 || ok_status=$?
assert "a joined worker with a valid client identity passes the pre-upgrade check (no token is asked for)" \
  "$([ "$ok_status" -eq 0 ] && echo 1 || echo 0)"

CURRENT_RUNNER="$UPG_WORK/current.sh"
write_upgrade_runner "$CURRENT_RUNNER" 'current_client_cert'
foreign_dir="$(new_worker_state foreign "$UPG_WORK/foreign-ca.crt")"
foreign_status=0; bash "$CURRENT_RUNNER" "$foreign_dir" >/dev/null 2>&1 || foreign_status=$?
assert "an unexpired client cert NOT signed by the current CA is not treated as current (after a CA reset the kubelet would 401 and the control plane would never re-issue)" \
  "$([ "$foreign_status" -ne 0 ] && echo 1 || echo 0)"
cp "$UPG_WORK/foreign-ca.crt" "$ok_dir/ca-bundle.pem"
bundle_status=0; bash "$CURRENT_RUNNER" "$ok_dir" >/dev/null 2>&1 || bundle_status=$?
assert "ca-bundle.pem, when present, is the trust anchor: a cert it does not chain to is rejected even if ca.pem signed it" \
  "$([ "$bundle_status" -ne 0 ] && echo 1 || echo 0)"
rm -f "$ok_dir/ca-bundle.pem"

exp_dir="$(new_worker_state expired "$UPG_WORK/expired.crt")"
exp_status=0; exp_out="$(bash "$VERIFY_RUNNER" "$exp_dir" 2>&1)" || exp_status=$?
assert "an expired client identity fails the upgrade with a re-join-with-a-fresh-token message naming the state to clear (a silently restarted kubelet would crash-loop on 401 with no hint)" \
  "$([ "$exp_status" -ne 0 ] && printf '%s' "$exp_out" | grep -q 'expired' && printf '%s' "$exp_out" | grep -qF "rm -rf $exp_dir" && printf '%s' "$exp_out" | grep -q 'fresh token' && echo 1 || echo 0)"

bothexp_dir="$(new_worker_state both-expired "$UPG_WORK/expired.crt")"
cp "$UPG_WORK/expired-rotated.crt" "$bothexp_dir/kubelet/pki/kubelet-client-current.pem"
bothexp_out="$(bash "$VERIFY_RUNNER" "$bothexp_dir" 2>&1)" || true
assert "the expired-identity message reports the notAfter of the rotated cert the kubelet actually uses, not the stale join-time cert (an operator comparing dates would otherwise misdiagnose when the node lost access)" \
  "$(printf '%s' "$bothexp_out" | grep -qF "$bothexp_dir/kubelet/pki/kubelet-client-current.pem: notAfter Jan  2 00:00:00 2021" && ! printf '%s' "$bothexp_out" | grep -q '2020' && echo 1 || echo 0)"
assert "the expired-identity message names the join-time cert's notAfter when no rotated cert exists" \
  "$(printf '%s' "$exp_out" | grep -qF "$exp_dir/kubelet-client.crt: notAfter Jan  2 00:00:00 2020" && echo 1 || echo 0)"

rot_dir="$(new_worker_state rotated "$UPG_WORK/expired.crt")"
cp "$UPG_WORK/valid.crt" "$rot_dir/kubelet/pki/kubelet-client-current.pem"
rot_status=0; bash "$VERIFY_RUNNER" "$rot_dir" >/dev/null 2>&1 || rot_status=$?
assert "a node whose join-time cert expired but whose kubelet rotated a valid one still upgrades (rotation keeps long-lived nodes alive; demanding a re-join would force a fresh token on every node after a year)" \
  "$([ "$rot_status" -eq 0 ] && echo 1 || echo 0)"

miss_dir="$UPG_WORK/missing"
mkdir -p "$miss_dir"
echo 'server: https://cp.example:6443' > "$miss_dir/kubeconfig"
miss_status=0; miss_out="$(bash "$VERIFY_RUNNER" "$miss_dir" 2>&1)" || miss_status=$?
assert "a worker kubeconfig without its client cert/key/CA means a join is required, said plainly (upgrading it would start a kubelet that can never authenticate)" \
  "$([ "$miss_status" -ne 0 ] && printf '%s' "$miss_out" | grep -q 'a join is required' && printf '%s' "$miss_out" | grep -qF "$miss_dir/kubelet-client.crt" && echo 1 || echo 0)"
nokc_dir="$UPG_WORK/missing-all"; mkdir -p "$nokc_dir"
nokc_out="$(bash "$VERIFY_RUNNER" "$nokc_dir" 2>&1)" || true
assert "kubeconfig is not listed as a missing join identity: without it the node is not detected as an existing worker, so the entry could never fire" \
  "$(printf '%s' "$nokc_out" | grep -qF "$nokc_dir/kubelet-client.crt" && ! printf '%s' "$nokc_out" | grep -qF "$nokc_dir/kubeconfig" && echo 1 || echo 0)"

# The install.sh worker branch, extracted: with an existing identity it must
# skip the join, never read a token, and restart kubelet.
write_worker_branch_runner() {
  local runner="$1" unit_dir="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"; JOIN_MODE="$2"; BIN_DIR=/opt/u7s/bin; NODE_NAME=n1; IFACE_IP=10.0.0.2; KUBELET_ROUND2_FLAGS=""'
    echo 'join_cluster() { echo join_cluster >> "$STATE_DIR/calls"; }'
    echo 'read_join_token() { echo read_join_token >> "$STATE_DIR/calls"; return 1; }'
    echo 'ensure_jq() { :; }'
    grep -E '^MEMLOW_KUBELET_MIB=' "$INSTALL"
    echo 'CONFIG_FILE="$STATE_DIR/config"; DEFAULT_SERVICE_CIDR=10.96.0.0/12'
    echo 'worker_ready_heartbeat() { echo "${HB_BEFORE-1000}"; }'
    echo 'client_cert_fingerprint() { echo FP1; }'
    echo 'wait_for_joined_node() { echo wait_for_joined_node >> "$STATE_DIR/calls"; }'
    echo 'wait_for_upgraded_worker() { echo "wait_for_upgraded_worker $*" >> "$STATE_DIR/calls"; }'
    echo 'systemctl() { echo "systemctl $*" >> "$STATE_DIR/calls"; }'
    echo 'if true; then'
    awk '/^  # --- Join an existing cluster via the CSR API/,/^  exit 0$/' "$INSTALL" \
      | sed "s#/etc/systemd/system/#$unit_dir/#"
    echo 'fi'
  } > "$runner"
}
BRANCH_UNITS="$UPG_WORK/units"; mkdir -p "$BRANCH_UNITS"
BRANCH_RUNNER="$UPG_WORK/branch.sh"
write_worker_branch_runner "$BRANCH_RUNNER" "$BRANCH_UNITS"

up_dir="$UPG_WORK/upgrade-branch"; mkdir -p "$up_dir"
up_status=0; bash "$BRANCH_RUNNER" "$up_dir" 0 >/dev/null 2>&1 || up_status=$?
assert "re-running install.sh on a joined worker with no token skips the join and restarts kubelet (an upgrade must not force minting a token for every node)" \
  "$([ "$up_status" -eq 0 ] && ! grep -qE '^(join_cluster|read_join_token)$' "$up_dir/calls" && grep -qx 'systemctl restart kubelet.service' "$up_dir/calls" && echo 1 || echo 0)"
assert "the upgrade waits for the Node to report Ready after the restart, passing the pre-restart Ready heartbeat and cert fingerprint (otherwise a stale Ready or a lost identity is reported as a successful upgrade)" \
  "$(grep -qx 'wait_for_upgraded_worker 1000 FP1' "$up_dir/calls" && echo 1 || echo 0)"

noapi_dir="$UPG_WORK/upgrade-no-api"; mkdir -p "$noapi_dir"
noapi_status=0; HB_BEFORE= bash "$BRANCH_RUNNER" "$noapi_dir" 0 >/dev/null 2>&1 || noapi_status=$?
assert "an unreachable API server before the restart aborts the upgrade untouched (an empty baseline would let any stale Ready heartbeat pass the post-restart wait)" \
  "$([ "$noapi_status" -ne 0 ] && ! grep -q 'systemctl restart' "$noapi_dir/calls" 2>/dev/null && echo 1 || echo 0)"

jn_dir="$UPG_WORK/join-branch"; mkdir -p "$jn_dir"
jn_status=0; bash "$BRANCH_RUNNER" "$jn_dir" 1 >/dev/null 2>&1 || jn_status=$?
assert "a fresh --join still runs join_cluster and the join wait (the tokenless path must not swallow real joins)" \
  "$([ "$jn_status" -eq 0 ] && grep -qx join_cluster "$jn_dir/calls" && grep -qx wait_for_joined_node "$jn_dir/calls" && ! grep -q '^wait_for_upgraded_worker' "$jn_dir/calls" && echo 1 || echo 0)"

# Post-restart verification.
HB_RUNNER="$UPG_WORK/hb.sh"
write_upgrade_runner "$HB_RUNNER" '
worker_ready_heartbeat() { echo "$HEARTBEAT"; }
wait_for_upgraded_worker "$BEFORE" "$FP_BEFORE"'
valid_fp="$(openssl x509 -in "$UPG_WORK/valid.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
stale_status=0; HEARTBEAT=100 BEFORE=100 FP_BEFORE="$valid_fp" bash "$HB_RUNNER" "$ok_dir" >/dev/null 2>&1 || stale_status=$?
assert "a Node whose Ready heartbeat is not newer than the restart time is not reported as upgraded (the old Ready condition lingers until the lifecycle controller notices)" \
  "$([ "$stale_status" -ne 0 ] && echo 1 || echo 0)"
older_status=0; HEARTBEAT=50 BEFORE=100 FP_BEFORE="$valid_fp" bash "$HB_RUNNER" "$ok_dir" >/dev/null 2>&1 || older_status=$?
assert "a Ready heartbeat older than the restart time is not reported as upgraded" \
  "$([ "$older_status" -ne 0 ] && echo 1 || echo 0)"
fresh_out="$(HEARTBEAT=200 BEFORE=100 FP_BEFORE="$valid_fp" bash "$HB_RUNNER" "$ok_dir" 2>&1)" && fresh_status=0 || fresh_status=$?
assert "a Node that reports Ready with a newer heartbeat and an unchanged client cert is a successful upgrade, reported as such" \
  "$([ "$fresh_status" -eq 0 ] && printf '%s' "$fresh_out" | grep -q 'client certificate unchanged' && echo 1 || echo 0)"
rotd_out="$(HEARTBEAT=200 BEFORE=100 FP_BEFORE="AA:BB" bash "$HB_RUNNER" "$ok_dir" 2>&1)" && rotd_status=0 || rotd_status=$?
assert "a client cert that changed across the restart is reported as rotated by the kubelet, not as a re-bootstrap" \
  "$([ "$rotd_status" -eq 0 ] && printf '%s' "$rotd_out" | grep -q 'rotated its client certificate' && echo 1 || echo 0)"
exp_after_status=0; HEARTBEAT=200 BEFORE=100 FP_BEFORE=x bash "$HB_RUNNER" "$exp_dir" >/dev/null 2>&1 || exp_after_status=$?
assert "an upgrade whose client cert is no longer valid afterwards fails loud even if the Node looks Ready" \
  "$([ "$exp_after_status" -ne 0 ] && echo 1 || echo 0)"

# The kubelet stamps the heartbeat with the worker's clock, so the wait must
# compare it only with an earlier reading of the same field. The API server's
# Date header (here 02:00:00, as if read before the restart) must not matter:
# a worker clock 3h ahead (stale heartbeat 05:00:00 == baseline) must not pass,
# and one 1h behind (fresh heartbeat 01:00:10 > baseline 01:00:00) must.
TIME_RUNNER="$UPG_WORK/time.sh"
write_upgrade_runner "$TIME_RUNNER" '
worker_api_get() {
  case "$1" in
    /version) printf "HTTP/2 200\r\ndate: Sat, 17 Oct 2026 02:00:00 GMT\r\n\r\n" ;;
    *) printf "{\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\",\"lastHeartbeatTime\":\"%s\"}]}}" "$SERVED_HB" ;;
  esac
}
SERVED_HB="$BASE_HB"; before="$(worker_ready_heartbeat any)"
SERVED_HB="$NOW_HB"
wait_for_upgraded_worker "$before" "$FP_BEFORE"'
ahead_status=0; BASE_HB=2026-10-17T05:00:00Z NOW_HB=2026-10-17T05:00:00Z FP_BEFORE="$valid_fp" bash "$TIME_RUNNER" "$ok_dir" >/dev/null 2>&1 || ahead_status=$?
assert "with the worker clock ahead of the API server, an unchanged (stale) Ready heartbeat is not mistaken for a post-restart one" \
  "$([ "$ahead_status" -ne 0 ] && echo 1 || echo 0)"
behind_status=0; BASE_HB=2026-10-17T01:00:00Z NOW_HB=2026-10-17T01:00:10Z FP_BEFORE="$valid_fp" bash "$TIME_RUNNER" "$ok_dir" >/dev/null 2>&1 || behind_status=$?
assert "with the worker clock behind the API server, a fresh Ready heartbeat is still accepted (a server-clock comparison would fail every upgrade on such a node)" \
  "$([ "$behind_status" -eq 0 ] && echo 1 || echo 0)"

# Control plane: the CA survives the re-run untouched, or the run fails. sa.key is not
# fingerprinted: the apiserver rotates it on its own.
CP_RUNNER="$UPG_WORK/cp.sh"
write_upgrade_runner "$CP_RUNNER" 'before="$(cp_identity_fingerprint)"; if [ -n "${MUTATE:-}" ]; then echo regenerated > "$STATE_DIR/$MUTATE"; fi; verify_cp_identity_preserved "$before"'
cp_state="$UPG_WORK/cp-state"; mkdir -p "$cp_state"
for f in ca.key ca.crt sa.key sa.pub; do echo "original $f" > "$cp_state/$f"; done
cp_ok_out="$(bash "$CP_RUNNER" "$cp_state" 2>&1)" && cp_ok_status=0 || cp_ok_status=$?
assert "a control-plane re-run that leaves ca.* alone succeeds and says no CA was re-minted" \
  "$([ "$cp_ok_status" -eq 0 ] && printf '%s' "$cp_ok_out" | grep -q 'no CA re-minted' && echo 1 || echo 0)"
cp_rot_status=0; MUTATE=sa.key bash "$CP_RUNNER" "$cp_state" >/dev/null 2>&1 || cp_rot_status=$?
assert "a rotated sa.key does not fail a control-plane upgrade (the apiserver rotates it on its own)" \
  "$([ "$cp_rot_status" -eq 0 ] && echo 1 || echo 0)"
for f in ca.key ca.crt; do
  cp_bad_status=0; MUTATE="$f" bash "$CP_RUNNER" "$cp_state" >/dev/null 2>&1 || cp_bad_status=$?
  assert "a control-plane upgrade that re-mints $f fails loud (every node's identity would silently die)" \
    "$([ "$cp_bad_status" -ne 0 ] && echo 1 || echo 0)"
  echo "original $f" > "$cp_state/$f"
done
assert_true "the control-plane path records the CA/SA fingerprint before restarting the apiserver and verifies it after (an upgrade must not re-mint cluster identity)" \
  grep -qF 'verify_cp_identity_preserved "$CP_IDENTITY_BEFORE"' "$INSTALL"

# First-boot race: the apiserver writes its CA/keys/kubeconfigs some time after
# `systemctl restart u7s-apiserver` returns. The wait runs against a stub whose
# sleep() writes the files only after N polls (kubeconfig last, as the real
# apiserver does), so removing the wait or dropping a file from its list fails.
WAITFILES_WORK="$(mktemp -d)"
WAITFILES_RUNNER="$WAITFILES_WORK/run.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo 'dir="$1"; polls=0'
  echo 'sleep() { polls=$((polls+1)); if [ "$polls" -ge "${APPEAR_AFTER:-999999}" ]; then for f in ca.crt ca.key intermediate-cert.pem intermediate.key sa.key kubeconfig kcm-kubeconfig; do [ "$f" = "${NEVER:-}" ] || echo x > "$dir/$f"; done; fi; }'
  awk '/^wait_for_apiserver_files\(\) \{/,/^\}/' "$INSTALL"
  echo 'wait_for_apiserver_files "$dir"; echo "polls=$polls"'
} > "$WAITFILES_RUNNER"

wf_dir="$WAITFILES_WORK/late"; mkdir -p "$wf_dir"
wf_out="$(APPEAR_AFTER=5 bash "$WAITFILES_RUNNER" "$wf_dir" 2>&1)" && wf_status=0 || wf_status=$?
assert "install waits for files the apiserver writes after its restart returns instead of racing them (a slow first boot otherwise fails the KCM restart)" \
  "$([ "$wf_status" -eq 0 ] && printf '%s' "$wf_out" | grep -q 'polls=5' && echo 1 || echo 0)"

wf_dir="$WAITFILES_WORK/present"; mkdir -p "$wf_dir"
for f in ca.crt ca.key intermediate-cert.pem intermediate.key sa.key kubeconfig kcm-kubeconfig; do echo x > "$wf_dir/$f"; done
wf_out="$(bash "$WAITFILES_RUNNER" "$wf_dir" 2>&1)" && wf_status=0 || wf_status=$?
assert "a re-run with the identity already on disk does not wait (upgrades must not pay the first-boot delay)" \
  "$([ "$wf_status" -eq 0 ] && printf '%s' "$wf_out" | grep -q 'polls=0' && echo 1 || echo 0)"

for missing in ca.crt kcm-kubeconfig intermediate.key; do
  wf_dir="$WAITFILES_WORK/never-$missing"; mkdir -p "$wf_dir"
  wf_out="$(APPEAR_AFTER=1 NEVER="$missing" bash "$WAITFILES_RUNNER" "$wf_dir" 2>&1)" && wf_status=0 || wf_status=$?
  assert "a $missing that never appears fails the install naming that file (an operator must see which artefact is missing, not a later unit failure)" \
    "$([ "$wf_status" -ne 0 ] && printf '%s' "$wf_out" | grep -qF "error: u7s-apiserver did not write $wf_dir/$missing" && echo 1 || echo 0)"
done
rm -rf "$WAITFILES_WORK"

CMWAIT_RUNNER="$(mktemp)"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo 'polls=0; sleep() { :; }'
  echo 'kubectl() { polls=$((polls+1)); [ "$polls" -gt "${FAIL_FIRST:-0}" ]; }'
  awk '/^wait_for_authentication_configmap\(\) \{/,/^\}/' "$INSTALL"
  echo 'wait_for_authentication_configmap /dev/null; echo "polls=$polls"'
} > "$CMWAIT_RUNNER"
cm_out="$(FAIL_FIRST=3 bash "$CMWAIT_RUNNER" 2>&1)" && cm_status=0 || cm_status=$?
assert "install keeps polling until the authentication ConfigMap appears (KCM must not start before it exists)" \
  "$([ "$cm_status" -eq 0 ] && printf '%s' "$cm_out" | grep -q 'polls=4' && echo 1 || echo 0)"
cm_out="$(FAIL_FIRST=9999 bash "$CMWAIT_RUNNER" 2>&1)" && cm_status=0 || cm_status=$?
assert "a ConfigMap that never appears fails the install with a clear timeout message instead of hanging" \
  "$([ "$cm_status" -ne 0 ] && printf '%s' "$cm_out" | grep -qF 'extension-apiserver-authentication was not published within 120s' && echo 1 || echo 0)"
rm -f "$CMWAIT_RUNNER"

wf_apiserver_line="$(grep -n '^if ! systemctl restart u7s-apiserver.service' "$INSTALL" | cut -d: -f1)"
wf_wait_line="$(grep -n '^wait_for_apiserver_files "\$STATE_DIR"' "$INSTALL" | cut -d: -f1)"
wf_kcm_line="$(grep -n '^systemctl restart u7s-kcm.service' "$INSTALL" | cut -d: -f1)"
assert "the file wait sits between the apiserver restart and the KCM/kubelet restarts (otherwise the wait guards nothing)" \
  "$([ -n "$wf_apiserver_line" ] && [ -n "$wf_wait_line" ] && [ -n "$wf_kcm_line" ] && [ "$wf_apiserver_line" -lt "$wf_wait_line" ] && [ "$wf_wait_line" -lt "$wf_kcm_line" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Supply chain: https-only curl, and a truncated download executes nothing.
# ---------------------------------------------------------------------------

# A curl without --proto '=https...' follows an https->http redirect, handing a
# network attacker the bytes that become root-run binaries or apt keys.
curl_lines="$(grep -nE '(^|[ (])curl ' "$INSTALL" | grep -vE '^[0-9]+:[[:space:]]*#|apt-get install' || true)"
bad_curls="$(printf '%s\n' "$curl_lines" | grep -vE "curl --proto '=https(,file)?'( --proto-redir '=https')? --tlsv1\.2 " || true)"
assert "every curl in install.sh is https-only with TLS >= 1.2, so a MITM cannot downgrade a fetch that feeds root-run code (offenders: ${bad_curls:-none})" \
  "$([ -n "$curl_lines" ] && [ -z "$bad_curls" ] && echo 1 || echo 0)"

# `curl | sudo bash` can be cut short anywhere. Bash parses a whole function
# before running it, so cutting inside main() is a syntax error. A bogus flag
# makes any executed prefix visible: main's arg parser would print "unknown
# argument".
main_line="$(grep -n '^main() {$' "$INSTALL" | cut -d: -f1)"
total_lines="$(wc -l < "$INSTALL")"
TRUNC_WORK="$(mktemp -d)"
trunc_ok=1
for cut_at in $(( main_line + 1 )) $(( (main_line + total_lines) / 2 )) $(( total_lines - 3 )); do
  head -n "$cut_at" "$INSTALL" > "$TRUNC_WORK/install.sh"
  trunc_status=0
  trunc_out="$(bash "$TRUNC_WORK/install.sh" --bogus-flag 2>&1)" || trunc_status=$?
  [ "$trunc_status" -ne 0 ] || trunc_ok=0
  printf '%s' "$trunc_out" | grep -q 'unknown argument' && trunc_ok=0
  printf '%s' "$trunc_out" | grep -qiE 'syntax error|unexpected end of file' || trunc_ok=0
done
rm -rf "$TRUNC_WORK"
assert "a truncated install.sh fails to parse and executes nothing, instead of running a script prefix as root" \
  "$trunc_ok"
assert "install.sh invokes main on its last line" \
  "$([ "$(tail -n 1 "$INSTALL")" = 'main "$@"' ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Supply chain: apt signing keys are pinned by fingerprint.
# ---------------------------------------------------------------------------

# install_apt_key is extracted verbatim; curl is stubbed to copy a local
# fixture key (the real function's fetch flags are covered by the curl test
# above). Real gpg parses real throwaway keys.
KEY_WORK="$(mktemp -d)"
export GNUPGHOME="$KEY_WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "pin-test <pin@test.invalid>" ed25519 sign never 2>/dev/null
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "other-test <other@test.invalid>" ed25519 sign never 2>/dev/null
good_fpr="$(gpg --batch --with-colons --list-keys pin@test.invalid | awk -F: '/^fpr:/{print $10; exit}')"
other_fpr="$(gpg --batch --with-colons --list-keys other@test.invalid | awk -F: '/^fpr:/{print $10; exit}')"
gpg --batch --armor --export pin@test.invalid > "$KEY_WORK/good.asc"
gpg --batch --armor --export other@test.invalid > "$KEY_WORK/other.asc"
cat "$KEY_WORK/good.asc" "$KEY_WORK/other.asc" > "$KEY_WORK/both.asc"
unset GNUPGHOME

{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo 'curl() { local out=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done; cp "$FIXTURE_KEY" "$out"; }'
  awk '/^install_apt_key\(\) \{/,/^\}/' "$INSTALL"
  echo 'install_apt_key https://example.invalid/Release.key "$1" "$2"'
} > "$KEY_WORK/runner.sh"

run_key_install() {
  KEY_STATUS=0
  KEY_OUT="$(FIXTURE_KEY="$1" bash "$KEY_WORK/runner.sh" "$2" "$KEY_WORK/out.gpg" 2>&1)" || KEY_STATUS=$?
}

rm -f "$KEY_WORK/out.gpg"
run_key_install "$KEY_WORK/good.asc" "$good_fpr"
assert "a key matching the pinned fingerprint is installed into the apt keyring" \
  "$([ "$KEY_STATUS" -eq 0 ] && [ -s "$KEY_WORK/out.gpg" ] && echo 1 || echo 0)"

rm -f "$KEY_WORK/out.gpg"
run_key_install "$KEY_WORK/other.asc" "$good_fpr"
assert "a key with a different fingerprint than the pin is refused, naming expected and actual, and no keyring is written -- a compromised mirror cannot swap in its own key" \
  "$([ "$KEY_STATUS" -ne 0 ] && [ ! -e "$KEY_WORK/out.gpg" ] && printf '%s' "$KEY_OUT" | grep -qF "expected: $good_fpr" && printf '%s' "$KEY_OUT" | grep -qF "actual:   $other_fpr" && echo 1 || echo 0)"

rm -f "$KEY_WORK/out.gpg"
run_key_install "$KEY_WORK/both.asc" "$good_fpr"
assert "a key file carrying the pinned key plus an attacker key is refused, since signed-by would trust both" \
  "$([ "$KEY_STATUS" -ne 0 ] && [ ! -e "$KEY_WORK/out.gpg" ] && echo 1 || echo 0)"

assert "both apt keys are installed through the fingerprint-checking function, never piped straight into gpg --dearmor" \
  "$([ "$(grep -c '^install_apt_key ' "$INSTALL")" -eq 2 ] && ! grep -qE 'curl .*\| *$|^ *\| gpg' "$INSTALL" && echo 1 || echo 0)"
rm -rf "$KEY_WORK"

# ---------------------------------------------------------------------------
# --service-cidr / --cluster-cidr / --cluster-dns: one value per range must
# reach every consumer, because a migrated cluster keeps its source's
# ClusterIPs and pod IPs; a single consumer left on the old default (kubelet
# resolv.conf pointing at a dead DNS VIP, flannel on the wrong pod net) breaks
# the cluster in a way that only shows under traffic. The functions are
# extracted from install.sh's real source and executed.
# ---------------------------------------------------------------------------
NET_WORK="$(mktemp -d)"
trap 'rm -rf "$DETECT_WORK" "$MANIFEST_WORK" "$NET_WORK"' EXIT
{
  for fn in ipv4_to_int int_to_ipv4 parse_cidr default_cluster_dns validate_network_config \
    reconcile_network_flag check_node_ip_outside_ranges render_vendored_manifests write_kubelet_config_yaml; do
    awk -v f="$fn" '$0 == f "() {" {p=1} p {print} p && /^}$/ {exit}' "$INSTALL"
  done
} > "$NET_WORK/fns.sh"
assert "all network-range functions were extracted from install.sh (if this fails the behavioral tests below test nothing)" \
  "$([ "$(grep -c '^[a-z0-9_]*() {$' "$NET_WORK/fns.sh")" -eq 9 ] && echo 1 || echo 0)"

# net_run <scenario>: runs <scenario> after the extracted functions with the
# production defaults loaded; sets NET_STATUS/NET_OUT.
net_run() {
  {
    echo 'set -uo pipefail'
    echo 'DEFAULT_SERVICE_CIDR="10.96.0.0/12"; DEFAULT_POD_CLUSTER_CIDR="10.244.0.0/16"'
    echo 'SERVICE_CIDR=""; POD_CLUSTER_CIDR=""; CLUSTER_DNS=""; EXISTING_INSTALL=0'
    echo 'CONFIG_FILE=/var/lib/u7s/config; STATE_DIR=/var/lib/u7s'
    cat "$NET_WORK/fns.sh"
    echo "$1"
  } > "$NET_WORK/scenario.sh"
  NET_STATUS=0
  NET_OUT="$(bash "$NET_WORK/scenario.sh" 2>&1)" || NET_STATUS=$?
}
# resolve <existing> <persisted svc> <persisted pod> <persisted dns> -- the
# same sequence the install flow runs after parsing flags.
RESOLVE='
resolve() {
  reconcile_network_flag --service-cidr SERVICE_CIDR "$PERSISTED_SVC" "$DEFAULT_SERVICE_CIDR" || return 1
  reconcile_network_flag --cluster-cidr POD_CLUSTER_CIDR "$PERSISTED_POD" "$DEFAULT_POD_CLUSTER_CIDR" || return 1
  local d; d="$(default_cluster_dns "$SERVICE_CIDR")" || return 1
  reconcile_network_flag --cluster-dns CLUSTER_DNS "$PERSISTED_DNS" "$d" || return 1
  validate_network_config 0
}
PERSISTED_SVC=""; PERSISTED_POD=""; PERSISTED_DNS=""
'
K3S='SERVICE_CIDR=10.43.0.0/16; POD_CLUSTER_CIDR=10.42.0.0/16; CLUSTER_DNS=10.43.0.10'

net_run "$RESOLVE"'resolve && echo "$SERVICE_CIDR $POD_CLUSTER_CIDR $CLUSTER_DNS"'
assert "no flags resolves to today's 10.96.0.0/12, 10.244.0.0/16 and 10.96.0.10 -- an upgrade of an existing install must not move any range" \
  "$([ "$NET_STATUS" -eq 0 ] && [ "$NET_OUT" = "10.96.0.0/12 10.244.0.0/16 10.96.0.10" ] && echo 1 || echo 0)"

net_run "$RESOLVE"'SERVICE_CIDR=10.43.0.0/16; POD_CLUSTER_CIDR=10.42.0.0/16; resolve && echo "$CLUSTER_DNS"'
assert "k3s ranges without --cluster-dns derive 10.43.0.10, k3s's own DNS VIP, so a migrated pod's resolv.conf stays valid" \
  "$([ "$NET_STATUS" -eq 0 ] && [ "$NET_OUT" = "10.43.0.10" ] && echo 1 || echo 0)"

net_bad() {
  local why="$1" scenario="$2" expect="$3"
  net_run "$RESOLVE$scenario"
  assert "$why" "$([ "$NET_STATUS" -ne 0 ] && printf '%s' "$NET_OUT" | grep -qF -- "$expect" && echo 1 || echo 0)"
}
net_bad "a non-CIDR --service-cidr is refused by name instead of reaching the apiserver as a crash loop" \
  'SERVICE_CIDR=10.43.0.0; resolve' "--service-cidr '10.43.0.0' is not a CIDR"
net_bad "an octet above 255 is refused -- bash arithmetic would otherwise silently wrap it into a different range" \
  'SERVICE_CIDR=10.300.0.0/16; resolve' "not a valid IPv4 CIDR"
net_bad "a CIDR with host bits set is refused, since components disagree on which network it names" \
  'SERVICE_CIDR=10.43.1.0/16; resolve' "host bits set"
net_bad "a service range wider than /12 is refused, as upstream's apiserver refuses it" \
  'SERVICE_CIDR=10.0.0.0/8; resolve' "must be between /12 and /28"
net_bad "overlapping service and pod ranges are refused: a Service VIP would equal a pod IP" \
  'SERVICE_CIDR=10.43.0.0/16; POD_CLUSTER_CIDR=10.43.128.0/17; resolve' "overlap"
net_bad "a pod range narrower than the /24 per-node mask is refused instead of leaving KCM unable to allocate a node CIDR" \
  'POD_CLUSTER_CIDR=10.42.0.0/25; resolve' "must be between /8 and /24"
net_bad "a --cluster-dns outside --service-cidr is refused: the Service would sit outside the ServiceCIDR object" \
  "$K3S; CLUSTER_DNS=10.96.0.10; resolve" "not an allocatable host"
net_bad "--cluster-dns equal to the kubernetes Service VIP (.1) is refused: two Services cannot share a ClusterIP" \
  "$K3S; CLUSTER_DNS=10.43.0.1; resolve" "not an allocatable host"
net_bad "--cluster-dns on the broadcast address is refused" \
  "$K3S; CLUSTER_DNS=10.43.255.255; resolve" "not an allocatable host"
net_bad "a malformed --cluster-dns is refused" \
  "$K3S; CLUSTER_DNS=10.43.0; resolve" "--cluster-dns '10.43.0' is not a valid IPv4"

net_run "$RESOLVE$K3S"'; CLUSTER_DNS=10.43.0.53; resolve && echo "$CLUSTER_DNS"'
assert "an explicit --cluster-dns inside the range is honoured, not overwritten by the derived tenth host" \
  "$([ "$NET_STATUS" -eq 0 ] && [ "$NET_OUT" = "10.43.0.53" ] && echo 1 || echo 0)"

net_run 'CLUSTER_DNS=10.43.0.10; validate_network_config 1 && echo ok'
assert "a worker validates only --cluster-dns syntax (it has no service range to check against)" \
  "$([ "$NET_STATUS" -eq 0 ] && [ "$NET_OUT" = ok ] && echo 1 || echo 0)"

net_run 'SERVICE_CIDR=10.43.0.0/16; POD_CLUSTER_CIDR=10.42.0.0/16; check_node_ip_outside_ranges 10.43.4.4'
assert "a node address inside the service range is refused: the host would be unreachable behind its own Service routing" \
  "$([ "$NET_STATUS" -ne 0 ] && printf '%s' "$NET_OUT" | grep -qF 'inside 10.43.0.0/16' && echo 1 || echo 0)"
net_run 'SERVICE_CIDR=10.43.0.0/16; POD_CLUSTER_CIDR=10.42.0.0/16; check_node_ip_outside_ranges 192.168.1.5'
assert "a node address outside both ranges passes" "$([ "$NET_STATUS" -eq 0 ] && echo 1 || echo 0)"

# Re-install: values persisted by the first install are sticky.
net_run "$RESOLVE"'EXISTING_INSTALL=1; PERSISTED_SVC=10.43.0.0/16; PERSISTED_POD=10.42.0.0/16; PERSISTED_DNS=10.43.0.10; resolve && echo "$SERVICE_CIDR $POD_CLUSTER_CIDR $CLUSTER_DNS"'
assert "a bare re-run of a k3s-range install keeps the persisted ranges instead of reverting to the defaults" \
  "$([ "$NET_STATUS" -eq 0 ] && [ "$NET_OUT" = "10.43.0.0/16 10.42.0.0/16 10.43.0.10" ] && echo 1 || echo 0)"
net_bad "re-installing with a different --service-cidr is refused: live Services already hold ClusterIPs from the old range" \
  'EXISTING_INSTALL=1; PERSISTED_SVC=10.43.0.0/16; SERVICE_CIDR=10.96.0.0/12; resolve' "conflicts with the value in effect since install time (10.43.0.0/16"
net_bad "re-installing with a different --cluster-cidr is refused: node podCIDRs were already allocated from the old one" \
  'EXISTING_INSTALL=1; PERSISTED_POD=10.42.0.0/16; POD_CLUSTER_CIDR=10.244.0.0/16; resolve' "--cluster-cidr"
net_bad "re-installing with a different --cluster-dns is refused: every kubelet's clusterDNS and the CoreDNS Service hold the old VIP" \
  'EXISTING_INSTALL=1; PERSISTED_DNS=10.96.0.10; CLUSTER_DNS=10.96.0.53; resolve' "--cluster-dns"
net_bad "an install that predates persistence ran the defaults, so a non-default range on re-run is refused" \
  'EXISTING_INSTALL=1; SERVICE_CIDR=10.43.0.0/16; resolve' "10.96.0.0/12"
net_run "$RESOLVE"'EXISTING_INSTALL=1; SERVICE_CIDR=10.96.0.0/12; resolve && echo ok'
assert "re-passing the defaults to a pre-persistence install is accepted (it is what is already running)" \
  "$([ "$NET_STATUS" -eq 0 ] && [ "$NET_OUT" = ok ] && echo 1 || echo 0)"
net_run "$RESOLVE"'EXISTING_INSTALL=0; PERSISTED_SVC=10.43.0.0/16; SERVICE_CIDR=10.96.0.0/12; resolve && echo ok'
assert "a stale config left by a failed first attempt does not block a fresh install with different ranges" \
  "$([ "$NET_STATUS" -eq 0 ] && [ "$NET_OUT" = ok ] && echo 1 || echo 0)"

# Every consumer receives the same values: render the REAL vendored manifests
# and kubelet config with k3s ranges.
NET_DEST="$NET_WORK/rendered"
mkdir -p "$NET_DEST"
cp "$ROOT_DIR"/manifests/*.yaml "$NET_DEST/"
net_run "$K3S"'; IFACE=eth0; IFACE_IP=192.168.1.5; KUBE_VERSION=1.37.1
render_vendored_manifests "'"$NET_DEST"'" && echo rendered
STATE_DIR="'"$NET_WORK"'"; systemctl() { return 1; }
write_kubelet_config_yaml 0 && echo kubelet'
assert "rendering the real vendored manifests and kubelet config with k3s ranges succeeds" \
  "$([ "$NET_STATUS" -eq 0 ] && printf '%s' "$NET_OUT" | grep -qx rendered && printf '%s' "$NET_OUT" | grep -qx kubelet && echo 1 || echo 0)"
assert_true "flannel's net-conf Network is the --cluster-cidr" \
  grep -qF '"Network": "10.42.0.0/16"' "$NET_DEST/flannel.yaml"
assert_true "kube-proxy's clusterCIDR is the --cluster-cidr (it masquerades non-pod traffic to Services)" \
  grep -qx '    clusterCIDR: 10.42.0.0/16' "$NET_DEST/kube-proxy.yaml"
assert_true "beep's --pod-cidr is the --cluster-cidr" \
  grep -qF -- '--pod-cidr=10.42.0.0/16' "$NET_DEST/beep.yaml"
assert_true "the CoreDNS kube-dns Service clusterIP is the --cluster-dns" \
  grep -qx '  clusterIP: 10.43.0.10' "$NET_DEST/coredns.yaml"
assert "no rendered manifest keeps the old default service/pod/DNS addresses outside comments" \
  "$(grep -hv '^[[:space:]]*#' "$NET_DEST/flannel.yaml" "$NET_DEST/kube-proxy.yaml" "$NET_DEST/beep.yaml" "$NET_DEST/coredns.yaml" | grep -qE '10\.96\.0\.|10\.244\.0\.' && echo 0 || echo 1)"
assert_false "no rendered manifest keeps an unresolved __PLACEHOLDER__" \
  grep -qE '__[A-Z_]+__' "$NET_DEST/flannel.yaml" "$NET_DEST/kube-proxy.yaml" "$NET_DEST/beep.yaml"
assert_true "kubelet-config.yaml's clusterDNS is the --cluster-dns, so pods' resolv.conf points at the CoreDNS Service" \
  grep -qx '  - 10.43.0.10' "$NET_WORK/kubelet-config.yaml"

printf 'kind: Service\nspec:\n  clusterIP: 10.1.2.3\n' > "$NET_WORK/bad-coredns.yaml"
mkdir -p "$NET_WORK/bad" && cp "$NET_WORK/bad-coredns.yaml" "$NET_WORK/bad/coredns.yaml"
net_run "$K3S"'; render_vendored_manifests "'"$NET_WORK/bad"'"'
assert "a CoreDNS manifest whose clusterIP line changed shape fails the install instead of shipping the wrong DNS VIP" \
  "$([ "$NET_STATUS" -ne 0 ] && printf '%s' "$NET_OUT" | grep -qF "no 'clusterIP' line" && echo 1 || echo 0)"

# Units and persistence: structural, like the KCM assertions above.
assert_true "u7s-apiserver.service passes --service-cluster-ip-range and --kube-dns-cluster-ip from the resolved values (the apiserver derives the kubernetes Service VIP and ServiceCIDR from the range)" \
  grep -qF -- '--service-cluster-ip-range $SERVICE_CIDR --kube-dns-cluster-ip $CLUSTER_DNS' "$INSTALL"
assert_true "u7s-kcm.service passes --service-cluster-ip-range=\$SERVICE_CIDR next to --cluster-cidr" \
  grep -qF -- '--cluster-cidr=$POD_CLUSTER_CIDR --service-cluster-ip-range=$SERVICE_CIDR' "$INSTALL"
assert_true "the config file persists all three values so a re-run can detect a conflict" \
  grep -qF 'printf '"'"'SERVICE_CIDR="%s"\nPOD_CLUSTER_CIDR="%s"\n'"'" "$INSTALL"
assert_true "--mint-join-token prints --cluster-dns for a non-default cluster so a joining worker's kubelet gets the right DNS" \
  grep -qF 'dns_flag=" --cluster-dns $persisted_dns"' "$INSTALL"
assert_false "no hardcoded 10.96.0.10 / 10.244.0.0/16 assignment is left outside the defaults block" \
  grep -nE '^\s*(POD_CLUSTER_CIDR|CLUSTER_DNS)="?10\.' "$INSTALL"

# ---------------------------------------------------------------------------
# wait_for_cluster_ready: install must not exit 0 while the node or a
# kube-system workload it shipped is still pulling images, or the user's first
# apply competes with those pulls on a small disk. Extracted from install.sh
# and run against a fake kubectl; sleep is stubbed.
# ---------------------------------------------------------------------------
RDY_WORK="$(mktemp -d)"
trap 'rm -rf "$DETECT_WORK" "$MANIFEST_WORK" "$NET_WORK" "$RDY_WORK"' EXIT
mkdir -p "$RDY_WORK/bin"
cat > "$RDY_WORK/bin/kubectl" <<'FAKE'
#!/usr/bin/env bash
# Models the fields the readiness check reads. Knobs:
#   FAKE_NODE_READY      node Ready status (default True)
#   FAKE_READY_AFTER     kube-proxy DaemonSet reports 0 ready for this many
#                        gets (or "never")
#   FAKE_COREDNS_OBS     coredns status.observedGeneration (generation is 2);
#                        counters stay "ready" to model a stale status
#   FAKE_COREDNS_POD2    Ready status of the second coredns pod
#   FAKE_COREDNS_POD2_TERMINATING  set => second coredns pod has deletionTimestamp
#   FAKE_DS_DESIRED      desiredNumberScheduled of the DaemonSets (default 1)
#   FAKE_ERR             every call fails like an unreachable/NotFound API
#   FAKE_CALL_SLEEP      every call takes this many real seconds
# Pods are only returned for the exact selector the object's spec carries, so
# a check that hard-codes labels sees no pods.
args="$*"
[ -n "${FAKE_CALL_SLEEP:-}" ] && sleep "$FAKE_CALL_SLEEP"
if [ -n "${FAKE_ERR:-}" ]; then echo 'Error from server (NotFound): not found' >&2; exit 1; fi
sel=""; prev=""
for a in "$@"; do [ "$prev" = "-l" ] && sel="$a"; prev="$a"; done
case "$args" in
  *"get node"*) echo "${FAKE_NODE_READY:-True}" ;;
  *"get deployment/coredns"*)
    printf '2|%s|2|2|2|2|True|{"k8s-app":"kube-dns"}' "${FAKE_COREDNS_OBS:-2}" ;;
  *"get daemonset/"*)
    name="${args##*get daemonset/}"; name="${name%% *}"
    d="${FAKE_DS_DESIRED:-1}"; r="$d"
    if [ "$name" = kube-proxy ]; then
      n=$(( $(cat "$FAKE_STATE" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$FAKE_STATE"
      if [ "${FAKE_READY_AFTER:-0}" = never ] || [ "$n" -le "${FAKE_READY_AFTER:-0}" ]; then r=0; fi
    fi
    printf '1|1|%s|%s|%s|%s|{"k8s-app":"%s","tier":"node"}' "$d" "$d" "$r" "$r" "$name" ;;
  *"get pods"*)
    case "$sel" in
      "k8s-app=kube-dns")
        echo "|True"
        if [ -n "${FAKE_COREDNS_POD2_TERMINATING:-}" ]; then echo "2026-01-01T00:00:00Z|True"; else echo "|${FAKE_COREDNS_POD2:-True}"; fi ;;
      "k8s-app="*",tier=node") if [ "${FAKE_DS_DESIRED:-1}" -gt 0 ]; then echo "|True"; fi ;;
    esac ;;
  *) exit 1 ;;
esac
FAKE
chmod +x "$RDY_WORK/bin/kubectl"
{
  echo 'set -uo pipefail'
  echo 'STATE_DIR=/nonexistent; NODE_NAME=n1'
  echo 'sleep() { SECONDS=$(( SECONDS + $1 )); echo "$1" >> "$FAKE_STATE.sleeps"; }'
  grep -E '^(READY_POLL_SECONDS|READY_PROGRESS_EVERY|READY_DEADLINE)=' "$INSTALL"
  for fn in ready_kubectl workload_is_ready wait_for_cluster_ready; do
    awk -v f="$fn() {" '$0 == f {p=1} p {print} p && /^}$/ {exit}' "$INSTALL"
  done
  echo 'CLUSTER_WORKLOADS="kube-system/deployment/coredns kube-system/daemonset/kube-proxy kube-system/daemonset/servicelb-controller"'
  echo 'wait_for_cluster_ready'
} > "$RDY_WORK/scenario.sh"
rdy_run() {
  rm -f "$RDY_WORK/state" "$RDY_WORK/state.sleeps"
  RDY_STATUS=0
  RDY_OUT="$(PATH="$RDY_WORK/bin:$PATH" FAKE_STATE="$RDY_WORK/state" "$@" bash "$RDY_WORK/scenario.sh" 2>&1)" || RDY_STATUS=$?
}
rdy_not_ready() { # $1 = exactly the items that must be named unready
  [ "$RDY_STATUS" -ne 0 ] && printf '%s' "$RDY_OUT" | grep -qF "not Ready after 10s: $1" && echo 1 || echo 0
}
assert "the wait scenario was extracted with the real functions (if this fails the wait tests below test nothing)" \
  "$(grep -q 'workload_is_ready()' "$RDY_WORK/scenario.sh" && grep -q 'ready_kubectl()' "$RDY_WORK/scenario.sh" && grep -q '^READY_POLL_SECONDS=' "$RDY_WORK/scenario.sh" && echo 1 || echo 0)"

rdy_run env FAKE_READY_AFTER=0 U7S_READY_TIMEOUT_SECONDS=600
assert "everything Ready (counters, generation, selected pods) exits 0 so install may report done" \
  "$([ "$RDY_STATUS" -eq 0 ] && printf '%s' "$RDY_OUT" | grep -qF 'all vendored workloads are Ready' && echo 1 || echo 0)"

rdy_run env FAKE_READY_AFTER=3 U7S_READY_TIMEOUT_SECONDS=600
assert "install keeps polling while a workload is not ready and returns 0 only once it is, so a user's first apply never races our image pulls" \
  "$([ "$RDY_STATUS" -eq 0 ] && [ "$(cat "$RDY_WORK/state")" -eq 4 ] && printf '%s' "$RDY_OUT" | grep -qF 'still waiting' && printf '%s' "$RDY_OUT" | grep -qF 'kube-system/daemonset/kube-proxy' && echo 1 || echo 0)"

rdy_run env FAKE_READY_AFTER=never U7S_READY_TIMEOUT_SECONDS=20
assert "a workload that never becomes ready fails the install non-zero, naming only it with a describe hint -- no silent success" \
  "$([ "$RDY_STATUS" -ne 0 ] && printf '%s' "$RDY_OUT" | grep -qF 'not Ready after 20s: kube-system/daemonset/kube-proxy' && printf '%s' "$RDY_OUT" | grep -qF 'describe daemonset/kube-proxy' && ! printf '%s' "$RDY_OUT" | grep -qF 'describe deployment/coredns' && echo 1 || echo 0)"
assert "the timeout is bounded by the configured seconds (20s at 5s polls = 4 sleeps), not unbounded" \
  "$([ "$(wc -l < "$RDY_WORK/state.sleeps")" -eq 4 ] && echo 1 || echo 0)"

rdy_run env FAKE_NODE_READY=False U7S_READY_TIMEOUT_SECONDS=10
assert "a node that is not Ready fails the install even when every workload is ready" \
  "$([ "$(rdy_not_ready node/n1)" = 1 ] && printf '%s' "$RDY_OUT" | grep -qF 'describe node n1' && echo 1 || echo 0)"

rdy_run env FAKE_COREDNS_OBS=1 U7S_READY_TIMEOUT_SECONDS=10
assert "stale Deployment status (observedGeneration < generation, counters still 'ready') is not ready: that is the false done after a restart" \
  "$(rdy_not_ready kube-system/deployment/coredns)"

rdy_run env FAKE_COREDNS_POD2=False U7S_READY_TIMEOUT_SECONDS=10
assert "counters say ready but a selected pod is Ready=False: not ready, because controller counters lag real pod state" \
  "$(rdy_not_ready kube-system/deployment/coredns)"

rdy_run env FAKE_COREDNS_POD2_TERMINATING=1 U7S_READY_TIMEOUT_SECONDS=10
assert "a Terminating pod that still reports Ready is not ready" \
  "$(rdy_not_ready kube-system/deployment/coredns)"

rdy_run env FAKE_DS_DESIRED=0 U7S_READY_TIMEOUT_SECONDS=10
assert "a DaemonSet with desiredNumberScheduled=0 is not ready: zero pods trivially match every counter, but nothing runs" \
  "$(rdy_not_ready 'kube-system/daemonset/kube-proxy kube-system/daemonset/servicelb-controller')"

rdy_run env FAKE_ERR=1 U7S_READY_TIMEOUT_SECONDS=10
assert "kubectl errors / NotFound on every call are never treated as ready: polling continues, then exit 1 naming every item" \
  "$(rdy_not_ready 'node/n1 kube-system/deployment/coredns kube-system/daemonset/kube-proxy kube-system/daemonset/servicelb-controller')"

rdy_start=$SECONDS
rdy_run env FAKE_CALL_SLEEP=2 FAKE_READY_AFTER=never U7S_READY_TIMEOUT_SECONDS=5
rdy_elapsed=$(( SECONDS - rdy_start ))
assert "the deadline is wall time checked before every kubectl call: with 2s calls and a 5s bound the wait ends within one call of it (took ${rdy_elapsed}s), not after a full poll's worth of calls" \
  "$([ "$RDY_STATUS" -ne 0 ] && [ "$rdy_elapsed" -le 8 ] && echo 1 || echo 0)"

rdy_run env U7S_READY_TIMEOUT_SECONDS=abc
assert "a malformed U7S_READY_TIMEOUT_SECONDS is rejected rather than silently treated as 0" \
  "$([ "$RDY_STATUS" -ne 0 ] && printf '%s' "$RDY_OUT" | grep -qF 'must be a whole number' && echo 1 || echo 0)"

# Structural: the workload list is what the vendored manifests actually ship,
# and only the control-plane path waits (a worker's node identity cannot read
# workloads; its own Ready+serving-cert wait is wait_for_joined_node).
wl_line="$(grep -F 'CLUSTER_WORKLOADS="kube-system' "$INSTALL")"
wl_ok=1
for spec in "coredns.yaml Deployment coredns" "kube-proxy.yaml DaemonSet kube-proxy" "beep.yaml DaemonSet servicelb-controller" "flannel.yaml DaemonSet kube-flannel-ds"; do
  read -r f k n <<< "$spec"
  awk -v k="$k" '$0=="kind: " k {s=1} s && /^  name: / {print $2; exit}' "$ROOT_DIR/manifests/$f" | grep -qx "$n" || wl_ok=0
  printf '%s' "$wl_line" | grep -qF "/$(printf '%s' "$k" | tr '[:upper:]' '[:lower:]')/$n" || wl_ok=0
done
assert "CLUSTER_WORKLOADS lists exactly the Deployment/DaemonSets the vendored manifests define (a new or renamed workload must be waited on)" "$wl_ok"
assert "no vendored manifest defines a Deployment/DaemonSet/StatefulSet beyond the four waited on" \
  "$([ "$(grep -hE '^kind: (Deployment|DaemonSet|StatefulSet)$' "$ROOT_DIR"/manifests/*.yaml | wc -l)" -eq 4 ] && echo 1 || echo 0)"
assert "the control-plane install waits after labelling the node, as its last step before reporting success" \
  "$(awk '/^label_control_plane_node \|\| exit 1$/ {l=NR} /^wait_for_cluster_ready \|\| exit 1$/ {w=NR} /^echo "u7s bootstrap complete/ {b=NR} END {print (l && w>l && b>w) ? 1 : 0}' "$INSTALL")"
assert "the worker path (which exits before the control-plane steps) never calls wait_for_cluster_ready" \
  "$(awk '/^if \[ "\$WORKER_MODE" -eq 1 \]; then$/ {w=1} w && /^  exit 0$/ {exit} w && /wait_for_cluster_ready/ {bad=1} END {print bad ? 0 : 1}' "$INSTALL")"

# --- control-plane memory protection ------------------------------------------
# Without these, a memory-starved 1 GiB node reclaims the control-plane
# binaries' own mapped pages first and thrashes until the kubelet misses its
# lease. MemoryLow only works if every ancestor cgroup has a low too, so the
# units must sit in u7s.slice and its low must cover their sum.
MEM_WORK="$(mktemp -d)"
trap 'rm -rf "$DETECT_WORK" "$WORKER_MODE_WORK" "$MANIFEST_WORK" "$PERSIST_WORK" "$RESOLV_WORK" "$MEM_WORK"' EXIT
{
  grep -E '^MEMLOW_[A-Z]+_MIB=' "$INSTALL"
  echo 'SYSTEMD_DIR="$1"'
  awk '/^write_memory_protection\(\) \{$/,/^}$/' "$INSTALL" | sed 's|/etc/systemd/system|$SYSTEMD_DIR|g'
  echo 'write_memory_protection "$2"'
} > "$MEM_WORK/runner.sh"
mkdir -p "$MEM_WORK/cp" "$MEM_WORK/worker"
bash "$MEM_WORK/runner.sh" "$MEM_WORK/cp" 0
bash "$MEM_WORK/runner.sh" "$MEM_WORK/worker" 1
mib() { grep -m1 "^$1=" "$INSTALL" | cut -d= -f2; }
cp_low=$(( $(mib MEMLOW_APISERVER_MIB) + $(mib MEMLOW_KCM_MIB) + $(mib MEMLOW_KUBELET_MIB) + $(mib MEMLOW_CRIO_MIB) ))
worker_low=$(( $(mib MEMLOW_KUBELET_MIB) + $(mib MEMLOW_CRIO_MIB) ))
assert_true "the control-plane u7s.slice low equals the sum of its units' lows, otherwise a unit's own low is capped by the slice and part of it is silently unprotected" \
  grep -qxF "MemoryLow=${cp_low}M" "$MEM_WORK/cp/u7s.slice"
assert_true "an agent node's u7s.slice protects kubelet and crio only (no apiserver/KCM run there, so reserving their share would shield nothing)" \
  grep -qxF "MemoryLow=${worker_low}M" "$MEM_WORK/worker/u7s.slice"
assert_true "u7s.slice keeps memory accounting on, or the kernel has no per-cgroup memory to protect" \
  grep -qxF 'MemoryAccounting=yes' "$MEM_WORK/cp/u7s.slice"
for mode in cp worker; do
  assert_true "crio.service ($mode) is moved into u7s.slice by a drop-in (the vendor unit is not rewritten) so its low is honoured" \
    grep -qxF 'Slice=u7s.slice' "$MEM_WORK/$mode/crio.service.d/10-u7s-memory.conf"
  assert_true "crio.service ($mode) drop-in sets its own MemoryLow" \
    grep -qxF "MemoryLow=$(mib MEMLOW_CRIO_MIB)M" "$MEM_WORK/$mode/crio.service.d/10-u7s-memory.conf"
done
assert_false "no MemoryMin anywhere: a hard minimum oversized on a 1 GiB node OOM-kills everything else instead of degrading" \
  grep -rq 'MemoryMin' "$MEM_WORK" "$INSTALL"

apiserver_block="$(awk '/^cat > \/etc\/systemd\/system\/u7s-apiserver\.service <<EOF$/{f=1} f{print} f&&/^EOF$/{exit}' "$INSTALL")"
kcm_block="$(awk '/^cat > \/etc\/systemd\/system\/u7s-kcm\.service <<EOF$/{f=1} f{print} f&&/^EOF$/{exit}' "$INSTALL")"
for pair in 'u7s-apiserver:apiserver_block:MEMLOW_APISERVER_MIB' 'u7s-kcm:kcm_block:MEMLOW_KCM_MIB' \
  'worker kubelet:kubelet_worker_block:MEMLOW_KUBELET_MIB' 'control-plane kubelet:kubelet_cp_block:MEMLOW_KUBELET_MIB'; do
  name="${pair%%:*}"; rest="${pair#*:}"; var="${rest%%:*}"; low="${rest#*:}"
  assert_true "$name unit joins u7s.slice with its own MemoryLow and accounting (a unit outside the slice gets no protection)" \
    bash -c 'b="$1"; printf "%s\n" "$b" | grep -qxF "Slice=u7s.slice" && printf "%s\n" "$b" | grep -qxF "MemoryAccounting=yes" && printf "%s\n" "$b" | grep -qxF "MemoryLow=\${$2}M"' _ "${!var}" "$low"
done
assert_false "the agent (worker) path must not give apiserver or KCM a slice: they do not run there" \
  bash -c 'printf "%s\n" "$1" | grep -q "u7s-apiserver\|u7s-kcm"' _ "$kubelet_worker_block"

mkdir -p "$MEM_WORK/kc-cp" "$MEM_WORK/kc-worker"
{
  echo 'STATE_DIR="$1"; CLUSTER_DNS=10.43.0.10'
  awk '/^write_kubelet_config_yaml\(\) \{$/,/^}$/' "$INSTALL"
  echo 'write_kubelet_config_yaml "$2"'
} > "$MEM_WORK/kc-runner.sh"
PATH="$RESOLV_WORK/bin-inactive:$PATH" bash "$MEM_WORK/kc-runner.sh" "$MEM_WORK/kc-cp" 0
PATH="$RESOLV_WORK/bin-inactive:$PATH" bash "$MEM_WORK/kc-runner.sh" "$MEM_WORK/kc-worker" 1
assert_true "kubelet reserves system and kube memory so pods cannot be scheduled into the daemons' share" \
  awk '/^systemReserved:/{s=1} /^kubeReserved:/{k=1} END{exit !(s&&k)}' "$MEM_WORK/kc-cp/kubelet-config.yaml"
reserved_mi() { awk -v k="$2:" '$0==k{getline; sub(/Mi$/,"",$2); print $2}' "$1"; }
cp_sys="$(reserved_mi "$MEM_WORK/kc-cp/kubelet-config.yaml" systemReserved)"
worker_sys="$(reserved_mi "$MEM_WORK/kc-worker/kubelet-config.yaml" systemReserved)"
assert "kubelet and crio are reserved on every node, including a worker" \
  "$([ -n "$(reserved_mi "$MEM_WORK/kc-worker/kubelet-config.yaml" kubeReserved)" ] && echo 1 || echo 0)"
assert "worker systemReserved is smaller than the control plane's (no apiserver/KCM on an agent) but nonzero (the OS still needs memory)" \
  "$([ -n "$worker_sys" ] && [ "$worker_sys" -gt 0 ] && [ "$worker_sys" -lt "$cp_sys" ] && echo 1 || echo 0)"
assert_true "allocatable is enforced on pods only" \
  awk '/^enforceNodeAllocatable:/{f=1;next} f&&/^  - /{n++; if($2!="pods")bad=1; next} {f=0} END{exit !(n==1&&!bad)}' "$MEM_WORK/kc-cp/kubelet-config.yaml"
assert_false "enforcing system-reserved/kube-reserved would cap the daemons themselves and starve the control plane the reservation is meant to protect" \
  grep -qE 'system-reserved|kube-reserved' "$MEM_WORK/kc-cp/kubelet-config.yaml" "$MEM_WORK/kc-worker/kubelet-config.yaml"

echo ""
echo "Results:${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
