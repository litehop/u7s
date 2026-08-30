#!/usr/bin/env bash
# Drives the WordPress+MariaDB E2E workload (examples/e2e/wordpress/) to prove the
# nginx -> php-fpm -> MariaDB -> HTTP write path works on a running u7s cluster,
# from committed manifests only -- no hand-hacking, no reliance on prior VM state.
#
# Requires: kubectl pointed at a u7s cluster that already has csi-hostpath v1.17.1
# installed (see examples/e2e/wordpress/README.md -- this script does not install
# csi-hostpath itself).
#
# Requires a WordPress database with no prior install: this script asserts the
# *installer* flow (GET / -> 302 -> install.php). If MariaDB already has WordPress
# tables from a previous run, WordPress skips the installer and step 1's 302
# assertion will fail. To reset: `kubectl delete -f examples/e2e/wordpress/ &&
# kubectl delete pvc -l app.kubernetes.io/name=mariadb` (the StatefulSet's
# persistentVolumeClaimRetentionPolicy is Retain, so the PVC must be deleted
# explicitly to get a fresh, empty MariaDB data directory).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_DIR="$(cd "$SCRIPT_DIR/../../examples/e2e/wordpress" && pwd)"
NAMESPACE="default"
KUBECTL_ARGS=()
SKIP_APPLY=0
LOCAL_PORT="${WORDPRESS_SMOKE_LOCAL_PORT:-18080}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--kubeconfig PATH] [--skip-apply]

  --kubeconfig PATH   Passed through as 'kubectl --kubeconfig PATH ...'.
  --skip-apply        Assume examples/e2e/wordpress/ is already applied and
                       Ready; only run the HTTP assertions.

Applies examples/e2e/wordpress/, waits for MariaDB + WordPress to become Ready,
then asserts: GET / -> 302, GET /wp-admin/install.php -> 200,
POST install.php?step=2 -> body contains "Success!", final GET / renders the
submitted site title. Exits non-zero on any failed assertion.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig)
      KUBECTL_ARGS=(--kubeconfig "$2")
      shift 2
      ;;
    --skip-apply)
      SKIP_APPLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

kc() {
  # ${KUBECTL_ARGS[@]+"${KUBECTL_ARGS[@]}"} (not a bare "${KUBECTL_ARGS[@]}") is the
  # bash-3.2-safe empty-array idiom -- macOS's stock /bin/bash is 3.2, where a plain
  # "${arr[@]}" on an empty array trips `set -u`'s unbound-variable check. This is
  # the script's default invocation (no --kubeconfig), so it must not crash there.
  kubectl "${KUBECTL_ARGS[@]+"${KUBECTL_ARGS[@]}"}" "$@"
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

PF_PID=""
JAR=""
cleanup() {
  [[ -n "$PF_PID" ]] && kill "$PF_PID" >/dev/null 2>&1 || true
  [[ -n "$JAR" ]] && rm -f "$JAR"
}
trap cleanup EXIT

if [[ "$SKIP_APPLY" -eq 0 ]]; then
  echo "== applying $MANIFEST_DIR =="
  kc apply -f "$MANIFEST_DIR"
fi

echo "== waiting for mariadb-0 to become Ready =="
kc -n "$NAMESPACE" wait --for=condition=Ready pod/mariadb-0 --timeout=300s \
  || fail "mariadb-0 never became Ready"

echo "== waiting for the pehelypress Deployment to become Available =="
kc -n "$NAMESPACE" wait --for=condition=Available deployment/pehelypress --timeout=300s \
  || fail "pehelypress Deployment never became Available"

echo "== port-forwarding to svc/pehelypress:80 =="
kc -n "$NAMESPACE" port-forward svc/pehelypress "$LOCAL_PORT:80" \
  >/tmp/wordpress-smoke-port-forward.log 2>&1 &
PF_PID=$!

BASE="http://127.0.0.1:$LOCAL_PORT"
for _ in $(seq 1 30); do
  curl -s -o /dev/null "$BASE/" && break
  sleep 1
done
curl -s -o /dev/null "$BASE/" || fail "port-forward to svc/pehelypress never came up (see /tmp/wordpress-smoke-port-forward.log)"

JAR="$(mktemp)"

echo "== GET / (expect 302 to the installer -- fresh, uninstalled WordPress) =="
STATUS="$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" "$BASE/")"
[[ "$STATUS" == "302" ]] || fail "GET / returned $STATUS, expected 302 (is WordPress already installed? see this script's header comment)"

echo "== GET /wp-admin/install.php (expect 200) =="
STATUS="$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" "$BASE/wp-admin/install.php")"
[[ "$STATUS" == "200" ]] || fail "GET /wp-admin/install.php returned $STATUS, expected 200"

SITE_TITLE="u7s-e2e-smoke-$(date +%s)"
echo "== POST /wp-admin/install.php?step=2 (expect body to contain 'Success!') =="
BODY="$(curl -s -b "$JAR" -c "$JAR" \
  --data-urlencode "weblog_title=$SITE_TITLE" \
  --data-urlencode "user_name=admin" \
  --data-urlencode "admin_password=SmokeTestPassw0rd!" \
  --data-urlencode "admin_password2=SmokeTestPassw0rd!" \
  --data-urlencode "admin_email=admin@example.invalid" \
  --data-urlencode "Submit=Install WordPress" \
  --data-urlencode "language=" \
  "$BASE/wp-admin/install.php?step=2")"
echo "$BODY" | grep -q "Success!" || fail "install POST response did not contain 'Success!' -- WordPress install did not complete"
echo "  -> Success! (install completed, site title: $SITE_TITLE)"

echo "== GET / (expect the rendered page to contain the submitted site title) =="
# WordPress flaps briefly (500/301) for a few seconds right after install.php's
# step=2 returns "Success!" (observed cause: wp_mail()'s new-admin-email notice
# fails to reach a nonexistent local sendmail, mid-request) before settling into
# steady-state 200s -- retry instead of treating that startup flap as a failure.
FOUND=0
for _ in $(seq 1 15); do
  FINAL_BODY="$(curl -s -b "$JAR" -c "$JAR" "$BASE/")"
  if echo "$FINAL_BODY" | grep -qF "$SITE_TITLE"; then
    FOUND=1
    break
  fi
  sleep 2
done
[[ "$FOUND" -eq 1 ]] \
  || fail "final GET / does not contain submitted site title '$SITE_TITLE' -- the MariaDB write did not round-trip back out"
echo "  -> rendered title '$SITE_TITLE' found in final GET / body"

echo "PASS: WordPress E2E HTTP round-trip verified end to end (nginx -> php-fpm -> MariaDB -> HTTP)."
