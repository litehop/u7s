#!/usr/bin/env bash
# Sourced library (copied onto the VM by 04-start-kcm.sh): wait for the apiserver to publish
# kube-system/extension-apiserver-authentication, which KCM's delegated authn/authz needs at start.
#
# wait_for_auth_configmap <kubeconfig>
#   KCM_AUTH_CM_TRIES (default 60) x KCM_AUTH_CM_INTERVAL seconds (default 2).
#   Returns 1 when the ConfigMap never appears.
wait_for_auth_configmap() {
  local kubeconfig="$1" tries="${KCM_AUTH_CM_TRIES:-60}" interval="${KCM_AUTH_CM_INTERVAL:-2}" i
  for ((i = 0; i < tries; i++)); do
    if kubectl --kubeconfig="$kubeconfig" -n kube-system get configmap extension-apiserver-authentication >/dev/null 2>&1; then
      return 0
    fi
    sleep "$interval"
  done
  echo "error: kube-system/extension-apiserver-authentication was not published within $((tries * interval))s (check the apiserver log); KCM needs it for delegated authn/authz" >&2
  return 1
}
