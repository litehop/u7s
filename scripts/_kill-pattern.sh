#!/usr/bin/env bash
# Sourced library: the `pkill -f` / `pgrep -f` ERE patterns that scope a kill to
# ONE u7s workdir.
#
# The workdir is ERE-escaped and preceded by a ' ' or '=' (the argv separators
# of `--flag <path>` / `--flag=<path>`) so a workdir that is a path-suffix of
# another live one (/a/wt vs /x/a/wt) cannot match the other stack's process,
# and regex metacharacters in the path match only themselves. The
# konnectivity-server pattern ends the workdir at a separator so /temp/u7s does
# not match /temp/u7s2.

# workdir_kill_pattern <apiserver|scheduler|konnectivity-server|sample-run-metrics> <workdir>
# workdir_kill_pattern lima-hostagent <path-to-ha.sock>   (the path is the whole last argv word)
workdir_kill_pattern() {
  local proc_type="$1" workdir="$2" esc
  esc=$(printf '%s' "$workdir" | sed -E 's/[][\.*^$+?(){}|\\]/\\&/g')
  case "$proc_type" in
    apiserver) printf 'u7s-apiserver.*[ =]%s/kubeconfig' "$esc" ;;
    scheduler) printf 'u7s-scheduler.*[ =]%s/kubeconfig' "$esc" ;;
    konnectivity-server) printf 'konnectivity-server.*[ =]%s([/ ]|$)' "$esc" ;;
    lima-hostagent) printf 'limactl hostagent.*[ =]%s( |$)' "$esc" ;;
    sample-run-metrics) printf 'sample-run-metrics.sh.*[ =]%s([/ ]|$)' "$esc" ;;
    *) echo "workdir_kill_pattern: unknown process type '$proc_type'" >&2; return 1 ;;
  esac
}
