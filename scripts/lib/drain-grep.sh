# shellcheck shell=bash
# `producer | grep -q` under `set -o pipefail` false-FAILs when grep exits on
# the first match and the producer dies of SIGPIPE (141) on its next write.
# drain_grep is grep that keeps reading its stdin to EOF, so the producer
# always finishes; the pipeline's status is grep's own.
drain_grep() {
  local rc=0
  grep "$@" || rc=$?
  cat >/dev/null
  return "$rc"
}
export -f drain_grep
