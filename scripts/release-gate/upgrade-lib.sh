#!/usr/bin/env bash
# Check library for the upgrade-from-previous-release gate (sourced, not executed): the pure
# decision logic shared by the host driver (upgrade-gate.sh) and the in-guest driver
# (upgrade-vm.sh). Tests: test-upgrade-gate-logic.sh.
#
# Results file format (key=value lines, first match wins, see rg_get in lib.sh):
#   <check>=1|0                 one of UG_CHECKS
#   <check>_detail=TEXT         what was observed
#   done=1                      the guest driver ran to the end
#   harness_error=TEXT          the run could not be judged (previous release failed to install,
#                               node never Ready, ...): INVALID, not a u7s FAIL

# An API outage longer than this fails the upgrade; below it the gap is only reported.
UG_MAX_DOWNTIME_SECS="${UG_MAX_DOWNTIME_SECS:-60}"

# check-key|verdict label, in report order.
UG_CHECKS="cand_install|candidate install.sh exits 0
node_ready|node Ready after the upgrade
version|server version changed to the candidate's
ca|CA (ca.key, ca.crt) preserved
sa_pub|service-account public keyring (sa.pub) preserved
marker|workload marker readable after the upgrade
workload|Deployment and DaemonSet pods keep their UIDs, no new restarts
downtime|API /readyz outage within bound
rerun_install|candidate install.sh re-run exits 0
rerun_quiet|re-run recreates and restarts nothing, API stays up"

# Newest non-snapshot release tag before the candidate; non-zero if there is none. HEAD sitting
# exactly on a release tag is the candidate itself, so the search starts from its parent.
ug_default_from() {
  local base=HEAD
  git describe --tags --exact-match --exclude '*-snapshot*' HEAD >/dev/null 2>&1 && base=HEAD^
  git describe --tags --abbrev=0 --exclude '*-snapshot*' "$base" 2>/dev/null
}

# $1 hashes-pre, $2 hashes-post ("<sha256>  <file>" lines), $3 file name. Exit 0 only if the file
# was hashed before and the hash is identical after; a file missing from both is not preserved.
ug_hash_preserved() {
  local pre post
  pre="$(grep " $3\$" "$1" | cut -d' ' -f1)"
  post="$(grep " $3\$" "$2" | cut -d' ' -f1)"
  [ -n "$pre" ] && [ "$pre" = "$post" ]
}

ug_tag_valid() { [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; }

# Echoes why the server version does not prove the candidate is running, or nothing.
# $1 before, $2 after, $3 the release string the candidate was stamped with (U7S_RELEASE,
# e.g. 0.4.7-snapshot.2), empty to skip the name check.
ug_version_problem() {
  local pre="$1" post="$2" expect="$3"
  if [ -z "$pre" ] || [ -z "$post" ]; then echo "server version unreadable (before='$pre' after='$post')"; return; fi
  if [ "$pre" = "$post" ]; then echo "server version unchanged ($post): the old binary is still serving"; return; fi
  case "$post" in
    *"+u7s-$expect") ;;
    *) [ -z "$expect" ] || echo "server version $post is not the candidate (expected +u7s-$expect)" ;;
  esac
}

# $1 file of "<epoch> <http code>" /readyz samples, $2/$3 window start/end epochs.
# Echoes "max_gap=<s> failed=<n> samples=<n>": the longest time between consecutive 200s inside
# the window (upper bound of the outage; a healthy 2 s poll shows 2-4), the non-200 samples, and
# the sample count. The gap runs from the window start to the first 200 and from the last 200 to
# the window end too; no 200 at all reports the whole window as the gap.
ug_downtime_summary() {
  awk -v from="$2" -v to="$3" '
    $1 >= from && $1 <= to {
      n++
      if ($2 == 200) { if ($1 - (seen ? prev : from) > gap) gap = $1 - (seen ? prev : from); prev = $1; seen = 1 }
      else failed++
    }
    END {
      if (!seen) gap = to - from
      else if (to - prev > gap) gap = to - prev
      printf "max_gap=%d failed=%d samples=%d\n", gap, failed, n
    }' "$1"
}

# $1 summary from ug_downtime_summary; exit 0 if the outage is within UG_MAX_DOWNTIME_SECS.
ug_downtime_ok() {
  local gap
  gap="$(sed -n 's/^max_gap=\([0-9]*\).*/\1/p' <<<"$1")"
  [ -n "$gap" ] && [ "$gap" -le "$UG_MAX_DOWNTIME_SECS" ]
}

# $1 before, $2 after: files of "<ns>/<name> <uid> <comma-separated restart counts>" per pod.
# Echoes one line per pod that was recreated or restarted since; nothing means continuity.
# Pods new in $2 are ignored.
ug_continuity_problems() {
  awk '
    function sum(s,   a, n, i, t) { n = split(s, a, ","); for (i = 1; i <= n; i++) t += a[i]; return t + 0 }
    NR == FNR { uid[$1] = $2; rs[$1] = sum($3); next }
    { seen[$1] = 1
      if ($1 in uid && $2 != uid[$1]) bad[$1] = "recreated (uid " uid[$1] " -> " $2 ")"
      else if ($1 in uid && sum($3) > rs[$1]) bad[$1] = "restarted (" rs[$1] " -> " sum($3) ")" }
    END {
      for (k in uid) if (!(k in seen)) bad[k] = "gone"
      for (k in bad) print k ": " bad[k]
    }' "$1" "$2" | sort
}

# Prints the verdict table for results file $1; returns 1 if any check failed or was not reached.
ug_verdict() {
  local f="$1" key label v detail bad=0
  while IFS='|' read -r key label; do
    v="$(rg_get "$f" "$key")"; detail="$(rg_get "$f" "${key}_detail")"
    case "$v" in
      1) printf 'PASS  %s%s\n' "$label" "${detail:+ ($detail)}" ;;
      0) printf 'FAIL  %s%s\n' "$label" "${detail:+ ($detail)}"; bad=1 ;;
      *) printf 'FAIL  %s (not reached)\n' "$label"; bad=1 ;;
    esac
  done <<<"$UG_CHECKS"
  [ "$bad" = 0 ]
}

# Exit status of the whole run from results file $1: 0 PASS, 1 FAIL, 3 INVALID.
ug_run_status() {
  local f="$1"
  if [ -n "$(rg_get "$f" harness_error)" ]; then return 3; fi
  [ "$(rg_get "$f" "done")" = 1 ] || return 3
  ug_verdict "$f" >/dev/null
}
