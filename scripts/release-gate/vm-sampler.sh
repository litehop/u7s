#!/usr/bin/env bash
# Runs inside the gate VM (as root). Every INTERVAL seconds appends to $OUT/samples.tsv:
#   <epoch>\t<phase>\tMEM\t<MemAvailable kB>
#   <epoch>\t<phase>\t<component>\t<PSS kB>\t<RSS kB>     (summed over all pids of a comm)
# and to $OUT/attrib.tsv, <epoch>\t<phase>\t<kind>\t<fields>, all cumulative (diff consecutive rows):
#   PSI   <cpu|io|memory> <some_total_us> <full_total_us>
#   STAT  <user+nice> <system> <iowait> <steal>                     (jiffies, /proc/stat)
#   DISK  <dev> <rd_ios> <rd_sectors> <wr_ios> <wr_sectors> <io_ms>
#   CG    <cgroup> <usage_usec> <throttled_usec>                    (root, top slices+scopes, system.slice/*, kubepods.slice/*)
#   CGIO  <cgroup> <rbytes> <wbytes> <rios> <wios>
#   PROC  <pid> <comm> <cpu_jiffies> <read_bytes> <write_bytes>     (pids with any activity, only every
#         SAMPLER_PROC_INTERVAL=30 s: the walk reads 2 files per pid; reaped children's
#         IO is folded into the parent, their CPU is not, so use CG for CPU attribution)
# <phase> is the current content of $OUT/phase. Pure /proc reads: no kubectl, no forks
# beyond pgrep and one awk per sample, so the probe stays cheap on a 1 vCPU box.
# SAMPLER_ROOT prefixes /proc and /sys, SAMPLER_ONCE=1 stops after one sample (tests).
set -u
OUT="${1:?usage: $0 <out-dir> [interval-secs]}"
INTERVAL="${2:-5}"
PROC_INTERVAL="${SAMPLER_PROC_INTERVAL:-30}"
last_proc=0
R="${SAMPLER_ROOT:-}"

# component:comm (comm is the kernel's 15-char truncated process name)
COMPONENTS="apiserver:u7s-apiserver kcm:kube-controller kubelet:kubelet crio:crio kube-proxy:kube-proxy coredns:coredns flanneld:flanneld mariadb:mariadbd php-fpm:php-fpm nginx:nginx"

shopt -s nullglob

sample_attrib() {
  local ts="$1" phase="$2" with_proc="$3" cg="$R/sys/fs/cgroup" procfiles=()
  [ "$with_proc" = 1 ] && procfiles=("$R"/proc/[0-9]*/stat "$R"/proc/[0-9]*/io)
  # tail -n +1 prints a "==> file <==" header per file and skips unreadable ones (a pid that exits
  # mid-sample, kernel-thread io); awk would abort on them. [x] globs match only existing files.
  tail -n +1 -- "$R"/proc/pressure/* "$R"/proc/s[t]at "$R"/proc/diskstat[s] \
    ${procfiles[@]+"${procfiles[@]}"} \
    "$cg"/[c]pu.stat "$cg"/[i]o.stat "$cg"/*.slice/cpu.stat "$cg"/*.slice/io.stat "$cg"/*.scope/cpu.stat "$cg"/*.scope/io.stat \
    "$cg"/system.slice/*/cpu.stat "$cg"/system.slice/*/io.stat \
    "$cg"/kubepods.slice/*/cpu.stat "$cg"/kubepods.slice/*/*/cpu.stat \
    "$cg"/kubepods.slice/*/io.stat "$cg"/kubepods.slice/*/*/io.stat 2>/dev/null | awk -v ts="$ts" -v ph="$phase" -v cglen="${#cg}" '
    function emit(kind, rest) { printf "%s\t%s\t%s\t%s\n", ts, ph, kind, rest }
    function cgname(f, suffix,   n) {
      n = substr(f, cglen + 1)
      sub(suffix, "", n)
      return n == "" ? "/" : n
    }
    /^==> .* <==$/ { fn = substr($0, 5, length($0) - 8); next }
    NF == 0 { next }
    fn ~ /\/pressure\/[a-z]+$/ {
      n = fn; sub(/.*\//, "", n)
      split($5, a, "=")
      if ($1 == "some") some[n] = a[2]
      if ($1 == "full") full[n] = a[2]
      next
    }
    fn ~ /\/proc\/stat$/ { if ($1 == "cpu") emit("STAT", ($2 + $3) "\t" $4 "\t" $6 "\t" $9); next }
    fn ~ /\/proc\/diskstats$/ {
      if ($3 ~ /^(sd[a-z]|vd[a-z]|nvme[0-9]+n[0-9]+)$/) emit("DISK", $3 "\t" $4 "\t" $6 "\t" $8 "\t" $10 "\t" $13)
      next
    }
    fn ~ /\/proc\/[0-9]+\/stat$/ {
      pid = fn; sub(/\/stat$/, "", pid); sub(/.*\//, "", pid)
      line = $0
      c = line; sub(/^[^(]*\(/, "", c); sub(/\)[^)]*$/, "", c)
      sub(/^.*\) /, "", line); split(line, fld, " ")
      comm[pid] = c; ticks[pid] = fld[12] + fld[13]
      next
    }
    fn ~ /\/proc\/[0-9]+\/io$/ {
      pid = fn; sub(/\/io$/, "", pid); sub(/.*\//, "", pid)
      if ($1 == "read_bytes:") prb[pid] = $2
      if ($1 == "write_bytes:") pwb[pid] = $2
      next
    }
    fn ~ /\/cpu\.stat$/ {
      if ($1 == "usage_usec") u[fn] = $2
      if ($1 == "throttled_usec") t[fn] = $2
      next
    }
    fn ~ /\/io\.stat$/ {
      rb[fn] += 0; wb[fn] += 0; ri[fn] += 0; wi[fn] += 0
      for (i = 2; i <= NF; i++) {
        split($i, a, "=")
        if (a[1] == "rbytes") rb[fn] += a[2]
        if (a[1] == "wbytes") wb[fn] += a[2]
        if (a[1] == "rios") ri[fn] += a[2]
        if (a[1] == "wios") wi[fn] += a[2]
      }
      next
    }
    END {
      for (n in some) emit("PSI", n "\t" some[n] "\t" (n in full ? full[n] : 0))
      for (f in u) emit("CG", cgname(f, "/cpu\\.stat$") "\t" u[f] "\t" t[f] + 0)
      for (f in rb) emit("CGIO", cgname(f, "/io\\.stat$") "\t" rb[f] "\t" wb[f] "\t" ri[f] "\t" wi[f])
      for (p in ticks) if (ticks[p] > 0 || prb[p] > 0 || pwb[p] > 0) emit("PROC", p "\t" comm[p] "\t" ticks[p] "\t" prb[p] + 0 "\t" pwb[p] + 0)
    }
  ' >> "$OUT/attrib.tsv"
}

while true; do
  ts="$(date +%s)"
  phase="$(cat "$OUT/phase" 2>/dev/null || echo none)"
  if [ "$ts" -ge $((last_proc + PROC_INTERVAL)) ]; then with_proc=1; last_proc="$ts"; else with_proc=0; fi
  sample_attrib "$ts" "$phase" "$with_proc"
  awk -v ts="$ts" -v ph="$phase" '/^MemAvailable:/ {printf "%s\t%s\tMEM\t%s\n", ts, ph, $2}' "$R/proc/meminfo" >> "$OUT/samples.tsv"
  for entry in $COMPONENTS; do
    name="${entry%%:*}"; comm="${entry#*:}"
    pids="$(pgrep -x "$comm" || true)"
    [ -n "$pids" ] || continue
    for p in $pids; do cat "/proc/$p/smaps_rollup" 2>/dev/null; done \
      | awk -v ts="$ts" -v ph="$phase" -v n="$name" '/^Pss:/ {pss+=$2} /^Rss:/ {rss+=$2} END {printf "%s\t%s\t%s\t%d\t%d\n", ts, ph, n, pss, rss}' >> "$OUT/samples.tsv"
  done
  [ -z "${SAMPLER_ONCE:-}" ] || exit 0
  sleep "$INTERVAL"
done
