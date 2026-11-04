# MariaDB 11.8 first init on GCP e2-micro

Bead: mayor-w5xs5

**Cause: not yet determined (work in progress).**

## Plan

1. Machine baseline: e2-micro vs e2-medium (nproc, cpuinfo, openssl speed/genrsa, steal).
2. Control A: podman run mariadb:11.8.6-noble on e2-micro, 3 fresh datadirs.
3. Control B: same on e2-medium.
4. u7s v0.4.3-snapshot.4 on e2-micro: MariaDB only x3, then with WordPress.
5. Profile (perf/gdb, strace -c, cgroup cpu.stat) where slow.
6. u7s suspects: probe connections, cgroup CPU limit, SSL auto-generation timing.

## Results

(filled in per experiment)
