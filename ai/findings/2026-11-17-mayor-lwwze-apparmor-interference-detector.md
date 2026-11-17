# AppArmor interference detector: design

Bead: mayor-lwwze
Status: design for operator approval; no code written
Date: 2026-11-17

**Recommendation:** ship a small node-local agent as a subcommand of the u7s
binary (`u7s-apiserver node-agent`), run by a systemd unit `u7s-node-agent` on
every node (control plane and workers) that tails `/dev/kmsg`, matches
AppArmor `DENIED` records whose pid lives in a container cgroup, and files
rate-limited `Warning` Events on its own Node (reason `AppArmorInterference`)
using the node's existing kubelet kubeconfig; it never touches profiles.

## 1. Where it runs

Survey (`scripts/install.sh`, `crates/apiserver`, `manifests/`):

| Node | Host processes today | In-cluster |
|---|---|---|
| Control plane | `u7s-apiserver` (embeds the scheduler, `--embedded-scheduler true`), `u7s-kcm` (upstream binary), `kubelet`, CRI-O | kube-proxy, flannel, beep DaemonSets |
| Worker (`--join`) | `kubelet`, CRI-O only (`install.sh` ~L2353 writes only `kubelet.service`) | same DaemonSets |

There is **no u7s-owned process on a worker**. The worker tarball does carry
the `u7s-apiserver` binary (used to build the node-identity CSR, install.sh
L103-105), so a subcommand needs no new artefact. The existing precedent for
"u7s emits Node Events from inside the binary" is
`crates/apiserver/src/cert_expiry.rs`, spawned in `lib.rs` (~L581); it writes
straight to the store, so it covers control-plane Nodes only (certs of
workers are visible there because the CP holds them; AppArmor is not).

Options:

- **(a) in-process task in the apiserver.** Zero footprint and zero new
  unit, direct store writes, root already. Covers only the control-plane node.
  Interference was reproduced on a *Lima worker-class* node, and the
  host profiles (dig, nslookup, man, ...) are installed per node, so worker
  coverage is the point. Insufficient alone.
- **(b) node-local agent in the u7s binary, systemd unit on every node.**
  Root, host PID/cgroup namespace and `/dev/kmsg` are native; no pod
  sandbox, so no AppArmor confinement of the detector itself and no
  dependency on the CNI, kube-proxy or scheduling being healthy (the
  detector must work precisely when containers misbehave). Footprint:
  one extra tokio process, estimated 3-6 MB RSS (to be measured; a
  single-threaded runtime plus a small REST client). Upgrade story: same
  tarball, same install.sh path as kubelet; on `--upgrade` of a worker
  (kubelet-only path, install.sh ~L1851) the unit is rewritten alongside
  `kubelet.service`. Cost: one more unit in the systemd-install contract
  (`docs/decisions/systemd-install-contract.md`) and one more thing
  install.sh must write on both paths.
- **(c) node-problem-detector-style DaemonSet/manifest.** Needs a privileged
  pod with `hostPID`, `/dev/kmsg`, host cgroup mount, an image (new pull at
  join, a registry dependency on an offline-ish stack), a ServiceAccount
  with `events`/`nodes` RBAC, and a pod slot plus requests on 1 GiB nodes;
  also depends on the detector pod scheduling and running through the very
  runtime it is diagnosing, and the privileged pod would itself be labelled
  by the stacking that causes the bug. `docs/decisions/upstream-component-shipping-shape.md`
  puts kube-proxy/beep in DaemonSets because they have no bootstrap
  circularity and are pure-cluster functions; this one is host-observational.
  Rejected.

Choose **(b)**. To honour "alongside apiserver" the code lives in a module of
the apiserver crate and the control-plane node optionally gets the same
code path (the unit is simply also installed there, using the CP kubelet
identity, `issue_cp_kubelet_identity`). One code path beats a store-sink
variant for the CP plus a REST variant for workers; the in-process sink is
a possible later optimisation, not a Phase 1 need.

Event write identity: the node's kubelet kubeconfig (`system:node:<name>`,
group `system:nodes`). The upstream `system:node` ClusterRole allows
`events` create/patch, and `node_authz.rs` already audits those rules
(L874). Open check for Phase 1: confirm u7s's NodeRestriction/Node authorizer
accepts an Event whose `regarding` is the caller's own Node
(Phase-1 test).

## 2. Signal source

Candidates, with AppArmor 5 on Ubuntu 26.04 (kernel 7.0):

- **`/dev/kmsg`** (recommended). Direct, no subprocess, structured
  `pri,seq,usec,flags;text` records, a monotonically increasing `seq`, and
  `O_NONBLOCK`/blocking read semantics that make a plain async loop trivial.
  Requires `CAP_SYSLOG` when `kernel.dmesg_restrict=1` (Ubuntu's default)
  otherwise any reader; root has it, and the unit runs as root. Uses
  `libc` (already a dependency of the apiserver crate), no new crate.
- **journald kernel stream** (`journalctl -k -f -o json`). Same data (journald
  ingests `/dev/kmsg`), but adds a subprocess (a ~10 MB RSS journalctl on
  1 GiB nodes), a JSON dependency on journald's field layout and
  availability (containers-only hosts, volatile journals, `Storage=none`)
  and needs `systemd-journal` group or root. Rejected: strictly worse, though it is
  a legitimate fallback if `/dev/kmsg` is unreadable.
- **audit netlink.** Gives records even when printk is suppressed, but
  requires `CAP_AUDIT_READ`, a netlink parser (no existing crate; a new
  dependency or hand-rolled), and **fights with auditd**: only one audit
  daemon may hold the netlink socket, and when one is attached the kernel
  stops printk-ing audit records to kmsg. Rejected for Phase 1.

Caveats the design must handle, not hide:

1. **Records go to kmsg only when no userspace audit daemon is attached**
   (`auditd` not running; Ubuntu default has none). On hosts with auditd,
   kmsg misses the denials. Detect "auditd present" (`/proc/*/comm` or
   `/run/auditd.pid`) and log a one-time notice at startup that detection is
   degraded (no Event is invented). Fallback source `/var/log/audit/audit.log`
   is out of scope; an open question.
2. **Kernel rate limiting.** AppArmor audit goes through
   `audit`/printk ratelimit; lines can be dropped
   (`audit: audit_lost=...`, `callbacks suppressed`). A first denial of a
   class is still logged, so a deduping Event path is reliable; the count
   is a lower bound and the message says so ("at least N").
3. **Replay.** `/dev/kmsg` replays the ring buffer from the start on open.
   Start from the beginning (boot-time denials, e.g. profile loads, are
   interesting) but persist `(boot_id, last_seq)` in
   `/var/lib/u7s/node-agent-seq` and skip `seq <= last_seq` for the same boot
   id, so an agent restart does not inflate Event counts.
4. **No-op when AppArmor is absent or disabled.** At startup, if
   `/sys/module/apparmor/parameters/enabled` is not `Y` (same guard install.sh
   uses at L2097), log once at info level and park (sleep forever, no
   busy-loop, no Event). Also park if `/dev/kmsg` is unopenable
   (`EPERM`/`ENOENT`, e.g. an unprivileged LXC): one warning in the journal,
   no Event, exit status 0 so systemd does not flap. Non-AppArmor kernels
   (SELinux, none) never match any record, so even a misconfigured unit is a
   clean no-op.

## 3. What to match

Record format (real, from the preserved GCP/Lima archive, `temp/e2e`):

```
audit: type=1400 audit(1792044314.598:186): apparmor="DENIED" operation="open" class="file" profile="who" name="/etc/nsswitch.conf" pid=1351 comm="who" requested_mask="r" denied_mask="r" fsuid=0 ouid=0
```

(Over `/dev/kmsg` the prefix is `kernel: ` stripped; the text is
`audit: type=1400 audit(...): apparmor=...`.) The two signal lines of the bug
are not in any preserved archive; the test vectors below for them are
**reconstructed** from the bead text and must be replaced with a real
capture in Phase 1 (`dmesg` on the Lima rig during the nslookup repro).

Parse into `key=value` pairs (quoted values, `\x`-escaped values hex-decoded
the way audit encodes names with spaces). Required: `apparmor="DENIED"`
(also `"AUDIT"`? no: `ALLOWED` complain-mode lines are out of scope;
`DENIED` only), `operation`, `profile`, `pid`. Optional: `peer`,
`comm`, `name`, `requested_mask`, `denied_mask`, `signal`, `class`.

A denial is **container interference** iff it passes either of two tests;
attribution (below) is the primary one and the label heuristic is the cheap
pre-filter and fallback:

1. **Label test.** `peer` or `profile` contains a stacked container
   profile: matches `//&` with a suffix of `u7s-default`, `crio-default`,
   `unconfined` ("container pid" form `<hostprof>//&<ctrprof>`), or the
   label is exactly one of the container profiles with a stacked peer. Examples:
   `profile="dig" peer="dig//&u7s-default"` (host profile hit an in-container
   process) and `profile="crio-default" peer="crio-default//&unconfined"`
   (the container's own profile lacks stacked-peer rules).
2. **Cgroup test.** The denied `pid` is alive and its
   `/proc/<pid>/cgroup` resolves to a CRI-O container scope (see 4). This
   decides records with plain labels, and is the **authority**: a label hit
   without a container cgroup is host noise.

Exclusions (host-only noise): a denial is dropped if the pid's cgroup is not
a container scope AND `peer` carries no stacked container label. Real
samples: `systemd-detect-virt` (sendmsg, capable perfmon), `who`
(open `/etc/nsswitch.conf`), `ubuntu_pro_esm_cache_systemd_detect_virt`
- all are plain host profiles with no peer and a non-container pid.
Plus a small deny-list on `comm`/`profile` of known host-only ones
only as a *short-circuit* for the dead-pid case (below), never as the
primary filter.

Dead pid: the pid often exits before we read (`nslookup` crashes right
after the denial). Then fall back to the label test alone; if the label
test passes with no cgroup, still report, with the Pod unknown. If neither
passes, drop. Prefer false negatives on ambiguous host noise over
false-positive warnings (a Warning that is routinely wrong trains users
to ignore it).

Test vectors (parser/classifier unit tests):

| # | Line (abridged) | Expect |
|---|---|---|
| 1 | `... profile="dig" ... operation="signal" ... peer="dig//&u7s-default"` (reconstructed) | interference, ops=signal, profile=dig |
| 2 | `... profile="nslookup" ... peer="nslookup//&crio-default"` (reconstructed) | interference |
| 3 | `... profile="crio-default" operation="signal" peer="crio-default//&unconfined"` (reconstructed) | interference (missing stacked-peer rule), hint = crio profile |
| 4 | real `systemd-detect-virt` sendmsg line | not interference |
| 5 | real `who` open `/etc/passwd` line | not interference |
| 6 | real `ubuntu_pro_esm_cache_systemd_detect_virt` capable line | not interference |
| 7 | `apparmor="ALLOWED"` complain-mode line | ignored |
| 8 | `comm="a b\x20c"` hex-escaped `comm` | decoded correctly |
| 9 | non-audit line (`usb 1-1: ...`) | ignored |

## 4. Attribution

pid to pod/container:

1. Read `/proc/<pid>/cgroup`. On cgroup v2 (Ubuntu 26.04) it is a single
   `0::<path>` line. With the systemd cgroup driver CRI-O uses, containers
   look like
   `/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid_with_underscores>.slice/crio-<64hex>.scope`
   (Guaranteed omits the QoS slice; BestEffort uses `kubepods-besteffort`).
2. Parse: pod UID = the `pod<uid>` segment with `_` replaced by `-`;
   container ID = the 64-hex in `crio-<id>.scope` (also match
   `cri-containerd-` and `docker-` prefixes cheaply? No: CRI-O only; others
   add scope later).
3. Resolve UID to namespace/name with a **node-scoped pod list**
   (`GET /api/v1/pods?fieldSelector=spec.nodeName=<node>`) cached for 30 s,
   refreshed on miss. Not a watch (a worker with 110 pods pays nothing
   between denials; denials are rare). A missed or unknown UID leaves the
   Pod fields unset.

Where Events go:

- **Node Event always.** This is what the operator asked for, it is the
  object the install owner reads (`kubectl describe node`), it survives pod
  deletion (the crashlooping pod is replaced but the cause is host-level)
  and it is dedup-friendly: one stable key per cause, not per pod instance.
- **Also a Pod Event**, only when the Pod resolved, same reason, shorter
  message, separately rate limited. Reason: the user who sees
  `CrashLoopBackOff` and runs `kubectl describe pod` gets the answer where
  they look. Cost: two Events per cause rather than one. If the operator
  prefers minimal scope, Phase 1 ships Node only and the Pod Event is a
  follow-up (Phase 2). The design supports both with one parameter (the
  `regarding` object).

The Node Event message names the *first* seen pod and "N containers
affected"; the key excludes the pod so a fleet crashloop is one Event.

## 5. Event shape

API: `events.k8s.io/v1` (the upstream recommended shape; core/v1 Events are
the legacy form). Note `cert_expiry.rs` today writes core/v1 Events with
`count`/`firstTimestamp`; the new emitter follows the upstream
`events.k8s.io/v1` conventions and `regarding`/`note`/`series`, which also
makes the Event round-trip correctly through both `kubectl get events` and
`kubectl describe`. The apiserver already serves the group
(`net_disc_cert_policy_events_gen*`). Phase 1 must confirm
`kubectl describe node` renders series Events (it reads either shape).

| Field | Value |
|---|---|
| `type` | `Warning` |
| `reason` | `AppArmorInterference` |
| `action` | `Denied` (events.k8s.io requires an action) |
| `reportingController` | `u7s.litehop.io/node-agent` (domain-qualified like upstream controllers, e.g. `kubelet`'s `kubernetes.io/kubelet`) |
| `reportingInstance` | `u7s-node-agent-<nodeName>` |
| `regarding` | Node (`kind: Node, name, uid`); namespace `default` like kubelet's Node Events |
| `related` | the Pod, when resolved |
| `eventTime` | time of the first denial of the series |
| `series` | `{count, lastObservedTime}` |
| `note` | see below, hard-capped at 1024 bytes (the API limit) |
| `metadata.name` | `<node>.u7s-apparmor-<hash(profile,operation,peer-kind)>` (deterministic like `event_name` in cert_expiry.rs, so a restart updates rather than duplicates) |

Message (note) template, single line so `kubectl get events` stays readable:

```
Host AppArmor profile "dig" denied operation "signal" on container process
comm="nslookup" (pod default/execpod-x, container "c", peer "dig//&u7s-default");
the container cannot work as intended. See docs/apparmor.md. If the profile is
shipped by Ubuntu, allow stacked peers narrowly in /etc/apparmor.d/local/dig:
"signal (send,receive) peer=dig//&*,", then run: apparmor_parser -r /etc/apparmor.d/dig
```

The remediation hint is built from `profile` (and `operation`) via a pure
function and is only a *suggestion text*; the agent never writes it. For
`crio-default` the hint instead says to configure CRI-O's
`apparmor_profile = "u7s-default"` (what `install.sh` already does) rather
than a local-override rule, because that profile is not a host file. Docs
page `docs/apparmor.md` is a Phase 2 deliverable (the message links to it by
path; the URL form is an open question).

Dedupe and aggregation:

- Key = `(profile, operation, peer-kind)`; pod and pid are *not* in the key.
- In-memory aggregator per key accumulates `count` and the latest `comm`/pod;
  flush at most **once per 5 minutes per key** (first occurrence flushes
  immediately so the first warning is prompt), `series.count` += suppressed
  denials. A global ceiling of 20 distinct keys per node per hour bounds a
  profile-storm; overflow is summarised in one Event
  `AppArmorInterference ... N further distinct denial classes suppressed`.
- Series refresh: the update is a PATCH of `series` on the existing
  deterministic name; if it vanished (apiserver event TTL), recreate.
- Pairs with the upstream recorder behaviour: heartbeat of the series every
  ~30 min while denials keep occurring so the Event does not age out under
  an active problem; the apiserver's event TTL (1 h upstream) lets a fixed
  problem fade on its own, no explicit clear (unlike cert_expiry's
  `clear_warnings`; here absence of denials is not proof of health).

## 6. False-positive and security policy

- **Read-only.** No profile load/unload/replace, no writes under
  `/etc/apparmor.d`, no `apparmor_parser`. The hint is text only. This is
  asserted by a unit test that the module has no code path taking a
  profile-file path for writing (a test that the exported API is
  parse/classify/format only) and by an unprivileged-capability review:
  unit runs with `CapabilityBoundingSet=CAP_SYSLOG CAP_DAC_READ_SEARCH`
  (the latter for `/proc/<pid>/cgroup` of other users), `ProtectSystem=strict`,
  `ProtectHome`, `NoNewPrivileges`, `ReadWritePaths=/var/lib/u7s`. Needs
  root uid only for the read of other pids' cgroups on hidepid mounts;
  standard `/proc` does not require it. Phase 1 verifies whether
  non-root + `CAP_SYSLOG` is enough.
- **Privacy.** kmsg contains host paths and file names (`name=`), and `comm`
  can carry attacker-chosen text (a container process can set its own
  `comm`). The note includes only: profile, operation, peer label, pod
  namespace/name (already visible to anyone who can read the Event
  namespace), `comm` sanitised to `[A-Za-z0-9._-]` and truncated to 15 chars
  (the kernel's `TASK_COMM_LEN-1`), and never `name=` (a path) or argument
  data. Control characters and quotes are stripped so a crafted `comm`
  cannot forge a second line or inject remediation text.
- **Spoofing.** Only `/dev/kmsg` lines starting with the audit type-1400
  prefix are considered; a container writing into `/dev/kmsg` (blocked by
  the default container policy; where allowed it needs CAP_SYSLOG) could
  forge a record. Forgery only yields a bogus warning, never an action;
  accepted. The cgroup test binds the Event to a real pid on the node.
- **False positives.** The cgroup/label rule above; stacked-peer lines for
  a profile denial that is the container's own *intended* policy
  (e.g. `deny mount` in `u7s-default` hit by an app that mounts) must **not**
  alarm: the `peer` is empty and the label is the container's own, so it is
  host-vs-container interference only if a *host* profile name is in the
  `profile` with a stacked container peer, or the container profile lacks
  the stacked-peer rule (`profile` and `peer` share the profile
  name stem). Plain `profile="u7s-default"` denials of `mount`/`/proc` writes
  are workload policy hits and are ignored. Needs a documented precise rule
  in the module's doc comment; test vector 10 in Phase 1.
- **False negatives are acceptable;** the Event says "at least".

## 7. Tests

Unit (pure functions, no kernel, no network), in a `node_agent` module:

- `parse_audit_line(&str) -> Option<Denial>` with the vectors in section 3
  (real lines for the host-noise rows; reconstructed signal lines replaced
  by real captures in Phase 1).
- `classify(&Denial, Option<&CgroupInfo>) -> Verdict` truth table: label
  yes/cgroup yes, label yes/no cgroup, label no/cgroup yes, neither; plus
  the "container's own profile policy hit is not interference" case.
- `parse_cgroup(&str) -> Option<ContainerRef>` for Guaranteed, Burstable,
  BestEffort, nested, non-container (`/system.slice/ssh.service`),
  `crio-conmon-<id>.scope` (conmon is a host process: must not match)
  and cgroup v1-shaped input (rejected, v2 only).
- `Aggregator`: clock-injected; first flush immediate, same key within 5 min
  folded into one count, key overflow summarised, restart seq skipping.
- `render_note` is under 1024 bytes for hostile `comm`/profile inputs,
  sanitised, contains the remediation for each profile family.
- Regression intent (Rule 9/14): each test names what breaks for the user
  (e.g. "nslookup in pods keeps crashing with no clue if a stacked `dig`
  denial is not classified as interference").

Integration on the Lima rig (kernel 7.0.0-43 arm64 reproduces; GCP x86
`7.0.0-1017-gcp` did not, so x86 GCP is a *negative* control that must
produce no Event): start the stack **without** the narrow local-override
rule, run `nslookup kubernetes.default` in an agnhost pod; assert within
60 s `kubectl get events --field-selector reason=AppArmorInterference`
shows the Node Event (and the Pod Event when enabled) naming `dig` or
`nslookup`; apply the override, redeploy, assert no new Event. Also assert
the host-noise lines (`systemd-detect-virt`, `who`, triggered via
`sudo who`) produce none. Needs `scripts/conformance/lima-start.sh` to
stop disabling the profiles (another worker's scope; do not touch here).
A kmsg-free variant: feed recorded lines through the agent via a
`--kmsg-path <file>` flag (a regular file, so no privilege) for CI without
AppArmor.

## 8. Size and phases

Estimate: about 600-800 lines Rust plus tests (parser 120, classifier 80,
cgroup 80, aggregator 120, event rendering and REST sink 150, runtime and
CLI 100) and about 60 lines of install.sh (unit on both install paths and
upgrade). No new crates (`libc` present; REST over the existing HTTP stack
or a thin `reqwest`-free client to be decided in Phase 2 after checking what
the apiserver crate already links).

Phases (beads to file only after approval):

1. **Parser + classifier + cgroup attribution + aggregator**, pure and
   tested, plus capture of real signal lines on the Lima rig (replaces the
   reconstructed vectors). ~350 lines.
2. **Agent runtime**: kmsg reader, seq persistence, AppArmor-absent no-op,
   Event sink (events.k8s.io/v1, Node), `node-agent` subcommand, local
   `--kmsg-path` file mode. ~300 lines.
3. **Packaging**: systemd unit with hardening in install.sh (CP, join,
   upgrade), `test-install-logic.sh` coverage, `docs/apparmor.md` with the
   narrow override rules, systemd-install-contract update.
4. **Pod Events** (if not folded into 2) and Lima-rig integration test
   (blocked on the lima-start.sh rework).
5. Later, optional: audit.log fallback; in-process sink for the CP.

## 9. Open questions for the operator

1. A separate `u7s-node-agent.service` on **every** node (recommended) vs
   in-process in the apiserver (CP only, zero footprint, workers
   uncovered). Is a worker gap acceptable for Phase 1?
2. Pod Events as well as Node Events (recommended, two Events per cause),
   or Node only?
3. events.k8s.io/v1 for the new Events while `cert_expiry.rs` emits core/v1:
   accept the inconsistency, or migrate cert_expiry later?
4. Hosts running `auditd` (kmsg gets no denials): log-only degraded notice
   (recommended) or implement the `audit.log` tail fallback?
5. Non-root with `CAP_SYSLOG` hardening, or plain root for Phase 1?
6. Docs URL for the Event message: repo path only, or a published URL?
7. Should the detector also cover `crio-default` mis-selection (CRI-O not
   pointed at `u7s-default`, e.g. the Lima rig), or only host-profile
   interference? Vector 3 assumes yes.
8. First-run replay of the kmsg ring buffer (boot-time denials get reported)
   or start-at-tail only (no historical noise)?
