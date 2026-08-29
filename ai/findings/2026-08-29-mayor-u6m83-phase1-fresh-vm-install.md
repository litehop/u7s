# Phase 1: fresh Ubuntu Lima VM + release-tarball u7s install

Bead: mayor-u6m83
Date: 2026-08-29
Shape: 3 (audit) — one fresh VM, no code changes

## Verdict

Install succeeded end-to-end (`lima-lima-workload` node `Ready`, CoreDNS +
kube-proxy `Running`), but only after working around two real, evidenced
gaps: no aarch64 release target (blocks this whole flow natively on Apple
Silicon hosts) and a broken `install.sh` reset procedure (stale kubelet cert
cache survives `rm -rf $STATE_DIR`, permanently breaking the node). 2
u7s-should-own gaps filed as follow-ons; 1 document-for-users gap noted
inline (no bead, per scope).

## Timeline

1. **VM provisioning:** ~10 min total, not the expected ~2 min. `template:ubuntu-lts`
   on this arm64 Mac host defaults to an aarch64 guest; Rosetta binfmt boots
   fine but cannot run u7s's dynamically-linked x86_64 binaries (see gap
   table). Recreating as a genuine x86_64 guest (`--arch x86_64`, Lima's QEMU
   driver) needed installing `lima-additional-guestagents` (+qemu) via brew,
   then booted in ~4.5 min.
2. **Build release tarball:** local build on macOS failed immediately
   (`cc-rs` can't find `x86_64-linux-gnu-gcc`) — cross-compiling this target
   from a non-Linux host isn't documented as unsupported anywhere. Downloaded
   the latest published release (`v0.2.0-snapshot.3`) instead. Separately,
   attempted a native from-source build of HEAD *inside* the fresh x86_64 VM
   (rustup + `build-essential`, ~2 min setup) to get an accurate, current
   `install.sh` — killed after **93+ minutes**, still mid-dependency
   compilation, never reached the final LTO link. QEMU TCG has no hardware
   acceleration for cross-ISA emulation on Apple Silicon, and the workspace's
   `fat`-LTO/`codegen-units=1` release profile is brutal under it.
3. **Copy + install:** ~2 min (apt package downloads: CRI-O, kubectl,
   kubernetes-cni). Straightforward given the published tarball + its
   self-consistent `install.sh`.
4. **Verify:** node stuck un-registered until a stale cert cache was cleared
   (see gap table); ~1 min to fix, then `Ready` within seconds.

## Gaps

| Symptom | Category | Fix |
|---|---|---|
| Rosetta-on-aarch64-guest can't run u7s's x86_64 binaries (missing glibc interpreter; Ubuntu's ARM ports mirror has no amd64 multiarch packages either) — only a full QEMU-emulated x86_64 VM works, and it's dramatically slower to build/run inside | **u7s-should-own** | mayor-gy4wy: ship an aarch64 release target |
| `install.sh`'s own documented reset (`rm -rf $STATE_DIR`, re-run) leaves `/var/lib/kubelet/pki` (kubelet's hardcoded cert-rotation cache, outside `$STATE_DIR`) untouched; the stale cert is signed by the deleted CA, so the node never re-registers — surfaces only as repeated "UnknownIssuer" / "node not registered" log spam on both sides, no actionable message | **u7s-should-own** | mayor-vamg1: point kubelet's `certDir` inside `$STATE_DIR`, or have the reset path also clear it |
| `build-release-tarball.sh`'s "Requires:" comment doesn't mention a C toolchain (`build-essential`); `cargo build` fails on a bare Ubuntu box too, buried in noisy `cc-rs`/build.rs warning spam | document-for-users | add one line to the script's header comment |
| `install.sh`'s final "Run: kubectl --kubeconfig=... get nodes" hint needs `sudo` (kubeconfig is `0600` root-owned) | neither | matches kubeadm's own `admin.conf` convention; already an expected, documented-elsewhere step |

## Reproducible install recipe (known-good baseline for Phase 2)

```
# Host (arm64 Mac): genuine x86_64 VM, not vz+Rosetta
brew install lima-additional-guestagents
limactl start --tty=false --name=lima-workload template:ubuntu-lts \
  --arch x86_64 --memory 4 --cpus 4 --disk 20 --timeout 20m

# Get a release tarball (local macOS build of this target is unsupported —
# see gap table; use a published release or build on native x86_64 Linux/CI)
gh release download <tag> --dir /tmp/u7s-dist
limactl copy /tmp/u7s-dist/u7s-*-x86_64-unknown-linux-gnu.tar.gz lima-workload:/tmp/
limactl copy /tmp/u7s-dist/install.sh lima-workload:/tmp/

limactl shell lima-workload -- sudo bash /tmp/install.sh \
  --tarball /tmp/u7s-*-x86_64-unknown-linux-gnu.tar.gz

limactl shell lima-workload -- sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig get nodes
limactl shell lima-workload -- sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig get pods -A
```

Node `lima-lima-workload` reaches `Ready`; `coredns-*` and `kube-proxy-*`
reach `1/1 Running` within ~1 minute of kubelet starting. (Node name carries
a doubled `lima-` prefix — Lima's own guest-hostname convention, not an
`install.sh` bug; cosmetic, overridable via `--node-name`.)

**Do not** `rm -rf /var/lib/u7s` to reset without also `rm -rf
/var/lib/kubelet/pki` (mayor-vamg1) — the documented single-directory wipe
does not fully reset kubelet's identity.

## Follow-on beads

- mayor-gy4wy — Add aarch64/arm64 target to release-tarball build + install.sh (u7s-should-own, P2)
- mayor-vamg1 — install.sh reset procedure leaves stale kubelet cert-rotation cache (u7s-should-own, P1 bug)

`lima-workload` is left running (x86_64, node `Ready`) for Phase 2
(mayor-itt0e).
