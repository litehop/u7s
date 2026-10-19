PRELIMINARY (run in progress): u7s has not yet been scored against CIS; results below are filled in as the kube-bench run completes.

Bead: mayor-m516k

## Method

- Benchmark: kube-bench v0.16.0 (release 2026-08-05), `--benchmark cis-2.0` (kube-bench maps K8s 1.34/1.35 to `cis-2.0`; there is no 1.37 mapping, so the newest profile is forced). Precedent for single-binary distros: `cfg/k3s-cis-1.11`, `cfg/rke2-cis-1.9`.
- Harness: kube-bench binary run inside the Lima VM (never on the host).
- The rig runs `u7s-apiserver` + scheduler on the macOS host; kubelet and KCM run in the VM. Production (`scripts/install.sh`) runs all as systemd units in one VM.

(Sections below are filled in as the run completes.)
