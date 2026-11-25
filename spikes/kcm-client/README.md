Throwaway spike comparing KCM client stacks (A: kube + full types, B: kube-runtime + narrow types, C: existing hyper client + narrow informer); results are in `ai/findings/2026-11-25-*-kcm-client-spike.md`.

Reproduce:

1. Seed: no script was kept. Create 1000 ReplicaSets (10 replicas, 10 namespaces) and 10 pods each with a controller ownerRef, 2 containers, env, resources and an emptyDir volume, bound to nonexistent node `bench-node`. Set status Running with 4 conditions via the status subresource.
2. Build one package at a time: `cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.35 --manifest-path spikes/kcm-client/Cargo.toml -p spike-<a|b|c>`.
3. Run inside a Linux VM, page cache dropped before each run: `<bin> --kubeconfig <kc> --server <url> --settle 20 [--trim 1]` (`--trim 1` is A-trim).
4. Interleave a, a-trim, b, c, three rounds. Each prints `Pss_Anon` (`/proc/self/smaps_rollup`) 20 s after sync; take medians.
5. After the metrics line, create 3 pods named `evt-*`, relabel them, force-delete one.
