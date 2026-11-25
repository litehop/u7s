Throwaway spike comparing KCM client stacks (A: kube + full types, B: kube-runtime + narrow types, C: existing hyper client + narrow informer). Answer: C wins under D2 (lowest idle anon; within 10%, fewer new crates).

| Option | Idle Pss_Anon | Bytes/pod (Pss delta) | New crates | Watch correct |
|---|---|---|---|---|
| A | 502.4 MiB | 52551 | 50 | yes |
| A-trim (`managedFields` cleared) | 243.8 MiB | 25469 | 50 | yes |
| B | 35.2 MiB | 3625 | 50 | yes |
| C | 33.8 MiB | 3508 | 0 | yes |

N = 4416 bytes/pod: B_chosen = 3508 (C), 1.25 x 3508 = 4385, rounded up to a multiple of 64.

Method: apiserver seeded with 10011 pods and 1003 ReplicaSets; `Pss_Anon` of the whole process is read 20 s after list+watch sync; bytes/pod is the delta from a pre-list baseline divided by pod count. Medians of 3 interleaved runs per option.

Reproduce:

1. Seed: no script was kept. Create 1000 ReplicaSets (10 replicas, 10 namespaces) and 10 pods each with a controller ownerRef, 2 containers, env, resources and an emptyDir volume, bound to nonexistent node `bench-node`. Set status Running with 4 conditions via the status subresource.
2. Build one package at a time: `cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.35 --manifest-path spikes/kcm-client/Cargo.toml -p spike-<a|b|c>`.
3. Run inside a Linux VM, page cache dropped before each run: `<bin> --kubeconfig <kc> --server <url> --settle 20 [--trim 1]` (`--trim 1` is A-trim).
4. Interleave a, a-trim, b, c, three rounds; take medians.
5. After the metrics line, create 3 pods named `evt-*`, relabel them, force-delete one.
