# Vendored in-cluster manifests

Real, standalone `.yaml` files for components u7s auto-applies in-cluster
(the well-known-folder mechanism, `docs/decisions/well-known-manifest-folder.md`)
-- not heredocs embedded in `install.sh`, not Rust `include_bytes!` constants.
Real files here are what makes these vendored components scannable by
automated dependency-update tooling (Renovate/Dependabot) for image-tag
version bumps.

Everything in this directory ships as-is: `scripts/build-release-tarball.sh`
copies every `*.yaml` file here into the release tarball's own `manifests/`
directory, and `scripts/install.sh` copies them from there into
`--manifest-output-dir` (default `/etc/u7s/manifests`), where the apiserver
auto-applies them at every boot. Do not add a manifest here that should NOT
be auto-applied by default (e.g. metrics-server, which is opt-in by design --
see `docs/decisions/upstream-component-shipping-shape.md` -- and lives at
`crates/apiserver/manifests/metrics-server.yaml` instead, for users to apply
themselves).

`flannel.yaml` (`__IFACE__`, `__POD_CLUSTER_CIDR__`) and `kube-proxy.yaml`
(`__KUBE_VERSION__`, `__IFACE_IP__`) each carry install-time placeholders
`scripts/install.sh` substitutes before writing them to
`--manifest-output-dir` -- see each file's own header comment for what every
placeholder substitutes to. CoreDNS is still compiled into the apiserver via
`include_bytes!` (`crates/apiserver/manifests/coredns.yaml`); migrating it
onto this mechanism is separate follow-on work (mayor-fiq79).
