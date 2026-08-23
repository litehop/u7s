# get-u7s: distribution reverse-proxy

Implements `docs/decisions/distribution-hosting-shape.md`: a small nginx
Deployment that streams the install script and release-tarball bytes to the
client itself, rather than redirecting to GitHub. GitHub's own domains
(`github.com`, `ghcr.io`) have no AAAA record; an IPv6-only client that got
redirected there would hit the exact reachability problem this proxy exists
to remove. `raw.githubusercontent.com` does have one, which is why the
install-script path proxies it directly instead of following a redirect.

## Deploying (Argo CD)

Point an Argo `Application` at this subfolder (`deploy/get-u7s/`) in this
repo, `destination.namespace: get-u7s` (or rely on `get-u7s.yaml`'s own
`Namespace` object + `CreateNamespace=true`). Once this lands on `main`,
Argo syncs it automatically -- there is no manual `kubectl apply` step, and
no cluster access was used or needed to build this.

## Channels and URL shape

Two channels, both fixed-URL proxies with no per-request GitHub API call
(so nothing to rate-limit-cache):

| Path                    | Proxies to                                                          |
|--------------------------|----------------------------------------------------------------------|
| `/stable/install.sh`    | `raw.githubusercontent.com/litehop/u7s/main/scripts/install.sh`    |
| `/dev/install.sh`       | same as above (script content doesn't differ by channel)           |
| `/stable/<asset>`       | `github.com/litehop/u7s/releases/latest/download/<asset>`          |
| `/dev/<asset>`          | `github.com/litehop/u7s/releases/download/dev/<asset>`             |

`stable` relies on GitHub's own "latest" convenience URL: GitHub resolves it
server-side as the newest release that is neither a draft nor a prerelease,
so no channel-selection logic is needed here.

`dev` points at a fixed, floating `dev` release tag. **That tag does not
exist yet.** Something needs to publish/overwrite its assets on a trigger
(a main-branch push is the natural one) -- that publishing mechanism is
explicitly out of scope for this bead and is tracked separately against
`.github/workflows/release-tarball.yaml`. Until it exists, `/dev/<asset>`
404s the same way `/stable/<asset>` does today (this repo has no tagged
release yet either) -- confirmed live against the real `litehop/u7s` repo,
see Verification below.

`<asset>` must be the exact filename GitHub has on the release (e.g.
whatever `scripts/build-release-tarball.sh` names the tarball) -- this proxy
forwards the name verbatim, it does not resolve or pattern-match it.

## Redirect-following mechanics

GitHub's download URLs don't serve bytes directly -- both channels 302
twice before reaching the actual asset (confirmed live against a real
GitHub release, 2026-08-23):

```
.../releases/latest/download/<asset>
  -> 302 -> .../releases/download/<tag>/<asset>
  -> 302 -> a signed release-assets.githubusercontent.com URL (200/206)
```

`proxy_pass` does not follow upstream redirects on its own -- it would hand
the 3xx straight to the client, reintroducing the exact IPv6-reachability
problem this proxy exists to remove.

**Chosen approach: `error_page`/`recursive_error_pages`, not njs.** The
original design considered njs (nginx's JavaScript module) for this, needed
back when the `dev` channel required parsing the Releases List API response
and picking the newest entry. Once the design moved to a fixed `dev` tag
(see above), both channels collapsed to mechanically identical fixed-URL
proxies with no JSON to parse and no per-request GitHub API call -- at which
point pure nginx directives became sufficient and njs was dropped entirely,
per Rule 2 (simplicity first). `nginx.conf`'s `default.conf` (embedded in
`get-u7s.yaml`'s ConfigMap) chains three internal redirects
(`@follow_hop1/2/3`, one hop of margin over the two observed live) via
`error_page 301 302 303 307 308 = @follow_hopN;` + `recursive_error_pages
on;`. One non-obvious wrinkle, found by running this against a real GitHub
release rather than assuming it would work: `$upstream_http_location` reads
as empty if referenced directly in the next hop's `proxy_pass` -- it must
first be captured into a local variable via `set $locN
$upstream_http_location;` in that same location. Without this, nginx fails
at runtime with `invalid URL prefix in ""`.

## Verification

**Verified locally** (Docker was available in the build environment):

- `nginx -t` config-syntax check against the exact production config, using
  the exact pinned image (`nginxinc/nginx-unprivileged:1.31-alpine@sha256:
  c3fed6436b61d2bf2201ec032c35c000871f7ed062dea5d586bc6bf4d0fdd140`).
- Live end-to-end smoke test of the redirect-following mechanism against a
  real GitHub release with actual assets (`cli/cli`, since `litehop/u7s` has
  no tagged release yet) -- both channel paths returned a real, complete,
  correctly-sized gzip tarball (14,863,663 bytes, verified with `file`),
  not an error or a redirect. Byte-range requests (`Range: bytes=0-99`)
  passed through correctly as `206 Partial Content`, confirming resumable
  downloads work.
- Upstream TLS certificate verification (`proxy_ssl_verify on;` +
  `proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;`, the
  system CA bundle already present in the base image -- confirmed by path
  and confirmed non-empty, no custom bundle shipped): the full redirect
  chase above still succeeds with verification on (proves the trust chain
  for github.com, github.com's own redirect target, and the signed
  release-assets.githubusercontent.com URL all validate against
  `verify_depth 2`). As a negative control, proxying the same config at
  `self-signed.badssl.com` fails with `upstream SSL certificate verify
  error: (18:self-signed certificate)` rather than silently accepting the
  untrusted cert -- confirming `proxy_ssl_verify` is actually enforcing,
  not a no-op.
- The exact final config, pointed at the real `litehop/u7s` repo: `/stable/
  install.sh` and `/dev/install.sh` both return the real script (200,
  23864 bytes matching the actual file); `/stable/<asset>` and `/dev/<asset>`
  both cleanly 404 (no tagged release / no `dev` tag exists yet, exactly as
  expected -- not a proxy bug).
- `readOnlyRootFilesystem: true` was tested directly: nginx fails to start
  without a writable `/tmp` (`mkdir() "/tmp/proxy_temp" failed`); the
  Deployment's `emptyDir` mount at `/tmp` fixes this, confirmed live.
- IPv6: the container's own `listen [::]:8080` was confirmed to answer a
  request over `::1` inside the test environment.

**Not verified, left for the operator** (no live cluster access from this
worktree):

- Whether the deployed proxy is actually reachable over IPv6 from outside
  the cluster -- container-internal `[::]` binding is not the same as
  external dual-stack routing through the Ingress/LoadBalancer.
- Whether the cluster's CNI honors `ipFamilyPolicy: PreferDualStack` on the
  Service at all.
- The `cert-manager.io/cluster-issuer`, `ingressClassName`, and hostname in
  `get-u7s.yaml`'s Ingress are `TODO` placeholders -- fill in the operator's
  real values before this can serve real TLS traffic.
- Publishing the `dev` release tag (separate, tracked against the
  release-tarball workflow) -- until that lands, the `dev` channel 404s.
- The `resolver` directive points at public DNS (`1.1.1.1`/`8.8.8.8` +
  their IPv6 equivalents) -- if the real cluster's egress NetworkPolicy
  blocks traffic to arbitrary external IPs, this proxy's dynamic hop-
  following (which needs `resolver` to look up each redirect target) will
  fail. The alternative -- pointing `resolver` at the cluster's own DNS
  Service ClusterIP -- wasn't applied here because that address is
  cluster-specific and not something this worktree could discover or
  safely guess; verify against the real NetworkPolicy and swap it in if
  needed.
