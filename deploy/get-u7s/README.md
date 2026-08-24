# get-u7s: distribution reverse-proxy

Implements `docs/decisions/distribution-hosting-shape.md`: a small nginx Deployment that streams the install script and release-tarball bytes to the client itself rather than redirecting to GitHub. `github.com` has no AAAA record, so an IPv6-only client handed a redirect would hit the exact reachability problem this proxy exists to remove.

## Routes

| Path             | Proxies to                                                   |
|------------------|--------------------------------------------------------------|
| `/install.sh`    | `github.com/litehop/u7s/releases/latest/download/install.sh` |
| `/<tag>/<asset>` | `github.com/litehop/u7s/releases/download/<tag>/<asset>`     |

Releases here are immutable -- assets freeze on publish and a used tag name can never be reused -- so no floating tag can carry rolling assets. The tag name is the channel selector, and these two fixed URLs are the whole channel design, with no GitHub API call to cache.

`/install.sh` rides GitHub's own `latest`: the newest release that is neither draft nor prerelease. It is a release *asset*, not a repo file, so script and tarball ship from one release and cannot skew.

`/<tag>/<asset>` reaches pre-release builds, which `latest` skips. It also serves `install.sh`, so `curl -sfL https://<host>/<tag>/install.sh | sh` is the pinned one-liner, and the script re-enters this route for its tarball. Tag and asset are forwarded verbatim; their patterns are deliberately narrow, since anything looser makes this an open `github.com` relay.

## Redirect chasing

GitHub download URLs do not serve bytes:

```
/releases/latest/download/<asset>
  -> 302 -> /releases/download/<tag>/<asset>
  -> 302 -> signed release-assets.githubusercontent.com URL (200/206)
```

`proxy_pass` will not follow those, and handing the 3xx to the client reintroduces the IPv6 problem. `@follow_hop1/2/3` chase them internally via `error_page 301 302 303 307 308` plus `recursive_error_pages on` -- three hops covers the two above.

Footgun: `$upstream_http_location` reads empty if used directly in the next hop's `proxy_pass`. Capture it first (`set $locN $upstream_http_location;`) in the same location, or nginx fails with `invalid URL prefix in ""`.

## Open items

- Ingress `cert-manager.io/cluster-issuer`, `ingressClassName` and hostname are `TODO` placeholders.
- External IPv6 reachability and `ipFamilyPolicy: PreferDualStack` are unverified against a real cluster.
- `/install.sh` 404s until a non-prerelease `v*` tag is pushed -- both existing releases are prereleases.
- `scripts/install.sh` still requires `--tarball <path>` and refuses URL fetches, so the one-liner is not yet end-to-end.
- `resolver` points at public DNS; if egress NetworkPolicy blocks it, hop chasing fails. Swap in the cluster DNS ClusterIP if so.
- `@follow_hop3` has no `error_page`, so a fourth GitHub hop would reach the client instead of failing loudly.
