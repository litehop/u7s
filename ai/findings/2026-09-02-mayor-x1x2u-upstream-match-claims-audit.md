Bead: mayor-x1x2u

## Verdict

3 of 4 "Matches upstream" claims hold exactly. The 4th (nodeclient
ClusterRoleBinding, lib.rs ~1998) is inaccurate on the binding's subject
group, but not a functional RBAC gap — severity lower/P3, comment-wording
only, no k8s workflow is blocked.

## Per-claim comparison

| u7s (lib.rs) | Claim | Upstream ref (k/k release-1.36) | Verdict | Severity |
|---|---|---|---|---|
| ~1447-1449, `services` rule in `system:node` ClusterRole | "Matches upstream bootstrappolicy.go's NodeRules() exactly" | `plugin/.../bootstrappolicy/policy.go:207`: `NewRule(Read...).Resources("services")`, `Read=[get,list,watch]` | MATCH | — |
| ~1997-2017 (comment ~1998), nodeclient ClusterRoleBinding → `system:bootstrappers` | "Matches upstream's `kubeadm:node-autoapprove-bootstrap` ClusterRoleBinding" | `policy.go` does **not** define this binding — it's created by `kubeadm init`, not kube-apiserver bootstrap policy (`cmd/kubeadm/app/phases/bootstraptoken/node/tlsbootstrap.go:94-109`). Real subject = `NodeBootstrapTokenAuthGroup` = `system:bootstrappers:kubeadm:default-node-token` (`constants.go:181`), a narrower subgroup. The nodeclient ClusterRole's own rules do match `policy.go:516-519` exactly. | MISMATCH (subject broader than upstream; comment overclaims literal binding parity) | lower/P3 |
| ~2040-2061 (comment ~2042), selfnodeclient ClusterRoleBinding → `system:nodes` | "Matches upstream's `kubeadm:node-autoapprove-certificate-rotation` ClusterRoleBinding" | `tlsbootstrap.go:116-131`, subject = `NodesGroup` = `system:nodes` (`constants.go:179`); role matches `policy.go:521-526` | MATCH | — |
| ~2101-2124 (comment ~2105), service-account-issuer-discovery binding → `system:serviceaccounts` | "Matches upstream Kubernetes bootstrap policy" | `policy.go:723`, subject = `AllServiceAccountsGroup` = `system:serviceaccounts` (`staging/.../authentication/serviceaccount/util.go:32`) | MATCH | — |

## Why the mismatch isn't P0/P1

u7s's bootstrap-token auth never implements kubeadm's
`system:bootstrappers:kubeadm:default-node-token` subgroup — every
bootstrap-token-authenticated identity gets exactly `system:bootstrappers`
(`csr.rs:897,913,964,986`; asserted by tests at `lib.rs:5757-5852`). Binding
the ClusterRole to the narrower upstream subgroup would break u7s's own node
join flow outright, since no token would ever land in that group. The
broader group is the only way this binding functions for u7s today — the
gap is that the comment claims byte-for-byte parity with a specific named
kubeadm object when the subject was deliberately widened. Risk is
theoretical over-privilege (any `system:bootstrappers` token, not just
kubeadm-default ones, can self-approve a node CSR), not a blocked workflow.

## Follow-on beads filed

One follow-on bead filed for the comment-accuracy mismatch (P3): reword the
`lib.rs` ~1998 comment to state the subject group is a deliberate
simplification of kubeadm's model, not a literal match — bead ID recorded
in mayor-x1x2u's notes.
