# Argo CD Gap Analysis

Date: 2026-05-19
Bead: mayor-cw9

## Method

Fetched `https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml`
and extracted all `kind:` / `apiVersion:` pairs. Cross-referenced against:
- `crates/apiserver/src/main.rs` — router (route registrations)
- `crates/apiserver/src/state.rs` — resource registry (`build_registry`)
- `crates/apiserver/src/handlers/discovery.rs` — STATIC_GROUPS and api_group_resources

## Resource types in Argo CD stable install manifest

| apiVersion | kind | u7s status |
|---|---|---|
| v1 | ConfigMap | SUPPORTED |
| v1 | Namespace | SUPPORTED |
| v1 | Secret | SUPPORTED |
| v1 | Service | SUPPORTED |
| v1 | ServiceAccount | SUPPORTED |
| apps/v1 | Deployment | SUPPORTED |
| apps/v1 | StatefulSet | SUPPORTED |
| rbac.authorization.k8s.io/v1 | ClusterRole | SUPPORTED |
| rbac.authorization.k8s.io/v1 | ClusterRoleBinding | SUPPORTED |
| rbac.authorization.k8s.io/v1 | Role | SUPPORTED |
| rbac.authorization.k8s.io/v1 | RoleBinding | SUPPORTED |
| apiextensions.k8s.io/v1 | CustomResourceDefinition | SUPPORTED |
| networking.k8s.io/v1 | NetworkPolicy | GAP — mayor-bph |
| admissionregistration.k8s.io/v1 | ValidatingWebhookConfiguration | GAP — mayor-5d9 |
| admissionregistration.k8s.io/v1 | MutatingWebhookConfiguration | GAP — mayor-5d9 |
| policy/v1 | PodDisruptionBudget | GAP — mayor-9za |

## Behavioral gaps (runtime failures)

| Gap | Impact | Bead |
|---|---|---|
| Strategic merge patch rejected (HTTP 415) | `kubectl apply` re-apply fails for all existing resources | mayor-7ak |
| Watch on core/v1 Namespaces missing | Argo CD cannot watch namespaces for app namespace discovery | mayor-5l4 |
| SubjectAccessReview missing | Argo CD cannot check per-user access; RBAC enforcement in UI broken | mayor-cn8 |
| TokenReview missing | Argo CD OIDC/Dex SSO token validation fails | mayor-cn8 |
| coordination.k8s.io/v1 (Lease) missing | Leader election fails; Argo CD controllers run without coordination | mayor-9xr |
| CRD /status subresource path for CR instances | Argo CD application-controller cannot write Application status | mayor-uca |

## Argo CD CRDs (installed by Argo CD itself)

Argo CD's install manifest creates these CRDs:
- `applications.argoproj.io` (v1alpha1) — namespaced
- `applicationsets.argoproj.io` (v1alpha1) — namespaced
- `appprojects.argoproj.io` (v1alpha1) — namespaced

These CRDs install correctly via the CRD handler. The CR instance CRUD path (through `cr.rs`) works for create/get/list/delete/patch. The gap is the `/status` subresource for CR instances (mayor-uca), which the Argo CD application-controller needs to report sync status.

## What already works

- Install manifest `kubectl apply` (first run, all objects new): ConfigMap, Namespace, Secret, Service, ServiceAccount, Deployment, StatefulSet, ClusterRole, ClusterRoleBinding, Role, RoleBinding, CRD objects all persist correctly.
- RBAC: Argo CD's roles/bindings are stored and indexed.
- ServiceAccount token creation (TokenRequest API) works.
- Generic watch for non-core groups already implemented (apps/v1, rbac, custom groups).

## Priority order for unblocking Argo CD

1. **mayor-7ak** — strategic merge patch: blocks idempotent `kubectl apply` (re-apply)
2. **mayor-bph** — networking.k8s.io: blocks install manifest apply
3. **mayor-5d9** — admissionregistration.k8s.io: blocks install manifest apply
4. **mayor-9xr** — coordination.k8s.io Leases: blocks controller leader election
5. **mayor-uca** — CRD /status subresource: blocks application-controller status reporting
6. **mayor-5l4** — namespace watch: blocks Argo CD namespace discovery
7. **mayor-cn8** — SubjectAccessReview/TokenReview: blocks SSO and per-user RBAC in UI
8. **mayor-9za** — policy/v1 PDB: lower priority, only affects HA install profile
