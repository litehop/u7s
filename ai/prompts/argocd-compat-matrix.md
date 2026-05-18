# Argo CD Compatibility Matrix for u7s

**Status:** Research document. Last updated: 2026-05-18.
**Argo CD version target:** v2.13 (latest stable as of early 2026; released late 2025).
**Purpose:** Gap analysis driving u7s implementation prioritization for the Argo CD GitOps milestone.

> **Note on research methodology:** This document is synthesized from Argo CD's published RBAC manifests
> (`install.yaml`), source code, and official documentation. Where exact API paths are cited they are
> derived from Argo CD's ClusterRole definitions and controller source. If a future version changes a
> specific verb or adds a resource, update this document and re-prioritize accordingly.

---

## 1. Executive Summary

To run a functional Argo CD GitOps setup on u7s, the API server must implement the following minimum
surface:

**Minimum for Argo CD to start (pre-sync):**

- `core/v1`: Secrets, ConfigMaps, ServiceAccounts, Namespaces, Events, Pods (read-only enough to check
  health), Services — get/list/watch/create/update/patch
- `apps/v1`: Deployments, ReplicaSets, StatefulSets, DaemonSets — get/list/watch (Argo CD reads these as
  managed resources)
- `rbac.authorization.k8s.io/v1`: ClusterRoles, ClusterRoleBindings, Roles, RoleBindings — get/list/watch
  (Argo CD creates its own RBAC on install)
- `apiextensions.k8s.io/v1`: CustomResourceDefinitions — create/get/list/watch/patch (Argo CD installs
  its own CRDs on startup)
- `argoproj.io/v1alpha1`: Application, AppProject, ApplicationSet — full CRUD + watch (Argo CD's core
  objects; only accessible once CRDs are installed)
- Discovery endpoints: `/api`, `/apis`, `/apis/<group>/<version>` — required for the client to know
  what the server supports before making any other call

**Non-negotiable items:**

- Watch streams with `allowWatchBookmarks=true` support — Argo CD's informers require reliable reconnect
  semantics
- `410 Gone` response when a watch `resourceVersion` is too old — forces a clean relist, required by the
  client-go informer contract
- Server-side apply (`PATCH` with `Content-Type: application/apply-patch+yaml`) — argocd-application-controller
  defaults to SSA when the server supports it; without it the controller falls back to SMP but SSA is
  the expected path in v2.13+
- Status subresource on `argoproj.io/v1alpha1/applications` — the controller writes sync/health status
  to `.status` separately from `.spec`
- RBAC enforcement — Argo CD's service accounts require specific ClusterRole permissions; a permissive
  allow-all policy is acceptable for early bring-up but must eventually be correct
- Namespace-scoped vs. cluster-scoped resource distinction — Argo CD can manage both; the API server
  must correctly route cluster-scoped resources (e.g., `ClusterRole`) to non-namespaced paths

---

## 2. Argo CD Component Breakdown

### 2.1 argocd-application-controller

The most API-intensive component. Runs the GitOps reconciliation loop: compares desired state (rendered
manifests from git) with live state in the cluster, and syncs.

**Startup calls (must succeed before the controller starts):**

```
GET /apis                                    # discover all API groups
GET /api/v1                                  # discover core resources
GET /apis/<group>/<version>                  # per-group discovery (repeated for all groups)
GET /api/v1/namespaces                       # list all namespaces (builds namespace cache)
GET /apis/argoproj.io/v1alpha1/applications  # list all Application objects
GET /apis/argoproj.io/v1alpha1/appprojects   # list all AppProject objects
```

**Watches maintained (long-lived, reconnect on disconnect):**

```
GET /apis/argoproj.io/v1alpha1/applications?watch=true&allowWatchBookmarks=true
GET /apis/argoproj.io/v1alpha1/appprojects?watch=true&allowWatchBookmarks=true
GET /api/v1/namespaces?watch=true&allowWatchBookmarks=true
```

**Per-sync reads (for every Application being synced):**

The controller performs a "live state cache": it lists and watches every resource type that appears in
the git manifests, across every managed namespace. For a typical GitOps workload:

```
GET /apis/apps/v1/namespaces/{ns}/deployments             # list
GET /apis/apps/v1/namespaces/{ns}/deployments?watch=true  # watch
GET /api/v1/namespaces/{ns}/services
GET /api/v1/namespaces/{ns}/configmaps
GET /api/v1/namespaces/{ns}/secrets                       # filtered: only non-SA secrets
GET /api/v1/namespaces/{ns}/serviceaccounts
GET /apis/apps/v1/namespaces/{ns}/statefulsets
GET /apis/apps/v1/namespaces/{ns}/daemonsets
GET /apis/networking.k8s.io/v1/namespaces/{ns}/ingresses  # if used by managed apps
GET /apis/batch/v1/namespaces/{ns}/jobs                   # if used
GET /apis/batch/v1/namespaces/{ns}/cronjobs               # if used
```

For cluster-scoped resources managed by Argo CD:

```
GET /apis/rbac.authorization.k8s.io/v1/clusterroles
GET /apis/rbac.authorization.k8s.io/v1/clusterrolebindings
GET /api/v1/namespaces                                    # cluster-scoped
GET /api/v1/persistentvolumes                             # if PVs managed
```

**Sync writes (apply managed resources to cluster):**

The controller defaults to server-side apply in v2.13:

```
PATCH /apis/apps/v1/namespaces/{ns}/deployments/{name}
  Content-Type: application/apply-patch+yaml
  ?fieldManager=argocd-controller&force=true
```

Fallback (when SSA not supported):

```
PATCH /apis/apps/v1/namespaces/{ns}/deployments/{name}
  Content-Type: application/strategic-merge-patch+json
```

For custom resources (CRDs):

```
PATCH /apis/{group}/{version}/namespaces/{ns}/{resource}/{name}
  Content-Type: application/apply-patch+yaml  (SSA preferred)
  Content-Type: application/merge-patch+json  (fallback)
```

**Status writes:**

```
PATCH /apis/argoproj.io/v1alpha1/namespaces/{ns}/applications/{name}/status
  Content-Type: application/merge-patch+json
```

**Event writes:**

```
POST /api/v1/namespaces/{ns}/events
PATCH /api/v1/namespaces/{ns}/events/{name}
  Content-Type: application/strategic-merge-patch+json
```

**Delete on prune:**

```
DELETE /apis/apps/v1/namespaces/{ns}/deployments/{name}
DELETE /api/v1/namespaces/{ns}/services/{name}
# ...for any resource type pruned
```

**Self-healing reads (compare live vs desired):**

The controller watches every managed resource type. When a watch event fires, it diffs the live object
against the last-rendered manifest and re-syncs if the resource was externally modified (self-heal mode).

**Verbs summary for argocd-application-controller:**

| Resource | Verbs |
|---|---|
| `argoproj.io/v1alpha1/applications` | get, list, watch, update, patch |
| `argoproj.io/v1alpha1/appprojects` | get, list, watch |
| `argoproj.io/v1alpha1/applications/status` | patch, update |
| `argoproj.io/v1alpha1/applications/finalizers` | update |
| `core/v1/namespaces` | get, list, watch |
| `core/v1/events` | create, patch |
| `core/v1/secrets` | get, list, watch (for managed secrets) |
| `core/v1/configmaps` | get, list, watch, create, update, patch |
| `core/v1/pods` | get, list, watch, delete (for pod-level resources) |
| `core/v1/pods/log` | get (for resource actions) |
| `core/v1/services` | get, list, watch, create, update, patch, delete |
| `core/v1/serviceaccounts` | get, list, watch, create, update, patch, delete |
| `apps/v1/deployments` | get, list, watch, create, update, patch, delete |
| `apps/v1/replicasets` | get, list, watch, create, update, patch, delete |
| `apps/v1/statefulsets` | get, list, watch, create, update, patch, delete |
| `apps/v1/daemonsets` | get, list, watch, create, update, patch, delete |
| `rbac.authorization.k8s.io/v1/clusterroles` | get, list, watch, create, update, patch, delete |
| `rbac.authorization.k8s.io/v1/clusterrolebindings` | get, list, watch, create, update, patch, delete |
| `rbac.authorization.k8s.io/v1/roles` | get, list, watch, create, update, patch, delete |
| `rbac.authorization.k8s.io/v1/rolebindings` | get, list, watch, create, update, patch, delete |
| `apiextensions.k8s.io/v1/customresourcedefinitions` | get, list, watch, create, update, patch |
| `batch/v1/jobs` | get, list, watch, create, update, patch, delete |
| `batch/v1/cronjobs` | get, list, watch, create, update, patch, delete |
| `networking.k8s.io/v1/ingresses` | get, list, watch, create, update, patch, delete |
| `policy/v1/poddisruptionbudgets` | get, list, watch, create, update, patch, delete |

The application-controller's ClusterRole uses `*` verbs on `*` resources in `*` apiGroups for managed
resource namespaces. In practice u7s must implement the resources above for a basic GitOps workload.

### 2.2 argocd-server

The API/UI server. Proxies Argo CD API calls to the Kubernetes API and serves the Argo CD web UI.

**Startup reads:**

```
GET /api/v1/namespaces/argocd/configmaps/argocd-cm        # main config
GET /api/v1/namespaces/argocd/secrets/argocd-secret       # signing key, admin password hash
GET /api/v1/namespaces/argocd/configmaps/argocd-rbac-cm   # RBAC policy
GET /api/v1/namespaces/argocd/configmaps/argocd-tls-certs-cm  # TLS certs for repos
GET /api/v1/namespaces/argocd/configmaps/argocd-ssh-known-hosts-cm
```

**Ongoing watches:**

```
GET /api/v1/namespaces/argocd/configmaps?watch=true&allowWatchBookmarks=true
GET /api/v1/namespaces/argocd/secrets?watch=true&allowWatchBookmarks=true
GET /apis/argoproj.io/v1alpha1/namespaces/{ns}/applications?watch=true
GET /apis/argoproj.io/v1alpha1/appprojects?watch=true
```

**When a user performs an action via the UI/CLI:**

```
# Get resource tree (show live state in UI)
GET /apis/apps/v1/namespaces/{ns}/deployments/{name}
GET /api/v1/namespaces/{ns}/replicasets      # (via legacy field)
GET /api/v1/namespaces/{ns}/pods
GET /api/v1/namespaces/{ns}/pods/{name}/log  # pod log streaming

# Resource actions (sync, rollback, delete)
# Delegates to application-controller via gRPC, which then calls K8s API

# Application CRUD
GET    /apis/argoproj.io/v1alpha1/namespaces/argocd/applications
POST   /apis/argoproj.io/v1alpha1/namespaces/argocd/applications
PUT    /apis/argoproj.io/v1alpha1/namespaces/argocd/applications/{name}
PATCH  /apis/argoproj.io/v1alpha1/namespaces/argocd/applications/{name}
DELETE /apis/argoproj.io/v1alpha1/namespaces/argocd/applications/{name}
```

**RBAC-related reads (for Argo CD's own authorization):**

```
GET /api/v1/namespaces/argocd/configmaps/argocd-rbac-cm   # policy.csv and scopes
```

argocd-server implements its own RBAC layer on top of Kubernetes RBAC — the `argocd-rbac-cm` ConfigMap
contains Casbin-format policies. The server does not call `SubjectAccessReview` or `SelfSubjectAccessReview`
for its internal authorization; it evaluates Casbin policies directly.

However, argocd-server may call `SelfSubjectAccessReview` to determine what the logged-in user can do
in the cluster:

```
POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews
POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews
```

**Verbs summary for argocd-server:**

| Resource | Verbs |
|---|---|
| `core/v1/configmaps` (argocd ns) | get, list, watch, create, update, patch |
| `core/v1/secrets` (argocd ns) | get, list, watch, create, update, patch |
| `core/v1/events` | get, list, watch |
| `core/v1/pods/log` | get |
| `core/v1/pods` | get, list, delete |
| `argoproj.io/v1alpha1/applications` | get, list, watch, create, update, patch, delete |
| `argoproj.io/v1alpha1/appprojects` | get, list, watch, create, update, patch, delete |
| `argoproj.io/v1alpha1/applicationsets` | get, list, watch |
| `authorization.k8s.io/v1/selfsubjectaccessreviews` | create |
| `authorization.k8s.io/v1/selfsubjectrulesreviews` | create |

### 2.3 argocd-repo-server

Fetches git repositories, renders Helm/Kustomize/plain manifests, and returns them to the
application-controller. **argocd-repo-server has minimal direct Kubernetes API interaction.** It reads
a few secrets for repository credentials and TLS configuration.

**Kubernetes API calls:**

```
GET /api/v1/namespaces/argocd/secrets?labelSelector=argocd.argoproj.io/secret-type=repository
GET /api/v1/namespaces/argocd/secrets?labelSelector=argocd.argoproj.io/secret-type=repo-creds
GET /api/v1/namespaces/argocd/secrets?labelSelector=argocd.argoproj.io/secret-type=cluster
GET /api/v1/namespaces/argocd/configmaps/argocd-tls-certs-cm
GET /api/v1/namespaces/argocd/configmaps/argocd-ssh-known-hosts-cm
GET /api/v1/namespaces/argocd/configmaps/argocd-cm   # for Helm version, plugin config
```

**Label selector watch:**

```
GET /api/v1/namespaces/argocd/secrets?labelSelector=argocd.argoproj.io/secret-type=repository&watch=true
```

This is the most label-selector-intensive watch that repo-server initiates. u7s must support
`?labelSelector=<key>=<value>` filtering on watch and list for Secrets and ConfigMaps.

**Verbs summary for argocd-repo-server:**

| Resource | Verbs |
|---|---|
| `core/v1/secrets` (argocd ns) | get, list, watch |
| `core/v1/configmaps` (argocd ns) | get, list, watch |

### 2.4 argocd-applicationset-controller

Watches ApplicationSet custom resources and generates Application objects from templates.

**Startup reads:**

```
GET /apis/argoproj.io/v1alpha1/applicationsets   # list all ApplicationSets
GET /apis/argoproj.io/v1alpha1/applications      # list existing Applications (to avoid duplicates)
```

**Ongoing watches:**

```
GET /apis/argoproj.io/v1alpha1/applicationsets?watch=true&allowWatchBookmarks=true
GET /apis/argoproj.io/v1alpha1/applications?watch=true
GET /api/v1/configmaps?watch=true&allowWatchBookmarks=true            # for ConfigMap generators
GET /api/v1/secrets?watch=true&allowWatchBookmarks=true               # for Secret generators
```

**For each ApplicationSet reconciliation:**

```
POST   /apis/argoproj.io/v1alpha1/namespaces/argocd/applications     # create generated App
PATCH  /apis/argoproj.io/v1alpha1/namespaces/argocd/applications/{n} # update generated App
DELETE /apis/argoproj.io/v1alpha1/namespaces/argocd/applications/{n} # delete when source removed
PATCH  /apis/argoproj.io/v1alpha1/namespaces/argocd/applicationsets/{n}/status
```

The ApplicationSet controller also reads cluster Secrets to enumerate target clusters for multi-cluster
generators:

```
GET /api/v1/namespaces/argocd/secrets?labelSelector=argocd.argoproj.io/secret-type=cluster
```

**Verbs summary for argocd-applicationset-controller:**

| Resource | Verbs |
|---|---|
| `argoproj.io/v1alpha1/applicationsets` | get, list, watch, update, patch |
| `argoproj.io/v1alpha1/applicationsets/status` | patch, update |
| `argoproj.io/v1alpha1/applicationsets/finalizers` | update |
| `argoproj.io/v1alpha1/applications` | get, list, watch, create, update, patch, delete |
| `core/v1/configmaps` | get, list, watch, create, update, patch, delete |
| `core/v1/secrets` | get, list, watch |
| `core/v1/events` | create, patch |

### 2.5 argocd-dex

Dex is an OIDC identity provider. It is **optional** — Argo CD can use local user accounts (stored in
`argocd-secret`) without Dex. For the u7s bring-up milestone, Dex can be disabled.

When Dex IS running, its Kubernetes API calls are minimal:

```
GET /api/v1/namespaces/argocd/configmaps/argocd-cm   # to find Dex config
GET /api/v1/namespaces/argocd/secrets/argocd-secret   # to find OAuth client secrets
```

Dex stores its state in memory or in an external database (SQLite by default in the Argo CD bundle),
not in Kubernetes objects.

**To disable Dex:** Set `server.dex.server.disable: "true"` in `argocd-cm`. No Kubernetes API calls
from Dex to worry about.

### 2.6 argocd-redis

Redis is used as an internal cache between argocd-server, argocd-application-controller, and argocd-repo-server.
It caches rendered manifests, cluster resource trees, and app state summaries.

**Redis makes no Kubernetes API calls.** It is a pure in-memory data structure server. u7s has no
special implementation requirement for Redis. Argo CD connects to Redis via TCP on port 6379; the
Redis Pod itself is a standard Kubernetes workload.

The Redis Pod is created by the Argo CD install manifest as a Deployment with a ClusterIP Service.
u7s must be able to run this Deployment as a normal workload — no special API requirements beyond
standard Pod/Deployment/Service lifecycle.

---

## 3. CRD Surface

Argo CD installs the following CRDs. u7s must support CRD registration (`apiextensions.k8s.io/v1`)
and must dynamically expose the corresponding custom resource API routes.

### 3.1 Application

```
group:    argoproj.io
version:  v1alpha1
kind:     Application
plural:   applications
scope:    Namespaced
```

**Schema complexity: HIGH.** The Application CRD has deeply nested schema:
- `spec.source` / `spec.sources[]` — Helm values, Kustomize config, plugin config, directory recurse
- `spec.destination` — server URL or cluster name + namespace
- `spec.syncPolicy` — automated sync, prune, self-heal, retry config, managed namespace annotations
- `status` — sync status, health status, conditions, resources[], operationState, summary
- `status.resources[]` — per-resource health/sync status; large arrays in real clusters

The Application CRD uses a **status subresource**. u7s must implement the status subresource for this
CRD: `PATCH /apis/argoproj.io/v1alpha1/namespaces/{ns}/applications/{name}/status`.

CEL validation rules are present in v2.12+ Application CRDs. u7s must run CEL validation or skip
it gracefully (accept the object without CEL validation) for bring-up.

### 3.2 AppProject

```
group:    argoproj.io
version:  v1alpha1
kind:     AppProject
plural:   appprojects
scope:    Namespaced (but in practice only in the argocd namespace)
```

**Schema complexity: MEDIUM.** AppProject defines allowed repositories, destination clusters/namespaces,
and allowed resource kinds. The schema is nested but not deeply so. No status subresource.

Key fields: `spec.destinations[]`, `spec.sourceRepos[]`, `spec.clusterResourceWhitelist[]`,
`spec.namespaceResourceBlacklist[]`, `spec.roles[]` (with Casbin-format policy rules).

### 3.3 ApplicationSet

```
group:    argoproj.io
version:  v1alpha1
kind:     ApplicationSet
plural:   applicationsets
scope:    Namespaced
```

**Schema complexity: HIGH.** ApplicationSet schemas include:
- `spec.generators[]` — many generator types: List, Cluster, Git, Matrix, Merge, SCMProvider,
  PullRequest, ClusterDecisionResource
- `spec.template` — an embedded Application spec
- `spec.strategy` — rolling sync strategy for generated apps
- `status.conditions[]`, `status.applicationStatus[]`

Status subresource: YES. u7s must support `applicationsets/status`.

### 3.4 Summary of CRDs

| CRD | Group | Version | Scope | Status Subresource | Schema Complexity |
|---|---|---|---|---|---|
| applications | argoproj.io | v1alpha1 | Namespaced | Yes | High |
| appprojects | argoproj.io | v1alpha1 | Namespaced | No | Medium |
| applicationsets | argoproj.io | v1alpha1 | Namespaced | Yes | High |

All three CRDs must support: get, list, watch, create, update, patch, delete, deletecollection.

**CRD installation path:** Argo CD's installer applies the CRD manifests on first deploy. The
application-controller checks for the CRDs on startup and will refuse to start if they are missing.
u7s must accept `POST /apis/apiextensions.k8s.io/v1/customresourcedefinitions` before any Argo CD
component can function.

---

## 4. RBAC Requirements

### 4.1 Service Accounts

Argo CD creates the following ServiceAccounts (all in the `argocd` namespace):

| ServiceAccount | Used By |
|---|---|
| `argocd-application-controller` | application-controller StatefulSet |
| `argocd-server` | argocd-server Deployment |
| `argocd-repo-server` | argocd-repo-server Deployment |
| `argocd-applicationset-controller` | applicationset-controller Deployment |
| `argocd-dex-server` | dex Deployment (if Dex enabled) |
| `argocd-redis` | redis Deployment |

### 4.2 ClusterRoles

**argocd-application-controller** (ClusterRole: `argocd-application-controller`):

This is the most permissive role. In the default install, it is effectively `cluster-admin` for
namespaces it manages:

```yaml
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

The `*/*` wildcard means: u7s must implement the complete Kubernetes RBAC wildcard matching. When the
application-controller tries to list/watch a resource type to build its live-state cache, the RBAC
check for that resource must succeed.

In practice (restricted install mode), the controller has:

```yaml
rules:
# Core resources it needs explicitly
- apiGroups: [""]
  resources: [events]
  verbs: [create, list, watch]
- apiGroups: [""]
  resources: [pods, pods/log]
  verbs: [get, list, watch]
- apiGroups: [apps]
  resources: [deployments, replicasets, statefulsets, daemonsets]
  verbs: [get, list, watch, create, update, patch, delete]
- apiGroups: [argoproj.io]
  resources: [applications, appprojects, applicationsets]
  verbs: [create, get, list, watch, update, patch, delete]
- apiGroups: [argoproj.io]
  resources: [applications/status, applications/finalizers]
  verbs: [get, patch, update]
- apiGroups: [apiextensions.k8s.io]
  resources: [customresourcedefinitions]
  verbs: [get, list, watch]
# ...plus all managed resource types
```

**argocd-server** (ClusterRole: `argocd-server`):

```yaml
rules:
- apiGroups: [""]
  resources: [configmaps, endpoints, pods, pods/log, secrets, serviceaccounts, services]
  verbs: [get, list, watch]
- apiGroups: [""]
  resources: [events]
  verbs: [list, watch]
- apiGroups: [""]
  resources: [pods, pods/exec]
  verbs: [create, delete]
- apiGroups: [argoproj.io]
  resources: [applications, appprojects, applicationsets]
  verbs: [create, delete, get, list, patch, update, watch]
- apiGroups: [batch]
  resources: [jobs]
  verbs: [create, delete, get, list, watch]
- apiGroups: [apps]
  resources: [deployments, replicasets, statefulsets, daemonsets]
  verbs: [get, list, watch]
- apiGroups: [authorization.k8s.io]
  resources: [selfsubjectaccessreviews, selfsubjectrulesreviews]
  verbs: [create]
- apiGroups: [rbac.authorization.k8s.io]
  resources: [clusterroles, clusterrolebindings, roles, rolebindings]
  verbs: [get, list, watch]
```

**argocd-applicationset-controller** (ClusterRole: `argocd-applicationset-controller`):

```yaml
rules:
- apiGroups: [argoproj.io]
  resources: [applications, applicationsets, applicationsets/status, applicationsets/finalizers]
  verbs: [create, delete, get, list, patch, update, watch]
- apiGroups: [""]
  resources: [events]
  verbs: [create, list, watch, patch]
- apiGroups: [""]
  resources: [configmaps, secrets]
  verbs: [get, list, watch, create, update, patch, delete]
```

**argocd-repo-server** (no ClusterRole; uses a Role in the argocd namespace):

```yaml
rules:
- apiGroups: [""]
  resources: [configmaps, secrets]
  verbs: [get, list, watch]
```

### 4.3 ClusterRoleBindings

| ClusterRoleBinding | ServiceAccount | ClusterRole |
|---|---|---|
| `argocd-application-controller` | argocd/argocd-application-controller | argocd-application-controller |
| `argocd-server` | argocd/argocd-server | argocd-server |
| `argocd-applicationset-controller` | argocd/argocd-applicationset-controller | argocd-applicationset-controller |

### 4.4 RBAC Implementation Requirements for u7s

1. u7s must support wildcard `*` in `apiGroups`, `resources`, and `verbs` in ClusterRole rules.
2. u7s must support subresource matching in RBAC rules (e.g., `pods/log`, `applications/status`).
3. u7s must resolve ClusterRoleBindings at request time to grant cluster-wide access.
4. u7s must support `authorization.k8s.io/v1/selfsubjectaccessreviews` — this is a virtual resource
   (no stored objects); the handler evaluates the caller's permissions and returns a result.

---

## 5. Watch and Informer Requirements

### 5.1 Watch patterns used by Argo CD

All Argo CD components use `client-go`'s informer framework. The watch pattern is:

1. List all objects of a type at a specific `resourceVersion` (or `resourceVersion=0` for "get current").
2. Start a watch from the returned list's `resourceVersion`.
3. Process events: ADDED, MODIFIED, DELETED, BOOKMARK.
4. On error or disconnect: re-list from the last seen BOOKMARK revision, then re-watch.
5. If the server returns `410 Gone`: full re-list from `resourceVersion=""`.

### 5.2 Required watch behaviors

**`allowWatchBookmarks=true`:**
The client sends `?allowWatchBookmarks=true` on every watch request. u7s must send BOOKMARK events
periodically (at most every 60 seconds with no other events) to give the client a fresh checkpoint.
BOOKMARK format:

```json
{"type":"BOOKMARK","object":{"apiVersion":"argoproj.io/v1alpha1","kind":"Application","metadata":{"resourceVersion":"12345"}}}
```

**`410 Gone` on stale resourceVersion:**
If a client reconnects with a `resourceVersion` that has been compacted from u7s's watch history
ring buffer, u7s must return `HTTP 410 Gone`. The client-go informer handles this by performing a
full relist. If u7s returns any other error, the informer may get stuck.

**`resourceVersion=0` semantics:**
A watch with `resourceVersion=0` means "start from now; give me a snapshot of current state via
ADDED events, then stream future changes." u7s must deliver synthetic ADDED events for all existing
objects at start of stream (or return them in the initial list, then stream from that list's rv).

Actually, `resourceVersion=0` on a LIST means "give me the freshest data the server has (may be
cached)". On a WATCH it means "give me events from now." These are distinct. u7s must implement both.

**Field selectors on watches:**
- `spec.nodeName=<node>` — used by kubelet-equivalent, not Argo CD directly
- `metadata.name=<name>` — single-object watch (Argo CD uses this for specific ConfigMaps)
- `involvedObject.name=<name>` — for event watches (argocd-server)

argocd-repo-server and argocd-server use **label selectors** on watch/list:

```
?labelSelector=argocd.argoproj.io/secret-type=repository
?labelSelector=argocd.argoproj.io/secret-type=cluster
```

u7s must support label selector filtering on both list and watch for at minimum: Secrets, ConfigMaps.

### 5.3 Watch resource types and expected volume

| Resource | Watcher | Label/Field Selector | Volume |
|---|---|---|---|
| `argoproj.io/v1alpha1/applications` | app-controller, server, appset-controller | none | low (10s of apps) |
| `argoproj.io/v1alpha1/appprojects` | app-controller, server | none | low |
| `argoproj.io/v1alpha1/applicationsets` | appset-controller | none | low |
| `core/v1/namespaces` | app-controller | none | low |
| `core/v1/secrets` (argocd ns) | server, repo-server, appset-controller | label selector | low |
| `core/v1/configmaps` (argocd ns) | server, repo-server, appset-controller | none | low |
| `apps/v1/deployments` | app-controller (per managed namespace) | none | medium |
| `apps/v1/statefulsets` | app-controller (per managed namespace) | none | medium |
| `core/v1/services` | app-controller (per managed namespace) | none | medium |
| `core/v1/pods` | app-controller (liveness/health check) | none | high (many pods) |

### 5.4 Watch reconnect behavior

client-go uses exponential backoff with jitter on reconnect. The server does not need to do anything
special for reconnect. However:

- The server MUST NOT close idle watch connections proactively (no idle timeout shorter than ~5 min).
- The server MUST handle watch cancellation cleanly when the HTTP connection closes (no goroutine leaks).
- The server SHOULD send a BOOKMARK at least every 60 seconds to prevent the client from re-listing
  unnecessarily.

---

## 6. Secret and ConfigMap Usage

Argo CD reads and writes specific ConfigMaps and Secrets in the `argocd` namespace. u7s must store
and serve these correctly; no special behavior beyond standard CRUD is required.

### 6.1 ConfigMaps

| Name | R/W | Contents |
|---|---|---|
| `argocd-cm` | R | Main Argo CD config: repo URLs, OIDC config, Dex config, resource exclusions, status badge, Helm settings |
| `argocd-rbac-cm` | R | Casbin RBAC policy (`policy.default`, `policy.csv`, `scopes`) |
| `argocd-tls-certs-cm` | R | Custom TLS certs for private git repos (keyed by hostname) |
| `argocd-ssh-known-hosts-cm` | R | SSH known hosts for git repos |
| `argocd-gpg-keys-cm` | R | GPG keys for commit verification |
| `argocd-cmd-params-cm` | R | Command-line parameter overrides for all Argo CD components |

All are read on startup and watched for changes (hot reload without restart).

### 6.2 Secrets

| Name | R/W | Contents |
|---|---|---|
| `argocd-secret` | R/W | `admin.password` (bcrypt), `admin.passwordMtime`, `server.secretkey` (JWT signing), `webhook.github.secret`, etc. |
| `argocd-initial-admin-secret` | R | Initial admin password (written by installer, read once by `argocd-server`) |
| `<repo-name>` (label: `argocd.argoproj.io/secret-type=repository`) | R | Per-repo: `url`, `username`, `password`, `sshPrivateKey`, `tlsClientCertData`, `tlsClientCertKey` |
| `<cluster-name>` (label: `argocd.argoproj.io/secret-type=cluster`) | R | Per-cluster: `server` URL, `name`, `config` (JSON with bearer token or exec config) |

**Note:** Argo CD lists repository and cluster secrets using label selectors, not by name. u7s must
index Secrets by labels for efficient label-selector queries. A full scan is acceptable for small
clusters (under 100 secrets) but a label index will be needed for performance at scale.

### 6.3 Secret access patterns

The application-controller reads cluster secrets on startup to build its multi-cluster client map.
For a single-cluster setup (Argo CD managing the cluster it runs in), it uses the in-cluster service
account token instead.

argocd-server reads `argocd-secret` on every user login to verify the admin password hash. This is
a frequent read — u7s's GET path for secrets must be fast (direct state store lookup, not a list scan).

---

## 7. Gap Analysis Table

This table is the actionable output. Priority: **must-have** = Argo CD will not start or sync without it.
**nice-to-have** = Argo CD starts and syncs basic workloads but some features are degraded.
**out-of-scope** = Not needed for the Argo CD GitOps milestone.

| API Group/Resource | Verbs | Priority | Notes |
|---|---|---|---|
| **Discovery** | | | |
| `GET /api` | — | must-have | First call any K8s client makes |
| `GET /apis` | — | must-have | First call any K8s client makes |
| `GET /api/v1` | — | must-have | Lists core resources |
| `GET /apis/{group}/{version}` | — | must-have | Per-group resource discovery |
| **core/v1** | | | |
| `core/v1/namespaces` | get, list, watch, create, update, patch, delete | must-have | App-controller lists all namespaces at startup |
| `core/v1/secrets` | get, list, watch, create, update, patch, delete | must-have | Argo CD config, repo creds, cluster creds |
| `core/v1/configmaps` | get, list, watch, create, update, patch, delete | must-have | All Argo CD config lives here |
| `core/v1/serviceaccounts` | get, list, watch, create, update, patch, delete | must-have | Argo CD creates its own SAs on install |
| `core/v1/services` | get, list, watch, create, update, patch, delete | must-have | Redis, argocd-server, dex services |
| `core/v1/pods` | get, list, watch, delete | must-have | Health checking, exec, log streaming |
| `core/v1/pods/log` | get (streaming) | must-have | Argo CD UI log viewer; must stream |
| `core/v1/pods/exec` | create | nice-to-have | Terminal in UI; not needed for sync |
| `core/v1/events` | create, patch, list, watch | must-have | App-controller writes sync events |
| `core/v1/persistentvolumeclaims` | get, list, watch, create, update, patch, delete | nice-to-have | Only if managed apps use PVCs |
| `core/v1/persistentvolumes` | get, list, watch | nice-to-have | Only if managed apps use PVs |
| `core/v1/endpoints` | get, list, watch | nice-to-have | ArgoCD-server reads these for health |
| `core/v1/resourcequotas` | get, list, watch | nice-to-have | If managing quota objects |
| `core/v1/limitranges` | get, list, watch | nice-to-have | If managing LimitRange objects |
| **apps/v1** | | | |
| `apps/v1/deployments` | get, list, watch, create, update, patch, delete | must-have | Core workload type; Argo CD itself runs as Deployments |
| `apps/v1/replicasets` | get, list, watch | must-have | Health computation for Deployments |
| `apps/v1/statefulsets` | get, list, watch, create, update, patch, delete | must-have | Redis runs as StatefulSet |
| `apps/v1/daemonsets` | get, list, watch, create, update, patch, delete | nice-to-have | Not used by Argo CD itself; needed for managed apps |
| `apps/v1/*/status` | get, patch, update | must-have | Status subresource for all apps/v1 types |
| **rbac.authorization.k8s.io/v1** | | | |
| `rbac/v1/clusterroles` | get, list, watch, create, update, patch, delete | must-have | Argo CD install creates ClusterRoles |
| `rbac/v1/clusterrolebindings` | get, list, watch, create, update, patch, delete | must-have | Argo CD install creates ClusterRoleBindings |
| `rbac/v1/roles` | get, list, watch, create, update, patch, delete | must-have | Argo CD creates namespace-scoped Roles |
| `rbac/v1/rolebindings` | get, list, watch, create, update, patch, delete | must-have | Argo CD creates namespace-scoped RoleBindings |
| **apiextensions.k8s.io/v1** | | | |
| `apiextensions/v1/customresourcedefinitions` | get, list, watch, create, update, patch, delete | must-have | Argo CD installs 3 CRDs on startup |
| **argoproj.io/v1alpha1** | | | |
| `argoproj.io/v1alpha1/applications` | get, list, watch, create, update, patch, delete | must-have | Core Argo CD object |
| `argoproj.io/v1alpha1/applications/status` | get, patch, update | must-have | Controller writes sync/health status here |
| `argoproj.io/v1alpha1/applications/finalizers` | update | must-have | Cascade delete of resources on app delete |
| `argoproj.io/v1alpha1/appprojects` | get, list, watch, create, update, patch, delete | must-have | Authorization policy for Applications |
| `argoproj.io/v1alpha1/applicationsets` | get, list, watch, create, update, patch, delete | nice-to-have | Required only if ApplicationSet controller enabled |
| `argoproj.io/v1alpha1/applicationsets/status` | patch, update | nice-to-have | Required only if ApplicationSet controller enabled |
| **authorization.k8s.io/v1** | | | |
| `authorization.k8s.io/v1/selfsubjectaccessreviews` | create | nice-to-have | UI feature; not needed for sync |
| `authorization.k8s.io/v1/selfsubjectrulesreviews` | create | nice-to-have | UI feature; not needed for sync |
| **batch/v1** | | | |
| `batch/v1/jobs` | get, list, watch, create, update, patch, delete | nice-to-have | Only if managed apps use Jobs |
| `batch/v1/cronjobs` | get, list, watch, create, update, patch, delete | nice-to-have | Only if managed apps use CronJobs |
| **networking.k8s.io/v1** | | | |
| `networking/v1/ingresses` | get, list, watch, create, update, patch, delete | nice-to-have | Only if managed apps use Ingresses |
| `networking/v1/networkpolicies` | get, list, watch, create, update, patch, delete | nice-to-have | Can store; enforcement is CNI's job |
| **policy/v1** | | | |
| `policy/v1/poddisruptionbudgets` | get, list, watch, create, update, patch, delete | nice-to-have | Only if managed apps use PDBs |
| **Patch mechanics** | | | |
| Server-side apply (`application/apply-patch+yaml`) | — | must-have | Default in Argo CD v2.12+; fallback to SMP without it but SSA is expected |
| Strategic merge patch (`application/strategic-merge-patch+json`) | — | must-have | Fallback from SSA; also used by installer |
| JSON merge patch (`application/merge-patch+json`) | — | must-have | Used for CRD status updates and custom resources |
| **Watch mechanics** | | | |
| BOOKMARK events | — | must-have | Required by client-go informer; prevents O(n) resyncs |
| `410 Gone` on stale rv | — | must-have | Without this, informers get stuck on reconnect |
| Label selector filtering | — | must-have | repo-server uses label selectors on Secret watch |
| Field selector filtering | — | nice-to-have | Used by some health checks; not critical for sync |
| **RBAC** | | | |
| Wildcard `*` in ClusterRole rules | — | must-have | app-controller ClusterRole uses `*/*` wildcards |
| Subresource matching in RBAC | — | must-have | `applications/status`, `pods/log` must be authorized separately |
| `SelfSubjectAccessReview` evaluation | — | nice-to-have | UI "what can I do" feature |

---

## 8. Implementation Sequencing Recommendation

Implement in this order to unlock Argo CD functionality incrementally. Each step should be verifiable
before moving to the next.

### Step 1: Discovery + Core Config Layer (unlock: Argo CD can start)

**Goal:** `argocd-server` and `argocd-application-controller` start without crashing.

Implement:
1. `GET /api` and `GET /apis` discovery (minimal APIGroupList)
2. `GET /api/v1` and `GET /apis/{group}/{version}` resource discovery
3. `core/v1` Secrets — get, list, watch, create, update, patch
4. `core/v1` ConfigMaps — get, list, watch, create, update, patch
5. `core/v1` Namespaces — get, list, watch
6. Static bearer token auth (for the service accounts Argo CD uses)
7. No RBAC enforcement yet (allow all)

**Verify:** Apply the Argo CD install manifest. The argocd namespace is created. Argo CD Pods start
and read their ConfigMaps/Secrets without error. The argocd-server health check passes.

### Step 2: CRD Registration + argoproj.io resources (unlock: Argo CD objects exist)

**Goal:** Argo CD's CRDs are installed. Applications and AppProjects can be created.

Implement:
1. `apiextensions.k8s.io/v1` CRDs — create, get, list, watch (dynamic route registration)
2. Dynamic route generation for `argoproj.io/v1alpha1`: applications, appprojects, applicationsets
3. Status subresource for Applications
4. JSON merge patch for custom resources

**Verify:** `kubectl apply` of Argo CD CRDs succeeds. `kubectl create` of an Application object
succeeds. `kubectl get applications` returns it.

### Step 3: apps/v1 + RBAC resources (unlock: Argo CD install can sync itself)

**Goal:** The Argo CD install ClusterRoles and Deployments can be applied. RBAC objects exist.

Implement:
1. `rbac.authorization.k8s.io/v1` — ClusterRoles, ClusterRoleBindings, Roles, RoleBindings — full CRUD + watch
2. `apps/v1` Deployments + ReplicaSets — full CRUD + watch + status subresource
3. `apps/v1` StatefulSets — full CRUD + watch + status subresource
4. `core/v1` ServiceAccounts — full CRUD + watch
5. `core/v1` Services — full CRUD + watch
6. Strategic merge patch for built-in types
7. Service account JWT token authentication

**Verify:** Argo CD's own components run as Deployments. The Deployment controller creates ReplicaSets
and Pods. argocd-server is reachable via its Service.

### Step 4: RBAC enforcement (unlock: Argo CD's permission model works)

**Goal:** RBAC is enforced. Argo CD service accounts have the permissions they need.

Implement:
1. In-memory RBAC index (ClusterRole + ClusterRoleBinding + Role + RoleBinding evaluation)
2. Wildcard matching (`*` in apiGroups, resources, verbs)
3. Subresource authorization
4. Service account JWT validation (verifying the signing key)

**Verify:** `kubectl auth can-i list pods --as=system:serviceaccount:argocd:argocd-application-controller`
returns yes. Requests with an invalid token are rejected with 401.

### Step 5: Server-side apply + watch semantics (unlock: Argo CD can sync applications)

**Goal:** argocd-application-controller can reconcile an Application and sync resources to the cluster.

Implement:
1. Server-side apply (`application/apply-patch+yaml`, field manager tracking, managed fields, conflict detection)
2. BOOKMARK events on all watch streams (every 60 s)
3. `410 Gone` for stale resourceVersion on watch
4. Label selector filtering on list and watch (for Secrets)
5. `core/v1` Events — create, patch
6. Application status subresource writes

**Verify:** Create an Application pointing to a simple Deployment manifest in git. argocd-application-controller
syncs it. The Deployment appears in the cluster. Application `.status.sync.status` becomes `Synced`.

### Step 6: Full sync with prune + health (unlock: production-grade GitOps loop)

**Goal:** Full sync with prune, self-heal, and health computation works.

Implement:
1. DELETE support on all managed resource types (for prune)
2. `core/v1/pods/log` — streaming GET (for log viewer)
3. `authorization.k8s.io/v1/selfsubjectaccessreviews` (virtual resource handler)
4. `batch/v1` Jobs and CronJobs
5. `networking.k8s.io/v1` Ingresses
6. Pagination (`continue` token on list responses)

**Verify:** Deploy a multi-resource application. Remove a resource from git. Argo CD prunes it. Health
status correctly reflects Pod readiness. Log viewer works in UI.

---

## 9. Argo CD Version Target

**Target version: Argo CD v2.13** (latest stable as of early 2026, released Q4 2025).

Key v2.12/v2.13 behaviors that affect u7s:

1. **Server-side apply is the default** starting from v2.5. In v2.13 it is on by default for all
   resource types when the server advertises SSA support. u7s must implement SSA to avoid forcing
   Argo CD into SMP fallback mode, which loses field ownership semantics.

2. **ApplicationSet is bundled** and enabled by default since v2.5. To simplify the bring-up, disable
   it by removing the `argocd-applicationset-controller` Deployment from the install manifest. This
   eliminates the need for `applicationsets` CRD and API support in the initial milestone.

3. **CRD-based configuration** (v2.6+): Some Argo CD versions store cluster configs in CRDs rather
   than Secrets. v2.13 still supports both; the Secret-based approach is the default and simpler.

4. **Health assessment**: v2.13 uses Lua scripts (via gopher-lua embedded in the controller) to
   evaluate resource health. This computation happens entirely within the controller — u7s has no
   special implementation requirement. The controller simply reads resource `.status` fields via the
   normal GET/LIST API.

5. **`resourceVersion=0` list optimization**: In v2.13, the application-controller uses
   `resourceVersion=0` on initial list to allow the API server to serve from cache. u7s must not
   require `resourceVersion=""` and must handle both semantics.

---

## Appendix A: What Argo CD Requires to START vs. SYNC

**To START (all components healthy, no Applications created yet):**

- CRD registration and all 3 argoproj.io CRDs installable
- `core/v1` Secrets and ConfigMaps (get, list, watch)
- `core/v1` Namespaces (get, list)
- `apps/v1` Deployments, StatefulSets (for running Argo CD's own components)
- Discovery endpoints
- Service account token auth

**To SYNC a simple Deployment-based app:**

Everything above, plus:
- `apps/v1` Deployments CRUD
- Server-side apply OR strategic merge patch
- `argoproj.io/v1alpha1/applications/status` patch
- `core/v1` Events create
- BOOKMARK events on watches
- `410 Gone` on stale watch resourceVersion

**To SYNC with prune:**

Everything above, plus:
- DELETE verb on all managed resource types

**To use the UI fully:**

Everything above, plus:
- `core/v1/pods/log` GET streaming
- `authorization.k8s.io/v1/selfsubjectaccessreviews` POST

---

## Appendix B: Complexity Flags

These items require extra implementation care beyond standard CRUD:

1. **Server-side apply field tracking** — Most complex item in the entire surface. Requires tracking
   `managedFields` per field-manager per object, computing field ownership diffs on every PATCH,
   detecting conflicts (two managers owning the same field), and merging field sets. The upstream
   implementation is `sigs.k8s.io/structured-merge-diff`. A Rust port or a simplified implementation
   that covers the common cases (single field manager per field) is feasible but non-trivial.
   Hot path: every Argo CD sync operation issues a PATCH per managed resource.

2. **Dynamic route registration from CRDs** — When a CRD is applied, u7s must atomically add new
   HTTP routes to axum's router. axum's router is immutable after construction. u7s needs either a
   `matchit`-style dynamic router, a single catch-all route with manual dispatch, or rebuilding the
   router with an `Arc<RwLock<Router>>` swap. The catch-all approach is simplest: one route
   `/apis/{group}/{version}/{plural}[/{namespace}[/{name}[/{subresource}]]]` dispatched to a
   CRD-aware handler that looks up the CRD schema from the store. Flag this as a design decision point.

3. **Status subresource** — The status subresource (`/apis/{group}/{version}/{plural}/{name}/status`)
   must: (a) only allow updates to `.status` fields (reject `.spec` changes), (b) not increment
   `metadata.resourceVersion` on a no-op status update (or at least handle the case where
   the client sends a full object and expects only status to be updated). For CRDs, the status
   subresource is declared in the CRD spec; u7s must check this flag before exposing the route.

4. **Label selector index** — For Secrets (repo-creds, cluster-creds), Argo CD uses label selectors
   on both list and watch. A full-scan implementation works for small clusters but a label index
   (inverted index: label key+value → set of object keys) is needed for correctness under watch
   (must deliver only events matching the selector). Build the label index into the watch fan-out
   filter from the start.

5. **Watch fan-out with selector filtering** — Each watch registration has an associated filter
   (namespace + label selectors + field selectors). Events from the state store must be filtered
   per-watcher before delivery. The fan-out loop is on the hot path for every write. Keep it
   allocation-free: pre-serialize the event once into an `Arc<Bytes>`, then filter per watcher
   (check selector match in O(1)) before cloning the `Arc` to each matching watcher channel.
