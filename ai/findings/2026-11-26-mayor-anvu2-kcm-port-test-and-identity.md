# KCM port: upstream integration tests vs external apiserver; per-controller identity

Bead: mayor-anvu2
Date: 2026-11-26. Upstream ref: `kubernetes/kubernetes@release-1.37`. Research-only; no product code changed.

1. **Upstream `test/integration` cannot target an external apiserver; it is not usable as-is, so each ported controller needs black-box Rust scenario tests.**
2. **Neither u7s audit nor metrics exposes requesting identity, so per-controller write counts are impossible today; the smallest change is a bounded `user` label on `apiserver_request_total`.**

## Q1: upstream integration framework

- Every controller test builds its own apiserver in-process. `dcSetup` (`test/integration/deployment/util.go:108`) calls `kubeapiservertesting.StartTestServerOrDie(t, nil, framework.DefaultTestServerFlags(), framework.SharedEtcd())`. The garbage-collector tests do the same (`test/integration/garbagecollector/garbage_collector_test.go:241`, `:366`).
- `StartTestServer` (`cmd/kube-apiserver/app/testing/testserver.go:156`) runs `app.NewConfig` (`:436`), `app.CreateServerChain` (`:444`) and `prepared.Run` (`:458`) in the test process. It hands back `ClientConfig` from the server's loopback config (`:527`). There is no kubeconfig or server-URL input. The framework variant `framework.StartTestServer` (`test/integration/framework/test_server.go:78`) is also in-process.
- The only external knob is etcd: `KUBE_INTEGRATION_ETCD_URL` (`test/integration/framework/etcd.go:301-303`). That replaces the storage backend, not the apiserver, so it does not help a Rust apiserver.
- The controllers under test are Go structs constructed in the test: `deployment.NewDeploymentController` and `replicaset.NewReplicaSetController` (`deployment/util.go:117,128`), and `garbagecollector.NewGarbageCollector` (`gc_test.go:279`). They are not run as a KCM binary. The tests reach into controller internals (the `rm` and `dc` handles, shared informers).
- Even for a hand-written hook, the Go controllers would then run in the test process, which only exercises Go code against the Rust apiserver. That tests the apiserver, not a Rust controller.

**Consequence.** To reuse upstream scenarios against a Rust controller, they must be rewritten as black-box tests (create objects via kubectl or a client, assert on observed state) that run against a live u7s control plane with the Rust KCM. Replacing `StartTestServerOrDie` with a kubeconfig client would be a fork of each test setup, not a hook. The deployment, replicaset and job tests would be the cheapest to port: their assertions mostly poll apiserver state (`deploymentTester.waitFor*`). The GC and namespace tests also depend on in-process informer and worker handles.

## Q2: identity in audit and metrics

**What exists**
- No audit log. `grep -i audit` over `crates/apiserver/src` matches only comments (`auth.rs:82,705,3994`) and none of `args.rs`, `serve.rs` or `lib.rs`. There is no audit policy or backend.
- `apiserver_request_total` has labels `verb, group, version, resource, scope, code` only (`crates/apiserver/src/metrics.rs:70-76`). The wrapper `record_request_total` (`metrics.rs:88`) takes those six values. It is called from `auth.rs:1871,1928`, with the authenticated `user` in scope (`auth.rs:1858-1893`).
- `authentication_attempts` and `authorization_attempts_total` have only `result` (`metrics.rs:412-454`).
- The only identity-bearing output is the `tracing::info!` "request rejected" line, emitted for denials only and rate-limited (`auth.rs:1244-1255`). Allowed writes are not logged.

**What the install gives**
KCM runs with `--use-service-account-credentials=true` (`scripts/test-install-logic.sh:103`), so each controller is its own `system:serviceaccount:kube-system:<name>-controller` and the identity is already distinct on the wire. The u7s apiserver just discards it.

**Weak workaround.** `metadata.managedFields[].manager` on surviving objects shows the writer's user agent. It misses deletes and objects already gone, and it is not a request count.

**Smallest change (suggested, not implemented).** Add a `user` label to `REQUEST_TOTAL` and `record_request_total`, set to `user.username` only when the user is a `system:serviceaccount:kube-system:*` or `system:kube-*` identity, and `other` otherwise. Cardinality stays bounded by the fixed kube-system controller set. A raw username label must not be used: CN and SA names are attacker-controlled. The bench `benches/request_total_record.rs` and the cardinality-ceiling test (`metrics.rs:473`) must be updated in lockstep. Counting then needs a `/metrics` scrape before and after the run, filtered by `verb in {create,update,patch,delete}`. Note `crates/apiserver` has other in-flight work (mayor-0h9um, mayor-yp00d), so sequence this after them.
