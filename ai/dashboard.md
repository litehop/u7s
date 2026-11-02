---
updated: 2026-10-31T17:10Z
---
# Dashboard — session 2026-10-31 WRAPPED (main `7d58f39f`)
**Stance:** pre-alpha, no existing users; Conformance correctness > security > perf > features; match upstream 1.37.1 except secure defaults for weak crypto (never hand-roll it); queue merge on green, never `--admin`. CI wall-clock is a ratchet (target ~5 min; bd memory `ci-speed-target-5min-full-runs`).
**Resume:** `claude --settings .claude/settings.json`; paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons. Read `ai/extended-context/` (release-gate, dual-stack updated today). No workers, Lima VMs or GCP VMs running.

## 🎯 Waiting on you
- **`yfca9` MariaDB — option A insufficient (~3/6 cold starts pass; draft #2068, do not merge).** Measured cause is CPU, not disk: MariaDB 11.8's first-init temp server burns ~28 CPU-s in libcrypto bignum math (gdb `BN_mod_exp_mont_consttime`, 0 disk I/O) vs the entrypoint's fixed ~40–55 s wait. Options: (1) **mayor rec:** scout to name the startup crypto work and supply/avoid it (pre-generated material via Secret, or MariaDB 10.11 LTS); (2) entrypoint wrapper with longer temp-server wait; (3) B init recovery (excluded earlier); (4) bigger gate node. Gate's 300 s mariadb-0 wait is also tight (passing starts 186–316 s). Blocks `vw7jc`, `i4bvb` burst A/B.
- **`feature-tests` → required check?** Now ~1.5–2.8 min, never the long pole. Mayor rec: yes.
- **`b6c59.1` CI-only cargo profile** (no fat LTO) for e2e-focus + PKI builds: ~3–5 min off the queue long pole (~7 min cold apiserver build); e2e then tests a differently-built binary. Mayor rec: yes; the release gate still tests the real binary.
- **Review mayor design calls:** CEL gate limits in #2064 (200 live / 64 per-CRD / 6+24 abandoned); bootstrap-IP fail-stop only on a real conflicting Service (#2061).
- Leftover idle test process PID 9379 (from a worker's hung revert run) — `kill 9379` is safe.

## ⏭ Next session
1. `yfca9` per your call → GCP gate → `vw7jc` → `i4bvb` burst A/B.
2. CI Phase 2 remaining: `b6c59.1` (your call), `.4`–`.9`; verify cache-prime keys (run 41217840010 vs next PR run, note on `b6c59.2`).
3. Dual-stack: `rv1aw` (unblocks `8w6at.7`), `.9` GCP harness, `.2` GCP verify (+ real `--join`), `.15` LOWs, #2045 rig.
4. Parity follow-ons: `eay5e` (PATCH create-on-update), `s0dyl` (always load old object on UPDATE), `wvna0`/`ghhcy` (TokenRequest), `43bnh` (int32), `okr7g`, DELETE-path cluster (`d8c5z`/`e918x`/`qap3i.22`), `agwmd`.
5. Tooling: `ntu2k` (tick title regex noise).

## 🔎 Open PRs
#2068 (draft, `yfca9` partial) · #2045 (draft, `8w6at.11` Lima dual-stack rig) · #2039 (draft, `i4bvb`) · #2030, #2052 Renovate.

## ✅ Merged 2026-10-31 (20: #2053–#2073 except draft #2068)
- Conformance/API parity: #2054 PriorityClass · #2059 create-verb authz on create-on-update + per-kind lost-race · #2071 empty-RV PUT 422 for 20 strict kinds · #2072 dryRun status PUT RV · #2063 int32 range + no-wrap protobuf encoders · #2064 CEL gate no longer rejects concurrent in-budget writes
- Security: #2056 secret files 0600 · #2060 CSR /approval validation · #2062 TokenRequest bound-object + NodeRestriction
- Dual-stack: #2058 manifests + beep v0.7.0 · #2061 secondary kube-dns IP · #2066 worker v6 forwarding
- CI/tooling: #2053 feature-flag tests · #2057 CI audit · #2069 script-tests 211→65 s, no Test/PKI rerun on main · #2055/#2070 flake fixes · #2065 rig KCM cache integrity · #2067 tick auto-close/enqueue fix · #2073 node_proxy wiring tests
- Closed without PR: `wbtk7` (#1975), `x0osa` (#1834), `qap3i.7` (dup).

## 📝 Decided 2026-10-31
- MariaDB `yfca9`: option A tried (insufficient; see above).
- CI speed: ratchet like docs — workflow changes must not worsen wall-clock, improve where possible; not a blocker for valuable checks.

## 📝 Decided 2026-10-30
- Gate: no pre-pull/sequencing; pd-standard stays; snapshot cuts and publish approval are operator-only.
- Memory: protect control-plane units (`i4bvb`, #2039 draft); size ~160Mi/~136Mi pending burst A/B.
- Crypto: aws-lc-rs only, RSA ≥ 2048. L7: Traefik; TLS later via cert-manager. CSR chain kept (ADR).
- Dual-stack epic `8w6at`: GCP subnet `u7s-test` now IPV4_IPV6 (one-way); beep work in beep tracker.

<!-- BEGIN AUTO: open-prs -->
#2068 · #2052 · #2045 · #2039 · #2030
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
Kept for draft PRs (#2068, #2045, #2039).
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
Stopped at wrap.
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
`main` @ `7d58f39f`.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending.
<!-- END AUTO: review-queue -->
