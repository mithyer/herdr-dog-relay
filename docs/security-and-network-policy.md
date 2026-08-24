---
title: Herdr-dog Relay Security and Network Policy
description: Uniform QUIC TLS 1.3 identity and bounded session security policy.
published: true
date: 2026-08-24T11:41:11+08:00
tags: herdr-dog, relay, security, quic, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay Security and Network Policy

## Current status

Status: `checkpointed` for QRM-PROD-1 P4 local cross-platform validation at Relay `074d84d`. QRM-1 Q4/Q5 security evidence and P2/P3 checkpoints remain preserved. P4 validates local verified enrollment/revocation, independent quota/no-forward boundaries, updater rollback, and disposable user-service behavior; live deployment and P6 lifecycle evidence remain open, with P6 planned/inactive.

## Required security

- QUIC TLS 1.3 is always enabled;
- production validates Relay server certificate, Core client certificate and trusted CA;
- development may use an explicitly test-only unverified mode, never plaintext;
- ALPN `herdr-dog-relay-quic/1` is mandatory for normal QRM and `herdr-dog-relay-enroll/1` is a separate terminal enrollment namespace;
- production normal QRM validates Relay server certificate, Core client certificate and active App allowlist fingerprint;
- enrollment additionally binds the authenticated Core identity, Relay single-use challenge, bounded CSR and generation;
- protected certificate, Intermediate-key and allowlist files require owner/mode/path validation and atomic replacement;
- updater archives require fixed-source checksum validation and safe regular-file extraction;
- plaintext UDP is forbidden;
- listener address and UDP port are explicit; default port is `18743`;
- connection/session/control-frame/buffer/timeout/enrollment limits are bounded;
- HDQS authority must be accepted before any Herdr byte;
- tokens, fingerprints, certificates, private keys and payloads are not logged or persisted in repository artifacts;
- malformed control protocol closes the physical connection; session authority failure closes only the session stream.

## Validation

QRM tests must cover wrong certificate, missing client identity, wrong ALPN, malformed HDQM/HDQS, stale generation/token/fingerprint, socket replacement, stream isolation and bounded cleanup.

## Checkpoint Log

[accepted](1-42) 2026-08-22 | QRM-1 Q3 security policy checkpointed
- Repository state: security policy and Q3 Relay implementation are checkpointed in the Relay submodule.
- Validation: TLS, identity, authority and redaction boundaries are frozen and tested.
- Scope: one generic QUIC listener and multiple isolated streams.
- Exclusions: plaintext, network classes, arbitrary commands, Herdr parsing and Q4/Q5 evidence claims.
- Residual risk: certificate provisioning and production evidence remain open.
- Next dependency: implement and validate Q4 before fresh review.

[active](1-53) 2026-08-22 | QRM-1 Relay Q4 security validation active
- Repository state: security policy and Q3 implementation are checkpointed; Q4 test-only network disturbance validation is beginning.
- Validation: TLS, identity, authority and redaction gates remain recorded; Q4 evidence is not yet claimed.
- Scope: packet disturbance, bounded queues, stream isolation and reconnect authority invalidation.
- Exclusions: plaintext, network classes, arbitrary commands, Herdr parsing and Q5 deployment.
- Residual risk: certificate provisioning and weak-network evidence remain open.
[checkpointed](1-56) 2026-08-23 | QRM-1 Relay Q4 security validation checkpointed
- Repository state: security policy and Q3 implementation are checkpointed; Q4 has no Relay production source change, Core implementation/status checkpoints are `bbc39b9`/`a44ef6d`, and this policy record is selective.
- Validation: Core/Relay TLS, identity, authority, redaction and weak-network quality gates pass; Luna max review P1/P2 findings were closed and revalidated.
- Scope: packet disturbance, bounded queues, stream isolation, reconnect authority invalidation and fail-closed cleanup.
- Exclusions: plaintext, network classes, arbitrary commands, Herdr parsing and Q5 deployment.
- Residual risk: P3 no-replay hardening, certificate provisioning and mb17 evidence remain open.
- Next dependency: keep Q5 external security evidence planned.

[active](1-64) 2026-08-23 | QRM-1 Relay Q5 external security preflight active
- Repository state: Relay Q4 security checkpoint is committed; Herdr master is `d6dae883` and generated schema helpers remain excluded.
- Validation: TLS 1.3, ALPN, identity, authority, redaction and bounded cleanup gates remain local-pass evidence; upstream subscription sequencing does not alter the Q5 read-only path.
- Scope: verify mb17 certificate/CA references, peer identity, UDP endpoint, two session socket identities and no-forward-before-bind prerequisites.
- Exclusions: plaintext, network classes, credential disclosure, Herdr parsing, writes, subscriptions, healthy Current, actions and arbitrary commands.
- Next dependency: complete non-destructive security preflight before starting the QRM Relay process.

[validated](1-71) 2026-08-23 | QRM-1 Relay Q5 mb17 external security evidence validated
- Repository state: verified TLS 1.3/mTLS certificate and CA material is outside the repository; server key is mode `0600`; old Relay/config backup is retained.
- Validation: temporary and final UDP bind, ALPN, client authentication, socket mode/identity, old TCP closure and Core typed read/failure-isolation evidence passed.
- Scope: generic device endpoint, peer identity, HDQM/HDQS authority and no-forward-before-bind boundary.
- Exclusions: plaintext, network classes, credential disclosure, Herdr parsing, writes, subscriptions, healthy Current, actions and arbitrary commands.
- Residual risk: PKI lifecycle, LaunchAgent supervision and final review/checkpoint remain open.
- Next dependency: complete post-fix review and synchronize the Q5 security checkpoint.

[active](1-83) 2026-08-24 | QRM-PROD-1 P2 Relay security implementation active
- Repository state: P1 Relay checkpoint is preserved; P2 security/source changes are uncommitted and mb17 is untouched.
- Validation: local Relay 66-test, Clippy, rustfmt, rustdoc and diff gates pass; production deployment is not claimed.
- Scope: mTLS/ALPN separation, Core-origin/challenge binding, protected material, allowlist/revocation, archive safety and supervision boundaries.
- Exclusions: no production certificate provisioning, live enrollment/deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: live client-certificate/allowlist admission, connection closure after revoke, updater cutover and mb17 evidence remain open.
- Next dependency: complete fresh P2 review/fix/revalidation before selective Relay checkpointing.

[implemented](1-91) 2026-08-24 | QRM-PROD-1 P2 Relay security implementation completed
- Repository state: P2 Relay security/source changes are uncommitted; P1 checkpoints remain preserved and mb17/Herdr are untouched.
- Validation: 69 Relay tests, Clippy, rustfmt, rustdoc, locked checks and diff checks pass locally.
- Scope: mTLS/ALPN separation, Core enrollment anchor/challenge, protected material, allowlist/revocation, archive safety and supervision boundaries.
- Exclusions: live P6 enrollment/deployment cutover, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: fresh P2 review/fix/revalidation and live client/mb17 evidence remain open.
- Next dependency: complete fresh P2 review, apply fixes, then selectively checkpoint Relay.

[accepted](1-99) 2026-08-24 | QRM-PROD-1 P2 Relay security local implementation accepted
- Repository state: P2 Relay security/source changes remain uncommitted; P1 checkpoints and Herdr/mb17 exclusions are preserved.
- Validation/review: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final fresh dual review found no P0-P2 findings.
- Scope: mTLS/ALPN separation, Core enrollment anchor/challenge, protected material, allowlist/revocation, archive safety and supervision boundaries.
- Exclusions: live P6 enrollment/deployment cutover, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live client/closure evidence and P4-P6 deployment evidence remain open; checkpointing is required.
- Next dependency: selectively checkpoint Relay, then synchronize parent status.

[checkpointed](1-107) 2026-08-24 | QRM-PROD-1 Relay security checkpointed at `51134bb`
- Repository state: Relay P2 security/source changes are committed at `51134bb`; Relay worktree is clean; parent status closure remains pending.
- Validation: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final review found no P0-P2 findings.
- Scope: mTLS/ALPN separation, Core enrollment anchor/challenge, protected material, allowlist/revocation, archive safety and supervision boundaries.
- Exclusions: live P6 enrollment/deployment cutover, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live client/closure and P4-P6 deployment evidence remain open.
- Next dependency: synchronize parent status and gitlinks.

[active](1-115) 2026-08-24 | QRM-PROD-1 P4 local security evidence active
- Repository state: P4 activation/baseline checkpoints are Core `413c5c0`/`1c0371e`, Relay `a244ba0`/`07b1be3`, App-iOS `e58eb3f`/`fe3c62a`, and parent `52fbe34`/`484d806`; current Relay changes restore governance sources removed from tracking by `0fc3563`.
- Validation: Relay 79 locked tests and quality gates include verified mTLS/ALPN, Core-anchor/challenge, two-App revoke isolation, normal-QRM missing-client rejection, enrollment no-forward, and quota exhaustion; see `/herdr-dog/relay/docs/p4-local-validation-report`.
- Scope: local-only P4 security evidence; no production issuance or deployment claim.
- Exclusions: no mb17 mutation, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: authorization consumption is in-memory across restart; Linux published-artifact/CI and P6 live evidence remain open. Verified revoke is rechecked independently of control traffic and closes matching idle connections and active bridges.
- Next dependency: complete P4 correction review and artifact/CI evidence before closure; do not enter P6.

[active](1-123) 2026-08-24 | QRM-PROD-1 P4 post-fix security validation
- Repository state: Relay source and governance restoration remain uncommitted; P4 remains local-only and active.
- Validation: verified mTLS/ALPN, protected material, allowlist admission, idle revoked active-bridge closure, no-forward and cross-platform quality gates pass.
- Scope: local P4 security and authority evidence only.
- Exclusions: no mb17 mutation, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: restart-persistent authorization, published Linux artifact/CI provenance and P6 lifecycle evidence remain open.
- Next dependency: complete final fresh review and selective checkpoint validation; do not activate P6.

[active](1-131) 2026-08-24 | QRM-PROD-1 P4 post-review security validation
- Review: disabled-enrollment revoke, installer native/startup/rollback, protected-file identity, certificate-expiry and verified-allowlist findings were corrected directly by the parent.
- Validation: macOS passed 82 Relay tests and native Ubuntu x86_64 passed 81 tests, with mTLS/ALPN, no-forward, revocation and redaction checks preserved.
- Scope: local protected material, allowlist/revocation, enrollment, updater and supervision security evidence only.
- Exclusions: no mb17 mutation, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: same-source checksum provenance, published Linux CI/artifact provenance, restart-persistent authorization and P6 lifecycle evidence remain open.
- Next dependency: keep P6 planned and inactive until separate deployment authorization; do not claim live issuance, mb17 deployment or P6 lifecycle evidence.

[checkpointed](1-140) 2026-08-24 | QRM-PROD-1 P4 local validation checkpointed
- Repository state: Relay implementation and restored governance sources are checkpointed at `074d84d`; no push; unrelated parent/Core/App-iOS/Herdr content remains preserved.
- Review: fresh GLM-5.3 security review found no P0-P3 issues; governance review's table-shape P3 was corrected and the narrow GLM-5.3 re-review found no P0-P3 issues.
- Validation: macOS passed 82 Relay tests (79 library plus 3 binary) and native Ubuntu 24.04 x86_64 passed 81 (78 library plus 3 binary), with locked quality, rustdoc, release/archive/checksum, supervision and version checks.
- Scope: local protected material, enrollment/allowlist, updater, supervision, governance restoration and cross-platform evidence only.
- Exclusions: no mb17 deployment, live issuance, remote update, Herdr mutation/parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: same-source checksum provenance, published Linux CI/artifact provenance, restart-persistent authorization and P6 lifecycle/rebind evidence remain open.
- Next dependency: keep P6 planned and inactive until separate deployment authorization; do not claim live issuance, mb17 deployment or P6 lifecycle evidence.
