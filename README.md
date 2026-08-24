---
title: Herdr-dog Relay
description: Single-device single-port QUIC TLS 1.3 opaque byte Relay.
published: true
date: 2026-08-24T11:41:11+08:00
tags: herdr-dog, relay, quic
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay

## Current status

QRM-PROD-1 P4 local cross-platform validation is checkpointed in Relay at `074d84d`. Its activation/baseline checkpoints are Core `413c5c0`/`1c0371e`, Relay `a244ba0`/`07b1be3`, App-iOS `e58eb3f`/`fe3c62a`, and parent `52fbe34`/`484d806`; the implementation checkpoint includes the restored Relay-owned governance sources and parent-led P4 hardening. P6 deployment remains planned and inactive. No live/production certificate issuance or deployment, Herdr payload parsing, writes, subscriptions, healthy `Online + Current`, actions, passthrough or automatic retry is claimed; disposable local certificate issuance is covered only as P4 test evidence.

## Boundary

The Relay authenticates Core, validates HDQM/HDQS/session authority and bridges opaque bytes to validated Herdr Unix sockets. It does not run Core, parse Herdr, expose arbitrary API commands or log payloads. The App communicates with Core only.

## Current implementation

QRM-PROD-1 P2 implementation/status is checkpointed at `51134bb`/`6176552`; P3 has no Relay source changes and its status is checkpointed at `76270bd`. P4 local enrollment/updater/supervision/test work and restored Relay governance sources are checkpointed at `074d84d`. The prior `0fc3563` index change removed Relay governance documents; the checkpoint restores `AGENTS.md` and `docs/` for Relay-index tracking. No P4 production capability is claimed and the opaque QUIC bridge boundary remains unchanged.

## Validation evidence

- [P4 local validation evidence](/herdr-dog/relay/docs/p4-local-validation-report) — local-only enrollment, updater, supervision, and typed App identity boundary evidence.

## Checkpoint Log

[active](1-33) 2026-08-22 | QRM-1 Relay active
- Repository state: README rewritten and uncommitted.
- Validation: project boundary and current architecture match the QRM plan.
- Scope: single-port QUIC Relay implementation.
- Exclusions: old TCP/Broker/network-class paths and Herdr API proxying.
- Residual risk: implementation and real network evidence remain open.
- Next dependency: complete Q0 document normalization, then Q1 QRM implementation.

[accepted](1-41) 2026-08-22 | QRM-1 Relay Q3 local implementation/review gate accepted
- Repository state: Q3 source/tests and Relay status documentation are checkpointed in this submodule; parent-Wiki changes are preserved.
- Validation: 46 locked Relay tests, Clippy, rustfmt, rustdoc and diff checks pass; fresh review found no confirmed P0/P1/P2 source defect.
- Scope: production Quinn server/bridge authority, bounded malformed-frame/deadline handling, redacted diagnostics and verified-mode CLI boundary.
- Exclusions: Q4 weak-network, Q5 mb17 deployment, Q6 App transport, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: Q4/Q5 external evidence remains open and is not implied by this checkpoint.
- Next dependency: implement and validate Q4 before fresh review.

[active](1-49) 2026-08-22 | QRM-1 Relay Q4 weak-network validation active
- Repository state: Relay Q3 implementation/status checkpoints are committed; Q4 test-only weak-network coverage is being added around the existing QUIC server seams.
- Validation: Relay Q3 local quality gates remain recorded; Q4 evidence is not yet claimed.
- Scope: bounded loss/delay/reorder, stream isolation, connection-loss cleanup and no raw payload logging.
- Exclusions: Q5 mb17 deployment, App transport, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: field/mobile loss evidence and Q5 deployment evidence remain open.
- Next dependency: complete Q4 Core/Relay test validation and fresh review.

[active](1-57) 2026-08-23 | QRM-1 Relay Q4 post-fix validation checkpoint
- Repository state: Relay Q3 implementation/status checkpoints remain committed; Q4 is test-only and introduces no Relay production source change, while parent and unrelated work remains preserved.
- Validation: the shared Core Q4 harness and Relay quality gates have passed locally after the control-priority close-order correction; the specified fresh GLM review remains pending.
- Scope: bounded loss/delay/reorder, QUIC control progress during a stalled session stream, stream isolation, reconnect authority invalidation and no raw payload logging.
- Exclusions: Q5 mb17 deployment, App transport, Herdr parsing, actions, subscriptions, healthy Current, passthrough and automatic retries.
- Residual risk: Q4 remains active/uncheckpointed and local harness evidence is not deployed Relay or mb17 evidence.
[checkpointed](1-63) 2026-08-23 | QRM-1 Relay Q4 weak-network validation checkpointed
- Repository state: Relay Q4 introduces no production source change; Core implementation checkpoint `bbc39b9` and Core status checkpoint `a44ef6d` are committed, while this Relay documentation checkpoint is selective and unrelated content remains preserved.
- Validation: the accepted `gpt-5.6-luna` max review's P1/P2 findings were closed by the pre-`SessionClosed` stall assertion, close-session stream retention and synchronized status tails; Core passed 313 tests and Relay passed 46 locked tests with all quality gates.
- Scope: bounded loss/delay/reorder, QUIC control progress during a stalled session stream, stream isolation, reconnect authority invalidation and no raw payload logging.
- Exclusions: Q5 mb17 deployment, App transport, Herdr parsing, actions, subscriptions, healthy Current, passthrough and automatic retries.
- Residual risk: the review's P3 no-replay assertion remains a future hardening gap; local evidence is not deployed Relay or mb17 evidence.
- Next dependency: keep Q5 planned until its real two-session deployment gate is separately activated.

[active](1-71) 2026-08-23 | QRM-1 Relay Q5 mb17 deployment preflight active
- Repository state: Relay Q4 documentation checkpoint is committed; Herdr master is `d6dae883`; generated schema helpers remain outside scope.
- Validation: QRM QUIC server/configuration gates are local-only; upstream protocol 20/schema 1 and schema digest are unchanged, and subscription sequencing changes do not affect the Q5 read-only path.
- Scope: inspect mb17 Relay artifact/configuration, verified TLS 1.3 identity, one UDP listener and at least two session sockets without forwarding Herdr bytes yet.
- Exclusions: legacy TCP/Broker fallback, credential changes, Herdr parsing in Relay, writes, subscriptions, healthy Current, actions and passthrough.
- Next dependency: complete the non-destructive preflight before replacing or starting the QRM Relay process.

[validated](1-78) 2026-08-23 | QRM-1 Relay Q5 mb17 deployment validated
- Repository state: Relay Q4 documentation checkpoint is committed; QRM x86_64 binary was built from the current Relay source and deployed outside the repository; old binary/config backup is retained on mb17.
- Validation: verified TLS 1.3/ALPN config loaded, temporary UDP bind passed, final UDP `100.64.0.6:18743` is live, old TCP listener is closed, and Core's two-session/failure-isolation targets passed.
- Scope: one Relay process/device, one UDP listener, two isolated Herdr session streams and opaque forwarding.
- Exclusions: legacy TCP/Broker/HDRL/HDBR/HDBD, per-session ports/children, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retries.
- Residual risk: no LaunchAgent, certificate rotation/PKI provenance and final selective checkpoint remain open.
- Next dependency: complete post-fix Core review/revalidation and checkpoint the deployment evidence.

[accepted](1-86) 2026-08-23 | QRM-1 Relay Q7 legacy cleanup accepted at review gate
- Repository state: Relay Q7 config/test cleanup is present but uncommitted; deployment artifacts and Herdr generated content remain excluded.
- Validation: 46 locked tests passed with Clippy warnings denied, rustfmt, rustdoc and diff checks; Core/App gates and fresh dual review found no P0-P2.
- Scope: QRM source retains one generic UDP/QUIC TLS 1.3 listener, SessionRegistry and opaque Unix bridge; the stale network-class probe is replaced by explicit unknown-table rejection.
- Exclusions: no legacy TCP/Broker fallback, Herdr parsing, App transport, deployment, writes, subscriptions, healthy Current, actions or passthrough.
- Residual risk: long-term supervision, PKI rotation, real native/device evidence and QRM overall acceptance remain open.
- Next dependency: selectively checkpoint Core, then Relay, App-iOS and the parent Wiki.

[checkpointed](1-94) 2026-08-23 | QRM-1 Relay Q7 legacy cleanup checkpointed
- Repository state: Relay implementation/status commit `a2dd9dc` is committed; deployment artifacts and Herdr generated content remain excluded.
- Validation: 46 locked tests passed with Clippy warnings denied, rustfmt, rustdoc and diff checks; Core/App gates and fresh dual review found no P0-P2.
- Scope: one generic UDP/QUIC TLS listener, SessionRegistry and opaque bridge remain active; stale network-class validation is replaced by explicit unknown-table rejection.
- Exclusions: no legacy TCP/Broker fallback, Herdr parsing, App transport, deployment, writes, subscriptions, healthy Current, actions or passthrough.
- Residual risk: long-term supervision, PKI rotation, real native/device evidence and QRM overall acceptance remain open.
- Next dependency: complete the ordered App-iOS and parent Wiki checkpoints.

[active](1-102) 2026-08-24 | QRM-PROD-1 P2 Relay implementation active
- Repository state: P1 checkpoints are preserved; P2 Relay source/config/workflow/template changes are uncommitted and mb17 is untouched.
- Validation: 66 Relay tests, Clippy with warnings denied, rustfmt, rustdoc and diff checks pass locally.
- Scope: protected material/allowlist, enrollment ALPN wire boundary, transient CSR issuance, stable-latest updater safety, CLI revoke/update and supervision templates.
- Exclusions: no live deployment, production PKI provisioning, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: full live enrollment/normal-QRM mTLS admission, updater restart/drain, cross-platform service execution and mb17 evidence remain open.
- Next dependency: complete the P2 implementation review/fix/revalidation gate before selective Relay checkpointing.

[implemented](1-110) 2026-08-24 | QRM-PROD-1 P2 Relay local implementation completed
- Repository state: P2 Relay source/config/workflow/template changes are uncommitted; P1 checkpoints remain preserved and mb17/Herdr are untouched.
- Validation: 69 Relay tests, Clippy, rustfmt, rustdoc, locked checks and diff checks pass locally.
- Scope: protected material/allowlist, enrollment ALPN, transient PKI, stable-latest updater/revoke CLI and supervision templates.
- Exclusions: live P6 drain/restart/readiness/rebind, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: fresh P2 review/fix/revalidation and real service/deployment evidence remain open.
- Next dependency: complete fresh P2 implementation review, apply fixes, then selectively checkpoint Relay.

[accepted](1-118) 2026-08-24 | QRM-PROD-1 P2 Relay local implementation accepted
- Repository state: P2 Relay source/config/workflow/template changes remain uncommitted; P1 checkpoints and Herdr/mb17 exclusions are preserved.
- Validation/review: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final fresh dual review found no P0-P2 findings.
- Scope: protected material/allowlist, Core-anchor enrollment ALPN, transient PKI, stable-latest updater/revoke and supervision templates.
- Exclusions: live P6 drain/restart/readiness/rebind, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live boundary coverage and P4-P6 real service/deployment evidence remain open; checkpointing is required.
- Next dependency: selectively checkpoint Relay, then synchronize parent status.

[checkpointed](1-126) 2026-08-24 | QRM-PROD-1 Relay P2 checkpointed at `51134bb`
- Repository state: Relay P2 implementation/docs/workflow/templates are committed at `51134bb`; Relay worktree is clean; parent status closure remains pending.
- Validation: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final review found no P0-P2 findings.
- Scope: protected material, Core-anchor enrollment, allowlist, transient PKI, stable-latest updater/revoke and supervision templates.
- Exclusions: live P6 cutover, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live boundary and P4-P6 service/deployment evidence remain open.
- Next dependency: synchronize parent status and gitlinks.

[active](1-134) 2026-08-24 | QRM-PROD-1 P4 local cross-platform validation activated
- Repository state: Relay P2 implementation/status `51134bb`/`6176552` and P3 status `76270bd` are checkpointed; P4 activation is documentation-only and uncommitted; Herdr, secrets and mb17 are unchanged.
- Herdr upstream check: `origin/master` and detached `HEAD` are `d6dae883`; tags `v0.8.2` and `v0.8.0` remain present; five generated schema helpers remain excluded; no Socket API schema or Relay byte-path impact was found.
- Validation baseline: Relay 69 quality-gate tests; P4 enrollment/update/service evidence is not yet claimed.
- Scope: disposable CA/material, two-App enrollment/revoke isolation, quota/ALPN/no-forward boundaries, archive rollback and macOS/Linux user-service lifecycle.
- Exclusions: no mb17 change, live certificate issuance/deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Next dependency: capture the disposable-material and local service baseline before P4 Relay implementation/evidence work.

[implemented](1-146) 2026-08-24 | QRM-PROD-1 P4 Relay enrollment local slice implemented
- Repository state: Relay enrollment implementation/test changes are uncommitted; P4 remains active; P3 status `76270bd`, Herdr, secrets and mb17 are unchanged.
- Validation: Relay 70 tests passed with locked quality gates; verified loopback enrollment covered two Apps, admin/revocation isolation, reconnect rejection, normal-QRM mTLS rejection, enrollment-ALPN no-forward and enrollment quota exhaustion.
- Scope: challenge-first terminal enrollment, protected Core anchor/mTLS, CSR binding, public certificate issuance and persistent allowlist/revocation local evidence.
- Exclusions: no live certificate issuance/deployment claim, mb17 change, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: updater/archive rollback, disposable service lifecycle, cross-architecture artifact evidence, authorization replay/expiry and P5 review remain open.
[validated](1-148) 2026-08-24 | QRM-PROD-1 P4 local updater/service slice validated
- Repository state: Relay enrollment/updater/test changes are uncommitted; P4 remains active; P3 status `76270bd`, Herdr, secrets and mb17 are unchanged.
- Validation: Relay 73 tests passed with locked quality gates; archive extraction and atomic replacement preserve a rollback copy, macOS/Linux arm64/x86_64 release selection is explicit, and LaunchAgent/systemd templates reject injection and escape paths.
- Scope: disposable local updater/archive and supervision-template evidence only; no service installation or remote update was performed.
- Exclusions: no live certificate issuance/deployment claim, mb17 change, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: startup/readiness rollback, GOAWAY/drain/restart, real service lifecycle, cross-architecture archive/checksum artifact evidence, authorization replay/expiry, lazy silent-peer revocation and P5 review remain open.
- Next dependency: run the fresh P4 review and parent-led correction loop; do not enter P6.

[accepted](1-156) 2026-08-24 | QRM-PROD-1 P4 local enrollment/updater slice review accepted
- Repository state: Relay source/tests and local status edits remain uncommitted; P4 overall remains active; Herdr, secrets and mb17 are unchanged.
- Validation: fresh dual read-only review found no P0-P2; parent Relay 73-test quality battery and Core/App baseline checks passed.
- Scope: verified local QUIC enrollment/revocation/quota/no-forward plus disposable archive extraction/replacement and supervision-template boundaries.
- Exclusions: no live certificate issuance, service installation, remote update, mb17 change, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: cross-architecture archive/checksum artifact provenance, startup/readiness rollback, GOAWAY/drain/restart, real service lifecycle, authorization replay/expiry, lazy silent-peer revocation and remaining P4/P5 gates remain open.
- Next dependency: finish remaining P4 artifact/service evidence; keep P4 active and do not enter P6.

[validated](1-164) 2026-08-24 | QRM-PROD-1 P4 local lifecycle and updater hardening validated
- Repository state: Relay source/tests and local status edits remain uncommitted; P4 remains active; Herdr, secrets and mb17 are unchanged.
- Validation: Relay 77 tests plus locked quality gates, macOS arm64/x86_64 checks, disposable LaunchAgent bootstrap/duplicate/bootout, disposable Ubuntu systemd-user verify/single-instance/cleanup, Core 315 passed/2 ignored, core-ffi 4 passed, and an entitled simulator run with all 45 App tests executed and no failures.
- Scope: local verified enrollment/revocation/quota/no-forward, malicious archive/startup/TOCTOU/rollback defenses, and disposable user-supervision evidence.
- Exclusions: no Relay/Herdr deployment, live issuance, remote update, mb17 change, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: local archive fixtures do not prove published Linux release artifacts or CI provenance; a Linux cross C sysroot is unavailable locally, and P5 review/P6 live lifecycle evidence remain open.
- Next dependency: review the latest P4 source/docs, then resolve the artifact/CI evidence boundary before P4 closure; do not enter P6.

[active](1-176) 2026-08-24 | QRM-PROD-1 P4 local correction loop active
- Repository state: P4 activation/baseline checkpoints are Core `413c5c0`/`1c0371e`, Relay `a244ba0`/`07b1be3`, App-iOS `e58eb3f`/`fe3c62a`, and parent `52fbe34`/`484d806`; Relay `0fc3563` removed governance docs from the index, and current uncommitted Relay work restores them for Relay-index tracking before any P4 checkpoint.
- Validation: Relay 79 locked tests and quality gates; static supervision-template drift checks; temporary macOS LaunchAgent and Ubuntu systemd-user fixtures; Core 315 passed/2 ignored; core-ffi 4 passed; entitled simulator 45 executed/0 failed/0 skipped.
- Scope: local-only enrollment/revocation/quota/no-forward, archive/startup/TOCTOU/rollback, user-supervision, governance, and typed App identity evidence. See `/herdr-dog/relay/docs/p4-local-validation-report`.
- Exclusions: no live issuance, deployment, remote update, mb17 change, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: no published Linux artifact/CI provenance, no local Linux C sysroot, restart-persistent authorization consumption; P5/P6 evidence remains open. The maintenance tick closes matching idle revoked connections and their active session bridges.

[active](1-182) 2026-08-24 | QRM-PROD-1 P4 cross-platform correction validated
- Repository state: P4 source, restored Relay-owned AGENTS/docs governance, README and evidence updates remain uncommitted; Herdr, secrets, mb17 configuration and existing service state are unchanged.
- Validation: Development macOS passed 81 Relay tests (78 library plus 3 binary) with locked tests, Clippy, rustfmt, rustdoc and diff checks. Native Ubuntu 24.04 x86_64 passed 80 tests (77 library plus 3 binary), Clippy, rustfmt, rustdoc, release build, disposable archive/checksum verification and `herdogrelay --version`.
- Scope: protected material, allowlist locking, enrollment, updater, supervision, governance restoration and cross-platform test-fixture corrections only. Linux arm64 is rejected because no supported release artifact exists.
- Exclusions: no mb17 deployment, live issuance, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Next dependency: complete the fresh P4 review and any parent-led correction/revalidation loop before selective checkpointing; do not enter P6.

[active](1-190) 2026-08-24 | QRM-PROD-1 P4 post-fix local validation
- Repository state: Relay source, governance restoration and P4 evidence remain uncommitted; unrelated Core/App-iOS/parent/Herdr content remains preserved and excluded.
- Validation: Development macOS passed 81 Relay tests and native Ubuntu 24.04 x86_64 passed 80 Relay tests plus release/archive/checksum evidence; the verified two-App regression proves idle revoked active-bridge closure without heartbeat and sibling usability.
- Scope: local protected-material, allowlist, enrollment, updater, supervision and cross-platform fixture evidence around the one-Relay/one-UDP/one-QUIC boundary.
- Exclusions: no deployment, live issuance, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: published Linux artifact/CI provenance, restart-persistent enrollment authorization and P6 lifecycle/rebind evidence remain open.
- Next dependency: complete final fresh review and selective checkpoint validation; keep P4 active and do not enter P6.

[active](1-198) 2026-08-24 | QRM-PROD-1 P4 post-review remediation validation
- Review: parent-led fixes close the reviewed disabled-enrollment revoke, installer safety, protected-file race, rollback-verification and certificate-expiry gaps; no production deployment claim is added.
- Validation: macOS passed 82 Relay tests (79 library plus 3 binary); native Ubuntu x86_64 passed 81 tests (78 library plus 3 binary), with locked quality, release/archive/checksum and version checks.
- Scope: local protected material, expiry-aware allowlist, enrollment/revocation, updater, supervision and governance restoration.
- Exclusions: no mb17 deployment, live issuance, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: same-source checksum provenance, published Linux CI/artifact provenance, restart-persistent authorization and P6 lifecycle/rebind evidence remain open.
- Next dependency: keep P6 planned and inactive until separate deployment authorization; do not claim live issuance, mb17 deployment or P6 lifecycle evidence.

[checkpointed](1-207) 2026-08-24 | QRM-PROD-1 P4 local validation checkpointed
- Repository state: Relay implementation and restored governance sources are checkpointed at `074d84d`; no push; unrelated parent/Core/App-iOS/Herdr content remains preserved.
- Review: fresh GLM-5.3 security review found no P0-P3 issues; governance review's table-shape P3 was corrected and the narrow GLM-5.3 re-review found no P0-P3 issues.
- Validation: macOS passed 82 Relay tests (79 library plus 3 binary) and native Ubuntu 24.04 x86_64 passed 81 (78 library plus 3 binary), with locked quality, rustdoc, release/archive/checksum, supervision and version checks.
- Scope: local protected material, enrollment/allowlist, updater, supervision, governance restoration and cross-platform evidence only.
- Exclusions: no mb17 deployment, live issuance, remote update, Herdr mutation/parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: same-source checksum provenance, published Linux CI/artifact provenance, restart-persistent authorization and P6 lifecycle/rebind evidence remain open.
- Next dependency: keep P6 planned and inactive until separate deployment authorization; do not claim live issuance, mb17 deployment or P6 lifecycle evidence.
