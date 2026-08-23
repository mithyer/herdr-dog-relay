---
title: Herdr-dog Relay
description: Single-device single-port QUIC TLS 1.3 opaque byte Relay.
published: true
date: 2026-08-24T01:43:10+08:00
tags: herdr-dog, relay, quic
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay

## Current status

QRM-1 Q5 mb17 one-port/two-session read-only evidence and Q6 App/embedded Core integration are checkpointed. Q7 Legacy Cleanup is checkpointed in Relay at `a2dd9dc`. QRM-PROD-1 P2 is now the active parent-owned Relay implementation stage: protected-file material validation, same-port enrollment framing/ALPN, persistent allowlist/revocation, stable-latest archive safety, and user-level supervision templates are implemented locally and remain uncheckpointed. No certificate issuance/deployment, Herdr payload parsing, writes, subscriptions, healthy `Online + Current`, actions, passthrough or automatic retry is claimed.

## Boundary

The Relay authenticates Core, validates HDQM/HDQS/session authority and bridges opaque bytes to validated Herdr Unix sockets. It does not run Core, parse Herdr, expose arbitrary API commands or log payloads. The App communicates with Core only.

## Current implementation

QRM-PROD-1 P2 is active and implemented locally but not checkpointed. The current Relay source adds bounded protected-file, allowlist, enrollment-wire, transient PKI, updater and supervision seams around the existing QRM QUIC bridge; the 66-test local gate passes. Production certificate material, live enrollment, remote update, service installation and mb17 deployment remain later evidence gates.

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
