---
title: Herdr-dog Relay Architecture
description: Single-device QUIC TLS 1.3 relay architecture for Herdr-dog.
published: true
date: 2026-08-24T01:43:10+08:00
tags: herdr-dog, relay, quic, architecture
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay Architecture

## Current status

Status: `active` for QRM-PROD-1 P2. QRM-1 Q4/Q5 evidence and the QRM-1 bounded package checkpoints remain preserved. The Relay now has local protected-material, enrollment/allowlist, updater and supervision seams around the one-process/one-UDP/one-QUIC topology; live issuance, deployment and service evidence remain unclaimed.

## Ownership

Relay owns QUIC authentication, bounded HDQM/HDQS validation, session fingerprint/generation/token authority, Herdr Unix socket identity checks and opaque byte forwarding. Core owns Herdr protocol parsing, Target state, projection, liveness and action safety. App sees only typed Core data.

## Invariants

- ALPN is `herdr-dog-relay-quic/1` for normal QRM and `herdr-dog-relay-enroll/1` for the terminal enrollment path;
- normal QRM requires TLS client authentication plus an active persisted App allowlist fingerprint;
- enrollment requires the authenticated Core origin, a Relay single-use challenge and bounded CSR/authorization binding;
- protected certificate/key/allowlist files are owner-validated and atomically updated;
- updater archives are fixed-source, checksum-verified and path/type/size bounded before extraction;
- plaintext UDP is forbidden;
- no Herdr bytes before accepted HDQS binding;
- session failure is isolated to one stream;
- connection loss invalidates all connection-local handles and tokens;
- Relay never parses, logs, persists or proxies arbitrary Herdr methods.

## Checkpoint Log

[accepted](1-38) 2026-08-22 | QRM-1 Q3 architecture checkpointed
- Repository state: architecture document and Q3 Relay implementation are checkpointed in the Relay submodule.
- Validation: single-port/device-scoped QUIC ownership, authority and stream-isolation boundaries are recorded.
- Scope: Relay server and session stream architecture.
- Exclusions: TCP, class listeners, Broker discovery, per-session ports, Herdr parsing and Q4/Q5 external evidence.
- Residual risk: weak-network and deployed mb17 evidence remain open.
- Next dependency: implement and validate Q4 before fresh review.

[active](1-49) 2026-08-22 | QRM-1 Relay Q4 architecture validation active
- Repository state: Relay Q3 architecture and implementation are checkpointed; Q4 test-only network disturbance validation is beginning.
- Validation: one-process/one-port/one-connection stream ownership remains recorded; Q4 evidence is not yet claimed.
- Scope: packet disturbance, stream isolation, reconnect authority and bounded queues.
- Exclusions: Q5 mb17, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: weak-network and deployed evidence remain open.
- Next dependency: implement Q4 harness validation.

[active](1-57) 2026-08-23 | QRM-1 Relay Q4 architecture post-fix validation checkpoint
- Repository state: Q3 Relay architecture and implementation remain checkpointed; Q4 uses the shared Core-owned test harness and does not change Relay production architecture.
- Validation: Core Q4 validation and existing Relay quality gates pass after the control-priority close-order correction; the specified fresh GLM review remains pending.
- Scope: packet disturbance, QUIC control progress during a stalled session stream, stream isolation, reconnect authority and bounded queues.
- Exclusions: Q5 mb17, Herdr parsing, actions, subscriptions, healthy Current, passthrough and deployment claims.
- Residual risk: Q4 remains active/uncheckpointed; local weak-network evidence is not field or deployed evidence.
[checkpointed](1-60) 2026-08-23 | QRM-1 Relay Q4 architecture checkpointed
- Repository state: Relay Q4 has no production architecture change; Core implementation/status checkpoints are `bbc39b9`/`a44ef6d`, and this Relay architecture record is selectively checkpointed.
- Validation: Luna max review findings on flow-control close ordering and status synchronization are closed; Core 313 tests and Relay 46 locked tests plus quality gates pass.
- Scope: packet disturbance, QUIC control progress during a stalled session stream, stream isolation, reconnect authority and bounded queues.
- Exclusions: Q5 mb17, Herdr parsing, actions, subscriptions, healthy Current, passthrough and deployment claims.
- Residual risk: P3 no-replay assertion hardening and deployed evidence remain open.
- Next dependency: keep Q5 planned until real mb17 evidence is separately activated.

[active](1-68) 2026-08-23 | QRM-1 Relay Q5 architecture preflight active
- Repository state: Relay Q4 architecture checkpoint is committed; Herdr master is `d6dae883`; generated schema helpers remain excluded.
- Validation: the one-process/one-port/one-connection architecture and TLS/authority boundaries remain unchanged; upstream subscription sequencing is outside Q5.
- Scope: validate deployed QUIC listener identity, two isolated session streams and Core-owned typed read attribution.
- Exclusions: legacy transport, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retries.
- Next dependency: complete non-destructive preflight before deployment replacement.

[validated](1-75) 2026-08-23 | QRM-1 Relay Q5 deployed architecture validated
- Repository state: the deployed mb17 Relay uses the QRM one-process/one-UDP/one-QUIC topology; old TCP listener is closed and rollback backup is retained.
- Validation: Core typed protocol-20 reads passed for default and `qrm-work`; stopped named socket failure remained isolated to its session.
- Scope: device-level connection sharing with session-stream routing and Core-owned Herdr interpretation.
- Exclusions: legacy transport, Herdr parsing in Relay, writes, subscriptions, healthy Current, actions, passthrough and automatic retries.
- Residual risk: no LaunchAgent, PKI rotation and final package checkpoint remain open.
- Next dependency: complete post-fix review and selective checkpointing.

[active](1-87) 2026-08-24 | QRM-PROD-1 P2 Relay architecture implementation active
- Repository state: P1 Relay checkpoint is preserved; P2 source and documentation changes are uncommitted, with no mb17 mutation.
- Validation: local Relay quality gates pass with 66 tests, Clippy, rustfmt, rustdoc and diff checks.
- Scope: protected material, enrollment ALPN, active allowlist/revocation, fixed-source updater and user-level supervision around QRM-1.
- Exclusions: no production issuance/deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: live mTLS enrollment admission, connection closure after revocation, updater drain/restart and mb17 evidence remain open.
- Next dependency: complete fresh P2 review/fix/revalidation before selective Relay checkpointing.

[implemented](1-95) 2026-08-24 | QRM-PROD-1 P2 Relay architecture implementation completed
- Repository state: P2 Relay source/config/workflow/template changes are uncommitted; P1 checkpoints remain preserved and mb17/Herdr are untouched.
- Validation: 69 Relay tests, Clippy, rustfmt, rustdoc, locked checks and diff checks pass locally.
- Scope: one-device/one-port/one-connection QRM with normal/enrollment ALPN, protected allowlist, transient PKI, fixed updater and supervision seams.
- Exclusions: live P6 drain/restart/readiness/rebind, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: fresh P2 review/fix/revalidation and real service/deployment evidence remain open.
- Next dependency: complete fresh P2 review, apply fixes, then selectively checkpoint Relay.

[accepted](1-103) 2026-08-24 | QRM-PROD-1 P2 Relay architecture local implementation accepted
- Repository state: P2 Relay source/config/workflow/template changes remain uncommitted; P1 checkpoints and Herdr/mb17 exclusions are preserved.
- Validation/review: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final fresh dual review found no P0-P2 findings.
- Scope: one-device/one-port/one-connection QRM with normal/enrollment ALPN, protected allowlist, transient PKI, fixed updater and supervision seams.
- Exclusions: live P6 cutover, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live enrollment/closure and P4-P6 service/deployment evidence remain open; checkpointing is required.
- Next dependency: selectively checkpoint Relay, then synchronize parent status.

[checkpointed](1-111) 2026-08-24 | QRM-PROD-1 Relay architecture checkpointed at `51134bb`
- Repository state: Relay P2 architecture/source/docs are committed at `51134bb`; Relay worktree is clean; parent status closure remains pending.
- Validation: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final review found no P0-P2 findings.
- Scope: one-device/one-port/one-connection QRM with normal/enrollment ALPN, protected allowlist, transient PKI, fixed updater and supervision seams.
- Exclusions: live P6 cutover, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live enrollment/closure and P4-P6 service/deployment evidence remain open.
- Next dependency: synchronize parent status and gitlinks.
