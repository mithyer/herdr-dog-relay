---
title: Herdr-dog Relay Architecture
description: Single-device QUIC TLS 1.3 relay architecture for Herdr-dog.
published: true
date: 2026-08-23T11:25:00+08:00
tags: herdr-dog, relay, quic, architecture
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay Architecture

## Current status

Status: `active` for QRM-1; Q4 weak-network validation is checkpointed as a test-only package and Q5 mb17 one-port/two-session read-only evidence is `validated` for the deployed x86_64 Relay. One `herdogrelay` process binds one UDP port, default `18743`, and accepts one QUIC TLS 1.3 connection per Core device. One control stream and one bidirectional stream per Herdr session share that connection; final review/checkpoint remains open.

## Ownership

Relay owns QUIC authentication, bounded HDQM/HDQS validation, session fingerprint/generation/token authority, Herdr Unix socket identity checks and opaque byte forwarding. Core owns Herdr protocol parsing, Target state, projection, liveness and action safety. App sees only typed Core data.

## Invariants

- ALPN is `herdr-dog-relay-quic/1`;
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
