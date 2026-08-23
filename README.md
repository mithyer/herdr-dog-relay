---
title: Herdr-dog Relay
description: Single-device single-port QUIC TLS 1.3 opaque byte Relay.
published: true
date: 2026-08-22T00:10:00+08:00
tags: herdr-dog, relay, quic
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay

## Current status

QRM-1 Q3 is locally accepted and checkpointed at the implementation/review gate. Q4 weak-network validation is checkpointed as a Core-owned test-only package; the Relay target is one user-level `herdogrelay` process, one UDP listener defaulting to `18743`, one QUIC TLS 1.3 connection per Core device and one session stream per Herdr session. Q5 mb17 read-only preflight is active; no deployment or capability claim is made.

## Boundary

The Relay authenticates Core, validates HDQM/HDQS/session authority and bridges opaque bytes to validated Herdr Unix sockets. It does not run Core, parse Herdr, expose arbitrary API commands or log payloads. The App communicates with Core only.

## Current implementation

QRM-1 Q3 is locally accepted and checkpointed in the Relay submodule. The local Relay includes the production Quinn UDP server, HDQM/HDQS authority lifecycle, opaque Unix bridge, bounded control/lease handling, malformed-frame rejection, and verified-mode production gating. Q4 is checkpointed as a Core-owned test-only weak-network package; local loopback evidence is not mb17 deployment evidence, and Q5 mb17 read-only preflight is active. Actions, subscriptions, healthy `Online + Current` and arbitrary passthrough remain disabled.

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
- Residual risk: remote binary readiness, TLS material, UDP reachability, session registration and cleanup/rollback remain open.
- Next dependency: complete the non-destructive preflight before replacing or starting the QRM Relay process.
