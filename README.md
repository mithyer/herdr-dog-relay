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

QRM-1 Q3 is locally accepted at the implementation/review gate. The Relay target is one user-level `herdogrelay` process, one UDP listener defaulting to `18743`, one QUIC TLS 1.3 connection per Core device and one session stream per Herdr session. Q4 weak-network and Q5 mb17 gates remain planned; no deployment claim is made.

## Boundary

The Relay authenticates Core, validates HDQM/HDQS/session authority and bridges opaque bytes to validated Herdr Unix sockets. It does not run Core, parse Herdr, expose arbitrary API commands or log payloads. The App communicates with Core only.

## Current implementation

QRM-1 Q3 is locally accepted and checkpointed in the Relay submodule. The local Relay includes the production Quinn UDP server, HDQM/HDQS authority lifecycle, opaque Unix bridge, bounded control/lease handling, malformed-frame rejection, and verified-mode production gating. Local loopback evidence is not mb17 deployment evidence; Q4 weak-network and Q5 mb17 read-only gates remain planned. Actions, subscriptions, healthy `Online + Current` and arbitrary passthrough remain disabled.

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
- Next dependency: keep Q4/Q5 planned until separately authorized and evidenced.
