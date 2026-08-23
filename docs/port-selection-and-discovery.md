---
title: Herdr-dog Relay Endpoint and Port Plan
description: Fixed single UDP endpoint and explicit configuration rules for QRM-1.
published: true
date: 2026-08-22T00:10:00+08:00
tags: herdr-dog, relay, quic, port, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay Endpoint and Port Plan

## Current status

Status: `active` for QRM-1; Q4 weak-network validation is checkpointed and deployed endpoint evidence remains planned.

## Contract

- one Relay device listener;
- default UDP port `18743`;
- CLI `--port` has priority over TOML, TOML over default;
- no candidate range, discovery sweep, random fallback or per-session data port;
- explicit bind address required for deployment;
- Core receives one typed host/port endpoint and opens one QUIC connection;
- QUIC TLS 1.3 and ALPN `herdr-dog-relay-quic/1` are required before control/data streams;
- multiple sessions use independent QUIC bidirectional streams, not additional ports.

## Validation

Configuration tests reject zero/invalid ports, unknown fields, plaintext mode, missing production identity material and non-bounded limits. Integration tests prove one listener serves at least three isolated session streams.

## Checkpoint Log

[accepted](1-40) 2026-08-22 | QRM-1 Q3 endpoint checkpointed
- Repository state: endpoint document and Q3 Relay implementation are checkpointed in the Relay submodule.
- Validation: fixed port and no-fallback policy recorded and tested.
- Scope: generic UDP endpoint and QUIC stream multiplexing.
- Exclusions: port ranges, network classes, Broker discovery and per-session data ports.
- Residual risk: deployed UDP reachability remains open.
- Next dependency: keep Q5 endpoint validation planned.

[active](1-51) 2026-08-22 | QRM-1 Relay Q4 endpoint validation active
- Repository state: endpoint policy and Q3 implementation are checkpointed; Q4 test-only network disturbance validation is beginning.
- Validation: fixed endpoint/no-fallback policy remains tested; Q4 evidence is not yet claimed.
- Scope: UDP endpoint behavior under deterministic disturbance and reconnect.
- Exclusions: port ranges, network classes, Broker discovery and per-session data ports.
- Residual risk: deployed UDP reachability remains open.
[checkpointed](1-54) 2026-08-23 | QRM-1 Relay Q4 endpoint validation checkpointed
- Repository state: endpoint policy and Core Q4 implementation/status checkpoints `bbc39b9`/`a44ef6d` are preserved; Relay has no Q4 production endpoint change and this document is selectively checkpointed.
- Validation: fixed endpoint/no-fallback policy remains tested; Core/Relay quality gates and the Luna max review correction loop pass.
- Scope: UDP endpoint behavior under deterministic disturbance and reconnect.
- Exclusions: port ranges, network classes, Broker discovery and per-session data ports.
- Residual risk: deployed UDP reachability and Q5 mb17 evidence remain open.
- Next dependency: keep Q5 endpoint validation planned.
