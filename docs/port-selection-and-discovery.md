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

Status: `accepted` for QRM-1 Q3; deployed endpoint evidence remains planned.

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
