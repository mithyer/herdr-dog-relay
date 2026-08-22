---
title: Herdr-dog Relay Architecture
description: Single-device QUIC TLS 1.3 relay architecture for Herdr-dog.
published: true
date: 2026-08-22T00:10:00+08:00
tags: herdr-dog, relay, quic, architecture
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay Architecture

## Current status

Status: `accepted` for QRM-1 Q3; Q4 weak-network and Q5 mb17 evidence remain planned. One `herdogrelay` process binds one UDP port, default `18743`, and accepts one QUIC TLS 1.3 connection per Core device. One control stream and one bidirectional stream per Herdr session share that connection.

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
- Next dependency: keep Q4/Q5 planned until their independent gates are authorized.
