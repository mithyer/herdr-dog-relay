---
title: Herdr-dog Relay QUIC Implementation Plan
description: QRM-1 single UDP listener, QUIC TLS 1.3, control/session streams and Unix byte bridge.
published: true
date: 2026-08-22T00:10:00+08:00
tags: herdr-dog, relay, quic, rust, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay QUIC Implementation Plan

## Current status

Status: `accepted` for QRM-1 Q3; QRM-1 remains active with Q4 weak-network and Q5 mb17 evidence planned. The implementation directly replaces the previous TCP, listener-class, Broker, HDRL/HDBD, per-session data-port and relay-child entry points. The Relay remains an opaque byte bridge and never parses Herdr protocol.

## Architecture

One `herdogrelay` process binds one UDP port, default `18743`, with QUIC TLS 1.3 and ALPN `herdr-dog-relay-quic/1`. Each Core device connection has one HDQM control stream and one HDQS bidirectional stream per approved Herdr session. `SessionRegistry` owns normalization, fingerprint/token/generation authority, validated Unix socket identity and bounded bridge task lifecycle.

## Configuration

```toml
[listener]
listen_address = "127.0.0.1"
port = 18743

[security]
mode = "verified"
server_certificate = ""
server_private_key = ""
trusted_client_ca = ""

[limits]
max_connections = 64
max_sessions_per_connection = 64
max_control_frame_bytes = 65536
buffer_bytes = 65536
handshake_timeout_secs = 5
idle_timeout_secs = 900
```

Every option is explicit in `config/default.toml`. `verified` is the production default; development trust relaxation remains TLS 1.3 and test-only. No plaintext, network-class, port-range or per-session-port option exists.

## Modules

```text
src/quic_server.rs       server owner, connection epoch and limits
src/quic_wire.rs         HDQM/HDQS bounded codec
src/session_registry.rs  session/fingerprint/generation/token authority
src/bridge.rs            opaque bounded QUIC-to-Unix forwarding
src/socket.rs            Unix owner/mode/type/identity validation
src/config.rs            one-listener TOML and TLS/resource validation
src/error.rs             redacted Relay errors
src/bin/herdogrelay.rs   one-port CLI host
```

## QRM phases

| Phase | Scope | Status | Gate |
| --- | --- | --- | --- |
| Q1 | codec, fake SessionRegistry, authority matrix and three-session tests | accepted | malformed/no-forward tests, locked quality gates and read-only review |
| Q2 | Quinn UDP server, TLS/mTLS, ALPN, HDQM and HDQS streams | accepted | loopback TLS, stream isolation, stale heartbeat and capacity rejection |
| Q3 | Unix socket bridge, deadlines, EOF and redacted cleanup | accepted | socket replacement, bounded buffers and lifecycle tests |
| Q4 | weak-network injection and reconnect | planned | stream isolation, new epochs/handles and memory bounds |
| Q5 | mb17 one-port/two-session read-only evidence | planned | typed ping/snapshot only |
| Q6 | hidden App transport consumer | planned | typed App boundary and Keychain identity |
| Q7 | remove remaining conflicting files and checkpoint | planned | current QRM-only source/config/docs |

## Verification commands

```text
cargo test --manifest-path relay/Cargo.toml --locked --all-targets --all-features
cargo clippy --manifest-path relay/Cargo.toml --locked --all-targets --all-features -- -D warnings
cargo fmt --manifest-path relay/Cargo.toml --all -- --check
cargo doc --manifest-path relay/Cargo.toml --all-features --no-deps
git diff --check
```

Q1 tests prove only bounded contract/fake behavior. Q2-Q5 are required before any deployment claim. No phase enables Herdr writes, subscriptions, healthy Current or arbitrary passthrough.

## Stop conditions

Block QRM-1 when TLS is absent, invalid authority reaches Herdr, one session sees another session's bytes, a session error kills unrelated streams, buffers are unbounded, or any diagnostic contains payload/token/certificate material.

## Checkpoint Log

[accepted](1-94) 2026-08-22 | QRM-1 Relay Q1 accepted; Q2 active
- Repository state: Relay Q1 source/config changes are uncommitted; deleted conflicting Manager/Broker/TCP files are outside the new QRM source set.
- Validation: 34 Relay tests, Clippy, rustfmt, rustdoc, locked dependency resolution and diff checks passed; fresh read-only review found no P0-P2.
- Scope: Core/Relay wire parity, bounded codec, SessionRegistry token/generation/epoch/TTL/capacity, malformed/no-forward tests, three-session isolation, Unix validation and redaction.
- Exclusions: Q2 UDP/Quinn I/O, Herdr parsing, subscriptions, healthy Current, actions and passthrough.
- Residual risk: Q2 TLS certificate loading, UDP listener, stream serving and real mb17 evidence remain open.
- Next dependency: Q2 production Quinn UDP server and session stream bridge.

[accepted](1-94) 2026-08-22 | QRM-1 Relay Q2 QUIC server gate accepted
- Repository state: Relay Q2 sources/tests remain uncommitted; deleted legacy Manager/Broker/TCP files and unrelated dirty content remain preserved.
- Validation: 41 locked Relay tests, Clippy with warnings denied, rustfmt, rustdoc, diff checks, mTLS/ALPN loopback, three-session network isolation, stale-heartbeat/capacity ErrorResponses, no-forward-before-bind and task cleanup passed; final read-only review found no P0-P2.
- Scope: one UDP listener, one QUIC connection control stream, isolated HDQS streams, bounded SessionRegistry, verified TLS policy and opaque Unix bridge.
- Exclusions: Q3 Runtime/bridge hardening, Q4 weak-network, Q5 mb17, Q6 App transport, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: prepared-entry reaping, close/error taxonomy, direct epoch assertions and future stream lifecycle remain P3 follow-ups.
- Next dependency: Q3 Core/Relay Runtime read integration and lifecycle hardening.

[accepted](1-110) 2026-08-22 | QRM-1 Relay Q3 lifecycle/security gate accepted
- Repository state: Relay Q3 Quinn server/bridge corrections and this implementation plan are checkpointed in the Relay submodule; unrelated dirty content is preserved.
- Validation: 46 locked Relay tests, Clippy warnings denied, rustfmt, rustdoc and diff checks pass; fresh dual review found no confirmed P0/P1/P2 source defect. Direct Debug-redaction, malformed-HDQS and production-mode tests pass.
- Scope: exact rejection cleanup, malformed HDQS InvalidFrame closure, bounded control/bridge lease handling, authority redaction, production verified-mode gating and normalized socket routing.
- Exclusions: Q4 weak-network, Q5 mb17, Q6 App transport, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: Q4 weak-network and Q5 deployed evidence remain open; they are not implied by this checkpoint.
- Next dependency: keep Q4/Q5 planned until their independent evidence gates are authorized.
