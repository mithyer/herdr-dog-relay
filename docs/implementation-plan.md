---
title: Herdr-dog Relay QUIC Implementation Plan
description: QRM-1 single UDP listener, QUIC TLS 1.3, control/session streams and Unix byte bridge.
published: true
date: 2026-08-23T11:25:00+08:00
tags: herdr-dog, relay, quic, rust, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay QUIC Implementation Plan

## Current status

Status: `active` for QRM-1 Q7 Legacy Cleanup. Q4 weak-network validation, Q5 mb17 one-port/two-session read-only evidence and Q6 App/embedded Core integration status are checkpointed; Q7 adds no Relay source behavior until its baseline inventory is complete. The implementation directly replaces the previous TCP, listener-class, Broker, HDRL/HDBD, per-session data-port and relay-child entry points. The Relay remains an opaque byte bridge and never parses Herdr protocol; service provisioning, Keychain lifecycle and QRM overall acceptance remain open.

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
| Q4 | weak-network injection and reconnect | checkpointed | stream isolation, new epochs/handles and memory bounds |
| Q5 | mb17 one-port/two-session read-only evidence | checkpointed | typed ping/snapshot and socket-failure isolation |
| Q6 | hidden App transport consumer | checkpointed | no Relay source change; Core/App-iOS target baseline and typed boundary |
| Q7 | remove remaining conflicting files and checkpoint | active | current QRM-only source/config/docs after baseline, cleanup, quality and review gates |

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
- Next dependency: continue Q4 weak-network validation while keeping Q5 planned.

[active](1-118) 2026-08-22 | QRM-1 Relay Q4 weak-network validation active
- Repository state: Relay Q3 checkpoints are committed; Q4 test-only weak-network validation is beginning without production listener or wire changes.
- Validation: Q3 Relay named tests and quality gates remain recorded; Q4 evidence is not yet claimed.
- Scope: deterministic loss/delay/reorder proxy coverage, bounded queue/bridge behavior, stream isolation and connection-loss cleanup.
- Exclusions: Q5 mb17, Q6 App transport, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: packet-level and memory-bound evidence remain open.
- Next dependency: implement and validate the Q4 harness before fresh review.

[active](1-126) 2026-08-23 | QRM-1 Relay Q4 evidence alignment
- Repository state: Q4 remains the active test-only package; the Core-owned LossyUdpProxy and real-Quinn loopback harness provide the weak-network evidence around the existing Relay transport, and no Relay production source change is introduced by this phase.
- Validation: the focused Core Q4 suite and the fresh read-only review are complete; the parent-led control-priority proof correction and the full Core/Relay quality battery remain pending before checkpointing.
- Scope: deterministic loss/delay/reorder, bounded packet/byte queues, control-stream priority, stream isolation, connection-loss cleanup and fresh-authority evidence supplied by the shared QRM harness.
- Exclusions: Q5 mb17, Q6 App transport, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: full serialized validation, post-fix review, and selective Core/Relay checkpointing remain open; local evidence is not deployment evidence.
- Next dependency: complete the parent-led P2 correction, rerun the quality battery, then append the final Q4 acceptance/checkpoint record.

[active](1-134) 2026-08-23 | QRM-1 Relay Q4 post-fix validation checkpoint
- Repository state: Q4 remains test-only and introduces no Relay production source change; Core/Relay quality and parent documentation changes are uncommitted, while unrelated content remains preserved.
- Validation: Core passed 313 serial all-target/all-feature tests and Relay passed 46 locked tests with Clippy, rustfmt, rustdoc, fuzz and diff gates; the session close-order and pre-`SessionClosed` stall corrections are validated. The specified fresh GLM review remains pending.
- Scope: deterministic loss/delay/reorder, bounded packet/byte queues, heartbeat/close control progress during session flow-control stall, stream isolation and fresh-authority evidence.
- Exclusions: Q5 mb17, Q6 App transport, Herdr parsing, actions, subscriptions, healthy Current, passthrough and automatic retries.
- Residual risk: Q4 is active and uncheckpointed; local Core harness evidence is not deployed Relay or mb17 evidence.
[checkpointed](1-140) 2026-08-23 | QRM-1 Relay Q4 weak-network implementation gate checkpointed
- Repository state: Q4 adds no Relay production source; Core implementation/status checkpoints are `bbc39b9`/`a44ef6d`, and this Relay plan/status checkpoint is selective.
- Validation: Core passed 313 tests and Relay passed 46 locked tests with Clippy, rustfmt, rustdoc, fuzz and diff checks; Luna max review P1/P2 findings were closed and revalidated.
- Scope: stream isolation, bounded packet/byte queues, deterministic loss/delay/reorder, control progress under flow-control stall and reconnect authority invalidation.
- Exclusions: Q5 mb17, Q6 App transport, Herdr parsing, actions, subscriptions, healthy Current, passthrough and deployment claims.
- Residual risk: P3 no-replay assertion hardening and real deployment evidence remain open.
- Next dependency: keep Q5 planned until its own deployment/evidence gate is activated.

[active](1-148) 2026-08-23 | QRM-1 Relay Q5 mb17 read-only deployment preflight active
- Repository state: Relay Q4 implementation/status documentation is checkpointed; Herdr master is `d6dae883` and generated schema helpers remain excluded.
- Validation: local Relay QRM gates pass; protocol 20/schema 1 and the v0.8.2 schema digest are unchanged, while upstream subscription sequencing is outside Q5.
- Scope: one QRM Relay process, one UDP listener, verified QUIC TLS 1.3/mTLS material, two Herdr session streams and opaque byte-forwarding readiness.
- Exclusions: old TCP/Broker/HDRL/HDBR/HDBD runtime, per-session ports/children, Herdr parsing, writes, subscriptions, healthy Current, actions and passthrough.
- Residual risk: mb17 artifact/configuration, certificate material, UDP reachability and socket identity remain unverified.
- Next dependency: complete non-destructive mb17 preflight before live Relay replacement or reads.

[validated](1-156) 2026-08-23 | QRM-1 Relay Q5 mb17 read-only deployment validated
- Repository state: Relay Q4 implementation/status documentation is checkpointed; QRM x86_64 artifact and TLS material are deployed outside the repository, and old binary/config backup is retained on mb17.
- Validation: verified TLS 1.3/ALPN temporary bind and final UDP `100.64.0.6:18743` passed; old TCP listener closed; Core two-session protocol-20 and exact socket-failure isolation targets passed.
- Scope: one Relay process/device, one UDP listener, two isolated session streams and opaque forwarding.
- Exclusions: old TCP/Broker/HDRL/HDBR/HDBD, per-session ports/children, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retries.
- Residual risk: final review/checkpoint, supervision and PKI lifecycle remain open.
- Next dependency: keep Q6 outside Relay source and wait for the Core/App-iOS target baseline.

[active](1-164) 2026-08-23 | QRM-1 Relay Q6 App/embedded Core integration activated; Relay unchanged
- Repository state: Relay Q5 deployment/status documentation is checkpointed at `e2b694b`; no Relay Q6 source change is authorized or added.
- Validation: Q5 one-process/one-port/two-session protocol-20 read-only evidence and session-local failure isolation passed.
- Scope: preserve the opaque QUIC/session-stream authority while App consumes only typed Core results.
- Exclusions: Relay implementation changes, App-Core wire/endpoint changes, App-to-Relay access, raw Herdr bytes, writes, subscriptions, healthy Current, actions and passthrough.
- Residual risk: Core/App-iOS target/FFI/Keychain/reconnect evidence, Q6 review and Q7 cleanup remain open.
[checkpointed](1-170) 2026-08-23 | QRM-1 Relay Q6 App/embedded Core integration checkpointed; Relay unchanged
- Repository state: Relay Q6 status checkpoint and previous Q5 deployment checkpoint are committed; no Relay Q6 source change was added; parent gitlink/status synchronization is complete at the parent layer.
- Validation: Core/FFI quality gates, iOS builds, hosted XCTest and fresh post-fix review passed with no P0-P2.
- Scope: preserve the opaque QUIC/session-stream authority while App consumes only typed Core results.
- Exclusions: Relay implementation changes, App-Core wire/endpoint changes, App-to-Relay access, raw Herdr bytes, writes, subscriptions, healthy Current, actions and passthrough.
- Residual risk: Keychain provisioning, real native/device evidence, cancellation propagation, Q7 cleanup and long-term PKI/service lifecycle remain open.
- Next dependency: capture a read-only Q7 baseline and inventory active legacy references before implementation cleanup.

[active](1-178) 2026-08-23 | QRM-1 Relay Q7 Legacy Cleanup activated
- Repository state: Relay Q6 status is checkpointed at `c4abc7f`; no Relay Q7 source change is authorized or added; Herdr generated helpers remain excluded.
- Validation: Q6 Core/FFI quality gates, iOS builds, hosted XCTest and fresh review passed; this Q7 activation is documentation-only.
- Scope: remove or rewrite active Relay legacy listener/config/export/test references while preserving the QRM QUIC listener, SessionRegistry, opaque bridge and historical checkpoints.
- Exclusions: no legacy fallback, new protocol behavior, Herdr parsing, App-Core changes, deployment changes, writes, subscriptions, healthy Current, actions or passthrough.
- Residual risk: active caller inventory, CLI/config fallout, deployment documentation and final Q7 review remain open.
- Next dependency: capture the read-only baseline and complete the Relay legacy active-entrypoint inventory before implementation cleanup.
