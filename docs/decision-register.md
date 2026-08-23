---
title: Herdr-dog Relay QUIC Decision Register
description: QRM-1 Relay port, TLS, ALPN, stream, resource and security decisions.
published: true
date: 2026-08-23T11:25:00+08:00
tags: herdr-dog, relay, quic, decisions, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay QUIC Decision Register

## Current status

Status: `active` for QRM-1 Q7 Legacy Cleanup. Q4 weak-network validation, Q5 mb17 one-port/two-session read-only deployment evidence and Q6 App/embedded Core integration status are checkpointed. This register preserves the QRM replacement decisions and now governs cleanup of active legacy listener/config/export/test references; no protocol or capability expansion is part of Q7.

## Decisions

| ID | Status | Decision | Evidence/gate |
| --- | --- | --- | --- |
| QRM-RLY-001 | decided | One UDP listener per remote device, default port 18743; CLI > TOML > default; no range scan or fallback | QRM-1 plan; config tests |
| QRM-RLY-002 | decided | No Tailscale/LAN/public listener classes; one generic endpoint/security policy | QRM-1 architecture review |
| QRM-RLY-003 | decided | QUIC TLS 1.3 is mandatory; production verifies certificate and client identity; development relaxation is test-only | rustls/quinn loopback negative tests |
| QRM-RLY-004 | decided | ALPN is `herdr-dog-relay-quic/1` and application control uses HDQM v1 | wire contract tests |
| QRM-RLY-005 | decided | One `herdogrelay` process owns all session streams for one device | multi-session server test |
| QRM-RLY-006 | decided | One control stream plus one bidirectional QUIC stream per approved session | stream routing tests |
| QRM-RLY-007 | decided | Relay forwards opaque Herdr bytes only after HDQS authority acceptance | no-forward-before-bind test |
| QRM-RLY-008 | decided | Session authority binds normalized name, fingerprint, token, Relay generation and configuration generation | mismatch matrix |
| QRM-RLY-009 | decided | Control frame maximum is 65536 bytes; connection/session/buffer/time limits are explicit | bounded allocation tests |
| QRM-RLY-010 | decided | Session failure is stream-local; malformed control closes the physical connection; a syntactically valid heartbeat with stale authority returns a fixed session-scoped ErrorResponse and preserves sibling streams | isolation/heartbeat tests |
| QRM-RLY-011 | decided | Manager/child, HDBR/HDBD, HDRL, TCP, class policy and per-session port fields are removed | QRM cleanup gate |
| QRM-RLY-012 | decided | Relay never parses Herdr JSON, stores payloads or exposes arbitrary commands | source/review/redaction gate |

## Required evidence

Q1 requires codec, fake authority and three-session tests. Q2 requires quinn TLS/ALPN loopback and malformed/negative paths. Q3 requires Unix socket identity, segmented byte bridge, EOF, backpressure and cleanup. Q5 requires real mb17 one-port/two-session typed ping/snapshot evidence; Q4 remains weak-network/reconnect validation. None of these gates authorizes actions, subscriptions, healthy Current or raw passthrough.

## Checkpoint Log

[accepted](1-46) 2026-08-22 | QRM-1 Relay decisions frozen
- Repository state: uncommitted documentation synchronization; no QRM Relay code checkpoint yet.
- Validation: port, TLS, ALPN, stream, authority, resource and no-parsing decisions recorded.
- Scope: Relay QRM-1 only.
- Exclusions: old TCP/class/Broker/per-session-port behavior, Herdr parsing and actions.
- Residual risk: dependency and real network evidence remain open.
- Next dependency: complete Q0 document normalization, then Q1 contract/fake review.

[accepted](1-46) 2026-08-22 | QRM-1 Relay Q2 decisions/evidence accepted
- Repository state: Relay Q2 code and decision documentation remain uncommitted; no deployment or parent checkpoint was made.
- Validation: 41 locked Relay tests, Clippy, rustfmt, rustdoc, diff checks and final read-only review passed with no P0-P2; QRM-RLY-010 now has stale-heartbeat ErrorResponse and sibling-isolation evidence.
- Scope: generic UDP QUIC listener, TLS 1.3/mTLS/ALPN, HDQM/HDQS control/session authority, bounded capacity and opaque bridge behavior.
- Exclusions: Q3/Q4 lifecycle and weak-network work, mb17 deployment, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: P3 prepared-authority reaping, direct epoch assertions and graceful-close taxonomy remain open.
- Next dependency: Q3 Runtime/bridge lifecycle hardening.

[accepted](1-62) 2026-08-22 | QRM-1 Relay Q3 lifecycle/security gate accepted
- Repository state: Relay Q3 server/bridge corrections and this decision register are checkpointed in the Relay submodule; unrelated dirty content is preserved.
- Validation: 46 locked Relay tests, Clippy warnings denied, rustfmt, rustdoc and diff checks pass; fresh dual review found no confirmed P0/P1/P2 source defect, with direct redaction and malformed-HDQS checks passing.
- Scope: exact authority rejection cleanup, fixed malformed-HDQS response, bounded bridge/control lease handling, production verified-mode gating and normalized socket routing.
- Exclusions: Q4 weak-network, Q5 mb17, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: Q4/Q5 evidence remains open and is not implied by this checkpoint.
- Next dependency: implement and validate Q4 before fresh review.

[active](1-73) 2026-08-22 | QRM-1 Relay Q4 decision/evidence gate active
- Repository state: Relay Q3 checkpoints are committed; Q4 test-only weak-network validation is beginning without production wire changes.
- Validation: Q3 authority, redaction and bridge gates remain recorded; Q4 packet-level evidence is not yet claimed.
- Scope: deterministic loss/delay/reorder, bounded bridge queue, stream isolation and connection-loss cleanup.
- Exclusions: Q5 mb17, App transport, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: weak-network and memory-bound evidence remain open.
- Next dependency: implement and validate Q4 before fresh review.

[active](1-78) 2026-08-23 | QRM-1 Relay Q4 evidence alignment
- Repository state: Q4 remains the active test-only package; Core owns the LossyUdpProxy and real-Quinn loopback harness around the existing Relay transport, with no Relay production wire or listener change in this phase.
- Validation: the focused Core Q4 suite and fresh read-only review are complete; the control-priority proof correction, full serialized quality battery and post-fix review remain pending.
- Scope: deterministic loss/delay/reorder, bounded packet/byte queues, control-stream progress, stream isolation, connection-loss cleanup and fresh-authority evidence.
- Exclusions: Q5 mb17, App transport, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: Q4 remains uncheckpointed, and local harness evidence must not be presented as deployed Relay or mb17 evidence.
- Next dependency: complete the parent-led P2 correction, rerun the quality battery, then append the final Q4 acceptance/checkpoint record.

[active](1-86) 2026-08-23 | QRM-1 Relay Q4 post-fix validation checkpoint
- Repository state: Q4 remains test-only with no Relay production source change; Core/Relay quality and parent documentation changes are uncommitted, while unrelated content remains preserved.
- Validation: Core passed 313 serial all-target/all-feature tests and Relay passed 46 locked tests with Clippy, rustfmt, rustdoc, fuzz and diff gates; session close-order and pre-`SessionClosed` stall corrections are validated. The specified fresh GLM review remains pending.
- Scope: deterministic loss/delay/reorder, bounded packet/byte queues, heartbeat/close control progress during session flow-control stall, stream isolation and fresh-authority evidence.
- Exclusions: Q5 mb17, App transport, Herdr parsing, actions, subscriptions, healthy Current, passthrough and automatic retries.
- Residual risk: Q4 is active and uncheckpointed; local Core harness evidence is not deployed Relay or mb17 evidence.
[checkpointed](1-92) 2026-08-23 | QRM-1 Relay Q4 decision/evidence gate checkpointed
- Repository state: Q4 remains test-only with no Relay production source change; Core implementation/status checkpoints are `bbc39b9`/`a44ef6d`, and Relay documentation is selectively checkpointed.
- Validation: 46 locked Relay tests, Clippy, rustfmt, rustdoc and diff checks pass; Core's 313-test battery and all quality gates pass. Luna max review P1/P2 findings were closed and revalidated.
- Scope: deterministic loss/delay/reorder, bounded packet/byte queues, control-stream progress, stream isolation, connection-loss cleanup and fresh-authority evidence.
- Exclusions: Q5 mb17, App transport, Herdr parsing, actions, subscriptions, healthy Current and passthrough.
- Residual risk: P3 no-replay assertion hardening and real deployment evidence remain open.
- Next dependency: keep Q5 planned until the real two-session deployment gate is explicitly activated.

[active](1-100) 2026-08-23 | QRM-1 Relay Q5 deployment/security preflight active
- Repository state: Relay Q4 decision/status checkpoints are committed; Herdr master is `d6dae883`; generated schema helpers remain excluded.
- Validation: local TLS/authority/redaction gates pass; protocol 20/schema 1 and schema digest are unchanged, and upstream subscription sequencing is outside Q5.
- Scope: verify mb17 artifact/configuration, one UDP endpoint, verified TLS 1.3/mTLS, two session sockets and no-forward-before-bind readiness.
- Exclusions: plaintext, legacy TCP/Broker/HDRL/HDBR/HDBD, per-session ports/children, Herdr parsing, writes, subscriptions, healthy Current, actions and passthrough.
- Residual risk: certificate provisioning, endpoint reachability, session identity and deployed isolation evidence remain open.
- Next dependency: complete non-destructive preflight before starting the QRM Relay process.

[validated](1-108) 2026-08-23 | QRM-1 Relay Q5 deployment/security evidence validated
- Repository state: QRM x86_64 Relay and verified mTLS paths are deployed outside the repository; old binary/config backup is retained and Herdr configuration/credentials were preserved.
- Validation: temporary and final UDP bind, TLS 1.3/ALPN, old TCP closure, two session sockets and Core typed read/failure-isolation evidence passed.
- Scope: one generic device listener, one process, one connection and per-session authority.
- Exclusions: plaintext, network classes, legacy TCP/Broker/HDRL/HDBR/HDBD, per-session ports/children, Herdr parsing, writes, subscriptions, healthy Current, actions and passthrough.
- Residual risk: production PKI lifecycle, LaunchAgent/supervision and final selective checkpoint remain open.
- Next dependency: capture a read-only Q7 baseline and inventory active legacy references before implementation cleanup.

[active](1-116) 2026-08-23 | QRM-1 Relay Q7 Legacy Cleanup activated
- Repository state: Relay Q6 status is checkpointed at `c4abc7f`; no Relay Q7 source change is authorized or added; Herdr generated helpers remain excluded.
- Validation: Q6 cross-repository quality, build and review gates passed; this Q7 activation is documentation-only.
- Scope: remove or rewrite active legacy Relay listener/config/export/test references while preserving QRM QUIC, TLS/ALPN, stream authority and opaque-byte boundaries.
- Exclusions: no protocol expansion, Herdr parsing, App-Core changes, deployment changes, writes, subscriptions, healthy Current, actions, passthrough or fallback.
- Residual risk: active caller inventory, stale decision references and final Q7 review remain open.
- Next dependency: implement Q7 cleanup from the recorded active-entrypoint inventory.

[active](1-124) 2026-08-23 | QRM-1 Relay Q7 read-only baseline captured
- Repository state: Relay `5714abf`, parent `00b7b86`, Core `f2867d5`, App-iOS `fc9cf7d`, Herdr `d6dae883`; no Relay Q7 source change has been made and generated helpers remain excluded.
- Validation: Relay 46 passed, Core/FFI quality, iOS target checks, simulator builds, formatting, Clippy, rustdoc, fuzz and diff checks passed; no implementation source changed.
- Scope: decision-linked active caller/config/export/test inventory before removing stale Relay transport surfaces.
- Inventory findings: tracked Relay source has no legacy Broker/HDBR/HDBD/HDRL/TCP implementation; only the stale network-class config rejection test remains in `src/config.rs`.
- Exclusions/residual risk: QRM TLS/ALPN, generic UDP listener and session authority decisions remain unchanged; cleanup and final review remain open.
- Next dependency: implement Q7 cleanup from the recorded active-entrypoint inventory.
