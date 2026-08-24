---
title: Herdr-dog Relay Endpoint and Port Plan
description: Fixed single UDP endpoint and explicit configuration rules for QRM-1.
published: true
date: 2026-08-24T11:41:11+08:00
tags: herdr-dog, relay, quic, port, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay Endpoint and Port Plan

## Current status

Status: `active` for QRM-PROD-1 P4 local cross-platform validation. QRM-1 Q4/Q5 endpoint evidence and P2/P3 checkpoints remain preserved. P4 validates local same-port enrollment/no-forward and disposable updater/service behavior only; deployment remains unverified.

## Contract

- one Relay device listener;
- default UDP port `18743`;
- CLI `--port` has priority over TOML, TOML over default;
- no candidate range, discovery sweep, random fallback or per-session data port;
- explicit bind address required for deployment;
- Core receives one typed host/port endpoint and opens one QUIC connection;
- QUIC TLS 1.3 and ALPN `herdr-dog-relay-quic/1` are required before normal control/data streams;
- same UDP listener may negotiate terminal `herdr-dog-relay-enroll/1` only for Core-mTLS enrollment;
- normal QRM admission requires an active persisted App allowlist identity;
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
- Next dependency: keep Q5 endpoint validation planned.

[active](1-61) 2026-08-23 | QRM-1 Relay Q5 mb17 endpoint preflight active
- Repository state: endpoint policy and Q4 status checkpoints are committed; Herdr master is `d6dae883`; generated schema helpers remain excluded.
- Validation: fixed UDP 18743 endpoint/no-fallback policy remains tested; Q5 has not yet modified the remote listener.
- Scope: non-destructive inspection of mb17 bind address, UDP port, process owner, listener state and endpoint reachability prerequisites.
- Exclusions: port ranges, discovery, random fallback, per-session ports, credential mutation, Herdr parsing and live forwarding before TLS/authority checks.
- Next dependency: complete endpoint preflight before any remote Relay replacement or live probe.

[validated](1-68) 2026-08-23 | QRM-1 Relay Q5 mb17 endpoint validated
- Repository state: QRM Relay is deployed outside the repository with one explicit UDP endpoint; the old TCP listener and old runtime path are closed, with rollback backup retained.
- Validation: final listener is `100.64.0.6:18743/UDP`; no range scan or fallback occurred; Core protocol-20 two-session read and socket-failure isolation passed.
- Scope: fixed endpoint, verified QUIC TLS 1.3/ALPN and one process/device.
- Exclusions: port ranges, discovery, random fallback, per-session ports, credential mutation, Herdr parsing and live writes.
- Residual risk: endpoint persistence/supervision and final checkpoint remain open.
- Next dependency: finish post-fix review and checkpoint the deployment evidence.

[active](1-78) 2026-08-24 | QRM-PROD-1 P2 Relay endpoint implementation active
- Repository state: P1 Relay checkpoint is preserved; P2 endpoint/config/source changes are uncommitted and mb17 is untouched.
- Validation: local Relay 66-test quality gates pass; no deployment or Herdr liveness evidence is claimed.
- Scope: one UDP listener with normal/enrollment ALPN separation, allowlist admission and fixed updater/supervision endpoint configuration.
- Exclusions: no port range/discovery/fallback, per-session ports, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: live ALPN/mTLS/allowlist admission and supervised restart evidence remain open.
- Next dependency: complete fresh P2 review/fix/revalidation before selective Relay checkpointing.

[implemented](1-86) 2026-08-24 | QRM-PROD-1 P2 Relay endpoint implementation completed
- Repository state: P2 endpoint/config/source changes are uncommitted; P1 checkpoints remain preserved and mb17/Herdr are untouched.
- Validation: 69 Relay tests, Clippy, rustfmt, rustdoc, locked checks and diff checks pass locally.
- Scope: one UDP listener with normal/enrollment ALPN, active allowlist admission and fixed updater/supervision endpoint configuration.
- Exclusions: no port range/discovery/fallback, per-session ports, live P6 deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: fresh P2 review/fix/revalidation and live ALPN/mTLS/allowlist/supervision evidence remain open.
- Next dependency: complete fresh P2 review, apply fixes, then selectively checkpoint Relay.

[accepted](1-94) 2026-08-24 | QRM-PROD-1 P2 Relay endpoint local implementation accepted
- Repository state: P2 endpoint/config/source changes remain uncommitted; P1 checkpoints and Herdr/mb17 exclusions are preserved.
- Validation/review: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final fresh dual review found no P0-P2 findings.
- Scope: one UDP listener with normal/enrollment ALPN, active allowlist admission and fixed updater/supervision endpoint configuration.
- Exclusions: no port range/discovery/fallback, per-session ports, live P6 deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: P3 live ALPN/mTLS/allowlist evidence and P4-P6 supervision/deployment remain open; checkpointing is required.
- Next dependency: selectively checkpoint Relay, then synchronize parent status.

[checkpointed](1-102) 2026-08-24 | QRM-PROD-1 Relay endpoint checkpointed at `51134bb`
- Repository state: Relay P2 endpoint/config/source changes are committed at `51134bb`; Relay worktree is clean; parent status closure remains pending.
- Validation: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final review found no P0-P2 findings.
- Scope: one UDP listener with normal/enrollment ALPN, active allowlist admission and fixed updater/supervision endpoint configuration.
- Exclusions: no port range/discovery/fallback, per-session ports, live P6 deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: P3 live ALPN/mTLS/allowlist and P4-P6 supervision/deployment evidence remain open.
- Next dependency: synchronize parent status and gitlinks.

[active](1-110) 2026-08-24 | QRM-PROD-1 P4 local endpoint evidence active
- Repository state: P4 activation/baseline checkpoints are Core `413c5c0`/`1c0371e`, Relay `a244ba0`/`07b1be3`, App-iOS `e58eb3f`/`fe3c62a`, and parent `52fbe34`/`484d806`; current Relay changes restore governance sources removed from tracking by `0fc3563`.
- Validation: Relay 79 locked tests include same-port enrollment ALPN terminal rejection of HDQM, normal-QRM missing-client rejection, and bounded quota isolation; local service fixtures do not bind a deployed Relay endpoint.
- Scope: one configured UDP endpoint and same-port terminal enrollment boundary under local P4 validation.
- Exclusions: no endpoint deployment, port discovery/fallback, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: published Linux release artifact/CI provenance, restart-persistent authorization and P6 real listener/restart/rebind evidence remain open.
- Next dependency: finish P4 correction review and artifact/CI evidence; do not activate P6.

[active](1-118) 2026-08-24 | QRM-PROD-1 P4 post-fix endpoint validation
- Repository state: Relay source and governance restoration remain uncommitted; P4 remains local-only and active.
- Validation: same-port enrollment/no-forward and normal-QRM allowlist boundaries pass in the 81-test macOS and 80-test native Ubuntu x86_64 batteries.
- Scope: one configured UDP endpoint and terminal enrollment boundary under local P4 validation.
- Exclusions: no endpoint deployment, port discovery/fallback, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: published Linux artifact/CI provenance, restart-persistent authorization and P6 listener/restart/rebind evidence remain open.
- Next dependency: complete final fresh review and selective checkpoint validation; do not activate P6.

[active](1-126) 2026-08-24 | QRM-PROD-1 P4 post-review endpoint validation
- Review: installer and protected-material corrections preserve the single configured UDP endpoint and fail-closed certificate/allowlist boundary.
- Validation: macOS passed 82 Relay tests and native Ubuntu x86_64 passed 81 tests, including enrollment/no-forward and normal-QRM allowlist checks.
- Scope: one configured UDP endpoint, terminal enrollment and local update/service validation.
- Exclusions: no endpoint deployment, port discovery/fallback, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: published Linux CI/artifact provenance and P6 listener/restart/rebind evidence remain open.
- Next dependency: complete the replacement fresh review and selective checkpoint validation; do not activate P6.
