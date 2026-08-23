---
title: Herdr-dog Relay Operations
description: User-level operation and verification rules for the single-port QUIC Relay.
published: true
date: 2026-08-22T00:10:00+08:00
tags: herdr-dog, relay, operations, quic, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay Operations

## Current status

Status: `active` for QRM-1; Q4 weak-network validation is checkpointed as test-only and Q5 mb17 evidence remains planned. `herdogrelay` is one user-level process per remote device. The process owns one UDP listener and multiple session streams.

## Configuration

Use a complete TOML file with explicit values for bind address, UDP port, TLS identity/CA references and resource limits. Default port is `18743`; CLI `--port` overrides TOML. All certificate/private-key material is provisioned outside repository files and logs.

## Start and inspect

- validate configuration before binding;
- bind exactly one UDP listener;
- complete QUIC TLS 1.3 and ALPN before accepting HDQM;
- inspect only bounded status categories, connection/session counts and close reasons;
- never print Herdr payloads, prompt text, tokens, fingerprints or private keys.

## Failure handling

A session socket failure closes only that session stream. A control protocol failure closes the connection. A QUIC connection loss invalidates all session handles and requires Core to reopen sessions. No automatic replay of unknown writes is permitted.

## Verification

Run Relay locked tests, Clippy, rustfmt, rustdoc, diff checks, loopback three-session tests, TLS negative tests, Unix identity tests and Core/Relay real mb17 read-only evidence. Local tests are not deployment evidence.

## Checkpoint Log

[accepted](1-45) 2026-08-22 | QRM-1 Q3 operations checkpointed
- Repository state: operations document and Q3 Relay implementation are checkpointed in the Relay submodule.
- Validation: one-process/one-port, bounded inspection and fail-closed handling rules are recorded.
- Scope: user-level QUIC Relay operation.
- Exclusions: old discovery/class listener, arbitrary command execution, payload logging and Q4/Q5 evidence claims.
- Residual risk: deployment certificate provisioning and mb17 UDP path remain open.
- Next dependency: implement and validate Q4 before fresh review.

[active](1-56) 2026-08-22 | QRM-1 Relay Q4 operations validation active
- Repository state: Relay Q3 operations and implementation are checkpointed; Q4 test-only weak-network validation is beginning.
- Validation: one-process/one-port and bounded inspection rules remain recorded; Q4 evidence is not yet claimed.
- Scope: loss/delay/reorder, connection-loss cleanup and bounded diagnostics.
- Exclusions: Q5 deployment, payload logging, arbitrary commands and Herdr parsing.
- Residual risk: weak-network, certificate provisioning and mb17 UDP evidence remain open.
[checkpointed](1-59) 2026-08-23 | QRM-1 Relay Q4 operations validation checkpointed
- Repository state: Q4 is test-only with no Relay production source change; Core implementation/status checkpoints are `bbc39b9`/`a44ef6d`, and Relay operations documentation is selectively checkpointed.
- Validation: Core 313 tests and Relay 46 locked tests plus Clippy, rustfmt, rustdoc, fuzz and diff gates pass; Luna max review P1/P2 findings were fixed and revalidated.
- Scope: loss/delay/reorder, connection-loss cleanup, bounded diagnostics and control progress during a stalled session.
- Exclusions: Q5 deployment, payload logging, arbitrary commands, Herdr parsing, actions, subscriptions and healthy Current.
- Residual risk: P3 no-replay hardening and certificate/mb17 deployment evidence remain open.
- Next dependency: keep Q5 planned until deployment validation is separately activated.
