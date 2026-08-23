---
title: Herdr-dog Relay Security and Network Policy
description: Uniform QUIC TLS 1.3 identity and bounded session security policy.
published: true
date: 2026-08-22T00:10:00+08:00
tags: herdr-dog, relay, security, quic, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay Security and Network Policy

## Current status

Status: `active` for QRM-1; Q4 weak-network validation is checkpointed and Q5 external security evidence remains planned. There is one generic UDP listener policy; network class is not a protocol concept.

## Required security

- QUIC TLS 1.3 is always enabled;
- production validates Relay server certificate, Core client certificate and trusted CA;
- development may use an explicitly test-only unverified mode, never plaintext;
- ALPN `herdr-dog-relay-quic/1` is mandatory;
- listener address and UDP port are explicit; default port is `18743`;
- connection/session/control-frame/buffer/timeout limits are bounded;
- Unix socket owner, mode, type, parent and replacement identity are checked;
- HDQS authority must be accepted before any Herdr byte;
- tokens, fingerprints, certificates, private keys and payloads are not logged or persisted in repository artifacts;
- malformed control protocol closes the physical connection; session authority failure closes only the session stream.

## Validation

QRM tests must cover wrong certificate, missing client identity, wrong ALPN, malformed HDQM/HDQS, stale generation/token/fingerprint, socket replacement, stream isolation and bounded cleanup.

## Checkpoint Log

[accepted](1-42) 2026-08-22 | QRM-1 Q3 security policy checkpointed
- Repository state: security policy and Q3 Relay implementation are checkpointed in the Relay submodule.
- Validation: TLS, identity, authority and redaction boundaries are frozen and tested.
- Scope: one generic QUIC listener and multiple isolated streams.
- Exclusions: plaintext, network classes, arbitrary commands, Herdr parsing and Q4/Q5 evidence claims.
- Residual risk: certificate provisioning and production evidence remain open.
- Next dependency: implement and validate Q4 before fresh review.

[active](1-53) 2026-08-22 | QRM-1 Relay Q4 security validation active
- Repository state: security policy and Q3 implementation are checkpointed; Q4 test-only network disturbance validation is beginning.
- Validation: TLS, identity, authority and redaction gates remain recorded; Q4 evidence is not yet claimed.
- Scope: packet disturbance, bounded queues, stream isolation and reconnect authority invalidation.
- Exclusions: plaintext, network classes, arbitrary commands, Herdr parsing and Q5 deployment.
- Residual risk: certificate provisioning and weak-network evidence remain open.
[checkpointed](1-61) 2026-08-23 | QRM-1 Relay Q4 security validation checkpointed
- Repository state: security policy and Q3 implementation are checkpointed; Q4 has no Relay production source change, Core implementation/status checkpoints are `bbc39b9`/`a44ef6d`, and this policy record is selective.
- Validation: Core/Relay TLS, identity, authority, redaction and weak-network quality gates pass; Luna max review P1/P2 findings were closed and revalidated.
- Scope: packet disturbance, bounded queues, stream isolation, reconnect authority invalidation and fail-closed cleanup.
- Exclusions: plaintext, network classes, arbitrary commands, Herdr parsing and Q5 deployment.
- Residual risk: P3 no-replay hardening, certificate provisioning and mb17 evidence remain open.
- Next dependency: keep Q5 external security evidence planned.
