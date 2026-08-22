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

Status: `accepted` for QRM-1 Q3; Q4/Q5 external security evidence remains planned. There is one generic UDP listener policy; network class is not a protocol concept.

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
- Next dependency: keep Q4/Q5 security validation planned.
