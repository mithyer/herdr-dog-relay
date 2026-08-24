---
title: Herdr-dog Relay Operations
description: User-level operation and verification rules for the single-port QUIC Relay.
published: true
date: 2026-08-24T11:41:11+08:00
tags: herdr-dog, relay, operations, quic, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay Operations

## Current status

Status: `active` for QRM-PROD-1 P4 local cross-platform validation. QRM-1 Q4/Q5 evidence and P2/P3 checkpoints remain preserved. P4 validates local enrollment/allowlist/revocation, updater rollback, and disposable user-service behavior; live issuance, remote update, deployment, GOAWAY/drain/restart/readiness/rebind, and P6 evidence remain separate gates.

## Configuration

Use a complete TOML file with explicit values for bind address, UDP port, TLS identity/CA references, protected Intermediate/Root paths, allowlist path, enrollment bounds, stable-latest updater bounds and resource limits. Default port is `18743`; CLI `--port` overrides TOML. Private-key, Intermediate and allowlist material is provisioned outside repository files and logs with protected owner/mode checks.

## Start and inspect

- validate protected configuration and material paths before binding;
- bind exactly one UDP listener;
- complete QUIC TLS 1.3 and normal/enrollment ALPN selection before accepting control frames;
- require active allowlist admission for normal QRM and Core-origin/challenge binding for enrollment;
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

[active](1-67) 2026-08-23 | QRM-1 Relay Q5 mb17 operations preflight active
- Repository state: Relay Q4 operations checkpoint is committed; Herdr master is `d6dae883` and generated schema helpers remain excluded.
- Validation: one-process/one-port and bounded inspection rules remain recorded; Q5 is limited to non-destructive deployment preflight before any live forwarding.
- Scope: inspect process owner, artifact/configuration hashes, UDP listener, TLS identity references, Herdr socket identity and two-session readiness.
- Exclusions: payload logging, credential disclosure/mutation, arbitrary commands, Herdr parsing, writes, subscriptions, healthy Current, actions and passthrough.
- Next dependency: complete preflight and stop on any preservation, identity or reachability failure.

[validated](1-74) 2026-08-23 | QRM-1 Relay Q5 mb17 operations validated
- Repository state: the x86_64 QRM binary, verified TLS config and external material are deployed outside the repository; the old binary/config backup and explicit rollback path are retained on mb17.
- Validation: old TCP Relay stopped, QRM UDP `100.64.0.6:18743` live, default/`qrm-work` sockets mode `0600`, Core typed protocol-20 reads and stopped-session isolation passed.
- Scope: user-level one-process/one-port operation, bounded inspection and read-only evidence.
- Exclusions: payload logging, credential disclosure/mutation, arbitrary commands, Herdr parsing, writes, subscriptions, healthy Current, actions and passthrough.
- Residual risk: no LaunchAgent, PKI rotation and final checkpoint remain open.
- Next dependency: record post-fix test outputs and checkpoint Q5 selectively.

[active](1-83) 2026-08-24 | QRM-PROD-1 P2 Relay operations implementation active
- Repository state: P1 Relay checkpoint is preserved; P2 operations/source/template changes are uncommitted and mb17 is untouched.
- Validation: 66 local Relay tests plus Clippy, rustfmt, rustdoc and diff checks pass.
- Scope: protected-file configuration, enrollment/allowlist operations, stable-latest update/replacement and LaunchAgent/systemd templates.
- Exclusions: no production material provisioning, live service installation, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: service lifecycle, updater restart/drain and real deployment preservation remain open.
- Next dependency: complete fresh P2 review/fix/revalidation before selective Relay checkpointing.

[implemented](1-91) 2026-08-24 | QRM-PROD-1 P2 Relay operations implementation completed
- Repository state: P2 Relay operations/source/template changes are uncommitted; P1 checkpoints remain preserved and mb17/Herdr are untouched.
- Validation: 69 Relay tests, Clippy, rustfmt, rustdoc, locked checks and diff checks pass locally.
- Scope: protected configuration, enrollment/allowlist operations, stable-latest replacement/revoke and user-level supervision templates.
- Exclusions: live P6 service installation/drain/restart/readiness/rebind, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: fresh P2 review/fix/revalidation and real service/deployment evidence remain open.
- Next dependency: complete fresh P2 review, apply fixes, then selectively checkpoint Relay.

[accepted](1-99) 2026-08-24 | QRM-PROD-1 P2 Relay operations local implementation accepted
- Repository state: P2 Relay operations/source/template changes remain uncommitted; P1 checkpoints and Herdr/mb17 exclusions are preserved.
- Validation/review: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final fresh dual review found no P0-P2 findings.
- Scope: protected configuration, enrollment/allowlist operations, stable-latest replacement/revoke and user-level supervision templates.
- Exclusions: live P6 service installation/drain/restart/readiness/rebind, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live lifecycle evidence and P4-P6 service/deployment preservation remain open; checkpointing is required.
- Next dependency: selectively checkpoint Relay, then synchronize parent status.

[checkpointed](1-107) 2026-08-24 | QRM-PROD-1 Relay operations checkpointed at `51134bb`
- Repository state: Relay P2 operations/source/templates are committed at `51134bb`; Relay worktree is clean; parent status closure remains pending.
- Validation: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; final review found no P0-P2 findings.
- Scope: protected configuration, enrollment/allowlist operations, stable-latest replacement/revoke and user-level supervision templates.
- Exclusions: live P6 service installation/drain/restart/readiness/rebind, production deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live lifecycle and P4-P6 service/deployment preservation remain open.
- Next dependency: synchronize parent status and gitlinks.

[active](1-115) 2026-08-24 | QRM-PROD-1 P4 local operations evidence active
- Repository state: P4 activation/baseline checkpoints are Core `413c5c0`/`1c0371e`, Relay `a244ba0`/`07b1be3`, App-iOS `e58eb3f`/`fe3c62a`, and parent `52fbe34`/`484d806`; the current Relay worktree restores tracked governance files removed by `0fc3563`.
- Validation: Relay 79 locked tests and quality gates; temporary macOS LaunchAgent bootstrap/duplicate/bootout and Ubuntu systemd-user verify/single-instance/cleanup fixtures passed; no Relay service was installed.
- Scope: local operation/template evidence and updater safety only; see `/herdr-dog/relay/docs/p4-local-validation-report`.
- Exclusions: no mb17 mutation, live issuance, deployment, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: published Linux artifact/CI provenance, restart-persistent authorization consumption, and P6 live service/rebind evidence remain open; local revoke closure is rechecked on the maintenance tick.
- Next dependency: finish P4 correction review and artifact/CI evidence; do not activate P6.

[active](1-123) 2026-08-24 | QRM-PROD-1 P4 cross-platform operations validation completed
- Repository state: Relay source, restored Relay-owned AGENTS/docs governance and operations/status edits remain uncommitted; P4 remains active; Herdr, secrets, mb17 configuration and existing service state are unchanged.
- Validation: Development macOS passed 81 Relay tests with locked quality gates. Native Ubuntu 24.04 x86_64 passed 80 Relay tests, Clippy, rustfmt, rustdoc, release build, disposable archive/checksum verification and `herdogrelay --version`; disposable macOS LaunchAgent and Ubuntu systemd-user lifecycle fixtures remain local-only.
- Scope: protected material, allowlist, updater, supervision and cross-platform operation evidence only; Linux arm64 is rejected because no supported release artifact exists.
- Exclusions: no mb17 deployment, live issuance, remote update, Herdr configuration mutation, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: published Linux artifact/CI provenance, P6 drain/restart/readiness/rebind and restart-persistent authorization evidence remain open; fresh review is still required.
- Next dependency: complete the fresh P4 review and any parent-led correction/revalidation loop before selective checkpointing.

[active](1-131) 2026-08-24 | QRM-PROD-1 P4 post-fix operations validation
- Repository state: Relay source and governance restoration remain uncommitted; P4 remains local-only and active.
- Validation: macOS 81-test and native Ubuntu x86_64 80-test batteries pass; disposable LaunchAgent/systemd fixtures and idle revoked active-bridge closure pass.
- Scope: protected material, allowlist, updater, supervision and cross-platform operation evidence only.
- Exclusions: no mb17 deployment, live issuance, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: published Linux artifact/CI provenance, restart-persistent authorization and P6 live service/rebind evidence remain open.
- Next dependency: complete final fresh review and selective checkpoint validation; do not activate P6.

[active](1-139) 2026-08-24 | QRM-PROD-1 P4 post-review remediation validation
- Review: parent fixes close the disabled-enrollment revoke, installer safety, protected-file race, rollback-verification and certificate-expiry findings.
- Validation: macOS passed 82 Relay tests and native Ubuntu x86_64 passed 81 tests, with supervision, release/archive/checksum and version checks preserved.
- Scope: protected material, expiry-aware allowlist, enrollment/revocation, updater, supervision and cross-platform operation evidence only.
- Exclusions: no mb17 deployment, live issuance, remote update, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: published Linux CI/artifact provenance, restart-persistent authorization and P6 live service/rebind evidence remain open.
- Next dependency: complete the replacement fresh review and selective checkpoint validation; do not activate P6.
