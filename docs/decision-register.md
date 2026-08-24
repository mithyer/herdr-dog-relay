---
title: Herdr-dog Relay QUIC Decision Register
description: QRM-1 Relay port, TLS, ALPN, stream, resource and security decisions.
published: true
date: 2026-08-24T01:43:10+08:00
tags: herdr-dog, relay, quic, decisions, plan
editor: markdown
dateCreated: 2026-08-22T00:10:00+08:00
---

# Herdr-dog Relay QUIC Decision Register

## Current status

Status: `active` for QRM-PROD-1 P4 local cross-platform validation after P3 Core/App checkpoint at Core `ca3ab03`/`3404bac`, Relay status `76270bd`, App-iOS `a309515`/`1e2919b` and parent `d340a92`. Q4 weak-network, Q5 mb17 one-port/two-session read-only evidence, Q6 App/embedded Core integration and Q7 cleanup remain checkpointed; this register records only P4 local evidence requirements and does not widen Herdr capabilities or change the opaque bridge boundary.

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
| QRM-RLY-PROD-001 | decided | Dedicated offline Root CA; one device Intermediate CA and protected Intermediate private key; Root key never enters Relay/runtime/release | QRM-PROD-1 P2/P4 | protected-file and secret-scan tests |
| QRM-RLY-PROD-002 | decided | Enrollment ALPN is same-port `herdr-dog-relay-enroll/1`, terminal and bounded; it requires TLS 1.3 server authentication plus current Core client mTLS and Relay challenge; normal QRM ALPN keeps mandatory mTLS and active allowlist | QRM-PROD-1 P2/P4 | ALPN/origin/quota isolation and no-forward tests |
| QRM-RLY-PROD-003 | decided | Every successful App enrollment persists fingerprint/app_id/generation/validity/status and `relay_update_admin` atomically; revoke fails closed | QRM-PROD-1 P1/P2/P4 | allowlist/revocation/atomicity matrix |
| QRM-RLY-PROD-004 | decided | Remote update is stable-latest only, fixed HTTPS/checksum inputs, no arbitrary command/URL, staged atomically with rollback | QRM-PROD-1 P2/P4/P6 | checksum/update/rollback tests |
| QRM-RLY-PROD-005 | decided | macOS LaunchAgent and Linux systemd user supervision use bounded restart/backoff and preserve one process/one UDP listener; Windows deferred | QRM-PROD-1 P2/P4 | service lifecycle tests |
| QRM-RLY-PROD-006 | decided | Enrollment has separate connection/request/byte quotas and cannot consume normal QRM mTLS/session capacity; terminal attempts close before QRM/Herdr access | QRM-PROD-1 P1/P2/P4 | quota and ALPN isolation tests |
| QRM-RLY-PROD-007 | decided | Revocation is local-only in this package; protected revoke atomically bumps allowlist generation and closes matching QRM connections; no App-facing revoke method | QRM-PROD-1 P2/P4 | revocation/generation/closure tests |
| QRM-RLY-PROD-008 | decided | Stable-latest update rejects unsafe archive entries and validates staged executable before atomic replacement; no downloaded script execution | QRM-PROD-1 P2/P4 | extraction/TOCTOU/rollback tests |
| QRM-RLY-PROD-009 | decided | Enrollment pre-auth/handshake, enrollment and normal-QRM quotas are independently bounded on the shared UDP listener | QRM-PROD-1 P1/P2/P4 | quota exhaustion/isolation tests |

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

[accepted](1-132) 2026-08-23 | QRM-1 Relay Q7 legacy cleanup accepted at review gate
- Repository state: Relay cleanup and explicit generic legacy-network rejection test are uncommitted; no deployment or Herdr generated content changed.
- Validation: 46 locked Relay tests passed with Clippy warnings denied, rustfmt, rustdoc and diff checks; Core/App quality and fresh dual review found no P0-P2 across the package.
- Scope: removed the old network-class test semantics and replaced them with fail-closed unknown `[network]` table rejection while retaining generic QRM UDP, TLS/ALPN, SessionRegistry and opaque bridge behavior.
- Exclusions: no legacy fallback, protocol expansion, Herdr parsing, App-Core changes, deployment, writes, subscriptions, healthy Current, actions or passthrough.
- Residual risk: Relay PKI/service supervision, real native/device evidence and QRM overall acceptance remain open.
- Next dependency: checkpoint Core first, then Relay, App-iOS and the parent Wiki in the required order.

[checkpointed](1-140) 2026-08-23 | QRM-1 Relay Q7 legacy cleanup checkpointed
- Repository state: Relay implementation and status are committed at `a2dd9dc`; deployment artifacts, Herdr generated content and unrelated Relay work remain excluded.
- Validation: 46 locked tests passed with Clippy warnings denied, rustfmt, rustdoc and diff checks; fresh dual review found no P0-P2.
- Scope: generic QRM UDP/TLS/ALPN, SessionRegistry and opaque bridge remain active; the stale network-class test is replaced by explicit unknown-table rejection and no legacy runtime path remains.
- Exclusions: no legacy fallback, protocol expansion, Herdr parsing, App-Core changes, deployment, writes, subscriptions, healthy Current, actions or passthrough.
- Residual risk: Relay PKI/service supervision, real native/device evidence and QRM overall acceptance remain open.
- Next dependency: complete the ordered App-iOS and parent Wiki checkpoints.

[active](1-152) 2026-08-23 | QRM-PROD-1 Relay decisions activated
- Repository state: Relay decision additions are uncommitted; existing QRM-1 decisions/checkpoints and unrelated content remain preserved.
- Validation: dedicated Root/Intermediate PKI, same-port enrollment ALPN, active App allowlist/admin, stable-latest SHA update and service supervision decisions are recorded.
- Scope: Relay security/control boundary; no Herdr protocol interpretation or capability expansion.
- Exclusions: Root signing key/runtime private material, Herdr writes, subscriptions, healthy Current, actions, passthrough, automatic retry and Windows support.
- Residual risk: CSR/certificate implementation, allowlist atomicity, update rollback, LaunchAgent/systemd tests and mb17 deployment remain open.
- Next dependency: synchronize App decision/boundary documentation, then begin reviewed P1 contract/fake implementation.

[active](1-163) 2026-08-23 | QRM-PROD-1 P0 correction validation
- Repository state: Relay decision additions are uncommitted; QRM-1 decisions/checkpoints and unrelated content remain preserved; no source, secret or deployment change was made.
- Validation: separate enrollment quota, local-only revoke, allowlist generation/closure, safe archive extraction and service/update decisions are recorded.
- Scope: Relay security/control decisions only; no Herdr protocol interpretation or capability expansion.
- Exclusions: Root signing key/runtime private material, Herdr writes, subscriptions, healthy Current, actions, passthrough, automatic retry and Windows support.
- Residual risk: post-fix review, P1 fake, protected storage, updater and mb17 evidence remain open.
- Next dependency: pass the corrected scope review before P1 contract/fake implementation.

[active](1-173) 2026-08-23 | QRM-PROD-1 P0 security/structure correction
- Repository state: Relay decision additions are uncommitted; QRM-1 decisions/checkpoints and unrelated content remain preserved; no source, secret or deployment change was made.
- Validation: Core-mtls enrollment origin/challenge, separate quota, local revoke, allowlist generation/closure, safe archive extraction and service/update decisions are recorded.
- Scope: Relay security/control decisions only; no Herdr protocol interpretation or capability expansion.
- Exclusions: Root signing key/runtime private material, Herdr writes, subscriptions, healthy Current, actions, passthrough, automatic retry and Windows support.
- Residual risk: final review, P1 fake, protected storage, updater and mb17 evidence remain open.
- Next dependency: complete the final P0 review before P1.

[implemented](1-181) 2026-08-24 | QRM-PROD-1 Relay P1 contract/fake implementation completed locally
- Repository state: Relay enrollment source/tests and decision documentation are uncommitted; QRM-1 decisions/checkpoints and unrelated content remain preserved; no deployment or secret material was changed.
- Validation: Relay locked tests passed 55, Clippy with warnings denied, rustfmt, rustdoc and diff checks passed; Core 312 passed/2 ignored with fuzz-crate checks and App hosted XCTest passed 37 tests.
- Scope: Relay PKI/enrollment origin, allowlist/revocation generation, stable-latest update worker and service decisions represented by bounded deterministic contracts/fakes with redacted diagnostics.
- Exclusions: Root signing key/runtime private material, Herdr writes, subscriptions, healthy Current, actions, passthrough, automatic retry, protected production storage, issuance, updater and Windows support.
- Residual risk: fresh post-fix read-only review and selective checkpoint remain; production Relay enrollment/update behavior is not evidenced.
- Next dependency: complete the fresh P1 review/fix gate, then append validated/accepted evidence before P2.

[accepted](1-189) 2026-08-24 | QRM-PROD-1 Relay P1 contract/fake accepted
- Repository state: Relay enrollment source/tests and decision documentation remain uncommitted; QRM-1 decisions/checkpoints and unrelated content are preserved; no deployment or secret material was changed.
- Validation/review: Relay 55 passed with Clippy, rustfmt, rustdoc and diff gates; final fresh dual review found no P0-P2 findings.
- Scope: Relay PKI/enrollment origin, allowlist/revocation generation, stable-latest update worker and service decisions represented by bounded deterministic contracts/fakes with redacted diagnostics.
- Exclusions: Root signing key/runtime private material, Herdr writes, subscriptions, healthy Current, actions, passthrough, automatic retry, protected production storage, issuance, updater and Windows support.
- Residual risk: P3 fake-parity items and production Relay enrollment/update behavior remain deferred; selective Relay checkpointing is still required.
- Next dependency: selectively checkpoint Relay, then continue App-iOS/parent checkpointing before P2.

[checkpointed](1-197) 2026-08-24 | QRM-PROD-1 Relay P1 checkpointed at `e038a32`
- Repository state: Relay enrollment implementation/status scope is committed at `e038a32`; Relay worktree is clean; parent Wiki gitlink/status synchronization remains pending.
- Validation: Relay 55 passed with Clippy warnings denied, rustfmt, rustdoc and diff checks passed.
- Scope: Relay P1 PKI/enrollment origin, allowlist/revocation generation, stable-latest update worker and service decisions represented by bounded contracts/fakes.
- Exclusions: Root signing key/runtime private material, Herdr writes, subscriptions, healthy Current, actions, passthrough, automatic retry, protected production storage, issuance, updater and Windows support.
- Residual risk: P3 fake-parity items and production Relay enrollment/update behavior remain deferred; App-iOS/parent checkpoint steps are still required.
- Next dependency: checkpoint App-iOS, then parent gitlink/status in order.

[active](1-205) 2026-08-24 | QRM-PROD-1 P2 Relay deployment lifecycle is active
- Repository state: P1 Relay checkpoint `e038a32`/`86e174b`, Core `dcbc3cd`/`4ba0852`, App-iOS `8b956ab`/`5d2b1c3`, parent `40390b6`/`4490417`; P2 activation is uncommitted and no deployment change is made.
- Validation: P1 Relay 55-test quality/review/checkpoint gates passed; QRM-1 opaque Herdr bridge and fail-closed security boundaries remain preserved.
- Scope: Relay PKI/enrollment origin, allowlist/revocation generation, stable-latest updater and supervision decisions, with implementation evidence required before P3.
- Exclusions: Root signing key/runtime private material, real certificate issuance, mb17 deployment, Herdr writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P2 must preserve quota isolation, Core-origin/challenge binding, rollback and redacted authority diagnostics.
- Next dependency: complete P2 activation review/status synchronization before Relay source implementation.

[implemented](1-213) 2026-08-24 | QRM-PROD-1 P2 local Relay implementation completed
- Repository state: P1 Relay checkpoint `86e174b`, Core P1 `4ba0852`, App-iOS P1 `8b956ab`/`5d2b1c3` and parent P1 `40390b6`/`4490417` are preserved; P2 activation docs are checkpointed in Core `9066dbf`, Relay `17fe0c3`, App-iOS `d7f3ea0` and parent `8d25df1`; P2 Relay source/config/workflow/template changes are uncommitted and mb17/Herdr are untouched.
- Validation: Relay 69 tests, Clippy with warnings denied, rustfmt, rustdoc, locked checks and diff gates pass; no deployment evidence is claimed.
- Scope: Relay PKI/enrollment origin, allowlist/revocation generation, stable-latest updater and supervision decisions represented by bounded production seams.
- Exclusions: live GOAWAY/drain/restart/readiness/rebind is P6-only; no Root signing key, Herdr writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: fresh P2 review/fix/revalidation and real issuance/service/deployment evidence remain open.
- Next dependency: complete fresh P2 implementation review, apply fixes, revalidate, then selectively checkpoint Relay and parent.

[accepted](1-221) 2026-08-24 | QRM-PROD-1 P2 local Relay implementation accepted
- Repository state: P2 Relay source/docs/workflow/template changes remain uncommitted; P1 Core/Relay/App-iOS/parent checkpoints and Herdr/mb17 exclusions are preserved.
- Validation/review: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; Core wire/quality gates passed; final fresh dual review found no P0-P2 findings.
- Scope: Relay PKI/enrollment origin, allowlist/revocation generation, stable-latest updater and supervision decisions represented by bounded production seams.
- Exclusions: live P6 GOAWAY/drain/restart/readiness/rebind, Root signing key, production issuance/deployment, Herdr writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live boundary coverage and P4-P6 real issuance/service/deployment evidence remain open; selective checkpointing is required.
- Next dependency: selectively checkpoint Relay, then App-iOS and parent in order.

[checkpointed](1-229) 2026-08-24 | QRM-PROD-1 Relay P2 checkpointed at `51134bb`
- Repository state: Relay P2 implementation, docs, workflow and deployment templates are committed at `51134bb`; Relay worktree is clean; App-iOS/parent checkpoint closure remains pending.
- Validation: Relay 69 passed with locked Clippy, rustfmt, rustdoc and diff gates; Core 312/2 ignored and Core quality gates passed.
- Scope: Relay PKI/enrollment origin, allowlist/revocation generation, stable-latest updater and supervision decisions represented by bounded production seams.
- Exclusions: live P6 GOAWAY/drain/restart/readiness/rebind, Root signing key, production issuance/deployment, Herdr writes, subscriptions, healthy Current, actions, passthrough and automatic retry.
- Residual risk: P3 live boundary coverage and P4-P6 real service/deployment evidence remain open.
- Next dependency: checkpoint App-iOS, then parent status in order.

[active](1-237) 2026-08-24 | QRM-PROD-1 P3 typed Core/App integration is active
- Repository state: Relay P2 implementation/status `51134bb`/`6176552` is checkpointed; P3 changes are Core/App-owned and activation docs are uncommitted.
- Validation: Relay P2 quality/review/checkpoint gates passed; no P3 Relay source or deployment behavior is authorized.
- Scope: Relay remains the opaque protected enrollment/update boundary while Core/App own typed authorization and identity/update routing.
- Exclusions: no Relay source, live issuance/deployment, Root key, Herdr writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: P3 typed authority and P4-P6 real evidence remain open.
- Next dependency: complete P3 activation review/status synchronization before Core/App source implementation.

[implemented](1-245) 2026-08-24 | QRM-PROD-1 P3 typed Core/App implementation completed locally
- Repository state: Relay P2 checkpoint/status `51134bb`/`6176552` remains clean; P3 Core/App source is uncommitted elsewhere; Relay source is unchanged.
- Validation: Relay 69-test quality/review/checkpoint gates remain passed; Core 315/2 ignored and App hosted 45/3 skipped gates pass, including bounded DER assembly.
- Scope: Relay decision boundary remains opaque while Core/App own typed enrollment/update authorization.
- Exclusions: no P3 Relay source, live issuance/deployment, Root key, Herdr writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: App Keychain happy-path entitlement evidence remains for P4; fresh P3 review/fix/revalidation and P4-P6 live evidence remain open.
- Next dependency: complete fresh P3 implementation review, apply fixes, revalidate, then selectively checkpoint Core/App-iOS and parent.

[validated](1-253) 2026-08-24 | QRM-PROD-1 P3 typed Core/App integration validated locally after review
- Repository state: Relay P2 implementation/status remain checkpointed; only P3 Relay status documentation is uncommitted; Core/App-iOS P3 sources remain uncommitted separately.
- Validation: Relay 69-test quality/review/checkpoint gates remain passed; Core 315 passed/2 ignored and App hosted XCTest 45 executed: 42 passed/3 skipped, including bounded PKCS#10 DER assembly; associated quality gates passed.
- Scope: Relay remains opaque and unchanged while Core/App-iOS own typed enrollment and identity/update boundaries.
- Exclusions: no Relay source, live certificate issuance, deployment, Herdr writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: Keychain entitlement skips and P4-P6 live enrollment/service/deployment evidence remain open.
- Next dependency: selectively checkpoint Core, Relay status/docs, App-iOS and parent in the required order; no acceptance or deployment claim before checkpointing.

[checkpointed](1-261) 2026-08-24 | QRM-PROD-1 P3 Relay status checkpointed; no Relay source changes
- Repository state: Relay P2 implementation/status remain checkpointed at `51134bb`/`6176552`; P3 adds no Relay source, deployment or certificate behavior; this status/documentation checkpoint is the only Relay change.
- Validation: Relay 69-test quality/review/checkpoint gates remain passed; Core 315 passed/2 ignored and App hosted XCTest 45 executed: 42 passed/3 skipped; associated quality gates passed.
- Scope: Relay remains opaque and unchanged while Core/App-iOS own typed enrollment and identity/update boundaries.
- Exclusions: no Relay source, live certificate issuance, deployment, Herdr writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: Keychain entitlement skips and P4-P6 live enrollment/service/deployment evidence remain open.
- Next dependency: checkpoint App-iOS implementation/status, then append the parent Wiki checkpoint without staging Herdr or unrelated content.

[active](1-269) 2026-08-24 | QRM-PROD-1 P4 Relay local enrollment/update/service validation activated
- Repository state: Relay P3 status `76270bd` is clean and contains no P3 source changes; P4 activation is documentation-only and uncommitted; Core/App-iOS/Herdr/mb17 are unchanged.
- Herdr upstream check: `origin/master` and detached `HEAD` are `d6dae883`; tags `v0.8.2` and `v0.8.0` remain present; five generated schema helpers remain excluded; no Socket API schema or Relay byte-path impact was found.
- Validation baseline: Relay 69 quality-gate tests; P4 evidence is not yet claimed and normal QRM/enrollment boundaries remain fail closed.
- Scope: quota/ALPN isolation, allowlist/revoke generation closure, archive/update rollback and macOS/Linux service evidence.
- Exclusions: no mb17 change, live certificate issuance/deployment, Herdr writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Next dependency: capture the disposable-material and local service baseline before Relay P4 implementation/evidence work.

[active](1-277) 2026-08-24 | QRM-PROD-1 P4 Relay baseline captured
- Repository state: Relay P3 status `76270bd` is clean; P4 remains documentation-only and uncommitted; Core/App-iOS/Herdr/mb17 are unchanged.
- Baseline: mb17 macOS 15.7.7 x86_64, Herdr 0.8.2, one Relay process at UDP `100.64.0.6:18743`, default and `qrm-work` sockets mode 0600, no LaunchAgent; protected configuration hashes were recorded without reading contents.
- Validation: Relay 69 quality-gate tests remain the baseline; no remote mutation or P4 evidence is claimed and normal QRM/enrollment remains fail closed.
- Scope: local quota/ALPN isolation, allowlist/revoke closure, archive rollback and service lifecycle evidence remain next.
- Exclusions: no mb17 change, live certificate issuance/deployment, Herdr parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Next dependency: create repository-external disposable material and capture the local macOS/Linux service baseline before Relay P4 evidence work.