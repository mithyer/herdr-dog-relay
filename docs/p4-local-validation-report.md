---
title: QRM-PROD-1 P4 Local Validation Evidence
description: Local-only evidence for Relay enrollment, updater, supervision, and typed App identity boundaries.
published: true
date: 2026-08-24T11:41:11+08:00
tags: herdr-dog, relay, qrm, validation, p4
editor: markdown
dateCreated: 2026-08-24T11:20:00+08:00
---

# QRM-PROD-1 P4 Local Validation Evidence

## Status

This report records a bounded local-only P4 validation batch checkpointed in Relay at `074d84d`. `QRM-PROD-1/P4` is checkpointed; P6 remains planned and inactive. It is not deployment evidence and does not enable Herdr writes, subscriptions, healthy `Online + Current`, actions, passthrough, automatic retries, or any D-gate closure.

## Scope

The batch validates:

- verified Relay enrollment boundaries, two independently enrolled Apps, revocation isolation, idle revoked-connection and active-bridge closure, normal-QRM mTLS rejection, independent enrollment quotas, and enrollment-ALPN no-forward behavior;
- updater archive validation, checksum failure, partial archive rejection, startup preflight, staged-source-swap rollback, and fixed release-selector/archive-shape contracts;
- disposable macOS LaunchAgent and Ubuntu systemd user-manager behavior without installing Relay, material, or configuration; and
- typed Core/App baseline checks plus an ad-hoc-entitled iOS simulator test run for the Keychain identity cases.

## Evidence

| Area | Environment | Result | Boundary |
| --- | --- | --- | --- |
| Relay Rust | Development Mac | `cargo test --locked --all-targets --all-features`: 82 total (79 library, 3 binary) passed; Clippy, rustfmt, rustdoc, shell syntax and diff checks passed. | Local source/test evidence only. |
| Relay Rust | `mb17u` Ubuntu 24.04 x86_64 | 81 total (78 library, 3 binary) passed; Clippy, rustfmt, rustdoc, release build, archive shape, SHA-256 verification, and `herdogrelay --version` passed using the existing user toolchain. | Native Linux x86_64 validation only; no Relay service or Herdr state was changed. |
| Core Rust | Development Mac | 315 passed, 2 ignored; Clippy, rustfmt, rustdoc, and fuzz checks passed. | Existing Core baseline, no P4 Core source change. |
| Core FFI | Development Mac | 4 passed; iOS device/simulator target checks passed. | No raw enrollment or Relay material leaves CoreBridge. |
| App Keychain | iPhone 17 Pro simulator | Temporary ad-hoc Keychain access-group entitlement produced 45 executed tests, 0 failures, 0 skips. Temporary entitlement and DerivedData were removed afterward. | Simulator Keychain evidence only; no persistent entitlement file, production signing, Secure Enclave, or real-device claim. |
| macOS supervision | Development Mac user domain | A disposable `launchctl` plist passed `plutil`, bootstrap, duplicate-label rejection, and bootout; the temporary directory was removed. | Used `/bin/sleep` only as a temporary fixture; no Relay, certificate, Herdr socket, or persistent LaunchAgent. |
| Linux supervision | `mb17u` Ubuntu 24.04 user manager | A disposable `/tmp` systemd unit and a substituted harmless-binary copy of the shipped unit passed `systemd-analyze verify`; a transient unit started as one instance, rejected a duplicate unit name, stopped, and was removed. | Used `/usr/bin/true` or `/bin/sleep` only as temporary fixtures; no Relay install, user config, Herdr, or mb17 state changed. |
| Release matrix | Development Mac | Disposable macOS arm64/x86_64 and Linux x86_64 archive names, checksums, and archive shapes are tested; Linux arm64 is rejected before download because no matching release artifact exists. | Does not prove a published GitHub artifact or Linux release binary. |

## Command Evidence

- The disposable macOS fixture used a unique `gui/$UID` label, `/usr/bin/plutil -lint`, `launchctl bootstrap`, a duplicate-bootstrap rejection check, and `launchctl bootout`; all temporary files were mode `0700`/`0600` and were removed.
- The disposable Ubuntu fixture used `systemd-analyze verify`, `systemd-run --user` with a unique transient unit, an active-state check, a duplicate-unit rejection check, `systemctl --user stop`, and cleanup. A copy of the shipped Linux unit was syntax-checked after substituting only `/usr/bin/true` for its unavailable fixture executable.
- The native Ubuntu Relay run used a temporary source/target/package directory, passed the complete locked test/Clippy/rustfmt/rustdoc battery, built `herdogrelay` for x86_64, created a disposable archive and same-run checksum manifest, verified the checksum and `--version`, then removed the temporary tree.
- The entitled simulator run passed its entitlement only through temporary Xcode build settings. No entitlement, key, certificate, DerivedData, or log was retained in the repository.
- The verified two-App regression creates an accepted HDQS/Unix bridge for App A, revokes App A while the bridge is idle, observes the bridge close without a heartbeat, and confirms App B remains usable; the Unix upstream fixture is held open so the bridge cannot finish from a prior EOF.

## Constraints And Residual Risks

- The local macOS host has no Linux C sysroot for `ring`, so local cross-compilation remains unavailable; the disposable native Ubuntu x86_64 run now supplies host-native Linux quality and archive evidence. The release workflow defines an Ubuntu build job, but no CI or published artifact was triggered by this batch.
- Linux arm64 is intentionally rejected because the current release workflow and installer provide no Linux arm64 artifact; this is a fail-closed support boundary, not missing validation.
- The updater test proves local pre-replacement startup failure and source-swap rollback behavior. Live GOAWAY, drain, supervisor restart, readiness, generation/epoch invalidation, and Core rebind remain P6 evidence.
- Local revocation is rechecked by the Relay maintenance tick; an idle matching verified connection and its active session bridges are closed without requiring a heartbeat or other control frame. Restart-persistent enrollment-authorization consumption remains a separate later-stage risk.
- Enrollment authorization consumption is in-memory, so an unexpired authorization needs a later persistence/restart-boundary decision before it can be represented as restart-replay proof.
- The same-origin GitHub archive and `checksums.txt` model is not an independent artifact-signature scheme.

## Checkpoint Log

[validated](1-60) 2026-08-24 | P4 bounded local evidence captured
- Repository state: Relay evidence/report and source/test changes are uncommitted; P4 remains active; Core/App-iOS/parent P4 baseline commits are preserved; Herdr is unchanged and excluded.
- Validation: Relay 77 tests and quality gates, Core 315 passed/2 ignored, core-ffi 4 passed, entitled simulator 45/0/0, disposable LaunchAgent, and disposable Ubuntu systemd-user lifecycle evidence are recorded above.
- Scope: local-only enrollment, updater, supervision, and typed App identity evidence.
- Exclusions: no deployment, live certificate issuance, remote update, Herdr configuration mutation, writes, subscriptions, healthy Current, actions, passthrough, or automatic retry.
- Residual risk: Linux published-artifact/CI provenance, P5 review, and P6 live lifecycle/rebind evidence remain open.
- Next dependency: finish P4 evidence review and resolve the artifact/CI boundary before P4 closure.

[validated](1-72) 2026-08-24 | P4 cross-platform correction validation completed
- Repository state: Relay source, restored Relay-owned governance files, evidence report and status edits remain uncommitted; P4 remains active; Herdr, secrets, mb17 configuration and existing service state are unchanged.
- Validation: Development macOS passed 81 Relay tests (78 library plus 3 binary) with locked tests, Clippy, rustfmt, rustdoc and diff checks. Native Ubuntu 24.04 x86_64 passed 80 tests (77 library plus 3 binary), Clippy, rustfmt, rustdoc, release build, disposable archive/checksum verification and `herdogrelay --version`. The Linux socket fixtures use owner-only parents and pass replacement-identity tests; the allowlist sidecar lock has explicit unlock cleanup.
- Scope: local protected-material, allowlist, enrollment, updater, supervision, governance restoration and cross-platform fixture evidence only.
- Exclusions: no mb17 deployment, live certificate issuance, remote update, Herdr configuration mutation, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: no published Linux artifact/CI provenance, no P6 GOAWAY/drain/restart/readiness/rebind evidence, and in-memory authorization replay after restart remain open; fresh P4 review is still required.
- Next dependency: inspect the fresh P4 review, apply only parent-led P0-P2 corrections if any, then rerun the complete validation battery before selective checkpointing.

[active](1-81) 2026-08-24 | QRM-PROD-1 P4 post-review remediation validation
- Repository state: parent-led Relay source, installer, Cargo metadata, restored Relay-owned governance files and evidence updates remain uncommitted; P4 remains active and unrelated Core/App-iOS/parent/Herdr content remains preserved.
- Review: fresh read-only Relay review found P1 blockers in disabled-enrollment revocation and installer safety plus P2 path-race, rollback-verification and certificate-expiry enforcement gaps; all reviewed P1/P2 corrections were applied directly by the parent.
- Validation: Development macOS passed 82 Relay tests (79 library plus 3 binary), Clippy, rustfmt, rustdoc, shell syntax and diff checks. Native Ubuntu 24.04 x86_64 passed 81 tests (78 library plus 3 binary), Clippy, rustfmt, rustdoc, release build, disposable archive/checksum verification and `herdogrelay --version`. The verified two-App regression creates an accepted HDQS/Unix bridge for App A, revokes App A while idle, observes bridge closure without heartbeat, and confirms App B remains usable.
- Scope: local protected-material race hardening, expiry-aware allowlist admission, enrollment/revocation, updater native-header/startup/rollback safety, supervision, governance restoration and cross-platform fixture evidence only. Linux arm64 is explicitly rejected because no supported release artifact exists.
- Exclusions: no mb17 deployment, live certificate issuance, remote update, Herdr configuration mutation, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: same-source checksum provenance, published Linux artifact/CI provenance, restart-persistent authorization, and P6 GOAWAY/drain/restart/readiness/rebind evidence remain open; no P6 or production claim is made.
- Next dependency: keep P6 planned and inactive until separate deployment authorization; do not claim live issuance, mb17 deployment or P6 lifecycle evidence.

[checkpointed](1-90) 2026-08-24 | QRM-PROD-1 P4 local validation checkpointed
- Repository state: Relay implementation and restored governance sources are checkpointed at `074d84d`; no push; unrelated parent/Core/App-iOS/Herdr content remains preserved.
- Review: fresh GLM-5.3 security review found no P0-P3 issues; governance review's table-shape P3 was corrected and the narrow GLM-5.3 re-review found no P0-P3 issues.
- Validation: macOS passed 82 Relay tests (79 library plus 3 binary) and native Ubuntu 24.04 x86_64 passed 81 (78 library plus 3 binary), with locked quality, rustdoc, release/archive/checksum, supervision and version checks.
- Scope: local protected material, enrollment/allowlist, updater, supervision, governance restoration and cross-platform evidence only.
- Exclusions: no mb17 deployment, live issuance, remote update, Herdr mutation/parsing, writes, subscriptions, healthy Current, actions, passthrough or automatic retry.
- Residual risk: same-source checksum provenance, published Linux CI/artifact provenance, restart-persistent authorization and P6 lifecycle/rebind evidence remain open.
- Next dependency: keep P6 planned and inactive until separate deployment authorization; do not claim live issuance, mb17 deployment or P6 lifecycle evidence.
