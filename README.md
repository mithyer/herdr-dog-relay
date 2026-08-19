# Herdr-dog Relay

Status: Rust implementation in progress. The R1 configuration contract and R2 local Unix socket bridge are implemented and locally verified; the relay must remain fail-closed and must not claim production deployment or Herdr integration until the documented verification gates pass.

Herdr-dog Relay is a planned user-level macOS service that exposes a controlled, authenticated network endpoint for a mobile Core and forwards the resulting byte stream to one Herdr Unix socket on the same host.

The relay is not Herdr-dog Core. It does not interpret the Herdr protocol, manage snapshots or subscriptions, decide action permissions, or expose arbitrary upstream methods. Those responsibilities remain inside the Core running with the mobile App.

## Design Summary

- Host: the macOS machine that runs Herdr, such as `mb17`.
- Downstream: one configured Herdr Unix socket, for example `/Users/<user>/.config/herdr/herdr.sock`.
- Upstream: an authenticated TCP/TLS connection from the mobile App's embedded Core.
- Network classes: `tailscale`, `lan`, and `public`.
- Default policy: `tailscale` enabled; `lan` and `public` disabled.
- App-facing setup: the user provides only the relay IP/address; v1 fixes the shared port contract to `18743..18752` (base `18743`, ten attempts), the Relay selects the first available candidate, and the App/Core probes the same range until an authenticated Relay handshake succeeds. Discovery may repeat that fixed sweep no more than three times with bounded backoff.
- Security posture: explicit listener binding, source allowlists, authenticated clients, bounded resources, no payload logging, and fail-closed policy handling.
- Initial deployment: a least-privileged user-level macOS LaunchAgent after the design and implementation gates are approved.

## Documentation

- [Architecture](docs/architecture.md): components, stream ownership, lifecycle, and failure boundaries.
- [Security and Network Policy](docs/security-and-network-policy.md): the three network classes, defaults, admission rules, authentication, and threat model.
- [Implementation Plan](docs/implementation-plan.md): dependency-ordered milestones and acceptance gates.
- [Decision Register](docs/decision-register.md): recorded decisions, owners, evidence, and unresolved questions.
- [Operations](docs/operations.md): planned deployment, diagnostics, rollback, and verification procedures.
- [Port Selection and Discovery](docs/port-selection-and-discovery.md): bounded ten-port selection, authenticated probing, and failure semantics.

## Current Implementation

The current Rust scope includes:

- fail-closed v1 configuration parsing and redacted validation errors;
- Unix socket type, owner, private-permission, parent-directory, and identity checks;
- bounded protocol-agnostic bidirectional forwarding with half-close propagation and whole-stream idle timeout;
- no Herdr payload parsing, logging, persistence, or automatic write retry.

This is local library evidence only. It does not establish a real network listener, TLS/mTLS handshake, deployment, or end-to-end Herdr integration.
## Current Non-Goals

This checkpoint does not include:

- a launchd plist;
- a TCP listener;
- TLS certificate generation or provisioning;
- Tailscale configuration changes;
- Herdr protocol parsing;
- App or Core changes;
- public-network exposure.

Rust implementation is authorized under the recorded decisions. Deployment, LAN/public enablement, and production claims remain gated by the linked verification requirements.
