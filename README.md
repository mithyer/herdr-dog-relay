# Herdr-dog Relay

Status: Rust implementation in progress. The R1 configuration contract, R2 local Unix socket bridge, and R3 authenticated Tailscale listener library are implemented and locally verified; the external Tailnet/Core/Herdr gate remains open, so the relay must remain fail-closed and must not claim production deployment or end-to-end integration.

Herdr-dog Relay is a planned user-level macOS service that exposes a controlled, authenticated network endpoint for a mobile Core and forwards the resulting byte stream to one Herdr Unix socket on the same host.

The relay is not Herdr-dog Core. It does not interpret the Herdr protocol, manage snapshots or subscriptions, decide action permissions, or expose arbitrary upstream methods. Those responsibilities remain inside the Core running with the mobile App.

## Design Summary

- Host: the macOS machine that runs Herdr, such as `mb17`.
- Downstream: one configured Herdr Unix socket. The default TOML uses `herdr_socket = "auto"`, which follows Herdr's macOS/Linux config resolution (`$XDG_CONFIG_HOME/herdr/herdr.sock` or `$HOME/.config/herdr/herdr.sock`); named sessions use `sessions/<name>/herdr.sock`, and a debug Herdr build uses `herdr-dev`. An absolute path can pin a deployment.
- Upstream: a configured transport from the mobile App's embedded Core; Tailscale uses encrypted Tailnet transport by default, while LAN/public use TLS 1.3 by default.
- Network classes: `tailscale`, `lan`, and `public`.
- Configuration template: [`config/default.toml`](config/default.toml) contains every TOML parameter with a safe default and an adjacent comment; Tailscale defaults to TLS off, while LAN/public default to TLS on.
- App-facing setup: the user provides only the relay IP/address; v1 fixes the shared port contract to `18743..18752` (base `18743`, ten attempts), the Relay selects the first available candidate, and the App/Core probes the same range until an authenticated Relay handshake succeeds. Discovery may repeat that fixed sweep no more than three times with bounded backoff.
- Security posture: explicit listener binding, source allowlists, class-specific transport authentication, bounded resources, no payload logging, and fail-closed policy handling.
- Initial deployment: a least-privileged user-level macOS LaunchAgent after the design and implementation gates are approved.

## Documentation

Relay design, security, implementation-plan, decision, operations, and port-discovery documents are maintained by the parent Wiki under `/herdr-dog/relay/docs/`. They are intentionally excluded from this submodule's GitHub tree so the relay repository remains focused on source and release artifacts.

## Current Implementation

The current Rust scope includes:

- fail-closed v1 configuration parsing with a complete commented TOML template and redacted validation errors;
- deterministic first-available selection across ports `18743..18752`;
- one explicit Tailscale listener with source allowlist admission;
- TLS 1.3 mutual client authentication for TLS-enabled listeners, with the fixed Relay handshake and source policy also mandatory for the default Tailscale path;
- fixed `HDRL` challenge/nonce/acknowledgement handshake before Unix-socket access;
- global, per-listener, and in-progress-handshake quotas with bounded deadlines;
- Unix socket type, owner, private-permission, parent-directory, and identity checks;
- bounded protocol-agnostic bidirectional forwarding with half-close propagation and whole-stream idle timeout;
- a `herdogrelay` command-line host that loads validated TOML, handles SIGINT/SIGTERM shutdown, and reports only bounded listener counters;
- a checksum-verified macOS release installer at [`install.sh`](install.sh) and a tag-triggered GitHub release workflow;
- no Herdr payload parsing, logging, persistence, or automatic write retry.

The installer downloads only a versioned macOS release archive into the user's `~/.local/bin` by default. It does not create or overwrite relay configuration, certificates, private keys, or credentials.

## Current Non-Goals

This checkpoint does not include:

- a macOS LaunchAgent deployment artifact;
- TLS certificate generation or provisioning;
- Tailscale configuration changes;
- Herdr protocol parsing;
- App or Core changes;
- public-network exposure.

This checkpoint includes the command-line host and release packaging, but it does not establish a real Tailscale path, iPhone/Core-to-Relay connection, deployment, or end-to-end Herdr integration.

Rust implementation is authorized under the recorded decisions. Deployment, LAN/public enablement, and production claims remain gated by the linked verification requirements.
