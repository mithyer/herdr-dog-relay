# Herdr-dog Relay

Status: RSB-3 Core/Relay local Broker integration is accepted after 333 Core tests (2 ignored), 104 Relay tests, all quality gates and fresh read-only review. Selective Core/Relay checkpoint is pending. The implementation adds a bounded Manager control listener, multi-lease authority, HDBD validation and local data bridge; App/iOS changes, mb17 deployment, subscriptions, healthy `Online + Current`, actions and arbitrary passthrough remain excluded.

Herdr-dog Relay is a planned user-level macOS service that exposes a controlled, authenticated network endpoint for the Core process and forwards the resulting byte stream to one Herdr Unix socket on the same host.

The relay is not Herdr-dog Core. It does not interpret the Herdr protocol, manage snapshots or subscriptions, decide action permissions, or expose arbitrary upstream methods. Those responsibilities remain inside the Core running with the mobile App.

## Design Summary

- Host: the macOS machine that runs Herdr, such as `mb17`.
- Downstream: one configured Herdr Unix socket. The default TOML uses `herdr_socket = "auto"`, which follows Herdr's macOS/Linux config resolution (`$XDG_CONFIG_HOME/herdr/herdr.sock` or `$HOME/.config/herdr/herdr.sock`); named sessions use `sessions/<name>/herdr.sock`, and a debug Herdr build uses `herdr-dev`. An absolute path can pin a deployment.
- Upstream: a configured transport from Core; the mobile App passes non-secret relay configuration parameters to Core through App-Core and does not connect to Relay directly; Tailscale uses encrypted Tailnet transport by default, while LAN/public use TLS 1.3 by default.
- Network classes: `tailscale`, `lan`, and `public`.
- Configuration template: [`config/default.toml`](config/default.toml) contains every TOML parameter with a safe default and an adjacent comment; Tailscale defaults to TLS off, while LAN/public default to TLS on.
- App-facing setup: the user provides only the relay IP/address to the App, which passes it to Core; Core owns the `RelayEndpoint`, selects the first available candidate, and probes `18743..18752` until an authenticated Relay handshake succeeds. Discovery may repeat that fixed sweep no more than three times with bounded backoff; the App never probes or connects to Relay.
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
- a schema-neutral Manager control listener for bounded HDBR discovery/ensure/heartbeat/release/status;
- Manager-owned multi-lease authority updates and HDBD session binding before the existing byte bridge;
- local data-port teardown/reuse tied to Manager lease expiry and idle-grace reap;
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

This checkpoint includes the command-line host, release packaging, the RSB-2 local Manager/relay-child contract/fake implementation, and the active RSB-3 local Broker control/data-binding implementation. It does not establish mb17 deployment, LaunchAgent installation, Tailscale/Core-to-Relay production integration, or end-to-end Herdr integration; those remain later gates.

Rust implementation is authorized under the recorded decisions. Broker listeners, deployment, LAN/public enablement, and production claims remain gated by the linked verification requirements.
