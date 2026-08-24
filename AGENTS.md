# Agent Instructions

## Project Status

`herdogrelay` is being rebuilt under QRM-1 as a single-device, single-UDP-port, single-QUIC-connection Relay. The active implementation must use QUIC TLS 1.3, ALPN `herdr-dog-relay-quic/1`, one control stream, and one isolated bidirectional stream per Herdr session.

The Relay is a narrow byte bridge. It must never run Core, interpret App-Core messages, parse Herdr protocol, expose arbitrary commands, or log/persist Herdr payloads and credentials.

## Language Policy

All Relay-owned documentation, source code, tests, comments, identifiers, configuration examples, and commit messages must be written in English.

Use concise English Conventional Commit messages when a commit is requested, for example:

```text
feat(relay): add quic session streams
```

## QRM Architecture Boundary

- One `herdogrelay` process serves one remote Herdr device.
- One UDP listener is used, with default port `18743`; CLI `--port` overrides TOML.
- No port range, discovery sweep, random fallback, network-class listener, per-session data port, or per-session child process exists in the active implementation.
- QUIC TLS 1.3 is mandatory. Production requires server certificate verification and Core client certificate authentication. Development may explicitly relax trust verification only through a test-only configuration, never encryption or certificate/key exchange.
- ALPN is `herdr-dog-relay-quic/1`.
- One QUIC connection has one HDQM control stream and one bidirectional HDQS stream per approved Herdr session.
- Relay validates session name, fingerprint, token, Relay process generation, connection epoch, configuration generation, Unix socket owner/mode/type/parent and replacement identity before forwarding any Herdr bytes.
- A session failure closes only its stream. A malformed connection-level control frame closes the physical connection.
- Core owns Herdr protocol interpretation, Target/Profile state, freshness, pairing, actions and no-auto-retry semantics.
- App never connects to Relay and never receives QUIC, HDQM, HDQS, token, socket-path or raw Herdr data.

## Configuration

The complete QRM TOML template is `config/default.toml`. Every option must be explicit, documented and validated before binding:

```toml
[listener]
listen_address = "127.0.0.1"
port = 18743

[security]
mode = "verified"
server_certificate = ""
server_private_key = ""
trusted_client_ca = ""

[limits]
max_connections = 64
max_sessions_per_connection = 64
max_control_frame_bytes = 65536
buffer_bytes = 65536
handshake_timeout_secs = 5
idle_timeout_secs = 900
```

Certificate and private-key values are absolute paths or platform-provided references outside the repository. They must not appear in argv, environment, logs, fixtures or App input. `mode=development_unverified` is test-only and still uses TLS 1.3.

## Security Requirements

- Bind only the configured UDP address and port.
- Require QUIC TLS 1.3 and the fixed ALPN before HDQM.
- Require mutual TLS and trusted identity in production.
- Bound connections, sessions, control frames, buffers, handshake timeouts and idle timeouts.
- Reject malformed HDQM/HDQS before allocation or Unix socket access.
- Use fixed reason codes, never free-form payloads, in HDQS rejection responses.
- Keep session tokens and fingerprints in memory or protected platform storage only; never log or persist active tokens.
- Validate Unix socket identity before each session connection and close on replacement.
- Never parse, transform, cache, retry or log Herdr bytes.
- Never add a plaintext, TCP, WebSocket or arbitrary passthrough fallback.

## Documentation Rules

- QRM plan documents must have complete Wiki.js frontmatter, one page-level H1, fixed status, explicit scope, validation/stopping sections, and exactly one tail `## Checkpoint Log`.
- Relay plan status must match the governing `herdr-dog-plan.md`; a subplan cannot activate a package by itself.
- Conflicting TCP/Broker/HDRL/HDBR/HDBD/network-class plan content must be rewritten or deleted, not retained as an alternate path.
- Keep README focused on current QRM status and navigation.
- `AGENTS.md` and `docs/` must be Relay-owned, versioned governance sources. Do not ignore, delete, or manage them only from the parent Wiki.

## Verification Rules

Before a QRM checkpoint:

```sh
cargo test --manifest-path relay/Cargo.toml --locked --all-targets --all-features
cargo clippy --manifest-path relay/Cargo.toml --locked --all-targets --all-features -- -D warnings
cargo fmt --manifest-path relay/Cargo.toml --all -- --check
git diff --check
```

Also run the required loopback QUIC tests, TLS/mTLS/ALPN negative tests, three-session isolation tests, Unix socket identity tests, redaction checks and the separately gated real mb17 read-only evidence. Local tests must not be described as deployment, Herdr liveness, healthy Current or action evidence.

One parent assistant is the only writer. Read-only subagents may review but must not edit the Relay worktree. Do not commit, push, tag, deploy or delete unrelated dirty/untracked files without explicit user authorization.
