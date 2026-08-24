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
## Documentation Rules

- QRM plan documents must have complete Wiki.js frontmatter, one page-level H1, fixed status, explicit scope, validation/stopping sections, and exactly one tail `## Checkpoint Log`.
- Relay plan status must match the governing `herdr-dog-plan.md`; a subplan cannot activate a package by itself.
- Conflicting TCP/Broker/HDRL/HDBR/HDBD/network-class plan content must be rewritten or deleted, not retained as an alternate path.
- Keep README focused on current QRM status and navigation.

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
