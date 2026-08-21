//! Herdr-dog Relay library.
//!
//! The relay is intentionally a narrow authenticated byte bridge. It does not
//! parse Herdr protocol messages or expose an arbitrary upstream API.
#![deny(unsafe_code)]
#![warn(missing_docs)]

// The relay depends on Unix-domain sockets and is intentionally constrained to Unix hosts.
#[cfg(not(unix))]
compile_error!("herdr-dog-relay currently supports Unix hosts only");

/// Bounded, protocol-agnostic bidirectional byte forwarding.
pub mod bridge;
/// Schema-neutral Broker Control framing and session-bound data-binding gate.
pub mod broker;
/// Strongly typed configuration and v1 policy constants.
pub mod config;
/// Shared error types and the crate result alias.
pub mod error;
/// Fixed binary challenge handshake used after TLS authentication.
pub mod handshake;
/// Authenticated Tailscale listener and bounded client admission.
pub mod listener;
/// User-level RSB-2 Manager, session resolver, fingerprint, lease, and child lifecycle contracts.
pub mod manager;
/// Validated Unix-domain socket access for the configured Herdr endpoint.
pub mod socket;

mod tls;
