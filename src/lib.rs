//! Herdr-dog Relay library for QRM-1.
//!
//! The Relay is a narrow QUIC TLS 1.3 session-stream bridge. It never parses Herdr protocol or
//! exposes arbitrary upstream commands.
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(not(unix))]
compile_error!("herdr-dog-relay currently supports Unix hosts only");

/// Bounded opaque bidirectional byte forwarding.
pub mod bridge;
/// QRM-1 single-listener configuration.
pub mod config;
/// Redacted Relay errors.
pub mod error;
/// QRM-1 bounded QUIC server owner and connection lifecycle.
pub mod quic_server;
/// QRM-1 HDQM/HDQS codec.
pub mod quic_wire;
/// QRM-1 per-connection session authority registry.
pub mod session_registry;
/// Validated Herdr Unix socket access.
pub mod socket;
