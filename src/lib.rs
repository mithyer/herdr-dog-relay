//! Herdr-dog Relay library.
//!
//! The relay is intentionally a narrow authenticated byte bridge. It does not
//! parse Herdr protocol messages or expose an arbitrary upstream API.
#![deny(unsafe_code)]
#![warn(missing_docs)]

// The relay depends on Unix-domain sockets and is intentionally constrained to Unix hosts.
#[cfg(not(unix))]
compile_error!("herdr-dog-relay currently supports Unix hosts only");

/// Strongly typed configuration and v1 policy constants.
pub mod config;
/// Shared error types and the crate result alias.
pub mod error;
