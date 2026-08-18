//! Herdr-dog Relay library.
//!
//! The relay is intentionally a narrow authenticated byte bridge. It does not
//! parse Herdr protocol messages or expose an arbitrary upstream API.
#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Shared error types and the crate result alias.
pub mod error;
