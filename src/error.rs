//! Redacted error categories for the QRM-1 Relay boundary.

use std::io;

/// Result type returned by Relay operations.
pub type RelayResult<T> = Result<T, RelayError>;

/// Stable, redacted Relay errors.
#[non_exhaustive]
#[derive(Clone, Debug, thiserror::Error)]
pub enum RelayError {
    /// A configuration field failed validation.
    #[error("invalid configuration for {field}: {reason}")]
    InvalidConfiguration {
        /// Stable configuration field name.
        field: &'static str,
        /// Non-secret validation reason.
        reason: &'static str,
    },
    /// Configuration file could not be read.
    #[error("configuration could not be read")]
    ConfigurationRead,
    /// Configuration syntax was invalid.
    #[error("configuration syntax is invalid")]
    ConfigurationSyntax,
    /// A bounded I/O operation failed.
    #[error("I/O operation failed: {operation} ({kind:?})")]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Sanitized operating-system error kind.
        kind: io::ErrorKind,
    },
    /// Unix socket identity validation failed.
    #[error("Unix socket identity check failed: {operation} ({reason})")]
    SocketIdentity {
        /// Stable validation operation.
        operation: &'static str,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// A listener could not start under its bounded policy.
    #[error("relay listener startup failed: {reason}")]
    ListenerStartup {
        /// Stable startup reason.
        reason: &'static str,
    },
    /// A TLS certificate, key or trust configuration failed.
    #[error("TLS configuration failed: {reason}")]
    TlsConfiguration {
        /// Stable non-secret TLS failure reason.
        reason: &'static str,
    },
    /// A QUIC/TLS/HDQM handshake failed.
    #[error("QUIC handshake failed: {reason}")]
    QuicHandshake {
        /// Stable handshake reason.
        reason: &'static str,
    },
    /// A peer failed certificate or client identity validation.
    #[error("QUIC peer authentication failed")]
    QuicAuthentication,
    /// A bounded QRM frame failed protocol validation.
    #[error("QRM protocol error: {reason}")]
    QuicProtocol {
        /// Stable protocol reason.
        reason: &'static str,
    },
    /// A session authority did not match the current connection.
    #[error("session authority was rejected")]
    SessionAuthority,
    /// A configured Herdr Unix socket was unavailable.
    #[error("Herdr Unix socket is unavailable")]
    UpstreamUnavailable,
    /// The bridge reached its bounded idle timeout.
    #[error("byte bridge idle timeout")]
    BridgeIdleTimeout,
    /// The connection/session quota was exhausted.
    #[error("relay resource limit reached")]
    ResourceLimit,
}

impl RelayError {
    /// Builds a redacted I/O error without retaining free-form OS text.
    ///
    /// # Parameters
    /// * `operation` - Stable non-secret operation label.
    /// * `source` - Operating-system error to classify.
    ///
    /// # Returns
    /// A sanitized I/O error.
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            operation,
            kind: source.kind(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RelayError;
    use std::{error::Error, io};

    // TEST:relay/src/error.rs[tests::io_errors_are_redacted]
    #[test]
    fn io_errors_are_redacted() {
        let error = RelayError::io("opening QUIC identity", io::Error::other("private key"));
        assert!(!error.to_string().contains("private key"));
        assert!(!format!("{error:?}").contains("private key"));
        assert!(error.source().is_none());
    }
}
