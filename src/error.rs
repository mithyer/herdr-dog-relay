//! Error types used at the relay's public boundaries.

use std::io;

/// The result type returned by relay operations.
pub type RelayResult<T> = Result<T, RelayError>;

/// Redacted, bounded error categories exposed by the relay.
#[non_exhaustive]
#[derive(Clone, Debug, thiserror::Error)]
pub enum RelayError {
    /// A configuration field failed a validation rule.
    #[error("invalid configuration for {field}: {reason}")]
    InvalidConfiguration {
        /// The stable configuration field name.
        field: &'static str,
        /// The non-secret validation reason.
        reason: &'static str,
    },
    /// The configuration file could not be read.
    #[error("configuration could not be read")]
    ConfigurationRead,
    /// The configuration file was not valid TOML.
    #[error("configuration syntax is invalid")]
    ConfigurationSyntax,
    /// A bounded I/O operation failed.
    #[error("I/O operation failed: {operation} ({kind:?})")]
    Io {
        /// The non-secret operation category.
        operation: &'static str,
        /// The operating-system error category without its free-form message.
        kind: io::ErrorKind,
    },
    /// The configured Unix socket failed an identity or permission check.
    #[error("Unix socket identity check failed: {operation} ({reason})")]
    SocketIdentity {
        /// The stable operation category.
        operation: &'static str,
        /// The non-secret identity failure reason.
        reason: &'static str,
    },
    /// Listener startup was rejected by a stable policy boundary.
    #[error("relay listener startup failed: {reason}")]
    ListenerStartup {
        /// The non-secret startup reason.
        reason: &'static str,
    },
    /// Every v1 candidate port was occupied.
    #[error("all v1 relay ports are occupied")]
    PortRangeExhausted,
    /// An enabled listener address could not be bound.
    #[error("relay listener address is unavailable")]
    ListenerAddressUnavailable,
    /// The accepted peer source was not in the listener allowlist.
    #[error("relay peer source is not allowed")]
    SourceNotAllowed,
    /// The global or per-listener client quota was exhausted.
    #[error("relay client limit reached")]
    ClientLimit,
    /// The concurrent TLS/Relay handshake quota was exhausted.
    #[error("relay handshake limit reached")]
    HandshakeLimit,
    /// The TLS certificate, key, or trust-anchor references are invalid.
    #[error("TLS configuration failed: {reason}")]
    TlsConfiguration {
        /// The non-secret TLS configuration reason.
        reason: &'static str,
    },
    /// The peer failed mandatory TLS client authentication.
    #[error("TLS client authentication failed")]
    TlsAuthentication,
    /// The peer failed the fixed Relay handshake.
    #[error("Relay handshake failed")]
    RelayHandshake,
    /// The TLS and Relay handshake deadline elapsed.
    #[error("Relay handshake timed out")]
    RelayHandshakeTimeout,
    /// The configured milestone does not support this enabled listener class.
    #[error("listener class is not supported in this milestone")]
    UnsupportedListenerClass,
    /// The configured Herdr socket could not be opened within the bounded deadline.
    #[error("Herdr Unix socket is unavailable")]
    UpstreamUnavailable,
    /// The bridge exceeded its bounded whole-stream idle timeout.
    #[error("byte bridge idle timeout")]
    BridgeIdleTimeout,
}

impl RelayError {
    /// Creates a redacted I/O error with a stable operation category.
    ///
    /// # Arguments
    ///
    /// * `operation` - A static non-secret operation label.
    /// * `source` - The operating-system error returned by the operation.
    ///
    /// # Returns
    ///
    /// The corresponding relay error.
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

    // TEST:relay/src/error.rs[tests::errors_do_not_embed_raw_configuration]
    #[test]
    fn errors_do_not_embed_raw_configuration() {
        let error = RelayError::InvalidConfiguration {
            field: "security.server_cert",
            reason: "path is required",
        };
        let rendered = error.to_string();
        assert!(!rendered.contains("BEGIN PRIVATE KEY"));
        assert!(rendered.contains("security.server_cert"));
    }

    // TEST:relay/src/error.rs[tests::io_errors_drop_free_form_source_text]
    #[test]
    fn io_errors_drop_free_form_source_text() {
        let error = RelayError::io(
            "opening client CA",
            io::Error::other("BEGIN PRIVATE KEY: secret"),
        );
        assert!(!error.to_string().contains("BEGIN PRIVATE KEY"));
        assert!(!format!("{error:?}").contains("BEGIN PRIVATE KEY"));
        assert!(error.source().is_none());
    }
}
