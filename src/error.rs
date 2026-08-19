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
