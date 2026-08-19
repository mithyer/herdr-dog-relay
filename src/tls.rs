//! TLS 1.3 and mutual-client-authentication construction.

use crate::{
    config::{SecurityConfig, V1_RELAY_ALPN},
    error::{RelayError, RelayResult},
};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use std::{
    fs,
    io::{BufReader, Cursor},
    sync::Arc,
};
use tokio_rustls::TlsAcceptor;

/// Builds the fail-closed TLS 1.3 mutual-TLS acceptor from validated references.
///
/// # Arguments
///
/// * `security` - Validated certificate, key, trust-anchor, and identity paths.
///
/// # Returns
///
/// A TLS acceptor advertising only the v1 Relay ALPN, or a redacted configuration error.
pub(crate) fn build_server_acceptor(security: &SecurityConfig) -> RelayResult<TlsAcceptor> {
    let server_chain = load_certificates(security.server_cert(), "server certificate")?;
    let trusted_client_certs = load_certificates(security.trusted_client_ca(), "client CA")?;
    let server_key = load_private_key(security.server_key())?;
    let mut roots = RootCertStore::empty();
    for certificate in trusted_client_certs {
        roots
            .add(certificate)
            .map_err(|_| RelayError::TlsConfiguration {
                reason: "client CA certificate is invalid",
            })?;
    }
    if roots.is_empty() {
        return Err(RelayError::TlsConfiguration {
            reason: "client CA contains no trust anchors",
        });
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| RelayError::TlsConfiguration {
            reason: "client certificate verifier could not be built",
        })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RelayError::TlsConfiguration {
            reason: "TLS 1.3 is unavailable",
        })?;
    let mut config = builder
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain, server_key)
        .map_err(|_| RelayError::TlsConfiguration {
            reason: "server certificate and key do not match",
        })?;
    config.alpn_protocols = vec![V1_RELAY_ALPN.to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Loads every PEM certificate in a configured file without retaining its path in errors.
fn load_certificates(
    path: &std::path::Path,
    purpose: &'static str,
) -> RelayResult<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let bytes = fs::read(path).map_err(|error| RelayError::io("reading TLS certificate", error))?;
    let mut reader = BufReader::new(Cursor::new(bytes));
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RelayError::TlsConfiguration { reason: purpose })?;
    if certificates.is_empty() {
        return Err(RelayError::TlsConfiguration { reason: purpose });
    }
    Ok(certificates)
}

/// Loads the first supported PEM private key in a configured file.
fn load_private_key(
    path: &std::path::Path,
) -> RelayResult<rustls::pki_types::PrivateKeyDer<'static>> {
    let bytes = fs::read(path).map_err(|error| RelayError::io("reading TLS private key", error))?;
    let mut reader = BufReader::new(Cursor::new(bytes));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| RelayError::TlsConfiguration {
            reason: "private key PEM is invalid",
        })?
        .ok_or(RelayError::TlsConfiguration {
            reason: "private key PEM is empty",
        })
}
