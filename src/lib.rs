//! Herdr-dog Relay library for QRM-1.
//!
//! The Relay is a narrow QUIC TLS 1.3 session-stream bridge. It never parses Herdr protocol or
//! exposes arbitrary upstream commands.
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(not(unix))]
compile_error!("herdr-dog-relay currently supports Unix hosts only");

/// Test-only Core/Relay HDB1 and HDE3 contract-composition facade; never enabled in production builds.
#[cfg(feature = "contract-test-support")]
#[doc(hidden)]
#[path = "bootstrap_test_support.rs"]
pub mod contract_test_support;

/// Maximum normalized HDB1 session name shared by test-gated wire and authority validation.
#[cfg(any(test, feature = "contract-test-support"))]
pub(crate) const HDB1_MAX_SESSION_BYTES: usize = 64;
/// Maximum HDB1 CSR size shared by test-gated wire and authority validation.
#[cfg(any(test, feature = "contract-test-support"))]
pub(crate) const HDB1_MAX_CSR_BYTES: usize = 16 * 1024;

/// Validate the source-aligned normalized Herdr session name for HDB1 test support.
#[cfg(any(test, feature = "contract-test-support"))]
pub(crate) fn is_valid_hdb1_session(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= HDB1_MAX_SESSION_BYTES
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Protected persistent App allowlist and generation store.
pub mod allowlist;
/// Schema-neutral Relay-side HDB1 hidden-workspace verifier and issuance fake.
#[cfg(any(test, feature = "contract-test-support"))]
#[allow(dead_code)]
pub(crate) mod bootstrap;
/// Core-to-Relay HDB1 stream dispatcher for local contract tests.
#[cfg(any(test, feature = "contract-test-support"))]
#[allow(dead_code)]
pub(crate) mod bootstrap_session;
/// Frozen server-authenticated HDB1 bootstrap frame codec.
#[cfg(any(test, feature = "contract-test-support"))]
#[allow(dead_code)]
pub(crate) mod bootstrap_wire;
/// Bounded opaque bidirectional byte forwarding.
pub mod bridge;
/// QRM-1 single-listener configuration.
pub mod config;
/// Schema-neutral QRM-PROD-1 enrollment, allowlist, and update contracts/fakes.
pub mod enrollment;
/// Generic HDE3 Relay enrollment session dispatcher for local contract tests.
#[cfg(any(test, feature = "contract-test-support"))]
#[allow(dead_code)]
pub(crate) mod enrollment_v3_session;
/// Frozen Core-enrollment HDE3 frame codec.
#[cfg(any(test, feature = "contract-test-support"))]
#[allow(dead_code)]
pub(crate) mod enrollment_v3_wire;
/// Bounded same-port enrollment frame codec.
pub mod enrollment_wire;
/// Redacted Relay errors.
pub mod error;
/// Protected durable enrollment issuance-result records.
pub mod issuance;
/// Protected-file validation and transient deployment material loading.
pub mod material;
/// Transient protected certificate issuance for App enrollment.
pub mod pki;
/// QRM-1 bounded QUIC server owner and connection lifecycle.
pub mod quic_server;
/// QRM-1 HDQM/HDQS codec.
pub mod quic_wire;
/// Version-two response-lost enrollment reconciliation frame codec.
pub mod reconciliation_wire;
/// QRM-1 per-connection session authority registry.
pub mod session_registry;
/// Validated Herdr Unix socket access.
pub mod socket;
/// Portable user-level LaunchAgent and systemd templates.
pub mod supervision;
/// Fixed-source stable-latest updater and archive safety checks.
pub mod updater;
/// QRM-PROD-1 enrollment/allowlist/update contract and deterministic fake surface.
pub use enrollment::{
    AUTHORITY_BYTES, AUTHORIZATION_ID_BYTES, AllowlistEntry, AllowlistRegistry, AllowlistRole,
    AllowlistState, AppId, CERTIFICATE_VALIDITY_SECS, CertificateMetadata, CoreAuthorization,
    CsrDigest, CsrMetadata, ENROLLMENT_TTL_SECS, EnrollmentChallenge, EnrollmentError,
    EnrollmentOutcome, EnrollmentSubmission, FakeCertificateAuthority, FakeRelayEnrollment,
    FakeUpdateWorker, Fingerprint, MAX_APP_ID_BYTES, MAX_CSR_BYTES, STABLE_LATEST_SELECTOR,
    UpdateRequest, UpdateSelector, UpdateStatus,
};
