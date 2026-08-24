//! Herdr-dog Relay library for QRM-1.
//!
//! The Relay is a narrow QUIC TLS 1.3 session-stream bridge. It never parses Herdr protocol or
//! exposes arbitrary upstream commands.
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(not(unix))]
compile_error!("herdr-dog-relay currently supports Unix hosts only");

/// Protected persistent App allowlist and generation store.
pub mod allowlist;
/// Bounded opaque bidirectional byte forwarding.
pub mod bridge;
/// QRM-1 single-listener configuration.
pub mod config;
/// Schema-neutral QRM-PROD-1 enrollment, allowlist, and update contracts/fakes.
pub mod enrollment;
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
