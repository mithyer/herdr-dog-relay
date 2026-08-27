//! Feature-gated Relay facade used only by cross-crate HDB1 and HDE3 contract tests.
//!
//! The facade owns the deterministic Relay verifier behind an async mutex and exposes only
//! sanitized test controls. It is unavailable unless `contract-test-support` is enabled.

use std::{fmt, net::IpAddr, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

use crate::{
    bootstrap::{BootstrapStartRequest, RelayBootstrapError, RelayBootstrapVerifier},
    bootstrap_session::{Hdb1RelaySessionError, RelayHdb1BootstrapSession},
    bootstrap_wire::{Hdb1Kind, Hdb1StartPayload},
    enrollment::CsrDigest,
};

#[cfg(feature = "contract-test-support")]
#[path = "enrollment_v3_test_support.rs"]
pub mod enrollment_v3;

/// Frozen HDB1 magic exposed only to the cross-crate parity test.
pub const HDB1_CONTRACT_MAGIC: [u8; 4] = crate::bootstrap_wire::HDB1_MAGIC;
/// Frozen HDB1 version exposed only to the cross-crate parity test.
pub const HDB1_CONTRACT_VERSION: u16 = crate::bootstrap_wire::HDB1_VERSION;
/// Frozen HDB1 header size exposed only to the cross-crate parity test.
pub const HDB1_CONTRACT_HEADER_BYTES: usize = crate::bootstrap_wire::HDB1_HEADER_BYTES;
/// Frozen HDB1 complete-frame limit exposed only to the cross-crate parity test.
pub const HDB1_CONTRACT_MAX_FRAME_BYTES: usize = crate::bootstrap_wire::HDB1_MAX_FRAME_BYTES;
/// Frozen HDB1 JSON payload limit exposed only to the cross-crate parity test.
pub const HDB1_CONTRACT_MAX_PAYLOAD_BYTES: usize = crate::bootstrap_wire::HDB1_MAX_PAYLOAD_BYTES;
/// Frozen HDB1 CSR limit exposed only to the cross-crate parity test.
pub const HDB1_CONTRACT_MAX_CSR_BYTES: usize = crate::bootstrap_wire::HDB1_MAX_CSR_BYTES;
/// Frozen HDB1 session-name limit exposed only to the cross-crate parity test.
pub const HDB1_CONTRACT_MAX_SESSION_BYTES: usize = crate::bootstrap_wire::HDB1_MAX_SESSION_BYTES;
/// Frozen HDB1 certificate-chain byte limit exposed only to the cross-crate parity test.
pub const HDB1_CONTRACT_MAX_CHAIN_BYTES: usize = crate::bootstrap_wire::HDB1_MAX_CHAIN_BYTES;
/// Frozen HDB1 certificate-count limit exposed only to the cross-crate parity test.
pub const HDB1_CONTRACT_MAX_CHAIN_CERTIFICATES: usize =
    crate::bootstrap_wire::HDB1_MAX_CHAIN_CERTIFICATES;
/// Fixed HDB1 kind values derived from the Relay codec for cross-crate parity checks.
pub const HDB1_CONTRACT_KIND_VALUES: [u8; 7] = [
    Hdb1Kind::Start as u8,
    Hdb1Kind::Challenge as u8,
    Hdb1Kind::Submit as u8,
    Hdb1Kind::CoreIssued as u8,
    Hdb1Kind::Reconcile as u8,
    Hdb1Kind::Result as u8,
    Hdb1Kind::Rejected as u8,
];

/// Check a normalized session name through the same Relay Start validator used by the dispatcher.
///
/// # Parameters
/// * `value` - Candidate normalized Herdr session name.
///
/// # Returns
/// `true` when the candidate satisfies the frozen HDB1 session contract.
// TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_contract_constants_match]
pub fn accepts_session_name(value: &str) -> bool {
    Hdb1StartPayload::new([1; 16], b"test-csr", [1; 32], value.to_owned(), [1; 32]).is_ok()
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum BootstrapTestError {
    /// A bounded stream operation exceeded its deadline.
    Timeout,
    /// The peer frame or payload was malformed.
    InvalidFrame,
    /// A frame exceeded the fixed HDB1 bound.
    FrameTooLarge,
    /// A frame arrived outside the current HDB1 exchange phase.
    InvalidOrder,
    /// A bounded HDB1 field failed validation.
    InvalidField,
    /// The deterministic verifier rejected the test setup.
    InvalidRequest,
}

impl fmt::Debug for BootstrapTestError {
    /// Format only the stable error category.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Timeout => "Timeout",
            Self::InvalidFrame => "InvalidFrame",
            Self::FrameTooLarge => "FrameTooLarge",
            Self::InvalidOrder => "InvalidOrder",
            Self::InvalidField => "InvalidField",
            Self::InvalidRequest => "InvalidRequest",
        })
    }
}

impl fmt::Display for BootstrapTestError {
    /// Format a sanitized test error without payload, identity or code data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Timeout => "HDB1 contract operation timed out",
            Self::InvalidFrame => "HDB1 contract frame is invalid",
            Self::FrameTooLarge => "HDB1 contract frame is too large",
            Self::InvalidOrder => "HDB1 contract operation order is invalid",
            Self::InvalidField => "HDB1 contract field is invalid",
            Self::InvalidRequest => "HDB1 contract setup is invalid",
        })
    }
}

impl std::error::Error for BootstrapTestError {}

impl From<Hdb1RelaySessionError> for BootstrapTestError {
    /// Map an internal Relay session error without exposing transport details.
    fn from(error: Hdb1RelaySessionError) -> Self {
        match error {
            Hdb1RelaySessionError::Timeout => Self::Timeout,
            Hdb1RelaySessionError::Wire(error) => match error {
                crate::bootstrap_wire::Hdb1Error::InvalidFrame => Self::InvalidFrame,
                crate::bootstrap_wire::Hdb1Error::FrameTooLarge => Self::FrameTooLarge,
                crate::bootstrap_wire::Hdb1Error::InvalidOrder => Self::InvalidOrder,
                crate::bootstrap_wire::Hdb1Error::InvalidField => Self::InvalidField,
            },
        }
    }
}

/// Sanitized Start inputs used by the feature-gated Relay contract-test facade.
pub struct BootstrapStartInput {
    /// Nonzero non-authoritative request identifier.
    request_id: [u8; 16],
    /// Bounded transient Core CSR bytes used only by the fake.
    core_csr: Vec<u8>,
    /// Nonzero digest of the App CSR.
    app_csr_digest: [u8; 32],
    /// Existing normalized Herdr session.
    normalized_session: String,
    /// Nonzero Core binding digest.
    core_binding_digest: [u8; 32],
}

impl fmt::Debug for BootstrapStartInput {
    /// Report bounded input shape without exposing identifiers or CSR bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapStartInput")
            .field("request_id_present", &true)
            .field("core_csr_len", &self.core_csr.len())
            .field("app_csr_digest_present", &true)
            .field("session_bound", &true)
            .field("core_binding_digest_present", &true)
            .finish()
    }
}

impl BootstrapStartInput {
    /// Create bounded Start inputs for the Core/Relay contract test.
    ///
    /// # Parameters
    /// * `request_id` - Nonzero non-authoritative request identifier.
    /// * `core_csr` - Bounded transient Core CSR bytes.
    /// * `app_csr_digest` - Nonzero digest of the App CSR.
    /// * `normalized_session` - Existing normalized Herdr session.
    /// * `core_binding_digest` - Nonzero Core binding digest.
    ///
    /// # Returns
    /// A test input retained only by the caller until `preview_code` is called.
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_issue_and_reconcile]
    pub fn new(
        request_id: [u8; 16],
        core_csr: &[u8],
        app_csr_digest: [u8; 32],
        normalized_session: &str,
        core_binding_digest: [u8; 32],
    ) -> Self {
        Self {
            request_id,
            core_csr: core_csr.to_vec(),
            app_csr_digest,
            normalized_session: normalized_session.to_owned(),
            core_binding_digest,
        }
    }
}

/// Relay-side HDB1 contract server that serializes access to one deterministic verifier fake.
#[derive(Clone)]
pub struct RelayBootstrapTestServer {
    /// Non-secret deterministic seed shared with the preview verifier.
    seed: [u8; 32],
    /// Core-owned test verifier protected across asynchronous stream operations.
    verifier: Arc<Mutex<RelayBootstrapVerifier>>,
}

impl fmt::Debug for RelayBootstrapTestServer {
    /// Report only that a verifier exists, without exposing its seed or retained state.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayBootstrapTestServer")
            .field("verifier_present", &true)
            .finish()
    }
}

impl RelayBootstrapTestServer {
    /// Create a deterministic Relay HDB1 contract server.
    ///
    /// # Parameters
    /// * `seed` - Non-secret seed used by the local verifier fake.
    ///
    /// # Returns
    /// A test server or a sanitized setup error.
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_issue_and_reconcile]
    pub fn new(seed: [u8; 32]) -> Result<Self, BootstrapTestError> {
        let verifier =
            RelayBootstrapVerifier::new(seed).map_err(|_| BootstrapTestError::InvalidRequest)?;
        Ok(Self {
            seed,
            verifier: Arc::new(Mutex::new(verifier)),
        })
    }

    /// Build a fresh deterministic verifier and the bootstrap ID for one Start input.
    fn preview_attempt(
        &self,
        peer_ip: IpAddr,
        configuration_generation: u64,
        now_epoch_seconds: u64,
        input: &BootstrapStartInput,
    ) -> Result<(RelayBootstrapVerifier, crate::bootstrap::Opaque32), BootstrapTestError> {
        let app_csr_digest = CsrDigest::from_bytes(input.app_csr_digest)
            .map_err(|_| BootstrapTestError::InvalidRequest)?;
        let request = BootstrapStartRequest::new(
            input.request_id,
            input.core_csr.clone(),
            app_csr_digest,
            input.normalized_session.clone(),
            configuration_generation,
            input.core_binding_digest,
        )
        .map_err(|_| BootstrapTestError::InvalidRequest)?;
        let mut preview = RelayBootstrapVerifier::new(self.seed)
            .map_err(|_| BootstrapTestError::InvalidRequest)?;
        let challenge = preview
            .start(peer_ip, request, now_epoch_seconds)
            .map_err(|_| BootstrapTestError::InvalidRequest)?;
        Ok((preview, challenge.bootstrap_id))
    }

    /// Preview the deterministic code for the exact Start request used by the live fake.
    ///
    /// This method exists only for the feature-gated contract test. The production Relay never
    /// exposes verification codes through a public API or diagnostics.
    ///
    /// # Parameters
    /// * `peer_ip` - Relay-observed test peer address.
    /// * `configuration_generation` - Generation passed to the live dispatcher.
    /// * `now_epoch_seconds` - Deterministic time passed to the live dispatcher.
    /// * `input` - Bounded Start fields shared with the live dispatcher.
    ///
    /// # Returns
    /// The deterministic six-digit test code or a sanitized setup error.
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_issue_and_reconcile]
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_rejection]
    pub fn preview_code(
        &self,
        peer_ip: IpAddr,
        configuration_generation: u64,
        now_epoch_seconds: u64,
        input: &BootstrapStartInput,
    ) -> Result<String, BootstrapTestError> {
        let (preview, bootstrap_id) =
            self.preview_attempt(peer_ip, configuration_generation, now_epoch_seconds, input)?;
        preview
            .test_code(bootstrap_id)
            .ok_or(BootstrapTestError::InvalidRequest)
    }

    /// Preview the deterministic approval identity for a pending Start request.
    ///
    /// This method exists only for the feature-gated contract test so it can exercise the
    /// pending-recovery wire result without exposing verifier state in production.
    ///
    /// # Parameters
    /// * `peer_ip` - Relay-observed test peer address.
    /// * `configuration_generation` - Generation passed to the live dispatcher.
    /// * `now_epoch_seconds` - Deterministic time passed to the live dispatcher.
    /// * `input` - Bounded Start fields shared with the live dispatcher.
    ///
    /// # Returns
    /// The opaque pending approval identity or a sanitized setup error.
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_pending_recovery]
    pub fn preview_approval_id(
        &self,
        peer_ip: IpAddr,
        configuration_generation: u64,
        now_epoch_seconds: u64,
        input: &BootstrapStartInput,
    ) -> Result<[u8; 32], BootstrapTestError> {
        let (preview, bootstrap_id) =
            self.preview_attempt(peer_ip, configuration_generation, now_epoch_seconds, input)?;
        preview
            .test_approval_id(bootstrap_id)
            .ok_or(BootstrapTestError::InvalidRequest)
    }

    /// Serve one Core Start/Challenge/Submit exchange on a bounded test stream.
    ///
    /// # Parameters
    /// * `peer_ip` - Relay-observed test peer address.
    /// * `configuration_generation` - Core/Relay generation bound to Start.
    /// * `now_epoch_seconds` - Deterministic time for the verifier fake.
    /// * `stream` - One bounded asynchronous byte stream reserved for this attempt.
    ///
    /// # Returns
    /// Success after the terminal response is written, or a sanitized framing/transport error.
    /// A code rejection is terminal for this one-shot local stream; the verifier's bounded
    /// failed-code budget is intentionally left to a later outer production transport policy.
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_issue_and_reconcile]
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_rejection]
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_start_rejection]
    // TEST:core/tests/hdb1_relay_loopback.rs[relay_rejects_malformed_cross_crate_frame]
    pub async fn serve<S>(
        &self,
        peer_ip: IpAddr,
        configuration_generation: u64,
        now_epoch_seconds: u64,
        stream: &mut S,
    ) -> Result<(), BootstrapTestError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut verifier = self.verifier.lock().await;
        RelayHdb1BootstrapSession::serve(
            &mut verifier,
            peer_ip,
            configuration_generation,
            now_epoch_seconds,
            stream,
        )
        .await
        .map_err(BootstrapTestError::from)
    }

    /// Serve one exact-binding Reconcile exchange on a fresh bounded test stream.
    ///
    /// # Parameters
    /// * `now_epoch_seconds` - Deterministic time for recovery validation.
    /// * `stream` - Fresh bounded asynchronous byte stream reserved for recovery.
    ///
    /// # Returns
    /// Success after the terminal recovery result is delivered, or a sanitized contract error.
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_issue_and_reconcile]
    // TEST:core/tests/hdb1_relay_loopback.rs[core_and_relay_compose_pending_recovery]
    pub async fn reconcile<S>(
        &self,
        now_epoch_seconds: u64,
        stream: &mut S,
    ) -> Result<(), BootstrapTestError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut verifier = self.verifier.lock().await;
        RelayHdb1BootstrapSession::reconcile(&mut verifier, now_epoch_seconds, stream)
            .await
            .map_err(BootstrapTestError::from)
    }
}

impl From<RelayBootstrapError> for BootstrapTestError {
    /// Map a verifier setup failure to a sanitized contract-test error.
    fn from(_: RelayBootstrapError) -> Self {
        Self::InvalidRequest
    }
}
