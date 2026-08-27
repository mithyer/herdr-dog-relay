//! Feature-gated Relay facade for the generic HDE3 contract-session tests.
//!
//! The facade exposes sanitized response constructors and stream-serving methods only. HDE3
//! frames, CSR bytes and certificate bytes remain behind the crate-private Relay modules.

use std::fmt;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    enrollment_v3_session::{
        HDE3_SESSION_IO_TIMEOUT, Hde3RelaySessionError, Hde3ServerResponse,
        RelayHde3EnrollmentSession,
    },
    enrollment_v3_wire::{
        HDE3_DIGEST_BYTES, HDE3_HEADER_BYTES, HDE3_ID_BYTES, HDE3_MAGIC, HDE3_MAX_CHAIN_BYTES,
        HDE3_MAX_CHAIN_CERTIFICATES, HDE3_MAX_CSR_BYTES, HDE3_MAX_FRAME_BYTES,
        HDE3_MAX_PAYLOAD_BYTES, HDE3_MAX_SESSION_BYTES, HDE3_VERSION, Hde3Error, Hde3IssuedInput,
        Hde3Kind, Hde3RejectedPayload, Hde3ResultPayload,
    },
};

/// Frozen HDE3 magic exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_MAGIC: [u8; 4] = HDE3_MAGIC;
/// Frozen HDE3 version exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_VERSION: u16 = HDE3_VERSION;
/// Frozen HDE3 header width exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_HEADER_BYTES: usize = HDE3_HEADER_BYTES;
/// Frozen HDE3 complete-frame bound exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_MAX_FRAME_BYTES: usize = HDE3_MAX_FRAME_BYTES;
/// Frozen HDE3 payload bound exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_MAX_PAYLOAD_BYTES: usize = HDE3_MAX_PAYLOAD_BYTES;
/// Frozen HDE3 CSR bound exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_MAX_CSR_BYTES: usize = HDE3_MAX_CSR_BYTES;
/// Frozen HDE3 session-name bound exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_MAX_SESSION_BYTES: usize = HDE3_MAX_SESSION_BYTES;
/// Frozen HDE3 certificate-chain bound exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_MAX_CHAIN_BYTES: usize = HDE3_MAX_CHAIN_BYTES;
/// Frozen HDE3 certificate-count bound exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_MAX_CHAIN_CERTIFICATES: usize = HDE3_MAX_CHAIN_CERTIFICATES;
/// Frozen HDE3 digest width exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_DIGEST_BYTES: usize = HDE3_DIGEST_BYTES;
/// Frozen HDE3 identifier width exposed only to cross-crate parity tests.
pub const HDE3_CONTRACT_ID_BYTES: usize = HDE3_ID_BYTES;
/// Fixed HDE3 kind values derived from the Relay codec.
pub const HDE3_CONTRACT_KIND_VALUES: [u8; 9] = [
    Hde3Kind::FirstAppSubmit as u8,
    Hde3Kind::ApprovalStart as u8,
    Hde3Kind::ApprovalChallenge as u8,
    Hde3Kind::ApprovalSubmit as u8,
    Hde3Kind::ConfirmPersisted as u8,
    Hde3Kind::Reconcile as u8,
    Hde3Kind::Renew as u8,
    Hde3Kind::Result as u8,
    Hde3Kind::Rejected as u8,
];
/// Fixed per-operation HDE3 deadline in seconds.
pub const HDE3_CONTRACT_SESSION_IO_TIMEOUT_SECS: u64 = HDE3_SESSION_IO_TIMEOUT.as_secs();

/// Reports whether a normalized session name satisfies the shared HDE3 contract.
pub fn accepts_session_name(value: &str) -> bool {
    crate::enrollment_v3_wire::validate_session(value).is_ok()
}

/// Sanitized Relay-side HDE3 contract-session error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hde3TestError {
    /// A bounded read, write or shutdown exceeded its deadline.
    Timeout,
    /// The peer frame or payload was malformed.
    InvalidFrame,
    /// A frame exceeded the fixed bound.
    FrameTooLarge,
    /// A frame arrived outside the current exchange phase.
    InvalidOrder,
    /// A bounded HDE3 field was invalid.
    InvalidField,
}

impl fmt::Display for Hde3TestError {
    /// Formats a sanitized error without payload, identity or certificate data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Timeout => "Relay HDE3 contract operation timed out",
            Self::InvalidFrame => "Relay HDE3 contract frame is invalid",
            Self::FrameTooLarge => "Relay HDE3 contract frame is too large",
            Self::InvalidOrder => "Relay HDE3 contract operation order is invalid",
            Self::InvalidField => "Relay HDE3 contract field is invalid",
        })
    }
}

impl std::error::Error for Hde3TestError {}

impl From<Hde3Error> for Hde3TestError {
    /// Maps the bounded codec error to a stable contract-test category.
    fn from(error: Hde3Error) -> Self {
        match error {
            Hde3Error::InvalidFrame => Self::InvalidFrame,
            Hde3Error::FrameTooLarge => Self::FrameTooLarge,
            Hde3Error::InvalidOrder => Self::InvalidOrder,
            Hde3Error::InvalidField => Self::InvalidField,
        }
    }
}

impl From<Hde3RelaySessionError> for Hde3TestError {
    /// Maps the Relay session error without exposing transport details.
    fn from(error: Hde3RelaySessionError) -> Self {
        match error {
            Hde3RelaySessionError::Timeout => Self::Timeout,
            Hde3RelaySessionError::Wire(error) => error.into(),
        }
    }
}

/// Sanitized HDE3 response selected by a local Relay contract fake.
#[derive(Clone, Eq, PartialEq)]
pub enum Hde3Response {
    /// A pending response with no certificate fields.
    Pending { approval_id: [u8; 32] },
    /// An issued or active response with fixed public-only test metadata.
    Issued { approval_id: [u8; 32], active: bool },
    /// A Result-level rejection with an approval identifier.
    Rejected { approval_id: [u8; 32], code: u16 },
    /// A fixed Rejected frame without an approval identifier.
    FixedRejected { code: u16 },
}

impl fmt::Debug for Hde3Response {
    /// Reports response shape without exposing identifiers or certificate bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pending { .. } => "Pending { approval_id_present: true }",
            Self::Issued { active, .. } => {
                if *active {
                    "Issued { active: true }"
                } else {
                    "Issued { active: false }"
                }
            }
            Self::Rejected { .. } => "Rejected { approval_id_present: true }",
            Self::FixedRejected { .. } => "FixedRejected",
        })
    }
}

impl Hde3Response {
    /// Creates a pending response for a nonzero approval identifier.
    pub fn pending(approval_id: [u8; 32]) -> Self {
        Self::Pending { approval_id }
    }

    /// Creates an issued or active response with bounded deterministic public metadata.
    pub fn issued(approval_id: [u8; 32], active: bool) -> Self {
        Self::Issued {
            approval_id,
            active,
        }
    }

    /// Creates a Result-level rejection for a nonzero approval identifier and code.
    pub fn rejected(approval_id: [u8; 32], code: u16) -> Self {
        Self::Rejected { approval_id, code }
    }

    /// Creates a fixed terminal rejection without an approval identifier.
    pub fn fixed_rejected(code: u16) -> Self {
        Self::FixedRejected { code }
    }

    /// Convert the sanitized response into the private Relay wire response.
    fn into_wire(self) -> Result<Hde3ServerResponse, Hde3TestError> {
        match self {
            Self::Pending { approval_id } => Hde3ResultPayload::new_pending(approval_id)
                .map(Hde3ServerResponse::Result)
                .map_err(Into::into),
            Self::Issued {
                approval_id,
                active,
            } => Hde3ResultPayload::new_issued(Hde3IssuedInput {
                approval_id,
                app_identity: [2; 32],
                certificate_chain: &[vec![3; 8], vec![4; 8]],
                certificate_fingerprint: [5; 32],
                certificate_chain_digest: [6; 32],
                not_after_epoch_seconds: 900,
                configuration_generation: 1,
                active,
            })
            .map(Hde3ServerResponse::Result)
            .map_err(Into::into),
            Self::Rejected { approval_id, code } => {
                Hde3ResultPayload::new_rejected(approval_id, code)
                    .map(Hde3ServerResponse::Result)
                    .map_err(Into::into)
            }
            Self::FixedRejected { code } => Hde3RejectedPayload::new(code)
                .map(Hde3ServerResponse::Rejected)
                .map_err(Into::into),
        }
    }
}

/// Relay HDE3 server facade used by the cross-crate contract tests.
pub struct Hde3Server;

impl fmt::Debug for Hde3Server {
    /// Reports the presence of a stateless contract server.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Hde3Server")
    }
}

impl Hde3Server {
    /// Creates a stateless HDE3 contract server.
    pub fn new() -> Self {
        Self
    }

    /// Serves one first-App request with a selected sanitized response.
    ///
    /// # Parameters
    /// * `stream` - One bounded asynchronous stream reserved for the operation.
    /// * `response` - Sanitized response selected by the fake.
    ///
    /// # Returns
    /// Success after response validation, write and terminal close.
    // TEST:core/tests/hde3_relay_loopback.rs[core_and_relay_compose_first_app]
    pub async fn serve_first_app<S>(
        &self,
        stream: &mut S,
        response: Hde3Response,
    ) -> Result<(), Hde3TestError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        RelayHde3EnrollmentSession::serve_first_app(stream, response.into_wire()?)
            .await
            .map_err(Into::into)
    }

    /// Serves a later ApprovalStart/Challenge/ApprovalSubmit exchange.
    ///
    /// # Parameters
    /// * `stream` - One bounded asynchronous stream reserved for the approval.
    /// * `approval_id` - Nonzero Relay approval identifier.
    /// * `challenge` - Nonzero one-time approval challenge.
    /// * `expires_at_epoch_seconds` - Protected challenge expiry.
    /// * `response` - Sanitized terminal response selected by the fake.
    ///
    /// # Returns
    /// Success after challenge and terminal response delivery.
    // TEST:core/tests/hde3_relay_loopback.rs[core_and_relay_compose_approval]
    pub async fn serve_approval<S>(
        &self,
        stream: &mut S,
        approval_id: [u8; 32],
        challenge: [u8; 32],
        expires_at_epoch_seconds: u64,
        response: Hde3Response,
    ) -> Result<(), Hde3TestError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        RelayHde3EnrollmentSession::serve_approval(
            stream,
            approval_id,
            challenge,
            expires_at_epoch_seconds,
            response.into_wire()?,
        )
        .await
        .map_err(Into::into)
    }

    /// Serves one exact-binding Reconcile request with a selected response.
    ///
    /// # Parameters
    /// * `stream` - One fresh bounded asynchronous stream.
    /// * `response` - Sanitized pending, issued, active or rejected response.
    ///
    /// # Returns
    /// Success after response validation, write and terminal close.
    // TEST:core/tests/hde3_relay_loopback.rs[core_and_relay_compose_reconcile]
    pub async fn serve_reconcile<S>(
        &self,
        stream: &mut S,
        response: Hde3Response,
    ) -> Result<(), Hde3TestError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        RelayHde3EnrollmentSession::serve_reconcile(stream, response.into_wire()?)
            .await
            .map_err(Into::into)
    }

    /// Serves one ConfirmPersisted request with a selected response.
    ///
    /// # Parameters
    /// * `stream` - One bounded asynchronous stream.
    /// * `response` - Sanitized active or rejected response.
    ///
    /// # Returns
    /// Success after response validation, write and terminal close.
    // TEST:core/tests/hde3_relay_loopback.rs[core_and_relay_compose_confirm]
    pub async fn serve_confirm_persisted<S>(
        &self,
        stream: &mut S,
        response: Hde3Response,
    ) -> Result<(), Hde3TestError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        RelayHde3EnrollmentSession::serve_confirm_persisted(stream, response.into_wire()?)
            .await
            .map_err(Into::into)
    }

    /// Serves one same-key Renew request with a selected response.
    ///
    /// # Parameters
    /// * `stream` - One bounded asynchronous stream.
    /// * `response` - Sanitized response selected by the fake.
    ///
    /// # Returns
    /// Success after response validation, write and terminal close.
    // TEST:core/tests/hde3_relay_loopback.rs[core_and_relay_compose_renew]
    pub async fn serve_renew<S>(
        &self,
        stream: &mut S,
        response: Hde3Response,
    ) -> Result<(), Hde3TestError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        RelayHde3EnrollmentSession::serve_renew(stream, response.into_wire()?)
            .await
            .map_err(Into::into)
    }
}

impl Default for Hde3Server {
    /// Creates a stateless HDE3 contract server.
    fn default() -> Self {
        Self::new()
    }
}
