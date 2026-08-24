//! Bounded HDE version-two response-lost reconciliation frames.
//!
//! HDE1 Challenge/Submit/Issued/Rejected frames remain unchanged. This module owns only the
//! version-two Reconcile request/result namespace and never carries private keys or raw CSRs.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// HDE magic retained across the versioned enrollment frame namespace.
pub const RECONCILIATION_MAGIC: [u8; 4] = *b"HDE1";
/// Version selected for the dedicated reconciliation extension.
pub const RECONCILIATION_VERSION: u16 = 2;
/// Fixed HDE header width shared with HDE1.
pub const RECONCILIATION_HEADER_BYTES: usize = 11;
/// Maximum public certificate chain bytes returned by one reconciliation result.
pub const MAX_RECONCILIATION_CHAIN_BYTES: usize = 48 * 1024;

/// One version-two reconciliation operation kind.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum ReconciliationFrameKind {
    /// Query one existing authorization/CSR result.
    Reconcile = 5,
    /// Return one bounded pending, issued or rejected result.
    Result = 6,
}

impl TryFrom<u8> for ReconciliationFrameKind {
    type Error = ReconciliationWireError;

    /// Decode one version-two operation kind.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            5 => Ok(Self::Reconcile),
            6 => Ok(Self::Result),
            _ => Err(ReconciliationWireError::InvalidFrame),
        }
    }
}

impl fmt::Debug for ReconciliationFrameKind {
    /// Report the operation name without payload material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Reconcile => "Reconcile",
            Self::Result => "Result",
        })
    }
}

/// Stable bounded reconciliation wire errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ReconciliationWireError {
    /// HDE magic, version, kind or payload shape is invalid.
    InvalidFrame = 1,
    /// Payload exceeds the fixed frame bound.
    FrameTooLarge = 2,
    /// The operation kind is not valid for the current direction.
    InvalidOrder = 3,
    /// The result payload violates the status-specific field contract.
    InvalidResult = 4,
}

/// One opaque version-two reconciliation frame.
#[derive(Clone, Eq, PartialEq)]
pub struct ReconciliationFrame {
    /// Version-two operation kind.
    pub kind: ReconciliationFrameKind,
    /// Bounded serialized JSON payload.
    pub payload: Vec<u8>,
}

impl fmt::Debug for ReconciliationFrame {
    /// Report operation and payload size without exposing correlation values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconciliationFrame")
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl ReconciliationFrame {
    /// Encode one bounded HDE version-two frame.
    ///
    /// # Parameters
    /// * `max_bytes` - Maximum serialized payload accepted by the Relay configuration.
    ///
    /// # Returns
    /// Encoded frame bytes or a stable bounded wire error.
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, ReconciliationWireError> {
        if self.payload.len() > max_bytes || self.payload.len() > u32::MAX as usize {
            return Err(ReconciliationWireError::FrameTooLarge);
        }
        let mut bytes = Vec::with_capacity(RECONCILIATION_HEADER_BYTES + self.payload.len());
        bytes.extend_from_slice(&RECONCILIATION_MAGIC);
        bytes.extend_from_slice(&RECONCILIATION_VERSION.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decode one complete HDE version-two frame.
    ///
    /// # Parameters
    /// * `bytes` - Complete frame bytes.
    /// * `max_bytes` - Maximum serialized payload bound.
    ///
    /// # Returns
    /// A validated frame or a stable wire error.
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, ReconciliationWireError> {
        if bytes.len() < RECONCILIATION_HEADER_BYTES
            || bytes[..4] != RECONCILIATION_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != RECONCILIATION_VERSION
        {
            return Err(ReconciliationWireError::InvalidFrame);
        }
        let kind = ReconciliationFrameKind::try_from(bytes[6])?;
        let payload_len = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
        if payload_len > max_bytes || bytes.len() != RECONCILIATION_HEADER_BYTES + payload_len {
            return Err(if payload_len > max_bytes {
                ReconciliationWireError::FrameTooLarge
            } else {
                ReconciliationWireError::InvalidFrame
            });
        }
        Ok(Self {
            kind,
            payload: bytes[RECONCILIATION_HEADER_BYTES..].to_vec(),
        })
    }

    /// Serialize one typed version-two payload.
    pub fn json<T: Serialize>(
        kind: ReconciliationFrameKind,
        value: &T,
        max_bytes: usize,
    ) -> Result<Self, ReconciliationWireError> {
        let payload =
            serde_json::to_vec(value).map_err(|_| ReconciliationWireError::InvalidFrame)?;
        if payload.len() > max_bytes {
            return Err(ReconciliationWireError::FrameTooLarge);
        }
        Ok(Self { kind, payload })
    }

    /// Deserialize one typed payload after checking the operation kind.
    pub fn parse_json<T: DeserializeOwned>(
        &self,
        expected: ReconciliationFrameKind,
    ) -> Result<T, ReconciliationWireError> {
        if self.kind != expected {
            return Err(ReconciliationWireError::InvalidOrder);
        }
        serde_json::from_slice(&self.payload).map_err(|_| ReconciliationWireError::InvalidFrame)
    }
}

/// Reads one bounded HDE version-two frame from an async stream.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<ReconciliationFrame, ReconciliationWireError> {
    let mut header = [0_u8; RECONCILIATION_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| ReconciliationWireError::InvalidFrame)?;
    let payload_len = u32::from_be_bytes([header[7], header[8], header[9], header[10]]) as usize;
    if payload_len > max_bytes {
        return Err(ReconciliationWireError::FrameTooLarge);
    }
    let mut bytes = Vec::with_capacity(RECONCILIATION_HEADER_BYTES + payload_len);
    bytes.extend_from_slice(&header);
    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| ReconciliationWireError::InvalidFrame)?;
    bytes.extend_from_slice(&payload);
    ReconciliationFrame::decode(&bytes, max_bytes)
}

/// Writes one bounded HDE version-two frame to an async stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &ReconciliationFrame,
    max_bytes: usize,
) -> Result<(), ReconciliationWireError> {
    writer
        .write_all(&frame.encode(max_bytes)?)
        .await
        .map_err(|_| ReconciliationWireError::InvalidFrame)
}

/// Reconciliation request keyed only by Core authorization and CSR digest.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcilePayload {
    /// Single-use Core authorization identity.
    pub authorization_id: [u8; 16],
    /// SHA-256 digest of the discarded CSR.
    pub csr_digest: [u8; 32],
}

impl fmt::Debug for ReconcilePayload {
    /// Report only fixed-field presence.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconcilePayload")
            .field("authorization_id_present", &true)
            .field("csr_digest_present", &true)
            .finish()
    }
}

/// Sanitized result status returned by reconciliation.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    /// Relay has consumed the authorization but terminal outcome is unresolved.
    Pending,
    /// Relay has an existing public issuance result.
    Issued,
    /// Relay has a terminal sanitized rejection.
    Rejected,
}

impl fmt::Debug for ReconciliationStatus {
    /// Format the stable status name.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pending => "Pending",
            Self::Issued => "Issued",
            Self::Rejected => "Rejected",
        })
    }
}

/// Version-two reconciliation result with status-specific public fields.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationResultPayload {
    /// Current reconciliation status.
    pub status: ReconciliationStatus,
    /// Existing public certificate chain for `issued` only.
    #[serde(default)]
    pub certificate_chain: Vec<Vec<u8>>,
    /// Public leaf fingerprint for `issued` only.
    #[serde(default)]
    pub fingerprint: Option<[u8; 32]>,
    /// Allowlist generation for `issued` only.
    #[serde(default)]
    pub allowlist_generation: Option<u64>,
    /// Public certificate expiry for `issued` only.
    #[serde(default)]
    pub not_after_epoch_seconds: Option<u64>,
    /// Stable rejection category for `rejected` only.
    #[serde(default)]
    pub rejection_code: Option<u16>,
}

impl ReconciliationResultPayload {
    /// Validate the status-specific field contract and public chain bounds.
    pub fn validate(&self) -> Result<(), ReconciliationWireError> {
        let total = self
            .certificate_chain
            .iter()
            .try_fold(0usize, |total, certificate| {
                total.checked_add(certificate.len())
            })
            .ok_or(ReconciliationWireError::FrameTooLarge)?;
        if total > MAX_RECONCILIATION_CHAIN_BYTES
            || self.certificate_chain.iter().any(Vec::is_empty)
        {
            return Err(ReconciliationWireError::FrameTooLarge);
        }
        let valid = match self.status {
            ReconciliationStatus::Pending => {
                self.certificate_chain.is_empty()
                    && self.fingerprint.is_none()
                    && self.allowlist_generation.is_none()
                    && self.not_after_epoch_seconds.is_none()
                    && self.rejection_code.is_none()
            }
            ReconciliationStatus::Issued => {
                !self.certificate_chain.is_empty()
                    && self
                        .fingerprint
                        .is_some_and(|fingerprint| fingerprint != [0; 32])
                    && self
                        .allowlist_generation
                        .is_some_and(|generation| generation > 0)
                    && self
                        .not_after_epoch_seconds
                        .is_some_and(|expiry| expiry > 0)
                    && self.rejection_code.is_none()
            }
            ReconciliationStatus::Rejected => {
                self.certificate_chain.is_empty()
                    && self.fingerprint.is_none()
                    && self.allowlist_generation.is_none()
                    && self.not_after_epoch_seconds.is_none()
                    && self.rejection_code.is_some_and(|code| code > 0)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(ReconciliationWireError::InvalidResult)
        }
    }
}

impl fmt::Debug for ReconciliationResultPayload {
    /// Report status and public shape without dumping certificate bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconciliationResultPayload")
            .field("status", &self.status)
            .field("certificate_count", &self.certificate_chain.len())
            .field(
                "certificate_bytes",
                &self.certificate_chain.iter().map(Vec::len).sum::<usize>(),
            )
            .field("fingerprint_present", &self.fingerprint.is_some())
            .field("allowlist_generation", &self.allowlist_generation)
            .field("not_after_epoch_seconds", &self.not_after_epoch_seconds)
            .field("rejection_code", &self.rejection_code)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST:relay/src/reconciliation_wire.rs[tests::version_two_round_trip_is_bounded]
    #[test]
    fn version_two_round_trip_is_bounded() {
        let request = ReconciliationFrame::json(
            ReconciliationFrameKind::Reconcile,
            &ReconcilePayload {
                authorization_id: [1; 16],
                csr_digest: [2; 32],
            },
            1024,
        )
        .expect("request");
        let bytes = request.encode(1024).expect("encode");
        let decoded = ReconciliationFrame::decode(&bytes, 1024).expect("decode");
        let payload: ReconcilePayload = decoded
            .parse_json(ReconciliationFrameKind::Reconcile)
            .expect("payload");
        assert_eq!(payload.authorization_id, [1; 16]);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 2);
    }

    // TEST:relay/src/reconciliation_wire.rs[tests::version_one_is_rejected]
    #[test]
    fn version_one_is_rejected() {
        let mut bytes = vec![b'H', b'D', b'E', b'1', 0, 1, 5, 0, 0, 0, 2, b'{', b'}'];
        assert_eq!(
            ReconciliationFrame::decode(&bytes, 1024),
            Err(ReconciliationWireError::InvalidFrame)
        );
        bytes[4] = 0;
        bytes[5] = 2;
        bytes[6] = 5;
        assert!(ReconciliationFrame::decode(&bytes, 1024).is_ok());
    }

    // TEST:relay/src/reconciliation_wire.rs[tests::issued_status_requires_public_metadata]
    #[test]
    fn issued_status_requires_public_metadata() {
        let issued = ReconciliationResultPayload {
            status: ReconciliationStatus::Issued,
            certificate_chain: vec![vec![1, 2, 3]],
            fingerprint: Some([4; 32]),
            allowlist_generation: Some(2),
            not_after_epoch_seconds: Some(200),
            rejection_code: None,
        };
        assert!(issued.validate().is_ok());
        let invalid = ReconciliationResultPayload {
            fingerprint: None,
            ..issued
        };
        assert_eq!(
            invalid.validate(),
            Err(ReconciliationWireError::InvalidResult)
        );
    }

    // TEST:relay/src/reconciliation_wire.rs[tests::status_fields_are_fail_closed]
    #[test]
    fn status_fields_are_fail_closed() {
        let pending = ReconciliationResultPayload {
            status: ReconciliationStatus::Pending,
            certificate_chain: Vec::new(),
            fingerprint: None,
            allowlist_generation: None,
            not_after_epoch_seconds: None,
            rejection_code: None,
        };
        assert!(pending.validate().is_ok());
        let invalid = ReconciliationResultPayload {
            status: ReconciliationStatus::Rejected,
            rejection_code: None,
            ..pending
        };
        assert_eq!(
            invalid.validate(),
            Err(ReconciliationWireError::InvalidResult)
        );
    }
}
