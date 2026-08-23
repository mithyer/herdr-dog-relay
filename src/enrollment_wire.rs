//! Bounded same-port enrollment frames.
//!
//! Enrollment uses a separate binary framing namespace and JSON payloads only for the bounded
//! typed fields. Raw CSR bytes exist only in one transient request value and are never logged or
//! persisted.

use crate::enrollment::EnrollmentError;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Enrollment framing magic.
pub const ENROLLMENT_MAGIC: [u8; 4] = *b"HDE1";
/// Enrollment framing version.
pub const ENROLLMENT_VERSION: u16 = 1;
/// Fixed enrollment frame header width.
pub const ENROLLMENT_HEADER_BYTES: usize = 11;

/// One bounded enrollment operation kind.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum EnrollmentFrameKind {
    /// Relay challenge sent after Core mTLS and enrollment ALPN.
    Challenge = 1,
    /// Core-authorized App CSR submission.
    Submit = 2,
    /// Public certificate chain and metadata.
    Issued = 3,
    /// Sanitized terminal rejection.
    Rejected = 4,
}

impl TryFrom<u8> for EnrollmentFrameKind {
    type Error = EnrollmentWireError;

    /// Decodes one bounded enrollment operation kind.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Challenge),
            2 => Ok(Self::Submit),
            3 => Ok(Self::Issued),
            4 => Ok(Self::Rejected),
            _ => Err(EnrollmentWireError::InvalidFrame),
        }
    }
}

impl fmt::Debug for EnrollmentFrameKind {
    /// Formats an enrollment kind without payload material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Challenge => "Challenge",
            Self::Submit => "Submit",
            Self::Issued => "Issued",
            Self::Rejected => "Rejected",
        })
    }
}

/// Stable bounded enrollment wire errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum EnrollmentWireError {
    /// Frame magic/version/kind/JSON shape is invalid.
    InvalidFrame = 1,
    /// Frame exceeds the configured request bound.
    FrameTooLarge = 2,
    /// Peer sent an operation in the wrong order.
    InvalidOrder = 3,
    /// Enrollment authorization or CSR binding failed.
    AuthorizationRejected = 4,
    /// Certificate/allowlist persistence failed.
    PersistenceFailed = 5,
    /// Enrollment connection quota or lifetime was exceeded.
    ResourceLimit = 6,
}

impl From<EnrollmentError> for EnrollmentWireError {
    /// Maps internal enrollment errors to a stable sanitized wire category.
    fn from(error: EnrollmentError) -> Self {
        match error {
            EnrollmentError::AllowlistPersistence => Self::PersistenceFailed,
            EnrollmentError::UpdateBusy => Self::ResourceLimit,
            _ => Self::AuthorizationRejected,
        }
    }
}

/// One bounded enrollment frame with opaque serialized payload.
#[derive(Clone, Eq, PartialEq)]
pub struct EnrollmentFrame {
    /// Operation kind.
    pub kind: EnrollmentFrameKind,
    /// Bounded serialized payload.
    pub payload: Vec<u8>,
}

impl fmt::Debug for EnrollmentFrame {
    /// Reports only operation and payload size.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentFrame")
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl EnrollmentFrame {
    /// Encodes one bounded enrollment frame.
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, EnrollmentWireError> {
        if self.payload.len() > max_bytes || self.payload.len() > u32::MAX as usize {
            return Err(EnrollmentWireError::FrameTooLarge);
        }
        let mut bytes = Vec::with_capacity(ENROLLMENT_HEADER_BYTES + self.payload.len());
        bytes.extend_from_slice(&ENROLLMENT_MAGIC);
        bytes.extend_from_slice(&ENROLLMENT_VERSION.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decodes one complete bounded frame from bytes.
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, EnrollmentWireError> {
        if bytes.len() < ENROLLMENT_HEADER_BYTES {
            return Err(EnrollmentWireError::InvalidFrame);
        }
        if bytes[..4] != ENROLLMENT_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != ENROLLMENT_VERSION
        {
            return Err(EnrollmentWireError::InvalidFrame);
        }
        let kind = EnrollmentFrameKind::try_from(bytes[6])?;
        let payload_len = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
        if payload_len > max_bytes || bytes.len() != ENROLLMENT_HEADER_BYTES + payload_len {
            return Err(if payload_len > max_bytes {
                EnrollmentWireError::FrameTooLarge
            } else {
                EnrollmentWireError::InvalidFrame
            });
        }
        Ok(Self {
            kind,
            payload: bytes[ENROLLMENT_HEADER_BYTES..].to_vec(),
        })
    }

    /// Serializes one typed payload into a bounded frame.
    pub fn json<T: Serialize>(
        kind: EnrollmentFrameKind,
        value: &T,
        max_bytes: usize,
    ) -> Result<Self, EnrollmentWireError> {
        let payload = serde_json::to_vec(value).map_err(|_| EnrollmentWireError::InvalidFrame)?;
        if payload.len() > max_bytes {
            return Err(EnrollmentWireError::FrameTooLarge);
        }
        Ok(Self { kind, payload })
    }

    /// Deserializes one typed payload after operation-kind validation.
    pub fn parse_json<T: DeserializeOwned>(
        &self,
        expected: EnrollmentFrameKind,
    ) -> Result<T, EnrollmentWireError> {
        if self.kind != expected {
            return Err(EnrollmentWireError::InvalidOrder);
        }
        serde_json::from_slice(&self.payload).map_err(|_| EnrollmentWireError::InvalidFrame)
    }
}

/// Reads one bounded enrollment frame from an async byte stream.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<EnrollmentFrame, EnrollmentWireError> {
    let mut header = [0_u8; ENROLLMENT_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| EnrollmentWireError::InvalidFrame)?;
    let payload_len = u32::from_be_bytes([header[7], header[8], header[9], header[10]]) as usize;
    if payload_len > max_bytes {
        return Err(EnrollmentWireError::FrameTooLarge);
    }
    let mut bytes = Vec::with_capacity(ENROLLMENT_HEADER_BYTES + payload_len);
    bytes.extend_from_slice(&header);
    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| EnrollmentWireError::InvalidFrame)?;
    bytes.extend_from_slice(&payload);
    EnrollmentFrame::decode(&bytes, max_bytes)
}

/// Writes one bounded enrollment frame to an async byte stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &EnrollmentFrame,
    max_bytes: usize,
) -> Result<(), EnrollmentWireError> {
    let bytes = frame.encode(max_bytes)?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| EnrollmentWireError::InvalidFrame)
}

/// Relay challenge payload sent before any CSR or authorization.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChallengePayload {
    /// Relay-minted challenge bytes.
    pub challenge: [u8; 32],
    /// Epoch-second expiry shown to Core for reconciliation.
    pub expires_at_epoch_seconds: u64,
}

/// Core-authorized enrollment submission payload.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentSubmitPayload {
    /// App installation identity.
    pub app_id: String,
    /// Exact Profile identity.
    pub pairing_id: String,
    /// Stable Target identity.
    pub target_id: String,
    /// Core client certificate fingerprint.
    pub core_identity: [u8; 32],
    /// Single-use Core authorization ID.
    pub authorization_id: [u8; 16],
    /// Relay challenge echoed by Core.
    pub challenge: [u8; 32],
    /// Core code-proof digest; raw code never crosses the wire.
    pub code_proof: [u8; 32],
    /// Profile configuration generation.
    pub configuration_generation: u64,
    /// Authorization expiry epoch seconds.
    pub expires_at_epoch_seconds: u64,
    /// Bounded raw CSR, retained only for validation and signing.
    pub csr: Vec<u8>,
}

/// Public certificate issuance response payload.
#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentIssuedPayload {
    /// Public DER leaf and Intermediate chain.
    pub certificate_chain: Vec<Vec<u8>>,
    /// Public leaf fingerprint.
    pub fingerprint: [u8; 32],
    /// Allowlist generation after atomic persistence.
    pub allowlist_generation: u64,
    /// Certificate expiry epoch seconds.
    pub not_after_epoch_seconds: u64,
}

/// Sanitized terminal rejection payload.
#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRejectedPayload {
    /// Stable numeric rejection category.
    pub code: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST:relay/src/enrollment_wire.rs[tests::enrollment_frame_round_trip_is_bounded]
    #[test]
    fn enrollment_frame_round_trip_is_bounded() {
        let frame = EnrollmentFrame::json(
            EnrollmentFrameKind::Challenge,
            &EnrollmentChallengePayload {
                challenge: [7; 32],
                expires_at_epoch_seconds: 10,
            },
            1024,
        )
        .expect("frame");
        let bytes = frame.encode(1024).expect("encode");
        let decoded = EnrollmentFrame::decode(&bytes, 1024).expect("decode");
        let payload: EnrollmentChallengePayload = decoded
            .parse_json(EnrollmentFrameKind::Challenge)
            .expect("payload");
        assert_eq!(payload.challenge, [7; 32]);
        assert!(frame.encode(1).is_err());
    }
}
