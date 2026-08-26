//! Frozen QRM-PROD-2 HDE3 Core-enrollment frame codec for Relay.
//!
//! HDE3 is a Core-enrollment-only namespace.  This module provides the bounded, versioned wire
//! shape needed by later production enrollment work without admitting HDB1, historical HDE1/HDE2,
//! normal QRM, arbitrary Herdr frames, or private material.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// HDE3 frame magic.
pub(crate) const HDE3_MAGIC: [u8; 4] = *b"HDE3";
/// HDE3 wire version.
pub(crate) const HDE3_VERSION: u16 = 3;
/// Fixed HDE3 header size in bytes.
pub(crate) const HDE3_HEADER_BYTES: usize = 11;
/// Maximum complete HDE3 frame, including its header.
pub(crate) const HDE3_MAX_FRAME_BYTES: usize = 64 * 1024;
/// Maximum HDE3 JSON payload after reserving the binary header.
pub(crate) const HDE3_MAX_PAYLOAD_BYTES: usize = HDE3_MAX_FRAME_BYTES - HDE3_HEADER_BYTES;
/// Maximum CSR DER bytes carried by one HDE3 request.
pub(crate) const HDE3_MAX_CSR_BYTES: usize = 16 * 1024;
/// Exact digest width used by HDE3.
pub(crate) const HDE3_DIGEST_BYTES: usize = 32;
/// Exact approval identifier width.
pub(crate) const HDE3_ID_BYTES: usize = 32;
/// Maximum normalized Herdr session name.
pub(crate) const HDE3_MAX_SESSION_BYTES: usize = 64;
/// Maximum public certificate chain bytes retained in one response.
pub(crate) const HDE3_MAX_CHAIN_BYTES: usize = 48 * 1024;
/// Maximum number of certificates in one public chain.
pub(crate) const HDE3_MAX_CHAIN_CERTIFICATES: usize = 8;

/// Decoded first-App CSR submission fields returned to Relay-owned callers.
type Hde3FirstAppSubmitFields = ([u8; HDE3_ID_BYTES], Vec<u8>, [u8; HDE3_DIGEST_BYTES]);

/// Decoded later approval submission fields returned to Relay-owned callers.
type Hde3ApprovalSubmitFields = (
    [u8; HDE3_ID_BYTES],
    [u8; HDE3_DIGEST_BYTES],
    String,
    Vec<u8>,
    [u8; HDE3_DIGEST_BYTES],
);

/// Fixed HDE3 operation registry.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Hde3Kind {
    /// Submits the original App CSR after first Core bootstrap.
    FirstAppSubmit = 1,
    /// Starts a later new-App approval.
    ApprovalStart = 2,
    /// Returns a Relay-minted approval challenge.
    ApprovalChallenge = 3,
    /// Submits the later approval code and App CSR.
    ApprovalSubmit = 4,
    /// Confirms protected App certificate-chain persistence.
    ConfirmPersisted = 5,
    /// Requests exact-binding issuance recovery.
    Reconcile = 6,
    /// Requests a bounded same-key renewal.
    Renew = 7,
    /// Returns a sanitized pending, issued, active, or rejected result.
    Result = 8,
    /// Returns a fixed sanitized rejection.
    Rejected = 9,
}

impl TryFrom<u8> for Hde3Kind {
    type Error = Hde3Error;

    /// Decodes one numeric HDE3 kind without accepting historical aliases.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::FirstAppSubmit),
            2 => Ok(Self::ApprovalStart),
            3 => Ok(Self::ApprovalChallenge),
            4 => Ok(Self::ApprovalSubmit),
            5 => Ok(Self::ConfirmPersisted),
            6 => Ok(Self::Reconcile),
            7 => Ok(Self::Renew),
            8 => Ok(Self::Result),
            9 => Ok(Self::Rejected),
            _ => Err(Hde3Error::InvalidFrame),
        }
    }
}

impl fmt::Debug for Hde3Kind {
    /// Formats the fixed operation name without payload material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FirstAppSubmit => "FirstAppSubmit",
            Self::ApprovalStart => "ApprovalStart",
            Self::ApprovalChallenge => "ApprovalChallenge",
            Self::ApprovalSubmit => "ApprovalSubmit",
            Self::ConfirmPersisted => "ConfirmPersisted",
            Self::Reconcile => "Reconcile",
            Self::Renew => "Renew",
            Self::Result => "Result",
            Self::Rejected => "Rejected",
        })
    }
}

/// Stable local errors for HDE3 framing and payload validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hde3Error {
    /// Magic, version, kind, JSON, or exact-frame shape is invalid.
    InvalidFrame,
    /// The complete frame or bounded field is too large.
    FrameTooLarge,
    /// A frame kind is not valid for the current exchange direction.
    InvalidOrder,
    /// A binary, identifier, session, code, or status field is invalid.
    InvalidField,
}

impl fmt::Display for Hde3Error {
    /// Formats a stable error without exposing payload or identity values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFrame => "HDE3 frame is invalid",
            Self::FrameTooLarge => "HDE3 frame exceeds its bound",
            Self::InvalidOrder => "HDE3 operation order is invalid",
            Self::InvalidField => "HDE3 field is invalid",
        })
    }
}

impl std::error::Error for Hde3Error {}

/// One bounded HDE3 frame with an opaque JSON payload.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Hde3Frame {
    /// Fixed operation kind.
    kind: Hde3Kind,
    /// Bounded UTF-8 JSON payload bytes.
    payload: Vec<u8>,
}

impl fmt::Debug for Hde3Frame {
    /// Reports only kind and payload length.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hde3Frame")
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Hde3Frame {
    /// Serializes one bounded JSON payload into an HDE3 frame.
    pub(crate) fn json<T: Serialize>(kind: Hde3Kind, value: &T) -> Result<Self, Hde3Error> {
        let payload = serde_json::to_vec(value).map_err(|_| Hde3Error::InvalidFrame)?;
        if payload.len() > HDE3_MAX_PAYLOAD_BYTES {
            return Err(Hde3Error::FrameTooLarge);
        }
        Ok(Self { kind, payload })
    }

    /// Returns the fixed operation kind.
    pub(crate) const fn kind(&self) -> Hde3Kind {
        self.kind
    }

    /// Decodes a typed JSON payload after checking its expected operation kind.
    pub(crate) fn parse_json<T: DeserializeOwned>(
        &self,
        expected: Hde3Kind,
    ) -> Result<T, Hde3Error> {
        if self.kind != expected {
            return Err(Hde3Error::InvalidOrder);
        }
        serde_json::from_slice(&self.payload).map_err(|_| Hde3Error::InvalidFrame)
    }

    /// Encodes a complete HDE3 frame with the fixed header.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Hde3Error> {
        if self.payload.len() > HDE3_MAX_PAYLOAD_BYTES {
            return Err(Hde3Error::FrameTooLarge);
        }
        let mut bytes = Vec::with_capacity(HDE3_HEADER_BYTES + self.payload.len());
        bytes.extend_from_slice(&HDE3_MAGIC);
        bytes.extend_from_slice(&HDE3_VERSION.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decodes one complete HDE3 frame without allocating beyond the frame bound.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Hde3Error> {
        if bytes.len() < HDE3_HEADER_BYTES || bytes.len() > HDE3_MAX_FRAME_BYTES {
            return Err(if bytes.len() > HDE3_MAX_FRAME_BYTES {
                Hde3Error::FrameTooLarge
            } else {
                Hde3Error::InvalidFrame
            });
        }
        if bytes[..4] != HDE3_MAGIC || u16::from_be_bytes([bytes[4], bytes[5]]) != HDE3_VERSION {
            return Err(Hde3Error::InvalidFrame);
        }
        let kind = Hde3Kind::try_from(bytes[6])?;
        let payload_len = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
        if payload_len > HDE3_MAX_PAYLOAD_BYTES {
            return Err(Hde3Error::FrameTooLarge);
        }
        if bytes.len() != HDE3_HEADER_BYTES + payload_len {
            return Err(Hde3Error::InvalidFrame);
        }
        Ok(Self {
            kind,
            payload: bytes[HDE3_HEADER_BYTES..].to_vec(),
        })
    }
}

/// Reads one bounded HDE3 frame from an asynchronous byte stream.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Hde3Frame, Hde3Error> {
    let mut header = [0_u8; HDE3_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| Hde3Error::InvalidFrame)?;
    let payload_len = u32::from_be_bytes([header[7], header[8], header[9], header[10]]) as usize;
    if payload_len > HDE3_MAX_PAYLOAD_BYTES {
        return Err(Hde3Error::FrameTooLarge);
    }
    let mut bytes = Vec::with_capacity(HDE3_HEADER_BYTES + payload_len);
    bytes.extend_from_slice(&header);
    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| Hde3Error::InvalidFrame)?;
    bytes.extend_from_slice(&payload);
    Hde3Frame::decode(&bytes)
}

/// Writes one bounded HDE3 frame to an asynchronous byte stream.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Hde3Frame,
) -> Result<(), Hde3Error> {
    writer
        .write_all(&frame.encode()?)
        .await
        .map_err(|_| Hde3Error::InvalidFrame)
}

/// Core-to-Relay first App CSR submission after Core bootstrap.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hde3FirstAppSubmitPayload {
    /// Durable bootstrap approval identifier encoded as base64url.
    pub(crate) approval_id: String,
    /// Original App CSR DER encoded as canonical base64url.
    pub(crate) app_csr: String,
    /// SHA-256 digest of the App CSR DER encoded as lowercase hex.
    pub(crate) app_csr_digest: String,
}

impl Hde3FirstAppSubmitPayload {
    /// Validates and decodes the first-App submission fields.
    pub(crate) fn decode_fields(&self) -> Result<Hde3FirstAppSubmitFields, Hde3Error> {
        let approval_id = decode_base64_exact::<HDE3_ID_BYTES>(&self.approval_id)?;
        let app_csr = decode_base64_bounded(&self.app_csr, HDE3_MAX_CSR_BYTES)?;
        let app_csr_digest = decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.app_csr_digest)?;
        validate_csr_digest(&app_csr, &app_csr_digest)?;
        Ok((approval_id, app_csr, app_csr_digest))
    }
}

/// Core-to-Relay later App approval start payload.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hde3ApprovalStartPayload {
    /// SHA-256 digest of the new App CSR DER encoded as lowercase hex.
    pub(crate) app_csr_digest: String,
    /// Normalized Herdr session name.
    pub(crate) normalized_session: String,
    /// Core binding digest encoded as lowercase hex.
    pub(crate) core_binding_digest: String,
    /// Exact Profile configuration generation.
    pub(crate) configuration_generation: u64,
}

impl Hde3ApprovalStartPayload {
    /// Validates the later approval-start binding fields.
    pub(crate) fn validate(&self) -> Result<(), Hde3Error> {
        decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.app_csr_digest)?;
        decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.core_binding_digest)?;
        validate_session(&self.normalized_session)?;
        if self.configuration_generation == 0 {
            return Err(Hde3Error::InvalidField);
        }
        Ok(())
    }
}

/// Relay-to-Core later approval challenge payload.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hde3ApprovalChallengePayload {
    /// Relay-minted approval identifier encoded as base64url.
    pub(crate) approval_id: String,
    /// Relay challenge encoded as base64url.
    pub(crate) challenge: String,
    /// Protected challenge expiry in epoch seconds.
    pub(crate) expires_at_epoch_seconds: u64,
}

impl Hde3ApprovalChallengePayload {
    /// Validates and decodes the later approval challenge.
    pub(crate) fn decode_fields(
        &self,
    ) -> Result<([u8; HDE3_ID_BYTES], [u8; HDE3_DIGEST_BYTES], u64), Hde3Error> {
        let approval_id = decode_base64_exact::<HDE3_ID_BYTES>(&self.approval_id)?;
        let challenge = decode_base64_exact::<HDE3_DIGEST_BYTES>(&self.challenge)?;
        if self.expires_at_epoch_seconds == 0 {
            return Err(Hde3Error::InvalidField);
        }
        Ok((approval_id, challenge, self.expires_at_epoch_seconds))
    }
}

/// Core-to-Relay later approval submit payload with transient code and CSR.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hde3ApprovalSubmitPayload {
    /// Approval identifier returned by ApprovalChallenge.
    pub(crate) approval_id: String,
    /// Challenge echo encoded as base64url.
    pub(crate) challenge: String,
    /// Six ASCII digits entered by the user.
    pub(crate) code: String,
    /// App CSR DER encoded as canonical base64url.
    pub(crate) app_csr: String,
    /// SHA-256 digest of the App CSR DER encoded as lowercase hex.
    pub(crate) app_csr_digest: String,
}

impl Hde3ApprovalSubmitPayload {
    /// Validates and decodes a later approval submission.
    pub(crate) fn decode_fields(&self) -> Result<Hde3ApprovalSubmitFields, Hde3Error> {
        let approval_id = decode_base64_exact::<HDE3_ID_BYTES>(&self.approval_id)?;
        let challenge = decode_base64_exact::<HDE3_DIGEST_BYTES>(&self.challenge)?;
        validate_code(&self.code)?;
        let app_csr = decode_base64_bounded(&self.app_csr, HDE3_MAX_CSR_BYTES)?;
        let app_csr_digest = decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.app_csr_digest)?;
        validate_csr_digest(&app_csr, &app_csr_digest)?;
        Ok((
            approval_id,
            challenge,
            self.code.clone(),
            app_csr,
            app_csr_digest,
        ))
    }
}

/// Core-to-Relay protected App certificate persistence confirmation.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hde3ConfirmPersistedPayload {
    /// Approval identifier encoded as base64url.
    pub(crate) approval_id: String,
    /// App certificate leaf identity encoded as lowercase hex.
    pub(crate) app_identity: String,
    /// Issued certificate leaf fingerprint encoded as lowercase hex.
    pub(crate) issued_certificate_fingerprint: String,
    /// Digest of the returned public chain encoded as lowercase hex.
    pub(crate) issued_certificate_chain_digest: String,
    /// Exact Profile configuration generation.
    pub(crate) configuration_generation: u64,
}

impl Hde3ConfirmPersistedPayload {
    /// Validates the exact confirmation identity and generation binding.
    pub(crate) fn validate(&self) -> Result<(), Hde3Error> {
        decode_base64_exact::<HDE3_ID_BYTES>(&self.approval_id)?;
        decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.app_identity)?;
        decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.issued_certificate_fingerprint)?;
        decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.issued_certificate_chain_digest)?;
        if self.configuration_generation == 0 {
            return Err(Hde3Error::InvalidField);
        }
        Ok(())
    }
}

/// Core-to-Relay exact-binding issuance recovery request.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hde3ReconcilePayload {
    /// Approval identifier encoded as base64url.
    pub(crate) approval_id: String,
    /// App CSR digest encoded as lowercase hex.
    pub(crate) app_csr_digest: String,
    /// Normalized Herdr session name.
    pub(crate) normalized_session: String,
    /// Core binding digest encoded as lowercase hex.
    pub(crate) core_binding_digest: String,
    /// Exact Profile configuration generation.
    pub(crate) configuration_generation: u64,
}

impl Hde3ReconcilePayload {
    /// Validates the persisted reconciliation binding.
    pub(crate) fn validate(&self) -> Result<(), Hde3Error> {
        decode_base64_exact::<HDE3_ID_BYTES>(&self.approval_id)?;
        decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.app_csr_digest)?;
        decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.core_binding_digest)?;
        validate_session(&self.normalized_session)?;
        if self.configuration_generation == 0 {
            return Err(Hde3Error::InvalidField);
        }
        Ok(())
    }
}

/// Core-to-Relay same-key renewal request.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hde3RenewPayload {
    /// Existing App certificate identity encoded as lowercase hex.
    pub(crate) existing_app_identity: String,
    /// Same-key App CSR DER encoded as canonical base64url.
    pub(crate) app_csr: String,
    /// SHA-256 digest of the same-key App CSR encoded as lowercase hex.
    pub(crate) app_csr_digest: String,
    /// Normalized Herdr session name.
    pub(crate) normalized_session: String,
    /// Core binding digest encoded as lowercase hex.
    pub(crate) core_binding_digest: String,
    /// Exact Profile configuration generation.
    pub(crate) configuration_generation: u64,
}

impl Hde3RenewPayload {
    /// Validates and bounds a same-key renewal request.
    pub(crate) fn validate(&self) -> Result<(), Hde3Error> {
        decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.existing_app_identity)?;
        let csr = decode_base64_bounded(&self.app_csr, HDE3_MAX_CSR_BYTES)?;
        let csr_digest = decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.app_csr_digest)?;
        validate_csr_digest(&csr, &csr_digest)?;
        decode_hex_exact::<HDE3_DIGEST_BYTES>(&self.core_binding_digest)?;
        validate_session(&self.normalized_session)?;
        if self.configuration_generation == 0 {
            return Err(Hde3Error::InvalidField);
        }
        Ok(())
    }
}

/// Sanitized HDE3 result state.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Hde3ResultStatus {
    /// The Relay has consumed an authorization but has no terminal result yet.
    Pending,
    /// The Relay has issued the same public certificate chain.
    Issued,
    /// Protected App persistence has been confirmed and identity is active.
    Active,
    /// The Relay has a terminal sanitized rejection.
    Rejected,
}

impl fmt::Debug for Hde3ResultStatus {
    /// Formats the stable result state.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pending => "Pending",
            Self::Issued => "Issued",
            Self::Active => "Active",
            Self::Rejected => "Rejected",
        })
    }
}

/// Relay-to-Core sanitized HDE3 result payload.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hde3ResultPayload {
    /// Approval identifier encoded as base64url.
    pub(crate) approval_id: String,
    /// Current sanitized result state.
    pub(crate) status: Hde3ResultStatus,
    /// App certificate identity, present for Issued or Active.
    pub(crate) app_identity: Option<String>,
    /// Public certificate chain, always present for Issued or Active replay and confirmation.
    pub(crate) certificate_chain: Option<Vec<String>>,
    /// Public leaf fingerprint, present for Issued or Active.
    pub(crate) certificate_fingerprint: Option<String>,
    /// Public chain digest, present for Issued or Active.
    pub(crate) certificate_chain_digest: Option<String>,
    /// Public certificate expiry, present for Issued or Active.
    pub(crate) not_after_epoch_seconds: Option<u64>,
    /// Profile configuration generation, present for Issued or Active.
    pub(crate) configuration_generation: Option<u64>,
    /// Nonzero sanitized rejection code, present only for Rejected.
    pub(crate) rejection_code: Option<u16>,
}

impl Hde3ResultPayload {
    /// Validates status-specific result fields without exposing certificate bytes.
    pub(crate) fn validate(&self) -> Result<(), Hde3Error> {
        decode_base64_exact::<HDE3_ID_BYTES>(&self.approval_id)?;
        match self.status {
            Hde3ResultStatus::Pending => {
                if self.app_identity.is_some()
                    || self.certificate_chain.is_some()
                    || self.certificate_fingerprint.is_some()
                    || self.certificate_chain_digest.is_some()
                    || self.not_after_epoch_seconds.is_some()
                    || self.configuration_generation.is_some()
                    || self.rejection_code.is_some()
                {
                    return Err(Hde3Error::InvalidField);
                }
            }
            Hde3ResultStatus::Issued | Hde3ResultStatus::Active => {
                decode_hex_exact::<HDE3_DIGEST_BYTES>(
                    self.app_identity
                        .as_deref()
                        .ok_or(Hde3Error::InvalidField)?,
                )?;
                decode_hex_exact::<HDE3_DIGEST_BYTES>(
                    self.certificate_fingerprint
                        .as_deref()
                        .ok_or(Hde3Error::InvalidField)?,
                )?;
                decode_hex_exact::<HDE3_DIGEST_BYTES>(
                    self.certificate_chain_digest
                        .as_deref()
                        .ok_or(Hde3Error::InvalidField)?,
                )?;
                let chain = self
                    .certificate_chain
                    .as_ref()
                    .ok_or(Hde3Error::InvalidField)?;
                decode_certificate_chain(chain)?;
                if self.not_after_epoch_seconds.unwrap_or(0) == 0
                    || self.configuration_generation.unwrap_or(0) == 0
                    || self.rejection_code.is_some()
                {
                    return Err(Hde3Error::InvalidField);
                }
            }
            Hde3ResultStatus::Rejected => {
                if self.rejection_code.unwrap_or(0) == 0
                    || self.app_identity.is_some()
                    || self.certificate_chain.is_some()
                    || self.certificate_fingerprint.is_some()
                    || self.certificate_chain_digest.is_some()
                    || self.not_after_epoch_seconds.is_some()
                    || self.configuration_generation.is_some()
                {
                    return Err(Hde3Error::InvalidField);
                }
            }
        }
        Ok(())
    }
}

/// Relay-to-Core terminal HDE3 rejection payload.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hde3RejectedPayload {
    /// Stable nonzero rejection code.
    pub(crate) code: u16,
}

impl Hde3RejectedPayload {
    /// Validates the fixed sanitized rejection shape.
    pub(crate) fn validate(&self) -> Result<(), Hde3Error> {
        if self.code == 0 {
            return Err(Hde3Error::InvalidField);
        }
        Ok(())
    }
}

/// Verify that a transient CSR is bound to its declared SHA-256 digest.
fn validate_csr_digest(csr: &[u8], expected: &[u8; HDE3_DIGEST_BYTES]) -> Result<(), Hde3Error> {
    let actual: [u8; HDE3_DIGEST_BYTES] = Sha256::digest(csr).into();
    if actual == *expected {
        Ok(())
    } else {
        Err(Hde3Error::InvalidField)
    }
}

/// Encode bytes using canonical unpadded base64url for JSON fields.
fn encode_base64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode one canonical base64url field with an exact byte width.
fn decode_base64_exact<const N: usize>(value: &str) -> Result<[u8; N], Hde3Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Hde3Error::InvalidField)?;
    if bytes.len() != N || encode_base64(&bytes) != value {
        return Err(Hde3Error::InvalidField);
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(&bytes);
    if output == [0; N] {
        return Err(Hde3Error::InvalidField);
    }
    Ok(output)
}

/// Decode a bounded non-empty base64url field.
fn decode_base64_bounded(value: &str, max_bytes: usize) -> Result<Vec<u8>, Hde3Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Hde3Error::InvalidField)?;
    if bytes.is_empty() || bytes.len() > max_bytes || encode_base64(&bytes) != value {
        return Err(if bytes.len() > max_bytes {
            Hde3Error::FrameTooLarge
        } else {
            Hde3Error::InvalidField
        });
    }
    Ok(bytes)
}

/// Encode a fixed digest as lowercase hexadecimal.
fn encode_hex<const N: usize>(bytes: &[u8; N]) -> String {
    let mut output = String::with_capacity(N * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

/// Decode a fixed lowercase hexadecimal field.
fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], Hde3Error> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Hde3Error::InvalidField);
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(Hde3Error::InvalidField);
    }
    let mut output = [0_u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        output[index] = (high << 4) | low;
    }
    if output == [0; N] {
        return Err(Hde3Error::InvalidField);
    }
    Ok(output)
}

/// Decode one known lowercase hexadecimal nibble.
fn hex_nibble(byte: u8) -> Result<u8, Hde3Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Hde3Error::InvalidField),
    }
}

/// Validate the source-aligned normalized Herdr session contract.
fn validate_session(value: &str) -> Result<(), Hde3Error> {
    if value.is_empty()
        || value.len() > HDE3_MAX_SESSION_BYTES
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Hde3Error::InvalidField);
    }
    Ok(())
}

/// Validate exactly six ASCII digits, including leading zeroes.
fn validate_code(value: &str) -> Result<(), Hde3Error> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Hde3Error::InvalidField);
    }
    Ok(())
}

/// Decode and bound a public certificate chain without exposing it in diagnostics.
fn decode_certificate_chain(values: &[String]) -> Result<Vec<Vec<u8>>, Hde3Error> {
    if values.is_empty() || values.len() > HDE3_MAX_CHAIN_CERTIFICATES {
        return Err(Hde3Error::InvalidField);
    }
    let mut total = 0_usize;
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let certificate = decode_base64_bounded(value, HDE3_MAX_CHAIN_BYTES)?;
        total = total
            .checked_add(certificate.len())
            .ok_or(Hde3Error::FrameTooLarge)?;
        if total > HDE3_MAX_CHAIN_BYTES {
            return Err(Hde3Error::FrameTooLarge);
        }
        output.push(certificate);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Compute the actual SHA-256 digest for a transient CSR fixture.
    fn csr_digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// Build a canonical first-App submission fixture.
    fn first_submit() -> Hde3FirstAppSubmitPayload {
        Hde3FirstAppSubmitPayload {
            approval_id: encode_base64(&[1; 32]),
            app_csr: encode_base64(&[2; 4]),
            app_csr_digest: encode_hex(&csr_digest(&[2; 4])),
        }
    }

    /// Verify every frozen HDE3 kind has its assigned numeric value.
    #[test]
    // TEST:relay/src/enrollment_v3_wire.rs[tests::kind_registry_is_frozen]
    fn kind_registry_is_frozen() {
        assert_eq!(Hde3Kind::FirstAppSubmit as u8, 1);
        assert_eq!(Hde3Kind::ApprovalStart as u8, 2);
        assert_eq!(Hde3Kind::ApprovalChallenge as u8, 3);
        assert_eq!(Hde3Kind::ApprovalSubmit as u8, 4);
        assert_eq!(Hde3Kind::ConfirmPersisted as u8, 5);
        assert_eq!(Hde3Kind::Reconcile as u8, 6);
        assert_eq!(Hde3Kind::Renew as u8, 7);
        assert_eq!(Hde3Kind::Result as u8, 8);
        assert_eq!(Hde3Kind::Rejected as u8, 9);
    }

    /// Verify CSR and digest fields use canonical bounded encodings.
    #[test]
    // TEST:relay/src/enrollment_v3_wire.rs[tests::first_submit_fields_are_bounded]
    fn first_submit_fields_are_bounded() {
        let fields = first_submit().decode_fields().expect("fields");
        assert_eq!(fields.0, [1; 32]);
        assert_eq!(fields.1, vec![2; 4]);
        assert_eq!(fields.2, csr_digest(&[2; 4]));
    }

    /// Reject uppercase hex, padded base64url, and zero approval IDs.
    #[test]
    // TEST:relay/src/enrollment_v3_wire.rs[tests::binary_fields_fail_closed]
    fn binary_fields_fail_closed() {
        let mut payload = first_submit();
        payload.app_csr_digest.replace_range(..1, "A");
        assert!(payload.decode_fields().is_err());
        let mut payload = first_submit();
        payload.app_csr_digest = encode_hex(&[9; 32]);
        assert!(payload.decode_fields().is_err());
        let mut payload = first_submit();
        payload.approval_id.push('=');
        assert!(payload.decode_fields().is_err());
        payload.approval_id = encode_base64(&[0; 32]);
        assert!(payload.decode_fields().is_err());
    }

    /// Ensure the complete-frame bound includes the binary header.
    #[test]
    // TEST:relay/src/enrollment_v3_wire.rs[tests::frame_bound_includes_header]
    fn frame_bound_includes_header() {
        let frame = Hde3Frame {
            kind: Hde3Kind::Result,
            payload: vec![b' '; HDE3_MAX_PAYLOAD_BYTES],
        };
        assert!(frame.encode().is_ok());
        let oversized = Hde3Frame {
            kind: Hde3Kind::Result,
            payload: vec![b' '; HDE3_MAX_PAYLOAD_BYTES + 1],
        };
        assert_eq!(oversized.encode(), Err(Hde3Error::FrameTooLarge));
    }

    /// Reject HDB1 and historical HDE1 magic in the HDE3 decoder.
    #[test]
    // TEST:relay/src/enrollment_v3_wire.rs[tests::other_namespaces_are_rejected]
    fn other_namespaces_are_rejected() {
        let mut bytes = Hde3Frame::json(Hde3Kind::Rejected, &Hde3RejectedPayload { code: 1 })
            .expect("frame")
            .encode()
            .expect("bytes");
        bytes[..4].copy_from_slice(b"HDB1");
        assert_eq!(Hde3Frame::decode(&bytes), Err(Hde3Error::InvalidFrame));
        bytes[..4].copy_from_slice(b"HDE1");
        assert_eq!(Hde3Frame::decode(&bytes), Err(Hde3Error::InvalidFrame));
    }

    /// Require exactly six ASCII digits for the later approval code.
    #[test]
    // TEST:relay/src/enrollment_v3_wire.rs[tests::approval_code_is_strict]
    fn approval_code_is_strict() {
        let valid = Hde3ApprovalSubmitPayload {
            approval_id: encode_base64(&[1; 32]),
            challenge: encode_base64(&[2; 32]),
            code: "000007".to_owned(),
            app_csr: encode_base64(&[3; 4]),
            app_csr_digest: encode_hex(&csr_digest(&[3; 4])),
        };
        assert!(valid.decode_fields().is_ok());
        let mut invalid = valid;
        invalid.code = "12345".to_owned();
        assert!(invalid.decode_fields().is_err());
    }

    /// Ensure Result states do not mix terminal and public certificate fields.
    #[test]
    // TEST:relay/src/enrollment_v3_wire.rs[tests::result_status_fields_are_exclusive]
    fn result_status_fields_are_exclusive() {
        let pending = Hde3ResultPayload {
            approval_id: encode_base64(&[1; 32]),
            status: Hde3ResultStatus::Pending,
            app_identity: None,
            certificate_chain: None,
            certificate_fingerprint: None,
            certificate_chain_digest: None,
            not_after_epoch_seconds: None,
            configuration_generation: None,
            rejection_code: None,
        };
        assert!(pending.validate().is_ok());
        let mut invalid = pending;
        invalid.rejection_code = Some(1);
        assert!(invalid.validate().is_err());
    }

    /// Verify asynchronous frame helpers preserve HDE3 over segmented I/O.
    #[tokio::test]
    // TEST:relay/src/enrollment_v3_wire.rs[tests::async_frame_round_trip]
    async fn async_frame_round_trip() {
        let frame = Hde3Frame::json(Hde3Kind::FirstAppSubmit, &first_submit()).expect("frame");
        let (mut writer, mut reader) = duplex(HDE3_MAX_FRAME_BYTES);
        let encoded = frame.encode().expect("bytes");
        let writer_task = tokio::spawn(async move {
            for chunk in encoded.chunks(5) {
                writer.write_all(chunk).await.expect("write");
            }
        });
        let received = read_frame(&mut reader).await.expect("read");
        writer_task.await.expect("writer");
        assert_eq!(received.kind(), Hde3Kind::FirstAppSubmit);
        let _: Hde3FirstAppSubmitPayload = received
            .parse_json(Hde3Kind::FirstAppSubmit)
            .expect("payload");
    }
}
