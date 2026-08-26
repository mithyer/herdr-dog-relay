//! Frozen QRM-PROD-2 HDB1 bootstrap frame codec for Relay.
//!
//! The codec is limited to the server-authenticated bootstrap namespace.  It validates bounded
//! JSON fields before a future verifier can use them and deliberately exposes no workspace,
//! private-key, or Herdr payload representation in diagnostics.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// HDB1 frame magic.
pub(crate) const HDB1_MAGIC: [u8; 4] = *b"HDB1";
/// HDB1 wire version.
pub(crate) const HDB1_VERSION: u16 = 1;
/// Fixed HDB1 header size in bytes.
pub(crate) const HDB1_HEADER_BYTES: usize = 11;
/// Maximum complete HDB1 frame, including its header.
pub(crate) const HDB1_MAX_FRAME_BYTES: usize = 64 * 1024;
/// Maximum HDB1 JSON payload after reserving the binary header.
pub(crate) const HDB1_MAX_PAYLOAD_BYTES: usize = HDB1_MAX_FRAME_BYTES - HDB1_HEADER_BYTES;
/// Maximum CSR DER bytes carried by one HDB1 request.
pub(crate) const HDB1_MAX_CSR_BYTES: usize = crate::HDB1_MAX_CSR_BYTES;
/// Exact digest width used by HDB1.
pub(crate) const HDB1_DIGEST_BYTES: usize = 32;
/// Exact bootstrap and approval identifier width.
pub(crate) const HDB1_ID_BYTES: usize = 32;
/// Exact non-authoritative request identifier width.
pub(crate) const HDB1_REQUEST_ID_BYTES: usize = 16;
/// Maximum normalized Herdr session name.
pub(crate) const HDB1_MAX_SESSION_BYTES: usize = crate::HDB1_MAX_SESSION_BYTES;
/// Maximum public certificate chain bytes retained in one response.
pub(crate) const HDB1_MAX_CHAIN_BYTES: usize = 48 * 1024;
/// Maximum number of certificates in one public chain.
pub(crate) const HDB1_MAX_CHAIN_CERTIFICATES: usize = 8;

/// Decoded HDB1 Start fields returned to Relay-owned callers.
type Hdb1StartFields = (
    [u8; HDB1_REQUEST_ID_BYTES],
    Vec<u8>,
    [u8; HDB1_DIGEST_BYTES],
    String,
    [u8; HDB1_DIGEST_BYTES],
);

/// Decoded HDB1 exact-binding recovery fields returned to Relay-owned callers.
type Hdb1ReconcileFields = ([u8; HDB1_ID_BYTES], [u8; HDB1_DIGEST_BYTES], String);

/// Fixed HDB1 operation registry.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Hdb1Kind {
    /// Starts the server-authenticated Core bootstrap.
    Start = 1,
    /// Returns a Relay-minted bootstrap challenge.
    Challenge = 2,
    /// Submits the user-entered six-digit code.
    Submit = 3,
    /// Returns the issued Core public certificate metadata.
    CoreIssued = 4,
    /// Requests exact-binding bootstrap recovery.
    Reconcile = 5,
    /// Returns a pending, issued, or terminal recovery result.
    Result = 6,
    /// Returns a fixed sanitized rejection.
    Rejected = 7,
}

impl TryFrom<u8> for Hdb1Kind {
    type Error = Hdb1Error;

    /// Decodes one numeric HDB1 kind without accepting aliases.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Start),
            2 => Ok(Self::Challenge),
            3 => Ok(Self::Submit),
            4 => Ok(Self::CoreIssued),
            5 => Ok(Self::Reconcile),
            6 => Ok(Self::Result),
            7 => Ok(Self::Rejected),
            _ => Err(Hdb1Error::InvalidFrame),
        }
    }
}

impl fmt::Debug for Hdb1Kind {
    /// Formats the fixed operation name without payload material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Start => "Start",
            Self::Challenge => "Challenge",
            Self::Submit => "Submit",
            Self::CoreIssued => "CoreIssued",
            Self::Reconcile => "Reconcile",
            Self::Result => "Result",
            Self::Rejected => "Rejected",
        })
    }
}

/// Stable local errors for HDB1 framing and payload validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hdb1Error {
    /// Magic, version, kind, JSON, or exact-frame shape is invalid.
    InvalidFrame,
    /// The complete frame or bounded field is too large.
    FrameTooLarge,
    /// A frame kind is not valid for the current exchange direction.
    InvalidOrder,
    /// A binary, identifier, session, code, or status field is invalid.
    InvalidField,
}

impl fmt::Display for Hdb1Error {
    /// Formats a stable error without exposing payload or identity values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFrame => "HDB1 frame is invalid",
            Self::FrameTooLarge => "HDB1 frame exceeds its bound",
            Self::InvalidOrder => "HDB1 operation order is invalid",
            Self::InvalidField => "HDB1 field is invalid",
        })
    }
}

impl std::error::Error for Hdb1Error {}

/// One bounded HDB1 frame with an opaque JSON payload.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Hdb1Frame {
    /// Fixed operation kind.
    kind: Hdb1Kind,
    /// Bounded UTF-8 JSON payload bytes.
    payload: Vec<u8>,
}

impl fmt::Debug for Hdb1Frame {
    /// Reports only kind and payload length.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hdb1Frame")
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Hdb1Frame {
    /// Serializes one bounded JSON payload into an HDB1 frame.
    pub(crate) fn json<T: Serialize>(kind: Hdb1Kind, value: &T) -> Result<Self, Hdb1Error> {
        let payload = serde_json::to_vec(value).map_err(|_| Hdb1Error::InvalidFrame)?;
        if payload.len() > HDB1_MAX_PAYLOAD_BYTES {
            return Err(Hdb1Error::FrameTooLarge);
        }
        Ok(Self { kind, payload })
    }

    /// Returns the fixed operation kind.
    pub(crate) const fn kind(&self) -> Hdb1Kind {
        self.kind
    }

    /// Decodes a typed JSON payload after checking its expected operation kind.
    pub(crate) fn parse_json<T: DeserializeOwned>(
        &self,
        expected: Hdb1Kind,
    ) -> Result<T, Hdb1Error> {
        if self.kind != expected {
            return Err(Hdb1Error::InvalidOrder);
        }
        serde_json::from_slice(&self.payload).map_err(|_| Hdb1Error::InvalidFrame)
    }

    /// Encodes a complete HDB1 frame with the fixed header.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Hdb1Error> {
        if self.payload.len() > HDB1_MAX_PAYLOAD_BYTES {
            return Err(Hdb1Error::FrameTooLarge);
        }
        let mut bytes = Vec::with_capacity(HDB1_HEADER_BYTES + self.payload.len());
        bytes.extend_from_slice(&HDB1_MAGIC);
        bytes.extend_from_slice(&HDB1_VERSION.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decodes one complete HDB1 frame without allocating beyond the frame bound.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Hdb1Error> {
        if bytes.len() < HDB1_HEADER_BYTES || bytes.len() > HDB1_MAX_FRAME_BYTES {
            return Err(if bytes.len() > HDB1_MAX_FRAME_BYTES {
                Hdb1Error::FrameTooLarge
            } else {
                Hdb1Error::InvalidFrame
            });
        }
        if bytes[..4] != HDB1_MAGIC || u16::from_be_bytes([bytes[4], bytes[5]]) != HDB1_VERSION {
            return Err(Hdb1Error::InvalidFrame);
        }
        let kind = Hdb1Kind::try_from(bytes[6])?;
        let payload_len = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
        if payload_len > HDB1_MAX_PAYLOAD_BYTES {
            return Err(Hdb1Error::FrameTooLarge);
        }
        if bytes.len() != HDB1_HEADER_BYTES + payload_len {
            return Err(Hdb1Error::InvalidFrame);
        }
        Ok(Self {
            kind,
            payload: bytes[HDB1_HEADER_BYTES..].to_vec(),
        })
    }
}

/// Reads one bounded HDB1 frame from an asynchronous byte stream.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Hdb1Frame, Hdb1Error> {
    let mut header = [0_u8; HDB1_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| Hdb1Error::InvalidFrame)?;
    let payload_len = u32::from_be_bytes([header[7], header[8], header[9], header[10]]) as usize;
    if payload_len > HDB1_MAX_PAYLOAD_BYTES {
        return Err(Hdb1Error::FrameTooLarge);
    }
    let mut bytes = Vec::with_capacity(HDB1_HEADER_BYTES + payload_len);
    bytes.extend_from_slice(&header);
    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| Hdb1Error::InvalidFrame)?;
    bytes.extend_from_slice(&payload);
    Hdb1Frame::decode(&bytes)
}

/// Writes one bounded HDB1 frame to an asynchronous byte stream.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Hdb1Frame,
) -> Result<(), Hdb1Error> {
    writer
        .write_all(&frame.encode()?)
        .await
        .map_err(|_| Hdb1Error::InvalidFrame)
}

/// Relay status carried by a Challenge without exposing workspace details.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Hdb1ChallengeStatus {
    /// The user code is awaiting one bounded submission.
    AwaitingCode,
}

impl fmt::Debug for Hdb1ChallengeStatus {
    /// Formats the stable challenge status.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AwaitingCode")
    }
}

/// Core-to-Relay first-bootstrap Start payload.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hdb1StartPayload {
    /// Non-authoritative request correlation identifier encoded as base64url.
    pub(crate) request_id: String,
    /// Core CSR DER encoded as canonical base64url.
    pub(crate) core_csr: String,
    /// SHA-256 digest of the App CSR DER encoded as lowercase hex.
    pub(crate) app_csr_digest: String,
    /// Normalized Herdr session name.
    pub(crate) normalized_session: String,
    /// Core binding correlation digest encoded as lowercase hex.
    pub(crate) core_binding_digest: String,
}

impl Hdb1StartPayload {
    /// Validates and decodes a Start payload before Relay authority checks.
    pub(crate) fn decode_fields(&self) -> Result<Hdb1StartFields, Hdb1Error> {
        let request_id = decode_base64_exact::<HDB1_REQUEST_ID_BYTES>(&self.request_id)?;
        let core_csr = decode_base64_bounded(&self.core_csr, HDB1_MAX_CSR_BYTES)?;
        let app_csr_digest = decode_hex_exact::<HDB1_DIGEST_BYTES>(&self.app_csr_digest)?;
        let core_binding_digest = decode_hex_exact::<HDB1_DIGEST_BYTES>(&self.core_binding_digest)?;
        validate_session(&self.normalized_session)?;
        Ok((
            request_id,
            core_csr,
            app_csr_digest,
            self.normalized_session.clone(),
            core_binding_digest,
        ))
    }
}

/// Relay-to-Core Challenge payload with no workspace or code disclosure.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hdb1ChallengePayload {
    /// Relay-minted bootstrap identifier encoded as base64url.
    pub(crate) bootstrap_id: String,
    /// Relay challenge encoded as base64url.
    pub(crate) challenge: String,
    /// Protected challenge expiry in epoch seconds.
    pub(crate) expires_at_epoch_seconds: u64,
    /// Sanitized challenge status.
    pub(crate) status: Hdb1ChallengeStatus,
}

impl Hdb1ChallengePayload {
    /// Validates and decodes the Challenge's fixed fields.
    pub(crate) fn decode_fields(
        &self,
    ) -> Result<([u8; HDB1_ID_BYTES], [u8; HDB1_DIGEST_BYTES], u64), Hdb1Error> {
        let bootstrap_id = decode_base64_exact::<HDB1_ID_BYTES>(&self.bootstrap_id)?;
        let challenge = decode_base64_exact::<HDB1_DIGEST_BYTES>(&self.challenge)?;
        if self.expires_at_epoch_seconds == 0 || self.status != Hdb1ChallengeStatus::AwaitingCode {
            return Err(Hdb1Error::InvalidField);
        }
        Ok((bootstrap_id, challenge, self.expires_at_epoch_seconds))
    }
}

/// Core-to-Relay Submit payload containing the transient human-entered code.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hdb1SubmitPayload {
    /// Bootstrap identifier returned by Challenge.
    pub(crate) bootstrap_id: String,
    /// Challenge echo encoded as base64url.
    pub(crate) challenge: String,
    /// Six ASCII digits entered by the user.
    pub(crate) code: String,
}

impl Hdb1SubmitPayload {
    /// Validates and decodes a transient Submit payload.
    pub(crate) fn decode_fields(
        &self,
    ) -> Result<([u8; HDB1_ID_BYTES], [u8; HDB1_DIGEST_BYTES], String), Hdb1Error> {
        let bootstrap_id = decode_base64_exact::<HDB1_ID_BYTES>(&self.bootstrap_id)?;
        let challenge = decode_base64_exact::<HDB1_DIGEST_BYTES>(&self.challenge)?;
        validate_code(&self.code)?;
        Ok((bootstrap_id, challenge, self.code.clone()))
    }
}

/// Relay-to-Core public Core certificate metadata in CoreIssued.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hdb1CoreIssuedPayload {
    /// Durable approval identifier encoded as base64url.
    pub(crate) approval_id: String,
    /// Issued Core leaf fingerprint encoded as lowercase hex.
    pub(crate) core_identity: String,
    /// Public Core leaf and device Intermediate certificates as base64url.
    pub(crate) certificate_chain: Vec<String>,
    /// Core certificate expiry in epoch seconds.
    pub(crate) not_after_epoch_seconds: u64,
    /// Sanitized post-bootstrap Core state.
    pub(crate) state: Hdb1CoreState,
}

impl Hdb1CoreIssuedPayload {
    /// Validates public Core issuance metadata without logging public certificate bytes.
    pub(crate) fn validate(&self) -> Result<(), Hdb1Error> {
        decode_base64_exact::<HDB1_ID_BYTES>(&self.approval_id)?;
        decode_hex_exact::<HDB1_DIGEST_BYTES>(&self.core_identity)?;
        decode_certificate_chain(&self.certificate_chain)?;
        if self.not_after_epoch_seconds == 0 || self.state != Hdb1CoreState::BootstrapPending {
            return Err(Hdb1Error::InvalidField);
        }
        Ok(())
    }
}

/// Sanitized Core lifecycle state after first bootstrap.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Hdb1CoreState {
    /// The Core leaf can only perform the bounded Core-enrollment flow.
    BootstrapPending,
}

impl fmt::Debug for Hdb1CoreState {
    /// Formats the stable Core lifecycle state.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapPending")
    }
}

/// Core-to-Relay exact-binding bootstrap recovery request.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hdb1ReconcilePayload {
    /// Durable approval identifier encoded as base64url.
    pub(crate) approval_id: String,
    /// Core binding digest encoded as lowercase hex.
    pub(crate) core_binding_digest: String,
    /// Normalized session name.
    pub(crate) normalized_session: String,
}

impl Hdb1ReconcilePayload {
    /// Builds a canonical exact-binding recovery payload from the wire-visible subset.
    ///
    /// # Parameters
    /// * `approval_id` - Non-zero durable approval identifier.
    /// * `core_binding_digest` - Non-zero Core binding digest.
    /// * `normalized_session` - Existing normalized Herdr session name.
    ///
    /// # Returns
    /// A validated canonical recovery payload.
    pub(crate) fn new(
        approval_id: [u8; HDB1_ID_BYTES],
        core_binding_digest: [u8; HDB1_DIGEST_BYTES],
        normalized_session: String,
    ) -> Result<Self, Hdb1Error> {
        validate_session(&normalized_session)?;
        if approval_id == [0; HDB1_ID_BYTES] || core_binding_digest == [0; HDB1_DIGEST_BYTES] {
            return Err(Hdb1Error::InvalidField);
        }
        Ok(Self {
            approval_id: encode_base64(&approval_id),
            core_binding_digest: encode_hex(&core_binding_digest),
            normalized_session,
        })
    }

    /// Validates and decodes the exact recovery binding.
    pub(crate) fn decode_fields(&self) -> Result<Hdb1ReconcileFields, Hdb1Error> {
        let approval_id = decode_base64_exact::<HDB1_ID_BYTES>(&self.approval_id)?;
        let core_binding_digest = decode_hex_exact::<HDB1_DIGEST_BYTES>(&self.core_binding_digest)?;
        validate_session(&self.normalized_session)?;
        Ok((
            approval_id,
            core_binding_digest,
            self.normalized_session.clone(),
        ))
    }

    /// Validates the exact recovery binding.
    pub(crate) fn validate(&self) -> Result<(), Hdb1Error> {
        self.decode_fields().map(|_| ())
    }
}

/// Sanitized HDB1 recovery status.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Hdb1ResultStatus {
    /// Relay has no terminal public issuance yet.
    Pending,
    /// Relay has the same durable Core issuance.
    Issued,
    /// Relay has a terminal rejection code.
    Rejected,
}

impl fmt::Debug for Hdb1ResultStatus {
    /// Formats the stable recovery status.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pending => "Pending",
            Self::Issued => "Issued",
            Self::Rejected => "Rejected",
        })
    }
}

/// Relay-to-Core exact-binding recovery result.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hdb1ResultPayload {
    /// Durable approval identifier encoded as base64url.
    pub(crate) approval_id: String,
    /// Current recovery status.
    pub(crate) status: Hdb1ResultStatus,
    /// Optional public Core identity, present only for Issued.
    pub(crate) core_identity: Option<String>,
    /// Optional public Core chain, present only for Issued.
    pub(crate) certificate_chain: Option<Vec<String>>,
    /// Optional Core certificate expiry, present only for Issued.
    pub(crate) not_after_epoch_seconds: Option<u64>,
    /// Optional nonzero sanitized rejection code, present only for Rejected.
    pub(crate) rejection_code: Option<u16>,
}

impl Hdb1ResultPayload {
    /// Validates status-specific recovery fields without exposing certificate bytes.
    pub(crate) fn validate(&self) -> Result<(), Hdb1Error> {
        decode_base64_exact::<HDB1_ID_BYTES>(&self.approval_id)?;
        match self.status {
            Hdb1ResultStatus::Pending => {
                if self.core_identity.is_some()
                    || self.certificate_chain.is_some()
                    || self.not_after_epoch_seconds.is_some()
                    || self.rejection_code.is_some()
                {
                    return Err(Hdb1Error::InvalidField);
                }
            }
            Hdb1ResultStatus::Issued => {
                decode_hex_exact::<HDB1_DIGEST_BYTES>(
                    self.core_identity
                        .as_deref()
                        .ok_or(Hdb1Error::InvalidField)?,
                )?;
                decode_certificate_chain(
                    self.certificate_chain
                        .as_ref()
                        .ok_or(Hdb1Error::InvalidField)?,
                )?;
                if self.not_after_epoch_seconds.unwrap_or(0) == 0 || self.rejection_code.is_some() {
                    return Err(Hdb1Error::InvalidField);
                }
            }
            Hdb1ResultStatus::Rejected => {
                if self.rejection_code.unwrap_or(0) == 0
                    || self.core_identity.is_some()
                    || self.certificate_chain.is_some()
                    || self.not_after_epoch_seconds.is_some()
                {
                    return Err(Hdb1Error::InvalidField);
                }
            }
        }
        Ok(())
    }
}

/// Relay-to-Core terminal rejection payload.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hdb1RejectedPayload {
    /// Stable nonzero rejection code.
    pub(crate) code: u16,
}

impl Hdb1RejectedPayload {
    /// Validates the fixed sanitized rejection shape.
    pub(crate) fn validate(&self) -> Result<(), Hdb1Error> {
        if self.code == 0 {
            return Err(Hdb1Error::InvalidField);
        }
        Ok(())
    }
}

/// Encode bytes using canonical unpadded base64url for JSON fields.
fn encode_base64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode one canonical base64url field with an exact byte width.
fn decode_base64_exact<const N: usize>(value: &str) -> Result<[u8; N], Hdb1Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Hdb1Error::InvalidField)?;
    if bytes.len() != N || encode_base64(&bytes) != value {
        return Err(Hdb1Error::InvalidField);
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(&bytes);
    if output == [0; N] {
        return Err(Hdb1Error::InvalidField);
    }
    Ok(output)
}

/// Decode a bounded non-empty base64url field.
fn decode_base64_bounded(value: &str, max_bytes: usize) -> Result<Vec<u8>, Hdb1Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Hdb1Error::InvalidField)?;
    if bytes.is_empty() || bytes.len() > max_bytes || encode_base64(&bytes) != value {
        return Err(if bytes.len() > max_bytes {
            Hdb1Error::FrameTooLarge
        } else {
            Hdb1Error::InvalidField
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
fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], Hdb1Error> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Hdb1Error::InvalidField);
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(Hdb1Error::InvalidField);
    }
    let mut output = [0_u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        output[index] = (high << 4) | low;
    }
    if output == [0; N] {
        return Err(Hdb1Error::InvalidField);
    }
    Ok(output)
}

/// Decode one known lowercase hexadecimal nibble.
fn hex_nibble(byte: u8) -> Result<u8, Hdb1Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Hdb1Error::InvalidField),
    }
}

/// Validate the shared HDB1 session contract before mapping the result to a wire error.
fn validate_session(value: &str) -> Result<(), Hdb1Error> {
    if !crate::is_valid_hdb1_session(value) {
        return Err(Hdb1Error::InvalidField);
    }
    Ok(())
}

/// Validate exactly six ASCII digits, including leading zeroes.
fn validate_code(value: &str) -> Result<(), Hdb1Error> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Hdb1Error::InvalidField);
    }
    Ok(())
}

/// Decode and bound a public certificate chain without exposing it in diagnostics.
fn decode_certificate_chain(values: &[String]) -> Result<Vec<Vec<u8>>, Hdb1Error> {
    if values.is_empty() || values.len() > HDB1_MAX_CHAIN_CERTIFICATES {
        return Err(Hdb1Error::InvalidField);
    }
    let mut total = 0_usize;
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let certificate = decode_base64_bounded(value, HDB1_MAX_CHAIN_BYTES)?;
        total = total
            .checked_add(certificate.len())
            .ok_or(Hdb1Error::FrameTooLarge)?;
        if total > HDB1_MAX_CHAIN_BYTES {
            return Err(Hdb1Error::FrameTooLarge);
        }
        output.push(certificate);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Build a valid canonical Start payload fixture.
    fn start_payload() -> Hdb1StartPayload {
        Hdb1StartPayload {
            request_id: encode_base64(&[1; 16]),
            core_csr: encode_base64(&[2; 32]),
            app_csr_digest: encode_hex(&[3; 32]),
            normalized_session: "default".to_owned(),
            core_binding_digest: encode_hex(&[4; 32]),
        }
    }

    /// Verify every frozen HDB1 kind has its assigned numeric value.
    #[test]
    // TEST:relay/src/bootstrap_wire.rs[tests::kind_registry_is_frozen]
    fn kind_registry_is_frozen() {
        assert_eq!(Hdb1Kind::Start as u8, 1);
        assert_eq!(Hdb1Kind::Challenge as u8, 2);
        assert_eq!(Hdb1Kind::Submit as u8, 3);
        assert_eq!(Hdb1Kind::CoreIssued as u8, 4);
        assert_eq!(Hdb1Kind::Reconcile as u8, 5);
        assert_eq!(Hdb1Kind::Result as u8, 6);
        assert_eq!(Hdb1Kind::Rejected as u8, 7);
    }

    /// Verify Relay validates canonical binary fields before authority processing.
    #[test]
    // TEST:relay/src/bootstrap_wire.rs[tests::start_fields_are_bounded]
    fn start_fields_are_bounded() {
        let payload = start_payload();
        let fields = payload.decode_fields().expect("fields");
        assert_eq!(fields.0, [1; 16]);
        assert_eq!(fields.1, vec![2; 32]);
        assert_eq!(fields.2, [3; 32]);
        assert_eq!(fields.3, "default");
        assert_eq!(fields.4, [4; 32]);
    }

    /// Reject non-canonical base64url, uppercase hexadecimal, and zero digests.
    #[test]
    // TEST:relay/src/bootstrap_wire.rs[tests::binary_fields_fail_closed]
    fn binary_fields_fail_closed() {
        let mut payload = start_payload();
        payload.request_id.push('=');
        assert!(payload.decode_fields().is_err());
        let mut payload = start_payload();
        payload.app_csr_digest.replace_range(..1, "A");
        assert!(payload.decode_fields().is_err());
        let mut payload = start_payload();
        payload.core_binding_digest = encode_hex(&[0; 32]);
        assert!(payload.decode_fields().is_err());
    }

    /// Enforce the complete-frame limit including the fixed header.
    #[test]
    // TEST:relay/src/bootstrap_wire.rs[tests::frame_bound_includes_header]
    fn frame_bound_includes_header() {
        let frame = Hdb1Frame {
            kind: Hdb1Kind::Start,
            payload: vec![b' '; HDB1_MAX_PAYLOAD_BYTES],
        };
        assert!(frame.encode().is_ok());
        let oversized = Hdb1Frame {
            kind: Hdb1Kind::Start,
            payload: vec![b' '; HDB1_MAX_PAYLOAD_BYTES + 1],
        };
        assert_eq!(oversized.encode(), Err(Hdb1Error::FrameTooLarge));
    }

    /// Reject the historical HDE1 magic in the bootstrap decoder.
    #[test]
    // TEST:relay/src/bootstrap_wire.rs[tests::hde_magic_is_not_bootstrap]
    fn hde_magic_is_not_bootstrap() {
        let mut bytes = Hdb1Frame::json(Hdb1Kind::Start, &start_payload())
            .expect("frame")
            .encode()
            .expect("bytes");
        bytes[..4].copy_from_slice(b"HDE1");
        assert_eq!(Hdb1Frame::decode(&bytes), Err(Hdb1Error::InvalidFrame));
    }

    /// Validate strict six-digit code handling without logging its value.
    #[test]
    // TEST:relay/src/bootstrap_wire.rs[tests::submit_code_is_strict]
    fn submit_code_is_strict() {
        let valid = Hdb1SubmitPayload {
            bootstrap_id: encode_base64(&[1; 32]),
            challenge: encode_base64(&[2; 32]),
            code: "000007".to_owned(),
        };
        assert_eq!(valid.decode_fields().expect("fields").2, "000007");
        let mut invalid = valid.clone();
        invalid.code = "12345".to_owned();
        assert!(invalid.decode_fields().is_err());
    }

    /// Reject status fields that are present in the wrong recovery state.
    #[test]
    // TEST:relay/src/bootstrap_wire.rs[tests::result_status_fields_are_exclusive]
    fn result_status_fields_are_exclusive() {
        let pending = Hdb1ResultPayload {
            approval_id: encode_base64(&[1; 32]),
            status: Hdb1ResultStatus::Pending,
            core_identity: None,
            certificate_chain: None,
            not_after_epoch_seconds: None,
            rejection_code: None,
        };
        assert!(pending.validate().is_ok());
        let mut invalid = pending;
        invalid.rejection_code = Some(1);
        assert!(invalid.validate().is_err());
    }

    /// Verify asynchronous frame helpers preserve HDB1 over segmented I/O.
    #[tokio::test]
    // TEST:relay/src/bootstrap_wire.rs[tests::async_frame_round_trip]
    async fn async_frame_round_trip() {
        let frame = Hdb1Frame::json(Hdb1Kind::Start, &start_payload()).expect("frame");
        let (mut writer, mut reader) = duplex(HDB1_MAX_FRAME_BYTES);
        let encoded = frame.encode().expect("bytes");
        let writer_task = tokio::spawn(async move {
            for chunk in encoded.chunks(3) {
                writer.write_all(chunk).await.expect("write");
            }
        });
        let received = read_frame(&mut reader).await.expect("read");
        writer_task.await.expect("writer");
        assert_eq!(received.kind(), Hdb1Kind::Start);
        let _: Hdb1StartPayload = received.parse_json(Hdb1Kind::Start).expect("payload");
    }
}
