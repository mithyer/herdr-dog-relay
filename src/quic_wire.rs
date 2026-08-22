//! Relay-side HDQM/HDQS codec mirror.
//!
//! This module validates the same bounded frames as Core without depending on Core's crate. The
//! Relay stores no Herdr payload and uses fixed reason categories only.

use std::fmt;

/// HDQM control magic.
pub const HDQM_MAGIC: [u8; 4] = *b"HDQM";
/// HDQS stream magic.
pub const HDQS_MAGIC: [u8; 4] = *b"HDQS";
/// QRM protocol version.
pub const QRM_PROTOCOL_VERSION: u16 = 1;
/// HDQM fixed header size.
pub const HDQM_HEADER_BYTES: usize = 27;
/// Maximum complete HDQM frame size.
pub const QRM_MAX_CONTROL_FRAME_BYTES: usize = 65_536;
/// Maximum HDQM payload size.
pub const QRM_MAX_CONTROL_PAYLOAD_BYTES: usize = QRM_MAX_CONTROL_FRAME_BYTES - HDQM_HEADER_BYTES;
/// Maximum session name size.
pub const QRM_MAX_SESSION_NAME_BYTES: usize = 64;
/// Fixed opaque authority width.
pub const QRM_AUTHORITY_BYTES: usize = 32;
/// Fixed HDQS response width.
pub const HDQS_RESPONSE_BYTES: usize = 20;

/// Stable Relay wire errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicProtocolError {
    /// Candidate bytes are too short.
    FrameTooShort,
    /// Candidate magic is invalid.
    InvalidMagic,
    /// Candidate protocol version is unsupported.
    UnsupportedVersion,
    /// Candidate operation kind is unknown.
    UnknownKind,
    /// Candidate payload exceeds the fixed bound.
    PayloadTooLarge,
    /// Candidate length is inconsistent.
    LengthMismatch,
    /// Candidate field is invalid.
    InvalidField,
    /// Candidate session is invalid.
    InvalidSession,
    /// Candidate response status is invalid.
    InvalidStatus,
}

impl fmt::Display for QuicProtocolError {
    /// Formats a stable protocol category without wire bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::FrameTooShort => "QRM frame is too short",
            Self::InvalidMagic => "QRM frame magic is invalid",
            Self::UnsupportedVersion => "QRM protocol version is unsupported",
            Self::UnknownKind => "QRM frame kind is unknown",
            Self::PayloadTooLarge => "QRM frame payload is too large",
            Self::LengthMismatch => "QRM frame length is inconsistent",
            Self::InvalidField => "QRM frame field is invalid",
            Self::InvalidSession => "QRM session name is invalid",
            Self::InvalidStatus => "QRM response status is invalid",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for QuicProtocolError {}

/// Registered control operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HdqmKind {
    /// Device hello.
    DeviceHello = 1,
    /// Device hello acknowledgement.
    DeviceHelloAck = 2,
    /// Session prepare.
    SessionPrepare = 3,
    /// Session prepare acknowledgement.
    SessionPrepareAck = 4,
    /// Session open.
    SessionOpen = 5,
    /// Session opened.
    SessionOpened = 6,
    /// Session close.
    SessionClose = 7,
    /// Session closed.
    SessionClosed = 8,
    /// Connection/session heartbeat.
    Heartbeat = 9,
    /// Bounded shutdown notification.
    GoAway = 10,
    /// Stable failure response.
    ErrorResponse = 11,
}

impl TryFrom<u8> for HdqmKind {
    type Error = QuicProtocolError;

    /// Decodes one registered control operation.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DeviceHello),
            2 => Ok(Self::DeviceHelloAck),
            3 => Ok(Self::SessionPrepare),
            4 => Ok(Self::SessionPrepareAck),
            5 => Ok(Self::SessionOpen),
            6 => Ok(Self::SessionOpened),
            7 => Ok(Self::SessionClose),
            8 => Ok(Self::SessionClosed),
            9 => Ok(Self::Heartbeat),
            10 => Ok(Self::GoAway),
            11 => Ok(Self::ErrorResponse),
            _ => Err(QuicProtocolError::UnknownKind),
        }
    }
}

/// One bounded HDQM frame.
#[derive(Clone, Eq, PartialEq)]
pub struct HdqmFrame {
    /// Registered control kind.
    pub kind: HdqmKind,
    /// Opaque request ID.
    pub request_id: [u8; 16],
    /// Typed operation payload.
    pub payload: Vec<u8>,
}

impl fmt::Debug for HdqmFrame {
    /// Reports only kind, request presence and payload length.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HdqmFrame")
            .field("kind", &self.kind)
            .field("request_id_present", &true)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl HdqmFrame {
    /// Encodes one bounded HDQM frame.
    pub fn encode(&self) -> Result<Vec<u8>, QuicProtocolError> {
        if self.payload.len() > QRM_MAX_CONTROL_PAYLOAD_BYTES {
            return Err(QuicProtocolError::PayloadTooLarge);
        }
        let mut output = Vec::with_capacity(HDQM_HEADER_BYTES + self.payload.len());
        output.extend_from_slice(&HDQM_MAGIC);
        output.extend_from_slice(&QRM_PROTOCOL_VERSION.to_be_bytes());
        output.push(self.kind as u8);
        output.extend_from_slice(&self.request_id);
        output.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    /// Decodes one complete HDQM frame before dispatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuicProtocolError> {
        if bytes.len() < HDQM_HEADER_BYTES {
            return Err(QuicProtocolError::FrameTooShort);
        }
        if bytes[..4] != HDQM_MAGIC {
            return Err(QuicProtocolError::InvalidMagic);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != QRM_PROTOCOL_VERSION {
            return Err(QuicProtocolError::UnsupportedVersion);
        }
        let kind = HdqmKind::try_from(bytes[6])?;
        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&bytes[7..23]);
        let payload_len = u32::from_be_bytes([bytes[23], bytes[24], bytes[25], bytes[26]]) as usize;
        if payload_len > QRM_MAX_CONTROL_PAYLOAD_BYTES {
            return Err(QuicProtocolError::PayloadTooLarge);
        }
        if bytes.len() != HDQM_HEADER_BYTES + payload_len {
            return Err(QuicProtocolError::LengthMismatch);
        }
        Ok(Self {
            kind,
            request_id,
            payload: bytes[HDQM_HEADER_BYTES..].to_vec(),
        })
    }
}

/// A validated normalized session name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionName(String);

impl SessionName {
    /// Normalizes empty input to `default` and validates the safe path grammar.
    pub fn new(value: &str) -> Result<Self, QuicProtocolError> {
        let value = if value.is_empty() { "default" } else { value };
        if value.len() > QRM_MAX_SESSION_NAME_BYTES
            || value == "."
            || value == ".."
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
        {
            return Err(QuicProtocolError::InvalidSession);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the canonical session name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fixed application acknowledgement for one authenticated QRM connection.
#[derive(Clone, Eq, PartialEq)]
pub struct DeviceHelloAck {
    /// Relay certificate identity repeated at the application boundary.
    pub relay_identity: [u8; QRM_AUTHORITY_BYTES],
    /// Relay process startup generation.
    pub relay_generation: u64,
    /// Current QUIC connection epoch.
    pub connection_epoch: u64,
}

/// Redacts Relay identity and generation values from diagnostics.
impl fmt::Debug for DeviceHelloAck {
    /// Formats only the presence of authenticated authority fields.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceHelloAck")
            .field("relay_identity_present", &true)
            .field("relay_generation_present", &true)
            .field("connection_epoch_present", &true)
            .finish()
    }
}

impl DeviceHelloAck {
    /// Encodes the fixed hello acknowledgement.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(48);
        bytes.extend_from_slice(&self.relay_identity);
        bytes.extend_from_slice(&self.relay_generation.to_be_bytes());
        bytes.extend_from_slice(&self.connection_epoch.to_be_bytes());
        bytes
    }

    /// Decodes the fixed hello acknowledgement.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuicProtocolError> {
        if bytes.len() != 48 {
            return Err(QuicProtocolError::LengthMismatch);
        }
        let mut identity = [0_u8; QRM_AUTHORITY_BYTES];
        identity.copy_from_slice(&bytes[..QRM_AUTHORITY_BYTES]);
        let relay_generation = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
        let connection_epoch = u64::from_be_bytes(bytes[40..48].try_into().unwrap());
        if relay_generation == 0 || connection_epoch == 0 || identity == [0; QRM_AUTHORITY_BYTES] {
            return Err(QuicProtocolError::InvalidField);
        }
        Ok(Self {
            relay_identity: identity,
            relay_generation,
            connection_epoch,
        })
    }
}

/// Request payload for one bounded SESSION_PREPARE control frame.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionPrepareRequest {
    /// Canonical session name.
    pub session: SessionName,
    /// Existing Profile fingerprint, or zero bytes for first observation.
    pub expected_fingerprint: [u8; QRM_AUTHORITY_BYTES],
    /// Core-owned configuration generation.
    pub configuration_generation: u64,
}

/// Redacts fingerprint and generation values from diagnostics.
impl fmt::Debug for SessionPrepareRequest {
    /// Formats only the normalized session and authority presence.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionPrepareRequest")
            .field("session", &self.session)
            .field("expected_fingerprint_present", &true)
            .field("configuration_generation_present", &true)
            .finish()
    }
}

impl SessionPrepareRequest {
    /// Encodes the request payload.
    pub fn encode(&self) -> Result<Vec<u8>, QuicProtocolError> {
        encode_session_name(&self.session, |output| {
            output.extend_from_slice(&self.expected_fingerprint);
            output.extend_from_slice(&self.configuration_generation.to_be_bytes());
        })
    }

    /// Decodes a complete request payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuicProtocolError> {
        let (session, offset) = decode_session_name(bytes)?;
        if bytes.len() != offset + QRM_AUTHORITY_BYTES + 8 {
            return Err(QuicProtocolError::LengthMismatch);
        }
        let mut fingerprint = [0_u8; QRM_AUTHORITY_BYTES];
        fingerprint.copy_from_slice(&bytes[offset..offset + QRM_AUTHORITY_BYTES]);
        Ok(Self {
            session,
            expected_fingerprint: fingerprint,
            configuration_generation: u64::from_be_bytes(
                bytes[offset + QRM_AUTHORITY_BYTES..].try_into().unwrap(),
            ),
        })
    }
}

/// Response payload for one successful SESSION_PREPARE operation.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionPrepareAck {
    /// Canonical session returned by Relay.
    pub session: SessionName,
    /// Verified session fingerprint.
    pub fingerprint: [u8; QRM_AUTHORITY_BYTES],
    /// Core-owned configuration generation.
    pub configuration_generation: u64,
    /// Relay process generation.
    pub relay_generation: u64,
    /// QUIC connection epoch.
    pub connection_epoch: u64,
    /// Opaque token minted for this prepare/open attempt.
    pub token: [u8; QRM_AUTHORITY_BYTES],
    /// Bounded token lifetime.
    pub token_ttl_secs: u32,
}

/// Redacts fingerprint, token, generation and epoch values from diagnostics.
impl fmt::Debug for SessionPrepareAck {
    /// Formats only the normalized session and authority presence.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionPrepareAck")
            .field("session", &self.session)
            .field("fingerprint_present", &true)
            .field("configuration_generation_present", &true)
            .field("relay_generation_present", &true)
            .field("connection_epoch_present", &true)
            .field("token_present", &true)
            .field("token_ttl_present", &true)
            .finish()
    }
}

impl SessionPrepareAck {
    /// Encodes the acknowledgement payload.
    pub fn encode(&self) -> Result<Vec<u8>, QuicProtocolError> {
        encode_session_name(&self.session, |output| {
            output.extend_from_slice(&self.fingerprint);
            output.extend_from_slice(&self.configuration_generation.to_be_bytes());
            output.extend_from_slice(&self.relay_generation.to_be_bytes());
            output.extend_from_slice(&self.connection_epoch.to_be_bytes());
            output.extend_from_slice(&self.token);
            output.extend_from_slice(&self.token_ttl_secs.to_be_bytes());
        })
    }

    /// Decodes a complete acknowledgement payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuicProtocolError> {
        let (session, offset) = decode_session_name(bytes)?;
        let expected = offset + QRM_AUTHORITY_BYTES + 8 + 8 + 8 + QRM_AUTHORITY_BYTES + 4;
        if bytes.len() != expected {
            return Err(QuicProtocolError::LengthMismatch);
        }
        let mut fingerprint = [0_u8; QRM_AUTHORITY_BYTES];
        fingerprint.copy_from_slice(&bytes[offset..offset + QRM_AUTHORITY_BYTES]);
        let config_start = offset + QRM_AUTHORITY_BYTES;
        let relay_start = config_start + 8;
        let epoch_start = relay_start + 8;
        let token_start = epoch_start + 8;
        let mut token = [0_u8; QRM_AUTHORITY_BYTES];
        token.copy_from_slice(&bytes[token_start..token_start + QRM_AUTHORITY_BYTES]);
        Ok(Self {
            session,
            fingerprint,
            configuration_generation: u64::from_be_bytes(
                bytes[config_start..relay_start].try_into().unwrap(),
            ),
            relay_generation: u64::from_be_bytes(
                bytes[relay_start..epoch_start].try_into().unwrap(),
            ),
            connection_epoch: u64::from_be_bytes(
                bytes[epoch_start..token_start].try_into().unwrap(),
            ),
            token,
            token_ttl_secs: u32::from_be_bytes(
                bytes[token_start + QRM_AUTHORITY_BYTES..]
                    .try_into()
                    .unwrap(),
            ),
        })
    }
}

/// Request payload for one SESSION_OPEN control frame.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionOpenRequest {
    /// Canonical prepared session.
    pub session: SessionName,
    /// Verified session fingerprint expected for this open.
    pub fingerprint: [u8; QRM_AUTHORITY_BYTES],
    /// Core-owned configuration generation.
    pub configuration_generation: u64,
    /// Relay process generation.
    pub relay_generation: u64,
    /// QUIC connection epoch.
    pub connection_epoch: u64,
    /// Token returned by prepare.
    pub token: [u8; QRM_AUTHORITY_BYTES],
}

/// Redacts fingerprint, token, generation and epoch values from diagnostics.
impl fmt::Debug for SessionOpenRequest {
    /// Formats only the normalized session and authority presence.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionOpenRequest")
            .field("session", &self.session)
            .field("fingerprint_present", &true)
            .field("configuration_generation_present", &true)
            .field("relay_generation_present", &true)
            .field("connection_epoch_present", &true)
            .field("token_present", &true)
            .finish()
    }
}

impl SessionOpenRequest {
    /// Encodes the open request payload.
    pub fn encode(&self) -> Result<Vec<u8>, QuicProtocolError> {
        encode_session_name(&self.session, |output| {
            output.extend_from_slice(&self.fingerprint);
            output.extend_from_slice(&self.configuration_generation.to_be_bytes());
            output.extend_from_slice(&self.relay_generation.to_be_bytes());
            output.extend_from_slice(&self.connection_epoch.to_be_bytes());
            output.extend_from_slice(&self.token);
        })
    }

    /// Decodes a complete open request payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuicProtocolError> {
        let (session, offset) = decode_session_name(bytes)?;
        let expected = offset + QRM_AUTHORITY_BYTES + 8 + 8 + 8 + QRM_AUTHORITY_BYTES;
        if bytes.len() != expected {
            return Err(QuicProtocolError::LengthMismatch);
        }
        let config_offset = offset + QRM_AUTHORITY_BYTES;
        let token_start = config_offset + 24;
        let mut fingerprint = [0_u8; QRM_AUTHORITY_BYTES];
        fingerprint.copy_from_slice(&bytes[offset..config_offset]);
        let mut token = [0_u8; QRM_AUTHORITY_BYTES];
        token.copy_from_slice(&bytes[token_start..]);
        Ok(Self {
            session,
            fingerprint,
            configuration_generation: u64::from_be_bytes(
                bytes[config_offset..config_offset + 8].try_into().unwrap(),
            ),
            relay_generation: u64::from_be_bytes(
                bytes[config_offset + 8..config_offset + 16]
                    .try_into()
                    .unwrap(),
            ),
            connection_epoch: u64::from_be_bytes(
                bytes[config_offset + 16..token_start].try_into().unwrap(),
            ),
            token,
        })
    }
}

/// Response payload for one successful SESSION_OPEN operation.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionOpenAck {
    /// Ephemeral handle used by the HDQS binding.
    pub session_handle: u16,
    /// Canonical session.
    pub session: SessionName,
    /// Verified session fingerprint.
    pub fingerprint: [u8; QRM_AUTHORITY_BYTES],
    /// Core-owned configuration generation.
    pub configuration_generation: u64,
    /// Relay process generation.
    pub relay_generation: u64,
    /// QUIC connection epoch.
    pub connection_epoch: u64,
    /// Active opaque session token.
    pub token: [u8; QRM_AUTHORITY_BYTES],
}

/// Redacts fingerprint, token, generation and epoch values from diagnostics.
impl fmt::Debug for SessionOpenAck {
    /// Formats only the handle/session and authority presence.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionOpenAck")
            .field("session_handle_present", &true)
            .field("session", &self.session)
            .field("fingerprint_present", &true)
            .field("configuration_generation_present", &true)
            .field("relay_generation_present", &true)
            .field("connection_epoch_present", &true)
            .field("token_present", &true)
            .finish()
    }
}

impl SessionOpenAck {
    /// Encodes the open acknowledgement payload.
    pub fn encode(&self) -> Result<Vec<u8>, QuicProtocolError> {
        if self.session_handle == 0 {
            return Err(QuicProtocolError::InvalidField);
        }
        let mut output =
            Vec::with_capacity(2 + 1 + self.session.as_str().len() + 32 + 8 + 8 + 8 + 32);
        output.extend_from_slice(&self.session_handle.to_be_bytes());
        output.extend_from_slice(&encode_session_name(&self.session, |_| {})?);
        output.extend_from_slice(&self.fingerprint);
        output.extend_from_slice(&self.configuration_generation.to_be_bytes());
        output.extend_from_slice(&self.relay_generation.to_be_bytes());
        output.extend_from_slice(&self.connection_epoch.to_be_bytes());
        output.extend_from_slice(&self.token);
        Ok(output)
    }

    /// Decodes a complete open acknowledgement payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuicProtocolError> {
        if bytes.len() < 3 {
            return Err(QuicProtocolError::FrameTooShort);
        }
        let session_handle = u16::from_be_bytes([bytes[0], bytes[1]]);
        if session_handle == 0 {
            return Err(QuicProtocolError::InvalidField);
        }
        let (session, name_offset) = decode_session_name(&bytes[2..])?;
        let offset = 2 + name_offset;
        let expected = offset + QRM_AUTHORITY_BYTES + 8 + 8 + 8 + QRM_AUTHORITY_BYTES;
        if bytes.len() != expected {
            return Err(QuicProtocolError::LengthMismatch);
        }
        let mut fingerprint = [0_u8; QRM_AUTHORITY_BYTES];
        fingerprint.copy_from_slice(&bytes[offset..offset + QRM_AUTHORITY_BYTES]);
        let config_start = offset + QRM_AUTHORITY_BYTES;
        let token_start = config_start + 24;
        let mut token = [0_u8; QRM_AUTHORITY_BYTES];
        token.copy_from_slice(&bytes[token_start..]);
        Ok(Self {
            session,
            session_handle,
            fingerprint,
            configuration_generation: u64::from_be_bytes(
                bytes[config_start..config_start + 8].try_into().unwrap(),
            ),
            relay_generation: u64::from_be_bytes(
                bytes[config_start + 8..config_start + 16]
                    .try_into()
                    .unwrap(),
            ),
            connection_epoch: u64::from_be_bytes(
                bytes[config_start + 16..token_start].try_into().unwrap(),
            ),
            token,
        })
    }
}

/// Encodes a bounded session name followed by operation-specific fields.
fn encode_session_name<F>(session: &SessionName, append: F) -> Result<Vec<u8>, QuicProtocolError>
where
    F: FnOnce(&mut Vec<u8>),
{
    let name = session.as_str().as_bytes();
    if name.is_empty() || name.len() > QRM_MAX_SESSION_NAME_BYTES {
        return Err(QuicProtocolError::InvalidSession);
    }
    let mut output = Vec::with_capacity(1 + name.len() + 64);
    output.push(name.len() as u8);
    output.extend_from_slice(name);
    append(&mut output);
    Ok(output)
}

/// Decodes a bounded session name and returns the next payload offset.
fn decode_session_name(bytes: &[u8]) -> Result<(SessionName, usize), QuicProtocolError> {
    let name_len = bytes
        .first()
        .copied()
        .map(usize::from)
        .ok_or(QuicProtocolError::FrameTooShort)?;
    if name_len == 0 || name_len > QRM_MAX_SESSION_NAME_BYTES || bytes.len() < 1 + name_len {
        return Err(QuicProtocolError::InvalidSession);
    }
    let session = std::str::from_utf8(&bytes[1..1 + name_len])
        .map_err(|_| QuicProtocolError::InvalidSession)
        .and_then(SessionName::new)?;
    Ok((session, 1 + name_len))
}

#[derive(Clone, Eq, PartialEq)]
/// Authority fields presented once at the start of one session stream.
pub struct HdqsBinding {
    /// Connection-local session handle.
    pub session_handle: u16,
    /// Core-owned configuration generation.
    pub configuration_generation: u64,
    /// Relay process generation.
    pub relay_generation: u64,
    /// QUIC connection epoch.
    pub connection_epoch: u64,
    /// Canonical session name.
    pub session: SessionName,
    /// Session fingerprint.
    pub fingerprint: [u8; QRM_AUTHORITY_BYTES],
    /// Opaque session token.
    pub token: [u8; QRM_AUTHORITY_BYTES],
}

impl fmt::Debug for HdqsBinding {
    /// Reports authority presence without token or fingerprint bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HdqsBinding")
            .field("session_handle_present", &true)
            .field("configuration_generation_present", &true)
            .field("relay_generation_present", &true)
            .field("connection_epoch_present", &true)
            .field("session", &self.session)
            .field("fingerprint_present", &true)
            .field("token_present", &true)
            .finish()
    }
}

impl HdqsBinding {
    /// Encodes the binding preface.
    pub fn encode(&self) -> Result<Vec<u8>, QuicProtocolError> {
        if self.session_handle == 0 || self.session.as_str().is_empty() {
            return Err(QuicProtocolError::InvalidField);
        }
        let name = self.session.as_str().as_bytes();
        if name.len() > QRM_MAX_SESSION_NAME_BYTES {
            return Err(QuicProtocolError::InvalidSession);
        }
        let mut output = Vec::with_capacity(97 + name.len());
        output.extend_from_slice(&HDQS_MAGIC);
        output.extend_from_slice(&QRM_PROTOCOL_VERSION.to_be_bytes());
        output.extend_from_slice(&self.session_handle.to_be_bytes());
        output.extend_from_slice(&self.configuration_generation.to_be_bytes());
        output.extend_from_slice(&self.relay_generation.to_be_bytes());
        output.extend_from_slice(&self.connection_epoch.to_be_bytes());
        output.push(name.len() as u8);
        output.extend_from_slice(name);
        output.extend_from_slice(&self.fingerprint);
        output.extend_from_slice(&self.token);
        Ok(output)
    }

    /// Decodes a complete binding preface.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuicProtocolError> {
        if bytes.len() < 97 {
            return Err(QuicProtocolError::FrameTooShort);
        }
        if bytes[..4] != HDQS_MAGIC {
            return Err(QuicProtocolError::InvalidMagic);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != QRM_PROTOCOL_VERSION {
            return Err(QuicProtocolError::UnsupportedVersion);
        }
        let handle = u16::from_be_bytes([bytes[6], bytes[7]]);
        let name_len = usize::from(bytes[32]);
        if handle == 0 || name_len == 0 || name_len > QRM_MAX_SESSION_NAME_BYTES {
            return Err(QuicProtocolError::InvalidField);
        }
        let expected = 33 + name_len + 64;
        if bytes.len() != expected {
            return Err(QuicProtocolError::LengthMismatch);
        }
        let session = std::str::from_utf8(&bytes[33..33 + name_len])
            .map_err(|_| QuicProtocolError::InvalidSession)
            .and_then(SessionName::new)?;
        let fingerprint_start = 33 + name_len;
        let token_start = fingerprint_start + 32;
        let mut fingerprint = [0_u8; 32];
        fingerprint.copy_from_slice(&bytes[fingerprint_start..token_start]);
        let mut token = [0_u8; 32];
        token.copy_from_slice(&bytes[token_start..]);
        Ok(Self {
            session_handle: handle,
            configuration_generation: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            relay_generation: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            connection_epoch: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            session,
            fingerprint,
            token,
        })
    }
}

/// Fixed HDQS response kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HdqsKind {
    /// Authority accepted.
    Accepted = 2,
    /// Authority rejected.
    Rejected = 3,
}

impl TryFrom<u8> for HdqsKind {
    type Error = QuicProtocolError;

    /// Decodes an accepted/rejected kind.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::Accepted),
            3 => Ok(Self::Rejected),
            _ => Err(QuicProtocolError::InvalidStatus),
        }
    }
}

/// Stable HDQS rejection categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HdqsReason {
    /// Accepted responses have no rejection reason.
    None = 0,
    /// Binding frame is malformed.
    InvalidFrame = 1,
    /// Session is not available.
    SessionNotFound = 2,
    /// Fingerprint mismatch.
    FingerprintMismatch = 3,
    /// Token mismatch.
    TokenMismatch = 4,
    /// Generation mismatch.
    GenerationMismatch = 5,
    /// Unix socket unavailable.
    SocketUnavailable = 6,
    /// Session capacity exhausted.
    CapacityExhausted = 7,
    /// Connection is closing.
    ConnectionClosing = 8,
    /// Session already has an active stream.
    SessionAlreadyOpen = 9,
}

impl TryFrom<u8> for HdqsReason {
    type Error = QuicProtocolError;

    /// Decodes a stable reason category.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::InvalidFrame),
            2 => Ok(Self::SessionNotFound),
            3 => Ok(Self::FingerprintMismatch),
            4 => Ok(Self::TokenMismatch),
            5 => Ok(Self::GenerationMismatch),
            6 => Ok(Self::SocketUnavailable),
            7 => Ok(Self::CapacityExhausted),
            8 => Ok(Self::ConnectionClosing),
            9 => Ok(Self::SessionAlreadyOpen),
            _ => Err(QuicProtocolError::InvalidStatus),
        }
    }
}

/// Fixed 20-byte HDQS accepted/rejected response.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HdqsResponse {
    /// Response kind.
    pub kind: HdqsKind,
    /// Stable status kind, equal to `kind`.
    pub status: HdqsKind,
    /// Accepted session handle, or zero for rejection.
    pub session_handle: u16,
    /// Rejection category, or `None` for accepted.
    pub reason: HdqsReason,
    /// Current connection epoch.
    pub connection_epoch: u64,
}

/// Redacts the connection epoch while retaining the fixed response category.
impl fmt::Debug for HdqsResponse {
    /// Formats only non-authoritative response classification and presence markers.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HdqsResponse")
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("session_handle_present", &true)
            .field("reason", &self.reason)
            .field("connection_epoch_present", &true)
            .finish()
    }
}

impl HdqsResponse {
    /// Creates a valid accepted response.
    pub const fn accepted(handle: u16, epoch: u64) -> Self {
        Self {
            kind: HdqsKind::Accepted,
            status: HdqsKind::Accepted,
            session_handle: handle,
            reason: HdqsReason::None,
            connection_epoch: epoch,
        }
    }

    /// Creates a valid rejected response.
    pub const fn rejected(reason: HdqsReason, epoch: u64) -> Self {
        Self {
            kind: HdqsKind::Rejected,
            status: HdqsKind::Rejected,
            session_handle: 0,
            reason,
            connection_epoch: epoch,
        }
    }

    /// Encodes the fixed response without free-text diagnostics.
    pub fn encode(self) -> Result<[u8; HDQS_RESPONSE_BYTES], QuicProtocolError> {
        if self.kind != self.status
            || (self.kind == HdqsKind::Accepted
                && (self.session_handle == 0 || self.reason != HdqsReason::None))
            || (self.kind == HdqsKind::Rejected && self.session_handle != 0)
        {
            return Err(QuicProtocolError::InvalidStatus);
        }
        let mut bytes = [0_u8; HDQS_RESPONSE_BYTES];
        bytes[..4].copy_from_slice(&HDQS_MAGIC);
        bytes[4..6].copy_from_slice(&QRM_PROTOCOL_VERSION.to_be_bytes());
        bytes[6] = self.kind as u8;
        bytes[7] = self.status as u8;
        bytes[8..10].copy_from_slice(&self.session_handle.to_be_bytes());
        bytes[10] = self.reason as u8;
        bytes[12..20].copy_from_slice(&self.connection_epoch.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes the fixed response and validates status invariants.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuicProtocolError> {
        if bytes.len() != HDQS_RESPONSE_BYTES {
            return Err(QuicProtocolError::LengthMismatch);
        }
        if bytes[..4] != HDQS_MAGIC {
            return Err(QuicProtocolError::InvalidMagic);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != QRM_PROTOCOL_VERSION {
            return Err(QuicProtocolError::UnsupportedVersion);
        }
        if bytes[11] != 0 {
            return Err(QuicProtocolError::InvalidStatus);
        }
        let response = Self {
            kind: HdqsKind::try_from(bytes[6])?,
            status: HdqsKind::try_from(bytes[7])?,
            session_handle: u16::from_be_bytes([bytes[8], bytes[9]]),
            reason: HdqsReason::try_from(bytes[10])?,
            connection_epoch: u64::from_be_bytes(bytes[12..20].try_into().unwrap()),
        };
        response.encode().map(|_| response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST:relay/src/quic_wire.rs[tests::relay_codec_round_trips_hdqm]
    #[test]
    fn relay_codec_round_trips_hdqm() {
        let frame = HdqmFrame {
            kind: HdqmKind::SessionOpen,
            request_id: [3; 16],
            payload: b"open".to_vec(),
        };
        assert_eq!(
            HdqmFrame::decode(&frame.encode().expect("encode")).expect("decode"),
            frame
        );
    }

    // TEST:relay/src/quic_wire.rs[tests::relay_codec_rejects_oversized_payload]
    #[test]
    fn relay_codec_rejects_oversized_payload() {
        let frame = HdqmFrame {
            kind: HdqmKind::ErrorResponse,
            request_id: [0; 16],
            payload: vec![0; QRM_MAX_CONTROL_PAYLOAD_BYTES + 1],
        };
        assert_eq!(frame.encode(), Err(QuicProtocolError::PayloadTooLarge));
    }

    // TEST:relay/src/quic_wire.rs[tests::relay_codec_rejects_malformed_frames]
    #[test]
    fn relay_codec_rejects_malformed_frames() {
        assert_eq!(
            HdqmFrame::decode(b"bad"),
            Err(QuicProtocolError::FrameTooShort)
        );
        let mut invalid = vec![0_u8; HDQM_HEADER_BYTES];
        invalid[..4].copy_from_slice(&HDQM_MAGIC);
        invalid[4..6].copy_from_slice(&QRM_PROTOCOL_VERSION.to_be_bytes());
        invalid[6] = 255;
        assert_eq!(
            HdqmFrame::decode(&invalid),
            Err(QuicProtocolError::UnknownKind)
        );
    }

    // TEST:relay/src/quic_wire.rs[tests::relay_hdqs_binding_round_trips]
    #[test]
    fn relay_hdqs_binding_round_trips() {
        let binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: 2,
            relay_generation: 3,
            connection_epoch: 4,
            session: SessionName::new("work").expect("session"),
            fingerprint: [5; 32],
            token: [6; 32],
        };
        assert_eq!(
            HdqsBinding::decode(&binding.encode().expect("encode")).expect("decode"),
            binding
        );
    }

    // TEST:relay/src/quic_wire.rs[tests::authority_debug_is_redacted]
    #[test]
    fn authority_debug_is_redacted() {
        let session = SessionName::new("work").expect("session");
        let request = SessionOpenRequest {
            session,
            fingerprint: [5; 32],
            configuration_generation: 17,
            relay_generation: 19,
            connection_epoch: 23,
            token: [7; 32],
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("fingerprint:"));
        assert!(!debug.contains("token:"));
        assert!(!debug.contains("configuration_generation: 17"));
        assert!(!debug.contains("relay_generation: 19"));
        assert!(!debug.contains("connection_epoch: 23"));
    }

    // TEST:relay/src/quic_wire.rs[tests::relay_hdqs_response_is_fixed]
    #[test]
    fn relay_hdqs_response_is_fixed() {
        let response = HdqsResponse::rejected(HdqsReason::TokenMismatch, 4);
        let debug = format!("{response:?}");
        assert!(!debug.contains("connection_epoch: 4"));
        assert_eq!(
            HdqsResponse::decode(&response.encode().expect("encode")).expect("decode"),
            response
        );
    }
}
