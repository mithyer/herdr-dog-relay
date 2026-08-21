//! Schema-neutral Broker Control framing and session-bound data gate.
//!
//! RSB-1 keeps this module independent from listeners, LaunchAgent lifecycle, Herdr sockets and
//! Relay byte forwarding.  It mirrors Core's frozen HDBR/HDBD contract so later runtime work has
//! one explicit pre-Herdr binding boundary.

use std::fmt;

/// Broker Control magic, distinct from HDRL.
pub const BROKER_CONTROL_MAGIC: [u8; 4] = *b"HDBR";
/// Session data-binding magic exchanged after HDRL.
pub const BROKER_DATA_MAGIC: [u8; 4] = *b"HDBD";
/// Frozen RSB-1 Broker protocol version.
pub const BROKER_PROTOCOL_VERSION: u16 = 1;
/// Common Broker frame header size.
pub const BROKER_FRAME_HEADER_BYTES: usize = 11;
/// Maximum encoded Broker frame size.
pub const BROKER_MAX_FRAME_BYTES: usize = 64 * 1024;
/// Maximum source-aligned session name length.
pub const BROKER_MAX_SESSION_BYTES: usize = 64;
/// Opaque Core and Broker identifier width.
pub const BROKER_ID_BYTES: usize = 16;
/// Opaque session fingerprint width.
pub const BROKER_FINGERPRINT_BYTES: usize = 32;
/// Opaque lease token width.
pub const BROKER_TOKEN_BYTES: usize = 32;
/// First Broker discovery port.
pub const BROKER_DISCOVERY_PORT_BASE: u16 = 18_743;
/// Number of Broker discovery candidates.
pub const BROKER_DISCOVERY_PORT_ATTEMPTS: u16 = 10;
/// Last Broker discovery port.
pub const BROKER_DISCOVERY_PORT_LAST: u16 =
    BROKER_DISCOVERY_PORT_BASE + BROKER_DISCOVERY_PORT_ATTEMPTS - 1;
/// First session Relay data port.
pub const BROKER_DATA_PORT_BASE: u16 = 18_753;
/// Number of session Relay data ports.
pub const BROKER_DATA_PORT_ATTEMPTS: u16 = 100;
/// Last session Relay data port.
pub const BROKER_DATA_PORT_LAST: u16 = BROKER_DATA_PORT_BASE + BROKER_DATA_PORT_ATTEMPTS - 1;
/// Maximum complete discovery sweeps.
pub const BROKER_MAX_DISCOVERY_SWEEPS: u8 = 3;

/// Broker Control message kind values mirrored from Core.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BrokerControlKind {
    /// Probe a Broker control candidate.
    DiscoveryRequest = 0x01,
    /// Return Broker identity and port policy.
    DiscoveryResponse = 0x02,
    /// Request or reuse a session lease.
    EnsureRequest = 0x10,
    /// Return a lease grant or stable rejection.
    EnsureResponse = 0x11,
    /// Renew a lease.
    HeartbeatRequest = 0x12,
    /// Return renewal status.
    HeartbeatResponse = 0x13,
    /// Release a lease.
    ReleaseRequest = 0x14,
    /// Return release status.
    ReleaseResponse = 0x15,
    /// Query bounded session status.
    StatusRequest = 0x16,
    /// Return bounded session status.
    StatusResponse = 0x17,
}

impl TryFrom<u8> for BrokerControlKind {
    type Error = BrokerProtocolError;

    /// Convert a registered wire kind without accepting arbitrary commands.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::DiscoveryRequest),
            0x02 => Ok(Self::DiscoveryResponse),
            0x10 => Ok(Self::EnsureRequest),
            0x11 => Ok(Self::EnsureResponse),
            0x12 => Ok(Self::HeartbeatRequest),
            0x13 => Ok(Self::HeartbeatResponse),
            0x14 => Ok(Self::ReleaseRequest),
            0x15 => Ok(Self::ReleaseResponse),
            0x16 => Ok(Self::StatusRequest),
            0x17 => Ok(Self::StatusResponse),
            _ => Err(BrokerProtocolError::UnknownKind),
        }
    }
}

/// HDBD data-binding message kinds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BrokerDataKind {
    /// Core's session binding proof.
    BindRequest = 0x01,
    /// Relay's accept/reject response.
    BindResponse = 0x02,
}

impl TryFrom<u8> for BrokerDataKind {
    type Error = BrokerProtocolError;

    /// Convert a registered HDBD kind without accepting Herdr passthrough commands.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::BindRequest),
            0x02 => Ok(Self::BindResponse),
            _ => Err(BrokerProtocolError::UnknownKind),
        }
    }
}

/// Redacted Broker protocol failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrokerProtocolError {
    /// The frame is shorter than its header.
    FrameTooShort,
    /// The frame magic is wrong for the selected protocol family.
    InvalidMagic,
    /// The protocol version is not supported.
    UnsupportedVersion,
    /// A preferred or selected port is outside the frozen range.
    InvalidPort,
    /// The message kind is not registered.
    UnknownKind,
    /// The frame exceeds the hard allocation bound.
    PayloadTooLarge,
    /// Header length and supplied bytes disagree.
    LengthMismatch,
    /// Typed payload fields are missing or malformed.
    InvalidPayload,
    /// The session name violates the source-aligned naming rule.
    InvalidSession,
    /// Herdr bytes were presented before the HDBD gate completed.
    BindingRequired,
    /// The binding authority did not match the active session lease.
    BindingRejected,
}

impl fmt::Display for BrokerProtocolError {
    /// Render a stable category without payload, token or endpoint text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::FrameTooShort => "broker frame too short",
            Self::InvalidMagic => "broker frame magic is invalid",
            Self::UnsupportedVersion => "broker protocol version is unsupported",
            Self::UnknownKind => "broker message kind is unknown",
            Self::PayloadTooLarge => "broker frame exceeds its bound",
            Self::LengthMismatch => "broker frame length is inconsistent",
            Self::InvalidPayload => "broker payload is invalid",
            Self::InvalidSession => "broker session name is invalid",
            Self::InvalidPort => "broker port is outside the frozen range",
            Self::BindingRequired => "session binding is required before upstream bytes",
            Self::BindingRejected => "session binding is rejected",
        };
        formatter.write_str(value)
    }
}

impl std::error::Error for BrokerProtocolError {}

/// One complete bounded Broker frame.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerFrame {
    /// Selected protocol family magic.
    magic: [u8; 4],
    /// Registered kind byte.
    kind: u8,
    /// Opaque bounded payload.
    payload: Vec<u8>,
}

impl fmt::Debug for BrokerFrame {
    /// Render frame metadata without payload bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerFrame")
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .field("magic", &self.magic)
            .finish()
    }
}

impl BrokerFrame {
    /// Construct a validated HDBR control frame.
    pub fn control(kind: BrokerControlKind, payload: Vec<u8>) -> Result<Self, BrokerProtocolError> {
        Self::new(BROKER_CONTROL_MAGIC, kind as u8, payload)
    }

    /// Construct a validated HDBD binding frame.
    pub fn data(kind: BrokerDataKind, payload: Vec<u8>) -> Result<Self, BrokerProtocolError> {
        Self::new(BROKER_DATA_MAGIC, kind as u8, payload)
    }

    /// Encode a complete frame in network byte order.
    pub fn encode(&self) -> Result<Vec<u8>, BrokerProtocolError> {
        let total = BROKER_FRAME_HEADER_BYTES
            .checked_add(self.payload.len())
            .ok_or(BrokerProtocolError::PayloadTooLarge)?;
        if total > BROKER_MAX_FRAME_BYTES {
            return Err(BrokerProtocolError::PayloadTooLarge);
        }
        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(&self.magic);
        encoded.extend_from_slice(&BROKER_PROTOCOL_VERSION.to_be_bytes());
        encoded.push(self.kind);
        encoded.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    /// Decode one complete frame with a caller-selected protocol family.
    pub fn decode(input: &[u8], expected_magic: [u8; 4]) -> Result<Self, BrokerProtocolError> {
        if input.len() < BROKER_FRAME_HEADER_BYTES {
            return Err(BrokerProtocolError::FrameTooShort);
        }
        if input[..4] != expected_magic {
            return Err(BrokerProtocolError::InvalidMagic);
        }
        if input[4..6] != BROKER_PROTOCOL_VERSION.to_be_bytes() {
            return Err(BrokerProtocolError::UnsupportedVersion);
        }
        let payload_len = u32::from_be_bytes(
            input[7..11]
                .try_into()
                .map_err(|_| BrokerProtocolError::FrameTooShort)?,
        ) as usize;
        let total = BROKER_FRAME_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(BrokerProtocolError::PayloadTooLarge)?;
        if total > BROKER_MAX_FRAME_BYTES {
            return Err(BrokerProtocolError::PayloadTooLarge);
        }
        if total != input.len() {
            return Err(BrokerProtocolError::LengthMismatch);
        }
        if expected_magic == BROKER_CONTROL_MAGIC {
            BrokerControlKind::try_from(input[6])?;
        } else if expected_magic == BROKER_DATA_MAGIC {
            BrokerDataKind::try_from(input[6])?;
        } else {
            return Err(BrokerProtocolError::InvalidMagic);
        }
        Ok(Self {
            magic: expected_magic,
            kind: input[6],
            payload: input[BROKER_FRAME_HEADER_BYTES..].to_vec(),
        })
    }

    /// Return the decoded control kind.
    pub fn control_kind(&self) -> Result<BrokerControlKind, BrokerProtocolError> {
        if self.magic != BROKER_CONTROL_MAGIC {
            return Err(BrokerProtocolError::InvalidMagic);
        }
        BrokerControlKind::try_from(self.kind)
    }

    /// Return the decoded data-binding kind.
    pub fn data_kind(&self) -> Result<BrokerDataKind, BrokerProtocolError> {
        if self.magic != BROKER_DATA_MAGIC {
            return Err(BrokerProtocolError::InvalidMagic);
        }
        BrokerDataKind::try_from(self.kind)
    }

    /// Borrow the opaque payload for a typed decoder.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Construct and validate a frame family/kind pair.
    fn new(magic: [u8; 4], kind: u8, payload: Vec<u8>) -> Result<Self, BrokerProtocolError> {
        if payload
            .len()
            .checked_add(BROKER_FRAME_HEADER_BYTES)
            .ok_or(BrokerProtocolError::PayloadTooLarge)?
            > BROKER_MAX_FRAME_BYTES
        {
            return Err(BrokerProtocolError::PayloadTooLarge);
        }
        if magic == BROKER_CONTROL_MAGIC {
            BrokerControlKind::try_from(kind)?;
        } else if magic == BROKER_DATA_MAGIC {
            BrokerDataKind::try_from(kind)?;
        } else {
            return Err(BrokerProtocolError::InvalidMagic);
        }
        Ok(Self {
            magic,
            kind,
            payload,
        })
    }
}

/// Opaque authority expected for one active session Relay child.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerBindingExpectation {
    /// Core instance authority.
    core_instance_id: [u8; BROKER_ID_BYTES],
    /// Broker instance authority.
    broker_instance_id: [u8; BROKER_ID_BYTES],
    /// Broker generation authority.
    broker_generation: u64,
    /// Session configuration generation.
    configuration_generation: u64,
    /// Session fingerprint authority.
    session_fingerprint: [u8; BROKER_FINGERPRINT_BYTES],
    /// Opaque lease token.
    lease_token: [u8; BROKER_TOKEN_BYTES],
    /// Normalized session name.
    session: String,
}

impl fmt::Debug for BrokerBindingExpectation {
    /// Redact every opaque authority field from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerBindingExpectation")
            .field("session", &self.session)
            .field("opaque_authority_present", &true)
            .finish()
    }
}

impl BrokerBindingExpectation {
    /// Construct a validated expected binding.
    pub fn new(
        core_instance_id: [u8; BROKER_ID_BYTES],
        broker_instance_id: [u8; BROKER_ID_BYTES],
        broker_generation: u64,
        configuration_generation: u64,
        session_fingerprint: [u8; BROKER_FINGERPRINT_BYTES],
        lease_token: [u8; BROKER_TOKEN_BYTES],
        session: &str,
    ) -> Result<Self, BrokerProtocolError> {
        validate_session(session)?;
        Ok(Self {
            core_instance_id,
            broker_instance_id,
            broker_generation,
            configuration_generation,
            session_fingerprint,
            lease_token,
            session: session.to_owned(),
        })
    }
}

/// A decoded HDBD binding request with opaque values retained only in memory.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerBindingRequest {
    /// Core instance authority.
    core_instance_id: [u8; BROKER_ID_BYTES],
    /// Broker instance authority.
    broker_instance_id: [u8; BROKER_ID_BYTES],
    /// Broker generation authority.
    broker_generation: u64,
    /// Session configuration generation.
    configuration_generation: u64,
    /// Session fingerprint authority.
    session_fingerprint: [u8; BROKER_FINGERPRINT_BYTES],
    /// Opaque lease token.
    lease_token: [u8; BROKER_TOKEN_BYTES],
    /// Normalized session name.
    session: String,
}

impl fmt::Debug for BrokerBindingRequest {
    /// Redact token, fingerprint and instance bytes from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerBindingRequest")
            .field("session", &self.session)
            .field("opaque_authority_present", &true)
            .finish()
    }
}

impl BrokerBindingRequest {
    /// Decode the Core HDBD request from a complete data frame.
    pub fn decode(frame: &BrokerFrame) -> Result<Self, BrokerProtocolError> {
        if frame.data_kind()? != BrokerDataKind::BindRequest {
            return Err(BrokerProtocolError::InvalidPayload);
        }
        let payload = frame.payload();
        let mut cursor = 0;
        let core_instance_id = take_array::<BROKER_ID_BYTES>(payload, &mut cursor)?;
        let broker_instance_id = take_array::<BROKER_ID_BYTES>(payload, &mut cursor)?;
        let broker_generation = take_u64(payload, &mut cursor)?;
        let configuration_generation = take_u64(payload, &mut cursor)?;
        let session_fingerprint = take_array::<BROKER_FINGERPRINT_BYTES>(payload, &mut cursor)?;
        let lease_token = take_array::<BROKER_TOKEN_BYTES>(payload, &mut cursor)?;
        let session_length = take_u8(payload, &mut cursor)? as usize;
        let end = cursor
            .checked_add(session_length)
            .ok_or(BrokerProtocolError::InvalidPayload)?;
        let session_bytes = payload
            .get(cursor..end)
            .ok_or(BrokerProtocolError::InvalidPayload)?;
        cursor = end;
        let session =
            std::str::from_utf8(session_bytes).map_err(|_| BrokerProtocolError::InvalidSession)?;
        validate_session(session)?;
        if cursor != payload.len() {
            return Err(BrokerProtocolError::InvalidPayload);
        }
        Ok(Self {
            core_instance_id,
            broker_instance_id,
            broker_generation,
            configuration_generation,
            session_fingerprint,
            lease_token,
            session: session.to_owned(),
        })
    }

    /// Compare the request with one active expected authority tuple.
    pub fn compare(&self, expected: &BrokerBindingExpectation) -> BrokerBindingDecision {
        if self.lease_token != expected.lease_token {
            return BrokerBindingDecision::LeaseRejected;
        }
        if self.core_instance_id != expected.core_instance_id {
            return BrokerBindingDecision::CoreMismatch;
        }
        if self.broker_instance_id != expected.broker_instance_id
            || self.broker_generation != expected.broker_generation
        {
            return BrokerBindingDecision::BrokerMismatch;
        }
        if self.session != expected.session {
            return BrokerBindingDecision::NameMismatch;
        }
        if self.session_fingerprint != expected.session_fingerprint
            || self.configuration_generation != expected.configuration_generation
        {
            return BrokerBindingDecision::SessionMismatch;
        }
        BrokerBindingDecision::Accepted
    }
}

/// Stable data-binding decisions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrokerBindingDecision {
    /// The binding is accepted and Herdr bytes may proceed.
    Accepted,
    /// The lease token is absent, stale or unknown.
    LeaseRejected,
    /// The Core instance does not own the lease.
    CoreMismatch,
    /// The Broker instance or generation is stale.
    BrokerMismatch,
    /// Fingerprint or configuration generation is stale.
    SessionMismatch,
    /// The normalized session name is wrong.
    NameMismatch,
}

impl BrokerBindingDecision {
    /// Return the frozen one-byte HDBD response status.
    pub const fn code(self) -> u8 {
        match self {
            Self::Accepted => 0,
            Self::LeaseRejected => 1,
            Self::CoreMismatch => 2,
            Self::BrokerMismatch => 3,
            Self::SessionMismatch => 4,
            Self::NameMismatch => 5,
        }
    }
}

/// Response emitted by the Relay data-binding gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BrokerBindingResponse {
    /// Stable accept/reject status.
    pub decision: BrokerBindingDecision,
    /// Current Broker generation.
    pub broker_generation: u64,
    /// Current session configuration generation.
    pub configuration_generation: u64,
}

impl BrokerBindingResponse {
    /// Encode this response as an HDBD frame.
    pub fn encode(self) -> Result<Vec<u8>, BrokerProtocolError> {
        let mut payload = Vec::with_capacity(17);
        payload.push(self.decision.code());
        payload.extend_from_slice(&self.broker_generation.to_be_bytes());
        payload.extend_from_slice(&self.configuration_generation.to_be_bytes());
        BrokerFrame::data(BrokerDataKind::BindResponse, payload)?.encode()
    }
}

/// Relay-side gate that keeps Herdr bytes closed until one binding is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerBindingGate {
    /// Active expected authority.
    expected: BrokerBindingExpectation,
    /// Whether forwarding is authorized; `Some(false)` is a terminal rejection.
    authorized: Option<bool>,
}

impl BrokerBindingGate {
    /// Construct a closed gate for one active lease.
    pub fn new(expected: BrokerBindingExpectation) -> Self {
        Self {
            expected,
            authorized: None,
        }
    }

    /// Decode and validate one HDBD request before any upstream forwarding.
    pub fn accept(
        &mut self,
        frame: &BrokerFrame,
    ) -> Result<BrokerBindingResponse, BrokerProtocolError> {
        if self.authorized.is_some() {
            return Err(BrokerProtocolError::InvalidPayload);
        }
        let request = match BrokerBindingRequest::decode(frame) {
            Ok(request) => request,
            Err(error) => {
                self.authorized = Some(false);
                return Err(error);
            }
        };
        let decision = request.compare(&self.expected);
        self.authorized = Some(decision == BrokerBindingDecision::Accepted);
        Ok(BrokerBindingResponse {
            decision,
            broker_generation: self.expected.broker_generation,
            configuration_generation: self.expected.configuration_generation,
        })
    }

    /// Return whether Herdr bytes may now be forwarded.
    pub const fn can_forward_upstream(&self) -> bool {
        matches!(self.authorized, Some(true))
    }

    /// Reject a forwarding attempt made before successful HDBD binding.
    pub fn authorize_upstream(&self) -> Result<(), BrokerProtocolError> {
        match self.authorized {
            Some(true) => Ok(()),
            Some(false) => Err(BrokerProtocolError::BindingRejected),
            None => Err(BrokerProtocolError::BindingRequired),
        }
    }
}

/// A bounded Broker discovery cursor mirroring Core's persisted-preference policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerDiscoveryCursor {
    /// Ordered candidate ports.
    candidates: Vec<u16>,
    /// Current sweep.
    sweep: u8,
    /// Current candidate index.
    candidate: usize,
}

impl BrokerDiscoveryCursor {
    /// Construct a cursor with an optional in-range preferred port.
    pub fn new(preferred: Option<u16>) -> Result<Self, BrokerProtocolError> {
        if preferred.is_some_and(|port| {
            !(BROKER_DISCOVERY_PORT_BASE..=BROKER_DISCOVERY_PORT_LAST).contains(&port)
        }) {
            return Err(BrokerProtocolError::InvalidPort);
        }
        let mut candidates = Vec::with_capacity(BROKER_DISCOVERY_PORT_ATTEMPTS as usize);
        if let Some(port) = preferred {
            candidates.push(port);
        }
        for port in BROKER_DISCOVERY_PORT_BASE..=BROKER_DISCOVERY_PORT_LAST {
            if Some(port) != preferred {
                candidates.push(port);
            }
        }
        Ok(Self {
            candidates,
            sweep: 0,
            candidate: 0,
        })
    }

    /// Return the next bounded `(sweep, port)` pair.
    pub fn next_candidate(&mut self) -> Option<(u8, u16)> {
        if self.sweep >= BROKER_MAX_DISCOVERY_SWEEPS {
            return None;
        }
        let sweep = self.sweep;
        let port = self.candidates[self.candidate];
        self.candidate += 1;
        if self.candidate == self.candidates.len() {
            self.candidate = 0;
            self.sweep += 1;
        }
        Some((sweep, port))
    }
}

/// Validate a source-aligned Herdr session name.
fn validate_session(session: &str) -> Result<(), BrokerProtocolError> {
    if session.is_empty()
        || session.len() > BROKER_MAX_SESSION_BYTES
        || session == "."
        || session == ".."
        || session
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        return Err(BrokerProtocolError::InvalidSession);
    }
    Ok(())
}

/// Take one fixed-width array from a payload.
fn take_array<const N: usize>(
    payload: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], BrokerProtocolError> {
    let end = cursor
        .checked_add(N)
        .ok_or(BrokerProtocolError::InvalidPayload)?;
    let bytes = payload
        .get(*cursor..end)
        .ok_or(BrokerProtocolError::InvalidPayload)?;
    *cursor = end;
    bytes
        .try_into()
        .map_err(|_| BrokerProtocolError::InvalidPayload)
}

/// Take one payload byte.
fn take_u8(payload: &[u8], cursor: &mut usize) -> Result<u8, BrokerProtocolError> {
    let value = *payload
        .get(*cursor)
        .ok_or(BrokerProtocolError::InvalidPayload)?;
    *cursor += 1;
    Ok(value)
}

/// Take one big-endian u64.
fn take_u64(payload: &[u8], cursor: &mut usize) -> Result<u64, BrokerProtocolError> {
    Ok(u64::from_be_bytes(take_array(payload, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expectation() -> BrokerBindingExpectation {
        BrokerBindingExpectation::new(
            [2; BROKER_ID_BYTES],
            [1; BROKER_ID_BYTES],
            4,
            9,
            [3; BROKER_FINGERPRINT_BYTES],
            [6; BROKER_TOKEN_BYTES],
            "main",
        )
        .expect("valid expectation")
    }

    fn binding_frame(token: [u8; BROKER_TOKEN_BYTES]) -> BrokerFrame {
        binding_frame_parts(
            [2; BROKER_ID_BYTES],
            [1; BROKER_ID_BYTES],
            4,
            9,
            [3; BROKER_FINGERPRINT_BYTES],
            token,
            "main",
        )
    }

    fn binding_frame_parts(
        core_instance_id: [u8; BROKER_ID_BYTES],
        broker_instance_id: [u8; BROKER_ID_BYTES],
        broker_generation: u64,
        configuration_generation: u64,
        session_fingerprint: [u8; BROKER_FINGERPRINT_BYTES],
        lease_token: [u8; BROKER_TOKEN_BYTES],
        session: &str,
    ) -> BrokerFrame {
        let mut payload = Vec::new();
        payload.extend_from_slice(&core_instance_id);
        payload.extend_from_slice(&broker_instance_id);
        payload.extend_from_slice(&broker_generation.to_be_bytes());
        payload.extend_from_slice(&configuration_generation.to_be_bytes());
        payload.extend_from_slice(&session_fingerprint);
        payload.extend_from_slice(&lease_token);
        payload.push(session.len() as u8);
        payload.extend_from_slice(session.as_bytes());
        BrokerFrame::data(BrokerDataKind::BindRequest, payload).expect("binding frame")
    }

    // TEST:relay/src/broker.rs[tests::control_and_data_families_are_separate]
    #[test]
    fn control_and_data_families_are_separate() {
        let control = BrokerFrame::control(BrokerControlKind::DiscoveryRequest, Vec::new())
            .expect("control")
            .encode()
            .expect("encoded");
        assert_eq!(
            BrokerFrame::decode(&control, BROKER_CONTROL_MAGIC)
                .expect("decode")
                .control_kind(),
            Ok(BrokerControlKind::DiscoveryRequest)
        );
        assert_eq!(
            BrokerFrame::decode(&control, BROKER_DATA_MAGIC),
            Err(BrokerProtocolError::InvalidMagic)
        );
    }

    // TEST:relay/src/broker.rs[tests::wrong_version_is_rejected]
    #[test]
    fn wrong_version_is_rejected() {
        let mut control = BrokerFrame::control(BrokerControlKind::DiscoveryRequest, Vec::new())
            .expect("control")
            .encode()
            .expect("encoded");
        control[5] = 2;
        assert_eq!(
            BrokerFrame::decode(&control, BROKER_CONTROL_MAGIC),
            Err(BrokerProtocolError::UnsupportedVersion)
        );
    }

    // TEST:relay/src/broker.rs[tests::binding_gate_rejects_before_upstream_authorization]
    #[test]
    fn binding_gate_rejects_before_upstream_authorization() {
        let mut gate = BrokerBindingGate::new(expectation());
        assert_eq!(
            gate.authorize_upstream(),
            Err(BrokerProtocolError::BindingRequired)
        );
        let response = gate
            .accept(&binding_frame([6; BROKER_TOKEN_BYTES]))
            .expect("binding response");
        assert_eq!(response.decision, BrokerBindingDecision::Accepted);
        assert!(gate.can_forward_upstream());
        assert_eq!(
            gate.accept(&binding_frame([6; BROKER_TOKEN_BYTES])),
            Err(BrokerProtocolError::InvalidPayload)
        );
    }

    // TEST:relay/src/broker.rs[tests::stale_token_is_rejected_without_authorizing_bytes]
    #[test]
    fn stale_token_is_rejected_without_authorizing_bytes() {
        let mut gate = BrokerBindingGate::new(expectation());
        let response = gate
            .accept(&binding_frame([7; BROKER_TOKEN_BYTES]))
            .expect("binding response");
        assert_eq!(response.decision, BrokerBindingDecision::LeaseRejected);
        assert_eq!(
            gate.authorize_upstream(),
            Err(BrokerProtocolError::BindingRejected)
        );
    }

    // TEST:relay/src/broker.rs[tests::binding_authority_mismatch_matrix_is_rejected]
    #[test]
    fn binding_authority_mismatch_matrix_is_rejected() {
        let cases = [
            (
                BrokerBindingDecision::LeaseRejected,
                binding_frame_parts(
                    [2; BROKER_ID_BYTES],
                    [1; BROKER_ID_BYTES],
                    4,
                    9,
                    [3; BROKER_FINGERPRINT_BYTES],
                    [7; BROKER_TOKEN_BYTES],
                    "main",
                ),
            ),
            (
                BrokerBindingDecision::CoreMismatch,
                binding_frame_parts(
                    [8; BROKER_ID_BYTES],
                    [1; BROKER_ID_BYTES],
                    4,
                    9,
                    [3; BROKER_FINGERPRINT_BYTES],
                    [6; BROKER_TOKEN_BYTES],
                    "main",
                ),
            ),
            (
                BrokerBindingDecision::BrokerMismatch,
                binding_frame_parts(
                    [2; BROKER_ID_BYTES],
                    [8; BROKER_ID_BYTES],
                    4,
                    9,
                    [3; BROKER_FINGERPRINT_BYTES],
                    [6; BROKER_TOKEN_BYTES],
                    "main",
                ),
            ),
            (
                BrokerBindingDecision::BrokerMismatch,
                binding_frame_parts(
                    [2; BROKER_ID_BYTES],
                    [1; BROKER_ID_BYTES],
                    5,
                    9,
                    [3; BROKER_FINGERPRINT_BYTES],
                    [6; BROKER_TOKEN_BYTES],
                    "main",
                ),
            ),
            (
                BrokerBindingDecision::SessionMismatch,
                binding_frame_parts(
                    [2; BROKER_ID_BYTES],
                    [1; BROKER_ID_BYTES],
                    4,
                    10,
                    [3; BROKER_FINGERPRINT_BYTES],
                    [6; BROKER_TOKEN_BYTES],
                    "main",
                ),
            ),
            (
                BrokerBindingDecision::SessionMismatch,
                binding_frame_parts(
                    [2; BROKER_ID_BYTES],
                    [1; BROKER_ID_BYTES],
                    4,
                    9,
                    [8; BROKER_FINGERPRINT_BYTES],
                    [6; BROKER_TOKEN_BYTES],
                    "main",
                ),
            ),
            (
                BrokerBindingDecision::NameMismatch,
                binding_frame_parts(
                    [2; BROKER_ID_BYTES],
                    [1; BROKER_ID_BYTES],
                    4,
                    9,
                    [8; BROKER_FINGERPRINT_BYTES],
                    [6; BROKER_TOKEN_BYTES],
                    "other",
                ),
            ),
            (
                BrokerBindingDecision::NameMismatch,
                binding_frame_parts(
                    [2; BROKER_ID_BYTES],
                    [1; BROKER_ID_BYTES],
                    4,
                    9,
                    [3; BROKER_FINGERPRINT_BYTES],
                    [6; BROKER_TOKEN_BYTES],
                    "other",
                ),
            ),
        ];
        for (expected, frame) in cases {
            let mut gate = BrokerBindingGate::new(expectation());
            let response = gate.accept(&frame).expect("typed mismatch response");
            assert_eq!(response.decision, expected);
            assert!(!gate.can_forward_upstream());
        }
    }

    // TEST:relay/src/broker.rs[tests::malformed_binding_terminalizes_the_gate]
    #[test]
    fn malformed_binding_terminalizes_the_gate() {
        let mut gate = BrokerBindingGate::new(expectation());
        let malformed = BrokerFrame::data(BrokerDataKind::BindRequest, Vec::new()).expect("frame");
        assert_eq!(
            gate.accept(&malformed),
            Err(BrokerProtocolError::InvalidPayload)
        );
        assert_eq!(
            gate.authorize_upstream(),
            Err(BrokerProtocolError::BindingRejected)
        );
        assert_eq!(
            gate.accept(&binding_frame([6; BROKER_TOKEN_BYTES])),
            Err(BrokerProtocolError::InvalidPayload)
        );
    }

    // TEST:relay/src/broker.rs[tests::opaque_authority_debug_is_redacted]
    #[test]
    fn opaque_authority_debug_is_redacted() {
        let expected = expectation();
        let rendered = format!("{:?}", expected);
        assert!(rendered.contains("opaque_authority_present"));
        assert!(!rendered.contains("6"));
        let request = BrokerBindingRequest::decode(&binding_frame([6; BROKER_TOKEN_BYTES]))
            .expect("binding request");
        let rendered = format!("{:?}", request);
        assert!(rendered.contains("opaque_authority_present"));
        assert!(!rendered.contains("6"));
    }

    // TEST:relay/src/broker.rs[tests::discovery_cursor_prefers_persisted_port_and_is_bounded]
    #[test]
    fn discovery_cursor_prefers_persisted_port_and_is_bounded() {
        let mut cursor = BrokerDiscoveryCursor::new(Some(18_750)).expect("preferred port");
        assert_eq!(cursor.next_candidate(), Some((0, 18_750)));
        let attempts: Vec<_> = std::iter::from_fn(|| cursor.next_candidate()).collect();
        assert_eq!(attempts.len(), 29);
        assert_eq!(cursor.next_candidate(), None);
        assert_eq!(
            BrokerDiscoveryCursor::new(Some(BROKER_DATA_PORT_BASE)),
            Err(BrokerProtocolError::InvalidPort)
        );
    }
}
