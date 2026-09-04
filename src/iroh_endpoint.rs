//! iroh-native application Relay endpoint for QRM-IROH-4.
//!
//! This module owns one iroh [`iroh::Endpoint`] and [`iroh::protocol::Router`] per application Relay process. It keeps
//! iroh transport objects, pairing input and session authority inside the Relay boundary while
//! reusing the existing bounded HDQM/HDQS and Unix bridge primitives.

use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(any(test, feature = "contract-test-support"))]
use iroh::EndpointAddr;
use iroh::{
    Endpoint, EndpointId, RelayMode, RelayUrl, SecretKey,
    endpoint::{Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::timeout,
};

use crate::{
    authority_store::{AuthorityStoreError, FileAuthorityStore},
    bridge::{self, BridgeLimits},
    quic_wire::{
        HDQM_HEADER_BYTES, HDQM_MAGIC, HDQS_MAGIC, HdqmFrame, HdqmKind, HdqsBinding, HdqsReason,
        HdqsResponse, QRM_MAX_SESSION_NAME_BYTES, SessionOpenAck, SessionOpenRequest,
        SessionPrepareAck, SessionPrepareRequest,
    },
    session_registry::{MAX_SESSION_STREAMS, SessionRegistry},
    socket::UnixSocketConnector,
};

/// Application ALPN used by the Core-to-Relay iroh connection.
pub const IROH_RELAY_ALPN: &[u8] = b"herdr-dog-iroh/1";
/// HDP1 application-control version.
pub const HDP1_VERSION: u16 = 1;
/// Maximum complete HDP1 or HDQM frame size.
pub const HDP1_MAX_FRAME_BYTES: usize = 64 * 1024;
/// HDP1 header size: magic, version, kind and payload length.
pub const HDP1_HEADER_BYTES: usize = 11;
/// The HDQM payload-length field occupies the fixed four-byte header suffix.
const HDQM_PAYLOAD_LENGTH_BYTES: usize = std::mem::size_of::<u32>();
/// Maximum number of accepted connections owned by one endpoint.
pub const MAX_IROH_CONNECTIONS: usize = 1024;
/// Maximum number of pairing records retained by one Relay process.
pub const MAX_PAIRING_RECORDS: usize = 64;
/// Maximum number of failed pairing submissions retained per peer attempt window.
pub const MAX_PAIRING_ATTEMPTS: usize = 5;
/// Maximum number of pairing challenges one peer may start in one window.
pub const MAX_PAIRING_CHALLENGES_PER_WINDOW: usize = 3;
/// Duration of the bounded per-peer pairing challenge window.
pub const PAIRING_CHALLENGE_WINDOW: Duration = Duration::from_secs(60);
/// Maximum control operation wait used by the endpoint handler.
pub const DEFAULT_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time allowed for a human to submit a code after a challenge is created.
pub const PAIRING_CHALLENGE_TTL_SECS: u64 = 300;
/// Host namespace for the Relay-owned iroh identity record.
const RELAY_IDENTITY_STORAGE_KEY: &str = "herdr-dog/relay/iroh-identity";
/// Fixed filename for the Relay-owned iroh identity record.
const RELAY_IDENTITY_FILENAME: &str = "relay-iroh-identity.json";
/// Record kind for the Relay-owned iroh identity.
const RELAY_IDENTITY_RECORD_KIND: &str = "core_identity";
/// Maximum JSON payload used by the development identity record.
const MAX_RELAY_IDENTITY_PAYLOAD_BYTES: usize = 1024;
/// Initial generation used by a newly created Relay identity.
const INITIAL_IDENTITY_GENERATION: u64 = 1;
/// Initial pairing-attempt identifier for a process with no recovered metadata.
const INITIAL_PAIRING_ATTEMPT_ID: u64 = 1;
/// Initial pairing-authority generation for a newly observed peer.
const INITIAL_PAIRING_GENERATION: u64 = 1;
/// Initial peer identity generation until the wire contract carries a newer value.
const INITIAL_PEER_IDENTITY_GENERATION: u64 = 1;
/// Host namespace for the Relay pairing-authority record.
const PAIRING_AUTHORITY_STORAGE_KEY: &str = "herdr-dog/relay/iroh-pairing-authority";
/// Fixed filename for the Relay pairing-authority record.
const PAIRING_AUTHORITY_FILENAME: &str = "relay-iroh-pairing-authority.json";
/// Record kind for the Relay pairing-authority record.
const PAIRING_AUTHORITY_RECORD_KIND: &str = "pairing_authority";
/// Host namespace for the Relay runtime-fence record.
const RUNTIME_FENCE_STORAGE_KEY: &str = "herdr-dog/relay/iroh-runtime-fence";
/// Fixed filename for the Relay runtime-fence record.
const RUNTIME_FENCE_FILENAME: &str = "relay-iroh-runtime-fence.json";
/// Record kind for the Relay runtime-fence record.
const RUNTIME_FENCE_RECORD_KIND: &str = "runtime_fence";
/// Maximum persisted pairing relations accepted during restart recovery.
const MAX_PERSISTED_PAIRING_RELATIONS: usize = MAX_PAIRING_RECORDS;

/// Stable HDP1 control kinds exchanged on the one control stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HdpKind {
    /// Starts or resumes the bounded pairing exchange.
    PairingStart = 1,
    /// Carries one transient six-digit pairing code.
    PairingSubmit = 2,
    /// Reports successful application pairing.
    PairingAccepted = 3,
    /// Reports a sanitized pairing rejection category.
    PairingRejected = 4,
    /// Reports that the connection may request bounded sessions.
    ConnectionReady = 5,
    /// Requests bounded connection shutdown.
    GoAway = 6,
}

impl TryFrom<u8> for HdpKind {
    type Error = HdpFrameError;

    /// Decodes one registered HDP1 kind.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::PairingStart),
            2 => Ok(Self::PairingSubmit),
            3 => Ok(Self::PairingAccepted),
            4 => Ok(Self::PairingRejected),
            5 => Ok(Self::ConnectionReady),
            6 => Ok(Self::GoAway),
            _ => Err(HdpFrameError::UnknownKind),
        }
    }
}

/// Redacted HDP1 frame validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HdpFrameError {
    /// The frame did not contain a complete fixed header.
    #[error("HDP1 frame is too short")]
    FrameTooShort,
    /// The frame magic did not match HDP1.
    #[error("HDP1 frame magic is invalid")]
    InvalidMagic,
    /// The frame version is not supported.
    #[error("HDP1 version is unsupported")]
    UnsupportedVersion,
    /// The frame kind is not registered.
    #[error("HDP1 kind is unknown")]
    UnknownKind,
    /// The complete frame exceeded the fixed bound.
    #[error("HDP1 frame exceeds the bounded limit")]
    FrameTooLarge,
    /// The declared payload length did not match the bytes supplied.
    #[error("HDP1 frame length is invalid")]
    LengthMismatch,
}

/// One bounded HDP1 frame.
#[derive(Clone, Eq, PartialEq)]
pub struct HdpFrame {
    /// Registered control kind.
    kind: HdpKind,
    /// Control payload retained only for the current stream operation.
    payload: Vec<u8>,
}

impl fmt::Debug for HdpFrame {
    /// Formats kind and payload length without exposing control bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HdpFrame")
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl HdpFrame {
    /// Creates a frame for an internal Relay control operation.
    fn new(kind: HdpKind, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            payload: payload.into(),
        }
    }

    /// Returns the registered control kind.
    pub fn kind(&self) -> HdpKind {
        self.kind
    }

    /// Returns the payload length without exposing payload contents.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Encodes one complete bounded HDP1 frame.
    pub fn encode(&self) -> Result<Vec<u8>, HdpFrameError> {
        let total = HDP1_HEADER_BYTES
            .checked_add(self.payload.len())
            .ok_or(HdpFrameError::FrameTooLarge)?;
        if total > HDP1_MAX_FRAME_BYTES {
            return Err(HdpFrameError::FrameTooLarge);
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(b"HDP1");
        bytes.extend_from_slice(&HDP1_VERSION.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decodes one complete HDP1 frame without retaining free-form diagnostics.
    pub fn decode(bytes: &[u8]) -> Result<Self, HdpFrameError> {
        if bytes.len() < HDP1_HEADER_BYTES {
            return Err(HdpFrameError::FrameTooShort);
        }
        if bytes[..4] != *b"HDP1" {
            return Err(HdpFrameError::InvalidMagic);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != HDP1_VERSION {
            return Err(HdpFrameError::UnsupportedVersion);
        }
        let kind = HdpKind::try_from(bytes[6])?;
        let payload_len = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
        let total = HDP1_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(HdpFrameError::FrameTooLarge)?;
        if total > HDP1_MAX_FRAME_BYTES {
            return Err(HdpFrameError::FrameTooLarge);
        }
        if bytes.len() != total {
            return Err(HdpFrameError::LengthMismatch);
        }
        Ok(Self {
            kind,
            payload: bytes[HDP1_HEADER_BYTES..].to_vec(),
        })
    }
}

impl Drop for HdpFrame {
    /// Clears transient control payload bytes when the private frame leaves Relay memory.
    fn drop(&mut self) {
        self.payload.fill(0);
    }
}

/// Stable errors returned while creating or shutting down an iroh Relay endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IrohEndpointError {
    /// A bounded endpoint setting was invalid.
    #[error("invalid iroh Relay endpoint configuration: {field}")]
    InvalidConfiguration {
        /// Stable configuration field name.
        field: &'static str,
    },
    /// The iroh endpoint could not bind.
    #[error("iroh Relay endpoint bind failed")]
    Bind,
    /// The iroh Router could not shut down cleanly.
    #[error("iroh Relay Router shutdown failed")]
    Shutdown,
    /// The selected provider cannot be mapped to the local iroh runtime.
    #[error("iroh Relay provider is unavailable")]
    ProviderUnavailable,
    /// A development recovery record failed closed.
    #[error("iroh Relay authority storage failed")]
    AuthorityStorage,
}

/// Development-only payload for the Relay-owned `core_identity` record.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRelayIdentity {
    /// Public EndpointId derived from the protected private key.
    endpoint_id: [u8; 32],
    /// Private key bytes retained only by this explicitly insecure local profile.
    secret_key: [u8; 32],
}

/// Own transient identity payload bytes and clear them on every return path.
struct ZeroizingIdentityBytes(Vec<u8>);

impl ZeroizingIdentityBytes {
    /// Wrap serialized identity bytes before passing them to the local record store.
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the serialized bytes for one bounded store operation.
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ZeroizingIdentityBytes {
    /// Clear serialized identity bytes before releasing the allocation.
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Serialize a Relay identity for the explicitly development-insecure recovery profile.
fn encode_relay_identity(
    secret_key: &SecretKey,
) -> Result<ZeroizingIdentityBytes, IrohEndpointError> {
    let mut identity = PersistedRelayIdentity {
        endpoint_id: *secret_key.public().as_bytes(),
        secret_key: secret_key.to_bytes(),
    };
    let payload = serde_json::to_vec(&identity);
    identity.secret_key.fill(0);
    let payload = payload.map_err(|_| IrohEndpointError::AuthorityStorage)?;
    if payload.len() > MAX_RELAY_IDENTITY_PAYLOAD_BYTES {
        return Err(IrohEndpointError::AuthorityStorage);
    }
    Ok(ZeroizingIdentityBytes::new(payload))
}

/// Decode and validate one persisted Relay identity without exposing its key or endpoint ID.
fn decode_relay_identity(
    record: crate::authority_store::StoredAuthorityRecord,
) -> Result<(SecretKey, u64), IrohEndpointError> {
    let (_revision, generation, state, payload) = record.into_parts();
    let payload = ZeroizingIdentityBytes::new(payload);
    if state != "active"
        || generation == 0
        || payload.as_slice().len() > MAX_RELAY_IDENTITY_PAYLOAD_BYTES
    {
        return Err(IrohEndpointError::AuthorityStorage);
    }
    let mut identity = serde_json::from_slice::<PersistedRelayIdentity>(payload.as_slice())
        .map_err(|_| IrohEndpointError::AuthorityStorage)?;
    let key = SecretKey::from_bytes(&identity.secret_key);
    let valid = EndpointId::from_bytes(&identity.endpoint_id).is_ok()
        && key.public().as_bytes() == &identity.endpoint_id;
    identity.secret_key.fill(0);
    if !valid {
        return Err(IrohEndpointError::AuthorityStorage);
    }
    Ok((key, generation))
}

/// Load the Relay identity without creating a record for a missing recovery directory.
fn load_relay_identity(
    store: &FileAuthorityStore,
) -> Result<Option<(SecretKey, u64)>, IrohEndpointError> {
    store
        .load(
            RELAY_IDENTITY_STORAGE_KEY,
            RELAY_IDENTITY_RECORD_KIND,
            RELAY_IDENTITY_FILENAME,
        )
        .map_err(|_| IrohEndpointError::AuthorityStorage)?
        .map(decode_relay_identity)
        .transpose()
}

/// Load or explicitly create one Relay identity while reconciling a known first-writer race.
fn load_or_create_relay_identity(
    store: &FileAuthorityStore,
    supplied: Option<&SecretKey>,
) -> Result<(SecretKey, u64), IrohEndpointError> {
    load_or_create_relay_identity_with_before_commit(store, supplied, |_| {})
}

/// Load or create one Relay identity with a hook immediately before the first commit.
///
/// The production caller supplies a no-op hook; focused tests use it to deterministically create
/// a competing first writer and exercise the conflict-reconciliation branch.
fn load_or_create_relay_identity_with_before_commit<F>(
    store: &FileAuthorityStore,
    supplied: Option<&SecretKey>,
    before_commit: F,
) -> Result<(SecretKey, u64), IrohEndpointError>
where
    F: FnOnce(&FileAuthorityStore),
{
    if let Some((recovered, generation)) = load_relay_identity(store)? {
        if supplied
            .is_some_and(|candidate| candidate.public().as_bytes() != recovered.public().as_bytes())
        {
            return Err(IrohEndpointError::AuthorityStorage);
        }
        // An implicit bind may adopt the identity won by another first writer.
        return Ok((recovered, generation));
    }

    let Some(candidate) = supplied.cloned() else {
        // Recovery bind is read-only for a missing identity; explicit key supply is the ensure path.
        return Err(IrohEndpointError::AuthorityStorage);
    };
    let payload = encode_relay_identity(&candidate)?;
    before_commit(store);
    let commit = store.commit(
        RELAY_IDENTITY_STORAGE_KEY,
        RELAY_IDENTITY_RECORD_KIND,
        RELAY_IDENTITY_FILENAME,
        INITIAL_IDENTITY_GENERATION,
        "active",
        payload.as_slice(),
        0,
    );
    drop(payload);
    match commit {
        Ok(_) => Ok((candidate, INITIAL_IDENTITY_GENERATION)),
        Err(AuthorityStoreError::Conflict) => {
            let Some((recovered, generation)) = load_relay_identity(store)? else {
                return Err(IrohEndpointError::AuthorityStorage);
            };
            // Only an explicit identity is required to match the concurrent winner. An implicit
            // bind may reuse that winner after the first-writer race.
            if supplied.is_some() && recovered.public().as_bytes() != candidate.public().as_bytes()
            {
                return Err(IrohEndpointError::AuthorityStorage);
            }
            Ok((recovered, generation))
        }
        Err(_) => Err(IrohEndpointError::AuthorityStorage),
    }
}

/// Resolve the Relay key and identity generation from the local recovery profile or an explicitly supplied key.
fn resolve_relay_secret_key(
    config: &IrohRelayConfig,
    supplied: Option<SecretKey>,
) -> Result<(SecretKey, u64), IrohEndpointError> {
    match config.authority_store.as_ref() {
        Some(store) => load_or_create_relay_identity(store, supplied.as_ref()),
        None => Ok((
            supplied.unwrap_or_else(SecretKey::generate),
            INITIAL_IDENTITY_GENERATION,
        )),
    }
}
///
/// Production implementations are expected to run the fixed verification-workspace contract
/// before returning. The code argument is transient and must never be logged, persisted or
/// returned by an implementation.
pub trait PairingVerifier: Send + Sync + fmt::Debug + 'static {
    /// Starts the fixed Relay-side pairing challenge for the authenticated peer.
    ///
    /// The implementation may create the bounded verification workspace here, but it must keep
    /// the generated code and workspace identity inside the Relay process.
    ///
    /// # Parameters
    /// * `peer` - Authenticated iroh EndpointId of the Core.
    ///
    /// # Returns
    /// `true` when the challenge was created and is ready for one transient submission.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_requires_control_exchange]
    fn begin(&self, peer: EndpointId) -> Pin<Box<dyn Future<Output = bool> + Send>>;

    /// Verifies one transient pairing attempt for the authenticated peer.
    ///
    /// # Parameters
    /// * `peer` - Authenticated iroh EndpointId of the Core.
    /// * `code` - Exactly six ASCII digits retained only for this call.
    ///
    /// # Returns
    /// `true` when the fixed Relay-side verifier accepted the attempt.
    fn verify(&self, peer: EndpointId, code: [u8; 6])
    -> Pin<Box<dyn Future<Output = bool> + Send>>;

    /// Cleans up the current pairing challenge after disconnect, expiry or terminal rejection.
    ///
    /// # Parameters
    /// * `peer` - Authenticated iroh EndpointId whose transient challenge should be removed.
    ///
    /// # Returns
    /// A future that completes after best-effort workspace cleanup.
    fn cancel(&self, peer: EndpointId) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// A default fail-closed verifier for endpoints that have no configured pairing backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectAllPairing;

impl PairingVerifier for RejectAllPairing {
    /// Rejects every pairing challenge without retaining the peer or code.
    fn begin(&self, _peer: EndpointId) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        Box::pin(async { false })
    }

    /// Rejects every pairing attempt without retaining the supplied code.
    fn verify(
        &self,
        _peer: EndpointId,
        mut code: [u8; 6],
    ) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        code.fill(0);
        Box::pin(async { false })
    }

    /// Performs no cleanup because this verifier never creates a challenge.
    fn cancel(&self, _peer: EndpointId) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }
}

/// A fixed Herdr verification-workspace pairing implementation.
///
/// PairingStart creates one hidden workspace and retains only its transient code/workspace binding;
/// successful, expired and disconnected attempts all close that workspace before authority changes.
#[derive(Clone)]
pub struct HerdrWorkspacePairingVerifier {
    /// Fixed-session Herdr client used only for workspace create/get/close.
    workspace: crate::bootstrap_runtime::HerdrWorkspaceClient,
    /// Transient pairing attempts keyed by authenticated Core EndpointId.
    attempts: Arc<tokio::sync::Mutex<BTreeMap<EndpointId, PendingPairing>>>,
}

/// Transient workspace binding retained during one pairing attempt.
#[derive(Clone)]
struct PendingPairing {
    /// Six-digit code shown only through the designated Herdr workspace label.
    code: [u8; 6],
    /// Workspace identifier required for exact cleanup.
    workspace_id: String,
    /// Monotonic expiry used to reject stale submissions.
    expires_at: Instant,
}

impl Drop for PendingPairing {
    /// Clears the transient pairing code when the attempt leaves Relay memory.
    fn drop(&mut self) {
        self.code.fill(0);
    }
}

impl fmt::Debug for HerdrWorkspacePairingVerifier {
    /// Reports verifier presence without exposing workspace paths, IDs or pairing state.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HerdrWorkspacePairingVerifier")
            .field("workspace_verifier_present", &true)
            .field("attempts_present", &true)
            .finish()
    }
}

impl HerdrWorkspacePairingVerifier {
    /// Construct the fixed verifier from the existing protected Relay enrollment configuration.
    ///
    /// # Parameters
    /// * `config` - Validated Relay configuration containing the fixed Herdr session/cwd.
    /// * `expected_uid` - UID required by the validated Herdr Unix socket connector.
    ///
    /// # Returns
    /// A verifier that performs only the fixed workspace create/get/close exchange.
    pub fn from_relay_config(
        config: &crate::config::RelayConfig,
        expected_uid: u32,
    ) -> Result<Self, IrohEndpointError> {
        if !config.enrollment().enabled() {
            return Err(IrohEndpointError::InvalidConfiguration {
                field: "enrollment.enabled",
            });
        }
        let session = config.enrollment().bootstrap_session().to_owned();
        let workspace = crate::bootstrap_runtime::HerdrWorkspaceClient::new(
            crate::bootstrap_runtime::session_socket_path(&session),
            expected_uid,
            config.enrollment().bootstrap_verification_cwd().to_owned(),
            session,
        )
        .map_err(|_| IrohEndpointError::InvalidConfiguration {
            field: "enrollment.bootstrap_verification_cwd",
        })?;
        Ok(Self {
            workspace,
            attempts: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
        })
    }

    /// Construct the fixed verifier from the standalone iroh runtime configuration.
    ///
    /// # Parameters
    /// * `config` - Validated socket, session and verification-cwd settings.
    ///
    /// # Returns
    /// A verifier that performs only the fixed workspace create/get/close exchange.
    pub fn from_runtime_config(
        config: &crate::config::IrohPairingConfig,
    ) -> Result<Self, IrohEndpointError> {
        let verification_cwd =
            config
                .verification_cwd()
                .to_str()
                .ok_or(IrohEndpointError::InvalidConfiguration {
                    field: "iroh.pairing.verification_cwd",
                })?;
        let workspace = crate::bootstrap_runtime::HerdrWorkspaceClient::new(
            config.socket_path().to_path_buf(),
            config.expected_uid(),
            verification_cwd.to_owned(),
            config.session().to_owned(),
        )
        .map_err(|_| IrohEndpointError::InvalidConfiguration {
            field: "iroh.pairing",
        })?;
        Ok(Self {
            workspace,
            attempts: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
        })
    }

    /// Create and retain one bounded workspace challenge for an authenticated peer.
    async fn begin_attempt(&self, peer: EndpointId) -> bool {
        // Check capacity before creating a Herdr workspace so reconnect churn cannot create
        // transient workspaces after the bounded verifier map is full.
        {
            let attempts = self.attempts.lock().await;
            if attempts.len() >= MAX_PAIRING_RECORDS || attempts.contains_key(&peer) {
                return false;
            }
        }
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        let Some(expires_at_epoch_seconds) = now.as_secs().checked_add(PAIRING_CHALLENGE_TTL_SECS)
        else {
            return false;
        };
        let code = crate::bootstrap_runtime::random_code();
        let Ok(title) =
            crate::bootstrap_runtime::verification_title(code, expires_at_epoch_seconds)
        else {
            return false;
        };
        let Ok(workspace_id) = self.workspace.create_and_verify(&title).await else {
            return false;
        };
        let Some(expires_at) =
            Instant::now().checked_add(Duration::from_secs(PAIRING_CHALLENGE_TTL_SECS))
        else {
            let _ = self.workspace.close(&workspace_id).await;
            return false;
        };
        let mut attempts = self.attempts.lock().await;
        if attempts.len() >= MAX_PAIRING_RECORDS || attempts.contains_key(&peer) {
            drop(attempts);
            let _ = self.workspace.close(&workspace_id).await;
            return false;
        }
        attempts.insert(
            peer,
            PendingPairing {
                code,
                workspace_id,
                expires_at,
            },
        );
        true
    }

    /// Verify one transient code and close the exact workspace on terminal success/expiry.
    async fn verify_attempt(&self, peer: EndpointId, mut code: [u8; 6]) -> bool {
        let Some((pending, expired)) = ({
            let attempts = self.attempts.lock().await;
            let Some(candidate) = attempts.get(&peer) else {
                code.fill(0);
                return false;
            };
            if Instant::now() >= candidate.expires_at {
                Some((candidate.clone(), true))
            } else if crate::bootstrap_runtime::constant_time_equal(&candidate.code, &code) {
                Some((candidate.clone(), false))
            } else {
                code.fill(0);
                return false;
            }
        }) else {
            code.fill(0);
            return false;
        };
        code.fill(0);
        // Keep an expired or matched record until close succeeds so a failed close can be retried
        // by the disconnect cleanup path without losing the exact workspace identity.
        if self.workspace.close(&pending.workspace_id).await.is_err() {
            return false;
        }
        let mut attempts = self.attempts.lock().await;
        if attempts
            .get(&peer)
            .is_some_and(|current| current.workspace_id == pending.workspace_id)
        {
            attempts.remove(&peer);
        }
        !expired
    }

    /// Cancel one transient challenge and close its exact workspace when present.
    async fn cancel_attempt(&self, peer: EndpointId) {
        let pending = self.attempts.lock().await.get(&peer).cloned();
        let Some(pending) = pending else {
            return;
        };
        // Keep the record and workspace identity when close fails so a later cleanup can retry.
        if self.workspace.close(&pending.workspace_id).await.is_err() {
            return;
        }
        let mut attempts = self.attempts.lock().await;
        if attempts
            .get(&peer)
            .is_some_and(|current| current.workspace_id == pending.workspace_id)
        {
            attempts.remove(&peer);
        }
    }
}

impl PairingVerifier for HerdrWorkspacePairingVerifier {
    /// Creates the fixed hidden workspace challenge before accepting submissions.
    fn begin(&self, peer: EndpointId) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        let verifier = self.clone();
        Box::pin(async move { verifier.begin_attempt(peer).await })
    }

    /// Compares the transient code and closes the verified workspace on success.
    fn verify(
        &self,
        peer: EndpointId,
        code: [u8; 6],
    ) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        let verifier = self.clone();
        Box::pin(async move { verifier.verify_attempt(peer, code).await })
    }

    /// Closes the challenge workspace after disconnect or terminal rejection.
    fn cancel(&self, peer: EndpointId) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let verifier = self.clone();
        Box::pin(async move { verifier.cancel_attempt(peer).await })
    }
}

/// Bounded configuration for one application Relay iroh endpoint.
#[derive(Clone, Debug)]
pub struct IrohRelayConfig {
    /// Maximum number of simultaneous Core connections.
    max_connections: usize,
    /// Maximum active/prepared sessions per Core connection.
    max_sessions_per_connection: usize,
    /// Deadline for pairing and control frame operations.
    control_timeout: Duration,
    /// Relay process generation carried into session authority.
    relay_generation: u64,
    /// Optional validated Herdr Unix socket connector used by session streams.
    socket_connector: Option<UnixSocketConnector>,
    /// Optional explicit IP bind address; absent means iroh's normal IP binds.
    bind_addr: Option<SocketAddr>,
    /// Relay mode selected by the Core/admin-owned provider configuration.
    relay_mode: RelayMode,
    /// Optional local recovery store for the explicitly development-insecure profile.
    authority_store: Option<Arc<FileAuthorityStore>>,
}

impl Default for IrohRelayConfig {
    /// Builds the fixed bounded default endpoint policy.
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_sessions_per_connection: MAX_SESSION_STREAMS,
            control_timeout: DEFAULT_CONTROL_TIMEOUT,
            relay_generation: 1,
            socket_connector: None,
            bind_addr: None,
            relay_mode: RelayMode::Default,
            authority_store: None,
        }
    }
}

impl IrohRelayConfig {
    /// Creates a bounded endpoint configuration.
    ///
    /// # Parameters
    /// * `max_connections` - Maximum simultaneous Core connections.
    /// * `max_sessions_per_connection` - Maximum prepared/active sessions per pair.
    /// * `control_timeout` - Pairing/control operation deadline.
    ///
    /// # Returns
    /// A validated configuration or a redacted configuration error.
    pub fn new(
        max_connections: usize,
        max_sessions_per_connection: usize,
        control_timeout: Duration,
    ) -> Result<Self, IrohEndpointError> {
        let config = Self {
            max_connections,
            max_sessions_per_connection,
            control_timeout,
            ..Self::default()
        };
        config.validate()?;
        Ok(config)
    }

    /// Adds the validated Unix socket used by admitted session streams.
    ///
    /// # Parameters
    /// * `connector` - Existing owner/mode/type-validated socket connector.
    ///
    /// # Returns
    /// The same endpoint configuration with the connector retained.
    pub fn with_socket_connector(mut self, connector: UnixSocketConnector) -> Self {
        self.socket_connector = Some(connector);
        self
    }

    /// Sets a non-zero Relay process generation for session authority.
    ///
    /// # Parameters
    /// * `generation` - Non-zero process generation.
    ///
    /// # Returns
    /// The same configuration, or a redacted validation error.
    pub fn with_relay_generation(mut self, generation: u64) -> Result<Self, IrohEndpointError> {
        if generation == 0 {
            return Err(IrohEndpointError::InvalidConfiguration {
                field: "relay_generation",
            });
        }
        self.relay_generation = generation;
        Ok(self)
    }

    /// Sets an explicit IP bind address, primarily for local test isolation.
    ///
    /// # Parameters
    /// * `address` - IP socket address; port zero requests an ephemeral port.
    ///
    /// # Returns
    /// The same configuration with the requested bind address.
    pub fn with_bind_addr(mut self, address: SocketAddr) -> Self {
        self.bind_addr = Some(address);
        self
    }

    /// Select a bounded custom relay map from operator-provisioned HTTPS URLs.
    ///
    /// # Parameters
    /// * `relay_urls` - Nonempty approved relay URL strings.
    ///
    /// # Returns
    /// The same endpoint configuration with explicit custom relay mode, or a redacted validation error.
    pub fn with_relay_urls(mut self, relay_urls: &[String]) -> Result<Self, IrohEndpointError> {
        if relay_urls.is_empty() || relay_urls.len() > 4 {
            return Err(IrohEndpointError::InvalidConfiguration {
                field: "relay_urls",
            });
        }
        let parsed = relay_urls
            .iter()
            .map(|value| RelayUrl::from_str(value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| IrohEndpointError::InvalidConfiguration {
                field: "relay_urls",
            })?;
        if parsed
            .iter()
            .any(|url| url.scheme() != "https" || url.host_str().is_none())
        {
            return Err(IrohEndpointError::InvalidConfiguration {
                field: "relay_urls",
            });
        }
        self.relay_mode = RelayMode::custom(parsed);
        Ok(self)
    }

    /// Disable network-relay use for deterministic local and contract tests.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_mode_defaults_to_public_and_tests_disable_relay]
    #[cfg(any(test, feature = "contract-test-support"))]
    pub fn without_network_relay_for_test(mut self) -> Self {
        self.relay_mode = RelayMode::Disabled;
        self
    }

    /// Attach an absolute local recovery directory for task #62 validation only.
    ///
    /// # Parameters
    /// * `root` - Host-selected directory for bounded pairing and runtime records.
    ///
    /// # Returns
    /// The same configuration with a lazy recovery store, or a sanitized path error.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_authority_store_round_trip]
    pub fn with_development_recovery_dir(
        mut self,
        root: impl AsRef<std::path::Path>,
    ) -> Result<Self, IrohEndpointError> {
        self.authority_store = Some(FileAuthorityStore::open(root).map_err(|_| {
            IrohEndpointError::InvalidConfiguration {
                field: "development_recovery_dir",
            }
        })?);
        Ok(self)
    }

    /// Returns the configured maximum connection count.
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Returns the configured per-connection session limit.
    pub const fn max_sessions_per_connection(&self) -> usize {
        self.max_sessions_per_connection
    }

    /// Returns the bounded control deadline.
    pub const fn control_timeout(&self) -> Duration {
        self.control_timeout
    }

    /// Returns the Relay process generation.
    pub const fn relay_generation(&self) -> u64 {
        self.relay_generation
    }

    /// Validates all fixed resource bounds before endpoint construction.
    fn validate(&self) -> Result<(), IrohEndpointError> {
        if self.max_connections == 0 || self.max_connections > MAX_IROH_CONNECTIONS {
            return Err(IrohEndpointError::InvalidConfiguration {
                field: "max_connections",
            });
        }
        if self.max_sessions_per_connection == 0
            || self.max_sessions_per_connection > MAX_SESSION_STREAMS
        {
            return Err(IrohEndpointError::InvalidConfiguration {
                field: "max_sessions_per_connection",
            });
        }
        if self.control_timeout.is_zero() || self.control_timeout > Duration::from_secs(30) {
            return Err(IrohEndpointError::InvalidConfiguration {
                field: "control_timeout",
            });
        }
        if self.relay_generation == 0 {
            return Err(IrohEndpointError::InvalidConfiguration {
                field: "relay_generation",
            });
        }
        Ok(())
    }
}

/// Pairing metadata retained for one authenticated EndpointId.
#[derive(Clone, Copy, Debug)]
struct PairingRecord {
    /// Monotonic pairing-authority generation for this peer identity.
    pairing_generation: u64,
    /// Relay identity generation that owns this relation.
    local_identity_generation: u64,
    /// Core identity generation observed when this relation was confirmed.
    peer_identity_generation: u64,
    /// Whether normal session admission is currently authorized.
    paired: bool,
    /// Whether this relation is a durable revocation tombstone.
    revoked: bool,
    /// Last bounded wall-clock update time for audit and recovery checks.
    updated_at_epoch_seconds: u64,
    /// Bounded pairing-attempt identifier associated with the last update.
    last_attempt_id: u64,
    /// Number of failed code attempts in the current bounded challenge.
    failed_attempts: usize,
    /// Start time of the per-peer challenge-rate window.
    challenge_window_started: Instant,
    /// Number of challenge workspaces started in the current rate window.
    challenge_count: usize,
}

/// JSON payload for the persistent Relay pairing-authority record.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedPairingAuthority {
    /// Peer relations without transient challenge or session material.
    relations: Vec<PersistedPairingRelation>,
}

/// One persisted Relay pairing relation.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedPairingRelation {
    /// Authenticated Core EndpointId bytes.
    peer_id: [u8; 32],
    /// Relay identity generation that owns this relation.
    local_identity_generation: u64,
    /// Core identity generation observed when this relation was confirmed.
    peer_identity_generation: u64,
    /// Monotonic pairing-authority generation.
    pairing_generation: u64,
    /// Durable revocation marker.
    revoked: bool,
    /// Last bounded wall-clock update time.
    updated_at_epoch_seconds: u64,
    /// Bounded pairing-attempt identifier associated with the last update.
    last_attempt_id: u64,
}

/// Return a bounded wall-clock timestamp for persisted authority metadata.
fn authority_timestamp() -> Result<u64, AuthorityStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().max(1))
        .map_err(|_| AuthorityStoreError::Unknown)
}

/// Encode only paired or revoked relations, excluding transient connection records.
fn encode_pairing_authority(
    pairings: &BTreeMap<EndpointId, PairingRecord>,
) -> Result<(Vec<u8>, u64), AuthorityStoreError> {
    let mut aggregate_generation = 1_u64;
    let relations = pairings
        .iter()
        .filter(|(_, record)| record.paired || record.revoked)
        .map(|(peer_id, record)| {
            if record.pairing_generation == 0
                || record.local_identity_generation == 0
                || record.peer_identity_generation == 0
                || record.updated_at_epoch_seconds == 0
                || record.last_attempt_id == 0
            {
                return Err(AuthorityStoreError::Invalid);
            }
            aggregate_generation = aggregate_generation.max(record.pairing_generation);
            Ok(PersistedPairingRelation {
                peer_id: *peer_id.as_bytes(),
                local_identity_generation: record.local_identity_generation,
                peer_identity_generation: record.peer_identity_generation,
                pairing_generation: record.pairing_generation,
                revoked: record.revoked,
                updated_at_epoch_seconds: record.updated_at_epoch_seconds,
                last_attempt_id: record.last_attempt_id,
            })
        })
        .collect::<Result<Vec<_>, AuthorityStoreError>>()?;
    if relations.len() > MAX_PERSISTED_PAIRING_RELATIONS {
        return Err(AuthorityStoreError::Invalid);
    }
    let payload = serde_json::to_vec(&PersistedPairingAuthority { relations })
        .map_err(|_| AuthorityStoreError::Invalid)?;
    if payload.len() > crate::authority_store::MAX_AUTHORITY_PAYLOAD_BYTES {
        return Err(AuthorityStoreError::Invalid);
    }
    Ok((payload, aggregate_generation))
}

/// Encode an empty Relay pairing replacement while preserving authority-generation monotonicity.
fn encode_empty_pairing_authority(generation: u64) -> Result<(Vec<u8>, u64), AuthorityStoreError> {
    if generation == 0 {
        return Err(AuthorityStoreError::Unknown);
    }
    let payload = serde_json::to_vec(&PersistedPairingAuthority {
        relations: Vec::new(),
    })
    .map_err(|_| AuthorityStoreError::Invalid)?;
    Ok((payload, generation))
}

/// Restore persistent relations while rebuilding all challenge fields as fresh process state.
fn restore_pairing_authority(
    store: &FileAuthorityStore,
    expected_local_identity_generation: u64,
) -> Result<(BTreeMap<EndpointId, PairingRecord>, u64, u64, u64), AuthorityStoreError> {
    if expected_local_identity_generation == 0 {
        return Err(AuthorityStoreError::Invalid);
    }
    let Some(record) = store.load(
        PAIRING_AUTHORITY_STORAGE_KEY,
        PAIRING_AUTHORITY_RECORD_KIND,
        PAIRING_AUTHORITY_FILENAME,
    )?
    else {
        return Ok((BTreeMap::new(), 0, INITIAL_PAIRING_ATTEMPT_ID, 0));
    };
    let (revision, aggregate_generation, state, payload) = record.into_parts();
    if state != "active" || aggregate_generation == 0 {
        return Err(AuthorityStoreError::Corrupt);
    }
    let decoded = serde_json::from_slice::<PersistedPairingAuthority>(&payload)
        .map_err(|_| AuthorityStoreError::Corrupt)?;
    if decoded.relations.len() > MAX_PERSISTED_PAIRING_RELATIONS {
        return Err(AuthorityStoreError::Corrupt);
    }
    // An empty relation set is an explicit committed replacement; missing storage is handled above.
    if decoded.relations.is_empty() {
        return Ok((
            BTreeMap::new(),
            revision,
            INITIAL_PAIRING_ATTEMPT_ID,
            aggregate_generation,
        ));
    }
    let now = Instant::now();
    let mut pairings = BTreeMap::new();
    let mut max_generation = 0_u64;
    let mut max_attempt_id = 0_u64;
    let mut stale_identity_generation = false;
    for relation in decoded.relations {
        if relation.pairing_generation == 0
            || relation.pairing_generation > aggregate_generation
            || relation.peer_identity_generation == 0
            || relation.updated_at_epoch_seconds == 0
            || relation.last_attempt_id == 0
        {
            return Err(AuthorityStoreError::Corrupt);
        }
        stale_identity_generation |=
            relation.local_identity_generation != expected_local_identity_generation;
        let peer_id =
            EndpointId::from_bytes(&relation.peer_id).map_err(|_| AuthorityStoreError::Corrupt)?;
        if pairings
            .insert(
                peer_id,
                PairingRecord {
                    pairing_generation: relation.pairing_generation,
                    local_identity_generation: relation.local_identity_generation,
                    peer_identity_generation: relation.peer_identity_generation,
                    paired: !relation.revoked,
                    revoked: relation.revoked,
                    updated_at_epoch_seconds: relation.updated_at_epoch_seconds,
                    last_attempt_id: relation.last_attempt_id,
                    failed_attempts: 0,
                    challenge_window_started: now,
                    challenge_count: 0,
                },
            )
            .is_some()
        {
            return Err(AuthorityStoreError::Corrupt);
        }
        max_generation = max_generation.max(relation.pairing_generation);
        max_attempt_id = max_attempt_id.max(relation.last_attempt_id);
    }
    if max_generation != aggregate_generation {
        return Err(AuthorityStoreError::Corrupt);
    }
    if stale_identity_generation {
        // A changed Relay identity invalidates old peer relations before endpoint bind.
        let empty_generation = aggregate_generation
            .checked_add(1)
            .ok_or(AuthorityStoreError::Unknown)?;
        let (payload, generation) = encode_empty_pairing_authority(empty_generation)?;
        let empty = BTreeMap::new();
        let next_revision = store.commit(
            PAIRING_AUTHORITY_STORAGE_KEY,
            PAIRING_AUTHORITY_RECORD_KIND,
            PAIRING_AUTHORITY_FILENAME,
            generation,
            "active",
            &payload,
            revision,
        )?;
        return Ok((empty, next_revision, INITIAL_PAIRING_ATTEMPT_ID, generation));
    }
    let next_attempt_id = max_attempt_id
        .checked_add(1)
        .ok_or(AuthorityStoreError::Unknown)?;
    Ok((pairings, revision, next_attempt_id, aggregate_generation))
}

/// Install a new process runtime fence before the Router begins accepting connections.
fn install_runtime_fence(store: &FileAuthorityStore) -> Result<u64, IrohEndpointError> {
    let current = store
        .load(
            RUNTIME_FENCE_STORAGE_KEY,
            RUNTIME_FENCE_RECORD_KIND,
            RUNTIME_FENCE_FILENAME,
        )
        .map_err(|_| IrohEndpointError::AuthorityStorage)?;
    let (revision, previous_epoch) = match current {
        Some(record) => {
            let (revision, generation, state, payload) = record.into_parts();
            if state != "active"
                || generation == 0
                || payload.len() != std::mem::size_of::<u64>()
                || u64::from_be_bytes(
                    payload
                        .as_slice()
                        .try_into()
                        .map_err(|_| IrohEndpointError::AuthorityStorage)?,
                ) != generation
            {
                return Err(IrohEndpointError::AuthorityStorage);
            }
            (revision, generation)
        }
        None => (0, 0),
    };
    let next_epoch = previous_epoch
        .checked_add(1)
        .ok_or(IrohEndpointError::AuthorityStorage)?;
    store
        .commit(
            RUNTIME_FENCE_STORAGE_KEY,
            RUNTIME_FENCE_RECORD_KIND,
            RUNTIME_FENCE_FILENAME,
            next_epoch,
            "active",
            &next_epoch.to_be_bytes(),
            revision,
        )
        .map_err(|_| IrohEndpointError::AuthorityStorage)?;
    Ok(next_epoch)
}

/// Active connection retained so rotation/revocation can close old authority.
struct ActiveConnection {
    /// Connection generation that identifies this physical pair.
    generation: u64,
    /// Strong handle used only to close the connection on revocation.
    connection: Connection,
}

/// Shared Relay admission state behind the Router handler.
struct IrohRelayState {
    /// Global connection semaphore.
    connection_limit: Arc<Semaphore>,
    /// Maximum pairing records retained for unknown and known peers.
    max_pairing_records: usize,
    /// Pairing metadata keyed by authenticated Core EndpointId.
    pairings: Mutex<BTreeMap<EndpointId, PairingRecord>>,
    /// One active physical connection per Core EndpointId.
    active: Mutex<BTreeMap<EndpointId, ActiveConnection>>,
    /// Broadcasts the bounded shutdown signal to every admitted handler.
    shutdown: watch::Sender<bool>,
    /// Optional local recovery store for pairing and runtime-fence records.
    authority_store: Option<Arc<FileAuthorityStore>>,
    /// Relay identity generation that owns persisted pairing relations.
    local_identity_generation: u64,
    /// Next transient pairing-attempt identifier.
    next_pairing_attempt_id: AtomicU64,
    /// Host revision for the pairing-authority record.
    pairing_revision: Mutex<u64>,
    /// Aggregate generation retained when the relation map is explicitly empty.
    pairing_authority_generation: Mutex<u64>,
    /// Nonzero process runtime epoch loaded and advanced at startup.
    runtime_epoch: u64,
    /// Monotonic physical connection generation source.
    next_generation: AtomicU64,
}

impl IrohRelayState {
    /// Creates empty bounded admission state.
    fn new(
        max_connections: usize,
        authority_store: Option<Arc<FileAuthorityStore>>,
        runtime_epoch: u64,
        local_identity_generation: u64,
    ) -> Result<Self, IrohEndpointError> {
        if local_identity_generation == 0 {
            return Err(IrohEndpointError::AuthorityStorage);
        }
        let (pairings, pairing_revision, next_pairing_attempt_id, pairing_authority_generation) =
            if let Some(store) = authority_store.as_ref() {
                restore_pairing_authority(store, local_identity_generation)
                    .map_err(|_| IrohEndpointError::AuthorityStorage)?
            } else {
                (BTreeMap::new(), 0, INITIAL_PAIRING_ATTEMPT_ID, 0)
            };
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            connection_limit: Arc::new(Semaphore::new(max_connections)),
            max_pairing_records: max_connections.min(MAX_PAIRING_RECORDS),
            pairings: Mutex::new(pairings),
            active: Mutex::new(BTreeMap::new()),
            shutdown,
            authority_store,
            local_identity_generation,
            next_pairing_attempt_id: AtomicU64::new(next_pairing_attempt_id),
            pairing_revision: Mutex::new(pairing_revision),
            pairing_authority_generation: Mutex::new(pairing_authority_generation),
            runtime_epoch,
            next_generation: AtomicU64::new(1),
        })
    }

    /// Reserves the one physical connection slot for a peer.
    fn try_admit(
        self: &Arc<Self>,
        peer: EndpointId,
        connection: Connection,
    ) -> Option<ConnectionLease> {
        if *self.shutdown.borrow() {
            return None;
        }
        let permit = self.connection_limit.clone().try_acquire_owned().ok()?;
        let local_generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let generation = self
            .runtime_epoch
            .checked_shl(32)
            .and_then(|epoch| epoch.checked_add(local_generation))?;
        let mut active = lock(&self.active);
        if *self.shutdown.borrow() || active.contains_key(&peer) {
            return None;
        }
        active.insert(
            peer,
            ActiveConnection {
                generation,
                connection,
            },
        );
        Some(ConnectionLease {
            state: Arc::clone(self),
            peer,
            generation,
            _permit: permit,
        })
    }

    /// Reports whether the peer has an active pairing relationship.
    fn is_paired(&self, peer: EndpointId) -> bool {
        lock(&self.pairings)
            .get(&peer)
            .is_some_and(|record| record.paired)
    }

    /// Allocate bounded metadata for a newly observed peer without persisting transient state.
    fn new_pairing_record(&self, now: Instant) -> Option<PairingRecord> {
        let last_attempt_id = self
            .next_pairing_attempt_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .ok()?;
        let updated_at_epoch_seconds = authority_timestamp().ok()?;
        Some(PairingRecord {
            pairing_generation: INITIAL_PAIRING_GENERATION,
            local_identity_generation: self.local_identity_generation,
            peer_identity_generation: INITIAL_PEER_IDENTITY_GENERATION,
            paired: false,
            revoked: false,
            updated_at_epoch_seconds,
            last_attempt_id,
            failed_attempts: 0,
            challenge_window_started: now,
            challenge_count: 0,
        })
    }

    /// Reserves one explicit pairing challenge under peer and registry limits.
    fn reserve_pairing_challenge(&self, peer: EndpointId) -> bool {
        let now = Instant::now();
        let mut pairings = lock(&self.pairings);
        let peer_is_new = !pairings.contains_key(&peer);

        if peer_is_new && pairings.len() >= self.max_pairing_records {
            return false;
        }
        if peer_is_new {
            let Some(record) = self.new_pairing_record(now) else {
                return false;
            };
            pairings.insert(peer, record);
        }
        let record = pairings.get_mut(&peer).expect("pairing record inserted");
        if record.paired {
            return false;
        }
        if now.duration_since(record.challenge_window_started) >= PAIRING_CHALLENGE_WINDOW {
            record.challenge_window_started = now;
            record.challenge_count = 0;
        }
        if record.challenge_count >= MAX_PAIRING_CHALLENGES_PER_WINDOW {
            return false;
        }
        record.challenge_count += 1;
        record.failed_attempts = 0;
        true
    }

    /// Records one failed pairing submission and returns whether another may be attempted.
    fn record_pairing_failure(&self, peer: EndpointId) -> bool {
        let mut pairings = lock(&self.pairings);
        if !pairings.contains_key(&peer) {
            if pairings.len() >= self.max_pairing_records {
                return false;
            }
            let Some(record) = self.new_pairing_record(Instant::now()) else {
                return false;
            };
            pairings.insert(peer, record);
        }
        let record = pairings.get_mut(&peer).expect("pairing record inserted");
        if record.failed_attempts >= MAX_PAIRING_ATTEMPTS {
            return false;
        }
        record.failed_attempts += 1;
        record.failed_attempts < MAX_PAIRING_ATTEMPTS
    }

    /// Marks a peer paired when the bounded pairing registry has capacity and persists it first.
    fn mark_paired(&self, peer: EndpointId) -> Result<bool, AuthorityStoreError> {
        let mut pairings = lock(&self.pairings);
        if !pairings.contains_key(&peer) && pairings.len() >= self.max_pairing_records {
            return Ok(false);
        }
        let mut candidate = pairings.clone();
        let now = Instant::now();
        let authority_generation = *lock(&self.pairing_authority_generation);
        let record = candidate.entry(peer).or_insert(PairingRecord {
            pairing_generation: 0,
            local_identity_generation: self.local_identity_generation,
            peer_identity_generation: INITIAL_PEER_IDENTITY_GENERATION,
            paired: false,
            revoked: false,
            updated_at_epoch_seconds: 0,
            last_attempt_id: 0,
            failed_attempts: 0,
            challenge_window_started: now,
            challenge_count: 0,
        });
        if record.paired {
            return Ok(true);
        }
        record.pairing_generation = if record.pairing_generation == 0 {
            authority_generation
                .checked_add(1)
                .ok_or(AuthorityStoreError::Unknown)?
                .max(INITIAL_PAIRING_GENERATION)
        } else {
            record
                .pairing_generation
                .checked_add(1)
                .ok_or(AuthorityStoreError::Unknown)?
        };
        record.local_identity_generation = self.local_identity_generation;
        record.peer_identity_generation = record
            .peer_identity_generation
            .max(INITIAL_PEER_IDENTITY_GENERATION);
        record.updated_at_epoch_seconds = authority_timestamp()?;
        record.last_attempt_id = self
            .next_pairing_attempt_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| AuthorityStoreError::Unknown)?;
        record.paired = true;
        record.revoked = false;
        record.failed_attempts = 0;
        let next_revision = self.commit_pairings(&candidate)?;
        *pairings = candidate;
        *lock(&self.pairing_revision) = next_revision;
        Ok(true)
    }

    /// Close the active physical connection for a peer without changing durable state.
    fn close_active_peer(&self, peer: EndpointId) {
        if let Some(active) = lock(&self.active).get(&peer) {
            active
                .connection
                .close(0u32.into(), b"peer authority unavailable");
        }
    }

    /// Revokes a peer, persists the tombstone, and closes its current connection.
    fn revoke_peer(&self, peer: EndpointId) -> Result<bool, AuthorityStoreError> {
        let mut pairings = lock(&self.pairings);
        let Some(current) = pairings.get(&peer).copied() else {
            drop(pairings);
            self.close_active_peer(peer);
            return Ok(false);
        };
        let was_paired = current.paired;
        let mut candidate = pairings.clone();
        let update_result = (|| {
            if !current.revoked {
                let record = candidate.get_mut(&peer).expect("pairing relation exists");
                record.paired = false;
                record.revoked = true;
                record.pairing_generation = record
                    .pairing_generation
                    .checked_add(1)
                    .ok_or(AuthorityStoreError::Unknown)?;
                record.local_identity_generation = self.local_identity_generation;
                record.peer_identity_generation = record
                    .peer_identity_generation
                    .max(INITIAL_PEER_IDENTITY_GENERATION);
                record.updated_at_epoch_seconds = authority_timestamp()?;
                record.last_attempt_id = self
                    .next_pairing_attempt_id
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        current.checked_add(1)
                    })
                    .map_err(|_| AuthorityStoreError::Unknown)?;
                record.failed_attempts = 0;
                let next_revision = self.commit_pairings(&candidate)?;
                *pairings = candidate;
                *lock(&self.pairing_revision) = next_revision;
            }
            Ok::<(), AuthorityStoreError>(())
        })();
        if let Err(error) = update_result {
            // A failed/unknown revoke must lose local admission until a later reconciliation.
            if let Some(record) = pairings.get_mut(&peer) {
                record.paired = false;
            }
            drop(pairings);
            self.close_active_peer(peer);
            return Err(error);
        }
        drop(pairings);
        self.close_active_peer(peer);
        Ok(was_paired)
    }

    /// Persist a complete pairing relation replacement through revision CAS.
    fn commit_pairings(
        &self,
        candidate: &BTreeMap<EndpointId, PairingRecord>,
    ) -> Result<u64, AuthorityStoreError> {
        let (payload, encoded_generation) = encode_pairing_authority(candidate)?;
        let current_generation = *lock(&self.pairing_authority_generation);
        let generation = if candidate.is_empty() {
            current_generation.max(INITIAL_PAIRING_GENERATION)
        } else {
            if encoded_generation < current_generation {
                return Err(AuthorityStoreError::Corrupt);
            }
            encoded_generation
        };
        let next_revision = if let Some(store) = self.authority_store.as_ref() {
            store.commit(
                PAIRING_AUTHORITY_STORAGE_KEY,
                PAIRING_AUTHORITY_RECORD_KIND,
                PAIRING_AUTHORITY_FILENAME,
                generation,
                "active",
                &payload,
                *lock(&self.pairing_revision),
            )?
        } else {
            *lock(&self.pairing_revision)
        };
        *lock(&self.pairing_authority_generation) = generation;
        Ok(next_revision)
    }

    /// Signals every admitted handler to send GoAway before force-close.
    // TEST:relay/src/iroh_endpoint.rs[tests::paired_connection_survives_control_silence]
    fn begin_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Waits a bounded interval for signaled handlers to release their active leases.
    // TEST:relay/src/iroh_endpoint.rs[tests::paired_connection_survives_control_silence]
    async fn drain(&self, timeout_duration: Duration) {
        self.begin_shutdown();
        let _ = timeout(timeout_duration, async {
            while self.active_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }

    /// Returns the number of active physical Core connections.
    fn active_count(&self) -> usize {
        lock(&self.active).len()
    }

    /// Returns the number of EndpointIds with a current pairing relationship.
    fn paired_count(&self) -> usize {
        lock(&self.pairings)
            .values()
            .filter(|record| record.paired)
            .count()
    }
}

/// One RAII reservation for a physical Core-to-Relay connection.
struct ConnectionLease {
    /// Shared admission state.
    state: Arc<IrohRelayState>,
    /// Authenticated Core EndpointId.
    peer: EndpointId,
    /// Physical connection generation.
    generation: u64,
    /// Semaphore permit held until connection cleanup.
    _permit: OwnedSemaphorePermit,
}

impl Drop for ConnectionLease {
    /// Removes this connection and any non-paired challenge owned by its exact lease.
    fn drop(&mut self) {
        // Keep the same lock order as revoke_peer so lease cleanup cannot deadlock revocation.
        let mut pairings = lock(&self.state.pairings);
        let mut active = lock(&self.state.active);
        let is_current = active
            .get(&self.peer)
            .is_some_and(|entry| entry.generation == self.generation);
        if is_current {
            active.remove(&self.peer);
            if pairings
                .get(&self.peer)
                .is_some_and(|record| !record.paired && !record.revoked)
            {
                pairings.remove(&self.peer);
            }
        }
    }
}

/// One application Relay iroh endpoint and Router owner.
pub struct IrohRelayEndpoint {
    /// One process-owned iroh endpoint.
    endpoint: Endpoint,
    /// Router that owns the application ALPN handler.
    router: Router,
    /// Shared peer/pairing/session admission state.
    state: Arc<IrohRelayState>,
}

impl fmt::Debug for IrohRelayEndpoint {
    /// Reports only non-secret identity and bounded counts.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IrohRelayEndpoint")
            .field("endpoint_id_present", &true)
            .field("active_connections", &self.state.active_count())
            .field("paired_peers", &self.state.paired_count())
            .field("router_shutdown", &self.router.is_shutdown())
            .finish()
    }
}

impl IrohRelayEndpoint {
    /// Binds an endpoint with a disposable or development-recovered Relay identity.
    ///
    /// # Parameters
    /// * `config` - Bounded endpoint and session policy.
    /// * `verifier` - Narrow pairing verifier owned by the Relay process.
    ///
    /// # Returns
    /// A running endpoint/Router pair or a redacted bind error.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_requires_control_exchange]
    pub async fn bind(
        config: IrohRelayConfig,
        verifier: Arc<dyn PairingVerifier>,
    ) -> Result<Self, IrohEndpointError> {
        config.validate()?;
        let (secret_key, identity_generation) = resolve_relay_secret_key(&config, None)?;
        Self::bind_resolved(config, verifier, secret_key, identity_generation).await
    }

    /// Provisions a generated identity only for an explicit local development startup.
    ///
    /// # Parameters
    /// * `config` - Endpoint policy with a development recovery directory.
    /// * `verifier` - Narrow pairing verifier owned by the Relay process.
    ///
    /// # Returns
    /// A running endpoint/Router pair or a redacted configuration/storage error.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_missing_identity_requires_explicit_key]
    // TEST:relay/src/iroh_endpoint.rs[tests::development_identity_requires_recovery_directory]
    pub async fn provision_development_identity(
        config: IrohRelayConfig,
        verifier: Arc<dyn PairingVerifier>,
    ) -> Result<Self, IrohEndpointError> {
        if config.authority_store.is_none() {
            return Err(IrohEndpointError::InvalidConfiguration {
                field: "development_recovery_dir",
            });
        }
        // Generate only inside the Relay boundary; the raw key is immediately consumed by bind.
        Self::bind_with_secret_key(config, verifier, SecretKey::generate()).await
    }

    /// Binds an endpoint using a protected-storage-loaded or explicitly supplied identity.
    ///
    /// When the development recovery profile is configured, an existing persisted identity is
    /// reused and an explicitly supplied key must match it. A missing record is initialized from
    /// the supplied key before the endpoint accepts any Core connection.
    ///
    /// # Parameters
    /// * `config` - Bounded endpoint and session policy.
    /// * `verifier` - Narrow pairing verifier owned by the Relay process.
    /// * `secret_key` - Relay-owned iroh identity loaded inside the Relay boundary.
    ///
    /// # Returns
    /// A running endpoint/Router pair or a redacted bind error.
    pub async fn bind_with_secret_key(
        config: IrohRelayConfig,
        verifier: Arc<dyn PairingVerifier>,
        secret_key: SecretKey,
    ) -> Result<Self, IrohEndpointError> {
        config.validate()?;
        let (secret_key, identity_generation) =
            resolve_relay_secret_key(&config, Some(secret_key))?;
        Self::bind_resolved(config, verifier, secret_key, identity_generation).await
    }

    /// Bind an endpoint after the Relay identity has been resolved and, when selected, persisted.
    async fn bind_resolved(
        config: IrohRelayConfig,
        verifier: Arc<dyn PairingVerifier>,
        secret_key: SecretKey,
        identity_generation: u64,
    ) -> Result<Self, IrohEndpointError> {
        let authority_store = config.authority_store.clone();
        // Install and restore all durable authority before binding or accepting any endpoint.
        let runtime_epoch = authority_store
            .as_ref()
            .map(|store| install_runtime_fence(store))
            .transpose()?
            .unwrap_or(1);
        let state = Arc::new(IrohRelayState::new(
            config.max_connections,
            authority_store,
            runtime_epoch,
            identity_generation,
        )?);
        // Minimal starts with relay transport disabled; apply the explicit provider mode here.
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .alpns(vec![IROH_RELAY_ALPN.to_vec()])
            .relay_mode(config.relay_mode.clone());
        if let Some(bind_addr) = config.bind_addr {
            builder = builder
                .clear_ip_transports()
                .bind_addr(bind_addr)
                .map_err(|_| IrohEndpointError::InvalidConfiguration { field: "bind_addr" })?;
        }
        let endpoint = builder.bind().await.map_err(|_| IrohEndpointError::Bind)?;
        let handler = IrohRelayHandler {
            config,
            state: Arc::clone(&state),
            verifier,
        };
        let router = Router::builder(endpoint.clone())
            .accept(IROH_RELAY_ALPN, handler)
            .spawn();
        Ok(Self {
            endpoint,
            router,
            state,
        })
    }

    /// Returns this Relay's public transport EndpointId.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Returns the current transport address for Core-only provisioning.
    ///
    /// This is available only to tests and the parent Core/Relay contract harness; it is never
    /// exported through the App boundary.
    #[cfg(any(test, feature = "contract-test-support"))]
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Returns the number of active physical Core connections.
    pub fn active_connection_count(&self) -> usize {
        self.state.active_count()
    }

    /// Returns the number of paired EndpointIds.
    pub fn paired_peer_count(&self) -> usize {
        self.state.paired_count()
    }

    /// Revokes one EndpointId and closes its current connection authority.
    ///
    /// # Parameters
    /// * `peer` - EndpointId whose relationship must be revoked.
    ///
    /// # Returns
    /// `Ok(true)` when an active pairing was durably revoked, `Ok(false)` when none existed, or a
    /// sanitized storage failure without claiming that revocation committed.
    pub fn try_revoke_peer(&self, peer: EndpointId) -> Result<bool, IrohEndpointError> {
        self.state
            .revoke_peer(peer)
            .map_err(|_| IrohEndpointError::AuthorityStorage)
    }

    /// Revokes one EndpointId and closes its current connection authority.
    ///
    /// # Parameters
    /// * `peer` - EndpointId whose relationship must be revoked.
    ///
    /// # Returns
    /// `true` when the relation was durably revoked; storage failures fail closed as `false`.
    pub fn revoke_peer(&self, peer: EndpointId) -> bool {
        self.try_revoke_peer(peer).unwrap_or(false)
    }

    /// Drains all handlers and closes the owned endpoint and its sockets.
    ///
    /// Consuming the owner ensures the final Endpoint clone is dropped after Router handlers stop.
    ///
    /// # Returns
    /// `Ok(())` after the handler drain and endpoint close, or a redacted shutdown error.
    // TEST:relay/src/iroh_endpoint.rs[tests::paired_connection_survives_control_silence]
    pub async fn shutdown(self) -> Result<(), IrohEndpointError> {
        let IrohRelayEndpoint {
            endpoint,
            router,
            state: _,
        } = self;
        let result = router
            .shutdown()
            .await
            .map_err(|_| IrohEndpointError::Shutdown);
        drop(router);
        endpoint.close().await;
        result
    }
}

/// Router protocol handler for the fixed application ALPN.
struct IrohRelayHandler {
    /// Bounded endpoint and bridge policy.
    config: IrohRelayConfig,
    /// Shared EndpointId/pairing admission state.
    state: Arc<IrohRelayState>,
    /// Narrow pairing verifier.
    verifier: Arc<dyn PairingVerifier>,
}

impl fmt::Debug for IrohRelayHandler {
    /// Reports only handler configuration presence and bounded state counts.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IrohRelayHandler")
            .field("config_present", &true)
            .field("paired_peers", &self.state.paired_count())
            .field("verifier_present", &true)
            .finish()
    }
}

impl ProtocolHandler for IrohRelayHandler {
    /// Accepts one authenticated Core connection under the one-pair limit.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = connection.remote_id();
        let Some(_lease) = self.state.try_admit(peer, connection.clone()) else {
            connection.close(0u32.into(), b"connection limit");
            return Ok(());
        };
        let connection_generation = lock(&self.state.active)
            .get(&peer)
            .map(|entry| entry.generation)
            .unwrap_or(1);
        if run_connection(
            connection.clone(),
            peer,
            connection_generation,
            &self.config,
            &self.state,
            &self.verifier,
        )
        .await
        .is_err()
        {
            connection.close(0u32.into(), b"protocol failure");
        }
        Ok(())
    }

    /// Signals active handlers to send bounded GoAway frames before Router force-close.
    // TEST:relay/src/iroh_endpoint.rs[tests::paired_connection_survives_control_silence]
    async fn shutdown(&self) {
        self.state.drain(self.config.control_timeout).await;
    }
}

/// Redacted internal connection-handler failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum IrohConnectionError {
    /// A bounded control or session read/write failed.
    #[error("iroh Relay connection I/O failed")]
    Io,
    /// A control or session frame failed validation.
    #[error("iroh Relay connection protocol failed")]
    Protocol,
    /// A control operation exceeded its deadline.
    #[error("iroh Relay connection deadline expired")]
    Timeout,
    /// A persistent authority commit failed closed.
    #[error("iroh Relay authority persistence failed")]
    Persistence,
}

/// Runs the pairing exchange and always asks the verifier to clean up its transient challenge.
async fn run_connection(
    connection: Connection,
    peer: EndpointId,
    connection_generation: u64,
    config: &IrohRelayConfig,
    state: &Arc<IrohRelayState>,
    verifier: &Arc<dyn PairingVerifier>,
) -> Result<(), IrohConnectionError> {
    let result = run_connection_inner(
        connection,
        peer,
        connection_generation,
        config,
        state,
        verifier,
    )
    .await;
    // The concrete Herdr verifier makes cancel idempotent after successful verification and uses
    // it to close any challenge left by timeout, disconnect, rejection or protocol failure.
    let _ = timeout(config.control_timeout, verifier.cancel(peer)).await;
    result
}

/// Runs the one control stream and then the bounded session stream set.
// TEST:relay/src/iroh_endpoint.rs[tests::paired_connection_survives_control_silence]
async fn run_connection_inner(
    connection: Connection,
    peer: EndpointId,
    connection_generation: u64,
    config: &IrohRelayConfig,
    state: &Arc<IrohRelayState>,
    verifier: &Arc<dyn PairingVerifier>,
) -> Result<(), IrohConnectionError> {
    // Subscribe after admission; checking the current value closes the startup/shutdown race.
    let mut shutdown_rx = state.shutdown.subscribe();
    if *shutdown_rx.borrow() {
        return Ok(());
    }
    let accepted = tokio::select! {
        _ = shutdown_rx.changed() => return Ok(()),
        accepted = timeout(config.control_timeout, connection.accept_bi()) => {
            accepted
                .map_err(|_| IrohConnectionError::Timeout)?
                .map_err(|_| IrohConnectionError::Io)?
        }
    };
    let (mut control_send, mut control_recv) = accepted;
    let mut paired = state.is_paired(peer);
    let mut pairing_started = false;
    // Keep the human pairing window separate from short per-frame control deadlines.
    let mut pairing_submit_deadline: Option<Instant> = None;

    loop {
        let read_timeout = pairing_submit_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(config.control_timeout);
        let frame = tokio::select! {
            _ = shutdown_rx.changed() => {
                send_goaway(&mut control_send, config.control_timeout).await;
                return Ok(());
            }
            frame = timeout(
                read_timeout,
                read_hdp_frame(&mut control_recv, HDP1_MAX_FRAME_BYTES),
            ) => {
                frame
                    .map_err(|_| IrohConnectionError::Timeout)?
                    .map_err(|_| IrohConnectionError::Protocol)?
            }
        };
        match frame.kind() {
            HdpKind::PairingStart => {
                if pairing_started || !frame.payload.is_empty() {
                    send_hdp_status(&mut control_send, HdpKind::PairingRejected, 5).await?;
                    continue;
                }
                if paired {
                    pairing_started = true;
                    send_hdp_status(&mut control_send, HdpKind::PairingAccepted, 0).await?;
                    send_hdp_status(&mut control_send, HdpKind::ConnectionReady, 0).await?;
                } else if !state.reserve_pairing_challenge(peer) {
                    send_hdp_status(&mut control_send, HdpKind::PairingRejected, 3).await?;
                } else if timeout(config.control_timeout, verifier.begin(peer))
                    .await
                    .unwrap_or(false)
                {
                    let Some(deadline) =
                        Instant::now().checked_add(Duration::from_secs(PAIRING_CHALLENGE_TTL_SECS))
                    else {
                        send_hdp_status(&mut control_send, HdpKind::PairingRejected, 3).await?;
                        continue;
                    };
                    pairing_submit_deadline = Some(deadline);
                    pairing_started = true;
                    send_hdp_status(&mut control_send, HdpKind::PairingRejected, 1).await?;
                } else {
                    send_hdp_status(&mut control_send, HdpKind::PairingRejected, 3).await?;
                }
            }
            HdpKind::PairingSubmit => {
                if !pairing_started {
                    send_hdp_status(&mut control_send, HdpKind::PairingRejected, 5).await?;
                    continue;
                }
                let valid_code = frame.payload.len() == 6
                    && frame.payload.iter().all(|digit| digit.is_ascii_digit());
                if !valid_code {
                    let may_continue = state.record_pairing_failure(peer);
                    send_hdp_status(
                        &mut control_send,
                        HdpKind::PairingRejected,
                        if may_continue { 2 } else { 4 },
                    )
                    .await?;
                    if !may_continue {
                        connection.close(0u32.into(), b"pairing budget exhausted");
                        return Ok(());
                    }
                    continue;
                }
                let mut code = [0_u8; 6];
                code.copy_from_slice(&frame.payload);
                let accepted = timeout(config.control_timeout, verifier.verify(peer, code))
                    .await
                    .unwrap_or(false);
                if accepted {
                    match state.mark_paired(peer) {
                        Ok(true) => {}
                        Ok(false) => {
                            send_hdp_status(&mut control_send, HdpKind::PairingRejected, 4).await?;
                            connection.close(0u32.into(), b"pairing capacity");
                            return Ok(());
                        }
                        Err(_) => {
                            send_hdp_status(&mut control_send, HdpKind::PairingRejected, 4).await?;
                            connection.close(0u32.into(), b"pairing persistence failed");
                            return Err(IrohConnectionError::Persistence);
                        }
                    }
                    paired = true;
                    send_hdp_status(&mut control_send, HdpKind::PairingAccepted, 0).await?;
                    send_hdp_status(&mut control_send, HdpKind::ConnectionReady, 0).await?;
                } else if state.record_pairing_failure(peer) {
                    send_hdp_status(&mut control_send, HdpKind::PairingRejected, 3).await?;
                } else {
                    send_hdp_status(&mut control_send, HdpKind::PairingRejected, 4).await?;
                    connection.close(0u32.into(), b"pairing budget exhausted");
                    return Ok(());
                }
            }
            HdpKind::GoAway => return Ok(()),
            HdpKind::PairingAccepted | HdpKind::PairingRejected | HdpKind::ConnectionReady => {
                send_hdp_status(&mut control_send, HdpKind::PairingRejected, 5).await?;
                continue;
            }
        }
        if paired {
            break;
        }
    }

    run_paired_connection(
        connection,
        connection_generation,
        config,
        control_send,
        control_recv,
        shutdown_rx,
    )
    .await
}

/// Runs control-plane HDQM operations and accepts isolated session streams.
async fn run_paired_connection(
    connection: Connection,
    connection_generation: u64,
    config: &IrohRelayConfig,
    mut control_send: SendStream,
    mut control_recv: RecvStream,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), IrohConnectionError> {
    let registry = Arc::new(Mutex::new(
        SessionRegistry::new(
            config.relay_generation,
            connection_generation,
            config.max_sessions_per_connection,
        )
        .map_err(|_| IrohConnectionError::Protocol)?,
    ));
    let session_slots = Arc::new(Semaphore::new(config.max_sessions_per_connection));
    let session_controls = Arc::new(Mutex::new(BTreeMap::<u16, oneshot::Sender<()>>::new()));
    let mut session_tasks = JoinSet::new();
    let (control_tx, mut control_rx) = mpsc::channel(1);
    let control_reader = tokio::spawn(async move {
        loop {
            let frame = read_hdqm_frame(&mut control_recv, HDP1_MAX_FRAME_BYTES).await;
            let terminal = frame.is_err();
            if control_tx.send(frame).await.is_err() {
                break;
            }
            if terminal {
                break;
            }
        }
    });

    // A dedicated reader owns the control stream so session arrivals cannot cancel a partial
    // header/payload read and desynchronize the next HDQM frame.
    let result = async {
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    // The handler hook has already bounded this drain; this write has its own deadline.
                    send_goaway(&mut control_send, config.control_timeout).await;
                    break;
                }
                control = control_rx.recv() => {
                    let Some(frame) = control else {
                        break;
                    };
                    let frame = frame.map_err(|_| IrohConnectionError::Protocol)?;
                    let should_stop = handle_hdqm_frame(
                        &mut control_send,
                        frame,
                        &registry,
                        &session_controls,
                    ).await?;
                    if should_stop {
                        break;
                    }
                }
                incoming = connection.accept_bi() => {
                    let (send, recv) = incoming.map_err(|_| IrohConnectionError::Io)?;
                    let Some(permit) = session_slots.clone().try_acquire_owned().ok() else {
                        let mut send = send;
                        let response = HdqsResponse::rejected(
                            HdqsReason::CapacityExhausted,
                            registry.lock().map_err(|_| IrohConnectionError::Protocol)?.connection_epoch(),
                        );
                        write_hdqs_response(&mut send, response).await?;
                        send.finish().map_err(|_| IrohConnectionError::Io)?;
                        continue;
                    };
                    session_tasks.spawn(run_session_stream(
                        send,
                        recv,
                        config.clone(),
                        registry.clone(),
                        session_controls.clone(),
                        permit,
                    ));
                }
                _ = connection.closed() => {
                    break;
                }
            }
        }
        Ok::<(), IrohConnectionError>(())
    }
    .await;

    control_reader.abort();
    let _ = control_reader.await;
    cancel_sessions(&session_controls);
    session_tasks.abort_all();
    while session_tasks.join_next().await.is_some() {}
    if let Ok(mut registry) = registry.lock() {
        registry.invalidate_connection();
    }
    result
}

/// Handles one post-pairing HDQM control request.
async fn handle_hdqm_frame(
    send: &mut SendStream,
    frame: HdqmFrame,
    registry: &Arc<Mutex<SessionRegistry>>,
    session_controls: &Arc<Mutex<BTreeMap<u16, oneshot::Sender<()>>>>,
) -> Result<bool, IrohConnectionError> {
    match frame.kind {
        HdqmKind::SessionPrepare => {
            let request = SessionPrepareRequest::decode(&frame.payload)
                .map_err(|_| IrohConnectionError::Protocol)?;
            let fingerprint = if request.expected_fingerprint == [0; 32] {
                let mut generated = [0_u8; 32];
                rand::rng().fill(&mut generated);
                generated
            } else {
                request.expected_fingerprint
            };
            let mut token = [0_u8; 32];
            rand::rng().fill(&mut token);
            let prepared = {
                let mut registry = registry.lock().map_err(|_| IrohConnectionError::Protocol)?;
                registry.reap_expired_prepared(std::time::Instant::now());
                registry
                    .prepare(
                        request.session.as_str(),
                        fingerprint,
                        request.configuration_generation,
                        token,
                    )
                    .map_err(|_| IrohConnectionError::Protocol)?
            };
            let response = SessionPrepareAck {
                session: prepared.session,
                fingerprint: prepared.fingerprint,
                configuration_generation: prepared.configuration_generation,
                relay_generation: prepared.relay_generation,
                connection_epoch: prepared.connection_epoch,
                token: prepared.token,
                token_ttl_secs: prepared.token_ttl_secs,
            };
            send_hdqm_frame(
                send,
                HdqmFrame {
                    kind: HdqmKind::SessionPrepareAck,
                    request_id: frame.request_id,
                    payload: response
                        .encode()
                        .map_err(|_| IrohConnectionError::Protocol)?,
                },
            )
            .await?;
        }
        HdqmKind::SessionOpen => {
            let request = SessionOpenRequest::decode(&frame.payload)
                .map_err(|_| IrohConnectionError::Protocol)?;
            let (response, active) = registry
                .lock()
                .map_err(|_| IrohConnectionError::Protocol)?
                .open_request(&request);
            let Some(active) = active else {
                send_hdqm_frame(
                    send,
                    HdqmFrame {
                        kind: HdqmKind::ErrorResponse,
                        request_id: frame.request_id,
                        payload: response
                            .encode()
                            .map_err(|_| IrohConnectionError::Protocol)?
                            .to_vec(),
                    },
                )
                .await?;
                return Ok(false);
            };
            let response = SessionOpenAck {
                session_handle: active.handle,
                session: active.prepared.session,
                fingerprint: active.prepared.fingerprint,
                configuration_generation: active.prepared.configuration_generation,
                relay_generation: active.prepared.relay_generation,
                connection_epoch: active.prepared.connection_epoch,
                token: active.prepared.token,
            };
            send_hdqm_frame(
                send,
                HdqmFrame {
                    kind: HdqmKind::SessionOpened,
                    request_id: frame.request_id,
                    payload: response
                        .encode()
                        .map_err(|_| IrohConnectionError::Protocol)?,
                },
            )
            .await?;
        }
        HdqmKind::SessionClose => {
            if frame.payload.len() != 2 {
                return Err(IrohConnectionError::Protocol);
            }
            let handle = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
            registry
                .lock()
                .map_err(|_| IrohConnectionError::Protocol)?
                .close(handle);
            if let Some(cancel) = lock(session_controls).remove(&handle) {
                let _ = cancel.send(());
            }
            send_hdqm_frame(
                send,
                HdqmFrame {
                    kind: HdqmKind::SessionClosed,
                    request_id: frame.request_id,
                    payload: Vec::new(),
                },
            )
            .await?;
        }
        HdqmKind::Heartbeat => {
            send_hdqm_frame(
                send,
                HdqmFrame {
                    kind: HdqmKind::Heartbeat,
                    request_id: frame.request_id,
                    payload: Vec::new(),
                },
            )
            .await?;
        }
        HdqmKind::GoAway => return Ok(true),
        _ => {
            send_hdqm_frame(
                send,
                HdqmFrame {
                    kind: HdqmKind::ErrorResponse,
                    request_id: frame.request_id,
                    payload: Vec::new(),
                },
            )
            .await?;
        }
    }
    Ok(false)
}

/// Runs one admitted HDQS stream and its validated Unix bridge.
async fn run_session_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    config: IrohRelayConfig,
    registry: Arc<Mutex<SessionRegistry>>,
    session_controls: Arc<Mutex<BTreeMap<u16, oneshot::Sender<()>>>>,
    _permit: OwnedSemaphorePermit,
) -> Result<(), IrohConnectionError> {
    let binding = timeout(config.control_timeout, read_hdqs_binding(&mut recv))
        .await
        .map_err(|_| IrohConnectionError::Timeout)?
        .map_err(|_| IrohConnectionError::Protocol)?;
    let accepted = registry
        .lock()
        .map_err(|_| IrohConnectionError::Protocol)?
        .accept_active(&binding);
    if accepted.kind != crate::quic_wire::HdqsKind::Accepted {
        write_hdqs_response(&mut send, accepted).await?;
        send.finish().map_err(|_| IrohConnectionError::Io)?;
        return Ok(());
    }

    let Some(connector) = config.socket_connector else {
        close_binding(&registry, &binding);
        let response = HdqsResponse::rejected(
            HdqsReason::SocketUnavailable,
            registry
                .lock()
                .map_err(|_| IrohConnectionError::Protocol)?
                .connection_epoch(),
        );
        write_hdqs_response(&mut send, response).await?;
        send.finish().map_err(|_| IrohConnectionError::Io)?;
        return Ok(());
    };
    let identity = match connector.validate() {
        Ok(identity) => identity,
        Err(_) => {
            close_binding(&registry, &binding);
            let response = HdqsResponse::rejected(
                HdqsReason::SocketUnavailable,
                registry
                    .lock()
                    .map_err(|_| IrohConnectionError::Protocol)?
                    .connection_epoch(),
            );
            write_hdqs_response(&mut send, response).await?;
            send.finish().map_err(|_| IrohConnectionError::Io)?;
            return Ok(());
        }
    };
    let unix = match connector.connect_checked(identity).await {
        Ok(unix) => unix,
        Err(_) => {
            close_binding(&registry, &binding);
            let response = HdqsResponse::rejected(
                HdqsReason::SocketUnavailable,
                registry
                    .lock()
                    .map_err(|_| IrohConnectionError::Protocol)?
                    .connection_epoch(),
            );
            write_hdqs_response(&mut send, response).await?;
            send.finish().map_err(|_| IrohConnectionError::Io)?;
            return Ok(());
        }
    };

    let (cancel_tx, mut cancel_rx) = oneshot::channel();
    let handle = binding.session_handle;
    if lock(&session_controls).insert(handle, cancel_tx).is_some() {
        close_binding(&registry, &binding);
        return Err(IrohConnectionError::Protocol);
    }
    write_hdqs_response(&mut send, accepted).await?;
    let network = IrohBiStream { recv, send };
    let bridge = bridge::run(network, unix, BridgeLimits::v1());
    tokio::pin!(bridge);
    tokio::select! {
        _ = &mut bridge => {}
        _ = &mut cancel_rx => {}
    }
    close_binding(&registry, &binding);
    lock(&session_controls).remove(&handle);
    Ok(())
}

/// Reads one complete HDP1 frame under a caller-supplied fixed bound.
async fn read_hdp_frame<R>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> Result<HdpFrame, HdpFrameError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; HDP1_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| HdpFrameError::FrameTooShort)?;
    let payload_len = u32::from_be_bytes([header[7], header[8], header[9], header[10]]) as usize;
    let total = HDP1_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(HdpFrameError::FrameTooLarge)?;
    if total > max_frame_bytes || total > HDP1_MAX_FRAME_BYTES {
        return Err(HdpFrameError::FrameTooLarge);
    }
    let mut bytes = header.to_vec();
    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| HdpFrameError::LengthMismatch)?;
    bytes.extend_from_slice(&payload);
    HdpFrame::decode(&bytes)
}

/// Reads one complete HDQM frame under the same 64 KiB complete-frame bound.
async fn read_hdqm_frame<R>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> Result<HdqmFrame, HdpFrameError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; HDQM_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| HdpFrameError::FrameTooShort)?;
    if header[..4] != HDQM_MAGIC {
        return Err(HdpFrameError::InvalidMagic);
    }
    let payload_length_offset = HDQM_HEADER_BYTES - HDQM_PAYLOAD_LENGTH_BYTES;
    let payload_length_bytes: [u8; HDQM_PAYLOAD_LENGTH_BYTES] = header[payload_length_offset..]
        .try_into()
        .expect("fixed HDQM payload-length suffix");
    let payload_len = u32::from_be_bytes(payload_length_bytes) as usize;
    let total = HDQM_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(HdpFrameError::FrameTooLarge)?;
    if total > max_frame_bytes || total > HDP1_MAX_FRAME_BYTES {
        return Err(HdpFrameError::FrameTooLarge);
    }
    let mut bytes = header.to_vec();
    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| HdpFrameError::LengthMismatch)?;
    bytes.extend_from_slice(&payload);
    HdqmFrame::decode(&bytes).map_err(|_| HdpFrameError::LengthMismatch)
}

/// Sends the frozen HDP1 GoAway frame under the existing control deadline.
// TEST:relay/src/iroh_endpoint.rs[tests::paired_connection_survives_control_silence]
async fn send_goaway(send: &mut SendStream, timeout_duration: Duration) {
    let _ = timeout(timeout_duration, send_hdp_status(send, HdpKind::GoAway, 0)).await;
}

/// Sends one HDP1 status frame without finishing the long-lived control stream.
async fn send_hdp_status(
    send: &mut SendStream,
    kind: HdpKind,
    reason: u8,
) -> Result<(), IrohConnectionError> {
    let payload = if reason == 0 {
        Vec::new()
    } else {
        vec![reason]
    };
    send_hdp_frame(send, HdpFrame::new(kind, payload)).await
}

/// Writes one HDP1 frame to the long-lived control stream.
async fn send_hdp_frame(send: &mut SendStream, frame: HdpFrame) -> Result<(), IrohConnectionError> {
    let bytes = frame.encode().map_err(|_| IrohConnectionError::Protocol)?;
    send.write_all(&bytes)
        .await
        .map_err(|_| IrohConnectionError::Io)?;
    send.flush().await.map_err(|_| IrohConnectionError::Io)
}

/// Writes one HDQM frame to the long-lived control stream.
async fn send_hdqm_frame(
    send: &mut SendStream,
    frame: HdqmFrame,
) -> Result<(), IrohConnectionError> {
    let bytes = frame.encode().map_err(|_| IrohConnectionError::Protocol)?;
    if bytes.len() > HDP1_MAX_FRAME_BYTES {
        return Err(IrohConnectionError::Protocol);
    }
    send.write_all(&bytes)
        .await
        .map_err(|_| IrohConnectionError::Io)?;
    send.flush().await.map_err(|_| IrohConnectionError::Io)
}
async fn read_hdqs_binding(reader: &mut RecvStream) -> Result<HdqsBinding, IrohConnectionError> {
    let mut prefix = [0_u8; 33];
    reader
        .read_exact(&mut prefix)
        .await
        .map_err(|_| IrohConnectionError::Io)?;
    if prefix[..4] != HDQS_MAGIC {
        return Err(IrohConnectionError::Protocol);
    }
    let name_len = usize::from(prefix[32]);
    if name_len == 0 || name_len > QRM_MAX_SESSION_NAME_BYTES {
        return Err(IrohConnectionError::Protocol);
    }
    let mut bytes = prefix.to_vec();
    let mut tail = vec![0_u8; name_len + 64];
    reader
        .read_exact(&mut tail)
        .await
        .map_err(|_| IrohConnectionError::Io)?;
    bytes.extend_from_slice(&tail);
    HdqsBinding::decode(&bytes).map_err(|_| IrohConnectionError::Protocol)
}

/// Writes one fixed HDQS response without exposing authority bytes in diagnostics.
async fn write_hdqs_response(
    send: &mut SendStream,
    response: HdqsResponse,
) -> Result<(), IrohConnectionError> {
    let bytes = response
        .encode()
        .map_err(|_| IrohConnectionError::Protocol)?;
    send.write_all(&bytes)
        .await
        .map_err(|_| IrohConnectionError::Io)?;
    send.flush().await.map_err(|_| IrohConnectionError::Io)
}
fn close_binding(registry: &Arc<Mutex<SessionRegistry>>, binding: &HdqsBinding) {
    if let Ok(mut registry) = registry.lock() {
        registry.close_exact(binding);
    }
}

/// Cancels all session bridges attached to one closing physical connection.
fn cancel_sessions(controls: &Arc<Mutex<BTreeMap<u16, oneshot::Sender<()>>>>) {
    let mut controls = lock(controls);
    let pending = std::mem::take(&mut *controls);
    for (_, cancel) in pending {
        let _ = cancel.send(());
    }
}

/// Adapts one iroh bidirectional stream to the existing bounded bridge.
struct IrohBiStream {
    /// iroh receive half.
    recv: RecvStream,
    /// iroh send half.
    send: SendStream,
}

impl AsyncRead for IrohBiStream {
    /// Polls bytes from the iroh receive half.
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for IrohBiStream {
    /// Polls bytes into the iroh send half.
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.send)
            .poll_write(cx, bytes)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "iroh send stream write failed",
                )
            })
    }

    /// Flushes the iroh send half.
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "iroh send stream flush failed",
                )
            })
    }

    /// Finishes the iroh send half.
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "iroh send stream shutdown failed",
                )
            })
    }
}

/// Acquires a poison-tolerant short-lived lock for internal bounded state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_store::AuthorityDeleteOutcome;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixListener,
    };

    /// Test-only verifier that accepts one fake six-digit code without logging it.
    #[derive(Debug)]
    struct FakePairingVerifier;

    impl PairingVerifier for FakePairingVerifier {
        /// Creates a disposable challenge for the local fake exchange.
        fn begin(&self, _peer: EndpointId) -> Pin<Box<dyn Future<Output = bool> + Send>> {
            Box::pin(async { true })
        }

        /// Accepts only the fixture code used by this module's local test.
        fn verify(
            &self,
            _peer: EndpointId,
            mut code: [u8; 6],
        ) -> Pin<Box<dyn Future<Output = bool> + Send>> {
            let accepted = code == *b"123456";
            code.fill(0);
            Box::pin(async move { accepted })
        }

        /// Releases no external fixture because the fake creates no workspace.
        fn cancel(&self, _peer: EndpointId) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async {})
        }
    }

    /// Creates a unique local/generated directory for Relay recovery tests.
    fn recovery_test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = PathBuf::from(format!(
            "/private/tmp/herdr-dog-relay-recovery-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("recovery root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("recovery root mode");
        root
    }

    /// Verify deletion uses revision CAS, is idempotent for missing records, and permits recreation.
    // TEST:relay/src/authority_store.rs[FileAuthorityStore::delete]
    #[test]
    fn authority_store_delete_is_cas_bound_and_idempotent() {
        let root = recovery_test_root();
        let store = FileAuthorityStore::open(&root).expect("open delete store");
        let key = "herdr-dog/test-delete";
        let kind = "runtime_fence";
        let filename = "delete-test.json";
        let missing_root = recovery_test_root();
        fs::remove_dir(&missing_root).expect("remove missing store root");
        let missing_store = FileAuthorityStore::open(&missing_root).expect("open missing store");
        assert_eq!(
            missing_store.delete(key, kind, filename, 0),
            Ok(AuthorityDeleteOutcome::Missing)
        );
        assert!(!missing_root.exists());
        let revision = store
            .commit(key, kind, filename, 1, "active", b"delete-me", 0)
            .expect("initial delete record");
        assert_eq!(revision, 1);
        assert_eq!(
            store.delete(key, kind, filename, 0),
            Err(AuthorityStoreError::Conflict)
        );
        assert_eq!(
            store.delete(key, kind, filename, revision),
            Ok(AuthorityDeleteOutcome::Deleted)
        );
        assert!(
            store
                .load(key, kind, filename)
                .expect("deleted record load")
                .is_none()
        );
        assert_eq!(
            store.delete(key, kind, filename, revision),
            Ok(AuthorityDeleteOutcome::Missing)
        );
        assert_eq!(
            store
                .commit(key, kind, filename, 1, "active", b"recreated", 0)
                .expect("recreate after delete"),
            1
        );
        assert_eq!(
            store.delete(key, kind, filename, 1),
            Ok(AuthorityDeleteOutcome::Deleted)
        );
        let _ = fs::remove_dir_all(root);
    }

    /// Verifies pairing tombstones and runtime epochs survive Relay restarts safely.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_authority_store_round_trip]
    #[tokio::test(flavor = "current_thread")]
    async fn relay_authority_store_round_trip() {
        let root = recovery_test_root();
        let config = IrohRelayConfig::new(4, 4, DEFAULT_CONTROL_TIMEOUT)
            .expect("bounded config")
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            )
            .with_development_recovery_dir(&root)
            .expect("recovery directory");
        let peer = SecretKey::generate().public();
        let relay_secret_key = SecretKey::generate();

        let first = IrohRelayEndpoint::bind_with_secret_key(
            config.clone(),
            Arc::new(FakePairingVerifier),
            relay_secret_key,
        )
        .await
        .expect("first Relay bind");
        let first_endpoint_id = first.endpoint_id();
        assert_eq!(first.state.runtime_epoch, 1);
        assert!(
            first
                .state
                .mark_paired(peer)
                .expect("persist first pairing")
        );
        assert_eq!(first.paired_peer_count(), 1);
        first.shutdown().await.expect("first Relay shutdown");

        let second = IrohRelayEndpoint::bind(config.clone(), Arc::new(FakePairingVerifier))
            .await
            .expect("restart Relay bind");
        assert_eq!(second.endpoint_id(), first_endpoint_id);
        assert_eq!(second.state.runtime_epoch, 2);
        assert_eq!(second.paired_peer_count(), 1);
        let restored_relation = lock(&second.state.pairings)[&peer];
        assert_eq!(
            restored_relation.local_identity_generation,
            second.state.local_identity_generation
        );
        assert_eq!(
            restored_relation.peer_identity_generation,
            INITIAL_PEER_IDENTITY_GENERATION
        );
        assert_eq!(restored_relation.pairing_generation, 1);
        assert!(restored_relation.updated_at_epoch_seconds > 0);
        assert!(restored_relation.last_attempt_id > 0);
        assert_eq!(*lock(&second.state.pairing_revision), 1);
        assert!(second.try_revoke_peer(peer).expect("persist revocation"));
        assert_eq!(second.paired_peer_count(), 0);
        second.shutdown().await.expect("second Relay shutdown");

        let third = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier))
            .await
            .expect("revoked restart Relay bind");
        assert_eq!(third.state.runtime_epoch, 3);
        assert_eq!(third.paired_peer_count(), 0);
        assert_eq!(lock(&third.state.pairings).len(), 1);
        assert!(!third.state.is_paired(peer));
        third.shutdown().await.expect("third Relay shutdown");
        let _ = fs::remove_dir_all(root);
    }

    /// Verifies an explicit empty pairing replacement survives restart as distinct from missing state.
    // TEST:relay/src/iroh_endpoint.rs[tests::empty_pairing_authority_replacement_recovers]
    #[test]
    fn empty_pairing_authority_replacement_recovers() {
        let root = recovery_test_root();
        let store = FileAuthorityStore::open(&root).expect("open pairing store");
        let pairings = BTreeMap::new();
        let (payload, generation) = encode_pairing_authority(&pairings).expect("encode empty set");
        let revision = store
            .commit(
                PAIRING_AUTHORITY_STORAGE_KEY,
                PAIRING_AUTHORITY_RECORD_KIND,
                PAIRING_AUTHORITY_FILENAME,
                generation,
                "active",
                &payload,
                0,
            )
            .expect("persist empty relation set");
        let (restored, restored_revision, next_attempt_id, generation) =
            restore_pairing_authority(&store, INITIAL_IDENTITY_GENERATION)
                .expect("restore empty relation set");
        assert_eq!(generation, 1);
        assert_eq!(next_attempt_id, INITIAL_PAIRING_ATTEMPT_ID);
        assert!(restored.is_empty());
        assert_eq!(restored_revision, revision);
        fs::remove_dir_all(root).expect("pairing recovery cleanup");
    }

    /// Verifies stale pairing relations are replaced when the Relay identity generation changes.
    // TEST:relay/src/iroh_endpoint.rs[tests::stale_pairing_authority_is_replaced]
    #[test]
    fn stale_pairing_authority_is_replaced() {
        let root = recovery_test_root();
        let store = FileAuthorityStore::open(&root).expect("open stale pairing store");
        let peer = SecretKey::generate().public();
        let mut pairings = BTreeMap::new();
        pairings.insert(
            peer,
            PairingRecord {
                pairing_generation: 1,
                local_identity_generation: 1,
                peer_identity_generation: INITIAL_PEER_IDENTITY_GENERATION,
                paired: true,
                revoked: false,
                updated_at_epoch_seconds: 1,
                last_attempt_id: 1,
                failed_attempts: 0,
                challenge_window_started: Instant::now(),
                challenge_count: 0,
            },
        );
        let (payload, generation) = encode_pairing_authority(&pairings).expect("encode stale");
        assert_eq!(
            store
                .commit(
                    PAIRING_AUTHORITY_STORAGE_KEY,
                    PAIRING_AUTHORITY_RECORD_KIND,
                    PAIRING_AUTHORITY_FILENAME,
                    generation,
                    "active",
                    &payload,
                    0,
                )
                .expect("persist stale relation"),
            1
        );
        let (restored, revision, next_attempt_id, generation) =
            restore_pairing_authority(&store, 2).expect("replace stale relation");
        assert_eq!(generation, 2);
        assert!(restored.is_empty());
        assert_eq!(revision, 2);
        assert_eq!(next_attempt_id, INITIAL_PAIRING_ATTEMPT_ID);
        let record = store
            .load(
                PAIRING_AUTHORITY_STORAGE_KEY,
                PAIRING_AUTHORITY_RECORD_KIND,
                PAIRING_AUTHORITY_FILENAME,
            )
            .expect("load replacement")
            .expect("replacement record");
        let (_revision, generation, state, payload) = record.into_parts();
        let decoded = serde_json::from_slice::<PersistedPairingAuthority>(&payload)
            .expect("decode replacement");
        assert_eq!(generation, 2);
        assert_eq!(state, "active");
        assert!(decoded.relations.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    /// Verifies the persisted pairing bound and control-frame debug redaction.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_authority_capacity_and_redaction]
    #[test]
    fn pairing_authority_capacity_and_redaction() {
        let mut pairings = BTreeMap::new();
        for index in 0..=MAX_PERSISTED_PAIRING_RELATIONS {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            bytes[8] = 0x5a;
            let peer = SecretKey::from_bytes(&bytes).public();
            pairings.insert(
                peer,
                PairingRecord {
                    pairing_generation: index as u64 + 1,
                    local_identity_generation: INITIAL_IDENTITY_GENERATION,
                    peer_identity_generation: INITIAL_PEER_IDENTITY_GENERATION,
                    paired: true,
                    revoked: false,
                    updated_at_epoch_seconds: 1,
                    last_attempt_id: index as u64 + 1,
                    failed_attempts: 0,
                    challenge_window_started: Instant::now(),
                    challenge_count: 0,
                },
            );
        }
        assert_eq!(
            encode_pairing_authority(&pairings),
            Err(AuthorityStoreError::Invalid)
        );
        let frame = HdpFrame::new(HdpKind::PairingSubmit, b"123456");
        let debug = format!("{frame:?}");
        assert!(!debug.contains("123456"));
        assert!(!debug.contains("payload:"));
    }

    /// Verifies malformed persisted pairing data fails closed before admission.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_authority_rejects_corrupt_payload]
    #[test]
    fn pairing_authority_rejects_corrupt_payload() {
        let root = recovery_test_root();
        let store = FileAuthorityStore::open(&root).expect("open corrupt pairing store");
        store
            .commit(
                PAIRING_AUTHORITY_STORAGE_KEY,
                PAIRING_AUTHORITY_RECORD_KIND,
                PAIRING_AUTHORITY_FILENAME,
                INITIAL_PAIRING_GENERATION,
                "active",
                b"not-json",
                0,
            )
            .expect("persist malformed pairing payload");
        assert!(matches!(
            restore_pairing_authority(&store, INITIAL_IDENTITY_GENERATION),
            Err(AuthorityStoreError::Corrupt)
        ));
        let _ = fs::remove_dir_all(root);
    }

    /// Verifies an explicit key cannot replace a different development-recovered identity.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_identity_rejects_mismatched_supplied_key]
    #[tokio::test(flavor = "current_thread")]
    async fn relay_identity_rejects_mismatched_supplied_key() {
        let root = recovery_test_root();
        let config = IrohRelayConfig::new(4, 4, DEFAULT_CONTROL_TIMEOUT)
            .expect("bounded config")
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            )
            .with_development_recovery_dir(&root)
            .expect("recovery directory");
        let first = IrohRelayEndpoint::bind_with_secret_key(
            config.clone(),
            Arc::new(FakePairingVerifier),
            SecretKey::generate(),
        )
        .await
        .expect("first Relay bind");
        first.shutdown().await.expect("first Relay shutdown");

        let result = IrohRelayEndpoint::bind_with_secret_key(
            config,
            Arc::new(FakePairingVerifier),
            SecretKey::generate(),
        )
        .await;
        assert!(matches!(result, Err(IrohEndpointError::AuthorityStorage)));
        let _ = fs::remove_dir_all(root);
    }

    /// Verifies first-writer conflict reconciliation adopts the matching committed identity.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_identity_first_writer_conflict_adopts_matching_key]
    #[test]
    fn relay_identity_first_writer_conflict_adopts_matching_key() {
        let root = recovery_test_root();
        let store = FileAuthorityStore::open(&root).expect("open identity store");
        let candidate = SecretKey::generate();
        let competing = candidate.clone();
        let (recovered, generation) =
            load_or_create_relay_identity_with_before_commit(&store, Some(&candidate), |store| {
                let payload = encode_relay_identity(&competing).expect("encode competing identity");
                store
                    .commit(
                        RELAY_IDENTITY_STORAGE_KEY,
                        RELAY_IDENTITY_RECORD_KIND,
                        RELAY_IDENTITY_FILENAME,
                        INITIAL_IDENTITY_GENERATION,
                        "active",
                        payload.as_slice(),
                        0,
                    )
                    .expect("commit competing first writer");
            })
            .expect("reconcile first-writer conflict");
        assert_eq!(recovered.public(), candidate.public());
        assert_eq!(generation, INITIAL_IDENTITY_GENERATION);
        let _ = fs::remove_dir_all(root);
    }

    /// Verifies missing recovery identity requires explicit development provisioning.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_missing_identity_requires_explicit_key]
    #[tokio::test(flavor = "current_thread")]
    async fn relay_missing_identity_requires_explicit_key() {
        let root = recovery_test_root();
        let config = IrohRelayConfig::new(4, 4, DEFAULT_CONTROL_TIMEOUT)
            .expect("bounded config")
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            )
            .with_development_recovery_dir(&root)
            .expect("recovery directory");
        assert!(matches!(
            IrohRelayEndpoint::bind(config.clone(), Arc::new(FakePairingVerifier)).await,
            Err(IrohEndpointError::AuthorityStorage)
        ));
        let endpoint = IrohRelayEndpoint::provision_development_identity(
            config,
            Arc::new(FakePairingVerifier),
        )
        .await
        .expect("explicit identity creation");
        endpoint.shutdown().await.expect("shutdown Relay");
        let _ = fs::remove_dir_all(root);
    }

    /// Verifies explicit development provisioning rejects a missing recovery directory.
    // TEST:relay/src/iroh_endpoint.rs[tests::development_identity_requires_recovery_directory]
    #[tokio::test(flavor = "current_thread")]
    async fn development_identity_requires_recovery_directory() {
        let config = IrohRelayConfig::default()
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            );
        let result = IrohRelayEndpoint::provision_development_identity(
            config,
            Arc::new(FakePairingVerifier),
        )
        .await;
        assert!(matches!(
            result,
            Err(IrohEndpointError::InvalidConfiguration {
                field: "development_recovery_dir"
            })
        ));
    }

    /// Verifies a corrupt persisted identity blocks Relay startup rather than generating a fallback.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_identity_corruption_fails_closed]
    #[tokio::test(flavor = "current_thread")]
    async fn relay_identity_corruption_fails_closed() {
        let root = recovery_test_root();
        let record_path = root.join(RELAY_IDENTITY_FILENAME);
        fs::write(&record_path, b"{}").expect("corrupt identity record");
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600))
            .expect("identity record mode");
        let config = IrohRelayConfig::new(4, 4, DEFAULT_CONTROL_TIMEOUT)
            .expect("bounded config")
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            )
            .with_development_recovery_dir(&root)
            .expect("recovery directory");
        let result = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier)).await;
        assert!(matches!(result, Err(IrohEndpointError::AuthorityStorage)));
        let _ = fs::remove_dir_all(root);
    }

    /// Verifies a large connection limit cannot expand the persisted pairing-record bound.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_registry_cap_is_fixed]
    #[test]
    fn pairing_registry_cap_is_fixed() {
        let state = IrohRelayState::new(MAX_IROH_CONNECTIONS, None, 1, INITIAL_IDENTITY_GENERATION)
            .expect("test state");
        assert_eq!(state.max_pairing_records, MAX_PAIRING_RECORDS);
    }

    /// Creates a loopback-only client endpoint for the endpoint integration tests.
    async fn client_endpoint() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            )
            .expect("client bind address")
            .bind()
            .await
            .expect("client endpoint")
    }

    /// Creates a unique owner-only directory for the fixed workspace verifier test.
    fn verifier_test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let temp_root = PathBuf::from("/private/tmp");
        let prefix = format!("hdi-{}-{nonce}", std::process::id());
        for attempt in 0..32 {
            let root = temp_root.join(format!("{prefix}-{attempt}"));
            match fs::create_dir(&root) {
                Ok(()) => {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                        .expect("verifier root mode");
                    return root;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("verifier root: {error}"),
            }
        }
        panic!("verifier root: could not allocate unique directory");
    }

    /// Serves the exact workspace.create/get/close exchange used by the iroh verifier.
    fn spawn_verifier_workspace_server(socket_path: PathBuf) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&socket_path).expect("workspace socket");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .expect("workspace socket mode");
        tokio::spawn(async move {
            let mut title = String::new();
            for expected_method in ["workspace.create", "workspace.get", "workspace.close"] {
                let (stream, _) = listener.accept().await.expect("workspace accept");
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .await
                    .expect("workspace request");
                let mut stream = reader.into_inner();
                let request: serde_json::Value =
                    serde_json::from_str(&line).expect("workspace request JSON");
                let id = request["id"].as_str().expect("request id");
                assert_eq!(request["method"].as_str(), Some(expected_method));
                let response = match expected_method {
                    "workspace.create" => {
                        assert_eq!(request["params"]["cwd"].as_str(), Some("/tmp"));
                        assert_eq!(request["params"]["focus"].as_bool(), Some(false));
                        assert_eq!(request["params"]["env"], serde_json::json!({}));
                        title = request["params"]["label"]
                            .as_str()
                            .expect("workspace title")
                            .to_owned();
                        serde_json::json!({
                            "id": id,
                            "result": {"workspace": {"workspace_id": "iroh-test-workspace"}}
                        })
                    }
                    "workspace.get" => serde_json::json!({
                        "id": id,
                        "result": {
                            "workspace": {
                                "workspace_id": "iroh-test-workspace",
                                "label": title
                            }
                        }
                    }),
                    "workspace.close" => {
                        serde_json::json!({"id": id, "result": {"type": "ok"}})
                    }
                    _ => unreachable!("fixed verifier method list"),
                };
                let mut bytes = serde_json::to_vec(&response).expect("workspace response");
                bytes.push(b'\n');
                stream
                    .write_all(&bytes)
                    .await
                    .expect("workspace response write");
            }
            fs::remove_file(socket_path).expect("workspace socket cleanup");
        })
    }

    /// Verifies the iroh pairing verifier performs the fixed Herdr workspace exchange.
    // TEST:relay/src/iroh_endpoint.rs[tests::herdr_workspace_verifier_uses_fixed_workspace_contract]
    #[tokio::test(flavor = "current_thread")]
    async fn herdr_workspace_verifier_uses_fixed_workspace_contract() {
        let root = verifier_test_root();
        let socket_path = root.join("herdr.sock");
        let workspace_task = spawn_verifier_workspace_server(socket_path.clone());
        let uid = crate::material::current_uid().expect("uid");
        let workspace = crate::bootstrap_runtime::HerdrWorkspaceClient::new(
            socket_path,
            uid,
            "/tmp".to_owned(),
            "default".to_owned(),
        )
        .expect("workspace client");
        let verifier = HerdrWorkspacePairingVerifier {
            workspace,
            attempts: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
        };
        let peer = SecretKey::generate().public();
        assert!(verifier.begin(peer).await);
        let code = verifier
            .attempts
            .lock()
            .await
            .get(&peer)
            .expect("pending verifier attempt")
            .code;
        assert!(verifier.verify(peer, code).await);
        assert!(verifier.attempts.lock().await.is_empty());
        workspace_task.await.expect("workspace server task");
        fs::remove_dir_all(root).expect("verifier test cleanup");
    }
    /// Reads one response frame from a long-lived control stream.
    async fn read_control_frame(recv: &mut RecvStream) -> HdpFrame {
        read_hdp_frame(recv, HDP1_MAX_FRAME_BYTES)
            .await
            .expect("control response")
    }

    /// Verifies frame bounds and the fixed six-kind registry without exposing payload bytes.
    // TEST:relay/src/iroh_endpoint.rs[tests::hdp1_rejects_oversized_frames]
    #[test]
    fn hdp1_rejects_oversized_frames() {
        let frame = HdpFrame::new(HdpKind::PairingSubmit, vec![b'1'; HDP1_MAX_FRAME_BYTES]);
        assert_eq!(frame.encode(), Err(HdpFrameError::FrameTooLarge));
        assert_eq!(HdpKind::try_from(7), Err(HdpFrameError::UnknownKind));
    }

    /// Verifies production defaults use the official public relay and local tests opt out.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_mode_defaults_to_public_and_tests_disable_relay]
    #[test]
    fn relay_mode_defaults_to_public_and_tests_disable_relay() {
        assert_eq!(IrohRelayConfig::default().relay_mode, RelayMode::Default);
        assert_eq!(
            IrohRelayConfig::default()
                .without_network_relay_for_test()
                .relay_mode,
            RelayMode::Disabled
        );
    }

    /// Verifies pairing is required before a control connection becomes session-ready.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_requires_control_exchange]
    #[tokio::test(flavor = "current_thread")]
    async fn pairing_requires_control_exchange() {
        let config = IrohRelayConfig::default()
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            );
        let server = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier))
            .await
            .expect("bind relay endpoint");
        let client = client_endpoint().await;
        let connection = client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect relay endpoint");
        let (mut send, mut recv) = connection.open_bi().await.expect("control stream");
        send.write_all(
            &HdpFrame::new(HdpKind::PairingStart, Vec::new())
                .encode()
                .expect("pairing start"),
        )
        .await
        .expect("write pairing start");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingRejected
        );
        send.write_all(
            &HdpFrame::new(HdpKind::PairingSubmit, b"123456".to_vec())
                .encode()
                .expect("pairing submit"),
        )
        .await
        .expect("write pairing submit");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingAccepted
        );
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::ConnectionReady
        );
        assert_eq!(server.active_connection_count(), 1);
        assert_eq!(server.paired_peer_count(), 1);
        connection.close(0u32.into(), b"test");
        server.shutdown().await.expect("shutdown relay endpoint");
    }

    /// Verifies the user-facing pairing deadline is longer than the control-frame deadline.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_submit_uses_challenge_ttl]
    #[tokio::test(flavor = "current_thread")]
    async fn pairing_submit_uses_challenge_ttl() {
        let config = IrohRelayConfig::new(4, 4, Duration::from_millis(25))
            .expect("short control timeout")
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            );
        let server = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier))
            .await
            .expect("bind relay endpoint");
        let client = client_endpoint().await;
        let connection = client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect relay endpoint");
        let (mut send, mut recv) = connection.open_bi().await.expect("control stream");
        send.write_all(
            &HdpFrame::new(HdpKind::PairingStart, Vec::new())
                .encode()
                .expect("pairing start"),
        )
        .await
        .expect("write pairing start");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingRejected
        );
        tokio::time::sleep(Duration::from_millis(75)).await;
        send.write_all(
            &HdpFrame::new(HdpKind::PairingSubmit, b"123456".to_vec())
                .encode()
                .expect("pairing submit"),
        )
        .await
        .expect("write pairing submit");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingAccepted
        );
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::ConnectionReady
        );
        connection.close(0u32.into(), b"test");
        connection.closed().await;
        server.shutdown().await.expect("shutdown relay endpoint");
    }

    /// Verifies a paired connection stays alive during control silence and receives shutdown GoAway.
    // TEST:relay/src/iroh_endpoint.rs[tests::paired_connection_survives_control_silence]
    #[tokio::test(flavor = "current_thread")]
    async fn paired_connection_survives_control_silence() {
        let config = IrohRelayConfig::new(4, 4, Duration::from_millis(25))
            .expect("short control timeout")
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            );
        let server = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier))
            .await
            .expect("bind relay endpoint");
        let client = client_endpoint().await;
        let connection = client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect relay endpoint");
        let (mut send, mut recv) = connection.open_bi().await.expect("control stream");
        send.write_all(
            &HdpFrame::new(HdpKind::PairingStart, Vec::new())
                .encode()
                .expect("pairing start"),
        )
        .await
        .expect("write pairing start");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingRejected
        );
        send.write_all(
            &HdpFrame::new(HdpKind::PairingSubmit, b"123456".to_vec())
                .encode()
                .expect("pairing submit"),
        )
        .await
        .expect("write pairing submit");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingAccepted
        );
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::ConnectionReady
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(server.active_connection_count(), 1);
        let shutdown = tokio::spawn(async move { server.shutdown().await });
        let goaway = tokio::time::timeout(Duration::from_secs(1), read_control_frame(&mut recv))
            .await
            .expect("bounded GoAway delivery");
        assert_eq!(goaway.kind(), HdpKind::GoAway);
        shutdown
            .await
            .expect("shutdown task")
            .expect("shutdown relay endpoint");
        connection.closed().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ticket_only_session_is_rejected() {
        let config = IrohRelayConfig::default()
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            );
        let server = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier))
            .await
            .expect("bind relay endpoint");
        let client = client_endpoint().await;
        let connection = client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect relay endpoint");
        let (mut control_send, mut control_recv) = connection.open_bi().await.expect("control");
        control_send
            .write_all(
                &HdpFrame::new(HdpKind::PairingStart, Vec::new())
                    .encode()
                    .expect("start"),
            )
            .await
            .expect("write start");
        assert_eq!(
            read_control_frame(&mut control_recv).await.kind(),
            HdpKind::PairingRejected
        );
        control_send
            .write_all(
                &HdpFrame::new(HdpKind::PairingSubmit, b"123456".to_vec())
                    .encode()
                    .expect("submit"),
            )
            .await
            .expect("write submit");
        assert_eq!(
            read_control_frame(&mut control_recv).await.kind(),
            HdpKind::PairingAccepted
        );
        assert_eq!(
            read_control_frame(&mut control_recv).await.kind(),
            HdpKind::ConnectionReady
        );
        let (mut session_send, mut session_recv) = connection.open_bi().await.expect("session");
        let binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: 1,
            relay_generation: 1,
            connection_epoch: 1,
            session: crate::quic_wire::SessionName::new("default").expect("session"),
            fingerprint: [1; 32],
            token: [2; 32],
        };
        session_send
            .write_all(&binding.encode().expect("binding"))
            .await
            .expect("write binding");
        let mut response_bytes = [0_u8; crate::quic_wire::HDQS_RESPONSE_BYTES];
        session_recv
            .read_exact(&mut response_bytes)
            .await
            .expect("read rejection");
        let response = HdqsResponse::decode(&response_bytes).expect("decode rejection");
        assert_eq!(response.kind, crate::quic_wire::HdqsKind::Rejected);
        assert_eq!(response.reason, HdqsReason::SessionNotFound);
        connection.close(0u32.into(), b"test");
        server.shutdown().await.expect("shutdown relay endpoint");
    }

    /// Verifies malformed submissions consume the bounded pairing-attempt budget.
    // TEST:relay/src/iroh_endpoint.rs[tests::malformed_pairing_attempts_are_bounded]
    #[tokio::test(flavor = "current_thread")]
    async fn malformed_pairing_attempts_are_bounded() {
        let config = IrohRelayConfig::default()
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            );
        let server = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier))
            .await
            .expect("bind relay endpoint");
        let client = client_endpoint().await;
        let connection = client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect relay endpoint");
        let (mut send, mut recv) = connection.open_bi().await.expect("control stream");
        send.write_all(
            &HdpFrame::new(HdpKind::PairingStart, Vec::new())
                .encode()
                .expect("pairing start"),
        )
        .await
        .expect("write pairing start");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingRejected
        );
        for attempt in 0..MAX_PAIRING_ATTEMPTS {
            send.write_all(
                &HdpFrame::new(HdpKind::PairingSubmit, vec![b'x'; 6])
                    .encode()
                    .expect("malformed pairing submit"),
            )
            .await
            .expect("write malformed pairing submit");
            if attempt + 1 == MAX_PAIRING_ATTEMPTS {
                // The terminal rejection may race the transport close; the bounded connection
                // close, rather than delivery of an optional final frame, is the security gate.
                let terminal = tokio::time::timeout(
                    Duration::from_secs(1),
                    read_hdp_frame(&mut recv, HDP1_MAX_FRAME_BYTES),
                )
                .await;
                if let Ok(Ok(response)) = terminal {
                    assert_eq!(response.kind(), HdpKind::PairingRejected);
                    assert_eq!(response.payload, vec![4]);
                }
                tokio::time::timeout(Duration::from_secs(2), connection.closed())
                    .await
                    .expect("pairing budget closes connection");
                break;
            }
            let response = read_control_frame(&mut recv).await;
            assert_eq!(response.kind(), HdpKind::PairingRejected);
            assert_eq!(response.payload, vec![2]);
        }
        connection.close(0u32.into(), b"test");
        connection.closed().await;
        assert_eq!(server.paired_peer_count(), 0);
        server.shutdown().await.expect("shutdown relay endpoint");
    }

    /// Verifies a pairing submission without PairingStart is rejected and closes the protocol.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_submit_requires_start]
    #[tokio::test(flavor = "current_thread")]
    async fn pairing_submit_requires_start() {
        let config = IrohRelayConfig::default()
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            );
        let server = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier))
            .await
            .expect("bind relay endpoint");
        let client = client_endpoint().await;
        let connection = client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect relay endpoint");
        let (mut send, mut recv) = connection.open_bi().await.expect("control stream");
        send.write_all(
            &HdpFrame::new(HdpKind::PairingSubmit, b"123456".to_vec())
                .encode()
                .expect("pairing submit"),
        )
        .await
        .expect("write pairing submit");
        let response = read_control_frame(&mut recv).await;
        assert_eq!(response.kind(), HdpKind::PairingRejected);
        assert_eq!(response.payload, vec![5]);
        connection.close(0u32.into(), b"test");
        connection.closed().await;
        server.shutdown().await.expect("shutdown relay endpoint");
    }

    /// Verifies challenge starts are bounded per peer and reset failed-code budget per challenge.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_challenge_rate_is_bounded]
    #[test]
    fn pairing_challenge_rate_is_bounded() {
        let state =
            IrohRelayState::new(4, None, 1, INITIAL_IDENTITY_GENERATION).expect("test state");
        let peer = SecretKey::generate().public();

        for _ in 0..MAX_PAIRING_CHALLENGES_PER_WINDOW {
            assert!(state.reserve_pairing_challenge(peer));
            for attempt in 0..MAX_PAIRING_ATTEMPTS {
                assert_eq!(
                    state.record_pairing_failure(peer),
                    attempt + 1 < MAX_PAIRING_ATTEMPTS
                );
            }
        }
        assert!(!state.reserve_pairing_challenge(peer));
    }

    /// Verifies the pairing registry rejects new unknown peers after its fixed capacity.
    // TEST:relay/src/iroh_endpoint.rs[tests::pairing_registry_is_bounded]
    #[test]
    fn pairing_registry_is_bounded() {
        let state =
            IrohRelayState::new(1, None, 1, INITIAL_IDENTITY_GENERATION).expect("test state");
        let first = SecretKey::generate().public();
        let second = SecretKey::generate().public();
        assert!(state.record_pairing_failure(first));
        assert!(!state.record_pairing_failure(second));
        assert_eq!(lock(&state.pairings).len(), 1);
    }

    /// Verifies a disconnected unpaired peer does not retain a pairing registry slot.
    // TEST:relay/src/iroh_endpoint.rs[tests::disconnected_unpaired_peer_releases_pairing_slot]
    #[tokio::test(flavor = "current_thread")]
    async fn disconnected_unpaired_peer_releases_pairing_slot() {
        let config = IrohRelayConfig::new(1, 4, DEFAULT_CONTROL_TIMEOUT)
            .expect("bounded config")
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            );
        let server = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier))
            .await
            .expect("bind relay endpoint");
        let first_client = client_endpoint().await;
        let first_connection = first_client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect first peer");
        let (mut first_send, mut first_recv) = first_connection.open_bi().await.expect("control");
        first_send
            .write_all(
                &HdpFrame::new(HdpKind::PairingStart, Vec::new())
                    .encode()
                    .expect("start"),
            )
            .await
            .expect("write start");
        assert_eq!(
            read_control_frame(&mut first_recv).await.kind(),
            HdpKind::PairingRejected
        );
        assert_eq!(lock(&server.state.pairings).len(), 1);
        first_connection.close(0u32.into(), b"test disconnect");
        first_connection.closed().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if server.active_connection_count() == 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first peer cleanup");
        assert_eq!(lock(&server.state.pairings).len(), 0);

        let second_client = client_endpoint().await;
        let second_connection = second_client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect second peer");
        let (mut second_send, mut second_recv) =
            second_connection.open_bi().await.expect("control");
        second_send
            .write_all(
                &HdpFrame::new(HdpKind::PairingStart, Vec::new())
                    .encode()
                    .expect("start"),
            )
            .await
            .expect("write start");
        assert_eq!(
            read_control_frame(&mut second_recv).await.kind(),
            HdpKind::PairingRejected
        );
        assert_eq!(lock(&server.state.pairings).len(), 1);
        second_connection.close(0u32.into(), b"test disconnect");
        second_connection.closed().await;
        server.shutdown().await.expect("shutdown relay endpoint");
    }

    /// Verifies failed durable revocation closes the peer and does not claim success.
    // TEST:relay/src/iroh_endpoint.rs[tests::revoke_failure_closes_active_peer_without_claiming_success]
    #[tokio::test(flavor = "current_thread")]
    async fn revoke_failure_closes_active_peer_without_claiming_success() {
        let root = recovery_test_root();
        let config = IrohRelayConfig::default()
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            )
            .with_development_recovery_dir(&root)
            .expect("recovery directory");
        let server = IrohRelayEndpoint::bind_with_secret_key(
            config,
            Arc::new(FakePairingVerifier),
            SecretKey::generate(),
        )
        .await
        .expect("bind relay endpoint");
        let client = client_endpoint().await;
        let connection = client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect relay endpoint");
        let (mut send, mut recv) = connection.open_bi().await.expect("control stream");
        send.write_all(
            &HdpFrame::new(HdpKind::PairingStart, Vec::new())
                .encode()
                .expect("pairing start"),
        )
        .await
        .expect("write pairing start");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingRejected
        );
        send.write_all(
            &HdpFrame::new(HdpKind::PairingSubmit, b"123456".to_vec())
                .encode()
                .expect("pairing submit"),
        )
        .await
        .expect("write pairing submit");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingAccepted
        );
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::ConnectionReady
        );
        assert_eq!(server.paired_peer_count(), 1);

        // Force a stale expected revision to model a failed/uncertain durable revoke.
        *lock(&server.state.pairing_revision) = 0;
        assert_eq!(
            server.try_revoke_peer(client.id()),
            Err(IrohEndpointError::AuthorityStorage)
        );
        assert_eq!(server.paired_peer_count(), 0);
        connection.closed().await;
        server.shutdown().await.expect("shutdown relay endpoint");
        let _ = fs::remove_dir_all(root);
    }

    /// Verifies revocation clears pairing state and closes the active connection.
    // TEST:relay/src/iroh_endpoint.rs[tests::revoke_closes_active_connection]
    #[tokio::test(flavor = "current_thread")]
    async fn revoke_closes_active_connection() {
        let config = IrohRelayConfig::default()
            .without_network_relay_for_test()
            .with_bind_addr(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback address"),
            );
        let server = IrohRelayEndpoint::bind(config, Arc::new(FakePairingVerifier))
            .await
            .expect("bind relay endpoint");
        let client = client_endpoint().await;
        let connection = client
            .connect(server.endpoint_addr(), IROH_RELAY_ALPN)
            .await
            .expect("connect relay endpoint");
        let (mut send, mut recv) = connection.open_bi().await.expect("control stream");
        send.write_all(
            &HdpFrame::new(HdpKind::PairingStart, Vec::new())
                .encode()
                .expect("pairing start"),
        )
        .await
        .expect("write pairing start");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingRejected
        );
        send.write_all(
            &HdpFrame::new(HdpKind::PairingSubmit, b"123456".to_vec())
                .encode()
                .expect("pairing submit"),
        )
        .await
        .expect("write pairing submit");
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::PairingAccepted
        );
        assert_eq!(
            read_control_frame(&mut recv).await.kind(),
            HdpKind::ConnectionReady
        );
        assert_eq!(server.paired_peer_count(), 1);
        assert!(server.revoke_peer(client.id()));
        assert_eq!(server.paired_peer_count(), 0);
        connection.closed().await;
        server.shutdown().await.expect("shutdown relay endpoint");
    }
}
