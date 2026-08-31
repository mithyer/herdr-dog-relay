//! Production-shaped HDB1 bootstrap authority for the Relay.
//!
//! This module is intentionally narrower than the normal QRM bridge. It owns only the server-only
//! bootstrap and later Core-enrollment approval state needed by HDB1/HDE3. Herdr access is limited
//! to one configured session and the fixed workspace create/get/close operations; no generic
//! request, subscription, workspace topology, verification code, or private key leaves this
//! module.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::Mutex,
    time::timeout,
};

use crate::{
    config::RelayConfig,
    error::{RelayError, RelayResult},
    material::{
        ProtectedFileKind, read_protected_file, validate_protected_path, write_protected_file,
    },
    pki,
    socket::UnixSocketConnector,
};

use super::bootstrap_wire::{
    HDB1_DIGEST_BYTES, HDB1_ID_BYTES, HDB1_MAX_CSR_BYTES, HDB1_MAX_SESSION_BYTES, Hdb1StartPayload,
};
use super::enrollment_v3_wire::HDE3_MAX_CSR_BYTES;

/// Maximum serialized Herdr response retained by the fixed workspace verifier.
const HERDR_RESPONSE_MAX_BYTES: usize = 64 * 1024;
/// Maximum workspace identifier retained for cleanup.
const WORKSPACE_ID_MAX_BYTES: usize = 128;
/// Maximum hidden workspace title accepted by the verifier.
const WORKSPACE_TITLE_MAX_BYTES: usize = 256;
/// Maximum retained active bootstrap attempts on one Relay.
const MAX_ACTIVE_BOOTSTRAPS: usize = 8;
/// Maximum retained approval records in one Relay process.
const MAX_APPROVALS: usize = 256;
/// Maximum starts permitted from one observed peer IP in the rolling window.
const MAX_PEER_STARTS: usize = 3;
/// Rolling peer-IP start window.
const PEER_START_WINDOW_SECS: u64 = 15 * 60;
/// Human code-entry lifetime.
const BOOTSTRAP_CODE_TTL_SECS: u64 = 300;
/// Hard lifetime for an HDB1 attempt.
pub(crate) const BOOTSTRAP_HARD_LIFETIME_SECS: u64 = 330;
/// Recovery lifetime for an issued but unconfirmed Core approval.
const CORE_APPROVAL_RECOVERY_TTL_SECS: u64 = 24 * 60 * 60;
/// Maximum failed code submissions for one approval.
const MAX_CODE_FAILURES: u8 = 5;
/// Maximum time for one fixed Herdr operation.
const HERDR_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Sanitized production bootstrap failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapRuntimeError {
    /// The HDB1/HDE3 binding or input is malformed.
    InvalidField,
    /// The configured session or profile binding does not match.
    AuthorityMismatch,
    /// The configured protected workspace operation failed.
    WorkspaceUnavailable,
    /// The active bootstrap or approval limit is exhausted.
    CapacityExhausted,
    /// The observed peer has exceeded its start budget.
    PeerRateLimited,
    /// The configured session already has a live approval.
    AlreadyActive,
    /// The challenge or approval lifetime has elapsed.
    Expired,
    /// The user code did not match the hidden workspace title.
    CodeMismatch,
    /// The per-challenge code-failure budget is exhausted.
    CodeRateLimited,
    /// The attempt or approval is not retained.
    NotFound,
    /// Protected certificate or state persistence failed.
    PersistenceFailed,
}

impl fmt::Display for BootstrapRuntimeError {
    /// Formats a stable diagnostic without exposing identifiers, code or Herdr data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidField => "bootstrap field is invalid",
            Self::AuthorityMismatch => "bootstrap authority does not match",
            Self::WorkspaceUnavailable => "bootstrap workspace is unavailable",
            Self::CapacityExhausted => "bootstrap capacity is exhausted",
            Self::PeerRateLimited => "bootstrap peer rate limit is exhausted",
            Self::AlreadyActive => "bootstrap approval is already active",
            Self::Expired => "bootstrap approval has expired",
            Self::CodeMismatch => "bootstrap code is invalid",
            Self::CodeRateLimited => "bootstrap code limit is exhausted",
            Self::NotFound => "bootstrap approval is not found",
            Self::PersistenceFailed => "bootstrap persistence failed",
        })
    }
}

impl std::error::Error for BootstrapRuntimeError {}

/// Public challenge metadata returned to the HDB1 stream handler.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct BootstrapChallenge {
    /// Relay-minted bootstrap identifier.
    pub(crate) bootstrap_id: [u8; HDB1_ID_BYTES],
    /// Relay-minted challenge bound to the attempt.
    pub(crate) challenge: [u8; HDB1_DIGEST_BYTES],
    /// Protected code-entry expiry.
    pub(crate) expires_at_epoch_seconds: u64,
}

impl fmt::Debug for BootstrapChallenge {
    /// Reports challenge presence without exposing opaque bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapChallenge")
            .field("bootstrap_id_present", &true)
            .field("challenge_present", &true)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

/// Public Core certificate material returned after HDB1 code verification.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CoreIssuedMaterial {
    /// Durable approval identifier used by later HDE3 operations.
    pub(crate) approval_id: [u8; HDB1_ID_BYTES],
    /// SHA-256 identity of the issued Core certificate's SubjectPublicKeyInfo.
    pub(crate) core_identity: [u8; HDB1_DIGEST_BYTES],
    /// Public Core leaf and Core-enrollment Intermediate chain.
    pub(crate) certificate_chain: Vec<Vec<u8>>,
    /// Core certificate expiry.
    pub(crate) not_after_epoch_seconds: u64,
}

impl fmt::Debug for CoreIssuedMaterial {
    /// Reports public certificate shape without DER bytes or identity values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreIssuedMaterial")
            .field("approval_id_present", &true)
            .field("core_identity_present", &true)
            .field("certificate_count", &self.certificate_chain.len())
            .field(
                "certificate_bytes",
                &self.certificate_chain.iter().map(Vec::len).sum::<usize>(),
            )
            .field("not_after_epoch_seconds", &self.not_after_epoch_seconds)
            .finish()
    }
}

/// Public later-App approval challenge metadata.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AppApprovalChallenge {
    /// Relay-minted approval identifier.
    pub(crate) approval_id: [u8; HDB1_ID_BYTES],
    /// Relay-minted code challenge.
    pub(crate) challenge: [u8; HDB1_DIGEST_BYTES],
    /// Protected code-entry expiry.
    pub(crate) expires_at_epoch_seconds: u64,
}

impl fmt::Debug for AppApprovalChallenge {
    /// Reports challenge presence without exposing opaque values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppApprovalChallenge")
            .field("approval_id_present", &true)
            .field("challenge_present", &true)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

/// Core-owned context returned after a later App code is verified.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct AppApprovalContext {
    /// Durable approval identifier.
    pub(crate) approval_id: [u8; HDB1_ID_BYTES],
    /// Core identity that performed the approval.
    pub(crate) core_identity: [u8; HDB1_DIGEST_BYTES],
    /// App CSR bytes retained only for the immediate certificate operation.
    pub(crate) app_csr: Vec<u8>,
    /// App CSR digest validated before the workspace operation.
    pub(crate) app_csr_digest: [u8; HDB1_DIGEST_BYTES],
    /// Core binding digest retained for exact authority checks.
    pub(crate) core_binding_digest: [u8; HDB1_DIGEST_BYTES],
    /// Normalized Herdr session.
    pub(crate) normalized_session: String,
    /// Profile configuration generation.
    pub(crate) configuration_generation: u64,
}

impl fmt::Debug for AppApprovalContext {
    /// Reports bounded shape without CSR or authority bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppApprovalContext")
            .field("approval_id_present", &true)
            .field("core_identity_present", &true)
            .field("app_csr_bytes", &self.app_csr.len())
            .field("app_csr_digest_present", &true)
            .field("core_binding_digest_present", &true)
            .field("session_bound", &true)
            .field("configuration_generation", &self.configuration_generation)
            .finish()
    }
}

/// Exact workspace authority used by the production verifier.
#[derive(Clone)]
struct HerdrWorkspaceClient {
    /// Validated session-specific Unix socket connector.
    socket: UnixSocketConnector,
    /// Remote cwd used only by workspace.create.
    verification_cwd: String,
    /// Normalized session selected by Relay configuration.
    normalized_session: String,
}

impl fmt::Debug for HerdrWorkspaceClient {
    /// Reports fixed operation scope without exposing paths or session names.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HerdrWorkspaceClient")
            .field("socket_configured", &true)
            .field("verification_cwd_present", &true)
            .field("session_bound", &true)
            .finish()
    }
}

impl HerdrWorkspaceClient {
    /// Construct the fixed-session verifier after validating the non-secret remote cwd.
    fn new(
        socket_path: PathBuf,
        expected_uid: u32,
        verification_cwd: String,
        normalized_session: String,
    ) -> Result<Self, BootstrapRuntimeError> {
        if !is_valid_session(&normalized_session)
            || verification_cwd.is_empty()
            || verification_cwd.len() > 1_024
            || !Path::new(&verification_cwd).is_absolute()
            || verification_cwd.contains('\n')
            || verification_cwd.contains('\r')
        {
            return Err(BootstrapRuntimeError::InvalidField);
        }
        let socket = UnixSocketConnector::new(socket_path, expected_uid)
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        Ok(Self {
            socket,
            verification_cwd,
            normalized_session,
        })
    }

    /// Create the hidden workspace and verify its label with a fresh get operation.
    async fn create_and_verify(&self, title: &str) -> Result<String, BootstrapRuntimeError> {
        if title.is_empty() || title.len() > WORKSPACE_TITLE_MAX_BYTES {
            return Err(BootstrapRuntimeError::InvalidField);
        }
        let result = self
            .request(
                "workspace.create",
                json!({"cwd": self.verification_cwd, "label": title, "focus": false}),
            )
            .await?;
        let workspace = result
            .get("workspace")
            .and_then(Value::as_object)
            .ok_or(BootstrapRuntimeError::WorkspaceUnavailable)?;
        let workspace_id = workspace
            .get("workspace_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= WORKSPACE_ID_MAX_BYTES)
            .ok_or(BootstrapRuntimeError::WorkspaceUnavailable)?
            .to_owned();
        let readback = self
            .request("workspace.get", json!({"workspace_id": workspace_id}))
            .await;
        let verified = match readback {
            Ok(value) => {
                value
                    .get("workspace")
                    .and_then(Value::as_object)
                    .and_then(|workspace| workspace.get("workspace_id").and_then(Value::as_str))
                    == Some(workspace_id.as_str())
                    && value
                        .get("workspace")
                        .and_then(Value::as_object)
                        .and_then(|workspace| workspace.get("label").and_then(Value::as_str))
                        == Some(title)
            }
            Err(_) => false,
        };
        if !verified {
            let _ = self.close(&workspace_id).await;
            return Err(BootstrapRuntimeError::WorkspaceUnavailable);
        }
        Ok(workspace_id)
    }

    /// Close one known hidden workspace; an already-missing workspace is reconciled.
    async fn close(&self, workspace_id: &str) -> Result<(), BootstrapRuntimeError> {
        if workspace_id.is_empty() || workspace_id.len() > WORKSPACE_ID_MAX_BYTES {
            return Err(BootstrapRuntimeError::InvalidField);
        }
        match self
            .request("workspace.close", json!({"workspace_id": workspace_id}))
            .await
        {
            Ok(value) => {
                if value
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind == "ok")
                {
                    Ok(())
                } else {
                    Err(BootstrapRuntimeError::WorkspaceUnavailable)
                }
            }
            Err(BootstrapRuntimeError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Send one fixed allowlisted Herdr request over a fresh Unix socket.
    async fn request(&self, method: &str, params: Value) -> Result<Value, BootstrapRuntimeError> {
        if !matches!(
            method,
            "workspace.create" | "workspace.get" | "workspace.close"
        ) {
            return Err(BootstrapRuntimeError::AuthorityMismatch);
        }
        let mut stream = self
            .socket
            .connect()
            .await
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        let request_id = format!("herdr-dog-bootstrap-{}", rand::random::<u64>());
        let mut request = serde_json::to_vec(&json!({
            "id": request_id,
            "method": method,
            "params": params,
        }))
        .map_err(|_| BootstrapRuntimeError::InvalidField)?;
        request.push(b'\n');
        timeout(HERDR_OPERATION_TIMEOUT, stream.write_all(&request))
            .await
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        let response = read_json_line(&mut stream).await?;
        if response.get("id").and_then(Value::as_str) != Some(request_id.as_str()) {
            return Err(BootstrapRuntimeError::WorkspaceUnavailable);
        }
        if let Some(error) = response.get("error") {
            return match error.get("code").and_then(Value::as_str) {
                Some("workspace_not_found") => Err(BootstrapRuntimeError::NotFound),
                _ => Err(BootstrapRuntimeError::WorkspaceUnavailable),
            };
        }
        response
            .get("result")
            .cloned()
            .ok_or(BootstrapRuntimeError::WorkspaceUnavailable)
    }
}

/// Read exactly one bounded newline-delimited JSON response.
async fn read_json_line(stream: &mut UnixStream) -> Result<Value, BootstrapRuntimeError> {
    let mut bytes = Vec::with_capacity(512);
    loop {
        let mut byte = [0_u8; 1];
        timeout(HERDR_OPERATION_TIMEOUT, stream.read_exact(&mut byte))
            .await
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= HERDR_RESPONSE_MAX_BYTES {
            return Err(BootstrapRuntimeError::CapacityExhausted);
        }
        if byte[0] == b'\r' {
            return Err(BootstrapRuntimeError::InvalidField);
        }
        bytes.push(byte[0]);
    }
    serde_json::from_slice(&bytes).map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)
}

/// One pending HDB1 server-only bootstrap attempt.
struct BootstrapAttempt {
    /// Relay-observed peer IP bound to this in-memory attempt.
    peer_ip: IpAddr,
    /// Durable approval identifier minted for later HDE3.
    approval_id: [u8; HDB1_ID_BYTES],
    /// Relay challenge returned to Core.
    challenge: [u8; HDB1_DIGEST_BYTES],
    /// Code retained only while the hidden workspace is active.
    code: [u8; 6],
    /// Core CSR retained only until certificate issuance.
    core_csr: Vec<u8>,
    /// App CSR digest carried by HDB1 Start.
    app_csr_digest: [u8; HDB1_DIGEST_BYTES],
    /// Core binding digest carried by HDB1 Start.
    core_binding_digest: [u8; HDB1_DIGEST_BYTES],
    /// Normalized session selected by Core.
    normalized_session: String,
    /// Profile configuration generation selected by Core.
    configuration_generation: u64,
    /// Hidden workspace identity used for cleanup.
    workspace_id: String,
    /// Code-entry expiry.
    expires_at_epoch_seconds: u64,
    /// Hard attempt expiry.
    hard_expires_at_epoch_seconds: u64,
    /// Number of failed code submissions.
    failed_codes: u8,
}

/// Durable-in-process Core approval record used by HDE3.
struct CoreApproval {
    /// Issued Core certificate SubjectPublicKeyInfo identity.
    core_identity: [u8; HDB1_DIGEST_BYTES],
    /// App CSR digest authorized by the Core bootstrap.
    app_csr_digest: [u8; HDB1_DIGEST_BYTES],
    /// Core binding digest.
    core_binding_digest: [u8; HDB1_DIGEST_BYTES],
    /// Normalized session.
    normalized_session: String,
    /// Profile configuration generation.
    configuration_generation: u64,
    /// Whether the first App certificate has been durably confirmed.
    confirmed: bool,
    /// Recovery deadline while the issued Core approval remains unconfirmed.
    recovery_expires_at_epoch_seconds: u64,
    /// Public Core issuance material for HDB1 recovery.
    issued: CoreIssuedMaterial,
}

/// Pending later-App approval record.
struct AppApproval {
    /// Core identity authorized to complete this approval.
    core_identity: [u8; HDB1_DIGEST_BYTES],
    /// App CSR digest bound by ApprovalStart.
    app_csr_digest: [u8; HDB1_DIGEST_BYTES],
    /// Core binding digest.
    core_binding_digest: [u8; HDB1_DIGEST_BYTES],
    /// Normalized session.
    normalized_session: String,
    /// Profile configuration generation.
    configuration_generation: u64,
    /// Relay challenge.
    challenge: [u8; HDB1_DIGEST_BYTES],
    /// Code retained only until the approval is submitted or expires.
    code: [u8; 6],
    /// Hidden workspace identity.
    workspace_id: String,
    /// Code-entry expiry.
    expires_at_epoch_seconds: u64,
    /// Failed code count.
    failed_codes: u8,
}

/// Shared mutable production bootstrap state.
struct BootstrapState {
    /// Active HDB1 attempts keyed by bootstrap identifier.
    attempts: BTreeMap<[u8; HDB1_ID_BYTES], BootstrapAttempt>,
    /// Core approvals keyed by approval identifier.
    core_approvals: BTreeMap<[u8; HDB1_ID_BYTES], CoreApproval>,
    /// Later-App approvals keyed by approval identifier.
    app_approvals: BTreeMap<[u8; HDB1_ID_BYTES], AppApproval>,
    /// Session names with active HDB1/HDE3 hidden workspaces.
    active_sessions: BTreeSet<String>,
    /// Peer-IP start timestamps for the bounded pre-auth rate limit.
    peer_starts: BTreeMap<IpAddr, Vec<u64>>,
    /// Restart-recovered workspace identities awaiting bounded cleanup.
    orphaned_workspaces: Vec<(String, String)>,
}

impl Default for BootstrapState {
    /// Creates empty bounded state.
    fn default() -> Self {
        Self {
            attempts: BTreeMap::new(),
            core_approvals: BTreeMap::new(),
            app_approvals: BTreeMap::new(),
            active_sessions: BTreeSet::new(),
            peer_starts: BTreeMap::new(),
            orphaned_workspaces: Vec::new(),
        }
    }
}

/// Persisted bootstrap record kind; no code, CSR or private material is stored.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum PersistedBootstrapKind {
    /// A workspace exists but no Core certificate is durable yet.
    PendingBootstrap,
    /// A later App approval workspace is awaiting code entry.
    PendingApp,
    /// Core certificate and approval metadata are available for HDE3.
    CoreIssued,
}

/// Restart-surviving non-secret bootstrap record.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedBootstrapRecord {
    /// Record lifecycle kind.
    kind: PersistedBootstrapKind,
    /// Opaque bootstrap/approval identifier.
    approval_id: [u8; 32],
    /// Original bootstrap identifier when available.
    bootstrap_id: Option<[u8; 32]>,
    /// Issued Core certificate SubjectPublicKeyInfo identity, when available.
    core_identity: Option<[u8; 32]>,
    /// App CSR digest bound by the attempt.
    app_csr_digest: [u8; 32],
    /// Core binding digest.
    core_binding_digest: [u8; 32],
    /// Normalized Herdr session.
    normalized_session: String,
    /// Profile configuration generation.
    configuration_generation: u64,
    /// Whether the first App certificate has been durably confirmed.
    #[serde(default)]
    confirmed: bool,
    /// Known hidden workspace identity, only for cleanup.
    workspace_id: Option<String>,
    /// Pending-record expiry or unconfirmed Core-approval recovery expiry; zero after confirmation.
    expires_at_epoch_seconds: u64,
    /// Hard bootstrap expiry for pending records.
    hard_expires_at_epoch_seconds: Option<u64>,
    /// Public Core certificate chain, only for CoreIssued records.
    certificate_chain: Option<Vec<Vec<u8>>>,
    /// Public Core certificate expiry, only for CoreIssued records.
    not_after_epoch_seconds: Option<u64>,
}

/// Top-level protected bootstrap state file.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedBootstrapFile {
    /// Bounded records in deterministic map order.
    records: Vec<PersistedBootstrapRecord>,
}

/// Cross-process lock for bootstrap state replacement.
struct BootstrapStateLock {
    /// Sidecar lock file retained for the operation lifetime.
    file: std::fs::File,
}

impl Drop for BootstrapStateLock {
    /// Release the advisory state lock on every return path.
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Protected restart-surviving state store for bootstrap cleanup and Core approval metadata.
#[derive(Clone)]
struct BootstrapStateStore {
    /// Protected JSON state path.
    path: PathBuf,
    /// UID required for the state path and sidecar lock.
    expected_uid: u32,
}

impl fmt::Debug for BootstrapStateStore {
    /// Report state-store presence without its path or records.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapStateStore")
            .field("path_present", &true)
            .field("expected_uid_present", &true)
            .finish()
    }
}

impl BootstrapStateStore {
    /// Open a protected state path without creating any state until the first mutation.
    fn open(path: impl Into<PathBuf>, expected_uid: u32) -> RelayResult<Self> {
        let path = path.into();
        validate_protected_path(&path, expected_uid)?;
        Ok(Self { path, expected_uid })
    }

    /// Read and validate bounded persisted records.
    fn load(&self) -> RelayResult<PersistedBootstrapFile> {
        if !self.path.exists() {
            return Ok(PersistedBootstrapFile::default());
        }
        let bytes = read_protected_file(
            &self.path,
            self.expected_uid,
            ProtectedFileKind::Private,
            256 * 1024,
        )?;
        let file: PersistedBootstrapFile =
            serde_json::from_slice(&bytes).map_err(|_| RelayError::ConfigurationRead)?;
        if file.records.len() > MAX_APPROVALS
            || file
                .records
                .iter()
                .any(|record| !valid_persisted_record(record))
        {
            return Err(RelayError::ConfigurationRead);
        }
        Ok(file)
    }

    /// Persist the bounded non-secret projection of in-memory bootstrap state atomically.
    fn persist(&self, state: &BootstrapState) -> RelayResult<()> {
        let _lock = self.lock_file()?;
        let mut records = Vec::new();
        for (bootstrap_id, attempt) in &state.attempts {
            records.push(PersistedBootstrapRecord {
                kind: PersistedBootstrapKind::PendingBootstrap,
                approval_id: attempt.approval_id,
                bootstrap_id: Some(*bootstrap_id),
                core_identity: None,
                app_csr_digest: attempt.app_csr_digest,
                core_binding_digest: attempt.core_binding_digest,
                normalized_session: attempt.normalized_session.clone(),
                configuration_generation: attempt.configuration_generation,
                confirmed: false,
                workspace_id: Some(attempt.workspace_id.clone()),
                expires_at_epoch_seconds: attempt.expires_at_epoch_seconds,
                hard_expires_at_epoch_seconds: Some(attempt.hard_expires_at_epoch_seconds),
                certificate_chain: None,
                not_after_epoch_seconds: None,
            });
        }
        for (approval_id, approval) in &state.app_approvals {
            records.push(PersistedBootstrapRecord {
                kind: PersistedBootstrapKind::PendingApp,
                approval_id: *approval_id,
                bootstrap_id: None,
                core_identity: Some(approval.core_identity),
                app_csr_digest: approval.app_csr_digest,
                core_binding_digest: approval.core_binding_digest,
                normalized_session: approval.normalized_session.clone(),
                configuration_generation: approval.configuration_generation,
                confirmed: false,
                workspace_id: Some(approval.workspace_id.clone()),
                expires_at_epoch_seconds: approval.expires_at_epoch_seconds,
                hard_expires_at_epoch_seconds: None,
                certificate_chain: None,
                not_after_epoch_seconds: None,
            });
        }
        for approval in state.core_approvals.values() {
            records.push(PersistedBootstrapRecord {
                kind: PersistedBootstrapKind::CoreIssued,
                approval_id: approval.issued.approval_id,
                bootstrap_id: None,
                core_identity: Some(approval.core_identity),
                app_csr_digest: approval.app_csr_digest,
                core_binding_digest: approval.core_binding_digest,
                normalized_session: approval.normalized_session.clone(),
                configuration_generation: approval.configuration_generation,
                confirmed: approval.confirmed,
                workspace_id: None,
                expires_at_epoch_seconds: approval.recovery_expires_at_epoch_seconds,
                hard_expires_at_epoch_seconds: None,
                certificate_chain: Some(approval.issued.certificate_chain.clone()),
                not_after_epoch_seconds: Some(approval.issued.not_after_epoch_seconds),
            });
        }
        if records.len() > MAX_APPROVALS {
            return Err(RelayError::ResourceLimit);
        }
        let bytes = serde_json::to_vec(&PersistedBootstrapFile { records })
            .map_err(|_| RelayError::ConfigurationRead)?;
        if bytes.len() > 256 * 1024 {
            return Err(RelayError::ResourceLimit);
        }
        if state.attempts.is_empty()
            && state.app_approvals.is_empty()
            && state.core_approvals.is_empty()
        {
            if self.path.exists() {
                std::fs::remove_file(&self.path).map_err(|_| RelayError::ConfigurationRead)?;
            }
            return Ok(());
        }
        write_protected_file(
            &self.path,
            self.expected_uid,
            &bytes,
            ProtectedFileKind::Private,
            256 * 1024,
        )
    }

    /// Restore Core approvals and cleanup-only workspace identities after a Relay restart.
    fn restore(&self, state: &mut BootstrapState) -> RelayResult<()> {
        let file = self.load()?;
        for record in file.records {
            match record.kind {
                PersistedBootstrapKind::CoreIssued => {
                    let (Some(core_identity), Some(chain), Some(not_after)) = (
                        record.core_identity,
                        record.certificate_chain,
                        record.not_after_epoch_seconds,
                    ) else {
                        return Err(RelayError::ConfigurationRead);
                    };
                    let issued = CoreIssuedMaterial {
                        approval_id: record.approval_id,
                        core_identity,
                        certificate_chain: chain,
                        not_after_epoch_seconds: not_after,
                    };
                    state.core_approvals.insert(
                        record.approval_id,
                        CoreApproval {
                            core_identity,
                            app_csr_digest: record.app_csr_digest,
                            core_binding_digest: record.core_binding_digest,
                            normalized_session: record.normalized_session,
                            configuration_generation: record.configuration_generation,
                            confirmed: record.confirmed,
                            recovery_expires_at_epoch_seconds: record.expires_at_epoch_seconds,
                            issued,
                        },
                    );
                }
                PersistedBootstrapKind::PendingBootstrap | PersistedBootstrapKind::PendingApp => {
                    let Some(workspace_id) = record.workspace_id else {
                        return Err(RelayError::ConfigurationRead);
                    };
                    state
                        .orphaned_workspaces
                        .push((record.normalized_session, workspace_id));
                }
            }
        }
        Ok(())
    }

    /// Acquire the sidecar lock for one state-file operation.
    fn lock_file(&self) -> RelayResult<BootstrapStateLock> {
        let parent = self.path.parent().ok_or(RelayError::ConfigurationRead)?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(RelayError::ConfigurationRead)?;
        let lock_path = parent.join(format!(".{name}.lock"));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)
            .map_err(|_| RelayError::ConfigurationRead)?;
        file.try_lock_exclusive()
            .map_err(|_| RelayError::ConfigurationRead)?;
        Ok(BootstrapStateLock { file })
    }
}

/// Validate one persisted record before it can influence cleanup or certificate authority.
fn valid_persisted_record(record: &PersistedBootstrapRecord) -> bool {
    record.approval_id != [0; 32]
        && record.app_csr_digest != [0; 32]
        && record.core_binding_digest != [0; 32]
        && is_valid_session(&record.normalized_session)
        && record.configuration_generation != 0
        && match record.kind {
            PersistedBootstrapKind::PendingBootstrap => {
                record.bootstrap_id.is_some()
                    && record
                        .workspace_id
                        .as_ref()
                        .is_some_and(|id| !id.is_empty() && id.len() <= WORKSPACE_ID_MAX_BYTES)
                    && record.hard_expires_at_epoch_seconds.is_some()
                    && record.certificate_chain.is_none()
            }
            PersistedBootstrapKind::PendingApp => {
                record.core_identity.is_some()
                    && record
                        .workspace_id
                        .as_ref()
                        .is_some_and(|id| !id.is_empty() && id.len() <= WORKSPACE_ID_MAX_BYTES)
                    && record.certificate_chain.is_none()
            }
            PersistedBootstrapKind::CoreIssued => {
                record.core_identity.is_some()
                    && record.workspace_id.is_none()
                    && record.certificate_chain.as_ref().is_some_and(|chain| {
                        !chain.is_empty()
                            && chain.len() <= 8
                            && chain.iter().map(Vec::len).sum::<usize>() <= 46 * 1024
                    })
                    && record
                        .not_after_epoch_seconds
                        .is_some_and(|value| value != 0)
                    && if record.confirmed {
                        record.expires_at_epoch_seconds == 0
                    } else {
                        record.expires_at_epoch_seconds != 0
                    }
            }
        }
}

#[derive(Clone)]
pub(crate) struct BootstrapRuntime {
    /// Shared attempt and approval state.
    state: Arc<Mutex<BootstrapState>>,
    /// Fixed hidden-workspace verifier.
    workspace: HerdrWorkspaceClient,
    /// Relay protected certificate configuration.
    security: crate::config::SecurityConfig,
    /// UID required for protected material reads.
    expected_uid: u32,
    /// Restart-surviving non-secret bootstrap state.
    store: BootstrapStateStore,
}

impl fmt::Debug for BootstrapRuntime {
    /// Reports only bounded state presence and fixed operation scope.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapRuntime")
            .field("state_present", &true)
            .field("workspace_verifier_present", &true)
            .field("security_material_present", &true)
            .finish()
    }
}

impl BootstrapRuntime {
    /// Construct the production verifier from the explicit Relay configuration.
    pub(crate) fn new(config: &RelayConfig, expected_uid: u32) -> RelayResult<Self> {
        if !config.enrollment().enabled() {
            return Err(RelayError::InvalidConfiguration {
                field: "enrollment.enabled",
                reason: "bootstrap requires enrollment to be enabled",
            });
        }
        let session = config.enrollment().bootstrap_session().to_owned();
        let socket_path = session_socket_path(&session);
        let workspace = HerdrWorkspaceClient::new(
            socket_path,
            expected_uid,
            config.enrollment().bootstrap_verification_cwd().to_owned(),
            session,
        )
        .map_err(|_| RelayError::InvalidConfiguration {
            field: "enrollment.bootstrap_verification_cwd",
            reason: "bootstrap workspace configuration is invalid",
        })?;
        let store =
            BootstrapStateStore::open(config.enrollment().bootstrap_state_path(), expected_uid)?;
        let mut state = BootstrapState::default();
        store.restore(&mut state)?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            workspace,
            security: config.security().clone(),
            expected_uid,
            store,
        })
    }

    /// Start one HDB1 attempt and create/read back the hidden verification workspace.
    pub(crate) async fn start(
        &self,
        peer_ip: IpAddr,
        payload: Hdb1StartPayload,
    ) -> Result<BootstrapChallenge, BootstrapRuntimeError> {
        let (
            _,
            core_csr,
            app_csr_digest,
            normalized_session,
            core_binding_digest,
            configuration_generation,
        ) = payload
            .decode_fields()
            .map_err(|_| BootstrapRuntimeError::InvalidField)?;
        if normalized_session != self.workspace.normalized_session
            || core_csr.len() > HDB1_MAX_CSR_BYTES
            || app_csr_digest == [0; HDB1_DIGEST_BYTES]
            || core_binding_digest == [0; HDB1_DIGEST_BYTES]
            || configuration_generation == 0
        {
            return Err(BootstrapRuntimeError::AuthorityMismatch);
        }
        let now = pki::current_epoch_seconds()
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        let mut state = self.state.lock().await;
        let core_approvals_expired = reap_expired_core_approvals(&mut state, now);
        let mut workspaces = std::mem::take(&mut state.orphaned_workspaces);
        workspaces.extend(reap_expired_state(&mut state, now));
        for (_, workspace_id) in &workspaces {
            if self.workspace.close(workspace_id).await.is_err() {
                state.orphaned_workspaces = workspaces;
                return Err(BootstrapRuntimeError::WorkspaceUnavailable);
            }
        }
        if !workspaces.is_empty() || core_approvals_expired {
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
        }
        if state.attempts.len() >= MAX_ACTIVE_BOOTSTRAPS
            || state.core_approvals.len() + state.app_approvals.len() >= MAX_APPROVALS
        {
            return Err(BootstrapRuntimeError::CapacityExhausted);
        }
        if state.active_sessions.contains(&normalized_session) {
            return Err(BootstrapRuntimeError::AlreadyActive);
        }
        // Prune every expired peer bucket before admitting a new unauthenticated Start so an
        // internet-facing server cannot retain one stale map entry per historical source IP.
        state.peer_starts.retain(|_, history| {
            history.retain(|timestamp| now.saturating_sub(*timestamp) < PEER_START_WINDOW_SECS);
            !history.is_empty()
        });
        let peer_history = state.peer_starts.entry(peer_ip).or_default();
        if peer_history.len() >= MAX_PEER_STARTS {
            return Err(BootstrapRuntimeError::PeerRateLimited);
        }
        peer_history.push(now);
        let bootstrap_id = mint_id(&state);
        let approval_id = mint_id(&state);
        let challenge = mint_id(&state);
        let code = random_code();
        let expires_at = now
            .checked_add(BOOTSTRAP_CODE_TTL_SECS)
            .ok_or(BootstrapRuntimeError::InvalidField)?;
        let hard_expires_at = now
            .checked_add(BOOTSTRAP_HARD_LIFETIME_SECS)
            .ok_or(BootstrapRuntimeError::InvalidField)?;
        let title = verification_title(code, expires_at)?;
        let workspace_id = self.workspace.create_and_verify(&title).await?;
        let cleanup_workspace_id = workspace_id.clone();
        state.active_sessions.insert(normalized_session.clone());
        state.attempts.insert(
            bootstrap_id,
            BootstrapAttempt {
                peer_ip,
                approval_id,
                challenge,
                code,
                core_csr,
                app_csr_digest,
                core_binding_digest,
                normalized_session: normalized_session.clone(),
                configuration_generation,
                workspace_id,
                expires_at_epoch_seconds: expires_at,
                hard_expires_at_epoch_seconds: hard_expires_at,
                failed_codes: 0,
            },
        );
        if self.store.persist(&state).is_err() {
            state.active_sessions.remove(&normalized_session);
            state.attempts.remove(&bootstrap_id);
            let _ = self.workspace.close(&cleanup_workspace_id).await;
            return Err(BootstrapRuntimeError::PersistenceFailed);
        }
        Ok(BootstrapChallenge {
            bootstrap_id,
            challenge,
            expires_at_epoch_seconds: expires_at,
        })
    }

    /// Abort one HDB1 attempt when challenge delivery cannot complete.
    ///
    /// # Parameters
    /// * `bootstrap_id` - In-memory attempt whose hidden workspace must be cleaned.
    ///
    /// # Returns
    /// `Ok(())` after the attempt is removed and cleanup is requested, or a sanitized cleanup or
    /// persistence error. The method never exposes the code, workspace title or CSR.
    // TEST:relay/src/bootstrap_runtime.rs[tests::production_challenge_abort_cleans_attempt]
    pub(crate) async fn abort(
        &self,
        bootstrap_id: [u8; HDB1_ID_BYTES],
    ) -> Result<(), BootstrapRuntimeError> {
        let mut state = self.state.lock().await;
        let Some(attempt) = state.attempts.remove(&bootstrap_id) else {
            return Ok(());
        };
        let session = attempt.normalized_session.clone();
        let workspace_id = attempt.workspace_id.clone();
        state.active_sessions.remove(&session);
        let cleanup_failed = self.workspace.close(&workspace_id).await.is_err();
        if cleanup_failed {
            state.orphaned_workspaces.push((session, workspace_id));
        }
        self.store
            .persist(&state)
            .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
        if cleanup_failed {
            return Err(BootstrapRuntimeError::WorkspaceUnavailable);
        }
        Ok(())
    }

    /// Verify one HDB1 code, close the workspace and issue one Core certificate.
    ///
    /// # Parameters
    /// * `peer_ip` - Relay-observed peer IP that must match the Start connection.
    /// * `bootstrap_id` - Active HDB1 attempt identifier.
    /// * `challenge` - Challenge returned by the matching Start connection.
    /// * `code` - User-entered six-digit verification code.
    ///
    /// # Returns
    /// Public Core certificate metadata or a sanitized bounded failure.
    // TEST:relay/src/bootstrap_runtime.rs[tests::production_submit_enforces_code_limit]
    pub(crate) async fn submit(
        &self,
        peer_ip: IpAddr,
        bootstrap_id: [u8; HDB1_ID_BYTES],
        challenge: [u8; HDB1_DIGEST_BYTES],
        code: &str,
    ) -> Result<CoreIssuedMaterial, BootstrapRuntimeError> {
        let supplied = parse_code(code)?;
        let now = pki::current_epoch_seconds()
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        let mut state = self.state.lock().await;
        let attempt = state
            .attempts
            .get_mut(&bootstrap_id)
            .ok_or(BootstrapRuntimeError::NotFound)?;
        if attempt.peer_ip != peer_ip || attempt.challenge != challenge {
            return Err(BootstrapRuntimeError::AuthorityMismatch);
        }
        if now > attempt.expires_at_epoch_seconds || now > attempt.hard_expires_at_epoch_seconds {
            let workspace_id = attempt.workspace_id.clone();
            let session = attempt.normalized_session.clone();
            let close = self.workspace.close(&workspace_id).await;
            if close.is_err() {
                return Err(BootstrapRuntimeError::WorkspaceUnavailable);
            }
            state.active_sessions.remove(&session);
            state.attempts.remove(&bootstrap_id);
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
            return Err(BootstrapRuntimeError::Expired);
        }
        if !constant_time_equal(&attempt.code, &supplied) {
            attempt.failed_codes = attempt.failed_codes.saturating_add(1);
            if attempt.failed_codes >= MAX_CODE_FAILURES {
                let workspace_id = attempt.workspace_id.clone();
                let session = attempt.normalized_session.clone();
                let close = self.workspace.close(&workspace_id).await;
                if close.is_err() {
                    return Err(BootstrapRuntimeError::WorkspaceUnavailable);
                }
                state.active_sessions.remove(&session);
                state.attempts.remove(&bootstrap_id);
                self.store
                    .persist(&state)
                    .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
                return Err(BootstrapRuntimeError::CodeRateLimited);
            }
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
            return Err(BootstrapRuntimeError::CodeMismatch);
        }
        let workspace_id = attempt.workspace_id.clone();
        let session = attempt.normalized_session.clone();
        let approval_id = attempt.approval_id;
        let app_csr_digest = attempt.app_csr_digest;
        let core_binding_digest = attempt.core_binding_digest;
        let normalized_session = attempt.normalized_session.clone();
        let configuration_generation = attempt.configuration_generation;
        let core_csr = attempt.core_csr.clone();
        let close = self.workspace.close(&workspace_id).await;
        if close.is_err() {
            return Err(BootstrapRuntimeError::WorkspaceUnavailable);
        }
        state.active_sessions.remove(&session);
        state.attempts.remove(&bootstrap_id);
        let issued = pki::issue_core_certificate(&self.security, self.expected_uid, &core_csr)
            .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
        let recovery_expires_at_epoch_seconds = now
            .checked_add(CORE_APPROVAL_RECOVERY_TTL_SECS)
            .ok_or(BootstrapRuntimeError::InvalidField)?;
        let core_identity = issued.app_identity();
        let material = CoreIssuedMaterial {
            approval_id,
            core_identity,
            certificate_chain: issued.certificate_chain(),
            not_after_epoch_seconds: issued.not_after_epoch_seconds(),
        };
        state.core_approvals.insert(
            approval_id,
            CoreApproval {
                core_identity,
                app_csr_digest,
                core_binding_digest,
                normalized_session,
                configuration_generation,
                confirmed: false,
                recovery_expires_at_epoch_seconds,
                issued: material.clone(),
            },
        );
        self.store
            .persist(&state)
            .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
        Ok(material)
    }

    /// Reconcile an issued Core certificate using the exact HDB1 binding subset.
    pub(crate) async fn reconcile(
        &self,
        approval_id: [u8; HDB1_ID_BYTES],
        core_binding_digest: [u8; HDB1_DIGEST_BYTES],
        normalized_session: &str,
    ) -> Result<CoreIssuedMaterial, BootstrapRuntimeError> {
        let now = pki::current_epoch_seconds()
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        let mut state = self.state.lock().await;
        let core_approvals_expired = reap_expired_core_approvals(&mut state, now);
        let mut workspaces = std::mem::take(&mut state.orphaned_workspaces);
        workspaces.extend(reap_expired_state(&mut state, now));
        for (_, workspace_id) in &workspaces {
            if self.workspace.close(workspace_id).await.is_err() {
                state.orphaned_workspaces = workspaces;
                return Err(BootstrapRuntimeError::WorkspaceUnavailable);
            }
        }
        if !workspaces.is_empty() || core_approvals_expired {
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
        }
        let approval = state
            .core_approvals
            .get(&approval_id)
            .ok_or(BootstrapRuntimeError::NotFound)?;
        if approval.core_binding_digest != core_binding_digest
            || approval.normalized_session != normalized_session
        {
            return Err(BootstrapRuntimeError::AuthorityMismatch);
        }
        Ok(approval.issued.clone())
    }

    /// Verify that a Core identity owns the exact bootstrap approval for its first App CSR.
    pub(crate) async fn authorize_first_app(
        &self,
        core_identity: [u8; HDB1_DIGEST_BYTES],
        approval_id: [u8; HDB1_ID_BYTES],
        app_csr_digest: [u8; HDB1_DIGEST_BYTES],
    ) -> Result<u64, BootstrapRuntimeError> {
        let now = pki::current_epoch_seconds()
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        let mut state = self.state.lock().await;
        let expired = state
            .core_approvals
            .get(&approval_id)
            .is_some_and(|approval| {
                !approval.confirmed && now > approval.recovery_expires_at_epoch_seconds
            });
        if expired {
            // Remove an unconfirmed approval before returning so it cannot authorize after TTL.
            state.core_approvals.remove(&approval_id);
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
            return Err(BootstrapRuntimeError::Expired);
        }
        let approval = state
            .core_approvals
            .get(&approval_id)
            .ok_or(BootstrapRuntimeError::NotFound)?;
        if approval.confirmed
            || approval.core_identity != core_identity
            || approval.app_csr_digest != app_csr_digest
        {
            return Err(BootstrapRuntimeError::AuthorityMismatch);
        }
        Ok(approval.configuration_generation)
    }

    /// Mark the first App certificate active after the App confirms protected persistence.
    ///
    /// # Parameters
    /// * `core_identity` - Core-enrollment certificate identity authenticated by HDE3.
    /// * `approval_id` - First-App approval identifier.
    /// * `app_csr_digest` - Exact CSR digest retained by HDB1.
    /// * `configuration_generation` - Core-owned generation retained by HDB1.
    ///
    /// # Returns
    /// `Ok(())` after the first Core approval is durably active, or a sanitized authority error.
    pub(crate) async fn confirm_first_app(
        &self,
        core_identity: [u8; HDB1_DIGEST_BYTES],
        approval_id: [u8; HDB1_ID_BYTES],
        app_csr_digest: [u8; HDB1_DIGEST_BYTES],
        configuration_generation: u64,
    ) -> Result<(), BootstrapRuntimeError> {
        let now = pki::current_epoch_seconds()
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        let mut state = self.state.lock().await;
        let expired = state
            .core_approvals
            .get(&approval_id)
            .is_some_and(|approval| {
                !approval.confirmed && now > approval.recovery_expires_at_epoch_seconds
            });
        if expired {
            // Expired unconfirmed material cannot be promoted after its recovery window.
            state.core_approvals.remove(&approval_id);
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
            return Err(BootstrapRuntimeError::Expired);
        }
        let approval = state
            .core_approvals
            .get_mut(&approval_id)
            .ok_or(BootstrapRuntimeError::NotFound)?;
        if approval.core_identity != core_identity
            || approval.app_csr_digest != app_csr_digest
            || approval.configuration_generation != configuration_generation
        {
            return Err(BootstrapRuntimeError::AuthorityMismatch);
        }
        if !approval.confirmed {
            // Keep the Core approval pending until the matching App certificate is durably stored.
            approval.confirmed = true;
            approval.recovery_expires_at_epoch_seconds = 0;
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
        }
        Ok(())
    }

    /// Start a later App approval using the same fixed hidden workspace verifier.
    pub(crate) async fn start_app_approval(
        &self,
        core_identity: [u8; HDB1_DIGEST_BYTES],
        app_csr_digest: [u8; HDB1_DIGEST_BYTES],
        core_binding_digest: [u8; HDB1_DIGEST_BYTES],
        normalized_session: String,
        configuration_generation: u64,
    ) -> Result<AppApprovalChallenge, BootstrapRuntimeError> {
        if !is_valid_session(&normalized_session)
            || normalized_session != self.workspace.normalized_session
            || app_csr_digest == [0; HDB1_DIGEST_BYTES]
            || core_binding_digest == [0; HDB1_DIGEST_BYTES]
            || configuration_generation == 0
        {
            return Err(BootstrapRuntimeError::InvalidField);
        }
        let now = pki::current_epoch_seconds()
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        let mut state = self.state.lock().await;
        let core_approvals_expired = reap_expired_core_approvals(&mut state, now);
        let mut workspaces = std::mem::take(&mut state.orphaned_workspaces);
        workspaces.extend(reap_expired_state(&mut state, now));
        for (_, workspace_id) in &workspaces {
            if self.workspace.close(workspace_id).await.is_err() {
                state.orphaned_workspaces = workspaces;
                return Err(BootstrapRuntimeError::WorkspaceUnavailable);
            }
        }
        if !workspaces.is_empty() || core_approvals_expired {
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
        }
        let core_approved = state.core_approvals.values().any(|approval| {
            approval.core_identity == core_identity
                && approval.core_binding_digest == core_binding_digest
                && approval.normalized_session == normalized_session
                && approval.configuration_generation == configuration_generation
                && approval.confirmed
        });
        if !core_approved {
            return Err(BootstrapRuntimeError::AuthorityMismatch);
        }
        if state.active_sessions.contains(&normalized_session) {
            return Err(BootstrapRuntimeError::AlreadyActive);
        }
        if state.app_approvals.len() >= MAX_APPROVALS {
            return Err(BootstrapRuntimeError::CapacityExhausted);
        }
        let approval_id = mint_id(&state);
        let challenge = mint_id(&state);
        let code = random_code();
        let expires_at = now
            .checked_add(BOOTSTRAP_CODE_TTL_SECS)
            .ok_or(BootstrapRuntimeError::InvalidField)?;
        let title = verification_title(code, expires_at)?;
        let workspace_id = self.workspace.create_and_verify(&title).await?;
        let cleanup_workspace_id = workspace_id.clone();
        state.active_sessions.insert(normalized_session.clone());
        state.app_approvals.insert(
            approval_id,
            AppApproval {
                core_identity,
                app_csr_digest,
                core_binding_digest,
                normalized_session: normalized_session.clone(),
                configuration_generation,
                challenge,
                code,
                workspace_id,
                expires_at_epoch_seconds: expires_at,
                failed_codes: 0,
            },
        );
        if self.store.persist(&state).is_err() {
            state.active_sessions.remove(&normalized_session);
            state.app_approvals.remove(&approval_id);
            let _ = self.workspace.close(&cleanup_workspace_id).await;
            return Err(BootstrapRuntimeError::PersistenceFailed);
        }
        Ok(AppApprovalChallenge {
            approval_id,
            challenge,
            expires_at_epoch_seconds: expires_at,
        })
    }

    /// Verify a later App code and return its transient CSR context after cleanup.
    ///
    /// # Parameters
    /// * `core_identity` - Authenticated HDE3 Core identity that started the approval.
    /// * `approval_id` - Relay approval identifier bound to the challenge.
    /// * `challenge` - Challenge returned by the matching ApprovalStart.
    /// * `code` - User-entered six-digit verification code.
    /// * `app_csr` - Transient public App CSR used for issuance.
    /// * `app_csr_digest` - Digest of the exact App CSR bytes.
    ///
    /// # Returns
    /// The exact approved CSR context or a sanitized bounded failure.
    pub(crate) async fn submit_app_approval(
        &self,
        core_identity: [u8; HDB1_DIGEST_BYTES],
        approval_id: [u8; HDB1_ID_BYTES],
        challenge: [u8; HDB1_DIGEST_BYTES],
        code: &str,
        app_csr: Vec<u8>,
        app_csr_digest: [u8; HDB1_DIGEST_BYTES],
    ) -> Result<AppApprovalContext, BootstrapRuntimeError> {
        if app_csr.is_empty()
            || app_csr.len() > HDE3_MAX_CSR_BYTES
            || digest(&app_csr) != app_csr_digest
        {
            return Err(BootstrapRuntimeError::InvalidField);
        }
        let supplied = parse_code(code)?;
        let now = pki::current_epoch_seconds()
            .map_err(|_| BootstrapRuntimeError::WorkspaceUnavailable)?;
        let mut state = self.state.lock().await;
        let approval = state
            .app_approvals
            .get_mut(&approval_id)
            .ok_or(BootstrapRuntimeError::NotFound)?;
        if approval.core_identity != core_identity
            || approval.challenge != challenge
            || approval.app_csr_digest != app_csr_digest
        {
            return Err(BootstrapRuntimeError::AuthorityMismatch);
        }
        if now > approval.expires_at_epoch_seconds {
            let workspace_id = approval.workspace_id.clone();
            let session = approval.normalized_session.clone();
            let close = self.workspace.close(&workspace_id).await;
            if close.is_err() {
                return Err(BootstrapRuntimeError::WorkspaceUnavailable);
            }
            state.active_sessions.remove(&session);
            state.app_approvals.remove(&approval_id);
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
            return Err(BootstrapRuntimeError::Expired);
        }
        if !constant_time_equal(&approval.code, &supplied) {
            approval.failed_codes = approval.failed_codes.saturating_add(1);
            if approval.failed_codes >= MAX_CODE_FAILURES {
                let workspace_id = approval.workspace_id.clone();
                let session = approval.normalized_session.clone();
                let close = self.workspace.close(&workspace_id).await;
                if close.is_err() {
                    return Err(BootstrapRuntimeError::WorkspaceUnavailable);
                }
                state.active_sessions.remove(&session);
                state.app_approvals.remove(&approval_id);
                self.store
                    .persist(&state)
                    .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
                return Err(BootstrapRuntimeError::CodeRateLimited);
            }
            self.store
                .persist(&state)
                .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
            return Err(BootstrapRuntimeError::CodeMismatch);
        }
        let workspace_id = approval.workspace_id.clone();
        let context = AppApprovalContext {
            approval_id,
            core_identity: approval.core_identity,
            app_csr,
            app_csr_digest,
            core_binding_digest: approval.core_binding_digest,
            normalized_session: approval.normalized_session.clone(),
            configuration_generation: approval.configuration_generation,
        };
        let session = approval.normalized_session.clone();
        let close = self.workspace.close(&workspace_id).await;
        if close.is_err() {
            return Err(BootstrapRuntimeError::WorkspaceUnavailable);
        }
        state.active_sessions.remove(&session);
        state.app_approvals.remove(&approval_id);
        self.store
            .persist(&state)
            .map_err(|_| BootstrapRuntimeError::PersistenceFailed)?;
        Ok(context)
    }
}

/// Build the platform-neutral Herdr socket path for the selected session.
fn session_socket_path(session: &str) -> PathBuf {
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("herdr");
    if session == "default" {
        root.join("herdr.sock")
    } else {
        root.join("sessions").join(session).join("herdr.sock")
    }
}

/// Reap unconfirmed Core approvals whose 24-hour recovery window elapsed.
fn reap_expired_core_approvals(state: &mut BootstrapState, now: u64) -> bool {
    let expired_approvals: Vec<_> = state
        .core_approvals
        .iter()
        .filter_map(|(id, approval)| {
            (!approval.confirmed
                && approval.recovery_expires_at_epoch_seconds != 0
                && now > approval.recovery_expires_at_epoch_seconds)
                .then_some(*id)
        })
        .collect();
    for id in &expired_approvals {
        state.core_approvals.remove(id);
    }
    !expired_approvals.is_empty()
}

/// Reap expired process-local attempts before admitting new work.
fn reap_expired_state(state: &mut BootstrapState, now: u64) -> Vec<(String, String)> {
    let mut workspaces = Vec::new();
    let expired_attempts: Vec<_> = state
        .attempts
        .iter()
        .filter_map(|(id, attempt)| (now > attempt.hard_expires_at_epoch_seconds).then_some(*id))
        .collect();
    for id in expired_attempts {
        if let Some(attempt) = state.attempts.remove(&id) {
            state.active_sessions.remove(&attempt.normalized_session);
            workspaces.push((attempt.normalized_session, attempt.workspace_id));
        }
    }
    let expired_approvals: Vec<_> = state
        .app_approvals
        .iter()
        .filter_map(|(id, approval)| (now > approval.expires_at_epoch_seconds).then_some(*id))
        .collect();
    for id in expired_approvals {
        if let Some(approval) = state.app_approvals.remove(&id) {
            state.active_sessions.remove(&approval.normalized_session);
            workspaces.push((approval.normalized_session, approval.workspace_id));
        }
    }
    workspaces
}

/// Mint one non-zero cryptographically random identifier not currently retained in state.
fn mint_id(state: &BootstrapState) -> [u8; 32] {
    loop {
        let value = rand::random::<[u8; 32]>();
        if value != [0; 32]
            && !state.attempts.contains_key(&value)
            && !state.core_approvals.contains_key(&value)
            && !state.app_approvals.contains_key(&value)
        {
            return value;
        }
    }
}

/// Generate a uniformly distributed six-digit code without exposing it in diagnostics.
fn random_code() -> [u8; 6] {
    const CODE_RANGE: u32 = 900_000;
    // Reject the incomplete final range so every six-digit value has equal probability.
    let sample = loop {
        let value = rand::random::<u32>();
        let acceptance_limit = u32::MAX - (u32::MAX % CODE_RANGE);
        if value < acceptance_limit {
            break value;
        }
    };
    let value = 100_000 + (sample % CODE_RANGE);
    let text = format!("{value:06}");
    let mut code = [0_u8; 6];
    code.copy_from_slice(text.as_bytes());
    code
}

/// Format the user-visible code-first title with the Relay host's local UTC offset.
fn verification_title(
    code: [u8; 6],
    expires_at_epoch_seconds: u64,
) -> Result<String, BootstrapRuntimeError> {
    let timestamp =
        i64::try_from(expires_at_epoch_seconds).map_err(|_| BootstrapRuntimeError::InvalidField)?;
    let local_offset =
        time::UtcOffset::current_local_offset().map_err(|_| BootstrapRuntimeError::InvalidField)?;
    let datetime = time::OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| BootstrapRuntimeError::InvalidField)?
        .to_offset(local_offset);
    let format = time::format_description::parse_borrowed::<2>(
        "[year]-[month]-[day]T[hour]:[minute]:[second][offset_hour sign:mandatory]:[offset_minute]",
    )
    .map_err(|_| BootstrapRuntimeError::InvalidField)?;
    let expiry = datetime
        .format(&format)
        .map_err(|_| BootstrapRuntimeError::InvalidField)?;
    let code = std::str::from_utf8(&code).map_err(|_| BootstrapRuntimeError::InvalidField)?;
    Ok(format!(
        "{code} (expires {expiry}) - herdr-dog verification"
    ))
}

/// Parse exactly six ASCII digits into a fixed-width value.
fn parse_code(value: &str) -> Result<[u8; 6], BootstrapRuntimeError> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BootstrapRuntimeError::InvalidField);
    }
    let mut result = [0_u8; 6];
    result.copy_from_slice(value.as_bytes());
    Ok(result)
}

/// Compare two six-digit codes without early exit on a mismatch.
fn constant_time_equal(left: &[u8; 6], right: &[u8; 6]) -> bool {
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Validate the source-aligned normalized Herdr session name.
fn is_valid_session(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= HDB1_MAX_SESSION_BYTES
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Hash one transient CSR before it is retained only for a single immediate operation.
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::{io::AsyncWriteExt, net::UnixListener};

    /// Create a unique owner-only directory for production bootstrap runtime tests.
    fn test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let temp_root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let prefix = format!("herdr-dog-bootstrap-runtime-{}-{nonce}", std::process::id());
        // Exclusive creation with retries prevents concurrent cargo test processes from colliding.
        for attempt in 0..32 {
            let root = temp_root.join(format!("{prefix}-{attempt}"));
            match fs::create_dir(&root) {
                Ok(()) => {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                        .expect("test root mode");
                    return root;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("test root: {error}"),
            }
        }
        panic!("test root: could not allocate unique directory");
    }

    /// Build a production-shaped runtime with injected test socket and protected state paths.
    fn test_runtime(root: &Path, socket_path: PathBuf) -> BootstrapRuntime {
        let uid = crate::material::current_uid().expect("uid");
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport=18743\n[security]\nmode=\"verified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\ntrusted_core_enrollment_ca=\"{}\"\ncore_enrollment_intermediate_certificate=\"{}\"\ncore_enrollment_intermediate_private_key=\"{}\"\ndevice_intermediate_certificate=\"{}\"\ndevice_intermediate_private_key=\"{}\"\npublic_root_certificate=\"{}\"\n[enrollment]\nenabled=true\nallowlist_path=\"{}\"\nissuance_result_path=\"{}\"\nbootstrap_state_path=\"{}\"\nbootstrap_session=\"default\"\nbootstrap_verification_cwd=\"/tmp\"\n[limits]\nmax_connections=8\nmax_sessions_per_connection=8\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            root.join("server.pem").display(),
            root.join("server.key").display(),
            root.join("client-ca.pem").display(),
            root.join("core-ca.pem").display(),
            root.join("core-intermediate.pem").display(),
            root.join("core-intermediate.key").display(),
            root.join("device-intermediate.pem").display(),
            root.join("device-intermediate.key").display(),
            root.join("root.pem").display(),
            root.join("allowlist.json").display(),
            root.join("issuance.json").display(),
            root.join("bootstrap-state.json").display(),
        ))
        .expect("production-shaped config");
        let workspace =
            HerdrWorkspaceClient::new(socket_path, uid, "/tmp".to_owned(), "default".to_owned())
                .expect("workspace client");
        let store = BootstrapStateStore::open(root.join("bootstrap-state.json"), uid)
            .expect("bootstrap state store");
        BootstrapRuntime {
            state: Arc::new(Mutex::new(BootstrapState::default())),
            workspace,
            security: config.security().clone(),
            expected_uid: uid,
            store,
        }
    }

    /// Serve the exact create/get/close response sequence consumed by one runtime attempt.
    fn spawn_workspace_server(socket_path: PathBuf) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&socket_path).expect("workspace socket");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .expect("workspace socket mode");
        tokio::spawn(async move {
            let mut title = String::new();
            for expected_method in ["workspace.create", "workspace.get", "workspace.close"] {
                let (mut stream, _) = listener.accept().await.expect("workspace accept");
                let request = read_json_line(&mut stream)
                    .await
                    .expect("workspace request");
                let id = request["id"].as_str().expect("request id");
                let method = request["method"].as_str().expect("request method");
                assert_eq!(method, expected_method);
                let response = match method {
                    "workspace.create" => {
                        title = request["params"]["label"]
                            .as_str()
                            .expect("workspace title")
                            .to_owned();
                        json!({
                            "id": id,
                            "result": {"workspace": {"workspace_id": "test-workspace"}}
                        })
                    }
                    "workspace.get" => json!({
                        "id": id,
                        "result": {
                            "workspace": {"workspace_id": "test-workspace", "label": title}
                        }
                    }),
                    "workspace.close" => json!({"id": id, "result": {"type": "ok"}}),
                    _ => unreachable!("fixed workspace method list"),
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

    /// Build a bounded HDB1 Start payload for runtime-level admission tests.
    fn test_start_payload(session: &str) -> Hdb1StartPayload {
        Hdb1StartPayload::new(
            [1; 16],
            &[1, 2, 3],
            [2; HDB1_DIGEST_BYTES],
            session.to_owned(),
            [3; HDB1_DIGEST_BYTES],
            1,
        )
        .expect("start payload")
    }

    /// Verify production HDB1 rejects a session binding before opening the Herdr socket.
    // TEST:relay/src/bootstrap_runtime.rs[tests::production_start_rejects_binding_mismatch]
    #[tokio::test(flavor = "current_thread")]
    async fn production_start_rejects_binding_mismatch() {
        let root = test_root();
        let runtime = test_runtime(&root, root.join("missing.sock"));
        let result = runtime
            .start(
                "127.0.0.1".parse().expect("peer IP"),
                test_start_payload("other"),
            )
            .await;
        assert_eq!(result, Err(BootstrapRuntimeError::AuthorityMismatch));
        fs::remove_dir_all(root).expect("cleanup");
    }

    /// Verify production HDB1 persists bounded code failures and closes at the fixed limit.
    // TEST:relay/src/bootstrap_runtime.rs[tests::production_submit_enforces_code_limit]
    #[tokio::test(flavor = "current_thread")]
    async fn production_submit_enforces_code_limit() {
        let root = test_root();
        let socket_dir = PathBuf::from(format!(
            "/private/tmp/hbr-{}-{}",
            std::process::id(),
            root.file_name().expect("root name").to_string_lossy()
        ));
        fs::create_dir(&socket_dir).expect("workspace socket directory");
        fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o700))
            .expect("workspace socket directory mode");
        let socket_path = socket_dir.join("s");
        let workspace_task = spawn_workspace_server(socket_path.clone());
        let runtime = test_runtime(&root, socket_path);
        let challenge = runtime
            .start(
                "127.0.0.1".parse().expect("peer IP"),
                test_start_payload("default"),
            )
            .await
            .expect("start");
        let peer_mismatch = runtime
            .submit(
                "127.0.0.2".parse().expect("different peer IP"),
                challenge.bootstrap_id,
                challenge.challenge,
                "000000",
            )
            .await;
        assert_eq!(peer_mismatch, Err(BootstrapRuntimeError::AuthorityMismatch));
        for _ in 0..4 {
            assert_eq!(
                runtime
                    .submit(
                        "127.0.0.1".parse().expect("peer IP"),
                        challenge.bootstrap_id,
                        challenge.challenge,
                        "000000",
                    )
                    .await,
                Err(BootstrapRuntimeError::CodeMismatch)
            );
        }
        assert_eq!(
            runtime
                .submit(
                    "127.0.0.1".parse().expect("peer IP"),
                    challenge.bootstrap_id,
                    challenge.challenge,
                    "000000",
                )
                .await,
            Err(BootstrapRuntimeError::CodeRateLimited)
        );
        assert_eq!(
            runtime
                .submit(
                    "127.0.0.1".parse().expect("peer IP"),
                    challenge.bootstrap_id,
                    challenge.challenge,
                    "000000",
                )
                .await,
            Err(BootstrapRuntimeError::NotFound)
        );
        workspace_task.await.expect("workspace task");
        fs::remove_dir_all(socket_dir).expect("workspace socket directory cleanup");
        fs::remove_dir_all(root).expect("cleanup");
    }

    /// Verify challenge-delivery failure cleanup removes the active session and workspace.
    // TEST:relay/src/bootstrap_runtime.rs[tests::production_challenge_abort_cleans_attempt]
    #[tokio::test(flavor = "current_thread")]
    async fn production_challenge_abort_cleans_attempt() {
        let root = test_root();
        let socket_dir = PathBuf::from(format!(
            "/private/tmp/hbr-abort-{}-{}",
            std::process::id(),
            root.file_name().expect("root name").to_string_lossy()
        ));
        fs::create_dir(&socket_dir).expect("workspace socket directory");
        fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o700))
            .expect("workspace socket directory mode");
        let socket_path = socket_dir.join("s");
        let workspace_task = spawn_workspace_server(socket_path.clone());
        let runtime = test_runtime(&root, socket_path);
        let challenge = runtime
            .start(
                "127.0.0.1".parse().expect("peer IP"),
                test_start_payload("default"),
            )
            .await
            .expect("start");
        runtime.abort(challenge.bootstrap_id).await.expect("abort");
        assert_eq!(
            runtime
                .submit(
                    "127.0.0.1".parse().expect("peer IP"),
                    challenge.bootstrap_id,
                    challenge.challenge,
                    "000000",
                )
                .await,
            Err(BootstrapRuntimeError::NotFound)
        );
        workspace_task.await.expect("workspace task");
        fs::remove_dir_all(socket_dir).expect("workspace socket directory cleanup");
        fs::remove_dir_all(root).expect("cleanup");
    }

    /// Verify a resumed HDE3 approval cannot be submitted by another Core identity.
    // TEST:relay/src/bootstrap_runtime.rs[tests::production_app_approval_rejects_core_identity_mismatch]
    #[tokio::test(flavor = "current_thread")]
    async fn production_app_approval_rejects_core_identity_mismatch() {
        let root = test_root();
        let runtime = test_runtime(&root, root.join("missing.sock"));
        let approval_id = [1_u8; HDB1_ID_BYTES];
        let app_csr = vec![1_u8, 2, 3];
        let app_csr_digest = digest(&app_csr);
        runtime.state.lock().await.app_approvals.insert(
            approval_id,
            AppApproval {
                core_identity: [2; HDB1_DIGEST_BYTES],
                app_csr_digest,
                core_binding_digest: [3; HDB1_DIGEST_BYTES],
                normalized_session: "default".to_owned(),
                configuration_generation: 1,
                challenge: [4; HDB1_DIGEST_BYTES],
                code: *b"123456",
                workspace_id: "test-workspace".to_owned(),
                expires_at_epoch_seconds: u64::MAX,
                failed_codes: 0,
            },
        );
        let result = runtime
            .submit_app_approval(
                [9; HDB1_DIGEST_BYTES],
                approval_id,
                [4; HDB1_DIGEST_BYTES],
                "123456",
                app_csr,
                app_csr_digest,
            )
            .await;
        assert_eq!(result, Err(BootstrapRuntimeError::AuthorityMismatch));
        fs::remove_dir_all(root).expect("cleanup");
    }

    /// Verify the fixed code comparison does not change the accepted shape.
    // TEST:relay/src/bootstrap_runtime.rs[tests::code_parser_is_fixed_width]
    #[test]
    fn code_parser_is_fixed_width() {
        assert_eq!(parse_code("000001").expect("code"), *b"000001");
        assert!(parse_code("1").is_err());
        assert!(parse_code("１２３４５６").is_err());
    }

    /// Verify the hidden title contains the code but remains bounded and explicit about the local offset.
    // TEST:relay/src/bootstrap_runtime.rs[tests::verification_title_is_bounded]
    #[test]
    fn verification_title_is_bounded() {
        let title = verification_title(*b"123456", 300).expect("title");
        assert!(title.starts_with("123456 (expires "));
        assert!(title.ends_with(" - herdr-dog verification"));
        assert!(title.len() <= WORKSPACE_TITLE_MAX_BYTES);
    }

    /// Verify only unconfirmed Core approvals are removed after their recovery deadline.
    // TEST:relay/src/bootstrap_runtime.rs[tests::unconfirmed_core_approval_expiry_is_reaped]
    #[test]
    fn unconfirmed_core_approval_expiry_is_reaped() {
        let mut state = BootstrapState::default();
        let issued = CoreIssuedMaterial {
            approval_id: [1; 32],
            core_identity: [2; 32],
            certificate_chain: vec![vec![3; 8]],
            not_after_epoch_seconds: 10_000,
        };
        state.core_approvals.insert(
            [1; 32],
            CoreApproval {
                core_identity: [2; 32],
                app_csr_digest: [4; 32],
                core_binding_digest: [5; 32],
                normalized_session: "default".to_owned(),
                configuration_generation: 1,
                confirmed: false,
                recovery_expires_at_epoch_seconds: 100,
                issued,
            },
        );
        assert!(reap_expired_core_approvals(&mut state, 101));
        assert!(state.core_approvals.is_empty());

        state.core_approvals.insert(
            [6; 32],
            CoreApproval {
                core_identity: [7; 32],
                app_csr_digest: [8; 32],
                core_binding_digest: [9; 32],
                normalized_session: "default".to_owned(),
                configuration_generation: 1,
                confirmed: true,
                recovery_expires_at_epoch_seconds: 0,
                issued: CoreIssuedMaterial {
                    approval_id: [6; 32],
                    core_identity: [7; 32],
                    certificate_chain: vec![vec![10; 8]],
                    not_after_epoch_seconds: 10_000,
                },
            },
        );
        assert!(!reap_expired_core_approvals(&mut state, 101));
        assert!(state.core_approvals.contains_key(&[6; 32]));
    }

    /// Verify the fixed session grammar rejects path-like and non-ASCII values.
    // TEST:relay/src/bootstrap_runtime.rs[tests::session_validation_is_fail_closed]
    #[test]
    fn session_validation_is_fail_closed() {
        assert!(is_valid_session("default"));
        assert!(is_valid_session("qrm-work"));
        assert!(!is_valid_session("../escape"));
        assert!(!is_valid_session("."));
        assert!(!is_valid_session("中文"));
    }
}
