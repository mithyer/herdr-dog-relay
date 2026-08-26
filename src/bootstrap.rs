//! Schema-neutral Relay verifier for the frozen HDB1 first-bootstrap flow.
//!
//! The fake models the narrowly scoped hidden verification workspace and Core certificate issuance
//! boundary. It never exposes the workspace, title, marker, verification code, CSR bytes, private
//! keys, certificate bytes, or Herdr payloads to callers or diagnostics.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;

use sha2::{Digest, Sha256};

use crate::enrollment::CsrDigest;

/// Maximum transient Core CSR size accepted by HDB1 Start.
pub(crate) const MAX_BOOTSTRAP_CORE_CSR_BYTES: usize = crate::HDB1_MAX_CSR_BYTES;
/// Maximum normalized Herdr session name size.
pub(crate) const MAX_BOOTSTRAP_SESSION_BYTES: usize = crate::HDB1_MAX_SESSION_BYTES;
/// Maximum concurrent active bootstrap attempts on one Relay.
pub(crate) const MAX_ACTIVE_BOOTSTRAPS: usize = 8;
/// Maximum starts from one observed peer address during the rolling window.
pub(crate) const MAX_PEER_STARTS: usize = 3;
/// Peer start rate-limit window in epoch seconds.
pub(crate) const BOOTSTRAP_START_WINDOW_SECS: u64 = 900;
/// Maximum retained terminal/issued bootstrap records before fail-closed admission.
pub(crate) const MAX_RETAINED_BOOTSTRAPS: usize = 256;
/// Maximum observed peer addresses retained for the rolling start window.
pub(crate) const MAX_TRACKED_PEERS: usize = 256;
/// Human code-entry idle/approval lifetime in epoch seconds.
pub(crate) const BOOTSTRAP_CODE_TTL_SECS: u64 = 300;
/// Hard lifetime for one bootstrap attempt in epoch seconds.
pub(crate) const BOOTSTRAP_HARD_LIFETIME_SECS: u64 = 330;
/// Maximum failed code submissions for one challenge.
pub(crate) const MAX_CODE_FAILURES_PER_CHALLENGE: u8 = 5;
/// Recovery lifetime for an issued but not yet reconciled bootstrap in epoch seconds.
pub(crate) const ISSUED_RECOVERY_TTL_SECS: u64 = 24 * 60 * 60;
/// Fake Core certificate validity in epoch seconds.
pub(crate) const CORE_CERTIFICATE_TTL_SECS: u64 = 90 * 24 * 60 * 60;

/// One fixed-width opaque identifier used only inside the Relay fake.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Opaque32([u8; 32]);

impl Opaque32 {
    /// Return the opaque bytes for crate-internal wire composition.
    pub(crate) const fn bytes(self) -> [u8; 32] {
        self.0
    }

    /// Construct a non-zero opaque value.
    fn new(bytes: [u8; 32]) -> Result<Self, RelayBootstrapError> {
        if bytes == [0; 32] {
            return Err(RelayBootstrapError::InvalidValue);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Opaque32 {
    /// Redact all opaque identifier bytes from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Opaque32(<redacted>)")
    }
}

/// Sanitized Core certificate metadata returned by the Relay fake.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct CoreCertificateMetadata {
    /// Relay approval identifier bound to the issuance.
    pub(crate) approval_id: Opaque32,
    /// Public Core certificate leaf identity digest.
    pub(crate) core_identity: Opaque32,
    /// Digest of the public leaf-plus-Intermediate chain.
    pub(crate) certificate_chain_digest: Opaque32,
    /// Public certificate serial number.
    pub(crate) serial: u64,
    /// Public certificate expiry in epoch seconds.
    pub(crate) not_after_epoch_seconds: u64,
}

impl fmt::Debug for CoreCertificateMetadata {
    /// Report public metadata shape without exposing identity or certificate values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreCertificateMetadata")
            .field("approval_id", &self.approval_id)
            .field("core_identity", &self.core_identity)
            .field("certificate_chain_digest", &self.certificate_chain_digest)
            .field("serial", &self.serial)
            .field("not_after_epoch_seconds", &self.not_after_epoch_seconds)
            .finish()
    }
}

/// Exact Core/Target/session/generation binding received in HDB1 Start.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct BootstrapBinding {
    /// SHA-256 digest of the transient Core CSR.
    core_csr_digest: CsrDigest,
    /// SHA-256 digest of the App CSR supplied by Core.
    app_csr_digest: CsrDigest,
    /// Normalized Herdr session name.
    normalized_session: String,
    /// Core configuration generation.
    configuration_generation: u64,
    /// Core-owned Profile/Target binding digest.
    core_binding_digest: Opaque32,
}

impl fmt::Debug for BootstrapBinding {
    /// Report only binding presence and bounded generation metadata.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapBinding")
            .field("core_csr_digest_present", &true)
            .field("app_csr_digest_present", &true)
            .field("session_bound", &true)
            .field("configuration_generation", &self.configuration_generation)
            .field("core_binding_digest_present", &true)
            .finish()
    }
}

impl BootstrapBinding {
    /// Construct a binding after hashing transient Core CSR bytes.
    ///
    /// # Parameters
    /// * `core_csr` - Bounded transient Core CSR bytes.
    /// * `app_csr_digest` - Core-provided App CSR digest.
    /// * `normalized_session` - Existing normalized Herdr session name.
    /// * `configuration_generation` - Non-zero Profile generation.
    /// * `core_binding_digest` - Non-zero Core-owned binding digest.
    ///
    /// # Returns
    /// A binding containing only digests and non-secret identity metadata.
    // TEST:relay/src/bootstrap.rs[bootstrap_start_creates_hidden_workspace_and_challenge]
    pub(crate) fn from_core_csr(
        core_csr: &[u8],
        app_csr_digest: CsrDigest,
        normalized_session: impl Into<String>,
        configuration_generation: u64,
        core_binding_digest: [u8; 32],
    ) -> Result<Self, RelayBootstrapError> {
        let normalized_session = normalized_session.into();
        validate_session(&normalized_session)?;
        if core_csr.is_empty() || core_csr.len() > MAX_BOOTSTRAP_CORE_CSR_BYTES {
            return Err(RelayBootstrapError::InvalidCsr);
        }
        if configuration_generation == 0 {
            return Err(RelayBootstrapError::InvalidGeneration);
        }
        let core_csr_digest = CsrDigest::from_bytes(Sha256::digest(core_csr).into())
            .map_err(|_| RelayBootstrapError::InvalidCsr)?;
        Ok(Self {
            core_csr_digest,
            app_csr_digest,
            normalized_session,
            configuration_generation,
            core_binding_digest: Opaque32::new(core_binding_digest)?,
        })
    }

    /// Determine whether two bindings are exactly equivalent.
    fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

/// Transient HDB1 Start input; the raw Core CSR is discarded by `RelayBootstrapVerifier::start`.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct BootstrapStartRequest {
    /// Non-authoritative 16-byte request correlation value.
    request_id: [u8; 16],
    /// Transient Core CSR bytes.
    core_csr: Vec<u8>,
    /// App CSR digest carried by HDB1 Start.
    app_csr_digest: CsrDigest,
    /// Normalized Herdr session name.
    normalized_session: String,
    /// Profile configuration generation.
    configuration_generation: u64,
    /// Core-owned Profile/Target binding digest.
    core_binding_digest: [u8; 32],
}

impl fmt::Debug for BootstrapStartRequest {
    /// Redact request and CSR data while retaining bounded shape information.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapStartRequest")
            .field("request_id_present", &true)
            .field("core_csr_len", &self.core_csr.len())
            .field("app_csr_digest_present", &true)
            .field("session_bound", &true)
            .field("configuration_generation", &self.configuration_generation)
            .field("core_binding_digest_present", &true)
            .finish()
    }
}

impl BootstrapStartRequest {
    /// Construct a bounded HDB1 Start request for the local fake.
    ///
    /// # Parameters
    /// * `request_id` - Non-zero non-authoritative request correlation bytes.
    /// * `core_csr` - Transient bounded Core CSR bytes.
    /// * `app_csr_digest` - Non-zero App CSR digest.
    /// * `normalized_session` - Existing normalized Herdr session name.
    /// * `configuration_generation` - Non-zero Profile generation.
    /// * `core_binding_digest` - Non-zero Core-owned binding digest.
    ///
    /// # Returns
    /// A validated transient Start request.
    // TEST:relay/src/bootstrap.rs[bootstrap_start_creates_hidden_workspace_and_challenge]
    pub(crate) fn new(
        request_id: [u8; 16],
        core_csr: Vec<u8>,
        app_csr_digest: CsrDigest,
        normalized_session: impl Into<String>,
        configuration_generation: u64,
        core_binding_digest: [u8; 32],
    ) -> Result<Self, RelayBootstrapError> {
        let normalized_session = normalized_session.into();
        validate_session(&normalized_session)?;
        if request_id == [0; 16] {
            return Err(RelayBootstrapError::InvalidValue);
        }
        if core_csr.is_empty() || core_csr.len() > MAX_BOOTSTRAP_CORE_CSR_BYTES {
            return Err(RelayBootstrapError::InvalidCsr);
        }
        if configuration_generation == 0 {
            return Err(RelayBootstrapError::InvalidGeneration);
        }
        let _ = Opaque32::new(core_binding_digest)?;
        Ok(Self {
            request_id,
            core_csr,
            app_csr_digest,
            normalized_session,
            configuration_generation,
            core_binding_digest,
        })
    }

    /// Convert the transient request into a digest-only binding.
    fn into_binding(self) -> Result<BootstrapBinding, RelayBootstrapError> {
        BootstrapBinding::from_core_csr(
            &self.core_csr,
            self.app_csr_digest,
            self.normalized_session,
            self.configuration_generation,
            self.core_binding_digest,
        )
    }
}

/// Sanitized Relay challenge returned after hidden workspace setup and readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BootstrapChallengeView {
    /// Opaque bootstrap identifier.
    pub(crate) bootstrap_id: Opaque32,
    /// Opaque challenge bound to this attempt.
    pub(crate) challenge: Opaque32,
    /// Code-entry expiry in epoch seconds.
    pub(crate) expires_at_epoch_seconds: u64,
}

/// Sanitized recovery status returned for an exact approval and binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapRecovery {
    /// The attempt is still pending and has no certificate.
    Pending {
        /// Hard attempt expiry.
        expires_at_epoch_seconds: u64,
    },
    /// The same public certificate metadata can be replayed without reissuance.
    Issued(CoreCertificateMetadata),
    /// The attempt is terminal and cannot issue a certificate.
    Rejected {
        /// Stable non-zero rejection code.
        code: u16,
    },
}

/// Stable Relay bootstrap fake error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelayBootstrapError {
    /// An opaque value or request ID was zero.
    InvalidValue,
    /// The normalized session name was invalid.
    InvalidSession,
    /// The Profile configuration generation was zero.
    InvalidGeneration,
    /// The transient Core CSR was empty or too large.
    InvalidCsr,
    /// The active bootstrap cap was exhausted.
    CapacityExhausted,
    /// The peer-IP rolling start limit was exhausted.
    PeerRateLimited,
    /// The session already has an active or unresolved workspace.
    AlreadyActive,
    /// The requested attempt was not found.
    NotFound,
    /// The supplied binding or challenge did not match.
    AuthorityMismatch,
    /// The challenge was malformed, reused, or in the wrong state.
    InvalidChallenge,
    /// The attempt's bounded lifetime elapsed.
    Expired,
    /// The human code did not match.
    CodeMismatch,
    /// The failed-code limit was reached.
    CodeRateLimited,
    /// Workspace setup or cleanup failed.
    WorkspaceFailure,
    /// Cleanup is pending and blocks a new attempt.
    CleanupPending,
    /// The lifecycle transition is not valid.
    InvalidState,
    /// A second terminal submission was attempted.
    AlreadyTerminal,
    /// The deterministic fake issuer failed.
    IssuanceFailed,
    /// The deterministic counter or time calculation overflowed.
    Overflow,
}

impl fmt::Display for RelayBootstrapError {
    /// Format a stable sanitized error without secrets or identity values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidValue => "bootstrap value is invalid",
            Self::InvalidSession => "bootstrap session is invalid",
            Self::InvalidGeneration => "bootstrap configuration generation is invalid",
            Self::InvalidCsr => "bootstrap Core CSR is invalid",
            Self::CapacityExhausted => "bootstrap capacity is exhausted",
            Self::PeerRateLimited => "bootstrap peer rate limit is exhausted",
            Self::AlreadyActive => "bootstrap session is already active",
            Self::NotFound => "bootstrap attempt is not found",
            Self::AuthorityMismatch => "bootstrap authority does not match",
            Self::InvalidChallenge => "bootstrap challenge is invalid",
            Self::Expired => "bootstrap attempt has expired",
            Self::CodeMismatch => "bootstrap code is invalid",
            Self::CodeRateLimited => "bootstrap code rate limit is exhausted",
            Self::WorkspaceFailure => "bootstrap workspace operation failed",
            Self::CleanupPending => "bootstrap cleanup is pending",
            Self::InvalidState => "bootstrap state transition is invalid",
            Self::AlreadyTerminal => "bootstrap attempt is already terminal",
            Self::IssuanceFailed => "bootstrap certificate issuance failed",
            Self::Overflow => "bootstrap value overflowed",
        })
    }
}

impl std::error::Error for RelayBootstrapError {}

/// Sanitized lifecycle state of one Relay bootstrap attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelayBootstrapState {
    /// Hidden workspace exists and the code is awaiting user entry.
    AwaitingCode,
    /// Workspace cleanup must complete before the attempt can terminate.
    CleanupPending,
    /// Core public certificate metadata was issued exactly once.
    Issued,
    /// Code or workspace processing reached a terminal rejection.
    Rejected,
    /// The bounded attempt lifetime elapsed.
    Expired,
}

/// Private hidden verification workspace record used only by the fake.
#[derive(Clone)]
struct VerificationWorkspace {
    /// Opaque workspace identity.
    id: Opaque32,
    /// Normalized session containing the hidden workspace.
    normalized_session: String,
    /// Exact lower-case hexadecimal recovery marker.
    marker_text: String,
    /// Code retained only in Relay memory for constant-time comparison.
    code: [u8; 6],
    /// Code-first hidden title retained only inside the fake workspace.
    title: String,
}

impl fmt::Debug for VerificationWorkspace {
    /// Redact workspace identity, marker, title, and verification code.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationWorkspace")
            .field("id", &self.id)
            .field("session_bound", &true)
            .field("marker_present", &true)
            .field("code_present", &true)
            .field("title_present", &true)
            .finish()
    }
}

/// Sanitized workspace readback used to prove create/readback binding.
struct WorkspaceReadback {
    /// Session returned by the fake workspace.
    normalized_session: String,
    /// Recovery marker returned by the fake workspace.
    marker_text: String,
}

/// Workspace operation failure injected by the deterministic fake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceError {
    /// The fake could not read a workspace.
    ReadFailed,
    /// The fake could not close a workspace.
    CloseFailed,
}

/// Deterministic hidden-workspace fake with explicit failure injection.
#[derive(Clone)]
struct FakeVerificationWorkspace {
    /// Non-secret seed used to mint opaque workspace identities.
    seed: [u8; 32],
    /// Monotonic workspace counter.
    next_counter: u64,
    /// Hidden workspace records.
    workspaces: BTreeMap<Opaque32, VerificationWorkspace>,
    /// Fail the next readback operation.
    fail_next_read: bool,
    /// Fail the next close operation.
    fail_next_close: bool,
}

impl fmt::Debug for FakeVerificationWorkspace {
    /// Report workspace count and fault state without secret data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeVerificationWorkspace")
            .field("workspace_count", &self.workspaces.len())
            .field("fail_next_read", &self.fail_next_read)
            .field("fail_next_close", &self.fail_next_close)
            .finish()
    }
}

impl FakeVerificationWorkspace {
    /// Construct an empty deterministic hidden-workspace fake.
    fn new(seed: [u8; 32]) -> Result<Self, RelayBootstrapError> {
        if seed == [0; 32] {
            return Err(RelayBootstrapError::InvalidValue);
        }
        Ok(Self {
            seed,
            next_counter: 1,
            workspaces: BTreeMap::new(),
            fail_next_read: false,
            fail_next_close: false,
        })
    }

    /// Create one hidden workspace and retain its code only in Relay memory.
    fn create(
        &mut self,
        normalized_session: &str,
        marker: [u8; 8],
        code: [u8; 6],
        expires_at_epoch_seconds: u64,
    ) -> Result<Opaque32, RelayBootstrapError> {
        let id = self.mint_id(b"workspace")?;
        let marker_text = encode_marker(marker);
        let code_text =
            std::str::from_utf8(&code).map_err(|_| RelayBootstrapError::InvalidValue)?;
        // The fake uses UTC as a deterministic explicit offset; production supplies host-local formatting.
        let expiry_text = format_expiry(expires_at_epoch_seconds)?;
        let title = format!("{code_text} (expires {expiry_text}) - herdr-dog verification");
        self.workspaces.insert(
            id,
            VerificationWorkspace {
                id,
                normalized_session: normalized_session.to_owned(),
                marker_text,
                code,
                title,
            },
        );
        Ok(id)
    }

    /// Read back the exact session and marker from a hidden workspace.
    fn readback(&mut self, id: Opaque32) -> Result<WorkspaceReadback, WorkspaceError> {
        if self.fail_next_read {
            self.fail_next_read = false;
            return Err(WorkspaceError::ReadFailed);
        }
        let workspace = self.workspaces.get(&id).ok_or(WorkspaceError::ReadFailed)?;
        Ok(WorkspaceReadback {
            normalized_session: workspace.normalized_session.clone(),
            marker_text: workspace.marker_text.clone(),
        })
    }

    /// Close one hidden workspace, retaining no code or topology after success.
    fn close(&mut self, id: Opaque32) -> Result<(), WorkspaceError> {
        if self.fail_next_close {
            self.fail_next_close = false;
            return Err(WorkspaceError::CloseFailed);
        }
        self.workspaces
            .remove(&id)
            .ok_or(WorkspaceError::CloseFailed)?;
        Ok(())
    }

    /// Return whether a workspace remains for a normalized session.
    fn has_session(&self, normalized_session: &str) -> bool {
        self.workspaces
            .values()
            .any(|workspace| workspace.normalized_session == normalized_session)
    }

    /// Count hidden workspaces retained by the fake.
    fn len(&self) -> usize {
        self.workspaces.len()
    }

    /// Fail the next workspace readback.
    fn fail_next_read(&mut self) {
        self.fail_next_read = true;
    }

    /// Fail the next workspace close.
    fn fail_next_close(&mut self) {
        self.fail_next_close = true;
    }

    /// Mint one deterministic opaque workspace ID.
    fn mint_id(&mut self, label: &[u8]) -> Result<Opaque32, RelayBootstrapError> {
        let counter = self.next_counter;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(RelayBootstrapError::Overflow)?;
        let mut hasher = Sha256::new();
        hasher.update(label);
        hasher.update(self.seed);
        hasher.update(counter.to_be_bytes());
        Opaque32::new(hasher.finalize().into())
    }
}

/// Deterministic Core certificate issuer that retains only public metadata.
#[derive(Clone)]
struct FakeCoreCertificateIssuer {
    /// Non-secret fixture seed.
    seed: [u8; 32],
    /// Monotonic public serial counter.
    next_serial: u64,
    /// Number of successful issuances.
    issued_count: usize,
    /// Fail the next issuance for rollback tests.
    fail_next: bool,
}

impl fmt::Debug for FakeCoreCertificateIssuer {
    /// Report issuance count and fault state without seed or certificate data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeCoreCertificateIssuer")
            .field("issued_count", &self.issued_count)
            .field("fail_next", &self.fail_next)
            .finish()
    }
}

impl FakeCoreCertificateIssuer {
    /// Construct an empty deterministic issuer.
    fn new(seed: [u8; 32]) -> Result<Self, RelayBootstrapError> {
        if seed == [0; 32] {
            return Err(RelayBootstrapError::InvalidValue);
        }
        Ok(Self {
            seed,
            next_serial: 1,
            issued_count: 0,
            fail_next: false,
        })
    }

    /// Issue one public Core certificate metadata record.
    fn issue(
        &mut self,
        approval_id: Opaque32,
        binding: &BootstrapBinding,
        now_epoch_seconds: u64,
    ) -> Result<CoreCertificateMetadata, RelayBootstrapError> {
        if self.fail_next {
            self.fail_next = false;
            return Err(RelayBootstrapError::IssuanceFailed);
        }
        if now_epoch_seconds == 0 {
            return Err(RelayBootstrapError::InvalidValue);
        }
        let serial = self.next_serial;
        self.next_serial = self
            .next_serial
            .checked_add(1)
            .ok_or(RelayBootstrapError::Overflow)?;
        let core_identity = self.derive(
            b"core-identity",
            serial,
            approval_id,
            binding.core_csr_digest,
            binding.core_binding_digest,
        )?;
        let certificate_chain_digest = self.derive(
            b"core-chain",
            serial,
            approval_id,
            binding.app_csr_digest,
            core_identity,
        )?;
        let not_after_epoch_seconds = now_epoch_seconds
            .checked_add(CORE_CERTIFICATE_TTL_SECS)
            .ok_or(RelayBootstrapError::Overflow)?;
        self.issued_count += 1;
        Ok(CoreCertificateMetadata {
            approval_id,
            core_identity,
            certificate_chain_digest,
            serial,
            not_after_epoch_seconds,
        })
    }

    /// Fail the next issuance without exposing or retaining certificate material.
    fn fail_next(&mut self) {
        self.fail_next = true;
    }

    /// Derive one non-zero public digest from bounded authority metadata.
    fn derive(
        &self,
        label: &[u8],
        serial: u64,
        approval_id: Opaque32,
        first: impl CopyBytes,
        second: impl CopyBytes,
    ) -> Result<Opaque32, RelayBootstrapError> {
        let mut hasher = Sha256::new();
        hasher.update(label);
        hasher.update(self.seed);
        hasher.update(serial.to_be_bytes());
        hasher.update(approval_id.0);
        hasher.update(first.copy_bytes());
        hasher.update(second.copy_bytes());
        Opaque32::new(hasher.finalize().into())
    }
}

/// Small internal trait for hashing fixed-width digest wrappers.
trait CopyBytes {
    /// Copy the value's bytes into a hash input.
    fn copy_bytes(self) -> [u8; 32];
}

impl CopyBytes for Opaque32 {
    /// Copy opaque bytes for internal deterministic derivation.
    fn copy_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl CopyBytes for CsrDigest {
    /// Copy CSR digest bytes for internal deterministic derivation.
    fn copy_bytes(self) -> [u8; 32] {
        *self.as_bytes()
    }
}

/// One active or terminal Relay bootstrap attempt.
#[derive(Clone)]
struct RelayBootstrapAttempt {
    /// Exact binding accepted at start.
    binding: BootstrapBinding,
    /// Source peer address observed after QUIC handshake.
    peer_ip: IpAddr,
    /// Opaque bootstrap identifier.
    bootstrap_id: Opaque32,
    /// Opaque approval identifier retained for recovery.
    approval_id: Opaque32,
    /// Hidden workspace identity.
    workspace_id: Opaque32,
    /// Hidden marker retained only for fake readback checks.
    marker: [u8; 8],
    /// Code retained only in Relay memory while the attempt is awaiting submission.
    code: Option<[u8; 6]>,
    /// Challenge returned to Core.
    challenge: Opaque32,
    /// Start time.
    created_at_epoch_seconds: u64,
    /// Code-entry expiry.
    challenge_expires_at_epoch_seconds: u64,
    /// Hard attempt expiry.
    hard_expires_at_epoch_seconds: u64,
    /// Failed code attempts.
    failed_code_attempts: u8,
    /// Current lifecycle state.
    state: RelayBootstrapState,
    /// Public issuance metadata after success.
    issued: Option<CoreCertificateMetadata>,
    /// Epoch second at which public issuance completed.
    issued_at_epoch_seconds: Option<u64>,
}

impl fmt::Debug for RelayBootstrapAttempt {
    /// Report lifecycle shape without authority values, code, marker, or workspace topology.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayBootstrapAttempt")
            .field("binding", &self.binding)
            .field("peer_ip_present", &true)
            .field("bootstrap_id", &self.bootstrap_id)
            .field("approval_id", &self.approval_id)
            .field("workspace_present", &true)
            .field("marker_present", &true)
            .field("challenge", &self.challenge)
            .field("created_at_epoch_seconds", &self.created_at_epoch_seconds)
            .field(
                "challenge_expires_at_epoch_seconds",
                &self.challenge_expires_at_epoch_seconds,
            )
            .field(
                "hard_expires_at_epoch_seconds",
                &self.hard_expires_at_epoch_seconds,
            )
            .field("failed_code_attempts", &self.failed_code_attempts)
            .field("state", &self.state)
            .field("code_present", &self.code.is_some())
            .field("issued", &self.issued.is_some())
            .field("issued_at_epoch_seconds", &self.issued_at_epoch_seconds)
            .finish()
    }
}

/// Deterministic Relay-side HDB1 verifier fake.
#[derive(Clone)]
pub(crate) struct RelayBootstrapVerifier {
    /// Non-secret fixture seed.
    seed: [u8; 32],
    /// Monotonic opaque-id counter.
    next_counter: u64,
    /// Attempts retained for exact reconciliation and terminal audit shape.
    attempts: BTreeMap<Opaque32, RelayBootstrapAttempt>,
    /// Active attempt by normalized session.
    active_by_session: BTreeMap<String, Opaque32>,
    /// Rolling peer-IP start history.
    peer_starts: HashMap<IpAddr, Vec<u64>>,
    /// Hidden verification workspace fake.
    workspace: FakeVerificationWorkspace,
    /// Public Core certificate fake issuer.
    issuer: FakeCoreCertificateIssuer,
}

impl fmt::Debug for RelayBootstrapVerifier {
    /// Report counts and fault-free lifecycle shape without secrets.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayBootstrapVerifier")
            .field("attempt_count", &self.attempts.len())
            .field("active_session_count", &self.active_by_session.len())
            .field("peer_history_count", &self.peer_starts.len())
            .field("workspace", &self.workspace)
            .field("issuer", &self.issuer)
            .finish()
    }
}

impl RelayBootstrapVerifier {
    /// Construct an empty deterministic verifier and its hidden workspace/issuer fakes.
    ///
    /// # Parameters
    /// * `seed` - Non-secret fixture seed.
    ///
    /// # Returns
    /// A verifier with no active attempts or retained workspace.
    // TEST:relay/src/bootstrap.rs[bootstrap_start_creates_hidden_workspace_and_challenge]
    pub(crate) fn new(seed: [u8; 32]) -> Result<Self, RelayBootstrapError> {
        if seed == [0; 32] {
            return Err(RelayBootstrapError::InvalidValue);
        }
        Ok(Self {
            seed,
            next_counter: 1,
            attempts: BTreeMap::new(),
            active_by_session: BTreeMap::new(),
            peer_starts: HashMap::new(),
            workspace: FakeVerificationWorkspace::new(derive_seed(seed, b"workspace"))?,
            issuer: FakeCoreCertificateIssuer::new(derive_seed(seed, b"issuer"))?,
        })
    }

    /// Start one bounded bootstrap and perform create/readback before returning a challenge.
    ///
    /// # Parameters
    /// * `peer_ip` - Relay-observed peer IP after the QUIC handshake.
    /// * `request` - Transient bounded HDB1 Start request.
    /// * `now_epoch_seconds` - Deterministic current epoch second.
    ///
    /// # Returns
    /// Sanitized challenge metadata; the code and workspace remain Relay-private.
    // TEST:relay/src/bootstrap.rs[bootstrap_start_creates_hidden_workspace_and_challenge]
    pub(crate) fn start(
        &mut self,
        peer_ip: IpAddr,
        request: BootstrapStartRequest,
        now_epoch_seconds: u64,
    ) -> Result<BootstrapChallengeView, RelayBootstrapError> {
        if now_epoch_seconds == 0 {
            return Err(RelayBootstrapError::InvalidValue);
        }
        self.reap_expired(now_epoch_seconds);
        self.prune_retained_attempts(now_epoch_seconds);
        if self.attempts.len() >= MAX_RETAINED_BOOTSTRAPS {
            return Err(RelayBootstrapError::CapacityExhausted);
        }
        let normalized_session = request.normalized_session.clone();
        self.prune_peer_history(now_epoch_seconds);
        if !self.peer_starts.contains_key(&peer_ip) && self.peer_starts.len() >= MAX_TRACKED_PEERS {
            return Err(RelayBootstrapError::CapacityExhausted);
        }
        if self.active_by_session.contains_key(&normalized_session)
            || self.workspace.has_session(&normalized_session)
        {
            return Err(RelayBootstrapError::AlreadyActive);
        }
        if self.active_by_session.len() >= MAX_ACTIVE_BOOTSTRAPS {
            return Err(RelayBootstrapError::CapacityExhausted);
        }
        let peer_history = self.peer_starts.entry(peer_ip).or_default();
        if peer_history.len() >= MAX_PEER_STARTS {
            return Err(RelayBootstrapError::PeerRateLimited);
        }
        peer_history.push(now_epoch_seconds);
        let binding = request.into_binding()?;
        let bootstrap_id = self.mint_id(b"bootstrap", &binding)?;
        let approval_id = self.mint_id(b"approval", &binding)?;
        let challenge = self.mint_id(b"challenge", &binding)?;
        let marker = self.mint_marker(bootstrap_id);
        let code = self.mint_code(bootstrap_id);
        let challenge_expires_at_epoch_seconds = now_epoch_seconds
            .checked_add(BOOTSTRAP_CODE_TTL_SECS)
            .ok_or(RelayBootstrapError::Overflow)?;
        let hard_expires_at_epoch_seconds = now_epoch_seconds
            .checked_add(BOOTSTRAP_HARD_LIFETIME_SECS)
            .ok_or(RelayBootstrapError::Overflow)?;
        let workspace_id = self
            .workspace
            .create(
                &binding.normalized_session,
                marker,
                code,
                challenge_expires_at_epoch_seconds,
            )
            .map_err(|_| RelayBootstrapError::WorkspaceFailure)?;
        let readback = match self.workspace.readback(workspace_id) {
            Ok(readback) => readback,
            Err(_) => {
                let _ = self.workspace.close(workspace_id);
                return Err(RelayBootstrapError::WorkspaceFailure);
            }
        };
        if readback.normalized_session != binding.normalized_session
            || readback.marker_text != encode_marker(marker)
        {
            let _ = self.workspace.close(workspace_id);
            return Err(RelayBootstrapError::WorkspaceFailure);
        }
        self.attempts.insert(
            bootstrap_id,
            RelayBootstrapAttempt {
                binding: binding.clone(),
                peer_ip,
                bootstrap_id,
                approval_id,
                workspace_id,
                marker,
                code: Some(code),
                challenge,
                created_at_epoch_seconds: now_epoch_seconds,
                challenge_expires_at_epoch_seconds,
                hard_expires_at_epoch_seconds,
                failed_code_attempts: 0,
                state: RelayBootstrapState::AwaitingCode,
                issued: None,
                issued_at_epoch_seconds: None,
            },
        );
        self.active_by_session
            .insert(binding.normalized_session, bootstrap_id);
        Ok(BootstrapChallengeView {
            bootstrap_id,
            challenge,
            expires_at_epoch_seconds: challenge_expires_at_epoch_seconds,
        })
    }

    /// Submit the transient six-digit code and issue one Core certificate at most once.
    ///
    /// # Parameters
    /// * `bootstrap_id` - Attempt returned by `start`.
    /// * `challenge` - Challenge returned by `start`.
    /// * `code` - Six ASCII digits read by the user from the designated Herdr UI.
    /// * `now_epoch_seconds` - Deterministic current epoch second.
    ///
    /// # Returns
    /// Public Core certificate metadata or a sanitized terminal/validation error.
    // TEST:relay/src/bootstrap.rs[bootstrap_code_is_single_use_and_issuance_is_idempotent]
    pub(crate) fn submit(
        &mut self,
        bootstrap_id: Opaque32,
        challenge: Opaque32,
        code: &str,
        now_epoch_seconds: u64,
    ) -> Result<CoreCertificateMetadata, RelayBootstrapError> {
        let supplied_code = parse_code(code)?;
        let (workspace_id, expected_challenge, expected_code, state, expires, hard_expires) = {
            let attempt = self
                .attempts
                .get(&bootstrap_id)
                .ok_or(RelayBootstrapError::NotFound)?;
            (
                attempt.workspace_id,
                attempt.challenge,
                attempt.code,
                attempt.state,
                attempt.challenge_expires_at_epoch_seconds,
                attempt.hard_expires_at_epoch_seconds,
            )
        };
        if state != RelayBootstrapState::AwaitingCode {
            return if state == RelayBootstrapState::Issued {
                Err(RelayBootstrapError::AlreadyTerminal)
            } else if state == RelayBootstrapState::CleanupPending {
                Err(RelayBootstrapError::CleanupPending)
            } else {
                Err(RelayBootstrapError::AlreadyTerminal)
            };
        }
        if challenge != expected_challenge {
            return Err(RelayBootstrapError::InvalidChallenge);
        }
        if now_epoch_seconds == 0 || now_epoch_seconds > expires || now_epoch_seconds > hard_expires
        {
            let expiration = if self.expire_attempt(bootstrap_id) {
                RelayBootstrapError::Expired
            } else {
                RelayBootstrapError::CleanupPending
            };
            return Err(expiration);
        }
        if !constant_time_equal(
            &expected_code.ok_or(RelayBootstrapError::InvalidState)?,
            &supplied_code,
        ) {
            let failures = {
                let attempt = self
                    .attempts
                    .get_mut(&bootstrap_id)
                    .ok_or(RelayBootstrapError::NotFound)?;
                attempt.failed_code_attempts = attempt.failed_code_attempts.saturating_add(1);
                attempt.failed_code_attempts
            };
            if failures < MAX_CODE_FAILURES_PER_CHALLENGE {
                return Err(RelayBootstrapError::CodeMismatch);
            }
            return self.terminate_after_failed_code(bootstrap_id);
        }
        if self.workspace.close(workspace_id).is_err() {
            if let Some(attempt) = self.attempts.get_mut(&bootstrap_id) {
                attempt.state = RelayBootstrapState::CleanupPending;
            }
            return Err(RelayBootstrapError::CleanupPending);
        }
        if let Some(attempt) = self.attempts.get_mut(&bootstrap_id) {
            // The code is no longer needed once the hidden workspace is closed.
            attempt.code = None;
        }
        let (approval_id, binding) = {
            let attempt = self
                .attempts
                .get(&bootstrap_id)
                .ok_or(RelayBootstrapError::NotFound)?;
            (attempt.approval_id, attempt.binding.clone())
        };
        let issued = match self.issuer.issue(approval_id, &binding, now_epoch_seconds) {
            Ok(issued) => issued,
            Err(error) => {
                self.mark_terminal(bootstrap_id, RelayBootstrapState::Rejected);
                return Err(error);
            }
        };
        if let Some(attempt) = self.attempts.get_mut(&bootstrap_id) {
            attempt.issued = Some(issued);
            attempt.issued_at_epoch_seconds = Some(now_epoch_seconds);
            attempt.state = RelayBootstrapState::Issued;
        }
        Ok(issued)
    }

    /// Submit a wire-decoded identifier pair after validating non-zero opaque values.
    ///
    /// # Parameters
    /// * `bootstrap_id` - Wire bootstrap identifier returned by Challenge.
    /// * `challenge` - Wire challenge returned by Challenge.
    /// * `code` - Six ASCII digits read by the user from the designated Herdr UI.
    /// * `now_epoch_seconds` - Deterministic current epoch second.
    ///
    /// # Returns
    /// Public Core certificate metadata or a sanitized terminal/validation error.
    pub(crate) fn submit_wire(
        &mut self,
        bootstrap_id: [u8; 32],
        challenge: [u8; 32],
        code: &str,
        now_epoch_seconds: u64,
    ) -> Result<CoreCertificateMetadata, RelayBootstrapError> {
        let bootstrap_id =
            Opaque32::new(bootstrap_id).map_err(|_| RelayBootstrapError::InvalidChallenge)?;
        let challenge =
            Opaque32::new(challenge).map_err(|_| RelayBootstrapError::InvalidChallenge)?;
        self.submit(bootstrap_id, challenge, code, now_epoch_seconds)
    }

    /// Retry cleanup for an attempt left pending after an injected workspace-close failure.
    ///
    /// # Parameters
    /// * `bootstrap_id` - Attempt whose hidden workspace needs cleanup.
    ///
    /// # Returns
    /// Nothing after cleanup and terminal rejection succeed.
    // TEST:relay/src/bootstrap.rs[bootstrap_cleanup_failure_blocks_new_start]
    pub(crate) fn retry_cleanup(
        &mut self,
        bootstrap_id: Opaque32,
    ) -> Result<(), RelayBootstrapError> {
        let workspace_id = {
            let attempt = self
                .attempts
                .get(&bootstrap_id)
                .ok_or(RelayBootstrapError::NotFound)?;
            if attempt.state != RelayBootstrapState::CleanupPending {
                return Err(RelayBootstrapError::InvalidState);
            }
            attempt.workspace_id
        };
        self.workspace
            .close(workspace_id)
            .map_err(|_| RelayBootstrapError::CleanupPending)?;
        self.mark_terminal(bootstrap_id, RelayBootstrapState::Rejected);
        Ok(())
    }

    /// Retry cleanup for a workspace left behind before an attempt was committed.
    ///
    /// # Parameters
    /// * `normalized_session` - Exact session whose hidden workspace should be closed.
    ///
    /// # Returns
    /// Nothing after the orphaned workspace is closed, or a bounded cleanup error.
    // TEST:relay/src/bootstrap.rs[bootstrap_start_rolls_back_and_exposes_no_orphan]
    pub(crate) fn retry_orphaned_workspace(
        &mut self,
        normalized_session: &str,
    ) -> Result<(), RelayBootstrapError> {
        validate_session(normalized_session)?;
        let workspace_id = self
            .workspace
            .workspaces
            .iter()
            .find_map(|(id, workspace)| {
                (workspace.normalized_session == normalized_session).then_some(*id)
            })
            .ok_or(RelayBootstrapError::NotFound)?;
        self.workspace
            .close(workspace_id)
            .map_err(|_| RelayBootstrapError::CleanupPending)
    }

    /// Reconcile from the HDB1 wire-visible binding subset.
    ///
    /// # Parameters
    /// * `approval_id` - Non-zero durable Relay approval identifier.
    /// * `core_binding_digest` - Core-owned binding digest carried by HDB1 Reconcile.
    /// * `normalized_session` - Normalized session carried by HDB1 Reconcile.
    /// * `now_epoch_seconds` - Deterministic current epoch second.
    ///
    /// # Returns
    /// The same recovery result after checking the full Start binding retained by Relay.
    // TEST:relay/src/bootstrap.rs[bootstrap_reconcile_requires_exact_binding]
    pub(crate) fn reconcile_wire(
        &mut self,
        approval_id: [u8; 32],
        core_binding_digest: [u8; 32],
        normalized_session: &str,
        now_epoch_seconds: u64,
    ) -> Result<BootstrapRecovery, RelayBootstrapError> {
        let approval_id = Opaque32::new(approval_id)?;
        let core_binding_digest = Opaque32::new(core_binding_digest)?;
        validate_session(normalized_session)?;
        let attempt = self
            .attempts
            .values()
            .find(|attempt| attempt.approval_id == approval_id)
            .ok_or(RelayBootstrapError::NotFound)?;
        if attempt.binding.core_binding_digest != core_binding_digest
            || attempt.binding.normalized_session != normalized_session
        {
            return Err(RelayBootstrapError::AuthorityMismatch);
        }
        let binding = attempt.binding.clone();
        self.reconcile(approval_id, &binding, now_epoch_seconds)
    }

    /// Reconcile one exact approval and binding without issuing a second certificate.
    ///
    /// # Parameters
    /// * `approval_id` - Durable approval identifier returned after challenge submission.
    /// * `binding` - Exact Core/Profile/session/generation binding.
    /// * `now_epoch_seconds` - Deterministic current epoch second.
    ///
    /// # Returns
    /// Pending, the same Issued public metadata within the recovery window, or a terminal rejection code.
    // TEST:relay/src/bootstrap.rs[bootstrap_reconcile_requires_exact_binding]
    pub(crate) fn reconcile(
        &mut self,
        approval_id: Opaque32,
        binding: &BootstrapBinding,
        now_epoch_seconds: u64,
    ) -> Result<BootstrapRecovery, RelayBootstrapError> {
        if now_epoch_seconds == 0 {
            return Err(RelayBootstrapError::InvalidValue);
        }
        let bootstrap_id = self
            .attempts
            .iter()
            .find_map(|(id, attempt)| (attempt.approval_id == approval_id).then_some(*id))
            .ok_or(RelayBootstrapError::NotFound)?;
        let attempt_binding = self
            .attempts
            .get(&bootstrap_id)
            .ok_or(RelayBootstrapError::NotFound)?
            .binding
            .clone();
        if !attempt_binding.matches(binding) {
            return Err(RelayBootstrapError::AuthorityMismatch);
        }
        let state = self
            .attempts
            .get(&bootstrap_id)
            .ok_or(RelayBootstrapError::NotFound)?
            .state;
        if state == RelayBootstrapState::AwaitingCode
            && now_epoch_seconds
                > self
                    .attempts
                    .get(&bootstrap_id)
                    .ok_or(RelayBootstrapError::NotFound)?
                    .hard_expires_at_epoch_seconds
            && self.expire_attempt(bootstrap_id)
        {
            return Ok(BootstrapRecovery::Rejected { code: 2 });
        }
        let state = self
            .attempts
            .get(&bootstrap_id)
            .ok_or(RelayBootstrapError::NotFound)?
            .state;
        match state {
            RelayBootstrapState::AwaitingCode | RelayBootstrapState::CleanupPending => {
                let expires_at_epoch_seconds = self
                    .attempts
                    .get(&bootstrap_id)
                    .ok_or(RelayBootstrapError::NotFound)?
                    .hard_expires_at_epoch_seconds;
                Ok(BootstrapRecovery::Pending {
                    expires_at_epoch_seconds,
                })
            }
            RelayBootstrapState::Issued => {
                let (issued_at, issued) = {
                    let attempt = self
                        .attempts
                        .get(&bootstrap_id)
                        .ok_or(RelayBootstrapError::NotFound)?;
                    (
                        attempt
                            .issued_at_epoch_seconds
                            .ok_or(RelayBootstrapError::InvalidState)?,
                        attempt.issued.ok_or(RelayBootstrapError::InvalidState)?,
                    )
                };
                if now_epoch_seconds < issued_at {
                    return Err(RelayBootstrapError::InvalidValue);
                }
                let recovery_expires_at = issued_at
                    .checked_add(ISSUED_RECOVERY_TTL_SECS)
                    .ok_or(RelayBootstrapError::Overflow)?;
                if now_epoch_seconds > recovery_expires_at {
                    self.mark_terminal(bootstrap_id, RelayBootstrapState::Expired);
                    return Ok(BootstrapRecovery::Rejected { code: 2 });
                }
                Ok(BootstrapRecovery::Issued(issued))
            }
            RelayBootstrapState::Rejected => Ok(BootstrapRecovery::Rejected { code: 1 }),
            RelayBootstrapState::Expired => Ok(BootstrapRecovery::Rejected { code: 2 }),
        }
    }

    /// Return the sanitized attempt state.
    ///
    /// # Parameters
    /// * `bootstrap_id` - Opaque attempt identifier.
    ///
    /// # Returns
    /// Current lifecycle state, if the attempt is retained.
    // TEST:relay/src/bootstrap.rs[bootstrap_code_is_single_use_and_issuance_is_idempotent]
    pub(crate) fn state(&self, bootstrap_id: Opaque32) -> Option<RelayBootstrapState> {
        self.attempts
            .get(&bootstrap_id)
            .map(|attempt| attempt.state)
    }

    /// Return the number of active session fences.
    pub(crate) fn active_count(&self) -> usize {
        self.active_by_session.len()
    }

    /// Return the deterministic test code for one live fake attempt.
    ///
    /// This accessor is compiled only for the local contract tests; production code never exposes
    /// the verification code to a caller.
    #[cfg(test)]
    pub(crate) fn test_code(&self, bootstrap_id: Opaque32) -> Option<String> {
        self.attempts.get(&bootstrap_id).and_then(|attempt| {
            attempt
                .code
                .as_ref()
                .and_then(|code| std::str::from_utf8(code).ok())
                .map(str::to_owned)
        })
    }

    /// Return the number of hidden workspaces retained by the fake.
    pub(crate) fn workspace_count(&self) -> usize {
        self.workspace.len()
    }

    /// Return the number of successful public certificate issuances.
    pub(crate) fn issued_count(&self) -> usize {
        self.issuer.issued_count
    }

    /// Inject a hidden workspace readback failure on the next start.
    pub(crate) fn fail_next_workspace_read(&mut self) {
        self.workspace.fail_next_read();
    }

    /// Inject a hidden workspace close failure on the next close.
    pub(crate) fn fail_next_workspace_close(&mut self) {
        self.workspace.fail_next_close();
    }

    /// Inject one certificate-issuer failure.
    pub(crate) fn fail_next_issuance(&mut self) {
        self.issuer.fail_next();
    }

    /// Mark an attempt terminal and remove only its active session fence.
    fn mark_terminal(&mut self, bootstrap_id: Opaque32, state: RelayBootstrapState) {
        let session = self
            .attempts
            .get(&bootstrap_id)
            .map(|attempt| attempt.binding.normalized_session.clone());
        if let Some(attempt) = self.attempts.get_mut(&bootstrap_id) {
            attempt.state = state;
            // Terminal attempts no longer need the transient verification code.
            attempt.code = None;
        }
        if let Some(session) = session {
            self.active_by_session.remove(&session);
        }
    }

    /// Expire one pending attempt and best-effort close its workspace.
    ///
    /// # Returns
    /// `true` when the workspace was closed and the attempt became terminal; `false` when cleanup
    /// remains pending and the session fence must stay active.
    fn expire_attempt(&mut self, bootstrap_id: Opaque32) -> bool {
        let workspace_id = self
            .attempts
            .get(&bootstrap_id)
            .map(|attempt| attempt.workspace_id);
        if let Some(workspace_id) = workspace_id {
            if self.workspace.close(workspace_id).is_ok() {
                self.mark_terminal(bootstrap_id, RelayBootstrapState::Expired);
                return true;
            }
            if let Some(attempt) = self.attempts.get_mut(&bootstrap_id) {
                attempt.state = RelayBootstrapState::CleanupPending;
            }
        }
        false
    }

    /// Close the hidden workspace after the failed-code limit and preserve cleanup state on error.
    fn terminate_after_failed_code(
        &mut self,
        bootstrap_id: Opaque32,
    ) -> Result<CoreCertificateMetadata, RelayBootstrapError> {
        let workspace_id = self
            .attempts
            .get(&bootstrap_id)
            .ok_or(RelayBootstrapError::NotFound)?
            .workspace_id;
        if self.workspace.close(workspace_id).is_err() {
            if let Some(attempt) = self.attempts.get_mut(&bootstrap_id) {
                attempt.state = RelayBootstrapState::CleanupPending;
            }
            return Err(RelayBootstrapError::CleanupPending);
        }
        self.mark_terminal(bootstrap_id, RelayBootstrapState::Rejected);
        Err(RelayBootstrapError::CodeRateLimited)
    }

    /// Reap attempts whose hard or issued-recovery lifetime has elapsed.
    ///
    /// # Parameters
    /// * `now_epoch_seconds` - Deterministic current epoch second.
    ///
    /// # Returns
    /// The number of attempts transitioned to the terminal `Expired` state. Cleanup failures remain
    /// `CleanupPending` and retain the active session fence for an explicit retry.
    // TEST:relay/src/bootstrap.rs[bootstrap_reap_releases_abandoned_and_issued_fences]
    pub(crate) fn reap_expired(&mut self, now_epoch_seconds: u64) -> usize {
        if now_epoch_seconds == 0 {
            return 0;
        }
        let due: Vec<_> = self
            .attempts
            .iter()
            .filter_map(|(bootstrap_id, attempt)| match attempt.state {
                RelayBootstrapState::AwaitingCode | RelayBootstrapState::CleanupPending
                    if now_epoch_seconds > attempt.hard_expires_at_epoch_seconds =>
                {
                    Some((*bootstrap_id, false))
                }
                RelayBootstrapState::Issued
                    if attempt
                        .issued_at_epoch_seconds
                        .and_then(|issued_at| issued_at.checked_add(ISSUED_RECOVERY_TTL_SECS))
                        .is_some_and(|expires_at| now_epoch_seconds > expires_at) =>
                {
                    Some((*bootstrap_id, true))
                }
                _ => None,
            })
            .collect();
        let mut expired = 0;
        for (bootstrap_id, issued) in due {
            if issued {
                self.mark_terminal(bootstrap_id, RelayBootstrapState::Expired);
            } else if !self.expire_attempt(bootstrap_id) {
                continue;
            }
            expired += 1;
        }
        expired
    }

    /// Prune terminal attempts and issued records past their bounded recovery window.
    fn prune_retained_attempts(&mut self, now_epoch_seconds: u64) {
        let removable: Vec<_> = self
            .attempts
            .iter()
            .filter_map(|(bootstrap_id, attempt)| {
                let expired_issued = attempt.state == RelayBootstrapState::Issued
                    && attempt
                        .issued_at_epoch_seconds
                        .and_then(|issued_at| issued_at.checked_add(ISSUED_RECOVERY_TTL_SECS))
                        .is_some_and(|expires_at| now_epoch_seconds > expires_at);
                (matches!(
                    attempt.state,
                    RelayBootstrapState::Rejected | RelayBootstrapState::Expired
                ) || expired_issued)
                    .then_some(*bootstrap_id)
            })
            .collect();
        for bootstrap_id in removable {
            let session = self
                .attempts
                .get(&bootstrap_id)
                .map(|attempt| attempt.binding.normalized_session.clone());
            self.attempts.remove(&bootstrap_id);
            if let Some(session) = session
                && self.active_by_session.get(&session) == Some(&bootstrap_id)
            {
                self.active_by_session.remove(&session);
            }
        }
    }

    /// Prune peer starts outside the bounded rolling window and discard empty histories.
    fn prune_peer_history(&mut self, now_epoch_seconds: u64) {
        for history in self.peer_starts.values_mut() {
            history.retain(|started| {
                now_epoch_seconds.saturating_sub(*started) < BOOTSTRAP_START_WINDOW_SECS
            });
        }
        self.peer_starts.retain(|_, history| !history.is_empty());
    }

    /// Mint one deterministic opaque ID bound to the current verifier and exact Profile binding.
    fn mint_id(
        &mut self,
        label: &[u8],
        binding: &BootstrapBinding,
    ) -> Result<Opaque32, RelayBootstrapError> {
        let counter = self.next_counter;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(RelayBootstrapError::Overflow)?;
        let mut hasher = Sha256::new();
        hasher.update(label);
        hasher.update(self.seed);
        hasher.update(counter.to_be_bytes());
        hasher.update(binding.normalized_session.as_bytes());
        hasher.update(binding.configuration_generation.to_be_bytes());
        hasher.update(binding.core_csr_digest.as_bytes());
        hasher.update(binding.app_csr_digest.as_bytes());
        hasher.update(binding.core_binding_digest.0);
        Opaque32::new(hasher.finalize().into())
    }

    /// Derive the exact lower-case hexadecimal recovery marker.
    fn mint_marker(&self, bootstrap_id: Opaque32) -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"marker");
        hasher.update(self.seed);
        hasher.update(bootstrap_id.0);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut marker = [0_u8; 8];
        marker.copy_from_slice(&digest[..8]);
        marker
    }

    /// Derive exactly six ASCII digits for the hidden designated-UI title.
    fn mint_code(&self, bootstrap_id: Opaque32) -> [u8; 6] {
        let mut hasher = Sha256::new();
        hasher.update(b"code");
        hasher.update(self.seed);
        hasher.update(bootstrap_id.0);
        let digest: [u8; 32] = hasher.finalize().into();
        let raw = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        let value = raw % 1_000_000;
        let text = format!("{value:06}");
        let mut code = [0_u8; 6];
        code.copy_from_slice(text.as_bytes());
        code
    }
}

/// Derive independent deterministic seeds for fake subcomponents.
fn derive_seed(seed: [u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(seed);
    hasher.finalize().into()
}

/// Format a deterministic RFC3339 expiry with an explicit UTC offset.
fn format_expiry(epoch_seconds: u64) -> Result<String, RelayBootstrapError> {
    let timestamp = i64::try_from(epoch_seconds).map_err(|_| RelayBootstrapError::Overflow)?;
    let datetime = time::OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| RelayBootstrapError::InvalidValue)?
        .to_offset(time::UtcOffset::UTC);
    let format = time::format_description::parse_borrowed::<2>(
        "[year]-[month]-[day]T[hour]:[minute]:[second][offset_hour sign:mandatory]:[offset_minute]",
    )
    .map_err(|_| RelayBootstrapError::InvalidValue)?;
    datetime
        .format(&format)
        .map_err(|_| RelayBootstrapError::InvalidValue)
}

/// Validate one source-aligned normalized session name.
fn validate_session(value: &str) -> Result<(), RelayBootstrapError> {
    if !crate::is_valid_hdb1_session(value) {
        return Err(RelayBootstrapError::InvalidSession);
    }
    Ok(())
}

/// Encode the private eight-byte marker as exactly sixteen lower-case hex characters.
fn encode_marker(marker: [u8; 8]) -> String {
    let mut output = String::with_capacity(16);
    for byte in marker {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

/// Parse exactly six ASCII digits without retaining caller-owned text.
fn parse_code(value: &str) -> Result<[u8; 6], RelayBootstrapError> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RelayBootstrapError::InvalidValue);
    }
    let mut code = [0_u8; 6];
    code.copy_from_slice(value.as_bytes());
    Ok(code)
}

/// Compare fixed-width codes without early exit on the first differing byte.
fn constant_time_equal(left: &[u8; 6], right: &[u8; 6]) -> bool {
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));

    /// Build one bounded Start request for a deterministic fake.
    fn request(session: &str) -> BootstrapStartRequest {
        BootstrapStartRequest::new(
            [1; 16],
            b"core-csr".to_vec(),
            CsrDigest::from_bytes([7; 32]).expect("app digest"),
            session,
            1,
            [8; 32],
        )
        .expect("request")
    }

    /// Build one fake verifier with non-secret fixture seed.
    fn verifier() -> RelayBootstrapVerifier {
        RelayBootstrapVerifier::new([9; 32]).expect("verifier")
    }

    /// Prove create/readback happens before a sanitized challenge is returned.
    // TEST:relay/src/bootstrap.rs[bootstrap_start_creates_hidden_workspace_and_challenge]
    #[test]
    fn bootstrap_start_creates_hidden_workspace_and_challenge() {
        let mut verifier = verifier();
        let challenge = verifier
            .start(PEER, request("default"), 100)
            .expect("start");
        assert_eq!(challenge.expires_at_epoch_seconds, 400);
        assert_eq!(verifier.active_count(), 1);
        assert_eq!(verifier.workspace_count(), 1);
        let code_text = std::str::from_utf8(
            verifier
                .attempts
                .values()
                .next()
                .expect("attempt")
                .code
                .as_ref()
                .expect("code"),
        )
        .expect("code text");
        let workspace = verifier
            .workspace
            .workspaces
            .values()
            .next()
            .expect("workspace");
        assert!(workspace.title.starts_with(code_text));
        assert!(workspace.title.contains("1970-01-01T00:06:40+00:00"));
        assert!(workspace.title.ends_with(" - herdr-dog verification"));
        assert_eq!(workspace.marker_text.len(), 16);
        assert!(
            workspace
                .marker_text
                .bytes()
                .all(|byte| { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) })
        );
        let debug = format!("{verifier:?}");
        assert!(!debug.contains("core-csr"));
        assert!(!debug.contains("100000"));
    }

    /// Prove hidden workspace readback failure does not retain an active attempt.
    // TEST:relay/src/bootstrap.rs[bootstrap_start_creates_hidden_workspace_and_challenge]
    #[test]
    fn bootstrap_start_rolls_back_readback_failure() {
        let mut verifier = verifier();
        verifier.fail_next_workspace_read();
        assert_eq!(
            verifier.start(PEER, request("default"), 100),
            Err(RelayBootstrapError::WorkspaceFailure)
        );
        assert_eq!(verifier.active_count(), 0);
        assert_eq!(verifier.workspace_count(), 0);
    }

    /// Prove a create/readback failure with a failed cleanup remains explicitly recoverable.
    // TEST:relay/src/bootstrap.rs[bootstrap_start_rolls_back_and_exposes_no_orphan]
    #[test]
    fn bootstrap_start_rolls_back_and_exposes_no_orphan() {
        let mut verifier = verifier();
        verifier.fail_next_workspace_read();
        verifier.fail_next_workspace_close();
        assert_eq!(
            verifier.start(PEER, request("default"), 100),
            Err(RelayBootstrapError::WorkspaceFailure)
        );
        assert_eq!(verifier.active_count(), 0);
        assert_eq!(verifier.workspace_count(), 1);
        assert_eq!(
            verifier.start(PEER, request("default"), 101),
            Err(RelayBootstrapError::AlreadyActive)
        );
        verifier
            .retry_orphaned_workspace("default")
            .expect("orphan cleanup");
        assert_eq!(verifier.workspace_count(), 0);
        assert!(verifier.start(PEER, request("default"), 102).is_ok());
    }

    /// Prove one code submission issues one public result and rejects duplicate submit.
    // TEST:relay/src/bootstrap.rs[bootstrap_code_is_single_use_and_issuance_is_idempotent]
    #[test]
    fn bootstrap_code_is_single_use_and_issuance_is_idempotent() {
        let mut verifier = verifier();
        let challenge = verifier
            .start(PEER, request("default"), 100)
            .expect("start");
        let code = std::str::from_utf8(
            verifier
                .attempts
                .get(&challenge.bootstrap_id)
                .expect("attempt")
                .code
                .as_ref()
                .expect("live code"),
        )
        .expect("code")
        .to_owned();
        let issued = verifier
            .submit(challenge.bootstrap_id, challenge.challenge, &code, 200)
            .expect("issue");
        assert_eq!(verifier.issued_count(), 1);
        assert_eq!(verifier.workspace_count(), 0);
        assert_eq!(
            verifier.state(challenge.bootstrap_id),
            Some(RelayBootstrapState::Issued)
        );
        assert!(
            verifier
                .attempts
                .get(&challenge.bootstrap_id)
                .expect("attempt")
                .code
                .is_none()
        );
        assert_eq!(
            verifier.submit(challenge.bootstrap_id, challenge.challenge, &code, 201),
            Err(RelayBootstrapError::AlreadyTerminal)
        );
        assert_eq!(verifier.issued_count(), 1);
        let binding = verifier
            .attempts
            .get(&challenge.bootstrap_id)
            .expect("attempt")
            .binding
            .clone();
        assert_eq!(
            verifier.reconcile(issued.approval_id, &binding, 202),
            Ok(BootstrapRecovery::Issued(issued))
        );
    }

    /// Prove wrong-code failures are bounded and terminal cleanup is required.
    // TEST:relay/src/bootstrap.rs[bootstrap_code_failure_limit_and_cleanup]
    #[test]
    fn bootstrap_code_failure_limit_and_cleanup() {
        let mut verifier = verifier();
        let challenge = verifier
            .start(PEER, request("default"), 100)
            .expect("start");
        for _ in 0..(MAX_CODE_FAILURES_PER_CHALLENGE - 1) {
            assert_eq!(
                verifier.submit(challenge.bootstrap_id, challenge.challenge, "000000", 101),
                Err(RelayBootstrapError::CodeMismatch)
            );
        }
        assert_eq!(
            verifier.submit(challenge.bootstrap_id, challenge.challenge, "000000", 101),
            Err(RelayBootstrapError::CodeRateLimited)
        );
        assert_eq!(verifier.active_count(), 0);
        assert_eq!(verifier.workspace_count(), 0);
        assert_eq!(
            verifier.state(challenge.bootstrap_id),
            Some(RelayBootstrapState::Rejected)
        );
    }

    /// Prove cleanup failure blocks a replacement workspace until explicit retry succeeds.
    // TEST:relay/src/bootstrap.rs[bootstrap_cleanup_failure_blocks_new_start]
    #[test]
    fn bootstrap_cleanup_failure_blocks_new_start() {
        let mut verifier = verifier();
        let challenge = verifier
            .start(PEER, request("default"), 100)
            .expect("start");
        for _ in 0..(MAX_CODE_FAILURES_PER_CHALLENGE - 1) {
            assert_eq!(
                verifier.submit(challenge.bootstrap_id, challenge.challenge, "000000", 101),
                Err(RelayBootstrapError::CodeMismatch)
            );
        }
        verifier.fail_next_workspace_close();
        assert_eq!(
            verifier.submit(challenge.bootstrap_id, challenge.challenge, "000000", 101),
            Err(RelayBootstrapError::CleanupPending)
        );
        assert_eq!(verifier.active_count(), 1);
        assert_eq!(
            verifier.start(PEER, request("default"), 102),
            Err(RelayBootstrapError::AlreadyActive)
        );
        verifier
            .retry_cleanup(challenge.bootstrap_id)
            .expect("cleanup");
        assert_eq!(verifier.active_count(), 0);
        assert_eq!(verifier.workspace_count(), 0);
    }

    /// Prove peer, session, and global caps are fail-closed.
    // TEST:relay/src/bootstrap.rs[bootstrap_limits_are_independent_and_fail_closed]
    #[test]
    fn bootstrap_limits_are_independent_and_fail_closed() {
        let mut verifier = verifier();
        let peer_one = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 11));
        for index in 0..MAX_PEER_STARTS {
            let session = format!("s{index}");
            let _ = verifier
                .start(peer_one, request(&session), 100 + index as u64)
                .expect("start");
        }
        assert_eq!(
            verifier.start(peer_one, request("rate-limited"), 110),
            Err(RelayBootstrapError::PeerRateLimited)
        );
        assert_eq!(verifier.active_count(), MAX_PEER_STARTS);
        assert!(verifier.start(PEER, request("new-peer"), 110).is_ok());
        assert_eq!(verifier.active_count(), MAX_PEER_STARTS + 1);
    }

    /// Prove exact binding mismatch cannot recover or expose an issued result.
    // TEST:relay/src/bootstrap.rs[bootstrap_reconcile_requires_exact_binding]
    #[test]
    fn bootstrap_reconcile_requires_exact_binding() {
        let mut verifier = verifier();
        let challenge = verifier
            .start(PEER, request("default"), 100)
            .expect("start");
        let attempt = verifier
            .attempts
            .get(&challenge.bootstrap_id)
            .expect("attempt");
        let approval_id = attempt.approval_id;
        let binding = attempt.binding.clone();
        let reconcile_payload = crate::bootstrap_wire::Hdb1ReconcilePayload::new(
            approval_id.0,
            binding.core_binding_digest.0,
            "default".to_owned(),
        )
        .expect("wire reconcile payload");
        reconcile_payload
            .validate()
            .expect("validate wire reconcile");
        let (wire_approval, wire_digest, wire_session) = reconcile_payload
            .decode_fields()
            .expect("decode wire reconcile");
        assert_eq!(
            verifier.reconcile_wire(wire_approval, wire_digest, &wire_session, 101),
            Ok(BootstrapRecovery::Pending {
                expires_at_epoch_seconds: 430
            })
        );
        let mismatched_payload = crate::bootstrap_wire::Hdb1ReconcilePayload::new(
            approval_id.0,
            [9; 32],
            "default".to_owned(),
        )
        .expect("mismatched wire reconcile payload");
        let (mismatched_approval, mismatched_digest, mismatched_session) = mismatched_payload
            .decode_fields()
            .expect("decode mismatched wire reconcile");
        assert_eq!(
            verifier.reconcile_wire(
                mismatched_approval,
                mismatched_digest,
                &mismatched_session,
                101,
            ),
            Err(RelayBootstrapError::AuthorityMismatch)
        );
        assert_eq!(
            verifier.reconcile(approval_id, &binding, 101),
            Ok(BootstrapRecovery::Pending {
                expires_at_epoch_seconds: 430
            })
        );
        let other = BootstrapBinding::from_core_csr(
            b"other",
            CsrDigest::from_bytes([7; 32]).expect("digest"),
            "default",
            1,
            [8; 32],
        )
        .expect("other binding");
        assert_eq!(
            verifier.reconcile(approval_id, &other, 101),
            Err(RelayBootstrapError::AuthorityMismatch)
        );
    }

    /// Prove expired cleanup remains pending until the hidden workspace is closed.
    // TEST:relay/src/bootstrap.rs[bootstrap_expiry_cleanup_failure_remains_pending]
    #[test]
    fn bootstrap_expiry_cleanup_failure_remains_pending() {
        let mut verifier = verifier();
        let challenge = verifier
            .start(PEER, request("default"), 100)
            .expect("start");
        let (approval_id, binding) = {
            let attempt = verifier
                .attempts
                .get(&challenge.bootstrap_id)
                .expect("attempt");
            (attempt.approval_id, attempt.binding.clone())
        };
        verifier.fail_next_workspace_close();
        assert_eq!(
            verifier.reconcile(approval_id, &binding, 431),
            Ok(BootstrapRecovery::Pending {
                expires_at_epoch_seconds: 430
            })
        );
        assert_eq!(
            verifier.state(challenge.bootstrap_id),
            Some(RelayBootstrapState::CleanupPending)
        );
        assert_eq!(verifier.active_count(), 1);
        verifier
            .retry_cleanup(challenge.bootstrap_id)
            .expect("cleanup");
        assert_eq!(verifier.active_count(), 0);
        assert_eq!(verifier.workspace_count(), 0);
    }

    /// Prove maintenance reaps abandoned attempts and releases issued recovery fences.
    // TEST:relay/src/bootstrap.rs[bootstrap_reap_releases_abandoned_and_issued_fences]
    #[test]
    fn bootstrap_reap_releases_abandoned_and_issued_fences() {
        let mut verifier = verifier();
        let abandoned = verifier
            .start(PEER, request("abandoned"), 100)
            .expect("abandoned start");
        assert_eq!(verifier.reap_expired(431), 1);
        assert_eq!(
            verifier.state(abandoned.bootstrap_id),
            Some(RelayBootstrapState::Expired)
        );
        assert_eq!(verifier.active_count(), 0);
        assert_eq!(verifier.workspace_count(), 0);

        let peer = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 11));
        let issued = verifier
            .start(peer, request("issued-reap"), 500)
            .expect("issued start");
        let code = {
            let attempt = verifier
                .attempts
                .get(&issued.bootstrap_id)
                .expect("issued attempt");
            std::str::from_utf8(attempt.code.as_ref().expect("code"))
                .expect("code")
                .to_owned()
        };
        verifier
            .submit(issued.bootstrap_id, issued.challenge, &code, 600)
            .expect("issue");
        assert_eq!(verifier.active_count(), 1);
        assert_eq!(verifier.reap_expired(600 + ISSUED_RECOVERY_TTL_SECS + 1), 1);
        assert_eq!(
            verifier.state(issued.bootstrap_id),
            Some(RelayBootstrapState::Expired)
        );
        assert_eq!(verifier.active_count(), 0);
        let replacement = verifier
            .start(
                peer,
                request("issued-replacement"),
                600 + ISSUED_RECOVERY_TTL_SECS + 2,
            )
            .expect("replacement start");
        assert_ne!(replacement.bootstrap_id, issued.bootstrap_id);
        assert_eq!(
            replacement.expires_at_epoch_seconds,
            600 + ISSUED_RECOVERY_TTL_SECS + 2 + BOOTSTRAP_CODE_TTL_SECS
        );
    }

    /// Prove issued recovery expiry and the global active-attempt bound.
    // TEST:relay/src/bootstrap.rs[bootstrap_issued_recovery_and_capacity_are_bounded]
    #[test]
    fn bootstrap_issued_recovery_and_capacity_are_bounded() {
        let mut verifier = verifier();
        let challenge = verifier.start(PEER, request("issued"), 100).expect("start");
        let (code, binding, approval_id) = {
            let attempt = verifier
                .attempts
                .get(&challenge.bootstrap_id)
                .expect("attempt");
            (
                std::str::from_utf8(attempt.code.as_ref().expect("code"))
                    .expect("code")
                    .to_owned(),
                attempt.binding.clone(),
                attempt.approval_id,
            )
        };
        verifier
            .submit(challenge.bootstrap_id, challenge.challenge, &code, 200)
            .expect("issue");
        assert_eq!(
            verifier.reconcile(approval_id, &binding, 200 + ISSUED_RECOVERY_TTL_SECS + 1,),
            Ok(BootstrapRecovery::Rejected { code: 2 })
        );
        assert_eq!(
            verifier.state(challenge.bootstrap_id),
            Some(RelayBootstrapState::Expired)
        );
        assert_eq!(verifier.active_count(), 0);

        let mut capacity_verifier =
            RelayBootstrapVerifier::new([9; 32]).expect("capacity verifier");
        for index in 0..MAX_ACTIVE_BOOTSTRAPS {
            let peer = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, index as u8 + 1));
            capacity_verifier
                .start(
                    peer,
                    request(&format!("capacity-{index}")),
                    100 + index as u64,
                )
                .expect("capacity start");
        }
        assert_eq!(
            capacity_verifier.start(PEER, request("capacity-overflow"), 200),
            Err(RelayBootstrapError::CapacityExhausted)
        );
    }

    /// Prove issuer failure is terminal after successful hidden-workspace cleanup.
    // TEST:relay/src/bootstrap.rs[bootstrap_issuance_failure_is_terminal]
    #[test]
    fn bootstrap_issuance_failure_is_terminal() {
        let mut verifier = verifier();
        let challenge = verifier
            .start(PEER, request("issuer-failure"), 100)
            .expect("start");
        let (code, binding, approval_id) = {
            let attempt = verifier
                .attempts
                .get(&challenge.bootstrap_id)
                .expect("attempt");
            (
                std::str::from_utf8(attempt.code.as_ref().expect("code"))
                    .expect("code")
                    .to_owned(),
                attempt.binding.clone(),
                attempt.approval_id,
            )
        };
        verifier.fail_next_issuance();
        assert_eq!(
            verifier.submit(challenge.bootstrap_id, challenge.challenge, &code, 200),
            Err(RelayBootstrapError::IssuanceFailed)
        );
        assert_eq!(
            verifier.state(challenge.bootstrap_id),
            Some(RelayBootstrapState::Rejected)
        );
        assert_eq!(verifier.active_count(), 0);
        assert_eq!(verifier.workspace_count(), 0);
        assert_eq!(
            verifier.reconcile(approval_id, &binding, 201),
            Ok(BootstrapRecovery::Rejected { code: 1 })
        );
        let next = verifier
            .start(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 11)),
                request("next"),
                202,
            )
            .expect("next start");
        assert_eq!(verifier.state(challenge.bootstrap_id), None);
        assert_eq!(verifier.active_count(), 1);
        assert_eq!(
            verifier.state(next.bootstrap_id),
            Some(RelayBootstrapState::AwaitingCode)
        );
    }
}
