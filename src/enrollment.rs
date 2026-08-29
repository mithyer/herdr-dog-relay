//! Schema-neutral Relay enrollment, allowlist, and update fakes for QRM-PROD-1 P1.
//!
//! The Relay-side contract contains only bounded public metadata and authority markers. It never
//! stores App private keys, raw CSR/certificate bytes, Herdr payloads, or production TLS state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum App identity length accepted by the Relay fake.
pub const MAX_APP_ID_BYTES: usize = 128;
/// Maximum raw CSR length accepted before bytes are discarded.
pub const MAX_CSR_BYTES: usize = 64 * 1024;
/// Fixed width for Relay challenges, CSR digests, and certificate fingerprints.
pub const AUTHORITY_BYTES: usize = 32;
/// Fixed width for Core authorization correlation IDs.
pub const AUTHORIZATION_ID_BYTES: usize = 16;
/// Maximum lifetime for one pending enrollment challenge.
pub const ENROLLMENT_TTL_SECS: u64 = 5 * 60;
/// Maximum allowed certificate validity in the fake.
pub const CERTIFICATE_VALIDITY_SECS: u64 = 90 * 24 * 60 * 60;
/// Only stable-latest update selector accepted by the fake.
pub const STABLE_LATEST_SELECTOR: &str = "stable-latest";

/// A bounded App identity supplied by Core after user-confirmed authorization.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct AppId(String);

impl AppId {
    /// Parse one bounded App identity.
    ///
    /// # Parameters
    /// * `value` - Stable App installation identity.
    ///
    /// # Returns
    /// A validated App identity or a sanitized enrollment error.
    // TEST:relay/src/enrollment.rs[tests::app_and_csr_bounds]
    pub fn new(value: impl Into<String>) -> Result<Self, EnrollmentError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_APP_ID_BYTES
            || value
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(EnrollmentError::InvalidAppId);
        }
        Ok(Self(value))
    }

    /// Borrow the identity for exact internal matching.
    ///
    /// # Returns
    /// The validated App identity text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AppId {
    /// Redact App identity from Relay diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AppId(<redacted>)")
    }
}

/// A public certificate or Core identity fingerprint.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Fingerprint([u8; AUTHORITY_BYTES]);

impl Fingerprint {
    /// Construct a non-zero fixed-width fingerprint.
    ///
    /// # Parameters
    /// * `bytes` - Public certificate or Core identity digest.
    ///
    /// # Returns
    /// A fingerprint or invalid metadata.
    pub fn from_bytes(bytes: [u8; AUTHORITY_BYTES]) -> Result<Self, EnrollmentError> {
        if bytes == [0; AUTHORITY_BYTES] {
            return Err(EnrollmentError::InvalidMetadata);
        }
        Ok(Self(bytes))
    }

    /// Return the fixed public fingerprint bytes for a wire response.
    pub const fn to_bytes(self) -> [u8; AUTHORITY_BYTES] {
        self.0
    }
}

impl fmt::Debug for Fingerprint {
    /// Report fingerprint presence without revealing identity bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Fingerprint(<redacted>)")
    }
}

/// A fixed-width Relay-minted challenge.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EnrollmentChallenge([u8; AUTHORITY_BYTES]);

impl EnrollmentChallenge {
    /// Construct a non-zero challenge.
    ///
    /// # Parameters
    /// * `bytes` - Relay-generated challenge bytes.
    ///
    /// # Returns
    /// A challenge or invalid metadata.
    pub fn from_bytes(bytes: [u8; AUTHORITY_BYTES]) -> Result<Self, EnrollmentError> {
        if bytes == [0; AUTHORITY_BYTES] {
            return Err(EnrollmentError::InvalidChallenge);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for EnrollmentChallenge {
    /// Redact challenge bytes from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentChallenge(<redacted>)")
    }
}

/// A fixed-width digest of discarded CSR bytes.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CsrDigest([u8; AUTHORITY_BYTES]);

impl CsrDigest {
    /// Construct a non-zero CSR digest.
    pub fn from_bytes(bytes: [u8; AUTHORITY_BYTES]) -> Result<Self, EnrollmentError> {
        if bytes == [0; AUTHORITY_BYTES] {
            return Err(EnrollmentError::InvalidCsr);
        }
        Ok(Self(bytes))
    }

    /// Borrow the digest for exact binding checks.
    pub(crate) const fn as_bytes(&self) -> &[u8; AUTHORITY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for CsrDigest {
    /// Redact CSR digest bytes from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CsrDigest(<redacted>)")
    }
}

/// Sanitized CSR metadata retained after Relay discards the raw CSR.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsrMetadata {
    /// App identity encoded by the CSR subject.
    app_id: AppId,
    /// Digest of the bounded CSR bytes.
    digest: CsrDigest,
    /// Original CSR length retained for audit bounds.
    byte_len: u32,
}

impl fmt::Debug for CsrMetadata {
    /// Retain only bounded shape metadata in diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CsrMetadata")
            .field("app_id", &"<redacted>")
            .field("digest_present", &true)
            .field("byte_len", &self.byte_len)
            .finish()
    }
}

impl CsrMetadata {
    /// Hash bounded CSR bytes and discard the raw representation.
    ///
    /// # Parameters
    /// * `app_id` - App identity expected in the CSR subject.
    /// * `bytes` - Candidate CSR bytes.
    ///
    /// # Returns
    /// Sanitized metadata or a bounded CSR error.
    // TEST:relay/src/enrollment.rs[tests::app_and_csr_bounds]
    pub fn from_bytes(app_id: AppId, bytes: &[u8]) -> Result<Self, EnrollmentError> {
        if bytes.is_empty() || bytes.len() > MAX_CSR_BYTES {
            return Err(EnrollmentError::InvalidCsr);
        }
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self::from_digest(
            app_id,
            CsrDigest::from_bytes(hasher.finalize().into())?,
            bytes.len(),
        )
    }

    /// Construct metadata from a digest computed by Core.
    ///
    /// # Parameters
    /// * `app_id` - App identity encoded by the CSR.
    /// * `digest` - Digest of the discarded CSR.
    /// * `byte_len` - Original bounded CSR length.
    ///
    /// # Returns
    /// Sanitized CSR metadata.
    pub fn from_digest(
        app_id: AppId,
        digest: CsrDigest,
        byte_len: usize,
    ) -> Result<Self, EnrollmentError> {
        if byte_len == 0 || byte_len > MAX_CSR_BYTES {
            return Err(EnrollmentError::InvalidCsr);
        }
        Ok(Self {
            app_id,
            digest,
            byte_len: byte_len as u32,
        })
    }

    /// Return the App identity bound by the CSR.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// Return the non-secret CSR digest.
    pub const fn digest(&self) -> CsrDigest {
        self.digest
    }

    /// Return the bounded original CSR length.
    pub const fn byte_len(&self) -> usize {
        self.byte_len as usize
    }
}

/// Core authorization presented after the existing Core client mTLS origin check.
#[derive(Clone, Eq, PartialEq)]
pub struct CoreAuthorization {
    /// Existing Core client certificate identity.
    core_identity: Fingerprint,
    /// Single-use Core authorization ID.
    authorization_id: [u8; AUTHORIZATION_ID_BYTES],
    /// Exact Profile identity represented as bounded opaque text.
    pairing_id: String,
    /// Stable Target identity represented as bounded opaque text.
    target_id: String,
    /// App identity authorized by Core.
    app_id: AppId,
    /// Relay-issued challenge bound to the authorization.
    challenge: EnrollmentChallenge,
    /// CSR digest bound to the authorization.
    csr_digest: CsrDigest,
    /// Core code proof digest; raw code never crosses this boundary.
    code_proof: CsrDigest,
    /// Profile configuration generation.
    configuration_generation: u64,
    /// Epoch-second expiry.
    expires_at_epoch_seconds: u64,
}

impl fmt::Debug for CoreAuthorization {
    /// Redact Core identity, IDs, challenge, proof and CSR metadata.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreAuthorization")
            .field("core_identity_present", &true)
            .field("authorization_id_present", &true)
            .field("pairing_id", &"<redacted>")
            .field("target_id", &"<redacted>")
            .field("app_id", &"<redacted>")
            .field("challenge_present", &true)
            .field("csr_digest_present", &true)
            .field("code_proof_present", &true)
            .field("configuration_generation", &self.configuration_generation)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

impl CoreAuthorization {
    /// Construct one bounded Core authorization fixture.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        core_identity: Fingerprint,
        authorization_id: [u8; AUTHORIZATION_ID_BYTES],
        pairing_id: impl Into<String>,
        target_id: impl Into<String>,
        app_id: AppId,
        challenge: EnrollmentChallenge,
        csr_digest: CsrDigest,
        code_proof: CsrDigest,
        configuration_generation: u64,
        expires_at_epoch_seconds: u64,
    ) -> Result<Self, EnrollmentError> {
        let pairing_id = bounded_identity(pairing_id.into())?;
        let target_id = bounded_identity(target_id.into())?;
        if authorization_id == [0; AUTHORIZATION_ID_BYTES]
            || configuration_generation == 0
            || expires_at_epoch_seconds == 0
        {
            return Err(EnrollmentError::InvalidMetadata);
        }
        Ok(Self {
            core_identity,
            authorization_id,
            pairing_id,
            target_id,
            app_id,
            challenge,
            csr_digest,
            code_proof,
            configuration_generation,
            expires_at_epoch_seconds,
        })
    }

    /// Return the authenticated Core identity.
    pub const fn core_identity(&self) -> Fingerprint {
        self.core_identity
    }

    /// Return the single-use authorization ID.
    pub const fn authorization_id(&self) -> [u8; AUTHORIZATION_ID_BYTES] {
        self.authorization_id
    }

    /// Return the Profile identity.
    pub fn pairing_id(&self) -> &str {
        &self.pairing_id
    }

    /// Return the Target identity.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Return the authorized App identity.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// Return the Relay challenge.
    pub const fn challenge(&self) -> EnrollmentChallenge {
        self.challenge
    }

    /// Return the CSR digest.
    pub const fn csr_digest(&self) -> CsrDigest {
        self.csr_digest
    }

    /// Return the Core code proof digest.
    pub const fn code_proof(&self) -> CsrDigest {
        self.code_proof
    }

    /// Return the Profile configuration generation.
    pub const fn configuration_generation(&self) -> u64 {
        self.configuration_generation
    }

    /// Return the authorization expiry epoch second.
    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.expires_at_epoch_seconds
    }
}

/// One sanitized Core-to-Relay enrollment submission.
#[derive(Clone, Eq, PartialEq)]
pub struct EnrollmentSubmission {
    /// Core authorization bound to challenge, CSR and generation.
    authorization: CoreAuthorization,
    /// Sanitized CSR metadata.
    csr: CsrMetadata,
}

impl fmt::Debug for EnrollmentSubmission {
    /// Redact authorization and CSR identity data from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentSubmission")
            .field("authorization", &self.authorization)
            .field("csr", &self.csr)
            .finish()
    }
}

impl EnrollmentSubmission {
    /// Construct one submission after Core has validated code proof.
    ///
    /// # Parameters
    /// * `authorization` - Existing Core mTLS-bound authorization.
    /// * `csr` - Sanitized CSR metadata.
    ///
    /// # Returns
    /// A submission or an exact CSR mismatch error.
    pub fn new(
        authorization: CoreAuthorization,
        csr: CsrMetadata,
    ) -> Result<Self, EnrollmentError> {
        if authorization.app_id() != csr.app_id() || authorization.csr_digest() != csr.digest() {
            return Err(EnrollmentError::CsrMismatch);
        }
        Ok(Self { authorization, csr })
    }

    /// Borrow the authorization.
    pub fn authorization(&self) -> &CoreAuthorization {
        &self.authorization
    }

    /// Borrow sanitized CSR metadata.
    pub fn csr(&self) -> &CsrMetadata {
        &self.csr
    }
}

/// Certificate metadata returned by the fake Intermediate CA.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateMetadata {
    /// Enrolled App identity.
    app_id: AppId,
    /// Public certificate fingerprint.
    fingerprint: Fingerprint,
    /// Public serial number.
    serial: u64,
    /// Allowlist generation at issuance.
    allowlist_generation: u64,
    /// Validity start epoch second.
    not_before_epoch_seconds: u64,
    /// Validity end epoch second.
    not_after_epoch_seconds: u64,
}

impl fmt::Debug for CertificateMetadata {
    /// Redact fingerprint and all certificate bytes from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateMetadata")
            .field("app_id", &"<redacted>")
            .field("fingerprint_present", &true)
            .field("serial", &self.serial)
            .field("allowlist_generation", &self.allowlist_generation)
            .field("not_before_epoch_seconds", &self.not_before_epoch_seconds)
            .field("not_after_epoch_seconds", &self.not_after_epoch_seconds)
            .finish()
    }
}

impl CertificateMetadata {
    /// Constructs public certificate metadata after a real or fake issuer succeeds.
    pub fn new(
        app_id: AppId,
        fingerprint: Fingerprint,
        serial: u64,
        allowlist_generation: u64,
        not_before_epoch_seconds: u64,
        not_after_epoch_seconds: u64,
    ) -> Result<Self, EnrollmentError> {
        if serial == 0
            || allowlist_generation == 0
            || not_before_epoch_seconds == 0
            || not_after_epoch_seconds <= not_before_epoch_seconds
        {
            return Err(EnrollmentError::InvalidMetadata);
        }
        Ok(Self {
            app_id,
            fingerprint,
            serial,
            allowlist_generation,
            not_before_epoch_seconds,
            not_after_epoch_seconds,
        })
    }

    /// Return the enrolled App identity.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// Return the public certificate fingerprint.
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Return the public serial number.
    pub const fn serial(&self) -> u64 {
        self.serial
    }

    /// Return the allowlist generation.
    pub const fn allowlist_generation(&self) -> u64 {
        self.allowlist_generation
    }

    /// Return the certificate validity start epoch second.
    pub const fn not_before_epoch_seconds(&self) -> u64 {
        self.not_before_epoch_seconds
    }

    /// Return the certificate validity end epoch second.
    pub const fn not_after_epoch_seconds(&self) -> u64 {
        self.not_after_epoch_seconds
    }
}

/// Role granted by a successful App enrollment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowlistRole {
    /// May request only the fixed stable-latest update.
    RelayUpdateAdmin,
}

/// State used by normal QRM and update authorization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowlistState {
    /// Certificate is waiting for protected App certificate-chain persistence confirmation.
    Pending,
    /// Certificate may enter normal QRM.
    Active,
    /// Certificate is denied and matching connections must close.
    Revoked,
}

/// Persistable non-secret allowlist entry.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    /// App identity.
    app_id: AppId,
    /// Public certificate identity.
    fingerprint: Fingerprint,
    /// Bounded role.
    role: AllowlistRole,
    /// Current state.
    state: AllowlistState,
    /// Allowlist generation.
    generation: u64,
    /// Certificate expiry.
    not_after_epoch_seconds: u64,
}

impl fmt::Debug for AllowlistEntry {
    /// Redact App/fingerprint values while keeping authorization state visible.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AllowlistEntry")
            .field("app_id", &"<redacted>")
            .field("fingerprint_present", &true)
            .field("role", &self.role)
            .field("state", &self.state)
            .field("generation", &self.generation)
            .finish()
    }
}

impl AllowlistEntry {
    /// Return the App identity.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// Return the public certificate fingerprint.
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Return the role.
    pub const fn role(&self) -> AllowlistRole {
        self.role
    }

    /// Return the state.
    pub const fn state(&self) -> AllowlistState {
        self.state
    }

    /// Return the allowlist generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the certificate validity end epoch second.
    pub const fn not_after_epoch_seconds(&self) -> u64 {
        self.not_after_epoch_seconds
    }
}

/// Result of a one-time enrollment fake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentOutcome {
    /// Public certificate metadata and active allowlist entry were created.
    Issued {
        /// Sanitized public certificate metadata.
        certificate: CertificateMetadata,
        /// Active allowlist entry written atomically with the certificate.
        entry: AllowlistEntry,
    },
    /// No certificate or allowlist entry was retained.
    Rejected(EnrollmentError),
}

/// Stable Relay enrollment/update error categories.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EnrollmentError {
    /// App identity is invalid.
    InvalidAppId,
    /// Challenge is unknown or malformed.
    InvalidChallenge,
    /// The challenge has expired.
    ChallengeExpired,
    /// CSR is absent or oversized.
    InvalidCsr,
    /// CSR and authorization do not match.
    CsrMismatch,
    /// Core authorization does not match the pending challenge.
    AuthorizationMismatch,
    /// Core authorization was reused.
    AuthorizationUsed,
    /// Profile generation is invalid.
    InvalidGeneration,
    /// Public metadata is invalid.
    InvalidMetadata,
    /// App identity/fingerprint already exists.
    DuplicateEnrollment,
    /// Allowlist persistence failed atomically.
    AllowlistPersistence,
    /// Entry was not found.
    AllowlistNotFound,
    /// Entry was already revoked.
    AlreadyRevoked,
    /// Caller is not an active update admin.
    UpdateUnauthorized,
    /// Another update holds the lock.
    UpdateBusy,
    /// The fake update worker failed.
    UpdateFailed,
}

impl fmt::Display for EnrollmentError {
    /// Format stable text without caller-controlled IDs or raw material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidAppId => "App identity is invalid",
            Self::InvalidChallenge => "enrollment challenge is invalid",
            Self::ChallengeExpired => "enrollment challenge expired",
            Self::InvalidCsr => "CSR is invalid or oversized",
            Self::CsrMismatch => "CSR binding mismatch",
            Self::AuthorizationMismatch => "Core authorization mismatch",
            Self::AuthorizationUsed => "Core authorization already used",
            Self::InvalidGeneration => "configuration generation is invalid",
            Self::InvalidMetadata => "enrollment metadata is invalid",
            Self::DuplicateEnrollment => "App enrollment already exists",
            Self::AllowlistPersistence => "allowlist persistence failed",
            Self::AllowlistNotFound => "allowlist entry was not found",
            Self::AlreadyRevoked => "allowlist entry already revoked",
            Self::UpdateUnauthorized => "Relay update authorization rejected",
            Self::UpdateBusy => "Relay update already running",
            Self::UpdateFailed => "Relay update failed",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for EnrollmentError {}

/// In-memory allowlist with atomic generation/revocation semantics.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistRegistry {
    /// Current generation invalidating revoked connections.
    generation: u64,
    /// Entries keyed by App identity.
    entries: BTreeMap<AppId, AllowlistEntry>,
}

impl Default for AllowlistRegistry {
    /// Construct an empty registry at generation one.
    fn default() -> Self {
        Self::new()
    }
}

impl AllowlistRegistry {
    /// Construct an empty allowlist.
    pub fn new() -> Self {
        Self {
            generation: 1,
            entries: BTreeMap::new(),
        }
    }

    /// Return the current allowlist generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Atomically add one pending update-admin entry.
    ///
    /// The entry cannot enter normal QRM or request updates until `activate` is called after
    /// the App confirms protected certificate-chain persistence.
    pub fn enroll_pending(
        &mut self,
        certificate: CertificateMetadata,
    ) -> Result<AllowlistEntry, EnrollmentError> {
        self.enroll_with_state(certificate, AllowlistState::Pending)
    }

    /// Atomically add one active update-admin entry.
    ///
    /// # Parameters
    /// * `certificate` - Public certificate metadata from the fake CA.
    ///
    /// # Returns
    /// Stored entry or a duplicate/persistence error; errors do not mutate state.
    // TEST:relay/src/enrollment.rs[tests::revocation_preserves_sibling]
    pub fn enroll(
        &mut self,
        certificate: CertificateMetadata,
    ) -> Result<AllowlistEntry, EnrollmentError> {
        self.enroll_with_state(certificate, AllowlistState::Active)
    }

    /// Add one entry with an explicit pre-activation state.
    fn enroll_with_state(
        &mut self,
        certificate: CertificateMetadata,
        state: AllowlistState,
    ) -> Result<AllowlistEntry, EnrollmentError> {
        if self.entries.contains_key(certificate.app_id())
            || self.entries.values().any(|entry| {
                entry.fingerprint() == certificate.fingerprint()
                    && entry.state() == AllowlistState::Active
            })
        {
            return Err(EnrollmentError::DuplicateEnrollment);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(EnrollmentError::AllowlistPersistence)?;
        let entry = AllowlistEntry {
            app_id: certificate.app_id().clone(),
            fingerprint: certificate.fingerprint(),
            role: AllowlistRole::RelayUpdateAdmin,
            state,
            generation,
            not_after_epoch_seconds: certificate.not_after_epoch_seconds,
        };
        self.generation = generation;
        self.entries.insert(entry.app_id.clone(), entry.clone());
        Ok(entry)
    }

    /// Activate one pending App identity after protected certificate persistence is confirmed.
    pub fn activate(
        &mut self,
        app_id: &AppId,
        fingerprint: Fingerprint,
    ) -> Result<AllowlistEntry, EnrollmentError> {
        let entry = self
            .entries
            .get_mut(app_id)
            .ok_or(EnrollmentError::AllowlistNotFound)?;
        if entry.state != AllowlistState::Pending || entry.fingerprint != fingerprint {
            return Err(EnrollmentError::UpdateUnauthorized);
        }
        entry.state = AllowlistState::Active;
        Ok(entry.clone())
    }

    /// Revoke one App and close only its matching authority while siblings survive.
    ///
    /// # Parameters
    /// * `app_id` - App selected by a protected local operator path.
    ///
    /// # Returns
    /// New allowlist generation or a stable lookup/state error.
    // TEST:relay/src/enrollment.rs[tests::revocation_preserves_sibling]
    pub fn revoke(&mut self, app_id: &AppId) -> Result<u64, EnrollmentError> {
        let entry = self
            .entries
            .get(app_id)
            .ok_or(EnrollmentError::AllowlistNotFound)?;
        if entry.state() == AllowlistState::Revoked {
            return Err(EnrollmentError::AlreadyRevoked);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(EnrollmentError::AllowlistPersistence)?;
        for value in self.entries.values_mut() {
            value.generation = generation;
            if value.app_id == *app_id {
                value.state = AllowlistState::Revoked;
            }
        }
        self.generation = generation;
        Ok(generation)
    }

    /// Check normal QRM admission for one certificate identity at the current wall-clock epoch.
    pub fn allows_qrm(&self, fingerprint: Fingerprint) -> bool {
        self.allows_qrm_at(fingerprint, current_epoch_seconds())
    }

    /// Check normal QRM admission against an explicit epoch for deterministic tests.
    pub fn allows_qrm_at(&self, fingerprint: Fingerprint, now_epoch_seconds: u64) -> bool {
        self.entries.values().any(|entry| {
            entry.fingerprint() == fingerprint
                && entry.state() == AllowlistState::Active
                && entry.not_after_epoch_seconds() > now_epoch_seconds
        })
    }

    /// Check stable-latest update authorization at the current wall-clock epoch.
    pub fn authorize_update(&self, fingerprint: Fingerprint) -> Result<(), EnrollmentError> {
        self.authorize_update_at(fingerprint, current_epoch_seconds())
    }

    /// Check stable-latest update authorization against an explicit epoch for deterministic tests.
    pub fn authorize_update_at(
        &self,
        fingerprint: Fingerprint,
        now_epoch_seconds: u64,
    ) -> Result<(), EnrollmentError> {
        if self.entries.values().any(|entry| {
            entry.fingerprint() == fingerprint
                && entry.state() == AllowlistState::Active
                && entry.role() == AllowlistRole::RelayUpdateAdmin
                && entry.not_after_epoch_seconds() > now_epoch_seconds
        }) {
            Ok(())
        } else {
            Err(EnrollmentError::UpdateUnauthorized)
        }
    }

    /// Return one entry for deterministic tests and local reconciliation.
    pub fn entry(&self, app_id: &AppId) -> Option<&AllowlistEntry> {
        self.entries.get(app_id)
    }

    /// Return all non-secret entries for persistence and bounded local inspection.
    pub fn entries(&self) -> impl Iterator<Item = &AllowlistEntry> {
        self.entries.values()
    }

    /// Validate a deserialized registry before it can authorize normal QRM.
    pub fn validate_persisted(&self) -> Result<(), EnrollmentError> {
        if self.generation == 0
            || self
                .entries
                .values()
                .any(|entry| entry.generation() == 0 || entry.not_after_epoch_seconds() == 0)
        {
            return Err(EnrollmentError::AllowlistPersistence);
        }
        Ok(())
    }
}

/// Deterministic metadata-only Root/Intermediate CA fake.
#[derive(Clone)]
pub struct FakeCertificateAuthority {
    /// Dedicated fake Root generation.
    root_generation: u64,
    /// Test-only Intermediate seed standing in for a private key.
    intermediate_seed: [u8; AUTHORITY_BYTES],
    /// Next deterministic serial.
    next_serial: u64,
}

impl fmt::Debug for FakeCertificateAuthority {
    /// Redact fake signing material from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeCertificateAuthority")
            .field("root_generation", &self.root_generation)
            .field("intermediate_seed_present", &true)
            .field("next_serial", &self.next_serial)
            .finish()
    }
}

impl FakeCertificateAuthority {
    /// Construct a metadata-only CA fake.
    ///
    /// # Parameters
    /// * `root_generation` - Positive fake Root generation.
    /// * `intermediate_seed` - Non-secret deterministic test seed.
    ///
    /// # Returns
    /// A fake CA with no production key material.
    pub fn new(
        root_generation: u64,
        intermediate_seed: [u8; AUTHORITY_BYTES],
    ) -> Result<Self, EnrollmentError> {
        if root_generation == 0 || intermediate_seed == [0; AUTHORITY_BYTES] {
            return Err(EnrollmentError::InvalidMetadata);
        }
        Ok(Self {
            root_generation,
            intermediate_seed,
            next_serial: 1,
        })
    }

    /// Issue public certificate metadata without returning certificate bytes.
    ///
    /// # Parameters
    /// * `csr` - Sanitized CSR metadata.
    /// * `allowlist_generation` - Generation written with the entry.
    /// * `now_epoch_seconds` - Validity start.
    ///
    /// # Returns
    /// Bounded certificate metadata.
    // TEST:relay/src/enrollment.rs[tests::certificate_fake_redacts_material]
    pub fn issue(
        &mut self,
        csr: &CsrMetadata,
        allowlist_generation: u64,
        now_epoch_seconds: u64,
    ) -> Result<CertificateMetadata, EnrollmentError> {
        if allowlist_generation == 0 || now_epoch_seconds == 0 {
            return Err(EnrollmentError::InvalidMetadata);
        }
        let serial = self.next_serial;
        self.next_serial = self
            .next_serial
            .checked_add(1)
            .ok_or(EnrollmentError::InvalidMetadata)?;
        let mut hasher = Sha256::new();
        hasher.update(b"herdr-dog relay fake certificate v1");
        hasher.update(self.root_generation.to_be_bytes());
        hasher.update(self.intermediate_seed);
        hasher.update(serial.to_be_bytes());
        hasher.update(csr.digest().as_bytes());
        let fingerprint = Fingerprint::from_bytes(hasher.finalize().into())?;
        let not_after = now_epoch_seconds
            .checked_add(CERTIFICATE_VALIDITY_SECS)
            .ok_or(EnrollmentError::InvalidMetadata)?;
        Ok(CertificateMetadata {
            app_id: csr.app_id().clone(),
            fingerprint,
            serial,
            allowlist_generation,
            not_before_epoch_seconds: now_epoch_seconds,
            not_after_epoch_seconds: not_after,
        })
    }
}

/// Deterministic Relay challenge/issuance fake.
#[derive(Clone)]
pub struct FakeRelayEnrollment {
    /// Deterministic challenge seed.
    seed: [u8; AUTHORITY_BYTES],
    /// Challenge counter.
    next_counter: u64,
    /// Pending challenges and their Core identity binding.
    pending: BTreeMap<EnrollmentChallenge, PendingChallenge>,
    /// Consumed authorization IDs.
    consumed: BTreeSet<[u8; AUTHORIZATION_ID_BYTES]>,
    /// Metadata-only certificate authority.
    authority: FakeCertificateAuthority,
    /// Atomic active/revoked allowlist.
    allowlist: AllowlistRegistry,
}

impl fmt::Debug for FakeRelayEnrollment {
    /// Report bounded fake state without challenge, identity, or certificate material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeRelayEnrollment")
            .field("pending_count", &self.pending.len())
            .field("consumed_count", &self.consumed.len())
            .field("allowlist_generation", &self.allowlist.generation())
            .finish()
    }
}

#[derive(Clone)]
struct PendingChallenge {
    /// Authenticated Core identity.
    core_identity: Fingerprint,
    /// Exact Profile identity.
    pairing_id: String,
    /// Stable Target identity.
    target_id: String,
    /// App identity.
    app_id: AppId,
    /// Profile generation.
    configuration_generation: u64,
    /// Challenge creation epoch second.
    created_at_epoch_seconds: u64,
}

impl FakeRelayEnrollment {
    /// Construct a deterministic Relay enrollment fake.
    ///
    /// # Parameters
    /// * `seed` - Non-secret challenge seed.
    /// * `ca_seed` - Non-secret fake Intermediate seed.
    ///
    /// # Returns
    /// A fake with empty pending challenges and allowlist.
    pub fn new(
        seed: [u8; AUTHORITY_BYTES],
        ca_seed: [u8; AUTHORITY_BYTES],
    ) -> Result<Self, EnrollmentError> {
        if seed == [0; AUTHORITY_BYTES] {
            return Err(EnrollmentError::InvalidChallenge);
        }
        Ok(Self {
            seed,
            next_counter: 1,
            pending: BTreeMap::new(),
            consumed: BTreeSet::new(),
            authority: FakeCertificateAuthority::new(1, ca_seed)?,
            allowlist: AllowlistRegistry::new(),
        })
    }

    /// Mint a single-use challenge after the Core mTLS origin is authenticated.
    ///
    /// # Parameters
    /// * `core_identity` - Existing active Core client certificate identity.
    /// * `pairing_id` - Exact Profile identity.
    /// * `target_id` - Stable Target identity.
    /// * `app_id` - App installation identity.
    /// * `configuration_generation` - Current Profile generation.
    /// * `now_epoch_seconds` - Current fake time.
    ///
    /// # Returns
    /// Relay challenge or a bounded metadata error.
    // TEST:relay/src/enrollment.rs[tests::challenge_binds_core_and_target]
    pub fn begin(
        &mut self,
        core_identity: Fingerprint,
        pairing_id: impl Into<String>,
        target_id: impl Into<String>,
        app_id: AppId,
        configuration_generation: u64,
        now_epoch_seconds: u64,
    ) -> Result<EnrollmentChallenge, EnrollmentError> {
        let pairing_id = bounded_identity(pairing_id.into())?;
        let target_id = bounded_identity(target_id.into())?;
        if configuration_generation == 0 || now_epoch_seconds == 0 {
            return Err(EnrollmentError::InvalidGeneration);
        }
        let counter = self.next_counter;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(EnrollmentError::InvalidChallenge)?;
        let mut hasher = Sha256::new();
        hasher.update(b"herdr-dog relay enrollment challenge v1");
        hasher.update(self.seed);
        hasher.update(counter.to_be_bytes());
        hasher.update(core_identity.0);
        hasher.update(pairing_id.as_bytes());
        hasher.update(target_id.as_bytes());
        hasher.update(app_id.as_str().as_bytes());
        let challenge = EnrollmentChallenge::from_bytes(hasher.finalize().into())?;
        self.pending.insert(
            challenge,
            PendingChallenge {
                core_identity,
                pairing_id,
                target_id,
                app_id,
                configuration_generation,
                created_at_epoch_seconds: now_epoch_seconds,
            },
        );
        Ok(challenge)
    }

    /// Accept one single-use Core-authorized CSR and atomically enroll its App.
    ///
    /// # Parameters
    /// * `submission` - Core authorization and sanitized CSR metadata.
    /// * `now_epoch_seconds` - Current fake time.
    ///
    /// # Returns
    /// Issued public metadata or a terminal rejection with no retained certificate.
    // TEST:relay/src/enrollment.rs[tests::challenge_binds_core_and_target]
    pub fn accept(
        &mut self,
        submission: EnrollmentSubmission,
        now_epoch_seconds: u64,
    ) -> EnrollmentOutcome {
        let authorization = submission.authorization();
        let Some(pending) = self.pending.remove(&authorization.challenge()) else {
            return EnrollmentOutcome::Rejected(EnrollmentError::InvalidChallenge);
        };
        if now_epoch_seconds.saturating_sub(pending.created_at_epoch_seconds) > ENROLLMENT_TTL_SECS
        {
            return EnrollmentOutcome::Rejected(EnrollmentError::ChallengeExpired);
        }
        if pending.core_identity != authorization.core_identity()
            || pending.pairing_id != authorization.pairing_id()
            || pending.target_id != authorization.target_id()
            || pending.app_id != *authorization.app_id()
            || pending.configuration_generation != authorization.configuration_generation()
            || authorization.expires_at_epoch_seconds() < now_epoch_seconds
            || authorization.csr_digest() != submission.csr().digest()
            || authorization.code_proof().as_bytes() == &[0; AUTHORITY_BYTES]
        {
            return EnrollmentOutcome::Rejected(EnrollmentError::AuthorizationMismatch);
        }
        if !self.consumed.insert(authorization.authorization_id()) {
            return EnrollmentOutcome::Rejected(EnrollmentError::AuthorizationUsed);
        }
        let generation = self.allowlist.generation();
        let certificate =
            match self
                .authority
                .issue(submission.csr(), generation, now_epoch_seconds)
            {
                Ok(certificate) => certificate,
                Err(error) => return EnrollmentOutcome::Rejected(error),
            };
        match self.allowlist.enroll(certificate.clone()) {
            Ok(entry) => EnrollmentOutcome::Issued { certificate, entry },
            Err(error) => EnrollmentOutcome::Rejected(error),
        }
    }

    /// Return the current allowlist for normal-QRM/update assertions.
    pub fn allowlist(&self) -> &AllowlistRegistry {
        &self.allowlist
    }

    /// Mutably access the allowlist only inside the protected fake/test boundary.
    pub fn allowlist_mut(&mut self) -> &mut AllowlistRegistry {
        &mut self.allowlist
    }
}

/// Fixed selector for the only supported update operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateSelector {
    /// Resolve stable latest from the fixed release source.
    StableLatest,
}

/// Bounded Relay update request with no URL, shell, or arbitrary version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRequest {
    /// Fixed request correlation ID.
    pub request_id: [u8; AUTHORIZATION_ID_BYTES],
    /// Stable-latest selector only.
    pub selector: UpdateSelector,
    /// Caller certificate fingerprint.
    pub caller: Fingerprint,
}

/// Sanitized update status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    /// Update lock acquired and worker running.
    Running,
    /// Replacement completed.
    Succeeded,
    /// Replacement failed and rollback is required/complete.
    Failed,
    /// Response was lost; no automatic retry is allowed.
    Unknown,
}

/// Deterministic update worker fake.
#[derive(Clone, Debug)]
pub struct FakeUpdateWorker {
    /// Whether the one update lock is held.
    running: bool,
    /// Next completion result.
    next: UpdateStatus,
}

impl Default for FakeUpdateWorker {
    /// Construct an idle worker with a successful next result.
    fn default() -> Self {
        Self {
            running: false,
            next: UpdateStatus::Succeeded,
        }
    }
}

impl FakeUpdateWorker {
    /// Construct an idle worker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the next deterministic completion result.
    pub fn set_next(&mut self, next: UpdateStatus) {
        self.next = next;
    }

    /// Start one authorized stable-latest update.
    ///
    /// # Parameters
    /// * `request` - Bounded fixed-selector request.
    /// * `allowlist` - Active certificate/role authority.
    ///
    /// # Returns
    /// Running status or sanitized authorization/busy failure.
    // TEST:relay/src/enrollment.rs[tests::update_admin_and_lock]
    pub fn start(
        &mut self,
        request: &UpdateRequest,
        allowlist: &AllowlistRegistry,
    ) -> Result<UpdateStatus, EnrollmentError> {
        self.start_at(request, allowlist, current_epoch_seconds())
    }

    /// Start one update against an explicit epoch for deterministic contract tests.
    ///
    /// # Parameters
    /// * `request` - Bounded fixed-selector request.
    /// * `allowlist` - Active certificate/role authority.
    /// * `now_epoch_seconds` - Clock value used for certificate expiry.
    ///
    /// # Returns
    /// Running status or sanitized authorization/busy failure.
    pub fn start_at(
        &mut self,
        request: &UpdateRequest,
        allowlist: &AllowlistRegistry,
        now_epoch_seconds: u64,
    ) -> Result<UpdateStatus, EnrollmentError> {
        if request.selector != UpdateSelector::StableLatest {
            return Err(EnrollmentError::UpdateUnauthorized);
        }
        allowlist.authorize_update_at(request.caller, now_epoch_seconds)?;
        if self.running {
            return Err(EnrollmentError::UpdateBusy);
        }
        self.running = true;
        Ok(UpdateStatus::Running)
    }

    /// Complete the current fake update without retrying it.
    pub fn complete(&mut self) -> Result<UpdateStatus, EnrollmentError> {
        if !self.running {
            return Err(EnrollmentError::UpdateBusy);
        }
        self.running = false;
        Ok(self.next)
    }
}

/// Returns the current epoch second, failing closed to the maximum value on clock failure.
fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |duration| duration.as_secs())
}

/// Validate a bounded opaque Profile/Target identity.
fn bounded_identity(value: String) -> Result<String, EnrollmentError> {
    if value.is_empty()
        || value.len() > MAX_APP_ID_BYTES
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(EnrollmentError::InvalidMetadata);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build deterministic public identities for Relay fake tests.
    // TEST:relay/src/enrollment.rs[tests::all]
    fn identities() -> (Fingerprint, AppId) {
        (
            Fingerprint::from_bytes([1; AUTHORITY_BYTES]).unwrap(),
            AppId::new("app-a").unwrap(),
        )
    }

    /// Build a deterministic Core authorization and CSR pair.
    // TEST:relay/src/enrollment.rs[tests::all]
    fn submission(
        core_identity: Fingerprint,
        challenge: EnrollmentChallenge,
        app_id: &AppId,
        suffix: &[u8],
    ) -> EnrollmentSubmission {
        let csr = CsrMetadata::from_bytes(app_id.clone(), suffix).unwrap();
        let mut authorization_id = [0_u8; AUTHORIZATION_ID_BYTES];
        authorization_id[0] = *suffix.last().expect("test suffix is non-empty");
        let authorization = CoreAuthorization::new(
            core_identity,
            authorization_id,
            "pair-a",
            "target-a",
            app_id.clone(),
            challenge,
            csr.digest(),
            CsrDigest::from_bytes([8; AUTHORITY_BYTES]).unwrap(),
            1,
            1_300,
        )
        .unwrap();
        EnrollmentSubmission::new(authorization, csr).unwrap()
    }

    // TEST:relay/src/enrollment.rs[tests::app_and_csr_bounds]
    #[test]
    fn app_and_csr_bounds() {
        assert!(AppId::new("app-a").is_ok());
        assert!(AppId::new(" ").is_err());
        let app = AppId::new("app-a").unwrap();
        assert!(CsrMetadata::from_bytes(app.clone(), &[]).is_err());
        assert!(CsrMetadata::from_bytes(app, &[0; MAX_CSR_BYTES + 1]).is_err());
    }

    // TEST:relay/src/enrollment.rs[tests::challenge_binds_core_and_target]
    #[test]
    fn challenge_binds_core_and_target() {
        let (core_identity, app_id) = identities();
        let mut fake =
            FakeRelayEnrollment::new([2; AUTHORITY_BYTES], [3; AUTHORITY_BYTES]).unwrap();
        let challenge = fake
            .begin(
                core_identity,
                "pair-a",
                "target-a",
                app_id.clone(),
                1,
                1_000,
            )
            .unwrap();
        let accepted = fake.accept(
            submission(core_identity, challenge, &app_id, b"csr-a"),
            1_001,
        );
        let (certificate, entry) = match accepted {
            EnrollmentOutcome::Issued { certificate, entry } => (certificate, entry),
            EnrollmentOutcome::Rejected(error) => panic!("unexpected rejection: {error}"),
        };
        assert_eq!(entry.app_id(), &app_id);
        assert_eq!(certificate.app_id(), &app_id);
        assert!(fake.allowlist().allows_qrm_at(entry.fingerprint(), 1_001));

        let wrong_core = Fingerprint::from_bytes([4; AUTHORITY_BYTES]).unwrap();
        let other_challenge = fake
            .begin(
                wrong_core,
                "pair-a",
                "target-a",
                AppId::new("app-b").unwrap(),
                1,
                1_000,
            )
            .unwrap();
        let rejected = fake.accept(
            submission(
                core_identity,
                other_challenge,
                &AppId::new("app-b").unwrap(),
                b"csr-b",
            ),
            1_001,
        );
        assert_eq!(
            rejected,
            EnrollmentOutcome::Rejected(EnrollmentError::AuthorizationMismatch)
        );
    }

    // TEST:relay/src/enrollment.rs[tests::revocation_preserves_sibling]
    #[test]
    fn revocation_preserves_sibling() {
        let core_identity = Fingerprint::from_bytes([1; AUTHORITY_BYTES]).unwrap();
        let app_a = AppId::new("app-a").unwrap();
        let app_b = AppId::new("app-b").unwrap();
        let mut fake =
            FakeRelayEnrollment::new([2; AUTHORITY_BYTES], [3; AUTHORITY_BYTES]).unwrap();
        let challenge_a = fake
            .begin(core_identity, "pair-a", "target-a", app_a.clone(), 1, 1_000)
            .unwrap();
        let entry_a = match fake.accept(
            submission(core_identity, challenge_a, &app_a, b"csr-a"),
            1_001,
        ) {
            EnrollmentOutcome::Issued { entry, .. } => entry,
            EnrollmentOutcome::Rejected(error) => panic!("unexpected rejection: {error}"),
        };
        let challenge_b = fake
            .begin(core_identity, "pair-a", "target-a", app_b.clone(), 1, 1_000)
            .unwrap();
        let entry_b = match fake.accept(
            submission(core_identity, challenge_b, &app_b, b"csr-b"),
            1_001,
        ) {
            EnrollmentOutcome::Issued { entry, .. } => entry,
            EnrollmentOutcome::Rejected(error) => panic!("unexpected rejection: {error}"),
        };
        let before = fake.allowlist().generation();
        let after = fake.allowlist_mut().revoke(&app_a).unwrap();
        assert!(after > before);
        assert!(!fake.allowlist().allows_qrm_at(entry_a.fingerprint(), 1_001));
        assert!(fake.allowlist().allows_qrm_at(entry_b.fingerprint(), 1_001));
        assert_eq!(fake.allowlist().entry(&app_b).unwrap().generation(), after);
    }

    // TEST:relay/src/enrollment.rs[tests::certificate_fake_redacts_material]
    #[test]
    fn certificate_fake_redacts_material() {
        let app = AppId::new("app-a").unwrap();
        let csr = CsrMetadata::from_bytes(app, b"private-csr-bytes").unwrap();
        let mut ca = FakeCertificateAuthority::new(1, [4; AUTHORITY_BYTES]).unwrap();
        let certificate = ca.issue(&csr, 2, 100).unwrap();
        let debug = format!("{certificate:?}");
        assert!(!debug.contains("private-csr-bytes"));
        assert!(!debug.contains("private"));
    }

    // TEST:relay/src/enrollment.rs[tests::allowlist_expiry_denies_authority]
    #[test]
    fn allowlist_expiry_denies_authority() {
        let (core_identity, app) = identities();
        let mut fake =
            FakeRelayEnrollment::new([2; AUTHORITY_BYTES], [3; AUTHORITY_BYTES]).unwrap();
        let challenge = fake
            .begin(core_identity, "pair-a", "target-a", app.clone(), 1, 1_000)
            .unwrap();
        let entry = match fake.accept(
            submission(core_identity, challenge, &app, b"csr-expiry"),
            1_001,
        ) {
            EnrollmentOutcome::Issued { entry, .. } => entry,
            EnrollmentOutcome::Rejected(error) => panic!("unexpected rejection: {error}"),
        };
        let expiry = entry.not_after_epoch_seconds();
        assert!(
            fake.allowlist()
                .allows_qrm_at(entry.fingerprint(), expiry - 1)
        );
        assert!(!fake.allowlist().allows_qrm_at(entry.fingerprint(), expiry));
        assert_eq!(
            fake.allowlist()
                .authorize_update_at(entry.fingerprint(), expiry),
            Err(EnrollmentError::UpdateUnauthorized)
        );
    }

    // TEST:relay/src/enrollment.rs[tests::update_admin_and_lock]
    #[test]
    fn update_admin_and_lock() {
        assert_eq!(STABLE_LATEST_SELECTOR, "stable-latest");
        let (core_identity, app) = identities();
        let mut fake =
            FakeRelayEnrollment::new([2; AUTHORITY_BYTES], [3; AUTHORITY_BYTES]).unwrap();
        let challenge = fake
            .begin(core_identity, "pair-a", "target-a", app.clone(), 1, 1_000)
            .unwrap();
        let entry = match fake.accept(submission(core_identity, challenge, &app, b"csr-a"), 1_001) {
            EnrollmentOutcome::Issued { entry, .. } => entry,
            EnrollmentOutcome::Rejected(error) => panic!("unexpected rejection: {error}"),
        };
        let request = UpdateRequest {
            request_id: [7; AUTHORIZATION_ID_BYTES],
            selector: UpdateSelector::StableLatest,
            caller: entry.fingerprint(),
        };
        let mut worker = FakeUpdateWorker::new();
        assert_eq!(
            worker.start_at(&request, fake.allowlist(), 1_001),
            Ok(UpdateStatus::Running)
        );
        assert_eq!(
            worker.start_at(&request, fake.allowlist(), 1_001),
            Err(EnrollmentError::UpdateBusy)
        );
        assert_eq!(worker.complete(), Ok(UpdateStatus::Succeeded));
        fake.allowlist_mut().revoke(&app).unwrap();
        assert_eq!(
            worker.start_at(&request, fake.allowlist(), 1_001),
            Err(EnrollmentError::UpdateUnauthorized)
        );
    }

    // TEST:relay/src/enrollment.rs[tests::enrollment_expiry_duplicate_and_reuse]
    #[test]
    fn enrollment_expiry_duplicate_and_reuse() {
        let (core_identity, app) = identities();
        let mut fake =
            FakeRelayEnrollment::new([2; AUTHORITY_BYTES], [3; AUTHORITY_BYTES]).unwrap();

        let duplicate_app = AppId::new("app-duplicate").unwrap();
        let duplicate_challenge = fake
            .begin(
                core_identity,
                "pair-a",
                "target-a",
                duplicate_app.clone(),
                1,
                1_000,
            )
            .unwrap();
        assert!(matches!(
            fake.accept(
                submission(
                    core_identity,
                    duplicate_challenge,
                    &duplicate_app,
                    b"csr-duplicate",
                ),
                1_001,
            ),
            EnrollmentOutcome::Issued { .. }
        ));
        let duplicate_challenge = fake
            .begin(
                core_identity,
                "pair-a",
                "target-a",
                duplicate_app.clone(),
                1,
                1_002,
            )
            .unwrap();
        assert_eq!(
            fake.accept(
                submission(
                    core_identity,
                    duplicate_challenge,
                    &duplicate_app,
                    b"csr-duplicate-2",
                ),
                1_003,
            ),
            EnrollmentOutcome::Rejected(EnrollmentError::DuplicateEnrollment)
        );

        let accepted_submission = submission(
            core_identity,
            {
                fake.begin(core_identity, "pair-a", "target-a", app.clone(), 1, 1_000)
                    .unwrap()
            },
            &app,
            b"csr-a",
        );
        assert!(matches!(
            fake.accept(accepted_submission.clone(), 1_001),
            EnrollmentOutcome::Issued { .. }
        ));

        let reused_app = AppId::new("app-reused").unwrap();
        let reused_challenge = fake
            .begin(
                core_identity,
                "pair-a",
                "target-a",
                reused_app.clone(),
                1,
                1_000,
            )
            .unwrap();
        assert_eq!(
            fake.accept(
                submission(core_identity, reused_challenge, &reused_app, b"csr-a"),
                1_001,
            ),
            EnrollmentOutcome::Rejected(EnrollmentError::AuthorizationUsed)
        );

        let expired_app = AppId::new("app-expired").unwrap();
        let expired_challenge = fake
            .begin(
                core_identity,
                "pair-a",
                "target-a",
                expired_app.clone(),
                1,
                2_000,
            )
            .unwrap();
        assert_eq!(
            fake.accept(
                submission(
                    core_identity,
                    expired_challenge,
                    &expired_app,
                    b"csr-expired"
                ),
                2_000 + ENROLLMENT_TTL_SECS + 1,
            ),
            EnrollmentOutcome::Rejected(EnrollmentError::ChallengeExpired)
        );
    }
    // TEST:relay/src/enrollment.rs[tests::debug_redaction]
    #[test]
    fn debug_redaction() {
        let (core_identity, app) = identities();
        let mut fake =
            FakeRelayEnrollment::new([2; AUTHORITY_BYTES], [3; AUTHORITY_BYTES]).unwrap();
        let challenge = fake
            .begin(core_identity, "pair-a", "target-a", app.clone(), 1, 1_000)
            .unwrap();
        let request = submission(core_identity, challenge, &app, b"secret-csr");
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-csr"));
        assert!(!debug.contains("private"));
    }
}
