//! Protected Relay issuance-result persistence for response-lost enrollment.
//!
//! The store contains only bounded public certificate material and sanitized status metadata. It
//! never persists private keys, raw CSRs, enrollment codes, QUIC tokens or Herdr payloads.

use crate::{
    enrollment::AppId,
    error::{RelayError, RelayResult},
    material::{
        MAX_ALLOWLIST_BYTES, ProtectedFileKind, read_protected_file, validate_protected_path,
        write_protected_file,
    },
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// Retention period for terminal or unresolved issuance results.
pub const ISSUANCE_RESULT_TTL_SECS: u64 = 24 * 60 * 60;
/// Maximum number of retained authorization records.
pub const MAX_ISSUANCE_RESULT_RECORDS: usize = 256;
/// Maximum serialized issuance-result file size.
pub const MAX_ISSUANCE_RESULT_BYTES: u64 = MAX_ALLOWLIST_BYTES;
/// Maximum public certificate-chain bytes in one record and reconciliation response.
pub const MAX_ISSUANCE_CHAIN_BYTES: usize = 48 * 1024;
/// Maximum authorization lifetime accepted by the durable store.
pub const MAX_AUTHORIZATION_TTL_SECS: u64 = 300;
/// Version of the protected issuance-result file format.
pub const ISSUANCE_RESULT_STORE_VERSION: u16 = 1;

/// One Core authorization and CSR binding used as the durable reconciliation key.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct IssuanceResultKey {
    /// Single-use Core authorization identity.
    authorization_id: [u8; 16],
    /// SHA-256 digest of the discarded CSR.
    csr_digest: [u8; 32],
}

impl IssuanceResultKey {
    /// Construct one non-zero authorization/CSR binding key.
    ///
    /// # Parameters
    /// * `authorization_id` - Core-issued single-use authorization identity.
    /// * `csr_digest` - Digest of the App CSR bound to that authorization.
    ///
    /// # Returns
    /// A validated key or a redacted configuration error.
    pub fn new(authorization_id: [u8; 16], csr_digest: [u8; 32]) -> RelayResult<Self> {
        if authorization_id == [0; 16] || csr_digest == [0; 32] {
            return Err(RelayError::QuicProtocol {
                reason: "issuance binding is empty",
            });
        }
        Ok(Self {
            authorization_id,
            csr_digest,
        })
    }

    /// Returns the authorization identifier for internal protocol correlation.
    pub const fn authorization_id(&self) -> [u8; 16] {
        self.authorization_id
    }

    /// Returns the CSR digest for exact binding checks.
    pub const fn csr_digest(&self) -> [u8; 32] {
        self.csr_digest
    }
}

impl fmt::Debug for IssuanceResultKey {
    /// Reports only that both non-secret correlation fields are present.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuanceResultKey")
            .field("authorization_id_present", &true)
            .field("csr_digest_present", &true)
            .finish()
    }
}

/// Durable reconciliation state for one enrollment attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceResultStatus {
    /// The authorization was consumed but allowlist/issuance completion is unresolved.
    Pending,
    /// A public certificate chain was issued and the allowlist transaction completed.
    Issued,
    /// The attempt reached a terminal sanitized rejection.
    Rejected,
}

/// Outcome of beginning an authorization/CSR persistence transaction.
#[derive(Clone, Debug)]
pub enum IssuanceBeginResult {
    /// The binding was newly persisted as pending.
    Created(IssuanceResultRecord),
    /// The binding already existed and must not be issued again.
    Existing(IssuanceResultRecord),
}

/// Sanitized public issuance result retained for bounded reconciliation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceResultRecord {
    /// Durable authorization/CSR binding.
    key: IssuanceResultKey,
    /// App identity encoded by the CSR and certificate.
    app_id: String,
    /// Current terminal or unresolved state.
    status: IssuanceResultStatus,
    /// Authorization expiry used to reject stale reconciliation.
    authorization_expires_at_epoch_seconds: u64,
    /// Retention deadline for this record.
    retained_until_epoch_seconds: u64,
    /// Public leaf and Intermediate certificate chain, never private material.
    certificate_chain: Vec<Vec<u8>>,
    /// Public leaf fingerprint after issuance.
    fingerprint: Option<[u8; 32]>,
    /// Allowlist generation after the issuance transaction.
    allowlist_generation: Option<u64>,
    /// Public certificate expiry after issuance.
    not_after_epoch_seconds: Option<u64>,
    /// Sanitized terminal rejection code.
    rejection_code: Option<u16>,
}

impl fmt::Debug for IssuanceResultRecord {
    /// Reports public shape and status without certificate bytes or correlation values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuanceResultRecord")
            .field("key", &self.key)
            .field("app_id_present", &true)
            .field("status", &self.status)
            .field(
                "authorization_expires_at_epoch_seconds",
                &self.authorization_expires_at_epoch_seconds,
            )
            .field(
                "retained_until_epoch_seconds",
                &self.retained_until_epoch_seconds,
            )
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

impl IssuanceResultRecord {
    /// Returns the durable reconciliation key.
    pub const fn key(&self) -> IssuanceResultKey {
        self.key
    }

    /// Returns the bounded App identity.
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// Returns the current reconciliation state.
    pub const fn status(&self) -> IssuanceResultStatus {
        self.status
    }

    /// Returns the authorization expiry.
    pub const fn authorization_expires_at_epoch_seconds(&self) -> u64 {
        self.authorization_expires_at_epoch_seconds
    }

    /// Returns the retention deadline.
    pub const fn retained_until_epoch_seconds(&self) -> u64 {
        self.retained_until_epoch_seconds
    }

    /// Returns the public certificate chain for an issued result.
    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.certificate_chain
    }

    /// Returns the public certificate fingerprint when issuance completed.
    pub const fn fingerprint(&self) -> Option<[u8; 32]> {
        self.fingerprint
    }

    /// Returns the allowlist generation when issuance completed.
    pub const fn allowlist_generation(&self) -> Option<u64> {
        self.allowlist_generation
    }

    /// Returns the certificate expiry when issuance completed.
    pub const fn not_after_epoch_seconds(&self) -> Option<u64> {
        self.not_after_epoch_seconds
    }

    /// Returns the sanitized rejection code when the attempt was rejected.
    pub const fn rejection_code(&self) -> Option<u16> {
        self.rejection_code
    }
}

/// Persisted file envelope with explicit format version and bounded record count.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedIssuanceResults {
    /// Protected file format version.
    version: u16,
    /// Retained records in deterministic order.
    records: Vec<IssuanceResultRecord>,
}

/// Sidecar lock guard for cross-process issuance-result transactions.
struct IssuanceLock {
    /// Exclusively locked sidecar file.
    file: File,
}

impl Drop for IssuanceLock {
    /// Releases the advisory lock on every return path.
    fn drop(&mut self) {
        // The primary operation result must not be replaced by a cleanup failure.
        let _ = self.file.unlock();
    }
}

/// Protected durable issuance-result store used by the Relay reconciliation path.
#[derive(Clone, Debug)]
pub struct PersistentIssuanceResults {
    /// Protected JSON path for public issuance metadata.
    path: PathBuf,
    /// Owner UID required for the path and file.
    expected_uid: u32,
    /// Current in-memory validated records.
    records: Vec<IssuanceResultRecord>,
}

impl PersistentIssuanceResults {
    /// Opens an existing store or creates an empty protected store.
    ///
    /// # Parameters
    /// * `path` - Absolute owner-protected JSON path.
    /// * `expected_uid` - UID required for all protected path components.
    ///
    /// # Returns
    /// A validated store or a sanitized persistence error.
    pub fn open(path: impl Into<PathBuf>, expected_uid: u32) -> RelayResult<Self> {
        let path = path.into();
        validate_protected_path(&path, expected_uid)?;
        let mut store = Self {
            path,
            expected_uid,
            records: Vec::new(),
        };
        let _lock = store.lock_file()?;
        if store.path.exists() {
            store.records = store.load_records()?;
        } else {
            store.persist_records(&[])?;
        }
        Ok(store)
    }

    /// Returns the protected store path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Begins or resumes one pending authorization/CSR binding.
    ///
    /// Existing records are returned unchanged, making duplicate Submit handling terminal and
    /// preventing a second certificate from being issued after a response-lost retry.
    ///
    /// # Parameters
    /// * `key` - Core authorization and CSR digest binding.
    /// * `app_id` - Validated App identity bound to the CSR.
    /// * `authorization_expires_at_epoch_seconds` - Core authorization deadline.
    /// * `now_epoch_seconds` - Current epoch used for TTL and expiry checks.
    ///
    /// # Returns
    /// A new pending record or an existing record that must not be issued again.
    pub fn begin_pending(
        &mut self,
        key: IssuanceResultKey,
        app_id: impl Into<String>,
        authorization_expires_at_epoch_seconds: u64,
        now_epoch_seconds: u64,
    ) -> RelayResult<IssuanceBeginResult> {
        let app_id = app_id.into();
        AppId::new(app_id.clone()).map_err(|_| RelayError::QuicProtocol {
            reason: "issuance App identity is invalid",
        })?;
        if authorization_expires_at_epoch_seconds <= now_epoch_seconds
            || authorization_expires_at_epoch_seconds - now_epoch_seconds
                > MAX_AUTHORIZATION_TTL_SECS
        {
            return Err(RelayError::QuicProtocol {
                reason: "issuance authorization is expired",
            });
        }
        let retained_until = authorization_expires_at_epoch_seconds
            .checked_add(ISSUANCE_RESULT_TTL_SECS)
            .ok_or(RelayError::QuicProtocol {
                reason: "issuance retention overflows",
            })?;
        let _lock = self.lock_file()?;
        let mut records = self.load_records()?;
        let changed = prune_records(&mut records, now_epoch_seconds);
        if let Some(existing) = records.iter().find(|record| record.key == key).cloned() {
            if existing.app_id != app_id {
                return Err(RelayError::QuicProtocol {
                    reason: "issuance binding App identity mismatch",
                });
            }
            if changed {
                self.persist_records(&records)?;
                self.records = records;
            } else {
                self.records = records;
            }
            return Ok(IssuanceBeginResult::Existing(existing));
        }
        if records
            .iter()
            .any(|record| record.key.authorization_id() == key.authorization_id())
        {
            return Err(RelayError::QuicProtocol {
                reason: "issuance authorization was bound to another CSR",
            });
        }
        if records.len() >= MAX_ISSUANCE_RESULT_RECORDS {
            return Err(RelayError::ResourceLimit);
        }
        let record = IssuanceResultRecord {
            key,
            app_id,
            status: IssuanceResultStatus::Pending,
            authorization_expires_at_epoch_seconds,
            retained_until_epoch_seconds: retained_until,
            certificate_chain: Vec::new(),
            fingerprint: None,
            allowlist_generation: None,
            not_after_epoch_seconds: None,
            rejection_code: None,
        };
        records.push(record.clone());
        self.persist_records(&records)?;
        self.records = records;
        Ok(IssuanceBeginResult::Created(record))
    }

    /// Attaches public certificate material to a pending record before allowlist commit.
    ///
    /// The record remains `pending` until the allowlist transaction succeeds, so a restart can
    /// reconcile a public issuance candidate without ever creating a second certificate.
    ///
    /// # Parameters
    /// * `key` - Existing pending authorization/CSR binding.
    /// * `certificate_chain` - Public leaf and Intermediate chain only.
    /// * `fingerprint` - Public leaf fingerprint.
    /// * `allowlist_generation` - Generation intended for the allowlist transaction.
    /// * `not_after_epoch_seconds` - Public certificate expiry.
    /// * `now_epoch_seconds` - Current epoch used for retention cleanup.
    ///
    /// # Returns
    /// The pending record carrying public issuance material.
    pub fn attach_certificate(
        &mut self,
        key: IssuanceResultKey,
        certificate_chain: Vec<Vec<u8>>,
        fingerprint: [u8; 32],
        allowlist_generation: u64,
        not_after_epoch_seconds: u64,
        now_epoch_seconds: u64,
    ) -> RelayResult<IssuanceResultRecord> {
        if fingerprint == [0; 32] || allowlist_generation == 0 || not_after_epoch_seconds == 0 {
            return Err(RelayError::QuicProtocol {
                reason: "issued metadata is invalid",
            });
        }
        validate_chain(&certificate_chain)?;
        let _lock = self.lock_file()?;
        let mut records = self.load_records()?;
        prune_records(&mut records, now_epoch_seconds);
        let record = records
            .iter_mut()
            .find(|record| record.key == key)
            .ok_or(RelayError::ConfigurationRead)?;
        if record.status == IssuanceResultStatus::Rejected {
            return Err(RelayError::QuicProtocol {
                reason: "issuance result is terminally rejected",
            });
        }
        if !record.certificate_chain.is_empty() {
            let same = record.certificate_chain == certificate_chain
                && record.fingerprint == Some(fingerprint)
                && record.allowlist_generation == Some(allowlist_generation)
                && record.not_after_epoch_seconds == Some(not_after_epoch_seconds);
            return if same {
                Ok(record.clone())
            } else {
                Err(RelayError::QuicProtocol {
                    reason: "issuance candidate was already attached",
                })
            };
        }
        record.certificate_chain = certificate_chain;
        record.fingerprint = Some(fingerprint);
        record.allowlist_generation = Some(allowlist_generation);
        record.not_after_epoch_seconds = Some(not_after_epoch_seconds);
        record.rejection_code = None;
        let result = record.clone();
        self.persist_records(&records)?;
        self.records = records;
        Ok(result)
    }

    /// Persists a public issued result after allowlist admission succeeds.
    ///
    /// # Parameters
    /// * `key` - Existing pending authorization/CSR binding.
    /// * `certificate_chain` - Public leaf and Intermediate chain only.
    /// * `fingerprint` - Public leaf fingerprint.
    /// * `allowlist_generation` - Generation committed by the allowlist transaction.
    /// * `not_after_epoch_seconds` - Public certificate expiry.
    /// * `now_epoch_seconds` - Current epoch used for terminal retention.
    ///
    /// # Returns
    /// The durable issued record.
    pub fn mark_issued(
        &mut self,
        key: IssuanceResultKey,
        certificate_chain: Vec<Vec<u8>>,
        fingerprint: [u8; 32],
        allowlist_generation: u64,
        not_after_epoch_seconds: u64,
        now_epoch_seconds: u64,
    ) -> RelayResult<IssuanceResultRecord> {
        if fingerprint == [0; 32] || allowlist_generation == 0 || not_after_epoch_seconds == 0 {
            return Err(RelayError::QuicProtocol {
                reason: "issued metadata is invalid",
            });
        }
        validate_chain(&certificate_chain)?;
        let _lock = self.lock_file()?;
        let mut records = self.load_records()?;
        prune_records(&mut records, now_epoch_seconds);
        let record = records
            .iter_mut()
            .find(|record| record.key == key)
            .ok_or(RelayError::ConfigurationRead)?;
        if record.status == IssuanceResultStatus::Rejected {
            return Err(RelayError::QuicProtocol {
                reason: "issuance result is terminally rejected",
            });
        }
        if record.status == IssuanceResultStatus::Issued {
            let same = record.certificate_chain == certificate_chain
                && record.fingerprint == Some(fingerprint)
                && record.allowlist_generation == Some(allowlist_generation)
                && record.not_after_epoch_seconds == Some(not_after_epoch_seconds);
            return if same {
                Ok(record.clone())
            } else {
                Err(RelayError::QuicProtocol {
                    reason: "issuance result was already finalized",
                })
            };
        }
        record.status = IssuanceResultStatus::Issued;
        record.certificate_chain = certificate_chain;
        record.fingerprint = Some(fingerprint);
        record.allowlist_generation = Some(allowlist_generation);
        record.not_after_epoch_seconds = Some(not_after_epoch_seconds);
        record.rejection_code = None;
        record.retained_until_epoch_seconds = now_epoch_seconds
            .checked_add(ISSUANCE_RESULT_TTL_SECS)
            .ok_or(RelayError::QuicProtocol {
                reason: "issuance retention overflows",
            })?;
        let result = record.clone();
        self.persist_records(&records)?;
        self.records = records;
        Ok(result)
    }

    /// Persists a sanitized terminal rejection for one pending authorization.
    ///
    /// # Parameters
    /// * `key` - Existing pending authorization/CSR binding.
    /// * `code` - Stable non-zero rejection category.
    /// * `now_epoch_seconds` - Current epoch used for terminal retention.
    ///
    /// # Returns
    /// The durable rejected record.
    pub fn mark_rejected(
        &mut self,
        key: IssuanceResultKey,
        code: u16,
        now_epoch_seconds: u64,
    ) -> RelayResult<IssuanceResultRecord> {
        if code == 0 {
            return Err(RelayError::QuicProtocol {
                reason: "issuance rejection code is empty",
            });
        }
        let _lock = self.lock_file()?;
        let mut records = self.load_records()?;
        prune_records(&mut records, now_epoch_seconds);
        let record = records
            .iter_mut()
            .find(|record| record.key == key)
            .ok_or(RelayError::ConfigurationRead)?;
        if record.status == IssuanceResultStatus::Issued {
            return Ok(record.clone());
        }
        if record.status == IssuanceResultStatus::Rejected {
            return if record.rejection_code == Some(code) {
                Ok(record.clone())
            } else {
                Err(RelayError::QuicProtocol {
                    reason: "issuance result has another rejection code",
                })
            };
        }
        record.status = IssuanceResultStatus::Rejected;
        record.certificate_chain.clear();
        record.fingerprint = None;
        record.allowlist_generation = None;
        record.not_after_epoch_seconds = None;
        record.rejection_code = Some(code);
        record.retained_until_epoch_seconds = now_epoch_seconds
            .checked_add(ISSUANCE_RESULT_TTL_SECS)
            .ok_or(RelayError::QuicProtocol {
                reason: "issuance retention overflows",
            })?;
        let result = record.clone();
        self.persist_records(&records)?;
        self.records = records;
        Ok(result)
    }

    /// Loads and prunes records before returning one reconciliation result.
    ///
    /// # Parameters
    /// * `key` - Authorization/CSR binding to query.
    /// * `now_epoch_seconds` - Current epoch for retention cleanup.
    ///
    /// # Returns
    /// A sanitized record when it is still retained.
    pub fn reconcile(
        &mut self,
        key: IssuanceResultKey,
        now_epoch_seconds: u64,
    ) -> RelayResult<Option<IssuanceResultRecord>> {
        let _lock = self.lock_file()?;
        let mut records = self.load_records()?;
        let changed = prune_records(&mut records, now_epoch_seconds);
        let result = records.iter().find(|record| record.key == key).cloned();
        if changed {
            self.persist_records(&records)?;
        }
        self.records = records;
        Ok(result)
    }

    /// Opens and exclusively locks the sidecar file for one transaction.
    fn lock_file(&self) -> RelayResult<IssuanceLock> {
        validate_protected_path(&self.path, self.expected_uid)?;
        let parent = self.path.parent().ok_or(RelayError::ConfigurationRead)?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(RelayError::ConfigurationRead)?;
        let lock_path = parent.join(format!(".{name}.lock"));
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)
            .map_err(|_| RelayError::ConfigurationRead)?;
        lock.try_lock_exclusive()
            .map_err(|_| RelayError::ConfigurationRead)?;
        Ok(IssuanceLock { file: lock })
    }

    /// Loads and validates the protected issuance-result envelope.
    fn load_records(&self) -> RelayResult<Vec<IssuanceResultRecord>> {
        let bytes = read_protected_file(
            &self.path,
            self.expected_uid,
            ProtectedFileKind::Allowlist,
            MAX_ISSUANCE_RESULT_BYTES,
        )?;
        let persisted: PersistedIssuanceResults =
            serde_json::from_slice(&bytes).map_err(|_| RelayError::ConfigurationRead)?;
        validate_records(&persisted)?;
        Ok(persisted.records)
    }

    /// Atomically persists a bounded issuance-result envelope.
    fn persist_records(&self, records: &[IssuanceResultRecord]) -> RelayResult<()> {
        if records.len() > MAX_ISSUANCE_RESULT_RECORDS {
            return Err(RelayError::ResourceLimit);
        }
        let persisted = PersistedIssuanceResults {
            version: ISSUANCE_RESULT_STORE_VERSION,
            records: records.to_vec(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| RelayError::ConfigurationRead)?;
        write_protected_file(
            &self.path,
            self.expected_uid,
            &bytes,
            ProtectedFileKind::Allowlist,
            MAX_ISSUANCE_RESULT_BYTES,
        )
    }
}

/// Removes records whose bounded retention deadline has elapsed.
fn prune_records(records: &mut Vec<IssuanceResultRecord>, now_epoch_seconds: u64) -> bool {
    let before = records.len();
    records.retain(|record| record.retained_until_epoch_seconds > now_epoch_seconds);
    before != records.len()
}

/// Validates one bounded public certificate chain.
fn validate_chain(chain: &[Vec<u8>]) -> RelayResult<()> {
    if chain.is_empty() {
        return Err(RelayError::QuicProtocol {
            reason: "issued certificate chain is empty",
        });
    }
    let mut total = 0usize;
    for certificate in chain {
        if certificate.is_empty() {
            return Err(RelayError::QuicProtocol {
                reason: "issued certificate is empty",
            });
        }
        total = total
            .checked_add(certificate.len())
            .ok_or(RelayError::ResourceLimit)?;
    }
    if total > MAX_ISSUANCE_CHAIN_BYTES {
        return Err(RelayError::ResourceLimit);
    }
    Ok(())
}

/// Validates all persisted records before they can influence reconciliation.
fn validate_records(persisted: &PersistedIssuanceResults) -> RelayResult<()> {
    if persisted.version != ISSUANCE_RESULT_STORE_VERSION
        || persisted.records.len() > MAX_ISSUANCE_RESULT_RECORDS
    {
        return Err(RelayError::ConfigurationRead);
    }
    let mut keys = BTreeSet::new();
    for record in &persisted.records {
        if !keys.insert(record.key)
            || record.key.authorization_id() == [0; 16]
            || record.key.csr_digest() == [0; 32]
            || AppId::new(record.app_id.clone()).is_err()
            || record.authorization_expires_at_epoch_seconds == 0
            || record.retained_until_epoch_seconds == 0
        {
            return Err(RelayError::ConfigurationRead);
        }
        match record.status {
            IssuanceResultStatus::Pending => {
                if record.rejection_code.is_some() {
                    return Err(RelayError::ConfigurationRead);
                }
                if !record.certificate_chain.is_empty() {
                    validate_chain(&record.certificate_chain)?;
                }
            }
            IssuanceResultStatus::Issued => {
                validate_chain(&record.certificate_chain)?;
                if record.fingerprint.is_none()
                    || record.allowlist_generation.is_none()
                    || record.not_after_epoch_seconds.is_none()
                    || record.rejection_code.is_some()
                {
                    return Err(RelayError::ConfigurationRead);
                }
            }
            IssuanceResultStatus::Rejected => {
                if !record.certificate_chain.is_empty()
                    || record.fingerprint.is_some()
                    || record.allowlist_generation.is_some()
                    || record.not_after_epoch_seconds.is_some()
                    || record.rejection_code.is_none_or(|code| code == 0)
                {
                    return Err(RelayError::ConfigurationRead);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    /// Creates a private temporary directory for issuance-store tests.
    fn temporary_directory() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("herdr-dog-issuance-{}", rand::random::<u64>()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
        path
    }

    /// Builds one deterministic non-secret reconciliation key.
    fn key(auth: u8, csr: u8) -> IssuanceResultKey {
        IssuanceResultKey::new([auth; 16], [csr; 32]).expect("key")
    }

    // TEST:relay/src/issuance.rs[tests::pending_record_survives_reopen]
    #[test]
    fn pending_record_survives_reopen() {
        let directory = temporary_directory();
        let path = directory.join("issuance.json");
        let uid = crate::material::current_uid().expect("uid");
        let mut store = PersistentIssuanceResults::open(&path, uid).expect("open");
        let pending = match store
            .begin_pending(key(1, 2), "app-a", 100, 90)
            .expect("pending")
        {
            IssuanceBeginResult::Created(record) => record,
            IssuanceBeginResult::Existing(_) => panic!("unexpected existing record"),
        };
        assert_eq!(pending.status(), IssuanceResultStatus::Pending);
        let existing = match store
            .begin_pending(key(1, 2), "app-a", 100, 90)
            .expect("existing")
        {
            IssuanceBeginResult::Existing(record) => record,
            IssuanceBeginResult::Created(_) => panic!("duplicate created a new record"),
        };
        assert_eq!(existing.status(), IssuanceResultStatus::Pending);
        drop(store);
        let mut reopened = PersistentIssuanceResults::open(&path, uid).expect("reopen");
        assert_eq!(
            reopened
                .reconcile(key(1, 2), 91)
                .expect("reconcile")
                .expect("record")
                .status(),
            IssuanceResultStatus::Pending
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/issuance.rs[tests::issued_record_is_public_and_redacted]
    #[test]
    fn issued_record_is_public_and_redacted() {
        let directory = temporary_directory();
        let path = directory.join("issuance.json");
        let uid = crate::material::current_uid().expect("uid");
        let mut store = PersistentIssuanceResults::open(&path, uid).expect("open");
        store
            .begin_pending(key(3, 4), "app-b", 100, 90)
            .expect("pending");
        let attached = store
            .attach_certificate(key(3, 4), vec![vec![1, 2], vec![3]], [5; 32], 2, 200, 91)
            .expect("attach");
        assert_eq!(attached.status(), IssuanceResultStatus::Pending);
        let issued = store
            .mark_issued(key(3, 4), vec![vec![1, 2], vec![3]], [5; 32], 2, 200, 91)
            .expect("issued");
        assert_eq!(issued.status(), IssuanceResultStatus::Issued);
        assert_eq!(issued.certificate_chain(), &[vec![1, 2], vec![3]]);
        let debug = format!("{issued:?}");
        assert!(!debug.contains("1, 2"));
        assert!(!debug.contains("app-b"));
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/issuance.rs[tests::rejected_record_expires]
    #[test]
    fn rejected_record_expires() {
        let directory = temporary_directory();
        let path = directory.join("issuance.json");
        let uid = crate::material::current_uid().expect("uid");
        let mut store = PersistentIssuanceResults::open(&path, uid).expect("open");
        store
            .begin_pending(key(5, 6), "app-c", 100, 90)
            .expect("pending");
        store.mark_rejected(key(5, 6), 7, 100).expect("reject");
        assert_eq!(
            store
                .reconcile(key(5, 6), 100 + ISSUANCE_RESULT_TTL_SECS)
                .expect("reconcile"),
            None
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/issuance.rs[tests::authorization_cannot_change_csr]
    #[test]
    fn authorization_cannot_change_csr() {
        let directory = temporary_directory();
        let path = directory.join("issuance.json");
        let uid = crate::material::current_uid().expect("uid");
        let mut store = PersistentIssuanceResults::open(&path, uid).expect("open");
        store
            .begin_pending(key(7, 8), "app-d", 100, 90)
            .expect("pending");
        let result = store.begin_pending(key(7, 9), "app-d", 100, 90);
        assert!(matches!(result, Err(RelayError::QuicProtocol { .. })));
        fs::remove_dir_all(directory).expect("cleanup");
    }
}
