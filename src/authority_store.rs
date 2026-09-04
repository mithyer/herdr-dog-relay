//! Relay-owned bounded persistent authority records for local recovery validation.
//!
//! This backend is intentionally labeled development-insecure. It stores only non-secret pairing
//! relations and runtime-fence metadata; active connections, stream handles, session tokens,
//! pairing codes and Herdr payloads remain process-local.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version of the shared Core/Relay bounded record envelope.
pub(crate) const AUTHORITY_SCHEMA_VERSION: u32 = 1;
/// Explicit marker preventing this backend from being mistaken for protected production storage.
pub(crate) const DEVELOPMENT_INSECURE_STORAGE_PROFILE: &str = "development-insecure";
/// Maximum decoded payload accepted for one Relay recovery record.
pub(crate) const MAX_AUTHORITY_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum serialized envelope read from one Relay host file.
const MAX_AUTHORITY_RECORD_BYTES: usize = MAX_AUTHORITY_PAYLOAD_BYTES + 4096;
/// Maximum host namespace key length.
const MAX_STORAGE_KEY_BYTES: usize = 128;
/// Maximum kind or state label length.
const MAX_LABEL_BYTES: usize = 64;
/// Shared domain separator for record integrity digests.
const AUTHORITY_DIGEST_DOMAIN: &[u8] = b"herdr-dog/authority-record/v1";

/// Sanitized outcomes from the Relay development-insecure record backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityStoreError {
    /// A path, key, kind or state was invalid.
    Invalid,
    /// The record or its filesystem identity was malformed.
    Corrupt,
    /// The host filesystem could not be read, created or locked.
    Unavailable,
    /// The record could not be atomically committed.
    PersistenceFailed,
    /// The expected record revision was stale.
    Conflict,
    /// The atomic outcome cannot be classified safely.
    Unknown,
}

/// Successful outcomes from an expected-revision record deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum AuthorityDeleteOutcome {
    /// An existing record was removed and the directory was synchronized.
    Deleted,
    /// The selected record was already absent; no storage was created.
    Missing,
}

/// One decoded bounded record transferred to a typed Relay recovery adapter.
pub(crate) struct StoredAuthorityRecord {
    /// Compare-and-commit revision assigned by the host record.
    pub(crate) revision: u64,
    /// Non-secret record generation.
    pub(crate) generation: u64,
    /// Typed lifecycle state.
    pub(crate) state: String,
    /// Decoded opaque payload, cleared when the record is dropped.
    pub(crate) payload: Vec<u8>,
}

impl StoredAuthorityRecord {
    /// Consume the record while transferring its decoded payload to a typed adapter.
    pub(crate) fn into_parts(mut self) -> (u64, u64, String, Vec<u8>) {
        let payload = std::mem::take(&mut self.payload);
        let state = std::mem::take(&mut self.state);
        (self.revision, self.generation, state, payload)
    }
}

impl Drop for StoredAuthorityRecord {
    /// Clear decoded payload bytes before releasing the record allocation.
    fn drop(&mut self) {
        self.payload.fill(0);
    }
}

/// JSON envelope used for Relay pairing-authority and runtime-fence records.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEnvelope {
    /// Stable host-namespaced logical key.
    key: String,
    /// Envelope schema version.
    schema_version: u32,
    /// Typed record kind discriminator.
    kind: String,
    /// Storage protection profile marker.
    protection: String,
    /// Monotonic compare-and-commit revision.
    revision: u64,
    /// Non-secret record generation.
    generation: u64,
    /// Typed lifecycle state.
    state: String,
    /// Decoded payload length.
    payload_len: u32,
    /// Domain-separated integrity digest.
    integrity: [u8; 32],
    /// Base64 payload; this profile is not production encryption.
    payload: String,
}

/// File-backed record store with process-local and cross-process serialization.
#[derive(Clone)]
pub(crate) struct FileAuthorityStore {
    /// Absolute host-selected directory containing fixed record files.
    root: PathBuf,
    /// Process-local mutation lock shared by handles for this store.
    transition_lock: Arc<Mutex<()>>,
}

impl fmt::Debug for FileAuthorityStore {
    /// Formats store presence without exposing the host-selected path.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileAuthorityStore")
            .field("root_present", &self.root.is_absolute())
            .finish()
    }
}

impl FileAuthorityStore {
    /// Open a lazy store without reading or creating its host directory.
    ///
    /// # Parameters
    /// * `root` - Absolute directory selected by the Relay host.
    ///
    /// # Returns
    /// A store handle, or a sanitized invalid-path error.
    // TEST:relay/src/iroh_endpoint.rs[tests::relay_authority_store_round_trip]
    pub(crate) fn open(root: impl AsRef<Path>) -> Result<Arc<Self>, AuthorityStoreError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(AuthorityStoreError::Invalid);
        }
        Ok(Arc::new(Self {
            root: root.to_path_buf(),
            transition_lock: Arc::new(Mutex::new(())),
        }))
    }

    /// Load one fixed record without creating missing storage or bypassing a lock.
    ///
    /// # Parameters
    /// * `key` - Host-namespaced logical key.
    /// * `kind` - Expected typed record kind.
    /// * `filename` - Fixed JSON filename selected by the typed adapter.
    ///
    /// # Returns
    /// A validated record, `None` for missing storage, or a sanitized storage error.
    pub(crate) fn load(
        &self,
        key: &str,
        kind: &str,
        filename: &str,
    ) -> Result<Option<StoredAuthorityRecord>, AuthorityStoreError> {
        validate_labels(key, kind, "active")?;
        validate_filename(filename)?;
        let metadata = match fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AuthorityStoreError::Unavailable),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AuthorityStoreError::Corrupt);
        }
        match fs::symlink_metadata(self.lock_path(filename)) {
            Ok(_) => return Err(AuthorityStoreError::Unavailable),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AuthorityStoreError::Unavailable),
        }
        self.read_record(key, kind, filename)
    }

    /// Commit one complete record through an expected-revision compare-and-commit.
    ///
    /// # Parameters
    /// * `key` - Host-namespaced logical key.
    /// * `kind` - Typed record kind.
    /// * `filename` - Fixed JSON filename selected by the typed adapter.
    /// * `generation` - Non-secret typed generation.
    /// * `state` - Bounded typed lifecycle state.
    /// * `payload` - Opaque payload bounded by the storage contract.
    /// * `expected_revision` - Required current revision, with zero meaning missing.
    ///
    /// # Returns
    /// The record protocol keeps each field explicit at this boundary so typed callers cannot
    /// accidentally omit the key, lifecycle state, or expected revision.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit(
        &self,
        key: &str,
        kind: &str,
        filename: &str,
        generation: u64,
        state: &str,
        payload: &[u8],
        expected_revision: u64,
    ) -> Result<u64, AuthorityStoreError> {
        validate_labels(key, kind, state)?;
        validate_filename(filename)?;
        if generation == 0 || payload.len() > MAX_AUTHORITY_PAYLOAD_BYTES {
            return Err(AuthorityStoreError::Invalid);
        }
        let _transition = self
            .transition_lock
            .lock()
            .map_err(|_| AuthorityStoreError::Unavailable)?;
        ensure_directory(&self.root)?;
        let _file_lock = AuthorityFileLock::acquire(&self.lock_path(filename))?;
        let current = self.read_record(key, kind, filename)?;
        let current_revision = current.as_ref().map_or(0, |record| record.revision);
        if current_revision != expected_revision {
            return Err(AuthorityStoreError::Conflict);
        }
        let revision = current_revision
            .checked_add(1)
            .ok_or(AuthorityStoreError::Unknown)?;
        let payload_len = u32::try_from(payload.len()).map_err(|_| AuthorityStoreError::Invalid)?;
        let mut envelope = AuthorityEnvelope {
            key: key.to_owned(),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind: kind.to_owned(),
            protection: DEVELOPMENT_INSECURE_STORAGE_PROFILE.to_owned(),
            revision,
            generation,
            state: state.to_owned(),
            payload_len,
            integrity: [0; 32],
            payload: STANDARD_NO_PAD.encode(payload),
        };
        envelope.integrity = record_digest(&envelope, payload);
        self.write_record(filename, &envelope)?;
        Ok(revision)
    }

    /// Compare-and-delete one complete bounded record after an exact revision check.
    ///
    /// This capability is retained for the future native-host disposal path; current typed
    /// recovery adapters remove authority through committed replacement records.
    ///
    /// # Parameters
    /// * `key` - Host-namespaced logical record key.
    /// * `kind` - Typed record kind.
    /// * `filename` - Fixed JSON filename selected by the typed adapter.
    /// * `expected_revision` - Required current revision, with zero allowed only for missing state.
    ///
    /// # Returns
    /// `Deleted` after removal and directory synchronization, `Missing` when the record was
    /// already absent, or a sanitized storage outcome. An uncertain removal returns `Unknown`.
    #[allow(dead_code)]
    pub(crate) fn delete(
        &self,
        key: &str,
        kind: &str,
        filename: &str,
        expected_revision: u64,
    ) -> Result<AuthorityDeleteOutcome, AuthorityStoreError> {
        validate_labels(key, kind, "active")?;
        validate_filename(filename)?;
        let root_metadata = match fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AuthorityDeleteOutcome::Missing);
            }
            Err(_) => return Err(AuthorityStoreError::Unavailable),
        };
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(AuthorityStoreError::Corrupt);
        }
        let _transition = self
            .transition_lock
            .lock()
            .map_err(|_| AuthorityStoreError::Unavailable)?;
        let _file_lock = AuthorityFileLock::acquire(&self.lock_path(filename))?;
        let current = self.read_record(key, kind, filename)?;
        let Some(current) = current else {
            return Ok(AuthorityDeleteOutcome::Missing);
        };
        if current.revision != expected_revision {
            return Err(AuthorityStoreError::Conflict);
        }
        drop(current);
        fs::remove_file(self.record_path(filename)).map_err(|_| AuthorityStoreError::Unknown)?;
        sync_directory(&self.root)?;
        Ok(AuthorityDeleteOutcome::Deleted)
    }

    /// Return the fixed JSON path for one validated filename.
    fn record_path(&self, filename: &str) -> PathBuf {
        self.root.join(filename)
    }

    /// Return the fixed lock path for one validated filename.
    fn lock_path(&self, filename: &str) -> PathBuf {
        self.root.join(format!("{filename}.lock"))
    }

    /// Read and validate one record while the caller owns any mutation lock.
    fn read_record(
        &self,
        key: &str,
        kind: &str,
        filename: &str,
    ) -> Result<Option<StoredAuthorityRecord>, AuthorityStoreError> {
        let path = self.record_path(filename);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AuthorityStoreError::Unavailable),
        };
        if metadata.len() > MAX_AUTHORITY_RECORD_BYTES as u64 {
            return Err(AuthorityStoreError::Corrupt);
        }
        validate_private_file(&metadata)?;
        let file = File::open(&path).map_err(|_| AuthorityStoreError::Unavailable)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_AUTHORITY_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthorityStoreError::Unavailable)?;
        if bytes.len() > MAX_AUTHORITY_RECORD_BYTES {
            return Err(AuthorityStoreError::Corrupt);
        }
        let envelope = serde_json::from_slice::<AuthorityEnvelope>(&bytes)
            .map_err(|_| AuthorityStoreError::Corrupt)?;
        decode_record(envelope, key, kind).map(Some)
    }

    /// Serialize, fsync and atomically replace a fixed record file.
    fn write_record(
        &self,
        filename: &str,
        envelope: &AuthorityEnvelope,
    ) -> Result<(), AuthorityStoreError> {
        let bytes = serde_json::to_vec(envelope).map_err(|_| AuthorityStoreError::Corrupt)?;
        if bytes.len() > MAX_AUTHORITY_RECORD_BYTES {
            return Err(AuthorityStoreError::Corrupt);
        }
        let counter = next_counter();
        let temporary = self
            .root
            .join(format!(".{filename}.tmp-{}-{counter}", std::process::id()));
        let mut file = create_private_new_file(&temporary)
            .map_err(|_| AuthorityStoreError::PersistenceFailed)?;
        if file.write_all(&bytes).is_err() || file.sync_all().is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(AuthorityStoreError::PersistenceFailed);
        }
        drop(file);
        fs::rename(&temporary, self.record_path(filename))
            .map_err(|_| AuthorityStoreError::Unknown)?;
        sync_directory(&self.root)
    }
}

/// Validate labels before they enter an envelope or path-derived operation.
fn validate_labels(key: &str, kind: &str, state: &str) -> Result<(), AuthorityStoreError> {
    let key_valid = !key.is_empty()
        && key.len() <= MAX_STORAGE_KEY_BYTES
        && key.is_ascii()
        && key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'.' | b'_' | b'-')
        });
    let label_valid = |value: &str| {
        !value.is_empty()
            && value.len() <= MAX_LABEL_BYTES
            && value.is_ascii()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    };
    (key_valid && label_valid(kind) && label_valid(state))
        .then_some(())
        .ok_or(AuthorityStoreError::Invalid)
}

/// Ensure only fixed JSON filenames are accepted.
fn validate_filename(filename: &str) -> Result<(), AuthorityStoreError> {
    if filename.is_empty()
        || filename.len() > 96
        || !filename.is_ascii()
        || !filename.ends_with(".json")
        || filename.bytes().any(|byte| {
            !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_' && byte != b'.'
        })
    {
        return Err(AuthorityStoreError::Invalid);
    }
    Ok(())
}

/// Decode and verify one persisted envelope.
fn decode_record(
    envelope: AuthorityEnvelope,
    expected_key: &str,
    expected_kind: &str,
) -> Result<StoredAuthorityRecord, AuthorityStoreError> {
    if envelope.key != expected_key
        || envelope.schema_version != AUTHORITY_SCHEMA_VERSION
        || envelope.kind != expected_kind
        || envelope.protection != DEVELOPMENT_INSECURE_STORAGE_PROFILE
        || envelope.revision == 0
        || envelope.generation == 0
        || envelope.payload_len as usize > MAX_AUTHORITY_PAYLOAD_BYTES
    {
        return Err(AuthorityStoreError::Corrupt);
    }
    validate_labels(&envelope.key, &envelope.kind, &envelope.state)?;
    let payload = STANDARD_NO_PAD
        .decode(envelope.payload.as_bytes())
        .map_err(|_| AuthorityStoreError::Corrupt)?;
    if payload.len() != envelope.payload_len as usize {
        return Err(AuthorityStoreError::Corrupt);
    }
    if !digests_equal(&envelope.integrity, &record_digest(&envelope, &payload)) {
        return Err(AuthorityStoreError::Corrupt);
    }
    Ok(StoredAuthorityRecord {
        revision: envelope.revision,
        generation: envelope.generation,
        state: envelope.state,
        payload,
    })
}

/// Compute an unambiguous domain-separated digest over metadata and payload.
fn record_digest(envelope: &AuthorityEnvelope, payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AUTHORITY_DIGEST_DOMAIN);
    for value in [
        envelope.key.as_bytes(),
        envelope.kind.as_bytes(),
        envelope.protection.as_bytes(),
        envelope.state.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(envelope.schema_version.to_be_bytes());
    digest.update(envelope.revision.to_be_bytes());
    digest.update(envelope.generation.to_be_bytes());
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(payload);
    digest.finalize().into()
}

/// Compare fixed-size digests without returning on the first mismatch.
fn digests_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Ensure the selected directory has private directory permissions.
fn ensure_directory(path: &Path) -> Result<(), AuthorityStoreError> {
    fs::create_dir_all(path).map_err(|_| AuthorityStoreError::Unavailable)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| AuthorityStoreError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AuthorityStoreError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).map_err(|_| AuthorityStoreError::Unavailable)?;
    }
    Ok(())
}

/// Reject symlinks and group/world-readable record files.
fn validate_private_file(metadata: &fs::Metadata) -> Result<(), AuthorityStoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AuthorityStoreError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(AuthorityStoreError::Corrupt);
        }
    }
    Ok(())
}

/// Create an exclusive private file with restrictive permissions.
fn create_private_new_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Sync a directory after replacement, tolerating unsupported directory fsync platforms.
fn sync_directory(path: &Path) -> Result<(), AuthorityStoreError> {
    match File::open(path).and_then(|directory| directory.sync_all()) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
            ) =>
        {
            Ok(())
        }
        Err(_) => Err(AuthorityStoreError::Unknown),
    }
}

/// Exclusive lock retained until the corresponding mutation completes.
struct AuthorityFileLock {
    /// Lock path removed after a normal guard drop.
    path: PathBuf,
    /// Open descriptor retaining the exclusive lock.
    _file: File,
}

impl AuthorityFileLock {
    /// Acquire a fail-closed lock without deleting stale lock files.
    fn acquire(path: &Path) -> Result<Self, AuthorityStoreError> {
        let mut file = create_private_new_file(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AuthorityStoreError::Unavailable
            } else {
                AuthorityStoreError::PersistenceFailed
            }
        })?;
        file.write_all(b"lock")
            .map_err(|_| AuthorityStoreError::PersistenceFailed)?;
        file.sync_all()
            .map_err(|_| AuthorityStoreError::PersistenceFailed)?;
        Ok(Self {
            path: path.to_path_buf(),
            _file: file,
        })
    }
}

impl Drop for AuthorityFileLock {
    /// Remove only the lock created by this guard.
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Monotonic temporary-file suffix used to avoid same-process collisions.
static TEMP_COUNTER: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();

/// Allocate one temporary-file suffix without exposing it to callers.
fn next_counter() -> u64 {
    TEMP_COUNTER
        .get_or_init(std::sync::atomic::AtomicU64::default)
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
