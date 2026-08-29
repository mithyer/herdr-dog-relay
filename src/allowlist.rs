//! Protected persistent App allowlist for QRM-PROD-1.
//!
//! The store contains only public certificate metadata and authorization state. It never stores
//! private keys, raw CSRs, enrollment codes, challenges, QRM tokens, or Herdr payloads.

use crate::{
    enrollment::{AllowlistEntry, AllowlistRegistry, AppId, EnrollmentError, Fingerprint},
    error::{RelayError, RelayResult},
    material::{
        MAX_ALLOWLIST_BYTES, ProtectedFileKind, read_protected_file, validate_protected_path,
        write_protected_file,
    },
};
use fs2::FileExt;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// Explicit sidecar-lock guard that releases advisory ownership on every return path.
struct AllowlistLock {
    /// The exclusively locked sidecar file.
    file: File,
}

impl Drop for AllowlistLock {
    /// Releases the advisory lock before closing the sidecar file.
    fn drop(&mut self) {
        // Ignore cleanup failure because the enclosing operation already has its primary result.
        let _ = self.file.unlock();
    }
}

/// One owner-validated, atomically persisted allowlist.
#[derive(Clone, Debug)]
pub struct PersistentAllowlist {
    /// Protected JSON path containing public allowlist metadata.
    path: PathBuf,
    /// UID required for the path and file.
    expected_uid: u32,
    /// In-memory registry used for admission and generation fencing.
    registry: AllowlistRegistry,
}

impl PersistentAllowlist {
    /// Opens an existing allowlist or creates an empty generation-one file.
    ///
    /// # Parameters
    /// * `path` - Absolute protected JSON path.
    /// * `expected_uid` - Owner UID required for parent and file.
    ///
    /// # Returns
    /// A validated persistent store or a sanitized configuration/persistence error.
    pub fn open(path: impl Into<PathBuf>, expected_uid: u32) -> RelayResult<Self> {
        let path = path.into();
        validate_protected_path(&path, expected_uid)?;
        let mut store = Self {
            path,
            expected_uid,
            registry: AllowlistRegistry::new(),
        };
        let _lock = store.lock_file()?;
        let registry = if store.path.exists() {
            store.load_registry()?
        } else {
            let registry = AllowlistRegistry::new();
            store.persist_registry(&registry)?;
            registry
        };
        store.registry = registry;
        Ok(store)
    }

    /// Opens and exclusively locks the sidecar file for one cross-process transaction.
    fn lock_file(&self) -> RelayResult<AllowlistLock> {
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
        Ok(AllowlistLock { file: lock })
    }

    /// Loads the current JSON registry after the caller holds the sidecar lock.
    fn load_registry(&self) -> RelayResult<AllowlistRegistry> {
        let bytes = read_protected_file(
            &self.path,
            self.expected_uid,
            ProtectedFileKind::Allowlist,
            MAX_ALLOWLIST_BYTES,
        )?;
        let registry: AllowlistRegistry =
            serde_json::from_slice(&bytes).map_err(|_| RelayError::ConfigurationRead)?;
        registry
            .validate_persisted()
            .map_err(|_| RelayError::ConfigurationRead)?;
        Ok(registry)
    }

    /// Persists one validated registry while the caller holds the sidecar lock.
    fn persist_registry(&self, registry: &AllowlistRegistry) -> RelayResult<()> {
        let bytes = serde_json::to_vec(registry).map_err(|_| RelayError::ConfigurationRead)?;
        write_protected_file(
            &self.path,
            self.expected_uid,
            &bytes,
            ProtectedFileKind::Allowlist,
            MAX_ALLOWLIST_BYTES,
        )
    }

    /// Returns the protected allowlist path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the current persisted generation.
    pub const fn generation(&self) -> u64 {
        self.registry.generation()
    }

    /// Checks whether one certificate fingerprint may enter normal QRM at the current epoch.
    pub fn allows_qrm(&self, fingerprint: Fingerprint) -> bool {
        self.registry.allows_qrm(fingerprint)
    }

    /// Checks normal-QRM admission against an explicit epoch for deterministic tests.
    pub fn allows_qrm_at(&self, fingerprint: Fingerprint, now_epoch_seconds: u64) -> bool {
        self.registry.allows_qrm_at(fingerprint, now_epoch_seconds)
    }

    /// Checks whether one certificate fingerprint may request stable-latest update at the current epoch.
    pub fn authorize_update(&self, fingerprint: Fingerprint) -> Result<(), EnrollmentError> {
        self.registry.authorize_update(fingerprint)
    }

    /// Checks update authorization against an explicit epoch for deterministic tests.
    pub fn authorize_update_at(
        &self,
        fingerprint: Fingerprint,
        now_epoch_seconds: u64,
    ) -> Result<(), EnrollmentError> {
        self.registry
            .authorize_update_at(fingerprint, now_epoch_seconds)
    }

    /// Returns an entry by App identity for local operator commands.
    pub fn entry(&self, app_id: &AppId) -> Option<&AllowlistEntry> {
        self.registry.entry(app_id)
    }

    /// Returns all public entries without exposing private material.
    pub fn entries(&self) -> impl Iterator<Item = &AllowlistEntry> {
        self.registry.entries()
    }

    /// Replaces the in-memory registry and persists it atomically.
    ///
    /// # Parameters
    /// * `registry` - Validated non-secret registry state.
    ///
    /// # Returns
    /// `Ok(())` after the replacement is durable, otherwise the old file remains intact.
    pub fn replace(&mut self, registry: AllowlistRegistry) -> RelayResult<()> {
        registry
            .validate_persisted()
            .map_err(|_| RelayError::ConfigurationRead)?;
        let _lock = self.lock_file()?;
        self.persist_registry(&registry)?;
        self.registry = registry;
        Ok(())
    }

    /// Enrolls one issued public certificate in a pending state and persists it atomically.
    pub fn enroll_pending(
        &mut self,
        certificate: crate::enrollment::CertificateMetadata,
    ) -> Result<AllowlistEntry, EnrollmentError> {
        let _lock = self
            .lock_file()
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        let mut next = self
            .load_registry()
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        let entry = next.enroll_pending(certificate)?;
        self.persist_registry(&next)
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        self.registry = next;
        Ok(entry)
    }

    /// Activates one pending App identity and persists it atomically.
    pub fn activate(
        &mut self,
        app_id: &AppId,
        fingerprint: Fingerprint,
    ) -> Result<AllowlistEntry, EnrollmentError> {
        let _lock = self
            .lock_file()
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        let mut next = self
            .load_registry()
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        let entry = next.activate(app_id, fingerprint)?;
        self.persist_registry(&next)
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        self.registry = next;
        Ok(entry)
    }

    /// Enrolls one issued public certificate and persists the new generation atomically.
    pub fn enroll(
        &mut self,
        certificate: crate::enrollment::CertificateMetadata,
    ) -> Result<AllowlistEntry, EnrollmentError> {
        let _lock = self
            .lock_file()
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        let mut next = self
            .load_registry()
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        let entry = next.enroll(certificate)?;
        self.persist_registry(&next)
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        self.registry = next;
        Ok(entry)
    }
    /// Revokes one App and atomically persists the new generation.
    pub fn revoke(&mut self, app_id: &AppId) -> Result<u64, EnrollmentError> {
        let _lock = self
            .lock_file()
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        let mut next = self
            .load_registry()
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        let generation = next.revoke(app_id)?;
        self.persist_registry(&next)
            .map_err(|_| EnrollmentError::AllowlistPersistence)?;
        self.registry = next;
        Ok(generation)
    }

    /// Reloads the protected file so local revocation closes matching live connections.
    pub fn reload(&mut self) -> RelayResult<()> {
        let _lock = self.lock_file()?;
        self.registry = self.load_registry()?;
        Ok(())
    }
    /// Returns a clone for bounded tests and a caller-owned transaction.
    pub fn snapshot(&self) -> AllowlistRegistry {
        self.registry.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::material::ensure_directory;
    use crate::{
        enrollment::{CsrMetadata, FakeCertificateAuthority},
        material::current_uid,
    };
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
    };

    /// Creates one owner-controlled temporary directory for persistence tests.
    fn temporary_directory() -> PathBuf {
        let suffix = rand::random::<u64>();
        let path = std::env::temp_dir().join(format!("herdr-dog-allowlist-{suffix}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
        path
    }

    // TEST:relay/src/allowlist.rs[tests::revocation_reload_blocks_normal_qrm]
    #[test]
    fn revocation_reload_blocks_normal_qrm() {
        let directory = temporary_directory();
        let uid = current_uid().expect("uid");
        let path = directory.join("allowlist.json");
        let mut store = PersistentAllowlist::open(&path, uid).expect("open");
        let app = crate::enrollment::AppId::new("app-a").expect("app");
        let csr = CsrMetadata::from_bytes(app.clone(), b"csr").expect("csr");
        let mut authority = FakeCertificateAuthority::new(1, [7; 32]).expect("authority");
        let certificate = authority.issue(&csr, 2, 1).expect("certificate");
        let fingerprint = certificate.fingerprint();
        store.enroll(certificate).expect("enroll");
        assert!(store.allows_qrm_at(fingerprint, 2));
        store.revoke(&app).expect("revoke");
        drop(store);
        let reloaded = PersistentAllowlist::open(&path, uid).expect("reload");
        assert!(!reloaded.allows_qrm_at(fingerprint, 2));
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/allowlist.rs[tests::stale_store_cannot_resurrect_revoked_app]
    #[test]
    fn stale_store_cannot_resurrect_revoked_app() {
        let directory = temporary_directory();
        let uid = current_uid().expect("uid");
        let path = directory.join("allowlist.json");
        let mut first = PersistentAllowlist::open(&path, uid).expect("first");
        let mut second = PersistentAllowlist::open(&path, uid).expect("second");
        let app_a = crate::enrollment::AppId::new("app-a").expect("app a");
        let app_b = crate::enrollment::AppId::new("app-b").expect("app b");
        let csr_a = CsrMetadata::from_bytes(app_a.clone(), b"csr-a").expect("csr a");
        let csr_b = CsrMetadata::from_bytes(app_b, b"csr-b").expect("csr b");
        let mut authority = FakeCertificateAuthority::new(1, [8; 32]).expect("authority");
        first
            .enroll(authority.issue(&csr_a, 2, 1).expect("certificate a"))
            .expect("enroll a");
        second.revoke(&app_a).expect("revoke a");
        first
            .enroll(authority.issue(&csr_b, 3, 2).expect("certificate b"))
            .expect("enroll b");
        let reloaded = PersistentAllowlist::open(&path, uid).expect("reopen");
        assert_eq!(
            reloaded.entry(&app_a).expect("app a").state(),
            crate::enrollment::AllowlistState::Revoked
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/allowlist.rs[tests::allowlist_reopens_and_preserves_generation]
    #[test]
    fn allowlist_reopens_and_preserves_generation() {
        let directory = temporary_directory();
        ensure_directory(
            &directory,
            fs::metadata(&directory).expect("metadata").uid(),
        )
        .expect("protected directory");
        let uid = fs::metadata(&directory).expect("metadata").uid();
        let path = directory.join("allowlist.json");
        let store = PersistentAllowlist::open(&path, uid).expect("open");
        assert_eq!(store.generation(), 1);
        drop(store);
        let reopened = PersistentAllowlist::open(&path, uid).expect("reopen");
        assert_eq!(reopened.generation(), 1);
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o077,
            0
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }
}
