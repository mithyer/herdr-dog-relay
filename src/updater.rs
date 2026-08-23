//! Fixed-source stable-latest updater with bounded archive validation.
//!
//! The updater never evaluates downloaded code, accepts arbitrary URLs, or replaces files before
//! checksum and extraction validation. It is a local explicit operation; supervisor restart and
//! Core generation/session reconciliation remain separate lifecycle steps.

use crate::{
    config::UpdateConfig,
    error::{RelayError, RelayResult},
    material::{
        ProtectedFileKind, current_uid, ensure_directory, validate_file_metadata,
        validate_protected_path,
    },
};
use flate2::read::GzDecoder;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
};
use tar::{Archive, EntryType};

/// Stable release repository accepted by the updater.
pub const STABLE_REPOSITORY: &str = "mithyer/herdr-dog-relay";
/// Stable release selector accepted by the updater.
pub const STABLE_CHANNEL: &str = "stable-latest";
/// Expected executable name inside every archive.
pub const EXPECTED_BINARY_NAME: &str = "herdogrelay";

/// Process-local/external update lock held for one explicit replacement.
pub struct UpdateLock {
    /// Protected lock file retained until the operation completes.
    file: File,
}

impl std::fmt::Debug for UpdateLock {
    /// Reports lock ownership without exposing a filesystem path.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UpdateLock(<held>)")
    }
}

impl Drop for UpdateLock {
    /// Releases the external lock when the explicit update operation ends.
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Bounded fixed-source updater.
#[derive(Clone, Debug)]
pub struct FixedSourceUpdater {
    /// Validated update policy.
    config: UpdateConfig,
}

impl FixedSourceUpdater {
    /// Creates an updater from a validated fixed-source policy.
    pub fn new(config: UpdateConfig) -> RelayResult<Self> {
        config.validate()?;
        if !config.enabled() {
            return Err(RelayError::Update {
                operation: "initializing updater",
                reason: "stable-latest updater is disabled",
            });
        }
        Ok(Self { config })
    }

    /// Acquires the exclusive stable-latest update lock.
    pub fn acquire_lock(&self) -> RelayResult<UpdateLock> {
        ensure_directory(
            self.config.staging_directory(),
            current_uid().map_err(|_| RelayError::Update {
                operation: "acquiring update lock",
                reason: "current owner UID is unavailable",
            })?,
        )
        .map_err(|_| RelayError::Update {
            operation: "acquiring update lock",
            reason: "staging directory is not owner-controlled",
        })?;
        let lock_path = self.config.staging_directory().join(".update.lock");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)
            .map_err(|_| RelayError::Update {
                operation: "acquiring update lock",
                reason: "update lock could not be opened",
            })?;
        file.try_lock_exclusive().map_err(|_| RelayError::Update {
            operation: "acquiring update lock",
            reason: "another update is already running",
        })?;
        Ok(UpdateLock { file })
    }

    /// Returns the fixed release archive name for the current target.
    pub fn archive_name(&self, os: &str, arch: &str) -> RelayResult<String> {
        let normalized_os = match os {
            "macos" | "linux" => os,
            _ => {
                return Err(RelayError::Update {
                    operation: "selecting release asset",
                    reason: "unsupported release operating system",
                });
            }
        };
        let normalized_arch = match arch {
            "arm64" | "x86_64" => arch,
            _ => {
                return Err(RelayError::Update {
                    operation: "selecting release asset",
                    reason: "unsupported release architecture",
                });
            }
        };
        Ok(format!(
            "{EXPECTED_BINARY_NAME}-{normalized_os}-{normalized_arch}.tar.gz"
        ))
    }

    /// Returns the only HTTPS archive source accepted by the updater.
    pub fn archive_url(&self, os: &str, arch: &str) -> RelayResult<String> {
        let archive = self.archive_name(os, arch)?;
        Ok(format!(
            "https://github.com/{}/releases/latest/download/{}",
            self.config.repository(),
            archive
        ))
    }

    /// Returns the same-source checksums URL for the fixed stable release.
    pub fn checksums_url(&self) -> String {
        format!(
            "https://github.com/{}/releases/latest/download/checksums.txt",
            self.config.repository()
        )
    }

    /// Downloads the fixed archive/checksum pair using fixed curl arguments.
    pub fn download_latest(&self, os: &str, arch: &str) -> RelayResult<(PathBuf, PathBuf)> {
        let archive_name = self.archive_name(os, arch)?;
        let archive_path = self.config.staging_directory().join(&archive_name);
        let checksum_path = self.config.staging_directory().join("checksums.txt");
        ensure_directory(
            self.config.staging_directory(),
            current_uid().map_err(|_| RelayError::Update {
                operation: "creating updater staging directory",
                reason: "current owner UID is unavailable",
            })?,
        )
        .map_err(|_| RelayError::Update {
            operation: "creating updater staging directory",
            reason: "staging directory is not owner-controlled",
        })?;
        download_https(
            &self.archive_url(os, arch)?,
            &archive_path,
            self.config.max_archive_bytes(),
        )?;
        download_https(&self.checksums_url(), &checksum_path, 1024 * 1024)?;
        Ok((archive_path, checksum_path))
    }

    /// Verifies the archive against the same-source checksums manifest.
    pub fn verify_checksum(&self, archive: &Path, checksums: &Path) -> RelayResult<()> {
        let archive_name =
            archive
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(RelayError::Update {
                    operation: "checking archive name",
                    reason: "archive name is invalid",
                })?;
        let manifest = fs::read_to_string(checksums).map_err(|_| RelayError::Update {
            operation: "reading checksum manifest",
            reason: "checksum manifest could not be read",
        })?;
        let expected = manifest.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            let digest = fields.next()?;
            let name = fields.next()?.trim_start_matches('*');
            (name == archive_name).then_some(digest)
        });
        let expected = expected
            .ok_or(RelayError::Update {
                operation: "checking archive checksum",
                reason: "archive is missing from checksum manifest",
            })?
            .to_ascii_lowercase();
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(RelayError::Update {
                operation: "checking archive checksum",
                reason: "checksum manifest entry is invalid",
            });
        }
        let mut file = File::open(archive).map_err(|_| RelayError::Update {
            operation: "reading update archive",
            reason: "archive could not be opened",
        })?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|_| RelayError::Update {
                operation: "hashing update archive",
                reason: "archive could not be read",
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let actual = format!("{:x}", hasher.finalize());
        if actual != expected {
            return Err(RelayError::Update {
                operation: "checking archive checksum",
                reason: "archive checksum mismatch",
            });
        }
        Ok(())
    }

    /// Validates archive paths, types, sizes, count and decompression ratio without extracting.
    pub fn validate_archive(&self, archive: &Path) -> RelayResult<()> {
        let compressed_size = fs::metadata(archive)
            .map_err(|_| RelayError::Update {
                operation: "validating update archive",
                reason: "archive metadata could not be read",
            })?
            .len();
        if compressed_size == 0 || compressed_size > self.config.max_archive_bytes() {
            return Err(RelayError::Update {
                operation: "validating update archive",
                reason: "archive size exceeds the configured bound",
            });
        }
        let file = File::open(archive).map_err(|_| RelayError::Update {
            operation: "validating update archive",
            reason: "archive could not be opened",
        })?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        let mut entries = 0_usize;
        let mut extracted_bytes = 0_u64;
        for entry in archive.entries().map_err(|_| RelayError::Update {
            operation: "validating update archive",
            reason: "tar index is invalid",
        })? {
            let entry = entry.map_err(|_| RelayError::Update {
                operation: "validating update archive",
                reason: "tar entry is invalid",
            })?;
            entries = entries.checked_add(1).ok_or(RelayError::Update {
                operation: "validating update archive",
                reason: "tar entry count overflow",
            })?;
            if entries > self.config.max_entries() {
                return Err(RelayError::Update {
                    operation: "validating update archive",
                    reason: "archive has too many entries",
                });
            }
            let entry_path = entry.path().map_err(|_| RelayError::Update {
                operation: "validating update archive",
                reason: "tar path is invalid",
            })?;
            validate_archive_path(&entry_path)?;
            if entry.header().entry_type() != EntryType::Regular {
                return Err(RelayError::Update {
                    operation: "validating update archive",
                    reason: "archive contains a non-regular entry",
                });
            }
            if entry_path.as_ref() != Path::new(EXPECTED_BINARY_NAME) {
                return Err(RelayError::Update {
                    operation: "validating update archive",
                    reason: "archive contains an unexpected file",
                });
            }
            let entry_size = entry.header().size().map_err(|_| RelayError::Update {
                operation: "validating update archive",
                reason: "tar entry size is invalid",
            })?;
            extracted_bytes =
                extracted_bytes
                    .checked_add(entry_size)
                    .ok_or(RelayError::Update {
                        operation: "validating update archive",
                        reason: "extracted size overflow",
                    })?;
            if extracted_bytes > self.config.max_extracted_bytes()
                || extracted_bytes
                    > compressed_size.saturating_mul(self.config.max_compression_ratio())
            {
                return Err(RelayError::Update {
                    operation: "validating update archive",
                    reason: "archive expansion exceeds the configured bound",
                });
            }
        }
        if entries != 1 || extracted_bytes == 0 {
            return Err(RelayError::Update {
                operation: "validating update archive",
                reason: "archive does not contain exactly one executable",
            });
        }
        Ok(())
    }

    /// Extracts one already checksum-verified archive into a fresh protected staging directory.
    pub fn extract_verified(&self, archive: &Path) -> RelayResult<PathBuf> {
        self.validate_archive(archive)?;
        let stage = self
            .config
            .staging_directory()
            .join(format!("stage-{}", std::process::id()));
        if stage.exists() {
            fs::remove_dir_all(&stage).map_err(|_| RelayError::Update {
                operation: "preparing updater staging",
                reason: "old staging directory could not be removed",
            })?;
        }
        fs::create_dir_all(&stage).map_err(|_| RelayError::Update {
            operation: "preparing updater staging",
            reason: "staging directory could not be created",
        })?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).map_err(|_| {
            RelayError::Update {
                operation: "preparing updater staging",
                reason: "staging permissions could not be set",
            }
        })?;
        let file = File::open(archive).map_err(|_| RelayError::Update {
            operation: "extracting update archive",
            reason: "archive could not be opened",
        })?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        let binary = stage.join(EXPECTED_BINARY_NAME);
        for entry in archive.entries().map_err(|_| RelayError::Update {
            operation: "extracting update archive",
            reason: "tar index is invalid",
        })? {
            let mut entry = entry.map_err(|_| RelayError::Update {
                operation: "extracting update archive",
                reason: "tar entry is invalid",
            })?;
            let entry_path = entry.path().map_err(|_| RelayError::Update {
                operation: "extracting update archive",
                reason: "tar path is invalid",
            })?;
            validate_archive_path(&entry_path)?;
            if entry.header().entry_type() != EntryType::Regular
                || entry_path.as_ref() != Path::new(EXPECTED_BINARY_NAME)
            {
                return Err(RelayError::Update {
                    operation: "extracting update archive",
                    reason: "archive contains an unsafe entry",
                });
            }
            let mut output = OpenOptions::new();
            output.write(true).create_new(true).mode(0o700);
            let mut file = output.open(&binary).map_err(|_| RelayError::Update {
                operation: "extracting update archive",
                reason: "staged executable could not be created",
            })?;
            std::io::copy(&mut entry, &mut file).map_err(|_| RelayError::Update {
                operation: "extracting update archive",
                reason: "staged executable could not be written",
            })?;
            file.sync_all().map_err(|_| RelayError::Update {
                operation: "extracting update archive",
                reason: "staged executable could not be synced",
            })?;
        }
        Ok(binary)
    }

    /// Atomically replaces the installed executable while retaining a local rollback copy.
    pub fn replace_binary(
        &self,
        staged: &Path,
        installed: &Path,
        backup: &Path,
    ) -> RelayResult<()> {
        if !staged.is_absolute() || !installed.is_absolute() || !backup.is_absolute() {
            return Err(RelayError::Update {
                operation: "replacing Relay binary",
                reason: "update paths must be absolute",
            });
        }
        let uid = current_uid().map_err(|_| RelayError::Update {
            operation: "replacing Relay binary",
            reason: "current owner UID is unavailable",
        })?;
        validate_protected_path(installed, uid).map_err(|_| RelayError::Update {
            operation: "replacing Relay binary",
            reason: "installed path is not owner-controlled",
        })?;
        validate_protected_path(backup, uid).map_err(|_| RelayError::Update {
            operation: "replacing Relay binary",
            reason: "backup path is not owner-controlled",
        })?;
        let staged_metadata = fs::symlink_metadata(staged).map_err(|_| RelayError::Update {
            operation: "replacing Relay binary",
            reason: "staged executable is unavailable",
        })?;
        validate_file_metadata(
            &staged_metadata,
            uid,
            ProtectedFileKind::Public,
            self.config.max_extracted_bytes(),
        )
        .map_err(|_| RelayError::Update {
            operation: "replacing Relay binary",
            reason: "staged executable ownership or mode is unsafe",
        })?;
        let _staged_digest = hash_file(staged, self.config.max_extracted_bytes())?;
        let installed_metadata = fs::metadata(staged).map_err(|_| RelayError::Update {
            operation: "replacing Relay binary",
            reason: "staged executable is unavailable",
        })?;
        if !installed_metadata.is_file() {
            return Err(RelayError::Update {
                operation: "replacing Relay binary",
                reason: "staged executable is not a regular file",
            });
        }
        if installed.exists() {
            fs::rename(installed, backup).map_err(|_| RelayError::Update {
                operation: "replacing Relay binary",
                reason: "previous executable could not be backed up",
            })?;
            sync_parent(installed)?;
        }
        if let Err(error) = fs::rename(staged, installed) {
            if backup.exists() {
                let _ = fs::rename(backup, installed);
                let _ = sync_parent(installed);
            }
            let _ = error;
            return Err(RelayError::Update {
                operation: "replacing Relay binary",
                reason: "staged executable could not be installed",
            });
        }
        sync_parent(installed)?;
        Ok(())
    }
}

/// Downloads one fixed HTTPS URL without invoking a shell or accepting caller arguments.
fn download_https(url: &str, destination: &Path, max_bytes: u64) -> RelayResult<()> {
    if !url.starts_with("https://github.com/") || !destination.is_absolute() {
        return Err(RelayError::Update {
            operation: "downloading update artifact",
            reason: "download source or destination is not allowed",
        });
    }
    let status = Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "5",
            "--max-time",
            "300",
            "--max-filesize",
        ])
        .arg(max_bytes.to_string())
        .arg("--output")
        .arg(destination)
        .arg(url)
        .status()
        .map_err(|_| RelayError::Update {
            operation: "downloading update artifact",
            reason: "curl could not be started",
        })?;
    if !status.success() {
        return Err(RelayError::Update {
            operation: "downloading update artifact",
            reason: "fixed HTTPS download failed",
        });
    }
    Ok(())
}

/// Hashes one staged executable after owner/mode/type validation.
fn hash_file(path: &Path, max_bytes: u64) -> RelayResult<[u8; 32]> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RelayError::Update {
        operation: "hashing staged executable",
        reason: "staged executable metadata is unavailable",
    })?;
    if metadata.len() > max_bytes {
        return Err(RelayError::Update {
            operation: "hashing staged executable",
            reason: "staged executable exceeds the configured bound",
        });
    }
    let mut file = File::open(path).map_err(|_| RelayError::Update {
        operation: "hashing staged executable",
        reason: "staged executable could not be opened",
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| RelayError::Update {
            operation: "hashing staged executable",
            reason: "staged executable could not be read",
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

/// Synchronizes the parent directory after an atomic replacement.
fn sync_parent(path: &Path) -> RelayResult<()> {
    let parent = path.parent().ok_or(RelayError::Update {
        operation: "syncing updater replacement",
        reason: "replacement path has no parent",
    })?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| RelayError::Update {
            operation: "syncing updater replacement",
            reason: "replacement directory could not be synced",
        })
}

/// Rejects absolute, parent-traversal, prefixed, and nested archive paths.
fn validate_archive_path(path: &Path) -> RelayResult<()> {
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(name))
            if name == EXPECTED_BINARY_NAME && components.next().is_none() =>
        {
            Ok(())
        }
        _ => Err(RelayError::Update {
            operation: "validating archive path",
            reason: "archive path is absolute, nested, or traversing",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    /// Builds one enabled updater policy rooted in an isolated temporary directory.
    fn updater() -> (FixedSourceUpdater, PathBuf) {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("herdr-dog-updater-{suffix}"));
        fs::create_dir(&directory).expect("directory");
        let config = UpdateConfig::from_toml_for_test(directory.clone());
        (FixedSourceUpdater::new(config).expect("updater"), directory)
    }

    // TEST:relay/src/updater.rs[tests::fixed_source_and_selector_are_bounded]
    #[test]
    fn fixed_source_and_selector_are_bounded() {
        let (updater, directory) = updater();
        assert_eq!(
            updater.archive_url("macos", "arm64").expect("url"),
            "https://github.com/mithyer/herdr-dog-relay/releases/latest/download/herdogrelay-macos-arm64.tar.gz"
        );
        assert!(updater.archive_name("windows", "x86_64").is_err());
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/updater.rs[tests::archive_path_policy_rejects_traversal]
    #[test]
    fn archive_path_policy_rejects_traversal() {
        assert!(validate_archive_path(Path::new("../herdogrelay")).is_err());
        assert!(validate_archive_path(Path::new("nested/herdogrelay")).is_err());
        assert!(validate_archive_path(Path::new("herdogrelay")).is_ok());
    }

    // TEST:relay/src/updater.rs[tests::update_lock_rejects_concurrency]
    #[test]
    fn update_lock_rejects_concurrency() {
        let (updater, directory) = updater();
        let first = updater.acquire_lock().expect("first lock");
        assert!(updater.acquire_lock().is_err());
        drop(first);
        assert!(updater.acquire_lock().is_ok());
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/updater.rs[tests::checksum_verification_rejects_mismatch]
    #[test]
    fn checksum_verification_rejects_mismatch() {
        let (updater, directory) = updater();
        let archive = directory.join("herdogrelay-macos-arm64.tar.gz");
        let checksums = directory.join("checksums.txt");
        fs::write(&archive, b"archive").expect("archive");
        let mut file = File::create(&checksums).expect("checksums");
        writeln!(
            file,
            "{}  {}",
            "0".repeat(64),
            archive.file_name().expect("name").to_string_lossy()
        )
        .expect("manifest");
        assert!(updater.verify_checksum(&archive, &checksums).is_err());
        fs::remove_dir_all(directory).expect("cleanup");
    }
}
