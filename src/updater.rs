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
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tar::{Archive, EntryType};

/// Stable release repository accepted by the updater.
pub const STABLE_REPOSITORY: &str = "mithyer/herdr-dog-relay";
/// Stable release selector accepted by the updater.
pub const STABLE_CHANNEL: &str = "stable-latest";
/// Expected executable name inside every archive.
pub const EXPECTED_BINARY_NAME: &str = "herdogrelay";
/// Maximum time allowed for a fixed-argument staged-binary startup probe.
const STARTUP_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum output accepted from the fixed `--version` startup probe.
const MAX_VERSION_OUTPUT_BYTES: usize = 128;

/// Numeric semantic version used to prevent stable-latest downgrades.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReleaseVersion {
    /// Major release component.
    major: u64,
    /// Minor release component.
    minor: u64,
    /// Patch release component.
    patch: u64,
}

impl ReleaseVersion {
    /// Parses an exact numeric `major.minor.patch` version.
    ///
    /// # Parameters
    /// * `value` - Version text without the command name.
    ///
    /// # Returns
    /// A parsed release version, or `None` for extra components or invalid text.
    fn parse(value: &str) -> Option<Self> {
        let mut components = value.split('.');
        let version = Self {
            major: components.next()?.parse().ok()?,
            minor: components.next()?.parse().ok()?,
            patch: components.next()?.parse().ok()?,
        };
        components.next().is_none().then_some(version)
    }

    /// Parses the exact bounded output of `herdogrelay --version`.
    ///
    /// # Parameters
    /// * `output` - Captured bounded standard output from the staged binary.
    ///
    /// # Returns
    /// A parsed version only when the output has the expected command prefix and shape.
    fn parse_version_output(output: &[u8]) -> Option<Self> {
        if output.len() >= MAX_VERSION_OUTPUT_BYTES {
            return None;
        }
        let text = std::str::from_utf8(output).ok()?.trim();
        Self::parse(text.strip_prefix("herdogrelay ")?)
    }
}

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
    /// Installed package version used to reject equal or older staged binaries.
    current_version: ReleaseVersion,
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
        let current_version =
            ReleaseVersion::parse(env!("CARGO_PKG_VERSION")).ok_or(RelayError::Update {
                operation: "initializing updater",
                reason: "current Relay version is invalid",
            })?;
        Ok(Self {
            config,
            current_version,
        })
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
        let normalized_arch = match (normalized_os, arch) {
            ("macos", "arm64" | "x86_64") | ("linux", "x86_64") => arch,
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

    /// Validates the staged command's version against the installed package version.
    ///
    /// # Parameters
    /// * `output` - Bounded output captured from the staged `--version` probe.
    ///
    /// # Returns
    /// `Ok(())` only when the staged version is strictly newer than the installed version.
    fn validate_staged_version(&self, output: &[u8]) -> RelayResult<()> {
        let staged_version =
            ReleaseVersion::parse_version_output(output).ok_or(RelayError::Update {
                operation: "checking staged Relay version",
                reason: "staged executable version output is invalid",
            })?;
        if staged_version <= self.current_version {
            return Err(RelayError::Update {
                operation: "checking staged Relay version",
                reason: "staged executable version is not newer",
            });
        }
        Ok(())
    }

    /// Verifies that one staged executable can start with the fixed `--version` argument.
    ///
    /// The probe inherits no caller-provided arguments and discards child I/O so a bad release
    /// cannot leak data into Relay logs. A failed or timed-out probe returns before replacement,
    /// leaving the currently installed executable untouched.
    ///
    /// # Parameters
    /// * `staged` - Absolute owner-controlled executable extracted from a verified archive.
    ///
    /// # Returns
    /// `Ok(())` only when the bounded startup probe exits successfully.
    // TEST:relay/src/updater.rs[tests::startup_probe_failure_preserves_installed_binary]
    pub fn verify_staged_startup(&self, staged: &Path) -> RelayResult<()> {
        if !staged.is_absolute() {
            return Err(RelayError::Update {
                operation: "probing staged Relay binary",
                reason: "staged executable path is not absolute",
            });
        }
        let uid = current_uid().map_err(|_| RelayError::Update {
            operation: "probing staged Relay binary",
            reason: "current owner UID is unavailable",
        })?;
        let metadata = fs::symlink_metadata(staged).map_err(|_| RelayError::Update {
            operation: "probing staged Relay binary",
            reason: "staged executable is unavailable",
        })?;
        validate_file_metadata(
            &metadata,
            uid,
            ProtectedFileKind::Public,
            self.config.max_extracted_bytes(),
        )
        .map_err(|_| RelayError::Update {
            operation: "probing staged Relay binary",
            reason: "staged executable ownership or mode is unsafe",
        })?;
        // Reject scripts and data files before process creation so a downloaded shell payload is never run.
        validate_native_executable(staged)?;
        let _digest = hash_file(staged, self.config.max_extracted_bytes())?;
        let mut child = Command::new(staged)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| RelayError::Update {
                operation: "probing staged Relay binary",
                reason: "staged executable could not be started",
            })?;
        let stdout = child.stdout.take().ok_or(RelayError::Update {
            operation: "probing staged Relay binary",
            reason: "staged executable output is unavailable",
        })?;
        let output_reader = thread::spawn(move || {
            let mut output = Vec::with_capacity(MAX_VERSION_OUTPUT_BYTES);
            stdout
                .take(MAX_VERSION_OUTPUT_BYTES as u64)
                .read_to_end(&mut output)
                .map(|_| output)
        });
        let started = Instant::now();
        let probe_result = loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => break Ok(()),
                Ok(Some(_)) => {
                    break Err(RelayError::Update {
                        operation: "probing staged Relay binary",
                        reason: "staged executable startup check failed",
                    });
                }
                Ok(None) if started.elapsed() < STARTUP_PROBE_TIMEOUT => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(RelayError::Update {
                        operation: "probing staged Relay binary",
                        reason: "staged executable startup check timed out",
                    });
                }
            }
        };
        if let Err(error) = probe_result {
            let _ = child.kill();
            let _ = child.wait();
            let _ = output_reader.join();
            return Err(error);
        }
        let output = output_reader
            .join()
            .map_err(|_| RelayError::Update {
                operation: "checking staged Relay version",
                reason: "staged executable output reader failed",
            })?
            .map_err(|_| RelayError::Update {
                operation: "checking staged Relay version",
                reason: "staged executable output could not be read",
            })?;
        self.validate_staged_version(&output)
    }

    /// Atomically replaces the installed executable while retaining a local rollback copy.
    ///
    /// # Parameters
    /// * `staged` - Absolute protected executable extracted from a verified archive.
    /// * `installed` - Absolute current executable path.
    /// * `backup` - Absolute local rollback path in the installed executable's directory.
    ///
    /// # Returns
    /// `Ok(())` after the installed file is revalidated against the staged digest.
    // TEST:relay/src/updater.rs[tests::staged_source_swap_restores_previous_binary]
    pub fn replace_binary(
        &self,
        staged: &Path,
        installed: &Path,
        backup: &Path,
    ) -> RelayResult<()> {
        self.replace_binary_with_pre_rename(staged, installed, backup, || {})
    }

    /// Performs the replacement after a private test hook that models a source-path race.
    fn replace_binary_with_pre_rename<F>(
        &self,
        staged: &Path,
        installed: &Path,
        backup: &Path,
        pre_rename: F,
    ) -> RelayResult<()>
    where
        F: FnOnce(),
    {
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
        let staged_digest = hash_file(staged, self.config.max_extracted_bytes())?;

        // Capture the old executable identity and digest before moving it into rollback storage.
        let previous_metadata = match fs::symlink_metadata(installed) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => {
                return Err(RelayError::Update {
                    operation: "replacing Relay binary",
                    reason: "installed executable metadata is unavailable",
                });
            }
        };
        let had_previous_binary = previous_metadata.is_some();
        let previous_digest = if let Some(metadata) = previous_metadata.as_ref() {
            validate_file_metadata(
                metadata,
                uid,
                ProtectedFileKind::Public,
                self.config.max_extracted_bytes(),
            )?;
            Some(hash_file(installed, self.config.max_extracted_bytes())?)
        } else {
            None
        };

        // Test-only callers can replace the staged path here; every failed rename or verification
        // must restore and verify the old binary before returning an update error.
        pre_rename();
        if had_previous_binary {
            fs::rename(installed, backup).map_err(|_| RelayError::Update {
                operation: "replacing Relay binary",
                reason: "previous executable could not be backed up",
            })?;
            if sync_parent(installed).is_err() {
                return rollback_update_error(
                    installed,
                    backup,
                    had_previous_binary,
                    previous_digest,
                    self.config.max_extracted_bytes(),
                    "previous executable backup could not be synchronized",
                );
            }
        }
        if fs::rename(staged, installed).is_err() {
            return rollback_update_error(
                installed,
                backup,
                had_previous_binary,
                previous_digest,
                self.config.max_extracted_bytes(),
                "staged executable could not be installed",
            );
        }
        let installed_metadata = match fs::symlink_metadata(installed) {
            Ok(metadata) => metadata,
            Err(_) => {
                return rollback_update_error(
                    installed,
                    backup,
                    had_previous_binary,
                    previous_digest,
                    self.config.max_extracted_bytes(),
                    "installed executable is unavailable",
                );
            }
        };
        let installed_digest = validate_file_metadata(
            &installed_metadata,
            uid,
            ProtectedFileKind::Public,
            self.config.max_extracted_bytes(),
        )
        .and_then(|_| hash_file(installed, self.config.max_extracted_bytes()));
        let installed_is_verified =
            matches!(installed_digest, Ok(digest) if digest == staged_digest);
        if !installed_is_verified || sync_parent(installed).is_err() {
            return rollback_update_error(
                installed,
                backup,
                had_previous_binary,
                previous_digest,
                self.config.max_extracted_bytes(),
                "installed executable failed post-replacement verification",
            );
        }
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

/// Requires the staged file to begin with a supported macOS Mach-O or Linux ELF executable magic.
fn validate_native_executable(path: &Path) -> RelayResult<()> {
    let mut header = [0_u8; 4];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|_| RelayError::Update {
            operation: "probing staged Relay binary",
            reason: "staged executable header could not be read",
        })?;
    let is_native = if cfg!(target_os = "macos") {
        matches!(
            header,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xbf, 0xba, 0xfe, 0xca]
        )
    } else if cfg!(target_os = "linux") {
        header == [0x7f, b'E', b'L', b'F']
    } else {
        false
    };
    if is_native {
        Ok(())
    } else {
        Err(RelayError::Update {
            operation: "probing staged Relay binary",
            reason: "staged executable is not a supported native binary",
        })
    }
}

/// Restores and verifies the prior executable after a failed replacement.
fn restore_previous_binary(
    installed: &Path,
    backup: &Path,
    had_previous_binary: bool,
    expected_digest: Option<[u8; 32]>,
    max_bytes: u64,
) -> RelayResult<()> {
    if had_previous_binary {
        if !backup.exists() {
            return Err(RelayError::Update {
                operation: "rolling back Relay binary",
                reason: "rollback copy is unavailable",
            });
        }
        if installed.exists() {
            fs::remove_file(installed).map_err(|_| RelayError::Update {
                operation: "rolling back Relay binary",
                reason: "failed replacement could not be removed",
            })?;
        }
        fs::rename(backup, installed).map_err(|_| RelayError::Update {
            operation: "rolling back Relay binary",
            reason: "rollback copy could not be restored",
        })?;
        sync_parent(installed)?;
        let metadata = fs::symlink_metadata(installed).map_err(|_| RelayError::Update {
            operation: "rolling back Relay binary",
            reason: "restored executable is unavailable",
        })?;
        validate_file_metadata(
            &metadata,
            current_uid().map_err(|_| RelayError::Update {
                operation: "rolling back Relay binary",
                reason: "current owner UID is unavailable",
            })?,
            ProtectedFileKind::Public,
            max_bytes,
        )
        .map_err(|_| RelayError::Update {
            operation: "rolling back Relay binary",
            reason: "restored executable metadata is unsafe",
        })?;
        if let Some(expected_digest) = expected_digest
            && hash_file(installed, max_bytes)? != expected_digest
        {
            return Err(RelayError::Update {
                operation: "rolling back Relay binary",
                reason: "restored executable digest does not match the prior binary",
            });
        }
    } else {
        if installed.exists() {
            fs::remove_file(installed).map_err(|_| RelayError::Update {
                operation: "rolling back Relay binary",
                reason: "failed replacement could not be removed",
            })?;
        }
        sync_parent(installed)?;
        if installed.exists() {
            return Err(RelayError::Update {
                operation: "rolling back Relay binary",
                reason: "failed replacement remains installed",
            });
        }
    }
    Ok(())
}

/// Converts a primary replacement failure into a fail-closed rollback result.
fn rollback_update_error(
    installed: &Path,
    backup: &Path,
    had_previous_binary: bool,
    previous_digest: Option<[u8; 32]>,
    max_bytes: u64,
    primary_reason: &'static str,
) -> RelayResult<()> {
    match restore_previous_binary(
        installed,
        backup,
        had_previous_binary,
        previous_digest,
        max_bytes,
    ) {
        Ok(()) => Err(RelayError::Update {
            operation: "replacing Relay binary",
            reason: primary_reason,
        }),
        Err(_) => Err(RelayError::Update {
            operation: "replacing Relay binary",
            reason: "replacement failed and rollback verification failed",
        }),
    }
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
    use flate2::{Compression, write::GzEncoder};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File},
        io::Write,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tar::{Builder, EntryType, Header};

    /// Builds a unique private updater root even when tests start within one clock tick.
    fn updater() -> (FixedSourceUpdater, PathBuf) {
        let directory = (0..32)
            .map(|attempt| {
                let suffix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time")
                    .as_nanos();
                std::env::temp_dir().join(format!(
                    "herdr-dog-updater-{}-{suffix}-{attempt}",
                    std::process::id()
                ))
            })
            .find(|path| fs::create_dir(path).is_ok())
            .expect("directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("directory mode");
        let config = UpdateConfig::from_toml_for_test(directory.clone());
        let mut updater = FixedSourceUpdater::new(config).expect("updater");
        // Use an older test baseline so the current package binary is a valid newer fixture.
        updater.current_version = ReleaseVersion {
            major: 0,
            minor: 1,
            patch: 0,
        };
        (updater, directory)
    }

    /// Creates one valid single-entry archive using an explicitly supplied entry name.
    fn create_archive_entry(
        directory: &Path,
        archive_name: &str,
        entry_name: &str,
        content: &[u8],
    ) -> PathBuf {
        let archive_path = directory.join(archive_name);
        let file = File::create(&archive_path).expect("archive file");
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        let mut header = Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o700);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, entry_name, content)
            .expect("archive entry");
        builder
            .into_inner()
            .expect("tar encoder")
            .finish()
            .expect("gzip archive");
        archive_path
    }

    /// Creates one valid single-binary release archive for local updater tests.
    fn create_archive(directory: &Path, archive_name: &str, content: &[u8]) -> PathBuf {
        create_archive_entry(directory, archive_name, EXPECTED_BINARY_NAME, content)
    }

    /// Reads the current Relay binary used by the startup/version probe fixture.
    fn native_version_fixture() -> Vec<u8> {
        let path = std::env::var_os("CARGO_BIN_EXE_herdogrelay")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("target")
                    .join("debug")
                    .join(EXPECTED_BINARY_NAME)
            });
        fs::read(path).expect("Relay version fixture")
    }

    /// Creates a link entry to prove the archive validator rejects non-regular files.
    fn create_link_archive(directory: &Path, archive_name: &str, entry_type: EntryType) -> PathBuf {
        let archive_path = directory.join(archive_name);
        let file = File::create(&archive_path).expect("link archive file");
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        let mut header = Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(0);
        builder
            .append_link(&mut header, EXPECTED_BINARY_NAME, "outside")
            .expect("link archive entry");
        builder
            .into_inner()
            .expect("link tar encoder")
            .finish()
            .expect("link gzip archive");
        archive_path
    }

    // TEST:relay/src/updater.rs[tests::archive_validator_rejects_malicious_entries]
    #[test]
    fn archive_validator_rejects_malicious_entries() {
        let (updater, directory) = updater();
        let unexpected = create_archive_entry(
            &directory,
            "unexpected.tar.gz",
            "unexpected-file",
            b"unexpected",
        );
        assert!(updater.validate_archive(&unexpected).is_err());
        let symlink = create_link_archive(&directory, "symlink.tar.gz", EntryType::Symlink);
        assert!(updater.validate_archive(&symlink).is_err());
        let hardlink = create_link_archive(&directory, "hardlink.tar.gz", EntryType::Link);
        assert!(updater.validate_archive(&hardlink).is_err());
        let compressed = create_archive(&directory, "compressed.tar.gz", &vec![0_u8; 512 * 1024]);
        assert!(updater.validate_archive(&compressed).is_err());
        let valid = create_archive(&directory, "valid.tar.gz", b"complete archive");
        let partial = directory.join("partial.tar.gz");
        let bytes = fs::read(&valid).expect("valid archive bytes");
        fs::write(&partial, &bytes[..bytes.len() / 2]).expect("partial archive");
        assert!(updater.validate_archive(&partial).is_err());
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/updater.rs[tests::staged_source_swap_restores_previous_binary]
    #[test]
    fn staged_source_swap_restores_previous_binary() {
        let (updater, directory) = updater();
        let install_directory = directory.join("install");
        fs::create_dir(&install_directory).expect("install directory");
        fs::set_permissions(&install_directory, fs::Permissions::from_mode(0o700))
            .expect("install mode");
        let installed = install_directory.join(EXPECTED_BINARY_NAME);
        let backup = install_directory.join("herdogrelay.previous");
        let staged = directory.join("staged-herdogrelay");
        fs::write(&installed, b"prior verified binary").expect("installed binary");
        fs::write(&staged, b"verified staged binary").expect("staged binary");
        for path in [&installed, &staged] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("binary mode");
        }
        assert!(
            updater
                .replace_binary_with_pre_rename(&staged, &installed, &backup, || {
                    fs::write(&staged, b"swapped staged binary").expect("source swap");
                })
                .is_err()
        );
        assert_eq!(
            fs::read(&installed).expect("restored installed binary"),
            b"prior verified binary"
        );
        assert!(!backup.exists());
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/updater.rs[tests::archive_extract_and_replace_preserve_rollback]
    #[test]
    fn archive_extract_and_replace_preserve_rollback() {
        let (updater, directory) = updater();
        let archive = create_archive(
            &directory,
            "herdogrelay-macos-arm64.tar.gz",
            b"new relay binary",
        );
        updater
            .validate_archive(&archive)
            .expect("archive validation");
        let staged = updater
            .extract_verified(&archive)
            .expect("archive extraction");
        let install_directory = directory.join("install");
        fs::create_dir(&install_directory).expect("install directory");
        fs::set_permissions(&install_directory, fs::Permissions::from_mode(0o700))
            .expect("install mode");
        let installed = install_directory.join(EXPECTED_BINARY_NAME);
        let backup = install_directory.join("herdogrelay.previous");
        fs::write(&installed, b"old relay binary").expect("old binary");
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o700))
            .expect("old binary mode");
        updater
            .replace_binary(&staged, &installed, &backup)
            .expect("atomic replacement");
        assert_eq!(
            fs::read(&installed).expect("installed binary"),
            b"new relay binary"
        );
        assert_eq!(
            fs::read(&backup).expect("rollback binary"),
            b"old relay binary"
        );
        assert!(!staged.exists());
        assert!(
            updater
                .replace_binary(
                    &directory.join("missing-staged-binary"),
                    &installed,
                    &backup,
                )
                .is_err()
        );
        assert_eq!(
            fs::read(&installed).expect("installed after rejected replacement"),
            b"new relay binary"
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/updater.rs[tests::staged_version_must_be_newer]
    #[test]
    fn staged_version_must_be_newer() {
        let (updater, directory) = updater();
        assert!(
            updater
                .validate_staged_version(b"herdogrelay 0.1.1\n")
                .is_ok()
        );
        assert!(
            updater
                .validate_staged_version(b"herdogrelay 0.1.0\n")
                .is_err()
        );
        assert!(
            updater
                .validate_staged_version(b"herdogrelay 0.1.1\nextra")
                .is_err()
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/updater.rs[tests::startup_probe_failure_preserves_installed_binary]
    #[test]
    fn startup_probe_failure_preserves_installed_binary() {
        let (updater, directory) = updater();
        let install_directory = directory.join("install");
        fs::create_dir(&install_directory).expect("install directory");
        fs::set_permissions(&install_directory, fs::Permissions::from_mode(0o700))
            .expect("install mode");
        let installed = install_directory.join(EXPECTED_BINARY_NAME);
        fs::write(&installed, b"known working binary").expect("installed binary");
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o700)).expect("installed mode");

        // A native fixture proves the probe uses the fixed `--version` argument without a shell.
        let good_archive = create_archive(
            &directory,
            "good-herdogrelay.tar.gz",
            &native_version_fixture(),
        );
        let good_staged = updater
            .extract_verified(&good_archive)
            .expect("good extraction");
        updater
            .verify_staged_startup(&good_staged)
            .expect("fixed startup probe");
        fs::remove_dir_all(good_staged.parent().expect("stage parent")).expect("stage cleanup");

        let marker = directory.join("script-executed");
        let script = format!("#!/bin/sh\ntouch {}\n", marker.display());
        let failing_archive =
            create_archive(&directory, "failing-herdogrelay.tar.gz", script.as_bytes());
        let failing_staged = updater
            .extract_verified(&failing_archive)
            .expect("failing extraction");
        // The script must be rejected by native-header validation before it can create the marker.
        assert!(updater.verify_staged_startup(&failing_staged).is_err());
        assert!(!marker.exists());
        assert_eq!(
            fs::read(&installed).expect("installed after failed probe"),
            b"known working binary"
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/updater.rs[tests::release_matrix_is_explicit]
    #[test]
    fn release_matrix_is_explicit() {
        let (updater, directory) = updater();
        for (os, arch) in [("macos", "arm64"), ("macos", "x86_64"), ("linux", "x86_64")] {
            let name = updater.archive_name(os, arch).expect("release asset");
            let archive = create_archive(&directory, &name, b"disposable relay artifact");
            let checksums = directory.join(format!("{name}.checksums"));
            let digest = Sha256::digest(fs::read(&archive).expect("archive bytes"));
            let mut manifest = File::create(&checksums).expect("checksums");
            writeln!(manifest, "{digest:x}  {name}").expect("checksum entry");
            updater
                .verify_checksum(&archive, &checksums)
                .expect("archive checksum");
            updater.validate_archive(&archive).expect("archive shape");
            assert!(
                updater
                    .archive_url(os, arch)
                    .expect("release URL")
                    .starts_with(
                        "https://github.com/mithyer/herdr-dog-relay/releases/latest/download/"
                    )
            );
        }
        fs::remove_dir_all(directory).expect("cleanup");
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
        // Linux arm64 has no published release artifact and must fail rather than request one.
        assert!(updater.archive_name("linux", "arm64").is_err());
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
