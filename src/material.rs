//! Protected-file loading and validation for QRM-PROD-1 deployment material.
//!
//! This module keeps certificate/key bytes transient and rejects unsafe path ownership,
//! permissions, symlink components, and oversized files before any TLS or allowlist operation.

use crate::{
    config::validate_absolute_path,
    error::{RelayError, RelayResult},
};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Maximum public certificate-chain bytes accepted from a protected file.
pub const MAX_PUBLIC_MATERIAL_BYTES: u64 = 128 * 1024;
/// Maximum protected public material or staged executable bytes.
pub const MAX_PUBLIC_PROTECTED_FILE_BYTES: u64 = 128 * 1024 * 1024;
/// Maximum private-key bytes accepted from a protected file.
pub const MAX_PRIVATE_MATERIAL_BYTES: u64 = 64 * 1024;
/// Maximum serialized allowlist bytes accepted from a protected file.
pub const MAX_ALLOWLIST_BYTES: u64 = 256 * 1024;

/// Permission class required for one protected deployment file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedFileKind {
    /// Public certificate or non-secret metadata may not be group/world writable.
    Public,
    /// Private key material must be owner-only and small.
    Private,
    /// Non-secret allowlist metadata is owner-only but may be larger than a key.
    Allowlist,
}

impl ProtectedFileKind {
    /// Returns the maximum permitted file size for this material class.
    pub const fn max_bytes(self) -> u64 {
        match self {
            Self::Public => MAX_PUBLIC_PROTECTED_FILE_BYTES,
            Self::Private => MAX_PRIVATE_MATERIAL_BYTES,
            Self::Allowlist => MAX_ALLOWLIST_BYTES,
        }
    }
}

/// Validates and reads one protected file without retaining its path in errors.
pub fn read_protected_file(
    path: &Path,
    expected_uid: u32,
    kind: ProtectedFileKind,
    max_bytes: u64,
) -> RelayResult<Vec<u8>> {
    validate_protected_path(path, expected_uid)?;
    let expected_metadata =
        fs::symlink_metadata(path).map_err(|_| RelayError::ConfigurationRead)?;
    validate_file_metadata(&expected_metadata, expected_uid, kind, max_bytes)?;
    // O_NOFOLLOW prevents a final-path symlink substitution between validation and open.
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|_| RelayError::ConfigurationRead)?;
    let opened_metadata = file.metadata().map_err(|_| RelayError::ConfigurationRead)?;
    validate_file_metadata(&opened_metadata, expected_uid, kind, max_bytes)?;
    if !same_file_identity(&expected_metadata, &opened_metadata) {
        return Err(RelayError::ConfigurationRead);
    }
    let capacity =
        usize::try_from(opened_metadata.len()).map_err(|_| RelayError::ConfigurationRead)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| RelayError::ConfigurationRead)?;
    if bytes.len() as u64 != opened_metadata.len() || bytes.len() as u64 > max_bytes {
        return Err(RelayError::ConfigurationRead);
    }
    Ok(bytes)
}

/// Atomically writes one bounded protected file with owner-only permissions.
pub fn write_protected_file(
    path: &Path,
    expected_uid: u32,
    bytes: &[u8],
    kind: ProtectedFileKind,
    max_bytes: u64,
) -> RelayResult<()> {
    validate_absolute_path("protected.file", path)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(RelayError::ConfigurationRead);
    }
    let parent = path.parent().ok_or(RelayError::ConfigurationRead)?;
    validate_directory(parent, expected_uid)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(RelayError::ConfigurationRead)?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(required_mode(kind));
    let mut file = options
        .open(&temporary)
        .map_err(|_| RelayError::ConfigurationRead)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| RelayError::ConfigurationRead)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(required_mode(kind)))
        .map_err(|_| RelayError::ConfigurationRead)?;
    fs::rename(&temporary, path).map_err(|_| RelayError::ConfigurationRead)?;
    Ok(())
}

/// Validates an absolute path and rejects final or non-root-owned symlink components before file access.
pub fn validate_protected_path(path: &Path, expected_uid: u32) -> RelayResult<()> {
    validate_absolute_path("protected.file", path)?;
    let components: Vec<_> = path.components().collect();
    if components.iter().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(RelayError::InvalidConfiguration {
            field: "protected.file",
            reason: "path contains dot components",
        });
    }
    let mut current = Path::new("/").to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        current.push(name);
        let is_final = index + 1 == components.len();
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() && (is_final || metadata.uid() != 0) {
                    return Err(RelayError::InvalidConfiguration {
                        field: "protected.file",
                        reason: "path contains an unsafe symlink component",
                    });
                }
                if !is_final && !metadata.is_dir() && !metadata.file_type().is_symlink() {
                    return Err(RelayError::ConfigurationRead);
                }
            }
            Err(error) if is_final && error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(RelayError::ConfigurationRead),
        }
    }
    let immediate_parent = path.parent().ok_or(RelayError::ConfigurationRead)?;
    validate_directory(immediate_parent, expected_uid)?;
    let mut component = immediate_parent.parent();
    while let Some(current) = component {
        if current == Path::new("/") {
            break;
        }
        let metadata = fs::symlink_metadata(current).map_err(|_| RelayError::ConfigurationRead)?;
        let mode = metadata.mode();
        let safe_ancestor = if metadata.file_type().is_symlink() {
            // Platform aliases such as macOS /var are acceptable only when root-owned.
            metadata.uid() == 0
        } else {
            metadata.is_dir()
                && (metadata.uid() == expected_uid || mode & 0o022 == 0 || mode & 0o1000 != 0)
        };
        if !safe_ancestor {
            return Err(RelayError::InvalidConfiguration {
                field: "protected.file",
                reason: "path contains an unsafe ancestor directory",
            });
        }
        component = current.parent();
    }
    Ok(())
}

/// Compares the descriptor identity with the metadata captured before opening a path.
fn same_file_identity(expected: &fs::Metadata, opened: &fs::Metadata) -> bool {
    expected.dev() == opened.dev()
        && expected.ino() == opened.ino()
        && expected.uid() == opened.uid()
        && expected.mode() == opened.mode()
        && expected.len() == opened.len()
}

/// Validates one protected file's type, owner, mode, and bounded size.
pub fn validate_file_metadata(
    metadata: &fs::Metadata,
    expected_uid: u32,
    kind: ProtectedFileKind,
    max_bytes: u64,
) -> RelayResult<()> {
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.len() == 0
        || metadata.len() > max_bytes
        || metadata.len() > kind.max_bytes()
    {
        return Err(RelayError::ConfigurationRead);
    }
    let mode = metadata.mode();
    let valid_mode = match kind {
        ProtectedFileKind::Public => mode & 0o022 == 0 && mode & 0o400 == 0o400,
        ProtectedFileKind::Private | ProtectedFileKind::Allowlist => {
            mode & 0o077 == 0 && mode & 0o400 == 0o400
        }
    };
    if !valid_mode {
        return Err(RelayError::InvalidConfiguration {
            field: "protected.file",
            reason: "file ownership or permissions are unsafe",
        });
    }
    Ok(())
}

/// Validates one owner-controlled directory before creating or replacing a file.
pub fn validate_directory(path: &Path, expected_uid: u32) -> RelayResult<()> {
    validate_absolute_path("protected.directory", path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| RelayError::ConfigurationRead)?;
    if !metadata.is_dir() || metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 {
        return Err(RelayError::InvalidConfiguration {
            field: "protected.directory",
            reason: "directory ownership or permissions are unsafe",
        });
    }
    Ok(())
}

/// Resolves the current Unix UID for protected-file ownership checks.
pub fn current_uid() -> RelayResult<u32> {
    let output = std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(|_| RelayError::ConfigurationRead)?;
    if !output.status.success() {
        return Err(RelayError::ConfigurationRead);
    }
    String::from_utf8(output.stdout)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .ok_or(RelayError::ConfigurationRead)
}

const fn required_mode(kind: ProtectedFileKind) -> u32 {
    match kind {
        ProtectedFileKind::Public => 0o640,
        ProtectedFileKind::Private | ProtectedFileKind::Allowlist => 0o600,
    }
}

/// Creates an owner-controlled directory tree for a local deployment adapter.
pub fn ensure_directory(path: &Path, expected_uid: u32) -> RelayResult<()> {
    validate_absolute_path("protected.directory", path)?;
    fs::create_dir_all(path).map_err(|_| RelayError::ConfigurationRead)?;
    validate_directory(path, expected_uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    /// Creates one owner-controlled temporary directory for protected-file tests.
    fn temporary_directory() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("herdr-dog-material-{suffix}"));
        fs::create_dir(&path).expect("directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
        path
    }

    // TEST:relay/src/material.rs[tests::protected_file_round_trip_is_bounded]
    #[test]
    fn protected_file_round_trip_is_bounded() {
        let directory = temporary_directory();
        let path = directory.join("allowlist.json");
        let uid = fs::metadata(&directory).expect("metadata").uid();
        write_protected_file(
            &path,
            uid,
            br#"{"generation":1}"#,
            ProtectedFileKind::Private,
            MAX_ALLOWLIST_BYTES,
        )
        .expect("write");
        let bytes =
            read_protected_file(&path, uid, ProtectedFileKind::Private, MAX_ALLOWLIST_BYTES)
                .expect("read");
        assert_eq!(bytes, br#"{"generation":1}"#);
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o077,
            0
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // TEST:relay/src/material.rs[tests::unsafe_material_modes_are_rejected]
    #[test]
    fn unsafe_material_modes_are_rejected() {
        let directory = temporary_directory();
        let path = directory.join("private.key");
        fs::write(&path, b"key").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
        let uid = fs::metadata(&directory).expect("metadata").uid();
        assert!(read_protected_file(&path, uid, ProtectedFileKind::Private, 64).is_err());
        fs::remove_dir_all(directory).expect("cleanup");
    }
}
