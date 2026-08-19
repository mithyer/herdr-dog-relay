//! Validated Unix-domain socket access for the configured Herdr endpoint.

use crate::{
    config::validate_absolute_path,
    error::{RelayError, RelayResult},
};
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::net::UnixStream;

/// A stable identity snapshot for one validated Unix socket path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixSocketIdentity {
    /// The device number containing the socket.
    device: u64,
    /// The inode number identifying the socket.
    inode: u64,
    /// The owner UID recorded for the socket.
    owner_uid: u32,
    /// The permission bits recorded for the socket.
    mode: u32,
    /// The device number containing the immediate parent directory.
    parent_device: u64,
    /// The inode number identifying the immediate parent directory.
    parent_inode: u64,
    /// The owner UID recorded for the immediate parent directory.
    parent_owner_uid: u32,
    /// The permission bits recorded for the immediate parent directory.
    parent_mode: u32,
}

/// A fail-closed policy for one Herdr Unix socket path.
#[derive(Clone, Debug)]
pub struct UnixSocketConnector {
    /// The configured socket path.
    path: PathBuf,
    /// The UID that must own both the socket and its immediate parent.
    expected_uid: u32,
}

impl UnixSocketConnector {
    /// Creates a connector with an explicit expected owner UID.
    ///
    /// # Arguments
    ///
    /// * `path` - The absolute, non-root Herdr Unix socket path.
    /// * `expected_uid` - The user UID that must own the socket and parent directory.
    ///
    /// # Returns
    ///
    /// A connector whose path boundary has been validated.
    pub fn new(path: impl Into<PathBuf>, expected_uid: u32) -> RelayResult<Self> {
        let path = path.into();
        validate_absolute_path("relay.herdr_socket", &path)?;
        Ok(Self { path, expected_uid })
    }

    /// Returns the configured socket path.
    ///
    /// # Returns
    ///
    /// The absolute path selected by configuration.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Validates the parent directory, socket type, owner, and permissions.
    ///
    /// # Returns
    ///
    /// A stable identity snapshot that can be used as a connection precondition.
    pub fn validate(&self) -> RelayResult<UnixSocketIdentity> {
        self.validate_path_components()?;
        let parent_metadata = self.validate_parent_directory()?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| RelayError::io("checking Herdr Unix socket", error))?;
        if !metadata.file_type().is_socket() {
            return Err(RelayError::SocketIdentity {
                operation: "checking Herdr Unix socket",
                reason: "configured path is not a Unix socket",
            });
        }
        self.validate_owner_and_mode(&metadata, "checking Herdr Unix socket", true)?;
        Ok(identity_from_metadata(&metadata, &parent_metadata))
    }

    /// Connects only when the socket identity remains stable across the connection.
    ///
    /// # Returns
    ///
    /// A connected Unix stream, or a redacted socket/I/O error.
    pub async fn connect(&self) -> RelayResult<UnixStream> {
        let expected = self.validate()?;
        self.connect_checked(expected).await
    }

    /// Connects only when a caller-provided socket identity still matches.
    ///
    /// # Arguments
    ///
    /// * `expected` - The identity captured before the operation began.
    ///
    /// # Returns
    ///
    /// A connected Unix stream whose path identity also matches after connect.
    pub async fn connect_checked(&self, expected: UnixSocketIdentity) -> RelayResult<UnixStream> {
        self.ensure_identity(expected)?;
        let stream = UnixStream::connect(&self.path)
            .await
            .map_err(|error| RelayError::io("connecting to Herdr Unix socket", error))?;
        self.ensure_identity(expected)?;
        Ok(stream)
    }

    /// Validates that the current path still has the supplied identity.
    ///
    /// # Arguments
    ///
    /// * `expected` - The identity captured for the current socket generation.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the path remains unchanged, otherwise a redacted identity error.
    pub fn ensure_identity(&self, expected: UnixSocketIdentity) -> RelayResult<()> {
        let actual = self.validate()?;
        if actual != expected {
            return Err(RelayError::SocketIdentity {
                operation: "checking Herdr Unix socket",
                reason: "socket identity changed",
            });
        }
        Ok(())
    }

    /// Rejects symlink components anywhere between the root and socket parent.
    fn validate_path_components(&self) -> RelayResult<()> {
        let mut component = self.path.parent();
        while let Some(path) = component {
            let metadata = fs::symlink_metadata(path)
                .map_err(|error| RelayError::io("checking Herdr socket path", error))?;
            if metadata.file_type().is_symlink() {
                return Err(RelayError::SocketIdentity {
                    operation: "checking Herdr socket path",
                    reason: "socket path contains a symlink component",
                });
            }
            if path == Path::new("/") {
                break;
            }
            component = path.parent();
        }
        Ok(())
    }

    /// Validates the immediate parent directory's type, owner, and write policy.
    fn validate_parent_directory(&self) -> RelayResult<fs::Metadata> {
        let parent = self.path.parent().ok_or(RelayError::SocketIdentity {
            operation: "checking Herdr socket parent",
            reason: "socket path has no parent directory",
        })?;
        let metadata = fs::symlink_metadata(parent)
            .map_err(|error| RelayError::io("checking Herdr socket parent", error))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(RelayError::SocketIdentity {
                operation: "checking Herdr socket parent",
                reason: "socket parent is not a real directory",
            });
        }
        self.validate_owner_and_mode(&metadata, "checking Herdr socket parent", false)?;
        Ok(metadata)
    }

    /// Applies owner and least-privilege permission checks to one metadata record.
    fn validate_owner_and_mode(
        &self,
        metadata: &fs::Metadata,
        operation: &'static str,
        socket: bool,
    ) -> RelayResult<()> {
        if metadata.uid() != self.expected_uid {
            return Err(RelayError::SocketIdentity {
                operation,
                reason: "owner UID does not match the configured owner",
            });
        }
        let mode = metadata.permissions().mode();
        let insecure = if socket {
            mode & 0o077 != 0 || mode & 0o600 != 0o600
        } else {
            mode & 0o022 != 0 || mode & 0o700 != 0o700
        };
        if insecure {
            return Err(RelayError::SocketIdentity {
                operation,
                reason: "permissions are broader than the private socket policy",
            });
        }
        Ok(())
    }
}

/// Builds a stable identity from Unix metadata without retaining a path or payload.
fn identity_from_metadata(
    metadata: &fs::Metadata,
    parent_metadata: &fs::Metadata,
) -> UnixSocketIdentity {
    UnixSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner_uid: metadata.uid(),
        mode: metadata.permissions().mode() & 0o777,
        parent_device: parent_metadata.dev(),
        parent_inode: parent_metadata.ino(),
        parent_owner_uid: parent_metadata.uid(),
        parent_mode: parent_metadata.permissions().mode() & 0o777,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{PermissionsExt, symlink},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Creates an isolated socket path for one test process.
    fn test_socket_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let short_label: String = label.chars().take(4).collect();
        std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temporary directory")
            .join(format!(
                "hd-r-{short_label}-{}-{nonce}.sock",
                std::process::id()
            ))
    }

    /// Creates an isolated directory with private permissions for path-boundary tests.
    fn test_directory_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let root = std::fs::canonicalize("/tmp")
            .expect("canonicalize short temporary directory")
            .join(format!("hd-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).expect("create private test directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("set private test directory mode");
        root
    }

    fn private_listener(path: &Path) -> (UnixListener, u32) {
        let listener = UnixListener::bind(path).expect("bind Unix listener");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set private socket mode");
        let uid = fs::symlink_metadata(path.parent().expect("socket parent"))
            .expect("read socket parent")
            .uid();
        (listener, uid)
    }

    // TEST:relay/src/socket.rs[tests::private_socket_connects]
    #[tokio::test(flavor = "current_thread")]
    async fn private_socket_connects() {
        let path = test_socket_path("connect");
        let (listener, uid) = private_listener(&path);
        let connector = UnixSocketConnector::new(&path, uid).expect("create connector");
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept socket");
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.expect("read byte");
            byte[0]
        });
        let mut stream = connector.connect().await.expect("connect socket");
        stream.write_all(b"x").await.expect("write byte");
        assert_eq!(accept.await.expect("join accept task"), b'x');
        fs::remove_file(path).expect("remove test socket");
    }

    // TEST:relay/src/socket.rs[tests::non_socket_path_is_rejected]
    #[tokio::test(flavor = "current_thread")]
    async fn non_socket_path_is_rejected() {
        let path = test_socket_path("file");
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("create regular file");
        drop(file);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set private file mode");
        let uid = fs::symlink_metadata(path.parent().expect("file parent"))
            .expect("read file parent")
            .uid();
        let error = UnixSocketConnector::new(&path, uid)
            .expect("create connector")
            .validate()
            .expect_err("regular file must be rejected");
        assert!(error.to_string().contains("not a Unix socket"));
        fs::remove_file(path).expect("remove regular file");
    }

    // TEST:relay/src/socket.rs[tests::symlink_path_is_rejected]
    #[tokio::test(flavor = "current_thread")]
    async fn symlink_path_is_rejected() {
        let target = test_socket_path("symlink-target");
        let path = test_socket_path("symlink");
        let (listener, uid) = private_listener(&target);
        drop(listener);
        symlink(&target, &path).expect("create socket symlink");
        let error = UnixSocketConnector::new(&path, uid)
            .expect("create connector")
            .validate()
            .expect_err("socket symlink must be rejected");
        assert!(error.to_string().contains("not a Unix socket"));
        fs::remove_file(path).expect("remove symlink");
        fs::remove_file(target).expect("remove socket target");
    }

    // TEST:relay/src/socket.rs[tests::owner_and_mode_boundaries_are_rejected]
    #[tokio::test(flavor = "current_thread")]
    async fn owner_and_mode_boundaries_are_rejected() {
        let path = test_socket_path("security");
        let (listener, uid) = private_listener(&path);
        drop(listener);
        let wrong_owner = UnixSocketConnector::new(&path, uid.saturating_add(1))
            .expect("create wrong-owner connector")
            .validate()
            .expect_err("wrong owner must be rejected");
        assert!(wrong_owner.to_string().contains("owner UID"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
            .expect("set broad socket mode");
        let broad_mode = UnixSocketConnector::new(&path, uid)
            .expect("create broad-mode connector")
            .validate()
            .expect_err("broad mode must be rejected");
        assert!(broad_mode.to_string().contains("permissions"));
        fs::remove_file(path).expect("remove test socket");
    }

    // TEST:relay/src/socket.rs[tests::intermediate_symlink_component_is_rejected]
    #[tokio::test(flavor = "current_thread")]
    async fn intermediate_symlink_component_is_rejected() {
        let root = test_directory_path("tree");
        let target = root.join("target");
        let nested = target.join("nested");
        let link = root.join("link");
        fs::create_dir_all(&nested).expect("create socket directories");
        symlink(&target, &link).expect("create intermediate symlink");
        let path = link.join("nested").join("socket");
        let (listener, uid) = private_listener(&path);
        drop(listener);
        let error = UnixSocketConnector::new(&path, uid)
            .expect("create connector")
            .validate()
            .expect_err("intermediate symlink must be rejected");
        assert!(error.to_string().contains("symlink component"));
        fs::remove_file(&path).expect("remove nested socket");
        fs::remove_file(&link).expect("remove intermediate symlink");
        fs::remove_dir_all(root).expect("remove socket directories");
    }

    // TEST:relay/src/socket.rs[tests::parent_permission_boundary_is_rejected]
    #[tokio::test(flavor = "current_thread")]
    async fn parent_permission_boundary_is_rejected() {
        let root = test_directory_path("parent");
        let path = root.join("socket");
        let (listener, uid) = private_listener(&path);
        drop(listener);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
            .expect("set broad parent mode");
        let error = UnixSocketConnector::new(&path, uid)
            .expect("create connector")
            .validate()
            .expect_err("broad parent mode must be rejected");
        assert!(error.to_string().contains("permissions"));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("restore parent mode");
        fs::remove_file(path).expect("remove parent test socket");
        fs::remove_dir(root).expect("remove socket parent");
    }

    // TEST:relay/src/socket.rs[tests::parent_replacement_fails_identity_precondition]
    #[tokio::test(flavor = "current_thread")]
    async fn parent_replacement_fails_identity_precondition() {
        let root = test_directory_path("parent-id");
        let path = root.join("socket");
        let (listener, uid) = private_listener(&path);
        drop(listener);
        let connector = UnixSocketConnector::new(&path, uid).expect("create connector");
        let expected = connector.validate().expect("capture parent identity");
        fs::remove_file(&path).expect("remove original parent socket");
        let old_root = root.with_extension("old");
        fs::rename(&root, &old_root).expect("move original parent");
        fs::create_dir(&root).expect("create replacement parent");
        let (replacement, _) = private_listener(&path);
        drop(replacement);
        let error = connector
            .connect_checked(expected)
            .await
            .expect_err("parent replacement must fail identity precondition");
        assert!(error.to_string().contains("identity changed"));
        fs::remove_file(path).expect("remove replacement parent socket");
        fs::remove_dir(root).expect("remove replacement parent");
        fs::remove_dir(old_root).expect("remove original parent");
    }

    // TEST:relay/src/socket.rs[tests::replaced_socket_fails_identity_precondition]
    #[tokio::test(flavor = "current_thread")]
    async fn replaced_socket_fails_identity_precondition() {
        let path = test_socket_path("replacement");
        let (listener, uid) = private_listener(&path);
        drop(listener);
        let connector = UnixSocketConnector::new(&path, uid).expect("create connector");
        let expected = connector.validate().expect("capture socket identity");
        fs::remove_file(&path).expect("remove original socket");
        let (replacement, _) = private_listener(&path);
        drop(replacement);
        let error = connector
            .connect_checked(expected)
            .await
            .expect_err("replacement must fail identity precondition");
        assert!(error.to_string().contains("identity changed"));
        fs::remove_file(path).expect("remove replacement socket");
    }
}
